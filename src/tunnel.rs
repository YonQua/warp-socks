// boringtun 的 Tunn 是纯 sans-I/O 状态机，这里负责：UDP 收发、reserved
// bytes 覆写(发送)/清零(接收)、可选的 t1/t2 decoy 伪装包、握手与重传定时器驱动。
//
// Phase 0 已在生产网络验证：reserved bytes 覆写/清零是握手能否成功的必需
// 机制；t1/t2 decoy 包不是必需项（默认关闭更快），但保留作为可选开关，
// 应对未来审查策略变化。
//
// Phase 2 起 WgTunnel 本身实现 tokio_smoltcp 的 AsyncDevice（Stream+Sink），
// 握手完成后交给 tokio_smoltcp::Net 常驻做虚拟网卡：Stream 产出隧道解密后的
// 明文 IP 包，Sink 把虚拟网卡要发的明文 IP 包重新加密发出去。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{Sink, Stream};
use rand::Rng;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::time::Interval;
use tokio_smoltcp::device::{AsyncDevice, DeviceCapabilities};

use crate::config::WgConfig;

// 对应 warp-plus `--wgconf` 模式硬编码的隧道 MTU（app/app.go: runWireguard()）。
const TUNNEL_MTU: usize = 1330;
// 密文包缓冲区：MTU + WireGuard 数据包开销，留足余量。
const PACKET_BUF: usize = 2048;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trick {
    None,
    T1,
    T2,
}

pub struct WgTunnel {
    tunn: Tunn,
    sock: UdpSocket,
    reserved: [u8; 3],
    trick: Trick,
    caps: DeviceCapabilities,
    // Stream::poll_next 里驱动握手重传/keepalive 定时器用。
    timer: Interval,
}

impl WgTunnel {
    pub async fn connect(config: &WgConfig, trick: Trick) -> Result<Self> {
        let static_private = StaticSecret::from(config.private_key);
        let peer_public = PublicKey::from(config.peer_public_key);
        let tunn = Tunn::new(static_private, peer_public, None, Some(5), 0, None);

        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("UDP bind 失败")?;
        sock.connect(config.endpoint)
            .await
            .with_context(|| format!("UDP connect 到 {} 失败", config.endpoint))?;

        let mut caps = DeviceCapabilities::default();
        caps.medium = tokio_smoltcp::smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;

        Ok(Self {
            tunn,
            sock,
            reserved: config.reserved,
            trick,
            caps,
            timer: tokio::time::interval(Duration::from_millis(250)),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    // 对应 wireguard/device/peer.go: SendBuffers() 里
    // `if !trick { copy(buffers[i][1:4], reserved) }`。
    fn patch_reserved(&self, packet: &mut [u8]) {
        if packet.len() > 3 && packet[0] > 0 && packet[0] < 5 {
            packet[1..4].copy_from_slice(&self.reserved);
        }
    }

    // 对应 wireguard/device/receive.go:138 `packet[1], packet[2], packet[3] = 0, 0, 0`。
    // boringtun::parse_incoming_packet 把前 4 字节当一个小端 u32 判断消息类型，
    // reserved bytes 非零会导致类型判断失败（InvalidPacket），必须先清零。
    fn strip_reserved(packet: &mut [u8]) {
        if packet.len() > 3 && packet[0] > 0 && packet[0] < 5 {
            packet[1..4].copy_from_slice(&[0, 0, 0]);
        }
    }

    fn try_send_network(&self, packet: &mut [u8]) -> io::Result<()> {
        self.patch_reserved(packet);
        self.sock.try_send(packet)?;
        Ok(())
    }

    // 对应 wireguard/device/send.go: sendRandomPackets()。
    async fn send_decoy_packets(&self) -> Result<()> {
        let header: Vec<u8> = match self.trick {
            Trick::None => return Ok(()),
            Trick::T1 => Vec::new(),
            Trick::T2 => {
                let clist = [0xDCu8, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3];
                let mut rng = rand::thread_rng();
                let first = clist[rng.gen_range(0..clist.len())];
                let mut h = vec![first, 0x00, 0x00, 0x00, 0x01, 0x08];
                let mut cid = [0u8; 8];
                rng.fill(&mut cid);
                h.extend_from_slice(&cid);
                h.extend_from_slice(&[0x00, 0x00, 0x44, 0xD0]);
                h
            }
        };

        // rand::thread_rng() 本身不是 Send（线程本地状态），每次只在同步代码段
        // 内借用、用完即扔，绝不跨越下面的 .await——否则整个 send_decoy_packets
        // 的 future 会被判定为非 Send，而 heal() 作为 Outbound trait 方法必须
        // 是 Send（async_trait 的默认要求，跟 connect_tcp/connect_udp 一致）。
        let num_packets = rand::thread_rng().gen_range(20..=50);
        let max_len = header.len() + 120;
        for _ in 0..num_packets {
            let packet = {
                let mut rng = rand::thread_rng();
                let packet_size = rng.gen_range((header.len() + 10)..=max_len);
                let mut packet = vec![0u8; packet_size];
                packet[..header.len()].copy_from_slice(&header);
                rng.fill(&mut packet[header.len()..]);
                packet
            };
            self.sock.send(&packet).await?;
            let delay_ms = rand::thread_rng().gen_range(80..=150);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        Ok(())
    }

    pub async fn handshake(&mut self, timeout: Duration) -> Result<()> {
        self.send_decoy_packets().await?;

        let mut buf = [0u8; PACKET_BUF];
        match self.tunn.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(packet) => {
                self.patch_reserved(packet);
                self.sock.send(packet).await?;
            }
            other => bail!("format_handshake_initiation 返回异常: {other:?}"),
        }

        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.tunn.time_since_last_handshake().is_some() {
                return Ok(());
            }
            self.pump_once(Duration::from_millis(500)).await?;
        }
        bail!("握手在 {timeout:?} 内未完成")
    }

    // 收一个 UDP 包（最多等 wait）并驱动状态机 + 重传定时器；握手阶段不关心隧道内数据。
    async fn pump_once(&mut self, wait: Duration) -> Result<()> {
        let mut recv_buf = [0u8; PACKET_BUF];
        let mut resp_buf = [0u8; PACKET_BUF];

        match tokio::time::timeout(wait, self.sock.recv(&mut recv_buf)).await {
            Ok(Ok(n)) => {
                Self::strip_reserved(&mut recv_buf[..n]);
                let mut result = self.tunn.decapsulate(None, &recv_buf[..n], &mut resp_buf);
                loop {
                    match result {
                        TunnResult::Done | TunnResult::Err(_) => break,
                        TunnResult::WriteToNetwork(packet) => {
                            self.patch_reserved(packet);
                            self.sock.send(packet).await?;
                            result = self.tunn.decapsulate(None, &[], &mut resp_buf);
                            continue;
                        }
                        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                            break
                        }
                    }
                }
            }
            Ok(Err(e)) => return Err(e).context("UDP recv 失败"),
            Err(_) => {} // 超时，落到下面驱动定时器
        }

        self.tick().await
    }

    // 驱动重传/keepalive 定时器；握手阶段的轮询循环里按需调用。
    async fn tick(&mut self) -> Result<()> {
        let mut buf = [0u8; PACKET_BUF];
        if let TunnResult::WriteToNetwork(packet) = self.tunn.update_timers(&mut buf) {
            self.patch_reserved(packet);
            self.sock.send(packet).await?;
        }
        Ok(())
    }

    // 尝试从底层 UDP socket 收一个包并推进状态机。
    // Ok(Some(pkt))：拿到一个隧道内明文 IP 包，要交给虚拟网卡。
    // Ok(None)：这一轮只处理了控制报文（握手/keepalive/丢弃），未来还有数据要收，需要继续 poll。
    fn poll_recv_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        let mut raw = [0u8; PACKET_BUF];
        let mut read_buf = ReadBuf::new(&mut raw);
        match self.sock.poll_recv(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let n = read_buf.filled().len();
        Self::strip_reserved(&mut raw[..n]);

        let mut resp_buf = [0u8; PACKET_BUF];
        let mut result = self.tunn.decapsulate(None, &raw[..n], &mut resp_buf);
        loop {
            match result {
                TunnResult::Done | TunnResult::Err(_) => return Poll::Ready(Ok(None)),
                TunnResult::WriteToNetwork(packet) => {
                    if let Err(e) = self.try_send_network(packet) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            return Poll::Ready(Err(e));
                        }
                    }
                    result = self.tunn.decapsulate(None, &[], &mut resp_buf);
                    continue;
                }
                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    return Poll::Ready(Ok(Some(packet.to_vec())));
                }
            }
        }
    }
}

impl Stream for WgTunnel {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            while this.timer.poll_tick(cx).is_ready() {
                let mut buf = [0u8; PACKET_BUF];
                if let TunnResult::WriteToNetwork(packet) = this.tunn.update_timers(&mut buf) {
                    if let Err(e) = this.try_send_network(packet) {
                        if e.kind() != io::ErrorKind::WouldBlock {
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                }
            }

            match this.poll_recv_plaintext(cx) {
                Poll::Ready(Ok(Some(pkt))) => return Poll::Ready(Some(Ok(pkt))),
                Poll::Ready(Ok(None)) => continue,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Vec<u8>> for WgTunnel {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let mut buf = [0u8; PACKET_BUF];
        match this.tunn.encapsulate(&item, &mut buf) {
            TunnResult::WriteToNetwork(packet) => match this.try_send_network(packet) {
                Ok(()) => Ok(()),
                // 底层 UDP 发送缓冲区瞬时打满：按丢包处理（TCP 由 smoltcp
                // 自身的重传定时器恢复），而不是把错误上抛。之前这里直接
                // 透传 WouldBlock，会被 tokio-smoltcp 的 send_all 当成硬错误，
                // 导致 Reactor 后台任务（tokio::spawn 结果被丢弃、无感知）
                // 整个退出——并发多连接高吞吐时非常容易触发，表现为所有连接
                // 一起卡死、新连接的隧道内 DNS 解析超时，直到健康检查判定
                // unhealthy 重启容器才恢复。
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
                Err(e) => Err(e),
            },
            TunnResult::Done => Ok(()),
            other => Err(io::Error::other(format!("encapsulate 异常: {other:?}"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncDevice for WgTunnel {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}
