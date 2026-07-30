// WireGuard 出网后端：把现有 tokio_smoltcp::Net 虚拟网卡包装成 Outbound trait。
//
// connect_tcp 走虚拟网卡的 TCP 栈；域名目标在隧道内用虚拟网卡的 UDP socket
// 发 DNS 查询解析。这层只是薄封装，实际逻辑在 tokio_smoltcp::Net 和 crate::dns 里。

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio_smoltcp::smoltcp::iface::Config as IfaceConfig;
use tokio_smoltcp::smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig, UdpSocket as TunnelUdpSocket};

use super::{Datagram, Host, Outbound, Stream};
use crate::config::WgConfig;
use crate::dns::{resolve, RecordType};
use crate::tunnel::{Trick, WgTunnel};

const DNS_SERVER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    53,
);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WgOutbound {
    net: Net,
}

impl WgOutbound {
    pub fn new(net: Net) -> Self {
        Self { net }
    }

    /// 建立 WireGuard 隧道（连接 + 握手）并起虚拟网卡，封装为 [`WgOutbound`]。
    ///
    /// # Errors
    /// 隧道连接、握手失败时返回错误。
    pub async fn establish(
        config: &WgConfig,
        trick: Trick,
        handshake_timeout: Duration,
    ) -> Result<Self> {
        let mut tunnel = WgTunnel::connect(config, trick).await?;
        tunnel.handshake(handshake_timeout).await?;

        let mut interface_config = IfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = rand::random();
        let ip_addr = IpCidr::new(IpAddress::from(IpAddr::V4(config.address_v4)), 32);
        let gateway = vec![IpAddress::from(IpAddr::V4(config.address_v4))];
        let mut net_config = NetConfig::new(interface_config, ip_addr, gateway);
        // 默认 8KiB 收发窗口在实测中把单连接吞吐限制在约 30KB/s（窗口/RTT），
        // 调大到 256KiB 后单连接吞吐可提升到 MB/s 级别。
        net_config.buffer_size = BufferSize {
            tcp_rx_size: 256 * 1024,
            tcp_tx_size: 256 * 1024,
            ..Default::default()
        };

        let net = Net::new(tunnel, net_config);
        Ok(Self::new(net))
    }

    // 域名在隧道内解析；IP 直接使用。connect_tcp/connect_udp 共用。
    async fn resolve_target(&self, host: Host, port: u16) -> std::io::Result<SocketAddr> {
        match host {
            Host::Ip(ip) => Ok(SocketAddr::new(ip, port)),
            Host::Domain(name) => {
                let ips = resolve(&self.net, DNS_SERVER, &name, RecordType::A, DNS_TIMEOUT)
                    .await
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            format!("隧道内解析域名 {name} 失败: {e}"),
                        )
                    })?;
                let ip = ips.into_iter().next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("域名 {name} 未解析到地址"),
                    )
                })?;
                Ok(SocketAddr::new(ip, port))
            }
        }
    }
}

/// 隧道内的 UDP 数据报通道：绑定虚拟网卡的一个 UDP socket，只认来自
/// `target` 的回包（对齐 `Datagram` trait 单一对端的语义）。
struct WgDatagram {
    sock: TunnelUdpSocket,
    target: SocketAddr,
}

#[async_trait]
impl Datagram for WgDatagram {
    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<()> {
        self.sock.send_to(buf, self.target).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let (n, from) = self.sock.recv_from(buf).await?;
            if from == self.target {
                return Ok(n);
            }
        }
    }
}

#[async_trait]
impl Outbound for WgOutbound {
    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Box<dyn Stream>> {
        // smoltcp 对未响应的 SYN 只会把重传间隔倍增到 60s 封顶，不加超时会永远挂着。
        let addr = self.resolve_target(host, port).await?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, self.net.tcp_connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("连接 {addr} 超时（{CONNECT_TIMEOUT:?}）"),
                )
            })??;
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, host: Host, port: u16) -> std::io::Result<Box<dyn Datagram>> {
        let target = self.resolve_target(host, port).await?;
        let sock = self
            .net
            .udp_bind("0.0.0.0:0".parse().unwrap())
            .await
            .map_err(|e| std::io::Error::other(format!("绑定隧道内 UDP socket 失败: {e}")))?;
        Ok(Box::new(WgDatagram { sock, target }))
    }
}
