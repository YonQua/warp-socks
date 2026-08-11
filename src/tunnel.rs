// boringtun 的 Tunn 是纯 sans-I/O 状态机，这里负责 UDP 收发、reserved
// bytes 覆写/清零、可选 decoy 包，以及握手与重传定时器。
//
// 握手完成后 WgTunnel 直接作为 netstack 的 AsyncDevice：同一个 reactor
// 同时驱动 smoltcp、WireGuard 状态机和 outer UDP socket，不再引入中间队列。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{Sink, Stream};
use rand::Rng;
use smoltcp::phy::{DeviceCapabilities, Medium};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::time::{Interval, MissedTickBehavior};

use crate::config::WgConfig;
use crate::dataplane::{DataPlaneObserver, DecapOutcome, Direction};
use crate::netstack::AsyncDevice;

const TUNNEL_MTU: usize = 1330;
const PACKET_BUF: usize = 2048;
const DECAP_ERROR_REPORT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
struct DecapErrorReport {
    total: u64,
    since_last_report: u64,
}

#[derive(Default)]
struct DecapErrorTracker {
    total: u64,
    since_last_report: u64,
    last_report_at: Option<Duration>,
}

impl DecapErrorTracker {
    fn observe(&mut self, now: Duration) -> Option<DecapErrorReport> {
        self.total = self.total.saturating_add(1);
        self.since_last_report = self.since_last_report.saturating_add(1);
        let should_report = self.total == 1
            || self
                .last_report_at
                .is_some_and(|last| now.saturating_sub(last) >= DECAP_ERROR_REPORT_INTERVAL);
        should_report.then(|| {
            let report = DecapErrorReport {
                total: self.total,
                since_last_report: self.since_last_report,
            };
            self.since_last_report = 0;
            self.last_report_at = Some(now);
            report
        })
    }
}

fn decap_error_class(error: &WireGuardError) -> &'static str {
    match error {
        WireGuardError::WrongIndex
        | WireGuardError::WrongKey
        | WireGuardError::NoCurrentSession
        | WireGuardError::ConnectionExpired => "session",
        WireGuardError::InvalidCounter | WireGuardError::DuplicateCounter => "replay",
        WireGuardError::InvalidMac | WireGuardError::InvalidAeadTag => "authentication",
        WireGuardError::LockFailed | WireGuardError::UnderLoad => "resource",
        WireGuardError::DestinationBufferTooSmall
        | WireGuardError::IncorrectPacketLength
        | WireGuardError::UnexpectedPacket
        | WireGuardError::WrongPacketType
        | WireGuardError::InvalidTai64nTimestamp
        | WireGuardError::WrongTai64nTimestamp
        | WireGuardError::InvalidPacket => "malformed",
    }
}

fn decap_error_is_warning(error: &WireGuardError) -> bool {
    !matches!(error, WireGuardError::DuplicateCounter)
}

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
    timer: Interval,
    started_at: Instant,
    endpoint: SocketAddr,
    observer: DataPlaneObserver,
    decap_errors: DecapErrorTracker,
    pending_network: VecDeque<Vec<u8>>,
}

impl WgTunnel {
    pub async fn connect(config: &WgConfig, trick: Trick) -> Result<Self> {
        let static_private = StaticSecret::from(config.private_key);
        let peer_public = PublicKey::from(config.peer_public_key);
        let peer_index = rand::thread_rng().gen_range(1..=0x00ff_ffff);
        let tunn = Tunn::new(static_private, peer_public, None, Some(5), peer_index, None)
            .map_err(|error| anyhow::anyhow!("创建 WireGuard 状态机失败: {error}"))?;

        let bind_addr = if config.endpoint.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0; 8], 0))
        };
        let sock = UdpSocket::bind(bind_addr)
            .await
            .context("绑定 WireGuard outer UDP socket 失败")?;
        sock.connect(config.endpoint)
            .await
            .with_context(|| format!("UDP connect 到 {} 失败", config.endpoint))?;

        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;

        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        Ok(Self {
            tunn,
            sock,
            reserved: config.reserved,
            trick,
            caps,
            timer,
            started_at: Instant::now(),
            endpoint: config.endpoint,
            observer: DataPlaneObserver::new(config.endpoint),
            decap_errors: DecapErrorTracker::default(),
            pending_network: VecDeque::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub(crate) fn observer(&self) -> DataPlaneObserver {
        self.observer.clone()
    }

    fn patch_reserved(&self, packet: &mut [u8]) {
        if packet.len() > 3 && packet[0] > 0 && packet[0] < 5 {
            packet[1..4].copy_from_slice(&self.reserved);
        }
    }

    fn strip_reserved(packet: &mut [u8]) {
        if packet.len() > 3 && packet[0] > 0 && packet[0] < 5 {
            packet[1..4].copy_from_slice(&[0, 0, 0]);
        }
    }

    fn prepare_network_packet(&self, packet: &mut [u8]) -> Vec<u8> {
        self.patch_reserved(packet);
        packet.to_vec()
    }

    fn send_or_queue_network(&mut self, packet: Vec<u8>) -> io::Result<()> {
        if self.pending_network.is_empty() {
            match self.sock.try_send(&packet) {
                Ok(size) => {
                    self.observer.record_outer_tx(size);
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        self.pending_network.push_back(packet);
        self.observer
            .record_outer_backlog(self.pending_network.len());
        Ok(())
    }

    fn poll_network_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(packet) = self.pending_network.front() {
            match self.sock.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }

            let result = self.sock.try_send(packet);
            match result {
                Ok(size) => {
                    self.observer.record_outer_tx(size);
                    self.pending_network.pop_front();
                    self.observer
                        .record_outer_backlog(self.pending_network.len());
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Poll::Ready(Ok(()))
    }

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
            let size = self.sock.send(&packet).await?;
            self.observer.record_outer_tx(size);
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
                let size = self.sock.send(packet).await?;
                self.observer.record_outer_tx(size);
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

    async fn pump_once(&mut self, wait: Duration) -> Result<()> {
        let mut recv_buf = [0u8; PACKET_BUF];
        let mut resp_buf = [0u8; PACKET_BUF];

        match tokio::time::timeout(wait, self.sock.recv(&mut recv_buf)).await {
            Ok(Ok(size)) => {
                self.observer.record_outer_rx(size);
                Self::strip_reserved(&mut recv_buf[..size]);
                let mut result = self
                    .tunn
                    .decapsulate(None, &recv_buf[..size], &mut resp_buf);
                loop {
                    match result {
                        TunnResult::Done => {
                            self.observer.record_decap(DecapOutcome::Done);
                            break;
                        }
                        TunnResult::Err(error) => {
                            self.observer.record_decap(DecapOutcome::Error);
                            self.observe_decap_error(&error);
                            break;
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            self.observer.record_decap(DecapOutcome::WriteToNetwork);
                            self.patch_reserved(packet);
                            let size = self.sock.send(packet).await?;
                            self.observer.record_outer_tx(size);
                            result = self.tunn.decapsulate(None, &[], &mut resp_buf);
                        }
                        TunnResult::WriteToTunnelV4(_, _) => {
                            self.observer.record_decap(DecapOutcome::WriteToTunnelV4);
                            break;
                        }
                        TunnResult::WriteToTunnelV6(_, _) => {
                            self.observer.record_decap(DecapOutcome::WriteToTunnelV6);
                            break;
                        }
                    }
                }
            }
            Ok(Err(error)) => return Err(error).context("UDP recv 失败"),
            Err(_) => {}
        }
        self.tick().await?;
        Ok(())
    }

    async fn tick(&mut self) -> io::Result<()> {
        let mut buf = [0u8; PACKET_BUF];
        match self.tunn.update_timers(&mut buf) {
            TunnResult::WriteToNetwork(packet) => {
                self.patch_reserved(packet);
                let size = self.sock.send(packet).await?;
                self.observer.record_outer_tx(size);
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                if let TunnResult::WriteToNetwork(packet) =
                    self.tunn.format_handshake_initiation(&mut buf, false)
                {
                    self.patch_reserved(packet);
                    let size = self.sock.send(packet).await?;
                    self.observer.record_outer_tx(size);
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(error) => {
                return Err(io::Error::other(format!(
                    "WireGuard timer 处理失败: {error:?}"
                )))
            }
            other => {
                return Err(io::Error::other(format!(
                    "WireGuard timer 返回异常: {other:?}"
                )))
            }
        }
        Ok(())
    }

    fn try_tick(&mut self) -> io::Result<()> {
        let mut buf = [0u8; PACKET_BUF];
        let packet = match self.tunn.update_timers(&mut buf) {
            TunnResult::WriteToNetwork(packet) => Some(self.prepare_network_packet(packet)),
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                match self.tunn.format_handshake_initiation(&mut buf, false) {
                    TunnResult::WriteToNetwork(packet) => Some(self.prepare_network_packet(packet)),
                    TunnResult::Done => None,
                    other => {
                        return Err(io::Error::other(format!(
                            "WireGuard 连接过期后重握手失败: {other:?}"
                        )))
                    }
                }
            }
            TunnResult::Done => None,
            TunnResult::Err(error) => {
                return Err(io::Error::other(format!(
                    "WireGuard timer 处理失败: {error:?}"
                )))
            }
            other => {
                return Err(io::Error::other(format!(
                    "WireGuard timer 返回异常: {other:?}"
                )))
            }
        };
        if let Some(packet) = packet {
            self.send_or_queue_network(packet)?;
        }
        Ok(())
    }

    fn poll_recv_plaintext(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        let mut raw = [0u8; PACKET_BUF];
        let mut read_buf = ReadBuf::new(&mut raw);
        match self.sock.poll_recv(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let size = read_buf.filled().len();
        self.observer.record_outer_rx(size);
        Self::strip_reserved(&mut raw[..size]);

        let mut response = [0u8; PACKET_BUF];
        let mut result = self.tunn.decapsulate(None, &raw[..size], &mut response);
        loop {
            match result {
                TunnResult::Done => {
                    self.observer.record_decap(DecapOutcome::Done);
                    return Poll::Ready(Ok(None));
                }
                TunnResult::Err(error) => {
                    self.observer.record_decap(DecapOutcome::Error);
                    self.observe_decap_error(&error);
                    return Poll::Ready(Ok(None));
                }
                TunnResult::WriteToNetwork(packet) => {
                    self.observer.record_decap(DecapOutcome::WriteToNetwork);
                    let packet = self.prepare_network_packet(packet);
                    if let Err(error) = self.send_or_queue_network(packet) {
                        return Poll::Ready(Err(error));
                    }
                    result = self.tunn.decapsulate(None, &[], &mut response);
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    self.observer.record_decap(DecapOutcome::WriteToTunnelV4);
                    self.observer.record_plaintext(Direction::Rx, packet);
                    return Poll::Ready(Ok(Some(packet.to_vec())));
                }
                TunnResult::WriteToTunnelV6(packet, _) => {
                    self.observer.record_decap(DecapOutcome::WriteToTunnelV6);
                    self.observer.record_plaintext(Direction::Rx, packet);
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
                if let Err(error) = this.try_tick() {
                    return Poll::Ready(Some(Err(error)));
                }
            }
            if let Poll::Ready(Err(error)) = this.poll_network_flush(cx) {
                return Poll::Ready(Some(Err(error)));
            }

            match this.poll_recv_plaintext(cx) {
                Poll::Ready(Ok(Some(packet))) => return Poll::Ready(Some(Ok(packet))),
                Poll::Ready(Ok(None)) => continue,
                Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Vec<u8>> for WgTunnel {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_network_flush(cx)
    }

    fn start_send(self: Pin<&mut Self>, packet: Vec<u8>) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.observer.record_plaintext(Direction::Tx, &packet);
        let mut encrypted = [0u8; PACKET_BUF];
        let network = match this.tunn.encapsulate(&packet, &mut encrypted) {
            TunnResult::WriteToNetwork(packet) => Some(this.prepare_network_packet(packet)),
            TunnResult::Done => None,
            other => return Err(io::Error::other(format!("encapsulate 异常: {other:?}"))),
        };
        if let Some(packet) = network {
            this.send_or_queue_network(packet)?;
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_network_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().poll_network_flush(cx)
    }
}

impl AsyncDevice for WgTunnel {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}

impl WgTunnel {
    fn observe_decap_error(&mut self, error: &WireGuardError) {
        let Some(report) = self.decap_errors.observe(self.started_at.elapsed()) else {
            return;
        };
        if decap_error_is_warning(error) {
            log::warn!(
                "WireGuard 解密报文被拒绝: endpoint={}, class={}, error={error:?}, total={}, since_last_report={}",
                self.endpoint,
                decap_error_class(error),
                report.total,
                report.since_last_report,
            );
        } else {
            log::debug!(
                "WireGuard 重复报文已丢弃: endpoint={}, error={error:?}, total={}, since_last_report={}",
                self.endpoint,
                report.total,
                report.since_last_report,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decap_error_reports_first_then_rate_limits() {
        let mut tracker = DecapErrorTracker::default();
        assert_eq!(
            tracker.observe(Duration::ZERO),
            Some(DecapErrorReport {
                total: 1,
                since_last_report: 1,
            })
        );
        assert_eq!(tracker.observe(Duration::from_secs(9)), None);
        assert_eq!(
            tracker.observe(Duration::from_secs(10)),
            Some(DecapErrorReport {
                total: 3,
                since_last_report: 2,
            })
        );
    }

    #[test]
    fn decap_error_classes_are_stable() {
        assert_eq!(
            decap_error_class(&WireGuardError::NoCurrentSession),
            "session"
        );
        assert_eq!(
            decap_error_class(&WireGuardError::DuplicateCounter),
            "replay"
        );
        assert_eq!(
            decap_error_class(&WireGuardError::InvalidAeadTag),
            "authentication"
        );
        assert_eq!(decap_error_class(&WireGuardError::UnderLoad), "resource");
        assert_eq!(
            decap_error_class(&WireGuardError::InvalidPacket),
            "malformed"
        );
        assert!(!decap_error_is_warning(&WireGuardError::DuplicateCounter));
        assert!(decap_error_is_warning(&WireGuardError::InvalidAeadTag));
    }
}
