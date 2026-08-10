// boringtun 的 Tunn 是纯 sans-I/O 状态机，这里负责：UDP 收发、reserved
// bytes 覆写(发送)/清零(接收)、可选的 t1/t2 decoy 伪装包、握手与重传定时器驱动。
//
// Phase 0 已在生产网络验证：reserved bytes 覆写/清零是握手能否成功的必需
// 机制；t1/t2 decoy 包不是必需项（默认关闭更快），但保留作为可选开关，
// 应对未来审查策略变化。
//
// Phase 2 起 WgTunnel 本身实现项目内 netstack 的 AsyncDevice（Stream+Sink），
// 握手完成后交给 Net 常驻做虚拟网卡：Stream 产出隧道解密后的
// 明文 IP 包，Sink 把虚拟网卡要发的明文 IP 包重新加密发出去。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::channel::mpsc;
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::Rng;
use smoltcp::phy::{DeviceCapabilities, Medium};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::netstack::AsyncDevice;

use crate::config::WgConfig;

// 对应 warp-plus `--wgconf` 模式硬编码的隧道 MTU（app/app.go: runWireguard()）。
const TUNNEL_MTU: usize = 1330;
// 密文包缓冲区：MTU + WireGuard 数据包开销，留足余量。
const PACKET_BUF: usize = 2048;
// WireGuard 密文会以 MTU 大小的数据报突发到达。系统默认 UDP 缓冲通常只有
// 数百 KiB，在视频和多连接下载时会先于 userspace reactor 被打满；单隧道
// 申请数 MiB 缓冲，以吸收调度抖动和突发，而不是依赖丢包后的 TCP/rekey 恢复。
const OUTER_UDP_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const DEVICE_CHANNEL_CAPACITY: usize = 1024;
const DEVICE_MAX_BURST_SIZE: usize = 100;
const OUTER_RX_BURST_SIZE: usize = 64;
const STALL_DIAGNOSTIC_AFTER: Duration = Duration::from_secs(10);
const STALL_DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(10);
const STALL_ACTIVE_TX_WINDOW: Duration = Duration::from_secs(2);
const OUTER_UDP_REBIND_COOLDOWN: Duration = Duration::from_secs(30);
const DECAP_ERROR_REPORT_INTERVAL: Duration = Duration::from_secs(10);
static NEXT_GENERATION_ID: AtomicU64 = AtomicU64::new(1);

/// 当前 WireGuard 代际的数据面活性。只记录隧道内业务 IP 包，握手和
/// keepalive 等控制报文不会掩盖数据面失联。
pub(crate) struct TunnelActivity {
    started_at: Instant,
    next_event: AtomicU64,
    last_tx_event: AtomicU64,
    last_rx_event: AtomicU64,
    unanswered_since_millis: AtomicU64,
    business_tx_packets: AtomicU64,
    authenticated_rx_packets: AtomicU64,
    last_business_tx_millis: AtomicU64,
    last_authenticated_rx_millis: AtomicU64,
    dropped_inner_packets: AtomicU64,
    outer_rx_packets: AtomicU64,
    outer_tx_packets: AtomicU64,
    last_outer_rx_millis: AtomicU64,
}

impl TunnelActivity {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            next_event: AtomicU64::new(1),
            last_tx_event: AtomicU64::new(0),
            // 创建代际本身作为接收基线；只有后续确实发送业务包且超过
            // quiet_for 后仍无已认证业务回包，才允许判为失联。
            last_rx_event: AtomicU64::new(1),
            unanswered_since_millis: AtomicU64::new(0),
            business_tx_packets: AtomicU64::new(0),
            authenticated_rx_packets: AtomicU64::new(0),
            last_business_tx_millis: AtomicU64::new(0),
            last_authenticated_rx_millis: AtomicU64::new(0),
            dropped_inner_packets: AtomicU64::new(0),
            outer_rx_packets: AtomicU64::new(0),
            outer_tx_packets: AtomicU64::new(0),
            last_outer_rx_millis: AtomicU64::new(0),
        }
    }

    fn mark_tx(&self) {
        let now = self.elapsed_millis();
        let previous_tx = self.last_tx_event.load(Ordering::Acquire);
        let last_rx = self.last_rx_event.load(Ordering::Acquire);
        if previous_tx <= last_rx {
            self.unanswered_since_millis.store(now, Ordering::Relaxed);
        }
        self.business_tx_packets.fetch_add(1, Ordering::Relaxed);
        self.last_business_tx_millis.store(now, Ordering::Relaxed);
        let event = self.next_event.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_tx_event.store(event, Ordering::Release);
    }

    fn mark_authenticated_rx(&self) {
        let now = self.elapsed_millis();
        self.authenticated_rx_packets
            .fetch_add(1, Ordering::Relaxed);
        self.last_authenticated_rx_millis
            .store(now, Ordering::Relaxed);
        let event = self.next_event.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_rx_event.store(event, Ordering::Release);
    }

    fn mark_inner_drop(&self) -> u64 {
        self.dropped_inner_packets.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn mark_outer_rx(&self) {
        self.outer_rx_packets.fetch_add(1, Ordering::Relaxed);
        self.last_outer_rx_millis
            .store(self.elapsed_millis(), Ordering::Relaxed);
    }

    fn mark_outer_tx(&self) {
        self.outer_tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> TunnelSnapshot {
        let elapsed_millis = self.elapsed_millis();
        let business_tx_packets = self.business_tx_packets.load(Ordering::Relaxed);
        let authenticated_rx_packets = self.authenticated_rx_packets.load(Ordering::Relaxed);
        TunnelSnapshot {
            business_tx_packets,
            authenticated_rx_packets,
            outer_rx_packets: self.outer_rx_packets.load(Ordering::Relaxed),
            outer_tx_packets: self.outer_tx_packets.load(Ordering::Relaxed),
            last_business_tx_age: event_age(
                elapsed_millis,
                business_tx_packets,
                self.last_business_tx_millis.load(Ordering::Relaxed),
            ),
            last_authenticated_rx_age: event_age(
                elapsed_millis,
                authenticated_rx_packets,
                self.last_authenticated_rx_millis.load(Ordering::Relaxed),
            ),
            outer_rx_silent_for: Duration::from_millis(
                elapsed_millis.saturating_sub(self.last_outer_rx_millis.load(Ordering::Relaxed)),
            ),
            netstack_rx_dropped: self.dropped_inner_packets.load(Ordering::Relaxed),
        }
    }

    /// 若最后一次业务发送后持续没有已认证业务回包，返回静默时长。
    pub(crate) fn stalled_for(&self, quiet_for: Duration) -> Option<Duration> {
        let last_tx = self.last_tx_event.load(Ordering::Acquire);
        let last_rx = self.last_rx_event.load(Ordering::Acquire);
        let unanswered_for = Duration::from_millis(
            self.elapsed_millis()
                .saturating_sub(self.unanswered_since_millis.load(Ordering::Relaxed)),
        );
        stall_duration(last_tx, last_rx, unanswered_for, quiet_for)
    }

    fn elapsed_millis(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

fn event_age(elapsed_millis: u64, count: u64, last_millis: u64) -> Option<Duration> {
    (count > 0).then(|| Duration::from_millis(elapsed_millis.saturating_sub(last_millis)))
}

pub(crate) struct TunnelSnapshot {
    pub(crate) business_tx_packets: u64,
    pub(crate) authenticated_rx_packets: u64,
    pub(crate) outer_rx_packets: u64,
    pub(crate) outer_tx_packets: u64,
    pub(crate) last_business_tx_age: Option<Duration>,
    pub(crate) last_authenticated_rx_age: Option<Duration>,
    pub(crate) outer_rx_silent_for: Duration,
    pub(crate) netstack_rx_dropped: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum StallEvent {
    Started { silent_for: Duration },
    Ongoing { silent_for: Duration },
    Recovered { stalled_for: Duration },
}

#[derive(Default)]
struct StallTracker {
    suspected_since: Option<Duration>,
    last_report_at: Option<Duration>,
}

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

impl StallTracker {
    fn clear(&mut self) {
        self.suspected_since = None;
        self.last_report_at = None;
    }

    fn observe(&mut self, now: Duration, stalled_for: Option<Duration>) -> Option<StallEvent> {
        match (self.suspected_since, stalled_for) {
            (None, Some(silent_for)) => {
                self.suspected_since = Some(now.saturating_sub(silent_for));
                self.last_report_at = Some(now);
                Some(StallEvent::Started { silent_for })
            }
            (Some(_), Some(silent_for))
                if self
                    .last_report_at
                    .is_some_and(|last| now.saturating_sub(last) >= STALL_DIAGNOSTIC_INTERVAL) =>
            {
                self.last_report_at = Some(now);
                Some(StallEvent::Ongoing { silent_for })
            }
            (Some(since), None) => {
                self.suspected_since = None;
                self.last_report_at = None;
                Some(StallEvent::Recovered {
                    stalled_for: now.saturating_sub(since),
                })
            }
            _ => None,
        }
    }
}

fn stall_duration(
    last_tx_event: u64,
    last_rx_event: u64,
    unanswered_for: Duration,
    quiet_for: Duration,
) -> Option<Duration> {
    (last_tx_event > last_rx_event && unanswered_for >= quiet_for).then_some(unanswered_for)
}

fn has_recent_business_tx(last_business_tx_age: Option<Duration>, active_window: Duration) -> bool {
    last_business_tx_age.is_some_and(|age| age <= active_window)
}

fn confirmed_outer_stall(
    authenticated_stall: Option<Duration>,
    outer_rx_silent_for: Duration,
    threshold: Duration,
) -> Option<Duration> {
    authenticated_stall.filter(|_| outer_rx_silent_for >= threshold)
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
    activity: Arc<TunnelActivity>,
    endpoint: SocketAddr,
    generation_id: u64,
    decap_errors: DecapErrorTracker,
    last_outer_udp_rebind_at: Option<Instant>,
}

/// smoltcp 看到的异步 packet device。WireGuard 状态机和 outer UDP socket
/// 由独立 transport task 持有，避免 smoltcp 发送背压阻塞 outer UDP 接收。
pub struct WgDevice {
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<io::Result<Vec<u8>>>,
    caps: DeviceCapabilities,
    task: JoinHandle<()>,
}

impl WgTunnel {
    pub async fn connect(config: &WgConfig, trick: Trick) -> Result<Self> {
        let static_private = StaticSecret::from(config.private_key);
        let peer_public = PublicKey::from(config.peer_public_key);
        // 对齐 boringtun 正式 Device：peer index 必须是随机、非零的 24-bit
        // 值。固定为 0 会让同一私钥的重握手/重建会话重复使用 sender index。
        let peer_index = rand::thread_rng().gen_range(1..=0x00ff_ffff);
        let tunn = Tunn::new(static_private, peer_public, None, Some(5), peer_index, None)
            .map_err(|error| anyhow::anyhow!("创建 WireGuard 状态机失败: {error}"))?;

        let sock = outer_udp_socket(config.endpoint)?;

        Ok(Self {
            tunn,
            sock,
            reserved: config.reserved,
            trick,
            activity: Arc::new(TunnelActivity::new()),
            endpoint: config.endpoint,
            generation_id: NEXT_GENERATION_ID.fetch_add(1, Ordering::Relaxed),
            decap_errors: DecapErrorTracker::default(),
            last_outer_udp_rebind_at: None,
        })
    }

    /// 返回与本隧道代际绑定的数据面活性句柄。
    pub(crate) fn activity(&self) -> Arc<TunnelActivity> {
        self.activity.clone()
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
        // 的 future 会被判定为非 Send，而 recover() 作为 Outbound trait 方法必须
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

    /// 握手完成后启动常驻 transport task，并返回供 smoltcp 使用的 packet device。
    #[must_use]
    pub fn start(self) -> WgDevice {
        let (outbound, outbound_rx) = mpsc::channel(DEVICE_CHANNEL_CAPACITY);
        let (inbound_tx, inbound) = mpsc::channel(DEVICE_CHANNEL_CAPACITY);
        let task = tokio::spawn(async move {
            if let Err(error) = self.run(outbound_rx, inbound_tx.clone()).await {
                let _ = inbound_tx.clone().send(Err(error)).await;
            }
        });
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUNNEL_MTU;
        caps.max_burst_size = Some(DEVICE_MAX_BURST_SIZE);
        WgDevice {
            outbound,
            inbound,
            caps,
            task,
        }
    }

    async fn run(
        mut self,
        mut outbound: mpsc::Receiver<Vec<u8>>,
        mut inbound: mpsc::Sender<io::Result<Vec<u8>>>,
    ) -> io::Result<()> {
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut raw = [0u8; PACKET_BUF];
        let mut stall_tracker = StallTracker::default();

        loop {
            tokio::select! {
                received = self.sock.recv(&mut raw) => {
                    let size = received?;
                    self.activity.mark_outer_rx();
                    self.handle_network_packet(&mut raw[..size], &mut inbound).await?;
                    for _ in 1..OUTER_RX_BURST_SIZE {
                        match self.sock.try_recv(&mut raw) {
                            Ok(size) => {
                                self.activity.mark_outer_rx();
                                self.handle_network_packet(&mut raw[..size], &mut inbound).await?;
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error),
                        }
                    }
                }
                packet = outbound.next() => {
                    let Some(packet) = packet else { return Ok(()); };
                    self.send_plaintext(&packet).await?;
                }
                _ = timer.tick() => self.tick().await?,
            }
            self.observe_stall(&mut stall_tracker).await;
        }
    }

    async fn observe_stall(&mut self, tracker: &mut StallTracker) {
        let now = self.activity.started_at.elapsed();
        let snapshot = self.activity.snapshot();
        if !has_recent_business_tx(snapshot.last_business_tx_age, STALL_ACTIVE_TX_WINDOW) {
            tracker.clear();
            return;
        }
        let stalled_for = confirmed_outer_stall(
            self.activity.stalled_for(STALL_DIAGNOSTIC_AFTER),
            snapshot.outer_rx_silent_for,
            STALL_DIAGNOSTIC_AFTER,
        );
        let Some(event) = tracker.observe(now, stalled_for) else {
            return;
        };
        let should_rebind = matches!(event, StallEvent::Started { .. });
        let (handshake_age, tx_bytes, rx_bytes, loss, handshake_rtt_ms) = self.tunn.stats();
        match event {
            StallEvent::Started { silent_for } | StallEvent::Ongoing { silent_for } => log::warn!(
                "WireGuard 数据面疑似停滞: endpoint={}, generation={}, silent_for={:?}, business_tx={}, authenticated_rx={}, outer_tx={}, outer_rx={}, last_business_tx_age={:?}, last_authenticated_rx_age={:?}, outer_rx_silent_for={:?}, netstack_rx_dropped={}, handshake_age={:?}, tunn_tx_bytes={}, tunn_rx_bytes={}, loss={:.4}, handshake_rtt_ms={:?}",
                self.endpoint,
                self.generation_id,
                silent_for,
                snapshot.business_tx_packets,
                snapshot.authenticated_rx_packets,
                snapshot.outer_tx_packets,
                snapshot.outer_rx_packets,
                snapshot.last_business_tx_age,
                snapshot.last_authenticated_rx_age,
                snapshot.outer_rx_silent_for,
                snapshot.netstack_rx_dropped,
                handshake_age,
                tx_bytes,
                rx_bytes,
                loss,
                handshake_rtt_ms,
            ),
            StallEvent::Recovered { stalled_for } => log::info!(
                "WireGuard 数据面恢复: endpoint={}, generation={}, stalled_for={:?}, business_tx={}, authenticated_rx={}, outer_tx={}, outer_rx={}, netstack_rx_dropped={}",
                self.endpoint,
                self.generation_id,
                stalled_for,
                snapshot.business_tx_packets,
                snapshot.authenticated_rx_packets,
                snapshot.outer_tx_packets,
                snapshot.outer_rx_packets,
                snapshot.netstack_rx_dropped,
            ),
        }

        if should_rebind {
            self.rebind_outer_udp().await;
        }
    }

    async fn rebind_outer_udp(&mut self) {
        let now = Instant::now();
        if self
            .last_outer_udp_rebind_at
            .is_some_and(|last| now.saturating_duration_since(last) < OUTER_UDP_REBIND_COOLDOWN)
        {
            return;
        }
        self.last_outer_udp_rebind_at = Some(now);

        let previous_local = self.sock.local_addr().ok();
        let new_sock = match outer_udp_socket(self.endpoint) {
            Ok(sock) => sock,
            Err(error) => {
                log::warn!(
                    "WireGuard outer UDP rebind 创建失败: endpoint={}, generation={}, previous_local={previous_local:?}, error={error:#}",
                    self.endpoint,
                    self.generation_id,
                );
                return;
            }
        };
        let current_local = new_sock.local_addr().ok();
        let mut buf = [0u8; PACKET_BUF];
        let packet = match self.tunn.format_handshake_initiation(&mut buf, true) {
            TunnResult::WriteToNetwork(packet) => packet,
            other => {
                log::warn!(
                    "WireGuard outer UDP rebind 重握手失败: endpoint={}, generation={}, result={other:?}",
                    self.endpoint,
                    self.generation_id,
                );
                return;
            }
        };
        self.patch_reserved(packet);
        if let Err(error) = new_sock.send(packet).await {
            log::warn!(
                "WireGuard outer UDP rebind 发送失败: endpoint={}, generation={}, current_local={current_local:?}, error={error}",
                self.endpoint,
                self.generation_id,
            );
            return;
        }

        self.activity.mark_outer_tx();
        self.sock = new_sock;
        log::warn!(
            "WireGuard outer UDP 已重绑: endpoint={}, generation={}, previous_local={previous_local:?}, current_local={current_local:?}",
            self.endpoint,
            self.generation_id,
        );
    }

    async fn send_plaintext(&mut self, packet: &[u8]) -> io::Result<()> {
        let mut buf = [0u8; PACKET_BUF];
        match self.tunn.encapsulate(packet, &mut buf) {
            TunnResult::WriteToNetwork(encrypted) => {
                self.send_network_packet(encrypted).await?;
                self.activity.mark_tx();
                Ok(())
            }
            TunnResult::Done => Ok(()),
            other => Err(io::Error::other(format!("encapsulate 异常: {other:?}"))),
        }
    }

    async fn handle_network_packet(
        &mut self,
        packet: &mut [u8],
        inbound: &mut mpsc::Sender<io::Result<Vec<u8>>>,
    ) -> io::Result<()> {
        Self::strip_reserved(packet);
        let mut response = [0u8; PACKET_BUF];
        let mut result = self.tunn.decapsulate(None, packet, &mut response);
        loop {
            match result {
                TunnResult::Done => return Ok(()),
                TunnResult::Err(error) => {
                    self.observe_decap_error(&error);
                    return Ok(());
                }
                TunnResult::WriteToNetwork(reply) => {
                    self.send_network_packet(reply).await?;
                    result = self.tunn.decapsulate(None, &[], &mut response);
                }
                TunnResult::WriteToTunnelV4(plain, _) | TunnResult::WriteToTunnelV6(plain, _) => {
                    self.activity.mark_authenticated_rx();
                    return deliver_inner_packet(inbound, &self.activity, plain.to_vec());
                }
            }
        }
    }

    fn observe_decap_error(&mut self, error: &WireGuardError) {
        let now = self.activity.started_at.elapsed();
        let Some(report) = self.decap_errors.observe(now) else {
            return;
        };
        if decap_error_is_warning(error) {
            log::warn!(
                "WireGuard 解密报文被拒绝: endpoint={}, generation={}, class={}, error={error:?}, total={}, since_last_report={}",
                self.endpoint,
                self.generation_id,
                decap_error_class(error),
                report.total,
                report.since_last_report,
            );
        } else {
            log::debug!(
                "WireGuard 重复报文已丢弃: endpoint={}, generation={}, error={error:?}, total={}, since_last_report={}",
                self.endpoint,
                self.generation_id,
                report.total,
                report.since_last_report,
            );
        }
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
                        TunnResult::Done => break,
                        TunnResult::Err(error) => {
                            self.observe_decap_error(&error);
                            break;
                        }
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

        self.tick().await?;
        Ok(())
    }

    // 驱动重传/keepalive 定时器；握手阶段的轮询循环里按需调用。
    async fn tick(&mut self) -> io::Result<()> {
        let mut buf = [0u8; PACKET_BUF];
        match self.tunn.update_timers(&mut buf) {
            TunnResult::WriteToNetwork(packet) => self.send_network_packet(packet).await?,
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                match self.tunn.format_handshake_initiation(&mut buf, false) {
                    TunnResult::WriteToNetwork(packet) => self.send_network_packet(packet).await?,
                    TunnResult::Done => {}
                    other => {
                        return Err(io::Error::other(format!(
                            "WireGuard 连接过期后重握手失败: {other:?}"
                        )))
                    }
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

    async fn send_network_packet(&mut self, packet: &mut [u8]) -> io::Result<()> {
        self.patch_reserved(packet);
        self.sock.send(packet).await?;
        self.activity.mark_outer_tx();
        Ok(())
    }
}

fn deliver_inner_packet(
    inbound: &mut mpsc::Sender<io::Result<Vec<u8>>>,
    activity: &TunnelActivity,
    packet: Vec<u8>,
) -> io::Result<()> {
    match inbound.try_send(Ok(packet)) {
        Ok(()) => Ok(()),
        Err(error) if error.is_full() => {
            let dropped = activity.mark_inner_drop();
            if dropped == 1 || dropped.is_power_of_two() {
                log::warn!("WireGuard netstack 接收队列拥塞，已丢弃 {dropped} 个隧道内数据包");
            }
            Ok(())
        }
        Err(_) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "netstack 已停止")),
    }
}

fn outer_udp_socket(endpoint: SocketAddr) -> Result<UdpSocket> {
    let domain = Domain::for_address(endpoint);
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("创建 WireGuard outer UDP socket 失败")?;
    socket
        .set_recv_buffer_size(OUTER_UDP_BUFFER_SIZE)
        .context("设置 WireGuard outer UDP 接收缓冲失败")?;
    socket
        .set_send_buffer_size(OUTER_UDP_BUFFER_SIZE)
        .context("设置 WireGuard outer UDP 发送缓冲失败")?;
    let recv_buffer_size = socket
        .recv_buffer_size()
        .context("读取 WireGuard outer UDP 接收缓冲失败")?;
    let send_buffer_size = socket
        .send_buffer_size()
        .context("读取 WireGuard outer UDP 发送缓冲失败")?;
    log::info!(
        "WireGuard outer UDP 缓冲: endpoint={endpoint}, recv={recv_buffer_size}, send={send_buffer_size}"
    );
    socket
        .set_nonblocking(true)
        .context("设置 WireGuard outer UDP nonblocking 失败")?;

    let bind_addr = if endpoint.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0; 8], 0))
    };
    socket
        .bind(&SockAddr::from(bind_addr))
        .context("绑定 WireGuard outer UDP socket 失败")?;
    socket
        .connect(&SockAddr::from(endpoint))
        .with_context(|| format!("UDP connect 到 {endpoint} 失败"))?;
    UdpSocket::from_std(socket.into()).context("接管 WireGuard outer UDP socket 失败")
}

impl Stream for WgDevice {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().inbound).poll_next(cx)
    }
}

impl Sink<Vec<u8>> for WgDevice {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().outbound)
            .poll_ready(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard transport 已停止"))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        Pin::new(&mut self.get_mut().outbound)
            .start_send(item)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard transport 已停止"))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().outbound)
            .poll_flush(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard transport 已停止"))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().outbound)
            .poll_close(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "WireGuard transport 已停止"))
    }
}

impl AsyncDevice for WgDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}

impl Drop for WgDevice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_only_reports_stall_after_tx_and_quiet_window() {
        let activity = TunnelActivity::new();
        assert_eq!(activity.stalled_for(Duration::ZERO), None);

        activity.mark_tx();
        assert_eq!(activity.stalled_for(Duration::from_secs(1)), None);
        assert!(activity.stalled_for(Duration::ZERO).is_some());

        activity.mark_authenticated_rx();
        assert_eq!(activity.stalled_for(Duration::ZERO), None);
    }

    #[test]
    fn stall_decision_uses_first_unanswered_tx_window() {
        let quiet_for = Duration::from_secs(15);
        assert_eq!(
            stall_duration(0, 1, Duration::from_secs(60), quiet_for),
            None
        );
        assert_eq!(
            stall_duration(2, 1, Duration::from_secs(14), quiet_for),
            None
        );
        assert_eq!(
            stall_duration(3, 1, Duration::from_secs(15), quiet_for),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            stall_duration(3, 4, Duration::from_secs(60), quiet_for),
            None
        );
    }

    #[test]
    fn stall_diagnostic_requires_recent_business_tx() {
        let active_window = Duration::from_secs(2);

        assert!(has_recent_business_tx(
            Some(Duration::from_millis(500)),
            active_window
        ));
        assert!(!has_recent_business_tx(
            Some(Duration::from_secs(3)),
            active_window
        ));
        assert!(!has_recent_business_tx(None, active_window));
    }

    #[test]
    fn outer_rebind_requires_both_authenticated_and_outer_rx_silence() {
        let threshold = Duration::from_secs(10);

        assert_eq!(
            confirmed_outer_stall(Some(threshold), Duration::from_secs(9), threshold),
            None
        );
        assert_eq!(confirmed_outer_stall(None, threshold, threshold), None);
        assert_eq!(
            confirmed_outer_stall(Some(threshold), threshold, threshold),
            Some(threshold)
        );
    }

    #[test]
    fn inactive_business_clears_stall_without_recovery_event() {
        let mut tracker = StallTracker::default();
        assert!(tracker
            .observe(Duration::from_secs(10), Some(Duration::from_secs(10)))
            .is_some());

        tracker.clear();

        assert_eq!(tracker.observe(Duration::from_secs(20), None), None);
    }

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

    #[test]
    fn full_inner_queue_drops_packet_without_stopping_transport() {
        let activity = TunnelActivity::new();
        let (mut sender, _receiver) = mpsc::channel(1);
        while sender.try_send(Ok(vec![1])).is_ok() {}

        deliver_inner_packet(&mut sender, &activity, vec![2]).unwrap();

        assert_eq!(activity.snapshot().netstack_rx_dropped, 1);
    }

    #[test]
    fn closed_inner_queue_stops_transport() {
        let activity = TunnelActivity::new();
        let (mut sender, receiver) = mpsc::channel(1);
        drop(receiver);

        let error = deliver_inner_packet(&mut sender, &activity, vec![1]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn stall_tracker_reports_edges_and_rate_limits_ongoing_events() {
        let mut tracker = StallTracker::default();

        assert_eq!(tracker.observe(Duration::ZERO, None), None);
        assert_eq!(
            tracker.observe(Duration::from_secs(10), Some(Duration::from_secs(10))),
            Some(StallEvent::Started {
                silent_for: Duration::from_secs(10)
            })
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(19), Some(Duration::from_secs(19))),
            None
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(20), Some(Duration::from_secs(20))),
            Some(StallEvent::Ongoing {
                silent_for: Duration::from_secs(20)
            })
        );
        assert_eq!(
            tracker.observe(Duration::from_secs(23), None),
            Some(StallEvent::Recovered {
                stalled_for: Duration::from_secs(23)
            })
        );
        assert_eq!(tracker.observe(Duration::from_secs(24), None), None);
    }

    #[test]
    fn activity_snapshot_distinguishes_outer_and_authenticated_packets() {
        let activity = TunnelActivity::new();
        activity.mark_outer_rx();
        activity.mark_outer_tx();
        activity.mark_tx();

        let before = activity.snapshot();
        assert_eq!(before.business_tx_packets, 1);
        assert_eq!(before.authenticated_rx_packets, 0);
        assert_eq!(before.outer_rx_packets, 1);
        assert_eq!(before.outer_tx_packets, 1);
        assert!(before.last_business_tx_age.is_some());
        assert_eq!(before.last_authenticated_rx_age, None);

        activity.mark_authenticated_rx();
        let after = activity.snapshot();
        assert_eq!(after.authenticated_rx_packets, 1);
        assert!(after.last_authenticated_rx_age.is_some());
        assert_eq!(activity.stalled_for(Duration::ZERO), None);
    }
}
