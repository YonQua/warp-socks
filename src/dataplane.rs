//! WireGuard 数据面只读观测。
//!
//! 所有热路径只更新原子计数器；独立 reporter 每 5 秒输出一个聚合窗口。
//! TCP 只记录头部元数据，不保留 IP 地址或任何载荷内容。

use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket};

pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Rx,
    Tx,
}

#[derive(Clone, Copy)]
pub(crate) enum DecapOutcome {
    Done,
    WriteToNetwork,
    WriteToTunnelV4,
    WriteToTunnelV6,
    Error,
}

#[derive(Clone)]
pub(crate) struct DataPlaneObserver {
    inner: Arc<ObserverInner>,
}

pub(crate) struct WeakDataPlaneObserver {
    inner: Weak<ObserverInner>,
}

struct ObserverInner {
    endpoint: SocketAddr,
    started_at: Instant,
    outer_rx_packets: AtomicU64,
    outer_rx_bytes: AtomicU64,
    outer_tx_packets: AtomicU64,
    outer_tx_bytes: AtomicU64,
    outer_tx_dropped: AtomicU64,
    device_tx_dropped: AtomicU64,
    decap_done: AtomicU64,
    decap_write_network: AtomicU64,
    decap_v4: AtomicU64,
    decap_v6: AtomicU64,
    decap_errors: AtomicU64,
    plain_rx_packets: AtomicU64,
    plain_rx_bytes: AtomicU64,
    plain_tx_packets: AtomicU64,
    plain_tx_bytes: AtomicU64,
    tcp_rx: TcpDirectionCounters,
    tcp_tx: TcpDirectionCounters,
    bulk_flow: BulkFlowCounters,
    outer_backlog_current: AtomicU64,
    outer_backlog_peak: AtomicU64,
    device_rx_backlog: AtomicU64,
    device_tx_backlog: AtomicU64,
    device_rx_backlog_peak: AtomicU64,
    device_tx_backlog_peak: AtomicU64,
    reactor_loops: AtomicU64,
    reactor_wake_calls: AtomicU64,
    reactor_waits: AtomicU64,
    reactor_device_wakes: AtomicU64,
    reactor_notify_wakes: AtomicU64,
    reactor_timer_wakes: AtomicU64,
    reactor_polls: AtomicU64,
    reactor_last_progress_ms: AtomicU64,
    reactor_max_gap_ms: AtomicU64,
}

#[derive(Default)]
struct TcpDirectionCounters {
    packets: AtomicU64,
    payload_bytes: AtomicU64,
    ack_packets: AtomicU64,
    ack_only_packets: AtomicU64,
    last_at_ms: AtomicU64,
    last_ports: AtomicU64,
    last_seq: AtomicU64,
    last_ack: AtomicU64,
    last_flags: AtomicU64,
    last_payload_len: AtomicU64,
}

#[derive(Default)]
struct BulkFlowCounters {
    ports: AtomicU64,
    rx_at_ms: AtomicU64,
    rx_seq: AtomicU64,
    rx_ack: AtomicU64,
    rx_payload_len: AtomicU64,
    ack_at_ms: AtomicU64,
    ack_seq: AtomicU64,
    ack_ack: AtomicU64,
}

#[derive(Clone, Copy, Default)]
struct CounterSnapshot {
    outer_rx_packets: u64,
    outer_rx_bytes: u64,
    outer_tx_packets: u64,
    outer_tx_bytes: u64,
    outer_tx_dropped: u64,
    device_tx_dropped: u64,
    decap_done: u64,
    decap_write_network: u64,
    decap_v4: u64,
    decap_v6: u64,
    decap_errors: u64,
    plain_rx_packets: u64,
    plain_rx_bytes: u64,
    plain_tx_packets: u64,
    plain_tx_bytes: u64,
    tcp_rx_packets: u64,
    tcp_rx_payload_bytes: u64,
    tcp_rx_ack_packets: u64,
    tcp_rx_ack_only_packets: u64,
    tcp_tx_packets: u64,
    tcp_tx_payload_bytes: u64,
    tcp_tx_ack_packets: u64,
    tcp_tx_ack_only_packets: u64,
    reactor_loops: u64,
    reactor_wake_calls: u64,
    reactor_waits: u64,
    reactor_device_wakes: u64,
    reactor_notify_wakes: u64,
    reactor_timer_wakes: u64,
    reactor_polls: u64,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SocketSnapshot {
    pub tcp_total: usize,
    pub tcp_established: usize,
    pub tcp_connecting: usize,
    pub tcp_closing: usize,
    pub tcp_closed: usize,
    pub tcp_rx_queue: usize,
    pub tcp_tx_queue: usize,
    pub udp_total: usize,
}

#[derive(Clone, Copy, Default)]
struct CpuSnapshot {
    usage_usec: u64,
    nr_periods: u64,
    nr_throttled: u64,
    throttled_usec: u64,
}

pub(crate) struct ReportState {
    counters: CounterSnapshot,
    cpu: Option<CpuSnapshot>,
}

impl Default for ReportState {
    fn default() -> Self {
        Self {
            counters: CounterSnapshot::default(),
            cpu: read_cpu_snapshot(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ReactorWake {
    Device,
    Notify,
    Timer,
}

impl DataPlaneObserver {
    pub(crate) fn new(endpoint: SocketAddr) -> Self {
        Self {
            inner: Arc::new(ObserverInner {
                endpoint,
                started_at: Instant::now(),
                outer_rx_packets: AtomicU64::new(0),
                outer_rx_bytes: AtomicU64::new(0),
                outer_tx_packets: AtomicU64::new(0),
                outer_tx_bytes: AtomicU64::new(0),
                outer_tx_dropped: AtomicU64::new(0),
                device_tx_dropped: AtomicU64::new(0),
                decap_done: AtomicU64::new(0),
                decap_write_network: AtomicU64::new(0),
                decap_v4: AtomicU64::new(0),
                decap_v6: AtomicU64::new(0),
                decap_errors: AtomicU64::new(0),
                plain_rx_packets: AtomicU64::new(0),
                plain_rx_bytes: AtomicU64::new(0),
                plain_tx_packets: AtomicU64::new(0),
                plain_tx_bytes: AtomicU64::new(0),
                tcp_rx: TcpDirectionCounters::default(),
                tcp_tx: TcpDirectionCounters::default(),
                bulk_flow: BulkFlowCounters::default(),
                outer_backlog_current: AtomicU64::new(0),
                outer_backlog_peak: AtomicU64::new(0),
                device_rx_backlog: AtomicU64::new(0),
                device_tx_backlog: AtomicU64::new(0),
                device_rx_backlog_peak: AtomicU64::new(0),
                device_tx_backlog_peak: AtomicU64::new(0),
                reactor_loops: AtomicU64::new(0),
                reactor_wake_calls: AtomicU64::new(0),
                reactor_waits: AtomicU64::new(0),
                reactor_device_wakes: AtomicU64::new(0),
                reactor_notify_wakes: AtomicU64::new(0),
                reactor_timer_wakes: AtomicU64::new(0),
                reactor_polls: AtomicU64::new(0),
                reactor_last_progress_ms: AtomicU64::new(0),
                reactor_max_gap_ms: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn downgrade(&self) -> WeakDataPlaneObserver {
        WeakDataPlaneObserver {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub(crate) fn record_outer_rx(&self, bytes: usize) {
        add(&self.inner.outer_rx_packets, 1);
        add(&self.inner.outer_rx_bytes, bytes);
    }

    pub(crate) fn record_outer_tx(&self, bytes: usize) {
        add(&self.inner.outer_tx_packets, 1);
        add(&self.inner.outer_tx_bytes, bytes);
    }

    pub(crate) fn record_outer_tx_dropped(&self) {
        add(&self.inner.outer_tx_dropped, 1);
    }

    pub(crate) fn record_device_tx_dropped(&self, packets: usize) {
        add(&self.inner.device_tx_dropped, packets);
    }

    pub(crate) fn record_decap(&self, outcome: DecapOutcome) {
        let counter = match outcome {
            DecapOutcome::Done => &self.inner.decap_done,
            DecapOutcome::WriteToNetwork => &self.inner.decap_write_network,
            DecapOutcome::WriteToTunnelV4 => &self.inner.decap_v4,
            DecapOutcome::WriteToTunnelV6 => &self.inner.decap_v6,
            DecapOutcome::Error => &self.inner.decap_errors,
        };
        add(counter, 1);
    }

    pub(crate) fn record_plaintext(&self, direction: Direction, packet: &[u8]) {
        let (packets, bytes, tcp) = match direction {
            Direction::Rx => (
                &self.inner.plain_rx_packets,
                &self.inner.plain_rx_bytes,
                &self.inner.tcp_rx,
            ),
            Direction::Tx => (
                &self.inner.plain_tx_packets,
                &self.inner.plain_tx_bytes,
                &self.inner.tcp_tx,
            ),
        };
        add(packets, 1);
        add(bytes, packet.len());
        if let Some(tcp_packet) = tcp_packet(packet) {
            let now_ms = self.elapsed_ms();
            tcp.record(now_ms, &tcp_packet);
            self.inner.bulk_flow.record(direction, now_ms, &tcp_packet);
        }
    }

    pub(crate) fn record_outer_backlog(&self, current: usize) {
        set_current_and_peak(
            &self.inner.outer_backlog_current,
            &self.inner.outer_backlog_peak,
            current,
        );
    }

    pub(crate) fn record_device_backlog(&self, rx: usize, tx: usize) {
        set_current_and_peak(
            &self.inner.device_rx_backlog,
            &self.inner.device_rx_backlog_peak,
            rx,
        );
        set_current_and_peak(
            &self.inner.device_tx_backlog,
            &self.inner.device_tx_backlog_peak,
            tx,
        );
    }

    pub(crate) fn record_reactor_wake_call(&self) {
        add(&self.inner.reactor_wake_calls, 1);
    }

    pub(crate) fn record_reactor_wait(&self) {
        add(&self.inner.reactor_waits, 1);
    }

    pub(crate) fn record_reactor_wake(&self, wake: ReactorWake) {
        let counter = match wake {
            ReactorWake::Device => &self.inner.reactor_device_wakes,
            ReactorWake::Notify => &self.inner.reactor_notify_wakes,
            ReactorWake::Timer => &self.inner.reactor_timer_wakes,
        };
        add(counter, 1);
    }

    pub(crate) fn record_reactor_poll(&self) {
        add(&self.inner.reactor_polls, 1);
    }

    pub(crate) fn record_reactor_loop(&self) {
        add(&self.inner.reactor_loops, 1);
        let now = self.elapsed_ms();
        let previous = self
            .inner
            .reactor_last_progress_ms
            .swap(now, Ordering::Relaxed);
        if previous > 0 {
            update_peak(&self.inner.reactor_max_gap_ms, now.saturating_sub(previous));
        }
    }

    pub(crate) fn report_window(&self, state: &mut ReportState, sockets: SocketSnapshot) {
        let current = self.snapshot();
        let delta = current.delta(state.counters);
        state.counters = current;
        let cpu = read_cpu_snapshot();
        let cpu_delta = cpu.zip(state.cpu).map(|(now, before)| now.delta(before));
        state.cpu = cpu;
        let now_ms = self.elapsed_ms();
        let reactor_last = self.inner.reactor_last_progress_ms.load(Ordering::Relaxed);

        log::info!(
            "WireGuard 数据面窗口: endpoint={}, window={}s, outer_rx={}/{}, outer_tx={}/{}, \
             decap=done:{},net:{},v4:{},v6:{},err:{}, plain_rx={}/{}, plain_tx={}/{}, \
             tcp_rx=pkts:{},payload:{},ack:{},ack_only:{},last:{}, \
             tcp_tx=pkts:{},payload:{},ack:{},ack_only:{},last:{}, bulk={}, \
             reactor=loops:{},wake_calls:{},waits:{},device:{},notify:{},timer:{},polls:{},idle_ms:{},max_gap_ms:{}, \
             dropped=outer_tx:{},device_tx:{}, backlog=outer:{}/{},device_rx:{}/{},device_tx:{}/{}, \
             sockets=tcp:{},est:{},connecting:{},closing:{},closed:{},rxq:{},txq:{},udp:{}, cgroup={}",
            self.inner.endpoint,
            REPORT_INTERVAL.as_secs(),
            delta.outer_rx_packets,
            delta.outer_rx_bytes,
            delta.outer_tx_packets,
            delta.outer_tx_bytes,
            delta.decap_done,
            delta.decap_write_network,
            delta.decap_v4,
            delta.decap_v6,
            delta.decap_errors,
            delta.plain_rx_packets,
            delta.plain_rx_bytes,
            delta.plain_tx_packets,
            delta.plain_tx_bytes,
            delta.tcp_rx_packets,
            delta.tcp_rx_payload_bytes,
            delta.tcp_rx_ack_packets,
            delta.tcp_rx_ack_only_packets,
            self.inner.tcp_rx.last_packet(now_ms),
            delta.tcp_tx_packets,
            delta.tcp_tx_payload_bytes,
            delta.tcp_tx_ack_packets,
            delta.tcp_tx_ack_only_packets,
            self.inner.tcp_tx.last_packet(now_ms),
            self.inner.bulk_flow.summary(now_ms),
            delta.reactor_loops,
            delta.reactor_wake_calls,
            delta.reactor_waits,
            delta.reactor_device_wakes,
            delta.reactor_notify_wakes,
            delta.reactor_timer_wakes,
            delta.reactor_polls,
            now_ms.saturating_sub(reactor_last),
            self.inner.reactor_max_gap_ms.swap(0, Ordering::Relaxed),
            delta.outer_tx_dropped,
            delta.device_tx_dropped,
            self.inner.outer_backlog_current.load(Ordering::Relaxed),
            self.inner.outer_backlog_peak.swap(0, Ordering::Relaxed),
            self.inner.device_rx_backlog.load(Ordering::Relaxed),
            self.inner.device_rx_backlog_peak.swap(0, Ordering::Relaxed),
            self.inner.device_tx_backlog.load(Ordering::Relaxed),
            self.inner.device_tx_backlog_peak.swap(0, Ordering::Relaxed),
            sockets.tcp_total,
            sockets.tcp_established,
            sockets.tcp_connecting,
            sockets.tcp_closing,
            sockets.tcp_closed,
            sockets.tcp_rx_queue,
            sockets.tcp_tx_queue,
            sockets.udp_total,
            format_cpu_delta(cpu_delta),
        );
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.inner.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            outer_rx_packets: load(&self.inner.outer_rx_packets),
            outer_rx_bytes: load(&self.inner.outer_rx_bytes),
            outer_tx_packets: load(&self.inner.outer_tx_packets),
            outer_tx_bytes: load(&self.inner.outer_tx_bytes),
            outer_tx_dropped: load(&self.inner.outer_tx_dropped),
            device_tx_dropped: load(&self.inner.device_tx_dropped),
            decap_done: load(&self.inner.decap_done),
            decap_write_network: load(&self.inner.decap_write_network),
            decap_v4: load(&self.inner.decap_v4),
            decap_v6: load(&self.inner.decap_v6),
            decap_errors: load(&self.inner.decap_errors),
            plain_rx_packets: load(&self.inner.plain_rx_packets),
            plain_rx_bytes: load(&self.inner.plain_rx_bytes),
            plain_tx_packets: load(&self.inner.plain_tx_packets),
            plain_tx_bytes: load(&self.inner.plain_tx_bytes),
            tcp_rx_packets: load(&self.inner.tcp_rx.packets),
            tcp_rx_payload_bytes: load(&self.inner.tcp_rx.payload_bytes),
            tcp_rx_ack_packets: load(&self.inner.tcp_rx.ack_packets),
            tcp_rx_ack_only_packets: load(&self.inner.tcp_rx.ack_only_packets),
            tcp_tx_packets: load(&self.inner.tcp_tx.packets),
            tcp_tx_payload_bytes: load(&self.inner.tcp_tx.payload_bytes),
            tcp_tx_ack_packets: load(&self.inner.tcp_tx.ack_packets),
            tcp_tx_ack_only_packets: load(&self.inner.tcp_tx.ack_only_packets),
            reactor_loops: load(&self.inner.reactor_loops),
            reactor_wake_calls: load(&self.inner.reactor_wake_calls),
            reactor_waits: load(&self.inner.reactor_waits),
            reactor_device_wakes: load(&self.inner.reactor_device_wakes),
            reactor_notify_wakes: load(&self.inner.reactor_notify_wakes),
            reactor_timer_wakes: load(&self.inner.reactor_timer_wakes),
            reactor_polls: load(&self.inner.reactor_polls),
        }
    }
}

impl WeakDataPlaneObserver {
    pub(crate) fn upgrade(&self) -> Option<DataPlaneObserver> {
        self.inner
            .upgrade()
            .map(|inner| DataPlaneObserver { inner })
    }
}

impl TcpDirectionCounters {
    fn record(&self, now_ms: u64, packet: &TcpPacket<&[u8]>) {
        let payload_len = packet.payload().len();
        add(&self.packets, 1);
        add(&self.payload_bytes, payload_len);
        if packet.ack() {
            add(&self.ack_packets, 1);
            if payload_len == 0 && !packet.syn() && !packet.fin() && !packet.rst() {
                add(&self.ack_only_packets, 1);
            }
        }
        self.last_at_ms
            .store(now_ms.saturating_add(1), Ordering::Relaxed);
        self.last_ports.store(
            (u64::from(packet.src_port()) << 16) | u64::from(packet.dst_port()),
            Ordering::Relaxed,
        );
        self.last_seq
            .store(u64::from(packet.seq_number().0 as u32), Ordering::Relaxed);
        self.last_ack
            .store(u64::from(packet.ack_number().0 as u32), Ordering::Relaxed);
        self.last_flags.store(tcp_flags(packet), Ordering::Relaxed);
        self.last_payload_len
            .store(payload_len as u64, Ordering::Relaxed);
    }

    fn last_packet(&self, now_ms: u64) -> String {
        let at = self.last_at_ms.load(Ordering::Relaxed);
        if at == 0 {
            return "none".to_string();
        }
        let ports = self.last_ports.load(Ordering::Relaxed);
        format!(
            "{}>{},seq:{},ack:{},flags:{},payload:{},age_ms:{}",
            ports >> 16,
            ports & 0xffff,
            self.last_seq.load(Ordering::Relaxed) as u32,
            self.last_ack.load(Ordering::Relaxed) as u32,
            format_tcp_flags(self.last_flags.load(Ordering::Relaxed)),
            self.last_payload_len.load(Ordering::Relaxed),
            now_ms.saturating_sub(at.saturating_sub(1)),
        )
    }
}

impl BulkFlowCounters {
    fn record(&self, direction: Direction, now_ms: u64, packet: &TcpPacket<&[u8]>) {
        let ports = (u64::from(packet.src_port()) << 16) | u64::from(packet.dst_port());
        match direction {
            Direction::Rx if packet.payload().len() >= 1_000 => {
                self.ports.store(ports, Ordering::Relaxed);
                self.rx_at_ms
                    .store(now_ms.saturating_add(1), Ordering::Relaxed);
                self.rx_seq
                    .store(u64::from(packet.seq_number().0 as u32), Ordering::Relaxed);
                self.rx_ack
                    .store(u64::from(packet.ack_number().0 as u32), Ordering::Relaxed);
                self.rx_payload_len
                    .store(packet.payload().len() as u64, Ordering::Relaxed);
            }
            Direction::Tx if packet.ack() && packet.payload().is_empty() => {
                let bulk_ports = self.ports.load(Ordering::Relaxed);
                let reverse = ((bulk_ports & 0xffff) << 16) | (bulk_ports >> 16);
                if bulk_ports != 0 && ports == reverse {
                    self.ack_at_ms
                        .store(now_ms.saturating_add(1), Ordering::Relaxed);
                    self.ack_seq
                        .store(u64::from(packet.seq_number().0 as u32), Ordering::Relaxed);
                    self.ack_ack
                        .store(u64::from(packet.ack_number().0 as u32), Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }

    fn summary(&self, now_ms: u64) -> String {
        let ports = self.ports.load(Ordering::Relaxed);
        let rx_at = self.rx_at_ms.load(Ordering::Relaxed);
        if ports == 0 || rx_at == 0 {
            return "none".to_string();
        }
        let ack_at = self.ack_at_ms.load(Ordering::Relaxed);
        let ack = if ack_at == 0 {
            "none".to_string()
        } else {
            format!(
                "seq:{},ack:{},age_ms:{}",
                self.ack_seq.load(Ordering::Relaxed) as u32,
                self.ack_ack.load(Ordering::Relaxed) as u32,
                now_ms.saturating_sub(ack_at.saturating_sub(1)),
            )
        };
        format!(
            "{}>{},rx_seq:{},rx_ack:{},rx_payload:{},rx_age_ms:{},ack:{}",
            ports >> 16,
            ports & 0xffff,
            self.rx_seq.load(Ordering::Relaxed) as u32,
            self.rx_ack.load(Ordering::Relaxed) as u32,
            self.rx_payload_len.load(Ordering::Relaxed),
            now_ms.saturating_sub(rx_at.saturating_sub(1)),
            ack,
        )
    }
}

impl CounterSnapshot {
    fn delta(self, previous: Self) -> Self {
        macro_rules! delta {
            ($field:ident) => {
                self.$field.saturating_sub(previous.$field)
            };
        }
        Self {
            outer_rx_packets: delta!(outer_rx_packets),
            outer_rx_bytes: delta!(outer_rx_bytes),
            outer_tx_packets: delta!(outer_tx_packets),
            outer_tx_bytes: delta!(outer_tx_bytes),
            outer_tx_dropped: delta!(outer_tx_dropped),
            device_tx_dropped: delta!(device_tx_dropped),
            decap_done: delta!(decap_done),
            decap_write_network: delta!(decap_write_network),
            decap_v4: delta!(decap_v4),
            decap_v6: delta!(decap_v6),
            decap_errors: delta!(decap_errors),
            plain_rx_packets: delta!(plain_rx_packets),
            plain_rx_bytes: delta!(plain_rx_bytes),
            plain_tx_packets: delta!(plain_tx_packets),
            plain_tx_bytes: delta!(plain_tx_bytes),
            tcp_rx_packets: delta!(tcp_rx_packets),
            tcp_rx_payload_bytes: delta!(tcp_rx_payload_bytes),
            tcp_rx_ack_packets: delta!(tcp_rx_ack_packets),
            tcp_rx_ack_only_packets: delta!(tcp_rx_ack_only_packets),
            tcp_tx_packets: delta!(tcp_tx_packets),
            tcp_tx_payload_bytes: delta!(tcp_tx_payload_bytes),
            tcp_tx_ack_packets: delta!(tcp_tx_ack_packets),
            tcp_tx_ack_only_packets: delta!(tcp_tx_ack_only_packets),
            reactor_loops: delta!(reactor_loops),
            reactor_wake_calls: delta!(reactor_wake_calls),
            reactor_waits: delta!(reactor_waits),
            reactor_device_wakes: delta!(reactor_device_wakes),
            reactor_notify_wakes: delta!(reactor_notify_wakes),
            reactor_timer_wakes: delta!(reactor_timer_wakes),
            reactor_polls: delta!(reactor_polls),
        }
    }
}

impl CpuSnapshot {
    fn delta(self, previous: Self) -> Self {
        Self {
            usage_usec: self.usage_usec.saturating_sub(previous.usage_usec),
            nr_periods: self.nr_periods.saturating_sub(previous.nr_periods),
            nr_throttled: self.nr_throttled.saturating_sub(previous.nr_throttled),
            throttled_usec: self.throttled_usec.saturating_sub(previous.throttled_usec),
        }
    }
}

fn tcp_packet(packet: &[u8]) -> Option<TcpPacket<&[u8]>> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            (ip.frag_offset() == 0 && ip.next_header() == IpProtocol::Tcp)
                .then(|| TcpPacket::new_checked(ip.payload()).ok())
                .flatten()
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            (ip.next_header() == IpProtocol::Tcp)
                .then(|| TcpPacket::new_checked(ip.payload()).ok())
                .flatten()
        }
        _ => None,
    }
}

fn tcp_flags(packet: &TcpPacket<&[u8]>) -> u64 {
    u64::from(packet.fin())
        | (u64::from(packet.syn()) << 1)
        | (u64::from(packet.rst()) << 2)
        | (u64::from(packet.psh()) << 3)
        | (u64::from(packet.ack()) << 4)
        | (u64::from(packet.urg()) << 5)
        | (u64::from(packet.ece()) << 6)
        | (u64::from(packet.cwr()) << 7)
}

fn format_tcp_flags(flags: u64) -> String {
    let names = [
        (0, "F"),
        (1, "S"),
        (2, "R"),
        (3, "P"),
        (4, "A"),
        (5, "U"),
        (6, "E"),
        (7, "C"),
    ];
    let value = names
        .into_iter()
        .filter_map(|(bit, name)| ((flags & (1 << bit)) != 0).then_some(name))
        .collect::<String>();
    if value.is_empty() {
        "-".to_string()
    } else {
        value
    }
}

fn read_cpu_snapshot() -> Option<CpuSnapshot> {
    let content = fs::read_to_string("/sys/fs/cgroup/cpu.stat")
        .or_else(|_| fs::read_to_string("/sys/fs/cgroup/cpu/cpu.stat"))
        .ok()?;
    Some(parse_cpu_stat(&content))
}

fn parse_cpu_stat(content: &str) -> CpuSnapshot {
    let mut snapshot = CpuSnapshot::default();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(value) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        match name {
            "usage_usec" => snapshot.usage_usec = value,
            "nr_periods" => snapshot.nr_periods = value,
            "nr_throttled" => snapshot.nr_throttled = value,
            "throttled_usec" => snapshot.throttled_usec = value,
            "throttled_time" => snapshot.throttled_usec = value / 1_000,
            _ => {}
        }
    }
    snapshot
}

fn format_cpu_delta(cpu: Option<CpuSnapshot>) -> String {
    cpu.map_or_else(
        || "unavailable".to_string(),
        |cpu| {
            format!(
                "usage_ms:{},periods:{},throttled:{},throttled_ms:{}",
                cpu.usage_usec / 1_000,
                cpu.nr_periods,
                cpu.nr_throttled,
                cpu.throttled_usec / 1_000,
            )
        },
    )
}

fn add(counter: &AtomicU64, value: usize) {
    counter.fetch_add(value as u64, Ordering::Relaxed);
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn set_current_and_peak(current: &AtomicU64, peak: &AtomicU64, value: usize) {
    let value = value as u64;
    current.store(value, Ordering::Relaxed);
    update_peak(peak, value);
}

fn update_peak(peak: &AtomicU64, value: u64) {
    peak.fetch_max(value, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_tcp_header_metadata_without_payload_storage() {
        let observer = DataPlaneObserver::new("192.0.2.1:2408".parse().unwrap());
        let mut packet = vec![0u8; 43];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&43u16.to_be_bytes());
        packet[9] = 6;
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..28].copy_from_slice(&123u32.to_be_bytes());
        packet[28..32].copy_from_slice(&456u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x18;
        packet[40..].copy_from_slice(b"abc");

        observer.record_plaintext(Direction::Rx, &packet);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.plain_rx_packets, 1);
        assert_eq!(snapshot.tcp_rx_packets, 1);
        assert_eq!(snapshot.tcp_rx_payload_bytes, 3);
        assert_eq!(snapshot.tcp_rx_ack_packets, 1);
        assert_eq!(snapshot.tcp_rx_ack_only_packets, 0);
        assert!(observer
            .inner
            .tcp_rx
            .last_packet(observer.elapsed_ms())
            .contains("12345>443,seq:123,ack:456,flags:PA,payload:3"));
    }

    #[test]
    fn bulk_flow_tracks_only_matching_reverse_ack() {
        let observer = DataPlaneObserver::new("192.0.2.1:2408".parse().unwrap());
        let rx = ipv4_tcp_packet(443, 12345, 100, 200, 0x18, 1_240);
        observer.record_plaintext(Direction::Rx, &rx);
        let unrelated_ack = ipv4_tcp_packet(20000, 443, 300, 400, 0x10, 0);
        observer.record_plaintext(Direction::Tx, &unrelated_ack);
        let matching_ack = ipv4_tcp_packet(12345, 443, 200, 1_340, 0x10, 0);
        observer.record_plaintext(Direction::Tx, &matching_ack);

        let summary = observer.inner.bulk_flow.summary(observer.elapsed_ms());
        assert!(summary.contains("443>12345,rx_seq:100,rx_ack:200,rx_payload:1240"));
        assert!(summary.contains("ack:seq:200,ack:1340"));
    }

    #[test]
    fn parses_cgroup_v2_cpu_stat() {
        let snapshot = parse_cpu_stat(
            "usage_usec 12000\nuser_usec 9000\nsystem_usec 3000\nnr_periods 20\nnr_throttled 3\nthrottled_usec 4500\n",
        );
        assert_eq!(snapshot.usage_usec, 12000);
        assert_eq!(snapshot.nr_periods, 20);
        assert_eq!(snapshot.nr_throttled, 3);
        assert_eq!(snapshot.throttled_usec, 4500);
    }

    fn ipv4_tcp_packet(
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload_len];
        let total_len = packet.len() as u16;
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[9] = 6;
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[28..32].copy_from_slice(&acknowledgement.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }
}
