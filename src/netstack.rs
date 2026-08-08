//! 面向本项目的 Tokio/smoltcp 适配层。
//!
//! `smoltcp` 本身是同步 sans-I/O 协议栈；这里用一个后台 reactor 把异步
//! WireGuard packet device、`smoltcp::Interface` 和 socket waker 串起来。
//! 只实现 warp-socks 需要的主动 TCP 连接和 UDP socket，不提供监听器、raw
//! socket 等无关能力。
//!
//! reactor、buffer device 和 socket handle 的基础结构参考了 MIT OR
//! Apache-2.0 许可的 `tokio-smoltcp 0.6.0`，并按本项目双栈主动拨号边界裁剪。

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::{poll_fn, FutureExt};
use futures::{Sink, Stream, StreamExt};
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use smoltcp::iface::{
    Config as InterfaceConfig, Context as InterfaceContext, Interface,
    SocketHandle as InnerSocketHandle, SocketSet,
};
use smoltcp::phy::{Device, DeviceCapabilities, RxToken, TxToken};
use smoltcp::socket::{tcp, udp, AnySocket};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

const DEFAULT_MAX_BURST_SIZE: usize = 100;
const DEFAULT_POLL_INTERVAL: SmolDuration = SmolDuration::from_secs(60);
const EPHEMERAL_PORT_FIRST: u16 = 10001;
const EPHEMERAL_PORT_LAST: u16 = 60000;

/// 可被异步 reactor 驱动的原始 IP packet device。
pub trait AsyncDevice:
    Stream<Item = io::Result<Vec<u8>>> + Sink<Vec<u8>, Error = io::Error> + Send + Unpin
{
    /// 返回介质、MTU 和 burst 等设备能力。
    fn capabilities(&self) -> &DeviceCapabilities;
}

/// 每种 socket 的缓冲区配置。
#[derive(Debug, Clone, Copy)]
pub struct BufferSize {
    pub tcp_rx_size: usize,
    pub tcp_tx_size: usize,
    pub udp_rx_size: usize,
    pub udp_tx_size: usize,
    pub udp_rx_meta_size: usize,
    pub udp_tx_meta_size: usize,
}

impl Default for BufferSize {
    fn default() -> Self {
        Self {
            tcp_rx_size: 8192,
            tcp_tx_size: 8192,
            udp_rx_size: 8192,
            udp_tx_size: 8192,
            udp_rx_meta_size: 32,
            udp_tx_meta_size: 32,
        }
    }
}

/// 双栈虚拟网卡配置。
pub struct NetConfig {
    pub interface_config: InterfaceConfig,
    pub ip_addrs: Vec<IpCidr>,
    pub gateways: Vec<IpAddress>,
    pub buffer_size: BufferSize,
}

impl NetConfig {
    /// 创建网络栈配置。
    pub fn new(
        interface_config: InterfaceConfig,
        ip_addrs: Vec<IpCidr>,
        gateways: Vec<IpAddress>,
    ) -> Self {
        Self {
            interface_config,
            ip_addrs,
            gateways,
            buffer_size: BufferSize::default(),
        }
    }
}

/// 运行于 WireGuard packet device 上的双栈 TCP/UDP 网络栈。
pub struct Net {
    reactor: Arc<Reactor>,
    source_v4: Option<IpAddress>,
    source_v6: Option<IpAddress>,
    stopper: Arc<Notify>,
}

impl Net {
    /// 创建网络栈并启动后台 reactor。
    ///
    /// # Errors
    /// 配置缺少地址、地址重复，或默认路由无法安装时返回错误。
    pub fn new<D: AsyncDevice + 'static>(device: D, config: NetConfig) -> io::Result<Self> {
        let caps = device.capabilities().clone();
        let mut buffered = BufferDevice::new(caps);
        let mut interface =
            Interface::new(config.interface_config, &mut buffered, SmolInstant::now());

        if config.ip_addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "netstack 至少需要一个接口地址",
            ));
        }

        let mut source_v4 = None;
        let mut source_v6 = None;
        interface.update_ip_addrs(|addrs| {
            for cidr in &config.ip_addrs {
                let address = cidr.address();
                match address {
                    IpAddress::Ipv4(_) => source_v4.get_or_insert(address),
                    IpAddress::Ipv6(_) => source_v6.get_or_insert(address),
                };
                let _ = addrs.push(*cidr);
            }
        });

        if interface.ip_addrs().len() != config.ip_addrs.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "netstack 接口地址数量超过 smoltcp 上限",
            ));
        }

        for gateway in config.gateways {
            let result = match gateway {
                IpAddress::Ipv4(v4) => interface.routes_mut().add_default_ipv4_route(v4),
                IpAddress::Ipv6(v6) => interface.routes_mut().add_default_ipv6_route(v6),
            };
            result.map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("添加默认路由 {gateway} 失败: {e}"),
                )
            })?;
        }

        let stopper = Arc::new(Notify::new());
        let (reactor, task) = Reactor::new(
            device,
            interface,
            buffered,
            config.buffer_size,
            stopper.clone(),
        );
        let reactor = Arc::new(reactor);
        let task_reactor = reactor.clone();
        tokio::spawn(async move {
            let result = task.await;
            task_reactor.stop_sockets();
            if let Err(error) = result {
                log::error!("WireGuard netstack reactor 已停止: {error}");
            }
        });

        Ok(Self {
            reactor,
            source_v4,
            source_v6,
            stopper,
        })
    }

    /// 连接远端 TCP，并按目标地址族选择对应接口源地址。
    ///
    /// # Errors
    /// 目标地址族未配置、socket 创建失败或连接失败时返回错误。
    pub async fn tcp_connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        let source = self.source_for(target)?;
        TcpStream::connect(self.reactor.clone(), source, target.into()).await
    }

    /// 绑定虚拟 UDP socket。通配地址只决定地址族，实际发包源地址由接口选择。
    ///
    /// # Errors
    /// 对应地址族未配置或 socket 绑定失败时返回错误。
    pub async fn udp_bind(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let source = self.source_for(addr)?;
        UdpSocket::new(self.reactor.clone(), source, addr).await
    }

    fn source_for(&self, addr: SocketAddr) -> io::Result<IpAddress> {
        let source = match addr {
            SocketAddr::V4(_) => self.source_v4,
            SocketAddr::V6(_) => self.source_v6,
        };
        source.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "未配置 {} 源地址",
                    if addr.is_ipv4() { "IPv4" } else { "IPv6" }
                ),
            )
        })
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.stopper.notify_one();
    }
}

struct BufferDevice {
    capabilities: DeviceCapabilities,
    max_burst_size: usize,
    recv_queue: VecDeque<Vec<u8>>,
    send_queue: VecDeque<Vec<u8>>,
}

impl BufferDevice {
    fn new(capabilities: DeviceCapabilities) -> Self {
        let max_burst_size = capabilities
            .max_burst_size
            .unwrap_or(DEFAULT_MAX_BURST_SIZE);
        Self {
            capabilities,
            max_burst_size,
            recv_queue: VecDeque::with_capacity(max_burst_size),
            send_queue: VecDeque::with_capacity(max_burst_size),
        }
    }

    fn take_send_queue(&mut self) -> VecDeque<Vec<u8>> {
        std::mem::replace(
            &mut self.send_queue,
            VecDeque::with_capacity(self.max_burst_size),
        )
    }

    fn push_received(&mut self, packets: impl Iterator<Item = Vec<u8>>) {
        let available = self.max_burst_size.saturating_sub(self.recv_queue.len());
        self.recv_queue.extend(packets.take(available));
    }
}

struct BufferRxToken(Vec<u8>);

impl RxToken for BufferRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct BufferTxToken<'a>(&'a mut BufferDevice);

impl TxToken for BufferTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.send_queue.push_back(packet);
        result
    }
}

impl Device for BufferDevice {
    type RxToken<'a> = BufferRxToken;
    type TxToken<'a> = BufferTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.recv_queue
            .pop_front()
            .map(|packet| (BufferRxToken(packet), BufferTxToken(self)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        (self.send_queue.len() < self.max_burst_size).then_some(BufferTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }
}

struct SocketTable {
    sockets: SocketSet<'static>,
    next_port: u16,
}

impl SocketTable {
    fn new() -> Self {
        Self {
            sockets: SocketSet::new(Vec::new()),
            next_port: EPHEMERAL_PORT_FIRST,
        }
    }

    fn allocate_port(
        &mut self,
        transport: Transport,
        family: AddressFamily,
        requested: u16,
    ) -> io::Result<u16> {
        let mut next = self.next_port;
        let port = select_port(&mut next, requested, |port| {
            self.port_in_use(transport, family, port)
        })?;
        self.next_port = next;
        Ok(port)
    }

    fn port_in_use(&self, transport: Transport, family: AddressFamily, port: u16) -> bool {
        self.sockets
            .iter()
            .any(|(_, socket)| match (transport, socket) {
                (Transport::Tcp, smoltcp::socket::Socket::Tcp(socket)) => socket
                    .local_endpoint()
                    .is_some_and(|endpoint| endpoint.port == port && family.matches(endpoint.addr)),
                (Transport::Udp, smoltcp::socket::Socket::Udp(socket)) => {
                    let endpoint = socket.endpoint();
                    endpoint.port == port && endpoint.addr.is_some_and(|addr| family.matches(addr))
                }
                _ => false,
            })
    }
}

type SharedSocketTable = Arc<Mutex<SocketTable>>;

#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl From<IpAddress> for AddressFamily {
    fn from(address: IpAddress) -> Self {
        match address {
            IpAddress::Ipv4(_) => Self::Ipv4,
            IpAddress::Ipv6(_) => Self::Ipv6,
        }
    }
}

impl AddressFamily {
    fn matches(self, address: IpAddress) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddress::Ipv4(_)) | (Self::Ipv6, IpAddress::Ipv6(_))
        )
    }
}

fn select_port(
    next: &mut u16,
    requested: u16,
    mut in_use: impl FnMut(u16) -> bool,
) -> io::Result<u16> {
    if requested != 0 {
        return (!in_use(requested)).then_some(requested).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("端口 {requested} 已被占用"),
            )
        });
    }

    let count = usize::from(EPHEMERAL_PORT_LAST - EPHEMERAL_PORT_FIRST) + 1;
    for _ in 0..count {
        let candidate = *next;
        *next = if candidate >= EPHEMERAL_PORT_LAST {
            EPHEMERAL_PORT_FIRST
        } else {
            candidate + 1
        };
        if !in_use(candidate) {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "临时端口已耗尽",
    ))
}

#[derive(Clone)]
struct SocketAllocator {
    table: SharedSocketTable,
    buffer_size: BufferSize,
}

impl SocketAllocator {
    fn new(buffer_size: BufferSize) -> Self {
        Self {
            table: Arc::new(Mutex::new(SocketTable::new())),
            buffer_size,
        }
    }

    fn connect_tcp(
        &self,
        context: &mut InterfaceContext,
        source: IpAddress,
        remote: IpEndpoint,
    ) -> io::Result<SocketHandle> {
        let rx = tcp::SocketBuffer::new(vec![0; self.buffer_size.tcp_rx_size]);
        let tx = tcp::SocketBuffer::new(vec![0; self.buffer_size.tcp_tx_size]);
        let mut socket = tcp::Socket::new(rx, tx);
        let mut table = self.table.lock();
        let port = table.allocate_port(Transport::Tcp, source.into(), 0)?;
        socket
            .connect(context, remote, IpEndpoint::new(source, port))
            .map_err(map_error)?;
        let handle = table.sockets.add(socket);
        Ok(SocketHandle {
            inner: handle,
            table: self.table.clone(),
        })
    }

    fn new_udp(&self, source: IpAddress, requested_port: u16) -> io::Result<(SocketHandle, u16)> {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.buffer_size.udp_rx_meta_size],
            vec![0; self.buffer_size.udp_rx_size],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; self.buffer_size.udp_tx_meta_size],
            vec![0; self.buffer_size.udp_tx_size],
        );
        let mut socket = udp::Socket::new(rx, tx);
        let mut table = self.table.lock();
        let port = table.allocate_port(Transport::Udp, source.into(), requested_port)?;
        socket
            .bind(IpListenEndpoint {
                addr: Some(source),
                port,
            })
            .map_err(map_error)?;
        let handle = table.sockets.add(socket);
        Ok((
            SocketHandle {
                inner: handle,
                table: self.table.clone(),
            },
            port,
        ))
    }
}

struct SocketHandle {
    inner: InnerSocketHandle,
    table: SharedSocketTable,
}

impl Deref for SocketHandle {
    type Target = InnerSocketHandle;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        self.table.lock().sockets.remove(self.inner);
    }
}

struct Reactor {
    notify: Arc<Notify>,
    interface: Arc<Mutex<Interface>>,
    allocator: SocketAllocator,
    stopped: AtomicBool,
}

impl Reactor {
    fn new(
        device: impl AsyncDevice + 'static,
        interface: Interface,
        buffered: BufferDevice,
        buffer_size: BufferSize,
        stopper: Arc<Notify>,
    ) -> (
        Self,
        impl std::future::Future<Output = io::Result<()>> + Send,
    ) {
        let interface = Arc::new(Mutex::new(interface));
        let notify = Arc::new(Notify::new());
        let allocator = SocketAllocator::new(buffer_size);
        let task = run_reactor(
            device,
            interface.clone(),
            buffered,
            allocator.clone(),
            notify.clone(),
            stopper,
        );
        (
            Self {
                notify,
                interface,
                allocator,
                stopped: AtomicBool::new(false),
            },
            task,
        )
    }

    fn socket<T: AnySocket<'static>>(&self, handle: InnerSocketHandle) -> MappedMutexGuard<'_, T> {
        MutexGuard::map(self.allocator.table.lock(), |table| {
            table.sockets.get_mut::<T>(handle)
        })
    }

    fn context(&self) -> MappedMutexGuard<'_, InterfaceContext> {
        MutexGuard::map(self.interface.lock(), Interface::context)
    }

    fn wake(&self) {
        self.notify.notify_one();
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    fn stop_sockets(&self) {
        self.stopped.store(true, Ordering::Release);
        for (_, socket) in self.allocator.table.lock().sockets.iter_mut() {
            match socket {
                smoltcp::socket::Socket::Tcp(socket) => socket.abort(),
                smoltcp::socket::Socket::Udp(socket) => socket.close(),
            }
        }
    }
}

async fn run_reactor(
    mut device: impl AsyncDevice,
    interface: Arc<Mutex<Interface>>,
    mut buffered: BufferDevice,
    allocator: SocketAllocator,
    notify: Arc<Notify>,
    stopper: Arc<Notify>,
) -> io::Result<()> {
    let max_burst = device
        .capabilities()
        .max_burst_size
        .unwrap_or(DEFAULT_MAX_BURST_SIZE);
    let mut received = VecDeque::with_capacity(max_burst);

    loop {
        let outgoing = buffered.take_send_queue();
        futures::stream::iter(outgoing.into_iter().map(Ok))
            .forward(&mut device)
            .await?;

        let mut stream_ended = false;
        if received.is_empty() && buffered.recv_queue.is_empty() {
            let delay = interface
                .lock()
                .poll_delay(SmolInstant::now(), &allocator.table.lock().sockets)
                .unwrap_or(DEFAULT_POLL_INTERVAL);
            tokio::select! {
                _ = tokio::time::sleep(delay.into()) => {}
                packet = device.next() => match packet {
                    Some(Ok(packet)) => received.push_back(packet),
                    Some(Err(error)) => return Err(error),
                    None => break,
                },
                _ = notify.notified() => {}
                _ = stopper.notified() => break,
            }

            while received.len() < max_burst {
                match device.next().now_or_never() {
                    Some(Some(Ok(packet))) => received.push_back(packet),
                    Some(Some(Err(error))) => return Err(error),
                    Some(None) => {
                        stream_ended = true;
                        break;
                    }
                    None => break,
                }
            }
        }

        buffered.push_received(received.drain(..));
        interface.lock().poll(
            SmolInstant::now(),
            &mut buffered,
            &mut allocator.table.lock().sockets,
        );

        if stream_ended {
            break;
        }
    }
    Ok(())
}

fn map_error(error: impl std::error::Error) -> io::Error {
    io::Error::other(error.to_string())
}

fn socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(ip) => SocketAddr::new(IpAddr::V4(ip), endpoint.port),
        IpAddress::Ipv6(ip) => SocketAddr::new(IpAddr::V6(ip), endpoint.port),
    }
}

/// 建立在 smoltcp 上的 Tokio TCP stream。
pub struct TcpStream {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
}

impl TcpStream {
    async fn connect(
        reactor: Arc<Reactor>,
        source: IpAddress,
        remote: IpEndpoint,
    ) -> io::Result<Self> {
        let handle = {
            let mut context = reactor.context();
            reactor
                .allocator
                .connect_tcp(&mut context, source, remote)?
        };
        let stream = Self { handle, reactor };
        stream.reactor.wake();
        poll_fn(|cx| stream.poll_connected(cx)).await?;
        Ok(stream)
    }

    fn poll_connected(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.reactor.is_stopped() {
            return Poll::Ready(Err(reactor_stopped()));
        }
        let mut socket = self.reactor.socket::<tcp::Socket>(*self.handle);
        match socket.state() {
            tcp::State::Established => Poll::Ready(Ok(())),
            tcp::State::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "TCP 连接建立失败",
            ))),
            _ => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.reactor.is_stopped() {
            return Poll::Ready(Err(reactor_stopped()));
        }
        let mut socket = self.reactor.socket::<tcp::Socket>(*self.handle);
        if !socket.may_recv() {
            return Poll::Ready(Ok(()));
        }
        if socket.can_recv() {
            let read = socket
                .recv_slice(buf.initialize_unfilled())
                .map_err(map_error)?;
            buf.advance(read);
            drop(socket);
            self.reactor.wake();
            return Poll::Ready(Ok(()));
        }
        socket.register_recv_waker(cx.waker());
        Poll::Pending
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.reactor.is_stopped() {
            return Poll::Ready(Err(reactor_stopped()));
        }
        let mut socket = self.reactor.socket::<tcp::Socket>(*self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if socket.can_send() {
            let written = socket.send_slice(buf).map_err(map_error)?;
            drop(socket);
            self.reactor.wake();
            return Poll::Ready(Ok(written));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.reactor.is_stopped() {
            return Poll::Ready(Err(reactor_stopped()));
        }
        let mut socket = self.reactor.socket::<tcp::Socket>(*self.handle);
        if socket.send_queue() == 0 {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.reactor.is_stopped() {
            return Poll::Ready(Ok(()));
        }
        let mut socket = self.reactor.socket::<tcp::Socket>(*self.handle);
        if socket.is_open() {
            socket.close();
            drop(socket);
            self.reactor.wake();
            socket = self.reactor.socket::<tcp::Socket>(*self.handle);
        }
        if socket.state() == tcp::State::Closed {
            return Poll::Ready(Ok(()));
        }
        socket.register_send_waker(cx.waker());
        Poll::Pending
    }
}

/// 建立在 smoltcp 上的异步 UDP socket。
pub struct UdpSocket {
    handle: SocketHandle,
    reactor: Arc<Reactor>,
    local_addr: SocketAddr,
}

impl UdpSocket {
    async fn new(
        reactor: Arc<Reactor>,
        source: IpAddress,
        mut local_addr: SocketAddr,
    ) -> io::Result<Self> {
        let (handle, port) = reactor.allocator.new_udp(source, local_addr.port())?;
        local_addr.set_port(port);
        reactor.wake();
        Ok(Self {
            handle,
            reactor,
            local_addr,
        })
    }

    /// 发送一个 UDP 数据报。
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        poll_fn(|cx| {
            if self.reactor.is_stopped() {
                return Poll::Ready(Err(reactor_stopped()));
            }
            let mut socket = self.reactor.socket::<udp::Socket>(*self.handle);
            match socket.send_slice(buf, target) {
                Err(udp::SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                }
                result => {
                    result.map_err(map_error)?;
                    drop(socket);
                    self.reactor.wake();
                    Poll::Ready(Ok(buf.len()))
                }
            }
        })
        .await
    }

    /// 接收一个 UDP 数据报及其来源。
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            if self.reactor.is_stopped() {
                return Poll::Ready(Err(reactor_stopped()));
            }
            let mut socket = self.reactor.socket::<udp::Socket>(*self.handle);
            match socket.recv_slice(buf) {
                Err(udp::RecvError::Exhausted) => {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
                result => {
                    let (size, metadata) = result.map_err(map_error)?;
                    let from = socket_addr(metadata.endpoint);
                    drop(socket);
                    self.reactor.wake();
                    Poll::Ready(Ok((size, from)))
                }
            }
        })
        .await
    }

    /// 返回调用方请求的绑定地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

fn reactor_stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "WireGuard netstack reactor 已停止",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    use smoltcp::phy::Medium;
    use smoltcp::wire::HardwareAddress;

    struct PendingDevice {
        capabilities: DeviceCapabilities,
    }

    impl Stream for PendingDevice {
        type Item = io::Result<Vec<u8>>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Sink<Vec<u8>> for PendingDevice {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Vec<u8>) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncDevice for PendingDevice {
        fn capabilities(&self) -> &DeviceCapabilities {
            &self.capabilities
        }
    }

    fn dual_stack_net() -> Net {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1330;
        let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = 1;
        Net::new(
            PendingDevice { capabilities },
            NetConfig::new(
                interface_config,
                vec![
                    IpCidr::new(IpAddress::v4(172, 16, 0, 2), 32),
                    IpCidr::new("2001:db8::2".parse::<Ipv6Addr>().unwrap().into(), 128),
                ],
                vec![
                    IpAddress::v4(172, 16, 0, 2),
                    "2001:db8::2".parse::<Ipv6Addr>().unwrap().into(),
                ],
            ),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn udp_bind_selects_source_address_by_family() {
        let net = dual_stack_net();
        let v4 = net.udp_bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
        let v6 = net.udp_bind("[::]:0".parse().unwrap()).await.unwrap();

        let v4_socket = net.reactor.socket::<udp::Socket>(*v4.handle);
        assert_eq!(v4_socket.endpoint().addr, net.source_v4);
        drop(v4_socket);
        let v6_socket = net.reactor.socket::<udp::Socket>(*v6.handle);
        assert_eq!(v6_socket.endpoint().addr, net.source_v6);
    }

    #[tokio::test]
    async fn tcp_connect_selects_source_address_by_family() {
        let net = dual_stack_net();

        for (target, expected) in [
            (
                "192.0.2.1:443".parse().unwrap(),
                IpAddress::v4(172, 16, 0, 2),
            ),
            (
                "[2001:db8::1]:443".parse().unwrap(),
                "2001:db8::2".parse::<Ipv6Addr>().unwrap().into(),
            ),
        ] {
            let mut connecting = Box::pin(net.tcp_connect(target));
            assert!(futures::poll!(&mut connecting).is_pending());

            let table = net.reactor.allocator.table.lock();
            let local = table.sockets.iter().find_map(|(_, socket)| match socket {
                smoltcp::socket::Socket::Tcp(tcp)
                    if tcp
                        .remote_endpoint()
                        .is_some_and(|remote| socket_addr(remote) == target) =>
                {
                    tcp.local_endpoint()
                }
                _ => None,
            });
            assert_eq!(local.map(|endpoint| endpoint.addr), Some(expected));
            drop(table);
            drop(connecting);
            assert!(net
                .reactor
                .allocator
                .table
                .lock()
                .sockets
                .iter()
                .next()
                .is_none());
        }
    }

    #[tokio::test]
    async fn failed_tcp_connect_does_not_leave_a_socket() {
        let net = dual_stack_net();
        let error = match net.tcp_connect("192.0.2.1:0".parse().unwrap()).await {
            Ok(_) => panic!("远端端口为 0 的 TCP 连接不应成功"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(net
            .reactor
            .allocator
            .table
            .lock()
            .sockets
            .iter()
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn dropping_udp_socket_releases_its_port() {
        let net = dual_stack_net();
        let socket = net.udp_bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
        let port = socket.local_addr().port();
        assert!(net.reactor.allocator.table.lock().port_in_use(
            Transport::Udp,
            AddressFamily::Ipv4,
            port
        ));
        drop(socket);
        assert!(!net.reactor.allocator.table.lock().port_in_use(
            Transport::Udp,
            AddressFamily::Ipv4,
            port
        ));
    }

    #[tokio::test]
    async fn source_selection_rejects_unconfigured_family() {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = 1;
        let net = Net::new(
            PendingDevice { capabilities },
            NetConfig::new(
                interface_config,
                vec![IpCidr::new(IpAddress::v4(192, 0, 2, 2), 32)],
                vec![],
            ),
        )
        .unwrap();

        let error = net
            .source_for("[2001:db8::1]:443".parse().unwrap())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    }

    #[tokio::test]
    async fn dropping_net_wakes_pending_udp_operation() {
        let net = dual_stack_net();
        let socket = net.udp_bind("0.0.0.0:0".parse().unwrap()).await.unwrap();
        let mut buf = [0; 32];
        let mut receiving = Box::pin(socket.recv_from(&mut buf));
        assert!(futures::poll!(&mut receiving).is_pending());

        drop(net);
        let error = tokio::time::timeout(std::time::Duration::from_millis(100), receiving)
            .await
            .expect("停止 reactor 后 pending UDP recv 应被唤醒")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn udp_ports_are_unique_within_an_address_family() {
        let net = dual_stack_net();
        let first = net
            .udp_bind("0.0.0.0:15000".parse().unwrap())
            .await
            .unwrap();
        let conflict = net
            .udp_bind("0.0.0.0:15000".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(conflict.kind(), io::ErrorKind::AddrInUse);

        let v6 = net.udp_bind("[::]:15000".parse().unwrap()).await.unwrap();
        assert_eq!(v6.local_addr().port(), 15000);
        drop(first);
        assert!(net.udp_bind("0.0.0.0:15000".parse().unwrap()).await.is_ok());
    }

    #[tokio::test]
    async fn tcp_and_udp_can_reuse_the_same_port() {
        let net = dual_stack_net();
        let mut connecting = Box::pin(net.tcp_connect("192.0.2.1:443".parse().unwrap()));
        assert!(futures::poll!(&mut connecting).is_pending());
        let port = net
            .reactor
            .allocator
            .table
            .lock()
            .sockets
            .iter()
            .find_map(|(_, socket)| match socket {
                smoltcp::socket::Socket::Tcp(socket) => {
                    socket.local_endpoint().map(|endpoint| endpoint.port)
                }
                _ => None,
            })
            .unwrap();
        let udp = net
            .udp_bind(format!("0.0.0.0:{port}").parse().unwrap())
            .await
            .unwrap();
        assert_eq!(udp.local_addr().port(), port);
    }

    #[test]
    fn ephemeral_port_selection_wraps_and_reports_exhaustion() {
        use std::collections::HashSet;

        let mut next = EPHEMERAL_PORT_LAST;
        let mut used = HashSet::new();
        let last = select_port(&mut next, 0, |port| used.contains(&port)).unwrap();
        used.insert(last);
        let first = select_port(&mut next, 0, |port| used.contains(&port)).unwrap();
        assert_eq!(last, EPHEMERAL_PORT_LAST);
        assert_eq!(first, EPHEMERAL_PORT_FIRST);

        used.extend(EPHEMERAL_PORT_FIRST..=EPHEMERAL_PORT_LAST);
        let exhausted = select_port(&mut next, 0, |port| used.contains(&port))
            .err()
            .unwrap();
        assert_eq!(exhausted.kind(), io::ErrorKind::AddrNotAvailable);
    }
}
