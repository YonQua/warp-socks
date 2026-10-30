// 单端口多协议探测分发，对照 warp-plus `proxy/pkg/mixed/proxy.go`：peek
// 第一个字节（不消费），0x05 → SOCKS5，0x04 → SOCKS4，其余 → HTTP 代理。
// tokio::net::TcpStream::peek 本身就是非消费读取，不需要像 Go 那样额外包一层
// bufio.Reader。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{error, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::time::{timeout, timeout_at, Instant};

use crate::outbound::Outbound;
use crate::{http_proxy, socks4, socks5};

// accept() 拿到非连接类错误（典型如 EMFILE/ENFILE 文件描述符耗尽）时的退避时长：
// 对照 hyper 经典的 AddrIncoming::poll_next_ 设计（hyperium/hyper
// src/server/tcp.rs，文档明确点名 EMFILE 场景）——这类错误通常是瞬时性资源紧张，
// 等一小段时间给现有连接腾出关闭的机会再重试，而不是让 accept 循环连带整个
// SOCKS5 服务、乃至整个进程一起退出（此前的行为：`listener.accept().await?`
// 把 EMFILE 当致命错误直接向上抛，被 supervisor 判定为"SOCKS5 服务提前退出"，
// 触发 endpoint 冷却 + 依赖 Docker `restart: unless-stopped` 整进程重启才能
// "自愈"——一次瞬时的并发连接数冲高本不该升级到这一级别）。
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

// IP 栈单 TCP 缓冲 512 KiB；限制业务并发为恢复和探测保留内存。
const MAX_CONNECTIONS: usize = 64;
const RECOVERY_WAIT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub enum ListenMode {
    Auto { port: u16 },
    Explicit(Vec<SocketAddr>),
}

pub async fn serve(outbound: Arc<dyn Outbound>, mode: ListenMode) -> Result<()> {
    let (_owner, state) = watch::channel(Some(outbound));
    serve_managed(state, mode).await
}

pub(crate) async fn serve_managed(
    state: watch::Receiver<Option<Arc<dyn Outbound>>>,
    mode: ListenMode,
) -> Result<()> {
    let listeners = bind_listeners(mode).await?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = tokio::task::JoinSet::new();
    for (listen_addr, listener, lan_only) in listeners {
        tasks.spawn(accept_loop(
            listener,
            listen_addr,
            lan_only,
            state.clone(),
            Arc::clone(&permits),
        ));
    }
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(e).context("监听任务异常终止"),
        None => anyhow::bail!("没有可用的监听任务"),
    }
}

async fn bind_listeners(mode: ListenMode) -> Result<Vec<(SocketAddr, TcpListener, bool)>> {
    match mode {
        ListenMode::Auto { port } => {
            let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
            Ok(vec![
                (v4, bind_socket(v4, false)?, true),
                (v6, bind_socket(v6, true)?, true),
            ])
        }
        ListenMode::Explicit(addrs) => {
            let mut listeners = Vec::with_capacity(addrs.len());
            for addr in addrs {
                let listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("监听 {addr} 失败"))?;
                listeners.push((addr, listener, false));
            }
            Ok(listeners)
        }
    }
}

fn bind_socket(addr: SocketAddr, only_v6: bool) -> Result<TcpListener> {
    let socket = listener_socket(addr, only_v6)?;
    let listener = std::net::TcpListener::from(socket);
    TcpListener::from_std(listener).with_context(|| format!("监听 {addr} 失败"))
}

fn listener_socket(addr: SocketAddr, only_v6: bool) -> Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(only_v6)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

async fn accept_loop(
    listener: TcpListener,
    listen_addr: SocketAddr,
    lan_only: bool,
    state: watch::Receiver<Option<Arc<dyn Outbound>>>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    log::info!("代理监听已就绪: {listen_addr}");
    let mut connections = tokio::task::JoinSet::new();
    loop {
        // 接受后再分配容量，满载时及时关闭，避免在应用层堆积等待任务。
        let accepted = tokio::select! {
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    warn!("代理连接任务异常: {error}");
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (client, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) if is_connection_error(&e) => {
                // 对端在三次握手完成前就中止了连接，下一条待接受的连接大概率立刻
                // 可用，直接重试，不计入退避。
                warn!("accept 到一个已中止的连接: {e}");
                continue;
            }
            Err(e) => {
                error!("accept 失败，{ACCEPT_ERROR_BACKOFF:?} 后重试: {e}");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        if lan_only && !is_lan_address(peer.ip()) {
            warn!("自动监听拒绝非 LAN 客户端: {peer}");
            continue;
        }
        let permit = Arc::clone(&permits).try_acquire_owned();
        let Ok(permit) = permit else {
            warn!("代理连接容量已满: {peer}");
            continue;
        };
        let mut state = state.clone();
        connections.spawn(async move {
            let _permit = permit;
            let ready = timeout(RECOVERY_WAIT, async {
                loop {
                    if let Some(outbound) = state.borrow_and_update().clone() {
                        return Ok::<_, watch::error::RecvError>(outbound);
                    }
                    state.changed().await?;
                }
            })
            .await;
            match ready {
                Ok(Ok(outbound)) => {
                    tokio::select! {
                        result = dispatch(client, peer, outbound) => {
                            if let Err(e) = result { warn!("连接 {peer} 处理失败: {e:#}"); }
                        }
                        _ = state.changed() => {
                            log::debug!("出口已失效，释放连接: {peer}");
                        }
                    }
                }
                _ => {
                    // 失败回复也有生命周期：HTTP keep-alive 不能永久占用恢复中的出口。
                    tokio::select! {
                        _ = timeout(HANDSHAKE_TIMEOUT, dispatch(client, peer, Arc::new(Unavailable))) => {}
                        _ = state.changed() => {}
                    }
                }
            }
        });
    }
}

struct Unavailable;

#[async_trait::async_trait]
impl Outbound for Unavailable {
    fn name(&self) -> &'static str {
        "recovering"
    }

    async fn connect_tcp(
        &self,
        _: crate::outbound::Host,
        _: u16,
    ) -> io::Result<crate::outbound::Connected> {
        Err(io::Error::new(io::ErrorKind::NotConnected, "出口尚未就绪"))
    }
}

fn is_lan_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr.is_loopback() || addr.is_private() || addr.is_link_local(),
        IpAddr::V6(addr) => {
            addr.is_loopback() || addr.is_unique_local() || addr.is_unicast_link_local()
        }
    }
}

/// 判定一个 accept 错误是否是"per-connection"错误：对应到具体某一条已经
/// 半途夭折的连接，不代表 listener 或进程本身的资源状况有问题，下一次
/// accept 大概率能立刻成功。对照 hyper `is_connection_error`
/// （hyperium/hyper src/server/tcp.rs）同名函数的判定标准。
fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

async fn dispatch(client: TcpStream, peer: SocketAddr, outbound: Arc<dyn Outbound>) -> Result<()> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut first_byte = [0u8; 1];
    let n = timeout_at(deadline, client.peek(&mut first_byte))
        .await
        .context("代理协议探测超时")??;
    if n == 0 {
        return Ok(());
    }
    match first_byte[0] {
        0x05 => socks5::handle_client(client, peer, outbound, deadline).await,
        0x04 => socks4::handle_client(client, peer, &*outbound, deadline).await,
        _ => http_proxy::handle_client(client, peer, outbound, deadline).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_mode_accepts_only_local_and_lan_addresses() {
        for addr in [
            "127.0.0.1",
            "10.10.10.2",
            "192.168.1.2",
            "::1",
            "fd00::2",
            "fe80::2",
        ] {
            assert!(is_lan_address(addr.parse().unwrap()), "{addr}");
        }
        for addr in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(!is_lan_address(addr.parse().unwrap()), "{addr}");
        }
    }

    #[test]
    fn auto_ipv6_listener_is_v6_only() {
        let socket = listener_socket("[::]:0".parse().unwrap(), true).unwrap();
        assert!(socket.only_v6().unwrap());
    }
}
