// 单端口多协议探测分发，对照 warp-plus `proxy/pkg/mixed/proxy.go`：peek
// 第一个字节（不消费），0x05 → SOCKS5，0x04 → SOCKS4，其余 → HTTP 代理。
// tokio::net::TcpStream::peek 本身就是非消费读取，不需要像 Go 那样额外包一层
// bufio.Reader。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{error, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

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

// 同时处理中的连接数上限：只是给一次异常的连接数飙升（例如单个客户端异常
// 打满连接）托底，避免它把 fd 都耗尽、连累 DNS 解析/健康检查探测等不走这个
// accept 循环的其它子系统。这不是运维需要按部署调整的旋钮（不在超时派生链
// 里，也不是资源配额），跟 appconfig.rs 里 startup_endpoint_cooldown /
// healthcheck_interval 同类处理：固定常量，不做成环境变量。
const MAX_CONNECTIONS: usize = 4096;

pub async fn serve(outbound: Arc<dyn Outbound>, listen_addrs: Vec<SocketAddr>) -> Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut listeners = Vec::with_capacity(listen_addrs.len());
    for listen_addr in listen_addrs {
        let listener = TcpListener::bind(listen_addr)
            .await
            .with_context(|| format!("监听 {listen_addr} 失败"))?;
        listeners.push((listen_addr, listener));
    }

    let mut tasks = tokio::task::JoinSet::new();
    for (listen_addr, listener) in listeners {
        tasks.spawn(accept_loop(
            listener,
            listen_addr,
            Arc::clone(&outbound),
            Arc::clone(&permits),
        ));
    }
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(e)) => Err(e).context("监听任务异常终止"),
        None => anyhow::bail!("没有可用的监听任务"),
    }
}

async fn accept_loop(
    listener: TcpListener,
    listen_addr: SocketAddr,
    outbound: Arc<dyn Outbound>,
    permits: Arc<Semaphore>,
) -> Result<()> {
    log::info!("代理监听已就绪: {listen_addr}");

    loop {
        // 先拿许可证、再 accept：达到并发上限时不消费 listener 的 backlog，
        // 新连接留在 OS 的 listen backlog 里排队等待，而不是被应用层主动拒绝
        // ——对照 tokio 官方 mini-redis 示例（tokio-rs/mini-redis
        // src/server.rs `Listener::run`）里 `limit_connections.acquire` 的限流
        // 写法。许可证随 accept 到的连接一起 move 进 spawn 的任务，处理完毕
        // 连接结束时随 permit 一起 drop 释放。
        let permit = Arc::clone(&permits)
            .acquire_owned()
            .await
            .expect("Semaphore 未被 close，acquire 不会失败");

        let (client, peer) = match listener.accept().await {
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
        let outbound = outbound.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = dispatch(client, peer, outbound).await {
                warn!("连接 {peer} 处理失败: {e:#}");
            }
        });
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
    let mut first_byte = [0u8; 1];
    let n = client.peek(&mut first_byte).await?;
    if n == 0 {
        return Ok(());
    }
    match first_byte[0] {
        0x05 => socks5::handle_client(client, peer, outbound).await,
        0x04 => socks4::handle_client(client, peer, &*outbound).await,
        _ => http_proxy::handle_client(client, peer, &*outbound).await,
    }
}
