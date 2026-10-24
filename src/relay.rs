// 各协议 CONNECT 语义成功后的双向转发，SOCKS5/SOCKS4/HTTP CONNECT 共用。
// 客户端可以是原始 TCP 或保留预读数据的 HTTP Upgrade 流，
// 出网一侧是 trait object（Box<dyn Stream>），底层可以是 WireGuard 虚拟网卡
// 的 TCP 流，也可以是 MASQUE H3 CONNECT 的双向 QUIC 流。

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use log::info;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::outbound::{Connected, Host, Outbound};

const RELAY_DRAIN_GRACE: Duration = Duration::from_secs(30);

/// 通过出网抽象建立 TCP 连接。
///
/// # Errors
/// 后端连接失败时返回 `io::Error`。
pub async fn connect(outbound: &dyn Outbound, host: Host, port: u16) -> std::io::Result<Connected> {
    outbound.connect_tcp(host, port).await
}

/// 双向转发：客户端 TCP 流 <-> 出网代理流，直到任一方关闭。
///
/// 统一记录目标和后端；I/O 错误与半关闭排空超时交给调用方报告。
pub async fn tunnel_tcp<C>(
    peer: SocketAddr,
    display: &str,
    backend: &str,
    client: C,
    conn: Connected,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let Connected {
        stream: outbound,
        note,
    } = conn;
    match note {
        Some(note) => info!("连接 {peer} -> {display}（backend={backend}, {note}）: 已建立"),
        None => info!("连接 {peer} -> {display}（backend={backend}）: 已建立"),
    }
    copy_with_drain(client, outbound, RELAY_DRAIN_GRACE).await?;
    info!("连接 {peer} -> {display}: 已关闭");
    Ok(())
}

async fn copy_with_drain<C, O>(client: C, outbound: O, drain_grace: Duration) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rc, mut wc) = tokio::io::split(client);
    let (mut ro, mut wo) = tokio::io::split(outbound);
    let down = async {
        tokio::io::copy(&mut ro, &mut wc).await?;
        wc.shutdown().await
    };
    tokio::pin!(down);
    {
        let up = tokio::io::copy(&mut rc, &mut wo);
        tokio::pin!(up);
        tokio::select! {
            result = &mut down => return result,
            result = &mut up => { result?; },
        }
    }
    // shutdown 与响应读取并发，整个收尾阶段共用一份预算。
    tokio::time::timeout(drain_grace, async {
        tokio::select! {
            result = &mut down => result,
            result = wo.shutdown() => {
                result?;
                down.await
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "客户端半关闭后响应排空超时"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_close_does_not_wait_forever_for_remote() {
        let (client, client_peer) = tokio::io::duplex(64);
        let (outbound, _outbound_peer) = tokio::io::duplex(64);
        drop(client_peer);

        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            copy_with_drain(client, outbound, Duration::from_millis(10)),
        )
        .await
        .expect("drain 宽限结束后 relay 应释放连接");
    }
}
