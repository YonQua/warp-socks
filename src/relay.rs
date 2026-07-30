// 各协议 CONNECT 语义成功后的双向转发，SOCKS5/SOCKS4/HTTP CONNECT 共用。
// 客户端一侧固定是 tokio::net::TcpStream（mixed 分发器只 peek 不消费首字节），
// 出网一侧是 trait object（Box<dyn Stream>），底层可以是 WireGuard 虚拟网卡
// 的 TCP 流，也可以是 MASQUE H3 CONNECT 的双向 QUIC 流。

use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::outbound::{Host, Outbound, Stream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// 通过出网抽象建立 TCP 连接。
///
/// # Errors
/// 连接超时或失败时返回 `io::Error`。
pub async fn connect(
    outbound: &dyn Outbound,
    host: Host,
    port: u16,
) -> std::io::Result<Box<dyn Stream>> {
    tokio::time::timeout(CONNECT_TIMEOUT, outbound.connect_tcp(host, port))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("连接目标超时（{CONNECT_TIMEOUT:?}）"),
            )
        })?
}

/// 双向转发：客户端 TCP 流 <-> 出网代理流，直到任一方关闭。
pub async fn tunnel_tcp(client: TcpStream, outbound: Box<dyn Stream>) -> Result<()> {
    let (mut ro, mut wo) = tokio::io::split(outbound);
    let (mut rc, mut wc) = client.into_split();
    let up = async {
        let n = tokio::io::copy(&mut rc, &mut wo).await;
        let _ = wo.shutdown().await;
        n
    };
    let down = async {
        let n = tokio::io::copy(&mut ro, &mut wc).await;
        let _ = wc.shutdown().await;
        n
    };
    let _ = tokio::join!(up, down);
    Ok(())
}
