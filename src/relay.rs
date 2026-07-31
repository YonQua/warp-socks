// 各协议 CONNECT 语义成功后的双向转发，SOCKS5/SOCKS4/HTTP CONNECT 共用。
// 客户端一侧固定是 tokio::net::TcpStream（mixed 分发器只 peek 不消费首字节），
// 出网一侧是 trait object（Box<dyn Stream>），底层可以是 WireGuard 虚拟网卡
// 的 TCP 流，也可以是 MASQUE H3 CONNECT 的双向 QUIC 流。

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use log::info;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::outbound::masque;
use crate::outbound::{Connected, Host, Outbound};

// 从 masque::CONNECT_STREAM_TIMEOUT（各 Outbound 实现里最大的连接预算，即
// open() 内部重连自愈需要的完整预算）直接派生，而不是手抄一个数字——
// masque 那边的子超时改动后这里自动跟着变，不会再出现"改了内层却忘了同
// 步外层"的漂移。留 5 秒余量：这里比内层更没耐心地提前取消，会把一次本
// 可恢复的重连误判成超时失败。
pub(crate) const CONNECT_TIMEOUT: Duration =
    Duration::from_secs(masque::CONNECT_STREAM_TIMEOUT.as_secs() + 5);

/// 通过出网抽象建立 TCP 连接。
///
/// # Errors
/// 连接超时或失败时返回 `io::Error`。
pub async fn connect(outbound: &dyn Outbound, host: Host, port: u16) -> std::io::Result<Connected> {
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
///
/// "已建立"/"已关闭" 日志统一收在这里：SOCKS5/SOCKS4/HTTP CONNECT 三处协议
/// 实现原先各自打印一遍"已建立"，且都没有对应的"已关闭"，是典型的重复
/// 逻辑分散在调用点的模式，收口到转发本身归属的地方。后端名 + colo 等
/// 诊断信息也并进这一行：单独打一行会跟这里的"已建立"分处两个模块，
/// 并发连接一多只能靠时间戳去猜哪条对应哪条，合并后同一次连接的信息
/// 天然聚在一起；`backend` 长时间运行只在启动时打过一次，翻旧了没法
/// 确认当前连接到底走的哪个后端，这里每条连接都带上就不用翻。
pub async fn tunnel_tcp(
    peer: SocketAddr,
    display: &str,
    backend: &str,
    client: TcpStream,
    conn: Connected,
) -> Result<()> {
    let Connected {
        stream: outbound,
        note,
    } = conn;
    match note {
        Some(note) => info!("连接 {peer} -> {display}（backend={backend}, {note}）: 已建立"),
        None => info!("连接 {peer} -> {display}（backend={backend}）: 已建立"),
    }
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
    info!("连接 {peer} -> {display}: 已关闭");
    Ok(())
}
