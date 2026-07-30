// 各协议 CONNECT 语义成功后的双向转发，SOCKS5/SOCKS4/HTTP CONNECT 共用。
// 客户端一侧固定是 tokio::net::TcpStream（mixed 分发器只 peek 不消费首字节），
// 出网一侧固定是 tokio_smoltcp::TcpStream（隧道内虚拟网卡拨号的结果）。

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_smoltcp::{Net, TcpStream as TunnelTcpStream};

// smoltcp 对未响应的 SYN 只会把重传间隔倍增到 60s 封顶，不像 Linux 内核那样
// 有限次数后放弃连接——隧道对端目的地黑洞丢包（被墙/不可达）时，不加超时
// 这个连接会永远占着虚拟网卡 SocketSet 里的一个 socket，客户端也感知不到
// 失败，只能一直挂起等。tokio::time::timeout 取消 tcp_connect 的 Future 会
// 正常触发 TcpStream 内部 SocketHandle 的 Drop，从 SocketSet 里摘除，不会
// 留下泄漏的 socket。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect(net: &Net, addr: SocketAddr) -> io::Result<TunnelTcpStream> {
    tokio::time::timeout(CONNECT_TIMEOUT, net.tcp_connect(addr))
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("连接 {addr} 超时（{CONNECT_TIMEOUT:?}）"),
            ))
        })
}

pub async fn tunnel_tcp(client: TcpStream, outbound: TunnelTcpStream) -> Result<()> {
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
