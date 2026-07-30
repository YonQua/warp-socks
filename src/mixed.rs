// 单端口多协议探测分发，对照 warp-plus `proxy/pkg/mixed/proxy.go`：peek
// 第一个字节（不消费），0x05 → SOCKS5，0x04 → SOCKS4，其余 → HTTP 代理。
// tokio::net::TcpStream::peek 本身就是非消费读取，不需要像 Go 那样额外包一层
// bufio.Reader。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::warn;
use tokio::net::{TcpListener, TcpStream};

use crate::outbound::Outbound;
use crate::{http_proxy, socks4, socks5};

pub async fn serve(outbound: Arc<dyn Outbound>, listen_addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("监听 {listen_addr} 失败"))?;

    loop {
        let (client, peer) = listener.accept().await?;
        let outbound = outbound.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatch(client, peer, &*outbound).await {
                warn!("连接 {peer} 处理失败: {e:#}");
            }
        });
    }
}

async fn dispatch(client: TcpStream, peer: SocketAddr, outbound: &dyn Outbound) -> Result<()> {
    let mut first_byte = [0u8; 1];
    let n = client.peek(&mut first_byte).await?;
    if n == 0 {
        return Ok(());
    }
    match first_byte[0] {
        0x05 => socks5::handle_client(client, peer, outbound).await,
        0x04 => socks4::handle_client(client, peer, outbound).await,
        _ => http_proxy::handle_client(client, peer, outbound).await,
    }
}
