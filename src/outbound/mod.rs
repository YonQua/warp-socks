// 出网抽象：SOCKS5/SOCKS4/HTTP 代理层只依赖这个 trait，不关心底层是
// WireGuard 虚拟网卡还是 MASQUE H3 CONNECT 流。
//
// 域名如何解析是后端的实现细节，绝不出现在 trait 上：
//   - WireGuard 走虚拟网卡 DNS
//   - MASQUE 收到域名后先经隧道内 DoH 解析成 IP，再拿 IP 建 CONNECT
//     （边缘不会自己解析裸域名，会 403；详见 outbound/masque/doh.rs）
// 域名字符串本身只在 Host::Domain 里传到后端，之后如何解析完全由各后端决定。

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub mod masque;
pub mod wireguard;

pub use masque::Masque;
pub use wireguard::WgOutbound;

/// 双向字节流。tokio_smoltcp::TcpStream、quinn (Send,Recv) 组合都满足。
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// 连接目标主机。
#[derive(Debug, Clone)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

/// 到单一对端的数据报通道（SOCKS5 UDP ASSOCIATE 用）：一次 `connect_udp`
/// 只绑定一个目的地址，语义上等价于已 connect 的 UDP socket。
#[async_trait]
pub trait Datagram: Send + Sync {
    /// 实际解析出的对端地址，用于给客户端拼 SOCKS5 UDP 响应头。
    fn peer_addr(&self) -> SocketAddr;

    /// # Errors
    /// 发送失败时返回 `io::Error`。
    async fn send(&self, buf: &[u8]) -> std::io::Result<()>;

    /// 只返回来自 `peer_addr()` 的数据；其余来源已由实现内部过滤。
    /// # Errors
    /// 接收失败时返回 `io::Error`。
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// 出网后端：给定 host:port 产出一条双向字节流，可选支持 UDP。
#[async_trait]
pub trait Outbound: Send + Sync {
    /// # Errors
    /// 连接失败（超时、拒绝、网络不可达、域名解析失败等）时返回 `io::Error`。
    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Box<dyn Stream>>;

    /// 建立到目标的 UDP 通道。默认不支持（如 MASQUE：H3 CONNECT 是字节流，
    /// 扛不了 datagram）；调用方应在收到 `ErrorKind::Unsupported` 时自行
    /// 决定回退方案，而不是把这当成普通连接失败处理。
    async fn connect_udp(&self, _host: Host, _port: u16) -> std::io::Result<Box<dyn Datagram>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "该出网后端不支持 UDP",
        ))
    }
}
