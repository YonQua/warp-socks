// 代理协议层仅依赖 Outbound；WARP、Psiphon 载体与最终 H2 在进程内组合。
// 域名解析归后端：WireGuard/H2 使用 IP 栈内 DNS，H3 使用隧道内 DoH。

use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) mod https;
mod ip;
pub mod masque;
pub mod psiphon;
pub mod wireguard;

pub use masque::Masque;
pub use wireguard::WgOutbound;

/// 双向字节流。项目内 netstack 的 TcpStream、quinn (Send,Recv) 组合都满足。
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// 连接目标主机。
#[derive(Debug, Clone)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    /// 判定一个地址字符串是字面量 IP 还是域名：能解析成 IP 就是 `Host::Ip`，
    /// 否则当域名处理。SOCKS5/SOCKS4a 的域名字段、HTTP CONNECT 的 Host 头都可能
    /// 塞字面量 IP（常见于"远程 DNS"客户端），这条判定与具体协议无关，统一在这里
    /// 做一次，避免每个协议实现各写一份、规则变化时到处漏改。
    pub fn parse(s: &str) -> Self {
        match s.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Domain(s.to_string()),
        }
    }
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

/// 一条建立好的 TCP 出网流，附带后端可选的诊断信息，纯展示用，日志里跟
/// 连接一起打印，没有就是 `None`。字段本身对内容不作任何假设（如 MASQUE
/// 填 "colo=LAX"）——`Connected` 是所有后端共用的类型，不该认识某个具体
/// 后端的专属概念，格式完全交给产出它的后端自己决定。
pub struct Connected {
    pub stream: Box<dyn Stream>,
    pub note: Option<String>,
}

/// 出网后端：给定 host:port 产出一条双向字节流，可选支持 UDP。
#[async_trait]
pub trait Outbound: Send + Sync {
    /// 后端名，用于展示（启动日志、每条连接日志），如 "MASQUE"/"WireGuard"。
    /// 只在实现处定义这一份，避免调用方各自维护一份同名字符串、改名时漏改。
    fn name(&self) -> &'static str;

    /// 后端是否原生支持隧道内 UDP。SOCKS5 必须在回复 UDP ASSOCIATE 前读取
    /// 这个静态能力，避免先回复成功、收到首包后才发现后端不支持而形成黑洞。
    fn supports_udp(&self) -> bool {
        false
    }

    /// 每个后端拥有自己的拨号、重连和协议握手超时；调用方不应再用一个了解
    /// 具体后端实现的外层超时包裹它。
    ///
    /// # Errors
    /// 连接失败（超时、拒绝、网络不可达、域名解析失败等）时返回 `io::Error`。
    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Connected>;

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
