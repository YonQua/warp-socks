// RFC 1928 SOCKS5 服务端：CONNECT（0x01）+ UDP ASSOCIATE（0x03），无认证。
// 出网通过 Outbound trait，不关心底层是 WireGuard 虚拟网卡还是 MASQUE。
//
// UDP ASSOCIATE 的转发语义对照 warp-plus `proxy/pkg/socks5/server.go:
// embedHandleAssociate`：只记住第一个客户端来源地址和第一个目的地址，
// 之后的包一律转发到这唯一一对 (source, target)——不支持一个 ASSOCIATE
// 会话内动态切换多个目的地，这是 Go 版本自己的简化，这里原样保留。
//
// UDP 的实际出网路径优先走 Outbound::connect_udp（后端支持则数据报也走隧道，
// 目前只有 WireGuard 后端支持）；后端返回 Unsupported（比如 MASQUE，H3
// CONNECT 是字节流扛不了 datagram）时才回退到宿主机网络直连出口。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use log::{info, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::outbound::{Datagram, Host, Outbound};
use crate::relay;

const REP_SUCCEEDED: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

async fn reply(client: &mut TcpStream, rep: u8) -> Result<()> {
    client
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn reply_with_addr(client: &mut TcpStream, rep: u8, addr: SocketAddr) -> Result<()> {
    let mut msg = vec![0x05, rep, 0x00];
    match addr {
        SocketAddr::V4(v4) => {
            msg.push(0x01);
            msg.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            msg.push(0x04);
            msg.extend_from_slice(&v6.ip().octets());
        }
    }
    msg.extend_from_slice(&addr.port().to_be_bytes());
    client.write_all(&msg).await?;
    Ok(())
}

pub(crate) async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    outbound: &dyn Outbound,
) -> Result<()> {
    // 方法协商：只接受“无认证”（0x00）。
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("不支持的 SOCKS 版本: {}", head[0]);
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xFF]).await?;
        bail!("客户端不支持无认证方式");
    }
    client.write_all(&[0x05, 0x00]).await?;

    // 请求：CONNECT 或 UDP ASSOCIATE。
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("不支持的 SOCKS 版本: {}", req[0]);
    }
    if !matches!(req[1], CMD_CONNECT | CMD_UDP_ASSOCIATE) {
        let _ = reply(&mut client, REP_CMD_NOT_SUPPORTED).await;
        bail!("不支持的命令: {}", req[1]);
    }

    if !matches!(req[3], 0x01 | 0x03 | 0x04) {
        let _ = reply(&mut client, REP_ATYP_NOT_SUPPORTED).await;
        bail!("不支持的地址类型: {}", req[3]);
    }

    match req[1] {
        CMD_CONNECT => handle_connect(client, peer, req[3], outbound).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(client, peer, req[3], outbound).await,
        _ => unreachable!(),
    }
}

/// 已解析的 SOCKS5 连接目标：主机（域名或 IP）+ 端口。
struct Target {
    host: Host,
    port: u16,
    display: String,
}

async fn handle_connect(
    mut client: TcpStream,
    peer: SocketAddr,
    atyp: u8,
    outbound: &dyn Outbound,
) -> Result<()> {
    let target = match read_target(&mut client, atyp).await {
        Ok(t) => t,
        Err(e) => {
            let _ = reply(&mut client, REP_HOST_UNREACHABLE).await;
            return Err(e);
        }
    };

    let conn = match relay::connect(outbound, target.host.clone(), target.port).await {
        Ok(s) => s,
        Err(e) => {
            let _ = reply(&mut client, REP_HOST_UNREACHABLE).await;
            return Err(e).with_context(|| format!("隧道内连接 {} 失败", target.display));
        }
    };
    reply(&mut client, REP_SUCCEEDED).await?;
    info!("连接 {peer} -> {}: 已建立", target.display);

    relay::tunnel_tcp(client, conn).await
}

// RFC 1928 UDP 请求/响应头：RSV(2)+FRAG(1)+ATYP(1)+ADDR+PORT，之后是负载。
// 只支持 FRAG=0（不分片），domain ATYP 走隧道内 DNS 解析。
fn decode_udp_header(buf: &[u8]) -> Option<(SocketAddrOrName, usize)> {
    if buf.len() < 4 || buf[2] != 0x00 {
        return None;
    }
    let atyp = buf[3];
    let mut pos = 4;
    let target = match atyp {
        0x01 => {
            if buf.len() < pos + 4 + 2 {
                return None;
            }
            let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
            pos += 4;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            SocketAddrOrName::Addr(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            if buf.len() < pos + 16 + 2 {
                return None;
            }
            let octets: [u8; 16] = buf[pos..pos + 16].try_into().ok()?;
            pos += 16;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            SocketAddrOrName::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0x03 => {
            if buf.len() < pos + 1 {
                return None;
            }
            let len = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + len + 2 {
                return None;
            }
            let name = String::from_utf8(buf[pos..pos + len].to_vec()).ok()?;
            pos += len;
            let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            pos += 2;
            SocketAddrOrName::Name(name, port)
        }
        _ => return None,
    };
    Some((target, pos))
}

enum SocketAddrOrName {
    Addr(SocketAddr),
    Name(String, u16),
}

fn target_host_port(target: &SocketAddrOrName) -> (Host, u16) {
    match target {
        SocketAddrOrName::Addr(a) => (Host::Ip(a.ip()), a.port()),
        SocketAddrOrName::Name(name, port) => (Host::Domain(name.clone()), *port),
    }
}

async fn handle_udp_associate(
    mut client: TcpStream,
    peer: SocketAddr,
    atyp: u8,
    outbound: &dyn Outbound,
) -> Result<()> {
    // 客户端在请求里带的 DST.ADDR/DST.PORT 只是建议地址，实际以每个 UDP 包
    // 自带的头部为准（多数客户端直接填 0.0.0.0:0），这里读掉但不解析、不使用。
    skip_target(&mut client, atyp).await?;

    let bind_ip = client.local_addr().context("获取本地地址失败")?.ip();
    let relay_sock = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .context("绑定 UDP ASSOCIATE 中继 socket 失败")?;
    let relay_addr = relay_sock.local_addr()?;

    if let Err(e) = reply_with_addr(&mut client, REP_SUCCEEDED, relay_addr).await {
        return Err(e).context("UDP ASSOCIATE 回复失败");
    }

    let mut client_addr: Option<SocketAddr> = None;
    let mut egress: Option<Box<dyn Datagram>> = None;
    let mut relay_buf = [0u8; 65536];
    let mut target_buf = [0u8; 65536];
    let mut ctrl_buf = [0u8; 1];

    loop {
        tokio::select! {
            // 控制连接关闭即拆除整个 UDP ASSOCIATE 会话（RFC1928 语义）。
            r = client.read(&mut ctrl_buf) => {
                match r {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => continue,
                }
            }
            r = relay_sock.recv_from(&mut relay_buf) => {
                let (n, from) = r.context("UDP ASSOCIATE 中继读失败")?;
                if client_addr.is_none() {
                    client_addr = Some(from);
                } else if client_addr != Some(from) {
                    continue; // 忽略非首个来源
                }
                let Some((target, header_len)) = decode_udp_header(&relay_buf[..n]) else {
                    continue;
                };
                if egress.is_none() {
                    egress = establish_egress(outbound, &target, bind_ip, peer).await;
                }
                if let Some(e) = &egress {
                    let _ = e.send(&relay_buf[header_len..n]).await;
                }
            }
            // 回包：目标 → 客户端；egress 建立前这个分支永不就绪。
            r = async {
                match &egress {
                    Some(e) => e.recv(&mut target_buf).await,
                    None => futures::future::pending().await,
                }
            } => {
                let Ok(n) = r else { continue };
                if let Some(client_addr) = client_addr {
                    let from = egress.as_ref().expect("recv 成功说明 egress 已建立").peer_addr();
                    let mut wrapped = encode_udp_header(from);
                    wrapped.extend_from_slice(&target_buf[..n]);
                    let _ = relay_sock.send_to(&wrapped, client_addr).await;
                }
            }
        }
    }
}

/// 建立到目标的 UDP 出网通道：优先走 Outbound::connect_udp（数据报走隧道）；
/// 后端明确回报 Unsupported 才回退到宿主机网络直连（域名用宿主机解析器）。
async fn establish_egress(
    outbound: &dyn Outbound,
    target: &SocketAddrOrName,
    bind_ip: IpAddr,
    peer: SocketAddr,
) -> Option<Box<dyn Datagram>> {
    let (host, port) = target_host_port(target);
    match outbound.connect_udp(host, port).await {
        Ok(d) => {
            info!(
                "连接 {peer} -> {}: 已建立（UDP ASSOCIATE，经隧道）",
                d.peer_addr()
            );
            Some(d)
        }
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
            info!("UDP ASSOCIATE: 当前出网后端不支持隧道内 UDP，改走宿主机网络直连出口");
            match host_datagram(bind_ip, target).await {
                Ok((d, display)) => {
                    info!("连接 {peer} -> {display}: 已建立（UDP ASSOCIATE，宿主机出口）");
                    Some(Box::new(d) as Box<dyn Datagram>)
                }
                Err(e) => {
                    warn!("UDP ASSOCIATE 宿主机出口建立失败: {e:#}");
                    None
                }
            }
        }
        Err(e) => {
            warn!("UDP ASSOCIATE 隧道内建立失败: {e}");
            None
        }
    }
}

fn encode_udp_header(target: SocketAddr) -> Vec<u8> {
    let mut out = vec![0u8, 0u8, 0u8];
    match target {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out
}

/// 宿主机网络直连的 UDP 数据报通道（MASQUE 等不支持隧道内 UDP 的后端回退用）。
struct HostDatagram {
    sock: tokio::net::UdpSocket,
    target: SocketAddr,
}

#[async_trait]
impl Datagram for HostDatagram {
    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<()> {
        self.sock.send_to(buf, self.target).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let (n, from) = self.sock.recv_from(buf).await?;
            if from == self.target {
                return Ok(n);
            }
        }
    }
}

/// 用宿主机解析器解析 UDP 目标并绑定出网 socket（不经过隧道）。
async fn host_datagram(
    bind_ip: IpAddr,
    target: &SocketAddrOrName,
) -> Result<(HostDatagram, String)> {
    use tokio::net::lookup_host;
    let (addr, display) = match target {
        SocketAddrOrName::Addr(a) => (*a, a.to_string()),
        SocketAddrOrName::Name(name, port) => {
            let addr = lookup_host(format!("{name}:{port}"))
                .await
                .with_context(|| format!("解析 {name}:{port} 失败"))?
                .next()
                .ok_or_else(|| anyhow!("{name}:{port} 未解析到地址"))?;
            (addr, format!("{name}:{port}({addr})"))
        }
    };
    let sock = tokio::net::UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .context("绑定 UDP ASSOCIATE 出网 socket 失败")?;
    Ok((HostDatagram { sock, target: addr }, display))
}

async fn read_target(client: &mut TcpStream, atyp: u8) -> Result<Target> {
    // 域名不在此解析：交给后端（MASQUE 直接交边缘解析，WireGuard 走虚拟网卡 DNS）。
    match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(addr));
            let port = u16::from_be_bytes(port);
            Ok(Target {
                host: Host::Ip(ip),
                port,
                display: format!("{ip}:{port}"),
            })
        }
        0x04 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(addr));
            let port = u16::from_be_bytes(port);
            Ok(Target {
                host: Host::Ip(ip),
                port,
                display: format!("{ip}:{port}"),
            })
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let mut name = vec![0u8; len_buf[0] as usize];
            client.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            client.read_exact(&mut port).await?;
            let name = String::from_utf8(name).context("域名不是合法 UTF-8")?;
            let port = u16::from_be_bytes(port);
            Ok(Target {
                host: Host::Domain(name.clone()),
                port,
                display: format!("{name}:{port}"),
            })
        }
        other => bail!("不支持的地址类型: {other}"),
    }
}

// 只按 ATYP 读掉地址字段的字节数，不解析、不做 DNS 查询——UDP ASSOCIATE
// 请求里的 DST.ADDR/DST.PORT 只是建议值，实际转发目的地以每个 UDP 包
// 自带的头部为准。
async fn skip_target(client: &mut TcpStream, atyp: u8) -> Result<()> {
    match atyp {
        0x01 => {
            client.read_exact(&mut [0u8; 4 + 2]).await?;
        }
        0x04 => {
            client.read_exact(&mut [0u8; 16 + 2]).await?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let mut rest = vec![0u8; len_buf[0] as usize + 2];
            client.read_exact(&mut rest).await?;
        }
        other => bail!("不支持的地址类型: {other}"),
    }
    Ok(())
}
