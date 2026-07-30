// SOCKS4/SOCKS4a 服务端，只实现 CONNECT（0x01）。协议细节对照
// warp-plus `proxy/pkg/socks4/{server,common}.go`：
// 请求 = VER(1)=4 + CMD(1) + PORT(2 BE) + IP(4) + USERID(以 \0 结尾，忽略内容)
//   + 若 IP == 0.0.0.1（SOCKS4a 哨兵值）则再跟一个以 \0 结尾的域名。
// 回复 = 0x00 + 状态码(0x5a 成功/0x5b 拒绝) + PORT(2 BE，全 0) + IP(4，全 0)。
// USERID 字段不做任何校验，仅读取丢弃（与 Go 版行为一致）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_smoltcp::Net;

use crate::dns::{resolve, RecordType};
use crate::relay;

const DNS_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

const CMD_CONNECT: u8 = 0x01;
const GRANTED: u8 = 0x5a;
const REJECTED: u8 = 0x5b;

const SOCKS4A_SENTINEL: [u8; 4] = [0, 0, 0, 1];

async fn read_cstring(client: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::new();
    loop {
        let b = client.read_u8().await?;
        if b == 0 {
            break;
        }
        buf.push(b);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn reply(client: &mut TcpStream, code: u8) -> Result<()> {
    client.write_all(&[0x00, code, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

pub(crate) async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    net: &Net,
) -> Result<()> {
    // mixed::dispatch 只 peek 了版本字节（0x04）没有消费，这里要先读掉它。
    let _version = client.read_u8().await?;
    let cmd = client.read_u8().await?;
    if cmd != CMD_CONNECT {
        let _ = reply(&mut client, REJECTED).await;
        bail!("SOCKS4 不支持的命令: {cmd}");
    }

    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    let mut ip_buf = [0u8; 4];
    client.read_exact(&mut ip_buf).await?;
    let is_socks4a = ip_buf == SOCKS4A_SENTINEL;

    let _username = read_cstring(&mut client).await?; // 不校验，只读掉

    let (target, target_display) = if is_socks4a {
        let host = read_cstring(&mut client).await?;
        match resolve(net, DNS_SERVER, &host, RecordType::A, DNS_TIMEOUT).await {
            Ok(addrs) => match addrs.into_iter().next() {
                Some(ip) => {
                    let addr = SocketAddr::new(ip, port);
                    (addr, format!("{host}:{port}({addr})"))
                }
                None => {
                    let _ = reply(&mut client, REJECTED).await;
                    bail!("域名 {host} 未解析到地址");
                }
            },
            Err(e) => {
                let _ = reply(&mut client, REJECTED).await;
                return Err(e).with_context(|| format!("隧道内解析域名 {host} 失败"));
            }
        }
    } else {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_buf)), port);
        (addr, addr.to_string())
    };

    let outbound = match relay::connect(net, target).await {
        Ok(s) => s,
        Err(e) => {
            let _ = reply(&mut client, REJECTED).await;
            return Err(e).with_context(|| format!("隧道内连接 {target_display} 失败"));
        }
    };
    reply(&mut client, GRANTED).await?;
    println!("连接 {peer} -> {target_display}: 已建立");

    relay::tunnel_tcp(client, outbound).await
}
