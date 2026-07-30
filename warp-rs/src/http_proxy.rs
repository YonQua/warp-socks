// HTTP 正向代理：CONNECT（隧道 HTTPS）+ 明文 HTTP 转发。对照 warp-plus
// `proxy/pkg/http/server.go`：用 http.ReadRequest 解析请求（这里用 httparse
// 做等价的请求行+头部解析，同样是成熟的第三方解析器而非手搓，对应 Go
// 选用标准库 net/http 而非自己写 HTTP 解析的工程决策）；CONNECT 回
// "200 Connection Established" 后原始双向转发；明文 HTTP 把请求行改写成
// origin-form（去掉 scheme/host，与 Go 版 URL.RequestURI() 效果一致）转发给
// 目标后同样双向转发，不单独处理 chunked/Content-Length 分包语义。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_smoltcp::Net;

use crate::dns::{resolve, RecordType};
use crate::relay;

const DNS_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HEAD_SIZE: usize = 16 * 1024;

struct ParsedRequest {
    method: String,
    path: String,
    version_1_0: bool,
    host_header: Option<String>,
    raw_head: Vec<u8>,
    head_len: usize,
}

async fn read_request(client: &mut TcpStream) -> Result<ParsedRequest> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 2048];
    loop {
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            bail!("客户端在请求头读完前关闭连接");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD_SIZE {
            bail!("HTTP 请求头超过 {MAX_HEAD_SIZE} 字节上限");
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(&buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let method = req.method.unwrap_or("").to_string();
                let path = req.path.unwrap_or("").to_string();
                let version_1_0 = req.version == Some(0);
                let host_header = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .map(|h| String::from_utf8_lossy(h.value).into_owned());
                return Ok(ParsedRequest {
                    method,
                    path,
                    version_1_0,
                    host_header,
                    raw_head: buf,
                    head_len,
                });
            }
            Ok(httparse::Status::Partial) => continue,
            Err(e) => bail!("HTTP 请求解析失败: {e}"),
        }
    }
}

fn split_host_port(s: &str) -> Option<(&str, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        Some((host, port))
    } else {
        let (host, port_str) = s.rsplit_once(':')?;
        Some((host, port_str.parse().ok()?))
    }
}

struct Target {
    host: String,
    port: u16,
    origin_form_path: String,
}

fn parse_target(method: &str, path: &str, host_header: Option<&str>) -> Result<Target> {
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) =
            split_host_port(path).ok_or_else(|| anyhow!("CONNECT 目标格式错误: {path}"))?;
        return Ok(Target {
            host: host.to_string(),
            port,
            origin_form_path: String::new(),
        });
    }

    if let Some(rest) = path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))
    {
        let is_https = path.starts_with("https://");
        let (authority, origin_path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (host, port) =
            split_host_port(authority).unwrap_or((authority, if is_https { 443 } else { 80 }));
        Ok(Target {
            host: host.to_string(),
            port,
            origin_form_path: origin_path.to_string(),
        })
    } else {
        let host_header = host_header.ok_or_else(|| anyhow!("HTTP 请求缺少 Host 头"))?;
        let (host, port) = split_host_port(host_header).unwrap_or((host_header, 80));
        Ok(Target {
            host: host.to_string(),
            port,
            origin_form_path: path.to_string(),
        })
    }
}

async fn resolve_host(net: &Net, host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs = resolve(net, DNS_SERVER, host, RecordType::A, DNS_TIMEOUT)
        .await
        .with_context(|| format!("隧道内解析域名 {host} 失败"))?;
    let ip = addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("域名 {host} 未解析到地址"))?;
    Ok(SocketAddr::new(ip, port))
}

fn describe_target(host: &str, port: u16, resolved: SocketAddr) -> String {
    if host.parse::<IpAddr>().is_ok() {
        resolved.to_string()
    } else {
        format!("{host}:{port}({resolved})")
    }
}

pub(crate) async fn handle_client(
    mut client: TcpStream,
    peer: SocketAddr,
    net: &Net,
) -> Result<()> {
    let parsed = read_request(&mut client).await?;
    let is_connect = parsed.method.eq_ignore_ascii_case("CONNECT");
    let target_info = parse_target(&parsed.method, &parsed.path, parsed.host_header.as_deref())?;
    let target = resolve_host(net, &target_info.host, target_info.port).await?;
    let target_display = describe_target(&target_info.host, target_info.port, target);

    if is_connect {
        let outbound = match relay::connect(net, target).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e).with_context(|| format!("隧道内连接 {target_display} 失败"));
            }
        };
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        println!("连接 {peer} -> {target_display}: 已建立");
        relay::tunnel_tcp(client, outbound).await
    } else {
        let mut outbound = match relay::connect(net, target).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                return Err(e).with_context(|| format!("隧道内连接 {target_display} 失败"));
            }
        };

        let version = if parsed.version_1_0 {
            "HTTP/1.0"
        } else {
            "HTTP/1.1"
        };
        let mut rewritten = format!(
            "{} {} {version}\r\n",
            parsed.method, target_info.origin_form_path
        )
        .into_bytes();
        // 请求行之后到头部结束（含空行）之间的原始字节就是各 header 行，原样转发。
        let headers_start = parsed
            .raw_head
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|p| p + 2)
            .unwrap_or(parsed.head_len);
        rewritten.extend_from_slice(&parsed.raw_head[headers_start..parsed.head_len]);
        outbound.write_all(&rewritten).await?;
        // 已经读入但属于 body 的那部分字节（比如 POST 数据的开头）先转发过去。
        outbound
            .write_all(&parsed.raw_head[parsed.head_len..])
            .await?;

        println!("连接 {peer} -> {target_display}: 已建立");
        relay::tunnel_tcp(client, outbound).await
    }
}
