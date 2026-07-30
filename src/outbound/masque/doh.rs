// 隧道内 DoH 解析（对齐 warp-go/tunnel/masque.go 的 resolveTarget/dialDoH）：
// 域名先通过 MASQUE 隧道内的一条独立 CONNECT 流解析成 IP，再拿 IP 去建真正的
// 目标 CONNECT，避免把域名原样交给边缘（边缘不做解析，见 mod.rs 头部说明）。
//
// 具体路径：CONNECT 到固定 Cloudflare DoH 出口 IP → 标准证书校验 TLS
// （SNI=cloudflare-dns.com，走公开 CA 链，与到边缘的 pinned-key TLS 是两回事）
// → 手写 HTTP/1.1 POST /dns-query（RFC 8484 wire format）→ 解析 A/AAAA。
//
// 不引入 h2/DNS 消息 crate：单发单收的请求量下 HTTP/1.1 + 手写 DNS 报文足够，
// 和 qpack.rs 的手写 H3/QPACK 保持同样的最小实现原则。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

/// 固定的 Cloudflare DoH 出口 IP（无需解析，直接当 CONNECT 的 authority 用）。
pub(super) const DOH_ADDRS: [&str; 2] = ["162.159.36.1:443", "162.159.46.1:443"];
const DOH_SNI: &str = "cloudflare-dns.com";
const DOH_PATH: &str = "/dns-query";
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const MIN_TTL: Duration = Duration::from_secs(5);
const MAX_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy)]
pub(super) enum QueryType {
    A,
    Aaaa,
}

impl QueryType {
    fn code(self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::Aaaa => 28,
        }
    }
}

struct CacheEntry {
    ip: IpAddr,
    expires_at: Instant,
}

/// 域名 → IP 的 TTL 缓存 + 复用的标准 TLS 配置。
pub(super) struct DnsCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
    tls: Arc<rustls::ClientConfig>,
}

impl DnsCache {
    /// # Errors
    /// 构造标准根证书 TLS 配置失败时返回错误。
    pub(super) fn new() -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // 显式传 ring provider：项目未装 process-default CryptoProvider（tls.rs 同样显式传），
        // 且只编译了 ring 后端（未启用 aws_lc_rs），不能用隐式 builder()。
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .context("构造 DoH TLS 协议版本失败")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            entries: Mutex::new(HashMap::new()),
            tls: Arc::new(cfg),
        })
    }

    pub(super) async fn cached(&self, domain: &str) -> Option<IpAddr> {
        let entries = self.entries.lock().await;
        entries
            .get(domain)
            .filter(|e| e.expires_at > Instant::now())
            .map(|e| e.ip)
    }

    async fn store(&self, domain: &str, ip: IpAddr, ttl: Duration) {
        let ttl = ttl.clamp(MIN_TTL, MAX_TTL);
        let mut entries = self.entries.lock().await;
        entries.insert(
            domain.to_string(),
            CacheEntry {
                ip,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// 在已建立的隧道字节流（到 DoH 出口 IP）上做 TLS 握手 + 一次 DoH 查询，
    /// 命中则顺带写入缓存。
    ///
    /// # Errors
    /// TLS 握手、请求/响应收发、DNS 报文解析失败时返回错误。
    pub(super) async fn resolve_over(
        &self,
        stream: impl AsyncRead + AsyncWrite + Unpin,
        domain: &str,
        qtype: QueryType,
    ) -> Result<IpAddr> {
        let connector = TlsConnector::from(self.tls.clone());
        let server_name =
            rustls::pki_types::ServerName::try_from(DOH_SNI).context("DoH SNI 非法")?;
        let mut tls = tokio::time::timeout(QUERY_TIMEOUT, connector.connect(server_name, stream))
            .await
            .context("DoH TLS 握手超时")?
            .context("DoH TLS 握手失败")?;

        let query = build_query(domain, qtype.code())?;
        let request = build_http_request(&query);
        tokio::time::timeout(QUERY_TIMEOUT, tls.write_all(&request))
            .await
            .context("DoH 请求发送超时")??;
        tokio::time::timeout(QUERY_TIMEOUT, tls.flush())
            .await
            .context("DoH 请求 flush 超时")??;

        let body = tokio::time::timeout(QUERY_TIMEOUT, read_http_response(&mut tls))
            .await
            .context("DoH 响应读取超时")??;

        let (ip, ttl) = parse_answer(&body)?;
        self.store(domain, ip, ttl).await;
        Ok(ip)
    }
}

/// 构造 RFC 1035 wire-format 单问题查询：ID 固定 0（RFC 8484 §4.1 建议，便于中间缓存），
/// RD=1，QDCOUNT=1，无 AN/NS/AR。
fn build_query(domain: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(32 + domain.len());
    msg.extend_from_slice(&[0x00, 0x00]); // ID = 0
    msg.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
    msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    msg.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("域名标签长度非法: {label:?}");
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root

    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    Ok(msg)
}

/// RFC 8484 §4.1：POST + `application/dns-message`，显式清空 body 编码，无需分块。
fn build_http_request(body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "POST {DOH_PATH} HTTP/1.1\r\n\
         host: {DOH_SNI}\r\n\
         content-type: application/dns-message\r\n\
         accept: application/dns-message\r\n\
         content-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    req
}

/// 读 HTTP/1.1 响应：先攒到 header 结束，再按 content-length 精确读满 body
/// （不能指望连接会主动关闭来做 EOF 判断，Cloudflare 默认走 keep-alive）。
async fn read_http_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.context("读取 DoH 响应失败")?;
        if n == 0 {
            bail!("DoH 连接在响应头读完前关闭");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 8192 {
            bail!("DoH 响应头过大");
        }
    };

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&buf[..header_end])
        .context("解析 DoH 响应头失败")?;
    let status = resp.code.unwrap_or(0);
    if status != 200 {
        bail!("DoH 服务器返回状态 {status}");
    }
    let content_length: usize = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse().ok())
        .context("DoH 响应缺少合法的 content-length")?;

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream
            .read(&mut chunk)
            .await
            .context("读取 DoH 响应体失败")?;
        if n == 0 {
            bail!("DoH 响应体未读满连接已关闭");
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok(body)
}

/// 从 DNS 响应报文里取第一条 A/AAAA 记录及其 TTL。
fn parse_answer(msg: &[u8]) -> Result<(IpAddr, Duration)> {
    if msg.len() < 12 {
        bail!("DNS 响应过短");
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?;
        pos = pos.checked_add(4).context("QTYPE/QCLASS 越界")?; // QTYPE + QCLASS
    }

    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            bail!("DNS 答案记录截断");
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > msg.len() {
            bail!("DNS 答案数据截断");
        }
        let rdata = &msg[pos..pos + rdlength];
        pos += rdlength;
        match (rtype, rdlength) {
            (1, 4) => {
                let ip = IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]);
                return Ok((ip, Duration::from_secs(u64::from(ttl))));
            }
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                return Ok((IpAddr::from(octets), Duration::from_secs(u64::from(ttl))));
            }
            _ => continue,
        }
    }
    bail!("DoH 响应未包含 A/AAAA 记录")
}

/// 跳过一个 DNS 名称（含压缩指针，指针本身不跟随，只按 2 字节跳过）。
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        if pos >= msg.len() {
            bail!("DNS 名称越界");
        }
        let len = msg[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= msg.len() {
                bail!("DNS 压缩指针越界");
            }
            return Ok(pos + 2);
        }
        pos = pos
            .checked_add(1 + len as usize)
            .ok_or_else(|| anyhow::anyhow!("DNS 名称长度溢出"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_encodes_labels_and_qtype() {
        let msg = build_query("cloudflare.com", 1).unwrap();
        assert_eq!(&msg[..6], &[0x00, 0x00, 0x01, 0x00, 0x00, 0x01]);
        // label "cloudflare"(10) + "com"(3) + root(0)
        assert_eq!(msg[12], 10);
        assert_eq!(&msg[13..23], b"cloudflare");
        assert_eq!(msg[23], 3);
        assert_eq!(&msg[24..27], b"com");
        assert_eq!(msg[27], 0);
        assert_eq!(&msg[28..30], &[0x00, 0x01]); // QTYPE=A
        assert_eq!(&msg[30..32], &[0x00, 0x01]); // QCLASS=IN
    }

    #[test]
    fn parse_answer_extracts_first_a_record() {
        let mut msg = build_query("example.com", 1).unwrap();
        msg[6] = 0x00;
        msg[7] = 0x01; // ANCOUNT = 1
                       // answer: 名称用压缩指针指回 offset 12（问题区），TYPE=A, CLASS=IN, TTL=300, RDLEN=4, RDATA
        msg.extend_from_slice(&[0xc0, 0x0c]);
        msg.extend_from_slice(&[0x00, 0x01]); // TYPE A
        msg.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
        msg.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        msg.extend_from_slice(&[93, 184, 216, 34]); // RDATA

        let (ip, ttl) = parse_answer(&msg).unwrap();
        assert_eq!(ip, IpAddr::from([93, 184, 216, 34]));
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn http_request_has_matching_content_length() {
        let body = vec![1u8, 2, 3];
        let req = build_http_request(&body);
        let text = String::from_utf8(req.clone()).unwrap();
        assert!(text.starts_with("POST /dns-query HTTP/1.1\r\n"));
        assert!(text.contains("content-length: 3\r\n"));
        assert!(req.ends_with(&body));
    }
}
