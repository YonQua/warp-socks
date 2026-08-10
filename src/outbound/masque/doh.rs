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

use crate::dns::{encode_dns_query, parse_dns_response, RecordType};

/// 固定的 Cloudflare DoH 出口 IP（无需解析，直接当 CONNECT 的 authority 用）。
pub(super) const DOH_ADDRS: [&str; 2] = ["162.159.36.1:443", "162.159.46.1:443"];
const DOH_SNI: &str = "cloudflare-dns.com";
const DOH_PATH: &str = "/dns-query";
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const MIN_TTL: Duration = Duration::from_secs(5);
const MAX_TTL: Duration = Duration::from_secs(300);

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
        record_type: RecordType,
    ) -> Result<IpAddr> {
        let connector = TlsConnector::from(self.tls.clone());
        let server_name =
            rustls::pki_types::ServerName::try_from(DOH_SNI).context("DoH SNI 非法")?;
        let mut tls = tokio::time::timeout(QUERY_TIMEOUT, connector.connect(server_name, stream))
            .await
            .context("DoH TLS 握手超时")?
            .context("DoH TLS 握手失败")?;

        let query = encode_dns_query(0, domain, record_type)?;
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

        let (addrs, ttl) = parse_dns_response(&body, 0, record_type)?;
        let ip = addrs
            .into_iter()
            .next()
            .context("DoH 响应未包含请求的地址记录")?;
        self.store(domain, ip, Duration::from_secs(u64::from(ttl)))
            .await;
        Ok(ip)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
