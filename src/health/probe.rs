// 对应 lib/core/probe.sh: probe_socks_trace —— 通过本地 SOCKS5 代理（域名解析
// 走隧道）请求 trace 接口，检查响应里的 warp=on|plus 标记，这是隧道对外提供
// 的真实使用路径，比直接探测出口 IP 更贴近实际用户流量。

use std::net::SocketAddr;
use std::time::Duration;

/// 探测成功时携带的信息（当前出口 IP，若响应里有）。
#[derive(Debug, Default, Clone)]
pub struct ProbeOutcome {
    pub ip: Option<String>,
}

#[derive(Debug)]
pub enum ProbeError {
    Request(String),
    MissingWarpMarker(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Request(msg) => write!(f, "请求失败: {msg}"),
            ProbeError::MissingWarpMarker(msg) => write!(f, "响应缺少 warp 标记: {msg}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// SOCKS5 trace 健康探测，对应 lib/core/probe.sh。
pub struct SocksTraceProbe {
    pub socks_addr: SocketAddr,
    pub timeout: Duration,
    pub trace_url: String,
}

impl SocksTraceProbe {
    #[must_use]
    pub fn new(socks_addr: SocketAddr, timeout: Duration) -> Self {
        Self {
            socks_addr,
            timeout,
            trace_url: "https://cloudflare.com/cdn-cgi/trace".to_string(),
        }
    }

    /// # Errors
    /// 探测失败（超时、连接失败、响应缺少 warp 标记）时返回错误。
    pub async fn probe(&self) -> Result<ProbeOutcome, ProbeError> {
        let proxy_url = format!("socks5h://{}", self.socks_addr);
        let proxy =
            reqwest::Proxy::all(&proxy_url).map_err(|e| ProbeError::Request(e.to_string()))?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .timeout(self.timeout)
            .build()
            .map_err(|e| ProbeError::Request(e.to_string()))?;

        let resp = client
            .get(&self.trace_url)
            .send()
            .await
            .map_err(|e| ProbeError::Request(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(ProbeError::Request(format!("HTTP {status}")));
        }

        let has_warp_marker = body
            .lines()
            .any(|line| line == "warp=on" || line == "warp=plus");
        if !has_warp_marker {
            return Err(ProbeError::MissingWarpMarker(summarize(&body)));
        }

        Ok(ProbeOutcome {
            ip: extract_trace_field(&body, "ip"),
        })
    }
}

fn extract_trace_field(body: &str, field: &str) -> Option<String> {
    let prefix = format!("{field}=");
    body.lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::to_string)
}

fn summarize(body: &str) -> String {
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(180).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_trace_fields() {
        let body = "ip=1.2.3.4\nwarp=on\ncolo=ABC\n";
        assert_eq!(extract_trace_field(body, "ip").as_deref(), Some("1.2.3.4"));
        assert_eq!(extract_trace_field(body, "colo").as_deref(), Some("ABC"));
        assert_eq!(extract_trace_field(body, "missing"), None);
    }
}
