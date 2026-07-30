// Cloudflare WARP Teams（WireGuard 账户）注册：用 Cloudflare Access 签发的
// TEAMS_TOKEN 换取一个完整 WARP 账户（含 WireGuard 私钥、边缘公钥/endpoint、
// 分配的隧道内地址），翻译自 lib/domain/account.sh: account_register_via_teams。
//
// 与 registration::masque 的两步 MASQUE 注册是两条独立的注册流程：这里产出
// 的 WgAccount 走 WireGuard 隧道（config.rs::parse_wg_conf 消费的 wg0.conf），
// masque 产出的 RegCredentials 走 MASQUE over QUIC/H3。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::{info, warn};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::fsutil::restrict_to_owner;

const REGISTER_URL: &str = "https://api.cloudflareclient.com/v0a2158/reg";
const CF_CLIENT_VERSION: &str = "a-6.10-2158";

/// Teams 注册产出的 WireGuard 账户（等价于 account.json 的必需字段）。
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct WgAccount {
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub config: WgAccountConfig,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct WgAccountConfig {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub peers: Vec<WgAccountPeer>,
    #[serde(default)]
    pub interface: WgAccountInterface,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct WgAccountPeer {
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub endpoint: WgAccountEndpoint,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct WgAccountEndpoint {
    #[serde(default)]
    pub host: String,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct WgAccountInterface {
    #[serde(default)]
    pub addresses: WgAccountAddresses,
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct WgAccountAddresses {
    #[serde(default)]
    pub v4: String,
    #[serde(default)]
    pub v6: String,
}

impl WgAccount {
    /// 保存到 JSON 文件（仅所有者可读写）。
    ///
    /// # Errors
    /// 写入失败时返回错误。
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self).context("序列化账户信息失败")?;
        fs::write(path, data).with_context(|| format!("写入 {} 失败", path.display()))?;
        restrict_to_owner(path);
        Ok(())
    }

    /// 从 JSON 文件加载。
    ///
    /// # Errors
    /// 文件读取或解析失败时返回错误。
    pub fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("读取 {} 失败", path.display()))?;
        serde_json::from_slice(&data)
            .with_context(|| format!("解析账户信息失败: {}", path.display()))
    }
}

#[derive(Serialize)]
struct TeamsRegisterRequest<'a> {
    key: &'a str,
    install_id: &'a str,
    fcm_token: &'a str,
    tos: &'a str,
    model: &'a str,
    serial_number: &'a str,
    locale: &'a str,
}

/// Teams（WireGuard 账户）注册。
pub struct TeamsRegistrar {
    pub token: String,
    pub account_path: PathBuf,
    pub retries: u32,
    pub retry_delay: Duration,
}

impl TeamsRegistrar {
    #[must_use]
    pub fn new(token: impl Into<String>, account_path: impl Into<PathBuf>) -> Self {
        Self {
            token: token.into(),
            account_path: account_path.into(),
            retries: 2,
            retry_delay: Duration::from_secs(2),
        }
    }

    /// # Errors
    /// 注册流程中的网络请求、解析或密钥生成失败时返回错误。
    pub async fn register(&self) -> Result<WgAccount> {
        let raw_token = normalize_token(&self.token);
        if raw_token.is_empty() {
            bail!("必须提供 TEAMS_TOKEN。");
        }

        let secret = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
        let public = boringtun::x25519::PublicKey::from(&secret);
        let private_key_b64 = STANDARD.encode(secret.to_bytes());
        let public_key_b64 = STANDARD.encode(public.as_ref());

        let install_id = random_alnum(22);
        let fcm_token = format!("{install_id}:APA91b{}", random_alnum(134));

        let client = http_client()?;
        let retries = self.retries.max(1);
        let mut attempt = 1u32;

        loop {
            let req_body = TeamsRegisterRequest {
                key: &public_key_b64,
                install_id: &install_id,
                fcm_token: &fcm_token,
                tos: &current_tos(),
                model: "PC",
                serial_number: &install_id,
                locale: "zh_CN",
            };

            let outcome = client
                .post(REGISTER_URL)
                .header("User-Agent", "okhttp/3.12.1")
                .header("CF-Client-Version", CF_CLIENT_VERSION)
                .header("Cf-Access-Jwt-Assertion", &raw_token)
                .json(&req_body)
                .send()
                .await;

            let (status_code, retry_after, response_body) = match outcome {
                Ok(resp) => {
                    let status_code = resp.status().as_u16();
                    let retry_after = resp
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.trim().parse::<u64>().ok());
                    let body = resp.text().await.unwrap_or_default();
                    (Some(status_code), retry_after, body)
                }
                Err(e) => (None, None, e.to_string()),
            };

            if status_code == Some(200) {
                let has_account = serde_json::from_str::<serde_json::Value>(&response_body)
                    .ok()
                    .and_then(|v| v.get("account").cloned())
                    .is_some_and(|v| !v.is_null());
                if has_account {
                    let mut account: WgAccount = serde_json::from_str(&response_body)
                        .with_context(|| format!("解析 Teams 注册响应失败: {response_body}"))?;
                    account.private_key = private_key_b64;
                    account.save(&self.account_path)?;
                    info!(
                        "Teams 注册成功，账号信息已保存到 {}",
                        self.account_path.display()
                    );
                    return Ok(account);
                }
            }

            if status_code == Some(401) && response_body.contains("token is expired") {
                bail!("registration token 已过期，请重新获取。");
            }

            warn!(
                "Teams 注册失败，第 {attempt}/{retries} 次，HTTP {}",
                status_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            warn!("响应摘要: {}", summarize(&response_body));

            if attempt >= retries {
                bail!("Teams 注册失败，已达到最大重试次数。");
            }

            let mut delay = self.retry_delay.saturating_mul(attempt);
            if let Some(retry_after) = retry_after {
                delay = delay.max(Duration::from_secs(retry_after));
            }
            if status_code == Some(429) {
                warn!("Cloudflare 返回 429；当前会尊重 Retry-After，并避免立即重启后继续撞接口。");
            }
            warn!("{} 秒后重试 Teams 注册。", delay.as_secs());
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("构造 HTTP 客户端失败")
}

/// 去掉 `com.cloudflare.warp://...token=...` 包装，只保留 token 本体。
fn normalize_token(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.starts_with("com.cloudflare.warp://") || !trimmed.contains("token=") {
        return trimmed.to_string();
    }
    let Some(idx) = trimmed.rfind("token=") else {
        return trimmed.to_string();
    };
    let after_token = &trimmed[idx + "token=".len()..];
    match after_token.find('&') {
        Some(end) => after_token[..end].to_string(),
        None => after_token.to_string(),
    }
}

fn random_alnum(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn current_tos() -> String {
    use time::OffsetDateTime;
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn summarize(body: &str) -> String {
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(220).collect()
}

fn reserved_bytes(client_id: &str) -> [u8; 3] {
    if client_id.is_empty() {
        return [0, 0, 0];
    }
    let mut padded = client_id.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    let decoded = STANDARD.decode(padded.as_bytes()).unwrap_or_default();
    let mut reserved = [0u8; 3];
    for (slot, byte) in reserved.iter_mut().zip(decoded.iter()) {
        *slot = *byte;
    }
    reserved
}

fn ensure_v4_cidr(addr: &str) -> String {
    if addr.contains('/') {
        addr.to_string()
    } else {
        format!("{addr}/32")
    }
}

fn ensure_v6_cidr(addr: &str) -> String {
    if addr.contains('/') {
        addr.to_string()
    } else {
        format!("{addr}/128")
    }
}

/// 从 [`WgAccount`] 生成 wg0.conf 并写入指定路径，对应
/// lib/domain/wireguard.sh: write_wg_config + build_wg_config_from_account。
/// DNS/MTU/PersistentKeepalive 不写在这里，隧道实现固定用等价的值（见
/// config.rs 头部注释）。
///
/// # Errors
/// 账户信息缺少必要字段、或写入文件失败时返回错误。
pub fn write_wg_conf(
    account: &WgAccount,
    endpoint_override: Option<&str>,
    path: &Path,
) -> Result<()> {
    if account.private_key.is_empty() {
        bail!("WireGuard 配置缺少 PrivateKey。");
    }
    let peer = account
        .config
        .peers
        .first()
        .context("账户信息缺少 Peer 公钥/endpoint。")?;
    if peer.public_key.is_empty() {
        bail!("WireGuard 配置缺少 Peer PublicKey。");
    }
    let address_v4 = &account.config.interface.addresses.v4;
    let address_v6 = &account.config.interface.addresses.v6;
    if address_v4.is_empty() {
        bail!("账户信息缺少 IPv4 地址。");
    }
    if address_v6.is_empty() {
        bail!("账户信息缺少 IPv6 地址。");
    }

    let endpoint_host = endpoint_override
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if peer.endpoint.host.is_empty() {
                "engage.cloudflareclient.com:2408".to_string()
            } else {
                peer.endpoint.host.clone()
            }
        });

    let reserved = reserved_bytes(&account.config.client_id);
    let text = format!(
        "[Interface]\n\
         PrivateKey = {}\n\
         Address = {}\n\
         Address = {}\n\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         AllowedIPs = 0.0.0.0/0,::/0\n\
         Endpoint = {}\n\
         Reserved = {},{},{}\n",
        account.private_key,
        ensure_v4_cidr(address_v4),
        ensure_v6_cidr(address_v6),
        peer.public_key,
        endpoint_host,
        reserved[0],
        reserved[1],
        reserved[2],
    );

    fs::write(path, text).with_context(|| format!("写入 {} 失败", path.display()))?;
    restrict_to_owner(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_token_strips_uri_wrapper() {
        assert_eq!(
            normalize_token("com.cloudflare.warp://register?token=abc123&other=1"),
            "abc123"
        );
        assert_eq!(normalize_token("plain-token"), "plain-token");
        assert_eq!(
            normalize_token("com.cloudflare.warp://register?token=abc123"),
            "abc123"
        );
    }

    #[test]
    fn reserved_bytes_from_client_id() {
        // "AQID" 是 [1,2,3] 的标准 base64（无需补 padding）。
        assert_eq!(reserved_bytes("AQID"), [1, 2, 3]);
        assert_eq!(reserved_bytes(""), [0, 0, 0]);
    }

    #[test]
    fn write_wg_conf_rejects_missing_fields() {
        let account = WgAccount::default();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        assert!(write_wg_conf(&account, None, &path).is_err());
    }

    #[test]
    fn write_wg_conf_uses_override_endpoint() {
        let account = WgAccount {
            private_key: "priv".to_string(),
            config: WgAccountConfig {
                client_id: String::new(),
                peers: vec![WgAccountPeer {
                    public_key: "peer-pub".to_string(),
                    endpoint: WgAccountEndpoint {
                        host: "default.example:2408".to_string(),
                    },
                }],
                interface: WgAccountInterface {
                    addresses: WgAccountAddresses {
                        v4: "10.0.0.2".to_string(),
                        v6: "fd00::2".to_string(),
                    },
                },
            },
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        write_wg_conf(&account, Some("1.2.3.4:2408"), &path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("Endpoint = 1.2.3.4:2408"));
        assert!(text.contains("Address = 10.0.0.2/32"));
        assert!(text.contains("Address = fd00::2/128"));
        assert!(text.contains("Reserved = 0,0,0"));
    }
}
