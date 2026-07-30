// Cloudflare WARP 注册：两步流程拿到 MASQUE 凭据。
//
// Step 1: POST /v0/reg，带一个临时的 Curve25519（WireGuard）公钥创建设备。
// Step 2: PATCH /v0/reg/{id}，登记 ECDSA P-256 密钥并切换 tunnel_type=masque，
//         响应里才带边缘地址、端口列表和边缘公钥。
//
// 翻译自 warp-go/registration/registration.go，公钥编码格式严格对齐：
//   - step2 的 key 是 ECDSA P-256 公钥的 PKIX SPKI DER → base64（Go x509.MarshalPKIXPublicKey）
//   - 边缘公钥（peer_public_key）也存成 base64 SPKI DER（API 返回的是 PEM SPKI，解析后规范化）

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://api.cloudflareclient.com/v0";
const CLIENT_VERSION: &str = "linux-2026.6.880.0";
const USER_AGENT: &str = "WARP for Linux";

/// WARP 注册信息（可序列化到 reg.json）。
#[derive(Serialize, Deserialize)]
pub struct Registration {
    pub id: String,
    pub token: String,
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub key_type: String,
    #[serde(default)]
    pub tunnel_type: String,
    /// ECDSA P-256 私钥的 PKCS8 DER → base64（rcgen/rustls 在 ring 后端下只接 PKCS8）。
    private_key: String,
    /// 边缘信息（step2 响应）。
    #[serde(default)]
    pub endpoint_v4: String,
    #[serde(default)]
    pub endpoint_v6: String,
    #[serde(default)]
    pub endpoint_ports: Vec<u16>,
    /// base64 PKIX SPKI DER。固定边缘用。
    #[serde(default)]
    pub peer_public_key: String,
    #[serde(default)]
    pub assigned_ipv4: String,
    #[serde(default)]
    pub assigned_ipv6: String,
}

/// 运行时所需的凭据：注册信息 + 重建的客户端证书与边缘固定公钥。
pub struct RegCredentials {
    pub registration: Registration,
    /// 自签客户端证书 DER（CN={id}.masque2.cloudflareclient.com，ECDSA P-256）。
    pub client_cert_der: Vec<u8>,
    /// 对应私钥的 PKCS8 DER。
    pub client_key_der: Vec<u8>,
    /// 边缘公钥 SPKI DER（用于固定校验）；为空表示注册时未拿到。
    pub pinned_spki_der: Vec<u8>,
}

#[derive(Serialize)]
struct RegisterRequest<'a> {
    key: &'a str,
    install_id: &'a str,
    fcm_token: &'a str,
    tos: &'a str,
    model: &'a str,
    serial_number: &'a str,
    os_version: &'a str,
    key_type: &'a str,
    tunnel_type: &'a str,
    locale: &'a str,
    warp_enabled: bool,
}

#[derive(Serialize)]
struct EnrollRequest<'a> {
    key: &'a str,
    key_type: &'a str,
    tunnel_type: &'a str,
}

#[derive(Deserialize)]
struct Wrapper<T> {
    result: T,
}

#[derive(Deserialize)]
struct RegResult {
    id: String,
    // step2 的 PATCH 响应不含 token（只有 step1 有），用 default 容忍；
    // register() 实际用 step1 拿到的 token。
    #[serde(default)]
    token: String,
    #[serde(default)]
    account: Account,
    #[serde(default)]
    key_type: String,
    #[serde(default)]
    tunnel_type: String,
    #[serde(default)]
    config: Option<EnrollConfig>,
}

#[derive(Deserialize, Default)]
struct Account {
    #[serde(default)]
    id: String,
}

#[derive(Deserialize, Default)]
struct EnrollConfig {
    #[serde(default)]
    peers: Vec<Peer>,
    #[serde(default)]
    interface: Interface,
}

#[derive(Deserialize, Default)]
struct Peer {
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    endpoint: Endpoint,
}

#[derive(Deserialize, Default)]
struct Endpoint {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
    #[serde(default)]
    ports: Vec<i64>,
}

#[derive(Deserialize, Default)]
struct Interface {
    #[serde(default)]
    addresses: Addresses,
}

#[derive(Deserialize, Default)]
struct Addresses {
    #[serde(default)]
    v4: String,
    #[serde(default)]
    v6: String,
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(USER_AGENT)
        .build()
        .context("构造 HTTP 客户端失败")
}

/// 生成一个随机的 WireGuard（Curve25519）公钥，base64 编码。
/// boringtun 内部已做 clamp，等价于 warp-go 的 generateRandomWgPubkey。
fn random_wg_pubkey() -> String {
    let secret = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
    let public = boringtun::x25519::PublicKey::from(&secret);
    STANDARD.encode(public.as_ref())
}

fn random_serial() -> String {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    OsRng.fill_bytes(&mut buf);
    // 用 base64 避免引入 hex 依赖；serial 内容 API 不校验。
    STANDARD.encode(buf)
}

/// ECDSA 私钥 → PKCS8 DER（rcgen/rustls 在 ring 后端下只接 PKCS8）。
fn pkcs8_der(signing_key: &SigningKey) -> Result<Vec<u8>> {
    let doc = signing_key
        .to_pkcs8_der()
        .context("ECDSA 私钥 PKCS8 编码失败")?;
    Ok(doc.as_bytes().to_vec())
}

/// 执行两步注册并返回运行时凭据。
///
/// # Errors
/// API 请求失败、返回非 200、或响应无法解析时返回错误。
pub async fn register() -> Result<RegCredentials> {
    println!("正在向 WARP API 注册（两步流程）...");
    let client = http_client()?;

    // Step 1: POST /reg，用临时 WireGuard 公钥创建设备。
    let tos = current_tos();
    let req_body = RegisterRequest {
        key: &random_wg_pubkey(),
        install_id: "",
        fcm_token: "",
        tos: &tos,
        model: "PC",
        serial_number: &random_serial(),
        os_version: "",
        key_type: "curve25519",
        tunnel_type: "wireguard",
        locale: "en_US",
        warp_enabled: true,
    };
    let url = format!("{API_BASE}/reg");
    println!("第 1 步: POST {url}");
    let resp = client
        .post(&url)
        .header("CF-Client-Version", CLIENT_VERSION)
        .json(&req_body)
        .send()
        .await
        .context("注册 API 请求失败")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("注册 API 返回 {status}: {body}");
    }
    let step1: Wrapper<RegResult> =
        serde_json::from_str(&body).with_context(|| format!("解析注册响应失败: {body}"))?;
    println!("第 1 步完成: id={}", step1.result.id);

    // Step 2: 生成 ECDSA P-256 密钥，PATCH 登记为 masque。
    println!("正在生成 ECDSA P-256 密钥对...");
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let spki_der = verifying_key
        .to_public_key_der()
        .context("序列化公钥失败")?;
    let pub_b64 = STANDARD.encode(spki_der.as_ref());

    let enroll_body = EnrollRequest {
        key: &pub_b64,
        key_type: "secp256r1",
        tunnel_type: "masque",
    };
    let enroll_url = format!("{API_BASE}/reg/{}", step1.result.id);
    println!("第 2 步: PATCH {enroll_url}（登记 MASQUE 密钥）");
    let resp = client
        .patch(&enroll_url)
        .header("CF-Client-Version", CLIENT_VERSION)
        .header("Authorization", format!("Bearer {}", step1.result.token))
        .json(&enroll_body)
        .send()
        .await
        .context("登记 API 请求失败")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("登记 API 返回 {status}: {body}");
    }
    let step2: Wrapper<RegResult> =
        serde_json::from_str(&body).with_context(|| format!("解析登记响应失败: {body}"))?;

    let private_key_b64 = STANDARD.encode(&pkcs8_der(&signing_key)?);

    let mut reg = Registration {
        id: step2.result.id.clone(),
        token: step1.result.token,
        account: step2.result.account.id,
        key_type: step2.result.key_type,
        tunnel_type: step2.result.tunnel_type,
        private_key: private_key_b64,
        endpoint_v4: String::new(),
        endpoint_v6: String::new(),
        endpoint_ports: Vec::new(),
        peer_public_key: String::new(),
        assigned_ipv4: String::new(),
        assigned_ipv6: String::new(),
    };

    // 从 config.peers[0] 提取边缘地址/端口/公钥。
    if let Some(cfg) = step2.result.config.as_ref() {
        if let Some(peer) = cfg.peers.first() {
            reg.endpoint_v4 = strip_host(&peer.endpoint.v4);
            reg.endpoint_v6 = strip_host(&peer.endpoint.v6);
            reg.endpoint_ports = peer.endpoint.ports.iter().map(|p| *p as u16).collect();
            if !peer.public_key.is_empty() {
                // API 返回 PEM SPKI，解析后规范化为 base64 SPKI DER 存储。
                let vk = p256::ecdsa::VerifyingKey::from_public_key_pem(&peer.public_key)
                    .with_context(|| format!("解析边缘公钥失败: {}", peer.public_key))?;
                let der = vk.to_public_key_der().context("边缘公钥重新编码失败")?;
                reg.peer_public_key = STANDARD.encode(der.as_ref());
            }
        }
        reg.assigned_ipv4 = cfg.interface.addresses.v4.clone();
        reg.assigned_ipv6 = cfg.interface.addresses.v6.clone();
    }

    println!(
        "✓ 注册成功: id={}，边缘={}（端口 {:?}），IPv6={}",
        reg.id, reg.endpoint_v4, reg.endpoint_ports, reg.endpoint_v6
    );

    let creds = build_credentials(&reg, &signing_key)?;
    Ok(creds)
}

fn current_tos() -> String {
    // warp-go 用 RFC3339 本地时；这里用 UTC，API 不校验时区。
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "2024-01-01T00:00:00Z".into())
}

/// 去掉 endpoint host 里可能带的 :port 或 []。
fn strip_host(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    s.split(':').next().unwrap_or(s).to_string()
}

/// 从私钥和注册信息重建运行时凭据（自签证书 + 边缘固定公钥）。
fn build_credentials(reg: &Registration, signing_key: &SigningKey) -> Result<RegCredentials> {
    let cert = build_client_cert(&reg.id, signing_key)?;
    let pinned_spki = if reg.peer_public_key.is_empty() {
        Vec::new()
    } else {
        STANDARD
            .decode(&reg.peer_public_key)
            .context("边缘公钥 base64 解码失败")?
    };
    Ok(RegCredentials {
        registration: reg.clone_struct(),
        client_cert_der: cert.der().to_vec(),
        client_key_der: pkcs8_der(signing_key)?,
        pinned_spki_der: pinned_spki,
    })
}

/// 自签客户端证书：CN={id}.masque2.cloudflareclient.com，ECDSA P-256，24h。
fn build_client_cert(reg_id: &str, signing_key: &SigningKey) -> Result<rcgen::Certificate> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyUsagePurpose,
    };
    use time::{Duration, OffsetDateTime};

    // 用注册的 ECDSA 私钥构造 KeyPair（保证证书公钥与登记的公钥一致）。
    // rcgen 0.13 ring 后端只接 PKCS8 DER；TryFrom 会从 DER 自动推断 ECDSA P-256。
    let pkcs8 = pkcs8_der(signing_key)?;
    let kp = rcgen::KeyPair::try_from(pkcs8.as_slice())
        .context("从 ECDSA 私钥构造 rcgen KeyPair 失败")?;

    let now = OffsetDateTime::now_utc();
    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("{reg_id}.masque2.cloudflareclient.com"),
        );
        dn
    };
    params.not_before = now;
    params.not_after = now + Duration::days(1);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.serial_number = Some(rcgen::SerialNumber::from(now.unix_timestamp() as u64));

    params.self_signed(&kp).context("自签客户端证书失败")
}

impl Registration {
    /// 浅克隆（私有字段一起带上）。
    fn clone_struct(&self) -> Self {
        Self {
            id: self.id.clone(),
            token: self.token.clone(),
            account: self.account.clone(),
            key_type: self.key_type.clone(),
            tunnel_type: self.tunnel_type.clone(),
            private_key: self.private_key.clone(),
            endpoint_v4: self.endpoint_v4.clone(),
            endpoint_v6: self.endpoint_v6.clone(),
            endpoint_ports: self.endpoint_ports.clone(),
            peer_public_key: self.peer_public_key.clone(),
            assigned_ipv4: self.assigned_ipv4.clone(),
            assigned_ipv6: self.assigned_ipv6.clone(),
        }
    }

    /// 保存到 JSON 文件。
    ///
    /// # Errors
    /// 写入失败时返回错误。
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self).context("序列化注册信息失败")?;
        std::fs::write(path, data).with_context(|| format!("写入 {} 失败", path.display()))
    }
}

/// 从文件加载注册信息并重建运行时凭据。
///
/// # Errors
/// 文件不存在、解析失败、或密钥重建失败时返回错误。
pub fn load(path: &Path) -> Result<RegCredentials> {
    let data = std::fs::read(path).with_context(|| format!("读取 {} 失败", path.display()))?;
    let reg: Registration = serde_json::from_slice(&data)
        .with_context(|| format!("解析注册文件失败: {}", path.display()))?;
    let pkcs8 = STANDARD
        .decode(&reg.private_key)
        .context("私钥 base64 解码失败")?;
    let signing_key =
        p256::ecdsa::SigningKey::from_pkcs8_der(&pkcs8).context("私钥 PKCS8 解析失败")?;
    build_credentials(&reg, &signing_key)
}

/// 向 API 注销并删除本地文件。
///
/// # Errors
/// API 注销失败或文件删除失败时返回错误。
pub async fn delete(path: &Path) -> Result<()> {
    let data = std::fs::read(path).with_context(|| format!("读取 {} 失败", path.display()))?;
    #[derive(Deserialize)]
    struct Ident {
        id: String,
        token: String,
    }
    let ident: Ident = serde_json::from_slice(&data).context("解析注册文件失败")?;
    if ident.id.is_empty() || ident.token.is_empty() {
        bail!("注册文件缺少 id 或 token，无法向 API 注销");
    }

    let client = http_client()?;
    let url = format!("{API_BASE}/reg/{}", ident.id);
    println!("正在注销: {url}");
    let resp = client
        .delete(&url)
        .header("Authorization", format!("Bearer {}", ident.token))
        .header("CF-Client-Version", CLIENT_VERSION)
        .send()
        .await
        .context("注销 API 请求失败")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() && status.as_u16() != 204 {
        // API 注销失败只警告，仍删除本地文件（避免凭据悬空）。
        println!("警告: API 注销返回 {status}: {body}（继续删除本地文件）");
    } else {
        println!("✓ 已注销: id={}", ident.id);
    }
    std::fs::remove_file(path).with_context(|| format!("删除 {} 失败", path.display()))?;
    Ok(())
}
