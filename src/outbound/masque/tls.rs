// MASQUE 的 TLS 配置：SNI 是约定名、证书由私有 CA 签发，标准链校验不适用；
// 鉴权靠比对注册时拿到的边缘 ECDSA 公钥（SPKI DER 字节相等）。
//
// ring 后端限制：不支持 P-521，只用 P-256/P-384 即可避免 X25519 触发 HelloRetryRequest。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::registration::RegCredentials;

/// 固定的边缘公钥（SPKI DER）。
#[derive(Debug)]
pub(super) struct PinnedEdge(pub(super) Vec<u8>);

impl rustls::client::danger::ServerCertVerifier for PinnedEdge {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("解析边缘证书失败: {e}")))?;
        match cert.public_key().raw {
            spki if spki == self.0.as_slice() => {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            _ => Err(rustls::Error::General("边缘公钥与注册登记的不匹配".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // MASQUE 只用 TLS 1.3；拒绝 1.2，不留兜底。
        Err(rustls::Error::General("MASQUE 只用 TLS 1.3".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

/// 构造 quinn 客户端配置：ring 后端、P-256/P-384、固定边缘公钥、自签客户端证书、ALPN h3。
///
/// # Errors
/// TLS 配置构建失败（无可用密码套件、证书/私钥不匹配等）时返回错误。
pub(super) fn client_config(creds: &RegCredentials) -> Result<quinn::ClientConfig> {
    // 曲线偏好：ring 无 P-521，只用 P-256/P-384，避免 X25519 导致 HelloRetryRequest。
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::ring::kx_group::SECP256R1,
        rustls::crypto::ring::kx_group::SECP384R1,
    ];

    let cert = vec![rustls::pki_types::CertificateDer::from(
        creds.client_cert_der.clone(),
    )];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        creds.client_key_der.clone(),
    ));

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedEdge(creds.pinned_spki_der.clone())))
        .with_client_auth_cert(cert, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    // QUIC 参数对齐 warp-svc 的 tokio-quiche 默认值（见 warp-go/tunnel/masque.go:180-201）。
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    transport.receive_window(10_000_000u32.into());
    transport.stream_receive_window(1_000_000u32.into());
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.initial_mtu(1350);

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .context("rustls→quinn crypto 适配失败")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    cfg.transport_config(Arc::new(transport));
    Ok(cfg)
}
