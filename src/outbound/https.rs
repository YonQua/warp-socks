//! Small HTTPS GET over an Outbound TCP stream. No other network path is used.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio_rustls::TlsConnector;

use super::{Host, Outbound};

/// Fetch a bounded HTTPS resource through `outbound` using public CA roots.
pub(crate) async fn get(
    outbound: &dyn Outbound,
    host: &str,
    path: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, get_inner(outbound, host, path, max_bytes))
        .await
        .context("HTTPS GET timed out")?
}

async fn get_inner(
    outbound: &dyn Outbound,
    host: &str,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let stream = outbound
        .connect_tcp(Host::Domain(host.to_owned()), 443)
        .await
        .with_context(|| format!("connecting to {host}:443"))?
        .stream;

    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("building HTTPS TLS protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .context("invalid HTTPS server name")?;
    let stream = TlsConnector::from(Arc::new(tls))
        .connect(server_name, stream)
        .await
        .with_context(|| format!("TLS handshake with {host}"))?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("HTTPS HTTP/1 handshake failed")?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header(http::header::HOST, host)
        .body(Empty::<Bytes>::new())
        .context("invalid HTTPS GET request")?;
    let response = async {
        let mut response = sender
            .send_request(request)
            .await
            .context("HTTPS GET failed")?;
        if !response.status().is_success() {
            bail!("HTTPS GET returned {}", response.status());
        }
        if response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|length| length.to_str().ok())
            .and_then(|length| length.parse::<usize>().ok())
            .is_some_and(|length| length > max_bytes)
        {
            bail!("HTTPS response exceeds size limit");
        }
        let mut body = Vec::new();
        while let Some(frame) = response.body_mut().frame().await {
            let frame = frame.context("reading HTTPS response")?;
            if let Ok(data) = frame.into_data() {
                if data.len() > max_bytes.saturating_sub(body.len()) {
                    bail!("HTTPS response exceeds size limit");
                }
                body.extend_from_slice(&data);
            }
        }
        Ok::<_, anyhow::Error>(body)
    };
    tokio::pin!(response);
    tokio::pin!(connection);
    tokio::select! {
        biased;
        result = &mut response => result,
        result = &mut connection => {
            result.context("HTTPS connection failed")?;
            response.await
        }
    }
}
