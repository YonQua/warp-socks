//! Native Psiphon SSH transport over an existing outbound.
mod server_list;

use super::{Connected, Host, Outbound};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{seq::SliceRandom, RngCore};
use serde_json::json;
use std::{io, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::{JoinHandle, JoinSet},
};

/// Validate the supported country selector and normalize it to uppercase.
///
/// # Errors
/// Returns an error for countries outside the advertised selection.
pub fn normalize_country(country: &str) -> Result<String> {
    let country = country.trim().to_ascii_uppercase();
    if !matches!(
        country.as_str(),
        "AT" | "AU"
            | "BE"
            | "BG"
            | "CA"
            | "CH"
            | "CZ"
            | "DE"
            | "DK"
            | "EE"
            | "ES"
            | "FI"
            | "FR"
            | "GB"
            | "HR"
            | "HU"
            | "IE"
            | "IN"
            | "IT"
            | "JP"
            | "LV"
            | "NL"
            | "NO"
            | "PL"
            | "PT"
            | "RO"
            | "RS"
            | "SE"
            | "SG"
            | "SK"
            | "US"
    ) {
        bail!("unsupported PSIPHON_COUNTRY: {country}");
    }
    Ok(country)
}

pub struct Psiphon {
    client: makiko::Client,
    _tasks: JoinSet<()>,
    country: String,
    _upstream: Arc<dyn Outbound>,
}
impl Psiphon {
    /// Download and shuffle SSH candidates for an already validated country.
    pub(crate) async fn candidates(
        upstream: &dyn Outbound,
        country: &str,
    ) -> Result<Vec<server_list::ServerEntry>> {
        let mut entries = server_list::fetch(upstream, country).await?;
        entries.retain(|e| e.ssh_port != 0 && e.capabilities.iter().any(|c| c == "SSH"));
        entries.shuffle(&mut rand::thread_rng());
        log::info!(
            "Psiphon signed list: country={country}, SSH candidates={}",
            entries.len()
        );
        Ok(entries)
    }
    pub(crate) async fn connect_entry(
        upstream: Arc<dyn Outbound>,
        entry: server_list::ServerEntry,
        country: &str,
    ) -> Result<Self> {
        let ip = entry.ip_address.parse::<IpAddr>()?;
        let socket = upstream
            .connect_tcp(Host::Ip(ip), entry.ssh_port)
            .await?
            .stream;
        let expected = STANDARD.decode(&entry.ssh_host_key)?;
        let (client, mut events, future) =
            makiko::Client::open(socket, makiko::ClientConfig::default())?;
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            if let Err(e) = future.await {
                log::debug!("Psiphon SSH closed: {e}");
            }
        });
        tasks.spawn(async move {
            while let Ok(Some(event)) = events.recv().await {
                if let makiko::ClientEvent::ServerPubkey(key, accept) = event {
                    if key.encode().as_ref() == expected.as_slice() {
                        accept.accept();
                    } else {
                        accept.reject(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Psiphon host key mismatch",
                        ));
                    }
                }
            }
        });
        let tunnel = Self {
            client,
            _tasks: tasks,
            country: country.into(),
            _upstream: upstream,
        };
        let mut session = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut session);
        let password = json!({
            "SessionId": hex::encode(session),
            "SshPassword": entry.ssh_password,
            "ClientCapabilities": [],
            "SponsorId": "FFFFFFFFFFFFFFFF"
        })
        .to_string();
        if !matches!(
            tunnel
                .client
                .auth_password(entry.ssh_username, password)
                .await?,
            makiko::AuthPasswordResult::Success
        ) {
            bail!("Psiphon authentication rejected");
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = json!({
            "propagation_channel_id": "FFFFFFFFFFFFFFFF",
            "sponsor_id": "FFFFFFFFFFFFFFFF",
            "client_version": "0",
            "client_platform": "Android_4.0.4_com.example.exampleClientLibraryApp",
            "relay_protocol": "SSH"
        });
        tunnel.client.send_request(makiko::GlobalReq {
            request_type: "psiphon-handshake".into(),
            payload: serde_json::to_vec(&payload)?.into(),
            reply_tx: Some(tx),
        })?;
        match rx.await.context("Psiphon handshake response lost")? {
            makiko::GlobalReply::Success(body) => {
                let _: serde_json::Value =
                    serde_json::from_slice(&body).context("invalid Psiphon handshake JSON")?;
            }
            makiko::GlobalReply::Failure => bail!("Psiphon handshake rejected"),
        }
        log::info!("Psiphon ready: country={country}, protocol=SSH");
        Ok(tunnel)
    }
}
#[async_trait]
impl Outbound for Psiphon {
    fn name(&self) -> &'static str {
        "Psiphon"
    }
    async fn connect_tcp(&self, host: Host, port: u16) -> io::Result<Connected> {
        let host = match host {
            Host::Domain(s) => s,
            Host::Ip(ip) => ip.to_string(),
        };
        let mut payload = makiko::PacketEncode::new();
        payload.put_str(&host);
        payload.put_u32(port.into());
        payload.put_str("127.0.0.1");
        payload.put_u32(0);
        // A cancelled channel-open has no per-request cancellation in makiko.
        // Close the session rather than leave a late channel confirmation unowned.
        let mut pending = PendingOpen(Some(self.client.clone()));
        let opened = tokio::time::timeout(
            Duration::from_secs(30),
            self.client.open_channel(
                "direct-tcpip".into(),
                makiko::ChannelConfig::default(),
                payload.finish(),
            ),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Psiphon connect timed out"))?;
        pending.0 = None;
        let (channel, mut receiver, _) = opened.map_err(io::Error::other)?;
        let (local, bridge) = tokio::io::duplex(65536);
        let (mut read, mut write) = tokio::io::split(bridge);
        let outgoing = channel.clone();
        let task = tokio::spawn(async move {
            let send = async {
                let mut buf = [0u8; 16384];
                loop {
                    let n = read.read(&mut buf).await?;
                    if n == 0 {
                        outgoing.send_eof().await.map_err(io::Error::other)?;
                        return Ok::<_, io::Error>(());
                    }
                    outgoing
                        .send_data(buf[..n].to_vec().into(), makiko::DATA_STANDARD)
                        .await
                        .map_err(io::Error::other)?;
                }
            };
            let receive = async {
                while let Some(event) = receiver.recv().await {
                    match event {
                        makiko::ChannelEvent::Data(data, _) => {
                            // This stream can carry the entire H2 tunnel. Preserve
                            // transport backpressure instead of timing out slow readers.
                            write.write_all(&data).await?;
                        }
                        makiko::ChannelEvent::Eof => {
                            write.shutdown().await?;
                        }
                        _ => {}
                    }
                }
                write.shutdown().await?;
                Ok::<_, io::Error>(())
            };
            let _ = tokio::try_join!(send, receive);
            let _ = outgoing.close();
        });
        Ok(Connected {
            stream: Box::new(PsiphonStream {
                io: local,
                channel,
                task,
            }),
            note: Some(format!("country={}", self.country)),
        })
    }
}
struct PendingOpen(Option<makiko::Client>);
impl Drop for PendingOpen {
    fn drop(&mut self) {
        if let Some(client) = self.0.take() {
            let _ = client.disconnect(makiko::DisconnectError::by_app());
        }
    }
}
struct PsiphonStream {
    io: tokio::io::DuplexStream,
    channel: makiko::Channel,
    task: JoinHandle<()>,
}
impl Drop for PsiphonStream {
    fn drop(&mut self) {
        let _ = self.channel.close();
        self.task.abort();
    }
}
impl tokio::io::AsyncRead for PsiphonStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for PsiphonStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
