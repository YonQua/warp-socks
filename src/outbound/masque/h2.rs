//! Cloudflare CONNECT-IP over HTTP/2. The carrier TCP connection goes through
//! Psiphon; only the Cloudflare edge carries the application IP packets.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures::channel::mpsc;
use futures::{Sink, Stream};
use http::{Method, Request};
use smoltcp::phy::{DeviceCapabilities, Medium};
use tokio::sync::mpsc as tokio_mpsc;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use super::{edge_addrs, tls, varint, SNI};
use crate::netstack::AsyncDevice;
use crate::outbound::{Host, Outbound};
use crate::registration::RegCredentials;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const PACKET_MTU: usize = 1280;
const MAX_CAPSULE_BUFFER: usize = 256 * 1024;

pub(super) struct H2Device {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: tokio_mpsc::Receiver<Vec<u8>>,
    capabilities: DeviceCapabilities,
    tasks: JoinSet<Result<()>>,
    _upstream: Arc<dyn Outbound>,
}

impl H2Device {
    // 任一载体任务结束即终止设备；发送背压期间也必须轮询任务结果。
    fn poll_termination(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Error> {
        match self.tasks.poll_join_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(Err(error)))) => Poll::Ready(io::Error::other(error)),
            Poll::Ready(Some(Err(error))) => Poll::Ready(io::Error::other(error)),
            Poll::Ready(_) => Poll::Ready(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MASQUE H2 载体任务已结束",
            )),
        }
    }
}

impl Stream for H2Device {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(error) = self.poll_termination(cx) {
            return Poll::Ready(Some(Err(error)));
        }
        self.incoming.poll_recv(cx).map(|packet| packet.map(Ok))
    }
}

impl Sink<Vec<u8>> for H2Device {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(error) = self.poll_termination(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.outgoing)
            .poll_ready(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE H2 发送任务已停止"))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> io::Result<()> {
        if item.len() > PACKET_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IP packet 超过 MASQUE MTU",
            ));
        }
        Pin::new(&mut self.outgoing)
            .start_send(item)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE H2 发送任务已停止"))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(error) = self.poll_termination(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.outgoing)
            .poll_flush(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE H2 发送任务已停止"))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        if let Poll::Ready(error) = self.poll_termination(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.outgoing)
            .poll_close(cx)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE H2 发送任务已停止"))
    }
}

impl AsyncDevice for H2Device {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }
}

pub(super) async fn connect(
    creds: &RegCredentials,
    upstream: Arc<dyn Outbound>,
) -> Result<H2Device> {
    let tls_config = tls::h2_client_config(creds)?;
    let mut errors = Vec::new();
    let addrs = edge_addrs(&creds.registration);
    for addr in addrs.into_iter().filter(|addr| addr.port() == 443) {
        // Psiphon's SSH channel cannot be cancelled independently during open;
        // attempts must be sequential rather than raced and dropped.
        let connected = match upstream.connect_tcp(Host::Ip(addr.ip()), addr.port()).await {
            Ok(connected) => connected,
            // A channel-open timeout closes the shared Psiphon session.
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                return Err(error).context("Psiphon 建连超时，会话已关闭");
            }
            Err(error) => {
                errors.push(format!("{addr}: {error}"));
                continue;
            }
        };
        match dial_one(addr, tls_config.clone(), connected.stream, upstream.clone()).await {
            Ok(device) => return Ok(device),
            Err(error) => errors.push(format!("{addr}: {error:#}")),
        }
    }
    if errors.is_empty() {
        bail!("MASQUE 注册信息没有 443/TCP 边缘地址");
    }
    bail!("MASQUE H2 所有边缘连接失败: {}", errors.join("; "))
}

async fn dial_one(
    addr: SocketAddr,
    tls_config: Arc<rustls::ClientConfig>,
    stream: Box<dyn crate::outbound::Stream>,
    upstream: Arc<dyn Outbound>,
) -> Result<H2Device> {
    let server_name = rustls::pki_types::ServerName::try_from(SNI)?.to_owned();
    let tls = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(tls_config).connect(server_name, stream),
    )
    .await
    .context("MASQUE H2 TLS 握手超时")??;
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(8 * 1024 * 1024)
        .max_frame_size(64 * 1024);
    let (mut sender, connection) = tokio::time::timeout(HANDSHAKE_TIMEOUT, builder.handshake(tls))
        .await
        .context("MASQUE H2 协商超时")??;
    let mut tasks = JoinSet::new();
    tasks.spawn(async move { connection.await.context("MASQUE H2 连接已结束") });
    sender = tokio::time::timeout(HANDSHAKE_TIMEOUT, sender.ready())
        .await
        .context("MASQUE H2 就绪超时")?
        .context("MASQUE H2 未就绪")?;
    let req = Request::builder()
        .method(Method::CONNECT)
        .uri("https://cloudflareaccess.com:443")
        .header("cf-connect-proto", "cf-connect-ip")
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())?;
    let (response, send_stream) = sender.send_request(req, false)?;
    let response = tokio::time::timeout(HANDSHAKE_TIMEOUT, response)
        .await
        .context("MASQUE CONNECT-IP 响应超时")??;
    if response.status() != 200 {
        bail!("MASQUE CONNECT-IP 被边缘拒绝: {}", response.status());
    }
    let colo = response
        .headers()
        .get("cf-warp-colo")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    log::info!("MASQUE H2 CONNECT-IP 已建立: edge={addr}, colo={colo}");
    let recv_stream = response.into_body();

    let (outgoing, outgoing_rx) = mpsc::channel(64);
    let (incoming_tx, incoming) = tokio_mpsc::channel(64);
    tasks.spawn(send_packets(send_stream, outgoing_rx));
    tasks.spawn(receive_packets(recv_stream, incoming_tx));
    let mut capabilities = DeviceCapabilities::default();
    capabilities.medium = Medium::Ip;
    capabilities.max_transmission_unit = PACKET_MTU;
    Ok(H2Device {
        outgoing,
        incoming,
        capabilities,
        tasks,
        _upstream: upstream,
    })
}

async fn send_packets(
    mut stream: h2::SendStream<Bytes>,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    use futures::StreamExt;
    while let Some(packet) = packets.next().await {
        if packet.len() > PACKET_MTU {
            bail!("IP packet 超过 MASQUE MTU");
        }
        let mut capsule = Vec::with_capacity(packet.len() + 4);
        capsule.push(0); // DATAGRAM capsule type
        varint::write(&mut capsule, packet.len() as u64);
        capsule.extend_from_slice(&packet);
        let mut remaining = Bytes::from(capsule);
        while !remaining.is_empty() {
            stream.reserve_capacity(remaining.len());
            let available = futures::future::poll_fn(|cx| stream.poll_capacity(cx))
                .await
                .ok_or_else(|| anyhow!("MASQUE H2 发送流已关闭"))??;
            if available == 0 {
                continue;
            }
            let chunk = remaining.split_to(available.min(remaining.len()));
            stream.send_data(chunk, false)?;
        }
    }
    stream.send_data(Bytes::new(), true)?;
    Ok(())
}

async fn receive_packets(
    mut stream: h2::RecvStream,
    sender: tokio_mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let mut buf = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.context("读取 MASQUE H2 数据失败")?;
        stream.flow_control().release_capacity(chunk.len())?;
        if buf.len() + chunk.len() > MAX_CAPSULE_BUFFER {
            bail!("MASQUE capsule 缓冲区超过上限");
        }
        buf.extend_from_slice(&chunk);
        let mut consumed = 0;
        while let Some((kind, kind_len)) = varint::read(&buf[consumed..]) {
            let Some((length, length_len)) = varint::read(&buf[consumed + kind_len..]) else {
                break;
            };
            let length = usize::try_from(length).context("MASQUE capsule 长度超出平台限制")?;
            if length > MAX_CAPSULE_BUFFER {
                bail!("MASQUE capsule 长度超过上限: {length}");
            }
            let header = kind_len + length_len;
            if buf.len() - consumed < header + length {
                break;
            }
            if kind == 0 {
                let packet = &buf[consumed + header..consumed + header + length];
                let packet = if packet.first() == Some(&0) && packet.len() > 1 {
                    &packet[1..] // CONNECT-IP context ID 0, if present.
                } else {
                    packet
                };
                if packet.first().is_some_and(|b| matches!(b >> 4, 4 | 6)) {
                    // IP 设备允许队列满时丢包；持续读取并释放 H2 窗口，避免
                    // reactor 等待发送时，入站队列反过来阻塞整条 H2 连接。
                    match sender.try_send(packet.to_vec()) {
                        Ok(()) | Err(tokio_mpsc::error::TrySendError::Full(_)) => {}
                        Err(tokio_mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                    }
                }
            }
            consumed += header + length;
        }
        buf.drain(..consumed);
    }
    bail!("MASQUE H2 数据流已关闭")
}
