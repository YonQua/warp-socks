// MASQUE 隧道：到 WARP 边缘的 QUIC 连接，每次 connect 产出一条 H3 CONNECT 双向流。
//
// 核心流程（对照 warp-go/tunnel/masque.go）：
//   1. 并发拨号所有候选边缘（20 字节 SCID 对齐 warp-svc），最先握手成功的中标
//   2. 建立常驻 H3 控制流（stream type 0x00 + 空 SETTINGS frame）
//   3. 域名目标先经隧道内 DoH 解析成 IP（见 doh.rs）
//   4. 每个连接请求：open_bi → 发 HEADERS(CONNECT, :authority=ip:port) → 读 :status
//   5. 200 后该双向流仍走 H3 DATA frame 分帧（RFC 9114 §4.4，同 HTTP/2 CONNECT
//      语义；warp-go 靠 quic-go 的 http3.RequestStream 自动分帧，见 wrap_data_framing）
//
// :authority 若原样传域名，边缘会以 403 拒绝 CONNECT（已用 warp-go 源码和官方
// 二进制逆向文档交叉验证：两者都在 CONNECT 前把域名解析成 IP，从未送裸域名）。
// 这里选择跟 warp-go 一致的隧道内 DoH，而非宿主本地解析器，避免域名在到达
// 隧道前就泄露到隧道外。
//
// 不附加 host 字段：曾尝试 :authority=IP 之外再带一条 host=域名 字面量，
// 保留域名给边缘做策略/日志，但边缘以 H3_MESSAGE_ERROR（错误码 270）reset
// 了流——RFC 9114 §4.3.1 / RFC 9113 §8.3.1 要求 :authority 与 Host 同时出现
// 时值必须一致，IP 与域名不一致触发了这条硬校验，并非编码 bug。

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use log::{debug, info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::dns::RecordType;
use crate::outbound::{Connected, Host, Outbound, Stream};
use crate::registration::RegCredentials;

mod doh;
pub(super) mod h2;
mod h2_outbound;
mod huffman;
mod qpack;
mod tls;

pub use h2_outbound::MasqueH2;

const SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
// 流额度不足只限制当前请求，不证明共享 QUIC 连接失效。
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
// 一次业务拨号包含 DNS、必要的重连和 CONNECT，所有阶段共用该预算。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(53);
const RELAY_BUF: usize = 64 * 1024;
const MAX_HEADERS_FRAME_SIZE: usize = 64 * 1024;

/// 一条到边缘的 MASQUE 连接。控制流随 Link 一起存活/释放，避免 forget 的内存语义模糊。
struct Link {
    conn: quinn::Connection,
    // H3 控制流必须常驻到连接结束（主动关闭会触发 H3_CLOSED_CRITICAL_STREAM）。
    _control: quinn::SendStream,
}

/// MASQUE 出网后端。
pub struct Masque {
    endpoint: quinn::Endpoint,
    creds: RegCredentials,
    addrs: Vec<SocketAddr>,
    link: Mutex<Link>,
    // 重连串行化，但不阻塞其他请求读取当前连接。
    reconnecting: Mutex<()>,
    dns: doh::DnsCache,
}

impl Masque {
    /// 用注册凭据建立 MASQUE 连接。
    ///
    /// # Errors
    /// TLS 配置、UDP 绑定、QUIC 拨号或 H3 控制流建立失败时返回错误。
    pub async fn new(creds: RegCredentials) -> Result<Self> {
        let cfg = tls::client_config(&creds)?;
        let endpoint = build_endpoint()?;
        let addrs = edge_addrs(&creds.registration);
        let link = connect(&endpoint, &cfg, &addrs).await?;
        let dns = doh::DnsCache::new().context("构造 DoH TLS 配置失败")?;
        Ok(Self {
            endpoint,
            creds,
            addrs,
            link: Mutex::new(link),
            reconnecting: Mutex::new(()),
            dns,
        })
    }

    /// 只在连接失效时重建；额度等待超时保留已有流。
    async fn open(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let conn = self.link.lock().await.conn.clone();
        if conn.close_reason().is_none() {
            match open_bi_bounded(&conn).await {
                Ok(pair) => return Ok(pair),
                Err(error) if conn.close_reason().is_none() => return Err(error),
                Err(_) => {}
            }
        }

        let _reconnecting = self.reconnecting.lock().await;
        // stable_id 判断避免多个调用者同时发现失效时重复重建：等到手上这把
        // 拨号锁时，link 可能已经被排在前面的调用者换成新连接了。
        let stale_id = self.link.lock().await.conn.stable_id();
        if stale_id == conn.stable_id() {
            warn!("QUIC 连接已失效，重连 ...");
            let creds = crate::registration::masque::refresh_credentials(&self.creds)?;
            let cfg = tls::client_config(&creds)?;
            let fresh = connect(&self.endpoint, &cfg, &self.addrs).await?;
            *self.link.lock().await = fresh;
        }
        drop(_reconnecting);
        let conn = self.link.lock().await.conn.clone();
        open_bi_bounded(&conn)
            .await
            .context("重连后 open_bi 仍超时或失败")
    }

    /// 域名解析：命中缓存直接返回，否则依次尝试 DoH 候选 IP 查 A/AAAA。
    async fn resolve_domain(&self, domain: &str) -> Result<IpAddr> {
        if let Some(ip) = self.dns.cached(domain).await {
            return Ok(ip);
        }
        let mut last_err = None;
        for record_type in [RecordType::A, RecordType::Aaaa] {
            match self.doh_query(domain, record_type).await {
                Ok(ip) => return Ok(ip),
                Err(e) => {
                    // A-only 或 AAAA-only 域名在第一种记录类型上没有答案是正常
                    // 回退路径；只有两种类型都失败时才由最终连接错误对外报告。
                    debug!("DoH 查询 {domain}（{record_type:?}）未命中: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("DoH 未解析出 {domain} 的 A/AAAA 记录")))
    }

    /// 依次尝试 DoH 候选出口 IP，逐个走隧道 CONNECT + 标准 TLS + HTTP/1.1 查询。
    async fn doh_query(&self, domain: &str, record_type: RecordType) -> Result<IpAddr> {
        let mut last_err = None;
        for doh_addr in doh::DOH_ADDRS {
            match self.doh_query_via(doh_addr, domain, record_type).await {
                Ok(ip) => return Ok(ip),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("无 DoH 候选地址")))
    }

    async fn doh_query_via(
        &self,
        doh_addr: &str,
        domain: &str,
        record_type: RecordType,
    ) -> Result<IpAddr> {
        let (stream, _colo) = self
            .connect_stream(doh_addr)
            .await
            .context("建立 DoH 隧道失败")?;
        self.dns.resolve_over(stream, domain, record_type).await
    }

    /// 打开一条隧道流并完成 H3 CONNECT 握手，返回可直接读写业务字节的流。
    /// `doh_query_via` 和 `connect_tcp` 都要"开流 → CONNECT → 失败就释放两侧"
    /// 这一套，统一到这一处，避免两份各自维护、超时/清理覆盖不一致。
    async fn connect_stream(&self, authority: &str) -> Result<(Box<dyn Stream>, Option<String>)> {
        let (mut send, mut recv) = self.open().await?;
        let exchanged = tokio::time::timeout(
            EXCHANGE_TIMEOUT,
            exchange(
                &mut send,
                &mut recv,
                authority,
                &self.creds.registration.token,
            ),
        )
        .await
        .context("MASQUE CONNECT 交换超时");
        match exchanged.and_then(|result| result) {
            Ok(colo) => Ok((wrap_data_framing(send, recv), colo)),
            Err(error) => {
                let _ = (recv.stop(0u32.into()), send.reset(0u32.into()));
                Err(error)
            }
        }
    }
}

/// 单次 `open_bi` 尝试，超时后视为失败（详见 `OPEN_TIMEOUT` 注释）。
async fn open_bi_bounded(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    match tokio::time::timeout(OPEN_TIMEOUT, conn.open_bi()).await {
        Ok(Ok(pair)) => Ok(pair),
        Ok(Err(e)) => Err(anyhow!("open_bi 失败: {e}")),
        Err(_) => Err(anyhow!(
            "open_bi 超时（{OPEN_TIMEOUT:?}，多半是边缘并发流配额耗尽）"
        )),
    }
}

#[async_trait]
impl Outbound for Masque {
    fn name(&self) -> &'static str {
        "MASQUE"
    }

    async fn connect_tcp(&self, host: Host, port: u16) -> io::Result<Connected> {
        tokio::time::timeout(CONNECT_TIMEOUT, async {
            let ip = match host {
                Host::Domain(d) => self
                    .resolve_domain(&d)
                    .await
                    .map_err(|e| io_err(format!("DoH 解析 {d} 失败: {e:#}")))?,
                Host::Ip(ip) => ip,
            };
            // authority 用 SocketAddr 的 Display 而非裸 `{ip}:{port}` 拼接：IPv6 字面量
            // 按 RFC 3986 §3.2.2 必须括在方括号里，否则地址内的冒号与端口分隔符冲突，
            // 边缘会当作非法 authority 以 H3_MESSAGE_ERROR reset 流。
            let authority = SocketAddr::new(ip, port).to_string();

            // colo 不在这里打日志：连上后交给调用方跟"已建立"合并成一行，避免
            // 同一次连接的信息分散在两个模块、并发时靠时间戳猜配对。
            let (stream, colo) = self
                .connect_stream(&authority)
                .await
                .map_err(|e| io_err(format!("MASQUE CONNECT {authority} 失败: {e:#}")))?;
            Ok(Connected {
                stream,
                note: colo.map(|c| format!("colo={c}")),
            })
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MASQUE DNS/CONNECT 总预算耗尽"))?
    }
}

/// 发 HEADERS(CONNECT) 并读 :status，200 才算隧道建立；返回边缘落地的 colo
/// （如 "LAX"，取自 `cf-warp-colo` 响应头，纯展示用，取不到就是 `None`）。
async fn exchange(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    authority: &str,
    token: &str,
) -> Result<Option<String>> {
    let headers = qpack::headers_frame(&qpack::encode_connect_request(authority, token));
    send.write_all(&headers)
        .await
        .context("发送 CONNECT 头失败")?;

    // 保留/GREASE 帧类型（RFC 9114 §7.2.8，形如 31*N+33）没有语义，接收方必须
    // 跳过（读 Length 后丢弃对应字节）而非报错，跳过后继续找真正的 HEADERS。
    const MAX_SKIPPED_FRAMES: u32 = 8;
    let payload = 'frames: {
        for _ in 0..MAX_SKIPPED_FRAMES {
            let frame_type = read_varint(recv).await?;
            let len = read_varint(recv).await?;
            if frame_type == 0x01 {
                let len = checked_headers_len(len)?;
                let mut payload = vec![0u8; len];
                recv.read_exact(&mut payload)
                    .await
                    .context("读取 CONNECT 响应失败")?;
                break 'frames payload;
            }
            discard_frame(recv, len).await?;
        }
        bail!("连续 {MAX_SKIPPED_FRAMES} 个非 HEADERS 帧后仍未收到响应");
    };
    let headers = qpack::decode_headers(&payload).map_err(anyhow::Error::msg)?;
    if headers.status != 200 {
        bail!("边缘拒绝 CONNECT，状态 {}", headers.status);
    }
    Ok(headers.colo)
}

fn checked_headers_len(len: u64) -> Result<usize> {
    let len = usize::try_from(len).context("HEADERS frame 长度超出平台上限")?;
    if len > MAX_HEADERS_FRAME_SIZE {
        bail!("CONNECT 响应 HEADERS frame 过大: {len}");
    }
    Ok(len)
}

/// CONNECT 成功后，把仍带 H3 DATA frame 分帧的裸双向流包成上层不用关心分帧
/// 的字节流：起一个泵任务做编解码，中间用一对 duplex 转发；调用方拿到的
/// `remote` 端只看到裸隧道字节。收方向遇到非 DATA 帧（如 GREASE）直接丢弃。
fn wrap_data_framing(send: quinn::SendStream, recv: quinn::RecvStream) -> Box<dyn Stream> {
    let (local, remote) = tokio::io::duplex(RELAY_BUF);
    let task = tokio::spawn(pump(send, recv, local));
    Box::new(FramedStream {
        io: remote,
        task: Some(task),
    })
}

/// H3 framing pump 的生命周期与返回给 relay 的流绑定；流被丢弃时直接取消
/// pump，因此半关闭宽限只由 relay 维护一份。
struct FramedStream {
    io: tokio::io::DuplexStream,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl AsyncRead for FramedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let empty = buf.remaining() == 0;
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if !empty && buf.filled().len() == before => {
                // duplex EOF 只表示 pump 关闭了写端；任务结果才决定是否正常结束。
                let Some(task) = this.task.as_mut() else {
                    return Poll::Ready(Ok(()));
                };
                match Pin::new(task).poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(result) => {
                        this.task = None;
                        Poll::Ready(result.map_err(io::Error::other).and_then(|result| result))
                    }
                }
            }
            result => result,
        }
    }
}

impl AsyncWrite for FramedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl Drop for FramedStream {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn pump(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    local: tokio::io::DuplexStream,
) -> io::Result<()> {
    let (mut local_read, mut local_write) = tokio::io::split(local);

    let download = drain_download(&mut recv, &mut local_write);
    tokio::pin!(download);
    let upload = async {
        if let Err(error) = drain_upload(&mut local_read, &mut send).await {
            let _ = send.reset(0u32.into());
            return Err(error);
        }
        send.finish().map_err(io::Error::other)
    };
    tokio::pin!(upload);

    tokio::select! {
        result = &mut download => return result,
        result = &mut upload => result?,
    }
    download.await
}

/// 边缘 → 本地：仅帧边界 EOF 正常，帧头或负载中断必须向调用方报错。
async fn drain_download(
    recv: &mut quinn::RecvStream,
    out: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    while let Some(frame_type) = read_varint_or_eof(recv).await? {
        let mut remaining = read_varint(recv).await?;
        while remaining > 0 {
            let chunk = remaining.min(RELAY_BUF as u64) as usize;
            // DATA 是字节流：已到达的负载立即交付，只在帧内 EOF 时报截断。
            let size = AsyncReadExt::read(recv, &mut buf[..chunk]).await?;
            if size == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "H3 帧负载意外结束",
                ));
            }
            if frame_type == 0x00 {
                out.write_all(&buf[..size]).await?;
            }
            remaining -= size as u64;
        }
    }
    Ok(())
}

async fn discard_frame(recv: &mut quinn::RecvStream, mut remaining: u64) -> Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    while remaining > 0 {
        let chunk = usize::try_from(remaining.min(RELAY_BUF as u64)).unwrap_or(RELAY_BUF);
        recv.read_exact(&mut buf[..chunk])
            .await
            .context("跳过未知帧失败")?;
        remaining -= chunk as u64;
    }
    Ok(())
}

/// 本地 → 边缘：读本地字节，包成 H3 DATA frame 发出。
async fn drain_upload(
    input: &mut (impl AsyncRead + Unpin),
    send: &mut quinn::SendStream,
) -> io::Result<()> {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = input.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        send.write_all(&qpack::data_frame(&buf[..n]))
            .await
            .map_err(io::Error::other)?;
    }
}

/// 绑定本地 UDP socket，源连接 ID 用 20 字节（对齐 warp-svc，避免 4 字节 SCID 触发边缘 PROTOCOL_VIOLATION）。
fn build_endpoint() -> Result<quinn::Endpoint> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").context("绑定 UDP socket 失败")?;
    socket.set_nonblocking(true).ok();
    let mut epc = quinn::EndpointConfig::default();
    epc.cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(20)));
    let runtime = quinn::default_runtime().context("需在 tokio 上下文调用")?;
    Ok(quinn::Endpoint::new(epc, None, socket, runtime)?)
}

/// 并发拨号所有候选边缘，最先握手成功的中标，其余候选直接丢弃（未完成的
/// QUIC 握手 drop 时自然放弃，无需显式取消）。
///
/// 之所以并发而非逐个尝试：重连由 `reconnecting` 串行化，逐个尝试在候选数
/// 多时最坏耗时是“候选数 × DIAL_TIMEOUT”，会让所有等待同一次重连的调用者
/// 长时间停顿；并发拨号把最坏耗时压到接近单次 DIAL_TIMEOUT。
async fn connect(
    endpoint: &quinn::Endpoint,
    cfg: &quinn::ClientConfig,
    addrs: &[SocketAddr],
) -> Result<Link> {
    if addrs.is_empty() {
        bail!("无候选边缘地址");
    }
    let dials = addrs
        .iter()
        .map(|&addr| Box::pin(dial_one(endpoint, cfg, addr)));
    let (conn, _rest) = futures::future::select_ok(dials).await?;
    let control = tokio::time::timeout(CONTROL_STREAM_TIMEOUT, async {
        let mut control = conn.open_uni().await.context("打开 H3 控制流失败")?;
        control
            .write_all(&qpack::control_stream_prelude())
            .await
            .context("发送控制流 SETTINGS 失败")?;
        Ok::<_, anyhow::Error>(control)
    })
    .await
    .context("建立 H3 控制流超时")??;
    Ok(Link {
        conn,
        _control: control,
    })
}

/// 拨号单个候选边缘地址，独立超时。
async fn dial_one(
    endpoint: &quinn::Endpoint,
    cfg: &quinn::ClientConfig,
    addr: SocketAddr,
) -> Result<quinn::Connection> {
    info!("QUIC 拨号 {addr}（SNI={SNI}）...");
    let connecting = endpoint
        .connect_with(cfg.clone(), addr, SNI)
        .with_context(|| format!("发起 {addr} 拨号失败"))?;
    match tokio::time::timeout(DIAL_TIMEOUT, connecting).await {
        Ok(Ok(conn)) => {
            info!("✓ QUIC 已连接到 {addr}");
            Ok(conn)
        }
        Ok(Err(e)) => {
            warn!("边缘 {addr} 不可达（{e}）");
            Err(anyhow!("边缘 {addr} 不可达（{e}）"))
        }
        Err(_) => {
            warn!("边缘 {addr} 拨号超时（{DIAL_TIMEOUT:?}）");
            Err(anyhow!("边缘 {addr} 拨号超时（{DIAL_TIMEOUT:?}）"))
        }
    }
}

/// 注册端口展开成候选地址，443 移末尾。
fn edge_addrs(reg: &crate::registration::Registration) -> Vec<SocketAddr> {
    let ports = if reg.endpoint_ports.is_empty() {
        vec![443u16]
    } else {
        reg.endpoint_ports.clone()
    };
    let mut ordered: Vec<u16> = ports.iter().copied().filter(|&p| p != 443).collect();
    if ports.contains(&443) {
        ordered.push(443);
    }
    let mut out = Vec::new();
    for host in [reg.endpoint_v4.as_str(), reg.endpoint_v6.as_str()] {
        if let Ok(ip) = host.parse::<IpAddr>() {
            for &p in &ordered {
                out.push(SocketAddr::new(ip, p));
            }
        }
    }
    out
}

/// 从 quinn 流读一个 QUIC 可变长度整数（RFC 9000 §16）。
async fn read_varint(recv: &mut quinn::RecvStream) -> io::Result<u64> {
    read_varint_or_eof(recv)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "H3 帧头意外结束"))
}

async fn read_varint_or_eof(recv: &mut quinn::RecvStream) -> io::Result<Option<u64>> {
    let mut buf = [0u8; 8];
    if AsyncReadExt::read(recv, &mut buf[..1]).await? == 0 {
        return Ok(None);
    }
    let len = 1usize << (buf[0] >> 6);
    AsyncReadExt::read_exact(recv, &mut buf[1..len]).await?;
    let mut value = (buf[0] & 0x3f) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Ok(Some(value))
}

fn io_err(msg: String) -> io::Error {
    io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_headers_frame_has_bounded_allocation() {
        assert_eq!(
            checked_headers_len(MAX_HEADERS_FRAME_SIZE as u64).unwrap(),
            MAX_HEADERS_FRAME_SIZE
        );
        assert!(checked_headers_len(MAX_HEADERS_FRAME_SIZE as u64 + 1).is_err());
    }

    #[tokio::test]
    async fn dropping_framed_stream_aborts_its_pump() {
        let (io, _peer) = tokio::io::duplex(1);
        let task = tokio::spawn(std::future::pending::<io::Result<()>>());
        let abort = task.abort_handle();
        drop(FramedStream {
            io,
            task: Some(task),
        });
        tokio::task::yield_now().await;
        assert!(abort.is_finished());
    }
}
