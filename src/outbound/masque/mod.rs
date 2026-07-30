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

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use async_trait::async_trait;
use log::{info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::outbound::{Connected, Host, Outbound, Stream};
use crate::registration::RegCredentials;

mod doh;
mod huffman;
mod qpack;
mod tls;

const SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);
// 对照 warp-go relayDrainGrace：客户端半关（上行结束）后，最多再等这么久的
// 下行数据；超时强制放弃，避免边缘一侧还在发送、但客户端早已消失（视频类
// 播放器频繁跳转/中止请求就是这种模式）时，这条 H3 流被无限期占着——大量
// 这种"孤儿流"累积起来会耗尽边缘对这条 QUIC 连接分配的并发流配额，表现为
// 之后所有新连接的 open_bi 都挂起超时。
const DRAIN_GRACE: Duration = Duration::from_secs(30);
const RELAY_BUF: usize = 64 * 1024;

/// 一条到边缘的 MASQUE 连接。控制流随 Link 一起存活/释放，避免 forget 的内存语义模糊。
struct Link {
    conn: quinn::Connection,
    // H3 控制流必须常驻到连接结束（主动关闭会触发 H3_CLOSED_CRITICAL_STREAM）。
    _control: quinn::SendStream,
}

/// MASQUE 出网后端。
pub struct Masque {
    endpoint: quinn::Endpoint,
    cfg: quinn::ClientConfig,
    addrs: Vec<SocketAddr>,
    token: String,
    link: Mutex<Link>,
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
        let token = creds.registration.token;
        let link = connect(&endpoint, &cfg, &addrs).await?;
        let dns = doh::DnsCache::new().context("构造 DoH TLS 配置失败")?;
        Ok(Self {
            endpoint,
            cfg,
            addrs,
            token,
            link: Mutex::new(link),
            dns,
        })
    }

    /// 取一条双向流；连接失效则整体重建一次（重连过程仍互斥，避免并发重复重建）。
    ///
    /// `conn.open_bi()` 在对端并发流配额耗尽时会挂起等待（而非报错返回），
    /// 视频等大流量长连接一多就容易触发。锁只用来保护"读/替换 link"这个瞬时
    /// 操作，克隆出 `Connection`（quinn 内部是 Arc handle，克隆是廉价的引用计数）
    /// 后立刻释放锁，真正可能长时间挂起的 `open_bi().await` 在锁外进行——否则
    /// 一次挂起会把所有并发调用者（业务连接/DNS 解析/健康检查探测）串行阻塞在
    /// 这把锁上，逐个等到各自超时，而非各自独立等待/超时。
    async fn open(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let conn = self.link.lock().await.conn.clone();
        if let Ok(pair) = conn.open_bi().await {
            return Ok(pair);
        }

        // open_bi 真正返回 Err 说明连接本身已失效（配额不足只会挂起，不会走到
        // 这里），需要重连。stable_id 判断避免多个调用者同时发现失效时重复重建：
        // 若锁到手时 link 已经被别人重连过，直接用新连接，不再重复拨号。
        let mut link = self.link.lock().await;
        if link.conn.stable_id() == conn.stable_id() {
            warn!("open_bi 失败，重连 ...");
            *link = connect(&self.endpoint, &self.cfg, &self.addrs).await?;
        }
        let conn = link.conn.clone();
        drop(link);
        conn.open_bi().await.context("重连后 open_bi 仍失败")
    }

    /// 域名解析：命中缓存直接返回，否则依次尝试 DoH 候选 IP 查 A/AAAA。
    async fn resolve_domain(&self, domain: &str) -> Result<IpAddr> {
        if let Some(ip) = self.dns.cached(domain).await {
            return Ok(ip);
        }
        let mut last_err = None;
        for qtype in [doh::QueryType::A, doh::QueryType::Aaaa] {
            match self.doh_query(domain, qtype).await {
                Ok(ip) => return Ok(ip),
                Err(e) => {
                    warn!("DoH 查询 {domain}（{qtype:?}）失败: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("DoH 未解析出 {domain} 的 A/AAAA 记录")))
    }

    /// 依次尝试 DoH 候选出口 IP，逐个走隧道 CONNECT + 标准 TLS + HTTP/1.1 查询。
    async fn doh_query(&self, domain: &str, qtype: doh::QueryType) -> Result<IpAddr> {
        let mut last_err = None;
        for doh_addr in doh::DOH_ADDRS {
            match self.doh_query_via(doh_addr, domain, qtype).await {
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
        qtype: doh::QueryType,
    ) -> Result<IpAddr> {
        let (stream, _colo) = self
            .connect_stream(doh_addr)
            .await
            .context("建立 DoH 隧道失败")?;
        self.dns.resolve_over(stream, domain, qtype).await
    }

    /// 打开一条隧道流并完成 H3 CONNECT 握手，返回可直接读写业务字节的流。
    /// `doh_query_via` 和 `connect_tcp` 都要"开流 → CONNECT → 失败就释放两侧"
    /// 这一套，统一到这一处，避免两份各自维护、超时/清理覆盖不一致。
    async fn connect_stream(&self, authority: &str) -> Result<(Box<dyn Stream>, Option<String>)> {
        tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            let (mut send, mut recv) = self.open().await?;
            match exchange(&mut send, &mut recv, authority, &self.token).await {
                Ok(colo) => Ok((wrap_data_framing(send, recv), colo)),
                Err(e) => {
                    let _ = (recv.stop(0u32.into()), send.reset(0u32.into()));
                    Err(e)
                }
            }
        })
        .await
        .context("打开隧道流超时")?
    }
}

#[async_trait]
impl Outbound for Masque {
    fn name(&self) -> &'static str {
        "MASQUE"
    }

    async fn connect_tcp(&self, host: Host, port: u16) -> io::Result<Connected> {
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
    tokio::time::timeout(EXCHANGE_TIMEOUT, send.write_all(&headers))
        .await
        .context("发送 CONNECT 头超时")??;

    // 保留/GREASE 帧类型（RFC 9114 §7.2.8，形如 31*N+33）没有语义，接收方必须
    // 跳过（读 Length 后丢弃对应字节）而非报错，跳过后继续找真正的 HEADERS。
    const MAX_SKIPPED_FRAMES: u32 = 8;
    let payload = 'frames: {
        for _ in 0..MAX_SKIPPED_FRAMES {
            let frame_type = read_varint(recv).await?;
            let len = read_varint(recv).await? as usize;
            if frame_type == 0x01 {
                let mut payload = vec![0u8; len];
                recv.read_exact(&mut payload)
                    .await
                    .context("读取 CONNECT 响应失败")?;
                break 'frames payload;
            }
            let mut skip = vec![0u8; len];
            recv.read_exact(&mut skip).await.context("跳过未知帧失败")?;
        }
        bail!("连续 {MAX_SKIPPED_FRAMES} 个非 HEADERS 帧后仍未收到响应");
    };
    let headers = qpack::decode_headers(&payload).map_err(anyhow::Error::msg)?;
    if headers.status != 200 {
        bail!("边缘拒绝 CONNECT，状态 {}", headers.status);
    }
    Ok(headers.colo)
}

/// CONNECT 成功后，把仍带 H3 DATA frame 分帧的裸双向流包成上层不用关心分帧
/// 的字节流：起一个泵任务做编解码，中间用一对 duplex 转发；调用方拿到的
/// `remote` 端只看到裸隧道字节。收方向遇到非 DATA 帧（如 GREASE）直接丢弃。
fn wrap_data_framing(send: quinn::SendStream, recv: quinn::RecvStream) -> Box<dyn Stream> {
    let (local, remote) = tokio::io::duplex(RELAY_BUF);
    tokio::spawn(pump(send, recv, local));
    Box::new(remote)
}

/// 两个方向在同一个任务内并发跑；上行先结束就只给下行 DRAIN_GRACE 的宽限
/// 期（见该常量注释），超时或下行先结束都会让 send/recv 被 drop 掉。
async fn pump(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    local: tokio::io::DuplexStream,
) {
    let (mut local_read, mut local_write) = tokio::io::split(local);

    let download = drain_download(&mut recv, &mut local_write);
    tokio::pin!(download);
    let upload = drain_upload(&mut local_read, &mut send);
    tokio::pin!(upload);

    tokio::select! {
        () = &mut download => return,
        () = &mut upload => {}
    }
    let _ = tokio::time::timeout(DRAIN_GRACE, download).await;
}

/// 边缘 → 本地：收 H3 DATA frame 解出负载写回本地；非 DATA 帧（如 GREASE）直接丢弃。
async fn drain_download(recv: &mut quinn::RecvStream, out: &mut (impl AsyncWrite + Unpin)) {
    loop {
        let frame_type = match read_varint(recv).await {
            Ok(v) => v,
            Err(_) => return,
        };
        let len = match read_varint(recv).await {
            Ok(v) => v as usize,
            Err(_) => return,
        };
        let mut buf = vec![0u8; len];
        if recv.read_exact(&mut buf).await.is_err() {
            return;
        }
        if frame_type == 0x00 && out.write_all(&buf).await.is_err() {
            return;
        }
    }
}

/// 本地 → 边缘：读本地字节，包成 H3 DATA frame 发出。
async fn drain_upload(input: &mut (impl AsyncRead + Unpin), send: &mut quinn::SendStream) {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = match input.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if send.write_all(&qpack::data_frame(&buf[..n])).await.is_err() {
            return;
        }
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
/// 之所以并发而非逐个尝试：`open()` 重连时持有 `link` 锁调用这里，期间所有
/// 并发的隧道操作（业务连接/DNS/健康检查探测）都会阻塞在锁上；逐个尝试在
/// 候选数多、DIAL_TIMEOUT 较大时最坏耗时是"候选数 × DIAL_TIMEOUT"，容易超过
/// 健康检查轮询间隔导致探测连续失败触发容器重启。并发拨号把最坏耗时压到
/// 接近单次 DIAL_TIMEOUT。
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
    let mut control = conn.open_uni().await.context("打开 H3 控制流失败")?;
    control
        .write_all(&qpack::control_stream_prelude())
        .await
        .context("发送控制流 SETTINGS 失败")?;
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
async fn read_varint(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.context("流意外结束")?;
    let len = 1usize << (first[0] >> 6);
    let mut buf = [0u8; 8];
    if len > 1 {
        recv.read_exact(&mut buf[1..len]).await?;
    }
    let mut value = (first[0] & 0x3f) as u64;
    for &b in &buf[1..len] {
        value = (value << 8) | b as u64;
    }
    Ok(value)
}

fn io_err(msg: String) -> io::Error {
    io::Error::other(msg)
}
