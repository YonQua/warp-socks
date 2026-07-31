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
// open_bi 单次尝试的超时：对端并发流配额耗尽时 open_bi 会无限期挂起而非报
// 错（视频等大量长连接同时在线时会真实触发），这里用超时把"挂起"也当成
// "这条连接暂时用不了"，交给 open() 触发重连——对照 warp-go openRequestStream
// 的 10s openCtx（masque.go:366）。
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
// 重连时建 H3 控制流（open_uni + 发 SETTINGS）的超时：这段是纯网络 I/O，
// 边缘响应慢时会无限期挂起——对照 warp-go dialAddr 的 setupTimer（同样
// 10s，masque.go:308-327）。没有这层超时时，一次控制流建立变慢会让
// open() 持锁重连的过程被无限拉长（见 open() 注释）。
const CONTROL_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
// open() 重连失败时最坏耗时：首次尝试超时(OPEN_TIMEOUT) + 重连拨号(至多
// DIAL_TIMEOUT，候选并发拨号，不是累加) + 建控制流(至多 CONTROL_STREAM_TIMEOUT)
// + 重试一次(OPEN_TIMEOUT)。
const OPEN_RETRY_BUDGET: Duration = Duration::from_secs(
    OPEN_TIMEOUT.as_secs() * 2 + DIAL_TIMEOUT.as_secs() + CONTROL_STREAM_TIMEOUT.as_secs(),
);
// connect_stream 的总预算，从上面两个子预算推导而非独立取一个数字：这样
// OPEN_TIMEOUT/DIAL_TIMEOUT 改动后这里自动跟着变，不会出现"改了内层超时
// 却忘了同步外层"的漂移。外层调用方（relay::CONNECT_TIMEOUT、健康检查的
// healthcheck_probe_timeout）都必须 ≥ 这个值，否则会在这里的重连自愈还没
// 跑完之前就被提前掐断，把一次本可恢复的重连误判成超时失败——这正是最初
// 加上 open() 重连后仍然复现崩溃的根因：多层超时互不知情、外层比内层更没
// 耐心。`pub(crate)` 是为了让 relay.rs / appconfig.rs 直接从这个值派生自己
// 的外层超时，而不是各自手抄一个数字再靠注释提醒"记得保持同步"。
pub(crate) const CONNECT_STREAM_TIMEOUT: Duration =
    Duration::from_secs(OPEN_RETRY_BUDGET.as_secs() + EXCHANGE_TIMEOUT.as_secs());
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
    // 只串行化"谁去拨号重连"，不覆盖对 link 的读取——重连期间其他调用者
    // 仍能立刻读到（旧的）link 去尝试 open_bi，不会被一次慢重连卡住整条
    // 读路径。对照 warp-go connMu（读，masque.go:331-345）与 reconnectMu
    // （重连，masque.go:391-410）分离的设计；此前 link 锁被 `*link =
    // connect(...).await?` 整段持有，是这次故障（大量并发调用者一起卡在
    // 获取 link 锁上，直到唯一一次重连结束）的根因。
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
        let token = creds.registration.token;
        let link = connect(&endpoint, &cfg, &addrs).await?;
        let dns = doh::DnsCache::new().context("构造 DoH TLS 配置失败")?;
        Ok(Self {
            endpoint,
            cfg,
            addrs,
            token,
            link: Mutex::new(link),
            reconnecting: Mutex::new(()),
            dns,
        })
    }

    /// 取一条双向流；连接失效或配额耗尽则整体重建一次（重连过程仍互斥，
    /// 避免并发重复重建）。
    ///
    /// 锁只用来保护"读/替换 link"这个瞬时操作，克隆出 `Connection`（quinn
    /// 内部是 Arc handle，克隆是廉价的引用计数）后立刻释放锁，真正可能长时间
    /// 挂起的 `open_bi().await` 在锁外进行——否则一次挂起会把所有并发调用者
    /// （业务连接/DNS 解析/健康检查探测）串行阻塞在这把锁上，逐个等到各自
    /// 超时，而非各自独立等待/超时。
    ///
    /// `open_bi_bounded` 把"挂起"和"报错"统一处理为失败：对端并发流配额
    /// 耗尽时 `open_bi()` 是挂起等待而非报错返回（大量视频等长连接同时在线
    /// 时会真实触发），若不把挂起也当失败处理，这条连接会一直卡住、永远
    /// 等不到重连，直至健康检查连续失败到阈值、整个进程被拖垮重启——重启
    /// 能"治好"只是因为重启后连接是全新的、配额也是满的，纯属巧合式自愈。
    async fn open(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let conn = self.link.lock().await.conn.clone();
        // `close_reason()` 是非阻塞的同步查询：连接已被 keep_alive/max_idle_timeout
        // （见 tls::client_config）判定失效、或对端主动关闭时立刻返回 Some，
        // 不需要真去发一次 open_bi 才发现。对照 warp-go currentConnection()
        // （masque.go:331-345）同样的"先查活性，已知失效就跳过尝试直接走
        // 重连"模式——没有这一步时，已知已死的连接仍要白等一整个 OPEN_TIMEOUT
        // 才会触发重连，而这种情况在有了 keep_alive/idle_timeout 之后是最常见
        // 的失效路径，不该占满超时预算。
        if conn.close_reason().is_none() {
            if let Ok(pair) = open_bi_bounded(&conn).await {
                return Ok(pair);
            }
        }

        // `reconnecting` 只串行化拨号本身，不占用 `link` 的锁：`connect()`
        // 是可能耗时的网络 I/O（拨号 + 建控制流，即便都已限时），若像此前那样
        // 在持有 `link` 锁的情况下 `.await` 它，会让所有并发调用者（包括只
        // 是想读一下 link 去试 open_bi 的）一起卡在获取锁上，直到这一次重连
        // 结束——这正是故障现场"上百个并发请求同时超时失败，但只有一次
        // 重连日志"的根因。
        let _reconnecting = self.reconnecting.lock().await;
        // stable_id 判断避免多个调用者同时发现失效时重复重建：等到手上这把
        // 拨号锁时，link 可能已经被排在前面的调用者换成新连接了。
        let stale_id = self.link.lock().await.conn.stable_id();
        if stale_id == conn.stable_id() {
            warn!("open_bi 超时或失败，重连 ...");
            let fresh = connect(&self.endpoint, &self.cfg, &self.addrs).await?;
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
        tokio::time::timeout(CONNECT_STREAM_TIMEOUT, async {
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
