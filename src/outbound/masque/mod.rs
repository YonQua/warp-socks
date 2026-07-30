// MASQUE 隧道：到 WARP 边缘的 QUIC 连接，每次 connect 产出一条 H3 CONNECT 双向流。
//
// 核心流程（对照 warp-go/tunnel/masque.go）：
//   1. 拨号到边缘（20 字节 SCID 对齐 warp-svc，端口 443 因 DAE 拦截放最后）
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::outbound::{Host, Outbound, Stream};
use crate::registration::RegCredentials;

mod doh;
mod qpack;
mod tls;

const SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(15);

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

    /// 取一条双向流；连接失效则整体重建一次（持锁期间完成，避免并发重连）。
    async fn open(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        {
            let link = self.link.lock().await;
            if let Ok(pair) = link.conn.open_bi().await {
                return Ok(pair);
            }
        }
        let mut link = self.link.lock().await;
        warn!("open_bi 失败，重连 ...");
        *link = connect(&self.endpoint, &self.cfg, &self.addrs).await?;
        link.conn.open_bi().await.context("重连后 open_bi 仍失败")
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
        let (mut send, mut recv) = tokio::time::timeout(EXCHANGE_TIMEOUT, self.open())
            .await
            .context("打开 DoH 隧道流超时")??;
        tokio::time::timeout(
            EXCHANGE_TIMEOUT,
            exchange(&mut send, &mut recv, doh_addr, &self.token),
        )
        .await
        .context("DoH CONNECT 超时")??;
        let stream = wrap_data_framing(send, recv);
        self.dns.resolve_over(stream, domain, qtype).await
    }
}

#[async_trait]
impl Outbound for Masque {
    async fn connect_tcp(&self, host: Host, port: u16) -> io::Result<Box<dyn Stream>> {
        let authority = match host {
            Host::Domain(d) => {
                let ip = self
                    .resolve_domain(&d)
                    .await
                    .map_err(|e| io_err(format!("DoH 解析 {d} 失败: {e:#}")))?;
                format!("{ip}:{port}")
            }
            Host::Ip(ip) => format!("{ip}:{port}"),
        };

        let (mut send, mut recv) = tokio::time::timeout(EXCHANGE_TIMEOUT, self.open())
            .await
            .map_err(|_| io_err(format!("打开隧道流超时: {authority}")))?
            .map_err(|e| io_err(format!("打开隧道流失败: {e}")))?;

        // CONNECT 交换失败统一在这里释放两侧，防僵尸流耗尽并发流配额。
        match exchange(&mut send, &mut recv, &authority, &self.token).await {
            Ok(()) => Ok(wrap_data_framing(send, recv)),
            Err(e) => {
                let _ = (recv.stop(0u32.into()), send.reset(0u32.into()));
                Err(io_err(format!("MASQUE CONNECT {authority} 失败: {e:#}")))
            }
        }
    }
}

/// 发 HEADERS(CONNECT) 并读 :status，200 才算隧道建立。
async fn exchange(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    authority: &str,
    token: &str,
) -> Result<()> {
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
    let status = qpack::decode_status(&payload).map_err(anyhow::Error::msg)?;
    if status != 200 {
        bail!("边缘拒绝 CONNECT，状态 {status}");
    }
    Ok(())
}

/// CONNECT 成功后，把仍带 H3 DATA frame 分帧的裸双向流包成上层不用关心分帧
/// 的字节流：起两个泵任务做编解码，中间用一对 duplex 转发；调用方拿到的
/// `remote` 端只看到裸隧道字节。收方向遇到非 DATA 帧（如 GREASE）直接丢弃。
fn wrap_data_framing(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Box<dyn Stream> {
    const RELAY_BUF: usize = 64 * 1024;
    let (local, remote) = tokio::io::duplex(RELAY_BUF);
    let (mut local_read, mut local_write) = tokio::io::split(local);

    tokio::spawn(async move {
        loop {
            let frame_type = match read_varint(&mut recv).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let len = match read_varint(&mut recv).await {
                Ok(v) => v as usize,
                Err(_) => return,
            };
            let mut buf = vec![0u8; len];
            if recv.read_exact(&mut buf).await.is_err() {
                return;
            }
            if frame_type == 0x00 && local_write.write_all(&buf).await.is_err() {
                return;
            }
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_BUF];
        loop {
            let n = match local_read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if send.write_all(&qpack::data_frame(&buf[..n])).await.is_err() {
                return;
            }
        }
    });

    Box::new(remote)
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

/// 遍历候选边缘（443 因 DAE 拦截放最后），首个握手成功的用。
async fn connect(
    endpoint: &quinn::Endpoint,
    cfg: &quinn::ClientConfig,
    addrs: &[SocketAddr],
) -> Result<Link> {
    let mut last: Option<anyhow::Error> = None;
    for &addr in addrs {
        info!("QUIC 拨号 {addr}（SNI={SNI}）...");
        let connecting = match endpoint.connect_with(cfg.clone(), addr, SNI) {
            Ok(c) => c,
            Err(e) => {
                last = Some(anyhow::Error::from(e));
                continue;
            }
        };
        match tokio::time::timeout(DIAL_TIMEOUT, connecting).await {
            Ok(Ok(conn)) => {
                let mut control = conn.open_uni().await.context("打开 H3 控制流失败")?;
                control
                    .write_all(&qpack::control_stream_prelude())
                    .await
                    .context("发送控制流 SETTINGS 失败")?;
                info!("✓ QUIC 已连接到 {addr}");
                return Ok(Link {
                    conn,
                    _control: control,
                });
            }
            Ok(Err(e)) => {
                warn!("边缘 {addr} 不可达（{e}），尝试下一个端口 ...");
                last = Some(anyhow::Error::from(e));
            }
            Err(_) => {
                warn!("边缘 {addr} 拨号超时（{DIAL_TIMEOUT:?}），尝试下一个端口 ...");
                last = Some(anyhow!("拨号 {addr} 超时"));
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("无候选边缘地址")))
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
