// WireGuard 出网后端：把现有 tokio_smoltcp::Net 虚拟网卡包装成 Outbound trait。
//
// connect_tcp 走虚拟网卡的 TCP 栈；域名目标在隧道内用虚拟网卡的 UDP socket
// 发 DNS 查询解析。这层只是薄封装，实际逻辑在 tokio_smoltcp::Net 和 crate::dns 里。
//
// 自愈（heal）语义对齐 masque::Masque::open()：探测失败时单飞重连，对
// Supervisor 完全透明。区别只是 WireGuard 没有 MASQUE close_reason() 那种
// 廉价活性查询——触发信号由调用方（健康探测失败）决定，候选池/冷却状态
// 因此整体收在这个后端自己手里，而不是暴露给编排层。

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use log::warn;
use tokio::sync::{Mutex, RwLock};
use tokio_smoltcp::smoltcp::iface::Config as IfaceConfig;
use tokio_smoltcp::smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig, UdpSocket as TunnelUdpSocket};

use super::{Connected, Datagram, Host, Outbound};
use crate::config::{parse_wg_conf, WgConfig};
use crate::dns::{resolve, RecordType};
use crate::endpoint::{plan_candidates, JsonFileEndpointStore};
use crate::registration::{self, WgAccount};
use crate::tunnel::{Trick, WgTunnel};

const DNS_SERVER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    53,
);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// `establish` 需要的、连接本身用不到、只在运行期自愈时才会用上的那部分
/// 状态，打包传入避免参数表过长，也把"自愈需要什么"集中在一处声明。
pub struct WgHealConfig {
    pub pool: Vec<String>,
    pub endpoint_state_file: PathBuf,
    pub wg_conf_path: PathBuf,
    pub cooldown: Duration,
}

/// 自愈上下文：换一个候选 endpoint 原地重建隧道需要的一切。整体收在这里、
/// 整体锁住——这把锁本身就是单飞锁（对齐 masque::Masque 的 `reconnecting`），
/// 不需要再单独维护一把 `Mutex<()>`。
struct HealCtx {
    account: WgAccount,
    pool: Vec<String>,
    endpoint_state_file: PathBuf,
    wg_conf_path: PathBuf,
    trick: Trick,
    handshake_timeout: Duration,
    cooldown: Duration,
    current: String,
}

pub struct WgOutbound {
    net: RwLock<Net>,
    heal_ctx: Mutex<HealCtx>,
}

impl WgOutbound {
    /// 用给定候选 endpoint 建立 WireGuard 隧道（连接 + 握手）并起虚拟网卡；
    /// 同时保存自愈所需的账户/候选池/冷却状态，供运行期 [`Outbound::heal`] 使用。
    ///
    /// # Errors
    /// 隧道连接、握手失败时返回错误。
    pub async fn establish(
        account: &WgAccount,
        endpoint: &str,
        trick: Trick,
        handshake_timeout: Duration,
        heal: WgHealConfig,
    ) -> Result<Self> {
        let wg_config = write_and_parse(account, endpoint, &heal.wg_conf_path)?;
        let net = build_net(&wg_config, trick, handshake_timeout).await?;
        Ok(Self {
            net: RwLock::new(net),
            heal_ctx: Mutex::new(HealCtx {
                account: account.clone(),
                pool: heal.pool,
                endpoint_state_file: heal.endpoint_state_file,
                wg_conf_path: heal.wg_conf_path,
                trick,
                handshake_timeout,
                cooldown: heal.cooldown,
                current: endpoint.to_string(),
            }),
        })
    }

    // 域名在隧道内解析；IP 直接使用。connect_tcp/connect_udp 共用。
    async fn resolve_target(&self, host: Host, port: u16) -> std::io::Result<SocketAddr> {
        match host {
            Host::Ip(ip) => Ok(SocketAddr::new(ip, port)),
            Host::Domain(name) => {
                let net = self.net.read().await;
                let ips = resolve(&net, DNS_SERVER, &name, RecordType::A, DNS_TIMEOUT)
                    .await
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            format!("隧道内解析域名 {name} 失败: {e}"),
                        )
                    })?;
                let ip = ips.into_iter().next().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("域名 {name} 未解析到地址"),
                    )
                })?;
                Ok(SocketAddr::new(ip, port))
            }
        }
    }
}

/// 建 `Tunn` + 握手 + 起虚拟网卡；`establish`/`heal` 共用。
async fn build_net(config: &WgConfig, trick: Trick, handshake_timeout: Duration) -> Result<Net> {
    let mut tunnel = WgTunnel::connect(config, trick).await?;
    tunnel.handshake(handshake_timeout).await?;

    let mut interface_config = IfaceConfig::new(HardwareAddress::Ip);
    interface_config.random_seed = rand::random();
    let ip_addr = IpCidr::new(IpAddress::from(IpAddr::V4(config.address_v4)), 32);
    let gateway = vec![IpAddress::from(IpAddr::V4(config.address_v4))];
    let mut net_config = NetConfig::new(interface_config, ip_addr, gateway);
    // 默认 8KiB 收发窗口在实测中把单连接吞吐限制在约 30KB/s（窗口/RTT），
    // 调大到 256KiB 后单连接吞吐可提升到 MB/s 级别。
    net_config.buffer_size = BufferSize {
        tcp_rx_size: 256 * 1024,
        tcp_tx_size: 256 * 1024,
        ..Default::default()
    };

    Ok(Net::new(tunnel, net_config))
}

/// 写 wg0.conf（覆盖 endpoint）再解析回 `WgConfig`；`establish`/`heal` 共用，
/// 避免两处各写一份"写文件再读回来"的模板代码。
fn write_and_parse(account: &WgAccount, endpoint: &str, path: &Path) -> Result<WgConfig> {
    registration::write_wg_conf(account, Some(endpoint), path)?;
    let path_str = path.to_str().context("wg0.conf 路径包含非 UTF-8 字符")?;
    parse_wg_conf(path_str)
}

/// 隧道内的 UDP 数据报通道：绑定虚拟网卡的一个 UDP socket，只认来自
/// `target` 的回包（对齐 `Datagram` trait 单一对端的语义）。
struct WgDatagram {
    sock: TunnelUdpSocket,
    target: SocketAddr,
}

#[async_trait]
impl Datagram for WgDatagram {
    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send(&self, buf: &[u8]) -> std::io::Result<()> {
        self.sock.send_to(buf, self.target).await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let (n, from) = self.sock.recv_from(buf).await?;
            if from == self.target {
                return Ok(n);
            }
        }
    }
}

#[async_trait]
impl Outbound for WgOutbound {
    fn name(&self) -> &'static str {
        "WireGuard"
    }

    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Connected> {
        // smoltcp 对未响应的 SYN 只会把重传间隔倍增到 60s 封顶，不加超时会永远挂着。
        let addr = self.resolve_target(host, port).await?;
        // 读锁覆盖整个 tcp_connect：期间若 heal() 想拿写锁会等到这次连接
        // 结束或超时（最坏 CONNECT_TIMEOUT），可接受——换来的是不需要确认
        // tokio_smoltcp::Net 是否可廉价 Clone。
        let net = self.net.read().await;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, net.tcp_connect(addr))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("连接 {addr} 超时（{CONNECT_TIMEOUT:?}）"),
                )
            })??;
        Ok(Connected {
            stream: Box::new(stream),
            note: None,
        })
    }

    async fn connect_udp(&self, host: Host, port: u16) -> std::io::Result<Box<dyn Datagram>> {
        let target = self.resolve_target(host, port).await?;
        let net = self.net.read().await;
        let sock = net
            .udp_bind("0.0.0.0:0".parse().unwrap())
            .await
            .map_err(|e| std::io::Error::other(format!("绑定隧道内 UDP socket 失败: {e}")))?;
        Ok(Box::new(WgDatagram { sock, target }))
    }

    /// 换一个未冷却的候选 endpoint，原地重建隧道；语义对齐
    /// `masque::Masque::open()` 的单飞重连——`heal_ctx` 锁本身就是单飞锁，
    /// 重建这段网络 I/O 在锁内进行（WireGuard 没有 MASQUE `close_reason()`
    /// 那种廉价活性查询，调用方直接决定"现在要重建"，不需要额外区分"读
    /// 当前状态"和"决定要不要重连"两把锁）。
    async fn heal(&self) -> Result<()> {
        let mut ctx = self.heal_ctx.lock().await;
        let mut store = JsonFileEndpointStore::load(&ctx.endpoint_state_file)?;
        store.mark_cooldown(&ctx.current, ctx.cooldown)?;

        let next = plan_candidates(ctx.pool.clone(), &store)
            .into_iter()
            .find(|ep| ep != &ctx.current)
            .context("候选池已无其它可用 endpoint")?;

        let build = async {
            let wg_config = write_and_parse(&ctx.account, &next, &ctx.wg_conf_path)?;
            build_net(&wg_config, ctx.trick, ctx.handshake_timeout).await
        };
        let fresh = match build.await {
            Ok(fresh) => fresh,
            Err(e) => {
                // next 本身建立失败，标记冷却避免下次探测失败又立刻选中它，对齐
                // run_wireguard() 启动循环里每个候选失败都会 mark_cooldown 的做法。
                // 冷却写入是 best-effort：就算它也失败（如本机 fd 耗尽），也不该
                // 掩盖真正的建隧道错误 e。
                let _ = store.mark_cooldown(&next, ctx.cooldown);
                return Err(e);
            }
        };
        // 隧道已经真正切换成功——net 替换、ctx.current 同步都是纯内存操作，
        // 不依赖磁盘 I/O，必须在这里就完成，不能让下面 record_success 的写盘
        // 失败倒过来污染"自愈是否成功"这个判断：不然调用方看到 heal() 返回
        // Err 会误以为隧道没切过去，实际 net 早已指向 next，只是没记到
        // endpoint-state.json 里而已（下次心跳探测走的是新隧道，会正常通过）。
        *self.net.write().await = fresh;
        ctx.current = next.clone();

        if let Err(e) = store.record_success(&next) {
            warn!("记录 endpoint {next} 成功状态失败（不影响本次自愈结果）: {e:#}");
        }
        Ok(())
    }
}
