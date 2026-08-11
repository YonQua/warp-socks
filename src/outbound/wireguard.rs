// WireGuard 出网后端：把项目内双栈 Net 虚拟网卡包装成 Outbound trait。
//
// connect_tcp 走虚拟网卡的 TCP 栈；域名目标在隧道内用虚拟网卡的 UDP socket
// 发 DNS 查询解析。这层只是薄封装，实际逻辑在 crate::netstack 和 crate::dns 里。
//
// WireGuard 后端持有单一、不可变的 Net 生命周期。运行期不原地重建或切换；
// 真实出口探测失败时由 Supervisor 结束整个进程生命周期。

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use smoltcp::iface::Config as IfaceConfig;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use super::{Connected, Datagram, Host, Outbound};
use crate::config::WgConfig;
use crate::dns::{resolve, RecordType};
use crate::netstack::{BufferSize, Net, NetConfig, UdpSocket as TunnelUdpSocket};
use crate::tunnel::{Trick, WgTunnel};

const DNS_SERVER: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    53,
);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

pub struct WgOutbound {
    net: Net,
}

impl WgOutbound {
    /// 用已派生的配置建立 WireGuard 隧道（连接 + 握手）并起虚拟网卡。
    ///
    /// # Errors
    /// 隧道连接、握手失败时返回错误。
    pub async fn establish(
        config: &WgConfig,
        trick: Trick,
        handshake_timeout: Duration,
    ) -> Result<Self> {
        let mut tunnel = WgTunnel::connect(config, trick).await?;
        tunnel.handshake(handshake_timeout).await?;
        let observer = tunnel.observer();
        let net = Net::new_observed(tunnel, build_net_config(config), observer)
            .context("启动 WireGuard 双栈网络栈失败")?;
        Ok(Self { net })
    }

    // 域名的 A/AAAA 并发走隧道内 DNS；IP 字面量直接返回。地址按 IPv4、IPv6
    // 分组返回，TCP 在下一层交错竞速，UDP 使用第一个地址（A 优先、AAAA 兜底）。
    async fn resolve_targets(net: &Net, host: Host, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        match host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(ip, port)]),
            Host::Domain(name) => {
                let (a, aaaa) = tokio::join!(
                    resolve(net, DNS_SERVER, &name, RecordType::A, DNS_TIMEOUT),
                    resolve(net, DNS_SERVER, &name, RecordType::Aaaa, DNS_TIMEOUT),
                );
                let mut targets = Vec::new();
                let mut seen = std::collections::HashSet::new();
                let mut errors = Vec::new();
                for result in [a, aaaa] {
                    match result {
                        Ok(resolved) => targets.extend(
                            resolved
                                .into_iter()
                                .filter(|ip| seen.insert(*ip))
                                .map(|ip| SocketAddr::new(ip, port)),
                        ),
                        Err(error) => errors.push(error.to_string()),
                    }
                }
                if targets.is_empty() {
                    let detail = if errors.is_empty() {
                        "A/AAAA 均无记录".to_string()
                    } else {
                        errors.join("; ")
                    };
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("隧道内解析域名 {name} 失败: {detail}"),
                    ));
                }
                Ok(targets)
            }
        }
    }
}

fn interleave_addresses(targets: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut v4 = targets
        .iter()
        .copied()
        .filter(SocketAddr::is_ipv4)
        .collect::<VecDeque<_>>();
    let mut v6 = targets
        .into_iter()
        .filter(SocketAddr::is_ipv6)
        .collect::<VecDeque<_>>();
    let mut ordered = Vec::with_capacity(v4.len() + v6.len());
    while !v4.is_empty() || !v6.is_empty() {
        if let Some(addr) = v4.pop_front() {
            ordered.push(addr);
        }
        if let Some(addr) = v6.pop_front() {
            ordered.push(addr);
        }
    }
    ordered
}

async fn connect_first<T, F, Fut>(
    targets: Vec<SocketAddr>,
    connect: F,
) -> std::io::Result<(T, SocketAddr)>
where
    F: Fn(SocketAddr) -> Fut + Clone,
    Fut: Future<Output = std::io::Result<T>>,
{
    let mut attempts = FuturesUnordered::new();
    for (index, target) in interleave_addresses(targets).into_iter().enumerate() {
        let connect = connect.clone();
        attempts.push(async move {
            if index > 0 {
                tokio::time::sleep(HAPPY_EYEBALLS_DELAY * index as u32).await;
            }
            (target, connect(target).await)
        });
    }

    let mut errors = Vec::new();
    while let Some((target, result)) = attempts.next().await {
        match result {
            Ok(stream) => return Ok((stream, target)),
            Err(error) => errors.push(format!("{target}: {error}")),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        if errors.is_empty() {
            "没有可连接的目标地址".to_string()
        } else {
            format!("所有目标地址连接失败: {}", errors.join("; "))
        },
    ))
}

fn build_net_config(config: &WgConfig) -> NetConfig {
    let mut interface_config = IfaceConfig::new(HardwareAddress::Ip);
    interface_config.random_seed = rand::random();
    let address_v4 = IpAddress::from(IpAddr::V4(config.address_v4));
    let address_v6 = IpAddress::from(IpAddr::V6(config.address_v6));
    let mut net_config = NetConfig::new(
        interface_config,
        vec![IpCidr::new(address_v4, 32), IpCidr::new(address_v6, 128)],
        vec![address_v4, address_v6],
    );
    // 默认 8KiB 收发窗口在实测中把单连接吞吐限制在约 30KB/s（窗口/RTT），
    // 调大到 256KiB 后单连接吞吐可提升到 MB/s 级别。
    net_config.buffer_size = BufferSize {
        tcp_rx_size: 256 * 1024,
        tcp_tx_size: 256 * 1024,
        ..Default::default()
    };

    net_config
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

    fn supports_udp(&self) -> bool {
        true
    }

    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Connected> {
        // smoltcp 对未响应的 SYN 只会把重传间隔倍增到 60s 封顶，不加超时会永远挂着。
        let targets = Self::resolve_targets(&self.net, host, port).await?;
        let connected = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_first(targets, |addr| self.net.tcp_connect(addr)),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("连接所有目标地址超时（{CONNECT_TIMEOUT:?}）"),
            )
        })??;
        Ok(Connected {
            stream: Box::new(connected.0),
            note: Some(format!("target={}", connected.1)),
        })
    }

    async fn connect_udp(&self, host: Host, port: u16) -> std::io::Result<Box<dyn Datagram>> {
        let target = Self::resolve_targets(&self.net, host, port)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "域名未解析到 UDP 目标地址",
                )
            })?;
        let bind_addr = match target {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let sock = self
            .net
            .udp_bind(bind_addr)
            .await
            .map_err(|e| std::io::Error::other(format!("绑定隧道内 UDP socket 失败: {e}")))?;
        Ok(Box::new(WgDatagram { sock, target }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn config() -> WgConfig {
        WgConfig {
            private_key: [1; 32],
            peer_public_key: [2; 32],
            endpoint: "192.0.2.1:2408".parse().unwrap(),
            reserved: [0; 3],
            address_v4: Ipv4Addr::new(172, 16, 0, 2),
            address_v6: "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
        }
    }

    #[test]
    fn net_config_contains_dual_stack_addresses_and_routes() {
        let config = build_net_config(&config());
        let v4 = IpAddress::from(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)));
        let v6 = IpAddress::from(IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()));

        assert_eq!(
            config.ip_addrs,
            vec![IpCidr::new(v4, 32), IpCidr::new(v6, 128)]
        );
        assert_eq!(config.gateways, vec![v4, v6]);
    }

    #[test]
    fn happy_eyeballs_interleaves_ipv4_and_ipv6() {
        let v4a = SocketAddr::from(([192, 0, 2, 1], 443));
        let v4b = SocketAddr::from(([192, 0, 2, 2], 443));
        let v6a = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443));
        let v6b = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443));

        assert_eq!(
            interleave_addresses(vec![v4a, v4b, v6a, v6b]),
            vec![v4a, v6a, v4b, v6b]
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_uses_ipv6_when_ipv4_stalls() {
        let v4 = SocketAddr::from(([192, 0, 2, 1], 443));
        let v6 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443));
        let started = tokio::time::Instant::now();

        let (connected, selected) = connect_first(vec![v4, v6], |target| async move {
            if target.is_ipv4() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "IPv4 stalled",
                ))
            } else {
                Ok(target)
            }
        })
        .await
        .unwrap();

        assert_eq!(selected, v6);
        assert_eq!(connected, v6);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
