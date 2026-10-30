// WireGuard 出网后端：把项目内双栈 Net 虚拟网卡包装成 Outbound trait。
//
// connect_tcp 走虚拟网卡的 TCP 栈；域名目标在隧道内用虚拟网卡的 UDP socket
// 发 DNS 查询解析。这层只是薄封装，实际逻辑在 crate::netstack 和 crate::dns 里。
//
// WireGuard 后端持有单一、不可变的 Net 生命周期。运行期不原地重建或切换；
// 真实出口探测失败时由 Supervisor 撤销旧出口并重建完整链路。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use smoltcp::wire::{IpAddress, IpCidr};

use super::{ip, Connected, Datagram, Host, Outbound};
use crate::config::WgConfig;
use crate::netstack::{Net, NetConfig, UdpSocket as TunnelUdpSocket};
use crate::tunnel::{Trick, WgTunnel};

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
}

fn build_net_config(config: &WgConfig) -> NetConfig {
    ip::net_config(vec![
        IpCidr::new(IpAddress::from(IpAddr::V4(config.address_v4)), 32),
        IpCidr::new(IpAddress::from(IpAddr::V6(config.address_v6)), 128),
    ])
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

    async fn terminated(&self) -> String {
        self.net.terminated().await
    }

    async fn connect_tcp(&self, host: Host, port: u16) -> std::io::Result<Connected> {
        ip::connect_tcp(&self.net, host, port).await
    }

    async fn connect_udp(&self, host: Host, port: u16) -> std::io::Result<Box<dyn Datagram>> {
        let target = ip::resolve_targets(&self.net, host, port)
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
}
