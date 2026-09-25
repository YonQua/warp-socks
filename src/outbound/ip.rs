//! IP 网络栈的地址配置、隧道内解析和 TCP 拨号，供 WireGuard 与 CONNECT-IP 共用。
use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use smoltcp::iface::Config as IfaceConfig;
use smoltcp::wire::{HardwareAddress, IpCidr};

use super::{Connected, Host};
use crate::dns::{resolve, RecordType};
use crate::netstack::{BufferSize, Net, NetConfig};

const DNS_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)), 53);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

pub(super) fn net_config(addresses: Vec<IpCidr>) -> NetConfig {
    let mut interface = IfaceConfig::new(HardwareAddress::Ip);
    interface.random_seed = rand::random();
    let gateways = addresses.iter().map(IpCidr::address).collect();
    let mut config = NetConfig::new(interface, addresses, gateways);
    // 保留现有 256 KiB TCP 窗口，避免小窗口限制高 RTT 隧道吞吐。
    config.buffer_size = BufferSize {
        tcp_rx_size: 256 * 1024,
        tcp_tx_size: 256 * 1024,
        ..Default::default()
    };
    config
}

pub(super) async fn connect_tcp(net: &Net, host: Host, port: u16) -> std::io::Result<Connected> {
    // smoltcp 对未响应的 SYN 只会把重传间隔倍增到 60s 封顶，不加超时会永远挂着。
    let targets = resolve_targets(net, host, port).await?;
    let connected = tokio::time::timeout(
        CONNECT_TIMEOUT,
        connect_first(targets, |addr| net.tcp_connect(addr)),
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

// 域名的 A/AAAA 并发走隧道内 DNS；IP 字面量直接返回。地址按 IPv4、IPv6
// 分组返回，TCP 在下一层交错竞速，UDP 使用第一个地址（A 优先、AAAA 兜底）。
pub(super) async fn resolve_targets(
    net: &Net,
    host: Host,
    port: u16,
) -> std::io::Result<Vec<SocketAddr>> {
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

#[cfg(test)]
mod tests {
    use super::*;
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
