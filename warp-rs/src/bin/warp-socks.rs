// 生产用二进制：解析 wg0.conf → boringtun 握手 → 虚拟 TCP/IP 栈 → SOCKS5 CONNECT。
// 用法：warp-socks <wg0.conf 路径> <SOCKS5 监听地址> [none|t1|t2]

use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio_smoltcp::smoltcp::iface::Config;
use tokio_smoltcp::smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig};

use warp_rs::config::parse_wg_conf;
use warp_rs::mixed;
use warp_rs::tunnel::{Trick, WgTunnel};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        bail!("用法: warp-socks <wg0.conf 路径> <SOCKS5 监听地址> [none|t1|t2]");
    }
    let conf_path = &args[1];
    let listen_addr: SocketAddr = args[2].parse().context("SOCKS5 监听地址格式错误")?;
    let trick = match args.get(3).map(String::as_str).unwrap_or("none") {
        "none" => Trick::None,
        "t1" => Trick::T1,
        "t2" => Trick::T2,
        other => bail!("trick 模式必须是 none/t1/t2，收到: {other}"),
    };

    let config = parse_wg_conf(conf_path)?;
    println!(
        "已解析 wg0.conf：endpoint={}, reserved={:?}, trick={:?}",
        config.endpoint, config.reserved, trick
    );

    let mut tunnel = WgTunnel::connect(&config, trick).await?;
    tunnel.handshake(Duration::from_secs(20)).await?;
    println!("✓ 握手已建立");

    let mut interface_config = Config::new(HardwareAddress::Ip);
    interface_config.random_seed = rand::random();

    let ip_addr = IpCidr::new(IpAddress::from(IpAddr::V4(config.address_v4)), 32);
    // Medium::Ip 下路由表只是内部记账、不涉及真实 ARP/NDP 解析，网关随便填一个即可
    // （AllowedIPs=0.0.0.0/0 时目的地永远走这唯一一张虚拟网卡）。
    let gateway = vec![IpAddress::from(IpAddr::V4(config.address_v4))];
    let mut net_config = NetConfig::new(interface_config, ip_addr, gateway);
    // 默认 8KiB 收发窗口在实测中把单连接吞吐限制在约 30KB/s（窗口/RTT），
    // 经隧道到真实目的地的 RTT 通常有上百毫秒，8KiB 窗口远小于所需 BDP。
    // 调大到 256KiB 后单连接吞吐可提升到 MB/s 级别；容器 mem_limit=256m 下，
    // 并发数十个连接（典型网页加载场景）总占用仍在数十 MB，留有余量。
    net_config.buffer_size = BufferSize {
        tcp_rx_size: 256 * 1024,
        tcp_tx_size: 256 * 1024,
        ..Default::default()
    };

    let net = Net::new(tunnel, net_config);

    println!("混合代理（SOCKS5/SOCKS4/HTTP）监听于 {listen_addr}");
    mixed::serve(net, listen_addr).await
}
