// Phase 0/1 握手可行性验证：读取现有生产 wg0.conf（只读，不改动、不重新注册），
// 用 boringtun 做真实握手。隧道内 DNS/SOCKS5 端到端验证见 warp-socks 二进制
// （Phase 2 起改走 tokio_smoltcp 虚拟网卡，不再需要这里单独手搓 IP 包测试）。
//
// 用法：handshake_probe <wg0.conf 路径> <none|t1|t2>

use std::env;
use std::time::Duration;

use anyhow::{bail, Result};
use warp_rs::config::parse_wg_conf;
use warp_rs::tunnel::{Trick, WgTunnel};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        bail!("用法: handshake_probe <wg0.conf 路径> <none|t1|t2>");
    }
    let conf_path = &args[1];
    let trick = match args[2].as_str() {
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
    println!("✓ 握手已建立（本地 UDP 端口 {:?}）", tunnel.local_addr()?);
    Ok(())
}
