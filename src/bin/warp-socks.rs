// 生产入口：长驻进程，内部完成注册确认、endpoint 候选尝试、SOCKS5 服务与
// 健康检查，替代旧版 shell 的编排（lib/app/main.sh 等，见 docs/module-boundaries.md）。
//
// 用法：
//   warp-socks [serve]                  默认子命令：启动隧道 + SOCKS5 服务（前台常驻）
//   warp-socks register reg <path>      注册 MASQUE 凭据并保存到 path（已存在则跳过）
//   warp-socks register del <path>      向 API 注销并删除本地文件
//   warp-socks healthcheck              无状态单次探测，探测失败以非零退出码结束

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use warp_rs::appconfig::AppConfig;
use warp_rs::fsutil::restrict_to_owner;
use warp_rs::health::SocksTraceProbe;
use warp_rs::registration;
use warp_rs::supervisor::Supervisor;

// 固定 UTC+8（东八区），与容器/宿主机的本地时区设置无关，日志时间戳始终
// 按这个偏移展示，避免跨时区部署时时间戳含义不一致。
const CST_OFFSET: time::UtcOffset = match time::UtcOffset::from_hms(8, 0, 0) {
    Ok(offset) => offset,
    Err(_) => unreachable!(),
};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let now = time::OffsetDateTime::now_utc().to_offset(CST_OFFSET);
            writeln!(
                buf,
                "[{:04}-{:02}-{:02} {:02}:{:02}:{:02} {:<5} {}] {}",
                now.year(),
                u8::from(now.month()),
                now.day(),
                now.hour(),
                now.minute(),
                now.second(),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        None | Some("serve") => Supervisor::new(AppConfig::from_env()).run().await,
        Some("register") => run_register(&args[2..]).await,
        Some("healthcheck") => run_healthcheck().await,
        Some(other) => bail!(
            "未知子命令: {other}\n用法: warp-socks [serve|register reg|del <path>|healthcheck]"
        ),
    }
}

async fn run_register(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        bail!(
            "用法:\n  warp-socks register reg <输出 reg.json 路径>\n  \
             warp-socks register del <reg.json 路径>"
        );
    }
    let path = PathBuf::from(&args[1]);
    match args[0].as_str() {
        "reg" => {
            // 幂等：已有注册则不覆盖（避免旧注册在 Cloudflare 侧失去凭据）。
            if path.exists() {
                println!("{} 已存在；如需更换请先用 del 注销。", path.display());
                return Ok(());
            }
            let creds = registration::register_masque().await?;
            creds
                .registration
                .save(&path)
                .with_context(|| format!("写入 {} 失败", path.display()))?;
            restrict_to_owner(&path);
            println!("✓ 注册信息已保存到 {}", path.display());
        }
        "del" => {
            registration::delete(&path).await?;
            println!("✓ 已删除 {}", path.display());
        }
        other => bail!("未知子命令: {other}（应为 reg 或 del）"),
    }
    Ok(())
}

/// 无状态单次探测：不读写任何失败计数/ready 标记文件，阈值判定完全在
/// Supervisor 自己的运行期健康检查循环里，这里只是给 Docker HEALTHCHECK
/// 一个状态展示信号。
async fn run_healthcheck() -> Result<()> {
    let config = AppConfig::from_env();
    let probe = SocksTraceProbe::new(config.listen_port, config.healthcheck_probe_timeout);
    match probe.probe().await {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("healthcheck 探测失败: {e}");
            std::process::exit(1);
        }
    }
}
