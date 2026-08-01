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
use warp_rs::health::heartbeat;
use warp_rs::registration;
use warp_rs::supervisor::Supervisor;

// 固定 UTC+8（东八区），与容器/宿主机的本地时区设置无关，日志时间戳始终
// 按这个偏移展示，避免跨时区部署时时间戳含义不一致。
const CST_OFFSET: time::UtcOffset = match time::UtcOffset::from_hms(8, 0, 0) {
    Ok(offset) => offset,
    Err(_) => unreachable!(),
};

// worker_threads 固定给 2，不用默认值：默认值是 std::thread::available_parallelism()
// 探测到的宿主机 CPU 核数，不感知 compose.yaml 里 `cpus: 0.50` 这个 cgroup
// 配额——在多核宿主机上会起远多于配额所需的线程数，徒增线程间调度/工作
// 窃取的开销。这个代理是 IO 密集型（大部分时间在 epoll 等待），真正的 CPU
// 需求集中在偶发的握手/隧道加解密上，2 个线程既够用又不会在 0.5 核配额下
// 造成过度线程争抢。
#[tokio::main(worker_threads = 2)]
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

/// 只读 Supervisor 运行期健康检查循环写的心跳文件（见 health::heartbeat），
/// 不再自己发起一次完整的 SOCKS→隧道探测——那条隧道本来就已经在被
/// Supervisor 自己的循环真实探测，这里重复探测只是白白多打一次流量、多一
/// 处要和内部超时预算保持同步的地方。阈值判定同样完全在 Supervisor 那边，
/// 这里只是把它的最新结果转成 Docker HEALTHCHECK 的退出码。
async fn run_healthcheck() -> Result<()> {
    let config = AppConfig::from_env();
    // 心跳最坏多久没更新一次：运行期循环每 healthcheck_interval 探测一次，
    // 一次探测最坏能拖到 healthcheck_probe_timeout（隧道自愈重连的完整预
    // 算），二者相加再留 10 秒余量，避免自愈还没跑完就被判成"心跳过期"。
    let max_age = config.healthcheck_interval
        + config.healthcheck_probe_timeout
        + std::time::Duration::from_secs(10);
    match heartbeat::check(max_age) {
        Ok(()) => Ok(()),
        Err(reason) => {
            eprintln!("healthcheck 不健康: {reason}");
            std::process::exit(1);
        }
    }
}
