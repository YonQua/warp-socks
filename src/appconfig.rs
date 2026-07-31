// 运行时环境变量解析，对应 lib/app/env.sh + normalize_runtime_tuning。
// WG_DIR/LISTEN_ADDR 等固定路径未做成环境变量——shell 版本里它们也不是
// `${VAR:-default}` 形式的可覆盖项，是写死的常量。

use std::path::PathBuf;
use std::time::Duration;

use crate::relay;
use crate::tunnel::Trick;

// 健康检查探测内部就是走 relay::connect()（同一条业务连接路径），这里在它
// 的超时基础上再留 5 秒余量，避免探测自己的超时比它调用的 connect() 更没
// 耐心。从 relay::CONNECT_TIMEOUT 派生而不是独立手抄一个数字，链路只有一
// 个源头（masque::CONNECT_STREAM_TIMEOUT），逐层派生、逐层加一点余量。
const HEALTHCHECK_PROBE_TIMEOUT_DEFAULT: u64 = relay::CONNECT_TIMEOUT.as_secs() + 5;

pub struct AppConfig {
    pub wg_dir: PathBuf,
    pub wg_conf: PathBuf,
    pub account_json: PathBuf,
    pub endpoint_state_file: PathBuf,
    pub reg_json: PathBuf,

    pub teams_token: String,
    pub endpoint_candidates: String,
    pub enable_masque: bool,
    pub trick: Trick,

    pub listen_port: u16,
    /// 仅用于启动日志，帮助区分"宿主机入口"与"容器内监听"。
    pub host_bind_display: String,

    pub register_retries: u32,
    pub register_retry_delay: Duration,
    pub startup_probe_delay: Duration,
    pub startup_probe_timeout: Duration,
    pub startup_ready_timeout: Duration,
    /// 启动阶段候选失败后的冷却时长；对应 env.sh 里写死的 STARTUP_ENDPOINT_COOLDOWN_SECONDS=30。
    pub startup_endpoint_cooldown: Duration,
    pub healthcheck_probe_timeout: Duration,
    pub healthcheck_failure_threshold: u32,
    /// 运行期健康检查轮询间隔；对应此前 Dockerfile HEALTHCHECK --interval=30s。
    pub healthcheck_interval: Duration,
    /// 运行期健康检查触发退出时对当前 endpoint 打的冷却时长；对应
    /// env.sh: RUNTIME_ENDPOINT_COOLDOWN_SECONDS_DEFAULT=60。
    pub runtime_endpoint_cooldown: Duration,
}

impl AppConfig {
    #[must_use]
    pub fn from_env() -> Self {
        let wg_dir = PathBuf::from("/etc/wireguard");
        Self {
            wg_conf: wg_dir.join("wg0.conf"),
            account_json: wg_dir.join("account.json"),
            endpoint_state_file: wg_dir.join("endpoint-state.json"),
            reg_json: wg_dir.join("reg.json"),
            wg_dir,

            teams_token: env_var("TEAMS_TOKEN", ""),
            endpoint_candidates: env_var("ENDPOINT_CANDIDATES", ""),
            enable_masque: is_true(&env_var("WARP_SOCKS_ENABLE_MASQUE", "0")),
            trick: match env_var("WARP_RS_TRICK", "none").as_str() {
                "t1" => Trick::T1,
                "t2" => Trick::T2,
                _ => Trick::None,
            },

            listen_port: 1080,
            host_bind_display: format!(
                "{}:{}",
                env_var("HOST_BIND_IP", "127.0.0.1"),
                env_var("HOST_BIND_PORT", "1080")
            ),

            register_retries: sanitize_positive_int(
                &env_var("WARP_SOCKS_REGISTER_RETRIES", "2"),
                2,
            ),
            register_retry_delay: Duration::from_secs(sanitize_nonnegative_int(
                &env_var("WARP_SOCKS_REGISTER_RETRY_DELAY", "2"),
                2,
            )),
            startup_probe_delay: Duration::from_secs(sanitize_nonnegative_int(
                &env_var("WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY", "1"),
                1,
            )),
            startup_probe_timeout: Duration::from_secs(u64::from(sanitize_positive_int(
                &env_var("WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT", "5"),
                5,
            ))),
            startup_ready_timeout: Duration::from_secs(u64::from(sanitize_positive_int(
                &env_var("WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT", "20"),
                20,
            ))),
            startup_endpoint_cooldown: Duration::from_secs(30),
            // 探测走跟真实业务连接相同的路径，隧道拥塞时的自愈重连也会在这
            // 次探测里自然发生——前提是这里给的时间够长；短于它会导致探测
            // 在自愈跑完前就先报超时，把可自愈的拥塞误判成"连续失败"进而
            // 触发整进程重启。默认值从 HEALTHCHECK_PROBE_TIMEOUT_DEFAULT 派
            // 生（见上方常量及其注释里的完整链路），不再是独立手抄的数字。
            healthcheck_probe_timeout: Duration::from_secs(u64::from(sanitize_positive_int(
                &env_var(
                    "WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT",
                    &HEALTHCHECK_PROBE_TIMEOUT_DEFAULT.to_string(),
                ),
                HEALTHCHECK_PROBE_TIMEOUT_DEFAULT as u32,
            ))),
            healthcheck_failure_threshold: sanitize_positive_int(
                &env_var("WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD", "3"),
                3,
            ),
            healthcheck_interval: Duration::from_secs(30),
            runtime_endpoint_cooldown: Duration::from_secs(60),
        }
    }
}

fn env_var(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn is_true(raw: &str) -> bool {
    matches!(raw, "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
}

/// 对应 lib/core/utils.sh: sanitize_positive_int —— 非正整数一律回退到默认值。
fn sanitize_positive_int(raw: &str, fallback: u32) -> u32 {
    match raw.trim().parse::<u32>() {
        Ok(v) if v > 0 => v,
        _ => fallback,
    }
}

/// 对应 lib/core/utils.sh: sanitize_nonnegative_int —— 允许 0，非法输入回退默认值。
fn sanitize_nonnegative_int(raw: &str, fallback: u64) -> u64 {
    raw.trim().parse::<u64>().unwrap_or(fallback)
}
