// 运行时环境变量解析，对应 lib/app/env.sh + normalize_runtime_tuning。

use std::path::PathBuf;
use std::time::Duration;

use crate::tunnel::Trick;

// 健康探测是运维策略，不应反向依赖某个 Outbound 的私有协议预算。63 秒保持
// 现有默认行为，并覆盖当前两种后端各自有界的 connect_tcp 实现。
const HEALTHCHECK_PROBE_TIMEOUT_DEFAULT: u64 = 63;

pub struct AppConfig {
    pub state_dir: PathBuf,
    pub wg_conf: PathBuf,
    pub account_json: PathBuf,
    pub endpoint_state_file: PathBuf,
    pub reg_json: PathBuf,

    pub teams_token: String,
    pub endpoint_candidates: String,
    pub enable_masque: bool,
    pub trick: Trick,

    /// `auto` 自动监听 IPv4/IPv6 并只允许 LAN 客户端；也可配置逗号分隔的
    /// 显式监听地址，此时第一个地址同时作为内部健康探测入口。
    pub listen_addrs: String,
    pub listen_port: u16,

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
        let state_dir = PathBuf::from(env_var("WARP_SOCKS_STATE_DIR", "/etc/warp-socks"));
        Self {
            wg_conf: state_dir.join("wg0.conf"),
            account_json: state_dir.join("account.json"),
            endpoint_state_file: state_dir.join("endpoint-state.json"),
            reg_json: state_dir.join("reg.json"),
            state_dir,

            teams_token: env_var("TEAMS_TOKEN", ""),
            endpoint_candidates: env_var("ENDPOINT_CANDIDATES", ""),
            enable_masque: is_true(&env_var("WARP_SOCKS_ENABLE_MASQUE", "1")),
            trick: match env_var("WARP_RS_TRICK", "none").as_str() {
                "t1" => Trick::T1,
                "t2" => Trick::T2,
                _ => Trick::None,
            },

            listen_addrs: env_var("SOCKS_LISTEN_ADDRS", "auto"),
            listen_port: sanitize_port(&env_var("SOCKS_LISTEN_PORT", "1080"), 1080),

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
            // 探测走真实业务路径；这个总预算是运维层可配置边界，后端内部
            // 的拨号/重连预算由各自 connect_tcp 实现负责。
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

fn sanitize_port(raw: &str, fallback: u16) -> u16 {
    match raw.trim().parse::<u16>() {
        Ok(port) if port != 0 => port,
        _ => fallback,
    }
}
