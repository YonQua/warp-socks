// 长驻进程编排：账户/MASQUE 注册 → （优先）MASQUE 隧道 → WireGuard endpoint
// 候选依次尝试（进程内直接换下一个，不再像旧 shell 那样每个候选 spawn 一次
// 子进程）→ 起 SOCKS5 服务 → 内部健康检查按后端阈值决定是否退出。
//
// 对应 lib/app/main.sh + lib/runtime/tunnel.sh + lib/runtime/recovery.sh 的编排部分。

use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use log::{info, warn};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::appconfig::AppConfig;
use crate::endpoint::{candidate_pool, plan_candidates, JsonFileEndpointStore};
use crate::health::{heartbeat, RecoveryAction, SocksTraceProbe, ThresholdRecovery};
use crate::mixed;
use crate::outbound::{Masque, Outbound, WgOutbound};
use crate::registration::{self, TeamsRegistrar, WgAccount};

const WG_HEALTH_FAILURE_THRESHOLD: u32 = 1;

pub struct Supervisor {
    config: AppConfig,
}

struct RunningProxy {
    serve_handle: Option<JoinHandle<Result<()>>>,
    probe_addr: std::net::SocketAddr,
    backend: &'static str,
    failure_threshold: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeExit {
    Shutdown,
    Unhealthy,
}

impl RunningProxy {
    fn into_parts(
        mut self,
    ) -> (
        JoinHandle<Result<()>>,
        std::net::SocketAddr,
        &'static str,
        u32,
    ) {
        (
            self.serve_handle
                .take()
                .expect("RunningProxy 必须持有监听任务"),
            self.probe_addr,
            self.backend,
            self.failure_threshold,
        )
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        if let Some(handle) = self.serve_handle.take() {
            handle.abort();
        }
    }
}

impl Supervisor {
    #[must_use]
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// # Errors
    /// 必要的注册/配置步骤失败、或所有 endpoint 候选均无法就绪时返回错误
    /// （调用方应以非零退出码结束进程，交给 Docker `restart: unless-stopped` 重启）。
    pub async fn run(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config.state_dir)
            .with_context(|| format!("创建 {} 失败", self.config.state_dir.display()))?;

        info!(
            "启动调优参数: register_retries={}, register_retry_delay={:?}, startup_ready_timeout={:?}, \
             startup_probe_delay={:?}, startup_probe_timeout={:?}, healthcheck_probe_timeout={:?}, \
             healthcheck_interval={:?}, healthcheck_failure_threshold={}",
            self.config.register_retries,
            self.config.register_retry_delay,
            self.config.startup_ready_timeout,
            self.config.startup_probe_delay,
            self.config.startup_probe_timeout,
            self.config.healthcheck_probe_timeout,
            self.config.healthcheck_interval,
            self.config.healthcheck_failure_threshold,
        );

        if self.config.enable_masque {
            match self.try_masque().await {
                Ok(proxy) => {
                    info!("✓ MASQUE 隧道已建立（{}）", self.config.reg_json.display());
                    return match self.serve_and_watch(proxy).await? {
                        RuntimeExit::Shutdown => Ok(()),
                        RuntimeExit::Unhealthy => {
                            bail!("MASQUE 端到端探测失败，退出并重新选择后端与路径。")
                        }
                    };
                }
                Err(reason) => warn!("MASQUE 不可用（{reason}），回退 WireGuard ..."),
            }
        }

        self.run_wireguard().await
    }

    /// WireGuard 出网策略：确保 Teams 账户存在（这是唯一会要求 `TEAMS_TOKEN`
    /// 的地方——只有真正跑到这里才需要）、按候选顺序依次尝试 endpoint。
    async fn run_wireguard(&self) -> Result<()> {
        let account = self.ensure_account().await?;

        let mut store = JsonFileEndpointStore::load(&self.config.endpoint_state_file)?;
        let candidates = plan_candidates(candidate_pool(&self.config.endpoint_candidates), &store);
        if candidates.is_empty() {
            bail!("未生成任何可用 endpoint 候选。");
        }
        log_candidate_plan(&candidates, &store);

        let total = candidates.len();
        for (index, endpoint) in candidates.iter().enumerate() {
            match self.try_wg_candidate(&account, endpoint).await {
                Ok(proxy) => {
                    store.record_success(endpoint)?;
                    info!("隧道与 SOCKS 已就绪：endpoint={endpoint}");
                    return match self.serve_and_watch(proxy).await? {
                        RuntimeExit::Shutdown => Ok(()),
                        RuntimeExit::Unhealthy => {
                            if let Err(error) =
                                store.mark_cooldown(endpoint, self.config.startup_endpoint_cooldown)
                            {
                                warn!("记录失效 endpoint 冷却失败: endpoint={endpoint}, error={error:#}");
                            }
                            bail!("WireGuard 端到端探测失败，当前 endpoint 已降级，退出并选择下一候选。")
                        }
                    };
                }
                Err(reason) => {
                    warn!("候选 {endpoint} 就绪失败: {reason}");
                    store.mark_cooldown(endpoint, self.config.startup_endpoint_cooldown)?;
                    if index + 1 < total {
                        warn!(
                            "切换到候选 {}/{}: {}。",
                            index + 2,
                            total,
                            candidates[index + 1]
                        );
                    }
                }
            }
        }

        bail!("启动阶段出口探测失败，退出等待容器重启。");
    }

    async fn ensure_account(&self) -> Result<WgAccount> {
        if self.config.account_json.is_file() {
            info!("检测到已有 Teams 账户，跳过重新注册。");
            return WgAccount::load(&self.config.account_json);
        }

        if self.config.teams_token.trim().is_empty() {
            bail!("首次启动或重建状态时必须提供 TEAMS_TOKEN。");
        }
        let registrar = TeamsRegistrar {
            token: self.config.teams_token.clone(),
            account_path: self.config.account_json.clone(),
            retries: self.config.register_retries,
            retry_delay: self.config.register_retry_delay,
        };
        registrar.register().await
    }

    /// MASQUE 出网策略：确保 `reg.json` 存在（缺失则自动注册）、加载凭据、建立
    /// 隧道并起 SOCKS5 监听。调用前提是 `self.config.enable_masque == true`；
    /// 任何一步失败都统一在这里汇总成一个原因，交给调用方决定是否回退。
    async fn try_masque(&self) -> Result<RunningProxy, String> {
        if self.config.reg_json.is_file() {
            info!(
                "检测到已有 MASQUE 注册（{}），跳过重新注册。",
                self.config.reg_json.display()
            );
        } else {
            info!(
                "MASQUE 已开启且 {} 不存在，开始自动注册...",
                self.config.reg_json.display()
            );
            let creds = registration::register_masque()
                .await
                .map_err(|e| format!("MASQUE 注册失败（{e:#}）"))?;
            creds
                .registration
                .save(&self.config.reg_json)
                .map_err(|e| format!("MASQUE 注册信息保存失败（{e}）"))?;
            crate::fsutil::restrict_to_owner(&self.config.reg_json);
            info!("MASQUE 注册完成：{}", self.config.reg_json.display());
        }

        let creds = registration::load(&self.config.reg_json)
            .map_err(|e| format!("加载 {} 失败（{e}）", self.config.reg_json.display()))?;
        let masque = Masque::new(creds)
            .await
            .map_err(|e| format!("MASQUE 建立失败（{e:#}）"))?;
        let outbound: Arc<dyn Outbound> = Arc::new(masque);
        let proxy = self
            .spawn_and_probe(outbound, self.config.healthcheck_failure_threshold)
            .await
            .map_err(|e| format!("{e:#}"))?;
        Ok(proxy)
    }

    /// 用给定 endpoint 建立 WireGuard 隧道 + 起 SOCKS5 监听；只有端到端
    /// 出口探测通过后才把配置写成 `wg0.conf` 审计快照。
    async fn try_wg_candidate(&self, account: &WgAccount, endpoint: &str) -> Result<RunningProxy> {
        let wg_config = registration::build_wg_config(account, Some(endpoint))?;
        let outbound = Arc::new(
            WgOutbound::establish(
                &wg_config,
                self.config.trick,
                self.config.startup_probe_timeout,
            )
            .await
            .context("建立 WireGuard 隧道失败")?,
        );
        let proxy = self
            .spawn_and_probe(outbound, WG_HEALTH_FAILURE_THRESHOLD)
            .await?;
        registration::write_wg_conf(&wg_config, &self.config.wg_conf)
            .context("写入已验证的 WireGuard 配置快照失败")?;
        Ok(proxy)
    }

    /// 起 SOCKS5 监听并反复探测直到就绪或启动预算耗尽；失败时监听任务会被中止。
    async fn spawn_and_probe(
        &self,
        outbound: Arc<dyn Outbound>,
        failure_threshold: u32,
    ) -> Result<RunningProxy> {
        let (listen_mode, probe_addr) =
            parse_listen_mode(&self.config.listen_addrs, self.config.listen_port)?;
        let backend = outbound.name();
        let serve_handle = tokio::spawn(mixed::serve(outbound, listen_mode));

        let probe = SocksTraceProbe::new(probe_addr, self.config.startup_probe_timeout);
        let deadline = Instant::now() + self.config.startup_ready_timeout;

        loop {
            if serve_handle.is_finished() {
                let err = match serve_handle.await {
                    Ok(Ok(())) => anyhow::anyhow!("SOCKS5 服务提前退出。"),
                    Ok(Err(e)) => e.context("SOCKS5 服务提前退出"),
                    Err(e) => anyhow::anyhow!("SOCKS5 服务任务异常终止: {e}"),
                };
                return Err(err);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                serve_handle.abort();
                bail!("启动探测超时。");
            }

            match probe.probe().await {
                Ok(outcome) => {
                    if let Some(ip) = outcome.ip {
                        info!("当前出口 IP: {ip}");
                    }
                    return Ok(RunningProxy {
                        serve_handle: Some(serve_handle),
                        probe_addr,
                        backend,
                        failure_threshold,
                    });
                }
                Err(_) => {
                    sleep(self.config.startup_probe_delay.min(remaining)).await;
                }
            }
        }
    }

    /// 提供服务并跑内部健康检查循环。达到当前后端的连续失败阈值后退出；
    /// WireGuard 阈值固定为一次，确保半死 TCP 随进程一起释放。
    async fn serve_and_watch(&self, proxy: RunningProxy) -> Result<RuntimeExit> {
        let (mut serve_handle, probe_addr, backend, failure_threshold) = proxy.into_parts();
        info!("代理监听模式: {}", self.config.listen_addrs);
        info!("内部健康探测入口: {probe_addr}");
        info!("隧道后端: {backend}");

        // spawn_and_probe 里已经跑过一次成功的就绪探测，这里直接记一次心跳，
        // 避免容器刚起来、第一轮 healthcheck_interval 还没到时，Docker
        // HEALTHCHECK 读不到任何心跳而误判成不健康（见 heartbeat.rs 注释）。
        heartbeat::record_success();

        // 探测走的是跟真实业务连接完全相同的路径（SOCKS5 -> outbound），隧道
        // 一时拥塞导致的自愈重连（如 masque::open() 内部换 QUIC 连接）也会在
        // 这次探测里自然发生——前提是 healthcheck_probe_timeout 给得够长，
        // 详见 appconfig.rs 里该字段默认值的注释。
        let probe = SocksTraceProbe::new(probe_addr, self.config.healthcheck_probe_timeout);
        let mut recovery = ThresholdRecovery::new(failure_threshold);
        let mut shutdown = Box::pin(shutdown_signal());

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("收到退出信号，正在停止隧道/SOCKS5。");
                    serve_handle.abort();
                    return Ok(RuntimeExit::Shutdown);
                }
                result = &mut serve_handle => {
                    return match result {
                        Ok(Ok(())) => bail!("SOCKS5 服务提前退出。"),
                        Ok(Err(e)) => Err(e.context("SOCKS5 服务提前退出")),
                        Err(e) => bail!("SOCKS5 服务任务异常终止: {e}"),
                    };
                }
                () = sleep(self.config.healthcheck_interval) => {
                    match probe.probe().await {
                        Ok(_) => {
                            heartbeat::record_success();
                            recovery.on_success();
                        }
                        Err(e) => {
                            let action = recovery.on_failure();
                            warn!(
                                "SOCKS 出口探测失败: {e}; failures={}/{}",
                                recovery.consecutive_failures(),
                                failure_threshold
                            );
                            if action == RecoveryAction::RequestExit {
                                serve_handle.abort();
                                return Ok(RuntimeExit::Unhealthy);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn parse_listen_mode(raw: &str, port: u16) -> Result<(mixed::ListenMode, std::net::SocketAddr)> {
    if raw.trim().eq_ignore_ascii_case("auto") {
        return Ok((
            mixed::ListenMode::Auto { port },
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        ));
    }
    let addrs = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("SOCKS_LISTEN_ADDRS 包含非法地址: {value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if addrs.is_empty() {
        bail!("SOCKS_LISTEN_ADDRS 至少需要一个监听地址");
    }
    let probe_addr = addrs[0];
    Ok((mixed::ListenMode::Explicit(addrs), probe_addr))
}

fn log_candidate_plan(candidates: &[String], store: &JsonFileEndpointStore) {
    info!("endpoint 候选，共 {} 个。", candidates.len());
    if let Some(last_good) = store.last_good() {
        info!("最近成功 endpoint: {last_good}");
    }
    let cooling = candidates
        .iter()
        .filter(|ep| store.is_cooling_down(ep))
        .count();
    if cooling > 0 {
        info!("当前有 {cooling} 个 endpoint 处于冷却，会排到候选列表后部。");
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("安装 SIGTERM handler 失败");
    let mut int = signal(SignalKind::interrupt()).expect("安装 SIGINT handler 失败");
    let mut hup = signal(SignalKind::hangup()).expect("安装 SIGHUP handler 失败");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
        _ = hup.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_uncommitted_proxy_aborts_listener_task() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let signal = DropSignal(Some(dropped_tx));
        let handle = tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<()>().await;
            Ok(())
        });
        let proxy = RunningProxy {
            serve_handle: Some(handle),
            probe_addr: "127.0.0.1:1080".parse().unwrap(),
            backend: "test",
            failure_threshold: 1,
        };

        drop(proxy);

        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("监听任务未被及时取消")
            .expect("监听任务未释放守卫");
    }

    #[test]
    fn parses_ipv4_and_ipv6_listeners() {
        let (mode, probe) = parse_listen_mode("127.0.0.1:1080, [2001:db8::10]:1080", 9999).unwrap();
        let mixed::ListenMode::Explicit(addrs) = mode else {
            panic!("应解析为显式监听模式");
        };
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv6());
        assert_eq!(probe, addrs[0]);
    }

    #[test]
    fn rejects_empty_or_invalid_listener_config() {
        assert!(parse_listen_mode(" , ", 1080).is_err());
        assert!(parse_listen_mode("192.0.2.10", 1080).is_err());
    }

    #[test]
    fn auto_mode_uses_loopback_for_health_probe() {
        let (mode, probe) = parse_listen_mode("AUTO", 2080).unwrap();
        assert!(matches!(mode, mixed::ListenMode::Auto { port: 2080 }));
        assert_eq!(probe, "127.0.0.1:2080".parse().unwrap());
    }
}
