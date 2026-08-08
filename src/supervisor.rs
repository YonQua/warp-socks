// 长驻进程编排：账户/MASQUE 注册 → （优先）MASQUE 隧道 → WireGuard endpoint
// 候选依次尝试（进程内直接换下一个，不再像旧 shell 那样每个候选 spawn 一次
// 子进程）→ 起 SOCKS5 服务 → 内部健康检查循环触发退出（由 Docker
// `restart: unless-stopped` 重新拉起容器）。
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
use crate::outbound::{Masque, Outbound, WgHealConfig, WgOutbound};
use crate::registration::{self, TeamsRegistrar, WgAccount};

pub struct Supervisor {
    config: AppConfig,
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
             healthcheck_failure_threshold={}",
            self.config.register_retries,
            self.config.register_retry_delay,
            self.config.startup_ready_timeout,
            self.config.startup_probe_delay,
            self.config.startup_probe_timeout,
            self.config.healthcheck_probe_timeout,
            self.config.healthcheck_failure_threshold,
        );

        if self.config.enable_masque {
            match self.try_masque().await {
                Ok((outbound, serve_handle)) => {
                    info!("✓ MASQUE 隧道已建立（{}）", self.config.reg_json.display());
                    return self.serve_and_watch(serve_handle, outbound).await;
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
        let pool = candidate_pool(&self.config.endpoint_candidates);
        let candidates = plan_candidates(pool.clone(), &store);
        if candidates.is_empty() {
            bail!("未生成任何可用 endpoint 候选。");
        }
        log_candidate_plan(&candidates, &store);

        let total = candidates.len();
        for (index, endpoint) in candidates.iter().enumerate() {
            match self.try_wg_candidate(&account, endpoint, &pool).await {
                Ok((outbound, serve_handle)) => {
                    store.record_success(endpoint)?;
                    info!("隧道与 SOCKS 已就绪：endpoint={endpoint}");
                    return self.serve_and_watch(serve_handle, outbound).await;
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
    async fn try_masque(&self) -> Result<(Arc<dyn Outbound>, JoinHandle<Result<()>>), String> {
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
        let serve_handle = self
            .spawn_and_probe(outbound.clone())
            .await
            .map_err(|e| format!("{e:#}"))?;
        Ok((outbound, serve_handle))
    }

    /// 用给定 endpoint 覆盖写 wg0.conf、建立 WireGuard 隧道 + 起 SOCKS5 监听。
    /// `pool` 是 `candidate_pool()` 的结果，交给 `WgOutbound` 保管，供运行期
    /// `Outbound::heal` 换候选时复用同一套排序规则。
    async fn try_wg_candidate(
        &self,
        account: &WgAccount,
        endpoint: &str,
        pool: &[String],
    ) -> Result<(Arc<dyn Outbound>, JoinHandle<Result<()>>)> {
        let heal_config = WgHealConfig {
            pool: pool.to_vec(),
            endpoint_state_file: self.config.endpoint_state_file.clone(),
            wg_conf_path: self.config.wg_conf.clone(),
            cooldown: self.config.runtime_endpoint_cooldown,
        };
        let outbound: Arc<dyn Outbound> = Arc::new(
            WgOutbound::establish(
                account,
                endpoint,
                self.config.trick,
                self.config.startup_probe_timeout,
                heal_config,
            )
            .await
            .context("建立 WireGuard 隧道失败")?,
        );
        let serve_handle = self.spawn_and_probe(outbound.clone()).await?;
        Ok((outbound, serve_handle))
    }

    /// 起 SOCKS5 监听并反复探测直到就绪或启动预算耗尽；失败时监听任务会被中止。
    async fn spawn_and_probe(&self, outbound: Arc<dyn Outbound>) -> Result<JoinHandle<Result<()>>> {
        let listen_addrs = parse_listen_addrs(&self.config.listen_addrs)?;
        let probe_addr = listen_addrs[0];
        let serve_handle = tokio::spawn(mixed::serve(outbound, listen_addrs));

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
                    return Ok(serve_handle);
                }
                Err(_) => {
                    sleep(self.config.startup_probe_delay.min(remaining)).await;
                }
            }
        }
    }

    /// 提供服务并跑内部健康检查循环。探测失败先尝试 `outbound.heal()` 自愈
    /// （是否支持、怎么自愈完全由后端自己决定，见 `Outbound::heal` 默认实现），
    /// 成功则这次探测失败不计入连续失败计数；自愈失败或不支持时按原有阈值
    /// 机制处理——连续失败达阈值退出进程交给 Docker 重启。
    async fn serve_and_watch(
        &self,
        mut serve_handle: JoinHandle<Result<()>>,
        outbound: Arc<dyn Outbound>,
    ) -> Result<()> {
        let backend = outbound.name();
        info!("代理监听地址: {}", self.config.listen_addrs);
        let probe_addr = parse_listen_addrs(&self.config.listen_addrs)?[0];
        info!("内部健康探测入口: {probe_addr}");
        info!("隧道后端: {backend}");

        // spawn_and_probe 里已经跑过一次成功的就绪探测，这里直接记一次心跳，
        // 避免容器刚起来、第一轮 healthcheck_interval 还没到时，Docker
        // HEALTHCHECK 读不到任何心跳而误判成不健康（见 heartbeat.rs 注释）。
        heartbeat::record(true);

        // 探测走的是跟真实业务连接完全相同的路径（SOCKS5 -> outbound），隧道
        // 一时拥塞导致的自愈重连（如 masque::open() 内部换 QUIC 连接）也会在
        // 这次探测里自然发生——前提是 healthcheck_probe_timeout 给得够长，
        // 详见 appconfig.rs 里该字段默认值的注释。
        let probe = SocksTraceProbe::new(probe_addr, self.config.healthcheck_probe_timeout);
        let mut recovery = ThresholdRecovery::new(self.config.healthcheck_failure_threshold);
        let mut shutdown = Box::pin(shutdown_signal());

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    info!("收到退出信号，正在停止隧道/SOCKS5。");
                    serve_handle.abort();
                    return Ok(());
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
                            heartbeat::record(true);
                            recovery.on_success();
                        }
                        Err(e) => {
                            heartbeat::record(false);
                            // 自愈是否可用完全由后端自己决定（`Outbound::heal` 默认
                            // 不支持）；MASQUE 的自愈已经在它自己的 connect_tcp 内部
                            // 发生，这里的探测失败即代表那次自愈也没能挽回，不需要
                            // 额外分支区分后端。
                            let healed = outbound.heal().await.is_ok() && probe.probe().await.is_ok();
                            if healed {
                                info!("{backend} 自愈成功，本次探测失败不计入连续失败计数。");
                                heartbeat::record(true);
                                recovery.on_success();
                                continue;
                            }
                            let action = recovery.on_failure(&e.to_string());
                            warn!(
                                "SOCKS 出口探测失败: {e}; failures={}/{}",
                                recovery.consecutive_failures(),
                                self.config.healthcheck_failure_threshold
                            );
                            if action == RecoveryAction::RequestExit {
                                serve_handle.abort();
                                bail!("连续失败达到阈值，退出等待容器重启。");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn parse_listen_addrs(raw: &str) -> Result<Vec<std::net::SocketAddr>> {
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
    Ok(addrs)
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

    #[test]
    fn parses_ipv4_and_ipv6_listeners() {
        let addrs = parse_listen_addrs("127.0.0.1:1080, [2001:db8::10]:1080").unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv6());
    }

    #[test]
    fn rejects_empty_or_invalid_listener_config() {
        assert!(parse_listen_addrs(" , ").is_err());
        assert!(parse_listen_addrs("192.0.2.10").is_err());
    }
}
