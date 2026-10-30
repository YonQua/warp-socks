// 长驻进程编排：账户/MASQUE 注册 → （优先）MASQUE 隧道 → WireGuard endpoint
// 候选依次尝试（进程内直接换下一个，不再像旧 shell 那样每个候选 spawn 一次
// 子进程）；常驻 SOCKS5 监听，内部健康检查按后端阈值触发出口重建。
//
// 对应 lib/app/main.sh + lib/runtime/tunnel.sh + lib/runtime/recovery.sh 的编排部分。

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use log::{info, warn};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::appconfig::AppConfig;
use crate::endpoint::{candidate_pool, plan_candidates, JsonFileEndpointStore};
use crate::health::{heartbeat, probe::probe_outbound, RecoveryAction, ThresholdRecovery};
use crate::mixed;
use crate::outbound::{masque::MasqueH2, psiphon::Psiphon, Masque, Outbound, WgOutbound};
use crate::registration::{self, RegCredentials, TeamsRegistrar, WgAccount};

const WG_HEALTH_FAILURE_THRESHOLD: u32 = 1;

pub struct Supervisor {
    config: AppConfig,
}

struct CachedCandidates {
    entries: Vec<crate::outbound::psiphon::server_list::ServerEntry>,
    fetched: std::time::Instant,
    preferred: Option<usize>,
}

struct RunningProxy {
    serve_handle: JoinHandle<Result<()>>,
}

struct SelectedWarp {
    outbound: Arc<dyn Outbound>,
    wg_endpoint: Option<String>,
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.serve_handle.abort();
    }
}

impl Supervisor {
    #[must_use]
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// # Errors
    /// 配置、监听或本地健康状态初始化失败时返回错误。
    /// 网络准备与出口故障由单一恢复循环处理，不关闭公共监听。
    pub async fn run(&self) -> Result<()> {
        let listen_mode = parse_listen_mode(&self.config.listen_addrs, self.config.listen_port)?;
        let psiphon_country = self.validate_psiphon_config()?;
        heartbeat::invalidate().context("重置启动健康状态失败")?;
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

        tokio::select! {
            result = self.run_service(listen_mode, psiphon_country.as_deref()) => result,
            signal = shutdown_signal() => {
                signal?;
                info!("收到退出信号，正在停止隧道/SOCKS5。");
                Ok(())
            }
        }
    }

    async fn run_service(
        &self,
        listen_mode: mixed::ListenMode,
        country: Option<&str>,
    ) -> Result<()> {
        let (state, receiver) = tokio::sync::watch::channel(None);
        let mut proxy = RunningProxy {
            serve_handle: tokio::spawn(mixed::serve_managed(receiver, listen_mode)),
        };
        // 监听是进程级资源，出口准备、运行和退避共用这一处监督。
        tokio::select! {
            result = &mut proxy.serve_handle => Err(listener_result(result)),
            result = self.recover_outbound(state, country) => result,
        }
    }

    async fn recover_outbound(
        &self,
        state: tokio::sync::watch::Sender<Option<Arc<dyn Outbound>>>,
        country: Option<&str>,
    ) -> Result<()> {
        let mut candidates = None;
        let mut failures = 0u32;
        loop {
            heartbeat::invalidate().context("重置恢复健康状态失败")?;
            let started = tokio::time::Instant::now();
            info!("出口准备开始: country={}", country.unwrap_or("none"));
            let prepare = async {
                let selected = self.prepare_base().await?;
                let outbound = match country {
                    Some(country) => {
                        self.prepare_region(
                            Arc::clone(&selected.outbound),
                            country,
                            &mut candidates,
                        )
                        .await?
                    }
                    None => Arc::clone(&selected.outbound),
                };
                Ok::<_, anyhow::Error>((selected, outbound))
            };
            let prepared = tokio::time::timeout(std::time::Duration::from_secs(120), prepare)
                .await
                .map_err(|error| {
                    candidates = None;
                    anyhow::Error::new(error).context("出口准备超过 120s 总预算")
                })
                .and_then(|result| result);
            match prepared {
                Ok((selected, outbound)) => {
                    let failure_threshold = if country.is_none() && selected.wg_endpoint.is_some() {
                        WG_HEALTH_FAILURE_THRESHOLD
                    } else {
                        self.config.healthcheck_failure_threshold
                    };
                    // prepare 已验证最终出口；先验证后发布，不让业务参与就绪判断。
                    state.send_replace(Some(Arc::clone(&outbound)));
                    failures = 0;
                    heartbeat::record_success();
                    info!(
                        "出口已就绪: backend={}, elapsed={:?}",
                        outbound.name(),
                        started.elapsed()
                    );
                    self.watch_outbound(
                        outbound.as_ref(),
                        country.map(|_| selected.outbound.as_ref()),
                        failure_threshold,
                    )
                    .await;
                    state.send_replace(None);
                    heartbeat::invalidate().context("重置恢复健康状态失败")?;
                    if country.is_none() {
                        if let Some(endpoint) = &selected.wg_endpoint {
                            let cooldown =
                                JsonFileEndpointStore::load(&self.config.endpoint_state_file)
                                    .and_then(|mut store| {
                                        store.mark_cooldown(
                                            endpoint,
                                            self.config.startup_endpoint_cooldown,
                                        )
                                    });
                            if let Err(error) = cooldown {
                                warn!("记录失效 endpoint 冷却失败: {error:#}");
                            }
                        }
                    }
                }
                Err(error) => warn!(
                    "出口准备失败: elapsed={:?}, error={error:#}",
                    started.elapsed()
                ),
            }
            failures = failures.saturating_add(1);
            let ceiling = 1u64 << failures.min(5);
            let delay = std::time::Duration::from_millis(rand::Rng::gen_range(
                &mut rand::thread_rng(),
                1000..=ceiling * 1000,
            ));
            warn!("出口恢复等待: failures={failures}, delay={delay:?}");
            sleep(delay).await;
        }
    }

    async fn prepare_region(
        &self,
        base: Arc<dyn Outbound>,
        country: &str,
        candidates: &mut Option<CachedCandidates>,
    ) -> Result<Arc<dyn Outbound>> {
        let creds = self.ensure_masque_credentials().await?;
        if candidates
            .as_ref()
            .is_none_or(|cache| cache.fetched.elapsed() >= std::time::Duration::from_secs(86400))
        {
            *candidates = Some(CachedCandidates {
                entries: Psiphon::candidates(base.as_ref(), country).await?,
                fetched: std::time::Instant::now(),
                preferred: None,
            });
        }
        let cache = candidates.as_mut().context("Psiphon 候选缓存未初始化")?;
        let mut order = (0..cache.entries.len()).collect::<Vec<_>>();
        use rand::seq::SliceRandom;
        order.shuffle(&mut rand::thread_rng());
        if let Some(preferred) = cache.preferred.take() {
            if let Some(index) = order.iter().position(|&index| index == preferred) {
                order.swap(0, index);
            }
        }
        let mut last_error = None;
        for (index, entry_index) in order.into_iter().take(8).enumerate() {
            let entry = cache.entries[entry_index].clone();
            let attempt = async {
                let ssh = tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    Psiphon::connect_entry(Arc::clone(&base), entry, country),
                )
                .await
                .context("Psiphon SSH 建立超时")??;
                let outbound: Arc<dyn Outbound> = Arc::new(
                    MasqueH2::new(&creds, Arc::new(ssh))
                        .await
                        .context("经 Psiphon 建立 MASQUE H2 失败")?,
                );
                self.wait_for_warp(outbound.as_ref()).await?;
                Ok::<_, anyhow::Error>(outbound)
            }
            .await;
            match attempt {
                Ok(outbound) => {
                    cache.preferred = Some(entry_index);
                    return Ok(outbound);
                }
                Err(error) => {
                    warn!(
                        "地区路径候选 {} 失败: country={country}, error={error:#}",
                        index + 1
                    );
                    last_error = Some(error);
                }
            }
        }
        *candidates = None;
        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("没有执行任何候选"))
            .context(format!("所选地区所有已尝试路径均不可用: {country}")))
    }

    async fn prepare_base(&self) -> Result<SelectedWarp> {
        if self.config.enable_masque {
            match self.try_masque().await {
                Ok(outbound) => {
                    info!("✓ MASQUE 隧道已建立（{}）", self.config.reg_json.display());
                    return Ok(SelectedWarp {
                        outbound,
                        wg_endpoint: None,
                    });
                }
                Err(reason) => warn!("MASQUE 不可用（{reason:#}），回退 WireGuard ..."),
            }
        }
        self.prepare_wireguard().await
    }

    async fn prepare_wireguard(&self) -> Result<SelectedWarp> {
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
                Ok(outbound) => {
                    store.record_success(endpoint)?;
                    info!("WireGuard 隧道已就绪：endpoint={endpoint}");
                    return Ok(SelectedWarp {
                        outbound,
                        wg_endpoint: Some(endpoint.clone()),
                    });
                }
                Err(reason) => {
                    warn!("候选 {endpoint} 就绪失败: {reason:#}");
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
        bail!("本轮出口候选探测均失败")
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

    async fn try_masque(&self) -> Result<Arc<dyn Outbound>> {
        let creds = self.ensure_masque_credentials().await?;
        let outbound: Arc<dyn Outbound> =
            Arc::new(Masque::new(creds).await.context("MASQUE 建立失败")?);
        self.wait_for_warp(&*outbound).await?;
        Ok(outbound)
    }

    async fn ensure_masque_credentials(&self) -> Result<RegCredentials> {
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
                .context("MASQUE 注册失败")?;
            creds
                .registration
                .save(&self.config.reg_json)
                .context("MASQUE 注册信息保存失败")?;
            info!("MASQUE 注册完成：{}", self.config.reg_json.display());
        }

        registration::load(&self.config.reg_json)
            .with_context(|| format!("加载 {} 失败", self.config.reg_json.display()))
    }

    /// 只把通过真实 WARP trace 的候选记录为成功。
    async fn try_wg_candidate(
        &self,
        account: &WgAccount,
        endpoint: &str,
    ) -> Result<Arc<dyn Outbound>> {
        let wg_config = registration::build_wg_config(account, Some(endpoint))?;
        let outbound: Arc<dyn Outbound> = Arc::new(
            WgOutbound::establish(
                &wg_config,
                self.config.trick,
                self.config.startup_probe_timeout,
            )
            .await
            .context("建立 WireGuard 隧道失败")?,
        );
        self.wait_for_warp(&*outbound).await?;
        registration::write_wg_conf(&wg_config, &self.config.wg_conf)
            .context("写入已验证的 WireGuard 配置快照失败")?;
        Ok(outbound)
    }

    async fn wait_for_warp(&self, outbound: &dyn Outbound) -> Result<()> {
        let mut last_error = None;
        tokio::time::timeout(self.config.startup_ready_timeout, async {
            loop {
                match probe_outbound(outbound, self.config.startup_probe_timeout).await {
                    Ok(outcome) => {
                        info!(
                            "出口验证成功: backend={}, IP={}, loc={}",
                            outbound.name(),
                            outcome.ip.as_deref().unwrap_or("unknown"),
                            outcome.loc.as_deref().unwrap_or("unknown")
                        );
                        return Ok(());
                    }
                    Err(error) => {
                        last_error = Some(error);
                        sleep(self.config.startup_probe_delay).await;
                    }
                }
            }
        })
        .await
        .map_err(|_| startup_probe_error("WARP 出口启动探测超时", last_error))?
    }

    fn validate_psiphon_config(&self) -> Result<Option<String>> {
        let country = self.config.psiphon_country.trim();
        if country.is_empty() {
            return Ok(None);
        }
        Ok(Some(crate::outbound::psiphon::normalize_country(country)?))
    }

    /// 仅判断出口是否需要重建；监听任务由 run_service 独立监督。
    async fn watch_outbound(
        &self,
        outbound: &dyn Outbound,
        base: Option<&dyn Outbound>,
        failure_threshold: u32,
    ) {
        let mut recovery = ThresholdRecovery::new(failure_threshold);
        let terminated = async {
            tokio::select! {
                reason = outbound.terminated() => format!("最终出站: {reason}"),
                reason = async {
                    match base {
                        Some(base) => base.terminated().await,
                        None => std::future::pending().await,
                    }
                } => format!("基础 WARP: {reason}"),
            }
        };
        tokio::pin!(terminated);
        loop {
            let outcome = tokio::select! {
                reason = &mut terminated => {
                    warn!("出站已终止，重建出口: {reason}");
                    return;
                }
                outcome = async {
                    sleep(self.config.healthcheck_interval).await;
                    probe_outbound(outbound, self.config.healthcheck_probe_timeout).await
                } => outcome,
            };
            match outcome {
                Ok(_) => {
                    heartbeat::record_success();
                    recovery.on_success();
                }
                Err(error) => {
                    let action = recovery.on_failure();
                    warn!(
                        "出口探测失败: {error}; failures={}/{}",
                        recovery.consecutive_failures(),
                        failure_threshold
                    );
                    if action == RecoveryAction::RequestExit {
                        return;
                    }
                }
            }
        }
    }
}

fn startup_probe_error(
    context: &str,
    last_error: Option<crate::health::ProbeError>,
) -> anyhow::Error {
    match last_error {
        Some(error) => anyhow::Error::new(error).context(context.to_owned()),
        None => anyhow::anyhow!("{context}，首次探测尚未完成"),
    }
}

fn listener_result(result: Result<Result<()>, tokio::task::JoinError>) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow::anyhow!("SOCKS5 服务提前退出。"),
        Ok(Err(error)) => error.context("SOCKS5 服务提前退出"),
        Err(error) => anyhow::anyhow!("SOCKS5 服务任务异常终止: {error}"),
    }
}

fn parse_listen_mode(raw: &str, port: u16) -> Result<mixed::ListenMode> {
    if raw.trim().eq_ignore_ascii_case("auto") {
        return Ok(mixed::ListenMode::Auto { port });
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
    Ok(mixed::ListenMode::Explicit(addrs))
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

async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).context("安装 SIGTERM handler 失败")?;
    let mut int = signal(SignalKind::interrupt()).context("安装 SIGINT handler 失败")?;
    let mut hup = signal(SignalKind::hangup()).context("安装 SIGHUP handler 失败")?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
        _ = hup.recv() => {}
    }
    Ok(())
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
            serve_handle: handle,
        };

        drop(proxy);

        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("监听任务未被及时取消")
            .expect("监听任务未释放守卫");
    }

    #[test]
    fn parses_ipv4_and_ipv6_listeners() {
        let mode = parse_listen_mode("127.0.0.1:1080, [2001:db8::10]:1080", 9999).unwrap();
        let mixed::ListenMode::Explicit(addrs) = mode else {
            panic!("应解析为显式监听模式");
        };
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv6());
    }

    #[test]
    fn rejects_empty_or_invalid_listener_config() {
        assert!(parse_listen_mode(" , ", 1080).is_err());
        assert!(parse_listen_mode("192.0.2.10", 1080).is_err());
    }

    #[test]
    fn parses_auto_mode() {
        let mode = parse_listen_mode("AUTO", 2080).unwrap();
        assert!(matches!(mode, mixed::ListenMode::Auto { port: 2080 }));
    }
}
