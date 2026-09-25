// 长驻进程编排：账户/MASQUE 注册 → （优先）MASQUE 隧道 → WireGuard endpoint
// 候选依次尝试（进程内直接换下一个，不再像旧 shell 那样每个候选 spawn 一次
// 子进程）→ 起 SOCKS5 服务 → 内部健康检查按后端阈值决定是否退出。
//
// 对应 lib/app/main.sh + lib/runtime/tunnel.sh + lib/runtime/recovery.sh 的编排部分。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use log::{info, warn};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::appconfig::AppConfig;
use crate::endpoint::{candidate_pool, plan_candidates, JsonFileEndpointStore};
use crate::health::{
    heartbeat, probe::probe_outbound, ProbeOutcome, RecoveryAction, SocksTraceProbe,
    ThresholdRecovery,
};
use crate::mixed;
use crate::outbound::{masque::MasqueH2, psiphon::Psiphon, Masque, Outbound, WgOutbound};
use crate::registration::{self, RegCredentials, TeamsRegistrar, WgAccount};

const WG_HEALTH_FAILURE_THRESHOLD: u32 = 1;

pub struct Supervisor {
    config: AppConfig,
}

struct RunningProxy {
    serve_handle: JoinHandle<Result<()>>,
    probe_addr: std::net::SocketAddr,
    backend: &'static str,
    failure_threshold: u32,
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
    /// 必要的注册/配置步骤失败、或所有 endpoint 候选均无法就绪时返回错误
    /// （调用方应以非零退出码结束进程，交给 Docker `restart: unless-stopped` 重启）。
    pub async fn run(&self) -> Result<()> {
        let (listen_mode, probe_addr) =
            parse_listen_mode(&self.config.listen_addrs, self.config.listen_port)?;
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
            result = self.run_service(listen_mode, probe_addr, psiphon_country.as_deref()) => result,
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
        probe_addr: SocketAddr,
        country: Option<&str>,
    ) -> Result<()> {
        let selected = self.prepare_base().await?;
        let failure_threshold = if country.is_some() || selected.wg_endpoint.is_none() {
            self.config.healthcheck_failure_threshold
        } else {
            WG_HEALTH_FAILURE_THRESHOLD
        };
        let outbound: Arc<dyn Outbound> = match country {
            Some(country) => {
                self.prepare_region(Arc::clone(&selected.outbound), country)
                    .await?
            }
            None => Arc::clone(&selected.outbound),
        };
        let (proxy, outcome) = self
            .spawn_and_probe(outbound, listen_mode, probe_addr, failure_threshold)
            .await?;
        if let Some(country) = country {
            info!(
                "Psiphon 前置已就绪: country={country}, Cloudflare 最终出口: IP={}, loc={}",
                outcome.ip.as_deref().unwrap_or("未知"),
                outcome.loc.as_deref().unwrap_or("未知"),
            );
        } else if let Some(ip) = outcome.ip {
            info!("当前出口 IP: {ip}");
        }
        self.serve_and_watch(proxy).await?;
        if country.is_none() {
            if let Some(endpoint) = &selected.wg_endpoint {
                let mut store = JsonFileEndpointStore::load(&self.config.endpoint_state_file)?;
                if let Err(error) =
                    store.mark_cooldown(endpoint, self.config.startup_endpoint_cooldown)
                {
                    warn!("记录失效 endpoint 冷却失败: endpoint={endpoint}, error={error:#}");
                }
            }
        }
        bail!("SOCKS 端到端探测失败，退出并重新选择后端与路径。")
    }

    async fn prepare_region(
        &self,
        base: Arc<dyn Outbound>,
        country: &str,
    ) -> Result<Arc<dyn Outbound>> {
        let creds = self.ensure_masque_credentials().await?;
        let candidates = Psiphon::candidates(base.as_ref(), country).await?;
        if candidates.is_empty() {
            bail!("所选地区没有可用 SSH 候选: {country}");
        }
        let mut last_error = None;
        for (index, entry) in candidates.into_iter().take(8).enumerate() {
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
                Ok(outbound) => return Ok(outbound),
                Err(error) => {
                    warn!(
                        "地区路径候选 {} 失败: country={country}, error={error:#}",
                        index + 1
                    );
                    last_error = Some(error);
                }
            }
        }
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
        bail!("启动阶段出口探测失败，退出等待容器重启。")
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
                        if let Some(ip) = outcome.ip {
                            info!("当前出口 IP: {ip}");
                        }
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

    /// 起唯一公开 SOCKS 入口；启动探测失败或取消时 Drop 会停止监听。
    async fn spawn_and_probe(
        &self,
        outbound: Arc<dyn Outbound>,
        listen_mode: mixed::ListenMode,
        probe_addr: SocketAddr,
        failure_threshold: u32,
    ) -> Result<(RunningProxy, ProbeOutcome)> {
        let backend = outbound.name();
        let mut proxy = RunningProxy {
            serve_handle: tokio::spawn(mixed::serve(outbound, listen_mode)),
            probe_addr,
            backend,
            failure_threshold,
        };
        let probe = SocksTraceProbe::new(probe_addr, self.config.startup_probe_timeout);
        let mut last_error = None;
        let outcome = tokio::time::timeout(self.config.startup_ready_timeout, async {
            loop {
                tokio::select! {
                    result = &mut proxy.serve_handle => return Err(listener_result(result)),
                    result = probe.probe() => {
                        match result {
                            Ok(outcome) => return Ok(outcome),
                            Err(error) => {
                                last_error = Some(error);
                                sleep(self.config.startup_probe_delay).await;
                            }
                        }
                    }
                }
            }
        })
        .await
        .map_err(|_| startup_probe_error("SOCKS 启动探测超时", last_error))??;
        Ok((proxy, outcome))
    }

    /// 运行期只探测唯一公开入口。`Ok(())` 仅表示连续失败达到阈值。
    async fn serve_and_watch(&self, mut proxy: RunningProxy) -> Result<()> {
        let (probe_addr, backend, failure_threshold) =
            (proxy.probe_addr, proxy.backend, proxy.failure_threshold);
        info!("代理监听模式: {}", self.config.listen_addrs);
        info!("内部健康探测入口: {probe_addr}");
        info!("隧道后端: {backend}");
        heartbeat::record_success();
        let probe = SocksTraceProbe::new(probe_addr, self.config.healthcheck_probe_timeout);
        let mut recovery = ThresholdRecovery::new(failure_threshold);
        loop {
            tokio::select! {
                result = &mut proxy.serve_handle => return Err(listener_result(result)),
                () = sleep(self.config.healthcheck_interval) => {
                    match probe.probe().await {
                        Ok(_) => {
                            heartbeat::record_success();
                            recovery.on_success();
                        }
                        Err(error) => {
                            let action = recovery.on_failure();
                            warn!(
                                "SOCKS 出口探测失败: {error}; failures={}/{}",
                                recovery.consecutive_failures(), failure_threshold
                            );
                            if action == RecoveryAction::RequestExit { return Ok(()); }
                        }
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
    let probe_addr = match addrs[0] {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
            SocketAddr::from(([127, 0, 0, 1], addr.port()))
        }
        SocketAddr::V6(addr) if addr.ip().is_unspecified() => {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], addr.port()))
        }
        addr => addr,
    };
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
