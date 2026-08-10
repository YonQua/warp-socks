# WireGuard 失联恢复落地方案

## 目标

在不改动 MASQUE 协议路径的前提下，修正 WireGuard transport 与 smoltcp
之间的背压语义，固定包含 keepalive/rekey 修正的 BoringTun 版本，缩短
高吞吐后数据面失联的恢复时间，并保证同一 peer 始终只有一个活动 generation。

本方案修复的是项目可控的恢复边界，不声称修复 Cloudflare WARP peer 或 BoringTun
内部产生 `REKEY_TIMEOUT` 的原因。

## 已验证事实

- 独立 WireGuard peer 在多个 Cloudflare endpoint 和 UDP 端口上均概率性复现失联。
- 某一历史故障窗口中容器未发生 OOM、CPU throttling 或 reactor panic；namespace
  累计 `RcvbufErrors` 不能归因到当前 generation，因此必须使用每代指标继续验证。
- 失联后已认证回包停止，随后出现 `HANDSHAKE(REKEY_TIMEOUT)`；重新握手可恢复。
- `WgOutbound::recover()` 已使用 `Mutex<RecoveryCtx>` 串行重建，天然满足 single-flight。
- 新 `Net` 通过 `RwLock` 原子替换，随后立即 shutdown 旧 `Arc<Reactor>`；同一
  WireGuard peer 不能让两个 outer UDP socket 同时排空，否则 endpoint roaming 会
  让新旧 generation 互相抢占。

## 第一性原理状态模型

只保留以下数据面事实，不再增加一套可漂移的健康状态机：

1. 当前代际最后一次发送隧道内业务 IP 包的时间。
2. 当前代际最后一次收到 BoringTun 验证并解密出的业务 IP 包的顺序。
3. 第一笔尚未等到后续认证回包的业务发送时间；后续发送不会重置这段等待。

以下条件定义统一的“认证数据面失联”信号：

- 当前代际确实发送过业务包；
- 最后发送时间晚于最后接收时间，说明发送后没有新回包；
- 第一笔尚未收到后续认证回包的业务发送已经等待至少 10 秒。

10 秒与项目 TCP 拨号超时一致。transport 只在该信号成立、近期业务 TX 仍持续，
且 outer UDP RX 也同期静默时重绑 socket；Supervisor 仍只在真实 SOCKS 探测失败后
才允许替换 endpoint generation。普通空闲隧道不会触发任何恢复。

## 实现边界

### 1. `src/tunnel.rs`

- 新增轻量 `TunnelActivity`，以单调时钟、事件序号和原子毫秒时间戳记录业务 TX/RX。
- transport 成功加密并写入 outer UDP 后记录 TX。
- `decapsulate` 返回 `WriteToTunnelV4/V6` 时记录已认证 RX。
- 握手、keepalive、cookie 等控制包不计入业务活性，避免控制流量掩盖数据面失联。
- BoringTun、outer UDP 和 timer 由单 transport task 持有；smoltcp 发包使用
  1024 包有界背压，解密队列满时丢包并计数，不让下游拥塞停止 outer UDP 读取和 timer。
- outer UDP 申请 4 MiB 收发缓冲并记录内核实际值；接收每轮最多批处理 64 包，
  然后返回公平调度点。
- 每代记录 outer RX/TX 包数、outer RX 静默时间和 netstack RX 丢包数；只用
  generation 内指标辅助归因，不用 namespace 累计值冒充当次故障证据。
- 每代分配仅用于日志关联的进程内 generation id。业务 TX 连续 10 秒没有已认证
  RX 时输出一次诊断快照，持续停滞每 10 秒至多追加一次；同代恢复时记录总停滞时间。
- 若近期业务 TX 持续发生，且认证 RX 与 outer UDP RX 都静默 10 秒，
  在 30 秒冷却约束下重绑同 endpoint UDP socket 并强制重握手。只有握手包
  写入新 socket 后才替换旧 socket，保留 BoringTun 状态机实例与 smoltcp generation，
  session/key 由 BoringTun 正常轮换。
- 提供纯函数式失联与状态边沿判定，单元测试不依赖真实等待。

### 2. `src/netstack.rs`

- smoltcp 产生的有限 packet 批次使用 `feed + flush`，不再使用会对有限
  Stream 调用 `poll_close` 的 `forward`。
- `DeviceCapabilities::max_burst_size` 声明为 100，与项目 packet device 的真实批处理边界一致。
- 确定性测试验证每个发送批次不会关闭长寿命 packet sink。

### 3. `src/outbound/wireguard.rs`

- 当前代际由 `Net` 与对应 `TunnelActivity` 组成，放在同一把 `RwLock` 内原子替换。
- `connect_tcp`、`connect_udp` 和域名解析始终从同一代际读取网络栈。
- `recover()` 继续复用现有单飞、endpoint 冷却和构建逻辑。
- generation id 只供诊断日志关联，不参与生命周期或恢复决策；不新增后台清理任务或
  连接 registry，旧代际仍由显式 shutdown 一次性终止。

### 4. `src/outbound/mod.rs` 与 `src/supervisor.rs`

- `Outbound::recover(mode)` 同时封装“是否需要”和“如何恢复”；默认返回 `NotNeeded`。
- MASQUE 不覆盖该方法，仍由连接路径内部重连。
- Supervisor 只选择 `Opportunistic` 或 `Forced` 并负责复测；WireGuard 明确失联时可在首次失败后重建。
- netstack reactor 已停止属于确定性硬故障，首次真实探测失败后立即重建。
- 提前重建或复测失败只继续累计原阈值；达到阈值仍退出，由 Docker 重启兜底。

## 并发与故障语义

- 重建网络 I/O 仍由 `recovery_ctx` 锁串行化，不允许并发建立多个新代际。
- 新代际完成握手和 netstack 初始化后才写锁替换；构建失败不污染当前 `Net`。
- 业务连接只克隆不可变 generation 快照，DNS 和拨号期间不持锁；写锁只覆盖
  generation 的内存替换与旧代际 shutdown。
- 旧连接不迁移。TCP 连接迁移不属于 TCP/WireGuard 可安全提供的语义；切换后旧代际立即
  停止，客户端重试后使用新代际。
- endpoint 状态文件写入失败只告警，不回滚已成功的内存切换。

## 验证矩阵

### 单元与静态检查

- 无发送、只有接收、收包仍新鲜：不得提前恢复。
- 发送晚于接收但未超过阈值：不得提前恢复。
- 发送晚于接收且已认证 RX 超时：请求提前恢复。
- 新 RX 到达后立即清除失联判定。
- stall 进入、限频持续和同代恢复事件均由纯状态机确定性测试覆盖。
- `cargo fmt --all -- --check`
- `cargo check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `docker compose config --quiet`
- `git diff --check`

### Docker 验收

- WireGuard TCP4、TCP6、域名和 UDP4/UDP6 基础能力保持通过。
- 使用独立 peer 执行 8 路并发持续流，观察失联窗口。
- 失联时必须先出现真实 SOCKS 探测失败和活性证据，再触发 endpoint 重建。
- 新连接应在新代际完成后恢复；旧连接允许由客户端重试，不承诺跨代际迁移。
- 容器不应因一次可恢复失联而重启；重建持续失败达到阈值时仍必须退出。
- 切回 MASQUE 后做一次 TCP4/TCP6 与 fail-closed UDP 冒烟，确认行为未变。

## 上线与回滚

1. 用固定镜像 tag 构建，不覆盖 `latest`。
2. 先用独立账号和备用端口验证，再替换正式容器。
3. 保留旧镜像 digest、Compose 和账户文件。
4. 若提前恢复出现误触发，只需回滚镜像；账户、endpoint 状态和协议配置无需迁移。
5. 若新代际建立失败，现有失败阈值与 Docker restart policy 仍是最终兜底。
