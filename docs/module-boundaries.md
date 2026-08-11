# 模块边界

这份文档描述当前 Rust 实现（`src/`）怎么组织，不讨论历史 shell 方案。

## 主链路

1. `WARP_SOCKS_ENABLE_MASQUE=1` 时优先尝试独立的 `reg.json`（MASQUE，见下方“状态文件”），成功则不需要 `TEAMS_TOKEN`/`account.json`
2. MASQUE 未开启，或开启但注册/建隧道失败需要回退时，才走 `TEAMS_TOKEN -> account.json`（首次注册，之后重启直接复用）-> `wg0.conf`（WireGuard 路径用）；`TEAMS_TOKEN` 只接受注册链接 `token=` 后面的原始三段 JWT，不接受 `token=` 本身、完整 URI 或引号
3. `Supervisor`（`src/supervisor.rs`）在进程内起隧道（`WARP_SOCKS_ENABLE_MASQUE=1` 时优先 MASQUE，失败或未开启则 userspace WireGuard）+ 内置 SOCKS5
4. 经 SOCKS5 出口探测通过（`warp=on`）后进入运行态
5. WireGuard 运行期真实 SOCKS trace 首次失败即冷却 endpoint、退出，并由 Docker 用全新隧道生命周期重新执行候选验证

说明：内核 `wg-quick` / `microsocks` 路径已废弃。中国等网络环境下，内核 WireGuard 常表现为 `0 B received`；带 WARP tricks 的 userspace 实现才能稳定握手。旧版 shell 编排（`lib/app/main.sh` 等按 endpoint 候选逐个拉起子进程）也已废弃，改为 `Supervisor` 在同一进程内完成候选尝试、SOCKS5 服务与健康检查，不再有子进程生命周期管理。

隧道、SOCKS5、注册、健康探测均由仓库根 `src/` 编译出的单一二进制 `warp-socks-rs` 提供（参考 bepass-org/warp-plus 思路重写，同一份 `wg0.conf` 格式、同样的 reserved bytes/trick 反审查机制），子命令为 `warp-socks [serve|register reg/del <path>|healthcheck]`（`src/bin/warp-socks.rs`）。日志用 `log`/`env_logger`（`RUST_LOG` 控制级别，默认 `info`，含隧道后端选择、连接建立/失败等关键信息）。

`Supervisor::run` 是一个纯粹的两分支调度：`WARP_SOCKS_ENABLE_MASQUE=1` 时先调用 `try_masque`（内部会在 `reg.json` 缺失时自动调用 `MasqueRegistrar::register` 生成，失败原因统一汇总成一个 `Err`），成功则直接提供服务；关闭或失败都会落到 `run_wireguard`。`ensure_account`（Teams 账户/`account.json`）只在 `run_wireguard` 里调用——MASQUE 开启且注册、建隧道都成功的场景全程不会要求 `TEAMS_TOKEN`；只有 MASQUE 未开启，或开启但失败需要回退 WireGuard 时，才会在缺少 `account.json` 且 `TEAMS_TOKEN` 为空时 `bail!` 退出等待重启。UDP ASSOCIATE 的数据报走隧道内 UDP 仅在 WireGuard 后端下支持；MASQUE 后端没有 CONNECT-UDP 能力，在回复 ASSOCIATE 前明确拒绝。项目不存在宿主机 UDP 直出路径。

## 状态文件

以下路径均相对状态目录。默认 compose.yaml 把宿主机 `./data` 挂载到容器内 `/etc/warp-socks`；原生运行可用 `WARP_SOCKS_STATE_DIR` 指向同一个 `data` 目录。这个目录同时保存 WireGuard 和 MASQUE 两套状态，见 `reg.json`。

- `data/account.json`
  - Teams 注册结果
  - 唯一账户状态来源
  - `config.client_id` base64 解码后取前 3 字节，作为运行配置的 reserved bytes，
    同时写入 `wg0.conf` 的 `Reserved =`

- `data/wg0.conf`
  - 由 `account.json` 和 endpoint 派生
  - 仅作为当前已通过端到端探测的运行配置快照；不参与运行期恢复决策

- `data/endpoint-state.json`
  - 只保存 `last_good_endpoint` 和 cooldown
  - 用于启动时候选重排（仅 WireGuard 路径，MASQUE 走固定边缘地址不涉及候选轮换）

- `data/reg.json`
  - MASQUE 路径的注册凭据（`WARP_SOCKS_ENABLE_MASQUE=1` 时使用）：设备 id/token、ECDSA 客户端密钥、边缘固定公钥等
  - 缺失时 `Supervisor::try_masque` 在进程内自动调用 `MasqueRegistrar::register` 生成
  - 与 `account.json`/`wg0.conf` 相互独立，WireGuard 路径不读写这个文件

## 源码模块职责

- `src/bin/warp-socks.rs`
  - 生产入口，子命令分发：`serve`（默认，起 `Supervisor`）/ `register reg|del` / `healthcheck`

- `src/appconfig.rs`
  - 环境变量解析、默认值、合法性兜底，供 `Supervisor` 和 `healthcheck` 子命令共用

- `src/supervisor.rs`
  - 进程内编排：账户确认、MASQUE 状态确保、endpoint 候选尝试（含冷却/切换）、SOCKS5 起服务与监督、运行期健康检查循环、优雅退出（SIGTERM/SIGINT/SIGHUP）
  - 取代旧版 `lib/app/main.sh` + `lib/runtime/tunnel.sh` + `lib/runtime/recovery.sh` 的子进程编排模型

- `src/registration/`
  - `teams.rs`：Cloudflare WARP Teams（WireGuard 账户）注册；严格校验 `TEAMS_TOKEN` 为注册链接 `token=` 后面的原始三段 JWT，再换取账户
  - `masque.rs`：MASQUE 边缘两步注册（`POST /v0/reg` + `PATCH /v0/reg/{id}`）
  - `mod.rs`：两条注册流程各自独立，产出不同凭据类型，不共享接口；只做子模块的 `pub use` 汇总

- `src/outbound/`
  - `mod.rs`：出网抽象 `Outbound` trait，SOCKS5/SOCKS4/HTTP 代理层只依赖它，不关心底层是 WireGuard 虚拟网卡还是 MASQUE H3 CONNECT 流
  - `wireguard.rs`：WireGuard 出网后端，封装项目内双栈 `Net` 虚拟网卡，为 WARP IPv4 `/32` 和 IPv6 `/128` 同时安装默认路由，域名并发解析 A/AAAA，TCP 交错竞速地址，UDP 使用 A 优先、AAAA 兜底；只持有单一不可变 `Net`
  - `masque/`：MASQUE 出网后端（QUIC/H3 CONNECT），含 `tls.rs`（证书/pinned-key 握手）、`qpack.rs`（H3 头部编解码）、`huffman.rs`（QPACK 静态表 Huffman 编解码）、`doh.rs`（隧道内 DoH 解析，边缘不接受裸域名 CONNECT）

- `src/netstack.rs`
  - 项目专用 Tokio/smoltcp 适配层；一个 reactor 驱动 `Interface`、TCP/UDP `SocketSet` 与 WireGuard packet device，不包含监听器或 raw socket 等无关能力

- `src/dataplane.rs`
  - WireGuard 数据面的只读聚合观测；热路径只更新原子计数，独立 reporter 每 5 秒关联 outer UDP、解封装、TCP 头部进度、reactor/backlog/socket 与 cgroup throttling
  - TCP 只保留端口、seq/ack/flags、载荷长度和事件年龄，不记录 IP 或载荷内容；观测不参与恢复决策

- `src/tunnel.rs`
  - boringtun `Tunn` 状态机的 I/O 驱动：UDP 收发、reserved bytes 覆写/清零、可选 t1/t2 反审查伪装包、握手与重传定时器
  - `WgTunnel` 直接实现 netstack 的 `AsyncDevice`，同一个 reactor 驱动 smoltcp、BoringTun、outer UDP 和 timer；没有数据中转 task、代际或 packet channel
  - netstack 有限发送批次使用 `feed + flush`；outer UDP 暂时不可写时由 `Sink` 背压保留待发报文，不静默丢包，也不关闭长寿命 packet sink
  - transport 不根据业务 TX/RX 顺序推断请求是否得到响应，也不执行重绑或 endpoint 切换；真实 trace 失败由 Supervisor 结束整个进程生命周期

- `src/config.rs`
  - 解析 `wg0.conf`

- `src/endpoint/`
  - `source.rs`：候选归一化、内置候选池、按 last_good/冷却排序
  - `state.rs`：`endpoint-state.json` 读写
  - `mod.rs`：候选来源与状态存储的 trait 抽象

- `src/health/`
  - `probe.rs`：`SocksTraceProbe`，走本地 SOCKS5 请求 trace 接口检查 `warp=on|plus`
  - `recovery.rs`：`ThresholdRecovery` 只累计连续失败并请求退出，不执行恢复动作；WireGuard 阈值固定为 1，MASQUE 使用配置值
  - `heartbeat.rs`：`Supervisor` 只记录最后一次成功探测时间，`healthcheck` 子命令检查其是否过期，不再自己发起真实探测
  - `mod.rs`：汇总探测、计数和心跳的具体实现

- `src/mixed.rs`
  - 多监听地址共享同一出网后端和并发上限；auto 模式创建独立 IPv4 与 V6-only IPv6 wildcard listener，并在协议分发前拒绝公网来源；每个入口仍按首字节分发 SOCKS5/SOCKS4/HTTP

- `src/socks5.rs` / `src/socks4.rs` / `src/http_proxy.rs`
  - 三种代理协议的服务端实现
  - SOCKS5 的一个 UDP ASSOCIATE 可同时维护多个独立目标通道并汇聚回包；worker 完成结果不修改 route map，关闭通道只按 sender 状态清理，目标建立时间、活跃目标数和空闲时间均有界，控制连接关闭时统一回收

- `src/relay.rs`
  - CONNECT 语义成功后的双向转发，三种协议共用

- `src/dns.rs`
  - 隧道内 DNS 解析（SOCKS5 CONNECT 域名解析必须在隧道内完成）

- `src/fsutil.rs`
  - 文件权限收紧为仅所有者可读写

容器入口直接是 Dockerfile 里的 `ENTRYPOINT ["/usr/local/bin/warp-socks-rs"]`，不再经过 `entrypoint.sh` 转发（旧版 shell 编排年代的 exec 包装脚本已删除，二进制本身就作为 PID 1 运行）。

## 当前约束

- 只支持 Teams 注册登录
- 隧道与代理由仓库根 `src/` 编译出的单一二进制提供，无子进程编排
- 启动阶段必须先拿到可用 SOCKS 出口，再标记 runtime ready
- WireGuard 运行期首次真实探测失败即冷却 endpoint、退出；MASQUE 达到失败阈值后退出

## 读代码顺序

建议按下面顺序看：

1. `src/bin/warp-socks.rs`
2. `src/appconfig.rs`
3. `src/supervisor.rs`（`run()` 里 MASQUE 优先、WireGuard 回退的分支顺序就是两条隧道路径的权威说明）
4. `src/registration/teams.rs` / `src/registration/masque.rs`
5. `src/outbound/wireguard.rs` / `src/outbound/masque/mod.rs`
6. `src/health/recovery.rs` / `src/health/heartbeat.rs`
