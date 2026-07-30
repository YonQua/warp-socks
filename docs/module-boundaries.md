# 模块边界

这份文档描述当前 Rust 实现（`src/`）怎么组织，不讨论历史 shell 方案。

## 主链路

1. `TEAMS_TOKEN -> account.json`（首次启动注册，之后重启直接复用）
2. `account.json -> wg0.conf`
3. `Supervisor`（`src/supervisor.rs`）在进程内起隧道（userspace WireGuard 或 MASQUE）+ 内置 SOCKS5
4. 经 SOCKS5 出口探测通过（`warp=on`）后进入运行态
5. 运行期 healthcheck 连续失败达到阈值后，请求容器重启

说明：内核 `wg-quick` / `microsocks` 路径已废弃。中国等网络环境下，内核 WireGuard 常表现为 `0 B received`；带 WARP tricks 的 userspace 实现才能稳定握手。旧版 shell 编排（`lib/app/main.sh` 等按 endpoint 候选逐个拉起子进程）也已废弃，改为 `Supervisor` 在同一进程内完成候选尝试、SOCKS5 服务与健康检查，不再有子进程生命周期管理。

隧道、SOCKS5、注册、健康探测均由仓库根 `src/` 编译出的单一二进制 `warp-socks-rs` 提供（参考 bepass-org/warp-plus 思路重写，同一份 `wg0.conf` 格式、同样的 reserved bytes/trick 反审查机制），子命令为 `warp-socks [serve|register reg/del <path>|healthcheck]`（`src/bin/warp-socks.rs`）。日志用 `log`/`env_logger`（`RUST_LOG` 控制级别，默认 `info`，含隧道后端选择、连接建立/失败等关键信息）。

`Supervisor::run` 每次启动优先尝试加载 `reg.json` 走 MASQUE（Cloudflare QUIC/H3 隧道），失败或文件不存在再回退到 `wg0.conf` 这条 WireGuard 路径。`reg.json` 是否存在由 `WARP_SOCKS_ENABLE_MASQUE` 开关控制（`Supervisor::ensure_masque_state`）：关闭时该文件不会被创建，MASQUE 分支自然跳过，行为与纯 WireGuard 完全一致；开启后缺失则自动在进程内调用 `MasqueRegistrar::register` 生成，注册失败只警告不中断启动。UDP ASSOCIATE 的数据报走隧道内 UDP 仅在 WireGuard 后端下支持；MASQUE 后端遇到 UDP 会明确报 `Unsupported` 并回退宿主机网络直连出口（`src/socks5.rs::establish_egress`）。

## 状态文件

- `wireguard/account.json`
  - Teams 注册结果
  - 唯一账户状态来源
  - `config.client_id` base64 解码后取前 3 字节，写入 `wg0.conf` 的 `Reserved =`
    （`src/config.rs` 只读文件里的 `Reserved` 字段）

- `wireguard/wg0.conf`
  - 由 `account.json` 和 endpoint 派生
  - 当前运行中的 endpoint 以它为准，也是 healthcheck 恢复时读取 endpoint 的唯一来源

- `wireguard/endpoint-state.json`
  - 只保存 `last_good_endpoint` 和 cooldown
  - 用于启动时候选重排

## 源码模块职责

- `src/bin/warp-socks.rs`
  - 生产入口，子命令分发：`serve`（默认，起 `Supervisor`）/ `register reg|del` / `healthcheck`

- `src/appconfig.rs`
  - 环境变量解析、默认值、合法性兜底，供 `Supervisor` 和 `healthcheck` 子命令共用

- `src/supervisor.rs`
  - 进程内编排：账户确认、MASQUE 状态确保、endpoint 候选尝试（含冷却/切换）、SOCKS5 起服务与监督、运行期健康检查循环、优雅退出（SIGTERM/SIGINT/SIGHUP）
  - 取代旧版 `lib/app/main.sh` + `lib/runtime/tunnel.sh` + `lib/runtime/recovery.sh` 的子进程编排模型

- `src/registration/`
  - `teams.rs`：Cloudflare WARP Teams（WireGuard 账户）注册，`TEAMS_TOKEN` 换取账户
  - `masque.rs`：MASQUE 边缘两步注册（`POST /v0/reg` + `PATCH /v0/reg/{id}`）
  - `mod.rs`：两条注册流程各自独立，产出不同凭据类型，不共享接口；只做子模块的 `pub use` 汇总

- `src/outbound/`
  - `mod.rs`：出网抽象 `Outbound` trait，SOCKS5/SOCKS4/HTTP 代理层只依赖它，不关心底层是 WireGuard 虚拟网卡还是 MASQUE H3 CONNECT 流
  - `wireguard.rs`：WireGuard 出网后端，封装 `tokio_smoltcp::Net` 虚拟网卡；`WgOutbound::establish` 消费 WG 握手 + smoltcp 网卡初始化
  - `masque/`：MASQUE 出网后端（QUIC/H3 CONNECT），含 `tls.rs`（证书/握手）、`qpack.rs`（H3 头部编解码）

- `src/tunnel.rs`
  - boringtun `Tunn` 状态机的 I/O 驱动：UDP 收发、reserved bytes 覆写/清零、可选 t1/t2 反审查伪装包、握手与重传定时器

- `src/config.rs`
  - 解析 `wg0.conf`

- `src/endpoint/`
  - `source.rs`：候选归一化、内置候选池、按 last_good/冷却排序
  - `state.rs`：`endpoint-state.json` 读写
  - `mod.rs`：候选来源与状态存储的 trait 抽象

- `src/health/`
  - `probe.rs`：`SocksTraceProbe`，走本地 SOCKS5 请求 trace 接口检查 `warp=on|plus`
  - `recovery.rs`：连续失败达到阈值即请求退出进程的恢复策略
  - `mod.rs`：探测方式与恢复策略的 trait 抽象

- `src/mixed.rs`
  - 单端口多协议探测分发（peek 首字节：0x05→SOCKS5，0x04→SOCKS4，其余→HTTP）

- `src/socks5.rs` / `src/socks4.rs` / `src/http_proxy.rs`
  - 三种代理协议的服务端实现

- `src/relay.rs`
  - CONNECT 语义成功后的双向转发，三种协议共用

- `src/dns.rs`
  - 隧道内 DNS 解析（SOCKS5 CONNECT 域名解析必须在隧道内完成）

- `src/fsutil.rs`
  - 文件权限收紧为仅所有者可读写

- `entrypoint.sh`
  - 容器入口，仅 `exec warp-socks-rs "$@"`

## 当前约束

- 只支持 Teams 注册登录
- 隧道与代理由仓库根 `src/` 编译出的单一二进制提供，无子进程编排
- 启动阶段必须先拿到可用 SOCKS 出口，再标记 runtime ready
- 运行期恢复策略固定为"连续失败后退出进程，由 Docker 重启容器"

## 读代码顺序

建议按下面顺序看：

1. `src/bin/warp-socks.rs`
2. `src/appconfig.rs`
3. `src/supervisor.rs`
4. `src/registration/teams.rs`
5. `src/outbound/wireguard.rs`
6. `src/health/recovery.rs`
