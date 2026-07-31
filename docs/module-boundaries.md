# 模块边界

这份文档描述当前 Rust 实现（`src/`）怎么组织，不讨论历史 shell 方案。

## 主链路

1. `WARP_SOCKS_ENABLE_MASQUE=1` 时优先尝试独立的 `reg.json`（MASQUE，见下方“状态文件”），成功则不需要 `TEAMS_TOKEN`/`account.json`
2. MASQUE 未开启，或开启但注册/建隧道失败需要回退时，才走 `TEAMS_TOKEN -> account.json`（首次注册，之后重启直接复用）-> `wg0.conf`（WireGuard 路径用）
3. `Supervisor`（`src/supervisor.rs`）在进程内起隧道（`WARP_SOCKS_ENABLE_MASQUE=1` 时优先 MASQUE，失败或未开启则 userspace WireGuard）+ 内置 SOCKS5
4. 经 SOCKS5 出口探测通过（`warp=on`）后进入运行态
5. 运行期 healthcheck 连续失败达到阈值后，请求容器重启

说明：内核 `wg-quick` / `microsocks` 路径已废弃。中国等网络环境下，内核 WireGuard 常表现为 `0 B received`；带 WARP tricks 的 userspace 实现才能稳定握手。旧版 shell 编排（`lib/app/main.sh` 等按 endpoint 候选逐个拉起子进程）也已废弃，改为 `Supervisor` 在同一进程内完成候选尝试、SOCKS5 服务与健康检查，不再有子进程生命周期管理。

隧道、SOCKS5、注册、健康探测均由仓库根 `src/` 编译出的单一二进制 `warp-socks-rs` 提供（参考 bepass-org/warp-plus 思路重写，同一份 `wg0.conf` 格式、同样的 reserved bytes/trick 反审查机制），子命令为 `warp-socks [serve|register reg/del <path>|healthcheck]`（`src/bin/warp-socks.rs`）。日志用 `log`/`env_logger`（`RUST_LOG` 控制级别，默认 `info`，含隧道后端选择、连接建立/失败等关键信息）。

`Supervisor::run` 是一个纯粹的两分支调度：`WARP_SOCKS_ENABLE_MASQUE=1` 时先调用 `try_masque`（内部会在 `reg.json` 缺失时自动调用 `MasqueRegistrar::register` 生成，失败原因统一汇总成一个 `Err`），成功则直接提供服务；关闭或失败都会落到 `run_wireguard`。`ensure_account`（Teams 账户/`account.json`）只在 `run_wireguard` 里调用——MASQUE 开启且注册、建隧道都成功的场景全程不会要求 `TEAMS_TOKEN`；只有 MASQUE 未开启，或开启但失败需要回退 WireGuard 时，才会在缺少 `account.json` 且 `TEAMS_TOKEN` 为空时 `bail!` 退出等待重启。UDP ASSOCIATE 的数据报走隧道内 UDP 仅在 WireGuard 后端下支持；MASQUE 后端遇到 UDP 会明确报 `Unsupported` 并回退宿主机网络直连出口（`src/socks5.rs::establish_egress`）。这不是本项目待补的功能缺口：Cloudflare 的 MASQUE 边缘和官方 `warp-svc` 客户端本身在 forward-proxy 模式下就不支持 CONNECT-UDP（RFC 9298），H3 CONNECT 只是字节流，扛不了数据报；真要把 UDP 也收进隧道需要换成 Connect-IP + TUN 的完全不同架构，会改变本项目免 root 的定位（交叉验证见本地参考实现 `warp-go/tunnel/udp.go` 及 `warp-go/docs/warp-masque-reverse-engineering.md` §9.6）。

## 状态文件

以下路径均相对宿主机 bind mount 目录（compose.yaml 里约定叫 `./data`，容器内挂载点是 `/etc/warp-socks`——都不再叫 wireguard，因为这个目录现在同时存 WireGuard 和 MASQUE 两套状态，见 `reg.json`）。

- `data/account.json`
  - Teams 注册结果
  - 唯一账户状态来源
  - `config.client_id` base64 解码后取前 3 字节，写入 `wg0.conf` 的 `Reserved =`
    （`src/config.rs` 只读文件里的 `Reserved` 字段）

- `data/wg0.conf`
  - 由 `account.json` 和 endpoint 派生
  - 当前运行中的 endpoint 以它为准，也是 healthcheck 恢复时读取 endpoint 的唯一来源

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
  - `teams.rs`：Cloudflare WARP Teams（WireGuard 账户）注册，`TEAMS_TOKEN` 换取账户
  - `masque.rs`：MASQUE 边缘两步注册（`POST /v0/reg` + `PATCH /v0/reg/{id}`）
  - `mod.rs`：两条注册流程各自独立，产出不同凭据类型，不共享接口；只做子模块的 `pub use` 汇总

- `src/outbound/`
  - `mod.rs`：出网抽象 `Outbound` trait，SOCKS5/SOCKS4/HTTP 代理层只依赖它，不关心底层是 WireGuard 虚拟网卡还是 MASQUE H3 CONNECT 流
  - `wireguard.rs`：WireGuard 出网后端，封装 `tokio_smoltcp::Net` 虚拟网卡；`WgOutbound::establish` 消费 WG 握手 + smoltcp 网卡初始化
  - `masque/`：MASQUE 出网后端（QUIC/H3 CONNECT），含 `tls.rs`（证书/pinned-key 握手）、`qpack.rs`（H3 头部编解码）、`huffman.rs`（QPACK 静态表 Huffman 编解码）、`doh.rs`（隧道内 DoH 解析，边缘不接受裸域名 CONNECT）

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
  - `heartbeat.rs`：`Supervisor` 运行期探测结果落一份心跳文件，`healthcheck` 子命令只读这份心跳、不再自己重新发起一次真实探测
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

容器入口直接是 Dockerfile 里的 `ENTRYPOINT ["/usr/local/bin/warp-socks-rs"]`，不再经过 `entrypoint.sh` 转发（旧版 shell 编排年代的 exec 包装脚本已删除，二进制本身就作为 PID 1 运行）。

## 当前约束

- 只支持 Teams 注册登录
- 隧道与代理由仓库根 `src/` 编译出的单一二进制提供，无子进程编排
- 启动阶段必须先拿到可用 SOCKS 出口，再标记 runtime ready
- 运行期恢复策略固定为"连续失败后退出进程，由 Docker 重启容器"

## 读代码顺序

建议按下面顺序看：

1. `src/bin/warp-socks.rs`
2. `src/appconfig.rs`
3. `src/supervisor.rs`（`run()` 里 MASQUE 优先、WireGuard 回退的分支顺序就是两条隧道路径的权威说明）
4. `src/registration/teams.rs` / `src/registration/masque.rs`
5. `src/outbound/wireguard.rs` / `src/outbound/masque/mod.rs`
6. `src/health/recovery.rs` / `src/health/heartbeat.rs`
