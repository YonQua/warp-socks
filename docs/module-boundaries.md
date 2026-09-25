# 模块边界

这份文档描述当前 Rust 实现（`src/`）怎么组织，不讨论历史 shell 方案。

## 主链路

1. `WARP_SOCKS_ENABLE_MASQUE=1` 时优先尝试独立的 `reg.json`（MASQUE，见下方“状态文件”），成功则不需要 `TEAMS_TOKEN`/`account.json`
2. MASQUE 未开启，或开启但注册/建隧道失败需要回退时，才走 `TEAMS_TOKEN -> account.json`（首次注册，之后重启直接复用）-> `wg0.conf`（WireGuard 路径用）；`TEAMS_TOKEN` 只接受注册链接 `token=` 后面的原始三段 JWT，不接受 `token=` 本身、完整 URI 或引号
3. `Supervisor::prepare_base` 选择并通过 HTTPS trace 验证基础 `Outbound`，不创建监听端口
4. `PSIPHON_COUNTRY` 非空时，把基础 WARP 依次传给 Psiphon 和 MASQUE H2，逐个验证 SSH、H2 和最终 WARP trace，首条完整可用路径成为最终 Cloudflare `Outbound`
5. 最终 `Outbound` 绑定唯一公共代理入口，SOCKS trace 返回 `warp=on|plus` 后记录健康心跳
6. 运行期仅最终入口拥有健康循环；普通 WireGuard 单失败冷却 endpoint，其余模式按配置阈值退出。地区模式失败不猜测故障来自哪个基础 endpoint

`PSIPHON_COUNTRY` 只选择前置 SSH 节点；Cloudflare 最终 IP 地区由实际连接决定，启动日志与 trace 可用于核对，不保证与所选国家一致，也不保证目标服务解锁。该模式仅提供 TCP，国家代码限制为 `AT AU BE BG CA CH CZ DE DK EE ES FI FR GB HR HU IE IN IT JP LV NL NO PL PT RO RS SE SG SK US`。

说明：内核 `wg-quick` / `microsocks` 路径已废弃。中国等网络环境下，内核 WireGuard 常表现为 `0 B received`；带 WARP tricks 的 userspace 实现才能稳定握手。旧版 shell 编排（`lib/app/main.sh` 等按 endpoint 候选逐个拉起子进程）也已废弃，改为 `Supervisor` 在同一进程内完成候选尝试、SOCKS5 服务与健康检查，不再有子进程生命周期管理。

隧道、SOCKS5、注册、健康探测均由仓库根 `src/` 编译出的单一二进制 `warp-socks-rs` 提供（参考 bepass-org/warp-plus 思路重写，同一份 `wg0.conf` 格式、同样的 reserved bytes/trick 反审查机制），子命令为 `warp-socks [serve|register reg/del <path>|healthcheck]`（`src/bin/warp-socks.rs`）。日志用 `log`/`env_logger`（`RUST_LOG` 控制级别，默认 `info`，含隧道后端选择、连接建立/失败等关键信息）。

`Supervisor::run` 在网络操作前校验监听地址和国家代码，一个信号处理循环覆盖启动与运行阶段。`prepare_base` 只负责 MASQUE 优先 / WireGuard 候选选择；`run_service` 负责可选的地区链路组合与公共服务启动。`ensure_account` 只在需要 WireGuard 时调用，纯 MASQUE 场景不需要 Teams 账户。

Psiphon 只作为 H2 的 TCP 载体，不是公共出口。节点列表通过基础 WARP 下载；SSH 通过基础 `Outbound::connect_tcp` 连接，不经过本地 SOCKS。各层持有上游所有权，生命周期随最终链路释放。WireGuard 原生支持 SOCKS5 UDP；MASQUE H3 和地区模式在 ASSOCIATE 阶段拒绝 UDP，没有宿主机 UDP 直出回退。

## 状态文件

以下路径均相对状态目录。默认 compose.yaml 把宿主机 `./data` 挂载到容器内 `/etc/warp-socks`；原生运行可用 `WARP_SOCKS_STATE_DIR` 指向同一个 `data` 目录。这个目录同时保存 WireGuard 和 MASQUE 两套状态，见 `reg.json`。

- `data/account.json`
  - Teams 注册结果
  - 唯一账户状态来源
  - `config.client_id` base64 解码后取前 3 字节，作为运行配置的 reserved bytes，
    同时写入 `wg0.conf` 的 `Reserved =`

- `data/wg0.conf`
  - 由 `account.json` 和 endpoint 派生
  - 仅作为当前已通过基础 WARP HTTPS trace 的 WireGuard 配置快照；地区模式的最终代理入口随后单独探测，不参与运行期恢复决策

- `data/endpoint-state.json`
  - 只保存 `last_good_endpoint` 和 cooldown
  - 用于启动时候选重排（仅 WireGuard 路径，MASQUE 走固定边缘地址不涉及候选轮换）

- `data/reg.json`
  - MASQUE 路径的注册凭据（基础 MASQUE 或地区模式使用）：设备 id/token、ECDSA 客户端密钥、边缘固定公钥等
  - 缺失时 `Supervisor::ensure_masque_credentials` 调用 `registration::register_masque` 生成
  - 与 `account.json`/`wg0.conf` 相互独立；普通 WireGuard 不使用，WireGuard 作为地区模式首层时仍需该文件构建最终 H2

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
  - `mod.rs`：出网抽象 `Outbound` trait，SOCKS5/SOCKS4/HTTP 代理层只依赖它，不关心底层是 WireGuard、MASQUE H3 还是 MASQUE H2
  - `ip.rs`：WireGuard / H2 共用的 IP 栈配置、隧道内 A/AAAA 解析和 TCP 地址竞速
  - `https.rs`：在现有 `Outbound` 上执行有大小和时间上限的 HTTPS GET，供启动 trace 与签名节点列表下载使用；Hyper 解析 HTTP，rustls 验证公开 CA
  - `wireguard.rs`：建立 WireGuard packet device 和单一 `Net`，通过共享 IP 拨号逻辑提供 TCP，并提供隧道内 UDP
  - `psiphon/`：签名节点列表验证、国家筛选、SSH 主机密钥校验和 direct-tcpip；持有基础 WARP，不提供监听入口
  - `masque/`：H3 CONNECT 与 H2 CONNECT-IP。`tls.rs` 共用客户端身份与边缘公钥校验；`qpack.rs` / `huffman.rs` 提供 H3 编解码，`doh.rs` 处理 H3 隧道内 DNS
  - `masque/h2.rs`：通过 Psiphon 建立 H2 CONNECT-IP，封装 IP capsule，收发任务遵守 H2 流控；有界入站 IP 队列满时丢包，保持 H2 读取和窗口释放，避免与 IP reactor 发送形成循环等待
  - `masque/h2_outbound.rs`：把 H2 packet device 接入现有 `Net`，使用注册分配的 IPv4/IPv6 地址

- `src/netstack.rs`
  - 项目专用 Tokio/smoltcp 适配层；一个 reactor 驱动 `Interface`、TCP/UDP `SocketSet` 与 IP packet device（WireGuard 或 H2），不包含监听器或 raw socket 等无关能力

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
  - `probe.rs`：共享 trace 解析；启动选择时直接通过基础 Outbound 探测，运行期 `SocksTraceProbe` 只通过最终公共入口检查 `warp=on|plus`
  - `recovery.rs`：`ThresholdRecovery` 只累计连续失败并请求退出，不执行恢复动作；普通 WireGuard 阈值固定为 1，MASQUE / 地区模式使用配置值
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

- WireGuard 使用 Teams 注册；MASQUE 使用独立注册
- 隧道与代理由仓库根 `src/` 编译出的单一二进制提供，无子进程编排
- 启动阶段必须先拿到可用 SOCKS 出口，再标记 runtime ready
- 普通 WireGuard 首次真实探测失败即冷却 endpoint、退出；MASQUE / 地区模式达到失败阈值后退出

## 读代码顺序

建议按下面顺序看：

1. `src/bin/warp-socks.rs`
2. `src/appconfig.rs`
3. `src/supervisor.rs`（先看 `run_service` 的链路组合，再看 `prepare_base` 的后端选择）
4. `src/registration/teams.rs` / `src/registration/masque.rs`
5. `src/outbound/wireguard.rs` / `src/outbound/masque/mod.rs`
6. `src/health/recovery.rs` / `src/health/heartbeat.rs`
