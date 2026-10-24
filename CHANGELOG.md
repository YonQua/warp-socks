# Changelog

记录本项目面向用户可见的行为变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。不记录内部重构、进度、调试过程——这些看 git log。

## [Unreleased]

### Changed

- **breaking**：`TEAMS_TOKEN` 统一为注册链接中 `token=` 后面的原始三段 JWT（`header.payload.signature`）；不再接受或自动截取 `token=`、完整 `com.cloudflare.warp://...` 链接或引号，错误格式会在发送注册请求前明确失败。
- WireGuard transport 收敛为直接实现 netstack `AsyncDevice` 的单 `Tunn`、单 outer UDP socket、单 `Net` 生命周期；移除数据中转 task、packet channel、代际热切换和基于 TX/RX 顺序的伪停滞判断。
- netstack 的有限发送批次改为 `feed + flush`，不再把每个批次误当成完整 Stream 并关闭 packet sink。
- WireGuard 运行期只以真实 SOCKS trace 失败作为恢复信号；首次失败即冷却当前 endpoint 并退出，让 Docker 以全新的 `Tunn`、outer UDP socket 和 `Net` 验证池中其它路径，同时释放无法靠原地重绑可靠续传的旧 TCP。
- TCP relay 在客户端上行结束后最多保留下行 30 秒，远端先结束则立即释放；视频 Range 请求被取消时不再因无限等待另一方向而堆积 `CLOSE_WAIT` 和虚拟 TCP socket。
- WireGuard peer index 改为与 BoringTun 正式 device 一致的随机非零 24-bit 值，避免不同生命周期重复使用固定 sender index。
- WireGuard 每 5 秒输出一个只读数据面窗口，聚合 outer UDP、BoringTun 解封装结果、TCP 头部进度、smoltcp reactor/backlog/socket 和 cgroup CPU throttling；不记录 IP 或载荷内容。
- endpoint 历史状态只会优先当前候选池中的 `last_good`；手工 `ENDPOINT_CANDIDATES` 不再被已移除的旧 endpoint 越界覆盖。
- WireGuard 域名解析改为隧道内并发 A/AAAA：NODATA/NXDOMAIN 不再误等到 DNS 超时，TCP 使用 IPv4 优先、250 ms 交错启动的轻量 Happy Eyeballs，UDP 使用 A 优先、AAAA 兜底；MASQUE 的单记录类型未命中降为 debug 日志。
- `SOCKS_LISTEN_ADDRS` 默认改为 `auto`：自动建立 IPv4 与 V6-only IPv6 listener，并按控制连接的实际本机地址返回同地址族 UDP relay；自动模式只接受本地或 LAN 客户端，不再要求部署者手填宿主机 IPv4/ULA。
- **breaking**：Compose 改用 Linux `network_mode: host`，移除 `ports` 发布模型；监听入口由 `SOCKS_LISTEN_ADDRS` 控制，默认自动双栈，也可按实际网络显式绑定，并让随机 SOCKS5 UDP relay 端口对远端客户端可达。
- MASQUE 等不支持隧道内 UDP 的后端现在在 UDP ASSOCIATE 阶段明确拒绝；项目不提供宿主机 UDP 直出路径，确保代理流量不会绕过 WARP。

- 隧道与代理统一由自研 `warp-rs`（Rust）提供：移除第三方 `warp-plus` 预编译二进制、`Dockerfile` 的 `fetcher` stage，以及 `TUNNEL_IMPL` 切换开关。
- 环境变量 `WARP_PLUS_LOG_VERBOSE` 改名为 `TUNNEL_LOG_VERBOSE`（后端无关的通用命名）。
- `TEAMS_TOKEN` 不再无条件必填：`WARP_SOCKS_ENABLE_MASQUE=1` 且 MASQUE 注册与建隧道都成功时，全程不再要求 Teams 账户；只有实际需要走 WireGuard（未开启 MASQUE，或 MASQUE 失败要回退）时才会校验。
- **breaking**：状态目录改名，容器内从 `/etc/wireguard` 改为 `/etc/warp-socks`，仓库默认 `compose.yaml` 的宿主机侧目录也从 `./wireguard` 改为 `./data`（该目录同时存 WireGuard 和 MASQUE 两套状态，继续叫 `wireguard` 名不副实）。已有部署升级时，把本地的 `./wireguard` 目录改名成 `./data`（或保留旧名、自行调整 `compose.yaml` 挂载行左侧），并把挂载行右侧改成 `/etc/warp-socks`，即可继续复用已有状态；不做迁移会导致读不到旧状态、等同重新注册。
- **breaking**：`WARP_SOCKS_ENABLE_MASQUE` 默认值从 `0` 改为 `1`，新部署默认优先走 MASQUE（免 `TEAMS_TOKEN`）、失败回退 WireGuard。已有部署如果依赖旧的 WireGuard-by-default 行为、且没有在 `.env`/`compose.yaml` 里显式设置这个变量，升级镜像后需要显式加上 `WARP_SOCKS_ENABLE_MASQUE=0` 才能保持原行为；MASQUE 路径不支持隧道内 UDP，UDP ASSOCIATE 会明确失败。

### Added

- 新增纯 Rust Psiphon 地区前置：通过 `PSIPHON_COUNTRY` 选择 31 个国家之一，经基础 WARP → Psiphon SSH → MASQUE H2 建立最终 Cloudflare 出口，保留唯一公共代理入口。地区模式仅支持 TCP；所选国家只限定前置节点，不保证最终 IP 地区或目标服务解锁。候选需通过 SSH、H2 和 WARP 出口验证，最多尝试 8 个，全部失败则启动失败，不回退为直接 Psiphon 出口。

- 新增 `WARP_SOCKS_STATE_DIR`，可覆盖默认状态目录 `/etc/warp-socks`，便于原生运行时直接复用仓库 `data` 目录。
- WireGuard userspace 网络栈改为项目内 `smoltcp 0.13.1` 异步适配层：同时配置 WARP IPv4/IPv6 地址与默认路由，TCP/UDP 均按目标地址族选择源地址，完整支持隧道内 IPv4/IPv6 字面量。
- SOCKS5 UDP ASSOCIATE 支持在同一 association 内访问多个 IPv4、IPv6 和域名目标；每目标使用独立隧道通道，关闭的 worker 由 sender 状态统一清理；活跃目标最多 64 个，建立超时 10 秒，建立后空闲 120 秒自动释放。
- netstack 直接以 `SocketSet` 作为 TCP/UDP socket 与端口占用的唯一事实源；按协议和地址族检查冲突，socket 删除即释放端口，回绕或耗尽时不会覆盖活跃 socket。
- CI 新增 `.github/workflows/ci.yml`：push/PR 时跑 `warp-rs` 的 `cargo fmt`/`clippy`/`test` 门禁。
- 发布镜像新增 `linux/arm/v7` 架构支持，用于覆盖 32 位 ARM 宿主机；发布流水线改用 `cross` 交叉编译三个 musl 目标二进制后再打包镜像（`Dockerfile.release`），避免 buildx 用 QEMU 完整模拟 rustc 编译。本地开发用的 `Dockerfile` 不受影响，仍是编译-from-source。

### Removed

- 移除 `entrypoint.sh`：容器入口改为 Dockerfile `ENTRYPOINT` 直接指向 `warp-socks-rs` 二进制。
- 移除 CI 里的 `shellcheck` 门禁与 `.shellcheckrc`：仓库内已无 shell 脚本，门禁失去检查对象。
