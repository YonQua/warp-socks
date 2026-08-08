# Changelog

记录本项目面向用户可见的行为变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。不记录内部重构、进度、调试过程——这些看 git log。

## [Unreleased]

### Changed

- **breaking**：Compose 改用 Linux `network_mode: host`，移除 `ports` 发布模型；监听入口改由 `SOCKS_LISTEN_ADDRS` 显式配置，可按实际网络绑定宿主机 IPv4/IPv6，并让随机 SOCKS5 UDP relay 端口对远端客户端可达。
- MASQUE 等不支持隧道内 UDP 的后端现在在 UDP ASSOCIATE 阶段明确拒绝；项目不提供宿主机 UDP 直出路径，确保代理流量不会绕过 WARP。

- 隧道与代理统一由自研 `warp-rs`（Rust）提供：移除第三方 `warp-plus` 预编译二进制、`Dockerfile` 的 `fetcher` stage，以及 `TUNNEL_IMPL` 切换开关。
- 环境变量 `WARP_PLUS_LOG_VERBOSE` 改名为 `TUNNEL_LOG_VERBOSE`（后端无关的通用命名）。
- `TEAMS_TOKEN` 不再无条件必填：`WARP_SOCKS_ENABLE_MASQUE=1` 且 MASQUE 注册与建隧道都成功时，全程不再要求 Teams 账户；只有实际需要走 WireGuard（未开启 MASQUE，或 MASQUE 失败要回退）时才会校验。
- **breaking**：状态目录改名，容器内从 `/etc/wireguard` 改为 `/etc/warp-socks`，仓库默认 `compose.yaml` 的宿主机侧目录也从 `./wireguard` 改为 `./data`（该目录同时存 WireGuard 和 MASQUE 两套状态，继续叫 `wireguard` 名不副实）。已有部署升级时，把本地的 `./wireguard` 目录改名成 `./data`（或保留旧名、自行调整 `compose.yaml` 挂载行左侧），并把挂载行右侧改成 `/etc/warp-socks`，即可继续复用已有状态；不做迁移会导致读不到旧状态、等同重新注册。
- **breaking**：`WARP_SOCKS_ENABLE_MASQUE` 默认值从 `0` 改为 `1`，新部署默认优先走 MASQUE（免 `TEAMS_TOKEN`）、失败回退 WireGuard。已有部署如果依赖旧的 WireGuard-by-default 行为、且没有在 `.env`/`compose.yaml` 里显式设置这个变量，升级镜像后需要显式加上 `WARP_SOCKS_ENABLE_MASQUE=0` 才能保持原行为；MASQUE 路径不支持隧道内 UDP，UDP ASSOCIATE 会明确失败。

### Added

- WireGuard userspace 网络栈改为项目内 `smoltcp 0.13.1` 异步适配层：同时配置 WARP IPv4/IPv6 地址与默认路由，TCP/UDP 均按目标地址族选择源地址，完整支持隧道内 IPv4/IPv6 字面量。
- SOCKS5 UDP ASSOCIATE 支持在同一 association 内访问多个 IPv4、IPv6 和域名目标；每目标使用独立隧道通道，关闭的 worker 由 sender 状态统一清理；活跃目标最多 64 个，建立超时 10 秒，建立后空闲 120 秒自动释放。
- netstack 直接以 `SocketSet` 作为 TCP/UDP socket 与端口占用的唯一事实源；按协议和地址族检查冲突，socket 删除即释放端口，回绕或耗尽时不会覆盖活跃 socket。
- CI 新增 `.github/workflows/ci.yml`：push/PR 时跑 `warp-rs` 的 `cargo fmt`/`clippy`/`test` 门禁。
- 发布镜像新增 `linux/arm/v7` 架构支持，用于覆盖 32 位 ARM 宿主机；发布流水线改用 `cross` 交叉编译三个 musl 目标二进制后再打包镜像（`Dockerfile.release`），避免 buildx 用 QEMU 完整模拟 rustc 编译。本地开发用的 `Dockerfile` 不受影响，仍是编译-from-source。

### Removed

- 移除 `entrypoint.sh`：容器入口改为 Dockerfile `ENTRYPOINT` 直接指向 `warp-socks-rs` 二进制。
- 移除 CI 里的 `shellcheck` 门禁与 `.shellcheckrc`：仓库内已无 shell 脚本，门禁失去检查对象。
