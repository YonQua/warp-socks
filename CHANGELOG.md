# Changelog

记录本项目面向用户可见的行为变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。不记录内部重构、进度、调试过程——这些看 git log。

## [Unreleased]

### Changed

- 隧道与代理统一由自研 `warp-rs`（Rust）提供：移除第三方 `warp-plus` 预编译二进制、`Dockerfile` 的 `fetcher` stage，以及 `TUNNEL_IMPL` 切换开关。
- 环境变量 `WARP_PLUS_LOG_VERBOSE` 改名为 `TUNNEL_LOG_VERBOSE`（后端无关的通用命名）。
- `TEAMS_TOKEN` 不再无条件必填：`WARP_SOCKS_ENABLE_MASQUE=1` 且 MASQUE 注册与建隧道都成功时，全程不再要求 Teams 账户；只有实际需要走 WireGuard（未开启 MASQUE，或 MASQUE 失败要回退）时才会校验。
- **breaking**：状态目录改名，容器内从 `/etc/wireguard` 改为 `/etc/warp-socks`，仓库默认 `compose.yaml` 的宿主机侧目录也从 `./wireguard` 改为 `./data`（该目录同时存 WireGuard 和 MASQUE 两套状态，继续叫 `wireguard` 名不副实）。已有部署升级时，把本地的 `./wireguard` 目录改名成 `./data`（或保留旧名、自行调整 `compose.yaml` 挂载行左侧），并把挂载行右侧改成 `/etc/warp-socks`，即可继续复用已有状态；不做迁移会导致读不到旧状态、等同重新注册。
- **breaking**：`WARP_SOCKS_ENABLE_MASQUE` 默认值从 `0` 改为 `1`，新部署默认优先走 MASQUE（免 `TEAMS_TOKEN`）、失败回退 WireGuard。已有部署如果依赖旧的 WireGuard-by-default 行为、且没有在 `.env`/`compose.yaml` 里显式设置这个变量，升级镜像后需要显式加上 `WARP_SOCKS_ENABLE_MASQUE=0` 才能保持原行为；MASQUE 路径的 UDP ASSOCIATE 会绕过隧道走宿主机直连出口（暴露宿主机真实 IP），这是 Cloudflare MASQUE 边缘协议本身的限制，不受此默认值变更影响，详见 `docs/module-boundaries.md`。

### Added

- CI 新增 `.github/workflows/ci.yml`：push/PR 时跑 `warp-rs` 的 `cargo fmt`/`clippy`/`test` 门禁。
- 发布镜像新增 `linux/arm/v7` 架构支持，用于覆盖 32 位 ARM 宿主机；发布流水线改用 `cross` 交叉编译三个 musl 目标二进制后再打包镜像（`Dockerfile.release`），避免 buildx 用 QEMU 完整模拟 rustc 编译。本地开发用的 `Dockerfile` 不受影响，仍是编译-from-source。

### Removed

- 移除 `entrypoint.sh`：容器入口改为 Dockerfile `ENTRYPOINT` 直接指向 `warp-socks-rs` 二进制。
- 移除 CI 里的 `shellcheck` 门禁与 `.shellcheckrc`：仓库内已无 shell 脚本，门禁失去检查对象。
