# Changelog

记录本项目面向用户可见的行为变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。不记录内部重构、进度、调试过程——这些看 git log。

## [Unreleased]

### Changed

- 隧道与代理统一由自研 `warp-rs`（Rust）提供：移除第三方 `warp-plus` 预编译二进制、`Dockerfile` 的 `fetcher` stage，以及 `TUNNEL_IMPL` 切换开关。
- 环境变量 `WARP_PLUS_LOG_VERBOSE` 改名为 `TUNNEL_LOG_VERBOSE`（后端无关的通用命名）。

### Added

- CI 新增 `.github/workflows/ci.yml`：push/PR 时跑 `warp-rs` 的 `cargo fmt`/`clippy`/`test` 门禁，以及全量 shell 脚本的 `shellcheck` 门禁。
