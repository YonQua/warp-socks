# 模块边界

这份文档只描述当前 shell 实现怎么组织，不讨论历史方案，也不讨论未来迁移语言。

## 主链路

1. `TEAMS_TOKEN -> account.json`（首次启动注册，之后重启直接复用）
2. `account.json -> wg0.conf`
3. `warp-plus --wgconf wg0.conf`（userspace WireGuard + 内置 SOCKS5）
4. 经 SOCKS5 出口探测通过（`warp=on`）后进入运行态
5. 运行期 healthcheck 连续失败达到阈值后，请求容器重启

说明：内核 `wg-quick` / `microsocks` 路径已废弃。中国等网络环境下，内核 WireGuard 常表现为 `0 B received`；带 WARP tricks 的 userspace 实现才能稳定握手。

## 状态文件

- `wireguard/account.json`
  - Teams 注册结果
  - 唯一账户状态来源
  - `config.client_id` base64 解码后取前 3 字节，写入 `wg0.conf` 的 `Reserved =`
    （warp-plus 在 `--wgconf` 模式下只认文件里的 `Reserved`，不认 `--reserved` flag）

- `wireguard/wg0.conf`
  - 由 `account.json` 和 endpoint 派生
  - 当前运行中的 endpoint 以它为准，也是 healthcheck 恢复时读取 endpoint 的唯一来源

- `wireguard/endpoint-state.json`
  - 只保存 `last_good_endpoint` 和 cooldown
  - 用于启动时候选重排

## 目录职责

- `entrypoint.sh`
  - 容器入口
  - 只负责加载模块并调用 `warp_main`

- `healthcheck/check-socks5.sh`
  - Docker healthcheck 入口
  - 只负责加载模块并调用 `warp_healthcheck_main`

- `lib/app/`
  - 进程级装配
  - 环境变量、主流程、启动日志

- `lib/core/`
  - 通用能力
  - 日志、错误码、基础工具、探测、endpoint 状态文件读写

- `lib/domain/`
  - 领域逻辑
  - Teams 注册、endpoint 候选整理、WireGuard 配置生成

- `lib/runtime/`
  - 运行期控制
  - `tunnel.sh`：warp-plus 单进程生命周期（起、探测、监督、退出）
  - `recovery.sh`：healthcheck 恢复

## 当前约束

- 只支持 Teams 注册登录
- 隧道与代理统一由 `warp-plus` 提供
- 启动阶段必须先拿到可用 SOCKS 出口，再标记 runtime ready
- 运行期恢复策略固定为“连续失败后重启容器”

## 读代码顺序

建议按下面顺序看：

1. `entrypoint.sh`
2. `lib/app/main.sh`
3. `lib/domain/account.sh`
4. `lib/domain/wireguard.sh`
5. `lib/runtime/tunnel.sh`
6. `lib/runtime/recovery.sh`
