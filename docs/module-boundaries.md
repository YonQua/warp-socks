# 模块边界

这份文档只描述当前 shell 实现怎么组织，不讨论历史方案，也不讨论未来迁移语言。

## 主链路

当前启动链固定为：

1. `TEAMS_TOKEN -> account.json`
2. `account.json -> wg0.conf`
3. `wg-quick up wg0`
4. 出口探测通过后启动 `microsocks`
5. 运行期 healthcheck 连续失败达到阈值后，请求容器重启

## 状态文件

- `wireguard/account.json`
  - Teams 注册结果
  - 唯一账户状态来源

- `wireguard/wg0.conf`
  - 由 `account.json` 和 endpoint 派生
  - 当前运行中的 endpoint 以它为准

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
  - `wg0` 生命周期、旁路网络、`microsocks` 监督、healthcheck 恢复

## 当前约束

- 只支持 Teams 注册
- 只支持通过外部命令驱动 WireGuard 和 SOCKS5
- 启动阶段必须先拿到可用出口，再开放代理
- 运行期恢复策略固定为“连续失败后重启容器”

## 读代码顺序

建议按下面顺序看：

1. `entrypoint.sh`
2. `lib/app/main.sh`
3. `lib/domain/account.sh`
4. `lib/domain/wireguard.sh`
5. `lib/runtime/network.sh`
6. `lib/runtime/socks.sh`
7. `lib/runtime/recovery.sh`
