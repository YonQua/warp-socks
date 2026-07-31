# warp-socks

一个面向单机部署的 WARP SOCKS5 Docker 方案：用 Cloudflare Teams registration token 注册一次，然后稳定提供一个本机可访问的 SOCKS5 出口。

主链路：`TEAMS_TOKEN -> account.json -> wg0.conf -> 隧道进程（userspace WireGuard + SOCKS5）`

1. `TEAMS_TOKEN -> account.json`（首次启动注册，之后重启直接复用）
2. `account.json -> wg0.conf`
3. 隧道进程起进程（userspace WireGuard + 内置 SOCKS5）
4. 经 SOCKS5 出口探测通过（`warp=on`）后进入运行态
5. 运行期 healthcheck 连续失败达到阈值后，请求容器重启

说明：不再使用内核 `wg-quick` / `microsocks`。在中国等网络环境下，内核 WireGuard 常卡在 `0 B received`；当前实现改用带 WARP tricks 的 userspace 客户端。

隧道与 SOCKS5 由本项目自研的 Rust 实现提供（仓库根 `src/`，参考 bepass-org/warp-plus 思路重写，同一份 `wg0.conf` 格式、同样的 reserved bytes/trick 反审查机制）。

当前状态和恢复规则也很简单：

- `account.json` 是唯一账户状态，`wg0.conf` 是当前运行配置，也是 healthcheck 恢复时读取当前 endpoint 的唯一来源
- `endpoint-state.json` 只保存 `last_good_endpoint` 和 cooldown
- 启动阶段失败直接退出，由 Docker 重启容器
- 运行期失败达到阈值后写入重启请求，由 PID 1 主动退出

隧道、SOCKS5、注册、健康探测、候选编排均已收口到自研的 `warp-socks-rs` 单一二进制（`src/`），子命令划分：

- `warp-socks serve`（默认）：`Supervisor`（`src/supervisor.rs`）常驻编排注册确认、endpoint 候选尝试、SOCKS5 服务与运行期健康检查
- `warp-socks register reg/del <path>`：MASQUE 凭据注册/注销
- `warp-socks healthcheck`：Docker HEALTHCHECK 用的无状态单次探测

容器入口只有 `entrypoint.sh`（直接 `exec warp-socks-rs "$@"`）。

对应说明见 [docs/module-boundaries.md](docs/module-boundaries.md)。

## 快速开始

1. 复制模板并编辑 `.env`：

```bash
cp .env.example .env
```

2. 填入 Teams registration token：

```env
TEAMS_TOKEN=com.cloudflare.warp://<your-team>.cloudflareaccess.com/auth?token=<your-token>
```

3. 启动：

```bash
docker compose up --build -d
```

4. 查看日志：

```bash
docker compose logs -f
```

5. 验证代理：

```bash
docker exec warp-socks curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

正常情况下应至少看到 `warp=on`，通常还会带 `gateway=on`。

## 配置

### 常用参数

| 变量                      | 必填                   | 说明                                                                                               |
| ------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------- |
| `TEAMS_TOKEN`             | 首次启动必填           | Cloudflare Teams registration token，推荐直接填完整 `com.cloudflare.warp://...auth?token=...` 链接。已有 `wireguard/account.json` 后重启可以留空 |
| `HOST_BIND_IP`          | 否                     | 宿主机发布地址，默认 `127.0.0.1`                                                                   |
| `HOST_BIND_PORT`        | 否                     | 宿主机发布端口，默认 `1080`                                                                        |
| `ENDPOINT_CANDIDATES`   | 否                     | 手工覆盖 endpoint 列表；留空时使用项目内置候选池                                                   |
| `RESTART_POLICY`        | `unless-stopped`       | Docker 重启策略                                                                                    |
| `RUST_LOG`              | `info`                 | 日志级别（`env_logger` 标准语法），默认 `info` 已包含连接建立/失败、隧道后端（MASQUE/WireGuard）等关键信息；调试可设 `RUST_LOG=debug` |

### 高级调优参数

| 变量                                       | 默认值 | 说明                                   |
| ------------------------------------------ | ------ | -------------------------------------- |
| `WARP_SOCKS_REGISTER_RETRIES`              | `2`    | Teams 注册最大尝试次数                 |
| `WARP_SOCKS_REGISTER_RETRY_DELAY`          | `2`    | Teams 注册失败后的基础重试间隔秒数     |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY`    | `1`    | 启动阶段两次探测之间的间隔秒数         |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT`  | `5`    | 单次启动阶段 SOCKS 出口探测超时秒数    |
| `WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT`   | `20`   | 启动阶段等待隧道+SOCKS 就绪的总秒数    |
| `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT`     | 派生值（约 63，见下方说明） | 运行期单次健康检查探测超时秒数         |
| `WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` | `3`    | 运行期连续失败达到多少次后请求容器重启 |
| `WARP_RS_TRICK`                            | `none` | 反审查伪装包模式，`none`/`t1`/`t2` |
| `WARP_SOCKS_ENABLE_MASQUE`                 | `0`    | 开启后自动确保 `reg.json` 存在（缺失则在进程内直接完成注册），warp-socks-rs 优先走 MASQUE，失败仍回退 WireGuard；关闭时行为与不开启完全一致 |

### 启动等待调优建议

如果你觉得启动或重试等待偏长，建议先用下面这组偏积极的参数：

```env
WARP_SOCKS_REGISTER_RETRIES=2
WARP_SOCKS_REGISTER_RETRY_DELAY=1
WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY=1
WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT=4
WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT=15
WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD=2
```

说明：

- userspace 握手通常 3~8 秒，遇到重试可能到 15 秒以上；`WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT` 是这段总等待时间，不建议低于 `15`。
- `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT` 不建议手工调低：探测走的是和真实业务连接相同的路径，隧道自身的自愈重连（MASQUE 侧的 `open()`）需要完整跑完才能拿到真实结果；调低到低于隧道自愈预算，会把"正在自愈"误判成"探测失败"，反而更容易触发不必要的容器重启。默认值已经从隧道自愈预算自动派生，一般不需要覆盖。
- `WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` 是运行期恢复的唯一连续失败阈值来源；Docker `HEALTHCHECK` 只负责定时触发，不再叠加第二层 `retries` 语义。
- 注册链路遇到 `429` 时仍会尊重服务端 `Retry-After`，这部分不会被本地更小的 delay 强行覆盖。

## Endpoint 策略

`ENDPOINT_CANDIDATES` 是唯一手工覆盖入口。

- 如果你显式填写了 `ENDPOINT_CANDIDATES`，启动阶段会按你给定的顺序逐个尝试。
- 如果你留空，启动阶段会使用项目内置候选池（含官方主入口与少量补充）：
  - `162.159.193.5:2408`
  - `162.159.193.9:2408`
  - `162.159.193.8:2408`
  - `162.159.193.3:2408`
  - `162.159.193.7:2408`
  - `162.159.193.47:2408`
  - `162.159.192.1:2408`
  - `162.159.195.1:2408`

运行期如果 healthcheck 连续失败达到阈值，当前 endpoint 会被临时标记为冷却；容器重启后，启动链会优先尝试最近一次成功的 endpoint，并把进入冷却的 endpoint 排到后面。内部恢复状态会持久化到 `./wireguard/endpoint-state.json`。

启动阶段会按顺序逐个尝试候选，单个候选最坏耗时约为 `WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT` 秒；默认候选池 8 个时，全部失败的最坏总耗时约 `8 × 20s ≈ 160` 秒，之后由 Docker 按 `RESTART_POLICY` 重启容器重试。这段等待期间容器还没有标记 runtime ready，healthcheck 不会介入，不会被误判为不健康。

容器内 SOCKS5 固定监听 `0.0.0.0:1080`，宿主机入口由 `HOST_BIND_IP:HOST_BIND_PORT` 决定。默认只监听 `127.0.0.1:1080`。当前 SOCKS5 无认证，不建议直接暴露到公网。

入口在复用或新建 `account.json` 后，会自动清理旧模型遗留的 `state.json` 和 `wgcf-*` 文件。

## 获取 Teams Token

`TEAMS_TOKEN` 推荐直接填完整的 `com.cloudflare.warp://...auth?token=...` 链接。

1. 打开 `https://<team-name>.cloudflareaccess.com/warp`
2. 完成登录
3. 在开发者工具里找到：

```text
com.cloudflare.warp://<team-name>.cloudflareaccess.com/auth?token=...
```

4. 把整条链接复制到 `.env`

这类 token 时效很短，复制后尽量立刻启动。

## 故障排查

### 容器起不来

先看：

```bash
docker compose logs --tail=80
```

最常见原因：

- `TEAMS_TOKEN` 为空且 `./wireguard` 下也没有可复用的 `account.json`
- Teams token 已过期
- Cloudflare 返回 `429 Too Many Requests`

Teams 注册链路遇到 `429` 时会按线性退避重试，并尊重服务端 `Retry-After`。

### 代理端口有了，但没有流量

先看：

```bash
docker compose logs --tail=120
docker inspect --format '{{json .State.Health.Log}}' warp-socks
```

重点关注：

- `当前出口 IP: ...`
- `启动后第 ... 次探测未通过: ...`
- `SOCKS 出口探测失败: ...`

如果你已经知道一组更适合当前网络环境的 endpoint，可以在 `.env` 里显式设置：

```env
ENDPOINT_CANDIDATES=ip1:port,ip2:port,ip3:port
```

### 想重建状态

```bash
rm -f wireguard/account.json wireguard/wg0.conf wireguard/endpoint-state.json
docker compose up --build -d
```

## 预构建镜像

发布版本会同步到 `ghcr.io/yonqua/warp-socks`。建议固定 tag，不要长期跟 `latest`。

```yaml
services:
  warp-socks:
    image: ghcr.io/yonqua/warp-socks:latest
    container_name: warp-socks
    restart: unless-stopped
    ports:
      - '${HOST_BIND_IP:-127.0.0.1}:${HOST_BIND_PORT:-1080}:1080'
    volumes:
      - ./wireguard:/etc/wireguard
    env_file:
      - .env
```
