# warp-socks

一个面向单机部署的 WARP SOCKS5 Docker 方案：使用 Cloudflare Teams registration token 注册一次，生成 WireGuard 配置，然后稳定提供一个本机可访问的 SOCKS5 出口。

当前实现只支持 Teams。

## 概览

当前实现的固定主链是：

1. `TEAMS_TOKEN -> account.json`
2. `account.json -> wg0.conf`
3. `wg-quick up wg0`
4. 出口探测通过后启动 `microsocks`
5. 运行期 healthcheck 连续失败达到阈值后，请求容器重启

当前状态和恢复规则也很简单：

- `account.json` 是唯一账户状态
- `wg0.conf` 是当前运行配置，也是当前 endpoint 的真相源
- `endpoint-state.json` 只保存 `last_good_endpoint` 和 cooldown
- 启动阶段失败直接退出，由 Docker 重启容器
- 运行期失败达到阈值后写入重启请求，由 PID 1 主动退出

当前目录按职责拆成四层：

- `lib/core/`：日志、错误、工具、探测、endpoint 状态
- `lib/domain/`：Teams 注册、endpoint 候选、WireGuard 配置
- `lib/runtime/`：`wg0`、旁路网络、`microsocks`、healthcheck 恢复
- `lib/app/`：环境装配与主流程

入口文件只有两个：

- `entrypoint.sh`
- `healthcheck/check-socks5.sh`

对应说明见 [docs/module-boundaries.md](docs/module-boundaries.md)。

## 快速开始

1. 复制模板并编辑 `.env`：

```bash
cp .env.example .env
```

2. 填入一个新的 Teams token：

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

正常情况下应至少看到 `warp=on`；Teams 路径通常还会带 `gateway=on`。

## 配置

### 常用参数

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `TEAMS_TOKEN` | 是 | Cloudflare Teams registration token，推荐直接填完整 `com.cloudflare.warp://...auth?token=...` 链接 |
| `HOST_BIND_IP` | 否 | 宿主机发布地址，默认 `127.0.0.1` |
| `HOST_BIND_PORT` | 否 | 宿主机发布端口，默认 `1080` |
| `ENDPOINT_CANDIDATES` | 否 | 手工覆盖 endpoint 列表；留空时使用项目内置候选池 |
| `RESTART_POLICY` | `unless-stopped` | Docker 重启策略 |
| `LOG_TIMEZONE` | `CST-8` | 容器日志时区 |
| `LOG_TIME_FORMAT` | `%Y-%m-%d %H:%M:%S %Z` | 容器日志时间格式 |
| `MICROSOCKS_LOG_ACCESS` | `1` | 是否输出 microsocks 连接日志 |
| `MICROSOCKS_LOG_LOCAL_CLIENTS` | `0` | 是否显示本地 `127.0.0.1` / `::1` 探测流量 |

### 高级调优参数

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WARP_SOCKS_REGISTER_RETRIES` | `2` | Teams 注册最大尝试次数 |
| `WARP_SOCKS_REGISTER_RETRY_DELAY` | `2` | Teams 注册失败后的基础重试间隔秒数 |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_RETRIES` | `2` | 启动阶段出口探测最大次数 |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY` | `1` | 启动阶段探测失败后的等待秒数 |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT` | `3` | 单次启动阶段出口探测超时秒数 |
| `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT` | `4` | 运行期单次健康检查探测超时秒数 |
| `WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` | `3` | 运行期连续失败达到多少次后请求容器重启 |

### 启动等待调优建议

如果你觉得启动或重试等待偏长，建议先用下面这组偏积极的参数：

```env
WARP_SOCKS_REGISTER_RETRIES=2
WARP_SOCKS_REGISTER_RETRY_DELAY=1
WARP_SOCKS_STARTUP_EGRESS_PROBE_RETRIES=2
WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY=1
WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT=2
WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT=3
WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD=2
```

说明：

- 如果你的网络偶发抖动较多，`WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT` 不建议低于 `2`。
- `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT` 决定运行期故障判定速度；调低后恢复更快，但误判概率也会上升。
- `WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` 是运行期恢复的唯一连续失败阈值来源；Docker `HEALTHCHECK` 只负责定时触发，不再叠加第二层 `retries` 语义。
- 注册链路遇到 `429` 时仍会尊重服务端 `Retry-After`，这部分不会被本地更小的 delay 强行覆盖。

## Endpoint 策略

`ENDPOINT_CANDIDATES` 是唯一手工覆盖入口。

- 如果你显式填写了 `ENDPOINT_CANDIDATES`，启动阶段会按你给定的顺序逐个尝试。
- 如果你留空，启动阶段会使用项目内置的实测候选池：
  - `162.159.193.5:2408`
  - `162.159.193.9:2408`
  - `162.159.193.8:2408`
  - `162.159.193.3:2408`
  - `162.159.193.7:2408`

运行期如果 healthcheck 连续失败达到阈值，当前 `wg0.conf` 里的 endpoint 会被临时标记为冷却；容器重启后，启动链会优先尝试最近一次成功的 endpoint，并把进入冷却的 endpoint 排到后面。内部恢复状态会持久化到 `./wireguard/endpoint-state.json`。

容器内 SOCKS5 固定监听 `0.0.0.0:1080`，宿主机入口由 `HOST_BIND_IP:HOST_BIND_PORT` 决定。默认只监听 `127.0.0.1:1080`。`microsocks` 是无认证 SOCKS5，不建议直接暴露到公网。

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

- `TEAMS_TOKEN` 为空
- token 已过期
- Cloudflare 返回 `429 Too Many Requests`

当前实现遇到 `429` 时会按线性退避重试，并尊重服务端 `Retry-After`。

### 代理端口有了，但没有流量

先看：

```bash
docker compose logs --tail=120
docker inspect --format '{{json .State.Health.Log}}' warp-socks
```

重点关注：

- `当前出口 IP: ...`
- `启动后第 ... 次出口探测未通过: ...`
- `远端解析路径探测失败`
- `本地解析路径也失败`

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
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    ports:
      - '${HOST_BIND_IP:-127.0.0.1}:${HOST_BIND_PORT:-1080}:1080'
    volumes:
      - ./wireguard:/etc/wireguard
    env_file:
      - .env
```
