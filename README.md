# warp-socks

一个面向单机部署的 WARP SOCKS5 Docker 方案：使用 Cloudflare Teams registration token 注册一次，生成 WireGuard 配置，然后稳定提供一个本机可访问的 SOCKS5 出口。

当前版本明确只支持 Teams，不再支持多后端模式，也不暴露大批运行时调参开关。

## 特性

- Teams-only：单一注册链路，减少兼容复杂度
- 薄状态模型：`account.json` 是唯一账户状态，`wg0.conf` 是派生文件
- 启动期硬门禁：隧道未拿到 WARP 出口前，不启动 SOCKS5
- 运行期自恢复：healthcheck 只判定失败，PID 1 负责退出容器交给 Docker 拉起
- endpoint 记忆：记录最近一次成功的 endpoint，并对连续失败的 endpoint 做临时冷却
- 小配置面：默认只需要一个 `TEAMS_TOKEN`

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

### 核心配置

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `TEAMS_TOKEN` | 是 | Cloudflare Teams registration token，推荐直接填完整 `com.cloudflare.warp://...auth?token=...` 链接 |
| `HOST_BIND_IP` | 否 | 宿主机发布地址，默认 `127.0.0.1` |
| `HOST_BIND_PORT` | 否 | 宿主机发布端口，默认 `1080` |
| `ENDPOINT_CANDIDATES` | 否 | 手工覆盖 endpoint 列表；留空时使用项目内置候选池 |

### 标准运行配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RESTART_POLICY` | `unless-stopped` | Docker 重启策略 |
| `LOG_TIMEZONE` | `CST-8` | 容器日志时区 |
| `LOG_TIME_FORMAT` | `%Y-%m-%d %H:%M:%S %Z` | 容器日志时间格式 |
| `MICROSOCKS_LOG_ACCESS` | `1` | 是否输出 microsocks 连接日志 |
| `MICROSOCKS_LOG_LOCAL_CLIENTS` | `0` | 是否显示本地 `127.0.0.1` / `::1` 探测流量 |

## Endpoint 策略

`ENDPOINT_CANDIDATES` 是唯一手工覆盖入口。

- 如果你显式填写了 `ENDPOINT_CANDIDATES`，启动阶段会按你给定的顺序逐个尝试。
- 如果你留空，启动阶段会使用项目内置的实测候选池：
  - `162.159.193.5:2408`
  - `162.159.193.9:2408`
  - `162.159.193.8:2408`
  - `162.159.193.3:2408`
  - `162.159.193.7:2408`

运行期如果 healthcheck 连续失败达到阈值，当前 active endpoint 会被临时标记为冷却；容器重启后，启动链会优先尝试最近一次成功的 endpoint，并把进入冷却的 endpoint 排到后面。内部恢复状态会持久化到 `./wireguard/endpoint-state.json`。

## 运行模型

当前实现的主链只有三段：

1. `TEAMS_TOKEN -> account.json`
2. `account.json -> wg0.conf`
3. `wg0 + healthcheck + microsocks`

对应边界也很简单：

- `account.json` 是唯一真实账户状态
- `wg0.conf` 是派生文件
- 启动阶段先拉起 `wg0`，再探测 WARP 出口，成功后才启动 `microsocks`
- 运行期健康检查只负责判定失败和写重启请求，不直接做修复动作
- PID 1 监督者收到重启请求后退出容器，再交给 Docker 重新拉起

容器内 SOCKS5 固定监听 `0.0.0.0:1080`，宿主机入口由 `HOST_BIND_IP:HOST_BIND_PORT` 决定。默认只监听 `127.0.0.1:1080`。`microsocks` 是无认证 SOCKS5，不建议直接暴露到公网。

入口在复用或新建 `account.json` 后，会自动清理旧模型遗留的 `state.json` 和 `wgcf-*` 文件；完成一次新的 Teams 启动后，`./wireguard` 会自然收敛到当前模型。

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

当前实现遇到 `429` 时会按线性退避重试，并尊重服务端 `Retry-After`，避免容器立刻重启后继续撞接口。

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
    sysctls:
      net.ipv4.conf.all.src_valid_mark: '1'
    ports:
      - '${HOST_BIND_IP:-127.0.0.1}:${HOST_BIND_PORT:-1080}:1080'
    volumes:
      - ./wireguard:/etc/wireguard
    env_file:
      - .env
```
