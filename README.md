# warp-socks

一个只做一件事的 WARP SOCKS5 Docker 方案：用 Cloudflare Teams registration token 注册一次，生成 WireGuard 配置，然后稳定提供一个本机可访问的 SOCKS5 出口。

当前版本明确不再支持多后端选择，也不再暴露大批运行时调参开关。

对外只保留一组很小的配置面：

核心配置：

- `TEAMS_TOKEN`
- `HOST_BIND_IP`
- `HOST_BIND_PORT`
- `ENDPOINT_CANDIDATES`

标准运行配置：

- `RESTART_POLICY`
- `LOG_TIMEZONE`
- `LOG_TIME_FORMAT`
- `MICROSOCKS_LOG_ACCESS`
- `MICROSOCKS_LOG_LOCAL_CLIENTS`

## 快速开始

1. 复制模板：

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

4. 看日志：

```bash
docker compose logs -f
```

5. 验证：

```bash
docker exec warp-socks curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

正常情况下应至少看到 `warp=on`；Teams 路径通常还会带 `gateway=on`。

## 设计边界

从第一性原理看，这个仓库只需要三段逻辑：

1. `TEAMS_TOKEN -> account.json`
2. `account.json -> wg0.conf`
3. `wg0 + healthcheck + microsocks`

因此当前实现里：

- `account.json` 是唯一真实账户状态
- `wg0.conf` 是派生文件
- 如果 `account.json` 已存在，就直接复用
- 如果你想重建状态，就删除 `./wireguard/account.json` 和 `./wireguard/wg0.conf`
- `ENDPOINT_CANDIDATES` 默认留空；只有当默认 endpoint 在你当前网络环境里不稳定时，再显式配置候选池

## 运行说明

- 容器内 SOCKS5 固定监听 `0.0.0.0:1080`
- 宿主机入口由 `HOST_BIND_IP:HOST_BIND_PORT` 决定
- 默认只监听 `127.0.0.1:1080`
- `microsocks` 无认证，不建议直接暴露到公网

启动阶段会先拉起 `wg0`，再做出口探测；只有探测成功后才启动 `microsocks`。如果启动阶段没有拿到出口 IP，容器会直接退出，交给 Docker 重启，而不是留下一个假可用端口。

运行期健康检查只做一件事：通过本地 SOCKS5 访问 `https://cloudflare.com/cdn-cgi/trace`，确认出口仍然是 WARP。如果连续失败，healthcheck 会请求 PID 1 主动退出容器，让 Docker 重新拉起新实例。

如果你配置了多个 endpoint 候选，启动阶段会按顺序逐个重建 `wg0.conf` 并逐个测试；运行期异常重启后，新实例会再次从候选列表头部开始尝试。这样保留了“多个 IP 轮换测试”的能力，但仍然维持单一 Teams 主链和简单恢复模型。只填一个时，就等价于固定单个 endpoint；留空时则直接使用 Teams 返回的默认 endpoint。

日志时间格式和 microsocks 访问日志也保留成了少量标准运行配置：

- `LOG_TIMEZONE` / `LOG_TIME_FORMAT` 控制容器内脚本日志时间格式
- `MICROSOCKS_LOG_ACCESS=0` 时完全关闭 microsocks 连接日志
- `MICROSOCKS_LOG_LOCAL_CLIENTS=1` 时显示本地 `127.0.0.1` / `::1` 探测流量，便于排障

入口在复用或新建 `account.json` 后，会自动清理旧模型遗留的 `state.json` 和 `wgcf-*` 文件；因此完成一次新的 Teams 启动后，`./wireguard` 会自然收敛到当前模型。

## 获取 Teams Token

`TEAMS_TOKEN` 推荐直接填完整的 `com.cloudflare.warp://...auth?token=...` 链接。

1. 打开：

```text
https://<team-name>.cloudflareaccess.com/warp
```

2. 完成登录。

3. 在开发者工具里找到：

```text
com.cloudflare.warp://<team-name>.cloudflareaccess.com/auth?token=...
```

4. 复制整条链接到 `.env`。

这类 token 时效很短，复制后尽量立刻启动。

## 故障排查

### 1. 容器起不来

先看：

```bash
docker compose logs --tail=80
```

最常见原因：

- `TEAMS_TOKEN` 为空
- token 已过期
- Cloudflare 返回 `429 Too Many Requests`

当前实现遇到 `429` 时会按线性退避重试，并尊重服务端 `Retry-After`，避免立刻重启后继续撞接口。

### 2. 代理端口有了，但没有流量

先看：

```bash
docker compose logs --tail=120
docker inspect --format '{{json .State.Health.Log}}' warp-socks
```

重点关注：

- `当前出口 IP: ...`
- `远端解析路径探测失败`
- `本地解析路径也失败`

如果默认 endpoint 在你当前网络环境里经常握手失败，可以在 `.env` 里设置：

```env
ENDPOINT_CANDIDATES=ip1:port,ip2:port,ip3:port
```

每次候选切换时，入口脚本都会重新从 `account.json` 生成一份新的 `wg0.conf`，而不是在旧文件上继续打补丁。

### 3. 想重建状态

```bash
rm -f wireguard/account.json wireguard/wg0.conf
docker compose up --build -d
```

这次成功启动也会顺手清掉旧的历史文件。

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
