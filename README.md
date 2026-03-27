# warp-socks

一个轻量的 WARP SOCKS5 Docker 方案，保持 `Alpine + WireGuard + microsocks` 结构，并支持三种注册后端：

- `teams`
- `wgcf-free`
- `wgcf-plus`

默认 `AUTH_MODE=auto`，优先级是：

```text
TEAMS_TOKEN > WARP_LICENSE_KEY > free
```

首次启动时，容器会按当前后端生成并持久化配置到 `./wireguard`；后续重启直接复用已有状态。

仓库已包含 `.dockerignore`，默认会把 `.git`、`.env`、`wireguard/` 等本地敏感或无关内容排除在 Docker build context 之外。

## 快速开始

1. 复制环境变量模板：

```bash
cp .env.example .env
```

2. 编辑 `.env`，按需要选择一种模式。

Teams：

```env
AUTH_MODE=teams
TEAMS_TOKEN=com.cloudflare.warp://<your-team>.cloudflareaccess.com/auth?token=<your-token>
```

WARP+：

```env
AUTH_MODE=wgcf-plus
WARP_LICENSE_KEY=<your-warp-plus-license-key>
```

免费模式：

```env
AUTH_MODE=wgcf-free
```

自动模式：

```env
AUTH_MODE=auto
```

3. 启动：

```bash
docker compose up --build -d
```

4. 查看日志：

```bash
docker compose logs -f
```

5. 查看容器健康状态：

```bash
docker compose ps
```

启动阶段现在会先探测公网出口：只有在拿到出口 IP 后才会启动 `microsocks`；如果连续探测失败，容器会直接退出，交给 Docker 按 `restart` 策略重试，而不是起一个实际上不可用的 SOCKS5 端口。

镜像还内置了一个极简 `HEALTHCHECK`：它会在容器内通过本地 SOCKS5 访问 `https://cloudflare.com/cdn-cgi/trace`，并检查是否返回 `warp=on` 或 `warp=plus`。默认情况下，连续失败达到阈值后它会终止容器主进程，交给 Docker 按 `restart` 策略自动拉起容器并重建隧道；如果你只想观测不恢复，可设置 `HEALTHCHECK_AUTO_RECOVER=0`。

当前 `compose.yaml` 还内置了三类运行保护：

- 基础资源限制：默认 `MEM_LIMIT=256m`、`CPU_LIMIT=0.50`
- 容器日志滚动：默认 `json-file`，`LOG_MAX_SIZE=1m`、`LOG_MAX_FILE=1`
- 启动出口探测：默认 `STARTUP_EGRESS_PROBE_RETRIES=3`、`STARTUP_EGRESS_PROBE_DELAY=2`、`STARTUP_EGRESS_PROBE_TIMEOUT=5`

这两类限制都可以通过 `.env` 覆盖。

6. 验证代理：

```bash
curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

正常情况下：

- 所有模式都至少应返回 `warp=on`
- `teams` 模式通常还会返回 `gateway=on`

## 安全边界

`microsocks` 是无认证 SOCKS5 代理。默认端口映射保持在 `127.0.0.1:1080 -> 1080`，这是推荐配置。

如果你把 `HOST_BIND_IP=0.0.0.0`，就等于把未鉴权代理直接暴露给外部网络。除非你已经有额外 ACL / 防火墙限制，并且明确接受出口被滥用的风险，否则不要这样做。

<details>
<summary><strong>获取 Teams Token</strong></summary>

<br>

`TEAMS_TOKEN` 推荐直接填完整的 `com.cloudflare.warp://...auth?token=...` 链接；如果你只复制了后面的 JWT，脚本也会自动归一化。

1. 在一台能打开网页的机器上访问：

```text
https://<team-name>.cloudflareaccess.com/warp
```

2. 按组织要求完成登录。

3. 登录成功后，打开浏览器开发者工具：
   `Option + Command + I` 或 `F12`

4. 找到类似下面这一整段链接：

```text
com.cloudflare.warp://<team-name>.cloudflareaccess.com/auth?token=...
```

5. 把整条 `com.cloudflare.warp://...` 复制到 `.env` 的 `TEAMS_TOKEN=`。

6. 这类 token 时效很短，通常只有约 1 分钟。复制后尽量立刻启动容器。

</details>

<details>
<summary><strong>关键说明</strong></summary>

<br>

### 1. 凭据与注册

- `registration token` 是短时效凭据，只用于首次注册。
- `WARP_LICENSE_KEY` 只在首次 `wgcf-plus` 注册或你主动更新绑定时需要；成功后会随着本地持久化状态一起复用。
- `wgcf-plus` 走的是社区 `wgcf` 工具链，不是 Cloudflare 官方 `warp-cli registration license` 容器化封装。
- 在已有可复用持久化状态时，`AUTH_MODE=auto` 会优先复用当前后端；`AUTH_MODE=teams` / `wgcf-plus` 也不再强制要求重复提供首次注册时的凭据。

### 2. 运行与安全

- 运行状态会持久化到 `./wireguard`；目录里包含私钥和账户信息，`.env` 里可能包含短时效 token，两者都不要提交到版本库。
- 默认端口映射是 `127.0.0.1:1080 -> 1080`，除非你已经有明确的网络访问控制，否则不要改成 `HOST_BIND_IP=0.0.0.0`。
- `ENDPOINT_IP` 默认建议留空；只有在默认端点握手失败，或者你所在网络环境明确只能稳定握手某个固定 endpoint 时，才手动覆盖。
- 启动阶段会先做公网出口探测；如果连续探测都拿不到出口 IP，容器会直接退出并等待 Docker 重试，不会继续启动一个不可用的 SOCKS5 端口。
- 当前仓库只有一个服务，Compose 默认网络已经足够；因此 `compose.yaml` 没有额外声明自定义 `networks`，避免增加无运行收益的配置面。

### 3. 阅读路径

- 后端切换、旧状态目录兼容和 `FORCE_REREGISTER=1` 的使用方式见下方“状态与后端切换”。
- 健康检查的恢复语义和固定 endpoint 的排障顺序见下方“故障排查”。

</details>

<details>
<summary><strong>故障排查</strong></summary>

<br>

### 1. 容器起不来

先看：

```bash
docker compose logs --tail=80
```

重点关注以下报错：

- `AUTH_MODE=teams 时必须提供 TEAMS_TOKEN`
- `AUTH_MODE=wgcf-plus 时必须提供 WARP_LICENSE_KEY`
- `当前持久化状态后端为 ...，请求后端为 ...`

这类错误通常不是网络故障，而是当前环境变量与 `./wireguard` 里的已有状态不一致。

### 2. 健康检查失败

先看容器状态：

```bash
docker compose ps
```

如果不是 `healthy`，再看日志：

```bash
docker compose logs --tail=120
```

当前健康检查默认会在连续失败达到阈值后触发一次容器重启，以便重新建立隧道；如果你把 `HEALTHCHECK_AUTO_RECOVER=0`，它就只负责探测。常见原因包括：

- `wg0` 没拉起来
- 注册后端状态与当前请求不一致
- 启动阶段的出口探测连续失败，容器已经提前退出等待重试
- 固定 endpoint 当前网络不可达或短时抖动
- 代理端口虽然在监听，但出口已经失效

日志里重点看两类线索：

- `远端解析路径探测失败`
- `本地解析路径也失败`

### 3. 代理端口能连，但访问失败

先在宿主机确认：

```bash
curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

如果没有看到 `warp=on`，继续看容器日志里的两类线索：

- `已覆盖 Endpoint 为 ...`
- `当前出口 IP: ...`

如果日志里已经显示启动成功，但流量仍失败，优先怀疑当前 endpoint 不适合你的网络环境。反过来，如果启动阶段连续报“出口探测未获取到 IP”并最终退出，那一般就不要再把问题归到 SOCKS5 本身，而应直接排查隧道和 endpoint。

### 4. endpoint 选择建议

`ENDPOINT_IP` 默认更适合排障时临时覆盖；但如果你所在网络环境明确只能握手某个固定 endpoint，也可以常驻配置。当前这台机器上，`162.159.193.7:2408` 已实测可用，因此 `.env.example` 里保留了注释示例。

建议顺序：

1. 能走默认 endpoint 就优先留空 `ENDPOINT_IP`
2. 如果当前网络已知只有固定端点可用，再设置 `ENDPOINT_IP=ip:port`
3. 如果必须常驻固定 endpoint，建议保持 `HEALTHCHECK_AUTO_RECOVER=1`
4. 如果启动阶段经常拿不到出口 IP，可先调大 `STARTUP_EGRESS_PROBE_RETRIES` / `STARTUP_EGRESS_PROBE_DELAY`
5. 如果仍频繁掉线，再考虑第二阶段的多 endpoint 轮换

### 5. 后端切换导致的问题

如果报错里已经出现“当前持久化状态后端为 ...，请求后端为 ...”，或者你本来就在做后端迁移，不要在这里反复重启，直接看下一节“状态与后端切换”。

</details>

<details>
<summary><strong>状态与后端切换</strong></summary>

<br>

`./wireguard` 不是示例目录，而是活的运行状态目录。首次启动成功后，当前后端的关键状态会落在这里，例如：

- `wg0.conf`
- `state.json`
- `account.json` 或 `wgcf-*`

这意味着你不能只改 `.env` 里的 `AUTH_MODE` 就指望无缝切换后端。当前仓库支持：

- `teams`
- `wgcf-free`
- `wgcf-plus`

一旦某个后端已经写入 `./wireguard`，后续重启会优先复用这套状态。如果当前请求后端和持久化后端不一致，入口脚本会拒绝启动。

只有在下面几类场景里才建议开启 `FORCE_REREGISTER=1`：

- 你确定要从 `teams` 切到 `wgcf-*`
- 你确定要从 `wgcf-free` 切到 `wgcf-plus`
- 当前持久化状态已经不可用，想重建

建议操作顺序：

1. 确认当前 `AUTH_MODE`、`TEAMS_TOKEN`、`WARP_LICENSE_KEY`
2. 备份 `./wireguard`
3. 设置 `FORCE_REREGISTER=1`
4. `docker compose up --build -d`
5. 验证健康状态和代理出口
6. 确认成功后，把 `FORCE_REREGISTER` 改回 `0`

如果你带着老的 `wgcf` 状态目录迁移过来，而目录里没有 `state.json`，`auto` 模式可能无法判断它属于 `wgcf-free` 还是 `wgcf-plus`。这种情况下应显式设置 `AUTH_MODE`，必要时直接重建状态。

</details>

## 常用变量

- `AUTH_MODE=auto|teams|wgcf-free|wgcf-plus`
- `TEAMS_TOKEN`
- `WARP_LICENSE_KEY`
- `FORCE_REREGISTER=0|1`
- `WARP_STACK=ipv4|dual|ipv6`
- `ENDPOINT_IP=ip:port`
- `STARTUP_EGRESS_PROBE_RETRIES`
- `STARTUP_EGRESS_PROBE_DELAY`
- `STARTUP_EGRESS_PROBE_TIMEOUT`
- `MEM_LIMIT`
- `CPU_LIMIT`
- `LOG_MAX_SIZE`
- `LOG_MAX_FILE`
- `HEALTHCHECK_AUTO_RECOVER=0|1`
- `HEALTHCHECK_AUTO_RECOVER_THRESHOLD`
- `HOST_BIND_IP`
- `HOST_BIND_PORT`
- `RESTART_POLICY=unless-stopped|no`

## 边界
- 当前目录提供的是轻量 WireGuard 路线，目标是稳定提供一个可用的 SOCKS5 出口。
