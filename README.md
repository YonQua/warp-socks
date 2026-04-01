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

日志会给入口脚本、healthcheck、`wg-quick` / `wgcf` 输出以及 `microsocks` 连接日志统一补上时间戳，格式类似：

```text
2026-04-01 14:30:45 CST [microsocks][INFO][mode=teams] client[5] 10.10.10.4: connected to api.cloudflare.com:443
```

默认时区是东八区固定偏移 `CST-8`，不依赖镜像里额外安装 `tzdata`；同时每条格式化日志都会尽量带上当前后端模式，例如 `mode=teams`。根日志会省略 `warp-socks` 组件名，避免和 `docker compose logs` 左侧的服务名前缀叠加。如果你想改成别的时区或格式，可在 `.env` 里覆盖 `LOG_TIMEZONE` / `LOG_TIME_FORMAT`。

默认情况下，`microsocks` 会保留真实客户端连接日志，但隐藏容器内 `127.0.0.1` / `::1` 的本地探测流量，避免 healthcheck 把日志刷屏。如果你想完全关闭这类连接日志，可设置 `MICROSOCKS_LOG_ACCESS=0`；如果你排障时希望连本地探测也一起看，可设置 `MICROSOCKS_LOG_LOCAL_CLIENTS=1`。

5. 查看容器健康状态：

```bash
docker compose ps
```

启动阶段会先探测公网出口：只有在拿到出口 IP 后才会启动 `microsocks`；如果连续探测失败，容器会直接退出，交给 Docker 按 `restart` 策略重试，而不是起一个实际上不可用的 SOCKS5 端口。

镜像内置了一个极简 `HEALTHCHECK`：它会在容器内通过本地 SOCKS5 访问 `https://cloudflare.com/cdn-cgi/trace`，并检查是否返回 `warp=on` 或 `warp=plus`。默认情况下，连续失败达到阈值后它会终止容器主进程，交给 Docker 按 `restart` 策略自动拉起容器并重建隧道；如果你只想观测不恢复，可设置 `HEALTHCHECK_AUTO_RECOVER=0`。

默认配置还包含三类运行保护：

- 基础资源限制：默认 `MEM_LIMIT=256m`、`CPU_LIMIT=0.50`
- 容器日志滚动：默认 `json-file`，`LOG_MAX_SIZE=1m`、`LOG_MAX_FILE=1`
- 启动出口探测：默认 `STARTUP_EGRESS_PROBE_RETRIES=3`、`STARTUP_EGRESS_PROBE_DELAY=2`、`STARTUP_EGRESS_PROBE_TIMEOUT=5`

另外还有一组“本地网段旁路”默认值：会把当前容器主网段和常见私网网段放到 WARP 默认路由之前。大多数场景保持默认即可；如果你的网络结构比较特殊，才需要改 `LOCAL_BYPASS_INCLUDE_PRIMARY`、`LOCAL_BYPASS_IPV4_SUBNETS`、`LOCAL_BYPASS_IPV6_SUBNETS`。

这些参数都可以通过 `.env` 覆盖。

6. 验证代理：

```bash
# 默认 HOST_BIND_PORT=1080；如果你把它改成 2080，这里也要改成 2080
curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

正常情况下：

- 所有模式都至少应返回 `warp=on`
- `teams` 模式通常还会返回 `gateway=on`

## 预构建镜像

推送 `v*` tag 时，GitHub Actions 会自动做两件事：

- 发布 GHCR 镜像到 `ghcr.io/yonqua/warp-socks`
- 创建同名 GitHub Release

自动化范围到 tag 为止，版本号本身仍需要维护者显式决定；如果你是在别的 VPS 或配置仓库里复用它，建议显式写版本 tag，而不是长期跟随 `latest`。

例如，把 `compose.yaml` 里的 `build:` 换成 `image:`：

```yaml
services:
  warp-socks:
    image: ghcr.io/yonqua/warp-socks:v0.3.0
```

或者在外部配置里写成：

```env
WARP_SOCKS_IMAGE=ghcr.io/yonqua/warp-socks:v0.3.0
```

GHCR 只是分发层，不会替代运行时的 `.env`、`cap_add`、`./wireguard` 持久化状态和目标 VPS 的 WireGuard / iptables 能力。

## 端口与地址层级

端口映射关系是：

```text
HOST_BIND_IP:HOST_BIND_PORT:BIND_PORT
```

- `HOST_BIND_IP` / `HOST_BIND_PORT` 是宿主机入口，也是客户端真正要连接的地址与端口。
- `BIND_ADDR` / `BIND_PORT` 是容器内 `microsocks` 自己监听的地址与端口。
- 大多数场景只改 `HOST_BIND_PORT`，把宿主机入口从 `1080` 改成 `2080`；`BIND_ADDR` / `BIND_PORT` 保持默认即可。
- 例子：如果你配置 `HOST_BIND_IP=0.0.0.0`、`HOST_BIND_PORT=2080`、`BIND_ADDR=0.0.0.0`、`BIND_PORT=1080`，那么客户端应该连接 `socks5://宿主机IP:2080`；容器日志里显示“容器内监听 `0.0.0.0:1080`”是正常的。
- `BIND_ADDR` 通常必须保持 `0.0.0.0`。Docker 发布端口会把流量转发到容器网卡地址，而不是容器里的 `127.0.0.1`；如果把 `BIND_ADDR` 改成 `127.0.0.1`，宿主机映射端口通常无法把流量送进容器内的 `microsocks`。

## 安全边界

`microsocks` 是无认证 SOCKS5 代理。默认端口映射保持在 `127.0.0.1:1080 -> 容器 1080`，这是推荐配置。

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
- 默认端口映射是 `127.0.0.1:1080 -> 容器 1080`，除非你已经有明确的网络访问控制，否则不要改成 `HOST_BIND_IP=0.0.0.0`。
- `ENDPOINT_IP` 默认建议留空；只有在默认端点握手失败，或者你所在网络环境明确只能稳定握手某个固定 endpoint 时，才手动覆盖。
- 如果单个固定 endpoint 仍会抖动，可以改用 `ENDPOINT_CANDIDATES=ip1:port,ip2:port`；启动失败时会在同一次启动流程里按顺序尝试后续候选，运行中健康检查连续失败后则会重启容器，并重新按你写的顺序再尝试一轮。
- 仓库只认 `.env` 里的 `ENDPOINT_IP` / `ENDPOINT_CANDIDATES`，不再自动读取 `./wireguard/endpoint-candidates.txt` 这类隐式缓存文件。
- 启动阶段会先做公网出口探测；如果连续探测都拿不到出口 IP，容器会直接退出并等待 Docker 重试，不会继续启动一个不可用的 SOCKS5 端口。
- 日志会把入口脚本、healthcheck 与 `microsocks` / `wg-quick` 关键输出统一格式化为 `时间 [组件][级别][mode=后端] 消息`；其中根日志默认省略组件名，避免和 `docker compose logs` 左侧的 `warp-socks |` 重复。默认时区是 `CST-8`，这样即使容器已经停掉，也能直接从最后一条日志看出准确时间和当前运行模式。
- 默认会隐藏 `microsocks` 本地 `127.0.0.1` / `::1` 探测连接日志，减少 healthcheck 噪音；真实局域网或外部客户端连接仍会保留。
- 仓库只有一个服务，Compose 默认网络已经足够；因此 `compose.yaml` 没有额外声明自定义 `networks`，避免增加无运行收益的配置面。
- 启动时会动态读取 `wg-quick` 当前安装出来的策略路由优先级，把“当前容器主网段 + 默认私网/ULA 旁路网段”提前装到它前面，并清理旧的错误优先级残留，确保局域网客户端访问宿主机发布端口时，回包不会误入 WARP 默认路由。
- 这组旁路网段可以通过 `.env` 控制：`LOCAL_BYPASS_INCLUDE_PRIMARY=0|1`、`LOCAL_BYPASS_IPV4_SUBNETS=`、`LOCAL_BYPASS_IPV6_SUBNETS=`。默认值是面向大多数局域网环境的安全基线，不建议无必要地全部关掉。

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

健康检查默认会在连续失败达到阈值后触发一次容器重启，以便重新建立隧道；如果你把 `HEALTHCHECK_AUTO_RECOVER=0`，它就只负责探测。常见原因包括：

- `wg0` 没拉起来
- 注册后端状态与当前请求不一致
- 启动阶段的出口探测连续失败，容器已经提前退出等待重试
- 固定 endpoint 当前网络不可达或短时抖动
- 固定 endpoint 只有单个候选，恢复时仍会反复撞回同一个端点
- 代理端口虽然在监听，但出口已经失效

日志里重点看两类线索：

- `远端解析路径探测失败`
- `本地解析路径也失败`

### 3. 代理端口能连，但访问失败

先在宿主机确认：

```bash
# 如果你把 HOST_BIND_PORT 改成了 2080，这里也要改成 2080
curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

如果没有看到 `warp=on`，继续看容器日志里的两类线索：

- `已覆盖 Endpoint 为 ...`
- `当前出口 IP: ...`

如果日志里已经显示启动成功，但流量仍失败，优先怀疑当前 endpoint 不适合你的网络环境。反过来，如果启动阶段连续报“出口探测未获取到 IP”并最终退出，那一般就不要再把问题归到 SOCKS5 本身，而应直接排查隧道和 endpoint。

### 4. endpoint 选择建议

`ENDPOINT_IP` 默认更适合排障时临时覆盖；但如果你所在网络环境明确只能握手固定 endpoint，也可以常驻配置。对“单个固定端点偶发失活”的环境，当前仓库已经支持 `ENDPOINT_CANDIDATES` 顺序尝试：启动阶段某个候选连续拿不到出口 IP，会在同一次启动流程里切到下一个；运行中连续 healthcheck 失败达到阈值后，容器会重启，并重新按你写的候选顺序再尝试一轮。

建议顺序：

1. 能走默认 endpoint 就优先留空 `ENDPOINT_IP`
2. 如果当前网络已知只有固定端点可用，再先设置 `ENDPOINT_IP=ip:port`
3. 如果单个固定 endpoint 仍会抖动，优先改用少量显式 `ENDPOINT_CANDIDATES=ip1:port,ip2:port`
4. 如果你有外部筛好的 endpoint，就显式写进 `ENDPOINT_CANDIDATES`
5. 使用固定 endpoint 或候选缓存时，建议保持 `HEALTHCHECK_AUTO_RECOVER=1`
6. 如果启动阶段经常拿不到出口 IP，再调大 `STARTUP_EGRESS_PROBE_RETRIES` / `STARTUP_EGRESS_PROBE_DELAY`

如果你已经筛出一组适合当前网络环境的候选，可以直接写进 `.env`，例如：

```env
ENDPOINT_CANDIDATES=ip1:port,ip2:port,ip3:port
```

`ENDPOINT_IP` 也支持主机名。但这种方式只是把 DNS 选择交给上游解析，不等于项目本身完成了稳定优选，因此更适合作为个人临时尝试，而不是仓库默认值。

如果你已经有外部筛好的 endpoint，请直接把它们写进 `.env` 里的 `ENDPOINT_CANDIDATES`。当前仓库不再自动读取 `./wireguard/endpoint-candidates.txt`，这样可以避免旧缓存和隐式状态干扰启动结果。

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
- `ENDPOINT_CANDIDATES=ip1:port,ip2:port`
- `STARTUP_EGRESS_PROBE_RETRIES`
- `STARTUP_EGRESS_PROBE_DELAY`
- `STARTUP_EGRESS_PROBE_TIMEOUT`
- `LOCAL_BYPASS_INCLUDE_PRIMARY=0|1`
- `LOCAL_BYPASS_IPV4_SUBNETS`
- `LOCAL_BYPASS_IPV6_SUBNETS`
- `MEM_LIMIT`
- `CPU_LIMIT`
- `LOG_MAX_SIZE`
- `LOG_MAX_FILE`
- `LOG_TIMEZONE`
- `LOG_TIME_FORMAT`
- `MICROSOCKS_LOG_ACCESS=0|1`
- `MICROSOCKS_LOG_LOCAL_CLIENTS=0|1`
- `HEALTHCHECK_AUTO_RECOVER=0|1`
- `HEALTHCHECK_AUTO_RECOVER_THRESHOLD`
- `HOST_BIND_IP`
- `HOST_BIND_PORT`
- `BIND_ADDR`
- `BIND_PORT`
- `RESTART_POLICY=unless-stopped|no`

## 边界

- 当前目录提供的是轻量 WireGuard 路线，目标是稳定提供一个可用的 SOCKS5 出口。
