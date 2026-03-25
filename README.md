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

更多说明见：

- [文档索引](docs/README.md)
- [运行边界](docs/runtime-boundaries.md)
- [故障排查](docs/troubleshooting.md)
- [状态与后端切换](docs/state-and-backend-switching.md)

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

镜像现在内置了一个极简 `HEALTHCHECK`：它会在容器内通过本地 SOCKS5 访问 `https://cloudflare.com/cdn-cgi/trace`，并检查是否返回 `warp=on` 或 `warp=plus`。这个检查只负责暴露“代理出口当前是否可用”，不负责自动修复。

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

## 获取 Teams Token

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

## 关键说明

- `registration token` 是短时效凭据，只用于首次注册。
- `WARP_LICENSE_KEY` 只在首次 `wgcf-plus` 注册或你主动更新绑定时需要；成功后会随着本地持久化状态一起复用。
- `wgcf-plus` 走的是社区 `wgcf` 工具链，不是 Cloudflare 官方 `warp-cli registration license` 容器化封装。
- 注册成功后，状态会持久化到 `./wireguard`；只要这个目录还在，后续重启通常不需要重新取 token。
- `./wireguard` 里会包含私钥和账户信息，`.env` 里会包含短时效 token；两者都不要提交到版本库。
- 默认端口映射是 `127.0.0.1:1080 -> 1080`，适合先本机验证；除非你已经有明确的网络访问控制，否则不要改成 `HOST_BIND_IP=0.0.0.0`。
- `ENDPOINT_IP` 默认建议留空，直接使用注册返回的 endpoint。只有在默认端点握手失败时，才临时手动覆盖。
- 当前这台机器上，`162.159.193.7:2408` 已实测可用，因此 `.env.example` 里保留了注释示例。
- 如果持久化目录里的后端与当前请求后端不一致，容器会拒绝启动；需要显式设置 `FORCE_REREGISTER=1` 才允许切换。
- 老的无 `state.json` 的 wgcf 持久化目录在 `auto` 模式下会被视为语义不明确；这种情况下应显式设置 `AUTH_MODE`，或直接用 `FORCE_REREGISTER=1` 重建。
- 当前健康检查只验证 SOCKS5 出口是否还能返回 `warp=on` / `warp=plus`；如果你后续想做自动恢复，应作为额外可选能力单独设计，而不是塞进启动主链路。

## 常用变量

- `AUTH_MODE=auto|teams|wgcf-free|wgcf-plus`
- `TEAMS_TOKEN`
- `WARP_LICENSE_KEY`
- `FORCE_REREGISTER=0|1`
- `WARP_STACK=ipv4|dual|ipv6`
- `ENDPOINT_IP=ip:port`
- `HOST_BIND_IP`
- `HOST_BIND_PORT`
- `RESTART_POLICY=unless-stopped|no`

## 边界

- 这不是 Cloudflare 官方当前 `Local proxy mode` 的等价实现。
- 官方当前 `Local proxy mode` 依赖 `MASQUE + Cloudflare One Client`。
- 当前目录提供的是轻量 WireGuard 路线，目标是稳定提供一个可用的 SOCKS5 出口。
- 更多边界说明见 [运行边界](docs/runtime-boundaries.md)。
