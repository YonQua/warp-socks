# 故障排查

## 1. 容器起不来

先看：

```bash
docker compose logs --tail=80
```

重点关注以下报错：

- `AUTH_MODE=teams 时必须提供 TEAMS_TOKEN`
- `AUTH_MODE=wgcf-plus 时必须提供 WARP_LICENSE_KEY`
- `当前持久化状态后端为 ...，请求后端为 ...`

这类错误通常不是网络故障，而是当前环境变量与 `./wireguard` 里的已有状态不一致。

## 2. 健康检查失败

先看容器状态：

```bash
docker compose ps
```

如果不是 `healthy`，再看日志：

```bash
docker compose logs --tail=80
```

当前健康检查只验证 SOCKS5 出口，不会给出修复建议。常见原因包括：

- `wg0` 没拉起来
- 注册后端状态与当前请求不一致
- 默认 endpoint 当前网络不可达
- 代理端口虽然在监听，但出口已经失效

## 3. 代理端口能连，但访问失败

先在宿主机确认：

```bash
curl --socks5 127.0.0.1:1080 https://cloudflare.com/cdn-cgi/trace
```

如果没有看到 `warp=on`，继续看容器日志里的两类线索：

- `已覆盖 Endpoint 为 ...`
- `当前出口 IP: ...`

如果日志里已经显示启动成功，但流量仍失败，优先怀疑当前 endpoint 不适合你的网络环境。

## 4. 默认 endpoint 握手失败

`ENDPOINT_IP` 只应用于排障，不建议长期常驻。

排障步骤：

1. 先保持 `ENDPOINT_IP` 为空重试
2. 如果当前网络已知有稳定可用端点，再临时设置 `ENDPOINT_IP=ip:port`
3. 验证通过后，优先考虑回到默认 endpoint

## 5. 想切换注册后端

不要直接改 `AUTH_MODE` 后重启。当前仓库会锁定 `./wireguard` 下的后端状态。

正确路径见 [状态与后端切换](state-and-backend-switching.md)。
