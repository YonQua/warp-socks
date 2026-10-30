# warp-socks

基于 Rust 的 Cloudflare WARP 代理，支持 SOCKS5、SOCKS4 和 HTTP，共用一个监听端口。面向 Linux Docker 部署，无需内核 WireGuard 或 TUN 设备。

- 默认使用 MASQUE，自动注册；不可用时回退 WireGuard。
- 支持 IPv4/IPv6，目标域名通过隧道解析。
- 可选 Psiphon 地区前置，最终出口仍为 Cloudflare。
- 出口故障自动恢复，注册凭据持久化保存。

| 出口模式 | TCP | SOCKS5 UDP | 首次使用 |
| --- | --- | --- | --- |
| MASQUE（默认） | 支持 | 不支持 | 自动注册 |
| WireGuard | 支持 | 支持 | 需要 Teams Token |
| Psiphon 地区前置 | 支持 | 不支持 | MASQUE 自动注册；基础链路使用 WireGuard 时需要 Teams Token |

## 快速开始

需要 Linux、Docker Engine 和 Docker Compose。默认使用 host network；以下部署方式不面向 Docker Desktop。

在项目目录执行：

```bash
cp .env.example .env
```

编辑 `.env`。默认 MASQUE 模式可将 `TEAMS_TOKEN` 留空；如需 WireGuard 回退，填写有效 Token。然后构建并启动：

```bash
docker compose up --build -d
docker compose logs -f
```

默认代理地址为 `socks5h://<服务器地址>:1080`，HTTP 代理使用 `http://<服务器地址>:1080`。使用 `socks5h` 可让目标域名通过代理解析。

验证出口：

```bash
docker run --rm --network container:warp-socks curlimages/curl \
  --noproxy "" --socks5-hostname 127.0.0.1:1080 \
  --max-time 30 https://cloudflare.com/cdn-cgi/trace
```

响应应包含 `warp=on` 或 `warp=plus`。镜像内不包含 curl，此命令通过临时容器检查代理。

> 代理未提供身份认证。默认只接受本机和内网来源，请用防火墙限制访问，不要直接暴露到公网。

### 使用预构建镜像

镜像地址：`ghcr.io/yonqua/warp-socks`。发布工作流包含 `linux/amd64`、`linux/arm64` 和 `linux/arm/v7`。

在仓库的 [compose.yaml](compose.yaml) 中移除 `build`，将 `image` 改为所选发布 tag 或 digest，再执行：

```bash
docker compose pull
docker compose up -d
```

版本行为以对应 tag 的文档和 [更新记录](CHANGELOG.md) 为准。

## 配置

常用配置写入 `.env`，修改后执行 `docker compose up -d`。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WARP_SOCKS_ENABLE_MASQUE` | `1` | 优先 MASQUE，失败回退 WireGuard；`0` 为仅使用 WireGuard |
| `TEAMS_TOKEN` | 空 | WireGuard 首次注册需要；已有账户可留空 |
| `SOCKS_LISTEN_ADDRS` | `auto` | 自动监听 IPv4/IPv6；也可填写逗号分隔的本机地址 |
| `SOCKS_LISTEN_PORT` | `1080` | auto 模式监听端口 |
| `PSIPHON_COUNTRY` | 空 | 可选前置地区，例如 `JP`、`US`、`SG` |
| `ENDPOINT_CANDIDATES` | 空 | WireGuard endpoint 列表；留空使用内置候选池 |
| `RUST_LOG` | `info` | 日志级别 |
| `RESTART_POLICY` | `unless-stopped` | Docker 重启策略 |

高级参数、监听规则和持久化文件说明见 [配置参考](docs/configuration.md)。

### WireGuard 模式

```env
WARP_SOCKS_ENABLE_MASQUE=0
TEAMS_TOKEN=header.payload.signature
```

Token 必须是注册链接 `token=` 后面的原始三段 JWT，不包含完整链接、`token=` 前缀或引号。获取步骤见 [Teams Token](docs/configuration.md#获取-teams-token)。

WireGuard 支持 SOCKS5 UDP。客户端需要能够访问服务器返回的 UDP relay 随机端口，不能只放行 TCP 1080。

### 地区前置

```env
PSIPHON_COUNTRY=JP
```

此模式通过指定地区的 Psiphon 节点建立最终 WARP 出口，仅支持 TCP。国家代码只约束前置节点，不保证最终 IP 地区或特定服务可用性。支持的国家代码见 [配置参考](docs/configuration.md#地区前置)。

## 日常使用

```bash
docker compose ps                  # 查看状态
docker compose logs --tail=100      # 查看近期日志
docker compose down                # 停止服务
```

账户和凭据保存在 `./data`，重建容器时会复用。请备份并保护此目录；无需为普通连接故障删除注册信息。

服务最多接受 64 条并发代理连接，满载时关闭新连接。出口恢复期间，新连接最多等待 5 秒；已有连接可能断开，需要客户端重新连接，代理不会重放业务请求。

## 故障排查

| 现象 | 检查方向 |
| --- | --- |
| `connection refused` | 容器是否运行、监听地址是否正确、客户端是否能访问服务器网络 |
| 端口可连接但请求失败 | 查看 `出口准备失败`、`出口探测失败` 等日志；监听存在不代表出口已就绪 |
| WireGuard 注册失败 | 检查 Token 格式、有效期和 `data` 目录权限；遇到 429 等待服务端限流解除 |
| `代理连接容量已满` | 降低并发，检查客户端是否长期占用连接 |
| UDP 不可用 | 确认使用 WireGuard，并检查 UDP relay 随机端口的网络可达性 |
| 容器反复退出 | 检查端口冲突、配置错误、目录权限和 OOM/退出码 |

检查容器健康记录：

```bash
docker inspect --format '{{json .State.Health.Log}}' warp-socks
```

健康检查直接验证出口，不经过代理协议入口；通过表示出口探测成功，不保证所有目标服务可访问，也不代表入口仍有空闲容量。

## 开发与文档

```bash
cargo build --locked --release --bin warp-socks
cargo test --locked --all-targets
```

- [配置参考](docs/configuration.md)
- [更新记录](CHANGELOG.md)
