# warp-socks

一个面向 Linux 单机部署的 WARP SOCKS5 Docker 方案。默认出口由 MASQUE H3 或 userspace WireGuard 承载；可选地区前置后，最终出口仍是 Cloudflare MASQUE H2。WireGuard 的 SOCKS5 UDP relay 通过 host network 对远端客户端可达。

基础链路：`MASQUE reg.json` 或 `TEAMS_TOKEN -> account.json -> userspace WireGuard`。同一个 Supervisor 选择基础 WARP，并提供唯一的公共代理入口。

1. `WARP_SOCKS_ENABLE_MASQUE=1` 时先尝试 MASQUE（`reg.json`，缺失时自动注册，见下方 `WARP_SOCKS_ENABLE_MASQUE`），成功则全程不需要 `TEAMS_TOKEN`/`account.json`
2. MASQUE 未开启，或开启但注册/建隧道失败需要回退时，才走 `TEAMS_TOKEN -> account.json`（首次注册，之后重启直接复用）-> `wg0.conf`
3. `Supervisor` 选择并验证基础 WARP；设置 `PSIPHON_COUNTRY` 时经该 WARP 连接所选地区的 Psiphon，再建立最终 Cloudflare MASQUE H2 隧道；只启动一个对外代理入口
4. 经 SOCKS5 出口探测通过（`warp=on|plus`）后进入运行态
5. 运行期仅探测最终代理入口：普通 WireGuard 模式首次失败即冷却 endpoint 并退出；MASQUE 或地区模式达到配置阈值后退出，由 Docker 重建整条链路

说明：WireGuard 路径不再使用内核 `wg-quick` / `microsocks`。在中国等网络环境下，内核 WireGuard 常卡在 `0 B received`；当前实现改用带 WARP tricks 的 userspace 客户端。

隧道与 SOCKS5 由本项目自研的 Rust 实现提供（仓库根 `src/`，参考 bepass-org/warp-plus 思路重写，同一份 `wg0.conf` 格式、同样的 reserved bytes/trick 反审查机制）。

当前状态和恢复规则也很简单：

- `account.json` 是唯一 WireGuard 账户状态；`endpoint-state.json` 保存 endpoint 选择历史；`wg0.conf` 只是当前成功运行配置的可审计快照，不参与恢复决策
- `reg.json` 是 MASQUE 路径的凭据文件（基础 MASQUE 或地区模式使用），缺失会自动注册；MASQUE 路径没有 endpoint 候选轮换，不涉及 `endpoint-state.json`
- `endpoint-state.json` 只保存 WireGuard 候选的 `last_good_endpoint` 和 cooldown
- 启动阶段失败直接退出，由 Docker 重启容器
- 普通 WireGuard 运行期首次探测失败即退出；MASQUE 和地区模式连续失败达到阈值后退出。地区链路失败不直接归因于基础 WireGuard endpoint

隧道、SOCKS5、注册、健康探测、候选编排均已收口到自研的 `warp-socks-rs` 单一二进制（`src/`），子命令划分：

- `warp-socks serve`（默认）：`Supervisor`（`src/supervisor.rs`）常驻编排注册确认、endpoint 候选尝试、SOCKS5 服务与运行期健康检查
- `warp-socks register reg/del <path>`：MASQUE 凭据注册/注销
- `warp-socks healthcheck`：Docker HEALTHCHECK 使用的只读心跳时效检查

容器入口直接是 `warp-socks-rs` 二进制本身（Dockerfile `ENTRYPOINT`），没有中间 shell 脚本转发。

对应说明见 [docs/module-boundaries.md](docs/module-boundaries.md)。

## 快速开始

1. 复制模板并编辑 `.env`：

```bash
cp .env.example .env
```

2. 如果要强制使用 WireGuard，填入 Teams registration token。等号右侧只能是
   注册链接 `token=` 参数的值，即由两个 `.` 分隔的原始三段 JWT：

```env
TEAMS_TOKEN=header.payload.signature
WARP_SOCKS_ENABLE_MASQUE=0
SOCKS_LISTEN_ADDRS=auto
SOCKS_LISTEN_PORT=1080
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
docker run --rm --network container:warp-socks curlimages/curl \
  --noproxy "" --socks5-hostname 127.0.0.1:1080 \
  --max-time 30 https://cloudflare.com/cdn-cgi/trace
```

正常情况下应看到 `warp=on` 或 `warp=plus`；`gateway` 值取决于后端和账户类型。镜像内没有 `curl`，此命令使用临时容器共享 `warp-socks` 的网络命名空间。

## 配置

### 常用参数

| 变量                      | 必填                   | 说明                                                                                               |
| ------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------- |
| `TEAMS_TOKEN`             | 条件必填               | Cloudflare Teams registration token，只填写注册链接中 `token=` 后面的原始三段 JWT，例如 `header.payload.signature`；不能包含 `token=`、完整 URI、引号或前后空白。已有 `data/account.json` 后重启可以留空；`WARP_SOCKS_ENABLE_MASQUE=1` 且 MASQUE 注册与建隧道都成功时也不需要（纯 MASQUE 场景不会触碰 Teams 账户），只有实际需要走 WireGuard（未开启 MASQUE，或 MASQUE 失败要回退）时才会要求填写 |
| `WARP_SOCKS_STATE_DIR`    | `/etc/warp-socks`      | 状态目录；`wg0.conf`、`account.json`、`endpoint-state.json` 和 `reg.json` 都相对此目录读写 |
| `SOCKS_LISTEN_ADDRS`    | 否                     | 默认 `auto`：自动监听 IPv4/IPv6，只允许 loopback、RFC1918 IPv4、ULA/link-local IPv6 客户端；也可填写逗号分隔的显式地址列表 |
| `SOCKS_LISTEN_PORT`     | 否                     | `auto` 模式的监听端口，默认 `1080`；显式地址列表模式忽略此项 |
| `PSIPHON_COUNTRY` | 否 | 留空保持原 WARP；填写国家代码（如 `JP`）经 Psiphon 前置连接 MASQUE H2，最终仍为 Cloudflare 出口 |
| `ENDPOINT_CANDIDATES`   | 否                     | 手工覆盖 endpoint 列表；留空时使用项目内置候选池                                                   |
| `RESTART_POLICY`        | `unless-stopped`       | Docker 重启策略                                                                                    |
| `RUST_LOG`              | `info`                 | 日志级别（`env_logger` 标准语法），默认 `info` 已包含连接建立/失败、隧道后端（MASQUE/WireGuard）等关键信息；调试可设 `RUST_LOG=debug` |

### 高级调优参数

| 变量                                       | 默认值 | 说明                                   |
| ------------------------------------------ | ------ | -------------------------------------- |
| `WARP_SOCKS_REGISTER_RETRIES`              | `2`    | Teams 注册最大尝试次数                 |
| `WARP_SOCKS_REGISTER_RETRY_DELAY`          | `2`    | Teams 注册失败后的基础重试间隔秒数     |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY`    | `1`    | 启动阶段两次探测之间的间隔秒数         |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT`  | `5`    | 单次启动出口探测超时秒数（基础 WARP、地区候选出口及最终 SOCKS）    |
| `WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT`   | `20`   | 每个基础 WARP 候选、地区候选出口及最终 SOCKS 各自的就绪探测预算；不包含注册、节点列表下载或握手，不是全部候选的总预算    |
| `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT`     | `63`   | 运行期单次健康检查探测的独立总预算（秒） |
| `WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` | `3`    | MASQUE / 地区模式连续失败阈值；普通 WireGuard 固定为 1 |
| `WARP_RS_TRICK`                            | `none` | 反审查伪装包模式，`none`/`t1`/`t2` |
| `WARP_SOCKS_ENABLE_MASQUE`                 | `1`    | 首层优先 MASQUE H3，失败回退 WireGuard；`0` 表示首层只用 WireGuard。`PSIPHON_COUNTRY` 非空时最终一层始终为 MASQUE H2，独立于此开关 |

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

- `WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT` 约束就绪探测，不包含注册或建隧道的耗时；地区模式还需要下载节点列表并建立 SSH / H2。
- `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT` 不建议手工调低：探测走的是和真实业务连接相同的路径，需要给后端内部的拨号、重连和协议握手留下完整执行时间。默认 63 秒是独立的运维总预算，不反向依赖某个具体后端的私有超时常量。
- 普通 WireGuard 模式不使用包计数猜测停滞：首次真实 SOCKS trace 失败即冷却当前 endpoint 并退出，让整个 `Tunn + UDP socket + Net` 生命周期和所有半死 TCP 一起释放。`WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` 用于 MASQUE 和地区模式；仅普通 WireGuard 失败会直接冷却 endpoint。Docker `HEALTHCHECK` 只读取最后成功心跳，不形成第二套恢复状态机。
- 注册链路遇到 `429` 时仍会尊重服务端 `Retry-After`，这部分不会被本地更小的 delay 强行覆盖。

## Endpoint 策略

这一节只适用于基础 WARP 选择 WireGuard 的场景（`WARP_SOCKS_ENABLE_MASQUE=0`，或 MASQUE 尝试失败回退后）。地区模式也可能以 WireGuard 为基础链路，但最终服务失败不会直接冷却该 endpoint。MASQUE 路径走固定的边缘地址（隧道内 DoH 解析），没有候选轮换。

`ENDPOINT_CANDIDATES` 是唯一手工覆盖入口。

- 如果你显式填写了 `ENDPOINT_CANDIDATES`，启动阶段会按你给定的顺序逐个尝试。
- 如果你留空，启动阶段会使用项目内置候选池（含官方主入口与少量补充）：
  - `162.159.193.5:2408`
  - `162.159.193.9:500`
  - `162.159.193.8:1701`
  - `162.159.193.3:4500`
  - `162.159.193.7:2408`
  - `162.159.193.47:500`
  - `162.159.193.10:1701`
  - `162.159.193.11:4500`

这些地址和端口位于 Cloudflare 为 Zero Trust WireGuard 公布的入口范围内；候选池同时覆盖
主端口 `2408` 和回退端口 `500`、`1701`、`4500`，使 endpoint 切换具备实际路径多样性。

生产环境不建议只填写一个 endpoint；单候选失效时，下一生命周期没有其它可验证路径。通常保持为空即可。

普通 WireGuard 模式运行期不根据 TX/RX 包顺序猜测“数据面停滞”。BoringTun 按协议处理 keepalive 和 rekey；只有真实 SOCKS trace 失败，Supervisor 才冷却当前 endpoint 并退出。Docker 新生命周期重新创建单一 `Tunn + outer UDP socket + Net`，同时强制释放旧的虚拟 TCP，让客户端明确重连，再验证候选池。每个候选必须完成握手和经过该 Outbound 的真实 HTTPS trace 后才写入 `wg0.conf` 与 `endpoint-state.json`。

启动阶段按顺序尝试候选；握手与就绪探测分别有超时预算，不能把 `WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT` 当作整个启动的总时限。只有最终 SOCKS 探测通过才记录健康心跳。全部候选失败后退出，由 Docker 按 `RESTART_POLICY` 重启。

Compose 使用 `network_mode: host`，因为 UDP ASSOCIATE relay 使用随机端口，Docker bridge 无法提前发布。默认 `SOCKS_LISTEN_ADDRS=auto` 会建立独立的 `0.0.0.0:1080` 与 `[::]:1080` listener，其中 IPv6 socket 显式启用 `IPV6_V6ONLY`。程序根据控制连接实际到达的本机地址和地址族自动绑定 UDP relay，因此宿主机地址变化时无需更新配置。

当前 SOCKS5 无认证。自动模式虽然监听全部接口，但在协议分发前只允许 loopback、RFC1918 IPv4、ULA 和 link-local IPv6 客户端；公网来源会被拒绝。仍建议使用主机防火墙限制允许访问的来源。需要其它网络范围时，可以改用显式地址列表；显式模式代表管理员已经选择暴露接口，不附加自动 LAN 来源限制。

客户端须在接受连接后 10 秒内完成代理协议探测与请求头握手；该期限不限制后端拨号或已建立连接的传输时间。SOCKS4 USERID 最多 1024 字节，SOCKS4a 域名最多 253 字节。客户端结束发送后，出站关闭与响应排空共享 30 秒宽限，避免远端不关闭时永久保留连接。H3 DNS 缓存最多保留 512 个域名，过期查询会移除对应条目；满容量新增时先清理过期项，仍满则只淘汰最早到期的一项。

状态文件与健康心跳在 Unix 上以 `0600` 同目录临时文件写入，再原子替换目标；不会通过目标符号链接写入其他文件。状态目录须由管理员控制且可写，部署应挂载整个目录，不支持把这些目标单文件作为挂载点；该写入方式不承诺断电持久性。

例如，以下只展示格式，使用的是不可路由的 RFC 文档地址，不能直接复制到生产：

```env
SOCKS_LISTEN_ADDRS=127.0.0.1:1080,192.0.2.10:1080,[2001:db8::10]:1080
```

WireGuard 后端使用项目内的 `smoltcp 0.13.1` 异步适配层，同时配置 WARP IPv4 `/32`、IPv6 `/128` 和两种默认路由。TCP 与 UDP 都按目标地址族选择对应的 WARP 源地址，因此 IPv4/IPv6 字面量均走隧道。域名在隧道内并发查询 A/AAAA；TCP 按 IPv4、IPv6 交错并每隔 250 ms 发起下一地址，首个成功连接胜出；UDP 确定性使用 A 优先、AAAA 兜底，因此 IPv6-only 域名也可工作。一个 SOCKS5 UDP ASSOCIATE 可以同时访问多个 IPv4、IPv6 或域名目标；每个 association 最多保留 64 个活跃目标，目标通道建立最多等待 10 秒，建立后空闲 120 秒释放。MASQUE 不支持隧道内 UDP，默认会在 SOCKS5 UDP ASSOCIATE 阶段明确拒绝，不会静默回退宿主机出口。

入口在复用或新建 `account.json` 后，会自动清理旧模型遗留的 `state.json` 和 `wgcf-*` 文件。

## 获取 Teams Token

`TEAMS_TOKEN` 只接受注册链接中 `token=` 后面的原始三段 JWT。它的形态应为
`header.payload.signature`，中间恰好有两个 `.`。

1. 打开 `https://<team-name>.cloudflareaccess.com/warp`
2. 完成登录
3. 在开发者工具里找到：

```text
com.cloudflare.warp://<team-name>.cloudflareaccess.com/auth?token=...
```

4. 只复制 `token=` 后面的内容到 `.env`。最终配置必须是一行
   `TEAMS_TOKEN=实际JWT`，不要包含 `token=`、完整链接、引号或前后空白

这类 token 时效很短，复制后尽量立刻启动。

## 故障排查

### 容器起不来

先看：

```bash
docker compose logs --tail=80
```

最常见原因：

- `TEAMS_TOKEN` 为空且 `./data` 下也没有可复用的 `account.json`
- Teams token 格式错误或已过期
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
rm -f data/account.json data/wg0.conf data/endpoint-state.json data/reg.json
docker compose up --build -d
```

## 预构建镜像

发布版本会同步到 `ghcr.io/yonqua/warp-socks`，支持 `linux/amd64`、`linux/arm64`、`linux/arm/v7` 三种架构。建议固定 tag，不要长期跟 `latest`。

```yaml
services:
  warp-socks:
    image: ghcr.io/yonqua/warp-socks:<固定版本或 digest>
    container_name: warp-socks
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./data:/etc/warp-socks
    env_file:
      - .env
```

验收应按实际后端覆盖能力：WireGuard 检查 TCP/UDP × IPv4/IPv6；MASQUE H3 和地区模式检查 TCP IPv4/IPv6，并确认 UDP ASSOCIATE 明确拒绝。所有模式都需检查 Cloudflare trace 包含 `warp=on|plus`，地区模式还需核对实际 `loc`。host network 生产配置面向 Linux；Docker Desktop 不在该部署合同内。

### 当前能力验收矩阵

| 路径 | 必须验证的结果 |
| --- | --- |
| SOCKS TCP → IPv4 字面量 | 连接成功，日志中的后端符合所选模式 |
| SOCKS TCP → IPv6 字面量 | 成功，trace 为 `warp=on|plus` |
| SOCKS TCP → 域名 | 成功，DNS 在隧道内解析；WireGuard/H2 并发查询 A/AAAA，H3 使用 DoH |
| WireGuard SOCKS UDP → IPv4 DNS | UDP ASSOCIATE 成功，relay 返回客户端可达的宿主机 IPv4 随机端口 |
| WireGuard SOCKS UDP → IPv6 目标 | 成功，真实建立 UDP ASSOCIATE，且无宿主机直出日志 |
| MASQUE H3 / 地区模式 UDP | 在 ASSOCIATE 阶段明确失败，无宿主机直出 |

程序内部 liveness 在 auto 模式固定使用 `127.0.0.1:SOCKS_LISTEN_PORT`，显式模式使用列表第一个地址，执行一次域名 TCP `warp=on|plus` 探测。它只判断进程和隧道主链路是否需要重启，不冒充完整能力矩阵；`tcp4`、`tcp6`、`udp4`、`udp6` 应由实际客户端或上层代理分别验证。

### 可选 Psiphon 地区前置（纯 Rust）

设置 `PSIPHON_COUNTRY=JP`，仍使用唯一的 `SOCKS_LISTEN_PORT` 入口（默认 `1080`）。国家留空时保持现有 WireGuard / MASQUE 行为；非空时链路为：

```text
客户端 → 唯一代理入口 → 最终 Cloudflare MASQUE H2 → 目标网站
                             ↑ 所选地区 Psiphon SSH
                             ↑ 基础 WARP（MASQUE H3 或 WireGuard）
```

国家代码选择 Psiphon 前置节点，最终网站看到的仍是 Cloudflare IP。Cloudflare 最终分配的 IP 地区需要通过 trace 核验，不能保证与所选国家完全一致，也不能保证 Google 等服务接受该 IP。

支持：`AT AU BE BG CA CH CZ DE DK EE ES FI FR GB HR HU IE IN IT JP LV NL NO PL PT RO RS SE SG SK US`。支持小写输入，自动转大写；所选地区没有可用 SSH 节点时启动失败，不切换其他地区或直接使用 Psiphon 出口。

同一个 Rust 进程管理全部链路，不需要 Go、外部 SSH 程序或第二个容器。Psiphon 校验官方节点列表签名和 SSH 主机密钥，目前实现 SSH/TCP，不包含 OSSH、Meek 或 QUIC；地区模式仅提供 TCP，SOCKS5 UDP ASSOCIATE 明确返回不支持。节点列表下载最多 30 秒，最多尝试 8 个节点；每个节点的 SSH 建立限时 20 秒，随后分别执行有界的 H2 建立和 WARP 出口探测，均成功才接受该候选，失败则继续下一个节点。各层直接通过 `Outbound` 组合，不创建内部 SOCKS 监听端口。

运行期只有最终代理入口的健康检查，验证 Cloudflare `warp=on|plus`；达到失败阈值后整个进程退出，由 Docker 重建链路。基础 WARP 只在启动选择时验证，不额外运行健康循环。TCP 建连取消/超时可能关闭共享 SSH 会话，正常慢读采用传输层背压。

验证边界：日本节点经两种基础 WARP 后端的 IPv4/IPv6 短请求已返回 `loc=JP`、`warp=on`。本地 DAE/VPN 网络中的持续下载出现过间歇停滞，其他 QUIC 实现也能复现；尚不能归因于地区功能或具体网络环节。短请求通过不代表长连接稳定，也不保证 Google 解锁。
