# 配置参考

常用参数与部署步骤见 [README](../README.md)。以下默认值对应当前源码；已有部署的环境变量会覆盖默认值。

## 高级参数

| 变量                                       | 默认值 | 说明                                   |
| ------------------------------------------ | ------ | -------------------------------------- |
| `WARP_SOCKS_REGISTER_RETRIES`              | `2`    | Teams 注册最大尝试次数                 |
| `WARP_SOCKS_REGISTER_RETRY_DELAY`          | `2`    | Teams 注册失败后的基础重试间隔秒数     |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_DELAY`    | `1`    | 启动阶段两次探测之间的间隔秒数         |
| `WARP_SOCKS_STARTUP_EGRESS_PROBE_TIMEOUT`  | `5`    | 单次启动出口探测超时秒数（基础 WARP 和地区候选出口）    |
| `WARP_SOCKS_STARTUP_SOCKS_READY_TIMEOUT`   | `20`   | 每个基础 WARP 候选、地区候选出口各自的就绪探测预算；不包含注册、节点列表下载或握手，不是全部候选的总预算    |
| `WARP_SOCKS_HEALTHCHECK_PROBE_TIMEOUT`     | `63`   | 运行期单次健康检查探测的独立总预算（秒） |
| `WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD` | `3`    | MASQUE / 地区模式连续失败阈值；普通 WireGuard 固定为 1 |
| `WARP_RS_TRICK`                            | `none` | 反审查伪装包模式，`none`/`t1`/`t2` |
| `WARP_SOCKS_STATE_DIR` | `/etc/warp-socks` | 账户、凭据与配置快照的保存目录 |
| `WARP_SOCKS_ENABLE_MASQUE`                 | `1`    | 首层优先 MASQUE H3，失败回退 WireGuard；`0` 表示首层只用 WireGuard。`PSIPHON_COUNTRY` 非空时最终一层始终为 MASQUE H2，独立于此开关 |

时间参数单位均为秒。各候选的就绪预算受整轮 120 秒准备预算约束；最终出口验证通过后发布到监听入口，没有额外的 SOCKS 就绪探测。缩短超时可能使慢链路在可用前就被判定失败，通常保持默认值即可。

`WARP_RS_TRICK` 和 `WARP_SOCKS_STATE_DIR` 是应用环境变量，仓库 Compose 未直接透传；容器部署需要在 `environment` 中显式添加，不能只写入 `.env`。

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

## 监听地址

默认 `SOCKS_LISTEN_ADDRS=auto` 监听 IPv4/IPv6，允许 loopback、RFC1918 IPv4、ULA/link-local IPv6 客户端。`SOCKS_LISTEN_PORT` 只在 auto 模式生效。

仅限本机访问可设置 `SOCKS_LISTEN_ADDRS=127.0.0.1:1080`。也可用逗号分隔多个本机地址；显式地址模式不附加 LAN 来源限制，应通过防火墙限制访问。

Linux host network 使 SOCKS5 UDP relay 的随机端口对客户端可达。改用 bridge 网络时，单独发布 TCP 1080 不能覆盖 UDP relay。

## WireGuard endpoint

`ENDPOINT_CANDIDATES` 留空使用内置候选池。自定义时填写逗号分隔的 `IP:port`；候选会结合上次成功记录与冷却状态重新排序。该变量只影响 WireGuard，不影响 MASQUE 边缘选择。

## 地区前置

`PSIPHON_COUNTRY` 支持以下国家代码（不区分大小写）：

```text
AT AU BE BG CA CH CZ DE DK EE ES FI FR GB HR HU IE IN IT JP LV NL NO PL PT RO RS SE SG SK US
```

国家代码约束 Psiphon 前置节点，最终出口仍是 Cloudflare。所选地区不可用时会重试，不会切换到其他地区或直接使用 Psiphon 出口。

## 持久化与资源

默认将宿主机 `./data` 挂载到容器 `/etc/warp-socks`。目录包含注册凭据，应限制访问并备份整个目录；不要把删除账户文件作为常规排障手段。

| 文件 | 用途 |
| --- | --- |
| `account.json` | WireGuard 账户 |
| `reg.json` | MASQUE 注册凭据 |
| `endpoint-state.json` | WireGuard 候选选择记录 |
| `wg0.conf` | 已验证 WireGuard 配置快照 |

仓库 Compose 默认限制内存 256 MiB、CPU 0.5，日志轮转为 10m × 3。资源限制可以按负载调整；不代表已经完成该限额下的压力验收。入口最多 64 条连接，满载关闭新连接；UDP 每个 association 最多 64 个目标，全进程最多 128 个目标 worker，报文字节额度 8 MiB。

健康检查只表示出口探测结果，不代表入口仍有空闲容量。出口恢复期间，新连接最多等待 5 秒；已有连接可能断开，需要客户端重新连接。

