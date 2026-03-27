# Changelog

## 2026-03-27

- 启动日志现在会同时区分“容器内 SOCKS5 监听地址”和“Docker 发布到宿主机的入口端口”，减少 `HOST_BIND_PORT` 与 `BIND_PORT` 混淆
- `compose.yaml` 现在把 `HOST_BIND_IP` / `HOST_BIND_PORT` 传入容器，仅用于启动日志展示宿主机入口映射
- README 与 `.env.example` 补充一段明确的端口层级说明，强调 `HOST_BIND_PORT` 才是客户端入口，而 `BIND_ADDR=0.0.0.0` 是容器内监听的推荐默认值
- 删除自动读取 `wireguard/endpoint-candidates.txt` 与持久化 `endpoint-cursor` 的逻辑，项目重新只认 `.env` 里的 `ENDPOINT_IP` / `ENDPOINT_CANDIDATES`，避免隐藏状态影响启动顺序
- 删除仓库内置的 endpoint 发现器与握手生成工具，移除 `cmd/discover-endpoints`、`internal/warphandshake`、`go.mod`、`go.sum` 和本地构建产物，项目重新收口为“轻量运行 + 显式 endpoint 候选消费”
- README / `.env.example` 进一步收口为 `ENDPOINT_IP` 与 `ENDPOINT_CANDIDATES` 两条轻量路径，不再保留仓库自带发现器或隐式缓存文件的使用说明
- 新增 repo-native `cmd/discover-endpoints`：使用仓库内维护的 WARP CIDR 与端口列表，直接发送 UDP 握手包筛选 `IP:Port` 候选，并按丢包率/延迟排序
- 发现器新增 `--preset`，默认改为官方 `teams-wireguard` 窄池优先：先扫 `162.159.193.0/24:2408`；原先的大范围多网段多端口扫描改为显式 `--preset wide`
- 新增 `teams-wireguard-fallback` 与 `consumer-wireguard` 预设，分别对应官方 WireGuard fallback 端口和 consumer/free 窄池
- README / `.env.example` 当前已收口为“主项目轻量运行 + 显式候选池优先”的路径；发现器保留为可选离线工具，不再作为默认主叙事
- 发现器默认优先读取 `wireguard/account.json`，按当前账号参数生成更贴近真实环境的握手包；缺失或解析失败时再回退到内置默认握手包
- 发现器现在改为“两阶段筛选”：先做 UDP 握手缩小候选池，再对前 N 个候选启动临时验证容器，直接复用启动后的 `trace` 出口探测标准；只有真正拿到出口 IP 的候选才会写入缓存
- 第二阶段验证现在默认附带当前仓库 `.env`，并把临时状态目录放到系统临时目录，减少与真实 `docker compose` 运行条件的漂移，也避免在仓库 `wireguard/` 下堆积 `.validator-*` 残留目录
- 第二阶段独立验证次数默认从 2 次提高到 3 次，并引入“多数派稳定阈值”判定；当前默认至少成功 `2/3` 次才会进入最终候选池
- `wireguard/endpoint-discovery.csv` 现在会额外记录第二阶段的成功次数、总次数和成功率，便于直接审查 endpoint 稳定度，而不是只看一次成败
- 新增本地 endpoint 缓存文件 `wireguard/endpoint-candidates.txt`；当 `.env` 未显式设置 `ENDPOINT_IP` / `ENDPOINT_CANDIDATES` 时，启动链路会自动读取这份缓存
- `lib/warp-common.sh` 新增 endpoint 缓存读取与 source 判定逻辑，`entrypoint.sh` 会在启动时明确记录当前是使用显式候选还是本地缓存
- 新增内部包 `internal/warphandshake`，收口账户文件解析、Reserved 提取和真实握手包生成逻辑
- 删除旧的 `scripts/discover-endpoints.py`、`scripts/optimize-endpoints.sh` 和临时 `cmd/warp-handshake-packet`，只保留 Go 版发现器
- `.dockerignore` 现在会排除 `cmd/`、`internal/`、`go.mod`、`go.sum`，避免本地发现工具进入 Docker build context
- 新增 `ENDPOINT_CANDIDATES`，允许预先提供多个固定 endpoint 候选，并在启动阶段按候选顺序轮换
- 启动阶段的 endpoint 轮换不再依赖整容器重启：当前候选连续拿不到出口 IP 时，会在同一次启动流程里直接切到下一个候选重试
- healthcheck 在连续失败达到阈值时，若配置了多个 endpoint 候选，会先推进候选游标，再终止 PID 1 触发容器重启
- `lib/warp-common.sh` 新增 endpoint 候选归一化、去重与游标持久化逻辑，供 `entrypoint.sh` 与 `healthcheck` 共享
- `.env.example` 与 README 同步补充“先筛出一批可用 endpoint，再交给容器轮换”的使用路径
- healthcheck 新增连续失败计数，并可在达到阈值后终止 PID 1，交给 Docker 按现有 `restart` 策略自动拉起容器并重建隧道
- healthcheck 现在会区分 `socks5h` 远端解析路径与 `socks5` 本地解析路径，并在失败日志里补充最近握手时间与连续失败次数
- `compose.yaml` 与 `.env.example` 新增 `HEALTHCHECK_AUTO_RECOVER`、`HEALTHCHECK_AUTO_RECOVER_THRESHOLD`，允许显式关闭自动恢复或调整阈值
- 启动阶段新增出口就绪门禁：连续探测拿不到出口 IP 时，不再继续启动 `microsocks`，而是直接退出容器等待重试
- 将 `entrypoint.sh` 与 `healthcheck` 的公共探测和参数处理下沉到共享的 `lib/warp-common.sh`，减少脚本间漂移
- 收正后端选择语义：已有可复用持久化状态时，`AUTH_MODE=auto` / `teams` / `wgcf-plus` 不再过度依赖首次注册凭据
- README、运行边界与故障排查文档同步更新为“轻量自恢复”语义，并补充固定单 endpoint 时的稳定性边界说明
- `compose.yaml` 新增直接面向 `docker compose up` 的 `mem_limit`、`cpus` 与 `json-file` 日志滚动限制；`.env.example` 与 README 同步补充 `MEM_LIMIT`、`CPU_LIMIT`、`LOG_MAX_SIZE`、`LOG_MAX_FILE`
- `compose.yaml` 与 `.env.example` 新增 `STARTUP_EGRESS_PROBE_RETRIES`、`STARTUP_EGRESS_PROBE_DELAY`、`STARTUP_EGRESS_PROBE_TIMEOUT`，允许调整启动阶段的出口探测重试
- 删除 `docs/README.md` 与 `docs/releases/v0.1.0.md`，去掉与当前运行无直接关系的索引页和发布快照文档
- 将 `docs/runtime-boundaries.md` 与 `docs/state-and-backend-switching.md` 的有效内容并回 `README.md`，只保留 `docs/troubleshooting.md` 作为专题排障文档
- 进一步将 `docs/troubleshooting.md` 并回 `README.md`，当前仓库不再保留 `docs/` 目录
- 对 README 再做一轮压缩，去掉 `关键说明`、`状态与后端切换`、`故障排查` 之间的重复表述，保持单文档但减少维护面
- 调整 README 章节顺序为“关键说明 -> 故障排查 -> 状态与后端切换”，更贴近实际使用与排障路径
- 对 README 的“关键说明”再做一轮视觉分组，按“凭据与注册 / 运行与安全 / 阅读路径”拆成更易扫读的 3 组

## 2026-03-25

- 启动隧道后会自动为主网段与私网地址添加路由和 OUTPUT 旁路，修复通过 Docker 发布端口从局域网访问 SOCKS5 时回复流量误入 WARP 隧道的问题
- `.env.example` 补充了 `HOST_BIND_IP` / `HOST_BIND_PORT` / `BIND_PORT` 的区别说明，并明确局域网访问应修改宿主机绑定项
- 项目目录与默认命名从 `warp-teams` 收正为 `warp-socks`，以匹配当前支持 `teams`、`wgcf-free`、`wgcf-plus` 的实际能力面
- 镜像新增极简 `HEALTHCHECK`，通过容器内本地 SOCKS5 请求 `cdn-cgi/trace` 校验 `warp=on` / `warp=plus`
- 新增独立 healthcheck 脚本，保持“检查”和启动主链路分离，不引入自动修复逻辑
- README 补充健康状态查看方式，并明确当前 healthcheck 只负责暴露出口可用性
- 新增 `docs/` 文档索引与 3 个专题文档，拆分运行边界、故障排查、状态与后端切换说明
- 强化 README 与 `.env.example` 中的安全边界提示，明确 `HOST_BIND_IP=0.0.0.0` 会暴露无认证 SOCKS5 代理
- 把 `microsocks` 构建源固定到上游已发布 tag `v1.0.5`，避免默认分支漂移影响镜像可复现性
- Dockerfile 进一步收敛：基础镜像固定到 `alpine:3.22.3`，builder 阶段改用固定 tarball 源码包，并为 `wgcf` 下载增加重试，降低漏洞扫描噪音与弱网构建失败概率

## 2026-03-24

- 收敛目录为当前可运行的轻量 WARP Teams SOCKS5 方案
- 保留 `Dockerfile`、`entrypoint.sh`、`compose.yaml`、`.env.example`、`README.md`
- 精简 `README.md`，删除过程性说明，保留最终启动与验证方法
- 清理上游对照测试文件、无效脚本下载结果、过程记录和明文 token 文件
- 修复复用持久化 `wg0.conf` 时的重启循环问题，确保容器重建后仍能稳定启动
- 把 `wg-quick` 的 Docker 兼容修补固化到镜像构建阶段，避免容器重建后再次触发只读 `sysctl` 写入
- 明确当前项目选择轻量 `WireGuard + microsocks` 路线，不以 `warp=plus` 或官方 `WarpProxy on port 40000` 为目标
- 把 `/etc/wireguard` 从 Docker named volume 改为当前目录 `./wireguard` 绑定，便于查看、备份和迁移
- 把 `CF-Client-Version` 从硬编码抽成可配置项，并明确它只是兼容注册头，不代表官方客户端当前版本
- 修复启动入口里的 `prepare_runtime()` 误写，恢复“缺少配置时先注册/生成 `wg0.conf`”的正确执行路径
- 整理 README 中 `TEAMS_TOKEN` 的获取步骤，补充浏览器操作说明和时效提醒
- 固定镜像名为显式名称，避免 Compose 自动生成重复镜像名
- 在 `.env.example` 和 README 里补充 `RESTART_POLICY` 的实际用法说明
- 启动时若已存在 `account.json`，现在会按当前环境重新生成 `wg0.conf`，确保端点覆盖等配置修改能真正生效
- 收正 `ENDPOINT_IP` 的定位：默认不再建议常驻配置，改为仅用于排障时的临时端点覆盖
- 当前网络下保留 `162.159.193.7:2408` 作为已验证可用的排障示例端点，而不是默认常驻端点
- 把 `.env.example` 补充为分段注释版，明确必填项、默认值和排障时才需要改动的变量
- 引入三模注册后端：`teams`、`wgcf-free`、`wgcf-plus`
- 新增 `AUTH_MODE`、`WARP_LICENSE_KEY`、`FORCE_REREGISTER`，并加入后端状态保护，避免持久化目录跨后端复用
- 镜像内新增 `wgcf`，支持免费 consumer WARP 与 WARP+ license key 路线
- 新增 `.gitignore`，避免把 `.env` 和 `wireguard/` 这类敏感运行数据提交到版本库
- 修复 `auto` 模式下优先级提示写入 stdout 污染后端选择结果的问题，改为写入 stderr
- 对没有 `state.json` 的旧 wgcf 状态新增显式保护，避免 `auto` 模式误判后端
- 修正 README 中误写入的本地绝对路径链接，避免上传 GitHub 后出现不可用的本地文件引用
- 再次精简 README 结构，合并重复说明，保留 GitHub 首页最需要的启动、验证和排障信息
- 新增 `.dockerignore`，排除 `.git`、`.env`、`wireguard/` 等本地敏感或无关内容，避免它们进入 Docker build context
