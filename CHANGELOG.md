# Changelog

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
