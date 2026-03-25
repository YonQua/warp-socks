# 文档索引

当前仓库保持轻量，主 README 只保留启动、验证和核心边界。以下专题文档用于补充运行期最容易混淆的部分：

- [运行边界](runtime-boundaries.md)：说明当前方案刻意不做什么，以及哪些配置属于高风险边界。
- [故障排查](troubleshooting.md)：整理最常见的启动失败、握手失败、健康检查失败和代理不可用排查路径。
- [状态与后端切换](state-and-backend-switching.md)：说明 `./wireguard` 的角色、后端锁定语义、`FORCE_REREGISTER=1` 的影响范围。
- [发布说明](releases/v0.1.0.md)：当前初版的对外发布摘要与运行边界。
