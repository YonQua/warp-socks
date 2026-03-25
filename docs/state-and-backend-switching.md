# 状态与后端切换

## `./wireguard` 是什么

`./wireguard` 不是示例目录，而是活的运行状态目录。首次启动成功后，当前后端的关键信息会落在这里，例如：

- `wg0.conf`
- `state.json`
- `account.json` 或 `wgcf-*`

这个目录里的内容会直接影响后续重启行为。

## 后端锁定语义

当前仓库支持三种后端：

- `teams`
- `wgcf-free`
- `wgcf-plus`

一旦某个后端成功写入 `./wireguard`，后续重启会优先复用这套状态。若你只是修改 `.env` 中的 `AUTH_MODE`，但没有清理状态，入口脚本会拒绝启动并提示后端不一致。

## 什么时候需要 `FORCE_REREGISTER=1`

只有在下面几类场景里才建议开启：

- 你确定要从 `teams` 切到 `wgcf-*`
- 你确定要从 `wgcf-free` 切到 `wgcf-plus`
- 当前持久化状态已经不可用，想重建

开启后会清理当前后端状态，再按新的环境变量重新注册。它的影响不是“重连一次”，而是“删除并重建当前注册结果”。

## 建议操作顺序

切换后端时建议这样做：

1. 确认当前 `AUTH_MODE`、`TEAMS_TOKEN`、`WARP_LICENSE_KEY`
2. 备份 `./wireguard`
3. 设置 `FORCE_REREGISTER=1`
4. `docker compose up --build -d`
5. 验证健康状态和代理出口
6. 确认成功后，把 `FORCE_REREGISTER` 改回 `0`

## 旧状态目录的注意事项

如果你带着老的 `wgcf` 状态目录迁移过来，而目录里没有 `state.json`，`auto` 模式可能无法判断它属于 `wgcf-free` 还是 `wgcf-plus`。这种情况下应显式设置 `AUTH_MODE`，必要时直接重建状态。
