# WireGuard 稳定生命周期方案

本文的 endpoint 冷却规则针对未启用 `PSIPHON_COUNTRY` 的普通 WireGuard 模式。地区模式只监督最终 Cloudflare 入口，整条链路失败时不直接归因或冷却基础 WireGuard endpoint。

## 已验证根因边界

同一故障可在 Docker `network_mode: host`、macOS 宿主机原生运行、多个 WARP
endpoint 和 `2408`、`500`、`4500` 端口上复现。切换 netstack 与 WireGuard
之间的 transport 结构、切换 BoringTun 版本、限制总下载速率都不能消除故障。

故障窗口内 outer UDP 仍能发送，socket 队列和发送错误为零，但不再收到回包。
更换本地 UDP 端口后新建的 SOCKS trace 可以恢复，但已经停滞的 TCP 下载不会
可靠续传。因此项目能确认的边界是当前 UDP 五元组失去回程；原地重绑不是完整
恢复。现有证据仍不足以断言是路由器、运营商还是 WARP peer 的内部策略。

## 最小状态模型

每个 WireGuard 生命周期只有：

1. 一个已通过握手和隧道内 HTTPS trace 的 endpoint。
2. 一个 BoringTun `Tunn`。
3. 一个 outer UDP socket。
4. 一个 smoltcp `Net`。

transport 不维护 stall counter、generation、endpoint 池、重绑通道或业务包活性
状态。Supervisor 是唯一恢复决策者，只接受真实 SOCKS trace 的结果：

1. trace 成功：记录心跳，不改变任何状态。
2. trace 失败：冷却当前 endpoint，退出进程。
3. Docker 新生命周期创建全新的 `Tunn`、outer UDP socket 和 `Net`，遍历候选
   池并对每个候选重新执行握手和隧道内 HTTPS trace，最终再验证公共 SOCKS 入口。

进程退出是刻意的恢复边界：当前代理实现的连接任务独立持有 `Outbound`，只停止
listener 不能同步销毁所有旧 TCP；进程级退出才能保证旧 peer、socket 和半死连接
同时消失，也避免同一 WireGuard peer 的 endpoint roaming 竞争。

这个设计收敛的是项目内的故障检测和恢复语义，不声称修复外部 UDP 五元组
概率性失去回程的原因。新生命周期可恢复新连接，但不承诺旧 TCP 跨生命周期续传。

## 明确不做

- 不用全局 TX/RX 顺序模拟请求响应关系。
- 不按固定周期盲目重绑。
- 不在进程内原地重绑 outer UDP。
- 不并行维护同一 peer 的多个 endpoint 或 netstack generation。
- 不用流量整形掩盖未经证实的限速问题。
- 不因单个 endpoint 失效删除候选池。

## 验证要求

- `cargo fmt --all -- --check`
- `cargo check`
- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `docker compose config --quiet`
- `git diff --check`
- 容器真实 trace 返回 `warp=on|plus`
- 单路持续下载完整结束
- 故障压测触发进程退出，Docker 重启后 trace 恢复且 endpoint 候选发生轮换
