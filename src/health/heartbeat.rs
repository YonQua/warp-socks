// Docker HEALTHCHECK CMD 只读这里的心跳文件，不再自己发起一次完整的
// SOCKS→隧道探测：这条隧道每 healthcheck_interval 本来就要被 Supervisor
// 自己的运行期循环真实探测一次（见 supervisor.rs），Docker 层再起一个独立
// 子进程重复探测同一条隧道纯属浪费，还逼着 Docker 的 --timeout 手动 ≥
// 隧道自愈重连的内部预算（masque → relay → appconfig 那条派生链），链路
// 每加一层就多一处要手动保持同步的地方——心跳文件把"最近一次真实探测的
// 结果"直接暴露出来，读文件是毫秒级的，--timeout 不再需要关心隧道内部
// 的任何超时预算。
//
// 写在 /tmp 而非 state_dir：state_dir 是宿主机 bind mount（./data），
// 心跳是纯运行期状态，不应该污染用户能看到、会被备份的那个目录；容器重启后
// /tmp 自然清空，语义上也正是"没有历史心跳就是还没探测过"。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HEARTBEAT_PATH: &str = "/tmp/warp-socks-health";

/// Supervisor 每次探测（启动就绪确认或运行期循环）后调用，记录结果与时间戳。
pub fn record(ok: bool) {
    let body = format!("{}\n{}\n", if ok { "ok" } else { "fail" }, now_secs());
    if let Err(e) = std::fs::write(HEARTBEAT_PATH, body) {
        log::warn!("写健康检查心跳文件失败（不影响探测本身）: {e}");
    }
}

/// 供 `healthcheck` 子命令读取。心跳缺失（刚启动，Supervisor 还没跑完第一次
/// 探测）、过期（超过 `max_age` 未更新，说明运行期循环可能已经卡住）、或上
/// 次探测本身失败，都视为不健康。
///
/// # Errors
/// 不健康时返回描述原因的字符串。
pub fn check(max_age: Duration) -> Result<(), String> {
    let content = std::fs::read_to_string(HEARTBEAT_PATH)
        .map_err(|_| "尚无心跳记录（可能刚启动，还没跑完第一次探测）".to_string())?;
    evaluate(&content, now_secs(), max_age)
}

/// 纯逻辑部分从文件 IO 里拆出来，单独可测：解析心跳内容 + 判断是否过期/失败。
fn evaluate(content: &str, now: u64, max_age: Duration) -> Result<(), String> {
    let mut lines = content.lines();
    let status = lines.next().unwrap_or("");
    let ts: u64 = lines
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "心跳文件格式异常".to_string())?;

    let age = now.saturating_sub(ts);
    if age > max_age.as_secs() {
        return Err(format!(
            "心跳已过期（{age}s 未更新，运行期健康检查循环可能已卡住）"
        ));
    }
    if status != "ok" {
        return Err("最近一次运行期探测失败".to_string());
    }
    Ok(())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_ok_heartbeat_passes() {
        assert!(evaluate("ok\n1000\n", 1010, Duration::from_secs(30)).is_ok());
    }

    #[test]
    fn stale_heartbeat_fails() {
        let err = evaluate("ok\n1000\n", 1031, Duration::from_secs(30)).unwrap_err();
        assert!(err.contains("过期"));
    }

    #[test]
    fn failed_probe_heartbeat_fails() {
        let err = evaluate("fail\n1000\n", 1005, Duration::from_secs(30)).unwrap_err();
        assert!(err.contains("失败"));
    }

    #[test]
    fn malformed_content_fails() {
        assert!(evaluate("garbage", 1000, Duration::from_secs(30)).is_err());
    }
}
