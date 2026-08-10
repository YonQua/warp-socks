// “简单错误恢复策略”：这里只判断连续失败是否达到阈值；具体选择后端自愈
// 或退出进程由 supervisor 统一编排，避免单次瞬时拥塞触发破坏性重连。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Continue,
    RequestExit,
}

/// 阈值恢复策略：连续失败次数达到阈值即请求退出。
pub struct ThresholdRecovery {
    failure_threshold: u32,
    consecutive_failures: u32,
}

impl ThresholdRecovery {
    #[must_use]
    pub fn new(failure_threshold: u32) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            consecutive_failures: 0,
        }
    }

    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn on_success(&mut self) -> RecoveryAction {
        self.consecutive_failures = 0;
        RecoveryAction::Continue
    }

    pub fn on_failure(&mut self, _reason: &str) -> RecoveryAction {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.failure_threshold {
            RecoveryAction::RequestExit
        } else {
            RecoveryAction::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_exit_only_after_threshold_consecutive_failures() {
        let mut recovery = ThresholdRecovery::new(3);
        assert_eq!(recovery.on_failure("x"), RecoveryAction::Continue);
        assert_eq!(recovery.on_failure("x"), RecoveryAction::Continue);
        assert_eq!(recovery.on_failure("x"), RecoveryAction::RequestExit);
    }

    #[test]
    fn success_resets_failure_count() {
        let mut recovery = ThresholdRecovery::new(2);
        recovery.on_failure("x");
        recovery.on_success();
        assert_eq!(recovery.on_failure("x"), RecoveryAction::Continue);
        assert_eq!(recovery.consecutive_failures(), 1);
    }
}
