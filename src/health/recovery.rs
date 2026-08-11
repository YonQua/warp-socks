/// Supervisor 使用的健康失败阈值；这里只计数，不执行恢复动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Continue,
    RequestExit,
}

pub struct ThresholdRecovery {
    threshold: u32,
    consecutive_failures: u32,
}

impl ThresholdRecovery {
    #[must_use]
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold: threshold.max(1),
            consecutive_failures: 0,
        }
    }

    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
    }

    pub fn on_failure(&mut self) -> RecoveryAction {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.threshold {
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
        assert_eq!(recovery.on_failure(), RecoveryAction::Continue);
        assert_eq!(recovery.on_failure(), RecoveryAction::Continue);
        assert_eq!(recovery.on_failure(), RecoveryAction::RequestExit);
    }

    #[test]
    fn success_resets_failure_count() {
        let mut recovery = ThresholdRecovery::new(2);
        recovery.on_failure();
        recovery.on_success();
        assert_eq!(recovery.on_failure(), RecoveryAction::Continue);
        assert_eq!(recovery.consecutive_failures(), 1);
    }
}
