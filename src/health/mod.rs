// 健康探测（SOCKS5 trace）与恢复策略（连续失败达到阈值就退出进程），
// 各只有一种实现，直接用具体类型。

pub mod heartbeat;
pub mod probe;
pub mod recovery;

pub use probe::{ProbeError, ProbeOutcome, SocksTraceProbe};
pub use recovery::{RecoveryAction, ThresholdRecovery};
