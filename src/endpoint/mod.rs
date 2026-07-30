// endpoint 候选池与冷却状态。只有一种持久化实现（JSON 文件）、一种候选来源
// 选择策略，不做接口抽象——直接用具体类型。

pub mod source;
pub mod state;

pub use source::{candidate_pool, normalize_endpoint, plan_candidates};
pub use state::JsonFileEndpointStore;
