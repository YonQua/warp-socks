// 账户注册：Teams（WireGuard 账户）与 MASQUE 边缘注册是两条独立流程，产出
// 各自的凭据类型，供对应的 outbound 后端消费；调用方各自直接调用具体类型
// /函数，不需要共享接口。

pub mod masque;
pub mod teams;

pub use masque::{delete, load, register as register_masque, RegCredentials, Registration};
pub use teams::{write_wg_conf, TeamsRegistrar, WgAccount};
