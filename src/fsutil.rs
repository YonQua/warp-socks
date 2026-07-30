// 小工具：把文件权限限制为仅所有者可读写（对应 shell 里散落的 chmod 600）。

use std::path::Path;

#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    if let Ok(meta) = fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_mode(0o600);
        let _ = fs::set_permissions(path, perm);
    }
}

#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &Path) {}
