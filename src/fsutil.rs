use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use std::path::Path;

/// 以私有权限创建同目录临时文件，完整写入后原子替换目标。
/// 父目录必须由管理员控制；共享临时目录须保留 sticky bit。
///
/// # Errors
/// 创建、写入或替换失败时返回错误，原目标保持不变。
pub fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".warp-socks-{:032x}.tmp", rand::random::<u128>()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    // 不打开目标路径：rename 替换目录项，不跟随符号链接或修改硬链接所指文件。
    let result = file.write_all(contents.as_ref()).and_then(|()| {
        drop(file);
        fs::rename(&temporary, path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
