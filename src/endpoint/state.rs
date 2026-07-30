// 对应 lib/core/endpoint-state.sh：把 last_good_endpoint 和每个 endpoint 的
// 冷却截止时间戳存到一个 JSON 文件里，重启进程后依然可读。

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::fsutil::restrict_to_owner;

#[derive(Serialize, Deserialize, Default)]
struct State {
    #[serde(default)]
    last_good_endpoint: String,
    #[serde(default)]
    cooldowns: HashMap<String, u64>,
}

/// [`EndpointStore`] 的 JSON 文件实现。
pub struct JsonFileEndpointStore {
    path: PathBuf,
    state: State,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl JsonFileEndpointStore {
    /// 加载状态文件（不存在则视为空状态），并清理已过期的冷却记录。
    ///
    /// # Errors
    /// 文件读取失败或写回失败时返回错误。
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let existed = path.exists();
        let state = if existed {
            let data = fs::read(&path).with_context(|| format!("读取 {} 失败", path.display()))?;
            serde_json::from_slice(&data).unwrap_or_default()
        } else {
            State::default()
        };

        let mut store = Self { path, state };
        store.prune_cooldowns(!existed)?;
        Ok(store)
    }

    fn prune_cooldowns(&mut self, force_save: bool) -> Result<()> {
        let now = now_unix();
        let before = self.state.cooldowns.len();
        self.state.cooldowns.retain(|_, until| *until > now);
        if force_save || before != self.state.cooldowns.len() {
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("创建 {} 失败", parent.display()))?;
        }
        let data = serde_json::to_vec_pretty(&self.state).context("序列化 endpoint 状态失败")?;
        fs::write(&self.path, data)
            .with_context(|| format!("写入 {} 失败", self.path.display()))?;
        restrict_to_owner(&self.path);
        Ok(())
    }
}

impl JsonFileEndpointStore {
    #[must_use]
    pub fn last_good(&self) -> Option<String> {
        if self.state.last_good_endpoint.is_empty() {
            None
        } else {
            Some(self.state.last_good_endpoint.clone())
        }
    }

    #[must_use]
    pub fn cooldown_remaining(&self, endpoint: &str) -> Duration {
        let Some(until) = self.state.cooldowns.get(endpoint).copied() else {
            return Duration::ZERO;
        };
        let now = now_unix();
        if until <= now {
            Duration::ZERO
        } else {
            Duration::from_secs(until - now)
        }
    }

    #[must_use]
    pub fn is_cooling_down(&self, endpoint: &str) -> bool {
        !self.cooldown_remaining(endpoint).is_zero()
    }

    /// # Errors
    /// 状态持久化失败时返回错误。
    pub fn record_success(&mut self, endpoint: &str) -> Result<()> {
        self.state.last_good_endpoint = endpoint.to_string();
        self.state.cooldowns.remove(endpoint);
        self.save()
    }

    /// # Errors
    /// 状态持久化失败时返回错误。
    pub fn mark_cooldown(&mut self, endpoint: &str, duration: Duration) -> Result<()> {
        let until = now_unix() + duration.as_secs();
        self.state.cooldowns.insert(endpoint.to_string(), until);
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_success_clears_cooldown_and_becomes_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint-state.json");
        let mut store = JsonFileEndpointStore::load(&path).unwrap();

        store
            .mark_cooldown("1.1.1.1:2408", Duration::from_secs(60))
            .unwrap();
        assert!(store.is_cooling_down("1.1.1.1:2408"));

        store.record_success("1.1.1.1:2408").unwrap();
        assert!(!store.is_cooling_down("1.1.1.1:2408"));
        assert_eq!(store.last_good().as_deref(), Some("1.1.1.1:2408"));
    }

    #[test]
    fn reloading_prunes_expired_cooldowns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoint-state.json");
        let mut store = JsonFileEndpointStore::load(&path).unwrap();
        store.mark_cooldown("1.1.1.1:2408", Duration::ZERO).unwrap();

        let reloaded = JsonFileEndpointStore::load(&path).unwrap();
        assert!(!reloaded.is_cooling_down("1.1.1.1:2408"));
    }
}
