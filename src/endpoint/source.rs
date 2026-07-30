// 对应 lib/domain/endpoints.sh：候选归一化、内置候选池、以及按 last_good/
// 冷却状态排序候选列表的逻辑。

use std::collections::HashSet;
use std::net::IpAddr;

use super::JsonFileEndpointStore;

/// 内置默认 endpoint 候选池，对应 lib/app/env.sh: DEFAULT_ENDPOINT_CANDIDATES。
const BUILTIN_CANDIDATES: &[&str] = &[
    "162.159.193.5:2408",
    "162.159.193.9:2408",
    "162.159.193.8:2408",
    "162.159.193.3:2408",
    "162.159.193.7:2408",
    "162.159.193.47:2408",
    "162.159.192.1:2408",
    "162.159.195.1:2408",
];

/// 归一化单个 endpoint：`host[:port]`，IPv6 归一化为 `[host]:port`；缺省端口 2408。
/// 对应 lib/domain/endpoints.sh: normalize_endpoint_value。
#[must_use]
pub fn normalize_endpoint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (host, port) = if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        (host.to_string(), after.strip_prefix(':').unwrap_or(""))
    } else if let Some(idx) = trimmed.rfind(':') {
        (trimmed[..idx].to_string(), &trimmed[idx + 1..])
    } else {
        (trimmed.to_string(), "")
    };

    if host.is_empty() {
        return None;
    }
    let port = if port.is_empty() { "2408" } else { port };
    let port_num: u16 = port.parse().ok().filter(|&p| p >= 1)?;

    Some(format_endpoint(&host, port_num))
}

fn format_endpoint(host: &str, port: u16) -> String {
    let looks_like_ipv6 = host
        .parse::<IpAddr>()
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false)
        || host.contains(':');
    if looks_like_ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn dedup_preserve_order(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

/// 有手工候选（`ENDPOINT_CANDIDATES` 环境变量，逗号分隔）就用手工候选，否则
/// 退回内置候选池，对应 lib/domain/endpoints.sh: build_endpoint_candidate_file
/// 里的来源选择。
#[must_use]
pub fn candidate_pool(manual_csv: &str) -> Vec<String> {
    let manual = dedup_preserve_order(manual_csv.split(',').filter_map(normalize_endpoint));
    if manual.is_empty() {
        dedup_preserve_order(BUILTIN_CANDIDATES.iter().map(|s| (*s).to_string()))
    } else {
        manual
    }
}

/// 按 last_good 优先、未冷却在前/冷却中在后排序候选列表，对应
/// lib/domain/endpoints.sh: reorder_endpoint_candidates。
#[must_use]
pub fn plan_candidates(pool: Vec<String>, store: &JsonFileEndpointStore) -> Vec<String> {
    let mut merged = Vec::new();
    if let Some(last_good) = store.last_good() {
        merged.push(last_good);
    }
    merged.extend(pool);
    let merged = dedup_preserve_order(merged);

    let (ready, cooling): (Vec<_>, Vec<_>) = merged
        .into_iter()
        .partition(|ep| !store.is_cooling_down(ep));
    ready.into_iter().chain(cooling).collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn normalizes_host_port_and_defaults_port() {
        assert_eq!(
            normalize_endpoint("1.1.1.1:2408").as_deref(),
            Some("1.1.1.1:2408")
        );
        assert_eq!(
            normalize_endpoint("1.1.1.1").as_deref(),
            Some("1.1.1.1:2408")
        );
        assert_eq!(
            normalize_endpoint("[2606:4700::1111]:2408").as_deref(),
            Some("[2606:4700::1111]:2408")
        );
        // 裸 IPv6（不带 []）没有可靠的端口分隔位置——shell 版本同样不支持，
        // 只支持带端口时用 [] 包裹的形式。
        assert_eq!(normalize_endpoint("  "), None);
        assert_eq!(normalize_endpoint("host:0"), None);
    }

    #[test]
    fn plan_candidates_puts_last_good_first_and_cooling_down_last() {
        let pool = candidate_pool("1.1.1.1:2408,2.2.2.2:2408,3.3.3.3:2408");
        let dir = tempfile::tempdir().unwrap();
        let mut store =
            JsonFileEndpointStore::load(dir.path().join("endpoint-state.json")).unwrap();
        store.record_success("3.3.3.3:2408").unwrap();
        store
            .mark_cooldown("1.1.1.1:2408", Duration::from_secs(60))
            .unwrap();

        let plan = plan_candidates(pool, &store);
        assert_eq!(plan, vec!["3.3.3.3:2408", "2.2.2.2:2408", "1.1.1.1:2408"]);
    }
}
