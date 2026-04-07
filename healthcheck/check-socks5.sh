#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/../lib/warp-common.sh"
[ -f "$COMMON_SH" ] || COMMON_SH="/usr/local/lib/warp-common.sh"
. "$COMMON_SH"

port="1080"
trace_url="https://cloudflare.com/cdn-cgi/trace"
state_dir="/tmp/warp-socks-healthcheck"
fail_count_file="${state_dir}/fail-count"
restart_request_file="${state_dir}/restart-requested"
ready_file="${state_dir}/runtime-ready"
auto_recover="1"
failure_threshold="3"
# 运行期健康检查会顺序探测 socks5h 和 socks5 两条路径。
# 这里保留 10 秒单探测窗口，兼顾抖动网络下的容忍度；
# Dockerfile 里的 HEALTHCHECK timeout 必须始终大于“两次探测总耗时 + 脚本开销”，
# 否则 Docker 会先把脚本杀掉，后面的失败计数和重启请求逻辑根本来不及执行。
probe_timeout_seconds=10
LOG_MODE="${LOG_MODE:-teams}"
LOG_COMPONENT="healthcheck"

log() {
  emit_log_line "$LOG_COMPONENT" "INFO" "$*" >&2
}

clear_restart_request() {
  rm -f "$restart_request_file"
}

request_container_restart() {
  requested_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"requested_at":"%s","failures":"%s"}\n' "$requested_at" "$current_failures" >"$restart_request_file"
  chmod 600 "$restart_request_file"
  log "连续失败达到阈值，已写入重启请求标记，等待 PID 1 监督进程退出容器。"
}

clear_recovery_state() {
  clear_fail_count
  clear_restart_request
}

read_fail_count() {
  if [ -s "$fail_count_file" ]; then
    count="$(cat "$fail_count_file" 2>/dev/null || true)"
    case "$count" in
      ''|*[!0-9]*)
        printf '0'
        ;;
      *)
        printf '%s' "$count"
        ;;
    esac
  else
    printf '0'
  fi
}

write_fail_count() {
  printf '%s\n' "$1" >"$fail_count_file"
}

clear_fail_count() {
  rm -f "$fail_count_file"
}

latest_handshake() {
  ts="$(wg show wg0 latest-handshakes 2>/dev/null | awk 'NR==1 {print $2}')"
  case "${ts:-}" in
    ''|0)
      printf 'none'
      ;;
    *)
      printf '%s' "$ts"
      ;;
  esac
}

failure_threshold="$(sanitize_positive_int "$failure_threshold" 3)"
mkdir -p "$state_dir"

# 启动阶段由入口脚本自己的出口探测与失败退出负责。
# 只有当 PID 1 明确标记“运行态已 ready”后，healthcheck 才接管运行期恢复。
if [ ! -f "$ready_file" ]; then
  clear_recovery_state
  exit 0
fi

previous_failures="$(read_fail_count)"

remote_reason=""
if remote_reason="$(probe_socks_trace remote_dns "$port" "$probe_timeout_seconds" "$trace_url")"; then
  if [ "$previous_failures" -gt 0 ]; then
    log "远端解析路径恢复，已清除连续失败计数 ${previous_failures}。"
  fi
  clear_recovery_state
  exit 0
fi

local_dns_ok=0
local_reason=""
if local_reason="$(probe_socks_trace local_dns "$port" "$probe_timeout_seconds" "$trace_url")"; then
  local_dns_ok=1
else
  :
fi

current_failures=$((previous_failures + 1))
write_fail_count "$current_failures"

message="远端解析路径探测失败: ${remote_reason:-unknown}; latest_handshake=$(latest_handshake); failures=${current_failures}/${failure_threshold}"
if [ "$local_dns_ok" -eq 1 ]; then
  message="${message}; 本地解析路径仍可用，优先怀疑 socks5h 远端解析或上游路径抖动。"
else
  message="${message}; 本地解析路径也失败: ${local_reason:-unknown}"
fi
log "$message"

if is_true "$auto_recover" && [ "$current_failures" -ge "$failure_threshold" ]; then
  active_endpoint="$(endpoint_state_get_active)"
  if [ -z "$active_endpoint" ]; then
    active_endpoint="$(current_wg_conf_endpoint "/etc/wireguard/wg0.conf")"
  fi

  if [ -n "$active_endpoint" ]; then
    endpoint_state_mark_cooldown "$active_endpoint" "$ENDPOINT_COOLDOWN_SECONDS_DEFAULT"
    cooldown_remaining="$(endpoint_state_cooldown_remaining "$active_endpoint")"
    log "当前 endpoint ${active_endpoint} 已标记冷却 ${cooldown_remaining} 秒，容器重启后会优先尝试其他候选。"
  fi

  if [ -n "${ENDPOINT_CANDIDATES:-}" ]; then
    log "连续失败达到阈值，容器重启后会按显式 endpoint 候选顺序重新尝试。"
  else
    log "连续失败达到阈值，容器重启后会按自动 endpoint 策略重新尝试。"
  fi
  request_container_restart
fi

exit 1
