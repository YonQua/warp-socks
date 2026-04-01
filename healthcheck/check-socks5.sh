#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/../lib/warp-common.sh"
[ -f "$COMMON_SH" ] || COMMON_SH="/usr/local/lib/warp-common.sh"
. "$COMMON_SH"

port="${BIND_PORT:-1080}"
trace_url="https://cloudflare.com/cdn-cgi/trace"
state_dir="/tmp/warp-socks-healthcheck"
fail_count_file="${state_dir}/fail-count"
auto_recover="${HEALTHCHECK_AUTO_RECOVER:-1}"
failure_threshold="${HEALTHCHECK_AUTO_RECOVER_THRESHOLD:-3}"
LOG_MODE_STATE_FILE="${LOG_MODE_STATE_FILE:-/etc/wireguard/state.json}"
LOG_COMPONENT="healthcheck"

log() {
  emit_log_line "$LOG_COMPONENT" "INFO" "$*" >&2
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
previous_failures="$(read_fail_count)"

remote_reason=""
if remote_reason="$(probe_socks_trace remote_dns "$port" 10 "$trace_url")"; then
  if [ "$previous_failures" -gt 0 ]; then
    log "远端解析路径恢复，已清除连续失败计数 ${previous_failures}。"
  fi
  clear_fail_count
  exit 0
fi

local_dns_ok=0
local_reason=""
if local_reason="$(probe_socks_trace local_dns "$port" 10 "$trace_url")"; then
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
  endpoint_total="$(endpoint_candidate_count)"
  if [ "$endpoint_total" -gt 1 ]; then
    log "连续失败达到阈值，容器重启后会按显式 endpoint 候选顺序重新尝试。"
  fi
  log "连续失败达到阈值，发送 TERM 给 PID 1 触发容器重启。"
  kill -TERM 1 || log "向 PID 1 发送 TERM 失败。"
fi

exit 1
