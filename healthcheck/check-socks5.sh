#!/bin/sh
set -eu

port="${BIND_PORT:-1080}"
trace_url="https://cloudflare.com/cdn-cgi/trace"
state_dir="/tmp/warp-socks-healthcheck"
fail_count_file="${state_dir}/fail-count"
auto_recover="${HEALTHCHECK_AUTO_RECOVER:-1}"
failure_threshold="${HEALTHCHECK_AUTO_RECOVER_THRESHOLD:-3}"

log() {
  printf '%s %s\n' "==> [warp-socks][healthcheck]" "$*" >&2
}

is_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

sanitize_positive_int() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*|0)
      printf '%s' "$fallback"
      ;;
    *)
      printf '%s' "$value"
      ;;
  esac
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

probe_trace() {
  mode="$1"
  trace_file="$(mktemp)"
  err_file="$(mktemp)"
  reason=""

  if [ "$mode" = "remote_dns" ]; then
    if ! curl \
      --silent \
      --show-error \
      --fail \
      --max-time 10 \
      --socks5-hostname "127.0.0.1:${port}" \
      "$trace_url" \
      >"$trace_file" \
      2>"$err_file"; then
      reason="$(tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c 1-180)"
    fi
  else
    if ! curl \
      --silent \
      --show-error \
      --fail \
      --max-time 10 \
      --socks5 "127.0.0.1:${port}" \
      "$trace_url" \
      >"$trace_file" \
      2>"$err_file"; then
      reason="$(tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c 1-180)"
    fi
  fi

  if [ -z "$reason" ] && grep -qE '^warp=(on|plus)$' "$trace_file"; then
    rm -f "$trace_file" "$err_file"
    return 0
  fi

  if [ -z "$reason" ]; then
    reason="$(tr '\n' ' ' <"$trace_file" | tr -s ' ' | cut -c 1-180)"
    [ -n "$reason" ] || reason="响应缺少 warp 标记。"
  fi

  rm -f "$trace_file" "$err_file"
  printf '%s' "$reason"
  return 1
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
if remote_reason="$(probe_trace remote_dns)"; then
  if [ "$previous_failures" -gt 0 ]; then
    log "远端解析路径恢复，已清除连续失败计数 ${previous_failures}。"
  fi
  clear_fail_count
  exit 0
fi

local_dns_ok=0
local_reason=""
if local_reason="$(probe_trace local_dns)"; then
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
  log "连续失败达到阈值，发送 TERM 给 PID 1 触发容器重启。"
  kill -TERM 1 || log "向 PID 1 发送 TERM 失败。"
fi

exit 1
