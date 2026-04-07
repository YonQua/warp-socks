#!/bin/sh

TRACE_URL_DEFAULT="https://cloudflare.com/cdn-cgi/trace"
TRACE_IP_URL_DEFAULT="https://1.1.1.1/cdn-cgi/trace"
LOG_TIMEZONE_DEFAULT="CST-8"
LOG_TIME_FORMAT_DEFAULT="%Y-%m-%d %H:%M:%S %Z"
LOG_MODE_DEFAULT="teams"

log_timestamp() {
  TZ="${LOG_TIMEZONE:-$LOG_TIMEZONE_DEFAULT}" \
    date +"${LOG_TIME_FORMAT:-$LOG_TIME_FORMAT_DEFAULT}"
}

current_log_mode() {
  if [ -n "${LOG_MODE:-}" ]; then
    printf '%s' "$LOG_MODE"
    return 0
  fi

  printf '%s' "$LOG_MODE_DEFAULT"
}

emit_log_line() {
  component="$1"
  level="$2"
  shift 2
  mode="$(current_log_mode)"
  component_prefix=""
  if [ -n "$component" ]; then
    component_prefix="[$component]"
  fi

  if [ -n "$mode" ]; then
    printf '%s %s[%s][mode=%s] %s\n' "$(log_timestamp)" "$component_prefix" "$level" "$mode" "$*"
  else
    printf '%s %s[%s] %s\n' "$(log_timestamp)" "$component_prefix" "$level" "$*"
  fi
}

log_info() {
  component="$1"
  shift
  emit_log_line "$component" "INFO" "$*"
}

log_warn() {
  component="$1"
  shift
  emit_log_line "$component" "WARN" "$*" >&2
}

log_error() {
  component="$1"
  shift
  emit_log_line "$component" "ERROR" "$*" >&2
}

format_log_stream() {
  component="$1"
  level="${2:-INFO}"
  filter_fn="${3:-}"

  while IFS= read -r line || [ -n "$line" ]; do
    if [ -n "$filter_fn" ] && ! "$filter_fn" "$line"; then
      continue
    fi
    emit_log_line "$component" "$level" "$line"
  done
}

create_formatted_log_pipe() {
  pipe_path="${1:-}"
  component="$2"
  level="${3:-INFO}"
  filter_fn="${4:-}"

  if [ -n "$pipe_path" ]; then
    rm -f "$pipe_path"
  else
    pipe_path="$(mktemp /tmp/warp-socks-log.XXXXXX)"
    rm -f "$pipe_path"
  fi

  mkfifo "$pipe_path"
  (
    format_log_stream "$component" "$level" "$filter_fn" <"$pipe_path"
    rm -f "$pipe_path"
  ) &

  FORMATTED_LOG_PIPE="$pipe_path"
  FORMATTED_LOG_READER_PID="$!"
}

run_with_formatted_logs() {
  component="$1"
  level="${2:-INFO}"
  filter_fn="${3:-}"
  shift 3

  create_formatted_log_pipe "" "$component" "$level" "$filter_fn"

  if "$@" >"$FORMATTED_LOG_PIPE" 2>&1; then
    cmd_status=0
  else
    cmd_status=$?
  fi

  wait "$FORMATTED_LOG_READER_PID" || true
  return "$cmd_status"
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

extract_trace_field() {
  field="$1"
  sed -n "s/^${field}=\(.*\)$/\1/p" | head -n 1
}

probe_direct_trace_ip() {
  timeout_seconds="$(sanitize_positive_int "$1" 5)"
  trace_url="${2:-$TRACE_IP_URL_DEFAULT}"
  trace="$(curl -s --max-time "$timeout_seconds" "$trace_url" || true)"
  printf '%s\n' "$trace" | extract_trace_field ip
}

probe_socks_trace() {
  mode="$1"
  port="$2"
  timeout_seconds="$(sanitize_positive_int "$3" 10)"
  trace_url="${4:-$TRACE_URL_DEFAULT}"
  trace_file="$(mktemp)"
  err_file="$(mktemp)"
  reason=""

  if [ "$mode" = "remote_dns" ]; then
    if ! curl \
      --silent \
      --show-error \
      --fail \
      --max-time "$timeout_seconds" \
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
      --max-time "$timeout_seconds" \
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
