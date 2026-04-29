#!/bin/sh

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

log() {
  log_info "$LOG_COMPONENT" "$*"
}

warn() {
  log_warn "$LOG_COMPONENT" "$*"
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
