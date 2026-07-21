#!/bin/sh

log_timestamp() {
  TZ="${LOG_TIMEZONE:-$LOG_TIMEZONE_DEFAULT}" \
    date +"${LOG_TIME_FORMAT:-$LOG_TIME_FORMAT_DEFAULT}"
}

emit_log_line() {
  component="$1"
  level="$2"
  shift 2
  component_prefix=""
  if [ -n "$component" ]; then
    component_prefix="[$component]"
  fi

  printf '%s %s[%s] %s\n' "$(log_timestamp)" "$component_prefix" "$level" "$*"
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
