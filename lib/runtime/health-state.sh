#!/bin/sh

clear_healthcheck_runtime_state() {
  rm -f "$HEALTHCHECK_FAIL_COUNT_FILE" "$HEALTHCHECK_RESTART_REQUEST_FILE" "$HEALTHCHECK_READY_FILE"
}

mark_healthcheck_runtime_ready() {
  mkdir -p "$HEALTHCHECK_STATE_DIR"
  : >"$HEALTHCHECK_READY_FILE"
}

healthcheck_clear_restart_request() {
  rm -f "$HEALTHCHECK_RESTART_REQUEST_FILE"
}

healthcheck_read_fail_count() {
  if [ -s "$HEALTHCHECK_FAIL_COUNT_FILE" ]; then
    count="$(cat "$HEALTHCHECK_FAIL_COUNT_FILE" 2>/dev/null || true)"
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

healthcheck_write_fail_count() {
  printf '%s\n' "$1" >"$HEALTHCHECK_FAIL_COUNT_FILE"
}

healthcheck_clear_fail_count() {
  rm -f "$HEALTHCHECK_FAIL_COUNT_FILE"
}

healthcheck_request_container_restart() {
  current_failures="$1"
  requested_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"requested_at":"%s","failures":"%s"}\n' "$requested_at" "$current_failures" >"$HEALTHCHECK_RESTART_REQUEST_FILE"
  chmod 600 "$HEALTHCHECK_RESTART_REQUEST_FILE"
  log "连续失败达到阈值，已写入重启请求标记，等待 PID 1 监督进程退出容器。"
}

healthcheck_clear_recovery_state() {
  healthcheck_clear_fail_count
  healthcheck_clear_restart_request
}
