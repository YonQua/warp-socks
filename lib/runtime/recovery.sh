#!/bin/sh

recovery_mark_active_endpoint_cooldown() {
  active_endpoint="$(tunnel_current_endpoint)"
  [ -n "$active_endpoint" ] || return 0

  endpoint_state_mark_cooldown "$active_endpoint" "$RUNTIME_ENDPOINT_COOLDOWN_SECONDS_DEFAULT"
  cooldown_remaining="$(endpoint_state_cooldown_remaining "$active_endpoint")"
  log "当前 endpoint ${active_endpoint} 已标记冷却 ${cooldown_remaining} 秒，容器重启后会优先尝试其他候选。"
}

warp_healthcheck_main() {
  failure_threshold="$HEALTHCHECK_FAILURE_THRESHOLD"
  probe_timeout_seconds="$HEALTHCHECK_PROBE_TIMEOUT"

  LOG_COMPONENT="healthcheck"

  mkdir -p "$HEALTHCHECK_STATE_DIR"

  # 启动阶段由入口脚本自己的出口探测与失败退出负责。
  # 只有当 PID 1 明确标记“运行态已 ready”后，healthcheck 才接管运行期恢复。
  if [ ! -f "$HEALTHCHECK_READY_FILE" ]; then
    healthcheck_clear_recovery_state
    exit 0
  fi

  previous_failures="$(healthcheck_read_fail_count)"

  if probe_socks_trace "$LISTEN_PORT" "$probe_timeout_seconds" "$TRACE_URL_DEFAULT"; then
    if [ "$previous_failures" -gt 0 ]; then
      log "探测恢复，已清除连续失败计数 ${previous_failures}。"
    fi
    healthcheck_clear_recovery_state
    exit 0
  fi

  current_failures=$((previous_failures + 1))
  healthcheck_write_fail_count "$current_failures"
  log "SOCKS 出口探测失败: ${PROBE_SOCKS_TRACE_REASON:-unknown}; endpoint=$(tunnel_current_endpoint); failures=${current_failures}/${failure_threshold}"

  if [ "$current_failures" -ge "$failure_threshold" ]; then
    recovery_mark_active_endpoint_cooldown

    if [ -n "${ENDPOINT_CANDIDATES:-}" ]; then
      log "连续失败达到阈值，容器重启后会按显式 endpoint 候选顺序重新尝试。"
    else
      log "连续失败达到阈值，容器重启后会按自动 endpoint 策略重新尝试。"
    fi
    healthcheck_request_container_restart "$current_failures"
  fi

  exit 1
}
