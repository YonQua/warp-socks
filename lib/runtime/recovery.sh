#!/bin/sh

recovery_latest_handshake() {
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

recovery_mark_active_endpoint_cooldown() {
  active_endpoint="$(tunnel_current_wg_conf_endpoint "/etc/wireguard/wg0.conf")"
  if [ -n "$active_endpoint" ]; then
    endpoint_state_mark_cooldown "$active_endpoint" "$RUNTIME_ENDPOINT_COOLDOWN_SECONDS_DEFAULT"
    cooldown_remaining="$(endpoint_state_cooldown_remaining "$active_endpoint")"
    log "当前 endpoint ${active_endpoint} 已标记冷却 ${cooldown_remaining} 秒，容器重启后会优先尝试其他候选。"
  fi
}

warp_healthcheck_main() {
  port="1080"
  trace_url="$TRACE_URL_DEFAULT"
  failure_threshold="$HEALTHCHECK_FAILURE_THRESHOLD"
  probe_timeout_seconds="$HEALTHCHECK_PROBE_TIMEOUT"

  LOG_MODE="${LOG_MODE:-teams}"
  LOG_COMPONENT="healthcheck"

  mkdir -p "$HEALTHCHECK_STATE_DIR"

  # 启动阶段由入口脚本自己的出口探测与失败退出负责。
  # 只有当 PID 1 明确标记“运行态已 ready”后，healthcheck 才接管运行期恢复。
  if [ ! -f "$HEALTHCHECK_READY_FILE" ]; then
    healthcheck_clear_recovery_state
    exit 0
  fi

  previous_failures="$(healthcheck_read_fail_count)"

  remote_reason=""
  if remote_reason="$(probe_socks_trace remote_dns "$port" "$probe_timeout_seconds" "$trace_url")"; then
    if [ "$previous_failures" -gt 0 ]; then
      log "远端解析路径恢复，已清除连续失败计数 ${previous_failures}。"
    fi
    healthcheck_clear_recovery_state
    exit 0
  fi

  local_dns_ok=0
  local_reason=""
  if local_reason="$(probe_socks_trace local_dns "$port" "$probe_timeout_seconds" "$trace_url")"; then
    local_dns_ok=1
  fi

  current_failures=$((previous_failures + 1))
  healthcheck_write_fail_count "$current_failures"

  message="远端解析路径探测失败: ${remote_reason:-unknown}; latest_handshake=$(recovery_latest_handshake); failures=${current_failures}/${failure_threshold}"
  if [ "$local_dns_ok" -eq 1 ]; then
    message="${message}; 本地解析路径仍可用，优先怀疑 socks5h 远端解析或上游路径抖动。"
  else
    message="${message}; 本地解析路径也失败: ${local_reason:-unknown}"
  fi
  log "$message"

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
