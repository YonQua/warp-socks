#!/bin/sh

tunnel_start_warp_plus() {
  endpoint="$1"
  bind_addr="${LISTEN_ADDR}:${LISTEN_PORT}"

  # --endpoint/--reserved/-4 在 --wgconf 模式下都不生效（app/app.go 的
  # runWireguard() 不读这三个字段），不传，避免让人误以为它们在起作用；
  # 真正的 endpoint/reserved 由 wg0.conf 决定。
  set -- "$WARP_PLUS_BIN" \
    --wgconf "$WG_CONF" \
    --dns 1.1.1.1 \
    --test-url "$TRACE_URL_DEFAULT" \
    -b "$bind_addr"
  is_true "$WARP_PLUS_LOG_VERBOSE" && set -- "$@" -v

  # 单一日志通道：无论是否 verbose，都先落到同一个文件，供进程异常退出时
  # 读取尾部诊断；verbose 时再额外用一个可追踪 PID 的 tail 把它接到容器日志。
  : >/tmp/warp-plus.log
  "$@" >>/tmp/warp-plus.log 2>&1 &
  WARP_PLUS_PID="$!"

  WARP_LOG_TAIL_PID=""
  if is_true "$WARP_PLUS_LOG_VERBOSE"; then
    tail -n +1 -F /tmp/warp-plus.log &
    WARP_LOG_TAIL_PID="$!"
  fi

  log "启动 warp-plus：endpoint=${endpoint}, bind=${bind_addr}"
}

# 当前运行中的 endpoint 只有 wg0.conf 一个真相源，直接解析，不额外维护状态文件。
tunnel_current_endpoint() {
  [ -s "$WG_CONF" ] || return 0
  sed -n 's/^Endpoint[[:space:]]*=[[:space:]]*//p' "$WG_CONF" | head -n 1
}

tunnel_stop_warp_plus() {
  pid="${WARP_PLUS_PID:-}"
  WARP_PLUS_PID=""
  [ -n "$pid" ] || return 0

  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true

  tail_pid="${WARP_LOG_TAIL_PID:-}"
  WARP_LOG_TAIL_PID=""
  if [ -n "$tail_pid" ] && kill -0 "$tail_pid" 2>/dev/null; then
    kill -TERM "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
  fi
}

# 单一探测循环：既覆盖"进程刚起来还没监听"，也覆盖"监听了但隧道没打通"。
# warp-plus 是一个进程同时干两件事，没必要拆成两级等待。
# 每次探测前先按真实已耗时算出剩余预算，探测超时钳制在剩余预算内，
# 保证总耗时不会超过 overall_timeout；过程中不逐次打日志，失败原因和
# 尝试次数交给调用方在候选失败时汇总打一条摘要。
tunnel_wait_ready() {
  overall_timeout="$1"
  per_attempt_timeout="$2"
  poll_interval="$3"
  start_ts="$(date +%s)"
  attempt=0

  while :; do
    elapsed=$(( $(date +%s) - start_ts ))
    remaining=$((overall_timeout - elapsed))
    [ "$remaining" -gt 0 ] || break

    if ! kill -0 "$WARP_PLUS_PID" 2>/dev/null; then
      stderr_hint=""
      if [ -s /tmp/warp-plus.log ]; then
        stderr_hint="$(tail -n 20 /tmp/warp-plus.log | tr '\n' ' ' | tr -s ' ' | cut -c 1-180)"
      fi
      if [ -n "$stderr_hint" ]; then
        PROBE_SOCKS_TRACE_REASON="warp-plus 进程已退出: ${stderr_hint}"
      else
        PROBE_SOCKS_TRACE_REASON="warp-plus 进程已退出。"
      fi
      break
    fi

    attempt=$((attempt + 1))
    this_timeout="$per_attempt_timeout"
    [ "$remaining" -lt "$this_timeout" ] && this_timeout="$remaining"

    if probe_socks_trace "$LISTEN_PORT" "$this_timeout" "$TRACE_URL_DEFAULT"; then
      if [ -n "${PROBE_SOCKS_TRACE_IP:-}" ]; then
        log "当前出口 IP: ${PROBE_SOCKS_TRACE_IP}"
      fi
      return 0
    fi

    sleep "$poll_interval"
  done

  TUNNEL_WAIT_ATTEMPTS="$attempt"
  TUNNEL_WAIT_ELAPSED_SECONDS=$(( $(date +%s) - start_ts ))
  return 1
}

tunnel_mark_candidate_failed() {
  endpoint="$1"
  reason="$2"

  warn "候选 ${endpoint} 就绪失败: attempts=${TUNNEL_WAIT_ATTEMPTS:-0}, elapsed=${TUNNEL_WAIT_ELAPSED_SECONDS:-0}s, reason=${reason}"
  endpoint_state_mark_cooldown "$endpoint" "$STARTUP_ENDPOINT_COOLDOWN_SECONDS"
  cooldown_remaining="$(endpoint_state_cooldown_remaining "$endpoint")"
  if [ "$cooldown_remaining" -gt 0 ]; then
    warn "当前 endpoint ${endpoint} 已进入 ${cooldown_remaining} 秒冷却。"
  fi
  tunnel_stop_warp_plus
}

tunnel_next_candidate_hint() {
  candidate_file="$1"
  index="$2"
  total="$3"
  [ "$total" -gt 1 ] && [ "$index" -lt "$total" ] || return 0
  sed -n "$((index + 1))p" "$candidate_file"
}

tunnel_start() {
  candidate_file="$(mktemp)"
  build_endpoint_candidate_file "$candidate_file"
  log_endpoint_candidate_plan "$candidate_file"
  candidate_count="$(count_endpoint_candidates "$candidate_file")"
  [ "$candidate_count" -gt 0 ] || fail_tunnel "未生成任何可用 endpoint 候选。"

  index=1
  while IFS= read -r endpoint_override; do
    [ -n "$endpoint_override" ] || continue

    build_wg_config_from_account "$endpoint_override"
    tunnel_start_warp_plus "$endpoint_override"

    if tunnel_wait_ready "$STARTUP_SOCKS_READY_TIMEOUT_SECONDS" "$STARTUP_EGRESS_PROBE_TIMEOUT" "$STARTUP_EGRESS_PROBE_DELAY"; then
      endpoint_state_record_success "$endpoint_override"
      rm -f "$candidate_file"
      log "隧道与 SOCKS 已就绪：endpoint=${endpoint_override}"
      return 0
    fi

    tunnel_mark_candidate_failed "$endpoint_override" "${PROBE_SOCKS_TRACE_REASON:-unknown}"

    next_endpoint="$(tunnel_next_candidate_hint "$candidate_file" "$index" "$candidate_count")"
    if [ -n "$next_endpoint" ]; then
      warn "切换到候选 $((index + 1))/${candidate_count}: ${next_endpoint}。"
    fi
    index=$((index + 1))
  done <"$candidate_file"

  rm -f "$candidate_file"
  fail_tunnel "启动阶段出口探测失败，退出等待容器重启。"
}

runtime_exit_supervisor() {
  exit_code="$1"
  clear_healthcheck_runtime_state
  tunnel_stop_warp_plus
  exit "$exit_code"
}

runtime_handle_shutdown() {
  signal_name="$1"
  log "收到 ${signal_name}，正在停止 warp-plus / SOCKS5。"
  runtime_exit_supervisor 0
}

tunnel_serve() {
  mark_healthcheck_runtime_ready
  log "SOCKS5 已由 warp-plus 提供（容器内监听）: ${LISTEN_ADDR}:${LISTEN_PORT}"
  log "Docker 发布端口（宿主机入口）: ${HOST_LISTEN_ADDR}:${HOST_LISTEN_PORT} -> 容器 ${LISTEN_ADDR}:${LISTEN_PORT}"

  while :; do
    if [ -f "$HEALTHCHECK_RESTART_REQUEST_FILE" ]; then
      log "检测到 healthcheck 写入重启请求，停止 SOCKS5 并退出容器。"
      runtime_exit_supervisor 1
    fi

    if ! kill -0 "$WARP_PLUS_PID" 2>/dev/null; then
      wait "$WARP_PLUS_PID"
      runtime_exit_supervisor $?
    fi

    sleep 1
  done
}
