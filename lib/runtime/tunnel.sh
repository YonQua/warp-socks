#!/bin/sh

# CLI：wg0.conf 路径 + 监听地址 + 可选 trick 模式；DNS 服务器和 MTU/keepalive
# 都硬编码在二进制里，等价于 warp-plus --wgconf 模式实际生效的那部分。日志是
# 它自己按行输出的中文文本，每次连接接受/失败都会打一行"连接 ..."开头的日志，
# 过滤规则匹配这个前缀；二进制自身不带时间戳，这里用 while read 逐行接上
# log_timestamp()（和其他日志同一套时区/格式配置），不用 awk 是因为 busybox
# awk 没有 strftime，拿不到时间。
tunnel_start_process() {
  endpoint="$1"
  bind_addr="${LISTEN_ADDR}:${LISTEN_PORT}"

  set -- "$WARP_RS_BIN" "$WG_CONF" "$bind_addr" "$WARP_RS_TRICK"

  : >"$TUNNEL_LOG_FILE"
  "$@" >>"$TUNNEL_LOG_FILE" 2>&1 &
  TUNNEL_PID="$!"

  tail -n +1 -F "$TUNNEL_LOG_FILE" | while IFS= read -r conn_line; do
    case "$conn_line" in
      连接\ *) printf '%s %s\n' "$(log_timestamp)" "$conn_line" ;;
    esac
  done &
  WARP_LOG_TAIL_PID="$!"

  WARP_LOG_RAW_TAIL_PID=""
  if is_true "$TUNNEL_LOG_VERBOSE"; then
    tail -n +1 -F "$TUNNEL_LOG_FILE" &
    WARP_LOG_RAW_TAIL_PID="$!"
  fi

  log "启动 warp-socks-rs：endpoint=${endpoint}, bind=${bind_addr}, trick=${WARP_RS_TRICK}"
}

# 当前运行中的 endpoint 只有 wg0.conf 一个真相源，直接解析，不额外维护状态文件。
tunnel_current_endpoint() {
  [ -s "$WG_CONF" ] || return 0
  sed -n 's/^Endpoint[[:space:]]*=[[:space:]]*//p' "$WG_CONF" | head -n 1
}

tunnel_stop_process() {
  pid="${TUNNEL_PID:-}"
  TUNNEL_PID=""
  [ -n "$pid" ] || return 0

  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true

  # tail -F 不会因为隧道进程退出而自己结束，按固定文件路径显式清理；
  # 管道里的 awk 会在 tail 退出、写端关闭后自然收到 EOF 退出。
  pkill -f "$TUNNEL_LOG_FILE" 2>/dev/null || true

  tail_pid="${WARP_LOG_TAIL_PID:-}"
  WARP_LOG_TAIL_PID=""
  if [ -n "$tail_pid" ] && kill -0 "$tail_pid" 2>/dev/null; then
    kill -TERM "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
  fi

  raw_tail_pid="${WARP_LOG_RAW_TAIL_PID:-}"
  WARP_LOG_RAW_TAIL_PID=""
  if [ -n "$raw_tail_pid" ] && kill -0 "$raw_tail_pid" 2>/dev/null; then
    kill -TERM "$raw_tail_pid" 2>/dev/null || true
    wait "$raw_tail_pid" 2>/dev/null || true
  fi
}

# 单一探测循环：既覆盖"进程刚起来还没监听"，也覆盖"监听了但隧道没打通"。
# warp-socks-rs 是一个进程同时干两件事，没必要拆成两级等待。
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

    if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
      stderr_hint=""
      if [ -s "$TUNNEL_LOG_FILE" ]; then
        stderr_hint="$(tail -n 20 "$TUNNEL_LOG_FILE" | tr '\n' ' ' | tr -s ' ' | cut -c 1-180)"
      fi
      if [ -n "$stderr_hint" ]; then
        PROBE_SOCKS_TRACE_REASON="隧道进程已退出: ${stderr_hint}"
      else
        PROBE_SOCKS_TRACE_REASON="隧道进程已退出。"
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
  tunnel_stop_process
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
    tunnel_start_process "$endpoint_override"

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
  tunnel_stop_process
  exit "$exit_code"
}

runtime_handle_shutdown() {
  signal_name="$1"
  log "收到 ${signal_name}，正在停止隧道/SOCKS5。"
  runtime_exit_supervisor 0
}

tunnel_serve() {
  mark_healthcheck_runtime_ready
  log "SOCKS5 已由 warp-socks-rs 提供（容器内监听）: ${LISTEN_ADDR}:${LISTEN_PORT}"
  log "Docker 发布端口（宿主机入口）: ${HOST_LISTEN_ADDR}:${HOST_LISTEN_PORT} -> 容器 ${LISTEN_ADDR}:${LISTEN_PORT}"

  while :; do
    if [ -f "$HEALTHCHECK_RESTART_REQUEST_FILE" ]; then
      log "检测到 healthcheck 写入重启请求，停止 SOCKS5 并退出容器。"
      runtime_exit_supervisor 1
    fi

    if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
      wait "$TUNNEL_PID"
      runtime_exit_supervisor $?
    fi

    sleep 1
  done
}
