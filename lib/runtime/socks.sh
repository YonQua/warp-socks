#!/bin/sh

should_emit_microsocks_log_line() {
  line="$1"
  if is_true "$MICROSOCKS_LOG_LOCAL_CLIENTS"; then
    return 0
  fi
  case "$line" in
    client*\ 127.0.0.1:\ connected\ to\ *|client*\ \[::1\]:\ connected\ to\ *|client*\ ::1:\ connected\ to\ *)
      return 1
      ;;
  esac
  return 0
}

socks_stop_child() {
  child_pid="${1:-}"
  [ -n "$child_pid" ] || return 0

  if kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$child_pid" 2>/dev/null; then
      kill -KILL "$child_pid" 2>/dev/null || true
    fi
  fi

  wait "$child_pid" 2>/dev/null || true
}

runtime_exit_supervisor() {
  exit_code="$1"
  clear_healthcheck_runtime_state
  socks_stop_child "$MICROSOCKS_PID"
  tunnel_bring_down_if_present
  exit "$exit_code"
}

runtime_handle_shutdown() {
  signal_name="$1"
  log "收到 ${signal_name}，正在停止 SOCKS5 并清理隧道。"
  runtime_exit_supervisor 0
}

socks_supervise_child() {
  child_pid="$1"

  while :; do
    if [ -f "$HEALTHCHECK_RESTART_REQUEST_FILE" ]; then
      log "检测到 healthcheck 写入重启请求，停止 SOCKS5 并退出容器。"
      runtime_exit_supervisor 1
    fi

    if ! kill -0 "$child_pid" 2>/dev/null; then
      wait "$child_pid"
      return $?
    fi

    sleep 1
  done
}

socks_start() {
  microsocks_log_pipe="/tmp/warp-socks-microsocks.log.pipe"
  mkdir -p "$HEALTHCHECK_STATE_DIR"
  clear_healthcheck_runtime_state
  log "启动无认证 SOCKS5（容器内监听）: ${LISTEN_ADDR}:${LISTEN_PORT}"
  log "Docker 发布端口（宿主机入口）: ${HOST_LISTEN_ADDR}:${HOST_LISTEN_PORT} -> 容器 ${LISTEN_ADDR}:${LISTEN_PORT}"

  if ! is_true "$MICROSOCKS_LOG_ACCESS"; then
    log "microsocks 连接日志已关闭。"
    microsocks -q -i "$LISTEN_ADDR" -p "$LISTEN_PORT" &
    MICROSOCKS_PID="$!"
    mark_healthcheck_runtime_ready
    socks_supervise_child "$MICROSOCKS_PID"
    return 0
  fi

  if is_true "$MICROSOCKS_LOG_LOCAL_CLIENTS"; then
    log "microsocks 连接日志已启用，包含本地 127.0.0.1/::1 探测流量。"
  else
    log "microsocks 连接日志已启用，默认隐藏本地 127.0.0.1/::1 探测流量。"
  fi

  create_formatted_log_pipe "$microsocks_log_pipe" "microsocks" "INFO" "should_emit_microsocks_log_line"
  microsocks -i "$LISTEN_ADDR" -p "$LISTEN_PORT" >"$FORMATTED_LOG_PIPE" 2>&1 &
  MICROSOCKS_PID="$!"
  mark_healthcheck_runtime_ready
  socks_supervise_child "$MICROSOCKS_PID"
}
