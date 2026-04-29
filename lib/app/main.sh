#!/bin/sh

warp_main() {
  mkdir -p "$WG_DIR"
  normalize_runtime_tuning
  verify_runtime_environment
  clear_healthcheck_runtime_state
  trap 'runtime_handle_shutdown TERM' TERM
  trap 'runtime_handle_shutdown INT' INT
  trap 'runtime_handle_shutdown HUP' HUP

  LOG_MODE="teams"
  export LOG_MODE

  log "启动调优参数: register_retries=${REGISTER_RETRIES}, register_retry_delay=${REGISTER_RETRY_DELAY}s, startup_probe_retries=${STARTUP_EGRESS_PROBE_RETRIES}, startup_probe_delay=${STARTUP_EGRESS_PROBE_DELAY}s, startup_probe_timeout=${STARTUP_EGRESS_PROBE_TIMEOUT}s, healthcheck_probe_timeout=${HEALTHCHECK_PROBE_TIMEOUT}s, healthcheck_failure_threshold=${HEALTHCHECK_FAILURE_THRESHOLD}"
  log "当前注册后端: teams"
  account_ensure_state
  tunnel_start
  socks_start
}
