#!/bin/sh

WARP_ERR_CONFIG=10
WARP_ERR_REGISTER=20
WARP_ERR_STATE=30
WARP_ERR_TUNNEL=40
WARP_ERR_PROXY=50
WARP_ERR_RECOVERY=60

warp_error() {
  error_type="$1"
  error_code="$2"
  shift 2
  log_error "$LOG_COMPONENT" "[error_type=${error_type}][code=${error_code}] $*"
}

fail() {
  warp_error "fatal" "${1:-1}" "${2:-未知错误。}"
  exit "${1:-1}"
}

fail_config() {
  fail "$WARP_ERR_CONFIG" "$1"
}

fail_register() {
  fail "$WARP_ERR_REGISTER" "$1"
}

fail_state() {
  fail "$WARP_ERR_STATE" "$1"
}

fail_tunnel() {
  fail "$WARP_ERR_TUNNEL" "$1"
}

fail_proxy() {
  fail "$WARP_ERR_PROXY" "$1"
}
