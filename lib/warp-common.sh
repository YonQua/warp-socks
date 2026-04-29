#!/bin/sh

if [ -z "${WARP_LIB_DIR:-}" ]; then
  if [ -f "$(dirname "$0")/lib/app/env.sh" ]; then
    WARP_LIB_DIR="$(CDPATH= cd -- "$(dirname "$0")/lib" && pwd)"
  elif [ -f "$(dirname "$0")/../lib/app/env.sh" ]; then
    WARP_LIB_DIR="$(CDPATH= cd -- "$(dirname "$0")/../lib" && pwd)"
  elif [ -f "/usr/local/lib/warp-socks/app/env.sh" ]; then
    WARP_LIB_DIR="/usr/local/lib/warp-socks"
  else
    printf '%s\n' "warp-common.sh: 无法定位 lib 目录。" >&2
    exit 1
  fi
fi

warp_source_lib() {
  rel_path="$1"
  # shellcheck disable=SC1090
  . "${WARP_LIB_DIR}/${rel_path}"
}

warp_source_lib "app/env.sh"
warp_source_lib "core/log.sh"
warp_source_lib "core/errors.sh"
warp_source_lib "core/utils.sh"
warp_source_lib "core/endpoint-state.sh"
warp_source_lib "core/probe.sh"
warp_source_lib "domain/endpoints.sh"
warp_source_lib "domain/account.sh"
warp_source_lib "domain/wireguard.sh"
warp_source_lib "runtime/health-state.sh"
warp_source_lib "runtime/network.sh"
warp_source_lib "runtime/socks.sh"
warp_source_lib "runtime/recovery.sh"
warp_source_lib "app/main.sh"
