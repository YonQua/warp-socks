#!/bin/sh

# 调用方（entrypoint.sh / healthcheck/check-socks5.sh）负责在 source 本文件前
# 算好并设置 WARP_LIB_DIR；两者的相对深度不同，只能各自算，这里不重复猜测。
: "${WARP_LIB_DIR:?WARP_LIB_DIR 必须在 source warp-common.sh 前设置}"

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
warp_source_lib "runtime/tunnel.sh"
warp_source_lib "runtime/recovery.sh"
warp_source_lib "app/main.sh"
