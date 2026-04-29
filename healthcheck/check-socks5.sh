#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
WARP_LIB_DIR="${SCRIPT_DIR}/../lib"
COMMON_SH="${WARP_LIB_DIR}/warp-common.sh"

if [ ! -f "$COMMON_SH" ]; then
  WARP_LIB_DIR="/usr/local/lib/warp-socks"
  COMMON_SH="${WARP_LIB_DIR}/warp-common.sh"
fi

. "$COMMON_SH"

warp_healthcheck_main
