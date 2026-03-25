#!/bin/sh
set -eu

port="${BIND_PORT:-1080}"

trace="$(
  curl \
    --silent \
    --show-error \
    --fail \
    --max-time 10 \
    --socks5-hostname "127.0.0.1:${port}" \
    https://cloudflare.com/cdn-cgi/trace
)"

printf '%s\n' "$trace" | grep -qE '^warp=(on|plus)$'
