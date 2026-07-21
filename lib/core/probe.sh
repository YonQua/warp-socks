#!/bin/sh

extract_trace_field() {
  field="$1"
  sed -n "s/^${field}=\(.*\)$/\1/p" | head -n 1
}

# 用 socks5h（域名解析走隧道）探测，这是隧道对外提供的真实使用路径。
probe_socks_trace() {
  port="$1"
  probe_timeout_seconds="$(sanitize_positive_int "$2" 10)"
  trace_url="${3:-$TRACE_URL_DEFAULT}"
  trace_file="$(mktemp)"
  err_file="$(mktemp)"
  PROBE_SOCKS_TRACE_REASON=""
  PROBE_SOCKS_TRACE_IP=""

  if ! curl \
    --silent \
    --show-error \
    --fail \
    --max-time "$probe_timeout_seconds" \
    --socks5-hostname "127.0.0.1:${port}" \
    "$trace_url" \
    >"$trace_file" \
    2>"$err_file"; then
    PROBE_SOCKS_TRACE_REASON="$(tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c 1-180)"
    rm -f "$trace_file" "$err_file"
    return 1
  fi

  PROBE_SOCKS_TRACE_IP="$(extract_trace_field ip <"$trace_file")"
  if grep -qE '^warp=(on|plus)$' "$trace_file"; then
    rm -f "$trace_file" "$err_file"
    return 0
  fi

  PROBE_SOCKS_TRACE_REASON="$(tr '\n' ' ' <"$trace_file" | tr -s ' ' | cut -c 1-180)"
  [ -n "$PROBE_SOCKS_TRACE_REASON" ] || PROBE_SOCKS_TRACE_REASON="响应缺少 warp 标记。"
  rm -f "$trace_file" "$err_file"
  return 1
}
