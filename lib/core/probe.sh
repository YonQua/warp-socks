#!/bin/sh

extract_trace_field() {
  field="$1"
  sed -n "s/^${field}=\(.*\)$/\1/p" | head -n 1
}

probe_direct_trace_ip() {
  timeout_seconds="$(sanitize_positive_int "$1" 5)"
  trace_url="${2:-$TRACE_IP_URL_DEFAULT}"
  trace_file="$(mktemp)"
  err_file="$(mktemp)"
  PROBE_DIRECT_TRACE_REASON=""
  PROBE_DIRECT_TRACE_IP=""

  if ! curl \
    --silent \
    --show-error \
    --fail \
    --location \
    --max-time "$timeout_seconds" \
    "$trace_url" \
    >"$trace_file" \
    2>"$err_file"; then
    PROBE_DIRECT_TRACE_REASON="$(tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c 1-180)"
    rm -f "$trace_file" "$err_file"
    return 1
  fi

  trace_ip="$(extract_trace_field ip <"$trace_file")"
  trace_warp="$(extract_trace_field warp <"$trace_file")"
  if [ -n "$trace_ip" ] && printf '%s' "$trace_warp" | grep -qE '^(on|plus)$'; then
    PROBE_DIRECT_TRACE_IP="$trace_ip"
    rm -f "$trace_file" "$err_file"
    return 0
  fi

  PROBE_DIRECT_TRACE_REASON="$(tr '\n' ' ' <"$trace_file" | tr -s ' ' | cut -c 1-180)"
  [ -n "$PROBE_DIRECT_TRACE_REASON" ] || PROBE_DIRECT_TRACE_REASON="响应缺少 warp=on 或出口 IP。"
  rm -f "$trace_file" "$err_file"
  return 1
}

probe_socks_trace() {
  mode="$1"
  port="$2"
  timeout_seconds="$(sanitize_positive_int "$3" 10)"
  trace_url="${4:-$TRACE_URL_DEFAULT}"
  trace_file="$(mktemp)"
  err_file="$(mktemp)"
  reason=""

  if [ "$mode" = "remote_dns" ]; then
    if ! curl \
      --silent \
      --show-error \
      --fail \
      --max-time "$timeout_seconds" \
      --socks5-hostname "127.0.0.1:${port}" \
      "$trace_url" \
      >"$trace_file" \
      2>"$err_file"; then
      reason="$(tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c 1-180)"
    fi
  else
    if ! curl \
      --silent \
      --show-error \
      --fail \
      --max-time "$timeout_seconds" \
      --socks5 "127.0.0.1:${port}" \
      "$trace_url" \
      >"$trace_file" \
      2>"$err_file"; then
      reason="$(tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c 1-180)"
    fi
  fi

  if [ -z "$reason" ] && grep -qE '^warp=(on|plus)$' "$trace_file"; then
    rm -f "$trace_file" "$err_file"
    return 0
  fi

  if [ -z "$reason" ]; then
    reason="$(tr '\n' ' ' <"$trace_file" | tr -s ' ' | cut -c 1-180)"
    [ -n "$reason" ] || reason="响应缺少 warp 标记。"
  fi

  rm -f "$trace_file" "$err_file"
  printf '%s' "$reason"
  return 1
}
