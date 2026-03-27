#!/bin/sh

TRACE_URL_DEFAULT="https://cloudflare.com/cdn-cgi/trace"
TRACE_IP_URL_DEFAULT="https://1.1.1.1/cdn-cgi/trace"

is_true() {
  case "${1:-0}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

sanitize_positive_int() {
  value="$1"
  fallback="$2"
  case "$value" in
    ''|*[!0-9]*|0)
      printf '%s' "$fallback"
      ;;
    *)
      printf '%s' "$value"
      ;;
  esac
}

extract_trace_field() {
  field="$1"
  sed -n "s/^${field}=\(.*\)$/\1/p" | head -n 1
}

probe_direct_trace_ip() {
  timeout_seconds="$(sanitize_positive_int "$1" 5)"
  trace_url="${2:-$TRACE_IP_URL_DEFAULT}"
  trace="$(curl -s --max-time "$timeout_seconds" "$trace_url" || true)"
  printf '%s\n' "$trace" | extract_trace_field ip
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

has_explicit_endpoint_candidates() {
  [ -n "${ENDPOINT_IP:-}" ] || [ -n "${ENDPOINT_CANDIDATES:-}" ]
}

normalize_endpoint_list() {
  {
    printf '%s\n' "${ENDPOINT_IP:-}"
    printf '%s\n' "${ENDPOINT_CANDIDATES:-}"
  } \
    | tr ',' '\n' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | awk 'NF && !seen[$0]++'
}

endpoint_candidate_count() {
  normalize_endpoint_list | awk 'NF {count++} END {print count+0}'
}

endpoint_candidate_at() {
  index="$(sanitize_positive_int "${1:-0}" 0)"
  if [ "$index" -le 0 ]; then
    return 1
  fi

  normalize_endpoint_list | sed -n "${index}p" | head -n 1
}
