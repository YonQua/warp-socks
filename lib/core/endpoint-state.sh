#!/bin/sh

endpoint_state_file() {
  printf '%s' "${ENDPOINT_STATE_FILE:-/etc/wireguard/endpoint-state.json}"
}

endpoint_state_read() {
  query="$1"
  shift
  state_file="$(endpoint_state_file)"
  [ -s "$state_file" ] || return 0
  jq -r "$@" "${query} // empty" "$state_file" 2>/dev/null || true
}

endpoint_state_update() {
  jq_filter="$1"
  shift
  ensure_endpoint_state_file
  state_file="$(endpoint_state_file)"
  tmp_file="$(mktemp)"

  if jq "$@" "$jq_filter" "$state_file" >"$tmp_file" 2>/dev/null; then
    mv "$tmp_file" "$state_file"
    chmod 600 "$state_file"
    return 0
  fi

  rm -f "$tmp_file"
  return 1
}

ensure_endpoint_state_file() {
  state_file="$(endpoint_state_file)"
  mkdir -p "$(dirname "$state_file")"
  if [ ! -s "$state_file" ]; then
    printf '%s\n' '{"last_good_endpoint":"","cooldowns":{}}' >"$state_file"
    chmod 600 "$state_file"
  fi
}

endpoint_state_prune_cooldowns() {
  ensure_endpoint_state_file
  state_file="$(endpoint_state_file)"
  now="$(date +%s)"
  tmp_file="$(mktemp)"

  if jq --argjson now "$now" \
    '.cooldowns = ((.cooldowns // {}) | with_entries(select((((.value | tonumber?) // 0)) > $now)))' \
    "$state_file" >"$tmp_file" 2>/dev/null; then
    mv "$tmp_file" "$state_file"
    chmod 600 "$state_file"
  else
    rm -f "$tmp_file"
  fi
}

endpoint_state_get_last_good() {
  endpoint_state_read '.last_good_endpoint'
}

endpoint_state_record_success() {
  endpoint="$1"
  endpoint_state_update \
    '.last_good_endpoint = $endpoint
     | .cooldowns = ((.cooldowns // {}) | del(.[$endpoint]))' \
    --arg endpoint "$endpoint" || true
}

endpoint_state_get_cooldown_until() {
  endpoint="$1"
  endpoint_state_read '.cooldowns[$endpoint]' --arg endpoint "$endpoint"
}

endpoint_state_cooldown_remaining() {
  endpoint="$1"
  cooldown_until="$(endpoint_state_get_cooldown_until "$endpoint")"
  now="$(date +%s)"

  case "$cooldown_until" in
    ''|*[!0-9]*)
      printf '0'
      ;;
    *)
      if [ "$cooldown_until" -le "$now" ]; then
        printf '0'
      else
        printf '%s' $((cooldown_until - now))
      fi
      ;;
  esac
}

endpoint_state_is_cooling_down() {
  endpoint="$1"
  [ "$(endpoint_state_cooldown_remaining "$endpoint")" -gt 0 ]
}

endpoint_state_mark_cooldown() {
  endpoint="$1"
  cooldown_seconds="$(sanitize_positive_int "${2:-$RUNTIME_ENDPOINT_COOLDOWN_SECONDS_DEFAULT}" "$RUNTIME_ENDPOINT_COOLDOWN_SECONDS_DEFAULT")"
  cooldown_until=$(( $(date +%s) + cooldown_seconds ))
  endpoint_state_update \
    '.cooldowns = (.cooldowns // {})
     | .cooldowns[$endpoint] = $cooldown_until' \
    --arg endpoint "$endpoint" \
    --argjson cooldown_until "$cooldown_until" || true
}
