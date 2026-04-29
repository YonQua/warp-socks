#!/bin/sh

endpoint_host_from_value() {
  endpoint="$1"
  case "$endpoint" in
    \[*\]:*)
      sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p' <<EOF
$endpoint
EOF
      ;;
    *:*)
      printf '%s' "${endpoint%:*}"
      ;;
    *)
      printf '%s' "$endpoint"
      ;;
  esac
}

endpoint_port_from_value() {
  endpoint="$1"
  case "$endpoint" in
    \[*\]:*)
      sed -n 's/^.*]:\([0-9][0-9]*\)$/\1/p' <<EOF
$endpoint
EOF
      ;;
    *:*)
      printf '%s' "${endpoint##*:}"
      ;;
    *)
      printf ''
      ;;
  esac
}

format_endpoint_value() {
  host="$1"
  port="$2"
  case "$host" in
    *:*)
      printf '[%s]:%s' "$host" "$port"
      ;;
    *)
      printf '%s:%s' "$host" "$port"
      ;;
  esac
}

endpoint_port_is_valid() {
  port="$1"
  case "$port" in
    ''|*[!0-9]*)
      return 1
      ;;
  esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

normalize_endpoint_value() {
  raw_endpoint="$1"
  trimmed_endpoint="$(printf '%s\n' "$raw_endpoint" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$trimmed_endpoint" ] || return 1

  endpoint_host="$(endpoint_host_from_value "$trimmed_endpoint")"
  endpoint_port="$(endpoint_port_from_value "$trimmed_endpoint")"
  [ -n "$endpoint_host" ] || return 1
  [ -n "$endpoint_port" ] || endpoint_port="2408"
  endpoint_port_is_valid "$endpoint_port" || return 1
  format_endpoint_value "$endpoint_host" "$endpoint_port"
}

emit_manual_endpoint_candidates() {
  source_candidates="$1"
  printf '%s\n' "$source_candidates" \
    | tr ',' '\n' \
    | while IFS= read -r raw_endpoint; do
      normalized_endpoint="$(normalize_endpoint_value "$raw_endpoint" || true)"
      [ -n "$normalized_endpoint" ] || continue
      printf '%s\n' "$normalized_endpoint"
    done \
    | awk 'NF && !seen[$0]++'
}

emit_auto_endpoint_candidates() {
  emit_manual_endpoint_candidates "$DEFAULT_ENDPOINT_CANDIDATES"
}

count_endpoint_candidates() {
  candidate_file="$1"
  awk 'NF {count++} END {print count+0}' "$candidate_file"
}

reorder_endpoint_candidates() {
  candidate_file="$1"
  endpoint_state_prune_cooldowns
  last_good_endpoint="$(endpoint_state_get_last_good)"
  merged_file="$(mktemp)"
  ready_file="$(mktemp)"
  cooled_file="$(mktemp)"

  {
    [ -n "$last_good_endpoint" ] && printf '%s\n' "$last_good_endpoint"
    cat "$candidate_file"
  } | awk 'NF && !seen[$0]++' >"$merged_file"

  while IFS= read -r endpoint; do
    [ -n "$endpoint" ] || continue
    if endpoint_state_is_cooling_down "$endpoint"; then
      printf '%s\n' "$endpoint" >>"$cooled_file"
    else
      printf '%s\n' "$endpoint" >>"$ready_file"
    fi
  done <"$merged_file"

  cat "$ready_file" "$cooled_file" >"$candidate_file"
  rm -f "$merged_file" "$ready_file" "$cooled_file"
}

build_endpoint_candidate_file() {
  candidate_file="$1"
  manual_candidates="$(emit_manual_endpoint_candidates "$ENDPOINT_CANDIDATES")"

  if [ -n "$manual_candidates" ]; then
    ENDPOINT_SOURCE="manual"
    printf '%s\n' "$manual_candidates" >"$candidate_file"
  else
    ENDPOINT_SOURCE="auto"
    emit_auto_endpoint_candidates | awk 'NF && !seen[$0]++' >"$candidate_file"
  fi

  reorder_endpoint_candidates "$candidate_file"
}

log_endpoint_candidate_plan() {
  candidate_file="${1:-}"
  [ -n "$candidate_file" ] || return 0
  candidate_total="$(count_endpoint_candidates "$candidate_file")"
  cooled_total=0
  while IFS= read -r endpoint; do
    [ -n "$endpoint" ] || continue
    if endpoint_state_is_cooling_down "$endpoint"; then
      cooled_total=$((cooled_total + 1))
    fi
  done <"$candidate_file"

  case "$ENDPOINT_SOURCE" in
    manual)
      log "endpoint 策略: 手工候选，共 ${candidate_total} 个。"
      ;;
    *)
      log "endpoint 策略: 自动候选，共 ${candidate_total} 个。"
      ;;
  esac

  last_good_endpoint="$(endpoint_state_get_last_good)"
  if [ -n "$last_good_endpoint" ]; then
    log "最近成功 endpoint: ${last_good_endpoint}"
  fi
  if [ "$cooled_total" -gt 0 ]; then
    log "当前有 ${cooled_total} 个 endpoint 处于冷却，会排到候选列表后部。"
  fi
}
