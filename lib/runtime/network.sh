#!/bin/sh

verify_runtime_environment() {
  for required_cmd in wg wg-quick ip iptables ip6tables curl jq microsocks; do
    command -v "$required_cmd" >/dev/null 2>&1 || fail_tunnel "缺少运行依赖: ${required_cmd}"
  done

  # 运行期不应再修改系统二进制；兼容修补应在构建期完成。
  if grep -q 'src_valid_mark' /usr/bin/wg-quick; then
    fail_tunnel "镜像内的 /usr/bin/wg-quick 仍包含 src_valid_mark 逻辑，请检查 Dockerfile 构建期修补。"
  fi
}

iterate_default_bypass_subnets() {
  family="$1"
  case "$family" in
    ipv4)
      printf '%s\n' "$LOCAL_BYPASS_IPV4_SUBNETS"
      ;;
    ipv6)
      printf '%s\n' "$LOCAL_BYPASS_IPV6_SUBNETS"
      ;;
    *)
      return 1
      ;;
  esac \
    | tr ',' '\n' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | awk 'NF && !seen[$0]++'
}

configured_bypass_summary() {
  family="$1"
  primary_subnet="$2"
  summary=""

  if [ -n "$primary_subnet" ]; then
    summary="$primary_subnet"
  fi

  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    if [ -n "$summary" ]; then
      summary="${summary},${subnet}"
    else
      summary="$subnet"
    fi
  done <<EOF
$(iterate_default_bypass_subnets "$family")
EOF

  printf '%s' "$summary"
}

ensure_ipv4_bypass() {
  subnet="$1"
  priority="${2:-}"
  [ -n "$subnet" ] || return 0

  [ -n "$priority" ] || priority="$(detect_local_bypass_rule_priority ipv4 "$LOCAL_BYPASS_RULE_PRIORITY_FALLBACK")"
  remove_stale_bypass_rules ipv4 "$subnet" "$priority"

  if ! ip rule show | awk -v subnet="$subnet" -v priority="$priority" '
    $1 == priority ":" && index($0, "to " subnet " lookup main") { found = 1 }
    END { exit found ? 0 : 1 }
  '; then
    ip rule add to "$subnet" lookup main priority "$priority"
  fi

  iptables -C OUTPUT -d "$subnet" -j ACCEPT >/dev/null 2>&1 || \
    iptables -I OUTPUT 1 -d "$subnet" -j ACCEPT
}

ensure_ipv6_bypass() {
  subnet="$1"
  priority="${2:-}"
  [ -n "$subnet" ] || return 0

  [ -n "$priority" ] || priority="$(detect_local_bypass_rule_priority ipv6 "$LOCAL_BYPASS_RULE_PRIORITY_FALLBACK")"
  remove_stale_bypass_rules ipv6 "$subnet" "$priority"

  if ! ip -6 rule show | awk -v subnet="$subnet" -v priority="$priority" '
    $1 == priority ":" && index($0, "to " subnet " lookup main") { found = 1 }
    END { exit found ? 0 : 1 }
  '; then
    ip -6 rule add to "$subnet" lookup main priority "$priority"
  fi

  ip6tables -C OUTPUT -d "$subnet" -j ACCEPT >/dev/null 2>&1 || \
    ip6tables -I OUTPUT 1 -d "$subnet" -j ACCEPT
}

detect_local_bypass_rule_priority() {
  family="$1"
  fallback="$2"

  if [ "$family" = "ipv6" ]; then
    rule_output="$(ip -6 rule show)"
  else
    rule_output="$(ip rule show)"
  fi

  current_priority="$(printf '%s\n' "$rule_output" | awk '
    /lookup main suppress_prefixlength 0/ || (/fwmark/ && /lookup 51820/) {
      priority = $1
      sub(/:$/, "", priority)
      if (priority ~ /^[0-9]+$/ && (min == "" || priority + 0 < min)) {
        min = priority + 0
      }
    }
    END {
      if (min != "") {
        print min
      }
    }
  ')"

  case "$current_priority" in
    ''|*[!0-9]*|0|1)
      printf '%s' "$fallback"
      ;;
    *)
      printf '%s' $((current_priority - 1))
      ;;
  esac
}

remove_stale_bypass_rules() {
  family="$1"
  subnet="$2"
  keep_priority="$3"
  [ -n "$subnet" ] || return 0
  [ -n "$keep_priority" ] || return 0

  if [ "$family" = "ipv6" ]; then
    ip -6 rule show | awk -v subnet="$subnet" -v keep_priority="$keep_priority" '
      index($0, "to " subnet " lookup main") {
        priority = $1
        sub(/:$/, "", priority)
        if (priority ~ /^[0-9]+$/ && priority != keep_priority) {
          print priority
        }
      }
    ' | while IFS= read -r stale_priority; do
      [ -n "$stale_priority" ] || continue
      ip -6 rule del to "$subnet" lookup main priority "$stale_priority" 2>/dev/null || true
    done
  else
    ip rule show | awk -v subnet="$subnet" -v keep_priority="$keep_priority" '
      index($0, "to " subnet " lookup main") {
        priority = $1
        sub(/:$/, "", priority)
        if (priority ~ /^[0-9]+$/ && priority != keep_priority) {
          print priority
        }
      }
    ' | while IFS= read -r stale_priority; do
      [ -n "$stale_priority" ] || continue
      ip rule del to "$subnet" lookup main priority "$stale_priority" 2>/dev/null || true
    done
  fi
}

remove_bypass_rules() {
  family="$1"
  subnet="$2"
  [ -n "$subnet" ] || return 0

  if [ "$family" = "ipv6" ]; then
    ip -6 rule show | awk -v subnet="$subnet" '
      index($0, "to " subnet " lookup main") {
        priority = $1
        sub(/:$/, "", priority)
        if (priority ~ /^[0-9]+$/) {
          print priority
        }
      }
    ' | while IFS= read -r stale_priority; do
      [ -n "$stale_priority" ] || continue
      ip -6 rule del to "$subnet" lookup main priority "$stale_priority" 2>/dev/null || true
    done

    while ip6tables -C OUTPUT -d "$subnet" -j ACCEPT >/dev/null 2>&1; do
      ip6tables -D OUTPUT -d "$subnet" -j ACCEPT >/dev/null 2>&1 || true
    done
  else
    ip rule show | awk -v subnet="$subnet" '
      index($0, "to " subnet " lookup main") {
        priority = $1
        sub(/:$/, "", priority)
        if (priority ~ /^[0-9]+$/) {
          print priority
        }
      }
    ' | while IFS= read -r stale_priority; do
      [ -n "$stale_priority" ] || continue
      ip rule del to "$subnet" lookup main priority "$stale_priority" 2>/dev/null || true
    done

    while iptables -C OUTPUT -d "$subnet" -j ACCEPT >/dev/null 2>&1; do
      iptables -D OUTPUT -d "$subnet" -j ACCEPT >/dev/null 2>&1 || true
    done
  fi
}

cleanup_local_network_bypass() {
  primary_v4_subnet="$(ip -4 route show dev eth0 proto kernel scope link | awk 'NR==1 {print $1}')"
  primary_v6_subnet="$(ip -6 route show dev eth0 proto kernel | awk '/^[0-9a-fA-F:]+\// {print $1; exit}')"

  remove_bypass_rules ipv4 "$primary_v4_subnet"
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    remove_bypass_rules ipv4 "$subnet"
  done <<EOF
$(iterate_default_bypass_subnets ipv4)
EOF

  remove_bypass_rules ipv6 "$primary_v6_subnet"
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    remove_bypass_rules ipv6 "$subnet"
  done <<EOF
$(iterate_default_bypass_subnets ipv6)
EOF
}

ensure_local_network_bypass() {
  primary_v4_subnet="$(ip -4 route show dev eth0 proto kernel scope link | awk 'NR==1 {print $1}')"
  primary_v6_subnet="$(ip -6 route show dev eth0 proto kernel | awk '/^[0-9a-fA-F:]+\// {print $1; exit}')"
  ipv4_bypass_priority="$(detect_local_bypass_rule_priority ipv4 "$LOCAL_BYPASS_RULE_PRIORITY_FALLBACK")"
  ipv6_bypass_priority="$(detect_local_bypass_rule_priority ipv6 "$LOCAL_BYPASS_RULE_PRIORITY_FALLBACK")"

  ensure_ipv4_bypass "$primary_v4_subnet" "$ipv4_bypass_priority"
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    ensure_ipv4_bypass "$subnet" "$ipv4_bypass_priority"
  done <<EOF
$(iterate_default_bypass_subnets ipv4)
EOF

  ensure_ipv6_bypass "$primary_v6_subnet" "$ipv6_bypass_priority"
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    ensure_ipv6_bypass "$subnet" "$ipv6_bypass_priority"
  done <<EOF
$(iterate_default_bypass_subnets ipv6)
EOF

  log "已为本地网络添加旁路: v4=[$(configured_bypass_summary ipv4 "$primary_v4_subnet")] v6=[$(configured_bypass_summary ipv6 "$primary_v6_subnet")]（策略优先级 v4=${ipv4_bypass_priority}, v6=${ipv6_bypass_priority}）"
}

tunnel_wait_for_egress_ready() {
  attempt=1

  while [ "$attempt" -le "$STARTUP_EGRESS_PROBE_RETRIES" ]; do
    if probe_direct_trace_ip "$STARTUP_EGRESS_PROBE_TIMEOUT"; then
      egress_ip="$PROBE_DIRECT_TRACE_IP"
      log "当前出口 IP: ${egress_ip}"
      return 0
    fi

    if [ "$attempt" -lt "$STARTUP_EGRESS_PROBE_RETRIES" ]; then
      warn "启动后第 ${attempt}/${STARTUP_EGRESS_PROBE_RETRIES} 次出口探测未通过: ${PROBE_DIRECT_TRACE_REASON:-unknown}，${STARTUP_EGRESS_PROBE_DELAY} 秒后重试。"
      sleep "$STARTUP_EGRESS_PROBE_DELAY"
    fi
    attempt=$((attempt + 1))
  done

  return 1
}

tunnel_bring_down_if_present() {
  if ip link show wg0 >/dev/null 2>&1; then
    wg-quick down wg0 >/dev/null 2>&1 || true
  fi
  cleanup_local_network_bypass
}

tunnel_mark_candidate_failed() {
  endpoint="$1"
  reason="$2"

  warn "当前 endpoint ${endpoint} 失败: ${reason}"
  endpoint_state_mark_cooldown "$endpoint" "$STARTUP_ENDPOINT_COOLDOWN_SECONDS"
  cooldown_remaining="$(endpoint_state_cooldown_remaining "$endpoint")"
  if [ "$cooldown_remaining" -gt 0 ]; then
    warn "当前 endpoint ${endpoint} 已进入 ${cooldown_remaining} 秒冷却。"
  fi
  tunnel_bring_down_if_present
}

tunnel_start() {
  candidate_file="$(mktemp)"
  build_endpoint_candidate_file "$candidate_file"
  log_endpoint_candidate_plan "$candidate_file"
  candidate_count="$(count_endpoint_candidates "$candidate_file")"
  [ "$candidate_count" -gt 0 ] || fail_tunnel "未生成任何可用 endpoint 候选。"

  index=1

  while IFS= read -r endpoint_override; do
    [ -n "$endpoint_override" ] || continue
    tunnel_bring_down_if_present

    tunnel_build_wg_config_from_account "$endpoint_override"

    log "正在启动 wg0"
    if ! run_with_formatted_logs "wg-quick" "INFO" "" wg-quick up wg0; then
      tunnel_mark_candidate_failed "$endpoint_override" "wg-quick up 失败。"
      if [ "$candidate_count" -gt 1 ] && [ "$index" -lt "$candidate_count" ]; then
        next_index=$((index + 1))
        next_endpoint="$(sed -n "${next_index}p" "$candidate_file" | head -n 1)"
        warn "wg0 启动失败，切换到候选 ${next_index}/${candidate_count}: ${next_endpoint:-unknown}。"
      fi
      index=$((index + 1))
      continue
    fi
    ensure_local_network_bypass

    if tunnel_wait_for_egress_ready; then
      endpoint_state_record_success "$endpoint_override"
      rm -f "$candidate_file"
      return 0
    fi

    tunnel_mark_candidate_failed "$endpoint_override" "未通过出口探测: ${PROBE_DIRECT_TRACE_REASON:-unknown}。"

    if [ "$candidate_count" -gt 1 ] && [ "$index" -lt "$candidate_count" ]; then
      next_index=$((index + 1))
      next_endpoint="$(sed -n "${next_index}p" "$candidate_file" | head -n 1)"
      warn "当前 endpoint ${endpoint_override:-unknown} 未通过出口探测，切换到候选 ${next_index}/${candidate_count}: ${next_endpoint:-unknown}。"
    fi

    index=$((index + 1))
  done <"$candidate_file"

  rm -f "$candidate_file"
  fail_tunnel "启动阶段出口探测失败，退出等待容器重启。"
}
