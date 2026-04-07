#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/lib/warp-common.sh"
[ -f "$COMMON_SH" ] || COMMON_SH="/usr/local/lib/warp-common.sh"
. "$COMMON_SH"

WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
ACCOUNT_JSON="${WG_DIR}/account.json"
ENDPOINT_STATE_FILE="${WG_DIR}/endpoint-state.json"

REGISTER_URL="https://api.cloudflareclient.com/v0a2158/reg"
CF_CLIENT_VERSION="a-6.10-2158"
TEAMS_TOKEN="${TEAMS_TOKEN:-}"
ENDPOINT_CANDIDATES="${ENDPOINT_CANDIDATES:-}"
MICROSOCKS_LOG_ACCESS="${MICROSOCKS_LOG_ACCESS:-1}"
MICROSOCKS_LOG_LOCAL_CLIENTS="${MICROSOCKS_LOG_LOCAL_CLIENTS:-0}"

LISTEN_ADDR="0.0.0.0"
LISTEN_PORT="1080"
HOST_LISTEN_ADDR="${HOST_BIND_IP:-127.0.0.1}"
HOST_LISTEN_PORT="${HOST_BIND_PORT:-1080}"

REGISTER_RETRIES=2
REGISTER_RETRY_DELAY=5
STARTUP_EGRESS_PROBE_RETRIES=3
STARTUP_EGRESS_PROBE_DELAY=2
STARTUP_EGRESS_PROBE_TIMEOUT=5
ENDPOINT_COOLDOWN_SECONDS="600"
DEFAULT_ENDPOINT_CANDIDATES="162.159.193.5:2408,162.159.193.9:2408,162.159.193.8:2408,162.159.193.3:2408,162.159.193.7:2408"

LOCAL_BYPASS_RULE_PRIORITY_FALLBACK=97
LOCAL_BYPASS_IPV4_SUBNETS="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16"
LOCAL_BYPASS_IPV6_SUBNETS="fc00::/7,fe80::/10"

HEALTHCHECK_STATE_DIR="/tmp/warp-socks-healthcheck"
HEALTHCHECK_FAIL_COUNT_FILE="${HEALTHCHECK_STATE_DIR}/fail-count"
HEALTHCHECK_RESTART_REQUEST_FILE="${HEALTHCHECK_STATE_DIR}/restart-requested"
HEALTHCHECK_READY_FILE="${HEALTHCHECK_STATE_DIR}/runtime-ready"

LOG_COMPONENT=""
MICROSOCKS_PID=""
ENDPOINT_SOURCE=""

log() {
  log_info "$LOG_COMPONENT" "$*"
}

warn() {
  log_warn "$LOG_COMPONENT" "$*"
}

fail() {
  log_error "$LOG_COMPONENT" "$*"
  exit 1
}

should_emit_microsocks_log_line() {
  line="$1"
  if is_true "$MICROSOCKS_LOG_LOCAL_CLIENTS"; then
    return 0
  fi
  case "$line" in
    client*\ 127.0.0.1:\ connected\ to\ *|client*\ \[::1\]:\ connected\ to\ *|client*\ ::1:\ connected\ to\ *)
      return 1
      ;;
  esac
  return 0
}

normalize_endpoint_value() {
  raw_endpoint="$1"
  trimmed_endpoint="$(printf '%s\n' "$raw_endpoint" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$trimmed_endpoint" ] || return 1

  endpoint_host="$(endpoint_host_from_value "$trimmed_endpoint")"
  endpoint_port="$(endpoint_port_from_value "$trimmed_endpoint")"
  [ -n "$endpoint_host" ] || return 1
  [ -n "$endpoint_port" ] || endpoint_port="2408"
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

clear_healthcheck_runtime_state() {
  rm -f "$HEALTHCHECK_FAIL_COUNT_FILE" "$HEALTHCHECK_RESTART_REQUEST_FILE" "$HEALTHCHECK_READY_FILE"
}

mark_healthcheck_runtime_ready() {
  mkdir -p "$HEALTHCHECK_STATE_DIR"
  : >"$HEALTHCHECK_READY_FILE"
}

prepare_runtime() {
  # Docker 容器里通常无法改这个 sysctl，删掉对应行避免 wg-quick 启动后自杀。
  sed -i '/sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/d' /usr/bin/wg-quick
  if grep -q 'src_valid_mark' /usr/bin/wg-quick; then
    fail "未能清理 /usr/bin/wg-quick 里的 src_valid_mark 逻辑。"
  fi
}

normalize_token() {
  token="$1"
  case "$token" in
    com.cloudflare.warp://*token=*)
      token="${token##*token=}"
      token="${token%%&*}"
      ;;
  esac
  printf '%s' "$token"
}

json_extract() {
  query="$1"
  jq -r "${query} // empty" "$ACCOUNT_JSON" 2>/dev/null || true
}

ensure_v4_cidr() {
  case "$1" in
    */*)
      printf '%s' "$1"
      ;;
    *)
      printf '%s/32' "$1"
      ;;
  esac
}

ensure_v6_cidr() {
  case "$1" in
    */*)
      printf '%s' "$1"
      ;;
    *)
      printf '%s/128' "$1"
      ;;
  esac
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

cleanup_obsolete_runtime_files() {
  rm -f \
    "${WG_DIR}/state.json" \
    "${WG_DIR}/wgcf-account.toml" \
    "${WG_DIR}/wgcf-profile.conf"
}

retry_after_seconds() {
  header_file="$1"
  sed -n 's/^[Rr]etry-[Aa]fter:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$header_file" | tail -n 1
}

register_via_teams() {
  raw_token="$(normalize_token "$TEAMS_TOKEN")"
  [ -n "$raw_token" ] || fail "首次启动或重建状态时必须提供 TEAMS_TOKEN。"

  private_key="$(wg genkey)"
  public_key="$(printf '%s' "$private_key" | wg pubkey)"
  install_id="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 22)"
  fcm_token="${install_id}:APA91b$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 134)"
  attempt=1

  while [ "$attempt" -le "$REGISTER_RETRIES" ]; do
    body_file="$(mktemp)"
    header_file="$(mktemp)"
    http_code="$(
      curl \
        --silent \
        --show-error \
        --location \
        --tlsv1.3 \
        --dump-header "$header_file" \
        --output "$body_file" \
        --write-out '%{http_code}' \
        --request POST \
        --header 'User-Agent: okhttp/3.12.1' \
        --header "CF-Client-Version: ${CF_CLIENT_VERSION}" \
        --header 'Content-Type: application/json' \
        --header "Cf-Access-Jwt-Assertion: ${raw_token}" \
        --data "{\"key\":\"${public_key}\",\"install_id\":\"${install_id}\",\"fcm_token\":\"${fcm_token}\",\"tos\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"model\":\"PC\",\"serial_number\":\"${install_id}\",\"locale\":\"zh_CN\"}" \
        "$REGISTER_URL" || true
    )"

    response_body="$(cat "$body_file")"
    rm -f "$body_file"

    if [ "$http_code" = "200" ] && printf '%s' "$response_body" | jq -e '.account' >/dev/null 2>&1; then
      printf '%s' "$response_body" \
        | jq --arg private_key "$private_key" '.private_key = $private_key' \
        >"$ACCOUNT_JSON"
      chmod 600 "$ACCOUNT_JSON"
      rm -f "$header_file"
      log "Teams 注册成功，账号信息已保存到 ${ACCOUNT_JSON}"
      return 0
    fi

    retry_after="$(retry_after_seconds "$header_file")"
    rm -f "$header_file"

    if [ "$http_code" = "401" ] && printf '%s' "$response_body" | grep -q 'token is expired'; then
      fail "registration token 已过期，请重新获取。"
    fi

    warn "Teams 注册失败，第 ${attempt}/${REGISTER_RETRIES} 次，HTTP ${http_code:-unknown}"
    warn "响应摘要: $(printf '%s' "$response_body" | tr '\n' ' ' | cut -c 1-220)"

    delay_seconds=$((REGISTER_RETRY_DELAY * attempt))
    case "$retry_after" in
      ''|*[!0-9]*)
        ;;
      *)
        if [ "$retry_after" -gt "$delay_seconds" ]; then
          delay_seconds="$retry_after"
        fi
        ;;
    esac

    if [ "$http_code" = "429" ]; then
      warn "Cloudflare 返回 429；当前会尊重 Retry-After，并避免立即重启后继续撞接口。"
    fi

    if [ "$attempt" -lt "$REGISTER_RETRIES" ]; then
      warn "${delay_seconds} 秒后重试 Teams 注册。"
    else
      warn "已达到最大重试次数；${delay_seconds} 秒后退出，避免容器立即重启后继续撞接口。"
    fi

    attempt=$((attempt + 1))
    sleep "$delay_seconds"
  done

  fail "Teams 注册失败，已达到最大重试次数。"
}

ensure_account_state() {
  if [ -s "$ACCOUNT_JSON" ]; then
    cleanup_obsolete_runtime_files
    endpoint_state_prune_cooldowns
    log "检测到已有 Teams 账户，跳过重新注册。"
    return 0
  fi

  rm -f "$WG_CONF" "$ENDPOINT_STATE_FILE"
  register_via_teams
  cleanup_obsolete_runtime_files
}

write_wg_config() {
  private_key="$1"
  peer_public_key="$2"
  endpoint_host="$3"
  address_v4="$4"
  address_v6="$5"

  [ -n "$private_key" ] || fail "WireGuard 配置缺少 PrivateKey。"
  [ -n "$peer_public_key" ] || fail "WireGuard 配置缺少 Peer PublicKey。"
  [ -n "$address_v4" ] || fail "Teams 返回里缺少 IPv4 地址。"
  [ -n "$address_v6" ] || fail "Teams 返回里缺少 IPv6 地址。"

  cat >"$WG_CONF" <<EOF
[Interface]
PrivateKey = ${private_key}
Address = $(ensure_v4_cidr "$address_v4")
Address = $(ensure_v6_cidr "$address_v6")
MTU = 1280

[Peer]
PublicKey = ${peer_public_key}
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = ${endpoint_host}
PersistentKeepalive = 15
EOF

  chmod 600 "$WG_CONF"
}

build_wg_config_from_account() {
  endpoint_override="${1:-}"
  [ -s "$ACCOUNT_JSON" ] || fail "缺少 ${ACCOUNT_JSON}，无法构建 WireGuard 配置。"

  private_key="$(json_extract '.private_key')"
  peer_public_key="$(json_extract '.config.peers[0].public_key // .peers[0].public_key')"
  endpoint_host="$(json_extract '.config.peers[0].endpoint.host // .peers[0].endpoint.host')"
  address_v4="$(json_extract '.config.interface.addresses.v4 // .interface.addresses.v4')"
  address_v6="$(json_extract '.config.interface.addresses.v6 // .interface.addresses.v6')"

  if [ -n "$endpoint_override" ]; then
    endpoint_host="$endpoint_override"
  fi
  endpoint_host="${endpoint_host:-engage.cloudflareclient.com:2408}"
  write_wg_config "$private_key" "$peer_public_key" "$endpoint_host" "$address_v4" "$address_v6"
  if [ -n "$endpoint_override" ]; then
    log "已生成 ${WG_CONF}，Endpoint = ${endpoint_override}"
  else
    log "已生成 ${WG_CONF}"
  fi
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

wait_for_egress_ready() {
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

bring_down_tunnel_if_present() {
  if ip link show wg0 >/dev/null 2>&1; then
    wg-quick down wg0 >/dev/null 2>&1 || true
  fi
  cleanup_local_network_bypass
}

stop_microsocks_child() {
  child_pid="${1:-}"
  [ -n "$child_pid" ] || return 0

  if kill -0 "$child_pid" 2>/dev/null; then
    kill -TERM "$child_pid" 2>/dev/null || true
    sleep 1
    if kill -0 "$child_pid" 2>/dev/null; then
      kill -KILL "$child_pid" 2>/dev/null || true
    fi
  fi

  wait "$child_pid" 2>/dev/null || true
}

handle_runtime_shutdown() {
  signal_name="$1"
  log "收到 ${signal_name}，正在停止 SOCKS5 并清理隧道。"
  exit_runtime_supervisor 0
}

exit_runtime_supervisor() {
  exit_code="$1"
  clear_healthcheck_runtime_state
  stop_microsocks_child "$MICROSOCKS_PID"
  bring_down_tunnel_if_present
  exit "$exit_code"
}

supervise_microsocks() {
  child_pid="$1"

  while :; do
    if [ -f "$HEALTHCHECK_RESTART_REQUEST_FILE" ]; then
      log "检测到 healthcheck 写入重启请求，停止 SOCKS5 并退出容器。"
      exit_runtime_supervisor 1
    fi

    if ! kill -0 "$child_pid" 2>/dev/null; then
      wait "$child_pid"
      return $?
    fi

    sleep 1
  done
}

start_tunnel() {
  candidate_file="$(mktemp)"
  build_endpoint_candidate_file "$candidate_file"
  log_endpoint_candidate_plan "$candidate_file"
  candidate_count="$(count_endpoint_candidates "$candidate_file")"
  [ "$candidate_count" -gt 0 ] || fail "未生成任何可用 endpoint 候选。"

  endpoint_state_set_active ""
  index=1

  while IFS= read -r endpoint_override; do
    [ -n "$endpoint_override" ] || continue
    bring_down_tunnel_if_present

    build_wg_config_from_account "$endpoint_override"

    log "正在启动 wg0"
    run_with_formatted_logs "wg-quick" "INFO" "" wg-quick up wg0
    ensure_local_network_bypass

    if wait_for_egress_ready; then
      endpoint_state_record_success "$endpoint_override"
      rm -f "$candidate_file"
      return 0
    fi

    warn "当前 endpoint ${endpoint_override} 未通过出口探测: ${PROBE_DIRECT_TRACE_REASON:-unknown}。"
    endpoint_state_mark_cooldown "$endpoint_override" "$ENDPOINT_COOLDOWN_SECONDS"
    endpoint_state_set_active ""
    cooldown_remaining="$(endpoint_state_cooldown_remaining "$endpoint_override")"
    if [ "$cooldown_remaining" -gt 0 ]; then
      warn "当前 endpoint ${endpoint_override} 已进入 ${cooldown_remaining} 秒冷却。"
    fi
    bring_down_tunnel_if_present

    if [ "$candidate_count" -gt 1 ] && [ "$index" -lt "$candidate_count" ]; then
      next_index=$((index + 1))
      next_endpoint="$(sed -n "${next_index}p" "$candidate_file" | head -n 1)"
      warn "当前 endpoint ${endpoint_override:-unknown} 未通过出口探测，切换到候选 ${next_index}/${candidate_count}: ${next_endpoint:-unknown}。"
    fi

    index=$((index + 1))
  done <"$candidate_file"

  rm -f "$candidate_file"
  fail "启动阶段出口探测失败，退出等待容器重启。"
}

start_socks5() {
  microsocks_log_pipe="/tmp/warp-socks-microsocks.log.pipe"
  mkdir -p "$HEALTHCHECK_STATE_DIR"
  clear_healthcheck_runtime_state
  log "启动无认证 SOCKS5（容器内监听）: ${LISTEN_ADDR}:${LISTEN_PORT}"
  log "Docker 发布端口（宿主机入口）: ${HOST_LISTEN_ADDR}:${HOST_LISTEN_PORT} -> 容器 ${LISTEN_ADDR}:${LISTEN_PORT}"

  if ! is_true "$MICROSOCKS_LOG_ACCESS"; then
    log "microsocks 连接日志已关闭。"
    microsocks -q -i "$LISTEN_ADDR" -p "$LISTEN_PORT" &
    MICROSOCKS_PID="$!"
    mark_healthcheck_runtime_ready
    supervise_microsocks "$MICROSOCKS_PID"
    return 0
  fi

  if is_true "$MICROSOCKS_LOG_LOCAL_CLIENTS"; then
    log "microsocks 连接日志已启用，包含本地 127.0.0.1/::1 探测流量。"
  else
    log "microsocks 连接日志已启用，默认隐藏本地 127.0.0.1/::1 探测流量。"
  fi

  create_formatted_log_pipe "$microsocks_log_pipe" "microsocks" "INFO" "should_emit_microsocks_log_line"
  microsocks -i "$LISTEN_ADDR" -p "$LISTEN_PORT" >"$FORMATTED_LOG_PIPE" 2>&1 &
  MICROSOCKS_PID="$!"
  mark_healthcheck_runtime_ready
  supervise_microsocks "$MICROSOCKS_PID"
}

mkdir -p "$WG_DIR"
prepare_runtime
clear_healthcheck_runtime_state
trap 'handle_runtime_shutdown TERM' TERM
trap 'handle_runtime_shutdown INT' INT
trap 'handle_runtime_shutdown HUP' HUP

LOG_MODE="teams"
export LOG_MODE

log "当前注册后端: teams"
ensure_account_state
start_tunnel
start_socks5
