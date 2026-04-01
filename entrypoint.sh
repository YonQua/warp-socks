#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
COMMON_SH="${SCRIPT_DIR}/lib/warp-common.sh"
[ -f "$COMMON_SH" ] || COMMON_SH="/usr/local/lib/warp-common.sh"
. "$COMMON_SH"

WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
ACCOUNT_JSON="${WG_DIR}/account.json"
WGCF_ACCOUNT="${WG_DIR}/wgcf-account.toml"
WGCF_PROFILE="${WG_DIR}/wgcf-profile.conf"
STATE_FILE="${WG_DIR}/state.json"
LOG_MODE_STATE_FILE="$STATE_FILE"
REGISTER_URL="${REGISTER_URL:-https://api.cloudflareclient.com/v0a2158/reg}"
AUTH_MODE="${AUTH_MODE:-auto}"
FORCE_REREGISTER="${FORCE_REREGISTER:-0}"
WARP_STACK="${WARP_STACK:-dual}"
REGISTER_RETRIES="${REGISTER_RETRIES:-3}"
REGISTER_RETRY_DELAY="${REGISTER_RETRY_DELAY:-5}"
LISTEN_ADDR="${BIND_ADDR:-0.0.0.0}"
LISTEN_PORT="${BIND_PORT:-1080}"
HOST_LISTEN_ADDR="${HOST_BIND_IP:-}"
HOST_LISTEN_PORT="${HOST_BIND_PORT:-}"
LOCAL_BYPASS_RULE_PRIORITY_FALLBACK=97
LOCAL_BYPASS_INCLUDE_PRIMARY="${LOCAL_BYPASS_INCLUDE_PRIMARY:-1}"
LOCAL_BYPASS_IPV4_SUBNETS="${LOCAL_BYPASS_IPV4_SUBNETS-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16}"
LOCAL_BYPASS_IPV6_SUBNETS="${LOCAL_BYPASS_IPV6_SUBNETS-fc00::/7,fe80::/10}"
WARP_LICENSE_KEY="${WARP_LICENSE_KEY:-}"
STARTUP_EGRESS_PROBE_RETRIES="${STARTUP_EGRESS_PROBE_RETRIES:-3}"
STARTUP_EGRESS_PROBE_DELAY="${STARTUP_EGRESS_PROBE_DELAY:-2}"
STARTUP_EGRESS_PROBE_TIMEOUT="${STARTUP_EGRESS_PROBE_TIMEOUT:-5}"
# 这是注册 API 的兼容客户端标识，不等同于 Cloudflare 官方桌面客户端的发布版本号。
CF_CLIENT_VERSION="${CF_CLIENT_VERSION:-a-6.10-2158}"
CURRENT_ENDPOINT_OVERRIDE=""
CURRENT_ENDPOINT_INDEX=""
CURRENT_ENDPOINT_TOTAL="0"
VALIDATE_ENDPOINT_ONLY="${VALIDATE_ENDPOINT_ONLY:-0}"
MICROSOCKS_LOG_ACCESS="${MICROSOCKS_LOG_ACCESS:-1}"
MICROSOCKS_LOG_LOCAL_CLIENTS="${MICROSOCKS_LOG_LOCAL_CLIENTS:-0}"
LOG_COMPONENT=""

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

start_log_pipe_formatter() {
  pipe_path="$1"
  component="$2"
  level="${3:-INFO}"
  filter_fn="${4:-}"

  rm -f "$pipe_path"
  mkfifo "$pipe_path"
  (
    format_log_stream "$component" "$level" "$filter_fn" <"$pipe_path"
    rm -f "$pipe_path"
  ) &
}

should_emit_microsocks_log_line() {
  line="$1"
  if ! is_true "$MICROSOCKS_LOG_LOCAL_CLIENTS"; then
    case "$line" in
      client*\ 127.0.0.1:\ connected\ to\ *|client*\ \[::1\]:\ connected\ to\ *|client*\ ::1:\ connected\ to\ *)
        return 1
        ;;
    esac
  fi
  return 0
}

log_endpoint_candidate_plan() {
  candidate_total="$(endpoint_candidate_count)"
  if has_explicit_endpoint_candidates && [ "$candidate_total" -gt 0 ]; then
    log "检测到显式 endpoint 候选，共 ${candidate_total} 个。"
  fi
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
  pattern="$1"
  sed -n "s/${pattern}/\\1/p" "$ACCOUNT_JSON" | head -n 1
}

toml_extract() {
  key="$1"
  file="$2"
  [ -f "$file" ] || return 0
  sed -n "s/^${key}[[:space:]]*=[[:space:]]*\"\\(.*\\)\"$/\\1/p" "$file" | head -n 1
}

ensure_wgcf() {
  command -v wgcf >/dev/null 2>&1 || fail "镜像里缺少 wgcf，可执行文件未安装。"
}

run_wgcf() {
  ensure_wgcf
  (
    cd "$WG_DIR"
    run_with_formatted_logs "wgcf" "INFO" "" wgcf "$@"
  )
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

iterate_configured_bypass_subnets() {
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
  primary_subnet="${2:-}"
  summary=""

  if is_true "$LOCAL_BYPASS_INCLUDE_PRIMARY" && [ -n "$primary_subnet" ]; then
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
$(iterate_configured_bypass_subnets "$family")
EOF

  printf '%s' "${summary:-none}"
}

write_state() {
  backend="$1"
  mkdir -p "$WG_DIR"
  printf '{"backend":"%s","written_at":"%s"}\n' \
    "$backend" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >"$STATE_FILE"
  chmod 600 "$STATE_FILE"
}

stored_wgcf_license_key() {
  toml_extract "license_key" "$WGCF_ACCOUNT"
}

current_state_backend() {
  backend=""

  if [ -s "$STATE_FILE" ]; then
    backend="$(sed -n 's/.*"backend":"\([^"]*\)".*/\1/p' "$STATE_FILE" | head -n 1)"
  fi

  if [ -n "$backend" ]; then
    printf '%s' "$backend"
    return 0
  fi

  if [ -s "$ACCOUNT_JSON" ]; then
    printf 'teams'
    return 0
  fi
}

has_legacy_wgcf_state() {
  [ ! -s "$STATE_FILE" ] && { [ -s "$WGCF_ACCOUNT" ] || [ -s "$WGCF_PROFILE" ]; }
}

clear_backend_state() {
  rm -f \
    "$STATE_FILE" \
    "$WG_CONF" \
    "$ACCOUNT_JSON" \
    "$WGCF_ACCOUNT" \
    "$WGCF_PROFILE"
}

detect_requested_backend() {
  existing_backend="$1"
  case "$AUTH_MODE" in
    auto)
      if [ -n "${TEAMS_TOKEN:-}" ]; then
        if [ -n "$WARP_LICENSE_KEY" ]; then
          warn "检测到 TEAMS_TOKEN 与 WARP_LICENSE_KEY 同时存在，当前按优先级使用 teams，忽略 WARP_LICENSE_KEY。"
        fi
        printf 'teams'
      elif [ -n "$WARP_LICENSE_KEY" ]; then
        printf 'wgcf-plus'
      elif [ -n "$existing_backend" ]; then
        printf '%s' "$existing_backend"
      else
        printf 'wgcf-free'
      fi
      ;;
    teams)
      [ -n "${TEAMS_TOKEN:-}" ] || [ "$existing_backend" = "teams" ] || fail "AUTH_MODE=teams 时必须提供 TEAMS_TOKEN，或已有可复用的 teams 持久化状态。"
      [ -n "$WARP_LICENSE_KEY" ] && warn "AUTH_MODE=teams 已显式指定，忽略 WARP_LICENSE_KEY。"
      printf 'teams'
      ;;
    wgcf-plus)
      [ -n "$WARP_LICENSE_KEY" ] || [ "$existing_backend" = "wgcf-plus" ] || fail "AUTH_MODE=wgcf-plus 时必须提供 WARP_LICENSE_KEY，或已有可复用的 wgcf-plus 持久化状态。"
      [ -n "${TEAMS_TOKEN:-}" ] && warn "AUTH_MODE=wgcf-plus 已显式指定，忽略 TEAMS_TOKEN。"
      printf 'wgcf-plus'
      ;;
    wgcf-free)
      [ -n "${TEAMS_TOKEN:-}" ] && warn "AUTH_MODE=wgcf-free 已显式指定，忽略 TEAMS_TOKEN。"
      [ -n "$WARP_LICENSE_KEY" ] && warn "AUTH_MODE=wgcf-free 已显式指定，忽略 WARP_LICENSE_KEY。"
      printf 'wgcf-free'
      ;;
    *)
      fail "不支持的 AUTH_MODE=${AUTH_MODE}，仅支持 auto、teams、wgcf-free、wgcf-plus。"
      ;;
  esac
}

ensure_backend_state() {
  requested_backend="$1"
  existing_backend="$(current_state_backend)"

  if is_true "$FORCE_REREGISTER"; then
    if [ -n "$existing_backend" ] || [ -s "$WG_CONF" ]; then
      log "FORCE_REREGISTER=1，清理已有 ${existing_backend:-unknown} 状态并重新注册。"
    fi
    clear_backend_state
    return 0
  fi

  if has_legacy_wgcf_state; then
    case "$requested_backend" in
      teams)
        fail "检测到没有 state.json 的旧 wgcf 状态，无法直接切到 teams。请设置 FORCE_REREGISTER=1。"
        ;;
      wgcf-free)
        if [ "$AUTH_MODE" = "auto" ]; then
          fail "检测到没有 state.json 的旧 wgcf 状态，auto 模式无法判断是 wgcf-free 还是 wgcf-plus。请显式设置 AUTH_MODE，或设置 FORCE_REREGISTER=1。"
        fi
        warn "检测到没有 state.json 的旧 wgcf 状态，当前按 wgcf-free 接管。"
        write_state "wgcf-free"
        ;;
      wgcf-plus)
        if [ -z "$WARP_LICENSE_KEY" ]; then
          fail "检测到没有 state.json 的旧 wgcf 状态。若要按 wgcf-plus 接管，请提供 WARP_LICENSE_KEY，或设置 FORCE_REREGISTER=1。"
        fi
        warn "检测到没有 state.json 的旧 wgcf 状态，当前按 wgcf-plus 接管。"
        write_state "wgcf-plus"
        ;;
    esac
    existing_backend="$(current_state_backend)"
  fi

  if [ -n "$existing_backend" ] && [ "$existing_backend" != "$requested_backend" ]; then
    fail "当前持久化状态后端为 ${existing_backend}，请求后端为 ${requested_backend}。如需切换，请设置 FORCE_REREGISTER=1。"
  fi

  if [ -n "$existing_backend" ] && [ ! -s "$STATE_FILE" ]; then
    write_state "$existing_backend"
  fi
}

register_via_teams() {
  raw_token="${TEAMS_TOKEN:-}"
  [ -n "$raw_token" ] || fail "首次 Teams 注册必须提供 TEAMS_TOKEN。"

  token="$(normalize_token "$raw_token")"
  [ -n "$token" ] || fail "TEAMS_TOKEN 解析后为空。"

  private_key="$(wg genkey)"
  public_key="$(printf '%s' "$private_key" | wg pubkey)"
  install_id="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 22)"
  fcm_token="${install_id}:APA91b$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 134)"
  attempt=1

  while [ "$attempt" -le "$REGISTER_RETRIES" ]; do
    body_file="$(mktemp)"
    http_code="$(
      curl \
        --silent \
        --show-error \
        --location \
        --tlsv1.3 \
        --output "$body_file" \
        --write-out '%{http_code}' \
        --request POST \
        --header 'User-Agent: okhttp/3.12.1' \
        --header "CF-Client-Version: ${CF_CLIENT_VERSION}" \
        --header 'Content-Type: application/json' \
        --header "Cf-Access-Jwt-Assertion: ${token}" \
        --data "{\"key\":\"${public_key}\",\"install_id\":\"${install_id}\",\"fcm_token\":\"${fcm_token}\",\"tos\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"model\":\"PC\",\"serial_number\":\"${install_id}\",\"locale\":\"zh_CN\"}" \
        "$REGISTER_URL" || true
    )"

    response_body="$(cat "$body_file")"
    rm -f "$body_file"
    compact_body="$(printf '%s' "$response_body" | tr -d '\r\n')"

    if [ "$http_code" = "200" ] && printf '%s' "$compact_body" | grep -q '"account"'; then
      printf '%s' "$compact_body" \
        | sed "s#\"key\":\"[^\"]*\"#\"key\":\"${public_key}\",\"private_key\":\"${private_key}\"#" \
        >"$ACCOUNT_JSON"
      chmod 600 "$ACCOUNT_JSON"
      write_state "teams"
      log "Teams 注册成功，账号信息已保存到 ${ACCOUNT_JSON}"
      return 0
    fi

    if [ "$http_code" = "401" ] && printf '%s' "$compact_body" | grep -q 'token is expired'; then
      fail "registration token 已过期，请重新获取。"
    fi

    log "注册失败，第 ${attempt}/${REGISTER_RETRIES} 次，HTTP ${http_code:-unknown}"
    log "响应摘要: $(printf '%s' "$response_body" | tr '\n' ' ' | cut -c 1-220)"
    attempt=$((attempt + 1))
    sleep "$REGISTER_RETRY_DELAY"
  done

  fail "注册失败，已达到最大重试次数。"
}

register_via_wgcf_free() {
  if [ -s "$WGCF_ACCOUNT" ]; then
    log "检测到已有 wgcf 账户，跳过免费注册。"
  else
    log "使用 wgcf 注册免费 WARP 账户..."
    run_wgcf register --accept-tos
    [ -s "$WGCF_ACCOUNT" ] || fail "wgcf 免费注册成功后未生成 ${WGCF_ACCOUNT}。"
  fi

  chmod 600 "$WGCF_ACCOUNT" || true
  write_state "wgcf-free"
}

register_via_wgcf_plus() {
  if [ ! -s "$WGCF_ACCOUNT" ]; then
    [ -n "$WARP_LICENSE_KEY" ] || fail "首次 wgcf-plus 注册必须提供 WARP_LICENSE_KEY。"
    log "使用 wgcf 注册 WARP 账户..."
    run_wgcf register --accept-tos
    [ -s "$WGCF_ACCOUNT" ] || fail "wgcf 注册成功后未生成 ${WGCF_ACCOUNT}。"
  fi

  current_license="$(stored_wgcf_license_key)"
  if [ -n "$WARP_LICENSE_KEY" ] && [ "$current_license" != "$WARP_LICENSE_KEY" ]; then
    log "绑定或更新 WARP+ license key..."
    run_wgcf update --license-key "$WARP_LICENSE_KEY"
  else
    log "检测到已有 wgcf-plus 账户，直接复用当前绑定。"
  fi

  chmod 600 "$WGCF_ACCOUNT" || true
  write_state "wgcf-plus"
}

generate_wgcf_profile() {
  [ -s "$WGCF_ACCOUNT" ] || fail "缺少 ${WGCF_ACCOUNT}，无法生成 wgcf WireGuard 配置。"
  rm -f "$WGCF_PROFILE"
  run_wgcf generate
  [ -s "$WGCF_PROFILE" ] || fail "wgcf generate 后未生成 ${WGCF_PROFILE}。"
  chmod 600 "$WGCF_PROFILE"
}

write_wg_config() {
  private_key="$1"
  peer_public_key="$2"
  endpoint_host="$3"
  address_v4="$4"
  address_v6="$5"
  mtu_value="$6"
  reserved_value="$7"

  [ -n "$private_key" ] || fail "WireGuard 配置缺少 PrivateKey。"
  [ -n "$peer_public_key" ] || fail "WireGuard 配置缺少 Peer PublicKey。"

  case "$WARP_STACK" in
    ipv4)
      [ -n "$address_v4" ] || fail "当前后端没有可用的 IPv4 地址。"
      interface_block="Address = $(ensure_v4_cidr "$address_v4")"
      allowed_ips="0.0.0.0/0"
      ;;
    ipv6)
      [ -n "$address_v6" ] || fail "当前后端没有可用的 IPv6 地址。"
      interface_block="Address = $(ensure_v6_cidr "$address_v6")"
      allowed_ips="::/0"
      ;;
    dual)
      [ -n "$address_v4" ] || fail "当前后端没有可用的 IPv4 地址。"
      [ -n "$address_v6" ] || fail "当前后端没有可用的 IPv6 地址。"
      interface_block="Address = $(ensure_v4_cidr "$address_v4")
Address = $(ensure_v6_cidr "$address_v6")"
      allowed_ips="0.0.0.0/0,::/0"
      ;;
    *)
      fail "不支持的 WARP_STACK=${WARP_STACK}，仅支持 ipv4、dual、ipv6。"
      ;;
  esac

  reserved_line=""
  if [ -n "$reserved_value" ]; then
    reserved_line="Reserved = ${reserved_value}
"
  fi

  cat >"$WG_CONF" <<EOF
[Interface]
PrivateKey = ${private_key}
${interface_block}
MTU = ${mtu_value:-1280}

[Peer]
PublicKey = ${peer_public_key}
${reserved_line}AllowedIPs = ${allowed_ips}
Endpoint = ${endpoint_host}
PersistentKeepalive = 15
EOF

  sed -i '/^DNS.*/d' "$WG_CONF"

  chmod 600 "$WG_CONF"
  [ -f "$STATE_FILE" ] && chmod 600 "$STATE_FILE"
}

build_teams_wg_config() {
  [ -s "$ACCOUNT_JSON" ] || fail "缺少 ${ACCOUNT_JSON}，无法构建 Teams WireGuard 配置。"

  private_key="$(json_extract '.*"private_key":"\([^"]*\)".*')"
  peer_public_key="$(json_extract '.*"peers":\[{"public_key":"\([^"]*\)","endpoint".*')"
  endpoint_host="$(json_extract '.*"peers":\[{"public_key":"[^"]*","endpoint":{"v4":"[^"]*","v6":"[^"]*","host":"\([^"]*\)".*')"
  address_v4="$(json_extract '.*"interface":{"addresses":{"v4":"\([^"]*\)","v6":"[^"]*".*')"
  address_v6="$(json_extract '.*"interface":{"addresses":{"v4":"[^"]*","v6":"\([^"]*\)".*')"

  endpoint_host="${endpoint_host:-engage.cloudflareclient.com:2408}"
  write_wg_config "$private_key" "$peer_public_key" "$endpoint_host" "$address_v4" "$address_v6" "1280" ""
  log "已生成 ${WG_CONF}，模式: ${WARP_STACK}"
}

build_wgcf_wg_config() {
  generate_wgcf_profile

  private_key="$(sed -n 's/^PrivateKey[[:space:]]*=[[:space:]]*//p' "$WGCF_PROFILE" | head -n 1)"
  peer_public_key="$(sed -n 's/^PublicKey[[:space:]]*=[[:space:]]*//p' "$WGCF_PROFILE" | head -n 1)"
  endpoint_host="$(sed -n 's/^Endpoint[[:space:]]*=[[:space:]]*//p' "$WGCF_PROFILE" | head -n 1)"
  mtu_value="$(sed -n 's/^MTU[[:space:]]*=[[:space:]]*//p' "$WGCF_PROFILE" | head -n 1)"
  reserved_value="$(sed -n 's/^Reserved[[:space:]]*=[[:space:]]*//p' "$WGCF_PROFILE" | head -n 1)"
  address_line="$(sed -n 's/^Address[[:space:]]*=[[:space:]]*//p' "$WGCF_PROFILE" | head -n 1)"
  address_v4="$(printf '%s' "$address_line" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -m1 '\.' || true)"
  address_v6="$(printf '%s' "$address_line" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -m1 ':' || true)"

  write_wg_config "$private_key" "$peer_public_key" "$endpoint_host" "$address_v4" "$address_v6" "${mtu_value:-1280}" "$reserved_value"
  log "已生成 ${WG_CONF}，模式: ${WARP_STACK}"
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

  if is_true "$LOCAL_BYPASS_INCLUDE_PRIMARY"; then
    remove_bypass_rules ipv4 "$primary_v4_subnet"
  fi
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    remove_bypass_rules ipv4 "$subnet"
  done <<EOF
$(iterate_configured_bypass_subnets ipv4)
EOF

  if is_true "$LOCAL_BYPASS_INCLUDE_PRIMARY"; then
    remove_bypass_rules ipv6 "$primary_v6_subnet"
  fi
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    remove_bypass_rules ipv6 "$subnet"
  done <<EOF
$(iterate_configured_bypass_subnets ipv6)
EOF
}

ensure_local_network_bypass() {
  primary_v4_subnet="$(ip -4 route show dev eth0 proto kernel scope link | awk 'NR==1 {print $1}')"
  primary_v6_subnet="$(ip -6 route show dev eth0 proto kernel | awk '/^[0-9a-fA-F:]+\// {print $1; exit}')"
  ipv4_bypass_priority="$(detect_local_bypass_rule_priority ipv4 "$LOCAL_BYPASS_RULE_PRIORITY_FALLBACK")"
  ipv6_bypass_priority="$(detect_local_bypass_rule_priority ipv6 "$LOCAL_BYPASS_RULE_PRIORITY_FALLBACK")"

  # 旁路规则必须动态保持在当前 wg-quick 自动规则之前。
  # 否则 endpoint 轮换或同一容器内重复 down/up 后，wg-quick 新拿到的更高优先级规则仍会把局域网回包抢走。
  if is_true "$LOCAL_BYPASS_INCLUDE_PRIMARY"; then
    ensure_ipv4_bypass "$primary_v4_subnet" "$ipv4_bypass_priority"
  fi
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    ensure_ipv4_bypass "$subnet" "$ipv4_bypass_priority"
  done <<EOF
$(iterate_configured_bypass_subnets ipv4)
EOF

  if is_true "$LOCAL_BYPASS_INCLUDE_PRIMARY"; then
    ensure_ipv6_bypass "$primary_v6_subnet" "$ipv6_bypass_priority"
  fi
  while IFS= read -r subnet; do
    [ -n "$subnet" ] || continue
    ensure_ipv6_bypass "$subnet" "$ipv6_bypass_priority"
  done <<EOF
$(iterate_configured_bypass_subnets ipv6)
EOF

  log "已为本地网络添加旁路: v4=[$(configured_bypass_summary ipv4 "$primary_v4_subnet")] v6=[$(configured_bypass_summary ipv6 "$primary_v6_subnet")]（策略优先级 v4=${ipv4_bypass_priority}, v6=${ipv6_bypass_priority}）"
}

wait_for_egress_ready() {
  probe_retries="$(sanitize_positive_int "$STARTUP_EGRESS_PROBE_RETRIES" 3)"
  probe_delay="$(sanitize_positive_int "$STARTUP_EGRESS_PROBE_DELAY" 2)"
  probe_timeout="$(sanitize_positive_int "$STARTUP_EGRESS_PROBE_TIMEOUT" 5)"
  attempt=1

  # 这里探测的是隧道起来后的第一条真实公网流量。
  # 如果连续探测都拿不到出口 IP，就不要继续启动 socks5，直接退出交给 Docker 重试。
  while [ "$attempt" -le "$probe_retries" ]; do
    egress_ip="$(probe_direct_trace_ip "$probe_timeout")"
    if [ -n "$egress_ip" ]; then
      log "当前出口 IP: ${egress_ip}"
      return 0
    fi

    if [ "$attempt" -lt "$probe_retries" ]; then
      warn "启动后第 ${attempt}/${probe_retries} 次出口探测未获取到 IP，${probe_delay} 秒后重试。"
      sleep "$probe_delay"
    fi
    attempt=$((attempt + 1))
  done

  return 1
}

select_endpoint_candidate_by_index() {
  requested_index="$(sanitize_positive_int "${1:-0}" 0)"
  CURRENT_ENDPOINT_OVERRIDE=""
  CURRENT_ENDPOINT_INDEX=""
  CURRENT_ENDPOINT_TOTAL="$(endpoint_candidate_count)"

  if [ "$CURRENT_ENDPOINT_TOTAL" -le 0 ]; then
    return 1
  fi

  if [ "$requested_index" -le 0 ] || [ "$requested_index" -gt "$CURRENT_ENDPOINT_TOTAL" ]; then
    requested_index=1
  fi

  CURRENT_ENDPOINT_INDEX="$requested_index"
  CURRENT_ENDPOINT_OVERRIDE="$(endpoint_candidate_at "$CURRENT_ENDPOINT_INDEX")"
  [ -n "$CURRENT_ENDPOINT_OVERRIDE" ]
}

apply_endpoint_override_to_wg_conf() {
  requested_index="${1:-}"
  if ! select_endpoint_candidate_by_index "$requested_index"; then
    return 1
  fi

  sed -i "s#^Endpoint = .*#Endpoint = ${CURRENT_ENDPOINT_OVERRIDE}#" "$WG_CONF"
  if [ "$CURRENT_ENDPOINT_TOTAL" -gt 1 ]; then
    log "已覆盖 Endpoint 为 ${CURRENT_ENDPOINT_OVERRIDE}（候选 ${CURRENT_ENDPOINT_INDEX}/${CURRENT_ENDPOINT_TOTAL}）"
  else
    log "已覆盖 Endpoint 为 ${CURRENT_ENDPOINT_OVERRIDE}"
  fi
}

bring_down_tunnel_if_present() {
  if ip link show wg0 >/dev/null 2>&1; then
    wg-quick down wg0 >/dev/null 2>&1 || true
  fi
  cleanup_local_network_bypass
}

start_tunnel() {
  candidate_count="$(endpoint_candidate_count)"
  # 无候选时视为单次尝试（不覆盖 Endpoint）；有候选时依次轮询每个候选。
  max_attempts="$([ "$candidate_count" -le 0 ] && echo 1 || echo "$candidate_count")"
  index=1

  while [ "$index" -le "$max_attempts" ]; do
    bring_down_tunnel_if_present
    [ "$candidate_count" -gt 0 ] && apply_endpoint_override_to_wg_conf "$index"

    log "正在启动 wg0"
    run_with_formatted_logs "wg-quick" "INFO" "" wg-quick up wg0
    ensure_local_network_bypass

    if wait_for_egress_ready; then
      return 0
    fi

    warn "启动后连续 ${STARTUP_EGRESS_PROBE_RETRIES} 次出口探测仍未获取到出口 IP。"
    bring_down_tunnel_if_present

    if [ "$candidate_count" -gt 1 ] && [ "$index" -lt "$candidate_count" ]; then
      failed_endpoint="${CURRENT_ENDPOINT_OVERRIDE:-unknown}"
      next_index=$((index + 1))
      next_endpoint="$(endpoint_candidate_at "$next_index")"
      warn "当前 endpoint ${failed_endpoint} 未通过出口探测，切换到候选 ${next_index}/${candidate_count}: ${next_endpoint:-unknown}。"
    fi

    index=$((index + 1))
  done

  fail "启动后连续 ${STARTUP_EGRESS_PROBE_RETRIES} 次出口探测仍未获取到出口 IP，判定隧道尚不可用，退出等待容器重启。"
}

start_socks5() {
  microsocks_log_pipe="/tmp/warp-socks-microsocks.log.pipe"
  log "启动无认证 SOCKS5（容器内监听）: ${LISTEN_ADDR}:${LISTEN_PORT}"
  if [ -n "$HOST_LISTEN_PORT" ]; then
    log "Docker 发布端口（宿主机入口）: ${HOST_LISTEN_ADDR:-0.0.0.0}:${HOST_LISTEN_PORT} -> 容器 ${LISTEN_ADDR}:${LISTEN_PORT}"
  fi

  if is_true "$MICROSOCKS_LOG_ACCESS"; then
    if is_true "$MICROSOCKS_LOG_LOCAL_CLIENTS"; then
      log "microsocks 连接日志已启用，包含本地 127.0.0.1/::1 探测流量。"
    else
      log "microsocks 连接日志已启用，默认隐藏本地 127.0.0.1/::1 探测流量。"
    fi
    start_log_pipe_formatter "$microsocks_log_pipe" "microsocks" "INFO" "should_emit_microsocks_log_line"
    exec microsocks -i "$LISTEN_ADDR" -p "$LISTEN_PORT" >"$microsocks_log_pipe" 2>&1
  fi

  log "microsocks 连接日志已关闭。"
  exec microsocks -q -i "$LISTEN_ADDR" -p "$LISTEN_PORT"
}

mkdir -p "$WG_DIR"
prepare_runtime

requested_backend="$(detect_requested_backend "$(current_state_backend)")"
LOG_MODE="$requested_backend"
export LOG_MODE LOG_MODE_STATE_FILE
log "当前注册后端: ${requested_backend}"
ensure_backend_state "$requested_backend"

case "$requested_backend" in
  teams)
    [ -s "$ACCOUNT_JSON" ] || register_via_teams
    write_state "teams"
    build_teams_wg_config
    ;;
  wgcf-free)
    [ -s "$WGCF_ACCOUNT" ] || register_via_wgcf_free
    write_state "wgcf-free"
    build_wgcf_wg_config
    ;;
  wgcf-plus)
    register_via_wgcf_plus
    write_state "wgcf-plus"
    build_wgcf_wg_config
    ;;
esac

log_endpoint_candidate_plan
start_tunnel
if is_true "$VALIDATE_ENDPOINT_ONLY"; then
  log "验证模式已通过出口探测，不启动 socks5。"
  exit 0
fi
start_socks5
