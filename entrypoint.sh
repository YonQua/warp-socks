#!/bin/sh
set -eu

WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
ACCOUNT_JSON="${WG_DIR}/account.json"
WGCF_ACCOUNT="${WG_DIR}/wgcf-account.toml"
WGCF_PROFILE="${WG_DIR}/wgcf-profile.conf"
STATE_FILE="${WG_DIR}/state.json"
REGISTER_URL="${REGISTER_URL:-https://api.cloudflareclient.com/v0a2158/reg}"
AUTH_MODE="${AUTH_MODE:-auto}"
FORCE_REREGISTER="${FORCE_REREGISTER:-0}"
WARP_STACK="${WARP_STACK:-dual}"
REGISTER_RETRIES="${REGISTER_RETRIES:-3}"
REGISTER_RETRY_DELAY="${REGISTER_RETRY_DELAY:-5}"
LISTEN_ADDR="${BIND_ADDR:-0.0.0.0}"
LISTEN_PORT="${BIND_PORT:-1080}"
WARP_LICENSE_KEY="${WARP_LICENSE_KEY:-}"
# 这是注册 API 的兼容客户端标识，不等同于 Cloudflare 官方桌面客户端的发布版本号。
CF_CLIENT_VERSION="${CF_CLIENT_VERSION:-a-6.10-2158}"

log() {
  printf '%s %s\n' "==> [warp-socks]" "$*"
}

warn() {
  printf '%s %s\n' "==> [warp-socks][WARN]" "$*" >&2
}

fail() {
  printf '%s %s\n' "==> [warp-socks][ERROR]" "$*" >&2
  exit 1
}

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
    wgcf "$@"
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
  case "$AUTH_MODE" in
    auto)
      if [ -n "${TEAMS_TOKEN:-}" ]; then
        if [ -n "$WARP_LICENSE_KEY" ]; then
          warn "检测到 TEAMS_TOKEN 与 WARP_LICENSE_KEY 同时存在，当前按优先级使用 teams，忽略 WARP_LICENSE_KEY。"
        fi
        printf 'teams'
      elif [ -n "$WARP_LICENSE_KEY" ]; then
        printf 'wgcf-plus'
      else
        printf 'wgcf-free'
      fi
      ;;
    teams)
      [ -n "${TEAMS_TOKEN:-}" ] || fail "AUTH_MODE=teams 时必须提供 TEAMS_TOKEN。"
      [ -n "$WARP_LICENSE_KEY" ] && warn "AUTH_MODE=teams 已显式指定，忽略 WARP_LICENSE_KEY。"
      printf 'teams'
      ;;
    wgcf-plus)
      [ -n "$WARP_LICENSE_KEY" ] || fail "AUTH_MODE=wgcf-plus 时必须提供 WARP_LICENSE_KEY。"
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

  if [ -n "${ENDPOINT_IP:-}" ]; then
    sed -i "s#^Endpoint = .*#Endpoint = ${ENDPOINT_IP}#" "$WG_CONF"
    log "已覆盖 Endpoint 为 ${ENDPOINT_IP}"
  fi

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

start_tunnel() {
  if ip link show wg0 >/dev/null 2>&1; then
    wg-quick down wg0 >/dev/null 2>&1 || true
  fi

  log "正在启动 wg0"
  wg-quick up wg0
  trace="$(curl -s --max-time 5 https://1.1.1.1/cdn-cgi/trace || true)"
  egress_ip="$(printf '%s\n' "$trace" | sed -n 's/^ip=\(.*\)$/\1/p' | head -n 1)"
  [ -n "$egress_ip" ] && log "当前出口 IP: ${egress_ip}" || log "未能在 5 秒内获取出口 IP"
}

start_socks5() {
  log "启动无认证 SOCKS5: ${LISTEN_ADDR}:${LISTEN_PORT}"
  exec microsocks -i "$LISTEN_ADDR" -p "$LISTEN_PORT"
}

mkdir -p "$WG_DIR"
prepare_runtime

requested_backend="$(detect_requested_backend)"
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

start_tunnel
start_socks5
