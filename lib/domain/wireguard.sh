#!/bin/sh

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

tunnel_current_wg_conf_endpoint() {
  wg_conf="${1:-/etc/wireguard/wg0.conf}"
  [ -s "$wg_conf" ] || return 0
  sed -n 's/^Endpoint[[:space:]]*=[[:space:]]*//p' "$wg_conf" | head -n 1
}

write_wg_config() {
  private_key="$1"
  peer_public_key="$2"
  endpoint_host="$3"
  address_v4="$4"
  address_v6="$5"

  [ -n "$private_key" ] || fail_state "WireGuard 配置缺少 PrivateKey。"
  [ -n "$peer_public_key" ] || fail_state "WireGuard 配置缺少 Peer PublicKey。"
  [ -n "$address_v4" ] || fail_state "Teams 返回里缺少 IPv4 地址。"
  [ -n "$address_v6" ] || fail_state "Teams 返回里缺少 IPv6 地址。"

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

tunnel_build_wg_config_from_account() {
  endpoint_override="${1:-}"
  [ -s "$ACCOUNT_JSON" ] || fail_state "缺少 ${ACCOUNT_JSON}，无法构建 WireGuard 配置。"

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
