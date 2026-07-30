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

account_client_id() {
  json_extract '.config.client_id // .client_id'
}

# WARP 用 client_id 派生的 3 字节 reserved 做协议层账户标识（算法：取 client_id
# base64 解码后的前 3 个字节，对照 bepass-org/warp-plus 的 generateWireguardConfig()）。
# 隧道实现（warp-rs/src/config.rs）只认 wg0.conf 里 [Peer] 段的 Reserved 字段。
# 用 set -- 精确取前 3 个字节，不管解码出多少字节，保证输出永远是合法的
# "a,b,c" 三段格式——否则解析 wg0.conf 会直接报错退出。
account_reserved_csv() {
  client_id="$(account_client_id)"
  decoded_bytes=""

  if [ -n "$client_id" ]; then
    padded="$client_id"
    while [ $(( ${#padded} % 4 )) -ne 0 ]; do
      padded="${padded}="
    done
    decoded_bytes="$(printf '%s' "$padded" | base64 -d 2>/dev/null | od -An -tu1 | tr -s '[:space:]' ' ')"
  fi

  # shellcheck disable=SC2086
  set -- ${decoded_bytes:-}
  printf '%s,%s,%s' "${1:-0}" "${2:-0}" "${3:-0}"
}

# DNS / MTU / PersistentKeepalive 不写在这里：隧道实现固定用 DNS 1.1.1.1、
# MTU 1330、PersistentKeepalive 5 秒（源自 bepass-org/warp-plus 的
# --wgconf 分支实际生效值），写在 wg0.conf 里也不会被读取。
write_wg_config() {
  private_key="$1"
  peer_public_key="$2"
  endpoint_host="$3"
  address_v4="$4"
  address_v6="$5"
  reserved_csv="$6"

  [ -n "$private_key" ] || fail_state "WireGuard 配置缺少 PrivateKey。"
  [ -n "$peer_public_key" ] || fail_state "WireGuard 配置缺少 Peer PublicKey。"
  [ -n "$address_v4" ] || fail_state "Teams 返回里缺少 IPv4 地址。"
  [ -n "$address_v6" ] || fail_state "Teams 返回里缺少 IPv6 地址。"

  cat >"$WG_CONF" <<EOF
[Interface]
PrivateKey = ${private_key}
Address = $(ensure_v4_cidr "$address_v4")
Address = $(ensure_v6_cidr "$address_v6")

[Peer]
PublicKey = ${peer_public_key}
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = ${endpoint_host}
Reserved = ${reserved_csv}
EOF

  chmod 600 "$WG_CONF"
}

build_wg_config_from_account() {
  endpoint_override="${1:-}"
  [ -s "$ACCOUNT_JSON" ] || fail_state "缺少 ${ACCOUNT_JSON}，无法构建 WireGuard 配置。"

  private_key="$(json_extract '.private_key')"
  peer_public_key="$(json_extract '.config.peers[0].public_key // .peers[0].public_key')"
  endpoint_host="$(json_extract '.config.peers[0].endpoint.host // .peers[0].endpoint.host')"
  address_v4="$(json_extract '.config.interface.addresses.v4 // .interface.addresses.v4')"
  address_v6="$(json_extract '.config.interface.addresses.v6 // .interface.addresses.v6')"
  reserved_csv="$(account_reserved_csv)"

  if [ -n "$endpoint_override" ]; then
    endpoint_host="$endpoint_override"
  fi
  endpoint_host="${endpoint_host:-engage.cloudflareclient.com:2408}"
  write_wg_config "$private_key" "$peer_public_key" "$endpoint_host" "$address_v4" "$address_v6" "$reserved_csv"
  log "已生成 ${WG_CONF}：endpoint=${endpoint_host}, reserved=${reserved_csv}"
}
