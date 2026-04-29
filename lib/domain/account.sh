#!/bin/sh

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

account_register_via_teams() {
  raw_token="$(normalize_token "$TEAMS_TOKEN")"
  [ -n "$raw_token" ] || fail_config "首次启动或重建状态时必须提供 TEAMS_TOKEN。"

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
      fail_register "registration token 已过期，请重新获取。"
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
      attempt=$((attempt + 1))
      sleep "$delay_seconds"
      continue
    fi

    warn "已达到最大重试次数；当前直接退出，避免无意义的额外等待。"
    attempt=$((attempt + 1))
  done

  fail_register "Teams 注册失败，已达到最大重试次数。"
}

account_ensure_state() {
  if [ -s "$ACCOUNT_JSON" ]; then
    cleanup_obsolete_runtime_files
    endpoint_state_prune_cooldowns
    log "检测到已有 Teams 账户，跳过重新注册。"
    return 0
  fi

  rm -f "$WG_CONF" "$ENDPOINT_STATE_FILE"
  account_register_via_teams
  cleanup_obsolete_runtime_files
}
