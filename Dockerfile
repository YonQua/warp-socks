ARG ALPINE_VERSION=3.22.3
ARG WARP_PLUS_VERSION=v1.2.6
# 为空则直连官方源；默认走自建 CDN 代理加速国内/弱网构建。
ARG APK_MIRROR_PREFIX=https://cdn.leishao.nyc.mn/https://dl-cdn.alpinelinux.org
ARG GITHUB_PROXY_PREFIX=https://cdn.leishao.nyc.mn/https://github.com

FROM alpine:${ALPINE_VERSION} AS fetcher

ARG WARP_PLUS_VERSION
ARG TARGETARCH
ARG APK_MIRROR_PREFIX
ARG GITHUB_PROXY_PREFIX

# 拉取 bepass warp-plus 预编译包。它基于带 WARP tricks 的 userspace WireGuard，
# 在中国等环境下比内核 wg-quick 更容易完成握手。
RUN set -eu \
 && if [ -n "${APK_MIRROR_PREFIX}" ]; then \
      sed -i "s#https://dl-cdn.alpinelinux.org#${APK_MIRROR_PREFIX}#g" /etc/apk/repositories; \
    fi \
 && apk add --no-cache ca-certificates curl unzip \
 && case "${TARGETARCH}" in \
      amd64) arch="amd64" ;; \
      arm64) arch="arm64" ;; \
      arm) arch="arm7" ;; \
      *) printf '%s\n' "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && if [ -n "${GITHUB_PROXY_PREFIX}" ]; then \
      warp_plus_url="${GITHUB_PROXY_PREFIX}/bepass-org/warp-plus/releases/download/${WARP_PLUS_VERSION}/warp-plus_linux-${arch}.zip"; \
    else \
      warp_plus_url="https://github.com/bepass-org/warp-plus/releases/download/${WARP_PLUS_VERSION}/warp-plus_linux-${arch}.zip"; \
    fi \
 && curl --fail --show-error --location \
      --retry 5 --retry-all-errors --retry-delay 2 \
      --output /tmp/warp-plus.zip \
      "${warp_plus_url}" \
 && mkdir -p /tmp/warp-plus \
 && unzip -o /tmp/warp-plus.zip -d /tmp/warp-plus \
 && install -m 0755 /tmp/warp-plus/warp-plus /usr/local/bin/warp-plus

FROM alpine:${ALPINE_VERSION}

ARG APK_MIRROR_PREFIX

# 仅保留：
# - curl/jq：注册与探测
# - wireguard-tools：注册时 wg genkey/pubkey
# 隧道与 SOCKS 全部交给 warp-plus userspace，不再依赖内核 wg0 / microsocks。
RUN set -eu \
 && if [ -n "${APK_MIRROR_PREFIX}" ]; then \
      sed -i "s#https://dl-cdn.alpinelinux.org#${APK_MIRROR_PREFIX}#g" /etc/apk/repositories; \
    fi \
 && apk add --no-cache ca-certificates curl jq wireguard-tools

COPY --from=fetcher /usr/local/bin/warp-plus /usr/local/bin/warp-plus
COPY lib /usr/local/lib/warp-socks
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY healthcheck/check-socks5.sh /usr/local/bin/healthcheck-check-socks5.sh

RUN chmod +x \
      /usr/local/bin/entrypoint.sh \
      /usr/local/bin/healthcheck-check-socks5.sh \
      /usr/local/lib/warp-socks/warp-common.sh \
      /usr/local/bin/warp-plus

# Docker 只负责定时调用 healthcheck；连续失败阈值完全由脚本内的
# WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD 控制，避免双重阈值来源。
HEALTHCHECK --interval=30s --timeout=25s --start-period=30s --retries=1 \
  CMD ["/usr/local/bin/healthcheck-check-socks5.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
