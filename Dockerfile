ARG ALPINE_VERSION=3.22.3

FROM alpine:${ALPINE_VERSION} AS builder

ARG MICROSOCKS_VERSION=v1.0.5

# 通过固定 tag tarball 拉源码，避免默认分支漂移，也省掉 builder 阶段的 git 依赖。
RUN apk add --no-cache build-base ca-certificates curl \
 && curl --fail --show-error --location \
      --retry 5 --retry-all-errors --retry-delay 2 \
      --output /tmp/microsocks.tar.gz \
      "https://github.com/rofl0r/microsocks/archive/refs/tags/${MICROSOCKS_VERSION}.tar.gz" \
 && mkdir -p /src \
 && tar -xzf /tmp/microsocks.tar.gz -C /src \
 && mv "/src/microsocks-${MICROSOCKS_VERSION#v}" /src/microsocks \
 && make -C /src/microsocks \
 && strip /src/microsocks/microsocks || true

FROM alpine:${ALPINE_VERSION}

# 当前版本只保留 Teams registration + WireGuard。
# 同时固化 Docker 里的 wg-quick 兼容修补，避免容器启动时写只读 sysctl 导致退出。
RUN apk add --no-cache ca-certificates curl iproute2 iptables jq wireguard-tools \
 && sed -i '/sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/d' /usr/bin/wg-quick

COPY --from=builder /src/microsocks/microsocks /usr/local/bin/microsocks
COPY lib/warp-common.sh /usr/local/lib/warp-common.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY healthcheck/check-socks5.sh /usr/local/bin/healthcheck-check-socks5.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck-check-socks5.sh /usr/local/lib/warp-common.sh

# 健康检查脚本会顺序做两次最坏 10 秒的 trace 探测；
# 这里留出额外余量，确保脚本能跑完整个失败计数和自恢复分支。
HEALTHCHECK --interval=30s --timeout=25s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/healthcheck-check-socks5.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
