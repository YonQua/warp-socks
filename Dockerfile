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

ARG WGCF_VERSION=v2.2.30

# 固化 Docker 里的 wg-quick 兼容修补，避免容器启动时写只读 sysctl 导致退出。
RUN apk add --no-cache ca-certificates curl iproute2 iptables wireguard-tools \
 && sed -i '/sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1/d' /usr/bin/wg-quick \
 && arch="$(apk --print-arch)" \
 && case "$arch" in \
      x86_64) wgcf_arch="amd64" ;; \
      aarch64) wgcf_arch="arm64" ;; \
      x86) wgcf_arch="386" ;; \
      armv7) wgcf_arch="armv7" ;; \
      armhf) wgcf_arch="armv6" ;; \
      s390x) wgcf_arch="s390x" ;; \
      *) echo "Unsupported architecture for wgcf: $arch" >&2; exit 1 ;; \
    esac \
 && curl --fail --show-error --location \
      --retry 5 --retry-all-errors --retry-delay 2 \
      --connect-timeout 20 \
      "https://github.com/ViRb3/wgcf/releases/download/${WGCF_VERSION}/wgcf_${WGCF_VERSION#v}_linux_${wgcf_arch}" \
      -o /usr/local/bin/wgcf \
 && chmod +x /usr/local/bin/wgcf

COPY --from=builder /src/microsocks/microsocks /usr/local/bin/microsocks
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY healthcheck/check-socks5.sh /usr/local/bin/healthcheck-check-socks5.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck-check-socks5.sh

HEALTHCHECK --interval=30s --timeout=12s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/healthcheck-check-socks5.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
