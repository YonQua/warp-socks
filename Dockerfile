FROM alpine:3.22 AS builder

# 单独编译 microsocks，最终镜像只拷贝产物，保持体积尽量小。
RUN apk add --no-cache build-base git
# 固定到已发布 tag，避免上游默认分支漂移影响镜像可复现性。
RUN git clone --depth 1 --branch v1.0.5 https://github.com/rofl0r/microsocks.git /src/microsocks
RUN make -C /src/microsocks

FROM alpine:3.22

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
 && curl -fsSL "https://github.com/ViRb3/wgcf/releases/download/v2.2.30/wgcf_2.2.30_linux_${wgcf_arch}" -o /usr/local/bin/wgcf \
 && chmod +x /usr/local/bin/wgcf

COPY --from=builder /src/microsocks/microsocks /usr/local/bin/microsocks
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY healthcheck/check-socks5.sh /usr/local/bin/healthcheck-check-socks5.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck-check-socks5.sh

HEALTHCHECK --interval=30s --timeout=12s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/healthcheck-check-socks5.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
