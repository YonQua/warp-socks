ARG ALPINE_VERSION=3.22.3
# rust:alpine 构建阶段用的镜像 tag，需和 ALPINE_VERSION 的大版本号对齐（决定 musl ABI）。
ARG RUST_VERSION=1.97.1-alpine3.22
# 为空则直连官方源；默认走自建 CDN 代理加速国内/弱网构建。
ARG APK_MIRROR_PREFIX=https://cdn.leishao.nyc.mn/https://dl-cdn.alpinelinux.org
# 为空则直连 crates.io 官方源；国内构建可设为 sparse registry 镜像地址，
# 例如 sparse+https://rsproxy.cn/index/（值需自带 sparse+ 前缀，原样写入 cargo 配置）。
ARG CARGO_REGISTRY_MIRROR=

FROM rust:${RUST_VERSION} AS rust-builder

ARG CARGO_REGISTRY_MIRROR

# 隧道+SOCKS 实现（参考 warp-plus 思路用 Rust 重写，见 warp-rs/），
# 只编译生产用的 warp-socks 二进制，跳过验证阶段遗留的 handshake_probe。
WORKDIR /build
COPY warp-rs/ .
RUN set -eu \
 && if [ -n "${CARGO_REGISTRY_MIRROR}" ]; then \
      mkdir -p .cargo \
      && printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n' \
        "${CARGO_REGISTRY_MIRROR}" >.cargo/config.toml; \
    fi \
 && cargo build --release --bin warp-socks \
 && install -m 0755 target/release/warp-socks /usr/local/bin/warp-socks-rs

FROM alpine:${ALPINE_VERSION}

ARG APK_MIRROR_PREFIX

# 仅保留：
# - curl/jq：注册与探测
# - wireguard-tools：注册时 wg genkey/pubkey
# 隧道与 SOCKS 由自研 warp-socks-rs 提供。
RUN set -eu \
 && if [ -n "${APK_MIRROR_PREFIX}" ]; then \
      sed -i "s#https://dl-cdn.alpinelinux.org#${APK_MIRROR_PREFIX}#g" /etc/apk/repositories; \
    fi \
 && apk add --no-cache ca-certificates curl jq wireguard-tools

COPY --from=rust-builder /usr/local/bin/warp-socks-rs /usr/local/bin/warp-socks-rs
COPY lib /usr/local/lib/warp-socks
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY healthcheck/check-socks5.sh /usr/local/bin/healthcheck-check-socks5.sh

RUN chmod +x \
      /usr/local/bin/entrypoint.sh \
      /usr/local/bin/healthcheck-check-socks5.sh \
      /usr/local/lib/warp-socks/warp-common.sh \
      /usr/local/bin/warp-socks-rs

# Docker 只负责定时调用 healthcheck；连续失败阈值完全由脚本内的
# WARP_SOCKS_HEALTHCHECK_FAILURE_THRESHOLD 控制，避免双重阈值来源。
HEALTHCHECK --interval=30s --timeout=25s --start-period=30s --retries=1 \
  CMD ["/usr/local/bin/healthcheck-check-socks5.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
