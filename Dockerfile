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

# 隧道、SOCKS、注册、健康探测均已收口到自研 warp-socks-rs 单一二进制
# （子命令 serve/register/healthcheck），只需编译一个 bin。
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
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

# 注册、健康探测、密钥生成均已用 Rust 原生实现（reqwest/boringtun），
# 不再需要 curl/jq/wireguard-tools；ca-certificates 保留给 reqwest 的
# rustls-tls 校验证书链用。
RUN set -eu \
 && if [ -n "${APK_MIRROR_PREFIX}" ]; then \
      sed -i "s#https://dl-cdn.alpinelinux.org#${APK_MIRROR_PREFIX}#g" /etc/apk/repositories; \
    fi \
 && apk add --no-cache ca-certificates

COPY --from=rust-builder /usr/local/bin/warp-socks-rs /usr/local/bin/warp-socks-rs
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod +x \
      /usr/local/bin/entrypoint.sh \
      /usr/local/bin/warp-socks-rs

# Docker 只负责定时展示健康状态；连续失败阈值判定与重启触发完全在
# warp-socks-rs 自己的运行期健康检查循环里（见 src/supervisor.rs）。
HEALTHCHECK --interval=30s --timeout=25s --start-period=30s --retries=1 \
  CMD ["/usr/local/bin/warp-socks-rs", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
