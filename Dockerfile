FROM rust:1.96.1-alpine AS builder

WORKDIR /usr/src/titaniumguard-dns

RUN apk add --no-cache \
        build-base \
        ca-certificates \
        cmake \
        linux-headers \
        ninja \
        perl \
        pkgconf

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY main.rs mcp.rs ops.rs secure.rs ./
COPY caching ./caching
COPY config ./config
COPY forwarder ./forwarder
COPY livereload ./livereload
COPY logging ./logging
COPY policy ./policy

RUN cargo build --locked --release --all-features

FROM alpine:3.22 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -S titaniumguard \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -G titaniumguard titaniumguard

COPY --from=builder /usr/src/titaniumguard-dns/target/release/titaniumguard-dns /usr/local/bin/titaniumguard-dns

USER titaniumguard:titaniumguard
EXPOSE 8080/tcp 8080/udp 8081/tcp 8082/tcp

ENTRYPOINT ["/usr/local/bin/titaniumguard-dns"]
