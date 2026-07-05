FROM rust:1.96.1-alpine AS builder

ARG BUILD_PROFILE=release

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
COPY src ./src

RUN if [ "$BUILD_PROFILE" = "release" ]; then \
        cargo build --locked --release --all-features; \
    elif [ "$BUILD_PROFILE" = "debug" ]; then \
        cargo build --locked --all-features; \
    else \
        echo "unsupported BUILD_PROFILE: $BUILD_PROFILE" >&2; \
        exit 1; \
    fi

FROM alpine:3.22 AS runtime

ARG BUILD_PROFILE=release

RUN apk add --no-cache ca-certificates \
    && addgroup -S titaniumguard \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -G titaniumguard titaniumguard

COPY --from=builder /usr/src/titaniumguard-dns/target/${BUILD_PROFILE}/titaniumguard-dns /usr/local/bin/titaniumguard-dns

USER titaniumguard:titaniumguard
EXPOSE 8080/tcp 8080/udp 8081/tcp 8082/tcp

ENTRYPOINT ["/usr/local/bin/titaniumguard-dns"]
