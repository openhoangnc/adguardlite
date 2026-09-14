# syntax=docker/dockerfile:1

# A drop-in replacement for the adguard/adguardhome image.
#
# The runtime contract is copied from upstream's docker/build.Dockerfile so an
# existing deployment can swap the image without touching its compose file:
# the binary lives at the same path under the same name, the working directory
# and config path are the same, the same ports are exposed, and the entrypoint
# takes the same arguments.

# ---------------------------------------------------------------------------
# Build stage.
# ---------------------------------------------------------------------------
FROM rust:1.98-alpine AS builder

# ring (the rustls crypto provider) and the musl static link need these.
RUN apk add --no-cache musl-dev

WORKDIR /src

# Copy the manifests first so a source-only change does not refetch crates.
COPY Cargo.toml Cargo.lock ./
COPY crates/agl-core/Cargo.toml      crates/agl-core/Cargo.toml
COPY crates/agl-gob/Cargo.toml       crates/agl-gob/Cargo.toml
COPY crates/agl-bolt/Cargo.toml      crates/agl-bolt/Cargo.toml
COPY crates/agl-config/Cargo.toml    crates/agl-config/Cargo.toml
COPY crates/agl-filter/Cargo.toml    crates/agl-filter/Cargo.toml
COPY crates/agl-dns/Cargo.toml       crates/agl-dns/Cargo.toml
COPY crates/agl-querylog/Cargo.toml  crates/agl-querylog/Cargo.toml
COPY crates/agl-stats/Cargo.toml     crates/agl-stats/Cargo.toml
COPY crates/agl-api/Cargo.toml       crates/agl-api/Cargo.toml
COPY crates/adguardlite/Cargo.toml   crates/adguardlite/Cargo.toml

# Stub sources so `cargo fetch` can resolve the workspace.
RUN set -eux; \
    for d in crates/*/; do \
        mkdir -p "$d/src"; \
        echo '' > "$d/src/lib.rs"; \
    done; \
    mkdir -p crates/adguardlite/src; \
    echo 'fn main() {}' > crates/adguardlite/src/main.rs

RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    cargo fetch --locked

# Now the real sources.
COPY crates crates
COPY web web
COPY tests tests

ARG TARGETARCH
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-target,target=/src/target,sharing=locked \
    set -eux; \
    # Touch every entry point so the stubbed build above is not reused.
    find crates -name '*.rs' -exec touch {} +; \
    cargo build --locked --profile dist --bin AdGuardHome; \
    cp target/dist/AdGuardHome /AdGuardHome; \
    strip /AdGuardHome || true

# ---------------------------------------------------------------------------
# Runtime stage.
# ---------------------------------------------------------------------------
FROM alpine:3.23

ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

LABEL \
	org.opencontainers.image.created=$BUILD_DATE \
	org.opencontainers.image.description="Network-wide ads & trackers blocking DNS server, Rust backend" \
	org.opencontainers.image.licenses="GPL-3.0" \
	org.opencontainers.image.revision=$VCS_REF \
	org.opencontainers.image.source="https://github.com/openhoangnc/adguardlite" \
	org.opencontainers.image.title="adguardlite" \
	org.opencontainers.image.version=$VERSION

RUN apk --no-cache add ca-certificates libcap tzdata && \
	mkdir -p /opt/adguardhome/conf /opt/adguardhome/work && \
	chown -R nobody: /opt/adguardhome

COPY --from=builder --chmod=0755 --chown=nobody:nogroup \
	/AdGuardHome /opt/adguardhome/AdGuardHome

# Lets the server bind port 53 without running as root.
RUN setcap 'cap_net_bind_service=+eip' /opt/adguardhome/AdGuardHome

# 53     : TCP, UDP : DNS
# 67     :      UDP : DHCP (server)
# 68     :      UDP : DHCP (client)
# 80     : TCP      : HTTP (main)
# 443    : TCP, UDP : HTTPS, DNS-over-HTTPS (incl. HTTP/3), DNSCrypt (main)
# 853    : TCP, UDP : DNS-over-TLS, DNS-over-QUIC
# 3000   : TCP, UDP : HTTP(S) (alt, incl. HTTP/3)
# 5443   : TCP, UDP : DNSCrypt (alt)
# 6060   : TCP      : HTTP (pprof)
EXPOSE 53/tcp 53/udp \
	67/udp \
	68/udp \
	80/tcp \
	443/tcp 443/udp \
	853/tcp 853/udp \
	3000/tcp 3000/udp \
	5443/tcp 5443/udp \
	6060/tcp

WORKDIR /opt/adguardhome/work

ENTRYPOINT ["/opt/adguardhome/AdGuardHome"]

CMD [ \
	"--no-check-update", \
	"-c", "/opt/adguardhome/conf/AdGuardHome.yaml", \
	"-w", "/opt/adguardhome/work" \
]
