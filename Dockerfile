# syntax=docker/dockerfile:1
#
# hxd-ng for operators: the server and `hlid`, run as an unprivileged
# user, configured from HXD_* environment variables or a mounted
# hxd-ng.toml. The ng port speaks plaintext HTTP and WebSocket; put a
# TLS-terminating proxy in front of it. docs/docker.md has the variables,
# the ports, and an nginx configuration.
#
#   docker build -t hxd-ng .
#   docker run -d --name hxd-ng -v hxd-ng:/var/lib/hxd-ng \
#     -p 5500-5501:5500-5501 -p 127.0.0.1:5700:5700 \
#     -e HXD_NAME="My Server" hxd-ng

ARG RUST_VERSION=1
ARG DEBIAN_RELEASE=trixie

FROM rust:${RUST_VERSION}-${DEBIAN_RELEASE} AS build

# The voice SFU's DTLS stack reaches aws-lc-sys, which needs cmake.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Cargo features to build with, passed straight to cargo:
# `--build-arg CARGO_FEATURES="--no-default-features --features inbox"`
# leaves voice, media, markdown and push out of the binary.
ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p hxd ${CARGO_FEATURES} \
    && cargo build --release --locked -p hlid \
    && install -D -m 0755 target/release/hxd target/release/hlid -t /out/


FROM debian:${DEBIAN_RELEASE}-slim

# Every TLS client in the binary carries its own roots; ca-certificates is
# for the shell an operator execs into.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 hxd \
    && useradd --system --uid 10001 --gid hxd --home-dir /var/lib/hxd-ng \
        --shell /usr/sbin/nologin hxd \
    && install -d -o hxd -g hxd -m 0700 /var/lib/hxd-ng \
    && install -d -o hxd -g hxd -m 0700 /run/hxd-ng \
    && install -d -m 0755 /etc/hxd-ng

COPY --from=build /out/hxd /out/hlid /usr/local/bin/
COPY docker/entrypoint.sh /usr/local/bin/hxd-entrypoint

# Accounts, the identity and VAPID keys, and the SQLite store all live
# here. Back it up as a whole: the keys are not recoverable.
VOLUME /var/lib/hxd-ng
WORKDIR /var/lib/hxd-ng
USER hxd
# Logs go to `docker logs` and whatever collects it, not a terminal.
ENV NO_COLOR=1

# Legacy Hotline, HTXF files (legacy + 1), voice media (legacy + 4, UDP),
# and the ng HTTP/WebSocket port the proxy forwards to.
EXPOSE 5500/tcp 5501/tcp 5504/udp 5700/tcp

# SIGTERM shuts down cleanly; SIGHUP (`docker kill -s HUP`) re-reads the
# revocation lists without dropping anyone.
STOPSIGNAL SIGTERM
ENTRYPOINT ["hxd-entrypoint"]
CMD []
