#!/bin/bash
# Start the image once and check it serves: the legacy port answers the
# TRTP handshake, the ng port answers discovery, and the image's own
# health check passes. What CI runs before it publishes anything, and
# runnable as it is against a local build:
#
#   docker build -t hxd-ng . && docker/smoke-test.sh hxd-ng
set -euo pipefail

image=${1:?usage: smoke-test.sh IMAGE}
name=hxd-ng-smoke-$$

fail() {
    echo "smoke-test: $*" >&2
    docker logs "$name" >&2 || true
    exit 1
}

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker run -d --name "$name" \
    -v "$name":/var/lib/hxd-ng \
    -p 127.0.0.1::5500 -p 127.0.0.1::5700 \
    -e HXD_NAME=smoke \
    -e HXD_ADMIN_LOGIN=Admin -e HXD_ADMIN_PASSWORD=smoke \
    "$image" >/dev/null

legacy=$(docker port "$name" 5500/tcp | head -n1)
ng=$(docker port "$name" 5700/tcp | head -n1)

# The handshake: "TRTPHOTL", version 1, subversion 2; the answer is
# "TRTP" and a zero error code.
handshake() {
    exec 3<>"/dev/tcp/${legacy%:*}/${legacy##*:}" || return 1
    printf 'TRTPHOTL\000\001\000\002' >&3
    reply=$(timeout 5 head -c 8 <&3 | od -An -tx1 | tr -d ' \n')
    exec 3<&-
    [ "$reply" = 5452545000000000 ]
}

ok=
for _ in $(seq 60); do
    [ "$(docker inspect -f '{{.State.Running}}' "$name")" = true ] ||
        fail "the container exited"
    if handshake 2>/dev/null; then
        ok=1
        break
    fi
    sleep 1
done
[ -n "$ok" ] || fail "no TRTP handshake on $legacy"
echo "smoke-test: legacy handshake on $legacy"

discovery=$(curl -fsS --max-time 5 "http://$ng/.well-known/hotline") ||
    fail "no discovery on $ng"
case $discovery in
    *'"smoke"'*) ;;
    *) fail "discovery does not name the server: $discovery" ;;
esac
echo "smoke-test: discovery on $ng"

docker exec "$name" bash -c 'exec 3<>/dev/tcp/127.0.0.1/5500' ||
    fail "the health check's probe fails"

# The login is folded the way FileAuth folds it.
docker exec "$name" test -f /var/lib/hxd-ng/accounts/admin.toml ||
    fail "no accounts/admin.toml"

docker stop "$name" >/dev/null
status=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$status" = 0 ] || fail "exited $status on SIGTERM"
echo "smoke-test: ok"
