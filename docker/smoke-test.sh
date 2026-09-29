#!/bin/bash
# Start the image once and check it serves: the legacy port answers the
# TRTP handshake, in the clear and over TLS, the ng port answers
# discovery, and the image's own health check passes. Then start it again
# in relay mode in front of the first, and check the relay answers
# discovery and carries a WebSocket on /trtp to the server's classic
# port. What CI runs before it publishes anything, and runnable as it is
# against a local build:
#
#   docker build -t hxd-ng . && docker/smoke-test.sh hxd-ng
set -euo pipefail

image=${1:?usage: smoke-test.sh IMAGE}
name=hxd-ng-smoke-$$
relay=$name-relay

fail() {
    echo "smoke-test: $*" >&2
    docker logs "$name" >&2 || true
    if docker inspect "$relay" >/dev/null 2>&1; then
        echo "smoke-test: the relay's log:" >&2
        docker logs "$relay" >&2 || true
    fi
    exit 1
}

tls_dir=$(mktemp -d)

cleanup() {
    # -v: the image declares a volume, and the relay, which mounts none,
    # is given an anonymous one.
    docker rm -f -v "$relay" >/dev/null 2>&1 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm -f "$name" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
    rm -rf "$tls_dir"
}
trap cleanup EXIT

# A throwaway self-signed pair, readable by the container's user.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$tls_dir/key.pem" -out "$tls_dir/cert.pem" \
    -subj /CN=localhost -days 1 2>/dev/null ||
    fail "openssl could not make a certificate"
chmod 0755 "$tls_dir"
chmod 0644 "$tls_dir/key.pem" "$tls_dir/cert.pem"

# A network of its own, where the relay finds the server by name.
docker network create "$name" >/dev/null
docker run -d --name "$name" --network "$name" \
    -v "$name":/var/lib/hxd-ng \
    -p 127.0.0.1::5500 -p 127.0.0.1::5600 -p 127.0.0.1::5700 \
    -v "$tls_dir":/etc/hxd-ng/tls:ro \
    -e HXD_TLS_CERT=/etc/hxd-ng/tls/cert.pem -e HXD_TLS_KEY=/etc/hxd-ng/tls/key.pem \
    -e HXD_NAME=smoke \
    -e HXD_ADMIN_LOGIN=Admin -e HXD_ADMIN_PASSWORD=smoke \
    "$image" >/dev/null

legacy=$(docker port "$name" 5500/tcp | head -n1)
tls=$(docker port "$name" 5600/tcp | head -n1)
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

# The same handshake inside TLS, trusting only the certificate mounted.
reply=$(printf 'TRTPHOTL\000\001\000\002' |
    timeout 10 openssl s_client -quiet -connect "$tls" -servername localhost \
        -CAfile "$tls_dir/cert.pem" -verify_return_error 2>/dev/null |
    head -c 8 | od -An -tx1 | tr -d ' \n') || true
[ "$reply" = 5452545000000000 ] || fail "no TRTP handshake over TLS on $tls (got '$reply')"
echo "smoke-test: legacy handshake over TLS on $tls"

discovery=$(curl -fsS --max-time 5 "http://$ng/.well-known/hotline") ||
    fail "no discovery on $ng"
case $discovery in
    *'"smoke"'*) ;;
    *) fail "discovery does not name the server: $discovery" ;;
esac
echo "smoke-test: discovery on $ng"

# The image's own health check, as Docker would run it.
health=$(docker inspect -f '{{index .Config.Healthcheck.Test 3}}' "$name")
docker exec "$name" bash -c "$health" ||
    fail "the health check's probe fails"

# The login is folded the way FileAuth folds it.
docker exec "$name" test -f /var/lib/hxd-ng/accounts/admin.toml ||
    fail "no accounts/admin.toml"

# Relay mode, with the server above as its classic server.
docker run -d --name "$relay" --network "$name" \
    -p 127.0.0.1::5700 \
    -e HXD_MODE=relay -e HXD_RELAY_UPSTREAM="$name:5500" \
    -e HXD_RELAY_NAME=smoke-relay \
    "$image" >/dev/null
front=$(docker port "$relay" 5700/tcp | head -n1)

discovery=
for _ in $(seq 30); do
    [ "$(docker inspect -f '{{.State.Running}}' "$relay")" = true ] ||
        fail "the relay exited"
    discovery=$(curl -fsS --max-time 5 "http://$front/.well-known/hotline" 2>/dev/null) &&
        break
    sleep 1
done
case $discovery in
    *'"smoke-relay"'*'"trtp"'* | *'"trtp"'*'"smoke-relay"'*) ;;
    *) fail "no relay discovery on $front: $discovery" ;;
esac
echo "smoke-test: relay discovery on $front"

# The TRTP handshake inside a WebSocket on /trtp: the upgrade, then the
# handshake as one binary frame (a client's frames are masked; an
# all-zero mask leaves the payload as it is), and the server's answer as
# one unmasked binary frame of eight bytes.
exec 3<>"/dev/tcp/${front%:*}/${front##*:}"
printf 'GET /trtp HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n' "$front" >&3
IFS= read -r -t 5 status_line <&3 || fail "no answer to the upgrade on $front"
case $status_line in
    "HTTP/1.1 101 "*) ;;
    *) fail "the upgrade on $front was answered: $status_line" ;;
esac
while IFS= read -r -t 5 header <&3; do
    [ "$header" = $'\r' ] && break
done
printf '\202\214\000\000\000\000TRTPHOTL\000\001\000\002' >&3
reply=$(timeout 5 head -c 10 <&3 | od -An -tx1 | tr -d ' \n') || true
exec 3<&-
[ "$reply" = 82085452545000000000 ] ||
    fail "no TRTP handshake through the relay on $front (got '$reply')"
echo "smoke-test: TRTP handshake through the relay's /trtp on $front"

health=$(docker inspect -f '{{index .Config.Healthcheck.Test 3}}' "$relay")
docker exec "$relay" bash -c "$health" ||
    fail "the relay's health check fails"

for container in "$relay" "$name"; do
    docker stop "$container" >/dev/null
    status=$(docker inspect -f '{{.State.ExitCode}}' "$container")
    [ "$status" = 0 ] || fail "$container exited $status on SIGTERM"
done
echo "smoke-test: ok"
