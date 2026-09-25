#!/bin/bash
# Start the image once and check it serves: the legacy port answers the
# TRTP handshake, in the clear and over TLS, the ng port answers
# discovery, and the image's own health check passes. What CI runs
# before it publishes anything, and runnable as it is against a local
# build:
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

tls_dir=$(mktemp -d)

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm -f "$name" >/dev/null 2>&1 || true
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

docker run -d --name "$name" \
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

docker exec "$name" bash -c 'exec 3<>/dev/tcp/127.0.0.1/5500' ||
    fail "the health check's probe fails"

# The login is folded the way FileAuth folds it.
docker exec "$name" test -f /var/lib/hxd-ng/accounts/admin.toml ||
    fail "no accounts/admin.toml"

docker stop "$name" >/dev/null
status=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$status" = 0 ] || fail "exited $status on SIGTERM"
echo "smoke-test: ok"
