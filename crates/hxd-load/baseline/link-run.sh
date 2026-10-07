#!/bin/bash
# One run across two linked servers (docs/load-testing.md §8): run.sh's
# server twice, `a` accepting a key-mode link that `b` dials over TLS,
# each with a fresh database and its own key and certificate.
#
#   link-run.sh NAME SCENARIO.toml [SYNC]
#
# The scenario's ports must be a's 15500 and 15700 in [target] and b's
# 16500 and 16700 in [[target.linked]]; `log = "@LOG@"` and
# `log = "@LOG_B@"` name their logs. Both servers share SERVER_CPUS.
# Environment as for run.sh, less ACCOUNTS and AFTER.
set -u
NAME=$1 SCEN=$2 SYNC=${3:-normal}
BIN=${BIN:-target/release} OUT=${OUT:-out} WORK=${WORK:-work}
half() {
    lscpu -p=CPU,CORE | grep -v '^#' |
        awk -F, -v upper="$1" '{ c[NR] = $1; k[NR] = $2; if ($2 > m) m = $2 }
            END { for (i = 1; i <= NR; i++) if ((k[i] > m / 2) == upper) { printf "%s%s", s, c[i]; s = "," } }'
}
SERVER_CPUS=${SERVER_CPUS:-$(half 0)}
HARNESS_CPUS=${HARNESS_CPUS:-$(half 1)}
D=$WORK/$NAME
mkdir -p "$OUT" && rm -rf "$D" && mkdir -p "$D/a" "$D/b" && D=$(cd "$D" && pwd)

# A key from a fresh seed: the seed in the hex file `hxd` reads, and the
# public half, base64url, as a peer names it.
key() {
    local seed
    seed=$(openssl rand -hex 32)
    echo "$seed" > "$1/link.key"
    perl -e 'print pack "H*", shift' "302e020100300506032b657004220420$seed" |
        openssl pkey -inform DER -pubout -outform DER | tail -c 32 |
        base64 | tr '+/' '-_' | tr -d '='
}
KEY_A=$(key "$D/a") KEY_B=$(key "$D/b")

server() { # dir port-base tag peer
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=localhost -keyout "$1/key.pem" -out "$1/cert.pem" 2> /dev/null
    cat > "$1/hxd-ng.toml" <<CFG
[server]
bind = "127.0.0.1:${2}500"
[paths]
accounts = "$1/accounts"
[ng]
bind = "127.0.0.1:${2}700"
max_detached_per_addr = 1024
[limits]
chat_lines = 0
spam_points = 0
ng_requests = 0
news_posts = 0
reconnect_seconds = 0
[inbox]
db = "$1/server.db"
sync = "$SYNC"
[history]
[news]
[metrics]
[tls]
bind = "127.0.0.1:${2}600"
cert = "$1/cert.pem"
key = "$1/key.pem"
[link]
tag = "$3"
key = "$1/link.key"
$4
CFG
    taskset -c "$SERVER_CPUS" "$BIN/hxd" --config "$1/hxd-ng.toml" > "$1/hxd.log" 2>&1 &
}

ulimit -n "$(ulimit -Hn)"
server "$D/a" 15 aa "[[link.peer]]
name = \"bb\"
accept = true
protection = \"key\"
key = \"$KEY_B\"
account = \"link-bb\"
features = [\"chat\", \"msgs\", \"info\"]"
PID_A=$!
server "$D/b" 16 bb "[[link.peer]]
name = \"aa\"
dial = \"127.0.0.1:15600\"
protection = \"key\"
key = \"$KEY_A\"
account = \"link-bb\"
features = [\"chat\", \"msgs\", \"info\"]"
PID_B=$!
# Whatever ends the script, neither server outlives it to hold the ports
# the next run binds.
trap 'kill "$PID_A" "$PID_B" 2> /dev/null' EXIT
linked() {
    for port in 15700 16700; do
        curl -s "127.0.0.1:$port/metrics" | grep -q '^hxd_links_up [1-9]' || return 1
    done
}
for _ in $(seq 100); do linked && break; sleep 0.1; done
if ! linked; then
    echo "the servers never linked" >&2
    tail -n 5 "$D/a/hxd.log" "$D/b/hxd.log" >&2
    kill "$PID_A" "$PID_B" 2> /dev/null
    exit 2
fi

cpu() { awk '{ print $14 + $15 }' "/proc/$1/stat"; }
before_a=$(cpu "$PID_A") before_b=$(cpu "$PID_B")
sed "s#@LOG@#$D/a/hxd.log#; s#@LOG_B@#$D/b/hxd.log#" "$SCEN" > "$D/scenario.toml"
TIMEFORMAT="harness_cpu_s=%U+%S"
{ time taskset -c "$HARNESS_CPUS" "$BIN/hxd-load" run "$D/scenario.toml" \
    --out "$OUT/$NAME.json" 2> "$OUT/$NAME.txt"; } 2> "$D/time"
status=$?
{
    echo "exit=$status"
    for s in a b; do
        pid=PID_${s^^} before=before_$s
        echo "$s: server_cpu_s=$(( ($(cpu "${!pid}") - ${!before}) / $(getconf CLK_TCK) ))" \
            "peak_rss_mb=$(( $(awk '/VmHWM/ { print $2 }' "/proc/${!pid}/status") / 1024 ))"
    done
    cat "$D/time"
} >> "$OUT/$NAME.txt"
kill "$PID_A" "$PID_B"
wait 2> /dev/null
for s in a b; do
    echo "$s: server_errors=$(grep -cE ' ERROR |panicked' "$D/$s/hxd.log")" >> "$OUT/$NAME.txt"
done
rm -rf "$D"
cat "$OUT/$NAME.txt"
exit "$status"
