#!/bin/bash
# One run across linked servers (docs/load-testing.md §8): run.sh's
# server once for [target] and once for each [[target.linked]], `a`
# accepting key-mode links that each of the others (`b`, `c`, ... up to
# `q`) dials over TLS, each with a fresh database and its own key and
# certificate.
#
#   link-run.sh NAME SCENARIO.toml [SYNC]
#
# The scenario's ports must be a's 15500 and 15700 in [target], and the
# k-th [[target.linked]]'s (15 + k)500 and (15 + k)700: b's 16500 and
# 16700, c's 17500 and 17700, and so on; `log = "@LOG@"`, `"@LOG_B@"`,
# `"@LOG_C@"` ... name their logs. The servers share SERVER_CPUS. With
# [target.proxy], b dials the proxy the run starts (listen
# 127.0.0.1:15601, upstream a's 15600) and the run waits for the link;
# the rest always dial a directly. Every server takes [interruption]
# grace as its [link] grace.
# Environment as for run.sh, less AFTER; ACCOUNTS writes the same
# accounts on every server, a ban across a link being placed on one.
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
N=$(grep -c '^\[\[target.linked\]\]' "$SCEN")
if [ "$N" -lt 1 ] || [ "$N" -gt 16 ]; then
    echo "$SCEN names $N linked servers; this runs 1 to 16" >&2
    exit 2
fi
LEAVES=$(echo b c d e f g h i j k l m n o p q | cut -d' ' -f1-"$N")
SERVERS="a $LEAVES"
mkdir -p "$OUT" && rm -rf "$D" && for s in $SERVERS; do mkdir -p "$D/$s"; done && D=$(cd "$D" && pwd)

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
declare -A KEY PID BASE
k=15
for s in $SERVERS; do
    KEY[$s]=$(key "$D/$s") BASE[$s]=$k
    k=$((k + 1))
done
KEY_A=${KEY[a]}
DIAL=127.0.0.1:15600
grep -q '^\[target.proxy\]' "$SCEN" && DIAL=127.0.0.1:15601
GRACE=$(awk -F= '
    /^[[:space:]]*\[/ { s = ($0 ~ /^[[:space:]]*\[interruption\][[:space:]]*(#.*)?$/) }
    s { k = $1; gsub(/[[:space:]]/, "", k) }
    s && k == "grace" { v = $2; sub(/#.*/, "", v); gsub(/[[:space:]]/, "", v); print v }' "$SCEN")

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
grace = ${GRACE:-60}
$4
CFG
    taskset -c "$SERVER_CPUS" "$BIN/hxd" --config "$1/hxd-ng.toml" > "$1/hxd.log" 2>&1 &
}

accept() { # tag key
    printf '[[link.peer]]\nname = "%s"\naccept = true\nprotection = "key"\nkey = "%s"\n' "$1" "$2"
    printf 'account = "link-%s"\nfeatures = ["chat", "msgs", "info"]\n' "$1"
}
dial() { # tag address
    printf '[[link.peer]]\nname = "aa"\ndial = "%s"\nprotection = "key"\nkey = "%s"\n' "$2" "$KEY_A"
    printf 'account = "link-%s"\nfeatures = ["chat", "msgs", "info"]\n' "$1"
}

ulimit -n "$(ulimit -Hn)"
PEERS_A=
for s in $LEAVES; do
    PEERS_A="$PEERS_A
$(accept "$s$s" "${KEY[$s]}")"
done
server "$D/a" 15 aa "$PEERS_A"
PID[a]=$!
for s in $LEAVES; do
    to=127.0.0.1:15600
    [ "$s" = b ] && to=$DIAL
    server "$D/$s" "${BASE[$s]}" "$s$s" "$(dial "$s$s" "$to")"
    PID[$s]=$!
done
# Whatever ends the script, no server outlives it to hold the ports the
# next run binds.
trap 'kill ${PID[*]} 2> /dev/null' EXIT
# Up: every server answers, and, dialing a directly, has its link.
# Through the proxy the link comes up only once the run starts it, and a
# wait for it here would only push b's dialer further into its backoff.
up() {
    for s in $SERVERS; do
        curl -s "127.0.0.1:${BASE[$s]}700/metrics" |
            grep -q "${1:-}" || return 1
    done
}
want='^hxd_links_up [1-9]'
[ "$DIAL" = 127.0.0.1:15600 ] || want=
for _ in $(seq 100); do up "$want" && break; sleep 0.1; done
if ! up "$want"; then
    echo "the servers never came up${want:+ linked}" >&2
    tail -n 5 "$D"/*/hxd.log >&2
    exit 2
fi

if [ -n "${ACCOUNTS:-}" ]; then
    for s in $SERVERS; do
        "$BIN/hxd-load" accounts "$D/$s/accounts" --prefix churn --count "$ACCOUNTS" \
            --password pw --admin mod > /dev/null
    done
fi

cpu() { awk '{ print $14 + $15 }' "/proc/$1/stat"; }
declare -A BEFORE
LOGS="s#@LOG@#$D/a/hxd.log#"
for s in $SERVERS; do
    BEFORE[$s]=$(cpu "${PID[$s]}")
    LOGS="$LOGS; s#@LOG_${s^^}@#$D/$s/hxd.log#"
done
sed "$LOGS" "$SCEN" > "$D/scenario.toml"
TIMEFORMAT="harness_cpu_s=%U+%S"
{ time taskset -c "$HARNESS_CPUS" "$BIN/hxd-load" run "$D/scenario.toml" \
    --out "$OUT/$NAME.json" 2> "$OUT/$NAME.txt"; } 2> "$D/time"
status=$?
{
    echo "exit=$status"
    for s in $SERVERS; do
        echo "$s: server_cpu_s=$(( ($(cpu "${PID[$s]}") - ${BEFORE[$s]}) / $(getconf CLK_TCK) ))" \
            "peak_rss_mb=$(( $(awk '/VmHWM/ { print $2 }' "/proc/${PID[$s]}/status") / 1024 ))"
    done
    cat "$D/time"
} >> "$OUT/$NAME.txt"
kill ${PID[*]}
wait 2> /dev/null
for s in $SERVERS; do
    echo "$s: server_errors=$(grep -cE ' ERROR |panicked' "$D/$s/hxd.log")" >> "$OUT/$NAME.txt"
done
rm -rf "$D"
cat "$OUT/$NAME.txt"
exit "$status"
