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
#
# HUB_HOST runs `a` on another host instead, over ssh, with that host to
# itself: the leaves sharing this one's cores with the hub is the very
# thing a measurement of the hub must not have. HUB_ADDR is where the
# leaves and the harness reach it (HUB_HOST's address by default); the
# scenario still names a as 127.0.0.1, and the run points it there. Its
# binaries and its run go in `hxd-link-run` in that host's home.
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
HUB_HOST=${HUB_HOST:-}
A=127.0.0.1 HERE=127.0.0.1
if [ -n "$HUB_HOST" ]; then
    # IPv4: the address goes into `host:port` as it is.
    HUB_ADDR=${HUB_ADDR:-$(getent ahostsv4 "$HUB_HOST" | awk '{ print $1; exit }')}
    A=$HUB_ADDR
    # The address the hub sees this host's connections come from: let
    # through its per-address limits, and allowed to scrape.
    HERE=$(ip route get "$A" | sed -n 's/.* src \([^ ]*\).*/\1/p')
    if [ -z "$A" ] || [ -z "$HERE" ]; then
        echo "no route to $HUB_HOST; set HUB_ADDR" >&2
        exit 2
    fi
    RHOME=$(ssh -n "$HUB_HOST" pwd) || exit 2
    RD=$RHOME/hxd-link-run/$NAME RBIN=$RHOME/hxd-link-run/bin
    if grep -q '^\[target.proxy\]' "$SCEN"; then
        echo "HUB_HOST and [target.proxy] together are not supported" >&2
        exit 2
    fi
fi
DIAL=$A:15600
grep -q '^\[target.proxy\]' "$SCEN" && DIAL=127.0.0.1:15601
GRACE=$(awk -F= '
    /^[[:space:]]*\[/ { s = ($0 ~ /^[[:space:]]*\[interruption\][[:space:]]*(#.*)?$/) }
    s { k = $1; gsub(/[[:space:]]/, "", k) }
    s && k == "grace" { v = $2; sub(/#.*/, "", v); gsub(/[[:space:]]/, "", v); print v }' "$SCEN")

config() { # dir port-base tag peer [bind] [dir-as-the-server-sees-it]
    local bind=${5:-127.0.0.1} at=${6:-$1}
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=localhost -keyout "$1/key.pem" -out "$1/cert.pem" 2> /dev/null
    cat > "$1/hxd-ng.toml" <<CFG
[server]
bind = "$bind:${2}500"
[paths]
accounts = "$at/accounts"
[ng]
bind = "$bind:${2}700"
max_detached_per_addr = 1024
[limits]
exempt = ["127.0.0.0/8", "::1", "$HERE"]
chat_lines = 0
spam_points = 0
ng_requests = 0
news_posts = 0
reconnect_seconds = 0
[inbox]
db = "$at/server.db"
sync = "$SYNC"
[history]
[news]
[metrics]
allow = ["127.0.0.0/8", "::1", "$HERE"]
[tls]
bind = "$bind:${2}600"
cert = "$at/cert.pem"
key = "$at/key.pem"
[link]
tag = "$3"
key = "$at/link.key"
grace = ${GRACE:-60}
$4
CFG
}
server() { # as config, and started here
    config "$@"
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
# On the far host, the hub's pid is the one that host gave it, and
# everything about it is asked over ssh.
remote() { ssh -n "$HUB_HOST" "$@"; }
hub() { [ "$1" = a ] && [ -n "$HUB_HOST" ]; }
if [ -n "$HUB_HOST" ]; then
    config "$D/a" 15 aa "$PEERS_A" 0.0.0.0 "$RD"
    remote "mkdir -p $RBIN && rm -rf $RD" || exit 2
    for b in hxd hxd-load; do
        [ "$(remote "sha256sum < $RBIN/$b" 2> /dev/null)" = "$(sha256sum < "$BIN/$b")" ] ||
            scp -q "$BIN/$b" "$HUB_HOST:$RBIN/$b" || exit 2
    done
    scp -qr "$D/a" "$HUB_HOST:$RD" || exit 2
    # Only the server in the background, not a list around it, whose
    # shell would hold ssh's output open for as long as it ran.
    PID[a]=$(remote "ulimit -n \$(ulimit -Hn); cd $RD || exit; \
        nohup $RBIN/hxd --config $RD/hxd-ng.toml > $RD/hxd.log 2>&1 < /dev/null & echo \$!")
else
    server "$D/a" 15 aa "$PEERS_A"
    PID[a]=$!
fi
for s in $LEAVES; do
    to=$A:15600
    [ "$s" = b ] && to=$DIAL
    server "$D/$s" "${BASE[$s]}" "$s$s" "$(dial "$s$s" "$to")"
    PID[$s]=$!
done
# Whatever ends the script, no server outlives it to hold the ports the
# next run binds.
# The hub on its own host is waited for there, so that its log is whole
# when its errors are counted.
kill_all() {
    for s in $SERVERS; do
        if hub "$s"; then
            remote "kill ${PID[a]} && for _ in \$(seq 100); do
                kill -0 ${PID[a]} || break; sleep 0.1; done" 2> /dev/null
        else
            kill "${PID[$s]}" 2> /dev/null
        fi
    done
}
trap kill_all EXIT
# Up: every server answers, and, dialing a directly, has its link.
# Through the proxy the link comes up only once the run starts it, and a
# wait for it here would only push b's dialer further into its backoff.
up() {
    for s in $SERVERS; do
        host=127.0.0.1
        [ "$s" = a ] && host=$A
        curl -s "$host:${BASE[$s]}700/metrics" |
            grep -q "${1:-}" || return 1
    done
}
want='^hxd_links_up [1-9]'
[ "$DIAL" = "$A:15600" ] || want=
for _ in $(seq 100); do up "$want" && break; sleep 0.1; done
if ! up "$want"; then
    echo "the servers never came up${want:+ linked}" >&2
    tail -n 5 "$D"/*/hxd.log >&2
    [ -n "$HUB_HOST" ] && remote "tail -n 5 $RD/hxd.log" >&2
    exit 2
fi

if [ -n "${ACCOUNTS:-}" ]; then
    for s in $LEAVES; do
        "$BIN/hxd-load" accounts "$D/$s/accounts" --prefix churn --count "$ACCOUNTS" \
            --password pw --admin mod > /dev/null
    done
    if [ -n "$HUB_HOST" ]; then
        remote "$RBIN/hxd-load accounts $RD/accounts --prefix churn --count $ACCOUNTS \
            --password pw --admin mod > /dev/null"
    else
        "$BIN/hxd-load" accounts "$D/a/accounts" --prefix churn --count "$ACCOUNTS" \
            --password pw --admin mod > /dev/null
    fi
fi

cpu() {
    if hub "$1"; then
        remote "awk '{ print \$14 + \$15 }' /proc/${PID[a]}/stat"
    else
        awk '{ print $14 + $15 }' "/proc/${PID[$1]}/stat"
    fi
}
rss() {
    if hub "$1"; then
        remote "awk '/VmHWM/ { print \$2 }' /proc/${PID[a]}/status"
    else
        awk '/VmHWM/ { print $2 }' "/proc/${PID[$1]}/status"
    fi
}
declare -A BEFORE
LOGS="s#@LOG@#$D/a/hxd.log#"
for s in $SERVERS; do
    BEFORE[$s]=$(cpu "$s")
    LOGS="$LOGS; s#@LOG_${s^^}@#$D/$s/hxd.log#"
done
# The hub's log is on its own host, where the harness cannot tail it;
# its errors are still counted below.
[ -n "$HUB_HOST" ] && LOGS="/@LOG@/d; s#127.0.0.1:15\([57]\)00#$A:15\100#g; $LOGS"
sed "$LOGS" "$SCEN" > "$D/scenario.toml"
TIMEFORMAT="harness_cpu_s=%U+%S"
{ time taskset -c "$HARNESS_CPUS" "$BIN/hxd-load" run "$D/scenario.toml" \
    --out "$OUT/$NAME.json" 2> "$OUT/$NAME.txt"; } 2> "$D/time"
status=$?
{
    echo "exit=$status"
    for s in $SERVERS; do
        echo "$s: server_cpu_s=$(( ($(cpu "$s") - ${BEFORE[$s]}) / $(getconf CLK_TCK) ))" \
            "peak_rss_mb=$(( $(rss "$s") / 1024 ))"
    done
    cat "$D/time"
} >> "$OUT/$NAME.txt"
kill_all
wait 2> /dev/null
for s in $SERVERS; do
    if hub "$s"; then
        errors=$(remote "grep -cE ' ERROR |panicked' $RD/hxd.log")
    else
        errors=$(grep -cE ' ERROR |panicked' "$D/$s/hxd.log")
    fi
    echo "$s: server_errors=$errors" >> "$OUT/$NAME.txt"
done
rm -rf "$D"
[ -n "$HUB_HOST" ] && remote "rm -rf $RD"
cat "$OUT/$NAME.txt"
exit "$status"
