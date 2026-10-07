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
# HUB_HOST runs `a` on another host instead, over ssh, and LEAF_HOSTS
# the leaves, in turn (`-` for this host): servers sharing one host's
# cores and disk measure each other as much as themselves. Every server
# then listens beyond loopback and is reached at its host's IPv4
# address, every host's address let through every server's [limits] and
# allowed to scrape it; the scenario still names each as 127.0.0.1, and
# the run points it there. A server elsewhere has the whole of its host
# (no SERVER_CPUS), and its binaries and its run go in `hxd-link-run` in
# that host's home.
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
declare -A HOST ADDR RD RHOME
read -ra LEAF_HOSTS <<< "${LEAF_HOSTS:-}"
i=0
for s in $SERVERS; do
    if [ "$s" = a ]; then
        HOST[a]=${HUB_HOST:-}
    elif [ ${#LEAF_HOSTS[@]} -gt 0 ]; then
        HOST[$s]=${LEAF_HOSTS[i % ${#LEAF_HOSTS[@]}]}
        [ "${HOST[$s]}" = - ] && HOST[$s]=
        i=$((i + 1))
    else
        HOST[$s]=
    fi
done
REMOTES=$(for s in $SERVERS; do [ -n "${HOST[$s]}" ] && echo "${HOST[$s]}"; done | sort -u)
v4() { getent ahostsv4 "$1" | awk '{ print $1; exit }'; }
BIND=127.0.0.1 HERE=127.0.0.1 ALLOW=
if [ -n "$REMOTES" ]; then
    if grep -q '^\[target.proxy\]' "$SCEN"; then
        echo "servers on other hosts and [target.proxy] together are not supported" >&2
        exit 2
    fi
    # This host's address as the others see it, and theirs.
    HERE=$(ip route get "$(v4 "$(echo "$REMOTES" | head -1)")" 2> /dev/null |
        sed -n 's/.* src \([^ ]*\).*/\1/p')
    BIND=0.0.0.0 ALLOW=$HERE
    for h in $REMOTES; do
        addr=$(v4 "$h")
        if [ -z "$addr" ] || [ -z "$HERE" ]; then
            echo "no IPv4 route to $h" >&2
            exit 2
        fi
        ALLOW="$ALLOW $addr"
        RHOME[$h]=$(ssh -n "$h" pwd) || exit 2
    done
fi
for s in $SERVERS; do
    if [ -n "${HOST[$s]}" ]; then
        ADDR[$s]=$(v4 "${HOST[$s]}") RD[$s]=${RHOME[${HOST[$s]}]}/hxd-link-run/$NAME/$s
    else
        ADDR[$s]=$HERE
    fi
done
A=${ADDR[a]}
DIAL=$A:15600
grep -q '^\[target.proxy\]' "$SCEN" && DIAL=127.0.0.1:15601
GRACE=$(awk -F= '
    /^[[:space:]]*\[/ { s = ($0 ~ /^[[:space:]]*\[interruption\][[:space:]]*(#.*)?$/) }
    s { k = $1; gsub(/[[:space:]]/, "", k) }
    s && k == "grace" { v = $2; sub(/#.*/, "", v); gsub(/[[:space:]]/, "", v); print v }' "$SCEN")

# Let through, and allowed to scrape: loopback, and every host in the run.
LET=$(for x in $ALLOW; do printf ', "%s"' "$x"; done)
config() { # dir port-base tag peer [dir-as-the-server-sees-it]
    local at=${5:-$1}
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=localhost -keyout "$1/key.pem" -out "$1/cert.pem" 2> /dev/null
    cat > "$1/hxd-ng.toml" <<CFG
[server]
bind = "$BIND:${2}500"
[paths]
accounts = "$at/accounts"
[ng]
bind = "$BIND:${2}700"
max_detached_per_addr = 1024
[limits]
exempt = ["127.0.0.0/8", "::1"$LET]
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
allow = ["127.0.0.0/8", "::1"$LET]
[tls]
bind = "$BIND:${2}600"
cert = "$at/cert.pem"
key = "$at/key.pem"
[link]
tag = "$3"
key = "$at/link.key"
grace = ${GRACE:-60}
$4
CFG
}
# A server elsewhere has the pid its host gave it, and everything about
# it is asked over ssh.
remote() { # server command
    ssh -n "${HOST[$1]}" "$2"
}
server() { # server port-base tag peer
    local s=$1 h=${HOST[$1]}
    if [ -z "$h" ]; then
        config "$D/$s" "${@:2}"
        taskset -c "$SERVER_CPUS" "$BIN/hxd" --config "$D/$s/hxd-ng.toml" > "$D/$s/hxd.log" 2>&1 &
        PID[$s]=$!
        return
    fi
    local rd=${RD[$s]} rbin=${RHOME[$h]}/hxd-link-run/bin
    config "$D/$s" "${@:2}" "$rd"
    remote "$s" "rm -rf $rd && mkdir -p ${rd%/*}" || exit 2
    scp -qr "$D/$s" "$h:$rd" || exit 2
    # Only the server in the background, not a list around it, whose
    # shell would hold ssh's output open for as long as it ran.
    PID[$s]=$(remote "$s" "ulimit -n \$(ulimit -Hn); cd $rd || exit; \
        nohup $rbin/hxd --config $rd/hxd-ng.toml > $rd/hxd.log 2>&1 < /dev/null & echo \$!")
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
# Whatever ends the script, no server outlives it to hold the ports the
# next run binds.
# One elsewhere is waited for there, so that its log is whole when its
# errors are counted.
kill_all() {
    for s in $SERVERS; do
        [ -n "${PID[$s]:-}" ] || continue
        if [ -n "${HOST[$s]}" ]; then
            remote "$s" "kill ${PID[$s]} && for _ in \$(seq 100); do
                kill -0 ${PID[$s]} || break; sleep 0.1; done" 2> /dev/null
        else
            kill "${PID[$s]}" 2> /dev/null
        fi
    done
}
trap kill_all EXIT
for h in $REMOTES; do
    rbin=${RHOME[$h]}/hxd-link-run/bin
    ssh -n "$h" "mkdir -p $rbin" || exit 2
    for b in hxd hxd-load; do
        [ "$(ssh -n "$h" "sha256sum < $rbin/$b" 2> /dev/null)" = "$(sha256sum < "$BIN/$b")" ] ||
            scp -q "$BIN/$b" "$h:$rbin/$b" || exit 2
    done
done
server a 15 aa "$PEERS_A"
for s in $LEAVES; do
    to=$A:15600
    [ "$s" = b ] && to=$DIAL
    server "$s" "${BASE[$s]}" "$s$s" "$(dial "$s$s" "$to")"
done
# Up: every server answers, and, dialing a directly, has its link.
# Through the proxy the link comes up only once the run starts it, and a
# wait for it here would only push b's dialer further into its backoff.
up() {
    for s in $SERVERS; do
        curl -s "${ADDR[$s]}:${BASE[$s]}700/metrics" |
            grep -q "${1:-}" || return 1
    done
}
want='^hxd_links_up [1-9]'
[ "$DIAL" = "$A:15600" ] || want=
for _ in $(seq 100); do up "$want" && break; sleep 0.1; done
if ! up "$want"; then
    echo "the servers never came up${want:+ linked}" >&2
    for s in $SERVERS; do
        if [ -n "${HOST[$s]}" ]; then
            remote "$s" "tail -n 5 ${RD[$s]}/hxd.log" >&2
        else
            tail -n 5 "$D/$s/hxd.log" >&2
        fi
    done
    exit 2
fi

if [ -n "${ACCOUNTS:-}" ]; then
    for s in $SERVERS; do
        if [ -n "${HOST[$s]}" ]; then
            remote "$s" "${RHOME[${HOST[$s]}]}/hxd-link-run/bin/hxd-load accounts \
                ${RD[$s]}/accounts --prefix churn --count $ACCOUNTS \
                --password pw --admin mod > /dev/null"
        else
            "$BIN/hxd-load" accounts "$D/$s/accounts" --prefix churn --count "$ACCOUNTS" \
                --password pw --admin mod > /dev/null
        fi
    done
fi

cpu() {
    if [ -n "${HOST[$1]}" ]; then
        remote "$1" "awk '{ print \$14 + \$15 }' /proc/${PID[$1]}/stat"
    else
        awk '{ print $14 + $15 }' "/proc/${PID[$1]}/stat"
    fi
}
rss() {
    if [ -n "${HOST[$1]}" ]; then
        remote "$1" "awk '/VmHWM/ { print \$2 }' /proc/${PID[$1]}/status"
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
# A log elsewhere is out of the harness's reach; its errors are still
# counted below.
for s in $SERVERS; do
    [ -n "${HOST[$s]}" ] || continue
    tag=LOG_${s^^}
    [ "$s" = a ] && tag=LOG
    b=${BASE[$s]}
    LOGS="/@$tag@/d; s#127.0.0.1:$b\([57]\)00#${ADDR[$s]}:$b\100#g; $LOGS"
done
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
    if [ -n "${HOST[$s]}" ]; then
        errors=$(remote "$s" "grep -cE ' ERROR |panicked' ${RD[$s]}/hxd.log")
    else
        errors=$(grep -cE ' ERROR |panicked' "$D/$s/hxd.log")
    fi
    echo "$s: server_errors=$errors" >> "$OUT/$NAME.txt"
done
rm -rf "$D"
for s in $SERVERS; do
    [ -n "${HOST[$s]}" ] && remote "$s" "rm -rf ${RD[$s]%/*}"
done
cat "$OUT/$NAME.txt"
exit "$status"
