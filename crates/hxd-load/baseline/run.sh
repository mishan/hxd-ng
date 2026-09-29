#!/bin/bash
# One baseline run (docs/load-testing.md §7): a fresh server and
# database, the server and the harness pinned to separate cores, and the
# server's CPU time and peak memory read from /proc around the run.
#
#   run.sh NAME SCENARIO.toml [SYNC]
#
# SYNC is the databases' `sync` ("normal" by default). The report is
# written to $OUT/NAME.json and the summary to $OUT/NAME.txt. The
# scenario's ports must be 15500 and 15700, and `log = "@LOG@"` names
# the server's log. Environment:
#
#   BIN            where hxd (built with --features metrics) and hxd-load are
#   OUT            where the results go (./out)
#   WORK           where each run's server lives while it runs (./work)
#   SERVER_CPUS    taskset list for the server (half the physical cores)
#   HARNESS_CPUS   taskset list for the harness (the other half)
#   ACCOUNTS       how many churn accounts to write first, for a scenario
#                  that logs in to them (password "pw", admin "mod")
#   AFTER          scrape the server's session and memory gauges this many
#                  times, ten seconds apart, once the run is over
set -u
NAME=$1 SCEN=$2 SYNC=${3:-normal}
BIN=${BIN:-target/release} OUT=${OUT:-out} WORK=${WORK:-work}
# Split by physical core, so neither side runs on the other's SMT siblings.
half() {
    lscpu -p=CPU,CORE | grep -v '^#' |
        awk -F, -v upper="$1" '{ c[NR] = $1; k[NR] = $2; if ($2 > m) m = $2 }
            END { for (i = 1; i <= NR; i++) if ((k[i] > m / 2) == upper) { printf "%s%s", s, c[i]; s = "," } }'
}
SERVER_CPUS=${SERVER_CPUS:-$(half 0)}
HARNESS_CPUS=${HARNESS_CPUS:-$(half 1)}
D=$WORK/$NAME
mkdir -p "$OUT" && rm -rf "$D" && mkdir -p "$D" && D=$(cd "$D" && pwd)
cat > "$D/hxd-ng.toml" <<CFG
[server]
bind = "127.0.0.1:15500"
[paths]
accounts = "$D/accounts"
[ng]
bind = "127.0.0.1:15700"
max_detached_per_addr = 1024
[limits]
chat_lines = 0
spam_points = 0
[inbox]
db = "$D/server.db"
sync = "$SYNC"
[history]
[news]
[metrics]
CFG
ulimit -n "$(ulimit -Hn)"
taskset -c "$SERVER_CPUS" "$BIN/hxd" --config "$D/hxd-ng.toml" > "$D/hxd.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -sf -o /dev/null 127.0.0.1:15700/metrics && break; sleep 0.1; done
if [ -n "${ACCOUNTS:-}" ]; then
    "$BIN/hxd-load" accounts "$D/accounts" --prefix churn --count "$ACCOUNTS" \
        --password pw --admin mod > /dev/null
fi
cpu() { awk '{ print $14 + $15 }' "/proc/$PID/stat"; }
before=$(cpu)
sed "s#@LOG@#$D/hxd.log#" "$SCEN" > "$D/scenario.toml"
TIMEFORMAT="harness_cpu_s=%U+%S"
{ time taskset -c "$HARNESS_CPUS" "$BIN/hxd-load" run "$D/scenario.toml" \
    --out "$OUT/$NAME.json" 2> "$OUT/$NAME.txt"; } 2> "$D/time"
status=$?
{
    echo "exit=$status server_cpu_s=$(( ($(cpu) - before) / $(getconf CLK_TCK) ))" \
        "peak_rss_mb=$(( $(awk '/VmHWM/ { print $2 }' "/proc/$PID/status") / 1024 ))"
    cat "$D/time"
    for i in $(seq "${AFTER:-0}"); do
        sleep 10
        echo "after $((i * 10))s: $(curl -s 127.0.0.1:15700/metrics |
            grep -E '^hxd_sessions\{|^hxd_process_resident_bytes' | tr '\n' ' ')"
    done
} >> "$OUT/$NAME.txt"
kill "$PID"
wait "$PID" 2> /dev/null
echo "server_errors=$(grep -cE ' ERROR |panicked' "$D/hxd.log")" >> "$OUT/$NAME.txt"
rm -rf "$D"
cat "$OUT/$NAME.txt"
exit "$status"
