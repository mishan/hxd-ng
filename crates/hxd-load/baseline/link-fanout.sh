#!/bin/bash
# L-8 (docs/load-testing.md §8.3): one hub and K leaves, K doubling, the
# room's talkers on the hub and its readers spread over every server, so
# each line the hub hears goes out to all K links. Each K is a run of
# link-run.sh of its own; its summary goes to $OUT/fanout-K.txt.
#
#   KS="1 2 4 8 16" RATE=200 READERS=20 link-fanout.sh
#
# Environment as for link-run.sh, and KS (up to 16 leaves), RATE (lines
# a second), READERS (per wire) and DURATION (seconds).
set -u
here=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-work} OUT=${OUT:-out}
mkdir -p "$WORK" "$OUT"
export WORK OUT
for k in ${KS:-1 2 4 8 16}; do
    scen="$WORK/fanout-$k.toml"
    {
        printf '[target]\nlegacy = "127.0.0.1:15500"\nng = "127.0.0.1:15700"\n'
        printf 'metrics = true\nlog = "@LOG@"\n'
        i=0
        for leaf in $(echo b c d e f g h i j k l m n o p q | cut -d' ' -f1-"$k"); do
            base=$((16 + i))
            printf '\n[[target.linked]]\nname = "%s"\nlegacy = "127.0.0.1:%s500"\n' "$leaf" "$base"
            printf 'ng = "127.0.0.1:%s700"\nmetrics = true\nlog = "@LOG_%s@"\n' "$base" "${leaf^^}"
            i=$((i + 1))
        done
        printf '\n[run]\nscenario = "chat"\nduration = %s\nsettle = 10\n' "${DURATION:-30}"
        printf '\n[chat]\nreaders_legacy = %s\nreaders_ng = %s\n' "${READERS:-20}" "${READERS:-20}"
        printf 'talkers_legacy = 5\ntalkers_ng = 5\ntalkers_at_target = true\n'
        printf 'rate = %s\nline_bytes = 64\n' "${RATE:-200}"
    } > "$scen"
    # A run whose servers never came up writes no summary: never report
    # an earlier run's in its place.
    rm -f "$OUT/fanout-$k.txt"
    "$here/link-run.sh" "fanout-$k" "$scen" > /dev/null
    echo "K=$k: $(grep -E 'every check|violations|^exit=' "$OUT/fanout-$k.txt" 2> /dev/null |
        tr '\n' ' ')"
    grep -E 'chat.delivery(.cross)? |^a: server_cpu' "$OUT/fanout-$k.txt" 2> /dev/null
done
