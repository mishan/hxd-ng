#!/bin/bash
# The baseline (docs/load-testing.md §7): every scenario, public chat at
# rising rates and in two room sizes, and chat again with every commit
# fsynced. Takes about half an hour. Environment as for run.sh.
set -u
here=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-work}
mkdir -p "$WORK"
export WORK
target='[target]
legacy = "127.0.0.1:15500"
ng = "127.0.0.1:15700"
metrics = true
log = "@LOG@"'

chat() { # rate room
    cat > "$WORK/chat-$1-$2.toml" <<S
$target
[run]
scenario = "chat"
duration = 30
settle = 10
[chat]
readers_legacy = $(($2 / 2))
readers_ng = $(($2 / 2))
talkers_legacy = 5
talkers_ng = 5
rate = $1
S
    echo "$WORK/chat-$1-$2.toml"
}

cat > "$WORK/slow.toml" <<S
$target
[run]
scenario = "slow_consumer"
duration = 60
[chat]
readers_legacy = 20
readers_ng = 20
talkers_legacy = 2
talkers_ng = 2
rate = 1000
line_bytes = 3000
[slow_consumer]
stalled_legacy = 2
stalled_ng = 2
S
cat > "$WORK/churn.toml" <<S
$target
accounts = { prefix = "churn", count = 200, password = "pw" }
admin = { login = "mod", password = "pw" }
[run]
scenario = "churn"
duration = 60
[churn]
ng = 200
legacy = 200
cycle = 0.5
away = 0.2
chat_rate = 50
kick_every = 1.0
S
storm() { # name rate step accounts
    cat > "$WORK/$1.toml" <<S
$target
accounts = { prefix = "churn", count = 200, password = "pw" }
[run]
scenario = "login_storm"
duration = 60
[login_storm]
accounts = $4
rate = $2
ramp_step = $3
ramp_every = 5
linger = 1.0
max_in_flight = 20000
S
}
storm storm-guest 100 50 false
storm storm-password 100 50 true

for room in 200 1000; do
    for rate in 50 100 200 500 1000 2000 4000; do
        [ "$room" = 1000 ] && [ "$rate" -gt 500 ] && continue
        "$here/run.sh" "chat-$rate-$room" "$(chat $rate $room)"
    done
done
for rate in 50 100 200; do
    "$here/run.sh" "chat-$rate-200-full" "$(chat $rate 200)" full
done
"$here/run.sh" slow "$WORK/slow.toml"
ACCOUNTS=200 "$here/run.sh" churn "$WORK/churn.toml"
AFTER=3 "$here/run.sh" storm-guest "$WORK/storm-guest.toml"
ACCOUNTS=200 AFTER=3 "$here/run.sh" storm-password "$WORK/storm-password.toml"
