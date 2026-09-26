# Load testing

Status: built. `hxd-load` with the login storm, public chat, slow
consumer and churn scenarios, and the invariant checks; the
`hxd-testclient` crate it drives both wires with. The other scenarios,
and a CI smoke run, are next.

The point of loading this server is to find what only breaks under
load, and where it slows down first; throughput numbers are a side
effect. So every scenario checks the server's invariants while it runs
as well as timing it, and any violation fails the run. A fast server
that delivers a line twice is not a fast server.

## 1. Running one

```sh
cargo build --release -p hxd --features metrics -p hxd-load
target/release/hxd --config hxd-ng.toml 2> hxd.log &
target/release/hxd-load run crates/hxd-load/scenarios/chat.toml --out chat.json
```

The summary goes to stderr; the report, as JSON, to `--out` or stdout.
The exit status is 0 when every check held, 1 when one did not, and 2
when the run could not start.

The server should be dedicated to the run and built with `metrics` (see
`docs/metrics.md`) with a `[metrics]` section that lets the harness's
host scrape: the run reads the server's own numbers before, during and
after, and its check for sessions left behind compares the server's
count with the one it started with. Without metrics the harness still
runs and still checks everything it can see from the clients' side.

For the baseline, put the server and the harness on separate cores
(`taskset`), raise `ulimit -n` for both, and record the storage the
database is on: the rate public chat can be persisted at is the disk's
fsync rate (`docs/metrics.md`, the `LogSerial` lock).

## 2. The scenario file

TOML, every key optional; `crates/hxd-load/scenarios/` holds one of
each to start from, and a test keeps them valid. The report carries the
whole scenario with its defaults filled in, so a run can be repeated
from its own output.

- `[target]`: the classic port, the classic TLS port and its name, the
  ng port, `metrics`, the server's `log`, the `accounts` and the `admin`
  account the churn uses.
- `[run]`: `scenario`, `duration` in seconds, `seed` for every random
  choice, `settle` (how long readers may take to hear the last line;
  five seconds by default), `teardown` (how long the server has to
  empty its roster), and the nick `prefix`.

`settle` is where open-loop measurement stops: a line not heard within
it counts as not heard at all, and its latency is missing from the
report. A server slower than `settle` therefore shows as one that loses
lines (`chat.all_heard`), and a run that expects one should raise it.

Every time is checked before the run starts; one that would divide by
zero, spin, or make no sense is refused, as is a scenario that needs a
port or an account the target does not name.
- One section per scenario, below.

Every nick and chat line carries a tag unique to the run, so the checks
tell this run's users from anyone else on the server.

## 3. The scenarios

Load is **open-loop**: arrivals and lines are scheduled in advance and
latency is measured from when each was *due*, so a server that stalls
shows up as latency rather than as a generator that quietly sent less.
Latencies are HDR histograms, reported as p50, p90, p99, p99.9 and max.

### Login storm (`login_storm`)

Arrivals at `rate` a second, rising by `ramp_step` every `ramp_every`
seconds, each on a wire picked by weight (`legacy`, `legacy_tls`,
`ng`). An arrival connects, logs in (as a guest, or to `[target]
accounts` with `accounts = true`), agrees to the agreement and fetches
the user list; it stays `linger` seconds and leaves. Each step is
reported on its own, and the knee is the first step whose p99 is twice
the first step's or whose failures pass one in a hundred.
`max_in_flight` caps what the generator attempts at once; an arrival
past it is counted as shed, which is the generator's limit and not the
server's.

### Public chat (`chat`)

`readers_*` and `talkers_*` on each wire, joined before the first line
and staying until the last is heard. The talkers together send `rate`
lines a second, evenly staggered. Each line is tagged with its sender,
the sender's count and when it was due, so every reader accounts for
every line: heard once, in order, all of them. `chat.delivery` is due
to heard, for every reader; `chat.echo` is due to heard for the sender
itself.

### Slow consumer (`slow_consumer`)

The chat room, plus `stalled_*` clients that log in and then never read
again. With metrics it samples the server's resident memory and the
classic writers' queue every `sample_every` seconds; afterwards it
reads from each stalled client to see whether the server hung up on
it. Passing means every stalled client was disconnected and the queue
never held more than `max_queued_bytes`, while the room is held to
everything the chat scenario holds it to.

### Churn (`churn`)

- `ng` account sessions that read for a while (mean `cycle` seconds),
  drop their connection, stay away (mean `away`), and resume; a
  session that was kicked logs in again. A session is given up only
  when it is over — kicked, or expired on the server's word. A lost
  connection or a resume that failed goes back through `resume`, a few
  times, rather than a fresh login that would leave the old session
  detached on the roster and blame the server for the ghost. At the
  end every session logs out, resuming first if its connection is
  gone.
- `legacy` guests that come and go in four ways: gone after the magic,
  gone with a login sent and unanswered, logged in and leaving
  cleanly, logged in and vanishing.
- Two talkers keep `chat_rate` lines a second flowing, so a resume
  always has something to replay.
- With `[target] admin`, a moderator kicks someone every `kick_every`
  seconds on average, attached or detached.

The accounts come from `hxd-load accounts <dir> --prefix P --count N
--password W --admin LOGIN`, run against the server's accounts
directory; it never overwrites a file. The server must let every
churner detach from the harness's one address (`[ng]
max_detached_per_addr` of at least `[churn] ng`), and `away` must stay
well under its `[ng] grace`, or it is right to end sessions the run
expects to find.

A churner drops its connection only after a `ping` has come back, so it
has read everything sent before it. The protocol still allows a resync
whenever an event went out on the lost connection unread
(`docs/hotline-ng.md` §6.2), and nothing a client sees says which
events those were, so resumes are counted by outcome,
`churn.resume.replayed` and `churn.resume.resync`, rather than held to
a rule the protocol does not make.

## 4. The checks

| Check | What must hold |
|---|---|
| `chat.in_order_once` | A reader hears each sender's lines one after another: never one twice, never one out of order, never one skipped. |
| `chat.all_heard` | By the end, every reader has heard every line every talker sent. |
| `chat.stayed` | Nobody in the room lost their connection or was kicked. |
| `ng.seq_gapless` | Every ng session's seqs went up by one, across every resume. |
| `churn.connection_kept` | An attached ng connection was lost only after a kick. |
| `churn.ended_only_by_kick` | Only a session that was kicked is told it was. |
| `churn.session_kept` | A detached session was still there when it came back, unless it was kicked. |
| `churn.seq_never_back` | A resync never took a session's seq backwards. |
| `roster.agrees` | Once things are quiet, every client's user list shows exactly the run's clients still present. |
| `roster.no_ghosts` | After everyone has left, a fresh client's list shows none of them. The observer has a nick of its own, as does the churn's moderator, so neither hides a client's ghost. |
| `roster.sessions_return` | With metrics, the server's own session count returns to where it was. |
| `server.log_clean` | With `log`, the server wrote no panic and no `ERROR` line during the run (terminal colors stripped). |
| `server.reachable` | With metrics, the server still answers once the run is over. A run whose server died still writes its report. |
| `slow.disconnected`, `slow.bounded` | The slow consumer's verdicts, above. Its roster check takes the stalled clients as listed or not, since a server that does the right thing has dropped them. |

## 5. Its own tests

`crates/hxd-load/tests/scenarios.rs` runs each scenario for a few
seconds against a real server in the test's process, built from a
config file as `hxd` builds one, on every `cargo test`. They hold the
harness to its checks on a healthy server, and they are small load runs
of the server in their own right.

The one thing they do not assert is the slow consumer's verdict. On
this server, as of this writing, neither wire disconnects a client that
has stopped reading within a short run, and the classic wire queues for
it without limit: `slow.disconnected` and `slow.bounded` are violated.
That is the finding the scenario exists to make, and it is fixed in the
server, not in the test.

## 6. The clients

`hxd-testclient` is a pair of scripted clients, one per wire, that
`hxd-load` drives and that the e2e suites can share. The classic one
frames with the pinned `hxproto` rather than with the server's framer,
so a framing bug on either side shows up as a disagreement rather than
cancelling out, and reads through a buffer so that a timeout cannot cut
a frame in half. The ng one checks every event's seq as it arrives.
Both keep whatever arrives while they wait for something else, so
nothing a caller has not looked at is ever dropped.
