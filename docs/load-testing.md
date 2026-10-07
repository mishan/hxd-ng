# Load testing

Status: built. `hxd-load` with the login storm, public chat, slow
consumer and churn scenarios, and the invariant checks; the
`hxd-testclient` crate it drives both wires with; and the baseline, a
script that runs them all the same way every time (§7). The other
scenarios, and a CI smoke run, are next. Server links (§8): the metrics,
several servers in a run, the proxy's cut and stall, and L-1 to L-8 are
built; the rest is planned.

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
Its `[limits]` should set `chat_lines`, `spam_points`, `ng_requests`,
`news_posts` and `reconnect_seconds` to 0: every harness client talks
far faster than a person, from one address, and the flood limits would
kick and ban them as mhxd's would, and the request limits slow them
down. The churn logs in and resumes its accounts far faster than a
person too, and an account is held to its reconnect rate from every
address, exempt ones included.

For numbers worth comparing, put the server and the harness on
separate cores (`taskset`), raise `ulimit -n` for both, and record the
storage the database is on: the rate public chat can be persisted at is
the disk's fsync rate (`docs/metrics.md`, the `LogSerial` lock). The
baseline script does all of that (§7).

Every connection the harness opens comes from one address, and the
server holds an address to a few connections and a slow reconnect rate
(`[limits]`, the README). Loopback is exempt by default, so a server on
the same host takes the whole load. A server on another host refuses
nearly all of it as `too_many` or `too_fast`: raise `[limits]` there, or
better, add the generator's address to `exempt`.

## 2. The scenario file

TOML, every key optional; `crates/hxd-load/scenarios/` holds one of
each to start from, and a test keeps them valid. The report carries the
whole scenario with its defaults filled in, so a run can be repeated
from its own output.

- `[target]`: the classic port, the classic TLS port and its name, the
  ng port, `metrics`, the server's `log`, the `accounts` and the `admin`
  account the churn uses.
- `[[target.linked]]`: servers linked to the target, each with a `name`
  and its own ports, `metrics` and `log` (§8).
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

Every login the harness makes, a storm's arrivals, the members a
scenario joins and the churners' logins alike, is tried again when the
server refuses it as busy: past `[server] logins_in_flight`, or past
the share of it one address may have, which every client of a run on
one machine shares. The ng wire says so as `rate_limited`, the classic
wire in its task error's text. As a real client does, the harness waits
a short and growing while before each new try, and gives up once
`BUSY_PATIENCE` (`member.rs`) has passed, when the refusal stands as
the login's error. A refusal the retry absorbs fails nothing and is
never a violation, since the server is right to refuse, so the report
counts them apart, in `busy_logins`: `refusals`, every try refused;
`logins`, those refused at least once; `gave_up`, those still refused
when patience ran out, which failed; and `longest_wait_ms`, the longest
a refused login spent from its first try to its last. The summary gives
them a line of their own, `logins refused as busy`. A count that climbs
from one run to the next, or a login that gave up, is what a login gate
losing places would look like.

### Login storm (`login_storm`)

Arrivals at `rate` a second, rising by `ramp_step` every `ramp_every`
seconds, each on a wire picked by weight (`legacy`, `legacy_tls`,
`ng`). An arrival connects, logs in (as a guest, or to `[target]
accounts` with `accounts = true`), agrees to the agreement and fetches
the user list; it stays `linger` seconds and leaves. Each step is
reported on its own, and the knee is the first step whose p99 is twice
the first step's or whose failures pass one in a hundred. An arrival
refused as busy is retried like any other login, and its latency, timed
from when it was due, includes the retries: the server's login gate
shows in a step as latency and in `busy_logins`, not as failed logins.
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
- A watcher on every server holds each uid it saw leave to the
  server's quarantine: none may join again inside it. What that guards
  is an allocator that hands a freed uid out early; the sequential one
  comes round to a uid only after the whole space.

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
| `roster.uid_quarantined` | In churn, no uid a watcher saw freed was given to anyone inside the server's quarantine; counted for joins heard after a part, and a watcher that stops hearing is a violation. |
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

The one thing they do not assert is the slow consumer's verdict. The
server disconnects a client that has stopped reading once it has
queued a bounded amount for it (`docs/metrics.md`, the lagged
outboxes), and a run of a few seconds at a test's rate never queues
that much. The baseline's slow consumer does, and holds the server to
both verdicts.

## 6. The clients

`hxd-testclient` is a pair of scripted clients, one per wire, that
`hxd-load` drives and that the e2e suites can share. The classic one
frames with the pinned `hxproto` rather than with the server's framer,
so a framing bug on either side shows up as a disagreement rather than
cancelling out, and reads through a buffer so that a timeout cannot cut
a frame in half. The ng one checks every event's seq as it arrives.
Both keep whatever arrives while they wait for something else, so
nothing a caller has not looked at is ever dropped.

## 7. The baseline

`crates/hxd-load/baseline/sweep.sh` runs every scenario against a
release build: public chat at rising rates in a small room and a large
one, chat again with every commit fsynced (`sync =
"full"`), the slow consumer, churn, and a login storm of guests and of
accounts. It takes about half an hour.

```sh
cargo build --release -p hxd --features metrics -p hxd-load
BIN=target/release crates/hxd-load/baseline/sweep.sh
```

Each run goes through `baseline/run.sh`, which can run one scenario on
its own the same way. A run gets a server of its own, with a fresh
database holding the inbox, history and news, since chat is persisted
under a lock and a server without history measures a different server.
The server and the harness are pinned to separate physical cores, so
neither runs on the other's SMT siblings. Around each run it records the
server's CPU seconds and peak memory from `/proc`, and the harness's
CPU time, since a harness that is out of CPU is measuring itself. The
reports go to `out/`, one JSON and one summary per run.

Two cautions for reading them. The numbers belong to the host: compare
a run with one from the same machine and storage, never across. And
one run is an anecdote. A disturbed host shows up as one run that
disagrees with its neighbors, so a result that matters is repeated
before it is believed.


## 8. Server links

What links cost as they grow, and how they give way: users per side,
cross-link chat, the number of links, and the network between them,
each until something bends, and what bent. Every break should be the
one `docs/server-link.md` promises: bounded, confined to one link, and
recovered from a snapshot rather than a silent gap. One that is not is
the finding.

### 8.1 What shapes it

- **The bounds**, each failing its own way, which is what the
  scenarios aim at: the core's one export feed (`FEED_CAP`; full, every
  link starts over), each link's share of it (`EXPORT_CAP`; full, that
  link does), what other transit links pass on through one
  (`RELAY_CAP`; full, that link does), ghosts' lines waiting to be
  logged (`CHAT_CAP`; full, a line is not shown), requests waiting for
  a peer (`REQUEST_CAP`,
  `MAX_PENDING`; past them, refused), and the ghost bounds (`[link]
  max_ghosts`, each peer's `ghosts`). `docs/metrics.md` has a series
  for each.
- **Ghosts' chat is one funnel**: one task commits every link's lines
  through `ChatCommit`, everything waiting at once, under the same
  `log_serial` as local chat. A line crossing a link is persisted on
  both servers, and a local talker waits behind ghosts' commits.
- **An interruption is held for `[link] grace`** and then is a
  netsplit: one part per ghost to every local session at once, and one
  join per user when the snapshot comes.
- **A request to a ghost finds its link by scanning every link's
  ghosts** under the hub's lock, and the feed hands each event to every
  link under it.

### 8.2 The harness

**Several servers per run** (built): `[[target.linked]]` names each
server linked to the target. Every scrape, log check and roster check
is made on each, and the report carries each one's metrics under
`linked`. A run whose servers have metrics and no link up does not
start; nor does one until `[target]` has a link up to each of the
others. Chat, the login storm and the scenarios below that cut or stall
a link take linked servers. They are a star on `[target]`, linked
without transit, so a server other than `[target]` lists only its own
users and `[target]`'s, and a chat room across more than one linked
server has its talkers on `[target]` (`talkers_at_target`).

**`baseline/link-run.sh`** (built) runs one scenario as `run.sh` does,
against `a` on run.sh's ports and one server for each linked one the
scenario names, `b` on 16500 and 16700, `c` on 17500 and 17700, and so
on, up to `q`: `a` accepts key-mode links that the others dial over
TLS, each with a fresh key,
certificate and database, `[limits]` at zero (a ghost's lines are held
to `chat_lines` as a local user's are) and `show_tags` off, since the
checks match the classic wire's nicks exactly and a tag would change
them. The `scenarios/link-*.toml` are written for it.

```sh
cargo build --release -p hxd --features metrics -p hxd-load
BIN=target/release crates/hxd-load/baseline/link-run.sh link-chat \
    crates/hxd-load/scenarios/link-chat.toml
```

On one host the hub shares its cores with every leaf, and the leaves
one disk, so what a run says about any of them is partly the others'.
`HUB_HOST` runs `a` on another host over ssh instead, and `LEAF_HOSTS`
the leaves, in turn (`-` for this one); `host:/dir` puts a server's run
under dir rather than that host's home, as on a disk of its own. A
server elsewhere is not held to `SERVER_CPUS`; it is reached at its
host's address, every server lets every host in the run through its
`[limits]` and its `[metrics] allow`, and a remote server's CPU, memory
and errors are read on its host. Not with `[target.proxy]`.

```sh
HUB_HOST=gauss LEAF_HOSTS="onyx -" KS=16 RATE=5000 \
    crates/hxd-load/baseline/link-fanout.sh
```

**`linkproxy`** (`proxy.rs`), a TCP proxy a run starts at
`[target.proxy] listen` and carries on to `upstream`, which the linked
servers dial instead of their peer. It copies bytes and never decrypts.
Built: the cut, which closes every connection it carries, and accepts
and at once closes every new one until restored, so each side sees its
link drop and the dialer a TLS handshake fail; and the stall, which
stops reading what the peer sends the dialer while the dialer's own
traffic still flows, so the peer hears from it as ever while its writes
back up, as behind a server that stopped reading. Its receive buffer
toward the peer is kept small, as such a server's would be, not
loopback's megabytes. And a latency, `[target.proxy] latency_ms` added
to every byte each way, in order, which a scenario may change mid-run
(L-6's `peer_latency_ms`, applied once the links are up, since a link
cannot be set up across a round trip near its own timeouts). Planned:
jitter, a bandwidth cap, a partition where connects time out, and the
connection left half open. With `[target.proxy]` in the scenario,
`link-run.sh` has `b` dial the proxy (`c`, if there is one, dials `a`
directly), and every server takes `[interruption] grace` as its `[link]
grace`.

### 8.3 Scenarios

| | Scenario | Shape | Scales with | Expected to give way as |
|---|---|---|---|---|
| L-1 | Cross-link chat (built) | A-B, the room spread over both, client `i` on server `i` modulo their number; `chat.delivery.cross` times the lines heard on another server than their sender's | delivery latency against rate, `chat.delivery` every line and `chat.delivery.cross` those that crossed; once with `sync = "full"` | ghosts' lines not shown (`chat.all_heard` failing on the far side only), or local talkers slowed behind ghosts' commits |
| L-2 | Presence storm (built) | a login storm on A; `[login_storm] observers_legacy` and `observers_ng` on each linked server time each arrival's join there (`link.join`) | from when an arrival was due to its join heard on B, against arrival rate | the ghost bound, exactly and no further; then a link's export queue (it starts over); then the feed (every link does) |
| L-3 | Interruption (built) | `[interruption] population_*` idle on A, `watchers_*` on B; the proxy cuts the link for each of `cuts` seconds in turn, swept across `grace`; `link.reconnect` times each link back, and the report each cut's parts and joins as the watchers heard them | time back up, snapshot time against N, the burst each local session takes | a local session dropped as `slow_consumer` by a netsplit's burst; only detached sessions should resync. Its numbers are what `grace` is tuned by |
| L-4 | Slow peer (built) | A-B through the proxy and A-C directly, the `[chat]` room on A and C; `[slow_peer] stalled`'s link stalled from `stall_after` to the end of the talking; `chat.delivery.before` and `.after` the stall | C's and A's local latency, which should not move; A's memory, inside `QueueBudget` | A closing B as `slow_consumer` within a bound; anything that slows C or A's own users fails it |
| L-5 | Churn across a link (built) | the churn scenario on A; once its time is up the kicks stop, then every churner says it is held, and B's list is compared with A's user for user; uid watchers on both | B's roster against A's once quiet | ghosts left on B, a uid reused inside its quarantine |
| L-6 | Requests (built) | requesters on A sending private messages (both wires) and user info (classic) to B's users, open-loop, at each count in `[requests] ghosts`; each step reported apart | round trip against the ghosts shown (the scan) | requests refused once more wait on the peer than a link lets wait: each requester waits on its answer, so that takes more requesters than that cap and a round trip long enough to keep them waiting together (about the cap divided by the round trip, a second); and answers outlasting the server's wait for the peer, which the sender hears as refused while the message is still delivered (`link.msgs_delivered`, `scenarios/link-requests-slow.toml` with `peer_latency_ms`) |
| L-7 | Moderation under load (built) | the room on A and B, and a moderator on A kicking or banning B's users, accounts there as on A, one every `every` seconds from `acts_after`; `chat.delivery.before` and `.after` the first act | each act answered (`moderation.kick`, `.ban`) and carried out on B (`moderation.carried`) | a slow store write holding up the hub or the feed |
| L-8 | Many links (built) | a hub with K leaves, K doubling (`baseline/link-fanout.sh`), the room's talkers on the hub (`[chat] talkers_at_target`) and its readers on every server | delivery to the leaves against K and rate; the hub's CPU | each leaf logging every line the hub fans out to it: past what a leaf can commit, its queue of ghosts' lines overflows and the lines are not shown there (`hxd_link_dropped_total{what="chat"}`), which every reader of it misses (`chat.all_heard`); sooner the more servers share a host. Past that, the hub's own fan-out, its lines reaching the leaves in bursts |

Each is swept one variable at a time from a fixed point, repeated, and
compared only on one host, as §7 asks: users per side up to the bounds
and past them with the bounds raised, chat rate, link latency from none
to a few hundred milliseconds, a bandwidth cap, and links (L-8). Chains
through transit (A-B-C, B relaying) join L-1 and L-2 once the harness
starts more than two servers.

### 8.4 Checks

Every check in §4 holds on every server, and a reader across a link is
held to `chat.in_order_once` and `chat.all_heard` as a local one is. A
line or user not carried for a bound counts in the metrics, never as a
gap; a ghost's line past `chat_lines` does not, which is one more reason
`[limits]` is zero. Beside them:

| Check | What must hold |
|---|---|
| `link.stayed_up` | With metrics, no link ended or came up during the run: none was cut. |
| `link.no_ghosts` | With metrics, after everyone has left, each server holds no more ghosts than before the run. |
| `link.joins_heard` | Every observer heard every arrival that logged in join its server. |
| `link.ghosts_shown` | In L-6, at each step `[target]` showed every one of the linked servers' users within `settle`. |
| `link.msgs_delivered` | In L-6, every message `[target]` accepted was heard by its recipient once, and every one it refused never, after each step and again once the run is quiet. User info answered with the ghost's server alone, and a message queued, count as refused; one unconfirmed (sent, not answered in time) is held to neither. |
| `link.requests_answered` | In L-6, every requester was answered within a wait past the server's own for the peer; one that was not is dropped from the run. |
| `churn.kicks_stopped` | In L-5, the moderator stopped kicking within `settle` of being told to. |
| `link.mirrors` | In L-5, every churner held within `settle`, and then every linked server lists exactly the run's users `[target]` does, user for user (a stale ghost under a nick still in use counts), within `settle`, and that is not none. |
| `link.recovered` | After each cut within `recover`: every link up again (with metrics; without, once the grace is past) and every watcher's server listing the whole population. In L-4, with metrics, every link up again within `recover` of the stall's end. |
| `link.grace_held` | A cut shorter than `grace` showed no watcher anyone leaving. |
| `link.stayed_connected` | Nobody in an interruption, watcher or population, lost their connection over it. |
| `link.contained` | In L-4 and L-7, the room's p99 from the stall, or the first act, on stays within `contained` times its p99 before (and a few milliseconds). |
| `link.acts_carried` | In L-7, every act answered, and within `settle` carried out on the victim's server: a kicked user told and still there, a banned one ended. |
| `link.kick_hides` | In L-7, a kicked ghost is gone from the moderator's list as soon as the kick is answered, and no victim acted on, kicked or banned, is listed there again by the end. |
| `link.peer_dropped` | In L-4, with metrics, `[target]` gave up on the stalled link, as a slow consumer or a lagged queue, within `drop_within` of the stall. |
| `link.bounded` | In L-4, with metrics, `[target]`'s classic writers, the link's among them, never held more than `max_queued_bytes`. |

`roster.agrees` is held across servers as it is on one: every
member's list, ghosts included, shows exactly the run's members on
every server. Up to the ghost bounds that is what a check of each
server's ghosts would ask.

### 8.5 Order

Built: the metrics; several servers in `hxd-load` with L-1 and L-2,
both also run small in `tests/scenarios.rs` against two servers in
process (without `metrics`, so there the clients' checks hold and the
link checks are the baseline's); the proxy's cut and L-3, run small in
process too; the stall and L-4 likewise, on three; and L-5 and L-6.
The proxy's latency and L-6 across it too, L-7, and L-8 on a hub and
three leaves. Next: a link pass in the baseline's sweep.
