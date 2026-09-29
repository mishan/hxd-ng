# Metrics

Status: built. The `metrics` Cargo feature and the `[metrics]` section;
the load harness that reads them is next.

What the server can say about itself while it is busy: how long each
lock is waited for and held and by whom, how long the store takes, how
long work queues for the blocking pool, how far a fan-out reaches and
what it costs, how far behind each wire's writers are, how logins take
and why connections end. It exists so that a load test can find a
bottleneck rather than only a slowdown, and so that an operator who
wants a dashboard can have one. Neither wire changes: this is a route
on the ng port and nothing else.

## 1. Building and configuring

The feature is off by default. With it off, every recording call in the
server is an empty function, and a `[metrics]` section is a startup
error rather than a promise the binary cannot keep.

```sh
cargo build --release -p hxd --features metrics
```

```toml
[metrics]
allow = ["127.0.0.0/8", "::1"]    # who may scrape; this is the default
```

The section needs `[ng]`: the numbers are served at `GET /metrics` on
the ng listener, in Prometheus's text format, rather than on a port of
their own for the operator to firewall.

**Who may scrape.** The numbers are for the operator. They say how busy
the server is and how long its locks take, which is exactly what
someone timing a flood would like to know. So a scrape is answered only
for an address `allow` names, and the address asked about is the
client's as the rest of the ng layer reads it: through a proxy listed
in `[ng] trusted_proxies`, the forwarded one. Two cases are refused
before that question is asked, because in both the socket's address,
most likely this host's own, is standing in for a client nobody named:

- a request carrying `Forwarded`, `X-Forwarded-For` or `X-Real-IP`
  from a peer that is *not* a trusted proxy;
- a request from a trusted proxy that did not name a client in the
  header `[ng] forwarded_header` says it writes: no header, the other
  one, or a value that is not an address.

What no rule can see is a forwarder that adds nothing at all: an onion
service, stunnel, a TCP-mode proxy or an SSH tunnel on this host.
Behind one of those every connection arrives from loopback, and the
default `allow` then lets everyone scrape. Such a server should name
something narrower in `allow` than this host.

## 2. What is measured

Every name here is written in one place, `hxd_core::instrument`, and
every label value is either fixed in the code or bounded by it. A
transaction type from the wire becomes a label only when the server
knows it (the number of a legacy transaction the session answers, or
an ng request name the dispatcher handles, or its family); anything a
client invents is `other`. Tests read each dispatcher's arms from its
source and fail if one has no label. A label value is a series the recorder keeps for the life of
the process, and a client must not be able to mint them.

### Locks

| Metric | Labels | |
|---|---|---|
| `hxd_lock_wait_seconds` | `lock`, `site` | from asking for the lock to holding it |
| `hxd_lock_hold_seconds` | `lock`, `site` | from holding it to letting go |

`lock` is the name of what the lock guards: `RosterInner` for the
roster, `LogSerial` for the order public chat is persisted in (held
once per commit, which may carry many lines, and by each redaction and
purge), `sqlite`
and `sqlite_registrar` for the two databases' connections. `site` is
the file and line that took it (`hxd-core/src/chat.rs:256`), so the
worst holder is named without anyone instrumenting it by hand. For the
SQLite locks the site is the store operation, and the hold is its time
on the disk.

The locks are `TimedMutex`, a `std::sync::Mutex` that reads the clock
on the way in and out. Both the wait and the hold are recorded after
the lock is released, so the recording is never part of what it
measures. It is not free, though: with the feature built in, every
acquisition formats its site label on the way out, whether or not a
`[metrics]` section installed anything to record it.

### The blocking pool

| Metric | Labels | |
|---|---|---|
| `hxd_blocking_queue_seconds` | `what` | from `spawn_blocking` to a thread starting it |
| `hxd_blocking_in_flight` | | closures running now |

`what` is the kind of work: `legacy` and `ng` for the frontends'
store calls, `login`, `purge`, `identity`, `media`, `avatar`,
`news_blob`, `registrar`, `files`, `push`, `prune`, and `metrics` for
a scrape's own render.

### The database

| Metric | Labels | |
|---|---|---|
| `hxd_sqlite_checkpoint_seconds` | `db`, `kind` | one WAL checkpoint on the checkpointer's own connection: a `passive` pass, or a `rewind` that emptied the log |
| `hxd_sqlite_wal_pages` | `db` | pages in the WAL when the last passive pass began |
| `hxd_sqlite_rewind_busy_total` | `db` | rewinds a reader held off |

`db` is the database's file name. Each file's WAL is folded back into
its database by a thread with a connection of its own, every second —
one thread to a file, however many of the server's stores share it —
never by the commit that happens to cross SQLite's threshold: that
commit is usually a chat line, holding the log's lock and everyone
behind it. A passive pass waits for nobody. Past a threshold the
checkpointer also rewinds the log, which holds the write lock while it
copies, syncs and waits for readers on the old log, so it is tried only
when the passive pass copied everything back. A pass that fell short
means a reader is holding a snapshot (a long read on another of the
server's connections to the file, or a reader outside the server: an
operator's shell, a backup), and then nothing is tried: the refusal is
counted, and the log grows on disk rather than holding up a commit. A rewind
that is tried waits a tenth of a second at most for a reader.

### Fan-out and the outboxes

| Metric | Labels | |
|---|---|---|
| `hxd_fanout_seconds` | `event` | one event delivered to every session it reaches, under the roster lock |
| `hxd_fanout_recipients` | `event` | how many that was |
| `hxd_events_pushed_total` | `sink` | `live` onto a connection, `buffered` for a detached session, `dropped` and lost to it (a broken buffer, or a connection cut off for falling behind), `closed` when nobody reads the channel (a connection on its way out, or the server account) |
| `hxd_outbox_broken_total` | | detached buffers that overflowed |
| `hxd_outbox_lagged_total` | `bound` | attached sessions whose client fell behind and was cut off: `count` for a whole channel (8192 events), `own` for its 16 MiB, `server` for more than the queues hold on average once the server's budget was spent |
| `hxd_voice_media_seconds` | `op` | each call into the SFU, all made under the roster lock |
| `hxd_voice_refused_total` | `what` | voice operations refused because the session had spent its allowance: `join`, or `video` for a start or a subscription change that adds a live stream (docs/voice.md §13) |
| `hxd_voice_policed_packets_total` | `stream` | inbound RTP the SFU dropped for arriving faster than its stream may: `audio`, `camera`, `screen` |
| `hxd_voice_policed_ends_total` | `stream` | streams ended for staying far over their rate: the session for `audio`, the publication for `camera` or `screen` |
| `hxd_voice_ice_ignored_total` | | trickled ICE candidates ignored because the session already held as many as it takes |

A fan-out runs under the roster lock, and so does its recording: once
per event, whatever its reach, so the cost inside the hold is a
constant rather than one per recipient.

### The wires

| Metric | Labels | |
|---|---|---|
| `hxd_frames_total` | `wire`, `dir`, `type` | frames in and out |
| `hxd_frame_bytes_total` | `wire`, `dir` | their bytes |
| `hxd_socket_write_seconds` | `wire` | one write, call to flush: a peer that stops reading turns into time here. A busy connection writes what is queued together, so one write may carry many frames |
| `hxd_outbox_depth` | `wire` | items waiting when the consumer took the next one |
| `hxd_write_queued_frames`, `hxd_write_queued_bytes` | `wire` | queued for the legacy writers, all connections together |
| `hxd_login_seconds` | `wire`, `auth` | first byte to a session on the roster; `auth` is `guest`, `password`, `identity` or `resume` |
| `hxd_flood_kicks_total` | `what` | sessions kicked for talking faster than `[limits]` allows: `chat` past `chat_lines`, `spam` past `spam_points` |
| `hxd_rate_limited_total` | `wire`, `reason` | requests answered `rate_limited`: `requests` past `[limits] ng_requests`, `news_post` past `news_posts`, `history` and `news_search` past their own |
| `hxd_logins_refused_busy_total` | | logins refused because the server was already working on `[server] logins_in_flight` of them |
| `hxd_throttled_total` | `what` | refused for coming too often from one address, account or session, before any work was done on it: `login` (past `[limits] login_failures` for one login, or `login_failures_per_addr` for every login together), `account` (a login or resume past `connections_per_account`, or past its account's rate at `reconnect_seconds`), `challenge` (`/identity/challenge`), `fetch` (an avatar or a news or media image), `upload` (an upload refused before its body was read) |
| `hxd_disconnects_total` | `wire`, `reason` | why a connection ended |
| `hxd_transfers_open` | `dir` | file transfers in progress |

The two wires queue in different places, which is why depth is
measured differently on each. A legacy connection's session task drains
the domain's channel at once into its writer's queue, so what piles up
behind a slow reader is the writer's, and the `hxd_write_queued_*`
gauges count it across every connection. An ng connection writes
inline, each write bounded by the pong deadline, so its backlog stays
in the domain's channel and `hxd_outbox_depth{wire="ng"}` is where it
shows.

The reasons: `eof`, `io_error` and `malformed` from the socket,
`closed` for a WebSocket close, `banned` for an address refused at
the door, `too_many` and `too_fast` for one past `[limits]` (the
connections its address holds, or how fast it opens them; a login past
its account's is `login`, and counted as `hxd_throttled_total{what="account"}`), `too_many_48` for
one whose IPv6 /48 holds as many as `connections_per_v6_48` (or, on
the ng port, `http_connections_per_v6_48`) lets it, `full` for a
connection past `[limits] ng_connections`, `handshake` and `login` for a connection that never got a
session, `kicked`, `logout`, `replaced`,
`send_failed`, `pong_deadline`, and `slow_consumer` for a client that
stopped taking what was sent to it: a classic writer's queue past its
bound or a write that made no progress for a minute, either wire's
session a whole channel behind, or either wire's queue among the
furthest behind once the server's budget is spent (below). A connection to the ng
port refused by `[limits]` before a byte of it is read, past
`http_connections_per_addr` (`too_many`), `http_connections_per_v6_48`
(`too_many_48`) or `ng_connections` (`full`),
is counted as `wire="http"`: it was never a session on either wire.

### Read at scrape time

| Metric | Labels | |
|---|---|---|
| `hxd_sessions` | `state` | `attached`, `detached`, `hidden` (on the roster, not yet announced), and `system` for the server account; each session is in exactly one |
| `hxd_detached_buffered_events` | `of` | events held for detached sessions, `sum` and `max` |
| `hxd_detached_broken` | | detached sessions whose buffer has broken |
| `hxd_sessions_lagging` | | attached sessions cut off for falling behind, not yet gone (counted in `attached` too) |
| `hxd_private_chats` | | rooms open |
| `hxd_queue_budget_bytes` | `of` | what every connection's queues hold together (`held`), against `[server] queue_budget_mb` (`limit`) |
| `hxd_live_queued_events` | | events waiting in attached connections' channels |
| `hxd_live_queued_bytes` | `of` | what those weigh, `sum` and `max` |
| `hxd_process_open_fds`, `hxd_process_resident_bytes` | | from `/proc` |
| `hxd_runtime_workers`, `hxd_runtime_alive_tasks`, `hxd_runtime_global_queue_depth` | | tokio's stable runtime metrics |

A server nobody is on reads zero attached and zero detached, with or
without a server account. That is the load harness's check for ghosts
after its clients have gone.

**The budget.** The queues that grow with a client's backlog, the live
channels, the classic writers' queues and the detached sessions'
buffers, draw on one server-wide budget as well as having their own
bounds: a per-connection bound is that bound times the
connections, and a login storm held gigabytes without any one queue
near its own. Past the budget, a queue that holds more than the queues
do on average is cut off as a slow consumer, which is the connections
furthest behind and not one in the middle of a burst; a detached
buffer breaks, and its resume is a resync. A queue that had kept up
may still take one large item, such as the user list of a crowded
server. The sizes are the
queues' own estimates (an event's weight, a frame's wire length); what
the allocator holds for them runs to a few times as much, so size
`queue_budget_mb` to a fraction of the memory the server may use.

Histograms keep their samples until they are folded into buckets, which
a scrape does and so does a clock, every few seconds: a server nobody
scraped used to hold every sample since the last scrape.

## 3. Profiling

```sh
cargo build --profile profiling -p hxd --features metrics
perf record -g target/profiling/hxd
```

`profiling` is `release` with line tables, which is what `perf` and a
flamegraph need to name a frame.

`tokio-console` has a feature of its own, because it also needs a
`cfg` the rest of the build must not carry:

```sh
RUSTFLAGS="--cfg tokio_unstable" cargo build -p hxd --features console
```
