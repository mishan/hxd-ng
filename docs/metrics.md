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
roster, `LogSerial` for the order public chat is persisted in, `sqlite`
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

### Fan-out and the outboxes

| Metric | Labels | |
|---|---|---|
| `hxd_fanout_seconds` | `event` | one event delivered to every session it reaches, under the roster lock |
| `hxd_fanout_recipients` | `event` | how many that was |
| `hxd_events_pushed_total` | `sink` | `live` onto a connection, `buffered` for a detached session, `dropped` by a broken buffer |
| `hxd_outbox_broken_total` | | detached buffers that overflowed |
| `hxd_outbox_lagged_total` | | attached sessions whose client fell a whole channel behind and was cut off |
| `hxd_voice_media_seconds` | `op` | each call into the SFU, all made under the roster lock |

A fan-out runs under the roster lock, and so does its recording: once
per event, whatever its reach, so the cost inside the hold is a
constant rather than one per recipient.

### The wires

| Metric | Labels | |
|---|---|---|
| `hxd_frames_total` | `wire`, `dir`, `type` | frames in and out |
| `hxd_frame_bytes_total` | `wire`, `dir` | their bytes |
| `hxd_socket_write_seconds` | `wire` | one write, call to flush: a peer that stops reading turns into time here |
| `hxd_outbox_depth` | `wire` | items waiting when the consumer took the next one |
| `hxd_write_queued_frames`, `hxd_write_queued_bytes` | `wire` | queued for the legacy writers, all connections together |
| `hxd_login_seconds` | `wire`, `auth` | first byte to a session on the roster; `auth` is `guest`, `password`, `identity` or `resume` |
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
the door, `handshake` and `login` for a connection that never got a
session, `kicked`, `logout`, `replaced`,
`send_failed`, `pong_deadline`, and `slow_consumer` for a client that
stopped taking what was sent to it: a classic writer's queue past its
bound or a write that made no progress for a minute, or either wire's
session a whole channel behind.

### Read at scrape time

| Metric | Labels | |
|---|---|---|
| `hxd_sessions` | `state` | `attached`, `detached`, `hidden` (on the roster, not yet announced), and `system` for the server account; each session is in exactly one |
| `hxd_detached_buffered_events` | `of` | events held for detached sessions, `sum` and `max` |
| `hxd_detached_broken` | | detached sessions whose buffer has broken |
| `hxd_sessions_lagging` | | attached sessions cut off for falling behind, not yet gone (counted in `attached` too) |
| `hxd_private_chats` | | rooms open |
| `hxd_process_open_fds`, `hxd_process_resident_bytes` | | from `/proc` |
| `hxd_runtime_workers`, `hxd_runtime_alive_tasks`, `hxd_runtime_global_queue_depth` | | tokio's stable runtime metrics |

A server nobody is on reads zero attached and zero detached, with or
without a server account. That is the load harness's check for ghosts
after its clients have gone.

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
