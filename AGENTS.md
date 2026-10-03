# AGENTS.md — hxd-ng working notes

> Orientation for anyone (human or AI) working in this codebase. This file
> is the map, not the territory: the product plan and phase status live in
> **[ROADMAP.md](ROADMAP.md)**, the Hotline-ng protocol spec in
> **[docs/hotline-ng.md](docs/hotline-ng.md)**, and how-to-run in
> **[README.md](README.md)**. Git history is the record of how we got here —
> the commit messages are written to be read.

## What this is

hxd-ng is a new Hotline server in Rust, written from scratch (not a port of
hxd/mhxd), sibling project to the [GtkHx](https://github.com/mishan/gtkhx)
client revival. It serves two protocol populations from one shared state:

- **Legacy Hotline** (TCP :5500) — the 1.2/1.5 wire format, byte-compatible
  with clients from the late 90s.
- **Hotline-ng** (WebSocket :5700) — a JSON protocol designed mobile-first,
  where sessions survive dropped connections.

**The hard requirement: never break old clients.** Hotline 1.2/1.5 clients
(and 1.9 where behavior is known) must connect, chat, and eventually
transfer files with no changes. It is the mirror image of GtkHx's
never-break-old-servers rule and outranks every other consideration.
Deviations from reference-server behavior are deliberate and commented at
the site.

License is **GPL-2.0-or-later** — forced by `hxproto`'s hxd ancestry,
and kept.

## Build and run

```sh
cargo build --workspace
cargo run --bin hxd           # config: hxd-ng.toml (all keys optional)
```

The [hx-libs](https://github.com/mishan/hx-libs) workspace provides
`hxproto` (the wire format, including the tracker protocol), `hxfiles-xfer`
and `hxhfs` as pinned git dependencies shared with GtkHx. Rules:

- Advancing the pin is a deliberate act with a full test run behind it.
- API changes in shared crates land in hx-libs first, then each consumer
  advances to the validated revision. The unrelated third-party hotline-rs
  implementation can be evaluated when its source is public.

MSRV is pinned to gtkhx's floor (`rust-version` in Cargo.toml) but has only
been exercised on newer toolchains; CI runs stable.

## Workspace map

| Crate | Role |
|---|---|
| `hxd-core` | The domain: presence roster, chat rooms, messaging, moderation and bans, the news tree, avatars, access bits, auth traits and account administration (`admin`), and `instrument` — every metric the server records, and `TimedMutex`, which the roster and the stores lock with. **Wire-free and UTF-8** — no transaction types, no Mac Roman, no JSON. Both frontends speak to it; a future frontend is "just" a third caller. |
| `hxd-session` | The legacy frontend: TRTP handshake, 22-byte-header framing, per-connection reader/writer/loop tasks, mhxd-mirroring protocol behavior, Mac Roman or negotiated UTF-8 ↔ UTF-8 at its edges (`encoding.rs`), the legacy news binding — `NEWSPATH` resolution, the 1.5 transactions and the 1.2 flat view (`news.rs`), the server banner (`banner.rs`), the 1.5 user editor (`accounts.rs`). `run_session` is generic over the byte stream so the ng port can feed it a tunnelled WebSocket, and `serve_tls` feeds it a TLS session from the legacy TLS port (`tls.rs`, whose certificate SIGHUP reloads). |
| `hxd-ng-session` | The ng frontend: the HTTP layer on the ng port (discovery, identity endpoints, the registrar's routes — `registrar.rs` — and the WebSocket upgrade for both the JSON protocol and the TRTP tunnel — `http.rs`), server-side identity state (`identity.rs`), the login/resume/sync handshake, session-token registry, seq-stamped event encoding. |
| `hl-identity` | Identity objects for `docs/hotline-ng-identity.md`: keys, device certificates, user cards, attestations, login proofs, and the registrar's requests, records and signed lists (with the one record verifier they all share) — deterministic CBOR, domain-separated Ed25519. Transport-free by design; shared with clients, proxies and relays, so it may eventually belong beside `hxproto` in hx-libs. |
| `hl-tunnel` | `WsByteStream`: a WebSocket whose binary frames carry a classic byte stream, as `AsyncRead + AsyncWrite`, with the keep-alive ping and the silence deadline. What the ng port's `/trtp` and `/htxf` and `hlrelay` all run the classic protocol over. |
| `hxd-auth-file` | Flat-TOML accounts (one file per account, `[access]` named bits + `[extra]` server-local policy + `[identity]` link), first-run guest bootstrap, and the account editing behind `hxd_core::admin`. Identity links and edits are written back with `toml_edit` so hand-edited files keep their comments; fingerprint lookups scan the directory. |
| `hxd-media` | The inline-media pipeline (`docs/inline-media.md`): magic-byte sniff, hand-written JPEG/PNG/GIF container walkers that refuse polyglots, a bounded decode and a re-encode that strips every byte of metadata by construction, and the fitting that makes an avatar and its legacy GIF (`docs/avatars.md`). Behind `hxd-core`'s `MediaCodec` trait and the `media` Cargo feature, and knows nothing about Hotline. |
| `hxd-markdown` | Markdown news bodies (`docs/news.md` §5): pulldown-cmark, built without its HTML writer, folded into the plain-text downgrade that search and legacy clients read, and the references a body makes. Text in, text out — nothing here ever produces markup. Behind `hxd-core`'s `BodyRenderer` trait and the `markdown` Cargo feature. |
| `hxd-voice` | The voice **and video** SFU: str0m, one UDP port, hand-written SDP, RTP forwarding, VP8 passthrough and keyframe requests. Behind `hxd-core`'s `VoiceMedia` trait and the `voice` Cargo feature, and knows nothing about Hotline. |
| `hxd-registrar` | The identity registrar (`docs/identity-registrar.md`): handles and their lifecycle, attestations, the records it publishes (revocation, rotation, freeze), the issuance log and stats, rate limits and replay, the operator's freeze, revoke and recover. Signed bytes in, signed bytes out; no HTTP, no roster, no account table beyond the reserved names it is handed. Its `RegistrarStore` trait, an in-memory store and the conformance suite live here. |
| `hxd-store-sqlite` | The durable store for the private-message inbox, chat history, news, the moderation trail and the bans: one SQLite file, WAL checkpointed by a thread and a connection of its own (never inside a commit, and one checkpointer to a file), public chat's log on a connection of its own beside the others' (`open_beside`), the schema and migrations of `docs/private-messages.md` §5, `docs/news.md` §4 and `docs/moderation.md` §7, and the conformance suites both stores of each kind are run against. Behind `hxd-core`'s `MessageStore`, `ChatLog`, `NewsStore`, `ModerationStore` and `AvatarStore` traits and the `inbox` Cargo feature; the in-memory stores beside them in `hxd-core` are what the domain tests use. The registrar's store is here too, in a file and a schema of its own. |
| `hxd-push-webpush` | The push sender (`docs/webpush-gateway.md`): a VAPID keypair and its RFC 8292 token, RFC 8291 payload encryption, RFC 8030's headers, the destination check a client-chosen URL demands, and a per-origin circuit breaker. Behind `hxd-core`'s `NotificationGateway` trait, reading the devices out of its `PushStore`, and knowing nothing about Hotline. |
| `hlid` | The identity tool: `init` (a whole identity in one command, into `$HLID_HOME`, which every file flag falls back to), keygen, device certificates, cards, attestations, `inspect`; `auth` runs the challenge binding against a server; `tunnel` listens on a local port for a classic client and carries it to `/trtp` over WebSocket with the user's device key (spec §11.1), and on the port after it for the client's file transfers and banner, carried to `/htxf`; `register`, `revoke` and `rotate` talk to a registrar. |
| `hxd-testclient` | Scripted clients for the server's own tests: the classic wire over TCP or TLS, framed with the pinned `hxproto` rather than the server's framer and read through a buffer so a timeout cannot cut a frame, and the ng wire with every event's seq checked as it arrives. Both keep what arrives while they wait for something else. Shared by `hxd-load` and the e2e suites. |
| `hxd-load` | The load harness (`docs/load-testing.md`): scenarios from TOML — the login storm, public chat, the slow consumer, churn — open-loop, timed from when each thing was due, with the server's invariants checked under load and a JSON report. `hxd-load accounts` writes the accounts churn logs in to. Its `tests/` run each scenario small against a real server. |
| `hlrelay` | A relay (`docs/hotline-ng-auth.md` §10.2, `docs/relay.md`): discovery, `/trtp` and `/htxf` in front of a classic server that has never heard of Hotline-ng, each socket copied to a TCP connection of its own. Knows nothing about the bytes it carries and does not authenticate. |
| `hxd` | The binary: config, wiring, the ng sweeper task, the voice media pump, `HXD_DEBUG` tracing, the operator's commands (`hxd account` in `accounts.rs`, `hxd ban` and the rest of moderation in `moderation.rs`), and behind the `metrics` feature the recorder `GET /metrics` renders (`metrics.rs`, `docs/metrics.md`). Its `tests/` hold the e2e suites. |

`tools/ng-client.mjs` is an interactive ng test client (Node 22+, or
`npm install` in tools/ for the `ws` fallback) — `/drop` exercises
detach/resume, `/msg` PMs by nick or uid.

`Dockerfile` and `docker/` are the operator's image: `entrypoint.sh`
writes a config from `HXD_*` variables at each start unless one is
mounted, and `docs/docker.md` lists them. A config key worth an
operator's variable gets one there. `.github/workflows/docker.yml`
builds the image on every PR and runs `docker/smoke-test.sh` against
it; a merge to main then publishes it to GHCR.

## Invariants that matter

**The domain is UTF-8 and wire-free.** A legacy connection's encoding
exists only at `hxd-session`'s edges, and every text field crosses them
through the connection's `TextEncoding`: Mac Roman, or UTF-8 when the
client negotiated Text-Encoding (capability bit 1). Mac Roman converts on
ingest (injective, so legacy-origin text round-trips exactly) and converts
with `?`-for-unmappable on egress; either way the wire's byte caps (31 for
a nick) apply *after* conversion, at a character boundary. Inbound, a
login, password, nick or subject is capped in characters, so one typed
on either wire cuts at the same place. A body leaves with that
connection's line ending (CR or LF) whatever the sender used.
Credentials are canonicalized to UTF-8 from the connection's encoding
before any auth backend sees them — HOPE proofs must use the same
canonical form when that lands. Never let a wire type or encoding leak into `hxd-core`'s API; that separation is what makes
the ng frontend (and any future one) possible.

**Presence is user-scoped, not connection-scoped.** A `UserSession` owns a
uid, a serial, and a seq-stamped outbox; transports attach to it. Legacy
socket death calls `end_session` (old behavior exactly); ng socket death
calls `connection_lost`, which detaches if policy allows. Detach policy:
`can_detach` is per-account (`[extra]`, default = has-a-password — guests
never detach), detached sessions are capped per source address, and
kicking a detached session must end it directly — there is no connection
to observe the `Kicked` event.

**Outbox seqs are gapless.** Every event a session should see consumes a
seq, including events the ng protocol can't express yet — those become
placeholder frames, never holes, or resume's `last_seq` accounting breaks.
Buffer overflow marks the outbox broken and resume answers
`resync_required`; it never silently gaps.

**Frame the legacy read stream by `len2` (DataSize), not `len`
(TotalSize)** — a lesson gtkhx paid for against fragmenting servers.
Clients never fragment, so `len != len2` is rejected outright. Size caps
mirror mhxd's.

**mhxd is the behavioral reference** for everything a 1.2/1.5 client can
observe: the login/agreement dance, server-side chat formatting (the
`\r%13.13s:  %s` and `\r *** %s %s` forms, byte for byte, empty tokens
skipped), user-list payloads, task-reply conventions (replies echo the
request trans; pushes count their own). GtkHx vendors it for cross-reading
in its development tree. Where we deviate on purpose — real access bits in
SELFINFO, readable task errors, acked broadcasts — the site says so.

**Video is layered on voice, never beside it.** One peer connection, one
UDP port, one room, one SDP path: video adds media sections to the voice
session and reuses 602/603/604 for every renegotiation. What it adds is
publication control and a status notification. Two rules carry the
weight, and both are load-bearing rather than stylistic. **Nothing is
delivered unasked** — a peer receives a publication only while it holds a
subscription to it, so a voice-only client is not a special case the
forwarding path has to remember to exclude, it is a peer whose
subscription set is permanently empty. And **inbound video is keyed by
the SSRC the answer declared, never by mid**: a camera and a screen from
one participant are the same codec at the same payload type on one
bundled transport, so there is nothing else to tell them apart and an
answer that omits `a=ssrc` costs that publication rather than being
guessed at.

**An image is a handle, and a handle is an authorization.** Bytes never
travel inside a chat transaction on either wire: an upload is
canonicalized — decoded and re-encoded by this server, so stripping
metadata is a property of the construction rather than of a filter that
could miss a chunk type — and what a chat line carries is an opaque
handle. Who may fetch it is **fixed when the line is relayed**, as
principals rather than uids (a `(uid, serial)` session for chat, a
mailbox for a private message, so mail read tomorrow still resolves),
and the set may narrow but never widen — the one exception being a
moderator judging a reported image. Attaching a handle asks whether
*this session* uploaded it; fetching one asks whether this principal was
shown it. Getting those two questions confused is how an image reaches
someone who was not in the room.

**The access bitmap is shared wire vocabulary; don't squat on bits.**
Reserved bits stay reserved (fogWraith allocates upward from 55).
Server-local policy that never crosses the wire goes in the account files'
`[extra]` section instead (`can_detach`, `set_subject`).

**Session-token trust is `(uid, serial)`.** uids recycle; serials never.
Tokens are CSPRNG bytes stored as SHA-256, compared in constant time. The
registry never holds its lock while calling into the core (copy out,
release, consult, reacquire) — keep it that way.

**A session must never outlive its transport silently.** Any handshake
send failure after attach routes through `end_session` (login) or
`connection_lost` (resume). A ghost on the roster with a dropped receiver
is the bug class to fear here.

**A client that will not drain is disconnected, not buffered for.**
Everything held for a connection is bounded: an attached session's
channel (`LIVE_QUEUE_CAP` events or `LIVE_QUEUE_BYTES`, whichever comes
first, weighed by `Event::weight` — past it the domain closes the
channel and signals the connection, and the frontend drops it as
`slow_consumer`, mid-send if need be), the classic writer's queue
(bytes), and each classic write (no progress for a minute). One client
that stops reading must cost the server a bounded amount and everyone
else nothing; `crates/hxd/tests/slow_consumer.rs` is the check. And a
bound per connection is that bound times the connections, so the
live channels, the classic writers' queues and the detached sessions'
buffers also draw a `Share` of one server-wide `QueueBudget`
(`hxd_core::budget`, `[server] queue_budget_mb`): past it, a queue
holding more than the queues do on average is dropped the same way,
and a detached buffer breaks. A new queue that can grow with a
client's backlog draws on it too. Two corollaries. A lag is the *connection's*, not the session's: `Events`
carries it, and `connection_lost_from` refuses a connection that has
been taken over, so an old connection never detaches the new one. And
no domain operation may push a session anywhere near the cap in one
go: a purge of thousands of lines sends nothing to a wire that cannot
show redactions (`Transport::redactions`).

**One address is held to so many connections, and so fast**
(`hxd_core::limits`, `[limits]`, mhxd's `nospam` defaults): a
`ConnPermit` from `Core::admit_connection` is held for the life of every
connection that can carry a session, taken where the classic wire
checks bans (plain, TLS and the `/trtp` tunnel alike; on the TLS port
at accept, so the handshake is counted) and at the ng upgrade, before
its token is redeemed, with the client's address as trusted proxies
give it. An IPv6
client is its /64; loopback is exempt by default. A new listener that
carries sessions takes a permit too. **An address counts a connection
only until it logs in**: carrier-grade NAT puts many people behind one
address, so a login or resume that makes a connection a person's
(`is_person`) moves its permit to its account's count
(`Core::admit_account`, `Core::admit_resume`, after the credentials
and the bans and before the attach), giving the address back its place
but not its reconnect charge, and spending one of the account's too, so
a login goes no faster than the slower of the two rates; past
`connections_per_account`, or past the account's rate, the login is
refused with a reason on both wires. The ng port's per-address place rides along (`ConnPermit::carry`)
and goes with it. Guests stay their address's. A new login path moves
the permit too. And one session talks so fast,
wherever it connects from, on mhxd's budgets: past `chat_lines` lines
of chat in a window, every line of a send counted, it is kicked and its
room told (`Core::chat_flood_check`, in the chat paths); past
`spam_points`, which every request spends at the price mhxd's table
gives its transaction, it is kicked and banned
(`Core::spend_spam`, called by each frontend before it acts on a
request; a new frontend or an ng request with a classic counterpart
calls it too). A session already kicked is refused, never kicked
again. An account that `can_spam` is held to neither. Most ng requests
have no classic counterpart to be priced by, so an ng session is also
held to a token bucket (`ng_requests`, `Core::spend_request`, kept
with the session so a resume does not refill it), each request
spending the weight `request_weight` in `conn.rs` gives it; a request
added to the dispatcher gets a weight there, and one the bucket cannot
pay for is answered `rate_limited` with `retry_after`, a delay and
never a kick. One account's news posts are held to `news_posts`
(`Core::news_post_reserve`, taken before an ng post and given back if
it is refused; `Core::news_post_counted`, after a classic one), which
the classic wire's posts count toward and are never refused by: that
wire keeps mhxd's rules. `can_spam` exempts from both, as from the
budgets. A wrong password counts against its address and the login it
was for, and against its address alone under a looser ceiling,
whichever wire or route it came in on (`Core::login_attempt` before,
with the login as the client sent it, `Core::login_failed` after); a
new path that checks a password does both. Every connection to
the ng port holds places in that port's own counts (`HttpLimits`) from
accept, in the socket itself so an upgrade carries them.

**Past capacity a login is refused, not queued.** Every login costs
everyone present a join and later a part, so a server admitting logins
faster than it can tell the room about them falls further behind with
each one. `Core::admit_login` bounds the logins in progress
(`[server] logins_in_flight`, a quarter of it per address until the
login is known to be a person's — `LoginPermit::logged_in` — `[limits]`
exempt addresses aside), from the
login request to the join, so a client slow to send one holds no place;
past it both wires refuse at once as busy (`rate_limited` with
`retry_after` on ng). A 1.5 client that answers the agreement before
joining joins outside the bound. A new login path takes a permit too.
And a connection writes what is already queued for it in one go, one
being sent a trickle of events at most every couple of milliseconds
(`COALESCE`), because one write per event was most of what a storm
cost; a task reply never waits.

**Public chat is committed in groups** (`chat::ChatCommit`): a line
joins a queue, and whoever finds no commit under way logs everything
queued in one transaction and relays it in order under `log_serial`,
then hands the lead on. Queue order is the order lines are logged and
heard in; anything else that must fall between two lines (a redaction,
a purge) takes `log_serial` as before, between batches.

**`assert!` over `debug_assert!`** for wire invariants — release builds
must not skip them.

## Testing

Three layers, all `cargo test --workspace`:

- **Unit** tests live with their crates (roster/outbox semantics, access
  bit numbering pinned against mhxd's constants, account parsing, frame
  round-trips).
- **E2E** suites in `crates/hxd/tests/` drive *real* servers on ephemeral
  loopback ports: `login.rs` (legacy login/presence/agreement),
  `accounts.rs` (the 1.5 user editor and the ng `accounts` family: each
  act under its bit, an administrator outranked by an account it would
  touch, an edit keeping the file's comments, a change reaching the
  account's sessions on both wires, `[extra]` policy no edit may give
  away, the classic editor leaving bit 56 as it was, and `hxd account`
  applied by a reload), `tls.rs`
  (the legacy wire over TLS beside a plaintext client, and HTXF on the
  TLS transfer port), `chat.rs` (chat/PM/moderation over the legacy
  wire, and the private-chat caps), `ng.rs` (the WebSocket
  frontend, **including cross-frontend scenarios** — a scripted 1.5 client
  and a WS client on one server, chat and PMs crossing both wire eras,
  detach showing as the away color, resume replay), `identity.rs` (the
  identity endpoints, linking, the `/trtp` tunnel, anchors — a real
  server per case with its own accounts directory), `media.rs` (inline
  media on both wires: the capability echo and its limits, single-shot
  and chunked upload, sliced downloads, a capable and a classic client
  in one room, a photo crossing each way, and a revocation),
  `file_management.rs` (New Folder, Delete, rename, Move and comments
  on both wires against one local area: each kind of entry under its own
  bit, Set Info changing only what differs from what was shown, drop
  boxes and aliases out of reach, a drop box behind a wire name cut
  short of saying so, a folder holding a drop box kept from an account
  that cannot view one, an act refused before any lookup to an account
  with none of its bits, folders nested too deep on either wire, a
  read-only area refusing it all),
  `avatars.rs` (a picture set on either wire and shown on the other,
  GIF Icons' probe and Icon Change, an account's avatar surviving a
  restart, a guest refused on both wires until its file allows it, the
  interval outlasting a reconnect, the icon list rationed, and an
  identity's avatar aged out of the database), `banner.rs` (the banner push after the agreement, and a
  banner file fetched over HTXF once per login), `inbox.rs` (offline
  private messages across both wires: queue, flush at login, resync,
  blocks, retention, the sender's daily quota refusing only
  what would have to wait), `news.rs` (threaded news on
  the ng wire: the tree and its containment rules, threads in reading
  order and paged both ways, references and backlinks, tombstones, who
  hears that the news changed and who hears that it is theirs, following
  and muting — and on the legacy wire: a scripted 1.5 client walking
  the tree an ng client built, reading both parts of a markdown article,
  posting and keeping house, and a 1.2 client reading the flat category,
  posting into it and hearing its push, read from the store once
  however many classic clients hear it; and the news ceilings refused
  on both wires), `moderation.rs` (the acts and
  reports on both wires against one database: a redaction blanking a
  rendered line and paging as a tombstone on 700 and `history`, a
  revocation and its refused re-upload, a kick with a purge across the
  log and the news, the ladder, a report reaching a legacy moderator
  from the system account and an ng one as an event, `/report`, and a
  reported image outliving its TTL for the moderator), `bans.rs` (`hxd
  ban` against a running server's database and SIGHUP, a banned login
  refused on both wires, and a ban outliving its server) and
  `registrar.rs` (the registrar built from a real
  `[registrar]` section: discovery under its own host only, handles,
  rotations published under both keys, a card's commitment, invites from
  the file and the command, the operator's commands on the running
  store, and `hlid register`, `revoke` and `rotate` driven as a user
  would), `voice.rs` (voice signaling on both wires against a
  recording media layer: the capability and privilege gates, the chunk
  and JSON shapes, one room shared by a classic and an ng client, joins
  past a session's allowance refused on each wire while leaves never
  are, and a burst of mute flips announced once with its final state),
  `limits.rs` (so many connections from one address across both
  wires, then a burst and a rate, a TLS handshake counted from accept,
  and an exempt address held to neither; a classic user's multi-line
  flood kicked once with the room told in mhxd's bytes, and a user past
  its spam points on each wire banned, the ng one refused `flooding`;
  an ng nick flood banned at User Change's price, a nick that changes
  nothing told to nobody on either wire, an account past its news posts
  told how long to wait, and the request limit answering `rate_limited`
  and then serving again, and still refusing after a resume),
  `http_limits.rs`
  (the ng port's own counts: plain HTTP and a WebSocket past an
  address's connections closed unanswered, the ceiling on everyone's
  and the reserve an exempt address is kept past it, an idle
  keep-alive closed; challenges and avatar fetches past their rate
  answered 429; failed logins on every wire locking the address out of
  all of them until it earns one back, guesses made at once held to
  the same count, a request refused before its password is checked
  not counted, and a login with no password not held to it),
  `relay.rs` (a classic server behind `hlrelay`: a client that reaches
  it only over WebSockets logs in, chats with one on the TCP port, and
  downloads over `/htxf`), `slow_consumer.rs` (a room flooded while one
  client reads
  nothing: on each wire it is dropped, the ng one while still silent
  and well inside the pong deadline; the reader hears every line; the
  ng one resumes into a resync; and clients each inside their own
  bounds dropped once together they pass the server's budget) and
  `metrics.rs` (`GET
  /metrics` from a config's `[metrics]`:
  a scrape that accounts for a client on each wire and for their
  leaving, and the scrapes it refuses — built only with
  `--features metrics`).
- The scripted legacy client packs and parses with the same pinned
  `hxproto` revision GtkHx uses, so e2e doubles as wire-compat
  checking. `hxd-testclient` is that client made shared; the suites
  predate it and carry their own copies, and move onto it as they are
  touched (`metrics.rs` has).
- **Load**, in `crates/hxd-load/tests/scenarios.rs`: each scenario for
  a few seconds against a real server in process, on every `cargo
  test`, held to its invariants. Real runs are `hxd-load run` against a
  release build with `metrics` (`docs/load-testing.md`).
- **End-to-end, out of process**, in `e2e/` — `cd e2e && npm test`.
  These start the *binary*: a real config file `hxd` parses itself, a
  real directory it bootstraps into, real sockets. That is a layer the
  suites above deliberately do not reach, since they build `Core` /
  `ServerCtx` / `NgCtx` by hand — so `Config::load`, `check_config`, the
  feature-gated section errors, the ng sweeper and the pruners have no
  other coverage anywhere. They are driven by `@hotline-ng/client`, the
  browser client's library: a second implementation of the ng wire
  written from the spec by the client rather than by us, so where the
  two agree the agreement is evidence rather than a tautology. Node
  only, so voice and video stay in the Rust suites where the real SFU
  is. The client is **pinned**: CI checks hx-ng out at the commit
  `e2e/hx-ng.rev` names, and a local run notes when `../hx-ng` is
  elsewhere. A wire change lands server first, covered by the Rust
  suites; the client follows; then the pin advances in the commit that
  adds the e2e cases using it. Advancing it is deliberate, like the
  `hxproto` pin — and in a stack, each branch pins the client commit
  its own e2e cases need.

House rules: **tests fail loudly** — never skip around something broken.
A chat sender receives its own echo, so tests must match events by
predicate, not take-the-first. Name test files by subject, never by
project phase (`login.rs`, not `phase1.rs`) — phase labels belong in
commit messages and docs only.

Before calling anything done, run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p hxd --no-default-features -- -D warnings
cargo clippy -p hxd --features metrics --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --features hxd/metrics --lib
cargo test -p hxd --features metrics --test metrics
node --check tools/ng-client.mjs
cd e2e && npm install && npm test   # needs a sibling ../hx-ng; CI pins it
docker build -t hxd-ng . && docker/smoke-test.sh hxd-ng
```

The best end-to-end check of all: point a real GtkHx at the legacy port
and `tools/ng-client.mjs` at the ng port, and chat between them.

## Debugging

`HXD_DEBUG=proto` turns on the wire trace (comma-separated categories;
`all` for everything) — its format matches gtkhx's `GTKHX_DEBUG=proto` so
a client trace and a server trace of the same session line up.
`RUST_LOG` wins when set.

## Conventions

- **Branches, not direct main commits.** Short kebab-case topic names
  (`ng-pm`, `registry-lock-discipline`) — no prefixes. Misha opens the PR,
  reviews, merges; CI must be green.
- **One commit per branch**, squashed before the PR opens
  (`git reset --soft <merge-base>`). During review, push follow-up
  commits; **don't force-push without asking**.
- Commits are authored `Misha Nasledov <misha@nasledov.com>`, descriptive
  bodies, no `Author:` line in the body, no `Co-Authored-By` trailer.
- **No AI attribution anywhere it lands in the tree** — not in commit
  messages, not in PR bodies, not in code comments or docs. No
  `Co-Authored-By`, no "generated with", no tool names. The work is the
  work; who or what typed it is not part of the record.
- **US spelling** in code, comments, docs and commit messages:
  *enrollment*, *behavior*, *canceled*, *license* (noun and verb). It is
  the spelling the specs in `docs/` already use, and a codebase that
  mixes the two makes `grep` unreliable — `enrolment` and `enrollment`
  are two different symbols. Existing British spellings get corrected
  when the line is touched for another reason, not in sweeps of their
  own.
- Review feedback comes from bots as well as humans; verify claims before
  acting — this repo has seen confident "won't compile" findings about
  code that compiles.
- Stacked branches: a fix belongs on the branch that introduced the code;
  descendants pick it up when they rebase at merge time.
- **Avoid exact counts in comments and docs** (lines, tests, files) — they
  go stale and the narrative is stronger without them.
- Prefer a scripted reproduction (an e2e test against a live in-process
  server) over interactive debugging sessions.

## Where things stand, and what's next

ROADMAP.md carries live status. In brief: the legacy server covers login,
presence, chat, private chats, PMs, broadcast, and moderation; the
Hotline-ng MVP (roster + chat + PMs with detach/resume) is complete and
cross-tested; voice and video are implemented on both wires, sharing one
room and one SFU; the identity registrar is built, and a server applying
what a registrar publishes (`docs/identity-registrar.md` §7) is next on
that front. The large open fronts, in rough order: HOPE + ciphers on the
legacy wire (`hxcrypto` currently lives in GtkHx), the ng rate-limit and
client-quickstart polish, files/HTXF, the
rest of news (the domain, store, search, subscriptions, markdown bodies,
attachments, the ng wire, the legacy binding and moderation have
landed; the legacy image part and the mhxd importer are staged in
`docs/news.md` §16), the push gateway itself
(`docs/push-notifications.md` P3 onward — the domain already decides who
is notified, for private messages and for news), and eventually the
persistence/clustering phases. The mobile app the ng
protocol exists for has not been started.
