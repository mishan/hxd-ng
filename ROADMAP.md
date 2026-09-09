# hxd-ng Roadmap

A new Hotline server in Rust — a from-scratch design, not a port of hxd/mhxd.
mhxd remains the behavioral reference (GtkHx vendors its source for
cross-reading), but hxd-ng does not inherit its architecture: no
select-loop-plus-callback core, no global connection array, no monolithic
process state.

**The compatibility constraint is the mirror image of GtkHx's.** GtkHx must
never break old servers; hxd-ng must never break old clients. Hotline 1.2 and
1.5 clients (and 1.9 where behavior is known) must connect, chat, and transfer
files against hxd-ng with no changes. Extensions follow the same rule as on the
client side: capability-negotiated or probed, never degrading the legacy path.

**License: GPL-2.0-or-later.** Forced and fine — `hxproto` is
hxd-derived and stays GPL (see gtkhx `docs/rust/crate-layout.md` §4), and a
Hotline server is exactly the audience that section says is already GPL.

---

## Phase 0 — Extract shared protocol code into `hx-libs` *(implemented, 2026-09)*

`hxproto` now lives in the independent
[`hx-libs`](https://github.com/mishan/hx-libs) Cargo workspace. GtkHx and
hxd-ng both use exact git revisions, so advancing the pin remains a deliberate
act with a full test run behind it. hxd-ng no longer carries the GtkHx
submodule just to reach one crate.

**This need not be the final shared implementation.** A third-party
[github.com/hotline-rs](https://github.com/hotline-rs) org exists (August
2026) — "Rust implementations of the Hotline protocol", hotline.rs domain,
code still private but described as hxproto → hotline-codec →
hotline-{client,server,tracker}, maintainer open to being a community
integration point and to accepting contributions. Misha is a member. That is
a promising shape — a shared seam nobody's client owns — so the working plan
is:

- **Don't stall on convergence.** Keep building against the pinned `hx-libs`
  crate; revisit when his code is public and readable.
- **Share knowledge and fixtures first, code later if ever.** The durable
  protocol findings (DataSize framing, the HOPE rekey marker, the Mobius
  options-field drop, Mac Roman fidelity, tracker v3 probe-fallback) and the
  Tier 2 wire-fixture corpus are facts, license-thin, and worth months to
  anyone implementing this protocol. A shared conformance corpus both stacks
  pass *is* interoperability, without either adopting the other's code.
- **Mind the license asymmetry.** Our `hxproto` is hxd-derived and
  permanently GPL; if the org's crates are permissive and independently
  written, code flows one way only — we can build on his, ours can't merge
  into his. Realistic convergence is hxd-ng/gtkhx eventually sitting on the
  org's crates *if* their coverage earns it; evaluate on a matrix of
  opcode/version coverage, extension support, real-server testing, license,
  and MSRV when the code posts.
- Crate-boundary differences (his codec split vs. our proto-with-framing)
  are cosmetic next to wire-truth coverage; don't weigh them heavily.
- His architecture sketch (August 2026): hxproto → hotline-codec →
  hotline-{client,server,tracker}, with binaries on top — hotline-cli /
  hotline-gui over the client crate, a hotline-daemon that injects Account
  and Files *providers* into the server crate, and a tracker daemon. The
  provider-injection shape mirrors our AuthBackend/store traits, which
  bodes well. **The convergence question to ask when code posts:** is his
  hotline-server's session model socket-scoped and wire-typed, or can it
  host our user-scoped, wire-free domain core? If the former, the realistic
  adoption surface is proto + codec under hxd-session, keeping hxd-core
  ours. Also unknowns: where HOPE/ciphers live, extension scope, tests,
  license. His tracker daemon covers a component we lack entirely.

The initial extraction deliberately moved only the crate both projects use.
Other pure Rust crates should move when a second consumer needs them, rather
than speculatively:

| Crate | Why the server needs it |
|---|---|
| `hxproto` | **Moved.** Symmetric parse and build, framing, Mac Roman ↔ UTF-8, HL dates, login, sanitising and dispatch tables. |
| `hxcrypto` | Candidate when hxd-ng implements HOPE and legacy ciphers. |
| `hxhfs` | Candidate when the server's file area needs shared resource-fork sidecars. |
| `hxfiles-xfer` | Candidate when the server implements HTXF. |

**What stays behind, and why:**

- `hxnet` — client connect lifecycle; also glib-coupled (`g_critical!` in FFI
  error paths, `hxbridge` runtime). The server writes its own network layer.
  If, during Phase 1–2, the HOPE handshake or HTXF subchannel logic in `hxnet`
  turns out to be cleanly host-agnostic, promoting those pieces into a shared
  `hotline-hope` / `hotline-htxf` crate is an option — but extract on demand,
  not speculatively.
- `hxtext`, `hxmacres` — glib-coupled; and the Mac Roman table the server
  needs already lives in `hxproto::text`.
- `hxtls-trust` — client-side TOFU. The server's TLS story is a rustls server
  config and a certificate, not a known-hosts store.
- `hxconfig` — gtkhx's settings schema, not generic.

`hxproto` remains `publish = false`; pinning a git revision and publishing a
crate to crates.io are separate decisions. The third-party `hotline-rs`
project is still worth evaluating once its implementation is public. Avoiding
duplicated protocol stacks is desirable, but adoption should follow evidence
about coverage, interoperability, licensing and MSRV rather than the name of
the crate.

---

## Architecture

Designed for the cluster future from day one, but with exactly one
implementation of everything at first: in-memory, single process.

```
                    ┌─────────────────────────────────────────┐
                    │              hxd-ng node                │
   TCP :5500 ──────▶│ listener → per-connection session actor │
   TLS :5600 ──────▶│   (tokio task, owns socket + cipher)    │
                    │            │ typed requests             │
                    │            ▼                            │
                    │   domain services (chat, presence,      │
                    │   accounts, news, files, transfers)     │
                    │      │            │            │        │
                    │   EventBus     Store       AuthBackend  │
                    │   (trait)      (trait)     (trait)      │
                    └──────┼────────────┼────────────┼────────┘
              v1:    in-proc broadcast  in-memory    account files
              later: Valkey pub/sub     PostgreSQL   PostgreSQL
```

### The session layer

One tokio task per client connection — the **session actor** — owns the
socket, the negotiated cipher/compression state, the transaction counter, and
the write half. It frames the read stream with `hxproto` (**by
`DataSize`, not `TotalSize`** — the same lesson gtkhx paid for), decodes the
transaction, and calls into domain services. Replies and server-push events
come back through the actor's mailbox, so all writes to one socket are
serialized in one place and a slow client can't block the world (bounded
mailbox; a client that won't drain gets disconnected, not buffered forever).

No session state lives outside the actor except what the domain layer owns.
"Which connections exist" is a registry keyed by session id; nothing iterates
a global array.

### The domain layer

Services are plain Rust modules with typed APIs — `chat`, `presence` (the
user list), `accounts`, `news`, `files`, `transfers`. They know nothing about
sockets or wire encoding; the session layer translates. This is the seam the
future HTTP protocol reuses: a second frontend speaking JSON/WebSocket calls
the *same* services.

Fan-out (chat lines, user join/part, broadcast) goes through an **EventBus**
trait. v1 is a `tokio::sync::broadcast` per scope (public chat, private chat
N, user list); the cluster phase swaps in Valkey pub/sub behind the same
trait without touching the services.

**Presence is user-scoped, not connection-scoped — from day one.** The
Hotline-ng phase redefines "on the server" as *holding an authenticated
session*, with zero or more live connections attached (see Phase 7). To make
that a frontend change rather than a domain rewrite, `presence` models a
roster of user sessions, each with a set of attached connections; the legacy
frontend is simply the degenerate case where one TCP connection equals one
session and detaching ends it. Costs nothing now, saves the paradigm shift
later.

### Storage and auth traits, from the start

- `AuthBackend` — `authenticate(login, proof) -> Account` where `proof`
  covers both legacy XOR-obfuscated passwords and HOPE HMAC digests.
  **Design constraint that shapes everything downstream:** HOPE login proves
  knowledge of the password via HMAC, so the server must hold a
  plaintext-equivalent secret — bcrypt/argon2 hashes cannot verify a HOPE
  login. Store secrets recoverably (encrypted at rest), and document it. A
  future HTTP protocol gets to use real password hashing; the legacy wire
  does not.
- `AccountStore` — CRUD for accounts + the access bitmap. v1: one file per
  account (TOML — human-editable, unlike hxd's binary UserData; a small
  `hxd-ng import-hxd` command can convert an existing hxd/mhxd `accounts/`
  tree). Later: PostgreSQL.
- News, bans, and file-area metadata get the same treatment: an in-memory /
  flat-file implementation now, a trait boundary a DB backend can slot into.

The access bitmap definitions come from `hxproto` / mhxd's headers —
one definition, shared with the client world, never re-typed by hand.

### Workspace layout

```
hxd-ng/
  crates/
    hxd-core/        domain services, EventBus + store traits, in-memory impls
    hxd-session/     session actor, framing, HOPE/cipher negotiation, dispatch
    hxd-auth-file/   account-file AuthBackend + AccountStore
    hxd-files/       file area: walkers, hxhfs sidecars, HTXF workers
    hxd/             the binary: config (TOML), listeners, wiring, CLI
  tests/             integration harness (see Testing)
```

`hxd-core` must stay free of `hxproto` types in its public API where
practical — the domain model (a chat line, a member, an account) is not a
wire struct. That's what keeps the HTTP frontend honest later.

### Conventions

tokio; `tracing` for logs with an `HXD_DEBUG`-style category filter and a
wire-trace category matching gtkhx's `GTKHX_DEBUG=proto` format (being able
to diff client and server traces of the same session is worth the small
effort of matching formats). `assert!` over `debug_assert!` for wire
invariants, same as the client crates. Config is one TOML file; SIGHUP or a
control socket for reload can come later.

---

## Phase 1 — Skeleton: a server you can log into

**Status: implemented** (branch `claude/phase1-skeleton`) and green against
a scripted hxproto client — the guest and account login flows, the
parked 1.5 agreement dance, presence fan-out, ping, and the refusal paths.
What remains before calling the exit criteria met: a session with real
clients (GtkHx, and a period 1.5 client) against a running instance.

- TCP listener, TRTP magic exchange, version handshake.
- Legacy 1.2-style login (XOR-obfuscated login/password) against the file
  `AuthBackend`; guest login.
- Agreement send/accept. **Be liberal here:** accept an agreement-accept with
  or without the options field (Mobius-family servers crash without it —
  don't inherit the fragility from the other side).
- User list, presence events (join/part/change), nick and icon changes,
  SELFINFO, keepalive/ping, clean disconnect.
- The wire-trace category, end to end.

**Exit criteria:** GtkHx and a 1.5-era client both connect, see each other in
the user list, and survive a version-mismatch matrix (1.2 client, 1.5 client,
no-version client).

## Phase 2 — Chat core ← the v1 milestone

- Public chat, `/me` actions, chat subject.
- Private chats: create, invite, decline, join/leave, per-chat member lists.
- Private messages, broadcast, user info.
- Access bitmap enforcement on every op (the mhxd bitmap is the reference).
- Admin over the wire: create/modify/delete accounts (the 1.5 user editor),
  kick, ban list.
- HOPE negotiation + ciphers (ChaCha20-Poly1305, Blowfish OFB-64) and zlib
  compression, server side, via `hxcrypto`. Port the rekey-marker behavior
  byte for byte — it's wire-format-critical on this side too.

**Exit criteria:** a real multi-user chat server you can run for friends,
administered entirely from GtkHx. This is the dogfooding point.

## Phase 3 — Files and transfers

- File area rooted in config; listing, info, move/rename/delete/mkdir,
  comments; drop-box semantics (upload-only folders).
- Resource forks via `hxhfs` sidecars, fork headers via `hxfiles-xfer`.
- HTXF download/upload subchannels with resume (send well-formed RFLT;
  *accept* sloppy ones — gtkhx's old malformed-RFLT bug is exactly the kind
  of client to stay compatible with).
- 1.5 folder transfers (GETFOLDER/PUTFOLDER) — and consume the trailing
  no-resource MACR marker the way mhxd does; Janus's failure to do so hangs
  real clients today.
- Transfer queueing and per-account limits.

## Phase 4 — News

1.2 flat news post/read, and the 1.5 threaded news tree (categories, bundles,
threads). mhxd's format is the compat reference for an importer, not the
native format.

**Designed 2026-09 in [docs/news.md](docs/news.md)**, which takes the scope
past the line above. What a modern client wants from a forum is rich text,
links between posts and a search box, and none of the three needs anything
the 1.5 wire cannot be told about — that wire has carried multipart articles
with per-part MIME types since it was written. The design:

- **Storage is SQLite, not flat files.** `news_node` and `news_article`
  behind a `NewsStore` trait, as more tables in the file that already holds
  the inbox and the chat log. The flat-file plan predates the store crate;
  the trait boundary it wanted is the one that arrived with `MessageStore`.
- **The domain is designed once and the ng wire is bound first**, because
  news is the Phase 4 subsystem where the ng protocol is not a second
  frontend onto an existing feature — it is where the feature arrives. The
  legacy binding is specced in full and staged last, so the model is checked
  against the wire it must serve without being shaped by it.
- **Threading is a materialized preorder path**, so a thread comes back in
  display order from one indexed range scan rather than a recursive query or
  a client-side reconstruction.
- **Bodies are markdown, with a server-rendered plain-text part** — a 1.5
  client reads prose where an ng client reads formatting, which is what the
  multipart article was always for. The server parses markdown and never
  renders HTML, so rich text adds no injection surface.
- **References between articles** — `[text](news:51)`, plus a `#51`
  shorthand that works on plain bodies typed in a period client — are
  extracted into an edge table at post time and indexed both ways, so
  backlinks cost nothing.
- **Full-text search over FTS5**, which the pinned rusqlite build already
  compiles in: a table and a query compiler, not a dependency. The query
  grammar is ours and closed, so a malformed search returns results rather
  than an error. It is also the one place the two wires are not equivalent —
  there is no 1.5 transaction to search with.
- **Attachments are durable and content-addressed**, in a blob store of
  their own rather than inline media's 24-hour handles: a chat image is a
  moment, a news article is a record. Legacy clients fetch a re-encoded
  derivative because the wire's per-part size is a u16.
- **"The news changed" and "someone answered you" are different
  signals**, and the design keeps them apart. The first is what
  `NEWSFILE_POST` has always been — cache invalidation broadcast to
  everyone reading, so a 1.2 client's open pane does not hold a stale
  copy — and the ng wire carries it forward for clients holding a view.
  The second is targeted and has a rule about when it may ring.
- **Subscriptions and push notifications close the loop.** A reply to
  your article, a reference to it, or a post in a thread you follow
  reaches you when you are not there — which is the thing that makes a
  forum worth returning to rather than worth remembering to check. It
  needs no notification queue: the article is already durable, so the
  stored state is a subscription and a read cursor, and unread is a
  query. That cursor also settles the coalescing question Phase 7 leaves
  open, at least for news — **a scope rings only when its subscriber is
  caught up with it**, so a forty-reply thread buzzes once per visit
  with no timer, no digest window and nothing to sweep. It also answers,
  by construction, the question of what a mention is: a reference names
  an article and an article has exactly one author, so none of the
  nicks-are-not-unique difficulty applies — on by default, behind a knob
  for operators who think citing someone should not summon them.
  Notifying legacy-wire accounts is deliberately left for later: it
  needs a repliable system mailbox and a digest, because nothing on that
  wire can unsubscribe.
- **1.2 flat news is a rendering of one category**, not a second store.
  The operator names the category a 1.2 client reads and posts into; a
  post from that wire becomes a reply in it, with its subject and parent
  read out of a leading `Subject:` / `Re: #398` block in the body, which
  is the only place that wire has to put them. Both are optional and both
  have defaults — a post is never refused for lacking metadata the client
  cannot send — and the read format shows the same two headers, so it
  teaches the convention without a manual.

Not started. `hxd-session` dispatches no news opcode and `hxd-core` has no
`news` module; the access bits it needs (20, 21, 33–37) have been parsed
since Phase 1.

## Phase 5 — Hardening and parity extras

- TLS on a dedicated port (rustls server-side), same TLS-from-byte-zero model
  GtkHx already speaks. Reject HOPE-on-TLS as redundant, same as the client.
- Tracker registration (UDP heartbeat to v1 trackers; v3 registration once
  scoped against Argus).
- Rate limiting, flood protection, connection caps per IP, ban enforcement at
  accept time.
- Fuzz the frame decoder (`cargo-fuzz` against the session layer's read
  path); a server's parser meets far more hostile input than a client's.

## Phase 6 — Extensions (fogWraith)

In rough order of value-for-effort:

1. **Chat history — implemented 2026-09.** Server-held scrollback replay. As of mid-2026 no public
   server implements the spec (GtkHx tests against a mock); hxd-ng becoming
   the **first real implementation — and thus the reference** — is a strong
   motivator and instantly useful to GtkHx's own test matrix. **Designed
   2026-09 in [docs/chat-history.md](docs/chat-history.md)**: public chat
   becomes a log behind a `ChatLog` trait, stored as a second table in
   the inbox's SQLite file, with a line's id assigned before fan-out so
   the live event and the history entry are one fact on both wires; the
   ng wire gets a `history` request and ids on `chat` events. The first three
   stages are implemented and cross-wire tested; pointing GtkHx's history
   suite at the real server remains the client-side follow-up.
2. **Text-Encoding** (fogWraith `Capabilities-Text-Encoding.md`) — a
   legacy-wire client advertising bit 1 of `DATA_CAPABILITIES` speaks UTF-8
   in every text field; Mac Roman becomes the non-negotiating fallback.
   hxd-core is already UTF-8 internally (the spec's own requirement), so
   this is edge work in `hxd-session`: a per-connection encoding flag
   gating the conversion calls, CR↔LF normalization, and the capability
   echo. Do it early in this phase — it's the cheapest extension and every
   modern client benefits. A `DefaultTextEncoding`-style config (Shift-JIS
   / Latin-1 legacy communities) and HOPE `app_id` sniffing can follow.
3. **GIF icons, inline media, colored nicknames, emoji shortcodes** — mostly
   relay + capability bits, cheap once the capability negotiation exists.
   Inline media is the exception: the relay is cheap, the server-side
   decode-and-re-encode pipeline the spec mandates is not. **Designed
   2026-09 in [docs/inline-media.md](docs/inline-media.md)**: an
   `hxd-media` crate behind a `MediaCodec` trait and a Cargo feature, an
   in-memory handle store with relay-time authorisation sets, 750/751 on
   the legacy wire and `POST`/`GET /media` over HTTP on the ng port.
   Both bring the first durable *content*, so
   [docs/moderation.md](docs/moderation.md) (same date) adds redaction,
   revocation, purges and reports with an audit trail; the legacy wire
   receives reports as server messages and is moderated from ng or the
   CLI until fogWraith allocates the transactions.
4. **Voice** — an SFU, a genuinely large subsystem (this is where Janus has
   two known server-side bugs, both written up in the "Open" section of
   gtkhx's `docs/voice.md` — read them as a spec of what not to do).
   `hxproto::voice` (ICE/SDP JSON, participants blob) is shared
   already. **Pulled forward and designed 2026-09 in
   [docs/voice.md](docs/voice.md)**: the room state and policy live in
   `hxd-core` behind a `VoiceMedia` trait, the SFU is a separate
   `hxd-voice` crate on str0m, and — the reason it jumped the queue — the
   server *being* the SFU means legacy and Hotline-ng clients share a
   voice room for free; only the signalling is per-frontend. The
   capability-negotiation plumbing it needs (parse and echo
   `DATA_CAPABILITIES`) is the same plumbing Text-Encoding needs, so that
   lands first and both ride it. **Implemented 2026-09** and tested end to
   end against a real client.
5. **Video** — camera and screen share on top of the voice room, specced
   2026-09 in [docs/capabilities-video.md](docs/capabilities-video.md): a
   draft written in fogWraith's shape for upstream contribution as
   `Capabilities-Video.md`, plus the Hotline-ng binding. It reuses the
   voice SFU, peer connection, room and SDP path wholesale — the new wire
   surface is five control transactions and a status notification — and it
   degrades per client, so a voice-only or classic client is unaffected by
   a room that has video in it. Not started; the largest new pieces are
   keyframe/PLI plumbing (no analogue in an audio SFU) and, on the client
   side, video rendering.

## Phase 7 — Hotline-ng: the HTTP-era protocol, and the presence paradigm shift

*(Reordered ahead of clustering, 2026-08 — rationale at the end of this
section. **Opened early, in parallel with the legacy phases**, 2026-08:
rather than finishing full server parity first, the MVP — user list + chat,
enough for an immediately usable mobile app — is designed in
[docs/hotline-ng.md](docs/hotline-ng.md), which is the protocol spec and
staging plan. The full Phase 7 scope below remains the destination.)*

A second protocol frontend speaking to the *same* domain services as the
legacy one, so both populations share one chat, one user list, one file
area. This is the payoff of keeping wire types out of `hxd-core`'s API.

GtkHx's roadmap parks the successor-protocol idea as a social problem — a new
protocol needs a server. hxd-ng **is** the server, which un-parks it: design
the protocol here, implement it here, and clients (including a future mobile
app, and GtkHx itself) follow. Spec lives in this repo when the phase opens.

**The paradigm shift: sessions decouple from connections.** Being "on the
server" means holding an authenticated session, not a live socket. A user
authenticates once, appears on the roster, and stays there — **active** when
a realtime connection is attached, **idle** after inactivity, **detached**
when no connection is attached at all but the session lives on. Closing the
app no longer means leaving the server; it means going quiet.

The pieces:

1. **Protocol shape.** An HTTP API (auth, history, files, account) plus one
   authenticated WebSocket multiplexing realtime events — presence and
   roster diffs, typing indicators, chat lines, membership changes. TLS-only,
   Unicode by construction, token auth (short-lived access + refresh),
   reconnect-tolerant with resumable event cursors, pagination everywhere.
   Mobile-first means designing for the connection *dropping* as the normal
   case, not the error case.
2. **Offline delivery.** A durable per-user inbox: DMs and mentions that
   arrive while detached are stored and delivered on reconnect, with read
   state. This is what makes a detached user still meaningfully *targetable*.
   **Designed 2026-09 in
   [docs/private-messages.md](docs/private-messages.md)**, which takes the
   whole private-message story with it. The address is the account, keyed
   by its identity fingerprint where it has one and its login where it
   does not — a login is renameable and re-registrable, so keying mail on
   it alone eventually delivers someone's private message to a stranger,
   which is the recycled-uid trap one layer up. Every PM to an account
   with an inbox is persisted before the sender is acked, so a message
   handed to a dying socket stops being unrecoverable. The ng wire gains
   `to_login`, `inbox`, `msg_read`, message guids for safe retry, and a
   block list; the legacy wire
   receives queued messages but does not address accounts, because a
   period client's user list is the only place it can name a person.
   That document's §12 reconciles all of it with fogWraith's
   Capabilities-Messaging, whose offline queue is the same problem: the
   two are two callers of one store, and the friend graph is what
   `to_login` should inherit when it lands.

3. **Push notifications.** A `NotificationGateway` trait (APNs / FCM /
   UnifiedPush / WebPush behind it) plus a device-token registry. DM or
   mention while detached → push. Notification content policy (full text vs.
   "you have a message") is a config knob — self-hosters differ on this.
4. **The persistence slice arrives here** (moved from the old Phase 7):
   durable storage behind `AccountStore` and the new session/token, inbox,
   and push-registration stores. Detached sessions, offline messages and
   device tokens must survive a server restart, so durable storage stops
   being optional at exactly this phase. The account-file backend remains
   supported for legacy-only small servers. **The first durable store is
   SQLite** (`hxd-store-sqlite`, decided 2026-09 in
   docs/private-messages.md §4): it needs no daemon, so a small server
   gains offline messages without gaining an operations problem, and the
   trait boundary is the same one PostgreSQL arrives behind. Postgres is
   still where clustering points — Phase 8 needs a store several nodes can
   share, which SQLite is not.
5. **Legacy interop rules.** Detached users appear on the 1.x user list
   flagged away (the legacy wire's closest concept; whether to hide them
   instead is a config option). A legacy client's PM to a detached user is
   accepted, queued, and pushed — the sender's UX is unchanged. Typing
   indicators and read state never touch the legacy wire. Detached users
   hold a stable uid so replies and user-info keep working.
6. **Auth split.** New-protocol accounts get real password hashing (argon2).
   The recoverable-secret constraint applies only to accounts that want
   legacy-wire access — per-account, opt-in, documented.

**Why this comes before clustering:** the cluster's whole job is fanning out
events and reconciling presence across nodes — and this phase redefines what
presence *is* and what an event's audience *is* (sessions, not sockets).
Clustering built first would be built around the wrong model and reworked.
The dependency also runs only one way: this phase needs single-node Postgres,
which is a strict subset of what clustering needs anyway. No good reason to
resist the reorder.

## Phase 8 — Clustering

1. **Valkey** behind the EventBus (pub/sub) and as the shared presence
   cache — sessions and their attached-connection locations.
2. **Multi-node:** a node owns the connections attached to it; detached
   sessions are node-less rows in shared storage, which the Phase 7 model
   makes natural. Cross-node fan-out rides the Valkey bus; accounts, bans,
   news, inboxes live in Postgres; the file area needs shared storage or
   node-affinity for transfers; the push gateway is already stateless.
   A design doc (`docs/clustering.md`) before code — cache invalidation,
   split-brain on the ban list, and transfer routing all want thought, not
   improvisation.

---

## Testing

- **Unit + wire tiers** live with the code as usual; wire fixtures come from
  the shared `hotline-rs` corpus.
- **The killer asset: GtkHx's Tier 3 suite.** Its many integration tests
  already exercise login, chat, files, news, and tracker against real
  servers via Docker, and its multi-server matrix design anticipates adding
  targets. Add an `hxd-ng` container to that matrix and every green run is a
  conformance statement from a real client. Do this as soon as Phase 1
  stands.
- **Headless client harness** in `tests/`: a thin driver over `hxproto`
  (build requests, parse replies — no glib needed) for server-initiated
  scenario tests the client suite can't express (N clients, kick during
  transfer, flood limits).
- **Real-client smoke tests** against period clients (Mac Hotline 1.2.3 /
  1.5 under emulation) before each release tag — the point of the whole
  exercise.

---

## Decisions locked in

1. **Shared crates live in `hotline-rs`**, consumed by git-pin; gtkhx
   migrates onto it in Phase 0. (Decided 2026-08.)
2. **v1 milestone = chat core** (Phase 2). Files, news, extensions follow.
3. **Cluster stack: PostgreSQL + Valkey**, behind traits that ship with an
   in-memory/flat-file implementation first.
4. **GPL-2.0-or-later.**
5. **Legacy wire compatibility outranks everything** — same rank it holds in
   gtkhx.
6. **Auth secrets are recoverable by design** on the legacy path (HOPE HMAC
   requires it); documented, encrypted at rest, and *not* carried into the
   Hotline-ng protocol.
7. **Hotline-ng (Phase 7) lands before clustering (Phase 8)**, because it
   redefines presence as user-session-scoped and clustering must be designed
   against that model, not retrofitted to it. `hxd-core` models presence
   that way from day one. (Decided 2026-08.)

## Open questions

- Repo/crate naming: `hotline-rs` and `hxd-ng` are working names.
- Whether HOPE handshake logic gets promoted out of `hxnet` into a shared
  crate or reimplemented server-side (decide when Phase 2 starts, with the
  code open).
- Tracker v3 registration semantics (scope against Argus when Phase 5 nears).
- Whether to publish the `hotline-rs` crates to crates.io (separate from
  extraction; no rush while `publish = false`).
- Detached-user rendering on the legacy wire: away flag, hidden, or a
  distinct "sleeping" nickname decoration — and whether legacy admins can
  kick a detached session.
- Session lifetime policy: how long a detached session stays on the roster
  before it lapses (fixed TTL, per-account, or admin-set).
- ~~Which push providers ship first~~ — **answered 2026-08: UnifiedPush /
  Web Push.** It needs no vendor account, no certificate and no app-store
  presence, and RFC 8291 payload encryption means the content-policy knob
  leaks nothing to a third party — which APNs and FCM cannot say. (When
  first decided it was also the only uniqush backend that worked; since
  uniqush-push 2.8.0 FCM is verified and APNs probably works, so that
  argument has retired and the others carry it.) APNs/FCM follow when
  there is an app to receive them. See docs/push-notifications.md §3.
- How a mention is defined, given that Hotline nicks are neither unique nor
  stable — and whether mentions are in the first push cut at all, or DMs
  carry it alone (docs/push-notifications.md §11). The inbox design assumes
  DMs alone (docs/private-messages.md §9). **Still open for chat**, but
  news has answered it for itself: docs/news.md §10.5 notifies on a
  *reference*, which names an article rather than a nick, so the
  ambiguity never arises. "Cite the thing, not the person" is the shape
  to reach for if chat ever wants one.
- Whether an account's inbox stays server-local or follows the portable
  identity across servers (docs/private-messages.md §13).
- Where push coalescing lives (domain rate limit, gateway digest window, or
  vendor collapse keys) — twenty chat lines should not be twenty buzzes.
  **Answered for news** in docs/news.md §10.7: a scope rings only when
  its subscriber is caught up with it, which needs no timer because the
  read cursor already exists for the badge, with the vendor collapse key
  underneath it rather than instead of it. Chat has no per-scope cursor
  and no subscription, so it still wants the time-based answer.
