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

**License: GPL-2.0-or-later.** Forced and fine — `hotline-proto` is
hxd-derived and stays GPL (see gtkhx `docs/rust/crate-layout.md` §4), and a
Hotline server is exactly the audience that section says is already GPL.

---

## Phase 0 — Extract the shared crates into `hotline-rs` *(punted, 2026-08)*

**Status: deferred.** For now hxd-ng consumes the crates straight from the
gtkhx tree via path dependencies (`../gtkhx/rust/crates/...`) — the two
checkouts live side by side, the crates are `publish = false` anyway, and
Cargo resolves their workspace-inherited fields against gtkhx's workspace, so
this works with zero gtkhx changes. The extraction below remains the intended
end state; everything in it is still accurate when the time comes. Until
then: hxd-ng CI (when it exists) needs a gtkhx checkout beside it, and API
changes in the shared crates get coordinated across both trees by hand.

The original decision: the protocol crates move out of the gtkhx tree into a
shared repo (working name **`hotline-rs`**) that both gtkhx and hxd-ng depend
on. This deliberately reverses gtkhx's "no reusable libhotline" stance, and
per its own roadmap, updating that paragraph (and `crate-layout.md` §5) is
part of this phase, not an afterthought.

**What moves** (all currently pure — no glib/gtk/gio in their dependency
graphs, verified against their Cargo.tomls):

| Crate | Why the server needs it |
|---|---|
| `hotline-proto` | The core win. Symmetric parse **and** build for every opcode, 1.0–1.9, plus framing (header + chunk), Mac Roman ↔ UTF-8, HL dates, login, sanitize, dispatch tables. A server is just the other end of the same builders and parsers. |
| `hxcrypto` | Hash/stream/AEAD/compress primitives — the server side of HOPE, Blowfish OFB-64, ChaCha20-Poly1305, zlib. |
| `hxhfs` | CAP/AppleDouble/Netatalk resource-fork sidecars for the file area. |
| `hxfiles-xfer` | The FFO+FILP fork-header codec HTXF speaks. |

**What stays behind, and why:**

- `hxnet` — client connect lifecycle; also glib-coupled (`g_critical!` in FFI
  error paths, `hxbridge` runtime). The server writes its own network layer.
  If, during Phase 1–2, the HOPE handshake or HTXF subchannel logic in `hxnet`
  turns out to be cleanly host-agnostic, promoting those pieces into a shared
  `hotline-hope` / `hotline-htxf` crate is an option — but extract on demand,
  not speculatively.
- `hxtext`, `hxmacres` — glib-coupled; and the Mac Roman table the server
  needs already lives in `hotline-proto::text`.
- `hxtls-trust` — client-side TOFU. The server's TLS story is a rustls server
  config and a certificate, not a known-hosts store.
- `hxconfig` — gtkhx's settings schema, not generic.

**Mechanics** (this is the `crate-layout.md` §5 checklist, now actually due):

1. New repo, Cargo workspace, the four crates moved with history if
   convenient (`git filter-repo`) or flat-imported if not.
2. **Gate the C ABI behind a Cargo feature** (`capi`, default off). gtkhx
   enables it; hxd-ng and any other pure-Rust consumer never compiles the
   `#[no_mangle]` surface.
3. gtkhx switches to git dependencies pinned to a rev. Bumping the pin is a
   deliberate act with a CI run behind it.
4. **MSRV of the shared repo = gtkhx's Debian-stable pin.** hxd-ng itself can
   float newer, but the shared crates must keep building for gtkhx.
5. The Tier 1/Tier 2 tests that exercise these crates travel with them (the
   wire fixtures especially — they are the conformance corpus both projects
   now share). gtkhx keeps its integration tiers.
6. CI: `cargo fmt --check`, `clippy -D warnings`, tests, at both MSRV and
   stable.
7. Naming: keep the `hx*` / `hotline-proto` names for now; a rename is
   cosmetic churn while everything is `publish = false`. Publishing to
   crates.io is a separate later decision.
8. Update gtkhx's `docs/rust/ROADMAP.md` motivation paragraph and
   `crate-layout.md` §5, per their own instructions.

**Exit criteria:** gtkhx builds green against the pinned `hotline-rs` repo
with the four crates deleted from its tree; hxd-ng's empty workspace depends
on the same pin.

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
the write half. It frames the read stream with `hotline-proto` (**by
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

The access bitmap definitions come from `hotline-proto` / mhxd's headers —
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

`hxd-core` must stay free of `hotline-proto` types in its public API where
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
threads). Flat-file storage behind the store trait; mhxd's format is the
compat reference for an importer, not the native format.

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

1. **Chat history** — server-held scrollback replay. As of mid-2026 no public
   server implements the spec (GtkHx tests against a mock); hxd-ng becoming
   the **first real implementation — and thus the reference** — is a strong
   motivator and instantly useful to GtkHx's own test matrix.
2. **GIF icons, inline media, colored nicknames, emoji shortcodes** — mostly
   relay + capability bits, cheap once the capability negotiation exists.
3. **Voice** — an SFU, a genuinely large subsystem (this is where Janus has
   two known server-side bugs; the renegotiation one is documented in gtkhx's
   `docs/janus-voice-renegotiation-bug.md` — read it as a spec of what not to
   do). `hotline-proto::voice` (ICE/SDP JSON) is shared already; the
   pure-Rust `hxvoice` state machine may be partially reusable. Explicitly
   deferred until everything above is solid.

## Phase 7 — Hotline-ng: the HTTP-era protocol, and the presence paradigm shift

*(Reordered ahead of clustering, 2026-08 — rationale at the end of this
section.)*

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
3. **Push notifications.** A `NotificationGateway` trait (APNs / FCM /
   UnifiedPush / WebPush behind it) plus a device-token registry. DM or
   mention while detached → push. Notification content policy (full text vs.
   "you have a message") is a config knob — self-hosters differ on this.
4. **The persistence slice arrives here** (moved from the old Phase 7):
   PostgreSQL via `sqlx` behind `AccountStore` and the new session/token,
   inbox, and push-registration stores. Detached sessions, offline messages
   and device tokens must survive a server restart, so durable storage stops
   being optional at exactly this phase. The account-file backend remains
   supported for legacy-only small servers.
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
- **Headless client harness** in `tests/`: a thin driver over `hotline-proto`
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
- Which push providers ship first (UnifiedPush is the self-hosting-friendly
  one; APNs/FCM need app-store presence that doesn't exist yet).
