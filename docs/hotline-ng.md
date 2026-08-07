# Hotline-ng: the HTTP-era protocol — MVP design

The Phase 7 design, opened early and deliberately small: **user list and
chat**, the minimum a mobile app needs to be immediately usable. This
document is the protocol spec for that MVP plus the domain-layer changes it
requires. Everything else Phase 7 promises (durable inbox, push
notifications, real password hashing for ng-only accounts) extends this
design; nothing here needs to be redone for it.

Decisions taken at design time (2026-08): **WebSocket-only transport** with
in-band auth (no HTTP framework until media/history/push need one),
**detached sessions with resume are in the MVP** (they are the point of the
phase, and they cost no persistence), and **TLS terminates in a reverse
proxy** (nginx/caddy with real certificates; the server listens plaintext on
localhost and the spec mandates WSS in production).

---

## 1. What the MVP is

A mobile (or web, or CLI) client can: log in with a Hotline account or as a
guest, see the user list with live updates, read and send public chat
(including `/me` actions), receive server notices and broadcasts, survive
network blips without churning the roster, and log out. Legacy and ng users
see each other and chat together; neither knows the other is different.

A mobile client can also send and receive **private messages** — first-class
in the MVP: they cross to and from legacy clients, and a PM to a detached
session buffers and replays on resume, which is the closest thing the grace
window offers to offline delivery.

Out of scope for the MVP, listed so their absence is a decision and not an
oversight: private chats (rooms), news, files and transfers, account
administration, tracker anything, message history from before your session,
push notifications, and durable offline delivery.

## 2. The paradigm shift, concretely

Legacy Hotline: you are "on the server" while your TCP socket lives. This
protocol: you are on the server while your **session** lives; a WebSocket
*attaches* to the session. The states:

| State | Meaning | Legacy clients see |
|---|---|---|
| `active` | A connection is attached | normal |
| `idle` | Attached but quiet (future: client-set or timer) | away flag |
| `detached` | No connection; grace window running | away flag |

Closing the app puts you in `detached`, not gone. Reconnecting inside the
grace window (default **5 minutes**, config `[ng] grace`) resumes the same
session — same uid, no part/join churn, missed events replayed. If the
window lapses, the session ends exactly as a legacy disconnect would.

**Detaching is a per-account permission, and guests don't get it.** A
roster presence that outlives its connection is exactly what a spammer
wants — join as a guest with a URL for a nick, drop the socket, pollute the
user list for free. So: accounts carry a `can_detach` flag; without it, a
dropped WebSocket ends the session immediately (legacy behavior) and
`resume` answers `session_expired`. The default is derived, not hardcoded:
**password-protected accounts may detach, password-less ones (guest) may
not**, overridable per account either way (`[extra] can_detach = true` for
a trusted kiosk account, `= false` for a passworded account on probation).
Two backstops keep even permitted detaching bounded: at most **2 detached
sessions per source address** (config `[ng] max_detached_per_addr`; the
oldest is ended when exceeded), and admin moderation works on detached
users — they sit on the roster, so they can be kicked and banned like
anyone else, which ends the session on the spot.

The legacy mapping costs nothing: the wire color field is a bitfield in
practice — bit 1 is away, bit 2 is admin (0 normal, 1 away, 2 admin,
3 admin-away) — so `idle`/`detached` set the away bit and the 1.x user list
renders it natively. Legacy-side away state maps back to `idle` in ng
rosters. No legacy client changes, no extension bits.

## 3. Architecture placement

A second frontend crate, sibling to the legacy one:

```
                 ┌────────────────────────────────────────────┐
  TCP :5500 ────▶│ hxd-session   (legacy wire, Mac Roman,     │
                 │                server-formatted chat)      │
                 │        │                                   │
                 │        ▼                                   │
                 │     hxd-core   (UTF-8, semantic events,    │
                 │        ▲        user-scoped sessions)      │
                 │        │                                   │
  WS  :5700 ────▶│ hxd-ng-session (JSON/WebSocket, tokens,    │
  (wss:// via    │                 resume, outbox replay)     │
   proxy)        └────────────────────────────────────────────┘
```

`hxd-ng-session` depends on `hxd-core`, `tokio-tungstenite`, `serde`/
`serde_json`, and a CSPRNG for tokens. It never sees the legacy wire;
`hxd-session` never sees JSON. Chat stays **semantic in the domain** — the
legacy frontend applies the `\r%13.13s:  %s` formatting at its edge (as it
already does), and ng clients receive structured `{from, text, style}` and
render however they like. This split was built in Phase 2a on purpose; the
MVP is the payoff.

## 4. Domain-layer changes (the D-steps)

**D1 — UTF-8 at the domain boundary.** Today `hxd-core` carries nicks and
chat text as raw Mac Roman bytes. It flips to `String`: the legacy frontend
converts Mac Roman → UTF-8 on ingest and UTF-8 → Mac Roman (lossy `?` for
unmappable, truncate nicks to 31 bytes *after* conversion) on egress, via
`hotline_proto::text`. This is lossless for all legacy-origin text — Mac
Roman → UTF-8 is injective and round-trips exactly — and lossy only for
ng-origin text shown to legacy clients, which is unavoidable. The
kick-announcement `ChatLine` event becomes a semantic `Notice { cid, text }`
that each frontend formats (legacy: `\r<text>`; ng: a `notice` event).

**D2 — presence states.** `UserSession` gains
`status: Active | Idle | Detached`; `UserInfo` carries it; roster events
fire on transitions. The legacy frontend derives the wire color from
`(admin, status)` instead of storing it; the ng frontend serializes the
status string.

**D3 — the outbox.** The per-session event channel becomes a seq-stamped
outbox owned by the roster entry:

- Every event gets the session's next `seq` (u64, monotonic, starts 1).
- With a connection attached: deliver immediately (channel as today, now
  carrying `(seq, Event)`).
- Detached: buffer, bounded (default 512 events); overflow marks the buffer
  broken — a later resume is refused with `resync_required` rather than
  silently gappy.
- `Core::connection_lost(uid)` → status `Detached`, start buffering.
  `Core::end_session(uid)` → today's `detach` (parts chats, roster part).
  The legacy frontend keeps calling `end_session` on socket death —
  unchanged behavior; grace for legacy clients is pointless since no 1.x
  client can re-attach.
- A sweeper (tokio interval task owned by the binary, calling
  `Core::sweep_detached(now)`) ends sessions whose grace lapsed.

**D4 — session tokens** live in `hxd-ng-session`, not the domain: a registry
of `session_id → (token hash, uid, outbox handle)`. The domain doesn't know
what a token is.

**D5 — account extras.** The account files grow an `[extra]` section for
server-local policy that never crosses the wire — the same concept as
mhxd's `access_extra`, deliberately *not* bits in the access bitmap (those
are ecosystem-shared wire vocabulary; fogWraith already allocates upward
from 55, and squatting on reserved bits invites collisions). First key:
`can_detach`, defaulting to *has-a-password*. `Account` grows the resolved
flag; `AttachInfo` carries it into the roster so `connection_lost` can
consult it. The Phase 2a public-subject gate (currently approximated by the
admin bit) moves to `[extra] set_subject` here too, retiring that
deviation.

## 5. Transport and framing

One WebSocket endpoint (config `[ng] bind`, default `127.0.0.1:5700`,
disabled when absent). Text frames, one JSON object per frame. The server
sends WS pings; a connection that misses them long enough is treated as
lost (→ detached). TLS is the proxy's job; the server never speaks it.

Three JSON shapes, discriminated by their first key:

```jsonc
// Client → server request. id is client-chosen, echoed in the reply.
{ "id": 7, "req": "chat", "params": { "text": "hello" } }

// Server → client reply.
{ "reply": 7, "ok": { } }
{ "reply": 7, "error": { "code": "access_denied", "text": "…" } }

// Server → client event. seq is per-session, monotonic, gapless.
{ "seq": 42, "ev": "chat", "data": { } }
```

Requests are answered in order. Unknown `req` → `error` with code
`unknown_method`; unknown fields in `params` are ignored (forward compat);
unknown `ev` values must be ignored by clients (same rule). Error codes are
a closed set per method plus the universal `unknown_method`,
`not_logged_in`, `access_denied`, `bad_request`, `rate_limited`.

## 6. The handshake

The first request on a fresh socket must be `login` or `resume`, within the
login timeout.

**Login** (new session):

```jsonc
{ "id": 0, "req": "login", "params": {
    "login": "misha",        // omit or "" for guest
    "password": "…",         // omit for password-less accounts
    "nick": "Misha",         // honored only with use_any_name
    "icon": 128              // legacy icon id; optional
} }

{ "reply": 0, "ok": {
    "session": "s_9f2c44b1",         // public session id
    "token": "…base64url, 32 bytes…",// secret; store for resume
    "self": { "uid": 3, "nick": "Misha", "icon": 128,
              "admin": true, "status": "active" },
    "server": { "name": "My Server", "subject": "welcome!" },
    "users": [ { "uid": 1, "nick": "alice", "icon": 2,
                 "admin": false, "status": "active" }, … ],
    "detach": { "grace": 300 },      // null when the account can't detach —
                                     // the client then knows a resume will
                                     // never succeed and re-logins instead
    "seq": 0                          // events start at seq 1
} }
```

The roster snapshot rides in the login reply — a mobile client renders one
round-trip after connect. Failure codes: `login_failed` (wrong account or
password — deliberately one code), `banned`, `server_full`.

**Resume** (existing session):

```jsonc
{ "id": 0, "req": "resume", "params": {
    "session": "s_9f2c44b1", "token": "…", "last_seq": 41 } }

{ "reply": 0, "ok": { "replay": 3, "self": { … } } }
// followed immediately by events 42, 43, 44, then live traffic
```

Failure codes: `session_expired` (grace lapsed or token wrong — log in
again), `resync_required` (buffer overflowed; the session is still alive:
follow with `sync`, below, and continue from its returned seq). A resume
while another connection is attached takes the session over: the old
connection is closed with a `replaced` close code — last device wins, which
is the mobile-friendly answer.

**Sync** (recover from `resync_required` without losing the session):

```jsonc
{ "id": 1, "req": "sync" }
{ "reply": 1, "ok": { "server": { … }, "users": [ … ], "seq": 977 } }
```

## 7. Requests and events — the MVP set

Requests:

| `req` | params | ok | notes |
|---|---|---|---|
| `login` / `resume` / `sync` | above | above | handshake only |
| `chat` | `text`, `style?` (`"normal"`\|`"action"`) | `{}` | needs send-chat access; multi-line allowed, server relays as one event |
| `msg` | `to` (uid), `text` | `{}` | needs send-msgs access; same 4096-byte cap as chat; a detached recipient buffers it for replay |
| `nick` | `nick?`, `icon?` | `{}` | nick honored only with use_any_name |
| `ping` | — | `{}` | keepalive for clients that want RTT |
| `logout` | — | `{}` | ends the session *now* (no grace) |

Events (all carry `seq`):

| `ev` | data | mirrors domain event |
|---|---|---|
| `user_joined` | `{ user }` | `Joined` |
| `user_changed` | `{ user }` | `Changed` (includes status transitions) |
| `user_parted` | `{ "uid": n }` | `Parted` |
| `chat` | `{ "from": {uid, nick}, "text", "style" }` | `Chat` (cid 0 only in MVP) |
| `notice` | `{ "text" }` | `Notice` |
| `subject` | `{ "subject" }` | `ChatSubject` (cid 0) |
| `broadcast` | `{ "from": {uid, nick}, "text" }` | `Broadcast` |
| `kicked` | `{}` | `Kicked`; server then closes, session ends |

A `user` object is `{ uid, nick, icon, admin, status }`. Uids remain the
16-bit legacy ids so the two rosters are one roster.

Events that exist in the domain but have no ng mapping yet (the
private-chat room family) are delivered to ng sessions as placeholder
frames the client ignores, keeping seq accounting gapless.

## 8. Text, encoding, limits

The protocol is UTF-8 by construction (it's JSON). Normative limits, chosen
to keep the legacy bridge sane: nick ≤ 31 bytes *in its Mac Roman form*
(the server truncates at the legacy edge and reports the ng-side nick
untruncated), chat text ≤ 4096 bytes per request, subject ≤ 255 bytes.
Chat text crossing to legacy clients is converted with `?` for unmappable
characters — tell your users their emoji become question marks on
twenty-five-year-old Macs, which is honestly part of the charm.

**The legacy wire itself can negotiate UTF-8.** fogWraith's
[Text-Encoding extension](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Text-Encoding.md)
defines `CAPABILITY_TEXT_ENCODING` (bit 1 of `DATA_CAPABILITIES`, field
`0x01F0`): a legacy-wire client that advertises it, and gets the bit echoed
in the login reply, exchanges UTF-8 in every text field — Mac Roman becomes
the fallback for clients that don't negotiate, exactly the per-connection
bridge that spec mandates ("servers MUST store all text internally as
UTF-8", which is what hxd-core now does). Implementing it is legacy-frontend
work, tracked on the roadmap: the conversion calls at `hxd-session`'s edges
become conditional on a per-connection encoding flag, plus the spec's
CR↔LF line-ending normalization (internal text uses LF; legacy Mac clients
get CR). Its future HOPE `app_id` refinement (per-client encoding guesses
for Shift-JIS/Latin-1 legacy clients) can ride the HOPE work when that
lands.

## 9. Security posture

- WSS mandatory in production; the plaintext listener binds localhost by
  default and the docs say why.
- Tokens: 32 bytes from the OS CSPRNG, stored server-side as a SHA-256
  hash, compared in constant time. A token is a bearer credential for one
  session, dies with it, and never appears in logs.
- Auth reuses the `AuthBackend` trait as-is (plaintext-equivalent secrets —
  the legacy constraint, documented there). ng-only accounts with argon2
  arrive with the database backend, not the MVP.
- Rate limiting: per-connection request cap (token bucket, config) from day
  one — this endpoint faces phones on the open internet, a harsher place
  than port 5500. Login attempts per address are separately capped.
- The ban list applies at WS accept exactly as at legacy accept.
- Roster pollution is bounded three ways: `can_detach` is per-account and
  off for guests (§2), detached sessions are capped per source address,
  and a kick or ban of a detached user ends its session immediately — the
  kick path must call `end_session` directly when no connection is attached
  to receive the event.

## 10. Implementation stages

Each lands separately with tests, roughly a branch apiece:

1. **N1 — domain prep**: D1 (UTF-8 + `Notice`), D2 (status), with the
   legacy frontend updated at its edges. Pure refactor, legacy Tier-3-style
   e2e stays green — this is the step most likely to shake out bugs, do it
   alone.
2. **N2 — outbox + policy**: D3 (`seq`, buffering, `connection_lost` /
   `end_session` / `sweep_detached`, the per-address detached cap, the
   kick-while-detached path) and D5 (`[extra] can_detach` with the
   has-a-password default). Unit-tested in `hxd-core` /`hxd-auth-file`
   without any network.
3. **N3 — the frontend**: `hxd-ng-session` crate — WS accept, handshake,
   token registry (D4), request dispatch, event encoding; binary config
   (`[ng] bind`, `grace`) and the sweeper task. E2E with a scripted
   tokio-tungstenite client.
4. **N4 — cross-frontend e2e**: legacy scripted client + ng scripted client
   on one server — mutual roster visibility, chat both ways with correct
   formatting/conversion, detached-shows-away on the legacy list, resume
   replay after a dropped WS, grace expiry parts both rosters, kick over ng.
5. **N5 — polish for a real app**: rate limits, close codes, the `replaced`
   takeover path, and a `docs/hotline-ng-client.md` quickstart for whoever
   writes the mobile app (likely us).

## 11. Future extensions (design hooks, no work now)

- **Push + offline inbox** (the rest of Phase 7): a `NotificationGateway`
  registration request, and the outbox growing a durable tail in Postgres —
  the seq/replay model is already the right substrate.
- **History**: `{ "req": "history", "params": { "before_seq", "limit" } }`
  once chat lines persist; the event shape doesn't change.
- **Private chats**: the domain events exist; ng needs a `cid` field on
  `chat`/`subject` events and room-lifecycle requests.
- **Capabilities**: the login reply grows a `caps: [...]` list the moment
  any of the above ships, so clients feature-detect instead of
  version-sniff.
- The hotline-rs org's protocol work, if it converges here: this spec is
  the artifact to share — it's implementation-independent and the org's
  server could adopt it wholesale.

## 12. Open questions

- Idle: client-set (`{"req":"status"}`), server inactivity timer, or both;
  and whether legacy away toggling (the 0x0ea1 rider) should round-trip
  into ng `idle`.
- Whether the roster should distinguish "same user, multiple sessions"
  before the multi-device future arrives, or let each login be its own
  roster row (MVP does the latter).
- Guest nick collisions: legacy servers allow duplicate nicks; mobile UX
  may want uniqueness. MVP inherits the legacy answer (duplicates fine).
