# Hotline-ng: design rationale

Status: companion to [hotline-ng.md](hotline-ng.md), which is the
normative protocol. This document is how that protocol came to be what it
is and how hxd-ng builds it: the decisions and the arguments for them, the
domain-layer changes the MVP needed, and the order it was built in. It
binds nobody. Where the two disagree, hotline-ng.md is right and this
document is stale.

Section numbers here are this document's own. The spec cites them as
"rationale §n".

---

## 1. Decisions taken at design time

The Phase 7 design was opened early (2026-08) and kept deliberately
small: **user list and chat**, the minimum a mobile app needs to be
immediately usable. Everything else Phase 7 promises — a durable inbox,
push notifications, real password hashing for ng-only accounts — extends
that design, and none of it needed the MVP redone.

Three decisions were taken up front:

- **WebSocket-only transport, with in-band auth.** No HTTP framework until
  media, history or push needed one. Authentication was the first to need
  one (`hotline-ng-auth-rationale.md` §2), and the ng port now carries a small HTTP
  router in front of the upgrade.
- **Detached sessions with resume are in the MVP.** They are the point of
  the phase, and they cost no persistence.
- **TLS terminates in a reverse proxy.** nginx or caddy with real
  certificates; the server listens plaintext on localhost, and the spec
  mandates WSS in production.

The MVP's scope: log in with an account or as a guest, see the user list
with live updates, read and send public chat (including `/me` actions),
receive notices and broadcasts, survive network blips without churning
the roster, and log out — with legacy and ng users seeing each other and
neither knowing the other is different. Private messages were in it from
the start, crossing to and from legacy clients; a PM to a detached
session buffers and replays on resume, which is the closest thing the
grace window offers to offline delivery.

Out of scope for the MVP, listed so their absence was a decision and not
an oversight: private chats (rooms), news, files and transfers, account
administration, tracker anything, message history from before your
session, push notifications, and durable offline delivery. History, the
durable inbox, news and files have since been built on top of the MVP
rather than into it.

## 2. Sessions, not sockets

Legacy Hotline: you are "on the server" while your TCP socket lives. This
protocol: you are on the server while your **session** lives, and a
WebSocket *attaches* to it. Closing the app puts you in `detached`, not
gone; reconnecting inside the grace window resumes the same session —
same uid, no part/join churn, missed events replayed. If the window
lapses, the session ends exactly as a legacy disconnect would.

**Why guests don't detach.** A roster presence that outlives its
connection is exactly what a spammer wants: join as a guest with a URL
for a nick, drop the socket, pollute the user list for free. So detaching
is a per-account permission, and its default is derived rather than
hardcoded — password-protected accounts may, password-less ones may not —
overridable per account either way (`[extra] can_detach = true` for a
trusted kiosk account, `= false` for a passworded account on probation).
The per-address cap and moderation of detached users are the two
backstops that keep even permitted detaching bounded. Behind a reverse
proxy the address is the one the proxy forwards (`hotline-ng-identity.md`
§5.3), since otherwise every client shares the proxy's.

**Why the legacy mapping costs nothing.** The wire's color field is a
bitfield in practice — bit 1 is away, bit 2 is admin (0 normal, 1 away,
2 admin, 3 admin-away) — so `idle` and `detached` set the away bit and
the 1.x user list renders it natively. No legacy client changes, no
extension bits.

**Why last device wins.** A resume while another connection is attached
takes the session over. A phone that roamed from Wi-Fi to cellular has
a new socket and a stale one the server has not yet noticed is dead;
refusing the new one would strand the user until the old one timed out.

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

`hxd-ng-session` never sees the legacy wire; `hxd-session` never sees
JSON. Chat stays **semantic in the domain** — the legacy frontend applies
the `\r%13.13s:  %s` formatting at its edge, and ng clients receive
structured `{from, text, style}` and render however they like. That split
was built in Phase 2a on purpose; the MVP is the payoff.

## 4. Domain-layer changes (the D-steps)

**D1 — UTF-8 at the domain boundary.** `hxd-core` carried nicks and chat
text as raw Mac Roman bytes. It flipped to `String`: the legacy frontend
converts Mac Roman → UTF-8 on ingest and UTF-8 → Mac Roman (lossy `?` for
unmappable, truncate nicks to 31 bytes *after* conversion) on egress, via
`hxproto::text`. This is lossless for all legacy-origin text — Mac
Roman → UTF-8 is injective and round-trips exactly — and lossy only for
ng-origin text shown to legacy clients, which is unavoidable. The
kick-announcement `ChatLine` event became a semantic `Notice { cid, text }`
that each frontend formats (legacy: `\r<text>`; ng: a `notice` event).

**D2 — presence states.** `UserSession` gained
`status: Active | Idle | Detached`; `UserInfo` carries it; roster events
fire on transitions. The legacy frontend derives the wire color from
`(admin, status)` instead of storing it; the ng frontend serializes the
status string.

**D3 — the outbox.** The per-session event channel became a seq-stamped
outbox owned by the roster entry:

- Every event gets the session's next `seq` (u64, monotonic, starts 1).
- With a connection attached: deliver immediately, the channel carrying
  `(seq, Event)`.
- Detached: buffer, bounded (`OUTBOX_BUFFER_CAP`); overflow marks the
  buffer broken — a later resume is refused with `resync_required` rather
  than silently gappy.
- `Core::connection_lost(uid)` → status `Detached`, start buffering.
  `Core::end_session(uid)` parts chats and the roster. The legacy
  frontend keeps calling `end_session` on socket death — unchanged
  behavior; grace for legacy clients is pointless since no 1.x client can
  re-attach.
- A sweeper (a tokio interval task owned by the binary, calling
  `Core::sweep_detached`) ends sessions whose grace lapsed.

**D4 — session tokens** live in `hxd-ng-session`, not the domain: a
registry of `session_id → (token hash, uid, serial)`. The domain doesn't
know what a token is.

**D5 — account extras.** The account files grew an `[extra]` section for
server-local policy that never crosses the wire — the same concept as
mhxd's `access_extra`, deliberately *not* bits in the access bitmap
(those are ecosystem-shared wire vocabulary; fogWraith allocates upward
from 55, and squatting on reserved bits invites collisions). First key:
`can_detach`, defaulting to *has-a-password*. `Account` carries the
resolved flag and `AttachInfo` carries it into the roster so
`connection_lost` can consult it. The Phase 2a public-subject gate moved
to `[extra] set_subject` in the same step. `access-bits.md` §4 is the
current list.

## 5. Why the wire looks like this

Notes against the spec's rules, in its order.

**Requests are answered in order** (spec §5) because that is the cheapest
promise to keep: hxd-ng handles each request inline and writes the reply
before reading the next, and a client never has to match replies out of
order.

**The roster snapshot rides in the login reply** (spec §6.1) so a mobile
client renders one round trip after connect.

**`login_failed` is one code** for a wrong account and a wrong password,
so the login request cannot be used to enumerate accounts. `denied` is a
different code because it is a different thing: an identity socket sends
no credentials, so nothing about a login failed, and a client told
`login_failed` would retry with a password it does not need.

**Stored mail follows the reply, never precedes it** (spec §6.3). `seq`
is what the client says it is at, so anything the server emits ahead of
that number is something the client has just been told it is past. A
`resume` answered `resync_required` therefore flushes nothing itself: the
flush comes after `sync`, whose seq the client will honor. Flushing at
the resume would mark mail delivered and then have the client skip it,
which is the one way a stored message can be lost outright.

**Nothing at or below `sync`'s seq arrives after its reply** (spec §6.3).
A reply and an event share one socket, so a server whose reply can
overtake an event the session was already handed reports a number the
client is not in fact past — and a client doing the natural thing,
dropping what it has already seen by seq, would drop a message the store
has marked delivered. hxd-ng makes the promise true rather than likely:
seq assignment and channel enqueue are one atomic operation under the
roster lock, so reading the session's seq and draining its pending events
ahead of the reply leaves everything at or below the snapshot sent, and
anything enqueued later has a higher seq. The alternative rule for
clients — never discard an event by seq — is weaker, which is why the
spec puts the obligation on the server.

**The connection loop prefers events to requests.** For the same reason:
without that bias the two race for one sink, and a `sync` reply could go
out ahead of an event whose seq it says the client is past. The cost is
that a link slower than a room can keep the event arm busy and delay
requests; each write is bounded by the pong deadline, so a dead peer
still ends.

**Placeholders, not holes** (spec §3). Skipping an event the ng wire
can't express would leave a gap in the seq stream a client could not
tell from loss, and resume's `last_seq` accounting would break.

**The `msg` reply hides the id** (spec §7.1). The message id is the
*recipient's* handle for marking read; handing a monotonic id to the
sender would tell them how much mail the server carries.

**`guid` answers as of now** (spec §7.1). A retry of a message that
queued, sent after the recipient arrived, is delivered by that retry; the
answer describing the original send would be describing a message that
no longer exists in that state.

**One error for three absences** (spec §7.1). `no_such_user` covers "no
such account", "that account takes no offline messages" and "no such
uid", so none can be told from the others from outside. `no_inbox` is
separate because it is about *your* account, which you already know.

**`blocks` lists objects rather than logins.** A block can be held
against an identity that logged in as a guest: its login is `guest` and
the fingerprint is what tells it apart, so a list of logins would name
something `unblock` could not resolve once that guest had left.

**Nicks are bounded in characters.** The legacy field is 31 bytes of Mac
Roman, and every character converts to exactly one Mac Roman byte or to
`?`, so 31 characters is the same bound counted before the conversion. A
longer nick is truncated once, on the way in, and every viewer sees the
same one; counting UTF-8 bytes instead cut a 28-character accented nick
that a 1.x client carries whole.

**Emoji become question marks** on the legacy side, which is unavoidable
and honestly part of the charm; tell your users.

**Markdown is a client affair.** GtkHx renders a conservative subset of
markdown in chat on receipt (GtkHx's `docs/chat-view.md` §4) and hx-ng
renders the same one, ported from the same scanner with the same tests,
so a line reads the same in both. None of it is on the wire: the server
neither parses nor rewrites chat text, and a legacy client sees the
asterisks. A news article is different, because its body says what it is.

**A client may declare itself less safe than it looks, never more**
(spec §7). `transport` is `"cleartext"` for a legacy client on plain TCP,
or when a tunnel told the server at `/identity/auth` that its own
downstream hop is cleartext. The roster carries it so a client can warn
before a private message goes somewhere unencrypted without
feature-detecting anything.

## 6. The legacy wire's own UTF-8

Not part of the ng protocol, but the reason the ng protocol's UTF-8
interior costs the legacy wire nothing. fogWraith's
[Text-Encoding extension](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Text-Encoding.md)
defines `CAPABILITY_TEXT_ENCODING` (bit 1 of `DATA_CAPABILITIES`, field
`0x01F0`): a legacy-wire client that advertises it, and gets the bit
echoed in the login reply, exchanges UTF-8 in every text field, with Mac
Roman the fallback for clients that don't negotiate — exactly the
per-connection bridge that spec mandates ("servers MUST store all text
internally as UTF-8", which is what hxd-core does). hxd-ng implements it:
the conversion calls at `hxd-session`'s edges go through a
per-connection encoding fixed at login, plus the spec's CR↔LF
normalization at egress (a body reaches a UTF-8 client with LF and a Mac
Roman one with CR, whatever its sender typed). The HOPE `app_id`
refinement — per-client encoding guesses for Shift-JIS and Latin-1 legacy
clients — can ride the HOPE work when that lands.

## 7. Implementation stages

Each landed separately with tests, roughly a branch apiece:

1. **N1 — domain prep**: D1 (UTF-8 and `Notice`), D2 (status), with the
   legacy frontend updated at its edges. A pure refactor with the legacy
   e2e kept green — the step most likely to shake out bugs, so done
   alone.
2. **N2 — outbox and policy**: D3 (`seq`, buffering, `connection_lost` /
   `end_session` / `sweep_detached`, the per-address detached cap, the
   kick-while-detached path) and D5 (`[extra] can_detach` with the
   has-a-password default). Unit-tested in `hxd-core` and `hxd-auth-file`
   without any network.
3. **N3 — the frontend**: the `hxd-ng-session` crate — WS accept,
   handshake, token registry (D4), request dispatch, event encoding; the
   binary's `[ng]` config and the sweeper task. E2E with a scripted
   tokio-tungstenite client.
4. **N4 — cross-frontend e2e**: a legacy scripted client and an ng
   scripted client on one server — mutual roster visibility, chat both
   ways with correct formatting and conversion, detached-shows-away on
   the legacy list, resume replay after a dropped WS, grace expiry
   parting both rosters, kick over ng.
5. **N5 — polish for a real app**: rate limits, close codes, the
   `replaced` takeover path, and a client quickstart for whoever writes
   the mobile app. The close codes and takeover are built; the general
   rate limits and the quickstart are not.

## 8. Future extensions

- **Push and the durable tail.** Device registration is specified
  (`push-notifications.md` §8) and the offline inbox is built; what
  remains is the outbox growing a durable tail — the seq/replay model is
  already the right substrate.
- **Private chats**: the domain events exist; ng needs a `cid` field on
  `chat` and `subject` events and room-lifecycle requests. Voice already
  carries `cid` on every request and event, so nothing there changes.
- **Moderation**: designed in `moderation.md` §5 — a `report` request for
  anyone, `redact`/`revoke`/`purge`/`kick` and the report queue for
  moderators, and `chat_redacted`/`media_revoked` events so a client can
  blank what it already drew.
- **Convergence.** The hotline-rs org's protocol work, if it converges
  here: hotline-ng.md is the artifact to share — it is
  implementation-independent and another server could adopt it wholesale.
