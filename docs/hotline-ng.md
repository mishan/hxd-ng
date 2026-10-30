# Hotline-ng: the WebSocket protocol

Status: built — the core below, plus history (chat-history.md), the
inbox (private-messages.md), news (news.md), media (inline-media.md),
voice and video (voice.md, capabilities-video.md), files (§7.2),
identity (hotline-ng-identity.md), and signed lines, articles and
private messages that are not sealed, rooms that require signing
(e2e-messages.md §4.6 to §4.12), and instant messaging (§7.5). The vouch
requests and the `*@host` ban entry are design not yet built in hxd-ng,
and say so where they appear.

> **Conformance language:** The key words "MUST", "MUST NOT", "REQUIRED",
> "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
> "OPTIONAL" in this document are to be interpreted as described in
> [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

This document is normative. It states rules and cites their reasons
rather than arguing them: the reasoning, the design history and how
hxd-ng builds the protocol are in
[hotline-ng-rationale.md](hotline-ng-rationale.md), cited as
"rationale §n". Values marked *hxd-ng* are that server's choices, given
so a client author knows what to expect from it; they are not
requirements on other servers.

---

## Contents

1. [Scope and conformance](#1-scope-and-conformance)
2. [Sessions and presence](#2-sessions-and-presence)
3. [Event sequencing](#3-event-sequencing)
4. [Capabilities and extension families](#4-capabilities-and-extension-families)
5. [Transport and framing](#5-transport-and-framing)
6. [The handshake](#6-the-handshake)
7. [Requests and events](#7-requests-and-events)
8. [Text and limits](#8-text-and-limits)
9. [Security](#9-security)
10. [Error codes](#10-error-codes)
11. [Obligations checklist](#11-obligations-checklist)
12. [Open questions](#12-open-questions)

---

## 1. Scope and conformance

Hotline-ng is a JSON protocol over WebSocket for Hotline servers. It is
designed for clients whose connections come and go — phones first — and
it shares one roster, one chat and one mail system with the classic
Hotline wire on the same server: a classic client and an ng client see
each other and talk to each other without either knowing the other is
different.

This document specifies:

- sessions that outlive their connections (§2) and the seq accounting
  that makes resuming one exact (§3);
- the capability list and the extension families it advertises (§4);
- framing (§5), the handshake (§6), the core requests and events (§7),
  text limits (§8), security requirements (§9) and error codes (§10).

Each extension family is specified in its own document (§4); this one
specifies only what they have in common. Authentication before the
upgrade, and the identity a socket carries into it, are specified in
[hotline-ng-auth.md](hotline-ng-auth.md) and
[hotline-ng-identity.md](hotline-ng-identity.md).

**A conforming server** implements §2, §3 and §5–§9, and answers every
request it receives (§5). It MAY implement any extension family, and
MUST advertise in `caps` (§4) exactly the families it serves.

**A conforming client** follows every client requirement of §2–§10
(§11 summarizes them), and MUST tolerate everything this document says may be added: unknown
fields, unknown events, unknown capabilities and unknown error codes.

Examples are JSON with comments (`jsonc`); the wire carries plain JSON.
"Absent" means the key is not in the object; it is not the same as
`null` unless the field's definition says so.

## 2. Sessions and presence

A **session** is a user's presence on the server: a uid on the roster, an
outbox of events (§3) and a secret token. A WebSocket **attaches** to a
session; the session is not the connection, and it may outlive it.

| `status` | Meaning |
|---|---|
| `active` | A connection is attached. |
| `idle` | A connection is attached, but the user is away. *Reserved: nothing sets it yet, in hxd-ng or in this document (§12).* |
| `detached` | No connection is attached; the grace window is running. |

**Detaching.** When a connection is lost without `logout`, the server
MUST either end the session — exactly as a classic disconnect would — or
detach it. A detached session stays on the roster with status
`detached`, keeps its uid, and buffers its events (§3). If no connection
resumes it within the **grace window**, the server MUST end it.

- The login reply's `detach` field (§6.1) tells the client which will
  happen: `{ "grace": <seconds> }` when this session may detach, `null`
  when it never will. A client given `null` MUST NOT attempt `resume`;
  it logs in again instead.
- Whether a session may detach is server policy. A server SHOULD NOT let
  a session with no password or identity detach (rationale §2). *hxd-ng:*
  per account, `[extra] can_detach`, defaulting to "has a password".
- A server SHOULD cap detached sessions per source address, ending the
  oldest when the cap is exceeded. *hxd-ng:* `[ng] max_detached_per_addr`,
  default 2.
- *hxd-ng:* `[ng] grace`, default 300 seconds.

**Moderating detached sessions.** A detached session is on the roster and
MUST be subject to kick and ban like any other. Kicking or banning one
MUST end it immediately; there is no connection to deliver `kicked` to.

**Takeover.** A `resume` of a session that already has a connection
attached MUST succeed if the token is valid (last device wins, rationale
§2). The server MUST close the previous connection with WebSocket close
code 1008 and reason `replaced`.

**Legacy presentation.** A session whose status is `idle` or `detached`
MUST be shown to classic clients with the away bit set in the user list's
color field.

**Uids** are the classic wire's 16-bit user ids, shared by both
populations: the two rosters are one roster. A uid identifies a session
only while that session lives; uids are reused.

## 3. Event sequencing

Every server-to-client event carries `seq`, an unsigned integer scoped to
the session.

- The first event of a session MUST have `seq` 1, and each later event
  MUST have exactly the previous `seq` plus one. Seqs are never reused
  within a session and never reset while it lives, across any number of
  resumes.
- A server MUST NOT skip a seq. An event the server has to deliver but
  cannot express on this wire — because the family it belongs to has no
  ng binding yet — MUST still be sent, with a placeholder `ev` the client
  does not recognize. *hxd-ng:* `{ "seq": n, "ev": "unsupported", "data": {} }`.
- A client MUST ignore an event whose `ev` it does not recognize, and MUST
  still count its `seq` as received.
- While a session is detached, the server buffers its events. The buffer
  MAY be bounded (*hxd-ng:* 512 events). When a bounded buffer overflows,
  the server MUST mark the session as unable to replay: a later `resume`
  is answered `resync_required` (§6.2), never a partial replay.
- A server MAY bound what it holds for an attached connection too, and
  close a connection whose client does not keep up. The session is then
  as if the connection had been lost, except that the events sent to it
  unread cannot be replayed: a later `resume` is answered
  `resync_required`. *hxd-ng:* 8192 events or 16 MiB behind, whichever
  comes first.

Replies do not carry `seq` and are not counted.

## 4. Capabilities and extension families

The login reply carries `caps`, an array of capability names. It MUST be
present, and empty when the server offers no extensions. A client MUST
ignore names it does not recognize.

A capability says a family of requests will be answered; it is not a
switch the client turns on. A server that does not serve a family MUST
answer that family's requests with an error — `unknown_method` or the
family's own "not available" code — and MUST NOT close the connection
over them.

| `caps` name | Family | Specified in | Login reply block |
|---|---|---|---|
| `history` | Server-held chat scrollback: the `history` request | §7 here; chat-history.md §7 | `history` |
| `inbox` | Durable private messages: `inbox`, `msg_read`, `block`, `unblock`, `blocks`, and `msg` to an absent account | §7.1 here; private-messages.md §6 | `inbox` |
| `media` | Images in chat and private messages; bytes over HTTP | inline-media.md §8 | `media` |
| `news` | Threaded news, subscriptions and `news_notify` | news.md §9, §10.9 | `news` |
| `voice` | Voice rooms | voice.md §8 | — |
| `video` | Camera and screen publications, layered on voice | capabilities-video.md, "Hotline-ng Binding" | `video` |
| `files` | The file area | §7.2 here | `files` |
| `identity` | The server has the identity endpoints of hotline-ng-auth.md | hotline-ng-identity.md §6.1 | fields in `self`, on a socket that authenticated with one |
| `push` | Push device registration | push-notifications.md §8; webpush-gateway.md §7 | `push` |
| `avatars` | Users' pictures: `avatar` on the `user` object, `avatar_clear`, bytes over HTTP | avatars.md §4 | `avatars` |
| `banner` | The server banner: where its image is, where a click goes, and `GET /banner` | banner.md §3 | `banner` |
| `accounts` | Account administration: `account_list`, `account_get`, `account_create`, `account_update`, `account_delete`, and `account_changed` | account-admin.md §5 | `accounts` |
| `roles` | Roles: `roles` on the `user` and account objects, `role_list`, `role_get`, `role_create`, `role_update`, `role_delete`, `roles_changed` and `roster_stale` | roles.md §7 | `roles`, and in `sync`'s reply |
| `rooms` | Curated rooms: `rooms`, `room_*`, `room` on `chat` and `history`, and the `room_*` events | chat-rooms.md §7 | `rooms`, and in `sync`'s reply |
| `chat_guid` | `guid` on `chat` honored: a repeat is the line it repeats, and the reply carries the line's `id` | §7.3 here | — |
| `messaging` | Friends, presence, instant messages and message requests: `friends`, `friend_*`, `presence`, `find_user`, `user_profile`, `receipt`, `typing`, `requests`, `request_answer`, `requests_clear`, their events, and `msg` by `to_login` as an instant message or a request | §7.5 here; instant-messaging.md | `messaging` |
| `friendships` | Portable friendships: offers, friendships and withdrawals on the `messaging` family's requests and events, `friendships_present` and `friendships_fetch`. Listed only to a login that asked for it (§7.5) | §7.5 here; proposals/portable-friends.md | — |
| `signed` | Signed lines, messages and articles: `signed` on `chat`, `msg`, `report` and, with `news`, `news_post`, and on the events, listings and articles that carry them; `signs` at login and its request; rooms that require signing (`signed` on the room object, chat-rooms.md §5.2). Only with `chat_guid`, a `server_key` and `[identity] hosts` | e2e-messages.md §4.6 | `signs`, echoed |

- `video` MUST NOT appear without `voice`.
- `friendships` MUST NOT appear without `messaging`.
- A login reply block is present exactly when its capability is, except
  where the family's own document says otherwise.
- Each family's document is normative for its requests, events, error
  codes and login block; this document does not repeat them.

## 5. Transport and framing

**Endpoint.** The protocol runs on a WebSocket upgraded from an HTTP/1.1
`GET`. *hxd-ng:* on the ng listener (`[ng] bind`, default
`127.0.0.1:5700`, disabled when absent), at the paths `/` and `/ng`. The
same listener serves the HTTP endpoints of hotline-ng-auth.md, the
inline-media and news-attachment byte routes, and the TRTP tunnel.

**Frames.** Each message is one WebSocket **text** frame holding one
JSON object. A client MUST NOT send binary frames; a server MUST ignore
them. A server MAY close the connection on a text frame that is not a
request object as specified below. *hxd-ng* does, and treats it as a
lost connection (§2); it does the same for a message larger than 256 KiB.

There are three message shapes, told apart by their keys:

```jsonc
// Client → server: a request. id is client-chosen and echoed in the reply.
{ "id": 7, "req": "chat", "params": { "text": "hello" } }

// Server → client: a reply, exactly one of ok or error.
{ "reply": 7, "ok": { } }
{ "reply": 7, "error": { "code": "access_denied", "text": "…" } }

// Server → client: an event (§3).
{ "seq": 42, "ev": "chat", "data": { } }
```

- `id` MUST be a non-negative integer that fits in 64 bits. Clients
  SHOULD NOT reuse one while its reply is outstanding.
- `params` MAY be omitted for a request that takes none. A client
  SHOULD send `{}` rather than omit `params` for a request whose params
  are all optional; a server SHOULD accept the omission, and MUST accept
  it where this document says so (`login`, `history`, `inbox`). A request
  whose `params` are present but malformed MUST be answered
  `bad_request`.
- The server MUST answer every request with exactly one reply, and MUST
  answer requests in the order they were received (rationale §5). A
  request still outstanding when the connection closes — lost, or closed
  by the server after `kicked` — goes unanswered; a client MUST treat it
  as failed.
- A server MUST ignore fields in `params` it does not recognize. A client
  MUST ignore fields in `ok`, in `error` and in event `data` it does not
  recognize.
- An error object has a `code`, from the closed sets of §10 and the
  family documents, and a `text` for a human. Clients MUST act on `code`
  and MUST NOT parse `text`.

**Keepalive.** The server SHOULD send WebSocket pings, and MAY treat a
connection from which it has received no frame at all — pongs included —
for several ping periods as lost. *hxd-ng:* a ping every 30 s, and lost
after 90 s of silence; a send that blocks for 90 s is also a lost
connection. Clients MUST answer pings (every WebSocket library does).

**Close codes** the server uses:

| Code | Reason | When |
|---|---|---|
| 1000 | `logout` | After the `logout` reply. |
| 1000 | `kicked` | After the `kicked` event. |
| 1008 | `replaced` | Another connection resumed this session (§2). |

A connection closed for any other reason — a failed handshake, a dead
link, a server shutdown — is a lost connection, and the session detaches
or ends per §2.

## 6. The handshake

The first request on a new connection MUST be `login` or `resume`, and it
MUST arrive within the server's login timeout (*hxd-ng:* 10 s), or the
server closes the connection. Any other first request is answered
`not_logged_in` and the connection is closed. After a successful
handshake, `login` and `resume` are answered `bad_request`.

A handshake that fails is answered with its error and the connection is
then closed. The client opens a new connection to try again.

### 6.1 Login

Starts a new session.

```jsonc
{ "id": 0, "req": "login", "params": {
    "login": "alice",        // omit or "" for guest
    "password": "…",         // omit for password-less accounts
    "nick": "Alice",         // honored only with the use-any-name privilege
    "icon": 128,             // classic icon id; optional
    "signs": "default",      // optional: "default" | "able" (e2e-messages.md §4.6)
    "sealed": true,          // optional: it can open sealed messages (e2e-messages.md §4.1)
    "messaging": true,       // optional: it speaks the friend family (§7.5)
    "friendships": true      // optional: with messaging, its portable part (§7.5)
} }
```

`params` MAY be omitted entirely, which is a guest login. On a socket
that authenticated with an identity before the upgrade, `login` and
`password` are ignored and SHOULD be omitted; the account is chosen as
hotline-ng-identity.md §8.1 says.

```jsonc
{ "reply": 0, "ok": {
    "session": "s_9f2c44b1",           // opaque session id
    "token": "…",                       // opaque secret; keep it for resume
    "self": { …user… },                 // §7.4, plus the fields below
    "server": { "name": "My Server", "subject": "welcome!",
                "agreement": "…" },     // agreement optional
    "users": [ { …user… }, … ],        // the roster, including self
    "detach": { "grace": 300 },         // or null (§2)
    "caps": [ "history", "voice" ],     // always present (§4)
    "seq": 0                            // the first event is seq 1
    // …plus one block per capability that has one (§4)
} }
```

| Field | Rule |
|---|---|
| `session` | Opaque string. Clients MUST NOT interpret it. |
| `token` | Opaque string, a bearer credential for this session (§9). Clients MUST store it only where they would store a password, and MUST NOT log it. |
| `self` | This session's `user` object (§7.4). On a socket that authenticated with an identity it also carries `identity.age`, `identity.outcome` and `identity.account`, which are for this user only (hotline-ng-identity.md §6.1). |
| `server` | `name` and `subject` are strings. `agreement`, when present, is the server's agreement text, for the client to show; accepting it is not a protocol step. |
| `users` | The complete roster at this moment, as `user` objects. |
| `detach` | §2. |
| `caps` | §4. |
| `seq` | The seq the client is at: 0 for a new session. |
| `signs` | The client's own `signs`, echoed when the server has the `signed` capability and the session proved a device whose certificate allows messages and is at most 512 bytes; absent otherwise. `"default"` puts `signs: true` in the session's roster `identity` (e2e-messages.md §4.6). Any other value of `signs` is `bad_request`. |
| `messaging` | Not echoed: the `messaging` block (§7.5) is present whenever the capability is. With the capability, `true` makes this a session that speaks the friend family from its login on (§7.5); without it, it is ignored. |
| `friendships` | Not echoed: `caps` lists `friendships` when it is granted (§7.5). Without `messaging`, it is ignored. |
| `sealed` | `true`, echoed when the client sent it and the session proved a device whose certificate allows messages and is at most 512 bytes; absent otherwise. It puts `sealed: true` in the session's roster `identity`, and such a session alone is sent sealed messages and may send them or ask `device_cert` (e2e-messages.md §4.1–§4.3). |

The roster is complete at the reply: the client needs no event to learn
who is present, and every event that follows is a change to it.

Errors:

| Code | Meaning |
|---|---|
| `bad_request` | `params` present but malformed. |
| `login_failed` | No such account, or the wrong password. Deliberately one code (rationale §5). |
| `denied` | The server's identity policy refused this socket (hotline-ng-identity.md §8.1). No credentials failed, and there is nothing to retry. |
| `revoked` | The socket's identity or device key was revoked on this server after it authenticated (identity-registrar.md §7.3). |
| `banned` | The address or identity is banned. *hxd-ng* refuses a banned address before the upgrade — closing the TCP connection at accept, or answering the HTTP request 403 — and never sends this code. |
| `server_full` | No uid is free. |
| `too_many_connections` | The account already holds as many connections as the server lets one account hold. Waiting does not help and there is no `retry_after`: closing one of the others does. *hxd-ng:* `[limits] connections_per_account`, for an account with a password or a linked identity (§9). |
| `rate_limited` | The server is taking logins as fast as it can, this address has failed too many, or this account has been logging in too often. Retry after `retry_after` seconds. *hxd-ng:* past `[server] logins_in_flight` logins in progress, or past `[limits] login_failures` wrong passwords from the address for this login, or `login_failures_per_addr` for every login together, on any wire, or past the account's burst of `connections_per_account` new connections earned back at `reconnect_seconds` (§9). |
| `server_error` | The server could not complete the login. |

### 6.2 Resume

Attaches this connection to an existing session.

```jsonc
{ "id": 0, "req": "resume", "params": {
    "session": "s_9f2c44b1", "token": "…", "last_seq": 41 } }

{ "reply": 0, "ok": { "replay": 3, "self": { …user… } } }
// then events 42, 43, 44, then live traffic
```

- `last_seq` is the highest seq the client has received. It MAY be
  omitted, meaning 0.
- `signs` is as at login (§6.1), said again on every resume: a resume
  that leaves out `"default"` takes `signs` off the roster row
  (`user_changed`). A reply that resumes (`ok`, not
  `resync_required`) echoes it as the login reply does.
- `sealed` is too: a resume without it loses `sealed`, and every sealed
  message held for the session is replayed as `msg` with `sealed_lost`
  in its place (e2e-messages.md §4.1). *hxd-ng:* a session's device is
  the one it logged in with, whatever a resuming socket proves.
- On success the reply's `replay` is the number of buffered events that
  follow it, in seq order, before any live event. `self` is the session's
  `user` object as it is now.
- The server MUST answer `resync_required`, not replay, when it cannot
  deliver every event after `last_seq`: the buffer overflowed (§3), some
  of those events were already sent to an earlier connection (before it
  was lost, or one this resume takes over) and are not in the buffer, or
  `last_seq` is not a seq this session has reached.

Errors:

| Code | Meaning |
|---|---|
| `bad_request` | `params` malformed. |
| `session_expired` | No such session, the token is wrong, or the grace window lapsed. Log in again. |
| `too_many_connections` | As for `login` (§6.1): the session's account holds as many connections as it may. The session is left as it was, and a resume after one of the others has closed finds it. A resume that takes the session over from a connection not yet known to be dead is not refused for that connection. |
| `rate_limited` | As for `login` (§6.1): the session's account has been connecting too often. The session is left as it was; retry after `retry_after` seconds. |
| `resync_required` | The session is alive and **this connection is now attached to it**, but the events after `last_seq` cannot be replayed. Follow with `sync` (§6.3) on this same connection. |

`resync_required` is the one handshake error that does not close the
connection.

### 6.3 Sync

Recovers from `resync_required` without losing the session. Valid at any
time after the handshake.

```jsonc
{ "id": 1, "req": "sync" }
{ "reply": 1, "ok": { "server": { "name": "…", "subject": "…" },
                      "users": [ … ], "seq": 977 } }
```

`users` is the complete roster and `seq` is the seq the client continues
from: the next event it receives has a greater one. With the `accounts`
capability it also carries that family's block, as the login reply does
(account-admin.md §5.1), since an `account_changed` may have been lost
in the gap, and with the `rooms` capability that family's block, with
the rooms this session is in and the newest line in each
(chat-rooms.md §7.4).

- **The server MUST NOT send an event with a seq at or below `sync`'s
  `seq` after the `sync` reply** (rationale §5). A server that cannot keep
  this promise does not conform.
- A session answered `resync_required` is live from that moment, so
  events can arrive between that error and the `sync` reply, carrying
  seqs below the one `sync` reports. **A client MUST NOT discard events it
  has already received when it applies `sync`'s seq**: that number says
  where to continue from, not which frames in hand to throw away.

### 6.4 Stored mail after the handshake

Private messages that waited for this account while it had no session
(§7.1) are delivered as ordinary `msg` events, with later seqs, **after**
the reply to `login`, to a successful `resume`, or to `sync` — never
inside a reply and never before it. A `resume` answered
`resync_required` delivers no stored mail; the `sync` that follows it
does (rationale §5).

## 7. Requests and events

The core requests are tabled in §7.3 and the core events in §7.4. Private
messages (§7.1) and files (§7.2) come first because other documents cite
them by those numbers.

### 7.1 Private messages

`msg` sends a private message. The rest of the private-message requests
belong to the `inbox` capability (§4).

- **Addressing.** `to` names a uid on the roster; `to_login` names an
  account, whether or not it holds a session. A request MUST name exactly
  one; naming both or neither is `bad_request`.
- **`text`** MUST be non-empty unless the message carries `media`
  (inline-media.md §8.3); an empty message is `bad_request`.
- **`guid`** is the client's own id for the message: a UUID, hyphenated or
  not, in either case; its version and variant bits are not checked, so
  any 32 hex digits serve. A client SHOULD send one. Two sends with the same guid between the
  same sender and recipient of a **stored** message — the recipient has an
  inbox and the sender has a mailbox — are one message, stored once and
  never refused, so a retry after a lost reply is safe. A message that is
  not stored (a guest's, or one to an account with no inbox, or on a
  server without the `inbox` capability) is not deduplicated, and neither
  is one sent without a guid: a retry is a second message. The reply to a retry describes the message as it
  stands now: a recipient who was away for the first send and is present
  for the retry receives it, and the retry is answered `queued: false`
  where the first send was answered `true`. That is delivery, not an
  error.
- **The reply** is `{ "queued": bool, "id"? }`: `queued` is `true` when
  the message waited in the recipient's inbox rather than going straight
  to a live session. A queued message's reply carries `id`, the stored
  message's id as the recipient's `msg` event will carry it, when the
  sender's own account has an inbox (rationale §5); a sender without one,
  such as an identity admitted as a guest, is answered `queued` alone, as
  is a message delivered at once.
- **The `msg` event** carries `from` (`{ uid, nick, login? }`), `text`,
  `at`, `queued` and, when the message was stored, `id`. `from.uid` is 0
  when a queued message's sender no longer has a session. `from.login` is
  absent when there is nobody to reply to — a guest, or an account since
  deleted. `id` is absent when nothing durable was stored. `at` is when
  the message was sent, not when it arrived.
- **The login reply's `inbox`** block, `{ unread, total }`, is present
  whenever the server has an inbox, so a client can show a badge before
  any mail arrives.

A stored message to an account with no attached session — detached, or
no session at all — waits in the inbox (`queued: true`) and is delivered
after the handshake of its next connection (§6.4). A message that is not
stored reaches a detached session through its outbox (§3) and is
delivered on resume; to an account with no session it cannot be
delivered at all, and is `no_such_user`.

**A client that receives `resync_required` MUST recover as follows:**
`sync`; then `inbox`, to find the private messages the gap held — they
were marked delivered when they entered it, and the store is now the only
copy; then `history` with `after` set to the last chat line id it holds,
repeated while `has_more`, to recover the gap's public chat; and with
the `rooms` capability, the same for each room `sync` lists in
`rooms.joined` whose `last_id` is past the client's cursor for that room,
with `room` set, since a line id is a cursor in its own room alone
(chat-rooms.md §7.4). A line
returned by `history` has the same id as its live `chat` event, so the
client deduplicates by id. Mail that arrived while no connection was
attached was never in the buffer; it is still pending, and `sync`
delivers it (§6.4).

### 7.2 Files

The `files` capability means this server exposes its file area. Every path
is slash-separated UTF-8 relative to its root; `""` names the root. Paths
are values, not URLs, and `.` / `..`, empty components, leading slashes and
trailing slashes are malformed.

- `files_list { path? }` returns `{ path, uploadable, entries }`, where
  `uploadable` says whether `files_upload` would take a file into that
  folder from this session. Each entry is
  `{ name, kind, size, media_type?, modified? }`, where `kind` is `file` or
  `folder`. In this section a `?` field is present and `null` when
  unknown, rather than absent.
- `files_info { path }` returns
  `{ path, name, kind, size, media_type?, created?, modified?, comment? }`.
  `path` names an entry, so `""` is `bad_request`.
- `files_download { path }` requires a file and returns
  `{ url, size, media_type? }`. `url` is a same-server bearer URL such as
  `/files/<token>`; it is short-lived and bound to the session that asked.
  `""` is `bad_request`.
- `files_preview { path }` requires a file, as `files_download` does, and
  returns `{ kind, url, media_type, size, truncated, width?, height? }`.
  `url` is a token as `files_download`'s is, but what it serves is made
  by the server rather than read from the file: for `kind` `image`, the
  image decoded and drawn again as a still within 1024 pixels a side,
  `width` by `height`; for `text`, its first 256 KiB as UTF-8 with LF
  line endings, Mac Roman when the file is declared text and is not
  UTF-8, and `truncated` when that is not all of it. For `video` (an
  MP4, QuickTime, WebM, Matroska or Ogg container, by its magic), the
  URL serves the file itself, with ranges where `files_download`'s
  would, typed as `media_type` says, which a client checks it can play;
  its token, once fetched, lasts an hour from each fetch rather than
  from its issue, so a paused video can still seek. A HEIF or AVIF
  photograph shares MP4's container and is not a video. `size` is the file's. A file that
  is none of these is `unsupported`, and an image past what the server
  will decode is `too_large`.

- `files_upload { path, size, comment?, fresh? }` begins an upload of a
  file of `size` bytes (decimal) to `path`, whose folder must exist, and
  returns `{ url, offset, piece, digest? }`. The bytes go to `url` in
  pieces, each a `PUT` of at most `piece` bytes with a `Content-Range`
  starting at `offset` and then at each piece's end; a piece that does
  not start there answers `409` with the offset in `Upload-Offset`, one
  that does answers `204` with the next, and the last answers `201`
  with `{ path }`, where the file was published. An empty file is one
  `PUT` with no range. `offset` is not `"0"` when this account left part
  of this file before: the client then compares `digest`, the Large
  File resume digest of the part the server holds, with the same digest
  of its own file, and echoes it in the first piece's `Upload-Digest`;
  a piece without the echo answers `409`, and a client whose file
  differs sends `fresh: true` to start over. The URL lasts as a
  download's does, and from each piece, and ends with the session.
  Besides those, a piece answers `404` when its upload is gone (ended
  with its session, expired, or its part replaced by another upload),
  which a client answers by asking `files_upload` again and being
  quoted what is there; `413` when it is longer than `piece` or the
  file is past this server's limit; `503` with `Retry-After` when the
  server is busy or the piece could not be written, to be tried again;
  and `422` with `{ error: { code, text } }` for a refusal in this
  section's codes, such as `already_exists` when the path was taken
  while the file arrived. The design is `ng-uploads.md`.
- `files_mkdir { path }` makes an empty folder at `path`.
- `files_delete { path }` deletes the entry at `path`, a folder with
  everything in it.
- `files_move { path, to }` moves the entry at `path` to `to`, which may
  name another folder, another name, or both: it is rename and move in
  one.
- `files_comment { path, comment }` sets the comment `files_info` shows;
  `""` clears it. *hxd-ng* keeps comments in Mac Roman, as a classic
  client reads them, so a character Mac Roman lacks is stored as `?`, and
  at most 200 of them.

Each of these four returns `{}`. None replaces an entry: a path or a `to`
that is taken is `already_exists`. `""` is `bad_request` for each, as is
a `to` inside the entry being moved.

`files_list` and `files_info` need the account's `[extra] file_list` and
`file_getinfo`, as on the legacy wire. Both are on unless the account file
turns them off, as mhxd has them, so an account that may not download can
still browse. `files_download` needs the `download_files` access bit. A
drop box, any path naming "drop box" in any case, also lists, answers
`files_info` and downloads only for `view_drop_boxes`, and the path is
refused before anything is looked up, so a name a drop box does not hold
is refused the same way as one it does.

`files_upload` keeps the legacy wire's FilePut rules (`files-plan.md`):
it needs `upload_files`, and `upload_anywhere` too outside a folder
whose path names an upload folder or a drop box. An account without
`view_drop_boxes` may upload into a drop box but not into a folder
inside one, which is `not_found`, and its upload into one is blind: it
is never refused for a name that is taken, nor quoted a part to resume,
but published under a free name, so that it learns nothing of what the
drop box holds, and it is sent in one piece (`piece` is its size).

The changes need the bit for the kind of entry they act on:
`create_folders` for `files_mkdir`; `delete_files` or `delete_folders`
for `files_delete`; for `files_move`, `rename_files` or `rename_folders`
when the name changes and `move_files` or `move_folders` when the folder
does, both when both do; and `comment_files` or `comment_folders` for
`files_comment`. A path or a `to` naming a drop box needs
`view_drop_boxes` besides, as on the legacy wire.

The login reply's `files` block says what this session may change, so a
client can leave out what it would only be refused:

```jsonc
"files": {
  "writable": true,   // false: the area is read-only, and "may" is empty
  "previews": ["image", "text", "video"],   // the kinds files_preview makes here
  "may": ["create_folders", "delete_files", "rename_files"]
}
```

`may` names the access bits above that this session holds, by their
names in access-bits.md §2: some of `create_folders`, `delete_files`,
`delete_folders`, `rename_files`, `rename_folders`, `move_files`,
`move_folders`, `comment_files`, `comment_folders`, `upload_files` and
`upload_anywhere`.

These methods answer errors from this set:

| code | when |
|---|---|
| `bad_request` | malformed params, or a malformed path |
| `not_available` | Files is not configured, or its source is unavailable |
| `access_denied` | `files_list` without `file_list`, `files_info` without `file_getinfo`, `files_download` without `download_files`, a change without the bit it needs, any of these on a drop box without `view_drop_boxes`, or without it a `files_move` or `files_delete` of a folder holding a drop box anywhere inside |
| `read_only` | a change to an area that cannot be changed |
| `already_exists` | a change onto a path that is taken |
| `cross_filesystem` | a `files_move` that would leave the filesystem its entry is on, or a `files_delete` of a folder with another filesystem mounted inside it |
| `not_authorized` | the session ended while the request was handled |
| `not_found` | no entry at that path |
| `not_folder` | `files_list` on a file, a `files_mkdir` or a `to` whose parent is a file, or a folder replaced by a file while a change to it was checked |
| `not_file` | `files_download` on a folder, or the other way round for a change |
| `too_large` | the entry exceeds this server's size limit |
| `too_deep` | a `files_mkdir` that would nest folders deeper than this server allows, a `files_move` of a folder that would leave it or anything inside it deeper than that, whichever way it moves, or a `files_delete` of a folder already nested deeper inside than it will walk; a refused delete removes nothing |
| `busy` | this server's outstanding-download limits, or its incomplete uploads' limits, are reached; retry later |
| `range_unsupported`, `range_invalid`, `origin_changed` | the source refused the request as the corresponding HTTP failure would |

All `size` values, including folder child counts, are decimal strings. A
client parses them as unsigned 64-bit integers or `bigint`; interpreting one
as a JSON number can silently round it. Timestamps are optional integer
seconds in the manifest's Hotline header epoch.

`GET` on the returned URL streams the file through this server. When the
file can be read from an offset, the full response carries
`Accept-Ranges: bytes`, and one byte range — `bytes=<first>-`,
`bytes=<first>-<last>`, or the suffix `bytes=-<count>` — answers `206` with
`Content-Range`. A range that selects nothing, its first byte at or past
the end, answers `416`. Otherwise `Range` is ignored, as RFC 9110 lets a
server ignore it, and the answer is `200` with the whole file: for a file
that cannot be resumed, for more than one range, and for a header that does
not parse. The token is reusable for resume until it expires, and dies with
its `(uid, serial)` session, taking any download still streaming on it
along. So does a download whose receiver stops reading for the server's
idle timeout. Unknown, expired, and unauthorized tokens all answer `404`.

### 7.3 The core requests

The requests every conforming server answers, plus those of the `history`
and `inbox` capabilities, which are specified here rather than in a
family document. Each family of §4 adds its own.

| `req` | `params` | `ok` | Errors besides §10's universal set |
|---|---|---|---|
| `login` / `resume` / `sync` | §6 | §6 | §6 |
| `chat` | `text`, `style?` (`"normal"` \| `"action"`), `media?`, `room?`, `guid?`, `signed?` | `{ "id"? }` | `no_such_room`, `not_a_member`, `read_only`, `signature_required`, `bad_signature`, `server_error` |
| `nick` | `nick?`, `icon?` | `{}` | — |
| `room_topic` | `room?`, `topic` | `{}` | `no_such_room` |
| `msg` | exactly one of `to` (uid) / `to_login`; `text`; `guid?`; `media?`; `signed?`; or `to`, `sealed` and `cert` alone | `{ "queued": bool, "id"?, "requested"? }` | `no_such_user`, `mailbox_full`, `quota_exceeded`, `blocked`, `not_delivered`, `unconfirmed`, `bad_signature`, `not_sealed`, `cert_changed`, `not_friends`, `request_full`, `roster_full`, `server_error` |
| `device_cert` | `uid` | `{ "cert" }` | `no_such_user`, `not_sealed`, `blocked`, `not_delivered` |
| `signs` | `signs` (`"default"` \| `"able"`) | `{}` | — |
| `history` | `room?`, `before?`, `after?` (line ids), `limit?` (1–200, default 50) | `{ "lines": […], "has_more": bool }` | `not_available`, `no_such_room`, `server_error` |
| `inbox` | `before?` (message id), `limit?` (1–200, default 50) | `{ "messages": […], "unread", "total" }` | `no_inbox`, `server_error` |
| `msg_read` | `up_to` (message id) | `{ "unread", "total" }` | `no_inbox`, `server_error` |
| `block` | exactly one of `uid` / `login`; `withdraw?` with `login` (§7.5) | `{}` | `no_such_user`, `no_inbox`, `server_error` |
| `unblock` | exactly one of `uid` / `login` / `fingerprint` | `{}` | `no_such_user`, `no_inbox`, `server_error` |
| `blocks` | — | `{ "blocked": [ { "login", "fingerprint"? } ] }` | `no_inbox`, `server_error` |
| `vouch` / `unvouch` / `vouches` | identity-vouch.md §3.2 | there | there. *Design, not built.* |
| `ping` | — | `{}` | — |
| `logout` | — | `{}` | — |

- **`chat`** needs the send-chat privilege. The text MAY contain line
  breaks and is relayed as one event. `media` is inline-media.md §8.3's.
  The reply carries `id` when the server kept the line (the `history`
  capability): the id its `chat` event carries, so the sender can match
  its own line without waiting for that event.
- **`guid`** on `chat` is the client's own id for the line, as on `msg`
  (§7.1), honored by a server that offers the `chat_guid` capability (§4);
  one that does not ignores it (§5), and there a retry is a second line.
  It is a UUID, hyphenated or not, and anything else is `bad_request`.
  Two sends with the same guid from the same sender into the same room
  are one line while the server remembers the guid: the repeat, whatever
  its text, is answered as the original was, `id` and all, even if that
  line has since been redacted or purged, and nothing is relayed or
  logged for it. The sender is its account where exactly one person is
  behind it (a password, or a linked identity), or else the identity the
  session proved, so a retry from a resumed session or from a new login
  is the same line whether or not the account has an inbox; any other
  session, such as a plain guest's, holds its guids for itself alone.
  Where the server keeps the line (the `history` capability) and the
  sender is an account or an identity, the guid is kept with the line,
  across restarts, for as long as the line is (chat-history.md §4.2): a
  line redacted or purged by a moderator keeps its guid, and one that
  retention or a room's deletion removes takes it along. In front of
  that, and without `history` or for a guest's session the only memory,
  the server remembers each room's latest guids for a bounded window,
  which a restart forgets (*hxd-ng:* ten minutes, and at most a room's
  latest 1024 lines sent with one), shared by the room's senders, so a
  busy room can end one sender's window early. A send after what the
  server remembers is a second line. A client SHOULD send a guid with
  every line it may have to send again, and reuse it on retry.
  *hxd-ng:* a repeat is charged as a request (§9), and not as a line of
  chat when it is found before it is queued, as one sent after its line
  is logged is.
- **`signed`** on `chat` and `msg`, with the `signed` capability, is the
  detached form of the line or message as e2e-messages.md §4.7 and §4.9
  have it, checked as its §4.11 says: `guid` is required and is its id,
  and whatever fails is `bad_signature`, with a `text` naming the
  check. A repeat under the same guid that is signed and says something
  else, an unsigned original included, is `bad_signature` too, not the
  line it repeats, and so is a signed `msg` under a guid its sender used
  toward someone else, as far as the server remembers: where it stores
  messages. *hxd-ng:* it costs one more against the request limit (§9).
- **`sealed`** on `msg` is a sealed message, and **`device_cert`** the
  certificate to seal one to, as e2e-messages.md §4.2 and §4.3 have
  them: from and to sessions that said `sealed` (§6.1), never stored
  and never queued, so `queued` is always `false`. *hxd-ng:* a sealed
  `msg` costs one more against the request limit for each 2048 bytes of
  its box, and `device_cert` 4, rationed on top at 20 a minute (§9).
  To a user of a linked server, both go by its home server, which checks
  the key a box was sealed to (e2e-messages.md §5), over a link trying
  the user keys draft and no other.
- **`signs`**, with the `signed` capability, changes the session's
  `signs` (§6.1) when its user turns signing every lobby line on or
  off, under the login's condition, which a session that does not meet
  it is refused `bad_request` for (e2e-messages.md §4.6).
- **`nick`** changes this session's nick and icon. A new nick needs the
  use-any-name privilege; without it the request is `access_denied` and
  changes nothing, icon included. An empty nick is ignored.
- **`room_topic`** with an absent `room` or `room` 0 sets the public
  chat's subject, which everyone hears as `subject`. It needs the
  set-subject privilege (*hxd-ng:* `[extra] set_subject`, as the classic
  120), and is answered whether or not the server has the `rooms`
  capability. Any other `room` is chat-rooms.md §7.2's.
- **`room`** on `chat`, `history` and `room_topic` is the `rooms`
  capability's (chat-rooms.md §7.2): absent or 0 is the lobby.
- **`msg`** needs the send-messages privilege, except to the server's own
  account (system-account.md §3). See §7.1.
- **`history`** needs the chat-history privilege. It pages public chat by
  line id: rows ascend by id; `before` and `after` are exclusive bounds,
  and together mean `after < id < before`, paged forward from `after`;
  an id of 0 is the same as omitting the bound. `limit` 0 is
  `bad_request`; a server MAY cap `limit` below 200. The login reply's
  `history` block, `{ max_lines, max_days }`, is the server's retention
  (chat-history.md §7). A server MAY rate-limit this request.
- **`inbox`** lists this account's stored messages, newest first, paging
  backward from `before`. Each is `{ id, from: { nick, login? }, text, at,
  read, media?, signed? }`; there is no uid, which may have been reused since.
- **`msg_read`** marks every message of this account's with an id at or
  below `up_to` read, and returns the counts after it.
- **`block`** refuses mail from an account, or from the identity of a
  session on the roster; **`unblock`** accepts it again. `fingerprint`
  names an existing block by the 52-character fingerprint `blocks`
  reports, and is valid only for `unblock`. A block keyed on a fingerprint
  lists with `fingerprint` present; one keyed on an account lists without
  it. A `uid` naming another server's user (`remote` in its
  row) refuses that user's private messages for the rest of this
  session, until it leaves, and is not listed.
- **`logout`** ends the session at once, with no grace, and the server
  then closes the connection (§5).

**News** (`news_*`), **push** (`push_register`, `push_unregister`),
**voice** (`voice_*`), **video** (`video_*`), **files** (`files_*`)
and **rooms** (`rooms`, `room_*` but the lobby's `room_topic`) requests
are specified where §4 says.

`rate_limited` from `chat`, `msg` and the news posts during a never-seen
key's newcomer delay carries `retry_after` (seconds) in the error object,
so a client can disable its compose box for that long rather than retry
blind (identity-registrar.md §7.3).

### 7.4 The core events

| `ev` | `data` | Sent when |
|---|---|---|
| `user_joined` | `{ "user": {…} }` | A session joins the roster. |
| `user_changed` | `{ "user": {…} }` | A session's nick, icon, `admin` flag or status changes. |
| `user_parted` | `{ "uid": n }` | A session leaves the roster. |
| `chat` | `{ "from": { uid, nick, remote? }, "text", "style", "at", "id"?, "media"?, "room"?, "guid"?, "signed"? }` | A line of public chat. `from.remote` is the speaker's `remote` (§7.4) for a user of a linked server. `id` is present when the server kept the line (the `history` capability). `room` is present for a line in a room (chat-rooms.md §7.3), never for the lobby. `guid` is the one the line was sent with (§7.3), present on the sending session's own copy alone: never on another session's, the same account's included, and never in `history`. `signed` is a signed line's detached form as it was sent, on every copy and in `history` (e2e-messages.md §4.7), or for a linked server's user's line, as e2e-messages.md §5 restores it, or in its link form while its certificate is not held. A linked server's user's `history` line carries `from.remote` too, `tagged` as it was when the line was logged, and `server_key` only on a signed line, the key it was checked against; a line logged before its server kept the rest carries only that key, if any. |
| `notice` | `{ "text", "room"? }` | A server notice, such as a kick announcement. |
| `subject` | `{ "subject", "room"? }` | The public chat's subject, or a room's topic, changed. |
| `broadcast` | `{ "from": { uid, nick }, "text" }` | An administrator's broadcast. |
| `msg` | `{ "from": { uid, nick, login?, fingerprint? }, "text", "at", "queued", "id"?, "media"?, "signed"?, "sealed"?, "sealed_lost"? }` | A private message (§7.1). `signed` is a signed message's detached form as it was sent, and on its `inbox` row too (e2e-messages.md §4.9). `sealed` is a sealed message's box as it was sent, with `from.fingerprint`, `text` the placeholder `[Encrypted message]` and no `id`; `sealed_lost` stands in its place for one held for a session that lost `sealed` (e2e-messages.md §4.1, §4.4). |
| `kicked` | `{}` | This session was kicked. The server then closes the connection (§5) and the session is over. |

Timestamps (`at`) are integer Unix seconds. Events of the extension
families — `voice_*`, `video_status`, `news_*`, `room_*` — are specified where §4
says, and `media_revoked`, `chat_redacted`, `chat_purged`, `report` and `report_closed`
in moderation.md §5, whose requests — `report`, `redact`, `revoke`,
`purge`, `kick` and the rest — are specified there too. Every event, of any family,
counts in §3's sequence.

**The `user` object:**

```jsonc
{
  "uid": 3, "nick": "Alice", "icon": 128,
  "admin": false,
  "status": "active",              // §2
  "transport": "encrypted",        // encrypted | cleartext | weak | unknown
  "identity": {                    // absent unless the session proved one
    "fingerprint": "6htgz65…",     // 52 characters, Crockford base32
    "handle": "alice@hl.example"   // null when no attestation was accepted
  },
  "avatar": { "id": "9f86d081…", "type": "image/png",  // absent unless the user has one
              "width": 128, "height": 96 },
  "color": 16744448,               // absent unless the user set a nick color
  "system": true                   // only on the server's own account
}
```

| Field | Rule |
|---|---|
| `uid` | §2. |
| `nick`, `icon` | As shown to every other user, classic clients included. |
| `admin` | The user may disconnect other users: the classic wire's admin color. |
| `status` | §2. |
| `transport` | Required. `"cleartext"` when any hop between this user's client and the server is unencrypted, as far as the server knows: a classic client on plain TCP, or a tunnel that declared its downstream hop cleartext (hotline-ng-auth.md §7.2, §8). A client MAY warn before sending a private message to a `cleartext` user. For a user of a linked server, whose connection is that server's: what that server said, where the two servers try the user transport draft (server-link.md §3.2), `"weak"` among it for a cipher that does not hold up (HOPE's RC4); `"unknown"` otherwise. Clients treat `"weak"`, `"unknown"` and any value they do not know as they would `cleartext`. |
| `remote` | Present only for a user of a linked server (server-link.md): `{server, tag, tagged, server_key?}`, the home server's name and tag, whether this server puts the tag in its users' names, and the home server's discovery key, base64url, when it said one over a link trying the user keys draft (server-link.md §7.7), which its signed lines are scoped to (e2e-messages.md §5). A client MAY show the tag itself when `tagged` is false. Such a user's `color` is its home server's. |
| `identity` | Present only when the session authenticated with an identity (hotline-ng-identity.md §6.1), or for a user of a linked server whose home server said the fingerprint it proved, over a link trying the user keys draft: then `{fingerprint}`, and `signs` when that server says it, as that server's word. It carries only what the roster may see: never `age`, `outcome` or anything that authorizes. `signs: true`, present only when true, says the client signs every lobby line (e2e-messages.md §4.6, §5), and `sealed: true` that it can open sealed messages (§4.1). |
| `avatar` | Present only when the user has one, on a server with the `avatars` capability (avatars.md §4.2). Clients SHOULD show it in place of the icon when they can, and fall back to `icon`. |
| `color` | For a user of a linked server, its home server's color. Otherwise present only when the user set a nick color for this session: `0x00RRGGBB` as a number (fogWraith's Colored Nicknames). Classic clients that send nick colors see it too. It is the user's choice of how their name looks, so a client MAY ignore it, for contrast or accessibility. This wire does not set one yet. |
| `system` | Present, and `true`, on exactly one user, the server's reserved account (system-account.md §2), when the server runs one; absent on every other user. Clients MUST read an absent `system` as `false`. That user is always on the roster, has `admin` set, cannot be kicked or banned, and is the sender and addressee of server mail and commands (system-account.md §3). |

### 7.5 Instant messaging

The `messaging` capability is instant-messaging.md's friend family:
friends made by request and response, their presence, instant messages
with receipts and typing, and message requests. That document gives
the semantics (who may take part, what a block, a request and an
approval do, the bounds); this section is the family's wire. Accounts
are named by `login` throughout, and every `fingerprint` here is the
52-character form of §7.4's `identity`, present where the account links
an identity.

**Declaring it.** A client that speaks the family says so at login
with `"messaging": true` (§6.1); a resume keeps what the login said.
Such a session is sent the family's events from its login on. A
session that never declared it is sent none of them, and is answered
as it was before the family existed, until it sends one of the
family's requests, which makes it a session that speaks the family
from then on. `msg` is not one of them.

**Taking part.** Only an account that holds `AccessMessaging` (bit 58,
`messaging` in access-bits.md) takes part, and never `admin` or
`guest`, whatever their bits. Any other session's requests of the
family are answered `access_denied`. The login reply's `messaging`
block says which this session is, and what its account shows of
itself, as it set it:

```jsonc
"messaging": {
  "takes_part": true,         // false: every request below is access_denied
  "max_roster": 500,          // MaxRosterSize: friends, blocks, approvals and requests sent
  "max_message_bytes": 4096,  // an instant message's text, in UTF-8 bytes
  "request_messages": 5,      // message requests one sender may send one recipient
  // The rest only where takes_part is true: the account's own.
  "state": "online",          // online | away | busy | invisible
  "status_text": "at lunch",  // absent unless set
  "discoverable": false,
  "takes_requests": false
}
```

`sync`'s reply carries the block too, as it stands then. `takes_part`
is decided as the session logs in and kept for its life: an
`account_changed` that gives or takes `messaging` changes it at the
account's next login, not before (*hxd-ng:* instant-messaging.md §6's
suspension is staged). A session's `state` starts `online`, whatever
another of its account's said, and a new login ends the account's
`invisible`: the account is shown to its friends again, and they are
told so, as the extension has it.

**Sending.** An instant message is a `msg` by `to_login` (§7.1) to a
friend, or under an approval; to anyone else taking part it becomes a
message request or is refused, as instant-messaging.md §4.1 orders it.
Beside §7.1's answers, its reply may be `{ "queued": true,
"requested": true }`, the one answer a request has, whether it was
stored, held or dropped; and it may be refused `not_friends`,
`request_full` or `roster_full` (below), with `quota_exceeded` for a
bound of instant-messaging.md §4.4 and `no_such_user` for an account
that has blocked the sender. A request carries text alone: one with
`media` is `not_friends`. A message to a friend whose text is longer
than `max_message_bytes`, or that carries `media`, is a private
message, as before. A sender SHOULD send a `guid`: receipts name the
message by it. A `msg` to an attached friend is answered `queued:
false` whatever the friend's state, `invisible` included, as the
extension has it.

**Receiving.** A friend's instant message reaches every attached
session of the recipient's that speaks the family as an `im` event,
and one sent while none was attached waits for the next `friends`
request, which hands over what waited (*hxd-ng:* `[inbox]
deliver_at_flush` at a time, the rest at the next). A client
acknowledges each `im` with `receipt`; one not acknowledged is handed
over again at the next `friends`. So a client SHOULD send `friends`
after `login`, after a `resume`, after `sync`, and after the first of
the family's requests from a session that did not declare it, and
MUST treat an `im` whose `guid` and sender it has already shown as a
repeat, not a second message: a resume's replay and a `friends` read
can both hand the same one over again. A session that does not speak
the family is handed a friend's instant messages as `msg` events, as
before.

| `req` | `params` | `ok` | Errors besides §10's universal set |
|---|---|---|---|
| `friends` | — | `{ "friends": [ friend… ] }` | — |
| `friend_add` | `login`, `note?` | `{ "state" }`: `pending_out`, or `accepted` where it met a request of theirs | `no_such_user`, `blocked`, `already_friends`, `request_pending`, `roster_full`, `quota_exceeded`, `bad_request` |
| `friend_respond` | `login`, `accept` (bool) | `{ "state" }`: `accepted`, or `removed` for a decline | `no_such_user`, `not_friends`, `roster_full` |
| `friend_remove` | `login` | `{}` | `no_such_user`, `not_friends` |
| `friend_alias` | `login`, `alias` (string, or `null` to clear) | `{}` | `no_such_user`, `not_friends` |
| `presence` | `state?` (`online` \| `away` \| `busy` \| `invisible`), `status_text?` (string, or `null` to clear), `discoverable?`, `takes_requests?` | `{}` | — |
| `find_user` | `login` | `{ "user" }` | `no_such_user` |
| `user_profile` | `login` | `{ "user" }`, with `profile` | `no_such_user` |
| `receipt` | `login`, `guid`, `read?` (default `false`) | `{}` | — |
| `typing` | `login`, `typing` (bool) | `{}` | — |
| `requests` | `cursor?` | `{ "requests": […], "approvals": […], "dropped", "takes_requests", "cursor"? }` | — |
| `request_answer` | `login`, `action` (`approve` \| `delete` \| `end`) | `{}` | `no_such_request`, `roster_full` |
| `requests_clear` | `since?`, `before?` (Unix seconds) | `{ "declined", "deleted" }` | — |

- **`friends`** is Get Roster (800): every row of this account's, a
  request sent to it among them. An approval is not a row; `requests`
  lists them.
- **`friend_add`** asks `login` for friendship, with `note` the
  request's note, cut to §8's private-message limit; a note longer
  than `max_message_bytes`, where a server sets that lower, is
  `bad_request`. A request already
  waiting from `login` is accepted instead, `accepted`; a session that
  has not said `takes_requests` and has not sent `requests` is
  answered `request_pending` for it, as the extension answers it.
  `blocked` here is the caller's own block of `login`, to be lifted
  first. A request is answered `pending_out` whether it was delivered,
  held or dropped (instant-messaging.md §4.4).
- **`friend_respond`** accepts or declines a request `login` sent;
  **`friend_remove`** ends a friendship, which ends it for both,
  withdraws a request the caller sent, or declines one it was sent. An
  act on a request that has lapsed or been withdrawn is `not_friends`.
- **`friend_alias`** sets the name this account shows a friend by, for
  itself alone. *hxd-ng* cuts it to a nick's 31 characters.
- **`presence`** is Set Presence (808), each absent field left as it
  was. `invisible` hides the account from its friends' presence,
  every session of it, which they are told is `offline`; any other
  state is this session's, and friends see the most
  available of an account's sessions. `discoverable` is the extension's,
  for a user search this wire does not carry yet. `takes_requests` turns message requests to this account on or off;
  sending it either way makes this a session that understands requests
  (instant-messaging.md §4.1), as `requests` does. *hxd-ng* cuts
  `status_text` to §8's subject limit.
- **`find_user`** and **`user_profile`** are Find User (822) and Get
  User Info (825). The `user` object is `{ login, name, presence?,
  status_text?, profile? }`: `name` is the profile's nickname or the
  login, `presence` and `status_text` are shown for a friend and for
  the caller's own account alone, and `profile` likewise, on
  `user_profile`'s reply: `{ nickname?, first_name?, last_name?,
  email?, gender?, birthdate?, country?, postcode?, languages }`, with
  `birthdate` `{ year?, month?, day? }` and `gender` the extension's
  code: 1 female, 2 male, 3 other, absent for unspecified, and any
  other number read as unspecified. On the caller's own login,
  `presence` is its own `state`, `invisible` included. An account that
  has blocked the caller is `no_such_user`, as one that does not exist
  is.
- **`receipt`** is IM Acknowledge (812): the caller received, or with
  `read` read, the `im` `login` sent under `guid`. **`typing`** is IM
  Typing (813). Both are answered `{}` whatever becomes of them: between
  two accounts with no friendship or approval they are dropped, so a
  stranger learns nothing from one, and a typing flag goes only to a
  friend. A typing flag lapses: a client that receives `typing: true`
  shows it for 10 seconds unless it is said again, and a client sends
  `typing: true` again every 5 seconds while its user is typing, and
  `typing: false` when they stop, send or leave the conversation.
- **`requests`** lists the message requests waiting for this account,
  by sender, oldest first, and its approvals: `requests` is `[{ login,
  fingerprint?, messages: [{ id, text, at, guid, signed? }] }]`, with
  `id` the inbox id a `report` names it by (moderation.md §4.2) and
  `signed` as on `msg`; `approvals` is `[{ login, fingerprint? }]`; and
  `dropped` is how many requests were dropped since the last listing,
  and `takes_requests` whether this account takes them now.
  `cursor`, an opaque string where present, is passed back to read
  the rest; a client
  MUST read on while it is present. *hxd-ng* bounds what can wait
  (`[messaging] max_requests` senders, each `request_messages`
  messages) and answers it all at once, so sends no `cursor`.
- **`request_answer`** approves the conversation with `login`, whose
  waiting messages then arrive as `im` events with `approval`;
  deletes its request, telling the sender nothing; or ends an
  approval. Deleting and ending hold the sender (instant-messaging.md
  §4.4).
- **`requests_clear`** declines every friend request and deletes every
  message request received from `since` up to `before`, each bound
  optional, and answers how many of each (instant-messaging.md §4.3).

**The `friend` object** is one row as its owner sees it:

```jsonc
{
  "login": "bob", "fingerprint": "6htgz65…",   // fingerprint absent unless linked
  "state": "accepted",          // pending_out | pending_in | accepted | blocked | removed
  "alias": "Bobby",             // absent unless set
  "presence": "online",         // offline | online | away | busy; only for accepted
  "status_text": "at lunch",    // only for accepted, when set
  "note": "hi, it's Bob"        // only for pending_in, when sent
}
```

`removed` appears only in a `friend` event: the row is gone.

**Events.** Only to a session that speaks the family:

| `ev` | `data` | Sent when |
|---|---|---|
| `friend` | `{ "friend": {…} }` | A row changed, whole, as it now stands, or went (`removed`): to every session of the account that speaks the family, the one whose request changed it included, so all of them agree. A client replaces its copy. |
| `friend_request` | `{ "login", "fingerprint"?, "note"? }` | Someone asked this account for friendship (804). |
| `presence` | `{ "login", "fingerprint"?, "state", "status_text"? }` | A friend's presence changed (809): `state` as on the `friend` object. *hxd-ng* tells a burst of changes once, with its final state. |
| `im` | `{ "from": { login, nick, fingerprint? }, "text", "at", "guid", "queued", "id"?, "signed"?, "approval"? }` | An instant message (811). `id` is the inbox row, absent for one past the sender's daily quota that was never stored; `queued` that it waited; `approval`, present and `true`, that it came under an approval rather than a friendship. |
| `receipt` | `{ "login", "fingerprint"?, "guid", "read" }` | A friend received (`read` false) or read a message this account sent it under `guid`. Under an approval only reads are told. |
| `typing` | `{ "login", "fingerprint"?, "typing" }` | A friend started or stopped typing to this account. |
| `requests_changed` | `{ "count" }` | The number of senders whose requests wait changed: to sessions that understand requests alone. |

A server that does not serve the family answers its requests
`unknown_method`, as §4 allows. The family's codes:

| Code | From | Meaning |
|---|---|---|
| `access_denied` | the family | This account does not take part. |
| `no_such_user` | the family, `msg` | No such account, one that does not take part, or one that has blocked you: one answer for all three. |
| `blocked` | `friend_add` | You have blocked them. |
| `already_friends` | `friend_add` | They are your friend already. |
| `request_pending` | `friend_add` | A friend request between you waits already. |
| `not_friends` | `friend_respond`, `friend_remove`, `friend_alias`, `msg` | There is no friendship or request to act on, or a `msg` that cannot be a request: they take no requests, you have blocked them, it carries `media`, or this session does not understand requests. |
| `roster_full` | `friend_add`, `friend_respond`, `request_answer`, `msg` | The act would take your rows past `max_roster`. |
| `quota_exceeded` | `friend_add`, `msg` | You have asked as many new people today as the server allows. |
| `request_full` | `msg` | You have sent that account as many requests as you may until it answers. |
| `no_such_request` | `request_answer` | No request or approval of theirs to answer. |

#### Portable friendships

The family's portable part is proposals/portable-friends.md's: a
friendship made by an offer signed by one party's device and an
acceptance signed by the other's, kept by the two clients and presented
by each on the servers its user chooses, and ended everywhere by a
signed withdrawal. That document gives the semantics, the order of each
check and why; proposals/friendship-objects.md defines the objects,
which travel here as base64url strings, as every identity object does:
an `offer`, a `friendship` (the offer and its acceptance) and a
`withdraw`. A friendship is named by its hash, and a withdrawal by its
pair hash, each the base64url of 32 bytes. Everything below reaches a
session only once it has asked for it, so a client that never does is
sent and answered what the rest of §7.5 says, byte for byte.

**Declaring it.** A client asks with `"friendships": true` at login,
beside `"messaging": true`. It is granted to a session that takes part,
whose socket authenticated with an identity its account links
(hotline-ng-identity.md §8.1), on a device whose certificate allows
messages and is at most 512 bytes; the login reply's `caps` then lists
`friendships`. Unlike every other name in `caps`, `friendships` is
listed only in reply to a login that asked for it, so that a client
that never asks is sent the reply it always was. Asked for and not
granted, it is not listed, and the session is answered as if it had not
asked. A resume keeps what the login was granted. Such a session is a
**friendships session**.

**The device-act gate** (portable-friends §3). Offering, accepting with
a friendship, presenting and withdrawing are open to a friendships
session alone, and only while its certificate is unexpired and not
revoked here, at the time of the act; any other session is answered
`access_denied`. An offer, an acceptance or a withdrawal that the
session gives as its own act is signed with the certificate it proved,
and one signed with any other is `bad_signature`. Its `time` is within
ten minutes of the server's clock either way, or it is `stale`: a
client signs by its own clock and never by one a server offers, and a
client told `stale` tells its user its clock is off. A password session
can still remove a friend, which ends the friendship on this server
alone.

What the family's existing requests take beside what they took:

| `req` | Added `params` | Added errors |
|---|---|---|
| `friend_add` | `offer` | `withdrawn`, `stale`, `bad_signature` |
| `friend_respond` | `friendship`, with `accept: true` | `withdrawn`, `stale`, `bad_signature` |
| `friend_remove` | `withdraw`; or `offer`, the caller's own upgrade offer, to cancel it alone; `fingerprint` in place of `login` | `stale`, `bad_signature` |
| `find_user` | `fingerprint` in place of `login` | — |
| `block` (§7.1) | `withdraw`, beside `login` | `stale`, `bad_signature` |

- **`friend_add` with an `offer`** asks for a portable friendship. Its
  `from` is the caller's identity and its `to` the fingerprint `login`'s
  account links, or the answer is `no_such_user`, one answer whether
  `login` links no identity or another, so that an offer cannot test a
  guess at a fingerprint. A withdrawal held here that ends it is
  `withdrawn`: sign a new one after ten minutes. Otherwise it is a
  friend request as ever, held to the same bounds, and answered the
  same. One that meets a request `login` sent is `request_pending`, as
  the extension answers it, and the client answers that request with
  `friend_respond` instead; a `friend_add` without an offer that meets
  one is answered as the rest of §7.5 answers a crossing. On a
  friendship already standing between two linked accounts it is an
  **upgrade offer**: answered `{ "state": "accepted" }`, outside the
  friend-request bounds, the friendship standing whatever becomes of
  it, and told to the friend's friendships sessions alone. An offer
  lapses at its `expires`: the request stays, plain, and an upgrade
  offer goes.
- **`friend_respond` with a `friendship`** accepts the offer `login`
  sent, built into a friendship by this client with its own acceptance:
  the offer must be the one stored, and the acceptance the caller's own.
  The friendship is then presented by both parties here, and both are
  told the `friend` entry with its hash. Without one, an `accept`
  makes a friendship of this server alone, and drops the offer. A
  decline drops the offer; for an upgrade offer it drops nothing else,
  and is answered `{ "state": "accepted" }`.
- **`friend_remove` with a `withdraw`** ends every friendship between
  the two whose half by the withdrawal's party predates its `before`,
  on this server and, as the withdrawal travels, everywhere else; the
  friend is told `removed` with it. Without one, it ends the friendship
  here alone, and the server keeps a withdrawal of its own for the
  caller, so that the caller's other devices do not present it straight
  back. So does one whose `withdraw` is refused, `stale`,
  `bad_signature`, or `access_denied` from a session that is not a
  friendships session: the friend is removed here all the same, and the
  refusal is the answer, for the client to sign afresh for the other
  servers. With `offer`, it cancels the caller's
  upgrade offer to `login` and nothing else. With `fingerprint` in place
  of `login`, it drops a friendship this account presented and the other
  party has not, and is answered `{}` whether or not there was one;
  with a friend's fingerprint it ends that friendship as `login` would.
- **`find_user` by `fingerprint`** finds the account that links it, as
  by `login`, with the same one answer `no_such_user` for an account
  that does not exist, does not take part or has blocked the caller.
  To a friendships session, the `user` object of `find_user` and
  `user_profile`, by either name, carries `fingerprint` where the
  account links an identity whose link the server would show it: what
  an `offer`'s `to` is. A link it would not show is answered as no link
  at all, never as `no_such_user`, so that the answer tells a hidden
  link from none and no further. *hxd-ng* shows every link.
- **`block` with a `withdraw`**, by `login` alone, withdraws, then
  blocks, as `friend_remove` with one does; the friend's other servers
  are told of a removal, never of a block. The block stands whatever
  becomes of the withdrawal, whose refusal is the answer. A `withdraw`
  beside `uid`, or on `unblock`, is `bad_request`.

Two requests are added, answered to friendships sessions alone:

| `req` | `params` | `ok` | Errors besides §10's universal set |
|---|---|---|---|
| `friendships_present` | `withdrawals?`, `friendships?`: arrays of objects, at most 32 together and at most one withdrawal for a pair | `{ "withdrawals": [ result… ], "friendships": [ result… ] }`, each in the order sent | `bad_request` past either bound |
| `friendships_fetch` | `hashes?`, `fingerprints?`: at most 32 together | `{ "friendships": [ { "hash", "friendship"? } ], "rotations": [ { "fingerprint", "records": [ … ] } ] }` | `bad_request` past the bound |

- **`friendships_present`** presents friendships on this server and
  gives it withdrawals, the withdrawals first. A result is `{ "hash",
  "result", "withdraw"? }`, `hash` the friendship hash, or a
  withdrawal's pair hash, and `result` one of:

  | `result` | For | The client |
  |---|---|---|
  | `ok` | presented, or a withdrawal taken | records it as presented here |
  | `no_such_user` | the other party has no account here, does not take part, or one of the two has blocked the other; counted toward the bound below as a presentation is | tries again at a later login |
  | `roster_full` | this account's own bound on friendships it presented whose friendship here is not active, or its roster as the friendship becomes active | tries again when it has room |
  | `bad_signature` | a friendship that fails its checks or names neither of this account's identity and a successor's, or a withdrawal that fails its checks or is not this session's own | drops the object |
  | `withdrawn` | a withdrawal held here ends the friendship | with `withdraw`, checks it and treats the friendship as withdrawn; with none, stops presenting it here |
  | `stale` | a withdrawal whose `time` is not within ten minutes of the server's clock | signs it afresh |

  When each party has presented a friendship for the pair, the two are
  friends here and each is told the `friend` entry as for a new friend;
  they need not have presented the same one. A client sends its
  withdrawals before `friends` at login, so that they are applied
  before its roster is read, and its friendships after. It presents only
  where its user chose to, per server and per friend, and finds a
  friend first by `find_user` by `fingerprint`, though presenting still
  answers for a friend who is not here.
- **`friendships_fetch`** fetches the friendships whose hashes a `friend`
  entry carried that the client does not hold: each hash is answered
  with its `friendship` only where it is in an entry this account was
  sent for a friend it now has, and without one otherwise, so that a
  hash tells a stranger nothing. A fingerprint is answered with
  `records`, the rotation records (identity-registrar.md §4.6) that end
  at it, oldest first, each the base64url of the signed record as it
  was published, where it is a friend's and this server has applied
  them, and with none otherwise: what a client checks before it moves a
  friendship to a friend's new key (portable-friends §10).
- **Checking a rotation.** A client checks both of each record's
  signatures itself. The other check, that the successor is the one the
  predecessor's card committed to or that its registrar published, is
  one this wire does not hand the client the means to make: a server
  applies a rotation only to the successor it anchored from the
  predecessor's own card, or from the records of a registrar it trusts
  (identity-records.md §4), and answers records for no rotation it has
  not applied, so a record served is one that check passed here. That
  is this server's word, which an honest server's is, and a dishonest
  one can serve only a rotation the predecessor's key signed, which is
  the theft the commitment guards against. So a client that has not
  made the check itself, from a card or a registrar it reaches another
  way, accepts a successor's upgrade offer only once its user confirms
  it, rather than unasked as portable-friends §10 lets a client that
  has.

What friendships sessions are sent beside the rest, and nobody else is:

- the **`friend` object** carries `friendships`, the hashes of the
  friendships each party presented, on an `accepted` entry that is
  portable: this account's own presentation first and the friend's
  second, or one alone where both presented the same friendship; `offer` on a `pending_in` entry whose request
  carries one, and on an `accepted` entry whose friend sent an upgrade
  offer this account has not answered; and `withdraw` on a `removed`
  entry that a withdrawal ended. A `removed` entry with no `withdraw`
  ended the friendship on this server alone: an account went, a
  presentation was dropped as its device was revoked, or a client
  removed without one. A client that recorded the friendship as
  presented here presents it again;
- **`friend_request`** carries `offer`, and an upgrade offer's is sent
  to these sessions alone.

| Code | From | Meaning |
|---|---|---|
| `withdrawn` | `friend_add`, `friend_respond` | A withdrawal this server holds ends the offer or the friendship. Sign again after ten minutes. |
| `stale` | `friend_add`, `friend_respond`, `friend_remove`, `block` | An offer, acceptance or withdrawal whose `time` is not within ten minutes of the server's clock. |
| `bad_signature` | `friend_add`, `friend_respond`, `friend_remove`, `block` | An offer, friendship or withdrawal that fails its checks, or is not this session's own act. |

*hxd-ng* prices `friendships_present` at 1 and 4 for each object it
carries and `friendships_fetch` at 4 and 1 for each hash or fingerprint,
against the session's request limit (§9), which is the session's and
not the account's, so a new login starts it afresh, and an `offer` or a
`withdraw` on
another request at 2 beside that request's price and a `friendship` at
4, for their signatures; none of them costs spam points, so a user who
brings hundreds of friends to a new server is paced, never kicked. It
shows every account's link to anyone, so it has no hidden links
(portable-friends §3), and its own bound on presentations not yet
presented by the other party is `[messaging] max_roster`. Unlinking an
identity drops what the account presented under it, and its sessions
that proved it make friendship acts no more, but its friends are told
nothing until instant-messaging.md's IM2b tells them of an unlink.

## 8. Text and limits

All text on this wire is UTF-8; JSON makes it so. A server that shares its
roster with classic clients converts text at the classic wire's edge,
and text that crosses to a classic client without the Text-Encoding
capability loses every character Mac Roman lacks, which becomes `?`.

| Limit | Value | Enforcement |
|---|---|---|
| Nick | 31 **characters** | Truncated on the way in, once, so every viewer sees the same nick (rationale §5). |
| Chat text | 4096 bytes of UTF-8 | Truncated at a character boundary. |
| Private message text | 4096 bytes of UTF-8 | Truncated at a character boundary. |
| Subject | 255 characters | The classic wire's bound, applied as characters where a subject is set. |

A server truncates text over these limits rather than rejecting the
request. A client SHOULD enforce them before sending, so that what its
user typed is what arrives. The exception is signed text
(e2e-messages.md §4.7): cutting it would break its signature, so a
signed line or message over its limit, or not canonical
(e2e-messages.md §3.1), is `bad_request`, never cut.

**Chat text is plain text.** A server MUST NOT parse, rewrite or
annotate it. A client MAY render a closed markdown dialect in it on
receipt, and SHOULD use the one GtkHx and hx-ng share (rationale §5); it
MUST NOT render anything a classic client would not also see as text. A
news body is different: it declares its own type (news.md §5).

## 9. Security

- **TLS.** In production the WebSocket MUST be `wss://`. A server that
  speaks plaintext SHOULD listen only on loopback by default, behind a
  proxy that terminates TLS. *hxd-ng* never speaks TLS on this port
  itself (its TLS listener is for the classic wire).
- **Tokens.** A session token MUST come from a CSPRNG with at least 128
  bits of entropy, and SHOULD be stored server-side only as a hash and
  compared in constant time. A token is a bearer credential for one
  session and MUST die with it. Servers and clients MUST NOT log tokens.
  *hxd-ng:* 32 bytes, hex-encoded, stored as SHA-256, trusted as
  `(uid, serial)` so a token for an ended session never resumes a later
  session on the same uid.
- **Credentials.** `password` crosses the wire as the classic wire's
  plaintext-equivalent secret; TLS is what protects it. A socket that
  authenticated with an identity (hotline-ng-auth.md) sends none.
- **Bans.** The server's ban list MUST apply to this listener as it does
  to the classic one. *hxd-ng* checks the client address — the one a
  trusted proxy forwards — on every HTTP request, the upgrade included.
  A `*@host` entry bans a registrar: an identity carrying any attestation
  from that host is refused with `denied`, before the admission policy
  runs, and it is checked where the identity is, not at accept
  (identity-registrar.md §7.3). *Design, with the registrar.*
- **Rate limits.** This endpoint faces phones on the open internet. A
  server SHOULD limit requests per connection and login attempts per
  address, and answers a request over its limit `rate_limited`, which a
  client MUST NOT treat as fatal. *hxd-ng* holds each session to a token
  bucket (`[limits] ng_requests` in `ng_request_seconds`, a burst of 40
  and then 20 a second by default) that every request after the
  handshake spends its weight from. A write, or a request others hear
  of, costs 2: `chat`, `msg`, `nick`, `signs`, `block`, `unblock`,
  `msg_read`, `avatar_clear`, `voice_answer`, `voice_mute`, `video_state`,
  `news_seen`, `news_subscribe`, `news_unsubscribe`, `news_mute`,
  `push_unregister`, `files_download`, `files_mkdir`, `files_delete`,
  `files_move`, `files_comment`, `report_close`, `redact`, `revoke`,
  `kick`, `friend_respond`, `friend_remove`, `friend_alias`,
  `presence`, `typing` and `request_answer`, and `friends` and
  `requests`, which read a row of the store for each one listed. What fans out,
  searches, asks a stranger, or joins, leaves or
  renegotiates media costs 4: `news_post`, `news_delete`,
  `news_node_create`, `news_node_rename`, `news_node_delete`,
  `news_search`, `voice_join`, `voice_leave`, `video_start`,
  `video_stop`, `video_subscribe`, `push_register`, `report`,
  `purge`, `device_cert`, `friend_add`, `requests_clear`, `find_user`
  and `user_profile`. Every other request, the reads, a
  trickled `voice_ice` candidate and a `receipt`, which a client sends
  for each `im` a `friends` read hands over, among them, costs 1, and only `logout`
  is free. A request the bucket cannot pay for costs nothing, and is
  answered `rate_limited` with `retry_after`, the whole seconds until it
  could be. The bucket is the session's rather than the connection's: it is
  filled at login and kept across a detach, so a resume finds it as the
  dropped connection left it rather than refilled. An account with
  `[extra] can_spam` is held to none, as it is held to no flood budget.
  Over and above that, one account may post so many news articles and
  replies (`news_posts` in `news_post_seconds`, ten and then one each
  half minute) — a guest, the guests from its address, IPv6 by the /64,
  so a fresh login is not a fresh allowance — past which `news_post` is
  answered the same way; so many folders (`folders` in
  `folder_seconds`, five hundred and then one each ten seconds, counted
  with the classic wire's New Folder and folder uploads), past which
  `files_mkdir` is too; and
  `history`, `news_search`, `device_cert`, media and news-attachment
  uploads (asked before the body is read), media and news-image downloads, avatar
  fetches and enrollment have limits of their own. Login attempts are
  limited per address and login: past `[limits] login_failures` wrong
  passwords for one login — here, on the classic wire, or at
  `/identity/auth` and `/identity/link` — a password login as that
  login is refused with `retry_after` until the address earns one back,
  so a guesser behind a carrier's shared address locks out the account
  it guesses at and nobody else there; and past
  `login_failures_per_addr` for every login together, every password
  login from the address is, so it cannot guess across every account
  instead. A socket that authenticated with an identity, or a guest
  login that sends no password, is not held to either. Each password is counted as it is let
  in and given back unless it turns out wrong (a password that
  verifies, a login refused for something other than its password,
  and a server that could not check it all give it back), so guesses
  made at once on many connections are held to the same count.
  `/identity/challenge` is limited per address, and answers 429 with
  `Retry-After`, as every HTTP route over its limit does. The port
  holds so many connections from one address, from one IPv6 /48 (its
  /64s together, each of which is an address), and from everyone,
  counted from accept, before a byte is read; past any of them a
  connection is closed unanswered. A socket that carries a session is
  held to the server's shared counts per address and per /48 as well,
  and is refused 429 past either. The per-address and per-/48 counts
  hold a socket until it logs in: one that logs in, or resumes, as an
  account with a password or a linked identity counts against that
  account from then on (`[limits] connections_per_account`), because a
  mobile carrier puts many unrelated people behind one address, and
  one past the account's cap is answered `too_many_connections`. A
  guest's socket goes on counting against its address and its /48.
  The rate at which an address may connect is not given back at
  login: each login costs its address a new connection and its account
  one of its own, and one past the account's rate is answered
  `rate_limited`, so neither goes faster than the slower of the two.
- **Flooding.** A server MAY instead kick a session that sends faster
  than anyone is allowed to, answering the request that crossed the line
  `flooding` before the `kicked` event (§10). *hxd-ng* holds a session to
  the budgets mhxd's `nospam` does, one session on either wire the same
  (`[limits]`): so many lines of `chat` in a window, every line of a
  multi-line `text` counted, and so many spam points, which a request
  that stands for a classic transaction spends at the price mhxd
  charges that one: `chat` and `msg` its Chat and Message, `nick` its
  User Change, and `signs` too, being told as one, the news writes
  their 1.5 transactions, `news_post` a threaded post, and the
  file-area changes their Delete File, New
  Folder, Set File Info and Move File. The friend family's requests
  but `msg` spend none: mhxd's table predates the extension and prices
  its transactions only by its catch-all, at which a receipt for every
  message read would be a ban, so they are held to the request limit
  and instant-messaging.md §4.4's bounds instead. Past the first the session is kicked and its room told;
  past the second it is kicked and banned for `[server] ban_time` —
  its account's login or its identity, and its address unless
  `[limits] exempt` holds that to nothing, so a plain guest on an
  exempt address is only kicked — and public chat told. A moderator's
  `kick` with `ban` bans the same way (moderation.md §3.5). An account
  with `[extra] can_spam` is held to neither.
- **Roster pollution** is bounded by the detach rules of §2: permission
  per account and off for guests, a per-address cap, and moderation that
  ends a detached session on the spot.

## 10. Error codes

**Universal** — any request MAY be answered with these:

| Code | Meaning |
|---|---|
| `unknown_method` | The server does not implement this `req`. |
| `not_logged_in` | The first request was not `login` or `resume` (§6). |
| `bad_request` | `params` malformed, a required param missing, or a combination this document forbids. |
| `access_denied` | The session lacks the privilege this request needs. |
| `rate_limited` | Over a limit (§9). Retry later; MAY carry `retry_after`. |
| `flooding` | The session sent faster than the server allows anyone to, and has been kicked for it (§9). **Fatal**, unlike `rate_limited`: a `kicked` event follows and the session ends. Retrying is what got it kicked. |
| `server_error` | The server failed. Not the client's fault; MAY be retried. |

**Core** — from §6 and §7:

| Code | From | Meaning |
|---|---|---|
| `login_failed` | `login` | Wrong account or password. |
| `denied` | `login` | Identity policy refused this socket. |
| `revoked` | `login` | This identity or device key is revoked here. |
| `banned` | `login` | Banned (§6.1). |
| `server_full` | `login` | No uid free. |
| `too_many_connections` | `login`, `resume` | The account holds as many connections as it may. |
| `session_expired` | `resume` | Log in again. |
| `resync_required` | `resume` | Attached; follow with `sync`. |
| `not_available` | `history`, `files_*`, family requests | The server does not offer this. |
| `no_such_room` | `room_*`, `chat`, `history` | No such room, or one this session may not see (chat-rooms.md §5). |
| `not_a_member` | `room_part`, `chat` | Not in that room, which this session may see. |
| `read_only` | `chat` | This session may read that room and not send in it. |
| `signature_required` | `chat` | An unsigned line into a room that requires signing, from a session that may otherwise send there (chat-rooms.md §5.2, e2e-messages.md §4.8). Nothing was relayed or logged. |
| `too_many_rooms` | `room_join` | This session is in as many rooms as it may be. |
| `rooms_full` | `room_create` | The server holds as many rooms as it may. |
| `name_taken` | `room_create`, `room_edit` | A room has that name already. |
| `no_such_role` | `room_create`, `room_edit`, `account_create`, `account_update`, `role_get`, `role_update`, `role_delete` | A gate or an edit names a role there is none of. |
| `no_such_user` | `msg`, `block`, `unblock`, `device_cert` | No such uid, no such account, or that account takes no offline mail — one answer for all three. |
| `no_inbox` | `inbox`, `msg_read`, `block`, `unblock`, `blocks` | *Your* account has no inbox, or the server has none: the `inbox` family's "not available" code. |
| `mailbox_full` | `msg` | The recipient's inbox is at its cap, or for a sealed message, the detached recipient holds as many as it may (e2e-messages.md §4.3; *hxd-ng:* `[sealed]`). |
| `quota_exceeded` | `msg` | The recipient is not connected, and you have stored as much mail today as the server allows. To someone connected, the same message is delivered. *hxd-ng:* `[inbox] max_sent_per_day` and `max_sent_bytes_per_day`. |
| `blocked` | `msg`, `device_cert` | The recipient blocks you. For a `msg` by `to_login`, only outside instant messaging: between two accounts that take part, a block reads as `no_such_user` (§7.5). |
| `not_delivered` | `msg` | The recipient is a user of a linked server (`remote`), and the message did not reach them: that server refused it, or could not be reached, or there were already as many waiting on it as the link lets wait, or it carries media, which cannot cross. `text` says which. Nothing is queued, and `guid` does not apply. |
| `unconfirmed` | `msg` | The recipient is a user of a linked server (`remote`), the message was sent to that server, and it did not answer in time: the message may still reach them. Sending it again may deliver it twice. Nothing is queued, and `guid` does not apply. |
| `not_sealed` | `msg`, `device_cert` | A sealed message, or a certificate to seal one to, that cannot be: `text` says whether this session or the target cannot open sealed messages, or the target's certificate has expired (e2e-messages.md §4.2, §4.3), or a user of a linked server behind a link that does not carry them, or whose server is not shown this session's key. |
| `cert_changed` | `msg` | The `cert` of a sealed message names a key other than the target's now: fetch its certificate and seal again, never in the clear (e2e-messages.md §4.3). |
| `bad_signature` | `chat`, `msg`, `report`, `news_post` | A `signed` that failed a check of e2e-messages.md §4.11, named by `text`: `signed too long ago; sign it again` for one whose `sent` is out of the server's window. Nothing was relayed or stored. |
| `withdrawn`, `stale` | the `messaging` family | §7.5: a friendship object a withdrawal held here ends, or one out of the server's time. `bad_signature` is §7.5's too, for a friendship object that fails its checks. |

The files codes are §7.2's. Each family's document lists its own. A
client MUST treat a code it does not recognize as a failure of that one
request.

## 11. Obligations checklist

A summary of the rules above, for implementers; the sections are
normative, this list is not.

**A server:**

- answers every request, once, in order, and ignores binary frames (§5);
- stamps every event with a gapless seq, placeholders included (§3);
- detaches or ends a session whose connection is lost, ends a detached
  session when its grace lapses, and ends a kicked or banned detached
  session at once (§2);
- closes a taken-over connection with 1008 `replaced` (§2);
- answers `resync_required` rather than replay partially (§3, §6.2);
- sends nothing at or below `sync`'s seq after its reply (§6.3);
- delivers stored mail after the `login`, successful `resume` or `sync`
  reply — never before or inside one, and not after a `resync_required`
  (§6.4);
- advertises exactly the families it serves, and answers an unserved
  family's requests with an error rather than closing (§4);
- shows `idle` and `detached` sessions to classic clients as away (§2);
- issues tokens with enough entropy, ends them with their session, never
  logs them, and applies its ban list to this listener (§9).

**A client:**

- sends only text frames, answers pings, acts on an error's `code` and
  never parses its `text` (§5);
- ignores unknown fields, events, capabilities and error codes, and
  counts unknown events' seqs (§3, §4, §5, §10);
- stores the token like a password and resumes with the last seq it
  received (§6.2), or logs in again when `detach` was `null` (§2);
- on `resync_required`: `sync`, then `inbox`, then `history` from its last
  line id, keeping events it already had (§6.3, §7.1);
- should send a `guid` with every private message and every chat line it
  may send again, and reuse it on retry (§7.1, §7.3); retries a chat
  line only where the server offers `chat_guid` (§4);
- reads an absent `system` as `false` (§7.4);
- with `messaging`, acknowledges each `im` with `receipt`, shows an
  `im` it has shown before once, sends `friends` after each handshake
  and `sync` for what waited, and lets a typing flag lapse (§7.5);
- with `friendships`, sends its withdrawals before `friends`, signs
  friendship objects by its own clock, and presents only where its user
  chose to (§7.5);
- treats `rate_limited` as a delay, not a failure (§9);
- renders no markup in chat that a classic client would not also see as
  text (§8);
- parses file sizes as strings (§7.2).

## 12. Open questions

- Idle: client-set (`{"req":"status"}`), server inactivity timer, or both;
  and whether legacy away toggling (the 0x0ea1 rider) should round-trip
  into ng `idle`.
- Whether the roster should distinguish "same user, multiple sessions"
  before the multi-device future arrives, or let each login be its own
  roster row (as it does now).
- Guest nick collisions: legacy servers allow duplicate nicks; mobile UX
  may want uniqueness. The protocol inherits the legacy answer
  (duplicates fine).
