# Hotline-ng: the WebSocket protocol

Status: built — the core below, plus history (chat-history.md), the
inbox (private-messages.md), news (news.md), media (inline-media.md),
voice and video (voice.md, capabilities-video.md), files (§7.2) and
identity (hotline-ng-identity.md). The vouch requests, `retry_after`,
the `*@host` ban entry and the general rate limits of §9 are design not
yet built in hxd-ng, and say so where they appear.

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
| `files` | The read-only file area | §7.2 here | — |
| `identity` | The server has the identity endpoints of hotline-ng-auth.md | hotline-ng-identity.md §6.1 | fields in `self`, on a socket that authenticated with one |
| `push` | Push device registration | push-notifications.md §8; webpush-gateway.md §7 | `push` |

- `video` MUST NOT appear without `voice`.
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
    "icon": 128              // classic icon id; optional
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
from: the next event it receives has a greater one.

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
  not. A client SHOULD send one. Two sends with the same guid between the
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
- **The reply** is `{ "queued": bool }`: `true` when the message waited
  in the recipient's inbox rather than going straight to a live session.
  It carries no message id (rationale §5).
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
repeated while `has_more`, to recover the gap's public chat. A line
returned by `history` has the same id as its live `chat` event, so the
client deduplicates by id. Mail that arrived while no connection was
attached was never in the buffer; it is still pending, and `sync`
delivers it (§6.4).

### 7.2 Files

The `files` capability means this server exposes the read-only file area.
Every path is slash-separated UTF-8 relative to its root; `""` names the
root. Paths are values, not URLs, and `.` / `..`, empty components, leading
slashes and trailing slashes are malformed.

- `files_list { path? }` returns `{ path, entries }`. Each entry is
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

`files_list` and `files_info` need the account's `[extra] file_list` and
`file_getinfo`, as on the legacy wire. Both are on unless the account file
turns them off, as mhxd has them, so an account that may not download can
still browse. A drop box, any path naming "drop box" in any case, also
lists only for `view_drop_boxes`. `files_download` needs the
`download_files` access bit.

These methods answer errors from this set:

| code | when |
|---|---|
| `bad_request` | malformed params, or a malformed path |
| `not_available` | Files is not configured, or its source is unavailable |
| `access_denied` | `files_list` without `file_list` (or, for a drop box, without `view_drop_boxes`), `files_info` without `file_getinfo`, or `files_download` without `download_files` |
| `not_authorized` | the session ended while the request was handled |
| `not_found` | no entry at that path |
| `not_folder` | `files_list` on a file |
| `not_file` | `files_download` on a folder |
| `too_large` | the entry exceeds this server's size limit |
| `busy` | this server's outstanding-download limits are reached; retry later |
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
| `chat` | `text`, `style?` (`"normal"` \| `"action"`), `media?` | `{}` | `server_error` |
| `nick` | `nick?`, `icon?` | `{}` | — |
| `msg` | exactly one of `to` (uid) / `to_login`; `text`; `guid?`; `media?` | `{ "queued": bool }` | `no_such_user`, `mailbox_full`, `blocked`, `server_error` |
| `history` | `before?`, `after?` (line ids), `limit?` (1–200, default 50) | `{ "lines": […], "has_more": bool }` | `not_available`, `server_error` |
| `inbox` | `before?` (message id), `limit?` (1–200, default 50) | `{ "messages": […], "unread", "total" }` | `no_inbox`, `server_error` |
| `msg_read` | `up_to` (message id) | `{ "unread", "total" }` | `no_inbox`, `server_error` |
| `block` | exactly one of `uid` / `login` | `{}` | `no_such_user`, `no_inbox`, `server_error` |
| `unblock` | exactly one of `uid` / `login` / `fingerprint` | `{}` | `no_such_user`, `no_inbox`, `server_error` |
| `blocks` | — | `{ "blocked": [ { "login", "fingerprint"? } ] }` | `no_inbox`, `server_error` |
| `vouch` / `unvouch` / `vouches` | identity-vouch.md §3.2 | there | there. *Design, not built.* |
| `ping` | — | `{}` | — |
| `logout` | — | `{}` | — |

- **`chat`** needs the send-chat privilege. The text MAY contain line
  breaks and is relayed as one event. `media` is inline-media.md §8.3's.
- **`nick`** changes this session's nick and icon. A new nick is honored
  only with the use-any-name privilege and is otherwise ignored, as is an
  empty one; either way the reply is `{}`.
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
  read, media? }`; there is no uid, which may have been reused since.
- **`msg_read`** marks every message of this account's with an id at or
  below `up_to` read, and returns the counts after it.
- **`block`** refuses mail from an account, or from the identity of a
  session on the roster; **`unblock`** accepts it again. `fingerprint`
  names an existing block by the 52-character fingerprint `blocks`
  reports, and is valid only for `unblock`. A block keyed on a fingerprint
  lists with `fingerprint` present; one keyed on an account lists without
  it.
- **`logout`** ends the session at once, with no grace, and the server
  then closes the connection (§5).

**News** (`news_*`), **push** (`push_register`, `push_unregister`),
**voice** (`voice_*`), **video** (`video_*`) and **files** (`files_*`)
requests are specified where §4 says.

`rate_limited` from `chat`, `msg` and the news posts during a never-seen
key's newcomer delay carries `retry_after` (seconds) in the error object,
so a client can disable its compose box for that long rather than retry
blind (identity-registrar.md §7.3). *Design, with the registrar.*

### 7.4 The core events

| `ev` | `data` | Sent when |
|---|---|---|
| `user_joined` | `{ "user": {…} }` | A session joins the roster. |
| `user_changed` | `{ "user": {…} }` | A session's nick, icon, `admin` flag or status changes. |
| `user_parted` | `{ "uid": n }` | A session leaves the roster. |
| `chat` | `{ "from": { uid, nick }, "text", "style", "at", "id"?, "media"? }` | A line of public chat. `id` is present when the server kept the line (the `history` capability). |
| `notice` | `{ "text" }` | A server notice, such as a kick announcement. |
| `subject` | `{ "subject" }` | The public chat's subject changed. |
| `broadcast` | `{ "from": { uid, nick }, "text" }` | An administrator's broadcast. |
| `msg` | `{ "from": { uid, nick, login? }, "text", "at", "queued", "id"?, "media"? }` | A private message (§7.1). |
| `kicked` | `{}` | This session was kicked. The server then closes the connection (§5) and the session is over. |

Timestamps (`at`) are integer Unix seconds. Events of the extension
families — `voice_*`, `video_status`, `news_*` — are specified where §4
says, and `media_revoked`, `chat_redacted`, `report` and `report_closed`
in moderation.md §5, whose requests — `report`, `redact`, `revoke`,
`purge`, `kick` and the rest — are specified there too. Every event, of any family,
counts in §3's sequence.

**The `user` object:**

```jsonc
{
  "uid": 3, "nick": "Alice", "icon": 128,
  "admin": false,
  "status": "active",              // §2
  "transport": "encrypted",        // encrypted | cleartext
  "identity": {                    // absent unless the session proved one
    "fingerprint": "6htgz65…",     // 52 characters, Crockford base32
    "handle": "alice@hl.example"   // null when no attestation was accepted
  },
  "system": true                   // only on the server's own account
}
```

| Field | Rule |
|---|---|
| `uid` | §2. |
| `nick`, `icon` | As shown to every other user, classic clients included. |
| `admin` | The user may disconnect other users: the classic wire's admin color. |
| `status` | §2. |
| `transport` | Required. `"cleartext"` when any hop between this user's client and the server is unencrypted, as far as the server knows: a classic client on plain TCP, or a tunnel that declared its downstream hop cleartext (hotline-ng-auth.md §7.2, §8). A client MAY warn before sending a private message to a `cleartext` user. |
| `identity` | Present only when the session authenticated with an identity (hotline-ng-identity.md §6.1). It carries only what the roster may see: never `age`, `outcome` or anything that authorizes. |
| `system` | Present, and `true`, on exactly one user, the server's reserved account (system-account.md §2), when the server runs one; absent on every other user. Clients MUST read an absent `system` as `false`. That user is always on the roster, has `admin` set, cannot be kicked or banned, and is the sender and addressee of server mail and commands (system-account.md §3). |

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
user typed is what arrives.

**Chat text is plain text.** A server MUST NOT parse, rewrite or
annotate it. A client MAY render a closed markdown dialect in it on
receipt, and SHOULD use the one GtkHx and hx-ng share (rationale §5); it
MUST NOT render anything a classic client would not also see as text. A
news body is different: it declares its own type (news.md §5).

## 9. Security

- **TLS.** In production the WebSocket MUST be `wss://`. A server that
  speaks plaintext SHOULD listen only on loopback by default, behind a
  proxy that terminates TLS. *hxd-ng* never speaks TLS itself.
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
  client MUST NOT treat as fatal. *hxd-ng* limits `history`,
  `news_search`, media and news-attachment uploads, media downloads, and
  enrollment; the general per-connection and login-attempt limits are not
  yet built.
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
| `server_error` | The server failed. Not the client's fault; MAY be retried. |

**Core** — from §6 and §7:

| Code | From | Meaning |
|---|---|---|
| `login_failed` | `login` | Wrong account or password. |
| `denied` | `login` | Identity policy refused this socket. |
| `revoked` | `login` | This identity or device key is revoked here. |
| `banned` | `login` | Banned (§6.1). |
| `server_full` | `login` | No uid free. |
| `session_expired` | `resume` | Log in again. |
| `resync_required` | `resume` | Attached; follow with `sync`. |
| `not_available` | `history`, `files_*`, family requests | The server does not offer this. |
| `no_such_user` | `msg`, `block`, `unblock` | No such uid, no such account, or that account takes no offline mail — one answer for all three. |
| `no_inbox` | `inbox`, `msg_read`, `block`, `unblock`, `blocks` | *Your* account has no inbox, or the server has none: the `inbox` family's "not available" code. |
| `mailbox_full` | `msg` | The recipient's inbox is at its cap. |
| `blocked` | `msg` | The recipient blocks you. |

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
- should send a `guid` with every private message, and reuse it on retry
  (§7.1);
- reads an absent `system` as `false` (§7.4);
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
