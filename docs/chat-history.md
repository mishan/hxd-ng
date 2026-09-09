# Chat history: server-held scrollback for both wires

ROADMAP Phase 6 item 1 promises "server-held scrollback replay" and notes
that no public server implements fogWraith's spec — hxd-ng becoming the
first real implementation, and so the reference GtkHx tests against, is
the motivation. This document designs it for the legacy wire (fogWraith
[Capabilities-Chat-History.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Chat-History.md),
read at `main` on 2026-09-08) and for Hotline-ng, from one store.

**Decision (2026-09): public chat is a log, and the log is a table in the
inbox's SQLite file.** A `ChatLog` trait in `hxd-core`, an in-memory
implementation for tests, and the SQLite one in `hxd-store-sqlite` as a
second table behind the store that already holds private messages. A
line is appended and given its id *before* it is fanned out, so the live
event and the history entry are the same fact with the same id on both
wires. Private chats are never written, which is the spec's rule and
ours. Off unless configured, like the inbox.

The companion design, [inline-media.md](inline-media.md), is what a
history entry carries when a line had an image; §8 here is the seam.

---

## 1. Where we are

A chat line is `Event::Chat { cid, from, text, style }`, built in
`Core::chat_public` and handed to every visible session's outbox
(`crates/hxd-core/src/chat.rs`). Nothing writes it down. A client that
arrives sees an empty pane; a client that reconnects has lost whatever
happened while it was gone — on the ng wire, a resume replays the outbox
buffer, but a lapsed grace window or a `resync_required` loses the lines
for good, and there is nowhere to ask.

The pieces the design needs already exist:

- **Capability negotiation** on both wires: `Caps` and `cap::CHAT_HISTORY`
  (bit 4) in `hxd-session/src/caps.rs`, echoed at LOGIN from
  `ServerConfig::caps`; the ng login reply's `caps` list.
- **Access bit 56** is already pinned as `bit::CHAT_HISTORY` in
  `hxd-core/src/access.rs`, from the same fogWraith allocation table.
- **The store crate** and its conventions: one connection behind a mutex,
  WAL, unix-seconds at the boundary, `SCHEMA_VERSION` with a migration
  arm per bump.
- **The hourly sweeper** in the binary that runs inbox retention.
- **The client side**: GtkHx parses `DATA_HISTORY_ENTRY` with
  `hxproto::parse::parse_history_entry`, fetches an initial batch
  after USER_GETLIST, uses `BEFORE` for "Load older" and `AFTER` for a
  reconnect catch-up, and renders the action / server-message / deleted
  flags. Its tests run against a mock; this server replaces the mock.

## 2. What the spec asks, and where it is silent

The spec is short and mostly mechanical. What a conforming server owes:

- Echo bit 4 only when history is enabled; echo it **regardless of the
  user's privilege** (the bit says the server can, not that you may).
- Optionally advertise retention as `DATA_HISTORY_MAX_MSGS` (`0x0F07`)
  and `DATA_HISTORY_MAX_DAYS` (`0x0F08`) beside the echo.
- Answer `Get Chat History (700)`: `DATA_CHANNEL_ID` (`0x0F01`, u32,
  required), `DATA_HISTORY_BEFORE` (`0x0F02`, u64), `DATA_HISTORY_AFTER`
  (`0x0F03`, u64), `DATA_HISTORY_LIMIT` (`0x0F04`, u16, default 50) with
  zero or more `DATA_HISTORY_ENTRY` (`0x0F05`) **oldest first** and one
  `DATA_HISTORY_HAS_MORE` (`0x0F06`, u8) meaning "more in the direction
  of the query".
- Pack each entry as `u64 id, i64 unix seconds, u16 flags, u16 icon,
  u16 nick_len, nick, u16 msg_len, msg`, then optional mini-TLV
  sub-fields (`u16 type, u16 len, bytes`) a client skips when unknown.
- Flags: bit 0 action (`/me`), bit 1 server message, bit 2 deleted
  (tombstone: id and timestamp kept, text may be empty).
- Text in the connection's negotiated encoding, `?` for unmappable.
- Channel 0 only; error on any other channel. **Never persist private
  chats.**
- Gate on bit 56, falling back to bit 9 where 56 has no meaning.
- Retention by count and by age; prune off the request path.

Two things it leaves open that this design has to answer:

1. **Sub-field types.** The chat-history document defines none and the
   inline-media document says sub-fields `0x0010`–`0x0014` "are
   allocated to this extension" in a section of the history document
   that does not exist (its link is to `Capabilities-Chat-Cistory.md`).
   §8 allocates them provisionally, and §11 lists it as the first thing
   to raise upstream.
2. **What a message id is.** Only "monotonically increasing uint64,
   opaque". §4 makes it a SQLite `AUTOINCREMENT` rowid, which is
   monotonic even across deletes, and nothing on either wire is allowed
   to know that.

## 3. The domain: a line has an id before anyone sees it

### 3.1 The trait

```rust
pub type LineId = u64;

pub struct NewLine {
    pub channel: u32,              // 0 today; the column exists for the future
    pub from_nick: String,
    pub from_login: Option<String>, // None for a guest; moderation, never the wire
    pub from_fingerprint: Option<[u8; 32]>,
    pub icon: u16,
    pub text: String,
    pub flags: LineFlags,          // ACTION | SERVER_MSG | DELETED
    pub at: SystemTime,
}

pub struct LogLine { pub id: LineId, /* the fields above */ pub media: Option<MediaMeta> }

pub struct HistoryQuery {
    pub channel: u32,
    pub before: Option<LineId>,   // strictly less than
    pub after: Option<LineId>,    // strictly greater than
    pub limit: usize,             // already clamped by the caller
}

pub struct HistoryPage { pub lines: Vec<LogLine>, pub has_more: bool }

pub trait ChatLog: Send + Sync + 'static {
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError>;
    fn query(&self, q: &HistoryQuery) -> Result<HistoryPage, StoreError>;
    fn tombstone(&self, id: LineId, at: SystemTime) -> Result<bool, StoreError>;
    fn prune(&self, max_lines: usize, max_age: Option<Duration>, now: SystemTime)
        -> Result<usize, StoreError>;
    fn attach_media(&self, id: LineId, media: &MediaMeta) -> Result<(), StoreError>;
}
```

Synchronous, like `MessageStore` and for the same reason (`inbox.rs`
module docs): `Core` is sync all the way down. `has_more` is computed by
the store — fetch `limit + 1`, return `limit` — so a client never learns
it from a count that a concurrent insert could make stale.

`query` returns ascending id order always, whichever cursor was used.
When both cursors are present they define the exclusive range
`after < id < before`, paged forward from `after`; `has_more` only reports
additional rows inside that range.
For a `before`-only or no-cursor query the store selects descending with
`LIMIT n+1` and reverses, which is what makes "the most recent 50" one
indexed seek rather than a table scan.

### 3.2 Ordering: append, then fan out, under one lock

`Core::chat_public` becomes:

```
let _serial = self.log_serial.lock();      // chat lines only; nothing else takes it
let id = log.append(&line)?;               // one INSERT, sub-millisecond
let ev = Event::Chat { id: Some(id), at, .. };
roster.lock().broadcast_where(&ev, None, reads_public_chat);
```

The extra mutex is the whole ordering argument. Without it, two lines
appended from two blocking threads could take ids in one order and reach
outboxes in the other, and a client's `after` cursor would then skip a
line it had actually seen live. With it, **history order is live order**,
which is the property that lets an ng client dedupe the live stream
against a catch-up page by id alone.

The cost is that public chat lines serialise through one SQLite insert.
On a server for friends that is nothing; if it ever is something, the
trait is the seam and a write-behind log with pre-assigned ids is the
answer behind it, not a weaker ordering rule above it.

The insert now sits on the chat path, so the frontends call
`chat_public` through `off_reactor` exactly as they call `msg` — the
legacy handler currently calls it inline on the reactor, and that
changes. A server with no log configured takes the same path with a
no-op log that hands out `None`, so there is one code path, not two.

### 3.3 What is written

- **Public chat lines and actions** (`Event::Chat`, cid 0), from either
  wire. `style == 1` sets the action flag.
- **Nothing else in v1.** Broadcasts, kick notices, subject changes and
  join/part are not lines; the history is the conversation. The spec
  permits recording broadcasts under the server-message flag and the
  column is there when someone wants it (§11).
- **Never a private chat** (cid ≠ 0). This is a `MUST NOT` in the spec
  and matches the expectation that the private-messages design already
  treats as load-bearing: pulling people aside is meant to leave no
  record on the server.

What is stored per line beyond the wire fields: the sender's login and
identity fingerprint. Neither ever crosses either wire in v1; they exist
so a future moderation tool (spec transactions 703/704, reserved) can
find every line a person wrote without guessing from nicks, and so a
tombstone can say who it was. They are the same two columns the inbox
keeps for a sender, kept for the same reason, and they are what a
purge (moderation.md §3.3) selects on.

### 3.4 The event grows two fields

```rust
Event::Chat {
    cid: u32,
    from: UserInfo,
    text: String,
    style: u16,
    id: Option<LineId>,   // Some when the line was persisted
    at: SystemTime,       // the server's receive time, the one in the log
    media: Option<MediaRef>,   // inline-media.md
}
```

The legacy encoder ignores `id` and `at` (a 106 has nowhere to put them,
and formatting a timestamp into the line would break the 13-column
alignment period clients depend on). The ng encoder emits both (§7).

## 4. Storage

### 4.1 One file, two tables

`[history]` names a SQLite file. When it is the same path as
`[inbox].db` — the recommended arrangement, and the default when
`[history]` omits `db` and an inbox exists — the binary opens **one**
`SqliteStore` and hands the same object out as both `MessageStore` and
`ChatLog`. Two connections to one file would mean two schema owners, and
WAL does not make that a good idea.

Schema version 2 adds:

```sql
CREATE TABLE chat_line (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  channel     INTEGER NOT NULL DEFAULT 0,
  nick        TEXT    NOT NULL,
  login       TEXT,
  login_fp    TEXT,
  icon        INTEGER NOT NULL DEFAULT 0,
  flags       INTEGER NOT NULL DEFAULT 0,
  body        TEXT    NOT NULL,
  at          INTEGER NOT NULL,          -- unix seconds
  deleted_at  INTEGER,
  media_id    BLOB,                      -- inline-media.md §9
  media_type  TEXT,
  media_w     INTEGER,
  media_h     INTEGER,
  media_bytes INTEGER
);
CREATE INDEX chat_line_by_channel ON chat_line (channel, id);
CREATE INDEX chat_line_at ON chat_line (at);   -- retention by age
```

`AUTOINCREMENT` costs a `sqlite_sequence` row and buys the spec's one
guarantee: an id is never reused, so a client's cursor from last week
still means what it meant. Plain `INTEGER PRIMARY KEY` can hand out a
deleted maximum rowid again, and retention deletes rows.

The migration is additive; the v1 `message` table is untouched by this
document (inline-media.md §9 adds its media columns in the same bump).
A database opened by a build that has history but no `[history]` section
still migrates to v2 — an empty table is not a feature.

### 4.2 Retention

`max_lines` (default 10 000) and `max_days` (default 0 = unlimited),
pruned by the existing hourly sweeper, never on a request. Pruning
deletes the oldest rows past the count and any row older than the age;
tombstones age out like everything else. Both values are advertised at
LOGIN (§6.1) and in the ng login reply (§7.1) whenever non-zero.

Tombstoned rows keep their id and timestamp with `body` and `nick`
emptied — the spec's cursor-stability argument, which is real: deleting a
row a client is paging past would make its next `before` skip or repeat.
What tombstones a row is a moderator's redaction — from the ng wire
or the CLI, with a reason and an audit row — designed in
[moderation.md](moderation.md) §3.1; transaction 703 is reserved
upstream and stays reserved here until it is defined.

### 4.3 Encryption at rest

Not in v1. The file has the inbox's `0600` treatment and the same
README warning, which is the honest answer for a server whose accounts
directory is already the crown jewels. The spec's suggestions (SQLCipher,
application-level ChaCha20) are all behind the trait if an operator ever
needs one.

## 5. Access

Bit 56 gates `700` on the legacy wire and `history` on the ng wire.
The spec's fallback — "if the server's access system does not assign
meaning to bit 56, check bit 9" — is expressed **at account-load time,
not at request time**: the file backend's `[access]` section gains
`read_chat_history`, and when the key is absent the bit takes the value
of `read_chat`. An operator who wants the distinction writes the key;
one who does not gets the spec's fallback with no code path deciding it
per request. It also means the bitmap a client sees in SELFINFO is the
truth, which this server already promises.

`FileAuth::bootstrap` gives the guest account `read_chat_history`
matching its `read_chat`, so a fresh server shows scrollback to a guest
who can read the room.

Bit 4 is echoed to every client that asks when `[history]` is
configured, whatever the account's bits say. A client that has the
capability and lacks the permission gets a readable task error from 700
and `access_denied` from `history`, and can show a disabled control
rather than nothing.

## 6. The legacy wire (`hxd-session`)

### 6.1 LOGIN

`ServerConfig::caps` gains bit 4 when `[history]` is configured; the
existing intersect-and-echo does the rest. Beside the echo, when the bit
survived the intersection, the reply carries `0x0F07` and `0x0F08` as
u32 BE for every retention value that is non-zero. A zero is not sent —
"0 = unlimited" in the spec and absence mean the same thing to a client,
and one shape is one less case.

### 6.2 Get Chat History (700)

In dispatch, gated like the voice transactions: a session that did not
negotiate bit 4 gets a task error rather than an answer (the spec allows
either; an error is the one a client author can debug).

Parse: `CHANNEL_ID` required, u32, must be 0 — anything else answers
"No such channel."; `BEFORE` and `AFTER` u64, absent when zero on the
wire as GtkHx sends them; when both are present they define the exclusive
range `AFTER < id < BEFORE`, paged forward; `LIMIT` u16, absent or 0 means the default 50,
anything above `[history] max_page` (default 200) is clamped silently,
as the spec says.

Then: bit 56 or "You are not allowed to read chat history."; the
per-session rate limit (10 requests per second, token bucket, the spec's
suggested figure) or "Slow down."; `off_reactor` into
`Core::history(uid, query)`; encode.

Encoding an entry is the mirror of `parse_history_entry` in the shared
crate, and lands beside it in `hxproto` as `build_history_entry`
so the two cannot disagree about a byte. Nick and body pass through the
session's text conversion — Mac Roman today, UTF-8 once Text-Encoding
lands — with the lengths taken **after** conversion; the nick was
truncated to 31 characters on the way in, so it fits, and a body is at
most 4096 bytes, so an entry is far under the 65 535 the field can
carry even with the media sub-fields of §8. Flags map one to one from
`LineFlags`. Entries go out ascending, then `HAS_MORE`.

A tombstoned line is sent with the deleted flag, empty nick, empty
body, and no sub-fields.

### 6.3 What GtkHx does, and one thing it does not

GtkHx's backward paging is deliberate and manual: a "Load older" row
that fires `BEFORE = oldest_msgid` on click and is drawn only while the
last reply said `has_more`. That shape fits this server exactly and
needs nothing from it.

Its post-login fetch is the other direction. On a first connect it asks
for `limit = chat_history_initial` (default 50); on a reconnect it asks
for `AFTER = last_msgid` with **no limit**, expecting "the server
applies its own". This server applies the default 50 and answers
`has_more = 1` when the gap was larger, and GtkHx's reply handler
advances its cursor and renders the batch but does not issue a
follow-up, so a client that missed more than 50 lines sees the first 50
of them and the rest never arrive. That is a client gap — a loop on
`has_more` in the catch-up path — noted here because this is the first
server whose answer will make it visible.

### 6.4 Legacy replay — off by default

The spec lets a server push recent lines as ordinary 106s to a client
that did not negotiate the bit. **hxd-ng does not, unless told to.** A
1.5 client is the population this project promises never to surprise,
and thirty lines arriving the instant the user list lands is exactly
that surprise; Hotline Navigator's heuristic for labelling them is not
something a period client has. `[history] replay = N` turns it on for
an operator who wants it, formatted as `\r[HH:MM] name:  text` so it is
at least visibly not live, sent after the client's USER_GETLIST (the
moment the spec suggests, and the one that means the client is ready to
draw), and never to a session that negotiated bit 4.

## 7. The ng wire (`hxd-ng-session`)

### 7.1 Login reply

`caps` gains `"history"`. A `history` block rides beside `video` and
`inbox`, present exactly when the cap is:

```jsonc
"history": { "max_lines": 10000, "max_days": 0 }
```

### 7.2 The `history` request

hotline-ng.md §11 sketched `{ "before_seq" }`; that was the wrong
cursor. A seq is per session and dies with it; a line id is what
survives a re-login, a second device, and a lapsed grace window.

| `req` | params | ok | errors |
|---|---|---|---|
| `history` | `before?` (id), `after?` (id), `limit?` (1–200, default 50) | `{ "lines": [ … ], "has_more": bool }` | `access_denied`, `not_available` (no `[history]`), `bad_request`, `rate_limited`, `server_error` |

Supplying both cursors requests the exclusive range `after < id < before`.
It pages forward from `after`, and `has_more` refers only to more rows before
the upper bound.

`lines` ascend by id. Each is the live `chat` event's data plus its
id and time, and a `deleted` flag when tombstoned:

```jsonc
{ "id": 1001, "at": 1729137541,
  "from": { "nick": "alice", "icon": 128 },
  "text": "What's up?", "style": "normal",
  "media": { … } }               // inline-media.md §8, when the line had one
```

No `uid` in `from`: the sender's uid was recycled minutes after they
left, and a client that keyed anything on it would attribute old lines
to whoever holds the number now. Live `chat` events keep `uid` because
the roster row is live. `from.login` is never sent (§3.3).

The same clamps as the legacy wire: 200 lines a page, 10 requests a
second, `channel` is not a parameter because there is one channel.

The shape is built for a client that loads as the user scrolls, which
is what hx-ng is expected to do where GtkHx has a button: each page's
oldest `id` is the next `before`, `has_more: false` is the top of the
conversation, and a page of 50 is small enough that a scroll-triggered
request finishes before the user reaches the top of the previous one.
The request rate limit is there for a scroll handler that fires too
eagerly, and `rate_limited` is the answer it gets, not a dropped
request — a client can back off and retry rather than lose its place.

### 7.3 The `chat` event grows `id` and `at`

```jsonc
{ "seq": 42, "ev": "chat", "data": {
    "from": { "uid": 3, "nick": "alice" }, "text": "hi", "style": "normal",
    "id": 1002, "at": 1729137560 } }
```

`id` is present exactly when the server persisted the line; a server
without `[history]` sends the event as it does today, so a client tests
for the key. `at` is always present — it costs nothing and a mobile
client wants to render a time on every line whether or not it can
scroll back.

**A client that resyncs pulls `history` with `after`.** This is
hotline-ng.md §7.1's inbox rule with a sibling: the events in a `resync_required` gap are
gone from the outbox, but every public line among them is in the log
under an id greater than the last one the client rendered. The recovery
is `sync`, then `inbox`, then `history { after: last_id }`, looping on
`has_more`. A client that reconnects after the grace window does the
same with a fresh `login`. Lines it already has and lines the catch-up
returns are the same lines with the same ids, so deduping is a set
lookup, not a heuristic — which is what §3.2's ordering lock is for.

## 8. Media in a history entry

A line sent with an inline image (inline-media.md) is stored with the
canonical metadata the relay carried — handle, MIME type, width, height,
byte size — and its history entry carries them as mini-TLV sub-fields.
The allocation is **provisional**, chosen to match the range the
inline-media document claims:

| Sub-type | Content | Size |
|---|---|---|
| `0x0010` | Media handle (`DATA_CHAT_MEDIA_ID` bytes) | ≤ 64 |
| `0x0011` | Canonical MIME type | ≤ 64 |
| `0x0012` | Width, u32 BE | 4 |
| `0x0013` | Height, u32 BE | 4 |
| `0x0014` | Canonical byte size, u32 BE | 4 |

`0x0011`–`0x0014` are sent for every line that had media — a client can
say "[image, PNG, 800×600]" forever. `0x0010` is sent only while the
handle is still live, and whether a history reader may then *download*
it is inline-media.md §5.4's question. On the ng wire the same five
values are the line's `media` object, with `id` absent once the handle
has expired.

GtkHx today skips all sub-fields, so nothing changes for it until it
chooses to render the placeholder.

## 9. Configuration

```toml
[history]
db = "hxd.sqlite"      # optional when [inbox] names a file; then it is that file
max_lines = 10000      # 0 = unlimited; advertised as DATA_HISTORY_MAX_MSGS
max_days = 0           # 0 = unlimited; advertised as DATA_HISTORY_MAX_DAYS
max_page = 200         # the clamp on a client's limit
replay = 0             # lines pushed as plain 106s to non-capable legacy clients
```

The section's presence is what turns history on, and it is a startup
error in a build without the `inbox` feature, which is where the SQLite
crate lives — the same shape as `[inbox]` itself. The feature is not
renamed; a `store` feature that both sections require is a rename for
the day a third table arrives.

## 10. Staging

H1–H3 are implemented in hxd-ng. H4 is the remaining client-side follow-up;
H5 belongs to the moderation implementation.

1. **H1 — the log.** `ChatLog`, `MemoryLog`, `LineFlags`, the
   `Event::Chat` fields, the serialising lock in `chat_public`, schema
   v2 and the SQLite implementation, retention in the sweeper. Unit
   tests in `hxd-core` (ordering under concurrent appends, cursor
   semantics in every combination, `has_more` in each direction,
   tombstones surviving prune until aged) and the conformance suite run
   against both stores, like the inbox's.
2. **H2 — the legacy wire.** `build_history_entry` in `hxproto`
   (landed in `hx-libs` before advancing hxd-ng's exact git pin), LOGIN
   advertisement, 700 dispatch with the clamps and gates, replay behind
   its config. E2E in `crates/hxd/tests/history.rs`: a scripted client
   negotiating bit 4, initial page, `before` paging to the beginning,
   `after` catch-up across a reconnect, the bit-56 refusal, channel 1
   refused, a non-negotiating client getting an error, Mac Roman
   transcoding of a UTF-8 line that an ng client sent.
3. **H3 — the ng wire.** `history` request, the `chat` event fields, the
   login-reply block, the resync rule in `hotline-ng.md` §7.1. E2E:
   an ng client dedupes a live line against its catch-up page by id; a
   line sent from the legacy wire comes back to an ng client with the
   same id both saw live.
4. **H4 — GtkHx against a real server.** Point the Tier-3 suite's
   history cases at hxd-ng in place of the mock, and fix the catch-up
   loop of §6.3 on the client side.
5. **H5 — moderation** (moderation.md §8), once the rows exist.

## 11. Open questions, and what to raise upstream

- **Sub-field allocation.** The inline-media document references a
  table the history document does not have. Ask fogWraith to add the
  allocation of §8 (or tell us the real one) before H2 emits a byte of
  it; until then the types are marked provisional in the code.
- **Reader download rights** for public-chat media in history — the
  spec's "no retroactive widening" rule against the obvious wish to see
  the picture in scrollback. inline-media.md §5.4 has the knob and the
  argument; it belongs in the same upstream conversation.
- **Should broadcasts be lines?** The spec allows it under the
  server-message flag. Leaning no: a broadcast is an admin's interrupt,
  not part of the conversation, and a client that renders it inline
  live does not need it again in scrollback.
- **Named channels** (ids 1+, transactions 701/702) are reserved
  upstream and untouched here; the `channel` column exists so adding
  them is not a migration.
- **The catch-up loop in GtkHx** (§6.3) is a client change this server
  will make necessary.
- **Redaction and reporting** are [moderation.md](moderation.md); its
  §8 asks upstream to define 703 as redact and to allocate a report
  transaction.
