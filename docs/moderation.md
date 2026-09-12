# Moderation: removing bad content, and hearing about it

Status: design, not built. Kick and ban are what they have always been;
the acts, reports, tables and requests below are chat-history.md §10's
H5 and wait on it. The 2026-09 amendments from system-account.md §6 and
identity-vouch.md §6 and §10 are folded in.

[chat-history.md](chat-history.md) makes public chat a record and
[inline-media.md](inline-media.md) lets people post images into it. A
server that keeps what people said and shows what people sent needs a
way to take it back, and a way for the people who saw it first to say
so. Neither fogWraith document has one: the history spec reserves
`703 Delete Chat History Message` and `704 Edit` and forbids using
them; the media spec says handles "MAY be deleted earlier on operator
demand (e.g. moderation tooling)" and stops there. This document is
the tooling.

**Decisions (2026-09):**

- **Three acts, one audit trail.** Redact a line, revoke an image, purge
  a person's recent output. Every act is a row in a `moderation` table
  with who, what, why and when, and every act is reachable from the ng
  wire and the operator CLI.
- **Reports are rows too**, filed against a line, an image, a private
  message or a person, delivered to whoever can act on them the moment
  they are filed, and closed with an outcome that the reporter can see.
- **Who moderates is `[extra] moderate`**, defaulting to the kick bit.
  Someone trusted to disconnect a person is trusted to redact what they
  posted; an operator can say otherwise per account either way.
- **A redacted line keeps its id and loses its text on every wire**,
  including to clients that already rendered it, where the wire can say
  so. A revoked image is gone from memory at once and its hash is
  remembered so it cannot come back.
- **The legacy wire can be moderated from, but not moderate.** Kick and
  ban work as they always did; redaction, revocation and reporting need
  transactions the spec has not allocated, so on that wire moderators
  receive reports as server messages and act from an ng client or the
  CLI. §8 says what to propose upstream.

---

## 1. What is at stake

Three things, in the order a moderator meets them:

1. **Someone posted something that should not stay.** A slur in
   scrollback that every new arrival reads; an image nobody should
   have to see. The line has an id and the image has a handle; both
   are in the store and both are being served.
2. **Someone keeps doing it.** Kick and ban exist, but the last twenty
   minutes of their output do not go with them, and a revoked image can
   be uploaded again from the same file.
3. **The moderator was not there.** The people who saw it are, and they
   have no way to say so except a private message to an admin who may
   be asleep, on a wire that may have no such admin online.

The inbox brought the first durable store; history and media bring the
first durable *content*, and content is what gets moderated.

## 2. Who may

`Account` gains `moderate: bool`, resolved by the file backend from
`[extra] moderate` and **defaulting to the account's `disconnect_users`
bit (22)**. That bit is what a period server calls a moderator: the
person who can kick. The default makes an existing admin account a
moderator with no file edits, and the key lets an operator hand
redaction to someone who may not kick, or withhold it from someone who
may.

It is `[extra]` and not an access bit for the reason hotline-ng.md §4/D5
gives: server-local policy that never crosses the wire as a bit. It does
cross the ng wire as a fact — the login reply's `self` gains
`"moderator": true` so a client can show the controls — which is a
statement about this session, not a bitmap position anyone else has to
agree on.

A moderator may not redact, revoke or purge a session that has
`cant_be_disconnected` (bit 23) unless they have `delete_users` (bit 15)
— the same ladder kick uses, so "can be kicked by" and "can be moderated
by" are one question.

## 3. The acts

All three run in `hxd-core`, take the acting principal and a reason,
write the audit row first, and then do the thing. A reason is required
and at most 512 characters; "no reason" is a legitimate reason, but it
has to be typed.

### 3.1 Redact a line

`Core::redact_line(by, id, reason)`:

1. Audit row: `redact`, actor, line id, the line's sender (login and
   fingerprint), the reason, now.
2. The line's body and nick are moved out of `chat_line` into the audit
   row's `evidence` column and replaced with empty strings; `flags` gains
   `DELETED`; `deleted_at` is stamped. The id and timestamp stay — the
   history spec's cursor-stability argument, and ours.
3. If the line carried media, its handle is revoked (§3.2) in the same
   act; the media metadata columns stay, so a history entry can still
   say "[image removed]".
4. `Event::ChatRedacted { cid: 0, id }` to every session that reads
   public chat.

Evidence — the original text — lives in the audit row for
`[moderation] evidence_days` (default 30) and is then scrubbed to an
empty string by the sweeper, leaving the row. Moderators can read it
through `reports` and `moderation_log` while it exists; nobody else
ever can. The retention is the operator's window to answer "why was
this removed?" and the scrub is the promise that the removed thing does
not sit on the server forever.

### 3.2 Revoke an image

`Core::revoke_media(by, handle, reason, block)`:

1. Audit row: `revoke`, actor, handle, uploader, reason, canonical
   SHA-256, byte size, dimensions, MIME.
2. The canonical bytes are dropped from the store at once — an
   in-flight 751 or `GET /media` gets "Media not found" on its next
   part. The handle's metadata is kept for the handle's remaining
   lifetime so that lines and inbox rows referencing it keep rendering
   a placeholder rather than nothing.
3. With `block` (the default), the canonical hash goes into
   `media_block` and any future upload whose canonical bytes hash the
   same is refused with code 0 and the text "Media rejected". The hash
   is of the *canonical* bytes, so the same source file re-uploaded is
   caught, and a recompressed one is not — this is a nuisance filter,
   not a fingerprint system, and it says so in the config.
4. `Event::MediaRevoked { id }` to every principal in the handle's
   authorisation set that has a session — the people who may have it on
   screen.

A revoked handle is also removed from every open report that named it,
with the report resolved as `removed` (§4.4).

### 3.3 Purge a person

`Core::purge_sender(by, who, since, reason)`, where `who` is a login or
a fingerprint and `since` is a duration (default 1 hour, max
`[history] max_days` or unlimited): every line by that sender in the
window is redacted as in §3.1, every live handle they uploaded in the
window is revoked as in §3.2, one audit row of kind `purge` records the
count and the ids. This is the act that goes with a ban, and the ng
`kick` request gains `purge?: seconds` so a moderator does both in one
motion.

A purge is by sender identity, not by uid: the sender may be gone, and
the uid may be someone else's by now. The chat log stores login and
fingerprint for exactly this (chat-history.md §3.3).

Every path that bans — `kick { ban }` on the ng wire, a legacy kick
with ban, an entry added to the ban list, and `kick { purge }` — also
writes the voucher suspension identity-vouch.md §6 describes when the
subject was admitted on a vouch. What it writes, for how long, and what
it pointedly does not do to the voucher are that section's to say; the
row it leaves is §7's `vouched_banned`, and the moderator making the
decision has the voucher's name in front of them (`vouched_by`, §7).

### 3.4 What is not an act

- **Editing a line** (704 upstream). No. A moderator changes what a
  person is on record as having said, or removes it; the second is the
  only one this server offers.
- **Deleting a private message from a recipient's inbox.** No. The
  recipient reported it (§4.2) and can delete it themselves when the
  inbox grows deletion; the moderator's remedy is the sender, not the
  row.
- **Un-redacting.** No. A redaction was a decision with a reason on
  record; reversing it is a new line.

## 4. Reports

### 4.1 What can be reported

| Target | Named by | Evidence attached |
|---|---|---|
| A public chat line | line id | none needed — the moderator can read the line |
| An image | handle | the handle is **pinned** and moderators are added to its set (§4.3) |
| A private message | inbox message id, by its recipient only | the message body, copied into the report by the recipient's act of reporting |
| A person | login, or fingerprint, or a uid on the roster | nothing; the reason is the evidence |

A report has a reason, required, at most 1024 characters. It is stored
with the reporter's mailbox (login and fingerprint), the target, the
evidence, and `open` status. A guest can report; the reporter is then
the session's `(uid, serial)` and the reporter cannot be told the
outcome later, which the reply says.

### 4.2 Private messages

A PM is private, so a moderator sees it only because its recipient chose
to show it. Reporting a message copies its stored body into the report
at that moment; the inbox row is untouched. Only the recipient may
report it — the store already scopes `inbox` reads by mailbox, and the
same check applies. A message with no inbox row (a server without one,
or a PM to a guest) can still be reported by pasting; the client sends
the text as `evidence` and the server marks the report `unverified`,
which the moderator sees.

### 4.3 Images

An image report is the one where timing matters: the handle expires in
24 hours and could be evicted sooner, and a moderator who cannot see
what was reported cannot judge it. So a report **pins** the handle —
exempt from expiry and eviction while any report on it is open, capped
at `[moderation] pin_days` (default 7) as a backstop — and adds every
moderator's mailbox to its authorisation set. This is a widening of the
set, which inline-media.md §5 promises not to do. It is the one
exception, and it is defensible: the operator can read their own
process memory, moderators are the operator's trust boundary, and the
alternative is moderating an image by its caption.

### 4.4 Lifecycle

`open` → one of `removed` (the moderator redacted / revoked / purged),
`dismissed`, or `duplicate` (of another report, which is closed with
it). Each close records the moderator and an optional note. Closing a
report unpins its handle. A report against a target that is already
gone — a redacted line, a revoked handle — is accepted and closed as
`removed` at once with no moderator involved, so the reporter is told
rather than ignored.

Rate limit: 10 reports per hour per account, and a second report of the
same target by the same reporter is the first one (answered with its
id). Reports are retained `[moderation] report_days` (default 90) after
closing.

### 4.5 Who hears

At filing, `Event::Report { id, kind, summary }` goes to every session
whose account has `moderate`. On the ng wire that is a `report` event;
on the legacy wire it is a **private message from the system account's
uid** (system-account.md §2), not the reader's own: one line,
`[report #17] alice reported an image from bob: "…reason…"`, and nothing
a period client has to understand beyond a PM window opening — one
whose reply box addresses the account that takes `/report` and the
rest of system-account.md §3. An
operator who does not want moderators' 1.5 clients popping windows
turns it off with `[moderation] notify_legacy = false`; the report is
still there when they look.

The ng login reply carries `moderation: { "open": n }` for moderators,
beside `inbox`, so a client can badge it before any event arrives.

## 5. The ng wire

Requests, all `access_denied` without `moderate` except `report`:

| `req` | params | ok | errors |
|---|---|---|---|
| `report` | exactly one of `line` (id), `media` (handle), `msg` (inbox id), `user` (`uid` \| `login` \| `fingerprint`); `reason`; `evidence?` (text, for a PM with no row) | `{ "id", "outcome": "open" \| "removed" }` | `bad_request`, `no_such_target`, `rate_limited`, `not_available` |
| `reports` | `status?` (`open` default \| `closed` \| `all`), `before?`, `limit?` (1–100) | `{ "reports": [ … ], "has_more" }` | |
| `report_close` | `id`, `outcome` (`dismissed` \| `duplicate`), `note?`, `of?` (id, for duplicate) | `{}` | `no_such_report` |
| `redact` | `id` (line), `reason` | `{}` | `no_such_line`, `protected` |
| `revoke` | `media` (handle), `reason`, `block?` (default true) | `{}` | `no_such_media`, `protected` |
| `purge` | `login` \| `fingerprint` \| `uid`, `since?` (seconds, default 3600), `reason` | `{ "lines": n, "media": n }` | `no_such_user`, `protected` |
| `kick` | `uid`, `ban?` (seconds), `purge?` (seconds), `reason?` | `{}` | `no_such_user`, `protected` |
| `moderation_log` | `before?`, `limit?` | `{ "entries": [ … ], "has_more" }` | |

`kick` is new to the ng wire — it has only ever *received* `kicked` —
and needs the kick bit, not `moderate`; `purge` inside it needs both.
A `report` object:

```jsonc
{ "id": 17, "at": 1729137541, "status": "open",
  "by": { "login": "alice" },                // absent for a guest reporter
  "target": { "kind": "media", "media": "…", "from": { "login": "bob" } },
  "reason": "…", "evidence": "…",            // evidence for msg reports
  "closed": { "at": …, "by": "carol", "outcome": "removed", "note": "…" } }
```

Events:

| `ev` | data | to |
|---|---|---|
| `chat_redacted` | `{ "id" }` | everyone reading public chat; a client blanks the line in place |
| `media_revoked` | `{ "id" }` | everyone who could fetch it; a client drops the image and keeps the placeholder |
| `report` | the report object | moderators |
| `report_closed` | `{ "id", "outcome" }` | the reporter, if they have a mailbox and a session; and moderators |

`history` returns a redacted line as the tombstone chat-history.md §7.2
describes: `deleted: true`, empty `text`, no `from.nick`. A redacted
line with media returns `media` without `id` and with
`"removed": true`.

## 6. The legacy wire

- **Redaction cannot reach a rendered line.** A 106 was sent and there
  is no transaction to unsend it; the line stays on screen until the
  window scrolls. History (700) shows the tombstone, which GtkHx already
  renders as "[message removed]". This is the wire's limit, not the
  server's.
- **Revocation reaches the next download only.** A client that already
  has the bytes has them.
- **Reports arrive as private messages from the system account** (§4.5)
  and the moderator acts from an ng client or the CLI. A `/report`
  *chat* command was considered and rejected, and the objection stands:
  public chat is never parsed, and a period client typing `/report`
  expects it to be chat. `/report <who> <reason…>` exists as a command
  to the system account instead, system-account.md §3, which a 1.2
  client can use because it is a private message.
- **Kick and ban** are unchanged, and `[moderation] kick_purges =
  seconds` makes a legacy kick purge the target's recent output as the
  ng `kick { purge }` does — off by default, because a kick over the
  legacy wire has meant one thing for twenty-five years. Two things
  reach the ban list from the identity work without a new transaction:
  its entry forms gain `*@host`, which bans a registrar
  (identity-registrar.md §7.3), and a ban of a vouched identity from
  this wire writes the same voucher suspension as one from the ng wire
  (§3.3, identity-vouch.md §6).

## 7. Storage, CLI, configuration

Schema version 2 (the same bump as history and media) adds:

```sql
CREATE TABLE moderation (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         INTEGER NOT NULL,        -- redact | revoke | purge | close | vouched_banned
  actor        TEXT    NOT NULL,        -- login, or 'cli'
  actor_fp     TEXT,
  target_line  INTEGER,
  target_media BLOB,
  target_login TEXT,
  target_fp    TEXT,
  vouched_by   TEXT,                    -- voucher's login, when the target was admitted on a vouch
  reason       TEXT    NOT NULL,
  evidence     TEXT,                    -- scrubbed after evidence_days
  media_hash   BLOB,
  at           INTEGER NOT NULL
);
CREATE TABLE report (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         INTEGER NOT NULL,        -- line | media | msg | user
  reporter     TEXT, reporter_fp TEXT,  -- NULL for a guest
  target_line  INTEGER, target_media BLOB, target_msg INTEGER,
  target_login TEXT, target_fp TEXT,
  vouched_by   TEXT,                    -- as on moderation
  reason       TEXT    NOT NULL,
  evidence     TEXT,
  verified     INTEGER NOT NULL DEFAULT 1,
  at           INTEGER NOT NULL,
  closed_at    INTEGER, closed_by TEXT, outcome INTEGER, note TEXT, duplicate_of INTEGER
);
CREATE INDEX report_open ON report (id) WHERE closed_at IS NULL;
CREATE TABLE media_block ( hash BLOB PRIMARY KEY, at INTEGER NOT NULL, by TEXT NOT NULL );
```

`chat_line` gains `deleted_by TEXT`; the audit row is the record, the
column is the fast answer.

`vouched_banned` is the row identity-vouch.md §6 writes from every ban
path (§3.3): `target_*` is the banned identity, `vouched_by` the
voucher, one row per voucher with an account here, and the moderation
UI shows it beside the voucher's name for as long as the suspension
lasts. `vouched_by` on both tables is what puts the voucher's name in
front of the moderator; the ng `report` object and `moderation_log`
entries carry it when set.

CLI, beside `inbox purge` and in its shape:

```
hxd history redact <id> --reason "…"
hxd media revoke <handle-or-prefix> --reason "…" [--no-block]
hxd purge <login> [--fingerprint FP] [--since 1h] --reason "…" [--dry-run]
hxd reports [--all] | hxd reports close <id> --outcome dismissed|duplicate [--note "…"]
hxd moderation log [--limit N]
```

The CLI acts as `cli` in the audit trail and runs against the store
directly, so it works while the server is down; a running server sees
the change on its next read (the memory media store is the exception —
`media revoke` from the CLI needs the server up, and says so).

```toml
[moderation]                # present whenever [history] or [media] is
evidence_days = 30          # how long a redacted line's text stays readable to moderators
report_days = 90            # closed reports are kept this long
pin_days = 7                # a reported image outlives its handle TTL up to this
notify_legacy = true        # reports as server messages to moderators on the legacy wire
kick_purges = 0             # seconds of a kicked user's output to purge; 0 = none
```

## 8. Staging, and upstream

Moderation lands as the last stage of each of the two designs — H5 and
M6 — because it needs the rows to exist, and it is one branch, not two:
the audit table, the acts, the reports, the ng requests and events, the
CLI. E2E in `crates/hxd/tests/moderation.rs`: a redacted line is a
tombstone through 700 and `history` and a `chat_redacted` event to an
ng client that had rendered it; a revoked image 404s mid-download and
its re-upload is refused; a purge with a kick empties the last hour of
a sender across both stores; a report from an ng client reaches a
legacy moderator as a server message and an ng moderator as an event;
a PM report carries the body and only the recipient may file it; a
report on a handle keeps it past its TTL and lets a moderator fetch it.

Upstream, in the same conversation as chat-history.md §11 and
inline-media.md §14:

- Ask for `703` to be defined as **redact** — id in, tombstone out,
  with a `TRAN_CHAT_MSG`-side notification so a capable client can
  blank a rendered line. This document's semantics are a proposal for
  it.
- Ask for a **report** transaction in the `705`–`709` range, with the
  four target kinds of §4.1.
- Ask the media document to say what a server may do with a handle for
  moderation, including the pinning-and-moderator-access exception of
  §4.3, so that the "MUST NOT widen" rule has the carve-out written
  down rather than assumed.
