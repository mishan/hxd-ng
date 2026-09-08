# Private messages, and an inbox for the offline

Phase 7 item 2 promises "a durable per-user inbox: DMs and mentions that
arrive while detached are stored and delivered on reconnect, with read
state," and `docs/push-notifications.md` §6 states the consequence
plainly: **a push whose message evaporated is a notification about
nothing.** The inbox is the prerequisite; this document designs it, and
with it the rest of the private-message story on both wires.

**Decision (2026-09): SQLite, addressed by identity, stored always.** The
inbox is a `MessageStore` trait in `hxd-core` with an in-memory
implementation for tests and a SQLite one in `hxd-store-sqlite`. A
private message to an account that has an inbox is persisted before the
sender is acked, whether or not the recipient is looking. Push is off
unless configured, and so is the inbox: a server that sets no database
keeps exactly today's behavior.

**This design is deliberately the storage layer under two wire
surfaces**, not a messenger of its own. fogWraith's
[Capabilities-Messaging](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Messaging.md)
specifies a full IM subsystem for the legacy wire — roster, friend
requests, presence, typing, receipts — whose offline queue is the same
problem this solves. §12 reconciles the two, and several decisions below
are made the way they are because of it.

---

## 1. Where we are

`Core::msg(from, to: Uid, text)` required the recipient to be a **visible
session on the roster**. That was the whole delivery model, and it had
three consequences worth naming before changing any of them.

- A detached session is on the roster, so a PM to one is accepted and
  buffers in its outbox. This is real and it works — `docs/hotline-ng.md`
  §1 calls it "the closest thing the grace window offers to offline
  delivery." But the buffer is capped at `OUTBOX_BUFFER_CAP`, it dies
  when the grace window lapses, and it dies with the process.
- An account with no session cannot be addressed at all. There is no uid
  to name, and uid is the only address either wire had.
- A PM to an *active* session goes out on the socket and is gone. If that
  socket dies in the same instant, the ng client's resume finds
  `last_seq + 1 != next_seq` and answers `resync_required` — the client
  learns it missed something and can never learn what.

The third is the one that decides §3.

## 2. Who can receive one

**An account has an inbox iff it has a password or a linked identity**,
overridable per account with `[extra] inbox = true | false`.

The disqualifying thing is not the absence of a password, it is the
absence of a person. A bare `guest` login is a door: everyone who walks
through it shares one name, so queuing mail there means handing it to
whoever logs in next. A linked identity is proof of exactly one person,
the same way a password is — and the identity work creates password-less
accounts *on purpose*, both those made by `new_accounts = create` and
linked accounts running with `identity_login`. Those are precisely the
accounts §4's fingerprint keying exists for; an eligibility rule that
excluded them would have keyed a mailbox nobody could own.

`can_detach` derives the same way and for the same argument, so the two
should be read and changed together (`hxd-auth-file`, `into_account`).

This is the second `[extra]` key of its kind, which is the point of that
section (`docs/hotline-ng.md` §4/D5): server-local policy that never
crosses the wire, deliberately not a bit in the shared access bitmap.

## 3. Store always, not only on a miss

The cheap design stores a message only when it cannot be delivered — the
recipient is detached or absent. It is a smaller change, it writes to
disk far less, and it leaves §1's third hole exactly where it is: a PM
handed to a dying socket is unrecoverable, and the ng resync path that
exists to recover from precisely that has nothing to recover from.

The alternative is to **persist every private message addressed to an
account with an inbox**, and treat live delivery as a state change on a
stored row (`delivered_at`) rather than as an alternative to storing it.
That is what buys us:

- A dropped socket stops losing messages. Resync means "ask the inbox,"
  and the answer is complete.
- `inbox` becomes a real recent-DM list, which is what a mobile client
  wants when it opens: the conversation, not just the unread tail.
- Read state has somewhere to live for messages the user *did* receive,
  which is what makes badge counts correct rather than approximate.
- There is exactly one delivery path to reason about and one place a
  message can be, instead of two that must agree.

The cost is one small `INSERT` on the private-message path, ahead of the
sender's ack. On the servers this project is for that is a rounding error
against everything else a PM does. If it ever stops being one, the trait
is the seam, and the answer is a different implementation behind it
rather than a different rule above it.

**What the inbox is still not.** It holds private messages, not chat. A
public or private-chat line remains ephemeral; scrollback is the separate
chat-history extension (ROADMAP Phase 6.1) and wants a different shape.
And "delivered" means the server handed the event to a live connection —
not that a client rendered it. Capabilities-Messaging's `IM Acknowledge
(812)` is the stronger version of that field, and adopting it is a change
to when `delivered_at` is stamped rather than to the schema (§12).

## 4. The mailbox key

**A mailbox belongs to an identity, and falls back to a login.**

The obvious key is the account login, on the reasoning that a login is
stable where a uid is not. It isn't. Accounts are `<login>.toml`; a
rename frees the old name, and someone else can take it. Mail queued for
`alice`, `alice` renamed to `alicia`, `alice` registered by a stranger —
and the mail is delivered to the stranger. That is the same failure as a
recycled uid, on a slower clock, with a durable blast radius.

The messaging-identity amendment already answers this for roster rows:
the identity fingerprint is the durable row key, the Login is the wire
addressing key, and an identity-linked account that renames is *renamed
in place* rather than removed and re-added. `Mailbox` is that rule for
the mailbox:

```rust
pub struct Mailbox {
    pub login: String,                    // what the wire addresses
    pub fingerprint: Option<[u8; 32]>,    // what the mailbox belongs to
}
```

The fingerprint is the raw bytes, never a rendering of them, and only
becomes text at the storage boundary where one function decides the
spelling. A `String` here would be a key that compares by *spelling* —
an operator's hand-typed capital, or a Crockford form meeting a hex one,
and mail stranded in a mailbox nobody can open.

Matching is strict, and the strictness is the point:

- A mailbox **with** a fingerprint matches rows with that fingerprint,
  whatever login sits beside them.
- A mailbox **without** one matches rows with no fingerprint *and* the
  same login.
- Neither ever matches the other kind.

A looser rule — "fingerprint, or the login as a fallback" — would let an
identity-linked account pick up mail addressed to whoever held that login
before it, which is the failure the type exists to prevent. The strict
rule costs one thing: mail queued for an account *before* it linked an
identity would be stranded. `MessageStore::claim(login, fingerprint)`
pays it, stamping that account's existing mail — to it, from it, and its
blocks — with the new fingerprint in one shot.

**The fingerprint is the raw 32 bytes, never a rendering of them.** It
arrives that way — the identity link holds `[u8; 32]` — and becomes text
only at the storage boundary, where one function picks the spelling. A
`String` key would compare by spelling, and the spellings differ: a
registrar's Crockford form, an operator's hand-typed capital, a hex
column. The conformance suite would pass and production would strand mail
in a mailbox nobody could open. Bytes cannot have that bug.

**Four obligations fall out of this, and every one is owed by code
elsewhere.** `Core` spells each of them so the identity work calls the
domain rather than the store, and so the calls cannot skip the §6.2
locking discipline.

- **Linking an identity must call `claim`** (`Core::inbox_claim`). Without
  it, an account's mail is stranded the moment it gains an identity.
  There are four link sites in the identity work — link-at-auth,
  `/identity/link`, the tunnel's self-link, and account creation — and
  the last has nothing to claim but calls anyway, so that "linking
  claims" has no exceptions to remember. **Wired.** Three of them go
  through `IdentityState::link_exclusive`, which is one place to forget
  it rather than three; the fourth is the tunnel's, in the legacy
  frontend's `reconcile_login`.
- **Rotating a key must call `rotate`** (`Core::inbox_rotate`), which
  re-stamps mail in both directions and both sides of every block.
  Without it a rotated identity loses its mailbox, and — the worse half —
  its blocks quietly stop applying, which looks exactly like blocks that
  were never made. **Not wired, because there is no rotation path yet:**
  §8.5 of the identity spec describes it and the registrar spec owns it.
  `Core::inbox_rotate` exists so that landing rotation is a call and not
  a design question.
- **Deleting an account must call `purge`** (`Core::inbox_purge`). A
  freed login can be registered by someone else, and a later `claim`
  would otherwise hand them the previous holder's mail. There is no
  account-deletion path in the server yet — deleting an account is
  `rm accounts/alice.toml` — so this one has a command of its own until
  there is: `hxd inbox purge <login> [--fingerprint HEX]`, which reads
  the account file for the mailbox key while it is still there and takes
  the fingerprint by hand when it is not.
- **Unlinking owes nothing**, and that is a decision rather than an
  oversight. Mail is addressed to a person; under the strict rule the
  fingerprint *is* the person, so an account that gives up its link gives
  up the mailbox that link addressed, and that mail travels with the
  identity to wherever it links next. The alternative — an `unclaim` that
  is `claim`'s inverse, so mail follows the account — would hand one
  person's correspondence to whoever links to that account afterwards.

On a server with no identity subsystem every mailbox is login-keyed and
all of this reduces to exactly the naive design — which is the shape a
seam should have.

## 5. The store

```rust
pub trait MessageStore: Send + Sync + 'static {
    // `push` decides three things at once, and it has to: dedup by guid
    // and the mailbox cap were both check-then-insert when the caller
    // asked them, and both race in exactly the case they exist for — a
    // client retrying a send, and a sender sending in parallel.
    fn push(&self, m: &NewMessage, cap: usize) -> Result<Pushed, StoreError>;
    fn find_guid(&self, to: &Mailbox, from: Option<&Mailbox>, guid: &MessageGuid)
        -> Result<Option<StoredMessage>, StoreError>;
    fn pending(&self, to: &Mailbox, limit: usize) -> Result<Vec<StoredMessage>, StoreError>;
    fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError>;
    fn is_pending(&self, to: &Mailbox, id: MessageId) -> Result<bool, StoreError>;
    // `Delivery::Read` is the legacy wire: see §11.
    fn mark_delivered(&self, ids: &[MessageId], at: SystemTime, what: Delivery)
        -> Result<(), StoreError>;
    fn mark_read(&self, to: &Mailbox, up_to: MessageId, at: SystemTime)
        -> Result<usize, StoreError>;
    fn list(&self, to: &Mailbox, before: Option<MessageId>, limit: usize)
        -> Result<Vec<StoredMessage>, StoreError>;
    fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError>;
    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError>;
    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError>;
    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError>;
    fn prune(&self, now: SystemTime, unread: Duration, read: Duration)
        -> Result<usize, StoreError>;
    // `at` because the store never reads a clock of its own: one clock,
    // the caller's, so a test can move it.
    fn set_blocked(&self, owner: &Mailbox, other: &Mailbox, blocked: bool, at: SystemTime)
        -> Result<(), StoreError>;
    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError>;
    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError>;
}
```

Sync, like `AuthBackend`, and for the same reason: `Core` is sync all the
way down, its state sits behind a `std::sync::Mutex`, and every method on
it returns without awaiting. Making one store call async would turn the
domain async — a change with nothing to do with messaging. `AuthBackend`
already carries the note that it goes async when a database backend
lands; this trait inherits it verbatim.

**SQLite via `rusqlite`, with the `bundled` feature**, not `sqlx`. The
reasoning is not about SQLite versus Postgres — Postgres remains where
Phase 7 item 4 points, and this trait is the seam it arrives behind. It
is that `sqlx` is an async client, and driving one from a sync trait
means blocking on a runtime from inside a lock-adjacent code path, which
is the shape that deadlocks. `rusqlite` is sync, the API is small enough
to read in an afternoon, and `bundled` compiles SQLite in so a build
needs no `libsqlite3-dev` and cannot skew against the system's version.

```sql
CREATE TABLE message (
  id           INTEGER PRIMARY KEY,   -- rowid: the order and the cursor
  kind         INTEGER NOT NULL,      -- 0 message, 1 read receipt
  recipient    TEXT    NOT NULL,      -- canonical account login
  recipient_fp TEXT,                  -- identity fingerprint, when linked
  sender       TEXT,                  -- NULL if the sender had nothing durable
  sender_fp    TEXT,
  sender_nick  TEXT    NOT NULL,      -- as displayed when it was sent
  body         TEXT    NOT NULL,
  guid         TEXT,                  -- the client's own id, when it gave one
  sent_at      INTEGER NOT NULL,      -- unix seconds
  delivered_at INTEGER,               -- handed to a live connection
  read_at      INTEGER                -- the client said so
);
-- Retry safety: one message per (sender, recipient, guid), keyed on the
-- *mailbox* rather than on its two columns — see below.
CREATE UNIQUE INDEX message_guid ON message (
  guid,
  IFNULL(recipient_fp, recipient),
  IFNULL(sender_fp, IFNULL(sender, ''))
) WHERE guid IS NOT NULL;

CREATE TABLE block (
  id         INTEGER PRIMARY KEY,
  owner      TEXT NOT NULL, owner_fp TEXT,
  other      TEXT NOT NULL, other_fp TEXT,
  created_at INTEGER NOT NULL         -- when, so a UI can say "blocked since"
  -- One row per pair. Nothing enforces it in SQL, because the key is
  -- again the mailbox rather than the columns; `claim` and `rotate`
  -- de-duplicate after a merge, and the conformance suite holds both
  -- stores to it.
);
```

**`guid` is the client's own id, and it is parsed rather than stored as
it arrives.** fogWraith has clients generate one per message and retry
idempotently, which our rowid cannot support because a retry arrives
before the client learned the id. A retry of a guid we already hold is
not stored twice and not refused, which is what makes a client safe to
retry after a socket died between the send and the reply. It is answered
*as of now* rather than as of the first send: the recipient may have
arrived in between, in which case the retry is what hands the message
over — leaving it pending until their next login while they are sitting
there would be a message waiting for no reason. So one guid can be
answered `queued: true` and then `queued: false`, and the second answer is
the true one. What the retry does not do is look fresh: the row has been in the
inbox since the original send, so it carries `queued` on the wire when it
is finally handed over. Uniqueness is scoped to the
sender–recipient pair, so two people cannot collide on each other's guids
and one person may reuse a guid toward two recipients. The `IFNULL`s in
that index are load-bearing twice over. A bare column list would let NULL
compare unequal to itself, and every unidentified sender or recipient —
most of them — would escape the constraint entirely. And the key has to
be *the mailbox*, `IFNULL(<col>_fp, <col>)`, not the pair of columns:
with both columns in the index, `(X, alice)` and `(NULL, alice)` are
distinct rows right up until `claim` stamps the second with `X`, hits the
constraint, and rolls back a transaction that was moving all of alice's
mail. Which is why `claim` and `rotate` collapse duplicate guids —
**on both halves of the key**, because a row can be moved by its sender
as readily as by its recipient — before they move anything. Delivery and
read state from either duplicate move to the survivor, so a merge cannot
make an already-seen message pending or unread again. Only a UUID's two spellings
are accepted, canonicalised to one; an index over arbitrary client text
is a place to put anything.

**`kind` is where read receipts live, rather than a second table.** A
receipt is addressed to the *original sender* — `recipient` is who sent
the message, `sender` is who read it, `body` is the acked message's guid
— so `pending`, `claim`, `rotate`, `purge` and retention all work on it
unchanged, and only a wire that can express a receipt branches on the
column. A receipt for a message that has since been pruned still
delivers: "they read it" is true even when the text is gone. It is
stamped read on arrival, which keeps it out of unread counts and ages it
on the read clock without prune needing to know what kinds exist, and
neither it nor its siblings count toward the queue cap — a chatty reader
must not be able to fill the mailbox it is acking into.

**Nothing writes a receipt yet**, and every read path this store exposes
filters to messages, so a kind the wire cannot carry can never occupy a
flush slot or be rendered as mail. The column exists now because adding
it later is a migration; the wire that fills it is `IM Acknowledge (812)`.

**And the shape that survives per-device envelopes.** When amendment C's
envelopes land, a message is N ciphertexts rather than one, `pending`
becomes "pending for this mailbox *and this device key*", and the flush
becomes per device. That is an `envelope` table keyed by
`(message_id, device_key)` with its own `delivered_at`, leaving
`message.delivered_at` to mean "at least one device". It hangs off
`message.id` and never off `guid`, so deduplication and encryption never
meet.

`Mailbox`'s matching rule appears in SQL as **one shape per kind of
mailbox** — `<col>_fp = ?` for an identified one, `<col>_fp IS NULL AND
<col> = ?` for a bare login — built in one function so the two
implementations cannot express it differently by accident. The single
null-safe clause it replaced (`<col>_fp IS ?fp AND (?fp IS NOT NULL OR
<col> = ?login)`) was correct and unindexable: SQLite could use only the
leading column, so on a server with no identities it read the whole
table. Two shapes, two partial indexes, and each query touches only its
own rows. What holds them to the same answer is
`inbox::conformance`: one suite, run by both, with the rename and claim
scenarios in it, because a disagreement there is mail delivered to the
wrong person.

`PRAGMA user_version` carries the schema version. WAL journaling,
`synchronous = NORMAL` by default (`[inbox] sync = "full"` for operators
who want the fsync): NORMAL survives a process crash, which is the
failure this subsystem is for, and does not survive a power cut, which
the documentation says at the knob rather than implying away.

Note the clock. The roster measures with `Instant` because it only ever
asks "how long since"; a stored message needs a wall time it can show a
human next week.

## 6. The domain

`Core` gains an `Option<Arc<dyn MessageStore>>` — `None` is today's
server, exactly. Two entry points:

| | |
|---|---|
| `msg(from: Uid, to: Uid, text)` | What both wires call. Resolves `to`'s mailbox and status, then §6.1. |
| `msg_login(from: Uid, to: &str, text)` | Address an account. Delivers live to the session that account holds if any, stores otherwise. |

### 6.1 The rule

| Recipient | What happens |
|---|---|
| Session `Active` or `Idle`, account has an inbox | Store, then deliver live and mark delivered. |
| Session `Active` or `Idle`, no inbox (guest) | Deliver live. Nothing stored, nothing to read later. |
| Session `Detached`, account has an inbox | Store. **Not** put in the outbox — the durable copy is the copy, and two would deliver twice. Flushed on resume. |
| Session `Detached`, no inbox | Buffer in the outbox, as before. |
| No session, account has an inbox | Store. Notify (§10). |
| Sender blocked by recipient | `ChatError::Blocked`, nothing stored (§9). |
| Mailbox at its queue cap | `ChatError::MailboxFull`, nothing stored (§9). |
| No session, no such account *or* no inbox | `ChatError::NoSuchUser` — one code for all of them, deliberately (§11). |

`Idle` sitting with `Active` is not a slip: idle means a connection is
attached and got the event. It is a *notification* candidate (§10), not a
delivery decision.

### 6.2 The lock

`Core::msg` must not hold the roster mutex across a disk write. The
sequence is: take the lock, resolve the recipient's mailbox and status
and the sender's, drop it, write, take it again to deliver. Which opens a
race — the recipient can resume between the decision and the write, so a
message can land in the inbox for a session that is live again by the
time it lands.

That race is benign in one direction and not the other. If the recipient
went from active to detached we merely stored something we could have
sent; the flush catches it. If it went from detached to active, the
message would sit unread until the *next* login, which is a real bug from
the user's side — the message arrived while they were looking at the
screen. So the store path ends by re-taking the lock and re-checking: if
the recipient is now attached, flush its pending messages immediately.
Same shape as the registry's copy-out/release/consult/reacquire
discipline in AGENTS.md.

### 6.3 Flush

`Core::flush_inbox(uid)` pushes a session's pending messages through its
outbox as `Event::Msg`, marks them delivered, and is idempotent. It runs
at login completion (after `announce`, so the roster is coherent first),
after a successful resume, after `sync` when resume required a resync, and
at the tail of a store that lost the §6.2 race. A `resync_required` reply
flushes nothing before that `sync`.

The flush is capped at `[inbox] deliver_at_flush` (default 25). The
remainder stays pending: an ng client pulls it with `inbox`, and every
client gets it on the next login. The cap exists for the legacy wire,
where each private message opens a window — two hundred of them would
take a period client apart. When the cap bites, one server notice says
how many are waiting, in place of a digest format nobody asked for.

Two consequences worth stating rather than discovering. A message that
arrives while a backlog is past the cap is stored but not in this
batch, so its sender is told `queued: true` — truthful: the row is
pending, and the recipient will see it after what is ahead of it. And
the notice fires on every send that finds a backlog, not once per
flush, which on the legacy wire is a server-message window each time.
Both are the cap doing its job on a mailbox that is genuinely behind;
neither is worth a second mechanism until someone is actually annoyed
by it.

### 6.4 The sender's uid

`Event::Msg` carries the sender's uid so a client can reply. A message
delivered from the inbox was sent by a session that is long gone, and
that uid may now belong to someone else.

The rule: a queued message's `from` uid is resolved **at delivery time,
by mailbox** — by fingerprint where there is one, by login-with-no-identity
where there is not, which is §4's rule again one layer up. If the sender's
mailbox currently holds a session, that session's uid is correct by
construction. If it does not, the uid is `0` and the nick and login carry
the identity; ng clients have `from.login`.

The legacy edge cannot pass that 0 through. A 1.x client decides
"private message" from the uid — GtkHx's `is_pm = !is_broadcast && uid >
0` — so a Send Message (104) with UID 0 goes through the *broadcast*
path and lands in the chat pane with the `[queued …]` stamp inline: no
PM window, nothing to reply to. So the legacy frontend substitutes the
recipient's own uid, with the sender's name in NAME, which is the shape
mhxd uses for its own server messages and which renders through the PM
path. A reply then goes to yourself rather than to nobody — the better
of the two answers a wire with no "from an absent user" can give.

What that costs, said plainly, because a client author will meet it:
every queued message from an absent sender carries the *same* uid — the
reader's own — so a client that keys its message windows on uid (GtkHx's
`msg_output_render` does, and titles the window from the first message's
name) collects mail from several absent senders into one window, titled
after whoever came first, with the reader's own entry in the header pane
and the reply box addressed to themselves. **The name on each line is
what tells the senders apart**, and it is on every line. A sender whose
nick equals the reader's own renders as that reader's own words, since
GtkHx classifies `is_self` by name. Whether a 1.5 client does the same
thing with uid 0 has not been checked against a real one.

Concretely `Event::Msg` carries `from`, `from_nick`, `from_login`, the
text, the stored `id`, `sent_at`, and `queued` — one boolean rather than
a timestamp comparison against a threshold, because a threshold is a bug
waiting for a slow network.

## 7. The two wires

**ng.** `msg` names its recipient one of two ways, and refuses both or
neither rather than guessing — a client that sent both meant something.

| `req` | params | ok | notes |
|---|---|---|---|
| `msg` | `to` (uid) **or** `to_login`, `text`, `guid?` | `{ "queued": bool }` | exactly one address; a repeated `guid` is the same message (§5) |
| `inbox` | `before?` (id), `limit?` (default 50, max 200) | `{ messages, unread, total }` | newest first, paginating backwards |
| `msg_read` | `up_to` (id) | `{ unread, total }` | marks everything of the caller's up to that id |
| `block` / `unblock` | `uid` **or** `login` (`unblock` may instead use `fingerprint`) | `{}` | §9; the uid form names a sender with no account login |
| `blocks` | — | `{ blocked: [{ login, fingerprint? }] }` | the fingerprint is what `unblock` takes back |

The `msg` event gains `at`, `queued`, `id`, and `from.login`. The login
reply gains `inbox: { unread, total }` and `"inbox"` in `caps`.

A block on an identity guest is the reason `blocks` lists objects rather
than logins: that block is held against a fingerprint and its login is
`guest`, so a list of logins named something `unblock` could not resolve
once the guest left. Blocking still needs someone you can see — a login
or a roster row; a fingerprint only lifts a block that exists.

Two edge rules the ng side enforces because the store cannot: a message
with no text is refused (`bad_request`) rather than taking a queue slot
and rendering as a bare stamp, and a nick is bounded to the legacy
wire's field — 31 *characters*, which is what 31 Mac Roman bytes are
worth (`hotline-ng.md` §8) — since it is copied into every stored row's
`sender_nick`. A nick arriving from the legacy side needs no bound of its
own: it was 31 Mac Roman bytes to begin with, so it is at most 31
characters and at most a few hundred UTF-8 bytes by construction.

Two things the reply deliberately does not say. `msg` answers whether the
message waited **and nothing else**: the id is the *recipient's* handle
for marking read, and handing a monotonic id to a sender would tell them
how much mail this server carries. And `inbox` lists no uids — a stored
message's sender may be long gone, and a uid from then may belong to
someone else now, so a client that wants to reply names the login.

**Legacy.** The 1.x wire can receive but not address. A period client's
user list is the only place it can name a person, so it sends to uids as
it always has — Phase 7 item 5's "a legacy client's PM to a detached user
is accepted, queued, and pushed," with the sender's UX unchanged. What it
gains is receiving: queued messages arrive as ordinary private messages
after login, in order, stamped:

```
[queued 2026-09-06 14:22 UTC]
are you around this weekend?
```

One line, prepended at the legacy edge (`[server] stamp_queued`, default
on), converted to CR line endings with the rest. It says UTC because the
server knows nothing about where the reader is and the wire has no way
for a client to tell it. This is presentation and belongs at the
frontend, not in the stored body — and when Capabilities-Messaging lands
it becomes the *fallback* path, for clients that negotiate no messaging
capability (§12).

**Not inventing an addressing mechanism for 1.x.** A server pseudo-user
taking `/msg <login> …` would let period clients address accounts, and it
was considered: a permanent fake roster row and a command language on a
wire that has none, to give a twenty-five-year-old client a feature its
UI has no concept of. Capabilities-Messaging's `Find User (822)` is the
right answer to that question and it is a different subsystem.

## 8. Read state

Three timestamps, each meaning one thing: `sent_at`, `delivered_at` (the
server handed it to a live connection), `read_at` (a client said so, via
`msg_read`).

A legacy session has no way to say it read something, so on that wire
**delivery is the read**: the flush sets both. That is not a shortcut, it
is the truth about what that wire can express, and the alternative — a
permanently unread inbox for every 1.x user — would make the unread count
useless for the accounts that use both wires. It belongs to the *session* rather than to
the store or to the caller: `flush_inbox(uid)` reads the flag off the
session it is flushing to, because the same mailbox is read on both
wires and the answer differs per connection — a phone and a 1.5 client
holding one account at once each get the rule their own wire can honour.

And one more thing that wire cannot do, said here rather than discovered:
**`delivered_at` on the legacy wire means "handed to the writer task"**,
not "the bytes reached the client". A 1.5 client whose socket dies during
the login flush loses up to `deliver_at_flush` messages for good, because
that wire has no resume to recover them with. "Delivered twice is the
right way round to be wrong" holds on the ng wire, which can replay; on
the legacy wire the rounding goes the other way and there is nowhere else
to put it. Per-message client acks — fogWraith's `IM Acknowledge (812)`
— are what would close it.

`msg_read` takes `up_to` rather than a list because that is how a reader
moves through a conversation, and because it makes the operation
idempotent and one statement. It is a *cursor in the caller's own
mailbox*: ids are server-wide, so an id the caller did not receive is
still a number, and everything of theirs below it is marked. What it
cannot do is reach another mailbox — that is what the store scopes, and
it is the part that would be a bug.

That asymmetry has a consequence worth writing down before someone files
it as a bug: **the legacy wire never generates a receipt.** When receipts
reach the wire, an ng sender will get a `Read` back from an ng reader and
nothing at all from a 1.x one — not because the message went unread, but
because that wire has no way to say so.

## 9. Blocking, the queue cap, and retention

```toml
[inbox]
db = "messages.db"       # absent = no inbox; today's server exactly
max_queued = 200         # messages *waiting*, per account
deliver_at_flush = 25
retain_unread = 2592000  # seconds: 30 days, from when it was sent
retain_read = 604800     # seconds: 7 days, from when it was read
sync = "normal"          # or "full"

[server]
stamp_queued = true      # the legacy-wire stamp, §7
```

**The cap counts what is waiting, not what is unread**, and the
difference matters. With store-always, "unread" includes messages the
recipient received live and simply hasn't marked read — so an ng client
that never sends `msg_read` would fill its own mailbox and start refusing
mail from everyone. Queue depth is the right measure; what bounds the
rest is retention. Capabilities-Messaging's `MaxOfflineQueue` (default
500) counts the same thing.

A full mailbox **refuses the send** — `MailboxFull`, `QueueFull` in the
spec's vocabulary. It does not silently drop, and it does not evict the
oldest to make room: a message a sender was told was delivered and which
then quietly disappeared is the failure mode that destroys trust in a
messaging system.

**Blocking exists because account addressing needs it.** Before
`to_login`, a sender had to be on the roster to reach you — a bounded,
present set, and one an admin can kick and ban. Account addressing
removes that bound: anyone with an account can put mail in anyone's
queue, from anywhere, and a queue has a cap. Fill someone's mailbox and
every legitimate sender is refused until they clear it. That is an
availability attack the cap alone cannot answer.

So a minimum viable version of the spec's `Block User (806)`: a per-owner
list in the same store, checked before anything is written, applying to
**both** ways of addressing — a block a recipient can sidestep by
clicking a name in the user list is not a block. It is one-way, it is
idempotent, and it follows an identity through `claim` like everything
else. What it is not is a friend graph; when that arrives the block list
belongs with it, and this moves.

**A plain guest cannot be blocked**, because there is nothing durable to
block: `guest` is a login several people share, and a block held against
it would block everyone who walks through that door. What bounds a plain
guest is the roster it has to be on, where it can be kicked and banned.

**So a plain guest may not queue mail at all.** "Anyone with an account
can put mail in anyone's mailbox" is the rule above, and a guest has no
account: it can reach a session that is *there*, live, and that is all.
Letting it store would hand the availability attack this section is about
to the one sender the block cannot answer — connect as guest, send
`max_queued` messages to each account in turn, and every legitimate
sender is refused `mailbox_full` until each owner clears their mailbox by
hand. A guest addressing an account with *no session at all* gets the
same `no_such_user` every other unreachable address gets; one addressing
a session that is on the roster but detached reaches its outbox and is
answered `Delivered`, which is the pre-inbox behaviour on that path and
is bounded by the outbox rather than by `max_queued`. Nothing durable is
written either way.

**An identity guest can.** Under `new_accounts = guest` an identity user
is a guest session *with a fingerprint*, and a fingerprint is exactly
what a block holds against — so its sender fingerprint is recorded even
though it has no inbox of its own, which also makes §6.4's
delivery-time uid resolution work for it. Naming one is the reason
`block` takes a uid as well as a login: an identity guest has a roster
row to point at and no account login to name.

Pruning runs hourly in the binary, next to the existing detached sweeper.

## 10. The notify seam

This is where `docs/push-notifications.md` §9 P2 attaches. That
document's §11 names the hazard exactly: the notify decision must live in
the domain, "or the legacy path silently skips it." §6.1's table is that
decision — computed in one place that both wires call.

`Core` holds a `NotificationGateway`, defaulting to none, and calls it
after a store that did not reach an attentive session: detached, absent,
or idle. A message to your own account is not news; a recipient with no
inbox earns nothing, because a push about a message that was never stored
is a doorbell for nothing.

**Three departures from the push doc's sketch**, all recorded there. The
trait is not `#[async_trait]` — `Core` is sync, and §4 already required
that `notify` never be awaited on the message path, so the spawn moves to
the implementation's side where the runtime handle lives. And the
notification carries a `Mailbox`, not a login: a gateway keys its device
registry on the fingerprint where there is one, for the same reason the
mailbox does (§4). push-notifications.md §5 already refuses to let uids
near a device registry; a renameable login is the same hazard, slower.
And there is no `NoopGateway`: a gateway that does nothing plus an
`Option` that means the same thing is one state too many.

And when there are device keys to key on, **the registry wants
`(identity_fp, device_fp)`**: a push token is per device, the identity
work already gives every device a certificate with its own fingerprint,
and that pair gets multi-device right without inventing a concept. It
answers §15's multi-device question for push, though not for read state.

Mentions stay out, per the push doc's own open question. DMs carry this
alone.

## 11. Security and privacy

**Account enumeration.** `to_login` tells any user who can send messages
whether an account exists. The mitigation is the one the login flow
already uses: **one error code for all of them** — no such account, takes
no offline messages, and (for `block`) not a blockable mailbox — so the
answer distinguishes nothing finer than "you cannot queue for that name."
A server that minds the remaining signal leaves `[inbox] db` unset.

**Nothing crosses mailboxes.** Every store operation is scoped by the
mailbox, taken from the *session's* account and never from a
client-supplied field — the same rule push-notifications.md §7 states for
registration, and the same failure if it is broken.

**Bodies at rest are plaintext.** The database file holds every private
message on the server in the clear, and it must be treated exactly like
the accounts directory: readable by the server user only, and named in
the deployment docs. An operator can already read PMs in flight; what
changes is that they persist.

**And in flight, on the legacy wire, in the clear.** A queued message
delivered to a 1.x client without TLS crosses the network unencrypted —
true of every legacy PM, but a queued one may be days old and its sender
had no way to know which wire would carry it. Same concern that shapes
the identity work's cleartext setting.

**Blocked is a named answer**, matching the spec's reason 3 rather than
silently discarding. It tells a spammer they were blocked, which is a
real cost; the alternative tells a legitimate correspondent nothing at
all, and diverging from the spec here would mean two subsystems that
answer the same question differently. §15 keeps the question open.

## 12. Reconciling with Capabilities-Messaging

The spec and this design solve the same storage problem and are different
products above it. Classic Hotline PM is "message someone in this room",
and this gave it durability; Capabilities-Messaging is a messenger —
roster, friend requests, blocks, presence aggregation, typing, receipts —
where the offline queue is one feature among many and the friend graph
gates all of it.

**They are two callers of one store**, which is the split `hxd-core`
exists for. What that costs, concretely:

| Concern | Here | Capabilities-Messaging | Reconciliation |
|---|---|---|---|
| Address | account login, identity fingerprint where linked | Login (bare identity) | Same, and the amendment's fingerprint rule is §4 |
| Store when | always | when no live session | Ours is a superset; the spec's queue is our `pending` |
| Delivered | server handed it over | recipient's `Delivered` ack (812) | A change to *when* `delivered_at` is stamped, not to the schema |
| Read | `msg_read` | `Read` ack (812), forwarded to the sender | The sender-side half needs somewhere to live (§15) |
| Cap | `max_queued` 200 | `MaxOfflineQueue` 500 | Same measure; a default to align |
| Retention | 30d unread / 7d read | `OfflineRetentionDays` 30 | Compatible |
| Sender told | `queued: true` | `OfflineQueued` (7) | Same fact |
| Message id | server rowid | client `DATA_MESSAGE_GUID` | Needs a column (§15) |
| Gate | block list | friendship + blocks + discoverable | Ours is the subset that protects the mailbox |
| Eligibility | has a password | `AccessMessaging` (58); admin/guest barred | Agree in practice (§2) |

**The numbering is already clean.** `AccessMessaging` is bit 58 and
`docs/capabilities-video.md` allocates 59/60 above it. The superseded
`Capabilities-Identity` draft had provisionally claimed transactions
800–804, which collides with this extension's 800–826 — his allocation is
the older one — and that draft was withdrawn when identity authentication
moved to the HTTP layer, taking the collision with it. The amendment
claims no new transactions or bits, so it stays clean.

**The legacy stamp becomes the fallback.** A client that negotiates
`CAPABILITY_MESSAGING` should receive `IM Deliver (811)` with
`DATA_MESSAGE_TIMESTAMP` as a real field; the `[queued …]` text prefix is
what a 1.5 client that knows nothing about messaging gets instead. That
layering already works, and needs no change here.

**`to_login` is where the two touch, and it is deliberately narrower than
it looks.** The spec gates account addressing behind friendship,
`NotDiscoverable` and blocks. This design has only the last of those,
because only the last is buildable without a roster. When the friend
graph lands, `to_login` should become the ng spelling of `IM Send` and
inherit the rest of the checks; until then blocking is what stands
between account addressing and a mailbox anyone can fill.

## 13. Staging

Each stage is a branch with tests, in the house style.

1. **M1 — the store.** `MessageStore`, `Mailbox`, the types, the
   in-memory implementation, and `hxd-store-sqlite` with the schema, the
   version pragma, and the shared conformance suite. Wired to nothing.
2. **M2 — the domain.** `Core` holds the store; `msg` gains the §6.1
   rule; `msg_login`, `flush_inbox`, the read/list operations, the queue
   cap, the §6.2 re-check, `claim`/`purge`, `Event::Msg`'s new fields.
   Unit tested against the in-memory store, no network, no disk. **This
   is where the interesting bugs are** — the detached/absent transitions,
   the race, and the rename cases.
3. **M3 — the wires.** Legacy: flush at login, the stamp, uid-0 handling.
   ng: `to_login`, the event fields, `inbox` and `msg_read`, the login
   reply's unread count.
4. **M4 — the binary.** The `[inbox]` config block, the store's
   construction behind the `inbox` Cargo feature, the prune interval, and
   the cross-frontend e2e that is the point of all of it: a legacy client
   PMs a detached ng user, the grace window lapses, the ng user logs in
   fresh and the message is there — and an ng client addresses an account
   with no session at all, which then logs in over the *legacy* wire and
   reads it.
5. **M5 — the notify seam.** `NotificationGateway`, the call site, and
   the recording-fake tests. Push's P2.
6. **M6 — blocking.** The block list, `block`/`unblock`/`blocks`, and
   the check on both addressing paths.

## 14. Risks

| Risk | Severity | Response |
|---|---|---|
| Mail delivered to a stranger after a rename | **High** — wrong person | The mailbox is keyed by fingerprint where there is one (§4), with `claim` and `purge` as the obligations that keeps it true |
| A client that never marks read locks its own mailbox | **High** — silent, and looks like the server refusing mail | The cap counts queue depth (§9) |
| Account addressing fills a mailbox and locks out every sender | Medium | Blocking (§9); friendship when the roster arrives |
| A disk write on the private-message path | Low | One indexed INSERT, WAL, no fsync by default; the trait is the seam |
| Login flush floods a period client with PM windows | Medium | `deliver_at_flush`, and the remainder waits rather than being dropped |
| A queued message replies to a recycled uid | High | Uid resolved at delivery by mailbox, `0` when nobody is there (§6.4) |
| Two copies of a message (outbox buffer *and* inbox) | Medium | A detached session with an inbox never buffers `Msg`; one path (§6.1) |
| Message bodies persist in the clear | Medium | Documented at the knob and in deployment; file permissions |
| The two store implementations drift on the matching rule | **High** — wrong person again | One conformance suite, run by both, with the rename cases in it |
| Scope creep into a messenger | Medium | §12: this is the storage layer; the roster is a different subsystem |

## 15. Open questions

- ~~**`DATA_MESSAGE_GUID` wants a column**~~ — **taken, §5.** Storing it
  now rather than migrating later; the dedup answer is "the same reply,
  no second row".
- ~~**Where the sender's read-receipt queue lives**~~ — **taken, §5:** a
  `kind` column on `message`, not a second table. Storage only until
  there is a wire to carry one.
- **Envelopes are per-device**, and `body` is one column. §5 records the
  shape that survives, but building it waits for the amendment. It also
  raises a question the no-ratchet multi-device plan owes an answer to: a
  device added after a message is queued has no envelope for it and can
  never read it.
- **Should `Blocked` be a named answer?** It is here, matching the spec
  (§11). Silently accepting and discarding tells a spammer nothing, at
  the cost of telling a legitimate correspondent nothing either.
- **Multi-device.** `hotline-ng.md` §12 lets each login be its own roster
  row. Two sessions of one account both flush the same pending set, which
  is right for delivery and wrong for read state. Worth revisiting when a
  real client has two devices. *Half-answered:* a message that **names a
  uid** goes to that session when it is attached, and to the lowest
  attached one otherwise — naming a uid names a device, and a legacy
  user clicking a name in the user list means that one. Read state is
  still shared, which is the half that remains.
- **Retention defaults.** 30 days unread and 7 read are guesses; the spec
  says 30 for its queue. The number that matters is whichever one an
  operator notices.
- **Does the inbox belong to the account or to the identity across
  servers?** §4 makes it follow the identity *on one server*. A portable
  inbox is a much larger idea and this design deliberately assumes the
  server-local account.
