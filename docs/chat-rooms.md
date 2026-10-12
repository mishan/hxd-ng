# Chat rooms: curated, persistent, logged

Status: R1 to R3 are built (§13): rooms in the domain, the rooms file
and `hxd room`, the ng wire of §7, and period clients' rooms of §6 but
for `700` (§6.7, R4). R3's exit, real 1.2, 1.5 and 1.9 clients against
a real server, has not been run. The ng wire of §7 is the spec part;
the rest binds nobody but this server.

Public chat today is one room everybody shares, and a private chat is a
room that exists while someone is in it and leaves no record.
This document adds a third kind: **named rooms the operator curates**,
like a Discord server's channels. They persist, they are logged and
paged like public chat where the server keeps history, and anyone
allowed in can find them. Public chat becomes the first of them, the
**lobby**.

fogWraith's
[Capabilities-Chat-History.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Chat-History.md)
(read at `6276726`, 2026-10-09) already set aside the space. It calls
them *channels*: "a persistent, named conversation space - like a
Discord channel. Channel 0 is always the public chat. Channels 1+ are
reserved for future named channels." It reserves transactions 701
(listing and metadata) and 702 (management) and fields
`0x0F09`–`0x0F1F`, and says live chat "will need to include
`DATA_CHANNEL_ID`" once named channels exist. Nobody has defined them. This
server builds them for the ng wire and for period clients, and §8 is
what to propose upstream for extended ones.

**Decisions (2026-10):**

- **Rooms are curated, not created by users.** The operator makes them
  with `hxd room`, and so can accounts the operator trusts with
  `[extra] manage_rooms` from an ng client. Anyone else joins, reads and
  talks. Ad-hoc conversations are what private chats are for, and they
  stay exactly as they are: ephemeral, invite-only, never logged.
- **A listed room is public, and public is logged when the lobby is.**
  On a server that keeps history, every line in a room goes into the
  chat log under the room's id as its channel, with the same id on both
  wires and the same moderation. On one that does not, a room is live
  chat, as the lobby is there. Rooms themselves are definitions in a
  file and need no database.
- **The lobby is room 0.** Today's public chat with today's log,
  subject and voice room. It is not in the rooms file and cannot be
  archived, renamed or gated.
- **One id per room, everywhere.** A room's id is its chat id on the
  classic wire, its channel in the log, its `room` on the ng wire, and
  its voice room. §2.2 says why one number can be all of those.
- **Period clients get rooms as private chats.** A `/join` sent to the
  system account invites the user into the room's chat id, and an
  unmodified 1.5 client opens a chat window for it. The lobby tells a
  classic user at login that rooms exist.
- **A room is gated by two lists.** `read` says who may see and join
  it, and `post` who may send in it. An entry is a login or, with
  [roles.md](roles.md), `@role`. An empty list leaves it to the access
  bit, as the lobby is. News categories gate with the same two lists
  (roles.md §11), so there is one shape and one resolver.

---

## 1. Where we are

Everything named here exists, and is single-room in ways this document
undoes:

- **Public chat is the roster, not an object** (`chat.rs`: cid 0 "is
  represented by the roster itself"). Its subject is
  `RosterInner::public_subject`, held in memory only. Its audience is
  `reads_public_chat`, bit 9.
- **Private chats** are `PrivateChat { creator, members, invited,
  subject, password }` in `RosterInner::chats`. Their ids come from
  `next_chat_id`, a CSPRNG and never 0, checked against the chats in
  use, because a voice room is addressed by a bare cid. A chat is
  deleted when its last member leaves.
- **The log already has a channel column** (`chat_line.channel`,
  indexed with id) that every caller sets to 0. Line ids are one
  `AUTOINCREMENT` across channels. Pruning is global, not per channel.
  `MemoryLog` and the conformance suite already keep channels apart.
- **Group commit** (`ChatCommit`) stages public lines and appends them
  with `append_all` under `log_serial`, then fans them out in order.
  `chat_commit_batch` assumes the lobby throughout: it builds channel 0,
  fans out to `reads_public_chat`, exports every line to the server
  links (`export_chat`), and captures each image's audience as the
  lobby's readers. Moderation's `tombstone_lines` sends redactions and
  purges to every `reads_public_chat` reader. The classic `700`
  handler, the ng `history` request, the compatibility replay and
  moderation's `redact_line`, `report` and purges all filter on channel
  0.
- **The classic wire already carries a chat id on every chat
  transaction.** 105 and 106 carry `CHAT_ID` when it is not 0, and
  invite (113), join (115), leave (116) and subject (119/120) are
  addressed by it. A room that is a chat id needs no new transaction.
  A classic session's run of public lines (`public_chat_frame`) gathers
  cid 0 only.
- **The ng wire has no chat id outside voice and video.** `chat`,
  `notice` and `subject` exist only for cid 0. Everything else is an
  `unsupported` placeholder event (hotline-ng-rationale.md lists the
  private-chat family as the missing piece).
- **Voice rooms are chat ids.** The frontends check bit 55 for every
  cid. `Core::voice_join` then requires, for a nonzero cid, that the
  chat exists and the session is a member, answering `NoSuchChat` and
  `NotAMember` differently (voice.md §2).
- **hx-ng** has a fixed `#Lobby` conversation first in its rail, with
  a single history cursor, `lastHistoryId`, kept in its resume record.
  Its voice already sends `cid: 0` for the lobby.

## 2. The room

### 2.1 What a room is

| Field | Meaning |
|---|---|
| `id` | u32, nonzero, permanent, assigned by the running server. §2.2 |
| `name` | 1–32 characters: lowercase ASCII letters, digits, `-` and `_`. Unique. Clients draw it after a `#`, which is never part of it. Easy to type into a period client's message box, and the same in Mac Roman and UTF-8 |
| `topic` | Up to 255 characters, the private-chat subject's cap. Kept with who set it and when |
| `position` | Sort order in a listing. Ties sort by name |
| `read` | Who may see, join and read it. §5 |
| `post` | Who may send in it. §5 |
| `max_lines`, `max_days` | This room's retention, over `[history]`'s. §3 |
| `archived_at` | Set on archive. §2.4 |

The lobby has the same shape in memory, with id 0. Its name is
`[rooms] lobby` (default `lobby`), its topic is the public subject, and
its gates are bits 9 and 10, as now. Its subject is kept in the rooms
file (§4), so it survives a restart, which it does not today.

### 2.2 One id, and why it can be

fogWraith keeps channel ids and private chat ids in **separate
namespaces**. `DATA_CHANNEL_ID` names a channel and `DATA_CHATID`
names a private chat, so no client confuses the two. This server
allocates a room's channel id **from the chat id namespace**, so the
id is also the room's chat id and its voice room. That is a choice
within the spec rather than against it: separate namespaces let the
two numbers differ, but nothing makes them. The risk is that a future
upstream channel specification allocates channel ids some other way,
and §8 raises it.

What it buys is that no wire needs a translation table. A period
client's 106 carries `CHAT_ID` = the room's id. An ng client's
`voice_join` sends `cid` = the same id. And the lobby already is 0 in
every one of those places.

Three rules keep it sound:

- **Only the running server assigns an id.** `next_chat_id` draws it
  against the private chats in use, every entry in the rooms file
  (archived and tombstones included) and, where there is a log, every
  channel that has lines. It is reserved in `RosterInner` before the
  file is written, so a private chat cannot draw it in between. `hxd
  room create`, which runs beside the server and cannot see its private
  chats, writes an entry without an id, and the server assigns one when
  it reloads the file (§4).
- **A room's id is never reused.** Archived and deleted rooms keep
  their entry. A hand-deleted tombstone is still caught by the log
  check, so a new room never inherits an old room's lines.
- **A room's id is not a secret, and does not have to be.** A private
  chat's id is unguessable because the id is all a voice join presents.
  A room is checked against its gates instead, and every transaction
  that names a room the session may not see answers exactly as for a
  chat id that does not exist (§5). An id that leaks, or that a former
  member remembers, tells nobody anything.

### 2.3 Membership

**A session joins a room and is then a member until it leaves.** It is
IRC's model and Hotline's private chats' model, not Discord's. The room
has a member list, the classic wire needs one (115's reply and
117/118), and fanning a line out to the sessions in the room is much
cheaper than to everyone who could be.

- The lobby keeps its rule: every session that can read public chat
  is in it, and nobody joins or leaves it.
- **Detach does not part.** An ng session that detaches keeps its
  rooms, and resume finds them, as it finds the session.
  `end_session` parts every room, as it parts every private chat.
- A kick or a ban ends the session and so parts it from every room.
- **What a client remembers is the client's.** An ng client rejoins
  its rooms after a fresh login, from its own state. A server-side
  "rooms this account is in" is an open question (§14).
- `[rooms] max_joined` (default 32) caps the rooms one session is in.
  A join past it is refused, never queued.

### 2.4 Lifecycle

- **Create**: `hxd room create <name>` or the ng `room_create`. Every
  session that can see the room hears `room_added` (§7.3).
- **Edit**: name, topic, position, gates and retention, by the same two
  routes. A rename keeps the id, so history and voice are untouched.
  A narrowed gate parts any member it no longer admits (§5).
- **Archive**: the room disappears from listings, its members are
  parted with a notice, and joins are refused. **Its log stays**, under
  retention, and moderators can still page it. Archived is what
  "deleted" means by default, because a moderation report or a purge
  may point at a line in it.
- **Unarchive**: `hxd room unarchive`. It comes back with its id and
  its history.
- **Delete**: `hxd room delete` only, from the CLI only. It leaves the
  entry as a tombstone (an id and `deleted = true`, no name), so the id
  is still not reused, and the server that loads the tombstone parts
  the room's members and then deletes its lines when there is a log.
  The moderation table records it, with a room target and a
  room-delete kind it gains for the purpose (§11); R1's command does
  not record it yet. An entry no server has loaded has no id and no
  lines, and is deleted by taking it out of the file.

There is no room a user can create. A user who wants a conversation
the operator did not plan for opens a private chat, which is the
ephemeral, unlogged thing people expect it to be.

## 3. The log

**When the server keeps history, every line in a room goes into the
chat log** with `channel` = the room's id. That is what makes a room's
history the same thing as the lobby's, with the same ids on both wires,
the same tombstones and the same purges. Without `[history]`, a room's
lines carry no id, as the lobby's do today, `history` answers
`not_available` for every room, and listings carry no `last_id`.

- **A commit queue per room.** Each room, the lobby included, has its
  own `ChatCommit` and its own serial, and holds it from append to
  fan-out, as the lobby's `log_serial` does now. What that serial
  protects is a client's catch-up: a client that heard line 11 live
  asks `history { after: 11 }` when it comes back, and if line 10 had
  been heard after 11, the catch-up would skip it, silently. The
  guarantee is needed only among lines one cursor is compared against,
  and a cursor is per room, because `history` is per room. So **ids
  ascend within a room in the order the room hears them**, and across
  rooms they interleave in an order nobody can observe. A client MUST
  NOT use one room's line id as another room's cursor (§7.4). One
  queue for every room would hold a line for a small room behind a
  lobby line's fan-out to everyone, and buy nothing a client can see.
  SQLite still takes one writer at a time, but the insert is the cheap
  part of a commit.
- **A classic run is gathered per room.** `public_chat_frame` gathers a
  run of consecutive lines for one room, as it gathers the lobby's now,
  and each run goes through that room's queue. A submit returns only
  once its lines are committed, so one sender's lines keep their order
  across rooms.
- **Everything the commit path assumes about the lobby becomes the
  room's.** A room's lines fan out to its members, never to
  `reads_public_chat`. **Only channel 0 is exported to server links**:
  a room line never crosses. A room line's image is authorized to the
  room's members at the moment it is relayed, which is AGENTS.md's
  image rule applied to a room rather than to the lobby, and a member
  who joins later was not shown it.
- **What else takes a serial takes the room's.** A redaction takes the
  serial of the line's room. A purge across rooms takes each room's in
  turn, never two at once, so no order of acquisition can deadlock.
  A room's redactions and purges go to every session that may read
  the room (§7.3), member or not, since one that paged its history holds
  its lines too.
- **Line ids remain global**, from one `AUTOINCREMENT`, so they never
  collide, and a redaction, a report or a purge names a line by id
  alone and finds its room from the row. A reader can see the gaps
  between one room's ids, and so roughly how much was said elsewhere,
  including in rooms it cannot read. That is accepted: it says how busy
  the server is, not who said what or where.
- **Retention is per room.** Pruning today keeps the newest
  `max_lines` lines across the whole table, so a busy lobby would evict
  a quiet room's whole history. Pruning keeps `max_lines` per channel,
  and a room may override `max_lines` and `max_days`. Age pruning stays
  one statement, since `at` is indexed. Count pruning runs per channel.
  The `max_lines` a server advertises (chat-history.md §6.1, §7.1) is
  the default, and a room's own is in its listing.
- **The newest id is kept in memory** per room, updated at commit, so a
  listing's `last_id` costs no query.

What is *not* logged, as now: private chats, broadcasts, joins and
parts, and the notices of §6.

## 4. Storage

Rooms are a short list an operator curates, so they live in a file,
`[rooms] file` (default `rooms.toml`, relative to the working directory
as every path in the config is), not a database. `hxd room` resolves it
from its own working directory, so it is run from the server's, as
`docker exec` does in the image.
A server with no store at all has rooms. The operator can read and edit
it, and comments survive every edit the server makes, because edits go
through `toml_edit` as account files' do:

```toml
# Rooms on this server. hxd room and ng managers edit this file.
# An entry without an id is given one by the server when it loads.
[lobby]
topic = "Welcome!"
topic_by = "alice"
topic_at = 1791500000

[[room]]
id = 2754100983           # written by the server; never reused
name = "lounge"
topic = "anything goes"
position = 0

[[room]]
id = 811937042
name = "staff"
read = ["@moderators", "carol"]
max_lines = 50000

[[room]]
id = 3110257001
name = "announcements"
post = ["@moderators"]

[[room]]
id = 3002288816
name = "old-news"
archived_at = 1791000000

[[room]]
id = 1559020211
deleted = true            # a tombstone: the id stays taken
```

The file is behind a `RoomStore` trait in `hxd-core`, with an in-memory
store for the domain tests and a conformance suite both run against.
The domain loads the rooms at startup and holds them in `RosterInner`
beside `chats`.

- **Writes are serialized.** A room write holds a rooms-write lock, as
  account writes hold theirs (account-admin.md §3), across writing the
  file and applying the change to the roster, so two edits cannot reach
  the roster in the other order from the file. Where one operation
  takes both, the account-write lock is taken first. The file is
  written whole to a temporary file and renamed over the old one, so a
  crash leaves one version or the other.
- **Topics are debounced.** A topic change takes effect at once in
  memory and on every wire. The file is rewritten at most every five
  seconds and at shutdown, and then with the topic alone, so a stream
  of 120s, which have no reply and cost little, cannot become a stream
  of file writes. A write that fails is logged, keeps the topic newer
  than the file's, and is tried again at the next reload or shutdown
  rather than every five seconds.
- **A reload diffs.** `hxd room` edits the file and sends SIGHUP, and
  a hand edit is followed by one, as `hxd account` is. The server
  rereads the file, assigns ids to entries without one and writes them
  back, and diffs the result against the roster: a room that appeared
  is announced, one that was archived or taken out of the file parts its
  members, and one whose gates narrowed parts whoever lost access. The
  lobby's subject is read at startup only: a reload leaves it as the
  server has it. An id that is a private chat's makes the file one that
  does not parse. The CLI and the server do not share a lock, so an
  edit made while a manager edits from an ng client can lose one of the
  two, as with accounts.
- **A file that does not parse** leaves the rooms as they were on a
  reload, and logs why. At startup it is an error: a server that came
  up without its rooms would show a restricted room's name to nobody,
  but would also have lost its gates.

## 5. Access

A room's access is decided per account, never per wire. Both gates are
lists of entries, each a login or `@role` (roles.md §10), and an empty
list leaves the decision to the access bit:

| Act | Needs |
|---|---|
| See it listed, join it, read it | bit 9 (read chat), and, if `read` is not empty, an entry naming the account or a role it holds |
| Send in it | bit 10 (send chat), may read it, and, if `post` is not empty, an entry naming the account or a role it holds |
| Set its topic | may post in it, and `[extra] set_subject` (the lobby's rule) |
| Page its history | bit 56, and may read it |
| Voice in it | bit 55, and a member |

- **A read-only room** is one whose `post` names only the people who
  announce: `post = ["@moderators"]`.
- **Room managers** are accounts with `[extra] manage_rooms`, default
  false even for an administrator, because an operator usually wants
  only one person reorganizing the rooms. A manager may see, join and
  send in every room, and create, edit and archive them. It is
  `[extra]`, not an access bit, for moderation.md §2's reason, and it
  joins account-admin.md §1's list of what an account "may do", so an
  administrator cannot hand it to someone through an account edit
  without holding it.
- **A moderator** (moderation.md §2) may see, join and page every
  room, and redact and purge in any room, restricted or archived,
  because judging a report means reading what it is about. An archived
  room is seen and paged, and joined by nobody. News gives
  moderators the same reach (roles.md §11.1), so the rule is one rule.
- **A guest** passes an empty `read` when its bits allow, and a
  non-empty one only if it names `guest`. A gate naming `@everyone` is
  refused when written: it would admit the guest while looking
  restrictive, and an empty list already means everyone.
- **A room the session may not see does not exist for it.** Every
  listing leaves it out, and every request and transaction naming it,
  on either wire, answers exactly as for a room or chat id that does not
  exist: `/join`, 113, 115, 116, 120, a 105 (dropped silently, as for an
  unknown chat), 600 and `voice_join`, `700`, and every ng `room_*`
  request. The name of a staff room is itself information. Only a
  session that may see the room is told it is `not_a_member`.
- **Access is checked when it changes, not only at join.** An edit
  to a gate, an account change, or a change to a role it holds, that
  takes away someone's access, parts their sessions at once (§6.4 for
  how a period client is told).

## 6. The classic wire, for period clients

A room appears to a 1.5 client as a private chat it has been invited
to. Private chat is in the 1.0–1.2 base set, and every 113 a client has
ever received was sent by a server, for a chat it did not create: what
is new is only that the inviter is the system account, and that the
chat is a room.

### 6.1 Finding and joining: the system account

system-account.md §1 decides that **public chat is never parsed as a
command**: a line typed into chat is chat, whatever it starts with.
So `/join` is a command in a private message to the system account,
like `/report` and `/msg`:

| Command | Does | Needs |
|---|---|---|
| `/rooms` | Lists the rooms this session may join, one per line: `#name — topic (n here)`, members first. One message, capped at a private message's length (4096 bytes), ending `… and more; /rooms <word> narrows it` when cut | — |
| `/rooms <word>` | Only rooms whose name or topic contains the word | — |
| `/join <name>` | Invites this session into the room (§6.2). `#` before the name is accepted and ignored. Answers `ok: invited to #name`, `ok: already in #name` (and sends no invite), or `error: no such room` | §5, see |
| `/part <name>` | Leaves the room, for a client whose window closed without sending 116. Answers `ok: left #name`, `error: you are not in #name`, or `error: no such room` | — |

They run as the session that sent them, from either wire. From the ng
wire, which has no invite to answer, `/join` joins at once and answers
`ok: joined #name`; an ng client should still use `room_join`. On a
server without rooms they are unknown commands, answered with the help.

### 6.2 The invite, and the window

1. `/join lounge` from a session that may see it.
2. The server sends **113 Invite to Chat** with `CHAT_ID` = the room's
   id, and `UID` and `NAME` = the system account. The 1.5 client puts
   up its usual dialog: *Server invites you to chat*.
3. The user accepts. The client sends **115 Join Chat** with that
   chat id. The server checks §5 then, whatever it remembers of an
   invite: an invite is how a period client is shown a room, never what
   admits it. The reply is the member list, every session in the room
   on either wire, and `CHAT_SUBJECT` = the room's topic.
4. After that reply, on the same writer, the server sends the joiner
   one notice in the room, never logged: `\r *** #lounge — this room is
   public and logged`, or `public` alone on a server without
   `[history]`, and `public, logged and read-only` (or `public and
   read-only`) when the session may not post. It and every other line
   of §6 come from the system account's uid, or the session's own on a
   server without one. A period
   client shows the room in a *private chat* window. The window's look
   promises privacy that the room does not have, so the line is
   load-bearing. It goes out on every join.
5. Lines in the room go out as **106** with `CHAT_ID`, formatted by
   `format_chat` like the lobby's. 117/118 track who comes and goes,
   and 119 tracks the topic.

Declining (114) is a no-op, as it is for a private chat.

**A client that declines by itself.** Hotline.md (fogWraith) and
GtkHx's protocol notes agree that a client receiving 113 from a server
whose version is below 151 sends 114 on its own when its
automatic-response or refuse-private-chat option is set. hxd-ng
reports 254 by default, which is safe. When `[server] version` is set
below 151, `/join` answers `ok: invited to #name — if no window opens,
turn off "refuse private chat" and "automatic response"`.

### 6.3 Transactions addressed to a room id

Each existing private-chat transaction, when its `CHAT_ID` names a room
the session may see (otherwise §5's last rule):

| Transaction | Does |
|---|---|
| 105 Send Chat | Sends in the room, under §5, through the room's queue and the flood count. A session that may read but not post gets, the first time, a notice in the room, `*** this room is read-only`, and its lines are dropped. 105 has no reply, and a line that vanishes with no word is a bug to the person typing it |
| 113 Invite to Chat | A member invites someone who may see the room. The invitee sees *alice invites you to chat* as for a private chat. Inviting someone who may not see it is refused with the same task error as a chat that does not exist |
| 115 Join Chat | §6.2 |
| 116 Leave Chat | Parts the room |
| 120 Set Chat Subject | Sets the topic, under §5. A password on a room is ignored: rooms have gates, not passwords |
| 112 Create Chat | Unchanged: it makes a private chat. Never a room |

A room counts toward `[rooms] max_joined`, never toward `[limits]
private_chats_per_user`, which counts the private chats a user creates.

### 6.4 Being parted

The classic wire has no message for "you are no longer in this chat".
When the server parts a classic session from a room (an archive, a
narrowed gate, a lost role), it sends a notice in the room,
`*** you were removed from #staff`, then **118** naming the session's
own uid, so the window's member list loses the user and every later
line from it is refused rather than silently lost. A room deleted from
the file has no name left to say, and is `this room`. What a 1.2, 1.5 or
1.9 client does with a 118 naming itself is R3's to test (§13).

### 6.5 The lobby notice

When a classic session finishes logging in (after the agreement, after
its USER_GETLIST, the moment chat-history.md §6.4 picked for replay),
the server sends it one line in the lobby, to that session only and
never logged, as an action-form notice from the system account's uid:

```
 *** Rooms: #lounge, #trading, #music and 4 more. Send /rooms to Server to see them, /join <name> to join one.
```

That is `\r *** %s` (mhxd's server-line form), with up to `[rooms]
announce_names` names, members first, and the system account's nick
in place of `Server`. It is sent only when there is a room the session
may see, the session holds bit 9, and `[system] commands` is on (the
line points at commands). It is sent at most once a day per account,
remembered in memory, so a client that reconnects is not told again.
Guests share an account, so a guest is remembered by its identity, or
else by its address. The memory is bounded: past the bound, whoever was
told longest ago is forgotten first.
`[rooms] announce = false` turns it off. It is not sent to ng
sessions, which list rooms natively, or to a classic session that
negotiated §8's capability.

### 6.6 What a period user cannot do

- **Browse without asking.** There is no room list in a 1.5 client's
  UI. `/rooms` is the list, and the lobby notice is how they learn it
  exists.
- **See a room's history.** A client that negotiated chat history
  (bit 4) and knows rooms can ask `700` with the room's id as
  `CHANNEL_ID` (§6.7). No client does today: GtkHx fetches history for
  public chat only, and fogWraith's specification keeps channel ids
  apart from chat ids, so a client written to it would not send a chat
  id there. R4 is GtkHx learning it.
- **Manage rooms.** That is the CLI and the ng wire. The classic wire
  has nothing to carry it until §8 lands.

How a 1.2, 1.5 and 1.9 client draws the invite dialog, a 106 that
arrives just after the 115 reply, and a burst of rooms is R3's exit
criterion, not an assumption.

### 6.7 `700` with a room's channel

chat-history.md §6.2's handler today answers "No such channel." to any
`CHANNEL_ID` but 0. It accepts a room's id when the session may read
the room (§5), and answers "No such channel." otherwise. The reply
echoes the room's `CHANNEL_ID`. Everything else — clamps, the byte
bound, tombstones, media sub-fields — is unchanged.

## 7. The ng wire

Capability `"rooms"` in the login reply's `caps`, present unless
`[rooms] enabled = false`, whether or not any room exists yet. Requests
of the family on a server without it answer `not_available`.

**A session is rooms-aware once it sends a request of this family**,
or a `chat` or `history` naming a room other than the lobby. Before
that, it is sent no `room_*` event and no event about a room it could
not have joined, so a client written before rooms sees today's protocol
exactly. The lobby's events are unchanged in every case. Awareness is
the session's, so a resume keeps it. The login reply's listing is as it
stood at login: a client that wants it kept current sends `rooms`, which
makes it aware.

**Room 0 and an absent `room`.** A server MUST omit `room` in events
about the lobby. It MUST accept an absent `room` and `room: 0` alike as
the lobby in every request that takes one. `room_join` and `room_part`
of the lobby are `bad_request`. Joining a room the session is already
in is answered as the first join was.

### 7.1 The login reply

A `rooms` block beside `history`:

```jsonc
"rooms": {
  "lobby": { "id": 0, "name": "lobby", "last_id": 98123 },
  "list": [
    { "id": 2754100983, "name": "lounge", "topic": "anything goes",
      "position": 0, "members": 4, "last_id": 98117, "may_post": true },
    …
  ],
  "max_joined": 32
}
```

`list` is the rooms this session may see, sorted by position then name,
never including the lobby or an archived room (a moderator or a manager
still pages an archived room by its id). `last_id` is the newest line id
in the room, absent without history. `may_post` is whether this session
may send there. `max_lines` and `max_days` are present when the room
has a retention of its own (§3). `self` gains `"manage_rooms": true`
when it is.

`last_id` lets a client that keeps its own read cursor per room badge
the rooms it has not joined. **It is not pushed:** nothing is sent
when a line is said in a room the session is not in. A client wanting
fresh badges asks `rooms` again, and the request is priced for that
(§7.2). That is the Discord sidebar, without the server holding read
state or fanning every line out to everyone who could see it.

The room object carries `read` and `post` only to a session that may
manage rooms, and to it `"archived": true` on an archived room. To anyone
else, who is admitted is not their business.

### 7.2 Requests

| `req` | `params` | `ok` | Errors besides hotline-ng.md §10's universal set |
|---|---|---|---|
| `rooms` | — | `{ "list": […] }`, as in the login reply | `not_available` |
| `room_join` | `room` | `{ "members": [ uid… ], "topic", "topic_by"?, "topic_at"?, "last_id"?, "may_post" }` | `no_such_room`, `too_many_rooms` |
| `room_part` | `room` | `{}` | `no_such_room`, `not_a_member` |
| `room_topic` | `room`, `topic` | `{}` | `no_such_room`, `access_denied` |
| `chat` | gains `room?` | `{}` | gains `no_such_room`, `not_a_member`, `read_only` |
| `history` | gains `room?` | as now | gains `no_such_room` |
| `room_create` | `name`, `topic?`, `position?`, `read?`, `post?`, `max_lines?`, `max_days?` | `{ "room": {…} }` | `access_denied`, `name_taken`, `rooms_full`, `bad_request` |
| `room_edit` | `room`, then any of `room_create`'s fields | `{ "room": {…} }` | `access_denied`, `no_such_room`, `name_taken`, `bad_request` |
| `room_archive` / `room_unarchive` | `room` | `{}` | `access_denied`, `no_such_room` |

- `no_such_room` covers a room this session may not see as well as one
  that does not exist (§5).
- `room_topic` of the lobby is its subject, under `[extra]
  set_subject`, as the classic 120. It is the subject request the ng
  wire never had.
- `chat` naming a room the session has not joined is `not_a_member`:
  sending does not imply joining. `read_only` is a room it may read but
  not post in.
- `too_many_rooms` is this session's `max_joined`; `rooms_full` is the
  server's `max_rooms`.
- In `room_create` and `room_edit`, `read` and `post` replace the list
  when present and leave it when absent; `[]` clears it. An entry that
  is neither a login nor `@role`, or that names `@everyone`, is
  `bad_request`.
- `room_create`, `room_edit` and the archive requests need
  `manage_rooms`. Delete is the CLI's alone (§2.4).
- **Weights** (`request_weight`, `conn.rs`): `rooms` light, since
  clients poll it; `room_join` and `room_part` moderate, since each
  fans out to the room, and they spend spam points at the price mhxd's
  table gives 115 and 116, as requests with classic counterparts do;
  `room_topic` as 120; the management requests heavy.

### 7.3 Events

| `ev` | `data` | Sent when |
|---|---|---|
| `chat` | gains `room` | A line in a room this session is in |
| `notice` | gains `room` | A server notice in a room, such as a kick or the §6.2 line |
| `subject` | gains `room` | A room's topic changed, to its members; the lobby's, to everyone, as now |
| `room_member_joined` | `{ "room", "user": {…} }` | A session joined a room this session is in |
| `room_member_parted` | `{ "room", "uid", "reason"? }` | A session left a room this session is in, or this session was parted. `reason`, `"access"` or `"archived"`, is sent to the session the server parted, and to nobody else: why someone lost access is not the room's business. Not sent when the session left the server: `user_parted` says that |
| `room_added` | `{ "room": {…} }` | A room this session may see was created, unarchived, or became visible to it |
| `room_changed` | `{ "room": {…} }` | A visible room's name, position, retention, gates or this session's `may_post` changed, to sessions that may see it; or its topic alone, to those that may see it and are not in it (members hear `subject`). Gates count only for a manager, who alone is shown them |
| `room_removed` | `{ "room" }` | A room was archived, or stopped being visible to this session. If it was a member, it was parted first |
| `chat_redacted` | gains `room` | moderation.md §5, for a line in a room: sent only to sessions that may read that room, and of those to the rooms-aware and its members |
| `chat_purged` | gains `room` | moderation.md §5. One event per room the purge touched, carrying that room's ids, each sent only to sessions that may read that room. The lobby's is unchanged and has no `room` |

Every one of them takes a seq, as every event does (hotline-ng.md §3).
Splitting a purge per room keeps one encoding per fan-out and keeps a
room's line ids from reaching anyone outside it.

### 7.4 Resync

hotline-ng.md §7.1's recovery after `resync_required` becomes `sync`,
then `inbox`, then **`history { room, after }` for each joined room
whose `last_id` is past the client's cursor for it**, each looping on
`has_more`. Line ids ascend within a room, not across rooms (§3), so a
cursor from one room means nothing in another.

`sync`'s reply gains the `rooms` block, with `joined`, the rooms this
session is in, each with its `last_id`:

```jsonc
"rooms": { "list": [ … ], "joined": [ { "id": 2754100983, "last_id": 98117 } ], "max_joined": 32 }
```

A client that resumes normally gets the room events it missed from the
outbox like any other, and needs nothing new.

## 8. Extended classic clients: what to propose upstream

GtkHx and other clients that negotiate capabilities are better served
by real channel transactions than by §6's invite mapping. The
reservations fit this design. The proposal:

- A **capability bit** for channels. None is allocated, and this server
  allocates none itself. Until one is, an extended client takes §6's
  path.
- **701** lists channels: per channel, `DATA_CHANNEL_ID`, name, topic,
  whether this user may post, position, member count, newest line id.
  These are the fields of §7.1, in `0x0F09`-onward fields.
- **702** with an action field: join, part, set topic, and for a
  manager create, edit, archive. Join and part could equally stay 115
  and 116 with the channel id as the chat id, as §6 does.
- **106 gains `DATA_CHANNEL_ID`** for a capable client, as the
  history spec already anticipates, so a capable client tells a room's
  line from a private chat's by the field.
- **The one-id question.** The specification keeps the two namespaces
  apart. §2.2 lets a channel id be a chat id because nothing forbids
  it; a specification that allocated channel ids differently would
  leave this server translating. Worth asking for the freedom
  explicitly.
- Per-channel permissions as server policy, not access bits, as §5
  does.

This goes to fogWraith as a proposal (`docs/proposals/`) once R2 has
shown the ng shape works, not before.

## 9. Voice and video

A room's voice room is its id (§2.2), so voice and video in a room cost
no new signaling. `voice_join { cid: <room> }` on the ng wire, or 600
with `CHAT_ID` on the classic one, joins it. The frontends check bit 55
as they do for every cid. `Core::voice_join`'s check for a nonzero cid
gains a branch: a room requires that the session is a member, and a
room it may not see answers `NoSuchChat`, never `NotAMember` (§5). The
one-room-at-a-time rule is unchanged: joining voice in `#music` leaves
voice in the lobby.

Parting a room parts its voice room, as parting a private chat does.

## 10. What else changes

- **Moderation.** `redact_line` and `report` accept a line in any
  channel. A report needs the reporter to be able to read the line's
  room. Purges select across every channel, so `lines_by` and
  `lines_by_ghost` gain an "any channel" form, and `chat_purged` goes
  out per room (§7.3). The classic wire ignores redactions today and
  still does.
- **AGENTS.md's public-chat invariant** ("Public chat is committed in
  groups") becomes per room: one `ChatCommit` and one serial per room,
  queue order being the order that room's lines are logged and heard in.
- **Flood and spam.** `chat_flood_check` already counts "public and
  private rooms together", and rooms join that count. A flood kick in a
  room posts its notice in the room it happened in, as
  `chat_flood_kick(uid, cid)` already does for any cid.
- **The domain's chat events say which kind of chat they are about.**
  `Event::Chat`, `Notice`, `ChatSubject` and the member events carry a
  bare cid. A room's are wrapped, `Event::InRoom { room, event }`, so
  the ng encoder can emit a room's events and keep a private chat's an
  `unsupported` placeholder until the ng private-chat work lands, and a
  frontend that shows no rooms leaves them out whole: the classic wire
  unwraps them into a private chat's transactions (§6), and the ng wire
  sends the placeholder for any it does not carry. A session's end is
  told to its rooms as a part, as to its private chats, except to a
  rooms-aware session, which hears it as `user_parted` alone (§7.3).
  The domain leaves that part out rather than the encoder, which could
  only turn it into a placeholder.
- **Server links.** Only the lobby crosses (§3). A ghost cannot be
  invited into a room, for the reason it cannot be invited into a
  private chat: every exported user refuses private chat. Linked rooms
  belong with the extension's own "private chat across links" future
  work.
- **The compatibility replay** (chat-history.md §6.4) stays lobby-only.
- **Metrics.** A rooms gauge beside `hxd_private_chats`, and room
  members, so a room nobody uses is visible.
- **hx-ng** gets a new conversation kind, per-room history cursors in
  place of the single `lastHistoryId` (in its resume record too, with
  the rooms it was in), a rejoin after a fresh login, rooms in the rail
  between the lobby and News, and voice's `cid` set to the room. hx-ng's
  own work, after R2.

## 11. Amendments to companion documents

- **hotline-ng.md** §4: a `rooms` row (family, this document §7, block
  `rooms`). §7.1: the resync recovery of §7.4. §7.3/§7.4: `room` on
  `chat`, `history`, `notice` and `subject`, and the new events.
- **chat-history.md** §3.3: rooms are logged; "never cid ≠ 0" becomes
  "never a private chat". §4.2: retention per channel. §6.2: a room's
  channel is accepted (§6.7). §7.2: `room` is a parameter.
- **moderation.md** §5: the audiences of `chat_redacted` and
  `chat_purged` (§7.3). §7: the room target and room-delete kind.
- **system-account.md** §3: `/rooms`, `/join` and `/part`, and `/rooms`
  as an exception to "one or two lines", as `/help` is.
- **voice.md** §2: a room's voice rule (§9).
- **account-admin.md** §1 and **access-bits.md** §4: `manage_rooms`.
- **AGENTS.md**: the public-chat invariant (§10).

## 12. Configuration

```toml
[rooms]
enabled = true
file = "rooms.toml"      # §4; relative to the working directory
lobby = "lobby"          # the lobby's name in listings and the ng rail
max_joined = 32          # rooms one session may be in
max_rooms = 256          # every entry, archived and tombstones included
announce = true          # §6.5's lobby notice to classic sessions
announce_names = 3       # names in that notice before "and n more"
```

All keys optional. The rooms themselves are not in the config: they
are in `[rooms] file`, managed by hand, by `hxd room` and by the ng
requests (§4). Whether their lines are logged is `[history]`'s
business, as it is the lobby's. `max_rooms` counts archived entries
and tombstones too, so a manager cannot create, fill and archive rooms
without end, and a file holding more entries is refused as one that
does not parse (§4). It also bounds what one reload tells a session:
about one event per room. A `max_rooms` past what a detached session
buffers (hotline-ng.md §3, 512 events in this server) lets a reload
that adds or removes that many rooms at once send such a session to
`resync_required` on its resume, never a gap.
Docker's entrypoint keeps the file in its data directory, and gains
`HXD_ROOMS_ANNOUNCE` and nothing else (docs/docker.md).

`hxd room` subcommands: `list [--archived]`, `create <name> [--topic …]
[--read entry,…] [--post entry,…] [--position n] [--max-lines n]
[--max-days n]`, `edit <name> [--name new] …`, `archive <name>`,
`unarchive <name>`, `delete <name> --purge`.

## 13. Staging

1. **R1 — the domain and the store.** `Room`, `RoomStore`, the memory
   and file stores with a conformance suite, rooms in `RosterInner`,
   `next_chat_id` checking rooms and the log, join/part/topic and §5's
   checks for logins, a `ChatCommit` per room with the commit path's
   lobby assumptions made the room's (§3), per-channel retention, `hxd
   room` and SIGHUP. Unit tests: ids ascending within each room in the
   order its members hear them while several rooms commit at once; a
   room line not exported to a link, its image not fetchable by a lobby
   reader outside the room, and its redaction not heard outside it; an
   entry written without an id given one that survives a reload; a
   server with no `[history]` carrying rooms; a room's id never reused
   after archive, delete or a hand-deleted tombstone; a narrowed gate
   parting members; retention keeping a quiet room's lines under a busy
   lobby; a file that does not parse refusing startup and leaving a
   running server's rooms alone.
2. **R2 — the ng wire.** §7 whole. E2E in `crates/hxd/tests/rooms.rs`:
   create, list, join, talk, page; a room an outsider may not see
   answering `no_such_room` to every request and `voice_join` naming
   it; a read-only room; archive parting members; resync catching up
   per room; a client that never sends a rooms request seeing no
   `room_*` event; a redaction reaching a room's reader and not an
   outsider; a member leaving the server told once.
3. **R3 — period clients.** The system commands, the invite mapping,
   the notices of §6.2–§6.5. E2E: a scripted 1.5 client `/join`s,
   accepts the invite, and talks with an ng client in the room; 113,
   115, 116, 120 and 600 naming a room the session may not see answered
   as for a chat that does not exist; `/join` of a room it is in
   sending no invite; a read-only room's notice; a parted session sent
   its 118; the lobby notice sent once and never to ng. Exit: a real
   1.2, 1.5 and 1.9 client against a real server (§6.4, §6.6).
4. **R4 — `700` per room**, §6.7, with GtkHx taught to page a room's
   window.
5. **R5 — hx-ng.** In that repository, then the e2e pin advances with
   cases using it (AGENTS.md's e2e rule).
6. **R6 — upstream.** §8's proposal.

`@role` gate entries arrive with roles.md's G4. Until then a gate holds
logins.

## 14. Open questions

- **Should the server remember the rooms an account is in?** It would
  make "always in your rooms" Discord's behavior across devices and
  reconnects, and let §6.5 re-invite a classic user automatically. It is
  per-account state the server does not keep today, and a classic
  client re-invited into four windows at every login is the kind of
  surprise chat-history.md §6.4 already declined.
- **Server-side read cursors per room.** `last_id` in listings lets
  each client keep its own. A cursor per account per room would make
  unread counts agree across a user's devices, as the inbox's `msg_read`
  does for mail.
- **A room's history in the period replay.** §10 says no. An operator
  might want `replay` per room, and it is cheap if asked for.
- **Rooms across server links**, with the hosting server moderating,
  when the extension grows that notion.
