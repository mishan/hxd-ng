# Server emoji

Status: the catalog, its images, `hxd emoji`, the server's copy of
the catalog, server emoji as reaction keys, references, and both wires
are built (§12); managing the catalog from a wire is not. This binds
nobody but this server: the protocol is the Server Emoji draft
(`Capabilities-Server-Emoji.md`, a draft written for this server, in
fogWraith's protocol documents and not yet allocated), which hxd-ng
implements on the classic wire as capability bit 20 and on the ng wire
as the `emoji` capability.

A server keeps a small catalog of custom emoji, curated by its
operator. A capable client types `:party:`, sends a reference binding
the name to a catalog id, and every capable reader draws the image;
everyone else reads `:party:`. With reactions, a catalog id is a
reaction key.

## 1. The catalog

An entry is:

| Property | Meaning |
|---|---|
| id | From 1, assigned by the store, never given again and never changed: what references and reactions name |
| name | `[a-z0-9_]`, 2 to 32 characters, unique among live entries, and given only if it is none of gemoji's shortcodes (§1.1); it may change |
| revision | The catalog revision the entry last changed at |
| image | The stored image, its SHA-256, its type, size and whether it is animated; gone once the entry is removed |

An image is never changed: a new picture is a new entry, so an id always
draws the same bytes and a client may cache them under it for good. One
picture may be two entries.

### 1.1 Shortcodes

A name a client already turns into a Unicode emoji, `:joy:` or
`:thumbsup:`, is never given to an entry: one would draw as the server's
picture on one client and as the Unicode emoji on the next. The list is
gemoji v4.1.0's shortcodes, kept in `hxd-core` (`emoji/gemoji.rs`, under
gemoji's MIT license), less the few no name can be. An add or a rename to
one is refused, by the type the store's writes take, so no writer can
skip the check. An entry already named one keeps its name: a later
release of the list, adopted here, refuses only new adds and renames.

The catalog has a **revision**, spent once by every change, in the
transaction that makes it. A rename to the entry's own name changes
nothing and spends none.

**Removal** keeps the id and the last name, so what named the entry can
still say `:name:`, and drops the image and its hash. As many removed
entries are kept as `max_count` allows live ones; past that the removed
entries with the lowest revision are **forgotten**, by revision and
never by when they were removed, since the revision is the one order
every writer agrees on where clocks may not. `floor` is the highest
revision forgotten: a client holding the catalog at a revision below it
may hold an entry nothing will mention again.

The catalog is a table in the SQLite database the moderation trail is
in (the file `[inbox]`, else `[history]`, else `[news]` names), not a
file:

- `AUTOINCREMENT` keeps an id from being given again across restarts
  and forgotten rows.
- Every row was written by the pipeline (§2); a directory of images
  beside an index invites an edit that skips it.
- A second writer, when the wires manage emoji, is serialized with the
  first by the database.

A server with no database has no catalog, and `[emoji] enabled` without
one is refused at startup.

## 2. Images

Every stored image is one this server made, through the pipeline every
upload goes through (`docs/inline-media.md` §3): sniffed, walked to its
exact end, probed before anything is allocated, decoded under the
codec's ceilings and re-encoded, so it carries no metadata of any kind.
It is then **fitted** within `max_dimension` square, keeping its aspect
ratio.

- **A still** (PNG, JPEG or a one-frame GIF) is a PNG. One past
  `max_bytes` is shrunk by quarters until it fits, and refused once its
  longest side is down to about 32 pixels. A photograph at 128 pixels is
  a PNG of several times the default `max_bytes`, so for one this is the
  common path rather than a corner.
- **An animation** is a GIF, every frame fitted. One past `max_bytes`
  is its first frame, as a still, shrunk the same way.
- **Before any decode**, a source is held to 1024 pixels a side, which
  bounds the work of fitting an animation frame by frame, and an
  animation to `max_frames`, 10 seconds in all, and its frames times its
  pixels within the codec's decode budget, so a large canvas allows
  fewer frames. `hxd emoji` reads a
  source of at most 2 MiB.

`hxd emoji` makes the image, so the server decodes nothing.

## 3. `hxd emoji`

```sh
hxd emoji list [--removed]
hxd emoji add <name> <file>
hxd emoji rename <name|'#id'> <new-name>
hxd emoji remove <name|'#id'>
```

It is the catalog's only writer. It opens the server's database, beside
a running server or without one, and takes its limits from `[emoji]`. A
refusal says why: a name that is taken, malformed or a common emoji's
shortcode, a catalog at
`max_count`, or an image the pipeline refused, the catalog unchanged.

A running server applies an edit on SIGHUP (§4).

## 4. The server's copy

The server holds the whole catalog, images included, as a snapshot
loaded at startup, and answers every read from it without touching the
store. That is at most twice `max_count` entries and `max_count` times
`max_bytes` of images: a few megabytes at the defaults, and the ceilings
of `max_count` and `max_bytes` bound the worst case.

SIGHUP reads the catalog again and serves it from then on. Until then,
the server serves the catalog as it was: an emoji `hxd emoji` added is
not there yet, and one it removed still is. An operator's batch of
edits followed by one SIGHUP is one reread. A store that
cannot be read at startup stops the server; on SIGHUP the copy in use
stays, and the log says why.

A listing is answered for the revision a client holds:

| The client holds | It is sent |
|---|---|
| Nothing | Every entry kept, live and removed |
| The current revision | Nothing |
| A revision from `floor` to the current one | The entries changed since, live and removed: a delta |
| A revision below `floor`, or above the current one | Every entry kept, as if it held nothing |

Entries go in ascending id order and are paged by id. Between pages the
catalog may change and each page carries the revision it was read at:
a client keeps the first page's, so its next delta covers what changed
while it paged. A client that can tell a later page of a delta was
answered whole (the ng wire's `delta`) knows entries were forgotten, or
the catalog restored, meanwhile, and starts again from no revision.

## 5. Reactions

A catalog id is a reaction key (`docs/hotline-ng.md` §7.3), `{
"custom": id }` on the ng wire and kind 2 packed as the id's four bytes
big-endian where it is kept, so it needs no migration. It names
the id and never the name: a rename changes nothing about the reactions
made with it, and a new emoji under a name an old one freed is another
key. Past the kind, a server emoji is a key like any other: it counts
toward a line's keys and an account's as an emoji does, and every
reader of reactions is shown it, one that does not know the catalog
too, which draws a placeholder for it.

- **Added**, it must be live in the copy the server serves (§4), on a
  line, a stored message and an instant message alike, or the reaction
  is refused `no_such_emoji`: one removed, one never added, or one
  added since the last SIGHUP. The check is after the session's own
  privileges and before the account's rate, since it looks up the
  catalog and not the target. A removal not yet applied by SIGHUP
  leaves the emoji live, and one applied between that check and the
  reaction being kept lets that one reaction through; nothing scans the
  reactions made.
- **Taken away**, it is never refused for what became of the emoji, so
  a reaction made with one since removed can be taken back. What stays
  goes on naming the id.
- **Who may send one**, to `react` or as the key `reactions` asks
  about: a session that declared `emoji` at login, to a server serving
  a catalog. From any other the key is malformed, added or taken away,
  so on a server with `[emoji] enabled = false` a reaction kept from
  before is shown and stays until retention, a redaction, a clear or a
  purge takes it.
- **A moderator's clear** records each server emoji by the name the
  catalog gives it, removed or not, and by its id once it is forgotten.

## 6. References

What makes `:party:` in a line or a message an emoji is a **reference**
its sender's client sends beside the text, binding the name to an id
for that one message; the text is sent, kept and relayed as typed, and
the server never reads it for names. A chat line, a private chat's line,
a private message and an instant message take them.

- **Kept** are those of the first 32 sent that name a live entry, in the
  copy the server serves (§4), by exactly its current name, then each id
  once, the first kept, in the order sent. Every other is dropped
  silently: a message is never refused over its references. A
  reference the text never uses is kept, and readers ignore it.
- **Stored** beside the line or the message, as what it answers is,
  and gone with its words when a redaction or a purge takes them.
- **Relayed** to a reader whose wire negotiated server emoji, and to
  nobody else, who reads `:party:`. A reference names an id, so a later
  rename leaves the image the sender saw.
- **Never across a link**: a lobby line crosses with its text alone, a
  linked user's line has none, and a message to one is sent without
  them.

## 7. The classic wire

Capability bit 20, offered where the server serves a catalog, and
confirmed only beside bit 1, as the draft requires: a Mac Roman session
reads `:name:` as text. The draft's numbers are kept in
`hxd-session/src/emoji.rs` until they are allocated. To a session
without bit 20 nothing changes: 713, 714 and 716 are answered as any
unknown transaction, not implemented; it is sent no 715 and no references.

- **The login reply** beside a confirmed bit 20 carries the catalog's
  revision, read after the session attached so a reload since is told
  by the 715 that follows, and `max_count`, `max_bytes` and
  `max_dimension`.
- **Get Emoji Catalog (713)** answers §4's listing from the revision
  the client sends, after the id it sends, as many entries as keep the
  reply within 64 KiB, with `DATA_EMOJI_MORE` when more remain.
  A delta and a whole listing look alike on this wire.
- **Get Emoji (714)** answers a live entry's image, and a removed or
  unknown id a task error with reason `NoSuchEmoji`. A session may fetch
  100 at once and then two a second; past that it is refused
  `RateLimited`.
- **Emoji Catalog Changed (715)**, task id 0, carries the revision,
  once per SIGHUP that moved it.
- **Manage Emoji (716)** is refused `NotAllowed` whatever it asks, the
  image unread: `hxd emoji` is the catalog's only writer.
- **References** in `DATA_EMOJI_REFS` on 105, 108 and 810 are read from
  a bit-20 session and dropped unread from any other, the text relayed
  as ever. They are sent beside the text on 106, 104 and 811, and in a
  700 entry as sub-field `0x0022`, never on a tombstone. A bit-17
  session's structured line carries none: on 106 they are beside the
  entry, so its entry is the same with references or without.
- **Spam points**: 713, 714 and 716 cost none, as the icon fetches do. A
  client fetching the images of a busy chat as it joins would be banned
  at mhxd's price, and 714 is rationed on its own.

## 8. The ng wire

Capability `emoji` (`docs/hotline-ng.md` §4), granted to a login that
declares `emoji: true`, where the server serves a catalog, and kept
across a resume. To a session that did not declare it nothing changes:
`emoji_list` is `not_available`, the `emoji` it sends is ignored, and it
is sent no `emoji_changed` and no references. `GET /emoji/{hash}`
serves any session, as below.

- **The login reply** beside the capability carries the `emoji` block,
  `{ "revision", "max_count", "max_bytes", "max_dimension", "manage":
  false }`, the revision read after the session attached, as on the
  classic wire. `manage` is `false`: `hxd emoji` is the catalog's only
  writer.
- **`emoji_list`**, `revision?` and `after?`, answers §4's listing as
  `{ "revision", "emoji"?, "delta"?, "has_more"? }`: at most 200
  entries in ascending id order after `after`, `emoji` left out when
  there are none, `delta: true` when they are only what changed since
  `revision`, and `has_more: true` when more remain, for the client to
  ask again with the same `revision` and `after` the last id. A live
  entry is `{ "id", "revision", "name", "hash", "width", "height",
  "animated"? }`, `hash` the image's SHA-256 in lowercase hex and
  `animated` present, and `true`, for an animation; a removed one is
  `{ "id", "revision", "name", "removed": true }`. It costs 1 of an ng
  session's request limit, and no spam points, as 713 costs none.
- **`emoji_changed`**, `{ "revision" }`, once per SIGHUP that moved the
  revision. A client told `resync_required` asks `emoji_list` again
  from the revision it holds, beside its `history` catch-up, since the
  gap may have held one.
- **`GET /emoji/{hash}`**, with the session's bearer as `GET
  /avatars/{id}` takes it (`docs/avatars.md` §4), answers a live
  emoji's image, PNG or GIF, cacheable for good (`private,
  max-age=31536000, immutable`, its `ETag` the hash), with `nosniff`
  and a sandbox CSP. Any session may fetch any live emoji, and one
  picture two entries share is served while either lives. A hash no
  live emoji has is 404 `no_such_emoji`, to a conditional request too:
  the lookup comes before `If-None-Match`, so a cache that revalidates
  drops it. One that does not keeps it, so a client stops showing an
  entry when `emoji_list` says it was removed. Without a session it is
  401, and past `[limits] avatar_fetches_per_minute` from one address
  429, counted apart from the avatars'. A server serving no catalog
  answers every hash 404, as one with no avatars answers `GET
  /avatars/{id}`.
- **References** are `emoji`, `[ { "name", "id" } ]`, on `chat` and
  `msg`, of which the first 32 are read and kept as §6 says. Anything
  but a list, or among the first 32 read anything but an object with a
  string `name` and an integer `id`, is `bad_request`; a name or an id no entry could have is dropped as
  every other miss is. They may go beside `signed`, outside what the
  signature covers, as the nick is; a repeat under a line's guid keeps
  the first line's; a sealed message has none. They are sent as kept
  on the `chat`, `msg` and `im` events, `history` lines, from a page or
  by `ids`, `inbox` rows and the messages of a `requests` listing, to
  sessions that declared `emoji` alone.

## 9. Restoring a backup

Restoring the database restores the catalog with it, and with it a
revision a client may already have passed. A client holding a revision
above the restored one is sent the whole catalog, but only until the
revision climbs back to it; after that its delta leaves out what the
restore took away. Nor can a client be told that an id it cached now
names a different picture: the database's record of the ids it gave is
restored with it, so an id given after the backup may be given again.
A restore invalidates every client's cache.

## 10. Limits

| What | Bound |
|---|---|
| `[emoji] max_count` | 200 live entries, at most 1000; as many removed ones kept |
| `max_bytes` | 16384, from 64 to 65535, so an image travels in one classic field |
| `max_dimension` | 128, from 64 to 256 |
| `max_frames` | 50, from 16 to 150 |
| An animation | 10 seconds |
| A source | 1024 pixels a side; 2 MiB as `hxd emoji` reads it |
| References | the first 32 sent, each id once |
| 714 | 100 at once a session, then two a second |
| `emoji_list` | 200 entries a page; 1 of the request limit |
| `GET /emoji/{hash}` | `[limits] avatar_fetches_per_minute` an address |

A lowered `max_bytes` or `max_dimension` holds new images to it; an
image already stored stays as it was made.

## 11. Failure modes

- **A store error at startup**: the server does not start. On SIGHUP:
  the copy in use stays, logged.
- **An edit not yet applied**: the server serves the catalog as of its
  last SIGHUP.
- **An image the pipeline refuses**: `hxd emoji` says why, the catalog
  unchanged.
- **A removal racing a reference or a reaction**: one may land. It names
  an id, and is drawn as `:name:` once the catalog says the entry is
  removed.

## 12. Stages

| Stage | Content | Built |
|---|---|---|
| E1 | The catalog's types, names and stores, schema V37, `[emoji]` | yes |
| E2 | The emoji pipeline, `hxd emoji`, the server's copy and its reload on SIGHUP | yes |
| E3 | Server emoji as reaction keys (§5) | yes |
| E4 | References in the domain (§6), and the classic wire (§7) | yes |
| E5 | The ng wire (§8) | yes |
| E6, E7 | hx-ng, and the out-of-process suite | no |

Managing the catalog from either wire, rather than from `hxd emoji`
alone, comes after.
