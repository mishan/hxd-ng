# Attachments: files on chat lines and private messages

Status: draft, 2026-10-25. Nothing here is built. Layer 1 (§2 to §10)
needs only what exists; layer 2 (§11) waits on the signing of
[e2e-messages.md](e2e-messages.md), itself a draft.

An image can ride a chat line or a private message
([inline-media.md](inline-media.md)), and a news article can carry
pictures ([news.md](news.md) §7), but a PDF, a patch or a zip cannot
travel with what someone says: today the sender uploads it into
`Uploads` and types where it is. This document makes a file an
attachment, kept by the server in its file area beside the line or
message that carries it, readable by the people that line or message
reached, and gone when it goes. Then, once signed messages exist, it
binds the file's exact bytes into the sender's signature.

**Decisions (2026-10):**

- **An attachment is a file in the file area**, in a folder the server
  owns, so the local area's path rules, publishing and resume are
  reused, and a classic client fetches one with an ordinary Hotline
  file transfer.
- **The bytes are never re-encoded or inspected.** Unlike an image, an
  attachment is served exactly as uploaded, download only, never
  rendered; images keep using inline media.
- **A reference is an id plus name, size and SHA-256**, recorded by the
  server at upload. The hash is checked when the file is published and
  whenever it is served.
- **Who may fetch is decided as inline media decides it**: by
  principals fixed when the line or message is relayed, with history
  readers added for a logged room, and mailboxes for mail.
- **An attachment lives exactly as long as its row**: the chat log line
  or the inbox message. A context with no row (a private chat, a
  server without history, a guest's mail) takes no attachment.
- **Attachments do not cross server links in v1.** A linked server's
  users see the text.
- **Signing adds one key to the signed message**, `file`, so one
  signature covers sender, text and bytes, sealed or not.

## 1. What this reuses, and why not the media store

The media store holds re-encoded images in memory for a day
(inline-media.md §4), and news keeps re-encoded images in a blob store
of its own (news.md §7.2). Neither fits an arbitrary file: the bytes
cannot be canonicalized, a file may be large, and it should outlive a
restart for as long as its message does. The file area already holds
arbitrary files durably, publishes an upload only once it is whole and
validated, never overwrites, stages partials in `.hxd-state`, and
resumes on both wires (files-plan.md, "Local writable slice";
ng-uploads.md §2, §3). So an attachment is a file there, and what this
document adds is ownership, a reference, an audience and a lifetime.

What it borrows from inline media is the authorization model
(inline-media.md §5.1, and AGENTS.md's "an image is a handle, and a
handle is an authorization"): attaching asks whether this sender
uploaded the file, and fetching asks whether this principal was shown
it. What it borrows from news is the two steps, stage and commit
(news.md §7.3), so that a large upload is never inside a request the
roster waits on.

## 2. Where attachments live

`[attachments] folder` (default `Attachments`) is a folder at the root
of the local area. The server makes it, and everything in it:

```
Attachments/
  Lobby/2026-10/report.pdf
  Rooms/2754100983/2026-10/build.log
  Mail/7QX4M2KD9H/2026-10/notes 2.txt
```

- **The lobby** is `Lobby`, and **a curated room** is `Rooms/<id>`, by
  its permanent id (chat-rooms.md §2.2), so a rename moves nothing.
- **A mailbox** is `Mail/<folder id>`, ten random Crockford base32
  characters, recorded against the recipient's mailbox key
  (private-messages.md §4). The folder belongs to whoever the mailbox
  does, so `claim`, `rotate` and `purge` re-key or remove the record
  with the mailbox's rows: one more obligation for each of the three.
- **A month folder** below each keeps any one folder under `[files]
  max_entries`, past which a listing is refused, and gives a classic
  user something to browse by.
- **The published name** is the attachment's name made safe for every
  wire: characters outside printable ASCII become `_`, `/` and `:`
  become `-`, a leading `.` becomes `_`, and it is cut to 31 characters
  keeping the extension, the most a classic listing shows
  (`hxd-session` `files.rs`, `base_name`). A taken name is numbered as
  a blind upload is (`notes 2.txt`, files-plan.md). The reference
  keeps the real name; the published one exists for classic clients.

`folder` must not name an upload folder or a drop box
(`FilePath::is_upload_folder`, `is_drop_box`): the server refuses it at
startup, since those rules would then open it to FilePut. With
`[files]` in manifest mode, or absent, `[attachments]` is a startup
error, since there is nowhere to put a file.

**Listings show what the session may fetch, and nothing else.** The
attachments folder and its `Lobby` and `Rooms` folders are listed as
any folder is. A room's folder is listed only to a session that may
see the room (chat-rooms.md §5), a `Mail` folder only to its owner, and
inside them a file only to a session that may fetch it (§5). A path the
session may not reach is answered as one that does not exist, before
anything is looked up, as a drop box is for an account without
`view_drop_boxes` (hotline-ng.md §7.2). Get Info, `files_info` and
Download Folder follow the listing.

**The folder is the server's to change.** On both wires, an upload,
New Folder, rename, move or comment inside it, or a move into it, is
refused (`access_denied` on ng, "That folder is the server's." on the
classic wire), with or without `upload_anywhere`. Delete is allowed
under the ordinary bits (`delete_files`, `delete_folders`), so an
administrator can remove a file by hand, and what was removed reads as
gone (§6). A file put there behind the server's back is not an
attachment and is listed to nobody; the hourly sweep logs it and
leaves it alone.

## 3. Uploading

An upload is staged first and attached afterward (§4):

1. **Ask.** `attachment_upload { name, size, sha256 }` (§8.2). The
   session needs `upload_files`. `upload_anywhere` is never needed, and
   never enough on its own. `name` is 1 to 255 bytes of UTF-8 with no
   C0 control, no `/`, and not `.` or `..`; anything else is
   `bad_request`, never rewritten, since a signature may cover it
   (§11). `size` is at least 1 and at most `[attachments] max_bytes`,
   itself at most `[files] max_file_size`. `sha256` is the client's
   hash of the whole file, hex.
2. **Send.** Pieces over HTTP, exactly ng-uploads.md §2: the same
   `PUT /files/upload/<token>` route, `Content-Range`, `piece`,
   `Upload-Offset`, the same partials in `.hxd-state`, the same I/O
   permits and transfer places.
3. **Publish to staging.** On the last piece the server reads the
   partial back, hashes it, and compares with `sha256`. A mismatch
   discards the partial and answers `422` with `hash_mismatch`. A match
   moves the file into a staging folder under `.hxd-state`, where no
   protocol path reaches, records the attachment (id, uploader, name,
   size, SHA-256, staged time), and answers `201` with the reference.

**Resume** is ng-uploads.md §3 with one change: a partial is keyed by
the account and the file's `sha256` rather than by a destination path,
since a staged upload has none. Asking again with the same hash is
quoted the partial's length and its trailing-window digest, and the
client echoes it as there. An account nobody in particular is behind,
`guest` above all, is never quoted a partial and sends in one piece, as
a blind upload does (ng-uploads.md §4), so one guest cannot finish or
learn of another's file.

**A staged attachment belongs to its sender**, held as a chat guid is
held (hotline-ng.md §7.3): the account where one person is behind it,
or the identity the session proved, or else the session alone. So a
client that uploads, loses its connection and logs in again can still
attach what it uploaded. One not attached within `pending_ttl`
(default an hour) is deleted.

**What it costs.** `attachment_upload` spends FilePut's 3 spam points
and is a write on the ng request limit, as `files_upload` is
(ng-uploads.md §5). In flight, an upload draws on the pools every
upload draws on: `max_partial_bytes`, `max_partials`,
`max_partials_per_account`, `uploads_per_account`, `upload_timeout` per
piece and `partial_ttl` for the whole. Published, it counts against
four bounds of its own, all refused before any piece is accepted:

| Bound | Default | Refused as |
|---|---|---|
| `max_bytes`, one file | 64 MiB | `too_large` |
| `uploads_per_hour`, per sender | 30 | `rate_limited` with `retry_after` |
| `quota_bytes`, staged and attached files one sender uploaded and still has | 512 MiB | `quota_exceeded` |
| `max_total_bytes`, every attachment on the server, 0 for none | 0 | `quota_exceeded` |

A sender here is keyed as news posts are: an account's sessions
together, a guest by its address (files-plan.md, F3). The file area has
no per-account quota of its own yet (files-plan.md, "Deferred work"),
so these are the only bounds on what attachments keep; they do not
count toward anything an ordinary upload is held to once published. `can_spam`
exempts from the rate, as from the other budgets. None of them evicts: an attachment is part of a record, and refusing
the next is better than removing an old one.

## 4. Attaching

`chat` and `msg` gain `attachment`, the id of a staged upload (§8.3).
At most one per line or message in v1. It is attached only when:

- the sender holds what the request already needs (send chat and the
  room's `post` gate, chat-rooms.md §5; or send messages), and still
  holds `upload_files`;
- the id names a staged upload of this sender's (§3), not yet attached;
  otherwise `no_such_attachment`, one answer for an id that never
  existed, is someone else's, has expired or was attached already;
- the request carries a `guid`, or it is `bad_request`, except beside
  `sealed` (below). A send that
  consumed the upload and lost its reply would otherwise fail on retry
  for an id already used; with the guid, the retry is answered as the
  original was (hotline-ng.md §7.1, §7.3), and nothing is attached
  twice;
- the line or message will be kept, since its row is the attachment's
  life (§6). A chat line needs the `history` capability; every room is
  logged when the lobby is (chat-rooms.md §3), and a private chat never
  is. A private message needs both the sender and the recipient to have
  a mailbox and the store to take the row, so a plain guest cannot
  attach and cannot be sent a file, and a message the sender's daily
  quota would leave unstored (private-messages.md §9) is refused
  `quota_exceeded` even to a connected recipient. Each of the rest is
  `not_attachable`, with a `text` saying which.

The file then moves from staging into its folder (§2) by the atomic
no-replace link FilePut publishes with, in the same step that commits
the line or the message row, and the row records the published path.
`text` may be empty when an attachment is present, as it may with
media.

A sealed message (e2e-messages.md §4.3) to a recipient with a mailbox
can carry one too, beside the box, and without a `guid`, which a sealed
message never takes: there is no row, so the file stays in the recipient's mailbox
folder until `[inbox] retain_unread` after it was sent, the longest an
unread stored message would last. A resend of the same box naming the
same attachment to the same recipient attaches nothing new. What a
sealed message's cleartext `attachment` tells the server is §12's.

## 5. Who may fetch

Every fetch needs `download_files`, as every download does. Beyond it:

| Context | May fetch |
|---|---|
| Lobby or room line | the sender, and every session the line was relayed to, as `Session` principals captured at relay (inline-media.md §5.1, §5.3); and any session that may page that room's history now (bit 56 and the room's read gate, chat-rooms.md §5) while the line is in the log |
| Private message | the sender's mailbox and the recipient's mailbox, read from the message row, so mail read days later, on any device, resolves |
| Sealed message | the recipient's mailbox and the sender's |
| A reported line or message | moderators, while the report is open (moderation.md §4.3's rule for a reported image) |

History readers are added for a logged room on purpose, where inline
media's default withholds them (inline-media.md §5.4): that rule was
written for an extension's MUST about images in memory, and a file
posted into a logged room is part of the room's record. A reader who
can page the line already sees its name, size and hash. Moderators may
page every room (chat-rooms.md §5), so they reach every room
attachment, and no mail attachment unless it is reported, as with mail
itself (moderation.md §4.2).

A guest session offers only itself as a principal, never the shared
login's mailbox (inline-media.md §5.1). Captured sessions are kept in
memory and pruned as they end, as media's are; the mailboxes are read
from the row, so nothing about mail authorization is lost at a
restart.

## 6. Lifetime

An attachment is removed, file and record, whenever its row is:

- **Chat retention** (chat-history.md §4.2): the hourly prune that
  removes lines past `max_lines` or `max_days`, a room's own included,
  removes their attachments.
- **A room deleted** (chat-rooms.md §2.4) takes its lines and its
  folder. An archived room keeps both, as it keeps its log.
- **Inbox retention** (private-messages.md §9, `retain_read`,
  `retain_unread`) and `hxd inbox purge` remove a message's attachment
  with it. Deleting an account removes nothing, as it removes no mail.
- **Redaction** of a line (moderation.md §3.1) removes its attachment,
  as it revokes an image, and records the name, size and hash in the
  one audit row.
- **A purge** of a person (moderation.md §3.3) removes every attachment
  they uploaded in the window, chat and mail alike, as it revokes every
  handle; the messages stay, their attachments reading gone.
- **A staged upload** not attached in `pending_ttl` (§3).

The row is deleted first and the file unlinked after; a file left by a
crash between the two is found by the hourly sweep, which unlinks a
file in the folder only when a record names it and its row has gone.

**Gone reads as gone.** A file removed by hand (§2), or one whose size,
modification time or bytes no longer match what was recorded (§7),
leaves the line and the message as they were, with the reference
marked gone: the ng object loses its `id` (§8.4), the classic text says
so (§9), and a fetch is `attachment_gone` to anyone who could have
fetched it and `not_found` to everyone else, the narrowing
inline-media.md §8.2 decided for images.

## 7. Serving

**Download only.** On the ng wire an attachment is fetched with
`attachment_download` (§8.3) and served by the `/files/<token>` route,
ranges and resume included (hotline-ng.md §7.2), with:

```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="…"; filename*=UTF-8''…
X-Content-Type-Options: nosniff
Content-Security-Policy: sandbox; default-src 'none'
Cache-Control: private, no-store
```

The type is fixed whatever the name says, and the disposition carries
the attachment's real name, not the published one. `files_preview` on
an attachment is `unsupported`: a client shows an attachment as a file
to save, never as content, and images belong to inline media, which
re-encodes them. On the classic wire it is an ordinary FileGet (202)
over HTXF, typed by its extension as any file without Finder
information is (ng-uploads.md §6).

**The hash is checked as it is served.** The record keeps the file's
size and modification time from when it was published. Every read
compares them first, and a file that differs is gone. A read from the
start hashes as it streams and holds its last 64 KiB back until the
hash matches, so a file changed on disk without its size or time
changing ends the transfer short, on either wire, rather than
completing with other bytes; it is then gone. A ranged read or a resume
is served after the size and time check alone, and the client's own
check (§8.4, §11) covers it.

## 8. The ng wire

### 8.1 Capability and login block

`caps` gains `"attachments"`, present only with `files` and
`chat_guid`, and a login block beside `files`:

```jsonc
"attachments": {
  "upload": true,               // this session holds upload_files
  "chat": true,                 // lines may carry one (history is on)
  "mail": true,                 // messages may (the inbox is on, and this account has a mailbox)
  "max_bytes": "67108864",
  "quota_bytes": "536870912",
  "used_bytes": "1048576"       // this sender's, at login
}
```

Sizes are decimal strings, as everywhere in §7.2.

### 8.2 Upload

```jsonc
→ { "req": "attachment_upload", "params": { "name": "report.pdf", "size": "48127330",
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" } }
← { "ok": { "url": "/files/upload/<token>", "offset": "0", "piece": "8388608" } }
```

`fresh: true` discards a partial, and `digest` comes with a nonzero
`offset`, both exactly as `files_upload`'s (hotline-ng.md §7.2). The
pieces are `files_upload`'s; the last answers

```jsonc
201 { "attachment": { "id": "…22 chars…", "name": "report.pdf",
                      "size": "48127330", "sha256": "9f86…0a08" } }
```

and `422 { "error": { "code": "hash_mismatch", … } }` when the bytes do
not hash to `sha256`. The id is 16 bytes from the OS CSPRNG,
base64url, as a media handle is.

### 8.3 Requests

| `req` | change |
|---|---|
| `attachment_upload` | new: §3, §8.2 |
| `attachment_download` | new: `{ id }` → `{ url, size }`, `url` a `/files/<token>` bearer URL as `files_download`'s, bound to the session and short-lived |
| `chat` | params gain `attachment?`; `guid` required with it (§4) |
| `msg` | params gain `attachment?`, `guid` required with it except beside `sealed`, where it is allowed and `guid` stays refused (§4) |

Both `attachment_upload` and `attachment_download` are answered
`not_available` without the capability.

### 8.4 Events and listings

The `chat` and `msg` events, `history` lines and `inbox` rows gain

```jsonc
"attachment": { "id": "…", "name": "report.pdf", "size": "48127330", "sha256": "9f86…0a08" }
```

with `id` absent once it is gone (§6), so a client never offers a fetch
that would fail, and the name, size and hash stay to be shown. A
redacted line carries none of it. A client SHOULD hash what it
downloads and compare it with `sha256` before it offers the file to its
user, and treat a mismatch as a failed download.

### 8.5 Errors

| Code | From | Meaning |
|---|---|---|
| `no_such_attachment` | `chat`, `msg` | Not this sender's staged upload, or expired, or attached already (§4) |
| `not_attachable` | `chat`, `msg` | This line or message would not be kept: a private chat, no history, a sender or recipient without a mailbox |
| `attachment_gone` | `attachment_download` | The file was removed, to a session that could have fetched it |
| `hash_mismatch` | the last piece, `422` | The bytes did not hash to `sha256` |

Besides those: `access_denied`, `bad_request`, `too_large`,
`quota_exceeded`, `rate_limited`, `busy` and `not_found` in their
existing meanings, `not_found` covering an id that does not exist and
one this session may not fetch alike. A message to a linked server's
user is `not_delivered`, as one with media is (§10).

## 9. The classic wire

**Receiving.** A classic recipient of a line (106) or a message (104)
with an attachment gets the text, then on a line of its own:

```
[file] report.pdf (45.9 MB) in Attachments/Lobby/2026-10
```

The name is the published one (§2), which is what the folder lists; the
size is bytes under 1024, and otherwise KB, MB or GB to one decimal,
base 1024; the folder is the path to browse to. With no text, that line
is the whole body, so the room shows `alice:  [file] report.pdf (45.9 MB)
in Attachments/Lobby/2026-10` in mhxd's form. Once the file is gone:

```
[file] report.pdf (45.9 MB), removed
```

The suffix is classic egress, as the conversion to Mac Roman is: the
stored text is the sender's, the ng wire carries it unchanged, and a
signed line keeps verifying (e2e-messages.md §4.11). Where a cap on
this wire would cut the body, it cuts the text before the suffix. A
`700` entry's body (chat-history.md §6.2), and the lines `[history]
replay` sends, carry the same suffix, and a stored message flushed at
login does too.

**Fetching.** The recipient browses to that folder and downloads the
file as any other: listing (200), Get Info (206), FileGet (202), HTXF,
resume, Large File where negotiated. Each is held to §5 by path: the
server looks the path up in the attachment records, and a file the
session may not fetch is "File not found.", as if it were not there.
An account without `download_files` sees the line and cannot fetch,
as with any file; the bootstrap guest has neither `upload_files` nor
`download_files`.

**Sending.** A classic client cannot attach in v1: 105 and 108 have no
field for it, and the folder refuses its uploads (§2). An extension for
it is §18's.

## 10. Server links

Nothing of an attachment crosses a link in v1. The hub exports a lobby
line's text and not its attachment, and an attachment-only line not at
all, exactly as it treats media (server-link.md §4.1). A linked
server's users therefore see the text, without the suffix, since they
could not fetch from here. A private message with an attachment to a
ghost is refused locally `not_delivered`, as one with media is
(server-link.md §6.2). Rooms do not cross links (chat-rooms.md §3), so
nothing else is affected. A signed lobby line with an attachment is
§11.4's.

## 11. Signed attachments

### 11.1 One signature, no second one

A file gets no signature of its own. When signed messages exist
(e2e-messages.md §3), the attachment's reference is part of the signed
message, so the sender's one signature covers who sent it, what it
says, its scope, and the exact bytes of its file, and a reader that
verifies the message and then the hash knows the file is the one the
sender attached. The same holds inside a sealed message, whose whole
map is signed (e2e-messages.md §3.8). Nothing in the construction
changes: `file` is one more key under the same `sig`, in the same
deterministic encoding, under the same domains.

### 11.2 The `file` key

The private message (e2e-messages.md §3.2) and the public line (§3.3)
gain one optional key:

| Key | Type | Req | Notes |
|---|---|---|---|
| `file` | map | no | `{ "name": tstr, "size": uint, "sha256": bstr(32) }`: the attachment as §3 recorded it. `name` 1 to 255 bytes of UTF-8 under §3's rules; `size` at least 1; `sha256` of the whole file |

- **It is not a text key**, so a detached form keeps it, and it crosses
  the wire with the signature rather than beside it. `name` is signed
  exactly as uploaded, with no canonicalization: §3 refuses a name
  with a control character, so there are no line endings to
  canonicalize.
- **A reader rejects** a `file` that is not a map of exactly those
  three keys with those types, a `name` outside §3's rules, a `size` of
  0, or a `sha256` that is not 32 bytes.
- **Size.** A `file` with a 255-byte name and a size past 32 bits
  encodes to 323 bytes. e2e-messages.md §9's largest detached line, 684
  bytes, becomes 1,007, inside the 1,020 bound of §3.1, so the bound
  stays. A whole map with a file may no longer fit the top padding size
  of §3.7 with a full text and a full quote (17,068 bytes before); a
  client shortens the quote, which §3.7 already requires of a map that
  fits in none.
- **Articles** are left alone: their attachments are images in the news
  store (news.md §7), not files.

### 11.3 What the server and the client check

A server offering `signed` and `attachments` checks, on ingest, beside
e2e-messages.md §4.11's list:

- a signed `chat` or `msg` with `attachment` carries a map whose `file`
  equals the attachment's recorded name, size and hash, byte for byte;
- a signed one without `attachment` carries no `file`;
- otherwise `bad_signature`, with a `text` naming the check, and
  nothing is relayed, stored or attached.

So a signed line or message with an attachment is always covered: there
is no signed-but-uncovered file, as there is a signed line with an
uncovered image (e2e-messages.md §4.7). A sealed message's `file` is
inside the box, where the server cannot check it; the cleartext
`attachment` beside it is checked by the recipient instead.

A client, after verifying the message (e2e-messages.md §3.5):

1. compares the event's `attachment` (name, size, hash) with the
   signed `file`, and for a sealed message with the opened map's;
2. downloads, hashes the bytes, and compares with `file.sha256` and
   `file.size`;
3. treats any difference as a **forged attachment**: it discards the
   bytes, never offers them to the user, and marks the message so,
   whatever state the message itself is in. The text stays in its
   state; only the file is refused.

A gone attachment (no `id`) on a verified message is shown as signed
and unavailable, never as forged: a server may delete, and cannot
substitute.

### 11.4 Links

A signed lobby line's link form must fit 256 bytes (e2e-messages.md
§5), and with `file` it cannot: its 201 bytes plus up to 323 is past
it. Since a server may neither cut it nor send its text unsigned
(§4.11 there), a signed lobby line with an attachment is not exported
to links at all, and the sender's `chat` reply is as for any line. A
signed private message to a ghost is refused before that, by §10.

### 11.5 The edit e2e-messages.md would need

Recommended, not made here:

- the header's last bullet and §1.1's "Attachments": a file attachment
  is covered by `file`; an image is still not;
- §3.2 and §3.3: the `file` row and its reject rules, as §11.2 gives
  them; §3.3's "Not signed" keeps `media` and names `file` as signed;
- §4.3: `attachment` allowed beside `sealed`;
- §4.7 and §4.9: `attachment` on signed `chat` and `msg`, and §11.3's
  checks, also in §4.11's list;
- §5: a signed line with `file` has no link form and is not exported;
- §8: the client's checks and the forged-attachment mark, and the
  "shown as not covered" sentence narrowed to images;
- §9: the size with `file`;
- §11's "Attachments" bullet narrowed to images and to sealing a file's
  bytes;
- §13: vectors for a line and a private message carrying `file`, and a
  reject case for a `file` with an extra key.

## 12. Threat model

**Server enforcement protects against other users**, given an honest
server: a file reaches only the principals its line or message
reached (§5); one session cannot attach another's upload (§4); a
listing tells nobody what they may not fetch (§2); a hostile name
cannot reach a path, since the published name is the server's and the
area resolves beneath its capability (files-plan.md); a file is never
rendered by the server's origin, and its type is fixed (§7); and the
quotas of §3 bound what one sender can make the server keep.

**It trusts the server.** The operator, and anyone with the disk or a
backup, reads every attachment, mail included, and can change, swap
or withhold one; an unsigned reference is the server's word, so a
hostile server can change the bytes and the hash together. The hash
check of §7 catches a file changed behind the server's back, by disk
corruption or a hand edit, and nothing more. Nothing scans what is
uploaded: a file may be malware, and a client says so before opening
one, as it would for any download.

**Signing adds authenticity of the bytes** (§11): no server, home or
relay, can substitute a file on a signed line or message, or rename
it, without the reader seeing a forged attachment. It adds nothing to
confidentiality, delivery or availability: a server can still read,
delete or withhold the file, and serve the message without it. It
costs the deniability e2e-messages.md §1.3 describes: a signed message
lets its recipient prove the file came from the sender.

**A sealed message with an attachment hides only its text.** The
cleartext `attachment` beside the box shows the server the file's name,
size and hash, and the file is in the area in the clear. A client says
so before sending one, and may name the file blandly.

## 13. Privacy and logging

- **File names are not logged** at info level, nor hashes: a name in a
  private message is as private as its text. The `attachments` tracing
  category (`HXD_DEBUG=attachments`) logs, at debug, the id's first six
  characters, the size, the uploader's login and the context (a room id
  or `mail`), enough to follow an upload to its fetches in one log.
- **A refusal** is logged at debug with its real reason and the
  uploader's login, as a rejected image is (inline-media.md §10).
- **Bearer URLs** are never logged, as no token is (hotline-ng.md §9);
  the path is logged as `/files/…`.
- **The moderation trail** keeps, for a redaction or a purge that
  removed an attachment, its name, size and hash in the audit row. The
  name is evidence and is scrubbed with the rest at `[moderation]
  evidence_days` (moderation.md §3.1); the hash is kept.
- **Metrics**, behind the `metrics` feature, count attachments and
  bytes by context and never name one.
- **On disk** an attachment is a file in the area, in the clear, and is
  in its backups (operating.md, "Backups", the file area's row).

## 14. Configuration

```toml
[attachments]                 # presence turns them on; needs [files] root,
                              # and [history] or [inbox] to have anything to attach to
folder = "Attachments"        # at the area's root; not an upload folder or a drop box
max_bytes = 67108864          # one file; at most [files] max_file_size
pending_ttl = 3600            # seconds a staged upload waits to be attached
uploads_per_hour = 30         # per sender: an account, or a guest by its address
quota_bytes = 536870912       # staged and attached files one sender still has
max_total_bytes = 0           # every attachment on the server; 0 = no limit
```

Lines take attachments where `[history]` is configured, messages where
`[inbox]` is.

## 15. Staging

1. **A1, the domain and the store.** The attachment record and its
   schema in `hxd-store-sqlite`, beside the log and the inbox, with an
   in-memory store for the domain tests; staging, publishing, the
   mailbox folder records and their `claim`, `rotate` and `purge`;
   authorization; every removal of §6 and the sweep; the quotas.
2. **A2, the ng wire.** The capability and login block,
   `attachment_upload` over the upload route, `attachment_download`,
   the `chat` and `msg` params, the event, `history` and `inbox`
   fields, the errors, registered in `hotline-ng.md` §4, §7 and §10;
   `operating.md`'s `[attachments]`.
3. **A3, the classic wire.** The suffix, the listing and fetch rules by
   path, and the refusals inside the folder.
4. **A4, hx-ng.** Attach, show, download, verify, and an e2e case in
   `e2e/` once the pin advances (AGENTS.md, Testing).
5. **A5, signing.** When e2e-messages.md's signing is built: `file` in
   `hl-identity`'s message objects with vectors, the server's checks,
   the client's, and §11.5's edit to e2e-messages.md.

## 16. Test plan

In `crates/hxd/tests/attachments.rs`, against real servers on both
ports:

- an upload in pieces, a resume on a new session quoted by hash and
  digest, a guest's upload in one piece, and a `hash_mismatch`;
- a lobby line and a room line with an attachment: the ng object, the
  classic suffix, and the file fetched over HTTP with §7's headers and
  over HTXF;
- §5's table: a session not in the room refused as `not_found` and
  "File not found.", a history reader allowed, a guest without
  `download_files` refused, a listing showing each session only its
  own files and mailbox;
- a private message to an offline account, read the next day on
  another device, attachment and all; one to a guest `not_attachable`;
- retention, a redaction, a purge and a room deletion each removing
  the file, and a file deleted by hand reading gone on both wires;
- a file altered on disk with its size and time kept ending the
  download short;
- the quotas and the rate, each refused as §3 says;
- FilePut, New Folder, rename and move refused inside the folder, with
  `upload_anywhere`;
- a lobby line exporting its text alone across a link, and a message
  to a ghost `not_delivered`;
- with A5, a signed line and message whose `file` matches, one whose
  `file` differs refused `bad_signature`, and e2e-messages.md §13's
  new vectors in `hl-identity`.

## 17. Later

- **Sealed attachments**: a file encrypted to the recipient's device
  under a key carried inside the sealed message, so the server holds
  only ciphertext. It comes with sealed messages to devices, and
  offline mail (e2e-messages.md §10), since a file is read later.
- **Group cryptography for rooms**, without which a room's file cannot
  be sealed to its members.
- **At-rest encryption** against a stolen disk is a deployment matter,
  filesystem or volume encryption, and not this protocol's, as for the
  chat log (chat-history.md §4.3).

## 18. Open questions

- **Several files per line or message**, and whether a line can carry
  an image and a file together.
- **Classic senders.** A GtkHx extension could upload into staging and
  name the upload in 105 and 108 by a field; worth proposing upstream
  beside Inline Media?
- **History readers** (§5): is a logged room's record the right
  audience by default, or should it follow `[media] history_access`?
- **Blocking a removed file's hash** from coming back, as a revoked
  image's is (moderation.md §3.2). Cheap, since the hash is known
  before the first piece.
- **Content-addressed storage.** Two people attaching the same file
  store it twice; news stores a blob once (news.md §7.2). Worth it, at
  the cost of a refcount?
- **Telling a sender** that a signed lobby line with an attachment did
  not cross a link (§11.4).
- **A sealed message's attachment** kept until `retain_unread` (§4):
  long enough, or should it follow the session's grace?
