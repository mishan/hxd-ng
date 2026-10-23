# Uploads on the Hotline-ng wire

Status: U1 (hxd-ng) and U2 (hx-ng) built. §8 stages it.

The ng wire browses, downloads and previews files and changes the area
(`hotline-ng.md` §7.2), but has no way to put a file there: a phone or
a browser can take a file from a server and cannot give one. This adds
`files_upload`. It is the classic FilePut's rules, which the local area
already enforces, carried over HTTP in pieces so that an upload outlives
the dropped connections the ng wire was designed around.

**Decisions (2026-10):**

- **The rules are FilePut's.** Who may upload where, drop boxes and the
  blind upload, never overwriting, the partials and their quotas, and
  publishing only once the whole file has arrived: one implementation
  (`hxd-files`), two wires. Nothing here is a second policy.
- **Bytes travel over HTTP, never the WebSocket.** The socket carries
  messages of 256 KiB and everyone's chat; a file is neither. The
  request reserves the upload and answers a URL; the bytes go there.
- **An upload is sent in pieces and resumes at the server's offset.** A
  piece is one HTTP request; a dropped connection costs at most one
  piece, and a client that comes back asks where to carry on.
- **An ng upload is a data fork.** There is no resource fork, type or
  creator to send; the area infers a type as it does for any file
  without Finder info.

## 1. The request

```jsonc
→ { "req": "files_upload", "params": { "path": "Uploads/photo.jpg", "size": "48127330", "comment": "" } }
← { "ok": { "url": "/files/upload/<token>", "offset": "0", "piece": "8388608" } }
```

- `path` names the file to make; its folder must exist. `size` is the
  whole file's length in bytes, a decimal u64 as everywhere in §7.2.
  `comment` is optional, as `files_comment` takes one.
- `offset` is where the client starts: `"0"` for a new upload, or the
  length of this account's partial for this path when it left one
  (§3). `piece` is the most one request may carry; the client may send
  less.
- Refusals are FilePut's, in §7.2's codes: `access_denied` (the bits,
  or a drop box path for an account that may not view one, refused
  before any lookup), `already_exists` (never for a blind upload, §4),
  `too_large` (past `max_file_size`), `busy` (the partials' quotas or
  the account's transfers), `not_folder`, `bad_request`.
- It needs `upload_files` for a folder whose path names an upload
  folder or a drop box (`FilePath::is_upload_folder`) and
  `upload_anywhere` elsewhere, exactly as FilePut does. `files_list`
  gains `uploadable: bool` for the folder it lists, so a client offers
  Upload where it would be allowed without reimplementing the rule.

## 2. The pieces

```
PUT /files/upload/<token>
Content-Range: bytes 0-8388607/48127330
<bytes>
```

- The range must start at the partial's current length and its total
  must be the request's `size`; anything else is `409 Conflict` with
  the current offset in `Upload-Offset`, so a client that lost track
  asks the server rather than guessing. A piece longer than `piece` is
  `413`.
- A piece that is not the last answers `204` with `Upload-Offset`. The
  last one is checked (the length is `size`), published as FilePut
  publishes, and answers `201` with `{ "path": "…" }`, the path it was
  published at, which a blind upload may have numbered (§4).
- A piece is written to the partial as it arrives, under the area's I/O
  permits, and holds one of the account's transfer places
  (`TransferLimits`) while it does, as a classic upload holds one for
  its whole transfer. `upload_timeout` bounds one piece, not the
  upload; `partial_ttl` bounds the upload.
- The route is the same origin and CORS as `/files/<token>`, with
  `PUT` and the two headers allowed and `Upload-Offset` exposed.

## 3. Resuming

- The token is bound to the session (`(uid, serial)`) like a download's,
  and lasts `download_ttl` from issue and then from each piece, as a
  video preview's does, so a pause between pieces does not cost it. A
  resumed ng session is the same session and keeps it.
- A client whose token has gone (its session ended, or it waited too
  long) asks `files_upload` again with the same `path` and `size`, and
  is quoted its partial's length: partials are keyed by the account's
  login and the path, as classic ones are, and outlive the session.
- Before the client sends from a quoted offset it checks that the
  partial is the start of its own file, the way Large File resume does:
  the quote carries `digest`, the SHA-256 trailing-window digest of the
  partial (`hxfiles_xfer::resume_digest`, a 64 KiB window), which the
  client compares with the same digest of its own file at that offset.
  It echoes the digest in the first piece's `Upload-Digest`, and the
  server refuses a piece that does not with `409`, so a client cannot
  carry on without having been told what it would be carrying on from.
  The check is the client's: the server holds no copy of the client's
  file, so the echo binds the piece to the quote, not to the bytes. A
  client whose file is not the partial's starts over with
  `"fresh": true`, which discards the partial; one that cannot compute
  the digest sends `fresh: true` and loses only the resume.
- The partial does not record the size it was begun with, so a client
  asking with another size is quoted the partial all the same, unless
  it is longer than the new size; the digest is what tells a client
  whether the partial is its file.

## 4. Drop boxes

As FilePut: an account without `view_drop_boxes` may upload into a drop
box but not into a folder inside one, and its upload is blind. A blind
upload is never refused for a taken name; it is published under the
first free one (`name 2.txt`). It is never quoted a partial (`offset`
is always `"0"`), and it is sent in one piece (`piece` is its size):
its partial lasts only while the request writing it does, as a classic
blind upload's lasts only while its transfer does, so one guest can
neither find nor finish another's, and a dropped connection starts it
over.

## 5. What it costs

- `files_upload` spends FilePut's 3 spam points (mhxd's table, as the
  file-area changes spend theirs) and is a write on the ng request
  limit. A piece spends neither: it is one upload's bytes, as a classic
  upload's transfer connection is.
- Bytes are bounded by what already bounds classic uploads: the
  partials' global bytes and count and their count per account,
  `max_file_size`, the I/O permits, and the account's transfer places.
  An ng upload adds no new pool.
- The connection limits of the ng port (`HttpLimits`) hold each piece's
  request like any other.

## 6. What the other wire sees

A published file is a file: a classic client lists and downloads it as
it would one a classic client uploaded, typed by its extension. A
classic upload and an ng upload of one path by one account share the
partial, so either may finish what the other began, which is how the
area is already keyed.

## 7. Not in this design

- **Folder uploads.** A client makes the folders (`files_mkdir`) and
  uploads the files one by one; a browser's folder picker gives the
  relative paths to do it with. A folder transaction can follow if one
  file at a time proves slow.
- **Resume across a page reload.** The server keeps the partial; a
  client that wants to resume after a reload must keep the file handle,
  which browsers allow only through the File System Access API. hx-ng
  resumes within a page's life (§8, U2).
- **Overwriting.** Neither wire replaces a file; delete it first.
- **Uploading to a manifest (HTTP) area.** It is read-only, as it is to
  classic clients.

## 8. Staging

- **U1 (hxd-ng).** `files_upload`, `files_list`'s `uploadable`, the
  `/files/upload/<token>` route over `hxd-files`'s partials and publish,
  the login block's `may` listing `upload_files` and `upload_anywhere`,
  the spec in `hotline-ng.md` §7.2, and an e2e: pieces, a resume on a
  new session with the digest, a mismatch starting over, a blind upload
  numbered, and each refusal on this wire as FilePut refuses it.
- **U2 (hx-ng).** An Upload button and a drop target where `uploadable`,
  pieces with progress and Cancel, a resume after a reconnect, and a
  Playwright spec against a real server.
