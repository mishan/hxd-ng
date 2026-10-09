# Files implementation plan

Status: first and second slices implemented, 2026-09-12, and file
management on the local area since. The first slice is read-only
manifest-backed HTTP; the second adds a capability-rooted local file area and
single-file uploads; the third, New Folder, Delete, rename, Move and
comments; Download Folder and Upload Folder since 2026-10 (F1 and F2 of
"Folder transfers"). This document is the execution plan and
acceptance contract for the Files work across hxd-ng and its clients. The
exploratory notes in
[`file-sources.md`](file-sources.md) remain useful design background; this
document fixes the first implementation boundary and its acceptance gates.

The external Large File reference is
[`Capabilities-Large-File.md`](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Large-File.md).
Where that document is draft or leaves behavior to the implementation, the
rules below and their wire tests become the local contract.

## Result we are targeting

The first Files release is read-only and serves a configured, manifest-backed
HTTP origin through both frontends:

- legacy Hotline clients browse folders, inspect entries, and download files
  over the normal FileList/FileGet/FileGetInfo and HTXF paths;
- capable legacy clients transfer files whose data or transfer size exceeds
  the 32-bit wire ceiling, including resume at a 64-bit offset;
- Hotline-ng clients use the same source through a typed JSON API and a
  short-lived, authorization-bound HTTP download token;
- ordinary files remain byte-compatible for clients that do not negotiate the
  Large File capability.

The first slice did not add uploads, mutations, folder-transfer transactions,
queueing, or a local-directory backend. The second slice adds only a local
source and FilePut; general mutations, folder transfers, and queueing remain
follow-on work and are not implied by the advertised behavior.

### Local writable slice

The local source opens its configured root once as a directory capability and
performs every later lookup relative to that authority. Protocol paths cannot
name absolute paths, traverse upward, follow symlinks, or reach `.hxd-state`
by any spelling a case-folding filesystem accepts. Uploads follow mhxd's
access rule: `upload_files` alone reaches folders whose path names an upload
folder or a drop box, and `upload_anywhere` reaches the rest. A drop box
lists, answers Get Info and downloads only for `view_drop_boxes`, as on mhxd,
and the path a client sends is checked before anything is looked up, so
asking for a name a drop box does not hold is refused the same way as one it
does. Uploads never overwrite a visible file and are
published atomically only after the exact body and FFO structure validate.

An account without `view_drop_boxes` learns nothing of what a drop box
holds, and that shapes its uploads in two ways mhxd does not. It may upload
into a drop box itself, which is what one is for, but not into a folder
inside one: that folder is not found, the same answer as a folder that is
not there, since it cannot target what it cannot see. (mhxd's
`rcv_file_put` never asks `check_dropbox`.) And its upload into a drop box
is blind: a name that is taken is neither refused, as mhxd refuses it, nor
replaced; the upload is published under the first free name, `name 2.txt`,
`name 3.txt` and on, the number before any extension, chosen under the tree
lock as it is published. It is never quoted a partial to resume, and its
partial is named afresh for each upload and discarded when the transfer
ends, so it can neither find nor disturb another's; every guest shares one
account, and a quote would tell one guest what another left half-sent. An
account that may view drop boxes uploads into them, and into folders inside
them, as anywhere else it may upload.

Incomplete uploads live under the mode-0700 `.hxd-state` directory. Their
opaque names bind the canonical account login to the destination path; limits
bound their global bytes and count, count per account, concurrent I/O, idle
time, total duration, and retention. An account at its count gives up its
least recently touched partial rather than being refused, a partial with
nothing in it goes when its transfer ends, and a partial expires as a whole.
Classic uploads preserve DATA, MACR, and CAP Finder metadata; the MACR fork is
optional, as the protocol's two-fork object and mhxd's client have it. Large File uploads are raw data and resume only after the server
recomputes the quoted partial length and SHA-256 trailing-window digest and
constant-time compares the client's echo. A client may turn the quote down by
sending the whole file without `HTXF_FLAG_RESUME`; that upload replaces the
partial. A request may leave the upload size out, as mhxd's own client always
does, and the server then caps the upload by any quoted offset plus the
length the handshake states.
HTTP and ng downloads remain read-only even when backed by this local area.

### File management

A local area can be changed as well as filled, on both wires: New Folder
(205), Delete (204), Set Info (207) for a rename and a comment, and Move
(208), and on the ng wire `files_mkdir`, `files_delete`, `files_move` and
`files_comment` (`hotline-ng.md` §7.2). A manifest area refuses them all
as read-only. mhxd is the reference for what each request carries, with
two deliberate differences:

- **Each kind of entry asks for its own bit.** mhxd admits an account
  holding either Delete bit, or either Move bit, and then acts on files
  and folders alike. Here a file asks `delete_files` and a folder
  `delete_folders`, and so on down the bitmap, and the kind is checked
  again under the tree lock, so a file swapped for a folder in between is
  refused rather than deleted under the file bit.
- **Make Alias (209) is refused.** An alias would be a symlink, and this
  area neither follows nor shows one.

As on mhxd, a path naming a drop box is out of reach without
`view_drop_boxes` for every one of these, as source or destination, and a
folder is deleted with everything in it. Set Info compares what it is
sent with what the connection was shown: a Get Info window sends back
both fields, and an unchanged one is not a change, so an account that
may rename but not comment can still rename from it. Nothing is ever
replaced: a new folder, a rename or a move onto a name that is taken is
refused, a move stays on its filesystem rather than copying, and a delete
does not reach into a filesystem mounted beneath its folder. Folders nest
only as deep as a delete or move will walk: New Folder refuses to go
past it, a move of a folder refuses any destination where it or anything
inside it would sit past it, in whichever direction it moves, and a
delete of a folder nested deeper behind the server's back, or holding a
mount, is refused after checking the whole tree and before removing any
of it. Every cheaper refusal comes before such a walk, so a request that
would be refused anyway does not pay for one.

That walk would otherwise tell an account without `view_drop_boxes`
something of what a drop box holds: which refusal a folder around one
earns, and at what destination depth, says how deep folders nest inside
it, or that a filesystem is mounted there. So for such an account a
move, rename or delete of a folder holding a drop box anywhere beneath
it is refused outright ("That folder holds a drop box.", `access_denied`
on the ng wire) the moment the walk reads the drop box's name, before
opening it; nothing inside can change the answer, and whatever the walk
answered before reaching it was about folders the account can list.
This is a deliberate difference from mhxd, which would move or delete
the folder, drop box and all: an account that may not see into a drop
box does not get to throw away what was sent to it either. An account
that may view drop boxes walks into one as into any other folder.

Each act is also refused before anything is looked up when the account
holds none of the bits it could need, as mhxd's `rcv.c` refuses it:
Delete without either delete bit, Move without either move bit, and Set
Info without any of the rename and comment bits. Otherwise "File not
found." against a refusal would say what exists, and a Set Info that
changes nothing would succeed for an account that may change nothing.

A comment is kept where an upload's is, in the CAP sidecar, so it is Mac
Roman there and at most 200 bytes, and a folder may have one too. Sidecars
are named by path, so a rename or a move carries the sidecars of
everything beneath it, and a delete removes them. A comment reads back
with LF line endings whichever wire wrote it. Every change and every
upload's publication take one lock on the tree, which makes checking that
a name is free and taking it one step; it is waited for before an I/O
permit is taken, so a long delete holds up other changes and not the
listings and downloads beside them.

## Repository and branch order

The work spans four repositories and is landed in dependency order:

1. `hx-libs`: add the shared, safe `hxfiles-xfer` codec and any missing
   `hxproto` Large File vocabulary. No GtkHx C ABI enters this repository.
2. GtkHx: consume the shared crates and move the current `hxfiles-xfer` FFI
   facade into `gtkhx-ffi`. Keep client workers and socket lifecycle in
   `hxnet`.
3. hxd-ng: advance the validated hx-libs pin, then add `hxd-core` file
   contracts, `hxd-files`, legacy dispatch, and the ng API.
4. hx-ng: add the typed client API and Files view after the ng wire shape is
   covered by the server.

Each repository uses a short topic branch with one squashed implementation
commit. The existing hx-ng `news-attachments` work is left untouched; the
client branch starts from its current mainline base.

## Shared-crate extraction

### `hxfiles-xfer` in hx-libs

Move the pure Rust parts of GtkHx's
`rust/crates/hxfiles-xfer` into hx-libs:

- FILP fixed and variable info-block encoding and parsing;
- DATA and MACR fork-header packing and 64-bit length reconstruction;
- HFS/header epoch conversion;
- HTXF preamble and flag parsing/building;
- checked range and transfer-size arithmetic;
- golden vectors for legacy and Large File forms.

The shared crate is `rlib`-only and has no glib, libc, raw pointers, C
symbols, or `gtkhx_` names. The generic FILP encoder currently embedded in
GtkHx `hxnet/src/xfer.rs` is moved here and parameterized by filename,
metadata, comment, fork lengths, resume offsets, and Large File mode.

GtkHx's `GtkhxFilpInfo`, `gtkhx_ffo_*` exports, ABI layout assertions, pointer
validation, and C-facing tests move to `gtkhx-ffi` as thin adapters over the
shared safe API.

### `hxhfs`

Do not make `hxhfs` a prerequisite for the HTTP-origin slice. When local
files and resource-fork sidecars enter scope, extract its native `hfs` API and
sidecar formats into hx-libs, while keeping the global configuration and C
ABI in GtkHx's FFI crate. Before that extraction, audit every on-disk length
represented as `u32`; the Large File wire capability must not inherit a
silent resource-fork truncation.

### `hxproto`

Extend the already shared control-plane crate with the complete Large File
field vocabulary and typed helpers, including 64-bit offset and folder-count
companions where required. Preserve the existing legacy builders and parsers;
new fields are additive and capability-gated.

## hxd-ng implementation

### Domain and source

Add wire-free, UTF-8 types to `hxd-core`:

- validated hierarchical `FilePath`;
- `FileEntry` and `FileInfo` with `u64` sizes and counts;
- a body type exposing a known total length and an async byte stream;
- an object-safe async `FileSource` trait for list, info, and ranged open.

Add `hxd-files` for the manifest cache, configured HTTP origin, redirect and
path validation, range streaming, transfer references, concurrency limits,
timeouts, and FILP/HTXF encoding. The origin is configuration-only: neither a
client path nor a manifest entry may supply an arbitrary host or URL.

### Legacy frontend

- Advertise and echo Large File capability only when the Files service is
  configured and operational.
- Without negotiation, omit entries whose true size cannot be represented by
  the legacy field; reject guessed direct requests rather than wrapping.
- With negotiation, emit the legacy value clamped to `0xffffffff` immediately
  followed by its exact 64-bit companion.
- Apply the same pairing to FileList, FileGetInfo, and FileGet replies.
- Bind every HTXF reference to the issuing `(uid, serial)`, path, prepared
  range, and expiry, and, for a direct control connection, to its address.
  A reference is spent by any presentation of it.
- Validate 16-byte legacy and extended HTXF handshakes before consuming any
  optional 64-bit field. Reject unauthorized flags. A download's declared
  length is not consulted: the protocol has the client send 0 there, and
  mhxd's own client echoes the transfer size instead.
- Encode FILP with the real variable-length filename/comment area, the DATA
  fork, and the trailing zero-length MACR marker.
- Parse 32-bit RFLT resumes for old clients and negotiated 64-bit offsets for
  positions beyond the legacy ceiling.
- Keep the legacy Mac Roman conversion and path/name rules at the
  `hxd-session` edge.

### Hotline-ng frontend

Expose folder listing, info, and download preparation through the ng protocol.
Represent sizes, offsets, and counts as decimal strings on the JSON wire so
the browser never rounds a full `u64`; hx-ng converts them to `bigint` for
arithmetic and display. Downloads are proxied through hxd-ng using short-lived
tokens rather than exposing the configured origin.

## hx-ng implementation

In `packages/hotline-ng`:

- add typed file request/response messages and decimal-`u64` helpers;
- add download-token handling with HTTP range and cancellation support;
- keep all library code DOM-free and runtime-dependency-free;
- add reconnect/error handling that does not silently retry an expired or
  authorization-bound token.

In `src/`:

- add a Files route and folder navigation;
- render exact sizes using `bigint` formatting;
- show metadata and download progress without assuming a 32-bit size;
- keep the UI usable when the server has Files disabled.

## Acceptance gates

The work is complete only when all of these are true:

- `hx-libs` pure-code tests cover legacy and Large File wire vectors, and its
  shared crates export no GtkHx FFI symbols;
- GtkHx builds and its C ABI tests pass through `gtkhx-ffi`;
- hxd-ng tests prove ordinary legacy behavior is unchanged;
- non-capable legacy clients cannot discover or fetch oversized entries;
- capable clients receive correctly paired fields, extended HTXF framing,
  high/low fork lengths, and 64-bit resume behavior;
- ng and legacy clients can fetch the same origin object through their
  respective APIs;
- malformed ranges, stale references, redirects, origin length changes, and
  authorization mismatches fail closed;
- sparse or synthetic fixtures exercise offsets beyond 4 GiB without moving
  multi-gigabyte payloads in CI;
- the full hxd-ng Rust gates, hx-ng type/package/build gates, and the real
  cross-frontend e2e suite pass.

## Folder transfers

Download Folder (210) and Upload Folder (213) on the classic wire, as mhxd
and GtkHx run them and Hotline.md and Capabilities-Large-File describe
them; the item header and actions are `hxfiles_xfer::folder`.

- **F1, Download Folder (built).** Needs `download_folders`. The folder is
  walked when 210 arrives, depth first, each folder before what it holds,
  in wire-name order, showing what a listing would: the names this
  connection is listed, without what a listing leaves out, and a drop
  box the account may not view sent as an empty folder (nor a file whose
  name reads as one, which FileGet would refuse it). Past `[files]
  max_folder_items` (default 100000) it is refused, and a session has one
  folder waiting to be fetched at a time, since its items are held until
  then. The reply carries the reference, the size
  the files' objects come to, and the item count, files and folders alike
  (mhxd counts the top level only, which disagrees with what it sends),
  with `XFERSIZE64` and `FOLDER_ITEM_COUNT64` in large-file mode. On the
  transfer port the client speaks first: NEXT for each item's header,
  then SEND or RESUME (an RFLT behind its length, read as `rflt`'s
  compatible parser reads one) for a file's object behind its 4-byte size,
  which is 0 past 32 bits, once per NEXT; NEXT past the last item and the
  server closes. A resume this area cannot make, or one past a fork's
  end, ends the transfer.
  The handshake's type is not read, since GtkHx's own test names 0. Sizes
  come from the walk, so a file that changed since ends the transfer at
  that item rather than send what was not announced. Names cross in the
  connection's encoding, where mhxd sends raw bytes.
- **F2, Upload Folder (built).** Needs `upload_folders`, where FilePut
  would take a file. The server drives: NEXT, the client's item header,
  SEND or RESUME for a file (GtkHx treats NEXT there as a protocol error),
  its object behind its size; the client's close between items ends it,
  and so does `max_folder_items`. The top folder is made when the
  transfer starts; each item is checked and published through the
  single-file upload path, its quotas included, as a classic object (the
  handshake may set no flags). A folder that already exists is refused
  unless the request sets the resume option (204), when the upload merges
  into it: a file already there is answered RESUME from its end, so the
  client sends its headers alone and what is there is kept (a longer
  copy's tail is read and dropped; GtkHx fails on its own side for a
  shorter one), and the rest is sent whole, an interrupted one included.
  Adding to a folder never reaches into a drop box the account may not
  view. Into one, the top folder is made blind, under a free name, as
  single files are published, and so is a folder named like one. Each
  file is held to `upload_timeout` as one uploaded alone is. An upload
  that fails partway keeps what arrived and its folder, as mhxd's does,
  so finishing it takes the resume option.
- **F3, the queue and limits.** Concurrent transfers per account,
  configurable, defaulting to mhxd's one download and one upload; queue
  positions in the replies and the Download Info (211) push; Kill Download
  (214) ending the transfer it names, though GtkHx never sends it.
- **Folder budget and depth (built).** Folders an account makes, by New
  Folder on either wire or in a folder upload, are held to `[limits]
  folders` in `folder_seconds` (500, then one each ten seconds), keyed
  as news posts are, so repeated uploads are bounded and not only one;
  `can_spam` exempts. Charging them spam points instead would have an
  ordinary upload of a few hundred folders kicked. A folder upload past
  it ends, keeping what arrived. `[files] max_depth` (32, mhxd's cap on a
  DIR path, and at most 64, the depth a delete or move walks) bounds
  where a folder is made or moved to; a tree made on disk is not held
  to it.

## Deferred work

The following remain separate milestones:

- the transfer queue and per-account limits (F3 above);
- per-account quotas and background origin prefetching;
- direct origin URLs in the ng client.
