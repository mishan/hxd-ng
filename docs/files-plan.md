# Files implementation plan

Status: first and second slices implemented, 2026-09-12. The first slice is
read-only manifest-backed HTTP; the second adds a capability-rooted local file
area and single-file uploads. This document is the execution plan and
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
name absolute paths, traverse upward, follow symlinks, or reach `.hxd-state`.
Uploads require both legacy upload access bits, never overwrite a visible file,
and are published atomically only after the exact declared body and FFO
structure validate.

Incomplete uploads live under the mode-0700 `.hxd-state` directory. Their
opaque names bind the canonical account login to the destination path; limits
bound their global bytes and count, count per account, concurrent I/O, idle
time, total duration, and retention. Classic uploads preserve DATA, MACR, and CAP Finder
metadata. Large File uploads are raw data and resume only after the server
recomputes the quoted partial length and SHA-256 trailing-window digest and
constant-time compares the client's echo. HTTP and ng downloads remain
read-only even when backed by this local area.

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
  range, and expiry.
- Validate 16-byte legacy and extended HTXF handshakes before consuming any
  optional 64-bit field. Reject unauthorized flags and mismatched declared
  lengths.
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

## Deferred work

The following remain separate milestones:

- folder get/put transactions and their 64-bit aggregate counts;
- move, rename, delete, mkdir, comments, and drop-box semantics;
- transfer queueing, per-account quotas, and background origin prefetching;
- direct origin URLs in the ng client.
