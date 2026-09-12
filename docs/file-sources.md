# File sources: serving a remote origin over HTXF

Status: superseded by [`files-plan.md`](files-plan.md) for the first slice; kept as exploratory background (ROADMAP Phase 3 says the same).

Nothing here is built yet — the
file area is ROADMAP.md Phase 3 and `hxd-session` dispatches no opcode in
the `0x00c8`–`0x00d5` range today.

The execution scope and acceptance gates are now maintained in
[`files-plan.md`](files-plan.md); this document remains the lower-level
exploration that informed that plan.

## Summary

The file area is defined behind a **`FileSource` trait** rather than as a
directory walker, and the first implementation reads from an **HTTP
origin** rather than local disk. A legacy 1.2/1.5 client browses and
downloads over the wire it has always spoken; the bytes come from a URL
the client never sees.

Two things motivate taking the remote backend first, before the local one:

- **The ng frontend wants files-as-URLs anyway.** With an HTTP-backed
  source, `hxd-ng-session` can hand out an origin URL directly and HTXF
  becomes the only shim in the system. The two frontends come out
  symmetric instead of the legacy one being privileged, which is the same
  argument that made `hxd-core` wire-free.
- **It is the honest hard case.** A local directory has free metadata,
  free seeks and no failure between `open` and `read`. An origin has none
  of those. A trait designed against the hard case admits the easy one;
  the reverse is how you end up with a trait shaped like `std::fs`.

## What does not change

- **The legacy client sees nothing new.** Same opcodes, same FILP frame,
  same subchannel port. The compatibility constraint in ROADMAP.md is
  untouched: an HTTP-backed file area that a 1.5 client can tell apart
  from a disk-backed one is a bug.
- **`hxd-core` stays wire-free and UTF-8.** `FileSource` speaks paths and
  entries, never chunks, never Mac Roman. The 4CC synthesis, the Mac
  Roman round-trip and the 31-byte name truncation all happen at
  `hxd-session`'s edge, after conversion, exactly as nicks do today.
- **No client-supplied URLs, ever.** See [Security](#security).

## The two wire shapes

A download is two connections, and the server must produce both.

### Control channel (:5500)

`FileGet` (`0x00ca`) carries `FILE_NAME` (`0x00c9`), `DIR` (`0x00ca`) and
optionally `RFLT` (`0x00cb`). The reply carries `HTXF_REF` (`0x006b`) and
`HTXF_SIZE` (`0x006c`). The client requires a non-zero ref — see
`hx_htxf_reply_extract` in `gtkhx/src/proto_helpers.c:325` — and uses the
size only to drive the progress bar.

Browsing needs `FileList` (`0x00c8`), whose entries carry a 4-byte type,
a 4-byte creator and **a size per entry**, and `FileGetInfo` (`0x00ce`)
for the info dialog. The per-entry size is the whole metadata problem in
one field; see below.

### HTXF subchannel (:5501)

The client opens a fresh TCP connection and sends 16 bytes — `'HTXF'`,
ref, len, type (`gtkhx/src/hotline.h:25`, and the transfer-type note at
`:183`, where the wire field is advisory for mhxd because the ref already
resolves a pre-created transfer). The server answers with a flattened
file object:

```
40 bytes   FILP fixed header
N bytes    info block; N = (hdr[38] ? 0x100 : 0) + hdr[39], then +16
16 bytes   DATA fork header (length in the low-32 slot at offset 12)
data       the file
16 bytes   MACR fork header, length 0
```

**The encode already exists in Rust.** `gtkhx/rust/crates/hxnet/src/xfer.rs:476`
has a byte-for-byte `FILP_TEMPLATE` (115 bytes) plus the patch list, and
`hxfiles-xfer`'s `ffo` module has the fork-header pack and the HFS epoch
math. That is the client's *upload* path, but a server download writes
the identical frame, so the server side is a port of `file_send_one`
minus the local filesystem, not a fresh interpretation of the format.
Neither crate is currently a dependency — the workspace consumes
`hxproto` from hx-libs (`Cargo.toml:29`), which has no htxf/ffo module —
so this is either ~200 lines carried over or the `hotline-htxf` promotion
ROADMAP.md:92 already contemplates.

Three details a server gets wrong that a client never hits:

- **The name field is variable and the comment offset follows it.** The
  template hardcodes a 3-byte name (`"hxd"`, a placeholder the receiving
  server ignores because `FILE_PUT` already told it the destination
  name). A server writing the real filename must widen the field *and*
  recompute the length at `hdr[38..40]`: it is `74 + namelen + comlen`,
  not the client's constant-folded `77 + comlen`. The client's parser
  reads the comment at `73 + info[71]`
  (`gtkhx/rust/crates/hxfiles-xfer/src/ffo.rs:129`), i.e. it derives the
  offset from the low byte of the name length, so a correct widening
  round-trips and an incorrect one desyncs into garbage.
- **`HTXF_SIZE` is the whole frame, not the file.** `133 + comlen +
  data_len + 16 + rsrc_len`, per the budget at `xfer.rs:997` that the
  folder stream requires be exact.
- **Emit the trailing zero-length MACR marker.** The client tolerates its
  absence but pays `MACR_DRAIN_TIMEOUT_MS` (`xfer.rs:273`) waiting for
  it — a visible end-of-transfer stall on every file.

Downloads always carry the FILP wrapper. The raw-bytes bypass in
`hxnet_xfer_file_send_one` is upload-only, and exists because the
receiving server reconstructs metadata from its own filesystem.

## The trait

```rust
// hxd-core: wire-free, UTF-8, no chunks and no Mac Roman.
trait FileSource {
    async fn list(&self, path: &FilePath) -> Result<Vec<Entry>>;
    async fn info(&self, path: &FilePath) -> Result<Info>;
    async fn open(&self, path: &FilePath, from: u64) -> Result<Body>;
    fn url(&self, path: &FilePath) -> Option<Url>;   // ng hands this out directly
}
```

`Body` yields a **known total length** plus an `AsyncRead`. The length is
not optional, because the DATA fork header is written before the first
data byte and cannot be revised — see below.

`from` rather than a range: HTXF resume is always a suffix.

`url()` returning `Option` is what keeps the trait honest for a local
directory (`None`) while letting the ng frontend skip the proxy entirely
for an origin-backed one.

## The metadata problem

Everything hard about an HTTP backend reduces to one property: **the
length must be known before the first byte goes out**, for both
`HTXF_SIZE` and the DATA fork header, and a listing needs it for every
entry at once. There is no chunked mode and no revision.

That makes the origin's enumeration story the dominant design input, and
the three plausible shapes differ by an order of magnitude:

| Origin | Enumeration | Sizes | Ranges |
|---|---|---|---|
| Manifest / JSON index (archive.org item metadata, a generated `index.json`, S3 `ListObjectsV2`) | one request | free | usually |
| Static file server with autoindex | scrape HTML | `HEAD` per entry — O(n) round trips per folder open | usually |
| Dynamic endpoint | none | none — `Content-Length` may be absent entirely | rarely |

The first is the design target. The second is servable with an entry
cache and a concurrency cap, at the cost of a slow first open. The third
is not servable without buffering the whole object first, which defeats
the point; a source that cannot answer `info` should refuse the listing
rather than lie about a size and truncate mid-transfer.

So: **`FileSource` is written against the manifest shape, and the trait
is allowed to fail `list`.** A backend that must `HEAD` its way to a
listing implements that as its own caching problem, not as a weaker
trait contract everyone else pays for.

## Resume and failure

Mid-stream failure is unrecoverable by construction. The fork length is
already committed, so an origin that 500s at 40% leaves exactly one
option: close the socket. The client sees a truncated transfer.

That makes resume load-bearing rather than a nicety. `RFLT` carries a
DATA offset, which becomes `Range: bytes=N-` upstream. Two consequences:

- **Probe `Accept-Ranges` and record it per origin.** Without ranges,
  resume degrades to fetch-and-discard-N (defensible for small N,
  absurd for large) or an honest refusal.
- **Accept sloppy RFLTs.** ROADMAP.md:279 is explicit, and the reason is
  in the mirror project: gtkhx shipped a malformed-RFLT bug for years.
  Send well-formed ones, parse forgiving ones.

Serve a `206` where a `200` was expected as a hard error, not as a
restart from zero — silently rewinding a resumed transfer corrupts the
client's file.

## Names and paths

A URL is UTF-8 and long; a wire name is Mac Roman and effectively capped
at 31 bytes for the clients that matter. The map is lossy in both
directions, and the client hands the **name** back on `FileGet` — so
this is a registry problem, not a formatting one:

- Two distinct origin paths can collapse to one legacy name. Collisions
  must be resolved deterministically and stably (the same URL gets the
  same name across restarts), or a client's resume and its file list
  disagree after a restart.
- `:` is the classic path separator and `/` is the modern one; both need
  escaping in a component, in both directions.
- `DIR` chunks are a component sequence, and the reverse map must reject
  anything that escapes the configured root before it becomes a URL.

## Mac metadata

Type and creator are synthesized from extension or MIME (`.txt` →
`TEXT`/`ttxt`, `.jpg` → `JPEG`, `.sit` → `SIT!`), with a
`????`/`????` fallback. `MACR` is always zero-length: an HTTP origin has
no resource fork. This is cosmetic for the transfer and load-bearing for
the user — a downloaded archive with the wrong creator does not open on
the Mac that asked for it.

The Finder comment is free space. Putting the source URL there is a
one-line feature and makes the proxy self-documenting from a 1996
client.

## Security

A Hotline server that fetches URLs is an SSRF pump unless the mapping is
airtight:

- **The origin base is config, never derived from client input.** The
  client names a path inside a configured root; it never names a host.
- **Redirects are re-validated against the allowlist**, or not followed.
- **Cap sizes and per-origin concurrency**, and give the ref table a TTL
  and a binding to the issuing session. mhxd pre-creates the transfer and
  treats the subchannel's type field as advisory; do the same, and treat
  an unknown or expired ref as a close.

## Where the code goes

- `hxd-core`: the `FileSource` trait, `FilePath`, `Entry`, `Info`. No
  wire types.
- `hxd-files` (new, already sketched at ROADMAP.md:217): the FILP
  encoder, the HTXF listener on `bind.port + 1`, the ref registry, the
  transfer workers. Backends `LocalDir` and `HttpOrigin` live here or
  beside it.
- `hxd-session`: the file opcodes, Mac Roman conversion, path mapping,
  4CC synthesis — all at the edge, per the standing invariant.
- `hxd`: config (`[files]` with the origin base), wiring, the second
  listener.

An HTTP client is a new dependency; `hyper` 1 is already in the tree on
the server side (`crates/hxd-ng-session/Cargo.toml`), so `hyper-util`'s
client plus rustls is the smaller addition over pulling in `reqwest`.

## Deferred

Folder downloads (`FileGetFolder`, `0x00d2`) need recursive enumeration
and the `FILE_NEXT`/`FILE_SEND` framing, and are worth having precisely
because Janus gets the trailing-marker handling wrong today
(ROADMAP.md:282). Uploads to an origin (presigned `PUT`, WebDAV) mean
the FILP *receive* path and drop-box semantics. `HTXF_FLAG_LARGE_FILE`
and the high-32 fork slot matter because origins routinely hold objects
a 1.2 client cannot represent; refuse them explicitly rather than
truncating. Transfer queueing and per-account limits are Phase 3
regardless of backend.

## Open questions

1. **Which origin shape first.** Undecided; the trait is written to
   tolerate all three, and the first backend picks itself once there is
   a concrete archive to serve.
2. **Cache or not.** A read-through disk cache turns the O(n) `HEAD`
   listing and the no-ranges resume from blockers into slow paths. It
   also reintroduces the local filesystem this design was avoiding.
3. **Whether the local backend is ever written**, or whether a local
   directory is just an origin served by a static file server on
   localhost. The second is tempting and probably wrong: it puts a
   socket in the path of the one case that does not need one.

## Validating it

gtkhx is the client, and the harness exists: `tests/integration/test_file_get.c`,
`test_real_htxf_connect.c` and the server matrix in that tree. A spike
that serves one hardcoded URL to a real client — FILP encode, one ref,
no listing — de-risks the frame shape before any of the above gets
built, and is the recommended first move.
