# Inline media: images in chat, on both wires

ROADMAP Phase 6 item 3 files inline media under "mostly relay +
capability bits". The relay half is; the other half is a server-side
image pipeline that decodes hostile bytes and re-encodes them, which is
the part fogWraith's
[Capabilities-Inline-Media.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Inline-Media.md)
(read at `main` on 2026-09-08) spends most of its words on, and rightly.
This document designs both for the legacy wire and for Hotline-ng, from
one media store, and says how an image survives the two places a
message can outlive its moment: the private-message inbox and the chat
log of [chat-history.md](chat-history.md).

**Decisions (2026-09):**

- **The pipeline is its own crate**, `hxd-media`, behind a `MediaCodec`
  trait in `hxd-core` and a `media` Cargo feature, so the domain never
  links an image decoder and a server that wants none builds without
  one — the voice and inbox shape.
- **Canonical bytes live in memory**, bounded by a total cap with
  oldest-first eviction, for the spec's 24-hour handle lifetime. Nothing
  touches disk, so there is nothing to scrub and nothing a restart
  leaves behind; the spec already tells clients not to count on a
  handle across sessions.
- **Authorization is captured at relay time in the domain**, as
  principals rather than uids: a session for chat fan-out, a mailbox
  for a private message, so a queued PM's image is still fetchable by
  the account that eventually reads it.
- **On the ng wire the bytes go over HTTP**, not inside WebSocket JSON:
  `POST /media` and `GET /media/{handle}` with the session token as a
  bearer credential. A browser wants `fetch` and a blob URL; base64 in
  a JSON frame is the wrong shape for a 200 KB image.
- **The media gateway is not implemented.** The spec requires it off by
  default; a legacy recipient sees the text the sender typed.

---

## 1. What the spec asks

The shape, in one paragraph. A capable client uploads bytes with
`TranUploadMedia (750)` and gets an opaque handle; it references the
handle from an ordinary chat send (105) or private message (108) with
two companion fields, `DATA_CHAT_MEDIA_ID` (`0x0202`) and
`DATA_CHAT_MEDIA_TYPE` (`0x0201`); the server relays those plus its own
width, height and byte size (`0x0205`–`0x0207`) to capable recipients
and strips all of it for the rest; a recipient fetches the bytes with
`TranDownloadMedia (751)`. Field ids `0x0201`–`0x021F` are the
extension's; advisory limits `0x020C`–`0x0211` ride the LOGIN reply
beside the echoed bit 3; `0x0212` is an optional coarse error code.

What the server owes, as the spec's own summary lists it: validate,
canonicalise and re-encode every upload before anyone sees it; strip
every byte of metadata; issue handles with 128 bits of entropy;
authorise every download against a set fixed at relay time; never relay
original bytes; never distinguish "expired" from "unauthorised"; never
gateway a private context; default the gateway and the send permission
off; drop media fields from senders and recipients that did not
negotiate the bit.

The formats are JPEG, PNG and GIF (static and animated), and only
those. SVG, WebP, AVIF, HEIC, TIFF and ICO are forbidden by name.

## 2. Where each piece lives

```
  hxd-media        MediaCodec: sniff, walk to the format's end, probe the
  (feature)        header, bounded decode, EXIF orientation, re-encode.
                   Knows nothing about Hotline.
        ▲
        │ trait
  hxd-core         MediaStore: handles, canonical bytes, authorisation
                   sets, upload sessions, quotas, expiry. The chat and
                   message paths attach a MediaRef to their events.
        ▲
   ┌────┴────────────────────┐
  hxd-session            hxd-ng-session
  750 / 751, LOGIN       POST /media, GET /media/{h}, chat/msg params,
  advert, chat/msg       login-reply block, event fields
  fields and stripping
```

`hxd-core` gains `media.rs`: the store, the principal type, the limits
struct, a `MediaRef` carried on events, and the `MediaCodec` trait it
calls but does not implement. `hxd-media` implements the trait on the
[`image`](https://crates.io/crates/image) crate — `png`, `zune-jpeg` and
`gif` underneath, the same decoders GtkHx's non-Linux path uses — plus
three small hand-written format walkers the crate does not provide
(§3.2). A server built without the feature has no `[media]` section and
never confirms bit 3.

## 3. The pipeline

The spec's ten steps, in its order, with what each one is here.

### 3.1 Before the bytes: permission and quota

1. **Bit 57.** `bit::SEND_MEDIA` joins `access.rs` at fogWraith's
   allocation (`AccessSendMedia`, the bit after `CHAT_HISTORY`), with
   `send_media` as its `[access]` key. Absent from an account file it is
   **off** — the spec says operators grant it explicitly, and the
   bootstrap guest does not get it. A session without it is refused at
   the first chunk with code 4.
2. **Quotas.** Per account: one upload per 10 s, 30 per hour, two
   concurrent upload sessions. Per address: 100 per hour. Downloads: 60
   per minute per session. All keyed as the spec keys them, which means
   every guest shares the `guest` account's bucket — deliberate; the
   shared door is the one that needs the throttle most. Refused with
   code 3, or 5 for the concurrent-session cap.

### 3.2 The bytes

3. **Size.** Assembled payload between 64 bytes and `max_bytes`
   (default 256 KiB). Code 1.
4. **Sniff.** The leading bytes must be one of exactly three
   signatures: `FF D8 FF`, `89 50 4E 47 0D 0A 1A 0A`, `GIF87a` /
   `GIF89a`. The declared type is never consulted here; it is a hint
   the client offered and the reply overwrites. Code 2.
5. **Walk to the end.** A format-specific walker follows the container
   structure — JPEG segments to `FF D9`, PNG chunks to `IEND`, GIF
   blocks to the `3B` trailer — and the walk must land **exactly** on
   the end of the payload. Any trailing byte is a reject, with no
   allowance for padding: the check exists to refuse polyglots, and a
   client that appends anything to a file it is about to upload has a
   bug this server should not paper over. The walkers are the one
   piece of parsing the `image` crate does not do, about a hundred
   lines each, and they are also the first line against a decoder
   being handed something structurally strange. Code 2.
6. **Probe.** The header alone, through `image`'s `ImageReader::into_dimensions`
   with `Limits` set: either dimension outside `1..=max_dimension`
   (default 2048) or the product over `max_pixels` (default 2048²) is
   refused before a pixel is allocated. Code 1.
7. **Bounded decode.** The full decode under `image::Limits` with
   `max_alloc` at 64 MiB, on a `spawn_blocking` thread, with the
   awaiting side holding a 2-second timeout. A Rust decoder cannot be
   killed from outside, so the time budget is honest only because the
   dimension and allocation caps above bound the work first — the
   timeout is the backstop for a pathological-but-legal file, and a
   decode that outlives it is abandoned to finish on its thread while
   the client is told code 5. A semaphore of `max_concurrent_decodes`
   (default 2) bounds how many such threads exist at once; a request
   that cannot take a permit within the budget is code 5 as well.
8. **Animation.** For a GIF, frames are collected with a running count
   and a running sum of delays; over `max_frames` (default 150) or
   `max_duration_ms` (default 15 000) stops the collection and refuses
   with code 1. Decoded frame bytes count against the same allocation
   budget as a still.

### 3.3 The re-encode, and one deliberate departure

9. **Re-encode.** The spec *recommends* PNG for images with an alpha
   channel and JPEG otherwise, GIF preserved for animated GIF. This
   server's rule is **format follows source**: JPEG in, JPEG out
   (quality 85, baseline); PNG in, PNG out; animated GIF in, GIF out;
   static GIF in, PNG out. The reason is what the recommendation does
   to a screenshot: an opaque PNG of text re-encoded as JPEG is visibly
   worse and slightly larger, and nobody sent a lossless image hoping
   for ringing around the letters. Nothing in the security argument
   depends on the choice — a re-encode by a known-good encoder is the
   property, and both rules have it — and the spec's word is
   "recommended". A static GIF becomes PNG because there is no reason
   to keep a palette format for a still, and PNG is lossless over it.

   EXIF orientation is applied to the pixel buffer first
   (`ImageDecoder::orientation` and `DynamicImage::apply_orientation`),
   so the canonical bytes are upright and carry no orientation tag. The
   encoders write no ancillary data: no EXIF, ICC, XMP, PNG text
   chunks, or GIF comment blocks — stripping is by construction, not by
   a filter that could miss a chunk type. A test in `hxd-media` walks
   every canonical output with the §3.2 walkers and asserts that only
   the structural chunks are present.

   The canonical size is whatever the encoder produced. It is usually
   smaller than the input; it can be larger for a PNG that was
   aggressively optimised, and that is fine — the input cap is what
   bounds work, and the canonical size is reported in
   `DATA_CHAT_MEDIA_BYTES` so a client can plan.

10. **Handle.** 16 bytes from the OS CSPRNG. On the legacy wire they
    are the raw bytes of `DATA_CHAT_MEDIA_ID`; on the ng wire the
    base64url spelling, 22 characters, which is also the path segment
    of `GET /media/{handle}`. The store keeps, per handle: canonical
    bytes, MIME type, width, height, the uploader's principal, creation
    time, and the authorisation set of §5.

**Every rejection is one of six coarse codes and a generic text.** The
text is `"Media rejected"`, `"Media too large"`, `"Unsupported media"`
or `"Slow down"`, never which walker or which limit. The server log gets
the real reason at debug level, without the bytes (§10).

## 4. Handles, lifetime, and where the bytes are

`MediaStore` is an in-memory map in `hxd-core`, guarded by its own
mutex — never the roster's, which must not be held across anything the
size of an image copy. A handle lives `handle_ttl` (default 24 h) and
is swept by the existing hourly task plus an eager check on access, so
an expired handle never answers even between sweeps. A moderator can end
it sooner, and a report can extend it: [moderation.md](moderation.md)
§3.2 and §4.3. The store also keeps each handle's canonical SHA-256,
which is what a revocation's re-upload block is keyed on.

The total of canonical bytes across all live handles is capped at
`max_total_bytes` (default 256 MiB). When an upload would cross it, the
oldest handles are dropped until it fits — the spec permits deleting
early, and evicting an old image is better than refusing a new one. A
server under that pressure is one with a hostile uploader, and the
per-account and per-address quotas are the real bound; the total cap is
what keeps the process alive if those are set generously.

Upload sessions (chunked uploads in flight) are the same shape: a
16-byte token, an idle deadline 30 s after the last chunk, the expected
part count, and the bytes so far, bounded at `max_bytes`. Out-of-order
index, duplicate index, a count mismatch, a first chunk that declares
a token, or a follow-up without one — each discards the session and
answers code 0. A server may refuse chunked uploads outright; this one
does not, because a 200 KB image does not fit in a 65 535-byte field.

**Nothing is on disk, and nothing survives a restart.** The spec has
clients treat handles as session-scoped and forbids caching them across
sessions, so a server that forgets them all at once is within the
contract. The two places a handle is *stored* — an inbox row and a chat
log line — degrade to their text (§9, §8) and the client renders the
placeholder it would have rendered for an expired handle. The
`MediaStore` is behind a trait boundary so a disk or object store can
arrive when clustering needs one; the memory implementation is what a
single node wants.

## 5. Authorisation

### 5.1 Principals, not uids

A uid is recycled within minutes and a session can outlive its socket,
so "the requester was a recipient" has to be said in terms that survive
both:

```rust
pub enum Principal {
    Session { uid: Uid, serial: u64 },   // the roster's (uid, serial), never reused
    Mailbox(Mailbox),                    // an account, keyed as the inbox keys it
}
```

A public-chat or private-room relay captures every media-capable
recipient as a `Session`, plus the sender. A private message captures
the sender's and recipient's `Mailbox` — which is what lets a message
that waited in the inbox for a day be read, image included, by whatever
session of that account picks it up. A guest has no mailbox, so a PM
*to* a guest captures the recipient session instead; a PM *from* a guest
captures the sending session. Nothing is ever added to a set after the
relay, which is the spec's "fixed at relay time"; sessions that end are
pruned from sets lazily, which is its "MAY narrow". The one exception
is a reported image, whose set gains the moderators who have to judge
it (moderation.md §4.3).

### 5.2 The domain learns one thing about a transport

Fan-out happens in `hxd-core`, which today knows nothing about what a
session negotiated. To capture *media-capable* recipients and only
them, `Transport` (roster.rs — "what the caller knows about the link")
gains one boolean, `inline_media`. The legacy frontend sets it from bit
3 of the negotiated caps; the ng frontend sets it true, because an ng
client is told what it can ignore rather than asked what it supports
(hotline-ng.md §5: unknown fields in event data are ignored). The
domain then computes the authorisation set as *recipients with the
flag* and leaves the rest of fan-out untouched; each frontend's encoder
strips or emits the fields according to its own connection, which is
where per-recipient capability already lives.

### 5.3 The three contexts

| Relay | Set at relay time |
|---|---|
| Public chat | sender + every visible, media-capable session with read-chat access |
| Private room | sender + every media-capable member at that moment; membership checked first |
| Private message | sender's mailbox + recipient's mailbox (a session where there is no mailbox) |

A download by anyone else, of any handle that exists or does not, is
`"Media not found"` with code 4 — one answer, so the error cannot be
used to test whether a handle exists.

### 5.4 History readers

The chat log keeps a line's handle (chat-history.md §8). Whether a
session that reads that line through `Get Chat History` may then
download the image is where the spec and the obvious wish disagree:
"gaining read access does NOT grant retroactive download rights" is a
MUST, and a user who reconnects with a better client and sees a
placeholder where their friend's photo was is going to ask why.

`[media] history_access` decides, and the default is the spec's:

- `"recipients"` (default): a history entry carries the handle, but a
  download resolves only for principals captured at relay time.
- `"readers"`: for **public chat only**, serving a line through 700 or
  `history` adds the reading session to that handle's set. Never for a
  private room (rooms are not logged anyway) and never for a PM.

The argument for `readers` is that public chat is public to everyone
holding read-chat, and a line's audience in the human sense is
everyone who could have been in the room. The argument against is the
spec's, and it is the reference implementation's job to ship the
spec's answer and raise the question upstream (§14).

## 6. Rate limits and the numbers

Every figure is the spec's recommended default and every one is
configurable; the spec allows tightening freely and relaxing only with
operator awareness, so the config file says which direction each knob
turns.

| Limit | Default | Where enforced |
|---|---|---|
| Encoded payload | 64 B – 256 KiB | store, on assembly |
| Dimension | 1 – 2048 px per axis | codec, header probe |
| Pixels | 2048 × 2048 | codec, header probe |
| Animation | 150 frames, 15 s | codec, frame collection |
| Decode budget | 2 s, 64 MiB, 2 concurrent | codec + the awaiting task |
| Upload rate | 1 / 10 s, 30 / h per account; 100 / h per address | store |
| Upload sessions | 2 per account, 30 s idle | store |
| Download rate | 60 / min per session | frontend |
| Handle lifetime | 24 h | store, swept hourly |
| Total canonical bytes | 256 MiB | store, oldest evicted |
| Chunk size advertised | 60 000 B | frontend |

60 000 is what GtkHx clamps any advertised chunk size to and what it
uses when none is advertised: it leaves room in a 65 535-byte field
frame for the index, final and token chunks around the payload. Every
download reply is sliced at it, and the advertisement says so.

## 7. The legacy wire (`hxd-session`)

### 7.1 LOGIN

`ServerConfig::caps` gains bit 3 when `[media]` is configured. When the
bit survives the intersection the reply carries all six advisory limits
as u32 BE — `MAX_BYTES`, `MAX_DIMENSION`, `MAX_PIXELS`, `CHUNK_SIZE`,
`MAX_FRAMES`, `MAX_DURATION_MS` — the spec's MUST, and the sibling of
the video ceilings that already ride this reply. Not one of them is
sent when the bit did not survive.

### 7.2 Upload (750)

Gated on bit 3 like every extension transaction. The handler collects
`PAYLOAD`, `DECLARED_TYPE`, `UPLOAD_TOKEN`, `PART_INDEX`, `PART_COUNT`,
`PART_FINAL`, and hands them to `Core::media_upload_part(uid, addr, part)`
through `off_reactor`, which is where the pipeline runs — never on the
reactor, and never under the roster lock.

- Single-shot: `PAYLOAD` + `PART_FINAL ≠ 0`, no token, no count (or
  count 1). Reply on success: `MEDIA_ID`, `MEDIA_TYPE`, `WIDTH`,
  `HEIGHT`, `BYTES`.
- Chunked: the first chunk carries `PART_COUNT ≥ 2` and no token; its
  reply carries `UPLOAD_TOKEN` (and nothing else). Each follow-up
  carries the token and the next index; an intermediate reply echoes
  the token, which GtkHx tolerates and the spec calls safe. The final
  chunk is the one with `PART_FINAL ≠ 0` and must be index
  `count − 1`; its reply is the single-shot success reply.
- Failure at any step: a task error whose `DATA_ERROR` is one of the
  four texts of §3.3 and whose `0x0212` is the code, u16 BE.

### 7.3 Download (751)

`MEDIA_ID` required; `PART_INDEX` optional, absent means 0. Bit 3 and
the per-session download rate gate it, then `Core::media_fetch(principal,
handle)` answers bytes-and-type or nothing. The reply is one slice:
`PAYLOAD` (this chunk, ≤ 60 000 bytes), `MEDIA_TYPE`, `PART_COUNT`,
`PART_FINAL`. A `PART_INDEX` past the count is "Media not found" like
any other bad request; the store re-checks authorisation on every part,
because the set can only shrink and a session that was kicked between
parts is exactly the one that should stop receiving.

### 7.4 Chat and private messages

**Inbound** (105, 108): the chunk walk picks up `MEDIA_ID` and
`MEDIA_TYPE`. From a session without bit 3 they are dropped on the
floor — "servers MUST drop these fields from any inbound transaction
whose sender did not negotiate the capability" — and the text goes
through as plain chat. From a capable session, exactly one of the two
present is a task error (chat has no task reply; the line is dropped
with a debug log, as an unpermitted chat is today); both present go to
`Core::chat_public(uid, text, style, Some(handle))`, which resolves the
handle to a `MediaRef { id, mime, width, height, bytes }` — the
sender's declared `MEDIA_TYPE` is discarded in favour of the canonical
one — refuses a handle the sender did not upload or that has expired,
and otherwise relays with the reference attached and the authorisation
set captured. The `msg` path does the same with `Core::msg`.

**Outbound** (106, 104): the encoder for `Event::Chat` and `Event::Msg`
appends `MEDIA_ID`, `MEDIA_TYPE`, `WIDTH`, `HEIGHT`, `BYTES` when the
event carries a `MediaRef` **and** the session has bit 3, and nothing
otherwise. The 13-column line formatting is unchanged either way; the
text is whatever the sender typed, `[image]` or a caption or nothing at
all — an empty body with a media reference is legal on this wire and
formats as the sender's name and no text.

A mixed private room is two encodings of one event, produced by two
sessions' encoders from one `Event`, which is what the frontend design
already gives for free.

## 8. The ng wire (`hxd-ng-session`)

### 8.1 Login reply

`caps` gains `"media"`, and a `media` block rides beside `video`,
`inbox` and `history`, present exactly when the cap is:

```jsonc
"media": {
  "max_bytes": 262144, "max_dimension": 2048, "max_pixels": 4194304,
  "max_frames": 150, "max_duration_ms": 15000,
  "types": ["image/jpeg", "image/png", "image/gif"]
}
```

No chunk size: HTTP carries a body. `types` is there so a client's file
picker can filter without hard-coding the spec's list.

### 8.2 Bytes over HTTP

Two routes on the ng port, beside the identity endpoints in `http.rs`:

```
POST /media
  Authorization: Bearer <session>.<token>
  Content-Type: image/jpeg | image/png | image/gif     (the hint; ignored for sniffing)
  Content-Length: ≤ max_bytes                          (413 before reading otherwise)
  <body: the image>

  201 { "media": { "id": "…22 chars…", "type": "image/png",
                   "width": 800, "height": 600, "bytes": 124000 } }

GET /media/{id}
  Authorization: Bearer <session>.<token>

  200  Content-Type: image/png
       Content-Length, Cache-Control: private, max-age=86400,
       X-Content-Type-Options: nosniff, Content-Disposition: inline,
       Content-Security-Policy: sandbox
       <canonical bytes>
```

The bearer is the session's public id and its secret token joined by a
dot; the registry looks it up the way `resume` does, constant-time on
the hash, and yields the session's `(uid, serial)` principal. A detached
session can still upload — its token is valid while it lives — and a
session that does not exist is 401 whatever the path.

Errors map the six codes onto status codes rather than a JSON body,
because a `fetch` caller branches on the status first: 1 → 413,
2 → 415, 3 → 429 (with `Retry-After`), 4 → 403 on upload, 5 → 503, and
0 → 400. A download that fails for any reason is **404**, one answer,
the spec's non-distinguishing rule in HTTP's own words. Bodies are a
one-line JSON `{ "error": { "code": "media_rejected", "text": "…" } }`
in the ng error shape so a client has one parser.

A browser client fetches with the header, makes a blob URL, and hands
it to an `<img>`; the `sandbox` CSP and `nosniff` are for the case
where someone navigates to the URL directly. Nothing about the response
is cacheable by a shared cache, and the handle is not in any log line
the proxy writes by default (§10).

### 8.3 Requests and events

| `req` | change |
|---|---|
| `chat` | params gain `media?` (handle string). The handle must be the caller's own upload and live: otherwise `bad_request` with text `"No such media."`, the same answer for both, and the chat is not sent. |
| `msg` | the same `media?` param, the same rule. `guid` idempotency covers the media: a retry with the same guid is the same message, image and all. |

| `ev` | change |
|---|---|
| `chat` | data gains `media: { id, type, width, height, bytes }` when the line had one. |
| `msg` | the same; for a queued message whose handle has since expired, `media` is present **without `id`** — the placeholder is still worth rendering. |

`text` may be empty when `media` is present; the server's "a message
needs text" refusal becomes "needs text or media".

## 9. The inbox: an image that waited

Schema version 2 (chat-history.md §4.1 is the same bump) adds to
`message`: `media_id BLOB, media_type TEXT, media_w, media_h,
media_bytes INTEGER`. `NewMessage` and `StoredMessage` carry
`media: Option<MediaMeta>`, and a flush emits it on the event.

A private message is persisted before its sender is acked
(private-messages.md §3), and its image is a handle with a 24-hour
life. Two cases:

- **Read within the lifetime** — the common one, a phone that was
  asleep for an hour: the recipient's mailbox is in the handle's set
  (§5.1), the event carries the reference, the client fetches the
  bytes. Works across a detach, a re-login, and a second device.
- **Read after it** — mail to an account that is away for days: the
  event carries the metadata without a handle, the client renders the
  placeholder, the text stands. The bytes are gone.

Pinning a handle while an undelivered row references it would close the
second case at the cost of letting the inbox extend a handle's life
indefinitely — a mailbox is capped at `cap` waiting messages, so the
bound exists, but it is a different bound from the one the spec states.
Not in v1; §14 keeps it.

## 10. Privacy and logging

- Canonical and original bytes are never written to a log. The `proto`
  trace category prints `PAYLOAD` chunks as `<n bytes>`; the `media`
  category (new) logs `[image: <mime>, <bytes> bytes, <w>x<h>]` and a
  handle **prefix** of six characters, enough to correlate an upload
  with a download in one operator's log and not enough to fetch with.
- Handles do not appear in the discovery document, in any unauthenticated
  response, or in the HTTP access log at info level (the path is
  logged as `/media/…`).
- A rejected upload is logged with its real reason at debug level and
  the uploader's login, which is the audit trail the coarse client code
  deliberately is not.
- The spec's "plaintext transport" residual risk is the legacy wire's
  existing condition; the README's line about HOPE and TLS covers it,
  and the ng wire is WSS-by-proxy already.

## 11. Configuration

```toml
[media]                        # presence turns the extension on
max_bytes = 262144             # ↓ tighten freely; ↑ relax knowingly
max_dimension = 2048
max_pixels = 4194304
max_frames = 150
max_duration_ms = 15000
max_concurrent_decodes = 2
handle_ttl = 86400             # seconds
max_total_bytes = 268435456    # canonical bytes across all live handles
history_access = "recipients"  # or "readers" — §5.4
[media.rate]
upload_interval = 10           # seconds between uploads, per account
upload_per_hour = 30           # per account
upload_per_hour_per_addr = 100
download_per_minute = 60       # per session
```

A `[media]` section in a build without the `media` feature is a startup
error, like `[inbox]` without its feature. The `media` feature is on by
default so CI covers the pipeline.

## 12. Staging

1. **M1 — `hxd-media`.** The crate, the trait, the three walkers, the
   probe/decode/re-encode with limits, orientation, animation limits.
   Tests on a corpus committed under `crates/hxd-media/tests/fixtures`:
   each format's minimal valid file; a JPEG with EXIF orientation 6
   that must come out rotated and tag-free; a PNG with `tEXt`, `iCCP`
   and `eXIf` chunks that must all be gone; a GIF with a comment
   extension; a PNG-then-ZIP polyglot and a JPEG with trailing bytes,
   both refused by the walker; a 1×1 PNG claiming 20 000×20 000 in its
   header, refused at the probe; a decompression bomb refused by
   allocation; an animated GIF over the frame cap and one over the
   duration cap; SVG, WebP, AVIF, BMP and ICO, each refused at the
   sniff. Every canonical output re-walked and asserted structural
   chunks only.
2. **M2 — the domain.** `MediaStore`, principals, quotas, upload
   sessions, expiry and eviction, `Transport.inline_media`, `MediaRef`
   on `Event::Chat` and `Event::Msg`, `chat_public` / `chat_private` /
   `msg` taking a handle and capturing sets. Unit-tested with a fake
   codec that returns fixed bytes, so the domain tests never decode
   anything.
3. **M3 — the legacy wire.** LOGIN advert, 750 single and chunked, 751
   sliced, the chat/msg field handling in both directions, error codes.
   E2E in `crates/hxd/tests/media.rs` with a scripted client that packs
   with `hxproto::inline_media` — the same builders GtkHx uses —
   covering: single-shot round trip; chunked upload and multi-part
   download; a capable and a non-capable client in one room, one
   seeing fields and the other not; a non-recipient's download refused
   with the same answer as a bogus handle; expiry; the private-room
   membership check; each error code.
4. **M4 — the ng wire.** The HTTP routes, the bearer, the params and
   event fields, the login block. E2E: an ng upload rendered by a legacy
   client's download and the reverse; a PM with media queued for a
   detached ng session and fetched after resume; the 404-for-everything
   rule.
5. **M5 — the two stores.** Schema v2 media columns on `message` and
   `chat_line`, the flush and the history entry carrying metadata, the
   `history_access` knob. E2E: an image sent, read back through 700
   with sub-fields, downloadable or not according to the knob.
6. **M6 — moderation** (moderation.md §8): revoke, the hash block,
   pinning, and the `media_revoked` event.

## 13. Cross-wire, in one sentence each

A photo attached in GtkHx is an `<img>` in hx-ng, and a photo dropped
in hx-ng is an inline row in GtkHx, because the handle is the same
sixteen bytes and only its spelling differs. A legacy client without
the bit sees the caption. A phone that was asleep gets the image with
its queued mail. A 1.5 client sees nothing new at all.

## 14. Open questions, and what to raise upstream

- **History readers** (§5.4): propose an amendment that a server MAY
  extend a public-chat handle's set to sessions served the line through
  `Get Chat History`, since the "no retroactive widening" rule was
  written for rooms and access changes, not for a log the spec itself
  introduced afterwards.
- **Sub-field allocation** in the history document (chat-history.md
  §11) — the same upstream conversation.
- **Format follows source** (§3.3) is a departure from a
  recommendation; worth saying upstream so the recommendation can say
  "or the source format".
- **Pinning handles for undelivered mail** (§9). Reports already pin
  (moderation.md §4.3), so the mechanism will exist; the question is
  only whether mail should use it.
- **A gateway** is off the table until someone asks for it; when they
  do, the constraints in the spec (public chat only, canonical bytes,
  128-bit paths, at most one upload per line) are the design.
- **Chunked uploads on the tunnel.** A TRTP-over-WebSocket session runs
  the legacy handler unchanged, so 750/751 work there as they do on
  TCP; whether a tunnelled GtkHx should prefer the HTTP route is a
  client question.
