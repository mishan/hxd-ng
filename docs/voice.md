# Voice chat: one SFU, two signalling wires

hxd-ng implements the fogWraith voice-chat capability — a server-side SFU
that clients reach over WebRTC, signalled over the client's existing
control connection — for **both** protocol populations at once. A GtkHx
user on the legacy TCP wire and a mobile user on the Hotline-ng WebSocket
join the same voice room and hear each other. This document says why that
is nearly free once the SFU exists, where each piece lives, what the SFU
is built on, and how the work stages.

Spec: fogWraith
[`Docs/Protocol/Capabilities-Voice.md`](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Voice.md),
read at `main` = `75d4485` (2026-09-05). GtkHx's implementation pins
`525e94e`; the two should be diffed once before V3 (§9) and the pin
recorded here. GtkHx's own write-up,
[`gtkhx/docs/voice.md`](../gtkhx/docs/voice.md), is the client-side
counterpart of this document and its "Open" section is the list of
server bugs we are here to not repeat (§6).

**Decision (2026-09): build it, ahead of the Phase 6 order.** The
ROADMAP had voice last among the extensions, "deferred until everything
above is solid." It moves up because it is the one extension whose value
compounds with Hotline-ng: the server *is* the SFU, so a mixed-population
voice room is a signalling problem, not a media problem, and the
signalling is small.

---

## 1. Why mixed rooms are free

The spec's architecture puts every media stream through the server:

```
   GtkHx (legacy TCP :5500)          mobile app (ng WS :5700)
        │ 600–606 transactions              │ voice_* JSON
        ▼                                   ▼
   hxd-session                        hxd-ng-session
        └──────────────┐   ┌────────────────┘
                       ▼   ▼
                     hxd-core        voice rooms, policy, who-hears-whom
                         │  VoiceMedia trait
                         ▼
                     hxd-voice       str0m SFU: DTLS-SRTP, ICE-lite, RTP forwarding
                         │
                    UDP :5504  ◀════ PCMU/RTP from every client, whichever wire it signalled on
```

Media never touches either frontend. A client's WebRTC stack talks to the
server's UDP port and nothing else; which TCP or WebSocket connection
carried its SDP is invisible on the media plane. So the whole of "legacy
and ng users share a room" is: the domain owns one voice-room model, and
each frontend encodes the same six signalling messages in its own wire
format. The legacy encoding is dictated by the spec; the ng encoding is
ours to define (§8) and is a transliteration.

This is the same seam that makes chat cross the eras — wire types stay
out of `hxd-core`, both frontends are callers — applied to a subsystem
where the payoff is larger, because a text-only mobile client is a
convenience and a voice-capable one is a reason to open the app.

## 2. What the spec asks of a server

Condensed; the spec is normative and this is the checklist.

- **Negotiation.** Bit 2 (`0x0004`) of `DATA_CAPABILITIES` (`0x01F0`) at
  LOGIN; echo it in the login reply iff voice is enabled and the SFU is
  up. Echo it regardless of the user's privilege — the capability means
  server support, and clients show a disabled button with a tooltip when
  the bit (below) is missing. Never send voice transactions to a client
  that didn't negotiate.
- **Privilege.** `accessVoiceChat` is access bit 55 (`bit::VOICE_CHAT`,
  already in `hxd-core::access`). It says a user may join voice; it does
  **not** say which room. Room membership is enforced separately: public
  chat (cid 0) is open to anyone with the bit, a private chat's voice
  room only to that chat's current members.
- **Room identifiers MUST be server-allocated from a CSPRNG** and unique
  among rooms in use, because a voice room is addressed by a bare cid and
  a guessable cid lets a voice-capable client join a room it was never
  invited to. Our `chat_create` allocates sequentially today (§11).
- **One room at a time.** Joining voice in room B implicitly leaves A;
  the A teardown and its status notification complete before the B join
  starts. If B fails, the user is in no room and is not re-joined to A.
- **The server is always the offerer.** Join reply carries the offer;
  every room change renegotiates every *other* participant with a new
  offer; the client only ever answers.
- **Renegotiation is serialised per peer.** Never send a client a second
  offer while one is unanswered; apply the change internally, mark the
  peer dirty, and send one consolidated offer when the answer arrives.
- **Mids are stable and meaningful.** `send` for the client's own
  microphone, `user-{UID}` (decimal, no leading zeros, never uid 0) for
  each other participant. A mid is never reassigned; a departed user's
  section stays in the SDP as `a=inactive` with port 9, and a rejoin
  reactivates the same mid. Every remote participant gets its own
  `user-{UID}` section — never bundle remote audio onto `send` (§6).
- **SDP shape.** BUNDLE over one transport, `rtcp-mux`, `setup:actpass`
  in the offer, `a=rtpmap:0 PCMU/8000` and nothing else, ICE credentials
  and DTLS fingerprint per section, port 9 everywhere.
- **Answer handling.** The answer's `send` section declares
  `a=ssrc:<n> cname:<c>`; that SSRC is how inbound RTP binds to the mic
  track. A server tolerates a missing declaration by payload-type
  fallback (which costs an unlabelled section in later offers); reject
  an answer without PCMU.
- **ICE.** Trickle in both directions as 604 notifications; empty
  candidate string (or empty field) is end-of-candidates; never wait for
  it. A single UDP port, default base + 4, serves every session.
- **Mute is server-enforced.** A muted participant's RTP is dropped, not
  forwarded, regardless of what the client sends. Status (605) fans out
  on every join/leave/mute; a ~100 ms debounce of mute flaps is
  RECOMMENDED.
- **Timeouts** (minimums; monotonic clocks): no answer after join, 10 s;
  ICE failure, 30 s; DTLS failure, 10 s; no RTP *or RTCP* from the client,
  30 s. Each tears the peer down and sends status to the room. The
  control connection is unaffected.
- **Cleanup.** Disconnect is an implicit leave. Kicked from a chat means
  removed from its voice. Last participant out tears the room's SFU state
  down. Enforce a per-room cap (`VoiceMaxPerRoom`, default 16).
- **Never** log audio; do log join/leave.

## 3. Where each piece lives

| Crate | Owns | Knows nothing about |
|---|---|---|
| `hxd-core` (`voice.rs`) | Voice rooms: who is in voice in which cid, muted flags, the one-room rule, the per-room cap, membership checks, the per-peer offer/answer serialisation state, and cleanup hooked into `end_session` / `connection_lost` / chat part / kick. Emits `Event::Voice*` through the existing outbox. Defines the `VoiceMedia` trait. | SDP syntax, ICE, DTLS, RTP, sockets, wire encodings |
| `hxd-voice` | The SFU: one UDP socket, one str0m `Rtc` per participant, hand-written SDP offers, answer parsing, ICE-lite candidates, DTLS-SRTP, RTP forwarding with mute enforcement, the media timeouts. Implements `VoiceMedia`. | Hotline, chat rooms, access bits, either wire |
| `hxd-session` | `DATA_CAPABILITIES` parse/echo; transactions 600–606 and fields `0x01F5`–`0x01F9` mapped to `Core` calls and `Event::Voice*`. | Media |
| `hxd-ng-session` | `caps: ["voice"]`; the `voice_*` requests and events (§8). | Media |
| `hxd` | `[voice]` config, the `voice` Cargo feature, wiring the SFU into `Core`, the UDP listener task. | — |

**The domain owns the room, not just the policy.** The alternative —
voice state inside `hxd-voice`, with `hxd-core` calling hooks on session
end and chat part — was considered and rejected. Voice membership is
chat-room-shaped state with chat-room-shaped lifecycle (part, kick,
disconnect, last-one-out), and every one of those transitions already
lives in `hxd-core`. Putting the room there means the cross-frontend
guarantee is the domain's, cleanup can't be forgotten in one frontend and
remembered in the other, and the whole policy surface is unit-testable
against a fake `VoiceMedia` with no WebRTC in the test at all — the same
shape as `NotificationGateway` with its recording fake.

**SDP is opaque to the domain.** `Event::VoiceOffer` carries a `String`;
the domain never parses it, any more than it parses a chat line. This is
the one place a media-plane artefact transits `hxd-core`, and it does so
as a payload, not a type; both frontends carry it verbatim. An ICE
candidate is a four-field struct mirroring the spec's
`RTCIceCandidateInit` (`candidate`, `sdp_mid`, `sdp_mline_index`,
`username_fragment`) — the legacy frontend encodes it as the JSON string
the spec mandates, the ng frontend as a JSON object; neither is a wire
type in the domain.

## 4. The domain model

```rust
pub struct VoiceParticipant { pub uid: Uid, pub muted: bool }

pub enum Event {
    // ...existing variants...
    /// An SDP offer for the recipient's own peer connection. Initial
    /// (answering a join) or a renegotiation.
    VoiceOffer { cid: u32, sdp: String },
    /// A server ICE candidate, RFC-8839 candidate line + mid, or
    /// end-of-candidates (empty candidate).
    VoiceIce { cid: u32, candidate: IceCandidate },
    /// The room's participant list changed (join, leave, mute).
    VoiceStatus { cid: u32, participants: Vec<VoiceParticipant> },
}

impl Core {
    pub fn voice_join(&self, uid: Uid, cid: u32) -> Result<VoiceJoin, VoiceError>;
    pub fn voice_leave(&self, uid: Uid, cid: u32) -> Result<(), VoiceError>;
    pub fn voice_answer(&self, uid: Uid, cid: u32, sdp: String) -> Result<(), VoiceError>;
    pub fn voice_ice(&self, uid: Uid, cid: u32, candidate: IceCandidate);
    pub fn voice_mute(&self, uid: Uid, cid: u32, muted: bool) -> Result<(), VoiceError>;
    pub fn voice_participants(&self, cid: u32) -> Vec<VoiceParticipant>;
}

pub struct VoiceJoin { pub sdp: String, pub codec: &'static str, pub participants: Vec<VoiceParticipant> }

pub enum VoiceError { Disabled, NoSuchChat, NotAMember, RoomFull, NotInVoice, BadAnswer }
```

`voice_join` is where the spec's ordering lives: check membership, leave
any current room (teardown, status to that room), then join — cap check,
`media.join(uid, cid)`, record the participant, get the joiner's initial
offer, and for every other participant either send a renegotiation offer
or mark them dirty. The privilege check (bit 55) stays with the frontends,
per the existing rule that wording belongs with the wire; the domain
enforces the structural rules.

**Per-peer serialisation** is two flags on each participant:
`offer_outstanding` and `dirty`. Room change with no offer outstanding →
fetch a fresh offer from the media layer and send it. Room change with an
offer outstanding → set `dirty`. `voice_answer` → apply the answer, clear
`offer_outstanding`, and if `dirty`, immediately fetch and send the
consolidated offer. This is the spec's deferral rule, and it is a
handful of lines because the media layer produces "the current offer for
this peer" on demand rather than diffing.

**Cleanup is not optional and has four entry points.** `end_session`
(legacy socket death, grace lapse, logout, kick) and **`connection_lost`**
(ng socket death) both leave voice: a peer whose control connection is
gone has a media path that is dead or about to be, and an ng client that
resumes re-joins explicitly. `part_one` and `kick` leave the voice room
for the chat being left. Because voice ends on `connection_lost`, nothing
voice-shaped is ever *buffered* for a detached session except the tail
of its own departure, so resume's replay stays harmless and the outbox
needs no notion of "ephemeral event".

**Media-originated events** — server ICE candidates, a peer failing a
timeout, a peer connecting — come back into the domain through
`Core::voice_media_event(MediaEvent)`, called from `hxd-voice`'s task.
`MediaEvent::Failed { uid }` is a leave with a status update, exactly as
the spec's timeout table says. With ICE-lite the server's candidates are
its configured addresses and are known at offer time, so the offer can
carry them inline (`a=candidate` lines) and the server's only trickled
604 is end-of-candidates, sent right after the offer. The 604 path exists
for symmetry with clients, which do trickle.

**Locking.** `VoiceMedia` calls are made while holding the roster lock.
That is deliberate and safe *only* because the media layer is sans-IO
(§5): every call is an in-memory state change on a str0m `Rtc` behind its
own mutex, never a socket operation or an await. If that ever changes,
the discipline from the token registry applies (copy out, release, call,
reacquire).

## 5. The SFU crate and why str0m

`hxd-voice` is built on [str0m](https://github.com/algesten/str0m), a
Sans-I/O WebRTC implementation designed for server-side SFUs. The
properties that decide it, each checked against the source at 0.23.1:

- **One UDP socket for every peer.** Each participant is an `Rtc`; the
  pump reads a datagram and asks `rtc.accepts(&input)` down the list,
  which demultiplexes by ICE credentials (STUN) and then by remote
  address. That is the spec's "single UDP port; the stack demultiplexes"
  sentence, and it is the library's documented pattern.
- **ICE-lite** (`set_ice_lite`), so the server is the passive ICE side
  with host candidates only — the spec's "the server's host candidate is
  the only one needed" shape — and the client does the connectivity
  checks.
- **PCMU as a static payload type** (`enable_pcmu`, PT 0) with G.711
  packetiser/depacketiser present, and **RTP mode** (`set_rtp_mode`) that
  hands us raw `RtpPacket`s and lets us write them back out unchanged —
  the spec's "forwards RTP without modification; never decodes."
- **The direct API** (`Rtc::direct_api()`): `declare_media(mid, kind)`
  with a **mid of our choosing**, `expect_stream_rx(ssrc, mid)` for the
  answer's declared SSRC, `declare_stream_tx(ssrc, mid)` for each
  forwarded participant, local ICE credentials and DTLS fingerprint on
  request, and remote credentials/fingerprint set from the parsed answer.
  This matters because str0m's *SDP* API generates random mids and has no
  way to name one `user-12`, and the spec's track-to-user mapping is
  those names. So we write the offer ourselves and parse the answer
  ourselves, which the direct API is for. A `Mid` is sixteen bytes;
  `user-65535` fits.
- **Pure Rust, MIT/Apache-2.0** (permissive, GPL-compatible; no
  license question), **MSRV 1.85.0** — the workspace's exact
  `rust-version`. Build with the `rust-crypto` feature rather than the
  default `aws-lc-rs`, which drags in a C/asm build and cmake.

Why not the alternatives: **webrtc-rs** (the Pion port, which is what
Janus's SFU is built on) is a full async stack that owns its own sockets
per peer connection and wants a `PeerConnection` per participant; it is
the natural second choice if str0m's direct API turns out to fight us,
and the `VoiceMedia` trait is the seam that makes swapping it a contained
job. **GStreamer's `webrtcbin`** is the client's choice, not a server's:
LGPL C, a runtime plugin dependency (`gstreamer1.0-nice`), and gtkhx's
gotchas section is the case against running it headless on a server.

**Hand-written SDP is a feature here, not a cost.** The spec fixes the
offer's shape down to the attribute list, and with ICE-lite the only
variable parts are our credentials and fingerprint, the room's mids and
directions, and the SSRC we forward on each `user-{UID}` section. That is
a template, deterministic per (peer, room state), and it is what makes
"the current offer for this peer" cheap to produce on demand (§4). Answer
parsing needs `ice-ufrag`, `ice-pwd`, `fingerprint`, `setup`, each
section's mid and direction, PCMU's presence, and the `send` section's
`a=ssrc` — `hotline_proto::voice::sdp::summarize` already parses the
shape (mids, BUNDLE, directions) for the client and can be extended for
the rest, or `str0m-proto`'s parser used for just this. `hxd-voice` may
depend on `hotline-proto`; it is not the domain.

**Forwarding** is the SFU's whole job and it is small: on
`Event::RtpPacket` from peer A in room R, for each other peer B in R that
has completed DTLS, `B.stream_tx_by_mid(user-A).write_rtp(...)` with A's
payload type, sequence number, timestamp and marker passed through. If A
is muted, drop the packet before that loop — server-enforced mute is one
`if`. The forwarded SSRC on B's `user-A` section is A's own SSRC (the
spec: no SSRC rewriting), which also means a rejoin by A with a fresh
SSRC updates `user-A`'s declared stream on every other peer's next
renegotiation.

**Addressing.** ICE-lite means the server must advertise an address the
client can actually reach: `[voice] advertise` lists them (v4 and v6,
both — a v6-only client should get a v6 candidate), defaulting to the
bind address when it is not a wildcard. A server behind NAT or in a
container with a wildcard bind and no `advertise` is misconfigured, and
startup should say so rather than offer `0.0.0.0` and let clients time
out.

## 6. The Janus bugs we are here to not repeat

Both are documented from the client side in
[`gtkhx/docs/voice.md`](../gtkhx/docs/voice.md) § Open, with scripted
reproductions. Both are avoided by construction in this design, and the
staging (§9) tests for both explicitly.

1. **The first joiner never hears the second joiner.** Janus applies a
   joiner's answer *after* the joiner's first microphone RTP can arrive;
   Pion drops the undeclared SSRC and the publisher is never forwarded. In
   this design `voice_answer` parses the `a=ssrc` and calls
   `expect_stream_rx` on the same call, before the domain returns — there
   is no window. The payload-type fallback for answers that omit
   `a=ssrc` is a str0m-level question (an unknown-SSRC event we can bind
   on first sight) and is an open item, not a v1 requirement: GtkHx's
   `webrtcbin` emits the declaration.
2. **Existing participants get the newcomer bundled onto `send` instead
   of a `user-{UID}` section**, which breaks speaker attribution and
   historically audio. Our offer template emits one `recvonly`-from-the-
   client's-view section per remote participant, named `user-{UID}`,
   always. There is no code path that reuses `send` for remote audio.

A third class, not a Janus bug but a client reality worth knowing: GtkHx
treats an offer that flips a section to `a=inactive` as the leave signal
and tears down that receive bin; `webrtcbin` fires no `pad-removed` for
it. So departures **must** be signalled the spec's way — `a=inactive`,
port 9, section retained — and never by dropping the `m=` line, which
would also misalign `sdpMLineIndex` for every later candidate.

## 7. The legacy wire (`hxd-session`)

**Capabilities first, as their own branch.** Nothing in `hxd-session`
reads `DATA_CAPABILITIES` today. Voice needs it, Text-Encoding (Phase 6
item 2) needs it, and the push work's `caps` list is the ng-side twin. So
V0 (§9) is: parse `0x01F0` at LOGIN into a per-connection `caps` bitset on
`Session`, echo the intersection of client-offered and server-supported
bits in the login reply, and expose `Session::has_cap`. Voice sets bit 2
in the supported set iff a `VoiceMedia` is wired. Text-Encoding then
lands as bit 1 on the same plumbing.

**Transactions** (`hotline-proto` has the client's builders and parsers;
the server side mirrors them):

| Opcode | Direction | Server does |
|---|---|---|
| 600 `VOICE_JOIN` | C→S, reply | `has_cap(VOICE)` else ignore; bit 55 else task error "You are not allowed to join voice chat."; `core.voice_join`; reply `CHAT_ID`, `VOICE_SDP`, `VOICE_CODEC` = `PCMU`, `VOICE_PARTICIPANTS`; errors map to task-error text |
| 601 `VOICE_LEAVE` | C→S, reply | `core.voice_leave`; empty reply |
| 602 `VOICE_SDP_OFFER` | S→C, notification | from `Event::VoiceOffer` |
| 603 `VOICE_SDP_ANSWER` | C→S, reply | `core.voice_answer`; empty reply, or task error on a rejected answer |
| 604 `VOICE_ICE` | both, notification | C→S: `core.voice_ice`; S→C: from `Event::VoiceIce` |
| 605 `VOICE_ROOM_STATUS` | S→C, notification | from `Event::VoiceStatus` |
| 606 `VOICE_MUTE` | C→S, reply | `core.voice_mute`; empty reply |

Server-initiated notifications carry **task id 0** with the reply flag
unset, per the spec's transaction-semantics section. Our `push()` helper
stamps pushes with their own counter (mhxd's convention, which the spec's
base protocol shares); voice notifications are the first place the
extension spec says otherwise. GtkHx dispatches these by type and doesn't
care; Janus sends 0; we send 0 for the three voice notifications and
leave the rest as they are, with the deviation commented at the site.

The `VOICE_PARTICIPANTS` blob (u16 uid, u16 flags, u16 codec id, all
big-endian, six bytes per entry) has a parser in `hotline-proto::voice`
and needs the matching builder; that belongs in the shared crate next to
its parser, round-trip tested there, and is a coordinated change across
the two trees. Everything else on this wire is plain chunk assembly.

## 8. The ng wire (`hxd-ng-session`)

A transliteration of the same six messages into the request/event shapes
of [hotline-ng.md](hotline-ng.md) §5. The login reply's `caps` list
(anticipated in hotline-ng.md §11 and by the push design) gains
`"voice"` when the SFU is wired.

| `req` | params | ok | errors |
|---|---|---|---|
| `voice_join` | `cid` | `{ "sdp", "codec": "PCMU", "participants": [ {uid, muted} ] }` | `voice_disabled`, `access_denied`, `no_such_chat`, `not_a_member`, `voice_full` |
| `voice_leave` | `cid` | `{}` | `not_in_voice` |
| `voice_answer` | `cid`, `sdp` | `{}` | `not_in_voice`, `bad_answer` |
| `voice_ice` | `cid`, `candidate` (object, or `null` for end-of-candidates) | `{}` | `not_in_voice` |
| `voice_mute` | `cid`, `muted` (bool) | `{}` | `not_in_voice` |

| `ev` | data |
|---|---|
| `voice_offer` | `{ cid, sdp }` |
| `voice_ice` | `{ cid, candidate }` — `candidate` is the `RTCIceCandidateInit` object, or `null` for end-of-candidates |
| `voice_status` | `{ cid, participants: [ {uid, muted} ] }` |

`candidate` is the same `RTCIceCandidateInit` dictionary the legacy wire
carries as a JSON string, embedded as an object because the transport is
already JSON; a web or mobile client hands it straight to
`addIceCandidate`. `participants` is an array of objects rather than the
packed blob for the same reason. Codec ids and reserved flag bits don't
cross this wire — if the spec ever adds a second codec, `codec` is
already a string.

**Detach and resume.** Voice ends on `connection_lost` (§4). A resumed
session finds itself out of voice — its replay tail includes the
`voice_status` that says so — and re-joins with a fresh `voice_join`.
This is the mobile-honest answer: a phone that dropped its WebSocket
dropped its UDP path too, and a fresh ICE/DTLS handshake is faster than
pretending the old one survived.

**Mobile clients** use the platform `RTCPeerConnection` (browser,
libwebrtc on iOS/Android). PCMU is mandatory-to-implement in all of them
(RFC 7874), so no codec work on the client. They get a server host
candidate and no TURN, which is the spec's model and works from carrier
NAT because the server is the one with the public address. The ng MVP
has no private chats, so ng voice is public-chat (cid 0) voice until the
ng private-chat work lands; the request shapes already carry `cid` so
nothing changes then.

## 9. Staging

Each stage is a branch with tests, in the house style.

0. **V0 — capabilities.** `DATA_CAPABILITIES` parse/echo in
   `hxd-session`; `caps` list in the ng login reply; e2e that a client
   offering bits gets back only the ones the server supports, and that a
   client offering none sees no change in any reply. Small, shared with
   Text-Encoding and push, and it retires the "no capability negotiation
   exists" gap on its own.
1. **V1 — the domain.** `hxd-core::voice`: rooms, the one-room rule, the
   cap, membership, the offer/answer serialisation flags, cleanup on all
   four paths, `Event::Voice*`, the `VoiceMedia` trait and a **recording
   fake**. Unit tests replay the spec's own sequence diagrams ("B joins
   with A present", "B leaves") as call traces and assert the exact
   sequence of media calls and events — the same technique `hxvoice`
   uses on the client. The interesting bugs are here: join-while-dirty,
   leave-while-offer-outstanding, kick-from-chat-while-in-voice,
   `connection_lost` racing an answer.
2. **V2 — `hxd-voice`.** The str0m SFU behind `VoiceMedia`: offer
   template, answer parser, direct-API session setup, ICE-lite, the UDP
   pump with `accepts()` demux, forwarding, mute, timeouts. Tested
   **without sockets**: str0m being sans-I/O, two `Rtc`s can be wired to
   each other by passing `Transmit` output straight into the other's
   `handle_input`, so a test can stand up a client-side `Rtc` (str0m in
   its ordinary SDP-answering role) against our server-side one and
   assert RTP forwarded, mute dropped, `a=inactive` on leave, and that a
   rejoin reactivates the same mid. This is the stage that tells us
   whether the direct API is the right tool; if it isn't, the trait means
   V1 and V3+ don't change.
3. **V3 — legacy wire.** 600–606 in `hxd-session`, the participants
   builder in `hotline-proto` (submodule pin advanced deliberately),
   `[voice]` config and the `voice` feature in `hxd`. E2E with a scripted
   legacy client that speaks the transactions and a str0m client for
   media, on a real server. Then the check that matters: **a real GtkHx**
   against hxd-ng — GtkHx's voice integration suite currently targets
   Janus only, and adding hxd-ng as a target is the conformance statement
   the ROADMAP's testing section has wanted since Phase 1.
4. **V4 — ng wire.** The `voice_*` requests and events, `caps: ["voice"]`,
   a browser-based ng voice client under `tools/` (a page with
   `RTCPeerConnection` is the cheapest real WebRTC stack we can point at
   the server), and the cross-frontend e2e: **a scripted legacy client
   and a scripted ng client in one voice room, RTP forwarded both ways**.
5. **V5 — real clients, mixed room.** GtkHx on :5500 and the browser page
   on :5700 in one room, hearing each other. This is the exit criterion.
   Run the two Janus-bug reproductions from gtkhx's `tools/` against
   hxd-ng and confirm they don't reproduce.

## 10. Risks, honestly

| Risk | Severity | Response |
|---|---|---|
| str0m's direct API is documented as low-level and *can* panic on an internally inconsistent setup | Medium | V2 exists to find out early; every panic path becomes a test; `VoiceMedia` is the seam to webrtc-rs if the API fights us |
| `webrtcbin` (GtkHx) against an ICE-lite server has not been tried by us | Medium — it's standard, but GtkHx's gotchas list is long | First thing V3 tests with a real GtkHx; fallback is full ICE with host candidates only, which str0m also does |
| RTP-mode forwarding fidelity (seq/timestamp/marker passthrough, RTCP the client needs for keepalive and jitter) | Medium | Assert passthrough in V2's two-`Rtc` tests; str0m generates RR/SR itself; the spec asks the SFU to forward feedback "SHOULD", not MUST — v1 forwards RTP and lets each leg's RTCP be per-peer |
| An unauthenticated UDP port on the internet | Medium | str0m drops anything that doesn't match a live ICE credential or an established peer; rate-limit `accepts()` misses per source; document the port in the firewall notes; voice is off by default |
| Bandwidth: PCMU has no DTX, 64 kbps per stream each way, N−1 downstream per client | Low for Hotline-sized rooms, real at 16 | The per-room cap is the knob; the spec's bandwidth table goes in the operator docs |
| Sequential cids are guessable, and the spec's room-membership rules say a guessed cid is a joinable private room | **High if membership isn't checked; Low once it is** | Membership check in V1 is the real defence; random cids (§11) are defence in depth and cheap |
| `hotline-proto` changes coordinated by hand across two trees | Low, recurring | Keep the shared-crate delta to the participants builder; everything else stays in hxd-ng |
| The mute-debounce timer has no natural home in a domain that "schedules nothing" | Low | Ship without it (it's a SHOULD); if PTT flapping is noisy in practice, the `hxd-voice` task owns the timer and calls `core.voice_flush_status(cid)` |

## 11. Open questions

- **Random cids.** The spec MUSTs a CSPRNG-allocated, collision-checked
  room id because voice rooms are addressed by bare cid. Legacy clients
  treat a cid as opaque, so switching `chat_create` to a random nonzero
  u32 costs nothing on the wire. Do it unconditionally, or only when
  voice is enabled? Unconditionally is simpler and one less mode.
- **Payload-type fallback for answers with no `a=ssrc`.** GtkHx declares
  it; browsers declare it; the spec tolerates its absence. Whether str0m
  in RTP mode surfaces an unknown SSRC we can bind on first sight decides
  whether this is a small addition or a real one. Find out in V2; not a
  v1 requirement.
- **Speaker indication on the legacy user list.** The spec derives it
  client-side from 605; hxd-ng has nothing to add. The RFC 6464
  `audio-level` extension would be better and the spec permits it as an
  optional `extmap`; in RTP mode the header extension would pass through
  the SFU untouched. Worth offering once a client asks for it.
- **Where `idle` sits.** An ng session that goes idle (hotline-ng.md §12,
  itself open) is still attached; voice continues. Confirm that's the
  intended reading when idle is defined.
- **Metrics and logging.** Join/leave logged, audio never; the spec
  mentions a metrics endpoint the server doesn't have. Participants per
  room and forwarded packet counts are the obvious first counters when
  one exists.
- **The spec pin.** Diff `75d4485` against GtkHx's `525e94e` before V3 and
  record the pin here; if they differ in anything normative, GtkHx is the
  client we test against and its reading wins until it updates.
