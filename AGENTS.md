# AGENTS.md — hxd-ng working notes

> Orientation for anyone (human or AI) working in this codebase. This file
> is the map, not the territory: the product plan and phase status live in
> **[ROADMAP.md](ROADMAP.md)**, the Hotline-ng protocol spec in
> **[docs/hotline-ng.md](docs/hotline-ng.md)**, and how-to-run in
> **[README.md](README.md)**. Git history is the record of how we got here —
> the commit messages are written to be read.

## What this is

hxd-ng is a new Hotline server in Rust, written from scratch (not a port of
hxd/mhxd), sibling project to the [GtkHx](https://github.com/mishan/gtkhx)
client revival. It serves two protocol populations from one shared state:

- **Legacy Hotline** (TCP :5500) — the 1.2/1.5 wire format, byte-compatible
  with clients from the late 90s.
- **Hotline-ng** (WebSocket :5700) — a JSON protocol designed mobile-first,
  where sessions survive dropped connections.

**The hard requirement: never break old clients.** Hotline 1.2/1.5 clients
(and 1.9 where behavior is known) must connect, chat, and eventually
transfer files with no changes. It is the mirror image of GtkHx's
never-break-old-servers rule and outranks every other consideration.
Deviations from reference-server behavior are deliberate and commented at
the site.

License is **GPL-2.0-or-later** — forced by `hotline-proto`'s hxd ancestry,
and kept.

## Build and run

```sh
git submodule update --init   # once; the shared crates live in gtkhx/
cargo build --workspace
cargo run --bin hxd           # config: hxd-ng.toml (all keys optional)
```

The **gtkhx submodule** provides `hotline-proto` (and, later, hxcrypto and
friends) via path deps. Rules:

- `exclude = ["gtkhx"]` in the workspace Cargo.toml is load-bearing:
  without it cargo auto-adopts the submodule's crates as workspace members
  and `--workspace` runs start linting gtkhx's code with our settings.
- Advancing the pin is a deliberate act with a full test run behind it.
- API changes in the shared crates are coordinated across both trees by
  hand. The eventual extraction (and the third-party hotline-rs org that
  may host it) is ROADMAP.md Phase 0.

MSRV is pinned to gtkhx's floor (`rust-version` in Cargo.toml) but has only
been exercised on newer toolchains; CI runs stable.

## Workspace map

| Crate | Role |
|---|---|
| `hxd-core` | The domain: presence roster, chat rooms, messaging, moderation, access bits, auth traits. **Wire-free and UTF-8** — no transaction types, no Mac Roman, no JSON. Both frontends speak to it; a future frontend is "just" a third caller. |
| `hxd-session` | The legacy frontend: TRTP handshake, 22-byte-header framing, per-connection reader/writer/loop tasks, mhxd-mirroring protocol behavior, Mac Roman ↔ UTF-8 at its edges. `run_session` is generic over the byte stream so the ng port can feed it a tunnelled WebSocket. |
| `hxd-ng-session` | The ng frontend: the HTTP layer on the ng port (discovery, identity endpoints, WebSocket upgrade for both the JSON protocol and the TRTP tunnel — `http.rs`), server-side identity state (`identity.rs`), the WebSocket-as-byte-stream adapter (`tunnel.rs`), the login/resume/sync handshake, session-token registry, seq-stamped event encoding. |
| `hl-identity` | Identity objects for `docs/hotline-ng-identity.md`: keys, device certificates, user cards, attestations, login proofs — deterministic CBOR, domain-separated Ed25519. Transport-free by design; shared with clients, proxies and relays, so it belongs with the `hotline-proto` tier when the shared-crate extraction happens. |
| `hxd-auth-file` | Flat-TOML accounts (one file per account, `[access]` named bits + `[extra]` server-local policy), first-run guest bootstrap. |
| `hxd-voice` | The voice **and video** SFU: str0m, one UDP port, hand-written SDP, RTP forwarding, VP8 passthrough and keyframe requests. Behind `hxd-core`'s `VoiceMedia` trait and the `voice` Cargo feature, and knows nothing about Hotline. |
| `hxd` | The binary: config, wiring, the ng sweeper task, the voice media pump, `HXD_DEBUG` tracing. Its `tests/` hold the e2e suites. |

`tools/ng-client.mjs` is an interactive ng test client (Node 22+, or
`npm install` in tools/ for the `ws` fallback) — `/drop` exercises
detach/resume, `/msg` PMs by nick or uid.

## Invariants that matter

**The domain is UTF-8 and wire-free.** Mac Roman exists only at
`hxd-session`'s edges: convert on ingest (injective, so legacy-origin text
round-trips exactly), convert + `?`-for-unmappable on egress, truncate
nicks to the wire's 31 bytes *after* conversion. Credentials are
canonicalized Mac Roman → UTF-8 before any auth backend sees them — HOPE
proofs must use the same canonical form when that lands. Never let a wire
type or encoding leak into `hxd-core`'s API; that separation is what makes
the ng frontend (and any future one) possible.

**Presence is user-scoped, not connection-scoped.** A `UserSession` owns a
uid, a serial, and a seq-stamped outbox; transports attach to it. Legacy
socket death calls `end_session` (old behavior exactly); ng socket death
calls `connection_lost`, which detaches if policy allows. Detach policy:
`can_detach` is per-account (`[extra]`, default = has-a-password — guests
never detach), detached sessions are capped per source address, and
kicking a detached session must end it directly — there is no connection
to observe the `Kicked` event.

**Outbox seqs are gapless.** Every event a session should see consumes a
seq, including events the ng protocol can't express yet — those become
placeholder frames, never holes, or resume's `last_seq` accounting breaks.
Buffer overflow marks the outbox broken and resume answers
`resync_required`; it never silently gaps.

**Frame the legacy read stream by `len2` (DataSize), not `len`
(TotalSize)** — a lesson gtkhx paid for against fragmenting servers.
Clients never fragment, so `len != len2` is rejected outright. Size caps
mirror mhxd's.

**mhxd is the behavioral reference** for everything a 1.2/1.5 client can
observe: the login/agreement dance, server-side chat formatting (the
`\r%13.13s:  %s` and `\r *** %s %s` forms, byte for byte, empty tokens
skipped), user-list payloads, task-reply conventions (replies echo the
request trans; pushes count their own). It is vendored for cross-reading
at `gtkhx/mhxd/`. Where we deviate on purpose — real access bits in
SELFINFO, readable task errors, acked broadcasts — the site says so.

**Video is layered on voice, never beside it.** One peer connection, one
UDP port, one room, one SDP path: video adds media sections to the voice
session and reuses 602/603/604 for every renegotiation. What it adds is
publication control and a status notification. Two rules carry the
weight, and both are load-bearing rather than stylistic. **Nothing is
delivered unasked** — a peer receives a publication only while it holds a
subscription to it, so a voice-only client is not a special case the
forwarding path has to remember to exclude, it is a peer whose
subscription set is permanently empty. And **inbound video is keyed by
the SSRC the answer declared, never by mid**: a camera and a screen from
one participant are the same codec at the same payload type on one
bundled transport, so there is nothing else to tell them apart and an
answer that omits `a=ssrc` costs that publication rather than being
guessed at.

**The access bitmap is shared wire vocabulary; don't squat on bits.**
Reserved bits stay reserved (fogWraith allocates upward from 55).
Server-local policy that never crosses the wire goes in the account files'
`[extra]` section instead (`can_detach`, `set_subject`).

**Session-token trust is `(uid, serial)`.** uids recycle; serials never.
Tokens are CSPRNG bytes stored as SHA-256, compared in constant time. The
registry never holds its lock while calling into the core (copy out,
release, consult, reacquire) — keep it that way.

**A session must never outlive its transport silently.** Any handshake
send failure after attach routes through `end_session` (login) or
`connection_lost` (resume). A ghost on the roster with a dropped receiver
is the bug class to fear here.

**`assert!` over `debug_assert!`** for wire invariants — release builds
must not skip them.

## Testing

Three layers, all `cargo test --workspace`:

- **Unit** tests live with their crates (roster/outbox semantics, access
  bit numbering pinned against mhxd's constants, account parsing, frame
  round-trips).
- **E2E** suites in `crates/hxd/tests/` drive *real* servers on ephemeral
  loopback ports: `login.rs` (legacy login/presence/agreement), `chat.rs`
  (chat/PM/moderation over the legacy wire), `ng.rs` (the WebSocket
  frontend, **including cross-frontend scenarios** — a scripted 1.5 client
  and a WS client on one server, chat and PMs crossing both wire eras,
  detach showing as the away color, resume replay).
- The scripted legacy client packs and parses with the same
  `hotline-proto` the real GtkHx uses, so e2e doubles as wire-compat
  checking.

House rules: **tests fail loudly** — never skip around something broken.
A chat sender receives its own echo, so tests must match events by
predicate, not take-the-first. Name test files by subject, never by
project phase (`login.rs`, not `phase1.rs`) — phase labels belong in
commit messages and docs only.

Before calling anything done, run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check tools/ng-client.mjs
```

The best end-to-end check of all: point a real GtkHx at the legacy port
and `tools/ng-client.mjs` at the ng port, and chat between them.

## Debugging

`HXD_DEBUG=proto` turns on the wire trace (comma-separated categories;
`all` for everything) — its format matches gtkhx's `GTKHX_DEBUG=proto` so
a client trace and a server trace of the same session line up.
`RUST_LOG` wins when set.

## Conventions

- **Branches, not direct main commits.** Short kebab-case topic names
  (`ng-pm`, `registry-lock-discipline`) — no prefixes. Misha opens the PR,
  reviews, merges; CI must be green.
- **One commit per branch**, squashed before the PR opens
  (`git reset --soft <merge-base>`). During review, push follow-up
  commits; **don't force-push without asking**.
- Commits are authored `Misha Nasledov <misha@nasledov.com>`, descriptive
  bodies, no `Author:` line in the body, no `Co-Authored-By` trailer.
- Review feedback comes from bots as well as humans; verify claims before
  acting — this repo has seen confident "won't compile" findings about
  code that compiles.
- Stacked branches: a fix belongs on the branch that introduced the code;
  descendants pick it up when they rebase at merge time.
- **Avoid exact counts in comments and docs** (lines, tests, files) — they
  go stale and the narrative is stronger without them.
- Prefer a scripted reproduction (an e2e test against a live in-process
  server) over interactive debugging sessions.

## Where things stand, and what's next

ROADMAP.md carries live status. In brief: the legacy server covers login,
presence, chat, private chats, PMs, broadcast, and moderation; the
Hotline-ng MVP (roster + chat + PMs with detach/resume) is complete and
cross-tested; voice and video are implemented on both wires, sharing one
room and one SFU. The large open fronts, in rough order: HOPE + ciphers on the
legacy wire (`hxcrypto` sits ready in the submodule), the ng rate-limit and
client-quickstart polish, the fogWraith Text-Encoding capability (cheap —
the UTF-8 interior already satisfies its core mandate), files/HTXF, news,
and eventually the persistence/clustering phases. The mobile app the ng
protocol exists for has not been started.
