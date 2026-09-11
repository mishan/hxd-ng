# hxd-ng

A Hotline server in Rust, written from scratch. It serves two protocol
populations from one shared state:

- **Legacy Hotline**, TCP `:5500` — the 1.2/1.5 wire format, byte-compatible
  with clients from the late 90s.
- **Hotline-ng**, WebSocket `:5700` — a JSON protocol designed mobile-first,
  where a session survives a dropped connection.

One roster, one set of chat rooms, one voice room. A 1.5 client and a phone
are in the same conversation, and neither can tell which wire the other is
on.

Two clients already speak to it: [GtkHx](https://github.com/mishan/gtkhx),
the period client revival, on the legacy wire, and
[hx-ng](https://github.com/mishan/hx-ng), a browser client, on the ng one.

**Never break old clients** is the hard requirement, and it outranks
everything else here. Deviations from reference-server behavior are
deliberate and commented at the site.

## What it does

- **Chat, private chats, private messages, moderation** on both wires, with
  mhxd as the behavioral reference for everything a period client can
  observe.
- **Voice and video** through one SFU: one UDP port, one peer connection,
  one room shared across both wires. Video adds media sections to the voice
  session rather than standing up anything of its own, and nothing is
  delivered to a peer that has not subscribed to it.
- **Images in chat**, on both wires. A photo attached in a 1.5 client
  renders in the browser and the other way round: the server validates,
  re-encodes and strips every byte of metadata, hands back an opaque
  handle, and decides who may fetch it from who was in the room when the
  line was sent. Clients that never negotiated the capability see the
  caption and nothing else.
- **Portable identity** — an Ed25519 keypair is who you are, independent of
  any one server's account table. A client proves it over HTTP, links it to
  an account, and can carry it to another server. Legacy clients reach it
  too, through a TRTP-over-WebSocket tunnel.
- **Private messages that outlive a session.** Mail for someone who is not
  there is stored and handed over when they arrive — so a 1.5 client's
  message reaches a phone that was asleep, and an ng client can address an
  account that holds no session at all.
- **Threaded news** on the ng wire: categories and bundles, articles that
  thread as replies, references between articles (a `#51` in the text)
  with backlinks, tombstones that keep a thread's shape when an article
  goes, and full-text search across all of it. A 1.5 client in the same
  room sees nothing change: the legacy wire carries no news yet.
- **Sessions that survive the network.** An ng session detaches when its
  socket dies and resumes with a gapless event replay; the roster shows it
  as away in the meantime.

Status and what is not built yet: [ROADMAP.md](ROADMAP.md). Orientation for
working in the code: [AGENTS.md](AGENTS.md).

## Getting started

### Prerequisites

The `hxproto` wire crate is shared with
[GtkHx](https://github.com/mishan/gtkhx) through the
[hx-libs](https://github.com/mishan/hx-libs) workspace. Cargo fetches the
pinned revision automatically.

Building the voice SFU needs a C/assembly toolchain and **cmake** — the
WebRTC stack's DTLS certificate generation reaches aws-lc-sys whichever
crypto provider is selected. On Debian/Ubuntu:

```sh
apt install build-essential cmake
```

A build with `--no-default-features` leaves voice, the inbox and the
image pipeline out and needs none of them.

### Build and run

```sh
cargo run --bin hxd                                  # listens on 0.0.0.0:5500
cargo run --bin hxd -- --config /path/to/hxd-ng.toml
```

Every config key is optional, and a server with no config file at all is a
working legacy-only server. The first run creates `accounts/` (mode 0700)
with a guest account; add more as TOML files in that directory.

### Say hello

The best end-to-end check is a real client, and there is one for each wire.

**[GtkHx](https://github.com/mishan/gtkhx)** speaks the legacy wire — point
it at `127.0.0.1:5500`.

**[hx-ng](https://github.com/mishan/hx-ng)** is the browser client for the ng
wire: public chat, the user list with the classic icons, private messages,
and the voice and video the SFU already serves. It never sees the legacy
wire, and the server cannot tell it apart from any other ng client.

```sh
git clone https://github.com/mishan/hx-ng && cd hx-ng
npm install && npm run dev     # http://localhost:5701, bound to every
                               # interface so a phone on the LAN can reach it
```

The two clients in the same room, one on each wire, is the check worth
running before believing any of this.

The repo also ships two deliberately minimal harnesses, for when you want to
see the protocol rather than use it. `tools/ng-client.mjs` is a terminal ng
client — no install on Node 22+; on older Node, `cd tools && npm install`
once for the `ws` fallback:

```sh
node tools/ng-client.mjs ws://127.0.0.1:5700 --login alice --password pw
# then type to chat; /drop tests detach+resume; /logout to leave
```

`tools/ng-voice.html` is the voice and video counterpart: one file, no build
step. Open it against a server with `[voice]` configured and it joins the
lobby's voice room with a real `RTCPeerConnection` — camera, screen share
and per-stream subscription included when `[voice.video]` is on.

### Tracing

```sh
HXD_DEBUG=proto cargo run --bin hxd     # comma-separated categories, or `all`
```

The format mirrors gtkhx's `GTKHX_DEBUG=proto`, so a client trace and a
server trace of the same session line up. `RUST_LOG` wins when set.

## Configuration

`hxd-ng.toml` by default. Each section below is independent, and every key
is optional unless noted.

### The legacy server

```toml
[server]
bind = "0.0.0.0:5500"
name = "My Server"
version = 185           # 0 mimics a pre-1.5 server
login_timeout = 10
ban_time = 1800         # seconds a kick-with-ban holds the address
stamp_queued = true     # stamp a message that waited in the inbox with its
                        # send time (docs/private-messages.md §7)

# Set User Flags bit 4 on unencrypted legacy sessions (docs/hotline-ng-auth.md §8).
# Off until that bit is confirmed free against 1.8/1.9 clients.
# mark_cleartext = false

[paths]
accounts = "accounts"
agreement = "agreement.txt"
```

### The ng frontend

Enabling `[ng]` turns on the WebSocket protocol — see
[docs/hotline-ng.md](docs/hotline-ng.md).

```toml
[ng]
bind = "127.0.0.1:5700"    # plaintext; put a WSS-terminating proxy in front
grace = 300                # detached-session grace window, seconds
max_detached_per_addr = 2

# Proxies only. The address walk skips whatever is listed here, and the
# mTLS binding header (X-Hotline-Client-Cert) is believed from these hosts
# and nowhere else.
# trusted_proxies = ["127.0.0.1"]

# Which header that proxy writes the client address into:
# x-forwarded-for | forwarded | none. The rightmost element outside
# trusted_proxies is the client (docs/hotline-ng-auth.md §6.3).
forwarded_header = "x-forwarded-for"
```

### Portable identity

Needs `[ng]`, because the identity endpoints and the tunnel are served by
the ng listener. See [docs/hotline-ng-auth.md](docs/hotline-ng-auth.md) for the
transport and [docs/hotline-ng-identity.md](docs/hotline-ng-identity.md)
for what an identity is and how it links to an account.

```toml
[identity]
key = "identity-server.key"         # Ed25519 seed; generated on first run
new_accounts = "guest"              # deny | guest | create
unattested = "guest"                # deny | guest | allow
min_attestation_age = 0             # seconds an attestation must have existed
clock_skew = 300                    # tolerated clock difference, seconds
successors = "identity-successors"  # §3.4 commitments; "" = memory only
trtp = true                         # serve the tunnel at /trtp
trtp_login = "verify"               # verify | trust: how a tunnelled classic
                                    # login meets the socket's identity
enroll = true                       # serve the enrollment mailbox at
                                    # /identity/enroll; off, a device enrolls
                                    # by the paste as before
enroll_sessions = 256               # open sessions at once, server-wide
enroll_per_address = 4              # open sessions and pending requests, per
                                    # source address

# web = "https://hl.example/app/"   # where a web client for this server lives.
                                    # Advertised in discovery so `hlid enroll`
                                    # can show a QR code that opens it with the
                                    # pairing code already in it. Must be on
                                    # this server's own origin to be drawn: the
                                    # QR's fragment carries the pairing secret,
                                    # so a client hosted elsewhere is one the
                                    # user names with `hlid enroll --web`

# max_new_accounts_per_hour = 60    # ceiling on what new_accounts = "create" writes
# allow_list = ["alice@hl.example", "<fingerprint>"]
# registrar_keys = { "hl.example" = "<base64url public key>" }

# Access bits for accounts "create" makes — same key names as an account
# file's [access]. Absent means whatever guest has, which is rarely right.
# [identity.default_access]
# read_chat = true
# send_chat = true
```

### The offline inbox

Absent means no inbox, and that is the default. Naming the database is what
turns it on. See [docs/private-messages.md](docs/private-messages.md).

```toml
[inbox]
db = "messages.db"
max_queued = 200         # messages waiting, per account; a full one refuses
deliver_at_flush = 25    # queued messages handed over per login
retain_unread = 2592000  # seconds; 30 days, from when it was sent
retain_read = 604800     # seconds; 7 days, from when it was read
sync = "normal"          # or "full": fsync every commit
```

### Chat history

Absent means no server-held scrollback. When `db` is omitted, history uses
the inbox database and shares its SQLite connection; without an inbox it is
required. See [docs/chat-history.md](docs/chat-history.md).

```toml
[history]
# db = "messages.db"      # required only without [inbox]
max_lines = 10000         # 0 = unlimited
max_days = 0              # 0 = unlimited
max_page = 200            # maximum rows in one request
replay = 0                # plain chat lines replayed to old legacy clients
```

### Threaded news

Absent means no news: the ng wire never offers the `news` cap, and a news
request is answered the way a server without the feature answers it. When
`db` is omitted, news uses the database `[inbox]` or `[history]` names and
shares its SQLite connection; with neither it is required. Nothing here
reaches a legacy client yet — the 1.2 and 1.5 news transactions are a
stage still to come. See [docs/news.md](docs/news.md).

```toml
[news]                    # presence turns it on
# db = "messages.db"      # required only without [inbox] or [history]
max_body = 65535          # the legacy NEWSDATA ceiling; ↓ freely, ↑ never
max_subject = 255         # the 1.5 pstring
max_refs = 32             # references recorded per article; past that, text
max_depth = 32            # reply nesting
max_node_depth = 16       # bundle nesting
max_page = 200            # threads in one request
retain_days = 0           # a thread's life after its last post; 0 = forever
self_delete = true        # authors may delete their own; false = period behavior
search = true             # false turns news_search off; the index is kept either way
search_max_results = 500  # the deepest a search pages
search_per_minute = 30    # searches per session
```

Who may read, post, delete and rearrange is the account's news bits —
`read_news`, `post_news`, `delete_articles` and the category and bundle
bits in [docs/access-bits.md](docs/access-bits.md). An article is its
author's to delete only when one person is behind the account, a password
or a linked identity; a guest's belongs to nobody.

### Inline media

Absent means no images: the legacy wire never confirms capability bit 3
and the ng wire never offers the `media` cap or its HTTP routes. The
send permission is off in every account file that does not name it —
including the bootstrap guest — because an image is the one thing a
stranger can put on everyone else's screen. See
[docs/inline-media.md](docs/inline-media.md).

```toml
[media]                      # presence turns it on
max_bytes = 262144           # per image, before canonicalization
max_dimension = 2048         # per axis
max_pixels = 4194304
max_frames = 150             # animated GIFs
max_duration_ms = 15000
max_concurrent_decodes = 2
handle_ttl = 86400           # seconds a handle answers
max_total_bytes = 268435456  # held across all live handles; oldest evicted
history_access = "recipients" # or "readers": may a scrollback reader fetch?

[media.rate]
upload_interval = 10          # seconds between one account's uploads
upload_per_hour = 30          # per account
upload_per_hour_per_addr = 100
download_per_minute = 60      # per session
upload_sessions = 2           # chunked uploads in flight, per account
```

Nothing touches disk: handles live in memory for their day and go with a
restart, which the extension's own spec allows for — clients are told
not to cache them across sessions.

### Voice and video

Both absent by default. Video rides the voice session, so `[voice.video]`
without `[voice]` does nothing. See [docs/voice.md](docs/voice.md) and
[docs/capabilities-video.md](docs/capabilities-video.md).

```toml
[voice]
# bind = "0.0.0.0:5504"           # default: the [server] bind, port + 4 (UDP)
advertise = ["203.0.113.5:5504"]  # what clients are told to send media to.
                                  # Required when bind is a wildcard: ICE-lite
                                  # gives a client nothing else to go on.
                                  # List a v4 and a v6 to serve both.
max_per_room = 16                 # the spec's VoiceMaxPerRoom

[voice.video]
max_cameras_per_room = 8          # VideoMaxCamerasPerRoom
max_screens_per_room = 1          # VideoMaxScreensPerRoom; a second sharer is
                                  # refused rather than preempting the first
max_width = 1280                  # camera ceiling
max_height = 720
max_fps = 30
max_bitrate = 1500000             # bits per second
screen_max_width = 1920           # screen-share ceiling: more pixels, fewer
screen_max_height = 1080          # frames — a desktop is mostly still
screen_max_fps = 15
screen_max_bitrate = 2500000
```

## Operating

### Accounts and identity

An account is one TOML file: an `[access]` table of named permission bits,
an `[extra]` table of server-local policy that never crosses the wire, and
an `[identity]` table linking it to a key. Every bit, key and switch —
what each one gates, which of them this server enforces today, and which
numbers are reserved — is in
[docs/access-bits.md](docs/access-bits.md). First run writes a `guest.toml`
with the bits a stranger can be trusted with; delete it to turn guests off.

An account links to an identity through an `[identity]` table in its file,
written by linking or by hand: `fingerprint`, `login = true` (the identity
may log in without the password), `allow_self_link = true`, `reserve_name`.

An account with a fingerprint and no password is reachable *only* by proving
the identity — the password path refuses it, empty password included — which
is what makes `new_accounts = "create"` safe alongside the legacy port.
(`reserve_name` is read but not yet enforced; §9's reserved-name rules are
unimplemented on both wires.)

With `[identity]` on, the ng listener also answers HTTP: `GET
/.well-known/hotline` for discovery, `POST /identity/challenge` and
`/identity/auth` for the challenge binding, `GET /identity/card/<fp>` and
`PUT /identity/card`, and `POST /identity/link` and `/identity/unlink` for
account association.

`hlid` makes the keys and objects and talks to the server. From nothing:

```sh
hlid init --name Alice        # identity key, device key, certificate, card
hlid agent  --server http://127.0.0.1:5700   # stay open: hand out codes, and
                                             # take renewals without one
hlid enroll --server http://127.0.0.1:5700   # certify a browser: show a code
                                             # (and a QR, if the server names a
                                             # web client on its own origin),
                                             # wait, ask, sign
hlid auth   --server http://127.0.0.1:5700
hlid link   --server http://127.0.0.1:5700 --login alice --password-stdin < pw.txt
hlid tunnel --server http://127.0.0.1:5700
```

`init` writes into `$HLID_HOME` (default `~/.hlid`), and `--identity`,
`--device`, `--cert` and `--card` fall back to what it wrote, which is why
none of the lines above name a file. That fallback is what lets a web
client print a command for you to run — it cannot know where you keep your
key, and a pre-filled path that guesses is right only by luck.

The long way, when you want the files somewhere specific or the
certificate to say something other than the default:

```sh
cargo run --bin hlid -- keygen identity id.key
cargo run --bin hlid -- keygen device dev.key

# Anything that writes an account link needs `manage`, and `--caps web`
# deliberately excludes it. A browser device gets `web`; the device you
# administer your account from gets this. `hlid init` writes an
# unrestricted certificate, since its device sits on the same machine as
# the identity key and a bit withheld there protects nothing.
hlid cert --identity id.key --device dev.key --caps login,message,manage -o cert.cbor
hlid card --identity id.key --name Alice -o card.cbor

# Certifying a browser, whose keys never leave it: the two public halves
# come off the screen, and `--bundle` writes the certificate and your card
# as the one blob the browser asks you to paste back.
hlid cert --device-pub 3f2a… --device-enc-pub 91c4… --caps web --bundle -o web.bundle

hlid auth   --server http://127.0.0.1:5700 --device dev.key --card card.cbor --cert cert.cbor
hlid link   --server http://127.0.0.1:5700 --device dev.key --card card.cbor --cert cert.cbor \
            --login alice --password-stdin < pw.txt
hlid tunnel --server http://127.0.0.1:5700 --device dev.key --card card.cbor --cert cert.cbor
```

After `hlid tunnel`, point any 1.x client at `127.0.0.1:5500` and it logs in
through the tunnel with your identity. That login can link an account too
(§8.3), which is why the certificate above carries `manage`; a tunnel used
with an account that is already linked wants `--caps login,message`.

### The inbox

An account has an inbox if it has a password or a linked identity — either is
proof of one person, where a bare `guest` login is shared. `[extra] inbox` in
the account file overrides it either way.

A guest can send to whoever is on the roster and cannot queue anything: it
has no account, so nothing can be blocked, and a sender that cannot be
blocked must not be able to fill a mailbox. `block`/`unblock` keep an account
addressable without making it reachable by everyone.

**The database holds every private message on the server in the clear.** It
is created 0600, as are its `-wal` and `-shm` companions; keep the directory
to match.

Deleting an account is still `rm accounts/alice.toml`, which leaves its mail
behind for whoever registers that login next — so take it with the account:

```sh
hxd inbox purge alice                     # while accounts/alice.toml exists
hxd inbox purge alice --fingerprint <fp>  # after it is gone: the value from
                                          # its [identity] table
hxd inbox purge alice --dry-run           # how much would go
```

### News

The search index is kept in step with the articles by the same writes
that change them. If it ever drifts — a database restored from a copy, a
file edited by hand — rebuild it from the articles:

```sh
hxd news-reindex
```

It opens the database the server uses, which must already exist, and
leaves the articles as they are. See [docs/news.md](docs/news.md) §6.4.

### Voice

Voice needs its **UDP** port reachable — the one thing operators most often
miss. Video rides that same port and that same peer connection, so there is
no second socket to open, and it is off unless `[voice.video]` is present.

Video is opt-in on both sides at runtime too: nobody publishes until they
ask, and nobody receives a stream until they ask for that stream in
particular, so a room with video in it costs a voice-only participant
nothing.

### Cargo features

`voice`, `inbox` and `media` are all on by default, so CI covers them. The
`inbox` feature supplies the shared SQLite store for the inbox, history and
news;
`media` supplies the image pipeline. Building without one leaves its
dependency out of the binary entirely — no WebRTC stack, no bundled SQLite,
no image decoder — and the matching config section then becomes a startup
error rather than a promise the build cannot keep.

## Documentation

| Document | What it covers |
|---|---|
| [hotline-ng.md](docs/hotline-ng.md) | The ng protocol: framing, the login/resume/sync handshake, the request and event tables, seq accounting |
| [hotline-ng-auth.md](docs/hotline-ng-auth.md) | Transport authentication: the principal, the challenge and mTLS bindings, transport tokens, the TRTP tunnel, cleartext marking, tunnels and relays |
| [hotline-ng-identity.md](docs/hotline-ng-identity.md) | Portable identity: the signed objects, the identity profile at authentication, cards, account association |
| [identity-enrollment.md](docs/identity-enrollment.md) | Certifying a device through a mailbox and a pairing code instead of a paste; renewal; what the mailbox is trusted with |
| [identity-threat-model.md](docs/identity-threat-model.md) | What identity defends against, and what it deliberately does not |
| [identity-test-vectors.json](docs/identity-test-vectors.json) | Signed objects and reject cases — the contract a second implementation is checked against |
| [access-bits.md](docs/access-bits.md) | Account permissions: every access bit and its `[access]` key, the reserved numbers, `[extra]` policy, and what a new server starts with |
| [private-messages.md](docs/private-messages.md) | The offline inbox: the mailbox rule, the store contract, delivery, blocking, retention |
| [chat-history.md](docs/chat-history.md) | Scrollback: the chat log, cursor paging on both wires, retention, fogWraith's `Get Chat History` |
| [news.md](docs/news.md) | Threaded news: the tree, articles and references, the store and its schema, the ng requests and events, search, subscriptions, markdown bodies, and the legacy binding still to come |
| [inline-media.md](docs/inline-media.md) | Images in chat: the re-encode pipeline, handles and relay-time authorisation, 750/751 and the HTTP routes |
| [moderation.md](docs/moderation.md) | Redaction, revocation, purges and reports: the acts, the audit trail, and what each wire can do |
| [voice.md](docs/voice.md) | The SFU: hand-written SDP, RTP forwarding, and one room across both signalling wires |
| [capabilities-video.md](docs/capabilities-video.md) | Video: publications, subscriptions, limits, and the renegotiation path |
| [push-notifications.md](docs/push-notifications.md) | Push: the notify decision in the domain, and delegating the device registry |
| [proposals/](docs/proposals/messaging-identity-amendment.md) | Proposed amendments to fogWraith's messaging extension |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check tools/ng-client.mjs
```

That is what CI runs. [AGENTS.md](AGENTS.md) is the map of the workspace —
which crate owns what, the invariants that matter, and the conventions this
repo is written to.
