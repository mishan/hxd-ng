# hxd-ng

A new Hotline server in Rust — wire-compatible with 1.2/1.5-era clients,
architected for a future beyond them. The plan is in [ROADMAP.md](ROADMAP.md).

The protocol crates are shared with
[GtkHx](https://github.com/mishan/gtkhx), vendored as a git submodule pinned
to a known-good revision:

```sh
git submodule update --init
```

Building the voice SFU needs a C/assembly toolchain and **cmake**: the
WebRTC stack's DTLS certificate generation reaches aws-lc-sys whichever
crypto provider is selected. On Debian/Ubuntu, `apt install build-essential
cmake`. A build with `--no-default-features` leaves voice out and needs
neither.

## Run

```sh
cargo run --bin hxd                 # listens on 0.0.0.0:5500
cargo run --bin hxd -- --config /path/to/hxd-ng.toml
```

First run creates `accounts/` with a guest account. Add accounts as TOML
files in that directory (see `crates/hxd-auth-file`'s docs for the format).

Configuration (`hxd-ng.toml`, all keys optional; the `[ng]` section enables
the Hotline-ng WebSocket frontend — see [docs/hotline-ng.md](docs/hotline-ng.md)):

```toml
[server]
bind = "0.0.0.0:5500"
name = "My Server"
version = 185          # 0 mimics a pre-1.5 server
login_timeout = 10
ban_time = 1800        # seconds a kick-with-ban holds the address
stamp_queued = true    # stamp a message that waited in the inbox with its send
                       # time, on the legacy wire (docs/private-messages.md §7)
# mark_cleartext = false  # set User Flags bit 4 on unencrypted legacy sessions
                          # (identity spec §10); off until that bit is confirmed
                          # free against 1.8/1.9 clients

[paths]
accounts = "accounts"
agreement = "agreement.txt"

[ng]
bind = "127.0.0.1:5700"   # plaintext; put a WSS-terminating proxy in front
grace = 300               # detached-session grace window, seconds
max_detached_per_addr = 2
# trusted_proxies = ["127.0.0.1"]   # believe X-Hotline-Client-Cert (mTLS binding) and
                                    # the forwarded address (who a ban is about) from these.
                                    # Proxies only: the walk below skips whatever is listed here
forwarded_header = "x-forwarded-for"  # which header that proxy writes the client address into:
                                      # x-forwarded-for | forwarded | none. The rightmost element
                                      # outside trusted_proxies is the client (identity spec §5.3)

[identity]                # portable identity — docs/hotline-ng-identity.md; needs [ng]
key = "identity-server.key"        # server Ed25519 seed, generated on first run
new_accounts = "guest"             # deny | guest | create
unattested = "guest"               # deny | guest | allow
min_attestation_age = 0            # seconds an attestation must have existed to count
clock_skew = 300                   # seconds of clock difference tolerated in signed objects
successors = "identity-successors" # where §3.4 successor commitments live; "" = memory only
# max_new_accounts_per_hour = 60   # ceiling on what new_accounts = "create" writes
# allow_list = ["alice@hl.example", "<fingerprint>"]
# registrar_keys = { "hl.example" = "<base64url public key>" }
# [identity.default_access]        # access bits for accounts "create" makes;
# read_chat = true                 # same key names as an account file's [access].
# send_chat = true                 # Absent = whatever guest has, which is rarely right.
trtp = true                        # serve TRTP-over-WebSocket at /trtp for tunnelled legacy clients
trtp_login = "verify"              # verify | trust: how a tunnelled classic login meets the socket's identity

[inbox]                     # absent = no inbox, and that's the default
db = "messages.db"          # naming it is what turns the inbox on
max_queued = 200            # messages waiting, per account; a full one refuses
deliver_at_flush = 25       # queued messages handed over per login
retain_unread = 2592000     # seconds; 30 days, from when it was sent
retain_read = 604800        # seconds; 7 days, from when it was read
sync = "normal"             # or "full": fsync every commit

[voice]                          # absent = voice off, and that's the default
# bind = "0.0.0.0:5504"          # default: the [server] bind, port + 4 (UDP)
advertise = ["203.0.113.5:5504"] # what clients are told to send media to;
                                 # required when bind is a wildcard, because
                                 # ICE-lite gives a client nothing else to
                                 # go on. List a v4 and a v6 to serve both.
max_per_room = 16                # the spec's VoiceMaxPerRoom

[voice.video]                    # absent = video off, and that's the default
max_cameras_per_room = 8         # VideoMaxCamerasPerRoom
max_screens_per_room = 1         # VideoMaxScreensPerRoom; a second sharer is
                                 # refused rather than preempting the first
max_width = 1280                 # camera ceiling
max_height = 720
max_fps = 30
max_bitrate = 1500000            # bits per second
screen_max_width = 1920          # screen-share ceiling: more pixels, fewer
screen_max_height = 1080         # frames — a desktop is mostly still
screen_max_fps = 15
screen_max_bitrate = 2500000
```

Private messages to someone who isn't there are stored and delivered when
they arrive — across the wires, so a 1.5 client's message reaches a phone
that was asleep, and an ng client can address an account that holds no
session at all (`to_login`) which a period client then reads at its next
login.

An account has an inbox if it has a password or a linked identity — either
is proof of one person, where a bare `guest` login is shared; `[extra]
inbox` overrides it either way.

**The database holds every private message on the server in the clear.**
It is created 0600, as are its `-wal` and `-shm` companions; keep the
directory to match.

Deleting an account is still `rm accounts/alice.toml`, which leaves its
mail behind for whoever registers that login next — so take it with the
account:

```sh
hxd inbox purge alice                       # while accounts/alice.toml exists
hxd inbox purge alice --fingerprint <fp>    # after it's gone: the value
                                           # from its [identity] table
hxd inbox purge alice --dry-run            # how much would go
```

The inbox is behind the `inbox` Cargo feature, on by default; without it
an `[inbox]` section is a startup error rather than a promise the build
can't keep. See [docs/private-messages.md](docs/private-messages.md).

Voice needs its **UDP** port reachable — the one thing operators most often
miss. It is behind the `voice` Cargo feature, on by default;
`cargo build --no-default-features` leaves the WebRTC stack out of the
binary entirely. See [docs/voice.md](docs/voice.md).

Video rides that same port and that same peer connection — no second
socket to open — and is off unless `[voice.video]` is present. It is
opt-in on both sides at runtime too: nobody publishes until they ask, and
nobody receives a stream until they ask for that stream in particular, so
a room with video in it costs a voice-only participant nothing. See
[docs/capabilities-video.md](docs/capabilities-video.md).

An account links to an identity through an `[identity]` table in its file
(written by linking, or by hand): `fingerprint`, `login = true` (identity
may log in without the password), `allow_self_link = true`, `reserve_name`.
An account with a fingerprint and no password is reachable *only* by
proving the identity — the password path refuses it, empty password
included — which is what makes `new_accounts = "create"` safe alongside
the legacy port. (`reserve_name` is read but not yet enforced: §9's
reserved-name rules are still unimplemented on both wires.)

With `[identity]` on, the ng listener also answers HTTP: `GET
/.well-known/hotline` for discovery, `POST /identity/challenge` and
`/identity/auth` for the challenge binding, `GET /identity/card/<fp>` and
`PUT /identity/card`, and `POST /identity/link` and `/identity/unlink`
for account association.

`hlid` (`cargo run --bin hlid`) makes the keys and objects and talks to
the server:

```sh
hlid keygen identity id.key && hlid keygen device dev.key
# `login,message,manage` — anything that writes an account link needs
# `manage`, and `--caps web` deliberately excludes it. A browser device
# gets `web`; the device you administer your account from gets this.
hlid cert --identity id.key --device dev.key --caps login,message,manage -o cert.cbor
hlid card --identity id.key --name Alice -o card.cbor
hlid auth   --server http://127.0.0.1:5700 --device dev.key --card card.cbor --cert cert.cbor
hlid link   --server http://127.0.0.1:5700 --device dev.key --card card.cbor --cert cert.cbor --login alice --password-stdin < pw.txt
hlid tunnel --server http://127.0.0.1:5700 --device dev.key --card card.cbor --cert cert.cbor
# then point any 1.x client at 127.0.0.1:5500 — it logs in through the tunnel with your identity.
# The tunnelled login can link an account too (§8.3), which is why this
# certificate carries `manage`; a tunnel used with an account that is
# already linked wants `--caps login,message` instead.
```

Try the ng frontend with the bundled client (no install on Node 22+;
on older Node, `cd tools && npm install` once for the `ws` fallback):

```sh
node tools/ng-client.mjs ws://127.0.0.1:5700 --login alice --password pw
# then type to chat; /drop tests detach+resume; /logout to leave
```

`tools/ng-voice.html` is the voice and video counterpart: open it in a
browser against a server with `[voice]` configured and it joins the
lobby's voice room with a real `RTCPeerConnection` — camera, screen share
and per-stream subscription included when `[voice.video]` is on. No build
step, one file. Two browser tabs and a real GtkHx on the legacy port is
the end-to-end check worth running before believing any of this.

Wire tracing mirrors gtkhx's client-side trace so the two line up:

```sh
HXD_DEBUG=proto cargo run --bin hxd
```

## Test

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```
