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

[paths]
accounts = "accounts"
agreement = "agreement.txt"

[ng]
bind = "127.0.0.1:5700"   # plaintext; put a WSS-terminating proxy in front
grace = 300               # detached-session grace window, seconds
max_detached_per_addr = 2

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

Try the ng frontend with the bundled client (no install on Node 22+;
on older Node, `cd tools && npm install` once for the `ws` fallback):

```sh
node tools/ng-client.mjs ws://127.0.0.1:5700 --login misha --password pw
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
