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
cmake`.

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
```

Try the ng frontend with the bundled client (no install on Node 22+;
on older Node, `cd tools && npm install` once for the `ws` fallback):

```sh
node tools/ng-client.mjs ws://127.0.0.1:5700 --login misha --password pw
# then type to chat; /drop tests detach+resume; /logout to leave
```

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
