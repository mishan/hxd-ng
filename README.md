# hxd-ng

A new Hotline server in Rust — wire-compatible with 1.2/1.5-era clients,
architected for a future beyond them. The plan is in [ROADMAP.md](ROADMAP.md).

The protocol crates are shared with
[GtkHx](https://github.com/mishan/gtkhx), vendored as a git submodule pinned
to a known-good revision:

```sh
git submodule update --init
```

## Run

```sh
cargo run --bin hxd                 # listens on 0.0.0.0:5500
cargo run --bin hxd -- --config /path/to/hxd-ng.toml
```

First run creates `accounts/` with a guest account. Add accounts as TOML
files in that directory (see `crates/hxd-auth-file`'s docs for the format).

Configuration (`hxd-ng.toml`, all keys optional):

```toml
[server]
bind = "0.0.0.0:5500"
name = "My Server"
version = 185          # 0 mimics a pre-1.5 server
login_timeout = 10

[paths]
accounts = "accounts"
agreement = "agreement.txt"
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
