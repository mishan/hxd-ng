# e2e — the tests that run the actual server

Everything in `crates/hxd/tests/` builds `Core` / `ServerCtx` / `NgCtx` in
process and spawns `serve` on an ephemeral port. That is the right shape
for what those suites prove, and it leaves a layer nothing observes:
`Config::load` and `check_config`, `build_ctx`, `voice::build`, the ng
sweeper, the inbox/history/media pruners, `FileAuth::bootstrap`, the
account audit, the server key that writes itself on first run. All of it
lives in `main.rs`, and until this suite existed nothing ran `main.rs`.

So these tests start the real binary, with a real config file it parses
itself, in a temp directory it bootstraps for itself, on real sockets.

They are driven from **both ends by different implementations**.
[`@hotline-ng/client`](https://github.com/mishan/hx-ng) is written from
`docs/hotline-ng.md` by the client, not by the server. Where it and hxd-ng
agree, the agreement is evidence; the hand-rolled JSON in
`crates/hxd/tests/ng.rs` can only ever agree with the person who wrote
both sides of it. Where they disagree, the spec says which is wrong, and
that conversation is the point.

The legacy side is the same argument, made locally: `harness/legacy.mjs`
is a Hotline 1.5 client written from the wire format, and every legacy
test in `crates/hxd/tests/` packs with `pack_frame` and parses with
`read_frame` — the server's own functions, from the `hxproto` the server
unpacks with. A framing bug symmetric between those two is invisible to
all of them. This one frames by `len2` because the format says so, and
gets its Mac Roman table out of Node's own `TextDecoder`.

So `crosswire.test.mjs` puts a 1997 client and a browser client in one
room with neither of them sharing a line with the server.

## Running them

```sh
cd e2e && npm install && npm test
```

`npm test` is `node --test` — no test framework, matching the rest of the
repo's taste for not taking dependencies. It builds `hxd` and `hlid` in
release first (a no-op once warm).

Every file gets its own server, because `node --test` gives every file its
own process; within a file the tests share one and must not assume a clean
roster, which is honest — a real server never has one.

## What is deliberately not here

**Voice and video.** They need WebRTC and Node has none. `voice.rs`,
`video.rs` and `voice_media.rs` already drive real `str0m` peers against
the real SFU over real UDP, which is a better test than a browser
automation harness would be.

**Anything the Rust suites already prove about the domain.** This is a
layer above them, not a replacement. Where the two overlap the duplication
is deliberate: the whole value is a second, independent implementation
arriving at the same answer.

## The client dependency

Currently a `file:` path to a sibling `../../hx-ng` checkout. It becomes
`@hotline-ng/client@^0.1.0` from the registry the moment that version is
published — one line in `package.json`, and CI stops needing the sibling
checkout.
