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

A `file:` path to a sibling `../../hx-ng` checkout, **pinned** in CI to
the commit `hx-ng.rev` names. Locally the suite runs whatever the sibling
holds; `npm test` says so first when that is not the pinned commit, or
when `packages/hotline-ng` there has uncommitted changes, and then runs
anyway — a newer client beside you is the usual state mid-change.

Advancing the pin is a one-line commit, and a deliberate one, like the
`hxproto` pin: it moves when a test here needs something the client has
landed. A wire change goes server first — the feature with its Rust
suites, which need no client — then the client, then the pin moves here
together with the e2e cases for the feature. hx-ng's CI runs this suite
from our `main` against its own tree, so a client change that breaks it
is caught there, pin or no pin.

Once `@hotline-ng/client` is published, `package.json` names a version
instead, and CI stops needing the sibling checkout.
