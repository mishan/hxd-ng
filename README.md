# hxd-ng

A Hotline server, written from scratch in Rust, that serves the Hotline
clients of 1997 and the phones of today from one shared state — and a new
protocol, **Hotline-ng**, for the clients that want more than 1997 offered.

## What Hotline is

[Hotline](https://en.wikipedia.org/wiki/Hotline_Communications) was a
Mac-first chat, file-sharing and bulletin-board system from the late
1990s: you ran a server, people connected to it directly, and a tracker
told them where servers were. Nothing about it was centralized, which is
why it still exists. A small community still runs servers, writes clients,
and extends the protocol; [hlwiki.com](https://hlwiki.com/index.php/Clients)
keeps the list.

## What hxd-ng is

A server that speaks two wires from one roster, one set of chat rooms and
one voice room:

- **Legacy Hotline** on TCP `:5500` — the classic wire, byte-compatible
  with 1.2 and 1.5 clients and with the modern clients that speak it.
  *Never break an old client* is the rule that outranks every other, and
  an unmodified 1.5 client on an emulated Mac is the check a release has
  to pass.
- **Hotline-ng** on WebSocket `:5700` — a JSON protocol designed for
  phones: a session survives a dropped connection, private messages wait
  for you, identity is a key you carry between servers, and voice and
  video are one WebRTC connection.

Someone on a 1.5 client and someone on a phone are in the same chat,
see each other on the same user list, and send each other private
messages; neither can tell which wire the other is on. Where the ng wire
offers something the classic wire cannot carry, the classic client sees
what it always saw and nothing breaks.

## What it offers today

Three populations reach this server, and not every feature reaches all
three. **Period client** means unmodified Hotline 1.2 / 1.5 / 1.9 on the
classic wire. **Extended client** means a modern client on the classic
wire that negotiates the community's protocol extensions — today that is
[GtkHx](https://github.com/mishan/gtkhx). **ng client** means anything on
the Hotline-ng wire — today that is [hx-ng](https://github.com/mishan/hx-ng).

| | Period client | Extended client (GtkHx) | ng client (hx-ng) |
|---|---|---|---|
| Public chat, private chats, user list, private messages | yes | yes | yes |
| Kick, ban, broadcast, server notices | yes | yes | yes |
| **Chat rooms** — curated and persistent, open to everyone or to a list | by `/join` to the server account, which invites them in | the same | yes |
| **Moderation** — reports, redacting a chat line, revoking an image, purging someone's last hour | reports by `/report` to the server account; moderators get reports as messages | the same | yes |
| **Private messages that wait for you** while you are away | receives them | receives them | sends, receives, reads later, blocks |
| **Sessions that survive the network** — close the app, reopen, nothing missed | shown as away | shown as away | yes |
| **Chat history** — scrollback the server kept | — | yes | yes |
| **Any script** — names, chat and messages in UTF-8 | Mac Roman, `?` for the rest | yes | yes |
| **Images in chat**, re-encoded and metadata-stripped by the server | sees the caption | yes | yes |
| **Nick colors** — a color for your name, for the session (Colored Nicknames) | — | yes | sees them |
| **Voice chat** — one room, one UDP port, no transcoding | — | yes | yes |
| **Video** — camera and screen share on the voice connection, opt-in per stream | — | when GtkHx adds it | yes |
| **The file area** — browse, Get Info, download; upload into upload folders and drop boxes; whole folders either way; new folder, delete, rename, move, comments | yes | yes, plus files over 4 GiB and verified resume | yes, a file at a time |
| **Threaded news** — markdown, references between articles, follows, search | reads and posts as plain text; 1.2 sees one category | reads and posts as plain text | yes |
| **Push notifications** — a private message or a news reply while the app is closed | — | — | yes, as Web Push, sent by the server itself or through a uniqush-push sidecar |
| **Portable identity** — an Ed25519 key that is you on any server that runs this | through a local tunnel | through a local tunnel | yes |
| **HOPE** — the secure login, and an encrypted session after it, on the plain port | — | yes | — (always TLS, through the proxy) |
| **TLS** on the classic wire, on a port of its own | — | yes | — (always TLS, through the proxy) |
| **Server linking** — other servers' users, public chat and private messages, on fogWraith's linked network | yes, as users of this server | the same | the same |
| **Tracker listing** — announced to HTRK v1 and v3 trackers | found through the tracker | found through the tracker | — (connects by address) |

No official Hotline software ever had voice or video; they are community
extensions, and today GtkHx and hx-ng are the two clients that speak them.
Between them that is voice on Linux, macOS and Windows desktops and in
the browser on a phone, in one room. Video is in hx-ng now and reaches
GtkHx when its rendering lands.

**Not built yet, and worth knowing before you run this:**

- **Aliases, and folder transfers on the ng wire.** This server refuses
  to make an alias, and an ng client moves files one at a time. What is
  built is in [docs/files-plan.md](docs/files-plan.md).
- **Standing and vouching.** A server applies what the registrars it
  trusts publish — revocations, rotations and freezes
  ([docs/identity-records.md](docs/identity-records.md)) — but standing,
  probation and vouches
  ([docs/identity-registrar.md](docs/identity-registrar.md) §7.5,
  [docs/identity-vouch.md](docs/identity-vouch.md)) are design, and so is
  a registrar's key backup.
- **Importing another server's news.** mhxd's and Mobius's news cannot
  be brought over yet ([docs/news.md](docs/news.md) §12.6).

If you need a complete classic Hotline server today,
[Mobius](https://github.com/jhalter/mobius) is the one to run. If you want
the ng wire — phones, surviving sessions, offline messages, voice with
GtkHx — this is the only server that has it.

## What it aims to offer

The [roadmap](ROADMAP.md) in one paragraph: what is left of parity with
a period server is mostly moving one over, the news an mhxd or Mobius
server kept included. Then the pieces that make the ng wire a real mobile
experience — a native app, and the APNs and FCM devices the push
gateway keeps a place for. Then federation: signed ban lists a server
can subscribe to, vouches that let a member bring someone in without
opening the door ([docs/identity-vouch.md](docs/identity-vouch.md)), and
identities that carry standing between servers. Clustering comes last,
because the session model has to be right before it is spread across
nodes.

The protocol is meant to be shared. Every ng document is written to be
implemented by someone else, and the community's other protocol work —
[fogWraith's extensions](https://github.com/fogWraith/Hotline), which
this server implements on the classic wire, and the
[hotline-rs](https://github.com/hotline-rs) crates — is what this project
is converging with rather than competing against.

## Clients

Any Hotline client connects to the classic wire. The ones with a current
maintainer:

| Client | Platforms | Wire | Notes |
|---|---|---|---|
| [GtkHx](https://github.com/mishan/gtkhx) | Linux, macOS, Windows | classic, with extensions | Voice, inline images, chat history, UTF-8, TLS, large files. The reference for the extended tier above |
| [hx-ng](https://github.com/mishan/hx-ng) | any browser, including phones | ng | Chat, user list, private messages, news, files, identity, voice and video. Static files; put it in front of your server |
| [Hotline Navigator](https://hotlinenavigator.com/) | macOS, Windows, Linux, iOS, Android | classic | A modern cross-platform client with TLS and inline previews; [source](https://github.com/fuzzywalrus/Hotline-Navigator) |
| [Hotline](https://github.com/mierau/hotline) by Dustin Mierau | macOS, iOS, iPadOS | classic | A remake by the original author |
| [Hermes](https://github.com/fogWraith/Hotline) by fogWraith | — | classic, with extensions | Alpha, alongside the Janus server and the extension specs |
| Hotline 1.2 / 1.5 / 1.9 | classic Mac OS, Windows | classic | The originals, on real or emulated hardware. Still the compatibility bar |

Voice and video need a client that speaks the extensions or the ng wire:
GtkHx or hx-ng.

A browser cannot open TCP, so it cannot reach a server that speaks only
the classic wire. `hlrelay`, built from this workspace, runs beside such
a server — hxd 0.x, mhxd, Janus, Mobius, anything — and carries
WebSockets to its ports, so that a web client can (`docs/relay.md`).
hxd-ng serves the same paths on its ng port and does not need one.

## Quick start

The image is the easy way to run it as a service: each merge to main
publishes `ghcr.io/mishan/hxd-ng`, configured from environment
variables and meant to sit behind nginx or another TLS-terminating
proxy. [docs/docker.md](docs/docker.md) has the variables, the ports and
the proxy. The same image runs `hlrelay` in front of a classic server,
with `HXD_MODE=relay`.

From a checkout, with a Rust toolchain and cmake
([docs/operating.md](docs/operating.md#build-prerequisites)):

```sh
cargo run --bin hxd                                  # listens on 0.0.0.0:5500
cargo run --bin hxd -- --config /path/to/hxd-ng.toml
```

Every config key is optional, and a server with no config file at all is a
working legacy-only server. The first run creates `accounts/` (mode 0700)
with a guest account; add more as TOML files in that directory, or with
`hxd account add`.

**Say hello.** Point [GtkHx](https://github.com/mishan/gtkhx), or any
other Hotline client, at `127.0.0.1:5500`. For the ng wire, give the
server an `[ng]` section and run [hx-ng](https://github.com/mishan/hx-ng)
from its checkout with `npm install && npm run dev`, which serves it on
<http://localhost:5701>, bound to every interface so a phone on the LAN
can reach it; a server of your own serves its static build
instead ([docs/operating.md](docs/operating.md#serving-hx-ng)). The two
clients in the same room, one on each wire, is the check worth running
before believing any of this. To see the protocol rather than use it,
`node tools/ng-client.mjs ws://127.0.0.1:5700 --login alice --password pw`
is a terminal ng client (Node 22+, or `cd tools && npm install` once for
the `ws` fallback; `/drop` tests detach and resume, `/logout` leaves),
and `tools/ng-voice.html`, against a server with `[voice]`, joins the
lobby's voice room, with video when `[voice.video]` is on, from a single
file.

## Documentation

- [docs/operating.md](docs/operating.md) — running a server: install,
  ports, the proxy, accounts, backups, SIGHUP, and every config key.
- [docs/docker.md](docs/docker.md) — the image and its variables.
- [docs/README.md](docs/README.md) — every document: the protocol specs,
  the designs, and what this server has built of each.
- [ROADMAP.md](ROADMAP.md) — the plan and where each phase stands.

## Development

[AGENTS.md](AGENTS.md) is the map of the workspace — which crate owns
what, the invariants that matter, the conventions this repo is written
to, and the full set of checks CI runs. Load testing — `hxd-load`, its
scenarios and the invariants it checks under load — is in
[docs/load-testing.md](docs/load-testing.md).
