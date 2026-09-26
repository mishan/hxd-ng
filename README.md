# hxd-ng

A Hotline server, written from scratch in Rust, that serves the Hotline
clients of 1997 and the phones of today from one shared state — and a new
protocol, **Hotline-ng**, for the clients that want more than 1997 offered.

## What Hotline is

[Hotline](https://en.wikipedia.org/wiki/Hotline_Communications) was a
Mac-first chat, file-sharing and bulletin-board system from the late
1990s: you ran a server, people connected to it directly, and a tracker
told them where servers were. Nothing about it was centralised, which is
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
| **Moderation** — reports, redacting a chat line, revoking an image, purging someone's last hour | reports by `/report` to the server account; moderators get reports as messages | the same | yes |
| **Private messages that wait for you** while you are away | receives them | receives them | sends, receives, reads later, blocks |
| **Sessions that survive the network** — close the app, reopen, nothing missed | shown as away | shown as away | yes |
| **Chat history** — scrollback the server kept | — | yes | yes |
| **Any script** — names, chat and messages in UTF-8 | Mac Roman, `?` for the rest | yes | yes |
| **Images in chat**, re-encoded and metadata-stripped by the server | sees the caption | yes | yes |
| **Voice chat** — one room, one UDP port, no transcoding | — | yes | yes |
| **Video** — camera and screen share on the voice connection, opt-in per stream | — | when GtkHx adds it | yes |
| **The file area** — browse, Get Info, download; upload into upload folders and drop boxes | yes | yes, plus files over 4 GiB and verified resume | browse and download |
| **Threaded news** — markdown, references between articles, follows, search | reads and posts as plain text; 1.2 sees one category | reads and posts as plain text | yes |
| **Push notifications** — a private message or a news reply while the app is closed | — | — | yes, as Web Push |
| **Portable identity** — an Ed25519 key that is you on any server that runs this | through a local tunnel | through a local tunnel | yes |
| Kick and ban | yes | yes | yes |
| **TLS** on the classic wire, on a port of its own | — | yes | — (always TLS, through the proxy) |
| **Tracker listing** — announced to HTRK v1 and v3 trackers | found through the tracker | found through the tracker | — (connects by address) |

No official Hotline software ever had voice or video; they are community
extensions, and today GtkHx and hx-ng are the two clients that speak them.
Between them that is voice on Linux, macOS and Windows desktops and in
the browser on a phone, in one room. Video is in hx-ng now and reaches
GtkHx when its rendering lands.

**Not built yet, and worth knowing before you run this:**

- **The rest of the file area.** Folder downloads and uploads, and
  file management — delete, rename, move, new folder, setting a comment —
  on either wire; uploads on the ng wire. What is built is in
  [docs/files-plan.md](docs/files-plan.md).
- **Servers reading a registrar's records.** The registrar itself is
  built — it gives a key a name like `alice@hl.example` and publishes
  revocations, rotations and freezes — but a server does not yet fetch
  and apply what a registrar publishes
  ([docs/identity-registrar.md](docs/identity-registrar.md) §7). Until it
  does, a server trusts attestations only from the registrars named in
  `[identity] registrar_keys`, and a registrar's revocations stop a key
  only at the registrar.

If you need a complete classic Hotline server today,
[Mobius](https://github.com/jhalter/mobius) is the one to run. If you want
the ng wire — phones, surviving sessions, offline messages, voice with
GtkHx — this is the only server that has it.

## What it aims to offer

The [roadmap](ROADMAP.md) in one paragraph: folder transfers and the rest
of the file area, so that a period client gets everything a period server
gave it. Then the pieces that make the ng
wire a real mobile experience — the registrar, and the enrollment
flow that certifies a phone without a paste. Then federation: signed
ban lists a server can subscribe to, vouches that let a member bring
someone in without opening the door
([docs/identity-vouch.md](docs/identity-vouch.md)), and identities that
carry standing between servers. Clustering comes last, because the
session model has to be right before it is spread across nodes.

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
| [hx-ng](https://github.com/mishan/hx-ng) | any browser, including phones | ng | Chat, user list, private messages, news, identity, voice and video. Static files; put it in front of your server |
| [Hotline Navigator](https://hotlinenavigator.com/) | macOS, Windows, Linux, iOS, Android | classic | A modern cross-platform client with TLS and inline previews; [source](https://github.com/fuzzywalrus/Hotline-Navigator) |
| [Hotline](https://github.com/mierau/hotline) by Dustin Mierau | macOS, iOS, iPadOS | classic | A remake by the original author |
| [Hermes](https://github.com/fogWraith/Hotline) by fogWraith | — | classic, with extensions | Alpha, alongside the Janus server and the extension specs |
| Hotline 1.2 / 1.5 / 1.9 | classic Mac OS, Windows | classic | The originals, on real or emulated hardware. Still the compatibility bar |

Voice and video need a client that speaks the extensions or the ng wire:
GtkHx or hx-ng.

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

To run it as a service instead, the `Dockerfile` builds an image
configured from environment variables, meant to sit behind nginx or
another TLS-terminating proxy; each merge to main publishes it as
`ghcr.io/mishan/hxd-ng`. [docs/docker.md](docs/docker.md) has the rest.

### Say hello

The best end-to-end check is a real client, and there is one for each
wire.

**[GtkHx](https://github.com/mishan/gtkhx)** speaks the classic wire — point
it at `127.0.0.1:5500`. So does any other Hotline client; GtkHx is the one
that will also show you voice and inline images.

**[hx-ng](https://github.com/mishan/hx-ng)** is the browser client for the
ng wire. It needs an `[ng]` section in the server's config (below):

```sh
git clone https://github.com/mishan/hx-ng && cd hx-ng
npm install && npm run dev     # http://localhost:5701, bound to every
                               # interface so a phone on the LAN can reach it
```

The two clients in the same room, one on each wire, is the check worth
running before believing any of this.

The repo also ships two deliberately minimal harnesses, for when you want
to see the protocol rather than use it. `tools/ng-client.mjs` is a terminal
ng client — no install on Node 22+; on older Node, `cd tools && npm install`
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

### Banner

An optional `[banner]` section gives the server a banner, the image a
1.5+ client shows above its windows. It is sent after the agreement,
as mhxd sends it. A banner file is held here and fetched over HTXF, on
the files port whether or not `[files]` is on (and on the TLS transfer
port with `[tls]`); a URL alone has the client fetch the image itself.

```toml
[banner]
file = "banner.jpg"               # JPEG, GIF or PNG, at most 1 MiB
url = "https://hl.example/"       # with file: where a click goes;
                                  # alone: where the image is, and
                                  # then it must be http(s)
```

Classic clients show JPEG and GIF. The file is re-read on SIGHUP, and
one that no longer loads leaves the banner in use as it was. A client
connected through the `/trtp` tunnel fetches a held banner through
`/htxf`, which `hlid tunnel` serves on its own port plus one. ng clients
are told of the banner in the login reply and fetch a held one with
`GET /banner` on the ng port (`docs/banner.md`).

### TLS on the legacy wire

An optional `[tls]` section opens a second control port that speaks TLS
from its first byte and the unchanged Hotline protocol inside it — the
separate-port model GtkHx, Janus and Mobius share. Period clients keep
the plaintext port; a client that speaks TLS connects here instead, and
its session is marked encrypted, as a tunnelled one is. With `[files]`
or a banner file, a TLS transfer port sits one above the TLS control
port, where a client looks for it.

```toml
[tls]
bind = "0.0.0.0:5600"
cert = "/etc/hxd-ng/tls/fullchain.pem"  # PEM chain, leaf first
key = "/etc/hxd-ng/tls/privkey.pem"
# files_bind = "0.0.0.0:5601"  # default: bind's port + 1
# self_signed = false          # see below
```

**Use a certificate from Let's Encrypt when you can.** A server with a
DNS name can have one for free, and a client checks it against the CAs
it already trusts, so users connect without being asked anything and a
changed certificate is not a warning they learn to click through.
certbot issues it (`certbot certonly --standalone -d hl.example`, or
`--webroot` when something already serves port 80), and renews it every
couple of months.

certbot keeps its files where only root can read them, so a server
running as its own user reads a copy. A deploy hook makes the copy at
every renewal and sends SIGHUP, which puts the new certificate in
service without dropping anyone. Save it as
`/etc/letsencrypt/renewal-hooks/deploy/hxd-ng.sh`, make it executable,
and run it once by hand for the first copy:

```sh
#!/bin/sh
live=/etc/letsencrypt/live/hl.example
install -D -m 644 -o hxd "$live/fullchain.pem" /etc/hxd-ng/tls/fullchain.pem
install -D -m 600 -o hxd "$live/privkey.pem" /etc/hxd-ng/tls/privkey.pem
systemctl reload hxd 2>/dev/null || pkill -HUP -x hxd || true
```

**Self-signed, when there is no name.** A server reached only by
address cannot get a CA's certificate, and a client can then only pin
the one it is shown on first connect. `self_signed = true` makes a pair
at `cert` and `key` on the first start that finds neither, and keeps it
after, so the pin stays good across restarts. It is off by default,
and a pin is only as good as the fingerprint users compare it against.
Replacing both files with a CA's pair later is all it takes to move
off it — clients that pinned the old one will warn once.

The server logs the certificate's SHA-256 fingerprint at start; with a
self-signed certificate, publish it so users can check the pin their
client makes. SIGHUP re-reads both
files, so a renewed certificate reaches the next connection without
dropping anyone. A v3 tracker listing carries the TLS port
(`advertised_tls_port` in `[tracker]` overrides it).

### Tracker registration

An optional `[tracker]` section announces the server over UDP using classic
HTRK v1 or the metadata-bearing v3 protocol. Targets name their protocol
explicitly because a silent v1 UDP tracker cannot be probed for v3. See
[docs/tracker-registration.md](docs/tracker-registration.md) for the complete
metadata and security configuration.

```toml
[tracker]
description = "A small Hotline community"
interval = 300
# advertised_port = 5500  # only when NAT maps a different public port
# advertised_tls_port = 5600  # the same for [tls], on v3 targets

[[tracker.targets]]
address = "hltracker.example" # UDP/5499 when the port is omitted
protocol = "v1"

[[tracker.targets]]
address = "argus.example:5499"
protocol = "v3"
hmac_secret = "shared secret"
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
# and nowhere else. Caddy and nginx configurations that set that header
# correctly: docs/hotline-ng-auth-rationale.md §6.1.
# trusted_proxies = ["127.0.0.1"]

# Which header that proxy writes the client address into:
# x-forwarded-for | forwarded | none. The rightmost element outside
# trusted_proxies is the client (docs/hotline-ng-auth.md §6.3).
forwarded_header = "x-forwarded-for"
```

### Files

Absent means neither wire advertises Files and the HTXF listener is not
opened. Choose exactly one source mode. The manifest mode is read-only: only
the configured HTTP(S) origin may provide bytes, so no client or manifest row
can turn the server into an arbitrary-URL proxy. See
[docs/files-plan.md](docs/files-plan.md).

```toml
[files]
manifest = "files.json"
origin = "https://downloads.example/files/"
# bind = "0.0.0.0:5501"       # default: [server] bind, port plus one
max_file_size = 68719476736   # per object
max_entries = 100000
max_concurrent = 8            # origin responses streamed at once
request_timeout = 15          # origin connect/request seconds
reference_ttl = 60            # unclaimed HTXF references
max_references = 4096         # outstanding HTXF references globally
max_references_per_session = 64
max_references_per_account = 256  # across all of one account's sessions
download_ttl = 60             # ng bearer URLs; reusable for resume
max_downloads = 4096          # outstanding ng bearer URLs globally
max_downloads_per_session = 64
max_downloads_per_account = 256
handshake_timeout = 10        # HTXF preamble seconds
idle_timeout = 60             # a download whose receiver stops reading, either wire
```

Listing and Get Info are the account's `[extra] file_list` and
`file_getinfo`, which are on unless the account file turns them off, as on
mhxd; downloading needs `download_files`. A download ends with the session that
asked for it, and an HTXF transfer must come from the address of a direct
control connection.

A local root enables FilePut. As on mhxd, an account with `upload_files` may
upload into any folder whose path names an upload folder or a drop box
(`Uploads`, `Drop Box`, in any case), and one that also has `upload_anywhere`
may upload anywhere. A drop box's contents are listed only to accounts with
`view_drop_boxes`. Existing files are never overwritten. Uploads are staged in
an internal mode-0700 directory, scoped by account and destination, and become
visible through an atomic no-replace link only after the transfer has arrived
and validated. Client paths are resolved beneath an open directory capability
without following symlinks; absolute paths, traversal, symlinks, and the
internal state path, however it is spelled, are not reachable through either
protocol.

```toml
[files]
root = "/srv/hxd/files"        # must already exist
# bind = "0.0.0.0:5501"
max_file_size = 68719476736   # data and resource forks combined
max_entries = 100000
max_concurrent = 8
max_partial_bytes = 68719476736
max_partials = 1024          # global abandoned/in-progress upload cap
max_partials_per_account = 4
request_timeout = 15          # each local read/write must make progress
upload_timeout = 3600         # hard wall-clock limit for one upload
partial_ttl = 604800          # abandoned partials, seconds
reference_ttl = 60
download_ttl = 60
handshake_timeout = 10
```

The local source keeps Finder metadata and resource forks in CAP-format records
under `.hxd-state`; that directory is reserved to the server and omitted from
listings. Large File uploads use raw bytes. A resumed one is accepted only when
the client echoes the server's SHA-256 digest for the exact stored offset and
trailing window. Folder upload and general file mutation remain separate work.

An interrupted upload stays unlisted until it completes, where mhxd shows the
truncated file. A classic client that offers to resume only when it sees the
file on the server therefore starts over; one that asks to resume anyway is
given the stored offset. An account at `max_partials_per_account` gives up its
least recently touched partial to make room for a new upload, and a partial
with nothing in it is dropped when its transfer ends.

The manifest schema is deliberately small and strict. Sizes are decimal
strings so its shape agrees with the ng wire:

```json
{
  "version": 1,
  "files": [
    {
      "path": "manuals/read me.txt",
      "size": "12",
      "media_type": "text/plain",
      "etag": "\"release-7\"",
      "ranges": true,
      "created": 123,
      "modified": 456,
      "comment": "Start here"
    }
  ]
}
```

When `etag` is present, every origin response must return that exact ETag.
`ranges = true` promises the origin honors open-ended byte ranges and returns
the corresponding `Content-Range`; a mismatch fails the transfer closed.

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

# Keys refused by hand, no registrar needed: an identity (every device of
# it) or one device. `hxd identity revoke` below writes these for you.
# revoked_identities = ["<fingerprint>"]
# revoked_devices = ["<fingerprint>"]

# Access bits for accounts "create" makes — same key names as an account
# file's [access]. Absent means whatever guest has, which is rarely right.
# [identity.default_access]
# read_chat = true
# send_chat = true
```

**Revoking a stolen key.** The only other remedy for a stolen device key is
its certificate's expiry, which is months. On this server, today:

```sh
hxd identity revoke <fingerprint>            # an identity: every device of it
hxd identity revoke --device <fingerprint>   # one device, leaving the others
hxd identity revoke --lift <fingerprint>     # undo either
systemctl reload hxd                         # or kill -HUP: applies it
```

The command edits the config file in place, keeping its comments, and
refuses to write one the server would not load. While it runs it holds
`<config>.revoke` beside the file, so a second one at the same moment is
refused rather than losing an entry; if a command is killed and leaves
that file behind, remove it. Fingerprints are the
52-character form `hlid inspect` and `hlid keygen` print. Nothing changes
in the running server until SIGHUP, which re-reads these two lists and
nothing else (a file that fails to load, or has gone missing, leaves the
lists as they were): every session the key holds, connected or waiting to
resume, ends then, its next login is refused with `revoked`, and nobody
else is dropped. An account whose linked identity is revoked can still
log in with its password.

### The registrar

A server can also be an identity registrar: it lends keys handles like
`alice@hl.example`, and publishes the revocations, rotations and freezes
that concern them. Needs `[identity]`. See
[docs/identity-registrar.md](docs/identity-registrar.md).

```toml
[registrar]
host = "hl.example"          # the name attestations carry; this server's
                             # discovery must be reachable at
                             # https://hl.example/.well-known/hotline
key = "registrar.key"        # its own signing key, apart from the server
                             # key; generated on first run
store = "registrar.db"       # SQLite, a file of its own
signup = "proof"             # open | proof | closed
# proof = "invite"           # what signup = proof asks for; "none" with open
invites = "registrar-invites"  # codes, one per line; read at start and SIGHUP
# proof_url = "https://hl.example/invite"   # where to ask for one
# level = 2                  # written into attestations; 2 for invites, 0 open
attestation_days = 365
hold_days = 365              # how long a lapsed name waits for its owner
handle_min = 3
handle_max = 32
# reserved = ["staff"]       # beside the built-in list and every account login
# rotation_delay = 86400     # hold a rotation back so a freeze can meet it

# [registrar.rate]
# registrations_per_address = 5     # an hour
# registrations_per_hour = 120      # registrar-wide; renewals don't count
# records_per_identity = 20         # an hour
# lookups_per_minute = 60           # per address
```

The operator's side, acting on the store the running server uses:

```sh
hxd registrar invites --add 10                  # print ten new invite codes
hxd registrar freeze <fingerprint>              # a holder reports a theft
hxd registrar freeze --lift <fingerprint>
hxd registrar revoke <handle> --reason abuse    # withdraw the name
hxd registrar recover <handle> --identity <fingerprint> [--keep-age]
hxd registrar inspect other.example             # verify another registrar's
                                                # log and stats, and show its
                                                # last month
```

And the user's, with `hlid`:

```sh
hlid register --registrar hl.example --handle alice --proof ABCD-EFGH-JKMN-PQRS --successor-commit
hlid revoke --registrar hl.example --device-cert lost-phone.cert --reason stolen
hlid rotate --registrar hl.example --to ~/.hlid/successor.key
```

`register` puts the attestation into your card and publishes the card
at the registrar. `--successor-commit` makes a successor key and commits
to it, which is what lets you rotate to it later — and stops a thief
with your identity key from rotating anywhere else. A server that
should trust the registrar's names lists its key in
`[identity] registrar_keys`.

Discovery names the registrar only when it is asked for under `host`,
so a verifier never finds the key under a name that did not publish it.
Behind a reverse proxy that means forwarding the `Host` header as the
client sent it (`proxy_set_header Host $host;` in nginx); a proxy that
rewrites it to the backend's address leaves the `registrar` block
`null`.

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
shares its SQLite connection; with neither it is required. A 1.5 client
browses the same tree over the threaded-news transactions, reading a
markdown article's plain-text part. A 1.2 client reads and posts into the
one category `flat_category` names, rendered newest first as a single
document; without it, a 1.2 client is told this server's news is
threaded. `flat_category` splits on `/`, so a category whose own name
contains one cannot be named there. See [docs/news.md](docs/news.md) §12.

```toml
[news]                    # presence turns it on
# db = "messages.db"      # required only without [inbox] or [history]
max_body = 65535          # the legacy NEWSDATA ceiling; ↓ freely, ↑ never
max_subject = 255         # the 1.5 pstring
markdown = "render"       # or "source", or "off"; see below
max_refs = 32             # references recorded per article; past that, text
max_depth = 32            # reply nesting
max_node_depth = 16       # bundle nesting
max_page = 200            # threads in one request
retain_days = 0           # a thread's life after its last post; 0 = forever
self_delete = true        # authors may delete their own; false = period behavior
search = true             # false turns news_search off; the index is kept either way
search_max_results = 500  # the deepest a search pages
search_per_minute = 30    # searches per session
legacy_catlist_max = 2000 # articles in one 1.5 category listing

flat_category = "General" # the 1.2 view: names from the root, "Bundle/Category"
flat_articles = 100       # entries in the 1.2 document; 65 535 bytes usually decides
flat_reply = "newest_thread"   # where a post with no Re: goes, or "new_thread"
flat_default_subject = "(no subject)"
# flat_masthead = "..."   # the line above the entries; absent = built in, "" = none;
                          # at most 4096 bytes

blobs = "news-blobs"      # durable content-addressed attachment bytes
[news.attach]              # absent = attachments off
max_bytes = 2097152        # one uploaded image
max_count = 8              # images on one article
max_total_bytes = 8589934592
stage_ttl = 1800           # abandoned upload lifetime, seconds
per_hour = 20              # staged images per account
legacy_derivative = true   # make the bounded still a 1.5 image part will serve

[news.notify]                   # absent = no subscriptions, no notifications
auto_subscribe = "participated" # or "own_thread", or "off"
reference = true                # does citing someone's article notify them
max_subs = 200                  # threads and categories followed or muted, per account
max_per_hour = 12               # news pushes per account; 0 = badges, no pushes
stale_after = 604800            # seconds behind before a scope rings again anyway; 0 = never
```

`markdown` decides what an article written in markdown gets. `render`
accepts it and parses it once, at post time, for the plain-text downgrade
that search reads and a legacy client will be given, and for the
references its `news:` links make. `source` accepts and stores it and
parses nothing; `off` takes plain text only. The default is `render` in a
build with the `markdown` feature and `off` in one without, where asking
for `render` is a startup error. Under `render`, a body whose lists and
quotes nest deeper than a parse can afford is refused.

`[news.notify]` needs no feature and no gateway: an attached client gets
its badge and its `news_notify` either way, and only the push to a device
with no session open is missing — no gateway delivers one yet. A guest
follows nothing; subscriptions are kept against the account, by the same
rule as the inbox.

`[news.attach]` needs the `media` image pipeline and the SQLite `inbox`
feature. Uploads are canonicalized and staged before a post; the post binds
their handles atomically. Staging permission defaults to the account's
`send_media` bit and can be overridden with `[extra] attach_news`; a guest
never stages, since a staged image belongs to the person who uploaded it.
News images go through the same pipeline as chat's: `[media]`'s dimension,
pixel and frame caps and its `max_concurrent_decodes` hold for both, and
only the byte ceiling is `[news.attach]`'s own.

Who may read, post, delete and rearrange is the account's news bits —
`read_news`, `post_news`, `delete_articles` and the category and bundle
bits in [docs/access-bits.md](docs/access-bits.md). An article is its
author's to delete only when one person is behind the account, a password
or a linked identity; a guest's belongs to nobody.

### Avatars

An optional `[avatars]` section lets users set a picture that every
client can show without an icon set: fogWraith's GIF Icons extension on
the legacy wire, the `avatars` capability on the ng one, and one avatar
crossing between them. An avatar belongs to the account (or to a guest's
proven identity) and is kept in the shared database, so it is there at
the next login. Uploads go through the inline-media pipeline, so this
needs the `media` feature. See [docs/avatars.md](docs/avatars.md).

```toml
[avatars]                 # presence turns it on
max_bytes = 262144        # the largest upload, on either wire
max_dimension = 128       # what an avatar is fitted to
legacy_max_bytes = 32768  # the GIF legacy clients are sent
set_interval = 10         # seconds between one session's changes
# db = "avatars.db"       # default: [inbox], [history] or [news]'s database
```

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

### Push notifications

Absent means no notifications leave the server: the ng wire offers no
`push` capability, a client never asks its user for permission, and
`push_register` is answered `not_available`. Present, the server is its
own Web Push sender — no sidecar and no third-party service — and what
it sends is encrypted to each device's own key, so the push service
relays ciphertext it cannot read. See
[docs/webpush-gateway.md](docs/webpush-gateway.md).

```toml
[push]                                # presence turns it on
contact = "mailto:admin@example.org"  # required; a push service may refuse a push without one
content = "sender"                    # full | sender | generic
vapid_key = "vapid.key"               # created on first start, mode 0600
db = "server.sqlite"                  # default: the file [inbox], [history] or [news] names, in that order; required with none of them
timeout = 10                          # seconds to wait for a push service, name lookup included
message_ttl = 2419200                 # how long it holds a private message's notification
news_ttl = 86400                      # the same for a news notice
breaker_failures = 5                  # failures before a push service is skipped
breaker_cooldown = 60                 # seconds it stays skipped
max_inflight = 64                     # pushes in flight at once
max_inflight_per_origin = 8           # of those, to any one push service
max_devices = 20                      # devices one account may register
allow_private_endpoints = false       # for an operator running their own push service
```

**`vapid_key` is the server's identity to every push service its users
subscribed through.** Every subscription is bound to it, so losing the
file or replacing it silently means every push is accepted by nobody and
no client can tell why. Back it up with the accounts directory. A server
whose key file is missing while devices are registered refuses to start
rather than mint a new key over them — restore the file, or point
`vapid_key` back at it. Rotating it deliberately is `hxd push rekey`
with the server stopped: it writes a new key and drops every registered
device, which the old key's subscriptions were bound to, and every
client re-subscribes at its next login.

`content` decides how much of a message leaves the server. On Web Push
the payload is encrypted to the device's own key and the push service
cannot read it, which makes `full` defensible; the default is `sender`
because a notification on a lock screen is read by whoever is looking at
it.

### The server account

Absent means no account on the roster and no commands: a private message
is a private message on every wire. Present, a reserved account sits on
the user list, and a private message to it is a command line — which is
the only place the server reads text as anything but text. **Public chat
is never parsed**, on any wire: a 1.5 user typing `/report` into the chat
box gets chat, because that is what they asked for. See
[docs/system-account.md](docs/system-account.md).

```toml
[system]              # presence turns it on
login = "server"      # reserved: nobody can log in as it
nick = "Server"       # what the user list shows
icon = 0
commands = true       # false leaves the account and answers with one line
rate = 10             # commands a minute, per session
```

It is what makes a period client able to do things its wire cannot
express: `/msg <login> <message>` reaches an account whether or not it is
online, which a 1.5 client's user list has no way to name, and
`/report <nick or login> <reason>` tells the moderators about someone.
`/help`, `/block`, `/unblock`, `/blocks` and `/stop` are the rest of what
it answers today.

### Moderation

Always on: kick and ban never needed a database, and neither do reports
— on a server with none they last until it stops. Where `[inbox]`,
`[history]` or `[news]` names a database (in that order), the audit
trail and the reports are kept there. Who moderates is `[extra] moderate`
in the account file, which defaults to the kick bit (`disconnect_users`).
The section is optional; these are its defaults. See
[docs/moderation.md](docs/moderation.md).

```toml
[moderation]
evidence_days = 30    # how long a redacted line's words stay readable to moderators
report_days = 90      # how long a closed report is kept
pin_days = 7          # how long a reported image may outlive its handle
notify_legacy = true  # reports as private messages to moderators on the classic wire
kick_purges = 0       # seconds of a kicked user's output a classic kick takes; 0 = none
```

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
through the tunnel with your identity. The tunnel also listens on the port
after it (`127.0.0.1:5501`), where the client looks for file transfers and
the banner, and carries each of those to the server's `/htxf`. That login can link an account too
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
and its news subscriptions behind for whoever registers that login next — so
take them with the account:

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

### Moderation

Moderators act from an ng client. The same acts, the reports and the
audit trail are reachable from the command line, as `cli`, against the
database directly — so they work with the server down, and a running
server sees the change on its next read:

```sh
hxd reports                                  # what is open; --all for everything
hxd reports close 17 --outcome dismissed     # or duplicate --of 12; --note says why
hxd history redact 4711 --reason "slur"      # blank a public line, keep its words for moderators
hxd purge bob --since 1h --reason "spam run" # redact bob's lines and delete his articles
hxd purge bob --since 1h --reason x --dry-run
hxd moderation log                           # the audit trail, newest first
```

Images live in the running server's memory, not in the database, so
revoking one — and a purge's images — is an ng moderator's to do; `hxd
media revoke` says so rather than pretending.

### Voice

Voice needs its **UDP** port reachable — the one thing operators most often
miss. Video rides that same port and that same peer connection, so there is
no second socket to open, and it is off unless `[voice.video]` is present.

Video is opt-in on both sides at runtime too: nobody publishes until they
ask, and nobody receives a stream until they ask for that stream in
particular, so a room with video in it costs a voice-only participant
nothing.

### Cargo features

`voice`, `inbox`, `media`, `markdown` and `push` are all on by default, so
CI covers them. The `inbox` feature supplies the shared SQLite store for
the inbox, history, news and devices; `media` supplies the image pipeline;
`markdown` supplies the parser behind `[news] markdown = "render"`; `push`
supplies the Web Push sender, and needs `inbox` for the store its devices
live in. Building without one leaves its dependency out of the binary
entirely — no WebRTC stack, no bundled SQLite, no image decoder, no
markdown parser, no TLS client — and the matching config section, or for
`markdown` the `render` mode, then becomes a startup error rather than a
promise the build cannot keep.

`metrics` is off by default: it serves the server's own numbers at
`GET /metrics` on the ng port, for load tests and dashboards, once a
`[metrics]` section asks for them (`docs/metrics.md`). `console` adds
tokio-console, and needs `RUSTFLAGS="--cfg tokio_unstable"` as well.

## Documentation

The ng protocol documents are written to be implemented by someone
other than this server. The last column is what this server has built.

| Document | What it covers | Built |
|---|---|---|
| [hotline-ng.md](docs/hotline-ng.md) | The ng protocol: framing, the login/resume/sync handshake, the request and event tables, seq accounting | yes |
| [hotline-ng-rationale.md](docs/hotline-ng-rationale.md) | The reasoning behind the ng protocol, its domain-layer changes and the order it was built in | yes |
| [hotline-ng-auth.md](docs/hotline-ng-auth.md) | Transport authentication: the principal, the challenge and mTLS bindings, transport tokens, the TRTP tunnel, cleartext marking, tunnels and relays | yes |
| [hotline-ng-auth-rationale.md](docs/hotline-ng-auth-rationale.md) | The reasoning behind transport authentication, and working Caddy and nginx configurations for the mTLS binding | yes |
| [hotline-ng-identity.md](docs/hotline-ng-identity.md) | Portable identity: the signed objects, the identity profile at authentication, cards, account association | yes, to the registrar stub |
| [identity-enrollment.md](docs/identity-enrollment.md) | Certifying a device through a mailbox and a pairing code instead of a paste; renewal | server side |
| [identity-registrar.md](docs/identity-registrar.md) | The registrar: handles, revocation, rotation, freeze, key backup, transparency; what a server does with it | the server-local revocation list |
| [identity-vouch.md](docs/identity-vouch.md) | A member lending standing to a key: rules, the local and portable forms, accountability | no |
| [identity-threat-model.md](docs/identity-threat-model.md) | What identity defends against, and what it deliberately does not | — |
| [identity-test-vectors.json](docs/identity-test-vectors.json) | Signed objects and reject cases — the contract a second implementation is checked against | yes |
| [system-account.md](docs/system-account.md) | The reserved server account: where commands and notifications live on the classic wire | no |
| [access-bits.md](docs/access-bits.md) | Account permissions: every access bit and its `[access]` key, the reserved numbers, `[extra]` policy | yes |
| [private-messages.md](docs/private-messages.md) | The offline inbox: the mailbox rule, the store contract, delivery, blocking, retention | yes |
| [chat-history.md](docs/chat-history.md) | Scrollback: the chat log, cursor paging on both wires, retention | yes |
| [news.md](docs/news.md) | Threaded news: the tree, articles and references, the store, the ng requests, search, subscriptions, markdown, and the legacy binding | ng wire |
| [inline-media.md](docs/inline-media.md) | Images in chat: the re-encode pipeline, handles and relay-time authorisation, 750/751 and the HTTP routes | yes |
| [moderation.md](docs/moderation.md) | Redaction, revocation, purges and reports: the acts, the audit trail, and what each wire can do | yes, less vouching |
| [voice.md](docs/voice.md) | The SFU: hand-written SDP, RTP forwarding, and one room across both signalling wires | yes |
| [capabilities-video.md](docs/capabilities-video.md) | Video: publications, subscriptions, limits, and the renegotiation path | yes |
| [push-notifications.md](docs/push-notifications.md) | Push: the notify decision in the domain, and the gateway | trait only |
| [files-plan.md](docs/files-plan.md) | The file area: browsing and downloads, the local area and uploads, and the Large File capability | yes, less folders and file management |
| [proposals/](docs/proposals/messaging-identity-amendment.md) | Proposed amendments to fogWraith's messaging extension | — |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check tools/ng-client.mjs
```

That is what CI runs, beside the e2e suite and a build and smoke test
of the Docker image. [AGENTS.md](AGENTS.md) is the map of the workspace —
which crate owns what, the invariants that matter, and the conventions this
repo is written to.
