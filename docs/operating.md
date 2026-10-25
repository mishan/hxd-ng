# Running an hxd-ng server

The operator's manual: how to build and run the server, what it listens
on, how it sits behind a proxy, the commands that look after it, what to
back up, what SIGHUP reloads, and every config key. What the server is
and which clients it serves is the [README](../README.md); the container
is [docker.md](docker.md), which maps most of what follows onto
environment variables.

## Install

### Build prerequisites

A Rust toolchain. The `hxproto` wire crate is shared with
[GtkHx](https://github.com/mishan/gtkhx) through the
[hx-libs](https://github.com/mishan/hx-libs) workspace. Cargo fetches the
pinned revision automatically.

Building the voice SFU needs a C/assembly toolchain and **cmake** — the
WebRTC stack's DTLS certificate generation reaches aws-lc-sys whichever
crypto provider is selected. On Debian/Ubuntu:

```sh
apt install build-essential cmake
```

A build with `--no-default-features` leaves voice out and needs no
cmake; the TLS stack's `ring` still wants the C compiler.

### Cargo features

`voice`, `inbox`, `media`, `markdown`, `push`, `uniqush` and `feeds` are
all on by default, so CI covers them. The `inbox` feature supplies the
shared SQLite store for the inbox, history, news, moderation, avatars,
the registrar and push devices; `media` supplies the image pipeline;
`markdown` supplies the parser behind `[news] markdown = "render"`;
`push` supplies the Web Push sender, and needs `inbox` for the store its
devices live in; `uniqush` supplies the uniqush-push gateway beside it,
and needs `push`; `feeds` supplies the feed fetcher and parser, and
needs `inbox` for the articles. Building without one leaves its
dependency out of the binary entirely — no WebRTC stack, no bundled
SQLite, no image decoder, no markdown parser, no TLS client, no feed
parser — and the matching config section, or for `markdown` the
`render` mode and for `uniqush` `[push] gateway = "uniqush"`, then
becomes a startup error rather than a promise the build cannot keep.

`metrics` is off by default: it serves the server's own numbers at
`GET /metrics` on the ng port, for load tests and dashboards, once a
`[metrics]` section asks for them ([metrics.md](metrics.md)). `console`
adds tokio-console, and needs `RUSTFLAGS="--cfg tokio_unstable"` as well.

### Docker

The `Dockerfile` builds an image configured from environment variables,
meant to sit behind nginx or another TLS-terminating proxy; each merge to
main publishes it as `ghcr.io/mishan/hxd-ng`. [docker.md](docker.md) has
the rest. The same image runs `hlrelay` in front of a classic server,
with `HXD_MODE=relay` (docker.md, "Relay mode").

### Running it

```sh
cargo run --bin hxd                                  # listens on 0.0.0.0:5500
cargo run --bin hxd -- --config /path/to/hxd-ng.toml
```

The config is `hxd-ng.toml` in the working directory unless `--config`
names another, and every relative path in it is relative to the working
directory. Every key is optional, and a server with no config file at all
is a working legacy-only server; a file that does not parse refuses the
start rather than half-configuring one. The first run creates
`accounts/` (mode 0700) with a guest account.

```sh
HXD_DEBUG=proto cargo run --bin hxd     # comma-separated categories, or `all`
```

`HXD_DEBUG` turns on the wire trace. The format mirrors gtkhx's
`GTKHX_DEBUG=proto`, so a client trace and a server trace of the same
session line up. `RUST_LOG` wins when set.

## Ports and the network

| Listener | Default | Key | Opened |
|---|---|---|---|
| Classic Hotline, TCP | `0.0.0.0:5500` | `[server] bind` | unless `[server] classic = false` |
| HTXF file transfers, TCP | `[server] bind`'s address, its port + 1 (5501) | `[files] bind` | with `[files]` or a `[banner] file`, unless `[server] classic = false` |
| Classic Hotline over TLS, TCP | `0.0.0.0:5600` | `[tls] bind` | with `[tls]`; linked servers connect here too |
| HTXF over TLS, TCP | `[tls] bind`'s address, its port + 1 (5601) | `[tls] files_bind` | with `[tls]`, and `[files]` or a `[banner] file` |
| Hotline-ng, TCP (HTTP and WebSocket) | `127.0.0.1:5700` | `[ng] bind` | with `[ng]` |
| Voice and video media, UDP | `[server] bind`'s address, its port + 4 (5504) | `[voice] bind` | with `[voice]` |
| Tracker registration, UDP out | to port 5499 when a target names none | `[[tracker.targets]] address` | with `[tracker]` |
| Server links, TCP out | the peer's TLS port | `[[link.peer]] dial` | with `[link]` |

The classic ports speak to clients directly: no 1.x client goes through
an HTTP proxy, and the HTXF ports must stay one above their control
ports on the public side too, since a classic client finds the transfer
port by adding one to the port it connected to. The ng port is
plaintext, and belongs behind a TLS-terminating proxy (below); it serves
the WebSocket at `/` and `/ng`, discovery, the identity endpoints, the
`/trtp` and `/htxf` tunnels, media, avatars, file downloads and uploads,
`/banner`, the registrar's routes and `/metrics`. The voice port is free
to move: clients send media to the addresses `[voice] advertise` names
([Voice](#voice)).

**Serving ng clients only.** `[server] classic = false` opens none of
the classic ports: not `[server] bind`, not HTXF, and not the `/trtp`
and `/htxf` tunnels, which discovery then leaves out. A server used only
by ng clients and bots never offers the classic login, whose password is
a plaintext equivalent. `[server] bind` is still the base the voice port
derives from. Everything that only the classic wire serves is refused at
startup rather than left configured and unserved: `[tls]`, `[link]`
(links are made on the TLS port), `[tracker]` (trackers list the classic
port) and `[files] bind`. ng clients' file transfers and the banner
still come over the ng port; `hlid tunnel` has nothing to connect to.

## Behind a reverse proxy

**TLS for the ng port.** Put nginx, Caddy or another proxy in front of
`[ng] bind`, terminating TLS. It needs the WebSocket upgrade, a long read
timeout (a session's socket stays open as long as the session does), the
`Host` header, `X-Forwarded-For`, and one line that matters for
security: it must **drop any `X-Hotline-Client-Cert` header a client
sends**. [`docker/nginx.conf`](../docker/nginx.conf) does all of it.
Caddy's `reverse_proxy` does the first four by itself; add
`header_up -X-Hotline-Client-Cert`.

**`[ng] trusted_proxies`** lists the proxies, and nothing else. Behind a
proxy every connection comes from the proxy's address, so without it
every user shares one address: one ban, one detached-session allowance,
one set of per-address limits. Listed, the client's address is read from
the header `[ng] forwarded_header` names (`X-Forwarded-For` by default,
or `Forwarded`), the rightmost element outside `trusted_proxies` being
the client ([hotline-ng-auth.md](hotline-ng-auth.md) §6.3).

**The mTLS binding.** `X-Hotline-Client-Cert` is believed from a trusted
proxy and nowhere else, and a non-empty `trusted_proxies` turns the
binding on. A proxy that sets the header from the client's certificate,
in Caddy and in nginx, is
[hotline-ng-auth-rationale.md](hotline-ng-auth-rationale.md) §6.1; one
that does not must strip it.

**`Host`, for logins and the registrar.** An identity's login proof
names the host the client addressed, and the server holds it to the
`Host` header the request arrived with (`X-Forwarded-Host` is not read),
so the proxy must forward `Host` as the client sent it
(`proxy_set_header Host $host;` in nginx). A proxy that rewrites it to
the backend's address refuses every such login as `wrong_host`, and
leaves discovery's `registrar` block `null`, since that is named only
when asked for under `[registrar] host`. List the names the server is
reached by in `[identity] hosts`.

**Limits behind a proxy.** A trusted proxy's connections carry
everyone, so they count toward `[limits] ng_connections` alone and the
proxy is the place to limit connections per client; the request limits
still apply to the address it forwards. The classic ports cannot be
proxied that way; what a TCP proxy in front of them does to the limits
is in [NAT, CGNAT, IPv6 and proxies](#nat-cgnat-ipv6-and-proxies). A forwarder that adds no header
at all — stunnel, a TCP-mode proxy, an SSH tunnel, an onion service —
makes every ng connection look like this host, which the default
`[metrics] allow` lets scrape; name something narrower there
([metrics.md](metrics.md)).

## Serving hx-ng

[hx-ng](https://github.com/mishan/hx-ng) is a directory of static files.
In its checkout, `npm install && npm run build` writes `dist/` (the build
needs Rust with the `wasm32-unknown-unknown` target and
`wasm-bindgen-cli` as well as Node; its README has the versions). Serve
that directory from the proxy that terminates TLS for `[ng]`, on the
same name — under `/app/`, say, with everything else passed to the ng
port:

```nginx
location /app/ {
    alias /srv/hx-ng/dist/;
}
# and `location /` passed to the ng port, as in docker/nginx.conf
```

Then edit `dist/config.json`, which needs no rebuild: set
`"defaultServer": "wss://hl.example/ng"`. It takes effect on a reload of
the page for a browser that has not connected before; one that has
starts from the server it last used.
Without it the client derives `wss://<this host>:5700`, which is the ng
port with no proxy in front of it. A page on its own name can reach the
server too, since the ng port answers CORS, but one on the server's own
origin is what `[identity] web` can name for enrollment QR codes.
Voice, video and notifications need the page on https. `npm run dev`
(<http://localhost:5701>, bound to every interface so a phone on the LAN
can reach it) is for working on the client, not for serving it.

## TLS on the classic wire

The plain classic port carries everything in the clear, as it always
has; a client that speaks HOPE (the secure login, on unless `[hope]
enabled = false`, [hope.md](hope.md)) keeps its password off the wire
and may encrypt the session after it, and one that speaks TLS connects
to `[tls]`'s port instead. An optional `[tls]` section opens a second
control port that speaks TLS from its first byte and the unchanged
Hotline protocol inside it — the separate-port model GtkHx, Janus and
Mobius share. Period clients keep the plaintext port, and a session on
the TLS port is marked encrypted, as a tunnelled one is. HOPE is refused
there, since the same protection twice buys nothing.

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
client makes. A v3 tracker listing carries the TLS port
(`advertised_tls_port` in `[tracker]` overrides it).

## Accounts, roles, rooms and identity

### Accounts

An account is one TOML file in `[paths] accounts`: an `[access]` table
of named permission bits, an `[extra]` table of server-local policy that
never crosses the wire, and an `[identity]` table linking it to a key.
Every bit, key and switch — what each one gates, which of them this
server enforces today, and which numbers are reserved — is in
[access-bits.md](access-bits.md). First run writes a `guest.toml` with
the bits a stranger can be trusted with; delete it to turn guests off.

`hxd account` edits the directory, keeping each file's comments, and
works with the server down
([account-admin.md](account-admin.md) §6):

```sh
hxd account list
hxd account show alice
hxd account add alice --like guest --password-stdin < pw.txt
                                    # or --access KEY,…; or --no-password,
                                    # which has to be said
hxd account passwd alice --password-file pw.txt
hxd account access alice upload_files=on send_media=off
hxd account roles alice +moderators -regulars
hxd account rm alice
```

A password never goes on the command line. A running server applies an
edit, or a hand edit, to whoever is logged in as the account on SIGHUP,
and ends the sessions of an account removed; a new login sees it at
once. Administrators can do the same from a 1.5 client's user editor or
an ng client.

Deleting an account leaves its mail, news subscriptions and push devices
behind for whoever registers that login next, so take them with it:

```sh
hxd inbox purge alice                     # while accounts/alice.toml exists
hxd inbox purge alice --fingerprint <fp>  # after it is gone: the value from
                                          # its [identity] table, which
                                          # `hxd account rm` prints
hxd inbox purge alice --dry-run           # how much would go
```

### Roles

An account can also list `roles = ["moderators"]`, named grants defined
once in the roles file (`[roles] file`, [roles.md](roles.md) §2.3);
`everyone` is held by every account, the guest included. The account's
own keys win over its roles either way, so `send_media = false`
withholds what a role grants (roles.md §3).

```sh
hxd role list
hxd role show moderators
hxd role add moderators --title Moderators --color 0x2e8b57 --position 20 \
    --access disconnect_users,get_user_info
hxd role access moderators get_user_info=off   # a role only grants: off takes it out
hxd role extra moderators moderate=on
hxd role rm moderators                         # out of every account first
```

A running server applies a role edit to every session on SIGHUP. With
no roles file there are no roles.

### Curated rooms

Rooms beside the lobby, persistent and gated by `read` and `post` lists
of logins, are on unless `[rooms] enabled = false`; the rooms themselves
are in `[rooms] file`, managed by hand, by `hxd room` and by an ng
client's room requests ([chat-rooms.md](chat-rooms.md)). Their lines are
logged where `[history]` logs the lobby's.

```sh
hxd room list --archived
hxd room create trading --topic "Buy and sell" --post alice,bob --position 2
hxd room edit trading --name market --max-days 30
hxd room archive market            # hides it and parts its members, keeping its lines
hxd room unarchive market
hxd room delete market --purge --reason "spam"   # leaves only its id; the server deletes its lines
hxd room                           # every flag
```

A running server applies an edit on SIGHUP, and gives a new room its id
then. A period client joins a room by sending `/join <name>` to the
server account, which invites it into a private chat that is the room,
so classic users need `[system]`; `/rooms` lists them. A classic session
that may see a room is told so in the lobby at most once a day
(`[rooms] announce`).

### Portable identity

Identity needs `[ng]` and `[identity]`. An account links to an identity
through an `[identity]` table in its file, written by linking or by
hand: `fingerprint`, `login = true` (the identity may log in without the
password), `allow_self_link = true`, `reserve_name`.

An account with a fingerprint and no password is reachable *only* by proving
the identity — the password path refuses it, empty password included — which
is what makes `new_accounts = "create"` safe alongside the legacy port.
(`reserve_name` is read but not yet enforced;
[hotline-ng-identity.md](hotline-ng-identity.md) §9's reserved-name rules
are unimplemented on both wires.)

With `[identity]` on, the ng listener also answers HTTP: `GET
/.well-known/hotline` for discovery, `POST /identity/challenge` and
`/identity/auth` for the challenge binding, `GET /identity/card/<fp>` and
`PUT /identity/card`, and `POST /identity/link` and `/identity/unlink` for
account association.

With `new_accounts = "create"`, every identity the server has not seen
before gets an account of its own, and every such account its own
`[limits] connections_per_account` once logged in. One address minting
fresh identities can so hold more logged-in connections than any one
account may: as many as the accounts it has been let create, which
`max_new_accounts_per_hour` bounds, and never more than `ng_connections`
lets the port hold. Each of those logins still costs its address a
connection at `reconnect_seconds` first.

`hlid` makes the keys and objects and talks to the server. It logs in
only under a name the server lists in `[identity] hosts`, so the
commands below need `hosts = ["127.0.0.1:5700"]` there. From nothing:

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
([hotline-ng-identity.md](hotline-ng-identity.md) §8.3), which is why the
certificate above carries `manage`; a tunnel used with an account that is
already linked wants `--caps login,message`.

**Revoking a stolen key.** Without a registrar, the only other remedy for
a stolen device key is its certificate's expiry, which is months. On this
server, today:

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
in the running server until SIGHUP: every session the key holds,
connected or waiting to resume, ends then, its next login is refused with
`revoked`, and nobody else is dropped. An account whose linked identity
is revoked can still log in with its password.

A registrar the server trusts (`[identity] registrar_keys` or
`trusted_registrars`) revokes, rotates and freezes its own identities
here too: the server fetches its records at login and applies them
([identity-records.md](identity-records.md)).

### The registrar

A server can also be an identity registrar: it lends keys handles like
`alice@hl.example`, and publishes the revocations, rotations and freezes
that concern them. Needs `[identity]`. See
[identity-registrar.md](identity-registrar.md). The operator's side,
acting on the store the running server uses:

```sh
hxd registrar invites --add 10                  # print ten new invite codes
hxd registrar freeze <fingerprint>              # a holder reports a theft
hxd registrar freeze --lift <fingerprint>
hxd registrar revoke <handle> --reason abuse    # withdraw the name; or lapsed, unspecified
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
`[identity] registrar_keys`, or its host in `trusted_registrars`. Behind
a proxy, forward `Host` ([above](#behind-a-reverse-proxy)).

## The inbox

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

## News

The search index is kept in step with the articles by the same writes
that change them. If it ever drifts — a database restored from a copy, a
file edited by hand — rebuild it from the articles:

```sh
hxd news-reindex
```

It opens the database the server uses, which must already exist, and
leaves the articles as they are. See [news.md](news.md) §6.4. `hxd news
feeds` lists the feeds the database remembers: their articles, when each
last fetched, and why one is failing.

News is kept until someone deletes it, as a period server keeps it, so
the ceilings are what bound it: a post past `max_articles`,
`max_text_bytes` or the author's `max_per_author` is refused, never made
room for, and the log says so each time. A guest's share is its
address's (an IPv6 one's /64), so one guest cannot fill every guest's.
What an article keeps of the address is not the address but a keyed
hash of it, HMAC-SHA-256 under a secret the server makes on first start
in `news-guest.key` beside the database (`[news] guest_secret` to put it
elsewhere), owner-only: equal addresses still match, and the database
alone does not say where a guest posted from. Keep the secret with the
data ([Backups](#backups)), and out of anything that copies the database
alone. A tombstone clears the key, and the database zeroes what it
leaves behind. Make room by deleting threads, by raising a ceiling, or
with `retain_days`. See [news.md](news.md) §7.4.

## Moderation and bans

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
hxd moderation log                           # the audit trail, newest first; --limit N
hxd ban add 203.0.113.0/24 --reason "botnet" --for 7d
hxd ban add login:bob --reason "spam"        # bob's account, and the identity it links
hxd ban list                                 # what stands; --all for every ban on record
hxd ban lift 12
hxd ban lift n3                              # one asked of a linked server; sent on SIGHUP
```

A ban refuses an address or block before the handshake, and a login
or an identity (`identity:FINGERPRINT`, whether it logs in with its key
or as the account it links) at login, with its reason, on both wires.
A registrar's every identity (`*@HOST`) is refused when a login proves
one of its handles, which a password login does not. A kick-with-ban is
one too, for `[server] ban_time`, and disconnects only the one kicked, as
mhxd's does. Where mhxd bans the kicked address, this bans the person —
the account's login, or the identity a guest proved — and the address
only when `[limits] exempt` does not hold it: behind Docker's userland
proxy, a TCP proxy or a CGNAT, an address ban would lock out everyone. A
plain guest on an exempt address is only kicked. Lifting either row
lifts both. A running server applies `hxd ban` on SIGHUP, ending the
sessions a new ban refuses.

Images live in the running server's memory, not in the database, so
revoking one — and a purge's images — is an ng moderator's to do; `hxd
media revoke` says so rather than pretending.

## Voice

Voice needs its **UDP** port reachable — the one thing operators most often
miss — and `[voice] advertise` set to the addresses clients can reach it
at. Video rides that same port and that same peer connection, so there is
no second socket to open, and it is off unless `[voice.video]` is present.

Video is opt-in on both sides at runtime too: nobody publishes until they
ask, and nobody receives a stream until they ask for that stream in
particular, so a room with video in it costs a voice-only participant
nothing.

## Server linking

`[link]` joins this server to others under fogWraith's Server Linking
Extension ([server-link.md](server-link.md)), configured in
[`[link]`](#link). Each `[[link.peer]]` names the peer's key; SIGHUP
re-reads them, unlinking a removed peer and dialing a new one.

```sh
hxd link status            # how each peer stands, as the running server last wrote it
hxd link suspend janus-home  # on SIGHUP: closed, what it showed goes, every
                             # attempt to link refused; outlasts a restart
hxd link resume janus-home
hxd link reset-id          # server stopped: a new key, and so a new server ID
```

After `reset-id` every peer must be given the new key, and bans this
server asked of linked servers can no longer be lifted, so lift the ones
that should be first. A suspension is kept in `link-state.toml` beside
the key.

## Backups

The files whose loss cannot be undone, or is undone silently wrong.
Paths are the defaults, relative to the working directory unless the
row says otherwise; each is whatever its key names.

| File | Key | Losing it |
|---|---|---|
| The config file | `--config` | Every setting, and `[identity] revoked_identities` and `revoked_devices`, which `hxd identity revoke` writes there: revoked keys log in again. |
| `accounts/` | `[paths] accounts` | Every account, its password and its identity link. |
| `roles.toml` | `[roles] file` | Every grant the roles gave; accounts keep listing roles that no longer grant anything. |
| `rooms.toml` | `[rooms] file` | Every room, its gates and topic; their lines stay in the database with no room to read them in. |
| The SQLite database, with its `-wal` | `[inbox] db`, `[history] db`, `[news] db`, `[avatars] db`, `[push] db` | Private messages, chat history, news, avatars, push devices, the moderation trail, reports and bans, and the registrars' records the server has fetched. Copy it with the server stopped or with `sqlite3 .backup`, never mid-write. |
| `news-guest.key`, beside the news database | `[news] guest_secret` | The guests' articles already kept are counted against no address. |
| `news-blobs/` | `[news] blobs` | Every image attached to an article. |
| `vapid.key` | `[push] vapid_key` | Every push subscription, which is bound to it: pushes are accepted by nobody and no client can tell why. The server refuses to start without it while devices are registered. |
| `identity-server.key` | `[identity] key` | The server key discovery publishes and every login proof is bound to; a new one is made in its place. |
| `identity-successors` | `[identity] successors` | The successor commitments the server holds, so a stolen identity key can rotate to a thief's key here, and the rotations it accepted, so a key rotated away from logs in again. |
| `registrar.key` | `[registrar] key` | Every attestation the registrar signed stops verifying, and every server that lists the key must be given a new one. |
| `registrar.db` | `[registrar] store` | Every handle, attestation and published record, and the invites. |
| `registrar-invites` | `[registrar] invites` | Codes written by hand and not yet imported; the store keeps the rest. |
| `link-server.key`, and `link-state.toml` beside it | `[link] key` | The server's ID on the linked network: every peer must be given the new key, and bans asked of linked servers cannot be lifted. `link-state.toml` holds the suspensions: a suspended peer links again. |
| The TLS key and certificate | `[tls] key`, `cert` | A CA's pair is issued again. A self-signed one is not: every client that pinned it warns. |
| The file area | `[files] root` | The files, and in `.hxd-state` their Finder metadata, resource forks and partial uploads. |

The keys are created owner-only; keep their copies the same way. Back up
the directory they are in rather than the database alone.

## What SIGHUP reloads

`systemctl reload` or `kill -HUP`. Nothing else is read again: every
other key takes a restart.

| Reloaded | What changes | A file that fails to load |
|---|---|---|
| `[identity] revoked_identities`, `revoked_devices`, from the config file | Sessions a newly revoked key holds, connected or detached, end | Lists unchanged |
| Bans, from the database `hxd ban` writes | Sessions a new ban refuses end | Bans unchanged |
| The account files of everyone logged in, and the roles file | Each session is told what its account now resolves to; the sessions of a removed account end | An account file that cannot be read is skipped; a roles file that does not load leaves the roles unchanged |
| `[rooms] file` | New rooms are announced and given ids; an archived or removed room, or a narrowed gate, parts whom it no longer admits | Rooms unchanged |
| `[registrar] reserved` and its invites file | The reserved names, with every account login, are set again; new invite codes are imported | Logged; a config that does not load changes neither, and `[registrar]` taken out of the file stays on until a restart |
| `[tls] cert` and `key` | The next handshake uses the new pair; nobody is dropped | Certificate in use unchanged |
| `[[link.peer]]`, and `hxd link suspend` and `resume` | A removed or suspended peer is unlinked, a new one dialed; `hxd ban lift n…` requests are sent | Peers unchanged; `[link]` taken out of the file stays on until a restart |
| `[banner] file`, when one is in use | The next client to agree is shown the new one | Banner unchanged |

## Configuration reference

`hxd-ng.toml` by default. Each section below is independent, in the
order the server's `Config` declares them, and every key is optional
unless marked required. **In the examples, a key shown uncommented is set to its
default** — leaving it out changes nothing — **except one marked
required, which has none; a commented key is an example** (`# e.g.`) to
change or leave out, and its comment says what absent means.

### `[server]`

```toml
[server]
bind = "0.0.0.0:5500"
classic = true          # false: ng clients only, nothing of the classic
                        # wire listened for (Ports and the network)
name = "hxd-ng"
version = 254           # 0 mimics a pre-1.5 server
login_timeout = 10
ban_time = 1800         # seconds a kick-with-ban holds the person, and an
                        # address [limits] does not exempt; kept
                        # in the [moderation] database, so a restart does
                        # not lift it
stamp_queued = true     # stamp a message that waited in the inbox with its
                        # send time (private-messages.md §7)
queue_budget_mb = 128   # what the server may hold for its clients, all
                        # together; past it, the furthest behind are dropped
                        # (metrics.md, the budget)
logins_in_flight = 32   # logins worked on at once, a quarter of them from
                        # one address at most (not one [limits] exempts)
                        # until each is known to be a person's; past it a
                        # login is refused as busy, and its user tries again

# Set User Flags bit 4 on unencrypted legacy sessions (hotline-ng-auth.md §8).
# Off until that bit is confirmed free against 1.8/1.9 clients.
mark_cleartext = false
```

### `[limits]`

What one address, one account, and one session, is held to, on both
wires together. Always on, at the defaults of mhxd's `nospam`. A
connection past any connection limit is closed unanswered on the
classic ports, as mhxd closes one, and refused with HTTP 429 on the ng
port, `/trtp` included. Every count is 0 for no limit, and a count with
a window needs its seconds.

| Key | Default | What it bounds |
|---|---|---|
| `connections_per_addr` | 5 | Connections one address holds at once, until they log in |
| `reconnect_seconds` | 2 | New connections past a burst of `connections_per_addr` (5 when that is 0): one more each this often. The same for an account's logins past `connections_per_account` |
| `connections_per_v6_48` | 20 | Connections the /64s of one IPv6 /48 hold together, until they log in; at least `connections_per_addr` |
| `connections_per_account` | 10 | Connections one account with a password or an identity holds at once, once logged in |
| `exempt` | `["127.0.0.0/8", "::1"]` | Addresses and blocks held to none of the per-address limits, and kept a few places past `ng_connections` |
| `chat_lines`, `chat_seconds` | 20, 5 | Chat lines one session sends in each window, or it is kicked (mhxd's `chat_max`) |
| `spam_points`, `spam_seconds` | 100, 5 | Spam points one session spends in each window, or it is kicked and banned (mhxd's `spam_max`) |
| `private_chats_per_user` | 16 | Private chats one session opened that are still open; per session, so a user with several is bounded by `private_chats` |
| `private_chats` | 4096 | Private chats open on the server |
| `ng_requests`, `ng_request_seconds` | 40, 2 | Request weight one ng session spends at once, earned back over the seconds |
| `news_posts`, `news_post_seconds` | 10, 300 | News posts one account makes at once, earned back over the seconds |
| `folders`, `folder_seconds` | 500, 5000 | Folders one account makes at once, by New Folder or a folder upload, earned back over the seconds |
| `login_failures` | 10 | Wrong passwords one address gives for one login, on any wire |
| `login_failures_per_addr` | 50 | Wrong passwords one address gives for every login together, earned back at the per-login rate |
| `login_failure_seconds` | 30 | How often one of either is earned back |
| `http_connections_per_addr` | 16 | Connections one address holds to the ng port, whatever they carry |
| `http_connections_per_v6_48` | 64 | The same from one IPv6 /48's /64s together; at least `http_connections_per_addr` |
| `ng_connections` | 4096 | Connections everyone holds to the ng port |
| `challenges_per_minute` | 30 | `POST /identity/challenge`, per address |
| `avatar_fetches_per_minute` | 600 | `GET /avatars/{id}`, per address |

#### Flood and spam

The flood limits hold for every session wherever it connects from,
loopback included. Every line of a multi-line chat counts, public and
private rooms together. A user past `chat_lines` is kicked and its room
is told, in mhxd's words, "X was kicked for chat spamming". Every
transaction a classic client sends spends spam points at the price
mhxd's table gives it (a chat line or a private message 2, a user list
20, anything it does not list 10; the extensions mhxd never had, and
fetching icons, cost nothing), as does an ng request that stands for
one of them (`chat`, `msg`, `nick`, the news posts, deletes and
creates, and the file-area changes). A user who reaches `spam_points` is
kicked and banned for `[server] ban_time`, and public chat is told as
mhxd tells it. The ban is placed as a moderator's kick-with-ban places
one ([Moderation and bans](#moderation-and-bans)): on the person, and on
the address unless `exempt` holds it, since everyone behind a shared
proxy would go with the flooder. Exempt a proxy that hides its clients'
addresses for this too. An account with `[extra] can_spam = true` is
held to neither, nor to the request limits below; by default that is
every account with the kick bit.

The two private-chat limits are this server's, not mhxd's, which has
none: a chat stays open, counted against whoever opened it, until its
last member leaves, and a create past either is refused with a task
error a period client shows like any other.

#### Requests and posts

The request limits are not mhxd's, and slow a client down rather than
kick it. Every request an ng session sends spends its weight from
`ng_requests`: a read 1, a write 2, and a post, a search or a call
joined 4. One the session cannot pay for is answered `rate_limited` with
how many seconds to wait. The allowance is the session's, so a client
that drops its socket and resumes carries on with what it had left; only
a fresh login starts full.

One account's news posts are held to `news_posts` the same way, and a
guest's by its address (an IPv6 one's /64), so logging in again does not
refill them; a classic post counts toward it but is never refused by
it, since mhxd would take it. Folders are held to `folders` alike, on
both wires and in a folder upload, which ends past it and keeps what
arrived.

#### Logins

The connection limits per address hold a connection until it logs in.
A connection that logs in as an account with a password or a linked
identity stops counting against its address and counts against its
account instead, held to `connections_per_account` from wherever it
comes, exempt addresses included. The address gets back its place (and
its /48 the place it held there, and the ng port the socket's places in
`http_connections_per_addr` and `http_connections_per_v6_48`), but not
the new connection it spent: each login costs its address one from the
address's burst and its account one from a burst of its own,
`connections_per_account` earned back at `reconnect_seconds`, so neither
logs in faster than the slower of the two rates. A guest, or any
account with neither a password nor an identity, stays counted against
its address. An account whose password is handed around is a person as
far as the server can tell; raise `connections_per_account`, or set it
to 0, on a server that gives out such a login.

A login past `connections_per_account` is refused: a classic client is
told so in its login's error text, an ng one gets
`too_many_connections`, and a resume past it gets the same and leaves
its session as it was for another try. A login or resume past the
account's rate is refused the same way, as `rate_limited` with how long
to wait on the ng wire. A detached ng session holds no connection, and a
resume that takes over a session from a socket not yet known to be dead
may go one past the cap for as long as that socket takes to close. The
share of `[server] logins_in_flight` one address may have holds a login
the same way, until it is known to be a person's.

An address that has given `login_failures` wrong passwords for one
login — on the classic wire, the ng wire's `login`, or `/identity/auth`
and `/identity/link` — is refused before its next password for that
login is checked, the right one included, until it has earned one back.
The count is kept for each address and login together, the login read
as the accounts are (case folded), so someone guessing at one account
locks that account out from their address and nobody else behind it.
An address that has given `login_failures_per_addr` wrong passwords
across every login is refused before any of its passwords is checked:
the ceiling that keeps it from guessing at every account in turn, five
people's worth of mistakes by default, earned back at the rate one
login's are. Each password counts from the
moment it is let in and is given back unless it turns out wrong — a
password that verifies, a login refused for something other than its
password, and a server that could not check it all give it back — so
guesses sent at once on many connections are held to the same count as
guesses sent one after another. A login that checks no password is not
held to it: a guest's, with none, and an identity that `[identity]
trtp_login = "trust"` admits, or that logs in on the ng wire without
one. A classic client is told so in the error text of the login it
already expects to fail; an ng one gets `rate_limited` with
`retry_after`, and an HTTP route 429 with `Retry-After`.

#### The ng port

The ng port holds each connection to `http_connections_per_addr` and
`ng_connections` from accept, before a byte is read, and for the whole
life of a WebSocket; past either it is closed unanswered. The count per
address is its own rather than `connections_per_addr`, because one
browser page opens several connections at once beside its socket. An ng
session's socket counts toward `connections_per_addr` as well, until it
logs in as a person, and keeps its place in `ng_connections`.
`ng_connections` is what bounds the port's descriptors whoever holds
them: keep it below the process's descriptor limit, less what the
classic port and the databases need. An address `exempt` lists still
gets in when it is full, into a few places kept past it for the
operator's own tools, such as a `/metrics` scrape; a trusted proxy is
not given them, exempt or not. An idle keep-alive connection is closed
after `[server] login_timeout`, as a request head that never arrives is.

#### NAT, CGNAT, IPv6 and proxies

Carrier-grade NAT puts many unrelated people behind one IPv4 address,
mobile carriers most of all, so an address is a fair bound on
connections nobody has vouched for and a poor one on people: that is
why a login moves its connection to its account's count. IPv4 has no
wider count than the address: one client seldom holds many IPv4
addresses, and its neighbors in a /24 are as likely strangers behind a
carrier's NAT as the same person.

An IPv6 client counts as its /64, which is what one subscriber is
given, and its /48 is counted as well: a subscriber is as often given a
/56 or a /48, hundreds or tens of thousands of /64s, and each would
otherwise be an address with a whole allowance of its own. A connection
must fit under both `connections_per_addr` and `connections_per_v6_48`
(on the ng port, under the two `http_` counts as well), and one past the
/48's is refused exactly as one past its address's is. The defaults are
four addresses' worth, so a site with a few machines on a few /64s gets
in and one client walking its /48 is held to a few machines' share
rather than filling `ng_connections`. An address in `exempt` is not
counted toward its /48.

An ng client behind a reverse proxy listed in `[ng] trusted_proxies`
counts as the address the proxy forwards. A classic client reaching the
server through a TCP proxy that hides its address counts as the proxy,
so every client of that proxy shares one allowance: exempt the proxy, or
raise the limit. A proxy on the same host connects from loopback, which
`exempt` holds to none of the per-address limits by default, so every
client behind it is exempt too, down to the share of logins in flight
one address may hold. For limits per client, list the proxy in `[ng]
trusted_proxies` for the ng port, or take loopback out of `exempt` for
a TCP proxy to the classic ports.

#### Load testing

A load generator talks far faster than a person, from one address. Set
`chat_lines`, `spam_points`, `ng_requests`, `news_posts` and
`reconnect_seconds` to 0, and put the generator's address in `exempt`
when it is not on the server's host ([load-testing.md](load-testing.md)).

### `[paths]`

```toml
[paths]
accounts = "accounts"
# agreement = "agreement.txt"   # e.g.; UTF-8 text shown at login. Absent, none
```

### `[roles]`

```toml
[roles]
file = "roles.toml"     # grants accounts share by name (roles.md);
                        # no file there means no roles
```

### `[ng]`

Enabling `[ng]` turns on the WebSocket protocol — see
[hotline-ng.md](hotline-ng.md).

```toml
[ng]
bind = "127.0.0.1:5700"    # plaintext; put a WSS-terminating proxy in front
grace = 300                # detached-session grace window, seconds
max_detached_per_addr = 2

# Proxies only. The address walk skips whatever is listed here, and the
# mTLS binding header (X-Hotline-Client-Cert) is believed from these hosts
# and nowhere else (hotline-ng-auth-rationale.md §6.1).
trusted_proxies = []       # e.g. ["127.0.0.1", "10.0.0.0/8"]

# Which header that proxy writes the client address into:
# x-forwarded-for | forwarded | none. The rightmost element outside
# trusted_proxies is the client (hotline-ng-auth.md §6.3).
forwarded_header = "x-forwarded-for"
```

### `[voice]` and `[voice.video]`

Both absent by default. Video rides the voice session, so `[voice.video]`
without `[voice]` does nothing. See [voice.md](voice.md) and
[capabilities-video.md](capabilities-video.md).

```toml
[voice]
# bind = "0.0.0.0:5504"             # e.g.; absent: [server] bind's address, port + 4 (UDP)
# advertise = ["203.0.113.5:5504"]  # e.g.; what clients are told to send media to.
                                    # Required unless bind, or [server] bind, is
                                    # a concrete address, which the default
                                    # 0.0.0.0 is not: ICE-lite gives a client
                                    # nothing else to go on.
                                    # List a v4 and a v6 to serve both.
max_per_room = 16                   # the spec's VoiceMaxPerRoom; at most 4096
joins = 5                           # joins one session may make in join_seconds;
join_seconds = 10                   # 0 for no limit. Leaving is never limited
status_debounce_ms = 100            # a burst of mute or pause flips is
                                    # announced once, with its final state
police_factor = 1.5                 # inbound media past this multiple of its
                                    # ceiling is dropped, not forwarded; 0 = off,
                                    # and below 1 is refused

[voice.video]
max_cameras_per_room = 8            # VideoMaxCamerasPerRoom
max_screens_per_room = 1            # VideoMaxScreensPerRoom; a second sharer is
                                    # refused rather than preempting the first
max_width = 1280                    # camera ceiling
max_height = 720
max_fps = 30
max_bitrate = 1500000               # bits per second
screen_max_width = 1920             # screen-share ceiling: more pixels, fewer
screen_max_height = 1080            # frames — a desktop is mostly still
screen_max_fps = 15
screen_max_bitrate = 2500000
changes = 10                        # video starts, and subscription changes
change_seconds = 10                 # that add a live stream, one session may
                                    # make; a stop, a pause and any other
                                    # subscription change never count
```

### `[identity]`

Needs `[ng]`, because the identity endpoints and the tunnel are served by
the ng listener. See [hotline-ng-auth.md](hotline-ng-auth.md) for the
transport, [hotline-ng-identity.md](hotline-ng-identity.md) for what an
identity is and how it links to an account, and
[identity-records.md](identity-records.md) §5 for the registrar keys.

```toml
[identity]
key = "identity-server.key"         # Ed25519 seed; generated on first run
new_accounts = "guest"              # deny | guest | create
unattested = "guest"                # deny | guest | allow
min_attestation_age = 0             # seconds an attestation must have existed
clock_skew = 300                    # tolerated clock difference, seconds
hosts = []                          # e.g. ["hl.example", "hl.example:5700"];
                                    # the names clients reach this server by;
                                    # needed unless login_proof_v1 is on
login_proof_v1 = false              # accept the old login proof; see below
successors = "identity-successors"  # hotline-ng-identity.md §3.4 commitments;
                                    # "" = memory only, the weaker mode
trtp = true                         # serve the tunnel at /trtp; never with
                                    # [server] classic = false
trtp_login = "verify"               # verify | trust: how a tunnelled classic
                                    # login meets the socket's identity
enroll = true                       # serve the enrollment mailbox at
                                    # /identity/enroll; off, a device enrolls
                                    # by the paste
enroll_sessions = 256               # open sessions at once, server-wide
enroll_per_address = 4              # open sessions and pending requests, per
                                    # source address
max_new_accounts_per_hour = 60      # ceiling on what new_accounts = "create" writes
allow_list = []                     # e.g. ["alice@hl.example", "<fingerprint>"];
                                    # non-empty admits only these identities

# web = "https://hl.example/app/"   # e.g.; where a web client for this server lives.
                                    # Advertised in discovery so `hlid enroll`
                                    # can show a QR code that opens it with the
                                    # pairing code already in it. Must be on
                                    # this server's own origin to be drawn: the
                                    # QR's fragment carries the pairing secret,
                                    # so a client hosted elsewhere is one the
                                    # user names with `hlid enroll --web`

# Registrars whose attestations, revocations, rotations and freezes this
# server applies: on a key given here, or on the key their discovery
# publishes. Absent, none.
# registrar_keys = { "hl.example" = "<base64url public key>" }   # e.g.
trusted_registrars = []             # e.g. ["hl.example"]
# registrar_urls = { "hl.example" = "http://10.0.0.5:5700" }     # e.g.; a registrar
                                    # not reached at https://<host>
registrar_timeout = 3               # seconds a login waits on registrars
revocation_max_age = 3600           # a record list is used at most this long
revocation_stale = "cached"         # cached | guest | deny: records not current
frozen = "deny"                     # deny | guest: an identity its registrar froze
banned_registrars = []              # hosts whose identities are refused
newcomer_delay = 120                # seconds a key nobody here answers for waits
                                    # before it may chat, message or post; 0 = off

# Keys refused by hand, no registrar needed: an identity (every device of
# it) or one device. `hxd identity revoke` writes these for you.
revoked_identities = []
revoked_devices = []

# Access bits for accounts "create" makes — same key names as an account
# file's [access]. Absent means whatever guest has, which is rarely right.
# [identity.default_access]
# read_chat = true
# send_chat = true
```

**`hosts`** are the names, `host[:port]` with the port left off for 80
and 443, that clients put in the URL they reach this server by. A login
proof names one, and the server signs each challenge for the one it was
asked under, so that a server elsewhere cannot pass this one's
challenges to its own users and log in here as them
([hotline-ng-auth.md](hotline-ng-auth.md) §6.2). Only these count: a
`Host` header is whatever the sender wrote, so the server never takes
one as its own name, and a request under any other name is refused
however it got here, past the proxy or around it. Empty, it signs no
challenge and accepts no new login proof, so no identity could log in
and the server refuses to start, saying what to set; with
`login_proof_v1` on it starts, and only clients still on the old proof
can log in with an identity, which the startup log says. A
configuration written before `hosts` existed needs one or the other to
start: the names, or the old proof turned on. A name outside ASCII may
be written either way; it is compared in its `xn--` form.

**`login_proof_v1`** accepts the login proof clients signed before
proofs named a host. It can be relayed in just that way, and logins
that use one are warned about in the log, at most once a minute.
It is off, and such a login is refused with `unsupported_proof`; `hlid`
and the browser client sign the new proof. Turning it on keeps older
clients logging in for now, at the cost of the relaying the new proof
closes: a server that shows this one's key as its own can log its
users in here as them.

### `[inbox]`

Absent means no inbox, and that is the default. Naming the database is what
turns it on. See [private-messages.md](private-messages.md).

```toml
[inbox]
db = "messages.db"       # required
max_queued = 200         # messages waiting, per account; a full one refuses
deliver_at_flush = 25    # queued messages handed over per login
retain_unread = 2592000  # seconds; 30 days, from when it was sent
retain_read = 604800     # seconds; 7 days, from when it was read
max_sent_per_day = 1000  # messages one account may store in a rolling day,
                         # delivered or waiting; 0 = no quota
max_sent_bytes_per_day = 8388608  # the same in body bytes
sync = "normal"          # or "full": fsync every commit
```

Retention keeps a delivered message as well as a waiting one, so the
sender's quota, not `max_queued`, is what bounds how fast one account can
grow the database. Past it, a message to someone connected still
arrives, live and unstored, as a period server delivers it; one that
would have to wait is refused, as a full mailbox refuses.

`full` costs a disk sync per commit. Public chat lines arriving together
share a commit, so a busy room pays one sync for many lines, but a line
still waits for the sync of the commit before its own: on a disk that
syncs in 5 ms, a line takes at least that long to be heard, and one
talker who waits for each line before sending the next is held to a
couple of hundred a second. `normal` loses at most the last moments
before a power cut, never a line that reached the disk, and never the
database.

### `[history]`

Absent means no server-held scrollback. When `db` is omitted, history uses
the inbox database; without an inbox it is required. Either way public chat
is written on a connection of its own, so the inbox, news and moderation
never hold it up. See [chat-history.md](chat-history.md).

```toml
[history]
# db = "messages.db"      # e.g.; required only without [inbox]
max_lines = 10000         # 0 = unlimited
max_days = 0              # 0 = unlimited
max_page = 200            # maximum rows in one request
replay = 0                # plain chat lines replayed to old legacy clients
```

### `[media]`

Absent means no images: the legacy wire never confirms capability bit 3
and the ng wire never offers the `media` cap or its HTTP routes. The
send permission is off in every account file that does not name it —
including the bootstrap guest — because an image is the one thing a
stranger can put on everyone else's screen. See
[inline-media.md](inline-media.md).

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
upload_interval = 10          # seconds between one account's uploads (a guest's: its address's)
upload_per_hour = 30          # per account, or per guest address
upload_per_hour_per_addr = 100
download_per_minute = 60      # per session
upload_sessions = 2           # chunked uploads in flight, per account
```

Nothing touches disk: handles live in memory for their day and go with a
restart, which the extension's own spec allows for — clients are told
not to cache them across sessions.

### `[news]`

Absent means no news: the ng wire never offers the `news` cap, and a news
request is answered the way a server without the feature answers it. When
`db` is omitted, news uses the database `[inbox]` or `[history]` names, on
the inbox's connection where there is one; with neither it is required. A 1.5 client
browses the same tree over the threaded-news transactions, reading a
markdown article's plain-text part. A 1.2 client reads and posts into the
one category `flat_category` names, rendered newest first as a single
document; without it, a 1.2 client is told this server's news is
threaded. `flat_category` splits on `/`, so a category whose own name
contains one cannot be named there. See [news.md](news.md) §12.

```toml
[news]                    # presence turns it on
# db = "messages.db"      # e.g.; required only without [inbox] or [history]
max_body = 65535          # the legacy NEWSDATA ceiling; ↓ freely, ↑ never
max_subject = 255         # the 1.5 pstring
markdown = "render"       # or "source", or "off"; see below
max_refs = 32             # references recorded per article; past that, text
max_depth = 32            # reply nesting
max_node_depth = 16       # bundle nesting
max_page = 200            # threads in one request
retain_days = 0           # a thread's life after its last post; 0 = forever
max_articles = 100000     # live articles the news may hold; 0 = no ceiling
max_text_bytes = 1073741824  # bytes of their bodies and plain-text parts
max_per_author = 10000    # live articles one account may hold, a guest's address as one
self_delete = true        # authors may delete their own; false = period behavior
search = true             # false turns news_search off; the index is kept either way
search_max_results = 500  # the deepest a search pages
search_per_minute = 30    # searches per session
legacy_catlist_max = 2000 # articles in one 1.5 category listing

# flat_category = "General"  # e.g.; the 1.2 view: names from the root, "Bundle/Category".
                          # Absent, a 1.2 client is told the news is threaded
flat_articles = 100       # entries in the 1.2 document; 65 535 bytes usually decides
flat_reply = "newest_thread"   # where a post with no Re: goes, or "new_thread"
flat_default_subject = "(no subject)"
# flat_masthead = "..."   # e.g.; the line above the entries; absent = built in,
                          # "" = none; at most 4096 bytes

blobs = "news-blobs"      # durable content-addressed attachment bytes
# guest_secret = "/srv/hxd/news-guest.key"  # e.g.; the key a guest's address is
                          # hashed under. Absent, news-guest.key beside the
                          # database; made on first start, mode 0600

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

[news.feeds]                    # what every feed is held to
every = 1800                    # seconds between polls
min_every = 300                 # the shortest every a feed may ask for
keep = 100                      # newest articles a feed keeps; 0 = retain_days decides
first_import = 20               # items a feed's first poll takes from its backlog
max_bytes = 4194304             # a response body, after decompression
timeout = 30                    # seconds for a whole fetch, redirects included
# proxy = "http://10.0.0.5:3128"  # e.g.; HTTP(S)_PROXY in the environment is never read

[[news.feed]]                   # one per feed; none = nothing is fetched
name = "mobius"                 # required; the feed's identity, kept across a change of URL
url = "https://github.com/jhalter/mobius/releases.atom"   # required
category = "Software/Mobius"    # required; made if missing, and read-only while configured
# every = 3600                  # e.g.; absent, [news.feeds] every
# keep = 50                     # e.g.; absent, [news.feeds] keep
# author = "Mobius"             # e.g.; in place of each item's own
replies = false                 # may people reply to its articles
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
its badge and its `news_notify` either way, and `[push]` is what rings a
device with no session open. A guest follows nothing; subscriptions are
kept against the account, by the same rule as the inbox.

`[news.attach]` needs the `media` image pipeline and the SQLite `inbox`
feature. Uploads are canonicalized and staged before a post; the post binds
their handles atomically. Staging permission defaults to the account's
`send_media` bit and can be overridden with `[extra] attach_news`; a guest
never stages, since a staged image belongs to the person who uploaded it.
News images go through the same pipeline as chat's: `[media]`'s dimension,
pixel and frame caps and its `max_concurrent_decodes` hold for both, and
only the byte ceiling is `[news.attach]`'s own.

`[[news.feed]]` polls an RSS, Atom or JSON feed into a category, one
article per item, with the item's own author; an item edited upstream
edits its article (`news_edited` on ng), and a feed keeps its newest
`keep`. Nobody posts into a feed's category, nor renames or deletes it
while the feed is configured; a moderator may delete its articles, and
a deleted item stays deleted. A feed whose URL is on the local network
is fetched as configured; any other is held to public addresses on
every connection, redirects included. Feeds are read at startup, and
`hxd news feeds` ([News](#news)) says how each is doing. Needs the `feeds` feature. See
[news-feeds.md](news-feeds.md).

Who may read, post, delete and rearrange is the account's news bits —
`read_news`, `post_news`, `delete_articles` and the category and bundle
bits in [access-bits.md](access-bits.md). An article is its
author's to delete only when one person is behind the account, a password
or a linked identity; a guest's belongs to nobody.

### `[files]`

Absent means neither wire advertises Files and the HTXF listener is not
opened. Choose exactly one source mode. The manifest mode is read-only: only
the configured HTTP(S) origin may provide bytes, so no client or manifest row
can turn the server into an arbitrary-URL proxy. See
[files-plan.md](files-plan.md).

```toml
[files]
manifest = "files.json"                    # required in this mode
origin = "https://downloads.example/files/"  # required with manifest
# bind = "0.0.0.0:5501"       # e.g.; absent: [server] bind's address, port + 1;
                              # refused with [server] classic = false
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
root = "/srv/hxd/files"       # required in this mode; must already exist
# bind = "0.0.0.0:5501"       # e.g.; absent: [server] bind's address, port + 1;
                              # refused with [server] classic = false
max_file_size = 68719476736   # data and resource forks combined
max_entries = 100000
max_folder_items = 100000     # the most one folder transfer holds
max_depth = 32                # the deepest a folder is made or moved to;
                              # at most 64
downloads_per_account = 1     # transfers one person runs at once: an
uploads_per_account = 1       # account, or a guest by its address; 0 for
                              # no limit
downloads = 0                 # and the server, 0 for no limit; a download
uploads = 0                   # past either waits its turn, an upload past
queue = 0                     # either is refused; downloads that may wait
max_concurrent = 8
max_partial_bytes = 68719476736
max_partials = 1024           # global abandoned/in-progress upload cap
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
trailing window. A folder is downloaded whole (Download Folder), with what a
listing would show of it, and uploaded whole (Upload Folder), each file
under the same limits as one uploaded alone.

A transfer counts against those limits from when it is granted until it
ends, or until its reference goes unclaimed. A download past one is
answered with its place in the queue and started with a Download Info
(211) when its turn comes, and a client that dials before then is held
until it. mhxd counts a connection, which anyone can open another of,
and refuses a download past a user's own limit rather than queue it; Kill Download (214)
takes back a waiting or running transfer. Downloads over the ng port's
HTTP are not counted.

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

### `[tracker]`

An optional `[tracker]` section announces the server over UDP using classic
HTRK v1 or the metadata-bearing v3 protocol. Targets name their protocol
explicitly because a silent v1 UDP tracker cannot be probed for v3. See
[tracker-registration.md](tracker-registration.md) for the `[tracker.v3]`
metadata and the security configuration.

```toml
[tracker]
description = ""          # e.g. "A small Hotline community"
interval = 300            # seconds between heartbeats
ack_timeout_ms = 2000     # how long to wait for a v3 acknowledgment
# advertised_port = 5500  # e.g.; only when NAT maps a different public port
# advertised_tls_port = 5600  # e.g.; the same for [tls], on v3 targets

[[tracker.targets]]
address = "hltracker.example" # required; UDP/5499 when the port is omitted
protocol = "v1"               # required: v1 or v3

[[tracker.targets]]
address = "argus.example:5499"
protocol = "v3"
# hmac_secret = "shared secret"  # e.g.; or password, the cleartext fallback
```

### `[system]`

Absent means no account on the roster and no commands: a private message
is a private message on every wire. Present, a reserved account sits on
the user list, and a private message to it is a command line — which is
the only place the server reads text as anything but text. **Public chat
is never parsed**, on any wire: a 1.5 user typing `/report` into the chat
box gets chat, because that is what they asked for. See
[system-account.md](system-account.md).

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
online, which a 1.5 client's user list has no way to name,
`/report <nick or login> <reason>` tells the moderators about someone,
and `/rooms`, `/join` and `/part` reach the curated rooms. `/help`,
`/block`, `/unblock`, `/blocks` and `/stop` are the rest of what it
answers today.

### `[push]`

Absent means no notifications leave the server: the ng wire offers no
`push` capability, a client never asks its user for permission, and
`push_register` is answered `not_available`. Present, the server sends
Web Push itself — no sidecar and no third-party service — or, with
`gateway = "uniqush"`, hands each notification to a
[uniqush-push](https://github.com/uniqush/uniqush-push) 2.11 or newer
sidecar, which sends it ([push-notifications.md](push-notifications.md)
§4.1). Either way what reaches a device is encrypted to its own key, so
the push service relays ciphertext it cannot read, and a client cannot
tell the two gateways apart. See [webpush-gateway.md](webpush-gateway.md).

```toml
[push]                                # presence turns it on
contact = "mailto:admin@example.org"  # required; a push service may refuse a push without one
content = "sender"                    # full | sender | generic
vapid_key = "vapid.key"               # created on first start, mode 0600
# db = "server.sqlite"                # e.g.; absent, the file [inbox], [history] or
                                      # [news] names, in that order; required with none
gateway = "webpush"                   # or "uniqush", with [push.uniqush]
# timeout = 10                        # seconds to wait for a push service, name lookup
                                      # included. Absent, 10 with webpush and 40 with
                                      # uniqush, where it must be more than 30
message_ttl = 2419200                 # how long it holds a private message's notification
news_ttl = 86400                      # the same for a news notice
breaker_failures = 5                  # failures before a push service is skipped
breaker_cooldown = 60                 # seconds it stays skipped
max_inflight = 64                     # pushes in flight at once
max_inflight_per_origin = 8           # of those, to any one push service
max_devices = 20                      # devices one account may register
allow_private_endpoints = false       # for an operator running their own push service

[push.uniqush]                        # with gateway = "uniqush" only
addr = "http://localhost:9898"        # or "unix:/run/uniqush/uniqush.sock"
# token_file = "/run/secrets/uniqush_token"   # e.g.; uniqush's bearer token.
                                      # Required over TCP
service = "hl-example"                # required; this server's service in uniqush,
                                      # one server's alone
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
it. Through uniqush, the sidecar is handed the plaintext to encrypt, and
`full` trusts it with every message.

uniqush's API reads every device and pushes as this server to whoever
reaches it: bind it where only hxd-ng can, and give it the token or use
its Unix socket. `timeout` has to outlast uniqush's own `[webpush]
request_timeout`, 30 seconds unless raised there, since uniqush answers
only after its first try at each device. Pin its image at
`ghcr.io/uniqush/uniqush-push:2.11`. [docker.md](docker.md), "Push
through uniqush", has the rest of what to know before running it.

### `[registrar]`

Needs `[identity]`. See [identity-registrar.md](identity-registrar.md) §11.

```toml
[registrar]
host = "hl.example"          # required; the name attestations carry. This
                             # server's discovery must be reachable at
                             # https://hl.example/.well-known/hotline
key = "registrar.key"        # its own signing key, apart from the server
                             # key; generated on first run
# retiring = [{ key = "<base64url>", until = 1798761600 }]   # e.g.; keys still
                             # valid for verification after a rotation
store = "registrar.db"       # SQLite, a file of its own
signup = "proof"             # open | proof | closed
# proof = "invite"           # e.g.; what signup = proof asks for, "none" with
                             # open. Absent, whichever signup needs
invites = "registrar-invites"  # codes, one per line; read at start and SIGHUP
# proof_url = "https://hl.example/invite"   # e.g.; where to ask for one
# level = 2                  # e.g.; written into attestations. Absent, what
                             # proof supports: 2 for invites, 0 open
attestation_days = 365
hold_days = 365              # how long a lapsed name waits for its owner
handle_min = 3
handle_max = 32
reserved = []                # e.g. ["staff"]; beside the built-in list and
                             # every account login
rotation_delay = 0           # seconds to hold a rotation back so a freeze
                             # can meet it
records_max_age = 3600       # seconds the record lists it publishes are
                             # good for: their `expires`
envelopes = false            # key backup; not built, and true is refused

[registrar.rate]
registrations_per_address = 5     # an hour
registrations_per_hour = 120      # registrar-wide; renewals don't count
records_per_identity = 20         # an hour
lookups_per_minute = 60           # per address
device_revocations_kept = 256     # per identity, on the full list; not a
                                  # rate: the oldest `until` goes first
```

### `[moderation]`

Always on: kick and ban never needed a database, and neither do reports
— on a server with none they last until it stops. Where `[inbox]`,
`[history]` or `[news]` names a database (in that order), the audit
trail, the reports and the bans are kept there. Who moderates is `[extra] moderate`
in the account file, which defaults to the kick bit (`disconnect_users`).
The section is optional. See [moderation.md](moderation.md).

```toml
[moderation]
evidence_days = 30    # how long a redacted line's words stay readable to moderators
report_days = 90      # how long a closed report, or an ended ban, is kept
pin_days = 7          # how long a reported image may outlive its handle
notify_legacy = true  # reports as private messages to moderators on the classic wire
kick_purges = 0       # seconds of a kicked user's output a classic kick takes; 0 = none
ban_v6_prefix = 64    # how wide a kick's ban is on an IPv6 address, in bits
```

### `[tls]`

See [TLS on the classic wire](#tls-on-the-classic-wire). With `[files]`
or a banner file, a TLS transfer port sits one above the TLS control
port, where a client looks for it.

```toml
[tls]
bind = "0.0.0.0:5600"
cert = "/etc/hxd-ng/tls/fullchain.pem"  # required; PEM chain, leaf first
key = "/etc/hxd-ng/tls/privkey.pem"     # required
# files_bind = "0.0.0.0:5601"  # e.g.; absent: bind's address, port + 1
self_signed = false            # make a pair at cert and key if neither exists
```

### `[banner]`

An optional `[banner]` section gives the server a banner, the image a
1.5+ client shows above its windows. It is sent after the agreement,
as mhxd sends it. A banner file is held here and fetched over HTXF, on
the files port whether or not `[files]` is on (and on the TLS transfer
port with `[tls]`); a URL alone has the client fetch the image itself.

```toml
[banner]
# file = "banner.jpg"             # e.g.; JPEG, GIF or PNG, at most 1 MiB
# url = "https://hl.example/"     # e.g.; with file: where a click goes;
                                  # alone: where the image is, and
                                  # then it must be http(s)
```

Classic clients show JPEG and GIF. A client connected through the
`/trtp` tunnel fetches a held banner through `/htxf`, which `hlid
tunnel` serves on its own port plus one. ng clients are told of the
banner in the login reply and fetch a held one with `GET /banner` on the
ng port ([banner.md](banner.md)).

### `[avatars]`

An optional `[avatars]` section lets users set a picture that every
client can show without an icon set: fogWraith's GIF Icons extension on
the legacy wire, the `avatars` capability on the ng one, and one avatar
crossing between them. An avatar belongs to the account (or to a guest's
proven identity) and is kept in the shared database, so it is there at
the next login. Uploads go through the inline-media pipeline, so this
needs the `media` feature, and are decoded one at a time on a budget
apart from `[media]`'s. Setting one is the account's `[extra]
set_avatar`, which defaults to a password or a linked identity, so the
bootstrap guest has none. See [avatars.md](avatars.md).

```toml
[avatars]                 # presence turns it on
max_bytes = 262144        # the largest upload, on either wire
max_dimension = 128       # what an avatar is fitted to
legacy_max_bytes = 32768  # the GIF legacy clients are sent
set_interval = 10         # seconds between one owner's changes
identity_retain_days = 90 # an identity's avatar, once it stops logging in; 0 keeps it
# db = "avatars.db"       # e.g.; absent, [inbox], [history] or [news]'s database,
                          # and with none, memory until the server stops
```

### `[metrics]`

`GET /metrics` on the ng port, in Prometheus's text format. Needs the
`metrics` feature and `[ng]`. See [metrics.md](metrics.md), which also
says why a forwarder that adds no header calls for a narrower `allow`.

```toml
[metrics]
allow = ["127.0.0.0/8", "::1"]    # who may scrape, in the trusted_proxies syntax
```

### `[link]`

Early, and absent by default. `[link]` joins this server to others under
fogWraith's Server Linking Extension, by server keys: each side proves its
key over the TLS session, so no password is shared and `[link]` needs
`[tls]`. Users cross both ways, shown on each server as users of the
other, and public chat, private messages and user info cross where both
sides enable them. See [server-link.md](server-link.md) and
[Server linking](#server-linking).

```toml
[link]
tag = "hx"                         # required; 1-8 printable ASCII, unique in the network
# color = 0x3a7bd5                 # e.g.; suggested for this server's users elsewhere
key = "link-server.key"            # generated on first start; the log shows
                                   # its public key to give your peers
show_tags = false                  # on to put the home server's tag in every
                                   # other server's user's name
max_ghosts = 2000                  # other servers' users shown, across links
grace = 60                         # seconds an interrupted link's users stay

[[link.peer]]
name = "janus-home"                # required
# dial = "janus.example:5600"      # e.g.; the peer's TLS port, for a peer you dial
accept = false                     # true for a peer that dials you; one or the other
protection = "key"                 # required; "key" is the only mode so far
key = "ed25519:base64url key"      # required; the peer's, as its log shows it
                                   # (prefix optional)
account = "link-hx"                # required; the login the peer expects (no
                                   # account here)
features = []                      # e.g. ["chat", "msgs", "info", "transit"]:
                                   # what this link carries, if the peer
                                   # agrees; transit joins this server to
                                   # the peer's network, and relays between
                                   # its links
ghosts = 1000                      # this link's users shown
drafts = []                        # e.g. ["user_transport"] (server-link.md §3.2)
```

### `[hope]`

HOPE, the secure login, on the plain classic port ([hope.md](hope.md)).
A client that does not speak it never notices.

```toml
[hope]
enabled = true          # false refuses step 1 with a reason
require_cipher = false  # true refuses a client with no cipher in common
                        # rather than checking its password and going on
                        # in plaintext, as mhxd does
```

### `[rooms]`

Curated rooms ([chat-rooms.md](chat-rooms.md) §12). On unless `enabled =
false`; the rooms themselves are in `file`, not in the config.

```toml
[rooms]
enabled = true
file = "rooms.toml"      # relative to the working directory
lobby = "lobby"          # the lobby's name in listings and the ng rail
max_joined = 32          # rooms one session may be in
max_rooms = 256          # every entry, archived and tombstones included
announce = true          # the lobby notice to classic sessions
announce_names = 3       # names in that notice before "and n more"
```
