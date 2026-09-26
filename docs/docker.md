# Running hxd-ng in Docker

The image in the repository's `Dockerfile` is for operators: `hxd` and
`hlid` on Debian slim, running as an unprivileged user (uid 10001), with
every piece of state in one volume and the configuration taken from
environment variables. It is meant to sit behind a TLS-terminating
reverse proxy — nginx, Caddy, or whatever already fronts the host —
because the ng port speaks plaintext HTTP and WebSocket
([hotline-ng.md](hotline-ng.md)).

## Quick start

Every merge to `main` publishes the image for linux/amd64:

```sh
docker pull ghcr.io/mishan/hxd-ng:latest
docker run -d --name hxd-ng --restart unless-stopped \
  -v hxd-ng:/var/lib/hxd-ng \
  -p 5500-5501:5500-5501 \
  -p 127.0.0.1:5700:5700 \
  -e HXD_NAME="My Hotline Server" \
  -e HXD_NG_TRUSTED_PROXIES=127.0.0.1,::1,gateway \
  -e HXD_ADMIN_LOGIN=admin -e HXD_ADMIN_PASSWORD='change me' \
  ghcr.io/mishan/hxd-ng:latest
```

Tags are `latest` and `sha-<commit>`; pin the second in anything that
should not change under you. `docker build -t hxd-ng .` builds the same
image from a checkout (see [Building](#building)).

Then put [`docker/nginx.conf`](../docker/nginx.conf) in `/etc/nginx/conf.d/`
with your host name and certificate, and reload nginx. Classic clients
connect to port 5500; ng clients to `wss://hl.example/`.
[`docker/compose.yaml`](../docker/compose.yaml) is the same thing for
Compose, and names the container `hxd-ng` so the commands below work
with either. It runs the published image, so it can be copied anywhere
on its own; uncommenting its `build:` lines builds a checkout instead.

`gateway` in `HXD_NG_TRUSTED_PROXIES` is what lets nginx on the host
vouch for its clients; [the proxy](#the-proxy) says why it is needed and
when it is dangerous. Leave it out when no proxy runs on the host.

## Where things live

The paths inside the container are fixed; where they come from on the
host is the operator's choice.

`-v hxd-ng:/var/lib/hxd-ng` in the quick start is a **named volume**:
`hxd-ng` there is a name, not a directory, and Docker keeps the data in
its own storage (`docker volume inspect hxd-ng` shows where). It needs
nothing done first, and it is what `docker/compose.yaml` uses. To keep
the state in a directory on the host instead, bind-mount one — a source
with a `/` in it is a path. The examples in this document all use one
layout under `/srv/hxd-ng`:

| On the host | In the container | What | Mounted |
|---|---|---|---|
| `/srv/hxd-ng/data` | `/var/lib/hxd-ng` | All state: accounts, the SQLite store, news blobs, the identity, VAPID and self-signed TLS keys. | Always, or the named volume instead. |
| `/srv/hxd-ng/etc` | `/etc/hxd-ng` | A config file of the operator's own. | Only for [a mounted config](#configuration). |
| `/srv/hxd-ng/tls` | `/etc/hxd-ng/tls`, read-only | A certificate and key from a CA. | Only for [TLS certificates](#tls-certificates). |
| `/srv/hxd-ng/files` | `/srv/files` | The file area, with `HXD_FILES_ROOT=/srv/files`. | Only for files. |

A directory the server writes to must exist and be owned by uid 10001,
which is who the server runs as:

```sh
install -d -o 10001 -g 10001 -m 0700 /srv/hxd-ng/data
docker run -d --name hxd-ng --restart unless-stopped \
  -v /srv/hxd-ng/data:/var/lib/hxd-ng \
  ...
```

and the same for `files` if it takes uploads. `tls` only needs to be
readable by 10001.

## Ports

| Port | Protocol | Through the proxy? | What |
|---|---|---|---|
| 5500 | TCP | no | Legacy Hotline. 1.x clients have no TLS; publish it directly. |
| 5501 | TCP | no | HTXF file transfers, with `HXD_FILES_ROOT` or `HXD_BANNER_FILE`. |
| 5600 | TCP | no | Legacy Hotline over TLS, with `HXD_TLS_CERT` or `HXD_TLS_SELF_SIGNED`, for clients that speak it (GtkHx, Hotline Navigator). hxd terminates this TLS itself. |
| 5601 | TCP | no | HTXF over TLS, with TLS on and `HXD_FILES_ROOT` or `HXD_BANNER_FILE`. |
| 5504 | UDP | no | Voice and video media, with `HXD_VOICE_ADVERTISE`. |
| 5700 | TCP | **yes** | The ng WebSocket, the `/trtp` tunnel, discovery, identity, media and file downloads. |

The container listens on these (the ng port on `HXD_NG_BIND`); choose
the public side with `-p`. Keep the legacy and HTXF ports adjacent on
the public side too, since a classic client finds the transfer port by
adding one to the port it connected to: `-p 6500-6501:5500-5501` works,
`-p 6500:5500 -p 5501:5501` does not, and the same holds for 5600 and
5601. The voice port is free: clients send media to the addresses
`HXD_VOICE_ADVERTISE` names, so publish `-p 6504:5504/udp` and advertise
port 6504 to match.

**Voice from the LAN as well as the internet.** A server behind NAT
advertises its WAN address, and a client on the same LAN then has to
reach it through the router's hairpin NAT, which many routers do for
TCP but not for UDP: the call connects from outside and stalls from
inside. Offer the LAN address too. With the default wildcard bind the
server cannot tell which of two IPv4 addresses a datagram arrived on,
and hxd refuses the pair, so bind the LAN address itself — under
`--network host`, where the container has the host's addresses:

```sh
-e HXD_VOICE_BIND=192.168.1.10:5504 \
-e HXD_VOICE_ADVERTISE=203.0.113.5,192.168.1.10
```

Clients try every address offered and keep the one that answers. Those
outside also see the LAN address, which is harmless. On a bridge
network the container's own address is Docker's, not the LAN's, so this
needs host networking.

Publish 5700 on loopback only (`127.0.0.1:5700:5700`), so the proxy is the
only way in. The proxy is trusted to say who each client is, and anyone
who can reach the port around it can claim to be anyone.

**IPv6 clients and bans.** With Docker's default userland proxy, a
connection that reaches a published port over IPv6 is relayed into the
container's IPv4 network from the gateway address. Every IPv6 classic
client then shares one address, so banning one bans them all, and the
per-address limits count them together. Either set `"userland-proxy":
false` in `/etc/docker/daemon.json` or give the container's network IPv6
(`enable_ipv6` on a Compose network) so the real addresses arrive.

## The proxy

nginx needs the WebSocket upgrade, a long read timeout, the `Host` header,
`X-Forwarded-For`, and one line that matters for security: it must
**drop any `X-Hotline-Client-Cert` header a client sends**, because hxd
believes that header from a trusted proxy. `docker/nginx.conf` does all
of it. Caddy's `reverse_proxy` does the first four by itself; add
`header_up -X-Hotline-Client-Cert`, or set it from the client certificate
as in [hotline-ng-auth-rationale.md](hotline-ng-auth-rationale.md) §6.1.

Behind a proxy every ng connection comes from the proxy's address, so hxd
has to be told which addresses are proxies or every user shares one
address — one ban, one detached-session allowance.
`HXD_NG_TRUSTED_PROXIES` lists them, and defaults to loopback alone. The
addresses in it are believed about two things: the client's address in
`X-Forwarded-For`, and the client's device key in `X-Hotline-Client-Cert`.
List proxies and nothing else
([hotline-ng-auth-rationale.md](hotline-ng-auth-rationale.md) §6).

A proxy on the host reaches a published port through Docker, which
connects to the container from the network's gateway. The value `gateway`
stands for that address, and trusting it is an explicit choice because
the gateway is not only the proxy:

- **Never publish 5700 beyond loopback while trusting the gateway.**
  Published on a public address, clients arriving through Docker's
  userland proxy — every IPv6 client — come from the gateway too, and
  any of them can then claim another client's address or device key.
- With `--network host` there is no Docker gateway: the container's
  default route is the host's, so `gateway` would trust the LAN router.
  Leave it out there; nginx on the host reaches hxd from `127.0.0.1`.

The entry point logs the address `gateway` resolved to at each start. A
proxy in another container on a user-defined network arrives from its
own address instead: set the variable to that address, or to the
network's subnet if nothing but proxies and hxd-ng is on it.

## Configuration

At every start the entry point writes a config file from the variables
below to `/run/hxd-ng/hxd-ng.toml` and runs `hxd` with it, so reconfiguring
is changing a variable and recreating the container. Paths inside it are
all under `/var/lib/hxd-ng`.

For anything the variables don't reach, there are two ways out:

- `HXD_EXTRA_CONFIG=/path/to/fragment.toml` appends a file to the
  generated config. It may add sections the variables don't write —
  `[registrar]`, `[news.notify]`, `[media.rate]` — but not repeat one they
  do, which TOML refuses. Every key in it must sit under a section
  header: the fragment lands after whichever section was written last,
  so a key before its first header would join that one, and the entry
  point refuses the file instead.
- **A mounted config file wins outright.** When `/etc/hxd-ng/hxd-ng.toml`
  exists (or the file `HXD_CONFIG` names), it is used as it is and the
  variables are ignored. Relative paths in it resolve against
  `/var/lib/hxd-ng`. The [README](../README.md#configuration) documents
  every key. hxd's own defaults apply to what it leaves out, and those
  are not the container's: `[ng]` binds `127.0.0.1:5700` unless the file
  says otherwise, which nothing outside the container can reach, so set
  `bind = "0.0.0.0:5700"` there.

  `hxd identity revoke` edits the file in place: it writes
  `hxd-ng.toml.revoke` beside it and renames that over the original. So
  mount the **directory**, writable by uid 10001
  (`-v /srv/hxd-ng/etc:/etc/hxd-ng`, with `chown 10001:10001` on it), not
  the file alone: a single-file bind mount cannot be renamed over, and
  the image's own `/etc/hxd-ng` is not the server's to write.

Switches take `on` or `off` (or `true`/`false`, `yes`/`no`, `1`/`0`).
Where the tables below give a default, it is the container's; hxd's own
default applies where they don't, and hxd's differ from the container's
for `HXD_NG`, `HXD_IDENTITY`, `HXD_INBOX`, `HXD_HISTORY`, `HXD_NEWS` and
`HXD_MEDIA`, which the image turns on. A variable set for a feature that
is off (`HXD_VIDEO` without voice, say) is reported and ignored.

### Server

| Variable | Default | |
|---|---|---|
| `HXD_NAME` | `hxd-ng` | The server name clients show. |
| `HXD_AGREEMENT_FILE` | `/var/lib/hxd-ng/agreement.txt` when it exists | The agreement shown at login (UTF-8). |
| `HXD_BANNER_FILE` | | A JPEG, GIF or PNG of at most 1 MiB, mounted into the container, shown to clients as the server banner. Publish 5501 for it. `docker kill -s HUP hxd-ng` re-reads it. |
| `HXD_BANNER_URL` | | With `HXD_BANNER_FILE`, where a click on the banner goes. Alone, where clients fetch the banner from. |
| `HXD_BAN_TIME` | 1800 | Seconds a kick-with-ban holds the address. |
| `HXD_LOGIN_TIMEOUT` | 10 | Seconds a connection has to log in. |

### First administrator

| Variable | |
|---|---|
| `HXD_ADMIN_LOGIN` | Writes `accounts/<login>.toml` with every access bit, on the first start that sees it. Logins are case-insensitive, so the file is named in lower case. |
| `HXD_ADMIN_PASSWORD` | Its password. Needed only by the start that writes the file. |
| `HXD_ADMIN_PASSWORD_FILE` | Or read the password from a file — a Docker or Swarm secret. |
| `HXD_GUEST` | `on`: a fresh volume gets the guest account, as hxd gives one on its own. `off` leaves guests out. Read only while the accounts directory does not exist yet. |

The account is written once and never touched again, so a password
changed in the file stays changed, and once the file exists the password
variable can be removed. Other accounts are TOML files in
`/var/lib/hxd-ng/accounts` ([access-bits.md](access-bits.md)); edit them
with `docker exec -it hxd-ng sh` or from the volume. hxd reads them at
each login, so there is nothing to restart.

### Hotline-ng and identity

| Variable | Default | |
|---|---|---|
| `HXD_NG` | `on` | The WebSocket frontend on 5700. |
| `HXD_NG_BIND` | `0.0.0.0:5700` | Where it listens inside the container. |
| `HXD_NG_TRUSTED_PROXIES` | `127.0.0.1,::1` | Addresses and CIDR blocks the proxy headers are believed from. `gateway` is the container's default gateway — read [the proxy](#the-proxy) before adding it. Empty or `none` believes nobody. |
| `HXD_NG_FORWARDED_HEADER` | `x-forwarded-for` | Or `forwarded`, or `none`. |
| `HXD_NG_GRACE` | 300 | Seconds a dropped ng session waits to be resumed. |
| `HXD_NG_MAX_DETACHED_PER_ADDR` | 2 | Detached sessions per client address. |
| `HXD_IDENTITY` | `on` | Portable identity and the `/trtp` tunnel ([hotline-ng-identity.md](hotline-ng-identity.md)). The server key is generated into the volume on first start. |
| `HXD_IDENTITY_NEW_ACCOUNTS` | `guest` | `deny`, `guest` or `create`. |
| `HXD_IDENTITY_UNATTESTED` | `guest` | `deny`, `guest` or `allow`. |
| `HXD_IDENTITY_WEB` | | Where a web client for this server lives, e.g. `https://hl.example/app/`. |
| `HXD_REVOKED_IDENTITIES` | | Identity fingerprints refused, every device of each, comma-separated in the 52-character form `hlid` prints. |
| `HXD_REVOKED_DEVICES` | | Device fingerprints refused: one stolen device, leaving the identity's others in. |

### Stored features

All of these share one SQLite file, `/var/lib/hxd-ng/hxd-ng.sqlite`.

| Variable | Default | |
|---|---|---|
| `HXD_INBOX` | `on` | Offline private messages ([private-messages.md](private-messages.md)). |
| `HXD_INBOX_MAX_QUEUED` | 200 | Messages waiting per account. |
| `HXD_INBOX_RETAIN_UNREAD` | 2592000 | Seconds an unread message is kept. |
| `HXD_INBOX_RETAIN_READ` | 604800 | Seconds a read one is kept. |
| `HXD_HISTORY` | `on` | Chat scrollback ([chat-history.md](chat-history.md)). |
| `HXD_HISTORY_MAX_LINES` | 10000 | Lines kept; 0 is unlimited. |
| `HXD_HISTORY_MAX_DAYS` | 0 | Days kept; 0 is unlimited. |
| `HXD_NEWS` | `on` | Threaded news ([news.md](news.md)). |
| `HXD_NEWS_RETAIN_DAYS` | 0 | A thread's life after its last post; 0 is forever. |
| `HXD_MEDIA` | `on` | Images in chat ([inline-media.md](inline-media.md)). Sending one needs the `send_media` bit: the account `HXD_ADMIN_LOGIN` writes has it, and any other account only if its file grants it. |
| `HXD_PUSH_CONTACT` | | Turns on Web Push; a `mailto:` or `https:` contact for push services ([webpush-gateway.md](webpush-gateway.md)). The VAPID key is generated into the volume, and losing it silently breaks every subscription — back it up. |
| `HXD_PUSH_CONTENT` | `sender` | `full`, `sender` or `generic`. |

### Everything else

| Variable | Default | |
|---|---|---|
| `HXD_SYSTEM` | `off` | The server account on the user list, and its commands ([system-account.md](system-account.md)). |
| `HXD_SYSTEM_NICK` | `Server` | Its nick. |
| `HXD_FILES_ROOT` | | A directory in the container to serve as the file area (`/srv/files` in the examples); mount one there. Uploads go into folders named `Uploads` or `Drop Box`. It must be writable by uid 10001 for uploads. |
| `HXD_FILES_MAX_FILE_SIZE` | 64 GiB | Bytes per file. |
| `HXD_TLS_CERT` | | Turns on the TLS ports: a PEM certificate chain, leaf first, mounted into the container — Let's Encrypt's `fullchain.pem` where the server has a DNS name ([below](#tls-certificates)). `docker kill -s HUP hxd-ng` re-reads a renewed certificate without dropping anyone. |
| `HXD_TLS_KEY` | | Its PEM private key, readable by uid 10001. |
| `HXD_TLS_SELF_SIGNED` | `off` | Turns on the TLS ports with a self-signed certificate made in the volume on first start and kept, for a server with no name a CA will certify. Clients ask users to trust it on first connect; the fingerprint is in the log to publish. `HXD_TLS_CERT` wins when both are set. |
| `HXD_VOICE_ADVERTISE` | | Turns on voice: the public addresses clients send media to, comma-separated. A bare IPv4 address gets the port of `HXD_VOICE_BIND`, 5504 by default; write IPv6 as `[addr]:port`. Publish the UDP port to match. |
| `HXD_VOICE_BIND` | `0.0.0.0:5504` | The UDP address voice listens on inside the container. A concrete address lets `HXD_VOICE_ADVERTISE` name a LAN address beside the WAN one ([voice from the LAN](#ports)). |
| `HXD_VOICE_MAX_PER_ROOM` | 16 | Voice participants per room. |
| `HXD_VIDEO` | `off` | Video on top of voice. |
| `HXD_TRACKERS` | | Trackers to list the server on, comma-separated `host` or `host:port`, over HTRK v1. Use `HXD_EXTRA_CONFIG` for v3 ([tracker-registration.md](tracker-registration.md)). |
| `HXD_TRACKER_DESCRIPTION` | | The description trackers show. |
| `HXD_TRACKER_ADVERTISED_PORT` | | The public legacy port, when it isn't the one the server listens on. |
| `HXD_DEBUG` | | `proto` for the wire trace, `all` for everything. `RUST_LOG` wins when set. |

### TLS certificates

A certificate from a public CA is the one to use: clients check it
against the roots they already trust and connect without a prompt. The
one the proxy already holds for the ng port names the same host, so
there is usually nothing new to issue. The files under
`/etc/letsencrypt/live` are symlinks into a directory only root can
read, so rather than mounting them, copy the pair where the container
can read it and tell the server — at every renewal, from a certbot
deploy hook, `/etc/letsencrypt/renewal-hooks/deploy/hxd-ng.sh`:

```sh
#!/bin/sh
live=/etc/letsencrypt/live/hl.example
install -D -m 644 -o 10001 "$live/fullchain.pem" /srv/hxd-ng/tls/fullchain.pem
install -D -m 600 -o 10001 "$live/privkey.pem" /srv/hxd-ng/tls/privkey.pem
docker kill -s HUP hxd-ng 2>/dev/null || true
```

Make it executable and run it once by hand for the first copy. The
hook writes to the host's `/srv/hxd-ng/tls`; the server reads the same
files as `/etc/hxd-ng/tls`, where the mount puts them, so the variables
name the container's side ([where things live](#where-things-live)):

```sh
docker run ... \
  -v /srv/hxd-ng/tls:/etc/hxd-ng/tls:ro \
  -e HXD_TLS_CERT=/etc/hxd-ng/tls/fullchain.pem \
  -e HXD_TLS_KEY=/etc/hxd-ng/tls/privkey.pem \
  -p 5600-5601:5600-5601 \
  ...
```

In `docker/compose.yaml`, uncomment the `tls` volume, the two
variables, and the 5600-5601 ports line.

A server reached only by address cannot get one; `HXD_TLS_SELF_SIGNED=on`
is for that case. The pair lives in `/var/lib/hxd-ng/tls` and belongs in
the backups: a new one means every client that pinned the old one
warns.

## State and backups

Everything lives in `/var/lib/hxd-ng`: the accounts, the SQLite store,
the news attachment blobs, and the identity and VAPID keys. The keys
cannot be regenerated without every client noticing, so back up the
whole volume, not just the database.

A named volume is ready as it is. A bind-mounted directory must be owned
by uid 10001 ([where things live](#where-things-live)); one that already
holds state from elsewhere can be given over with
`chown -R 10001:10001 /srv/hxd-ng/data`.

The store runs in WAL mode, so copying the files of a running server can
catch it mid-write. The image has no `sqlite3`; stop the container and
copy the state. From a named volume:

```sh
docker stop hxd-ng
docker run --rm -v hxd-ng:/data:ro -v "$PWD":/backup debian:trixie-slim \
  tar -C /data -czf /backup/hxd-ng-backup.tar.gz .
docker start hxd-ng
```

From a bind-mounted directory, the same with
`tar -C /srv/hxd-ng/data -czf hxd-ng-backup.tar.gz .` on the host.

Or, to keep it running, point a `sqlite3` on the host at the database
(`docker volume inspect hxd-ng` gives a named volume's path) and use
`.backup`, then copy everything else beside it.

**Other users, read-only root.** The generated config goes in
`/run/hxd-ng`, the one place outside the volume the entry point writes.
`--read-only --tmpfs /run/hxd-ng:mode=1777` runs the image on a
read-only root filesystem; without the mode, Docker makes the tmpfs
root's and the server cannot write there. `--user` with another uid
takes the same tmpfs, since the image's own directory belongs to 10001,
and a bind-mounted state directory owned by that uid: a new named
volume copies the image's directory, owner and all, so it would belong
to 10001 too.

## Operating

Every `hxd` subcommand runs through the entry point with the same
configuration the server has:

```sh
docker exec hxd-ng hxd-entrypoint registrar invites --add 5
docker exec hxd-ng hxd-entrypoint inbox purge alice --dry-run
```

**Revoking a key** depends on where the config comes from. With the
variables, list the fingerprint in `HXD_REVOKED_IDENTITIES` (or
`HXD_REVOKED_DEVICES`) and recreate the container: the generated file is
rewritten at every start, so `hxd-entrypoint identity revoke` is refused
rather than recording a revocation the next start would drop. With a
mounted config (writable, as above), the command edits it, and SIGHUP
applies it without a restart, ending the sessions it now refuses:

```sh
docker exec hxd-ng hxd-entrypoint identity revoke <fingerprint>
docker kill -s HUP hxd-ng
```

Anything that is not a subcommand runs as given, so
`docker run --rm hxd-ng hlid --help` works too. `docker stop` sends
SIGTERM, which hxd handles; there is no need for `--init`.

The image's health check opens a connection to the legacy port from
inside the container. A mounted config that moves that port needs
`--health-cmd` to match, or `--no-healthcheck`.

## Building

`docker build` fetches the pinned hx-libs revision itself. Cargo's
registry and target directory are BuildKit cache mounts, so a rebuild
after a source change recompiles only what changed.

```sh
docker build --build-arg CARGO_FEATURES="--no-default-features --features inbox" -t hxd-ng .
```

leaves voice, media, markdown and push out of the binary; their variables
must then stay off (`HXD_MEDIA=off`), since a section the build can't
serve is a startup error rather than a silently ignored promise.
`RUST_VERSION` and `DEBIAN_RELEASE` pick the toolchain image and the base.

CI builds the image on every pull request and starts it once, checking
that the legacy port and the ng discovery endpoint answer; a merge to
`main` does the same and then publishes it
(`.github/workflows/docker.yml`). The published image is linux/amd64
only: building the Rust workspace for arm64 under emulation would take
far longer than the rest of CI. Build it on an arm64 host for one.
