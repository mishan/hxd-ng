# Running hxd-ng in Docker

The image in the repository's `Dockerfile` is for operators: `hxd` and
`hlid` on Debian slim, running as an unprivileged `hxd` user, with every
piece of state in one volume and the configuration taken from
environment variables. It is meant to sit behind a TLS-terminating
reverse proxy — nginx, Caddy, or whatever already fronts the host —
because the ng port speaks plaintext HTTP and WebSocket
([hotline-ng.md](hotline-ng.md)).

## Quick start

```sh
docker build -t hxd-ng .
docker run -d --name hxd-ng --restart unless-stopped \
  -v hxd-ng:/var/lib/hxd-ng \
  -p 5500-5501:5500-5501 \
  -p 127.0.0.1:5700:5700 \
  -e HXD_NAME="My Hotline Server" \
  -e HXD_ADMIN_LOGIN=admin -e HXD_ADMIN_PASSWORD='change me' \
  hxd-ng
```

Then put [`docker/nginx.conf`](../docker/nginx.conf) in `/etc/nginx/conf.d/`
with your host name and certificate, and reload nginx. Classic clients
connect to port 5500; ng clients to `wss://hl.example/`.
[`docker/compose.yaml`](../docker/compose.yaml) is the same thing for
Compose.

## Ports

| Port | Protocol | Through the proxy? | What |
|---|---|---|---|
| 5500 | TCP | no | Legacy Hotline. 1.x clients have no TLS; publish it directly. |
| 5501 | TCP | no | HTXF file transfers, with `HXD_FILES_ROOT`. |
| 5504 | UDP | no | Voice and video media, with `HXD_VOICE_ADVERTISE`. |
| 5700 | TCP | **yes** | The ng WebSocket, the `/trtp` tunnel, discovery, identity, media and file downloads. |

The container always listens on these; choose the public side with
`-p`. Keep the legacy, HTXF and voice ports in their base-plus-one and
base-plus-four arrangement on the public side too, since a classic client
finds the transfer port by adding one to the port it connected to:
`-p 6500-6501:5500-5501` works, `-p 6500:5500 -p 5501:5501` does not.

Publish 5700 on loopback only (`127.0.0.1:5700:5700`), so the proxy is the
only way in. The proxy is trusted to say who each client is, and anyone
who can reach the port around it can claim to be anyone.

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
address — one ban, one detached-session allowance. `HXD_NG_TRUSTED_PROXIES`
defaults to loopback plus the container's default gateway, which is the
address a proxy on the host arrives from through a published port. A
proxy in another container on a user-defined network arrives from its own
address instead: set the variable to that address, or to the network's
subnet if nothing but proxies and hxd-ng is on it. List proxies and
nothing else ([hotline-ng-auth-rationale.md](hotline-ng-auth-rationale.md)
§6).

## Configuration

At every start the entry point writes a config file from the variables
below to `/run/hxd-ng/hxd-ng.toml` and runs `hxd` with it, so reconfiguring
is changing a variable and recreating the container. Paths inside it are
all under `/var/lib/hxd-ng`.

For anything the variables don't reach, there are two ways out:

- `HXD_EXTRA_CONFIG=/path/to/fragment.toml` appends a file to the
  generated config. It may add sections the variables don't write —
  `[registrar]`, `[news.notify]`, `[media.rate]` — but not repeat one they
  do, which TOML refuses.
- **A mounted config file wins outright.** When `/etc/hxd-ng/hxd-ng.toml`
  exists (or the file `HXD_CONFIG` names), it is used as it is and the
  variables are ignored. Relative paths in it resolve against
  `/var/lib/hxd-ng`. The [README](../README.md#configuration) documents
  every key. Mount it writable if you use `hxd identity revoke`, which
  edits it.

Switches take `on` or `off` (or `true`/`false`, `yes`/`no`, `1`/`0`).
Leaving a variable unset takes hxd's own default.

### Server

| Variable | Default | |
|---|---|---|
| `HXD_NAME` | `hxd-ng` | The server name clients show. |
| `HXD_AGREEMENT_FILE` | `/var/lib/hxd-ng/agreement.txt` when it exists | The agreement shown at login (UTF-8). |
| `HXD_BAN_TIME` | 1800 | Seconds a kick-with-ban holds the address. |
| `HXD_LOGIN_TIMEOUT` | 10 | Seconds a connection has to log in. |

### First administrator

| Variable | |
|---|---|
| `HXD_ADMIN_LOGIN` | Writes `accounts/<login>.toml` with every access bit, on the first start that sees it. |
| `HXD_ADMIN_PASSWORD` | Its password. |
| `HXD_ADMIN_PASSWORD_FILE` | Or read the password from a file — a Docker or Swarm secret. |
| `HXD_GUEST` | `on`: a first start also writes the guest account, as hxd does on its own. `off` leaves guests out. |

The account is written once and never touched again, so a password
changed in the file stays changed. Other accounts are TOML files in
`/var/lib/hxd-ng/accounts` ([access-bits.md](access-bits.md)); edit them
with `docker exec -it hxd-ng sh` or from the volume. hxd reads them at
each login, so there is nothing to restart.

### Hotline-ng and identity

| Variable | Default | |
|---|---|---|
| `HXD_NG` | `on` | The WebSocket frontend on 5700. |
| `HXD_NG_TRUSTED_PROXIES` | `127.0.0.1,::1,gateway` | Addresses and CIDR blocks the proxy headers are believed from. `gateway` is the container's default gateway; empty or `none` believes nobody. |
| `HXD_NG_FORWARDED_HEADER` | `x-forwarded-for` | Or `forwarded`, or `none`. |
| `HXD_NG_GRACE` | 300 | Seconds a dropped ng session waits to be resumed. |
| `HXD_NG_MAX_DETACHED_PER_ADDR` | 2 | Detached sessions per client address. |
| `HXD_IDENTITY` | `on` | Portable identity and the `/trtp` tunnel ([hotline-ng-identity.md](hotline-ng-identity.md)). The server key is generated into the volume on first start. |
| `HXD_IDENTITY_NEW_ACCOUNTS` | `guest` | `deny`, `guest` or `create`. |
| `HXD_IDENTITY_UNATTESTED` | `guest` | `deny`, `guest` or `allow`. |
| `HXD_IDENTITY_WEB` | | Where a web client for this server lives, e.g. `https://hl.example/app/`. |

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
| `HXD_NEWS` | `on` | Threaded news on the ng wire ([news.md](news.md)). |
| `HXD_NEWS_RETAIN_DAYS` | 0 | A thread's life after its last post; 0 is forever. |
| `HXD_MEDIA` | `on` | Images in chat ([inline-media.md](inline-media.md)). Sending one needs the `send_media` bit, which no account has unless its file grants it. |
| `HXD_PUSH_CONTACT` | | Turns on Web Push; a `mailto:` or `https:` contact for push services ([webpush-gateway.md](webpush-gateway.md)). The VAPID key is generated into the volume, and losing it silently breaks every subscription — back it up. |
| `HXD_PUSH_CONTENT` | `sender` | `full`, `sender` or `generic`. |

### Everything else

| Variable | Default | |
|---|---|---|
| `HXD_SYSTEM` | `off` | The server account on the user list, and its commands ([system-account.md](system-account.md)). |
| `HXD_SYSTEM_NICK` | `Server` | Its nick. |
| `HXD_FILES_ROOT` | | A directory in the container to serve as the file area; mount one there. Uploads go into folders named `Uploads` or `Drop Box`. It must be writable by uid 10001 for uploads. |
| `HXD_FILES_MAX_FILE_SIZE` | 64 GiB | Bytes per file. |
| `HXD_VOICE_ADVERTISE` | | Turns on voice: the public addresses clients send media to, comma-separated. A bare IPv4 address gets port 5504; write IPv6 as `[addr]:port`. Publish `5504:5504/udp` to match. |
| `HXD_VOICE_MAX_PER_ROOM` | 16 | Voice participants per room. |
| `HXD_VIDEO` | `off` | Video on top of voice. |
| `HXD_TRACKERS` | | Trackers to list the server on, comma-separated `host` or `host:port`, over HTRK v1. Use `HXD_EXTRA_CONFIG` for v3 ([tracker-registration.md](tracker-registration.md)). |
| `HXD_TRACKER_DESCRIPTION` | | The description trackers show. |
| `HXD_TRACKER_ADVERTISED_PORT` | | The public legacy port, when it isn't the one the server listens on. |
| `HXD_DEBUG` | | `proto` for the wire trace, `all` for everything. `RUST_LOG` wins when set. |

## State and backups

Everything lives in `/var/lib/hxd-ng`: the accounts, the SQLite store,
the news attachment blobs, and the identity and VAPID keys. The keys
cannot be regenerated without every client noticing, so back up the
whole volume, not just the database. The store runs in WAL mode; stop
the container or use `sqlite3 .backup` for a consistent copy.

## Operating

Every `hxd` subcommand runs through the entry point with the same
configuration the server has:

```sh
docker exec hxd-ng hxd-entrypoint registrar invites --add 5
docker exec hxd-ng hxd-entrypoint inbox purge alice --dry-run
docker exec hxd-ng hxd-entrypoint identity revoke <fingerprint>   # needs a mounted, writable config
docker kill -s HUP hxd-ng        # re-read the revocation lists, dropping nobody
```

Anything that is not a subcommand runs as given, so
`docker run --rm hxd-ng hlid --help` works too. `docker stop` sends
SIGTERM, which hxd handles; there is no need for `--init`.

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
