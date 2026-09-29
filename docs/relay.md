# hlrelay: a WebSocket front for a classic server

Status: built, with per-address limits, and without authentication,
TLS or bans of its own. The protocol it follows is `hotline-ng-auth.md`
§10.2; this document is how to run it.

A browser cannot open a TCP connection, so a web client cannot reach a
Hotline server that speaks only the classic protocol on its TCP ports —
which is nearly all of them. `hlrelay` runs beside such a server and
carries WebSockets to it: a client opens `/trtp` and speaks the classic
protocol inside it, byte for byte, and opens `/htxf` for each file
transfer. The server sees an ordinary client. Nothing about the server
changes, and it need not know the relay is there.

hxd-ng does not need it: its ng port serves the same paths itself.

## Running it

```sh
hlrelay --upstream 127.0.0.1:5500
```

That listens on `127.0.0.1:5700` and relays to the server on port 5500
and its transfer port, 5501. It listens on loopback because a browser
needs TLS in front of it (below), and that proxy reaches it there, as
hxd-ng's ng listener does by default; `--listen 0.0.0.0:5700` serves
plain HTTP to everyone, for a client that is not a browser page.

| Flag | Default | |
|---|---|---|
| `--upstream HOST:PORT` | required | The server's classic port. Resolved on each connection, so a container name works. |
| `--transfer HOST:PORT` | upstream's port plus one | Its transfer port, when it is not the next one. |
| `--no-transfers` | | Serve no `/htxf`, for a server with no files and no banner. |
| `--listen ADDR` | `127.0.0.1:5700` | Where to listen. Repeat for several. |
| `--name NAME` | `hlrelay` | The server's name in discovery. A relay cannot ask the server: a classic server names itself only to a client that has logged in. Set it: the default is never the upstream's address, which discovery would publish to anyone. |
| `--max-connections N` | 512 | Sockets relayed at once, control and transfer together. Past it an upgrade is a `503`. |
| `--max-pending N` | 128 | HTTP connections accepted and not yet upgraded. Past it a connection is closed unanswered. |
| `--max-per-address N` | 16 | Connections one client address holds at once, relayed or not yet upgraded. `0` is no limit. |
| `--trusted-proxy ADDR[/BITS]` | none | A proxy whose forwarded header is believed. Repeat for several. |
| `--forwarded-header NAME` | `x-forwarded-for` | The header those proxies write the client's address into: `x-forwarded-for`, `forwarded` (RFC 7239), or `none`. |
| `-h`, `--help` | | Print the flags and exit. |

`RUST_LOG` sets the log level, `info` by default. Each socket is logged
when it opens and when it closes, with the client's address and the
bytes carried each way; behind a trusted proxy, with the address the
proxy forwarded and the proxy's own.
SIGTERM or Ctrl-C stops it, closing the sockets it carries.

### In Docker

hxd-ng's image carries `hlrelay` too, and runs it instead of the server
with `HXD_MODE=relay`, its flags taken from `HXD_RELAY_*` variables
([docker.md](docker.md#relay-mode) lists them):

```sh
docker run -d --name hlrelay --restart unless-stopped \
  -p 127.0.0.1:5700:5700 \
  --add-host host.docker.internal:host-gateway \
  -e HXD_MODE=relay \
  -e HXD_RELAY_UPSTREAM=host.docker.internal:5500 \
  -e HXD_RELAY_NAME="My Server" \
  -e HXD_RELAY_TRUSTED_PROXIES=gateway \
  ghcr.io/mishan/hxd-ng:latest
```

In a container it listens on `0.0.0.0:5700` by default, since nothing
outside can reach its loopback, and `-p` decides who reaches it. So the
startup warning about a loopback relay with no trusted proxy (below)
never appears there, though a proxy on the host is the usual case: it
reaches the relay from Docker's gateway, which is what `gateway` in
`HXD_RELAY_TRUSTED_PROXIES` stands for.

## Limits and proxies

What the relay spends is bounded three ways. `--max-connections` caps
the sockets it relays, each of which also holds a connection to the
server. `--max-pending` caps the HTTP connections it has accepted and
not yet upgraded; each has the header timeout, from when it connects,
to make its requests, after which it is closed once the request in
flight is answered: an upgrade whose dial to the server outlasts that
deadline still opens. And `--max-per-address`
caps what any one client address holds of both, so that one address
cannot take every slot. An IPv4 address counts as itself and an IPv6
one as its /64, which is what one subscriber is given; an IPv4 address
mapped into IPv6 is the IPv4 address. All three are the relay's however
many `--listen` addresses it has: every listener draws on the same
counts.

A client past its address's limit is refused. Connecting directly, it is
refused as it connects, closed before its request is read: answering
would mean holding the connection open to read it, which is what a flood
of connections wants. Through a trusted proxy its address is known only
once its request has been read, so its upgrade is answered `429`.

Behind a reverse proxy every client arrives from the proxy's address.
`--trusted-proxy` names the proxies whose forwarded header is believed,
and `--forwarded-header` which header they write, with the rules
hxd-ng's ng listener applies to `[ng] trusted_proxies` and
`[ng] forwarded_header` (`hotline-ng-auth.md` §6.3): the header is read
only from a listed proxy, and only the one named, since a proxy passes a
header it does not write straight through from the client. The client
is the rightmost address in the header that is not a listed proxy; an
element that names no address ends the search at the proxy. List
proxies only, never a range that holds clients. A connection from a
listed proxy is counted against its client's address rather than the
proxy's, and not before its request is read; the pending cap bounds
those. With `--forwarded-header none`, or a proxy left unlisted, every
client behind it shares the proxy's address and its limit, so raise
`--max-per-address` or set it to `0`.

Loopback is not trusted by default, though it is where the documented
proxy sits. A proxy believed without being configured to write the
header passes on whatever the client wrote in it, and each client could
name itself a new address with every connection; sharing one limit is
the failure that costs less. A relay that listens only on loopback with
no `--trusted-proxy` says so in a warning at startup instead.

## Where clients find it

A web client that is given a classic address — from a tracker, or a
`hotline://` URL — looks for `/.well-known/hotline` on the classic port
plus 200, then on 443 (`hotline-ng-auth.md` §5.1). So a server on 5500
wants its relay on 5700; a server on 6000, on 6200. A relay that shares
a host's web server on 443 can be found there too, by proxying
`/.well-known/hotline`, `/trtp` and `/htxf` to it.

## TLS

`hlrelay` speaks plain HTTP. A page served over `https` may only open
`wss://`, so in front of the relay goes a reverse proxy that holds a
certificate a browser trusts and forwards WebSocket upgrades — Caddy,
nginx, or anything else that does. With Caddy, for a host with a name:

```
hl.example.org:5700 {
    reverse_proxy 127.0.0.1:5701
}
```

and `hlrelay --listen 127.0.0.1:5701 --upstream 127.0.0.1:5500
--trusted-proxy 127.0.0.1 --name "My Server"`. Caddy writes the
client's address into `X-Forwarded-For`, which is the relay's default;
without `--trusted-proxy` every client would share Caddy's address and
its per-address limit. A server reached only by address can have a certificate for the address
itself; Let's Encrypt issues short-lived ones, renewed over port 80 or
443.

The hop from the relay to the server is plain TCP, as it is for any
client on the classic port, so keep the relay on the server's host.
HOPE, where the server offers it, passes through the relay untouched
and protects the login end to end.

## What it changes for the server

Every relayed client arrives from the relay's address. The server's own
address bans cannot tell them apart, and banning one bans the relay;
per-address connection limits count them all together, so a server
that has one should exempt the relay's address. Transfers work, because
a client's transfer connections leave from the same relay address as
its control connection, which is the address the server checks a
transfer against. The relay limits each client's address itself, as
§10.2 asks (see "Limits and proxies"); bans of its own are not built
yet.

## What it will not do

It connects only to the one server it was started for, on its two
ports. It is not a general proxy, and there is no flag to make it one.
