# Tracker registration

Status: implemented for HTRK v1 and v3.

This is hxd-ng's registering-server binding for fogWraith's
[classic tracker specification](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Tracker/Tracker.md)
and
[tracker protocol v3](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Tracker/Tracker-Protocol-v3.md).
It does not make hxd-ng a tracker and does not fetch tracker listings.

## 1. Configuration is the version negotiation

Tracker registration is UDP. A v1 tracker normally sends no response, so a
server cannot safely send a v3 probe and infer from silence that it should
fall back. Each target therefore names its wire version explicitly:

```toml
[tracker]
description = "A small Hotline community"
interval = 300
# advertised_port = 5500   # defaults to the legacy listener's actual port
# ack_timeout_ms = 2000

[[tracker.targets]]
address = "hltracker.example" # UDP/5499 by default
protocol = "v1"
# password = "private tracker password"

[[tracker.targets]]
address = "argus.example:5499"
protocol = "v3"
# password = "cleartext fallback"
hmac_secret = "shared HMAC secret"
```

An address is a host name or IP address with an optional port. An IPv6
address must be bracketed — `[2001:db8::1]` or `[2001:db8::1]:5499` — because
`2001:db8::1:5499` reads equally well as a bare address, and hxd-ng refuses to
guess which was meant.

The server name comes from `[server] name`; the tracker section adds its
description. `advertised_port` is for a public NAT mapping that differs from
the local listener. Each target is independent: DNS, send, or acknowledgment
failure for one is logged and retried without delaying another or stopping
the Hotline server.

The default heartbeat interval is five minutes. A v3 tracker can recommend a
different interval in its acknowledgment. hxd-ng accepts nonzero values from
30 seconds through one day and otherwise keeps the configured interval. The
first registration is sent immediately.

## 2. Classic v1

A v1 heartbeat contains the 12-byte big-endian header, a random nonzero
process-lifetime PassID, and Pascal strings for the name, description, and
optional password. Name and description use Mac Roman, matching the classic
Hotline wire. Unmappable characters in the name and description become `?`,
as they do everywhere on the classic wire, but a password must be exactly
representable in Mac Roman: a v1 tracker drops a wrong password silently, so a
degraded one would leave the server unlisted with nothing in the log. All
three are validated against the one-byte length limit rather than silently
truncated.
The live visible-session count is sampled for every heartbeat.

The PassID remains stable until the process exits so a tracker can coalesce a
heartbeat after an address or port change. v1 has no explicit deregistration;
its entry expires after heartbeats stop.

## 3. Version 3

A v3 target receives the v1-compatible prefix with version `0x0003`, UTF-8
Pascal strings, the `H3` extension marker, and typed TLVs. hxd-ng supplies
these live fields without operator duplication:

- software and legacy protocol version;
- process uptime;
- inline-media and voice support, only when those services were built and
  started;
- large-file (64-bit) transfer support, whenever the Files service was built —
  the same condition under which both wires echo the large-file capability;
- current visible-session count in the fixed header.

The optional `[tracker.v3]` table supplies operator facts:

```toml
[tracker.v3]
ipv6 = "2001:db8::10"
hostname = "hl.example"
country_code = "US"
region = "California"
language = "en"
maturity = 0                  # 0 general, 1 teen, 2 mature, 3 adult
rules_url = "https://hl.example/rules"
banner_url = "https://hl.example/banner.png"
icon_url = "https://hl.example/icon.png"
link_down_mbit = 1000
link_up_mbit = 100
timezone_offset_min = -420
contact_url = "mailto:admin@hl.example"
server_launched = 1788768000  # stable Unix timestamp, not process start
tags = "chat,retro"
private_listing = false
listing_category = 10        # 0 omitted; 1 through 12 are the spec vocabulary
listing_language_strict = false
```

Fields with no truthful source are omitted. In particular, hxd-ng does not
invent content totals, rolling user statistics, TLS/HOPE support, or activity
timestamps. `MAX_USERS` and `MIN_PROTOCOL_VERSION` are not configurable
either: the specification defines them as limits the server enforces at
login, and hxd-ng has no user cap or client-version floor to report. They
become live fields when those limits exist.

### Authentication and acknowledgments

When `hmac_secret` is set, every registration has a fresh random 8-byte nonce
and an HMAC-SHA256 over the full datagram with the signature value zeroed, as
the v3 specification requires. A configured legacy password remains in the
compatible prefix, but a conforming v3 tracker gives the HMAC precedence. That
is a fallback for a tracker without HMAC support, and it still sends the
password in the clear, so hxd-ng logs a warning at startup for any v3 target
configured with both.

Acknowledgments are optional. A valid success acknowledgment may provide a
registration token and heartbeat interval. Tokens are held only in memory,
scoped to the target that issued them, and included in its later heartbeats.
Malformed, oversized, or unknown-status acknowledgments are ignored as target
failures; unknown TLVs are skipped for forward compatibility.

On graceful shutdown hxd-ng sends each v3 target a `DEREGISTER` registration,
including its token and a fresh authenticated nonce when available. It waits
briefly for these datagrams to leave, but tracker failure never holds shutdown
indefinitely.

## 4. Transport boundary

Registration uses plaintext UDP. When a shared secret is configured, HMAC
authenticates the complete datagram and the nonce provides replay protection;
it does not encrypt the legacy-compatible name, description, or password.
DTLS is a separate transport feature and is not implemented. Operators who
need confidentiality should avoid a cleartext password and use a v3 tracker
with HMAC authentication.
