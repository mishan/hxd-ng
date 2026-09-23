# Hotline-ng transport authentication

Status: partial — built in hxd-ng except the `bindings` setting, rate
limits on the endpoints (§12), the cleartext restriction policy (§8), and
any binding other than the two of §6.

> **Conformance language:** The key words "MUST", "MUST NOT", "REQUIRED",
> "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and
> "OPTIONAL" in this document are to be interpreted as described in
> [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

This document is normative. It states rules and cites their reasons
rather than arguing them: the reasoning, and the reverse-proxy recipes an
operator needs to meet §6.3's contract, are in
[hotline-ng-auth-rationale.md](hotline-ng-auth-rationale.md), cited as
"rationale §n". Values marked *hxd-ng* are that server's choices, not
requirements on other implementations.

Companion documents: `hotline-ng.md` (the WebSocket protocol this
extends), `hotline-ng-identity.md` (the Hotline identity profile: what a
key principal is, cards, account association), and
`identity-threat-model.md` (what all of this protects, and from whom).

---

## Contents

1. [Scope and conformance](#1-scope-and-conformance)
2. [Where authentication happens](#2-where-authentication-happens)
3. [The principal](#3-the-principal)
4. [Primitives](#4-primitives)
5. [Discovery](#5-discovery)
6. [Authentication](#6-authentication)
7. [Opening a WebSocket](#7-opening-a-websocket)
8. [Cleartext sessions and the legacy wire](#8-cleartext-sessions-and-the-legacy-wire)
9. [Account association](#9-account-association)
10. [Tunnels and relays](#10-tunnels-and-relays)
11. [Settings](#11-settings)
12. [Endpoint requirements](#12-endpoint-requirements)
13. [Open questions](#13-open-questions)

---

## 1. Scope and conformance

This document specifies how a connection to the ng listener acquires an
authenticated **principal** (§3) before the WebSocket upgrade, what the
transport may decide with one, and how the classic TRTP protocol is
carried over such a socket (§7.3). It does not say what a principal
*means*; that is a **profile**'s (§6.4). One profile is defined, in
`hotline-ng-identity.md`, and it is what hxd-ng implements.

Two bindings (§6.2, §6.3) produce a principal; both end in the same
state, a short-lived transport token bound to the principal (§6.1),
which the client presents when it opens a WebSocket (§7.1). Two
application protocols run over the authenticated socket: the ng JSON
protocol of `hotline-ng.md` (§7.2) and TRTP in binary frames (§7.3). The
classic wire on its own TCP port is not changed by anything here.

The roles this document constrains:

- **A server** terminates the socket and the application protocol on it.
  A conforming server implements §4–§9 and §12 and at least one binding.
- **A relay** terminates the socket but forwards its bytes to a legacy
  server (§10.2). It implements §4–§7 and §10.2, and never §9.
- **A tunnel** is a client that carries a classic client's bytes to a
  server (§10.1).
- **A client** follows §5–§7 and the client rules of §8.
- **A reverse proxy** in front of any of these, if it forwards client
  certificates, meets the contract of §6.3.

## 2. Where authentication happens

Authentication happens over HTTP, before the WebSocket upgrade, on the
same listener that accepts the upgrade (rationale §2). The endpoints of
§5 and §6 MUST be served by that listener; their paths are those
discovery advertises (§5), and a client MUST read them from discovery
rather than assume them.

On an authenticated socket the application protocol carries no
credentials: the socket already belongs to its principal when the first
frame arrives.

## 3. The principal

A principal is server-side state attached to one socket, never a wire
object. The fields name what a server knows; they are not an encoding.

| Field | Meaning |
|---|---|
| `method` | How the party was authenticated, and so the namespace `id` lives in. This document defines `key`: an Ed25519 public key whose holder signed a challenge (§6.2) or presented it in a TLS client certificate (§6.3). §6.5 sketches `oidc`, `saml` and `webauthn` without defining them. |
| `id` | Stable and unique within `method`. For `key`, the fingerprint of the key (§4.2). For a method that authenticates against a third party, the issuer and the issuer's subject identifier together, never the subject alone. |
| `subject` | Who this principal is an instance of, set by the profile; `id` when the profile sets none. The Hotline identity profile sets the *identity* fingerprint, so that every device of one person is one subject. |
| `key` | A public key, present only when its holder can sign arbitrary bytes with it (a `key` principal's key can; a WebAuthn credential's cannot). A profile MUST NOT build signed objects on a principal without one. |
| `profile` | What the profile verified and carries with the socket. Under Hotline identity: the card, the device certificate, the accepted attestations, and the derived handle and age. |

Rules (rationale §3):

- **Policy keys on `(method, subject)`.** Allow lists, bans and "already
  connected from this principal" MUST be decided on the subject within
  its method. A list of bare fingerprints is a list of `key` principals.
- **Bindings of one method are indistinguishable.** A key proved by
  challenge and the same key presented in a certificate MUST produce the
  same principal, and nothing downstream may behave differently for
  them. Different methods are distinguishable by `method`.
- **Every principal has a profile** (§6.4). A server MUST NOT admit a
  `key` principal except under a profile; for `key` the only profile is
  Hotline identity. A method that authenticates against a third party
  MAY define a default profile as part of its definition.
- **The transport decides only on its own grounds.** A binding whose
  proof fails is refused by the transport. Whether an otherwise valid
  principal is *admitted* is the profile's decision, at the profile's
  step of the `auth` request (§6.4).
- **A principal belongs to one socket.** A session — the application
  object with a uid — is created by the application login on that socket,
  may be resumed on another, and carries whatever it copied from the
  principal at login. The profile says what is copied
  (`hotline-ng-identity.md` §6).

## 4. Primitives

### 4.1 Encoding and signatures

Signed objects in this document and in every profile are CBOR (RFC 8949)
in deterministic encoding (RFC 8949 §4.2.1). A signature covers the
object's encoded bytes with the `sig` entry removed, prefixed by a domain
string:

```
sig = Ed25519.sign(key, domain || 0x00 || cbor_bytes_without_sig)
```

- Verifiers MUST check the signature over the bytes as received, and
  MUST reject a non-deterministic encoding.
- In JSON, an object is carried as base64url, without padding, of its
  CBOR bytes.
- Every object has an integer `v`; this document defines `v = 1`. A
  reader MUST reject a `v` it does not know, including `0`.
- Unknown keys MUST be ignored on read. They are covered by the
  signature.
- Timestamps are Unix seconds, UTC. `bstr(n)` is a byte string of
  exactly `n` bytes.

`hotline-ng-identity.md` §3.1 restates these rules so that it stands
alone; the two MUST NOT drift. *hxd-ng:* `crates/hl-identity` implements
both.

### 4.2 Fingerprint

`SHA-256(pubkey)`, 32 bytes, displayed as lowercase Crockford base32
without padding (52 characters). A UI MAY shorten it to 8 characters.
Servers MUST store and compare full fingerprints. A `key` principal's
`id` is the fingerprint of its key; a profile may define fingerprints of
other keys.

### 4.3 Server key

A server implementing this document MUST have an Ed25519 keypair,
generated on first start and kept across restarts. It is published in
discovery (§5), bound into login proofs (§6.2), and used by the
federation spec to sign. It is not a TLS key.

## 5. Discovery

`GET /.well-known/hotline` on the ng listener MUST be served without
authentication, as `application/json`:

```jsonc
{
  "v": 1,
  "name": "My Server",
  "server_key": "…base64url 32 bytes…",
  "ng": { "ws": "/ng", "trtp": "/trtp" },
  "identity": {
    "enabled": true,
    "bindings": [ "challenge", "mtls" ],
    "association": "server",
    "endpoints": {
      "challenge": "/identity/challenge",
      "auth":      "/identity/auth",
      "card":      "/identity/card",
      "link":      "/identity/link",
      "unlink":    "/identity/unlink",
      "enroll":    "/identity/enroll"
    },
    "new_accounts": "guest",
    "min_attestation_age": 0,
    "trusted_registrars": [],
    "web": "https://hl.example/app/"
  },
  "registrar": null
}
```

This document owns:

| Field | Rule |
|---|---|
| `v` | `1`. |
| `name` | The server's name. |
| `server_key` | The server key (§4.3), base64url. MUST be present when `identity.enabled` is true. *hxd-ng* sends `null` when identity is disabled. |
| `ng.ws` | The path of the ng JSON protocol (§7.2). |
| `ng.trtp` | The path of TRTP over WebSocket (§7.3). Present only when the server serves it. |
| `identity.enabled` | Whether this listener authenticates (§6). When `false`, the rest of the `identity` block MAY be absent, and so it is in hxd-ng. |
| `identity.bindings` | The bindings of §6 this server accepts: `challenge`, `mtls`. |
| `identity.association` | `server` when the listener can associate accounts with principals (§9); `none` on a relay (§10.2). |
| `identity.endpoints.challenge`, `.auth` | Where §6.2 and §6.3 are served. |

The block is named for the profile the key binding shipped with. A
future binding MUST get a block of its own, with its own `endpoints`.
Everything else under `identity` is the profile's
(`hotline-ng-identity.md` §4), except `endpoints.enroll` and `web`, which
are `identity-enrollment.md` §3's. `registrar` is a registrar's own
block (`identity-registrar.md` §3), or `null`; *hxd-ng* always sends
`null`.

A client MUST ignore fields it does not recognize, and MAY cache the
document for the life of a connection; a relay MAY cache it per
upstream. The same format serves servers, registrars, relays and
tunnels.

## 6. Authentication

### 6.1 Model

A binding ends by minting a **transport token** and binding a principal
(§3) to it server-side. The token:

- is an opaque bearer string; clients MUST NOT interpret it (*hxd-ng:*
  32 CSPRNG bytes, base64url);
- MUST expire; the `expires_in` the binding returns says when (*hxd-ng:*
  60 seconds);
- MUST be spent by the upgrade that redeems it (§7.1): one token opens at
  most one socket. The profile's own authenticated endpoints
  (`hotline-ng-identity.md` §8.2, §8.4, and the card upload) accept it
  without spending it, until it expires;
- authenticates a socket, not a session (rationale §4), and serves both
  WebSocket paths of §7.

The upgrade (§7.1) redeems the token and reads the principal off it; it
never sees a proof, a key, a certificate or an assertion. The server
ends in the same state whichever binding minted the token.

### 6.2 Challenge binding

Works for every client, browsers included.

**Step 1.** `POST` to the `challenge` endpoint, with an empty body.

```jsonc
{ "challenge": "…base64url 32 bytes…", "server_key": "…", "expires_in": 60 }
```

The server MUST store the challenge for `expires_in` seconds and MUST
consume it on use. *hxd-ng* bounds the number of outstanding challenges
and answers `503` when the bound is reached.

**Step 2.** `POST` to the `auth` endpoint:

```jsonc
{
  "proof":      "…base64url CBOR…",
  "downstream": "local",        // optional: local | cleartext
  // …plus what the profile requires (§6.4): for Hotline identity, "card"
  // and "device_cert", and optionally "login", "password", "create"
}
```

`proof` is a **login proof**, domain `hl-identity/login/v1`, signed by
the key being proved:

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `challenge` | bstr(32) | yes | From step 1. |
| `server_key` | bstr(32) | yes | From step 1. Binds the proof to this server (rationale §5). |
| `device` | bstr(32) | yes | The public key the proof is signed with. Named for the identity profile, where it is a device key; the transport reads it as *the key*. |
| `time` | uint | yes | The signer's clock. |
| `sig` | bstr(64) | yes | |

`downstream` declares the hop *behind* the client (§8): `local` (the
default) for a client that is the endpoint or a tunnel listening only on
loopback, `cleartext` for a tunnel forwarding over a network hop.
*hxd-ng* also accepts `loopback` as a synonym for `local`. Any other
value, of any JSON type, is a `400`.

The transport's check, failing on the first error: the signature
verifies with `device`; `challenge` is known and unexpired; `server_key`
is this server's; `time` is within the server's clock-skew tolerance
(*hxd-ng:* 300 seconds). Passing it establishes a `key` principal whose
`id` is the fingerprint of `device`. The profile's verification then
runs on the same request (§6.4).

On success, `200`:

```jsonc
{
  "token": "…",
  "expires_in": 60
  // …plus the profile's fields: for Hotline identity, "fingerprint",
  // "handle", "age", "outcome", "account" (hotline-ng-identity.md §5.3)
}
```

On failure, `{ "error": code, "text": "…" }`. The transport's codes:

| `code` | Status | Meaning |
|---|---|---|
| `bad_proof`, `unknown_challenge` | 401 | Prove it again. |
| `denied` | 403 | Policy refused this principal. |
| `server_error` | 500 | The server failed. |

A profile adds codes of its own in the same shape
(`hotline-ng-identity.md` §5.3). A client MUST treat any `401` as "prove
it again", any `403` as "not with this principal", and a code it does
not recognize by its status. A body the server cannot parse, or one
missing a field this document or the profile requires, is a `400` with a
plain-text reason, not a JSON error. A server without authentication
enabled answers `404` on these endpoints.

### 6.3 mTLS binding

For clients that can present a TLS client certificate: native apps,
tunnels and relays.

**The certificate** is a self-signed X.509 certificate whose
SubjectPublicKeyInfo is the Ed25519 public key being proved (RFC 8410).
Nothing else in it is examined: validity dates, subject and extensions
are ignored, because the profile's objects are the authority on all of
that. The key MUST be read from the SubjectPublicKeyInfo **by position**
— `Certificate` → `TBSCertificate`, skipping `version`, `serialNumber`,
`signature`, `issuer`, `validity` and `subject` — and MUST NOT be found
by searching the DER (rationale §6).

**The proxy contract.** A server that does not terminate TLS itself
receives the certificate from its reverse proxy, as base64 DER in
`X-Hotline-Client-Cert`.

- The proxy MUST request, and MUST NOT require, a client certificate.
- The proxy MUST set `X-Hotline-Client-Cert` from the certificate that
  took part in its own TLS handshake, and MUST remove any copy the client
  sent.
- The server MUST honor the header only from an address in its trusted
  proxies (*hxd-ng:* `[ng] trusted_proxies`), and MUST ignore it from
  anywhere else.
- An empty or all-whitespace value means no certificate.
- A value from a trusted proxy that does not decode to a certificate with
  an Ed25519 key MUST be answered `400`, never treated as an
  unauthenticated request.

Rationale §6.1 has working Caddy and nginx configurations.

**The client's address.** A trusted proxy is also believed about whom it
speaks for. The address the server keys bans and per-address limits on
MUST be the **rightmost element that is not itself a trusted proxy**,
read across every line, in order, of the one forwarded header the server
is configured to read (*hxd-ng:* `[ng] forwarded_header`:
`X-Forwarded-For`, RFC 7239 `Forwarded`, or none). An element the server
cannot parse ends the walk, and the socket's peer is used. A server MUST
NOT read both headers. The trusted-proxy list MUST contain proxies and
no clients (rationale §6).

**The request.** With a client certificate on the connection, the `auth`
request MAY omit `proof` and carry only what the profile requires:

```jsonc
{ "card": "…", "device_cert": "…" }     // the identity profile's fields
```

The transport's check is that the certificate's key is the key the
profile's objects name (under Hotline identity, `device_cert.device`);
the profile's verification then runs as for §6.2, and the response and
error codes are the same.

**Requests carrying `Origin`.** A request with an `Origin` header MUST
NOT be authenticated by a client certificate: `auth` without `proof` is
then a `400`, and the upgrade requires a token (§7.1), whether or not a
certificate is present (rationale §6).

**A key on file.** Once a key's profile objects are on file, an upgrade
carrying a client certificate for that key is authenticated without a
token (§7.1), for as long as the profile says those objects are valid.
The `auth` call is therefore needed once per key, and again when the
profile's objects change. The principal such an upgrade yields MUST carry
the `downstream` the key last declared at `auth` (§8). What "on file"
means and what is re-checked on each upgrade is the profile's
(`hotline-ng-identity.md` §5.5).

### 6.4 Profiles

A binding proves possession of something; a profile says what it is
worth. They meet at the `auth` request:

- the profile adds fields to the request and to the success response;
- the profile's verification runs after the transport's, on the same
  request, in an order the profile defines, and refuses with its own
  codes;
- the profile sets the principal's `subject` and `profile` (§3), and MAY
  restrict what the principal may do;
- the profile says what a session copies from the principal at login,
  what the roster shows (§7.2), and whether and how the principal
  associates with an account (§9).

This document defines no profile. `hotline-ng-identity.md` defines the
Hotline identity profile for `key` principals: a key is a device
certified by an identity, and a request without a valid card and device
certificate is refused. A binding of another method would be specified
in this document with its own steps, and with a default profile or a
pointer to one; whether it yields a signing `key` is part of its
definition.

### 6.5 Other methods

None of these is defined or implemented, and no implementation is
required to support them. Each would reach a transport token through its
own standard and present it at the upgrade exactly as §7.1 describes; a
method that arrives by browser redirect is what `?token=` exists for.
The principal each would produce:

| Method | `id` | `key` | Default profile |
|---|---|---|---|
| `oidc` | issuer URL and `sub`, together | none | the display-name claim and whatever the operator maps; nothing signed |
| `saml` | IdP `entityID` and `NameID`, together, the `NameID` format included in the comparison | none | mapped attributes, as for OIDC |
| `webauthn` | this server's relying-party id and the credential id, together | **absent**: the authenticator signs only its own assertions | the display name given at registration |

A row that turns out wrong means §3 is wrong first. Rationale §10 records
which of these to define if asked.

## 7. Opening a WebSocket

Both WebSocket paths advertised in discovery are authenticated the same
way and differ only in what flows after the upgrade.

### 7.1 Presenting the transport token

An upgrade request is authenticated by the first of these it carries, in
this order; the others are not consulted:

1. `Authorization: Bearer <token>` — for any client that can set headers.
2. `?token=<token>` in the upgrade URL — for browsers.
3. A client certificate for a key on file (§6.3), forwarded under the
   proxy contract — no token at all. Not available to a request with
   `Origin`.

The server MUST validate the upgrade request itself before redeeming a
token, so that a malformed handshake (a `400`) does not spend it.

The upgrade MUST be refused with `401`, and MUST NOT proceed as an
unauthenticated socket, when:

- the token is unknown, expired or already spent;
- `Authorization` is present but is not a Bearer token;
- a token is presented to a server that does not authenticate;
- on a server that authenticates, with no token presented, a client
  certificate is presented for a key not on file, or on a request with
  `Origin`.

On a server that authenticates, with no token presented, an undecodable
certificate header from a trusted proxy is a `400` (§6.3). A server that
does not authenticate does not offer the mTLS binding and ignores the
header.

An upgrade with no token and no certificate is unauthenticated and
proceeds exactly as it would without this document: the ng JSON
handshake of `hotline-ng.md` §6, or a classic TRTP handshake in the
tunnel.

A deployment that serves the `?token=` form MUST keep the query string
out of its logs on these paths — access logs, error logs, and any
redirect or upgrade-failure log (rationale §4). Cookies MUST NOT
authenticate an upgrade.

### 7.2 The ng JSON protocol (`ng.ws`)

On an authenticated socket the first request is still `login`. What the
server does with its `login` and `password` params is the profile's
decision — under Hotline identity they are ignored and SHOULD be omitted
(`hotline-ng-identity.md` §6.1) — and the account the session lands on is
decided per §9. The reply is `hotline-ng.md` §6.1's, with the profile's
additions to `self`, and `caps` carries the profile's name (`identity`
for Hotline identity).

Each `user` object (`hotline-ng.md` §7.4) carries the required
`transport` field this document defines — `"encrypted"` or
`"cleartext"`, per §8 — and MAY carry a sub-object the profile defines
for what other users may know about the principal (the identity profile's
`identity: { fingerprint, handle }`).

`resume` is unaffected: the session token proves continuity, and what the
session copied from the principal belongs to the session, not the
connection.

### 7.3 TRTP over WebSocket (`ng.trtp`)

The socket carries the classic protocol unchanged, in binary frames whose
payloads, concatenated in order, are exactly the byte stream a TCP
connection to the classic port would carry, in both directions.

- Frame boundaries carry no meaning. Either side MAY split or join
  transactions across frames.
- A text frame on this path is a protocol error; the server MUST close
  the socket.
- Inside the tunnel the client performs the ordinary TRTP handshake and
  Login (107) with whatever classic credentials it has. What the server
  does with them, given the principal on the socket, is account
  association (§9; under Hotline identity, `hotline-ng-identity.md`
  §8.3).
- The server treats the session as encrypted for §8, subject to
  `downstream`.
- A server MAY refuse to negotiate HOPE transport encryption inside the
  tunnel.
- The server SHOULD send a WebSocket ping on a quiet socket and MAY drop
  one that has sent nothing for several ping periods (*hxd-ng:* a ping
  every 30 seconds, dropped after three silent periods). Classic sessions
  have no idle traffic of their own, so this is what notices a peer that
  has gone and what keeps a NAT mapping alive. A tunnel answers pings as
  any WebSocket library does.

## 8. Cleartext sessions and the legacy wire

Nothing in this document adds fields or transactions to TRTP.

**The `transport` field.** A session is `cleartext` when any hop between
its client and the server is unencrypted as far as the server knows:

| Session | `transport` |
|---|---|
| Classic client on the TCP port, with HOPE transport encryption | `encrypted` |
| Classic client on the TCP port, without it | `cleartext` |
| Either WebSocket path over WSS, `downstream` `local` or absent | `encrypted` |
| Either WebSocket path over WSS, `downstream: "cleartext"` | `cleartext` |

*hxd-ng* does not implement HOPE, so every classic TCP session is
`cleartext`. It marks every WebSocket session by `downstream` alone,
assuming the TLS proxy `hotline-ng.md` §9 requires; it cannot check
that one is there.

A server MUST honor `downstream: "cleartext"`. A client MAY declare
itself less safe than it looks and never more (rationale §5). An ng
client MUST warn before sending a private message to a `cleartext`
session.

**The legacy marker.** A server MAY also set bit 4 (value 16) of User
Flags (112) for cleartext sessions on the classic wire. This bit is not
settled: Hotline 1.8/1.9 may already use that value for "automatic
response". A server MUST NOT set it by default until that is resolved
(§13; rationale §7). *hxd-ng:* `[server] mark_cleartext`, off.

**Cleartext policy.** A server MAY restrict cleartext sessions on its
classic port, in one of three positions: `off` refuses sessions that do
not negotiate HOPE (or the port sits behind a TLS wrapper); `restricted`
ANDs their access with an operator mask, whose recommended default
allows public chat and news reading only; `on` is legacy behavior, and
operator tooling SHOULD warn about it. *Design; hxd-ng reports
`transport` and can set the legacy marker, and restricts nothing.*

## 9. Account association

*Association* maps a principal to a local account. Only a server that
terminates the socket **and** implements the application protocol on it
MAY associate, because only it has the principal and the account table in
one place. A relay or tunnel MUST NOT, and a relay advertises
`association: "none"` (§5).

A stored link MUST record the principal's `method` and `subject`
together, so that links from different methods cannot collide; an account
MAY hold one link per method. Everything else — what a link is, which
paths write one, what happens to a principal with no account, how a
classic login inside a tunnel is reconciled with the principal on the
socket — is the profile's (`hotline-ng-identity.md` §8).

## 10. Tunnels and relays

Neither needs to parse the protocol it carries, and nothing here requires
TRTP knowledge. Neither is confidential: both handle the payload in the
clear (rationale §8).

### 10.1 Tunnel: legacy client → authenticating server

Runs where the user trusts, holds one key, listens on a local TCP port for
a classic client, and forwards bytes over TRTP over WebSocket (§7.3).

- It authenticates upstream with its own key, by either binding, with the
  objects its profile requires. Under Hotline identity it is a device like
  any other, with a device certificate scoped to what a tunnel needs
  (`hotline-ng-identity.md` §10).
- It MUST forward bytes verbatim in both directions and MUST NOT alter the
  classic login; the server reconciles that with the principal (§9).
- It MUST listen only on loopback unless its user opts in to another
  address. When it listens anywhere but loopback it MUST send
  `"downstream": "cleartext"` at `auth` (§6.2).

A native client MAY embed a tunnel, and a relay MAY act as one downstream.

### 10.2 Relay: authenticating front for a legacy server

Runs in front of a server that speaks only TRTP (hxd 0.x, Mobius,
HLServer). It serves discovery, the `challenge` and `auth` endpoints, the
profile's public endpoints and the WebSocket paths, and forwards each
socket's bytes to a TCP connection to the legacy server. It has a
principal for every socket and no account table.

- It holds its own server key (§4.3) and is, for authentication, the
  server: its allow list, ban list and the profile's admission policy
  apply at the HTTP layer, and the federation spec treats its signatures
  as the operator's.
- It MUST refuse a socket whose principal is banned, not on an allow list
  it enforces, or refused by the profile, before any bytes reach the
  legacy server.
- It MUST NOT associate accounts (§9), and advertises `association:
  "none"`. What the profile's endpoints return on a relay is the
  profile's (`hotline-ng-identity.md` §10).
- It adds nothing to the legacy wire. Clients connecting through it see
  principal information only through its discovery and the profile's
  public endpoints.
- It MAY offer `ng.ws` only by implementing the ng JSON protocol against
  TRTP downstream. A relay that offers only `ng.trtp` is complete.

### 10.3 What a server guarantees them

A server that follows this document gives tunnels and relays:

- a stable discovery document;
- single-use challenges, and tokens spent by the upgrade;
- the mTLS header contract, honored only from trusted proxies;
- a TRTP-over-WebSocket path that carries exactly the bytes the TCP port
  would, and pings a quiet socket.

A tunnel or relay that follows this section is indistinguishable, to the
server and to other users, from a native client, except that a
relay-fronted legacy server has no account association to offer.

## 11. Settings

Informative: what hxd-ng reads. A row marked *(not implemented)* is
design, and setting it is a startup error. The profile's settings are
`hotline-ng-identity.md` §12; they share `[identity]` because hxd-ng has
one profile and one switch.

| Setting | Default | Meaning |
|---|---|---|
| `[identity]` present | absent | The master switch for this document's endpoints and the identity profile together. Absent, discovery reports `enabled: false` and the endpoints answer `404`. Needs `[ng]`; `[identity]` without it is a startup error. |
| `[identity] key` | `identity-server.key` | The server's Ed25519 seed (§4.3), hex, mode 0600; generated on first run. |
| `[identity] clock_skew` | `300` | Seconds of tolerance on the proof's `time` (§6.2). |
| `[identity] trtp` | `true` | Serve TRTP over WebSocket (§7.3). |
| `[ng] trusted_proxies` | empty | Addresses whose `X-Hotline-Client-Cert` and forwarded-address headers are believed (§6.3). Single addresses or CIDR blocks; IPv4-mapped peers on a `[::]` bind match their IPv4 form. Proxies only, never a range that contains clients. Non-empty turns on the mTLS binding. |
| `[ng] forwarded_header` | `"x-forwarded-for"` | The one header a trusted proxy writes the client's address into: `"x-forwarded-for"`, `"forwarded"` (RFC 7239), or `"none"` (§6.3). |
| `[server] mark_cleartext` | `false` | The legacy marker of §8. |
| `[identity] bindings` | — | *(not implemented)* The challenge binding is always served, and mTLS whenever `[ng] trusted_proxies` is non-empty. |
| `[legacy] cleartext`, `cleartext_mask` | — | *(not implemented)* The cleartext policy of §8. |

## 12. Endpoint requirements

- **CORS.** The HTTP routes a browser client calls — discovery, the
  identity endpoints, the enrollment mailbox — MUST answer
  `Access-Control-Allow-Origin: *`, MUST answer the `OPTIONS` preflight
  (which `PUT` of a card as `application/cbor` triggers), and MUST name
  `ETag` in `Access-Control-Expose-Headers`. This is safe only because no
  route is authenticated by an ambient credential, and a server MUST keep
  it so: no cookies, and no client certificate on a request with
  `Origin` (§6.3; rationale §9).
- **Secrets.** Transport tokens and challenges MUST come from a CSPRNG,
  SHOULD be stored only as a hash, and MUST NOT be logged, as for session
  tokens (`hotline-ng.md` §9).
- **Rate limits.** A server SHOULD limit the `challenge` and `auth`
  endpoints per source address, as it limits login attempts. *Not
  implemented in hxd-ng.*
- **Bounded state.** Every table an unauthenticated caller can grow —
  outstanding challenges, unredeemed tokens, the key-on-file cache of
  §6.3 — MUST be bounded, whether or not rate limits exist (rationale §9).
  *hxd-ng* sheds at the bound: `503` for challenges, eviction for the
  cache.

## 13. Open questions

- **Other methods.** Which of §6.5's methods, if any, to define fully.
  Rationale §10 has the positions: OIDC first if asked.
- **HOPE inside the tunnel.** Refusing it is simplest; allowing it is
  harmless but doubles encryption. Should the server advertise it as
  unsupported on the tunnel path so clients don't try?
- **User Flags bit 4 on 1.8/1.9.** §8's cleartext marker takes value 16
  in field 112 on the strength of "classic clients ignore unknown bits".
  If 1.8/1.9 already means "automatic response" by that value, the marker
  has to move to a bit nothing has claimed. It needs testing against a
  real client before any server turns marking on by default.
