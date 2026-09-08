# Hotline-ng identity — HTTP-layer authentication and portable identity

Status: draft, for discussion. Implemented in hxd-ng: the identity
objects (§3, `crates/hl-identity`, with test vectors in
`identity-test-vectors.json`), discovery and the endpoints of §4–§8, both
WebSocket paths of §6, account association including `trtp_login`, and
the `hlid` tool. Not yet: revocation, reserved-name enforcement, the
mTLS binding beyond the header contract, and everything in the registrar
and federation specs. Supersedes the earlier `Capabilities-Identity`
draft, which put authentication inside the legacy transaction protocol;
this version keeps TRTP unchanged and does authentication where the ng
transport already lives, in HTTP.

Revision note: the relay and tunnel sections and the account rules were
reworked after review to separate *transport identity* (who holds the
socket, which any relay or tunnel can establish) from *account
association* (which only a server that terminates the socket can do), and
to add TRTP-over-WebSocket as a transport so legacy clients get identity
through a plain tunnel.

Companion documents: the identity threat model (what this protects and from
whom), `hotline-ng.md` (the WebSocket protocol this extends), and the
registrar and federation specs (handles, key storage, revocation, presence,
vouches — referenced but not defined here).

---

## 1. Summary

A user's identity is an Ed25519 keypair. Each device holds its own keypair,
certified by the identity key. A signed, versioned *user card* carries the
public profile and any registrar attestations.

None of that depends on a transport. What this document adds is two
layers with different owners:

**Transport identity** — who holds this socket. A small set of HTTP
endpoints, served by the same listener that accepts WebSocket upgrades,
through which a client proves it holds a device key and registers its card
and certificate. Two ways to do the proof — a challenge signed by the
device key, or a TLS client certificate presented to the reverse proxy —
end in the same state: *this connection belongs to device key D of
identity I*. Anything that terminates the HTTP handshake can establish
this, including a relay that only forwards the bytes it carries. It is
enough, on its own, for admission (allow lists, bans by fingerprint) and
rate limits — decisions a transport can make about a connection.

Roster marking and presence are *not* in that set, though they are
downstream of it: they are things the application protocol says about a
session, so only a server that terminates that protocol can do them. A
relay that forwards opaque TRTP establishes the transport identity and
then has no way to tell the legacy server behind it (§11.2), which is why
a relayed session shows no identity to other users while a tunnelled one
(§6.3, where the identity-aware server *is* the endpoint) does.

**Account association** — which local account, if any, this identity is.
Only a server that also implements the application protocol on the socket
can do this, because only it has the transport identity and the account
table in one place. hxd-ng does, for both application protocols it
speaks over WebSocket: the ng JSON protocol and, new in this revision,
TRTP itself in binary frames.

The legacy wire (TRTP on :5500) is not changed. A legacy client reaches a
linked account with the account's name and password, or through a local
tunnel that authenticates upstream with the user's device key and
forwards TRTP bytes over WebSocket — at which point the server knows who
it is and treats it like any other identity session.

---

## 2. Why HTTP and not the chat protocol

Authentication is a transport concern. The ng transport is a WebSocket,
which begins as an HTTP request, and hxd-ng already assumes a TLS-terminating
reverse proxy in front of it. Doing authentication in that HTTP exchange
means:

- the WebSocket session arrives already bound to a key, and the JSON protocol
  never carries credentials for identity users;
- a tunnel in front of a *legacy client* can authenticate upstream with the
  user's key using plain HTTP client code and then forward bytes, without
  knowing anything about TRTP;
- a relay in front of a *legacy server* (hxd 0.x, Mobius, HLServer) can
  establish who is on each socket and gatekeep accordingly, without that
  server changing and without the relay reading the tunnelled protocol;
- mTLS becomes a first-class option rather than a special case, since it is
  an HTTP-layer mechanism already.

The cost is that hxd-ng grows a small HTTP router on the ng listener, which
`hotline-ng.md` deferred "until media/history/push need one." Identity needs
one. It is a handful of routes.

---

## 3. Identity objects

These are unchanged from the earlier draft and are defined here in full so
this document stands alone.

### 3.1 Encoding and signatures

Signed objects are CBOR (RFC 8949) in deterministic encoding (§4.2.1). A
signature covers the object's encoded bytes with the `sig` entry removed,
prefixed by a domain string:

```
sig = Ed25519.sign(key, domain || 0x00 || cbor_bytes_without_sig)
```

Verifiers check over the bytes as received and reject non-deterministic
encodings. In JSON contexts an object is carried as base64url (no padding)
of its CBOR bytes. Every object has an integer `v`; this document defines
`v = 1`. Unknown keys are ignored on read and covered by the signature; a
`v` the reader does not know is rejected — higher because it may mean
something this reader would get wrong, and `0` because it is not a
version this or any document defines.

Timestamps are Unix seconds, UTC. `bstr(n)` is a byte string of exactly `n`
bytes.

### 3.2 Fingerprint

`SHA-256(pubkey)`, 32 bytes. Displayed as lowercase Crockford base32, no
padding; may be shortened to 8 characters in UI. Servers store and compare
full fingerprints.

### 3.3 Device certificate

Domain `hl-identity/device-cert/v1`, signed by the identity key. At most
4 KiB encoded — a certificate is three keys, two timestamps and a short
label, and a server caches the bytes of every one it admits (§13), so the
limit is what bounds that cache.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | Identity public key |
| `device` | bstr(32) | yes | Device Ed25519 public key |
| `device_enc` | bstr(32) | yes | Device X25519 public key (E2E messaging) |
| `issued` | uint | yes | |
| `expires` | uint | yes | Recommended 90 days; renew at one-third remaining |
| `caps` | uint | no | Absent = all. Bit 0 login, 1 message, 2 vouch, 3 manage |
| `name` | tstr | no | Human label, device lists only. 1–64 characters, no leading or trailing space, and no control or invisible characters (§3.5) — it is rendered next to a fingerprint. Absent is fine; present and blank is not |
| `sig` | bstr(64) | yes | |

Web-client certificates should omit the vouch and manage bits.

### 3.4 User card

Domain `hl-identity/card/v1`, signed by the identity key. At most 16 KiB
encoded.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `updated` | uint | yes | Servers never replace a cached card with an older one |
| `name` | tstr | yes | Display name, 1–32 characters, at least one of them not a space, and none of them leading or trailing space — `"   "` is a blank row in a user list and `"admin "` is a spoof of `admin`. No control or invisible characters (§3.5); signers SHOULD normalise to NFC, but verifiers do not — a verifier re-serves the exact bytes it was given, so it cannot normalise them |
| `icon` | uint | no | Legacy icon id |
| `profile` | tstr | no | ≤ 2048 bytes |
| `attestations` | array | no | Attestation objects, each fully signed; at most 8. The size limit alone allows dozens, and each one an unauthenticated caller embeds is a signature the server verifies |
| `vouches` | array | no | Federation spec; ignored by servers that don't implement it |
| `links` | array of tstr | no | URLs to display; servers never fetch them |
| `successor` | bstr(32) | no | SHA-256 of a pre-committed successor identity key (threat model, "stolen identity key"). Once set, immutable: a later card for the same identity that changes or omits it is refused (`bad_card`) by any server that cached the earlier one, and rotation is accepted only to the committed key. A server persists the commitment for identities with standing on it — see §13. |
| `sig` | bstr(64) | yes | |

### 3.5 Attestation

Domain `hl-identity/attestation/v1`, signed by a registrar key.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `registrar` | tstr | yes | Registrar host, lowercase. Hostname syntax (ASCII letters, digits, `-`, `.`), 1–253 bytes — it is rendered as part of the handle, and anything else could read downstream as a different host |
| `registrar_key` | bstr(32) | yes | Hint only; verifiers confirm against the registrar's published key |
| `handle` | tstr | yes | Local part, 1–64 bytes; full handle is `handle@registrar`. No `@`, no whitespace, and no control or invisible characters — a handle is rendered next to account logins and display names, so a zero-width space or a bidi override in one is a spoof of another |
| `registered` | uint | yes | First registration; preserved across reissue; the value used for age. Non-zero and no later than `issued` — a registrar writing `0` would hand its users infinite standing wherever `min_attestation_age` is set |
| `issued` | uint | yes | |
| `expires` | uint | yes | Recommended one year; strictly after `issued` |
| `level` | uint | no | Registrar-declared signup strictness, 0–3 |
| `sig` | bstr(64) | yes | |

### 3.6 Login proof

Domain `hl-identity/login/v1`, signed by the device key. Used only by the
challenge binding (§5.2).

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `challenge` | bstr(32) | yes | Echoed from the server |
| `server_key` | bstr(32) | yes | Echoed from the server; binds the proof to this server |
| `device` | bstr(32) | yes | |
| `time` | uint | yes | Rejected outside the server's clock-skew tolerance |
| `sig` | bstr(64) | yes | |

### 3.7 Server key

A server implementing this document has an Ed25519 keypair generated on
first start. It is published in discovery (§4), bound into login proofs, and
used by the federation spec to sign ban lists and vouches. It is not a TLS
key.

---

## 4. Discovery

`GET /.well-known/hotline` on the ng listener, served without
authentication, with `Content-Type: application/json`:

```jsonc
{
  "v": 1,
  "name": "My Server",
  "server_key": "…base64url 32 bytes…",
  "ng": { "ws": "/ng", "trtp": "/trtp" },  // WebSocket paths: JSON protocol, TRTP tunnel
  "identity": {
    "enabled": true,
    "bindings": [ "challenge", "mtls" ],    // which of §5 this server accepts
    "new_accounts": "guest",                // deny | guest | create
    "association": "server",                // or "none" on a relay (§11.2)
    "min_attestation_age": 0,
    "trusted_registrars": [],               // hosts whose attestations are accepted;
                                            // empty accepts none — every identity is unattested
    "endpoints": {
      "challenge": "/identity/challenge",
      "auth":      "/identity/auth",
      "card":      "/identity/card",
      "link":      "/identity/link",
      "unlink":    "/identity/unlink"
    }
  },
  "registrar": null                         // or the registrar spec's block
}
```

The same document is where a registrar advertises its own endpoints and key,
so one discovery format serves servers, registrars, relays and tunnels.
Clients cache it for the connection's lifetime; relays cache it per
upstream.

---

## 5. Authentication

### 5.1 Model

Authentication produces a short-lived *transport token*: an opaque bearer
token, 32 bytes base64url, valid for 60 seconds, bound server-side to a
device key, its identity, and the verified card and certificate. The client
presents it when opening a WebSocket (§6), and the socket is thereafter
known to belong to that device. Tokens are single-use.

The token is deliberately not a session token. A session is an
application-layer object — it has a uid and a roster row — and the same
transport token authenticates a socket whether the application protocol
on it turns out to be ng JSON or tunnelled TRTP. Nothing application-level
exists until the application protocol's own login runs.

Two bindings produce a token. Servers advertise which they accept. The
server ends in the same state either way and nothing above the transport
can tell them apart.

### 5.2 Challenge binding

Works everywhere, including browsers.

**Step 1.** `POST /identity/challenge` with an empty body. Response:

```jsonc
{ "challenge": "…base64url 32 bytes…", "server_key": "…", "expires_in": 60 }
```

The challenge is stored server-side for 60 seconds and consumed on use.
Servers rate-limit this endpoint per source address as they do login
attempts; it is free to call and costs the server a random draw.

**Step 2.** `POST /identity/auth`:

```jsonc
{
  "card":        "…base64url CBOR…",
  "device_cert": "…base64url CBOR…",
  "proof":       "…base64url CBOR…",
  "downstream":  "local"                 // optional: local | cleartext
}
```

`downstream` is what the client declares about the hop *behind* it. A
client that is the endpoint, or a tunnel forwarding only over loopback,
says `local` (the default). A tunnel forwarding over a cleartext network
hop (§11.1) MUST say `cleartext`; the server then marks the session
`cleartext` on the roster (§10) so other users get the PM warning, TLS on
the WebSocket notwithstanding. The server has no way to verify the claim
and takes the conservative direction at face value: a client may make a
session look less safe than it is, never more.

The server verifies in this order and fails on the first error:

1. proof signature with `device`; `challenge` known and unexpired;
   `server_key` matches; `time` within tolerance;
2. `device_cert` signature with its `identity`; `device` matches the
   proof; within validity; login capability set;
3. `card` signature; `identity` matches the certificate;
4. neither key revoked (cached revocation list; behaviour on a stale cache
   is a setting);
5. attestations verified against trusted registrars, expired or untrusted
   ones discarded, age computed from the oldest surviving `registered`;
6. allow list, minimum attestation age, unattested policy.

Success (200):

```jsonc
{
  "token": "…",
  "expires_in": 60,
  "fingerprint": "…",
  "handle": "alice@hl.example",            // null if no accepted attestation
  "age": 31536000,                          // seconds; 0 if unattested
  "outcome": "linked",                      // see below
  "account": "alice"                        // the login, when one is associated
}
```

`outcome` is one of:

| | |
|---|---|
| `linked` | an account already associates this identity, and login lands on it |
| `created` | `new_accounts = create` made one during this call; `account` names it |
| `guest` | no association; the session will be a guest |
| `unattested_guest` | as `guest`, and the reason is that no attestation was accepted |
| `classic_pending_link` | `login`/`password` named an account that could not be linked (someone else's identity, or self-linking off). The session will be a guest and an operator has to resolve it |

The request may also carry `"create": false`, which suppresses account
creation for this call on a `new_accounts = create` server. A client that
means to link an *existing* classic account should send it: otherwise the
first auth creates a new account, and `/identity/link` afterwards can only
answer `already_linked`. Sending credentials implies it.

Failure with `{ "error": code, "text": "…" }`:

| code | status | |
|---|---|---|
| `bad_card`, `bad_cert`, `bad_proof`, `card_too_large`, `unknown_challenge` | 401 | prove it again |
| `login_failed` | 401 | the `login`/`password` of §5.4 didn't verify |
| `denied`, `revoked`, `no_manage` | 403 | policy, or the device certificate lacks `manage` |
| `already_linked`, `would_orphan`, `not_linked` | 409 | conflicts with the account's state (§8.2, §8.4) |
| `server_error` | 500 | ours, logged, not explained |

`outcome` tells the client what account association will happen when an
application login runs on a socket carrying this token *and presents no
credentials of its own* (§8), so a guest downgrade can be shown as
information rather than discovered as a surprise.

That qualifier matters because the token is path-agnostic: the same token
admits an ng `login` and a tunnelled TRTP Login (107), and only the ng path
is fully decided at auth time. A tunnelled classic login under
`trtp_login = verify` (§8.3) carries a name and password that
`/identity/auth` never saw, so it can land on — and link — an account this
response could not have named. `outcome` is therefore a prediction, not a
commitment, and a client MUST take the association the application login
actually reports (the ng `self` event, or the classic Login reply) as
authoritative. A client that intends to send classic credentials later
should treat `guest` as "unless my credentials say otherwise" rather than
displaying it as settled.

### 5.3 mTLS binding

For clients that can present a TLS client certificate: native apps, tunnels
and relays. Not browsers.

The client certificate is a self-signed X.509 certificate whose
SubjectPublicKeyInfo is the device's Ed25519 public key (RFC 8410). Nothing
else in the certificate is examined; validity dates, subject and extensions
are ignored, since the device certificate (§3.3) is the authority on all of
that.

Ignoring the rest is not the same as not parsing it. The key MUST be taken
from the SubjectPublicKeyInfo by position — walk `Certificate` →
`TBSCertificate`, skip `version`, `serialNumber`, `signature`, `issuer`,
`validity` and `subject`, and read the seventh field. Everything ahead of
the SPKI is chosen by whoever requested the certificate (`serialNumber` is
an arbitrary INTEGER; a `Name` attribute value is `ANY`), so an
implementation that *searches* the DER for RFC 8410's algorithm identifier
will find whatever bytes the subject planted there. A certificate whose own
SPKI is the attacker's key — which is what the proxy's handshake validates
— carrying a victim's device key inside its subject would then be read as
the victim's device.

hxd-ng does not terminate TLS. The reverse proxy requests (but must not
require) a client certificate and forwards it on the upstream request as
`X-Hotline-Client-Cert` (base64 DER). The server honours that header only
from addresses listed in `[ng] trusted_proxies`; from anywhere else it is
stripped.

Trusting the proxy's address is necessary but not sufficient. The proxy
MUST set `X-Hotline-Client-Cert` from the certificate that took part in
*its own* TLS handshake, and MUST drop any copy of the header the client
sent — otherwise a client can send the header through the proxy carrying
any device's public certificate and impersonate that device. In Caddy,
`header_up X-Hotline-Client-Cert {http.request.tls.client.certificate_der_base64}`
does both: it replaces any inbound value, and sets nothing when there was
no client certificate. An empty value means the client offered no
certificate, which is "none" and not "a broken one" — some proxies send
the header unconditionally.

A trusted proxy is also believed about *who* it is speaking for. The
address the server keys bans and per-address session limits on is the
**rightmost element that is not itself in `trusted_proxies`**, read
across every line of one header — `X-Forwarded-For` or RFC 7239's
`Forwarded`, whichever `[ng] forwarded_header` says this proxy writes.
Without any of this, every client behind the proxy shares one address, so
banning one of them bans the deployment.

The rightmost rule is not a stylistic choice. The stock directives
*append*: nginx's `$proxy_add_x_forwarded_for` and HAProxy's `option
forwardfor` add the peer they see to whatever the client already sent, so
the left of the list is client-supplied and only its right end was
written by the proxy. Reading the first element would let any client pick
its own address — a fresh one per connection to shed a ban or a
per-address limit, or someone else's to inherit their ban. Walking from
the right and stopping at the first element outside `trusted_proxies` is
correct under an appending proxy *and* under one that replaces the header
outright; an element the server can't parse ends the walk and leaves the
socket's peer in place.

**`trusted_proxies` must list proxies and nothing else.** The walk skips
over every element it finds in that list, so a range that also contains
client addresses — a `10.0.0.0/8` on a network where clients live too —
makes it skip the proxy's own element and take the client's, which is the
bug this rule exists to prevent. List the addresses the proxy speaks
from, not the network it sits on.

`forwarded_header` names one header rather than trying both because a
proxy passes through what it doesn't know about: nginx that sets
`X-Forwarded-For` forwards a client-supplied `Forwarded:` line untouched,
so a server that read both would read whichever one the *client* filled
in. The default is `x-forwarded-for`; set `forwarded` only if the proxy
is configured to write RFC 7239, and `none` to key everything on the
proxy's own address. Header *lines* are concatenated in order for the
walk, so a client-supplied line ahead of the proxy's own is to the left
of it and never wins.

**Stock nginx cannot do this.** `$ssl_client_escaped_cert` is
URL-encoded PEM and `$ssl_client_raw_cert` is PEM with real newlines; a
header carries neither, and nginx has no base64-DER variable and no
string functions to make one. A server that can't decode the header
answers 400 rather than falling through to an unauthenticated request,
so a misconfiguration is loud — but it is still a misconfiguration, and
the fall-through version of this failure is what "mTLS silently isn't
working" used to mean.

With njs, one function does it:

```nginx
# hotline.js
function client_cert_der(r) {
    var pem = r.variables.ssl_client_raw_cert;
    if (!pem) return "";
    return pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
}
export default { client_cert_der };
```

```nginx
js_import hotline from hotline.js;
js_set $hotline_client_cert hotline.client_cert_der;
proxy_set_header X-Hotline-Client-Cert $hotline_client_cert;   # empty when absent
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # who it speaks for
```

The `proxy_set_header` is what drops any copy the client sent, and an
empty value removes the header — both halves of the contract above. Lua
works the same way. Without njs or Lua, use Caddy for the mTLS binding,
or the challenge binding of §5.2, which needs no proxy cooperation at
all. An operator who lists a proxy in `trusted_proxies` is asserting
that it is configured this way; the server cannot check it. Operators who
terminate TLS in the server itself in some future build get the same
header semantics from the in-process listener, with the same contract
satisfied by construction.

With a client certificate on the connection, `POST /identity/auth` omits
`proof`:

```jsonc
{ "card": "…", "device_cert": "…" }
```

The server checks that the certificate's public key equals `device_cert.device`
and continues from step 2 above. Response and failure codes are the same.

Once a device has a card and certificate on file, a WebSocket upgrade that
carries a client certificate for that device key is authenticated without a
token (§6), for as long as the stored device certificate is valid. This is
the "the connection is the credential" path mTLS users expect; the
`/identity/auth` call is needed once per device, and again when the card or
certificate changes.

### 5.4 Registering with a password

Either binding may add `"login"` and `"password"` to `/identity/auth` to
verify an existing classic account and, if permitted, link it in the same
step. See §8.2. For ng JSON sessions this is the only place a password
travels; it must never appear in a JSON frame for identity users. A
tunnelled TRTP session carries its classic login inside the tunnel as it
always has, encrypted by the WebSocket's TLS.

---

## 6. Opening a WebSocket

Two WebSocket paths are advertised in discovery. Both are authenticated
the same way; they differ only in what flows after the upgrade.

### 6.1 Presenting the transport token

An upgrade request is authenticated by one of, in order of preference:

- `Authorization: Bearer <token>` — any client that can set request
  headers (native apps, tunnels, relays);
- `?token=<token>` in the upgrade URL — browsers, whose `WebSocket` API
  takes a URL and a protocol list and nothing else. The token is
  single-use and expires in 60 seconds, which is what makes a value in
  the URL tolerable at all.

  A deployment that serves this form **MUST** keep the query string out
  of its logs on these paths — access logs, error logs, and any redirect
  or upgrade-failure log — because common reverse-proxy defaults record
  it, and an upgrade that fails or is abandoned leaves the token
  unredeemed and live for its remaining seconds. "Single-use" bounds the
  damage only once someone has used it;
- a client certificate on the connection for a device key on file,
  forwarded under the §5.3 proxy contract, which needs no token at all.

Cookies are not used: they would make every cross-site page a potential
initiator of an authenticated socket.

An upgrade with an invalid or expired token is refused with HTTP 401. It
is not downgraded to an unauthenticated socket, so a client cannot silently
end up as a guest because a token expired in flight.

An upgrade with none of these is an unauthenticated socket and proceeds
exactly as it does today: the ng JSON handshake of `hotline-ng.md` §6, or
a classic TRTP handshake in the tunnel. Nothing changes for clients that
don't use identity.

### 6.2 The ng JSON protocol (`ng.ws`)

On an authenticated socket the first frame is still `login`, but its
`login` and `password` params are ignored (and should be omitted). The
server associates an account per §8 and replies as usual, with three
additions to the `ok` object:

```jsonc
"self": { "uid": 3, "nick": "Alice", "icon": 128, "admin": false,
          "status": "active",
          "identity": { "fingerprint": "…", "handle": "alice@hl.example",
                        "age": 31536000, "outcome": "linked" } },
"caps": [ "identity", … ]
```

Each `user` object in the roster and in `user_joined` / `user_changed`
gains an optional `identity` sub-object with `fingerprint` and `handle`
(never `age` or `outcome`, which are the server's business), and a
required `transport` field: `"encrypted"` or `"cleartext"` (§10). Clients
that predate this ignore both.

`resume` is unaffected: the session token already proves continuity, and
the identity binding is a property of the session once the session
exists, not of the connection.

### 6.3 TRTP over WebSocket (`ng.trtp`)

The socket carries the classic protocol unchanged: binary frames, whose
payloads concatenated in order are exactly the byte stream a TCP
connection to the legacy port would carry, in both directions. Frame
boundaries carry no meaning; a client may send one transaction per frame
or split however it likes, and the server may do the same. Text frames on
this path are a protocol error and close the socket.

Inside the tunnel the client performs the ordinary TRTP handshake and
Login (107) with whatever classic credentials it has. What the server
does with those, given that it also knows the transport identity, is §8.3.
The server treats the session as encrypted for §10, since the WebSocket
is TLS.

This path needs no TRTP-aware code in the tunnel or in any relay. In
hxd-ng it is the existing legacy frontend fed from a WebSocket instead of
a TCP socket, plus the identity annotation on the session. HOPE transport
encryption is unnecessary inside the tunnel and a server may refuse to
negotiate it there.

**Keep-alive is the server's job here, as on the JSON path.** A classic
session says nothing for as long as its user is only watching, and the
protocol inside has no idle traffic of its own — so the server sends a
WebSocket ping on a quiet socket (hxd-ng: every 30 seconds), which is
what notices a peer that has gone away and what keeps a NAT mapping
alive. A tunnel answers with a pong, as any WebSocket library does for
it, and needs no code for this. A socket that has sent nothing at all for
three ping periods is dropped: a ping with no deadline behind it asks a
question and accepts no answer.

---

## 7. Cards

`GET /identity/card/<fingerprint>` — public, no authentication. Returns the
server's cached card for that identity as `application/cbor`, exactly the
bytes received, so the signature verifies; 404 if none. Cacheable: the
server sets `ETag` to the card's `updated` value in entity-tag syntax —
the decimal in double quotes, `ETag: "1757116860"` — and answers
`If-None-Match` with 304. `updated` is the card's own version, so it is a
strong validator. Relays, tunnels, other servers and registrars all use
this.

`PUT /identity/card` — authenticated by transport token or client
certificate; the
device certificate must carry the manage bit. Body is the new card as
`application/cbor`. Verified as in §5.2 step 3; the `updated` monotonicity
rule applies, and a card that changes a committed `successor` is refused
with `bad_card` (§3.4).

On acceptance a server should emit `user_changed` for that identity's
sessions and, on the legacy wire, Notify Change User (301) if the name or
icon changed. hxd-ng does not yet: sessions carry no identity → uid index,
so it answers `{"updated": true}` and the roster catches up at the next
login. Clients should not depend on the notification.

Cards are per identity, not per session or per wire. A card set from a
web client is the card the server shows for the same identity's tunnelled
legacy session.

---

## 8. Account association

Everything in this section is for a server that terminates the socket and
implements the application protocol — hxd-ng, or another server that
adopts this document natively. A relay or tunnel does none of it (§11).

An account may carry one identity fingerprint; an identity may be linked
to one account per server. The link is what gives an identity user
permissions, a reserved name, and a place in the operator's existing
account tools.

### 8.1 Association at login

When an application login runs on a socket with a transport identity and
names no classic account (an ng `login` with no `login` param; a TRTP
Login (107) as guest):

- if an account links this fingerprint, the session is that account, with
  its access bitmap and everything else; if the operator has set
  `identity_login = false` on the account, the login fails with `denied`;
- otherwise the server's `new_accounts` policy applies: `deny` refuses the
  login; `guest` gives a guest session that nonetheless knows its identity
  (for reserved-name enforcement, marking, and linking later); `create`
  makes an account named from the handle's local part (numeric suffix on
  collision) or the short fingerprint, with the server's default identity
  access, no password, and the link set. The login name an account is
  created under is never one the server gives its own meaning to, `guest`
  in particular.

`deny` is decided on every path that admits an identity with no linked
account — the unattested one, the `classic_pending_link` one of §8.2, and
the re-admission of a device already on file (§5.3) — and again when the
application login re-reads the link (§6.2), so a token minted while the
account was linked does not outlive it for the rest of its minute.
Removing a link locks that device out at its next connection rather than
at its certificate's expiry.

`/identity/auth` reports which of these will happen as `outcome`.

### 8.2 Linking an existing classic account

**Writing a link is account management, and every path that writes one
requires the device certificate's `manage` capability** — at auth, after
auth, and inside a tunnel (§8.3). A certificate without it can still log
in and use the server; it cannot bind an account to the key. Note what
this means for a tunnel that will self-link: §11.1's advice to carry only
the login and message bits is right for a tunnel used with an
already-linked account, and a tunnel that is expected to make the link
needs `manage` as well.

Three ways, all requiring the account to allow self-linking, to have a
password, and to have no link to a different identity:

- **At auth.** `/identity/auth` includes `login` and `password`. The server
  verifies the password as for a normal login. If the identity also
  verifies and the account is linkable, the link is made and `outcome` is
  `linked`. If not linkable, the token is still issued with `outcome`
  `classic_pending_link` and the session that redeems it is an ordinary
  identity-tagged guest: the credentials verified, so the client is told
  the difference between "wrong password" and "that account will not take
  this identity", but nothing about the account is conferred and the
  operator is who resolves the link. Under `new_accounts = deny` there is
  no guest to fall back to, so the auth is refused outright.
- **Inside a tunnel.** A classic Login (107) on a tunnelled socket that
  names a self-linkable account and gives its password links it, exactly
  as "at auth" does (§8.3).
- **After auth.** `POST /identity/link` with `{ "login", "password" }`.
  On success a guest session belonging to this
  identity is upgraded in place: the server sends `user_changed` for it
  with the new nick and admin flag and a `self` refresh event carrying the
  new access. Servers that don't want to support in-place upgrade may
  reply `{ "reconnect": true }` after recording the link; the client
  reconnects and lands on the account.

Linking an identity to a second account on the same server is refused
with `already_linked`.

**A password-less account is never linked this way.** Every path above
verifies the account's password first, and an account with no password
verifies for anybody — so self-linking one would hand it to whoever
asked, and §8.3's rule that a linked password-less account refuses the
password path would then lock everyone else out. The operator links such
an account by editing its file, which is also where the account came
from.

### 8.3 Tunnelled TRTP sessions

A legacy client inside a tunnel sends a classic Login (107) with a name
and password, or as guest, and expects the reply a 1.9 server would give.
The server has a transport identity for the socket as well. How it
reconciles the two is the `[identity] trtp_login` setting:

- `verify` (default) — classic credentials are checked exactly as on the
  TCP port. If they name an account, that account must be the one linked
  to the identity, or have no link and be self-linkable *and the socket's
  certificate must carry `manage`* (in which case the login links it, as
  §8.2 "at auth" does); naming someone else's account fails the login, and
  so does naming a linkable account from a certificate that may not write
  links. A guest login associates per §8.1, and does so even on a server
  with no guest account at all: naming no account is a question about the
  identity, and a linked account that may log in answers it. The identity
  adds marking, reserved-name enforcement and admission; it never
  substitutes for a password.
- `trust` — if the identity has a linked account **whose
  `identity_login` is on**, that account is used and the classic
  credentials are ignored. This lets a linked account be password-less
  and lets a user type anything into a 1.5 login box. Operators who
  enable it are trusting their allow list and registrar policy in place
  of passwords for those accounts.

  `identity_login = false` is not overridden by `trust`. The two settings
  answer different questions — one is the operator's policy for the
  server, the other is the account's own — and a server-wide switch that
  silently cancelled a per-account refusal would make the per-account
  setting unreliable in exactly the deployments that set it. A session
  reaching such an account still needs its password, and a guest login
  on that socket fails with `denied` per §8.1.

  "Still needs its password" is a TRTP-path statement. On the ng JSON
  path an identity socket ignores credentials entirely (§6.2) — there is
  nowhere to put a password that the server will read — so an account
  with `identity_login = false` is reachable only from a socket with no
  transport identity. That is the intended shape (the account has said it
  does not want identity login), but a client has to know to open a plain
  socket for it.

  **A password-less account with `identity_login = false` is reachable by
  nobody**, on either wire: no password means every password login is
  refused (the rule above), and the flag refuses the key that was the
  other way in. §8.4's `would_orphan` stops the *server* writing that
  state; nothing stops an operator typing it, so the file backend names
  such accounts in a warning at startup, where an operator is looking.
  Set a password, or allow identity login.

  A password-less account that is *not* linked has a narrower version of
  the same shape: the plain TCP port admits it (an empty password matches
  an empty password), and a tunnelled or ng login cannot, because linking
  is what would make the key its credential and §8.2 never self-links a
  password-less account. Such an account stays a plain-port account until
  an operator writes the link into its file.

Either way the session is identity-aware from the server's point of view
and indistinguishable from a native identity session in the roster.

### 8.4 Unlinking

`POST /identity/unlink`, authenticated with the manage bit, or by the
operator through account administration. Refused with `would_orphan` if
the account has no password, until one is set.

**Stored mail belongs to the identity, not to the account it was linked
to.** A private-message inbox keyed by fingerprint
(`private-messages.md` §4) addresses the person, and after an unlink the
account is addressed by its bare login again — so everything stored
while the link stood stays with the identity and follows it to whatever
it links next. That is the deliberate choice: the alternative, mail
following the account, would hand one person's correspondence to whoever
links to that account afterwards. It is also invisible from the
account's side, which is why the reply says how much:

```jsonc
{ "unlinked": "alice", "mail_stays_with_identity": 42 }
```

Re-linking the same identity to the same account brings it all back.

### 8.5 Rotation

When a rotation record from the registrar spec is verified — either
carried in the card's attestations as a successor attestation, or picked
up during revocation refresh — a server holding the predecessor
fingerprint moves the link to the successor, logs both, and keeps bans and
reserved names with the account.

### 8.6 Legacy clients on the TCP port

A legacy client on the plain TCP port logs into a linked account with the
account's name and password exactly as before, gets the same permissions
and reserved name, and has no transport identity. Its card is whatever the
identity last set. Nothing in TRTP changes.

---

## 9. Reserved names

A reserved name is a display name only one account may wear on a server.
It is a property of the account: the operator sets `reserve_name = true` and
the reserved string is the account's login name. This is unchanged from
current practice; the identity layer only adds enforcement for sessions the
server can recognise.

When any session tries to set a display name reserved by another account,
the server refuses it. *(hxd-ng reads and stores `reserve_name`; the
enforcement described in the rest of this section is not wired to the
name-setting paths yet.)* On ng, `nick` replies `error: name_reserved`. On the
legacy wire, where Set Client User Info (304) has no reply, the server
substitutes a discriminated name (`alice~7f3a` for a tunnelled session
with an identity, `alice (2)` for a plain classic one) and announces the
correction in Notify Change User (301). Legacy behaviour for classic
sessions is therefore "the name gets a suffix," which some servers already
do.

If a classic account and an identity-created account collide on a reserved
string, the identity-linked one wins and the other's reservation is
suspended and logged for the operator.

---

## 10. Cleartext sessions and the legacy wire

Nothing in this document adds fields or transactions to TRTP. The legacy
wire is affected in two ways only, both optional and both about what a
classic session *sees*, not about authentication:

- **Transport marking.** So that ng users can be warned before PMing a
  session whose link is readable in transit, every roster entry on ng
  carries `transport`. On the legacy wire, servers *may* set bit 4 (value
  16) of User Flags (112) for cleartext sessions; 1.2/1.5 clients ignore
  unknown flag bits, and clients that know it render a marker. This is the
  one TRTP-visible change and a server may omit it.

  **The bit is not settled.** Hotline 1.8/1.9 may already allocate value
  16 in field 112 as "automatic response", in which case setting it makes
  every cleartext session look auto-responding to those clients, and this
  document has to move the marker to a bit nothing has claimed. Nothing
  in the tree the reference implementation was written from confirms
  either reading, so hxd-ng ships the marking **off by default**
  (`[server] mark_cleartext`) until it has been checked against a real
  1.8.5 or 1.9 client. An implementation that turns it on by default is
  betting on the reading that has not been verified, which the "never
  break old clients" rule does not allow.
- **Cleartext policy.** A three-position setting: `off` (legacy port
  refuses sessions that don't negotiate HOPE transport encryption, or is
  behind a TLS wrapper), `restricted` (cleartext sessions have their access
  ANDed with an operator mask whose recommended default allows public chat
  and news reading only), `on` (legacy behaviour, with a warning in
  operator tooling).

A tunnelled TRTP session (§6.3) is `encrypted` **when the tunnel's own
local hop is**. The hop the server can see — tunnel to server — is TLS,
and the server never sees those bytes in the clear. The other hop, the
classic client to the tunnel, is cleartext by construction (§11.1): the
tunnel exists because the client cannot speak TLS. On loopback that hop
crosses nothing, and the session is `encrypted`. Off loopback — which
§11.1 permits, deliberately and opt-in — it crosses a network, and the
session is `cleartext`.

The server cannot observe which, so the tunnel declares it: `downstream`
at `/identity/auth` (§5.2), `cleartext` when the tunnel listens anywhere
but loopback. A client may declare itself less safe than it looks and
never more, so a tunnel that lies can only cost its own user a warning
they didn't need. `hlid tunnel` sets it from its own `--listen`.

With that hop on loopback this is, rather than HOPE transport
encryption, the recommended way for a legacy client to get an encrypted
session — it also gets an identity.

An ng client must warn before sending a private message to a `cleartext`
session.

---

## 11. Tunnels and relays

Neither needs to *parse* the protocol it carries. That is the point:
everything in this section is possible with an HTTP client library, a
WebSocket library, and `hl-identity`, and nothing here requires TRTP
knowledge.

It is not a confidentiality claim. Both processes handle the payload
bytes in the clear and can read or alter them at will; the threat model
says so of their operators explicitly. What they are spared is
understanding those bytes, not seeing them.

### 11.1 Tunnel: legacy client → identity-aware server

Runs on the user's machine (or somewhere they trust), holds one device
key, listens on a local TCP port for the classic client, and forwards
bytes over a TRTP-over-WebSocket connection (§6.3) to the server.

- It authenticates upstream with its own device key by either binding. Its
  device certificate should carry only the login and message bits, unless
  the user means to link an account through it: writing a link needs
  `manage` on every path (§8.2), the tunnelled classic login included, so
  a tunnel that will self-link needs that bit too and should lose it once
  the link is made. It is a device like any other and appears in the
  user's device list as one.
- It presents the identity's current card, cached from wherever the user
  last set it; it does not synthesise cards.
- It forwards bytes verbatim in both directions and does nothing else. In
  particular it does not touch the classic login: the server sees it
  inside the tunnel and applies §8.3.
- Its local hop is cleartext on loopback. It must not be configured to
  listen on a non-loopback address without the user opting in, since that
  would re-create exactly the exposure the tunnel exists to remove — and
  when the user does opt in, the tunnel MUST say `"downstream":
  "cleartext"` at `/identity/auth` (§5.2) so the session is marked and
  other users are warned before PMing it. A tunnel has no other way to
  tell the server, and the server has no other way to know.

This is stunnel with an identity. A relay (§11.2) can also act as one
downstream, and a native client can embed one.

### 11.2 Relay: identity-aware front for a legacy server

Runs in front of a server that speaks only TRTP (hxd 0.x, Mobius,
HLServer). Implements discovery, the identity endpoints and the WebSocket
paths, and forwards each socket's bytes to a TCP connection to the legacy
server. It has a transport identity for every socket and no account table.

- It holds its own server key and is, for identity purposes, the server:
  its allow list, ban list and registrar policy apply at the HTTP layer,
  and the federation spec treats its signatures as the operator's.
- It gatekeeps: refuses sockets whose identity is banned, unattested
  beyond policy, or not on an allow list, before any bytes reach the
  legacy server. This is where a relay earns its keep, and it needs no
  cooperation from the server behind it.
- It does not associate accounts. The classic login inside the tunnel is
  the legacy server's business; the relay never sees a password it needs
  to check and never holds one. `/identity/auth` on a relay accepts no
  `login`/`password`; `/identity/link` and `/identity/unlink` return 404;
  `outcome` is always `guest` in the sense of "the legacy server decides".
- It serves cards from its own cache and may annotate nothing on the
  legacy wire, since it doesn't speak it. Clients connecting through the
  relay see identity information only via the relay's own discovery and
  card endpoints. Discovery says so: `"identity": { "association":
  "none" }`, so clients don't expect reserved names or auto-login.
- It can offer the ng JSON path only if it implements the JSON protocol
  itself against TRTP downstream, which is a full client implementation
  and out of scope here; a relay that offers only `ng.trtp` is complete.

### 11.3 What the server guarantees them

Discovery is stable, cards are byte-exact, tokens and challenges are
single-use, the mTLS header contract is honoured only from trusted
proxies, and the TRTP-over-WebSocket path carries exactly the bytes the
TCP port would and pings a quiet socket (§6.3). A tunnel or relay that follows this section is
indistinguishable from a native client to the server and to other users,
except that a relay-fronted legacy server has no account association to
offer.

---

## 12. Settings

The table is what `hxd-ng` reads today; a row marked *(not implemented)*
is design, not configuration, and setting it is a startup error —
`[identity]` uses `deny_unknown_fields`.

| Setting | Default | Meaning |
|---|---|---|
| `[identity]` present | absent | The section's presence is the master switch. Absent, discovery reports `enabled: false` and the endpoints 404. It needs `[ng]`: without an ng listener there is nothing to serve the endpoints from, so `[identity]` without `[ng]` is a startup error rather than a section quietly ignored |
| `[identity] key` | `identity-server.key` | The server's Ed25519 seed, hex, mode 0600; generated on first run |
| `[identity] new_accounts` | `guest` | `deny`, `guest`, `create`. The default is `guest` rather than `deny` so that, with `unattested = guest`, an attested identity is never treated worse than an unattested one |
| `[identity.default_access]` | guest access | Access bits for accounts `create` writes, keyed exactly as an account file's `[access]` table. The guest fallback is convenient but wrong for anything guests may not have — the messaging extension's `AccessMessaging`, for one — so operators using `create` should set it explicitly |
| `[identity] max_new_accounts_per_hour` | `60` | Ceiling on accounts `create` may write per hour; `0` turns creation off while leaving the rest of `create` in place. Past the ceiling, identities are still admitted, as guests. `create` writes a file per never-seen key, and with `unattested = guest` any fresh key qualifies |
| `[identity] allow_list` | empty | Fingerprints or handles; non-empty means identity login is restricted to these |
| `[identity] min_attestation_age` | `0` | Seconds |
| `[identity] unattested` | `guest` | `deny`, `guest`, `allow` |
| `[identity.registrar_keys]` | empty | Registrar host → base64url public key. **Empty accepts no attestation at all**, so every identity is unattested; there is no "empty means any". Static until the registrar spec's discovery fetch exists |
| `[identity] clock_skew` | `300` | Seconds |
| `[identity] trtp` | `true` | Serve the TRTP-over-WebSocket path |
| `[identity] trtp_login` | `verify` | `verify` or `trust`; see §8.3 |
| `[identity] successors` | `identity-successors` | Where §3.4 successor commitments are kept, for the identities §13 says get one. `""` keeps them in the card cache only, which a restart forgets — and so does enough traffic to evict the card. Making the caches forget is the attack the commitment exists to stop |
| `[ng] trusted_proxies` | empty | Addresses whose `X-Hotline-Client-Cert` and forwarded-address headers are believed (§5.3). Single addresses or CIDR blocks (`["127.0.0.1", "10.0.0.0/8"]`); IPv4-mapped peers on a `[::]` bind match their IPv4 form. Also the set the rightmost-element walk skips over, so it must contain proxies and no clients |
| `[ng] forwarded_header` | `"x-forwarded-for"` | Which header a trusted proxy writes the client's address into: `"x-forwarded-for"`, `"forwarded"` (RFC 7239), or `"none"` (§5.3). Only the named one is read |
| `[server] mark_cleartext` | `false` | Whether the legacy user list marks unencrypted sessions with User Flags bit 4. Off until that bit is confirmed free against 1.8/1.9 — see §10 |
| `[identity] bindings` | — | *(not implemented)* Both bindings of §5 are served: challenge always, mTLS whenever `[ng] trusted_proxies` is non-empty |
| `[identity] revocation_max_age`, `revocation_stale` | — | *(not implemented)* §5.2 step 4 is stubbed; there is no registrar to fetch a list from yet |
| `[legacy] cleartext`, `cleartext_mask` | — | *(not implemented)* §10 marks cleartext sessions; it does not restrict them |

Account files gain an `[identity]` table: `fingerprint` (the 52-character
form), `login` (bool, default true), `allow_self_link` (bool, default
true) and `reserve_name` (bool, default false). Existing account files
without it are valid.

An account with a linked identity and no password is reachable *only* by
proving the identity: the password path refuses it outright, empty
password included (§8.3). That is what makes `new_accounts = create` safe
to run on a server that also serves the legacy port.

---

## 13. Implementation notes

- The ng listener needs to route a few HTTP paths before the upgrade. Any
  minimal HTTP layer over the existing `tokio-tungstenite` accept works;
  this is the point at which `hotline-ng.md`'s "no HTTP framework yet"
  decision expires, and it should be revisited with media and history in
  mind rather than solved just for identity.
- Verification (card, certificate, proof, attestation) is one function over
  decoded CBOR. Both bindings and the card endpoint call it.
- Transport tokens, challenges and session tokens share the same storage
  discipline as `hotline-ng.md` §9: CSPRNG, stored hashed, never logged.
  hxd-ng looks them up in a map keyed by the SHA-256 of the secret, which
  is not a constant-time compare and does not need to be: what varies
  with the attacker's input is the hash of their guess, and the timing of
  a lookup on it says nothing about the secret. A store that compared
  secrets directly would need one.
- TRTP over WebSocket is `hxd-session` driven by an adapter that presents
  binary frames as `AsyncRead`/`AsyncWrite`, plus one extra field on the
  session (the transport identity, if any) consulted at Login (107). The
  legacy frontend otherwise doesn't know it isn't on TCP.
- The cached card and device certificate are what make the mTLS
  "connection is the credential" path work. hxd-ng keys them by device
  public key (not its fingerprint — the key is what arrives in the
  certificate, and hashing it to look it up buys nothing), with the
  identity public key alongside. Both tables are bounded and evicted:
  they are filled by `/identity/auth`, which any fresh key can reach when
  `unattested = guest`. Bounding the *count* only bounds the memory if
  the entries are bounded too — the cached bytes are a card (§3.4, 16
  KiB) and a certificate (§3.3, 4 KiB), which is what those size limits
  are for.
- Re-admitting a device already on file is a *read-only* admission. It
  re-checks the signatures, honours an existing account link, and writes
  nothing — no link, no account creation. Otherwise every upgrade repeats
  the side effects of the `/identity/auth` that first recorded the device.
  Read-only is about *writes*, not about policy: `new_accounts = deny`,
  the allow list and the attestation rules are decided again on every
  admission. A device cached while its account was linked must not keep
  being admitted as a guest after the operator removes the link.
- The successor commitment of §3.4 must outlive the process. A server that
  holds it only in memory hands an attacker "restart the server" as the
  way to move it, which is exactly the attack the commitment exists to
  stop. hxd-ng writes `[identity] successors`, one line per identity,
  appended and compacted at load rather than rewritten per insert.
- **Who gets anchored.** Only an identity with *standing* on this server:
  one with an account here (linked or created) or an attestation the
  server accepted. Anchoring every card that ever authenticated
  contradicts the bounded-growth rule below — with `unattested = guest`
  any fresh key can reach `/identity/auth`, and each one would leave a
  durable line behind. What a commitment protects is a relationship
  people on the server have with an identity; a key nobody here knows has
  none yet, and gets its anchor on the login that gives it one. A server
  bounds the table as well and says so in its log when it is full: a
  ceiling that only holds while the operator's policy is restrictive is
  not a bound.
- Registrar keys for attestation checks are fetched from the registrar's
  `/.well-known/hotline` over HTTPS and cached with a long lifetime. A
  server with no outbound network still runs identity; it just accepts no
  attestations.
- Bounding the verification work one request can buy matters as much as
  bounding storage: a card is an unauthenticated caller's bytes, and
  everything in it that costs a signature check needs a count. hxd-ng
  verifies a card's own envelope before anything it contains, caps the
  attestations it will look at (§3.4), reads and checks the card's own
  fields before entering the attestation loop at all, and checks each
  attestation's cheap fields and subject before its signature.
- Rate limits: `/identity/challenge` and `/identity/auth` per source address
  like login attempts. A forged card costs an attacker nothing and the
  server two signature checks. Not implemented in hxd-ng yet; the growth
  of every table an unauthenticated caller can touch is bounded
  independently, so the limiter is a refinement rather than a load-bearing
  part of the design.
- **Interaction with `CAPABILITY_MESSAGING`.** fogWraith's messaging
  extension keys everything on the account Login; a linked identity is an
  account, so the two compose without change. The seams — a durable key
  beside the Login, lookup by handle, an opaque envelope through the
  message path for E2E — are proposed as amendments to that extension in
  `docs/proposals/messaging-identity-amendment.md`.

---

## 14. Open questions

- **Transport token vs session token.** Reviewed and kept separate (§5.1):
  the token authenticates a socket before any application protocol has
  run, and the same token serves both WebSocket paths. If the ng JSON
  path ever wanted `resume` to double as first attach, that would be a
  session-layer change and could be made without touching this layer.
- **`trtp_login = trust` and legacy client UX.** A 1.5 client will still
  show a login box. Is "type anything" acceptable, or should tunnels
  advertise a fixed placeholder login the user is told to use?
- **HOPE inside the tunnel.** Refusing it is simplest; allowing it is
  harmless but doubles encryption. Should the server advertise it as
  unsupported on the tunnel path so clients don't try?
- **Reserved name as login name.** Simple and matches how operators think,
  but a user can't reserve a display name that differs from their login.
  Is a separate `reserved_name` field worth the schema change?
- **Card size and media.** 16 KiB is generous for text and useless for
  images. Should icons and images be referenced by hash through the inline
  media extension rather than inlined?
- **Device renewal without the identity key.** A phone holding only a device
  key can't mint its own renewal. The registrar spec needs a renew-device
  flow that doesn't unwrap the identity key on the device; its shape decides
  whether 90-day certificates are practical.
- **User Flags bit 4 on 1.8/1.9.** §10's cleartext marker takes value 16
  in field 112 on the strength of "classic clients ignore unknown bits".
  If 1.8/1.9 already means "automatic response" by that value, the marker
  has to move to a bit nothing has claimed. Needs testing against a real
  client before any server turns marking on by default.
- **Multiple sessions per identity on one server.** `hotline-ng.md` §12
  already asks whether the roster should group same-user sessions. Identity
  gives it a reliable key to group on; this document doesn't require it.
