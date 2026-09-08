# Hotline-ng transport authentication — an authenticated principal for the ng listener

Status: draft, for discussion. Split out of `hotline-ng-identity.md`
after review: that document tried to be both the transport's
authentication layer and the definition of a Hotline identity, and the
two have different owners and different lifetimes. This document is the
transport half. It says how a connection to the ng listener acquires an
authenticated *principal* before the WebSocket upgrade, what the
transport is entitled to decide with one, and how the classic TRTP
protocol is carried over such a socket. It does not say what a principal
*means* — whether a key is a person, a device, an account — which is a
*profile*'s business. One profile is defined today, in
`hotline-ng-identity.md`, and it is what hxd-ng ships.

Implemented in hxd-ng: discovery, both bindings of §6, transport tokens,
both WebSocket paths of §7, cleartext marking, the proxy contract. Not
yet: the `bindings` setting, rate limits on the endpoints, and any
binding other than the two here.

Companion documents: `hotline-ng-identity.md` (the identity profile:
what a key principal is under Hotline identity, cards, account
association), `identity-threat-model.md` (what all of this protects and
from whom), and `hotline-ng.md` (the WebSocket protocol this extends).

---

## 1. Summary

The ng transport is a WebSocket, which begins as an HTTP request. This
document adds a small set of HTTP endpoints, served by the same listener
that accepts the upgrade, through which a client proves it holds a key.
Two ways to do the proof — a challenge signed by the key, or a TLS client
certificate presented to the reverse proxy — end in the same state: *this
connection belongs to key K*. That state is the **principal** (§3).

A principal is enough, on its own, for what a transport can decide about
a connection: admission (allow lists, bans), and rate limits. Anything
that terminates the HTTP handshake can establish one, including a relay
that only forwards the bytes it carries (§10.2).

What a principal is *not* enough for is everything the application
protocol says about a session: roster marking, presence, which local
account this is. Those are downstream of the principal and belong to a
server that terminates the application protocol, and to the profile that
says what the key means. The transport hands the principal to the
application login and stops.

Two application protocols run over the authenticated socket: the ng JSON
protocol of `hotline-ng.md`, and TRTP itself in binary frames (§7.3), so
a legacy client behind a plain tunnel gets an authenticated, encrypted
session with no change to the legacy wire. The legacy wire (TRTP on
:5500) is not changed by anything here.

**Principals and profiles.** Both bindings yield a key. What that key is
worth — whether it is admitted at all, what it displays as, whether it
may hold an account — is decided by a profile layered on this document
(§6.4). The Hotline identity profile requires the key to be a *device*
certified by an *identity*, and supplies a card and attestations; that
is the only profile defined and the only one hxd-ng implements. Other
kinds of principal are conceivable — an OIDC subject, a WebAuthn
credential — and would be new bindings in this document with their own
profiles. Nothing in the WebSocket paths, the cleartext rules or the
tunnel and relay roles would change for them: a binding's only output is
a token bound to a principal, the upgrade's only input is that token, and
neither side of that contract knows what the other did (§6.1). §6.5 says
what principal each of those methods would produce, and no more.

---

## 2. Why HTTP and not the chat protocol

Authentication is a transport concern. The ng transport is a WebSocket,
which begins as an HTTP request, and hxd-ng already assumes a TLS-terminating
reverse proxy in front of it. Doing authentication in that HTTP exchange
means:

- the WebSocket session arrives already bound to a key, and the JSON protocol
  never carries credentials for authenticated sockets;
- a tunnel in front of a *legacy client* can authenticate upstream with the
  user's key using plain HTTP client code and then forward bytes, without
  knowing anything about TRTP;
- a relay in front of a *legacy server* (hxd 0.x, Mobius, HLServer) can
  establish who is on each socket and gatekeep accordingly, without that
  server changing and without the relay reading the tunnelled protocol;
- mTLS becomes a first-class option rather than a special case, since it is
  an HTTP-layer mechanism already;
- a binding that is not a key at all (an identity-provider login, say)
  has somewhere to live that is neither the chat protocol nor the legacy
  wire.

The cost is that hxd-ng grows a small HTTP router on the ng listener, which
`hotline-ng.md` deferred "until media/history/push need one." Authentication
needs one. It is a handful of routes.

---

## 3. The principal

A principal is what a binding produces and what the rest of the system
consumes. It is server-side state attached to a socket, never a wire
object; the fields below name what a server knows, not an encoding. The
shape is `(method, id)`, with an optional key: enough to name any
authenticated party this transport might one day admit, and nothing that
requires the transport to understand what the party is.

| Field | Meaning |
|---|---|
| `method` | How the party was authenticated, and therefore what namespace `id` lives in. This document defines `key`: an Ed25519 public key whose holder signed a challenge (§6.2) or presented it in a TLS client certificate (§6.3). §6.5 sketches `oidc`, `saml` and `webauthn` without defining them |
| `id` | A stable identifier, unique within `method`. For `key`, the fingerprint of the key (§4.2). For a method that authenticates against a third party, the issuer and the issuer's subject identifier together (§6.5), never the subject alone |
| `subject` | Who this principal is an instance of. Supplied by the profile; absent, it is `id`. The Hotline identity profile sets it to the *identity* fingerprint, so that every device of one person is one subject |
| `key` | A public key, when `method` yields one, with the algorithm the method says it is. Present only if the holder can sign arbitrary bytes with it: a `key` principal's Ed25519 key qualifies, a WebAuthn credential's does not (§6.5), and an identity-provider login has none. A profile may build signed objects on this field only when the method says it qualifies |
| `profile` | Whatever the profile verified and wants carried with the socket: under Hotline identity, the card, the device certificate, the accepted attestations and the derived handle and age. Under a method with no objects of its own, the display name and whatever else the profile extracted from the method's assertion |

Rules:

- **Policy keys on `(method, subject)`.** Allow lists, bans and "already
  connected from this principal" are decided on the subject *within its
  method*, so that a profile which groups several keys under one person
  gets one decision for the person, and so that an identifier from one
  issuer can never collide with the same string from another. A ban list
  that names bare fingerprints is a ban list of `key` principals; the
  federation spec, which signs and exchanges such lists, either carries
  the method with each entry or scopes itself to `key`, and has to say
  which.
- **Bindings of one method are indistinguishable above the transport.**
  A key proved by challenge and the same key presented in a client
  certificate produce the same principal. Nothing downstream may behave
  differently, and nothing in the principal records which binding ran.
  Different methods *are* distinguishable, by `method`, and a profile may
  treat them differently — a key can sign, an issuer's subject cannot.
- **Every principal has a profile.** A profile says what a principal is
  worth (§6.4): whether it is admitted at all, what it displays as,
  whether it may hold an account. For `key` the only profile is Hotline
  identity, which requires a card and a device certificate, and a server
  that admitted a bare key with neither would be running a profile this
  document does not define. A method that authenticates against a third
  party may define a *default* profile — the party's display name and
  claims, nothing signed — so that it needs no separate object scheme to
  be useful; that default is part of the method's definition, not of the
  transport.
- **The transport decides only on its own grounds.** A binding that fails
  its proof is refused here. Whether an otherwise-valid principal is
  *admitted* — allow lists, attestation policy, "no unknown keys" — is the
  profile's decision, made with the profile's information, at the
  profile's step of the auth exchange (§6.4).
- **The principal outlives nothing.** It is a property of one socket. A
  session — the application-layer object with a uid and a roster row — is
  created by the application login on that socket, may be resumed on
  another socket, and carries whatever it copied from the principal at
  login. The profile says what is copied (`hotline-ng-identity.md` §6).

---

## 4. Primitives

### 4.1 Encoding and signatures

Signed objects in this document and in every profile are CBOR (RFC 8949)
in deterministic encoding (§4.2.1). A signature covers the object's
encoded bytes with the `sig` entry removed, prefixed by a domain string:

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

These rules are restated in `hotline-ng-identity.md` §3.1 so that
document stands alone; the two must not drift. `crates/hl-identity` is
the one implementation of both.

### 4.2 Fingerprint

`SHA-256(pubkey)`, 32 bytes. Displayed as lowercase Crockford base32, no
padding; may be shortened to 8 characters in UI. Servers store and compare
full fingerprints. A `key` principal's `id` is the fingerprint of its
key; a profile may define fingerprints of other keys (the identity
profile's subject is the fingerprint of the identity key).

### 4.3 Server key

A server implementing this document has an Ed25519 keypair generated on
first start. It is published in discovery (§5), bound into login proofs
(§6.2), and used by the federation spec to sign ban lists and vouches. It
is not a TLS key.

---

## 5. Discovery

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
    "bindings": [ "challenge", "mtls" ],    // which of §6 this server accepts
    "association": "server",                // or "none" on a relay (§10.2)
    "endpoints": {
      "challenge": "/identity/challenge",
      "auth":      "/identity/auth",
      "card":      "/identity/card",        // profile endpoints: hotline-ng-identity.md §4
      "link":      "/identity/link",
      "unlink":    "/identity/unlink"
    },
    "new_accounts": "guest",                // the rest of the block is the profile's
    "min_attestation_age": 0,
    "trusted_registrars": []
  },
  "registrar": null                         // or the registrar spec's block
}
```

`v`, `name`, `server_key` and `ng` are this document's. So are, inside
the `identity` block, `enabled`, `bindings`, `association`, and the
`challenge` and `auth` endpoints: they describe the key binding and where
to reach it. The block is named for the profile the key binding shipped
with, and the paths under it carry the same name; both are what discovery
*says* they are, and a client reads them from here rather than assuming
them. A future binding gets its own block, with its own `endpoints`.
Everything else under `identity` is defined by `hotline-ng-identity.md`
§4.

`server_key` is required because the challenge binding binds proofs to
it and the federation spec signs with it; a server that offered only a
method with no proof of its own (§6.5) would still publish one, since
discovery is one document and federation does not care how a socket was
authenticated.

`association` says whether the server behind this listener can associate
accounts with principals at all (§9): `server` when it terminates the
application protocol, `none` on a relay, so clients don't expect reserved
names or auto-login from a relay.

The same document is where a registrar advertises its own endpoints and key,
so one discovery format serves servers, registrars, relays and tunnels.
Clients cache it for the connection's lifetime; relays cache it per
upstream.

---

## 6. Authentication

### 6.1 Model

Authentication produces a short-lived *transport token*: an opaque bearer
token, 32 bytes base64url, valid for 60 seconds, bound server-side to a
principal (§3). The client presents it when opening a WebSocket (§7), and
the socket is thereafter known to belong to that principal. Tokens are
single-use.

The token is deliberately not a session token. A session is an
application-layer object — it has a uid and a roster row — and the same
transport token authenticates a socket whether the application protocol
on it turns out to be ng JSON or tunnelled TRTP. Nothing application-level
exists until the application protocol's own login runs.

**This is the whole interface between a binding and the transport.** A
binding, whatever it is, ends by minting a token and binding a principal
(§3) to it server-side; the upgrade (§7.1) redeems the token and reads
the principal off it. The upgrade never sees a proof, a key, a
certificate or an assertion, and the binding never sees a socket. A
server can therefore say "this connection is authenticated as this
principal" without the part of it that handles WebSockets knowing whether
the principal came from a signed challenge, a client certificate, or
something this document does not define. That is what keeps §7–§10
independent of §6.2 and §6.3.

Two bindings produce a token today. Servers advertise which they accept.
The server ends in the same state either way and nothing above the
transport can tell them apart.

### 6.2 Challenge binding

Works everywhere, including browsers.

**Step 1.** `POST` to the `challenge` endpoint with an empty body. Response:

```jsonc
{ "challenge": "…base64url 32 bytes…", "server_key": "…", "expires_in": 60 }
```

The challenge is stored server-side for 60 seconds and consumed on use.
Servers rate-limit this endpoint per source address as they do login
attempts; it is free to call and costs the server a random draw.

**Step 2.** `POST` to the `auth` endpoint:

```jsonc
{
  "proof":       "…base64url CBOR…",
  "downstream":  "local",                // optional: local | cleartext
  // …plus whatever the profile requires (§6.4): for Hotline identity,
  // "card" and "device_cert", and optionally "login", "password", "create"
}
```

`proof` is a **login proof**, domain `hl-identity/login/v1`, signed by the
key being proved:

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `challenge` | bstr(32) | yes | Echoed from the server |
| `server_key` | bstr(32) | yes | Echoed from the server; binds the proof to this server, so a challenge relayed from elsewhere is useless |
| `device` | bstr(32) | yes | The public key the proof is signed with. Named `device` because under the identity profile it is a device key; the transport reads it as *the key* |
| `time` | uint | yes | Rejected outside the server's clock-skew tolerance |
| `sig` | bstr(64) | yes | |

`downstream` is what the client declares about the hop *behind* it. A
client that is the endpoint, or a tunnel forwarding only over loopback,
says `local` (the default). A tunnel forwarding over a cleartext network
hop (§10.1) MUST say `cleartext`; the server then marks the session
`cleartext` on the roster (§8) so other users get the PM warning, TLS on
the WebSocket notwithstanding. The server has no way to verify the claim
and takes the conservative direction at face value: a client may make a
session look less safe than it is, never more.

The server verifies, and fails on the first error:

1. proof signature with `device`; `challenge` known and unexpired;
   `server_key` matches; `time` within tolerance.

That is the whole of the transport's check. It establishes a `key`
principal with `id` = fingerprint of `device`. The profile's verification
runs next, on the same request, and may refuse it (§6.4).

Success (200) carries the token and whatever the profile adds:

```jsonc
{
  "token": "…",
  "expires_in": 60,
  // …profile fields: for Hotline identity, "fingerprint", "handle", "age",
  // "outcome", "account" (hotline-ng-identity.md §5.3)
}
```

Failure with `{ "error": code, "text": "…" }`. The transport's codes:

| code | status | |
|---|---|---|
| `bad_proof`, `unknown_challenge` | 401 | prove it again |
| `denied` | 403 | policy refused this principal |
| `server_error` | 500 | ours, logged, not explained |

A profile adds codes of its own in the same shape (the identity
profile's are in `hotline-ng-identity.md` §5.3). A client treats any 401
as "prove it again", any 403 as "not with this principal", and any code
it does not know by its status.

### 6.3 mTLS binding

For clients that can present a TLS client certificate: native apps, tunnels
and relays. Not browsers.

The client certificate is a self-signed X.509 certificate whose
SubjectPublicKeyInfo is the Ed25519 public key being proved (RFC 8410).
Nothing else in the certificate is examined; validity dates, subject and
extensions are ignored, since the profile's own objects (under Hotline
identity, the device certificate) are the authority on all of that.

Ignoring the rest is not the same as not parsing it. The key MUST be taken
from the SubjectPublicKeyInfo by position — walk `Certificate` →
`TBSCertificate`, skip `version`, `serialNumber`, `signature`, `issuer`,
`validity` and `subject`, and read the seventh field. Everything ahead of
the SPKI is chosen by whoever requested the certificate (`serialNumber` is
an arbitrary INTEGER; a `Name` attribute value is `ANY`), so an
implementation that *searches* the DER for RFC 8410's algorithm identifier
will find whatever bytes the subject planted there. A certificate whose own
SPKI is the attacker's key — which is what the proxy's handshake validates
— carrying a victim's key inside its subject would then be read as the
victim.

hxd-ng does not terminate TLS. The reverse proxy requests (but must not
require) a client certificate and forwards it on the upstream request as
`X-Hotline-Client-Cert` (base64 DER). The server honours that header only
from addresses listed in `[ng] trusted_proxies`; from anywhere else it is
stripped.

Trusting the proxy's address is necessary but not sufficient. The proxy
MUST set `X-Hotline-Client-Cert` from the certificate that took part in
*its own* TLS handshake, and MUST drop any copy of the header the client
sent — otherwise a client can send the header through the proxy carrying
any key's public certificate and impersonate that key. In Caddy,
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
or the challenge binding of §6.2, which needs no proxy cooperation at
all. An operator who lists a proxy in `trusted_proxies` is asserting
that it is configured this way; the server cannot check it. Operators who
terminate TLS in the server itself in some future build get the same
header semantics from the in-process listener, with the same contract
satisfied by construction.

With a client certificate on the connection, `POST` to the `auth`
endpoint omits `proof` and carries only what the profile requires:

```jsonc
{ "card": "…", "device_cert": "…" }     // the identity profile's fields
```

The transport's check is that the certificate's public key is the key the
profile's objects name (under Hotline identity, `device_cert.device`);
the profile's verification then runs as for the challenge binding.
Response and failure codes are the same.

Once a key has the profile's objects on file, a WebSocket upgrade that
carries a client certificate for that key is authenticated without a
token (§7.1), for as long as the profile says those objects are valid.
This is the "the connection is the credential" path mTLS users expect;
the `auth` call is needed once per key, and again when the profile's
objects change. What "on file" means, and what is re-checked on every
such upgrade, is the profile's (`hotline-ng-identity.md` §5.5).

### 6.4 Profiles

A binding proves possession of something. A profile says what the thing
is worth. The two meet at the `auth` request:

- the profile adds fields to the request (its objects, and any
  credentials it accepts) and to the success response;
- the profile's verification runs after the transport's, on the same
  request, in an order the profile defines, and refuses with its own
  error codes;
- the profile sets `subject` and `profile` on the principal (§3) and may
  restrict what the principal may do (the identity profile's device
  capabilities, for one);
- the profile says what a session copies from the principal at login,
  what the roster shows (§7.2), and whether and how the principal
  associates with an account (§9).

This document defines no profile. `hotline-ng-identity.md` defines the
Hotline identity profile for `key` principals, and it is the profile hxd-ng
implements: a key is a *device* certified by an *identity*, and a request
with no valid card and certificate is refused. There is no bare-key
admission in hxd-ng, and a server that offered one would be running a
profile with its own document.

A binding of another method — an identity-provider login, a platform
authenticator — would be specified in this document with its own step 1
and step 2, and either a default profile of its own (§3) or a pointer to
one. Whether it yields a `key` the profile can sign with is a property of
the method, stated in its definition, so that nobody expects cards or
end-to-end messaging from a principal that cannot have them. §6.5 does
this for the three methods review asked about, to the depth needed to
show they fit, and no further.

### 6.5 Other methods

None of these is implemented, and this document does not require any
implementation to support them, nor does it say how any of them works —
each has its own standard. What it does say is the principal (§3) each
would produce, because that is the only thing about them the transport
has to be able to carry, and writing it down is how §3 and §7.1 are
checked against something other than a key.

| Method | `id` | `key` | Default profile |
|---|---|---|---|
| `oidc` | issuer URL and `sub`, together — `sub` is unique only within an issuer | none | the display-name claim and whatever the operator maps; nothing signed |
| `saml` | identity provider `entityID` and `NameID`, together, with the `NameID` format part of the comparison | none | mapped attributes, as for OIDC |
| `webauthn` | this server's relying-party id and the credential id, together — a credential is scoped to one origin by construction | **absent**: the credential has a public key, but the authenticator signs only its own assertion structure with it, never arbitrary bytes, so a profile can sign nothing with it | the display name given at registration |

Each would reach a transport token in whatever way its own standard
provides — a posted token, a redirect that ends at a callback, an
assertion — and would then be presented at the upgrade exactly as §7.1
describes, since the upgrade sees only the token. A method that arrives
by browser redirect is what the `?token=` form of §7.1 exists for.
Everything else about them — endpoints, verification, registration of
a WebAuthn credential against a principal that already exists — belongs
to a section that would define the method, and to the standard it
implements.

What the three have in common is what §3 is for: an `id` that is a pair
of namespace and identifier, a `key` that is present only when it can
sign, and a profile that may be no more than a display name. An
implementer who finds one of these rows wrong should fix §3 first and
the row second.

---

## 7. Opening a WebSocket

Two WebSocket paths are advertised in discovery. Both are authenticated
the same way; they differ only in what flows after the upgrade.

### 7.1 Presenting the transport token

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
- a client certificate on the connection for a key on file, forwarded
  under the §6.3 proxy contract, which needs no token at all.

The upgrade request carries nothing about the principal itself: no key,
no proof, no profile object. It carries a token, or a client certificate
the server can already map to a key on file. Everything the socket then
knows about who holds it is read from what the token was bound to (§3),
and that binding has the same shape whatever minted it. The client
certificate form is the one exception, and it is an optimisation for
the `key` method rather than a second model: it works only because that
method's proof *is* something the TLS handshake can carry. A binding of
any other method needs nothing from this section beyond "mint a token
and present it here".

Cookies are not used: they would make every cross-site page a potential
initiator of an authenticated socket.

An upgrade with an invalid or expired token is refused with HTTP 401. It
is not downgraded to an unauthenticated socket, so a client cannot silently
end up as a guest because a token expired in flight.

An upgrade with none of these is an unauthenticated socket and proceeds
exactly as it does today: the ng JSON handshake of `hotline-ng.md` §6, or
a classic TRTP handshake in the tunnel. Nothing changes for clients that
don't authenticate.

### 7.2 The ng JSON protocol (`ng.ws`)

On an authenticated socket the first frame is still `login`. What the
server does with its `login` and `password` params is the profile's
decision — under Hotline identity they are ignored and should be omitted
(`hotline-ng-identity.md` §6.1) — and the account the session lands on is
decided per §9. The reply is as usual, with the profile's additions to
`self` and a `caps` entry naming the profile (`"identity"` for Hotline
identity).

Each `user` object in the roster and in `user_joined` / `user_changed`
gains a required `transport` field, `"encrypted"` or `"cleartext"` (§8),
which is this document's, and an optional sub-object the profile
defines for what other users may know about the principal (the identity
profile's `identity: { fingerprint, handle }`). Clients that predate
this ignore both.

`resume` is unaffected: the session token already proves continuity, and
whatever the session copied from the principal is a property of the
session once the session exists, not of the connection.

### 7.3 TRTP over WebSocket (`ng.trtp`)

The socket carries the classic protocol unchanged: binary frames, whose
payloads concatenated in order are exactly the byte stream a TCP
connection to the legacy port would carry, in both directions. Frame
boundaries carry no meaning; a client may send one transaction per frame
or split however it likes, and the server may do the same. Text frames on
this path are a protocol error and close the socket.

Inside the tunnel the client performs the ordinary TRTP handshake and
Login (107) with whatever classic credentials it has. What the server
does with those, given that it also holds a principal for the socket, is
account association (§9; under Hotline identity,
`hotline-ng-identity.md` §8.3). The server treats the session as
encrypted for §8, since the WebSocket is TLS.

This path needs no TRTP-aware code in the tunnel or in any relay. In
hxd-ng it is the existing legacy frontend fed from a WebSocket instead of
a TCP socket, plus the principal on the session. HOPE transport
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

## 8. Cleartext sessions and the legacy wire

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

A tunnelled TRTP session (§7.3) is `encrypted` **when the tunnel's own
local hop is**. The hop the server can see — tunnel to server — is TLS,
and the server never sees those bytes in the clear. The other hop, the
classic client to the tunnel, is cleartext by construction (§10.1): the
tunnel exists because the client cannot speak TLS. On loopback that hop
crosses nothing, and the session is `encrypted`. Off loopback — which
§10.1 permits, deliberately and opt-in — it crosses a network, and the
session is `cleartext`.

The server cannot observe which, so the tunnel declares it: `downstream`
at the `auth` endpoint (§6.2), `cleartext` when the tunnel listens
anywhere but loopback. A client may declare itself less safe than it
looks and never more, so a tunnel that lies can only cost its own user a
warning they didn't need. `hlid tunnel` sets it from its own `--listen`.

With that hop on loopback this is, rather than HOPE transport
encryption, the recommended way for a legacy client to get an encrypted
session — it also gets a principal.

An ng client must warn before sending a private message to a `cleartext`
session.

---

## 9. Account association

*Association* is the mapping from a principal to a local account, and
the rule this document sets is about who may do it: only a server that
terminates the socket **and** implements the application protocol on it,
because only it has the principal and the account table in one place.
hxd-ng does, for both application protocols it speaks over WebSocket. A
relay or tunnel never does (§10), and says so in discovery
(`association: "none"`).

A link, wherever it is stored, records the principal's `method` and
`subject` together: an account file that carries an identity fingerprint
is recording a `key` link, and an account that may one day be reached
through an identity provider records that issuer's subject beside it, not
instead of it. The two cannot collide and an account may in principle
hold one of each. Everything else — what a link is, which paths write
one, what happens to a principal with no account, how a classic login
inside a tunnel is reconciled with the principal on the socket — is the
profile's. For Hotline identity it is `hotline-ng-identity.md` §8.

---

## 10. Tunnels and relays

Neither needs to *parse* the protocol it carries. That is the point:
everything in this section is possible with an HTTP client library, a
WebSocket library, and the profile's object library (`hl-identity` for
Hotline identity), and nothing here requires TRTP knowledge.

It is not a confidentiality claim. Both processes handle the payload
bytes in the clear and can read or alter them at will; the threat model
says so of their operators explicitly. What they are spared is
understanding those bytes, not seeing them.

### 10.1 Tunnel: legacy client → authenticating server

Runs on the user's machine (or somewhere they trust), holds one key,
listens on a local TCP port for the classic client, and forwards bytes
over a TRTP-over-WebSocket connection (§7.3) to the server.

- It authenticates upstream with its own key by either binding, and
  presents whatever objects its profile requires. Under Hotline identity
  it is a device like any other, with a device certificate scoped to
  what a tunnel needs (`hotline-ng-identity.md` §10).
- It forwards bytes verbatim in both directions and does nothing else. In
  particular it does not touch the classic login: the server sees it
  inside the tunnel and reconciles it with the principal (§9).
- Its local hop is cleartext on loopback. It must not be configured to
  listen on a non-loopback address without the user opting in, since that
  would re-create exactly the exposure the tunnel exists to remove — and
  when the user does opt in, the tunnel MUST say `"downstream":
  "cleartext"` at the `auth` endpoint (§6.2) so the session is marked and
  other users are warned before PMing it. A tunnel has no other way to
  tell the server, and the server has no other way to know.

This is stunnel with a key. A relay (§10.2) can also act as one
downstream, and a native client can embed one.

### 10.2 Relay: authenticating front for a legacy server

Runs in front of a server that speaks only TRTP (hxd 0.x, Mobius,
HLServer). Implements discovery, the `challenge` and `auth` endpoints, the
profile's public endpoints, and the WebSocket paths, and forwards each
socket's bytes to a TCP connection to the legacy server. It has a
principal for every socket and no account table.

- It holds its own server key and is, for authentication purposes, the
  server: its allow list, ban list and the profile's admission policy
  apply at the HTTP layer, and the federation spec treats its signatures
  as the operator's.
- It gatekeeps: refuses sockets whose principal is banned, not on an
  allow list, or refused by the profile's policy, before any bytes reach
  the legacy server. This is where a relay earns its keep, and it needs
  no cooperation from the server behind it.
- It does not associate accounts (§9). The classic login inside the
  tunnel is the legacy server's business; the relay never sees a password
  it needs to check and never holds one. Discovery says so:
  `"association": "none"`. What the profile's endpoints return on a relay
  is the profile's (`hotline-ng-identity.md` §10).
- It annotates nothing on the legacy wire, since it doesn't speak it.
  Clients connecting through the relay see principal information only via
  the relay's own discovery and the profile's public endpoints.
- It can offer the ng JSON path only if it implements the JSON protocol
  itself against TRTP downstream, which is a full client implementation
  and out of scope here; a relay that offers only `ng.trtp` is complete.

### 10.3 What the server guarantees them

Discovery is stable, tokens and challenges are single-use, the mTLS
header contract is honoured only from trusted proxies, and the
TRTP-over-WebSocket path carries exactly the bytes the TCP port would and
pings a quiet socket (§7.3). A tunnel or relay that follows this section
is indistinguishable from a native client to the server and to other
users, except that a relay-fronted legacy server has no account
association to offer.

---

## 11. Settings

The table is what `hxd-ng` reads today; a row marked *(not implemented)*
is design, not configuration, and setting it is a startup error. The
profile's own settings are in `hotline-ng-identity.md` §12; they share
the `[identity]` section because hxd-ng has one profile and one switch.

| Setting | Default | Meaning |
|---|---|---|
| `[identity]` present | absent | The section's presence is the master switch for this document's endpoints and for the identity profile together. Absent, discovery reports `enabled: false` and the endpoints 404. It needs `[ng]`: without an ng listener there is nothing to serve the endpoints from, so `[identity]` without `[ng]` is a startup error rather than a section quietly ignored |
| `[identity] key` | `identity-server.key` | The server's Ed25519 seed (§4.3), hex, mode 0600; generated on first run |
| `[identity] clock_skew` | `300` | Seconds of tolerance on the proof's `time` (§6.2) |
| `[identity] trtp` | `true` | Serve the TRTP-over-WebSocket path (§7.3) |
| `[ng] trusted_proxies` | empty | Addresses whose `X-Hotline-Client-Cert` and forwarded-address headers are believed (§6.3). Single addresses or CIDR blocks (`["127.0.0.1", "10.0.0.0/8"]`); IPv4-mapped peers on a `[::]` bind match their IPv4 form. Also the set the rightmost-element walk skips over, so it must contain proxies and no clients. Non-empty is what turns the mTLS binding on |
| `[ng] forwarded_header` | `"x-forwarded-for"` | Which header a trusted proxy writes the client's address into: `"x-forwarded-for"`, `"forwarded"` (RFC 7239), or `"none"` (§6.3). Only the named one is read |
| `[server] mark_cleartext` | `false` | Whether the legacy user list marks unencrypted sessions with User Flags bit 4. Off until that bit is confirmed free against 1.8/1.9 — see §8 |
| `[identity] bindings` | — | *(not implemented)* Both bindings of §6 are served: challenge always, mTLS whenever `[ng] trusted_proxies` is non-empty |
| `[legacy] cleartext`, `cleartext_mask` | — | *(not implemented)* §8 marks cleartext sessions; it does not restrict them |

---

## 12. Implementation notes

- The ng listener needs to route a few HTTP paths before the upgrade. Any
  minimal HTTP layer over the existing `tokio-tungstenite` accept works;
  this is the point at which `hotline-ng.md`'s "no HTTP framework yet"
  decision expires, and it should be revisited with media and history in
  mind rather than solved just for authentication. hxd-ng uses hyper
  directly.
- **The HTTP routes answer CORS**, with `Access-Control-Allow-Origin: *`
  and an `OPTIONS` handler for the preflight that `PUT /identity/card`
  triggers by sending `application/cbor`. A wildcard is safe here for a
  reason worth stating rather than assuming: every one of these routes is
  authenticated by a token in the body or the URL and none by a cookie,
  so a hostile page has no ambient credential to ride and an allow-list
  would protect nothing. Without it a browser client can only ever talk
  to the server that served it, which rules out both a client offering a
  choice of servers and a device following an enrollment link to a mailbox
  somewhere else (`identity-enrollment.md` §5.6). `ETag` is named in
  `Access-Control-Expose-Headers` so the card fetch can still be
  revalidated.
- Transport tokens, challenges and session tokens share the same storage
  discipline as `hotline-ng.md` §9: CSPRNG, stored hashed, never logged.
  hxd-ng looks them up in a map keyed by the SHA-256 of the secret, which
  is not a constant-time compare and does not need to be: what varies
  with the attacker's input is the hash of their guess, and the timing of
  a lookup on it says nothing about the secret. A store that compared
  secrets directly would need one.
- TRTP over WebSocket is `hxd-session` driven by an adapter that presents
  binary frames as `AsyncRead`/`AsyncWrite`, plus one extra field on the
  session (the principal, if any) consulted at Login (107). The legacy
  frontend otherwise doesn't know it isn't on TCP.
- The "key on file" path of §6.3 is a cache of the profile's objects,
  keyed by public key (not its fingerprint — the key is what arrives in
  the certificate, and hashing it to look it up buys nothing). It is
  filled by the `auth` endpoint, which any fresh key can reach under a
  permissive profile policy, so it is bounded and evicted; and bounding
  the *count* only bounds the memory if the entries are bounded too,
  which is what the profile's object size limits are for.
- Rate limits: the `challenge` and `auth` endpoints per source address
  like login attempts. A forged request costs an attacker nothing and the
  server at least one signature check. Not implemented in hxd-ng yet; the
  growth of every table an unauthenticated caller can touch is bounded
  independently, so the limiter is a refinement rather than a load-bearing
  part of the design.

---

## 13. Open questions

- **Transport token vs session token.** Reviewed and kept separate (§6.1):
  the token authenticates a socket before any application protocol has
  run, and the same token serves both WebSocket paths. If the ng JSON
  path ever wanted `resume` to double as first attach, that would be a
  session-layer change and could be made without touching this layer.
- **Other methods.** Review asked that the transport not foreclose
  standard mechanisms beside a raw key — OIDC, SAML, WebAuthn — and that
  it say what each would look like without requiring any implementation
  to support it. §3 and §6.5 are the answer; what remains open is which,
  if any, to define fully and implement, and that is a question for a
  deployment that needs one. Positions so far:
  - *OIDC* is the one worth doing first, when asked: operators will want
    SSO, and a relay in front of a legacy server gated by an identity
    provider is a compelling shape. There is a second route to SSO that
    touches nothing here: an OIDC-backed *registrar* that issues
    attestations after the provider's login, so the user keeps a key and
    the server trusts the registrar through the identity profile's
    existing knobs. Which route is wanted depends on whether SSO users
    should have a portable identity, and both can coexist.
  - *DPoP* (RFC 9449) is what §6.2 already is in shape — a server nonce,
    a proof signed by the key, bound to the server, a time window — in
    JOSE rather than CBOR, and bound to the request URL, which is
    fragile behind exactly the proxies §6.3 fights with. Its real value
    would be as the bridge that key-binds an OIDC token. Keep the CBOR
    proof; revisit if OIDC lands.
  - *WebAuthn* fits the challenge binding but yields no signing key, so
    it is a second factor or a device of some other principal, not a
    first; the registrar is where the threat model already puts it.
  - *SAML* fits and is not recommended; an OIDC broker covers it.
- **HOPE inside the tunnel.** Refusing it is simplest; allowing it is
  harmless but doubles encryption. Should the server advertise it as
  unsupported on the tunnel path so clients don't try?
- **User Flags bit 4 on 1.8/1.9.** §8's cleartext marker takes value 16
  in field 112 on the strength of "classic clients ignore unknown bits".
  If 1.8/1.9 already means "automatic response" by that value, the marker
  has to move to a bit nothing has claimed. Needs testing against a real
  client before any server turns marking on by default.
