# Hotline-ng transport authentication: design rationale

Status: companion to [hotline-ng-auth.md](hotline-ng-auth.md), which is
normative. This document is why that one says what it does, plus the
reverse-proxy recipes an operator needs to meet its contract. It binds
nobody. Where the two disagree, hotline-ng-auth.md is right and this
document is stale.

Section numbers here are this document's own. The spec cites them as
"rationale §n".

---

## 1. Why a separate transport layer

`hotline-ng-auth.md` was split out of `hotline-ng-identity.md` after
review. That document was trying to be both the transport's
authentication layer and the definition of a Hotline identity, and the
two have different owners and different lifetimes. The transport half
says how a connection acquires an authenticated principal and what the
transport may decide with it. It does not say what a principal *means*
— whether a key is a person, a device or an account — which is a
profile's business.

A principal is enough for what a transport can decide on its own:
admission and rate limits. Anything that terminates the HTTP handshake
can establish one, including a relay that only forwards bytes. What a
principal is not enough for is everything the application protocol says
about a session — roster marking, presence, which local account this
is — and those belong to a server that terminates the application
protocol, together with the profile.

## 2. Why HTTP and not the chat protocol

The ng transport is a WebSocket, which begins as an HTTP request, and
hxd-ng already assumes a TLS-terminating reverse proxy in front of it.
Doing authentication in that HTTP exchange means:

- the WebSocket session arrives already bound to a key, and the JSON
  protocol never carries credentials for authenticated sockets;
- a tunnel in front of a *legacy client* can authenticate upstream with
  the user's key using plain HTTP client code and then forward bytes,
  without knowing anything about TRTP;
- a relay in front of a *legacy server* (hxd 0.x, Mobius, HLServer) can
  establish who is on each socket and gatekeep accordingly, without that
  server changing and without the relay reading the tunneled protocol;
- mTLS becomes a first-class option rather than a special case, since it
  is an HTTP-layer mechanism already;
- a binding that is not a key at all (an identity-provider login, say)
  has somewhere to live that is neither the chat protocol nor the legacy
  wire.

The cost is that hxd-ng grows a small HTTP router on the ng listener,
which the ng MVP deferred "until media/history/push need one"
(`hotline-ng-rationale.md` §1). Authentication needed one. It is a
handful of routes, and hxd-ng uses hyper directly; media, history and
news attachments have since joined them.

## 3. The shape of a principal

`(method, id)`, with an optional key, is enough to name any
authenticated party this transport might one day admit, and nothing in
it requires the transport to understand what the party is.

**Policy keys on `(method, subject)`** so that a profile which groups
several keys under one person gets one decision for the person, and so
that an identifier from one issuer can never collide with the same
string from another. A ban list of bare fingerprints is a ban list of
`key` principals; the federation spec, which signs and exchanges such
lists, will have to carry the method with each entry or scope itself to
`key`, and say which.

**Bindings of one method are indistinguishable** because anything that
behaved differently for a key proved by challenge and the same key
presented in a certificate would be a second trust model hiding in the
first.

**A `key` principal must have a profile** because a bare key says
nothing about who holds it. For `key` the only profile is Hotline
identity, which requires a card and a device certificate; a server that
admitted a bare key would be running a profile no document defines. A
method that authenticates against a third party can define a default
profile — the party's display name and claims, nothing signed — so that
it needs no separate object scheme to be useful.

## 4. Tokens, not sessions

The transport token is deliberately not a session token. A session is an
application-layer object with a uid and a roster row, and the same
transport token authenticates a socket whether the protocol on it turns
out to be ng JSON or tunneled TRTP. Nothing application-level exists
until the application protocol's own login runs. Review asked whether the
two should merge; they were kept separate, and if the ng JSON path ever
wanted `resume` to double as first attach, that would be a session-layer
change that leaves this layer alone.

The token is the whole interface between a binding and the upgrade. The
upgrade never sees a proof, a key, a certificate or an assertion, and the
binding never sees a socket, which is what keeps the WebSocket paths, the
cleartext rules and the tunnel and relay roles independent of how any
binding works. The client-certificate form of the upgrade is the one
exception, and it is an optimization for the `key` method rather than a
second model: it works only because that method's proof *is* something
the TLS handshake can carry.

**The `?token=` form** exists because a browser's `WebSocket` API takes a
URL and a protocol list and nothing else. A single-use token with a
minute's life is what makes a value in a URL tolerable at all — but only
once it has been used. An upgrade that fails or is abandoned leaves the
token unredeemed and live, and common reverse-proxy defaults log query
strings, which is why the spec puts a logging requirement on the
deployment.

**Cookies are not used** because they would make every cross-site page a
potential initiator of an authenticated socket.

**An invalid token is a 401, never a downgrade**, so a client cannot end
up a guest because a token expired in flight. The same rule is why a
non-bearer `Authorization` header, a token presented to a server without
identity, and — on a server that offers the mTLS binding — a client
certificate that cannot be used are all refused rather than ignored: in
each case the caller believes it authenticated. A server without identity
offers no certificate binding, so a certificate header there asserts
nothing and is ignored.

## 5. The challenge binding

The proof echoes `server_key` so that a challenge relayed from another
server is useless. `challenge` is free for the caller and costs the
server a random draw, which is why it wants a rate limit and, until one
exists, a bounded table.

**`downstream` goes one way.** The server cannot verify what a client
says about the hop behind it, so it takes the claim at face value only in
the conservative direction: a client may make a session look less safe
than it is, never more. A tunnel that lies can only cost its own user a
warning they didn't need.

## 6. The mTLS binding and the proxy contract

**Why the key is read by position.** Everything ahead of the
SubjectPublicKeyInfo is chosen by whoever requested the certificate —
`serialNumber` is an arbitrary INTEGER and a `Name` attribute value is
`ANY` — so an implementation that *searches* the DER for RFC 8410's
algorithm identifier finds whatever bytes the subject planted there. A
certificate whose own SPKI is the attacker's key, which is what the
proxy's handshake validated, carrying a victim's key inside its subject,
would then be read as the victim.

**Why the proxy must set the header from its own handshake and drop the
client's copy.** Otherwise a client can send the header through the
proxy, carrying any key's public certificate, and impersonate that key.
An empty value means no certificate, not a broken one, because some
proxies send the header unconditionally.

**Why the rightmost untrusted element.** The stock directives append:
nginx's `$proxy_add_x_forwarded_for` and HAProxy's `option forwardfor`
add the peer they see to whatever the client already sent, so the left of
the list is client-supplied and only its right end was written by the
proxy. Reading the first element would let any client pick its own
address — a fresh one per connection to shed a ban or a per-address
limit, or someone else's to inherit their ban. Walking from the right and
stopping at the first element outside `trusted_proxies` is correct under
an appending proxy and under one that replaces the header outright.

**Why `trusted_proxies` must list proxies and nothing else.** The walk
skips every element it finds in that list, so a range that also contains
clients — a `10.0.0.0/8` on a network where clients live too — makes it
skip the proxy's own element and take the client's.

**Why one forwarded header, not both.** A proxy passes through what it
doesn't know about: nginx that sets `X-Forwarded-For` forwards a
client-supplied `Forwarded:` line untouched, so a server that read both
would read whichever one the *client* filled in.

**Why a request with `Origin` may not use a certificate.** A client
certificate is ambient in a browser — the TLS layer attaches it to
whatever a page fetches, including a hostile page's cross-origin
request — and these routes answer `Access-Control-Allow-Origin: *`. A
hostile page could POST to `auth`, ride a certificate it never saw, and
read the token back. Browsers set `Origin` on every request that could be
that attack; the native apps and tunnels the binding is for set it on
none. A browser entitled to log in still can, by signing a proof. A
WebSocket upgrade is not subject to CORS at all and would ride the
certificate just as well, which is why the upgrade has the same rule.

### 6.1 Proxy recipes

**Caddy** meets the whole contract in one directive, which replaces any
inbound value and sets nothing when there was no certificate:

```
header_up X-Hotline-Client-Cert {http.request.tls.client.certificate_der_base64}
```

**Stock nginx cannot.** `$ssl_client_escaped_cert` is URL-encoded PEM
and `$ssl_client_raw_cert` is PEM with real newlines; a header carries
neither, and nginx has no base64-DER variable and no string functions to
make one. A server that can't decode the header answers 400 rather than
falling through to an unauthenticated request, so the misconfiguration
is loud. With njs, one function does it:

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
empty value removes the header — both halves of the contract. Lua works
the same way. Without njs or Lua, use Caddy for the mTLS binding, or the
challenge binding, which needs no proxy cooperation at all. An operator
who lists a proxy in `trusted_proxies` is asserting that it is configured
this way; the server cannot check it.

## 7. Cleartext marking

The tunnel's local hop is cleartext by construction — the tunnel exists
because the classic client cannot speak TLS. On loopback that hop crosses
nothing; off loopback it crosses a network. The server cannot observe
which, so the tunnel declares it. With that hop on loopback, a tunnel is
the recommended way for a legacy client to get an encrypted session,
rather than HOPE transport encryption, and it also gets a principal.

**Why the legacy marker ships off.** The marker takes value 16 in User
Flags (112) on the strength of "classic clients ignore unknown bits".
Hotline 1.8/1.9 may already allocate that value as "automatic response",
in which case setting it makes every cleartext session look
auto-responding to those clients. Nothing in the tree the reference
implementation was written from confirms either reading, and betting on
the unverified one is what the never-break-old-clients rule forbids.

## 8. Tunnels and relays

Neither needs to parse the protocol it carries: everything the spec asks
of them is possible with an HTTP client library, a WebSocket library and
the profile's object library (`hl-identity` for Hotline identity). That
is not a confidentiality claim. Both handle the payload in the clear and
can read or alter it; what they are spared is understanding it. A tunnel
is stunnel with a key, and a relay earns its keep by gatekeeping in front
of a server that cannot.

A relay can offer the ng JSON path only by implementing the JSON protocol
itself against TRTP downstream, which is a full client implementation;
a relay that offers only the TRTP path is complete.

## 9. The HTTP routes

**CORS is a wildcard on purpose.** Every route is authenticated by a
token in a header, the body or the URL, and none by a cookie, so a hostile page has
no ambient credential to ride and an allow-list would protect nothing.
Without CORS a browser client can only talk to the server that served
it, which rules out both a client offering a choice of servers and a
device following an enrollment link to a mailbox somewhere else
(`identity-enrollment.md` §5.6). "No ambient credential" is a property
the routes have to keep, which is what the `Origin` rule of §6 is for.

**Hashed lookup needs no constant-time compare.** hxd-ng looks secrets up
in a map keyed by their SHA-256. What varies with the attacker's input is
the hash of their guess, and the timing of a lookup on it says nothing
about the secret. A store that compared secrets directly would need one.

**Bounded tables before rate limits.** A forged `auth` request costs an
attacker nothing and the server at least one signature check, and the
tables it fills — challenges, and the key-on-file cache of devices and
cards — are reachable by any fresh key under a permissive profile. hxd-ng
bounds each table and sheds at the bound, so the per-address limiter,
when it lands, is a refinement rather than a load-bearing part of the
design. The key-on-file cache is keyed by public key, not fingerprint,
because the key is what arrives in the certificate; bounding its count
bounds its memory only because the profile bounds its objects' sizes.

**TRTP over WebSocket in hxd-ng** is `hxd-session` driven by an adapter
that presents binary frames as `AsyncRead`/`AsyncWrite`, plus the
principal on the session, consulted at Login (107). The legacy frontend
otherwise doesn't know it isn't on TCP.

## 10. Other methods: positions

Review asked that the transport not foreclose standard mechanisms beside
a raw key, and that it say what each would look like without requiring
anyone to support it. The spec's §3 and §6.5 are the answer. Positions
on which to define fully, if asked:

- **OIDC** is the one worth doing first: operators will want SSO, and a
  relay in front of a legacy server gated by an identity provider is a
  compelling shape. There is a second route to SSO that touches nothing
  here: an OIDC-backed registrar that issues attestations after the
  provider's login, so the user keeps a key and the server trusts the
  registrar through the identity profile's existing knobs. That route
  exists (`identity-registrar.md` §5.3, `proof = oidc`). Which is wanted
  depends on whether SSO users should have a portable identity, and both
  can coexist.
- **DPoP** (RFC 9449) is what the challenge binding already is in shape —
  a server nonce, a proof signed by the key, bound to the server, a time
  window — in JOSE rather than CBOR, and bound to the request URL, which
  is fragile behind exactly the proxies §6 fights with. Its real value
  would be as the bridge that key-binds an OIDC token. Keep the CBOR
  proof; revisit if OIDC lands.
- **WebAuthn** fits the challenge binding but yields no signing key, so
  it is a second factor or a device of some other principal, not a
  first; the registrar is where the threat model already puts it.
- **SAML** fits and is not recommended; an OIDC broker covers it.
