# Hotline-ng identity — HTTP-layer authentication and portable identity

Status: draft, for discussion. The identity objects (§3) are implemented in
`crates/hl-identity` with test vectors in `identity-test-vectors.json`;
nothing server-side is. Supersedes the earlier `Capabilities-Identity`
draft, which put authentication inside the legacy transaction protocol;
this version keeps TRTP unchanged and does authentication where the ng
transport already lives, in HTTP.

Companion documents: the identity threat model (what this protects and from
whom), `hotline-ng.md` (the WebSocket protocol this extends), and the
registrar and federation specs (handles, key storage, revocation, presence,
vouches — referenced but not defined here).

---

## 1. Summary

A user's identity is an Ed25519 keypair. Each device holds its own keypair,
certified by the identity key. A signed, versioned *user card* carries the
public profile and any registrar attestations.

None of that depends on a transport. What this document adds is:

- a small set of HTTP endpoints, served by the same listener that accepts
  the ng WebSocket, through which a client proves it holds a device key and
  registers its card and certificate with the server;
- two ways to do that proof — a challenge signed by the device key, or a TLS
  client certificate presented to the reverse proxy — that end in the same
  server state: *this connection belongs to device key D of identity I*;
- rules for how the server links that identity to an ordinary local account,
  so reserved names, permissions and bans keep working unchanged;
- what a relay in front of a legacy server, and a proxy in front of a legacy
  client, are expected to guarantee.

The legacy wire (TRTP on :5500) is not changed. A legacy client reaches a
linked account with the account's name and password, or through a proxy that
holds the user's device key and speaks ng upstream.

---

## 2. Why HTTP and not the chat protocol

Authentication is a transport concern. The ng transport is a WebSocket,
which begins as an HTTP request, and hxd-ng already assumes a TLS-terminating
reverse proxy in front of it. Doing authentication in that HTTP exchange
means:

- the WebSocket session arrives already bound to a key, and the JSON protocol
  never carries credentials for identity users;
- a proxy that fronts a *legacy client* can authenticate upstream with the
  user's key using plain HTTP client code, and then speak TRTP to the client
  exactly as a 1.9 server would;
- a relay that fronts a *legacy server* (hxd 0.x, Mobius, HLServer) can offer
  identity to ng clients by implementing these endpoints itself and mapping
  identities to accounts on the server behind it, without that server
  changing;
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
`v` higher than the reader knows is rejected.

Timestamps are Unix seconds, UTC. `bstr(n)` is a byte string of exactly `n`
bytes.

### 3.2 Fingerprint

`SHA-256(pubkey)`, 32 bytes. Displayed as lowercase Crockford base32, no
padding; may be shortened to 8 characters in UI. Servers store and compare
full fingerprints.

### 3.3 Device certificate

Domain `hl-identity/device-cert/v1`, signed by the identity key.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | Identity public key |
| `device` | bstr(32) | yes | Device Ed25519 public key |
| `device_enc` | bstr(32) | yes | Device X25519 public key (E2E messaging) |
| `issued` | uint | yes | |
| `expires` | uint | yes | Recommended 90 days; renew at one-third remaining |
| `caps` | uint | no | Absent = all. Bit 0 login, 1 message, 2 vouch, 3 manage |
| `name` | tstr | no | Human label, device lists only |
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
| `name` | tstr | yes | Display name, 1–32 chars after NFC |
| `icon` | uint | no | Legacy icon id |
| `profile` | tstr | no | ≤ 2048 bytes |
| `attestations` | array | no | Attestation objects, each fully signed |
| `vouches` | array | no | Federation spec; ignored by servers that don't implement it |
| `links` | array of tstr | no | URLs to display; servers never fetch them |
| `sig` | bstr(64) | yes | |

### 3.5 Attestation

Domain `hl-identity/attestation/v1`, signed by a registrar key.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `registrar` | tstr | yes | Registrar host, lowercase |
| `registrar_key` | bstr(32) | yes | Hint only; verifiers confirm against the registrar's published key |
| `handle` | tstr | yes | Local part; full handle is `handle@registrar` |
| `registered` | uint | yes | First registration; preserved across reissue; the value used for age |
| `issued` | uint | yes | |
| `expires` | uint | yes | Recommended one year |
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
  "ng": { "ws": "/ng" },                    // WebSocket path
  "identity": {
    "enabled": true,
    "bindings": [ "challenge", "mtls" ],    // which of §5 this server accepts
    "new_accounts": "guest",                // deny | guest | create
    "min_attestation_age": 0,
    "trusted_registrars": [],               // empty = any
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
so one discovery format serves servers, registrars, relays and proxies.
Clients cache it for the connection's lifetime; relays cache it per
upstream.

---

## 5. Authentication

### 5.1 Model

Authentication produces a short-lived *identity ticket*: an opaque bearer
token, 32 bytes base64url, valid for 60 seconds, bound server-side to a
device key, its identity, and the verified card and certificate. The client
presents the ticket when opening the WebSocket (§6). Tickets are single-use.

Two bindings produce a ticket. Servers advertise which they accept. The
server ends in the same state either way and the WebSocket protocol cannot
tell them apart.

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
  "proof":       "…base64url CBOR…"
}
```

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
  "ticket": "…",
  "expires_in": 60,
  "fingerprint": "…",
  "handle": "misha@hl.example",            // null if no accepted attestation
  "age": 31536000,                          // seconds; 0 if unattested
  "outcome": "linked"                       // linked | will_create | guest | unattested_guest
}
```

Failure (401 or 403) with `{ "error": code, "text": "…" }` where `code` is
one of `bad_card`, `bad_cert`, `bad_proof`, `revoked`, `denied`,
`card_too_large`, `unknown_challenge`.

`outcome` tells the client what will happen at WebSocket login before it
happens, so a guest downgrade can be shown as information rather than
discovered as a surprise.

### 5.3 mTLS binding

For clients that can present a TLS client certificate: native apps, proxies
and relays. Not browsers.

The client certificate is a self-signed X.509 certificate whose
SubjectPublicKeyInfo is the device's Ed25519 public key (RFC 8410). Nothing
else in the certificate is examined; validity dates, subject and extensions
are ignored, since the device certificate (§3.3) is the authority on all of
that.

hxd-ng does not terminate TLS. The reverse proxy requests (but must not
require) a client certificate and forwards it on the upstream request as
`X-Hotline-Client-Cert` (base64 DER). The server honours that header only
from addresses listed in `[ng] trusted_proxies`; from anywhere else it is
stripped. Operators who terminate TLS in the server itself in some future
build get the same header semantics from the in-process listener.

With a client certificate on the connection, `POST /identity/auth` omits
`proof`:

```jsonc
{ "card": "…", "device_cert": "…" }
```

The server checks that the certificate's public key equals `device_cert.device`
and continues from step 2 above. Response and failure codes are the same.

Once a device has a card and certificate on file, a WebSocket upgrade that
carries a client certificate for that device key is authenticated without a
ticket (§6), for as long as the stored device certificate is valid. This is
the "the connection is the credential" path mTLS users expect; the
`/identity/auth` call is needed once per device, and again when the card or
certificate changes.

### 5.4 Registering with a password

Either binding may add `"login"` and `"password"` to `/identity/auth` to
log into an existing classic account and, if permitted, link it in the same
step. See §8. Over the challenge binding this is the only place a password
travels; it must never appear in a WebSocket frame for identity users.

---

## 6. Opening the WebSocket

The ng WebSocket path is advertised in discovery. An upgrade request is
authenticated by one of:

- `Authorization: Bearer <ticket>` — native clients, proxies, relays;
- `Sec-WebSocket-Protocol: hotline-ng, hl-identity.<ticket>` — browsers,
  whose WebSocket API cannot set headers. The server selects `hotline-ng` in
  its response and consumes the second entry;
- a client certificate on the connection for a device key on file (§5.3).

An upgrade with none of these is an unauthenticated ng connection and
proceeds exactly as `hotline-ng.md` §6 describes: the first frame must be
`login` or `resume`, with account name and password or as guest. Nothing
about the existing handshake changes for clients that don't use identity.

An upgrade with an invalid or expired ticket is refused with HTTP 401. It is
not downgraded to unauthenticated, so a client cannot silently end up as a
guest because a ticket expired in flight.

On an authenticated upgrade, the first frame is still `login`, but its
`login` and `password` params are ignored (and should be omitted). The
server resolves the account from the identity per §8 and replies as usual,
with three additions to the `ok` object:

```jsonc
"self": { "uid": 3, "nick": "Misha", "icon": 128, "admin": false,
          "status": "active",
          "identity": { "fingerprint": "…", "handle": "misha@hl.example",
                        "age": 31536000, "outcome": "linked" } },
"caps": [ "identity", … ]
```

and each `user` object in the roster and in `user_joined` / `user_changed`
gains an optional `identity` sub-object with `fingerprint` and `handle`
(never `age` or `outcome`, which are the server's business), and a required
`transport` field: `"encrypted"` or `"cleartext"` (§10). Clients that
predate this ignore both.

`resume` is unaffected: the session token already proves continuity, and the
identity binding is a property of the session, not the connection.

---

## 7. Cards

`GET /identity/card/<fingerprint>` — public, no authentication. Returns the
server's cached card for that identity as `application/cbor`, exactly the
bytes received, so the signature verifies; 404 if none. Cacheable; the
server sets `ETag` to the card's `updated` value. Relays, proxies, other
servers and registrars all use this.

`PUT /identity/card` — authenticated by ticket or client certificate; the
device certificate must carry the manage bit. Body is the new card as
`application/cbor`. Verified as in §5.2 step 3; the `updated` monotonicity
rule applies. On acceptance the server emits `user_changed` for that user's
sessions and, on the legacy wire, Notify Change User (301) if the name or
icon changed.

Cards are per identity, not per session or per wire. A card set over ng is
what a proxy for a legacy client will fetch.

---

## 8. Accounts

### 8.1 Linking on first login

An account may carry one identity fingerprint; an identity may be linked to
one account per server. When an authenticated upgrade completes `login`:

- if an account links this fingerprint, the session is that account, with
  its access bitmap and everything else; if the account has been marked
  `identity_login = false` by the operator, the login fails with `denied`;
- otherwise the server's `new_accounts` policy applies: `deny` refuses the
  login; `guest` gives a guest session that nonetheless knows its identity
  (for reserved-name enforcement and for linking later); `create` makes an
  account named from the handle's local part (numeric suffix on collision)
  or the short fingerprint, with the server's default identity access,
  no password, and the link set.

`/identity/auth` reports which of these will happen as `outcome`.

### 8.2 Linking an existing account

Two ways, both requiring the account to allow self-linking and to have no
link to a different identity:

- **At auth.** `/identity/auth` includes `login` and `password`. The server
  verifies the password as it would for a normal login. If the identity also
  verifies and the account is linkable, the link is made and `outcome` is
  `linked`. If not linkable, the ticket is still issued and the session logs
  into the account by password with `outcome` `classic_pending_link`.
- **After auth.** `POST /identity/link` with `{ "login", "password" }` (or
  no body, to link the account the ticket is currently logged into on
  another connection — see below). Requires the manage bit. On success a
  guest session that belongs to this identity is upgraded in place: the
  server sends `user_changed` for it with the new nick and admin flag and a
  `self` refresh event carrying the new access. Servers that don't want to
  support in-place upgrade may reply `{ "reconnect": true }` after recording
  the link; the client reconnects and lands on the account.

Linking an identity to a second account on the same server is refused with
`already_linked`.

### 8.3 Unlinking

`POST /identity/unlink`, authenticated with the manage bit, or by the
operator through account administration. Refused with `would_orphan` if the
account has no password, until one is set.

### 8.4 Rotation

When a rotation record from the registrar spec is verified — either carried
in the card's attestations as a successor attestation, or picked up during
revocation refresh — a server holding the predecessor fingerprint moves the
link to the successor, logs both, and keeps bans and reserved names with the
account.

### 8.5 Legacy clients on linked accounts

A legacy client logs into a linked account with the account's name and
password exactly as before, gets the same permissions and reserved name, and
has no device key. Its card is whatever the identity last set. Nothing in
TRTP changes.

---

## 9. Reserved names

A reserved name is a display name only one account may wear on a server.
It is a property of the account: the operator sets `reserve_name = true` and
the reserved string is the account's login name. This is unchanged from
current practice; the identity layer only adds enforcement for sessions the
server can recognise.

When any session tries to set a display name reserved by another account,
the server refuses it. On ng, `nick` replies `error: name_reserved`. On the
legacy wire, where Set Client User Info (304) has no reply, the server
substitutes a discriminated name (`misha~7f3a` for an identity-bearing
session via a proxy, `misha (2)` for a plain classic one) and announces the
correction in Notify Change User (301). Legacy behaviour for classic sessions
is therefore "the name gets a suffix," which some servers already do.

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
  16) of User Flags (112) for cleartext sessions; classic clients ignore
  unknown flag bits, and clients that know it render a marker. This is the
  one TRTP-visible change and a server may omit it.
- **Cleartext policy.** A three-position setting: `off` (legacy port
  refuses sessions that don't negotiate HOPE transport encryption, or is
  behind a TLS wrapper), `restricted` (cleartext sessions have their access
  ANDed with an operator mask whose recommended default allows public chat
  and news reading only), `on` (legacy behaviour, with a warning in
  operator tooling).

An ng client must warn before sending a private message to a `cleartext`
session.

---

## 11. Proxies and relays

Both are ordinary ng clients from the server's point of view. This section
says what each must guarantee so that a server, a registrar and a user can
rely on them.

### 11.1 Proxy: legacy client → ng server

Runs on the user's machine (or somewhere they trust), holds one device key,
speaks TRTP to the classic client on localhost and ng upstream.

- It authenticates upstream with its own device key by either binding. Its
  device certificate should carry only the login and message bits; it is a
  device like any other and appears in the user's device list as one.
- It presents the identity's current card, fetched from the registrar or
  cached from the client's last ng session; it does not synthesise cards.
- It maps the classic client's login/password to *nothing*: the upstream
  account is whatever the identity is linked to. It may accept any
  login/password from the local client, or none.
- It performs the reserved-name substitution and transport marking on
  behalf of the server, since the server's legacy wire isn't involved.
- It must not decrypt E2E PMs for a cleartext local client without the
  user having explicitly enabled that, and must mark the local hop as
  cleartext if it is one.

### 11.2 Relay: ng client → legacy server

Runs in front of a server that speaks only TRTP (hxd 0.x, Mobius,
HLServer), implements discovery, the identity endpoints and the ng
WebSocket, and speaks TRTP downstream.

- It holds its own server key and is, for identity purposes, the server.
  The federation spec treats its signatures as the operator's.
- It maintains the fingerprint → (login, password) mapping for the legacy
  server, either as an operator-managed table or by creating accounts
  through the legacy server's administration transactions when
  `new_accounts = create`. That mapping is the relay's account file and is
  protected accordingly.
- It cannot enforce reserved names for legacy sessions that connect to the
  legacy server directly, and should say so in discovery
  (`"identity": { "enforcement": "relay-only" }`) so users know the
  guarantee is partial.
- Cards are served from the relay's cache; the legacy server never sees
  them.

### 11.3 What the server guarantees them

Discovery is stable, cards are byte-exact, tickets and challenges are
single-use, and the mTLS header contract is honoured only from trusted
proxies. A relay or proxy that follows this section is indistinguishable
from a native ng client to the server and to other users.

---

## 12. Settings

| Setting | Default | Meaning |
|---|---|---|
| `[identity] enabled` | `false` | Master switch; when off, discovery reports `enabled: false` and the endpoints return 404 |
| `[identity] bindings` | `["challenge"]` | Which of §5 to accept |
| `[identity] new_accounts` | `deny` | `deny`, `guest`, `create` |
| `[identity] default_access` | guest access | Access bitmap for created accounts |
| `[identity] allow_list` | empty | Fingerprints or handles; non-empty means identity login is restricted to these |
| `[identity] min_attestation_age` | `0` | Seconds |
| `[identity] unattested` | `guest` | `deny`, `guest`, `allow` |
| `[identity] trusted_registrars` | empty | Empty = any |
| `[identity] revocation_max_age` | `86400` | Seconds before the cache must refresh |
| `[identity] revocation_stale` | `allow` | `allow` or `guest` |
| `[identity] clock_skew` | `300` | Seconds |
| `[ng] trusted_proxies` | empty | Addresses whose `X-Hotline-Client-Cert` header is believed |
| `[legacy] cleartext` | `on` | `off`, `restricted`, `on` |
| `[legacy] cleartext_mask` | chat + news | Access mask for `restricted` |

Account records gain `identity_fingerprint` (optional, 32 bytes),
`identity_login` (bool, default true), `allow_self_link` (bool) and
`reserve_name` (bool). Existing account files without these are valid.

---

## 13. Implementation notes

- The ng listener needs to route a few HTTP paths before the upgrade. Any
  minimal HTTP layer over the existing `tokio-tungstenite` accept works;
  this is the point at which `hotline-ng.md`'s "no HTTP framework yet"
  decision expires, and it should be revisited with media and history in
  mind rather than solved just for identity.
- Verification (card, certificate, proof, attestation) is one function over
  decoded CBOR. Both bindings and the card endpoint call it.
- Tickets, challenges and session tokens share the same storage discipline
  as `hotline-ng.md` §9: CSPRNG, stored hashed, constant-time compare,
  never logged.
- The cached card and device certificate per device key are what make the
  mTLS "connection is the credential" path work; keep them keyed by device
  fingerprint, with the identity fingerprint alongside.
- Registrar keys for attestation checks are fetched from the registrar's
  `/.well-known/hotline` over HTTPS and cached with a long lifetime. A
  server with no outbound network still runs identity; it just accepts no
  attestations.
- Rate limits: `/identity/challenge` and `/identity/auth` per source address
  like login attempts. A forged card costs an attacker nothing and the
  server two signature checks.

---

## 14. Open questions

- **Ticket in the subprotocol.** The browser path puts a bearer token in
  `Sec-WebSocket-Protocol`, which appears in proxy logs more readily than an
  `Authorization` header. A cookie set by `/identity/auth` is the
  alternative and brings its own CSRF and same-site questions. Which is the
  lesser evil for the web client?
- **HOPE-encrypted legacy sessions.** Under this design they get no identity
  without a proxy. Is a TRTP-side binding worth defining later as an
  hxd-ng-local extension, or is "use a proxy or wss" the answer?
- **Relay account mapping.** §11.2 leaves how a relay provisions accounts on
  the legacy server to the relay. Should the spec define a minimum (e.g.
  "must support an operator-managed table") so relays are interchangeable?
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
- **Multiple sessions per identity on one server.** `hotline-ng.md` §12
  already asks whether the roster should group same-user sessions. Identity
  gives it a reliable key to group on; this document doesn't require it.
