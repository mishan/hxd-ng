# Hotline identity — portable identity, and the identity profile for hotline-ng

Status: draft, for discussion. Implemented in hxd-ng: the identity
objects (§3, `crates/hl-identity`, with test vectors in
`identity-test-vectors.json`), the profile's part of authentication (§5),
cards (§7), account association including `trtp_login` (§8), and the
`hlid` tool. Not yet: revocation, reserved-name enforcement, and
everything in the registrar and federation specs.

This revision splits the earlier single document in two, after review
pointed out that the transport's authentication and the definition of a
Hotline identity have different owners and can each be used without the
other. `hotline-ng-auth.md` is now the transport: discovery, the
challenge and mTLS bindings, transport tokens, the WebSocket paths, the
TRTP tunnel, cleartext marking, and the tunnel and relay roles. This
document is what a key *means* when Hotline identity is the profile in
use: the signed objects, how they are verified at authentication, what
the roster shows, cards, and account association. Section numbers for
the objects (§3), cards (§7), account association (§8), settings (§12)
and implementation notes (§13) are unchanged from the single document,
since code and other documents cite them.

Companion documents: `hotline-ng-auth.md` (the transport this profiles),
`identity-threat-model.md` (what this protects and from whom),
`hotline-ng.md` (the WebSocket protocol), and the registrar and
federation specs (handles, key storage, revocation, presence, vouches —
referenced but not defined here).

---

## 1. Summary

A user's identity is an Ed25519 keypair. Each device holds its own keypair,
certified by the identity key. A signed, versioned *user card* carries the
public profile and any registrar attestations.

None of that depends on a transport. The objects (§3) are what a client, a
registrar, a relay and a server all agree on, and `hl-identity` is the one
implementation of them.

What this document adds is the **identity profile** of the transport's
`key` principal (`hotline-ng-auth.md` §3): when a socket has proved it
holds a key, this profile says the key is a *device* of an *identity*,
requires the device certificate and card that establish that, sets the
principal's subject to the identity's fingerprint so every device of one
person is one subject, and derives a handle and an age from whatever
attestations the server trusts. It is enough, together with the
transport, for admission and for what other users see.

**Account association** — which local account, if any, this identity is —
is the second thing this document defines (§8). Only a server that
terminates the socket and implements the application protocol on it can
do this, because only it has the principal and the account table in one
place. hxd-ng does, for both application protocols it speaks over
WebSocket: the ng JSON protocol and TRTP in binary frames.

The legacy wire (TRTP on :5500) is not changed. A legacy client reaches a
linked account with the account's name and password, or through a local
tunnel that authenticates upstream with the user's device key and
forwards TRTP bytes over WebSocket — at which point the server knows who
it is and treats it like any other identity session.

---

## 2. Layering

The transport document defines the exchange; this document fills in the
profile's part of it. The hooks, in the order a connection meets them:

| Transport hook (`hotline-ng-auth.md`) | What this profile supplies |
|---|---|
| Discovery §5 | The rest of the `identity` block: `new_accounts`, `min_attestation_age`, `trusted_registrars`, and the `card`, `link`, `unlink` endpoints (§4) |
| The `auth` request §6.2, §6.3 | `card` and `device_cert`; optionally `login`, `password`, `create` (§5.1). The proof's `device` must be the certificate's `device` |
| Verification §6.2 | Steps 2–6 of §5.2, after the transport's proof check |
| The `auth` response §6.2 | `fingerprint`, `handle`, `age`, `outcome`, `account` (§5.3) and the profile's error codes |
| The principal §3 | `subject` = identity fingerprint; `profile` = the verified card, certificate and accepted attestations |
| Key on file §6.3 | What is cached per device and what is re-checked on a certificate-only upgrade (§5.5) |
| The ng login §7.2 | Credentials ignored; `self.identity`; the roster's `identity` sub-object; `caps` gains `"identity"` (§6.1) |
| The TRTP tunnel §7.3 | How the classic Login (107) inside is reconciled with the identity (§8.3) |
| Account association §9 | All of §8 |
| Tunnels and relays §10 | Device capabilities for a tunnel; what a relay's profile endpoints return (§10) |

Nothing else in the transport document changes for this profile, and
nothing here is needed to run the transport with a different one.

---

## 3. Identity objects

These are transport-independent and are defined here in full so this
document stands alone.

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

These are the same rules as `hotline-ng-auth.md` §4.1, which the login
proof follows; the two must not drift.

### 3.2 Fingerprint

`SHA-256(pubkey)`, 32 bytes. Displayed as lowercase Crockford base32, no
padding; may be shortened to 8 characters in UI. Servers store and compare
full fingerprints. Unqualified, "fingerprint" in this document means the
fingerprint of the *identity* key; a device has one too, and it is the
transport principal's `id`.

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

Defined by the transport, `hotline-ng-auth.md` §6.2 (domain
`hl-identity/login/v1`). Under this profile it is signed by the device
key, and its `device` must equal the device certificate's `device`
(§5.2). `hl-identity` implements it beside the objects above because a
client that makes one needs the other three.

### 3.7 Server key

Defined by the transport, `hotline-ng-auth.md` §4.3. This profile uses it
for nothing the transport does not; the federation spec signs ban lists
and vouches with it.

---

## 4. Discovery

Inside the `identity` block of `GET /.well-known/hotline`
(`hotline-ng-auth.md` §5), the profile's fields:

```jsonc
"identity": {
  // "enabled", "bindings", "association", and the "challenge" and "auth"
  // endpoints are the transport's
  "new_accounts": "guest",                // deny | guest | create (§8.1)
  "min_attestation_age": 0,               // seconds (§11)
  "trusted_registrars": [],               // hosts whose attestations are accepted;
                                          // empty accepts none — every identity is unattested
  "endpoints": {
    "card":   "/identity/card",           // §7
    "link":   "/identity/link",           // §8.2
    "unlink": "/identity/unlink"          // §8.4
  }
}
```

A relay (`association: "none"`) serves `card` and answers 404 on `link`
and `unlink` (§10).

---

## 5. Authentication

The transport's `auth` request (`hotline-ng-auth.md` §6.2 by challenge,
§6.3 by client certificate) proves a key. This section is what the same
request carries and what the server checks so that the key is a device
of an identity.

### 5.1 The request

```jsonc
{
  "proof":       "…",                    // transport: challenge binding only
  "downstream":  "local",                // transport
  "card":        "…base64url CBOR…",     // §3.4
  "device_cert": "…base64url CBOR…",     // §3.3
  "create":      false,                  // optional, see §5.3
  "login":       "alice",                // optional, see §5.4
  "password":    "…"
}
```

`card` and `device_cert` are required. A request without them is not a
request this profile can admit, and hxd-ng has no other profile, so it is
refused (`bad_cert`).

### 5.2 Verification

After the transport has verified the proof (its step 1), the server
continues in this order and fails on the first error:

2. `device_cert` signature with its `identity`; `device` matches the
   proof — or, on the mTLS binding, the client certificate's key; within
   validity; login capability set;
3. `card` signature; `identity` matches the certificate;
4. neither key revoked (cached revocation list; behaviour on a stale cache
   is a setting);
5. attestations verified against trusted registrars, expired or untrusted
   ones discarded, age computed from the oldest surviving `registered`;
6. admission policy (§11): allow list, minimum attestation age, unattested
   policy.

On success the principal's `subject` is the identity fingerprint and its
`profile` is the card, the certificate and the accepted attestations, all
as received.

### 5.3 The response

Success (200) adds to the transport's `token` and `expires_in`:

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

Failure with `{ "error": code, "text": "…" }`, in addition to the
transport's codes:

| code | status | |
|---|---|---|
| `bad_card`, `bad_cert`, `card_too_large` | 401 | prove it again |
| `login_failed` | 401 | the `login`/`password` of §5.4 didn't verify |
| `revoked`, `no_manage` | 403 | policy, or the device certificate lacks `manage` |
| `already_linked`, `would_orphan`, `not_linked` | 409 | conflicts with the account's state (§8.2, §8.4) |

`denied` (403) is the transport's code and is what admission policy (§11)
answers with.

`outcome` tells the client what account association will happen when an
application login runs on a socket carrying this token *and presents no
credentials of its own* (§8), so a guest downgrade can be shown as
information rather than discovered as a surprise.

That qualifier matters because the token is path-agnostic: the same token
admits an ng `login` and a tunnelled TRTP Login (107), and only the ng path
is fully decided at auth time. A tunnelled classic login under
`trtp_login = verify` (§8.3) carries a name and password that the `auth`
request never saw, so it can land on — and link — an account this
response could not have named. `outcome` is therefore a prediction, not a
commitment, and a client MUST take the association the application login
actually reports (the ng `self` event, or the classic Login reply) as
authoritative. A client that intends to send classic credentials later
should treat `guest` as "unless my credentials say otherwise" rather than
displaying it as settled.

### 5.4 Registering with a password

Either binding may add `"login"` and `"password"` to the `auth` request to
verify an existing classic account and, if permitted, link it in the same
step. See §8.2. For ng JSON sessions this is the only place a password
travels; it must never appear in a JSON frame for identity users. A
tunnelled TRTP session carries its classic login inside the tunnel as it
always has, encrypted by the WebSocket's TLS.

### 5.5 A device on file

The transport's "connection is the credential" path
(`hotline-ng-auth.md` §6.3, §7.1) admits a WebSocket upgrade that carries
a client certificate for a key already on file, without a token. Under
this profile, "on file" means the server has cached a card and a device
certificate for that device key from an earlier `auth` call, and the
upgrade is admitted for as long as the stored device certificate is
valid.

Re-admitting a device this way is a *read-only* admission. It re-checks
the signatures, honours an existing account link, and writes nothing —
no link, no account creation. Read-only is about *writes*, not about
policy: `new_accounts = deny`, the allow list and the attestation rules
(§11) are decided again on every admission. A device cached while its
account was linked must not keep being admitted as a guest after the
operator removes the link.

---

## 6. Sessions

### 6.1 The ng JSON protocol

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
(never `age` or `outcome`, which are the server's business), beside the
transport's required `transport` field (`hotline-ng-auth.md` §7.2, §8).
Clients that predate this ignore both.

The identity is copied to the session at login and is a property of the
session from then on: `resume` on a new socket keeps it.

### 6.2 Tunnelled TRTP sessions

Inside the tunnel (`hotline-ng-auth.md` §7.3) the client performs the
ordinary TRTP handshake and Login (107) with whatever classic credentials
it has. The server holds an identity for the socket as well; how it
reconciles the two is §8.3. Either way the session is identity-aware
from the server's point of view and indistinguishable from a native
identity session in the roster.

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
adopts this document natively. A relay or tunnel does none of it
(`hotline-ng-auth.md` §9, §10).

An account may carry one identity fingerprint; an identity may be linked
to one account per server. The link is what gives an identity user
permissions, a reserved name, and a place in the operator's existing
account tools.

### 8.1 Association at login

When an application login runs on a socket with an identity and names no
classic account (an ng `login` with no `login` param; a TRTP Login (107)
as guest):

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
the re-admission of a device already on file (§5.5) — and again when the
application login re-reads the link (§6.1), so a token minted while the
account was linked does not outlive it for the rest of its minute.
Removing a link locks that device out at its next connection rather than
at its certificate's expiry.

The `auth` response reports which of these will happen as `outcome`
(§5.3).

### 8.2 Linking an existing classic account

**Writing a link is account management, and every path that writes one
requires the device certificate's `manage` capability** — at auth, after
auth, and inside a tunnel (§8.3). A certificate without it can still log
in and use the server; it cannot bind an account to the key. Note what
this means for a tunnel that will self-link: §10's advice to carry only
the login and message bits is right for a tunnel used with an
already-linked account, and a tunnel that is expected to make the link
needs `manage` as well.

Three ways, all requiring the account to allow self-linking, to have a
password, and to have no link to a different identity:

- **At auth.** The `auth` request includes `login` and `password`. The
  server verifies the password as for a normal login. If the identity also
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
The server has an identity for the socket as well. How it reconciles the
two is the `[identity] trtp_login` setting:

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
  path an identity socket ignores credentials entirely (§6.1) — there is
  nowhere to put a password that the server will read — so an account
  with `identity_login = false` is reachable only from a socket with no
  identity. That is the intended shape (the account has said it does not
  want identity login), but a client has to know to open a plain socket
  for it.

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
and reserved name, and has no identity. Its card is whatever the
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

## 10. Tunnels and relays

The roles are the transport's (`hotline-ng-auth.md` §10). What this
profile adds to each:

**A tunnel** (legacy client → identity-aware server) holds one device
key and is a device like any other: it appears in the user's device list
as one. Its device certificate should carry only the login and message
bits, unless the user means to link an account through it — writing a
link needs `manage` on every path (§8.2), the tunnelled classic login
included, so a tunnel that will self-link needs that bit too and should
lose it once the link is made. It presents the identity's current card,
cached from wherever the user last set it; it does not synthesise cards.

**A relay** (identity-aware front for a legacy server) serves cards from
its own cache (§7) and applies this profile's admission policy (§11) at
the HTTP layer. It does not associate accounts: its `auth` endpoint
accepts no `login`/`password`; `/identity/link` and `/identity/unlink`
return 404; `outcome` is always `guest` in the sense of "the legacy
server decides". Clients connecting through the relay see identity
information only via the relay's own discovery and card endpoints.

---

## 11. Admission policy

The profile's policy is decided at step 6 of §5.2 and again on every
admission that follows — a certificate-only upgrade (§5.5) and the
application login that re-reads the account link (§8.1) — so nothing a
token or a cache remembers outlives the operator's current settings for
longer than a socket. Refusal is the transport's `denied`.

| Knob | Decides |
|---|---|
| `allow_list` | Non-empty: only these fingerprints or handles are admitted |
| `trusted_registrars` / `[identity.registrar_keys]` | Whose attestations count. Empty accepts none; there is no "empty means any" |
| `min_attestation_age` | The oldest accepted `registered` must be at least this many seconds ago |
| `unattested` | What an identity with no accepted attestation gets: `deny`, `guest`, `allow` |
| `new_accounts` | What an admitted identity with no linked account gets (§8.1) |
| `identity_login` (per account) | Whether the linked account accepts identity login at all (§8.1, §8.3) |

The defaults are arranged so that an attested identity is never treated
worse than an unattested one: `new_accounts = guest` beside
`unattested = guest`.

---

## 12. Settings

The table is what `hxd-ng` reads today; a row marked *(not implemented)*
is design, not configuration, and setting it is a startup error —
`[identity]` uses `deny_unknown_fields`. The transport's rows —
`[identity]` as the master switch, `key`, `clock_skew`, `trtp`, and the
`[ng]` proxy settings — are in `hotline-ng-auth.md` §11; they share the
section because hxd-ng has one profile and one switch.

| Setting | Default | Meaning |
|---|---|---|
| `[identity] new_accounts` | `guest` | `deny`, `guest`, `create`. The default is `guest` rather than `deny` so that, with `unattested = guest`, an attested identity is never treated worse than an unattested one |
| `[identity.default_access]` | guest access | Access bits for accounts `create` writes, keyed exactly as an account file's `[access]` table. The guest fallback is convenient but wrong for anything guests may not have — the messaging extension's `AccessMessaging`, for one — so operators using `create` should set it explicitly |
| `[identity] max_new_accounts_per_hour` | `60` | Ceiling on accounts `create` may write per hour; `0` turns creation off while leaving the rest of `create` in place. Past the ceiling, identities are still admitted, as guests. `create` writes a file per never-seen key, and with `unattested = guest` any fresh key qualifies |
| `[identity] allow_list` | empty | Fingerprints or handles; non-empty means identity login is restricted to these |
| `[identity] min_attestation_age` | `0` | Seconds |
| `[identity] unattested` | `guest` | `deny`, `guest`, `allow` |
| `[identity.registrar_keys]` | empty | Registrar host → base64url public key. **Empty accepts no attestation at all**, so every identity is unattested; there is no "empty means any". Static until the registrar spec's discovery fetch exists |
| `[identity] trtp_login` | `verify` | `verify` or `trust`; see §8.3 |
| `[identity] successors` | `identity-successors` | Where §3.4 successor commitments are kept, for the identities §13 says get one. `""` keeps them in the card cache only, which a restart forgets — and so does enough traffic to evict the card. Making the caches forget is the attack the commitment exists to stop |
| `[identity] revocation_max_age`, `revocation_stale` | — | *(not implemented)* §5.2 step 4 is stubbed; there is no registrar to fetch a list from yet |

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

- Verification (card, certificate, proof, attestation) is one function over
  decoded CBOR. Both bindings and the card endpoint call it.
- The cached card and device certificate are what make the mTLS
  "connection is the credential" path work (§5.5). hxd-ng keys them by
  device public key with the identity public key alongside. Both tables
  are bounded and evicted: they are filled by the `auth` endpoint, which
  any fresh key can reach when `unattested = guest`. Bounding the *count*
  only bounds the memory if the entries are bounded too — the cached
  bytes are a card (§3.4, 16 KiB) and a certificate (§3.3, 4 KiB), which
  is what those size limits are for.
- The successor commitment of §3.4 must outlive the process. A server that
  holds it only in memory hands an attacker "restart the server" as the
  way to move it, which is exactly the attack the commitment exists to
  stop. hxd-ng writes `[identity] successors`, one line per identity,
  appended and compacted at load rather than rewritten per insert.
- **Who gets anchored.** Only an identity with *standing* on this server:
  one with an account here (linked or created) or an attestation the
  server accepted. Anchoring every card that ever authenticated
  contradicts the bounded-growth rule above — with `unattested = guest`
  any fresh key can reach the `auth` endpoint, and each one would leave a
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
- The session carries the identity as part of its transport description
  (`hxd-core`'s `Transport`), consulted at the ng login and at the
  classic Login (107) inside a tunnel; the legacy frontend otherwise
  doesn't know which wire it is on.
- **Interaction with `CAPABILITY_MESSAGING`.** fogWraith's messaging
  extension keys everything on the account Login; a linked identity is an
  account, so the two compose without change. The seams — a durable key
  beside the Login, lookup by handle, an opaque envelope through the
  message path for E2E — are proposed as amendments to that extension in
  `docs/proposals/messaging-identity-amendment.md`.

---

## 14. Open questions

- **`trtp_login = trust` and legacy client UX.** A 1.5 client will still
  show a login box. Is "type anything" acceptable, or should tunnels
  advertise a fixed placeholder login the user is told to use?
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
- **Web device lifetimes.** §3.3 recommends 90 days for every device.
  A browser's device key is a non-extractable `CryptoKey` in IndexedDB,
  which page code cannot read but a copied profile directory can, so
  against the threat a certificate's lifetime actually bounds — a stolen
  machine logging in as you until expiry — it is the same container as
  a key file and the same number applies. hx-ng's plan
  (`hx-identity-keys.md` §7.2) reads it that way: 90 by default, with
  longer offered as the user's explicit choice, on the grounds that
  nothing here caps a lifetime and the spec already permits it. Does the
  spec agree, or does a web device deserve a carve-out in either
  direction — shorter because an XSS can mint tokens for as long as the
  page is open, or longer because four paste ceremonies a year is what
  will stop people using it?
- **SSO through a registrar.** The transport's open questions
  (`hotline-ng-auth.md` §13) weigh OIDC as a transport binding. The
  alternative that keeps users on keys is an OIDC-backed registrar that
  issues attestations after the IdP login; the server then trusts it
  through `[identity.registrar_keys]` and `min_attestation_age` with no
  transport change, and those users keep cards and E2E. It needs the
  registrar spec, and a client that generates a key without a ceremony —
  which the web client already does. Worth writing up once the registrar
  spec exists.
- **Multiple sessions per identity on one server.** `hotline-ng.md` §12
  already asks whether the roster should group same-user sessions. Identity
  gives it a reliable key to group on; this document doesn't require it.
