# Identity registrar — handles, revocation, rotation and key backup

Status: draft, unimplemented. This is the document `hotline-ng-identity.md`
calls "the registrar spec" and its §5.2 step 4, §8.5 and §12 wait on. It
is deliberately the smallest registrar that closes those gaps: a first
document that unblocks revocation and nothing more. The optional §9 is
the one place it goes past that, because it is what answers the identity
spec's open question about devices with no holder.

Companion documents: `hotline-ng-identity.md` (the objects, the profile,
and the verifier this document plugs into), `hotline-ng-auth.md` (the
transport and discovery), `identity-enrollment.md` (device certification;
a registrar hosts its mailbox unchanged), `identity-threat-model.md` (what
a registrar is trusted with). Presence records, vouches and signed ban
lists are the federation spec's and are not defined here; where the
threat model lists them under the registrar, this document says so and
leaves them.

Normative sections are §3 through §11. §12 onward is implementation,
threat-model deltas, the amendments this document needs in its
companions, and open questions.

---

## 1. Summary

A **registrar** is a server that lends an identity a name and a place
to be found. It issues the attestations the identity spec already
defines (§3.5 there), publishes signed records that say a key is
revoked, rotated or frozen, and optionally keeps an encrypted copy of
the identity key that it cannot open.

Everything a registrar publishes is verifiable from signatures alone,
and everything it issues is published: the log of §6.6 is what lets an
operator who has never met a registrar decide whether to trust it.
A server checking an identity needs the registrar's public key and an
HTTPS fetch; it needs no session at the registrar, no shared secret, and
no trust beyond the two the threat model already grants: *availability*
and *honest publication*. A registrar that lies can only withhold; the
records it publishes are signed by the user, and its own signature is
over the fact of publication.

A registrar is an identity-enabled server: it implements discovery and
the card endpoints of the companion documents, adds one discovery block
and four endpoints, and is otherwise ordinary. In hxd-ng it is a
feature of `hxd`, not a second binary.

---

## 2. What a registrar is trusted with

From `identity-threat-model.md`, restated as obligations:

| The registrar | Because |
|---|---|
| MUST issue an attestation only to a key that has proved it holds itself | An attestation is what other servers trust for age and name |
| MUST publish a user-signed revocation or rotation it has accepted, and MUST NOT alter one | Withholding is the residual risk the threat model accepts; forging is not |
| MUST refuse a rotation to a key other than one the identity committed to, when it holds a commitment | The commitment is only worth making if someone enforces it before any server has anchored it |
| MUST NOT be able to read a key envelope it stores | Confidentiality of the identity key never depends on the registrar |
| MAY freeze an identity and MAY revoke its own attestations | Availability is the registrar's lever, and the only one |

What a registrar sees: who registered, when, from where, with what
proof; every record posted; every envelope fetch attempt. What it cannot
do: sign as a user, move a name to a key the user did not sign for, or
decrypt an envelope.

---

## 3. Discovery

A registrar fills the `registrar` block of `GET /.well-known/hotline`
(`hotline-ng-auth.md` §5), which is `null` on a server that is not one:

```jsonc
"registrar": {
  "v": 1,
  "host": "hl.example",                  // the string attestations carry as `registrar`
  "key": "…base64url 32 bytes…",         // registrar signing key (§4.1)
  "retiring": [                          // optional: keys still valid for verification
    { "key": "…", "until": 1790000000 }
  ],
  "signup": "open",                      // open | proof | closed (§5.3)
  "proof": null,                         // what a registration's `proof` must be: invite | email | oidc | null
  "level": 0,                            // the `level` this registrar writes (§5.3)
  "attestation_days": 365,
  "handle": { "min": 3, "max": 32 },     // what this registrar issues (§5.1)
  "records_max_age": 3600,               // how long a fetched record list may be cached (§7.2)
  "endpoints": {
    "register":  "/registrar/register",  // §6.1
    "records":   "/registrar/records",   // §6.2
    "lookup":    "/registrar/lookup",    // §6.3
    "log":       "/registrar/log",       // §6.6: every attestation issued
    "stats":     "/registrar/stats",     // §6.6
    "envelopes": "/registrar/envelopes"  // §9; absent: no key backup here
  }
}
```

`host` MUST equal the hostname the document was fetched from, lowercase,
with no port. An attestation names its registrar by this string (§3.5 of
the identity spec, hostname syntax), and a verifier resolves it to a key
by fetching `https://<host>/.well-known/hotline` — so a registrar lives
on the HTTPS default port at the name it signs with. A deployment that
cannot do that (a test rig, a private network) is what
`[identity.registrar_keys]` is for: a static host-to-key entry is
consulted before discovery and is never refreshed.

**The registrar key is not the server key.** `server_key` signs
short-lived things (login proofs bind to it; the federation spec's ban
lists). The registrar key signs attestations that live a year and
records that live forever, so it rotates on its own schedule (§4.1) and
is kept apart. A server that is both publishes both.

The identity block's `enroll` endpoint (`identity-enrollment.md` §3) is
served by a registrar exactly as by any other identity-enabled server;
nothing there changes.

---

## 4. Objects

### 4.1 Encoding, signatures, keys

Every object here follows `hotline-ng-identity.md` §3.1: deterministic
CBOR, `sig` over `domain || 0x00 || bytes-without-sig`, `v = 1`, unknown
keys ignored on read and covered by the signature, timestamps in Unix
seconds. `hl-identity` is the one implementation.

One rule is added for objects with two signers. **`ack`** is a second
signature, by the second party, over the same bytes with both `sig` and
`ack` removed, under the object's domain with `/ack` appended:

```
sig = Ed25519.sign(first,  domain          || 0x00 || bytes_without_sig_and_ack)
ack = Ed25519.sign(second, domain || "/ack" || 0x00 || bytes_without_sig_and_ack)
```

Only the rotation record (§4.6) uses it.

**The registrar key** is an Ed25519 keypair generated on first start of
the registrar feature. To rotate it, a registrar publishes the new key
as `key` and the old one under `retiring` with an `until` at least
`attestation_days` in the future, and reissues attestations as they
come due. A verifier accepts a signature by a retiring key until its
`until`. Attestations and records carry `registrar_key` as a hint only,
as the identity spec already says; the published key is what counts.

### 4.2 Registration request

Domain `hl-identity/register/v1`, signed by the **identity key**. At most
2 KiB encoded. One object serves first registration and every reissue.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | Identity public key; the key that signs this |
| `registrar` | tstr | yes | The registrar's `host`. Binds the request to one registrar, so a request captured for one cannot be replayed at another |
| `handle` | tstr | yes | Requested local part, in the registrar's canonical form (§5.1) |
| `time` | uint | yes | Rejected outside the registrar's clock-skew tolerance |
| `successor` | bstr(32) | no | `SHA-256` of a pre-committed successor key, as in the card's `successor`. The registrar records it as the identity's commitment (§5.4) |
| `proof` | tstr | no | Signup material when `signup = proof`: an invite code, a token the registrar's own signup page issued, an OIDC id_token. Opaque to this document; ≤ 1 KiB |
| `sig` | bstr(64) | yes | |

Signing with the identity key rather than a device key is deliberate: a
name is an identity-level asset (threat model, assets 5), and a stolen
device must not be able to acquire or renew one. The identity key is
used "rarely"; once a year is rarely.

### 4.3 Attestation

Defined by `hotline-ng-identity.md` §3.5 and not restated. What this
document fixes is what the registrar writes into it:

- `registered` — the time of the identity's *first* successful
  registration of this handle, preserved across every reissue and across
  a rotation (§5.4). A recovery (§8.3) is the one place a registrar
  decides whether to preserve it.
- `issued` — now. `expires` — `issued + attestation_days × 86400`.
- `level` — the registrar's advertised level (§5.3), never higher for
  one identity than for another. A registrar with tiers publishes the
  lowest and issues that.
- `registrar_key` — the key that signed.

### 4.4 Device revocation

Domain `hl-identity/revoke-device/v1`. Signed by the identity key, **or**
by a device key whose certificate carries the `manage` bit. At most
6 KiB encoded (a certificate is 4 KiB).

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `device` | bstr(32) | yes | The device public key being revoked |
| `time` | uint | yes | |
| `until` | uint | yes | The `expires` of the latest certificate the signer knows for this device. A signer that does not know it writes `time + 2 years`. Publication stops after `until` (§4.9); the revocation itself is permanent |
| `reason` | uint | no | 0 unspecified, 1 lost, 2 stolen, 3 retired. Display only |
| `signer` | bstr(32) | no | Present when a device key signed: that device's public key |
| `signer_cert` | bstr | no | Required with `signer`: that device's certificate, so the record verifies with no other state. Its `identity` must equal this object's, its `device` must equal `signer`, it must carry `manage`, and `time` must fall within its validity |
| `sig` | bstr(64) | yes | |

A device may revoke itself; it may not revoke the identity. Web-client
certificates omit `manage` (identity spec §3.3), so a script in a browser
cannot revoke the user's other devices; a tunnel or a native client with
`manage` can, which is what "revokes the device from any other device"
in the threat model means.

### 4.5 Identity revocation

Domain `hl-identity/revoke-identity/v1`, signed by the identity key. At
most 512 bytes.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `time` | uint | yes | |
| `reason` | uint | no | 0 unspecified, 1 retired, 2 compromised |
| `sig` | bstr(64) | yes | |

Permanent and final: the key is dead and names no successor. A user
who has a successor rotates (§4.6) instead. A registrar that accepts one
releases the handle after the hold (§5.2), deletes the identity's
envelopes (§9), and keeps publishing the record.

### 4.6 Rotation

Domain `hl-identity/rotate/v1`. Signed by the predecessor (`sig`) and
acknowledged by the successor (`ack`), §4.1. At most 512 bytes.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | Predecessor public key |
| `successor` | bstr(32) | yes | Successor public key |
| `time` | uint | yes | |
| `sig` | bstr(64) | yes | By `identity` |
| `ack` | bstr(64) | yes | By `successor` |

Both signatures are required. The predecessor's says "I hand over"; the
successor's says "I accept", which is what stops a stolen key rotating
an identity onto a bystander's key to strand it. A rotation is therefore
possible only while the user still holds the old key — theft, not loss.
Loss is recovery (§8.3), which is weaker on purpose.

A rotation is one hop. The successor should commit its own `successor`
in its card, so the chain continues.

### 4.7 Freeze

Domain `hl-identity/freeze/v1`, signed by the **registrar key**. At most
512 bytes.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `registrar` | tstr | yes | |
| `frozen` | bool | yes | `true` freezes; `false` lifts |
| `time` | uint | yes | The latest `time` for an identity wins |
| `sig` | bstr(64) | yes | |

A freeze is the registrar's only unilateral act against a user, and it
is reversible. What it means to a verifying server is policy (§7.3);
what it means at the registrar is §8.1.

### 4.8 Attestation revocation

Domain `hl-identity/revoke-attestation/v1`, signed by the **registrar
key**. At most 512 bytes.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `registrar` | tstr | yes | |
| `handle` | tstr | yes | |
| `time` | uint | yes | Every attestation for this (identity, registrar, handle) with `issued ≤ time` is void |
| `reason` | uint | no | 0 unspecified, 1 recovered to another key, 2 rotated, 3 lapsed, 4 abuse |
| `sig` | bstr(64) | yes | |

A registrar revoking its own attestation makes the identity unattested
*at that registrar*; the identity's other attestations, if any, stand.
This is how a name moves on recovery or rotation, and how a registrar
withdraws its word from an abuser without touching the key.

### 4.9 Record list

Domain `hl-identity/records/v1`, signed by the registrar key. What the
`records` endpoint returns (§6.2).

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `registrar` | tstr | yes | |
| `issued` | uint | yes | |
| `expires` | uint | yes | `issued + records_max_age`. A cache serves it until then |
| `identity` | bstr(32) | no | Present on a per-identity list: every entry concerns this key |
| `since` | uint | no | Present on a delta: entries have `seq > since` |
| `more` | bool | no | `true` when the page was cut at the size bound; fetch again with `since` = the last `seq` |
| `entries` | array | yes | Each `[seq, record]`: a registrar-assigned `uint`, monotonic across the registrar, and the record's encoded bytes as `bstr` |
| `sig` | bstr(64) | yes | |

Records inside are the objects of §4.4–§4.8, each with its own
signature, which the reader verifies individually. The list's signature
says the registrar published these; the records' signatures say who
made them. **An empty per-identity list is a signed statement that the
registrar holds nothing against that key**, and is cacheable like any
other.

A page is at most 1 MiB. Entries leave the *full* list when they stop
mattering — a device revocation after its `until`, an attestation
revocation after the last attestation it voids would have expired — and
never leave a *per-identity* list, which is the one a verifier consults
for a key in front of it. Rotations, identity revocations and freezes
are never pruned from either.

---

## 5. Handles

### 5.1 Syntax and canonical form

The identity spec's attestation admits a wide local part (1–64 bytes,
no `@`, no whitespace, no control or invisible characters) so that
registrars can differ. A verifier accepts that form from any registrar.
This section is what *this* registrar profile issues, and it is
narrower:

- lowercase ASCII letters, digits, `.`, `_`, `-`;
- first character a letter or digit, last a letter or digit, no two
  punctuation characters in a row;
- `handle.min` to `handle.max` characters, defaults 3 and 32.

A registration request carries the handle in this form already. The
registrar compares handles case-insensitively for uniqueness — `Alice`
and `alice` are one name — and rejects a request whose `handle` is not
already canonical (`handle_invalid`) rather than folding it, so that
what the user signed is what is issued.

Non-ASCII handles are out of scope for v1. The confusable problem is
real and belongs to whichever registrar first wants them, with a
profile of its own.

### 5.2 Reservation and lifecycle

A registrar keeps a reserved list, and MUST reserve at least the names a
Hotline server gives its own meaning to — `guest`, `admin`, the system
account's login (`system-account.md` §2, whatever `[system] login` is
set to), and the account logins its own server holds — because `new_accounts = create`
names accounts from a handle's local part and the identity spec forbids
creating one under those names. The list is the registrar's; hxd-ng
ships a default (§11).

A handle moves through:

| State | Meaning | Leaves it by |
|---|---|---|
| **free** | nobody holds it | registration |
| **held** | attested to an identity; attestation unexpired | reissue keeps it here; expiry, revocation or rotation move it |
| **lapsed** | attestation expired without reissue, or attestation revoked | reissue by the same identity within `hold_days` returns it to *held* with `registered` preserved; the hold passing releases it |
| **released** | the hold passed | registration by anyone, with a fresh `registered` |

`hold_days` defaults to 365. A lapsed handle is held for the same
identity only: nobody else can take it during the hold, and the
identity that lost it can have it back with its age intact. An
identity revocation (§4.5) starts the hold at once; a rotation (§4.6)
does not lapse the handle at all — it moves (§5.4).

### 5.3 Signup policy and levels

`signup` in discovery is one of:

| | |
|---|---|
| `open` | any correctly signed request is granted, subject to §10's rate limits |
| `proof` | a request must carry `proof` of the kind `proof` names, and the registrar validates it however that kind requires |
| `closed` | no new registrations; reissues continue |

`proof` kinds are strings, and how a client obtains one is the
registrar's business, not this document's: `invite` is a code the
operator handed out; `email` is a token the registrar's own signup page
mailed; `oidc` is an id_token from the provider the registrar's page
names; `vouch` is a signed vouch from an identity attested here
(`identity-vouch.md` §5). A request that needs one and lacks it is answered
`proof_required` with a `text` and, when there is somewhere to go, a
`url`. This is the smallest hook that lets an OIDC-backed registrar
exist (`hotline-ng-auth.md` §13) without this document defining OIDC.

`level` is the number the attestation carries and what a server's
operator reads when deciding whom to trust and how long to keep their
users on probation (§7.5):

| `level` | The registrar attests that |
|---|---|
| 0 | a key asked and was rate-limited; nothing else |
| 1 | the key's holder controlled a contact address or an external account at signup |
| 2 | an existing member invited them, or signup cost something |
| 3 | an operator verified the person by some out-of-band means they publish |

A registrar publishes its `level` and writes exactly that. A registrar
whose practice changes publishes the new number and reissues under it as
attestations come due; it does not rewrite history.

### 5.4 Commitments and rotation at the registrar

A registration request's `successor`, and the `successor` of any card
the registrar caches for an attested identity, is recorded as that
identity's **commitment**: once recorded, immutable, exactly as the
identity spec's §3.4 rule for servers. A later request or card that
changes or drops it is refused (`successor_mismatch`).

A rotation record (§4.6) posted to the registrar is accepted when:

1. both signatures verify;
2. the identity is attested here and not frozen;
3. the registrar holds no commitment for it, or `SHA-256(successor)`
   equals the commitment;
4. no rotation for this identity has been accepted already.

On acceptance the registrar records the successor as holding every
handle the predecessor held, with each handle's `registered` preserved;
publishes the rotation under *both* fingerprints (§6.2); publishes a
§4.8 revocation (reason 2) of the predecessor's attestations; deletes
the predecessor's envelopes; and records the successor's card
`successor`, if any, as the next commitment. The successor obtains its
own attestations by sending an ordinary registration request for each
handle, which the registrar answers as a reissue.

**The registrar SHOULD delay publication** of an accepted rotation by
`rotation_delay` (default 24 hours when the registrar holds a contact
address for the identity, otherwise 0) and notify the identity through
that address, so that a rotation signed by a thief before the owner
noticed can be met with a freeze (§8.1) before any server acts on it.
During the delay the rotation is pending: a freeze cancels it, and a
second rotation is refused.

Step 3 is the sentence that makes the card's commitment worth
publishing before any server has anchored it. A thief with the identity
key can sign a rotation to their own key; a registrar that holds the
commitment will not publish it, and the threat model's "servers that
have never seen the user" gap is closed by the one party that has.

---

## 6. Endpoints

All under the registrar's advertised paths, on the ng listener, HTTPS.
Request and response bodies are JSON unless stated; signed objects
travel as base64url CBOR. Errors are `{ "error": code, "text": "…" }`
with the status in the table at §6.5. None of these endpoints takes a
transport token: every write is a signed object, and every read is
public.

### 6.1 `register`

`POST <register>` with `{ "request": "…" }`, a §4.2 object.

The registrar verifies the signature, `registrar` against its own host,
`time` against its skew tolerance, the handle's form (§5.1), and then
decides:

- the identity already holds this handle (*held* or *lapsed* within the
  hold): **reissue** — a new attestation with `registered` preserved;
- the handle is *free* or *released*: **registration** — `signup` and
  `proof` are consulted (§5.3), rate limits apply (§10), and on success
  `registered = now`;
- otherwise `handle_taken`, or `handle_held` when it is another
  identity's lapsed name, or `handle_reserved`.

Either way, a `successor` in the request is checked against the
recorded commitment (§5.4) before anything is written. A frozen identity
is answered `frozen`; a revoked or rotated one, `revoked`.

Response, 200:

```jsonc
{
  "attestation": "…base64url CBOR…",     // §4.3
  "handle": "alice@hl.example",
  "registered": 1725580800,
  "expires": 1788652800,
  "reissued": false
}
```

The client embeds the attestation in its card, re-signs the card, and
`PUT`s it to the registrar's card endpoint (identity spec §7) — and to
any other server it wants to show it to, or simply presents it at the
next `auth`. Nothing here writes the card for the client.

### 6.2 `records`

`GET <records>/<fingerprint>` — the per-identity list (§4.9 with
`identity` set): every unpruned record naming this key as `identity`,
`device`'s owner, predecessor **or successor** of a rotation. This is
the call a verifying server makes. `ETag` is the list's `issued`;
`Cache-Control: max-age` is `records_max_age`. An unknown fingerprint is
a 200 with no entries — signed, so that a cache can hold "nothing known"
as confidently as it holds a revocation.

`GET <records>?since=<seq>` — the full list as a delta, for a server
that would rather pull everything periodically than ask per identity.
Omit `since` for the whole thing from the beginning, paged by `more`.

`POST <records>` with `{ "record": "…" }` — a user posts a §4.4, §4.5 or
§4.6 record. The registrar verifies it as §7.1 says a server would (the
same function), checks that `identity` is attested here, applies §5.4
for a rotation, assigns a `seq`, stores it, and answers
`{ "seq": n, "published": true }` — or `"published": false` with
`"pending_until"` for a rotation inside its delay. A record already
held is answered with its existing `seq` and is not a failure, so a
client that lost the reply can post again. Registrar-signed records
(§4.7, §4.8) are never accepted here; they come from the registrar's own
tools.

Portable vouches and withdrawals (`identity-vouch.md` §4.1) are
accepted here too, from vouchers attested at this registrar, and are
indexed under both `voucher` and `subject` so the per-identity list for
a vouched key carries its vouches and their withdrawals; the voucher's
outstanding count is enforced on acceptance (`identity-vouch.md` §5).

A device revocation for a device the registrar has never seen is
accepted: the registrar cannot know every certificate an identity has
issued, and a revocation of an unknown device costs nothing but a row
until `until`.

### 6.3 `lookup`

`GET <lookup>/<handle>` — `{ "fingerprint": "…", "identity": "…base64url
pubkey…", "registered": n, "expires": n }` for a *held* handle; 404
otherwise, one code for free, lapsed, reserved and unknown alike, so a
lookup reveals less than a registration attempt already would.

`GET <lookup>?identity=<fingerprint>` — `{ "handles": [ "alice", … ] }`
for the handles this registrar attests to that key; an empty array for
a key it does not know.

Lookups are public. A handle is a name meant to be found, and the
messaging amendment's "find by handle" is a client of this. They are
rate-limited per address like every other unauthenticated read.

### 6.4 Cards

A registrar serves `GET /identity/card/<fingerprint>` and accepts `PUT
/identity/card` exactly as `hotline-ng-identity.md` §7 defines, for
every identity it attests to, and is the card's home of record: a
server or client that wants an identity's current card and has only a
handle does `lookup` then `card`. A `PUT` needs the transport's
authentication and a `manage`-capable device, as §7 there says, which
is why a registrar is an identity-enabled server and not a bare HTTP
service. The registrar anchors the card's `successor` as §5.4 says.

### 6.5 Errors

| code | status | |
|---|---|---|
| `bad_request` | 400 | malformed JSON or CBOR, missing field, wrong `registrar` |
| `bad_signature` | 401 | a signature did not verify, including `ack` |
| `bad_time` | 401 | `time` outside skew; a stale request is a replay |
| `handle_invalid`, `handle_reserved`, `handle_taken`, `handle_held` | 409 | §5.1, §5.2 |
| `proof_required`, `proof_invalid` | 403 | §5.3; the former carries `url` when there is one |
| `signup_closed` | 403 | |
| `frozen` | 403 | §8.1; reissue, records and envelopes all refuse |
| `revoked` | 403 | identity revoked or rotated away; the body names `successor` when there is one |
| `successor_mismatch` | 409 | §5.4 |
| `not_registered` | 404 | a record for an identity this registrar does not attest to |
| `not_found` | 404 | lookups; envelopes |
| `too_large` | 413 | the object's size bound |
| `rate_limited` | 429 | §10 |

### 6.6 Transparency: the issuance log and stats

An attestation's `registered` and `level` are asserted by the registrar
and verifiable by nobody. What makes trusting a registrar a decision an
operator can defend is being able to see what it does, so a registrar
publishes everything it issues.

`GET <log>?since=<seq>` — domain `hl-identity/log/v1`, signed by the
registrar key, the same shape as the record list (§4.9): `registrar`,
`issued`, `expires`, `since`, `more`, and `entries` of `[seq, bytes]`
where each `bytes` is an attestation the registrar issued, in issuance
order, **including reissues**. The log is append-only: an entry's `seq`
is assigned once, an attestation appears exactly once, and nothing is
ever removed. A registrar that has been running a year has a year of
attestations here, and an operator can count them. Nothing in an
attestation is private — every one of them ends up in a card that the
identity shows to servers — so the log discloses only *volume* and
*timing*, which is exactly what it is for.

`GET <stats>` — domain `hl-identity/stats/v1`, signed, ≤ 1 KiB:

| Key | Type | Notes |
|---|---|---|
| `v` | uint | `1` |
| `registrar` | tstr | |
| `at` | uint | |
| `identities` | uint | identities with at least one *held* handle |
| `issued_24h`, `issued_7d`, `issued_total` | uint | attestations issued, first registrations only |
| `revoked_total` | uint | §4.8 records the registrar has signed |
| `vouched_total`, `vouched_revoked` | uint | registrations whose `proof` was a vouch (`identity-vouch.md` §5), and how many of those the registrar has since revoked or been told were banned (§6.7). Zero and absent on a registrar with no `proof = vouch` |
| `frozen` | uint | identities currently frozen |
| `log_seq` | uint | the last `seq` in the log, so a reader can tell whether the log and the stats agree |
| `sig` | bstr(64) | |

Stats are recomputed at most hourly and cached. The numbers are the
registrar's own claim, but they are a claim the log can be checked
against by anyone who cares to page it, which is the point: a registrar
that minted ten thousand identities last Tuesday has either a log that
shows it or stats the log contradicts.

hxd-ng's server side does nothing with either endpoint automatically.
They are for the operator deciding what to put in `trusted_registrars`,
and for a `hxd registrar inspect <host>` tool that fetches both and
prints the shape of the last month.

### 6.7 Reports from servers (deferred)

A registrar that accepts `proof = vouch` is issuing attestations on its
vouchers' word, and today it learns nothing about how that word held
up: a voucher whose vouched keys are banned at every server they reach
is, to the registrar, a voucher under their outstanding count. The fix
is a **report**, and this document does not define it, because a report
is a server telling a registrar something and being believed, and
nothing in the design yet lets a registrar decide which servers to
believe. That is the federation spec's first problem — an authenticated
server-to-server message signed by `server_key` — and defining it here
would be defining it by accident.

What this document fixes is what a registrar may do with one when it
exists, so that the federation spec inherits a boundary rather than
drawing one:

- A report is accepted only from a server on the registrar's
  `reporting_servers` allowlist, and says: this identity, admitted here
  on a vouch by that voucher, was banned here, at this time.
- The registrar keeps it **private**. It is never a record, never in
  the per-identity list, never in the log.
- The registrar uses it for exactly one decision: whether to accept
  `proof = vouch` from that voucher, under a threshold of its own
  choosing (`vouch_reports`, default 2 distinct servers).
- The only thing published is the aggregate in `stats`:
  `vouched_revoked`.

The alternative — a signed penalty record other servers could read —
was considered and refused, for reasons `identity-vouch.md` §11 keeps:
it would carry a ban from a server nobody chose to trust into every
server that reads records, would need dispute handling, and would make a
month-long local consequence a permanent public one.

---

## 7. What a verifying server does

This section is the body of `hotline-ng-identity.md` §5.2 steps 4 and 5
and §8.5, which cite it. A server that implements the identity profile
and trusts at least one registrar does all of it; a server with
`trusted_registrars` empty does none of it and is unchanged.

### 7.1 Resolving a registrar

For an attestation whose `registrar` is trusted:

1. If `[identity.registrar_keys]` names the host, that key is the
   registrar's, and step 2 is skipped.
2. Otherwise fetch `https://<host>/.well-known/hotline`, cache the
   `registrar` block for 24 hours, and take `key` and `retiring`. A
   signature that fails against a cached key triggers one refresh
   before it fails for good, so a key rotation is not a day of
   refusals.
3. Verify the attestation against `key`, or against a `retiring` key
   whose `until` has not passed.

A server with no outbound network keeps working exactly as the identity
spec says: it accepts no attestations, every identity is unattested,
and none of the rest of this section runs.

### 7.2 Fetching records

For each registrar that attested the identity in front of it, the
server fetches `GET <records>/<identity fingerprint>` and caches the
signed list until its `expires`, or for `[identity] revocation_max_age`,
whichever is sooner. The fetch happens at `auth`, at a certificate-only
re-admission (identity spec §5.5), and at the application login that
re-reads the link — the same three points at which admission policy is
re-decided — and is served from cache within its lifetime.

When the registrar cannot be reached and the cache is past its
lifetime, `[identity] revocation_stale` decides:

| | |
|---|---|
| `cached` (default) | use the stale list; log it |
| `guest` | admit as an unattested guest would be admitted |
| `deny` | refuse with `denied` |

The default is the threat model's: "servers keep cached attestations
with a staleness limit rather than failing closed." An unattested
identity has no registrar to ask and is never stale.

### 7.3 Applying records

In `time` order, the records that name the identity or the presenting
device:

| Record | Effect at the server |
|---|---|
| identity revocation | refuse: `revoked` |
| rotation, this key the predecessor | refuse: `rotated`, body naming `successor`; and §7.4 |
| rotation, this key the successor | §7.4, then continue |
| freeze, latest `frozen = true` | `[identity] frozen`: `deny` (default) refuses with `denied`; `guest` admits as unattested |
| device revocation of the presenting device | refuse: `revoked`; drop the cached certificate and card for that device (§5.5 there) |
| attestation revocation | discard that attestation before computing age; if none survive, the identity is unattested |

Then age, from the oldest surviving `registered`, and admission policy,
exactly as before.

A server also keeps a **local revocation list**, `[identity]
revoked_devices` and `revoked_identities`, of fingerprints the operator
has refused by hand. It is consulted first and needs no registrar. It
exists so that an operator can lock out a stolen key *today*, on the one
server they run, whatever the registrar does or does not publish.

**Banning a registrar.** `[identity] banned_registrars` lists hosts
whose identities are refused outright, with `denied`, *before* the
unattested policy runs: an identity carrying any attestation from a
banned registrar is refused, not downgraded. Removing a registrar from
`trusted_registrars` makes its users unattested, which on a server with
`unattested = guest` still lets them in the door; banning it does not.
The legacy ban list's entry form gains `*@host` for the same thing, so
an admin can do it from a client without a config edit. A registrar ban
is a statement about the registrar, so it applies to the identity even
when it also carries an attestation from a trusted one — a user who
wants back in drops the attestation from their card.

**Admission cost on first sight.** A never-seen key with no accepted
attestation and no vouch (`identity-vouch.md`) is admitted per policy but
may not `chat`, `msg` or post news for `[identity] newcomer_delay`
seconds (default 120) from first admission, and every request in that
window answers `rate_limited` with a `retry_after`. The clock is per
fingerprint and durable for a day, so reconnecting does not reset it,
and it is exactly the connect-time delay IRC networks impose on new
connections: it makes a throwaway key cost two minutes of the attacker's
attention per key, which is enough to change the economics of "mint,
spam, discard" and nothing else. The delay is 0 for attested, vouched
and linked identities, and for guests on the legacy wire, whose cost is
already the lack of a stable name.

**Free keys never create accounts.** `new_accounts = create` applies to
an identity only when it is *attested by a trusted registrar* or
*vouched* (`identity-vouch.md`); an unattested identity is never more
than `unattested` says, whatever `new_accounts` is. This closes the
combination the identity spec's §12 warns about, where `create` beside
`unattested = guest` wrote an account — with `can_detach` and `inbox`
deriving true from the link — for every fresh key that reached the
`auth` endpoint. A server whose operator wants exactly that behaviour
sets `unattested = allow`, which is the setting that already means "an
unattested key is as good as an attested one", and `max_new_accounts_per_hour`
is then the only bound and is documented as such.

### 7.4 Rotation at the server

A server learns of a rotation from a registrar's records (§7.2, under
either fingerprint) or from the successor's `auth` request, which MAY
carry `"rotation": "…"` (the amendment of §14). It accepts a rotation
when both signatures verify **and** one of:

- the server holds a §3.4 anchor for the predecessor and
  `SHA-256(successor)` equals it; or
- the rotation came from a trusted registrar's signed record list.

A rotation from the `auth` request alone, for a predecessor the server
never anchored, is ignored — not refused; the successor is simply a new
key. With no anchor and no registrar there is nobody to say the old
owner consented, and a rotation is the one act that locks the old key
out permanently, so the server takes nobody's word for it.

On acceptance: the account link, bans, reserved name, block-list entries
and stored mail keyed on the predecessor's fingerprint move to the
successor; the predecessor's fingerprint is written to the same durable
file as anchors (`[identity] successors`) as *rotated to X*; the
predecessor's cached cards and certificates are dropped; both
fingerprints are logged. A later `auth` by the predecessor is refused
`rotated`. The successor's card `successor`, if present, is anchored as
the next commitment.

### 7.5 Standing and probation

Admission asks two questions that the identity spec's §11 asks with one
knob each, and this section separates them, because vouching
(`identity-vouch.md`) is what shows they were two.

**Standing** is who answers for the key, and it is a class, not a
number:

| Class | Meaning |
|---|---|
| `unknown` | a bare key; nobody |
| `vouched` | a member with standing here answers for it (`identity-vouch.md` §2) |
| `attested` | a trusted registrar names it |
| `linked` | this operator gave it an account |

`[identity.admission]` says what each class is admitted as — `deny`,
`guest` or `allow` — and replaces the single `unattested` knob, whose
value becomes `admission.unknown`. `new_accounts` applies to `vouched`
and `attested`; `newcomer_delay` (§7.3) applies to `unknown` only. A
key is admitted at its highest class.

**Age** is how long the key has been answered for: from `registered`
for an attested key, from the earliest live vouch for a vouched one,
from account creation for a linked one. It is the key's own, never
borrowed, and a vouched key's is honestly small.

**Record** is what this server has held against the key: upheld
reports, redactions, kicks, from the moderation audit table.

**Probation** is what a key admitted with standing may do while its
age is short and its record is clean, and it is where age belongs. It
replaces `min_attestation_age`, which gated the *door* on age and so
had to choose between keeping a vouched friend out for a month and
letting a stranger's key straight in:

```toml
[identity.probation]
until_age    = 2592000   # seconds of own age before full access; 0 disables
clean_record = true      # a moderation action against the key restarts the clock
access       = { send_msgs = false, send_media = false, voice_chat = false, post_news = false }
```

While on probation the session's resolved access is its account's
(or the guest set) *masked* by `probation.access`, using the same
named keys as an account file's `[access]` and `[extra]` tables
(`access-bits.md`); a key absent from the mask is unchanged. Probation
ends when own age reaches `until_age` and, with `clean_record`, no
moderation action against the fingerprint is younger than that. It
applies equally to a young attested key and a young vouched one, which
is the point: standing decided the door, and the room is decided by
what the key has done since.

`self.identity` in the ng login reply gains `"probation": { "until":
unix }` while it holds, so a client can say why the compose button is
grey rather than let the user discover it by refusal.

---

## 8. Freeze, theft and loss

These are procedures at the registrar. What a server does with the
resulting records is §7.

### 8.1 Freeze

An identity is frozen when its holder reports a compromise out of band
and the registrar operator is satisfied it is them — by the contact
address from signup, by the recovery code (§9.3), or by whatever the
registrar's `level` says it verifies. The operator's tool publishes a
§4.7 record with `frozen = true`.

While frozen the registrar refuses reissue, records and envelope fetches
for that identity (`frozen`) and cancels any pending rotation. A freeze
is lifted by a `frozen = false` record when the holder has rotated
(§8.2) or recovered (§8.3), or when the report turns out to be wrong.

Whether a registrar may freeze on its own initiative, for abuse, is the
threat model's open question and stays open: this document gives the
operator the record and says nothing about when to use it beyond a
holder's report.

### 8.2 Theft: the holder still has the key

The thief may already have signed things. The holder:

1. reports; the registrar freezes, which cancels a pending rotation
   the thief may have posted and stops the thief reissuing;
2. generates the successor key — the one whose hash they committed, if
   they committed one, since nothing else will be accepted where the
   commitment is held;
3. signs a rotation with the old key and acknowledges with the new;
4. the registrar verifies out of band that it is the holder posting,
   lifts the freeze, and accepts and publishes the rotation — without
   the delay, since the holder is on the line.

Every server that trusts the registrar moves the link at the next
admission. A server that anchored the commitment would have accepted
the rotation from the `auth` request alone; the registrar path is what
covers the rest.

### 8.3 Loss: the holder has no key

No rotation is possible; there is nothing to sign with. The holder
restores from an envelope (§9) if one exists, and this becomes §8.2
without the thief. Failing that, **recovery**: the registrar verifies
the person out of band, publishes a §4.8 revocation (reason 1) of the
handle's attestations to the old key, and accepts a registration
request for the same handle from the new key as a reissue.

Whether `registered` is preserved is the registrar's call, and it MUST
publish which. Preserving it keeps the person's standing at servers that
trust age; not preserving it means the new key is a stranger everywhere.
A registrar whose recovery verification is at least as strict as its
signup SHOULD preserve it. Either way, the threat model's sentence
stands: reserved names and account links on other servers do not
follow, because no rotation record exists to move them. The new key is
a new person to those servers until their operators link it by hand.

---

## 9. Key backup: envelopes

Optional. A registrar that offers it advertises `envelopes`; one that
does not omits the endpoint and all of this section. It exists for the
user with one device, which is most users: a phone that holds the
identity key has no holder anywhere else to renew it from
(`identity-enrollment.md` §12, `hotline-ng-identity.md` §14), and the
threat model's mitigations for loss are all some form of "a copy
somewhere."

### 9.1 The envelope

Domain `hl-identity/envelope/v1`, **unsigned** CBOR — its integrity is
the AEAD's. At most 1 KiB.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `kind` | uint | yes | 1 passphrase, 2 recovery code |
| `kdf` | map | yes | `{ "alg": "argon2id", "m": KiB, "t": iterations, "p": lanes, "salt": bstr(16) }` |
| `nonce` | bstr(24) | yes | |
| `ct` | bstr(48) | yes | XChaCha20-Poly1305 over the 32-byte identity seed |

Derivation, for a secret `S` (the passphrase's UTF-8 bytes NFC, or the
recovery code's 20 characters as ASCII):

```
okm      = Argon2id(S, salt, m, t, p, 64 bytes)
enc_key  = okm[0..32]
auth_key = okm[32..64]
ct       = XChaCha20-Poly1305.seal(enc_key, nonce,
             aad = "hl-identity/envelope/v1" || 0x00 || identity_pubkey,
             seed)
```

The associated data binds the envelope to one identity: a registrar
that served the wrong envelope, or an attacker who swapped one, gets an
authentication failure at the client rather than a wrong key that
"works". Minimum parameters a registrar accepts: `m ≥ 65536` (64 MiB),
`t ≥ 3`, `p ≥ 1`. A client should use more when the device allows.
`kdf` is in the clear so the registrar can enforce the floor and the
client can derive before it has anything else.

Two keys from one derivation: `enc_key` never leaves the client;
`auth_key` is what the client sends to fetch, and the registrar stores
`SHA-256(auth_key)`. Neither the passphrase nor `enc_key` is ever
derivable from what the registrar holds without the envelope *and* an
offline attack on the KDF, which is why the floor is what it is.

### 9.2 Put, fetch, delete

`PUT <envelopes>` with `{ "request": "…" }`, domain
`hl-identity/envelope-put/v1`, signed by the identity key, ≤ 2 KiB:

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `kind` | uint | yes | one envelope per kind per identity; a put replaces |
| `time` | uint | yes | |
| `auth_hash` | bstr(32) | no | `SHA-256(auth_key)`. Required with `envelope` |
| `envelope` | bstr | no | the §9.1 object. Absent: delete this kind |
| `sig` | bstr(64) | yes | |

Only an attested, unfrozen identity may put; the registrar answers
`{ "stored": true }` or `{ "deleted": true }`.

`POST <envelopes>/fetch` with `{ "handle": "alice", "kind": 1, "auth":
"…base64url auth_key…" }`. The registrar resolves the handle, hashes
`auth`, compares in constant time, and on a match returns
`{ "identity": "…base64url pubkey…", "envelope": "…" }`. **Every other
outcome is `not_found`**: no such handle, no envelope of that kind, wrong
key, frozen. One answer, so that the endpoint confirms nothing about a
handle to someone who does not hold its secret.

The fetch is the one place an unauthenticated caller can spend the
registrar's time on someone else's account, and it is rate-limited
accordingly (§10): per handle, hard, with a lockout that lengthens. A
locked-out handle answers `rate_limited`, which is the one exception to
"every other outcome is `not_found`", because the owner needs to know
why their own passphrase stopped working. The lockout is an availability
cost the owner pays for a name someone else is hammering; that is the
trade every password-recovery endpoint makes and this one does not
pretend otherwise.

On identity revocation or rotation the registrar deletes the identity's
envelopes (§4.5, §5.4).

### 9.3 Recovery code

An envelope of `kind = 2` is wrapped by a **recovery code**: 20
characters of Crockford base32 from the OS CSPRNG (100 bits), shown once
at creation as four groups of five, never stored by the client. The
same derivation applies; the KDF floor is the same so that one code path
serves both kinds.

The code covers loss (threat model): a user who has forgotten the
passphrase, or set none, types the code. It also serves the registrar
as the out-of-band proof for a freeze (§8.1): a client can present the
recovery envelope's `auth_key` to the operator's tool as "I hold the
code", without unwrapping anything, and the registrar checks it against
the stored hash exactly as a fetch does. A registrar that uses it that
way MUST accept it only once per freeze, MUST NOT accept it after the
envelope was replaced, and counts the attempt against §10's fetch limit
for that handle.

### 9.4 What this gives a device with no holder

A phone with the passphrase can fetch, unwrap the seed in a Worker or
its native equivalent, mint a device certificate for itself, and drop
the seed — hx-ng's phase C with the registrar as the copy. That is the
"renew-device flow that doesn't unwrap the identity key on the device"
the identity spec's §14 asked for, answered by unwrapping it briefly
rather than not at all, and it is why delegated certification (a device
certifying a device) is not in this document: it would widen what a
stolen device can do to gain what an envelope already gives, and it
needs a threat-model entry this document would rather not write.

---

## 10. Bounds and rate limits

Every table an unauthenticated caller can grow has a ceiling, and every
ceiling is a setting with a default.

| What | Default | Past it |
|---|---|---|
| Registrations per hour, per address | 5 | `rate_limited` |
| Registrations per hour, registrar-wide | 120 | `rate_limited`; reissues exempt |
| Record posts per hour, per identity | 20 | `rate_limited` |
| Device revocations kept per identity | 256 | oldest-`until` pruned from the full list; per-identity list keeps all |
| Envelope fetches per hour, per handle | 10 | `rate_limited`, then lockout doubling from 1 hour, capped at 24 |
| Envelope fetches per hour, per address | 30 | `rate_limited` |
| Lookups per minute, per address | 60 | `rate_limited` |
| Record-list page | 1 MiB | `more = true` |
| Envelopes per identity | 2 (one per kind) | a put replaces |
| Clock skew | 300 s | `bad_time` |
| Pending rotations | 1 per identity | second refused `bad_request` |

Signed requests are replay-checked by `time` and a seen-set of request
digests held for the skew window, as the transport does for proofs.

---

## 11. Settings

hxd-ng's `[registrar]` section. Its presence is the switch, and it
requires `[identity]`, which requires `[ng]`; without them it is a
startup error, as `[identity]` without `[ng]` is.

| Setting | Default | Meaning |
|---|---|---|
| `host` | *required* | The `host` of §3. Checked against the `Host` the discovery document is served under |
| `key` | `registrar.key` | Ed25519 seed file; generated on first run, mode 0600 |
| `retiring` | empty | `[{ key = "…", until = … }]` for §4.1 key rotation |
| `store` | `registrar.db` | SQLite file (§12) |
| `signup` | `proof` | `open`, `proof`, `closed`. The default is the one that does not make a fresh install a sybil factory |
| `proof` | `invite` | `invite`, `email`, `oidc`, `vouch`, or `none` with `signup = open` |
| `invites` | `registrar-invites` | For `proof = invite`: a file of codes, one per line, each consumed on use |
| `level` | `2` when `proof = invite`, else per §5.3 | Written into attestations; a startup error if it exceeds what `proof` supports |
| `attestation_days` | `365` | |
| `hold_days` | `365` | §5.2 |
| `handle_min`, `handle_max` | `3`, `32` | §5.1 |
| `reserved` | built-in list | Additional reserved local parts; the built-in list is `guest`, `admin`, `administrator`, `root`, `system`, `server`, `registrar`, `postmaster`, `abuse`, plus every account login on this server |
| `rotation_delay` | `86400` when a contact exists, else `0` | §5.4 |
| `records_max_age` | `3600` | §4.9 |
| `reporting_servers` | empty | §6.7; *(deferred)* servers whose vouch reports are believed, keyed by `server_key` |
| `vouch_reports` | `2` | §6.7; distinct reporting servers before `proof = vouch` is refused from a voucher |
| `envelopes` | `false` | §9 |
| `envelope_max` | `1024` | bytes |
| `rate.*` | §10's column | one key per row of §10 |

Additions to `[identity]`, replacing the two rows the identity spec
marks *(not implemented)*:

| Setting | Default | Meaning |
|---|---|---|
| `revocation_max_age` | `3600` | §7.2; the smaller of this and the list's own `expires` |
| `revocation_stale` | `cached` | `cached`, `guest`, `deny` (§7.2) |
| `frozen` | `deny` | `deny`, `guest` (§7.3) |
| `revoked_devices`, `revoked_identities` | empty | Fingerprints refused by hand (§7.3) |
| `banned_registrars` | empty | Hosts whose identities are refused outright (§7.3) |
| `newcomer_delay` | `120` | Seconds before a never-seen `unknown` key may chat, message or post (§7.3); `0` disables |
| `[identity.admission] unknown`, `vouched`, `attested` | `guest`, `allow`, `allow` | What each standing class is admitted as (§7.5). `unknown` replaces `unattested` |
| `[identity.probation] until_age` | `2592000` | Own age before full access (§7.5); replaces `min_attestation_age`, which gated the door |
| `[identity.probation] clean_record` | `true` | A moderation action restarts the clock |
| `[identity.probation] access` | the four in §7.5 | Access mask while on probation, `access-bits.md` key names |
| `registrar_keys` | empty | Unchanged in meaning; now an override consulted before discovery (§7.1) |

Registrar operator tools, in `hxd`:

```sh
hxd registrar freeze   <fingerprint> [--lift]
hxd registrar revoke   <handle> --reason abuse
hxd registrar recover  <handle> --identity <new fingerprint> [--keep-age]
hxd registrar invites  --add 10
hxd registrar inspect  <host>            # §6.6: fetch log and stats, print the last month
```

User tools, in `hlid`:

```sh
hlid register    --registrar hl.example --handle alice [--proof CODE] [--successor-commit]
hlid revoke      --device <fingerprint> [--reason stolen]
hlid revoke      --identity
hlid rotate      --to <successor key file>
hlid backup      --registrar hl.example [--recovery-code]
hlid restore     alice@hl.example
```

---

## 12. Storage and implementation notes

- **One store, SQLite**, behind a `RegistrarStore` trait in the shape of
  `hxd-store-sqlite`: `identity` (pubkey, fingerprint, commitment,
  frozen, revoked, rotated_to, contact, created), `handle` (canonical,
  identity, registered, state, lapsed_at), `attestation` (identity,
  handle, issued, expires, bytes), `record` (seq, kind, identity,
  other_identity, device, until, bytes), `envelope` (identity, kind,
  auth_hash, bytes, updated), `invite` (code_hash, used_by, used_at).
  `record.other_identity` is what makes the per-identity list find a
  rotation under the successor.
- **The verifier is one function**, in `hl-identity`, over the records
  of §4.4–§4.8: the registrar calls it on `POST records`, the server
  calls it on every list entry, and `hlid` calls it before posting. A
  record the registrar would accept is one every server would, by
  construction.
- **Per-identity lists are signed on demand and cached** for
  `records_max_age` keyed by fingerprint, so a burst of admissions for
  one identity costs one signature. The full list is signed per page.
- **Freeze, revoke and recover are transactions** with the record write:
  a freeze that is recorded but not published is the failure that
  matters most, so the row and the record are one commit.
- **The `manage`-signed device revocation** reuses the certificate
  verifier from `auth`; `signer_cert` is checked before `sig`, and the
  cheap fields before either, as the identity spec's §13 does for cards.
- **Nothing here needs the roster or the account table** except the
  reserved-name list, which reads account logins once at startup and
  on reload. The feature mounts under the ng listener beside the identity
  endpoints and can be built with the rest of the server off.
- **hlid** gains the codecs for §4.2 and §4.4–§4.6, the envelope codec
  and derivation (`argon2` and `chacha20poly1305` are the two new
  dependencies), and the commands of §11.

---

## 13. Threat model deltas

To fold into `identity-threat-model.md`:

- **Registrar operator, can:** see envelope fetch attempts and their
  source addresses; hold envelope ciphertext and mount an offline KDF
  attack on it, bounded by §9.1's floor and the user's passphrase; delay
  a rotation by `rotation_delay`. **Cannot:** publish a rotation to a
  key other than the committed one; unfreeze a record it did not sign
  (it signed all of them — the point is that a lift is as visible as a
  freeze).
- **New scenario, envelope brute force.** Attacker with the ciphertext
  (registrar breach or a malicious registrar) and no passphrase.
  Mitigation: Argon2id at the floor makes a weak passphrase expensive
  and a recovery code (100 bits) infeasible. Residual: a weak passphrase
  is a weak passphrase; clients should say so at creation.
- **New scenario, handle lockout.** Attacker who knows a handle
  hammers the fetch until it locks. Mitigation: the lockout caps at 24
  hours; the owner's other devices are unaffected; the recovery code
  path is a separate `kind` with its own counter. Residual: a day
  without restore-from-passphrase for a targeted user.
- **Stolen identity key, amended.** The registrar's refusal to publish
  a non-committed rotation and its delay-and-notify window are the
  mitigations that were previously listed as "registrar freeze" alone.
- **Malicious registrar, amended.** It can additionally serve a stale
  or empty per-identity list; a server's `revocation_stale` and the
  user's second attestation elsewhere are the answers, unchanged.

---

## 14. Amendments this document needs in its companions

Listed so that they are made deliberately and reviewed as such, not
inferred from this one.

`hotline-ng-identity.md`:

- §5.1: the `auth` request MAY carry `"rotation": "…base64url CBOR…"`, a
  §4.6 record whose `successor` is the certificate's `identity`.
  Handled per §7.4 here.
- §5.2 step 4 becomes: "records fetched per `identity-registrar.md` §7.2
  applied per §7.3; a stale cache is `revocation_stale`." Step 5 gains
  "after attestation revocations are applied."
- §5.3: two failure codes, `rotated` (403, body carries `successor`) and
  `frozen` (403).
- §8.5: replaced by a reference to §7.4 here; "carried in the card's
  attestations as a successor attestation" is withdrawn — the rotation
  is its own object and never rides in a card.
- §8.1 and §11: `new_accounts = create` never applies to an `unknown`
  identity (§7.3 here). The §12 sentence "with `unattested = guest` any
  fresh key qualifies" is withdrawn; `admission.unknown = allow` is the
  one setting under which a fresh key may create.
- §11 and §12: `unattested` becomes `[identity.admission] unknown` and
  `min_attestation_age` becomes `[identity.probation] until_age`, with
  the semantics of §7.5 here — age no longer gates admission, it gates
  full access. The old names are read as aliases for one release with a
  startup warning. §6.1: `self.identity.probation`.
- §12: the two *(not implemented)* rows replaced by §11's seven.
- §13: "Registrar keys… fetched from the registrar's
  `/.well-known/hotline`" gains the override order of §7.1.
- §14: the "device renewal without the identity key" and "SSO through a
  registrar" questions are answered by §9.4 and §5.3 respectively and
  can be closed with pointers.

`hotline-ng-auth.md` §5: the `registrar` block is §3 here.

`hotline-ng.md` §7 and the legacy ban list: the `*@host` entry form and
the `retry_after` on `rate_limited` during `newcomer_delay` (§7.3).

`identity-enrollment.md` §12: "Mobile without a desktop" is answered by
§9.4; the delegated-certification alternative is declined there.

`identity-threat-model.md`: §13 here.

`crates/hl-identity`: the `ack` rule (§4.1) in `signed.rs`; the seven
new codecs; the envelope derivation.

---

## 15. Test vectors

To be added to `identity-test-vectors.json`, generated by the same tool
as the existing ones, with the same identity, device and registrar keys
so that the objects chain:

- `register`: a first registration with `successor`, and a reissue.
- `revoke_device`: one signed by the identity key; one signed by a
  `manage` device with `signer_cert`; one that must fail because the
  signer's certificate lacks `manage`.
- `revoke_identity`.
- `rotate`: `sig` and `ack` both shown with their exact signature
  inputs, and a failing vector with `ack` by the wrong key.
- `freeze` and `revoke_attestation`, signed by the registrar key.
- `records`: a per-identity list holding the above, with `seq` values
  and the list signature input; an empty per-identity list.
- `envelope`: a `kind = 1` envelope with fixed salt and nonce, the
  passphrase in the clear, `enc_key`, `auth_key`, `auth_hash`, and the
  seed; a `kind = 2` envelope with its code.

---

## 16. Open questions

- **Self-service freeze.** A signed "freeze me" from the identity key
  is useless (the thief has the key too), but a *freeze code* — a second
  100-bit code, shown at registration, whose hash the registrar holds —
  would let a user freeze without an operator awake. It is SQRL's rescue
  code. Worth adding once there is a registrar with more than a few
  dozen users.
- **Should a freeze be enforced by servers at all**, or only by the
  registrar? §7.3 says servers refuse by default. The argument against:
  it hands the registrar a kill switch over every server the user is on,
  which the threat model's "servers moderate themselves" resists. The
  argument for: a frozen identity is, by the registrar's word, in the
  wrong hands right now. Kept as a per-server setting so operators can
  decide.
- **Multiple registrars per identity.** A card holds up to eight
  attestations; nothing here forbids registering at several. But the
  commitment is per registrar, and two registrars holding different
  commitments for one key would each refuse the other's rotation. The
  right rule is probably "the card's `successor` is the commitment, and
  a registrar records what the card says" — which this document does —
  and a registration request with a `successor` that disagrees with the
  card is refused. Needs a sentence in §5.4 once someone has tried it.
- **Registrar migration.** A user whose registrar is shutting down
  re-attests elsewhere and loses age. A registrar could sign a
  *transfer* record that another registrar honours as `registered`
  provenance. Left out; it is a federation-spec conversation.
- **Contact addresses.** §5.4's delay wants somewhere to notify. `proof
  = email` yields one; `invite` and `open` do not. Whether a registrar
  should be able to hold a contact the user gave voluntarily, and what
  it may do with it, is a privacy question the threat model does not
  answer yet.
- **Unicode handles**, deferred at §5.1.
