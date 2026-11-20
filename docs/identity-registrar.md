# Identity registrar — handles, revocation, rotation and key backup

Status: draft; the registrar is built, and so is the verifying server but for §7.5.
hxd-ng is a registrar when `[registrar]` is configured (§11): discovery
(§3), the objects of §4 in `hl-identity` with their test vectors (§15),
handles and their lifecycle (§5, with `signup = open`, `proof` by invite,
or `closed`), every endpoint of §6, key backup's envelopes (§9), the
operator's freeze, revocation and recovery (§8), the ceilings of §10,
and `hlid register`, `revoke`, `rotate`, `backup` and `restore`. The server-local revocation list of
§7.3 — `[identity] revoked_identities` and `revoked_devices`, written by
`hxd identity revoke` and re-read on SIGHUP — is built too, because it
needs no registrar, and so is a server fetching and applying a
registrar's records, rotations included (`identity-records.md` R1–R3).
Not built: standing and probation (§7.5); `proof` by `email`, `oidc` or `vouch`, and vouches
in the record lists; and reports (§6.7, deferred by design). This is the
document `hotline-ng-identity.md`
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
with no port. A server that is a registrar withholds the block — sends
`null` — when the document is asked for under any other name, so a
verifier can never find the key under a host that did not publish it. An attestation names its registrar by this string (§3.5 of
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

A device-signed revocation is also judged by its signer's device epoch
(§4.10): one whose `signer_cert` has an `epoch` below the floor its
reader holds for the identity is void, whatever its `time`. The window
check above is against a `time` the signer chose, so without this a
device reset with the others could sign a revocation dated inside its
old certificate's window, and revoke each device enrolled after the
reset, one at a time. The registrar refuses one at acceptance (§6.2),
and a server ignores one in a list it applies (§7.3), each against the
floor it holds then. One a server applied before it knew the floor is
judged again when the floor rises, and dropped if its signer is below
it. The cost is that a device a reset device revoked stays out only
through its own certificates being below the floor too, and a holder
refusing to certify a key it knows was reset (`identity-enrollment.md`
§8). A revocation the identity key signed is never affected, so one
meant to outlast a later reset is signed with the identity key.
`hl-identity`'s `DeviceRevocation::check_signer_floor` is the check,
refusing `BelowFloor`, and `signer_epoch` reads the signer's epoch
(`None` for the identity's own). `Record::parse` holds no floor, since a
list is parsed before its identity's floor is known: the caller checks
each device-signed revocation before applying it.

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
envelopes (§9), and keeps publishing the record. One posted while a
rotation is pending cancels the rotation (§4.6).

### 4.6 Rotation

Domain `hl-identity/rotate/v1`. Signed by the predecessor (`sig`) and
acknowledged by the successor (`ack`), §4.1. At most 512 bytes.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | Predecessor public key |
| `successor` | bstr(32) | yes | Successor public key |
| `time` | uint | yes | |
| `next` | bstr(32) | no | `SHA-256` of the successor's own successor key: the commitment the successor takes as it holds the identity (§5.4). Never the predecessor's or the successor's own fingerprint, refused `bad_request` |
| `sig` | bstr(64) | yes | By `identity` |
| `ack` | bstr(64) | yes | By `successor` |

Both signatures are required. The predecessor's says "I hand over"; the
successor's says "I accept", which is what stops a stolen key rotating
an identity onto a bystander's key to strand it. A rotation is therefore
possible only while the user still holds the old key — theft, not loss.
Loss is recovery (§8.3), which is weaker on purpose.

A rotation is one hop. The successor should commit its own `successor`
in its card, so the chain continues, and the rotation should name the
same commitment as `next`. A registrar that publishes the rotation
records `next` as the successor's commitment if the successor holds
none here, whether the rotation brings it here or it was known
already; a successor holding one keeps it, and a rotation to it naming
another `next`, or none, is refused (`successor_mismatch`, §5.4). `next` is
inside both signatures, so nobody holding only one of the two keys can
post the same rotation at any registrar with another. A commitment sent beside
the record, such as the successor's card, would not hold: rotation
records are public once published and name no registrar, so a thief
holding only the successor's key could post the owner's rotation at a
second registrar first, beside a commitment to a key of its own.

The predecessor's identity revocation (§4.5) always wins: posted while
a rotation is pending, it is accepted and cancels the rotation. Once
the identity has committed to its successor, a thief holding only the
old key can therefore destroy the identity, but not take it, since a
rotation it signs goes only to the committed key (§5.4); without a
commitment, its rotation to a key of its own is accepted, and published
at once where there is no delay. The owner's answers to a theft are to
rotate first, and a freeze (§8.2). Once the rotation is published the predecessor writes
nothing more, its revocation included (`revoked`, naming the
successor); the successor may revoke itself.

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

Because `≤` includes the revocation's own second, a registrar that
reissues the handle to the same identity in that second MUST give the
attestation an `issued` later than the revocation's `time`, or the
attestation is void as it leaves.

### 4.9 Record list

Domain `hl-identity/records/v1`, signed by the registrar key. What the
`records` endpoint returns (§6.2).

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `registrar` | tstr | yes | |
| `issued` | uint | yes | |
| `expires` | uint | yes | `issued + records_max_age`. A cache serves it until then |
| `fingerprint` | bstr(32) | no | Present on a per-identity list: `SHA-256` of the key it was asked for, and every entry concerns that key. The fingerprint rather than the key, because the list for a key the registrar has never seen can name it no other way |
| `since` | uint | no | Present on a delta: entries have `seq > since` |
| `more` | bool | no | `true` when the page was cut at the size bound; fetch again with `since` = the last `seq`. A page with `more` and no entries has no last `seq` and is refused |
| `entries` | array | yes | Each `[seq, record]`: a registrar-assigned `uint`, monotonic across the registrar, and the record's encoded bytes as `bstr` |
| `sig` | bstr(64) | yes | |

Records inside are the objects of §4.4 to §4.8 and §4.10, each with
its own signature, which the reader verifies individually. The list's
signature says the registrar published these; the records' signatures
say who made them. **An empty per-identity list is a signed statement
that the registrar holds nothing against that key**, and is cacheable
like any other.

A page is at most 1 MiB. Entries leave the *full* list when they stop
mattering — a device revocation after its `until`, an attestation
revocation after the last attestation it voids would have expired — and
never leave a *per-identity* list, which is the one a verifier consults
for a key in front of it. Rotations, identity revocations and freezes
are never pruned from either. A device epoch record superseded by a
higher one leaves the full list, where the higher one says all a reader
of it needs, but stays in the per-identity list, so a server that
missed an earlier reset still learns when it was signed (§4.10, §7.3).
Each is at most 512 bytes, at most four are published a day, and the
per-identity list keeps a bounded number of them (§10).

### 4.10 Device epoch

Domain `hl-identity/device-epoch/v1`, signed by the **identity key**. At
most 512 bytes. A *reset*: every device certificate of `identity` whose
`epoch` (`hotline-ng-identity.md` §3.3) is below this record's is
revoked.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | The key that signs this |
| `epoch` | uint | yes | The floor. At least 1, at most `2^63 - 1`, so it fits the signed 64-bit integer a store keeps; anything else is refused |
| `time` | uint | yes | When it was signed. Never compared with a certificate. It orders and displays the record, and bounds what a server keeps of friendships it took before the reset (§7.3) |
| `sig` | bstr(64) | yes | |

- **The identity key alone signs it.** A device signature never
  verifies on it, whatever the device's `caps`: a reset ends what only
  the identity key can certify again, so a stolen `manage` device must
  not be able to sign every other device out.
- **It has no `reason`.** It is published, and "compromise suspected"
  is worth not publishing. Nothing that follows a reset depends on why.
- **Effect.** It revokes a certificate when `cert.identity` is its
  `identity` and `cert.epoch` is below its `epoch`, for login, and it
  judges the device-signed objects `hotline-ng-identity.md` §3.3 lists:
  device revocations (§4.4), vouches, vouch withdrawals and friendship
  objects, each by its own rule there. Signed chat lines, messages and
  articles are not judged by it. Floors only rise: an identity's floor
  is the highest `epoch` among the records a reader holds for it, from
  every registrar and from what it kept (§7.3).
- **Telling it apart.** Records carry no type tag (§4.9). This one's
  key is `epoch`, read by `Record::parse` after `ack` or `successor`,
  `device`, `frozen` and `handle`, and before the identity revocation
  read when none of them is present. It carries none of those five:
  `DeviceEpoch::parse` refuses one that does by name, and
  `Record::parse` reads it as the kind that key names, which fails its
  signature (a record with `device` beside `epoch` is a failed device
  revocation). A record with `epoch` that does not verify as a
  device epoch is read as an identity revocation, and reports its
  failure as a device epoch only if that fails too: an identity
  revocation carrying an unknown `epoch` key verified as itself before
  this record existed, and still must. The two domains differ, so at
  most one verifies. A reader from before this record reads it as an
  identity revocation, which fails its signature, and skips the entry
  rather than refusing the identity; that failure is what lets a list
  carry the record to old servers, and `hl-identity`'s tests hold it.

How it composes:

- **Device revocation (§4.4)** names a device key and is permanent for
  every certificate of it, whatever its epoch; the floor names
  certificates. Either refuses. An identity-signed revocation outlasts
  every reset; a device-signed one is void once its signer is below
  the floor (§4.4).
- **Identity revocation (§4.5)** refuses everything and makes the floor
  moot.
- **Rotation (§4.6).** Certificates name their identity key, so the
  predecessor's are refused `rotated` once a rotation is accepted. The
  successor is a new key with no records and floor 0; its certificates
  may start at any epoch, and nothing is carried over. A rotation is
  the answer when the identity key itself may be out, a reset when
  only devices may be.
- **Freeze (§4.7).** A frozen identity's reset is refused `frozen`, as
  its other records are.
- **Several registrars.** An identity attested at several posts the
  reset to each, and a reader takes the highest floor across them. A
  registrar that missed one is caught up by the next post, within the
  step bound (§6.2).

The epoch is a counter, not a cutoff on `issued`, so no certificate is
compared with a clock, and a reset retried after a lost reply asks for
the same `epoch` again, which the registrar answers as done (§6.2).
Every minter must know the current epoch, so a minter that does not
mints a certificate that is dead at first use, which fails safe and
visibly.

`time` has one effect beyond order: a server keeps a friendship it took
a presentation of before the earliest `time` it has seen for each reset
that puts one of its halves below the floor, and refuses one it did not
(`proposals/portable-friends.md` §6). A `time` earlier than the
identity's current record's is refused (§6.2), so one bad clock cannot
reach back past the last reset that registrar published; an honest
holder never trips it, since it signs each post at the later of now and
that registrar's current record's `time` (below). Within that bound, a
`time` in the past is accepted: it makes servers keep less, a cost to
the identity that signed it and to the friends whose friendships with it
must then be remade, and nobody else. A `time` up to the skew tolerance
in the future is accepted too, as for every record, and lets a server
keep what it took up to that long after the reset was signed. The clock
residual is that tolerance, at most five minutes by default, plus
however far the server's own clock, which times what it takes, is wrong.

`hl-identity`: `DeviceEpoch { identity, epoch, time }` with `sign`,
`parse` and `revokes(&cert)`, and `Record::DeviceEpoch`, whose `kind()`
is `"device_epoch"`.

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
exist (`hotline-ng-auth-rationale.md` §10) without this document
defining OIDC.

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

An identity this registrar knows (§9.2) that has no **commitment** yet
takes one from the first of: a registration request with a `successor`,
a card carrying one `PUT` to the registrar (§6.4), or a card carrying
one shown at sign-in on the registrar's server (the ng `auth`, or a
classic client's device proof). Once recorded it is immutable, exactly
as the identity spec's §3.4 rule for servers. A later request or card
that changes or drops it is refused (`successor_mismatch`). None is
recorded for an identity that is frozen, revoked or rotated away. While
a rotation is pending, the identity it hands over records none, not even
the key the rotation goes to, since the registrar cannot tell whose
rotation it is, and the key it goes to records none but its `next`: a
registration request that would make one is refused (`rotation_pending`,
or as that identity's other requests are), and so is a card carrying
one, put (`rotation_pending`) or shown at sign-in (`bad_card`), rather
than served as the identity's card with a commitment the registrar does
not hold. Otherwise a card of a frozen identity has its commitment left
untaken, the card itself accepted and served as any other, and a card of
an identity revoked or rotated away has it left untaken too, and is not
served (§6.4). A card cached earlier that the registrar would now refuse,
such as one of a successor naming another key than the `next` its
rotation recorded, is no longer served. A residual: checking a card
publishes no due rotation, so until the registrar's next write a card is
still refused for a rotation that is due, with a `pending_until` already
past. A commitment recorded then could pin the identity to a thief's key
for good, or have the rotation dropped at publication. That does not
stop whoever holds the successor's key from defeating the owner's
rotation wherever it can write for the successor: by revoking the
successor, or by rotating it on first, so that the owner's rotation is
refused at posting, or dropped when it comes due if it was posted first
(condition 5). Where the successor is unknown and the registrar takes no
new registration from it (`closed`, or an invite it does not have), it
can do neither. It cannot take the identity either way. A rotation names
the successor's own commitment as `next` (§4.6).

A rotation record (§4.6) posted to the registrar is accepted when:

1. both signatures verify;
2. the identity is attested here and not frozen;
3. the registrar holds no commitment for it, or `SHA-256(successor)`
   equals the commitment;
4. no rotation for this identity has been accepted already;
5. the successor, if this registrar knows it, is neither revoked,
   rotated away nor frozen and has no rotation of its own pending
   (`bad_request`), and holds no commitment here or holds the one the
   rotation names as `next`; a rotation without `next` to a successor
   holding one is refused too (`successor_mismatch`).

On acceptance the registrar records the successor as holding every
handle the predecessor held, with each handle's `registered` preserved;
publishes the rotation under *both* fingerprints (§6.2); publishes a
§4.8 revocation (reason 2) of the predecessor's attestations; deletes
the predecessor's envelopes. In the same write a successor holding no
commitment here, new or known, takes the rotation's `next` as its
commitment; one holding a commitment keeps it, which condition 5 makes
the same. A held rotation whose record the registrar can no longer read
is dropped, not published without its `next`. The successor obtains its
own attestations by sending an ordinary registration request for each
handle, which the registrar answers as a reissue; one carrying a
`successor` must match the commitment held, or with none records it.

**The registrar SHOULD delay publication** of an accepted rotation by
`rotation_delay` (default 24 hours when the registrar holds a contact
address for the identity, otherwise 0) and notify the identity through
that address, so that a rotation signed by a thief before the owner
noticed can be met with a freeze (§8.1) before any server acts on it.
During the delay the rotation is pending: a freeze cancels it, so does
the predecessor's identity revocation (§4.6), and a second rotation is
refused `rotation_pending`. When the delay ends, the registrar checks
it again as if it had just been posted, and drops it if it no longer
passes: the successor may have been revoked, frozen, committed or
rotated on meanwhile, and handles moved to it then could never be
renewed. The operator may end the delay early (§8.2), and the rotation
is checked the same way.

Step 3 is the sentence that makes the card's commitment worth
publishing before any server has anchored it. A thief with the identity
key can sign a rotation to their own key; a registrar that holds the
commitment will not publish it, and the threat model's "servers that
have never seen the user" gap is closed by the one party that has.

---

### 5.5 Successor code

The key a card commits to (§5.4) is kept nowhere but on paper until a
rotation needs it, so a client writes it down as a **successor code**
when it makes the commitment, and the user types it back to rotate. The
code is the successor identity key's 32-byte seed:

```
S1-B9D5M-PJTB9-D5MPJ-TB9D5-MPJTB-9D5MP-JTB9D-5MPJT-B9D5M-PJTB9-D0EZ
```

`S1`, then 54 symbols of Crockford base32
(`0123456789ABCDEFGHJKMNPQRSTVWXYZ`):

- the first 52 are the seed's 256 bits, most significant bit first; the
  last of them carries the seed's final bit and four zero bits;
- the last 2 are the first 10 bits of
  `SHA-256("hl-identity/successor-code/v1" || seed)`.

It is shown as `S1-` and the 54 symbols in groups of five joined by
hyphens, once, at the commitment, and never stored by the client.

`S1` names the kind and the form. A fingerprint is of the same alphabet
and nearly the same length, and without the prefix one would read as a
successor code; with it, and the fixed length, neither a fingerprint nor
a recovery code (§9.3) reads as one, and a later form (`S2`) can be told
apart. Both of its symbols are of the alphabet, so the reading below
reads them too.

The code is typed back forgiving case, spaces, hyphens and Crockford's
confusables (`O` for `0`, `I` and `L` for `1`), as a recovery code is,
since it is read off paper. A client MUST read as no code at all
anything else off the alphabet, a code without `S1`, a number of symbols
other than 56 with it, and a last seed symbol with any of its four low
bits set.

What it checks next depends on whether it holds the commitment the
code is for, from the card or from `lookup` (§6.3):

- **Without the commitment**, the check symbols are all there is: a code
  whose check symbols are not its seed's MUST be read as no code. A
  misread seed is another key, and nothing about it looks wrong until
  the rotation it signs is refused; ten bits miss about one random
  misreading in a thousand.
- **With the commitment**, it decides instead of the check symbols,
  which it outranks: the client MUST NOT sign with a code unless
  `SHA-256` of its key's public key equals the commitment, whatever its
  check symbols say. A code that does not
  match MAY be mended: read again with each seed symbol in turn taken
  for each other symbol, or with its one symbol off the alphabet taken
  for each, and the reading the commitment matches taken. A misread
  check symbol leaves the seed as typed, so the commitment matches as
  it stands. Two misread symbols are not mended.

A code is one key's: a rotation (§4.6) uses it once, and the successor
commits to a new one in its own card, written down the same way.

## 6. Endpoints

All under the registrar's advertised paths, on the ng listener, HTTPS.
Request and response bodies are JSON unless stated; signed objects
travel as base64url CBOR. Errors are `{ "error": code, "text": "…" }`
with the status in the table at §6.5. None of these endpoints takes a
transport token: every write is a signed object, and every read is
public. Key backup's three, under `envelopes`, are §9.2.

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
`fingerprint` set), served as the signed object itself,
`application/cbor`, as a card is: every unpruned record naming this key as `identity`,
`device`'s owner, predecessor **or successor** of a rotation. This is
the call a verifying server makes. `ETag` is the list's `issued`;
`Cache-Control: max-age` is `records_max_age`. An unknown fingerprint is
a 200 with no entries — signed, so that a cache can hold "nothing known"
as confidently as it holds a revocation.

`GET <records>?since=<seq>` — the full list as a delta, for a server
that would rather pull everything periodically than ask per identity.
Omit `since` for the whole thing from the beginning, paged by `more`.

`POST <records>` with `{ "record": "…" }` — a user posts a §4.4, §4.5 or
§4.6 record, a device epoch (§4.10), or a portable vouch or vouch
withdrawal (below). The registrar verifies it as §7.1 says a server
would (the same function), checks that `identity` is attested here,
applies §5.4 for a rotation, assigns a `seq`, stores it, and answers
`{ "seq": n, "published": true }` — or `"published": false` with
`"pending_until"` for a rotation inside its delay. A record already
held is answered with its existing `seq` and is not a failure, so a
client that lost the reply can post again; the same rotation posted
again while it waits is answered as pending. A different rotation
while one is pending is answered `rotation_pending` with the held
rotation's `pending_until`.
Registrars before that code answered a second rotation `bad_request`
with the text "a rotation for this identity is already pending", and a
client talking to one takes that answer to mean the same.
Registrar-signed records (§4.7, §4.8) are never accepted here; they
come from the registrar's own tools.

**A device that was reset signs nothing that is published.** A device
revocation (§4.4), a vouch or a vouch withdrawal whose `signer_cert` has
an `epoch` below the identity's current floor is refused
`bad_signature`, "the signer's device was reset", whatever its `time`.
The check comes right after the record parses and verifies, before the
digest check, so posting again the exact bytes of one published before
the floor rose is refused, not answered as held; the copy already
published stays in the lists. Readers ignore a device revocation or a
vouch below the floor wherever they find it (§7.3). A vouch withdrawal
published before the floor rose keeps its effect, since a withdrawal
only takes standing away; the registrar, which knows the order of its
own publications, refuses only those posted after it published the
floor, and a server takes one below its floor only from a registrar
whose list shows it published before that registrar's floor (§7.3,
`identity-vouch.md` §4.1).

That test is only as good as each registrar's floor, so a holder posts
its identity's current device epoch record to every registrar it is
registered at whenever it resets, first thing after it registers at a
new registrar, and again whenever a list it reads from a registrar lacks
it, each time signing the record afresh, as every post of a reset is
signed (below), rather than resending its bytes. A registrar that never
learned the floor proves nothing before it, and a below-floor withdrawal
it published is taken from it by nobody. A registrar that learned the
floor late, from a post it missed or after a restore from a backup, can
have published, before its floor record, a withdrawal a thief posted
after the reset; a server takes that one. That is a residual of a
registrar behind its identity's resets.

**A device epoch (§4.10)** is posted here too, and decided in this
order, under the registrar's one writer lock, which decides every write
in turn, with `cur` the `epoch` of the identity's current device epoch
record (0 for none):

1. the record parses and verifies, and a `time` in the future past the
   skew tolerance is refused, as for every record;
2. the exact bytes already held are answered with their `seq` and
   `"epoch": cur`, which may be higher than the one posted;
3. `not_registered` and `frozen`, as for every record;
4. an `epoch` at most `cur` is not a failure, and nothing is stored:
   `{ "seq": <the current record's seq>, "published": true, "epoch": cur }`.
   It is decided before the rate limits (§10) are checked or charged,
   so a retry is answered even at the limit;
5. an `epoch` past `cur + 16` is `bad_request`, "an epoch advances at
   most 16 at a time";
6. a `time` earlier than the current record's is `bad_request`, "a reset
   is not dated before the last one";
7. the rate limits, then publication: a `seq` and the record stored, and
   the identity's earlier device epoch record taken out of the full list
   (§4.9) in the same transaction, so no reader of it sees two or none;
   the per-identity list keeps both. The answer is
   `{ "seq": n, "published": true, "epoch": epoch }`.

Step 4 makes a retry safe without a read first: a holder whose post
landed and whose reply was lost signs the same `epoch` again with a
fresh `time`, which is new bytes and passes step 2, and is answered as
done. Two holders posting one `epoch` both see success. The `epoch` in
every answer says where the identity stands: an answer equal to the
`epoch` posted is done, and one above it is not, since another holder
reset past it and the devices minted since at the higher epoch are not
signed out. That holder resets again at the answer plus 1.

The bound of step 5 rather than `cur + 1` is so one post catches up a
registrar that missed resets, up to sixteen behind, while a buggy or
hostile signer still cannot push the floor to the top of its range and
leave the identity no epoch to mint in short of rotating. The epoch is
then not exactly a count of resets, which nothing depends on.

**A holder's reset.** It first fetches the per-identity list from each
registrar that attests the identity, past any cache (`Cache-Control:
no-cache`), and takes `target` as one past the highest `epoch` any of
them, or its own record, holds. With no registrar reachable it stops and
says so: a reset nobody can fetch protects nothing. To each registrar
`R` it posts `target`, or `cur_R + 16` first where `R` is more than
sixteen behind, and goes on from `R`'s answer until `R` answers
`target`. Every post, the steps of a catch-up included, is signed afresh
with its `time` the later of now and the `time` of `R`'s current record,
which the fetch read, so step 6 never refuses an honest holder whose
clock is behind. An answer above `target` means another holder reset
past it meanwhile: the holder takes that answer plus 1 as its new
`target` and posts again to every registrar, including those already
done. That second reset signs out the devices the other holder minted at
the higher epoch, which is intended: a reset is a statement that no
device certified before it is trusted, whichever holder certified it,
and the other holder learns of it as any minter does (§4.10). Each post
that publishes spends one of `R`'s daily resets (§10), so a registrar
far behind takes days to catch up, and a reset waits there meanwhile;
the holder says where it is not yet done and retries later.

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
pubkey…", "registered": n, "expires": n, "successor": "…" }` for a
*held* handle; 404 otherwise, one code for free, lapsed, reserved and
unknown alike, so a lookup reveals less than a registration attempt
already would. `successor` is the commitment the registrar holds for
the holder (§5.4), as a fingerprint, and is absent while it holds none.
It is read from the registrar's store, so it is there whenever the
handle is, where a card (§6.4) may not be to hand: a client checking a
successor code on a device with no card (§5.5) reads it here. A client
that does not know the field ignores it. It reveals the commitment to
anyone who asks, as the holder's card already does wherever it is
published: the hash of a key nobody has seen, which tells a reader only
that a successor exists and lets it check one presented later.

The field is unauthenticated: a registrar, its store or anyone between
it and the client can name a key of their own there. A client making a
card, as a restore does (§9.4), MUST NOT sign this `successor` into it
without verifying it against an object the identity signed, such as a
card carrying it that `card` serves (§6.4). Signed into a card, it is a
commitment the identity made, and the registrar and every server that
anchors it hold it for good (§5.4).

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
hxd-ng caches cards in memory, and keeps in its store the newest card
put or shown at sign-in that carries the commitment it holds for an
identity attested here, once that commitment is recorded and while the
identity is not frozen, revoked or rotated away, and none dated past
its clock skew. `card` serves the newer of the two that it would not
refuse, so after a restart, or once the cached card is refused, it
serves the kept card: signed by the identity, carrying the commitment a
restore must keep (§9.4). For an identity this registrar has seen
revoked or rotated away it serves none, cached or kept, and the kept
card is dropped with the revocation or rotation. A
card carrying no commitment is not kept, and after a restart `card`
answers 404 for it until it is put or shown again; so it does for an
identity that committed in its registration request alone. It also
answers 404 for a cached or kept card it would now refuse, and 503, to
`GET` and `PUT` alike, when its store cannot read or check a card
(`hotline-ng-identity.md` §7).

### 6.5 Errors

| code | status | |
|---|---|---|
| `bad_request` | 400 | malformed JSON or CBOR, missing field, wrong `registrar`, an envelope of other parameters than v1's |
| `bad_signature` | 401 | a signature did not verify, including `ack` |
| `bad_time` | 401 | `time` outside skew; a stale request is a replay |
| `handle_invalid`, `handle_reserved`, `handle_taken`, `handle_held` | 409 | §5.1, §5.2 |
| `proof_required`, `proof_invalid` | 403 | §5.3; the former carries `url` when there is one |
| `signup_closed` | 403 | |
| `frozen` | 403 | §8.1; reissue, records and envelope puts all refuse. An envelope fetch is answered `not_found` (§9.2) |
| `revoked` | 403 | identity revoked or rotated away; the body names `successor` when there is one |
| `successor_mismatch` | 409 | §5.4 |
| `rotation_pending` | 409 | §5.4: a rotation of this identity, or to it, is held; the body carries its `pending_until` |
| `not_registered` | 404 | a record for an identity this registrar does not attest to |
| `not_found` | 404 | lookups; every envelope fetch that is not a match; every route under `envelopes` at a registrar that keeps none |
| `too_large` | 413 | the object's size bound |
| `rate_limited` | 429 | §10, with `retry_after`; an envelope fetch's lockout too |

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

For each registrar that attested the identity in front of it, and each
trusted registrar it holds a list from for that identity whatever the
card now shows (`identity-records.md` §3), the server fetches
`GET <records>/<identity fingerprint>` and caches the signed list until
its `expires`, or for `[identity] revocation_max_age`, whichever is
sooner. The fetch happens at `auth`, at a certificate-only
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
identity with no list held has no registrar to ask and is never stale.
A list held that no longer verifies is not stale: it proves nothing
either way, and once the other lists held have been applied the server
refuses with `denied` whatever `revocation_stale` says, until the list
is fetched whole; so does a cache that cannot be read, for an identity
whose card names a trusted registrar or that one is remembered as
attesting (`identity-records.md` §3).

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
| device epoch, the presenting certificate's `epoch` below the floor | refuse: `revoked`, the body carrying the floor as `epoch`; drop the cached certificate and card for that device |
| attestation revocation | discard that attestation before computing age; if none survive, the identity is unattested |

Then age, from the oldest surviving `registered`, and admission policy,
exactly as before.

The floor is not a `time`-ordered effect: it is the highest `epoch`
among the device epoch records the server holds for the identity, from
every registrar it fetched from, and never lower than the highest it has
verified before. A server keeps that record durably, by the identity's
fingerprint, and applies it whatever later lists say, so a list that no
longer carries it lowers nothing, and it is consulted for every login of
the identity whether or not the card shown carries attestations
(`identity-records.md` §3). It also keeps, for each `epoch` it has seen,
the earliest `time` it has seen for it, which decides what friendships
it keeps (`proposals/portable-friends.md` §6).

The floor applies at `auth` on both bindings, at the classic wire's
device proof, at a certificate-only re-admission, at token redemption
and resume, to live sessions through the sweep, which ends them as it
ends a revoked device's, to vouches, vouch withdrawals and friendship
objects as `hotline-ng-identity.md` §3.3 says, and to push
registrations; nor is a certificate below it served for sealing.

**Installing a floor, raising it, or any record moving a half's reset
`time` earlier judges again what the server took before.** A device
revocation applied from a list is dropped if its signer is below the
floor (§4.4). The presentations of each friendship no longer held are
dropped: those whose earliest time of taking under that hash is at or
after the reset `time` of a half below the floor, as
`proposals/portable-friends.md` §6 says. A vouch withdrawal below the
floor that was handed to the server directly is dropped, and one taken
from a registrar's list stays only if that list shows it published
before the registrar's own floor above its signer's epoch: the list
carries a device epoch record whose `epoch` is above the signer's, the
first of which has a higher `seq` than the withdrawal's
(`identity-vouch.md` §4.1). The server keeps, with each withdrawal it
took from a list, the registrar and the `seq` it came under, for this
test. From then on, a below-floor withdrawal handed to the server is
refused.

The cost falls on the owner's own withdrawals too: one its device signed
before the reset and handed to a server directly, or published by a
registrar that never learned the floor, is dropped, and the vouch it
withdrew counts again. So after a reset a holder signs again, from a
current device or with the identity key, every vouch withdrawal it means
to keep, and posts them where it posted the old ones, as its clients
already sign their friendship cutoffs afresh
(`proposals/portable-friends.md` §5.1).

A server also keeps a **local revocation list**, `[identity]
revoked_devices` and `revoked_identities`, of fingerprints the operator
has refused by hand. It is consulted first and needs no registrar. It
exists so that an operator can lock out a stolen key *today*, on the one
server they run, whatever the registrar does or does not publish.
Refusing the next login is half of that; the other half is that the
session the attacker already holds ends too. Installing a list — at
startup, or when SIGHUP re-reads it — ends every session, connected or
detached, whose transport key it now refuses, so a resume token is not
a way back in, and a transport token minted before the revocation no
longer redeems. What is compared is the key the socket proved, never
the fingerprint an account is linked to: an account whose linked
identity is revoked can still be reached with its password, which is
not the thing that was stolen.

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

On acceptance: the account link, bans, reserved name, block-list entries,
stored mail, news subscriptions and authorship, and an avatar keyed on
the predecessor's fingerprint move to the successor; the predecessor's fingerprint is written to the same durable
file as anchors (`[identity] successors`) as *rotated to X*; the
predecessor's cached cards and certificates are dropped; both
fingerprints are logged. A later `auth` by the predecessor is refused
`rotated`. The rotation's `next`, if present, is anchored as the
successor's commitment, in the same write as the rotation. From then
on the successor's card must carry `successor` equal to `next`: one
that carries another, or omits it, is refused `bad_card`.

The successor's card is never its anchor. Its key's holder may not be
its owner, and may sign in first: a card it shows, committing to a key
of its own, would make that key the one a later rotation is taken to,
which the registrars, holding `next`, would all refuse. A
successor whose rotation carried no `next` has no anchor: a further
rotation of it shown at `auth` is ignored, and one is accepted only
from a trusted registrar's records. A rotation to a key already
anchored to anything but its `next`, by a card shown while the key
stood alone, is ignored, as that anchor cannot be taken back. So is any
rotation into a key that is already a rotation's successor, with a
`next` or without: a key has one predecessor, the first accepted here,
and whoever holds it alone could make a second, committed to it, to
choose its `next` or to have the owner's dropped. If that holder's
rotation arrives first, the owner's is the one not taken, and nothing
of it moves. A rotation into a key that has itself rotated away is not
taken either: what it moved there would be stranded, since that key's
`auth` is refused `rotated`.

Each of these three is ignored when an `auth` request shows it, since
whoever holds the successor key alone can replay one there, and the old
key stays admitted. From a trusted registrar's records it is **held**
instead: the registrar has said the old key is retired, and this server
declines only to hand what it holds to a successor it cannot vouch for.
The predecessor is refused `rotated`, naming the successor, at `auth`
and wherever else its key is checked, and its sessions end, as at an
acceptance; nothing moves, neither the account link nor bans, mail,
friendships or the rest; the successor takes no anchor from it. A
held rotation stands as an accepted one does: no other rotation of
that predecessor is taken, and neither key can be a rotation's
successor here again. A rotation from a predecessor anchored to
another key is never held: it is the thief's rotation the anchor
beats, whoever publishes it, and the old key stays admitted, for the
owner's own rotation to the anchored key to be taken. Nor is one into
a key that rotated to its predecessor, which would leave each refused
as rotated to the other.

Whoever holds the successor key alone can force a hold, and so lock
the old key out here until the operator relinks it: by anchoring the
successor elsewhere with standing, by having a rotation of a key of
their own into it accepted first, or by having a registrar publish its
rotation onward first. They take nothing by it, since nothing moves to
the successor. A hold can come without a thief, too: the successor
key signed in with standing before a rotation that carries no `next`,
or records applied out of order, the onward rotation before the one
into it. Once one is held, the predecessor's account can still be
reached with its password, if it has one, and the operator can link it
by hand, setting `fingerprint` in the account file's `[identity]` table
once no other account links that key, to a key this server admits: the
successor, or, where the successor has itself rotated away (`B => C`
accepted before `A => B` was held), the end of its rotations, `C`,
since `B` is refused `rotated` too. What else the server keeps stays
with the predecessor's key.
hxd-ng writes a rotation's `next` in `[identity] successors` as a line
of its own, and drops, with a warning at load, any other anchor a
successor has there, such as one an older build took from its card, and
any anchor of a key that is the successor of two rotations, as a file
an older build wrote may hold. A held rotation is the line
`<predecessor> => <successor> held`. A build from before held
rotations reads it as malformed and drops it when it compacts the
file, admitting the predecessor again as it would have; a build that
holds them holds it again at the next fetch of the registrar's records
that publish it.

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

While frozen the registrar refuses reissue, records and envelope puts
for that identity (`frozen`), answers its envelope fetches as it
answers a miss and its salt lookups with a decoy (§9.2), and cancels
any pending rotation. A freeze
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
3. signs a rotation with the old key and acknowledges with the new,
   naming the successor's own commitment as `next` (§4.6);
4. the registrar verifies out of band that it is the holder posting,
   lifts the freeze, and once the holder posts the rotation (the freeze
   canceled any pending one, so it is pending again only once posted
   again), publishes it at once with `hxd registrar publish
   <fingerprint> --to <successor>`, naming the successor the holder
   confirmed, since the holder is on the line. A rotation pending to
   any other key is refused and left waiting.

Lifting the freeze opens a window until the holder's rotation is posted.
In it the thief's revocation is accepted, as it is at any time (§4.6):
the identity can be destroyed, though not taken. Without a commitment
the thief's own rotation is accepted too. `--to` keeps the operator from
publishing that one, but left alone it publishes by itself when the
delay ends, and while it waits the holder's rotation is refused
`rotation_pending`; the remedy is to freeze again, which cancels it.
Where the registrar holds no commitment, the thief may also record one
in the window, to a key of its own: the holder's rotation is then
refused `successor_mismatch`, and the holder is left with revoking the
identity or with recovery (§8.3). The holder posts at once. A thief that
reposts its rotation each time the freeze lifts can keep that up for as
long as it likes, so freezing again ends a round, not the contest. A
mode that lifts the freeze and publishes the holder's rotation in one
write, taking the signed record from the operator, would close the
window; it is not built.

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
| `kdf` | map | yes | `{ "alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": bstr(16) }` |
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
"works".

**v1 has one set of parameters**: `m = 65536` (64 MiB), `t = 3`,
`p = 1`, which a phone can afford. A reader refuses any other, so a
registrar can never ask a device to spend more than v1 does, and only
the salt varies. The `kdf` map is **closed**: exactly those five keys.
It is unsigned, so a key this version does not define is refused
rather than left for some later reader to give a meaning. Stronger
parameters are a new version.

**Each seal draws a fresh 16-byte salt** from the OS CSPRNG, and a
fresh nonce. One salt and one secret make one key, so a fresh salt is
what makes a replaced envelope's `auth_key` a different one: an
envelope sealed again under the same passphrase is fetched by another
key than the one it replaced, and whoever learned the old one has
nothing.

Two keys from one derivation: `enc_key` never leaves the client;
`auth_key` is what the client sends to fetch, and the registrar stores
`SHA-256(auth_key)`. Neither the passphrase nor `enc_key` is ever
derivable from what the registrar holds without the envelope *and* an
offline attack on the KDF, which is why the parameters are what they
are.

### 9.2 Put, salt, fetch, delete

`PUT <envelopes>` with `{ "request": "…" }`, domain
`hl-identity/envelope-put/v1`, signed by the identity key, ≤ 2 KiB:

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `identity` | bstr(32) | yes | |
| `registrar` | tstr | yes | this registrar's `host` (§3), so a put made for one cannot be replayed at another |
| `kind` | uint | yes | one envelope per kind per identity; a put replaces |
| `time` | uint | yes | |
| `auth_hash` | bstr(32) | no | `SHA-256(auth_key)`. Present exactly when `envelope` is |
| `envelope` | bstr | no | the §9.1 object, of this `kind`, at most `envelope_max`. Absent: delete this kind |
| `sig` | bstr(64) | yes | |

The registrar checks the signature, `registrar` against its own host
(`bad_request`), `time` against its skew tolerance (`bad_time`), and
the envelope's form, v1's parameters included. A put's `time` must also
be later than the last put of its kind for that identity, to the
second, a delete included, which the store keeps across restarts
(`bad_time`): a put sent again, or an older one sent over a newer,
changes nothing. A client that lost the reply, or puts twice in one
second, signs the put again once the second has turned. Puts are held to the
record posts' rate per identity (§10). Only an identity this registrar
knows may put (`not_registered`): one that has registered here, its
handles lapsed or not, or the successor of a rotation it published,
before the successor's first reissue too. And only an unfrozen one
(`frozen`) that is neither revoked nor rotated away (`revoked`). It
answers `{ "stored": true }` or `{ "deleted": true }`.
A client opens what it is about to put with the keys it will fetch with
before sending it, so that what is stored is what those keys open.

A device with nothing but the handle and the secret first asks for the
salt. `POST <envelopes>/params` with `{ "handle": "alice", "kind": 1 }`
answers `{ "kdf": "…base64url…" }`, the CBOR `kdf` map of §9.1: the
stored envelope's, for a handle whose holder keeps an envelope of that
kind here. **For anything else** — no such handle, no envelope of that
kind, a frozen holder — it answers a **decoy**: v1's parameters under
`HMAC-SHA256(decoy_secret, "hl-identity/envelope-decoy/v1" || 0x00 ||
lowercase(handle) || 0x00 || kind)`, cut to 16 bytes, where
`decoy_secret` is the registrar's own and never published. A decoy is
the same each time it is asked for and unpredictable without the
secret, so one lookup confirms nothing about a handle: a real salt and
a decoy look alike. Asked again over time they do not behave alike,
and that is a residual risk: a real salt changes when its envelope is
sealed again, and turns into the decoy when the envelope is deleted or
its holder frozen, revoked or rotated, so someone polling `params` for
a handle learns that its envelope changed and roughly when, though not
what it holds. Replacing `envelope_secret` changes every decoy at once
and shows the same of every handle whose salt did not change. Salt
lookups are lookups, and are held to §10's lookup limit per address.

The device derives from that salt, then `POST <envelopes>/fetch` with
`{ "handle": "alice", "kind": 1, "auth": "…base64url auth_key…" }`. The
registrar resolves the handle — held, or lapsed within the hold, since
an attestation that ran out while its only device was lost is what a
backup is for — hashes `auth`, compares in constant time, and on a
match returns `{ "identity": "…base64url pubkey…", "envelope": "…" }`.
**Every other outcome is `not_found`**, with one body: no such handle,
no envelope of that kind, wrong key, frozen. One answer, so that the
endpoint confirms nothing about a handle to someone who does not hold
its secret. The device opens the envelope with the keys it derived; an
envelope under any other salt than the lookup gave is refused rather
than derived for again.

The fetch is the one place an unauthenticated caller can spend the
registrar's time on someone else's account, and it is rate-limited
accordingly (§10), by two counts, both per handle *asked for* and per
kind, whether or not the handle exists, and both kept in the store, so
a restart grants no fresh allowance — they are the only thing between a
passphrase and an online guess:

- **Per handle, per address** (an IPv4 address, or an IPv6 /64): 10 an
  hour, then a lockout of an hour, doubling with each lockout to a day.
  What it buys: one address guesses slowly, and locking it out locks
  out that address alone, so **one address can no longer lock the owner
  out**. What it costs: nothing for the owner, who fetches from
  somewhere else.
- **Per handle, from everywhere**: 200 a day
  (`envelope_fetches_per_handle_daily`). What it buys: **guessing is
  capped** at that many a day however many addresses the guesser has,
  which against a passphrase worth guessing at Argon2id's cost is the
  number that matters. What it costs: **a botnet can still lock the
  owner out**, by spending the day's fetches before the owner does, for
  as long as it keeps spending them at that rate.

The operator's `hxd registrar unlock <handle> [--kind
passphrase|recovery]` forgets both counts for a handle, on the running
store, for the owner who asks out of band. Counts sit in a fixed number
of slots chosen by `HMAC-SHA256(envelope_secret, …)` of the handle, the
kind and the address, so nobody can grow the table; two counts share a
slot only by a collision no one without the secret can aim for, and
the later takes it over. Where there is an envelope its day's count is
kept with it instead, so no flood of other handles can evict it.

Eviction makes the per-address count best-effort. A slot taken over
starts afresh, so an address's lockout, and its doubling, can be
forgotten before the day after its last lockout that §10 gives it —
by an attacker filling the table, which takes on the order of the
table's size in fetches, each held to the per-address rate. Guessing
stays capped by the day's count, which for a handle with an envelope
cannot be evicted.

A handle refused by either answers `rate_limited` with `retry_after`,
which is the one exception to "every other outcome is `not_found`",
because the owner needs to know why their own passphrase stopped
working. A handle with no envelope is counted the same way as one with,
so a lockout says nothing a miss does not, with one residual: its day's
count is kept in an evictable slot, where an envelope's is kept on its
own row. An attacker who brings a handle to the daily ceiling, then
spends on the order of the table's size in fetches of other handles to
evict its slot, and asks again, sees `not_found` where the handle has
no envelope and still `rate_limited` where it has one. That costs
roughly the ceiling plus the table's size in fetches, across enough
addresses to pass the per-address rates, and tells only whether the
handle keeps an envelope of that kind — what the salt lookup's decoy
otherwise hides.

On identity revocation (§4.5) or an accepted rotation (§5.4) the
registrar deletes the identity's envelopes in the same transaction as
the record.

### 9.3 Recovery code

An envelope of `kind = 2` is wrapped by a **recovery code**: 20
characters of Crockford base32 from the OS CSPRNG (100 bits), shown once
at creation as four groups of five, never stored by the client. The
same derivation applies under the same parameters, so that one code
path serves both kinds; the code is typed back forgiving case, spaces,
hyphens and Crockford's confusables (`O` for `0`, `I` and `L` for `1`),
since it is read off paper. A new code replaces the old one's envelope.

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

An envelope holds the identity seed and nothing else: not the card,
and not the successor key a card commits to (§5.4). A restore takes the
card the registrar keeps (§6.4), which carries the commitment, and never
the commitment `lookup` names (§6.3). Where
the registrar keeps none, a new card commits to nothing, and the
registrar, holding the commitment, refuses the next registration
`successor_mismatch` until a card commits to the same successor again
— which takes the original successor key, kept apart from the identity
key on purpose. `hlid restore` says so, and `hlid register
--successor-commit --successor-key FILE` makes that commitment again.

---

## 10. Bounds and rate limits

Every table an unauthenticated caller can grow has a ceiling, and every
ceiling is a setting with a default.

| What | Default | Past it |
|---|---|---|
| Registrations per hour, per address | 5 | `rate_limited` |
| Registrations per hour, registrar-wide | 120 | `rate_limited`; reissues exempt |
| Record posts per hour, per identity | 20 | `rate_limited` |
| Device epochs published per day, per identity | 4 | `rate_limited` with `retry_after`; each also counts as a record post. An answer to an `epoch` at most the current one, or to bytes already held, counts toward neither |
| Epoch step per published device epoch | 16 | `bad_request` |
| Answers that charge nothing (a device epoch at or below the current one, bytes already held), per minute, per address | counted as lookups | `rate_limited`, so a free answer is not a free amplifier |
| Device revocations kept per identity | 256 | oldest-`until` pruned from the full list; per-identity list keeps all |
| Superseded device epoch records kept per identity | 256 | the oldest dropped from the per-identity list; a server that read it keeps its earliest `time` for that `epoch` (§7.3); one that never did has only the later records' times, and so may hold presentations taken between the two, a residual of a reset that many resets back |
| Envelope fetches per hour, per handle, per address | 10 | `rate_limited`, then lockout doubling from 1 hour, capped at 24 and forgotten a day after the last ends, or sooner if its slot is taken over (§9.2). Per kind, for any handle asked after, kept in the store |
| Envelope fetches per day, per handle | 200 | `rate_limited` until the day turns; per kind, kept in the store |
| Envelope fetches per hour, per address | 30, and 8 times that per IPv6 /48 | `rate_limited`. Counted in memory, apart from registrations and lookups so a flood of fetches leaves them their room; past 16384 addresses at once a new one goes uncounted rather than refused, since the stored counts are the bound on guessing. An IPv4-mapped IPv6 address counts as its IPv4 |
| Fetch count slots | 65536 | fixed; a new count takes a slot over, so a full table refuses nobody |
| Envelope puts per hour, per identity | the record posts' 20 | `rate_limited` |
| Salt lookups per minute, per address | counted as lookups | `rate_limited` |
| Lookups per minute, per address | 60 | `rate_limited` |
| Record-list page | 1 MiB | `more = true` |
| Envelopes per identity | 2 (one per kind) | a put replaces |
| Envelope size | `envelope_max`, 1024 | `too_large` |
| Clock skew | 300 s | `bad_time` |
| Pending rotations | 1 per identity | second refused `rotation_pending` |

Signed requests are replay-checked by `time` and a seen-set of request
digests held for the skew window, as the transport does for proofs. A
registration request seen again inside the window is answered with the
reply it got the first time and issues nothing, so a client that lost
the reply can resend it; records are idempotent by digest (§6.2), and
a device epoch at or below the current one is answered as done; an
envelope put must be newer than the last of its kind (§9.2).

---

## 11. Settings

hxd-ng's `[registrar]` section. Its presence is the switch, and it
requires `[identity]`, which requires `[ng]`; without them it is a
startup error, as `[identity]` without `[ng]` is.

| Setting | Default | Meaning |
|---|---|---|
| `host` | *required* | The `host` of §3: a lowercase hostname, no port. Discovery carries the `registrar` block only when asked for under this `Host` |
| `key` | `registrar.key` | Ed25519 seed file; generated on first run, mode 0600 |
| `retiring` | empty | `[{ key = "…", until = … }]` for §4.1 key rotation |
| `store` | `registrar.db` | SQLite file (§12) |
| `signup` | `proof` | `open`, `proof`, `closed`. The default is the one that does not make a fresh install a sybil factory |
| `proof` | `invite`, or `none` with `signup = open` | `invite`, `email`, `oidc`, `vouch`, or `none` with `signup = open`. hxd-ng checks `invite` and refuses the other three at startup |
| `proof_url` | none | Where to get an invite; returned as `url` with `proof_required` |
| `invites` | `registrar-invites` | For `proof = invite`: a file of codes, one per line, `#` comments allowed. Imported into the store at start and on SIGHUP, and spent there; `hxd registrar invites --add` appends to it |
| `level` | `2` when `proof = invite`, else per §5.3 | Written into attestations; a startup error if it exceeds what `proof` supports |
| `attestation_days` | `365` | |
| `hold_days` | `365` | §5.2 |
| `handle_min`, `handle_max` | `3`, `32` | §5.1 |
| `reserved` | built-in list | Additional reserved local parts; the built-in list is `guest`, `admin`, `administrator`, `root`, `system`, `server`, `registrar`, `postmaster`, `abuse`, plus the system account's login and every account login on this server, re-read on SIGHUP |
| `rotation_delay` | `86400` when a contact exists, else `0` | §5.4. hxd-ng holds no contacts, so its default is `0` |
| `records_max_age` | `3600` | §4.9 |
| `reporting_servers` | empty | §6.7; *(deferred)* servers whose vouch reports are believed, keyed by `server_key` |
| `vouch_reports` | `2` | §6.7; distinct reporting servers before `proof = vouch` is refused from a voucher |
| `envelopes` | `false` | §9: keep envelopes, and advertise `envelopes` in discovery |
| `envelope_max` | `1024` | bytes; from 256 to 1024 |
| `envelope_secret` | `registrar-envelope.secret` | The secret of §9.2's decoys and fetch-count slots; generated on first run, mode 0600. Replacing it changes every decoy at once, which shows a watcher which handles' salts stayed put, and forgets every count kept outside an envelope |
| `rate.*` | §10's column | one key per row of §10: `registrations_per_address`, `registrations_per_hour`, `records_per_identity` (envelope puts too), `lookups_per_minute` (salt lookups too), `device_revocations_kept`, `envelope_fetches_per_handle` (per address), `envelope_fetches_per_handle_daily`, `envelope_fetches_per_address` |

The clock-skew tolerance is `[identity] clock_skew`: one server, one
clock.

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

Server operator tools, in `hxd`, built:

```sh
hxd identity revoke    <fingerprint> [--device] [--lift]   # §7.3's local list
```

Registrar operator tools, in `hxd`, built. They act on the store the
running server uses, and never create a registrar key of their own:

```sh
hxd registrar freeze   <fingerprint> [--lift]
hxd registrar publish  <fingerprint> --to <successor>   # §8.2: its pending rotation, without the delay
hxd registrar revoke   <handle> --reason abuse|lapsed|unspecified   # abuse also bars the holder
hxd registrar recover  <handle> --identity <new fingerprint> [--keep-age]
hxd registrar invites  --add 10
hxd registrar unlock   <handle> [--kind passphrase|recovery]   # §9.2: forget its fetch counts
hxd registrar inspect  <host>            # §6.6: fetch log and stats, print the last month
```

User tools, in `hlid`, built; `--registrar` also takes a full URL, for
a test rig:

```sh
hlid register    --registrar hl.example --handle alice [--proof CODE] [--successor-commit]
hlid revoke      --registrar hl.example (--device-cert FILE | --device-pub HEX) [--reason stolen] [--by-device]
hlid revoke      --registrar hl.example --identity-revoke --yes
hlid rotate      --registrar hl.example --to <successor key file> [--next-key FILE]
hlid backup      --registrar hl.example [--recovery] [--delete]
hlid restore     --registrar hl.example --handle alice [--recovery]
```

A device revocation names the device's *key*, which a fingerprint
cannot give back, so `hlid revoke` takes its certificate — whose
`expires` is then the record's `until` — or its public key. `register`
puts the attestation into the card, re-signs it and publishes it at the
registrar; `--successor-commit` makes a successor key beside the
identity key and commits the card and the registration to it. `rotate`
makes the successor's own successor key first (`--next-key`, by default
`successor.next.key` for `--to successor.key`), signs its commitment
into the rotation as `next` (§4.6), and prints the successor's card and
reissues, the card committing to that key. `backup`
puts a passphrase envelope, or with `--recovery` makes a recovery code,
shows it once and puts its envelope; `--delete` removes one kind.
`restore` looks up the salt, derives, fetches and opens, and lays the
identity out in `$HLID_HOME` as `hlid init` does, with a new device and
the card the registrar keeps. Both read the secret from `--password-file` or
`--password-stdin`, and refuse `--password`, which `ps` would show.

---

## 12. Storage and implementation notes

- **One store, SQLite**, behind a `RegistrarStore` trait in the shape of
  `hxd-store-sqlite` — built as `hxd-registrar`'s trait, an in-memory
  store for its tests, and `SqliteRegistrarStore` in a file of its own,
  held to one conformance suite. The trait is shaped around the two
  writes, an issuance and a publication with its effects, rather than
  around the tables: `identity` (pubkey, fingerprint, commitment,
  frozen, revoked, rotated_to, contact, created, card), `handle` (canonical,
  identity, registered, state, lapsed_at), `attestation` (identity,
  handle, issued, expires, bytes), `record` (seq, kind, identity,
  other_identity, device, until, bytes), `envelope` (identity, kind,
  auth_hash, bytes, updated), `lockout` (handle, kind, start, count,
  until, strikes, forget_at), `invite` (code_hash, used_by, used_at).
  `record.other_identity` is what makes the per-identity list find a
  rotation under the successor.
- **The verifier is one function**, in `hl-identity`, over the records
  of §4.4–§4.8: the registrar calls it on `POST records`, the server
  calls it on every list entry, and `hlid` calls it before posting. A
  record the registrar would accept is one every server would, by
  construction.
- **Per-identity lists are signed on demand.** A cache keyed by
  fingerprint for `records_max_age` would make a burst of admissions for
  one identity cost one signature; hxd-ng signs each time, because one
  Ed25519 signature is cheaper than the invalidation a freeze would need.
  The full list is signed per page.
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
- **hlid** gains the codecs for §4.2 and §4.4–§4.6 and the envelope
  codec and derivation, all through `hl-identity` (which brings `argon2`
  and `chacha20poly1305` for §9), and the commands of §11.
- **A pending rotation has no timer.** It is published by the first
  read or write of the registrar after its delay, under the write lock,
  so there is nothing to miss across a restart.
- **The write lock spans processes.** The operator's commands open the
  server's store from a process of their own. Each decision and the
  writes it leads to run in one store transaction (`BEGIN IMMEDIATE`
  in SQLite), so neither side acts on a state the other is halfway
  through changing.

---

## 13. Threat model deltas

To fold into `identity-threat-model.md`:

- **Registrar operator, can:** see envelope fetch attempts and their
  source addresses; hold envelope ciphertext and mount an offline KDF
  attack on it, bounded by §9.1's parameters and the user's passphrase; delay
  a rotation by `rotation_delay`. **Cannot:** publish a rotation to a
  key other than the committed one; unfreeze a record it did not sign
  (it signed all of them — the point is that a lift is as visible as a
  freeze).
- **New scenario, envelope brute force.** Attacker with the ciphertext
  (registrar breach or a malicious registrar) and no passphrase.
  Mitigation: Argon2id at v1's parameters makes a weak passphrase expensive
  and a recovery code (100 bits) infeasible. Residual: a weak passphrase
  is a weak passphrase; clients should say so at creation.
- **New scenario, handle lockout.** Attacker who knows a handle
  hammers the fetch until it locks. Mitigation: an address locks out
  only itself, so the owner fetching from anywhere else is unaffected;
  the recovery code path is a separate `kind` with its own counts; the
  operator can unlock a handle. Residual: a botnet spending the handle's
  daily ceiling locks the owner out for as long as it keeps doing so.
- **New scenario, distributed guessing.** Attacker with many addresses
  guesses at a handle's passphrase online. Mitigation: the daily
  ceiling caps guesses at `envelope_fetches_per_handle_daily` whatever
  the number of addresses. Residual: that many guesses a day, forever,
  against a weak passphrase.
- **New scenario, salt polling.** Attacker polls `params` for a handle.
  Residual: learns when its envelope is resealed or goes, not what it
  holds (§9.2).
- **New scenario, evicting a count.** Attacker floods fetches of other
  handles to take over count slots. Residual: an address's lockout can
  be forgotten early, and a handle at its daily ceiling can be told
  apart as having an envelope or not, for roughly the ceiling plus the
  slot table's size in fetches (§9.2).
- **Stolen identity key, amended.** The registrar's refusal to publish
  a non-committed rotation and its delay-and-notify window are the
  mitigations that were previously listed as "registrar freeze" alone.
  The old key's revocation always cancels a pending rotation, so a
  stolen identity key of a committed identity can destroy it but not
  take it (§4.6).
- **Malicious registrar, amended.** It can additionally serve a stale
  or empty per-identity list; a server's `revocation_stale` and the
  user's second attestation elsewhere are the answers, unchanged. A
  list that drops a device epoch it once served lowers no floor a
  server already holds (§7.3); one that never publishes a reset is
  answered by the second attestation.
- **Registrar operator, can additionally** see when an identity resets
  its devices and roughly how often (the epoch); and, since a holder
  fetches the identity's records before it mints, when and from which
  addresses its holder and envelope devices certify devices. Not how
  many devices exist, or which: a reset tells it less than revoking each
  device would.
- **Anyone shown a certificate** learns a lower bound on how many times
  its identity has reset, from its `epoch`.
- **New scenario, a device after a reset.** A thief holding a device
  key and its certificate, still within its window, after its identity
  reset. Mitigation: the certificate is refused at login, and the
  device revocations, vouches and friendship objects its device signs
  are refused however they are dated (§4.4), so a leaked `manage`
  device cannot revoke the devices enrolled after the reset. The vouch
  withdrawals it made before the reset still stand, which only takes
  standing away.
  A reset is signed by the identity key alone, so a stolen device
  cannot sign one. Residuals: a server that has never fetched a list
  since the reset and cannot reach the registrar admits it under
  `revocation_stale = cached`; an identity never attested has no
  registrar to publish a reset; a card shown without attestations, at a
  server that holds no floor for the identity, is admitted with no
  fetch, onto its linked account if it has one; a server that does not
  know the record skips it; and across a link nothing is checked
  (`server-link.md` §7.7). Each holds for a device revocation today.
- **New scenario, a reused device key.** A client that enrolls again
  after a reset with its old device key, at a holder that has lost its
  record of that key, is certified at the new epoch, and a copy of that
  key is back in. Mitigation: an enrollee refused for its epoch makes a
  new key, and a holder refuses a key it knows was reset
  (`identity-enrollment.md` §8). Residual: a client that does not.
- **Stolen identity key, amended.** A thief holding it can reset, at
  most four times a day, each ending every session of the identity
  everywhere it is seen; the owner rotates (§4.6).

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

`hotline-ng.md` §7 and §9, and the legacy ban list: the `*@host` entry form and
the `retry_after` on `rate_limited` during `newcomer_delay` (§7.3).

`identity-enrollment.md` §12: "Mobile without a desktop" is answered by
§9.4; the delegated-certification alternative is declined there.

`identity-threat-model.md`: §13 here.

hx-libs' `hl-identity`: the `ack` rule (§4.1) in `signed.rs`; the seven
new codecs; the envelope derivation.

---

## 15. Test vectors

In `identity-test-vectors.json`, with the same identity, device and
registrar keys as the rest so that the objects chain, and checked by
`hl-identity`'s `tests/vectors.rs` (the envelopes in
`tests/envelope.rs`):

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
- Device epochs, checked by `tests/device_epoch.rs` as well:
  `device_cert_epoch` and `device_cert_epoch_max`, the device
  certificate in epoch 3 and in epoch `2^63 - 1`; `device_epoch` and
  `device_epoch_max`, the record at 4 and at `2^63 - 1`;
  `records_device_epoch`, a per-identity list carrying one; and
  `revoke_device_by_epoch_device`, a device revocation by a `manage`
  device whose certificate is in epoch 1, dated inside its window,
  refused at floor 2 and standing at 1. Among `rejects`: a certificate
  with `epoch` 0 written out and one at `2^63`, a record at epoch 0, one
  signed by a device key, and one carrying `device` beside `epoch`.
- `envelope`: a `kind = 1` envelope with fixed salt and nonce, the
  passphrase in the clear, `enc_key`, `auth_key`, `auth_hash`, and the
  seed; a `kind = 2` envelope with its code; a decoy salt; and the
  envelopes, `kdf` maps and puts that must be refused.

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
