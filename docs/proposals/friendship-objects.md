# Proposal: friendship objects

Status: proposal. Built in `hl-identity` (`friendship`) with §6's
vectors. The signed objects that
`portable-friends.md` is built on: an offer, an acceptance, the
friendship the two make, and a withdrawal that ends friendships. Defined
in the terms of `hotline-ng-identity.md` ("the identity spec"), for
`hl-identity` and its test vectors, so that the second version of
fogWraith's
[Capabilities-Messaging-Identity.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Messaging-Identity.md)
("the identity draft") can cite them. Their shape reuses
`identity-vouch.md`'s signed statement and withdrawal. Where a server
takes or holds them, and what a client does with them, is
`portable-friends.md`'s.

---

## 1. Common rules

Each object is deterministic CBOR with a domain string, `v = 1`, unknown
keys ignored and covered by the signature (the identity spec's §3.1),
implemented in `hl-identity` beside the device certificate and the
signed message. Times are Unix seconds, as the identity spec's are.
Signatures are verified strictly, by `e2e-messages.md` §3.1's rule. `S`
is that section's skew allowance, ten minutes, and a certificate is
**valid at** a time as `e2e-messages.md` §3.5 defines it, with `S` at
both ends.

Every object is signed by a **device** key, so that any of a person's
devices can make one; a device need not hold the identity key
(`identity-enrollment.md`). The object carries the device's certificate
as `cert`, and is signed by that certificate's `device` key. The
certificate must be for the object's `from` (its `identity` is `from`),
allow messages (bit 1 of `caps`, or `caps` absent), be at most 512
bytes, as a signed message's is (`e2e-messages.md` §2, §3.5), and be
valid at the object's `time`. Revocation is not part of this check
(§5). `from` repeats the certificate's `identity` so that the checks
that come before the signature, of the pair and of `to`, can run on the
object alone; an object whose `from` is not its certificate's
`identity` is rejected. Bit 2 of `caps`, which the identity spec's §3.3
describes as "may sign vouches and withdrawals", means a vouch's
withdrawals (`identity-vouch.md` §4.1); a friendship's need only bit
1. This document asks §3.3 to say "vouch withdrawals".

`from` is always an identity's public key, which its own certificate
carries. A party named by the other is named by fingerprint, since that
is all a stranger is shown (the identity draft's `DATA_FRIEND_IDENTITY`).

---

## 2. Offer

Domain `hl-identity/friend-offer/v1`. At most 1 KiB.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `from` | bstr(32) | yes | The offering identity's public key |
| `to` | bstr(32) | yes | The offered identity's fingerprint |
| `time` | uint | yes | |
| `expires` | uint | yes | `time < expires <= time + 30 days` (2,592,000 seconds) |
| `id` | bstr(16) | yes | Random; makes two offers between the same pair two friendships |
| `cert` | bstr | yes | |
| `sig` | bstr(64) | yes | |

A friend request's note (`DATA_REQUEST_NOTE`) stays outside the offer:
it is for the request, not the friendship, and signing it would make the
friendship carry it everywhere.

An offer hands its target the sender's device certificate, which the
identity draft otherwise gives friends alone (Get User Info, 825): its
device keys, and its `name` if it has one. A sender who would rather
not name the device to a stranger signs offers from a certificate
without one.

---

## 3. Acceptance, and the friendship

Domain `hl-identity/friend-accept/v1`. At most 1 KiB.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `offer` | bstr(32) | yes | SHA-256 of the offer's whole encoding, `sig` included, as the array carries it |
| `from` | bstr(32) | yes | The accepting identity's public key, whose fingerprint is the offer's `to` |
| `time` | uint | yes | |
| `cert` | bstr | yes | |
| `sig` | bstr(64) | yes | |

A **friendship** is the offer and the acceptance, carried together as a
deterministic CBOR array of exactly two byte strings, the offer's bytes
first and the acceptance's second, each at most 1 KiB. Anything else, a
third element, the two reversed, or the objects embedded as maps rather
than as their bytes, is rejected, so each friendship has one encoding.
The array is not signed; each element is. A friendship is named by its
**friendship hash**, the SHA-256 of the array's bytes, not of the
offer's: two acceptances of one offer, by two devices or signed twice,
are two friendships with two halves by the acceptor, which a withdrawal
can treat differently (§4), so they need two names. Each party's
**half** is the object that party signed, and a half's time is that
object's `time`.

**Checking a friendship**, cheapest first, as the identity spec's §13
orders a card's checks:

1. the array as above, sizes and `v`, the offer's
   `time < expires <= time + 30 days`, and the offer's `to` is not the
   SHA-256 of its own `from`;
2. the acceptance's `offer` is the hash of the offer, the SHA-256 of
   its `from` is the offer's `to`, and the two `from`s differ;
3. each `time <= now + S` by the checker's clock, and the offer's
   `time` <= the acceptance's `time` <= the offer's `expires`;
4. each certificate is for its object's `from`, allows messages, and
   is valid at that object's `time` (§1);
5. the identity key's signature on each certificate, and each
   certificate's device key's on its object;
6. no withdrawal the checker holds ends it (§4).

A lone offer, checked as a server takes it, gets the steps that apply
to one object: 1 without the array, then 3 to 6. A client accepts an
offer only while its own clock is at most the offer's `expires`, and
dates the acceptance by that clock, so step 3's `<= expires` carries
no `S`.

These checks alone bound nothing in real time, since a `time` is its
signer's to write. What does is where the objects are taken: an offer
and an acceptance are each a live act at a server, which requires its
`time` within `S` of its own clock, either way (`portable-friends.md`
§4.1). Every half of an honest friendship is therefore dated by some
server's clock, give or take `S`.

That holds only where the acceptance is taken at a server. One handed
to a checker any other way, as Present Friendships hands it, can be
backdated: an acceptor can sign one months after the offer lapsed, dated
inside its window, with a certificate valid then. So `expires` bounds
the date an acceptor writes, not when it can complete a friendship. What
bounds that is that the offerer must present the friendship too, and its
client adopts an offer that comes back accepted only if it first sees
the acceptance before the offer's `expires` plus `S` by its own clock
(`portable-friends.md` §5.1).

---

## 4. Withdrawal

Domain `hl-identity/friend-withdraw/v1`. At most 1 KiB.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `from` | bstr(32) | yes | The withdrawing identity's public key |
| `pair` | bstr(32) | yes | The pair hash, below |
| `party` | bstr(32) | no | The fingerprint whose halves `before` dates; `from`'s if absent |
| `before` | uint | yes | Ends friendships whose half by `party` predates this |
| `time` | uint | yes | When it was signed; `before` is no later |
| `cert` | bstr | yes | |
| `sig` | bstr(64) | yes | |

The **pair hash** names two identities without saying which is which:

```
pair = SHA-256("hl-identity/friend-pair/v1" || 0x00 || lo || hi)
```

where `lo` and `hi` are the lesser and the greater of the two
fingerprints, compared as unsigned bytes, lexicographically.

A withdrawal **ends every friendship between the pair whose half by
`party` is dated before `before`**, wherever it is presented, for good.
One object covers a second friendship made elsewhere, a copy another
device still holds, and, where `party` is the offerer, a pending offer,
since a friendship made from it would have a half the withdrawal ends.
Where `party` is the offeree, a later acceptance postdates `before`,
and the friendship it makes stands. A withdrawal's
**effective party** is `party`, or with it absent the SHA-256 of
`from`, and is one of the pair. A party withdrawing on its own account
leaves `party` out; one spreading a withdrawal copies its effective
party and its `before`, naming that party unless it is the spreader's
own (`portable-friends.md` §5.3), so that a spread ends exactly what it
spreads and every cutoff is a time the withdrawer's side of the pair
was dated by. Each honest half and each withdrawal is taken at a server
within `S` of its clock (§3, below), so for honest halves a cutoff
compares times on servers' clocks, not on two devices'; a thief with a
device can date a half ahead, which only the device-act gate
(`portable-friends.md` §3) bounds. Making friends again takes a half by
the effective party that postdates the withdrawal: a new offer, or,
where that party is the offeree, a new acceptance, even of an offer
still open. A client holding a cutoff for a pair signs no half for that
pair until its own clock is past `before`, so that a friendship remade
from another device, whose clock runs behind, is not dated inside the
cutoff and ended when the cutoff reaches a server that did not yet hold
it. A server that holds the withdrawal refuses a half it would end,
and the client tries again later.

- **A withdrawal is a cutoff a client keeps, and signs afresh for each
  server it gives it to**: the same `pair`, `party` and `before`, and a
  fresh `time`. Servers take one only fresh and from a session of its
  `from` identity (`portable-friends.md` §4.3), with a `time` within
  `S` of the server's clock, and refuse a backdated or replayed one
  `Stale`.
  Nobody presents someone else's. A party's other devices and the
  friend's client spread a removal by signing their own.
- **Freshness is the server's check, not the client's.** A withdrawal a
  client is handed is old by nature, and the client checks it whole
  (below) without regard to how old its `time` is. A `time` in the
  future is another matter: a thief with a device could otherwise date
  one, and its `before`, at the certificate's expiry, and end every
  friendship the pair remade until then. So every checker refuses one
  past `now + S` (step 2 below).
- **It names the pair, not one friendship**, so anyone who knows both
  fingerprints can tell which pair it is for. A server holding the edge
  knows them anyway. It also carries its signer: `from`, and the
  certificate with its device keys and any `name`.
- **Checking it whole** needs both fingerprints. Its signature and
  certificate can be checked against its own `from` alone. A checker
  that holds no pair matching `pair` may keep a withdrawal checked by
  steps 1, 2, 5 and 6 below, and finishes steps 3 and 4 only once it
  matches a pair it holds; it applies nothing before both pass.

**Checking a withdrawal**, cheapest first:

1. size and `v`; and `party`, if present, is not the SHA-256 of
   `from`, which absence already says, so that each withdrawal has one
   encoding;
2. `before <= time`, and `time <= now + S` by the checker's clock;
3. the pair hash, recomputed from the two fingerprints the checker
   holds, is `pair`;
4. the SHA-256 of `from` is one of the two where the checker has
   applied no rotation of it, or the last key of a chain of rotations
   the checker has applied from one of the two (`portable-friends.md`
   §4.4); a chain that forks or loops has no last key. Any key the
   checker has seen rotated away from, wherever it sits in the chain,
   is refused as `from`, whatever the withdrawal's `party` and
   `before`, since the rotation may have retired it. The
   effective party is one of the two, and one that the checker has
   seen rotated away from has `before` no later than the `time` of the
   rotation away from it. A successor carries its predecessor's
   cutoffs over by signing them afresh, `from` its own key and `party`
   the predecessor, explicitly, since its own fingerprint is in no
   pair the old friendships make;
5. the certificate, by §1, at `time`;
6. the identity key's signature on the certificate, and the
   certificate's device key's on the withdrawal.

Step 4's rotation rule is checked when a withdrawal is taken, or when
one kept unchecked first matches a pair (above), against the rotations
the checker has applied then. A withdrawal already applied stays in
force when a rotation is applied later: an honest predecessor's cutoff
is still its owner's, and the successor's client signs it afresh. Nor
does a withdrawal whose `from` is a predecessor, or a spread of one,
count against a successor's offer to a friend of the predecessor: a
thief holding the old key can still sign one at a checker that has not
applied the rotation, and the friend's client that later learns of the
rotation sets it aside when the successor re-offers
(`portable-friends.md` §10).

---

## 5. Revocation

A device's revocation does not invalidate what it signed. A device is
revoked when it is retired as well as when it is stolen, and a
revocation does not say since when the device was not its owner's
(`identity-registrar.md` §4.4), so no checker could tell the
friendships a retired phone made from the ones a thief did. What bounds
a thief is where the objects can be used, which is
`portable-friends.md` §6's.

Nor does a certificate's expiry end what its key can sign. A key whose
certificate lapsed can still sign withdrawals, and halves, dated inside
its old window, and a client checks a withdrawal handed to it without
regard to its age (§4). A device that is retired is therefore revoked,
not left to lapse, so that the checks that consult revocation
(`portable-friends.md` §5.3, §6) reach it.

---

## 6. Test vectors

`identity-test-vectors.json` holds, in `friend_objects` and
`friend_pairs`, checked by `hl-identity`'s `tests/friendship.rs`, an
offer, its acceptance, the friendship's array bytes and its hash, a
pair hash with its input in hex, and a withdrawal by each party, one
with `party` naming the other, with a friendship each ends and one each
leaves standing, all checked at a stated `now` with `S` as above.

It holds rejections, in `friend_rejects`, as `rejects` and
`message_rejects` hold for the objects already there, each failing at
one step with no state beyond the object:

- an offer re-signed under the acceptance's domain, and under
  `hl-identity/message/v1`; a withdrawal re-signed under
  `hl-identity/vouch-withdraw/v1`;
- each object over 1 KiB, and with `v` other than 1;
- an offer whose `to` is its own `from`'s fingerprint;
- an acceptance whose `offer` is another offer's hash, and one whose
  `from` is not the offer's `to`;
- an acceptance dated before the offer's `time`, and one after its
  `expires`;
- an offer whose `expires` is more than 30 days after its `time`, and
  one whose `expires` is its `time`;
- arrays reversed, with a third element, with maps in place of byte
  strings, of indefinite length, and with a head not in its shortest
  form;
- a friendship whose certificate carries a bad identity signature;
- a withdrawal whose `before` is after its `time`, and one whose
  `party` is its own `from`'s fingerprint;
- a certificate for another identity, one without bit 1, and one over
  512 bytes, each for an offer, an acceptance and a withdrawal.

And it holds reads, in `friend_reads` and `friend_cert_window`, as
`message_reads` and `cert_window` hold them:
each case an object or a friendship with the state it is checked
against, a `now`, the pair's two fingerprints, the rotations applied
as a list of records, and the withdrawals held, and an `expect` of
accepted or the step it fails at. `keys` holds a successor and a
successor's successor for the chains below, with `rotate` and
`rotate_successor` between them.

- a pair hash whose offerer's fingerprint is the greater of the two,
  with its input in hex;
- an offer, and an acceptance, dated past `now + S`;
- a withdrawal dated past `now + S`, one whose `pair` is another
  pair's hash, one whose `from` is outside the pair, and one whose
  `party` is;
- across one rotation: a successor's withdrawal naming its
  predecessor, accepted; one whose `before` is after the rotation,
  refused; and one from the predecessor, refused;
- across two, A to A' to A'': a withdrawal from A', the middle key,
  naming A with `before` before the first rotation, refused, and one
  from A'' naming A, accepted;
- a withdrawal applied before a rotation, still ending its friendship
  once the rotation is applied, since a withdrawal held is not checked
  again;
- boundaries: a half dated exactly `before`, which stands, a
  withdrawal with `before` equal to its `time`, accepted, and one
  whose certificate has expired by `now` but was valid at its `time`,
  accepted;
- each boundary of the certificate's window, as `cert_window` holds
  them for a signed message.
