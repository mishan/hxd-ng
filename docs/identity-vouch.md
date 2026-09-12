# Vouching — standing lent by a member

Status: draft, unimplemented. Companion to `hotline-ng-identity.md` (whose
card reserves a `vouches` array and whose device certificate reserves
capability bit 2, `vouch`, both defined here), `identity-registrar.md`
(whose `proof` kinds gain `vouch`, and whose §7.3 newcomer delay and
create rule this document waives), `moderation.md` (which gains "vouched
by" and the penalty of §6), and `identity-threat-model.md` (which lists
vouches as an asset and a sybil vector and gets §9's entries).

---

## 1. Summary

A vouch is a member saying *I will answer for this key*. It is not a
statement that a key belongs to a particular person — that is the
registrar's handle — and it is not a link in a chain: a vouch counts
only when the voucher has standing of their own at the place it is
read, and a vouch from someone who is merely vouched counts for nothing.

What it buys the vouched key is the door: admission as the `vouched`
standing class (`identity-registrar.md` §7.5), which the operator's
admission policy may treat as it treats an attested key — the
`new_accounts` policy applies, the newcomer delay does not. What it does
**not** buy is age. A vouched key is new, its age runs from the moment
someone began answering for it, and it serves the same probation any
new key serves. Standing decides the door; the key's own age and own
record decide the room. What a vouch costs the voucher is one of a
small number of vouches they may have outstanding, and their ability to
vouch for a while if the key is banned.

The design is an invitation tree with the invitations signed, which is
the part of PGP's web of trust that ever worked, with the part that did
not — transitive trust and trust levels — left out on purpose.

Two forms, one meaning:

- **local**: a row on one server, made by a request from a logged-in
  account. Needs no identity key on the voucher's side, so a classic
  account can vouch. Counts on that server only.
- **portable**: a signed object the vouched identity carries in its
  card. Counts at any server where the voucher has standing. Needs the
  voucher to be an identity user with a vouch-capable device.

A server implements the local form first; the portable form is what
the card's `vouches` array is for and can follow.

---

## 2. Rules

These hold for both forms and are the whole of what makes vouching
safe. Everything after this section is mechanism.

1. **Depth one.** A vouch is counted only if the voucher has *direct*
   standing where it is read: an account there, or an attestation from a
   registrar trusted there. Standing that was itself obtained by a vouch
   does not qualify. A ring of fresh keys vouching for each other
   produces nothing.
2. **Binary.** A vouch exists or it does not. There are no levels,
   weights, or partial vouches, and nothing is computed across them
   except a count.
3. **Expiring and revocable.** At most one year; the voucher may
   withdraw it at any time; withdrawal takes effect at the vouched key's
   next admission.
4. **Bounded.** A voucher has at most `vouches_outstanding` (default 5)
   live at once and may make at most one new vouch per
   `vouch_interval` (default 7 days). The bound is what makes a vouch
   cost something.
5. **Accountable, not punitive.** A ban of a vouched key suspends the
   voucher's ability to vouch and is shown to moderators beside the
   voucher's name. It never bans the voucher.
6. **Deliberate.** A client presents vouching as an act with the
   consequence stated — "you will be shown as having vouched for this
   key, and you will not be able to vouch for 30 days if it is banned" —
   and never as a one-click button next to a stranger.

---

## 3. The local form

### 3.1 Who may vouch

An account with `[extra] vouch`, which derives true from the same rule
as `can_detach` in `access-bits.md`: a password *or* a linked identity,
so that `guest` and any other shared login cannot. An account that was
itself created by `new_accounts = create` on the strength of a vouch has
`vouch` derived false until the operator sets it, which is rule 1 for
accounts. The operator may set it either way per account.

### 3.2 Requests

On the ng wire:

| `req` | params | ok | notes |
|---|---|---|---|
| `vouch` | `fingerprint`, `expires?` (unix seconds, ≤ 1 year), `note?` (≤ 256 bytes, moderators only see it) | `{ "outstanding": n, "max": m }` | rule 4 enforced; `vouch_limit` / `vouch_cooldown` / `vouch_suspended` on refusal |
| `unvouch` | `fingerprint` | `{}` | |
| `vouches` | — | `{ "vouches": [ { fingerprint, handle?, expires, note } ], "outstanding", "max", "suspended_until"? }` | mine |

Errors: `access_denied` (no `vouch` extra), `no_such_user` (the
fingerprint is one the server has never admitted — a vouch is for
someone who has at least reached the door), `already_vouched`,
`self_vouch`, and the three above.

The same three as `POST`, `DELETE` and `GET` on `/identity/vouch`, for
a client that would rather do it over HTTP beside `link`; both paths
write the same row. The legacy wire has no way to name a fingerprint and
gets nothing; GtkHx, which can, uses the HTTP form.

### 3.3 Effect at admission

When an identity is admitted and has no accepted attestation, the
server looks for live local vouches for its fingerprint whose voucher
still satisfies rule 1 *now* — the account exists and is not banned,
its `vouch` extra is still true, and it is not suspended (§6). If at
least one exists, the identity's standing class is `vouched`
(`identity-registrar.md` §7.5):

- `[identity.admission] vouched` decides admission, in place of
  `unknown`; `new_accounts` applies;
- `newcomer_delay` (`identity-registrar.md` §7.3) is 0 — someone
  answers for the key, which is what the delay was pricing;
- its **own age** is the `time` of its earliest live vouch here. Not
  the voucher's age: a vouched key is a new key, and probation
  (`identity-registrar.md` §7.5) runs on its own age and its own record
  exactly as for a young attested key;
- `outcome` in the `auth` response is as for an attested identity, and
  the response gains `"vouched_by": n`, a count. The roster shows
  nothing: a vouch is between the voucher, the vouched and the
  moderators.

Nothing else changes. A vouched identity is still whoever it is; a
vouch is not a handle, and a server that shows handles shows none for
it.

---

## 4. The portable form

### 4.1 The object

Domain `hl-identity/vouch/v1`. Signed by the voucher's identity key, or
by a voucher's device key whose certificate carries the `vouch` bit
(`hotline-ng-identity.md` §3.3, bit 2), with the certificate embedded as
the device-revocation record does. At most 8 KiB encoded, which allows
the certificate and one attestation.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `voucher` | bstr(32) | yes | Voucher's identity public key |
| `subject` | bstr(32) | yes | Vouched identity public key |
| `time` | uint | yes | |
| `expires` | uint | yes | At most one year after `time` |
| `scope` | tstr | no | A server or registrar host; absent means anywhere the voucher has standing. A vouch for a registrar's signup is scoped to it (§5) |
| `predecessor` | bstr(32) | no | §7: "the subject is the person who held this key" |
| `attestation` | bstr | no | One of the voucher's attestations, so the vouch verifies with no lookup at a server that trusts that registrar |
| `signer` | bstr(32) | no | Present when a device key signed |
| `signer_cert` | bstr | no | Required with `signer`; must carry `vouch` and be valid at `time` |
| `sig` | bstr(64) | yes | |

Withdrawal is `hl-identity/vouch-withdraw/v1`: `v`, `voucher`,
`subject`, `time`, the same signer rules, `sig`. A withdrawal is
published where the vouch would be read: posted to the registrar's
`records` if the voucher is attested there, and posted to any server
the voucher is on. A server that has seen a withdrawal ignores every
vouch by that voucher for that subject with `time` before the
withdrawal's.

Web-client certificates omit the `vouch` bit, as they omit `manage`, so
a script in a browser cannot spend the user's vouches. A tunnel or
native client carries it when the user means to vouch from there.

### 4.2 In the card

The vouched identity embeds vouches for itself in its card's `vouches`
array, at most 8, each a fully signed object. The rules of the identity
spec's §13 apply — the card's own envelope is verified first, the count
is capped, cheap fields are checked before signatures — because each
one is a signature check an unauthenticated caller can request.

### 4.3 Effect at admission

For each vouch in the card whose `subject` is the identity, `expires`
has not passed, `scope` is absent or names this server, and signature
verifies: the server decides whether the **voucher** has standing here
under rule 1 —

- an account on this server links the voucher's fingerprint and is not
  banned, and has `vouch` true; or
- the embedded `attestation`, or one the server has cached for the
  voucher, is from a trusted registrar and is not revoked (which may
  cost a records fetch, cached as `identity-registrar.md` §7.2 caches
  everything else).

If so, the vouch counts exactly as a local one (§3.3); the subject's
own age runs from the vouch's `time`. If not, it is ignored, not
refused: a card may carry vouches from people this server has never
heard of, and that is fine.

A portable vouch is subject to rule 4 at the voucher's *registrar*, not
at every server that reads it — no server can see the voucher's
outstanding count elsewhere. §5 says how the registrar enforces it;
a voucher with no registrar is bounded only by the card's cap of 8 and
by each server's own limit on vouches it will count per subject
(`vouches_counted`, default 3).

---

## 5. At a registrar

`identity-registrar.md` §5.3's `proof` kinds gain **`vouch`**: a
registration request's `proof` is a base64url portable vouch with
`scope` equal to the registrar's host and `subject` equal to the
request's `identity`. The registrar accepts it when the voucher is
attested there, not frozen, not suspended (§6), and under their
`vouches_outstanding` — which the registrar knows, because every vouch
it accepts as proof is recorded against the voucher, and a voucher's
outstanding vouches are the ones it has recorded with `expires` in the
future. The registrar writes `level` 2 for a vouched signup, which is
what §5.3 there says level 2 means.

A registrar also accepts portable vouches and withdrawals on `POST
records` from attested vouchers, and includes them in the per-identity
list for both `voucher` and `subject`, so that a server fetching records
for a vouched identity gets its vouches and their withdrawals in one
place. The outstanding count is enforced there too. This is the one
mechanism that bounds a portable voucher across servers, and it is why
a portable vouch is worth more from an attested identity than from a
bare key.

The count is a bound, not a judgment. Whether a registrar should also
learn that a voucher's vouched keys keep getting banned — and refuse
`proof = vouch` from them — is `identity-registrar.md` §6.7, which
defers the server-to-registrar report it needs to the federation spec
and says what the registrar may do with one when it exists: use it for
that one decision, and publish only an aggregate.

---

## 6. Accountability

When a server bans an identity (kick with ban, `moderation.md`'s
`purge`, or the ban list), it looks up who vouched for that identity —
local rows, and portable vouches it counted at the identity's last
admission — and for each voucher with an account here:

- sets `vouch_suspended_until = now + vouch_penalty` (default 30 days);
  their existing vouches stop counting for that period and they may
  make no new ones;
- writes an audit row, `vouched_banned`, naming voucher and vouched,
  which the moderation UI shows beside the voucher's name for as long
  as the suspension lasts;
- **does not** ban, kick, restrict or message the voucher.

For a portable voucher with no account here, the server does nothing
today. When the federation spec defines an authenticated
server-to-registrar report (`identity-registrar.md` §6.7), a server MAY
send one to the voucher's registrar; the registrar keeps it private
and uses it for nothing but its own `proof = vouch` decision. **A
suspension is never published as a record**, and never reaches another
server: it is a month without vouching at the server that banned the
key, and that is all it is.

A moderator's report view and the audit table gain a `vouched_by`
column for any subject that was admitted on a vouch. Every ban decision
about a vouched key is made with the voucher's name in front of the
moderator, which is the accountability this document means: visible,
and mild.

---

## 7. Standing after loss

`identity-registrar.md` §8.3 leaves a recovered identity a stranger at
every server that never saw a rotation, because there is no rotation to
see. Vouches with `predecessor` set are the social form of one:
"*I vouch that this key is the person who held that key.*"

A server that holds at least `social_recovery` (default `0`, off) such
vouches for the same `subject` and `predecessor` pair, from distinct
vouchers each with standing here, whose `predecessor` is a fingerprint
this server has an account link for, MAY move the link exactly as
`identity-registrar.md` §7.4 moves it on rotation, and logs every
voucher. With the default of `0` it does not: the vouches are shown to
the operator as evidence — "three members vouch that `7f3a…` is the
person who was `alice`" — and the operator moves the link by hand.
Servers that would rather automate it set a number, and three is the
smallest number this document would suggest.

A `predecessor` vouch is otherwise an ordinary vouch and counts for
admission like one.

---

## 8. Settings

| Setting | Default | Meaning |
|---|---|---|
| `[identity] vouches_outstanding` | `5` | Live vouches one account may have (rule 4); also the registrar's bound in §5 |
| `[identity] vouch_interval` | `604800` | Seconds between new vouches by one account |
| `[identity] vouch_penalty` | `2592000` | Suspension after a vouched key is banned (§6) |
| `[identity] vouches_counted` | `3` | Portable vouches a server will verify per subject |
| `[identity] social_recovery` | `0` | §7; `0` shows evidence only |
| `[identity.admission] vouched` | `allow` | What the `vouched` class is admitted as (`identity-registrar.md` §7.5) |
| `[extra] vouch` (per account) | derived (§3.1) | May this account vouch |

Probation for a vouched key is `[identity.probation]`, defined in
`identity-registrar.md` §7.5 and §11; nothing about it is
vouch-specific.

Registrar side, `[registrar] proof = vouch` beside the existing kinds.

---

## 9. Threat model deltas

- **Vouch rings.** Sybils vouching for sybils. Rule 1: none of them has
  standing, so none of the vouches count, however many there are.
- **Coercion and social pressure.** A member vouches because refusing is
  awkward, and a harasser arrives with a real name attached. Rules 4
  and 6 are the defenses: a vouch is scarce and its consequence is
  stated at the moment of giving it. This is the realistic failure and
  it is not fully solvable; what §6 guarantees is that the member who
  vouched sees the consequence and the moderator sees the member.
- **Punishing a voucher through their vouched.** Getting someone's
  friend banned to suspend the friend's vouching. Bans are moderators'
  acts, and the penalty is a month without vouching, not a month
  without the server. Low value to an attacker.
- **Social graph exposure** (threat model asset 7). A portable vouch in
  a card is public, and says who knows whom. The local form reveals
  nothing outside the server's own tables and moderation UI, which is
  why it is the default and the portable form is the user's explicit
  choice, made with that stated. A registrar's per-identity record list
  also carries portable vouches; that is a disclosure the user makes
  when they choose the portable form.
- **A stolen vouch-capable device** can spend the user's vouches on the
  attacker's keys until revoked. Rule 4 bounds it to five; §6 makes each
  one visible; the device revocation is the fix. Web clients cannot do
  it at all.

---

## 10. Amendments this document needs in its companions

- `hotline-ng-identity.md` §3.3: capability bit 2 `vouch` — "may sign
  vouches and withdrawals (`identity-vouch.md` §4.1)". §3.4: `vouches`
  — "portable vouches for this identity, at most 8, `identity-vouch.md`
  §4.2". §5.3: `vouched_by` in the `auth` response. §11: "or vouched"
  wherever "attested" gates a policy, and one row for §3.3 here.
- `identity-registrar.md` §5.3: `proof = vouch`; §6.2: vouches and
  withdrawals accepted on `POST records` and indexed under both keys;
  §7.3: "no vouch" in the newcomer-delay and create rules already reads
  this document.
- `access-bits.md` §4: the `vouch` extra, derived as §3.1 says.
- `moderation.md`: the `vouched_banned` audit row and the `vouched_by`
  column; the suspension written by every ban path.
- `hotline-ng.md` §7: the three requests of §3.2.
- `identity-threat-model.md`: §9 here, replacing its one-line entries
  for vouches.

---

## 11. Open questions

- ~~Should a vouch confer an age?~~ **Decided: no.** An earlier draft
  borrowed the voucher's age, which let a day-old key pass a one-year
  threshold on one old member's word and conflated "answered for" with
  "known for a while". A vouched key now has its own age from the vouch
  and serves probation like any new key (§3.3, `identity-registrar.md`
  §7.5).
- **Vouching for a legacy account.** A classic account has no
  fingerprint to vouch for. It also has no need: its password is its
  standing. Left out.
- **Mutual vouches.** Two members vouching for each other is fine and
  common. Two fresh keys doing it is nothing (rule 1). Nothing to add,
  but worth a test.
- ~~Whether a registrar's penalty should be published.~~ **Decided:
  no record, ever.** A published penalty is a ban travelling by a side
  door, needs the registrar to trust servers, and turns a mild local
  consequence into a permanent public mark. What is kept is
  `identity-registrar.md` §6.7: a private report from an allowlisted
  server, used by the registrar for its own `proof = vouch` decision
  only, and an aggregate count in its stats. Both wait on the federation
  spec's server-to-registrar message.
