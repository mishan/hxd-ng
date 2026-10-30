# Proposal: portable friends for the Instant Messaging extension

Status: proposal. PF1 and PF2 (§8) are built: the objects in
`hl-identity`, and the server and the ng wire (`hotline-ng.md` §7.5).
Of PF3, device proof on the classic wire (§3) is built, on a server
with an ng port; Present Friendships and Get Friendships are not.
Builds on `instant-messaging.md`,
hxd-ng's implementation of fogWraith's
[Capabilities-Messaging.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Messaging.md)
("the extension"), on the extension's
[Capabilities-Messaging-Identity.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Messaging-Identity.md)
("the identity draft"), of which §4 and §7 would become the draft's
second version, and on the signed objects of `friendship-objects.md`
("the objects"), which it would cite. Also on `hotline-ng-identity.md`
("the identity spec"), `e2e-messages.md` and `private-messages.md`.

---

## 1. Summary

The extension makes a friend an account Login on one server. That is a
messenger for one server's members: the friendship, the people in it and
the trust put into it end at that server's edge, and a person who uses
three servers makes the same friend three times, trusting each server's
word each time that the friend is who it says.

The identity draft puts the identity fingerprint beside the Login, so a
client can recognize the same person under another Login or on another
server, and lets two such friends sign and seal what they send. It
leaves the friendship itself where the extension put it: a row each
server keeps, made by that server's own request and response.

This proposal moves the friendship to the two people. When both
accounts are linked to identities and both clients implement it,
accepting a friend request produces a **friendship**: an offer signed by
one party's device and an acceptance signed by the other's, naming both
identities (the objects, §2 and §3). Each client keeps it and, on a
server where the user chooses to, presents it, where it becomes an
accepted roster entry with no new request once the friend has presented
one there too. Ending it is a signed withdrawal by either party, which
ends every friendship between the two whose withdrawer's half predates
it, wherever it is presented.

What it buys:

- **Friends once, everywhere.** A friendship made on one server is in
  place on the next server both people bring it to.
- **Trust on first contact, once.** The first friend request trusts the
  server that carried it to show the right fingerprint, as now. After
  that the key is pinned in the friendship, and someone on another
  server under another key is visibly not that friend.
- **Friends across links.** A ghost's home server can say its
  fingerprint (`server-link.md`, `DATA_LINK_USER_KEY`, sent for a
  connection that proved an identity while `[identity] login_proof_v1`
  is off), so a client can recognize a friend's key on a linked server
  without either server keeping a row for it.

What it does not do:

- **Prove that a session is the friend.** A friendship proves a
  relationship between two keys. Which Login or ghost holds a key is a
  server's word, and only a signed or sealed message proves who sent it
  (§9).
- **Carry presence or messages between servers that are not linked.**
  That is federation, and nothing here is a step toward it that would
  have to be undone.

Accounts without an identity, and clients that do not implement this,
keep `instant-messaging.md`'s model exactly. The two kinds of edge sit
side by side on one roster.

---

## 2. Edges, and consent

**A friendship is between two identities, and an edge is a server's
friendship between two of its accounts**, the pair-level fact with an
id of `instant-messaging.md` §3. There is
still at most one edge per pair of accounts, now of one of two kinds:

- **local**: made by Add Friend (802) and Friend Response (805) on this
  server when the two accounts are not both identity-linked, or a
  client on either side does not implement this. The extension's
  friendship, as `instant-messaging.md` has it.
- **portable**: between two identity-linked accounts, active once each
  party has presented a friendship between the two identities here
  (§4.3). They need not have presented the same one: two people who
  made friends on two servers before either was presented at the other
  hold two friendships, and either serves. A local edge between two
  identity-linked accounts becomes portable when they make a friendship
  here, or once both have presented one, keeping its id and its
  aliases; until then it stays the local edge it was. A withdrawal
  presented here ends a local edge between the pair made before its
  `before`, as it ends a friendship.

Everything the extension says about an accepted entry applies to both
kinds alike. The kinds differ only in how the edge comes to exist and
how it ends.

**Each party's consent is per server.** A portable edge is active only
once *each* party has presented on that server. One party cannot make a
friendship visible on a server the other has not taken it to, which is
how a person keeps a friend off a server: by not presenting there.
Removing a friend from a device that implements this is a withdrawal,
and ends the friendship everywhere (the objects, §4); removing one from
a password session, or from a client that sends no withdrawal, ends it
on that server only (§4.3). This is a rule honest servers keep; §9
says what a dishonest one can do instead.

---

## 3. Device acts

**Every friendship act is a device act.** Offering, accepting,
presenting and withdrawing are open only to a session that proved a
device certificate of the account's linked identity, as the identity
draft's sealed-capable sessions do, and whose certificate is unexpired
and not revoked as far as this server knows at the time of the act, not
only at login, since a resumed ng session outlives its login. An offer,
an acceptance or a withdrawal the session gives as its own act is signed
by that same certificate. A password login alone never qualifies, even
to an identity-linked account (`identity-registrar.md` §7.3 keeps such
accounts reachable by password after a revocation); it can still remove
a friend, as the extension requires, but only here. This is what bounds
a stolen device (§6).

On the classic wire, a session proves a device inside the `/trtp`
tunnel (`hotline-ng-identity.md` §8.3), or on any TRTP connection with
Prove Device, below. A classic client behind `hlid tunnel` never holds
the key and leaves bit 13 and `CAPABILITY_FRIENDSHIPS` (§7) off, so it
keeps the extension's model unchanged. A client that holds a device key
itself, GtkHx among them, proves it with Prove Device on whatever port
it reached, so a server with no ng port, as Janus and every other
plain-TRTP server is today, can see a device proved, and link one,
once it implements the two transactions.

**Proving a device on the classic wire** is a standalone extension,
not messaging's, under a capability bit of its own,
`CAPABILITY_DEVICE_PROOF`, with transactions and fields fogWraith
places outside messaging's ranges, since the identity draft's sealed
messages and the server link's user keys draft need a proved device as
much as friendships do. It is the challenge binding of
`hotline-ng-auth.md` §6.2 carried in two transactions, with objects of
the same shape under domains of their own: a **TRTP server challenge**,
domain `hl-identity/server-challenge-trtp/v1`, with the server
challenge's keys, and a **device proof**, domain
`hl-identity/device-proof/v1`, with the login proof's keys, `v = 1`,
and `exporter` below. Neither verifies as the other's ng counterpart,
so a challenge the ng port signed cannot be passed off as a TRTP one,
nor a device proof spent at the ng port's `auth`, which ignores keys it
does not know and so could never be kept from it by a key alone.

1. **Get Device Challenge** carries `DATA_PROOF_HOST`, the address the
   client dialed in §6.2's form of a host, port included. The server
   answers with `DATA_SERVER_CHALLENGE`, a TRTP server challenge signed
   for that host, or fails with no reason code where it does not answer
   as that host, has no server key, or the host's port is not the
   listener the request arrived on, so that a challenge for the TLS
   port is never signed on the plain one. The classic names it answers
   as are configured apart from the ng port's (`[identity]
   classic_hosts`, beside `hosts`), since they carry the classic ports.
   A client checks it as §6.2 has a client check a server challenge,
   under its own domain, against the key it pins for that host as
   `server-key-handover.md` §5.1 pins one, trusting it at first
   contact, and follows a handover only as that document has it; a
   challenge's `next` is what lets it. A session holds one challenge at
   a time; a new request replaces it.
2. **Prove Device** carries `DATA_DEVICE_PROOF`, a device proof signed
   by the device key for that challenge, and `DATA_DEVICE_CERT`,
   the device's certificate, and may carry `DATA_USER_CARD`, the
   identity's card. The server runs §6.2's checks on it, the challenge
   spent whatever follows, refusing it if `exporter` is present on a
   session whose server side is not TLS 1.3 or absent on one that is,
   and then the identity profile's admission as
   an ng login has it (`hotline-ng-identity.md` §5.2 steps 2 to 6, with
   the card it carries or the one the server holds): the certificate is
   the proof's `device`, signed by its identity, within validity, with
   the login capability and at most 512 bytes; not
   revoked as far as this server knows; and admitted by the allow list
   and the admission classes, under probation's mask. The identity must
   be the one the account links, and the account must allow identity
   login (`identity_login`). It answers with an empty reply, or with
   the ordinary error reply, as extensions outside messaging report
   theirs: one text for a proof outside the server's clock-skew
   tolerance, so the user can fix the clock, and one for every other
   failure, revocation, admission and a wrong identity included, so
   that the answer says nothing of why. A device acts for friendships
   and sealed messages only where its certificate also allows messages
   (§3 above, the identity draft).

**Proving can link.** On an account linked to no identity, a Prove
Device that carries the identity's card, from a certificate with the
`manage` capability, links the account as the ng port's "at auth" does
(`hotline-ng-identity.md` §8.2): the account must allow self-linking,
the session must have logged in with its password and be encrypted
(TLS 1.3, or HOPE with a cipher), since on a plain session someone
riding it could link the account to an identity of their own, and the
identity must be linked to no other account here; otherwise it answers
with the ordinary error reply, as any failure is, and links nothing.
So a server with no ng port can link as one with one does. A
password-less linked account cannot make the classic Login (107) that
comes first (§8.3 there), and proves its device in the tunnel alone.

A session proves one device, once: Prove Device on a session already
device-proved, the tunnel's included, fails with no reason code. From
then on the session is device-proved with that certificate for its
life, and with bit 13 it is sealed-capable. A client proves before it
joins the user list, so that its fingerprint is there from its first
announcement: it leaves User Name (102) and User Icon ID (104) out of
its Login (107), which would otherwise announce it at once, sends them
in Agreed (121), and proves between the login reply and 121; a server
takes both transactions in that window. A proof made after joining
holds here, but its fingerprint is not exported over a link
(`server-link.md`), whose sessions keep the fingerprint they were
announced with. A client also proves before Get Roster (800), as it
withdraws (§4.3).

On a TLS 1.3 connection the proof also carries `exporter`, the TLS 1.3
exporter value (RFC 8446 §7.5) under the label
`EXPERIMENTAL-hl-identity-device-proof`, as the server link's key proof
labels its own, an empty context and 32 bytes, never the early
exporter, which the server checks against its side of the connection,
so that a proof cannot be carried onto another connection. Under TLS
1.2, which the TLS port also allows, an exporter (RFC 5705) is bound to
the connection only with the extended master secret (RFC 7627), which
cannot be relied on, so the proof is as on a plain connection. There
nothing binds it, and someone in the middle could ride a proved
session; it still signs nothing, since every friendship act and sealed
message is the device's own. `[identity] classic_proof` is `any`, the
default, or `encrypted`, which refuses Prove Device on a session
`hotline-ng-auth.md` §8 does not count encrypted: TLS, or HOPE with a
cipher, not HOPE's password MAC alone. Both transactions are rated as
§4.3 rates presenting, per account and per address, so that
reconnecting buys nothing: a challenge costs a signature and a proof
several checks and perhaps a registrar's fetch, and the one challenge a
session holds bounds only what challenges hold.

**The Login is still the address on the wire.** The extension's
transactions name a Login, and they keep doing so. A portable edge is
reported under the Login of the account that links the friend's
fingerprint here, with `DATA_FRIEND_IDENTITY` beside it, as the identity
draft already has it. Edges are keyed by identity where there is one,
as `instant-messaging.md` §3 keys every relationship, against the
identity draft's "roster rows … stay keyed by Login" (a deviation that
document lists, §8). The other amendments this makes to the identity
draft are listed in §8.

A **hidden link** is an account's link to an identity that this server
would not show an ordinary user: the fingerprint's mapping to a Login,
as Find User by `DATA_FRIEND_IDENTITY` and an entry's
`DATA_FRIEND_IDENTITY` would reveal it. It hides an account while it is
offline only; a session that proved the identity shows its fingerprint
on the ng user list (`identity.fingerprint`) and to linked servers
(`DATA_LINK_USER_KEY`) whatever the link's setting.

---

## 4. On a server

### 4.1 Making one

A friendship is made when both accounts are identity-linked and the
sending client puts an offer in Add Friend (802). Whether the target's
client implements this is learned at its answer, so the target account
being linked is all the server checks first. An 802 without an offer
makes a local edge, as the extension describes.

- **Add Friend (802)** carries the offer, from a device-proved session
  signing with its own certificate (§3). The server checks that its
  `from` is the identity linked to the sending account and its `to` the
  fingerprint linked to the target Login, that its `time` is within `S`
  of the server's clock either way (the objects, §1; else `Stale`), and
  the offer itself (the objects' §3 steps 1 and 3 to 5 as they apply to
  one object). A target that has blocked the sender is answered as
  `instant-messaging.md` §4.1 answers a block, before anything else. A
  target that is not linked, whose link this server would not show the
  sender, or whose fingerprint is not `to`, is answered
  `AccountNotFound`, one answer for all three, so an offer cannot test a
  guess at a hidden link; a hidden link counts as shown where the target
  has presented a friendship naming the sender (§4.3). After those, step
  6: an offer with a half a withdrawal held here ends is refused
  `Withdrawn`, and the client tries again later. The server stores the
  offer as the extension stores a pending request, and delivers it in
  **Friend Request (804)**, now or at the target's next login, with the
  offer to the target's sessions that negotiated both bits (§7) and as
  a plain request to the others, unless the sender is held or dropped
  (`instant-messaging.md` §4.4), when the offer is stored nowhere. An
  offer past its `expires` lapses as `instant-messaging.md` §3 has
  everything lapse, at its next read and with no hold or notice: the
  offer is dropped and the request stays, plain, which a plain 805
  accepts as a local edge, so that a client that never saw the offer
  sees its request as the extension has it.
- **An 802 with an offer on an existing edge**, local or portable,
  between two identity-linked accounts, an **upgrade offer**, is not
  `AlreadyFriends`: it is answered `OK`, the edge stays `Accepted` on
  both rosters, and the offer is delivered as an 804 only to the
  target's sessions that negotiated `CAPABILITY_FRIENDSHIPS` (§7),
  since a client that did not would show a request from someone
  already its friend. Its acceptance makes a local edge portable, or
  replaces both parties' presentations on a portable one (§10's move),
  keeping the edge and its id either way. Its rejection, or a plain
  805 from a client that cannot sign, drops the offer and nothing else,
  where the extension's rejection drops both rows. It asks nothing new
  of the target, so it is outside `instant-messaging.md` §4.4's
  friend-request bounds, ledger and holds, and it lapses, is declined
  or is canceled touching the offer alone.
- **Friend Response (805)** accepting carries the whole friendship,
  which the accepting client builds from the offer it was sent, from a
  device-proved session signing the acceptance with its own
  certificate. The server checks that it is the stored offer's, that
  the acceptance's `time` is within `S` of the server's clock either
  way (else `Stale`), that the acceptance's `from` is the
  identity linked to the accepting account, and the friendship itself,
  refused `Withdrawn` if a withdrawal held here ends it.
  It stores the edge as portable and as presented by both parties (they
  made it here), and sends both parties' sessions the Roster Entry
  (801) the extension requires, with the friendship's hash in it
  (§4.2).
- **A plain 805** accepting an offer with no edge behind it, from a
  client that cannot sign an acceptance, makes a local edge. The offer
  is dropped, not kept.
- **Remove Friend (803) on a pending request** cancels it and carries
  no withdrawal, which would end every friendship between the pair: the
  offerer's adoption rule (§5.1) and activation by both parties already
  keep a canceled offer from becoming a friendship anywhere. An 803
  carrying an upgrade offer (`DATA_FRIEND_OFFER`) cancels that offer
  and keeps the edge.
- **Crossing requests.** An 802 carrying an offer that meets the
  target's pending request to the sender is answered `RequestPending`,
  as the extension has it; one without an offer is answered as the
  extension, or message requests where a server implements them
  (`instant-messaging.md` §3), answers it; a client that implements this
  answers the pending request with an 805 instead. Once both accounts
  of a local edge are linked, whichever client learns it first sends an
  upgrade offer; two that cross are harmless, since the first
  acceptance makes the edge portable and drops the other offer.

A message request (`instant-messaging.md` §4) answered with Add Friend
carries an offer in the same way.

### 4.2 Showing one

A portable edge's roster entries (800, 801) carry the hashes of the
friendships each party presented, one or two, to the two parties'
sessions that negotiated `CAPABILITY_FRIENDSHIPS`, so that each device
of each party learns of them once it shares a server with the edge.
Get Roster streams its entries as separate 801s, one of the forms the
extension allows, whenever its reply would pass the frame bound the
server sets (hxd-ng's is 256 KiB). The friendships
themselves are a few kilobytes each, and a roster of hundreds sent
whole at every login would be megabytes for every device, so a client
asks for the ones whose hash it does not hold with **Get Friendships**:
at most 32 hashes, answered for each with the friendship, or with
nothing where the hash is not one this caller's account was sent in
the entry of an active edge, so that a hash tells a stranger nothing
and an inactive edge stays shown to nobody. It also takes a friend's
fingerprint, for the rotation records behind it (§10), answered only
for the fingerprint in an active edge's entry this caller's account was
sent. It is open to the sessions Present Friendships is (§4.3), and
rated as presenting is, with no signature to check.

A `Removed` entry for a portable edge ended by a withdrawal carries that
withdrawal, to the same sessions. The extension says a removal carries
only `DATA_FRIEND_LOGIN`; this adds a field a client that does not know
it ignores. A `Removed` without one ends the edge on this server only
where an account was deleted or unlinked or a client removed without
sending one; where `AccessMessaging` was revoked or a device's
revocation applied, it leaves the edge inactive with its id (§4.3,
`instant-messaging.md` §6).

### 4.3 Presenting one

**Present Friendships** is a new request carrying friendships and
withdrawals, at most 32 objects and at most one withdrawal per pair,
since the reply names a withdrawal by its pair hash; a request with more
is a failure with no reason code, and a client with two withdrawals for
one pair sends them in separate requests. It is open only to
device-proved sessions (§3) that were confirmed `CAPABILITY_MESSAGING`
(bit 6) and negotiated bit 13 and `CAPABILITY_FRIENDSHIPS`. The server
applies a request's
withdrawals before its friendships.

A client finds a friend first with Find User (822) by
`DATA_FRIEND_IDENTITY`, which the identity draft defines, and presents
only friendships whose other party it found. A fingerprint tells the
server less than a friendship, which names both people and their hash.
Presenting still answers for a friend who is not there, so a client
that skips the lookup is told, not misled. A client whose own link is
hidden here presents without the lookup, since its friend cannot find
it until it has, and two hidden parties would otherwise wait on each
other for good.

For each friendship the server checks, in this order:

1. the friendship (the objects' §3 steps 1 to 5), and that one of its
   identities is the presenting account's linked fingerprint: else
   `BadSignature`; then, unless it is for an edge already active, the
   presenter's own bound on inactive presentations (below), else
   `RosterFull`, before anything of the other party is looked at;
2. the other party: if it has no account here, or one messaging
   refuses, or one that has blocked the presenter here, it answers
   `AccountNotFound`, keeping nothing new and changing nothing it
   already holds, as Find User answers all three;
   and the same if the presenter has blocked it here, which tells the
   presenter only of its own block, and leaves the client to present
   again after an unblock;
3. withdrawals: if one it holds ends the friendship, `Withdrawn`, unless
   the other party's link is one step 4 would hide, when it answers
   `AccountNotFound` and keeps nothing new;
4. if the other party's link is one this server would not show the
   presenter, `AccountNotFound` too, but it records the presentation
   (below), since activation needs both parties and so shows nobody
   anything the hidden party has not chosen;
5. otherwise `OK`, and it records that this party has presented it,
   replacing any friendship this party presented here for the pair
   before. A replacement on an active edge sends both parties'
   sessions its entry again, with the hashes it now carries.

When each party has presented a friendship for the pair, the edge is
active and both are sent its 801 as for a new friend. Activation is a
friendship between the pair for `instant-messaging.md` §4: it ends a
pending friend request between the two, ends an approval (§4.6 there)
and moves the messages queued on it onto the edge, and delivers a
waiting message request's messages on the edge, each released as a
flush (§5 there). An edge left inactive
by a dropped presentation (§6) keeps its id while the other party's
presentation stands, as a suspended edge does, so the messages queued
on it are released when it is active again.

An active edge counts toward each party's `MaxRosterSize`, as
`instant-messaging.md` §4.4 counts roster states, in place of any
pending request or approval between the pair that its activation ends.
Past the presenter's own, it does
not become active: the presentation is kept and the presenter answered
`RosterFull`, its own count. Past the other party's, the presenter is
answered `OK`, since the other party's roster is not the presenter's
business, and the edge becomes active when the other party next
presents or has room. Presenting again for an edge already active is
never `RosterFull`. An inactive presentation is shown to nobody and
does not count toward the cap, so that a cap's answer says nothing of a
hidden party. Inactive presentations are bounded on their own, at
`MaxRosterSize` per presenting account; past it a presentation is
refused `RosterFull` at step 1, rather than an older one dropped while
the client still records it as presented. The bound counts every
friendship the account has presented here that is not active, whether
step 4 recorded it or step 2 kept nothing of it but its hash, as the
identity draft has it, so that reaching it says nothing of which other
parties were hidden. A
party's presentations are dropped when it unlinks or its account is
deleted; its withdrawals are kept.

**A hidden link.** An account whose identity link this server would not
show is not found by others. Presenting a friendship is that account
holder's consent to be found by the friend it names, and only by them,
and only until it is withdrawn: Find User, Add Friend and Present
Friendships from that friend's account answer as for a shown link, and
the friend's entry for it carries `DATA_FRIEND_IDENTITY`. Remove
Friend (803) naming a party with which the presenter has only an
inactive presentation drops that presentation, so the consent can be
taken back on one server without a withdrawal everywhere; it may name
the party by `DATA_FRIEND_IDENTITY`, since a hidden party's Login is
one the presenter cannot learn. It is answered `OK` whether or not
there was a presentation to drop, so it cannot test for a hidden
party.

For each withdrawal, the server checks it: fresh, from the `from`
identity's device-proved session, signed by that session's own
certificate (§3), with a `time` within `S` of the server's clock,
else `Stale`. It applies it to whatever presentations and, where its
`party` is the offerer, pending offers it ends, and keeps it in any
case, so that what it ends cannot be presented here later. One for a
pair of which it holds nothing cannot be checked whole (the objects,
§4), and is kept unapplied until a friendship for that pair is
presented, against which it is then checked. At
most `MaxRosterSize` of an account's are kept, its oldest dropped
first, the server's own (below) last. An evicted withdrawal no longer
stops another device bringing back what it ended, which is why the
bound is generous.

**Applying a withdrawal**, however it arrives (Present Friendships,
Remove Friend (803), Block User (806)), drops the presentations and
pending offers it ends, and the edge follows what is left. Where each
party still has a presentation standing, as where a friendship made
after a rotation outlives the old pair's withdrawal (§10), the edge
stays active, and both parties' sessions are sent its entry again. Where
one party has none, it goes inactive, and both are told `Removed` with
the withdrawal (§4.2). Unlike an edge a dropped presentation leaves
inactive (§6), it takes a new id when it is next active, since whatever
activates it is a friendship made after the withdrawal, and the messages
queued before it stay held until retention takes them
(`instant-messaging.md` §5). Where neither has one, it is deleted as the
extension's mutual removal deletes it, both are told `Removed` with the
withdrawal, and the removed party, the one that is not `party`, is held
as Remove Friend (803) holds a sender in `instant-messaging.md` §4.4,
since a spread is signed by the removed side itself.

Blocking stays a server's matter, as the extension has it. A block by
an identity user withdraws and then blocks locally. The withdrawal
reaches the friend's other servers as removal, never as a block, so the
extension's block confidentiality holds.

**Removal without a withdrawal.** Remove Friend (803) or Block User
(806) on a portable edge from a client that sends no withdrawal, or
from a password session, which cannot, ends the edge here, and the
server records a withdrawal of its own for the remover, dated by its
clock, that applies on this server only. Without it, the remover's
other devices, which keep their own record of what they presented,
would bring the edge straight back. An 803 or 806 whose withdrawal is
refused `Stale` still removes the friend here in the same way, and is
answered `Stale` so that the client can sign afresh for its other
servers.

**The reply** carries a group for each object in the request: the
friendship hash, or for a withdrawal its pair hash, and a reason code.

| Reason | For | The client |
|---|---|---|
| `OK` (0) | presented, or a withdrawal taken | records it as presented here |
| `AccountNotFound` (1) | steps 2 to 4 | tries again at a later login |
| `RateLimited` (10) | past the rate below | tries again after the ng wire's `retry_after`, or on the classic wire, which carries no delay, backs off |
| `RosterFull` (12) | step 1's bound, or activation past a cap, which may pass | tries again when it has room |
| `BadSignature` (16) | step 1, or a withdrawal that does not verify or is not the presenter's | drops the object |
| `Withdrawn` (new) | step 3, or a half at 802 or 805 that a withdrawal held here ends | with the withdrawal beside it, treats the friendship as withdrawn once it has checked that (§5.3); with none, the server's own (above), stops presenting it here; at 802 or 805, which carry none, tries again after `S` |
| `Stale` (new) | an object whose `time` is not within `S` of the server's clock: a withdrawal here or at 803 and 806, an offer or an acceptance at 802 and 805 | signs it afresh, or tells the user its clock is off |

A client told `Stale` has a clock it cannot use for friendship acts,
and tells the user. It signs only by its own clock, never one a server
offers: a server whose clock runs ahead would collect halves dated in
the future, which outlive any withdrawal whose `before` is earlier.

**The order at login.** A client sends its withdrawals before Get
Roster (800), which is when instant messages are drained
(`instant-messaging.md` §5), so that each is applied first, and before
its friendships, so that the rate below delays a removal last; its
friendships may follow the roster. On the ng wire its withdrawals go
before the friend family's roster request, for the same reason.

**Rate.** Each object costs a signature check, a friendship about
four, so a server keeps with each presentation the hash it checked,
and the same account presenting again under that hash skips step 1's
signatures, though never steps 2 to 4. The hash goes with the
presentation, and being the presenter's own it says nothing of anyone
else's. Presenting draws on the same per-account rate as Find User
(822), which the extension requires to be rate-limited, one object at
a time, and past it answers
`RateLimited` with a delay rather than spending spam points. A
friend looked up and then presented spends twice. A user who brings
hundreds of friends to a new server is paced, not kicked. Every
transaction this document adds (Get Device Challenge, Prove Device,
Present Friendships, Get Friendships) is rated so, and none spends spam
points.

Step 4 records a presentation and steps 2 and 3 do not, so a reply's
timing could tell a hidden party from an absent one; a server makes
the two cost alike, or answers both after the same delay.

### 4.4 Linking, rotation, deletion

`instant-messaging.md` §6 holds for portable edges, which also keep
their id when a local edge becomes portable, so queued messages are
gated as there (`instant-messaging.md` §5). Beyond it:

- **Unlinking** drops the account's presentations (§4.3). A link made
  again starts from the presentations its clients make then.
- **Rotation.** A server that has applied the rotation
  (`identity-records.md` §4), following a chain of them to its end,
  takes the successor in the predecessor's place in every check of this
  document: as a friendship's party, as the presenter, and as a
  withdrawal's `from`. A withdrawal's pair hash is the pair a friendship
  names, so one from either party for pair(A, B) ends the friendships
  made under A, on an edge now keyed by A's successor (§4.3), and a
  friendship made after the rotation, between the successor and B, needs
  a withdrawal of its own: a client withdrawing signs one for each pair
  it holds friendships under, and names `party` explicitly, the
  predecessor's fingerprint for a pair the predecessor made, since an
  absent `party` means `from`, which is not one of that pair. A server
  that has not applied the rotation refuses all of those from the
  successor, since the key is not one the friendship names, and there
  the old friendship can be withdrawn only by the other party. A checker
  that has applied the rotation refuses every withdrawal whose `from` is
  the predecessor, since what that key signs after the rotation may be a
  thief's; the successor's client signs the predecessor's cutoffs afresh
  as its own, `from` the successor and `party` the predecessor, with
  `before` no later than the rotation's time (the objects, §4). So a
  stolen predecessor key ends nothing directly through a server or a
  friend's client that has applied the rotation. A server that has not
  still takes it, and a friend's client that has not yet learned of the
  rotation can spread it under its own key (§5.3), ending the old pair
  even where the rotation is applied; the move (§10) does not count such
  a withdrawal against the friendship, so what it costs is the old pair
  until the successor's offer is accepted, not the friend. Clients move
  friendships to the successor (§10).
- **Deletion** drops the account's presentations with its edges. Its
  withdrawals stay.

---

## 5. On a client

### 5.1 What it keeps, and where it presents

Its friendships, its withdrawals as cutoffs (`pair`, `party` and
`before`) to sign afresh for each server (the objects, §4), and for each
server, which friendships it has presented there. **Presenting is
opt-in, per server:** a client presents only on a server where the user
has chosen to bring their friends, and lets the user leave particular
friends out. A new device asks before presenting anywhere, since the
choices made on another device do not reach it. Presenting tells the
server about the friendship (§9), which is why it is never done by
default. A lost record of what was presented costs a second
presentation, which is idempotent, and a `Removed` without a withdrawal
clears the record for that server, so the friendship is presented there
again if the account comes back. A friendship recorded as presented on
a server, whose edge the client has seen active there and is now
missing from Get Roster (or the ng friend family's roster), is treated
as a `Removed` without a withdrawal and presented again at once, so a
client that was signed out when the edge ended still learns why: the
`Withdrawn` reply carries the withdrawal. An edge never seen active is
waiting for the other party, and is not presented again.

**Adopting.** A client adopts a friendship whose own half this device
signed: an offer it holds that comes back accepted, if it first sees the
acceptance before the offer's `expires` plus `S` (the objects, §3), by
its own clock, or an acceptance it signed. The acceptance's own `time`
proves nothing about when it was made (the objects, §3), and the client
checks the friendship whole. It adopts one whose own half another of its
identity's devices signed, learned from an entry (§4.2), only once the
user confirms it (§6). It never adopts one that a withdrawal it holds
ends.

### 5.2 Several devices

Each device holds its own copy, and they meet at servers:

- An active edge's entries carry its friendships' hashes (§4.2), so a
  new device learns a friend from the first server it shares with that
  edge, fetches the friendship, and adopts it once the user confirms.
- A withdrawal made on one device reaches another wherever they share a
  server: in the `Removed` entry if the other is signed in, and in the
  reply when the other presents a friendship it ends.

Where two devices of one person share no server, they do not converge:
the second keeps presenting a friendship the first withdrew, on
servers the first never visits, until a withdrawal reaches it. The
friend's client, if it is honest, spreads the withdrawal too (§5.3).
Closing this needs a channel between a person's devices that is not a
Hotline server (§11).

### 5.3 Spreading a withdrawal

A client handed a withdrawal ending one of its friendships, in a
`Removed` entry or a reply, checks it whole (the objects, §4); one whose
`from` is the verified successor of one of the pair counts as that
party's (§10). It also checks the signing device against the
revocations it knows, and does not spread one a revoked device signed,
since a dishonest server can hand it one signed after the theft (§6).
It never acts on one it has not checked, and a `Removed` without one
changes nothing beyond that server's row.

Once it has checked one, it signs its own: the same pair, `party` the
original's effective party (the objects, §4), left out where that is
the spreader's own identity, the original's `before`, and a fresh
`time`. It
presents that on every server where it presented any of the
friendships it ends, and drops them. It ends exactly what the original
ended, measured on the same side of the pair, so a friendship the two
have made again since is untouched. A remover's other devices spread
it the same way. A spread whose `before` is later
than the time it would carry, as one copied from a server whose clock
ran ahead can be, waits until it is not.

The withdrawer's own client drops every friendship it holds for the
pair, whatever its dates, since its user meant the person, not a cutoff.

A removed party whose client does not spread it keeps the edge only on
servers where the remover presented and has not been back since. The
remover's own devices remove it there at their next login, each signing
the cutoff afresh for that server.

### 5.4 Display

For a portable friend, a client SHOULD prefer the friend's user card
name (the identity spec's §3.4), which is the same on every server,
over a server's published name. A local alias is kept by the client
across servers for the identity, not per Login. The extension's
`DATA_FRIEND_NICKNAME` stays the per-server alias it is.

A client attributes to a friend only what that friend's key signed or
sealed. A plain message under the Login a server reports for the
friend is that server's word, friendship or not.

### 5.5 Friends on linked servers

A ghost whose home server shows a friend's fingerprint
(`DATA_LINK_USER_KEY`) is, by that server's word, the friend's session.
A client may show it as the friend seen in the user list, which is all
it is: not messenger presence, which does not cross a link in this
version, since a link carries a user list, not a roster. It does not
show it as the friend online, since the friend may be Invisible as a
messenger while listed as a user. Private messages to it are the link's
signed and sealed private messages (`e2e-messages.md` §5), which
already cross, and only those prove the ghost is the friend. Neither
server keeps a row for it. PF5 (§8) is what more would take.

---

## 6. Stolen and retired devices

A device's revocation does not invalidate what it signed (the objects,
§5). Retiring a device costs a presentation again for each friendship
another device holds (below), and loses, wherever the revocation is
applied, any friendship only the retired device held, since an inactive
edge is shown to nobody and no other device can learn it there. So a
client retires a device only once a device that stays has adopted its
friendships, which it learns as a new device does (§5.2) while the old
one's presentations still stand.

What bounds a thief is that every friendship act is a device act (§3).
A thief with a device can act as its owner only while that device can
log in somewhere: until the revocation reaches that server (an hxd-ng
server that trusts the registrar ends such sessions when it applies the
records, `identity-records.md`), or the certificate expires, which the
identity spec recommends at 90 days and does not cap. A holder renewing
under `hlid agent --renew auto` (`identity-enrollment.md` §8) renews a
stolen device's certificate as readily as any other's, so for it only
the revocation bounds the theft. Within that, the thief can make
friendships in the owner's name, present them where it logs in, and
withdraw the owner's friendships. Outside it, the thief can make no
friendship act at an honest server, and a password allows none beyond
removing a friend on one server. A withdrawal it signed within it
outlives the revocation, though: a dishonest server can hand one, made
before or after the theft was noticed, to the friend's client, which is
why a client spreads none a revoked device signed (§5.3).

**A server drops what a revoked device presented.** It records which
device's certificate made each presentation, counting an 805 as both
parties' presentations by the devices that signed its halves. When it
applies a device's revocation, it drops that device's presentations
and tells both parties `Removed` without a withdrawal. The owner's other
devices then present again what they hold (§5.1), so a friendship the
owner keeps comes back and one only the thief held does not. A server
that never learns of the revocation keeps them.

**A friendship the thief made spreads only through the owner's own
clients**, which present it only if they adopt it (§5.1). A client
adopts a friendship whose own half another device signed only once the
user confirms it, shown as the friend, the device that signed and when,
grouped by the signing device so that a new device asks once per device
rather than once per friend. That is the moment a thief's friendship
would spread, and the one at which the owner can see it. One the user
does not recognize is withdrawn. Confirming stops a thief only once the
owner suspects the device; until then, its friendships look like any
other device's.

A device that holds the identity key (a holder, `identity-enrollment.md`)
is the identity: revoking it is not enough, and only rotating the
identity (`identity-registrar.md` §4.6) recovers from its theft.

How a client learns of a revocation: from the registrar's records for
an attested identity, or because the user revoked the device from this
client. An identity with no registrar may never tell its other devices,
which is part of why adoption asks rather than waiting for one.

---

## 7. Numbers

The classic wire needs fields, transactions, reason codes and a
capability bit, all fogWraith's to number, asked for with message
requests' in one list (`instant-messaging.md` §7). He has reserved
them, which is not adopting this draft: `CAPABILITY_FRIENDSHIPS` is bit
15 (`0x8000`), Present Friendships 833 and Get Friendships 834, and the
fields and codes are as below.

| Field | Number | Type | In |
|---|---|---|---|
| `DATA_FRIEND_OFFER` | `0x0658` | Binary (at most 1024) | 802, 804; 803 canceling an upgrade offer (§4.1) |
| `DATA_FRIENDSHIP` | `0x0659` | Binary (at most 2080: two objects and the array around them) | 805; Present Friendships; the Get Friendships reply |
| `DATA_FRIEND_WITHDRAW` | `0x065A` | Binary (at most 1024) | 803, 806, a `Removed` 801, and Present Friendships and its reply |
| `DATA_FRIENDSHIP_HASH` | `0x065B` | Binary (32) | 800 and 801, up to two in an entry; the Present Friendships reply, a friendship hash or a pair hash; Get Friendships and its reply |
| `DATA_IDENTITY_ROTATION` | `0x065C` | Binary (at most 512), repeated in chain order | The Get Friendships reply, for a friend's fingerprint (§10) |

| Code | Name | Meaning |
|---|---|---|
| 18 | `Withdrawn` | A withdrawal this server holds ends the friendship |
| 19 | `Stale` | A friendship object's `time` is not within `S` of the server's clock |

`BadSignature` (16) is the identity draft's, for a signed message that
fails; this widens it to friendship objects.

A host is at most a 253-byte name, a kept trailing dot and `:65535`,
260 bytes, an IPv6
address in brackets being shorter; a TRTP server challenge is about
222 bytes and a device proof about 264 with `exporter`, each beside its
host, so 576 holds either.

Present Friendships' request is `DATA_FRIENDSHIP` and
`DATA_FRIEND_WITHDRAW` fields in any order, each one object. Its reply's
groups are delimited by `DATA_FRIENDSHIP_HASH`, as the extension
delimits roster entries by `DATA_FRIEND_LOGIN`, each followed by its
`DATA_REASON_CODE` and, for `Withdrawn`, the withdrawal when there is
one. 802 and 805 answer `Stale` for an offer or an acceptance out of
time, and 803 and 806 for a withdrawal, and
802 and 805 answer `Withdrawn` for a half a withdrawal held here ends.
At most 32 objects of at most 2080 bytes each, about 66 KiB, fit any
frame bound a server sets in practice, and each field is well inside the
65,535 bytes a field's length allows. Get Friendships' request is up to
32 `DATA_FRIENDSHIP_HASH` and `DATA_FRIEND_IDENTITY` fields, and its
reply's groups are delimited by the one they answer, each followed by
its `DATA_FRIENDSHIP`, or for a fingerprint its `DATA_IDENTITY_ROTATION`
records in chain order, where there are any. Remove Friend (803) may
name its party by `DATA_FRIEND_IDENTITY` (§4.3).

**`CAPABILITY_FRIENDSHIPS`**, a capability bit, says a client
implements this. Bit 13 alone cannot: it means the identity draft's
first version, whose clients send no offers and would show an upgrade
offer as a request from someone already a friend. A server sends these
fields, the upgrade offer's 804 and the hashes in entries only to
sessions that negotiated both bits, and opens Present Friendships and
Get Friendships to those alone.

**Device proof's own numbers**, reserved apart from messaging's (§3):
`CAPABILITY_DEVICE_PROOF`, bit 14 (`0x4000`); Get Device Challenge,
1020, and Prove Device, 1021; and the fields below. A server opens the
two transactions to a session that negotiated the bit, whatever else it
negotiated.

| Field | Number | Type | In |
|---|---|---|---|
| `DATA_PROOF_HOST` | `0x0420` | String (at most 260) | Get Device Challenge (§3) |
| `DATA_SERVER_CHALLENGE` | `0x0421` | Binary (at most 576) | Get Device Challenge's reply |
| `DATA_DEVICE_PROOF` | `0x0422` | Binary (at most 576) | Prove Device |
| `DATA_DEVICE_CERT` | `0x0423` | Binary (at most 512) | Prove Device |
| `DATA_USER_CARD` | `0x0424` | Binary (at most 16384) | Prove Device, to link (§3) |

**The ng wire** carries the same objects as base64url, as it carries
every identity object: an `offer` on the friend family's add request
and its friend request event, a `friendship` on its accept, a
`withdraw` on its remove, on the `inbox` family's `block`
(`hotline-ng.md` §4) and on a removed entry, `offer` on a remove that
cancels an upgrade offer, `friendships` (hashes) on entries, the
requests `friendships_present`, answered for each object, and
`friendships_fetch` by hash or fingerprint, answered with friendships
and `rotations`, and the errors `withdrawn` and `stale`. The capability
is a `friendships` family (`hotline-ng.md` §4), offered only to a
session whose login proved a device, and never without `messaging`, in
place of bits 13 and `CAPABILITY_FRIENDSHIPS`. An ng login proves its
device at the ng port, so the two classic transactions have no ng
counterpart.

---

## 8. In hxd-ng

Each stage is a branch with tests, in the house style, after
`instant-messaging.md`'s store and domain (IM1, IM2); PF2 after its ng
wire (IM3), and PF3 after its classic wire (IM4). This document and the
objects go to fogWraith early, as a draft beside message requests'
(`instant-messaging.md` §8), with §7's numbers asked for then, so that
they are reserved before PF3 needs them.

1. **PF1, the objects.** `friendship-objects.md` in `hl-identity`, with
   its vectors. Transport-free, so it can be written beside IM1 and IM2.
2. **PF2, the server and the ng wire.** Portable edges, presentations by
   the device that made them, and withdrawals in the store; the
   device-act gate (§3); making, showing and presenting (§4); a device's
   revocation dropping its presentations (§6); rotation records fetched
   by fingerprint and clients moving friendships to a successor (§10);
   the ng
   friend family's offers, presentation and fetching by hash (§7),
   owed to `hotline-ng.md` §4 and §10, and present's and fetch's
   `request_weight`. hx-ng keeps friendships and presents them.
   This is where the design is first used end to end, by a client we
   control.
3. **PF3, the classic wire.** §7's fields, Get Device Challenge and
   Prove Device with linking, Present Friendships and Get Friendships,
   once their numbers are reserved, each rated as §4.3 has it, in
   `hxproto` in hx-libs first, then GtkHx with its own device key, on
   any port; `[identity] classic_hosts` and `classic_proof`, owed to
   `hotline-ng-identity.md` §12.
4. **PF4, upstream.** §4's rules and §7's numbers as the identity
   draft's second version, citing the objects, written server-neutral
   once PF2 has shown they work: without hxd-ng's settings (`[identity]
   hosts`, `classic_hosts`, `classic_proof`, `login_proof_v1`), tools
   (`hlid tunnel`, `hlid agent`), `caps::WEB`, the `/trtp` tunnel, our
   clients and crates, and the 256 KiB frame bound, and citing hxd-ng's
   documents by URL. Proving a device on the classic wire
   (§3) goes with it: it is what lets a server with no ng port see a
   device proved, and it gives the identity draft's sealed-capable
   sessions the proof at login that draft assumes but defines no way to
   make over plain TRTP.
5. **PF5, presence across links.** A link extension in which a home
   server tells a peer that a ghost is a friend of one of the peer's
   users, under friendship H, only where both parties presented at that
   peer, so that friends see each other's messenger presence across a
   link. The peer holds the presentations because its own users made
   them. Its wire is a draft of its own beside fogWraith's Server-Link
   extension (`server-link.md`), written after PF2, in `hxd-link`.

**Deliberate deviations from the extension**, beside
`instant-messaging.md` §8's, all proposed upstream (PF4) and all
opt-in: each reaches only a session that negotiated
`CAPABILITY_FRIENDSHIPS` or one that sent the new field, so a client
that did neither sees the extension unchanged.

- **An upgrade offer** (§4.1) is not `AlreadyFriends`; rejecting or
  canceling it drops the offer, not the friendship; and it is outside
  the friend-request bounds.
- **Offers lapse at their `expires`** (§4.1), which can be sooner than
  `instant-messaging.md` §8's lapse of every request.
- **A `Removed` entry carries a withdrawal** (§4.2), where the
  extension's carries only `DATA_FRIEND_LOGIN`, and a removal from a
  device ends the friendship on the friend's other servers (§2).
- **Remove Friend (803)** may name its party by `DATA_FRIEND_IDENTITY`
  (§4.3) and may carry an offer, canceling it alone (§4.1).
- **`AccountNotFound` for an account that exists** and holds
  `AccessMessaging`, where its link is hidden or does not match the
  offer (§4.1, §4.3), so that an offer or a presentation cannot test a
  guess at a hidden link.

**Amendments to the identity draft**, proposed as its second version
(PF4), each reaching only a client that sends the new fields or
transactions:

- **Edges keyed by identity** (§3), `instant-messaging.md` §8's
  deviation, against "roster rows … stay keyed by Login".
- **`DATA_FRIEND_IDENTITY` to a hidden link's friend** (§4.3), where
  the draft sends it only where the server would show the link to an
  ordinary user.
- **A server checks what it is given** (§4), where the draft says it
  "need check nothing cryptographic".
- **Sealed-capable when proved**: a session proved by device proof
  (§3), as by an identity login, is sealed-capable, where the draft has
  the device proved at login.
- **`BadSignature` widened** to friendship objects (§7).
- **An offer hands a stranger a device certificate**, which the draft
  gives friends alone (the objects, §2).

---

## 9. Security and privacy

- **What a client can check.** A client shows as portable friends only
  friendships it checked itself, so no server can show it a friendship
  the friend did not sign, and it adopts one its own other device signed
  only when the user confirms.
- **What a dishonest server can still do.** It decides who is sent
  presence and messages on its own wire, and can tell a stranger when
  someone is online, as it can today. It can activate any friendship it
  has seen, on itself, whether or not both parties presented it there;
  a client notices only by finding an entry for a friendship its own
  record says it never presented to that server. It can put a friend's
  genuine friendship on a Login that is not the friend's, since the
  friendship names keys and the Login is its word; a client that
  attributes only signed or sealed messages to a friend (§5.4) is not
  fooled. It can ignore a presentation or a withdrawal, so a removal
  reaches it only if it chooses to apply it. A clock run ahead of real
  time would have it collect halves dated in the future, to outlive
  later withdrawals; clients sign by their own clocks (§4.3), so such a
  server refuses honest halves `Stale` rather than collecting them.
  It can hand a client a withdrawal a thief signed, which the client
  does not spread once it knows the device revoked (§5.3). Friendships
  constrain what clients believe, not what a server sends.
- **First contact.** The fingerprint in the first offer is the server's
  word, as under the identity draft. Clients SHOULD offer a way to
  compare fingerprints out of band, and SHOULD mark a friendship
  compared that way.
- **The friend graph.** A client's lookups tell a server which
  fingerprints it is looking for, and its presentations which
  friendships it has with those found, both identities and the hash
  included. A withdrawal's pair hash can be matched by anyone who
  knows both fingerprints. Servers that compare notes see the same
  friendship hash at each. That is the reason presenting is opt-in per
  server and per friend (§5.1). Hiding the graph from a server that
  matches friends needs a secret the two people's devices share and the
  server does not, which needs the device channel of §11.
- **A stolen device**, or a malicious script in a web client, whose
  certificates allow messages (`caps::WEB`), can make friendships in
  its owner's name and withdraw the owner's friendships for as long as
  it can log in as a device (§6). Friendships it makes reach the
  owner's other devices only as confirmations the owner can refuse, and
  what it presented is dropped wherever its revocation is applied.
  Its withdrawals are permanent, and can still be handed out after the
  revocation by a dishonest server to a client that does not yet know
  of it (§6): recovering a friendship a thief withdrew is making friends
  again. Withdrawals take no certificate bit
  of their own, since a web client that can be trusted to message
  friends and remove them on one server is trusted with the same choice
  made everywhere.

---

## 10. Rotation

When a friend rotates their identity (`identity-registrar.md` §4.6),
their friendships move to the successor's key, so that they stop
depending on every server having applied the rotation. §4.4 still
holds meanwhile, so nothing breaks while they move.

- **The record is fetched from the server.** A friend's entry under a
  new fingerprint, with no `Removed` before it, is a rotation by the
  identity draft's rule. The client asks Get Friendships for that
  fingerprint (§4.2), and a server that has applied the rotation answers
  with its records, one for each rotation of the chain, in
  `DATA_IDENTITY_ROTATION` (§7), and the ng wire the same way. Asking
  the server that already holds the edge tells it nothing new, where
  asking a registrar would tell it whose friends the client is
  checking, and a roster that does not carry the records costs nobody
  their bytes at every login.
- **The client checks it itself**: both of its signatures, the
  predecessor's and the successor's (`identity-registrar.md` §4.6), and
  that the SHA-256 of its `successor` is the commitment in the
  predecessor's card (the identity spec's §3.4), from a card the client
  holds. Without a card holding a commitment, the client may instead
  find the rotation in the predecessor's registrar's published records
  (`identity-registrar.md` §6.2), at the cost of that fetch. A record it
  cannot check either way it ignores.
- **Moving.** The successor's client offers each friend afresh under the
  successor at the next server they share, an upgrade offer (§4.1), and
  presents the new friendship wherever it presented the old. A friend's
  client that has checked the rotation, and holds a friendship with the
  predecessor, or dropped one, that no withdrawal ends but one whose
  `from` is the predecessor or its own spread of one, accepts without
  asking the user and presents the new friendship wherever it presented
  the old. Withdrawals from the predecessor do not count, since what
  that key signs after the rotation may be a thief's, and the successor
  offers only the friends it still holds. It withdraws the old pair on a
  server only once that server's entry carries the new friendship for
  both parties, so that the withdrawal leaves the edge standing (§4.3)
  rather than ending it before the successor has been back. A server
  that has not applied the rotation takes no presentation from the
  successor (§4.4), and keeps the old friendship until it does. Only
  the friend who rotated offers, so two clients never cross offers; any
  other successor's offer, from a rotation the client has not checked
  or to a friend who had ended the friendship, is an ordinary friend
  request.
- **An identity with no commitment and no registrar** cannot rotate in a
  way a friend can check, so its friends make friends again by hand.

---

## 11. Later versions

- **A device channel.** Several of the limits above (devices that share
  no server, choices made on one device reaching another, learning of a
  revocation without a registrar, a graph hidden by shared secrets, a
  record of friendships surviving the loss of every device) come down
  to a person's devices having no way to reach each other but Hotline
  servers. The registrar's envelopes (`identity-registrar.md` §9) are
  the nearest thing, but an envelope is the identity seed alone, of a
  fixed size, and put under the identity key. A roster would need an
  envelope kind of its own, sized for it, that any device can put and
  fetch.
- **Withdrawals beyond servers.** A withdrawal names its pair by a hash
  anyone holding both fingerprints can match, so publishing withdrawals
  in a registrar's records would publish who stopped being friends with
  whom to anyone who can guess. That is not a fit for the registrar as
  it is, and waits on a design that is.
