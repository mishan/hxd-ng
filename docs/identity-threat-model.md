# hxd-ng identity: threat model

Status: design, with a built core. What hxd-ng implements today is the
transport of `hotline-ng-auth.md` and the identity profile of
`hotline-ng-identity.md` — the identity objects, both bindings, account
association, and the successor commitment described below. Not
implemented anywhere yet: revocation, rotation and freezing, envelopes
and recovery codes (`identity-registrar.md`), vouches
(`identity-vouch.md`), reserved names, and everything the federation
spec, which is not yet written, will cover. Read a "the server
refuses…" sentence as what the design requires, not as a guarantee you
can rely on today.

This document says what the identity system is meant to protect, from whom,
and what it deliberately does not protect. The mechanism specs
(`hotline-ng-identity.md`, `identity-registrar.md`, `identity-vouch.md`,
messaging-e2e, federation) are written against this document. If a
mechanism can't be justified by something here, it should be cut or this
document should change first.

## Summary of the design being modelled

- A user's identity is an Ed25519 keypair (the *identity key*). It is
  long-lived and rarely used directly.
- Each device holds a short-lived *device key*, signed by the identity key.
  Logins, message signing and PM encryption use device keys.
- A *registrar* is an hxd-ng server with the registrar feature enabled
  (`identity-registrar.md`). It issues a handle (`name` at that
  registrar), stores the identity key in encrypted envelopes the
  registrar cannot open, and publishes revocation and rotation records.
- A user's public identity travels as a signed, versioned *user card*
  (profile, registrar attestations, portable vouches —
  `identity-vouch.md` §4). Servers cache it.
- On first login to a server, the server creates or links a local account and
  keeps the identity fingerprint on it. Reserved names and permissions are
  attached to the local account, not the key.
- PMs between identity users are end-to-end encrypted to device keys.
  Everything else (public chat, news, files, voice) is visible to the server.
- Presence is published by the client, not the server, and is off unless the
  user turns it on and the server's policy allows it.

## Actors

| Actor | What they hold |
|---|---|
| **User** | identity key (wrapped), device keys, user card |
| **Server operator** | full view of their own server's state and traffic |
| **Registrar operator** | handle table, envelopes it cannot open, attestations, the records it publishes (`identity-registrar.md` §4); presence records if hosted there — federation spec, not defined |
| **Other users** | whatever the server shows them; decrypted PMs they receive |
| **Network attacker** | passive or active position on the wire |
| **Legacy (1.x) client** | a classic account or guest login; no identity; possibly cleartext |
| **Tunnel / relay operator** | transport identity of every socket it fronts, and the payload in the clear — it terminates the TLS it forwards under. The hops differ and neither is protected end to end: a *tunnel* takes cleartext TCP from the classic client (loopback by default, off-loopback opt-in) and speaks TLS upstream; a *relay* takes TLS from the client and speaks **plain TCP** to the legacy server behind it, so credentials and messages cross that last hop unprotected |

## Assets, ranked

1. **Identity key.** Losing it to an attacker is the worst outcome: they
   become you everywhere until the registrar freezes you.
2. **Device keys.** Bounded damage: one device, until expiry or revocation.
3. **PM content** between identity users.
4. **Reserved names and standing** on a given server.
5. **Handle** at a registrar.
6. **Presence** (which server you are on, when).
7. **Social graph** (who you PM, who you vouch for, who you follow).

## What each actor can see and do

### Server operator

Can:
- read all public chat, news, files, voice, and user lists on their server
- see who PMs whom on their server, when, and message sizes
- see the identity fingerprint, registrar handle and attestation age of every
  identity user who has logged in
- ban, warn, restrict, or refuse any key; publish a signed ban list
- decide whether federated users can join at all (allow list), and what
  permissions they get
- decide whether their server may appear in presence records

Cannot:
- read PM content between identity users
- forge a user card, vouch, attestation or message from a key they don't hold
- move a user's reserved name or standing to a different key

The operator is trusted for everything on their own server except PM
content. This is stated as a property, not a bug: hxd-ng keeps the
operator in charge.

### Registrar operator

Can:
- see who registered, when, from where, and with what signup proof
- see every envelope fetch attempt and its source address
  (`identity-registrar.md` §9.2)
- hold envelope ciphertext and mount an offline KDF attack on it, bounded
  by the floor of `identity-registrar.md` §9.1 and the user's passphrase
- freeze an identity (`identity-registrar.md` §4.7, §8.1): refuse it
  reissue, records and envelope fetches, and cancel a pending rotation
- delay a rotation by `rotation_delay` (`identity-registrar.md` §5.4)
- see presence records and their ACLs, if presence is hosted at the
  registrar — federation spec, not defined
- withhold or delay revocation records

Cannot:
- decrypt an envelope (the wrapping secret never leaves the client,
  `identity-registrar.md` §9.1)
- sign as the user
- rotate a user to a key the registrar chose, without the user's signature
  (see "registrar-assisted recovery" below for the deliberate exception)
- publish a rotation to a key other than the committed one, when it
  holds a commitment (`identity-registrar.md` §5.4)
- unfreeze quietly: it signed every freeze and every lift
  (`identity-registrar.md` §4.7), so a lift is as visible as a freeze

The registrar is trusted for *availability* and *honest publication*, not
for confidentiality of keys. A malicious registrar can make an identity
unusable; it cannot impersonate it.

### Other users

Can:
- see whatever the server's permissions show them
- receive and decrypt PMs sent to them, and forward them anywhere
- report a PM to an operator by forwarding the decrypted content
- vouch for a key (`identity-vouch.md`); have their vouching suspended,
  and be shown to moderators beside it, if that key is banned — never be
  banned for it (§6 there)

Cannot:
- read PMs between two other identity users
- claim a reserved name held by a linked identity on that server
  (design; hxd-ng does not enforce reserved names yet)

### Tunnel and relay operators

A tunnel on the user's machine is the user's own device and sees what the
user sees. A relay in front of a legacy server is, for identity purposes,
a server operator: it can see every tunnelled byte (it terminates TLS),
gatekeep by identity, and sign ban lists — and it can do nothing with
accounts, because it has none. Trusting a relay is trusting its operator
exactly as one trusts the operator of the server behind it.

### Network attacker

All ng connections are TLS. On those, a passive attacker learns endpoints
and traffic shape only. An active attacker with a bad certificate is stopped
by ordinary TLS verification; pinning is not planned for v1.

Cleartext 1.x connections are a separate case, below.

## Attack scenarios

### Stolen device key
Attacker can log in as the user from that device, read new PMs sent to that
device, and sign messages. They cannot rotate the identity or add devices;
what a device whose certificate carries the `vouch` or `manage` bit can
additionally do is under "Vouching" below and `identity-registrar.md`
§4.4.

Mitigations: device keys expire (proposed 90 days); the user revokes the
device from any other device; revocation is published by the registrar and
checked by servers with a bounded cache age (`identity-registrar.md` §4.4,
§7.2), and an operator can refuse the fingerprint by hand on their own
server without one (`revoked_devices`, §7.3 there); revoked device keys
no longer receive PMs.

Residual risk: messages sent to that device between compromise and
revocation are readable. There is no forward secrecy in v1.

### Stolen identity key
Attacker can do everything the user can, including signing revocations and
rotations.

Mitigations:
- *Registrar freeze, commitment enforcement and delayed publication.*
  Rotation records are published only through a registrar. The user
  reports the compromise out of band, the registrar freezes the identity
  (`identity-registrar.md` §8.1), and rotation to a new key goes through
  the registrar's verification (§8.2 there). Two things the registrar
  does before any report are what make that window survivable: it
  refuses to publish a rotation to any key but the committed one when it
  holds a commitment (§5.4 there), and it delays publication of an
  accepted rotation by `rotation_delay` and notifies the holder, so a
  rotation a thief signed first can be met with a freeze before any
  server acts on it. This is the deliberate case where the registrar
  gates a user action.
- *Recovery code.* A second envelope of the identity key, unlockable by a
  one-time code shown at registration. This covers *loss*, not theft.
- *Optional pre-committed successor key.* The user generates a next key,
  stores it offline, and publishes `SHA-256(next public key)` as the
  `successor` field of their user card. A signature carries no trustworthy
  time, so "older" cannot mean "signed earlier" — an attacker holding the
  identity key can sign and backdate anything. What makes the commitment
  binding is that it is *anchored before compromise*: every server that
  cached the card holds the commitment, refuses any later card that
  changes or drops it, and accepts rotation only to the committed key. The
  registrar records it at registration for the same reason. "Holds" has
  to mean *on disk*: an anchor a server keeps only in memory is one an
  attacker can clear by getting the server restarted, which is precisely
  the "make the caches forget" move the commitment exists to block. The attacker
  can therefore publish a card with their own commitment only to servers
  that have never seen the user, which is the registrar's job to cover.
  "Every server that cached the card" is narrower in practice: a server
  anchors an identity it has a relationship with — an account, or an
  attestation it accepted — because a durable line per passing key is a
  disk-filling primitive for anyone who can reach the auth endpoint (spec
  §13). A user who has never logged in anywhere is covered by the
  registrar's record, not by servers that have only seen their card.

Residual risk: between theft and freeze, the attacker is the user. Reserved
names and standing follow the successor key after rotation, so a frozen
identity that rotates cleanly loses nothing but time.

### Lost identity key (no attacker)
User loses all devices and all envelopes.

Mitigations: passkey sync, multiple passkeys per registrar account, the
registrar envelopes and recovery code (`identity-registrar.md` §9), and a
password-wrapped key file. Registrar-assisted recovery (re-attesting the
same handle to a new key after out-of-band verification, §8.3 there) is
available for the handle, but reserved names and standing on other
servers do not carry over automatically; the new key is a new person to
those servers unless the operator links it by hand, or enough members
vouch that it is the same person (`identity-vouch.md` §7).

### Envelope brute force
Attacker holds envelope ciphertext — a registrar breach, or a malicious
registrar — and no passphrase.

Mitigations: Argon2id at the floor of `identity-registrar.md` §9.1 makes
a weak passphrase expensive and a recovery code (100 bits, §9.3 there)
infeasible; the envelope is bound to one identity by its associated
data, so a swapped envelope fails to open rather than opening wrong.

Residual risk: a weak passphrase is a weak passphrase. Clients should
say so at creation.

### Handle lockout
Attacker who knows a handle hammers the envelope fetch until the
registrar locks it (`identity-registrar.md` §9.2, §10).

Mitigations: the lockout caps at 24 hours; the owner's other devices are
unaffected; the recovery-code envelope is a separate `kind` with its
own counter.

Residual risk: a day without restore-from-passphrase for a targeted
user.

### Sybil keys
Keys are free; new registrar accounts are as cheap as the registrar's
signup. An attacker makes many identities to evade bans or to vouch for
each other.

Mitigations: attestation age is shown to servers and operators; a bare
key never creates an account, pays `newcomer_delay` on first sight, and
is admitted as `[identity.admission] unknown` says
(`identity-registrar.md` §7.3, §7.5); a young key of any standing is on
probation (§7.5 there); registrars choose their own signup strictness
and advertise it (§5.3 there), and publish a log of everything they
issue (§6.6 there) so an operator can count; servers may drop trust in,
or ban outright, a registrar that mints abusers (§7.3 there); a vouch
counts only from a voucher with direct standing, so a ring of fresh keys
vouching for each other produces nothing (`identity-vouch.md` §2).

Residual risk: a registrar with open signup is a sybil factory. This is a
per-registrar reputation problem, handled the same way as any server's.

### Vouching
`identity-vouch.md` §9, condensed. A vouch is a member answering for a
key: depth one, binary, expiring, bounded, accountable but not punitive
(§2 there).

- *Vouch rings.* Sybils vouching for sybils. None of them has standing,
  so none of the vouches count, however many there are (rule 1 there).
- *Coercion and social pressure.* A member vouches because refusing is
  awkward, and a harasser arrives with a real name attached. A vouch is
  scarce (rule 4) and its consequence is stated at the moment of giving
  it (rule 6). This is the realistic failure and it is not fully
  solvable; what §6 there guarantees is that the member who vouched sees
  the consequence and the moderator sees the member.
- *Punishing a voucher through their vouched.* Getting someone's friend
  banned to suspend the friend's vouching. Bans are moderators' acts and
  the penalty is a month without vouching, not a month without the
  server; low value to an attacker.
- *Social graph exposure* (asset 7). A portable vouch in a card is
  public and says who knows whom; so is a registrar's per-identity
  record list that carries one. The local form reveals nothing outside
  the server's own tables and moderation UI, which is why it is the
  default and the portable form is the user's explicit choice, made with
  that stated.
- *Stolen vouch-capable device.* Can spend the user's vouches on the
  attacker's keys until revoked. Rule 4 bounds it to five, §6 there
  makes each one visible, and the device revocation is the fix;
  web-client certificates omit the bit (`hotline-ng-identity.md` §3.3).

### Malicious registrar
Refuses to publish a revocation; publishes a bogus one; serves a stale or
empty per-identity record list; freezes a user out of spite; goes away.

Mitigations: revocation records are user-signed, so the registrar can only
withhold, not forge; a stale or empty list is answered by the server's
`revocation_stale` (`identity-registrar.md` §7.2) and by the user's
second attestation elsewhere; the user may re-attest at a second
registrar with the same key; servers keep cached attestations with a
staleness limit rather than failing closed; the recovery code and key
file do not depend on the registrar.

Residual risk: a withheld revocation leaves a stolen device key valid until
expiry. A vanished registrar strands users who kept no other envelope.

### Malicious server operator
Logs PMs, harvests user cards, publishes a poisoned ban list.

Mitigations: PM content is encrypted; user cards are public by design and
contain nothing the user did not choose to put in them; ban-list
subscription is opt-in per subscribing server with a per-list policy.

Residual risk: PM metadata, and everything not E2E.

### Cleartext 1.x sessions
A legacy client on plain TCP exposes its own traffic and everything the
server sends it, including other users' public chat, user lists and file
names, to any passive observer.

Mitigations: cleartext is a three-position server setting (off / restricted
/ on); restricted sessions get an operator-defined reduced permission set;
cleartext sessions are marked in the user list; identity users cannot
authenticate over cleartext; ng clients warn before PMing a cleartext user.

Residual risk: in `on` mode, this is 1997. That is the operator's choice.

### Hostile client ignoring presence policy
A client publishes a `hidden` server's address anyway.

Mitigations: allow-listed servers reject unknown keys at the handshake before
sending name, banner or user count. The worst case is "a host exists," which
is no worse than a tracker listing or a phone call.

### Web client key exposure
The identity key is unwrapped in browser memory while the web client runs.

Mitigations: sign in a worker; keep web device keys short-lived; never write
the unwrapped identity key to browser storage; prefer bootstrapping native
clients from the web flow rather than running long web sessions.

Residual risk: an XSS in the web client is a device-key compromise, possibly
an identity-key compromise if it lands during unwrap.

## Explicit non-goals for v1

- **Forward secrecy.** PMs use static device encryption keys with no
  ratchet. A compromised device key exposes past PMs to that device.
- **Metadata privacy.** Servers see who talks to whom; registrars see
  envelope fetches and, if the federation spec puts it there, hosted
  presence. Nothing here hides that.
- **Encrypted group chats, voice, files, news.** Server-visible.
- **Anonymity.** Handles, attestations and vouches are designed to make
  people accountable, not unlinkable.
- **Global name uniqueness.** Handles are unique per registrar; reserved
  names are unique per server. There is no global namespace.
- **Protection from a user's own contacts.** A PM recipient can forward
  anything.
- **Certificate pinning** for server TLS.

## Properties worth stating to users

The short version, suitable for a login screen or README:

> The server operator can read everything you do on their server except
> private messages to other registered users. They can see who you message
> and when. Your registrar can lock you out but cannot read your key or
> pretend to be you. If you lose your key and all your backups, you start
> over.

## Open questions

- Should a registrar be able to freeze an identity *without* a user report,
  e.g. on abuse grounds? This makes the registrar a moderator, which cuts
  against "servers moderate themselves." Still open:
  `identity-registrar.md` §8.1 gives the operator the record and says
  nothing about using it beyond a holder's report.
- ~~Cache staleness limit for attestations and revocations when a
  registrar is unreachable: hours, days? Fail toward guest or toward
  cached?~~ **Closed:** `identity-registrar.md` §7.2 — the list's own
  `expires` capped by `revocation_max_age`; past that, `revocation_stale`
  decides, default `cached`.
- ~~Does a device certificate carry capability restrictions (may not
  vouch, may not rotate), or are all devices equal?~~ **Closed: yes**,
  the `caps` bits of `hotline-ng-identity.md` §3.3; web-client
  certificates omit `vouch` and `manage`, which is the XSS blast-radius
  reduction this question wanted.
- Do reserved names require a linked identity, or can classic accounts
  reserve too? Proposed: both, identity-linked wins on conflict.
- Should presence ACLs live at the registrar (leaks social graph to it) or be
  encrypted per recipient (more client work, no leak)?
- ~~Handle syntax. `user@host` reads as email; `@user@host` and
  `user:host` are the alternatives in use elsewhere.~~ **Closed:**
  `user@host` (`hotline-ng-identity.md` §3.5); the local part's
  canonical form is `identity-registrar.md` §5.1.
