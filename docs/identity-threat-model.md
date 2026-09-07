# hxd-ng identity: threat model

Status: draft, for discussion. Nothing here is implemented.

This document says what the identity system is meant to protect, from whom,
and what it deliberately does not protect. The mechanism specs
(capabilities-identity, registrar, messaging-e2e, federation) are written
against this document. If a mechanism can't be justified by something here,
it should be cut or this document should change first.

## Summary of the design being modelled

- A user's identity is an Ed25519 keypair (the *identity key*). It is
  long-lived and rarely used directly.
- Each device holds a short-lived *device key*, signed by the identity key.
  Logins, message signing and PM encryption use device keys.
- A *registrar* is an hxd-ng server with the registrar feature enabled. It
  issues a handle (`name` at that registrar), stores the identity key in
  encrypted envelopes the registrar cannot open, and publishes revocation and
  rotation records.
- A user's public identity travels as a signed, versioned *user card*
  (profile, registrar attestations, vouches). Servers cache it.
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
| **Registrar operator** | handle table, wrapped identity keys, attestations, revocations, presence records if hosted there |
| **Other users** | whatever the server shows them; decrypted PMs they receive |
| **Network attacker** | passive or active position on the wire |
| **Legacy (1.x) client** | a classic account or guest login; no identity; possibly cleartext |
| **Tunnel / relay operator** | transport identity of every socket it fronts; the tunnelled bytes pass through it under TLS on both sides, but a tunnel on the user's own machine, or a relay, terminates that TLS and can read them |

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
- see who registered, when, and with what signup verification
- see every device bootstrap (when a wrapped key is fetched)
- freeze an identity (refuse to publish rotations, mark it disputed)
- see presence records and their ACLs, if presence is hosted at the registrar
- withhold or delay revocation records

Cannot:
- decrypt a wrapped identity key (the wrapping secret never leaves the client)
- sign as the user
- rotate a user to a key the registrar chose, without the user's signature
  (see "registrar-assisted recovery" below for the deliberate exception)

The registrar is trusted for *availability* and *honest publication*, not
for confidentiality of keys. A malicious registrar can make an identity
unusable; it cannot impersonate it.

### Other users

Can:
- see whatever the server's permissions show them
- receive and decrypt PMs sent to them, and forward them anywhere
- report a PM to an operator by forwarding the decrypted content
- vouch for a key; be held responsible if that key is banned

Cannot:
- read PMs between two other identity users
- claim a reserved name held by a linked identity on that server

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
device, and sign messages. They cannot rotate the identity, sign vouches, or
add devices.

Mitigations: device keys expire (proposed 90 days); the user revokes the
device from any other device; revocation is published by the registrar and
checked by servers with a bounded cache age; revoked device keys no longer
receive PMs.

Residual risk: messages sent to that device between compromise and
revocation are readable. There is no forward secrecy in v1.

### Stolen identity key
Attacker can do everything the user can, including signing revocations and
rotations.

Mitigations:
- *Registrar freeze.* Rotation records are published only with registrar
  approval. The user reports the compromise out of band, the registrar
  freezes the identity, and rotation to a new key goes through the
  registrar's verification. This is the deliberate case where the registrar
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
  registrar records it at registration for the same reason. The attacker
  can therefore publish a card with their own commitment only to servers
  that have never seen the user, which is the registrar's job to cover.

Residual risk: between theft and freeze, the attacker is the user. Reserved
names and standing follow the successor key after rotation, so a frozen
identity that rotates cleanly loses nothing but time.

### Lost identity key (no attacker)
User loses all devices and all envelopes.

Mitigations: passkey sync, multiple passkeys per registrar account, the
recovery code, and a password-wrapped key file. Registrar-assisted recovery
(re-attesting the same handle to a new key after out-of-band verification)
is available for the handle, but reserved names and standing on other
servers do not carry over automatically; the new key is a new person to
those servers unless the operator links it by hand.

### Sybil keys
Keys are free; new registrar accounts are as cheap as the registrar's
signup. An attacker makes many identities to evade bans or inflate vouches.

Mitigations: attestation age is shown to servers and operators; servers may
treat young or unattested keys as guests; registrars choose their own signup
strictness and advertise it; servers may drop trust in a registrar that
mints abusers; vouches carry the voucher's standing with them.

Residual risk: a registrar with open signup is a sybil factory. This is a
per-registrar reputation problem, handled the same way as any server's.

### Malicious registrar
Refuses to publish a revocation; publishes a bogus one; freezes a user out
of spite; goes away.

Mitigations: revocation records are user-signed, so the registrar can only
withhold, not forge; the user may re-attest at a second registrar with the
same key; servers keep cached attestations with a staleness limit rather
than failing closed; the recovery code and key file do not depend on the
registrar.

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
  bootstraps and hosted presence. Nothing here hides that.
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
  against "servers moderate themselves."
- Cache staleness limit for attestations and revocations when a registrar is
  unreachable: hours, days? Fail toward guest or toward cached?
- Does a device certificate carry capability restrictions (may not vouch,
  may not rotate), or are all devices equal? Restricting the web client's
  device key would shrink the XSS blast radius.
- Do reserved names require a linked identity, or can classic accounts
  reserve too? Proposed: both, identity-linked wins on conflict.
- Should presence ACLs live at the registrar (leaks social graph to it) or be
  encrypted per recipient (more client work, no leak)?
- Handle syntax. `user@host` reads as email; `@user@host` and `user:host`
  are the alternatives in use elsewhere.
