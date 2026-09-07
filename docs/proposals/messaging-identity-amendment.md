# Proposal: portable identity in the Instant Messaging extension

Status: proposal to fogWraith for `Docs/Protocol/Capabilities-Messaging.md`.
Written against the version current on 2026-09-06. Companion to hxd-ng's
`docs/hotline-ng-identity.md`, referred to below as "the identity spec".

## Summary

The messaging extension keys everything on the account Login: roster
rows, presence, offline queues, discovery. The identity spec ends by
linking a portable identity — an Ed25519 key with a signed user card and,
optionally, a registrar handle — to exactly one account per server. On a
server running both, a linked identity gets a roster, presence and IM with
no change to either document, because from messaging's point of view it is
simply an account.

This proposal is about the seams: the places where the Login being the
only key shows, and one hook the identity spec's end-to-end messaging plan
needs. It asks for four things, in decreasing order of importance:

1. an optional stable key beside the Login on roster, presence and
   discovery entries, so rows survive account renames and can be matched
   across servers;
2. lookup by handle or fingerprint in Find User and User Search, and
   blocking by fingerprint;
3. field reservations, a client capability bit, per-device queue state
   and the rules that let an encrypted message body travel through IM
   Send / IM Deliver and the offline queue opaquely without leaving any
   session a message it cannot read;
4. two paragraphs in Security Considerations reflecting what an
   identity-bound session changes.

Nothing here alters behaviour for a client or server that does not
implement the identity spec. Every new field is optional and sent only
when the subject has a linked identity; every new lookup form is in
addition to the Login form.

## What does not change

Worth stating so the review is about the deltas:

- **Bare identity remains the Login.** Roster rows, blocks, queues and
  authorization are still keyed by Login. The fingerprint is carried
  alongside, never instead. A server with no identity support sends no
  new fields and rejects no requests it accepts today.
- **`guest` and `admin` stay out.** An identity user who has not been
  linked or created an account is a guest session that knows who it is,
  and the rule that `guest` never participates applies to it unchanged.
  Operators who want identity users to message use the identity spec's
  `new_accounts = create`, which makes them ordinary accounts.
- **The sender is the session.** "The server MUST derive the
  authenticated Login from the session" is exactly what an identity-bound
  socket provides; nothing to add.
- **Presence stays server-local.** The identity spec's federation
  document describes client-published presence across servers; it answers
  a different question and does not touch Presence Changed (809).
- **Allocations don't collide.** Capability bits 6–8, access bit 58,
  transactions 800–826 and fields `0x0600`–`0x0627` are all clear of the
  identity spec, which uses HTTP and defines no TRTP numbers. (An earlier
  hxd-ng draft had proposed 800–809 for identity; it was withdrawn.)
  Because the identity spec allocates nothing on the legacy wire, the two
  capability bits this proposal needs — 11 for `CAPABILITY_IDENTITY` and
  12 for `CAPABILITY_MESSAGE_ENVELOPE` — are allocated *here*, and both
  are subject to the messaging extension's own registry. hxd-ng's
  allocations stop at 10 (video), so 11 and 12 are free today.

---

## Amendment A — a stable key beside the Login

### Problem

The spec's own account-rename rule is the symptom: a rename is a
`Removed` entry followed by a fresh one, "since the Login is the roster
key and a client cannot rename a row it identifies by that key". Local
aliases, unread state and anything else a client hangs on the row go with
it. The same limitation means a client cannot recognise that
`misha` on this server and `mnasledov` on another are the same person,
even when both accounts are linked to one identity.

### Change

Add two optional fields, sent only for a subject whose account has a
linked identity:

| ID (hex) | Dec | Name | Type | Description |
|---|---|---|---|---|
| `0x061D` | 1565 | `DATA_FRIEND_IDENTITY` | Binary (32) | Fingerprint of the linked identity: SHA-256 of its Ed25519 public key (identity spec §3.2) |
| `0x061E` | 1566 | `DATA_FRIEND_HANDLE` | String | The subject's registrar handle, `name@registrar`, when the server accepted an attestation for it |

They are added to the field lists of:

- Get Roster (800) entries and Roster Entry (801), subject to the
  complete-entry rule: a server sends both whenever it holds them; a
  client replaces, never merges.
- Presence Changed (809).
- Friend Request (804), so the recipient can recognise a requester they
  know from elsewhere.
- Find User (822), User Search (823) and Get User Info (825) results,
  under the existing visibility rules for `FieldUserName`: these are
  public-card fields, not friend-only ones. A fingerprint is a public key
  hash and a handle is designed to be told to people; neither reveals
  presence.

### Rename rule

Replace the rename bullet under *Persistence* with:

> **Rename.** Rewrite all references atomically. For each affected online
> friend, send a Roster Entry (801) for the new Login. To a friend's
> session that negotiated `CAPABILITY_IDENTITY` (bit 11) *and* whose
> subject has a linked identity, that entry carries `DATA_FRIEND_IDENTITY`
> and no `Removed` precedes it: the client MUST rename the row it holds
> under that fingerprint in place, preserving its alias and local state.
> To every other session — a client that did not negotiate bit 11, or any
> client when the account has no linked identity — send a removal for the
> stale Login followed by the fresh entry, as before. A client that keys
> rows by Login therefore never sees a Login change without a `Removed`.

The server needs a per-session signal for this, and `DATA_CAPABILITIES`
from Login (107) is where it belongs. **This proposal allocates bit 11,
`CAPABILITY_IDENTITY`**, for it — the identity spec does not, and cannot:
it works entirely over HTTP and states that it defines no TRTP numbers.
The bit means "this client understands `DATA_FRIEND_IDENTITY` and
`DATA_FRIEND_HANDLE` on a roster entry"; a client may negotiate it
whether or not the server or the client has an identity of its own.

`DATA_MESSAGING_FEATURES` (below) is the server-side half and does not
substitute for it: it says what the *server* offers, and the rename rule
turns on what a particular *client* can parse.

### Client rule

Add to *Client Behaviour*:

> 11. Treats `DATA_FRIEND_IDENTITY`, when present, as the durable key for
>     a roster row: two entries with the same fingerprint are the same
>     person even if their Login differs, and a client MAY offer to merge
>     local state (aliases, history) across them. The Login remains the
>     addressing key on the wire.
> 12. Treats a Roster Entry (801) whose Login matches an existing row but
>     whose `DATA_FRIEND_IDENTITY` differs, with no intervening `Removed`
>     for that Login, as an identity rotation (identity spec §8.5): the
>     row keeps its state and takes the new fingerprint. A reassigned
>     Login always arrives after a `Removed` (the *Delete* rule above), so
>     the two cases cannot be confused.

### Rotation

The identity spec lets an identity rotate to a successor key, after
which the linked account carries a new fingerprint and the same Login. A
server MUST send a Roster Entry (801) with the new `DATA_FRIEND_IDENTITY`
to every online friend when that happens, exactly as for a rename, and
MUST NOT send `Removed`. Nothing else changes: the offline queue, blocks
and receipts belong to the account and follow it.

---

## Amendment B — lookup by handle or fingerprint

### Problem

Someone who knows a person as `misha@hl.example` from another server has
no way to find them here except by guessing the local Login. The identity
spec makes the handle the thing you tell people; the messaging extension
should accept it.

### Change

Find User (822) accepts exactly one of `DATA_FRIEND_LOGIN`,
`DATA_FRIEND_HANDLE` or `DATA_FRIEND_IDENTITY`. The reply is unchanged in
shape and always carries `DATA_FRIEND_LOGIN`, which is the key the caller
will use from then on. A request carrying more than one, or none, is a
failure with no reason code.

User Search (823) matches `DATA_FRIEND_HANDLE` on substring as it matches
Login and display name, gated by the subject's `DATA_DISCOVERABLE`
preference exactly as those are. Fingerprints are not searched: a hash is
not something a person types a fragment of.

Block User (806) likewise accepts `DATA_FRIEND_IDENTITY` in place of
`DATA_FRIEND_LOGIN`. This is the one place a fingerprint is needed as an
*address* rather than a lookup key: under the identity spec's
`new_accounts = guest` policy an identity user is a `guest` session that
carries a fingerprint, and while such a session cannot use this
extension's IM (the `guest` rule stands), it can still send a classic
Send Private Message (108) to anyone on the user list. A block by
fingerprint is the only kind that can stick to it. Servers store such a
block against the fingerprint and apply it to 108 as they apply Login
blocks; Block Update (807) echoes it with `DATA_FRIEND_IDENTITY` and no
Login.

All existing enumeration rules apply: rate limits, `AccountNotFound` for
a subject who has blocked the caller, no presence for non-friends.
Lookup by handle is a directory question with the same answer
`AccountNotFound` when the server accepted no attestation for that handle,
so a client cannot learn from a miss whether the person is absent or
merely unattested here.

---

## Amendment C — an opaque envelope through the message path

### Problem

IM Send (810) requires `DATA_MESSAGE_BODY`, and *Security Considerations*
says the server observes content; that is the honest description of the
extension today. The identity spec's plan for end-to-end private messages
between identity users — encrypt to each recipient device's X25519 key,
no ratchet in v1 — wants to ride the existing message path rather than
invent a second one, because the offline queue, receipts and typing are
exactly right for it. Store-and-forward of ciphertext needs the server to
carry a body it cannot read, and a way for the sender to learn the
recipient's device keys.

This amendment asks only for the reservations and the one rule that lets
an envelope through. The construction of the envelope, key discovery
details and multi-device semantics belong in a separate document
(`Capabilities-Messaging-E2E`, to be written against the identity spec),
so that this extension's review is not held up on cryptography.

### Change

| ID (hex) | Dec | Name | Type | Description |
|---|---|---|---|---|
| `0x061F` | 1567 | `DATA_MESSAGE_ENVELOPE` | Binary | An encrypted message body addressed to one recipient device; **repeated**, one per device. Opaque to the server |
| `0x0628` | 1576 | `DATA_FRIEND_DEVICE_CERT` | Binary | A recipient device's identity-signed device certificate (identity spec §3.3, CBOR); **repeated**. Friend-only. The X25519 key is its `device_enc` |

A client that can produce and consume envelopes says so at Login (107)
with `CAPABILITY_MESSAGE_ENVELOPE` (bit 12 of `DATA_CAPABILITIES`,
provisional). Everything below is conditioned on that bit, per session.

Rules:

- In IM Send (810), `DATA_MESSAGE_BODY` becomes REQUIRED **unless at least
  one `DATA_MESSAGE_ENVELOPE` is present**. A send carrying envelopes MAY
  also carry a body; a send carrying neither is a failure.
- **A body-less send must be deliverable to everyone it will reach.** If
  any of the recipient's live sessions did not negotiate bit 12, the
  server fails the send with reason `15 BodyRequired` and delivers
  nothing; the sender re-sends with a body. (A device with a
  message-capable certificate on file is envelope-capable by definition,
  so offline devices never trigger this.) `DATA_FRIEND_CAPABILITIES` on
  the roster row lets a sender see it coming.
- IM Deliver (811) to a session that negotiated bit 12 carries the
  envelope(s) addressed to that session's device and the body if present.
  To a session that did not, it carries the body only; envelopes are
  stripped. A session never receives an envelope it cannot open or a
  message with nothing it can read.
- **Delivery and the offline queue are per device for envelopes.** The
  existing queue is account-scoped and one `Delivered` from any session
  settles the message; that cannot work when each device needs its own
  envelope. For a message with envelopes the server keeps delivery state
  per `(message, device)`: an envelope is queued for its device whether or
  not another device is live, `IM Acknowledge (812) Delivered` from a
  device settles that device's envelope only, and a device's flush on
  connect (Get Offline Messages, or the login-time flush) carries the
  envelopes still outstanding for it. The message as a whole is retained
  until every addressed device has acknowledged or `OfflineRetentionDays`
  elapses, whichever is first. Body-only messages keep the account-scoped
  behaviour unchanged. A device certified *after* a message was queued has
  no envelope for it and does not receive it; the E2E document owes an
  answer to that (a body fallback, or a re-send the recipient's other
  device performs), and this amendment only requires that the queue not
  pretend otherwise.
- `MaxMessageBytes` bounds the encoded size of the whole transaction's
  bodies and envelopes together, so an operator's cap means the same
  thing for both.
- Get User Info (825) returns `DATA_FRIEND_DEVICE_CERT` for each of the
  subject's devices whose certificate is on file and grants the message
  capability, **only when the caller is an accepted friend**, under the
  same rule as `DATA_FRIEND_CAPABILITIES`. It is the identity-signed
  device certificate itself (identity spec §3.3), not a bare key: a server
  that handed out raw X25519 keys could substitute its own and read
  everything, which is exactly the malicious-operator case the threat
  model says E2E defeats. A client MUST verify each certificate against
  the subject's identity key — the one in `DATA_FRIEND_IDENTITY`, which it
  should already hold from the roster — check validity and the message
  capability, and encrypt only to `device_enc` keys that pass; a
  certificate that fails is treated as absent. Device certificates are
  not part of the public card; they change with the subject's device
  list, which is a fact about the person's life a stranger has no
  business with.
- Two new reason codes. `14 NoDeviceKeys`: an envelope-only send names a
  recipient with no message-capable device certificate on file, so there
  is nothing the *sender* could have encrypted to; this is a failure
  (error flag set), not information. `15 BodyRequired`: as above.
- A new advertisement in the login reply's limits sub-block:

  | ID (hex) | Dec | Name | Type | |
  |---|---|---|---|---|
  | `0x0623` | 1571 | `DATA_MESSAGING_FEATURES` | UInt16 | Bit 0: identity fields (Amendment A/B) are sent; bit 1: envelopes are accepted, stored per device and forwarded |

  Absent means neither, which is what a server predating this proposal
  is. A client MUST NOT send envelopes to a server that has not set bit
  1: such a server rejects the send for lacking a body, which is the
  right outcome, but the client can do better than discover it that way.

### Allocation note

`0x061D`–`0x061F` are the three general IDs the spec reserves for future
messaging fields. This proposal uses all of them, and puts the device key
at `0x0628`, the first ID after the limits sub-block, which would need
its reservation extended (`0x0628`–`0x062F` for identity-related
messaging fields is the suggestion). If spending the last three general
IDs on this is unwelcome, `DATA_FRIEND_HANDLE` is the one to drop: a
client can fetch the card for a fingerprint from the identity spec's
`GET /identity/card/<fingerprint>` and read the handle there. The
fingerprint is the field the others depend on.

---

## Amendment D — security considerations

Two additions, one clarification.

**Public handle, password-less accounts.** After the existing *Public
handle* bullet:

> An account linked to a portable identity with `identity_login` enabled
> (identity spec §8) may have no password at all: possession of the
> identity's device key is the credential, proven at the transport layer
> before the session exists. For such an account the Login being public
> exposes nothing, and operators may prefer it for exactly the reason
> the previous bullet warns about. The `admin`/`guest` rule above is
> unaffected; it is about what those logins are, not how they
> authenticate.

**Transport encryption.** After the existing bullet:

> A message sent as envelopes only, to device certificates the sender
> verified against the recipient's identity key, carries content the
> server cannot read. That is the whole of the guarantee: a send that also
> carries a plaintext body is readable by the server regardless of the
> envelopes beside it, and a client that encrypts to a device key it did
> not verify has encrypted to whoever supplied the key. Where the
> guarantee holds it changes the trust statement for that path only: the
> server still sees who messages whom, when, and how much. A relayed file
> transfer and the public chat are unchanged.

**Identifier spoofing.** Append to the existing bullet:

> The same rule covers `DATA_FRIEND_IDENTITY` and `DATA_FRIEND_HANDLE`: a
> server attributes them from the account it resolved, never from a
> client-supplied value, and a client-supplied fingerprint in a request
> is a lookup key, not an assertion.

---

## Amendment E — editorial

- Under *Architecture → Identity Model*, add a row to the table:

  | Layer | Hotline equivalent | Stable across reconnect? | Role |
  |---|---|---|---|
  | Portable identity | linked identity fingerprint (identity spec) | Yes, and across servers and renames | Optional durable key beside the Login; never an addressing key on this wire |

- Under *Reuse of Existing Subsystems*, add: "**Identity** reuses the
  portable-identity layer where a server implements it (identity spec):
  a linked identity is an account, and this extension sees nothing
  else."
- Cross-reference the identity spec from the *Background* section's
  last paragraph.

---

## On hxd-ng's side

Not part of the proposal, listed so the whole picture is visible:

- The identity spec's `default_access` setting becomes an explicit access
  template rather than "whatever the guest account has", because guest
  must not hold `AccessMessaging` and an operator using `create` will
  want created accounts to.
- hxd-ng will honour `CAPABILITY_MESSENGER_SESSION` in the ng JSON
  roster as it must in the legacy user list.
- Roster, presence and IM need a JSON binding in `hotline-ng.md` for ng
  clients, as voice got. That is hxd-ng's work and not this extension's
  concern, but it is the reason hxd-ng has an interest in the fields
  above being stable before it is written.
- The E2E document will define the envelope construction against the
  identity spec's device certificates (X25519 keys, message capability
  bit) and say what a client does with a recipient who has both E2E and
  non-E2E devices.

## Allocation summary

| Kind | Value | Name |
|---|---|---|
| Field | `0x061D` | `DATA_FRIEND_IDENTITY` |
| Field | `0x061E` | `DATA_FRIEND_HANDLE` |
| Field | `0x061F` | `DATA_MESSAGE_ENVELOPE` |
| Field | `0x0623` | `DATA_MESSAGING_FEATURES` |
| Field | `0x0628` | `DATA_FRIEND_DEVICE_CERT` (needs the reserved range extended) |
| Capability bit | 11 | `CAPABILITY_IDENTITY` (provisional; allocated by this proposal, not by the identity spec) |
| Capability bit | 12 | `CAPABILITY_MESSAGE_ENVELOPE` (provisional; next after 11) |
| Reason code | 14 | `NoDeviceKeys` |
| Reason code | 15 | `BodyRequired` |

No new access bits or transactions. The two capability bits are the
additions since the first draft: 11 tells the server a client can parse
identity fields on a roster entry, and 12 is what makes body-less
delivery safe for sessions that predate this proposal.
