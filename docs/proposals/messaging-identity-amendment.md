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
2. lookup by handle or fingerprint in Find User and User Search;
3. field reservations and one rule change so an encrypted message body
   can travel through IM Send / IM Deliver and the offline queue opaquely;
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
> friend, send a Roster Entry (801) for the new Login. If the account has
> a linked identity, that entry carries `DATA_FRIEND_IDENTITY`, and a
> client that finds an existing row with the same fingerprint MUST
> rename that row in place, preserving its alias and local state; the
> server MUST NOT send a `Removed` for the old Login in that case. If the
> account has no linked identity, send a removal for the stale Login
> followed by the fresh entry, as before.

### Client rule

Add to *Client Behaviour*:

> 11. Treats `DATA_FRIEND_IDENTITY`, when present, as the durable key for
>     a roster row: two entries with the same fingerprint are the same
>     person even if their Login differs, and a client MAY offer to merge
>     local state (aliases, history) across them. The Login remains the
>     addressing key on the wire.

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
| `0x0628` | 1576 | `DATA_FRIEND_DEVICE_KEY` | Binary (32) | A recipient device's X25519 public key; **repeated**. Friend-only |

Rules:

- In IM Send (810), `DATA_MESSAGE_BODY` becomes REQUIRED **unless at least
  one `DATA_MESSAGE_ENVELOPE` is present**. A send carrying envelopes MAY
  also carry a body (a fallback for the recipient's non-E2E devices, or
  a placeholder); a send carrying neither is a failure.
- IM Deliver (811) forwards every envelope unchanged, and the body if
  present. The offline queue stores envelopes as it stores bodies.
  `MaxMessageBytes` bounds the encoded size of the whole transaction's
  bodies and envelopes together, so an operator's cap means the same
  thing for both.
- Get User Info (825) returns `DATA_FRIEND_DEVICE_KEY` for each of the
  subject's devices whose certificate is on file and grants the message
  capability, **only when the caller is an accepted friend**, under the
  same rule as `DATA_FRIEND_CAPABILITIES`. Device keys are not part of
  the public card; they change with the subject's device list, which is
  a fact about the person's life a stranger has no business with.
- A new reason code: `14 NoDeviceKeys` — the recipient has no device the
  server can encrypt to. Returned by IM Send when a send carries
  envelopes only and the server knows the recipient has no message-capable
  device on file; informational, since a sender who fetched keys first
  will not see it.
- A new advertisement in the login reply's limits sub-block:

  | ID (hex) | Dec | Name | Type | |
  |---|---|---|---|---|
  | `0x0623` | 1571 | `DATA_MESSAGING_FEATURES` | UInt16 | Bit 0: identity fields (Amendment A/B) are sent; bit 1: envelopes are accepted and forwarded |

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

> Where both peers are identity users on message-capable devices, the
> envelope path of IM Send (810) carries content the server cannot read.
> This changes the trust statement for that path only: the server still
> sees who messages whom, when, and how much. A relayed file transfer and
> the public chat are unchanged.

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
| Field | `0x0628` | `DATA_FRIEND_DEVICE_KEY` (needs the reserved range extended) |
| Reason code | 14 | `NoDeviceKeys` |

No new capability bits, access bits or transactions.
