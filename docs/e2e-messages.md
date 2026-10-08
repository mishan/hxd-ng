# End-to-end encrypted private messages

Status: draft, 2026-10. Nothing here is built. This is the end-to-end
messaging document that `hotline-ng-identity.md` §3.3 names for the
`device_enc` key, and the construction the server linking user keys
draft leaves to it ("Sealed Messages in Link Private Message"). Where
the two differ, on what the signature binds (§3.1) and how freshness is
judged (§3.5), this document is the newer word, and the draft should
follow it.

A private message between two users who both log in with a key can be
**sealed**: encrypted to the recipient's device and signed by the
sender's, so that no server can read it, the two home servers included,
and none can write one in another user's name. Version 1 is deliberately
small:

- a **sealed box per message**: each message is encrypted to the
  recipient device's X25519 key with a fresh ephemeral key, and signed by
  the sender device's Ed25519 key. No ratchet, no prekeys, no session
  state on either client;
- **online and held messages**: to a session that is attached, or
  detached and resuming, on one server or across server links. Mail for a
  user with no session is not sealed in v1, but the format is built so a
  later version can seal it (§10);
- **text, quote and options** only. Images and other attachments stay
  outside v1.

## 1. What it protects, and what it does not

**Protects:**

- **Confidentiality from every server.** A sealed message is readable only
  by the device it was sealed to. Operators who log, a relay that is
  breached, a database copied off a disk: none of them can read it.
- **Sender authenticity.** The recipient can tell which identity sent a
  message, by its fingerprint, that it was meant for them, and that
  nobody altered it on the way.
- **Replay.** A message is never shown twice, or long after it was sealed.
  This holds against every server, the recipient's own included, because
  it is judged by the recipient's clock (§3.5).
- **Length, roughly.** Padding hides the exact size.

**Does not protect:**

- **A server that substitutes a key.** A client learns which fingerprint a
  user has from its server, and across links from every relay in between
  (user groups are not signed). A server that replaces a user's
  fingerprint and serves a matching device certificate can read what is
  sealed to that user, or seal in their name. On first contact only
  comparing fingerprints out of band protects against that; afterwards,
  a client that remembers contacts by fingerprint notices a change (§8).
- **Delivery.** Any server on the path can drop, delay (up to the hold
  time, §3.5), reorder or selectively deliver sealed messages, and the
  sender is never told.
- **Metadata.** Every server on the path sees who wrote to whom, when, and
  the padded size, which roughly tells a long message or one with a quote
  from a short one. A device certificate shows when it was issued and
  when it expires, which says how often its owner rotates, and a
  session's `sealed` flag says what kind of client it runs.
- **A stolen device key, after the fact.** Without forward secrecy, whoever
  holds a device's X25519 private key can open every message ever sealed
  to it that they have a copy of. Device certificates expire (90 days by
  the identity spec), and a device that rotates its key limits the damage
  to messages sealed to the old one. A ratchet is the cure, and a later
  version's (§11).
- **Deniability.** The sender's signature lets the recipient prove to
  anyone that the sender wrote a message. That makes a reported sealed
  message verifiable (§11), and it means a sender cannot disown one.
- **Revocation of the sender's device.** A recipient has no source of its
  own for whether the sender's certificate was revoked; it may ask its
  server (§3.4).
- **The endpoints.** A compromised client, or a recipient who copies a
  message, is outside any protocol. In a browser, the long-term keys are
  non-extractable, but the secrets derived for each message pass through
  script memory.
- **Downgrade.** Any server on the path can make sealing impossible, by
  hiding a fingerprint or refusing a certificate. A client must not then
  fall back to cleartext silently (§8).

`identity-threat-model.md` covers the identity keys these rest on; a
stolen device key and a malicious server operator are its scenarios too.

## 2. Keys

Every device certificate (`hotline-ng-identity.md` §3.3) carries two
keys:

- `device` (Ed25519): signs. Here it signs the sealed message's contents.
- `device_enc` (X25519): agrees keys. Here it is what a message is sealed
  to.

A certificate is used for messages only if its `caps` allow messages
(bit 1, or `caps` absent), it has not expired, and it is at most 512
bytes. A certificate meant for messages SHOULD leave out `name`, since it
crosses the network in full. A client keeps both private keys where it
keeps the device key today: hx-ng in WebCrypto, as non-extractable keys.

## 3. The construction

### 3.1 The sealed plaintext

A CBOR map in deterministic encoding, as `hotline-ng-identity.md` §3.1:

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `id` | bstr(16) | yes | Random. The message's identity for replay |
| `sent` | uint | yes | Unix seconds, when the sender sealed it |
| `to` | bstr(32) | yes | The recipient's identity fingerprint |
| `cert` | bstr | yes | The sender's device certificate, at most 512 bytes |
| `text` | tstr | yes | The message: 1 to 8192 bytes of UTF-8 |
| `quote` | tstr | no | The message it quotes, at most 8192 bytes |
| `auto` | bool | no | An automatic response (the classic options' meaning). Present only when true |
| `sig` | bstr(64) | yes | Ed25519 by the sender's `device` key |

```
sig = Ed25519.sign(device, "hl-identity/sealed-message/v1" || 0x00 || cbor_bytes_without_sig)
```

The signature covers everything else. The encryption already pins a
message to one device's key; `to` pins it to one identity. A certificate
is not a proof that its owner holds its `device_enc` key, so someone
could issue a certificate under their own identity that reuses another
person's key; `to` is what keeps a message sealed to that certificate
from being passed to the key's real owner as one meant for them. Unknown
keys are covered and ignored; a `v` other than `1` is rejected, as
identity objects are; a reader rejects a `tstr` that is not valid UTF-8,
a `text` that is empty or longer than 8192 bytes, a `quote` that is empty
or longer than 8192, and an `auto` that is present and not `true`.

**Signatures are verified strictly**, by one rule every implementation
applies exactly: `S` is less than the group order `L`; the public key `A`
is canonically encoded (it re-encodes to the same 32 bytes) and not of
small order; `R` is not of small order; and the cofactorless equation
`[S]B = R + [k]A` holds, `k` being SHA-512(`R` || `A` || message) reduced
mod `L`. WebCrypto's Ed25519 does not promise this rule, and browsers
differ, so a browser verifies with a script implementation of exactly it.
§13's vectors include a mixed-order `A` and a small-order `R`.

### 3.2 Padding

The plaintext is the CBOR map followed by zero bytes, up to exactly the
smallest of 512, 1024, 2048, 4096, 8192 or 17,103 bytes the map fits in.
A map that fits in none is too long and is not sent. A reader decodes
exactly one CBOR item from the start and requires every byte after it to
be `0x00`. The padding is outside the signature, and the AEAD protects
it. The largest map, a full message, a full quote, a 512-byte
certificate and `auto`, encodes to 17,068 bytes, inside the top size.

### 3.3 Sealing

HPKE (RFC 9180), base mode, with the suite

- KEM `0x0020`, DHKEM(X25519, HKDF-SHA256),
- KDF `0x0001`, HKDF-SHA256,
- AEAD `0x0002`, AES-256-GCM,

single-shot, to the recipient's `device_enc` key:

```
info   = "hl-identity/sealed-message/v1/hpke"
aad    = 0x01
enc, ct = HPKE.SealBase(pkR = device_enc, info, aad, plaintext)
sealed = 0x01 || enc (32 bytes) || ct
```

The leading byte is the format's version, and the AEAD's associated data
too: a reader rejects any other. This `info` is this format's alone; any
other use of a `device_enc` key (sealed push payloads, for one) uses an
`info` of its own, so a ciphertext made for one can never open as the
other. The X25519 result is checked as RFC 9180
requires: an all-zero shared secret is an error (WebCrypto throws on it;
x25519-dalek needs `was_contributory`).

AES-GCM rather than ChaCha20-Poly1305 because WebCrypto has the one and
not the other, and a browser client cannot take its non-extractable key
anywhere else. HPKE's key schedule needs HKDF's Extract and Expand as
separate steps, and WebCrypto's HKDF always runs both, so a browser
builds the two on HMAC-SHA256. Where RFC 9180 extracts with an empty
salt, a browser uses 32 bytes of `0x00`, which RFC 5869 makes the same
and WebCrypto's HMAC accepts. AES-GCM is not key-committing, which costs
nothing here: each ciphertext has one recipient key, and the signature
inside covers its contents. Franking, or one ciphertext for several
recipients, would need a commitment.

### 3.4 Opening

The recipient's client:

1. checks the first byte is `0x01`, and opens the rest with its
   `device_enc` key, `aad` = `0x01`;
2. checks the padding (§3.2) and the fields (§3.1), parses the map with
   `v = 1`, and checks `to` is its own identity fingerprint;
3. checks freshness (§3.5);
4. checks `(sender fingerprint, id)` is not one it has already accepted,
   the sender fingerprint being SHA-256 of `cert`'s identity key, never
   what the server says;
5. checks `cert`: a valid device certificate whose signature by its
   identity key verifies by §3.1's strict rule, whose identity key hashes
   to the **fingerprint the sender is shown with** (below), allowing
   messages, at most 512 bytes, issued no later than `sent` plus the skew
   allowance, and unexpired at `sent`, at the time its server received
   it, and now;
6. verifies `sig` strictly (§3.1) with `cert`'s `device` key;
7. records `(sender fingerprint, id)` as accepted, in one atomic
   insert-if-absent, and shows it only if the insert added it; if it was
   already there, the message is dropped as at 4.

The fingerprint the sender is shown with is the event's
`from.fingerprint` (§4.4), and it holds only if the roster, when the
event arrives, shows the same fingerprint for `from.uid` or shows nobody
at that uid (a sender who has since left). A uid the roster shows with
another fingerprint, or with none, makes the message unverified.

A message that fails 1 or 2 is shown as one that could not be opened.
One that fails 3 or 4 is dropped without being shown: a replay is not a
message. One that fails 5 or 6 is shown as **a message that could not be
verified**, without its text, which the user can reveal only on purpose,
marked as unverified, never as from that user, and its `id` is not
recorded. Anyone who holds the recipient's certificate can seal a
message to it, so unverified text must not read like a message.

A client that wants more than the certificate's expiry may compare
`cert`'s `device` and `device_enc` keys (not its bytes, since a renewed
certificate differs) with what `device_cert` (§4.2) returns for the
sender now, while the sender still has a session. That detects only a
certificate other than the sending session's current one. It is not a
revocation check: the server answering for that session is whichever
one the sender logged in to, and a thief with a revoked key logs in
where the revocation has not been seen.

A client names a verified sender by the certificate's fingerprint, and
the contact it has pinned to it (§8), not by the nick the server shows,
and shows the signed `sent` beside the server's `at`.

### 3.5 Freshness and replay

Judged by the recipient's own clock, so no server can stretch it:

- `sent` must lie between `M − H` and `now + S`, `M` being the later of
  `now` and the latest time the client has seen (below), where `H` is how long a
  message can be held, **24 hours** in v1, and `S` the skew allowance,
  ten minutes. A session's grace (five minutes by default) is far
  shorter; `H` leaves room for a server that sets a longer one, and
  bounds how long any server can sit on a message, and how far back a
  stolen key can date one.
- An accepted `(sender fingerprint, id)` is remembered until `sent + H +
  S`. The memory is stored with the device key, kept across restarts,
  and shared by every session using it (several tabs, or several
  processes of one client): checking and recording are one atomic step,
  and the record is written before the message is shown. A client keeps
  the latest time it has seen, stored with the memory, and prunes by it,
  so a clock set back neither empties the memory nor reopens the window
  for what it pruned. A clock set forward and then corrected leaves the
  client refusing messages until it catches up, which is the safe side.

The time the recipient's home server received the message is still
passed along (`at`, §4.4), for display and as one of the certificate's
expiry checks, but freshness never rests on it, since that server is one
of the parties a sealed message keeps out. A client whose clock is off,
the sender's by more than `S` or the recipient's by more than `H`, drops
or has dropped what it should not. A client compares its clock with the
server's `at` and warns when they differ by more than `S`; it never sets
its clock from the server's, which would hand the server the check.

## 4. On a Hotline-ng server

These add to `hotline-ng.md`: a login parameter, a request, `msg`
parameters, event fields, a roster field and the error codes
`not_sealed` and `cert_changed`, registered
there when they are built. `private-messages.md` §6.1 carries the
sealed rows of its delivery rule (§4.3).

### 4.1 Saying a client can open them

A client that can open sealed messages sends `"sealed": true` in `login`
and in every `resume`, and only if its session proves a device key whose
certificate allows messages and is at most 512 bytes. The login reply
echoes `"sealed": true` when the server will carry them. A roster row's
`identity` gains `"sealed": true` for such a session, so other clients
know before they ask.

A session that resumes without `"sealed": true`, or on a connection
proving a different `device_enc` key, or none, loses `sealed` (a renewed
certificate with the same keys keeps it): its roster row changes
(`user_changed`), and every sealed message held for it is replaced in
the outbox by the placeholder event (§4.4, without `sealed`, with
`"sealed_lost": true`, which only a server sets, so a client can say a
message to this device was lost), never removed, since an outbox's seqs
are gapless. A later `resume` with `"sealed": true`, proving a
certificate that allows messages, regains `sealed`; what was replaced
stays replaced.

### 4.2 Fetching a certificate

```
→ { "req": "device_cert", "params": { "uid": 7 } }
← { "ok": { "cert": "<base64url>" } }
```

The certificate of the device the session `uid` proved, local or a
linked server's user's (through Link Device Keys, 915). It is the
certificate the session proves now, after any resume, not the one it
logged in with. Only a session
that is itself `sealed` may ask; any other is refused `not_sealed`.
Refused also `no_such_user`, `not_sealed` (the target cannot open sealed
messages, or its certificate does not allow messages, has expired or is
revoked), `blocked`, or `not_delivered` (a linked server refused or did
not answer). It weighs 4 against the request limit, as a search does,
and is rate-limited on top, since it is what a client would scrape to
watch who logs in with which device.

A client checks the certificate exactly as §3.4 step 5 checks the
sender's, against the fingerprint the roster shows for `uid`, and seals
only to one that passes.

### 4.3 Sending

`msg` gains `sealed`, base64url of §3.3's bytes, in place of `text`, and
`cert`, base64url of the SHA-256 of the `device_enc` key it was sealed
to (the key, not the certificate, so a renewal with the same keys
changes nothing):

```
→ { "req": "msg", "params": { "to": 7, "sealed": "AQ…", "cert": "q2…" } }
← { "ok": { "queued": false } }
```

`sealed` without `cert`, or with `to_login`, `text` or `media`, is
`bad_request`, and so is a size other than one of §3.2's plus 49 bytes;
`guid` does not apply. The sending session must itself be `sealed`. The
server checks what it can: that `cert` names the `device_enc` key of the
target session's current certificate, still unexpired and not revoked,
that the target can open sealed messages, and every rule a `msg` already
has (blocks, limits, refusals). A `cert` that names another key is
refused `cert_changed`: the client fetches the certificate again and
seals again, and never takes it as a reason to fall back to cleartext.
Anything else that fails is `not_sealed`, and a user with no session is
`no_such_user`. For a ghost, the check is the target's home server's
(§5).

**A sealed message is never stored.** To a detached session it goes into
the outbox, whether or not the account has an inbox, and is delivered at
resume; the reply is always `queued: false`. So sealed and cleartext mail
for one detached account can arrive out of order, the one at resume and
the other from the inbox. A sealed message is lost, and nobody is told,
if the outbox overflows (`resync_required`) or the session's grace runs
out first; `inbox` cannot recover it. A sender who needs to know it
arrived asks. A held sealed message weighs its full size in the outbox
and against the server's queue budget (`Event::weight`).

Since a held sealed message has no durable copy, one sender must not be
able to overflow someone's outbox with them and so destroy what others
sent. A detached session holds at most so many bytes of sealed messages
from one sender, and so many in all (hxd-ng: `[sealed]
held_per_sender_kb`, 64, and `held_kb`, 256); past either, a `msg` is
refused `mailbox_full` and the outbox is untouched. A sealed `msg` also
weighs 2 against the request limit, as any `msg`, plus 1 for each 2048
bytes of `sealed`.

A client retrying a sealed message resends the same bytes, the same
`id` inside, so the recipient keeps only one.

A sealed message carries up to 8192 bytes of text, where a cleartext ng
message carries 4096: a client falling back to cleartext (§8) splits a
longer message, or sends nothing until the user confirms.

### 4.4 Receiving

The `msg` event for a sealed message carries:

- `sealed`, the bytes as sent;
- `from`, with `fingerprint` as the server knows it;
- `at`, when this server received it, whatever the delay until it was
  delivered;
- `queued: false`, and no `id` (it is never stored);
- `text`: the placeholder `[Encrypted message]`, for anything that cannot
  open it.

A client that understands `sealed` ignores `text` and any options outside
the sealed message.

When the client replies, it seals only to a certificate whose identity
key hashes to the fingerprint the message was verified under. A uid is
not a person: uids are reused, and a server can name any uid in `from`.
If the roster shows no session with that fingerprint at the uid the
client would send to, it looks for one that has it, or asks the user.

### 4.5 What a server must never do

Decrypt (it has no key that could), log, or keep a sealed message past
its delivery; keep it in chat history or an inbox; or put a sealed
message's size in a log line. These keep what a server can learn to what
the wire shows.

## 5. Across server links

As the server linking user keys draft has it: a certificate crosses as
Link Device Keys (915), and a sealed message as `DATA_LINK_SEALED` in
Link Private Message (905), with the placeholder in `FieldData` and the
quote only inside. The sender's fingerprint is the one in the sending
ghost's user group. A home server delivering a sealed 905 to an ng
session passes the time it received it as `at`. The sending server puts
`msg`'s `cert` in the 905 as `DATA_LINK_SEALED_TO`, and the target's home
server checks it as §4.3 does, refusing `NoDeviceKeys` for a target
that cannot open sealed messages or whose current `device_enc` key is
another; the sending server answers its client `cert_changed` or
`not_sealed` to match. The check is needed because a ghost's ID
promises no device: a link quarantines an old ID only for minutes, and
not across a restart, so a 905 can reach whoever holds the ID now, and
nothing carries a session's `sealed` across a link but the answer to
915.

Two of the draft's rules give way to this document's: its signature over
"the recipient's device key" is this one's over the recipient's identity
fingerprint (§3.1), and its ten-minute freshness window, judged by the
home server's time, is this one's recipient-clock rule (§3.5). The
draft's own text, its revocation paragraph's included, should be brought
in line.

## 6. On the classic wire

Not in v1. A classic client would need a way to fetch a ghost's or a
user's certificate and to send and receive the sealed field, which
belongs with the identity amendments to fogWraith's Messaging extension,
whose rule that no messaging transaction names a ghost would need an
exception. GtkHx is the client expected to do it. That amendment queues messages
offline for days, which v1's hold time would drop; it needs §10's mail
marker first. A classic client that knows nothing of this receives the
placeholder.

## 7. Limits

- A sealed message counts against every limit a message does: the
  sender's spam points, the ng request bucket, the recipient's blocks.
- `device_cert` is rate-limited per session (§4.2).

## 8. What a client should do

- **Remember contacts by fingerprint**, with the name and server they were
  seen under, and warn when a remembered contact appears without one or
  with a different one.
- **Never fall back silently.** If sealing is impossible to someone it has
  sealed to before, send in the clear only after the user confirms; show
  for every message, sent and received, whether it was sealed.
- **Show fingerprints** for comparing out of band, and record a contact as
  compared once the user says so.
- **Keep private keys non-extractable** where the platform allows.

## 9. Size

| Part | Bytes |
|---|---|
| Version | 1 |
| HPKE `enc` | 32 |
| Plaintext, padded | 512 to 17,103 |
| AES-GCM tag | 16 |
| **Sealed** | **561 to 17,152** |

The largest is the whole of what the linking draft allows
`DATA_LINK_SEALED`; as base64url in a `msg`, about 22,900 characters.

## 10. Leaving room for offline messages

Version 1 does not seal mail for a user with no session, but nothing in
the format is tied to a session, so a later version can:

- **A message is sealed to a device key, not a session.** Mail for a user
  can be sealed to each of their devices that allows messages, each copy
  its own sealed message. Copies can share an `id` so a client can group
  them, but nothing makes them identical (a sender could give each
  device different text) and nothing syncs one device's replay memory to
  another's, so each copy is judged on its own. Where those certificates
  come from (the user's card, the registrar, or their home server's
  record of devices that have logged in) is the later version's
  question; v1 only ever uses the one a session proved.
- **Freshness is the recipient's to judge, with a hold time.** Stored mail
  needs a longer `H`. A later version would mark mail as mail inside the
  signature, so a server cannot pass an old held message off as mail to
  get the longer window; a v1 reader ignores that unknown key and keeps
  v1's `H`, which is the safe side.
- **The format is versioned twice** (`v`, and the leading byte), so a
  later version that adds fields, or changes the construction for stored
  mail, is recognized rather than misread.

What it would still need: an inbox that holds a sealed copy per device;
a way to know a user's devices without a session; and an answer for a
device added after the mail was sent, which cannot read it.

## 11. Later

- **Forward secrecy.** A ratchet, or per-device prekeys published with the
  card, so that a stolen device key does not open past messages.
- **Offline mail** (§10).
- **Reports.** `docs/moderation.md`'s report of a private message carries
  free text; a sealed message's plaintext with its signature and
  certificate would let a moderator verify what was reported, at the
  price of the sender's deniability, which §1 already gives up. The
  moderator's tool and the client must verify by the same rule (§3.1).
- **Attachments**: an image's handle sealed with the text, and its bytes
  encrypted under a key carried inside.
- **The classic wire** (§6).
- **Private chat**, which needs a group construction this one is not.

## 12. Open questions

- Should `device_cert` also answer for a user who is offline, from the
  devices that have logged in before? That is the first step of §10, and
  it reveals which devices a user has.
- Should the roster show `identity.sealed` to everyone, or only to
  sessions that are `sealed` themselves, since it reveals which client
  someone uses?

## 13. Test vectors

To come, beside `identity-test-vectors.json`: a sealed message with its
keys, ephemeral key, plaintext and bytes, and the strict-verification
edges of §3.1. RFC 9180 prints no vector for this suite; the CFRG's
`test-vectors.json` for HPKE has one, and an implementation should pass it
first.
