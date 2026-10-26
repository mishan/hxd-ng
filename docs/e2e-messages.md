# Signed and sealed messages

Status: draft, 2026-10. `hl-identity` has the signed objects of §3.1 to
§3.5, their detached and link forms (§5), and sealing and opening both
kinds of box (§3.7 to §3.11), with §13's vectors for them. hxd-ng
carries signed public lines, in the lobby and in rooms, signed private
messages that are not sealed, and signed articles, on the ng wire: the
`signed` capability and `signs` (§4.6), the checks of §4.11 on ingest,
the indexes of signed lines and signed articles by `(signer, id)` (§4.7,
§4.10), `signed` on events, `history`, `inbox` and articles, rooms that
require signing (§4.8), and moderation's share of them (§4.12), the
classic wire getting the text alone (§6); and sealed private messages:
`sealed` at login and resume and on the roster, `device_cert`, `msg`
carrying a box to the session of the device it was sealed to, held for a
detached one within `[sealed]` and lost with `sealed_lost` by a resume
without `sealed`, never stored (§4.1 to §4.5), and a sealed message's
report (§4.12); and both across server links, to and from peers that
try the server linking user keys draft (§5, `server-link.md` §7.7):
signed lobby lines and signed private messages in their link form,
checked where they arrive once the certificate a server fetches by Link
Device Keys is held, sealed messages, `device_cert` for a linked
server's user, and pasted evidence of a linked server's line. A signed
lobby line reaches a peer that does not try the draft with its signature
all the same (§4.11). A session's device is the one it logged in with (`hotline-ng.md` §6.2),
so a resume cannot prove another `device_enc` (§4.1). The indexes do
not reach a redacted line or a deleted
article, whose content goes with its words (§4.12). Secure rooms are not
built yet, so `/rooms` shows `(signed lines only)` alone (§4.8). This is
the end-to-end messaging document that `hotline-ng-identity.md` §3.3
names for the `device_enc` key, and the construction the server linking
user keys draft leaves to it ("Sealed Messages in Link Private
Message"); §5 follows that draft's link wire, and §6 the messaging
identity draft's classic one. It rests on the `server_challenge` and
`[identity] hosts` of `hotline-ng-auth.md` §6.2, `hotline-ng.md`'s
`chat_guid` (§4, §7.1, §7.3), and hl-identity's `verify_domain`, which
refuses a key that does not re-encode to its own bytes (§3.1). Rotating
the server key with a handover is `server-key-handover.md`'s (§4.13).

A user who logs in with a key can **sign** what they write with their
device's key, so that no server can write a line in their name or alter
one, and a private message between two such users can also be
**sealed**: encrypted to the recipient's device, so that no server can
read it, the two home servers included. Signing and sealing are one
construction in two layers. The signed message (§3.1) is a signed
identity object; sealing (§3.8) encrypts that same object, padded, to
one device. Version 1 is deliberately small:

- **signed objects for three scopes**: a private message, bound to its
  recipient; a line of public chat, bound to its server and room; and a
  news article, bound to its server and category. Each is signed by the
  sender device's Ed25519 key, and is sent beside its text when it is not
  sealed;
- a **sealed box per private message**: each is encrypted to the
  recipient device's X25519 key with a fresh ephemeral key, either
  holding a signed message or, where the sender wants a message it can
  deny, authenticated by the sender device's own X25519 key instead
  (§3.11). No ratchet, no prekeys, no session state on either client;
- **the sender's choice**: whether a line is signed is decided by its
  sender, line by line (§1.3), except that a curated room can require it
  (§4.8). Private chats are never signed in v1;
- **online and held sealed messages**: to a session that is attached, or
  detached and resuming, on one server or across server links. Mail for
  a user with no session is not sealed in v1, but the format is built so
  a later version can seal it (§10). Signed messages that are not sealed
  are stored like any other;
- **text, quote and options** only. Images and other attachments are not
  covered by a signature, and not sealed, in v1.

## 1. What it protects, and what it does not

### 1.1 Signing

**Protects:**

- **Authorship against every server.** A signed line, message or
  article names its author by the identity fingerprint of the device
  certificate inside it, never by what a server says. No server, home
  or relay, can write a signed one in someone's name, or alter one,
  without the reader noticing. That holds where nothing else protects
  it: chat history served long after the fact, a linked server's lines
  relayed through servers that could rewrite them, moderation evidence,
  and news meant to be attributable for years.
- **Integrity of exactly what was said**: the text, an action's style, a
  message's options, an article's subject, body, type and parent.
- **Scope.** A line said in a room cannot be shown as said in the lobby,
  in another room, under another server key, or as a private message; a
  private message cannot be shown as one to someone else. "Another
  server" holds only as far as server keys tell servers apart (below),
  and for a linked server's line it rests on this server's word about
  that server's key (§5), which a reader has no pin of its own for.

**Does not protect:**

- **Delivery, order or completeness.** Any server on the path can drop,
  delay, reorder, withhold from some readers, or serve history
  selectively. A signature proves each line, never the conversation. A
  per-sender hash chain would expose some gaps in one sender's lines;
  v1 has none.
- **Confidentiality.** A signed message that is not sealed is read and
  logged by every server it crosses.
- **Replay, beyond showing it.** A server can show a signed line or
  message again. The reader sees when and where it was signed (§3.6),
  and a duplicate of one it holds is dropped; a server can still show
  one the reader has not seen at a later time.
- **A server that substitutes a key**, as for sealing (§1.2): a server
  that invents a user with its own key can sign as that user. Only a
  client that remembers contacts by fingerprint (§8) turns a signature
  into "the same person as last time".
- **Telling a stripped signature from none.** Unsigned lines are
  legitimate (classic clients, guests, clients and users that do not
  sign), so a server or a relay can drop the signature and deliver the
  text as an unsigned line. A client that remembers that a contact
  signs, and the roster's `identity.signs` (§4.6), turn some of that
  into a warning (§8); a hostile server can clear the flag too.
- **Deniability** (§1.3).
- **A server that shows another server's key.** "This server" in a
  scope means the `server_key` this host gave. Anyone can publish
  anyone's key in discovery; what makes a server prove it holds its own
  for a host is the `server_challenge` it signs in its challenge reply
  (`hotline-ng-auth.md` §6.2), which it signs only for the names in
  `[identity] hosts`. A client pins a key per host on that signature
  (§8), never on discovery's word, so a server offers `signed` only
  with those names configured (§4.6). At first contact over plain HTTP
  the pin is trust on first use: a network attacker can then sign a
  challenge with a key of its own. §12 keeps a question open.
- **A changed server key.** It warns, and what was signed under the
  old one shows as signed for elsewhere (§4.13).
- **What happened to the device later, or a stolen key.** A line or an
  article is not checked against now (§3.5), and `at` is the server's
  word, so a thief holding a device key, with a server willing to
  serve what it writes, can make history dated anywhere inside the
  certificate's life that verifies for good. Revocation does not tell
  those lines from the device's real ones, since nothing says when the
  key was taken. Only an honest server's check at ingest, `sent` within
  `S` of its clock (§4.11), bounds it.
- **Attachments.** An image on a signed line or article is not covered,
  and is shown as such (§8).

### 1.2 Sealing

**Protects:**

- **Confidentiality from every server.** A sealed message is readable only
  by the device it was sealed to. Operators who log, a relay that is
  breached, a database copied off a disk: none of them can read it.
- **Sender authenticity.** The recipient can tell which identity sent a
  message, by its fingerprint, that it was meant for them, and that
  nobody altered it on the way: the sealed message is a signed one, or,
  sealed in auth mode, authenticated by the sender device's key
  (§3.11).
- **Replay.** A message is never shown twice, or long after it was sealed.
  This holds against every server, the recipient's own included, because
  it is judged by the recipient's clock (§3.10).
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
  time, §3.10), reorder or selectively deliver sealed messages, and the
  sender is never told.
- **Metadata.** Every server on the path sees who wrote to whom, when, and
  the padded size, which roughly tells a long message or one with a quote
  from a short one. A device certificate shows when it was issued and
  when it expires, which says how often its owner rotates, and a
  session's `sealed` flag says what kind of client it runs. A box's
  leading byte says whether it is signed or deniable.
- **A stolen device key, after the fact.** Without forward secrecy,
  whoever holds a device's X25519 private key can open every message
  ever sealed to it that they have a copy of. Since that key also
  authenticates a deniable box (§3.11), they can write deniable boxes as
  that device to anyone, until its certificate expires: `device_enc`
  is as good as a signing key for deniable messages. Device
  certificates expire (90 days by the identity spec), and a device that
  rotates its key limits the damage to messages sealed to the old one. A
  ratchet is the cure for reading, and a later version's (§11).
- **Deniability**, for a signed box (§1.3).
- **Key-compromise impersonation**, for a deniable box (§3.11). Whoever
  holds a device's X25519 private key can write deniable boxes to that
  device that open as from anyone whose certificate they have, and the
  device cannot tell them from real ones.
- **Revocation of the sender's device.** A recipient has no source of its
  own for whether the sender's certificate was revoked; it may ask its
  server (§3.9).
- **The endpoints.** A compromised client, or a recipient who copies a
  message, is outside any protocol. In a browser, the long-term keys are
  non-extractable, but the secrets derived for each message pass through
  script memory.
- **Downgrade.** Any server on the path can make sealing impossible, by
  hiding a fingerprint or refusing a certificate. A client must not then
  fall back to cleartext silently (§8).

`identity-threat-model.md` covers the identity keys these rest on; a
stolen device key and a malicious server operator are its scenarios too.

### 1.3 Deniability, and why signing is the sender's choice

An Ed25519 signature is **transferable**: whoever holds a signed message
and its certificate can prove to anyone that the identity's device
signed exactly that text, in that scope, claiming that time. A signed
sealed message gives that up to its recipient, which is what makes a
reported private message verifiable (§4.12), and a sender cannot disown
one.

A private message can be sealed **deniably** instead (§3.11): HPKE's
auth mode, keyed by the two devices' X25519 keys, convinces the
recipient that the sender's device wrote it and convinces nobody else,
since the recipient's key could have made the same box. Deniable means
to anyone who trusts neither the recipient nor the servers on the path:
the sender's server saw which authenticated session submitted the box,
so a server that logs boxes, which §4.5 forbids and a hostile one does
anyway, and a recipient who reveals the plaintext can together attribute
it. So a sender's choice for private messages is signed and sealed,
which is attributable, or sealed deniably; a message that is not sealed
is signed or not, as a line is. Sealing with no sender authentication at
all, HPKE's base mode around an unsigned message, is never offered:
anyone who holds the recipient's public key, its server included, could
write one, so it would authenticate nothing while looking as private as
the rest.

For public chat that changes what chat is. Hotline chat has always been
deniable in practice: the server's log is its operator's word, and a
private chat is the conversation that leaves no record
(`chat-rooms.md` §5.1; `chat-history.md` §3.3 never logs one). A signed
line is a record on every disk it reaches: one leaked log becomes proof
of who said what, which serves harassment as readily as moderation. So
signing is never a property of logging in with a key. The sender's
client decides for each line, by a setting the user keeps per scope
(§8); a room may require it (§4.8), and a user then posts there
knowingly. News is publication, where being attributable is the point.

A signed line also carries its certificate, and so the sender's
identity and device keys, into history, into every reader's copy and
across links, where an unsigned line's sender is a nick and, for a
ghost, no identity at all. `chat-history.md` §3.3's rule that a line's
fingerprint never crosses either wire does not hold for a signed line:
its fingerprint is in the line.

**Private chats are never signed in v1**, and a private chat cannot
require it: a signature would leave exactly the record that a private
chat exists not to leave. Signed lines that stop proving anything once
the conversation is over need short-lived keys published on expiry,
which v1 does not have (§11).

## 2. Keys

Every device certificate (`hotline-ng-identity.md` §3.3) carries two
keys:

- `device` (Ed25519): signs. Here it signs every signed message (§3).
- `device_enc` (X25519): agrees keys. Here it is what a private message
  is sealed to, and, in a deniable box, what authenticates its sender
  (§3.11).

A client signs or seals only with a certificate whose `caps` allow
messages (bit 1, or `caps` absent), that has not expired, and that is
at most 512 bytes. Bit 1 covers public lines and articles as well as
private messages: there is no separate bit for them. A certificate
meant for messages SHOULD leave out `name`, since it crosses the network
in full and, on a public line, reaches every reader. A client keeps both
private keys where it keeps the device key today: hx-ng in WebCrypto, as
non-extractable keys.

## 3. The construction

### 3.1 The signed message

A signed message is a CBOR map in deterministic encoding, signed as
every identity object is (`hotline-ng-identity.md` §3.1):

```
sig = Ed25519.sign(device, domain || 0x00 || cbor_bytes_without_sig)
```

There are three, each with a domain and a scope of its own:

| Object | Domain | Scope |
|---|---|---|
| Private message (§3.2) | `hl-identity/message/v1` | `to`: the recipient's identity fingerprint |
| Public line (§3.3) | `hl-identity/chat/v1` | `in`: `{ server, room }` |
| Article (§3.4) | `hl-identity/news/v1` | `in`: `{ server, category }` |

The domains keep one object from ever verifying as another, and the
scope keys differ as well, so a line cannot pass for a message even
where the maps are otherwise alike. Unknown keys are covered and
ignored, with these exceptions: a line or an article that carries `to`,
and a private message that carries `in`, is rejected, which keeps the
barrier structural; `in` holds exactly the keys its object's table
gives it; so does an article's `parent`; and a map that carries
`cert_sha256`, which only the link form holds (§5), is rejected. A `v`
other than `1` is rejected, as identity objects are; a reader rejects a
`tstr` that is not valid UTF-8, and each object's table says what else
it rejects. `S`, the skew allowance used below, is ten minutes.

**Signatures are verified strictly**, by one rule every implementation
applies exactly: `S` is less than the group order `L`; the public key
`A` is canonically encoded (it re-encodes to the same 32 bytes) and not
of small order; `R` is not of small order; and the cofactorless
equation `[S]B = R + [k]A` holds, `k` being SHA-512(`R` || `A` ||
message) reduced mod `L`, checked by comparing the encoding of
`[S]B − [k]A` with `R`'s bytes, so that a non-canonical `R` fails. (This
`S` is the signature's scalar, not the skew allowance.) A mixed-order
`A` is not of small order, so it is accepted when the cofactorless
equation holds, as hl-identity's check accepts it: `verify_domain`
refuses a small-order key (`is_weak`) or one that does not re-encode
to its 32 bytes, then runs ed25519-dalek's `verify_strict`. A
signature that satisfies only the cofactored equation, `[8][S]B = [8]R
+ [8][k]A`, is rejected, and so is a key in its second encoding, as
§13's vector checks. WebCrypto's Ed25519 does not promise this rule,
and browsers differ, so a browser verifies with a script
implementation of exactly it. §13's vectors pin both edges of a
mixed-order `A` and a small-order `R`.

**Canonical text.** Every text a signature covers (`text`, `quote`,
`subject`, `body`) is signed in canonical form: each CR LF pair, and
then each remaining lone CR, replaced by one LF. Nothing else changes:
no Unicode normalization, no trimming, no change to a leading or
trailing line break. A signer canonicalizes before signing and sends
the canonical text; a verifier canonicalizes the text it was handed
before checking it, since a server link carries CR line endings
(`server-link.md` §4.4) and classic egress rewrites them. Every limit
on a signed text is measured on its canonical form. A canonical text
holds no U+0000 and no other C0 control but LF and TAB; a reader
rejects one that does, and a server answers a request carrying one
`bad_request`. Unicode normalization is left out on
purpose: a verifier re-checks the bytes it was given, as a card's
verifier does (`hotline-ng-identity.md` §3.4).

**Detached and whole.** A signed message travels two ways:

- **Whole**: the complete map, `sig` included. A sealed message seals the
  whole private message (§3.7, §3.8), and a report can carry one (§4.12).
- **Detached**: the map without its text keys (`text` for a private
  message or a line; `subject` and `body` for an article), `sig` kept,
  in deterministic encoding, carried beside the text it signs. This is
  how a signed message that is not sealed is sent, stored and served, so
  the text crosses the wire once. A detached form is at most 1020 bytes,
  the bound the classic wire's `DATA_MESSAGE_SIGNED` shares (§6); one
  that holds a text key is rejected. Across a server link it travels in
  a smaller **link form**, with `cert` replaced by its hash (§5).

To verify a detached form, a reader decodes it (rejecting a
non-deterministic encoding, as for any identity object), inserts the
canonical text under its key, and encodes the result without `sig` in
deterministic encoding: those bytes, after the domain and `0x00`, are
what `sig` covers. A whole map and its detached form with the same text
therefore have the same signature.

### 3.2 The private message

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `id` | bstr(16) | yes | Random. The message's identity for replay, and the `guid` of a signed `msg` (§4.9) |
| `sent` | uint | yes | Unix seconds, when the sender signed it |
| `to` | bstr(32) | yes | The recipient's identity fingerprint |
| `cert` | bstr | yes | The sender's device certificate, at most 512 bytes |
| `text` | tstr | yes | The message, canonical: 1 to 8192 bytes of UTF-8 in a whole map, 1 to 4096 beside a detached form |
| `quote` | tstr | no | The message it quotes, canonical, at most 8192 bytes. Whole maps only |
| `auto` | bool | no | An automatic response (the classic options' meaning). Present only when true |
| `sig` | bstr(64) | yes | Ed25519 by the sender's `device` key, domain `hl-identity/message/v1` |

A sealed message's encryption pins it to one device's key; `to` pins it
to one identity. A certificate is not a proof that its owner holds its
`device_enc` key, so someone could issue a certificate under their own
identity that reuses another person's key; `to` is what keeps a message
sealed to that certificate from being passed to the key's real owner as
one meant for them. For a message that is not sealed, `to` is the only
thing that does. The limits follow the form a reader holds, which it
can always see: a whole map (opened from a sealed message, or carried
in a report) may carry a `quote` and up to 8192 bytes of text; a
detached form, `msg`'s `signed` (§4.9), carries no `quote`, since the
cleartext `msg` has none, and its text is at most 4096 bytes, the
cleartext limit. A reader rejects a `text` that is empty or longer than
its form allows, a `quote` that is empty, longer than 8192, or in a
detached form, and an `auto` that is present and not `true`.

### 3.3 The public line

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `id` | bstr(16) | yes | Random. The line's identity, and the `guid` of its `chat` request (§4.7) |
| `sent` | uint | yes | Unix seconds, when the sender signed it |
| `in` | map | yes | `{ "server": bstr(32), "room": uint }` |
| `cert` | bstr | yes | The sender's device certificate, at most 512 bytes |
| `text` | tstr | yes | The line, canonical: 1 to 4096 bytes of UTF-8 |
| `act` | bool | no | An action (`style: "action"`). Present only when true |
| `sig` | bstr(64) | yes | Ed25519 by the sender's `device` key, domain `hl-identity/chat/v1` |

- **`in.server`** is the server key of the server whose lobby or room
  the line is said in (`hotline-ng-auth.md` §4.3), published in
  discovery as `server_key`. Names and hosts change and are not unique;
  that key is what already binds a login proof to a server. A client
  learns it from discovery and pins it by its `server_challenge`
  (§4.13) before it signs, and learns a linked server's from its
  users' rows (§5).
- **`in.room`** is 0 for the lobby, or a curated room's id
  (`chat-rooms.md` §2.2: permanent, never reused). A room's name can
  pass to another room after a rename; its id cannot. A private chat's
  id is never a line's scope.
- **Not signed:** the nick, which is the server's label, capped,
  mutable and decorated across links; anything the server assigns
  after the line is sent, such as its line id and `at`; and any
  `media`.

`id` is 16 random bytes, sent as the request's `guid` in 32 hex digits,
hyphenated as a UUID or not, which is all `hotline-ng.md` §7.1 asks of a
guid, and §7.3 takes for `chat`'s: its version and variant bits are not
checked, so it need not be a version-4 UUID, and the hex is read without
regard to case. Every reader sees it in the detached form, where the
`chat` event otherwise shows a guid to its sender alone (`hotline-ng.md`
§7.4), and that is harmless: a guid is remembered per sender, so knowing
another's lets nobody repeat or block their line.

A reader rejects an `in` that is not a map of exactly those two keys,
with those types, a `text` that is empty or longer than 4096 bytes, and
an `act` that is present and not `true`. A reply or quote, if public
chat gains one, will name its target by `(fingerprint, id)`, not by the
server's line id alone, so a signed reply cannot be re-pointed at
another line.

### 3.4 The article

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `id` | bstr(16) | yes | Random. The article's identity |
| `sent` | uint | yes | Unix seconds, when the author signed it |
| `in` | map | yes | `{ "server": bstr(32), "category": bstr(16) }`: the server key, as §3.3, and the category's node `guid` (`news.md` §3.1, "stable forever") |
| `parent` | map | no | The article it replies to: `{ "article": uint, "id"?: bstr(16), "by"?: bstr(32) }` |
| `cert` | bstr | yes | The author's device certificate, at most 512 bytes |
| `subject` | tstr | yes | Canonical, 1 to 255 bytes of UTF-8, no line break |
| `body` | tstr | yes | Canonical, at most 65 535 bytes of UTF-8 |
| `mime` | tstr | yes | `"text/plain"` or `"text/markdown"` |
| `sig` | bstr(64) | yes | Ed25519 by the author's `device` key, domain `hl-identity/news/v1` |

`parent.article` is the parent's article id on the server `in.server`
names; `parent.id` and `parent.by` are present together when the parent
is itself signed, and are its `id` and its author's fingerprint, so a
reply stays bound to what it answered even where an id does not; they
are absent when the parent is unsigned. A server checks them at ingest
(§4.11), and a reader shows a reply whose `parent` does not match the
article it is threaded under as signed for elsewhere (§3.5). The
category is named by its guid rather than its node id because the guid
is what the node keeps forever. `mime` is required here although
`news_post` has a default, so the signature never depends on a server's.
Attachments are not covered in v1. A reader rejects a `subject` or
`body` outside those bounds, a `mime` other than those two, an `in`
that is not a map of exactly `server` and `category` with those types,
and a `parent` with unknown keys, the wrong types, or only one of `id`
and `by`.

### 3.5 Checking a signed message

Every reader, a server on ingest (§4.11), a client (§8) and a
moderator's tool (§4.12), checks a signed message in this order:

1. the map: deterministic encoding, `v = 1`, the fields of its table,
   and for a detached form, reassembly as §3.1 says, or for a link form,
   told by `cert_sha256` in place of `cert`, as §5 says;
2. `cert`: a valid device certificate whose signature by its identity
   key verifies by §3.1's strict rule, allowing messages, at most 512
   bytes, and valid at `sent` and at the time the reader's server
   received the message (`at`); a sealed message is also checked
   against now (§3.9);
3. `sig`, strictly (§3.1), with `cert`'s `device` key, under the
   object's domain.

The signer is SHA-256 of `cert`'s identity key, never what a server
says. A message that fails any step is **invalid**. One that passes is
then checked against its scope: `to` against the identity the reader's
session proved, `in` against the server and the room or category it is
shown in. The server is this server's current key, or, at a reader, an
alias of it a followed handover keeps (`server-key-handover.md` §5.5),
or, for a lobby line of a linked server's user, that user's home
server's key, as the `chat` event's or the history line's
`from.remote.server_key` gives it (§5), so a live line still verifies
after its sender has left. A message that passes all three steps and
fails its scope is valid but **signed for elsewhere**, and shown as
such, never as said here (§8). A reader whose session proved no identity
has nothing to check `to` against, and shows such a message as
unverified (§8).

A certificate is **valid at** a time `t` exactly as hl-identity's
window check has it, with `S` as its skew: `expires` is after `issued`,
`issued ≤ t + S`, and `t ≤ expires + S`. So `expires` is inclusive, and
the skew applies at both ends.

A message that is not sealed is not checked against now: what was said
while a certificate was valid stays signed by it after the certificate
expires, and its history stays verifiable. §1.1 says what that costs
when a key is stolen.

### 3.6 Freshness of a message that is not sealed

A signed message that is not sealed is a statement with a signed time
and scope, which every server it crosses has seen. Replaying it makes
nobody say anything new, as long as the reader sees when and where it
was said, so its rules are lighter than a sealed message's (§3.10):

- **Time is shown, not enforced.** A client shows the signed `sent`
  beside the server's `at`, and marks a message whose `sent` and `at`
  differ by more than `S` as sent at its signed time. `at` is the right
  reference rather than now: a resumed session hears lines up to its
  grace old, and stored mail is days old, while `at` is when the server
  received it either way, so a server that lies about `at` makes its own
  lie visible against `sent`.
- **Duplicates.** `(signer, id)` is the message's identity. A client
  drops a second copy live (a retry, a link's echo), remembering what it
  showed for a recent window per scope, and shows a history line or an
  inbox row once whatever its server id. The memory need not be
  durable or shared between tabs: a duplicate public line is noise, not
  an action addressed to the user. A private message that is not
  sealed is held to the same rule, against the inbox rows and live
  messages the client holds: a server could show one again, and it
  would be shown with its signed time, which is what §1.1 concedes.
- **One id, one message.** A second message under a `(signer, id)`
  already seen, with other content (text, scope, options, parent), is an
  equivocation; one signed again that differs only in `sent`, `cert` and
  `sig` is the same message. A server refuses it (§4.11), and a client
  shows the first it saw and drops the other.
- **At the server.** A server refuses a signed message whose `sent` is
  more than `S` from its own clock (§4.11): it is its author's live
  message, so it is fresh or it is wrong. A client that signed a line
  and then held it, in a send queue while offline, signs it again
  before it sends, with the same `id`, so the retry is still the same
  line.

### 3.7 Padding

A sealed message's plaintext is the whole private message (§3.2)
followed by zero bytes, up to exactly the smallest of 512, 1024, 2048,
4096, 8192 or 17,103 bytes the map fits in. A map that fits in none is
too long and is not sent. A reader decodes exactly one CBOR item from
the start and requires every byte after it to be `0x00`. The padding is
outside the signature, and the AEAD protects it. The largest map, a
full message, a full quote, a 512-byte certificate and `auto`, encodes
to 17,068 bytes, inside the top size. A deniable box (§3.11) pads its
plaintext to the same sizes less 32 bytes, for the sender key it
carries in the clear, so both forms come in exactly the same sizes. A
reader rejects a padded plaintext whose length is not one of its
form's sizes.

### 3.8 Sealing

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

The leading byte is the format's version and form, `0x01` for this
signed box and `0x02` for a deniable one (§3.11), and the AEAD's
associated data too: a reader rejects any other. This `info` is the
encryption's domain, apart from the signature's (§3.1), and this
format's alone; any other use of a `device_enc` key (sealed push
payloads, for one) uses an `info` of its own, so a ciphertext made for
one can never open as the other. Every X25519 result, in either mode,
is checked as RFC 9180 requires: an all-zero shared secret is an error
(WebCrypto throws on it; x25519-dalek needs `was_contributory`).

AES-GCM rather than ChaCha20-Poly1305 because WebCrypto has the one and
not the other, and a browser client cannot take its non-extractable key
anywhere else. HPKE's key schedule needs HKDF's Extract and Expand as
separate steps, and WebCrypto's HKDF always runs both, so a browser
builds the two on HMAC-SHA256. Where RFC 9180 extracts with an empty
salt, a browser uses 32 bytes of `0x00`, which RFC 5869 makes the same
and WebCrypto's HMAC accepts. AES-GCM is not key-committing, which costs
nothing here: each ciphertext has one recipient key, and in a signed box
the signature inside covers its contents, while in a deniable box the
auth-mode key schedule binds `pkS` and `pkR`, for one recipient.
Franking, or one ciphertext for several recipients, would need a
commitment.

### 3.9 Opening

The recipient's client, for a box whose first byte is `0x01` (§3.11
says what differs for `0x02`):

1. checks the first byte is `0x01`, and opens the rest with its
   `device_enc` key, `aad` = `0x01`;
2. checks the padding (§3.7) and the fields (§3.2), parses the map,
   which must be in deterministic encoding, with `v = 1`, and checks
   `to` is its own identity fingerprint;
3. checks freshness (§3.10);
4. checks `(sender fingerprint, id)` is not one it has already accepted,
   the sender fingerprint being SHA-256 of `cert`'s identity key, never
   what the server says: the fingerprint read from `cert` as parsed,
   before step 5 checks it; a `cert` that does not parse goes on to fail
   step 5;
5. checks `cert` as §3.5 step 2 does, valid now as well, and that
   its identity key hashes to the **fingerprint the sender is shown
   with** (below);
6. verifies `sig` strictly (§3.1) with `cert`'s `device` key;
7. records `(sender fingerprint, id)` as accepted, in one atomic
   insert-if-absent, and shows it only if the insert added it; if it was
   already there, the message is dropped as at 4.

The fingerprint the sender is shown with is the event's
`from.fingerprint` (§4.4), and it holds only if the roster, when the
event arrives, shows the same fingerprint for `from.uid` or shows nobody
at that uid (a sender who has since left). A uid the roster shows with
another fingerprint makes the message fail step 5 as **invalid**, and
one it shows with none makes it **unverified**.

These map onto §8's states. A message that fails 1 or 2 is
**unopened**. One that fails 3 or 4 is dropped without being shown: a
replay is not a message. One that fails 5 or 6 is **invalid**, or
**unverified** for a uid with no fingerprint; either way it is shown
without its text, which the user can reveal only on purpose, never as
from that user, and its `id` is not recorded. Anyone who holds the
recipient's certificate can seal a message to it, so such text must
not read like a message.

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

### 3.10 Freshness and replay of a sealed message

Judged by the recipient's own clock, so no server can stretch it:

- `sent` must lie between `M − H` and `now + S`, `M` being the later of
  `now` and the latest time the client's own clock has shown (below),
  where `H` is how long a message can be held, **24 hours** in v1, and
  `S` the skew allowance (§3.1). A session's grace (five minutes by
  default) is far shorter; `H` leaves room for a server that sets a
  longer one, and bounds how long any server can sit on a message, and
  how far back a stolen key can date one.
- An accepted `(sender fingerprint, id)` is remembered until `sent + H +
  S`. The memory is stored with the device key, kept across restarts,
  and shared by every session using it (several tabs, or several
  processes of one client): checking and recording are one atomic step,
  and the record is written before the message is shown. A client keeps
  the latest time its own clock has shown, stored with the memory, and
  prunes by it, so a clock set back neither empties the memory nor
  reopens the window for what it pruned. A clock set forward and then
  corrected leaves the client refusing messages until it catches up,
  which is the safe side.

The time the recipient's home server received the message is still
passed along (`at`, §4.4), for display and as one of the certificate's
expiry checks, but freshness never rests on it, since that server is one
of the parties a sealed message keeps out. A client whose clock is off,
the sender's by more than `S` or the recipient's by more than `H`, drops
or has dropped what it should not. A client compares its clock with the
server's `at` and warns when they differ by more than `S`; it never sets
its clock from the server's, which would hand the server the check.

This machinery is a sealed message's because no server can vet one: it
is an action addressed to the recipient that only the recipient can
judge. It holds for both forms of box. A signed message that is not
sealed follows §3.6.

### 3.11 Sealing deniably: HPKE auth mode

A sender that wants a private message it can deny seals it with HPKE's
auth mode (RFC 9180 §5.1.3, `AuthEncap` and `AuthDecap`) in place of a
signature: the sender's static key is its own certified `device_enc`
key, the recipient's is the recipient device's, and the suite is
§3.8's. Only someone holding one of the two private keys can make such
a box, so the recipient knows the sender's device wrote it; and since
the recipient's key makes exactly the same boxes, the recipient can
prove nothing to anyone else. That is deniable against third parties
who trust neither the recipient nor the servers on the path; the
sending server knows which session submitted the box (§1.3).

**The plaintext** is §3.2's private message without `sig`, every other
rule of §3.2 kept: `v`, `id`, `sent`, `to`, `cert`, `text`, `quote?` and
`auto?`, a whole map, up to 8192 bytes of text. It is padded as §3.7
says for this form. A map that carries `sig` is rejected: a signature
inside a deniable box would undo it.

**The box:**

```
info   = "hl-identity/sealed-message/v1/hpke-auth"
aad    = 0x02
enc, ct = HPKE.SealAuth(pkR = recipient device_enc,
                        skS = sender device_enc private key,
                        info, aad, plaintext)
sealed = 0x02 || pkS (32 bytes) || enc (32 bytes) || ct
```

`pkS` is the sender's `device_enc` key, in the clear, because
`AuthDecap` needs it before anything is opened; the server already
knows it from the certificate the sending session proved. The leading
byte, the `aad`, the `info` and the HPKE mode all differ from a signed
box's, so neither form ever opens as the other.

**Opening** follows §3.9, but:

- at step 1, the first byte is `0x02`, and the rest opens with
  `AuthDecap` under the recipient's `device_enc` key and `pkS`, `aad` =
  `0x02`;
- at step 2, the map has no `sig`;
- at step 5, `cert`'s `device_enc` MUST also equal `pkS`, the key
  `AuthDecap` used: otherwise the box proves only that someone holding
  `pkS`'s private key wrote it, not that the certificate's identity did;
- step 6 is skipped: there is no signature to verify.

What fails 5 is invalid, or unverified, as §3.9 says. A box opened
with the wrong `pkS` does not open at all, and is unopened. Freshness
and replay are §3.10's, on the same memory. What passes is shown in
§8's **deniable** state.

**What it costs:**

- **Key-compromise impersonation.** Whoever steals a device's
  `device_enc` private key can write boxes to that device that open as
  from anyone whose certificate they hold, and the device cannot tell
  them from real ones. A signed box does not have this weakness.
- **`device_enc` signs, in effect.** The same thief can write deniable
  boxes as that device to anyone (§1.2), so the key needs the care a
  signing key does.
- **No verifiable report.** A moderator cannot check one, since the
  recipient could have written it; a report of it is pasted evidence
  without `signed`, accepted as unverified (§4.12).
- The sender's `device_enc` key in the clear, which the server knew
  already, and the leading byte, which says the sender chose to be
  deniable.

## 4. On a Hotline-ng server

These add to `hotline-ng.md`: the `signed` capability, the login
parameters `sealed` and `signs`, a request, parameters on `msg`, `chat`
and `news_post`, fields on events, listings and the `user` object, and
the error codes `not_sealed`, `cert_changed`, `bad_signature` and
`signature_required`, registered there when they are built.
`private-messages.md` §6.1 carries the sealed rows of its delivery rule
(§4.3). `hotline-ng.md` §8 gains the exception that signed text is
refused rather than cut (§4.7). `news.md` gains `signed` on `news_post`
and the article object, `guid` on the node object, node guids that are
never shared, and an index of signed articles by `(signer, id)` (§4.10);
`chat-rooms.md` the room's `signed` mark (§4.8); `moderation.md`
`signed` in the report object and on `report` (§4.12); `chat-history.md`
`server_key` in a ghost line's `from.remote` and an index of signed
lines by `(signer, id)` (§4.7, §5); and `server-link.md` and
`hotline-ng.md` `server_key` in a live `chat` event's `from.remote`
(§5). §4.1 to §4.5 are sealing; §4.6 onward, signing.

### 4.1 Saying a client can open them

A client that can open sealed messages sends `"sealed": true` in `login`
and in every `resume`, and only if its session proves a device key whose
certificate allows messages and is at most 512 bytes. Such a client
opens both forms of box, signed and deniable (§3.11). The login reply
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
logged in with. Only a session that is itself `sealed` may ask; any
other is refused `not_sealed`. Refused also `no_such_user`, `not_sealed`
(the target cannot open sealed messages, or its certificate does not
allow messages, has expired or is revoked), `blocked`, or
`not_delivered` (a linked server refused or did not answer). One code
for the asker and the target is intended: a client knows whether its own
session is `sealed`, so `not_sealed` only ever tells it something about
the target, and its `text` says which. It weighs 4 against the request
limit, as a search does, and is rate-limited on top, since it is what a
client would scrape to watch who logs in with which device (*hxd-ng:*
20 a minute per session).

A client checks the certificate exactly as §3.9 step 5 checks the
sender's, against the fingerprint the roster shows for `uid`, and seals
only to one that passes.

### 4.3 Sending

`msg` gains `sealed`, base64url of §3.8's or §3.11's bytes, in place of
`text`, and `cert`, base64url of the SHA-256 of the `device_enc` key it
was sealed to (the key, not the certificate, so a renewal with the same
keys changes nothing):

```
→ { "req": "msg", "params": { "to": 7, "sealed": "AQ…", "cert": "q2…" } }
← { "ok": { "queued": false } }
```

`sealed` without `cert`, or with `to_login`, `text`, `signed` or
`media`, is `bad_request`, and so is a size other than one of §3.7's
plus 49 bytes, either form; so is `guid`, since a sealed message is
never stored and nothing could be deduplicated by it. The sending session
must itself be `sealed`, and a deniable box's `pkS` MUST be the
`device_enc` key of the certificate the session proves, or the `msg` is
`bad_request`. The server checks what it can: that `cert` names the
`device_enc` key of the target session's current certificate, still
unexpired and not revoked, that the target can open sealed messages,
and every rule a `msg` already has (blocks, limits, refusals). A `cert`
that names another key is refused `cert_changed`: the client fetches the
certificate again and seals again, and never takes it as a reason to
fall back to cleartext. Anything else that fails is `not_sealed`, and a
user with no session is `no_such_user`. For a ghost, the check is the
target's home server's (§5).

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

### 4.5 What a server must never do with a sealed message

Decrypt (it has no key that could), log, or keep a sealed message past
its delivery; keep it in chat history or an inbox; or put a sealed
message's size in a log line. These keep what a server can learn to what
the wire shows.

### 4.6 The `signed` capability, and saying a client signs

A server that carries signed messages lists `"signed"` in the login
reply's `caps` (`hotline-ng.md` §4). It then accepts, checks (§4.11),
stores and serves the detached form on `chat`, `msg` and, with `news`,
`news_post`. It lists `signed` only when it publishes a `server_key` in
discovery, which is the scope every signed line and article names; only
when `[identity] hosts` names the hosts it answers as, since without
them it signs no `server_challenge` (`hotline-ng-auth.md` §6.2) and no
client can pin its key; and only beside `chat_guid` (`hotline-ng.md` §4,
§7.3), since a signed line's id is its guid: a server that lists
`signed` without `chat_guid` is broken, and a client does not sign lines
to it. A linked server lists it too: a signed lobby line crosses every
link with its signature (§4.11, §5). A client MUST NOT send
`signed` to a server
without the capability: a server that ignored an unknown parameter
would relay the text unsigned, and the sender would never know.

A client that can sign sends `signs` in `login` and in every `resume`,
and only if its session proves a device key whose certificate allows
messages and is at most 512 bytes: `"default"` when its user signs
public lines by default, `"able"` when it signs only where asked or
required. The roster row's `identity` gains `"signs": true` for
`"default"` alone; a resume that drops it loses it (`user_changed`). On
the roster it says what the client does by default, not that every
line will be signed, and the server sets it, so it is a hint to the
stripping check of §8 and nothing more. To the server, either value
says the session can sign, which a room that requires signing asks
(§4.8). Any other value is `bad_request`. The login reply echoes
`signs`, with the client's own string, when the server will carry
signed messages, as it echoes `sealed`.

A reader that does not log in with a key can still pin a server's key:
it asks `challenge` (`hotline-ng-auth.md` §6.2) for the
`server_challenge`, and verifies it, without going on to `auth`.

The `signed` parameter, on every request that takes one, is base64url
(no padding) of the detached form (§3.1). On every event and listing
that carries one, `signed` is the detached form exactly as it was
received, or for a linked line as §5 restores it, or its link form as
it arrived when the certificate could not be fetched (§5), which a
client tells by `cert_sha256` in place of `cert`; and the text beside
it is the canonical text it was checked against.

### 4.7 Signed chat

```
→ { "req": "chat", "params": { "text": "hi", "room": 2754100983,
      "guid": "7d4fa8e2…", "signed": "pmF2AWJpZFA…" } }
← { "ok": { "id": 98124 } }
```

- `guid` is required with `signed`, and the 16 bytes its hex digits
  spell are the line's `id` (§3.3); a signed request whose `guid`
  differs is refused `bad_signature`. A retry sends the same `guid`,
  and is the same line, answered as the original was, as
  `hotline-ng.md` §7.3 has it for `guid`, whether it carries the same
  `signed` or the line signed again (§3.6). One exception to §7.3's
  "whatever its text": a repeat whose text, style, room or other signed
  content differs is an equivocation, refused `bad_signature` rather
  than answered as the original.
- `text` is the canonical text, 1 to 4096 bytes: one that holds a CR, is
  empty, or is longer is `bad_request`, never cut. This is an exception
  to `hotline-ng.md` §8's rule that text over a limit is truncated, made
  there when this is built: cutting signed text would break its
  signature, and a client already SHOULD enforce the limit before
  sending.
- `style` is `"action"` exactly when the line's `act` is true; otherwise
  `bad_signature`.
- `room` absent or 0 is the lobby, and `in.room` is then 0.
- `media` is allowed, and is not covered by the signature (§8).

The `chat` event and every `history` line for a signed line gain
`signed`. A signed line is relayed and logged as any line is: the same
queue, the same flood count and spam points, the same commit
(`chat::ChatCommit`), the detached form stored with the line.

A guid is remembered per sender and per room (`hotline-ng.md` §7.3),
while a signed `id` is the signer's across every room. A server
offering `signed` therefore keeps an index of signed lines by
`(signer, id)`, for as long as it keeps the lines, and refuses a line
under a pair it holds in another room, or with other content, as an
equivocation; `chat-history.md` gains the index. Each room commits its
lines apart (`hotline-ng.md` §7.3), so two sends of one id into two
rooms at the same moment can both be logged before either is in the
index: the refusal holds as far as the server remembers (§4.11), and a
reader drops the second copy (§3.6).

### 4.8 Rooms that require signing

A curated room can require signed lines:

- **Marked** `signed = true` in its rooms-file entry, beside `secure`;
  `"signed": true` on the room object wherever it appears (the login
  reply's `rooms.list`, `rooms`, `room_added`, `room_changed`), present
  only when true, as `secure` is, and in `room_join`'s reply too, which
  carries no `secure`, so a client knows before it sends; and `signed?`
  on `room_create` and `--signed` on `hxd room create`, which a server
  without the `signed` capability refuses `bad_request`. The lobby's
  `[lobby]` entry refuses the key, as a file that does not parse, and so
  does a server with no store: a signed room needs one, for its log and
  its stored mark (below). A server without the capability, such as one
  whose identity is disabled and so publishes no `server_key`, treats a
  rooms file that marks a room as one that does not parse, which fails
  its startup (`chat-rooms.md` §4). That is intended: a room that
  requires signing on a server nobody can sign to is a room nobody can
  post in, and an operator should hear of it at once.
- **Fixed at creation.** The mark is set when the room is made and never
  changes. `room_edit` naming `signed` with a value other than the
  room's is `bad_request`. A server MUST keep each room's mark, signed
  or not, with the room's stored state, beside its log, and refuse a
  rooms file that disagrees with it, at startup and on reload alike, as
  a file that does not parse (`chat-rooms.md` §4): on a reload the rooms
  stay as they were and the server logs why, and at startup it does not
  start. A reload that adds `signed = true` to an existing room
  disagrees, and is refused. Only for a room whose stored state predates
  the mark does the server, at startup, scan the log: a room marked
  signed whose log holds an unsigned line that is not a tombstone fails
  startup the same way, with a reason naming the room, and one that
  passes has its mark recorded then, so later reloads compare against
  the stored mark. So the mark holds from a room's first line. A client
  that remembers a room's mark treats a change as it treats a changed
  server key (§8). Because the mark never changes, every unsigned line a
  signed room shows is one a signature was expected on (§8): the server
  did not accept it as unsigned, so it was stripped, or served by a
  server breaking §4.11.
- **Refused, not dropped.** In such a room a `chat` without `signed`,
  from a session the gates let post (`chat-rooms.md` §5), is answered
  `signature_required`, to the sender alone; nothing is logged, relayed
  or counted as a line. From a session the gates do not let post, it is
  `read_only`, as in any room it may only read.
- **`may_post` says whether the session can sign.** It is false, beside
  the gates' answer, for an ng session the server knows cannot sign:
  one that proved no device key (a plain guest's, for one), one whose
  certificate does not allow messages, or one that did not send
  `signs` (§4.6). Such a session reads the room and is told it may not
  post, as a classic one is told the room is read-only. A resume that
  changes this changes `may_post`, which `room_changed` already
  announces.
- **A topic is not a line.** Setting a signed room's topic needs the
  gates alone (`chat-rooms.md` §5), and carries no signature.
- **Only rooms.** The lobby cannot be marked: it is every period
  client's, and every link's. A private chat cannot be (§1.3).
- **Classic sessions read it as read-only.** A period or extended
  client, on any port or through `/trtp`, cannot sign a line (§6), so
  it is treated as a member that may read and not post, exactly as in a
  read-only room (`chat-rooms.md` §6.2, §6.3): its join notice says
  `read-only`, `/rooms` adds `(signed lines only)` after the room's
  count, following `(encrypted connections only)` when the room is
  secure too, and its first 105 there is answered with a notice in the
  room and its lines are dropped. The notice follows the same
  precedence as the ng answer: `*** this room takes signed lines only,
  which this client cannot send` to a session the gates let post, and
  the read-only room's own notice to one they do not. Access stays
  decided per account, never per wire (`chat-rooms.md` §5): the mark is
  about what a line must carry, not who may read, so a classic user who
  passes the gates still joins and reads, and closing the room to
  classic joins would hide a conversation they are entitled to.
- **Links** carry no room (`chat-rooms.md` §8.1), so the mark has
  nothing to cross yet. When rooms cross, a room's mark is its host's.

`chat-rooms.md` gains the rooms-file key, the lobby's refusal of it and
a storeless server's, the stored mark and the startup and reload rules
that keep it fixed, the room object's field, the `room_create` and
`room_join` fields, `hxd room create --signed` (and no way to change it
with `edit`), `room_edit`'s refusal, `may_post`'s added condition, the
error on `chat` and its precedence, the classic notices and the `/rooms`
marker when this is built.

### 4.9 Signed private messages

`msg` gains `signed` beside `text`, for a message that is signed and not
sealed. A sealed message is signed or deniable by its box (§3.8,
§3.11), and an unsealed one signed or not by this parameter, so a
user's choice for private messages is one of signed and sealed,
sealed deniably, signed in the clear, or neither (§8):

```
→ { "req": "msg", "params": { "to": 7, "text": "hi",
      "guid": "0b9c41d3-…", "signed": "pmF2AWJpZFA…" } }
← { "ok": { "queued": false } }
```

- `guid` is required, and equal to the message's `id`, as §4.7.
- `text` is canonical and 1 to 4096 bytes, as §4.7; `quote` is absent
  from the map.
- `to` in the map is the recipient's identity fingerprint: the identity
  the recipient's account is linked to (`hotline-ng-identity.md` §8),
  whether `to` names a session of it or `to_login` the account, or for
  a session with no account of its own, the identity it proved. A
  recipient with none
  is `bad_request`; one with another is `bad_signature`. For a ghost,
  the recipient's fingerprint is what its row shows, and its home
  server checks (§5).
- With `sealed` it is `bad_request`; with `media`, the media is not
  covered.

A signed message is stored and delivered as any `msg` is, the detached
form kept with its inbox row and deduplicated by `guid` as
`hotline-ng.md` §7.1 has it. The `msg` event and every `inbox` row for
it gain `signed`, so a stored message verifies when it is read days
later (§3.6). An `inbox` row's `from` has no uid or fingerprint, so a
signed row is named by its certificate, as a history line is (§8).

### 4.10 Signed articles

With `news` and `signed`, `news_post` gains `signed`, the detached form
without `subject` and `body` (`news.md` §9.2):

- `subject` and `body` are canonical and within §3.4's bounds and the
  server's `max_subject` and `max_body`; over them is `bad_request`,
  never cut. So is a subject a server would change as it keeps it:
  *hxd-ng* makes a subject one line, trimmed, with a tab as a space
  (`news.md` §9.2), so a signed subject with a tab, or a space at
  either end, is `bad_request`. `mime` MUST be sent and equal the
  map's. `parent`, when sent, is the map's `parent.article`, and the
  map has no `parent` without it.
- `in.category` is the guid of the category posted into. On a server
  with `signed`, a `node` object gains `guid`, base64url of its 16
  bytes, so a client can name it. Such a server MUST never give two
  nodes one guid, an importer's included, or a signed article could be
  shown in a category it was not posted to. `news.md` does not enforce
  that today, and gains it with this.
- `attach` is allowed, and attachments are not covered.
- A retry under the same `(signer, id)` with the same content (§3.6),
  signed again or not, is the same post, answered with the article's
  id; with other content it is refused `bad_signature`. The server
  recognizes it by an index of signed articles by `(signer, id)`, which
  `news.md` gains with the node guid's uniqueness. *hxd-ng* keeps nothing
  of what a deleted article said, so the index does not reach it, as it
  does not reach a redacted line (§4.12).
- An article is never edited (`news.md` §18), so nothing but its
  deletion changes a signed one, and a feed's article, which a feed
  rewrites, is never signed.

An `article` object gains `signed` wherever it is served, in
`news_article`, `news_thread` and `news_threads`; a search hit does not.
A deleted article loses `signed` with its body. A feed's article
(`news-feeds.md`) is never signed. A classic reader is served the
article as now: the plain downgrade and the subject cut at the legacy
edge (`news.md` §12.1) are classic egress and never touch the stored
copy.

### 4.11 What a server must do with a signed message, and never do

A server MUST check every signed request on ingest, by §3.5 with its own
clock as now, and with:

- `cert`'s identity key hashing to the identity fingerprint the session
  proved, and `cert`'s `device` being the device key the session proves
  now, after any resume;
- `sent` within `S` of its own clock;
- for `chat` and `msg`, `id` equal to the request's `guid`
  (`news_post` has none);
- the scope: `in.server` its own `server_key`, `in.room` the room the
  line is sent to, `in.category` the category posted into, `to` the
  recipient's fingerprint (§4.9);
- an article's `parent`: `parent.article` the article it replies to,
  and `parent.id` and `parent.by` that article's signed `id` and its
  signer's fingerprint when it is signed, and absent when it is not;
- no other message by the same signer under the same `id` with other
  content (§3.6), as far as the server remembers.

Anything that fails is refused `bad_signature`, with a `text` naming the
check, and nothing is relayed or stored. A `sent` outside the window
has a `text` of its own, `signed too long ago; sign it again`, so a
client that held a line knows to sign it again (§3.6). That keeps an
invalid signature in a client's view a sign of tampering, not of a
client's bug.

A server MUST store the detached form with the line, the inbox row and
the article; serve it unchanged with the text it was checked against, on
every event, `history` page, `inbox` listing and article; and carry it
across links in its link form (§5).

A server MUST NOT alter signed text, by truncation, rewriting or a
change of line ending in what it stores and serves on the ng wire;
attach a detached form to any text but the one it came with; deliver,
relay or serve a signed line, message or article on the ng wire or
over a link without its signature while keeping its text (a redaction
removes both, §4.12); or sign on a user's behalf. The classic wire and
a push notification's body carry text with no field for a signature,
and get the text alone.

### 4.12 Moderation

- **Redaction** (`moderation.md` §3.1) moves the detached form with the
  body and nick into the audit row's `evidence`, and the sweeper scrubs
  it with them. *hxd-ng* keeps nothing of what a redacted line said, so
  the index of signed lines (§4.7) does not reach it: its guid still
  answers a line sent again under its id in its room as that line. A
  tombstone carries no signature. A tombstone that still
  verified would need the signature to cover a commitment to the text
  rather than the text, and would keep a proof that a removed line was
  said, which is a cost to its author's deniability that no reader
  needs.
- **An article deleted as a moderation act** (`moderation.md` §3.1,
  `news.md` §11) moves its detached form into the audit row beside the
  subject and body its `evidence` keeps, as a redaction does, and the
  sweeper scrubs it with them.
- **Purge** (`moderation.md` §3.3) selects on the stored fingerprint,
  which for a signed line is its certificate's (§4.11 made it the
  session's).
- **A report of a public line, an inbox message or an article** carries
  the detached form from the stored row: the `report` object's `target`
  gains `text` and `signed` for a line, and for a ghost's line
  `from.remote.server_key` as well, as the history line carries it (§5);
  a message's copied `evidence` gains `signed` beside it; and an
  article, reported by id as now, is checked from its stored row, which
  carries `signed`. A moderator's tool verifies it by §3.5, its scope
  against the server's own key, or for a ghost's line the home key the
  target carries, so a moderator judges what the sender signed rather
  than what the server kept. A ghost's line stored before its
  certificate was fetched carries its link form, which the tool cannot
  verify until the certificate is.
- **Pasted evidence**, for lines and private messages only. `report`
  gains `signed?` beside `evidence`: the detached form of what
  `evidence` pastes, or a whole private message (§3.1), such as a sealed
  one the reporter opened, with `evidence` then absent and taken from
  its `text`. The server checks it by §3.5 with one difference: there is
  no `at` of its own, so the certificate is checked at `sent` alone. Its
  scope is checked by its kind: a line's `in.server` against the
  server's own key, or against the current key of one of its linked
  peers, as their server groups gave it (§5), or against any home key
  stored beside a ghost's line in its history; and a private message's
  `to` against the reporter's identity fingerprint. A line signed under
  a key the server does not know is refused. The linked peers' keys are
  accepted because a ghost's line is one a reporter here was shown, and
  the key it names is one this server already vouched for when it showed
  it; a key it never knew is one it cannot vouch for. The report's
  target is the identity of the certificate: a `user` target, when one
  is named, must be that identity, and when none is, the server names
  it. A pasted ghost's line names no `user`, since its sender has no
  account or session here to name, and the server names the
  certificate's identity. Anything else is refused `bad_signature`. The
  report stays `verified: false`, which says the server holds no row of
  it, and carries `signed`, which the moderator's tool checks for
  itself. This is what a sealed message's report was waiting for, at the
  price of the sender's deniability (§1.3).
- **A deniable box** (§3.11) has no signature to carry. Its report is
  pasted evidence without `signed`, accepted as unverified like any
  other, and a client reporting one says that the moderator cannot
  check it. The plaintext of a deniable box is never accepted as
  `signed`: it has no `sig`, which §3.5 counts as invalid, so it is
  refused `bad_signature`, the code every failed check of a signed
  message gets.
- The moderator's tool and the client verify by the same rule (§3.1,
  §3.5).

`moderation.md` gains `signed` on `report` and in the report object;
pasted `evidence` for a public line, which is new to it, since today
only a private message with no row is pasted; and one relaxation of
its rule that a report names exactly one target: pasted evidence with
`signed` may name none, and the server then names the certificate's
identity.

### 4.13 When the server key changes

A client pins a host's `server_key` only once the key's
`server_challenge` (`hotline-ng-auth.md` §6.2) verifies for the host,
never on discovery's word alone (§8). That proves the key is the host's
because a server signs one only for the names in `[identity] hosts`
(§1.1). At first contact over plain HTTP the pin is trust on first use,
since a network attacker can then answer with a challenge it signed with
a key of its own. A client signs nothing to a host whose key it could
not pin, one that sends no `server_challenge`. Scope checks use the
current key alone at the server on ingest; at a reader, the current key
or an alias a followed handover keeps
([server-key-handover.md](server-key-handover.md) §5.5).

A changed server key warns as any changed pin does, and makes what was
signed under the old key "signed for elsewhere"; while that warning is
unanswered the client signs nothing to that host, and a client that
signed under the old key is refused `bad_signature` and signs again. A
signed, pre-committed handover that carries the old key forward as an
alias is specified separately, in
[server-key-handover.md](server-key-handover.md).

## 5. Across server links

As the server linking user keys draft has it: a certificate crosses as
Link Device Keys (915), and a sealed message as `DATA_LINK_SEALED` in
Link Private Message (905), with the placeholder in `FieldData` and the
quote only inside, a deniable box (§3.11) in the same field, unchanged.
The sender's fingerprint is the one in the sending
ghost's user group. A home server delivering a sealed 905 to an ng
session passes the time it received it as `at`. The sending server puts
`msg`'s `cert` in the 905 as `DATA_LINK_SEALED_TO`, and the target's home
server checks it as §4.3 does, refusing `NoDeviceKeys` for a target
that cannot open sealed messages or whose current `device_enc` key is
another; the sending server answers its client `cert_changed` or
`not_sealed` to match. The check is needed because a ghost's ID
promises no device: a link quarantines an old ID only for minutes, and
a server hearing from a peer that restarted may re-use a ghost for any
incoming user with the same home server, name and icon, who may be
someone else on another device, so a 905 can reach whoever the ID
stands for now, and nothing carries a session's `sealed` across a link
but the answer to 915.

The draft, as published in fogWraith's Hotline repository
([`Docs/Protocol/Server-Link-User-Keys.md`](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Server-Link-User-Keys.md)),
binds the recipient's identity fingerprint, allows a signed box or a
deniable one (§3.11) under this document's domains, judges freshness by
the recipient's clock and checks the sender's certificate as §3.9 does.
It carries signed messages as this section does, and differs from this
document in nothing that matters. The extension
(`Capabilities-Server-Link.md`) reserves the field numbers below for
that draft, which it has not adopted yet.

Signed messages cross the link wire this way:

- **A lobby line's signature** rides Link Chat (904) as one optional
  field, `DATA_LINK_SIGNED` (`0x0647`), holding the link form below, at
  most 256 bytes. A signed lobby line's link form is 201 bytes, and 206
  for an action, so with its header it takes about a fifth of the 1024
  bytes the extension's fields beside a 904's baseline share
  (`Capabilities-Server-Link.md`, Relaying Fields), and leaves room for
  other extensions. Relaying Fields passes it on unchanged through
  servers that know nothing of it, and drops a transaction whole rather
  than trim it. A relay that builds a fresh 904 can still leave it out;
  §8's stripping check is the defense.
- **A signed private message** rides 905 the same way, beside its text,
  for a message signed and not sealed: 187 bytes, and 193 for an
  automatic response. A sealed message carries its signature, or its
  deniable proof, inside `DATA_LINK_SEALED`, never beside it.
- **The home server's discovery key**, `DATA_LINK_DISCOVERY_KEY`
  (`0x0648`), in its server group (900, 912, 913), relayed like the
  group's other fields, so a reader can check a ghost's line's
  `in.server`. It is the `server_key` of discovery, not the link key,
  which is a different key unless the operator made them one
  (`server-link.md` §8). The ng `user` object's `remote` gains
  `server_key`, base64url, for a ghost whose home server sent one, and
  so does the `remote` a ghost's `chat` event carries in `from`
  (`server-link.md` §5), so a line can be checked after the ghost has
  left the roster.

**The link form** is the detached form (§3.1) without `cert`, carrying
in its place `cert_sha256`, a bstr(32): the SHA-256 of the certificate.
The signature still covers `cert` exactly as §3.1 defines, so the link
changes only what is sent, never what is signed, and a line signed once
for local readers crosses a link unchanged. A verifier fetches the
certificate, checks that its SHA-256 equals `cert_sha256`, removes
`cert_sha256`, restores `cert` and the canonical text under their keys,
and verifies `sig` over the deterministic encoding without `sig`, as
§3.1 says. A fetched certificate whose SHA-256 differs is treated as
one that could not be fetched, since a device change looks the same,
so a relay that rewrites the hash, or serves another certificate under
the same identity, makes the line unverifiable, as stripping would,
and can never make it verify. A link form that carries `cert`, or lacks
`cert_sha256`, is rejected, and a signed message whose own map carries
`cert_sha256` cannot take the link form; hxd-ng refuses one on ingest,
`bad_signature` (§3.1), since it could neither carry it across a link
signed nor strip its signature.

**The certificate is fetched** through Link Device Keys (915), in the
server's own name: a 915 without `DATA_LINK_USER_ID`. A receiving hxd-ng
server keeps certificates by hash, so one fetch serves every line the
device signs, and never holds a link's lines for a fetch: the order of a
path and a room's commit order stay as they are. A line whose certificate
is cached is checked and served in full, `cert` restored, to its own
clients, in history and to moderators (§4.12), so they verify on their own
and the line still verifies after its sender has left. One whose
certificate is not cached yet is relayed at once in its link form, as it
arrived, which names its certificate only by hash and which a client shows
as **unverified** (§8); the server fetches the certificate in the
background, and once it has it, history holds and serves the full form, so
a later page or a moderator verifies the line. A line whose certificate
cannot be fetched, because its home server no longer answers for that
session (the sender has left, or moved to another device) or never
exported the sender's fingerprint, stays unverified. As a home server,
hxd-ng answers a server's own 915 only for a session it has seen sign: one
that signed a lobby line, or, for one that signed only private messages,
over the links those went out on. It answers it without step 5's condition
that the session's client can open sealed messages, so a client that signs
without `sealed` can still be verified across a link, and holds it to the
per-link rate limit, since it has no ghost behind it. A server's own
request is indistinguishable from a user's that a relay has stripped of
`DATA_LINK_USER_ID`, so the requester's checks of a user's 915 (a current
ghost, exclusions, refused private messages) are no guarantee against a
server on the path; having seen the session sign is what bounds it. Janus
up to 2.0.28 answers `UnknownUser` to a 915 without `DATA_LINK_USER_ID`,
so a Janus relay of those versions on the path blocks servers' own
fetches, and the lines behind it stay unverified; Janus 2.0.29, in
development, is to relay them.

The text survives the crossing: 904 carries the raw text the user typed,
never the formatted line, as UTF-8 with CR line endings. A receiving
server canonicalizes a signed 904's or 905's text (§3.1), CR to LF,
before it stores, shows or serves it; canonical text holds no CR, so
that gives back exactly what was signed. `server-link.md` §4.4's cut at
8192 bytes applies only to a classic line in Mac Roman; a signed line
is at most 4096, and one that does not fit a link's bounds is dropped,
never cut.

A linked lobby line's scope is its home server's key and room 0. The draft
makes a receiving server's check a MAY; hxd-ng, which MUST check what its
own clients send (§4.11), checks every signed 904, and a 905 as the
target's home server, once it holds the certificate, as a client would: by
§3.5 with that scope (for a 905, `to` its user's identity fingerprint) and
no session to compare, and the signer against the fingerprint in the
sender's user group. It does not show one that fails, and answers a 905
that fails `BadSignature` (reason 14, reserved for the user keys draft); it
relays a 904 onward unchanged regardless, as the extension requires, and
never shows or relays one with the signature removed. It stores the signed
form with the ghost's line in history (`server-link.md` §4.3), with its
home server's `server_key` beside it, and a `history` line of a ghost
carries that key as `from.remote.server_key`: history's `from` already
carries the ghost's `remote` (`server-link.md` §5), and `chat-history.md`
gains the key in it. Without the key every stored linked line would read
as signed for elsewhere. So a server's history of a linked lobby verifies
line by line. A ghost's row carries `identity.fingerprint` when its home
server said one (`DATA_LINK_USER_KEY`) over a link trying the draft, and a
client checks a line's certificate against it; without one, its line is
named by its certificate's fingerprint and the contact pinned to it, if
any. A ghost whose row has no `server_key` cannot have its lines' scope
checked: they are shown as unverified (§8), which is not the same as
failing, and a receiving server neither drops them nor counts them
invalid.

*hxd-ng* tries the draft only with a peer whose `[[link.peer]]` entry
lists `user_keys` in `drafts`, as that peer's operator agreed
(`server-link.md` §7.7, the extension's "Trying out a draft"). With
such a peer it says its discovery key and its users' fingerprints,
sends signed and sealed messages, and offers Link Device Keys (link
feature bit 4); it reads the fingerprints and discovery keys only from
such a peer, and a signature or a sealed message from any. A signed
lobby line goes to every peer with `DATA_LINK_SIGNED`, one that does not
try the draft included, since it may not cross without its signature
(§4.11) and a peer passes a field it does not know on as it came, which
is how a relay already carries one; a line relayed between two links
goes on whole the same way. Toward a peer that does not try the draft,
a signed message to a user behind it is refused `bad_request` (that
peer says no fingerprint to sign it to), a sealed one `not_sealed`, and
a `device_cert` `not_delivered`. It says a fingerprint only while
`[identity] login_proof_v1` is off: it does not record which proof a
session logged in with, and the draft exports only a key proved with
one naming this server's host. A scope that does not match is a failure
here, not "signed for elsewhere": a line from a linked server scoped to
any other is a replay, and a link form's room, style and home key are
checked before its certificate is held. A line or message from a ghost
whose home server said no fingerprint stays unverified even when its
certificate is held, since certificates are kept by hash and one held
may be another user's, and none is fetched for it. A line logged before its certificate came that
fails once it does stays in history in its link form, unverified. A
sealed message from a ghost whose home server said no fingerprint is
refused `NoDeviceKeys`, since its recipient could not check who sealed
it. A ghost's sealed `msg` event carries the fingerprint its home server
said as `from.fingerprint`.

Rooms do not cross links yet (`chat-rooms.md` §8.1); when they do, a
room's scope is its host's key and the host's room id.

## 6. On the classic wire

The messaging identity draft proposes signed and sealed messages for
fogWraith's Instant Messaging extension
([`Docs/Protocol/Capabilities-Messaging-Identity.md`](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Messaging-Identity.md)),
for messages between friends on one server whose accounts are linked to
identities, under capability bit 13 (`CAPABILITY_IDENTITY`), which
`Capabilities.md` and `Capabilities-Messaging.md` reserve for it with
its fields and reason codes, the draft not yet adopted. IM Send (810)
and IM Deliver (811) carry a signed message as `DATA_MESSAGE_SIGNED`
beside the body: §3.2's detached form with the certificate inside, at most
1020 bytes (§3.1), unlike a link's, since a message read from the offline
queue must verify after its sender has left. A signed message is delivered
only to sessions that negotiated `CAPABILITY_TEXT_ENCODING`, and others
get the body alone; one that fails a server's check is refused
`BadSignature` (reason 16). They carry a sealed message as
`DATA_MESSAGE_SEALED`, §3.8's or §3.11's bytes, with
`DATA_MESSAGE_SEALED_TO` naming the `device_enc` key as `msg`'s `cert`
does (§4.3). As here, a sealed message goes only to a live session that
can open it and is never queued. A sender learns the recipient's devices
from Get User Info (825), which lists a `DATA_FRIEND_DEVICE_CERT` for each
live sealed-capable device, to friends alone, and none while the recipient
is `Invisible`. The draft makes a server's check of a signed message a
MAY; hxd-ng checks it on ingest as §4.11 does. Friends on linked servers,
and sealed mail for an offline device (§10), are left to the draft's later
versions. GtkHx is the client expected to do it.

Outside bit 13, classic chat and private messages carry no signature.
Chat (105, 106) and private messages (108, 104) have no field for one:
a classic reader gets a signed line, message or article as text, as
now, with nothing to say it was signed, and a classic sender's lines
are never signed. The user keys draft notes the same of a ghost's
chat, as 106, and a ghost's private message, as 104; a sealed one from
a ghost arrives as the placeholder. A binding for chat needs the raw UTF-8 text beside the
signature, as fields of 106 and of a 700 entry, because the line a
classic client is sent is formatted by the server (`\r%13.13s:  %s`)
and cannot be turned back into what was signed; and the same pair on
105, for sending. It is not in v1. A room that requires signing is
read-only to a classic client (§4.8).

## 7. Limits

- A sealed or signed message counts against every limit a message or a
  line does: the sender's spam points, the ng request bucket, the
  recipient's blocks, the room's flood count.
- A signed request costs the server two verifications, the certificate's
  and the message's, and MAY weigh more against the request limit for
  it (hxd-ng: one more).
- A detached form is at most 1020 bytes (§3.1), and its link form 256
  (§5); signed text is refused over its limit, never cut (§4.7).
- `device_cert` is rate-limited per session (§4.2).

## 8. What a client should do

- **Remember contacts by fingerprint**, with the name and server they were
  seen under, and warn when a remembered contact appears without one or
  with a different one.
- **Never fall back silently.** If sealing is impossible to someone it has
  sealed to before, send in the clear only after the user confirms; show
  for every message, sent and received, whether it was sealed.
- **Let the user choose signing per scope**, the lobby, each room, news
  and private messages, and keep the choice; never sign in a private
  chat. For private messages the choice is, when sealed, signed and
  attributable or deniable (§3.11), and in the clear, signed or not. A
  client SHOULD default to signing articles and to sealing a private
  message wherever it can, signed and sealed rather than deniable, and
  SHOULD leave the lobby and rooms unsigned by default, for §1.3's
  reason, except a room that requires it, where it says so before the
  user sends. Once on in a scope, it signs every line there, so that an
  unsigned one stands out.
- **Pin each server's key.** A client remembers the `server_key` a host
  proved to it the first time, by its `server_challenge` (§4.13), and
  warns when the host later gives another. Every line it signs there
  names that key, and a change is a rotation, a lost key, a stolen one,
  or a server showing someone else's (§1.1). What it signs to a host it
  could not pin is §4.13's.
- **Show every line, message and article in exactly one of these
  states**, and never as verifiably from its sender unless it is the
  first or the sixth; an unsigned one is shown by its nick, as today:
  1. **Verified**: valid by §3.5, its scope this server (its key or an
     alias, §3.5) and this room, category, parent or recipient, and its
     signer the fingerprint the server names for the sender: the
     roster's for a live line or message from a local uid, the article's
     `from.fingerprint`, and for a ghost before user keys cross, the
     certificate's own. A history line or an inbox row, neither of which
     names a uid or a fingerprint, is its certificate's. Named by the
     pinned contact, or the fingerprint, with the signed time shown, and
     for a ghost's line with its home server too, whose key this server
     vouched for (§1.1).
  2. **Signed for elsewhere**: valid, its scope another room, server,
     category, parent or recipient. Shown with where it was signed,
     never as said here.
  3. **Unverified**: valid, or for a link form uncheckable, but nothing to
     check it against: a live line or message from a local uid whose row
     has no `identity`, an article with no `from.fingerprint`, a ghost's
     line whose row has no `server_key` (§5), or a history line whose
     `from.remote` has no `server_key`, a linked line or message served in
     its link form because its certificate was not fetched (§5), or a
     private message read by a session that proved no identity to check
     `to` against (§3.5). Shown as signed by its fingerprint, or for a
     link form, which names none, by a key that could not be checked, and
     not as from the nick beside it.
  4. **Invalid**: a signature that fails §3.5, or names a signer other
     than the one the server names (a roster row's or an article's
     other fingerprint). Marked so that the mark outweighs the nick;
     the text may be shown, since the server could have sent it
     unsigned, but never as from that user.
  5. **Unsigned**: no signature. Shown as lines are today.
  6. **Deniable**: a deniable box (§3.11) that opened and passed every
     check of §3.9 that applies. Shown as from the sender, as a verified
     message is, and marked as one its recipient could not prove to
     anyone, which is also why a report of it cannot be checked.
  7. **Unopened**: a sealed box that failed §3.9's steps 1 or 2. Shown
     as a message that could not be opened.

  A sealed message that is invalid or unverified (§3.9) has its text
  hidden until the user reveals it on purpose.

  Marks go on top of a state: **sent at another time**, on 1, 2 or 6,
  when `sent` is more than `S` from `at`, with the signed time shown;
  and **signature expected**, on 5, when it comes from a fingerprint
  the client has seen sign in this scope, or whose row says `signs`,
  with a warning that a signature may have been removed, and on every
  unsigned line in a room that requires signing (§4.8); a client
  remembers a room's mark as it remembers a server key. An attachment on a
  signed line or article is shown as not covered.
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
A deniable box (§3.11) is the same sizes: its 32-byte `pkS` comes out of
the padded plaintext's.

A detached public line with no unknown keys, a four-byte room id and
`act` encodes to 684 bytes with a 512-byte certificate, and to 405 with
a certificate that leaves out `name`, which encodes to 234. The bound is
1020 (§3.1), 1360 characters of base64url beside the text. On a link
the form carries the certificate's hash instead (§5): 201 bytes for a
lobby line, 206 for an action, 187 for a private message and 193 for an
automatic response, inside the link's bound of 256.

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
- **Deniability after the fact.** A device certifies a short-lived chat
  key, a day's, signs lines with it, and publishes its private key once
  it expires, as OTR publishes old MAC keys. Live readers get
  authenticity; afterwards anyone could have signed the line, so a
  leaked log proves nothing. It is the only route to lines that are
  signed and still deniable, and so to signing public chat by default; a
  private message already has a deniable form (§3.11), which needs a
  single recipient. It needs a certificate type, somewhere to publish
  expired keys, and clients that stop trusting a signature by a key once
  it is published.
- **Attachments**: an image's handle sealed with the text, and its bytes
  encrypted under a key carried inside; and for a signed line or
  article, the canonical image's SHA-256 under a `media` key, which the
  upload's reply would have to return, since the server re-encodes. An
  unknown key is covered and ignored, so it is a compatible addition.
- **A signing policy in the card.** A user card (`hotline-ng-identity.md`
  §3.4) that says its identity signs every public line would let a
  client tell a stripped signature from none for anyone whose card it
  holds, at the price of making signing a commitment of the identity
  rather than a choice per line.
- **Signed chat on the classic wire** (§6).
- **Private chat**, which needs a group construction this one is not,
  and an answer to §1.3 before it is signed.

## 12. Open questions

- Should `device_cert` also answer for a user who is offline, from the
  devices that have logged in before? That is the first step of §10, and
  it reveals which devices a user has.
- Should the roster show `identity.sealed` and `identity.signs` to
  everyone, or only to sessions that are `sealed` or sign themselves,
  since they reveal which client someone uses?
- Should an importer (`news.md` §12.6) carry a signed article's signature
  to another server? Its scope names the server it was posted on, so it
  would be shown as signed for elsewhere, which is true, and keeps it
  attributable after the move.
- **Should lines bind the host too?** The login proof binds the host the
  client connected to (`hotline-ng-auth.md` §6.2). Should a signed
  line's or article's scope also name the host, as WebAuthn binds the
  origin, or is the server key, pinned per host (§8), enough?

## 13. Test vectors

In `identity-test-vectors.json`, in its shape (`domain`, `fields`,
`unsigned_hex`, `signature_input_hex`, `signature_hex` and `signed_hex`
per object, signed by the file's device key under a new certificate
from its identity key with `caps` 3 and no `name`, the file's
`device_cert` having the `name` "browser", and `message_rejects`
entries naming the error each must fail with), and for sealing a
`sealed` entry naming the recipient's device and what its reader knows,
the ikm each box's ephemeral key is derived from, and `sealed_rejects`
naming the state of §8 each opens in and its error. They are:

- a public line in the lobby, in a room, and as an action, each also as
  its detached form, and the lobby line and the action as their link
  form (§5), with the reassembled bytes equal to `unsigned_hex`;
- canonical text: CR LF, a lone CR, the two mixed, a trailing CR, a TAB
  kept, and text in NFD left as it is;
- the certificate window (§3.5), with `S` of 600 seconds: `issued` at
  `sent + S` accepted and at `sent + S + 1` rejected, `sent` at
  `expires + S` accepted and at `expires + S + 1` rejected, and
  `expires` equal to `issued` rejected;
- a mixed-order `A` whose signature satisfies the cofactorless equation,
  accepted, and one whose signature satisfies only the cofactored
  equation, rejected;
- a private message signed only, with its link form (§5) as a message
  and as an automatic response, and the same map as the plaintext of a
  sealed message, with its keys, ephemeral key, padding and bytes, so
  the two are seen to share their signature;
- a deniable box (§3.11): the sender's and recipient's `device_enc`
  keys, the ephemeral key, the plaintext without `sig`, its padding and
  the bytes; and the same box opened under base mode and the base
  `info`, which fails;
- an article, with a signed parent and an unsigned one;
- rejects: each object under another's domain, a line and an article
  with `to`, a private message with `in`, an `in` with an unknown key, a
  detached form holding its text, one over 1020 bytes, a link form
  carrying `cert`, one lacking `cert_sha256`, one whose certificate
  hashes to another `cert_sha256`, one over 256 bytes, a whole or
  detached map carrying `cert_sha256`, a detached
  private message with `quote`, empty and overlong text, text with
  U+0000 or another C0 control, an `act` or `auto` of `false`, a
  `parent` with `id` and no `by`, a non-deterministic encoding, a
  certificate without bit 1, a small-order `A`, a non-canonical encoding
  of an `A` that is not of small order, a small-order `R`, a padded
  plaintext whose length is not one of its form's sizes, one with a
  nonzero padding byte, a deniable box whose certificate's `device_enc`
  differs from the `pkS` `AuthDecap` used, a deniable box with another
  `pkS` swapped in, which fails to open, a deniable box whose `to` is
  not the recipient's, a deniable box's plaintext carrying `sig`, and
  a box with `0x02` sealed in base mode.

RFC 9180 prints no vector for the HPKE suite; the CFRG's
`test-vectors.json` for HPKE has them, and an implementation should
pass every one it has for this suite, in base and auth mode, first.
hl-identity checks its HPKE against them, kept for this suite in
`crates/hl-identity/tests/rfc9180-vectors.json`.
