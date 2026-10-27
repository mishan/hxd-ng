# Server key handover

Status: draft, 2026-10. Built in hl-identity (`handover`): the
handover object (§3), the challenge's `next` (§2), and a client's
checks (§5) as functions over what it remembers, with vectors (§10).
Not built: a server serving `next` and `server_handovers`, and the
tooling to make a successor and sign a handover (§6). A companion to
`e2e-messages.md`, whose §4.13 leaves rotating the server key to this
document. It rests on `hotline-ng-auth.md` §4.3 (the server key), §5
(discovery) and §6.2 (the `server_challenge` and `[identity] hosts`),
and asks additions of all three, listed in §8.

A signed line or article names its server by the server key
(`e2e-messages.md` §3.3), and a client pins that key per host on the
`server_challenge` the server signs for it (`e2e-messages.md` §4.13). A
server that replaces its key therefore warns every client that pinned
the old one, and turns everything signed under it into "signed for
elsewhere". A **handover** lets the old key sign over to its successor,
so that a client follows the change without a warning and keeps the old
key as an **alias** for what was signed under it.

A handover is to a **pre-committed successor**, much as a user card's
`successor` is (`hotline-ng-identity.md` §3.4): the server says in
advance, under its current key's signature, which key comes next.
Without the commitment, a thief who stole the server key could hand
over to a key of its own, silently. A card's commitment is immutable; a
server's may be made again after its successor is lost, at the price of
one warning to each client that held the old one (§5.6).

`S`, the skew allowance below, is ten minutes, as in `e2e-messages.md`
§3.1, and "verified strictly" means that document's strict rule.

## 1. What it protects, and what it does not

**Protects:**

- **Rotation without a warning**, and lines and articles signed under
  the old key still in scope (§5.5).
- **A thief of the current key alone**, against clients that already
  hold the commitment: a handover to a key of its own does not match
  it, and warns (§5.3).

**Does not protect:**

- **A thief of the current key, against new pins.** While it holds the
  key, it can sign challenges with a commitment of its own, which every
  client that first pins, or pins again after a warning, takes on trust
  on first use (§5.1).
- **A holder of a retired key.** For clients that have not followed
  the real handover, it can sign that handover again with a later
  `time`, widening the retired key's alias window; and at a client's
  first pin it controls the whole chain served then, so first-pin
  aliases are trust on first use (§5.1).
- **A holder of both a retired key and its live successor** can fork
  the clients that have not followed the real handover.
- **Different clients shown different chains.** Fork detection is each
  client's own, with no gossip between them, so a server that shows
  clients different chains is caught only by a client served both.
- **A lost key.** A key the server no longer holds signs no handover
  (§5.6).

## 2. The commitment, in the server challenge

This document asks `hotline-ng-auth.md` §6.2's server challenge to gain
an optional key:

| Key | Type | Req | Notes |
|---|---|---|---|
| `next` | bstr(32) | no | SHA-256 of the 32 bytes of the key that will follow `server_key`, covered by `sig` |

Signed objects ignore unknown keys and cover them, so a server adds it
without breaking a client that knows nothing of it. The commitment
lives only there. Discovery carries none: it may be plain HTTP, and
only the signed challenge is believed.

A server MAY add a commitment to a key that has none, by starting to
sign `next` in its challenges. That protects only the clients that pin
after it: a client that pinned the key before, by a first pin or by
following a handover with no `next` into it, remembers no commitment,
and warns at that key's first rotation (§5.2). A server changes or
removes a commitment only by handing over (§3), or by committing again
after losing its successor (§5.6).

## 3. The handover

Domain `hl-identity/server-handover/v1`, signed by `old`, in
deterministic CBOR as every identity object is
(`hotline-ng-identity.md` §3.1):

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `old` | bstr(32) | yes | The key handing over |
| `new` | bstr(32) | yes | Its successor; never equal to `old` |
| `next` | bstr(32) | no | SHA-256 of the 32 bytes of the key that will follow `new`: `new`'s own commitment |
| `time` | uint | yes | Unix seconds, when `new` took over |
| `sig` | bstr(64) | yes | Ed25519 by `old`, domain `hl-identity/server-handover/v1` |

A handover SHOULD carry `next`: one without it ends what a client can
follow, since no later handover can link to it (§5.3).

## 4. The chain, in discovery

`server_handovers`, a field `hotline-ng-auth.md` §5's discovery table
gains, is a JSON array of base64url strings (no padding), each one
handover's CBOR, and is absent when there are none. Each is signed on
its own, so plain HTTP cannot alter one. The array is oldest first,
each one's `new` the next one's `old`, times strictly ascending, no key
appearing twice, the last one's `new` the `server_key`, and at most 16.
A server never hands over to a key it handed over from earlier, as from
K1 back to K0 after K0 to K1, which would leave a key that is both the
pin and an alias.
A server keeps the latest 16 it has signed, and serves each as the
bytes it signed, never a signature made again, which with a randomized
signer would look like a fork.

## 5. What a client does

A client keeps, per host, its pin, the commitment it remembers, its
aliases and its fork records (§5.4) durably, on disk, as
`identity-threat-model.md` asks of anchors. It checks the served chain
against its fork records on every fetch of discovery, which it makes on
each connection, and so at every pin and every key change too.

### 5.1 Pinning

At first contact, or when the user accepts a warning and the client
pins again, the client verifies the server challenge for the host
(`hotline-ng-auth.md` §6.2) and takes its `next`, possibly absent, as
the commitment it remembers. At first contact, the chain served then
gives aliases only (§5.5), on trust on first use. It is checked as §5.3
checks a chain,
except that the first `new` is not matched against a commitment: the
signatures, the links from each `next` to the following `new`, the
times, no repeated key, and the last handover's `new` being the
challenge's `server_key` and its `next` being the challenge's `next`
all still apply. A chain that fails them, or that holds more than 16
handovers, gives no aliases, and the client pins with none.

### 5.2 Same key, later

The challenge's `next` must equal the commitment the client remembers.

- A client that remembers none and sees one neither adopts it nor
  warns. Adopting one on sight would be no safer than the pin, and would
  let a thief pre-commit to a key of its own; that key's first rotation
  warns instead.
- A client that remembers one and sees another, or none, warns. If the
  user accepts, it pins again, taking the new `next` and keeping its
  aliases.

### 5.3 Key changed

The client follows the served chain from the handover whose `old` is
the key it pinned, and moves the pin only when all of these hold of
the handovers it follows, from that one on (that the whole list keeps
§4's shape is the server's obligation, not the client's check):

- each handover verifies strictly with its `old`;
- the first one's `new` hashes to the remembered commitment, and each
  later one's `old` is the previous one's `new` and its `new` hashes to
  the previous one's `next`; a handover with no `next` ends what can be
  followed, and a handover after it fails;
- times strictly ascend, the first later than that of every handover
  the client holds a record of, and none is later than now plus `S`;
- no key repeats, and the list holds at most 16;
- the new key's server challenge verifies for the host;
- the last followed handover's `new` is that challenge's `server_key`,
  and its `next` equals that challenge's `next`, both absent counting
  as equal.

Anything else warns, as a changed pin. On success the client moves the
pin without a warning, keeps the old keys as aliases, and takes the
challenge's `next` as its commitment. A client pinned at a key older
than the 16 kept warns. When the user accepts any warning, the client
pins as in §5.1 but takes no aliases from the chain served then, since
a key it gave up at an earlier warning could otherwise come back as an
alias, through a handover signed by whoever holds that key now.

### 5.4 Forks

A client keeps, per host, for each handover it has followed or taken at
a first pin, its `old`, the SHA-256 of its bytes, its `time` and its
`next`. A served handover from the `old` of a record, whose bytes
differ from the record's, is a fork, whether it names another `new` or
the same one at another time: the client warns and keeps the one it
holds. (Two from one `old` in one served list already break §4, and
warn as a chain that cannot be followed.) A served handover that does not
verify forks nothing, since its `old` is not to be believed, and nor
does a list of more than 16, which is not verified at all. If the user
accepts that warning, the client keeps its record, takes no alias from
the conflicting handover, and remembers that handover's SHA-256 so as
not to warn of it again. Pinning again after a warning
keeps these records and aliases; a chain served at that pin that
conflicts with them warns in turn.

### 5.5 Aliases

A line or article whose `in.server` is a kept handover's `old` is in
scope (`e2e-messages.md` §3.5) when its `sent` is no later than that
handover's `time` plus `S`, and signed for elsewhere after it. Aliases
taken at a first pin are no stronger than that pin. A server checks
ingest against its current key alone; a client that signed under the
old one is refused `bad_signature` and signs again.

### 5.6 A lost key, or a lost successor

A server that lost its key publishes the new one with no handover: what
was signed under the old key becomes signed for elsewhere, and a client
that pinned it warns. That is accepted, since the alternative is taking
the server's word that the old key was its own.

A server that lost, or exposed, its committed successor commits again
on the same key, signing another `next`: each client that remembered
the old commitment warns once (§5.2), and on acceptance keeps its
aliases, since the key itself did not change.

## 6. What a server does

- Keeps the successor's private key where the running server cannot
  reach it, as `identity-threat-model.md` says for a card's successor
  (SHOULD), or a thief of the server takes both.
- Signs a handover only to the key it committed to, with that key's own
  `next` (SHOULD, §3).
- Serves `server_handovers` and the challenge's `next` as §2 and §4
  say.

Tooling to make a successor and sign a handover is deferred: there is
no `hxd` command for it yet.

## 7. Across server links

Only a server's current key crosses a link (`e2e-messages.md` §5), so a
linked server's rotation makes its users' earlier lines signed for
elsewhere on the servers it links to, until the link wire carries the
chain too.

## 8. Additions to other documents

Made:

- `hotline-ng-auth.md` §6.2: `next` in the server challenge (§2).
- `e2e-messages.md` §3.5 and §4.13: a reader's scope check accepts an
  alias a followed handover keeps (§5.5), where the server on ingest
  accepts the current key alone.

Pending until a server serves them:

- `hotline-ng-auth.md` §5: `server_handovers` in discovery (§4).
- `hotline-ng-auth.md` §4.3: the handover object (§3), beside the
  server key it rotates.

## 9. Open questions

- Should the link wire carry a linked server's chain, so its users'
  earlier lines stay in scope on the servers it links to (§7)?

## 10. Test vectors

In `server-handover-vectors.json`, beside `identity-test-vectors.json`
and in its shape, with server keys beyond that file's one. Handovers and
challenges are named once and the cases name them: each client case is
what a client remembers, the chain served and the new challenge, and
what the client does. hl-identity's `tests/server_handover.rs`
generates the file and checks every vector against the crate.
Everything a case expects binds but a warning's `reason`, which names
the check of that implementation that failed. They are:

- a server challenge carrying `next`, signed with it, beside
  `hotline-ng-auth.md` §6.2's own vectors, and one whose `next` is not
  32 bytes, refused;
- a handover with `next`, and a chain of two; the same chain served
  from before the pin, followed from the pinned key; the alias
  boundary, a line with `sent` at the handover's `time + S` in scope
  and at `time + S + 1` signed for elsewhere; and a chain whose last
  handover and the new challenge both lack `next`, accepted;
- §5.2's same-key cases: none remembered and one seen (no warning),
  one remembered and another seen (warning), one remembered and none
  seen (warning);
- boundaries accepted: exactly 16 handovers followed, and a handover
  whose `time` is exactly now plus `S`;
- first pins that give no aliases: a chain that fails its checks, and
  one of more than 16 handovers;
- pins again after a warning, which give no aliases (§5.3): after a
  commitment warning, where the replaced key's handover gives none;
  after a second key-change warning, where a key given up at the first
  signs a handover it never made and gives none; and one whose chain
  forks against a record, which warns in turn (§5.4);
- a list of more than 16 handovers at the same key, which is not
  verified and forks nothing;
- rejects: a handover signed by `new` rather than `old`; one whose
  `new` equals its `old`; one whose `new` does not match the
  commitment; a key change with no commitment remembered (§5.2); a
  followed handover no later than a record the client holds; a later
  `new` that does not match the previous `next`; a
  later `old` that is not the previous `new`; a handover after one with
  no `next`; a last `new` that is
  not the new challenge's `server_key`, with both `next`s absent; a
  fork from one `old` to two keys; a fork with the same `old` and `new`
  at another `time`; a handover whose `time` is past now plus `S`; a
  chain whose times are equal; a list of more than 16 handovers; a
  chain that repeats a key; a new key whose challenge `next` differs
  from the last followed handover's; the new key's challenge signed for
  another host; a pinned key older than the 16 kept; a handover in a
  non-deterministic encoding; a `v` other than `1`; and a chain whose
  last `new` is not the `server_key`.
