# Applying a registrar's records: the verifying server

Status: R1's admission half built (records fetched at `auth`, kept on disk and applied); the sweep that ends sessions and `banned_registrars` are next. §6 stages it.

`identity-registrar.md` §7 says what a server that trusts a registrar
does with what the registrar publishes: resolve its key, fetch the
signed records naming an identity, and refuse or downgrade on a
revocation, a rotation or a freeze. The registrar half is built (it
publishes all of it, `crates/hxd-registrar`); the server half mostly is
not, so a key revoked at its registrar still logs in everywhere but the
registrar's own server. This document is the plan for building §7: what
exists, the decisions §7 leaves to the implementation, and the order.
It changes no wire behavior §7 does not already specify.

## 1. What exists

- **Attestations** are verified at `auth` against `[identity.registrar_keys]`,
  a static host-to-key table whose hosts are the trusted set
  (`hxd-ng-session/src/identity.rs`, `accept_attestations`). There is no
  discovery fetch and no `retiring` key.
- **The local revocation list** (`[identity] revoked_identities`,
  `revoked_devices`, `hxd identity revoke`) is complete: refused at
  `auth`, at resume and at token redemption, and installing it ends the
  sessions it now refuses (`hxd-core/src/revoked.rs`).
- **A registrar ban** (`*@host` in the ban list) matches the one handle
  accepted from a trusted registrar.
- **Anchors** (`[identity] successors`, identity spec §3.4) are kept and
  enforced on cards; nothing yet acts on a rotation.
- **`hl-identity`** parses and verifies every record kind and the signed
  record list (`Record::parse`, `SignedList::parse`), given the
  registrar's keys; checking a list's entries against the fingerprint
  asked for, and its `expires` against now, is the caller's.
- **`hxd-feeds`' fetch** is a bounded, conditional HTTPS GET that checks
  every address it connects to, redirects included, and fetches an
  operator-configured private host as configured.

Absent: discovery and its cache, the records fetch and its cache, every
effect in §7.3's table, `revocation_stale`, `frozen`, rotation at the
server (§7.4), `banned_registrars`, `newcomer_delay`, the `create`
restriction, and standing, probation and vouching (§7.5).

## 2. Decisions

Decided 2026-10: a revoked key's sessions end as soon as the revocation
is found, the records cache is durable, and the fetch is its own crate.

- **One fetch client, shared.** The fetch moves out of `hxd-feeds` into
  a crate of its own, `hxd-fetch`, which `hxd-feeds` and the identity
  code both use: the address checks, the bounds and the conditional GET
  are the same problem, and a second copy is a second place for an SSRF
  to hide. A registrar named in `[identity.registrar_keys]` is
  configured by the operator and is fetched as a configured feed is,
  private address and all; a registrar learned any other way is not
  fetched at all (§7.1 resolves only trusted registrars).
- **The identity code fetches with `hxd-fetch` directly.** The tests
  stand a real registrar up in process and point the verifying server at
  it with `[identity.registrar_urls]`, which asks for the registrar by its
  own name at an address the operator gives, as a LAN deployment would.
  The handshake never blocks on the network for longer than
  `[identity] registrar_timeout` (default 3 s); past it the cache and
  `revocation_stale` decide, as for an unreachable registrar.
- **The records cache is durable.** Lists are kept in a small SQLite
  table beside the bans (fingerprint, registrar, the signed bytes, their
  `expires`, when fetched), so `revocation_stale = cached` still has
  something to use after a restart while the registrar is down. A list
  is re-verified as it is read back, so the file is a cache and never a
  source of trust.
- **A revocation found ends sessions, as the local list's does.** §7
  fetches at three points, all of them admissions. A key revoked while
  its session is attached would otherwise keep that session until it
  next resumes, which can be days for a phone. So a sweep refreshes, on
  the records' own lifetime, the lists of identities with a live or
  detached session, and applying a list that now refuses one ends its
  sessions through the same path `set_revocations` uses. A rotation's
  predecessor and a device revocation end theirs too; a freeze ends
  them only when `frozen = deny`.
- **A ban on a registrar reads every attestation.** `banned_registrars`
  (and `*@host`) is checked against each attestation on the card,
  verified or not: a card is the identity's own signature, so an
  attestation on it is one its holder chose to carry, and nobody can put
  one on another's card.

## 3. Applying records

As §7.3's table, at each of its three points and at the sweep: a list
is applied in `time` order; `AuthRefused` gains `Rotated { successor }`
and the `frozen` outcomes; a device revocation also drops the device's
cached card. An attestation revocation is applied before age is
computed, and an identity left with no attestation is unattested, which
`unattested` (later `admission.unknown`) then decides. Every effect is
logged with the registrar, the record's `seq` and the fingerprint, and
counted in `metrics` (`hxd_identity_records_applied_total{kind}`).

An identity's records are fetched from the registrars that attested it,
so a card shown without its attestations is not looked up: whoever holds
a revoked identity key can drop the attestation and be admitted as the
unattested key it then is. §7.2 says as much (an unattested identity "is
never stale"); what refuses a stolen key everywhere is its holder
revoking it, which every server that cached the list then applies, and
the operator's own `revoked_identities`.

## 4. Rotation at the server

§7.4 as written: accepted from a trusted registrar's list, or from an
`auth` request's `rotation` when the server anchored the predecessor.
What moves to the successor, each in the store that keeps it:

| What | Where |
|---|---|
| the account link | the account file's `[identity]`, rewritten with `toml_edit` |
| bans | the moderation store |
| block-list entries | the inbox store |
| stored mail | the inbox store's mailbox key |
| the anchor | `[identity] successors`, the predecessor written as *rotated to X* |

Each move is idempotent and the whole is retried until it completes,
since a rotation is seen at whichever of several points comes first and
a server may stop between two stores.

## 5. Settings

```toml
[identity]
registrar_timeout  = 3          # seconds a handshake waits on a registrar
trusted_registrars = []         # hosts trusted on their discovery document's key
revocation_max_age = 3600       # a list is used at most this long, whatever its `expires`
revocation_stale   = "cached"   # cached | guest | deny, past both
frozen             = "deny"     # deny | guest
banned_registrars  = []         # hosts whose identities are refused with `denied`

[identity.registrar_keys]       # trusted on this key; discovery is still read for endpoints
[identity.registrar_urls]       # host → base URL, for a registrar not at https://<host>
```

A host in both `trusted_registrars` and `registrar_keys` is trusted by
its configured key.

## 6. Staging

- **R1: records.** `hxd-fetch`; discovery with its cache and `retiring`
  keys; the records fetch, its durable cache and `revocation_stale`;
  every row of §7.3 but rotation; the sweep ending sessions;
  `banned_registrars`. The e2e stands up a real registrar and a
  verifying server: a device revoked, an identity revoked mid-session,
  an attestation revoked downgrading to unattested, a freeze and its
  lift, the registrar unreachable under each `revocation_stale`, and a
  key rotation at the registrar honored through `retiring`.
- **R2: rotation.** §7.4 and the moves of §4, with the `auth` request's
  `rotation`, e2e from `hlid rotate` to a session on the successor
  holding the predecessor's account, mail and bans.
- **R3: newcomers.** `newcomer_delay`, and `new_accounts = create`
  limited to attested (and, once R4 lands, vouched) keys.
- **R4: standing and probation.** §7.5 and `identity-vouch.md`, which is
  a draft of its own and is designed further before it is staged.
