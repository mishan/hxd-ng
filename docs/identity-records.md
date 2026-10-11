# Applying a registrar's records: the verifying server

Status: designed, not built. §6 stages it.

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

- **One fetch client, shared.** The fetch moves out of `hxd-feeds` into
  a crate of its own, `hxd-fetch`, which `hxd-feeds` and the identity
  code both use: the address checks, the bounds and the conditional GET
  are the same problem, and a second copy is a second place for an SSRF
  to hide. A registrar named in `[identity.registrar_keys]` is
  configured by the operator and is fetched as a configured feed is,
  private address and all; a registrar learned any other way is not
  fetched at all (§7.1 resolves only trusted registrars).
- **The identity code asks through a trait.** `hxd-ng-session` gains a
  `RegistrarClient` (discover a host, fetch a fingerprint's records),
  which `hxd` implements over `hxd-fetch` and the tests implement over a
  real `hxd-registrar` in process, the way the e2e suites already stand
  a registrar up. The handshake never blocks on the network for longer
  than `[identity] registrar_timeout` (default 3 s); past it the cache
  and `revocation_stale` decide, as for an unreachable registrar.
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
revocation_max_age = 3600       # a list is used at most this long, whatever its `expires`
revocation_stale   = "cached"   # cached | guest | deny, past both
frozen             = "deny"     # deny | guest
banned_registrars  = []         # hosts whose identities are refused with `denied`

[identity.registrar_keys]       # unchanged; a host here skips discovery
```

`trusted_registrars` (§11 there) is accepted as the list of hosts to
trust by discovery; a host in both is trusted by its configured key.

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

## 7. Open questions

1. **Sessions on a revocation.** §2 ends a session as soon as its key is
   found revoked, through a sweep. The alternative is §7's letter, which
   checks only at admission and leaves a revoked key's session until it
   next resumes.
2. **The durable cache.** §2 keeps it in SQLite so a restart while a
   registrar is down still has a list. In memory, a restart forgets it,
   and `revocation_stale = cached` then has nothing and admits as though
   no record existed.
3. **The fetch crate.** §2 extracts `hxd-fetch`. The alternative is the
   identity code depending on `hxd-feeds`, which ties identity to the
   `feeds` feature.
