# hxd-ng documents

One line per document: what it is, whether this server has built it,
which client population it reaches, and whether it is an hxd-ng internal
or a specification meant to be implemented by someone else. Each
document also carries a `Status:` line at its top; this table is the
index, that line is the truth if they ever disagree.

**Population**: *period* is an unmodified Hotline 1.2 / 1.5 / 1.9
client; *extended* is a modern client on the classic wire negotiating
the community's extensions (GtkHx today); *ng* is the Hotline-ng
WebSocket wire (hx-ng today). See the README's feature matrix.

**Kind**: *spec* is written to be implemented by a second party and
should be read as normative where it uses MUST/SHOULD; *design* is how
hxd-ng builds something and binds nobody else; *proposal* is addressed
to another project.

## The ng protocol

| Document | Built | Population | Kind |
|---|---|---|---|
| [hotline-ng.md](hotline-ng.md) — framing, handshake, requests and events, seq accounting | yes | ng | spec |
| [hotline-ng-auth.md](hotline-ng-auth.md) — transport authentication, discovery, transport tokens, the TRTP tunnel, tunnels and relays | yes | ng, and period/extended through a tunnel | spec |
| [hotline-ng-identity.md](hotline-ng-identity.md) — the identity objects, the identity profile at auth, cards, account association | yes, to the registrar stub | ng, tunnel | spec |
| [identity-enrollment.md](identity-enrollment.md) — certifying a device through a mailbox and a code | server side | ng | spec |
| [identity-registrar.md](identity-registrar.md) — handles, revocation, rotation, freeze, key backup, transparency, standing and probation | no | ng | spec |
| [identity-vouch.md](identity-vouch.md) — a member lending standing to a key | no | ng; local form from any account | spec |
| [identity-threat-model.md](identity-threat-model.md) — what identity defends against | — | — | design |
| [identity-test-vectors.json](identity-test-vectors.json) — signed objects and reject cases | yes | — | spec |
| [push-notifications.md](push-notifications.md) — the notify decision and the gateway | trait only | ng | design |

## Features on both wires

| Document | Built | Population | Kind |
|---|---|---|---|
| [access-bits.md](access-bits.md) — every access bit, `[extra]` policy, `[identity]` flags | yes | all | design |
| [private-messages.md](private-messages.md) — the offline inbox | yes | all (period receives) | design |
| [chat-history.md](chat-history.md) — server-held scrollback, fogWraith's Get Chat History | yes | extended, ng | design, implements a fogWraith spec |
| [inline-media.md](inline-media.md) — images in chat, fogWraith's Inline Media | yes | extended, ng (period sees the caption) | design, implements a fogWraith spec |
| [moderation.md](moderation.md) — reports, redaction, revocation, purge | schema only | all (period can be moderated) | design |
| [news.md](news.md) — threaded news, references, follows, search, markdown, the legacy bindings | ng wire | ng now; period when §12 lands | design; §9–§10 are the ng spec |
| [system-account.md](system-account.md) — the reserved server account: commands and notifications on the classic wire | no | all | design |
| [voice.md](voice.md) — the SFU, one room across both signalling wires | yes | extended, ng | design, implements a fogWraith spec |
| [capabilities-video.md](capabilities-video.md) — video publications and subscriptions | yes | ng; extended when GtkHx renders | spec, contributed to fogWraith's set |
| [files-plan.md](files-plan.md) — the file area's first slice | no | all | design |
| [file-sources.md](file-sources.md) — exploratory background for files | superseded | — | design |

## Proposals

| Document | Addressed to |
|---|---|
| [proposals/messaging-identity-amendment.md](proposals/messaging-identity-amendment.md) | fogWraith's Capabilities-Messaging |

## Reading order for a second implementer

1. `hotline-ng.md` — the wire.
2. `hotline-ng-auth.md`, then `hotline-ng-identity.md` — how a socket
   gets a principal and what the principal means.
3. `identity-registrar.md` §7 — what a server does with a registrar,
   and §7.5 for admission and probation.
4. `news.md` §9–§10, `inline-media.md` §8, `moderation.md` §5,
   `voice.md` §6, `capabilities-video.md` — the ng request families,
   each in its own document.
5. `identity-test-vectors.json` — check your objects against it before
   anything else.

Everything else is how this server does it, and is worth reading for
the reasoning but binds nobody.
