# Changelog

What changed in each release of the `hxd` server, for the people who
run one. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as AGENTS.md's "Releasing" describes it.

## [Unreleased]

## [0.1.0] - 2026-10-29

The first release.

### Upgrading

- From this release on, the SQLite databases (the main store and a
  registrar's) migrate their schema forward on start and cannot be
  downgraded: an older `hxd` refuses a database a newer one has migrated,
  so going back means restoring the backup taken before the upgrade
  (docs/operating.md, "Backups").

### Known limitations

Designed but not built yet:

- Vouching (docs/identity-vouch.md).
- File attachments on chat lines and private messages (docs/attachments.md).
- Importing mhxd's and Mobius's news.
- Secure rooms, and rooms across links.
- Bans placed from the config, and the ban list on the ng wire.
- A registrar's standing and probation, and its key backup.
- The delivered/read split for private messages: delivery to a classic client still marks a message read.
- Instant messaging on the classic wire (the extension's 800-block for period clients), and portable friendships (docs/proposals/portable-friends.md).
- Legacy text encodings other than Mac Roman, such as Shift-JIS or Latin-1.
- The real-client exit tests for rooms (period 1.2, 1.5 and 1.9 clients) and for voice (a mixed room) have not been run.

### Legacy Hotline wire

- Hotline 1.2 and 1.5 clients (and 1.9 where its behavior is known) on TCP :5500: login, the agreement, user list, nick and icon changes, Get User Info, keepalive, with mhxd's observable behavior.
- Public chat, `/me`, the chat subject, private chats and their invites, private messages, broadcast.
- The access bitmap enforced on every request; the 1.5 user editor for accounts.
- Text-Encoding: UTF-8 for a client that negotiates it, Mac Roman with `?` for the rest.
- HOPE secure login with ChaCha20-Poly1305 or Blowfish transport on the plain port (`[hope]`).
- TLS on a port of its own with a TLS HTXF port beside it (`[tls]`); a CA's certificate or a self-signed one, reloaded on SIGHUP.
- Tracker registration to HTRK v1 and v3 trackers (`[tracker]`).
- The system account (`[system]`): `/help`, `/msg`, `/report`, `/block`, `/rooms`, `/join`, `/role` and the rest, for clients that only have private messages.

### Hotline-ng wire

- A JSON protocol over WebSocket on :5700 (`[ng]`), meant to sit behind a TLS-terminating proxy; spec in docs/hotline-ng.md.
- Sessions that detach when the connection drops and resume with every event replayed by seq, or a resync.
- Discovery, transport tokens, and, with `[identity]`, the TRTP tunnel (`/trtp`, `/htxf`) that carries the classic wire over the ng port.
- Trusted proxies and the client-address header they write (`[ng] trusted_proxies`).
- A weighted request limit per session, answered `rate_limited` with `retry_after`.
- The ng port's own HTTP limits: connections per address and in all, counted from accept, and rates on challenges and avatar fetches.

### Identity and registrar

- Portable identity: Ed25519 identity keys, device certificates, cards and login proofs bound to the server's host (`[identity]`).
- Accounts linked to an identity, or made for one on first login.
- Device enrollment through a mailbox and a code (`/identity/enroll`).
- Server key handover to a pre-committed successor (`hxd identity successor`, `hxd identity handover`).
- Revocation by hand (`hxd identity revoke`), and a registrar's revocations, rotations and freezes applied from the registrars the server trusts.
- Identity policy: `new_accounts = "create"` opt-in (default `guest`), `newcomer_delay`, `allow_list`, `banned_registrars`.
- An identity registrar on the ng port (`[registrar]`): handles, attestations, published records, and `hxd registrar` for freeze, revoke, recover, `invites` and `inspect`.
- `hlid`: a whole identity in one command, certificates, `enroll` and `agent`, `auth`, `register`, `revoke`, `rotate`, and `tunnel` for a classic client.
- Signed public lines, private messages and news articles on the ng wire; private messages sealed to a device (`[sealed]`).

### Accounts and limits

- Accounts as TOML files, with a guest made on first run and `hxd account` for editing; the ng `accounts` requests.
- Connection caps and rates per address and per account, mhxd's chat-flood and spam-point limits, failed-login throttling (`[limits]`), and a bound on logins in progress (`[server] logins_in_flight`).
- A client that will not drain is dropped as a slow consumer, its queues bounded per connection and by `[server] queue_budget_mb` in all.

### Chat, rooms and roles

- Chat history: server-held scrollback, fogWraith's Get Chat History on the classic wire and `history` on ng (`[history]`).
- Curated, persistent rooms from a rooms file, gated by `read` and `post` lists (`[rooms]`, `hxd room`); period clients join by `/join`.
- Rooms that require signed lines (`hxd room create --signed`), read-only to classic clients.
- Roles: named grants accounts hold, resolved to the access every wire sees (`[roles]`, `hxd role`, `/role`).
- Colored Nicknames on the classic wire, shown on ng.

### Private messages and inbox

- An offline inbox: a message to an account that is away waits and is delivered at login, on both wires (`[inbox]`).
- Message guids for safe retry, read state, blocks, retention and a per-sender daily quota.
- `hxd inbox purge` for a deleted account's mail, subscriptions and push devices.

### Instant messaging

- fogWraith's Instant Messaging extension on the ng wire, off by default (`[messaging]`, `HXD_MESSAGING`), for accounts holding `[access] messaging`: friends, presence with Invisible, IMs through the offline inbox with delivered and read receipts and typing, and discovery that shows non-friends no presence (docs/instant-messaging.md, docs/hotline-ng.md).
- Message requests: a stranger's messages held until approved, for an account that takes them, with approvals, holds and bounds per sender, address and recipient.
- Blocks read as a missing account on every request that names one.
- A classic `/msg <login>` to a friend arrives as an IM, and from a classic sender to someone who takes requests, as a request.

### News and feeds

- Threaded news with markdown bodies, references between articles, backlinks and full-text search (`[news]`, `hxd news-reindex`).
- Follows and mutes, and the notifications they earn: replies, references and posts in a followed thread (`[news.notify]`).
- Image attachments on articles, content-addressed and quota-bound.
- The 1.5 threaded-news transactions over the same tree, and 1.2 flat news as one category (`[news] flat_category`).
- Ceilings on live articles and text, and a share of them per author.
- RSS, RDF, Atom and JSON Feed polled into read-only categories (`[[news.feed]]`, limits in `[news.feeds]`, `hxd news feeds`).

### Moderation and bans

- Reports, redaction of a chat line, revocation of an image, and a purge of someone's last hour, with an audit trail (`[moderation]`).
- Reports delivered to classic moderators as messages from the system account, and to ng moderators as events.
- Durable bans on addresses, logins, identities and registrars, placed by a kick with ban or `hxd ban add`, listed and lifted with `hxd ban list` and `hxd ban lift`, applied on SIGHUP.
- Moderation from the command line, against the database: `hxd history redact`, `hxd media revoke`, `hxd purge`, `hxd reports`, `hxd moderation log`.

### Files

- The file area: browse, Get Info, download and upload, folders either way, Large File with verified resume, drop boxes, and New Folder, Delete, rename, Move and comments on a local area (`[files]`).
- The file area on the ng wire too: browse, download, previews (`files_preview`), uploads resumed across sessions (`files_upload`) and the same file management.
- A transfer queue with per-account limits (`[files] downloads_per_account`, `uploads_per_account`, `downloads`, `uploads`, `queue`).

### Media and avatars

- Images in chat (fogWraith's Inline Media): decoded and re-encoded by the server, every byte of metadata stripped, served by handle (`[media]`).
- Avatars on both wires: fogWraith's GIF Icons and the ng `avatars` capability, kept per account (`[avatars]`).

### Voice and video

- A voice SFU on one UDP port, one room shared by classic and ng clients (`[voice]`).
- Camera and screen share on the voice connection, subscribed to per stream (`[voice.video]`).

### Server linking

- fogWraith's Server Linking by key mode over TLS (`[link]`, `hxd link`): users, public chat, private messages, user info, kicks and bans across links, and relaying between them.
- The user transport and user keys drafts: how a linked user is connected, and their signed and sealed messages.

### Push

- Web Push sent by the server itself, for a private message or a news reply while the app is closed (`[push]`).
- A uniqush-push 2.11 sidecar as the second gateway (`[push] gateway = "uniqush"`).
- `hxd push rekey` to replace the VAPID key, dropping every registered device.

### Operations

- One TOML config file, every key optional; SIGHUP reloads accounts, roles, rooms, bans, revocations, the TLS certificate, link peers and the banner (docs/operating.md).
- Optional subsystems behind Cargo features, a config section for a missing one refused at start.
- `[server] classic = false` for an ng-only server.
- The server banner, held or by URL, shown on both wires (`[banner]`).
- The Docker image at `ghcr.io/mishan/hxd-ng`, configured from `HXD_*` variables, with `HXD_MODE=relay` for `hlrelay` (docs/docker.md).
- `hlrelay`: discovery, `/trtp` and `/htxf` in front of a classic server that does not speak ng (docs/relay.md).
- `GET /metrics` behind the `metrics` feature (`[metrics]`, docs/metrics.md).
- `hxd-load`: scenarios on both wires with the server's invariants checked under load (docs/load-testing.md).
- `HXD_DEBUG=proto` wire trace, in GtkHx's format.
- `tools/ng-client.mjs`, a terminal ng client, and `tools/ng-voice.html`, a one-file voice and video client.

[Unreleased]: https://github.com/mishan/hxd-ng/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mishan/hxd-ng/releases/tag/v0.1.0
