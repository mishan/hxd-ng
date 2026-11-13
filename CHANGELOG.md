# Changelog

What changed in each release of the `hxd` server, for the people who
run one. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as AGENTS.md's "Releasing" describes it.

## [Unreleased]

### Upgrading

- Key backup at the registrar (docs/identity-registrar.md §9):
  `[registrar] envelopes = true`, refused at startup until now, keeps
  each identity's key sealed under its holder's passphrase or recovery
  code, which the registrar cannot open, and advertises `envelopes` in
  discovery. Three routes: `PUT /registrar/envelopes` to store or
  delete one, `POST /registrar/envelopes/params` for the salt (a decoy
  for a handle with none) and `POST /registrar/envelopes/fetch`. New
  keys `envelope_max` (1024), `envelope_secret`
  (`registrar-envelope.secret`, generated on first start; back it up
  with the registrar key), and `[registrar.rate]
  envelope_fetches_per_handle` (10 an hour per handle from one address,
  then that address is locked out from an hour, doubling to a day),
  `envelope_fetches_per_handle_daily` (200 a day per handle from
  everywhere, the ceiling on guessing) and
  `envelope_fetches_per_address` (30 an hour, 240 per IPv6 /48). Counts
  are kept in the store; `hxd registrar unlock <handle>` forgets them.
  Envelope puts are held to `records_per_identity`, and one no newer
  than the last is refused. The registrar database moves to schema 2 on
  first start, adding the envelopes and the fetch counts. An identity's
  envelopes go when it is revoked or rotated. `hlid backup` and `hlid
  restore` are the user's side.

- `[ng] max_detached_per_login` (default 2) is a new key: how many
  detached sessions one login may hold at one address. `[ng]
  max_detached_per_addr` is now the backstop for every login there
  together, and its default rises from 2 to 32. An IPv6 address counts
  as its /64. Behind carrier-grade NAT or a shared router, one person's
  dropped connection no longer ends someone else's detached session
  until the address holds 32. A
  config that set `max_detached_per_addr = 2` keeps the old cap, IPv6
  now counted by /64, until it is raised. The Docker image takes
  `HXD_NG_MAX_DETACHED_PER_LOGIN`.
- Schema 37 adds the server emoji catalog, and `[emoji]` is a new
  config section, off unless enabled (docs/server-emoji.md).
- The ng wire gains `news_timeline`: one stream, newest first, of the
  threads started in every news category an account follows and has
  not muted, each marked `unread` as its category's badge counts it,
  and `news_seen { timeline: true, from, up_to }` to say a run of it
  was shown (docs/news.md §10.8, §10.9). Each costs 4 of an ng
  session's request limit. A client that never asks sees no change.
- Server emoji: a catalog of images the operator curates with `hxd
  emoji` and the server rereads on SIGHUP. Where `[emoji]` is enabled,
  the classic wire offers it as capability bit 20 to a UTF-8 session,
  and the ng wire to a login that declares `emoji: true`: the `emoji`
  capability and its block, `emoji_list`, `emoji_changed`, `GET
  /emoji/{hash}` and the `emoji` refs on `chat` and `msg` and on what
  carries them (docs/server-emoji.md §8). `GET /emoji/{hash}` is held
  to `[limits] avatar_fetches_per_minute` per address, counted apart
  from the avatars'. A client that never asks for either sees no
  change. The Docker image turns the catalog on with `HXD_EMOJI`.
- Reactions on the classic wire: capability bit 19, the Reactions
  draft's, offered where `[reactions]` and `[structured_chat]` are both
  enabled, and confirmed only beside bits 1 and 17. No new key: the
  login reply carries `[reactions] max_keys` and `max_per_user`, and the
  account's `burst` and `per_second` hold classic reactions as they do
  ng's. Send Reaction (710) reacts to a lobby or room line, an instant
  message or a stored private message, Reaction Changed (711) tells the
  change in batches, Get Reactions (712) reads them back, and a line's
  reactions ride its Get Chat History (700) entry. A stored private
  message's reference reaches a client with bit 19 as `DATA_PM_ID` on
  its 104 and on the reply to the 108 that sent it. 710 costs a line's
  spam points and 712 one and one for each ten targets
  (docs/reactions.md). A client without the bit sees no change.
- Replies on the classic wire: capability bit 18, the Replies draft's,
  offered wherever `[structured_chat]` is enabled and confirmed only
  beside bits 1 and 17, with no key of its own. A line of the lobby, a
  room or a private chat, an instant message and a private message may
  say which one it answers, by its line id, its guid or its stored
  message's reference, heard on both wires; Get Chat History (700) takes
  line ids to fetch a page's quoted lines in one request, under the
  history rate (docs/replies.md). A client without the bit sees no
  change. **A server that has kept a reply to a lobby notice cannot be
  downgraded cleanly**: an older one answers every 700 and ng `history`
  page holding such a line "Server error.". A 700 refused for a
  session with the bit carries the Structured Chat family's
  `DATA_CHAT_REASON` beside its text, so a client tells a rate refusal
  (6) from a refused permission (2), a malformed id (12) or too many
  (13) without reading the text.

### Fixed

- A client that may use any name logging in, agreeing or changing its
  info with an empty name, or one a classic client reads as empty (a
  leading NUL, or nothing but control characters), and shown with none:
  such a name at login falls back to the account's, and one sent later
  leaves the nick as it was. An account file's `name` like that is read
  as the login, and `[system] nick` like that is refused. A linked
  user with no name is shown as `unnamed`, and an update without one
  keeps the name it was shown by.

## [0.3.0] - 2026-11-05

### Upgrading

- No schema migration and no config change.
- On the ng wire, the `msg` reply to a message that went as an instant
  message carries `im: true` and the message's `guid`, the one it was
  sent with or the server's own, so a client names it by guid for
  replies and reactions rather than as a stored message. A client that
  ignores unknown fields sees no other change.

### Fixed

- A private message waiting for its recipient, retried by login under
  its guid once they were back, never reaching their attached session.
- A retry by login of a private message read and pruned since answered
  as an instant message.

## [0.2.0] - 2026-11-04

### Upgrading

- The main SQLite store migrates from schema 29 to 36 on first start:
  portable friendships, a private message's reference and per-mailbox
  cursor, replies, reactions on chat lines and on stored private
  messages, and stubs of read messages. Forward-only, as before: take a
  backup first (docs/operating.md, "Backups"). The registrar's database
  is unchanged.
- A new secret, `messaging-requests.key` beside `[inbox] db`
  (`[messaging] request_secret`), is made owner-only on first start
  wherever `[messaging]` and `[inbox]` are configured, and one that
  cannot be read refuses the start. Back it up with the other keys.
  Each address's count of requests sent today starts over once.
- `[messaging] max_message_bytes` is now at most 65505, and twice
  `request_messages` messages of that size must fit a page of the
  classic wire's Get Message Requests; a config past either is refused
  at start. The defaults are well inside both.
- Get User Info shows a user's login and address only to that user and
  to a session holding `disconnect_users`; everyone else, the bootstrap
  guest included, reads `-` in their place.
- A private message to a login now reaches every attached session of
  the account but the sender's, rather than one of them.
- To an account taking part in messaging, a guest's message by login is
  now a message request, or refused where the account takes none.
- On the ng wire, a stored private message is named by `ref`, and `id`
  is now its place in the reader's own mailbox; the `msg` reply carries
  `ref` in place of `id`. An id a client kept from 0.1.0 is not a cursor,
  so a client should read `inbox` afresh; a cursor its mailbox never
  issued is refused `bad_request` by `inbox`, `msg_read` and `report`.
- Get Chat History sends a line in the session's own line endings, its
  nick cut to the user list's length.
- Account and roles files and a self-signed TLS certificate are written
  owner-only, and an account file loosened by hand is made owner-only
  again by its next edit. A key or secret readable by group or others
  is still used, with a warning naming it.
- A read message pruned inside its sender's `[inbox] retain_unread`
  window leaves a stub until the window ends; raising `retain_unread`
  can show a sender which of its messages already past the old window
  were read (docs/operating.md, `[inbox]`).
- The Docker image's `latest` tag follows main alone; a release tag
  publishes `X.Y.Z` and `X.Y`.

### Known limitations

Built since 0.1.0: instant messaging on the classic wire, and portable friendships on both wires.

- Signed and sealed messages on the classic wire (capability bit 13 is never confirmed).
- Replies on signed lines and messages.
- hx-ng reacts to public lines only: no client reacts to instant or stored private messages yet.

### Legacy Hotline wire

- Structured Chat, capability bit 17: each chat line also sent as its Chat History entry, to a client that asks (`[structured_chat]`, `HXD_STRUCTURED_CHAT`, docs/chat-history.md section 12).
- Classic FILP uploads, and their resumes, from a session that negotiated Large Files, as GtkHx sends them; a refused HTXF transfer is logged at INFO with its peer and reason.

### Hotline-ng wire

- Replies: `re` on `chat` and `msg`, naming a line, a stored private message, an instant message or a signed line, relayed as sent to sessions that declare `replies`; `history` by `ids` (docs/hotline-ng.md section 7.3).
- Reactions: an account's emoji on lobby and room lines, instant messages and stored private messages (`react`), counted on `history` and `inbox`, told live as `reactions_changed` batched per room, and read again with `reactions`, naming who reacted by nick; off by default (`[reactions]`, needs `[history]`; `HXD_REACTIONS`).
- An instant message read as mail carries `im: true` and its `guid`.

### Identity and registrar

- Device proof on the classic wire: Get Device Challenge and Prove Device, capability bit 14, for a classic client holding its own device key (`[identity] classic_hosts`, `classic_proof`; `HXD_IDENTITY_CLASSIC_HOSTS`, `HXD_IDENTITY_CLASSIC_PROOF`; docs/proposals/portable-friends.md section 3).

### Instant messaging

- fogWraith's Instant Messaging extension and the message requests draft on the classic wire, capability bits 6 and 8, for accounts taking part, sharing friends, presence, IMs and requests with ng (docs/instant-messaging.md section 7).
- Portable friendships: a friendship signed by both parties' devices, presented on another server and in place there with no new request, and ended everywhere by a signed withdrawal; on ng (`friendships`) and on the classic wire (capability bit 15), from a proved device (docs/proposals/portable-friends.md, docs/hotline-ng.md section 7.5).
- Requests from guests: the plain guests as one group, an identity guest by its fingerprint to sessions that can name it; an approved identity guest's messages wait for an absent recipient only with `[messaging] queue_identity_guests`.
- Listing message requests renews an account's opt-in, and Set Presence without a state leaves presence, and Invisible, as it was.

### Moderation and bans

- A moderator's clear of a line's reactions, recorded with its reason.
- A purge (`purge`, a kick with purge, `hxd purge`) takes the person's reactions in its window, on lines and stored private messages; `hxd inbox purge` takes and counts an account's.
- The moderation log shows an act kind it does not know as `unknown (N)` rather than failing.

### Operations

- Keys, secrets, account files and the self-signed certificate are written whole through a temporary file beside them, so a crash never leaves a partial key that refuses the next start; `hlid`'s keys too.
- `HXD_SYSTEM_ICON` for the system account's icon in the Docker image.

### Fixed

- Chat history's hourly retention failing with "database is locked" beside the inbox, and pruning nothing.
- A session left on the roster, and online to friends, after its connection task panicked; a link or dialer that panics is unregistered and dialed again.
- Status text set while Invisible reaching friends once the account's last session left.
- A released message request counted twice toward the sender's daily quota.
- A message to a session that had just logged in arriving marked queued.
- A retry of a read and pruned private message storing a second copy, which told its sender it had been read.

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
- The real-client exit test for rooms (period 1.2, 1.5 and 1.9 clients) has not been run.

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

[Unreleased]: https://github.com/mishan/hxd-ng/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/mishan/hxd-ng/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mishan/hxd-ng/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mishan/hxd-ng/releases/tag/v0.1.0
