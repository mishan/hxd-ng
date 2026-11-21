# Changelog

What changed in each release of the `hxd` server, for the people who
run one. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as AGENTS.md's "Releasing" describes it.

## [Unreleased]

### Upgrading

- Pronouns: a user sets their account's with `/pronouns <text>` to the
  system account (`/pronouns clear` takes them down), and a classic
  client's Get User Info shows them as a `pronouns:` line after `name:`,
  here and on linked servers (docs/system-account.md §3). The ng wire
  shows them as `pronouns` on the `user` object, a change as
  `user_changed`, and sets them with the `pronouns` request, listed as
  the `pronouns` capability (docs/hotline-ng.md §7.3, §7.4). They are kept
  in the account file under a new `[profile]` section, which a build
  from before this release refuses to read: roll back only after taking
  `[profile]` and `[extra] pronouns` out of the files that have them. New keys: `[server]
  pronouns` (default `true`; `false` shows none, a linked server's
  users' included, and takes none, while a user may still clear what is
  kept) and `[extra]
  pronouns` (default: a password or a linked identity, as `set_avatar`;
  no role may grant it). A value an account file holds that the server
  would not have written is not shown, and said so at startup.

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

- Device epochs at the registrar (docs/identity-registrar.md §4.10,
  §6.2): `POST /registrar/records` takes a reset, signed by the identity
  key alone, revoking every device certificate of the identity below
  its `epoch`. An `epoch` may move at most 16 past the current one, a
  reset dated before the last is refused, and four may be published a
  day per identity; a reset at or below the current one, like any record
  already held, is answered as done with where the identity stands
  (`epoch`, and `hash`, the current record's) and counted as a lookup.
  A device revocation signed by a device certified below the identity's
  epoch is refused `bad_signature`. The full record list carries an
  identity's latest reset alone; its own list keeps the 256 before it.
  No schema change.

- Servers now apply resets (docs/identity-registrar.md §7.3): a device
  certificate issued below the highest `epoch` its identity's trusted
  registrars publish is refused `revoked` at `/identity/auth`,
  with that floor as `epoch` in the body, and at the classic wire's
  Prove Device, a device on file and a token's redemption; the records
  sweep ends its sessions on both wires, connected or detached, and a
  resume or a login on a socket that authenticated first is refused
  `revoked` with `epoch`. Nothing is sealed to it. With no reset every
  certificate is admitted as before. The floor is read from the lists
  held, not yet kept apart from them, and a reset device's push
  registrations and friendship presentations are not yet judged by it.

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
  (6) from a refused permission (2), a channel it does not serve (1), a
  malformed id (12) or too many (13) without reading the text.
- Persons: `[server] coalesce = true`, off by default, shows the
  sessions of one person as one user on both wires: an account linked
  to an identity, for its sessions that logged in as that identity or
  with the account's password, and an account whose file says `[extra]
  personal = true`, for its password sessions. The person joins once,
  leaves with its last device, is one member of each room and private
  chat, is in voice on one device at a time, is kicked and banned whole,
  and crosses a link as one user. An ng client that declares `persons`
  sees its own devices and may end one, and a moderator's sees every
  person's devices, with each one's login and address, and may kick one
  alone; sealed messages reach each device of a person with a box of its
  own, up to `[limits] connections_per_account` of its newest devices
  and never more than 11, which is also the limit where it is 0
  (docs/operating.md, Persons; docs/hotline-ng.md §7.6). A client
  that does not declare it sees one user per person. The Docker image
  turns it on with `HXD_COALESCE`. `kick` with
  `device` from a client that did not declare `persons` is refused
  `bad_request` rather than kicking the whole person.
- An ng session kicked, banned, refused by a revocation or ended by
  another of its person's devices answers its `resume` with `kicked`,
  `banned` (with the ban's reason and end), `revoked` (as a login with
  the key is) or `ended` rather than `session_expired`, whether it was
  attached or detached, so a client that missed the event stops
  instead of logging in again and undoing it, coalescing on or off
  (docs/hotline-ng.md §6.2). A session ended by a freeze at its
  registrar or a rotation of its identity is still `session_expired`,
  and its next `/identity/auth` is refused `denied` or `rotated`, as
  the records say, rather than `revoked`.
  A client that knows none of the codes takes it as any other refused
  resume.
- Metrics: `hxd_roster_rows` counts the rows the user list shows,
  beside `hxd_sessions` (docs/metrics.md).
- `hxd-load accounts --linked` links each account it writes to an
  identity of its own (docs/load-testing.md).
- The registrar's handle lookup carries `successor`, the commitment it
  holds for the holder, read from its store, so a client can learn it
  after a restart has emptied the card cache. A rotation record's
  `next`, signed by both keys, is recorded as the successor's commitment
  when the successor holds none at the registrar. A rotation is refused
  when its successor is frozen, has a rotation of its own pending, or
  already holds a commitment other than its `next` (or holds one and the
  rotation names none), at posting and again when a held rotation is
  published. No commitment is recorded for a frozen, revoked or rotated
  identity, and while a rotation waits, none for the identity it hands
  over and none but its `next` for the successor. A second rotation
  posted while one waits answers the new code `rotation_pending` (409)
  with `pending_until`, where it was `bad_request` before. The old key's
  identity revocation still cancels a pending rotation: once an identity
  has committed to its successor at the registrar, a stolen identity key
  can destroy it there but not take it. `hxd registrar publish
  <fingerprint> --to <successor>` publishes a pending rotation to that
  successor at once, for a holder the operator has confirmed
  (docs/identity-registrar.md §4.6, §5.4, §6.3, §8.2). `GET
  /identity/card/<fp>` is held per address to `[limits]
  avatar_fetches_per_minute`, counted apart from the avatars and the
  emoji. On a server with a registrar, `GET /identity/card/<fp>` answers
  404 for a cached card the registrar would now refuse, and 503, as `PUT
  /identity/card` does, when the registrar's store cannot check a card;
  `hlid restore` takes only a 404 as no card and otherwise stops.
- The registrar keeps, in its store, the newest card put or shown at
  sign-in that carries the successor commitment it holds for an
  identity, and `GET /identity/card/<fp>` serves it when it is newer
  than the cached card or the cache has none, as after a restart. A
  restore (`hlid restore`) then takes that card, signed by the
  identity and carrying the commitment; before, after a restart it made
  a card without it, which the registrar refused. A kept card is
  checked as a cached one is, and not served when the registrar would
  refuse it. A card dated past the registrar's clock skew is not kept.
  For an identity the registrar has revoked or rotated away, `GET
  /identity/card/<fp>` serves no card, cached or kept, where a cached
  one was served before, and the kept card goes. The registrar
  database moves to schema 3 on first start, adding the kept card to
  each identity's row; a build from before this release refuses to open
  it. docs/identity-registrar.md §6.3 now says a client must not sign
  the lookup's `successor` into a card without checking it against an
  object the identity signed (§6.3, §6.4).
- On every server with `[identity]`, the `ETag` of `GET
  /identity/card/<fp>` is the card's `updated` and a digest of its
  bytes, where it was `updated` alone, since two cards of one identity
  can share an `updated` (docs/hotline-ng-identity.md §7). A client
  that sends back the tag it was given is unaffected; one that built
  the tag from `updated` is sent the card again rather than 304.
- `hlid rotate` signs the successor's own commitment into the rotation
  as `next`: it makes the successor's successor key first
  (`--next-key`, by default `successor.next.key` for `--to
  successor.key`), and the successor's card it prints the command for
  commits to that key. Before, it signed no `next` and left the
  successor to register a commitment afterward, which a thief holding
  only the successor's key could have beaten at another registrar
  (docs/identity-registrar.md §4.6). A `--next-key` naming `--to`, the
  identity key or that card's file is refused, and `hlid card`, `cert`
  and `attest` refuse an `-o` that holds a key.
- A trusted registrar's rotation that this server does not take for
  its successor (one anchored here to a key other than its `next`,
  already a rotation's successor, or rotated away) is held rather than
  ignored: the old key is refused `rotated`, naming the successor, and
  its sessions end, but nothing moves, the account link included, and
  the successor gains no anchor. One shown only at `auth` is still
  ignored, and so is any rotation from an old key anchored here to
  another or into a key that rotated to it. Whoever holds the successor
  key alone can force a hold, locking the old key out here, though not
  taking anything of it. To give the account to its owner, set
  `fingerprint` in its file's `[identity]` table by hand to a key that
  is admitted: the successor, or, if the successor has rotated on, the
  end of its rotations. `[identity] successors` gains a
  `<predecessor> => <successor> held` line; a build from before this
  release drops it when it compacts the file and admits the old key
  again, until an upgraded one fetches the registrar's records again
  (docs/identity-registrar.md §7.4).

### Fixed

- A client that may use any name logging in, agreeing or changing its
  info with an empty name, or one a classic client reads as empty (a
  leading NUL, or nothing but control characters), and shown with none:
  such a name at login falls back to the account's, and one sent later
  leaves the nick as it was. An account file's `name` like that is read
  as the login, and `[system] nick` like that is refused. A linked
  user with no name is shown as `unnamed`, and an update without one
  keeps the name it was shown by.
- The enrollment mailbox (docs/identity-enrollment.md §5): an answer,
  approval or denial, is handed out again to its request's secret for a
  minute after the first fetch, so an enrollee whose connection dropped
  mid-poll finds it on its next poll instead of a 410 and an approved
  enrollment lost. A request's `expires_in` is never past the end of
  the holder's session, which takes its requests with it.
- An identity's registrar records are fetched by its fingerprint from
  every trusted registrar this server holds a list from, not only from
  those its card names (docs/identity-records.md §3). A stolen device
  key shown with an older card that carries no attestation, or one
  under a registrar key no longer published, no longer reaches its
  linked account on `/identity/auth` or classic Prove Device past a
  device or identity revocation published since the last fetch: it is
  refused `revoked`, as with the current card. A held list past its
  lifetime is stale for `revocation_stale` too, so `guest` and `deny`
  now apply to any card of an identity with a list held, whichever
  registrars the card names. An identity with no list on file, as one
  an operator linked by hand, is admitted as before.
- A trusted registrar's list held damaged refuses the identity's every
  device, `denied` at `/identity/auth` and refused at classic Prove
  Device, whatever `revocation_stale` says, until the list is fetched
  whole again; a revocation or rotation in another list it holds is
  still answered as such. Under the default `cached`, such a list was
  taken as stale and the login admitted on what it could read, so after
  a restart, with the registrar out of reach, a device it had revoked
  could sign in. While the records store cannot be read, an identity
  whose card names a trusted registrar, or that one is remembered as
  having attested, is refused the same way; any other is admitted as
  before. The list is fetched again at each login, so the refusal ends
  within a minute of the registrar answering (docs/identity-records.md
  §3). A list never fetched, or past its lifetime, is
  `revocation_stale`'s as before. For a registrar gone for good, take
  it out of `trusted_registrars` and `registrar_keys`.
- An operator-keyed registrar whose discovery document could not be had
  is asked for it again after a minute rather than a day, however its
  records fetches went meanwhile, keeping the records path last
  discovered, so one serving its records at a path of its own is not
  asked at the default one for a day. Without a document it is asked
  for one once a minute while a list is due.
- Push notifications to a revoked device. A device key revoked by the
  operator's list or by a trusted registrar's records, or one whose
  identity key is revoked, or frozen under `[identity] frozen = deny`,
  kept its push registrations until its certificate expired, up to 90
  days, and was still sent notifications. Applying the revocation now
  deletes them, and unsubscribes them from uniqush under `gateway =
  "uniqush"`; a registration racing the revocation is refused `revoked`.
  A frozen identity's devices register again at their next login once
  the freeze lifts. A registrar's revocation reaches an identity with
  no session here too: the records sweep refreshes the lists of
  identities with push registrations every ten minutes, fetching each
  only once due under `revocation_max_age`, so while the registrar can
  be reached a device revoked there is sent notifications for no longer
  than `revocation_max_age`, ten minutes, a minute and the sweep's own
  time. The sweep accepts a rotation it finds for such an identity too,
  and with anchors moves its account link as at an admission.
  Registrations left from before are deleted when the operator's list
  is next loaded, or a registrar's revocation next applied.
- A rotation's successor is no longer anchored from its own card, which
  whoever holds the successor key alone could show first, committing to
  a key of their own, and then rotate the identity to it with every
  registrar refusing. A rotation's `next` is the successor's commitment
  in `[identity] successors`, and a successor card that disagrees is
  refused `bad_card`. A successor whose rotation carried no `next` has
  none: a further rotation of it is taken only from a trusted
  registrar's records, no longer from the `rotation` an `auth` carries.
  Shown at `auth`, a rotation to a key already anchored to anything but
  its `next` is ignored, and so is any rotation into a key that is
  already a rotation's successor or has itself rotated away
  (docs/identity-registrar.md §7.4); from a registrar's records, such
  a rotation is held, as the held-rotation note above says.
  The file gains a `<fingerprint> = next <commitment>` line beside the
  plain one, and at the first start an anchor an older build took from a
  successor's card is dropped from it with a warning, leaving that
  successor to a registrar's records. Rolled back, a build from before
  this release keeps the plain line and drops the `next` one, so after
  upgrading again that successor too is left to a registrar's records.

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
