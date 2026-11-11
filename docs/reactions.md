# Reactions on the classic wire

Status: lines and instant messages are built: Send Reaction (710),
Reaction Changed (711), Get Reactions (712) and a line's reactions on
its Get Chat History (700) entry. Stored private messages as targets are
not, and the binary does not offer capability bit 19 until they are. This
binds nobody but this server: the protocol is the Reactions draft
(`Capabilities-Reactions.md`, a draft written for this server, in
fogWraith's protocol documents and not yet allocated), with the targets
and the notification mechanism it takes from the Replies draft and the
line ids and reply shape it takes from Structured Chat.

The ng wire's reactions are `hotline-ng.md` §7.3. Both wires are
translations of one domain (`hxd_core::reaction`): who may react, the
caps, the rate, the batches and who is told are decided there, once, and
a reaction made on either wire is told on both. What this document
covers is `hxd_session::reactions` and the choices the draft left to it.

## 1. Negotiation

- **Bit 19** is confirmed only beside bits 1 (Text Encoding) and 17
  (Structured Chat), as the draft requires, and only where the core keeps
  reactions (`[reactions] enabled`, which needs `[history]`), which the
  configured bits do not promise. A link's login never holds it.
- **The login reply** beside it carries `DATA_REACTION_TARGETS`, lines
  (`0x0002`) always, kind 4 (`0x0010`) where there are rooms and
  instant messages (`0x0004`) to a session that negotiated bit 6 (§2), and
  `[reactions] max_keys` and `max_per_user` as `DATA_MAX_REACTION_KEYS`
  and `DATA_MAX_REACTIONS_PER_USER`. The targets are fixed for the
  session as it was told them.
- **Who may react** is the ng wire's rule: a session of one person's
  account holding the send-chat privilege, the interim gate until the
  draft's React access bit is allocated.
- **A session without bit 19**, a period client and one with bit 17
  alone included, is sent exactly what it was: 710, 712 and 717 are
  answered "Not implemented." as any transaction this server does not
  know, and no 711 or field of the family's reactions reaches it.

## 2. Targets

- **A lobby line** is kind 1 on channel 0, by its history id.
- **A room** shows on this wire as a private chat under its id
  (`chat-rooms.md`), with no `DATA_CHANNEL_ID` (`chat-history.md` §12),
  and the Replies draft names a line in such a channel as kind 4 under
  the chat id. So a room's line is kind 4, and kind 1 on a room's id is
  taken as the same line. Every target goes back to a reader as its
  channel is addressed, the lobby's as kind 1 and a room's as kind 4,
  whatever kind it was asked in.
- **A line nobody keeps**, a private chat's under kind 4 or kind 4 on
  chat 0, is no target: 710 answers `NoSuchTarget` once who may react has
  been asked, and 712 leaves it out.
- **Two id spaces under one chat id.** A room's notices carry ids from
  the room's own count, which starts at a random point below 2^62
  (`chat-history.md` §12), and its kept lines their history ids. Kind 4
  cannot say which is meant, and this server reads it as a history id.
  A notice's id is then above every line yet relayed and fails the read
  check, with overwhelming probability rather than certainty: were the
  two to meet, a reaction meant for a notice would land on a kept line
  of the same room that its reactor could read.
- **An instant message** is kind 2, its sender's login and guid as the
  friend family carries them (`instant-messaging.md` §7). It is offered
  only to a session that negotiated bit 6, since without it a session
  holds no instant message to name, though the draft describes the
  field as what the server accepts. 710 names the conversation's other
  party in `DATA_FRIEND_LOGIN`, and is checked as IM Acknowledge (812)
  is: the two must be friends or share an approval, neither blocking
  the other. The message is never looked up, and kept nowhere to be
  read again, so 712 refuses it.
- **Kinds 3 and 5** (signed lines, private messages) are not taken yet
  and are `InvalidTarget`, as is anything malformed.

## 3. Send Reaction (710)

- **Actions** 1 and 2 add and remove one key; 3 is a moderator's clear.
  A key is one emoji of at most 64 bytes as sent, or with bit 20 one of
  the server's own by id. The core spells an emoji key in its
  fully-qualified form, so U+2764 comes back in a summary as U+2764
  U+FE0F.
- **A messenger session** (bit 8) may hold bit 19 and send 710 on an
  instant message alone: a line, or a clear, is `NotAllowed`, since it
  is hidden from the lines' readers. Its 712 and 717 are refused, as
  anything outside the friend family is.
- **A clear** needs the `moderate` permission and a line the moderator
  could have read, by an author it may moderate. 710 carries no reason
  and the moderation trail takes no act without one, so the clear is
  recorded with a fixed reason, "Cleared on the classic wire.".
- **Refusals** carry the draft's reason codes in `DATA_CHAT_REASON`:

| Code | When |
|---|---|
| 1 `NoSuchTarget` | A line missing, tombstoned, unreadable, not yet relayed, or kept by nobody; an instant message with a party the reactor may not message |
| 2 `NotAllowed` | A guest, no send-chat, a messenger session on a line, an archived room, a read-only one under `[reactions] read_only_rooms = "deny"`, or a clear from anyone but a moderator or on a protected author's line |
| 3 `InvalidKey` | Not one emoji, past 64 bytes, a server's without bit 20 |
| 4 `TooManyKeys` | The line has `max_keys` keys |
| 5 `TooManyOfYours` | The account holds `max_per_user` on the line |
| 6 `RateLimited` | Past the account's `[reactions] burst` and `per_second` |
| 7 `NoSuchEmoji` | A server emoji added that is not live |
| 12 `InvalidTarget` | A kind this server does not take, or malformed; an instant message without its party, naming neither the reactor nor its party as sender, or cleared |

  An action the draft does not define has no code, and is "Malformed
  request." alone. A success carries the key's count after, for an add
  or a remove on a line, and nothing for a clear or an instant message.
- **Price.** 2 spam points, as a line is. A reaction is not a line and
  never counts toward the chat flood.

## 4. Reaction Changed (711)

- One event the core sends is one 711, with task id 0, its groups in the
  event's order: a line's summary, with the reader's own keys where it
  holds any, a moderator's clear, and an instant message's change. The
  core's batching holds: at most one a room a batch, for the most recent
  lines of each.
- **An instant message's change** is action 1 or 2, the key, and the
  reactor's login in `DATA_FRIEND_LOGIN`, told to the other party's
  sessions with bits 6 and 19 (under an approval, those that understand
  requests) and no one else. For a party with none, the domain keeps it
  as the ng wire does (`hotline-ng.md` §7.3) and tells it after the reply
  to the next Get Roster from a session with bit 19, one 711 a
  conversation; a Get Roster from a session without the bit leaves it
  waiting.
- **A frame's worth.** A 711 past the frame budget, a frame's data less
  room for what precedes the groups, is split between groups, never
  inside one.
- **A summary budget.** A purge owes every room it touched at once, and
  together their summaries could pass what one connection may have
  queued, dropping a reader that was keeping up. So line summaries draw
  on a per-session allowance, a burst of 1 MiB earned back at 256 KiB a
  second; one past it is not sent, the line left to 712 as one outside
  the live window is, and it is counted in
  `hxd_reaction_summaries_skipped_total` (`metrics.md`). Clears and
  instant messages' changes are always sent.
- **A redaction** tells this wire nothing, since it shows no
  redactions; 700 pages the line's tombstone, which carries no
  reactions.

## 5. Get Reactions (712)

- **Targets.** 1 to 50, counted before any is read: more is
  `TooManyTargets`, none `InvalidTarget`, and an instant message, which
  is kept nowhere to be read again, `InvalidTarget`. A key beside more
  than one target is `TooManyTargets` too, a code the draft does not
  name for it.
- **The answer** is a group for each line the session could have read,
  by Send Reaction's read rules, in the order asked and as often as it
  is named: the target, the summary, and the reader's own keys where it
  holds any. A line it could not have read, a tombstone, one that does
  not exist and one nobody keeps are left out alike.
- **Who reacted.** With a key and one target, the group goes on with a
  `FieldUserName` for each account holding the key, newest first and at
  most 100, each the nick it reacted under, cut as a user list cuts one.
  A login is never sent. The names come after the reader's own keys, so
  a client reads a group as running to the next `DATA_TARGET`.
- **A frame's worth.** A reply past the frame budget is refused
  `TooManyTargets`, and the client asks fewer. At the default caps fifty
  targets fit with room to spare; only lines near `max_keys` at its
  ceiling with long keys reach it.
- **Price.** 1 spam point and 1 for each ten targets or part of ten, as
  the draft asks.

## 6. Chat history (700)

To a session with bit 19, a 700 entry carries the line's reactions as
the draft's sub-fields: `0x0021` `REACTIONS`, the summary every reader
shares, and `0x0023` `REACTIONS_MINE`, the keys this reader's account
holds, each left off when empty and in type order beside media's and
Server Emoji's `0x0022`. A tombstone carries neither, and a live 106
never does, since a live line has none yet. This wire's 700 answers the
lobby alone, so a room's lines are read with 712. A reader without bit
19 is paged the same bytes as before.

## 7. Notifications

This server sends none: the Replies draft's Notification (718) is never
sent, for reactions or anything else, on either wire. Set Notifications
(717) is the draft's to answer for bit 19 all the same, and a client
that sent it and heard "Not implemented." would take the server for a
broken one, so to a session with bit 19 it is answered
`DATA_NOTIFY_TYPES` = 0, the types the server will send, and so is a
login that carries `DATA_NOTIFY_TYPES`. It costs 1 spam point.

## 8. Not yet

- Stored private messages as targets, and `DATA_PM_ID` on a private
  message.
- Bit 19 among what the binary offers.
- Reactions across a server link, which the draft leaves on the server
  they were made on.
- The draft's optional notice to a line's author.
