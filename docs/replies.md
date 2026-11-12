# Replies on the classic wire

Status: built for lines of chat, private messages and instant
messages: `DATA_REPLY_TO` on Send Chat (105) in the lobby, a room and a
private chat, relayed on Chat Message (106) and paged on Get Chat
History (700) as the entry's sub-field, 700 by line id for the lines a
page's replies answer, on Send Instant Msg (108) relayed on Server
Message (104), and on IM Send (810) relayed on IM Deliver (811), and a
stored private message's reference to a session that negotiated the
bit. This
binds nobody but this server: the protocol is the Replies draft
(`Capabilities-Replies.md`, a draft written for this server, in
fogWraith's protocol documents and not yet allocated), with the line ids
and reply shape it takes from Structured Chat.

The ng wire's replies are `hotline-ng.md` §7.3. Both wires carry one
reference the core keeps (`hxd_core::reply`): a reply made on either is
heard on both. What this document covers is `hxd_session::replies` and
the choices the draft left to it.

## 1. Negotiation

- **Bit 18** is offered wherever `[structured_chat]` is enabled, and
  needs no key of its own. It is confirmed only beside bits 1 (Text
  Encoding) and 17 (Structured Chat), as the draft requires. A link's
  login never holds it.
- **The login reply** beside it carries `DATA_REPLY_TARGETS`: kept lines
  (`0x0002`, kind 1) where there is `[history]`, lines nobody keeps
  (`0x0010`, kind 4) always, instant messages (`0x0004`, kind 2) to
  a session that negotiated the friend family's bit 6, and private
  messages (`0x0020`, kind 5) where there is `[inbox]`. The targets are
  fixed for the session as it was told them, and a session is sent no
  reference of a kind they leave out.
- **A session without bit 18**, a period client and one with bit 17 or
  19 alone included, is sent exactly what it was, and a `DATA_REPLY_TO`
  it sends is ignored. The draft's `Replies.ClassicForm` is `none` here
  and is not a setting: the server never looks a target up, so no
  formatted line or 104 is ever decorated.

## 2. Targets

- **A lobby line** is kind 1 on channel 0, by its history id.
- **A line nobody keeps** is kind 4 under its chat's id, by the id that
  chat counted it under (`chat-history.md` §12): the lobby's notices, and
  its lines on a server without `[history]`, on chat 0; a private chat's
  under its chat id.
- **A room** shows on this wire as a private chat under its id, so its
  line is kind 4 under that id: the room's kept line where there is
  `[history]`, and one nobody keeps where there is not. Kind 1 on a
  room's 105 is dropped, as the draft's table has it, since this wire's
  700 answers no room for a kind 1 to name; reactions take it
  (`reactions.md` §2).
- **Two id spaces under one chat id.** A room's notices and its kept
  lines are both kind 4 under the room's id, and a reference to a notice
  is kept as one to the room's line of that id. Nothing is looked up, so
  nothing collides: the reply names no line, and is drawn as its text
  alone.
- **An instant message** is kind 2, by its sender's login and its guid,
  and names a message of the conversation it is said in: its login is
  the sending account's or the 810's `DATA_FRIEND_LOGIN`, either in any
  case, and is kept as sent.
- **A private message** is kind 5, by the reference it was stored
  under (§5), whoever's message it is: its reader resolves it from its
  own mail, where another pair's resolves to nothing. Only a stored
  message has a reference, so one whose stored flag is clear is
  dropped; the draft's references for messages the server does not
  store are not built, on this wire or ng.
- **Never resolved.** A target retired, redacted, never relayed or
  never seen by its reader is kept and relayed as sent. A kept lobby line
  answering a notice is stored with its kind 4 reference, which a server
  older than this one cannot read back: a downgrade answers every page
  holding such a line "Server error.".

## 3. What is dropped

105 has no reply to refuse a line with, so a reference the draft does
not allow is dropped and the line relayed without it, and 108 and 810
drop one alike, as the draft has every transaction do: one from a sender without
bit 18, of a kind the login did not offer (kind 3 among them), of a
kind a line or a message does not take, malformed, past 128 bytes,
naming line id 0, a private message not stored, two in one request,
and one naming a chat
other than the one the line is said in, or an instant message of
neither party's. Those last two are the core's own rules
(`Reply::in_room`, `Reply::between`), which it also holds every
frontend's line and message to, refusing the whole of it; the
parse here asks them first, so the classic wire never loses a line or a
message to them.

## 4. Relay and history

- **106.** To a reader with bit 18, a reply's entry carries sub-field
  `0x0020` `REPLY_TO`, the target as this wire names it, after media's
  and before anything later, the sender's echo included. A reply from ng
  is heard here as kind 1 for the lobby and kind 4 under a room's id.
- **104.** To a session with bit 18, a private message's reply carries
  `DATA_REPLY_TO`, live and when it waited, beside the reply's own
  `DATA_PM_ID` where the reply was stored. A reply
  from ng is heard here as kind 5, or kind 2 for one naming an instant
  message.
- **811.** To a session with bit 18, an instant message's reply carries
  `DATA_REPLY_TO`, live and when it waited for Get Roster. A reply from
  ng is heard here as kind 2, or kind 5 for one naming a private
  message, which 810 cannot send.
- **Only what a reader was offered.** A 106, 104 or 811 carries a
  reference only of a kind its reader's login listed, so a session without bit 6
  is never sent an instant message's, which it could not resolve.
- **The ng wire** hears a classic reply as `re`, `{ "line" }`,
  `{ "line", "room" }`, `{ "im" }` or `{ "pm" }`; one naming a line
  nobody keeps has no form there, and is heard as its text alone.
- **700.** To a reader with bit 18, a line's entry carries the same
  sub-field, in type order after media's and before the Reactions
  draft's `0x0021`. A tombstone carries none: a redaction takes a reply's
  target with its words, while a reply to a redacted line keeps its own.
  A reader without the bit is paged the same bytes as before.
- **700 by id.** A session with bits 4 and 18 may ask for at most 50
  lines by `DATA_LINE_ID` (`0x0f20`) in place of the cursors, which
  beside them are ignored, so that it can draw a page's quotes in one
  request. `DATA_CHANNEL_ID` is still required and 0, a room's chat id
  being "No such channel." as for a page. The answer is the lobby's lines
  among the ids, ascending, each entry built as a page builds it, an id
  asked twice answered once: another room's line, whether the reader may
  read it or not, and one that does not exist are left out alike, and a
  tombstone is sent as one. Where they overrun one frame the highest ids
  are left out and `DATA_HISTORY_HAS_MORE` is 1, for the client to ask
  again for those past the last it was handed. More than 50 ids, or one
  not 8 bytes, is "Malformed chat history request.". It costs no spam
  points and is held to the history rate, as a page is. A session
  without bit 18 is paged, its `DATA_LINE_ID` a field it does not know.
- **700's refusals.** The draft makes 700 by line id one of the
  Structured Chat family's requests, and this server refuses any 700
  from a session with bit 18 in the family's reply shape, since it
  cannot tell what was asked before it refuses for permission or rate:
  the text unchanged and `DATA_CHAT_REASON` beside it: `NotAllowed` (2)
  without bit 56,
  `RateLimited` (6) past the history rate, `InvalidTarget` (12) for an
  id not 8 bytes and `TooManyTargets` (13) for more than 50. A request
  malformed in its channel or cursors, a channel that is not 0, a
  session without bit 4, and the server's own failures have no code of
  the family's that describes them, and carry none. Bit 17 alone sends
  no request of the family's, so every other session, bit 17's too, is
  refused with the text alone, the bytes it always was.

## 5. Private messages' references

A stored private message's reference reaches a session with bit 18, as
one with the Reactions draft's bit 19 (`reactions.md` §2): as
`DATA_PM_ID` on the 104 that hands the message over and on the reply to
the 108 that sent it. The reactions a message gathered while it waited
are told after its 104 only to a session with bit 19. A 108 with bit 18
may carry `DATA_REPLY_TO` naming one as kind 5: the flag, which must
say stored, then the same 16 bytes, which the ng wire spells as its
`pm` target.

## 6. Notifications

This server sends no Notification (718). Set Notifications (717) is the
draft's to answer for bit 18 or 19, so to a session with either it is
answered `DATA_NOTIFY_TYPES` = 0, and so is a login that carries
`DATA_NOTIFY_TYPES`, whether or not the server keeps reactions; a
messenger session (bit 8) is refused it, as anything outside the friend
family. It costs 1 spam point.

## 7. Server links

No reference crosses a link (`server-link.md`): a classic reply to a
ghost's lobby line is kept and relayed here, and heard at the line's
home as its text alone. A private message to or from a ghost is never
stored, so it has no `DATA_PM_ID` and cannot be named, and a reply's
108 to a ghost is heard there as its text alone.

## 8. Not yet

- The draft's notification to a line's author.
- References for private messages the server does not store.
