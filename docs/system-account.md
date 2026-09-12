# The system account — where commands live

Status: draft, unimplemented. This document is the rule three others
were each half-stating: `moderation.md` §6 rejected a `/report` chat
command, `private-messages.md` §7 rejected a `/msg <login>` pseudo-user,
and `news.md` §10.11 then required "a real mailbox for the server" that
can be replied to with `stop`. All three were reasoning about the same
thing from different ends. This is the one place it is decided, and
the other three cite it.

---

## 1. The rule

**Public chat is never parsed.** A line typed into the chat box is chat,
on every wire, whatever it starts with. A period client typing `/report`
expects it to be chat, and it is; the closed markdown dialect that
clients may *draw* (`hotline-ng.md` §8) is the only thing chat text ever
means, and the server does not even do that.

**A private message to the system account is a command line.** The
system account is a reserved account that is always on the roster. A
private message addressed to it is not delivered to anyone; it is
parsed, acted on, and answered with one private message back. This is
deliberate on the user's part in a way a chat line is not — they opened
a window to a thing called *Server* and typed at it — and it is the
same shape as the mailing-list `stop` the news document already
accepted: a convention wearing a Hotline private message, which an
unmodified 1.2 client can use because it needs nothing the wire does
not already carry.

**A news body's header block is authored.** `news.md` §12.5's leading
`Subject:` / `Re: #398` lines stand under the same reasoning: an
article is composed, not typed, and the block is documented where an
author will see it.

So the distinction is not "conventions are forbidden on the legacy
wire". It is: the server interprets text only where the user addressed
it *to the server*, and never where they addressed it to the room.

---

## 2. The account

One reserved account, `[system] login` (default `server`), with a
display name `[system] nick` (default `Server`) and an icon
`[system] icon`. It is created on first start like the guest account,
as an account file marked `system = true`.

**Nobody can log into it.** It has no password and `[identity] login =
false`, which `hotline-ng-identity.md` §8.3 describes as "reachable by
nobody" and warns about at startup. For this one account that state is
the intended one, and `system = true` is what tells the startup check
so, rather than the operator having to ignore a warning. Its access
bitmap is empty; it never sends chat, never joins a room, never
transfers a file. Everything it does, it does as the server.

**It is always on the roster**, on both wires: a session created at
startup with the first uid the roster hands out — a real uid, not a
magic number, because `private-messages.md` §6.4 already found that uid
0 goes through the broadcast path on a period client — with `admin`
set, so a 1.x list draws it in red and an ng client can mark it. The
ng `user` object gains `"system": true` for it. It is `protected` in
the moderation sense: kick and ban refuse it. It is not counted toward
`server_full` or toward the user count a tracker is told.

**It is a mailbox.** `Notification.from` in the news document, which is
`None` today because there is nobody to reply to, becomes this
account's mailbox. News notifications, moderation's report lines to
moderators (`moderation.md` §4.5), and any future thing the server has
to say to one person come from it, as private messages with a uid a
client can reply to. That is the reason it exists on the roster at all
rather than as a parser behind a magic address: the legacy wire needs a
uid on a Send Message (104) for a PM window to open, and it needs the
same uid to still be there when the user hits reply.

---

## 3. Commands

A private message to the system account is one command per message.
The first line is the command; further lines belong to the last
argument, so a `/report` can carry a multi-line reason. The command
word is case-insensitive, the leading `/` is optional — `stop` and
`/stop` are the same, since `news.md` §10.11 already promised the bare
word — and anything unrecognised is answered with the help text, never
silence. Arguments that name a person take a **nick on the roster** or
a **login**, in that order of resolution, because a nick is what a
period client's user list shows and a login is what an absent person
has.

| Command | Does | Needs |
|---|---|---|
| `/help` | The list below, in one message | — |
| `/report <who> <reason…>` | Files a report against that user, exactly as the ng `report { user }` request does, with the reason as `evidence`. The reporter gets `ok: report #17 filed` and the moderators get what `moderation.md` §4.5 says they get | the ng `report` rules; one per target per hour |
| `/msg <login> <text…>` | Sends a private message to an account by login, whether or not it holds a session — the ng `msg { to_login }` request. The answer says `sent` or `queued`. This is the addressing mechanism `private-messages.md` §7 declined to invent as a pseudo-user; as a command to the account that already exists it costs nothing it was worried about | `send_msgs` |
| `/block <who>`, `/unblock <who>`, `/blocks` | The three ng block requests | — |
| `/stop [#article]` | Unsubscribes from the news scope of the most recent notification this account sent the user, or from the thread of the named article. `news.md` §10.11 | — |
| `/vouch <who>`, `/unvouch <who>`, `/vouches` | `identity-vouch.md` §3.2, by nick: the roster session's identity fingerprint is what gets vouched for, so a period client can vouch for the person it can see | `[extra] vouch` |

Every command runs **as the session that sent it**, with that session's
access and identity. The system account confers nothing; it is a place
to type, and authorization is whatever the equivalent ng request would
check. A command an ng client could not make, this cannot make either.

**Answers are one private message, one or two lines, plain words**:
`ok: …` or `error: …` followed by what the equivalent ng error code
means in English. Never a wall of text; `/help` is the one exception
and it is under ten lines. An ng client that sends commands here gets
the same answers, and should not: it has requests, and the reply to a
request is structured. The parser exists for wires that have nothing
else.

**Rate.** Ten commands a minute per session; past that, one `error:
slow down` and silence until the minute is up. Report and vouch have
their own limits already.

---

## 4. Queued mail from an absent sender

Optional, and a consequence rather than a requirement.
`private-messages.md` §6.4 delivers queued mail from an absent sender
under the *reader's own* uid, because the wire has no "from someone who
is not here" and uid 0 misrenders. The cost it states is that every
absent sender lands in one window titled after the first, with the
reply box addressed to the reader.

With a system account on the roster there is a second answer: deliver
it from the system account's uid, with the sender's name in NAME as
today. The window is then titled *Server*, which is at least true, the
`[queued …]` stamp says who and when, and the reply box addresses the
server — where `/msg <login> …` now goes to the right person. That is a
reply that reaches someone, which the current shape cannot offer. It is
a per-server setting, `[system] queued_from_system`, off by default
until it has been seen on a real 1.5 client, because the current
behaviour has been.

---

## 5. Settings

| Setting | Default | Meaning |
|---|---|---|
| `[system] login` | `server` | The reserved login. Reserved everywhere a login is reserved: the identity spec's "never one the server gives its own meaning to", the registrar's reserved list, and `new_accounts = create`'s naming |
| `[system] nick` | `Server` | Display name on the roster |
| `[system] icon` | `0` | |
| `[system] commands` | `true` | Parse private messages to it. Off, it is still the notification sender and answers every PM with one line saying commands are off |
| `[system] queued_from_system` | `false` | §4 |
| `[system] rate` | `10` | Commands per minute per session |

---

## 6. Amendments this document needs in its companions

- `moderation.md` §6: the bullet "A `/report` chat command was
  considered and rejected" becomes a pointer here — the objection was
  to *chat*, and it stands; the command is to the system account. §4.5:
  report lines to legacy moderators come from the system account's uid.
- `private-messages.md` §7: the paragraph "Not inventing an addressing
  mechanism for 1.x" becomes a pointer to §3's `/msg`; the sentence
  about `Find User (822)` being the right answer for capable clients
  stays, since it is. §6.4: the option of §4 here.
- `news.md` §10.11: "a real mailbox for the server" is §2 here; the
  reply parser is §3's `/stop`.
- `hotline-ng-identity.md` §8.1 and §8.3: `system = true` is the
  legitimate form of the reachable-by-nobody state; the startup warning
  skips it. §12's account-file table gains the flag.
- `hotline-ng.md` §7: `"system": true` on the `user` object; the roster
  snapshot always contains it.
- `identity-registrar.md` §5.2: the built-in reserved list already has
  `server`; it gains whatever `[system] login` is set to.
- `access-bits.md` §5: the `system` flag beside `[identity]`'s.

---

## 7. Open questions

- **Should the system account be hidden from the ng roster** and
  surfaced as a first-class "server" affordance instead? An ng client
  has no need of a fake user row; it has requests. But hiding it makes
  the two rosters differ, which `hotline-ng.md` §2 promised they never
  would. Kept visible with `system: true` so a client that wants to
  draw it differently can.
- **Whether `/report` should accept a line.** The legacy wire has
  history ids only through 700, and a period client cannot copy one.
  `/report <who>` is what a 1.5 user can actually do; a line target is
  an ng request.
- **A 1.5 client that already has a user named `Server`** on a server
  migrated from mhxd. Reserved-name collision handling
  (`hotline-ng-identity.md` §9) applies; the operator renames one.
