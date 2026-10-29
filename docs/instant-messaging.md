# Instant messaging

Status: design; the store (IM1, §8) is built. hxd-ng's implementation of fogWraith's
[Capabilities-Messaging.md](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Messaging.md)
("the extension"), built on the inbox (`private-messages.md`), with
message requests (§4) added. Friendships that travel with a person's
identity from server to server are proposed separately, in
`proposals/portable-friends.md` on the objects of
`proposals/friendship-objects.md`; nothing here depends on them.

---

## 1. Summary

The extension is a messenger beside Hotline's chat: a roster of friends
made by request and response, presence summed across a Login's
sessions, instant messages with receipts and typing, discovery, and an
offline queue. hxd-ng already has most of the machinery under it, built
for the inbox and the identity work (§2), so the work is a friend graph,
presence and profiles as a subsystem of their own, and the two wires
for it.

One thing is added. The extension refuses an instant message to anyone
who is not a friend (`NotFriends`). Here, a message from someone with an
account who is not a friend and is not blocked goes to the recipient's
**message requests** instead, held until the recipient approves the
conversation, makes the sender a friend, or deletes it (§4). The friend
request's note (`DATA_REQUEST_NOTE`) is the extension's one message
before friendship; a request is the same idea, without having to ask
for friendship first.

---

## 2. Where this sits

| The extension's | hxd-ng's | Gap |
|---|---|---|
| Offline queue, `OfflineQueued` | the inbox (`private-messages.md`), `queued: true` | `delivered_at` stamped at the 812 ack where there is one (§5); the friendship, approval or request a row came on |
| `DATA_MESSAGE_GUID`, dedup | the `guid` column (`private-messages.md` §5) | none |
| Read receipts held for the sender | the `kind` column (`private-messages.md` §5) | a wire to carry them |
| Blocks | the block list, keyed by mailbox (`private-messages.md` §9) | moved into the relationship store (§3), with the alias a row keeps and a `Blocked` row's count toward `MaxRosterSize` |
| Login to sessions | the roster's sessions per account | presence summed across them |
| Mailbox keyed by fingerprint, strict matching | `Mailbox` (`private-messages.md` §4) | relationships keyed the same way |
| `AccessMessaging` (58) | reserved in `access.rs`; roles can grant it | the gate |
| Calls | the SFU and its rooms | a guest list per call room |
| Signed and sealed messages | `e2e-messages.md`, `hl-identity` | the 810/811 binding |
| Notifications | the notify seam (`private-messages.md` §10) and its gateways | IMs through it (§5) |

---

## 3. Relationships

Blocks, friendships, approvals, holds and pending requests are one
system, kept in one **relationship store**: a `RelationshipStore` trait
in `hxd-core`, an in-memory store beside it and one in
`hxd-store-sqlite`, under one conformance suite, as the inbox's stores
are.

**A relationship is directed**: a row for an `(owner, other)` pair,
each keyed as the inbox keys a mailbox (`private-messages.md` §4), by
fingerprint where the account has an identity and by Login otherwise,
matched strictly, so a relationship is rename-proof where the account
has an identity. A row holds what its owner has decided about the other,
each part on its own:

- **an alias** (`DATA_FRIEND_NICKNAME`), for an accepted or a
  `Blocked` entry;
- **blocked**;
- **approval granted** (§4.6);
- **holding** the other's requests, and until when (§4.4);
- **ignoring** the other, in a mode, and until when (§10);
- **pending out**: a friend request sent and not yet answered, when it
  was sent, and whether it was delivered (§4.4).

Each side's state is its own, so a mutual block, or one side unblocking
while the other still blocks, needs nothing special: two rows, each
blocked or not. The extension's `PendingIn` is the other row's pending
out, read from the owner's side, where it was delivered: a held or
dropped request is a pending out its target never sees. An 802 that
meets the other side's pending out accepts both, whether or not that
pending out was delivered, since the caller has asked for the same
friendship, so the answer says nothing of whether the earlier request
was held; an 802 carrying an offer aside
(`proposals/portable-friends.md` §4.1), which waits for an acceptance.

**A friendship is a fact about the pair**, not either row: made when a
friend request is accepted, ended by either side's removal or block,
with an id never reused that both rows point to and that the queued
messages sent on it carry (§5). An approval has an id of its own in the
same sense. The extension's roster states are read from the two rows
and the pair: `Accepted` where there is a friendship, `Blocked` where
the owner's row is, `PendingOut` from the owner's pending out and
`PendingIn` from the other's delivered one. An **edge**, where this
document and `proposals/portable-friends.md` say so, is a friendship.

**The inbox's block list moves into the store**, with
`private-messages.md` §9's behavior unchanged: a block is checked
before anything is written, applies to every way of addressing an
account, and is what the inbox's `set_blocked`, `is_blocked` and
`blocked` (`MessageStore`) answered before it moved. The ng `block`, `unblock` and
`blocks` are Block User (806), Unblock User (807) and the `Blocked` rows
of Get Roster under the ng spelling, with the same effects, so a block
ends a friendship or an approval on either wire, on this server; it
ends a portable friendship elsewhere only where the blocker's client
sends a withdrawal (`proposals/portable-friends.md` §4.3). A ghost's
block stays where it is: `Core::block_ghost` keeps it on the blocking
session for that session's life (`server-link.md` §11), since a ghost
has no account here to key a row by.

Everything the extension says about an accepted entry (presence, what
non-friends see, Invisible, typing, receipts, the offline queue's
bounds) holds as written. The Login stays the address on the wire.

**Expiry is lazy.** Whatever lapses (an ignore, a hold, a friend
request, a request, a queued message past retention) is stored with
when it lapses, and is found lapsed when it is next read: the read
compares that time with the core's clock and answers as if the lapsed
part were gone, and the cleanup below deletes it. A lapse is announced to nobody. A client
sees a lapsed friend request gone at its next roster read, and an act
on one, 805 or 803, is answered `NotFriends` (ng `not_friends`), as on
a request its sender withdrew. Counts against a
bound (§4.4) count only the rows that have not lapsed, by an indexed
time, so nothing has to have been swept for a bound to be right. A row
nobody reads again costs only its storage until the **cleanup**, a task
of its own, off every request's path, deletes what lapsed a while ago,
and ledger rows past every window that counts them, in small batches so
that it never holds the store for long. Since a lapsed row already reads
as gone, the cleanup changes no answer and tells nobody anything: it is
reclaiming space, never deciding, and nothing waits on it.

---

## 4. Message requests

### 4.1 What becomes a request

Requests exist only where `[messaging] enabled` is on, between two
accounts that both hold `AccessMessaging` (`admin` and `guest` are
treated as lacking it whatever their bits, as the extension requires),
a classic sender aside (below), and both **take requests**. A recipient
account takes requests unless it has turned them off in its profile, as
it turns off `discoverable`, or no client of it has ever listed them
(§4.5). A sender takes them per session: only a session that has listed
requests sends one, so a session that never has, though another of its
account's has, is answered as the extension answers it today, is never
sent `Requested`, and never approves a request by replying (§4.3). So a
user whose clients have never shown requests is never sent one, and a
client that has never shown them is told nothing it could not read, a
classic sender aside (below).

A message to a non-friend is then answered, in this order:

0. **No such account**, or one that messaging refuses: as Find User
   answers it, `AccountNotFound` (ng `no_such_user`), so that the next
   step's answer sets a blocker apart from nothing, and counted toward
   the rate Find User is held to.
1. **The recipient has blocked the sender**: as Find User answers it,
   `AccountNotFound` (ng `no_such_user`), before any bound is checked,
   so a block reads as a missing account on every request that names
   one by Login or fingerprint, 802, 810, 822, 825 and an `ignore` by
   login among them. 806, 807 and an `ignore` by uid against someone who
   has blocked the caller are answered as usual, since they change only
   the caller's own row, and 806 and 807 to a Login nobody holds are
   answered as usual too, so that their answer never sets a blocker
   apart from a missing account. A block also deletes the blocker's
   own requests to the blocked account and its pending out, so that the
   blocked account never answers one and meets the block.
2. **The sender has blocked the recipient**, or either side has turned
   requests off or never listed them: `NotFriends`, as the extension has
   it. It tells the sender only about its own block or about a setting.
3. **Otherwise**: a **request**, answered `Requested` (§4.2), and
   stored, held or dropped by the bounds (§4.4).

An account that once listed requests but has not within
`request_retention_days` is **lapsed**: it is still answered as taking
requests, and the request is dropped, answered and counted as one that
was stored (§4.4). Answering it `NotFriends` instead would tell a
stranger when its user last used a client that shows requests.

A request is not delivered as an IM Deliver (811), raises no badge and
no push (§5), and does not count toward the recipient's queue. The
recipient's sessions that have listed requests are told only that the
number of requests changed.

**Which messages.** On the ng wire, a `msg` by `to_login` to an account
holding `AccessMessaging`: to a friend, or under an approval, it is an
instant message, and to anyone else it follows the order above, which
answers `private-messages.md` §12's question of what account addressing
becomes beside a friend graph. This changes what an ng `to_login` is
answered once messaging is on, deliberately (§8). An ng sender without
`AccessMessaging` is answered as for a recipient taking no requests. A
request carries text alone: a `msg` with `media` that would become one
is refused `not_friends`, so a stranger's first contact is never an
image. A sealed message (`DATA_MESSAGE_SEALED`, ng `sealed`) to anyone
but a friend is refused `NotFriends` (ng `not_friends`), so neither a
request nor an approved message is ever sealed, whatever certificate
an offer has handed over, and every one can be reported (§4.5). A reply
that would approve (§4.3) past the replier's `MaxRosterSize` is refused
`RosterFull` (ng `roster_full`) and not stored.

The classic `/msg <login>` (`system-account.md` §3) is the same call,
`Core::msg_login`, and follows the same rule, under the same holds and
bounds. Its sender is a classic session, which can never list requests,
and is exempt from having to, and from holding `AccessMessaging`, so a
guest or an account without the bit makes a request as anyone does.
Guests share one account, so a guest sender is bounded and held by its
address rather than its account, at the per-sender values, so that
reconnecting earns it nothing, and an approval of one is kept on that
session for its life, as a ghost's block is (§3), so that it lets in
no other guest. The recipient's answer, which approves the conversation
(§4.3), reaches the sender as an ordinary private message, which a 1.5
client shows, through the inbox's flush if it has gone
(`private-messages.md` §6.3), as all of an approval's traffic does for
a party that cannot list requests (§4.6). Refusing it `NotFriends`, for
want of listing or of the bit, would cut 1.5 users off from messaging
accounts they could write to before,
and letting it bypass requests would let any classic session skip the
holds and bounds. `/block` and `/unblock` are the relationship store's
block (§3).

A `to_login` to an account without `AccessMessaging`, a `msg` to a uid
on the roster, and a classic private message (108) to a user on the
list stay as they are: they reach someone present, or an account outside
messaging, as before, keep `private-messages.md` §11's named `blocked`,
and a uid `msg` to a detached session still goes to its inbox. A bit-8
messenger session (§7) is on neither user list, so neither 108 nor a uid
`msg` can name it. On the classic wire, an IM Send (810) to a non-friend
is refused `NotFriends` whatever the recipient takes until fogWraith
gives `Requested` a number (§7), and only then makes requests.

### 4.2 What the sender sees

`Requested`, a new reason code on a successful 810 (§7); on the ng
wire, always `{ "queued": true, "requested": true }`, with no `id`. The
same answer whether the request was stored, held after a delete or a
removal, or dropped by a full box or a lapsed recipient, and whether the
recipient is online, has looked, or never will. A sender with a request
waiting gets no receipts, no typing and no presence from the recipient.
The server enforces that, not the recipient's client: it drops 812 and
813, and their ng counterparts, between two accounts with no live
friendship or approval, and `msg_read`'s `up_to` skips rows its gate
holds, so a read cursor never turns into a `Read` for a request.

### 4.3 What the recipient does

For each sender, the recipient may:

- **Approve the conversation** (§4.6). The waiting messages are
  delivered as IMs. Replying to a sender whose request is waiting
  approves it too: writing back is consent to the conversation.
- **Add the sender as a friend.** Add Friend (802), as usual. The
  request stays listed, and its messages with it, until the sender
  accepts, when they are delivered; if the sender declines, the request
  is as it was.
- **Delete the request.** Its messages are deleted, the sender is told
  nothing, and the sender is held (§4.4).
- **Block the sender.** Block User (806), as usual, which deletes the
  request too.

Declining a friend request (805, or 803 on a pending one) holds its
sender as a delete does, an offer on an existing friendship aside
(§4.4).

**Clearing them in bulk.** One act declines every friend request and
deletes every message request received in a span of time, `since` to
`before`, each optional, so that a recipient who has been flooded can
clear the flood and keep what came before it, or clear everything. A
message request is in the span by its first waiting message, so a
flood's opener decides. Each sender is held, and told, as one decline
or delete would hold and tell it (§4.4). Approvals and friendships are
untouched. It is one transaction of the store, answered with how many
of each it cleared, and the recipient's sessions hear it once:
`requests_changed`, and a `Removed` 801 (and its ng counterpart) for
each friend request, which `max_friend_requests` keeps to a bounded
burst.

### 4.4 Bounds

Requests are the one way a stranger can put something in front of a
user, with Add Friend's note (`DATA_REQUEST_NOTE`) the other, so both
are bounded more tightly than the inbox. Every bound counts what the
sender *sent*, kept in a **ledger** of
`(sender, recipient, guid, bytes, time)` written for every request
whatever becomes of it, stored, held or dropped, so that what the
recipient did never changes what the sender is told. Nor does it change
how long the server took to tell it: the reply goes once the ledger row
is written, and the message row, `requests_changed` and any lazy delete
(§3) follow it, off its path.

- **Per sender and recipient**: at most `request_messages` requests sent
  to one recipient within `request_retention_days`. Past it the sender
  is refused `QueueFull` (ng `request_full`).
- **Per sender**: at most `requests_per_day` distinct recipients in a
  rolling day, refused `RateLimited` (ng `quota_exceeded`). Requests
  count toward the inbox's daily quota (`private-messages.md` §9) from
  the ledger, by what was sent, not from the rows that survive.
- **Per address**: `[limits] requests_per_address`, a looser ceiling on
  the distinct recipients requested from one address in a rolling day,
  so that new accounts are not new budgets, and loose because
  carrier-grade NAT puts many people behind one address. It is counted
  against the address of the connection the request arrived on, as
  `[ng] trusted_proxies` give it, an IPv6 address as its /64, and
  `[limits] exempt` is held to none of it, as for a login's attempts.
- **Held senders**: after the recipient deletes a sender's request,
  declines its friend request, removes it as a friend (803) or ends its
  approval, that sender's requests to the recipient are held for
  `request_retention_days`: answered `Requested`, counted in the ledger,
  and stored nowhere. Removing someone stops them contacting you, which
  is the extension's reason for mutual removal. A hold is recorded
  against both keys of the mailbox it was placed on, Login and
  fingerprint, so that linking or unlinking an identity does not shed
  it.
- **Per recipient**: at most `max_requests` senders waiting. Past it a
  new request is dropped, answered and counted the same, so that a
  burst of new accounts cannot flush out the requests the recipient
  already has. The listing says how many were dropped (§4.5).
- **Retention**: a request not acted on is deleted after
  `request_retention_days`.

**Friend requests** (802) share the per-sender and per-address bounds
and the hold, and have bounds of their own:

- **Per recipient**: at most `max_friend_requests` delivered and
  waiting. Past it a new one is dropped, as a held sender's is below,
  and counted in the listing's dropped (§4.5).
- **Not in the recipient's roster**: a `PendingIn` counts toward the
  sender's `MaxRosterSize` alone, so that strangers cannot fill a
  roster and leave its owner unable to add a friend.
- **Expiry**: a friend request not answered within
  `request_retention_days` lapses, as if withdrawn, without a hold or a
  notice (§3).
- **Accepting at the cap**: since a `PendingIn` takes no place, an 805
  that accepts at the recipient's `MaxRosterSize` is refused
  `RosterFull`, and the request stays as it was.

A held or dropped sender's 802 is answered as any is and recorded on its
own row as a pending out not delivered (§3): the recipient is sent no
804, never reads it as `PendingIn`, and its note goes nowhere. A repeat
is answered `RequestPending`, as one delivered would be, so the sender
cannot tell.

An 802 carrying an offer on an existing friendship
(`proposals/portable-friends.md` §4.1) asks for nothing new, so it is
outside these bounds, the ledger and the hold, and its decline or lapse
touches only the offer.

**A retry** under a `guid` already in the ledger is answered from the
ledger as its original was, never from message rows, and is not counted
again, so a retry tells the sender nothing a deleted, held or dropped
request would not.

### 4.5 Listing them

The recipient lists requests by sender, oldest first, each sender with
its fingerprint where its link is shown (the identity draft) or one of
its messages is signed, whose certificate names it anyway,
and each message with its inbox id, so that a request can be reported as
any message is (`moderation.md` §4.2); the report path reads a request
row for its recipient alone, past the gate of §5. The listing also gives
the approvals, and how many requests were dropped since the last
listing. Listing is what marks a client as able to show requests
(§4.1), and a session as one to send approvals and `requests_changed`
to (§4.6), so a client that shows requests lists them once after each
login.

### 4.6 Approvals

An **approval** is a recipient's permission for one non-friend to
message them: the owner's row, granted (§3), with an id. It counts
toward the approver's `MaxRosterSize` alone, and past it the approver is
refused `RosterFull`. It is not a roster entry and is never reported in
800 or 801: it is listed with the requests (§4.5).

Messages pass both ways, but an approval shows less than a friendship:

- **Every send is answered as queued** (`OfflineQueued`, ng
  `queued: true`), retries included, whether or not a live session took
  it, and `Delivered` receipts are not forwarded. Read receipts are,
  since a read is a person's act, and typing is not sent. An approved
  stranger learns no more of when the recipient is around than the
  replies and the read receipts say.
- **No presence, profile or capabilities**, which stay the friends' (the
  extension's discovery rules).
- **Signed, not sealed.** A sealed send to a non-friend is refused
  (§4.1), so an approved conversation can be signed but not sealed.
- **Only to sessions that list requests.** Its 811, 812 and 813 go to
  each party's sessions that have listed requests, and wait for one
  otherwise, since a client that does not know approvals has no row to
  show them under. A party none of whose sessions can list them, a
  classic sender's (§4.1), is sent the messages as ordinary private
  messages through the inbox instead, and no receipts.

On the classic wire an approved conversation over 810 waits for the
numbers of §7, as requests do; until then it is the ng wire's.

The approver ends one through the requests operations (§7), which holds
the sender as a delete does (§4.4). Either party's Block User (806) ends
it, and so does a friendship between the pair, which then takes the
approval's queued messages. Remove Friend (803) does not name an
approval: it names a roster row, and the sender has none.

---

## 5. Queued messages

**A queued instant message is delivered only while the friendship or
approval it was sent on is live**, and is held undelivered, then pruned
by retention, once it is not. The extension's reason for mutual removal
is that removing someone has to stop them contacting you, and a message
queued before the removal and waiting for the remover's next login would
still reach them. Gating at delivery rather than purging at removal
leaves the store to retention. Pending read receipts between the two are
gated the same way.

Each IM Send row in the inbox carries the id of the friendship or
approval it was sent on, or marks it a request. The gate holds a row
where no live friendship or approval has its id, or where the recipient
ignores its sender in `messages` or `all` mode (§10), an ignore that has
not lapsed; a private message, which has no friendship id, is held by
the second alone. A friendship made again has
a new id, so what was queued on the old one stays held; a friendship or
approval suspended and restored (§6) keeps its id, so a suspension
holds its rows and its restoration releases them. A request's rows take
the id of whatever approval or friendship releases them.

**The gate is the store's**, on every read and every hand-over, so no
caller can forget it: `pending`, `list`, the counts and badges, the ng
`inbox` pull, `find_guid`'s hand-over of a retry to an attached
recipient (`private-messages.md` §5), `is_pending`, the re-check flush
(§6.2 there), the flushes at login, resume and sync, and the notify
seam (§10 there). A held row, or a request's, does not count toward the
recipient's queue cap, so that a removed friend's backlog, or a
stranger's, cannot fill the recipient's mailbox. Held rows are bounded
per sender and recipient at `max_offline` instead, a send past it
answered as a full queue would be. The one read past the
gate is a report, by the row's recipient (§4.5).

**A release is a drain, never a push of the backlog.** An ignore
lifted, an approval granted, a friendship made, activated or restored
can release thousands of held rows at once, and pushing them would take
a session past its live queue's bound and drop it as a slow consumer.
The rows become pending, oldest first, as far as the recipient's queue
cap has room, the rest staying held until it has, and go as any pending
row of their kind does: IM rows at the next drain below, approval rows
the same to sessions that have listed requests, and private messages by
the inbox's flush (`private-messages.md` §6.3). A release to an
attached recipient drains it then, rather than at its next 800, so that
what was held arrives ahead of what is sent after. Each is capped at
`deliver_at_flush`, the rest pulled or waiting for the next.

**Delivery.** In hxd-ng the inbox also holds classic private messages
and ng `msg`s to a uid (`private-messages.md` §3), which are not gated
by friendship. IM Send rows are drained at Get Roster (800), as the
extension's reference server drains its offline queue (its
Implementation Notes), and on the ng wire at the friend family's roster
request, rather than with the rest of the inbox at login
(`private-messages.md` §6.3). A session that negotiated neither bit 6
nor the ng friend family never sends either, so it is handed a friend's
IMs as private messages: live as `private-messages.md` §6.1 hands a
stored message to an attached session, and at the login flush for those
still waiting, a 1.5 client with the `[queued …]` stamp (§7 there).
Approval rows go that way only to a party none of whose sessions can
list requests (§4.6). Every drain is capped by
`deliver_at_flush`, as the login flush is, the rest pulled or waiting
for the next. A request's rows are never drained.

**`delivered_at`** is stamped at the 812 ack from a session that can
send one, and at the handover for a session that cannot. A row handed
to a bit-6 session that never acks counts as delivered toward the queue
cap, so a client that does not ack does not fill its own mailbox, and is
handed over again at its next Get Roster, within `deliver_at_flush`,
until it is acked or retention takes it. An ng IM sent without a `guid`
is given one by the server, since 811 requires `DATA_MESSAGE_GUID`.

**Push.** IMs from a friend or under an approval go through the notify
seam as private messages do (`private-messages.md` §10), under
`push-notifications.md` §6's rules on when a push happens and what it
may contain. Invisible still pushes: it hides the user from others, not
from their own devices. Busy suppresses the push, which is what
do-not-disturb means. Requests never push (§4.1); a user who wants to
hear of one looks.

---

## 6. Linking, renaming, deletion

The inbox's obligations (`private-messages.md` §4) extend to the
relationship store, through the same calls:

- **Linking** (`Core::inbox_claim`) stamps the account's relationships
  with its new fingerprint, as it stamps its mail: its rows and the
  rows naming it, friendships, approvals, holds, pending requests and
  the ledger (§4.4) alike, so that a held sender who links an identity
  starts from where it was.
- **Unlinking** owes nothing, as for mail: friendships keyed by the
  identity leave with it, and the friends are told `Removed`. A hold
  survives it, being recorded under both keys (§4.4).
- **Rotation** (`Core::rotate_identity`) re-stamps the same set to the
  successor.
- **Renaming.** hxd-ng has no rename in the server; an operator renames
  a Login-keyed account by moving its file, which is a deletion and a
  new account, and does `hxd inbox purge` on the old Login so that its
  next holder inherits nobody's relationships. A fingerprint-keyed
  account keeps them through a rename, and its friends are told as the
  identity draft has it: under bit 13 its entry in place, otherwise
  `Removed` and a new entry. The purge of the old Login is owed for it
  too, since a hold also matches by Login (§4.4).
- **Deletion** (`Core::inbox_purge`) deletes the account's
  relationships in both directions: its rows, the rows naming it,
  friendships and approvals either way, the requests it sent and those
  waiting for it, and its ledger entries, telling its friends `Removed`;
  a portable friendship's withdrawals are kept
  (`proposals/portable-friends.md` §4.4).
  The running server's delete (`Core::account_delete`) does not call it
  today; IM2 makes it, so that a freed Login inherits nobody's friends.
  `hxd inbox purge`, run while the server is stopped, cannot tell
  anyone, and the friends learn at their next Get Roster.
- **Revoking `AccessMessaging`** suspends the account's friendships and
  approvals, and holds its waiting requests either way, unlisted, rather
  than deleting them, a deliberate deviation (§8). Under roles, one
  mistaken role edit and a reload would erase the friendships of
  everyone holding the role, which a person cannot rebuild from their
  side. A suspension tells the account's friends `Removed`, so a live
  client does not show a friend it cannot reach, and restoration sends
  the entry again; a suspended friendship is not live, so the messages
  queued on it are held (§5), which is everything the extension's reason
  for deletion requires.

---

## 7. The wires

**The classic wire**: capability bits 6 and 8 (bit 6 only for accounts
with bit 58), transactions 800–813 and 822–826, the limits fields, bit
8's hiding from 300/301/302 and from the ng roster, and the identity
draft's fields. Message requests add transactions from the extension's
unallocated 829–839:

- **Get Message Requests**, `DATA_REQUEST_CURSOR` optional, answered
  first with `DATA_REQUEST_COUNT`, the requests dropped since the last
  listing, and `DATA_REQUEST_CURSOR` where there is more, before any
  group, as a reason code precedes entries, since everything after a
  `DATA_FRIEND_LOGIN` belongs to its group; then groups delimited by
  `DATA_FRIEND_LOGIN`, each the sender's `DATA_FRIEND_IDENTITY` where
  §4.5 shows it and its messages, each message delimited by its
  `DATA_MESSAGE_GUID`, which with the sender names it for a report, and
  carrying `DATA_MESSAGE_BODY`, `DATA_MESSAGE_TIMESTAMP` and, where it was
  signed, the identity draft's `DATA_MESSAGE_SIGNED`; then approvals as
  groups with no messages and `DATA_ROSTER_STATE` `Accepted`; a page
  bounded to fit the frame limit;
- **Answer Message Request**, `DATA_FRIEND_LOGIN` and
  `DATA_REQUEST_ACTION`: approve, delete, or end an approval;
- **Clear Message Requests** (§4.3), `DATA_SPAN_SINCE` and
  `DATA_SPAN_BEFORE` each optional, answered with `DATA_REQUEST_COUNT`,
  the message requests deleted, and `DATA_FRIEND_REQUEST_COUNT`, the
  friend requests declined;
- **Message Requests Changed**, a push carrying `DATA_REQUEST_COUNT`,
  the senders waiting, sent only to sessions that have listed requests.

A period client clears its requests as `/requests clear
[newer|older <duration>]` to the system account (`system-account.md`),
everything if no span is given.

Until the numbers are given, a classic 810 to a non-friend is refused
`NotFriends` and requests exist on the ng wire alone (§4.1), apart from
`/msg <login>`, which needs no number.

**A client learns that a server takes requests** from the login reply,
as it learns buddy icons: a server that confirms `CAPABILITY_MESSAGING`
and takes requests advertises its message bound beside the extension's
limits (its Server Limits Advertisement), and one that sends no
`DATA_MAX_REQUEST_MESSAGES` takes none, so a client offers no requests
view and expects `NotFriends`.

**The numbers asked of fogWraith**, for this document and
`proposals/portable-friends.md` together, sent as one request (§8), so
that the two ask for adjacent ranges once. The fields overflow the
extension's free messaging block, `0x062C`–`0x062F`, so he places them;
portable friends' fields are specified in its §7. The identity draft's
own field line names `0x0628`–`0x062F`, though the extension reserves
it only `0x0628`–`0x062B`; the request points that out, so that the
block stays free for him to place these in.

| Kind | Name | Type, or proposed | In |
|---|---|---|---|
| Reason code | `Requested` | 17 | 810 (§4.2) |
| Reason code | `Withdrawn` | 18, or 17 if `Requested` is given none | portable friends §7 |
| Reason code | `Stale` | 19, or 18 if `Requested` is given none | portable friends §7 |
| Capability bit | `CAPABILITY_FRIENDSHIPS` | his to choose | portable friends §7 |
| Transaction | Get Message Requests | 829–839 | above |
| Transaction | Answer Message Request | 829–839 | above |
| Transaction | Clear Message Requests | 829–839 | above |
| Transaction | Message Requests Changed | 829–839 | above |
| Transaction | Present Friendships | 829–839 | portable friends §4.3 |
| Transaction | Get Friendships | 829–839 | portable friends §4.2 |
| Field | `DATA_TAKES_REQUESTS` | UInt16 | 808, beside `DATA_DISCOVERABLE` |
| Field | `DATA_REQUEST_CURSOR` | Binary | Get Message Requests and its reply |
| Field | `DATA_REQUEST_ACTION` | UInt16: 1 approve, 2 delete, 3 end | Answer Message Request |
| Field | `DATA_REQUEST_COUNT` | UInt32 | Get Message Requests, Clear Message Requests and Message Requests Changed replies, as each says |
| Field | `DATA_FRIEND_REQUEST_COUNT` | UInt32 | Clear Message Requests' reply |
| Field | `DATA_SPAN_SINCE`, `DATA_SPAN_BEFORE` | UInt64, Unix seconds | Clear Message Requests |
| Field | `DATA_MAX_REQUEST_MESSAGES` | UInt32 | Login reply, from the limits sub-block `0x0625`–`0x0627`: `request_messages`; absent when the server takes no requests |
| Field | `DATA_FRIEND_OFFER`, `DATA_FRIENDSHIP`, `DATA_FRIEND_WITHDRAW`, `DATA_FRIENDSHIP_HASH`, `DATA_IDENTITY_ROTATION` | Binary | portable friends §7 |

Device proof (portable friends §3) is not messaging's and is asked for
on its own, as a standalone extension with a capability bit,
transactions and fields outside these ranges, since sealed messages,
portable friendships and the server link's user keys draft all need a
classic session that proved a device.

**Asked of fogWraith**, beside the numbers:

1. to reserve the numbers above;
2. to comment on message requests, as an optional section of the
   extension or a companion draft;
3. to accept the deviations a client other than ours depends on:
   `Requested` on a successful 810, `AccountNotFound` for a block on
   810, an upgrade offer not answered `AlreadyFriends`, and a `Removed`
   801 carrying a withdrawal (`proposals/portable-friends.md` §4.2);
4. to take portable friends' §4 and §7 as the identity draft's second
   version;
5. to take device proof (portable friends §3) as an extension of its
   own, which the identity draft and the user keys draft cite.

**What an existing client sees.** Everything asked is opt-in: a client
that sets no new capability bit, sends no new field and never lists
requests is answered as the extension answers it today, and is sent
nothing it has not seen before. Requests pass only between accounts
whose clients have both listed them (§4.1); portable friendships go
only to sessions that negotiated `CAPABILITY_FRIENDSHIPS`; Prove Device
changes only the session that sends it. Two things an existing client
can notice are asked as what a server MAY or SHOULD do, with replies
the extension already has: a block read as `AccountNotFound` at 810,
which is the extension's own SHOULD at 802 carried to 810, and the
friend-request bounds of §4.4, under which a held request reads to its
sender as one never answered. The hxd-ng policy below (§8) is not
asked of anyone.

**The ng wire**: the friend family in the JSON protocol, the same
operations and states under the ng spellings, and for requests:

- `requests` `{ cursor? }`, answered `{ requests: [{ login,
  fingerprint?, messages: [{ id, text, at, guid, signed? }] }],
  approvals: [{ login, fingerprint? }], dropped, cursor? }`;
- `request_answer` `{ login, action: "approve" | "delete" | "end" }`,
  answered `{}`, or refused `no_such_request`, and `approve` past the
  approver's `MaxRosterSize` `roster_full`;
- `requests_clear` `{ since?, before? }` (§4.3), Unix seconds as `at`
  is, answered `{ declined, deleted }`;
- the event `requests_changed` `{ count }`, the senders waiting, to
  sessions that have listed requests;
- `takes_requests` in the profile, beside `discoverable`; a profile
  update that leaves it out leaves it as it was, since the classic
  wire sets it in 808 rather than in the whole-profile 826;
- `msg`'s reply for a request, `{ "queued": true, "requested": true }`
  (§4.2), and its new refusals, `not_friends`, `request_full` and
  `roster_full` (§4.1), with `quota_exceeded` and `no_such_user` as they
  are.

This document is the family's, a `messaging` capability in
`hotline-ng.md` §4's table, with its error codes owed to §10 there:
the friend family's requests and events under ng spellings, `requests`,
`request_answer`, `requests_clear` and `requests_changed`, and §10's
`ignore`, `unignore`, `ignores`, `ignores_changed` and the `user`
object's `ignored`. Each request is owed a weight in `request_weight`
in `conn.rs`. `system-account.md` §3 is owed `/requests clear`,
`/ignore`, `/unignore` and `/ignores`, and `/block` and `/unblock`
moving onto the relationship store.

---

## 8. In hxd-ng

Each stage is a branch with tests, in the house style.

1. **IM1, the store.** The relationship store (§3): its trait, the
   in-memory store and SQLite's with a migration that moves the inbox's
   block list into it, under one conformance suite with the rename,
   linking and rotation cases in it; friendships and approvals with
   their ids; requests, the ledger and holds (§4.4); per-account status
   text, `discoverable`, taking requests and when requests were last
   listed, and profile; the inbox's friendship column.
2. **IM2, the domain.** `Core`'s friend operations, telling both
   parties' sessions; presence summed across a login's sessions; the
   Invisible rule; discovery that shows non-friends no presence; IM Send
   onto the inbox, `delivered_at` at the ack, drained at Get Roster and
   gated in the store (§5); requests, approvals and their bounds (§4),
   `/msg <login>` among them; push (§5); the lifecycle calls of §6, with
   `account_delete` purging; `message.friendship` re-stamped from the
   ids a claim or rotation merged, and a friendship merged beside a
   block ended, both parties told. Unit-tested against the in-memory
   store.
3. **IM3, the ng wire and hx-ng.** The friend family and requests in the
   JSON protocol. hx-ng gains a friends list and a requests view. This
   is where the design is first used end to end, by a client we control.
4. **IM4, the classic wire.** §7's classic half, requests once IM5 has
   their numbers. The 800-block in `hxproto` in hx-libs first, then
   GtkHx's buddy list. Checked against Janus where it can be run, and
   against Tagban's Hotline Instant Messenger where a Mac is to hand.
5. **IM5, upstream**, before IM4 rather than after it. Message requests
   sent to fogWraith early, as a draft for his input, with §7's numbers
   and asks in one request together with
   `proposals/portable-friends.md`'s, so that IM4 waits on nothing else.
   What is sent is rewritten server-neutral first, in the extension's
   style: its `Messaging.*` settings with defaults in place of
   `[messaging]` and `[limits]`, and none of `Core::`, the inbox, the
   system account or the stages.

Calls (818–821, with a guest list on each call's room enforced at
Join Voice Room on both wires) and the user-to-user file relay
(814–817, each side's transport protection ended separately) follow,
the relay after the files work it depends on.

Buddy icons (827, 828) are the avatar the account already has
(`avatars.md`): setting one is setting the avatar, on either wire, and
`DATA_BUDDY_ICON_HASH` names the stored image, so there is one picture
per account rather than two to keep in step. They follow IM4.

**What it costs**, and how each stage is built to keep it small:

- **Presence fans out.** One change is an 809 to every session of every
  friend, a roster of hundreds each, and a login storm is many at once.
  Friends are found from an index held in memory by mailbox, never the
  store, and a burst of changes from one session is announced once with
  its final state, as voice's mute flips are (IM2).
- **A fingerprint finds an account by scanning the accounts directory**
  in `hxd-auth-file` today, and every delivery, request and
  presentation to an identity asks it. IM1 gives the lookup an index,
  kept in step with linking and unlinking.
- **The delivery gate is on every inbox read** (§5), counts and badges
  included. The live friendship and approval ids a mailbox may receive
  on, and the senders its unlapsed `messages` and `all` ignores hold,
  are indexed with its rows, so the gate is a join, not a check per row
  (IM1).
- **The ledger grows with what is sent**, a flood included, though the
  bounds of §4.4 keep it finite. It is indexed by sender and time and
  by address and time, so a rolling day is a range, and the cleanup
  (§3) reclaims it (IM1).
- **Ignored chat** is filtered by ng clients themselves, by the
  roster's `ignored`, and by the server only for classic sessions
  (§10), so the relay's path is the same for every ng session.

**Settings**: a `[messaging]` section with the extension's settings
(`enabled`, off by default; `max_roster`; `max_message_bytes`;
`offline_retention_days`; `max_offline`, aligned with `[inbox]`;
`max_sessions_per_login`, default 0, unlimited) and the requests'
(`request_messages`, `requests_per_day`, `max_requests`,
`max_friend_requests`, `request_retention_days`), with
`requests_per_address` under `[limits]`.

**Deliberate deviations from the extension**, in two groups. The first
is proposed upstream (§7), each opt-in or a server's MAY; the second is
hxd-ng's own policy and is not.

*Proposed upstream:*

- **Message requests** (§4): between accounts that both take requests,
  an 810 to a non-friend succeeds with `Requested` instead of failing
  `NotFriends`; and an 810 to an account that has blocked the sender
  fails `AccountNotFound`, as Find User does, instead of `Blocked`,
  carrying to 810 the extension's SHOULD at 802.
- **Approvals** (§4.6): sends answered `OfflineQueued` even when a live
  session took them, `Delivered` receipts not forwarded, and approvals,
  and ignores of someone who is no entry (§10), counted toward
  `MaxRosterSize` though they are not roster entries, so a client that
  knows nothing of them can be told `RosterFull` below the roster it
  sees.
- **Friend requests** (§4.4), as a server MAY bound them: one from a
  held sender, or past the recipient's `max_friend_requests`, is
  dropped, no 804 sent, though it is answered `PendingOut`; a
  `PendingIn` does not count toward the recipient's `MaxRosterSize`, so
  an 805 that accepts at the cap is refused `RosterFull`; an unanswered
  request lapses, where the extension's never do; and two crossing
  requests accept each other (§3).
- **Sealed messages** (§4.1): refused to anyone but a friend, where the
  identity draft would carry one to anyone holding the certificate.

*hxd-ng's policy, not proposed:*

- **Account addressing** (§4.1): once messaging is on, an ng `to_login`
  or a classic `/msg <login>` to a non-friend holding `AccessMessaging`
  makes a request or is refused, where it used to go to the inbox from
  anyone not blocked; a classic one makes a request from a guest or an
  account without the bit too.
- **Sessions.** The extension says a server that bounds a Login's
  sessions evicts the oldest rather than refusing the login. `[limits]`
  refuses: past `connections_per_account`, and for logins faster than
  `reconnect_seconds` once past it, on both wires and for every account
  with a password or an identity, because it bounds what one account
  costs the server, whether or not it uses messaging.
  `max_sessions_per_login` evicts as the extension says, and is useful
  only below `connections_per_account`; past that, the refusal is ours.
- **Draining** (§5): IM Send rows drain at 800 at most
  `deliver_at_flush` at a time, where the extension drains the whole
  queue.
- **`AccessMessaging` revoked** suspends an account's friendships where
  the extension deletes them (§6).

Gating queued messages at delivery (§5) is an addition the extension
does not mention rather than a deviation from it.

**Deliberate deviations from the identity draft.** Relationships are
keyed by fingerprint where the account has an identity (§3), where the
draft keys roster rows by Login, so that a relationship survives a
rename; unlinking ends them (§6).

---

## 9. Security and privacy

- **What a request tells its sender.** One answer, `Requested`, whether
  the request was stored, held or dropped and whether the recipient is
  online, has looked, has lapsed or never will, and no receipt, typing
  or presence until an approval or a friendship (§4.2). The bounds,
  the daily quota and retries are all answered from the ledger of what
  was sent, so their refusals say nothing of what the recipient did, and
  every outcome writes the same ledger row (§4.4). Whether an account
  takes requests at all is visible to anyone, as `discoverable` is.
- **A block reads as a missing account** on every request that names an
  account (§4.1), as Find User already answers it, between accounts
  holding `AccessMessaging`; to a blocker without it, a `to_login`
  keeps `blocked`, which shows the bit, though Find User shows it
  anyway. A `msg` to a uid
  keeps `private-messages.md` §11's named `blocked`: the uid is someone
  visibly present, so the block is account addressing's to hide, not
  the user list's.
- **A request costs the recipient little.** It raises no notification,
  takes no place in the mailbox, and is bounded per sender, per address,
  per day and per recipient, and a delete, a decline or a removal holds
  the sender (§4.4). A recipient who wants none turns them off.
- **An approval is narrower than a friendship.** Messages and read
  receipts pass; presence, profile, capabilities, typing and `Delivered`
  receipts do not, and every send is answered as queued (§4.6).
- **An ignore is not invisible.** It sends the other nothing, but anyone
  under a `messages` ignore who sees the ignorer online, a friend or a
  stranger sending a `msg` by uid, sees every message answered as
  queued, no receipt come back, and a sealed one refused (§10).
- **Moderation.** A request is an inbox row like any other, listed with
  its inbox id, so reporting one goes through the inbox's reporting path
  (`moderation.md` §4.2), and an operator sees the sender as for any
  message.

---

## 10. Ignore

A block ends a friendship, and from a client that sends a withdrawal
ends it everywhere it is presented (`proposals/portable-friends.md`
§4.3), because a block is a stronger act than a removal, and a removal
already does. A person who wants someone out of sight on one server
without ending anything ignores them instead: a state of the ignorer's
own row (§3) that applies on this server alone, sends the other
nothing, and leaves any friendship or approval standing. It is not
invisible (§9), and someone who must not be seen to ignore blocks
instead.

An ignore is in one mode at a time:

- **`messages`**: their IMs, private messages and requests are held by
  the store's gate (§5), kept out of the inbox, its counts and the
  notify seam, and delivered if the ignore is lifted within retention,
  as a suspended friendship's are. A sealed message, which is never
  stored, is answered as for a recipient with no session that can take
  it, and their typing (813) is dropped, so the ignorer is never told of
  a message that does not come.
- **`presence`**: their presence is not reported to the ignorer, who
  reads them as Offline, as for Invisible, in 800, 809 and their ng
  counterparts. The other still sees the ignorer's.
- **`chat`**: their lines in public chat and in rooms are hidden from
  the ignorer. An ng client hides them itself: the `user` object of
  each of their sessions on the ignorer's roster carries
  `ignored: { mode, until? }`, sent to the ignorer alone, in `users`,
  `user_joined` and, when an ignore is set or lifted, `user_changed`,
  so the client filters by uid and the relay serves every ng session
  one line alike. The server filters only for a classic session, which
  cannot, from a set held on the session and loaded at login, and a
  session that ignores nobody's chat skips the check, and in `history`
  replies to the ignorer, whose lines name no uid (`chat-history.md`
  §7), by the line's sending account; a reply is not the relay's
  fan-out, so that costs the relay nothing.
- **`all`**: the three together.

Setting a mode replaces the one before. An ignore may be given a
duration, and is kept until it is lifted if it is not. The row stores
when it lapses, and an ignore found lapsed (§3) is lifted as an
`unignore` lifts it: what it held is released (§5) at the next drain
rather than the moment it lapses, and what outlived retention while
held is gone, as it would be after a lift by hand. A lapse sends
nothing: a client and a classic session's set compare `until` with the
time, as the store does, and a presence-ignored friend's presence is
whole again at the client's next roster read. Setting an ignore again
replaces its duration too, so an ignore made permanent loses its lapse
and one given a new duration counts from then. An ignore of someone
who is otherwise no entry counts toward the ignorer's `MaxRosterSize`,
as a `Blocked` row does, which bounds the ignores and the classic
session's set.

A period client reaches it as `/ignore <who> [mode] [duration]` (`all`
if no mode is given; a duration such as `30m`, `12h` or `7d`),
`/unignore <who>` and `/ignores`, beside `/block` in the system
account's commands (`system-account.md`). On the ng wire:

- `ignore` `{ uid | login, mode, seconds? }`, exactly one of `uid` and
  `login` as for `block`, answered `{}`, or refused `roster_full`, or,
  by login alone, `no_such_user` as Find User answers (§4.1, step 1);
- `unignore` `{ uid | login | fingerprint }`, answered `{}`;
- `ignores`, answered `{ ignores: [{ login?, fingerprint?, uid?, mode,
  until? }] }`, `uid` for a ghost's or a guest's;
- the event `ignores_changed` `{ ignores }`, the whole list, to the
  ignorer's sessions when an ignore is set or lifted, from any device or
  either wire.

An ignore of a ghost or of a guest stays on the ignoring session, as a
ghost's block does (§3), since there is no account to key a row by,
or, for a guest, one that every guest shares, and lapses with it if the
session ends first. It is built after IM3, on both wires.

---

## 11. Later versions

- **Requests across links.** A ghost cannot send an IM in this version.
  Whether a link extension should carry requests from a peer's users,
  and whose bounds hold them, waits for presence across links
  (`proposals/portable-friends.md`, PF5).
