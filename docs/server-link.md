# Server linking: hxd-ng on a linked network

Status: partial, 2026-10. Built: L0 (the uid quarantine, Colored
Nicknames), L1 (links by key mode, Hello, server lists, pings, close,
reload), L2 (users crossing one link both ways, ghosts on both wires), L3
(public chat both ways), L4 (private messages and user info), L5
(moderation both ways), L6 (interruption and its grace period), L7
(relaying between this server's links) and L8's metrics. The rest is design. It implements fogWraith's
[Server Linking Extension](https://github.com/fogWraith/Hotline/blob/main/Docs/Protocol/Capabilities-Server-Link.md)
("the extension" below), through its fifth revision (server keys), against
Janus 2.0.19 as the first peer.

The extension joins independently run servers into one community: every
server's users appear in every other server's user list as *ghosts*, with
one public chat and private messages between them. A linking server dials
its peer's classic port, logs in with capability bit 11, and speaks the
900-block of transactions over that session. Classic clients need nothing
new: a ghost is a user with a uid.

This document is how hxd-ng does that without breaking what it already
promises: a wire-free UTF-8 domain, user-scoped presence with gapless
outboxes, bounded queues everywhere, and fail-closed handling of anything
it does not understand. The extension is the spec; where this document
and the extension disagree about the wire, the extension wins and this
document is wrong.

**Naming.** The code already uses "link" for associating an identity with
an account (`LinkAuthority`, `LinkOutcome`, the `link` parameter of
`run_connection`). Code for this document says *peer* and *ghost*
(`PeerId`, `PeerFeed`, `PeerRouter`, the `ghosts` map, the `server_link`
module) and keeps "link" for the crate name and the extension's own terms.

---

## 1. What is at stake

- **Classic clients see ghosts as users.** User list rows, joins and parts,
  chat lines and private messages from ghosts must look exactly like their
  local counterparts, in mhxd's bytes, on 1.2, 1.5 and 1.9 clients.
- **A ghost is not a connection.** Every handler that writes to a user,
  starts a transfer, inspects an account or keys a store on a uid must
  never be reached with a ghost's uid. The extension calls this the
  property most likely to regress as a server grows, and hxd-ng has grown
  a lot of uid-keyed features: private chat, voice and video, inline media
  handles, the inbox, blocking, reports, purge, news notifications,
  avatars.
- **Nothing private crosses.** No login, address, access bit or password
  material leaves this server over a link, and nothing arriving over one
  can grant privilege here.
- **A peer that will not drain costs a bounded amount**, and nothing
  arriving over a link may push a local session near its queue cap in one
  go, or stall a local session while it waits on the network.

## 2. Shape

| Where | What |
|---|---|
| `hxd-core` | Ghosts and the peer-facing domain API (`server_link` module): attach and update ghosts, deliver their chat and messages, the export feed, exclusions, bans placed for peers. Wire-free, and it never builds display strings. |
| `hxd-link` (new crate) | The link wire: the 900-block, the hub that owns the server and ID tables, one I/O task per link, the dialer, the key proof, relaying. Depends on `hxd-core` and on `hxd-session`'s framing. Knows nothing about classic clients or the ng wire. |
| `hxd-session`, `hxd-ng-session` | Show ghosts to their clients, refuse what cannot be done to a ghost, and on the classic ports, hand a session that logs in with bit 11 to `hxd-link`. |

The `[link]` config section is the switch; there is no Cargo feature,
since `hxd-link` adds nothing to the build that TLS and identity have not
already brought.

## 3. Ghosts in the domain

### 3.1 A map of their own

The precedent for a user with no connection is the system session: an
`attach` whose `Events` receiver is dropped. Building ghosts that way
would make every `users.get(&uid)` in the core a place where a ghost might
be found and acted on, which is the regression the extension warns about.

**Ghosts live in `RosterInner.ghosts: HashMap<Uid, Ghost>`, not in
`users`.** Every existing lookup stays local-only (`user()`,
`user_details()`, `snapshot()`, `access_of()`, `resolve_person()`) and
finds nothing for a ghost's uid, so every existing feature fails for a
ghost as it would for a user who has left: broadcasts, the inbox and its
flush, voice, media audiences, private chats, reports, blocking, purge,
avatars and GIF icons all go through `users`. A feature added later is
safe by default: it cannot see ghosts.

What does see them opts in, through lookups of its own:

- `roster_rows()`, new: local users and visible ghosts, sorted by uid.
  Used only by the classic user list (300) and the ng roster at login,
  resume and sync.
- `resolve(uid) -> Target { Local, Ghost(GhostRef), Refused(PeerRefusal), None }`,
  new: for the three translated acts (§6), which are its only callers. A
  ghost that is excluded or hidden here resolves to `Refused(Excluded)`.
- The uid allocator, which checks both maps and the quarantine (§3.3).

Counts stay local: the tracker counts with `snapshot()` (local-only), and
`census()` and metrics count `users`, as the extension asks of tracker
listings and the info port. A ghost gauge is separate (L8).

**Joins and parts for ghosts are the core's**: attaching a visible ghost
broadcasts `Event::Joined` to visible local sessions, consuming a seq in
each outbox like any other event; parting, hiding or excluding one
broadcasts `Event::Parted`. Nothing about seq accounting changes.

### 3.2 The ghost record

```rust
pub(crate) struct Ghost {
    serial: u64,              // from last_serial, never reused
    peer: PeerId,             // the link it was learned over
    peer_uid: u16,            // the id that link uses for it
    home: ServerId,           // its home server
    own_name: String,         // as relayed, never a display name
    icon: u16,
    away: bool,
    refuses_msgs: bool,       // its own flag, or set because its path lacks private messages
    excluded_here: bool,      // this server's ID is in its exclusion list
    hidden_here: bool,        // kicked from here, or a failed kick or ban (§6.3)
    group: Vec<Field>,        // the user group exactly as received, every field, in order
}
```

`group` is what Relaying Fields needs: a relay re-sends a user group whole
and in order, rewriting only the user ID and flags, so the exclusion list,
the user's own `DATA_COLOR` and fields outside the baseline go on as they
came. The parsed fields beside it are what this server uses.

`hidden_here` is local and survives later user updates, since the next
complete group from the peer does not mention it. It clears only when the
ghost goes, or when it is re-used after a new epoch of its home server.
Only the adjacent peer's epoch is visible (Hello carries it; server
groups do not), so in practice it clears on re-use only for a ghost homed
on the peer itself: a relay restarting does not end the home server's
session, and a ghost homed further away stays hidden, which is the
conservative direction. **Re-use keeps the uid and mints a new serial.**

### 3.3 Uid quarantine

The extension requires that a uid not be reused for five minutes after it
stopped being exported, so a request in transit cannot reach whoever holds
it next. `next_uid()` continues upward from the last uid allocated and
wraps, skipping only uids in use, so on a busy server a wrap can reach a
uid freed a moment ago.

The allocator keeps freed uids, local and ghost alike (a ghost's uid is
the id this server exports it under when it relays), in a `VecDeque` of
(uid, freed at) with a `HashSet` beside it, so a check costs O(1) under the
roster lock, and skips any uid freed less than five minutes ago. If no
uid is free otherwise, it takes the least recently freed one rather than
refuse a login as "Server full". It applies whether or not links are
configured: one rule is simpler than two, and nothing a client sees
changes.

### 3.4 Display

The domain has no away, refuses-messages or refuses-chat flags; the
classic frontend derives away from `status != Active`. **The core never
builds a display name**: it carries a ghost's own name and where it is
from, and each frontend renders them.

- `UserInfo` gains `remote: Option<RemoteRef>`:

  ```rust
  pub struct RemoteRef {
      pub home_tag: String,
      pub home_name: String,
      pub tagged: bool,         // [link] show_tags when the ghost was shown
      pub refuses_msgs: bool,
  }
  ```

- A ghost's `UserInfo.nick` is its own name; away maps to `status: Idle`;
  `admin` is always false.
- `Event::Msg` gains `from_remote: Option<RemoteRef>`, since it carries a
  sender's name as a string rather than a `UserInfo`.
- The chat log stores, for a ghost line, its own name, its home server's
  ID and tag at the time, the ghost's serial and this server's epoch (the
  next schema version), so a replay renders it the way a live line would,
  a later change of `show_tags` applies to history too, and a purge can
  name the ghost exactly (§6.3). Rendering takes the tag, name and color
  from a server table the hub keeps in the core (`peer_servers`), and
  falls back to the stored tag for a server no longer reachable.

**The classic frontend** renders `name@tag` when `[link] show_tags` is on:
the name is cut to leave room for the tag within the 31-byte nick cap, so
the cut never takes the tag. In chat lines, the name is cut to fit
`@tag` inside `name_column`'s 13 columns, so the tag survives there too.
`wire_color` adds 4 (refuses private messages) from `refuses_msgs` and 8
(refuses private chat) on every ghost, and never 16 (cleartext).

**The ng frontend** sends `nick` as the own name and `remote: {server,
tag, color}`, and the client decides how to show it (§5).

`show_tags` is read when a ghost is shown and kept in its `RemoteRef`, so
changing it takes a restart, like the rest of `[link]` outside the peers.

### 3.5 Colored Nicknames

The extension identifies an untagged ghost by its home server's color,
through Colored Nicknames (`DATA_COLOR`, `0x0500`), which hxd-ng
implements (L0) for the clients that send a color. A ghost shows its home
server's color, never its own: the hub puts the home server's color in
the ghost's `UserInfo.color`, so every frontend shows it the way it shows
a local user's. Its own color still crosses the link, in its group.

Color tells a ghost apart only so far: since L0 any local user may pick
any color, the one a linked server's users show included. A name never
proved where someone was from on Hotline, and a color does not either;
the user info prefix does, and the tag option, `show_tags`, puts the home
server in every ghost's name for operators who want that shown in every
client. It is off by default, as the extension has it.

### 3.6 Bounded fan-out

A snapshot arriving, or a netsplit past the grace period, is one `Joined`
or `Parted` per ghost to every local session in one go. AGENTS.md forbids
any domain operation that pushes a session near its cap in one go.

- **A server-wide ghost cap**, `[link] max_ghosts` (default 2000; the
  config check holds it to half of `LIVE_QUEUE_CAP`), across all links,
  beside the per-link bound the extension recommends, `ghosts` on each
  peer (default 1000), which also bounds a snapshot held while its parts
  arrive. Ghosts past either are not represented, and traffic naming them
  is dropped and logged.
- A detached ng session buffers at most `OUTBOX_BUFFER_CAP` events, which
  a netsplit can exceed. It breaks and resumes into `resync_required`,
  which is what that answer exists for. A roster-reset event that replaced
  the burst with one frame is possible later and not needed first.

## 4. The peer-facing API

### 4.1 Subscribing and the feed

`hxd-link` needs every local user it may export, and then every change, at
one consistent position, because the extension has it send a complete
snapshot and then updates:

```rust
impl Core {
    pub fn peer_feed(&self, cap: usize) -> mpsc::Receiver<(u64, PeerEvent)>;
    pub fn peer_snapshot(&self) -> (u64, Vec<LocalUser>);
}
```

The feed numbers each event under the roster lock, and a snapshot is
taken under it with the number it stands at, so a link that sends one
skips every event numbered up to it: the snapshot and the updates after it
neither miss nor repeat anything. The core `try_send`s `PeerEvent`s to the
feed from inside the roster lock, at the call sites that broadcast local
presence: `announce`, `update_with_color`, `set_status`, `apply_account`
(when the name changes: the admin bit never crosses),
`RosterInner::end_session` (which every way of leaving goes through), and
the broadcast step of `chat_commit_batch`, which checks there that the
sender is exported (`chat_public` does not check `visible`, so a line
could otherwise reach the feed ahead of its sender's `Shown`). They sit at
the call sites, not
inside `broadcast_where`, which also carries ghosts' own `Joined` events.
All of them run under the roster lock, so the feed is totally ordered: a
user is always `Shown` before their first `Chat`.

```rust
pub enum PeerEvent {
    Shown(LocalUser),
    Changed(LocalUser),
    Gone(Uid, GoneReason),     // Disconnected; NotExported and Banned with L5
    Chat { from: Uid, text: String, style: u16, line: u32 },
}
```

`LocalUser` carries only what may cross: uid, own name, icon, away and
color; later, the serial, exclusions (§7.5) and the user key fingerprint. Never the
login, address or access bits; the type has no field for them, so a later
change cannot leak them. Refuses-messages has no source in the domain and
is always false for local users. A session's departure reason is recorded on
the `UserSession` when it is kicked or banned, and
`RosterInner::end_session` reads it, so a ban reaches peers as `Banned`
even though the frontend that ends the session later knows nothing about
the ban. A `Chat` is exported only if its sender is still on the roster
when the line is broadcast (the commit re-check and the broadcast take the
lock separately), and a uid is quarantined once freed, so a line never
reaches the feed after its sender's `Gone`. The feed counts the lines it
carries, and each link builds a 904's line ID from this server's ID, its
epoch and that count; the history's own `LineId` is a database row and
does not cross.

**What is exported:**

- visible, announced local sessions;
- not the system session. It is in the classic user list, so this is a
  deviation from the extension's "every session an ordinary client would
  see", and deliberate: a private message to it runs commands, and no
  other server's user has any business sending one;
- chat lines from exported senders, with text (a media-only line is not
  exported; a line with media exports its text), and never a ghost's
  line, which the hub relayed itself.

**There is one feed, into the hub** (§7.4), not one per link: the core
pushes each event once. The hub is in process and never waits on a
socket, so a full feed means the hub itself has stalled; the feed is then
marked broken and the hub closes every link with `Shutdown` and
resubscribes, and each reconnection sends a fresh snapshot. A slow *peer*
never reaches the feed: it fills its own writer queue (§7.4), and only its
link is closed.

### 4.2 Calls from the hub

```rust
impl Core {
    pub fn ghost_attach(&self, g: GhostInfo) -> Option<Uid>;   // None: no uid free
    pub fn ghost_update(&self, uid: Uid, g: GhostInfo) -> bool;
    pub fn ghost_part(&self, uid: Uid);
    pub fn ghosts_part_peer(&self, peer: PeerId, home: Option<ServerId>);
    pub fn ghost_chat(&self, uid: Uid, text: String, style: u16) -> Result<(), ChatError>;
    pub fn ghost_msg(&self, from: Uid, to: Uid, text: String) -> Result<(), PeerRefusal>;
    pub fn info_text_for_peer(&self, uid: Uid) -> Result<String, PeerRefusal>;
    pub fn peer_exclude(&self, uid: Uid, requester: ServerId) -> Result<(), PeerRefusal>;
    pub fn peer_ban(&self, uid: Uid, by: PeerRequester, for_: Option<Duration>, reason: String) -> Result<PeerBanId, PeerRefusal>;
    pub fn peer_unban(&self, id: PeerBanId, by: ServerId) -> Result<(), PeerRefusal>;
}
```

All but the bans are synchronous and quick. The bans write to the store,
so the hub spawns them off the reactor and carries on; it never awaits
them in its own loop, which would back the feed up.

`ghost_msg` refuses with `Excluded` when either party is excluded or
hidden at the other's server, and with `RateLimited` past a per-ghost and
per-link budget. A recipient that is detached gets the message in its
buffer, as any direct message.

### 4.3 Ghost chat

A ghost's line must keep its link's order, never run a commit on the
reactor, and never stall the link's reader. `ChatCommit` is unchanged;
the hub feeds it from one task of its own:

- **Staged on arrival.** The link resolves the ghost and asks
  `Core::ghost_line` for a `GhostLine`, under the roster lock: `None` for
  a ghost excluded here or past local users' chat limit, and otherwise
  the line with the ghost's `UserInfo` as it is now. Staging it then is
  what keeps the last line of a ghost whose 903 follows at once.
- **One committer.** Every link's lines go, in the order they arrived,
  into one bounded channel, and one `spawn_blocking` task submits them to
  `ChatCommit` a line at a time (`Core::ghost_chat`), as a local sender
  does; local lines share its commits. Past the channel's bound a line is
  not shown here, and is logged: the extension's volume bound, held
  across every link. It is relayed onward whether it is shown here or
  not (§7.4.1).
- **The batch re-check.** `Staged` has no session for a ghost's line, and
  the re-check looks the ghost up in `ghosts` instead: a line is dropped
  when its ghost is still present but hidden, and goes out under the
  ghost's current name, or under the one it was staged with when the
  ghost has gone since.

One task holds every link's lines to one commit each, which a busy
network could outrun; batching them is the change if it does.

Where the line is shown:

- not for a ghost that is excluded or hidden here (the hub has relayed it
  regardless, as the extension requires);
- the per-ghost rate limit decides display only, for the same reason;
- history records it with the ghost's name as shown (`name@tag` when
  tagged) and icon, and no login or fingerprint. Each server's history is the chat it saw. The home server
  and the line ID join it with the next schema version, as purge needs
  (§6.3).

**Two consequences, stated.** A batch that fails to commit drops its ghost
lines locally without a trace, as it drops local ones. And `ghost_part`
takes effect at once while a line staged just before it commits a moment
later, so a client can see a ghost leave and then its last line; the
alternative is losing it.

### 4.4 Text on a link

- **Line endings are CR on a link.** The domain stores whatever a client
  sent (CR from classic clients, LF from ng ones), and each frontend
  normalizes on the way out. The hub does the same: it converts LF and
  CR LF to CR when it builds a 904 or 905, and passes what arrives on to
  the core as it came. The classic encoder's `body()` is for clients and
  is not reused: for UTF-8 it emits LF.
- **Byte maximums.** Chat lines and private messages are already cut at
  4096 bytes on both wires, so a local line exceeds the extension's 8192
  bytes only from a classic client in Mac Roman, where one byte can become
  three in UTF-8. When `[link]` is configured, such a line is cut to 8192
  bytes of UTF-8 at ingest, before it is shown anywhere, so every copy on
  the network is the same, as the extension requires. (A UTF-8 classic
  client's invalid bytes, each a replacement character, can do it too.) A local name longer than 255 bytes is
  not exported; hxd-ng's nick cap is far below that.
- **Receiving:** the hub drops, never truncates, a transaction or group
  over the extension's maximums or the Relaying Fields bounds.

## 5. The ng wire

A ghost's `user` object gains `remote: {server, tag, tagged}`, beside its
`color`, which is its home server's. It has no
`identity` (until user keys), no `avatar`, and `admin: false`. Its
`transport` describes the user's own connection, which this server cannot
know, so `hotline-ng.md` gains a third value, `unknown`, for ghosts.
Clients already must not treat anything but `encrypted` as protected.
`msg` events gain `from.remote` for a ghost sender, and chat events and
`history` entries carry the ghost's `remote` in `from`. These are wire changes: they land in
`hotline-ng.md` with the server, and the e2e pin on hx-ng advances when
the client handles them.

There is no ng request for another user's info today, so user info for a
ghost is classic-only; the `remote` object names the home server, which is
what the extension's prefix line is for.

## 6. Acts on a ghost

### 6.1 Resolve, then answer when the answer comes

The extension translates three acts, each after the local privilege check
it would get with a local target:

| Act | Classic | ng | Over the link |
|---|---|---|---|
| Private message | 108 | `msg` with `to` | Link Private Message (905) |
| User info | 303 | none (§5) | Link User Info (906) |
| Kick, kick with ban | 110 | `kick` | Link Kick (907), Link Ban (908) |

The core's `msg` and `kick_by` are synchronous and called off the reactor,
so the core cannot await a peer inside them. So the frontend asks the core
first (`Core::peer_msg`, `Core::peer_user_info`): `None` for a uid that is
not a ghost shown here, which goes on exactly as today; otherwise a
receiver for the answer, already answered when nothing can cross (§6.2)
and otherwise filled by the `PeerRouter` the hub gives the core when it
starts:

```rust
pub trait PeerRouter: Send + Sync {
    fn msg(&self, from: Uid, to: Uid, text: String) -> oneshot::Receiver<Result<(), PeerRefusal>>;
    fn user_info(&self, of: Uid) -> oneshot::Receiver<Result<String, PeerRefusal>>;
}
```

The hub sends the request over the ghost's link and the link matches the
reply by its task. An answer that has not come in `PEER_WAIT` (ten
seconds, the extension's per hop) is `Unreachable`, and the hub gives the
request up then, so the link forgets a request a peer never answers. A
reply marked an error is a refusal whether or not it carries a reason.

- **Classic:** awaited on a task of its own, and the reply sent when it
  comes. A reply echoes the request's task ID, so its place among other
  frames does not matter, and the session loop goes on meanwhile. The
  task holds the connection's sender for at most `PEER_WAIT`.
- **ng:** awaited in place. The ng wire promises replies in the order of
  their requests (`hotline-ng.md` §5), so the session stops for the
  wait: no events are sent and no frames read, though the domain cutting
  it off for lag still ends it at once. Its events wait in its live
  channel, where under a tight queue budget a session holding more than
  others is the one dropped. A reply queue that held later replies behind
  a pending one would lift this, and is the change if it matters.

That puts ghost handling in two frontends for three acts, which is the
whole list: everything else is already refused by §3.1.

### 6.2 Private messages

- Refused locally, without anything crossing, when the ghost refuses
  them or its link did not negotiate them, when the sender is not
  exported (the system session, a session not yet announced), and when
  the message carries media or is over 8192 bytes (§4.4). Receiving, a
  905 may carry 17,408 bytes beside its baseline, room for a message and
  its quote in another form, as the extension bounds it. A ghost hidden
  here is no user at all, as for every other act. The sender excluded at
  the ghost's home server joins this with exclusion (L5).
- Delivered to a local user as `Event::Msg` from the ghost's uid and own
  name, with no login, on the direct (non-durable) path: a ghost has no
  mailbox, so nothing is queued or blocked. A message spends a line of
  the ghost's chat allowance, local users' limit, and past it is refused
  `RateLimited`.
- `Event::Msg` has no quote or automatic-response flag, and the classic
  108 handler reads neither (214, 113). hxd-ng sends neither over a link
  and ignores both on receipt, until it supports them locally.
- On ng, a refusal is `not_delivered` with the reason as text.

### 6.3 Kicks, bans and purge

- `Core::ghost_kick` hides the ghost here at once, with `Parted` to local
  sessions, as the extension requires, and asks its home server through
  the router: 907, or 908 for a kick with a ban (the classic `[server]`
  ban time, or the ng `ban`).
- The ghost stays hidden for as long as it is shown, whatever the home
  server answers: its exclusion arrives when the kick took, and nothing
  does when it did not. **If a kick or ban fails** (`Unreachable`,
  `UnknownUser`, `InvalidRequester`, or no reply), the classic moderator
  gets a task error saying it was applied here only; the ng reply says
  `network: false` (`moderation.md`). Nothing is announced in chat.
- **Purge.** A ghost is given a random 16-byte key when it is shown,
  and its public lines are logged with it (`chat_line.ghost`, schema
  version 16, both stores and the conformance suite), in the line's own
  insert. `Core::purge_ghost` takes its lines in the window by that key
  (`ChatLog::lines_by_ghost`), never by name, so a local user or another
  ghost of the same name is spared, and records the act with the ghost
  named (`linked user nick@tag`) in its evidence; a ghost has no images
  or articles here to take, and nothing crosses a link. The ng `kick`
  with `purge`, and the classic kick under `[moderation] kick_purges`,
  take the ghost's key, kick it, so it is hidden and lines of its still
  queued are dropped by the commit re-check (§4.3), then purge by the key,
  which outlasts the ghost should its home server's answer take it away.
  A ghost hidden here already can be kicked again, and purged. A ghost
  that has left can no longer be named by uid, so its lines are purged
  while it is here or redacted one by one.

### 6.4 User info

- **As requester**, the classic 303 reply for a ghost is a first line
  naming the home server (`  server: <name>`), then the text the router
  returns, or that line and nothing else when the request fails or times
  out, as the extension requires.
- **As home server**, `info_text_for_peer` builds what an ordinary,
  unprivileged client may see: the name, the icon number and how long the
  user has been connected. Never the login or address. hxd-ng's own 303 is
  all-or-nothing today and includes both, so this is a new, smaller text,
  not a reuse.

## 7. The link wire (`hxd-link`)

### 7.1 Accepting

A Login (107) that sets bit 11 on the TLS port goes to `hxd-link`;
anywhere else it is refused. It is decided **before** `reconcile_login`. Today only the text
encoding is settled that early (the capabilities are intersected after
the credentials), so the link branch reads the requested bits from the
login itself, and `parse_login` learns `DATA_LINK_SERVER_KEY` (`0x0640`)
and `DATA_LINK_KEY_PROOF` (`0x0641`):

- `caps.rs` gains `SERVER_LINK = 11`. `legacy_caps()` never offers it: a
  link login is taken before capabilities are intersected, and only bits 1
  and 11 are echoed to it. It is decided before the login permit too, so a
  link is never refused as busy: it never joins the room.
- Bit 11 is confirmed only alongside bit 1, only for the login named by an
  accepting peer entry, and only on a connection accepted on the TLS port
  with an exporter value (§7.3). `transport.encrypted` is not the test: it
  is also true for the `/trtp` tunnel. Anything else is refused, never
  downgraded to an ordinary login; bit 11 not confirmed is reported to the
  dialer's operator as a configuration error, as the extension says.
- **A key-mode login never reaches `reconcile_login`.** The proof is
  verified instead; the password is not checked and the attempt is not
  counted toward lockout. A valid proof on a login without bit 11 is
  refused, as is a login that sets bit 11 without bit 1. **A key-mode link
  needs no account**: its peer entry, the login it names and the key, is
  the authorization, and no account is made for it, so there is none to
  delete or disable under a live link. Nothing stops an operator creating
  an ordinary account of the same name, which is then an ordinary account
  like any other; the link does not use it. A password-mode login (L8) goes through
  `reconcile_login` as today.
- A confirmed link session takes no `LoginPermit`, sends no agreement, never reaches `attach` or `announce`, and replies with the
  acceptor's key and proof in key mode. A request on it that the link
  does not define is refused with an error, and a notification it does
  not define is dropped.
- **Limits** (L8). The connection took its address's place, and spent its
  reconnect token, at accept, before anything showed it was a link. The
  extension's way out is what hxd-ng does: once a link has authenticated
  from an address, that address is trusted for a bounded time (renewed
  while the link stays up). Trust waives only the connection count, the
  reconnect rate and the per-address login share, **never the
  login-failure lockout** (which `exempt` also waives today): everyone
  behind the peer's NAT shares the address. Never bans an operator set,
  either. Today's exempt set is a static `AddrSet` copied into each
  `RateGate` and the ng port's limits, so the trusted set is a shared
  structure of its own that those consult.
- **The permit stays the address's.** AGENTS.md says a new login path
  moves its permit to the account's count; link logins deliberately do
  not, because `connections_per_account` and the account's reconnect rate
  would refuse a newest-wins redial (below).
- **The handoff** is two calls on a `PeerAcceptor` trait object passed to
  the TLS accept loop (`serve_tls_with_peers`), the only listener links
  are accepted on, so `hxd-session` does not depend on `hxd-link` and
  never holds the server key:
  - `authorize(login, exporter, addr) -> Result<Grant, Refusal>`, before
    `reconcile_login`: `hxd-link` checks the entry, verifies the proof and
    builds the login reply, with the acceptor's key and proof, which
    `hxd-session` sends with the login's task ID;
  - `accept(grant, io)`, with the frames, the writer and the place in
    `LinkIo`, awaited inside
    `run_connection`, so its teardown (aborting the reader, flushing the
    writer) still runs when the link ends. `Outbound` gains
    `Request { ty, trans, chunks }`, a frame with a caller-chosen task ID
    and the reply flag clear, since the pending-request map needs known
    IDs; `Reply { error: true }` already carries a non-zero error code.
  - The reader's frame limit (`MAX_FRAME_DATA`, 256 KiB) applies to links
    too: this server splits its own snapshot parts well below it, and the
    limit is one to confirm with Janus.
- **Newest wins.** A link login for an account that already has a live
  link closes the old one with `Replaced` and is treated as a reconnection
  for reconciliation, which is what lets Janus redial over a half-open
  link.
- **Authorization is continuous.** SIGHUP re-reads `[[link.peer]]`: an
  entry removed closes its link with `Unlinked`, a changed key with
  `ProtocolError`. A password-mode link (L8) will also need an
  account-change notifier, since a link session is not on the roster and
  gets no `AccountChanged`.

### 7.2 Dialing

`hxd-link` dials each dialing peer entry itself: TCP, TLS (§7.3), the TRTP
handshake, then a Login (107) with bits 1 and 11 and either the key proof
or the password. It reuses `hxd-session`'s frame reader and packer. There
is no outbound TRTP client in the server today, and the test client's is
test-shaped and not reused.

Reconnection follows the extension: a prompt first attempt, backoff with
jitter to a ceiling of a few minutes, the slow pace for `Suspended` and
failed key checks, ordinary backoff for `Loop`, `TagConflict` and
`HopLimit`, and no automatic reconnect after `Unlinked`,
`VersionUnsupported` or `Replaced`.

### 7.3 Protection

hxd-ng has no HOPE yet (a HOPE login is refused today), so the first two
protections are:

- **Server keys over TLS**, the extension's key mode. The proof needs the
  exporter value of the accepted TLS connection, which `run_connection`
  loses when it splits the stream; `serve_tls` computes it after the
  handshake, while it still holds the `tokio_rustls` stream, and passes it
  in beside the transport. The dialer takes it from its own connection.
  Both refuse key mode unless TLS 1.3 was negotiated
  (`with_safe_default_protocol_versions` also allows 1.2).
- **Verified TLS**, for peers with a real certificate: the dialer verifies
  against the system roots or a pinned fingerprint, and logs in with the
  password the peer issued.

A link over plain TCP, or over the ng port's `/trtp` tunnel, is refused.
HOPE AEAD joins when `hxhope` lands in hx-libs.

### 7.4 The hub and its links

**The hub** owns everything shared between links: the server table, each
link's ID tables, the core subscription, and the "server before its users"
ordering that relaying needs. **Each link** is an I/O task with a bounded
writer queue of its own, drawing on the server's `QueueBudget`. The hub
never waits on a socket: a link whose queue is full is dropped (once
lagged it can send nothing, not even a Close), which the peer sees as an
interruption, and it reconnects to a fresh snapshot; no other link
notices. A `PeerId` is stable per peer entry across reconnections, which
is what lets the grace period find what a link left behind.

The hub holds, per link:

- **ID tables**: peer id to ghost uid for what the peer exported, and
  exported uid for what this server exports (a local uid, or a relayed
  ghost's uid: for hxd-ng the id it exports under is the uid itself);
- **a pending-request map** keyed by task id for requests this server sent
  (905 to 910), with the ten-second timeout the extension recommends,
  answering the original request with `Unreachable` when it fires;
- the negotiated features, the peer's epoch and server group.

**Establishment** follows the extension's order on every link from L1:
Hello first in each direction and nothing before it, closing with
`ProtocolError` a peer that sends none within 30 seconds; the Hello
checks (the server ID derived from the proven key on a key-mode link, then
Loop and TagConflict); this server's Link Servers (§7.4.1);
and its snapshot only after the peer's first complete Link Servers is
accepted. Between snapshot parts nothing but Ping, Close and replies is
sent, so feed events that arrive meanwhile are held, within a bound whose
overflow closes the link, and sent after the last part. After that: a Ping
after 60 seconds without sending, and the link counted dead after three
intervals without receiving.

**Topology arrives only over transit.** Over a link with
`LINK_FEATURE_TRANSIT` the peer's Link Servers, Server Updates and Server
Gones name the servers behind it, and users homed on them; the hub checks
every server group (Loop, TagConflict, hop limit) and accepts ghosts homed
behind the link. Over a link without it the peer shows only itself, and a
server it names besides is ignored, so that leaving transit off declines
the peer's network as the extension means it to. Past the bound on
servers behind a link, a server is ignored rather than the link closed,
and a server a later update makes unacceptable is forgotten with its
users. A ghost not represented because of a cap (§3.6) stays
unrepresented: its later updates and departure are ignored, and anything
naming it is dropped.

**Checks.** Every incoming transaction is checked before the core sees it,
as the extension's conformance list requires: a user group must be homed
behind its link, a sender must be a current ghost from that link, a target
must be a user exported over it, a moderation requester must lie behind
it. A failed check is logged and dropped, or answered with its reason;
only server or user state that cannot be parsed closes the link.

**Relaying Fields**: groups are kept whole (`Ghost.group`) and re-sent
whole; fields that never cross are refused at every hop; the bounds are
checked on receipt and a group over them is dropped whole.

### 7.4.1 Relaying

Between two links that both negotiated transit, the hub passes on what
one learns to the other (`Relay`, numbered under the hub's lock as the
export feed is, into a channel of each link's own):

- **Servers.** A link's Link Servers names the servers behind the other
  transit links, the peers included, one hop farther (`Hub::relay_open`,
  just before it is sent); a server accepted later goes on as a Server
  Update, and one forgotten, or a link ended past its grace, as a Server
  Gone for it and everything behind it, standing for its users.
- **Users.** A ghost goes on as a user group under this server's uid for
  it, every field as it came but the ID and the flags (this server's
  rules: away, refusing messages or chat, refusing messages over a link
  that cannot carry them, never an admin); a change as an update, a
  departure as a User Gone with the reason it came with. A link's
  snapshot holds the other transit links' ghosts beside the local users.
- **Order.** What was passed on before a link's snapshot was taken is
  in it, servers aside: those go out ahead of the snapshot, as a server is
  announced before its users, and what came after waits for it.
- **Chat.** A line arriving over a link with public chat and transit
  goes on to the others with both, its speaker under this server's uid,
  whatever this server shows of it (an excluded or rate-limited speaker
  included).
- **Requests.** A 905, 906, 907 or 908 naming a ghost goes on to the link
  it came from (`Hub::forward`), its IDs translated and every other field
  as it came, the requester included, and the reply goes back as it was
  given; a hop that does not answer in `PEER_WAIT` is `Unreachable`. A
  909 for another server's ban is routed by that server's ID, never back
  over the link it came in on. A ghost is only addressable over a link it
  was shown on, so both links must have transit.

A link held through an interruption (§7.6) is still relayed as it was:
nothing about it goes on until the grace runs out. What this server's
moderation owes now reaches across the whole network (§7.5).

### 7.5 Moderation, both sides

Every request first passes the requester check: `DATA_LINK_REQUESTER`
must be the peer or a server learned over the link (`Hub::requester`),
or it is refused `InvalidRequester` and logged. Moderation needs no
feature: it is part of every link.

**As home server:**

- **Kick (907)**: `Core::peer_kick` adds the requester to the session's
  exclusions (`UserSession.excluded_at`, exported in `LocalUser` as
  `DATA_LINK_EXCLUDE`), emits `Changed` so the user's group is
  re-exported, and tells the user with a server message naming the
  requesting server.
- **Ban (908)**: `Core::peer_ban`, off the reactor, places a ban acting
  as `link <tag> (<name>)` with the operator's standing, so the audit
  trail and `hxd ban list` name the requesting server, and as a
  moderator's ban, so every session it refuses ends. It bans what the
  extension asks a home server to judge by: the person (account or
  identity) where there is one, so their every session ends and nobody
  else behind their address does, and the address only for a shared
  login such as `guest`. The user is told which server banned them by a
  server message sent before the ban, which ends the session with a
  `Kicked` that carries no text, and their departure crosses as 903 with
  `Banned`. `DATA_LINK_DURATION` is required, and a reason over 8192
  bytes or not UTF-8 is refused `RefusedFields`. The handle returned is
  16 random bytes, kept against a row this ban created and the requester
  (`link_ban`, schema version 14): a target already banned is extended
  rather than banned again, and that row is another act's, so then the
  reply carries no handle and the requester keeps nothing to lift. A
  store that will not answer an unban answers `Unreachable`, which the
  requester asks again, never `UnknownBan`, which it takes for lifted.
  An unban lifts the act's every row, and a local
  lift leaves the handle naming nothing, so a later 909 answers
  `UnknownBan`, as the extension expects. A failure reply is marked an
  error as well as carrying its reason. When there is nothing
  to ban by (a guest on an exempt address), the session is ended and the
  answer is `UnknownUser`, and the requester keeps the ghost hidden as
  for a failed ban. Protection from disconnection is not consulted for
  the user banned, as the extension says; other sessions the ban
  refuses end as a local moderator's ban ends them.
- **Unban (909)**: honored only from the requester that made the ban, and
  only for this server's own bans (`DATA_LINK_SERVER_ID`); another
  server's goes on toward that server (§7.4.1).

**As requester:** a ban another server placed at this server's asking is
recorded with its handle, the home server and what was known at the
time (`network_ban`, schema version 15), and listed by `hxd ban list`
after the local bans as `n#ID`. `hxd ban lift nID` is an offline
command, like every operator command, so it marks the ban asked for
lifting; the running server sends the 909 to the ban's home server on
the next SIGHUP, and whenever a link comes up (`Hub::send_unbans`), and
logs the answer. A ban asked for under a server key this server has
since replaced is not sent, as its home server would answer any other
requester `UnknownBan`: its operator lifts it. `OK`, or
`UnknownBan` because the home server's operator lifted it already or it
ran out, marks it lifted; anything else, or a home server out of reach,
leaves it to be sent again.

### 7.6 Interruption

A link that drops without a Close, goes quiet, or that either side
closes for a `Shutdown`, is interrupted, established or not, so a
reconnection that fails inside the grace discards nothing: what the
link learned (the peer, its servers and their ghosts) is held for the
grace period (`[link] grace`, seconds, default 60) without telling local
clients or other links. Requests to a held ghost answer `Unreachable`,
and a held server is still its link's to the Loop and Tag checks, so no
other link can claim it meanwhile. Its dialer, if this server dials,
tries the peer at least every quarter of the grace while it holds them,
whatever its backoff has reached, so an outage that ends inside the
grace comes back inside it. A link replaced by a newer one for the
same peer (a redial over a half-open link) is held the same way, for the
new link to take back. Any other ending (`Unlinked`, `ProtocolError` and
the rest) parts everyone at once, as does removing the peer while it is
held.

When the peer is back, `Hub::resume`, after its Hello, takes what was
held: a Hello naming a different server means the old one is gone and
its ghosts leave. Held servers return, and once the new Link Servers is
complete (`Hub::servers_settled`) those it no longer names are forgotten
with their users. The same epoch means its user IDs still name the same
people, so the snapshot reconciles as it does any snapshot: ghosts it
names stay, with their uids, and the rest leave. A new epoch means the
peer restarted: a held ghost is re-used, under the ID the peer now
gives it, for a user with the same home server, name and icon, and the
rest leave. Past the grace without the peer back, everything held
leaves, as do a restarted peer's ghosts still unmatched if its link
drops before its snapshot. This server's own shutdown closes its links
for a `Shutdown` and then lets none in and dials none, so its peers hold
its users rather than take them into a link it is about to drop. Ghosts are not marked away meanwhile, and
nothing is said in chat, both the extension's MAYs.

## 8. Server identity and configuration

- **The server key** is `[link] key`, its own file, generated on first run
  by `load_key` and kept out of the accounts directory, so copying the
  accounts to set up another server does not copy the server ID. An
  operator MAY point it at the identity key (`key = "identity"`), so peers
  can check the fingerprint against discovery, at a cost the
  configuration documents: `hxd link reset-id` would then rotate the ng
  `server_key` too, and so refuses while the key is shared.
- **The server ID** is derived from the key, from the first link on.
  `hxd link reset-id` works on a stopped server, like every operator
  command: the restart drops its links, which peers take as an
  interruption, as they would a `Shutdown`, and its next Hello names the
  new ID, which is all the extension asks of an ID change. It never closes
  them with `Unlinked`, which would stop its peers' dialers. It says what it
  costs: bans this server placed under its old ID can no longer be
  lifted, so an operator lifts the ones they want lifted first.
- **The epoch** is random at each start.
- **Suspensions** persist across restarts, in a state file beside the key,
  as do trusted addresses (§7.1).

```toml
[link]
tag = "hx"                  # 1-8 printable ASCII, unique in the network
color = 0x3a7bd5            # suggested color for this server's users elsewhere
show_tags = false           # on to tag every ghost, for clients without colors (§3.5)
grace = 60                  # seconds what an interrupted link learned is kept
max_ghosts = 2000           # across all links (§3.6)
# key = "link-server.key"

[[link.peer]]
name = "janus-home"
dial = "janus.example:5600" # or accept = true
protection = "key"          # "key" or "tls"
key = "ed25519:b64..."      # the peer's public key, base64url, prefix optional (Janus writes it); checked for canonical form and small order at load
account = "link-hx"         # the account the peer issued this server, or this server's for the peer
# password = "..."          # tls mode only: what the peer issued
features = ["chat", "msgs", "info", "transit"]
ghosts = 1000               # this link's bound
```

- A key-mode entry needs no account (§7.1). A tls-mode accepting entry's
  account (L8) has a password generated with at least 128 bits of entropy
  and shown once.
- SIGHUP re-reads `[[link.peer]]`: an entry removed closes its link with
  `Unlinked`, a changed key with `ProtocolError`, as the extension
  specifies; a new entry starts dialing.
- Operator commands are offline processes, as every `hxd` command is:
  `hxd link suspend <name>` and `resume` write the state file, which the
  server applies on SIGHUP; `hxd link status` reads a status file the
  server rewrites as links change; `hxd link reset-id` as above.

## 9. Testing

- **Unit**, in `hxd-link`: each transaction's parse and build against the
  extension's tables; the ID tables; the checks of §7.4; the key proof
  against fixed exporter values in both roles; text conversion and the
  byte maximums. In `hxd-core`: `ChatCommit` with enqueued ghost lines
  interleaved with waiting submitters, never left without a leader.
- **E2E**, a new `crates/hxd/tests/link.rs`: two (three for relaying)
  in-process servers linked in key mode over loopback TLS, each with a
  scripted classic client and an ng client.
  - A user on one server appears on the other on both wires, with mhxd's
    user list bytes, and leaves; the tracker count does not include
    ghosts.
  - **Every classic transaction and ng request that names a uid fails for
    a ghost** exactly as for a uid nobody holds, except the translated
    ones. One table-driven test over the classic list `NAMES_A_USER`,
    which a unit test checks against the dispatcher's source, so a new
    uid-reading arm fails until it is listed.
  - Chat crosses both ways, formatted by the receiver, in order; a
    media-only line does not cross; a user's last line before leaving is
    heard; public chat keeps flowing while ghost lines stream in.
  - A private message crosses and is answered on both wires; a ghost
    whose link does not carry them is greyed out on a classic client and
    refused on both.
  - Kick, ban, unban and their persistence; a failed ban keeps the ghost
    hidden and is not announced; purge of a ghost spares a local user
    with the same name.
  - A dropped link inside the grace period shows nothing; past it, a
    netsplit; a Janus-style redial over a half-open link is `Replaced`.
  - A slow peer is closed and resynchronized, and costs the other link and
    local users nothing.
- **Interop** with Janus 2.0.19, by hand with fogWraith first, then
  scripted if Janus can run in CI.

## 10. Staging

Each stage is a branch with its tests. Nothing lands before its first
use: dead code fails `-D warnings`.

| Stage | What | Covered by |
|---|---|---|
| L0 | Prerequisites with no link: uid quarantine, Colored Nicknames on the classic wire | unit, `nick_colors.rs` |
| L1 | `hxd-link`: capability bit 11, key mode, accept and dial, the handoff, `Replaced`, continuous authorization, Hello and its checks, Ping, Close, empty Link Servers; receiving the peer's Servers, Server Updates and Gones | `link.rs` |
| L2 | Users over one link, including users homed behind the peer: snapshot, update, gone; `ghosts`, `roster_rows`, `RemoteRef`; ghosts on both wires; bounded fan-out; **the fail-closed table test** | `link.rs` |
| L3 | Public chat both ways: ghost lines staged on arrival and committed by one task, text rules, ghost lines in the log | `link.rs` |
| L4 | Private messages and user info: the router, answered on a task (classic) or in place (ng) | `link.rs` |
| L5 | Kick, ban and unban on both sides; the requester's ban records; purge of a ghost's lines | `link.rs` |
| L6 | Interruption, grace, reconciliation, epoch | `link.rs` |
| L7 | Relaying between this server's own links: servers, users, chat and requests passed on between transit links | `link.rs` |
| L8 | Verified TLS, trusted addresses, `hxd link` commands, metrics and the ghost gauge (built; the rest planned) | `link.rs`, `limits.rs`, `metrics.rs` |
| L9 | User keys, after the end-to-end document | later |

L1 to L3 make a test link with Janus. **L5 is the minimum for a real
network**: the extension makes moderation part of every link, always
honored, and a server that cannot carry out a ban on its own user should
not link with anyone.

**Janus dependency.** Key mode needs Janus 2.0.19, still in development.
If it is late, a test link with Janus needs verified TLS, which L8 would
have to move ahead of L1.

## 11. Open questions

- **Blocking a ghost.** The inbox's blocking keys on mailboxes, which a
  ghost does not have, and the extension refuses acts it does not
  translate. A local mute of a ghost may be worth having; a block that
  follows a person needs user keys.
- **Detached sessions.** A detached ng session stays on the roster as away
  and stays exported the same way, so a resume inside its grace is
  invisible to the network.
- **The tunnel.** A peer that can reach hxd-ng only over WebSockets could
  link over `/trtp` if the ng port terminated TLS in process. Left out
  until someone needs it.
- **Load.** A login storm on one server is a storm of joins on every linked
  server. The bounds above handle a burst, but `hxd-load` should grow a
  two-server scenario before linking is on by default
  (`docs/load-testing.md` §8).
