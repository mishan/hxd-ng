# Roles: permissions shared by name

Status: G1 and G2 are built (§14): the roles file, resolution,
`everyone`, reload, §6.1's minimal overrides and the command line, §5's
rule for giving and taking roles, the info line and the commands of
§6.2 and §6.3. Its `@` login reservation is built on its own. Of G3,
§7 is built but for `role_in_use`, which nothing can call for until
gates take roles (G4) and restrictions exist (G7).
The rest is design. §7, §9.4, §11.3 and §12.5 are the ng spec; the rest
binds nobody but this server.

An account's permissions today are its own: an access bitmap and an
`[extra]` table in its file, written one account at a time. That is
Hotline's model and mhxd's, and it does not scale past a handful of
staff. Promoting someone to moderator means copying a dozen keys from
another file by hand, and changing what moderators may do means editing
every moderator. KDX had account *classes* for this; Discord has
*roles*. This document adds roles, and makes them what gates a room
([chat-rooms.md](chat-rooms.md) §5) and a news category.

**Decisions (2026-10):**

- **A role is a named set of grants:** access bits and `[extra]` policy,
  plus a display title, color and position. An account holds any
  number of roles. There is no inheritance between roles.
- **The account file can still say anything.** A key in an account's
  `[access]` or `[extra]` overrides its roles, either way: `true` grants
  what no role does, `false` withholds what a role grants. An account
  with no roles reads exactly as it does today.
- **Configuration and circumstance are kept apart.** Roles and the
  account file are an account's *configuration*: what an administrator
  set, what an editor shows, and what "who may change whom" compares.
  Restrictions and probation are *circumstance*: a deny mask the server
  holds on the session, which lifts without anyone editing the account.
  The permissions a session acts with are the configuration under the
  mask (§3).
- **Every client sees the result, never the parts.** The classic wire
  carries effective permissions. Roles appear on the wire only in the
  ng `roles` family and in display.
- **A classic editor edits configuration, and the server keeps the file
  minimal.** A save writes an override only where a bit differs from
  what the roles give, and removes overrides that have come to match
  (§6.1).
- **Who may change whom is still one rule**, account-admin.md §1's,
  over configuration, extended to what roles add: the keys only roles
  and rooms introduced, and holding a role something is gated on (§5).
- **Some roles take away.** A *restriction* is a role that only
  withholds, such as `muted`. A moderator applies it to someone, for a
  time or until lifted, as a moderation act with a reason and an audit
  row. Nothing in an account file undoes one (§9).
- **Period administrators can edit roles as `@role`.** In a 1.5 client's
  user editor, opening the login `@moderators` opens the role (§6.4).
- **Rooms and news are gated by the same lists.** A room's and a news
  node's `read` and `post` lists hold logins and `@role` entries (§10,
  §11). A gated news node is invisible to everyone it does not admit.
- **Roles and people can be mentioned.** `@moderators` or `@alice` in a
  chat line notifies the role's holders, or the person, if they can read
  that room. The line itself is delivered exactly as typed (§12).

---

## 1. Where we are

- An account is `accounts/<login>.toml`: `name`, `password`, `[access]`
  (named bits, `raw_bits`), `[extra]`, `[identity]`
  (`hxd-auth-file`). Its `[access]` keys are true or false, and false
  and absent mean the same thing today.
- `[extra]` keys that are absent derive defaults, several from a bit
  (`set_subject`, `can_spam` and `moderate` track `disconnect_users`,
  bit 22; `attach_news` tracks `send_media`, bit 57). Bit 56 follows
  bit 9 unless the file names it.
- `hxd_core::admin` decides who may change whom (account-admin.md §1):
  `beyond()` compares the bits and the `[extra]` keys `set_subject`,
  `file_list`, `file_getinfo`, `attach_news`, `moderate` and
  `can_spam`. Account writes are taken one at a time, and
  `apply_account` copies the backend's `Account` onto every session of
  it and sends `AccountChanged` (§3 there). SIGHUP applies edits made
  outside the server (`Core::reload_accounts`).
- The frontends gate on their own copy of the account, fed by
  `AccountChanged`.
- The classic editor (350–353) reads and writes an 8-byte bitmap, and
  cuts a login at 31 characters. The ng `accounts` family carries named
  bits and `raw_bits`.
- `[identity.default_access]` gives accounts that identity creates their
  starting bits. `[identity.probation] access` is designed to mask a
  session on probation (identity-registrar.md §7.5) and is not built.
- Nick colors are fogWraith's Colored Nicknames: a client chooses its
  own color, and the server relays it (`UserInfo::color`).
- Get User Info's text on the classic wire is composed by this server
  (`name`, `login`, `address`, `online`).

## 2. The role

### 2.1 What a role is

| Field | Meaning |
|---|---|
| `name` | The key: 1–30 characters, lowercase ASCII letters, digits, `-` and `_`, starting with a letter or digit, since a leading `-` reads as taking a role away on a command line. Unique. 30, so that `@name` fits a classic login's 31 (§6.4) |
| `title` | What clients show, e.g. `Moderators`. Up to 31 characters, a classic `NAME`'s. Defaults to `name` |
| `color` | Optional `0xRRGGBB`. §8 |
| `position` | Display order: the user list groups by it and the highest colored role colors a nick. It is **not** authority (§5) |
| `access` | Named bits and `raw_bits`, as an account file's table. Only `true` means anything in a role: a role grants, it never withholds |
| `extra` | `[extra]` keys, the same way, from §5's list only |
| `mentionable` | May `@name` in chat notify its holders (§12). Default false |

### 2.2 `everyone`

One role is built in: **`everyone`**, held by every account, the
bootstrap guest included. It is defined, like any role, in the roles
file, and it starts empty. It is how an operator says "every account may
read news" once. Because it reaches the guest, the file's comment says
so where it is written. It cannot be deleted, and it cannot be named in
a gate (§10).

### 2.3 Where roles live

One file, `[roles] file` (default `roles.toml`, in the working
directory like every relative path in the config),
edited through `toml_edit` so comments survive, like account files and
the rooms file:

```toml
# Roles on this server. hxd role and ng administrators edit this file.
# `everyone` is every account, the guest included.
[role.everyone]
access = { read_news = true }

[role.moderators]
title = "Moderators"
color = 0x2e8b57
position = 20
mentionable = true
access = { disconnect_users = true, get_user_info = true }
extra = { moderate = true }

[role.regulars]
title = "Regulars"
position = 10
access = { upload_files = true, send_media = true }

[role.muted]
kind = "restriction"     # §9
title = "Muted"
deny = { send_chat = true, send_msgs = true, send_media = true }
```

And an account names its roles:

```toml
# accounts/alice.toml
name = "Alice"
password = "…"
roles = ["moderators", "regulars"]

[access]
send_media = false      # an override: regulars may, Alice may not
```

- **A name in `roles` that no role has** is a startup warning and
  grants nothing, like an unknown access key. A restriction's name
  there is the same warning: restrictions are applied, not held (§9).
- **A roles file that does not parse** is a startup error, and on a
  reload leaves the roles as they were and logs why. A server that came
  up without its roles would come up without every restriction's
  definition, and a mute that silently lifts at a restart is worse than
  a server that will not start. A file naming an access key that does
  not exist is refused the same way, where an account's is a warning: a
  typo in a role fails every holder at once. Until restrictions are built (G7), an
  entry with `kind` or `deny` is refused the same way, so a file
  written for them is never read as granting what it meant to withhold.
- **`false` in a role means nothing**, so `hxd role access … KEY=off`
  removes the key rather than writing it.
- **Writes are serialized** under the account-write lock, held from
  the file write through telling the last holder, as an account edit
  holds it. The file is written whole and renamed into place. `hxd
  role` writes it beside a running server without the lock: the server
  reads the file as it is on disk just before changing it, so an edit
  made since is kept, and it is what new logins resolve with from then
  on. Sessions already logged in are given a hand edit by SIGHUP.

## 3. Resolving an account

Resolution has two halves, in two places.

**Configuration**, resolved by `hxd-auth-file` from the files:

1. **Roles.** The union of `everyone`'s and every listed role's
   `access` and `extra` grants.
2. **The account's own keys.** Each `[access]` and `[extra]` key
   present sets its value, true or false, over step 1. `raw_bits`
   grants raw bits and `raw_deny` withholds them, since a list of numbers
   has no way to say `false`. Bit 56 is named by either of its keys, by
   `raw_deny`, or by a role granting it, and only then stops following
   bit 9.

**The mask**, held by `hxd-core` on the `UserSession`:

3. **Restrictions** in force on the account or the session (§9), and
   **probation** when the session is on it, each a set of keys to deny.
   It is reapplied in `apply_account` before `AccountChanged` is sent,
   so an account edit can never wash it out, and changed by applying or
   lifting a restriction.

**Derivation**, one function in `hxd-core` that both halves call:

4. **Defaults derive last.** Bit 56, where nothing named it, follows
   bit 9. An `[extra]` key nothing named derives from the bits as they
   now stand, as today. Because this runs after the mask, a mute that
   denies `send_media` also leaves `attach_news` false, and one that
   denies `read_chat` takes bit 56 with it.
5. **A denial reaches what derives from it**, even where configuration
   named the derived key: denying bit 9 denies bit 56, denying bit 57
   denies `attach_news`, denying bit 22 denies `moderate`, `can_spam`
   and `set_subject`. A mask means what it says whatever an account
   file spelled out.

*Configuration* is steps 1, 2 and 4 without the mask: what the classic
editor opens, what the ng account object carries, and what
account-admin.md §1 compares. *Effective* is all five: what a session
acts with, what SELFINFO and the `accounts` login block carry, and what
`account_changed` reports.

`Account` gains `roles: Vec<String>` for display and for the ng editor.
A gate in `hxd-core` asks whether the session has a bit, as now, or,
for a room or a news node, whether its account is named or holds a
named role (§10).

**The meaning of `false` changes, and nothing breaks.** Today `false`
and absent are the same in an account file, because nothing else
grants. Under roles, `false` withholds what a role grants. A file with
no `roles` key and no `everyone` grants resolves exactly as before.

## 4. Changes reach sessions

A role edit is an account edit for every account holding it (or every
account, for `everyone`). It is taken under the account-write lock
(account-admin.md §3) and applied as an account edit is: each affected
session's configuration first, under its mask, so the domain's gates
see it, then `Event::AccountChanged`, so a classic client gets fresh
self-info (354) and an ng client `account_changed`. The write counter
counts role writes too, so a login that read its account before the
edit is caught.

**No role edit may push a session near its queue's cap** (AGENTS.md's
slow-consumer invariant). A role's title, color and position reach ng
clients as one `roles_changed` (§7.3), coalesced to at most one a few
seconds, and clients redraw from it: nobody is sent a `user_changed`
per holder for a display change. A change that does alter holders'
roster rows (bit 22's administrator flag, or who holds the role)
sends `user_changed` per holder while there are few. Past `[roles]
bulk_rows` rows changed at once, by any account change, a role edit
or a reload, an ng session is sent one `roster_stale` instead,
and answers it with `sync`. Each sync costs a whole roster, so the
threshold sits where that is cheaper than the rows. A classic session gets its 301s through
its writer's byte budget like any other burst. A role's color
reaches classic clients as each holder's next 301 or login, not as a
burst of its own.

`hxd role` edits the file, as `hxd account` does an account's, and the
operator sends SIGHUP (`systemctl reload`); `Core::reload_accounts`
then reads the roles again and re-resolves every session, keeping its
mask. A hand edit of the roles file is followed by the same signal.

## 5. Who may

account-admin.md §1's rule, that a session may write only an account
that may do nothing the session's own account may not, and may not
leave one able to, compares **configuration** (§3), never the mask: a
muted administrator is still an administrator to it. Roles extend what
it compares:

- **`manage_roles` and `manage_rooms` join `beyond()`'s keys.** So does
  every `[extra]` key a role may grant: a role's `extra` accepts only
  keys `beyond()` compares. That leaves out the keys that say an
  account is one person, `can_detach`, `inbox`, `set_avatar` and
  `vouch`: a role, `everyone` most of all, must never let a shared
  login detach or receive mail.
- **Holding a gated role is a privilege.** A role that a room's or a
  news node's `read` or `post` list names is something an account "may
  do", in `beyond()`'s sense, exactly as a bit is. So a session can give
  `@staff` to someone, itself included, only if it holds `@staff`
  itself or `manage_roles`, and cannot make itself a member of a room
  by assigning itself the role that gates it.

**Assigning a role** is an account edit: `modify_users`, under that
rule. A restriction cannot be assigned: it is applied (§9).

**Creating and editing a role** need `[extra] manage_roles` (default
false), and an edit is allowed only when:

- the role, before and after the edit, grants nothing the session's
  configuration lacks; and
- every account holding the role is one the session may edit under
  account-admin.md §1. Without this, a moderator could strip a role an
  administrator also holds and take bits from them.

**Deleting a role** needs the same, and is refused while anything
still names it: a room's or a news node's gate, or, for a restriction,
a restriction in force. Removing the last entry of a gate would open
what it gated, so a gate is changed on purpose before its role can go.
Deleting removes the name from every account file that lists it, under
the account-write lock.

`everyone` is held by every account, so editing it needs a session that
outranks every account on the server. In practice that means the
operator at the command line, who is held to none of this, as for
accounts.

There is deliberately **no role hierarchy** in Discord's sense (a role
may act on roles below it). Here the subset rule already says who may
touch whom, from what the accounts can actually do, and a second,
positional answer could only disagree with it. `position` orders the
display and nothing else.

## 6. The classic wire

### 6.1 The user editor

A period client's user editor shows one bitmap and saves one bitmap.
It cannot show roles, so it is given the account's **configuration**,
and a save is read as "the account's configuration should end up
exactly these bits":

- **Open User (352)** sends the configuration. A restriction is not
  configuration, and an editor that showed it would turn "save" into
  "make the mute permanent".
- **Set User (353)** compares each bit it carries with what the
  account's roles alone give. Where they match, the account's override
  for that bit is **removed**. Where they differ, an override is
  written: `true` or `false`. So saving an account unchanged writes
  nothing. Unchecking a bit a role grants writes `false`. Re-checking
  it later removes that `false`, and the account follows its role again.
- **New User (350)** makes an account with no roles, then overrides as
  for 353.
- A bit above what the editor can show (access-bits.md §1: 40 for 1.5)
  is left as the account had it, as account-admin.md §4 says, so a bit
  only a role gives, such as 55 or 57, goes on following the role.

The cost: an override pins its bit against later role edits. That is
what the administrator asked for, and easy to forget. And 353 carries
the bitmap as it stood at 352, so the session remembers what 352
showed, and a bit the save leaves as shown keeps what the account has
now: a role narrowed, or the account's roles changed, between opening
and saving is not written back as an override. `hxd account
show`, the ng editor and §6.3's `/role` show overrides apart from what
roles give, so they can be found and cleared.

### 6.2 Seeing roles

Get User Info's text, which this server composes, gains a line for the
target's roles, highest position first, in mhxd's format:

```
    name: alice
   login: alice
   roles: Moderators, Regulars
 address: …
```

That is the only place a period client sees a role. Its user list shows
the administrator color (bit 22) as it always has.

### 6.3 Commands to the system account

Role assignment has no field on the classic wire, so it is a command
(system-account.md §3), run as the session with the ng request's
checks:

| Command | Does | Needs |
|---|---|---|
| `/roles` | Lists the roles, highest first, with their holders' count | `read_users` |
| `/role <login>` | The account's roles and its overrides | `read_users` |
| `/role add <login> <role>`, `/role remove <login> <role>` | Assigns or takes away a role | §5 |

An account is named by its login, never by a nick: anyone can take a
nick that names someone else, and a role given to the wrong account is
a privilege given away.

A role's own grants are edited as §6.4's pseudo-account, from the ng
wire, or from the command line. Restrictions are applied with
`/restrict` (§9.4).

### 6.4 `@role`: a role in the period user editor

A 1.5 client's user editor opens an account by the login typed into it.
It has no list to browse (that is 1.8's 348, which is not built). So a
login beginning with `@` names a role, and the editor's four
transactions act on the role:

| Transaction | On `@name` | Needs |
|---|---|---|
| Open User (352) | `NAME` = the role's title, `LOGIN` = `@name`, `PASSWORD` = the single NUL, `ACCESS` = the role's access grants | `read_users` |
| Set User (353) | `ACCESS` replaces the role's access bits, and a changed `NAME` its title. Its `extra`, color, position, mentionability and raw bits past the bitmap are kept, since the editor cannot show them, and so are the bits above its tier (access-bits.md §1). A role that does not exist is refused, "No such role.": roles are made with 350 | `manage_roles`, and §5's edit rule |
| New User (350) | Creates the role, with the bitmap as its grants | `manage_roles`, and grants the session's configuration has |
| Delete User (351) | Deletes the role, under §5's delete rule | `manage_roles`, and §5's edit rule |

`@everyone` opens and saves like any role and cannot be deleted. A role
has no password: a 353 with or without `PASSWORD` keeps it so, and a
350 with a typed password is refused, "A role has no password." A
restriction cannot be opened here: its bits mean "withheld", and a
period editor would draw them as granted. It answers "Edit restrictions
from an ng client or the command line."

**The `@` is reserved.** A login may not begin with `@`. Every write
path refuses one as `invalid_login`, and identity's `new_accounts =
create` never makes one. A login attempt as `@anything` is refused as
an unknown account, by the auth backend, the way the system account's
login is. `@` is a legal login character today, so an existing account
file whose login begins with it disables this section with a startup
warning naming the file, and stays an account, rather than either
quietly shadowing the other.

Whether the official 1.5 and 1.9 editors let `@` be typed into Open
User is G6's to test. GtkHx's does.

When 348 List Users is built, roles list after the accounts, as
`@name`, so a 1.8 editor finds them the same way.

## 7. The ng wire

### 7.1 The login reply

Capability `"roles"`, present whenever the server administers accounts
(the roles file is always configured, and an absent one is `everyone`
granting nothing), and requests of the family answer `not_available`
without it. A `roles`
block lists the roles:

```jsonc
"roles": {
  "list": [
    { "name": "moderators", "title": "Moderators", "color": 3050327,
      "position": 20, "mentionable": true },
    { "name": "regulars", "title": "Regulars", "position": 10 }
  ],
  "manage_roles": true            // present when this session may
}
```

The **`user` object** gains `roles`, the names of the user's roles,
absent when empty. Restrictions are never in it. The `sync` reply
carries the `roles` block too, since a `roles_changed` may have been
lost in the gap it recovers from.

### 7.2 Requests

| `req` | `params` | `ok` | Needs |
|---|---|---|---|
| `role_list` | — | `{ "roles": [ role… ] }`, with grants, restrictions included, and `holder_count` | `read_users` |
| `role_get` | `name` | `{ "role": {…}, "holders": [ login… ] }` | `read_users` |
| `role_create` | `name`, `title?`, `color?`, `position?`, `mentionable?`, `access?`, `raw_bits?`, `extra?`; or for a restriction `kind: "restriction"`, `title?`, `deny` | `{ "role": {…} }` | `manage_roles`, §5 |
| `role_update` | `name`, then any of `role_create`'s fields but `kind`; `color: null` clears it | `{ "role": {…} }` | `manage_roles`, §5 |
| `role_delete` | `name` | `{}` | `manage_roles`, §5 |

Errors besides account-admin.md §5.3's: `no_such_role`, `already_exists`
(a name taken by `role_create`), `role_in_use` (deleting a role a gate
or a restriction in force names), and `bad_request` for deleting or
renaming `everyone`, a `kind` change, or an `extra` key §5 does not
allow in a role. `outranked` covers §5's conditions.

**The account object** (account-admin.md §5.2) carries configuration,
never the mask:

```jsonc
{ "login": "alice", …,
  "access": ["read_chat", "send_chat", "disconnect_users"],  // configuration (§3)
  "raw_bits": [],
  "roles": ["moderators", "regulars"],
  "grant": ["upload_files"],        // the account's own true keys
  "deny": ["send_media"],           // its own false keys
  "raw_grant": [], "raw_deny": [] }
```

`account_create` and `account_update` gain `roles`, which replaces the
list, and accept **either** `access` with `raw_bits` (configuration:
the server keeps overrides minimal, as §6.1 does for 353) **or**
`grant`, `deny`, `raw_grant` and `raw_deny` (the overrides, written as
given). Both kinds together are `bad_request`. An editor that
understands roles sends overrides. A client written before roles sends
`access` and gets §6.1's behavior, which is the right one for it, and,
because `access` is configuration, cannot make a mute permanent.

**Weights and prices.** The role writes weigh what `account_*` writes
do in `request_weight`, and spend spam points at the price of 353, their
classic counterpart. `role_list` and `role_get` weigh what `account_list`
does.

### 7.3 Events

| `ev` | `data` | Sent when |
|---|---|---|
| `roles_changed` | `{ "list": […] }`, as in the login reply | A role was created or deleted, or its title, color, position or mentionability changed. To every session, coalesced (§4). Clients redraw names and colors from it |
| `user_changed` | as now | The roles a user holds changed, or a role edit changed their roster row (§4) |
| `roster_stale` | `{}` | One change, a role edit or a reload most often, changed more roster rows than `[roles] bulk_rows`. The client sends `sync` |
| `account_changed` | as now | This session's effective access changed, by a role, the account, or the mask |

A change to a role's grants alone is not `roles_changed`. It reaches
holders as `account_changed`, and nobody else needs it.

## 8. Display

- **Grouping.** An ng client may group its user list by each user's
  highest role, in position order, as Discord's member list does.
- **Color.** A role's color is a **default**, not an override: a user
  who chose a nick color (Colored Nicknames) keeps it, and one who did
  not is drawn in the color of their highest colored role. The server
  sends that color as the user's color on both wires, so a classic
  client that negotiated Colored Nicknames draws it without knowing
  roles exist. On ng the client works it out from `user.roles` and
  `roles_changed`, so a color change reaches nobody as a burst (§4).
- The administrator affordance (`admin` on the roster, red in a 1.x
  user list) stays bit 22, however the bit was granted.

## 9. Restrictions: roles that take away

### 9.1 What one is

A restriction is a role with `kind = "restriction"` (§2.3's `muted`). It
has a `deny` table of access and `[extra]` keys and nothing that
grants. Applied, it joins the session's mask (§3 step 3). **Nothing
undoes a restriction but lifting it**: not a role grant, not an account
override, not an administrator saving the account in an editor, since
editors see configuration and the mask is not configuration. Grants are
a union, overrides are the account's last word on its configuration,
and restrictions are a second union, of denials, applied after both.
No two rules are ever weighed against each other: a bit is withheld if
any restriction withholds it.

**A restriction is not configuration.** An operator does not put
`muted` in an account file and leave it there; that is a warning (§2.3).
A permanent "this account may never post" is an override, `post_news =
false`, which is what the account file is for. A restriction is *done
to* someone, so it lives where moderation's acts live. It cannot be
held, assigned, or named in a gate.

Probation (identity-registrar.md §7.5) is a mask too, applied by the
server rather than by a moderator, and shares the mechanism. It is not
a restriction role.

### 9.2 Applying one

A restriction is a moderation act (moderation.md §3) beside redact,
revoke and purge:

- **Who:** a session that may moderate (moderation.md §2), against a
  target it may moderate there, and never itself. Denying anything of
  administrative weight, which means `moderate`, `can_spam`, the
  `manage_*` keys, or the user-administration and moderation bits
  (14–17, 22, 23), also needs account-admin.md §1's rule against the
  target: a moderator cannot silence an administrator's ability to
  moderate, and two moderators cannot race to mute each other's tools.
  The restriction may deny only what the moderator's own configuration
  holds.
- **What:** one restriction role, a reason, and optionally a duration.
  With a duration it lifts itself at the end, by the sweeper, on
  `Core`'s clock so a test can move it. Without one it lasts until
  lifted.
- **Whom:** an account, which reaches every session of it and every
  later login, and the identity fingerprint the session logged in with,
  if any, so the same key on a new account is restricted too. For an
  account that is not one person (the guest, or any account with neither
  password nor identity, by the rule `can_detach` derives by), it is
  the **session**, and that account's other sessions from the same
  address for the duration, so a muted guest cannot reconnect out of it.
  An address-keyed restriction always has a duration, at most `[roles]
  max_address_minutes` (default a day), and never reaches an account
  that is one person: carrier-grade NAT puts strangers behind one
  address, and AGENTS.md already counts a logged-in person by account
  rather than by address for that reason.
- **Recorded:** a row in the moderation table with who, whom, what, why,
  when and until, like every act. Lifting is a row too.
- **Told:** the target hears it from the system account as a private
  message on the classic wire, and as a `restricted` event on ng (§9.4):
  what was restricted, why, and until when. A restriction nobody is
  told about looks like a bug. Lifting is told the same way.

**Lifting** needs what applying needed, against the same target, and
is never done to oneself: a muted moderator stays muted until someone
else, or the clock, lifts it.

Applying or lifting changes the session's mask and sends
`account_changed` and fresh self-info (354), so a classic client greys
out what it may no longer do.

Restrictions need the moderation store, as bans do. A server without
one has no restrictions, and the requests answer `not_available`.

### 9.3 Seeing one

- The target's own sessions see their effective permissions, as always,
  and were told why.
- Moderators see restrictions through `restrictions` (§9.4) and Get
  User Info, which gains a `restricted:` line, naming each and when it
  lifts, for a session that may moderate the target.
- Everyone else sees nothing. A mute is not a public stocks, and a
  restricted user's nick is drawn as before. Nothing on the `user`
  object says it, so the roster encodes one way for everyone.

### 9.4 The requests and commands

ng, in moderation.md §5's family:

| `req` | `params` | `ok` |
|---|---|---|
| `restrict` | exactly one of `uid` / `login` / `fingerprint`, `role`, `reason`, `minutes?` | `{ "id" }` |
| `unrestrict` | `id`, `reason?` | `{}` |
| `restrictions` | `uid?` / `login?` / `fingerprint?` | `{ "restrictions": [ { "id", "role", "target", "by", "reason", "at", "until"? } ] }` |

Errors: moderation.md §5's for its acts (`protected`, `no_such_user`,
`outranked`), plus `no_such_role`, `bad_request` for a role that is not
a restriction or a target that is the session itself, and
`no_such_restriction`. Weights and spam prices are `kick`'s.

**The `restricted` event**, to the target's sessions: `{ "role",
"title", "reason", "until"?, "lifted"? }`.

To the system account, for a period moderator:

| Command | Does |
|---|---|
| `/restrict <who> <role> [<minutes>m] <reason…>` | Applies it. `/restrict alice muted 30m spamming links` |
| `/unrestrict <who> [<role>]` | Lifts that one, or every restriction on the user |
| `/restrictions [<who>]` | What is in force |

And `hxd restrict` / `hxd unrestrict` / `hxd restrictions` at the
command line, against the running server's database with SIGHUP, as
`hxd ban` is.

## 10. Gates

A room's (chat-rooms.md §5) and a news node's (§11) gates are lists
whose entries are **a login or `@role`**. The `@` tells them apart, so
a login and a role may share a name. An account passes a gate when an
entry names it or a role it holds. An empty list passes everyone the
access bit already passes.

- A gate may not name `@everyone`, which would admit the guest while
  looking restrictive; an empty list already means everyone. It may not
  name a restriction.
- Passing a gate is decided from configuration: the roles the account
  holds and its login. A restriction narrows what a member may *do*
  (a muted member of `#staff` may read it but not post), not which
  gates it passes.
- **Gates are rechecked when they change.** An edit to a gate, a change
  to the roles an account holds, or an account edit that takes away what
  a gate needs, parts the account's sessions from rooms it no longer
  passes (chat-rooms.md §6.4, §7.3) and hides the news it can no longer
  see (§11.2).

## 11. News

news.md §8 gates the whole tree with `read_news` (20) and `post_news`
(21), and §18 there names per-category permission as an open question,
with two warnings: a period client that can see a category's name but
not its contents, and a reference that confirms an article exists in a
category the reader cannot see. Gates answer it, and the warnings
decide how.

### 11.1 Gates on a node

A bundle or a category may carry §10's two lists:

| Field | On | Meaning |
|---|---|---|
| `read` | bundle, category | Only accounts it admits see the node and anything under it. Empty: everyone with `read_news` |
| `post` | category | Only accounts it admits may start a thread or reply here. Empty: everyone with `post_news` who may read it |

The bits still come first: a gate narrows `read_news` and `post_news`
and never widens them. **Gates compose down the tree**: to see a
category, a reader must pass the `read` of every bundle above it and of
the category, so a "Members" bundle gates everything filed in it
without repeating itself on each child.

Moderators and `manage_roles` holders see every node, as moderators
and room managers see every room (chat-rooms.md §5): keeping house and
judging reports both need it.

### 11.2 Invisible, not locked

**A node a reader may not see does not exist for that reader**, on both
wires and everywhere a node or an article can surface:

- **Listings.** The ng tree and the 1.5 directory listing (news.md
  §12.2) leave it out, and a bundle's child count counts only what the
  reader can see. A period client is never shown a name it cannot open,
  which was §18's first worry.
- **Search** filters by the reader's visibility inside the query, never
  after the page is cut, so a page is never short and never hints.
- **References and backlinks** resolve against the **reader's**
  visibility (news.md §18's last fix, which this makes required). A
  reference into a gated category reads as unresolved, exactly as a
  reference to an article that does not exist.
- **Attachment bytes** over HTTP (news.md §9.4) need a live article in
  a node the requester can see. A gated attachment answers `404`, as an
  unknown one does.
- **Events and notifications** (news.md §9.3's events, follows, the
  pushes of news.md §10, the 1.2 flat push) go only to sessions and
  accounts that can see the node *when they are delivered*. Someone who
  loses sight of a node is sent `news_node_deleted` for it, as news.md
  §9.3's rule for a stale cache implies, and stops hearing a thread they
  followed there.
- **Requests naming it** answer as for a node that does not exist:
  `no_such_node`, or the 1.5 task error for a bad path.

**The 1.2 flat category** (news.md §12.5) is the only news a 1.2 client
reaches, so gating it would show every 1.2 reader an empty board with
no explanation. Gating the flat category, or a bundle above it, is
refused. A server that wants members-only news for 1.2 users makes
members-only *accounts*, not a gated category.

**Feed categories** (news-feeds.md) can be gated like any other. `post`
means nothing on one, since nobody posts there.

### 11.3 Setting gates

A node's gates are set with the bit that creates its kind
(`create_categories` (34) or `create_news_bundles` (36)), from the ng
wire or the command line, with one more rule: **the session must still
see the node afterwards**, unless it holds `manage_roles`. Gating a
category to a role you do not hold would make it vanish from under you
with no way to undo it from your own client.

- ng: the node object (news.md §9.2) gains `read` and `post`, sent to
  sessions that may set them. `news_node_access { id, read?, post? }`
  sets them: a list replaces, `[]` clears, absent keeps. Errors besides
  news.md §9.2's: `no_such_node`, `access_denied`, `bad_request` (an
  entry that is neither a login nor `@role`, `@everyone`, a restriction,
  or `post` on a bundle), `would_hide` (the session would no longer see
  it), `flat_category` (§11.2). It weighs what `news_node_create` does.
- Classic: no field exists. A period administrator sets gates from an
  ng client or the command line, and a period reader just sees the tree
  they can see.
- `hxd news access <path> --read entry,… --post entry,…`.

The gates are columns on the node in the news store. §5 refuses to
delete a role a gate names, so a gate never names a role that does not
exist, and an empty gate always means a choice someone made.

## 12. Mentions

### 12.1 What a mention names

push-notifications.md §11 left chat mentions open because nicks are not
unique on a Hotline server and change freely, and a mention that
notifies the wrong person is worse than one that misses. Two things
close that:

- **A role** is unique by name and the server knows exactly who holds
  it, so `@moderators` is a mention by construction, the way a news
  reference is (news.md §10.5).
- **A person** is named by the nick the sender sees, **resolved when the
  line is committed**, against the roster at that instant: the sessions
  wearing that nick then, which is who the sender was looking at in the
  user list. A rename a minute later changes nothing, because the
  mention was already resolved. A nick is ambiguous over time but not at
  a single instant, and a mention only ever needs that instant.

### 12.2 The amendment to "public chat is never parsed"

system-account.md §1 says a line typed into chat is chat, whatever it
starts with. What that rule protects is that a period user typing
`/report` or `@moderators` into the room sees exactly that said to the
room. A mention keeps that: the line is committed, logged and delivered
**exactly as typed**, to exactly the audience it would have had, and
nothing in it is swallowed, rewritten or acted on as a command. The
rule becomes:

> **Public chat is never parsed as a command.** A line typed into chat
> is chat, delivered as typed, on every wire. The one thing the server
> reads in it is a mention (roles.md §12), and only to notify, never
> to change what the room hears.

### 12.3 What counts

The server finds the tokens `@name` in a line where `@` is at the start
of the line or follows whitespace or an opening bracket, so
`alice@example.com` mentions nothing. Then, first match wins:

1. **A role**, case-insensitively, that is `mentionable` and not a
   restriction, mentioned by a session of an account that is one
   person. A guest cannot ring a role: it is many people behind one
   login, and one of them could ring the moderators all evening.
2. **A nick on the roster**, case-insensitively, of a local session
   that can read the room. Nicks may hold spaces, so the server takes
   the **longest** roster nick the text after `@` begins with, and the
   character after it must not continue a word: `@Misha N, look` finds
   `Misha N` when that nick is on, and `Misha` when only that is.
   **Several sessions wearing the nick** are all mentioned: a rare
   duplicate notified twice is better than the real person missed, and
   is what the sender's user list showed anyway. A ghost is not a
   target: its home server rings it (below).
3. **A login**, exactly, of an account that is one person and has no
   session on the roster, so that an ng account offline can still be
   pushed (§12.4). A reserved name is its account's login
   (hotline-ng-identity.md §9), so it resolves here too. The sender is
   never told whether this matched: a mention is not a way to ask
   whether an account exists.

A token that names nothing is just text, and the line keeps its
spelling either way. Roles are matched first, so a nick that collides
with a mentionable role's name mentions the role. The person is still
reachable by login.

Steps 1 and 2 are resolved under the roster lock while the line is
committed, since they are lookups in memory. Step 3, and everything that
delivers a mention, run after the room's serial is released: no file is
read and no push is sent while a room's lines wait (chat-rooms.md §3).

Only public chat and rooms are read. **Private chats are never
parsed**: they are not public and are not logged, and the expectation
chat-history.md protects there covers this as well.

**A line that arrives over a server link** (Link Chat, 904) is read for
**people only** (step 2), and only for this server's own users: each
home server rings its own. No link field carries a mention, so a linked
server that does not read mentions simply does not notify, and nothing
on the wire changes. Roles are never read in a relayed line: another
server's `@moderators` is not this one's. The home server resolves the
nick when the line arrives, not against the roster the sender saw, and
a nick worn on two servers is rung on both (§15). Every server hears a
relayed line once and rings only its own users, so a server in the
middle of three neither rings twice nor adds anyone.

### 12.4 Who hears it

The mentioned people, and the holders of each mentioned role, **who can
read the room the line was said in**, are not the sender, are not
restricted from reading it, and have not blocked the sender
(private-messages.md). The read check matters most on the classic wire,
because what a classic recipient receives carries the text: a mention
in `#staff` must never reach anyone outside it.

| Recipient | Receives |
|---|---|
| ng, attached | The `chat` event, if it is in the room, carrying `mentions`; the client highlights the line itself. If it is not in the room, a `mention` event (§12.5) |
| ng, detached or idle, or offline with registered devices | A push, by push-notifications.md §6's rule, which already names mentions. The payload is the room and the line id, and the text only as the account's content policy allows. Coalescing chat pushes is push-notifications.md §11's open question, and this does not answer it |
| classic, online | A private message from the system account (§12.6), when the account has asked for them |
| classic, offline | Nothing |

Someone mentioned more than once in one line, by name and by a role or
by two roles, hears it once.

### 12.5 The ng wire

Capability `"mentions"`, present unless `[roles] mentions = false`.

- **The `chat` event gains `mentions`**, what passed §12.3, absent when
  nothing did: `{ "roles": ["moderators"], "users": [7, 12] }`. Users
  are uids, which the roster already shows everyone, and never logins. It
  is the same for every recipient: a client knows its own uid and roles
  and decides whether the line is for it. One encoding per line, as
  fan-out wants. A client MUST NOT highlight a line it sent.
- **The line keeps them.** The log row gains a `mentions` column, holding
  the roles and the mentioned accounts, or the nick for a session with
  none. A `history` line, answered per request, carries
  `mentions: { "roles": […], "you": true }`, with `you` present when
  the reader's account was mentioned, so a highlight survives
  scrollback without a login ever reaching a reader.
- **`mention`**, a new event, `{ "room"?, "id"?, "at", "from": { "uid",
  "nick" }, "roles"?, "text" }`, goes to a mentioned session that is
  attached and not in the room, so a client can badge a room it has not
  joined. `id` is the line id, absent without history, so the client
  can page to it with `history`.

### 12.6 The classic wire

A period client has no highlight a server can set. What it has is the
private message, which opens a window and plays a sound. Using that is
a change to what a 1.5 user experiences from typing anyone types, so it
is **opt-in**: `[roles] mention_messages` (default `false`) sets it for
the server, and a user overrides it for their own account with
`/mentions on` or `/mentions off` to the system account, kept in a
`[prefs]` table in the account file, written back as other edits are.
`[prefs]` holds what a user chose for themselves, which is not policy
and does not belong in `[extra]`.

A recipient who has asked for them gets one message from the system
account (system-account.md §2):

```
[#lobby] alice: @moderators someone's posting links in here, can you look?
(Reply in #lobby. Messages here go to Server.)
```

The message names the room, the sender's nick and the line, in the
recipient's encoding, cut to 4096 bytes at a character boundary. It
does not come from the sender's uid: the sender did not write a private
message, and a reply landing in their window as if they had would be
the server putting words in a window they did not open. A reply to it
that is not a command, within a few minutes of a mention message, is
answered with that one line again rather than with `/help`.

An extended client gets the same message, if it asked. A capability
that let GtkHx highlight the line in place belongs in chat-rooms.md
§8's proposal.

### 12.7 Abuse

A mention is one line that rings many doorbells, so it has more limits
than a line of chat:

- **A cooldown per sender and target**, `[roles] mention_cooldown`
  (default two minutes), whether the target is a role or a person. The
  sender is the account, the address for an account that is not one
  person, and the link peer for a ghost, so neither reconnecting nor a
  linked server minting ghosts resets it. A mention inside the cooldown
  is delivered as chat and notifies nobody, and the sender hears a
  notice, `*** @moderators was mentioned recently; nobody was
  notified.` A notice and not silence, because a mention that quietly
  fails is how someone in trouble learns not to ask.
- **A ceiling per target across senders**: a role or a person is rung
  at most a few times a minute by everyone together, so many guests
  cannot each ring once.
- **Coalescing per classic recipient:** at most one mention message
  every thirty seconds. Mentions in that window are summed up in one
  message sent when the window ends, `… and 3 more mentions in
  #lobby`, after checking that the recipient can still read each room
  it names.
- **Spam points:** a line costs more for each token that could be a
  mention, priced like a private message each, and charged when the
  line is priced, before it is committed, as every line is. A run stops
  short of the line that would spend the last point, as now.
- `can_spam` exempts from the cooldown, the ceiling and the price, as it
  does from every other limit. It never exempts a recipient from
  coalescing.

A redaction (moderation.md §3.1) cannot recall a classic mention
message already sent, and does not try. On ng the `mention` event and
the push carry the line id, so a client that hears `chat_redacted` can
drop its notification as well as the line.

A mention is not a report. `/report` and the ng `report` request are
structured, tracked and closed with an outcome. A mention is a shout in
the room. Both should exist.

## 13. What else changes

- **`[identity] default_roles`** joins `[identity.default_access]`, so
  an identity-created account can start as a `member` rather than with
  a copied bitmap. Roles come first, and `default_access` is that
  account's overrides.
- **`hxd account`** gains `roles <login> [+role|-role…]`, `show` prints
  roles and overrides separately, and `add --like` copies roles as well
  as overrides.
- **`hxd role`**: `list`, `show <name>`, `add <name> [--title …]
  [--color …] [--position n] [--access KEY,…]`, `access <name>
  KEY=on|off…`, `extra <name> KEY=on|off…`, `rm <name>`. Against the
  files directly, so they work with the server down. A running server
  applies them on SIGHUP. `rm` checks §5's delete rule against the
  rooms file and, where the news store can be opened, the news gates,
  and refuses when it cannot tell; until gates are built (G4, G8) there
  is nothing to check. It takes the name out of the account files
  first, so a removal cut short can be run again. `hxd account access`
  sets the file's own keys, and writes `false` only where something
  else grants the bit.
- **Server links.** Roles do not cross. A ghost has none, and its home
  server decides what it may do.
- **Tests.** `crates/hxd/tests/accounts.rs` grows the role cases
  (§14). Configuration (§3's steps 1 and 2) is a table-driven unit test
  in `hxd-auth-file`, one row per combination of role grant, account
  `true`, account `false` and absence, for a bit, for bit 56 and for a
  derived `[extra]` key; the mask's rows are `hxd-core`'s, beside
  derivation.

- **Configuration**, all keys optional:

  ```toml
  [roles]
  file = "roles.toml"          # §2.3; relative to the config file
  mentions = true              # §12; off removes the capability
  mention_messages = false     # §12.6; classic mention messages, server default
  mention_cooldown = 120       # seconds, per sender and target (§12.7)
  bulk_rows = 64               # §4; past it, ng sessions get roster_stale
  max_address_minutes = 1440   # §9.2; the longest address-keyed restriction
  ```

**Amendments to companion documents:**

- **account-admin.md** §1: configuration, not effective; `manage_roles`
  and `manage_rooms`; gated roles as privileges (§5). §4: §6.1's
  minimal overrides and §6.4's `@` logins. §5.2: the account object's
  configuration fields and overrides (§7.2). §5.3: `invalid_login`
  covers a leading `@`.
- **access-bits.md** §4: `manage_roles`; roles' `extra` keys; `[prefs]`.
  §5: the probation mask as part of §3's mask.
- **moderation.md** §2: restricting and lifting (§9.2). §3: the
  restrict act. §5: its requests and the `restricted` event. §7: the
  restriction table and its act kinds.
- **system-account.md** §1: §12.2's wording. §3: `/role`, `/roles`,
  `/restrict`, `/unrestrict`, `/restrictions` and `/mentions`, and the
  reply to a mention message.
- **hotline-ng.md** §4: `roles` and `mentions` rows. §7.4: `mentions`
  on `chat`, and the `mention`, `roles_changed`, `roster_stale` and
  `restricted` events.
- **chat-history.md** §4: the `mentions` column. §7.2: `mentions` on a
  history line.
- **news.md** §8: §11's gates. §9.2: `news_node_access` and the node
  object's gates. §18: the per-category question and the reference
  oracle, answered here.
- **push-notifications.md** §11: the mention question, answered by §12.
- **identity-registrar.md** §7.5: probation as §3's mask.

## 14. Staging

1. **G1 — resolution and files.** The roles file, `roles` in account
   files, §3's two halves with derivation last, `everyone`, `hxd role`
   and the account CLI's additions, reload, §6.1's minimal overrides,
   and the `@` reservation, so no account can take one before G6. The
   overrides come this early because every save of an account goes
   through them: one that wrote a role's bits into the file would pin
   them there, and a role taken away later would take nothing. Unit
   tests: saving unchanged writes nothing, unchecking a role's bit
   writes `false`, re-checking clears it. No wire changes: a role's
   grants are simply there, in SELFINFO and on every gate.
2. **G2 — who may, and the classic editor.** §5's checks on giving and
   taking roles in `hxd_core::admin`, §6.2's info line, §6.3's
   commands, and §6.1's save remembering what 352 showed. E2E in
   `accounts.rs`: a moderator refused a role that grants what it lacks,
   and refused taking it from someone who holds it; a role granting
   `manage_rooms` refused to someone without it; a role given reaching
   the holder's sessions on both wires; a role changed while the editor
   was open not saved over. Holding a gated role as a privilege waits
   for `@role` gate entries (G4).
3. **G3 — the ng wire.** §7 whole, without `kind` until G7, and §5's
   checks on creating, editing and deleting a role, which nothing but
   `hxd role` can do before it. E2E: a role edit refused while an
   administrator holds the role.
4. **G4 — gates.** §10, on chat-rooms.md's R1 and R2.
5. **G5 — display.** §8's colors on both wires, user lists grouped by
   role in hx-ng.
6. **G6 — `@role`.** §6.4. Exit: the official 1.5 editor opening and
   saving `@moderators`.
7. **G7 — restrictions.** §9, on moderation's store and audit trail,
   with the mask of §3. Unit tests: a mute denying `send_media` leaving
   `attach_news` false; one denying `read_chat` leaving no history; an
   account edit, and a reload, leaving a mask in place; a moderator
   refused lifting its own restriction and restricting an
   administrator's `moderate`; an address-keyed restriction reaching a
   guest on that address and not a person.
8. **G8 — news gates.** §11, with the visibility tests first: a
   reference into a gated category unresolved for an outsider and
   resolved for a member, a search never returning a gated article to an
   outsider, an attachment `404` to an outsider, a gated category absent
   from a 1.5 client's directory listing, `news_node_deleted` to a
   reader who loses a role, gating the flat category refused, and
   deleting a role a gate names refused.
9. **G9 — mentions.** §12, on chat-rooms.md's R1 and R2 and G3. E2E: an
   `@moderators` line reaching an ng holder as `mentions` and, once it
   has asked, a classic holder as a message from the system account; a
   classic holder that has not asked sent nothing; `@alice` reaching
   her on both wires, and an offline ng account pushed by login; a nick
   with a space found by the longest match; a rename after the line
   changing nothing; two sessions with one nick both mentioned; a guest
   mentioned as its session only and unable to ring a role; a block
   silencing a mention; a mention in `#staff` reaching no one outside
   it; a non-mentionable role and an e-mail address notifying nobody;
   the cooldown's notice; a classic recipient's burst summed up when
   the window ends; over a link, `@alice` from the peer ringing alice
   here, `@moderators` from the peer ringing nobody, and a server in
   the middle of three ringing its own users once; a history line
   carrying `you` for the mentioned reader only.

## 15. Open questions

- **Role color against a user's own color.** §8 lets the user's own
  choice win. Discord does the opposite. Whether staff should be
  unmistakable or users should keep what they picked is a community's
  decision, and may want a setting once someone asks.
- **Room-scoped restrictions.** A mute in `#trading` only is Discord's
  channel overwrite. It needs a mask per room where §3 keeps one per
  session, and the room's chat gate checking it. Worth doing when a
  room-level mute is asked for.
- **Probation as a restriction role.** Probation already shares §3's
  mask. Making it a built-in restriction would give it §9.3's
  visibility to moderators, at the cost of a reserved role name and
  a mask that a moderator might be able to lift. Decide with
  identity-registrar.md §7.5 when probation is built.
- **Renaming a role.** `title` covers what people see. A rename would
  have to rewrite account files, gates in the rooms file and the news
  store, and the moderation table's restrictions, across a file and a
  database with no transaction between them.
- **Hidden roles.** A role that is mechanism, not identity
  (`can-upload`), shown on no wire. Every role is visible for now, and
  a client can draw only the ones with a color.
- **More mention reach.** `@everyone` and `@here` (behind the broadcast
  bit), roles choosing who may mention them, queuing role mentions for
  offline classic holders, mentioning someone offline by display name,
  and queued mail for a person mentioned while offline (which needs
  system-account.md §4's mailbox). Each widens what one line can do,
  and none is needed to prove the rest.
- **Mentions resolved by the sender's server, across a link.** §12.3
  has each home server read relayed lines for its own users, which
  needs no wire change. The alternative is for the origin to resolve,
  and Link Chat (904) to carry the link user ids it resolved, under a
  new field and link feature: the mention would mean exactly what the
  sender saw, and roles could cross where both servers agreed what one
  meant, but a hostile peer could fabricate targets, which text alone
  cannot. A proposal to fogWraith (server-link.md), to make only if
  resolution at the home server is seen to go wrong in practice.
- **Upstream.** fogWraith has nothing for roles or groups. If GtkHx
  wants to edit roles, a proposal goes with chat-rooms.md §8's.
- **Gating the file area.** KDX had folder access lists by class, and
  §10's lists would fit a folder. The file area's visibility rules
  (drop boxes, a folder holding one) are the place to start.
