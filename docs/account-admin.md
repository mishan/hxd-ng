# Account administration

Status: built, 2026-10 — the classic wire's user editor, the ng
`accounts` family and `hxd account`. Not built: an account rename, the
1.8 batch editor (348 List Users, 349 Update User), and the per-account
`[extra]` and `[identity]` settings over either wire, which stay the
operator's to edit in the file.

An account is a file in the accounts directory (`hxd-auth-file`). This
document is how it is changed without a shell on the host: from a
classic client's user editor, from an ng client, and from the command
line beside a running server. All three write through one backend
trait, `AccountAdmin`, and the two wires through one domain API,
`hxd_core::admin`, so who may change what is decided once.

## 1. Who may change whom

**Who** is the access bit each act has always needed (access-bits.md):
`read_users` to read or list, `create_users` to make, `modify_users` to
change, `delete_users` to delete.

**Whom** is narrower than mhxd, which let `modify_users` do anything to
anyone: a session may write or delete only an account that may do
nothing the session's own account may not, and may not leave one able
to. "May do" is the access bits and the server-local policy the file
grants beside them — `moderate`, `can_spam`, `set_subject`,
`attach_news`, `file_list`, `file_getinfo` — whether said in `[extra]`
or derived, since a new account given the kick bit moderates by
default. Not `can_detach`, `inbox` or `set_avatar`: those follow from a
password and say an account is one person, not what it may do to
anyone else, so a password-less administrator may still give an account
a password. Without that, `modify_users` is every privilege there is,
one edit of one's own account away. Both accounts are read as their
files say at that moment, by the backend with its writes held, so
neither is promoted or demoted between the check and the write; and the
session's own file must still grant the act's bit, as well as its
session.
Reading is not restricted this way. The operator, at the command line,
is held to none of it.

Setting a password is an edit like any other: an administrator who may
change an account whose only way in is a linked identity can give it a
password and log in as it, as mhxd's could.

## 2. What an edit changes

An edit names some of a login, a name, a password and the access
bitmap; what it leaves out stays as it was. A new account takes its
login as its name, no password, and no access.

The file backend rewrites only the keys an edit's bits change, with
`toml_edit`, so an operator's comments, `[extra]` and `[identity]`
survive any number of edits from any client. A set bit with no name goes
to `raw_bits`. Bit 56 (`read_chat_history`) with no key follows
`read_chat` (access-bits.md), so it is written out only where it parts
from it, and an account that never named it goes on following it.

Passwords are capped at 31 characters on every path, since a classic
login cuts its password there and a longer one could never be typed on
that wire. The file holds a recoverable secret, as it always has
(`hxd_core::account`).

## 3. A change reaches the account's sessions

Every session logged in as the account is brought up to date as the
edit lands: what it may do, the server-local policy its account file
derives (`can_detach`, `inbox`, `moderate`, …), its administrator color,
and — for an account that may not choose its own name — its nick. The
roster changes first, so the domain's own checks see the new access at
once; each frontend then hears `Event::AccountChanged` and updates its
copy. A classic client is sent fresh self-info (354), as at login; an ng
client is sent `account_changed` (§5.4). Either frontend handles what it
was sent before the next request, so a request that follows a change is
judged by the account as it now is.

Account writes are taken one at a time, from the file through telling
the sessions, so two edits cannot reach the sessions in the opposite
order from the file. A login that read its account before an edit began
and joined the roster after the edit told it is caught too: each write
counts itself, a login notes the count before authenticating, and if it
moved by the time the session is on the roster the account is read
again and applied — or, if it is gone, the login is refused.

Deleting an account disconnects every session logged in as it but the
deleter's own (mhxd's `kick_transients`, on by default there). Its mail
is left for `hxd inbox purge` — with `--fingerprint` for an account that
linked an identity, which `hxd account rm` prints, since nothing can say
it once the file is gone.

An edit made outside the server — `hxd account`, or a hand edit — is
applied the same way on SIGHUP (`Core::reload_accounts`): every session
is told what its account says now, and the sessions of an account that
is gone are disconnected. A new login sees any edit at once.

## 4. The classic wire

New User (350), Delete User (351), Open User (352) and Set User (353),
as mhxd answers them:

- Open User names its login in the clear; the others obfuscate it
  (XOR 0xff), as they do the password.
- Open User's reply carries `NAME`, the obfuscated `LOGIN`, a `PASSWORD`
  of a single NUL — never the password — and the 8-byte `ACCESS`.
- A Set User `PASSWORD` of that single NUL keeps the account's password,
  so saving what was opened changes no password. A Set User with no
  `PASSWORD` at all clears it, as mhxd's and Mobius's do: a period
  client's editor leaves the field out when its box is emptied. An empty
  name keeps the account's name.
- Set User makes an account that does not exist, as mhxd's does and
  GtkHx relies on, but only for a session that also holds
  `create_users`. New User refuses a login that is taken, where mhxd
  overwrote it.
- The period editors cannot show bit 56, so this wire leaves it as the
  account had it — following `read_chat` unless the file says otherwise
  — whatever the bitmap carries.

Each refusal is a task error with readable text. The spam table prices
them as mhxd's does.

## 5. The ng wire: the `accounts` family

Offered as the `accounts` capability whenever the server administers
accounts (hotline-ng.md §4). A server that does not answers the family
with `not_available`.

### 5.1 The login block

```jsonc
"accounts": { "access": ["read_chat", "send_chat", "read_users"], "raw_bits": [] }
```

What this session's account may do, for a client deciding what to offer.
`access` lists the names of access-bits.md (the `[access]` keys); bits
with no name are listed by number in `raw_bits`. The same object is the
data of `account_changed`.

### 5.2 Requests

| `req` | `params` | `ok` | Needs |
|---|---|---|---|
| `account_list` | — | `{ "accounts": [ { "login", "name" } ] }` | `read_users` |
| `account_get` | `login` | `{ "account": {…} }` | `read_users` |
| `account_create` | `login`, `name?`, `password?`, `access?`, `raw_bits?` | `{ "account": {…} }` | `create_users` |
| `account_update` | `login`, `name?`, `password?`, `access?`, `raw_bits?` | `{ "account": {…} }` | `modify_users` |
| `account_delete` | `login` | `{}` | `delete_users` |

- A login is case-insensitive and answered lowercase.
- `access` replaces the whole bitmap: the named bits it lists, plus the
  numbers in `raw_bits`, which is empty when omitted. A client editing
  an account sends back the `raw_bits` it was shown. `raw_bits` without
  `access` is `bad_request`.
- `password: ""` clears the password. Omitted, it is kept. An empty or
  omitted `name` keeps the account's, which for a new one is its login.
- `account_update` never makes an account.

**The account object:**

```jsonc
{ "login": "eve", "name": "Eve", "password": true,
  "access": ["read_chat", "send_chat"], "raw_bits": [41],
  "identity": "6htgz65…" }   // absent unless the account links one
```

`password` says whether one is set; the password itself never leaves
the server.

### 5.3 Errors

| Code | Meaning |
|---|---|
| `access_denied` | The session lacks the bit the request needs. |
| `outranked` | The account may do, or would be left able to do, something the session's own account may not: an access bit or the `[extra]` policy of §1. |
| `no_such_account` | `account_get`, `account_update`, `account_delete` of a login with no account. |
| `already_exists` | `account_create` of a login that has one. |
| `invalid_login` | Not a login: up to 31 letters, digits and `_ - . @`, not starting with `.`. A write to the server's own login answers it too; `account_get` and `account_delete` answer `no_such_account` for that login. |
| `bad_request` | Malformed, an access name that names no bit, a raw bit past 63, or a name or password past 31 characters. |
| `not_available` | The server does not administer accounts, whatever the session may do. |

### 5.4 The event

| `ev` | `data` | Sent when |
|---|---|---|
| `account_changed` | `{ "access", "raw_bits" }` (§5.1) | An administrator changed the account this session is logged in as (§3). |

The `sync` reply carries the §5.1 block too (hotline-ng.md §6.3), since
an `account_changed` may have been lost in the gap it recovers from.

## 6. The command line

```sh
hxd account list
hxd account show <login>
hxd account add <login> [--name N] [--access KEY,… | --like LOGIN] \
    (--password-stdin | --password-file F | --no-password)
hxd account passwd <login> (--password-stdin | --password-file F)
hxd account access <login> KEY=on|off…
hxd account rm <login>
```

Against the accounts directory directly, so they work with the server
down; a running server applies them on SIGHUP (§3). A password never
goes on the command line, where `ps` shows it to everyone on the host.
`add` takes its access from `--access`, from the account `--like` names
(the guest account is the usual template), or none; an account with no
password and no linked identity is an open door, so `--no-password` has
to be said. `access` leaves history as the file has it — following
`read_chat`, or set apart from it — unless the same command names
`read_chat_history`.

The command line and the server do not hold one lock between them, so
an edit made while the server links an identity to the same account can
lose one of the two; edit accounts while nobody is linking.
