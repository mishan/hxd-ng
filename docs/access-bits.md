# Account permissions: every bit, key and switch

What an account may do on this server is decided in three places, and
only the first of them crosses the wire:

- **The access bitmap** — the Hotline `[access]` bits, an 8-byte field
  every client since 1.2 knows how to read. Section 2 lists all of them.
- **`[extra]`** — server-local policy with no wire representation, for
  decisions the bitmap has no bit for and must not grow one. Section 4.
- **`[identity]`** — per-account switches over portable identity: whether
  a key may log in as this account, and who may link one. Section 5.

The reference for the bit numbering is mhxd's `struct hl_access_bits`,
mirrored in GtkHx's `src/hl_access.h`. The numbering here must match
those files bit for bit, because these bytes are interpreted by every
client ever shipped. `crates/hxd-core/src/access.rs` is where it lives,
and its tests pin the extension bits to both their numbers and the bytes
they set.

---

## 1. The bitmap

Eight bytes, big-endian, **bit 0 is the most significant bit of byte 0**
and bit 63 is the least significant bit of byte 7. `AccessBits` stores
bit *n* at `1 << (63 - n)`, so the wire form is the big-endian byte dump
and nothing has to be reversed on the way out.

Where it goes:

- **Legacy wire.** The real bits ride in `USER_SELFINFO`'s `ACCESS`
  field after login. This is a deliberate deviation: the reference server
  sends an all-ones constant there, and clients grey out what an account
  cannot do based on what they read — which only works if it is true.
- **ng wire.** The bitmap is never shipped. A client learns what the
  *server* offers from `caps` in the login reply, and what its own
  account may do by being refused: every gate answers `access_denied`.
  The one access-derived field on the ng roster is `admin`, which is
  bit 22.

Granting, in an account file (`hxd-auth-file`, one TOML file per
account):

```toml
[access]
read_chat = true
send_chat = true
send_msgs = true
# Bits with no name — reserved, or an extension this server has not
# implemented — go in by number.
raw_bits = [58]
```

Three rules worth knowing:

- **A key that is not a name is a startup warning, not a silent no.** A
  typo'd `send_msg` is logged as an unknown access key and ignored,
  because an account file that quietly grants nothing is worse than one
  that complains.
- **`chat_history` is accepted as an alias for `read_chat_history`**, for
  files written while the capability existed and the server side did not.
  New files use the spec's name.
- **Bit 56 falls back to bit 9.** If an account file mentions neither
  `read_chat_history` nor `chat_history` and grants `read_chat`, bit 56
  is set too — fogWraith's rule for an access system that predates the
  allocation. An explicit key, either way, wins.

---

## 2. The named bits

"Enforced" means this server checks it somewhere. "Parsed" means the key
is accepted, stored, and reported to clients in `SELFINFO`, but no code
consults it — the subsystem it governs is not implemented here yet, and
the bit is carried so that an account file written today stays correct
when it is.

### Files and folders (0–8, 25, 28–31, 38, 39)

Every one of these is **parsed**. Files and HTXF are an open front on the
roadmap; when they land, these are the bits they will read.

| Bit | `[access]` key | Meaning |
|---:|---|---|
| 0 | `delete_files` | Delete a file |
| 1 | `upload_files` | Upload into an upload folder |
| 2 | `download_files` | Download a file |
| 3 | `rename_files` | Rename a file |
| 4 | `move_files` | Move a file |
| 5 | `create_folders` | Create a folder |
| 6 | `delete_folders` | Delete a folder |
| 7 | `rename_folders` | Rename a folder |
| 8 | `move_folders` | Move a folder |
| 25 | `upload_anywhere` | Upload outside the designated upload folders |
| 28 | `comment_files` | Set a file's comment |
| 29 | `comment_folders` | Set a folder's comment |
| 30 | `view_drop_boxes` | See the contents of a drop box |
| 31 | `make_aliases` | Create an alias |
| 38 | `upload_folders` | Upload a whole folder |
| 39 | `download_folders` | Download a whole folder |

### Chat (9, 10, 11)

| Bit | `[access]` key | Meaning | Status |
|---:|---|---|---|
| 9 | `read_chat` | Receive public chat. Also the predicate for a public line's *image* audience — a session that does not read chat is not captured when a picture is relayed — and the fallback source for bit 56 | **Enforced**, both wires |
| 10 | `send_chat` | Send public chat | **Enforced**, both wires |
| 11 | `create_pchats` | Open a private chat and invite to it | **Enforced**, legacy wire — the ng protocol has no private chats yet |

### User administration (14–17)

All **parsed**. There is no account administration over either wire; a
server's accounts are files an operator edits.

| Bit | `[access]` key | Meaning |
|---:|---|---|
| 14 | `create_users` | Create an account |
| 15 | `delete_users` | Delete an account |
| 16 | `read_users` | Read an account's settings |
| 17 | `modify_users` | Change an account's settings |

### News (20, 21, 33–37)

All **parsed**. News is an open front; `docs/news.md` is its design, and
the ROADMAP notes these numbers are already reserved for it.

| Bit | `[access]` key | Meaning |
|---:|---|---|
| 20 | `read_news` | Read news |
| 21 | `post_news` | Post to news |
| 33 | `delete_articles` | Delete an article (1.5+ threaded news) |
| 34 | `create_categories` | Create a category |
| 35 | `delete_categories` | Delete a category |
| 36 | `create_news_bundles` | Create a bundle |
| 37 | `delete_news_bundles` | Delete a bundle |

### Moderation, identity and presence (22, 23, 24, 26, 27, 32)

| Bit | `[access]` key | Meaning | Status |
|---:|---|---|---|
| 22 | `disconnect_users` | Kick a user. Also what sets `admin` on the roster on both wires, and the default for `[extra] set_subject` | **Enforced**; the kick itself is legacy-wire |
| 23 | `cant_be_disconnected` | Cannot be kicked — checked on the *target* of a kick | **Enforced**, legacy wire |
| 24 | `get_user_info` | Read another user's info. Reading your own never needs it | **Enforced**, legacy wire |
| 26 | `use_any_name` | Choose a nickname rather than being given the account's name | **Enforced**, both wires |
| 27 | `dont_show_agreement` | Skip the agreement at login | **Enforced**, legacy wire — ng has no agreement dance, it publishes the text in the server info |
| 32 | `can_broadcast` | Send a server-wide broadcast | **Enforced**, legacy wire |

### Private messages (40)

| Bit | `[access]` key | Meaning | Status |
|---:|---|---|---|
| 40 | `send_msgs` | Send a private message | **Enforced**, both wires |

Whether a message can be *stored* for an account that is not connected is
a separate question with no bit: see `[extra] inbox` in section 4.

### Extensions (55–60)

fogWraith allocates these upward from 55. They are extension bits, so a
client that never negotiated the matching capability never sees the
traffic they gate — but the bit is what decides whether a client that
*did* is allowed to act.

| Bit | `[access]` key | Meaning | Status |
|---:|---|---|---|
| 55 | `voice_chat` | Join a voice room | **Enforced**, both wires |
| 56 | `read_chat_history` | Request scrollback. Falls back to bit 9 when unmentioned — see section 1 | **Enforced**, both wires |
| 57 | `send_media` | Upload an image and reference it from a chat line or a private message. **Off unless an account file says so**: an image is the one thing a user can put on everyone else's screen without their asking, so an operator grants it rather than an account inheriting it | **Enforced** in the domain, so both wires |
| 59 | `video_chat` | Publish camera video in a voice room | **Enforced**, both wires |
| 60 | `screen_share` | Publish a screen share. **Its own bit, deliberately** — showing your face and showing your desktop are different trust decisions, and a screen share can leak documents, credentials and other people's messages in a way a camera generally cannot. Neither bit implies the other | **Enforced**, both wires |

---

## 3. Reserved numbers

These have no name and no `[access]` key. They are still *representable*
— `raw_bits` takes any number below 64 — because some deployed servers
use the reserved ones privately and a server that could not round-trip
them would corrupt an account it was only reading.

| Numbers | Why they are reserved |
|---|---|
| 12, 13, 18, 19 | Reserved in the reference headers. mhxd's "everything enabled" constant leaves them clear, which is the cross-check `access.rs` tests against |
| 41–54 | Unallocated between the last classic bit and the first extension |
| 58 | `AccessMessaging`, allocated by fogWraith's messaging extension. Not implemented here; the number stays reserved so the video bits do not drift onto it |
| 61–63 | Unallocated above the current extensions |

Nothing in this tree should claim one of these. New server-local policy
belongs in `[extra]`, which costs no wire vocabulary at all.

---

## 4. `[extra]`: policy that never crosses the wire

mhxd's `access_extra` concept. These are per-account decisions with no
bit and no client-visible representation, which is exactly why they are
here and not in the bitmap. Every one of them is optional, and an absent
key derives a default rather than being false.

| `[extra]` key | Meaning | Default when absent |
|---|---|---|
| `can_detach` | May a session outlive its connection — the ng detach/resume path | A password *or* a linked identity. What disqualifies an account is not the missing password but the missing person: `guest` is one login several people share, and a drive-by should not get to park a nick on the roster |
| `set_subject` | May this account set the public chat subject | Tracks `disconnect_users`, preserving the reference server's spirit of a config-granted privilege rather than a wire bit |
| `inbox` | May private messages be stored for this account and delivered later | The same rule `can_detach` derives by, for the same reason: queuing mail against a shared login hands it to whoever logs in next |
| `attach_news` | May this account stage durable images for news posts | Tracks `send_media` (bit 57), so image-upload policy has one default on both chat and news while an operator may narrow either account. Either way only an account that is one person stages: a staged handle is its uploader's, and `guest` is several people |

---

## 5. `[identity]`: who may be this account

Per-account switches over portable identity
(`docs/hotline-ng-identity.md`). Not permissions in the bitmap sense —
they say who may *become* this account rather than what it may do.

| `[identity]` key | Meaning | Default |
|---|---|---|
| `fingerprint` | The identity key linked to this account | none |
| `login` | May the linked key log in, as against only being recognized | `true` |
| `allow_self_link` | May a holder link their own key to this account | `true` |
| `reserve_name` | Is the account's name reserved for the linked identity | `false` |

An account with no password and `login = false` can be reached by
nothing. `unlink` refuses to write that state; an operator typing it by
hand gets a startup complaint instead.

---

## 6. What a new server starts with

**The bootstrap guest.** First run writes `guest.toml` with the bits a
stranger can be trusted with — `read_chat`, `read_chat_history`,
`send_chat`, `create_pchats`, `send_msgs`, `get_user_info`,
`use_any_name` — and a commented-out `send_media` with a note saying to
read `inline-media.md` before uncommenting it. No password, so
`can_detach` and `inbox` both derive false. Deleting the file disables
guest logins.

**Accounts identity creates.** With `[identity] new_accounts = create`, a
holder authenticating with an unknown key gets an account, and
`[identity.default_access]` says what it starts with — the same key names
an account file uses, validated against the same table, so a typo there
is a startup error rather than a surprise later. It has no effect unless
`new_accounts = create`, and says so in the log if set anyway.

---

## 7. Where to look in the tree

| | |
|---|---|
| `crates/hxd-core/src/access.rs` | `AccessBits`, the `bit` constants, the wire round-trip, the tests that pin the numbering |
| `crates/hxd-auth-file/src/lib.rs` | `NAMED_BITS`, the `[access]`/`[extra]`/`[identity]` tables, the bit-56 fallback, the guest bootstrap |
| `crates/hxd-session/src/session.rs` | Legacy-wire gates, and `SELFINFO`'s real bitmap |
| `crates/hxd-ng-session/src/conn.rs` | ng gates, all answering `access_denied` |
| `crates/hxd-core/src/media.rs` | Bit 57, checked in the domain so both wires inherit it |
