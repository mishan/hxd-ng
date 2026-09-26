# Avatars

A user's picture, shown beside their name on both wires, that nobody
else needs an icon set to see. On the legacy wire it is fogWraith's
**GIF Icons** extension, as mhxd and Janus serve it. On the ng wire it
is an `avatars` capability: an `avatar` on the `user` object, bytes over
HTTP, and a content-addressed fetch a client can cache for good. The two
are one avatar: whichever wire set it, both wires show it.

The classic 16-bit icon id stays exactly as it was, on both wires. An
avatar is shown in its place by a client that has one to show; a client
that does not keeps drawing the icon.

## 1. What an avatar is

An avatar is an image this server encoded (`docs/inline-media.md` §3):
sniffed, walked, probed, decoded under the codec's ceilings and
re-encoded, so it carries no metadata of any kind. On top of that
pipeline it is **fitted**: scaled down, keeping its aspect ratio, until
neither side exceeds `max_dimension` (128 by default). Format follows
source, as for inline media: JPEG stays JPEG, PNG and a still GIF
become PNG, and an animated GIF stays an animated GIF, every frame
fitted — unless re-encoding it (every frame at full canvas) comes out
larger than `max_bytes`, in which case the avatar is its first frame.

Each avatar has two renditions:

| Rendition | For | Rule |
|---|---|---|
| **canonical** | ng clients | As above. |
| **legacy GIF** | GIF-icon clients on the legacy wire | At most 256 pixels a side, which is as large as GtkHx decodes one, and within `legacy_max_bytes` (32 KiB, the extension's recommendation): the canonical animation when it is both, the animation fitted again to 256 when only the canvas is too large, and otherwise a GIF this server makes from the first frame, scaled down until it fits. An avatar that cannot fit has none, and legacy clients see no avatar for that user. |

An avatar's **id** is the SHA-256 of its canonical bytes, in lowercase
hex. The same picture uploaded twice is the same id, and a given id
always names the same bytes: that is what lets a client cache a fetch
for good (§4.3).

## 2. Whose avatar it is

An avatar belongs to its **owner**, and outlives the session that set
it:

| Session | Owner | Lifetime |
|---|---|---|
| A named account | The account's login | Until changed or cleared, on any wire, from any session of that account. |
| A guest that proved an identity | The identity's fingerprint | The same, for every guest session of that identity. |
| Any other guest | None | The session: `guest` is a login many people share, so it cannot own a picture. |

A session's avatar is its owner's avatar, loaded when the session logs
in and before anyone is told the session exists, so a join never
arrives without the picture and is never followed by a change to add
it. Every live session of an owner shows the same avatar: setting it
from one changes it on all of them, and each change is announced once
per session.

The durable store is the shared SQLite file (`[avatars] db`, or the
database `[inbox]`, `[history]` or `[news]` names). A server with none
keeps avatars in memory, which still carries an account's avatar from
one session to the next until the process restarts.

## 3. The legacy wire: GIF Icons

The extension's four transactions, as the reference servers answer
them (`mhxd/src/hxd/rcv.c`, `rcv_icon_*`):

| Transaction | Request | Reply |
|---|---|---|
| Get Icon List (1861) | — | One `0x0301` entry per visible user **that has a legacy GIF**. |
| Set Icon (1862) | `0x0300`: a GIF, or empty to clear | Bare task. |
| Get Icon (1863) | `0x0067`: the uid | `0x0067` and `0x0300`, empty when the user has no avatar. |
| Icon Change (1864) | — (pushed) | `0x0067`: whose avatar changed. |

Where this server differs, on purpose:

- **Set Icon validates.** The payload must begin `GIF87a` or `GIF89a`,
  as the extension says a server should check, and must go through the
  pipeline like any other image. mhxd stores whatever arrives.
  A refusal is a task error with readable text.
- **A user who joins already wearing an avatar is announced with Icon
  Change**, after the join. A user-list row cannot carry a picture, and
  a GIF-icon client fetches one only when told of a change; on mhxd the
  change came from the client, which set its icon again after every
  login.
- **Icon Change is sent only to sessions that have used the
  extension.** A session becomes GIF-icon aware the first time it sends
  1861, 1862 or 1863 — which GtkHx does right after login, since the
  extension has no capability bit and its clients probe for it. mhxd
  sends 1864 to everyone; a 1.x client that never heard of the
  extension has no reason to be handed transactions it does not know.
- **Get Icon for a uid nobody holds** is a task error; mhxd leaves it
  unanswered.
- **An empty entry is omitted from the list**, which the extension
  allows, rather than listed at length zero as mhxd does.
- **The list fits one transaction.** GtkHx and mhxd's own client accept
  a transaction of up to 1 MiB (`MAX_HOTLINE_PACKET_LEN` on the client
  side), so the reply stops adding entries before it would pass that,
  and each user left out is announced with Icon Change straight after
  it, which is what makes a GIF-icon client fetch them one at a time.
  mhxd sends every entry, however many.

## 4. The ng wire

### 4.1 Capability

`avatars` in `caps`, with a login block:

```jsonc
"avatars": {
  "max_bytes": 262144,          // the largest upload
  "max_dimension": 128,         // what an avatar is fitted to
  "types": [ "image/jpeg", "image/png", "image/gif" ]
}
```

### 4.2 The `user` object

A `user` object carries `avatar` when the user has one, and leaves it
out when they do not, as it does `identity`:

```jsonc
"avatar": { "id": "9f86d081…", "type": "image/png", "width": 128, "height": 96 }
```

A change to it is a `user_changed` event, like a change to a nick or an
icon, delivered to every session including the changer's own; one that
clears it is a `user_changed` without the key.

### 4.3 Bytes over HTTP

```
PUT /avatar
  Authorization: Bearer <session>.<token>
  <body: the image>

  200 { "avatar": { "id": …, "type": …, "width": …, "height": … } }

GET /avatars/{id}
  Authorization: Bearer <session>.<token>

  200  Content-Type: image/png
       Cache-Control: private, max-age=31536000, immutable
       ETag: "<id>"
       <canonical bytes>
```

`PUT /avatar` sets the calling session's owner's avatar. Refusals use
the media routes' statuses and error bodies (`docs/inline-media.md`
§8.2): 413, 415, 429 with `Retry-After`, 503. An owner gets one
attempt per `set_interval` (10 s) — refused or not, since a refused one
still cost a decode — and another inside it is 429 with `Retry-After`
set to the interval. The allowance is the owner's and not the
session's, because a change is shown on every session of the owner and
each of those is announced to everyone; a session-only guest is its own
owner. `avatar_clear` shares the allowance. A session that ends while
its upload is being decoded changes nothing: the change is pinned to
the session that asked, not to its uid.

`GET /avatars/{id}` answers for any avatar held by a session on the
roster, or stored for an owner; anything else is 404. Any session may
fetch any avatar — an avatar is shown to the whole server by design —
and the bearer is required only so that the server's users' pictures
are not a public web directory. Because the id is the content, a
response never changes and a client may keep it indefinitely.

### 4.4 Clearing

```jsonc
{ "id": 7, "req": "avatar_clear" }
{ "reply": 7, "ok": {} }
```

Clears the calling session's owner's avatar. Clearing what is already
clear succeeds and announces nothing.

## 5. Crossing the wires

| Set on | ng clients see | GIF-icon legacy clients see |
|---|---|---|
| ng, a PNG or JPEG | it | a GIF made from it (§1) |
| ng, an animated GIF | it | it, if within 32 KiB; otherwise its first frame |
| legacy, a GIF | its canonical rendition | the same GIF, re-encoded |

A classic client that never used the extension sees the icon id, as it
always has.

## 6. Configuration

```toml
[avatars]
max_bytes = 262144        # the largest upload, on either wire
max_dimension = 128       # what an avatar is fitted to
legacy_max_bytes = 32768  # the legacy GIF rendition's ceiling
set_interval = 10         # seconds between one session's changes
# db = "avatars.db"       # default: the shared database, if any
```

Absent means neither wire offers avatars: the legacy transactions are
answered as unknown ones, and ng has no `avatars` capability. It needs
the `media` Cargo feature, which carries the image pipeline.

## 7. Not yet

- **Moderation.** A moderator cannot yet clear someone else's avatar,
  and an avatar cannot be reported. Both belong with the acts of
  `docs/moderation.md`, audited like the rest.
- **Account removal** does not yet delete the stored avatar.
