# hxd-ng web client

A browser client for the **Hotline-ng** wire: public chat, the user list
with the classic icons, private messages, and the voice and video the
SFU already serves. It talks only the JSON/WebSocket protocol in
[`docs/hotline-ng.md`](../docs/hotline-ng.md) — it never sees the legacy
wire, and the server cannot tell it apart from any other ng client.

## Running it

Against a server on this machine:

```sh
cargo run --bin hxd            # [ng] bind = "127.0.0.1:5700"
cd client && npm install && npm run dev
```

`npm run dev` serves on <http://localhost:5701> with hot reload. The
default server URL in the connect form is `ws://127.0.0.1:5700`, which
is where `hxd` puts the ng listener.

A production build lands in `dist/` and is a directory of static files —
no server-side anything:

```sh
npm run build
cd dist && python3 -m http.server 8080
```

`dist/` is a build artefact and is **not** committed — it would churn on
every change. `public/icons.png` and `public/icons.json` are, because
they change only when `icons.rsrc` does, and committing them means
running the client needs no Python.

### Serving it to a phone, and why voice needs https

`getUserMedia` and `getDisplayMedia` do not merely *fail* outside a
secure context — `navigator.mediaDevices` is **undefined** there. So a
phone opening `http://titan:5701/` over the LAN gets chat, the roster and
private messages working perfectly and no microphone at all. The client
detects this and says so in the voice bar instead of throwing; there is
no way around it from the page's side.

Two ways to get a secure context for testing:

```sh
# a tunnel, so the phone's browser sees localhost
ssh -L 5701:localhost:5701 -L 5700:localhost:5700 titan

# or a real certificate in front of both, which is what production wants
# anyway: https for the page, wss:// for the ng endpoint
```

The ng spec mandates WSS in production for its own reasons; the same
certificate serves the page. `localhost` counts as secure, which is why
the development setup above works unencrypted on the machine itself.

## The icons

The user-list icons are the ones every Hotline client of the era shipped:
the `cicn` resources in [`../gtkhx/icons.rsrc`](../gtkhx/icons.rsrc),
which is the same file GtkHx renders from. `DATA_ICON` on the wire is a
16-bit index into that table.

They are packed into **one sprite sheet** — `public/icons.png` plus a
JSON index of `id → [x, y, w, h]` — by `tools/build-icons.py`:

```sh
npm run icons     # python3 tools/build-icons.py ../gtkhx/icons.rsrc public
```

Six hundred separate PNGs would be six hundred requests for a roster
that shows eight of them, and there is no way to know in advance which
eight. One atlas is a single cacheable file the browser decodes once,
and CSS `background-position` picks the sprite; identical art filed under
several ids shares a cell, so the sheet is smaller than the sum of its
parts. Sprites render with `image-rendering: pixelated` at 2× in the
roster and 1× in the chat gutter — these are hand-placed pixels and a
bilinear filter ruins them.

The generator needs Pillow; nothing else here needs Python at all, which
is why its output is committed. Rerun it when `icons.rsrc` changes.

## The debug drawer

**Debug** in the title bar, or ⇧⌘D / Ctrl+Shift+D, or `?debug` in the
URL to have it open before the first frame:

- **Wire** — every frame in both directions, exactly as it crossed the
  socket, with a filter and a pause. Collected from the first frame
  whether or not the drawer is open, so opening it after something went
  wrong still shows you the login.
- **Session** — session id, uid, `seq`, detach grace, negotiated `caps`,
  video ceilings, ping RTT.
- **Media** — peer connection and ICE state, the transceiver mids, and
  per-SSRC packet counts from `getStats()`.

**Copy report** puts the session state and the whole frame log on the
clipboard, which is what to attach to a bug.

## Commands

Typed into the composer:

| | |
|---|---|
| `/me <text>` | chat with `style: "action"` |
| `/msg <nick\|uid> <text>` | open a PM conversation and send |
| `/nick <name>` | needs `use_any_name` |
| `/icon <n>` | or click your own icon in the title bar |
| `/drop` | close the socket without logging out — exercises resume |
| `/clear`, `/close` | clear this transcript, close this PM |
| `/debug`, `/logout`, `/help` | |

## What it does with the protocol

- **Sessions outlive connections.** The socket is an attachment, not the
  session. A dropped connection reconnects with backoff and `resume`s,
  replaying what it missed; `resync_required` is handled as the spec
  intends, with a `sync` on the same socket rather than a new login. A
  **page reload** resumes too — session id, token and `last_seq` live in
  `sessionStorage` — so you keep your uid and your place in the room.
- **Seq accounting is exact.** Every event advances `seq`, including the
  `unsupported` placeholders the server emits for domain events this
  protocol revision cannot express. That is what makes `last_seq`
  meaningful on the next resume.
- **The roster shows what the ng wire knows and the 1.x list could not**:
  `idle` and `detached` are different states, not one away flag, and
  voice membership, mute, and video publications are marked per person.
- **Nothing is drawn optimistically.** A line of chat appears when the
  event carrying it arrives — including your own, because the server
  echoes chat to its author. Private messages are the exception the
  protocol forces: `msg` has no echo, so the sender's half is local.
- **Video is opt-in in both directions.** Nothing is published until you
  ask and nothing is received until you subscribe, and the subscription
  is declared as a complete set so turning it all off is one request.

Passwords are never stored. The session token is a bearer credential for
one session and lives in `sessionStorage`, so it dies with the tab.

## Layout of the source

| | |
|---|---|
| `src/wire/protocol.ts` | the wire's shapes — the twin of `crates/hxd-ng-session/src/proto.rs` |
| `src/wire/connection.ts` | one session across however many sockets: handshake, resume, backoff, the trace hook |
| `src/state.ts` | roster and transcripts; no DOM |
| `src/ui/` | the shell, roster, transcript, composer, icon picker, media, debug drawer |
| `tools/build-icons.py` | `icons.rsrc` → sprite sheet |

There is no UI framework, on purpose: this client doubles as a readable
reference for the protocol, and a reader chasing a bug should not have to
know a rendering library's rules to follow what the DOM is doing.
`src/ui/dom.ts` is the whole abstraction.

`tools/ng-voice.html` at the repo root stays as the minimal single-file
rig for poking at the SFU with no build step at all.
