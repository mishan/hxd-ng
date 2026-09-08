# Identity enrollment — certifying a device without the paste

Status: draft, for discussion. Being built groundwork first: the §5.4
bundle exists in `hl-identity` and `hlid cert --bundle` writes it, and
the identity endpoints answer CORS so a browser elsewhere can reach a
mailbox. The mailbox itself, the enrollment request, and both `hlid`
commands are not written yet, in hxd-ng or in hx-ng. Companion to
`hotline-ng-identity.md` (the objects and the profile),
`hotline-ng-auth.md` (the transport), hx-ng's `identity-keys.md` (the
browser's side of the same problem, whose §7 describes the paste this
document replaces), and the identity threat model.

---

## 1. The problem

A device is what a device certificate (`hotline-ng-identity.md` §3.3)
says it is, and only the identity key can sign one. The browser never
holds the identity key — that is the whole point of hx-ng's model B —
so enrolling a browser is a trip to wherever the key lives: the browser
shows two public keys, the user runs `hlid cert` with them, and pastes
the result back. Two pastes of hex, once per browser, and again every
ninety days when the certificate expires. That ceremony is what keeps
the recommended lifetime from being livable, and it only works at all
if the browser and the terminal are on the same desk.

This document moves the two pastes through a relay. The identity holder
opens a short-lived *session* at a *mailbox*, gets a pairing code, and
waits. The device being enrolled posts a signed request under that
code. The holder is prompted, shows what it is about to certify, signs
on approval, and posts the bundle back. The device fetches it and checks
it exactly as it would have checked a paste.

Nothing in it is new cryptography: the request is a signed CBOR object
like every other in `hl-identity`, the bundle is the certificate and
card the paste already carried, and the mailbox verifies nothing and is
trusted with nothing but availability (§9). It is the OAuth device-code
flow (RFC 8628) turned inside out — the terminal shows the code and the
browser is the thing being authorized — and, because the mailbox is not
on localhost, the browser can be on a phone.

The paste stays. A device that reaches a server with no mailbox, or a
user with no agent running, enrolls as today. This is a faster path, not
the only one.

---

## 2. Roles

**The holder** has the identity key: `hlid enroll` for one device, `hlid
agent` for as long as it runs, a native client later. It opens sessions,
displays codes, prompts, signs, answers. It is the only party that can
answer a request, and the prompt it shows is the security boundary of
the whole flow (§9).

**The enrollee** holds a device keypair (signing and X25519) and wants a
certificate for it: a browser, a tunnel on another machine, a phone. It
posts a request and fetches the answer. It verifies what it gets and
shows the user whose device it has just become.

**The mailbox** routes requests to sessions and answers to requests, for
a few minutes, in memory. Any server that serves `[identity]` may host
one; so may a registrar. It never reads what it carries beyond the
routing fields, holds no keys, and makes no decisions.

---

## 3. Discovery

A mailbox advertises itself in the `identity` block of
`/.well-known/hotline` (`hotline-ng-auth.md` §5):

```jsonc
"endpoints": {
  "enroll": "/identity/enroll"        // absent: no mailbox here
},
"web": "https://hl.example/app/"    // optional: where a web client for this server lives (§5.6)
```

A registrar advertises the same key in its own block. A browser that
knows a server and a handle can therefore find a mailbox at either; the
holder and the enrollee must use the same one, and the code the holder
shows says which (§5.1).

---

## 4. The enrollment request

Domain `hl-identity/enroll-request/v1`, signed by the *device* signing key
being enrolled. At most 8 KiB encoded (the optional certificate inside is
bounded at 4 KiB by §3.3). Encoding and signature rules are
`hotline-ng-identity.md` §3.1.

| Key | Type | Req | Notes |
|---|---|---|---|
| `v` | uint | yes | `1` |
| `device` | bstr(32) | yes | Device Ed25519 public key; the key that signs this |
| `device_enc` | bstr(32) | yes | Device X25519 public key |
| `name` | tstr | no | Requested label, §3.3's rules for `name`. The holder may edit it |
| `caps` | uint | no | Requested capability bits. Absent = whatever the holder's policy gives a device of this kind. The holder never grants more than it would have at the terminal |
| `days` | uint | no | Requested lifetime. Absent = the holder's default. The holder may shorten |
| `time` | uint | yes | Rejected outside the holder's clock-skew tolerance; a stale request is a replay |
| `prev` | bstr | no | The device's current certificate, for renewal (§8). Its `device` must equal this object's |
| `pair` | bstr(32) | no | `HMAC-SHA-256(pairing secret, device)`, when the enrollee got the pairing secret by scanning the holder's QR code (§5.6). Proves the request came from whoever scanned it |
| `sig` | bstr(64) | yes | |

The signature proves the requester holds the key it wants certified.
For a first enrollment that proves little — a certificate for a key you
do not hold is useless to you — but it is what makes `prev` mean
something: a renewal signed by the same key that the old certificate
names is the same device asking again, and the holder can treat it
differently (§8). Signing every request rather than only renewals keeps
one format.

---

## 5. The mailbox

Five routes under the advertised prefix. All bodies are JSON. Secrets
are 32 bytes base64url, handled as `hotline-ng.md` §9 handles tokens:
CSPRNG, stored hashed, never logged.

### 5.1 The holder opens a session

`POST <enroll>/sessions`, body optional:

```jsonc
{ "identity": "…fingerprint…" }      // optional: accept renewals for this identity without a code (§8)
```

Response:

```jsonc
{
  "session":    "…secret…",           // the holder's handle on this session
  "code":       "K7PM-4XWE",          // what the user types into the enrollee
  "expires_in": 600
}
```

The holder also draws, locally and never sent to the mailbox, a 16-byte
*pairing secret*. It is used only by the QR path (§5.6); a session whose
code is typed never sees it.

The code is eight characters from a 32-symbol alphabet with the
confusable letters removed (Crockford base32 without `I`, `L`, `O`, `U`,
which it already excludes, and displayed with a hyphen after four), so
about forty bits, drawn by the mailbox. It admits **one** request and is
dead after that; a holder that means to enroll two devices opens two
sessions. It is dead at `expires_in` too. The holder displays it with the
mailbox's host beside it, since the enrollee has to use the same one:

```
Enroll a device at hl.example: enter code  K7PM-4XWE  (expires in 10:00)
This identity: alice  3f2a8c1d…
```

Unauthenticated, rate-limited per source address, and the number of open
sessions is bounded (§11). The holder is not asked to prove it holds an
identity key: the mailbox has nothing to protect with that proof, since
a session opened by someone with no key can answer nothing an enrollee
would accept (§9).

### 5.2 The enrollee posts a request

`POST <enroll>/requests`:

```jsonc
{
  "code":    "K7PM-4XWE",             // routes to the session that owns it; or
  "request": "…base64url CBOR…"       // §4; if it carries `prev`, may route by identity instead (§8)
}
```

Response 201:

```jsonc
{ "request": "…secret…", "expires_in": 300 }
```

The mailbox decodes the request only far enough to enforce the size
limit and, when no code is given, to read `prev` for routing. It does
not verify signatures; that is the holder's job, and doing it here would
make the mailbox's CBOR parser an unauthenticated attack surface for no
benefit.

Errors, `{ "error": code, "text": "…" }`:

| code | status | |
|---|---|---|
| `unknown_code` | 404 | no open session has it, or it was used |
| `no_holder` | 404 | `prev`-routed and no standing session for that identity |
| `request_too_large`, `bad_request` | 400 | |
| `rate_limited` | 429 | |

A wrong code is a 404, not a hint. Codes are single-use and short-lived
and guesses are rate-limited per address, which is what forty bits needs.

### 5.3 The holder waits

`GET <enroll>/sessions/<session>` — long-poll: the mailbox holds the
connection up to 30 seconds and answers as soon as there is something,
or with an empty list at the deadline. Response:

```jsonc
{
  "pending": [
    { "id": "r1", "request": "…base64url CBOR…", "received": 1757116860 }
  ],
  "expires_in": 412
}
```

`id` is a short mailbox-assigned name for answering, not the enrollee's
secret. A session opened with `identity` sees renewals routed by
`prev` here as well as anything the code admitted. A holder that would
rather subscribe than poll gets that when the transport grows a
subscription route; the shape of `pending` is meant to survive that.

### 5.4 The holder answers

`POST <enroll>/sessions/<session>/answers`:

```jsonc
{ "id": "r1", "bundle": "…base64url CBOR…" }        // approved; or
{ "id": "r1", "denied": "not_mine" }                  // denied, with a reason for the enrollee's UI
```

The bundle is a CBOR map, unsigned because both members are:

| Key | Type | Notes |
|---|---|---|
| `v` | uint | `1` |
| `cert` | bstr | The new device certificate (§3.3) |
| `card` | bstr | The identity's current card (§3.4) |

This is also the format `hlid cert --bundle` writes for the paste path,
so the enrollee has one thing to verify whichever way it arrived. (The
flag rather than the `-o FILE.bundle` this document first proposed:
deciding what to write from the name the user chose for the file would
make `web.bundle` and `web.bin` produce different formats, which is a
surprise waiting for whoever tidies up their filenames.)

Only the session's secret can answer; the code cannot. That asymmetry is
deliberate (§9): the code is shown on a screen and typed on another, the
session secret never leaves the holder's process.

### 5.5 The enrollee fetches the answer

`GET <enroll>/requests/<request>` — long-poll, 30 seconds. Responses:

| status | body | |
|---|---|---|
| 200 | `{ "bundle": "…" }` | approved; the request is consumed |
| 202 | `{ "expires_in": n }` | still pending at the deadline; poll again |
| 403 | `{ "denied": "reason" }` | the holder said no; the request is consumed |
| 410 | | expired, or already fetched |

The enrollee then does what hx-ng `identity-keys.md` §7.1 step 4 does
with a paste: `cert.device` equals its own signing key, `cert.device_enc`
its own X25519 key, `cert.identity` equals `card.identity`, neither
expired; both signatures if the codec is there, a probe auth if not. And
one thing the paste path did not need to say, because the user had just
typed the identity's own command: **it shows who it has become** —

```
This browser is now a device of  alice  3f2a8c1d…
```

— and a browser that has enrolled with this identity before compares
the fingerprint to the one it stored and refuses a change without a
confirmation (§9).

### 5.6 A QR code instead of typing

Beside the code, when discovery advertises `web`, the holder renders a
QR code of

```
https://hl.example/app/#enroll=K7PM-4XWE&mailbox=hl.example&identity=3f2a…&pair=…base64url 16 bytes…
```

Everything is in the fragment, which browsers do not send to the
server, so nothing here reaches an access log. A phone camera opens the
web client with all four filled in: the code and mailbox, so the user
types nothing and cannot pick the wrong server; the identity
fingerprint, so the enrollee *pins it before it asks* rather than
learning it from the answer; and the pairing secret, which the enrollee
folds into its request as `pair` (§4).

Those last two change what the flow relies on. With a typed code, the
mailbox could substitute a request or an answer and only a human
comparing fingerprints would catch it (§9). With a scanned QR, the
enrollee refuses any answer that is not from the pinned identity, and
the holder refuses any request whose `pair` does not verify under the
secret it drew — and the mailbox never had the secret, so it cannot
mint a `pair` for a device key of its own. Both directions are then
checked by software, and the prompt (§6) can drop the "compare the
fingerprint" line and show only the name:

```
Certify  "Safari on the phone"  9c41e7b2  (scanned)?  [y/N]
```

The scan is the ceremony: whoever can photograph the terminal can
enroll a device, exactly as whoever can read the code can put a prompt
in front of the user today, except that the scanned request passes the
check the typed one asks the human to do. That is the right trade for a
QR that is on screen for ten minutes on the user's own desk; it is why
the pairing secret is 16 bytes rather than something typeable, and why
the typed-code path keeps the human comparison instead of accepting a
short `pair`.

Where it does not help: a browser on the same machine as the terminal
has no camera pointed at the terminal, and types the code. A bundle is
around a kilobyte of CBOR, which fits in a QR and is miserable to scan
into a browser from a laptop webcam; the answer always comes back
through the mailbox. And the reverse direction — the *enrollee* showing
a QR of its device key for the holder to scan — needs a holder with a
camera, which is a phone holding the identity key, and that is the
native-client future of §12 rather than anything `hlid` can do.

---

## 6. The holder's prompt

What the holder shows before signing is the only place a human checks
anything, so it shows everything that matters and nothing else:

```
Enrollment request via hl.example, code K7PM-4XWE

  device      9c41e7b2  ("Firefox on the laptop")
  asks for    login, message · 90 days
  will get    login, message · 90 days

Compare the device fingerprint with the one the browser is showing.
Certify?  [y/N]
```

The enrollee shows the same eight-character device fingerprint beside
its code entry. The user's job is to see that they match. That is the
step a hostile mailbox cannot fake (§9), and it is why the fingerprint
is on both screens rather than only in the terminal.

"Will get" is the holder's policy applied to the request: the
capability bits are the request's ∩ what the holder gives a device it
did not generate (`--caps web` by default: login and message, never
vouch or manage), the lifetime is min(requested, `--days`). A request
that asks for `manage` is shown asking for it and shown not getting it,
and the user can override with a flag they typed themselves. Nothing a
request says can widen what the holder would have done at the terminal.

The default answer is no. An agent that has been left running and gets
a request its user did not initiate should time out to a denial, not
to an approval.

A request whose `pair` verifies (§5.6) is shown as `(scanned)` and
without the comparison line, because the check it asks the human to
make has already been made. A request with a `pair` that does *not*
verify is refused outright, not shown: the only way to produce one is
to have guessed, and a guess is not something to put in front of the
user.

---

## 7. `hlid`

Two commands. The first is the deliverable; the second is what it grows
into.

```
hlid enroll --server URL [--caps web|LIST] [--days N] [--identity K]
    open one session, show the code, wait for one request, prompt, answer, exit
hlid agent --server URL [--caps …] [--days …] [--renew ask|auto|deny]
    keep a standing session open (§5.1 with `identity`), handle any number
    of requests and renewals until stopped
```

`enroll` is `agent` with a budget of one and no standing session, and
should be the same code. Both render the §5.6 QR code in the terminal
when discovery advertises a web client (half-block characters, which
every terminal since the VT100's successors can show), and print the
code alone when it does not. Both use the identity key from `hlid`'s default
directory, as hx-ng's plan asks of every pre-filled command, so the
browser's UI can say "run `hlid enroll --server https://hl.example`"
without naming a file.

The prompt is a terminal prompt in v1. The point of putting the flow
behind a mailbox rather than a clipboard is that the prompt can move —
to a tray app, an Electron window, a native client — without the
protocol changing, and `agent` is written as a library call with a
`Prompt` trait so that it can.

---

## 8. Renewal

A certificate near expiry is renewed by the same flow with `prev` set.
Two things change.

**No code is needed.** A holder running `agent` opened its session with
`identity`, so the mailbox routes a request whose `prev.identity` matches
straight to it (§5.2). The browser can do this on its own from
one-third remaining (`hotline-ng-identity.md` §3.3) without the user
typing anything: post, wait, store. If no standing session exists it
gets `no_holder` and falls back to asking the user for a code, and
failing that to the paste.

**The prompt is lighter, and it is still a prompt.** The holder verifies
`prev`: signed by this identity, `prev.device` equal to the request's
`device`, and the requested `caps` a subset of `prev.caps` with `days` no
longer than `prev`'s lifetime — "the same device asking for the same or
less". Then:

```
Renew  "Firefox on the laptop"  9c41e7b2  (expires in 27 days)?  [Y/n]
```

The default is yes, and it is one key. What it is not, by default, is
silent, and this is the decision in the flow worth defending. The
ninety-day lifetime exists to bound how long a *copied profile* keeps
logging in as you (hx-ng `identity-keys.md` §1, §7.2): a browser
directory copied off a machine holds the device key, and the
certificate's expiry is when it stops working. A holder that renews any
correctly-signed request without asking renews the copy too, forever,
and the lifetime bounds nothing. Asking turns the copy's renewal into
something the user sees — a renewal for a browser they were not using
is the one signal a copied profile gives — and one keypress a quarter is
what the ceremony was supposed to cost.

`--renew auto` exists for a user who has read that paragraph and owns
the machine outright. `--renew deny` exists for a holder that wants
renewals to come through a code like a first enrollment.

---

## 9. What the mailbox is trusted with

Availability, and nothing else. Every other party is checked by someone
who is not the mailbox.

| A hostile mailbox can… | …and what stops it mattering |
|---|---|
| Drop or delay anything | The user notices, and pastes |
| Read requests and bundles | Both are public material: public keys, a name, a certificate and card the server will be shown at the next auth anyway |
| Substitute the **request** — feed the holder its own device key under the user's code | The holder shows the device fingerprint; the enrollee shows its own; they do not match. This is why §6 puts the fingerprint on both screens and why the prompt defaults to no |
| Substitute the **answer** — hand the enrollee a bundle for a different identity | The enrollee shows who it has become, and pins the fingerprint after the first enrollment (§5.5). Also a bundle for a different identity does not help the mailbox log in as anyone: the browser would authenticate as *the mailbox's* identity, which the mailbox could do already |
| Open sessions and post requests itself | It can prompt the holder with its own device key, which is the substituted-request case, and it can fill its own tables |
| Any of the above against a **scanned** enrollment | Nothing: the pinned identity rejects a substituted answer, the pairing secret it never saw rejects a substituted request (§5.6) |

What the **code** protects is delivery: that the request lands at the
session the user meant, and that nobody who did not see the terminal
can put a prompt in front of the user. It does not protect the answer
(only the session secret can post one) and it does not need to keep a
request confidential. Forty bits, single-use, ten minutes and a
per-address rate limit is enough for that job; it would not be enough
for a job where guessing the code got the guesser something, which is
why the flow is arranged so that it does not.

What the **prompt** protects is everything else. The holder is the
only party with the identity key, so a certificate exists only if a
human said yes to what the holder displayed, and the display is
computed from the request the holder verified, not from anything the
mailbox says about it.

Threat-model entries this adds or touches: *web client key exposure*
(the renewal argument of §8 is the reason renewal prompts), *tunnel and
relay operators* (a mailbox operator is one more of these, with less to
see), and a new one, *hostile mailbox*, which is the table above.

---

## 10. Settings

| Setting | Default | Meaning |
|---|---|---|
| `[identity] enroll` | `true` | Serve the mailbox. Needs `[identity]`; the routes 404 without it, and discovery omits `enroll` |
| `[identity] enroll_sessions` | `256` | Open sessions at once, server-wide; past it, `POST sessions` answers 503 |
| `[identity] enroll_per_address` | `4` | Open sessions and pending requests per source address |

Session lifetime (600 s), request lifetime (300 s), long-poll deadline
(30 s) and the code alphabet are protocol constants, not settings: an
enrollee and a holder on different servers should see the same clock.

---

## 11. Implementation notes

- **State is one table of sessions**, keyed by the SHA-256 of the
  session secret, each holding its code (until used), its optional
  identity fingerprint, and up to a handful of pending requests keyed by
  the SHA-256 of their secrets. A second index maps live codes and
  standing identities to sessions. Everything has a deadline and a sweep
  removes what is past it. No persistence: a mailbox restart loses
  sessions, and the holder re-opens.
- **Bounds.** Sessions are capped (§10); requests per session are capped
  at 8; request bodies at 8 KiB plus JSON overhead; and the mailbox
  decodes CBOR only to read `prev.identity` for routing, which is a
  fixed-depth walk, not a general parse. Every table an unauthenticated
  caller can grow has a ceiling, as with every other table in the ng
  listener.
- **Long-poll** is a `tokio::sync::Notify` per session and per request,
  awaited with a 30-second timeout. The HTTP layer in `hxd-ng-session`
  already handles requests that outlive a keepalive.
- **The mailbox is the same code on a relay and a registrar**: it
  reads nothing from the account table and nothing from the card cache.
  It belongs in `hxd-ng-session` beside the identity endpoints, behind a
  trait so a registrar binary can mount it alone.
- **`hlid`** gains the request/bundle codecs in `hl-identity`
  (`EnrollRequest`, `Bundle`), the two commands, and a `Prompt` trait
  with a terminal implementation. `hlid cert --bundle` writes the §5.4
  format, so hx-ng's paste path and this path share a verifier.
- **hx-ng** gains a code entry beside the existing paste box, its own
  device fingerprint next to it, the poll loop, the pinned identity
  fingerprint, the renewal poster, and a reader for the `#enroll=`
  fragment that fills the first three in and computes `pair`. Its
  verifier is unchanged.
- **`hlid`** renders the QR with a small pure-Rust encoder; it is the
  only new dependency this document asks for.

---

## 12. Open questions

- **Linking in the same trip.** hx-ng's plan wants "enroll this browser
  and link my account" to be one terminal visit. The holder could run
  the equivalent of `hlid link` after approving, if the request said
  which account and the user typed the password at the holder. It is a
  natural extension and it keeps the password out of the browser; it is
  left out of v1 so that the flow that certifies and the flow that
  writes account links are reviewed separately.
- **Should the enrollee prove anything about itself first?** Today a
  request costs its poster nothing but a signature, and the prompt is
  the filter. An enrollee that has previously authenticated at this
  server could carry a transport token, which would let the mailbox
  reject drive-by requests before they reach the holder. Worth it only
  if prompts from strangers turn out to be a nuisance in practice.
- **A subscription instead of a poll** for the holder, over a WebSocket
  on the ng listener. The `pending` shape is designed to be pushed
  unchanged. Not needed until an agent is expected to run for days.
- **Mobile without a desktop.** This flow enrolls a phone when the user
  has a holder somewhere else. A user who has no holder needs the
  identity key on the phone, and there are two candidate routes, neither
  of which this document takes: a registrar-held password-wrapped key
  envelope unwrapped on the phone by a WebAuthn PRF passkey, in a Worker
  that mints the certificate and exits (hx-ng's phase C plus a registrar
  backup); or *delegated certification*, where an already-enrolled
  device with a new capability bit may certify another device to depth
  one, which also answers `hotline-ng-identity.md` §14's "device renewal
  without the identity key" and would let a phone enroll a phone with the
  identity key offline. The second widens what a stolen device can do
  and needs its own threat-model entry before it is more than a
  question. Both belong to the registrar spec.
- **Denial reasons.** `denied` carries a free string for the enrollee's
  UI. If there turn out to be three reasons, they should be codes.
