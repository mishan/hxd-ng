# Push notifications: delegating the device registry to uniqush-push

Status: design; only the `NotificationGateway` trait exists. The first
gateway to build is decided below, and it is not the one this document
was written around.

Phase 7 item 3 promises "a `NotificationGateway` trait (APNs / FCM /
UnifiedPush / WebPush behind it) plus a device-token registry." This
document argues that we should **build the trait and not the registry** —
the registry, the per-vendor transports, the token lifecycle and the
retry/backoff machinery already exist in
[uniqush-push](https://github.com/uniqush/uniqush-push), which hxd-ng can
drive over HTTP as a sidecar. It also says exactly where the seam goes,
what hxd-ng still owes, and how to stage the work.

**Written against uniqush-push 2.8.0 (released 2026-09-03), and
re-checked against it 2026-09-05.** 2.8.0 is the minimum: 2.7.0 has no
Web Push backend at all and cannot deliver to APNs or FCM.

**Decision (2026-08): yes, with the trait kept honest.** `NotificationGateway`
ships with a no-op default and a `UniqushGateway` HTTP implementation.
Push is off unless configured. A server that wants nothing to do with a
Go daemon and a Redis loses push, not the build.

**Refined 2026-09 against the identity spec.** Three things changed shape
once identity landed:
- **The subscriber is a mailbox**, keyed by fingerprint where there is one
  (§5).
- **On an identity session the device names itself** with its
  certificate (§5.1).
- **Credentials are per server, and the app is not.** An operator's push
  credentials are a VAPID keypair, while a native app reaches APNs and FCM
  through a relay its publisher runs (§8.1, §8.2).

**Decision, 2026-09: the first gateway is `WebPushGateway`, in-process.**
The design review (`hxd-ng-design-review-2026-09.md` §3, action 1) is
right that the sidecar is more than the first gateway needs. A native
Web Push sender — VAPID (RFC 8292), the delivery protocol (RFC 8030) and
the payload encryption (RFC 8291) — is one crate behind the existing
`NotificationGateway` trait, no daemon, no Redis, and it is the escape
hatch §3 and §10 already reserve. It goes first; the license review §3
mentions for a native implementation comes before the crate. The
uniqush design the rest of this document describes is **kept**, as the
multi-vendor path for when there is an iOS app that needs APNs; when
that is scheduled, this document moves to `docs/proposals/` and the Web
Push gateway gets its own. Nothing below is withdrawn — the seam (§4),
the subscriber model (§5), the payload rules (§6) and the protocol
additions (§8) hold for either gateway; only the order changed.

---

## 1. What uniqush actually is

A standalone daemon (Go, Apache-2.0) with a RESTful API and Redis for
storage. Its model is three nouns:

- a **service** — one app, e.g. `hxd`;
- a **push service provider** (PSP) — credentials for one vendor backend
  within a service (`/addpsp`);
- a **delivery point** — one device's registration under a
  `(service, subscriber)` pair (`/subscribe`).

The endpoints that matter to us: `/addpsp`, `/subscribe`,
`/unsubscribe`, `/push`, `/subscriptions`, `/nrdp`, `/previewpush`, and
`/checkdb` for operators. `/addpsp` refuses to overwrite a PSP whose fixed
data differs (the VAPID *public* key is fixed; the private key is not, so a
mistyped private key is just re-sent) — the way out is `/addpsp` again with
`replace=true`, which keeps every subscription. **Not `/rmpsp`**: it does
not delete subscriptions in 2.8.0, but it is the wrong tool for a
credential change and in 2.7.0 it silently unsubscribed every device in
the service. The deployment docs should say `replace=true`, once.

`/push` takes a `service`, one or more `subscriber`s (comma-separated
under `subscriber` or `subscribers`), and payload fields; it fans out to
every delivery point those subscribers own and answers with a JSON body
counting successes, failures, and **dropped** points — the ones the vendor
told it are dead. uniqush really does delete those, not merely report
them. Multi-subscriber fan-out is a `/push` feature only: `/subscribe` and
`/unsubscribe` parse the same comma-separated list and then silently use
the first entry. **`/push` also takes wildcards** — `alice.*` matches a
prefix and a bare `*` pushes to *every subscriber in the service*. Our
subscriber ids (§5) can never contain `*`, and the gateway must never pass
anything else through as a subscriber; a wildcard reaching `/push` would
be a broadcast to every device on the server.

Payload fields are *nearly* arbitrary, with reserved names that will bite
a naive payload builder: `service`, `subscriber`/`subscribers` are
consumed by the router, `badge` is coerced to an integer, the
`uniqush.perdp.*` and `uniqush.*` prefixes are reserved, and **fields with
empty values are silently dropped** — a notification whose fields all get
consumed comes back as `EMPTY_NOTIFICATION`.

Backends registered today: APNs, FCM, GCM, ADM, and
`webpush`/`unifiedpush`.

**Backend health, stated plainly** (from the project's own README, which
is candid about it):

| Backend | State (2.8.0) |
|---|---|
| UnifiedPush / Web Push | Works. No vendor account, no certificate. New in 2.8.0. |
| FCM / GCM | **Works.** Migrated to the HTTP v1 API; confirmed end to end against a real Firebase project on 2026-09-01 (delivered to a browser; an Android device has not been tried). `/addpsp` takes `projectid` + `credentialsfile`, not `apikey`. |
| APNs | **Probably works.** HTTP/2 by default, `apns-push-type`, `.p8` token auth, failure classification; driven against a conformance simulator and Apple's real sandbox. **Never delivered to a real device** — that needs a paid developer account, which neither project has. |
| ADM | Believed working, unverified. |

Earlier drafts of this document said FCM could not deliver and APNs had
never met Apple's servers. Both were true of 2.7.0 and are not true of
2.8.0; the staging in §9 was Android-first for those reasons and stays
Android-first for the reasons that remain (§3).

## 2. What this buys us, and what it doesn't

**Buys us**, in descending order of how much we'd hate writing it:

- The **device registry**: `(service, subscriber) → many delivery points`,
  with add/remove/query and Redis persistence. This is most of Phase 7's
  "device-token registry" — we still keep a thin index of our own for the
  operations uniqush's API can't express (§5), but not the storage, not
  the vendor-specific credential shapes, and not the pruning.
- **Token lifecycle.** Vendors report unregistered/invalid tokens on
  delivery; uniqush prunes them. Every push system that skips this
  eventually accumulates a graveyard of dead tokens and a mystery about
  why delivery counts drift.
- **Per-vendor transports** — HTTP/2 APNs pooling, RFC 8030/8291/8292
  Web Push with VAPID and `aes128gcm` payload encryption, retry and
  `Retry-After` handling, the SSRF policy that Web Push's
  caller-chosen-endpoint model demands.
- **Fan-out to a subscriber's N devices** from one call, which is exactly
  the shape our multi-device future wants.

**Doesn't buy us** — and it's important that this list is the short one,
because everything on it is domain policy that belongs in hxd-core anyway:

- *When* to push. "DM or mention while detached" is our rule, not
  uniqush's.
- The **durable offline inbox** (Phase 7 item 2). uniqush is delivery, not
  storage; a push is a doorbell, and the message must still be in the
  inbox when the user opens the app.
- **Read state**, and therefore notification dismissal/badge accuracy.
- **Notification content policy** (full text vs. "you have a message") —
  our config knob, applied when we build the payload.
- **Authorization.** Its REST API has no authentication whatsoever (§7).

## 3. Why this fits *this* project specifically

Four reasons that are about hxd-ng, not about push systems generally.

**The roadmap's own open question already picked UnifiedPush.** Phase 7's
last open question reads: "Which push providers ship first (UnifiedPush is
the self-hosting-friendly one; APNs/FCM need app-store presence that
doesn't exist yet)." When this was first written, that was also the one
uniqush backend that worked; as of 2.8.0 FCM works too and APNs probably
does. The choice stands on the grounds that haven't moved: UnifiedPush
needs no vendor account, no certificate and no app-store presence, and it
is the backend whose payload the provider cannot read (§6). FCM and APNs
follow when there is an app to receive them. **This resolves the open
question rather than colliding with it.**

**Process separation solves a license problem we'd otherwise have.**
hxd-ng is GPL-2.0-or-later, forced by `hxproto`'s hxd ancestry.
uniqush is Apache-2.0, which is *incompatible with GPLv2* — linking an
Apache-2.0 library into a GPLv2 binary is the classic patent-clause
conflict. Talking to a separate daemon over HTTP raises none of it. A
native Rust Web Push implementation would need its own license review;
this doesn't.

**Redis converges with Phase 8, not away from it.** Adding Redis looks
like a third datastore next to Phase 7's Postgres — but Phase 8's locked-in
stack is "PostgreSQL + Valkey," and Valkey is a Redis fork speaking the
same protocol. uniqush is on `redis/go-redis` v9, which talks to Valkey
fine. The operational surface we're adding early is one we had already
decided to add.

**We maintain it.** Misha is the current uniqush maintainer; the FCM HTTP
v1 migration and the APNs HTTP/2 repair shipped in 2.8.0, and what is left
on that side (APNs delivery to a real device) is blocked on an Apple
account, not on code. This is a reason the integration is *low-risk to
unblock* — we are not waiting on a stranger — but it is emphatically
**not** an argument that uniqush is the right choice. Guard against the bias by keeping the trait
(§4) real and the config optional. If the sidecar ever stops earning its
keep, a native `WebPushGateway` behind the same trait is a contained piece
of work.

## 4. The seam

```
hxd-core                       hxd-push-uniqush          uniqush-push
┌──────────────────────┐       ┌────────────────┐        ┌──────────┐
│ inbox: DM/mention    │       │ POST /push     │        │ APNs     │
│ arrives for a        │──────▶│ POST /subscribe│───────▶│ FCM      │
│ detached session     │ trait │ POST /unsub    │  HTTP  │ WebPush  │
│                      │       │                │        │ (→ Redis)│
│ NotificationGateway ─┘       └────────────────┘        └──────────┘
│   (no-op by default) │
└──────────────────────┘
```

The trait lives in `hxd-core` next to `AuthBackend` and the store traits;
it names domain concepts only, no HTTP, no vendor vocabulary:

**Shipped 2026-09** in `hxd-core`'s `notify` module, with four departures
from the sketch this section carried, all forced and all smaller than
they look:

```rust
pub trait NotificationGateway: Send + Sync + 'static {
    /// Best effort, and MUST NOT block: implementations spawn and return.
    fn notify(&self, n: &Notification<'_>);
}
```

**Not `async_trait`.** `Core` is sync all the way down and its state sits
behind a `std::sync::Mutex`; one async call in the domain would make the
whole domain async. But `notify` was never going to be awaited on the
message path anyway — the paragraph below says so, and says why — so the
spawn happens either way. This puts it on the implementation's side of
the trait, where the runtime handle lives.

**No `NoopGateway`.** A gateway that does nothing, plus an `Option` that
means the same thing, is one state too many; `Core` holds
`Option<Arc<dyn NotificationGateway>>` and `None` is the default.

**No registration methods, yet.** `register` and `unregister` answer the
ng protocol requests in §8, which arrive with the gateway crate; the
domain has nothing to say about a device. The message path is what had to
exist first, and it is what §11's "the notify decision must live in the
domain" is about.

**And the notification carries a mailbox, not a login.** §5 refuses to
let uids near a device registry because they recycle; a login recycles
too, on a rename, so a gateway keys its subscriber id on the identity
fingerprint where there is one and the login only where there is not.
See private-messages.md §4 — it is the same rule the mailbox itself uses,
and the same failure if it is broken.

**And `Notification` is a sum**, since news brought a second kind
(news.md §10.10): `Message(MessageNotice)` for a private message,
`News(NewsNotice)` for an article someone should hear about. A gateway
builds a different payload for each — a conversation to open, a thread to
open — and `to()` answers the mailbox either way.

`UniqushGateway` lives in its own crate (`hxd-push-uniqush`) so that a
build without push pulls in no HTTP client at all, and so that a future
`hxd-push-webpush` is a sibling rather than a rewrite.

**`notify` is fire-and-forget from the domain's point of view, and this is
not a stylistic preference.** uniqush's `/push` answers only after the *first
delivery attempt* at every delivery point of every named subscriber has
completed (delivery is asynchronous per backend, but the response waits so
it can report what happened), and the Web Push path allows tens of seconds
per point. A chat or PM path that
awaited that would be handing a stranger's flaky push provider a lever on
our latency. So the gateway call is spawned, its outcome logged, its
failure not the sender's problem — and the client-side timeout and circuit
breaker in P3 (§9) are load-bearing, not polish. A push that never arrives
is a degraded notification, not a lost message; the message is in the
inbox.

One consequence to know when reading logs: transient failures are retried
in the background with a backoff that honours the provider's `Retry-After`
(capped at 30 minutes), long after the HTTP response we saw, so a delivery
point dropped *on retry* never appears in the `droppedCount` we saw and an
abandoned retry surfaces only as `UNIQUSH_ERROR_FAILED_RETRY` in uniqush's
own log. Our
view of the registry is eventually-consistent with uniqush's, and the
gateway must not treat its own bookkeeping as authoritative.

## 5. Subscriber identity — the one real gotcha

uniqush validates service names on every request, and subscriber names at
`/subscribe` and `/unsubscribe` (**not** at `/push`, which takes the
subscriber unvalidated). The patterns are

```
service:    ^[a-zA-Z.0-9_@\[\]^\\\\-]+$
subscriber: ^[a-zA-Z.0-9_@-\[\]^\\\\-]+$
```

— which look different but accept the identical set, `-.0-9@A-Z[\]^_a-z`.
The `@-\[` in the subscriber pattern is an accidental *range*
(`@`–`[`, i.e. `@ A-Z [`), not a literal hyphen; the literal hyphen comes
from the trailing `-`. Harmless, and worth knowing before someone
"fixes" it upstream and changes the accepted set out from under us.

Hotline account logins are arbitrary text:
Mac Roman on the legacy wire, canonicalized to UTF-8 before any backend
sees them (see AGENTS.md). Spaces and non-ASCII in a login are ordinary,
not exotic. **Account names cannot be used as uniqush subscribers
directly.**

Nor can uids: uids are the 16-bit legacy ids and they *recycle*. A device
registered against a recycled uid would push someone else's DMs to a
stranger's phone. That is the worst bug this subsystem can have, so the
mapping must not go anywhere near uids.

Nor, as the first draft had it, can the login alone, even hex-encoded: a
login recycles too, on a rename, and a device registered against
`alice` would push the next `alice`'s private messages to the first one's
phone. That is the uid failure on a slower clock.

**The mapping is the mailbox's, with the two kinds kept apart:**

- an identified mailbox is `hx-f-<lowercase hex of the 32 fingerprint
  bytes>`;
- an unidentified one is `hx-l-<lowercase hex of the login's canonical
  UTF-8 bytes>`.

Deterministic, collision-free, inside the accepted charset, and reversible
— which matters at three in the morning when you are reading uniqush's
logs and want to know whose device that is. The two prefixes carry the
mailbox rule's strictness into uniqush (private-messages.md §4): an
identity never shares a subscriber with a login, whatever the login is.
No new state and no lookup table; long names make long ids, and uniqush
does not care.

The login-keyed form keeps the rename hazard the fingerprint form is free
of, so it inherits the mailbox's obligations, owed at the same call
sites:

- **Deleting an account unregisters its devices** (`inbox_purge`'s twin).
- **Linking an identity moves them from `hx-l-` to `hx-f-`.** That means
  an `/unsubscribe` and a `/subscribe` per device, which the gateway can do
  because its device index holds each triple (`inbox_claim`'s twin).
- **A rename by an operator is a deletion and a registration** as far as
  the gateway is concerned. The devices re-register at their next login.

An identity has none of these, which is one reason identity accounts are
the easy case.

If a future account model grows a stable opaque account id (the database
backend is the natural place), the `hx-l-` form becomes that id instead,
and the hex-form subscribers age out as their delivery points are dropped
or re-registered.

**Delivery points are identified by their content, not by a name we
choose.** uniqush derives a delivery point's identity from a hash of its
fixed data — for Web Push, the `(endpoint, p256dh, auth)` triple. Two
consequences we have to design around:

- Re-registering the *same* triple is genuinely idempotent, so a client
  that re-registers on every login is fine.
- Re-registering a *changed* endpoint (an ntfy distributor
  re-provisioning, a reinstalled app) creates a **new** delivery point and
  leaves the old one in place until a vendor 404/410 retires it. Devices
  therefore accumulate rather than converge, and a user can end up being
  pushed at addresses they no longer read.

The `devid` field does not help here: uniqush stores it (with `old_devid`
and `subscribe_date`) as *volatile* data, outside the identity hash, and
returns it from `/subscriptions` uninterpreted — a display label that
cannot be used to subscribe, unsubscribe, or target. 2.8.0 does expose a
`delivery_point_id` (`/subscriptions?include_delivery_point_ids=1`) that
`/push` accepts to target a subset of a subscriber's devices, but
`/unsubscribe` still refuses it and demands the full fixed data back. So
the picture for us is unchanged: **`devid` in our protocol (§8) must be a
gateway-side lookup key we own, not something passed through.**
That means the gateway keeps its own small `account → devices` table
(one row per registration, holding the uniqush fixed-data triple) — which
is not the device registry we were trying to avoid building, but a thin
index over uniqush's, and it is what makes the next paragraph possible.

The `service` name is one constant per server instance (config
`[push] service`, default `hxd`), which lets one uniqush deployment serve
several hxd-ng instances.

### 5.1 With an identity, the device names itself

The identity spec gives every device a certificate with a key of its own,
and on an identity session that key *is* the transport principal's `id`
(hotline-ng-identity.md §3.3, §5). private-messages.md §10 already
observed that the registry wants `(identity_fp, device_fp)`. Taking that
seriously changes five things, and each one is a problem above that stops
being one.

**`devid` is the device fingerprint, and the client does not choose it.**
On an identity session `push_register` ignores a client-supplied `devid`
and uses the fingerprint of the certificate the socket authenticated with.
The gateway's index is keyed `(subscriber, devid)`. So when a device
re-registers with a changed endpoint — an ntfy distributor
re-provisioning, a reinstalled app on the same key — the old triple is
unsubscribed and the new one takes its place. Registrations **converge**
instead of accumulating, which is the "stale delivery points" risk in §10
answered for every identity device. A password session supplies its own
`devid`: a random value per install that the client keeps. It is a lookup
key and nothing more, and re-registering with the same one replaces as
above.

**A device's registration lives as long as its certificate.** The index
records the certificate's `expires`. Past it, the gateway skips the
device on `/push` and unsubscribes it on the next pass; renewal
(identity-enrollment.md) re-registers at the next login. A certificate the
revocation list names is unsubscribed when the list is refreshed. Together
these give the one thing a password account cannot have: **a lost phone
stops buzzing when its key is revoked**, not when someone remembers to
call `push_unregister` from another device.

**The certificate's capabilities say who may do what.** Registering needs
the certificate's `message` bit (bit 1): a push is a message delivered to
that device, and a certificate its identity issued for logging in alone
has not been trusted with messages. Unregistering *this* device needs
nothing more than the session. Unregistering *another* device, or all of
them, is account management and needs `manage` (bit 3), the same line
hotline-ng-identity.md §8.2 draws around writing a link. A web client's
certificate, which omits `manage`, can therefore turn its own
notifications off and cannot silence the owner's phone.

**Rotation drops, it does not re-key.** Device certificates are signed by
the identity key, so a rotated identity's devices are re-certified under
the successor and re-register when they next log in. The gateway
unsubscribes everything under the predecessor's `hx-f-` rather than moving
it. Moving it would keep delivering to devices the successor has not
vouched for. Unlinking needs nothing: an unlinked identity has no mailbox
on this server, so nothing addresses its subscriber, and its registrations
lie dormant until it links again. That is the same answer
hotline-ng-identity.md §8.4 gives for its mail.

**The payload can be sealed to the device.** A certificate carries
`device_enc`, an X25519 key meant for end-to-end messaging. Encrypting
the notification's content to it, under a domain string of its own
(`hl-identity/push/v1`) and inside whatever the transport already does,
takes uniqush, the relay of §8.2, and Apple or Google out of the trust set
for content. §6's asymmetry is then gone for identity devices:
`content = "full"` costs the same on APNs as on UnifiedPush. The server
still reads it, because it is the server, and a password device still gets
§6's content policy. This needs the sealing specified in `hl-identity`
with test vectors, like every other object there, so it is a stage of its
own (§9, P6) rather than a detail of P3.

## 6. When we push, and what's in it

The rule from Phase 7: **a DM or a mention arriving for a session that is
not `active` produces a push.** Concretely:

- `detached` → push. This is the case the phase exists for.
- `idle` → push. The app is open but backgrounded or quiet; the OS decides
  whether to make noise.
- `active` → no push. A connection is attached and got the event.
- No session at all → push, *if* the account has registered devices. This
  is the "closing the app doesn't mean leaving, but eventually the grace
  window lapses" case, and it's what makes hxd-ng feel like a messaging
  app rather than a chat room you have to be sitting in.

The last bullet has a consequence worth stating: **the durable inbox
(Phase 7 item 2) is a prerequisite for push to be worth anything.** A push
whose message evaporated when the grace window lapsed is a notification
about nothing. Item 2 lands before item 3; the staging in §9 reflects
that.

**Payload, and the privacy asymmetry.** Content policy is
`[push] content = "full" | "sender" | "generic"` (default `sender`:
"Message from alice"). But the honest framing differs by backend, and
we should document it rather than pretend it doesn't:

- **Web Push / UnifiedPush** encrypts the payload to the device's own
  keypair (RFC 8291, `aes128gcm`). **The push provider cannot read it** —
  ntfy, or whichever distributor the user chose, relays ciphertext.
- **APNs / FCM** hand the payload to Apple or Google in the clear. On
  those backends `content = "full"` is a real disclosure to a third party,
  and the config documentation must say so at the knob.

**Be precise about who is blinded, because it is not everyone.** uniqush
performs the RFC 8291 encryption itself, which means it receives our
plaintext over the REST API and can log it. The hxd-ng → uniqush hop is
cleartext HTTP (§7). So Web Push removes the *provider* from the trust
set, not the sidecar: with UnifiedPush, `content = "full"` trusts the
operator's own uniqush and nothing beyond it, whereas with APNs/FCM it
also trusts Apple or Google. That is a meaningful improvement and a second
independent argument for UnifiedPush as the first-class backend — but it
is not end-to-end encryption and the docs must not imply it is.

Two Web Push limits to design within (re-checked in 2.8.0's
`srv/webpush/push_service.go`): uniqush hardcodes a 12-hour TTL and
`Urgency: normal` with no per-push override — the `ttl` parameter applies
to APNs, FCM and ADM only — and the plaintext payload ceiling is under
4 KB. `content = "full"` on a long message must truncate on our side
rather than discover the ceiling at delivery time. uniqush also does not
set the RFC 8030 `Topic` header, which is Web Push's collapse key; that is
an upstream change we can make when the coalescing question (§11) is
decided, and `msggroup` already covers FCM's.

Payloads are shaped per backend, and the gateway builds them
accordingly: for Web Push the parameters become a JSON body the app
decrypts and renders itself; for FCM the display text goes in
`uniqush.notification.fcm` (shown by the device) and structured fields in
`uniqush.payload.fcm` (all values strings); for APNs `msg` becomes
`aps.alert.body` and `uniqush.apns_push_type` selects `alert` versus
`background`. `/previewpush` renders any of these without sending, which
is how the payload builder's tests should check themselves.

**News notifies too, by a rule of its own** (news.md §10.5–§10.7).
Someone answered your article, cited it, or posted in something you
follow. It is a push only when you had caught up with that thread or
category, so a busy one rings once per visit. The notice carries the
scope, and `SubScope::key()` — `thread:398` — is its collapse key:
`msggroup` for FCM, and the RFC 8030 `Topic` header once uniqush sets one.
The payload names a thread to open rather than a message, and content
policy applies to its excerpt as it does to a message's text.

## 7. Deployment and security posture

**uniqush's REST API is unauthenticated.** There is no token, no basic
auth, no TLS — the shipped config binds `localhost:9898` and that is the
entire access control story. (`restapi_unix.go` is signal handling, not a
unix-socket listener; don't be misled by the name.)

**Exposing that port is not "leaking a device registry," it is handing
over the devices.** `GET /subscriptions?subscriber=…` returns each
delivery point's fixed data — for Web Push, the `endpoint`, `p256dh` and
`auth` triple, which is the complete credential set for sending arbitrary
encrypted pushes straight to that user's phone, bypassing uniqush
entirely. `GET /psps` returns every provider including the **VAPID
private key itself**. And `GET /stop` — no method check, no auth — shuts
the daemon down. Therefore:

- uniqush binds loopback, or a private interface hxd-ng alone can reach.
  There is no configuration in which that port faces the internet.
- If hxd-ng and uniqush are ever on different hosts, that link needs a
  proxy that adds authentication, or a network the operator controls
  end to end. Say this in the deployment docs, once, loudly.
- Redis persistence must be on (uniqush's own README stresses this):
  losing the delivery-point set means every device silently stops getting
  pushes until it re-registers.

**Web Push SSRF.** The Web Push destination is chosen by whoever calls
`/subscribe` — in our case by a client's UnifiedPush distributor. uniqush
already refuses non-globally-routable destinations by default, does not
follow redirects, and re-checks before every push rather than only at
subscribe time. We inherit that for free and should not relax it; the
`allow_private_addresses` escape hatch is for operators running their own
push server on a private network, and belongs in their config, not ours.

**Registration is authenticated by us, not by uniqush.** The
`push_register` request (§8) only ever arrives on an authenticated ng
session, and the gateway derives the subscriber id from the *session's*
account — never from a client-supplied field. Otherwise anyone could
register a device against anyone's account and subscribe to their DMs.

**And only an account can register.** A guest has no mailbox, so there
is nothing durable to deliver to (private-messages.md §2). The login reply
does not offer push to a guest session (§8.1), and `push_register` from
one is refused `no_mailbox`, the code news gives a guest who tries to
subscribe. On an identity session the device is the certificate's rather
than the client's, and so is what it may do with other devices (§5.1).

## 8. Protocol additions

Two new ng requests, fitting the existing shapes in
[hotline-ng.md](hotline-ng.md) §7:

| `req` | params | ok | notes |
|---|---|---|---|
| `push_register` | `type` (`"webpush"`\|`"unifiedpush"`, or `"apns"`\|`"fcm"` with `token` for an operator who ships their own app), `endpoint`, `p256dh`, `auth`, `devid?` | `{ "devid": "…" }` | account from the session, never from params; `devid` from the device certificate on an identity session (§5.1) and required from the client otherwise; idempotent per `devid`, and a changed endpoint replaces the old one |
| `push_unregister` | `devid?` (omit = this device), `all?` | `{}` | another device, or `all`, needs `manage` on an identity session |

**Omitting `devid` means this device, not every device.** The first draft
had it the other way round, so the request a client sends most — turn
notifications off here — was one missing field away from silencing
every device the account owns. Logging out everywhere is `all: true`,
said on purpose.

Errors: `no_mailbox` (a guest), `not_available` (no gateway configured),
`no_capability` (an identity device whose certificate lacks `message`,
or `manage` for another device), `bad_request` (a triple that is not one).

**`push_unregister` is harder than it looks, and the gateway absorbs
that.** uniqush has no unsubscribe-all endpoint, `/unsubscribe` will not
accept a delivery-point id, and for Web Push it demands the full
`(endpoint, p256dh, auth)` triple back. The only path through uniqush's
own API is `GET /subscriptions` followed by a replayed `/unsubscribe` per
device — an N+1 round trip against the endpoint that hands out device
credentials (§7). That is why the gateway keeps its own device index
(§5): with it, `push_unregister` is a local lookup and N `/unsubscribe`
calls, and we never call `/subscriptions` in normal operation at all.

The login reply grows `caps: ["push"]` when a gateway is configured —
this is the moment hotline-ng.md §11 anticipated for the capability list,
so it arrives here rather than being retrofitted.

`logout` does **not** unregister devices. Logging out of the app is the
single most common moment to want a push about what you're missing; only
an explicit `push_unregister` (or a vendor telling uniqush the token is
dead) removes a device.

Nothing about this touches the legacy wire. A 1.x client has no devices.

### 8.1 Per server, and asked for

Every server has its own push credentials, and they cost its operator
nothing. For Web Push and UnifiedPush, a credential is a **VAPID keypair**
(RFC 8292) that the server generates once. No vendor account, no
certificate, no app store: `hxd` makes one on first start when `[push]` is
configured and hands it to uniqush with `/addpsp`. That keypair is what
makes a registration *this server's*. A push service accepts pushes to an
endpoint only when they are signed by the key the subscription was made
with.

The login reply offers it, to sessions that can take it up:

```jsonc
"caps": [ "push", … ],
"push": {
  "vapid": "BEl6…",        // the server's public key, base64url, uncompressed P-256
  "types": ["webpush"],    // what push_register accepts here
  "content": "sender"      // what a notification will say: full | sender | generic
}
```

Present only for a session with a mailbox, so a guest is never asked, as
news offers `subscribe` only to one (news.md §9.1). `content` is there so
a client can tell its user, before they agree, whether the text of their
messages will leave the server.

**The device's consent is the client's to ask for.** The server never
asks. In a browser, the client asks the user for notification permission,
then calls `pushManager.subscribe({ userVisibleOnly: true,
applicationServerKey: push.vapid })`, and sends the resulting endpoint and
keys as `push_register`. On Android, a UnifiedPush distributor is asked
for an endpoint for that server, which UnifiedPush calls an *instance*.
Either way the result is per server by construction. A subscription is
bound to one application server key, so a browser client that talks to
three servers holds three subscriptions, one service-worker registration
each, and turning one off touches nothing else.

This settles §11's question about the service: **per server**. One uniqush
may still serve several hxd-ng instances, each under its own `service`
and its own VAPID keypair.

### 8.2 Native apps: the credentials belong to the app

APNs and FCM do not work this way, and no configuration makes them. An
APNs key is issued to the developer account that owns an app's bundle id,
and FCM's credentials to the Firebase project the app is built against. An
operator who did not publish the app cannot push to it. So a mobile app
distributed through a store, and pointed at servers run by strangers,
cannot have each server hold its own APNs credentials.

**The answer is a relay the app's publisher runs**, and it is the one
Matrix (a "push gateway") and Mastodon (a Web Push → APNs relay) arrived
at for the same reason:

- The app registers with its platform (APNs or FCM) and gets a device
  token.
- It asks its publisher's relay for a **Web Push endpoint** bound to that
  token — an opaque URL.
- It registers that endpoint with each server as `type: "webpush"`, with
  keys it generated itself.
- Each server pushes to the relay exactly as it pushes to ntfy: RFC 8291
  ciphertext, signed with that server's VAPID key.
- The relay forwards the ciphertext to APNs or FCM as a data payload, and
  the app decrypts it on the device.

What this buys:
- **Operators configure nothing vendor-specific.** Every server speaks
  only Web Push, which is uniqush's working backend (§1), and `apns` and
  `fcm` PSPs are needed only by an operator who ships their own build.
- **The relay cannot read the payload.** It holds no key for it, the way
  ntfy cannot today (§6). With §5.1's sealing on top, neither can Apple.
- **One set of vendor credentials**, held by the one party Apple and
  Google will issue them to.

What it costs:
- **The relay sees metadata**: which servers a device uses, and when they
  push.
- **It is a service the publisher has to keep running.** A relay that is
  down is push that is down for every server that app talks to. Its
  obligations are the same as §4's for uniqush: a timeout, a breaker,
  and a doorbell that failing to ring loses nothing.

The relay knows nothing about Hotline, accounts, or hxd-ng. It maps
endpoint paths to device tokens, and it belongs to the app, not to this
repository. It is written down here because it is what makes "every
operator sets their own credentials" true for mobile as well as for the
browser.

## 9. Staging

Each stage is a branch with tests, in the house style. P1 and P2 are
Phase 7 item 2 and are listed because item 3 is worthless without them.

1. **P1 — durable inbox.** ✅ **Done 2026-09**, designed in
   [private-messages.md](private-messages.md) and staged there as M1–M4.
   DMs for non-active sessions persist with read state, addressed by
   account login rather than the recycling uid, on **SQLite** rather than
   Postgres — a server that wants offline messages should not have to gain
   a database daemon, and the trait is the seam Postgres arrives behind
   when clustering needs a store several nodes can share. Mentions are not
   in it (§11).
2. **P2 — the notify decision.** ✅ **Done 2026-09.** The domain computes
   "this message should notify account X" on the stored-message path that
   both wires call, and hands it to a `NotificationGateway`; with none
   configured, nothing is sent. Unit-tested in `hxd-core` with a recording
   fake and no network at all: detached and absent notify, an attentive
   session does not, a message to your own account is not news, and a
   recipient with no inbox earns nothing because a push about a message
   that was never stored is a doorbell for nothing. Idle notifies too, by
   the rule, though nothing sets idle yet (hotline-ng.md §12). Mention
   parsing and cross-device dedup remain open.
3. **P3 — `hxd-push-uniqush`.** The HTTP client: the subscriber-id
   mapping with its two prefixes (§5), the device index keyed
   `(subscriber, devid)` with each certificate's expiry beside it (§5.1),
   `/subscribe`, `/unsubscribe`, `/push`, payload construction per kind of
   notice and per content policy (minding the reserved field names and
   the Web Push size ceiling), dropped-delivery-point logging, and — not
   optional, see §4 — an aggressive client timeout plus a circuit breaker,
   so a wedged sidecar degrades to no-push rather than to backpressure.
   Tested against a mock HTTP server; no uniqush needed in CI.
4. **P4 — ng protocol.** `push_register` / `push_unregister` with the
   device taken from the certificate on an identity session, the `caps`
   entry and the login reply's `push` block (§8.1), the VAPID keypair
   generated on first start, config (`[push]` block), the claim, purge and
   rotation calls of §5 and §5.1, and the docs including the §7 warnings.
   E2E with the scripted ng client and a stub gateway, and in hx-ng, whose
   browser client is the first thing that can actually say yes to a
   permission prompt.
5. **P5 — a real end-to-end.** A UnifiedPush distributor (ntfy) on a real
   Android device, a real uniqush, a real hxd-ng: DM a detached user, watch
   the phone buzz. This is the exit criterion; everything before it is
   plumbing that hasn't met a vendor yet.

6. **P6 — sealed payloads.** The `hl-identity/push/v1` sealing to a
   device's `device_enc` (§5.1), specified and vectored in `hl-identity`,
   implemented in hx-ng's library, and switched on per registration where
   the device has a certificate. Independent of P5; it is what makes
   `content = "full"` safe to recommend.

APNs and FCM are deliberately absent from the staging. APNs is blocked on
an Apple developer account and an app that doesn't exist (uniqush's HTTP/2
path itself is no longer the blocker — it is verified as far as Apple's
sandbox allows). FCM is blocked only on an app: uniqush's
`examples/fcm-demo` delivers to a browser in ten minutes, so an
**FCM-to-browser P5b** is a cheap second real-world check once P5 passes,
and it exercises the gateway's per-backend payload shaping (§6) that the
Web Push path doesn't. When the mobile app is real enough to have a bundle
id, it gets the relay of §8.2, and the servers need no changes at all:
they already speak Web Push. The `apns` and `fcm` registration types stay
for an operator who publishes their own build, where each is a different
`pushservicetype` on a different PSP.

## 10. Risks, honestly

| Risk | Severity | Response |
|---|---|---|
| FCM delivery to an Android device unverified (browser verified) | Low **for us** — no Play Store presence either | UnifiedPush covers de-Googled Android; the browser path is a cheap P5b |
| APNs never delivered to a real device | Low now, blocking later | Needs an Apple account and an app; P5 is Android-first by design |
| Second daemon + Redis is real operational weight for a small server | Medium | Push is optional and off by default; a small legacy-only server is unaffected |
| Maintainer bias toward our own project | Medium — it's the kind of bias that doesn't feel like one | The trait, the separate crate, and a `WebPushGateway` escape hatch are the mitigation; re-evaluate at P3 if the sidecar is fighting us |
| uniqush's unauthenticated API exposed | **High if misconfigured** — `/subscriptions` hands out send-capable device credentials, `/stop` kills the daemon | Loopback only, documented at §7 and repeated in the deployment docs; the gateway's own device index means we never call `/subscriptions` in normal operation |
| Subscriber-id collision, uid reuse, or a retaken login | **High** — wrong person's DMs | The mailbox mapping (§5) never touches uids, keys identities by fingerprint, keeps the two kinds apart by prefix, and gives login-keyed subscribers the mailbox's purge and claim obligations |
| Stale delivery points accumulate as endpoints rotate | Medium — pushes to addresses nobody reads | The device index is keyed `(subscriber, devid)`, so a re-registration replaces; on identity sessions `devid` is the certificate's and cannot drift (§5.1); vendor 404/410 is the backstop, not the plan |
| A lost or stolen device keeps receiving notifications | Medium — a stranger reads the lock screen | Identity devices stop at certificate revocation or expiry (§5.1); password devices only at `push_unregister`, which is one more reason identity accounts are the recommended case |
| The app publisher's relay (§8.2) goes down or goes bad | Medium for mobile, none for the browser | It sees metadata and never content; failing to ring loses nothing; a browser or UnifiedPush device does not use it |
| `/push` blocks; a slow provider becomes our latency | Medium | `notify` is spawned, never awaited; client timeout + circuit breaker in P3 |
| Redis loses the delivery-point set | Medium | Persistence required and documented; devices re-register on login, so recovery is a login cycle |

## 11. Open questions

- **Mentions need a definition.** Nick-match in chat text is the obvious
  one, but nicks aren't unique on a Hotline server (hotline-ng.md §12
  keeps duplicates legal) and nicks change freely. A mention that
  notifies the wrong person is worse than one that misses. **News has
  one, by construction** (news.md §10.5): a reference names an article,
  and an article has exactly one author. Chat is still open, and "cite
  the thing, not the person" is the shape to try first.
- ~~**Do legacy-originated PMs push?**~~ — **answered 2026-09: yes, and
  the decision is in the domain.** Phase 7 item 5 says a legacy client's
  PM to a detached user is "accepted, queued, and pushed", so both wires
  reach the same rule by calling the same function; the legacy path
  silently skipping it was the failure to avoid, and placing the decision
  in `hxd-core::chat` is what avoids it.
- **Coalescing.** Twenty chat lines in a busy room shouldn't be twenty
  buzzes. **Answered for news** (news.md §10.7): a scope rings only when
  its subscriber had caught up with it, which needs the cursor news has
  and chat does not, with a per-account hourly ceiling underneath and the
  scope as the vendor collapse key. For chat — which in practice means
  private messages, the only chat that pushes — a per-account rate limit
  or a digest window is still needed before P5 is pleasant to live with.
- ~~**Whether `service` should be per-server or per-app.**~~ — **answered
  2026-09: per server** (§8.1). Each server has its own VAPID keypair and
  its own `service`; what is per app is the relay a native app's
  publisher runs (§8.2), which the servers never need to know about.
- **What a multi-server app shows.** A phone following three servers
  holds three registrations and gets three streams of pushes, each
  naming its server. Whether a client merges them into one inbox, and
  what "mark as read" means across them, is the app's to design. The
  protocol gives it one thing to hold on to: an identity fingerprint is
  the same on every server that identity uses.
- Whether uniqush should be vendored for
  version-pinning and reproducible deployment, or simply documented as an
  external dependency with a minimum version — which is **2.8.0** either
  way, and which needs Go 1.25+ to build.
