# Push notifications: delegating the device registry to uniqush-push

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
hxd-ng is GPL-2.0-or-later, forced by `hotline-proto`'s hxd ancestry.
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

```rust
#[async_trait]
pub trait NotificationGateway: Send + Sync {
    /// Register one device for an account. Idempotent.
    async fn register(&self, acct: &AccountId, dev: &DeviceRegistration)
        -> Result<(), GatewayError>;

    /// Drop one device, or all devices for an account (logout-everywhere).
    async fn unregister(&self, acct: &AccountId, dev: Option<&DeviceId>)
        -> Result<(), GatewayError>;

    /// Best-effort delivery. Never blocks a chat or PM path.
    async fn notify(&self, acct: &AccountId, n: &Notification)
        -> Result<NotifyOutcome, GatewayError>;
}
```

A `NoopGateway` is the default. `UniqushGateway` lives in its own crate
(`hxd-push-uniqush`) so that a build without push pulls in no HTTP client
at all, and so a future `hxd-push-webpush` is a sibling rather than a
rewrite.

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

**The mapping: `hx-<lowercase hex of the account name's canonical UTF-8
bytes>`.** Deterministic, collision-free, inside the accepted charset, and
reversible — which matters at three in the morning when you are reading
uniqush's logs and want to know whose device that is. No new state, no
migration, no lookup table. Long names produce long subscriber ids;
uniqush does not care, and Hotline logins are short.

If a future account model grows a stable opaque account id (the database
backend is the natural place), the subscriber id becomes that id instead,
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

## 8. Protocol additions

Two new ng requests, fitting the existing shapes in
[hotline-ng.md](hotline-ng.md) §7:

| `req` | params | ok | notes |
|---|---|---|---|
| `push_register` | `type` (`"unifiedpush"`\|`"webpush"`\|`"apns"`\|`"fcm"`), `endpoint?`, `p256dh?`, `auth?`, `token?`, `devid?` | `{}` | account taken from the session, never from params; idempotent |
| `push_unregister` | `devid?` (omit = all devices) | `{}` | logout-everywhere is `push_unregister` with no `devid` |

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

## 9. Staging

Each stage is a branch with tests, in the house style. P1 and P2 are
Phase 7 item 2 and are listed because item 3 is worthless without them.

1. **P1 — durable inbox.** DMs and mentions for non-active sessions persist
   with read state. Postgres arrives here (Phase 7 item 4). No push yet.
2. **P2 — the notify decision.** The domain computes "this event should
   notify account X," calls a `NotificationGateway`, and the only
   implementation is `NoopGateway`. Unit-testable in `hxd-core` with a
   recording fake and no network at all. **This is where the interesting
   bugs are** — idle/detached/absent transitions, mention parsing,
   self-notification suppression, dedup across a user's own devices.
3. **P3 — `hxd-push-uniqush`.** The HTTP client: subscriber-id mapping,
   the device index (§5), `/subscribe`, `/unsubscribe`, `/push`, payload
   construction per content policy (minding the reserved field names and
   the Web Push size ceiling), dropped-delivery-point logging, and — not
   optional, see §4 — an aggressive client timeout plus a circuit breaker,
   so a wedged sidecar degrades to no-push rather than to backpressure.
   Tested against a mock HTTP server; no uniqush needed in CI.
4. **P4 — ng protocol.** `push_register` / `push_unregister`, the `caps`
   list, config (`[push]` block), and the docs including the §7 warnings.
   E2E with the scripted ng client and a stub gateway.
5. **P5 — a real end-to-end.** A UnifiedPush distributor (ntfy) on a real
   Android device, a real uniqush, a real hxd-ng: DM a detached user, watch
   the phone buzz. This is the exit criterion; everything before it is
   plumbing that hasn't met a vendor yet.

APNs and FCM are deliberately absent from the staging. APNs is blocked on
an Apple developer account and an app that doesn't exist (uniqush's HTTP/2
path itself is no longer the blocker — it is verified as far as Apple's
sandbox allows). FCM is blocked only on an app: uniqush's
`examples/fcm-demo` delivers to a browser in ten minutes, so an
**FCM-to-browser P5b** is a cheap second real-world check once P5 passes,
and it exercises the gateway's per-backend payload shaping (§6) that the
Web Push path doesn't. When the mobile app is real enough to have a bundle
id, the gateway needs no changes: each is a different `pushservicetype`
on a different PSP.

## 10. Risks, honestly

| Risk | Severity | Response |
|---|---|---|
| FCM delivery to an Android device unverified (browser verified) | Low **for us** — no Play Store presence either | UnifiedPush covers de-Googled Android; the browser path is a cheap P5b |
| APNs never delivered to a real device | Low now, blocking later | Needs an Apple account and an app; P5 is Android-first by design |
| Second daemon + Redis is real operational weight for a small server | Medium | Push is optional and off by default; a small legacy-only server is unaffected |
| Maintainer bias toward our own project | Medium — it's the kind of bias that doesn't feel like one | The trait, the separate crate, and a `WebPushGateway` escape hatch are the mitigation; re-evaluate at P3 if the sidecar is fighting us |
| uniqush's unauthenticated API exposed | **High if misconfigured** — `/subscriptions` hands out send-capable device credentials, `/stop` kills the daemon | Loopback only, documented at §7 and repeated in the deployment docs; the gateway's own device index means we never call `/subscriptions` in normal operation |
| Subscriber-id collision or uid reuse | **High** — wrong person's DMs | The hex mapping (§5) makes collisions impossible and never touches uids |
| Stale delivery points accumulate as endpoints rotate | Medium — pushes to addresses nobody reads | The gateway's device index lets us unsubscribe the old triple when a client re-registers a changed endpoint; vendor 404/410 is the backstop, not the plan |
| `/push` blocks; a slow provider becomes our latency | Medium | `notify` is spawned, never awaited; client timeout + circuit breaker in P3 |
| Redis loses the delivery-point set | Medium | Persistence required and documented; devices re-register on login, so recovery is a login cycle |

## 11. Open questions

- **Mentions need a definition.** Nick-match in chat text is the obvious
  one, but nicks aren't unique on a Hotline server (hotline-ng.md §12
  keeps duplicates legal) and nicks change freely. A mention that
  notifies the wrong person is worse than one that misses. Possibly
  mentions are out of scope for the first cut and DMs alone carry P1–P5.
- **Do legacy-originated PMs push?** Phase 7 item 5 says a legacy client's
  PM to a detached user is "accepted, queued, and pushed" — so yes, and
  the notify decision must live in the domain rather than in
  `hxd-ng-session`, or the legacy path silently skips it. The staging
  above assumes the domain placement; it's called out here because it's
  the kind of thing that gets implemented in the wrong crate by accident.
- **Coalescing.** Twenty chat lines in a busy room shouldn't be twenty
  buzzes. A per-account rate limit or a digest window is needed before
  P5 is pleasant to live with; where it lives (domain, gateway, or the
  vendor's own collapse keys) is undecided.
- **Whether `service` should be per-server or per-app.** One uniqush
  serving several hxd-ng instances wants distinct services; a single
  mobile app talking to several servers wants distinct VAPID keys per
  server anyway. Probably per-server, but it interacts with how the app
  handles multi-server accounts, which nobody has designed yet.
- Whether uniqush should be vendored as a submodule (as gtkhx is) for
  version-pinning and reproducible deployment, or simply documented as an
  external dependency with a minimum version — which is **2.8.0** either
  way, and which needs Go 1.25+ to build.
