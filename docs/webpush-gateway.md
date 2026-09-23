# The Web Push gateway: the device registry hxd-ng keeps itself

Status: built — the registry, the sender, the two ng requests and
`[push]` on the server, and hx-ng as the client that asks for
permission and renders what arrives. What is left is §9's G5, a real
end-to-end against a phone. Staged in §9; each stage marks itself there
as it lands.

[push-notifications.md](push-notifications.md) §0 decided that the first
gateway is `WebPushGateway`, in-process, and that when it is built it
gets a document of its own. This is that document. It is the normative
design of what hxd-ng ships: the device registry, the VAPID credential,
the RFC 8291 sender, the two ng requests, and the failure behavior of a
push that meets a provider having a bad day.

**What it does not restate.** The seam
(push-notifications.md §4), the subscriber model and the obligations a
login-keyed mailbox owes (§5), what an identity device adds (§5.1), when
a push happens and what content policy means (§6), the ng requests and
the login block (§8), and the per-server credential model (§8.1) are
unchanged by moving the sender in-process, and they are normative where
they stand. So are the two rules of §7 that are not about uniqush — the
account comes from the session, and a guest is refused `no_mailbox` —
which §8 restates. What changes is everything that was uniqush's job
and is now ours. This document says only that, plus the parts §9's P3
left to the implementation.

---

## 1. What moving in-process changes

| Concern | With the sidecar | Here |
|---|---|---|
| Device registry | uniqush's, with a thin index of ours beside it (§5) | ours, and the only one. A `PushStore` beside the inbox and the news stores |
| Delivery-point identity | a hash of the fixed data, so a changed endpoint accumulates a second device (§5) | the row's own key, `(mailbox, devid)`, so a changed endpoint replaces |
| RFC 8291 encryption | uniqush's, over a cleartext REST hop that could log the plaintext (§6) | ours, in this process. The ciphertext leaves the server and nothing between here and the device holds a key for it |
| VAPID keypair | uniqush's PSP, readable over an unauthenticated port (§7) | a file the operator owns, `0600`, never served |
| RFC 8030 `Topic` | not set; the collapse key rode `msggroup` and only on FCM (§6) | set, so the collapse key news designed (news.md §10.7) works on the wire it was designed for |
| TTL and urgency | hardcoded 12 hours, `normal` (§6) | per notification kind, `[push]` configurable |
| SSRF refusal | inherited from uniqush | ours to implement, §6 below, and it is not optional |
| Unauthenticated local port | the deployment hazard §7 is about | none. There is no port |
| APNs, FCM | uniqush's backends | not here. A native app reaches them through the publisher's relay (§8.2 there), which speaks Web Push to us like any other endpoint |

The one thing the sidecar had that this does not is **vendor breadth**,
and §8.2 of that document is why it costs us nothing today: an app that
needs APNs registers a relay endpoint, and every server it talks to still
speaks only Web Push.

## 2. The registry

A device is a row. The store trait lives in `hxd-core` beside
`MessageStore` and `NewsStore`, and the SQLite implementation beside
theirs: in the file the inbox, history or news keeps, in that order of
preference, unless `[push] db` names one of its own. `hxd inbox purge`
looks where the server writes, by the same rule.

```rust
pub struct Device {
    /// Whose. The mailbox rule, as mail and subscriptions use it.
    pub owner: Mailbox,
    /// The key the owner names this device by: the device fingerprint —
    /// the SHA-256 of the device key (hotline-ng-identity.md §3.2), not
    /// of its certificate, so a renewal keeps it — on an identity
    /// session, and the client's own opaque value on a password one
    /// (push-notifications.md §5.1).
    pub devid: DeviceId,
    /// Where to POST. Absolute https URL, checked by §6 before it is
    /// stored and again before every send.
    pub endpoint: String,
    /// The subscription's public key, P-256 uncompressed, 65 bytes.
    pub p256dh: [u8; 65],
    /// The subscription's auth secret, 16 bytes.
    pub auth: [u8; 16],
    /// When the device certificate expires, for a device that has one:
    /// past it the row is skipped and then swept (§5.1 there). `None`
    /// for a password device, which expires only when it is removed.
    pub expires: Option<SystemTime>,
    pub registered_at: SystemTime,
    /// Advanced on every accepted send, so an operator can see which
    /// devices are live without reading a provider's logs.
    pub last_push_at: Option<SystemTime>,
}
```

`(owner, devid)` is the primary key, and registering over it replaces —
which is the convergence §5.1 asked for, and it is the whole reason the
row is keyed this way rather than by the endpoint. A renewed certificate
keeps its device key, so its re-registration replaces its own row and
carries the new `expires` with it.

**A mailbox holds a bounded number of devices**, `[push] max_devices`
(default 20). A password session names its own `devid`, so without a cap
one account could register rows without end, and every row is a request
per notification to a destination the account chose (§5, §6). Past the
cap a new `devid` is refused `too_many_devices`, as news refuses a
follow past `max_subs` (news.md §10.12); re-registering one the mailbox
already has is a replacement and always succeeds. Refusing rather than
evicting the oldest is deliberate: an eviction would let a session
without `manage` push the owner's phone out of the table by registering
enough of its own.

**The mailbox obligations are the same as mail's and subscriptions', at
the same call sites** (§5 there), and they are the reason the store is a
`hxd-core` trait rather than the gateway crate's private business:

- `devices_claim(login, fingerprint)` — linking an identity moves the
  rows, exactly as `MessageStore::claim` and `NewsStore::subs_claim` do.
  Where the identity already has a row under the same `devid`, the
  identity's own row wins and the login's is dropped. A claimed password
  device keeps `expires: None` and the `devid` its client chose: it was
  the account's device before the link and still is, and it leaves by
  `push_unregister` like any other — `all: true` from a device with
  `manage` included.
- `devices_purge(&Mailbox)` — deleting an account takes its devices.
- `devices_rotate(from, to)` — **drops rather than moves** (§5.1): a
  successor has not vouched for the predecessor's devices, and they
  re-register at their next login. The signature matches its siblings so
  the caller cannot forget one; the implementation deletes.

A rename is a deletion and a registration, as it is for mail.

**Expiry is a comparison, not a sweeper.** A row past `expires` is
skipped at send time whether or not anything has deleted it; a periodic
sweep deletes expired rows across every mailbox, as housekeeping a
server may skip and still be correct.

**What §5.1 promised is revocation, and it has not landed.** §5.1 says a
lost phone stops buzzing *when its key is revoked*. The server-local
revocation list that would do that (`[identity] revoked_devices`,
[`identity-registrar.md`](identity-registrar.md) §7.3) is designed and not
built. Until it is, a lost identity device is silenced by the owner —
`push_unregister` naming it, or `all: true`, from a device holding
`manage` (§7) — or by its certificate expiring, which with the
recommended lifetimes can be weeks. That gap is real and is this
design's, not the sidecar's; when the list lands it deletes the rows of
a named device fingerprint at the same moment it refuses the key.

## 3. The credential

One VAPID keypair per server (P-256, RFC 8292), generated on first start
when `[push]` is configured and written to `[push] vapid_key` (default
`vapid.key` beside the accounts directory), created `0600` and written
whole or not at all. The public key
is what the login reply offers as `push.vapid` (§8.1 there) and what the
client's subscription is bound to.

**Losing or replacing it invalidates every registration**, because a push
service accepts a push only when it is signed by the key the subscription
was made with. The server therefore never regenerates a key that exists,
refuses to start on a key it cannot read rather than quietly minting a
second one, and logs the public key's fingerprint at startup so an
operator can tell two servers apart.

**A missing key is not a first start if there are devices.** A deleted
file, or a `vapid_key` path changed in the configuration, looks exactly
like a server that has never had one. So a key is generated only when the
registry is empty; a server whose store holds devices and whose key file
is absent refuses to start and says why, rather than minting a key every
one of those rows is already invalid against.

**Rotating it deliberately is `hxd push rekey`**, and it drops every
device row in the same step as it writes the new key. Each row is bound
to the old key, and a push service answers a mismatched one with a
`401` or `403` — which §5 never deletes on — so rows kept across a rekey
would fail on every notification, for as long as their clients stay
away, without ever being retired. Dropping them costs nothing that was
not already lost: every client re-subscribes at its next login.

The JWT is signed ES256 over `{aud, exp, sub}`, `aud` the endpoint's
origin as RFC 6454 serializes it (scheme and lowercase host, the port
only where it is not 443), `exp` no more than 24 hours out (12 by
default), signed per push — an ES256 signature costs less than the key
agreement beside it, and a cache is state for nothing — and `sub` the
operator's `mailto:` or `https:` contact from `[push] contact`. The
contact is required: `[push]` without it is a configuration error,
because it is how a push service reaches an operator whose server is
misbehaving, and a service may refuse a push without one.

## 4. The send

Per device, per notification:

1. **Encrypt** (RFC 8291, `aes128gcm`), a fresh ephemeral P-256 keypair
   and a fresh random 16-byte salt per device per notification. Two HKDF
   stages: the first, salted with the subscription's `auth` secret over
   the ECDH secret, with info `"WebPush: info\0"` followed by the
   subscription's public key and the ephemeral one, yields the input
   keying material; the second, salted with the random salt, yields the
   content-encryption key and the nonce under RFC 8188's
   `"Content-Encoding: aes128gcm\0"` and
   `"Content-Encoding: nonce\0"`. Then AES-128-GCM over the plaintext
   and its `0x02` delimiter, into the RFC 8188 header block — salt,
   record size, and the ephemeral public key as the key id. The
   ciphertext is the body.
2. **Headers**: `Content-Encoding: aes128gcm`, `TTL`, `Urgency`,
   `Topic` where the notice has a collapse key, and
   `Authorization: vapid t=<jwt>, k=<public key>`.
3. **POST** to `endpoint`, with the timeout and breaker of §5.

**The plaintext is JSON, and the client renders it.** One object, with
`kind` naming which of the two it is, so a service worker can switch on
it:

```jsonc
{ "kind": "message", "from": "alice", "from_nick": "Alice",
  "text": "…", "id": "…", "unread": 3 }

{ "kind": "news", "reason": "reply", "from_nick": "Alice",
  "subject": "…", "excerpt": "…", "article": 412, "root": 398,
  "category": 3, "scope": "thread", "target": 398, "unread": 2 }
```

`from` is the sender's login, and absent for a sender with no mailbox
(a guest); `from_nick` is the nick they sent under. A news notice names
its scope the way the `news_notify` event does (news.md §10.6), `scope`
and `target` as two fields, so a client parses one shape whichever way
the notice reached it.

Content policy (§6 there) is applied **before** encryption. `full` sends
everything above. `sender` drops `text` and `excerpt` and keeps the
names and the subject — a subject is what a thread is called, and
without it the notice names nothing to open. `generic` drops the names
and the subject too, and keeps only what a client needs to open the
right thing and nothing an author wrote: `kind`, `reason`, the ids
(`id`, `article`, `root`, `category`, `scope`, `target`) and `unread`. A
client cannot be told something the server chose not to encrypt, which is
the point of applying it here rather than at render time.

**Size.** The RFC 8291 record is 4096 bytes including the header block
and the AEAD tag, so the plaintext ceiling is 3993 bytes and the practical
one is lower. `text` and `excerpt` are truncated on a character boundary
to fit the ceiling with the rest of the object around them, on our side,
with an ellipsis — never discovered at the provider (§6 there says so of
the sidecar, and it is more true of us, because a 413 costs a round trip
we could have avoided).

**TTL and urgency by kind.** A private message is `TTL` 4 weeks and
`Urgency: high`: it is durable in the inbox and worth waking a phone for.
A news notice is `TTL` 24 hours and `Urgency: normal`: the article is in
its thread either way, and a day-old "someone replied" is not worth a
notification. `[push] message_ttl` and `news_ttl` move the TTLs; the
urgency belongs to the kind and does not follow them.

**`Topic` is the collapse key.** `SubScope::key()` — `thread:398` — for a
news notice. For a private message it is the conversation, which is the
sender's mailbox: two messages from one person while the phone is out of
reach arrive as the later one, whose `unread` counts both. Senders with
no mailbox (guests) share one key. This is about private messages only;
room chat is not a notification kind, and §10's open question about
coalescing it is untouched. RFC 8030 restricts `Topic` to 32 characters
of base64url, so the header is the first 32 characters of the URL-safe
base64 of an HMAC-SHA256 of the key, under a secret derived from the
server's VAPID private key. Keyed, because a bare hash of `thread:398`
is enumerable by anyone who can count threads, and a provider that logs
the header should learn from it only that two pushes collapse.

## 5. When it goes wrong

`notify` must not block (§4 there), so every send is spawned. What the
spawned task does with an answer:

| Answer | What it means | What we do |
|---|---|---|
| `201`, `200`, `202` | accepted | stamp `last_push_at` |
| `404`, `410` | the subscription is gone | delete the row — but only if it still holds the endpoint that answered. A client that re-subscribed while this push was in flight has replaced the row, and the old endpoint's `410` is about the old endpoint |
| `429` | slow down | drop this push, and pause **this subscription** for `Retry-After` (at most an hour; `breaker_cooldown` when absent or unreadable) |
| `413` | our record was too big | log it loudly with the kind and the byte count, because §4's truncation should have made it impossible |
| other `4xx` | our JWT, our key, or our request | log with the origin; do not retry, do not delete the row — a rejected credential is an operator problem, and deleting the user's devices over it would turn a configuration mistake into data loss |
| `5xx`, timeout, connect error, refused destination | the provider or the network | drop, count it against the origin's breaker |

**The breaker hears only about the origin's health.** A `4xx` is an
answer about one subscription or about our credential, and the origins
that matter most — FCM, Mozilla's autopush, Apple — each serve every
subscriber of their browser. If a stale subscription's `403` counted
against `fcm.googleapis.com`, one abandoned Chrome profile would trip the
breaker and silence every Chrome user on the server. So a `4xx` never
counts, and a `429` pauses the subscription that drew it rather than the
origin: a limit that really is the origin's recurs on each subscription
and pauses each in turn, which costs a few requests; a pause scoped to
the origin would let one device's throttling mute everyone behind it.
Removal paths are several — the client, the vendor's `404`/`410`,
expiry, rotation, purge — and the vendor's is the only one decided by a
party other than us and the account.

**A timeout and a breaker, per origin, and they are load-bearing** (§4
there). The timeout is 10 seconds by default (`[push] timeout`) and
covers the whole send, name resolution included. Past
`breaker_failures` consecutive failures (default 5) an origin is skipped
entirely for `breaker_cooldown` (default 60 seconds). After the cooldown
exactly one probe is let through, and every other send to that origin is
skipped until the probe answers: success closes the breaker, failure
reopens it. A wedged provider degrades to no-push rather than to a task
queue that grows. Nothing here retries: the message is in the inbox and
the article is in its thread, and a retried doorbell is worth less than
the memory it costs.

**Concurrency is bounded, overall and per origin.** A semaphore caps
in-flight sends (`[push] max_inflight`, default 64) so a fan-out to a
large account, or a provider answering slowly, cannot become unbounded
task growth. A second cap per origin (`[push] max_inflight_per_origin`,
default 8) keeps one origin that answers slowly — by accident, or
because the account that registered it wants it to — from holding the
permits every other origin's sends need. Past either cap a send is
dropped rather than queued, and logged at debug. A dropped doorbell is a
degraded notification; a queue that never drains is an outage.

## 6. The destination is attacker-chosen, and it is a URL we fetch

`endpoint` comes from the client. The sidecar refused non-routable
destinations for us (§7 there); here it is our check, and it runs in two
halves, because one of them can be answered where the registration is
and the other cannot. **At registration**: the URL's shape, and the
address itself where the host is a literal — a client naming
`https://127.0.0.1/` is told no while it is still asking. **Before every
send**: what the host's *name* resolves to, because DNS moves and a name
that answered publicly last week can answer `127.0.0.1` today. The
rules, either way:

- `https` only, no userinfo, no fragment. Any port: a self-hosted push
  service need not sit on 443, and the address check below is what keeps
  a port from being a way in.
- The address must be globally routable, judged against the IANA IPv4
  and IPv6 special-purpose address registries rather than a list of the
  familiar cases: no loopback, private, shared (CGNAT, `100.64.0.0/10`),
  link-local, unique-local or site-local, multicast, documentation,
  benchmarking, reserved, broadcast or unspecified address. An IPv6
  address that carries an IPv4 one — v4-mapped, v4-compatible, NAT64's
  well-known prefix (`64:ff9b::/96`), 6to4 (`2002::/16`) — is judged by
  the IPv4 address inside it; on a host with NAT64, `64:ff9b::a00:1`
  *is* `10.0.0.1`. Local-use NAT64 (`64:ff9b:1::/48`), whose IPv4 address
  is not in a fixed place, and `2001::/23`, Teredo among it, are refused
  outright.
- **The address checked is the address connected to.** A name is
  resolved once per send, every answer is checked, and the connection is
  made to those checked addresses and no others. Checking one resolution
  and letting the HTTP client make its own is a DNS-rebinding hole: an
  attacker's name server answers a public address to the check and
  `169.254.169.254` to the connect. For the same reason no proxy is
  honored — `HTTPS_PROXY` in the environment would move resolution
  somewhere this check cannot see.
- Redirects are never followed.
- Connections are not pooled. Each send is its own connection, closed
  when it answers, so an endpoint that accepts and never hangs up costs
  one timeout and no file descriptor after it.
- The response body is never read; the status and `Retry-After` are all
  that is used.
- `[push] allow_private_endpoints` exists for the operator running their
  own push service on a private network, defaults false, and is
  documented as what it is. It lifts the address check — at registration
  and at send, for names and for literal addresses alike — and nothing
  else.

Refusing at registration gives the client an error it can show; refusing
at send time deletes nothing, counts against the origin's breaker, and
skips. The shape half lives in the domain, beside the store that will
hold the row; the resolver half lives in the gateway, because the domain
is synchronous and has no business doing DNS.

## 7. The ng protocol

Exactly push-notifications.md §8 and §8.1: `push_register`,
`push_unregister`, the error codes, `caps: ["push"]`, and the login
reply's `push` block. Two clarifications the in-process registry settles
that §8 left to the gateway:

- **`devid` is ours and opaque to the client** on an identity session
  (the device fingerprint, §5.1 there) and the client's own value on a
  password session: 8 to 64 bytes of printable ASCII, refused otherwise.
  It is the replace key of §2, so a client that invents a new one per
  registration accumulates devices until §2's cap refuses it; hx-ng
  generates one per install and keeps it.
- **Where the device comes from.** Whether a session has a device
  certificate is decided when it logs in, and it is a property of the
  session from then on (hotline-ng-auth.md §7.2): a session resumed on a
  socket that presented no certificate is still the certificate's, with
  its `message` and `manage` bits and its fingerprint as `devid`. The
  token is what proves continuity, so whatever certificate a resuming
  socket presents, or does not, is not consulted.
- **A password session cannot name an identity device.** A `devid` that
  is spelled like a device fingerprint — 64 lowercase hex characters — is
  refused from a session without a certificate, so a password login on a
  linked account cannot overwrite the phone's row and strip its expiry.
- **`push_unregister { all: true }`** deletes every row of the mailbox in
  one store call, needs `manage` on an identity session (§5.1 there), and
  answers `{}` whether or not there was anything to delete, because
  telling a client how many devices an account has is not this request's
  business.

## 8. Configuration

```toml
[push]
contact = "mailto:admin@example.org"  # VAPID `sub`; required
content = "sender"                    # full | sender | generic (§6 there)
vapid_key = "vapid.key"               # generated on first start, 0600
db = "server.sqlite"                  # default: [inbox]'s, [history]'s or [news]'s file
timeout = 10
message_ttl = 2419200                 # 4 weeks
news_ttl = 86400
breaker_failures = 5
breaker_cooldown = 60
max_inflight = 64
max_inflight_per_origin = 8
max_devices = 20                      # per mailbox (§2)
allow_private_endpoints = false
```

Absent `[push]`, there is no gateway, `caps` has no `push`, the login
reply has no `push` block, and `push_register` answers `not_available` —
the same shape news uses for a server with no `[news.notify]`.

## 9. Staging

1. **G1 — the registry. Built.** `Device`, `PushStore`, `MemoryDevices`,
   the SQLite table at schema version 7, the conformance suite over
   both, and the three obligations paid from `Core::inbox_claim`,
   `inbox_rotate` and `inbox_purge` beside mail's and news's.
   `hxd inbox purge` takes an account's devices with its mail, and
   `Core::sweep_devices` is the expiry housekeeping. No network, no
   crypto, nothing to configure.
2. **G2 — the sender. Built.** `hxd-push-webpush`: the VAPID keypair
   and its token, RFC 8291 encryption, RFC 8030's headers, the
   destination check, the per-origin breaker and the in-flight caps, and
   the answer table. RFC 8291's own vector, and RFC 8292's example token
   verified (an ES256 signature is randomized, so it can be verified but
   not reproduced), are the tests for the two that cannot be checked by
   reading; the answer table and everything the gateway decides are
   tested behind a transport seam, so no TLS server is needed in CI.
3. **G3 — the wire. Built.** `push_register` and `push_unregister`, the
   login reply's `push` block and `push` in `caps`, `[push]` and the
   `push` Cargo feature, the keypair read — or, on a first start, created
   — before anything binds, the devices in the store, the expiry sweeper
   beside the inbox's, and `hxd push rekey`. E2E against a real server
   with the real registry. `hxd push devices` is not in it: an operator
   who wants to count devices has the store, and it lands if one ever
   needs it.
4. **G4 — the client. Built, in hx-ng.** hx-ng asks for permission, subscribes with the
   offered key, registers, and renders both payload kinds in its service
   worker. The first thing in the chain that can say yes to a prompt.
5. **G5 — a real end-to-end.** A browser and a UnifiedPush distributor on
   a real device against a real server: DM a detached user, watch it
   buzz. The exit criterion, as push-notifications.md §9 P5 says; the
   only difference is that there is no sidecar in the picture.

G1 and G2 are independent and can land in either order. G3 needs both.

## 10. Open

- **Sealing to the device** (push-notifications.md §5.1, §9 P6) is
  unchanged and still wants `hl-identity` vectors. It matters less here
  than it did with a sidecar — there is no REST hop holding our
  plaintext — and it still matters for a relay-backed native app, which
  is exactly the case that has no browser between it and a vendor.
- **Chat mentions** are still not a notification kind (§11 there). News
  answered coalescing for itself (news.md §10.7), private messages
  collapse per sender (§4), and room chat has not been asked.
- **Which failures deserve an operator's attention** is a log level
  today. If a server ever accumulates enough devices for that to be
  noise, the answer is a counter per origin rather than a quieter log.
