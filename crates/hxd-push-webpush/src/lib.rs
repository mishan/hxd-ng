//! The in-process Web Push sender (`docs/webpush-gateway.md`).
//!
//! A `NotificationGateway` that encrypts to each of a mailbox's devices
//! (RFC 8291), signs the push with the server's own VAPID key
//! (RFC 8292), and POSTs it to the push service the client chose
//! (RFC 8030). No daemon, no Redis, no cleartext hop: what leaves this
//! process is ciphertext nothing between here and the subscriber's user
//! agent holds a key for.
//!
//! **`notify` never blocks and never retries.** The trait's contract is
//! that the message path hands the work off and returns; a push that
//! never arrives is a degraded notification, not a lost message, because
//! the message is in the inbox and the article is in its thread. So a
//! wedged push service costs a doorbell, and the timeout, the breaker
//! and the in-flight cap below are what make that true rather than
//! aspirational.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use hxd_core::inbox::Mailbox;
use hxd_core::notify::{Notification, NotificationGateway};
use hxd_core::push::{Device, PushStore};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

pub mod encrypt;
pub mod endpoint;
pub mod http;
pub mod payload;
pub mod vapid;

pub use payload::Content;
pub use vapid::{Vapid, VapidError};

/// `[push]`, as the server hands it over.
#[derive(Debug, Clone)]
pub struct Config {
    pub content: Content,
    /// How long to wait for a push service before giving up on this
    /// notification. Aggressive on purpose: a provider's bad minute must
    /// not become this server's.
    pub timeout: Duration,
    /// A private message is durable and worth waking a phone for.
    pub message_ttl: Duration,
    /// A news notice is not: the article is in its thread either way,
    /// and a day-old "someone replied" is noise.
    pub news_ttl: Duration,
    /// Consecutive failures before an origin is skipped outright.
    pub breaker_failures: u32,
    /// How long it stays skipped, after which one probe is let through.
    pub breaker_cooldown: Duration,
    /// Sends in flight at once, across every account. Past it a push is
    /// dropped rather than queued: a dropped doorbell is a degraded
    /// notification, a queue that never drains is an outage.
    pub max_inflight: usize,
    /// Sends in flight at once to any one origin, so that one answering
    /// slowly — by accident, or because the account that registered it
    /// wants it to — cannot hold the permits every other origin needs.
    pub max_inflight_per_origin: usize,
    /// For the operator running their own push service on a private
    /// network, and for nobody else.
    pub allow_private_endpoints: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            content: Content::default(),
            timeout: Duration::from_secs(10),
            message_ttl: Duration::from_secs(4 * 7 * 24 * 60 * 60),
            news_ttl: Duration::from_secs(24 * 60 * 60),
            breaker_failures: 5,
            breaker_cooldown: Duration::from_secs(60),
            max_inflight: 64,
            max_inflight_per_origin: 8,
            allow_private_endpoints: false,
        }
    }
}

/// One POST, as the transport sees it. No hxd-ng types: a transport
/// knows about HTTP and nothing else.
#[derive(Debug, Clone)]
pub struct Push {
    pub endpoint: String,
    /// Seconds, as RFC 8030 spells it.
    pub ttl: u64,
    pub urgency: &'static str,
    /// The RFC 8030 `Topic`, already hashed and cut to the header's
    /// 32-character alphabet.
    pub topic: String,
    pub authorization: String,
    /// The RFC 8291 record: header block and ciphertext.
    pub body: Vec<u8>,
}

/// What a push service said, as far as this gateway acts on it
/// (`docs/webpush-gateway.md` §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 200, 201, 202.
    Accepted,
    /// 404 or 410: the subscription is gone, and the vendor is retiring
    /// it — the one removal decided by neither us nor the account.
    Gone,
    /// 429, with whatever `Retry-After` said.
    Slow(Option<Duration>),
    /// 413: our record was too big, which the payload builder should
    /// have made impossible.
    TooBig,
    /// 400, 401, 403 and every other status that is neither success nor
    /// the provider's own trouble: our credential or our request. Never
    /// deletes a device — a rejected credential is an operator problem,
    /// and deleting the user's phones over a typo in the contact would
    /// turn a misconfiguration into data loss. Never counts against the
    /// origin either: it is an answer about one subscription or about
    /// us, and FCM answering one stale row with a 403 must not silence
    /// every Chrome user on the server.
    Rejected(u16),
    /// 5xx: the provider's trouble, which the breaker hears about.
    Failed(u16),
    /// A timeout, a connect error, a refused destination.
    Unreachable(String),
}

/// Where a push actually goes. The seam exists so the answer table above
/// is testable without a TLS server, and so the destination check is one
/// thing rather than two.
pub trait Transport: Send + Sync + 'static {
    fn post(&self, push: Push) -> Pin<Box<dyn Future<Output = Outcome> + Send>>;
}

/// One origin's recent history, for the breaker.
#[derive(Debug, Default, Clone, Copy)]
struct Breaker {
    consecutive: u32,
    /// When the cooldown ends, for an origin that is currently open.
    open_until: Option<Instant>,
    /// The cooldown ended and one send has been let through to see
    /// whether the origin is back. Every other send is skipped until it
    /// answers; without this, the first caller after a cooldown would
    /// clear the gate and the whole fan-out behind it would follow.
    probing: bool,
}

/// A lock that a panic elsewhere does not turn into a panic here. The
/// maps behind these locks hold nothing a half-finished update can make
/// unsafe to read, and a poisoned breaker must not become push that is
/// dead for everyone until a restart.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `now + d`, without the panic `Instant`'s `+` has for a `d` it cannot
/// represent. The durations here come from configuration and from push
/// services, and neither is ours to trust that far.
fn after(now: Instant, d: Duration) -> Instant {
    now.checked_add(d)
        .or_else(|| now.checked_add(http::MAX_RETRY_AFTER))
        .unwrap_or(now)
}

/// A send's place under the per-origin cap, given back when the send
/// ends however it ends.
struct OriginSlot {
    inner: Arc<Inner>,
    origin: String,
}

impl Drop for OriginSlot {
    fn drop(&mut self) {
        let mut inflight = lock(&self.inner.per_origin);
        if let Some(n) = inflight.get_mut(&self.origin) {
            *n -= 1;
            if *n == 0 {
                inflight.remove(&self.origin);
            }
        }
    }
}

/// The gateway, which is a handle: the state is in an `Arc` because
/// every send outlives the `&self` that started it, and a trait object
/// cannot hand itself out.
#[derive(Clone)]
pub struct WebPushGateway(Arc<Inner>);

struct Inner {
    devices: Arc<dyn PushStore>,
    vapid: Arc<Vapid>,
    config: Config,
    transport: Arc<dyn Transport>,
    breakers: Mutex<HashMap<String, Breaker>>,
    /// Subscriptions a push service answered `429` for, by endpoint, and
    /// until when. Per subscription rather than per origin: FCM, autopush
    /// and Apple each serve every subscriber of their browser, and one
    /// device's throttling must not mute all of them.
    paused: Mutex<HashMap<String, Instant>>,
    inflight: Arc<Semaphore>,
    per_origin: Mutex<HashMap<String, usize>>,
    /// The `Topic` HMAC's key, derived from the VAPID key so that it
    /// needs no file of its own and changes when that key does.
    topic_key: [u8; 32],
    /// The runtime to spawn onto, captured where one is known to exist
    /// rather than asked for on the message path — which may be any
    /// thread at all.
    runtime: tokio::runtime::Handle,
}

impl WebPushGateway {
    /// Build a gateway. Must be called from within a tokio runtime,
    /// which the server always is.
    pub fn new(
        devices: Arc<dyn PushStore>,
        vapid: Arc<Vapid>,
        config: Config,
        transport: Arc<dyn Transport>,
    ) -> Self {
        let inflight = Arc::new(Semaphore::new(config.max_inflight.max(1)));
        let topic_key = vapid.topic_key();
        WebPushGateway(Arc::new(Inner {
            devices,
            vapid,
            config,
            transport,
            breakers: Mutex::new(HashMap::new()),
            paused: Mutex::new(HashMap::new()),
            inflight,
            per_origin: Mutex::new(HashMap::new()),
            topic_key,
            runtime: tokio::runtime::Handle::current(),
        }))
    }

    /// The key a client subscribes against.
    pub fn vapid_public_key(&self) -> &str {
        self.0.vapid.public_key()
    }

    pub fn content_policy(&self) -> Content {
        self.0.config.content
    }
}

impl Inner {
    /// Is this origin currently skipped? Takes the breaker's lock and
    /// nothing else. When the cooldown ends exactly one probe is let
    /// through, and everything else waits for its answer.
    fn breaker_allows(&self, origin: &str, now: Instant) -> bool {
        let mut breakers = lock(&self.breakers);
        let Some(b) = breakers.get_mut(origin) else {
            return true;
        };
        match b.open_until {
            Some(until) if until > now => false,
            Some(_) if b.probing => false,
            Some(_) => {
                b.probing = true;
                true
            }
            None => true,
        }
    }

    /// What an origin's answer says about its health. `failed` only for
    /// the provider's own trouble — a 5xx, a timeout, no connection — and
    /// never for an answer about one subscription.
    fn breaker_record(&self, origin: &str, failed: bool, now: Instant) {
        let mut breakers = lock(&self.breakers);
        if !failed {
            breakers.remove(origin);
            return;
        }
        let b = breakers.entry(origin.to_string()).or_default();
        b.consecutive = b.consecutive.saturating_add(1);
        if b.probing || b.consecutive >= self.config.breaker_failures {
            b.open_until = Some(after(now, self.config.breaker_cooldown));
            b.probing = false;
            debug!(origin, "push: skipping an origin that keeps failing");
        }
    }

    /// Is this subscription paused by a `429`?
    fn paused(&self, endpoint: &str, now: Instant) -> bool {
        let mut paused = lock(&self.paused);
        match paused.get(endpoint) {
            Some(until) if *until > now => true,
            Some(_) => {
                paused.remove(endpoint);
                false
            }
            None => false,
        }
    }

    fn pause(&self, endpoint: &str, until: Instant, now: Instant) {
        let mut paused = lock(&self.paused);
        // Bounded by the number of registered devices anyway; pruned
        // here so a pause nobody looks at again does not stay forever.
        if paused.len() >= 1024 {
            paused.retain(|_, u| *u > now);
        }
        paused.insert(endpoint.to_string(), until);
    }

    /// A place under the per-origin cap, or `None` at the cap.
    fn origin_slot(self: &Arc<Self>, origin: &str) -> Option<OriginSlot> {
        let mut inflight = lock(&self.per_origin);
        let n = inflight.entry(origin.to_string()).or_default();
        if *n >= self.config.max_inflight_per_origin.max(1) {
            return None;
        }
        *n += 1;
        Some(OriginSlot {
            inner: self.clone(),
            origin: origin.to_string(),
        })
    }

    /// The whole of one notification's work, off the message path.
    async fn deliver(self: Arc<Self>, to: Mailbox, built: payload::Built, kind: Kind) {
        let now = SystemTime::now();
        // The store is synchronous, and on SQLite a read is a disk read:
        // off the runtime's worker threads, as every other store call
        // made from async code in this server is.
        let store = self.devices.clone();
        let who = to.clone();
        let devices = match crate::spawn_blocking("push", move || store.devices(&who, now)).await {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => {
                warn!("push: reading {}'s devices: {e}", to.login);
                return;
            }
            Err(e) => {
                warn!("push: reading {}'s devices: {e}", to.login);
                return;
            }
        };
        let topic = http::topic(&self.topic_key, &built.collapse);
        let plaintext = Arc::new(built.plaintext);
        for device in devices {
            let Some(origin) = vapid::origin_of(&device.endpoint) else {
                warn!("push: a stored endpoint is not a URL; dropping the device");
                self.retire(&to, &device);
                continue;
            };
            let permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    debug!("push: at the in-flight cap, dropping a notification");
                    return;
                }
            };
            let Some(slot) = self.origin_slot(&origin) else {
                debug!(
                    origin,
                    "push: at the origin's in-flight cap, dropping a push"
                );
                continue;
            };
            let this = self.clone();
            let to = to.clone();
            let plaintext = plaintext.clone();
            let topic = topic.clone();
            self.runtime.spawn(async move {
                this.send_to(&to, &device, &origin, &plaintext, &topic, kind)
                    .await;
                drop((permit, slot));
            });
        }
    }

    async fn send_to(
        &self,
        to: &Mailbox,
        device: &Device,
        origin: &str,
        plaintext: &[u8],
        topic: &str,
        kind: Kind,
    ) {
        if self.paused(&device.endpoint, Instant::now()) {
            return;
        }
        // Encrypted before the breaker is asked, so that a send the
        // breaker lets through as its probe always reaches the transport
        // and always answers: a probe that never answers would hold the
        // origin shut for good.
        let body = match encrypt::encrypt(
            plaintext,
            &device.p256dh,
            &device.auth,
            &encrypt::Ephemeral::new(),
        ) {
            Ok(b) => b,
            Err(encrypt::EncryptError::BadSubscriptionKey) => {
                // Registration checked it, so this is a row that cannot
                // be encrypted to and never will be.
                warn!("push: a stored subscription key is not a key; dropping the device");
                self.retire(to, device);
                return;
            }
            Err(e) => {
                warn!("push: encrypting for {}: {e:?}", to.login);
                return;
            }
        };
        if !self.breaker_allows(origin, Instant::now()) {
            return;
        }
        let bytes = body.len();
        let ttl = match kind {
            Kind::Message => self.config.message_ttl,
            Kind::News => self.config.news_ttl,
        };
        let outcome = self
            .transport
            .post(Push {
                endpoint: device.endpoint.clone(),
                ttl: ttl.as_secs(),
                urgency: kind.urgency(),
                topic: topic.to_string(),
                authorization: self.vapid.authorization(origin, SystemTime::now()),
                body,
            })
            .await;
        self.apply(to, device, origin, kind, bytes, outcome);
    }

    /// The answer table (`docs/webpush-gateway.md` §5), in one place so
    /// that what a status code means is not spread across the sender.
    fn apply(
        &self,
        to: &Mailbox,
        device: &Device,
        origin: &str,
        kind: Kind,
        bytes: usize,
        outcome: Outcome,
    ) {
        let now = Instant::now();
        match outcome {
            Outcome::Accepted => {
                self.breaker_record(origin, false, now);
                let (store, to, devid) = (self.devices.clone(), to.clone(), device.devid.clone());
                crate::spawn_blocking("push", move || {
                    if let Err(e) = store.touch(&to, &devid, SystemTime::now()) {
                        debug!("push: stamping a device: {e}");
                    }
                });
            }
            Outcome::Gone => {
                self.breaker_record(origin, false, now);
                self.retire(to, device);
            }
            Outcome::Slow(asked) => {
                // The origin answered, so it is up; this subscription
                // waits for as long as it was asked to, within reason.
                self.breaker_record(origin, false, now);
                let wait = asked
                    .unwrap_or(self.config.breaker_cooldown)
                    .min(http::MAX_RETRY_AFTER);
                self.pause(&device.endpoint, after(now, wait), now);
            }
            Outcome::TooBig => {
                self.breaker_record(origin, false, now);
                warn!(
                    origin,
                    kind = kind.name(),
                    bytes,
                    "push: a record was refused as too large, which the payload \
                     builder should have made impossible"
                );
            }
            Outcome::Rejected(status) => {
                self.breaker_record(origin, false, now);
                warn!(
                    origin,
                    status, "push: refused; check [push] contact and the VAPID key"
                );
            }
            Outcome::Failed(status) => {
                self.breaker_record(origin, true, now);
                debug!(origin, status, "push: the push service is in trouble");
            }
            Outcome::Unreachable(why) => {
                self.breaker_record(origin, true, now);
                debug!(origin, "push: {why}");
            }
        }
    }

    /// The vendor said this subscription is gone, or it is unusable.
    /// Deletes the row only while it still holds the endpoint this was
    /// about: a client that re-subscribed meanwhile has a new one.
    fn retire(&self, to: &Mailbox, device: &Device) {
        let store = self.devices.clone();
        let (to, devid, endpoint) = (to.clone(), device.devid.clone(), device.endpoint.clone());
        crate::spawn_blocking("push", move || {
            if let Err(e) = store.retire(&to, &devid, &endpoint) {
                warn!("push: retiring a device of {}: {e}", to.login);
            }
        });
    }
}

/// The two kinds of notification, as far as a push is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Message,
    News,
}

impl Kind {
    fn of(n: &Notification<'_>) -> Self {
        match n {
            Notification::Message(_) => Kind::Message,
            Notification::News(_) => Kind::News,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Message => "message",
            Kind::News => "news",
        }
    }

    /// A private message is worth waking a phone for; a news notice can
    /// wait for the screen to come on. The kind's, and not derived from
    /// the TTLs, which an operator may set in any order.
    fn urgency(self) -> &'static str {
        match self {
            Kind::Message => "high",
            Kind::News => "normal",
        }
    }
}

impl NotificationGateway for WebPushGateway {
    fn notify(&self, n: &Notification<'_>) {
        // Everything expensive is on the other side of this spawn: the
        // store read, the key agreement, the POST. What happens on the
        // caller's thread is building one JSON object and cloning a
        // mailbox.
        let inner = self.0.clone();
        let built = payload::build(n, inner.config.content);
        let to = n.to().clone();
        inner
            .runtime
            .clone()
            .spawn(inner.deliver(to, built, Kind::of(n)));
    }
}

/// `tokio::task::spawn_blocking`, with the pool's queue time and
/// occupancy reported under `what` (`hxd_core::instrument::blocking`).
pub(crate) fn spawn_blocking<R: Send + 'static>(
    what: &'static str,
    f: impl FnOnce() -> R + Send + 'static,
) -> tokio::task::JoinHandle<R> {
    tokio::task::spawn_blocking(hxd_core::instrument::blocking(what, f))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use hxd_core::notify::MessageNotice;
    use hxd_core::push::{DeviceId, MemoryDevices};

    use super::*;

    /// A transport that answers from a script and remembers what it was
    /// asked to send. The real one is exercised against a push service;
    /// what is tested here is everything this gateway decides.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<Push>>,
        answers: Mutex<Vec<Outcome>>,
        calls: AtomicU32,
        /// How long each answer takes, for the cases about what happens
        /// while a push is in flight.
        delay: Duration,
    }

    impl Recorder {
        fn sent(&self) -> Vec<Push> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl Transport for Recorder {
        fn post(&self, push: Push) -> Pin<Box<dyn Future<Output = Outcome> + Send>> {
            self.sent.lock().unwrap().push(push);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().unwrap();
            let outcome = if answers.is_empty() {
                Outcome::Accepted
            } else {
                answers.remove(0)
            };
            let delay = self.delay;
            Box::pin(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                outcome
            })
        }
    }

    fn vapid() -> Arc<Vapid> {
        let dir = std::env::temp_dir().join(format!(
            "hxd-push-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(
            Vapid::load_or_create(&dir.join("vapid.key"), "mailto:a@example.org", true).unwrap(),
        )
    }

    /// A subscription whose keys are real ones, so encryption is
    /// exercised rather than stubbed.
    fn device(owner: &Mailbox, id: &str) -> Device {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        use base64::Engine;
        let p256dh = B64
            .decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
            .unwrap();
        Device {
            owner: owner.clone(),
            devid: DeviceId::parse(id).unwrap(),
            endpoint: format!("https://push.example.net/v/{id}"),
            p256dh: p256dh.try_into().unwrap(),
            auth: [9; 16],
            expires: None,
            registered_at: SystemTime::now(),
            last_push_at: None,
        }
    }

    struct Server {
        gateway: WebPushGateway,
        devices: Arc<MemoryDevices>,
        transport: Arc<Recorder>,
    }

    fn server(config: Config, answers: Vec<Outcome>) -> Server {
        slow_server(config, answers, Duration::ZERO)
    }

    fn slow_server(config: Config, answers: Vec<Outcome>, delay: Duration) -> Server {
        let devices = Arc::new(MemoryDevices::new());
        let transport = Arc::new(Recorder {
            answers: Mutex::new(answers),
            delay,
            ..Recorder::default()
        });
        let gateway = WebPushGateway::new(
            devices.clone(),
            vapid(),
            config,
            transport.clone() as Arc<dyn Transport>,
        );
        Server {
            gateway,
            devices,
            transport,
        }
    }

    fn message<'a>(to: &'a Mailbox, from: &'a Mailbox) -> Notification<'a> {
        Notification::Message(MessageNotice {
            to,
            from: Some(from),
            from_nick: "Alice",
            text: "are you there",
            id: 7,
            unread: 1,
        })
    }

    /// `notify` spawns, and the store calls go to the blocking pool; the
    /// work is done when both have run it. Real time rather than yields,
    /// because a blocking-pool thread is not this runtime's to schedule.
    async fn settle() {
        for _ in 0..40 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    #[tokio::test]
    async fn a_push_reaches_every_device_and_stamps_the_ones_that_took_it() {
        let s = server(Config::default(), vec![]);
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();
        s.devices
            .register(&device(&to, "laptop-instal"), 8)
            .unwrap();

        s.gateway.notify(&message(&to, &from));
        settle().await;

        let sent = s.transport.sent();
        assert_eq!(sent.len(), 2, "one per device");
        let push = &sent[0];
        assert!(push.authorization.starts_with("vapid t="));
        assert!(push.authorization.contains(", k="));
        assert_eq!(push.urgency, "high", "a private message is worth a wake");
        assert_eq!(push.ttl, Config::default().message_ttl.as_secs());
        assert_eq!(push.topic.len(), 32);
        assert!(
            !push.body.is_empty() && push.body.len() > 86,
            "an RFC 8291 record, header block and all"
        );
        assert!(
            !String::from_utf8_lossy(&push.body).contains("are you there"),
            "and the text is not in it in the clear"
        );

        for d in s.devices.devices(&to, SystemTime::now()).unwrap() {
            assert!(
                d.last_push_at.is_some(),
                "an accepted push stamps its device"
            );
        }
    }

    #[tokio::test]
    async fn the_vendor_retiring_a_subscription_deletes_the_device() {
        let s = server(Config::default(), vec![Outcome::Gone]);
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();

        s.gateway.notify(&message(&to, &from));
        settle().await;

        assert!(
            s.devices
                .devices(&to, SystemTime::now())
                .unwrap()
                .is_empty(),
            "410 is the vendor retiring the subscription"
        );
    }

    #[tokio::test]
    async fn a_refused_credential_keeps_the_users_devices() {
        let s = server(Config::default(), vec![Outcome::Rejected(401)]);
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();

        s.gateway.notify(&message(&to, &from));
        settle().await;

        assert_eq!(
            s.devices.devices(&to, SystemTime::now()).unwrap().len(),
            1,
            "an operator's misconfiguration must not become data loss"
        );
    }

    #[tokio::test]
    async fn an_origin_that_keeps_failing_is_skipped_until_it_cools_down() {
        let config = Config {
            breaker_failures: 2,
            breaker_cooldown: Duration::from_secs(600),
            ..Config::default()
        };
        let s = server(
            config,
            vec![
                Outcome::Unreachable("timed out".into()),
                Outcome::Unreachable("timed out".into()),
            ],
        );
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();

        for _ in 0..4 {
            s.gateway.notify(&message(&to, &from));
            settle().await;
        }
        assert_eq!(
            s.transport.sent().len(),
            2,
            "two failures open the breaker and the rest are not attempted"
        );
        assert_eq!(
            s.devices.devices(&to, SystemTime::now()).unwrap().len(),
            1,
            "and a provider outage never costs the user a device"
        );
    }

    #[tokio::test]
    async fn a_news_notice_is_less_urgent_and_shorter_lived() {
        use hxd_core::news::{NotifyReason, SubScope};
        let s = server(Config::default(), vec![]);
        let to = Mailbox::login("bob");
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();

        s.gateway
            .notify(&Notification::News(hxd_core::notify::NewsNotice {
                to: &to,
                reason: NotifyReason::Reply,
                from_nick: "Alice",
                subject: "a thread",
                excerpt: "a reply",
                article: 412,
                root: 398,
                category: 3,
                scope: SubScope::Thread(398),
                unread: 1,
            }));
        settle().await;

        let sent = s.transport.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].urgency, "normal");
        assert_eq!(sent[0].ttl, Config::default().news_ttl.as_secs());
        assert_eq!(
            sent[0].topic,
            http::topic(&s.gateway.0.vapid.topic_key(), "thread:398"),
            "the scope is the collapse key, so a busy thread replaces rather than stacks"
        );
    }

    #[tokio::test]
    async fn an_expired_device_is_never_pushed_at() {
        let s = server(Config::default(), vec![]);
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        let mut lapsed = device(&to, "phone-install");
        lapsed.expires = Some(SystemTime::now() - Duration::from_secs(1));
        s.devices.register(&lapsed, 8).unwrap();

        s.gateway.notify(&message(&to, &from));
        settle().await;
        assert!(s.transport.sent().is_empty());
    }

    fn endpoints(s: &Server) -> Vec<String> {
        s.transport.sent().into_iter().map(|p| p.endpoint).collect()
    }

    /// After a cooldown one probe goes, and the rest of the fan-out waits
    /// for its answer rather than following it through the gate.
    #[tokio::test]
    async fn a_cooled_down_origin_gets_one_probe_not_a_stampede() {
        let config = Config {
            breaker_failures: 1,
            breaker_cooldown: Duration::from_millis(20),
            ..Config::default()
        };
        let s = slow_server(
            config,
            vec![
                Outcome::Unreachable("down".into()),
                Outcome::Unreachable("still down".into()),
            ],
            Duration::from_millis(30),
        );
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices.register(&device(&to, "first-device"), 8).unwrap();
        s.gateway.notify(&message(&to, &from));
        settle().await;
        assert_eq!(s.transport.sent().len(), 1, "one failure opens it");

        tokio::time::sleep(Duration::from_millis(30)).await;
        for id in ["second-devic", "third-device", "fourth-devic"] {
            s.devices.register(&device(&to, id), 8).unwrap();
        }
        s.gateway.notify(&message(&to, &from));
        settle().await;
        assert_eq!(
            s.transport.sent().len(),
            2,
            "four devices behind a cooled-down origin, and one probe"
        );
    }

    /// A 403 is about one subscription or about us, and FCM serves every
    /// Chrome user: it must not open the breaker on the origin.
    #[tokio::test]
    async fn an_answer_about_one_subscription_does_not_shut_the_origin() {
        let config = Config {
            breaker_failures: 1,
            ..Config::default()
        };
        let s = server(config, vec![Outcome::Rejected(403)]);
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices.register(&device(&to, "stale-device"), 8).unwrap();
        s.gateway.notify(&message(&to, &from));
        settle().await;
        s.gateway.notify(&message(&to, &from));
        settle().await;
        assert_eq!(s.transport.sent().len(), 2, "the origin stayed open");

        // The provider's own trouble is another matter.
        let s = server(
            Config {
                breaker_failures: 1,
                ..Config::default()
            },
            vec![Outcome::Failed(503)],
        );
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();
        s.gateway.notify(&message(&to, &from));
        settle().await;
        s.gateway.notify(&message(&to, &from));
        settle().await;
        assert_eq!(s.transport.sent().len(), 1, "a 503 opens it");
    }

    /// A 429 pauses the subscription that drew it, for no longer than the
    /// cap, and the others behind the same origin carry on. A value that
    /// cannot be added to an `Instant` is the case that used to panic
    /// under the breaker's lock.
    #[tokio::test]
    async fn a_throttled_subscription_pauses_alone() {
        let s = server(
            Config::default(),
            vec![Outcome::Slow(Some(Duration::from_secs(u64::MAX)))],
        );
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices.register(&device(&to, "throttled-de"), 8).unwrap();
        s.devices.register(&device(&to, "healthy-devi"), 8).unwrap();

        s.gateway.notify(&message(&to, &from));
        settle().await;
        let first = endpoints(&s);
        assert_eq!(first.len(), 2);
        let throttled = s.transport.sent()[0].endpoint.clone();

        s.gateway.notify(&message(&to, &from));
        settle().await;
        let second = &endpoints(&s)[2..];
        assert_eq!(second.len(), 1, "the throttled one waits");
        assert_ne!(second[0], throttled, "and only it");
    }

    /// The client re-subscribed while a push to its old endpoint was in
    /// flight; the old endpoint's 410 must not take the new row.
    #[tokio::test]
    async fn a_gone_answer_spares_a_row_that_was_replaced_meanwhile() {
        let s = slow_server(
            Config::default(),
            vec![Outcome::Gone],
            Duration::from_millis(20),
        );
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.devices
            .register(&device(&to, "phone-install"), 8)
            .unwrap();
        s.gateway.notify(&message(&to, &from));
        tokio::time::sleep(Duration::from_millis(5)).await;

        let mut moved = device(&to, "phone-install");
        moved.endpoint = "https://push.example.net/v/renewed".into();
        s.devices.register(&moved, 8).unwrap();
        settle().await;

        let rows = s.devices.devices(&to, SystemTime::now()).unwrap();
        assert_eq!(rows.len(), 1, "the new subscription survived");
        assert_eq!(rows[0].endpoint, "https://push.example.net/v/renewed");
    }

    /// One origin answering slowly holds at most its own share of the
    /// permits.
    #[tokio::test]
    async fn a_slow_origin_holds_only_its_share() {
        let config = Config {
            max_inflight_per_origin: 2,
            ..Config::default()
        };
        let s = slow_server(config, vec![], Duration::from_millis(50));
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        for id in [
            "tarpit-one!!",
            "tarpit-two!!",
            "tarpit-three",
            "tarpit-four!",
        ] {
            s.devices.register(&device(&to, id), 8).unwrap();
        }
        let mut elsewhere = device(&to, "elsewhere-de");
        elsewhere.endpoint = "https://other.example.org/v/1".into();
        s.devices.register(&elsewhere, 8).unwrap();

        s.gateway.notify(&message(&to, &from));
        settle().await;
        let sent = endpoints(&s);
        assert_eq!(
            sent.iter()
                .filter(|e| e.starts_with("https://push.example.net/"))
                .count(),
            2,
            "two of the four at the capped origin"
        );
        assert!(
            sent.iter()
                .any(|e| e.starts_with("https://other.example.org/")),
            "and another origin is not held up by it"
        );
    }

    #[tokio::test]
    async fn a_mailbox_with_no_devices_costs_one_store_read() {
        let s = server(Config::default(), vec![]);
        let (to, from) = (Mailbox::login("bob"), Mailbox::login("alice"));
        s.gateway.notify(&message(&to, &from));
        settle().await;
        assert!(s.transport.sent().is_empty());
    }
}
