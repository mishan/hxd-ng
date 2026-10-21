//! The uniqush-push gateway (`docs/push-notifications.md` §4.1).
//!
//! A `NotificationGateway` that hands each notification to a
//! uniqush-push sidecar, which encrypts it and sends it on. uniqush keeps
//! a second copy of the device registry, and the store stays the record:
//! a push names the delivery points the store's rows hold and never a
//! subscriber's every device; a row the store gains is subscribed by a
//! task of this gateway's own, and a row it loses is unsubscribed; and a
//! device uniqush prunes, which it reports in the push's answer and in
//! its log of removals, is retired from the store. Where uniqush has lost
//! a device the store still holds, the row is subscribed again rather
//! than retired, so a Redis that lost its data costs a push or two.
//!
//! What a client receives is the in-process sender's payload byte for
//! byte, under its keyed collapse key, TTL and urgency, so the two
//! gateways cannot be told apart from a phone. `notify` never blocks,
//! and a sidecar that stops answering opens the in-process sender's
//! breaker, as one origin: it degrades to no push, not to a queue.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hxd_core::inbox::Mailbox;
use hxd_core::notify::{Notification, NotificationGateway};
use hxd_core::push::{Device, PushStore, SidecarRecord};
use hxd_push_webpush::{payload, Breaker, Kind, Vapid};
use serde_json::Value;
use tokio::sync::{Notify, Semaphore};
use tracing::{debug, info, warn};

pub mod client;
pub mod subscriber;

pub use client::{Addr, CallError, Client};

/// How often the gateway reads uniqush's log of removals and looks for
/// rows to subscribe when nothing has asked it to.
const PERIOD: Duration = Duration::from_secs(60);

/// The first and the longest wait between attempts while uniqush is not
/// answering.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// What a cheap call to uniqush may take: `/health`, and the provider's
/// check, which the server's start waits on.
const QUICK: Duration = Duration::from_secs(5);

/// A page of `/removed`: uniqush answers no more than this.
const REMOVED_PAGE: usize = 1000;

/// The most delivery points one `/push` names: uniqush tries this many
/// devices at once, so a push naming more waits a second
/// `request_timeout` behind the first, and a mailbox of slow endpoints
/// would take one call past `[push] timeout`.
const PUSH_BATCH: usize = 16;

/// Deliveries to one mailbox at once. Past it a notification is dropped,
/// as at the in-flight cap, so an account whose endpoints are slow holds
/// no more of that cap than this.
const PER_MAILBOX: usize = 2;

const SUCCESS: &str = "UNIQUSH_SUCCESS";
const NO_PROVIDER: &str = "UNIQUSH_ERROR_NO_PUSH_SERVICE_PROVIDER";

/// `[push.uniqush]`, as the server hands it over.
#[derive(Clone)]
pub struct Config {
    pub addr: Addr,
    /// The bearer token, read from `token_file`.
    pub token: Option<String>,
    /// This server's name in uniqush. Required, because two servers on
    /// one default would share every login-keyed subscriber
    /// (`docs/push-notifications.md` §5).
    pub service: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("service", &self.service)
            .finish()
    }
}

/// Does `service` keep to the characters uniqush documents for one?
pub fn valid_service(service: &str) -> bool {
    !service.is_empty()
        && service
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'@' | b'.'))
}

/// Why the gateway cannot push yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// uniqush is not answering; the gateway tries again.
    Unreachable(String),
    /// uniqush answered, and pushing as this server through it would be
    /// wrong: the service has a provider this server did not hand it, or
    /// uniqush refused the one it was handed.
    Fatal(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::Unreachable(e) | Refused::Fatal(e) => f.write_str(e),
        }
    }
}

/// The gateway, a handle onto state every task it spawns shares.
#[derive(Clone)]
pub struct UniqushGateway(Arc<Inner>);

struct Inner {
    devices: Arc<dyn PushStore>,
    vapid: Arc<Vapid>,
    config: hxd_push_webpush::Config,
    service: String,
    client: Client,
    /// The same, under [`QUICK`].
    quick: Client,
    breaker: Mutex<Breaker>,
    inflight: Arc<Semaphore>,
    topic_key: [u8; 32],
    runtime: tokio::runtime::Handle,
    /// Wakes the keeper: a row to subscribe, or a log to read.
    wake: Notify,
    /// The next pass reads the log of removals.
    read_log: AtomicBool,
    /// The provider is checked and handed over; until then nothing is
    /// pushed, since a push would be signed by whoever's provider is
    /// there.
    ready: AtomicBool,
    /// Rows uniqush would not subscribe, by subscriber, devid and
    /// subscription: tried again on the period, not at every wake.
    refused: Mutex<HashSet<Refusal>>,
    /// Deliveries in flight, by subscriber.
    delivering: Mutex<HashMap<String, usize>>,
}

/// A delivery's place under [`PER_MAILBOX`], given back however it ends.
struct Delivering<'a>(&'a Inner, String);

impl Drop for Delivering<'_> {
    fn drop(&mut self) {
        let mut d = lock(&self.0.delivering);
        if let Some(n) = d.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                d.remove(&self.1);
            }
        }
    }
}

type Refusal = (String, String, String, Vec<u8>, Vec<u8>);

fn refusal(d: &Device) -> Refusal {
    (
        subscriber::of(&d.owner),
        d.devid.as_str().to_string(),
        d.endpoint.clone(),
        d.p256dh.to_vec(),
        d.auth.to_vec(),
    )
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A store call, off the runtime's workers: on SQLite it is a disk read.
async fn blocking<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> Option<R> {
    let task = tokio::task::spawn_blocking(hxd_core::instrument::blocking("push", f));
    match task.await {
        Ok(r) => Some(r),
        Err(e) => {
            warn!("push: a store call did not finish: {e}");
            None
        }
    }
}

/// A contact as `/psps` shows it: uniqush keeps an address bare, however
/// it was given.
fn bare(contact: &str) -> &str {
    contact.strip_prefix("mailto:").unwrap_or(contact)
}

fn refused(e: CallError) -> Refused {
    match e {
        CallError::Down(e) | CallError::TimedOut(e) => Refused::Unreachable(e),
        CallError::Refused(e) => Refused::Fatal(e),
    }
}

fn code(v: &Value) -> &str {
    v["code"].as_str().unwrap_or("")
}

impl UniqushGateway {
    /// Build a gateway over `devices`. Must be called within a tokio
    /// runtime, which every send is spawned onto; nothing is sent until
    /// [`Self::prepare`] has passed and [`Self::start`] has run.
    pub fn new(
        devices: Arc<dyn PushStore>,
        vapid: Arc<Vapid>,
        config: hxd_push_webpush::Config,
        uniqush: Config,
    ) -> Self {
        let client = Client::new(uniqush.addr.clone(), uniqush.token.clone(), config.timeout);
        let quick = Client::new(uniqush.addr, uniqush.token, QUICK);
        UniqushGateway(Arc::new(Inner {
            devices,
            topic_key: vapid.topic_key(),
            vapid,
            inflight: Arc::new(Semaphore::new(config.max_inflight.max(1))),
            config,
            service: uniqush.service,
            client,
            quick,
            breaker: Mutex::new(Breaker::default()),
            runtime: tokio::runtime::Handle::current(),
            wake: Notify::new(),
            read_log: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            refused: Mutex::default(),
            delivering: Mutex::default(),
        }))
    }

    /// Check the service's Web Push provider against what the store
    /// recorded and the key file holds, and hand uniqush this server's
    /// where it may (`docs/push-notifications.md` §4.1). Each call to
    /// uniqush in it takes at most a few seconds.
    pub async fn prepare(&self) -> Result<(), Refused> {
        self.0.prepare().await
    }

    /// Start the task that subscribes rows and reads uniqush's log.
    /// Pushes go once the provider is checked, which the task does first
    /// if [`Self::prepare`] could not.
    pub fn start(&self) {
        let inner = self.0.clone();
        self.0.runtime.spawn(inner.keep());
    }
}

impl Inner {
    async fn call(&self, path: &str, form: &[(&str, &str)]) -> Result<Value, CallError> {
        self.call_on(&self.client, path, form).await
    }

    async fn call_on(
        &self,
        client: &Client,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<Value, CallError> {
        if !lock(&self.breaker).allows(Instant::now()) {
            return Err(CallError::Down("uniqush keeps failing; skipped".into()));
        }
        let mut answer = client.call(path, form).await;
        // A `/push` waits on the push services it names, so one that
        // runs out of time may be an account's slow endpoints rather
        // than uniqush: whether uniqush is up is `/health`'s to say.
        if let (Err(CallError::TimedOut(e)), "/push") = (&answer, path) {
            let e = e.clone();
            answer = match self.quick.call("/health", &[]).await {
                Ok(_) => Err(CallError::Refused(e)),
                Err(health) => Err(CallError::Down(format!("{e}; {health}"))),
            };
        }
        let mut breaker = lock(&self.breaker);
        match &answer {
            Err(CallError::Down(e) | CallError::TimedOut(e)) => {
                if breaker.failed(
                    Instant::now(),
                    self.config.breaker_failures,
                    self.config.breaker_cooldown,
                ) {
                    warn!("push: uniqush keeps failing ({e}); skipping it for a while");
                }
            }
            _ => breaker.succeeded(),
        }
        answer
    }

    /// uniqush has no provider for the service, as after `/rmpsp` or a
    /// Redis that lost its data: stop pushing until the keeper has
    /// handed it over again.
    fn lost_provider(&self) {
        if self.ready.swap(false, Ordering::SeqCst) {
            warn!("push: uniqush has lost this server's provider; handing it over again");
        }
        self.wake.notify_one();
    }

    async fn prepare(&self) -> Result<(), Refused> {
        let store = self.devices.clone();
        let record = match blocking(move || store.sidecar()).await {
            Some(Ok(r)) => r,
            Some(Err(e)) => return Err(Refused::Unreachable(format!("the store: {e}"))),
            None => return Err(Refused::Unreachable("the store".into())),
        };
        // What was handed over under another service says nothing about
        // this one, and neither do the names it gave the rows.
        let record = match record {
            Some(r) if r.service == self.service => Some(r),
            Some(r) => {
                info!(
                    from = r.service,
                    to = self.service,
                    "push: the uniqush service changed; subscribing every device again"
                );
                self.clear_all().await;
                None
            }
            None => None,
        };
        let psps = self
            .call_on(&self.quick, "/psps", &[])
            .await
            .map_err(refused)?;
        let (public, contact) = (self.vapid.public_key(), self.vapid.contact());
        let theirs = psps["services"][self.service.as_str()]
            .as_array()
            .into_iter()
            .flatten()
            .find(|p| p.get("vapidpublickey").is_some());
        let shows = |p: &Value, key: &str, c: &str| {
            p["vapidpublickey"].as_str() == Some(key)
                && p["subscriber"].as_str().map(bare) == Some(bare(c))
        };
        match theirs {
            Some(p) if shows(p, public, contact) => {}
            Some(p)
                if record
                    .as_ref()
                    .is_some_and(|r| shows(p, &r.public_key, &r.contact)) =>
            {
                info!("push: handing uniqush this server's new VAPID key or contact");
                self.add_psp(true).await?;
            }
            Some(p) => {
                return Err(Refused::Fatal(format!(
                    "uniqush's service {:?} has a Web Push provider this server did not \
                     hand it (key {}); name another [push.uniqush] service, or remove that \
                     provider with /rmpsp if it is this server's",
                    self.service,
                    p["vapidpublickey"].as_str().unwrap_or("?")
                )));
            }
            None => self.add_psp(false).await?,
        }
        let record = SidecarRecord {
            service: self.service.clone(),
            public_key: public.to_string(),
            contact: contact.to_string(),
            cursor: record.and_then(|r| r.cursor),
        };
        let store = self.devices.clone();
        match blocking(move || store.set_sidecar(&record)).await {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(Refused::Unreachable(format!("the store: {e}"))),
            None => return Err(Refused::Unreachable("the store".into())),
        }
        self.ready.store(true, Ordering::SeqCst);
        info!(
            service = self.service,
            vapid = public,
            "push: uniqush gateway configured"
        );
        Ok(())
    }

    async fn add_psp(&self, replace: bool) -> Result<(), Refused> {
        let private = self.vapid.private_key();
        let mut form = vec![
            ("service", self.service.as_str()),
            ("pushservicetype", "webpush"),
            ("vapidpublickey", self.vapid.public_key()),
            ("vapidprivatekey", private.as_str()),
            ("subscriber", self.vapid.contact()),
        ];
        if replace {
            form.push(("replace", "true"));
        }
        let answer = self
            .call_on(&self.quick, "/addpsp", &form)
            .await
            .map_err(refused)?;
        match code(&answer["details"]) {
            SUCCESS => Ok(()),
            other => Err(Refused::Fatal(format!(
                "uniqush refused this server's provider: {other} {}",
                answer["details"]["errorMsg"].as_str().unwrap_or("")
            ))),
        }
    }

    /// The keeper: the provider until it is checked, then the log and the
    /// rows to subscribe, at every wake and on a period, backing off while
    /// uniqush does not answer.
    async fn keep(self: Arc<Self>) {
        let mut backoff = MIN_BACKOFF;
        // The period is kept whatever else wakes the keeper, so a stream
        // of registrations cannot starve the log.
        let mut next_period = Instant::now();
        loop {
            let periodic = Instant::now() >= next_period;
            if periodic {
                next_period = Instant::now() + PERIOD;
                self.read_log.store(true, Ordering::SeqCst);
            }
            let wait = match self.pass(periodic).await {
                Ok(()) => {
                    backoff = MIN_BACKOFF;
                    PERIOD
                }
                Err(Refused::Unreachable(e)) => {
                    debug!("push: uniqush: {e}; trying again in {backoff:?}");
                    let wait = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    wait
                }
                Err(Refused::Fatal(e)) => {
                    tracing::error!("push: not pushing through uniqush: {e}");
                    return;
                }
            };
            let wait = wait.min(next_period.saturating_duration_since(Instant::now()));
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn pass(&self, periodic: bool) -> Result<(), Refused> {
        if !self.ready.load(Ordering::SeqCst) {
            self.prepare().await?;
        }
        if self.read_log.swap(false, Ordering::SeqCst) {
            if let Err(e) = self.read_removed().await {
                self.read_log.store(true, Ordering::SeqCst);
                return Err(Refused::Unreachable(e));
            }
        }
        self.subscribe_pending(periodic)
            .await
            .map_err(Refused::Unreachable)
    }

    /// Subscribe every row uniqush has not named, writing the name back
    /// only while the row still holds what was subscribed. A row uniqush
    /// refused is tried again on the period alone.
    async fn subscribe_pending(&self, periodic: bool) -> Result<(), String> {
        let store = self.devices.clone();
        let rows = match blocking(move || store.unsubscribed(SystemTime::now())).await {
            Some(Ok(rows)) => rows,
            Some(Err(e)) => {
                warn!("push: reading the devices to subscribe: {e}");
                return Ok(());
            }
            None => return Ok(()),
        };
        if periodic {
            lock(&self.refused).clear();
        }
        for row in rows {
            if lock(&self.refused).contains(&refusal(&row)) {
                continue;
            }
            let subscriber = subscriber::of(&row.owner);
            let (p256dh, auth) = (B64.encode(row.p256dh), B64.encode(row.auth));
            let answer = self
                .call(
                    "/subscribe",
                    &[
                        ("service", self.service.as_str()),
                        ("subscriber", subscriber.as_str()),
                        ("pushservicetype", "webpush"),
                        ("endpoint", row.endpoint.as_str()),
                        ("p256dh", p256dh.as_str()),
                        ("auth", auth.as_str()),
                        ("devid", row.devid.as_str()),
                    ],
                )
                .await;
            let details = match answer {
                Ok(v) => v["details"].clone(),
                Err(CallError::Down(e) | CallError::TimedOut(e)) => return Err(e),
                Err(CallError::Refused(e)) => {
                    warn!("push: subscribing a device of {}: {e}", row.owner.login);
                    lock(&self.refused).insert(refusal(&row));
                    continue;
                }
            };
            let Some(dp) = details["deliveryPoint"]
                .as_str()
                .filter(|_| code(&details) == SUCCESS)
            else {
                if code(&details) == NO_PROVIDER {
                    self.lost_provider();
                    return Ok(());
                }
                warn!(
                    "push: uniqush would not subscribe a device of {}: {} {}",
                    row.owner.login,
                    code(&details),
                    details["errorMsg"].as_str().unwrap_or("")
                );
                lock(&self.refused).insert(refusal(&row));
                continue;
            };
            let (store, dp, subscribed) = (self.devices.clone(), dp.to_string(), row.clone());
            match blocking(move || store.set_delivery_point(&subscribed, &dp)).await {
                // Overtaken by a replacement: what was subscribed is no
                // row's, unless another row holds it.
                Some(Ok(false)) => self.unsubscribe(vec![row]).await,
                Some(Err(e)) => warn!("push: recording a delivery point: {e}"),
                _ => {}
            }
        }
        Ok(())
    }

    /// Unsubscribe rows the store took, each with what it held, unless
    /// another row of the mailbox still holds the same: uniqush keeps
    /// one device for both. Best effort: one lost costs storage in
    /// uniqush, never a ring, since pushes name their devices.
    async fn unsubscribe(&self, taken: Vec<Device>) {
        let mut done: Vec<(String, &Device)> = Vec::new();
        for row in &taken {
            let subscriber = subscriber::of(&row.owner);
            if done
                .iter()
                .any(|(s, d)| *s == subscriber && d.same_subscription(row))
            {
                continue;
            }
            let (store, owner) = (self.devices.clone(), row.owner.clone());
            let still = match blocking(move || store.devices(&owner, SystemTime::now())).await {
                Some(Ok(rows)) => rows.iter().any(|d| d.same_subscription(row)),
                _ => true,
            };
            if !still {
                let (p256dh, auth) = (B64.encode(row.p256dh), B64.encode(row.auth));
                let answer = self
                    .call(
                        "/unsubscribe",
                        &[
                            ("service", self.service.as_str()),
                            ("subscriber", subscriber.as_str()),
                            ("pushservicetype", "webpush"),
                            ("endpoint", row.endpoint.as_str()),
                            ("p256dh", p256dh.as_str()),
                            ("auth", auth.as_str()),
                        ],
                    )
                    .await;
                match answer {
                    Ok(v) if code(&v["details"]) == SUCCESS => {}
                    Ok(v) => debug!("push: unsubscribing: {}", code(&v["details"])),
                    Err(e) => debug!("push: an unsubscribe was lost: {e}"),
                }
            }
            done.push((subscriber, row));
        }
    }

    /// Retire `owner`'s rows that hold `dp`, and unsubscribe them: a row
    /// subscribed again before the removal was read has the name it had,
    /// and this takes back what that subscribe left.
    async fn retire(&self, owner: Mailbox, dp: String) {
        let store = self.devices.clone();
        match blocking(move || store.retire_delivery_point(&owner, &dp)).await {
            Some(Ok(taken)) if !taken.is_empty() => self.unsubscribe(taken).await,
            Some(Err(e)) => warn!("push: retiring a device uniqush pruned: {e}"),
            _ => {}
        }
    }

    async fn clear_all(&self) {
        let store = self.devices.clone();
        if let Some(Err(e)) = blocking(move || store.clear_delivery_points()).await {
            warn!("push: clearing delivery points: {e}");
        }
    }

    /// Read uniqush's log of removals from the cursor the store keeps,
    /// retiring each row it names. A log that lost entries, or that does
    /// not know the cursor, says nothing of which devices uniqush still
    /// has, so every row is subscribed again: never retired.
    async fn read_removed(&self) -> Result<(), String> {
        let store = self.devices.clone();
        let Some(Ok(Some(mut record))) = blocking(move || store.sidecar()).await else {
            return Ok(());
        };
        loop {
            let limit = REMOVED_PAGE.to_string();
            let mut form = vec![
                ("service", self.service.as_str()),
                ("limit", limit.as_str()),
            ];
            if let Some(cursor) = &record.cursor {
                form.push(("since", cursor.as_str()));
            }
            let answer = match self.call("/removed", &form).await {
                Ok(v) => v,
                Err(CallError::Down(e) | CallError::TimedOut(e)) => return Err(e),
                Err(CallError::Refused(e)) => {
                    warn!("push: reading uniqush's removals: {e}");
                    return Ok(());
                }
            };
            match code(&answer) {
                SUCCESS => {}
                "UNIQUSH_ERROR_GENERIC" if record.cursor.is_some() => {
                    warn!(
                        "push: uniqush does not know this server's place in its log ({}); \
                         subscribing every device again",
                        answer["errorMsg"].as_str().unwrap_or("")
                    );
                    self.clear_all().await;
                    record.cursor = None;
                    self.save(&record).await;
                    self.wake.notify_one();
                    continue;
                }
                other => {
                    warn!(
                        "push: reading uniqush's removals: {other} {}",
                        answer["errorMsg"].as_str().unwrap_or("")
                    );
                    return Ok(());
                }
            }
            if answer["truncated"].as_bool() == Some(true) {
                warn!("push: uniqush's log lost removals; subscribing every device again");
                self.clear_all().await;
                self.wake.notify_one();
            }
            let removed = answer["removed"].as_array().cloned().unwrap_or_default();
            for r in &removed {
                let (Some(owner), Some(dp)) = (
                    r["subscriber"].as_str().and_then(subscriber::mailbox),
                    r["deliveryPoint"].as_str(),
                ) else {
                    continue;
                };
                if r["service"].as_str() == Some(self.service.as_str()) {
                    self.retire(owner, dp.to_string()).await;
                }
            }
            if let Some(next) = answer["next"].as_str() {
                record.cursor = Some(next.to_string());
                self.save(&record).await;
            }
            if removed.len() < REMOVED_PAGE {
                return Ok(());
            }
        }
    }

    async fn save(&self, record: &SidecarRecord) {
        let (store, record) = (self.devices.clone(), record.clone());
        if let Some(Err(e)) = blocking(move || store.set_sidecar(&record)).await {
            warn!("push: keeping uniqush's cursor: {e}");
        }
    }

    /// One notification: the store's rows for `to`, and a `/push` per
    /// [`PUSH_BATCH`] of the delivery points they hold.
    async fn deliver(self: Arc<Self>, to: Mailbox, built: payload::Built, kind: Kind) {
        let (store, who) = (self.devices.clone(), to.clone());
        let rows = match blocking(move || store.devices(&who, SystemTime::now())).await {
            Some(Ok(rows)) => rows,
            Some(Err(e)) => {
                warn!("push: reading {}'s devices: {e}", to.login);
                return;
            }
            None => return,
        };
        if rows.iter().any(|d| d.delivery_point.is_none()) {
            self.wake.notify_one();
        }
        let mut dps: Vec<&str> = rows
            .iter()
            .filter_map(|d| d.delivery_point.as_deref())
            .collect();
        dps.sort_unstable();
        dps.dedup();
        // Without `delivery_point_id` a push reaches every device uniqush
        // has for the subscriber, the ones the store forgot included.
        if dps.is_empty() {
            return;
        }
        let Ok(_permit) = self.inflight.clone().try_acquire_owned() else {
            debug!("push: at the in-flight cap, dropping a notification");
            return;
        };
        let subscriber = subscriber::of(&to);
        let _place = {
            let mut d = lock(&self.delivering);
            let n = d.entry(subscriber.clone()).or_default();
            if *n >= PER_MAILBOX {
                debug!(
                    "push: {} has pushes in flight already; dropping one",
                    to.login
                );
                return;
            }
            *n += 1;
            Delivering(&self, subscriber.clone())
        };
        // No batch starts past this, so a mailbox of many slow devices
        // holds its permit for two calls' time at most, not one per
        // batch. A call is never cut short: one cut short would leave the
        // breaker's probe unanswered.
        let deadline = Instant::now() + self.config.timeout + QUICK;
        let ttl = kind.ttl(&self.config).as_secs().to_string();
        let msggroup = hxd_push_webpush::http::topic(&self.topic_key, &built.collapse);
        let plaintext = String::from_utf8_lossy(&built.plaintext);
        for (i, batch) in dps.chunks(PUSH_BATCH).enumerate() {
            if Instant::now() >= deadline {
                debug!(
                    "push: out of time for {}'s devices; {} not pushed",
                    to.login,
                    dps.len() - i * PUSH_BATCH
                );
                break;
            }
            let dp_ids = batch.join(",");
            let answer = self
                .call(
                    "/push",
                    &[
                        ("service", self.service.as_str()),
                        ("subscriber", subscriber.as_str()),
                        ("delivery_point_id", dp_ids.as_str()),
                        ("uniqush.payload.webpush", &*plaintext),
                        ("ttl", ttl.as_str()),
                        ("msggroup", msggroup.as_str()),
                        ("uniqush.urgency", kind.urgency()),
                    ],
                )
                .await;
            match answer {
                Ok(v) => self.answered(&to, &rows, &v).await,
                Err(e) => debug!("push: {e}"),
            }
        }
    }

    /// What a `/push` answer says about the rows it named. A device's
    /// own failure, a retry included, is not uniqush's and is only logged.
    async fn answered(&self, to: &Mailbox, rows: &[Device], v: &Value) {
        let entries = |key: &str| v[key].as_array().cloned().unwrap_or_default();
        for e in entries("successDetails") {
            let Some(dp) = e["deliveryPoint"].as_str() else {
                continue;
            };
            for row in rows
                .iter()
                .filter(|d| d.delivery_point.as_deref() == Some(dp))
            {
                let (store, to, devid) = (self.devices.clone(), to.clone(), row.devid.clone());
                if let Some(Err(e)) =
                    blocking(move || store.touch(&to, &devid, SystemTime::now())).await
                {
                    debug!("push: stamping a device: {e}");
                }
            }
        }
        for e in entries("failureDetails") {
            if code(&e) == NO_PROVIDER {
                self.lost_provider();
            }
            debug!(
                "push: uniqush: {} {}",
                code(&e),
                e["errorMsg"].as_str().unwrap_or("")
            );
        }
        let dropped = entries("droppedDetails");
        for e in &dropped {
            let Some(dp) = e["deliveryPoint"].as_str() else {
                continue;
            };
            if e["removed"].is_object() {
                self.retire(to.clone(), dp.to_string()).await;
            } else if code(e) == "UNIQUSH_NOT_SUBSCRIBED" {
                let (store, owner, dp) = (self.devices.clone(), to.clone(), dp.to_string());
                if let Some(Err(e)) =
                    blocking(move || store.clear_delivery_point(&owner, &dp)).await
                {
                    warn!("push: clearing a delivery point: {e}");
                }
            }
        }
        // The answer is the fast path, and the log the record: anything
        // dropped is worth reading it for.
        if !dropped.is_empty() {
            self.read_log.store(true, Ordering::SeqCst);
            self.wake.notify_one();
        }
    }
}

impl NotificationGateway for UniqushGateway {
    fn notify(&self, n: &Notification<'_>) {
        if !self.0.ready.load(Ordering::SeqCst) {
            debug!("push: uniqush is not ready; dropping a notification");
            return;
        }
        let inner = self.0.clone();
        let built = payload::build(n, inner.config.content);
        let to = n.to().clone();
        inner
            .runtime
            .clone()
            .spawn(inner.deliver(to, built, Kind::of(n)));
    }

    fn devices_changed(&self, added: bool, taken: &[Device]) {
        if !taken.is_empty() {
            let inner = self.0.clone();
            let taken = taken.to_vec();
            self.0
                .runtime
                .spawn(async move { inner.unsubscribe(taken).await });
        }
        if added {
            self.0.wake.notify_one();
        }
    }
}
