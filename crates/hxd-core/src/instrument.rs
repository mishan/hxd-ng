//! What the server can say about itself under load.
//!
//! Every function here is a no-op unless the `metrics` feature is on, in
//! which case it records through the [`metrics`](https://docs.rs/metrics)
//! facade and whatever recorder the binary installed. Callers never
//! `cfg` anything: the frontends and the stores call these
//! unconditionally, and only this crate and the binary know the feature
//! exists. The metric names live here and nowhere else, so this file is
//! also the catalog `docs/metrics.md` describes.
//!
//! Label values are either `&'static str` or bounded by construction — a
//! transaction type from the wire is labeled only when it is one the
//! server knows, never as the client sent it, because every distinct
//! label value is a series the recorder keeps forever.

use std::ops::{Deref, DerefMut};
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

#[cfg(feature = "metrics")]
use std::panic::Location;
#[cfg(feature = "metrics")]
use std::time::{Duration, Instant};

/// A `std::sync::Mutex` that reports how long each caller waited for it
/// and how long it held it, labeled by the lock's name and by the call
/// site (`#[track_caller]`), so a lock's worst holder is named without an
/// edit at any of its sites.
///
/// `lock()` returns what `Mutex::lock` returns, guard type aside, so
/// `.lock().unwrap()` and `.unwrap_or_else(|e| e.into_inner())` read the
/// same at every site. The hold is recorded after the inner guard is
/// released: the recording is never part of what it measures.
pub struct TimedMutex<T> {
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    name: &'static str,
    inner: Mutex<T>,
}

impl<T> TimedMutex<T> {
    pub const fn named(name: &'static str, value: T) -> Self {
        TimedMutex {
            name,
            inner: Mutex::new(value),
        }
    }

    #[track_caller]
    pub fn lock(&self) -> LockResult<TimedGuard<'_, T>> {
        #[cfg(feature = "metrics")]
        let site = Location::caller();
        #[cfg(feature = "metrics")]
        let asked = Instant::now();
        let wrap = |guard| TimedGuard {
            guard: Some(guard),
            #[cfg(feature = "metrics")]
            held: Held::start(self.name, site, asked),
        };
        match self.inner.lock() {
            Ok(guard) => Ok(wrap(guard)),
            Err(poisoned) => Err(PoisonError::new(wrap(poisoned.into_inner()))),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for TimedMutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimedMutex")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .finish()
    }
}

/// The name a defaulted lock reports: the protected type's own, without
/// its path. `Core`'s locks are defaulted with it, so a lock's name is
/// the name of what it guards.
impl<T: Default> Default for TimedMutex<T> {
    fn default() -> Self {
        let full = std::any::type_name::<T>();
        let name = full.rsplit("::").next().unwrap_or(full);
        TimedMutex::named(name, T::default())
    }
}

/// The guard [`TimedMutex::lock`] hands out; it derefs to the value.
pub struct TimedGuard<'a, T> {
    /// Always `Some` until `drop` takes it, so that the lock is released
    /// before the hold is recorded.
    guard: Option<MutexGuard<'a, T>>,
    #[cfg(feature = "metrics")]
    held: Held,
}

impl<T> Deref for TimedGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard present until drop")
    }
}

impl<T> DerefMut for TimedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().expect("guard present until drop")
    }
}

impl<T> Drop for TimedGuard<'_, T> {
    fn drop(&mut self) {
        drop(self.guard.take());
        #[cfg(feature = "metrics")]
        self.held.finish();
    }
}

/// The clock readings a guard carries. Both are recorded in `finish`,
/// after the lock is released: formatting the site and looking up the
/// histograms is not free, and done while holding the lock it would be
/// counted in the very hold it measures, and paid by every waiter.
#[cfg(feature = "metrics")]
struct Held {
    lock: &'static str,
    site: &'static Location<'static>,
    asked: Instant,
    got: Instant,
}

#[cfg(feature = "metrics")]
impl Held {
    fn start(lock: &'static str, site: &'static Location<'static>, asked: Instant) -> Self {
        Held {
            lock,
            site,
            asked,
            got: Instant::now(),
        }
    }

    fn finish(&self) {
        let held = self.got.elapsed();
        let site = site_label(self.site);
        metrics::histogram!("hxd_lock_wait_seconds", "lock" => self.lock, "site" => site.clone())
            .record(self.got - self.asked);
        metrics::histogram!("hxd_lock_hold_seconds", "lock" => self.lock, "site" => site)
            .record(held);
    }
}

/// `hxd-core/src/chat.rs:256`: the workspace's `crates/` prefix is the
/// same on every site and says nothing.
#[cfg(feature = "metrics")]
fn site_label(site: &Location<'_>) -> String {
    let file = site.file();
    let file = file.strip_prefix("crates/").unwrap_or(file);
    format!("{file}:{}", site.line())
}

/// Wrap a closure bound for `spawn_blocking` so the pool reports how long
/// it sat queued before a thread took it, and how many are running.
/// `what` names the caller's kind of work, not the call.
pub fn blocking<R>(what: &'static str, f: impl FnOnce() -> R) -> impl FnOnce() -> R {
    #[cfg(feature = "metrics")]
    let queued = Instant::now();
    move || {
        #[cfg(feature = "metrics")]
        let _running = {
            metrics::histogram!("hxd_blocking_queue_seconds", "what" => what)
                .record(queued.elapsed());
            InFlight::enter()
        };
        #[cfg(not(feature = "metrics"))]
        let _ = what;
        f()
    }
}

/// `hxd_blocking_in_flight`, decremented however the closure ends.
#[cfg(feature = "metrics")]
struct InFlight;

#[cfg(feature = "metrics")]
impl InFlight {
    fn enter() -> Self {
        metrics::gauge!("hxd_blocking_in_flight").increment(1.0);
        InFlight
    }
}

#[cfg(feature = "metrics")]
impl Drop for InFlight {
    fn drop(&mut self) {
        metrics::gauge!("hxd_blocking_in_flight").decrement(1.0);
    }
}

/// A started clock, or nothing at all without the feature.
#[derive(Clone, Copy)]
pub struct Timer {
    #[cfg(feature = "metrics")]
    at: Instant,
}

impl Timer {
    pub fn start() -> Self {
        Timer {
            #[cfg(feature = "metrics")]
            at: Instant::now(),
        }
    }

    #[cfg(feature = "metrics")]
    fn elapsed(self) -> Duration {
        self.at.elapsed()
    }
}

/// One event fanned out to `recipients` sessions, under the roster lock.
pub fn fanout(event: &'static str, recipients: usize, took: Timer) {
    #[cfg(feature = "metrics")]
    {
        metrics::histogram!("hxd_fanout_seconds", "event" => event).record(took.elapsed());
        metrics::histogram!("hxd_fanout_recipients", "event" => event).record(recipients as f64);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (event, recipients, took);
}

/// Where an outbox put an event.
#[derive(Clone, Copy)]
pub enum Pushed {
    /// Onto an attached connection's channel.
    Live,
    /// Into a detached session's replay buffer.
    Buffered,
    /// Nowhere: the buffer was already broken, or broke on this one.
    Dropped,
}

/// Events pushed, tallied by the caller and recorded once: a fan-out
/// runs under the roster lock, and one recorder lookup per recipient
/// there would be paid by everyone waiting for it.
#[derive(Clone, Copy, Default)]
pub struct Tally {
    live: u64,
    buffered: u64,
    dropped: u64,
}

impl Tally {
    pub fn add(&mut self, to: Pushed) {
        match to {
            Pushed::Live => self.live += 1,
            Pushed::Buffered => self.buffered += 1,
            Pushed::Dropped => self.dropped += 1,
        }
    }

    pub fn record(self) {
        #[cfg(feature = "metrics")]
        for (sink, n) in [
            ("live", self.live),
            ("buffered", self.buffered),
            ("dropped", self.dropped),
        ] {
            if n > 0 {
                metrics::counter!("hxd_events_pushed_total", "sink" => sink).increment(n);
            }
        }
    }
}

/// A detached session's buffer overflowed; its resume will be a resync.
pub fn outbox_broken() {
    #[cfg(feature = "metrics")]
    metrics::counter!("hxd_outbox_broken_total").increment(1);
}

/// How many items were waiting in a connection's outbound queue when its
/// consumer took the next one. A client that reads slowly shows up here
/// as the tail, long before it shows up anywhere else.
pub fn queue_depth(wire: &'static str, depth: usize) {
    #[cfg(feature = "metrics")]
    metrics::histogram!("hxd_outbox_depth", "wire" => wire).record(depth as f64);
    #[cfg(not(feature = "metrics"))]
    let _ = (wire, depth);
}

/// Frames and bytes queued for writing across every connection of a
/// wire. Signed: the writer subtracts what it wrote, and what it never
/// will when its connection ends.
pub fn write_queued(wire: &'static str, frames: i64, bytes: i64) {
    #[cfg(feature = "metrics")]
    {
        metrics::gauge!("hxd_write_queued_frames", "wire" => wire).increment(frames as f64);
        metrics::gauge!("hxd_write_queued_bytes", "wire" => wire).increment(bytes as f64);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (wire, frames, bytes);
}

/// One write to a socket, from the call to the flush: a peer that stops
/// reading turns into time spent here.
pub fn socket_write(wire: &'static str, took: Timer) {
    #[cfg(feature = "metrics")]
    metrics::histogram!("hxd_socket_write_seconds", "wire" => wire).record(took.elapsed());
    #[cfg(not(feature = "metrics"))]
    let _ = (wire, took);
}

/// Which way a frame went.
#[derive(Clone, Copy)]
pub enum Dir {
    In,
    Out,
}

/// What a frame is, as a label: a name, or a legacy transaction type,
/// which is formatted only when something records it.
#[derive(Clone, Copy)]
pub enum Kind<'a> {
    Name(&'a str),
    Type(u32),
}

/// One frame on a wire. The caller passes a [`Kind`] the server knows,
/// or `Name("other")`: see the module note on label values.
pub fn frame(wire: &'static str, dir: Dir, kind: Kind<'_>, bytes: usize) {
    #[cfg(feature = "metrics")]
    {
        let dir = match dir {
            Dir::In => "in",
            Dir::Out => "out",
        };
        let kind = match kind {
            Kind::Name(name) => name.to_owned(),
            Kind::Type(ty) => ty.to_string(),
        };
        metrics::counter!("hxd_frames_total", "wire" => wire, "dir" => dir, "type" => kind)
            .increment(1);
        metrics::counter!("hxd_frame_bytes_total", "wire" => wire, "dir" => dir)
            .increment(bytes as u64);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (wire, dir, kind, bytes);
}

/// From the first byte of a connection to a session on the roster.
/// `auth` is how it logged in: `guest`, `password`, `identity`, `resume`.
pub fn login(wire: &'static str, auth: &'static str, took: Timer) {
    #[cfg(feature = "metrics")]
    metrics::histogram!("hxd_login_seconds", "wire" => wire, "auth" => auth).record(took.elapsed());
    #[cfg(not(feature = "metrics"))]
    let _ = (wire, auth, took);
}

/// A connection ended, and why.
pub fn disconnect(wire: &'static str, reason: &'static str) {
    #[cfg(feature = "metrics")]
    metrics::counter!("hxd_disconnects_total", "wire" => wire, "reason" => reason).increment(1);
    #[cfg(not(feature = "metrics"))]
    let _ = (wire, reason);
}

/// One call into the media plane, made under the roster lock.
pub fn voice_call(op: &'static str, took: Timer) {
    #[cfg(feature = "metrics")]
    metrics::histogram!("hxd_voice_media_seconds", "op" => op).record(took.elapsed());
    #[cfg(not(feature = "metrics"))]
    let _ = (op, took);
}

/// A file transfer in progress, `download` or `upload`, until the guard
/// drops.
pub fn transfer_open(dir: &'static str) -> Open {
    #[cfg(feature = "metrics")]
    metrics::gauge!("hxd_transfers_open", "dir" => dir).increment(1.0);
    #[cfg(not(feature = "metrics"))]
    let _ = dir;
    Open {
        #[cfg(feature = "metrics")]
        dir,
    }
}

/// [`transfer_open`]'s guard.
#[must_use = "the transfer counts as open until this drops"]
pub struct Open {
    #[cfg(feature = "metrics")]
    dir: &'static str,
}

#[cfg(feature = "metrics")]
impl Drop for Open {
    fn drop(&mut self) {
        metrics::gauge!("hxd_transfers_open", "dir" => self.dir).decrement(1.0);
    }
}

/// A gauge whose value the binary reads at scrape time rather than one
/// kept up to date as things happen.
pub fn gauge(name: &'static str, labels: &[(&'static str, &'static str)], value: f64) {
    #[cfg(feature = "metrics")]
    metrics::gauge!(name, labels).set(value);
    #[cfg(not(feature = "metrics"))]
    let _ = (name, labels, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Guarded(u32);

    #[test]
    fn a_defaulted_lock_is_named_for_what_it_guards() {
        let m = TimedMutex::<Guarded>::default();
        assert_eq!(m.name, "Guarded");
        *m.lock().unwrap() = Guarded(7);
        assert_eq!(m.lock().unwrap().0, 7);
    }

    #[test]
    fn a_poisoned_lock_still_hands_out_its_value() {
        let m = std::sync::Arc::new(TimedMutex::named("t", 1u32));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison it");
        })
        .join();
        let g = m.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(*g, 1);
    }

    #[test]
    fn blocking_runs_the_closure() {
        assert_eq!(blocking("test", || 41 + 1)(), 42);
    }
}
