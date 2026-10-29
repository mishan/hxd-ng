//! The server's clock: real time, plus an offset a test can advance, so a
//! test can see what the server decides a minute or a day from now
//! without waiting for it. What reads a clock reads its
//! [`Core`](crate::Core)'s, so each server a test starts keeps time of
//! its own; so far that is the verifying side's identity state and
//! registrars, and the rest of the server is on real time.
//! Timers (tokio's sleeps and timeouts) stay on real time: the offset
//! moves what the server decides, not when it wakes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default)]
pub struct Clock {
    /// Milliseconds added to real time.
    offset: Arc<AtomicU64>,
}

impl Clock {
    fn offset(&self) -> Duration {
        Duration::from_millis(self.offset.load(Ordering::Relaxed))
    }

    pub fn now(&self) -> Instant {
        Instant::now() + self.offset()
    }

    /// The wall time, for what is stored and lapses.
    pub fn wall(&self) -> SystemTime {
        SystemTime::now() + self.offset()
    }

    /// Unix seconds.
    pub fn unix(&self) -> u64 {
        (SystemTime::now() + self.offset())
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// How long ago `at`, a time this clock gave, was.
    pub fn since(&self, at: Instant) -> Duration {
        self.now().saturating_duration_since(at)
    }

    /// Move this clock, and everything reading it, `by` into the future.
    pub fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.offset.fetch_add(ms, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advancing_moves_both_kinds_of_time_and_every_copy() {
        let clock = Clock::default();
        let copy = clock.clone();
        let (at, unix) = (clock.now(), clock.unix());
        copy.advance(Duration::from_secs(90));
        assert!(clock.since(at) >= Duration::from_secs(90));
        assert!(clock.unix() >= unix + 90);
    }
}
