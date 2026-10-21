//! One origin's recent history, and whether to send to it
//! (`docs/webpush-gateway.md` §5). A uniqush sidecar is one origin to
//! the same rule (push-notifications.md §4.1).

use std::time::{Duration, Instant};

#[derive(Debug, Default, Clone, Copy)]
pub struct Breaker {
    consecutive: u32,
    /// When the cooldown ends, for an origin that is currently open.
    open_until: Option<Instant>,
    /// The cooldown ended and one send has been let through to see
    /// whether the origin is back. Every other send is skipped until it
    /// answers; without this, the first caller after a cooldown would
    /// clear the gate and the whole fan-out behind it would follow.
    probing: bool,
}

impl Breaker {
    /// May a send go now? When the cooldown ends exactly one probe is let
    /// through, and everything else waits for its answer.
    pub fn allows(&mut self, now: Instant) -> bool {
        match self.open_until {
            Some(until) if until > now => false,
            Some(_) if self.probing => false,
            Some(_) => {
                self.probing = true;
                true
            }
            None => true,
        }
    }

    /// The origin answered, so it is up.
    pub fn succeeded(&mut self) {
        *self = Breaker::default();
    }

    /// The origin's own trouble, answering whether it opened the breaker:
    /// `failures` in a row, or a probe's failure, shut it for `cooldown`.
    pub fn failed(&mut self, now: Instant, failures: u32, cooldown: Duration) -> bool {
        self.consecutive = self.consecutive.saturating_add(1);
        if self.probing || self.consecutive >= failures {
            self.open_until = Some(crate::after(now, cooldown));
            self.probing = false;
            return true;
        }
        false
    }
}
