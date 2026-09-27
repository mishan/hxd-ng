//! What the server holds for its clients, all of them together.
//!
//! Every queue that waits on a client has a bound of its own — a live
//! channel ([`crate::LIVE_QUEUE_CAP`], [`crate::LIVE_QUEUE_BYTES`]), a
//! classic writer's queue — and each is sized so that one client that
//! stops reading costs the server a bounded amount. But a per-connection
//! bound is a bound times the number of connections. A login storm with
//! a few thousand connections present, each holding the joins and parts
//! of all the others, held gigabytes without any one of them near its
//! own cap. So the queues also draw on one budget, and past it the
//! server cuts off whoever holds more than the queues hold on average:
//! the connections that are furthest behind, not one that is merely in
//! the middle of a burst.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// The default budget, in bytes as the queues weigh them
/// ([`crate::Event::weight`], a classic frame's wire length). The weights
/// are estimates, and what the allocator holds for them runs to a few
/// times this.
pub const QUEUE_BUDGET: usize = 128 << 20;

/// The server's budget, and what its queues hold of it now.
pub struct QueueBudget {
    limit: usize,
    held: AtomicUsize,
    /// Queues drawing on it now: one per [`Share`].
    shares: AtomicUsize,
}

/// Why a queue was refused what it asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Over {
    /// Past the queue's own bound.
    Own,
    /// The server's budget is spent and this queue holds more than the
    /// queues do on average.
    Server,
}

impl Over {
    /// For the metric that counts connections cut off.
    pub fn label(self) -> &'static str {
        match self {
            Over::Own => "own",
            Over::Server => "server",
        }
    }
}

impl Default for QueueBudget {
    fn default() -> Self {
        QueueBudget {
            limit: QUEUE_BUDGET,
            held: AtomicUsize::new(0),
            shares: AtomicUsize::new(0),
        }
    }
}

impl QueueBudget {
    pub fn new(limit: usize) -> Arc<QueueBudget> {
        Arc::new(QueueBudget {
            limit,
            held: AtomicUsize::new(0),
            shares: AtomicUsize::new(0),
        })
    }

    /// A share for one queue. What it still holds when it is dropped goes
    /// back to the budget, so a queue that ends with events in it — a
    /// connection that died mid-backlog — leaves nothing behind.
    pub fn share(self: &Arc<Self>) -> Share {
        self.shares.fetch_add(1, Ordering::AcqRel);
        Share {
            budget: self.clone(),
            held: AtomicUsize::new(0),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

/// One queue's draw on the budget.
pub struct Share {
    budget: Arc<QueueBudget>,
    held: AtomicUsize,
}

impl Share {
    /// Take `bytes` for something about to be queued, or refuse. `own` is
    /// the queue's own bound. Past the server's budget a queue may still
    /// take up to what the queues hold on average, so what is refused is
    /// the backlog of whoever is furthest behind. Not the budget's even
    /// split: with the budget spent by a few stalled connections, that is
    /// small enough to catch a reader in the middle of a burst, where the
    /// average is still set by the stalled. And someone always holds at
    /// least the average, so the queues past it go and the total stops
    /// growing.
    pub fn take(&self, bytes: usize, own: usize) -> Result<(), Over> {
        let mine = self.held.fetch_add(bytes, Ordering::AcqRel) + bytes;
        if mine > own {
            self.held.fetch_sub(bytes, Ordering::AcqRel);
            return Err(Over::Own);
        }
        let b = &self.budget;
        let all = b.held.fetch_add(bytes, Ordering::AcqRel) + bytes;
        if all > b.limit {
            let average = all / b.shares.load(Ordering::Acquire).max(1);
            if mine > average {
                b.held.fetch_sub(bytes, Ordering::AcqRel);
                self.held.fetch_sub(bytes, Ordering::AcqRel);
                return Err(Over::Server);
            }
        }
        Ok(())
    }

    /// Give back what [`Share::take`] took, once it has left the queue.
    pub fn give(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::AcqRel);
        self.budget.held.fetch_sub(bytes, Ordering::AcqRel);
    }

    /// What this queue holds.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        let left = *self.held.get_mut();
        self.budget.held.fetch_sub(left, Ordering::AcqRel);
        self.budget.shares.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_takes_up_to_its_own_bound() {
        let budget = QueueBudget::new(1 << 20);
        let s = budget.share();
        assert_eq!(s.take(60, 100), Ok(()));
        assert_eq!(s.take(60, 100), Err(Over::Own));
        assert_eq!((s.held(), budget.held()), (60, 60));
        s.give(60);
        assert_eq!((s.held(), budget.held()), (0, 0));
    }

    #[test]
    fn past_the_budget_only_a_queue_past_the_average_is_refused() {
        let budget = QueueBudget::new(400);
        let behind = budget.share();
        let bursting = budget.share();
        let others: Vec<Share> = (0..2).map(|_| budget.share()).collect();
        assert_eq!(behind.take(340, usize::MAX), Ok(()), "under the budget");
        assert_eq!(bursting.take(50, usize::MAX), Ok(()));
        // Over the budget now, with an average past 100: the one furthest
        // behind is refused, and one in a burst of its own is not.
        assert_eq!(behind.take(20, usize::MAX), Err(Over::Server));
        assert_eq!(bursting.take(20, usize::MAX), Ok(()));
        assert_eq!(others[0].take(20, usize::MAX), Ok(()));
        assert_eq!(budget.held(), 430);
        // And a refusal took nothing.
        assert_eq!(behind.held(), 340);
    }

    #[test]
    fn queues_that_all_fall_behind_together_stop_at_the_budget() {
        let budget = QueueBudget::new(1000);
        let shares: Vec<Share> = (0..10).map(|_| budget.share()).collect();
        for _ in 0..1000 {
            for s in &shares {
                let _ = s.take(10, usize::MAX);
            }
        }
        // Past the budget each can take one more before it is past the
        // average, and none after.
        assert!(budget.held() <= 1000 + 10 * 10, "{}", budget.held());
    }

    #[test]
    fn a_dropped_share_returns_what_it_held() {
        let budget = QueueBudget::new(1000);
        let a = budget.share();
        let b = budget.share();
        a.take(300, usize::MAX).unwrap();
        b.take(200, usize::MAX).unwrap();
        assert_eq!(b.take(600, usize::MAX), Err(Over::Server));
        drop(a);
        assert_eq!(budget.held(), 200);
        assert_eq!(b.take(600, usize::MAX), Ok(()), "back under the budget");
    }
}
