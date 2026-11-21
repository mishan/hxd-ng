//! Why a session was ended or kicked, for its resume
//! (`docs/hotline-ng.md` §6.2): one detached has nobody there to hear
//! it, and one attached may lose its socket before its client reads it,
//! and either would otherwise answer its resume as a session that
//! lapsed, which a client meets by logging in again, undoing the end.
//! Kept no longer than the grace a resume could have come in, and for so
//! many sessions at most, the oldest forgotten first.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::roster::{Core, RosterInner, Uid};

/// How many ended sessions are remembered at once.
pub const ENDINGS: usize = 4096;

/// What ended a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndedBy {
    /// One of its own person's devices ended it (`device_end`).
    Ended,
    /// A kick.
    Kicked,
    /// Its identity or device key was revoked here, which a login with
    /// that key is told too.
    Revoked,
    /// Its certificate was issued below its identity's device epoch
    /// floor, this one, which a login with it is told too.
    BelowFloor(u64),
    /// A kick with a ban, or a ban, that stands now.
    Banned(crate::ban::BanHit),
}

impl EndedBy {
    /// Which of two endings a resume is told: the one that says most.
    fn rank(&self) -> u8 {
        match self {
            EndedBy::Ended => 0,
            EndedBy::Kicked => 1,
            EndedBy::Revoked | EndedBy::BelowFloor(_) => 2,
            EndedBy::Banned(_) => 3,
        }
    }
}

/// What a ban of the session would match, kept so its resume can tell a
/// ban, with its reason and its end, from a kick.
#[derive(Clone)]
struct Who {
    login: String,
    identity: Option<[u8; 32]>,
    handle: Option<String>,
    addr: Option<IpAddr>,
}

/// Sessions ended or kicked, by `(uid, serial)`, which a uid let go and
/// given out again does not match.
#[derive(Default)]
pub(crate) struct Endings {
    by: HashMap<(Uid, u64), (EndedBy, Who, Instant)>,
    order: VecDeque<(Uid, u64)>,
}

impl Endings {
    fn record(&mut self, key: (Uid, u64), why: EndedBy, who: Who, now: Instant) {
        match self.by.get_mut(&key) {
            Some(had) if had.0.rank() >= why.rank() => {}
            Some(had) => (had.0, had.1) = (why, who),
            None => {
                self.by.insert(key, (why, who, now));
                self.order.push_back(key);
            }
        }
        while self.order.len() > ENDINGS {
            if let Some(old) = self.order.pop_front() {
                self.by.remove(&old);
            }
        }
    }

    fn get(&self, key: (Uid, u64), within: Duration, now: Instant) -> Option<(EndedBy, Who)> {
        self.by
            .get(&key)
            .filter(|(_, _, at)| now.duration_since(*at) < within)
            .map(|(why, who, _)| (why.clone(), who.clone()))
    }

    fn forget(&mut self, older_than: Duration, now: Instant) {
        while let Some(key) = self.order.front().copied() {
            match self.by.get(&key) {
                Some((_, _, at)) if now.duration_since(*at) < older_than => break,
                _ => {
                    self.order.pop_front();
                    self.by.remove(&key);
                }
            }
        }
    }
}

impl RosterInner {
    /// `uid` is being ended for `why`, at once or once its connection
    /// has heard it.
    pub(crate) fn remember_end(&mut self, uid: Uid, why: EndedBy) {
        let Some(s) = self.users.get(&uid) else {
            return;
        };
        let who = Who {
            login: s.login.clone(),
            identity: s.identity,
            handle: s
                .info
                .transport
                .identity
                .as_ref()
                .and_then(|t| t.handle.clone()),
            addr: s.addr,
        };
        self.endings
            .record((uid, s.serial), why, who, Instant::now());
    }
}

impl Core {
    /// What ended the session `(uid, serial)`, if it was ended or kicked
    /// within `within`.
    pub fn ended_by(&self, uid: Uid, serial: u64, within: Duration) -> Option<EndedBy> {
        let (why, who) = {
            let r = self.roster.lock().unwrap();
            r.endings.get((uid, serial), within, Instant::now())?
        };
        if !matches!(
            why,
            EndedBy::Kicked | EndedBy::Revoked | EndedBy::BelowFloor(_)
        ) {
            return Some(why);
        }
        // A kick's ban is placed after it, and a revocation may come
        // between the two: asked now, as a login would be.
        let banned = who.addr.and_then(|a| self.address_banned(a)).or_else(|| {
            self.person_banned(
                Some(&who.login),
                who.identity.as_ref(),
                who.handle.as_deref(),
            )
        });
        Some(banned.map_or(why, EndedBy::Banned))
    }

    /// Whether the session `(uid, serial)` was ended or kicked within
    /// `within`: [`Core::ended_by`] without asking after a ban.
    pub fn remembers_end(&self, uid: Uid, serial: u64, within: Duration) -> bool {
        let r = self.roster.lock().unwrap();
        r.endings
            .get((uid, serial), within, Instant::now())
            .is_some()
    }

    /// Forget sessions ended longer ago than `grace`, past which their
    /// resume would have lapsed anyway. Run by the ng sweeper.
    pub fn forget_endings(&self, grace: Duration) {
        let mut r = self.roster.lock().unwrap();
        r.endings.forget(grace, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> Who {
        Who {
            login: "alice".into(),
            identity: None,
            handle: None,
            addr: None,
        }
    }

    #[test]
    fn so_many_endings_are_kept_the_oldest_forgotten_first_and_none_past_its_time() {
        let mut e = Endings::default();
        let t0 = Instant::now();
        for uid in 0..=ENDINGS as u64 {
            e.record((uid as Uid, uid), EndedBy::Kicked, who(), t0);
        }
        let hour = Duration::from_secs(3600);
        assert_eq!(e.by.len(), ENDINGS);
        let why = |key, within, now| e.get(key, within, now).map(|(why, _)| why);
        assert_eq!(why((0, 0), hour, t0), None, "the oldest went");
        assert_eq!(why((1, 1), hour, t0), Some(EndedBy::Kicked));
        assert_eq!(why((1, 2), hour, t0), None, "another serial");
        let later = t0 + Duration::from_secs(60);
        assert_eq!(
            why((1, 1), Duration::from_secs(60), later),
            None,
            "past its time"
        );
        e.forget(Duration::from_secs(60), later);
        assert!(e.by.is_empty() && e.order.is_empty(), "forgotten");
    }

    #[test]
    fn of_two_endings_the_one_that_says_more_is_kept() {
        use EndedBy::*;
        let t0 = Instant::now();
        let hour = Duration::from_secs(3600);
        for (first, then, kept) in [
            (Revoked, Kicked, Revoked),
            (Kicked, Revoked, Revoked),
            (Kicked, Ended, Kicked),
        ] {
            let mut e = Endings::default();
            e.record((1, 1), first.clone(), who(), t0);
            e.record((1, 1), then.clone(), who(), t0);
            let why = e.get((1, 1), hour, t0).map(|(why, _)| why);
            assert_eq!(why, Some(kept), "{first:?} then {then:?}");
            assert_eq!(e.order.len(), 1);
        }
    }
}
