//! The session-token registry: `session_id → (token hash, uid, serial)`.
//!
//! Tokens are bearer credentials for one session: 32 CSPRNG bytes, handed
//! to the client hex-encoded, stored server-side only as a SHA-256 hash and
//! compared in constant time. The `(uid, serial)` pair — not the uid alone —
//! is what the registry trusts, because uids recycle and a stale token must
//! never resume into a stranger's session.
//!
//! The domain doesn't know tokens exist (`docs/hotline-ng.md` §4, D4).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use hxd_core::{Core, Uid};
use sha2::{Digest, Sha256};

struct Entry {
    token_hash: [u8; 32],
    uid: Uid,
    serial: u64,
    /// The session's media-download budget (`docs/inline-media.md` §6),
    /// which lives here because it is the one piece of per-session state
    /// the HTTP routes can reach: they hold a bearer token and a `Core`,
    /// and nothing else about the socket the session belongs to.
    media_tokens: f64,
    media_refill: Instant,
}

/// See the module docs.
#[derive(Default)]
pub struct Registry {
    entries: Mutex<HashMap<String, Entry>>,
    counter: Mutex<u64>,
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a session id + token for a freshly attached session.
    pub fn issue(&self, core: &Core, uid: Uid) -> Option<(String, String)> {
        let serial = core.session_serial(uid)?;
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).ok()?;
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let session_id = {
            let mut c = self.counter.lock().unwrap();
            *c += 1;
            format!("s_{:08x}", *c)
        };
        self.entries.lock().unwrap().insert(
            session_id.clone(),
            Entry {
                token_hash: hash(&token),
                uid,
                serial,
                // Full, not empty: a client that opens a room full of
                // images fetches them all at once, and the budget is
                // there to bound a loop rather than to make the first
                // download wait for a refill. The cap is applied on use,
                // where the configured rate is known.
                media_tokens: f64::MAX,
                media_refill: Instant::now(),
            },
        );
        Some((session_id, token))
    }

    /// Validate a resume credential. Returns the uid only when the token
    /// matches *and* the session it named still exists (serial check —
    /// a recycled uid must not honor an old token). Invalid or stale
    /// entries are dropped on the way through.
    ///
    /// Lock discipline: the entry's fields are copied out and the registry
    /// lock released *before* consulting the core, so the two mutexes are
    /// never held together — no ordering to get wrong, no cross-lock
    /// contention, and immune by construction if the core ever grows a
    /// path back into the registry.
    pub fn validate(&self, core: &Core, session_id: &str, token: &str) -> Option<Uid> {
        let (token_hash, uid, serial) = {
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(session_id)?;
            (entry.token_hash, entry.uid, entry.serial)
        };
        if !constant_time_eq(&token_hash, &hash(token)) {
            return None;
        }
        if core.session_serial(uid) != Some(serial) {
            // Stale: the named session is gone (or its uid was recycled).
            // Session ids are never reused (monotonic counter), so the key
            // can't have become valid again since the snapshot.
            self.entries.lock().unwrap().remove(session_id);
            return None;
        }
        Some(uid)
    }

    /// Take one media-download token for this session, refilling at
    /// `per_minute`. A session may burst a minute's worth — a client
    /// opening a room full of images fetches them all at once — and is
    /// then held to the rate.
    ///
    /// An unknown session id answers `false`: the download routes check
    /// the bearer first, so the only way to reach this with one is a
    /// session that ended in between.
    pub fn allow_download(&self, session_id: &str, per_minute: u32) -> bool {
        let cap = per_minute.max(1) as f64;
        let mut entries = self.entries.lock().unwrap();
        let Some(entry) = entries.get_mut(session_id) else {
            return false;
        };
        let now = Instant::now();
        entry.media_tokens = (entry.media_tokens
            + now.duration_since(entry.media_refill).as_secs_f64() * cap / 60.0)
            .min(cap);
        entry.media_refill = now;
        if entry.media_tokens < 1.0 {
            return false;
        }
        entry.media_tokens -= 1.0;
        true
    }

    /// Forget a session (logout, kick, denial-of-detach).
    pub fn remove(&self, session_id: &str) {
        self.entries.lock().unwrap().remove(session_id);
    }

    /// Drop entries whose sessions no longer exist (sweeper hygiene).
    ///
    /// Same lock discipline as [`Registry::validate`]: snapshot under the
    /// registry lock, consult the core with no lock held, remove under a
    /// reacquired lock. Session ids are never reused, so a key stale at
    /// snapshot time is stale forever — the deferred removal races nothing.
    pub fn prune(&self, core: &Core) {
        let snapshot: Vec<(String, Uid, u64)> = {
            let entries = self.entries.lock().unwrap();
            entries
                .iter()
                .map(|(k, e)| (k.clone(), e.uid, e.serial))
                .collect()
        };
        let stale: Vec<String> = snapshot
            .into_iter()
            .filter(|(_, uid, serial)| core.session_serial(*uid) != Some(*serial))
            .map(|(k, _, _)| k)
            .collect();
        if stale.is_empty() {
            return;
        }
        let mut entries = self.entries.lock().unwrap();
        for k in stale {
            entries.remove(&k);
        }
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}
