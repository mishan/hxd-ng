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

use hxd_core::{Core, Uid};
use sha2::{Digest, Sha256};

struct Entry {
    token_hash: [u8; 32],
    uid: Uid,
    serial: u64,
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
            },
        );
        Some((session_id, token))
    }

    /// Validate a resume credential. Returns the uid only when the token
    /// matches *and* the session it named still exists (serial check —
    /// a recycled uid must not honor an old token). Invalid or stale
    /// entries are dropped on the way through.
    pub fn validate(&self, core: &Core, session_id: &str, token: &str) -> Option<Uid> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get(session_id)?;
        if !constant_time_eq(&entry.token_hash, &hash(token)) {
            return None;
        }
        if core.session_serial(entry.uid) != Some(entry.serial) {
            entries.remove(session_id);
            return None;
        }
        Some(entry.uid)
    }

    /// Forget a session (logout, kick, denial-of-detach).
    pub fn remove(&self, session_id: &str) {
        self.entries.lock().unwrap().remove(session_id);
    }

    /// Drop entries whose sessions no longer exist (sweeper hygiene).
    pub fn prune(&self, core: &Core) {
        self.entries
            .lock()
            .unwrap()
            .retain(|_, e| core.session_serial(e.uid) == Some(e.serial));
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}
