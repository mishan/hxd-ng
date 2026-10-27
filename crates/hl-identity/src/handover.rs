//! The server key handover (`docs/server-key-handover.md`): a server key
//! signing over to the successor it committed to, and a client's check
//! of the chain of them a server serves against what it pinned for the
//! host. What the client remembers, and where, is the caller's; this
//! only decides.

use sha2::{Digest, Sha256};

use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{PublicKey, ServerKey};
use crate::message::SKEW;
use crate::proof::ServerChallenge;
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/server-handover/v1";

/// The most handovers a server keeps and a client follows (§4).
pub const MAX_CHAIN: usize = 16;

/// What a `next` commits to: the SHA-256 of the key that follows.
pub fn commitment(key: &PublicKey) -> [u8; 32] {
    Sha256::digest(key).into()
}

/// §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handover {
    pub old: PublicKey,
    pub new: PublicKey,
    /// `new`'s own commitment. Without it no later handover can be
    /// followed (§5.3).
    pub next: Option<[u8; 32]>,
    /// When `new` took over.
    pub time: u64,
}

impl Handover {
    pub fn sign(&self, old: &ServerKey) -> Result<Vec<u8>, Error> {
        assert_eq!(old.public(), self.old);
        let unsigned = map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("old", Some(Value::Bytes(self.old.to_vec()))),
            ("new", Some(Value::Bytes(self.new.to_vec()))),
            ("next", self.next.map(|n| Value::Bytes(n.to_vec()))),
            ("time", Some(Value::Uint(self.time))),
        ]);
        let bytes = signed::seal(unsigned, |body| old.sign(DOMAIN, body));
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Handover, Error> {
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let h = Handover {
            old: signed::bytes32(v, "old")?,
            new: signed::bytes32(v, "new")?,
            next: signed::opt_bytes32(v, "next")?,
            time: signed::uint(v, "time")?,
        };
        if h.new == h.old {
            return Err(Error::BadField("new"));
        }
        env.verify(&h.old, DOMAIN)?;
        Ok(h)
    }
}

/// A handover a client followed or took at a first pin: its fork record
/// (§5.4) and the alias it gives (§5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Followed {
    pub old: PublicKey,
    /// SHA-256 of the handover's bytes as served.
    pub sha256: [u8; 32],
    pub time: u64,
    pub next: Option<[u8; 32]>,
}

impl Followed {
    /// §5.5: whether a line or article whose `in.server` is `server`
    /// and that was sent at `sent` is in scope under this alias.
    pub fn covers(&self, server: &PublicKey, sent: u64) -> bool {
        &self.old == server && sent <= self.time.saturating_add(SKEW)
    }
}

/// §5.2: whether a challenge under the pinned key, committing to `seen`,
/// passes without a warning. A commitment seen where none is remembered
/// is not adopted, so the caller keeps remembering none.
pub fn same_key(remembered: Option<&[u8; 32]>, seen: Option<&[u8; 32]>) -> bool {
    remembered.is_none() || remembered == seen
}

/// What a client remembers of a host (§5).
#[derive(Debug, Clone, Copy)]
pub struct Pinned<'a> {
    pub key: PublicKey,
    pub commitment: Option<[u8; 32]>,
    pub followed: &'a [Followed],
    /// The hashes of conflicting handovers whose fork warning the user
    /// accepted, which do not warn again (§5.4).
    pub dismissed: &'a [[u8; 32]],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The same key, and no warning: nothing changes.
    Keep,
    /// Move the pin to `key` without a warning, remember `commitment`,
    /// and add `followed` to the fork records and aliases (§5.3).
    Follow {
        key: PublicKey,
        commitment: Option<[u8; 32]>,
        followed: Vec<Followed>,
    },
    Warn(Warning),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// A served handover conflicts with a record (§5.4); `sha256` is its
    /// hash, which the client dismisses if the user accepts.
    Fork { sha256: [u8; 32] },
    /// The same key with another commitment than the remembered one, or
    /// none (§5.2).
    Recommitted,
    /// The key changed and the served chain does not carry the pin to it
    /// (§5.3).
    Chain(Broken),
}

/// Why a served chain cannot be followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broken {
    /// More than [`MAX_CHAIN`] handovers.
    TooLong,
    /// No handover from the pinned key: it is older than those kept, or
    /// was not handed over at all.
    NotServed,
    /// The first followed `new` does not match the remembered commitment.
    Commitment,
    /// A handover that does not parse or verify.
    Bad(Error),
    /// A handover whose `old` is not the previous one's `new`, or whose
    /// `new` does not match the previous one's `next`, which includes
    /// one after a handover with no `next`.
    Link,
    /// Times not strictly ascending, from after every record the client
    /// holds, or one past now plus `S`.
    Time,
    RepeatedKey,
    /// The last `new` is not the challenge's `server_key`.
    ServerKey,
    /// The last `next` is not the challenge's `next`.
    Next,
}

type Served = (Result<Handover, Error>, [u8; 32]);

/// `None` for a list longer than §4 allows, which is never verified, so
/// that its length costs nothing: it forks nothing, gives no aliases and
/// cannot be followed.
fn serve<B: AsRef<[u8]>>(chain: &[B]) -> Option<Vec<Served>> {
    if chain.len() > MAX_CHAIN {
        return None;
    }
    let served = chain.iter().map(|b| {
        let b = b.as_ref();
        (Handover::parse(b), Sha256::digest(b).into())
    });
    Some(served.collect())
}

/// §5.4. A handover that does not verify names no `old` worth believing,
/// so it forks nothing.
fn forks(served: &[Served], followed: &[Followed], dismissed: &[[u8; 32]]) -> Result<(), Warning> {
    for (h, sha256) in served {
        let Ok(h) = h else { continue };
        if !dismissed.contains(sha256)
            && followed
                .iter()
                .any(|f| f.old == h.old && &f.sha256 != sha256)
        {
            return Err(Warning::Fork { sha256: *sha256 });
        }
    }
    Ok(())
}

/// §5.3's checks over `chain`, the served handovers from the pinned key
/// on, but the first `new`'s commitment, which is the caller's.
fn walk(chain: &[Served], challenge: &ServerChallenge, now: u64) -> Result<Vec<Followed>, Broken> {
    let mut keys = Vec::new();
    let mut prev: Option<&Handover> = None;
    let mut followed = Vec::new();
    for (h, sha256) in chain {
        let h = h.as_ref().map_err(|e| Broken::Bad(e.clone()))?;
        match prev {
            Some(p) if h.old != p.new || p.next != Some(commitment(&h.new)) => {
                return Err(Broken::Link)
            }
            Some(p) if h.time <= p.time => return Err(Broken::Time),
            Some(_) => {}
            None => keys.push(h.old),
        }
        if h.time > now.saturating_add(SKEW) {
            return Err(Broken::Time);
        }
        if keys.contains(&h.new) {
            return Err(Broken::RepeatedKey);
        }
        keys.push(h.new);
        followed.push(Followed {
            old: h.old,
            sha256: *sha256,
            time: h.time,
            next: h.next,
        });
        prev = Some(h);
    }
    if let Some(last) = prev {
        if last.new != challenge.server_key {
            return Err(Broken::ServerKey);
        }
        if last.next != challenge.next {
            return Err(Broken::Next);
        }
    }
    Ok(followed)
}

/// A first pin (§5.1): the aliases `chain` gives, to become the client's
/// records, none if it fails. The client pins `challenge`'s key and
/// remembers its `next`; `challenge` is one [`ServerChallenge::check`]
/// has passed for the host.
pub fn pin<B: AsRef<[u8]>>(chain: &[B], challenge: &ServerChallenge, now: u64) -> Vec<Followed> {
    serve(chain)
        .and_then(|served| walk(&served, challenge, now).ok())
        .unwrap_or_default()
}

/// A pin again after the user accepted a warning (§5.1, §5.3): only the
/// fork check, since it takes no aliases. A key given up at an earlier
/// warning would otherwise come back as an alias through a handover
/// signed by whoever holds it now.
pub fn repin<B: AsRef<[u8]>>(
    chain: &[B],
    followed: &[Followed],
    dismissed: &[[u8; 32]],
) -> Result<(), Warning> {
    forks(&serve(chain).unwrap_or_default(), followed, dismissed)
}

/// Every later fetch of discovery (§5.2–§5.4): `chain` as served, and
/// `challenge` as [`ServerChallenge::check`] has passed it for the host.
pub fn check<B: AsRef<[u8]>>(
    pinned: &Pinned<'_>,
    chain: &[B],
    challenge: &ServerChallenge,
    now: u64,
) -> Verdict {
    let served = serve(chain);
    let listed = served.as_deref().unwrap_or_default();
    if let Err(w) = forks(listed, pinned.followed, pinned.dismissed) {
        return Verdict::Warn(w);
    }
    if challenge.server_key == pinned.key {
        if same_key(pinned.commitment.as_ref(), challenge.next.as_ref()) {
            return Verdict::Keep;
        }
        return Verdict::Warn(Warning::Recommitted);
    }
    let follow = || {
        let served = served.as_deref().ok_or(Broken::TooLong)?;
        let (from, first) = served
            .iter()
            .enumerate()
            .find_map(|(i, (h, _))| match h {
                Ok(h) if h.old == pinned.key => Some((i, h)),
                _ => None,
            })
            .ok_or(Broken::NotServed)?;
        if pinned.commitment != Some(commitment(&first.new)) {
            return Err(Broken::Commitment);
        }
        if pinned.followed.iter().any(|f| f.time >= first.time) {
            return Err(Broken::Time);
        }
        let mut followed = walk(&served[from..], challenge, now)?;
        followed.retain(|f| !pinned.followed.iter().any(|r| r.old == f.old));
        Ok(followed)
    };
    match follow() {
        Ok(followed) => Verdict::Follow {
            key: challenge.server_key,
            commitment: challenge.next,
            followed,
        },
        Err(b) => Verdict::Warn(Warning::Chain(b)),
    }
}
