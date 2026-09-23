//! The identity registrar (`docs/identity-registrar.md`).
//!
//! A registrar lends an identity a name and a place to be found: it
//! issues attestations for handles, publishes the records that say a key
//! is revoked, rotated or frozen, and logs everything it issues so an
//! operator who has never met it can decide whether to trust it (§1).
//!
//! This crate is that, and nothing of Hotline: it takes signed bytes in
//! and hands signed bytes back, and the HTTP around it is
//! `hxd-ng-session`'s. It reads no roster and no account — the one thing
//! it wants from the server around it is the list of names already
//! spoken for, which the caller hands it as [`Config::reserved`].
//!
//! Every write is serialized through one lock, held from the first check
//! to the last write. The store makes each write atomic; the lock makes
//! the *decision* atomic with it, so two registrations of one free handle
//! cannot both see it free. The lock is two: this process's mutex, and
//! the store's own ([`RegistrarStore::begin`]), which is what holds off
//! an operator's `hxd registrar` command writing the same file from
//! another process. Nothing here is on a hot path — a registrar issues a
//! name a year per user — so a lock is the honest tool.
//!
//! Times are Unix seconds and always the caller's, so the tests can
//! drive every lifecycle without a clock.

pub mod conformance;
pub mod memory;
pub mod store;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use hl_identity::registrar::{attestation_reason, handle_is_canonical};
use hl_identity::{
    Attestation, AttestationRevocation, Card, Fingerprint, Freeze, ListKind, PublicKey, Record,
    RegisterRequest, RegistrarKeys, Rotation, ServerKey, SignedList, Stats,
};
use sha2::{Digest, Sha256};

pub use store::{
    Counts, Effect, HandleRow, HandleState, IdentityRow, Issue, Issued, Key, NewRecord, Page,
    Pending, Publish, RecordFilter, RecordKind, Recovery, RegistrarStore, StoreError,
};

const DAY: u64 = 86_400;

/// Who may register (§5.3). Only the kinds of proof this registrar can
/// check are representable: `email`, `oidc` and `vouch` need machinery
/// (a mailer, a provider, the vouch spec) that is not built, and a
/// setting that promised them would be a registrar that silently
/// refused everyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signup {
    /// Any correctly signed request, subject to the rate limits.
    Open,
    /// A request must carry an unspent invite code as its `proof`.
    Invite,
    /// No new registrations; reissues continue.
    Closed,
}

/// §10's ceilings. Every one is a setting with a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rates {
    pub registrations_per_address: u32,
    pub registrations_total: u32,
    pub records_per_identity: u32,
    pub lookups_per_address: u32,
    pub device_revocations_kept: usize,
}

impl Default for Rates {
    fn default() -> Self {
        Rates {
            registrations_per_address: 5,
            registrations_total: 120,
            records_per_identity: 20,
            lookups_per_address: 60,
            device_revocations_kept: 256,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// The name attestations carry as `registrar` (§3): lowercase, no
    /// port.
    pub host: String,
    pub signup: Signup,
    /// Where a person without an invite can get one, for the
    /// `proof_required` answer.
    pub proof_url: Option<String>,
    /// The `level` written into every attestation (§5.3).
    pub level: u64,
    pub attestation_days: u64,
    pub hold_days: u64,
    pub handle_min: usize,
    pub handle_max: usize,
    /// Local parts nobody may newly register: the built-in list, the
    /// operator's additions, and the server's own account logins.
    pub reserved: HashSet<String>,
    /// Seconds a posted rotation is held before it is published (§5.4).
    pub rotation_delay: u64,
    pub records_max_age: u64,
    /// Keys still valid for verification, with the time each stops being
    /// (§4.1). Published, never signed with.
    pub retiring: Vec<(PublicKey, u64)>,
    pub clock_skew: u64,
    pub rates: Rates,
}

impl Config {
    /// The names a registrar reserves whatever its operator adds (§11).
    pub const BUILT_IN_RESERVED: &'static [&'static str] = &[
        "guest",
        "admin",
        "administrator",
        "root",
        "system",
        "server",
        "registrar",
        "postmaster",
        "abuse",
    ];

    /// A configuration with every default of §11 and the given host.
    pub fn new(host: impl Into<String>) -> Config {
        Config {
            host: host.into(),
            signup: Signup::Invite,
            proof_url: None,
            level: 2,
            attestation_days: 365,
            hold_days: 365,
            handle_min: 3,
            handle_max: 32,
            reserved: Self::BUILT_IN_RESERVED
                .iter()
                .map(|s| s.to_string())
                .collect(),
            rotation_delay: 0,
            records_max_age: 3600,
            retiring: Vec::new(),
            clock_skew: 300,
            rates: Rates::default(),
        }
    }
}

/// Why a request was refused: §6.5's codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    BadRequest(String),
    BadSignature,
    BadTime,
    HandleInvalid,
    HandleReserved,
    HandleTaken,
    HandleHeld,
    ProofRequired {
        url: Option<String>,
    },
    ProofInvalid,
    SignupClosed,
    Frozen,
    /// Revoked, or rotated away to `successor`.
    Revoked {
        successor: Option<PublicKey>,
    },
    SuccessorMismatch,
    NotRegistered,
    NotFound,
    TooLarge,
    RateLimited {
        retry_after: u64,
    },
    /// The store failed. The operator's problem, and logged where it
    /// happened; the client hears only that it was not them.
    Store(StoreError),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::BadRequest(_) => "bad_request",
            Refusal::BadSignature => "bad_signature",
            Refusal::BadTime => "bad_time",
            Refusal::HandleInvalid => "handle_invalid",
            Refusal::HandleReserved => "handle_reserved",
            Refusal::HandleTaken => "handle_taken",
            Refusal::HandleHeld => "handle_held",
            Refusal::ProofRequired { .. } => "proof_required",
            Refusal::ProofInvalid => "proof_invalid",
            Refusal::SignupClosed => "signup_closed",
            Refusal::Frozen => "frozen",
            Refusal::Revoked { .. } => "revoked",
            Refusal::SuccessorMismatch => "successor_mismatch",
            Refusal::NotRegistered => "not_registered",
            Refusal::NotFound => "not_found",
            Refusal::TooLarge => "too_large",
            Refusal::RateLimited { .. } => "rate_limited",
            Refusal::Store(_) => "server_error",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Refusal::BadRequest(_) => 400,
            Refusal::BadSignature | Refusal::BadTime => 401,
            Refusal::HandleInvalid
            | Refusal::HandleReserved
            | Refusal::HandleTaken
            | Refusal::HandleHeld
            | Refusal::SuccessorMismatch => 409,
            Refusal::ProofRequired { .. }
            | Refusal::ProofInvalid
            | Refusal::SignupClosed
            | Refusal::Frozen
            | Refusal::Revoked { .. } => 403,
            Refusal::NotRegistered | Refusal::NotFound => 404,
            Refusal::TooLarge => 413,
            Refusal::RateLimited { .. } => 429,
            Refusal::Store(_) => 500,
        }
    }

    /// A sentence for a person.
    pub fn text(&self) -> String {
        match self {
            Refusal::BadRequest(why) => why.clone(),
            Refusal::BadSignature => "a signature did not verify".into(),
            Refusal::BadTime => {
                "the request's time is outside the clock-skew tolerance, or it was already used"
                    .into()
            }
            Refusal::HandleInvalid => {
                "handles are lowercase letters, digits and . _ - (not two in a row, \
                 not at either end)"
                    .into()
            }
            Refusal::HandleReserved => "that handle is reserved".into(),
            Refusal::HandleTaken => "that handle is taken".into(),
            Refusal::HandleHeld => "that handle is being held for the identity that had it".into(),
            Refusal::ProofRequired { .. } => "this registrar needs an invite code".into(),
            Refusal::ProofInvalid => "that invite code is not valid or was already used".into(),
            Refusal::SignupClosed => "this registrar is not taking new registrations".into(),
            Refusal::Frozen => "this identity is frozen at this registrar".into(),
            Refusal::Revoked { successor: None } => "this identity is revoked".into(),
            Refusal::Revoked { successor: Some(_) } => {
                "this identity was rotated to a successor key".into()
            }
            Refusal::SuccessorMismatch => {
                "the successor does not match the one this identity committed to".into()
            }
            Refusal::NotRegistered => "this registrar does not attest to that identity".into(),
            Refusal::NotFound => "not found".into(),
            Refusal::TooLarge => "the object is too large".into(),
            Refusal::RateLimited { .. } => "too many requests; try again later".into(),
            Refusal::Store(_) => "server error".into(),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Store(e) => write!(f, "{e}"),
            other => write!(f, "{}: {}", other.code(), other.text()),
        }
    }
}

impl From<StoreError> for Refusal {
    fn from(e: StoreError) -> Self {
        tracing::error!("{e}");
        Refusal::Store(e)
    }
}

/// How a parse failure is answered. A bad signature, or a key that is
/// not one, is `bad_signature`; an object over its bound is `too_large`;
/// everything else is the request being malformed.
fn parse_refusal(e: hl_identity::Error) -> Refusal {
    use hl_identity::Error as E;
    match e {
        E::BadSignature | E::InvalidKey => Refusal::BadSignature,
        E::TooLarge => Refusal::TooLarge,
        other => Refusal::BadRequest(other.to_string()),
    }
}

/// The answer to a registration (§6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub attestation: Vec<u8>,
    /// `handle@host`.
    pub handle: String,
    pub registered: u64,
    pub expires: u64,
    pub reissued: bool,
}

/// The answer to a posted record (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posted {
    Published {
        seq: u64,
    },
    /// A rotation inside its delay.
    Pending {
        until: u64,
    },
}

/// A held handle, as `lookup` shows it (§6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub identity: PublicKey,
    pub registered: u64,
    pub expires: u64,
}

/// A request's address, as the limits count it: an IPv6 host is given a
/// /64 to wander in, so the /64 is what is counted.
fn address_key(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Limit {
    RegisterFrom(IpAddr),
    RegisterAll,
    Records(Key),
    LookupFrom(IpAddr),
}

impl Limit {
    fn window(self) -> u64 {
        match self {
            Limit::LookupFrom(_) => 60,
            _ => 3600,
        }
    }
}

/// Fixed windows per key. Bounded like every table an unauthenticated
/// caller can grow: past the ceiling, expired windows are dropped, and if
/// that is not enough the caller is refused — a full table must never be
/// a way out of being counted.
#[derive(Debug, Default)]
struct Limits {
    windows: HashMap<Limit, (u64, u32)>,
    /// Registrations accepted inside the skew window, by the digest of
    /// the request, with the answer each got and the time it may be
    /// forgotten (§10).
    seen: HashMap<[u8; 32], (u64, Registered)>,
}

const MAX_WINDOWS: usize = 16 * 1024;
const MAX_SEEN: usize = 16 * 1024;

impl Limits {
    /// Would one more under `key` pass `max`? `Err` carries the seconds
    /// until the window turns.
    fn check(&mut self, key: Limit, max: u32, now: u64) -> Result<(), u64> {
        let w = key.window();
        if let Some((start, count)) = self.windows.get(&key) {
            if now < start + w && *count >= max {
                return Err(start + w - now);
            }
        }
        if !self.windows.contains_key(&key) && self.windows.len() >= MAX_WINDOWS {
            self.windows
                .retain(|k, (start, _)| now < *start + k.window());
            if self.windows.len() >= MAX_WINDOWS {
                return Err(w);
            }
        }
        Ok(())
    }

    fn charge(&mut self, key: Limit, now: u64) {
        let w = key.window();
        let e = self.windows.entry(key).or_insert((now, 0));
        if now >= e.0 + w {
            *e = (now, 0);
        }
        e.1 += 1;
    }

    fn take(&mut self, key: Limit, max: u32, now: u64) -> Result<(), u64> {
        self.check(key, max, now)?;
        self.charge(key, now);
        Ok(())
    }

    fn seen(&self, digest: &[u8; 32], now: u64) -> Option<Registered> {
        self.seen
            .get(digest)
            .filter(|(until, _)| now < *until)
            .map(|(_, r)| r.clone())
    }

    /// Past the ceiling the entry is simply not kept: the request it
    /// would have answered is then outside the window or answered as a
    /// reissue, and neither issues anything the first did not.
    fn remember(&mut self, digest: [u8; 32], until: u64, reply: Registered, now: u64) {
        if self.seen.len() >= MAX_SEEN {
            self.seen.retain(|_, (u, _)| now < *u);
            if self.seen.len() >= MAX_SEEN {
                return;
            }
        }
        self.seen.insert(digest, (until, reply));
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The display alphabet of invite codes: Crockford's, which has no I, L,
/// O or U to misread.
const INVITE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The stored form of an invite: `SHA-256` of the code with its grouping
/// and case taken out, so `abcd-efgh…` typed from a screen matches.
pub fn invite_hash(code: &str) -> [u8; 32] {
    let norm: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    digest(norm.as_bytes())
}

/// A fresh invite code: 80 bits from the OS CSPRNG, as four groups of
/// four.
pub fn new_invite_code() -> String {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).expect("OS CSPRNG unavailable");
    let chars: Vec<char> = raw
        .iter()
        .map(|b| INVITE_ALPHABET[(b & 31) as usize] as char)
        .collect();
    chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

pub struct Registrar {
    cfg: Config,
    /// Reloadable separately from the rest, because the server's account
    /// logins change without the registrar's settings changing.
    reserved: RwLock<HashSet<String>>,
    key: ServerKey,
    store: Arc<dyn RegistrarStore>,
    write: Mutex<()>,
    limits: Mutex<Limits>,
    /// Stats are recomputed at most hourly (§6.6).
    stats: Mutex<Option<(u64, Vec<u8>)>>,
}

impl fmt::Debug for Registrar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registrar")
            .field("host", &self.cfg.host)
            .finish_non_exhaustive()
    }
}

impl Registrar {
    pub fn new(cfg: Config, key: ServerKey, store: Arc<dyn RegistrarStore>) -> Registrar {
        Registrar {
            reserved: RwLock::new(cfg.reserved.clone()),
            cfg,
            key,
            store,
            write: Mutex::new(()),
            limits: Mutex::new(Limits::default()),
            stats: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public()
    }

    /// Replace the reserved names, as a reload does when the server's
    /// accounts changed.
    pub fn set_reserved(&self, reserved: HashSet<String>) {
        *self.reserved.write().unwrap() = reserved;
    }

    fn hold(&self) -> u64 {
        self.cfg.hold_days.saturating_mul(DAY)
    }

    fn keys(&self) -> Vec<PublicKey> {
        let mut keys = vec![self.key.public()];
        keys.extend(self.cfg.retiring.iter().map(|(k, _)| *k));
        keys
    }

    fn check_time(&self, time: u64, now: u64) -> Result<(), Refusal> {
        if time.abs_diff(now) > self.cfg.clock_skew {
            return Err(Refusal::BadTime);
        }
        Ok(())
    }

    /// The identity's standing, for anything that writes on its behalf.
    fn usable(row: &IdentityRow) -> Result<(), Refusal> {
        if let Some(successor) = row.rotated_to {
            return Err(Refusal::Revoked {
                successor: Some(successor),
            });
        }
        if row.revoked {
            return Err(Refusal::Revoked { successor: None });
        }
        if row.frozen {
            return Err(Refusal::Frozen);
        }
        Ok(())
    }

    /// Run a decision and the writes it leads to under the write lock:
    /// the mutex, then the store's transaction. A refusal commits like a
    /// success — whatever was written before it (a due rotation published
    /// on the way in) stands on its own.
    fn writing<T, E: From<StoreError>>(&self, f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        /// Rolls back if `f` unwinds.
        struct Open<'a>(Option<&'a dyn RegistrarStore>);
        impl Drop for Open<'_> {
            fn drop(&mut self) {
                if let Some(store) = self.0 {
                    store.rollback();
                }
            }
        }
        let _w = self.write.lock().unwrap();
        self.store.begin()?;
        let mut open = Open(Some(&*self.store));
        let result = f();
        open.0 = None;
        if let Err(e) = self.store.commit() {
            self.store.rollback();
            return Err(e.into());
        }
        result
    }

    fn limit(&self, key: Limit, max: u32, now: u64) -> Result<(), Refusal> {
        self.limits
            .lock()
            .unwrap()
            .check(key, max, now)
            .map_err(|retry_after| Refusal::RateLimited { retry_after })
    }

    // --- §6.1 register -----------------------------------------------------

    pub fn register(&self, bytes: &[u8], addr: IpAddr, now: u64) -> Result<Registered, Refusal> {
        let req = RegisterRequest::parse(bytes).map_err(parse_refusal)?;
        if req.registrar != self.cfg.host {
            return Err(Refusal::BadRequest(format!(
                "this registrar is {}, not {}",
                self.cfg.host, req.registrar
            )));
        }
        self.check_time(req.time, now)?;
        // A replay inside the skew window (§10) changes nothing: it is
        // answered with what the request got the first time, so a client
        // that lost the reply can send it again, and a replayer learns
        // only what the client already knew.
        let request_digest = digest(bytes);
        if let Some(reply) = self.limits.lock().unwrap().seen(&request_digest, now) {
            return Ok(reply);
        }
        if !handle_is_canonical(&req.handle, self.cfg.handle_min, self.cfg.handle_max) {
            return Err(Refusal::HandleInvalid);
        }

        let reply = self.writing(|| {
            self.publish_due(now)?;
            let row = self.store.identity(&req.identity)?;
            if let Some(row) = &row {
                Self::usable(row)?;
                // §5.4: once recorded, the commitment is immutable, and a
                // request that changes *or drops* it is refused.
                if row.commitment.is_some() && req.successor != row.commitment {
                    return Err(Refusal::SuccessorMismatch);
                }
            }

            let fp = Fingerprint::of(&req.identity).0;
            let existing = self.store.handle(&req.handle)?;
            let grant = self.store.recovery(&req.handle)?;
            let hold = self.hold();
            let (registered, first, recovery) = match (&grant, &existing) {
                // An operator's recovery (§8.3): the grantee's next request
                // is a reissue, whatever state the handle is in.
                (Some(g), _) if g.fingerprint == fp => {
                    let registered = match (&existing, g.keep_age) {
                        (Some(h), true) => h.registered,
                        _ => now,
                    };
                    (registered, false, Some(g.handle.clone()))
                }
                // Anyone else waits, the old key included: it is the one
                // the recovery took the name from.
                (Some(_), _) => return Err(Refusal::HandleHeld),
                (None, Some(h)) if h.identity == req.identity => match h.state(now, hold) {
                    HandleState::Released => (now, true, None),
                    // Revoked for abuse: the hold keeps everyone off the
                    // name, the abuser included.
                    _ if h.barred => return Err(Refusal::HandleHeld),
                    // Held, or lapsed within the hold: a reissue, age kept.
                    _ => (h.registered, false, None),
                },
                (None, Some(h)) => match h.state(now, hold) {
                    HandleState::Held => return Err(Refusal::HandleTaken),
                    HandleState::Lapsed => return Err(Refusal::HandleHeld),
                    HandleState::Released => (now, true, None),
                },
                (None, None) => (now, true, None),
            };

            let mut invite = None;
            if first {
                if self.reserved.read().unwrap().contains(&req.handle) {
                    return Err(Refusal::HandleReserved);
                }
                match self.cfg.signup {
                    Signup::Closed => return Err(Refusal::SignupClosed),
                    Signup::Open => {}
                    Signup::Invite => {
                        let Some(code) = req.proof.as_deref() else {
                            return Err(Refusal::ProofRequired {
                                url: self.cfg.proof_url.clone(),
                            });
                        };
                        let hash = invite_hash(code);
                        if !self.store.invite_open(&hash)? {
                            return Err(Refusal::ProofInvalid);
                        }
                        invite = Some(hash);
                    }
                }
                // Reissues are exempt from both: a registrar that ran out of
                // registrations must still renew the names it gave out.
                self.limit(
                    Limit::RegisterFrom(address_key(addr)),
                    self.cfg.rates.registrations_per_address,
                    now,
                )?;
                self.limit(Limit::RegisterAll, self.cfg.rates.registrations_total, now)?;
            }

            // An attestation revocation voids everything issued at or before
            // its time (§4.8), so a reissue in the same second as one — the
            // operator's revoke, and the holder asking again at once — would
            // be void as it left. It is issued the second after instead.
            let issued = match row {
                Some(_) => match self.revoked_through(&req.identity, &req.handle)? {
                    Some(t) if t >= now => t.saturating_add(1),
                    _ => now,
                },
                None => now,
            };
            if issued > now.saturating_add(self.cfg.clock_skew) {
                return Err(Refusal::RateLimited {
                    retry_after: issued - now - self.cfg.clock_skew,
                });
            }
            let expires = issued.saturating_add(self.cfg.attestation_days.saturating_mul(DAY));
            let attestation = Attestation {
                identity: req.identity,
                registrar: self.cfg.host.clone(),
                registrar_key: self.key.public(),
                handle: req.handle.clone(),
                registered,
                issued,
                expires,
                level: Some(self.cfg.level),
            }
            .sign(&self.key);
            let issued = self.store.issue(&Issue {
                identity: req.identity,
                commitment: req.successor,
                handle: HandleRow {
                    name: req.handle.clone(),
                    identity: req.identity,
                    registered,
                    expires,
                    lapsed_at: None,
                    barred: false,
                },
                first,
                issued,
                attestation: attestation.clone(),
                invite,
                recovery,
            })?;
            if issued == Issued::InviteSpent {
                return Err(Refusal::ProofInvalid);
            }
            let reply = Registered {
                attestation,
                handle: format!("{}@{}", req.handle, self.cfg.host),
                registered,
                expires,
                reissued: !first,
            };
            // Charged under the lock, so two first registrations cannot
            // both fit under one remaining slot. A charge for a write that
            // then fails to commit errs toward refusing.
            if first {
                let mut limits = self.limits.lock().unwrap();
                limits.charge(Limit::RegisterFrom(address_key(addr)), now);
                limits.charge(Limit::RegisterAll, now);
            }
            Ok(reply)
        })?;
        // Remembered only once committed: a replay answered from here is
        // an attestation the log holds, never one a failed commit lost.
        // A replay that arrives before this line is simply decided again.
        let until = req.time.saturating_add(self.cfg.clock_skew) + 1;
        self.limits
            .lock()
            .unwrap()
            .remember(request_digest, until, reply.clone(), now);
        tracing::info!(
            handle = %req.handle,
            fingerprint = %Fingerprint::of(&req.identity).short(),
            reissued = reply.reissued,
            "registrar issued an attestation"
        );
        Ok(reply)
    }

    /// The latest time this registrar revoked the identity's attestations
    /// for the handle (§4.8), if it ever has.
    fn revoked_through(&self, identity: &Key, handle: &str) -> Result<Option<u64>, Refusal> {
        let keys = self.keys();
        let held = self
            .store
            .records_page(RecordFilter::Identity(*identity), 0, usize::MAX)?;
        Ok(held
            .entries
            .iter()
            .filter_map(|(_, b)| {
                match Record::parse(
                    b,
                    Some(RegistrarKeys {
                        host: &self.cfg.host,
                        keys: &keys,
                    }),
                ) {
                    Ok(Record::RevokeAttestation(r))
                        if r.identity == *identity && r.handle == handle =>
                    {
                        Some(r.time)
                    }
                    _ => None,
                }
            })
            .max())
    }

    // --- §6.2 records ------------------------------------------------------

    /// Accept a user-signed record (§4.4–§4.6).
    pub fn post_record(&self, bytes: &[u8], now: u64) -> Result<Posted, Refusal> {
        let keys = self.keys();
        let registrar = RegistrarKeys {
            host: &self.cfg.host,
            keys: &keys,
        };
        let record = Record::parse(bytes, Some(registrar)).map_err(parse_refusal)?;
        if !record.user_signed() {
            return Err(Refusal::BadRequest(
                "registrar-signed records come from the registrar's own tools".into(),
            ));
        }
        // A record may be signed well before it is posted — that is the
        // point of a revocation prepared in advance — but not in the
        // future.
        if record.time() > now.saturating_add(self.cfg.clock_skew) {
            return Err(Refusal::BadTime);
        }
        let d = digest(bytes);

        self.writing(|| {
            self.publish_due(now)?;
            // Posting again after a lost reply is not a failure (§6.2).
            if let Some(seq) = self.store.record_seq(&d)? {
                return Ok(Posted::Published { seq });
            }
            let identity = *record.identity();
            if let Some(p) = self.store.pending(&identity)? {
                if p.digest == d {
                    return Ok(Posted::Pending {
                        until: p.publish_at,
                    });
                }
            }
            let Some(row) = self.store.identity(&identity)? else {
                return Err(Refusal::NotRegistered);
            };
            Self::usable(&row)?;
            self.limit(
                Limit::Records(identity),
                self.cfg.rates.records_per_identity,
                now,
            )?;

            let posted = match &record {
                Record::RevokeDevice(r) => {
                    let seq = self.store.publish(&Publish {
                        records: vec![NewRecord {
                            kind: RecordKind::RevokeDevice,
                            identity,
                            other: None,
                            until: Some(r.until),
                            digest: d,
                            bytes: bytes.to_vec(),
                        }],
                        effects: vec![],
                    })?;
                    Posted::Published { seq: seq[0] }
                }
                Record::RevokeIdentity(_) => {
                    // Permanent and final (§4.5): the handles lapse now and
                    // are released after the hold, and a pending rotation has
                    // nothing left to rotate.
                    let seq = self.store.publish(&Publish {
                        records: vec![NewRecord {
                            kind: RecordKind::RevokeIdentity,
                            identity,
                            other: None,
                            until: None,
                            digest: d,
                            bytes: bytes.to_vec(),
                        }],
                        effects: vec![
                            Effect::Revoke(identity),
                            Effect::LapseHandles { identity, at: now },
                            Effect::DropPending(identity),
                        ],
                    })?;
                    Posted::Published { seq: seq[0] }
                }
                Record::Rotate(r) => self.accept_rotation(&row, r, d, bytes, now)?,
                Record::Freeze(_) | Record::RevokeAttestation(_) => unreachable!("refused above"),
            };
            self.limits
                .lock()
                .unwrap()
                .charge(Limit::Records(identity), now);
            tracing::info!(
                kind = record.kind(),
                fingerprint = %Fingerprint::of(&identity).short(),
                ?posted,
                "registrar accepted a record"
            );
            Ok(posted)
        })
    }

    /// §5.4's four conditions, then publish or hold.
    fn accept_rotation(
        &self,
        row: &IdentityRow,
        r: &Rotation,
        d: [u8; 32],
        bytes: &[u8],
        now: u64,
    ) -> Result<Posted, Refusal> {
        if self.store.pending(&r.identity)?.is_some() {
            return Err(Refusal::BadRequest(
                "a rotation for this identity is already pending".into(),
            ));
        }
        self.rotation_allowed(row, &r.successor)?;
        if self.cfg.rotation_delay > 0 {
            let until = now.saturating_add(self.cfg.rotation_delay);
            self.store.publish(&Publish {
                records: vec![],
                effects: vec![Effect::SetPending(Pending {
                    identity: r.identity,
                    successor: r.successor,
                    publish_at: until,
                    digest: d,
                    bytes: bytes.to_vec(),
                })],
            })?;
            return Ok(Posted::Pending { until });
        }
        let seq = self.publish_rotation(r.identity, r.successor, d, bytes.to_vec(), now)?;
        Ok(Posted::Published { seq })
    }

    /// Whether `row` may rotate to `successor` as things stand: the
    /// commitment, if there is one, names it, and it has not itself been
    /// revoked or rotated away. Asked when a rotation is posted, and again
    /// when a held one is published — either may have changed meanwhile.
    fn rotation_allowed(&self, row: &IdentityRow, successor: &Key) -> Result<(), Refusal> {
        if row
            .commitment
            .is_some_and(|c| c != Fingerprint::of(successor).0)
        {
            return Err(Refusal::SuccessorMismatch);
        }
        if let Some(succ) = self.store.identity(successor)? {
            if succ.revoked || succ.rotated_to.is_some() {
                return Err(Refusal::BadRequest(
                    "the successor key is revoked or rotated away".into(),
                ));
            }
        }
        Ok(())
    }

    /// Publish an accepted rotation: the record under both keys, the
    /// handles moved with their age, and the predecessor's attestations
    /// revoked (reason 2) — one transaction.
    fn publish_rotation(
        &self,
        from: Key,
        to: Key,
        d: [u8; 32],
        bytes: Vec<u8>,
        now: u64,
    ) -> Result<u64, Refusal> {
        let mut records = vec![NewRecord {
            kind: RecordKind::Rotate,
            identity: from,
            other: Some(to),
            until: None,
            digest: d,
            bytes,
        }];
        for h in self.store.handles_of(&from)? {
            records.push(self.attestation_revocation(
                from,
                &h.name,
                attestation_reason::ROTATED,
                now,
            )?);
        }
        let seqs = self.store.publish(&Publish {
            records,
            effects: vec![
                Effect::Rotate { from, to, at: now },
                Effect::DropPending(from),
            ],
        })?;
        tracing::info!(
            from = %Fingerprint::of(&from).short(),
            to = %Fingerprint::of(&to).short(),
            "registrar published a rotation"
        );
        Ok(seqs[0])
    }

    fn attestation_revocation(
        &self,
        identity: Key,
        handle: &str,
        reason: u64,
        now: u64,
    ) -> Result<NewRecord, Refusal> {
        // A reissue in the second of an earlier revocation is dated the
        // second after it (see `register`), so a revocation dated `now`
        // would leave that attestation standing. Dated one past the
        // earlier one, it voids everything `register` could have issued.
        let time = match self.revoked_through(&identity, handle)? {
            Some(t) if t >= now => t.saturating_add(1),
            _ => now,
        };
        let bytes = AttestationRevocation {
            identity,
            registrar: self.cfg.host.clone(),
            handle: handle.to_owned(),
            time,
            reason: Some(reason),
        }
        .sign(&self.key);
        let until = self
            .store
            .attestations_expire(&identity, handle, time)?
            .unwrap_or(time);
        Ok(NewRecord {
            kind: RecordKind::RevokeAttestation,
            identity,
            other: None,
            until: Some(until),
            digest: digest(&bytes),
            bytes,
        })
    }

    /// Publish every pending rotation whose delay has passed. Called with
    /// the write lock held, at the top of every write and list, so a
    /// rotation is published the first time anything looks after its
    /// time — there is no timer to miss.
    fn publish_due(&self, now: u64) -> Result<(), Refusal> {
        for p in self.store.pending_due(now)? {
            // Everything accepting it checked, checked again: the
            // successor may have revoked itself or rotated on while this
            // one waited, and handles moved to it then would be stuck.
            let refused = match self.store.identity(&p.identity)? {
                None => Some(Refusal::NotRegistered),
                Some(row) => match Self::usable(&row) {
                    Err(r) => Some(r),
                    Ok(()) => match self.rotation_allowed(&row, &p.successor) {
                        Err(Refusal::Store(e)) => return Err(Refusal::Store(e)),
                        Err(r) => Some(r),
                        Ok(()) => None,
                    },
                },
            };
            if let Some(why) = refused {
                tracing::info!(
                    from = %Fingerprint::of(&p.identity).short(),
                    to = %Fingerprint::of(&p.successor).short(),
                    %why,
                    "registrar dropped a held rotation"
                );
                self.store.publish(&Publish {
                    records: vec![],
                    effects: vec![Effect::DropPending(p.identity)],
                })?;
            } else {
                self.publish_rotation(p.identity, p.successor, p.digest, p.bytes, now)?;
            }
        }
        Ok(())
    }

    fn sign_list(
        &self,
        kind: ListKind,
        fingerprint: Option<[u8; 32]>,
        since: Option<u64>,
        page: Page,
        now: u64,
    ) -> Vec<u8> {
        SignedList {
            registrar: self.cfg.host.clone(),
            issued: now,
            expires: now.saturating_add(self.cfg.records_max_age),
            fingerprint,
            since,
            more: page.more,
            entries: page.entries,
        }
        .sign(kind, &self.key)
    }

    fn page_budget() -> usize {
        hl_identity::registrar::LIST_MAX_BYTES - SignedList::PAGE_OVERHEAD
    }

    /// The per-identity list (§6.2): every record naming the key, never
    /// pruned. An unknown fingerprint gets a signed empty list, which is
    /// the registrar saying it holds nothing against that key.
    pub fn records_for(
        &self,
        fp: &[u8; 32],
        since: Option<u64>,
        now: u64,
    ) -> Result<Vec<u8>, Refusal> {
        self.writing(|| self.publish_due(now))?;
        let page = match self.store.identity_by_fingerprint(fp)? {
            Some(row) => self.store.records_page(
                RecordFilter::Identity(row.key),
                since.unwrap_or(0),
                Self::page_budget(),
            )?,
            None => Page::default(),
        };
        Ok(self.sign_list(ListKind::Records, Some(*fp), since, page, now))
    }

    /// The full list, as a delta from `since` (§6.2).
    pub fn records_since(&self, since: Option<u64>, now: u64) -> Result<Vec<u8>, Refusal> {
        self.writing(|| self.publish_due(now))?;
        let page = self.store.records_page(
            RecordFilter::All {
                now,
                device_cap: self.cfg.rates.device_revocations_kept,
            },
            since.unwrap_or(0),
            Self::page_budget(),
        )?;
        Ok(self.sign_list(ListKind::Records, None, since, page, now))
    }

    /// The issuance log from `since` (§6.6).
    pub fn log_since(&self, since: Option<u64>, now: u64) -> Result<Vec<u8>, Refusal> {
        let page = self
            .store
            .log_page(since.unwrap_or(0), Self::page_budget())?;
        Ok(self.sign_list(ListKind::Log, None, since, page, now))
    }

    /// The signed stats (§6.6), recomputed at most hourly.
    pub fn stats(&self, now: u64) -> Result<Vec<u8>, Refusal> {
        let mut cache = self.stats.lock().unwrap();
        if let Some((at, bytes)) = cache.as_ref() {
            if now < at + 3600 {
                return Ok(bytes.clone());
            }
        }
        let c = self.store.counts(now)?;
        let bytes = Stats {
            registrar: self.cfg.host.clone(),
            at: now,
            identities: c.identities,
            issued_24h: c.issued_24h,
            issued_7d: c.issued_7d,
            issued_total: c.issued_total,
            revoked_total: c.revoked_total,
            frozen: c.frozen,
            log_seq: c.log_seq,
        }
        .sign(&self.key);
        *cache = Some((now, bytes.clone()));
        Ok(bytes)
    }

    // --- §6.3 lookup -------------------------------------------------------

    fn lookup_limit(&self, addr: IpAddr, now: u64) -> Result<(), Refusal> {
        self.limits
            .lock()
            .unwrap()
            .take(
                Limit::LookupFrom(address_key(addr)),
                self.cfg.rates.lookups_per_address,
                now,
            )
            .map_err(|retry_after| Refusal::RateLimited { retry_after })
    }

    /// A held handle's holder. `None` for free, lapsed, reserved and
    /// unknown alike, so a lookup says no more than a registration
    /// attempt would.
    pub fn lookup_handle(
        &self,
        handle: &str,
        addr: IpAddr,
        now: u64,
    ) -> Result<Option<Found>, Refusal> {
        self.lookup_limit(addr, now)?;
        // Stored in canonical lowercase (§5.1): `Alice` asks after `alice`.
        Ok(self
            .store
            .handle(&handle.to_ascii_lowercase())?
            .filter(|h| h.state(now, self.hold()) == HandleState::Held)
            .map(|h| Found {
                identity: h.identity,
                registered: h.registered,
                expires: h.expires,
            }))
    }

    /// The handles this registrar attests to that key, held ones only.
    pub fn lookup_identity(
        &self,
        fp: &[u8; 32],
        addr: IpAddr,
        now: u64,
    ) -> Result<Vec<String>, Refusal> {
        self.lookup_limit(addr, now)?;
        let Some(row) = self.store.identity_by_fingerprint(fp)? else {
            return Ok(Vec::new());
        };
        Ok(self
            .store
            .handles_of(&row.key)?
            .into_iter()
            .filter(|h| h.state(now, self.hold()) == HandleState::Held)
            .map(|h| h.name)
            .collect())
    }

    // --- §6.4 cards ----------------------------------------------------------

    /// A card for an identity attested here must carry the commitment the
    /// registrar holds (§5.4). Called before the card is accepted.
    pub fn check_card(&self, card: &Card) -> Result<(), Refusal> {
        match self.store.identity(&card.identity)? {
            Some(row) if row.commitment.is_some() && card.successor != row.commitment => {
                Err(Refusal::SuccessorMismatch)
            }
            _ => Ok(()),
        }
    }

    /// Record an accepted card's commitment, for an identity attested
    /// here that has none yet.
    pub fn note_card(&self, card: &Card) -> Result<(), Refusal> {
        let Some(c) = card.successor else {
            return Ok(());
        };
        self.writing(|| {
            if self.store.set_commitment(&card.identity, &c)? {
                tracing::info!(
                    fingerprint = %Fingerprint::of(&card.identity).short(),
                    "registrar recorded a successor commitment from a card"
                );
            }
            Ok(())
        })
    }

    // --- §8 operator actions -------------------------------------------------

    /// Freeze or lift (§4.7, §8.1). A freeze cancels a pending rotation.
    /// Returns the record's seq.
    pub fn freeze(&self, fp: &[u8; 32], frozen: bool, now: u64) -> Result<u64, OpError> {
        self.writing(|| {
            self.publish_due(now)?;
            let row = self
                .store
                .identity_by_fingerprint(fp)?
                .ok_or(OpError::UnknownIdentity)?;
            // The latest `time` wins at every reader, so a freeze and its
            // lift in one second would leave them guessing. Every freeze
            // record for an identity gets a later time than the one before.
            let mut time = now;
            let held = self
                .store
                .records_page(RecordFilter::Identity(row.key), 0, usize::MAX)?;
            let keys = self.keys();
            for (_, b) in held.entries {
                if let Ok(Record::Freeze(f)) = Record::parse(
                    &b,
                    Some(RegistrarKeys {
                        host: &self.cfg.host,
                        keys: &keys,
                    }),
                ) {
                    time = time.max(f.time + 1);
                }
            }
            let bytes = Freeze {
                identity: row.key,
                registrar: self.cfg.host.clone(),
                frozen,
                time,
            }
            .sign(&self.key);
            let mut effects = vec![Effect::SetFrozen(row.key, frozen)];
            if frozen {
                effects.push(Effect::DropPending(row.key));
            }
            let seq = self.store.publish(&Publish {
                records: vec![NewRecord {
                    kind: RecordKind::Freeze,
                    identity: row.key,
                    other: None,
                    until: None,
                    digest: digest(&bytes),
                    bytes,
                }],
                effects,
            })?;
            Ok(seq[0])
        })
    }

    /// Withdraw the registrar's word for a handle (§4.8): the holder's
    /// attestations for it are void, the handle lapses, and with `bar`
    /// the holder may not reissue it — which is what `abuse` means.
    pub fn revoke_handle(
        &self,
        handle: &str,
        reason: u64,
        bar: bool,
        now: u64,
    ) -> Result<u64, OpError> {
        let handle = handle.to_ascii_lowercase();
        let handle = handle.as_str();
        self.writing(|| {
            self.publish_due(now)?;
            let h = self.store.handle(handle)?.ok_or(OpError::UnknownHandle)?;
            let record = self.attestation_revocation(h.identity, handle, reason, now)?;
            let seq = self.store.publish(&Publish {
                records: vec![record],
                effects: vec![Effect::LapseHandle {
                    name: handle.to_owned(),
                    at: now,
                    barred: bar,
                }],
            })?;
            Ok(seq[0])
        })
    }

    /// Recovery (§8.3): void the old key's attestations for the handle
    /// (reason 1) and grant its next registration to `new_fp` as a
    /// reissue, with or without its age. The old key is barred from it.
    pub fn recover(
        &self,
        handle: &str,
        new_fp: &[u8; 32],
        keep_age: bool,
        now: u64,
    ) -> Result<u64, OpError> {
        let handle = handle.to_ascii_lowercase();
        let handle = handle.as_str();
        self.writing(|| {
            self.publish_due(now)?;
            let h = self.store.handle(handle)?.ok_or(OpError::UnknownHandle)?;
            if &Fingerprint::of(&h.identity).0 == new_fp {
                return Err(OpError::SameIdentity);
            }
            let record = self.attestation_revocation(
                h.identity,
                handle,
                attestation_reason::RECOVERED,
                now,
            )?;
            let seq = self.store.publish(&Publish {
                records: vec![record],
                effects: vec![
                    Effect::LapseHandle {
                        name: handle.to_owned(),
                        at: now,
                        barred: true,
                    },
                    Effect::GrantRecovery(Recovery {
                        handle: handle.to_owned(),
                        fingerprint: *new_fp,
                        keep_age,
                        granted: now,
                    }),
                ],
            })?;
            Ok(seq[0])
        })
    }

    /// Add invite codes. Returns how many were new.
    pub fn add_invites(&self, codes: &[String]) -> Result<usize, OpError> {
        let hashes: Vec<[u8; 32]> = codes.iter().map(|c| invite_hash(c)).collect();
        // Under the write lock like every other write, so it never lands
        // inside, and is never rolled back with, another's transaction.
        self.writing(|| Ok(self.store.add_invites(&hashes)?))
    }
}

/// Why an operator action failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    UnknownIdentity,
    UnknownHandle,
    SameIdentity,
    Store(StoreError),
}

impl fmt::Display for OpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpError::UnknownIdentity => {
                write!(f, "this registrar has never attested that identity")
            }
            OpError::UnknownHandle => write!(f, "this registrar has never issued that handle"),
            OpError::SameIdentity => write!(f, "that identity already holds the handle"),
            OpError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpError {}

impl From<StoreError> for OpError {
    fn from(e: StoreError) -> Self {
        OpError::Store(e)
    }
}

impl From<Refusal> for OpError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Store(e) => OpError::Store(e),
            other => OpError::Store(StoreError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests;
