//! The enrollment mailbox (`docs/identity-enrollment.md` §5).
//!
//! It routes requests to sessions and answers to requests, for a few
//! minutes, in memory, and that is the whole of it. It never reads what
//! it carries beyond the fields it routes on, holds no keys, and makes
//! no decisions. What it is trusted with is availability (§9): a hostile
//! mailbox can drop or delay anything, and everything else it might try
//! is caught by the holder's prompt or by the enrollee's own checks.
//!
//! That is also why this file knows nothing about the rest of the
//! server. It reads no account, consults no card cache, and takes no
//! `IdentityState` — so a registrar binary can mount it beside nothing
//! at all. (The spec asks for a trait here; a struct with no
//! dependencies gets a registrar the same thing with less ceremony, and
//! a trait can be extracted the day there are two implementations.)
//!
//! Every table an unauthenticated caller can grow has a ceiling: open
//! sessions server-wide and per address, pending requests per session,
//! and the encoded size of a request. Nothing here is persisted — a
//! restart loses sessions and the holder opens another.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hl_identity::Fingerprint;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

/// Protocol constants, not settings (§10): an enrollee and a holder on
/// different servers should see the same clock.
pub const SESSION_TTL: Duration = Duration::from_secs(600);
pub const REQUEST_TTL: Duration = Duration::from_secs(300);
pub const LONG_POLL: Duration = Duration::from_secs(30);

/// Pending requests per session (§11). A holder enrolling one device
/// needs one; the rest is room for a retry and a mistake.
const MAX_PENDING: usize = 8;

/// The encoded request, before base64 (§4).
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Crockford base32 minus nothing — it already excludes `I`, `L`, `O`
/// and `U`. Eight characters is about forty bits, which is what a
/// single-use, ten-minute, rate-limited code needs and no more (§9).
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_CHARS: usize = 8;

#[derive(Debug, Clone)]
pub struct MailboxConfig {
    /// Open sessions at once, server-wide.
    pub max_sessions: usize,
    /// Open sessions and pending requests per source address.
    pub per_address: usize,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        MailboxConfig {
            max_sessions: 256,
            per_address: 4,
        }
    }
}

/// What a holder is told when it opens a session.
///
/// No `Debug`, here or on [`Posted`]: both carry a secret, and the
/// storage discipline these share with every other token in the ng
/// listener is CSPRNG, stored hashed, never logged. A derived `Debug` is
/// how "never logged" stops being true.
pub struct Opened {
    pub session: String,
    pub code: String,
    pub expires_in: u64,
}

/// What an enrollee is told when its request is accepted.
pub struct Posted {
    pub request: String,
    pub expires_in: u64,
}

/// A request waiting for the holder to look at it (§5.3).
pub struct PendingView {
    pub id: String,
    pub request: Vec<u8>,
    pub received: u64,
}

/// What `GET <enroll>/requests/<secret>` found (§5.5).
pub enum Fetched {
    /// Approved; the request is consumed.
    Bundle(Vec<u8>),
    /// The holder said no; the request is consumed.
    Denied(String),
    /// Still waiting at the long-poll deadline.
    Pending { expires_in: u64 },
    /// Expired, or already fetched. Deliberately the same answer for
    /// both: a caller that fetched an answer has no business asking
    /// again, and telling it which of the two happened would let anyone
    /// holding a stale secret learn whether it was ever used.
    Gone,
}

/// Why a call was refused. The wire codes and statuses of §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    UnknownCode,
    NoHolder,
    RequestTooLarge,
    BadRequest,
    TooManySessions,
    RateLimited,
    UnknownSession,
    UnknownRequest,
}

impl Refused {
    pub fn code(self) -> &'static str {
        match self {
            Refused::UnknownCode => "unknown_code",
            Refused::NoHolder => "no_holder",
            Refused::RequestTooLarge => "request_too_large",
            Refused::BadRequest => "bad_request",
            Refused::TooManySessions => "too_many_sessions",
            Refused::RateLimited => "rate_limited",
            Refused::UnknownSession | Refused::UnknownRequest => "not_found",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Refused::UnknownCode
            | Refused::NoHolder
            | Refused::UnknownSession
            | Refused::UnknownRequest => 404,
            Refused::RequestTooLarge | Refused::BadRequest => 400,
            Refused::RateLimited => 429,
            Refused::TooManySessions => 503,
        }
    }

    pub fn text(self) -> &'static str {
        match self {
            // A wrong code is a 404 and not a hint (§5.2).
            Refused::UnknownCode => "no open session has that code",
            Refused::NoHolder => "no standing session for that identity",
            Refused::RequestTooLarge => "the enrollment request exceeds 8 KiB",
            Refused::BadRequest => "malformed enrollment request",
            Refused::TooManySessions => "too many open enrollment sessions; retry shortly",
            Refused::RateLimited => "too many enrollment sessions from this address",
            Refused::UnknownSession => "no such enrollment session",
            Refused::UnknownRequest => "no such enrollment request",
        }
    }
}

struct Pending {
    id: String,
    addr: IpAddr,
    request: Vec<u8>,
    received: u64,
    expires: Instant,
    answer: Option<Answer>,
    /// Woken when the answer arrives.
    notify: Arc<Notify>,
}

#[derive(Clone)]
enum Answer {
    Bundle(Vec<u8>),
    Denied(String),
}

struct Session {
    /// `None` once the code has admitted its one request (§5.1).
    code: Option<String>,
    addr: IpAddr,
    expires: Instant,
    /// Keyed by the SHA-256 of the request secret, as everything else
    /// here is.
    pending: HashMap<[u8; 32], Pending>,
    next_id: u64,
    /// Woken when a request arrives.
    notify: Arc<Notify>,
}

#[derive(Default)]
struct Inner {
    /// Keyed by the SHA-256 of the session secret.
    sessions: HashMap<[u8; 32], Session>,
    /// Live codes, normalized, to the session that owns them.
    by_code: HashMap<String, [u8; 32]>,
    /// Standing identities to the session that offered to hold them.
    by_identity: HashMap<Fingerprint, [u8; 32]>,
    /// Request secret hash to the session holding it, so that
    /// `GET /requests/<secret>` is one lookup rather than a scan.
    by_request: HashMap<[u8; 32], [u8; 32]>,
}

pub struct Mailbox {
    cfg: MailboxConfig,
    inner: Mutex<Inner>,
}

impl Mailbox {
    pub fn new(cfg: MailboxConfig) -> Mailbox {
        Mailbox {
            cfg,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// §5.1. Unauthenticated on purpose: the mailbox has nothing to
    /// protect with a proof of key possession, since a session opened by
    /// someone with no identity key can answer nothing an enrollee would
    /// accept.
    pub fn open_session(
        &self,
        addr: IpAddr,
        identity: Option<Fingerprint>,
    ) -> Result<Opened, Refused> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(now);

        if inner.sessions.len() >= self.cfg.max_sessions {
            return Err(Refused::TooManySessions);
        }
        if inner.sessions.values().filter(|s| s.addr == addr).count() >= self.cfg.per_address {
            return Err(Refused::RateLimited);
        }

        // Drawn until it is unused rather than assumed unique: forty bits
        // is plenty against guessing and says nothing about collisions
        // among a few hundred live codes.
        //
        // Compared in the normalized form, which is what `by_code` is
        // keyed by. Checking the display form — which carries the
        // hyphen — could never match anything, so this loop ran exactly
        // once and a collision would have overwritten the index and
        // misrouted the earlier session's requests.
        let code = loop {
            let c = draw_code();
            if !inner.by_code.contains_key(&normalize_code(&c)) {
                break c;
            }
        };
        let secret = random32();
        let key = hash(secret.as_bytes());

        inner.by_code.insert(normalize_code(&code), key);
        // Last writer wins: a holder that restarts its agent should take
        // over its own identity's renewals rather than be shut out by
        // the session it just abandoned.
        if let Some(fp) = identity {
            inner.by_identity.insert(fp, key);
        }
        inner.sessions.insert(
            key,
            Session {
                code: Some(normalize_code(&code)),
                addr,
                expires: now + SESSION_TTL,
                pending: HashMap::new(),
                next_id: 1,
                notify: Arc::new(Notify::new()),
            },
        );
        Ok(Opened {
            session: secret,
            code,
            expires_in: SESSION_TTL.as_secs(),
        })
    }

    /// §5.2. `code` routes to the session that owns it; without one, the
    /// request must carry a `prev` naming an identity some session is
    /// standing by for.
    ///
    /// The request is not verified here, and deliberately not: that is
    /// the holder's job, and doing it here would make this parser an
    /// unauthenticated attack surface for no benefit.
    pub fn post_request(
        &self,
        addr: IpAddr,
        code: Option<&str>,
        request: &[u8],
    ) -> Result<Posted, Refused> {
        if request.len() > MAX_REQUEST_BYTES {
            return Err(Refused::RequestTooLarge);
        }
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(now);

        // Per address across the whole mailbox, not per session: §10's
        // limit is on what one caller can make the server hold, and a
        // caller who can reach several sessions should not get several
        // times the allowance.
        let mine = inner
            .sessions
            .values()
            .flat_map(|s| s.pending.values())
            .filter(|p| p.addr == addr)
            .count();
        if mine >= self.cfg.per_address {
            return Err(Refused::RateLimited);
        }

        // Resolve the route without spending anything yet. A code is
        // single-use, so a request refused *after* it was taken out of
        // the index would burn the user's code on somebody else's rate
        // limit and leave them re-reading a terminal for a code that no
        // longer works.
        let normalized;
        let key = match code {
            Some(c) => {
                normalized = normalize_code(c);
                *inner.by_code.get(&normalized).ok_or(Refused::UnknownCode)?
            }
            None => {
                // Routing by renewal: read `prev`'s identity out of the
                // request without a general parse (§11), and find the
                // session standing by for it.
                normalized = String::new();
                let fp = prev_identity(request).ok_or(Refused::BadRequest)?;
                *inner.by_identity.get(&fp).ok_or(Refused::NoHolder)?
            }
        };

        if inner
            .sessions
            .get(&key)
            .is_none_or(|s| s.pending.len() >= MAX_PENDING)
        {
            return Err(Refused::RateLimited);
        }

        // Accepted, so now the code is spent: it admits one request and
        // is dead after that (§5.1).
        if !normalized.is_empty() {
            inner.by_code.remove(&normalized);
            if let Some(s) = inner.sessions.get_mut(&key) {
                s.code = None;
            }
        }
        let session = inner.sessions.get_mut(&key).expect("checked just above");

        let secret = random32();
        let rkey = hash(secret.as_bytes());
        let id = format!("r{}", session.next_id);
        session.next_id += 1;
        session.pending.insert(
            rkey,
            Pending {
                id,
                addr,
                request: request.to_vec(),
                received: unix_now(),
                expires: now + REQUEST_TTL,
                answer: None,
                notify: Arc::new(Notify::new()),
            },
        );
        let notify = session.notify.clone();
        inner.by_request.insert(rkey, key);
        drop(inner);

        // Wake the holder's long poll, if one is parked.
        notify.notify_waiters();
        Ok(Posted {
            request: secret,
            expires_in: REQUEST_TTL.as_secs(),
        })
    }

    /// §5.3, long-polled: answer as soon as there is something, or with
    /// an empty list at the deadline.
    /// `wait` is [`LONG_POLL`] in production; it is a parameter so that a
    /// test can exercise the deadline without spending thirty seconds on
    /// it, which is the only thing that would otherwise stop the
    /// timed-out branch from being tested at all.
    pub async fn poll_session(
        &self,
        secret: &str,
        wait: Duration,
    ) -> Result<(Vec<PendingView>, u64), Refused> {
        let key = hash(secret.as_bytes());
        let deadline = Instant::now() + wait;
        loop {
            let notify = {
                let mut inner = self.inner.lock().unwrap();
                inner.sweep(Instant::now());
                let session = inner.sessions.get(&key).ok_or(Refused::UnknownSession)?;
                let expires_in = remaining(session.expires);
                let waiting: Vec<PendingView> = session
                    .pending
                    .values()
                    .filter(|p| p.answer.is_none())
                    .map(|p| PendingView {
                        id: p.id.clone(),
                        request: p.request.clone(),
                        received: p.received,
                    })
                    .collect();
                if !waiting.is_empty() {
                    return Ok((waiting, expires_in));
                }
                if Instant::now() >= deadline {
                    return Ok((Vec::new(), expires_in));
                }
                session.notify.clone()
            };
            // Timing out here rather than sleeping to the deadline in one
            // go so that a session which expires mid-poll is noticed.
            let _ = tokio::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                notify.notified(),
            )
            .await;
        }
    }

    /// §5.4. Only the session secret can answer; the code cannot. The
    /// asymmetry is the point — a code is shown on a screen and typed on
    /// another, and the session secret never leaves the holder.
    pub fn answer(&self, secret: &str, id: &str, answer: Answered) -> Result<(), Refused> {
        let key = hash(secret.as_bytes());
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(Instant::now());
        let session = inner
            .sessions
            .get_mut(&key)
            .ok_or(Refused::UnknownSession)?;
        let pending = session
            .pending
            .values_mut()
            .find(|p| p.id == id && p.answer.is_none())
            .ok_or(Refused::UnknownRequest)?;
        pending.answer = Some(match answer {
            Answered::Bundle(b) => Answer::Bundle(b),
            Answered::Denied(r) => Answer::Denied(r),
        });
        let notify = pending.notify.clone();
        drop(inner);
        notify.notify_waiters();
        Ok(())
    }

    /// §5.5, long-polled. An approved or denied answer consumes the
    /// request.
    pub async fn fetch_answer(&self, secret: &str, wait: Duration) -> Fetched {
        let key = hash(secret.as_bytes());
        let deadline = Instant::now() + wait;
        loop {
            let notify = {
                let mut inner = self.inner.lock().unwrap();
                inner.sweep(Instant::now());
                let Some(&skey) = inner.by_request.get(&key) else {
                    return Fetched::Gone;
                };
                let Some(session) = inner.sessions.get_mut(&skey) else {
                    return Fetched::Gone;
                };
                let Some(pending) = session.pending.get_mut(&key) else {
                    return Fetched::Gone;
                };
                match pending.answer.take() {
                    Some(a) => {
                        session.pending.remove(&key);
                        inner.by_request.remove(&key);
                        return match a {
                            Answer::Bundle(b) => Fetched::Bundle(b),
                            Answer::Denied(r) => Fetched::Denied(r),
                        };
                    }
                    None if Instant::now() >= deadline => {
                        return Fetched::Pending {
                            expires_in: remaining(pending.expires),
                        }
                    }
                    None => pending.notify.clone(),
                }
            };
            let _ = tokio::time::timeout(
                deadline.saturating_duration_since(Instant::now()),
                notify.notified(),
            )
            .await;
        }
    }

    /// Drop what has expired. Called on every request as well, so this
    /// is belt and braces for a mailbox nobody is using.
    pub fn sweep(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(Instant::now())
    }

    #[cfg(test)]
    fn session_count(&self) -> usize {
        self.inner.lock().unwrap().sessions.len()
    }
}

/// What a holder is saying about a request (§5.4).
pub enum Answered {
    Bundle(Vec<u8>),
    Denied(String),
}

impl Inner {
    fn sweep(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        self.sessions.retain(|_, s| {
            if s.expires <= now {
                dropped += 1;
                return false;
            }
            s.pending.retain(|_, p| p.expires > now);
            true
        });
        let live: std::collections::HashSet<[u8; 32]> = self.sessions.keys().copied().collect();
        self.by_code
            .retain(|_, k| self.sessions.get(k).is_some_and(|s| s.code.is_some()));
        self.by_identity.retain(|_, k| live.contains(k));
        self.by_request.retain(|rk, sk| {
            self.sessions
                .get(sk)
                .is_some_and(|s| s.pending.contains_key(rk))
        });
        dropped
    }
}

/// Read `prev.identity` out of an encoded request and fingerprint it,
/// without a general parse (§11): decode the request, take `prev`,
/// decode that, take `identity`. A fixed-depth walk over two maps.
///
/// Returns `None` for anything that isn't shaped like that, including a
/// request with no `prev` — which is a first enrollment, and a first
/// enrollment needs a code.
fn prev_identity(request: &[u8]) -> Option<Fingerprint> {
    use hl_identity::cbor::{decode_canonical, Value};
    let prev = match decode_canonical(request).ok()?.get("prev")? {
        Value::Bytes(b) => b.clone(),
        _ => return None,
    };
    match decode_canonical(&prev).ok()?.get("identity")? {
        Value::Bytes(b) => {
            let key: [u8; 32] = b.as_slice().try_into().ok()?;
            Some(Fingerprint::of(&key))
        }
        _ => None,
    }
}

/// Normalized for lookup: a code is read off one screen and typed into
/// another, so case, the display hyphen, and Crockford's confusables all
/// have to survive the trip.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            'U' => 'V',
            c => c,
        })
        .collect()
}

/// Eight characters, displayed with a hyphen after four.
fn draw_code() -> String {
    let bytes = {
        let mut b = [0u8; CODE_CHARS];
        getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
        b
    };
    let mut s = String::with_capacity(CODE_CHARS + 1);
    for (i, b) in bytes.iter().enumerate() {
        if i == CODE_CHARS / 2 {
            s.push('-');
        }
        s.push(ALPHABET[(*b & 31) as usize] as char);
    }
    s
}

fn random32() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn hash(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

fn remaining(deadline: Instant) -> u64 {
    deadline.saturating_duration_since(Instant::now()).as_secs()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::{DeviceCert, DeviceKey, EnrollRequest, IdentityKey};

    const QUICK: Duration = Duration::from_millis(50);

    fn addr(n: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, n])
    }

    fn mailbox() -> Mailbox {
        Mailbox::new(MailboxConfig::default())
    }

    /// A first-enrollment request: signed, and with no `prev`, so it can
    /// only be routed by a code.
    fn request(seed: u8) -> Vec<u8> {
        let d = DeviceKey::from_seed(&[seed; 32]);
        EnrollRequest::new(&d, unix_now()).sign(&d)
    }

    /// A renewal for `identity`, which routes without a code.
    fn renewal(seed: u8, identity: &IdentityKey) -> Vec<u8> {
        let d = DeviceKey::from_seed(&[seed; 32]);
        let prev = DeviceCert::for_device(identity, &d, unix_now(), 86_400)
            .unwrap()
            .sign(identity);
        let mut r = EnrollRequest::new(&d, unix_now());
        r.prev = Some(prev);
        r.sign(&d)
    }

    #[tokio::test]
    async fn a_request_reaches_the_holder_and_the_answer_reaches_the_device() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();

        let (pending, _) = m.poll_session(&opened.session, QUICK).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request, request(2));

        m.answer(
            &opened.session,
            &pending[0].id,
            Answered::Bundle(b"the bundle".to_vec()),
        )
        .unwrap();

        match m.fetch_answer(&posted.request, QUICK).await {
            Fetched::Bundle(b) => assert_eq!(b, b"the bundle"),
            _ => panic!("expected the bundle"),
        }
        // Consumed: an answer is fetched once, and a second ask cannot
        // tell "already fetched" from "never existed" (§5.5).
        assert!(matches!(
            m.fetch_answer(&posted.request, QUICK).await,
            Fetched::Gone
        ));
    }

    #[tokio::test]
    async fn a_denial_reaches_the_device_too() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let (pending, _) = m.poll_session(&opened.session, QUICK).await.unwrap();
        m.answer(
            &opened.session,
            &pending[0].id,
            Answered::Denied("not_mine".into()),
        )
        .unwrap();
        match m.fetch_answer(&posted.request, QUICK).await {
            Fetched::Denied(r) => assert_eq!(r, "not_mine"),
            _ => panic!("expected a denial"),
        }
    }

    #[test]
    fn a_drawn_code_is_looked_up_in_the_form_the_index_uses() {
        // The bug this guards: `by_code` is keyed by the normalized
        // code, and the collision check compared the display form. A
        // hyphen made the two always different, so the check never matched and
        // a collision would have silently rebound a live code to a new
        // session.
        let drawn = draw_code();
        assert!(drawn.contains('-'), "the display form carries a hyphen");
        assert!(!normalize_code(&drawn).contains('-'));
        assert_ne!(
            drawn,
            normalize_code(&drawn),
            "if these were ever equal the collision check would be untested"
        );
    }

    #[tokio::test]
    async fn a_code_admits_one_request_and_is_then_dead() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        // A holder meaning to enroll two devices opens two sessions
        // (§5.1); the same code twice is the case this refuses.
        assert_eq!(
            m.post_request(addr(2), Some(&opened.code), &request(3))
                .err(),
            Some(Refused::UnknownCode)
        );
    }

    #[tokio::test]
    async fn a_wrong_code_is_a_404_and_not_a_hint() {
        let m = mailbox();
        m.open_session(addr(1), None).unwrap();
        assert_eq!(
            m.post_request(addr(2), Some("AAAA-AAAA"), &request(2))
                .err(),
            Some(Refused::UnknownCode)
        );
    }

    #[tokio::test]
    async fn a_code_survives_being_read_off_a_screen_and_typed_back() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        // Lower case, no hyphen, and Crockford's confusables: whoever
        // typed `l` for `1` or `O` for `0` should not be told their code
        // is wrong.
        let typed = opened.code.to_lowercase().replace('-', "");
        let typed = typed.replace('1', "l").replace('0', "o");
        assert!(m.post_request(addr(2), Some(&typed), &request(2)).is_ok());
    }

    #[tokio::test]
    async fn a_renewal_routes_by_identity_with_no_code_at_all() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let opened = m.open_session(addr(1), Some(id.fingerprint())).unwrap();

        let posted = m.post_request(addr(2), None, &renewal(2, &id)).unwrap();
        let (pending, _) = m.poll_session(&opened.session, QUICK).await.unwrap();
        assert_eq!(pending.len(), 1, "the standing session saw it");

        m.answer(&opened.session, &pending[0].id, Answered::Bundle(vec![7]))
            .unwrap();
        assert!(matches!(
            m.fetch_answer(&posted.request, QUICK).await,
            Fetched::Bundle(_)
        ));
    }

    #[tokio::test]
    async fn a_renewal_with_nobody_standing_by_is_no_holder() {
        let m = mailbox();
        let stranger = IdentityKey::from_seed(&[9u8; 32]);
        // A session with no identity does not collect renewals, even
        // though it is open and has a live code.
        m.open_session(addr(1), None).unwrap();
        assert_eq!(
            m.post_request(addr(2), None, &renewal(2, &stranger)).err(),
            Some(Refused::NoHolder)
        );
    }

    #[tokio::test]
    async fn a_first_enrollment_cannot_route_itself() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        m.open_session(addr(1), Some(id.fingerprint())).unwrap();
        // No code and no `prev`: there is nothing to route on, and
        // guessing is not one of the options.
        assert_eq!(
            m.post_request(addr(2), None, &request(2)).err(),
            Some(Refused::BadRequest)
        );
    }

    #[tokio::test]
    async fn only_the_session_secret_can_answer() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let (pending, _) = m.poll_session(&opened.session, QUICK).await.unwrap();

        // The code is shown on a screen and typed into another machine;
        // the session secret never leaves the holder's process. Only one
        // of them may say yes (§5.4).
        assert_eq!(
            m.answer(&opened.code, &pending[0].id, Answered::Bundle(vec![1]))
                .err(),
            Some(Refused::UnknownSession)
        );
        assert!(m
            .answer(&opened.session, &pending[0].id, Answered::Bundle(vec![1]))
            .is_ok());
    }

    #[tokio::test]
    async fn answering_the_same_request_twice_is_refused() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let (pending, _) = m.poll_session(&opened.session, QUICK).await.unwrap();
        let id = pending[0].id.clone();
        assert!(m
            .answer(&opened.session, &id, Answered::Bundle(vec![1]))
            .is_ok());
        assert_eq!(
            m.answer(&opened.session, &id, Answered::Bundle(vec![2]))
                .err(),
            Some(Refused::UnknownRequest)
        );
    }

    #[tokio::test]
    async fn the_holder_is_woken_by_a_request_rather_than_waiting_out_the_poll() {
        let m = Arc::new(mailbox());
        let opened = m.open_session(addr(1), None).unwrap();
        let code = opened.code.clone();

        let poller = {
            let m = m.clone();
            let session = opened.session.clone();
            // A deadline far longer than the test should take: if the
            // notify does not fire, this is a timeout rather than a pass.
            tokio::spawn(async move { m.poll_session(&session, Duration::from_secs(10)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        m.post_request(addr(2), Some(&code), &request(2)).unwrap();

        let (pending, _) = tokio::time::timeout(Duration::from_secs(2), poller)
            .await
            .expect("the poll should have been woken, not timed out")
            .unwrap()
            .unwrap();
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn a_poll_with_nothing_waiting_comes_back_empty_at_the_deadline() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        let (pending, expires_in) = m.poll_session(&opened.session, QUICK).await.unwrap();
        assert!(pending.is_empty());
        assert!(expires_in > 0, "the session is still open");
    }

    #[tokio::test]
    async fn a_request_nobody_has_answered_is_still_pending_at_the_deadline() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        assert!(matches!(
            m.fetch_answer(&posted.request, QUICK).await,
            Fetched::Pending { .. }
        ));
    }

    #[tokio::test]
    async fn an_oversized_request_is_refused_before_anything_looks_at_it() {
        let m = mailbox();
        let opened = m.open_session(addr(1), None).unwrap();
        assert_eq!(
            m.post_request(
                addr(2),
                Some(&opened.code),
                &vec![0u8; MAX_REQUEST_BYTES + 1]
            )
            .err(),
            Some(Refused::RequestTooLarge)
        );
        // And the code is untouched, since nothing was admitted.
        assert!(m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .is_ok());
    }

    #[tokio::test]
    async fn open_sessions_are_bounded_server_wide_and_per_address() {
        let m = Mailbox::new(MailboxConfig {
            max_sessions: 3,
            per_address: 2,
        });
        assert!(m.open_session(addr(1), None).is_ok());
        assert!(m.open_session(addr(1), None).is_ok());
        // Third from the same address: the per-address limit bites first.
        assert_eq!(
            m.open_session(addr(1), None).err(),
            Some(Refused::RateLimited)
        );

        assert!(m.open_session(addr(2), None).is_ok());
        // Server-wide ceiling, reached from a fresh address.
        assert_eq!(
            m.open_session(addr(3), None).err(),
            Some(Refused::TooManySessions)
        );
        assert_eq!(m.session_count(), 3);
    }

    #[tokio::test]
    async fn pending_requests_are_bounded_per_address_across_sessions() {
        let m = Mailbox::new(MailboxConfig {
            max_sessions: 16,
            per_address: 2,
        });
        // One caller, several sessions: the allowance is theirs, not
        // each session's, so reaching more sessions buys nothing.
        let codes: Vec<String> = (0..3)
            .map(|i| m.open_session(addr(10 + i), None).unwrap().code)
            .collect();
        assert!(m
            .post_request(addr(2), Some(&codes[0]), &request(2))
            .is_ok());
        assert!(m
            .post_request(addr(2), Some(&codes[1]), &request(3))
            .is_ok());
        assert_eq!(
            m.post_request(addr(2), Some(&codes[2]), &request(4)).err(),
            Some(Refused::RateLimited)
        );
        // Somebody else is unaffected.
        assert!(m
            .post_request(addr(3), Some(&codes[2]), &request(5))
            .is_ok());
    }

    #[tokio::test]
    async fn a_refused_request_does_not_spend_the_code() {
        let m = Mailbox::new(MailboxConfig {
            max_sessions: 16,
            per_address: 1,
        });
        let opened = m.open_session(addr(1), None).unwrap();

        // Somebody else uses up their own allowance elsewhere, and then
        // this address is refused. The user's code must survive that:
        // burning it would send them back to a terminal for a code that
        // no longer works, for a reason that was never about them.
        let other = m.open_session(addr(9), None).unwrap();
        assert!(m
            .post_request(addr(2), Some(&other.code), &request(9))
            .is_ok());
        assert_eq!(
            m.post_request(addr(2), Some(&opened.code), &request(2))
                .err(),
            Some(Refused::RateLimited)
        );
        assert!(
            m.post_request(addr(3), Some(&opened.code), &request(2))
                .is_ok(),
            "the code still works for whoever the limit was not about"
        );
    }

    #[test]
    fn a_code_is_eight_characters_of_the_confusable_free_alphabet() {
        for _ in 0..64 {
            let c = draw_code();
            assert_eq!(c.len(), CODE_CHARS + 1, "{c}");
            assert_eq!(c.as_bytes()[CODE_CHARS / 2], b'-', "{c}");
            for ch in c.bytes().filter(|b| *b != b'-') {
                assert!(ALPHABET.contains(&ch), "{c} has {}", ch as char);
                assert!(!b"ILOU".contains(&ch), "{c} has a confusable");
            }
        }
    }

    #[test]
    fn normalizing_is_what_makes_a_typed_code_forgiving() {
        assert_eq!(normalize_code("k7pm-4xwe"), "K7PM4XWE");
        assert_eq!(normalize_code("K7PM 4XWE"), "K7PM4XWE");
        // Crockford's substitutions, so a human transcription error in
        // the four ambiguous glyphs is not a wrong code.
        assert_eq!(normalize_code("ILOU0000"), "11 0V0000".replace(' ', ""));
    }

    #[test]
    fn expiry_drops_a_session_and_everything_indexed_on_it() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let opened = m.open_session(addr(1), Some(id.fingerprint())).unwrap();
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();

        {
            let mut inner = m.inner.lock().unwrap();
            let key = hash(opened.session.as_bytes());
            inner.sessions.get_mut(&key).unwrap().expires = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(m.sweep(), 1);

        let inner = m.inner.lock().unwrap();
        assert!(inner.sessions.is_empty());
        assert!(inner.by_code.is_empty(), "the code went with it");
        assert!(inner.by_identity.is_empty(), "so did the standing identity");
        assert!(
            inner.by_request.is_empty(),
            "and so did its pending request"
        );
    }
}
