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

use hl_identity::{Fingerprint, SessionClaim};
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

/// Wrong codes one address may offer inside [`GUESS_WINDOW`] before it is
/// refused outright.
///
/// §5.2 and §9 both rest on this — "guesses are rate-limited per address,
/// which is what forty bits needs" — and until it was here, nothing
/// counted them: a wrong code is refused before any table is touched, so
/// an address could try as fast as it could open sockets. Ten a minute is
/// far more than a human retyping off a screen needs, and it holds a
/// guesser to a hundred tries inside the ten minutes a code exists, which
/// is what makes forty bits the right size rather than a hope.
const WRONG_CODES_PER_WINDOW: u32 = 10;
const GUESS_WINDOW: Duration = Duration::from_secs(60);

/// Addresses whose wrong guesses are being counted at once. Another table
/// an unauthenticated caller can grow, so it has a ceiling like the rest.
/// Entries live [`GUESS_WINDOW`] and the sweep drops them; past the
/// ceiling, the entry nearest its own expiry is evicted to make room, so
/// that filling the table is never a way to get out of being counted.
const MAX_GUESSERS: usize = 4096;

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

/// What one poll of a session found (§5.3).
pub struct Polled {
    pub pending: Vec<PendingView>,
    pub expires_in: u64,
    /// Whether this session's code still admits a request.
    ///
    /// Not in the spec's §5.3 table, and it should be: a code is
    /// single-use, so a holder that stays open — `hlid agent` — is
    /// otherwise displaying a code it has no way of knowing is dead, and
    /// the user finds out by typing it and being told it is unknown.
    /// The server already tracks this (§11 keeps the code "until used");
    /// this is only reporting it.
    pub code_live: bool,
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
    BadClaim,
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
            Refused::BadClaim => "bad_claim",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Refused::UnknownCode
            | Refused::NoHolder
            | Refused::UnknownSession
            | Refused::UnknownRequest => 404,
            Refused::RequestTooLarge | Refused::BadRequest | Refused::BadClaim => 400,
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
            // Three things reach this now — open sessions, pending
            // requests, and wrong codes — so it no longer names one.
            Refused::RateLimited => "too many enrollment attempts from this address; retry shortly",
            Refused::UnknownSession => "no such enrollment session",
            Refused::UnknownRequest => "no such enrollment request",
            Refused::BadClaim => "the session claim does not verify for this session",
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
    /// The identity this session has proved it holds, and so stands by
    /// for (§5.1). Kept so that a second claim, or a close, can take the
    /// first one back out of `by_identity` — sweeping by liveness alone
    /// would leave a live session indexed under an identity it no longer
    /// claims.
    identity: Option<Fingerprint>,
    addr: IpAddr,
    expires: Instant,
    /// Keyed by the SHA-256 of the request secret, as everything else
    /// here is.
    pending: HashMap<[u8; 32], Pending>,
    next_id: u64,
    /// Given up by its holder (§5.1). It routes nothing and counts
    /// against nobody; it exists only until the answers it has already
    /// made have been collected.
    closed: bool,
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
    /// Wrong codes lately, per source address (§5.2).
    wrong_codes: HashMap<IpAddr, Guesses>,
}

/// Wrong codes from one address, and when the window holding them opened.
struct Guesses {
    count: u32,
    since: Instant,
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

    /// §5.1. Unauthenticated: a session opened by someone with no
    /// identity key can answer nothing an enrollee would accept, so
    /// there is nothing here a proof would protect.
    ///
    /// Standing by for an identity's renewals is the exception, and it
    /// is a separate call — [`Mailbox::claim_identity`] — because that
    /// one *is* worth protecting.
    pub fn open_session(&self, addr: IpAddr) -> Result<Opened, Refused> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(now);

        if inner.sessions.len() >= self.cfg.max_sessions {
            return Err(Refused::TooManySessions);
        }
        // Closed sessions do not count: they route nothing and are only
        // still here so an enrollee can collect an answer already made.
        // Charging a holder for them is what made a rotating agent
        // rate-limit itself out of its own mailbox.
        if inner
            .sessions
            .values()
            .filter(|s| s.addr == addr && !s.closed)
            .count()
            >= self.cfg.per_address
        {
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
        inner.sessions.insert(
            key,
            Session {
                code: Some(normalize_code(&code)),
                identity: None,
                closed: false,
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

    /// §5.1. Stand by for an identity's renewals, having proved the
    /// identity key is held.
    ///
    /// The proof is a [`SessionClaim`] over this session's key, so the
    /// mailbox learns nothing it could replay and the holder signs
    /// nothing that means anything anywhere else. Without it, anyone
    /// could name anyone's fingerprint — fingerprints are public — and
    /// have `by_identity` route that identity's renewals to them, which
    /// is a stranger switching off renewal for an identity they do not
    /// hold.
    ///
    /// Last writer wins, which it can safely be now that only the key
    /// holder can write: a holder that restarts its agent takes its own
    /// identity's renewals back rather than being shut out by the
    /// session it just abandoned.
    pub fn claim_identity(&self, secret: &str, claim: &[u8]) -> Result<(), Refused> {
        // The same value the session is stored under: `hash` here and
        // `session_key` there are one function with two callers.
        let key = hash(secret.as_bytes());
        let claim = SessionClaim::parse(claim, &key).map_err(|_| Refused::BadClaim)?;
        let fp = claim.fingerprint();

        let mut inner = self.inner.lock().unwrap();
        inner.sweep(Instant::now());
        // Looked up before anything is written, so a claim for a session
        // that has expired is a 404 and not a stray index entry.
        let session = inner
            .sessions
            .get_mut(&key)
            .filter(|s| !s.closed)
            .ok_or(Refused::UnknownSession)?;
        let previous = session.identity.replace(fp);
        if let Some(old) = previous {
            // Only when the index still names *this* session. Last writer
            // wins, so another session may have claimed `old` since — and
            // removing by key alone took that session's entry out from
            // under it, leaving a holder that had claimed nothing wrong
            // receiving no renewals at all. `close_session` never had the
            // bug because it clears `identity` and lets the sweep decide,
            // and the sweep checks the value; this is the same rule
            // written out.
            if old != fp && inner.by_identity.get(&old) == Some(&key) {
                inner.by_identity.remove(&old);
            }
        }
        inner.by_identity.insert(fp, key);
        Ok(())
    }

    /// Give a session up before its ten minutes are out.
    ///
    /// Not in §5, and it should be. A holder that rotates — `hlid agent`
    /// opens a replacement the moment its code is spent — otherwise
    /// leaves the session it abandoned sitting in the table until the
    /// TTL, where it goes on counting against `enroll_per_address`. Four
    /// rotations inside ten minutes and the holder is rate-limited out
    /// of its own mailbox.
    ///
    /// Only the session secret can do this, as with answering: the code
    /// cannot, and neither can anyone who has only seen one.
    pub fn close_session(&self, secret: &str) -> Result<(), Refused> {
        let key = hash(secret.as_bytes());
        let mut inner = self.inner.lock().unwrap();
        inner.sweep(Instant::now());
        let session = inner
            .sessions
            .get_mut(&key)
            .filter(|s| !s.closed)
            .ok_or(Refused::UnknownSession)?;

        // Closed rather than dropped, and this is the whole subtlety.
        // The holder is done with the session the moment it has answered
        // — but the *enrollee* has not collected that answer yet, and it
        // is parked on a long poll waiting for it. Dropping the session
        // would take the bundle with it and the browser would be told
        // its request expired, seconds after a human approved it.
        //
        // So closing stops the session receiving anything new and stops
        // it counting against the address, and leaves answers already
        // made to be collected. `sweep` removes it once they have been.
        session.closed = true;
        session.code = None;
        session.identity = None;
        session.pending.retain(|_, p| p.answer.is_some());
        let empty = session.pending.is_empty();
        if empty {
            inner.sessions.remove(&key);
        }
        // Drops the code and identity indexes that pointed at it, and
        // the request index for anything just discarded.
        inner.sweep(Instant::now());
        Ok(())
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
                // Checked before the lookup, not after it, so an address
                // that has spent its budget cannot go on probing and
                // reading the answers. A caller with a *live* code pays
                // nothing here beyond the check itself: nothing is
                // recorded, and the budget it is checked against is only
                // ever spent by getting the code wrong.
                if inner.out_of_guesses(addr, now) {
                    return Err(Refused::RateLimited);
                }
                match inner.by_code.get(&normalized) {
                    Some(k) => *k,
                    None => {
                        inner.note_wrong_code(addr, now);
                        return Err(Refused::UnknownCode);
                    }
                }
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
    pub async fn poll_session(&self, secret: &str, wait: Duration) -> Result<Polled, Refused> {
        let key = hash(secret.as_bytes());
        let deadline = Instant::now() + wait;
        // Resolved once: a session's `Notify` outlives every poll of it,
        // and the loop below has to register against it *before* it reads
        // the state it is waiting on.
        let notify = {
            let mut inner = self.inner.lock().unwrap();
            inner.sweep(Instant::now());
            let session = inner.sessions.get(&key).ok_or(Refused::UnknownSession)?;
            session.notify.clone()
        };
        loop {
            // `notify_waiters()` stores no permit, so a request arriving
            // between the read below and the registration of this waiter
            // used to be lost outright — the poll then sat out its full
            // wait with an answer already on the table. `enable()`
            // registers now, before the read, so that arrival wakes it.
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut inner = self.inner.lock().unwrap();
                inner.sweep(Instant::now());
                let session = inner
                    .sessions
                    .get(&key)
                    .filter(|s| !s.closed)
                    .ok_or(Refused::UnknownSession)?;
                let expires_in = remaining(session.expires);
                let code_live = session.code.is_some();
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
                    return Ok(Polled {
                        pending: waiting,
                        expires_in,
                        code_live,
                    });
                }
                if Instant::now() >= deadline {
                    return Ok(Polled {
                        pending: Vec::new(),
                        expires_in,
                        code_live,
                    });
                }
            }
            // Timing out here rather than sleeping to the deadline in one
            // go so that a session which expires mid-poll is noticed.
            let _ =
                tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), notified)
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
            .filter(|s| !s.closed)
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
        // As in `poll_session`: registered against before the state is
        // read, so an answer landing in between is not lost. A pending
        // request's `Notify` outlives every fetch of it, and a request
        // that is gone is caught by the read itself.
        let notify = {
            let mut inner = self.inner.lock().unwrap();
            inner.sweep(Instant::now());
            let Some(&skey) = inner.by_request.get(&key) else {
                return Fetched::Gone;
            };
            let Some(pending) = inner.sessions.get(&skey).and_then(|s| s.pending.get(&key)) else {
                return Fetched::Gone;
            };
            pending.notify.clone()
        };
        loop {
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
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
                    None => {}
                }
            }
            let _ =
                tokio::time::timeout(deadline.saturating_duration_since(Instant::now()), notified)
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
            // A closed session is only still here to be collected from.
            // Once there is nothing left to collect, it goes.
            !(s.closed && s.pending.is_empty())
        });
        self.by_code
            .retain(|_, k| self.sessions.get(k).is_some_and(|s| s.code.is_some()));
        // Keyed on the claim, not on the session merely still existing —
        // the same shape as `by_code` above, and for the same reason. A
        // closed session stays in `sessions` until its answers are
        // collected, but `close_session` has cleared its `identity`, and
        // routing a renewal to a session no holder is polling any more
        // parks the browser until the request expires.
        self.by_identity
            .retain(|_, k| self.sessions.get(k).is_some_and(|s| s.identity.is_some()));
        self.by_request.retain(|rk, sk| {
            self.sessions
                .get(sk)
                .is_some_and(|s| s.pending.contains_key(rk))
        });
        self.wrong_codes
            .retain(|_, g| now.duration_since(g.since) < GUESS_WINDOW);
        dropped
    }

    /// Whether this address has used up its wrong codes for the moment
    /// (§5.2). A window that has run out is forgotten here rather than
    /// waiting for the next sweep, so the budget is genuinely per window
    /// and not per sweep.
    fn out_of_guesses(&mut self, addr: IpAddr, now: Instant) -> bool {
        match self.wrong_codes.get(&addr) {
            Some(g) if now.duration_since(g.since) >= GUESS_WINDOW => {
                self.wrong_codes.remove(&addr);
                false
            }
            Some(g) => g.count >= WRONG_CODES_PER_WINDOW,
            None => false,
        }
    }

    /// Charge one wrong code to this address.
    ///
    /// A full table evicts rather than declining to record, and that is
    /// the whole reason this is not three lines. An address with no entry
    /// has no budget, so simply refusing to insert would hand unlimited
    /// guesses to whoever arrived after the table filled — which is a
    /// bypass anyone able to fill it can also walk through. Evicting the
    /// entry nearest its own expiry keeps every caller counted; the worst
    /// it costs a bystander is their counter reset to the honest budget
    /// they started with, and it costs the guesser a guess to do it.
    fn note_wrong_code(&mut self, addr: IpAddr, now: Instant) {
        if let Some(g) = self.wrong_codes.get_mut(&addr) {
            g.count = g.count.saturating_add(1);
            return;
        }
        if self.wrong_codes.len() >= MAX_GUESSERS {
            let oldest = self
                .wrong_codes
                .iter()
                .min_by_key(|(_, g)| g.since)
                .map(|(a, _)| *a);
            if let Some(a) = oldest {
                self.wrong_codes.remove(&a);
            }
        }
        self.wrong_codes.insert(
            addr,
            Guesses {
                count: 1,
                since: now,
            },
        );
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
    use hl_identity::enroll::session_key;
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

    /// Open a session and claim `identity` for it, which is what a
    /// standing holder does and the only way into `by_identity`.
    fn standing(m: &Mailbox, addr: IpAddr, identity: &IdentityKey) -> Opened {
        let opened = m.open_session(addr).unwrap();
        let claim =
            SessionClaim::new(identity.public(), session_key(&opened.session)).sign(identity);
        m.claim_identity(&opened.session, &claim).unwrap();
        opened
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
        let opened = m.open_session(addr(1)).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();

        let pending = m
            .poll_session(&opened.session, QUICK)
            .await
            .unwrap()
            .pending;
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
        let opened = m.open_session(addr(1)).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let pending = m
            .poll_session(&opened.session, QUICK)
            .await
            .unwrap()
            .pending;
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
    async fn the_poll_says_whether_the_code_still_works() {
        // A holder that stays open needs this: a code is single-use, and
        // a standing agent would otherwise go on displaying one that is
        // dead, with the user finding out by typing it.
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
        assert!(
            m.poll_session(&opened.session, QUICK)
                .await
                .unwrap()
                .code_live
        );

        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        assert!(
            !m.poll_session(&opened.session, QUICK)
                .await
                .unwrap()
                .code_live,
            "the code was spent by that request"
        );
    }

    #[tokio::test]
    async fn opening_a_session_moves_the_standing_identity_at_once() {
        // The property a rotating holder depends on. It opens the
        // replacement before letting go of the old session and then
        // sweeps the old one, which is only correct if opening is what
        // moves the identity index — under this lock — so that a renewal
        // is either already on the outgoing session or lands on the new
        // one, and never falls between them.
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let a = standing(&m, addr(1), &id);
        m.post_request(addr(2), None, &renewal(2, &id)).unwrap();
        assert_eq!(
            m.poll_session(&a.session, QUICK)
                .await
                .unwrap()
                .pending
                .len(),
            1
        );

        // Rotate. From here the index names B, so nothing further can
        // arrive on A.
        let b = standing(&m, addr(1), &id);
        m.post_request(addr(3), None, &renewal(3, &id)).unwrap();
        assert_eq!(
            m.poll_session(&b.session, QUICK)
                .await
                .unwrap()
                .pending
                .len(),
            1,
            "the new session collects renewals"
        );
        // And what was already on A is still there to be swept, rather
        // than moved or dropped.
        assert_eq!(
            m.poll_session(&a.session, Duration::ZERO)
                .await
                .unwrap()
                .pending
                .len(),
            1,
            "the outgoing session still holds what it was given"
        );
    }

    #[tokio::test]
    async fn a_zero_wait_poll_answers_at_once() {
        // What a rotating holder needs: it has just opened a new session
        // and has to sweep the old one for anything that arrived while
        // the rotation was in flight. Blocking the full deadline to find
        // nothing would stall the session it just opened.
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
        let started = Instant::now();
        let polled = m
            .poll_session(&opened.session, Duration::ZERO)
            .await
            .unwrap();
        assert!(polled.pending.is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a zero wait should not block"
        );

        // And it still returns what is there, which is the point.
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let polled = m
            .poll_session(&opened.session, Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(polled.pending.len(), 1);
    }

    #[tokio::test]
    async fn a_renewal_leaves_the_code_alone() {
        // A standing session collects renewals by identity, and those do
        // not touch the code — so an agent showing one can keep showing
        // it while renewals come and go.
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let opened = standing(&m, addr(1), &id);
        m.post_request(addr(2), None, &renewal(2, &id)).unwrap();
        assert!(
            m.poll_session(&opened.session, QUICK)
                .await
                .unwrap()
                .code_live
        );
    }

    #[tokio::test]
    async fn a_code_admits_one_request_and_is_then_dead() {
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
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
        m.open_session(addr(1)).unwrap();
        assert_eq!(
            m.post_request(addr(2), Some("AAAA-AAAA"), &request(2))
                .err(),
            Some(Refused::UnknownCode)
        );
    }

    #[tokio::test]
    async fn guessing_codes_is_bounded_per_address() {
        // What §5.2 and §9 both claim and nothing enforced: "guesses are
        // rate-limited per address, which is what forty bits needs". A
        // wrong code is refused before any table is touched, so without
        // this an address could try as fast as it could open sockets.
        let m = mailbox();
        m.open_session(addr(1)).unwrap();
        for i in 0..WRONG_CODES_PER_WINDOW {
            assert_eq!(
                m.post_request(addr(2), Some(&draw_code()), &request(2))
                    .err(),
                Some(Refused::UnknownCode),
                "guess {i} is still just a wrong code"
            );
        }
        assert_eq!(
            m.post_request(addr(2), Some(&draw_code()), &request(2))
                .err(),
            Some(Refused::RateLimited),
            "past the budget the address is refused rather than answered"
        );
    }

    #[tokio::test]
    async fn one_address_guessing_does_not_lock_out_another() {
        // The limit is per address precisely so that a guesser cannot
        // stop anybody else enrolling. If it were global, filling it
        // would be a cheaper attack than the one it prevents.
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
        for _ in 0..WRONG_CODES_PER_WINDOW + 5 {
            let _ = m.post_request(addr(2), Some(&draw_code()), &request(2));
        }
        assert!(
            m.post_request(addr(3), Some(&opened.code), &request(3))
                .is_ok(),
            "a different address types the live code and gets in"
        );
    }

    #[tokio::test]
    async fn a_live_code_is_not_charged_against_the_guess_budget() {
        // The budget is only ever spent by getting a code wrong. A user
        // who types live codes — several devices, several sessions —
        // must never run into it. `per_address` is raised so that the
        // *other* limit, on pending requests, is not what this measures.
        let m = Mailbox::new(MailboxConfig {
            max_sessions: 256,
            per_address: 64,
        });
        for i in 0..WRONG_CODES_PER_WINDOW + 5 {
            let opened = m.open_session(addr(1)).unwrap();
            assert!(
                m.post_request(addr(2), Some(&opened.code), &request(2))
                    .is_ok(),
                "live code {i} should not be charged to the guess budget"
            );
        }
    }

    #[test]
    fn a_full_guess_table_still_counts_the_next_address() {
        // Declining to record once the table is full would hand unlimited
        // guesses to whoever arrived after it filled — a bypass anyone
        // able to fill it can also walk through. Eviction keeps everyone
        // counted.
        let mut inner = Inner::default();
        let now = Instant::now();
        for i in 0..MAX_GUESSERS {
            let a = IpAddr::from(std::net::Ipv6Addr::from(i as u128));
            inner.note_wrong_code(a, now);
        }
        assert_eq!(inner.wrong_codes.len(), MAX_GUESSERS);

        let late = IpAddr::from([203, 0, 113, 7]);
        for _ in 0..WRONG_CODES_PER_WINDOW {
            assert!(!inner.out_of_guesses(late, now));
            inner.note_wrong_code(late, now);
        }
        assert!(
            inner.out_of_guesses(late, now),
            "an address that arrived after the table filled is counted like any other"
        );
        assert!(
            inner.wrong_codes.len() <= MAX_GUESSERS,
            "and it stays bounded"
        );
    }

    #[test]
    fn a_guess_budget_refills_when_its_window_passes() {
        let mut inner = Inner::default();
        let a = addr(2);
        let start = Instant::now();
        for _ in 0..WRONG_CODES_PER_WINDOW {
            inner.note_wrong_code(a, start);
        }
        assert!(inner.out_of_guesses(a, start));
        assert!(
            !inner.out_of_guesses(a, start + GUESS_WINDOW),
            "a mistyped code should not cost the window after it"
        );
    }

    #[tokio::test]
    async fn a_code_survives_being_read_off_a_screen_and_typed_back() {
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
        // Lower case, no hyphen, and Crockford's confusables: whoever
        // typed `l` for `1` or `O` for `0` should not be told their code
        // is wrong.
        let typed = opened.code.to_lowercase().replace('-', "");
        let typed = typed.replace('1', "l").replace('0', "o");
        assert!(m.post_request(addr(2), Some(&typed), &request(2)).is_ok());
    }

    #[test]
    fn a_stranger_may_not_stand_by_for_an_identity_it_does_not_hold() {
        // Fingerprints are public — they are printed on the holder's own
        // screen — so without a proof this is all it would take to have
        // every renewal for an identity delivered to somebody else, and
        // none to its holder.
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let attacker = IdentityKey::from_seed(&[9u8; 32]);

        let theirs = m.open_session(addr(9)).unwrap();
        // The victim's fingerprint, signed by the key the attacker
        // actually has. It verifies; it is just not a claim on this
        // identity, because the identity is taken from the key.
        let wrong_key =
            SessionClaim::new(attacker.public(), session_key(&theirs.session)).sign(&attacker);
        m.claim_identity(&theirs.session, &wrong_key).unwrap();

        // A renewal for the victim still has nowhere to go.
        assert_eq!(
            m.post_request(addr(2), None, &renewal(2, &id)).err(),
            Some(Refused::NoHolder),
            "a stranger's session collected the victim's renewals"
        );

        // Naming the victim's key and signing with the attacker's is the
        // other half, and it cannot even be built here: `SessionClaim`
        // will not sign for a key it does not hold, and
        // `a_claim_may_only_be_signed_by_the_identity_it_names` in
        // `hl-identity` checks that such bytes do not verify.
    }

    #[test]
    fn a_claim_is_only_good_for_the_session_it_names() {
        // A claim overheard from one session — by the mailbox, which is
        // the party §9 already treats as hostile — is not a claim on
        // another.
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let first = m.open_session(addr(1)).unwrap();
        let second = m.open_session(addr(1)).unwrap();

        let for_first = SessionClaim::new(id.public(), session_key(&first.session)).sign(&id);
        assert_eq!(
            m.claim_identity(&second.session, &for_first).err(),
            Some(Refused::BadClaim)
        );
    }

    #[test]
    fn a_claim_needs_a_session_that_is_still_open() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let claim = SessionClaim::new(id.public(), session_key("never-opened")).sign(&id);
        assert_eq!(
            m.claim_identity("never-opened", &claim).err(),
            Some(Refused::UnknownSession)
        );
    }

    #[test]
    fn reclaiming_moves_the_identity_and_leaves_nothing_behind() {
        // A holder that restarts its agent takes its own renewals back,
        // which is what last-writer-wins is for and is safe now that
        // only the key holder can be the writer.
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let other = IdentityKey::from_seed(&[2u8; 32]);
        let s = m.open_session(addr(1)).unwrap();

        let first = SessionClaim::new(id.public(), session_key(&s.session)).sign(&id);
        m.claim_identity(&s.session, &first).unwrap();
        // The same session claiming a second identity releases the
        // first, rather than leaving a live session indexed under an
        // identity it no longer stands by for.
        let second = SessionClaim::new(other.public(), session_key(&s.session)).sign(&other);
        m.claim_identity(&s.session, &second).unwrap();

        assert!(m.post_request(addr(2), None, &renewal(2, &other)).is_ok());
        assert_eq!(
            m.post_request(addr(3), None, &renewal(3, &id)).err(),
            Some(Refused::NoHolder)
        );
    }

    #[test]
    fn a_session_that_moves_on_does_not_evict_whoever_took_its_identity() {
        // The other half of last-writer-wins, and the half that was
        // wrong. A holder restarts its agent, so session B claims the
        // identity session A held — B wins, which is the point. If A then
        // claims something else, the release of its old claim must not
        // take B's index entry with it: B claimed correctly, is being
        // polled, and would simply stop receiving renewals.
        let m = mailbox();
        let x = IdentityKey::from_seed(&[1u8; 32]);
        let y = IdentityKey::from_seed(&[2u8; 32]);
        let a = m.open_session(addr(1)).unwrap();
        let b = m.open_session(addr(2)).unwrap();

        for (s, id) in [(&a, &x), (&b, &x)] {
            let claim = SessionClaim::new(id.public(), session_key(&s.session)).sign(id);
            m.claim_identity(&s.session, &claim).unwrap();
        }
        assert!(
            m.post_request(addr(3), None, &renewal(3, &x)).is_ok(),
            "B took the identity, as last-writer-wins says it should"
        );

        let claim = SessionClaim::new(y.public(), session_key(&a.session)).sign(&y);
        m.claim_identity(&a.session, &claim).unwrap();
        assert!(
            m.post_request(addr(4), None, &renewal(4, &x)).is_ok(),
            "and A moving on leaves B holding it"
        );
        assert!(
            m.post_request(addr(5), None, &renewal(5, &y)).is_ok(),
            "while A now holds what it actually claimed"
        );
    }

    #[test]
    fn closing_a_session_gives_the_address_its_allowance_back() {
        // What a rotating agent depends on. `per_address` is 4 by
        // default, and a holder that abandons a session on every spent
        // code used to spend its whole allowance on sessions it had
        // finished with — four rotations inside the ten-minute TTL and
        // it was locked out of its own mailbox.
        let cfg = MailboxConfig {
            per_address: 2,
            ..MailboxConfig::default()
        };
        let m = Mailbox::new(cfg);

        let first = m.open_session(addr(1)).unwrap();
        let second = m.open_session(addr(1)).unwrap();
        assert_eq!(m.open_session(addr(1)).err(), Some(Refused::RateLimited));

        m.close_session(&first.session).unwrap();
        assert!(
            m.open_session(addr(1)).is_ok(),
            "closing did not free the allowance"
        );

        // Only the session secret can do it, and only once.
        assert_eq!(
            m.close_session("not-a-session").err(),
            Some(Refused::UnknownSession)
        );
        m.close_session(&second.session).unwrap();
        assert_eq!(
            m.close_session(&second.session).err(),
            Some(Refused::UnknownSession)
        );
    }

    #[tokio::test]
    async fn closing_a_session_does_not_throw_away_an_answer_nobody_has_collected() {
        // The holder is done the moment it has answered; the enrollee is
        // not. It is parked on a long poll waiting for the bundle, and a
        // rotating agent closes the session it just answered on within
        // milliseconds. Dropping the session there would tell a browser
        // its request expired seconds after a human approved it.
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let pending = m.poll_session(&opened.session, QUICK).await.unwrap();
        m.answer(
            &opened.session,
            &pending.pending[0].id,
            Answered::Bundle(b"the bundle".to_vec()),
        )
        .unwrap();

        m.close_session(&opened.session).unwrap();

        match m.fetch_answer(&posted.request, QUICK).await {
            Fetched::Bundle(b) => assert_eq!(b, b"the bundle"),
            _ => panic!("closing the session lost an answered request"),
        }
        // And once collected, the session really is gone.
        m.sweep();
        assert_eq!(m.session_count(), 0);
    }

    #[tokio::test]
    async fn a_closed_session_routes_nothing_and_costs_nothing() {
        let cfg = MailboxConfig {
            per_address: 1,
            ..MailboxConfig::default()
        };
        let m = Mailbox::new(cfg);
        let opened = m.open_session(addr(1)).unwrap();
        let posted = m
            .post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let pending = m.poll_session(&opened.session, QUICK).await.unwrap();
        m.answer(
            &opened.session,
            &pending.pending[0].id,
            Answered::Denied("declined".into()),
        )
        .unwrap();
        m.close_session(&opened.session).unwrap();

        // Still holding an answer, and still not costing the holder its
        // allowance — which is the whole point of closing.
        assert!(m.open_session(addr(1)).is_ok());
        // Nothing else works on it: it cannot be polled, answered on,
        // claimed, or closed twice.
        assert_eq!(
            m.poll_session(&opened.session, QUICK).await.err(),
            Some(Refused::UnknownSession)
        );
        assert_eq!(
            m.close_session(&opened.session).err(),
            Some(Refused::UnknownSession)
        );
        assert!(matches!(
            m.fetch_answer(&posted.request, QUICK).await,
            Fetched::Denied(_)
        ));
    }

    #[test]
    fn closing_a_session_takes_its_identity_out_of_the_index() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let s = standing(&m, addr(1), &id);
        assert!(m.post_request(addr(2), None, &renewal(2, &id)).is_ok());

        m.close_session(&s.session).unwrap();
        assert_eq!(
            m.post_request(addr(3), None, &renewal(3, &id)).err(),
            Some(Refused::NoHolder)
        );
        assert!(m.inner.lock().unwrap().by_identity.is_empty());
    }

    #[tokio::test]
    async fn a_closed_session_holding_an_answer_still_routes_no_renewals() {
        // The case the test above cannot reach: its pending request was
        // unanswered, so closing dropped the session outright and took
        // the index with it. Answer first and the session survives the
        // close — it is still there to be collected from — and the
        // identity index used to survive with it, keyed on the session
        // merely existing rather than on the claim. Renewals then routed
        // to a session no holder can poll any more, and the browser sat
        // there until its request expired.
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let opened = standing(&m, addr(1), &id);

        let posted = m.post_request(addr(2), None, &renewal(2, &id)).unwrap();
        let pending = m
            .poll_session(&opened.session, QUICK)
            .await
            .unwrap()
            .pending;
        m.answer(&opened.session, &pending[0].id, Answered::Bundle(vec![7]))
            .unwrap();
        m.close_session(&opened.session).unwrap();

        // Still holding the answer, so the session is still there.
        assert_eq!(m.session_count(), 1);
        assert!(matches!(
            m.fetch_answer(&posted.request, QUICK).await,
            Fetched::Bundle(_)
        ));

        // But it holds no identity: a renewal is told there is no
        // holder, and falls back to a code, rather than being parked on
        // a session nobody is listening to.
        assert_eq!(
            m.post_request(addr(3), None, &renewal(3, &id)).err(),
            Some(Refused::NoHolder)
        );
        assert!(m.inner.lock().unwrap().by_identity.is_empty());
    }

    #[tokio::test]
    async fn a_renewal_routes_by_identity_with_no_code_at_all() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let opened = standing(&m, addr(1), &id);

        let posted = m.post_request(addr(2), None, &renewal(2, &id)).unwrap();
        let pending = m
            .poll_session(&opened.session, QUICK)
            .await
            .unwrap()
            .pending;
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
        m.open_session(addr(1)).unwrap();
        assert_eq!(
            m.post_request(addr(2), None, &renewal(2, &stranger)).err(),
            Some(Refused::NoHolder)
        );
    }

    #[tokio::test]
    async fn a_first_enrollment_cannot_route_itself() {
        let m = mailbox();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        standing(&m, addr(1), &id);
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
        let opened = m.open_session(addr(1)).unwrap();
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let pending = m
            .poll_session(&opened.session, QUICK)
            .await
            .unwrap()
            .pending;

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
        let opened = m.open_session(addr(1)).unwrap();
        m.post_request(addr(2), Some(&opened.code), &request(2))
            .unwrap();
        let pending = m
            .poll_session(&opened.session, QUICK)
            .await
            .unwrap()
            .pending;
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
        let opened = m.open_session(addr(1)).unwrap();
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

        let polled = tokio::time::timeout(Duration::from_secs(2), poller)
            .await
            .expect("the poll should have been woken, not timed out")
            .unwrap()
            .unwrap();
        assert_eq!(polled.pending.len(), 1);
    }

    #[tokio::test]
    async fn a_poll_with_nothing_waiting_comes_back_empty_at_the_deadline() {
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
        let polled = m.poll_session(&opened.session, QUICK).await.unwrap();
        assert!(polled.pending.is_empty());
        assert!(polled.expires_in > 0, "the session is still open");
        assert!(polled.code_live, "nothing has used the code yet");
    }

    #[tokio::test]
    async fn a_request_nobody_has_answered_is_still_pending_at_the_deadline() {
        let m = mailbox();
        let opened = m.open_session(addr(1)).unwrap();
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
        let opened = m.open_session(addr(1)).unwrap();
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
        assert!(m.open_session(addr(1)).is_ok());
        assert!(m.open_session(addr(1)).is_ok());
        // Third from the same address: the per-address limit bites first.
        assert_eq!(m.open_session(addr(1)).err(), Some(Refused::RateLimited));

        assert!(m.open_session(addr(2)).is_ok());
        // Server-wide ceiling, reached from a fresh address.
        assert_eq!(
            m.open_session(addr(3)).err(),
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
            .map(|i| m.open_session(addr(10 + i)).unwrap().code)
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
        let opened = m.open_session(addr(1)).unwrap();

        // Somebody else uses up their own allowance elsewhere, and then
        // this address is refused. The user's code must survive that:
        // burning it would send them back to a terminal for a code that
        // no longer works, for a reason that was never about them.
        let other = m.open_session(addr(9)).unwrap();
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
        let opened = standing(&m, addr(1), &id);
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
