//! Limits a single address is held to, whatever it is logged in as, and
//! those a single session is.
//!
//! **Connections.** mhxd's `nospam` defaults are the reference: at most
//! five connections from one address, and not two within two seconds.
//! The second is kept as a rate rather than a rule — a burst up to the
//! connection cap, then one more every two seconds — because an ng
//! client that drops and resumes, or a person who quits and reconnects,
//! makes two connections in quick succession for good reasons. An
//! address past either limit has its connection closed unanswered, as
//! mhxd does: answering it would mean holding the connection open to
//! do so, which is what a flood of them wants.
//!
//! **Talk.** One session is held to mhxd's two budgets, whatever address
//! it came from ([`FloodLimits`]): `chat_max` lines of chat in a
//! `chat_time`-second window, every line of a multi-line send counted,
//! and `spam_max` spam points in a `spam_time`-second window, which each
//! transaction it sends spends at the rate mhxd's table charges it. Past
//! the first it is kicked and its room told, past the second kicked and
//! banned for `[server] ban_time` with public chat told, both in mhxd's
//! words. An account that `can_spam` is held to neither.
//!
//! **Requests.** Neither budget sees most of what an ng client can ask
//! for, and mhxd has no counterpart to price it by. One ng session is
//! held to a token bucket instead ([`RequestLimits`]): each request
//! spends its weight, a read the least and what writes, fans out or
//! renegotiates media more, and one the bucket cannot pay for is
//! answered `rate_limited` with how long to wait, which is a delay and
//! not a kick. The bucket is the session's, like the budgets, so a
//! client that drops its socket and resumes finds it as it left it.
//! One account's news posts are held to a slower bucket of their own,
//! which the classic wire's posts draw on and are never refused by. An
//! account that `can_spam` is held to neither of these either, as it is
//! held to neither budget.
//!
//! Some requests are cheap to make and dear to answer, or
//! are a guess at something: a password, a challenge that fills a table.
//! Those are held to a rate per address ([`RateGate`]) — a burst, then
//! one more as each comes due — and one past it is told how long to
//! wait. Failed logins are one of them, and are counted wherever a
//! password is checked, whichever wire it arrived on
//! ([`Core::login_attempt`], [`LoginLimits`]).
//!
//! **Addresses.** An IPv4 address is itself; an IPv6 one is its /64,
//! which is what one subscriber is given, so a client cannot step past
//! the cap by walking its own prefix. An IPv4 address mapped into IPv6
//! is the IPv4 address. Addresses in `exempt` are held to none of the
//! limits an address is, though a session from one is still held to its
//! own: loopback by default, so the tests, the load harness and an
//! operator's own tools are not refused by their own server.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::roster::Core;

/// A set of addresses and CIDR blocks: `"192.0.2.7"`, `"10.0.0.0/8"`,
/// `"2001:db8::/32"`.
///
/// Both sides are canonicalized before comparing. A peer on 127.0.0.1
/// reaching a server bound to `[::]` arrives as `::ffff:127.0.0.1`, and
/// an exact comparison would silently never match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddrSet(Vec<(IpAddr, u32)>);

impl AddrSet {
    /// Parse the entries. The error names the offending entry.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, String> {
        let mut out = Vec::new();
        for e in entries {
            let e = e.as_ref().trim();
            let (addr, prefix) = match e.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (e, None),
            };
            let addr: IpAddr = addr
                .parse()
                .map_err(|_| format!("{e:?} is not an IP address"))?;
            let addr = addr.to_canonical();
            let full = if addr.is_ipv4() { 32 } else { 128 };
            let bits = match prefix {
                None => full,
                Some(p) => {
                    let bits: u32 = p
                        .parse()
                        .map_err(|_| format!("{e:?} has a bad prefix length"))?;
                    if bits > full {
                        return Err(format!("{e:?} prefix exceeds {full} bits"));
                    }
                    bits
                }
            };
            out.push((addr, bits));
        }
        Ok(AddrSet(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.0
            .iter()
            .any(|(net, bits)| prefix_eq(peer, *net, *bits))
    }
}

fn prefix_eq(a: IpAddr, b: IpAddr, bits: u32) -> bool {
    fn octets(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        }
    }
    if a.is_ipv4() != b.is_ipv4() {
        return false;
    }
    let (a, b) = (octets(a), octets(b));
    let (whole, rest) = ((bits / 8) as usize, bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
}

/// The address a limit counts against: IPv4 as itself, IPv6 as its /64.
pub fn limit_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::from(o)
        }
        v4 => v4,
    }
}

/// How connections from one address are limited (`[limits]`).
#[derive(Debug, Clone)]
pub struct ConnLimits {
    /// Connections one address may hold at once; 0 is no limit. It is
    /// also the reconnect burst, which with no limit here stays at
    /// [`CONNECTIONS_PER_ADDR`]: a burst of one would make the rate a
    /// flat one connection per interval, and refuse an ng client's quick
    /// drop and resume.
    pub per_addr: usize,
    /// How often one address earns another new connection once it has
    /// spent its burst; zero is no rate limit.
    pub reconnect: Duration,
    /// Addresses not limited.
    pub exempt: AddrSet,
}

impl Default for ConnLimits {
    fn default() -> Self {
        ConnLimits {
            per_addr: CONNECTIONS_PER_ADDR,
            reconnect: RECONNECT_EVERY,
            exempt: AddrSet::parse(&["127.0.0.0/8", "::1"]).expect("loopback parses"),
        }
    }
}

/// mhxd's `conn_max`.
pub const CONNECTIONS_PER_ADDR: usize = 5;
/// mhxd's `reconn_time`.
pub const RECONNECT_EVERY: Duration = Duration::from_secs(2);

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnRefused {
    /// The address already holds as many as it may.
    TooMany,
    /// The address has been connecting faster than it may.
    TooFast,
}

impl ConnRefused {
    /// For the disconnect metric.
    pub fn reason(self) -> &'static str {
        match self {
            ConnRefused::TooMany => "too_many",
            ConnRefused::TooFast => "too_fast",
        }
    }
}

/// The connections each address holds, and what it has spent of its
/// burst. The core keeps one for every connection that can carry a
/// session ([`Core::admit_connection`]); a frontend may keep another for
/// connections of its own that do not.
#[derive(Default)]
pub struct ConnGate(Arc<GateInner>);

#[derive(Default)]
pub(crate) struct GateInner {
    limits: ConnLimits,
    by_addr: Mutex<Table>,
}

/// The addresses the gate remembers, and how large the table may grow
/// before it is next pruned.
#[derive(Default)]
struct Table {
    map: HashMap<IpAddr, AddrState>,
    prune_at: usize,
}

/// The fewest addresses the table is let grow to before a prune.
const PRUNE_FLOOR: usize = 4096;

struct AddrState {
    live: usize,
    /// New connections the address may still make at once.
    tokens: f64,
    at: Instant,
}

/// One connection's place in its address's count; dropping it gives the
/// place back.
pub struct ConnPermit {
    gate: Option<(Arc<GateInner>, IpAddr)>,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        if let Some((gate, key)) = self.gate.take() {
            let mut by = gate.by_addr.lock().unwrap();
            if let Some(s) = by.map.get_mut(&key) {
                s.live = s.live.saturating_sub(1);
            }
        }
    }
}

impl ConnGate {
    pub fn new(limits: ConnLimits) -> ConnGate {
        ConnGate(Arc::new(GateInner {
            limits,
            by_addr: Mutex::default(),
        }))
    }

    /// Is `ip` held to no per-address limit (`exempt`)? The flood
    /// limits hold for it all the same.
    pub fn exempt(&self, ip: IpAddr) -> bool {
        self.0.limits.exempt.contains(ip)
    }

    /// The limits this gate holds addresses to.
    pub fn limits(&self) -> &ConnLimits {
        &self.0.limits
    }

    pub fn admit(&self, ip: IpAddr) -> Result<ConnPermit, ConnRefused> {
        let gate = &self.0;
        let l = &gate.limits;
        if (l.per_addr == 0 && l.reconnect.is_zero()) || l.exempt.contains(ip) {
            return Ok(ConnPermit { gate: None });
        }
        let key = limit_key(ip);
        let now = Instant::now();
        let burst = burst(l.per_addr);
        let mut by = gate.by_addr.lock().unwrap();
        // An address that holds nothing and has earned its whole burst
        // back is forgotten, so the table holds only addresses that are
        // connected or were a moment ago. The walk is over the whole
        // table, so it waits until the table has doubled since the last
        // one: a table of busy addresses that prunes to nearly its own
        // size is not walked again at every connection.
        if by.map.len() >= by.prune_at.max(PRUNE_FLOOR) {
            by.map
                .retain(|_, s| s.live > 0 || refill(s, now, l.reconnect, burst) < burst);
            by.prune_at = by.map.len().saturating_mul(2);
        }
        let s = by.map.entry(key).or_insert(AddrState {
            live: 0,
            tokens: burst,
            at: now,
        });
        s.tokens = refill(s, now, l.reconnect, burst);
        s.at = now;
        if l.per_addr != 0 && s.live >= l.per_addr {
            return Err(ConnRefused::TooMany);
        }
        if !l.reconnect.is_zero() {
            if s.tokens < 1.0 {
                return Err(ConnRefused::TooFast);
            }
            s.tokens -= 1.0;
        }
        s.live += 1;
        Ok(ConnPermit {
            gate: Some((gate.clone(), key)),
        })
    }
}

/// A rate one address is held to: a burst of `burst`, then one more
/// every `every`. Past it the caller is told how long until the next.
/// A `burst` of 0, or a zero `every`, is no limit; `exempt` addresses are
/// never limited. What the gate counts is the caller's: a request, or a
/// failed login ([`RateGate::spend`] after the fact, with
/// [`RateGate::check`] before it).
pub struct RateGate {
    burst: f64,
    every: Duration,
    exempt: AddrSet,
    by_addr: Mutex<RateTable>,
}

/// The addresses a [`RateGate`] remembers, and how large the table may
/// grow before it is next walked.
#[derive(Default)]
struct RateTable {
    map: HashMap<IpAddr, Bucket>,
    prune_at: usize,
    /// How many times the table has been walked, for the tests.
    #[cfg(test)]
    walks: usize,
}

/// What one address has left of a [`RateGate`]'s burst, as of `at`.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Default for RateGate {
    /// No limit.
    fn default() -> Self {
        RateGate::new(0, Duration::ZERO, AddrSet::default())
    }
}

/// How many addresses a gate remembers before it first forgets the ones
/// that have earned their whole burst back.
const RATE_KEPT: usize = 4096;

/// The most addresses a gate remembers at all. Addresses spread over
/// more networks than this (an IPv6 client has a /64 per network it
/// cares to route) cost a bounded table, not a growing one.
const RATE_CAP: usize = 1 << 16;

impl RateGate {
    pub fn new(burst: u32, every: Duration, exempt: AddrSet) -> RateGate {
        RateGate {
            burst: f64::from(burst),
            every,
            exempt,
            by_addr: Mutex::default(),
        }
    }

    /// `per_minute` a minute, all of them at once if need be: the burst
    /// is the minute's worth.
    pub fn per_minute(per_minute: u32, exempt: AddrSet) -> RateGate {
        let every = if per_minute == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs(60) / per_minute
        };
        RateGate::new(per_minute, every, exempt)
    }

    fn off(&self, ip: IpAddr) -> bool {
        self.burst < 1.0 || self.every.is_zero() || self.exempt.contains(ip)
    }

    /// Admit one more from `ip` and spend it, or say how long until one
    /// would be admitted.
    pub fn take(&self, ip: IpAddr) -> Result<(), Duration> {
        self.at(ip, Instant::now(), true)
    }

    /// Give back one [`take`](Self::take) spent: what it admitted turned
    /// out not to be what the gate counts. The bucket does not go above
    /// its burst.
    pub fn refund(&self, ip: IpAddr) {
        if self.off(ip) {
            return;
        }
        let now = Instant::now();
        let mut by = self.by_addr.lock().unwrap();
        let burst = self.burst;
        let b = self.bucket(&mut by, ip, now);
        b.tokens = (b.tokens + 1.0).min(burst);
    }

    fn bucket<'a>(&self, by: &'a mut RateTable, ip: IpAddr, now: Instant) -> &'a mut Bucket {
        let (burst, every) = (self.burst, self.every);
        let earned = |b: &Bucket| {
            (b.tokens + now.duration_since(b.at).as_secs_f64() / every.as_secs_f64()).min(burst)
        };
        let key = limit_key(ip);
        // An address that has earned its whole burst back is one a fresh
        // bucket describes, so the table holds only addresses that spent
        // something a moment ago. The walk is over the whole table, under
        // the lock every login takes, so it waits until the table has
        // doubled since the last one — as `ConnGate`'s does — and a table
        // of addresses still paying off their spending is not walked
        // again at every call.
        if !by.map.contains_key(&key) && by.map.len() >= by.prune_at.max(RATE_KEPT) {
            #[cfg(test)]
            {
                by.walks += 1;
            }
            by.map.retain(|_, b| earned(b) < burst);
            // Still near the cap, the fullest are forgotten until a
            // quarter of it is free, so the next walk is that many new
            // addresses away. Forgetting an address gives it its whole
            // burst back, which is why it is the fullest that go: each
            // was the nearest to a fresh bucket already, and an address
            // that spent a moment ago is among the emptiest and stays. To
            // have one of its own addresses forgotten, and gain at most a
            // burst by it, an attacker must first bring a quarter of the
            // cap's worth of new networks, each of which was a fresh
            // burst of its own anyway. The other way to hold the
            // cap, refusing whatever address is new, would let anyone
            // with enough networks to fill the table lock out every
            // address that had not yet been seen.
            let keep = RATE_CAP / 4 * 3;
            if by.map.len() > keep {
                let mut fill: Vec<(f64, IpAddr)> =
                    by.map.iter().map(|(k, b)| (earned(b), *k)).collect();
                fill.select_nth_unstable_by(keep, |a, b| a.0.total_cmp(&b.0));
                for (_, k) in &fill[keep..] {
                    by.map.remove(k);
                }
            }
            by.prune_at = by.map.len().saturating_mul(2).min(RATE_CAP);
        }
        let b = by.map.entry(key).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        b.tokens = earned(b);
        b.at = now;
        b
    }

    fn at(&self, ip: IpAddr, now: Instant, spend: bool) -> Result<(), Duration> {
        if self.off(ip) {
            return Ok(());
        }
        let every = self.every;
        let mut by = self.by_addr.lock().unwrap();
        let b = self.bucket(&mut by, ip, now);
        if b.tokens < 1.0 {
            return Err(every.mul_f64(1.0 - b.tokens));
        }
        if spend {
            b.tokens -= 1.0;
        }
        Ok(())
    }
}

/// How many failed logins one address may make (`[limits]`): a burst of
/// `failures`, then one more every `every`. Past it the address is
/// refused before its password is checked, until it has earned one back —
/// a right password included, or guessing would go on. 0 is no limit,
/// which is what a `Core` built by hand has; a server built from a config
/// has [`LoginLimits::RECOMMENDED`] unless it says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoginLimits {
    pub failures: u32,
    pub every: Duration,
}

impl LoginLimits {
    /// Ten wrong passwords at once, then one every thirty seconds: a
    /// person who mistypes is never refused, a guesser gets a hundred and
    /// twenty an hour.
    pub const RECOMMENDED: LoginLimits = LoginLimits {
        failures: 10,
        every: Duration::from_secs(30),
    };
}

/// A password about to be checked, holding the failure it will count
/// as if it is wrong ([`Core::login_attempt`]). Settle it with
/// [`Core::login_failed`] or [`Core::login_refund`] once the answer is
/// in; one dropped unsettled counts as a failure.
#[derive(Debug)]
#[must_use = "settle it with Core::login_failed or Core::login_refund"]
pub struct LoginAttempt {
    /// The address whose failure was spent; `None` when nothing was.
    held: Option<IpAddr>,
}

impl Core {
    /// Hold failed logins to `limits` rather than
    /// [`LoginLimits::default`]. Addresses exempt from `[limits]` are
    /// held to none.
    pub fn with_login_limits(mut self, limits: LoginLimits) -> Self {
        self.login_failures = RateGate::new(limits.failures, limits.every, AddrSet::default());
        self
    }

    /// May `addr` try `password` now? `Err` says how long until it may:
    /// it has failed as often as it may for now, and the frontend refuses
    /// the login without checking it. Asked before every password is
    /// checked, on every wire.
    ///
    /// The failure is spent here, before the password is checked, and
    /// given back when the attempt is settled as anything but a wrong
    /// guess ([`Core::login_refund`]). Checking first and spending once
    /// the answer is in would let every connection an address holds pass
    /// the check while the first of their passwords was still being
    /// verified, and a guesser would get as many tries at once as it
    /// could open connections. An empty password is not a guess — it is
    /// how a guest logs in, and it is one value, which trying again
    /// cannot change — so it is neither held to the count nor counted.
    pub fn login_attempt(&self, addr: IpAddr, password: &[u8]) -> Result<LoginAttempt, Duration> {
        if password.is_empty() || self.conn_gate.exempt(addr) {
            return Ok(LoginAttempt { held: None });
        }
        match self.login_failures.take(addr) {
            Ok(()) => Ok(LoginAttempt { held: Some(addr) }),
            Err(wait) => {
                crate::instrument::throttled("login");
                Err(wait)
            }
        }
    }

    /// The password `attempt` was for did not verify, or named no
    /// account: the failure it spent stays spent. Dropping an attempt
    /// unsettled says the same.
    pub fn login_failed(&self, attempt: LoginAttempt) {
        drop(attempt);
    }

    /// The attempt was not a wrong guess — the password verified, or the
    /// login was refused for something other than it, or the server
    /// could not tell — and the failure it spent is given back.
    pub fn login_refund(&self, attempt: LoginAttempt) {
        if let Some(addr) = attempt.held {
            self.login_failures.refund(addr);
        }
    }

    /// The addresses `[limits]` holds to none of its limits, for a
    /// frontend's own gates to exempt as well.
    pub fn limits_exempt(&self) -> &AddrSet {
        &self.conn_gate.limits().exempt
    }
}

/// New connections an address may make at once: its connection cap, or
/// mhxd's when there is none.
fn burst(per_addr: usize) -> f64 {
    match per_addr {
        0 => CONNECTIONS_PER_ADDR as f64,
        n => n as f64,
    }
}

fn refill(s: &AddrState, now: Instant, every: Duration, burst: f64) -> f64 {
    if every.is_zero() {
        return burst;
    }
    let earned = now.duration_since(s.at).as_secs_f64() / every.as_secs_f64();
    (s.tokens + earned).min(burst)
}

/// How fast one session may talk (`[limits]`), mhxd's `nospam` budgets:
/// `chat_lines` lines of chat in each `chat_per` window (mhxd's
/// `chat_max` and `chat_time`), and `spam_points` points in each
/// `spam_per` window (its `spam_max` and `spam_time`), which every
/// transaction spends at the rate its table charges. Past the first the
/// session is kicked; past the second it is kicked and its address
/// banned for `ban_for`, or only kicked when that is zero, as mhxd's
/// `ban_time` of 0 has it. A count of 0 is no limit, which is what a
/// `Core` built by hand has ([`FloodLimits::default`]); a server built
/// from a config has [`FloodLimits::MHXD`] unless it says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FloodLimits {
    pub chat_lines: u32,
    pub chat_per: Duration,
    pub spam_points: u32,
    pub spam_per: Duration,
    pub ban_for: Duration,
}

impl FloodLimits {
    /// mhxd's `nospam` defaults, and its `ban_time`.
    pub const MHXD: FloodLimits = FloodLimits {
        chat_lines: 20,
        chat_per: Duration::from_secs(5),
        spam_points: 100,
        spam_per: Duration::from_secs(5),
        ban_for: Duration::from_secs(1800),
    };
}

/// How many lines mhxd counts in a chat send: every piece its
/// `cr_strtok_r` loop cuts the text into at a CR or an LF, the empty
/// ones included, so one more than the breaks it holds.
pub(crate) fn chat_lines(text: &str) -> u32 {
    let breaks = text.bytes().filter(|b| *b == b'\r' || *b == b'\n').count();
    u32::try_from(breaks).unwrap_or(u32::MAX).saturating_add(1)
}

/// What one session has spent of its budgets.
#[derive(Debug, Default)]
pub(crate) struct Flood {
    chat: Window,
    spam: Window,
}

/// A fixed window, as mhxd keeps one: it starts at the first spend after
/// the last one ran out, and everything spent in it is forgotten when it
/// does.
#[derive(Debug, Default)]
struct Window {
    start: Option<Instant>,
    spent: u32,
}

impl Window {
    fn roll(&mut self, per: Duration, now: Instant) {
        if self.start.is_none_or(|s| now.duration_since(s) >= per) {
            self.start = Some(now);
            self.spent = 0;
        }
    }
}

impl Flood {
    /// Spend `lines` lines of chat: `false`, and nothing spent, when that
    /// would take the window past `chat_lines`. mhxd kicks at the first
    /// line past it, before the lines of the send it has formatted so far
    /// are relayed, so a send that crosses it is refused whole.
    pub(crate) fn chat(&mut self, lines: u32, limits: &FloodLimits, now: Instant) -> bool {
        if limits.chat_lines == 0 || limits.chat_per.is_zero() {
            return true;
        }
        self.chat.roll(limits.chat_per, now);
        if self.chat.spent.saturating_add(lines) > limits.chat_lines {
            return false;
        }
        self.chat.spent += lines;
        true
    }

    /// Spend `points` spam points, returning the window's total, and
    /// whether it is still under `spam_points`: mhxd kicks when a
    /// transaction brings the total to the budget, not past it.
    pub(crate) fn spam(&mut self, points: u32, limits: &FloodLimits, now: Instant) -> (u32, bool) {
        if limits.spam_points == 0 || limits.spam_per.is_zero() {
            return (0, true);
        }
        self.spam.roll(limits.spam_per, now);
        self.spam.spent = self.spam.spent.saturating_add(points);
        (self.spam.spent, self.spam.spent < limits.spam_points)
    }
}

/// How fast one ng session may ask, and one account post news
/// (`[limits]`), neither of which mhxd limits. `requests` is the weight
/// one session may spend at once, across every connection it resumes
/// on, earned back evenly over `requests_per`; `news_posts` the articles
/// and replies one account may post at once, earned back over
/// `news_posts_per`. A count of 0 is no
/// limit, which is what a `Core` built by hand has
/// ([`RequestLimits::default`]); a server built from a config has
/// [`RequestLimits::DEFAULT`] unless it says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RequestLimits {
    pub requests: u32,
    pub requests_per: Duration,
    pub news_posts: u32,
    pub news_posts_per: Duration,
}

impl RequestLimits {
    /// A burst of 40 and then 20 a second, in weight: joining a call
    /// with the camera on, and answering the renegotiations that brings,
    /// spends less than the burst even from a device trickling an ICE
    /// candidate for each of a dozen addresses, opening the news spends
    /// a few, and a person does not sustain twenty reads a second.
    /// Ten posts at once and then one each half minute: a thread's
    /// back-and-forth is slower than that, and a flood of a hundred
    /// takes most of an hour.
    pub const DEFAULT: RequestLimits = RequestLimits {
        requests: 40,
        requests_per: Duration::from_secs(2),
        news_posts: 10,
        news_posts_per: Duration::from_secs(300),
    };
}

/// A token bucket: `count` tokens when full, earned back evenly over
/// `per`, so a burst of the whole count and then a steady rate.
#[derive(Debug, Clone)]
pub struct RateBucket {
    count: u32,
    per: Duration,
    tokens: f64,
    at: Instant,
}

impl RateBucket {
    /// A full bucket, or `None` for no limit (a count or a period of 0).
    pub fn new(count: u32, per: Duration, now: Instant) -> Option<RateBucket> {
        (count != 0 && !per.is_zero()).then_some(RateBucket {
            count,
            per,
            tokens: f64::from(count),
            at: now,
        })
    }

    fn refill(&mut self, now: Instant) {
        let earned = now.saturating_duration_since(self.at).as_secs_f64() * f64::from(self.count)
            / self.per.as_secs_f64();
        self.tokens = (self.tokens + earned).min(f64::from(self.count));
        self.at = self.at.max(now);
    }

    /// Spend `cost`, or say how long until it could be: nothing is spent
    /// by a refusal. A cost past the whole bucket costs the whole
    /// bucket, so that no request is refused forever.
    pub fn spend(&mut self, cost: u32, now: Instant) -> Result<(), Duration> {
        if let Some(wait) = self.wait(cost, now) {
            return Err(wait);
        }
        self.tokens -= f64::from(cost.min(self.count));
        Ok(())
    }

    /// How long until `cost` could be spent, or `None` when it could be
    /// now; spending nothing.
    pub fn wait(&mut self, cost: u32, now: Instant) -> Option<Duration> {
        self.refill(now);
        let cost = f64::from(cost.min(self.count));
        (self.tokens < cost).then(|| {
            Duration::from_secs_f64(
                (cost - self.tokens) * self.per.as_secs_f64() / f64::from(self.count),
            )
        })
    }

    /// Spend `cost` whether it is there or not, down to empty: for what
    /// is counted but never refused.
    pub fn charge(&mut self, cost: u32, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - f64::from(cost)).max(0.0);
    }

    /// Give back `cost` spent on something that did not happen, up to
    /// full.
    pub fn refund(&mut self, cost: u32, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens + f64::from(cost)).min(f64::from(self.count));
    }

    fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= f64::from(self.count)
    }
}

/// Whose news posts a bucket counts: an account's, by the mailbox rule,
/// or one session's when it is not one person — a guest, whose login
/// every other guest shares and whose posts must not stop theirs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PostKey {
    Account(Option<[u8; 32]>, String),
    Session(u64),
}

/// Every account's news-post bucket ([`RequestLimits::news_posts`]).
#[derive(Debug, Default)]
pub(crate) struct PostRates(Mutex<HashMap<PostKey, RateBucket>>);

impl PostRates {
    /// Take one post from `key`'s bucket, or say how long until one is
    /// there; a refusal takes nothing. Taken before the post is made, so
    /// two sessions of one account posting at once cannot both be let
    /// through on the one post that was left, and given back by
    /// [`Self::refund`] when the post is then refused for what it says.
    pub(crate) fn reserve(
        &self,
        key: PostKey,
        limits: &RequestLimits,
        now: Instant,
    ) -> Result<(), Duration> {
        let Some(fresh) = RateBucket::new(limits.news_posts, limits.news_posts_per, now) else {
            return Ok(());
        };
        self.with(key, fresh, now, |b| b.spend(1, now))
    }

    /// Give back a post [`Self::reserve`] took for one that did not land.
    pub(crate) fn refund(&self, key: &PostKey, now: Instant) {
        if let Some(b) = self.0.lock().unwrap().get_mut(key) {
            b.refund(1, now);
        }
    }

    /// Count one post of `key`'s, whether or not there was one left: a
    /// post that has landed has been made.
    pub(crate) fn count(&self, key: PostKey, limits: &RequestLimits, now: Instant) {
        let Some(fresh) = RateBucket::new(limits.news_posts, limits.news_posts_per, now) else {
            return;
        };
        self.with(key, fresh, now, |b| b.charge(1, now));
    }

    fn with<T>(
        &self,
        key: PostKey,
        fresh: RateBucket,
        now: Instant,
        f: impl FnOnce(&mut RateBucket) -> T,
    ) -> T {
        let mut by = self.0.lock().unwrap();
        // An account whose bucket has filled again is forgotten, so the
        // table holds only those that posted a moment ago.
        if by.len() > 4096 {
            by.retain(|_, b| !b.full(now));
        }
        f(by.entry(key).or_insert(fresh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(per_addr: usize, reconnect: Duration) -> ConnGate {
        ConnGate::new(ConnLimits {
            per_addr,
            reconnect,
            exempt: AddrSet::parse(&["127.0.0.0/8"]).unwrap(),
        })
    }

    #[test]
    fn an_address_holds_at_most_its_share_of_connections() {
        let g = gate(2, Duration::ZERO);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let a = g.admit(ip).unwrap();
        let _b = g.admit(ip).unwrap();
        assert_eq!(g.admit(ip).err(), Some(ConnRefused::TooMany));
        assert!(
            g.admit("192.0.2.2".parse().unwrap()).is_ok(),
            "another address"
        );
        drop(a);
        assert!(g.admit(ip).is_ok(), "a place came back");
    }

    #[test]
    fn past_its_burst_an_address_waits_to_connect_again() {
        let g = gate(3, Duration::from_millis(200));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..3 {
            drop(g.admit(ip).unwrap());
        }
        assert_eq!(g.admit(ip).err(), Some(ConnRefused::TooFast));
        std::thread::sleep(Duration::from_millis(250));
        assert!(g.admit(ip).is_ok(), "one more, earned");
        assert_eq!(g.admit(ip).err(), Some(ConnRefused::TooFast));
    }

    #[test]
    fn with_no_cap_the_reconnect_burst_is_mhxds() {
        let g = gate(0, Duration::from_secs(60));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..CONNECTIONS_PER_ADDR)
            .map(|_| g.admit(ip).expect("within the burst"))
            .collect();
        assert_eq!(g.admit(ip).err(), Some(ConnRefused::TooFast));
        drop(held);
        assert_eq!(
            g.admit(ip).err(),
            Some(ConnRefused::TooFast),
            "closing gives no burst back"
        );
    }

    #[test]
    fn the_table_forgets_idle_addresses() {
        let g = gate(2, Duration::ZERO);
        let busy: IpAddr = "198.51.100.1".parse().unwrap();
        let _held = g.admit(busy).unwrap();
        let len = || g.0.by_addr.lock().unwrap().map.len();
        for i in 0..PRUNE_FLOOR as u32 - 1 {
            drop(
                g.admit(IpAddr::from((0x0a00_0000 + i).to_be_bytes()))
                    .unwrap(),
            );
        }
        assert_eq!(len(), PRUNE_FLOOR, "not yet walked");
        drop(g.admit("203.0.113.1".parse().unwrap()).unwrap());
        assert_eq!(len(), 2, "the busy address and the newest are left");
        let _again = g.admit(busy).unwrap();
        assert_eq!(
            g.admit(busy).err(),
            Some(ConnRefused::TooMany),
            "the busy address kept its count"
        );
    }

    #[test]
    fn an_ipv6_client_is_its_64_and_loopback_is_exempt() {
        let g = gate(1, Duration::ZERO);
        let _a = g.admit("2001:db8:1:2::1".parse().unwrap()).unwrap();
        assert_eq!(
            g.admit("2001:db8:1:2:ffff::9".parse().unwrap()).err(),
            Some(ConnRefused::TooMany),
            "the same /64"
        );
        assert!(g.admit("2001:db8:1:3::1".parse().unwrap()).is_ok());
        let _b = g.admit("192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(
            g.admit("::ffff:192.0.2.1".parse().unwrap()).err(),
            Some(ConnRefused::TooMany),
            "a mapped address is the IPv4 one"
        );
        for _ in 0..10 {
            std::mem::forget(g.admit("127.0.0.1".parse().unwrap()).unwrap());
        }
    }

    #[test]
    fn chat_lines_are_counted_as_mhxd_cuts_them() {
        assert_eq!(chat_lines("one"), 1);
        assert_eq!(chat_lines(""), 1);
        assert_eq!(chat_lines("one\rtwo"), 2);
        // The empty pieces count too: between a CR and its LF, and after
        // the last break.
        assert_eq!(chat_lines("one\r\ntwo\r"), 4);
    }

    #[test]
    fn a_session_talks_up_to_its_window_and_then_a_new_one_opens() {
        let limits = FloodLimits {
            chat_lines: 3,
            chat_per: Duration::from_secs(5),
            spam_points: 10,
            spam_per: Duration::from_secs(5),
            ban_for: Duration::ZERO,
        };
        let mut f = Flood::default();
        let t = Instant::now();
        assert!(f.chat(2, &limits, t));
        assert!(!f.chat(2, &limits, t), "a send that would cross it");
        assert!(f.chat(1, &limits, t), "the refused one spent nothing");
        assert!(!f.chat(1, &limits, t + Duration::from_secs(4)));
        // A fixed window, not a rate: it all comes back at once.
        assert!(f.chat(3, &limits, t + Duration::from_secs(5)));

        assert_eq!(f.spam(4, &limits, t), (4, true));
        assert_eq!(f.spam(4, &limits, t), (8, true));
        assert_eq!(f.spam(2, &limits, t), (10, false), "reaching it is enough");
        assert_eq!(f.spam(2, &limits, t + Duration::from_secs(5)), (2, true));

        let none = FloodLimits::default();
        for _ in 0..1000 {
            assert!(f.chat(100, &none, t));
            assert!(f.spam(100, &none, t).1);
        }
    }

    #[test]
    fn a_rate_admits_its_burst_then_says_how_long_to_wait() {
        let g = RateGate::new(3, Duration::from_secs(10), AddrSet::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t = Instant::now();
        for _ in 0..3 {
            assert!(g.at(ip, t, true).is_ok());
        }
        let wait = g.at(ip, t, true).unwrap_err();
        assert!(
            wait > Duration::from_secs(9) && wait <= Duration::from_secs(10),
            "{wait:?}"
        );
        assert!(
            g.at("192.0.2.2".parse().unwrap(), t, true).is_ok(),
            "another address"
        );
        let later = t + Duration::from_secs(10);
        assert!(g.at(ip, later, true).is_ok(), "one earned");
        assert!(g.at(ip, later, true).is_err());
        // An IPv6 client is its /64 here too.
        let v6 = RateGate::new(1, Duration::from_secs(60), AddrSet::default());
        assert!(v6.take("2001:db8::1".parse().unwrap()).is_ok());
        assert!(v6.take("2001:db8::2".parse().unwrap()).is_err());
    }

    #[test]
    fn a_refund_gives_back_what_a_take_spent_and_no_more() {
        let g = RateGate::new(2, Duration::from_secs(60), AddrSet::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // Refunded before anything was spent, the burst stays the burst.
        g.refund(ip);
        g.refund(ip);
        assert!(g.take(ip).is_ok());
        assert!(g.take(ip).is_ok());
        assert!(g.take(ip).is_err(), "none left");
        g.refund(ip);
        assert!(g.take(ip).is_ok(), "one given back");
        assert!(g.take(ip).is_err());
    }

    #[test]
    fn a_rate_table_is_walked_seldom_and_held_to_its_cap() {
        // Nothing earns its whole burst back in the test's lifetime, so no
        // walk can forget an address for being full again.
        let g = RateGate::new(1, Duration::from_secs(3600), AddrSet::default());
        let addr = |i: u32| IpAddr::from((0x0a00_0000 + i).to_be_bytes());
        let spread = RATE_CAP as u32 * 2;
        for i in 0..spread {
            assert!(g.take(addr(i)).is_ok());
            assert!(g.by_addr.lock().unwrap().map.len() <= RATE_CAP);
        }
        // Doubling up to the cap, then a quarter of it between walks.
        let walks = g.by_addr.lock().unwrap().walks;
        assert!(walks <= 16, "walked {walks} times");
        for i in spread - 64..spread {
            assert!(
                g.take(addr(i)).is_err(),
                "an address that spent lately is not the one forgotten"
            );
        }
        assert!(g.take(addr(0)).is_ok(), "the fullest were forgotten");
        assert!(
            g.take("203.0.113.1".parse().unwrap()).is_ok(),
            "a new address is admitted with the table full"
        );
    }

    #[test]
    fn a_rate_of_zero_and_an_exempt_address_are_not_limited() {
        let off = RateGate::per_minute(0, AddrSet::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..100 {
            assert!(off.take(ip).is_ok());
        }
        let g = RateGate::per_minute(1, AddrSet::parse(&["127.0.0.0/8"]).unwrap());
        for _ in 0..100 {
            assert!(g.take("127.0.0.1".parse().unwrap()).is_ok());
        }
        assert!(g.take(ip).is_ok());
        assert!(g.take(ip).is_err());
    }

    #[test]
    fn failed_logins_lock_an_address_out_until_it_earns_one_back() {
        let core = Core::new()
            .with_conn_limits(ConnLimits {
                exempt: AddrSet::default(),
                ..ConnLimits::default()
            })
            .with_login_limits(LoginLimits {
                failures: 2,
                every: Duration::from_millis(200),
            });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let pw = b"wrong".as_slice();
        core.login_failed(core.login_attempt(ip, pw).unwrap());
        core.login_failed(core.login_attempt(ip, pw).expect("one mistake"));
        assert!(core.login_attempt(ip, pw).is_err(), "locked out");
        core.login_refund(
            core.login_attempt("192.0.2.2".parse().unwrap(), pw)
                .unwrap(),
        );
        // An empty password is a guest's, and is neither refused nor
        // counted.
        for _ in 0..5 {
            core.login_failed(core.login_attempt(ip, b"").expect("no password"));
        }
        std::thread::sleep(Duration::from_millis(250));
        core.login_refund(core.login_attempt(ip, pw).expect("one earned back"));
        core.login_refund(
            core.login_attempt(ip, pw)
                .expect("a right password costs nothing"),
        );
        // A core built by hand is not limited.
        let open = Core::new();
        for _ in 0..50 {
            open.login_failed(open.login_attempt(ip, pw).unwrap());
        }
        assert!(open.login_attempt(ip, pw).is_ok());
    }

    #[test]
    fn attempts_in_flight_at_once_are_held_to_the_limit() {
        // Every attempt spends its failure as it is let in, so attempts
        // waiting on their answers at once cannot all pass a check none
        // of them has yet failed.
        let core = Core::new()
            .with_conn_limits(ConnLimits {
                exempt: AddrSet::default(),
                ..ConnLimits::default()
            })
            .with_login_limits(LoginLimits {
                failures: 3,
                every: Duration::from_secs(60),
            });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..20)
            .filter_map(|_| core.login_attempt(ip, b"guess").ok())
            .collect();
        assert_eq!(held.len(), 3);
        for a in held {
            core.login_failed(a);
        }
        assert!(core.login_attempt(ip, b"guess").is_err());
    }

    #[test]
    fn a_set_parses_blocks_and_matches_across_the_mapping() {
        let s = AddrSet::parse(&["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]).unwrap();
        assert!(s.contains("10.1.2.3".parse().unwrap()));
        assert!(s.contains("::ffff:192.0.2.7".parse().unwrap()));
        assert!(s.contains("2001:db8:9::1".parse().unwrap()));
        assert!(!s.contains("11.0.0.1".parse().unwrap()));
        assert!(AddrSet::parse(&["10.0.0.0/33"]).is_err());
        assert!(AddrSet::parse(&["nope"]).is_err());
    }

    #[test]
    fn a_bucket_spends_its_burst_then_its_rate_and_says_how_long() {
        let t = Instant::now();
        let mut b = RateBucket::new(4, Duration::from_secs(2), t).unwrap();
        b.spend(2, t).unwrap();
        b.spend(2, t).unwrap();
        let wait = b.spend(1, t).unwrap_err();
        assert_eq!(
            wait,
            Duration::from_millis(500),
            "one token every half second"
        );
        // A refusal spends nothing: half a second later the one is there.
        let t = t + Duration::from_millis(500);
        b.spend(1, t).unwrap();
        // A weight past the bucket costs the bucket rather than never
        // being allowed.
        let t = t + Duration::from_secs(10);
        b.spend(9, t).unwrap();
        assert!(b.spend(1, t).is_err());
        assert!(RateBucket::new(0, Duration::from_secs(1), t).is_none());
        assert!(RateBucket::new(5, Duration::ZERO, t).is_none());
    }

    #[test]
    fn a_charge_is_never_refused_but_empties_the_bucket() {
        let t = Instant::now();
        let mut b = RateBucket::new(2, Duration::from_secs(10), t).unwrap();
        for _ in 0..5 {
            b.charge(1, t);
        }
        assert_eq!(
            b.spend(1, t),
            Err(Duration::from_secs(5)),
            "empty, not in debt"
        );
    }

    #[test]
    fn posts_are_counted_by_account_and_a_guest_by_its_session() {
        let limits = RequestLimits {
            news_posts: 2,
            news_posts_per: Duration::from_secs(60),
            ..RequestLimits::default()
        };
        let rates = PostRates::default();
        let t = Instant::now();
        let alice = || PostKey::Account(None, "alice".into());
        rates.reserve(alice(), &limits, t).unwrap();
        // A post refused for what it says is given back.
        rates.refund(&alice(), t);
        rates.reserve(alice(), &limits, t).unwrap();
        rates.reserve(alice(), &limits, t).unwrap();
        assert_eq!(
            rates.reserve(alice(), &limits, t),
            Err(Duration::from_secs(30)),
            "taken when asked, so a second asker finds it gone"
        );
        // Counted past the limit, as a post on the other wire is.
        rates.count(alice(), &limits, t);
        assert_eq!(
            rates.reserve(alice(), &limits, t),
            Err(Duration::from_secs(30)),
            "empty, not in debt"
        );
        rates.count(PostKey::Session(7), &limits, t);
        rates.count(PostKey::Session(8), &limits, t);
        rates.count(PostKey::Session(8), &limits, t);
        rates.reserve(PostKey::Session(7), &limits, t).unwrap();
        assert!(rates.reserve(PostKey::Session(8), &limits, t).is_err());
        assert_eq!(
            rates.reserve(alice(), &RequestLimits::default(), t),
            Ok(()),
            "no limit"
        );
    }
}
