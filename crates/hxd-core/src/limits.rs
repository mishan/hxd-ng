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
//! **Accounts.** Those two hold a connection only until it logs in.
//! Carrier-grade NAT puts many unrelated people behind one IPv4
//! address, mobile carriers most of all, so an address is a fair bound
//! on connections nobody has vouched for and a poor one on people who
//! have: a connection that logs in as an account with one person
//! behind it ([`crate::Account::is_person`]) gives its address back its
//! place and holds one in its account's count ([`ConnLimits::per_account`])
//! for the rest of its life ([`Core::admit_account`]). A guest, or any
//! account with neither a password nor an identity, is nobody in
//! particular, and stays counted against its address. An account at its
//! cap is refused the login, with a reason, on either wire.
//!
//! The reconnect rate is not moved the same way. The new connection a
//! login was made on stays spent from its address's burst, and the login
//! spends one from its account's as well, so a person reconnects at the
//! lower of the two rates: an address cannot log in faster than it can
//! connect however many accounts it spreads its logins over, and an
//! account cannot log in faster than its own rate from however many
//! addresses, exempt ones included. A login its account's rate refuses
//! is told how long to wait, on either wire.
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
//! ([`Core::login_attempt`], [`LoginLimits`]): by the address and the
//! login it guessed at, so a guesser behind a shared address locks out
//! the account it is guessing and not everyone else behind the address,
//! and by the address alone against a looser ceiling, so one address
//! cannot guess across every account there is.
//!
//! **Addresses.** An IPv4 address is itself; an IPv6 one is its /64,
//! which is what one subscriber is given, so a client cannot step past
//! the cap by walking its own prefix. An IPv4 address mapped into IPv6
//! is the IPv4 address. A subscriber is as often given a /56 or a /48,
//! though, which is hundreds or tens of thousands of /64s, each an
//! address of its own; so the connections a /48 holds are counted
//! again, to a wider cap ([`ConnLimits::per_v6_48`]), and a connection
//! must fit under both. IPv4 has no wider count: its addresses are dear
//! enough that one client does not hold many, and the neighbors in a
//! /24 are as likely a carrier's NAT pool or a campus of strangers as
//! one person. The /48's count is an address's like the /64's, so a
//! connection that logs in as a person gives both back when its place
//! moves to its account (**Accounts**, above). Addresses in `exempt`
//! are held to none of the
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

/// The IPv6 /48 an address is in, whose connections are counted
/// together as well as by /64; `None` for IPv4, which has no wider count
/// (`crate::limits`).
fn v6_48(ip: IpAddr) -> Option<IpAddr> {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[6..].fill(0);
            Some(IpAddr::from(o))
        }
        IpAddr::V4(_) => None,
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
    /// Connections the /64s of one IPv6 /48 may hold at once between
    /// them, beside each one's `per_addr`; 0 is no limit. An exempt
    /// address's connections are not counted toward it, and like
    /// `per_addr` it counts a connection only until it logs in as a
    /// person ([`ConnGate::admit_account`]).
    pub per_v6_48: usize,
    /// How often one address earns another new connection once it has
    /// spent its burst; zero is no rate limit.
    pub reconnect: Duration,
    /// Connections one account may hold at once once they have logged
    /// in ([`Core::admit_account`]); 0 is no limit. It is also the
    /// account's own burst of new connections, earned back at
    /// `reconnect` as an address's is, with [`CONNECTIONS_PER_ACCOUNT`]
    /// standing in when there is no limit. Held from every address,
    /// exempt ones included: it is the account's limit, not an
    /// address's.
    pub per_account: usize,
    /// Addresses not limited.
    pub exempt: AddrSet,
}

impl Default for ConnLimits {
    fn default() -> Self {
        ConnLimits {
            per_addr: CONNECTIONS_PER_ADDR,
            per_v6_48: CONNECTIONS_PER_V6_48,
            reconnect: RECONNECT_EVERY,
            per_account: CONNECTIONS_PER_ACCOUNT,
            exempt: AddrSet::parse(&["127.0.0.0/8", "::1"]).expect("loopback parses"),
        }
    }
}

/// mhxd's `conn_max`.
pub const CONNECTIONS_PER_ADDR: usize = 5;
/// Four addresses' worth, not mhxd's, which counted an IPv6 address as
/// itself: a site with a few machines on a few /64s of its delegation
/// is not held to one machine's share, and one client walking its /48
/// is held to a few machines' rather than to tens of thousands.
pub const CONNECTIONS_PER_V6_48: usize = 4 * CONNECTIONS_PER_ADDR;
/// mhxd's `reconn_time`.
pub const RECONNECT_EVERY: Duration = Duration::from_secs(2);
/// Connections one account may hold. Twice what mhxd let one address
/// hold, which was a household's worth of one person's machines: a
/// phone, a laptop and a desktop each with a classic client and an ng
/// one open fit with room left, and an ng session that has dropped its
/// socket holds none.
pub const CONNECTIONS_PER_ACCOUNT: usize = 10;

/// Why a connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnRefused {
    /// The address already holds as many as it may.
    TooMany,
    /// The address has been connecting faster than it may.
    TooFast,
    /// The address's IPv6 /48 already holds as many as it may.
    TooManyIn48,
}

impl ConnRefused {
    /// For the disconnect metric.
    pub fn reason(self) -> &'static str {
        match self {
            ConnRefused::TooMany => "too_many",
            ConnRefused::TooFast => "too_fast",
            ConnRefused::TooManyIn48 => "too_many_48",
        }
    }
}

/// Why a login, or a resume, was refused a place in its account's count
/// ([`ConnGate::admit_account`]): the frontend refuses it with a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountRefused {
    /// The account holds as many connections as it may
    /// ([`ConnLimits::per_account`]). Waiting does not help; closing one
    /// of the others does.
    Full,
    /// The account has spent its burst of new connections, and earns
    /// the next one back in this long ([`ConnLimits::reconnect`]).
    TooFast(Duration),
}

impl AccountRefused {
    /// For the metric and the log.
    pub fn reason(self) -> &'static str {
        match self {
            AccountRefused::Full => "too_many",
            AccountRefused::TooFast(_) => "too_fast",
        }
    }
}

/// The connections each address holds, and what it has spent of its
/// burst, and the same for each account a connection has logged in as.
/// The core keeps one for every connection that can carry a session
/// ([`Core::admit_connection`]); a frontend may keep another for
/// connections of its own that do not.
#[derive(Default)]
pub struct ConnGate(Arc<GateInner>);

#[derive(Default)]
pub(crate) struct GateInner {
    limits: ConnLimits,
    by_addr: Mutex<Table>,
}

/// The addresses and accounts the gate remembers, and how large each
/// table may grow before it is next pruned; and the connections each
/// IPv6 /48 holds.
#[derive(Default)]
struct Table {
    map: HashMap<IpAddr, AddrState>,
    prune_at: usize,
    accounts: HashMap<Box<str>, AddrState>,
    accounts_prune_at: usize,
    /// A /48 is here only while it holds a connection: it has no burst
    /// to remember, so it is forgotten as its last place is given back
    /// and never needs a walk of its own.
    by_48: HashMap<IpAddr, usize>,
}

/// The fewest addresses the table is let grow to before a prune.
const PRUNE_FLOOR: usize = 4096;

struct AddrState {
    live: usize,
    /// New connections the address may still make at once.
    tokens: f64,
    at: Instant,
}

/// One connection's place in its address's count, and in its /48's
/// when that is counted, or once it has logged in as a person in its
/// account's alone; dropping it gives back whichever it holds.
pub struct ConnPermit {
    gate: Option<(Arc<GateInner>, Place)>,
    /// A place the same connection holds in another gate's count, given
    /// up with the address's at login ([`ConnPermit::carry`]).
    carried: Option<SharedPlace>,
}

/// Whose count a [`ConnPermit`] holds a place in.
enum Place {
    /// An address as [`limit_key`] has it, and its IPv6 /48 when that is
    /// counted.
    Addr(IpAddr, Option<IpAddr>),
    Account(Box<str>),
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        if let Some((gate, place)) = self.gate.take() {
            let mut by = gate.by_addr.lock().unwrap();
            match &place {
                Place::Addr(key, wide) => {
                    by.release_addr(*key, *wide);
                }
                Place::Account(login) => {
                    if let Some(s) = by.accounts.get_mut(login) {
                        s.live = s.live.saturating_sub(1);
                    }
                }
            }
        }
    }
}

impl Table {
    /// Give back a place in `key`'s count, and in `wide`'s, the /48 it
    /// is in, when that is counted: the two are taken together
    /// ([`ConnGate::admit`]) and always given back together, whether the
    /// connection drops or moves to its account's count.
    fn release_addr(&mut self, key: IpAddr, wide: Option<IpAddr>) {
        if let Some(wide) = wide {
            if let Some(n) = self.by_48.get_mut(&wide) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.by_48.remove(&wide);
                }
            }
        }
        if let Some(s) = self.map.get_mut(&key) {
            s.live = s.live.saturating_sub(1);
        }
    }
}

impl ConnPermit {
    /// A place in no count: the gate held this connection to nothing.
    fn free() -> ConnPermit {
        ConnPermit {
            gate: None,
            carried: None,
        }
    }

    /// Give up `other` along with this permit's place in its address's
    /// count when the connection logs in as a person
    /// ([`ConnGate::admit_account`]). The ng port counts a connection by
    /// address in a gate of its own from accept, and a socket that has
    /// logged in is no longer its address's to count there either.
    pub fn carry(&mut self, other: SharedPlace) {
        self.carried = Some(other);
    }

    /// Does this permit hold a place in an account's count?
    pub fn is_account(&self) -> bool {
        matches!(self.gate, Some((_, Place::Account(_))))
    }
}

/// A connection's place in a count, shared between whoever holds the
/// connection and whoever may give the place up early: the ng port's
/// socket holds its per-address place in one, and the session it
/// carries gives it up at login ([`ConnPermit::carry`]).
#[derive(Clone, Default)]
pub struct SharedPlace(Arc<Mutex<Option<ConnPermit>>>);

impl SharedPlace {
    pub fn new(place: Option<ConnPermit>) -> SharedPlace {
        SharedPlace(Arc::new(Mutex::new(place)))
    }

    /// Give the place back now, rather than when the last holder goes.
    pub fn release(&self) {
        let place = self.0.lock().unwrap().take();
        drop(place);
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
        if (l.per_addr == 0 && l.per_v6_48 == 0 && l.reconnect.is_zero()) || l.exempt.contains(ip) {
            return Ok(ConnPermit::free());
        }
        let key = limit_key(ip);
        let wide = if l.per_v6_48 == 0 { None } else { v6_48(ip) };
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
        let Table { map, by_48, .. } = &mut *by;
        let s = map.entry(key).or_insert(AddrState {
            live: 0,
            tokens: burst,
            at: now,
        });
        s.tokens = refill(s, now, l.reconnect, burst);
        s.at = now;
        if l.per_addr != 0 && s.live >= l.per_addr {
            return Err(ConnRefused::TooMany);
        }
        // Asked before the burst is spent: a connection the /48 refuses
        // costs its address nothing, as one its own count refuses does.
        if let Some(wide) = wide {
            if by_48.get(&wide).copied().unwrap_or(0) >= l.per_v6_48 {
                return Err(ConnRefused::TooManyIn48);
            }
        }
        if !l.reconnect.is_zero() {
            if s.tokens < 1.0 {
                return Err(ConnRefused::TooFast);
            }
            s.tokens -= 1.0;
        }
        s.live += 1;
        if let Some(wide) = wide {
            *by_48.entry(wide).or_insert(0) += 1;
        }
        Ok(ConnPermit {
            gate: Some((gate.clone(), Place::Addr(key, wide))),
            carried: None,
        })
    }

    /// Move `place` from its address's count to `login`'s, or refuse
    /// with [`AccountRefused`] and leave it where it was. `slack` places
    /// past the cap are allowed: a resume that takes a session over from
    /// a connection that has not yet noticed it is gone holds one more
    /// than the account has sessions, for a moment.
    ///
    /// The address is given back its place, and its IPv6 /48 the place
    /// it held there, but not the new connection the address spent of
    /// its burst: the login spends one of the account's too, or is
    /// refused [`AccountRefused::TooFast`] when the account has none
    /// left. Each login so costs both, and neither an address logging in
    /// as many accounts nor an account logging in from many addresses
    /// goes faster than the slower of its two rates. A place given back
    /// to an address exempt from its limits, or to a gate that holds
    /// addresses to none, is nothing given back; the account is held to
    /// its rate all the same. A permit already in an account's count
    /// stays where it is.
    pub fn admit_account(
        &self,
        place: &mut ConnPermit,
        login: &str,
        slack: usize,
    ) -> Result<(), AccountRefused> {
        if place.is_account() {
            return Ok(());
        }
        let gate = &self.0;
        assert!(
            place
                .gate
                .as_ref()
                .is_none_or(|(g, _)| Arc::ptr_eq(g, gate)),
            "a place moves to an account in the gate that counted it"
        );
        let l = &gate.limits;
        let now = Instant::now();
        let burst_account = burst_of(l.per_account, CONNECTIONS_PER_ACCOUNT);
        let mut guard = gate.by_addr.lock().unwrap();
        let by = &mut *guard;
        // As the address table is: an account that holds nothing and has
        // its burst back is forgotten, once the table has doubled.
        if by.accounts.len() >= by.accounts_prune_at.max(PRUNE_FLOOR) {
            by.accounts.retain(|_, s| {
                s.live > 0 || refill(s, now, l.reconnect, burst_account) < burst_account
            });
            by.accounts_prune_at = by.accounts.len().saturating_mul(2);
        }
        let key: Box<str> = login.into();
        let a = by.accounts.entry(key.clone()).or_insert(AddrState {
            live: 0,
            tokens: burst_account,
            at: now,
        });
        a.tokens = refill(a, now, l.reconnect, burst_account);
        a.at = now;
        if l.per_account != 0 && a.live >= l.per_account.saturating_add(slack) {
            return Err(AccountRefused::Full);
        }
        if !l.reconnect.is_zero() {
            if a.tokens < 1.0 {
                return Err(AccountRefused::TooFast(l.reconnect.mul_f64(1.0 - a.tokens)));
            }
            a.tokens -= 1.0;
        }
        a.live += 1;
        if let Some((_, Place::Addr(addr, wide))) = &place.gate {
            // The /48's place goes with the address's: it counts the
            // connections its addresses hold, and this one is no longer
            // an address's.
            by.release_addr(*addr, *wide);
        }
        drop(guard);
        // The address's place was given back above, under the lock; the
        // permit now holds the account's, and dropping it gives that back.
        place.gate = Some((gate.clone(), Place::Account(key)));
        if let Some(carried) = place.carried.take() {
            carried.release();
        }
        Ok(())
    }
}

/// A rate one address is held to: a burst of `burst`, then one more
/// every `every`. Past it the caller is told how long until the next.
/// A `burst` of 0, or a zero `every`, is no limit; `exempt` addresses are
/// never limited. What the gate counts is the caller's: a request, or a
/// failed login ([`RateGate::take`] before it is known, and
/// [`RateGate::refund`] once it is known not to count). A gate may
/// count an address as a whole, or an address and a name within it
/// ([`RateGate::take_named`]) — the login a password was a guess at —
/// each with a bucket of its own.
pub struct RateGate {
    burst: f64,
    every: Duration,
    exempt: AddrSet,
    by_addr: Mutex<RateTable>,
}

/// What a [`RateGate`] counts: an address, as [`limit_key`] has it, and
/// the name within it when the gate counts by name.
type RateKey = (IpAddr, Option<Box<str>>);

/// The keys a [`RateGate`] remembers, and how large the table may grow
/// before it is next walked.
#[derive(Default)]
struct RateTable {
    map: HashMap<RateKey, AddrBucket>,
    prune_at: usize,
    /// How many times the table has been walked, for the tests.
    #[cfg(test)]
    walks: usize,
}

/// What one address has left of a [`RateGate`]'s burst, as of `at`.
#[derive(Debug)]
struct AddrBucket {
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
        self.at(ip, None, Instant::now(), true)
    }

    /// [`take`](Self::take), from the bucket `ip` has for `name` rather
    /// than the one it has as a whole. Each name `ip` uses has a bucket
    /// of its own, and another address's use of the same name costs
    /// this one nothing.
    pub fn take_named(&self, ip: IpAddr, name: &str) -> Result<(), Duration> {
        self.at(ip, Some(name), Instant::now(), true)
    }

    /// Give back one [`take`](Self::take) spent: what it admitted turned
    /// out not to be what the gate counts. The bucket does not go above
    /// its burst.
    pub fn refund(&self, ip: IpAddr) {
        self.refund_to(ip, None);
    }

    /// Give back one [`take_named`](Self::take_named) spent.
    pub fn refund_named(&self, ip: IpAddr, name: &str) {
        self.refund_to(ip, Some(name));
    }

    fn refund_to(&self, ip: IpAddr, name: Option<&str>) {
        if self.off(ip) {
            return;
        }
        let now = Instant::now();
        let mut by = self.by_addr.lock().unwrap();
        let burst = self.burst;
        let b = self.bucket(&mut by, key_of(ip, name), now);
        b.tokens = (b.tokens + 1.0).min(burst);
    }

    fn bucket<'a>(&self, by: &'a mut RateTable, key: RateKey, now: Instant) -> &'a mut AddrBucket {
        let (burst, every) = (self.burst, self.every);
        let earned = |b: &AddrBucket| {
            (b.tokens + now.duration_since(b.at).as_secs_f64() / every.as_secs_f64()).min(burst)
        };
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
                let mut fill: Vec<(f64, RateKey)> =
                    by.map.iter().map(|(k, b)| (earned(b), k.clone())).collect();
                fill.select_nth_unstable_by(keep, |a, b| a.0.total_cmp(&b.0));
                for (_, k) in &fill[keep..] {
                    by.map.remove(k);
                }
            }
            by.prune_at = by.map.len().saturating_mul(2).min(RATE_CAP);
        }
        let b = by.map.entry(key).or_insert(AddrBucket {
            tokens: burst,
            at: now,
        });
        b.tokens = earned(b);
        b.at = now;
        b
    }

    fn at(
        &self,
        ip: IpAddr,
        name: Option<&str>,
        now: Instant,
        spend: bool,
    ) -> Result<(), Duration> {
        if self.off(ip) {
            return Ok(());
        }
        let every = self.every;
        let mut by = self.by_addr.lock().unwrap();
        let b = self.bucket(&mut by, key_of(ip, name), now);
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
/// `failures` at each login it guesses at, then one more every `every`,
/// and a burst of `failures_per_addr` across every login together, then
/// one more every `every` too. Past either the address is refused before
/// its password for that login is checked, until it has earned one back
/// — a right password included, or guessing would go on. A count of 0
/// is no limit, which is what a `Core` built by hand has; a server built
/// from a config has [`LoginLimits::RECOMMENDED`] unless it says
/// otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LoginLimits {
    pub failures: u32,
    pub failures_per_addr: u32,
    pub every: Duration,
}

impl LoginLimits {
    /// Ten wrong passwords at once for one login, then one every thirty
    /// seconds: a person who mistypes is never refused, a guesser gets a
    /// hundred and twenty an hour at any one account.
    ///
    /// Fifty across every login from one address, earned back at the
    /// same rate. The burst is five people's worth of mistakes, so the
    /// people behind one carrier's address are not refused for each
    /// other's typing, and the rate is what the address as a whole was
    /// held to when failures were counted by address alone: over any
    /// window longer than the burst, no address guesses faster than it
    /// could before failures were counted by login, however many
    /// accounts it spreads its guesses over.
    pub const RECOMMENDED: LoginLimits = LoginLimits {
        failures: 10,
        failures_per_addr: 50,
        every: Duration::from_secs(30),
    };
}

/// The name a failed login is counted under: the login as the accounts
/// backend reads it — ASCII case folded, and an empty one the guest
/// account, as `AuthBackend::authenticate` has it — cut to a length no
/// login reaches, so one a client makes up cannot make the table large.
pub fn login_key(login: &str) -> String {
    const MAX: usize = 64;
    let login = if login.is_empty() { "guest" } else { login };
    let mut end = login.len().min(MAX);
    while !login.is_char_boundary(end) {
        end -= 1;
    }
    login[..end].to_ascii_lowercase()
}

/// A password about to be checked, holding the failure it will count
/// as if it is wrong ([`Core::login_attempt`]). Settle it with
/// [`Core::login_failed`] or [`Core::login_refund`] once the answer is
/// in; one dropped unsettled counts as a failure.
#[derive(Debug)]
#[must_use = "settle it with Core::login_failed or Core::login_refund"]
pub struct LoginAttempt {
    /// The address, and the login within it, whose failure was spent;
    /// `None` when nothing was.
    held: Option<(IpAddr, String)>,
}

impl Core {
    /// Hold failed logins to `limits` rather than
    /// [`LoginLimits::default`]. Addresses exempt from `[limits]` are
    /// held to none.
    pub fn with_login_limits(mut self, limits: LoginLimits) -> Self {
        self.login_failures = RateGate::new(limits.failures, limits.every, AddrSet::default());
        self.login_failures_per_addr =
            RateGate::new(limits.failures_per_addr, limits.every, AddrSet::default());
        self
    }

    /// May `addr` try `password` for `login` now? `Err` says how long
    /// until it may: it has failed as often as it may for now, at that
    /// login or at every login together, and the frontend refuses the
    /// login without checking it. Asked before every password is
    /// checked, on every wire, with the login the password is for as the
    /// client sent it (canonicalized here, [`login_key`]).
    ///
    /// Counted by login within an address so that a guesser behind a
    /// carrier's shared address locks out only the account it is
    /// guessing at, and not everyone else behind the address; and by the
    /// address as a whole against a looser ceiling so that it cannot
    /// guess at every account there is instead.
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
    pub fn login_attempt(
        &self,
        addr: IpAddr,
        login: &str,
        password: &[u8],
    ) -> Result<LoginAttempt, Duration> {
        if password.is_empty() || self.conn_gate.exempt(addr) {
            return Ok(LoginAttempt { held: None });
        }
        let key = login_key(login);
        let taken = self.login_failures.take_named(addr, &key).and_then(|()| {
            self.login_failures_per_addr
                .take(addr)
                .inspect_err(|_| self.login_failures.refund_named(addr, &key))
        });
        match taken {
            Ok(()) => Ok(LoginAttempt {
                held: Some((addr, key)),
            }),
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
        if let Some((addr, key)) = attempt.held {
            self.login_failures.refund_named(addr, &key);
            self.login_failures_per_addr.refund(addr);
        }
    }

    /// The addresses `[limits]` holds to none of its limits, for a
    /// frontend's own gates to exempt as well.
    pub fn limits_exempt(&self) -> &AddrSet {
        &self.conn_gate.limits().exempt
    }
}

/// `name`'s bucket within `ip`, or `ip`'s own.
fn key_of(ip: IpAddr, name: Option<&str>) -> RateKey {
    (limit_key(ip), name.map(Box::from))
}

/// New connections an address may make at once: its connection cap, or
/// mhxd's when there is none.
fn burst(per_addr: usize) -> f64 {
    burst_of(per_addr, CONNECTIONS_PER_ADDR)
}

/// New connections a count's owner may make at once: its cap, or
/// `otherwise` when it has none.
fn burst_of(cap: usize, otherwise: usize) -> f64 {
    match cap {
        0 => otherwise as f64,
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

/// How many private chats may be open (`[limits]`). A chat costs the
/// server a row and a place in every member's lookups for as long as
/// anyone is in it, and creating one costs a click, so both are capped:
/// the chats one session created that are still open, and every chat
/// on the server. A count of 0 is no limit, which is what a `Core`
/// built by hand has; a server built from a config has
/// [`ChatLimits::DEFAULT`] unless it says otherwise. mhxd has neither,
/// and a period client meets them as the task error any refused create
/// is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChatLimits {
    pub per_creator: usize,
    pub total: usize,
}

impl ChatLimits {
    pub const DEFAULT: ChatLimits = ChatLimits {
        per_creator: 16,
        total: 4096,
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

/// A token bucket: `count` per `per`, refilled continuously.
#[derive(Debug)]
pub(crate) struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    /// Spend one of `count` per `per` from `slot`, filling it on first
    /// use: `Err` with how long until one is earned back when there are
    /// none left. A count or a period of 0 is no limit.
    pub(crate) fn take(
        slot: &mut Option<Bucket>,
        count: u32,
        per: Duration,
        now: Instant,
    ) -> Result<(), Duration> {
        if count == 0 || per.is_zero() {
            return Ok(());
        }
        let full = f64::from(count);
        let b = slot.get_or_insert(Bucket {
            tokens: full,
            at: now,
        });
        let every = per.as_secs_f64() / full;
        let earned = now.saturating_duration_since(b.at).as_secs_f64() / every;
        b.tokens = (b.tokens + earned).min(full);
        b.at = now;
        if b.tokens < 1.0 {
            return Err(Duration::from_secs_f64((1.0 - b.tokens) * every));
        }
        b.tokens -= 1.0;
        Ok(())
    }

    /// Give back one [`Bucket::take`] just spent from `slot`, for an
    /// operation that turned out not to happen. Never past `count`.
    pub(crate) fn refund(slot: &mut Option<Bucket>, count: u32) {
        if let Some(b) = slot {
            b.tokens = (b.tokens + 1.0).min(f64::from(count));
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
/// or when it is not one person — a guest, whose login every other guest
/// shares and whose posts must not stop theirs — its address, as
/// [`limit_key`] has it, so logging in again is not a fresh bucket. One
/// session's only for a guest with no address to key it by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PostKey {
    Account(Option<[u8; 32]>, String),
    Guest(IpAddr),
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
        gate_with(per_addr, 0, reconnect, 0)
    }

    fn gate_for(per_addr: usize, reconnect: Duration, per_account: usize) -> ConnGate {
        gate_with(per_addr, 0, reconnect, per_account)
    }

    fn gate_48(per_addr: usize, per_v6_48: usize, reconnect: Duration) -> ConnGate {
        gate_with(per_addr, per_v6_48, reconnect, 0)
    }

    fn gate_with(
        per_addr: usize,
        per_v6_48: usize,
        reconnect: Duration,
        per_account: usize,
    ) -> ConnGate {
        ConnGate::new(ConnLimits {
            per_addr,
            per_v6_48,
            reconnect,
            per_account,
            exempt: AddrSet::parse(&["127.0.0.0/8", "2001:db8:1:ff::/64"]).unwrap(),
        })
    }

    /// The `n`th /64 of 2001:db8:`site`::/48, host `host`.
    fn in_48(site: u16, n: u16, host: u16) -> IpAddr {
        IpAddr::from([0x2001, 0xdb8, site, n, 0, 0, 0, host])
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
    fn the_64s_of_one_48_share_a_wider_cap() {
        let g = gate_48(2, 5, Duration::ZERO);
        // Each /64 well inside its own share, and the /48 full all the
        // same.
        let held: Vec<_> = (0..5)
            .map(|n| g.admit(in_48(1, n, 1)).expect("inside both counts"))
            .collect();
        assert_eq!(
            g.admit(in_48(1, 100, 1)).err(),
            Some(ConnRefused::TooManyIn48),
            "a /64 the gate has never seen, in a full /48"
        );
        assert_eq!(
            g.admit(in_48(1, 0, 2)).err(),
            Some(ConnRefused::TooManyIn48),
            "a /64 with room of its own"
        );
        // Another /48 is counted apart, and IPv4 has no wider count.
        let _other: Vec<_> = (0..5)
            .map(|n| g.admit(in_48(2, n, 1)).expect("another /48"))
            .collect();
        let _v4: Vec<_> = (0..20u8)
            .map(|i| g.admit(IpAddr::from([198, 51, 100, i])).expect("IPv4"))
            .collect();
        // The /64's own count still comes first.
        let _again = g.admit(in_48(3, 0, 1)).unwrap();
        let _twice = g.admit(in_48(3, 0, 2)).unwrap();
        assert_eq!(g.admit(in_48(3, 0, 3)).err(), Some(ConnRefused::TooMany));
        drop(held);
        assert!(
            g.admit(in_48(1, 100, 1)).is_ok(),
            "the /48's places came back with the /64s'"
        );
    }

    #[test]
    fn a_place_gives_back_both_its_counts() {
        let g = gate_48(1, 2, Duration::ZERO);
        let a = g.admit(in_48(1, 1, 1)).unwrap();
        let _b = g.admit(in_48(1, 2, 1)).unwrap();
        assert_eq!(
            g.admit(in_48(1, 3, 1)).err(),
            Some(ConnRefused::TooManyIn48)
        );
        drop(a);
        // The /64 and the /48 each have a place again.
        let _c = g.admit(in_48(1, 1, 2)).expect("both counts released");
        assert_eq!(
            g.admit(in_48(1, 1, 3)).err(),
            Some(ConnRefused::TooMany),
            "and the /64 holds its one again"
        );
    }

    #[test]
    fn a_refusal_by_the_48_spends_nothing_of_the_burst() {
        let g = gate_48(0, 1, Duration::from_secs(60));
        let a = g.admit(in_48(1, 1, 1)).unwrap();
        for _ in 0..10 {
            assert_eq!(
                g.admit(in_48(1, 2, 1)).err(),
                Some(ConnRefused::TooManyIn48)
            );
        }
        drop(a);
        // A burst of mhxd's five, less none for the refusals.
        for _ in 0..CONNECTIONS_PER_ADDR {
            drop(g.admit(in_48(1, 2, 1)).expect("the burst is whole"));
        }
        assert_eq!(g.admit(in_48(1, 2, 1)).err(), Some(ConnRefused::TooFast));
    }

    #[test]
    fn exempt_addresses_are_not_counted_toward_their_48() {
        let g = gate_48(1, 1, Duration::ZERO);
        // The exempt /64 is inside 2001:db8:1::/48.
        let _tools: Vec<_> = (0..10)
            .map(|i| g.admit(in_48(1, 0xff, i)).expect("exempt"))
            .collect();
        let _a = g.admit(in_48(1, 1, 1)).expect("the /48 is still empty");
        assert_eq!(
            g.admit(in_48(1, 2, 1)).err(),
            Some(ConnRefused::TooManyIn48)
        );
        assert!(
            g.admit(in_48(1, 0xff, 99)).is_ok(),
            "and a full /48 does not refuse its exempt /64"
        );
    }

    #[test]
    fn the_48s_are_forgotten_as_they_empty_and_the_64s_still_pruned() {
        let g = gate_48(2, 4, Duration::ZERO);
        let busy = in_48(1, 1, 1);
        let _held = g.admit(busy).unwrap();
        let lens = || {
            let by = g.0.by_addr.lock().unwrap();
            (by.map.len(), by.by_48.len())
        };
        // Enough /64s to reach the floor, spread over many /48s.
        for i in 0..PRUNE_FLOOR as u32 - 1 {
            drop(
                g.admit(in_48(2 + (i >> 8) as u16, (i & 0xff) as u16, 1))
                    .unwrap(),
            );
        }
        assert_eq!(lens(), (PRUNE_FLOOR, 1), "only the busy /48 is held");
        drop(g.admit(in_48(0x7fff, 0, 1)).unwrap());
        assert_eq!(lens(), (2, 1), "the busy /64 and the newest are left");
        let _second = g.admit(in_48(1, 2, 1)).unwrap();
        let _third = g.admit(in_48(1, 3, 1)).unwrap();
        let _fourth = g.admit(busy).unwrap();
        assert_eq!(
            g.admit(in_48(1, 4, 1)).err(),
            Some(ConnRefused::TooManyIn48),
            "the busy /48 kept its count through the prune"
        );
    }

    #[test]
    fn with_no_wider_cap_a_48_is_not_counted() {
        let g = gate(1, Duration::ZERO);
        let _held: Vec<_> = (0..50).map(|n| g.admit(in_48(1, n, 1)).unwrap()).collect();
        assert!(g.0.by_addr.lock().unwrap().by_48.is_empty());
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
            assert!(g.at(ip, None, t, true).is_ok());
        }
        let wait = g.at(ip, None, t, true).unwrap_err();
        assert!(
            wait > Duration::from_secs(9) && wait <= Duration::from_secs(10),
            "{wait:?}"
        );
        assert!(
            g.at("192.0.2.2".parse().unwrap(), None, t, true).is_ok(),
            "another address"
        );
        let later = t + Duration::from_secs(10);
        assert!(g.at(ip, None, later, true).is_ok(), "one earned");
        assert!(g.at(ip, None, later, true).is_err());
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
                failures_per_addr: 0,
                every: Duration::from_millis(200),
            });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let pw = b"wrong".as_slice();
        core.login_failed(core.login_attempt(ip, "alice", pw).unwrap());
        core.login_failed(core.login_attempt(ip, "alice", pw).expect("one mistake"));
        assert!(core.login_attempt(ip, "alice", pw).is_err(), "locked out");
        core.login_refund(
            core.login_attempt("192.0.2.2".parse().unwrap(), "alice", pw)
                .unwrap(),
        );
        // An empty password is a guest's, and is neither refused nor
        // counted.
        for _ in 0..5 {
            core.login_failed(core.login_attempt(ip, "alice", b"").expect("no password"));
        }
        std::thread::sleep(Duration::from_millis(250));
        core.login_refund(
            core.login_attempt(ip, "alice", pw)
                .expect("one earned back"),
        );
        core.login_refund(
            core.login_attempt(ip, "alice", pw)
                .expect("a right password costs nothing"),
        );
        // A core built by hand is not limited.
        let open = Core::new();
        for _ in 0..50 {
            open.login_failed(open.login_attempt(ip, "alice", pw).unwrap());
        }
        assert!(open.login_attempt(ip, "alice", pw).is_ok());
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
                failures_per_addr: 0,
                every: Duration::from_secs(60),
            });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..20)
            .filter_map(|_| core.login_attempt(ip, "alice", b"guess").ok())
            .collect();
        assert_eq!(held.len(), 3);
        for a in held {
            core.login_failed(a);
        }
        assert!(core.login_attempt(ip, "alice", b"guess").is_err());
    }

    #[test]
    fn a_login_moves_a_connection_from_its_address_to_its_account() {
        let g = gate_for(2, Duration::ZERO, 3);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mut a = g.admit(ip).unwrap();
        let _b = g.admit(ip).unwrap();
        assert_eq!(g.admit(ip).err(), Some(ConnRefused::TooMany));
        g.admit_account(&mut a, "alice", 0).unwrap();
        assert!(a.is_account());
        // Once more is nothing: the place is the account's already.
        g.admit_account(&mut a, "alice", 0).unwrap();
        let mut c = g.admit(ip).expect("the address has its place back");
        assert_eq!(g.admit(ip).err(), Some(ConnRefused::TooMany));
        g.admit_account(&mut c, "alice", 0).unwrap();
        // Many people behind one address: each logged in, none refused.
        let people: Vec<_> = (0..20)
            .map(|i| {
                let mut p = g.admit(ip).expect("a place before login");
                g.admit_account(&mut p, &format!("person{i}"), 0).unwrap();
                p
            })
            .collect();
        drop(people);
        let mut d = g.admit(ip).unwrap();
        g.admit_account(&mut d, "alice", 0).unwrap();
        let mut e = g.admit(ip).unwrap();
        assert_eq!(
            g.admit_account(&mut e, "alice", 0),
            Err(AccountRefused::Full),
            "the account is at its cap"
        );
        assert!(!e.is_account(), "a refusal leaves the place where it was");
        assert_eq!(
            g.admit(ip).err(),
            Some(ConnRefused::TooMany),
            "still the address's"
        );
        g.admit_account(&mut e, "alice", 1)
            .expect("a takeover may go one past");
        drop((a, e));
        let mut f = g.admit(ip).unwrap();
        g.admit_account(&mut f, "alice", 0)
            .expect("a place came back to the account");
        // An address the gate does not count still counts its account.
        let mut local = g.admit("127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(
            g.admit_account(&mut local, "alice", 0),
            Err(AccountRefused::Full)
        );
        g.admit_account(&mut local, "bob", 0).unwrap();
    }

    #[test]
    fn a_login_gives_the_48_back_its_place_with_the_address() {
        let g = gate_with(1, 2, Duration::ZERO, 0);
        let mut a = g.admit(in_48(1, 1, 1)).unwrap();
        let _b = g.admit(in_48(1, 2, 1)).unwrap();
        assert_eq!(
            g.admit(in_48(1, 3, 1)).err(),
            Some(ConnRefused::TooManyIn48)
        );
        g.admit_account(&mut a, "alice", 0).unwrap();
        // Both counts have the place back: the /64 and the /48 alike.
        let _c = g.admit(in_48(1, 1, 2)).expect("the /64 and the /48");
        assert_eq!(
            g.admit(in_48(1, 3, 1)).err(),
            Some(ConnRefused::TooManyIn48),
            "and the /48 is full again with the new one"
        );
        // The account's place holds no /48, so dropping it gives none
        // back twice.
        drop(a);
        assert_eq!(
            g.admit(in_48(1, 3, 1)).err(),
            Some(ConnRefused::TooManyIn48)
        );
        assert_eq!(g.0.by_addr.lock().unwrap().by_48.values().sum::<usize>(), 2);
        // The ng port's place, carried, gives back its /48 as it goes.
        let core_gate = gate_for(0, Duration::ZERO, 0);
        let port = gate_48(0, 1, Duration::ZERO);
        let shared = SharedPlace::new(Some(port.admit(in_48(2, 1, 1)).unwrap()));
        let mut place = core_gate.admit(in_48(2, 1, 1)).unwrap();
        place.carry(shared.clone());
        assert_eq!(
            port.admit(in_48(2, 2, 1)).err(),
            Some(ConnRefused::TooManyIn48)
        );
        core_gate.admit_account(&mut place, "bob", 0).unwrap();
        let _d = port
            .admit(in_48(2, 2, 1))
            .expect("the port's /48 place went with the login");
    }

    #[test]
    fn one_address_and_one_account_log_in_no_faster_than_the_address_connects() {
        let every = Duration::from_millis(300);
        let g = gate_for(2, every, 4);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // The address's burst of two, each logged in as alice.
        for _ in 0..2 {
            let mut p = g.admit(ip).expect("within the address's burst");
            g.admit_account(&mut p, "alice", 0).unwrap();
        }
        assert_eq!(
            g.admit(ip).err(),
            Some(ConnRefused::TooFast),
            "a login gives the address back its place but not its charge"
        );
        // Sustained, one address logging in as one account goes no faster
        // than the address connects: one every interval, not two.
        let start = Instant::now();
        let mut logins = 0;
        while start.elapsed() < every * 4 {
            if let Ok(mut p) = g.admit(ip) {
                g.admit_account(&mut p, "alice", 0)
                    .expect("alice has her own burst left");
                logins += 1;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(logins <= 5, "{logins} logins in four intervals");
    }

    #[test]
    fn an_account_logs_in_no_faster_than_its_own_rate_from_anywhere() {
        let g = gate_for(0, Duration::from_secs(3600), 2);
        let mut held = Vec::new();
        for i in 0..2 {
            let ip = IpAddr::from([192, 0, 2, i + 1]);
            let mut p = g.admit(ip).unwrap();
            g.admit_account(&mut p, "alice", 0).unwrap();
            held.push(p);
        }
        drop(held);
        let mut p = g.admit("192.0.2.9".parse().unwrap()).unwrap();
        match g.admit_account(&mut p, "alice", 0) {
            Err(AccountRefused::TooFast(wait)) => {
                assert!(wait > Duration::from_secs(3500), "{wait:?}")
            }
            other => panic!("alice's burst is spent: {other:?}"),
        }
        assert!(!p.is_account(), "a refusal leaves the place where it was");
        // From an exempt address too: the rate is the account's.
        let mut local = g.admit("127.0.0.1".parse().unwrap()).unwrap();
        assert!(matches!(
            g.admit_account(&mut local, "alice", 0),
            Err(AccountRefused::TooFast(_))
        ));
        g.admit_account(&mut local, "bob", 0)
            .expect("another account has its own");
    }

    #[test]
    fn many_accounts_behind_one_address_share_its_rate_to_connect() {
        let g = gate_for(0, Duration::from_secs(3600), 2);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // Each person logs in at a rate of their own, but only on the
        // connections the address could make before they logged in.
        let people: Vec<_> = (0..CONNECTIONS_PER_ADDR)
            .map(|i| {
                let mut p = g.admit(ip).expect("within the address's burst");
                g.admit_account(&mut p, &format!("person{i}"), 0).unwrap();
                p
            })
            .collect();
        assert_eq!(
            g.admit(ip).err(),
            Some(ConnRefused::TooFast),
            "however many accounts it logged in as"
        );
        drop(people);
    }

    #[test]
    fn a_carried_place_is_given_up_at_login_and_not_before() {
        let core_gate = gate_for(0, Duration::ZERO, 0);
        let port = gate(1, Duration::ZERO);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let shared = SharedPlace::new(Some(port.admit(ip).unwrap()));
        let mut place = core_gate.admit(ip).unwrap();
        place.carry(shared.clone());
        assert_eq!(port.admit(ip).err(), Some(ConnRefused::TooMany));
        core_gate.admit_account(&mut place, "alice", 0).unwrap();
        let _again = port
            .admit(ip)
            .expect("the port's place went with the login");
        drop(place);
        drop(shared);
    }

    #[test]
    fn a_login_is_counted_as_the_accounts_backend_reads_it() {
        assert_eq!(login_key("Alice"), "alice");
        assert_eq!(login_key(""), "guest");
        assert_eq!(login_key("GUEST"), "guest");
        let long = "\u{e9}".repeat(40);
        let key = login_key(&long);
        assert!(key.len() <= 64 && long.starts_with(&key), "{key}");
    }

    #[test]
    fn a_guesser_locks_out_the_login_it_guesses_and_not_its_neighbors() {
        let core = Core::new()
            .with_conn_limits(ConnLimits {
                exempt: AddrSet::default(),
                ..ConnLimits::default()
            })
            .with_login_limits(LoginLimits {
                failures: 2,
                failures_per_addr: 5,
                every: Duration::from_secs(3600),
            });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let pw = b"wrong".as_slice();
        for _ in 0..2 {
            core.login_failed(core.login_attempt(ip, "alice", pw).unwrap());
        }
        assert!(core.login_attempt(ip, "alice", pw).is_err(), "locked out");
        assert!(
            core.login_attempt(ip, "ALICE", pw).is_err(),
            "whatever its case"
        );
        core.login_refund(
            core.login_attempt(ip, "bob", b"right")
                .expect("bob, behind the same address, is not"),
        );
        core.login_refund(
            core.login_attempt("192.0.2.2".parse().unwrap(), "alice", pw)
                .expect("nor alice from elsewhere"),
        );
        // The ceiling: five wrong guesses from the address in all, over
        // any number of logins.
        core.login_failed(core.login_attempt(ip, "bob", pw).unwrap());
        core.login_failed(core.login_attempt(ip, "carol", pw).unwrap());
        core.login_failed(core.login_attempt(ip, "dave", pw).unwrap());
        assert!(
            core.login_attempt(ip, "erin", pw).is_err(),
            "the address has guessed as often as it may"
        );
        // A right password gives back both.
        let ceiling = Core::new()
            .with_conn_limits(ConnLimits {
                exempt: AddrSet::default(),
                ..ConnLimits::default()
            })
            .with_login_limits(LoginLimits {
                failures: 10,
                failures_per_addr: 1,
                every: Duration::from_secs(3600),
            });
        for _ in 0..5 {
            ceiling.login_refund(ceiling.login_attempt(ip, "alice", b"right").unwrap());
        }
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
    fn posts_are_counted_by_account_and_a_guest_by_its_address() {
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
        let here = || PostKey::Guest("192.0.2.7".parse().unwrap());
        let there = || PostKey::Guest("192.0.2.8".parse().unwrap());
        rates.count(here(), &limits, t);
        rates.count(there(), &limits, t);
        rates.count(there(), &limits, t);
        rates.reserve(here(), &limits, t).unwrap();
        assert!(rates.reserve(there(), &limits, t).is_err());
        assert_eq!(
            rates.reserve(alice(), &RequestLimits::default(), t),
            Ok(()),
            "no limit"
        );
    }
}
