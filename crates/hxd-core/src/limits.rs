//! Limits a single address is held to, whatever it is logged in as.
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
//! **Addresses.** An IPv4 address is itself; an IPv6 one is its /64,
//! which is what one subscriber is given, so a client cannot step past
//! the cap by walking its own prefix. An IPv4 address mapped into IPv6
//! is the IPv4 address. Addresses in `exempt` are not limited at all:
//! loopback by default, so the tests, the load harness and an operator's
//! own tools are not refused by their own server.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
/// burst.
#[derive(Default)]
pub(crate) struct ConnGate(Arc<GateInner>);

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
    pub(crate) fn new(limits: ConnLimits) -> ConnGate {
        ConnGate(Arc::new(GateInner {
            limits,
            by_addr: Mutex::default(),
        }))
    }

    /// Is `ip` held to no per-address limit (`exempt`)?
    pub(crate) fn exempt(&self, ip: IpAddr) -> bool {
        self.0.limits.exempt.contains(ip)
    }

    pub(crate) fn admit(&self, ip: IpAddr) -> Result<ConnPermit, ConnRefused> {
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
    fn a_set_parses_blocks_and_matches_across_the_mapping() {
        let s = AddrSet::parse(&["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]).unwrap();
        assert!(s.contains("10.1.2.3".parse().unwrap()));
        assert!(s.contains("::ffff:192.0.2.7".parse().unwrap()));
        assert!(s.contains("2001:db8:9::1".parse().unwrap()));
        assert!(!s.contains("11.0.0.1".parse().unwrap()));
        assert!(AddrSet::parse(&["10.0.0.0/33"]).is_err());
        assert!(AddrSet::parse(&["nope"]).is_err());
    }
}
