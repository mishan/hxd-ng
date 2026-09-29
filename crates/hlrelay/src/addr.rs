//! Who a connection is from, and how many connections each address may
//! hold (`docs/relay.md`, "Limits and proxies").
//!
//! **Who.** A relay behind a reverse proxy sees every client arrive from
//! the proxy. The client's own address is taken from the one forwarded
//! header the operator says their proxy writes, and only when the socket
//! peer is a proxy they listed — the same rules, and the same walk, as
//! hxd-ng's ng listener uses for `[ng] trusted_proxies` and
//! `[ng] forwarded_header` (`docs/hotline-ng-auth.md` §6.3). They are
//! repeated here rather than shared because the ng listener's copy lives
//! in a crate that brings the whole server with it.
//!
//! **How many.** An IPv4 address is itself; an IPv6 one is its /64,
//! which is what one subscriber is given, so a client cannot step past
//! the limit by walking its own prefix. An IPv4 address mapped into IPv6
//! is the IPv4 address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use hyper::HeaderMap;

/// Addresses whose forwarded-address header is believed: single
/// addresses or CIDR blocks.
///
/// Both sides are canonicalized before comparing. A proxy on 127.0.0.1
/// reaching a relay bound to `[::]` arrives as `::ffff:127.0.0.1`, and an
/// exact comparison would silently never match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<(IpAddr, u32)>);

impl TrustedProxies {
    /// Parse `"192.0.2.7"`, `"10.0.0.0/8"`, `"2001:db8::/32"`. The error
    /// names the offending entry; it reaches the operator at startup.
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
                .map_err(|_| format!("trusted proxy {e:?} is not an IP address"))?;
            let addr = addr.to_canonical();
            let full = if addr.is_ipv4() { 32 } else { 128 };
            let bits = match prefix {
                None => full,
                Some(p) => {
                    let bits: u32 = p
                        .parse()
                        .map_err(|_| format!("trusted proxy {e:?} has a bad prefix length"))?;
                    if bits > full {
                        return Err(format!("trusted proxy {e:?}: prefix exceeds {full} bits"));
                    }
                    bits
                }
            };
            out.push((addr, bits));
        }
        Ok(TrustedProxies(out))
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

/// The header a trusted proxy uses to say who it is speaking for.
///
/// Proxies pass headers they don't know about straight through: nginx
/// configured to write `X-Forwarded-For` forwards a client-supplied
/// `Forwarded:` untouched, so believing both would mean believing
/// whichever one the client filled in. The operator says which one their
/// proxy owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardedHeader {
    /// `X-Forwarded-For`, what Caddy and the stock nginx and HAProxy
    /// directives write.
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded`.
    Forwarded,
    /// Neither: every client behind the proxy shares its address.
    None,
}

impl ForwardedHeader {
    /// Parse `x-forwarded-for`, `forwarded` or `none`.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "x-forwarded-for" => Ok(ForwardedHeader::XForwardedFor),
            "forwarded" => Ok(ForwardedHeader::Forwarded),
            "none" => Ok(ForwardedHeader::None),
            other => Err(format!(
                "forwarded header {other:?} is not one of \"x-forwarded-for\", \"forwarded\", \"none\""
            )),
        }
    }
}

/// The client's address: the socket peer, or, when the peer is a trusted
/// proxy, the rightmost element of the forwarded chain that is not one.
///
/// Proxies that append (nginx's `$proxy_add_x_forwarded_for`, HAProxy's
/// `option forwardfor`) leave the client's own claim on the left and the
/// peer they saw on the right, so walking from the right is correct under
/// those and under a proxy that replaces the header outright. An element
/// that names nothing parseable ends the walk at the socket peer: an
/// unreadable chain is not evidence.
pub(crate) fn client_addr(
    headers: &HeaderMap,
    peer: IpAddr,
    trusted: &TrustedProxies,
    header: ForwardedHeader,
) -> IpAddr {
    if !trusted.contains(peer) {
        return peer;
    }
    let name = match header {
        ForwardedHeader::None => return peer,
        ForwardedHeader::XForwardedFor => "x-forwarded-for",
        ForwardedHeader::Forwarded => "forwarded",
    };
    // Split as bytes, not as text: a value that is not UTF-8 is unreadable
    // only where its bad bytes are, so junk the client put on the left
    // cannot hide the elements its proxies appended on the right.
    let mut elements = Vec::new();
    for value in headers.get_all(name) {
        elements.extend(value.as_bytes().split(|&b| b == b','));
    }
    forwarded_client(&elements, header, trusted).unwrap_or(peer)
}

/// The rightmost element of a forwarded chain that isn't a trusted
/// proxy. `None` means nobody was named: the chain is empty, every
/// element is a trusted proxy, or the walk reached one it cannot read.
fn forwarded_client(
    elements: &[&[u8]],
    header: ForwardedHeader,
    trusted: &TrustedProxies,
) -> Option<IpAddr> {
    for element in elements.iter().rev() {
        let element = std::str::from_utf8(element).ok()?;
        let named = match header {
            ForwardedHeader::Forwarded => forwarded_for(element).and_then(host_ip),
            _ => host_ip(element),
        };
        match named {
            Some(ip) if trusted.contains(ip) => continue,
            Some(ip) => return Some(ip.to_canonical()),
            None => return None,
        }
    }
    None
}

/// The `for=` value of one RFC 7239 `Forwarded` element.
fn forwarded_for(element: &str) -> Option<&str> {
    for param in element.split(';') {
        let Some((k, v)) = param.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("for") {
            return Some(v.trim().trim_matches('"'));
        }
    }
    None
}

/// An IP out of a `for=` or `X-Forwarded-For` value, which may be
/// `1.2.3.4`, `1.2.3.4:5678`, `[2001:db8::1]:5678`, or one of RFC 7239's
/// obfuscated forms, which name nobody.
fn host_ip(value: &str) -> Option<IpAddr> {
    let v = value.trim();
    if let Ok(ip) = v.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = v.strip_prefix('[') {
        let (inside, _) = rest.split_once(']')?;
        return inside.parse().ok();
    }
    v.rsplit_once(':').and_then(|(host, _)| host.parse().ok())
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

/// How many connections each address holds. An address leaves the table
/// when its last connection ends, so the table is never larger than the
/// connections the relay holds.
pub(crate) struct AddrLimit {
    /// Connections one address may hold at once; 0 is no limit.
    per_addr: usize,
    live: Mutex<HashMap<IpAddr, usize>>,
}

impl AddrLimit {
    pub(crate) fn new(per_addr: usize) -> Arc<Self> {
        Arc::new(AddrLimit {
            per_addr,
            live: Mutex::new(HashMap::new()),
        })
    }

    /// A place in `ip`'s count, or `None` when it holds all it may.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<AddrPermit> {
        if self.per_addr == 0 {
            return Some(AddrPermit { held: None });
        }
        let key = limit_key(ip);
        let mut live = self.live.lock().unwrap();
        let n = live.entry(key).or_insert(0);
        if *n >= self.per_addr {
            return None;
        }
        *n += 1;
        Some(AddrPermit {
            held: Some((self.clone(), key)),
        })
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.live.lock().unwrap().len()
    }
}

/// One connection's place in its address's count; dropping it gives the
/// place back.
pub(crate) struct AddrPermit {
    held: Option<(Arc<AddrLimit>, IpAddr)>,
}

impl Drop for AddrPermit {
    fn drop(&mut self) {
        if let Some((limit, key)) = self.held.take() {
            let mut live = limit.live.lock().unwrap();
            if let Some(n) = live.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    live.remove(&key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn trusted_proxies_match_by_prefix_and_canonical_form() {
        let t = TrustedProxies::parse(&["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]).unwrap();
        assert!(t.contains(ip("127.0.0.1")));
        // A proxy on loopback reaching a `[::]` bind.
        assert!(t.contains(ip("::ffff:127.0.0.1")));
        assert!(t.contains(ip("10.200.1.1")));
        assert!(t.contains(ip("2001:db8:1::5")));
        assert!(!t.contains(ip("127.0.0.2")));
        assert!(!t.contains(ip("2001:db9::1")));
        assert!(TrustedProxies::parse(&["::ffff:192.0.2.7"])
            .unwrap()
            .contains(ip("192.0.2.7")));
        assert!(TrustedProxies::parse(&["10.0.0.0/33"]).is_err());
        assert!(TrustedProxies::parse(&["not-an-address"]).is_err());
        assert!(!TrustedProxies::default().contains(ip("127.0.0.1")));
    }

    #[test]
    fn the_client_is_the_rightmost_untrusted_element_behind_a_trusted_peer() {
        let trusted = TrustedProxies::parse(&["127.0.0.1", "10.0.0.0/8"]).unwrap();
        let xff = ForwardedHeader::XForwardedFor;
        let headers = |name: &str, values: &[&str]| {
            let mut h = HeaderMap::new();
            for v in values {
                h.append(
                    hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    v.parse().unwrap(),
                );
            }
            h
        };
        let proxy = ip("127.0.0.1");

        // The client's own claim on the left is not believed.
        let h = headers("x-forwarded-for", &["203.0.113.9, 198.51.100.4"]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), ip("198.51.100.4"));
        // Our own hops are walked past, across repeated headers too.
        let h = headers("x-forwarded-for", &["198.51.100.4", "10.0.0.7, 10.0.0.8"]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), ip("198.51.100.4"));
        // A peer that is not a proxy is who it is, whatever it claims.
        let h = headers("x-forwarded-for", &["198.51.100.4"]);
        assert_eq!(
            client_addr(&h, ip("192.0.2.1"), &trusted, xff),
            ip("192.0.2.1")
        );
        // Only the configured header is read.
        let h = headers("forwarded", &["for=198.51.100.4"]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), proxy);
        assert_eq!(
            client_addr(&h, proxy, &trusted, ForwardedHeader::Forwarded),
            ip("198.51.100.4")
        );
        assert_eq!(
            client_addr(&h, proxy, &trusted, ForwardedHeader::None),
            proxy
        );
        // An unreadable element ends the walk at the peer.
        let h = headers("x-forwarded-for", &["198.51.100.4, _hidden"]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), proxy);
        // Bytes that are not UTF-8 are unreadable only where they are:
        // on the left, past the client, they change nothing, in the same
        // value or in an earlier one...
        let bytes = |values: &[&[u8]]| {
            let mut h = HeaderMap::new();
            for v in values {
                h.append(
                    "x-forwarded-for",
                    hyper::header::HeaderValue::from_bytes(v).unwrap(),
                );
            }
            h
        };
        let h = bytes(&[&b"\xff\xfe, 198.51.100.4, 10.0.0.7"[..]]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), ip("198.51.100.4"));
        let h = bytes(&[&b"\xff\xfe"[..], &b"198.51.100.4"[..]]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), ip("198.51.100.4"));
        // ...and where the walk reaches them, they end it at the peer.
        let h = bytes(&[&b"198.51.100.4, \xff\xfe, 10.0.0.7"[..]]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), proxy);
        // Ports and brackets are not part of the address.
        let h = headers("x-forwarded-for", &["[2001:db8::1]:443"]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), ip("2001:db8::1"));
        let h = headers("x-forwarded-for", &["198.51.100.4:5678"]);
        assert_eq!(client_addr(&h, proxy, &trusted, xff), ip("198.51.100.4"));
    }

    #[test]
    fn ipv6_is_limited_by_its_64_and_mapped_ipv4_as_ipv4() {
        assert_eq!(limit_key(ip("192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(limit_key(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
        assert_eq!(
            limit_key(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            ip("2001:db8:1:2::")
        );
    }

    #[test]
    fn an_address_holds_at_most_its_limit_and_gets_places_back() {
        let limit = AddrLimit::new(2);
        let a = limit.try_acquire(ip("2001:db8::1")).unwrap();
        // Another address in the same /64 is the same subscriber.
        let b = limit.try_acquire(ip("2001:db8::2")).unwrap();
        assert!(limit.try_acquire(ip("2001:db8::3")).is_none());
        // Someone else is not affected.
        let other = limit.try_acquire(ip("192.0.2.1")).unwrap();
        drop(a);
        let c = limit.try_acquire(ip("2001:db8::3")).unwrap();
        drop((b, c, other));
        // Nothing is remembered about an address with no connections.
        assert_eq!(limit.tracked(), 0);

        let none = AddrLimit::new(0);
        let held: Vec<_> = (0..100)
            .map(|_| none.try_acquire(ip("192.0.2.1")).unwrap())
            .collect();
        assert_eq!(held.len(), 100);
        assert_eq!(none.tracked(), 0);
    }
}
