//! The destination check (`docs/webpush-gateway.md` §6).
//!
//! A push endpoint is a URL **the client chooses and this server then
//! fetches**, which is the shape of every server-side request forgery
//! there has ever been. The sidecar refused non-routable destinations on
//! our behalf; in-process it is this module, and it runs twice — once at
//! registration, so a client gets an error it can show, and again
//! against the resolved address before every send, because DNS moves and
//! a name that answered publicly last week can answer `127.0.0.1` today.

use std::net::IpAddr;

/// Why an endpoint will not be pushed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not an absolute `https` URL with a host.
    NotHttps,
    /// Credentials in the authority, which a push endpoint has no use
    /// for and which would put a secret in every log line.
    HasUserinfo,
    /// A fragment, which is never sent and so can only be a way to make
    /// two spellings of one endpoint look like two.
    HasFragment,
    /// A host that resolves somewhere this server has no business
    /// POSTing to: loopback, a private network, link-local, or any of
    /// the other addresses that are only reachable because this process
    /// is inside something.
    NotGloballyRoutable,
    /// The name does not resolve at all.
    Unresolvable,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Refused::NotHttps => "not an absolute https URL",
            Refused::HasUserinfo => "carries credentials in its authority",
            Refused::HasFragment => "carries a fragment",
            Refused::NotGloballyRoutable => "does not resolve to a public address",
            Refused::Unresolvable => "does not resolve",
        };
        f.write_str(s)
    }
}

/// The host and port to connect to, once the URL itself is acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Check the URL's shape: `https`, a host, no userinfo, nothing exotic.
///
/// Hand-parsed rather than through a URL crate, for the reason the ng
/// port's HTTP layer is hand-written: this needs four rules, and a
/// general parser's permissiveness is the opposite of what a check
/// wants. Anything it is unsure about it refuses.
pub fn check(url: &str) -> Result<Target, Refused> {
    let rest = url.strip_prefix("https://").ok_or(Refused::NotHttps)?;
    if rest.contains('#') {
        return Err(Refused::HasFragment);
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return Err(Refused::HasUserinfo);
    }
    // A bracketed IPv6 literal keeps its colons; everything else has at
    // most one, before the port.
    let (host, port) = match authority.strip_prefix('[') {
        Some(after) => {
            let (host, tail) = after.split_once(']').ok_or(Refused::NotHttps)?;
            (host, tail.strip_prefix(':'))
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(Refused::NotHttps);
    }
    let port = match port {
        None => 443,
        Some(p) => p.parse().map_err(|_| Refused::NotHttps)?,
    };
    Ok(Target {
        host: host.to_string(),
        port,
    })
}

/// Is `addr` somewhere a public push service could actually be?
///
/// `IpAddr::is_global` is unstable, so the rules are written out, from
/// the IANA IPv4 and IPv6 special-purpose address registries. They are
/// deliberately a **deny list of everything special**, not an allow list
/// of one range: a new special-purpose block appearing is a reason to
/// add a line here, and until then the failure mode is that a push goes
/// to a documentation address rather than that it goes to a database on
/// the operator's LAN.
///
/// An IPv6 address that carries an IPv4 one is judged by the IPv4
/// address inside it: v4-mapped, v4-compatible, NAT64's well-known
/// prefix and 6to4 all
/// deliver to that address on a host that routes them, and on an
/// IPv6-only host with NAT64, `64:ff9b::a00:1` *is* `10.0.0.1`.
pub fn is_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT.
                || (a == 100 && (64..128).contains(&b))
                // 192.0.0.0/24, IETF protocol assignments.
                || v4.octets()[..3] == [192, 0, 0]
                // 192.88.99.0/24, the retired 6to4 relay anycast.
                || v4.octets()[..3] == [192, 88, 99]
                // 198.18.0.0/15, benchmarking.
                || (a == 198 && (b & 0xfe) == 18)
                // 240.0.0.0/4, reserved, and 0.0.0.0/8.
                || a >= 240
                || a == 0)
        }
        IpAddr::V6(v6) => {
            // A v4 address wearing a v6 hat is still that address, and
            // this is the check people forget.
            if let Some(v4) = embedded_v4(v6) {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7, unique local.
                || (s[0] & 0xfe00) == 0xfc00
                // fe80::/10, link-local, and fec0::/10, the deprecated
                // site-local, which some stacks still route.
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                // 2001::/23, IETF protocol assignments — Teredo's
                // 2001::/32 among them, which tunnels to an address this
                // check cannot see. Refused whole: a push service does
                // not live there.
                || (s[0] == 0x2001 && s[1] < 0x0200)
                // 2001:db8::/32 and 3fff::/20, documentation.
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] & 0xfff0) == 0x3ff0
                // 64:ff9b:1::/48, NAT64 for local use. Its v4 address is
                // not in a fixed place (RFC 6052 splits it around the u
                // octet), and nothing public lives there.
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                // 100::/64, discard-only.
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                // ::/96 that is not v4-compatible, i.e. anything else in
                // the first /8 the registry has not given out.
                || s[0] == 0)
        }
    }
}

/// The IPv4 address an IPv6 one delivers to, for the forms that carry
/// one in a fixed place: `::ffff:a.b.c.d` (mapped), `::a.b.c.d`
/// (compatible, deprecated but still parsed), `64:ff9b::a.b.c.d`
/// (NAT64's well-known prefix), and `2002:aabb:ccdd::/48` (6to4).
fn embedded_v4(v6: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    let s = v6.segments();
    let o = v6.octets();
    let tail = std::net::Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    // v4-compatible: ::a.b.c.d, but not :: or ::1, which are their own.
    if s[..6] == [0; 6] && !v6.is_unspecified() && !v6.is_loopback() {
        return Some(tail);
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(tail);
    }
    if s[0] == 0x2002 {
        return Some(std::net::Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_endpoint_is_an_https_url_with_a_host() {
        assert_eq!(
            check("https://push.example.net/v/abc"),
            Ok(Target {
                host: "push.example.net".into(),
                port: 443
            })
        );
        assert_eq!(
            check("https://push.example.net:8443/v/abc").unwrap().port,
            8443
        );
        assert_eq!(
            check("https://[2606:4700::1]:8443/v").unwrap(),
            Target {
                host: "2606:4700::1".into(),
                port: 8443
            }
        );
        assert_eq!(check("http://push.example.net/v"), Err(Refused::NotHttps));
        assert_eq!(check("/v/abc"), Err(Refused::NotHttps));
        assert_eq!(check("https:///v/abc"), Err(Refused::NotHttps));
        assert_eq!(
            check("https://user:pw@push.example.net/v"),
            Err(Refused::HasUserinfo)
        );
        assert_eq!(
            check("https://push.example.net:nope/v"),
            Err(Refused::NotHttps)
        );
        assert_eq!(
            check("https://push.example.net/v#frag"),
            Err(Refused::HasFragment)
        );
    }

    #[test]
    fn the_places_a_push_may_not_go() {
        let private = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.0.1",
            "192.0.0.1",
            "198.19.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "2001:db8::1",
            "ff02::1",
            // The one people forget.
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            // And the rest of the v4 it carries.
            "::127.0.0.1",
            "::10.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::a00:1",
            "2002:a00:1::1",
            "2002:7f00:1::",
            "2001::1",
            "2001:0:4136:e378::1",
            "fec0::1",
            "100::1",
            "3fff::1",
            "::2",
            "192.88.99.1",
        ];
        for a in private {
            assert!(
                !is_public(a.parse().unwrap()),
                "{a} is not somewhere a push service is"
            );
        }
        for a in [
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            // What a public v4 address looks like when it is carried.
            "64:ff9b::101:101",
            "2002:101:101::1",
        ] {
            assert!(is_public(a.parse().unwrap()), "{a} is a public address");
        }
    }
}
