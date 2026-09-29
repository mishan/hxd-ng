//! A guest's share of the news, kept under a key the database alone
//! cannot turn back into an address (`docs/news.md` §7.4).
//!
//! Guests are counted against `max_per_author` by the address they post
//! from, as [`crate::limits::limit_key`] has it. What the store keeps is
//! not that address but a keyed hash of it: HMAC-SHA-256 under a secret
//! the server keeps outside the database, cut to 128 bits. Equal
//! addresses still give equal keys, so counting is unchanged, but a copy
//! of the database is not a list of where guests posted from. The
//! secret must live apart from the data: IPv4 has few enough addresses
//! that a hash anyone could recompute would be read back by trying them
//! all.

use std::fmt;
use std::net::IpAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The length of the secret a [`GuestKeyer`] is made from.
pub const GUEST_SECRET_LEN: usize = 32;

/// What says which guests a live article's share is charged to: equal
/// for the guests of one address under one secret, and nothing else
/// about them.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuestKey([u8; 16]);

impl GuestKey {
    /// As the store keeps it: lowercase hex.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// [`GuestKey::to_hex`] read back, or `None` for anything else.
    pub fn from_hex(text: &str) -> Option<GuestKey> {
        if text.len() != 32 || !text.is_ascii() {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(GuestKey(out))
    }
}

impl fmt::Debug for GuestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GuestKey({})", self.to_hex())
    }
}

/// Turns a guest's address into its [`GuestKey`], under the server's
/// secret. A server keeps its secret across restarts, so a guest's
/// articles stay charged to its address; a secret lost or replaced
/// leaves the articles keyed under the old one counted under none, and
/// every address starts again from nothing.
#[derive(Clone)]
pub struct GuestKeyer([u8; GUEST_SECRET_LEN]);

impl GuestKeyer {
    pub fn new(secret: [u8; GUEST_SECRET_LEN]) -> GuestKeyer {
        GuestKeyer(secret)
    }

    /// A secret of this process's own, from the OS CSPRNG: what a `Core`
    /// built by hand keys with, and forgets when it stops.
    pub fn ephemeral() -> GuestKeyer {
        let mut secret = [0u8; GUEST_SECRET_LEN];
        getrandom::getrandom(&mut secret).expect("the OS CSPRNG");
        GuestKeyer(secret)
    }

    /// The key of the guests at `addr`: its [`crate::limits::limit_key`]
    /// (IPv4 whole, IPv6 its /64), hashed under the secret.
    pub fn key(&self, addr: IpAddr) -> GuestKey {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes a key of any length");
        mac.update(b"hxd-ng news guest\0");
        match crate::limits::limit_key(addr) {
            IpAddr::V4(v4) => {
                mac.update(&[4]);
                mac.update(&v4.octets());
            }
            IpAddr::V6(v6) => {
                mac.update(&[6]);
                mac.update(&v6.octets());
            }
        }
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag[..16]);
        GuestKey(out)
    }
}

impl Default for GuestKeyer {
    fn default() -> Self {
        GuestKeyer::ephemeral()
    }
}

impl fmt::Debug for GuestKeyer {
    /// Never the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestKeyer(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_the_address_block_under_the_secret_and_nothing_readable() {
        let keyer = GuestKeyer::new([7; GUEST_SECRET_LEN]);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let here = keyer.key(ip("192.0.2.7"));
        assert_eq!(here, keyer.key(ip("::ffff:192.0.2.7")), "mapped is IPv4");
        assert_ne!(here, keyer.key(ip("192.0.2.8")), "a neighbor");
        assert_eq!(
            keyer.key(ip("2001:db8:1:2::1")),
            keyer.key(ip("2001:db8:1:2:ffff::9")),
            "one /64"
        );
        assert_ne!(
            keyer.key(ip("2001:db8:1:2::1")),
            keyer.key(ip("2001:db8:1:3::1"))
        );
        assert_eq!(
            here,
            GuestKeyer::new([7; GUEST_SECRET_LEN]).key(ip("192.0.2.7")),
            "the same secret, the same key"
        );
        assert_ne!(
            here,
            GuestKeyer::new([8; GUEST_SECRET_LEN]).key(ip("192.0.2.7")),
            "another secret, another key"
        );
        let hex = here.to_hex();
        assert_eq!(hex.len(), 32);
        assert!(!hex.contains("192"), "{hex}");
        assert_eq!(GuestKey::from_hex(&hex), Some(here));
        assert_eq!(GuestKey::from_hex("192.0.2.7"), None);
        assert_eq!(format!("{keyer:?}"), "GuestKeyer(..)");
    }
}
