//! The enrollment bundle (`docs/identity-enrollment.md` §5.4): a device
//! certificate and the card of the identity that signed it, carried as
//! one object.
//!
//! It is the *answer* half of enrollment, and it exists because the two
//! halves have to travel together. A certificate says which identity
//! certified a device; only the card says who that identity claims to
//! be, and the enrollee has no way to fetch one for an identity that has
//! never authenticated at the server it is talking to. Shipping them
//! separately made the browser accept "one or two blobs, in either
//! order, told apart by shape" — which works, and is one more thing to
//! get right in the one place that must not get things wrong.
//!
//! Unsigned, and deliberately so: there is nothing here to sign. Both
//! members carry their own signature under their own domain, and a
//! wrapper signature would only certify that someone put two objects in
//! a bag. What binds them is checked rather than asserted — see
//! [`Bundle::open`].
//!
//! The same bytes serve both paths of §5: the mailbox carries this, and
//! `hlid cert --bundle` writes it for the paste. That is the point. A
//! browser that verifies one verifies the other, and the ceremony a user
//! falls back to is not a second code path to audit.

use crate::card::{self, Card};
use crate::cbor::{self, Value};
use crate::cert::{self, DeviceCert};
use crate::error::Error;
use crate::signed::{self, VERSION};

/// The wrapper's own ceiling. Its members are bounded individually — a
/// certificate at 4 KiB (§3.3), a card at 16 KiB (§3.4) — so this is
/// those two plus the map around them, and it exists so that a decoder
/// can refuse before allocating rather than after.
pub const MAX_BYTES: usize = cert::MAX_BYTES + card::MAX_BYTES + 256;

/// A certificate and the card of the identity that signed it.
///
/// The fields are the raw encodings, not the parsed objects: a bundle is
/// something to hand on as often as something to read, and re-encoding a
/// parsed object to forward it would be a chance to change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub cert: Vec<u8>,
    pub card: Vec<u8>,
}

impl Bundle {
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&cbor::map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("card", Some(Value::Bytes(self.card.clone()))),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
        ]))
    }

    /// Structure only: canonical CBOR, a known `v`, and two byte
    /// strings. Neither member is decoded, let alone verified —
    /// [`Bundle::open`] is what does that, and separating them keeps a
    /// relay that only forwards a bundle from having to hold an opinion
    /// about its contents.
    pub fn parse(bytes: &[u8]) -> Result<Bundle, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let v = cbor::decode_canonical(bytes)?;
        if !matches!(v, Value::Map(_)) {
            return Err(Error::NotAMap);
        }
        let version = signed::uint(&v, "v")?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        Ok(Bundle {
            cert: signed::bytes(&v, "cert")?,
            card: signed::bytes(&v, "card")?,
        })
    }

    /// Parse both members, verify both signatures, and check the one
    /// thing that makes them a bundle rather than two files: that the
    /// card belongs to the identity the certificate names.
    ///
    /// What is deliberately *not* checked here is the device: only the
    /// enrollee knows which keys it holds, and comparing them is its job
    /// (§5.5). Nor is expiry, which needs a clock the caller has and
    /// this crate does not.
    pub fn open(&self) -> Result<(DeviceCert, Card), Error> {
        let cert = DeviceCert::parse(&self.cert)?;
        let card = Card::parse(&self.card)?;
        if cert.identity != card.identity {
            return Err(Error::KeyMismatch);
        }
        Ok((cert, card))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DeviceKey, IdentityKey};

    fn bundle_for(id: &IdentityKey, name: &str) -> Bundle {
        let dev = DeviceKey::from_seed(&[7u8; 32]);
        let cert = DeviceCert::for_keys(id, dev.public(), dev.public_enc(), 1_000, 86_400)
            .unwrap()
            .sign(id);
        let card = Card::new(id, name, 1_000).sign(id, Vec::new()).unwrap();
        Bundle { cert, card }
    }

    #[test]
    fn a_bundle_round_trips_and_opens() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let b = bundle_for(&id, "alice");
        let back = Bundle::parse(&b.encode()).unwrap();
        assert_eq!(back, b);

        let (cert, card) = back.open().unwrap();
        assert_eq!(cert.identity, id.public());
        assert_eq!(card.name, "alice");
    }

    #[test]
    fn a_card_from_a_different_identity_is_not_a_bundle() {
        // The failure this check exists for: a mailbox that hands back a
        // real certificate with somebody else's real card, so that every
        // signature verifies and the name beside the fingerprint is a
        // lie (§9, "substitute the answer").
        let alice = IdentityKey::from_seed(&[1u8; 32]);
        let mallory = IdentityKey::from_seed(&[2u8; 32]);
        let mixed = Bundle {
            cert: bundle_for(&alice, "alice").cert,
            card: bundle_for(&mallory, "mallory").card,
        };
        assert_eq!(mixed.open(), Err(Error::KeyMismatch));
    }

    #[test]
    fn a_member_that_does_not_verify_is_refused_by_open_not_by_parse() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let mut b = bundle_for(&id, "alice");
        let last = b.cert.len() - 1;
        b.cert[last] ^= 0xff;
        let bytes = b.encode();

        // Forwarding it is still fine — a relay is not a verifier.
        assert!(Bundle::parse(&bytes).is_ok());
        assert_eq!(
            Bundle::parse(&bytes).unwrap().open(),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn the_wrapper_is_bounded_before_anything_is_decoded() {
        let huge = vec![0u8; MAX_BYTES + 1];
        assert_eq!(Bundle::parse(&huge), Err(Error::TooLarge));
    }

    #[test]
    fn version_zero_is_not_an_older_bundle() {
        let bytes = cbor::encode(&cbor::map(vec![
            ("v", Some(Value::Uint(0))),
            ("card", Some(Value::Bytes(vec![1]))),
            ("cert", Some(Value::Bytes(vec![2]))),
        ]));
        assert_eq!(Bundle::parse(&bytes), Err(Error::UnsupportedVersion(0)));
    }
}
