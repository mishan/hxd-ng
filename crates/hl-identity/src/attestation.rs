//! The registrar attestation (`docs/hotline-ng-identity.md` §3.5).
//!
//! Signed by a registrar's [`ServerKey`]. The registrar's public key rides
//! inside the object as a hint; a verifier that hasn't confirmed that key
//! against the registrar's `/.well-known/hotline` has verified nothing but
//! internal consistency. [`Attestation::parse`] does the internal check;
//! [`Attestation::verify_registrar`] is the step that makes it mean
//! something.

use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{PublicKey, ServerKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/attestation/v1";

/// The recommended attestation lifetime (§3.5).
pub const RECOMMENDED_LIFETIME: u64 = 365 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub identity: PublicKey,
    /// Registrar host, lowercase.
    pub registrar: String,
    /// The signing key as claimed by the object. See the module docs.
    pub registrar_key: PublicKey,
    /// Local part; the full handle is `handle@registrar`.
    pub handle: String,
    /// First registration at this registrar; preserved across reissue.
    pub registered: u64,
    pub issued: u64,
    pub expires: u64,
    /// Registrar-declared signup strictness, 0–3.
    pub level: Option<u64>,
}

impl Attestation {
    pub fn full_handle(&self) -> String {
        format!("{}@{}", self.handle, self.registrar)
    }

    pub(crate) fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            (
                "registrar_key",
                Some(Value::Bytes(self.registrar_key.to_vec())),
            ),
            ("handle", Some(Value::Text(self.handle.clone()))),
            ("registered", Some(Value::Uint(self.registered))),
            ("issued", Some(Value::Uint(self.issued))),
            ("expires", Some(Value::Uint(self.expires))),
            ("level", self.level.map(Value::Uint)),
        ])
    }

    /// Sign as the registrar. `self.registrar_key` must be `key`'s public
    /// half.
    pub fn sign(&self, key: &ServerKey) -> Vec<u8> {
        debug_assert_eq!(key.public(), self.registrar_key);
        signed::seal(self.unsigned(), |body| key.sign(DOMAIN, body))
    }

    /// The signed object as a CBOR value, for embedding in a card.
    pub fn signed_value(&self, key: &ServerKey) -> Value {
        crate::cbor::decode_canonical(&self.sign(key)).expect("seal produces canonical CBOR")
    }

    /// Decode and check the signature against the embedded registrar key.
    pub fn parse(bytes: &[u8]) -> Result<Attestation, Error> {
        Self::from_envelope(Envelope::open(bytes)?)
    }

    pub(crate) fn from_value(value: Value) -> Result<Attestation, Error> {
        Self::from_envelope(Envelope::from_value(value)?)
    }

    fn from_envelope(env: Envelope) -> Result<Attestation, Error> {
        let v = &env.value;
        let a = Attestation {
            identity: signed::bytes32(v, "identity")?,
            registrar: signed::text(v, "registrar")?,
            registrar_key: signed::bytes32(v, "registrar_key")?,
            handle: signed::text(v, "handle")?,
            registered: signed::uint(v, "registered")?,
            issued: signed::uint(v, "issued")?,
            expires: signed::uint(v, "expires")?,
            level: signed::opt_uint(v, "level")?,
        };
        if a.registrar != a.registrar.to_lowercase() || a.registrar.is_empty() {
            return Err(Error::BadField("registrar"));
        }
        if a.handle.is_empty() || a.handle.contains('@') {
            return Err(Error::BadField("handle"));
        }
        if a.level.is_some_and(|l| l > 3) {
            return Err(Error::BadField("level"));
        }
        env.verify(&a.registrar_key, DOMAIN)?;
        Ok(a)
    }

    /// The step that gives the attestation meaning: `expected` is the
    /// registrar's key as fetched from its discovery document, and `now`
    /// and `skew` are the verifier's clock and tolerance.
    pub fn verify_registrar(&self, expected: &PublicKey, now: u64, skew: u64) -> Result<(), Error> {
        if &self.registrar_key != expected {
            return Err(Error::KeyMismatch);
        }
        signed::check_window(self.issued, self.expires, now, skew)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;

    #[test]
    fn round_trip_and_registrar_check() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let a = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "misha".into(),
            registered: 1_600_000_000,
            issued: 1_700_000_000,
            expires: 1_700_000_000 + RECOMMENDED_LIFETIME,
            level: Some(2),
        };
        let bytes = a.sign(&reg);
        let back = Attestation::parse(&bytes).unwrap();
        assert_eq!(back, a);
        assert_eq!(back.full_handle(), "misha@hl.example");
        assert!(back
            .verify_registrar(&reg.public(), 1_710_000_000, 300)
            .is_ok());
        let impostor = ServerKey::from_seed(&[4u8; 32]);
        assert_eq!(
            back.verify_registrar(&impostor.public(), 1_710_000_000, 300),
            Err(Error::KeyMismatch)
        );
    }

    #[test]
    fn field_rules() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let base = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "misha".into(),
            registered: 1,
            issued: 2,
            expires: 3,
            level: None,
        };
        let a = Attestation {
            registrar: "HL.example".into(),
            ..base.clone()
        };
        assert_eq!(
            Attestation::parse(&a.sign(&reg)),
            Err(Error::BadField("registrar"))
        );
        let a = Attestation {
            handle: "misha@x".into(),
            ..base.clone()
        };
        assert_eq!(
            Attestation::parse(&a.sign(&reg)),
            Err(Error::BadField("handle"))
        );
        let a = Attestation {
            level: Some(4),
            ..base
        };
        assert_eq!(
            Attestation::parse(&a.sign(&reg)),
            Err(Error::BadField("level"))
        );
    }
}
