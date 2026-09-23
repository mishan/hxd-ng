//! Common shape of every signed object: a canonical CBOR map with a `v`
//! and a `sig`, verified over the map minus `sig` under a per-type domain.

use crate::cbor::{self, Value};
use crate::error::Error;
use crate::keys::{verify_domain, PublicKey};

/// The current version of every object type this crate defines.
pub const VERSION: u64 = 1;

/// A decoded, canonical map with its signature split out. Not yet
/// verified — the caller knows which key applies.
pub(crate) struct Envelope {
    pub value: Value,
    pub signed_bytes: Vec<u8>,
    pub sig: [u8; 64],
}

impl Envelope {
    /// Decode and split. Checks canonical form, map-ness, `v`, and the
    /// shape of `sig`; nothing else.
    pub fn open(bytes: &[u8]) -> Result<Envelope, Error> {
        let value = cbor::decode_canonical(bytes)?;
        Self::from_value(value)
    }

    /// Same as [`Envelope::open`] for a map already decoded as part of a
    /// larger object (attestations inside a card). The bytes are known
    /// canonical because the enclosing object was.
    pub fn from_value(value: Value) -> Result<Envelope, Error> {
        if !matches!(value, Value::Map(_)) {
            return Err(Error::NotAMap);
        }
        // `!=`, not `>`: `v = 0` is not "an older version we can read",
        // it is a version that never existed, and accepting it would let
        // one object's bytes be re-read as another version later.
        let v = uint(&value, "v")?;
        if v != VERSION {
            return Err(Error::UnsupportedVersion(v));
        }
        let sig = bytes32x2(&value, "sig")?;
        let signed_bytes = cbor::encode(&value.without("sig"));
        Ok(Envelope {
            value,
            signed_bytes,
            sig,
        })
    }

    pub fn verify(&self, public: &PublicKey, domain: &str) -> Result<(), Error> {
        verify_domain(public, domain, &self.signed_bytes, &self.sig)
    }
}

/// An object with two signers (`identity-registrar.md` §4.1): `sig` by
/// the first and `ack` by the second, both over the map with *both*
/// removed, the second under the domain with `/ack` appended. Neither
/// signature covers the other, so the two parties can sign in either
/// order, and neither can be lifted onto a different object.
pub(crate) struct AckedEnvelope {
    pub value: Value,
    pub signed_bytes: Vec<u8>,
    pub sig: [u8; 64],
    pub ack: [u8; 64],
}

impl AckedEnvelope {
    pub fn from_value(value: Value) -> Result<AckedEnvelope, Error> {
        if !matches!(value, Value::Map(_)) {
            return Err(Error::NotAMap);
        }
        let v = uint(&value, "v")?;
        if v != VERSION {
            return Err(Error::UnsupportedVersion(v));
        }
        let sig = bytes32x2(&value, "sig")?;
        let ack = bytes32x2(&value, "ack")?;
        let signed_bytes = cbor::encode(&value.without("sig").without("ack"));
        Ok(AckedEnvelope {
            value,
            signed_bytes,
            sig,
            ack,
        })
    }

    pub fn verify(&self, first: &PublicKey, second: &PublicKey, domain: &str) -> Result<(), Error> {
        verify_domain(first, domain, &self.signed_bytes, &self.sig)?;
        verify_domain(second, &ack_domain(domain), &self.signed_bytes, &self.ack)
    }
}

pub(crate) fn ack_domain(domain: &str) -> String {
    format!("{domain}/ack")
}

/// [`seal`] for a two-signer object.
pub(crate) fn seal_acked(
    unsigned: Value,
    sign: impl FnOnce(&[u8]) -> [u8; 64],
    ack: impl FnOnce(&[u8]) -> [u8; 64],
) -> Vec<u8> {
    let body = cbor::encode(&unsigned);
    let sig = sign(&body);
    let ack = ack(&body);
    let Value::Map(mut entries) = unsigned else {
        unreachable!("seal_acked is only called with maps")
    };
    entries.push((Value::Text("sig".into()), Value::Bytes(sig.to_vec())));
    entries.push((Value::Text("ack".into()), Value::Bytes(ack.to_vec())));
    cbor::encode(&Value::Map(entries))
}

/// Attach a signature to an unsigned map and encode it.
pub(crate) fn seal(unsigned: Value, sign: impl FnOnce(&[u8]) -> [u8; 64]) -> Vec<u8> {
    let body = cbor::encode(&unsigned);
    let sig = sign(&body);
    let Value::Map(mut entries) = unsigned else {
        unreachable!("seal is only called with maps")
    };
    entries.push((Value::Text("sig".into()), Value::Bytes(sig.to_vec())));
    cbor::encode(&Value::Map(entries))
}

// Field accessors. Required variants fail on absence; optional ones fail
// only on presence with the wrong type, so a stray key of the wrong shape
// is an error rather than silently ignored.

pub(crate) fn uint(v: &Value, key: &'static str) -> Result<u64, Error> {
    match v.get(key) {
        Some(Value::Uint(n)) => Ok(*n),
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

pub(crate) fn opt_uint(v: &Value, key: &'static str) -> Result<Option<u64>, Error> {
    match v.get(key) {
        Some(Value::Uint(n)) => Ok(Some(*n)),
        Some(_) => Err(Error::BadField(key)),
        None => Ok(None),
    }
}

/// A byte string of any length, required. Most byte fields here are keys
/// or signatures and so are fixed-width; the exceptions are the ones
/// carrying another object whole — the bundle's `cert` and `card`, and
/// (through [`opt_bytes`]) an enrollment request's `prev`.
pub(crate) fn bytes(v: &Value, key: &'static str) -> Result<Vec<u8>, Error> {
    match v.get(key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

pub(crate) fn opt_bytes(v: &Value, key: &'static str) -> Result<Option<Vec<u8>>, Error> {
    match v.get(key) {
        Some(Value::Bytes(b)) => Ok(Some(b.clone())),
        Some(_) => Err(Error::BadField(key)),
        None => Ok(None),
    }
}

pub(crate) fn bytes32(v: &Value, key: &'static str) -> Result<[u8; 32], Error> {
    match v.get(key) {
        Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| Error::BadField(key)),
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

pub(crate) fn opt_bytes32(v: &Value, key: &'static str) -> Result<Option<[u8; 32]>, Error> {
    match v.get(key) {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| Error::BadField(key)),
        Some(_) => Err(Error::BadField(key)),
        None => Ok(None),
    }
}

fn bytes32x2(v: &Value, key: &'static str) -> Result<[u8; 64], Error> {
    match v.get(key) {
        Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| Error::BadField(key)),
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

pub(crate) fn text(v: &Value, key: &'static str) -> Result<String, Error> {
    match v.get(key) {
        Some(Value::Text(s)) => Ok(s.clone()),
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

pub(crate) fn opt_text(v: &Value, key: &'static str) -> Result<Option<String>, Error> {
    match v.get(key) {
        Some(Value::Text(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Error::BadField(key)),
        None => Ok(None),
    }
}

pub(crate) fn boolean(v: &Value, key: &'static str) -> Result<bool, Error> {
    match v.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

pub(crate) fn opt_bool(v: &Value, key: &'static str) -> Result<Option<bool>, Error> {
    match v.get(key) {
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(Error::BadField(key)),
        None => Ok(None),
    }
}

pub(crate) fn opt_array(v: &Value, key: &'static str) -> Result<Vec<Value>, Error> {
    match v.get(key) {
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(Error::BadField(key)),
        None => Ok(Vec::new()),
    }
}

/// Validity-window check shared by certificates and attestations.
/// `skew` is the server's tolerance in seconds, applied in both
/// directions.
pub(crate) fn check_window(issued: u64, expires: u64, now: u64, skew: u64) -> Result<(), Error> {
    if expires <= issued {
        return Err(Error::NotYetValid);
    }
    if issued > now.saturating_add(skew) {
        return Err(Error::NotYetValid);
    }
    if expires.saturating_add(skew) < now {
        return Err(Error::Expired);
    }
    Ok(())
}
