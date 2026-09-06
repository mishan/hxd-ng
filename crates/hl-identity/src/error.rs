//! One error type for every parse and verification failure.
//!
//! The variants are deliberately coarse on the wire-facing side: a server
//! maps them to the spec's `bad_card` / `bad_cert` / `bad_proof` codes and
//! logs the detail. Nothing here carries key material.

use std::fmt;

use crate::cbor::CborError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bytes weren't (canonical) CBOR from the supported subset.
    Cbor(CborError),
    /// The top-level item wasn't a map.
    NotAMap,
    /// A required key is absent.
    MissingField(&'static str),
    /// A key is present with the wrong type or an out-of-range value.
    BadField(&'static str),
    /// `v` is newer than this implementation understands.
    UnsupportedVersion(u64),
    /// A public key that isn't a valid Ed25519 point.
    InvalidKey,
    /// The signature didn't verify under the object's domain.
    BadSignature,
    /// Two objects that must agree on a key don't.
    KeyMismatch,
    /// `expires` is in the past (beyond the skew allowance).
    Expired,
    /// `issued` is in the future (beyond the skew allowance), or
    /// `expires` isn't after `issued`.
    NotYetValid,
    /// A proof's `time` is outside the skew allowance.
    ClockSkew,
    /// A proof echoes a different challenge or server key than expected.
    ChallengeMismatch,
    /// The device certificate doesn't grant the capability being used.
    CapabilityMissing,
    /// The object exceeds its size limit.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cbor(e) => write!(f, "{e}"),
            Error::NotAMap => write!(f, "object is not a CBOR map"),
            Error::MissingField(k) => write!(f, "missing field `{k}`"),
            Error::BadField(k) => write!(f, "bad field `{k}`"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported object version {v}"),
            Error::InvalidKey => write!(f, "invalid public key"),
            Error::BadSignature => write!(f, "bad signature"),
            Error::KeyMismatch => write!(f, "key mismatch between objects"),
            Error::Expired => write!(f, "expired"),
            Error::NotYetValid => write!(f, "not yet valid"),
            Error::ClockSkew => write!(f, "timestamp outside clock-skew tolerance"),
            Error::ChallengeMismatch => write!(f, "challenge or server key mismatch"),
            Error::CapabilityMissing => {
                write!(f, "device certificate lacks the required capability")
            }
            Error::TooLarge => write!(f, "object too large"),
        }
    }
}

impl std::error::Error for Error {}

impl From<CborError> for Error {
    fn from(e: CborError) -> Self {
        Error::Cbor(e)
    }
}
