//! Hotline identity objects.
//!
//! The objects of `docs/hotline-ng-identity.md` §3 and the login proof of
//! `docs/hotline-ng-auth.md` §6.2: keys, device certificates, user cards,
//! registrar attestations and login proofs, with their deterministic CBOR
//! encoding and domain-separated Ed25519 signatures. No HTTP, no sockets,
//! no storage — a server, a registrar, a proxy, a relay and a client all
//! use this crate and nothing in it knows which one it is.
//!
//! Every object is built as a struct, signed to bytes, and parsed back
//! from bytes with its signature verified in the same call. Parsing checks
//! what can be checked without a clock or outside knowledge; time validity,
//! registrar-key confirmation and revocation are separate steps the caller
//! sequences, because the caller owns the clock, the trust list and the
//! cache. [`verify_login`] is that sequence for the common case.
//!
//! Test vectors live in `docs/identity-test-vectors.json` and are checked
//! by `tests/vectors.rs`; other implementations should check against the
//! same file.

pub mod attestation;
pub mod bundle;
pub mod card;
pub mod cbor;
pub mod cert;
pub mod enroll;
mod error;
pub mod keys;
mod names;
pub mod proof;
mod signed;

pub use attestation::Attestation;
pub use bundle::Bundle;
pub use card::Card;
pub use cert::{caps, DeviceCert};
pub use enroll::EnrollRequest;
pub use error::Error;
pub use keys::{DeviceKey, Fingerprint, IdentityKey, PublicKey, ServerKey};
pub use proof::LoginProof;
pub use signed::VERSION;

/// What a server needs to know to check a login (§5.2, steps 1–3).
#[derive(Debug, Clone, Copy)]
pub struct LoginContext<'a> {
    /// The challenge this server issued and has not yet consumed.
    pub challenge: &'a [u8; 32],
    /// This server's public key.
    pub server_key: &'a PublicKey,
    /// The server's clock, Unix seconds.
    pub now: u64,
    /// Clock-skew tolerance in seconds (`[identity] clock_skew`).
    pub skew: u64,
}

/// The result of a successful [`verify_login`]: the three objects, parsed
/// and mutually consistent.
#[derive(Debug, Clone)]
pub struct VerifiedLogin {
    pub card: Card,
    pub cert: DeviceCert,
    pub proof: LoginProof,
}

impl VerifiedLogin {
    pub fn identity(&self) -> &PublicKey {
        &self.cert.identity
    }

    pub fn device(&self) -> &PublicKey {
        &self.cert.device
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.cert.identity)
    }
}

/// Steps 1–3 of `/identity/auth` for the challenge binding, in the spec's
/// order and failing on the first error:
///
/// 1. the proof verifies, answers this challenge for this server, and is
///    fresh;
/// 2. the certificate verifies, names the proof's device key, is within
///    its validity window, and grants login;
/// 3. the card verifies and belongs to the certificate's identity.
///
/// Not done here, because they need state this crate doesn't hold:
/// revocation (step 4), attestation trust and age (step 5), and policy
/// (step 6). The returned [`VerifiedLogin`] carries the parsed
/// attestations for the caller to confirm with
/// [`Attestation::verify_registrar`].
pub fn verify_login(
    card: &[u8],
    cert: &[u8],
    proof: &[u8],
    ctx: LoginContext<'_>,
) -> Result<VerifiedLogin, Error> {
    let proof = LoginProof::parse(proof)?;
    proof.check(ctx.challenge, ctx.server_key, ctx.now, ctx.skew)?;

    let cert = DeviceCert::parse(cert)?;
    if cert.device != proof.device {
        return Err(Error::KeyMismatch);
    }
    cert.check_valid(ctx.now, ctx.skew)?;
    cert.require(caps::LOGIN)?;

    let card = Card::parse(card)?;
    if card.identity != cert.identity {
        return Err(Error::KeyMismatch);
    }

    Ok(VerifiedLogin { card, cert, proof })
}

/// The mTLS binding's variant (§5.3): the transport already proved
/// possession of `device`, so there is no proof; the card and certificate
/// are checked against that key instead.
pub fn verify_presented(
    card: &[u8],
    cert: &[u8],
    device: &PublicKey,
    now: u64,
    skew: u64,
) -> Result<(Card, DeviceCert), Error> {
    let cert = DeviceCert::parse(cert)?;
    if &cert.device != device {
        return Err(Error::KeyMismatch);
    }
    cert.check_valid(now, skew)?;
    cert.require(caps::LOGIN)?;
    let card = Card::parse(card)?;
    if card.identity != cert.identity {
        return Err(Error::KeyMismatch);
    }
    Ok((card, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct World {
        id: IdentityKey,
        dev: DeviceKey,
        srv: ServerKey,
        card: Vec<u8>,
        cert: Vec<u8>,
    }

    fn world() -> World {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let srv = ServerKey::from_seed(&[5u8; 32]);
        let card = Card::new(&id, "Alice", 1_700_000_000)
            .sign(&id, vec![])
            .unwrap();
        let cert = DeviceCert::for_device(&id, &dev, 1_700_000_000, cert::RECOMMENDED_LIFETIME)
            .unwrap()
            .sign(&id);
        World {
            id,
            dev,
            srv,
            card,
            cert,
        }
    }

    #[test]
    fn happy_path() {
        let w = world();
        let ch = [7u8; 32];
        let proof = LoginProof::sign(&w.dev, &ch, &w.srv.public(), 1_700_000_500);
        let ctx = LoginContext {
            challenge: &ch,
            server_key: &w.srv.public(),
            now: 1_700_000_600,
            skew: 300,
        };
        let v = verify_login(&w.card, &w.cert, &proof, ctx).unwrap();
        assert_eq!(v.identity(), &w.id.public());
        assert_eq!(v.device(), &w.dev.public());
        assert_eq!(v.fingerprint(), w.id.fingerprint());
    }

    #[test]
    fn proof_from_a_different_device_than_the_cert() {
        let w = world();
        let stranger = DeviceKey::from_seed(&[8u8; 32]);
        let ch = [7u8; 32];
        let proof = LoginProof::sign(&stranger, &ch, &w.srv.public(), 1_700_000_500);
        let ctx = LoginContext {
            challenge: &ch,
            server_key: &w.srv.public(),
            now: 1_700_000_500,
            skew: 300,
        };
        assert_eq!(
            verify_login(&w.card, &w.cert, &proof, ctx).unwrap_err(),
            Error::KeyMismatch
        );
    }

    #[test]
    fn card_from_a_different_identity_than_the_cert() {
        let w = world();
        let other = IdentityKey::from_seed(&[9u8; 32]);
        let card = Card::new(&other, "Other", 1).sign(&other, vec![]).unwrap();
        let ch = [7u8; 32];
        let proof = LoginProof::sign(&w.dev, &ch, &w.srv.public(), 1_700_000_500);
        let ctx = LoginContext {
            challenge: &ch,
            server_key: &w.srv.public(),
            now: 1_700_000_500,
            skew: 300,
        };
        assert_eq!(
            verify_login(&card, &w.cert, &proof, ctx).unwrap_err(),
            Error::KeyMismatch
        );
    }

    #[test]
    fn expired_cert_and_missing_login_cap() {
        let w = world();
        let ch = [7u8; 32];
        let proof = LoginProof::sign(&w.dev, &ch, &w.srv.public(), 1_800_000_000);
        let ctx = LoginContext {
            challenge: &ch,
            server_key: &w.srv.public(),
            now: 1_800_000_000,
            skew: 300,
        };
        assert_eq!(
            verify_login(&w.card, &w.cert, &proof, ctx).unwrap_err(),
            Error::Expired
        );

        let mut c = DeviceCert::for_device(&w.id, &w.dev, 1_700_000_000, 1000).unwrap();
        c.caps = Some(caps::MESSAGE);
        let cert = c.sign(&w.id);
        let proof = LoginProof::sign(&w.dev, &ch, &w.srv.public(), 1_700_000_100);
        let ctx = LoginContext {
            challenge: &ch,
            server_key: &w.srv.public(),
            now: 1_700_000_100,
            skew: 300,
        };
        assert_eq!(
            verify_login(&w.card, &cert, &proof, ctx).unwrap_err(),
            Error::CapabilityMissing
        );
    }

    #[test]
    fn presented_binding() {
        let w = world();
        let (card, cert) =
            verify_presented(&w.card, &w.cert, &w.dev.public(), 1_700_000_100, 300).unwrap();
        assert_eq!(card.identity, cert.identity);
        let stranger = DeviceKey::from_seed(&[8u8; 32]);
        assert_eq!(
            verify_presented(&w.card, &w.cert, &stranger.public(), 1_700_000_100, 300).unwrap_err(),
            Error::KeyMismatch
        );
    }
}
