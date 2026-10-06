//! Server keys and the key proof (the extension's "Server Keys over TLS"
//! and "The Key Proof").
//!
//! Each side of a key-mode link signs the TLS 1.3 exporter value of the
//! session, bound to its role and to both keys. The exporter depends on
//! the whole handshake, so a proof made for one TLS session is worthless
//! in another: that is what lets the certificate go unverified.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::server::ServerId;

pub use hxd_session::peer::{EXPORTER_LABEL, EXPORTER_LEN};

const PROOF_DOMAIN: &[u8] = b"hotline-link-key-proof-v1";

/// Which end of the link made a proof. Bound into it, so neither side can
/// hand the other's proof back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Dialer,
    Acceptor,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Dialer => 0x01,
            Role::Acceptor => 0x02,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Not the canonical encoding of a curve point.
    NotCanonical,
    /// A point of small order, for which anyone can forge.
    SmallOrder,
}

/// Check a public key the way every implementation must, so a key one
/// server accepts is never one another refuses. Go's `crypto/ed25519` and
/// `ed25519-dalek` both accept some keys the extension forbids, so the
/// check is made here, where a key is configured or received.
pub fn check_public(public: &[u8; 32]) -> Result<VerifyingKey, KeyError> {
    let point = CompressedEdwardsY(*public)
        .decompress()
        .ok_or(KeyError::NotCanonical)?;
    if point.compress().to_bytes() != *public {
        return Err(KeyError::NotCanonical);
    }
    if point.is_small_order() {
        return Err(KeyError::SmallOrder);
    }
    VerifyingKey::from_bytes(public).map_err(|_| KeyError::NotCanonical)
}

fn proof_message(
    role: Role,
    exporter: &[u8; EXPORTER_LEN],
    signer: &[u8; 32],
    peer: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(PROOF_DOMAIN.len() + 1 + 1 + EXPORTER_LEN + 64);
    m.extend_from_slice(PROOF_DOMAIN);
    m.push(0x00);
    m.push(role.byte());
    m.extend_from_slice(exporter);
    m.extend_from_slice(signer);
    m.extend_from_slice(peer);
    m
}

/// This server's key.
pub struct LinkKey {
    signing: SigningKey,
}

impl LinkKey {
    pub fn from_seed(seed: &[u8; 32]) -> LinkKey {
        LinkKey {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn server_id(&self) -> ServerId {
        ServerId::of_key(&self.public())
    }

    pub fn fingerprint(&self) -> hl_identity::Fingerprint {
        hl_identity::Fingerprint::of(&self.public())
    }

    /// This side's proof for a session, to the peer whose key is `peer`.
    pub fn prove(&self, role: Role, exporter: &[u8; EXPORTER_LEN], peer: &[u8; 32]) -> [u8; 64] {
        self.signing
            .sign(&proof_message(role, exporter, &self.public(), peer))
            .to_bytes()
    }
}

/// Check the peer's proof. Every input is this side's own: the key its
/// operator configured for the peer, the role the peer must have played,
/// its own exporter value and its own key. Nothing is taken from the wire
/// but the signature.
pub fn verify_proof(
    configured: &VerifyingKey,
    peer_role: Role,
    exporter: &[u8; EXPORTER_LEN],
    own: &[u8; 32],
    proof: &[u8; 64],
) -> bool {
    let message = proof_message(peer_role, exporter, &configured.to_bytes(), own);
    configured
        .verify_strict(&message, &Signature::from_bytes(proof))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> LinkKey {
        LinkKey::from_seed(&[b; 32])
    }

    #[test]
    fn a_proof_verifies_only_for_its_session_role_and_keys() {
        let (dialer, acceptor, other) = (key(1), key(2), key(3));
        let exporter = [9; EXPORTER_LEN];
        let proof = dialer.prove(Role::Dialer, &exporter, &acceptor.public());
        let dialer_vk = check_public(&dialer.public()).unwrap();

        assert!(verify_proof(
            &dialer_vk,
            Role::Dialer,
            &exporter,
            &acceptor.public(),
            &proof
        ));
        // Another TLS session: a man in the middle carrying it across.
        assert!(!verify_proof(
            &dialer_vk,
            Role::Dialer,
            &[8; EXPORTER_LEN],
            &acceptor.public(),
            &proof
        ));
        // Reflected back as the other role.
        assert!(!verify_proof(
            &dialer_vk,
            Role::Acceptor,
            &exporter,
            &acceptor.public(),
            &proof
        ));
        // Meant for a different server.
        assert!(!verify_proof(
            &dialer_vk,
            Role::Dialer,
            &exporter,
            &other.public(),
            &proof
        ));
        // Checked against a key that did not make it.
        let other_vk = check_public(&other.public()).unwrap();
        assert!(!verify_proof(
            &other_vk,
            Role::Dialer,
            &exporter,
            &acceptor.public(),
            &proof
        ));
    }

    #[test]
    fn non_canonical_and_small_order_keys_are_refused() {
        // The identity point, of order 1.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(check_public(&identity).err(), Some(KeyError::SmallOrder));
        // y = p (2^255 - 19) encodes the same point as y = 0, non-canonically.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(check_public(&p).err(), Some(KeyError::NotCanonical));
        assert!(check_public(&key(1).public()).is_ok());
    }

    #[test]
    fn a_servers_id_is_the_start_of_its_key_fingerprint() {
        let k = key(1);
        assert_eq!(k.server_id().0, k.fingerprint().0[..8]);
    }
}
