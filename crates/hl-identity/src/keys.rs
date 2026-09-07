//! Identity and device keys, fingerprints, and domain-separated signing.
//!
//! Two tiers (`docs/hotline-ng-identity.md` §3): the **identity key** is
//! long-lived and signs certificates, cards and lifecycle records; a
//! **device key** is minted per device, certified by the identity key, and
//! does everything routine. Neither tier's secret leaves this module except
//! as a seed the caller asked for in order to store it.
//!
//! Every signature in the protocol is over `domain || 0x00 || bytes`, with a
//! distinct domain string per object type, so a signature made for one
//! purpose can't be replayed as another.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::Error;

/// A 32-byte Ed25519 public key.
pub type PublicKey = [u8; 32];

/// `SHA-256(public key)`.
///
/// Displayed as lowercase Crockford base32 (52 characters, no padding);
/// [`Fingerprint::short`] gives the first eight for UI. Servers store and
/// compare the full 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of(public: &PublicKey) -> Self {
        Fingerprint(Sha256::digest(public).into())
    }

    /// The first eight display characters — enough to tell users apart in
    /// a user-info panel, never enough to authorize anything.
    pub fn short(&self) -> String {
        self.to_string().chars().take(8).collect()
    }

    /// Parse the display form: exactly 52 Crockford base32 digits. Case
    /// and the usual Crockford confusables (`o`→`0`, `i`/`l`→`1`) are
    /// accepted, since the form exists to be typed and pasted.
    pub fn parse(s: &str) -> Option<Fingerprint> {
        if s.len() != 52 {
            return None;
        }
        let mut out = [0u8; 32];
        let mut acc: u64 = 0;
        let mut nbits = 0;
        let mut i = 0;
        for c in s.bytes() {
            let c = match c.to_ascii_lowercase() {
                b'o' => b'0',
                b'i' | b'l' => b'1',
                c => c,
            };
            let d = CROCKFORD.iter().position(|&x| x == c)? as u64;
            acc = (acc << 5) | d;
            nbits += 5;
            if nbits >= 8 {
                nbits -= 8;
                if i < 32 {
                    out[i] = ((acc >> nbits) & 0xff) as u8;
                    i += 1;
                }
            }
        }
        // 52 digits carry 260 bits; the trailing 4 must be zero.
        if i != 32 || acc & ((1 << nbits) - 1) != 0 {
            return None;
        }
        Some(Fingerprint(out))
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 256 bits → 52 base32 digits (the last carries 1 bit).
        let mut acc: u64 = 0;
        let mut nbits = 0;
        for &b in &self.0 {
            acc = (acc << 8) | b as u64;
            nbits += 8;
            while nbits >= 5 {
                nbits -= 5;
                f.write_str(
                    std::str::from_utf8(&CROCKFORD[((acc >> nbits) & 31) as usize..][..1]).unwrap(),
                )?;
            }
        }
        if nbits > 0 {
            f.write_str(
                std::str::from_utf8(&CROCKFORD[((acc << (5 - nbits)) & 31) as usize..][..1])
                    .unwrap(),
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self)
    }
}

fn fresh_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).expect("OS CSPRNG unavailable");
    seed
}

/// Sign `bytes` under `domain` with an Ed25519 key.
fn sign_domain(key: &SigningKey, domain: &str, bytes: &[u8]) -> [u8; 64] {
    let mut msg = Vec::with_capacity(domain.len() + 1 + bytes.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.push(0);
    msg.extend_from_slice(bytes);
    key.sign(&msg).to_bytes()
}

/// Verify a domain-separated signature.
///
/// The key is checked, not merely decompressed. `VerifyingKey::from_bytes`
/// only says the bytes are a point; the small-order points are points
/// too, and the neutral element with `S = 0` verifies *any* message under
/// the permissive equation. Since a fingerprint is a hash of the public
/// key, such a key would be a shared identity — one every holder could
/// sign for, and a single allow-list entry, link or block for all of
/// them. `is_weak` rejects the small-order points, and `verify_strict`
/// closes the cofactor ambiguity for everything else.
pub fn verify_domain(
    public: &PublicKey,
    domain: &str,
    bytes: &[u8],
    sig: &[u8; 64],
) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::InvalidKey)?;
    if key.is_weak() {
        return Err(Error::InvalidKey);
    }
    let mut msg = Vec::with_capacity(domain.len() + 1 + bytes.len());
    msg.extend_from_slice(domain.as_bytes());
    msg.push(0);
    msg.extend_from_slice(bytes);
    key.verify_strict(&msg, &Signature::from_bytes(sig))
        .map_err(|_| Error::BadSignature)
}

/// The long-lived identity key.
pub struct IdentityKey {
    signing: SigningKey,
}

impl IdentityKey {
    /// A new identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::from_seed(&fresh_seed())
    }

    /// Reconstruct from a stored 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        IdentityKey {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The seed, for the caller to wrap and store. Zeroized on drop.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        self.signing.verifying_key().to_bytes()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public())
    }

    pub(crate) fn sign(&self, domain: &str, bytes: &[u8]) -> [u8; 64] {
        sign_domain(&self.signing, domain, bytes)
    }
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityKey({})", self.fingerprint())
    }
}

/// A device's signing and encryption keys.
///
/// Both are derived from one 32-byte seed so a device stores one secret:
/// the signing key is the seed itself; the X25519 secret is
/// `SHA-256("hl-identity/device-enc/v1" || seed)`, clamped by the library.
/// The two keys are independent as far as anyone without the seed can tell.
pub struct DeviceKey {
    signing: SigningKey,
    enc: x25519_dalek::StaticSecret,
}

impl DeviceKey {
    pub fn generate() -> Self {
        Self::from_seed(&fresh_seed())
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(b"hl-identity/device-enc/v1");
        h.update(seed);
        let enc_seed: [u8; 32] = h.finalize().into();
        DeviceKey {
            signing: SigningKey::from_bytes(seed),
            enc: x25519_dalek::StaticSecret::from(enc_seed),
        }
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// The Ed25519 public key — the `device` field of a certificate.
    pub fn public(&self) -> PublicKey {
        self.signing.verifying_key().to_bytes()
    }

    /// The X25519 public key — the `device_enc` field of a certificate.
    pub fn public_enc(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.enc).to_bytes()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public())
    }

    pub(crate) fn sign(&self, domain: &str, bytes: &[u8]) -> [u8; 64] {
        sign_domain(&self.signing, domain, bytes)
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({})", self.fingerprint())
    }
}

/// A registrar's or server's signing key. Same primitive as the identity
/// key; a separate type so the two can't be confused at a call site.
pub struct ServerKey {
    signing: SigningKey,
}

impl ServerKey {
    pub fn generate() -> Self {
        Self::from_seed(&fresh_seed())
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        ServerKey {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        self.signing.verifying_key().to_bytes()
    }

    pub(crate) fn sign(&self, domain: &str, bytes: &[u8]) -> [u8; 64] {
        sign_domain(&self.signing, domain, bytes)
    }
}

impl fmt::Debug for ServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerKey({})", Fingerprint::of(&self.public()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_display_is_52_chars_and_stable() {
        let fp = Fingerprint([0u8; 32]);
        assert_eq!(fp.to_string(), "0".repeat(52));
        let fp = Fingerprint([0xff; 32]);
        // 255 bits of ones then one zero bit: 51 'z' and then 'y'? No —
        // 256 = 51*5 + 1, so the last digit carries one 1-bit padded with
        // four zeros: 0b10000 = 16 = 'g'.
        assert_eq!(fp.to_string(), format!("{}g", "z".repeat(51)));
        assert_eq!(fp.short().len(), 8);
    }

    #[test]
    fn fingerprint_parse_round_trips() {
        let fp = Fingerprint::of(&IdentityKey::from_seed(&[3u8; 32]).public());
        let text = fp.to_string();
        assert_eq!(Fingerprint::parse(&text), Some(fp));
        assert_eq!(Fingerprint::parse(&text.to_uppercase()), Some(fp));
        assert_eq!(Fingerprint::parse(&text[..51]), None);
        let mut bad = text.clone();
        bad.replace_range(51..52, "z"); // non-zero padding bits
        assert_eq!(Fingerprint::parse(&bad), None);
        assert_eq!(Fingerprint::parse(&"u".repeat(52)), None); // 'u' isn't in the alphabet
    }

    #[test]
    fn domain_separation() {
        let k = IdentityKey::from_seed(&[7u8; 32]);
        let sig = k.sign("a", b"msg");
        assert!(verify_domain(&k.public(), "a", b"msg", &sig).is_ok());
        assert_eq!(
            verify_domain(&k.public(), "b", b"msg", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            verify_domain(&k.public(), "a", b"msh", &sig),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn device_keys_are_seed_determined() {
        let a = DeviceKey::from_seed(&[1u8; 32]);
        let b = DeviceKey::from_seed(&[1u8; 32]);
        assert_eq!(a.public(), b.public());
        assert_eq!(a.public_enc(), b.public_enc());
        assert_ne!(a.public(), a.public_enc());
    }

    #[test]
    fn small_order_keys_cannot_sign_for_everyone() {
        // The neutral element with S = 0 verifies any message under the
        // permissive equation, and its fingerprint would then be an
        // identity shared by everyone who tried it.
        let neutral = [0u8; 32];
        let sig = [0u8; 64];
        assert_eq!(
            verify_domain(&neutral, "hl-identity/card/v1", b"anything", &sig),
            Err(Error::InvalidKey)
        );
        assert_eq!(
            verify_domain(&neutral, "hl-identity/card/v1", b"something else", &sig),
            Err(Error::InvalidKey)
        );
        // The order-8 point with the low bit set decompresses fine and is
        // still weak.
        let mut order8 = [0u8; 32];
        order8[0] = 0x01;
        assert!(matches!(
            verify_domain(&order8, "hl-identity/card/v1", b"x", &sig),
            Err(Error::InvalidKey) | Err(Error::BadSignature)
        ));
    }

    #[test]
    fn invalid_public_key_is_rejected_not_panicked() {
        // Roughly half of all 32-byte strings don't decompress to a curve
        // point; find one rather than hard-code an encoding whose
        // treatment (canonical or not) varies between libraries.
        let bad = (0u8..=255)
            .map(|i| {
                let mut k = [0u8; 32];
                k[0] = i;
                k
            })
            .find(|k| VerifyingKey::from_bytes(k).is_err())
            .expect("some low-y encoding is off-curve");
        assert_eq!(
            verify_domain(&bad, "a", b"", &[0; 64]),
            Err(Error::InvalidKey)
        );
    }
}
