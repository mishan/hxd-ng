//! The device certificate (`docs/hotline-ng-identity.md` §3.3).

use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{DeviceKey, IdentityKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/device-cert/v1";

/// Device capability bits. Absent `caps` means all of them.
pub mod caps {
    /// May perform identity login.
    pub const LOGIN: u64 = 1 << 0;
    /// May sign and receive end-to-end messages.
    pub const MESSAGE: u64 = 1 << 1;
    /// May sign vouches on the user's behalf.
    pub const VOUCH: u64 = 1 << 2;
    /// May link/unlink accounts and change the user card.
    pub const MANAGE: u64 = 1 << 3;
    /// What a browser-hosted device should get.
    pub const WEB: u64 = LOGIN | MESSAGE;
}

/// The recommended certificate lifetime (§3.3).
pub const RECOMMENDED_LIFETIME: u64 = 90 * 24 * 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    pub identity: PublicKey,
    pub device: PublicKey,
    pub device_enc: [u8; 32],
    pub issued: u64,
    pub expires: u64,
    /// `None` on the wire means unrestricted.
    pub caps: Option<u64>,
    pub name: Option<String>,
}

impl DeviceCert {
    /// A certificate for `device`, valid from `issued` for `lifetime`
    /// seconds, unrestricted and unnamed. Adjust fields before signing.
    pub fn for_device(
        identity: &IdentityKey,
        device: &DeviceKey,
        issued: u64,
        lifetime: u64,
    ) -> Self {
        DeviceCert {
            identity: identity.public(),
            device: device.public(),
            device_enc: device.public_enc(),
            issued,
            expires: issued + lifetime,
            caps: None,
            name: None,
        }
    }

    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("device", Some(Value::Bytes(self.device.to_vec()))),
            ("device_enc", Some(Value::Bytes(self.device_enc.to_vec()))),
            ("issued", Some(Value::Uint(self.issued))),
            ("expires", Some(Value::Uint(self.expires))),
            ("caps", self.caps.map(Value::Uint)),
            ("name", self.name.clone().map(Value::Text)),
        ])
    }

    /// Sign with the identity key. The key must match `self.identity`;
    /// signing with another produces a certificate nobody will accept.
    pub fn sign(&self, identity: &IdentityKey) -> Vec<u8> {
        debug_assert_eq!(identity.public(), self.identity);
        signed::seal(self.unsigned(), |body| identity.sign(DOMAIN, body))
    }

    /// Decode and verify the signature against the embedded identity key.
    /// Time validity is a separate step ([`DeviceCert::check_valid`])
    /// because the caller decides the clock and the tolerance.
    pub fn parse(bytes: &[u8]) -> Result<DeviceCert, Error> {
        let env = Envelope::open(bytes)?;
        let cert = Self::from_envelope(&env)?;
        env.verify(&cert.identity, DOMAIN)?;
        Ok(cert)
    }

    fn from_envelope(env: &Envelope) -> Result<DeviceCert, Error> {
        let v = &env.value;
        Ok(DeviceCert {
            identity: signed::bytes32(v, "identity")?,
            device: signed::bytes32(v, "device")?,
            device_enc: signed::bytes32(v, "device_enc")?,
            issued: signed::uint(v, "issued")?,
            expires: signed::uint(v, "expires")?,
            caps: signed::opt_uint(v, "caps")?,
            name: signed::opt_text(v, "name")?,
        })
    }

    pub fn check_valid(&self, now: u64, skew: u64) -> Result<(), Error> {
        signed::check_window(self.issued, self.expires, now, skew)
    }

    pub fn allows(&self, cap: u64) -> bool {
        self.caps.is_none_or(|c| c & cap == cap)
    }

    pub fn require(&self, cap: u64) -> Result<(), Error> {
        if self.allows(cap) {
            Ok(())
        } else {
            Err(Error::CapabilityMissing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (IdentityKey, DeviceKey, DeviceCert) {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let cert = DeviceCert::for_device(&id, &dev, 1_700_000_000, RECOMMENDED_LIFETIME);
        (id, dev, cert)
    }

    #[test]
    fn round_trip() {
        let (id, _, mut cert) = fixture();
        cert.caps = Some(caps::WEB);
        cert.name = Some("browser".into());
        let bytes = cert.sign(&id);
        let back = DeviceCert::parse(&bytes).unwrap();
        assert_eq!(back, cert);
        assert!(back.allows(caps::LOGIN));
        assert!(!back.allows(caps::MANAGE));
        assert_eq!(back.require(caps::MANAGE), Err(Error::CapabilityMissing));
    }

    #[test]
    fn tampering_breaks_signature() {
        let (id, _, cert) = fixture();
        let mut bytes = cert.sign(&id);
        // Flip a bit inside the device_enc key, which the signature
        // covers but which isn't used to verify it.
        let at = bytes
            .windows(32)
            .position(|w| w == cert.device_enc)
            .unwrap();
        bytes[at + 5] ^= 1;
        assert_eq!(DeviceCert::parse(&bytes), Err(Error::BadSignature));
    }

    #[test]
    fn wrong_identity_key_is_rejected() {
        let (_, dev, mut cert) = fixture();
        let other = IdentityKey::from_seed(&[9u8; 32]);
        cert.identity = other.public();
        // Signed by `other` but claims... `other` — consistent, accepted.
        assert!(DeviceCert::parse(&cert.sign(&other)).is_ok());
        // Now claim the original identity while signing with `other`:
        // debug_assert catches it in tests, so bypass by building bytes
        // through the public path with a mismatched claim.
        let claim = DeviceCert {
            identity: IdentityKey::from_seed(&[1u8; 32]).public(),
            ..DeviceCert::for_device(&other, &dev, 0, 10)
        };
        let bytes = signed::seal(claim.unsigned(), |b| other.sign(DOMAIN, b));
        assert_eq!(DeviceCert::parse(&bytes), Err(Error::BadSignature));
    }

    #[test]
    fn validity_window() {
        let (_, _, cert) = fixture();
        let t = cert.issued;
        assert!(cert.check_valid(t, 0).is_ok());
        assert!(cert.check_valid(t - 100, 300).is_ok());
        assert_eq!(cert.check_valid(t - 400, 300), Err(Error::NotYetValid));
        assert!(cert.check_valid(cert.expires + 100, 300).is_ok());
        assert_eq!(
            cert.check_valid(cert.expires + 400, 300),
            Err(Error::Expired)
        );
    }

    #[test]
    fn unknown_fields_are_ignored_but_signed() {
        let (id, _, cert) = fixture();
        // Add a future field before signing — a v2 signer might.
        let Value::Map(mut entries) = cert.unsigned() else {
            unreachable!()
        };
        entries.push((Value::Text("future".into()), Value::Uint(42)));
        let bytes = signed::seal(Value::Map(entries), |b| id.sign(DOMAIN, b));
        assert_eq!(DeviceCert::parse(&bytes).unwrap(), cert);
    }

    #[test]
    fn newer_version_is_rejected() {
        let (id, _, cert) = fixture();
        let Value::Map(entries) = cert.unsigned() else {
            unreachable!()
        };
        let entries = entries
            .into_iter()
            .map(|(k, v)| {
                if matches!(&k, Value::Text(t) if t == "v") {
                    (k, Value::Uint(2))
                } else {
                    (k, v)
                }
            })
            .collect();
        let bytes = signed::seal(Value::Map(entries), |b| id.sign(DOMAIN, b));
        assert_eq!(DeviceCert::parse(&bytes), Err(Error::UnsupportedVersion(2)));
    }
}
