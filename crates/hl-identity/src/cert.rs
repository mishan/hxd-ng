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

/// Encoded size limit (§3.3). A certificate is three keys, two
/// timestamps, a capability mask and a short name — a few hundred bytes
/// signed — so this is room to spare rather than a constraint.
///
/// It needs a limit at all because a server caches the bytes of every
/// certificate it admits, one per device, and the only other bound is
/// the HTTP request body. Without this, a certificate whose `name` fills
/// that body made the device cache two orders of magnitude larger than
/// the card cache it was sized against (identity spec §13).
pub const MAX_BYTES: usize = 4 * 1024;

/// Device-name length in characters (§3.3). A device name is "Alice's
/// phone", shown next to the fingerprint.
pub const NAME_MAX_CHARS: usize = 64;

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
    ///
    /// Requires the device's own [`DeviceKey`] — which is exactly what a
    /// non-extractable browser key never gives up (hx-ng's
    /// `docs/identity-keys.md` §9). [`DeviceCert::for_keys`] is the same
    /// constructor for a caller that holds only the two public keys.
    pub fn for_device(
        identity: &IdentityKey,
        device: &DeviceKey,
        issued: u64,
        lifetime: u64,
    ) -> Result<Self, Error> {
        Self::for_keys(
            identity,
            device.public(),
            device.public_enc(),
            issued,
            lifetime,
        )
    }

    /// The same certificate as [`DeviceCert::for_device`], for a caller
    /// that holds the device's two *public* keys and not its seed — the
    /// shape a browser's non-extractable `CryptoKey`s are in: it can
    /// export the public half of each and no more, so there is no seed
    /// file to hand `for_device`.
    ///
    /// Refuses a window that doesn't fit in the field rather than
    /// wrapping into one: `issued + lifetime` overflowing would panic a
    /// debug build and, in release, silently produce a certificate that
    /// expired in 1970 — build-dependent bytes for something that gets
    /// signed.
    pub fn for_keys(
        identity: &IdentityKey,
        device: PublicKey,
        device_enc: [u8; 32],
        issued: u64,
        lifetime: u64,
    ) -> Result<Self, Error> {
        let expires = issued
            .checked_add(lifetime)
            .ok_or(Error::BadField("expires"))?;
        Ok(DeviceCert {
            identity: identity.public(),
            device,
            device_enc,
            issued,
            expires,
            caps: None,
            name: None,
        })
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

    /// Sign with the identity key, which must match `self.identity`.
    ///
    /// `assert!`, not `debug_assert!` (AGENTS.md): this is a wire
    /// invariant, and a release build that skipped it would hand back a
    /// certificate whose signature cannot verify — a failure that shows
    /// up as "the server rejects my device" a long way from its cause.
    pub fn sign(&self, identity: &IdentityKey) -> Vec<u8> {
        assert_eq!(
            identity.public(),
            self.identity,
            "signing a device certificate with a key that is not its identity"
        );
        signed::seal(self.unsigned(), |body| identity.sign(DOMAIN, body))
    }

    /// Decode and verify the signature against the embedded identity key.
    /// Time validity is a separate step ([`DeviceCert::check_valid`])
    /// because the caller decides the clock and the tolerance.
    ///
    /// The size is checked before anything is decoded, and the fields
    /// before the signature is verified: both are free, and this is the
    /// one place a certificate is bounded — `sign` stays infallible, and
    /// `hlid` parses back what it signs so an over-long `--name` is an
    /// error there rather than a certificate no server will read.
    pub fn parse(bytes: &[u8]) -> Result<DeviceCert, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let cert = Self::from_envelope(&env)?;
        cert.check_fields()?;
        env.verify(&cert.identity, DOMAIN)?;
        Ok(cert)
    }

    fn check_fields(&self) -> Result<(), Error> {
        match &self.name {
            // A device name is rendered next to a fingerprint, so it
            // refuses what a card's display name refuses (§3.3, §3.4) —
            // including a name made of spaces, and the surrounding space
            // that makes two device names look alike. Absent is fine;
            // present and empty is not, because that is a name saying
            // nothing rather than no name.
            Some(n)
                if n.chars().count() > NAME_MAX_CHARS
                    || n.trim() != n
                    || n.trim().is_empty()
                    || n.chars().any(crate::names::is_deceptive) =>
            {
                Err(Error::BadField("name"))
            }
            _ => Ok(()),
        }
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
    #[test]
    fn a_lifetime_that_does_not_fit_is_refused_not_wrapped() {
        use super::*;
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        assert_eq!(
            DeviceCert::for_device(&id, &dev, u64::MAX - 5, 10),
            Err(Error::BadField("expires")),
            "a release build would otherwise sign a cert that expired in 1970"
        );
        assert!(DeviceCert::for_device(&id, &dev, 0, u64::MAX).is_ok());
        assert!(DeviceCert::for_device(&id, &dev, 1, u64::MAX).is_err());
        // `for_device` is `for_keys` plus reading the two public halves
        // off a `DeviceKey`; the overflow check lives in `for_keys`
        // alone, so it has to refuse the same way called directly.
        assert_eq!(
            DeviceCert::for_keys(&id, dev.public(), dev.public_enc(), u64::MAX - 5, 10),
            Err(Error::BadField("expires"))
        );
    }

    #[test]
    fn for_keys_matches_for_device_given_the_same_keys() {
        use super::*;
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let via_device =
            DeviceCert::for_device(&id, &dev, 1_700_000_000, RECOMMENDED_LIFETIME).unwrap();
        let via_keys = DeviceCert::for_keys(
            &id,
            dev.public(),
            dev.public_enc(),
            1_700_000_000,
            RECOMMENDED_LIFETIME,
        )
        .unwrap();
        assert_eq!(via_device, via_keys);
        // And the signed bytes are identical, not just the struct —
        // `hlid cert --device-pub` and `hlid cert --device` for the same
        // key must produce the same certificate.
        assert_eq!(via_device.sign(&id), via_keys.sign(&id));
    }

    #[test]
    #[should_panic(expected = "not its identity")]
    fn signing_with_the_wrong_key_is_caught_in_every_build() {
        use super::*;
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let other = IdentityKey::from_seed(&[9u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        // `debug_assert!` here meant a release build shipped a
        // certificate that verifies nowhere (AGENTS.md).
        let _ = DeviceCert::for_device(&id, &dev, 0, 10)
            .unwrap()
            .sign(&other);
    }

    use super::*;

    fn fixture() -> (IdentityKey, DeviceKey, DeviceCert) {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let cert = DeviceCert::for_device(&id, &dev, 1_700_000_000, RECOMMENDED_LIFETIME).unwrap();
        (id, dev, cert)
    }

    #[test]
    fn an_oversized_certificate_is_refused_before_it_is_decoded() {
        // §13's bounded-growth claim: the server caches `cert` bytes per
        // device, `MAX_DEVICES` of them. Without this the only bound was
        // the 64 KiB request body, which is ~16x what the card table was
        // sized for.
        let (id, _, mut cert) = fixture();
        cert.name = Some("d".repeat(MAX_BYTES));
        assert_eq!(DeviceCert::parse(&cert.sign(&id)), Err(Error::TooLarge));

        // Small enough to decode, too long to accept.
        cert.name = Some("d".repeat(NAME_MAX_CHARS + 1));
        assert_eq!(
            DeviceCert::parse(&cert.sign(&id)),
            Err(Error::BadField("name"))
        );
        // And a name that hides, or says nothing, as a card's does
        // (§3.4).
        for name in ["phone\u{200b}", "", "   ", "phone "] {
            cert.name = Some(name.into());
            assert_eq!(
                DeviceCert::parse(&cert.sign(&id)),
                Err(Error::BadField("name")),
                "{name:?}"
            );
        }
        // No name at all is not a name saying nothing.
        cert.name = None;
        assert!(DeviceCert::parse(&cert.sign(&id)).is_ok());
        cert.name = Some("d".repeat(NAME_MAX_CHARS));
        assert!(DeviceCert::parse(&cert.sign(&id)).is_ok());
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
            ..DeviceCert::for_device(&other, &dev, 0, 10).unwrap()
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
