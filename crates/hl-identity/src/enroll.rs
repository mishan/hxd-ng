//! The enrollment request (`docs/identity-enrollment.md` §4): a device
//! asking to be certified, signed by the key it wants certified.
//!
//! It is the *question* half of enrollment, and [`crate::Bundle`] is the
//! answer. A device posts one of these to a mailbox under a pairing
//! code; the holder of the identity key reads it, shows a human what it
//! is about to certify, and signs a certificate if the human says yes.
//!
//! The signature proves only that the requester holds the key it is
//! asking about, which for a first enrollment proves very little — a
//! certificate for a key you do not hold is useless to you. It is worth
//! having anyway for two reasons. It makes [`EnrollRequest::prev`] mean
//! something, since a renewal signed by the key the old certificate
//! names is the same device asking again (§8). And it keeps one format,
//! rather than a signed object for renewals and an unsigned one for
//! everything else.
//!
//! Nothing here decides anything. What a request *gets* is the holder's
//! policy intersected with what it asked for (§6), and no field in this
//! object can widen it. `caps`, `days` and `name` are requests in the
//! ordinary English sense: a holder reads them, shows them, and is free
//! to grant less.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::cbor::{map, Value};
use crate::cert;
use crate::error::Error;
use crate::keys::{DeviceKey, IdentityKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/enroll-request/v1";

/// Encoded size limit (§4). Room for the optional `prev`, which is a
/// whole certificate and bounded at [`cert::MAX_BYTES`], plus the keys
/// and the short strings around it.
pub const MAX_BYTES: usize = 8 * 1024;

/// The pairing secret drawn by the holder for the QR path (§5.6). Not a
/// key and never sent to the mailbox: the holder puts it in a QR code,
/// the enrollee reads it with a camera, and the tag it produces proves
/// the request came from whoever was looking at that screen.
///
/// Sixteen bytes rather than something typeable, deliberately: the typed
/// path asks a human to compare fingerprints instead, and a short secret
/// here would weaken the one path that does not need a human at all.
pub const PAIRING_SECRET_BYTES: usize = 16;

/// `HMAC-SHA-256(pairing secret, device public key)` — §4's `pair`.
///
/// Keyed by the secret and over the device key, so it binds *this*
/// device to *that* QR code. A mailbox that never saw the secret cannot
/// produce one for a device key of its own, which is what stops it
/// substituting a request on the scanned path (§9).
pub fn pair_tag(secret: &[u8; PAIRING_SECRET_BYTES], device: &PublicKey) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(device);
    mac.finalize().into_bytes().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollRequest {
    /// The Ed25519 public key being enrolled; the key that signs this.
    pub device: PublicKey,
    /// The X25519 public key that will go in the certificate.
    pub device_enc: [u8; 32],
    /// A label for the device, subject to the certificate's name rules.
    pub name: Option<String>,
    /// Capability bits asked for. `None` leaves it to the holder.
    pub caps: Option<u64>,
    /// Lifetime in days asked for. `None` leaves it to the holder.
    pub days: Option<u64>,
    /// When this was made. A holder outside its skew tolerance treats it
    /// as a replay.
    pub time: u64,
    /// The device's current certificate, for a renewal (§8).
    pub prev: Option<Vec<u8>>,
    /// [`pair_tag`], when the enrollee scanned the holder's QR code.
    pub pair: Option<[u8; 32]>,
}

impl EnrollRequest {
    /// A first-enrollment request for `device`, with nothing asked for.
    /// Set the optional fields before signing.
    pub fn new(device: &DeviceKey, time: u64) -> Self {
        EnrollRequest {
            device: device.public(),
            device_enc: device.public_enc(),
            name: None,
            caps: None,
            days: None,
            time,
            prev: None,
            pair: None,
        }
    }

    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("device", Some(Value::Bytes(self.device.to_vec()))),
            ("device_enc", Some(Value::Bytes(self.device_enc.to_vec()))),
            ("name", self.name.clone().map(Value::Text)),
            ("caps", self.caps.map(Value::Uint)),
            ("days", self.days.map(Value::Uint)),
            ("time", Some(Value::Uint(self.time))),
            ("prev", self.prev.clone().map(Value::Bytes)),
            ("pair", self.pair.map(|p| Value::Bytes(p.to_vec()))),
        ])
    }

    /// Sign with the device key, which must be the one named in
    /// `device`.
    ///
    /// `assert!`, not `debug_assert!` (AGENTS.md): a release build that
    /// skipped it would produce a request that cannot verify, and the
    /// holder would report it as a bad request a long way from here.
    pub fn sign(&self, device: &DeviceKey) -> Vec<u8> {
        assert_eq!(
            device.public(),
            self.device,
            "signing an enrollment request with a key that is not the one it names"
        );
        signed::seal(self.unsigned(), |body| device.sign(DOMAIN, body))
    }

    /// Decode and verify the signature against the `device` key the
    /// object itself names — the only key that could have signed it, and
    /// the only one a mailbox or a holder has before it has decided
    /// anything.
    ///
    /// Field checks come before the signature check, since they are free
    /// and this is reached by an unauthenticated caller.
    pub fn parse(bytes: &[u8]) -> Result<EnrollRequest, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let req = Self::from_envelope(&env)?;
        req.check_fields()?;
        env.verify(&req.device, DOMAIN)?;
        Ok(req)
    }

    fn from_envelope(env: &Envelope) -> Result<EnrollRequest, Error> {
        let v = &env.value;
        Ok(EnrollRequest {
            device: signed::bytes32(v, "device")?,
            device_enc: signed::bytes32(v, "device_enc")?,
            name: signed::opt_text(v, "name")?,
            caps: signed::opt_uint(v, "caps")?,
            days: signed::opt_uint(v, "days")?,
            time: signed::uint(v, "time")?,
            prev: signed::opt_bytes(v, "prev")?,
            pair: signed::opt_bytes32(v, "pair")?,
        })
    }

    fn check_fields(&self) -> Result<(), Error> {
        // §4: the name follows §3.3's rules, because it is going into a
        // certificate's `name` if the holder accepts it as offered. A
        // request whose name a certificate could not carry is refused
        // here rather than silently rewritten there.
        if let Some(n) = &self.name {
            if n.chars().count() > cert::NAME_MAX_CHARS
                || n.trim() != n
                || n.trim().is_empty()
                || n.chars().any(crate::names::is_deceptive)
            {
                return Err(Error::BadField("name"));
            }
        }
        // Bounded here as well as by MAX_BYTES: `prev` is the only
        // variable-length field, so without this the size limit is the
        // only thing between a caller and an 8 KiB "certificate" that
        // every holder will try to parse.
        if self
            .prev
            .as_ref()
            .is_some_and(|p| p.len() > cert::MAX_BYTES)
        {
            return Err(Error::BadField("prev"));
        }
        Ok(())
    }

    /// The certificate this request is renewing, parsed and checked
    /// against the request that carries it.
    ///
    /// Separate from [`EnrollRequest::parse`] for the reason
    /// [`crate::Bundle::open`] is separate from its parse: a mailbox
    /// routes a request by reading `prev`'s identity and never needs to
    /// verify it, and making every reader pay for an extra signature
    /// check would be an unauthenticated caller's idea of a good time.
    ///
    /// What is checked here is the part that does not need to know the
    /// identity: that `prev` really is a certificate, and that it names
    /// the same device as the request. Whether it was signed by the
    /// identity being asked, and whether the caps and lifetime asked for
    /// are no wider than it (§8), is the holder's policy and needs the
    /// holder's key to judge.
    pub fn prev_cert(&self) -> Option<Result<cert::DeviceCert, Error>> {
        let prev = self.prev.as_ref()?;
        Some(cert::DeviceCert::parse(prev).and_then(|c| {
            if c.device == self.device {
                Ok(c)
            } else {
                Err(Error::KeyMismatch)
            }
        }))
    }

    /// Whether `pair` is the tag for this device under `secret`.
    ///
    /// A request with no `pair` is not scanned and answers `false`; a
    /// request with a wrong one is refused outright rather than shown to
    /// the user (§6), because the only way to produce one is to have
    /// guessed.
    pub fn pair_matches(&self, secret: &[u8; PAIRING_SECRET_BYTES]) -> bool {
        let Some(tag) = self.pair else {
            return false;
        };
        // Through the MAC's own verifier rather than `==`: this compares
        // a value an attacker chooses against one they are trying to
        // find, which is the shape that wants a constant-time compare.
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&self.device);
        mac.verify_slice(&tag).is_ok()
    }
}

/// The domain of a [`SessionClaim`]. Distinct from [`DOMAIN`], so a
/// signature made over one object can never be read as the other.
pub const CLAIM_DOMAIN: &str = "hl-identity/enroll-session/v1";

/// A holder proving, to a mailbox, that it holds the identity key whose
/// renewals it is asking to be sent (§5.1).
///
/// §5.1 originally asked for no proof here, and the reasoning was sound
/// for what the mailbox held at the time: a session opened by someone
/// with no identity key can answer nothing an enrollee would accept, so
/// there was nothing a proof would protect. §8's codeless renewal
/// changed that. The mailbox now keeps an index from identity
/// fingerprint to session, and a fingerprint is public — so without this
/// object, anyone could claim anyone's fingerprint and have every
/// renewal for that identity delivered to them instead of to its holder.
/// They still cannot certify anything. They can make renewals silently
/// stop working, which is the one thing the mailbox *is* trusted with
/// (§9).
///
/// The claim signs the session it is for, not a timestamp. A session key
/// is the SHA-256 of a secret that only the mailbox and the holder that
/// opened it ever see, so a captured claim is worth nothing against any
/// other session: there is no window to replay inside, and no clock for
/// the two ends to disagree about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaim {
    /// The identity public key being claimed. The key that signs this,
    /// and the key whose fingerprint the mailbox will index by.
    pub identity: PublicKey,
    /// SHA-256 of the session secret — the mailbox's own key for the
    /// session, which the holder computes from the secret it was given.
    pub session: [u8; 32],
}

impl SessionClaim {
    pub fn new(identity: PublicKey, session: [u8; 32]) -> SessionClaim {
        SessionClaim { identity, session }
    }

    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("session", Some(Value::Bytes(self.session.to_vec()))),
        ])
    }

    /// Sign with the identity key, which must be the one named in
    /// `identity`.
    ///
    /// `assert!` for the reason [`EnrollRequest::sign`] uses one: a
    /// release build that skipped it would produce a claim that cannot
    /// verify, and the mailbox would refuse it a long way from here.
    pub fn sign(&self, identity: &IdentityKey) -> Vec<u8> {
        assert_eq!(
            identity.public(),
            self.identity,
            "signing a session claim with a key that is not the one it names"
        );
        signed::seal(self.unsigned(), |body| identity.sign(CLAIM_DOMAIN, body))
    }

    /// Decode and verify against the `identity` key the claim names, and
    /// check that it is for `session`.
    ///
    /// The session is a parameter rather than something the caller
    /// compares afterwards, because forgetting that comparison is the
    /// whole vulnerability: a claim that verifies but names a different
    /// session proves possession of a key and nothing about *this*
    /// session.
    pub fn parse(bytes: &[u8], session: &[u8; 32]) -> Result<SessionClaim, Error> {
        if bytes.len() > MAX_CLAIM_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let claim = SessionClaim {
            identity: signed::bytes32(&env.value, "identity")?,
            session: signed::bytes32(&env.value, "session")?,
        };
        if &claim.session != session {
            return Err(Error::BadField("session"));
        }
        env.verify(&claim.identity, CLAIM_DOMAIN)?;
        Ok(claim)
    }

    pub fn fingerprint(&self) -> crate::Fingerprint {
        crate::Fingerprint::of(&self.identity)
    }
}

/// A claim is three fixed-width fields and a signature; nothing in it
/// varies. Generous enough for the CBOR around them and no more.
pub const MAX_CLAIM_BYTES: usize = 256;

/// The mailbox's key for a session, from the secret it handed out:
/// `SHA-256(secret)`.
///
/// Here rather than at either end, because both ends have to agree on it
/// exactly — the holder signs this value and the mailbox compares
/// against the key it already stores the session under. It is the same
/// hashed-token discipline every other secret in the listener uses; this
/// only gives it a name the holder can call.
pub fn session_key(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceCert;

    fn device() -> DeviceKey {
        DeviceKey::from_seed(&[2u8; 32])
    }

    #[test]
    fn a_request_round_trips() {
        let d = device();
        let mut r = EnrollRequest::new(&d, 1_757_116_800);
        r.name = Some("Firefox on the laptop".into());
        r.caps = Some(cert::caps::WEB);
        r.days = Some(90);
        let signed = r.sign(&d);
        assert_eq!(EnrollRequest::parse(&signed).unwrap(), r);
    }

    #[test]
    fn a_request_may_only_be_signed_by_the_device_it_names() {
        // Asking for a certificate on somebody else's key: the request
        // names the victim's `device`, and is signed by the attacker's,
        // because signing it with the victim's would need the victim's
        // key — which is the whole point. `sign` refuses to build this,
        // so the test seals it by hand, the way an attacker would.
        let victim = device();
        let attacker = DeviceKey::from_seed(&[9u8; 32]);
        let r = EnrollRequest::new(&victim, 1_757_116_800);
        let forged = signed::seal(r.unsigned(), |body| attacker.sign(DOMAIN, body));
        assert_eq!(EnrollRequest::parse(&forged), Err(Error::BadSignature));

        // The honest version of the same object verifies, so the failure
        // above is the signer and not the shape.
        assert!(EnrollRequest::parse(&r.sign(&victim)).is_ok());
    }

    #[test]
    fn prev_must_name_the_device_that_is_asking() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let d = device();
        let stranger = DeviceKey::from_seed(&[3u8; 32]);

        let mine = DeviceCert::for_device(&id, &d, 1_000, 86_400)
            .unwrap()
            .sign(&id);
        let theirs = DeviceCert::for_device(&id, &stranger, 1_000, 86_400)
            .unwrap()
            .sign(&id);

        let mut r = EnrollRequest::new(&d, 1_100);
        r.prev = Some(mine);
        let back = EnrollRequest::parse(&r.sign(&d)).unwrap();
        assert_eq!(back.prev_cert().unwrap().unwrap().device, d.public());

        // Renewing somebody else's certificate is the interesting
        // failure: the request is validly signed, and the certificate is
        // real, and they are about different devices.
        r.prev = Some(theirs);
        let back = EnrollRequest::parse(&r.sign(&d)).unwrap();
        assert_eq!(back.prev_cert().unwrap(), Err(Error::KeyMismatch));

        // And no `prev` at all is a first enrollment, not an error.
        r.prev = None;
        let back = EnrollRequest::parse(&r.sign(&d)).unwrap();
        assert!(back.prev_cert().is_none());
    }

    #[test]
    fn prev_is_bounded_below_the_request_size_limit() {
        let d = device();
        let mut r = EnrollRequest::new(&d, 1_000);
        r.prev = Some(vec![0u8; cert::MAX_BYTES + 1]);
        assert_eq!(
            EnrollRequest::parse(&r.sign(&d)),
            Err(Error::BadField("prev"))
        );
    }

    #[test]
    fn a_pair_tag_binds_one_device_to_one_secret() {
        let secret = [7u8; PAIRING_SECRET_BYTES];
        let other_secret = [8u8; PAIRING_SECRET_BYTES];
        let d = device();

        let mut r = EnrollRequest::new(&d, 1_000);
        r.pair = Some(pair_tag(&secret, &d.public()));
        let back = EnrollRequest::parse(&r.sign(&d)).unwrap();
        assert!(back.pair_matches(&secret));

        // A holder that drew a different secret refuses it, which is the
        // point: the mailbox never saw either.
        assert!(!back.pair_matches(&other_secret));

        // A tag for a different device does not travel: this is the
        // mailbox splicing a real tag onto its own key.
        let mut spliced = EnrollRequest::new(&DeviceKey::from_seed(&[4u8; 32]), 1_000);
        spliced.pair = Some(pair_tag(&secret, &d.public()));
        assert!(!spliced.pair_matches(&secret));

        // No tag is not a match; it is an unscanned request, which the
        // caller distinguishes by looking at `pair`.
        r.pair = None;
        let back = EnrollRequest::parse(&r.sign(&d)).unwrap();
        assert!(!back.pair_matches(&secret));
        assert!(back.pair.is_none());
    }

    #[test]
    fn a_claim_round_trips_for_the_session_it_names() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let session = session_key("a-session-secret");
        let claim = SessionClaim::new(id.public(), session);
        let signed = claim.sign(&id);
        assert_eq!(SessionClaim::parse(&signed, &session).unwrap(), claim);
        assert_eq!(claim.fingerprint(), id.fingerprint());
    }

    #[test]
    fn a_claim_is_worth_nothing_against_another_session() {
        // The whole reason the claim signs a session rather than a
        // timestamp: a mailbox that captured this one — or anyone who
        // did — cannot present it for a session of their own.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let mine = session_key("mine");
        let theirs = session_key("theirs");
        let signed = SessionClaim::new(id.public(), mine).sign(&id);
        assert_eq!(
            SessionClaim::parse(&signed, &theirs),
            Err(Error::BadField("session"))
        );
    }

    #[test]
    fn a_claim_may_only_be_signed_by_the_identity_it_names() {
        // A fingerprint is public, so this is the check that stops a
        // stranger standing by for somebody else's renewals.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let attacker = IdentityKey::from_seed(&[9u8; 32]);
        let session = session_key("s");
        let honest = SessionClaim::new(id.public(), session);
        let forged = signed::seal(honest.unsigned(), |body| attacker.sign(CLAIM_DOMAIN, body));
        assert_eq!(
            SessionClaim::parse(&forged, &session),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn a_claim_is_not_a_request_and_a_request_is_not_a_claim() {
        // Distinct domains, so neither object's signature can be
        // replayed as the other's.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let session = session_key("s");
        let claim = SessionClaim::new(id.public(), session);
        let wrong_domain = signed::seal(claim.unsigned(), |body| id.sign(DOMAIN, body));
        assert_eq!(
            SessionClaim::parse(&wrong_domain, &session),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn a_name_a_certificate_could_not_carry_is_refused_here() {
        let d = device();
        let mut r = EnrollRequest::new(&d, 1_000);
        for bad in ["  padded  ", "   ", &"x".repeat(cert::NAME_MAX_CHARS + 1)] {
            r.name = Some(bad.to_owned());
            assert_eq!(
                EnrollRequest::parse(&r.sign(&d)),
                Err(Error::BadField("name")),
                "accepted {bad:?}"
            );
        }
    }
}
