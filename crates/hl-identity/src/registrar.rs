//! The registrar's objects (`docs/identity-registrar.md` §4 and §6.6).
//!
//! Three kinds of thing, by who signs them:
//!
//! - **user-signed**: the registration request (§4.2), and the three
//!   records a user posts — device revocation (§4.4), identity
//!   revocation (§4.5) and rotation (§4.6). Each verifies from its own
//!   bytes, with no outside state: the key that signs is in the object,
//!   and a device that signs brings its certificate along.
//! - **registrar-signed records**: freeze (§4.7) and attestation
//!   revocation (§4.8). These verify only against the registrar's
//!   published key, which the caller fetched.
//! - **registrar-signed lists**: the record list (§4.9), the issuance log
//!   (§6.6) and the stats (§6.6), which say "the registrar published
//!   this" and nothing about who made what they carry.
//!
//! [`Record::parse`] is the one verifier of §12: the registrar runs it on
//! a posted record, a server runs it on every list entry, and `hlid`
//! runs it on what it is about to post. A record one of them would accept
//! is therefore one every one of them would.

use crate::attestation::is_host;
use crate::cbor::{self, map, Value};
use crate::cert::{caps, DeviceCert};
use crate::error::Error;
use crate::keys::{DeviceKey, IdentityKey, PublicKey, ServerKey};
use crate::signed::{self, AckedEnvelope, Envelope, VERSION};

pub const REGISTER_DOMAIN: &str = "hl-identity/register/v1";
pub const REVOKE_DEVICE_DOMAIN: &str = "hl-identity/revoke-device/v1";
pub const REVOKE_IDENTITY_DOMAIN: &str = "hl-identity/revoke-identity/v1";
pub const ROTATE_DOMAIN: &str = "hl-identity/rotate/v1";
pub const FREEZE_DOMAIN: &str = "hl-identity/freeze/v1";
pub const REVOKE_ATTESTATION_DOMAIN: &str = "hl-identity/revoke-attestation/v1";
pub const RECORDS_DOMAIN: &str = "hl-identity/records/v1";
pub const LOG_DOMAIN: &str = "hl-identity/log/v1";
pub const STATS_DOMAIN: &str = "hl-identity/stats/v1";

/// Encoded size bounds (§4.2–§4.8, §6.6). A device revocation carries a
/// whole certificate, which is what makes it the large one.
pub const REGISTER_MAX_BYTES: usize = 2 * 1024;
pub const REVOKE_DEVICE_MAX_BYTES: usize = 6 * 1024;
pub const SMALL_RECORD_MAX_BYTES: usize = 512;
pub const STATS_MAX_BYTES: usize = 1024;
/// A page of a record list or of the log (§4.9).
pub const LIST_MAX_BYTES: usize = 1024 * 1024;
/// A registration's opaque signup material (§4.2).
pub const PROOF_MAX_BYTES: usize = 1024;

/// The handles this registrar profile issues (§5.1): lowercase ASCII
/// letters, digits, `.`, `_` and `-`; a letter or digit at each end; no
/// two punctuation characters in a row; `min` to `max` characters.
///
/// This is a check of form, not a canonicalization: a request whose
/// handle is not already in this form is refused rather than folded, so
/// what the user signed is what is issued.
pub fn handle_is_canonical(handle: &str, min: usize, max: usize) -> bool {
    let b = handle.as_bytes();
    if b.len() < min || b.len() > max || b.is_empty() {
        return false;
    }
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let punct = |c: u8| matches!(c, b'.' | b'_' | b'-');
    if !alnum(b[0]) || !alnum(b[b.len() - 1]) {
        return false;
    }
    if !b.iter().all(|&c| alnum(c) || punct(c)) {
        return false;
    }
    !b.windows(2).any(|w| punct(w[0]) && punct(w[1]))
}

fn bytes_field(v: Option<PublicKey>) -> Option<Value> {
    v.map(|k| Value::Bytes(k.to_vec()))
}

fn check_host(host: &str) -> Result<(), Error> {
    if is_host(host) {
        Ok(())
    } else {
        Err(Error::BadField("registrar"))
    }
}

fn check_size(bytes: &[u8], max: usize) -> Result<(), Error> {
    if bytes.len() > max {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}

fn reason(v: &Value, max: u64) -> Result<Option<u64>, Error> {
    let r = signed::opt_uint(v, "reason")?;
    if r.is_some_and(|r| r > max) {
        return Err(Error::BadField("reason"));
    }
    Ok(r)
}

// --- §4.2 Registration request -------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub identity: PublicKey,
    /// The registrar's `host`: a request captured for one registrar is
    /// useless at another.
    pub registrar: String,
    /// The requested local part, already in the registrar's form.
    pub handle: String,
    pub time: u64,
    /// `SHA-256` of a pre-committed successor key (§5.4).
    pub successor: Option<[u8; 32]>,
    /// Signup material when the registrar asks for it. Opaque here.
    pub proof: Option<String>,
}

impl RegisterRequest {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            ("handle", Some(Value::Text(self.handle.clone()))),
            ("time", Some(Value::Uint(self.time))),
            ("successor", bytes_field(self.successor)),
            ("proof", self.proof.clone().map(Value::Text)),
        ])
    }

    /// Sign with the identity key — never a device key: a name is an
    /// identity-level asset, and a stolen device must not be able to
    /// acquire or renew one.
    ///
    /// Parses back what it signs, so a request no registrar would read is
    /// an error here rather than a round trip.
    pub fn sign(&self, identity: &IdentityKey) -> Result<Vec<u8>, Error> {
        assert_eq!(
            identity.public(),
            self.identity,
            "signing a registration request with a key that is not its identity"
        );
        let bytes = signed::seal(self.unsigned(), |body| identity.sign(REGISTER_DOMAIN, body));
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    /// Decode, bound and verify against the embedded identity key. The
    /// handle's form, the host and the clock are the registrar's checks.
    pub fn parse(bytes: &[u8]) -> Result<RegisterRequest, Error> {
        check_size(bytes, REGISTER_MAX_BYTES)?;
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let r = RegisterRequest {
            identity: signed::bytes32(v, "identity")?,
            registrar: signed::text(v, "registrar")?,
            handle: signed::text(v, "handle")?,
            time: signed::uint(v, "time")?,
            successor: signed::opt_bytes32(v, "successor")?,
            proof: signed::opt_text(v, "proof")?,
        };
        check_host(&r.registrar)?;
        if r.handle.is_empty() || r.handle.len() > 64 {
            return Err(Error::BadField("handle"));
        }
        if r.proof.as_ref().is_some_and(|p| p.len() > PROOF_MAX_BYTES) {
            return Err(Error::BadField("proof"));
        }
        env.verify(&r.identity, REGISTER_DOMAIN)?;
        Ok(r)
    }
}

// --- §4.4 Device revocation ----------------------------------------------

/// Why a device was revoked. Display only.
pub mod device_reason {
    pub const UNSPECIFIED: u64 = 0;
    pub const LOST: u64 = 1;
    pub const STOLEN: u64 = 2;
    pub const RETIRED: u64 = 3;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocation {
    pub identity: PublicKey,
    pub device: PublicKey,
    pub time: u64,
    /// The `expires` of the latest certificate the signer knows for the
    /// device. Publication in the full list stops after it; the
    /// revocation itself is permanent.
    pub until: u64,
    pub reason: Option<u64>,
    /// Set when a device, not the identity, signed: that device's key.
    pub signer: Option<PublicKey>,
    /// That device's certificate, so the record verifies alone.
    pub signer_cert: Option<Vec<u8>>,
}

impl DeviceRevocation {
    /// `until` for a signer that does not know the device's certificate:
    /// two years from `time`.
    pub fn default_until(time: u64) -> u64 {
        time.saturating_add(2 * 365 * 24 * 3600)
    }

    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("device", Some(Value::Bytes(self.device.to_vec()))),
            ("time", Some(Value::Uint(self.time))),
            ("until", Some(Value::Uint(self.until))),
            ("reason", self.reason.map(Value::Uint)),
            ("signer", bytes_field(self.signer)),
            ("signer_cert", self.signer_cert.clone().map(Value::Bytes)),
        ])
    }

    /// Sign with the identity key. `signer` and `signer_cert` must be
    /// unset.
    pub fn sign(&self, identity: &IdentityKey) -> Result<Vec<u8>, Error> {
        assert_eq!(identity.public(), self.identity);
        assert!(self.signer.is_none() && self.signer_cert.is_none());
        let bytes = signed::seal(self.unsigned(), |body| {
            identity.sign(REVOKE_DEVICE_DOMAIN, body)
        });
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    /// Sign with a device key whose certificate carries `manage`. Fills
    /// `signer` and `signer_cert` from what it is given.
    pub fn sign_as_device(&self, device: &DeviceKey, cert: Vec<u8>) -> Result<Vec<u8>, Error> {
        let r = DeviceRevocation {
            signer: Some(device.public()),
            signer_cert: Some(cert),
            ..self.clone()
        };
        let bytes = signed::seal(r.unsigned(), |body| device.sign(REVOKE_DEVICE_DOMAIN, body));
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<DeviceRevocation, Error> {
        check_size(bytes, REVOKE_DEVICE_MAX_BYTES)?;
        Self::from_envelope(Envelope::open(bytes)?)
    }

    /// The cheap fields first, then `signer_cert`, then `sig` — the order
    /// the identity spec's §13 uses for cards, so a record that fails on
    /// a field costs no signature.
    fn from_envelope(env: Envelope) -> Result<DeviceRevocation, Error> {
        let v = &env.value;
        let r = DeviceRevocation {
            identity: signed::bytes32(v, "identity")?,
            device: signed::bytes32(v, "device")?,
            time: signed::uint(v, "time")?,
            until: signed::uint(v, "until")?,
            reason: reason(v, device_reason::RETIRED)?,
            signer: signed::opt_bytes32(v, "signer")?,
            signer_cert: signed::opt_bytes(v, "signer_cert")?,
        };
        if r.until < r.time {
            return Err(Error::BadField("until"));
        }
        match (&r.signer, &r.signer_cert) {
            (None, None) => env.verify(&r.identity, REVOKE_DEVICE_DOMAIN)?,
            (Some(signer), Some(cert)) => {
                let cert = DeviceCert::parse(cert)?;
                if cert.identity != r.identity || &cert.device != signer {
                    return Err(Error::KeyMismatch);
                }
                cert.require(caps::MANAGE)?;
                // The certificate had to be good *when the revocation
                // was signed*, not now: a revocation outlives the
                // certificate of whoever signed it, and must.
                if r.time < cert.issued || r.time > cert.expires {
                    return Err(Error::Expired);
                }
                env.verify(signer, REVOKE_DEVICE_DOMAIN)?;
            }
            (Some(_), None) => return Err(Error::MissingField("signer_cert")),
            (None, Some(_)) => return Err(Error::MissingField("signer")),
        }
        Ok(r)
    }
}

// --- §4.5 Identity revocation --------------------------------------------

pub mod identity_reason {
    pub const UNSPECIFIED: u64 = 0;
    pub const RETIRED: u64 = 1;
    pub const COMPROMISED: u64 = 2;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRevocation {
    pub identity: PublicKey,
    pub time: u64,
    pub reason: Option<u64>,
}

impl IdentityRevocation {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("time", Some(Value::Uint(self.time))),
            ("reason", self.reason.map(Value::Uint)),
        ])
    }

    pub fn sign(&self, identity: &IdentityKey) -> Result<Vec<u8>, Error> {
        assert_eq!(identity.public(), self.identity);
        let bytes = signed::seal(self.unsigned(), |body| {
            identity.sign(REVOKE_IDENTITY_DOMAIN, body)
        });
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<IdentityRevocation, Error> {
        check_size(bytes, SMALL_RECORD_MAX_BYTES)?;
        Self::from_envelope(Envelope::open(bytes)?)
    }

    fn from_envelope(env: Envelope) -> Result<IdentityRevocation, Error> {
        let v = &env.value;
        let r = IdentityRevocation {
            identity: signed::bytes32(v, "identity")?,
            time: signed::uint(v, "time")?,
            reason: reason(v, identity_reason::COMPROMISED)?,
        };
        env.verify(&r.identity, REVOKE_IDENTITY_DOMAIN)?;
        Ok(r)
    }
}

// --- §4.6 Rotation -------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// The predecessor.
    pub identity: PublicKey,
    pub successor: PublicKey,
    pub time: u64,
}

impl Rotation {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("successor", Some(Value::Bytes(self.successor.to_vec()))),
            ("time", Some(Value::Uint(self.time))),
        ])
    }

    /// Signed by the predecessor and acknowledged by the successor. Both
    /// are required: the predecessor's says "I hand over", the
    /// successor's "I accept", and without the second a stolen key could
    /// rotate an identity onto a bystander's key to strand it.
    pub fn sign(
        &self,
        predecessor: &IdentityKey,
        successor: &IdentityKey,
    ) -> Result<Vec<u8>, Error> {
        assert_eq!(predecessor.public(), self.identity);
        assert_eq!(successor.public(), self.successor);
        let ack_domain = signed::ack_domain(ROTATE_DOMAIN);
        let bytes = signed::seal_acked(
            self.unsigned(),
            |body| predecessor.sign(ROTATE_DOMAIN, body),
            |body| successor.sign(&ack_domain, body),
        );
        Self::parse(&bytes)?;
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Rotation, Error> {
        check_size(bytes, SMALL_RECORD_MAX_BYTES)?;
        Self::from_value(cbor::decode_canonical(bytes)?)
    }

    fn from_value(value: Value) -> Result<Rotation, Error> {
        let env = AckedEnvelope::from_value(value)?;
        let v = &env.value;
        let r = Rotation {
            identity: signed::bytes32(v, "identity")?,
            successor: signed::bytes32(v, "successor")?,
            time: signed::uint(v, "time")?,
        };
        if r.identity == r.successor {
            return Err(Error::BadField("successor"));
        }
        env.verify(&r.identity, &r.successor, ROTATE_DOMAIN)?;
        Ok(r)
    }

    /// What a card or a registration commits to when it names this
    /// rotation's successor.
    pub fn commitment(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.successor).into()
    }
}

// --- §4.7 Freeze ---------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Freeze {
    pub identity: PublicKey,
    pub registrar: String,
    /// `true` freezes; `false` lifts. The latest `time` wins.
    pub frozen: bool,
    pub time: u64,
}

impl Freeze {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            ("frozen", Some(Value::Bool(self.frozen))),
            ("time", Some(Value::Uint(self.time))),
        ])
    }

    pub fn sign(&self, registrar: &ServerKey) -> Vec<u8> {
        signed::seal(self.unsigned(), |body| registrar.sign(FREEZE_DOMAIN, body))
    }

    fn from_envelope(env: Envelope, keys: &[PublicKey]) -> Result<Freeze, Error> {
        let v = &env.value;
        let r = Freeze {
            identity: signed::bytes32(v, "identity")?,
            registrar: signed::text(v, "registrar")?,
            frozen: signed::boolean(v, "frozen")?,
            time: signed::uint(v, "time")?,
        };
        check_host(&r.registrar)?;
        verify_any(&env, keys, FREEZE_DOMAIN)?;
        Ok(r)
    }
}

// --- §4.8 Attestation revocation -----------------------------------------

pub mod attestation_reason {
    pub const UNSPECIFIED: u64 = 0;
    pub const RECOVERED: u64 = 1;
    pub const ROTATED: u64 = 2;
    pub const LAPSED: u64 = 3;
    pub const ABUSE: u64 = 4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRevocation {
    pub identity: PublicKey,
    pub registrar: String,
    pub handle: String,
    /// Every attestation for this (identity, registrar, handle) with
    /// `issued ≤ time` is void.
    pub time: u64,
    pub reason: Option<u64>,
}

impl AttestationRevocation {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            ("handle", Some(Value::Text(self.handle.clone()))),
            ("time", Some(Value::Uint(self.time))),
            ("reason", self.reason.map(Value::Uint)),
        ])
    }

    pub fn sign(&self, registrar: &ServerKey) -> Vec<u8> {
        signed::seal(self.unsigned(), |body| {
            registrar.sign(REVOKE_ATTESTATION_DOMAIN, body)
        })
    }

    /// Whether this voids `a`.
    pub fn voids(&self, a: &crate::Attestation) -> bool {
        a.identity == self.identity
            && a.registrar == self.registrar
            && a.handle == self.handle
            && a.issued <= self.time
    }

    fn from_envelope(env: Envelope, keys: &[PublicKey]) -> Result<AttestationRevocation, Error> {
        let v = &env.value;
        let r = AttestationRevocation {
            identity: signed::bytes32(v, "identity")?,
            registrar: signed::text(v, "registrar")?,
            handle: signed::text(v, "handle")?,
            time: signed::uint(v, "time")?,
            reason: reason(v, attestation_reason::ABUSE)?,
        };
        check_host(&r.registrar)?;
        if r.handle.is_empty() || r.handle.len() > 64 {
            return Err(Error::BadField("handle"));
        }
        verify_any(&env, keys, REVOKE_ATTESTATION_DOMAIN)?;
        Ok(r)
    }
}

/// A registrar may publish under a current key and any retiring ones
/// (§4.1); a signature by any of them is the registrar's.
fn verify_any(env: &Envelope, keys: &[PublicKey], domain: &str) -> Result<(), Error> {
    if keys.is_empty() {
        return Err(Error::KeyMismatch);
    }
    let mut last = Error::BadSignature;
    for k in keys {
        match env.verify(k, domain) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

// --- The records, as one type --------------------------------------------

/// Any of the five records a record list carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    RevokeDevice(DeviceRevocation),
    RevokeIdentity(IdentityRevocation),
    Rotate(Rotation),
    Freeze(Freeze),
    RevokeAttestation(AttestationRevocation),
}

/// Who a registrar-signed record must come from: the host it names and
/// the keys it may be signed by.
#[derive(Debug, Clone, Copy)]
pub struct RegistrarKeys<'a> {
    pub host: &'a str,
    pub keys: &'a [PublicKey],
}

impl Record {
    /// Parse and verify any record. The objects carry no type tag, so the
    /// kind is read from the keys each one alone has — `ack` or
    /// `successor` a rotation, `device` a device revocation, `frozen` a
    /// freeze, `handle` an attestation revocation, and none of them an
    /// identity revocation — and the signature is then checked under
    /// that kind's domain. A misreading can only fail: domains are what
    /// keep one kind's signature from verifying as another's.
    ///
    /// `registrar` is needed for the two registrar-signed kinds and
    /// refused-by-absence without it (`KeyMismatch`); a registrar-signed
    /// record that names a different host is `BadField("registrar")`.
    pub fn parse(bytes: &[u8], registrar: Option<RegistrarKeys<'_>>) -> Result<Record, Error> {
        check_size(bytes, REVOKE_DEVICE_MAX_BYTES)?;
        let value = cbor::decode_canonical(bytes)?;
        let has = |k| value.get(k).is_some();
        let small = || check_size(bytes, SMALL_RECORD_MAX_BYTES);
        if has("ack") || has("successor") {
            small()?;
            return Rotation::from_value(value).map(Record::Rotate);
        }
        if has("device") {
            return DeviceRevocation::from_envelope(Envelope::from_value(value)?)
                .map(Record::RevokeDevice);
        }
        small()?;
        if has("frozen") || has("handle") {
            let reg = registrar.ok_or(Error::KeyMismatch)?;
            let env = Envelope::from_value(value)?;
            let r = if env.value.get("frozen").is_some() {
                Record::Freeze(Freeze::from_envelope(env, reg.keys)?)
            } else {
                Record::RevokeAttestation(AttestationRevocation::from_envelope(env, reg.keys)?)
            };
            if r.registrar() != Some(reg.host) {
                return Err(Error::BadField("registrar"));
            }
            return Ok(r);
        }
        IdentityRevocation::from_envelope(Envelope::from_value(value)?).map(Record::RevokeIdentity)
    }

    /// The identity the record is about (the predecessor, for a
    /// rotation).
    pub fn identity(&self) -> &PublicKey {
        match self {
            Record::RevokeDevice(r) => &r.identity,
            Record::RevokeIdentity(r) => &r.identity,
            Record::Rotate(r) => &r.identity,
            Record::Freeze(r) => &r.identity,
            Record::RevokeAttestation(r) => &r.identity,
        }
    }

    pub fn time(&self) -> u64 {
        match self {
            Record::RevokeDevice(r) => r.time,
            Record::RevokeIdentity(r) => r.time,
            Record::Rotate(r) => r.time,
            Record::Freeze(r) => r.time,
            Record::RevokeAttestation(r) => r.time,
        }
    }

    /// The host a registrar-signed record names; `None` for the three a
    /// user signs.
    pub fn registrar(&self) -> Option<&str> {
        match self {
            Record::Freeze(r) => Some(&r.registrar),
            Record::RevokeAttestation(r) => Some(&r.registrar),
            _ => None,
        }
    }

    /// Whether a user may post this (§6.2): the registrar-signed kinds
    /// come from the registrar's own tools and nowhere else.
    pub fn user_signed(&self) -> bool {
        self.registrar().is_none()
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Record::RevokeDevice(_) => "revoke_device",
            Record::RevokeIdentity(_) => "revoke_identity",
            Record::Rotate(_) => "rotate",
            Record::Freeze(_) => "freeze",
            Record::RevokeAttestation(_) => "revoke_attestation",
        }
    }
}

// --- §4.9 Record list, §6.6 issuance log ---------------------------------

/// Which of the two lists: they are one shape under two domains, and a
/// log page must never verify as a record list or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Records,
    Log,
}

impl ListKind {
    fn domain(self) -> &'static str {
        match self {
            ListKind::Records => RECORDS_DOMAIN,
            ListKind::Log => LOG_DOMAIN,
        }
    }
}

/// A signed page of `[seq, bytes]` entries: records (§4.9) or issued
/// attestations (§6.6). The page's signature says the registrar
/// published these; each entry's own signature says who made it, and the
/// reader verifies every one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedList {
    pub registrar: String,
    pub issued: u64,
    pub expires: u64,
    /// A per-identity record list: the fingerprint it was asked for, and
    /// every entry concerns that key. A fingerprint rather than the key,
    /// because a list for a key the registrar has never seen can name it
    /// no other way — and that list, empty and signed, is the one that
    /// says "nothing held against this key".
    pub fingerprint: Option<[u8; 32]>,
    /// A delta: every entry has `seq > since`.
    pub since: Option<u64>,
    /// The page was cut at the size bound; fetch again from the last seq.
    pub more: bool,
    pub entries: Vec<(u64, Vec<u8>)>,
}

impl SignedList {
    /// What one entry adds to a page's encoding, beyond its bytes, at
    /// most: the two-item array head, a `seq` up to nine bytes, and a
    /// byte-string head up to nine. A registrar packs a page against
    /// [`LIST_MAX_BYTES`] with this.
    pub const ENTRY_OVERHEAD: usize = 1 + 9 + 9;
    /// Everything on a page but its entries, at most.
    pub const PAGE_OVERHEAD: usize = 512;

    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            ("issued", Some(Value::Uint(self.issued))),
            ("expires", Some(Value::Uint(self.expires))),
            (
                "fingerprint",
                self.fingerprint.map(|f| Value::Bytes(f.to_vec())),
            ),
            ("since", self.since.map(Value::Uint)),
            ("more", self.more.then_some(Value::Bool(true))),
            (
                "entries",
                Some(Value::Array(
                    self.entries
                        .iter()
                        .map(|(seq, b)| {
                            Value::Array(vec![Value::Uint(*seq), Value::Bytes(b.clone())])
                        })
                        .collect(),
                )),
            ),
        ])
    }

    pub fn sign(&self, kind: ListKind, registrar: &ServerKey) -> Vec<u8> {
        assert!(
            kind == ListKind::Records || self.fingerprint.is_none(),
            "the issuance log has no per-identity form"
        );
        signed::seal(self.unsigned(), |body| registrar.sign(kind.domain(), body))
    }

    /// Verify the page against the registrar's keys and check its shape:
    /// the host, the window, and `seq` strictly increasing and past
    /// `since`. The entries' own signatures are the caller's next step.
    pub fn parse(
        bytes: &[u8],
        kind: ListKind,
        registrar: RegistrarKeys<'_>,
    ) -> Result<SignedList, Error> {
        check_size(bytes, LIST_MAX_BYTES)?;
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let items = match v.get("entries") {
            Some(Value::Array(items)) => items,
            Some(_) => return Err(Error::BadField("entries")),
            None => return Err(Error::MissingField("entries")),
        };
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            match item {
                Value::Array(pair) => match pair.as_slice() {
                    [Value::Uint(seq), Value::Bytes(b)] => entries.push((*seq, b.clone())),
                    _ => return Err(Error::BadField("entries")),
                },
                _ => return Err(Error::BadField("entries")),
            }
        }
        let list = SignedList {
            registrar: signed::text(v, "registrar")?,
            issued: signed::uint(v, "issued")?,
            expires: signed::uint(v, "expires")?,
            fingerprint: signed::opt_bytes32(v, "fingerprint")?,
            since: signed::opt_uint(v, "since")?,
            more: signed::opt_bool(v, "more")?.unwrap_or(false),
            entries,
        };
        if list.registrar != registrar.host {
            return Err(Error::BadField("registrar"));
        }
        if list.expires < list.issued {
            return Err(Error::BadField("expires"));
        }
        if kind == ListKind::Log && list.fingerprint.is_some() {
            return Err(Error::BadField("fingerprint"));
        }
        let floor = list.since.unwrap_or(0);
        let mut prev: Option<u64> = None;
        for (seq, _) in &list.entries {
            if (list.since.is_some() && *seq <= floor) || prev.is_some_and(|p| *seq <= p) {
                return Err(Error::BadField("entries"));
            }
            prev = Some(*seq);
        }
        verify_any(&env, registrar.keys, kind.domain())?;
        Ok(list)
    }
}

// --- §6.6 Stats ----------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub registrar: String,
    pub at: u64,
    /// Identities with at least one held handle.
    pub identities: u64,
    /// First registrations only.
    pub issued_24h: u64,
    pub issued_7d: u64,
    pub issued_total: u64,
    /// Attestation revocations the registrar has signed.
    pub revoked_total: u64,
    /// Identities currently frozen.
    pub frozen: u64,
    /// The last `seq` in the issuance log.
    pub log_seq: u64,
}

impl Stats {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("registrar", Some(Value::Text(self.registrar.clone()))),
            ("at", Some(Value::Uint(self.at))),
            ("identities", Some(Value::Uint(self.identities))),
            ("issued_24h", Some(Value::Uint(self.issued_24h))),
            ("issued_7d", Some(Value::Uint(self.issued_7d))),
            ("issued_total", Some(Value::Uint(self.issued_total))),
            ("revoked_total", Some(Value::Uint(self.revoked_total))),
            ("frozen", Some(Value::Uint(self.frozen))),
            ("log_seq", Some(Value::Uint(self.log_seq))),
        ])
    }

    pub fn sign(&self, registrar: &ServerKey) -> Vec<u8> {
        signed::seal(self.unsigned(), |body| registrar.sign(STATS_DOMAIN, body))
    }

    pub fn parse(bytes: &[u8], registrar: RegistrarKeys<'_>) -> Result<Stats, Error> {
        check_size(bytes, STATS_MAX_BYTES)?;
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let s = Stats {
            registrar: signed::text(v, "registrar")?,
            at: signed::uint(v, "at")?,
            identities: signed::uint(v, "identities")?,
            issued_24h: signed::uint(v, "issued_24h")?,
            issued_7d: signed::uint(v, "issued_7d")?,
            issued_total: signed::uint(v, "issued_total")?,
            revoked_total: signed::uint(v, "revoked_total")?,
            frozen: signed::uint(v, "frozen")?,
            log_seq: signed::uint(v, "log_seq")?,
        };
        if s.registrar != registrar.host {
            return Err(Error::BadField("registrar"));
        }
        verify_any(&env, registrar.keys, STATS_DOMAIN)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::DeviceCert;
    use crate::keys::verify_domain;

    const T: u64 = 1_750_000_000;

    fn id(n: u8) -> IdentityKey {
        IdentityKey::from_seed(&[n; 32])
    }

    fn reg() -> ServerKey {
        ServerKey::from_seed(&[3u8; 32])
    }

    fn keys(k: &[PublicKey]) -> RegistrarKeys<'_> {
        RegistrarKeys {
            host: "hl.example",
            keys: k,
        }
    }

    #[test]
    fn handle_profile() {
        for ok in ["alice", "a.b", "a_b-c", "abc", "a1", "0day", "x.y.z"] {
            assert!(handle_is_canonical(ok, 2, 32), "{ok}");
        }
        for bad in [
            "Alice",
            "al",
            ".abc",
            "abc.",
            "a..b",
            "a._b",
            "a b",
            "al@x",
            "ålice",
            "a\u{200b}b",
            "",
        ] {
            assert!(!handle_is_canonical(bad, 3, 32), "{bad:?}");
        }
        assert!(!handle_is_canonical(&"a".repeat(33), 3, 32));
        assert!(handle_is_canonical(&"a".repeat(32), 3, 32));
    }

    #[test]
    fn register_request_round_trip_and_binding() {
        let alice = id(1);
        let r = RegisterRequest {
            identity: alice.public(),
            registrar: "hl.example".into(),
            handle: "alice".into(),
            time: T,
            successor: Some([9u8; 32]),
            proof: Some("INVITE-1".into()),
        };
        let bytes = r.sign(&alice).unwrap();
        assert_eq!(RegisterRequest::parse(&bytes).unwrap(), r);
        // The signature covers the registrar: re-pointing a captured
        // request at another host breaks it.
        let mut v = cbor::decode_canonical(&bytes).unwrap();
        if let Value::Map(entries) = &mut v {
            for (k, val) in entries.iter_mut() {
                if k == &Value::Text("registrar".into()) {
                    *val = Value::Text("evil.example".into());
                }
            }
        }
        assert_eq!(
            RegisterRequest::parse(&cbor::encode(&v)),
            Err(Error::BadSignature)
        );
        let long = RegisterRequest {
            proof: Some("x".repeat(PROOF_MAX_BYTES + 1)),
            ..r
        };
        assert!(long.sign(&alice).is_err());
    }

    #[test]
    fn device_revocation_by_identity_and_by_a_manage_device() {
        let alice = id(1);
        let phone = DeviceKey::from_seed(&[2u8; 32]);
        let laptop = DeviceKey::from_seed(&[4u8; 32]);
        let r = DeviceRevocation {
            identity: alice.public(),
            device: phone.public(),
            time: T,
            until: DeviceRevocation::default_until(T),
            reason: Some(device_reason::STOLEN),
            signer: None,
            signer_cert: None,
        };
        let by_id = r.sign(&alice).unwrap();
        assert_eq!(
            Record::parse(&by_id, None).unwrap(),
            Record::RevokeDevice(r.clone())
        );

        let cert = DeviceCert::for_device(&alice, &laptop, T - 100, 86400)
            .unwrap()
            .sign(&alice);
        let by_dev = r.sign_as_device(&laptop, cert).unwrap();
        let back = DeviceRevocation::parse(&by_dev).unwrap();
        assert_eq!(back.signer, Some(laptop.public()));

        // A web certificate has no `manage`, so a page cannot revoke the
        // user's other devices.
        let mut web = DeviceCert::for_device(&alice, &laptop, T - 100, 86400).unwrap();
        web.caps = Some(caps::WEB);
        assert_eq!(
            r.sign_as_device(&laptop, web.sign(&alice)).unwrap_err(),
            Error::CapabilityMissing
        );
        // A certificate from another identity vouches for nothing here.
        let mallory = id(7);
        let foreign = DeviceCert::for_device(&mallory, &laptop, T - 100, 86400)
            .unwrap()
            .sign(&mallory);
        assert_eq!(
            r.sign_as_device(&laptop, foreign).unwrap_err(),
            Error::KeyMismatch
        );
        // Nor does one that was not valid when the record was signed.
        let stale = DeviceCert::for_device(&alice, &laptop, T - 1000, 100)
            .unwrap()
            .sign(&alice);
        assert_eq!(
            r.sign_as_device(&laptop, stale).unwrap_err(),
            Error::Expired
        );
    }

    #[test]
    fn rotation_needs_both_signatures() {
        let old = id(1);
        let new = id(2);
        let r = Rotation {
            identity: old.public(),
            successor: new.public(),
            time: T,
        };
        let bytes = r.sign(&old, &new).unwrap();
        assert_eq!(
            Record::parse(&bytes, None).unwrap(),
            Record::Rotate(r.clone())
        );

        // `ack` by anyone but the successor fails, and says so as a
        // signature failure rather than anything subtler.
        let mut v = cbor::decode_canonical(&bytes).unwrap();
        let body = cbor::encode(&v.without("sig").without("ack"));
        let wrong = id(9).sign(&signed::ack_domain(ROTATE_DOMAIN), &body);
        if let Value::Map(entries) = &mut v {
            for (k, val) in entries.iter_mut() {
                if k == &Value::Text("ack".into()) {
                    *val = Value::Bytes(wrong.to_vec());
                }
            }
        }
        assert_eq!(Rotation::parse(&cbor::encode(&v)), Err(Error::BadSignature));

        // The two signatures are over the same bytes under two domains.
        let v = cbor::decode_canonical(&bytes).unwrap();
        let body = cbor::encode(&v.without("sig").without("ack"));
        let Some(Value::Bytes(sig)) = v.get("sig") else {
            panic!()
        };
        let Some(Value::Bytes(ack)) = v.get("ack") else {
            panic!()
        };
        let sig: [u8; 64] = sig.as_slice().try_into().unwrap();
        let ack: [u8; 64] = ack.as_slice().try_into().unwrap();
        assert!(verify_domain(&old.public(), ROTATE_DOMAIN, &body, &sig).is_ok());
        assert!(verify_domain(&new.public(), "hl-identity/rotate/v1/ack", &body, &ack).is_ok());

        let selfish = Rotation {
            successor: old.public(),
            ..r
        };
        let bytes = signed::seal_acked(
            selfish.unsigned(),
            |b| old.sign(ROTATE_DOMAIN, b),
            |b| old.sign(&signed::ack_domain(ROTATE_DOMAIN), b),
        );
        assert_eq!(Rotation::parse(&bytes), Err(Error::BadField("successor")));
    }

    #[test]
    fn registrar_records_need_the_registrar() {
        let alice = id(1);
        let k = [reg().public()];
        let f = Freeze {
            identity: alice.public(),
            registrar: "hl.example".into(),
            frozen: true,
            time: T,
        };
        let bytes = f.sign(&reg());
        assert_eq!(
            Record::parse(&bytes, Some(keys(&k))).unwrap(),
            Record::Freeze(f.clone())
        );
        assert_eq!(Record::parse(&bytes, None), Err(Error::KeyMismatch));
        let other = [ServerKey::from_seed(&[8u8; 32]).public()];
        assert_eq!(
            Record::parse(&bytes, Some(keys(&other))),
            Err(Error::BadSignature)
        );
        // A retiring key still counts.
        let both = [other[0], k[0]];
        assert!(Record::parse(&bytes, Some(keys(&both))).is_ok());
        // Signed by the right key for the wrong host.
        let elsewhere = Freeze {
            registrar: "other.example".into(),
            ..f
        };
        assert_eq!(
            Record::parse(&elsewhere.sign(&reg()), Some(keys(&k))),
            Err(Error::BadField("registrar"))
        );

        let a = AttestationRevocation {
            identity: alice.public(),
            registrar: "hl.example".into(),
            handle: "alice".into(),
            time: T,
            reason: Some(attestation_reason::ABUSE),
        };
        let rec = Record::parse(&a.sign(&reg()), Some(keys(&k))).unwrap();
        assert!(!rec.user_signed());
        assert_eq!(rec, Record::RevokeAttestation(a));
    }

    #[test]
    fn identity_revocation_is_recognized_by_elimination() {
        let alice = id(1);
        let r = IdentityRevocation {
            identity: alice.public(),
            time: T,
            reason: Some(identity_reason::COMPROMISED),
        };
        let rec = Record::parse(&r.sign(&alice).unwrap(), None).unwrap();
        assert_eq!(rec.kind(), "revoke_identity");
        assert!(rec.user_signed());
        // A registration request is not a record, whatever it resembles.
        let req = RegisterRequest {
            identity: alice.public(),
            registrar: "hl.example".into(),
            handle: "alice".into(),
            time: T,
            successor: None,
            proof: None,
        }
        .sign(&alice)
        .unwrap();
        assert!(Record::parse(&req, Some(keys(&[reg().public()]))).is_err());
    }

    #[test]
    fn lists_verify_and_keep_their_domains_apart() {
        let k = [reg().public()];
        let list = SignedList {
            registrar: "hl.example".into(),
            issued: T,
            expires: T + 3600,
            fingerprint: Some(id(1).fingerprint().0),
            since: None,
            more: false,
            entries: vec![(1, vec![1, 2]), (5, vec![3])],
        };
        let bytes = list.sign(ListKind::Records, &reg());
        assert_eq!(
            SignedList::parse(&bytes, ListKind::Records, keys(&k)).unwrap(),
            list
        );
        assert_eq!(
            SignedList::parse(&bytes, ListKind::Log, keys(&k)),
            Err(Error::BadField("fingerprint"))
        );
        let log = SignedList {
            fingerprint: None,
            since: Some(0),
            more: true,
            ..list.clone()
        };
        let bytes = log.sign(ListKind::Log, &reg());
        assert_eq!(
            SignedList::parse(&bytes, ListKind::Log, keys(&k)).unwrap(),
            log
        );
        assert_eq!(
            SignedList::parse(&bytes, ListKind::Records, keys(&k)),
            Err(Error::BadSignature)
        );
        let backwards = SignedList {
            entries: vec![(5, vec![]), (5, vec![])],
            ..list
        };
        assert_eq!(
            SignedList::parse(
                &backwards.sign(ListKind::Records, &reg()),
                ListKind::Records,
                keys(&k)
            ),
            Err(Error::BadField("entries"))
        );
    }

    #[test]
    fn stats_round_trip() {
        let k = [reg().public()];
        let s = Stats {
            registrar: "hl.example".into(),
            at: T,
            identities: 3,
            issued_total: 4,
            log_seq: 9,
            ..Stats::default()
        };
        let bytes = s.sign(&reg());
        assert!(bytes.len() <= STATS_MAX_BYTES);
        assert_eq!(Stats::parse(&bytes, keys(&k)).unwrap(), s);
    }
}
