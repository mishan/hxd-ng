//! Friendship objects (`docs/proposals/friendship-objects.md`): an
//! offer, the acceptance that answers it, the friendship the two make,
//! and the withdrawal that ends friendships between a pair. Each is
//! signed by a device key whose certificate it carries (§1), and each
//! check runs the spec's steps in its order. A refusal names the step it
//! failed at, which is what the spec's reads are stated in.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::cbor::{self, map, Value};
use crate::cert::{self, caps, DeviceCert};
use crate::error::Error;
use crate::keys::{DeviceKey, Fingerprint, PublicKey};
use crate::message::{self, CERT_MAX_BYTES, SKEW};
use crate::registrar::Rotation;
use crate::signed::{self, Envelope, VERSION};

pub const OFFER_DOMAIN: &str = "hl-identity/friend-offer/v1";
pub const ACCEPT_DOMAIN: &str = "hl-identity/friend-accept/v1";
pub const WITHDRAW_DOMAIN: &str = "hl-identity/friend-withdraw/v1";
pub const PAIR_DOMAIN: &str = "hl-identity/friend-pair/v1";

/// The bound on each object, and on each element of a friendship.
pub const MAX_BYTES: usize = 1024;
/// A friendship's array at its longest: its head, and two elements at
/// [`MAX_BYTES`] behind three-byte heads. Checked before it is decoded.
pub const FRIENDSHIP_MAX_BYTES: usize = 1 + 2 * (3 + MAX_BYTES);
/// How long after its `time` an offer may expire (§2).
pub const OFFER_MAX_LIFETIME: u64 = 30 * 24 * 3600;

/// Why a check refused an object: the step of its check it failed at,
/// and what failed there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub step: u8,
    pub error: Error,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}: {}", self.step, self.error)
    }
}

impl std::error::Error for Refused {}

trait AtStep<T> {
    fn at(self, step: u8) -> Result<T, Refused>;
}

impl<T> AtStep<T> for Result<T, Error> {
    fn at(self, step: u8) -> Result<T, Refused> {
        self.map_err(|error| Refused { step, error })
    }
}

/// Two identities, by fingerprint, without saying which is which (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    lo: Fingerprint,
    hi: Fingerprint,
}

impl Pair {
    pub fn new(a: Fingerprint, b: Fingerprint) -> Pair {
        if a.0 <= b.0 {
            Pair { lo: a, hi: b }
        } else {
            Pair { lo: b, hi: a }
        }
    }

    pub fn contains(&self, fp: &Fingerprint) -> bool {
        self.lo == *fp || self.hi == *fp
    }

    /// The pair hash: SHA-256 of the domain, a NUL, and the lesser and
    /// the greater fingerprint.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PAIR_DOMAIN.as_bytes());
        h.update([0]);
        h.update(self.lo.0);
        h.update(self.hi.0);
        h.finalize().into()
    }
}

/// An offer (§2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub from: PublicKey,
    pub to: Fingerprint,
    pub time: u64,
    pub expires: u64,
    pub id: [u8; 16],
    pub cert: Vec<u8>,
}

impl Offer {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("from", Some(Value::Bytes(self.from.to_vec()))),
            ("to", Some(Value::Bytes(self.to.0.to_vec()))),
            ("time", Some(Value::Uint(self.time))),
            ("expires", Some(Value::Uint(self.expires))),
            ("id", Some(Value::Bytes(self.id.to_vec()))),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
        ])
    }

    fn from_value(v: &Value) -> Result<Offer, Error> {
        let offer = Offer {
            from: signed::bytes32(v, "from")?,
            to: Fingerprint(signed::bytes32(v, "to")?),
            time: signed::uint(v, "time")?,
            expires: signed::uint(v, "expires")?,
            id: message::bytes16(v, "id")?,
            cert: signed::bytes(v, "cert")?,
        };
        if offer.expires <= offer.time
            || offer.expires > offer.time.saturating_add(OFFER_MAX_LIFETIME)
        {
            return Err(Error::BadField("expires"));
        }
        if offer.to == offer.offerer() {
            return Err(Error::BadField("to"));
        }
        Ok(offer)
    }

    /// Sign with the device key the certificate names, refusing what a
    /// checker would refuse without a clock.
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, Error> {
        let unsigned = self.unsigned();
        Self::from_value(&unsigned)?;
        seal(
            unsigned,
            &self.from,
            &self.cert,
            self.time,
            device,
            OFFER_DOMAIN,
        )
    }

    /// A lone offer, as a server takes it: §3's step 1 without the
    /// array, then steps 3 to 6, against `held`, the withdrawals the
    /// checker holds. None of them compares `expires` with `now`: a lone
    /// offer's expiry is the caller's to enforce.
    pub fn check(bytes: &[u8], now: u64, held: &[Held]) -> Result<Offer, Refused> {
        let (offer, env) = open(bytes, Offer::from_value).at(1)?;
        not_ahead(offer.time, now).at(3)?;
        let cert = cert_at(&offer.cert, &offer.from, offer.time).at(4)?;
        verify(&cert, &env, OFFER_DOMAIN).at(5)?;
        if held.iter().any(|w| offer.ended_by(w)) {
            return Err(Error::Withdrawn).at(6);
        }
        Ok(offer)
    }

    pub fn offerer(&self) -> Fingerprint {
        Fingerprint::of(&self.from)
    }

    pub fn pair(&self) -> Pair {
        Pair::new(self.offerer(), self.to)
    }

    /// Whether `w` ends this offer: a friendship made from it would have
    /// a half by the offerer that `w` ends (§4). A withdrawal by the
    /// offeree does not, since an acceptance signed after it postdates
    /// its cutoff.
    pub fn ended_by(&self, w: &Held) -> bool {
        w.ends(&self.pair(), &self.offerer(), self.time)
    }
}

/// An acceptance (§3), naming its offer by the SHA-256 of the offer's
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceptance {
    pub offer: [u8; 32],
    pub from: PublicKey,
    pub time: u64,
    pub cert: Vec<u8>,
}

impl Acceptance {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("offer", Some(Value::Bytes(self.offer.to_vec()))),
            ("from", Some(Value::Bytes(self.from.to_vec()))),
            ("time", Some(Value::Uint(self.time))),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
        ])
    }

    fn from_value(v: &Value) -> Result<Acceptance, Error> {
        Ok(Acceptance {
            offer: signed::bytes32(v, "offer")?,
            from: signed::bytes32(v, "from")?,
            time: signed::uint(v, "time")?,
            cert: signed::bytes(v, "cert")?,
        })
    }

    /// Sign with the device key the certificate names. What it is
    /// checked against, the offer, is [`Friendship::check`]'s.
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, Error> {
        seal(
            self.unsigned(),
            &self.from,
            &self.cert,
            self.time,
            device,
            ACCEPT_DOMAIN,
        )
    }
}

/// A friendship (§3): an offer and its acceptance, both checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Friendship {
    pub offer: Offer,
    pub acceptance: Acceptance,
    /// The friendship hash, the SHA-256 of the array's bytes, which
    /// names it.
    pub hash: [u8; 32],
}

impl Friendship {
    /// The array a friendship is carried as: the offer's bytes, then the
    /// acceptance's.
    pub fn encode(offer: &[u8], acceptance: &[u8]) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Bytes(offer.to_vec()),
            Value::Bytes(acceptance.to_vec()),
        ]))
    }

    /// §3's six steps, in order, against `held`, the withdrawals the
    /// checker holds.
    pub fn check(bytes: &[u8], now: u64, held: &[Held]) -> Result<Friendship, Refused> {
        let (offer_bytes, accept_bytes) = split(bytes).at(1)?;
        let (offer, offer_env) = open(&offer_bytes, Offer::from_value).at(1)?;
        let (acceptance, accept_env) = open(&accept_bytes, Acceptance::from_value).at(1)?;

        if acceptance.offer != <[u8; 32]>::from(Sha256::digest(&offer_bytes)) {
            return Err(Error::BadField("offer")).at(2);
        }
        if Fingerprint::of(&acceptance.from) != offer.to || acceptance.from == offer.from {
            return Err(Error::KeyMismatch).at(2);
        }

        not_ahead(offer.time, now)
            .and(not_ahead(acceptance.time, now))
            .at(3)?;
        if !(offer.time..=offer.expires).contains(&acceptance.time) {
            return Err(Error::BadField("time")).at(3);
        }

        let offer_cert = cert_at(&offer.cert, &offer.from, offer.time).at(4)?;
        let accept_cert = cert_at(&acceptance.cert, &acceptance.from, acceptance.time).at(4)?;

        verify(&offer_cert, &offer_env, OFFER_DOMAIN)
            .and_then(|()| verify(&accept_cert, &accept_env, ACCEPT_DOMAIN))
            .at(5)?;

        let friendship = Friendship {
            offer,
            acceptance,
            hash: Sha256::digest(bytes).into(),
        };
        if held.iter().any(|w| friendship.ended_by(w)) {
            return Err(Error::Withdrawn).at(6);
        }
        Ok(friendship)
    }

    pub fn pair(&self) -> Pair {
        self.offer.pair()
    }

    /// Whether `w` ends this friendship: its half by `w`'s effective
    /// party is dated before `w`'s `before` (§4).
    pub fn ended_by(&self, w: &Held) -> bool {
        let pair = self.pair();
        w.ends(&pair, &self.offer.offerer(), self.offer.time)
            || w.ends(&pair, &self.offer.to, self.acceptance.time)
    }
}

/// The array's two byte strings, and nothing else in their place.
fn split(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if bytes.len() > FRIENDSHIP_MAX_BYTES {
        return Err(Error::TooLarge);
    }
    match cbor::decode_canonical(bytes)? {
        Value::Array(items) => match <[Value; 2]>::try_from(items) {
            Ok([Value::Bytes(offer), Value::Bytes(acceptance)]) => Ok((offer, acceptance)),
            _ => Err(Error::BadField("friendship")),
        },
        _ => Err(Error::BadField("friendship")),
    }
}

/// A withdrawal (§4), as it is signed and read. What ends friendships
/// is a [`Held`], which only a whole check makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withdrawal {
    pub from: PublicKey,
    pub pair: [u8; 32],
    /// `None` means `from`'s own fingerprint, which is never written out,
    /// so that each withdrawal has one encoding.
    pub party: Option<Fingerprint>,
    pub before: u64,
    pub time: u64,
    pub cert: Vec<u8>,
}

impl Withdrawal {
    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("from", Some(Value::Bytes(self.from.to_vec()))),
            ("pair", Some(Value::Bytes(self.pair.to_vec()))),
            ("party", self.party.map(|p| Value::Bytes(p.0.to_vec()))),
            ("before", Some(Value::Uint(self.before))),
            ("time", Some(Value::Uint(self.time))),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
        ])
    }

    fn from_value(v: &Value) -> Result<Withdrawal, Error> {
        let w = Withdrawal {
            from: signed::bytes32(v, "from")?,
            pair: signed::bytes32(v, "pair")?,
            party: signed::opt_bytes32(v, "party")?.map(Fingerprint),
            before: signed::uint(v, "before")?,
            time: signed::uint(v, "time")?,
            cert: signed::bytes(v, "cert")?,
        };
        if w.party == Some(Fingerprint::of(&w.from)) {
            return Err(Error::BadField("party"));
        }
        Ok(w)
    }

    /// Sign with the device key the certificate names, refusing what a
    /// checker would refuse without a clock or a pair.
    pub fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, Error> {
        let unsigned = self.unsigned();
        Self::from_value(&unsigned)?;
        if self.before > self.time {
            return Err(Error::BadField("before"));
        }
        seal(
            unsigned,
            &self.from,
            &self.cert,
            self.time,
            device,
            WITHDRAW_DOMAIN,
        )
    }

    /// Steps 1, 2, 5 and 6, which need nothing but the withdrawal: what a
    /// checker holding no pair that matches `pair` may keep one on. It
    /// ends nothing until [`Kept::check_pair`] passes too.
    pub fn parse(bytes: &[u8], now: u64) -> Result<Kept, Refused> {
        let (w, env) = Self::open_timed(bytes, now)?;
        w.verify(&env)?;
        Ok(Kept(w))
    }

    /// All six steps, in order.
    pub fn check(
        bytes: &[u8],
        now: u64,
        pair: &Pair,
        rotations: &[Rotation],
    ) -> Result<Held, Refused> {
        let (w, env) = Self::open_timed(bytes, now)?;
        w.pair_rules(pair, rotations)?;
        w.verify(&env)?;
        Ok(Held(w))
    }

    /// Steps 3 and 4: against the pair's two fingerprints, and the
    /// rotations the checker has applied, each already checked.
    fn pair_rules(&self, pair: &Pair, rotations: &[Rotation]) -> Result<(), Refused> {
        if self.pair != pair.hash() {
            return Err(Error::KeyMismatch).at(3);
        }
        // A chain ends only at a key with no rotation away from it, so a
        // key the checker has seen rotated away from is refused wherever
        // it sits in the chain: what it signs after the rotation may be a
        // thief's.
        let from = Some(Fingerprint::of(&self.from));
        if chain_end(pair.lo, rotations) != from && chain_end(pair.hi, rotations) != from {
            return Err(Error::KeyMismatch).at(4);
        }
        let party = self.effective_party();
        if !pair.contains(&party) {
            return Err(Error::BadField("party")).at(4);
        }
        if rotations
            .iter()
            .any(|r| Fingerprint::of(&r.identity) == party && self.before > r.time)
        {
            return Err(Error::BadField("before")).at(4);
        }
        Ok(())
    }

    fn open_timed(bytes: &[u8], now: u64) -> Result<(Withdrawal, Envelope), Refused> {
        let (w, env) = open(bytes, Withdrawal::from_value).at(1)?;
        if w.before > w.time {
            return Err(Error::BadField("before")).at(2);
        }
        not_ahead(w.time, now).at(2)?;
        Ok((w, env))
    }

    fn verify(&self, env: &Envelope) -> Result<(), Refused> {
        let cert = cert_at(&self.cert, &self.from, self.time).at(5)?;
        verify(&cert, env, WITHDRAW_DOMAIN).at(6)
    }

    /// `party`, or with it absent the SHA-256 of `from`.
    pub fn effective_party(&self) -> Fingerprint {
        self.party.unwrap_or_else(|| Fingerprint::of(&self.from))
    }
}

/// A withdrawal that passed the steps [`Withdrawal::parse`] runs, kept
/// until a pair it names is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept(Withdrawal);

impl Kept {
    pub fn withdrawal(&self) -> &Withdrawal {
        &self.0
    }

    /// Steps 3 and 4, the rest of the check.
    pub fn check_pair(self, pair: &Pair, rotations: &[Rotation]) -> Result<Held, Refused> {
        self.0.pair_rules(pair, rotations)?;
        Ok(Held(self.0))
    }
}

/// A withdrawal checked whole, which a checker holds and applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held(Withdrawal);

impl Held {
    pub fn withdrawal(&self) -> &Withdrawal {
        &self.0
    }

    /// Whether this ends a half by `party`, dated `time`, of a
    /// friendship between `pair`. A half dated exactly `before` stands.
    pub fn ends(&self, pair: &Pair, party: &Fingerprint, time: u64) -> bool {
        let w = &self.0;
        w.pair == pair.hash() && w.effective_party() == *party && time < w.before
    }
}

/// The last key of the chain of rotations from `start`, or `None` where
/// the rotations applied fork or loop, so that no one key ends it.
fn chain_end(start: Fingerprint, rotations: &[Rotation]) -> Option<Fingerprint> {
    let mut key = start;
    for _ in 0..=rotations.len() {
        let mut next = rotations
            .iter()
            .filter(|r| Fingerprint::of(&r.identity) == key)
            .map(|r| r.successor);
        match next.next() {
            None => return Some(key),
            Some(successor) if next.all(|s| s == successor) => {
                key = Fingerprint::of(&successor);
            }
            Some(_) => return None,
        }
    }
    None
}

fn open<T>(bytes: &[u8], read: fn(&Value) -> Result<T, Error>) -> Result<(T, Envelope), Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    let env = Envelope::open(bytes)?;
    Ok((read(&env.value)?, env))
}

/// A `time` no later than `now + S`.
fn not_ahead(time: u64, now: u64) -> Result<(), Error> {
    if time > now.saturating_add(SKEW) {
        return Err(Error::ClockSkew);
    }
    Ok(())
}

/// §1's certificate: for `from`, allowing messages, at most
/// [`CERT_MAX_BYTES`] and valid at `time`. Its signature is the next
/// step's.
fn cert_at(bytes: &[u8], from: &PublicKey, time: u64) -> Result<(DeviceCert, Envelope), Error> {
    if bytes.len() > CERT_MAX_BYTES {
        return Err(Error::BadField("cert"));
    }
    let (cert, env) = DeviceCert::open(bytes)?;
    if cert.identity != *from {
        return Err(Error::KeyMismatch);
    }
    cert.require(caps::MESSAGE)?;
    signed::check_window(cert.issued, cert.expires, time, SKEW)?;
    Ok((cert, env))
}

/// The identity key's signature on the certificate, then its device
/// key's on the object.
fn verify(
    (cert, cert_env): &(DeviceCert, Envelope),
    env: &Envelope,
    domain: &str,
) -> Result<(), Error> {
    cert_env.verify(&cert.identity, cert::DOMAIN)?;
    env.verify(&cert.device, domain)
}

fn seal(
    unsigned: Value,
    from: &PublicKey,
    cert: &[u8],
    time: u64,
    device: &DeviceKey,
    domain: &str,
) -> Result<Vec<u8>, Error> {
    let (cert, cert_env) = cert_at(cert, from, time)?;
    cert_env.verify(&cert.identity, cert::DOMAIN)?;
    if cert.device != device.public() {
        return Err(Error::KeyMismatch);
    }
    let bytes = signed::seal(unsigned, |body| device.sign(domain, body));
    if bytes.len() > MAX_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKey;

    const T: u64 = 1_757_117_000;
    const DAY: u64 = 86_400;
    const NOW: u64 = T + DAY;

    struct Who {
        id: IdentityKey,
        dev: DeviceKey,
        cert: Vec<u8>,
    }

    impl Who {
        fn new(seed: u8) -> Who {
            let id = IdentityKey::from_seed(&[seed; 32]);
            let dev = DeviceKey::from_seed(&[seed + 0x80; 32]);
            let mut c = DeviceCert::for_device(&id, &dev, T - 200, 90 * DAY).unwrap();
            c.caps = Some(caps::WEB);
            let cert = c.sign(&id);
            Who { id, dev, cert }
        }

        fn fp(&self) -> Fingerprint {
            self.id.fingerprint()
        }
    }

    fn offer(a: &Who, b: &Who) -> Offer {
        Offer {
            from: a.id.public(),
            to: b.fp(),
            time: T,
            expires: T + DAY,
            id: [0x11; 16],
            cert: a.cert.clone(),
        }
    }

    fn withdrawal(by: &Who, pair: Pair) -> Withdrawal {
        Withdrawal {
            from: by.id.public(),
            pair: pair.hash(),
            party: None,
            before: T + 3600,
            time: T + 3600,
            cert: by.cert.clone(),
        }
    }

    #[test]
    fn a_kept_withdrawal_ends_nothing_until_its_pair_passes() {
        let (a, b, x) = (Who::new(1), Who::new(2), Who::new(5));
        let ob = offer(&a, &b).sign(&a.dev).unwrap();
        let acceptance = Acceptance {
            offer: Sha256::digest(&ob).into(),
            from: b.id.public(),
            time: T + 60,
            cert: b.cert.clone(),
        };
        let fs = Friendship::encode(&ob, &acceptance.sign(&b.dev).unwrap());
        let pair = Pair::new(b.fp(), a.fp());
        let w = withdrawal(&a, pair);
        let kept = Withdrawal::parse(&w.sign(&a.dev).unwrap(), NOW).unwrap();
        assert_eq!(kept.withdrawal(), &w);
        assert_eq!(
            kept.clone().check_pair(&Pair::new(a.fp(), x.fp()), &[]),
            Err(Refused {
                step: 3,
                error: Error::KeyMismatch
            })
        );
        let held = kept.check_pair(&pair, &[]).unwrap();
        assert_eq!(
            Friendship::check(&fs, NOW, &[held]),
            Err(Refused {
                step: 6,
                error: Error::Withdrawn
            })
        );

        let elsewhere = Pair::new(a.fp(), x.fp());
        let other = Withdrawal::check(
            &withdrawal(&a, elsewhere).sign(&a.dev).unwrap(),
            NOW,
            &elsewhere,
            &[],
        )
        .unwrap();
        assert!(Friendship::check(&fs, NOW, &[other]).is_ok());
    }

    #[test]
    fn signing_refuses_what_a_checker_would() {
        let (a, b) = (Who::new(1), Who::new(2));
        let offer = offer(&a, &b);
        assert_eq!(offer.sign(&b.dev), Err(Error::KeyMismatch));
        let to_self = Offer {
            to: a.fp(),
            ..offer.clone()
        };
        assert_eq!(to_self.sign(&a.dev), Err(Error::BadField("to")));
        let w = Withdrawal {
            before: T + 1,
            time: T,
            ..withdrawal(&a, offer.pair())
        };
        assert_eq!(w.sign(&a.dev), Err(Error::BadField("before")));
    }
}
