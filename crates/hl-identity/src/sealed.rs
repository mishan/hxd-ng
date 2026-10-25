//! Sealed private messages (`docs/e2e-messages.md` §3.7–§3.11): the
//! whole signed map, padded and encrypted to one device's `device_enc`
//! key with HPKE (RFC 9180) in base mode (§3.8), or the map without its
//! signature in auth mode under the sender device's own `device_enc` key,
//! which the recipient could have made as well (§3.11); and opening
//! either in §3.9's order, ending in the states a client shows (§8).
//!
//! Freshness is the reader's clock and its replay memory, which outlives
//! any call here, so the caller keeps it behind [`Replay`].

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};

use crate::cbor::{self, Value};
use crate::cert::{caps, DeviceCert};
use crate::error::Error;
use crate::keys::{fresh_seed, DeviceKey, Fingerprint};
use crate::message::{
    check_cert, pad, unpad, Object, PrivateMessage, Sender, Signed, MESSAGE_DOMAIN, PAD_SIZES, SKEW,
};
use crate::signed::{self, Envelope, VERSION};

type Kem = X25519HkdfSha256;

/// Each form's HPKE `info`, which no other use of a `device_enc` key
/// shares (§3.8).
pub const SIGNED_INFO: &[u8] = b"hl-identity/sealed-message/v1/hpke";
pub const DENIABLE_INFO: &[u8] = b"hl-identity/sealed-message/v1/hpke-auth";
/// Each form's leading byte, which is its `aad` as well.
pub const SIGNED_BOX: u8 = 0x01;
pub const DENIABLE_BOX: u8 = 0x02;
/// What a box adds to its padded plaintext: the leading byte, `enc` and
/// the AES-GCM tag (§4.3, §9). A deniable box's `pkS` comes out of its
/// plaintext's sizes, so both forms come in the same sizes.
pub const OVERHEAD: usize = 1 + 32 + 16;
/// `H`, how long a sealed message can be held (§3.10), in seconds.
pub const HOLD: u64 = 24 * 3600;

/// Sign `message` with `sender` and seal it to the recipient device's
/// `device_enc` key (§3.8); or, `deniable`, seal it unsigned under
/// `sender`'s own `device_enc` key, which its certificate must name
/// (§3.11). Refuses what a reader would: a field out of bounds, or a
/// certificate that does not allow messages, is not valid at `sent` or
/// is not `sender`'s; and a recipient key whose X25519 result is all
/// zeros.
pub fn seal(
    message: &PrivateMessage,
    sender: &DeviceKey,
    recipient: &[u8; 32],
    deniable: bool,
) -> Result<Vec<u8>, Error> {
    seal_from_ikm(message, sender, recipient, deniable, &fresh_seed())
}

/// The recipient's certificate's `device_enc`, once it allows messages
/// and its identity is the one `message.to` names (§4.2).
pub fn seal_to(
    message: &PrivateMessage,
    sender: &DeviceKey,
    recipient: &DeviceCert,
    deniable: bool,
) -> Result<Vec<u8>, Error> {
    recipient.require(caps::MESSAGE)?;
    if Fingerprint::of(&recipient.identity) != message.to {
        return Err(Error::KeyMismatch);
    }
    seal(message, sender, &recipient.device_enc, deniable)
}

/// [`seal`] with the ephemeral key derived from `ikm` (RFC 9180
/// `DeriveKeyPair`), so a test vector's box can be made again byte for
/// byte. Only the vectors may call it: one `ikm` used twice to the same
/// recipient repeats `enc`, and so the AES-GCM key and nonce, under two
/// plaintexts, which gives away their XOR and lets anyone forge a box;
/// and anyone who knows `ikm` can open it.
#[doc(hidden)]
pub fn seal_from_ikm(
    message: &PrivateMessage,
    sender: &DeviceKey,
    recipient: &[u8; 32],
    deniable: bool,
    ikm: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    if !deniable {
        let plaintext = pad(&message.sign(sender)?, false)?;
        return seal_padded(&plaintext, recipient, None, ikm);
    }
    let unsigned = message.unsigned();
    PrivateMessage::from_value(&unsigned, false)?;
    let cert = check_cert(&message.cert, message.sent, message.sent)?;
    if cert.device_enc != sender.public_enc() {
        return Err(Error::KeyMismatch);
    }
    let plaintext = pad(&cbor::encode(&unsigned), true)?;
    seal_padded(&plaintext, recipient, Some(sender), ikm)
}

/// The box around a padded plaintext: base mode, or auth mode under
/// `sender`'s `device_enc` key.
fn seal_padded(
    plaintext: &[u8],
    recipient: &[u8; 32],
    sender: Option<&DeviceKey>,
    ikm: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let pk_r = public(recipient)?;
    let (form, info, mode) = match sender {
        None => (SIGNED_BOX, SIGNED_INFO, OpModeS::Base),
        Some(s) => (
            DENIABLE_BOX,
            DENIABLE_INFO,
            OpModeS::Auth((secret(s), public(&s.public_enc())?)),
        ),
    };
    let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
        &mode,
        &pk_r,
        info,
        plaintext,
        &[form],
        &mut Ikm(Some(ikm)),
    )
    .map_err(|_| Error::InvalidKey)?;
    let pk_s = sender.map_or(Vec::new(), |s| s.public_enc().to_vec());
    Ok([&[form][..], &pk_s, &enc.to_bytes(), &ct].concat())
}

/// What a reader knows about a box it was handed.
#[derive(Debug, Clone, Copy)]
pub struct Opening {
    /// The reader's clock.
    pub now: u64,
    /// When the reader's server received it (`at`): for display and the
    /// certificate's window, never for freshness (§3.10).
    pub at: u64,
    /// The identity the reader's session proved, which `to` must name.
    pub reader: Fingerprint,
    /// The fingerprint the sender is shown with (§3.9): `Named` with the
    /// event's `from.fingerprint` when the roster shows it for the
    /// sender's uid or shows nobody there, and with the roster's when it
    /// shows another; `Unknown` when it shows the uid with none, or the
    /// event names none. `Certificate` opens the box as from its
    /// certificate's identity, checked against nothing: never for a live
    /// `msg`, whose sender the server names.
    pub sender: Sender,
}

/// The sealed messages a device has accepted (§3.10), which the caller
/// keeps: stored with the device key, across restarts, and shared by
/// every session using it.
pub trait Replay {
    /// Records `now` as a time the reader's clock has shown, and returns
    /// the latest it has shown, which the memory is pruned by: so a clock
    /// set back neither empties it nor reopens the window.
    fn latest(&mut self, now: u64) -> u64;
    /// Whether `(signer, id)` was accepted.
    fn accepted(&self, signer: &Fingerprint, id: &[u8; 16]) -> bool;
    /// Records `(signer, id)` as accepted until `until`, in one atomic
    /// insert-if-absent, written before the message is shown: `false` if
    /// it was there already.
    fn accept(&mut self, signer: Fingerprint, id: [u8; 16], until: u64) -> bool;
}

/// §8's states for a sealed message. `sent_apart`: `sent` is more than
/// [`SKEW`] from `at`, so it is shown as sent at its signed time.
#[derive(Debug, Clone)]
pub enum Opened {
    /// A signed box that passed every step: shown as from its signer.
    Verified {
        message: Signed<PrivateMessage>,
        sent_apart: bool,
    },
    /// A deniable box that passed every step that applies: shown as from
    /// the certificate's identity, and as one its recipient could not
    /// prove to anyone.
    Deniable {
        message: PrivateMessage,
        cert: DeviceCert,
        sent_apart: bool,
    },
    /// Valid, from a uid the roster shows with no fingerprint. Its text is
    /// hidden until the user reveals it on purpose, and it is not
    /// recorded. `whole` is a signed box's map, which a report carries
    /// (§4.12); `None` for a deniable one.
    Unverified {
        message: PrivateMessage,
        signer: Fingerprint,
        whole: Option<Vec<u8>>,
    },
    /// Failed step 5 or 6: its text hidden until the user reveals it on
    /// purpose, never shown as from that user, and not recorded. Anyone
    /// who holds the recipient's certificate can seal one.
    Invalid {
        message: PrivateMessage,
        error: Error,
    },
    /// Stale, or accepted already (steps 3, 4 and 7): not shown at all.
    Dropped(Error),
    /// Failed step 1 or 2: shown as a message that could not be opened.
    Unopened(Error),
}

/// §3.9 in order, and §3.11 for a deniable box.
pub fn open(sealed: &[u8], reader: &DeviceKey, ctx: &Opening, memory: &mut impl Replay) -> Opened {
    let read = unbox(sealed, reader)
        .and_then(|(padded, pk_s)| Ok((read_map(&padded, pk_s.is_some(), ctx.reader)?, pk_s)));
    let ((message, env), pk_s) = match read {
        Ok(read) => read,
        Err(e) => return Opened::Unopened(e),
    };
    let latest = memory.latest(ctx.now);
    if let Err(e) = fresh(message.sent, ctx.now, latest) {
        return Opened::Dropped(e);
    }
    let claimed = DeviceCert::parse(&message.cert).map(|c| Fingerprint::of(&c.identity));
    if claimed.is_ok_and(|signer| memory.accepted(&signer, &message.id)) {
        return Opened::Dropped(Error::Replayed);
    }
    let cert = match verify(&message, env.as_ref(), pk_s, ctx) {
        Ok(cert) => cert,
        Err(error) => return Opened::Invalid { message, error },
    };
    let signer = Fingerprint::of(&cert.identity);
    if ctx.sender == Sender::Unknown {
        let whole = env.map(|env| cbor::encode(&env.value));
        return Opened::Unverified {
            message,
            signer,
            whole,
        };
    }
    let until = message.sent.saturating_add(HOLD + SKEW);
    if !memory.accept(signer, message.id, until) {
        return Opened::Dropped(Error::Replayed);
    }
    let sent_apart = message.sent.abs_diff(ctx.at) > SKEW;
    match env {
        Some(env) => Opened::Verified {
            message: Signed {
                message,
                cert,
                whole: env.value,
            },
            sent_apart,
        },
        None => Opened::Deniable {
            message,
            cert,
            sent_apart,
        },
    }
}

/// Step 1: the padded plaintext, and for a deniable box the `pkS` it
/// opened under.
fn unbox(sealed: &[u8], reader: &DeviceKey) -> Result<(Vec<u8>, Option<[u8; 32]>), Error> {
    let (&form, rest) = sealed.split_first().ok_or(Error::OpenFailed)?;
    check_len(form, sealed.len())?;
    let (info, pk_s, rest) = match form {
        SIGNED_BOX => (SIGNED_INFO, None, rest),
        DENIABLE_BOX => {
            let (pk_s, rest) = split32(rest)?;
            (DENIABLE_INFO, Some(pk_s), rest)
        }
        other => return Err(Error::UnsupportedVersion(other.into())),
    };
    let mode = match pk_s {
        None => OpModeR::Base,
        Some(pk) => OpModeR::Auth(public(&pk).map_err(|_| Error::OpenFailed)?),
    };
    let (enc, ct) = split32(rest)?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).map_err(|_| Error::OpenFailed)?;
    let plaintext = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &mode,
        &secret(reader),
        &enc,
        info,
        ct,
        &[form],
    )
    .map_err(|_| Error::OpenFailed)?;
    Ok((plaintext, pk_s))
}

/// Whether a box of this leading byte and length could hold a padded
/// plaintext (§3.7): what a server checks a `sealed` it is handed by
/// (§4.3), and a reader before anything is opened.
pub fn check_len(form: u8, len: usize) -> Result<(), Error> {
    if form != SIGNED_BOX && form != DENIABLE_BOX {
        return Err(Error::UnsupportedVersion(form.into()));
    }
    if !PAD_SIZES.iter().any(|size| size + OVERHEAD == len) {
        return Err(Error::BadField("padding"));
    }
    Ok(())
}

/// A deniable box's `pkS`, which a server checks is the `device_enc` of
/// the certificate the sending session proves (§4.3).
pub fn sender_enc(sealed: &[u8]) -> Option<[u8; 32]> {
    match sealed.split_first() {
        Some((&DENIABLE_BOX, rest)) => split32(rest).ok().map(|(pk, _)| pk),
        _ => None,
    }
}

/// Step 2: the padding, then a deterministic map of §3.2's fields with
/// `v = 1`, holding `sig` exactly when the box is signed, sent to the
/// reader.
fn read_map(
    padded: &[u8],
    deniable: bool,
    reader: Fingerprint,
) -> Result<(PrivateMessage, Option<Envelope>), Error> {
    let value = cbor::decode_canonical(unpad(padded, deniable)?)?;
    let (message, env) = if deniable {
        if !matches!(value, Value::Map(_)) {
            return Err(Error::NotAMap);
        }
        // A signature inside a deniable box would undo it.
        if value.get("sig").is_some() {
            return Err(Error::BadField("sig"));
        }
        match signed::uint(&value, "v")? {
            VERSION => (PrivateMessage::from_value(&value, false)?, None),
            v => return Err(Error::UnsupportedVersion(v)),
        }
    } else {
        let env = Envelope::from_value(value)?;
        (PrivateMessage::from_value(&env.value, false)?, Some(env))
    };
    if message.to != reader {
        return Err(Error::BadField("to"));
    }
    Ok((message, env))
}

/// Step 3 (§3.10): `sent` no earlier than `H` before the later of `now`
/// and the latest time the clock has shown, and no later than `S` after
/// `now`.
fn fresh(sent: u64, now: u64, latest: u64) -> Result<(), Error> {
    if sent < now.max(latest).saturating_sub(HOLD) || sent > now.saturating_add(SKEW) {
        return Err(Error::ClockSkew);
    }
    Ok(())
}

/// Steps 5 and 6: the certificate as §3.5 checks it, valid now as well,
/// its identity the one the sender is shown with and, in a deniable box,
/// its `device_enc` the `pkS` the box opened under; then the signature.
fn verify(
    message: &PrivateMessage,
    env: Option<&Envelope>,
    pk_s: Option<[u8; 32]>,
    ctx: &Opening,
) -> Result<DeviceCert, Error> {
    let cert = check_cert(&message.cert, message.sent, ctx.at)?;
    cert.check_valid(ctx.now, SKEW)?;
    let shown_as_another =
        matches!(ctx.sender, Sender::Named(fp) if fp != Fingerprint::of(&cert.identity));
    if shown_as_another || pk_s.is_some_and(|pk| pk != cert.device_enc) {
        return Err(Error::KeyMismatch);
    }
    if let Some(env) = env {
        env.verify(&cert.device, MESSAGE_DOMAIN)?;
    }
    Ok(cert)
}

fn split32(bytes: &[u8]) -> Result<([u8; 32], &[u8]), Error> {
    let (key, rest) = bytes.split_at_checked(32).ok_or(Error::OpenFailed)?;
    Ok((key.try_into().expect("split at 32"), rest))
}

fn public(key: &[u8; 32]) -> Result<<Kem as hpke::Kem>::PublicKey, Error> {
    <Kem as hpke::Kem>::PublicKey::from_bytes(key).map_err(|_| Error::InvalidKey)
}

fn secret(key: &DeviceKey) -> <Kem as hpke::Kem>::PrivateKey {
    <Kem as hpke::Kem>::PrivateKey::from_bytes(&*key.enc_secret()).expect("32 bytes")
}

/// The one draw HPKE's `Encap` makes: the ikm `DeriveKeyPair` turns into
/// the ephemeral key, which is what lets a vector fix it.
struct Ikm<'a>(Option<&'a [u8; 32]>);

impl RngCore for Ikm<'_> {
    fn next_u32(&mut self) -> u32 {
        unreachable!("HPKE draws its ephemeral key with fill_bytes")
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!("HPKE draws its ephemeral key with fill_bytes")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(self.0.take().expect("one ephemeral key per box"));
    }
}

impl CryptoRng for Ikm<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert;
    use crate::keys::IdentityKey;

    const SENT: u64 = 1_700_000_000;
    const IKM: [u8; 32] = [0xe1; 32];

    struct World {
        id: IdentityKey,
        dev: DeviceKey,
        cert: Vec<u8>,
        reader: IdentityKey,
        reader_dev: DeviceKey,
    }

    fn world() -> World {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        // Valid from before the oldest `sent` a reader takes to after the
        // latest `now` here, so the certificate never decides a freshness
        // case.
        let mut c = DeviceCert::for_device(&id, &dev, SENT - 2 * HOLD, 4 * HOLD).unwrap();
        c.caps = Some(caps::WEB);
        World {
            cert: c.sign(&id),
            id,
            dev,
            reader: IdentityKey::from_seed(&[7u8; 32]),
            reader_dev: DeviceKey::from_seed(&[8u8; 32]),
        }
    }

    fn pm(w: &World) -> PrivateMessage {
        PrivateMessage {
            id: [8; 16],
            sent: SENT,
            to: w.reader.fingerprint(),
            cert: w.cert.clone(),
            text: "A private word.".into(),
            quote: None,
            auto: false,
        }
    }

    fn ctx(w: &World) -> Opening {
        Opening {
            now: SENT + 30,
            at: SENT + 30,
            reader: w.reader.fingerprint(),
            sender: Sender::Named(w.id.fingerprint()),
        }
    }

    #[derive(Default)]
    struct Memory {
        latest: u64,
        accepted: Vec<(Fingerprint, [u8; 16], u64)>,
    }

    impl Replay for Memory {
        fn latest(&mut self, now: u64) -> u64 {
            self.latest = self.latest.max(now);
            self.latest
        }

        fn accepted(&self, signer: &Fingerprint, id: &[u8; 16]) -> bool {
            self.accepted.iter().any(|(s, i, _)| s == signer && i == id)
        }

        fn accept(&mut self, signer: Fingerprint, id: [u8; 16], until: u64) -> bool {
            if self.accepted(&signer, &id) {
                return false;
            }
            self.accepted.push((signer, id, until));
            true
        }
    }

    /// A certificate that expires a hundred seconds after `SENT`.
    fn short(w: &World) -> Vec<u8> {
        DeviceCert::for_device(&w.id, &w.dev, SENT - 100, 200)
            .unwrap()
            .sign(&w.id)
    }

    fn sealed(w: &World, m: &PrivateMessage, deniable: bool) -> Vec<u8> {
        seal_from_ikm(m, &w.dev, &w.reader_dev.public_enc(), deniable, &IKM).unwrap()
    }

    /// The box around a plaintext a sender would never pad, in either
    /// form.
    fn boxed(w: &World, plaintext: &[u8], sender: Option<&DeviceKey>) -> Vec<u8> {
        seal_padded(plaintext, &w.reader_dev.public_enc(), sender, &IKM).unwrap()
    }

    /// `state`, and the error it carries if it carries one.
    fn state(o: &Opened) -> (&'static str, Option<Error>) {
        match o {
            Opened::Verified { .. } => ("verified", None),
            Opened::Deniable { .. } => ("deniable", None),
            Opened::Unverified { .. } => ("unverified", None),
            Opened::Invalid { error, .. } => ("invalid", Some(error.clone())),
            Opened::Dropped(e) => ("dropped", Some(e.clone())),
            Opened::Unopened(e) => ("unopened", Some(e.clone())),
        }
    }

    #[test]
    fn each_form_opens_once_as_what_was_sealed() {
        let w = world();
        for deniable in [false, true] {
            let bytes = sealed(&w, &pm(&w), deniable);
            assert_eq!(bytes.len(), PAD_SIZES[0] + OVERHEAD, "{deniable}");
            assert_ne!(
                bytes,
                seal(&pm(&w), &w.dev, &w.reader_dev.public_enc(), deniable).unwrap()
            );
            let mut memory = Memory::default();
            match open(&bytes, &w.reader_dev, &ctx(&w), &mut memory) {
                Opened::Verified {
                    message,
                    sent_apart: false,
                } if !deniable => {
                    assert_eq!(message.message, pm(&w));
                    assert_eq!(message.whole(), pm(&w).sign(&w.dev).unwrap());
                }
                Opened::Deniable {
                    message,
                    cert,
                    sent_apart: false,
                } if deniable => {
                    assert_eq!(message, pm(&w));
                    assert_eq!(Fingerprint::of(&cert.identity), w.id.fingerprint());
                }
                other => panic!("{deniable}: {other:?}"),
            }
            let again = open(&bytes, &w.reader_dev, &ctx(&w), &mut memory);
            assert_eq!(state(&again), ("dropped", Some(Error::Replayed)));
            assert_eq!(sender_enc(&bytes), deniable.then(|| w.dev.public_enc()));

            let unknown = Opening {
                sender: Sender::Unknown,
                ..ctx(&w)
            };
            match open(&bytes, &w.reader_dev, &unknown, &mut Memory::default()) {
                Opened::Unverified { whole, .. } => {
                    assert_eq!(whole, (!deniable).then(|| pm(&w).sign(&w.dev).unwrap()))
                }
                other => panic!("{deniable}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_largest_message_fills_the_largest_box_in_either_form() {
        let w = world();
        let Value::Map(mut entries) = cbor::decode_canonical(&w.cert).unwrap().without("sig")
        else {
            unreachable!()
        };
        entries.push((Value::Text("future".into()), Value::Bytes(vec![])));
        let short = signed::seal(Value::Map(entries.clone()), |b| w.id.sign(cert::DOMAIN, b));
        entries.pop();
        entries.push((
            Value::Text("future".into()),
            Value::Bytes(vec![0; 512 - short.len() - 2]),
        ));
        let cert = signed::seal(Value::Map(entries), |b| w.id.sign(cert::DOMAIN, b));
        assert_eq!(cert.len(), 512);
        let largest = PrivateMessage {
            cert,
            text: "x".repeat(8192),
            quote: Some("q".repeat(8192)),
            auto: true,
            ..pm(&w)
        };
        for deniable in [false, true] {
            let bytes = sealed(&w, &largest, deniable);
            assert_eq!(bytes.len(), PAD_SIZES[PAD_SIZES.len() - 1] + OVERHEAD);
            let opened = open(&bytes, &w.reader_dev, &ctx(&w), &mut Memory::default());
            assert_eq!(
                state(&opened).0,
                ["verified", "deniable"][deniable as usize]
            );
        }
    }

    #[test]
    fn seal_refuses_what_a_reader_would() {
        let w = world();
        let stranger = DeviceKey::from_seed(&[3u8; 32]);
        let to = w.reader_dev.public_enc();
        let recipient_cert = |identity: &IdentityKey, cap| {
            let mut c = DeviceCert::for_device(identity, &w.reader_dev, SENT, 1000).unwrap();
            c.caps = Some(cap);
            c
        };
        let to_cert = recipient_cert(&w.reader, caps::WEB);
        let opened = open(
            &seal_to(&pm(&w), &w.dev, &to_cert, false).unwrap(),
            &w.reader_dev,
            &ctx(&w),
            &mut Memory::default(),
        );
        assert_eq!(state(&opened).0, "verified");
        for (name, got, want) in [
            (
                "to a certificate of another identity",
                seal_to(&pm(&w), &w.dev, &recipient_cert(&w.id, caps::WEB), true),
                Error::KeyMismatch,
            ),
            (
                "to a certificate without bit 1",
                seal_to(
                    &pm(&w),
                    &w.dev,
                    &recipient_cert(&w.reader, caps::LOGIN),
                    false,
                ),
                Error::CapabilityMissing,
            ),
            (
                "signed by another device",
                seal(&pm(&w), &stranger, &to, false),
                Error::KeyMismatch,
            ),
            (
                "deniable under another device's key",
                seal(&pm(&w), &stranger, &to, true),
                Error::KeyMismatch,
            ),
            (
                "deniable, empty text",
                seal(
                    &PrivateMessage {
                        text: String::new(),
                        ..pm(&w)
                    },
                    &w.dev,
                    &to,
                    true,
                ),
                Error::BadField("text"),
            ),
            (
                "a recipient key of small order",
                seal(&pm(&w), &w.dev, &[0; 32], false),
                Error::InvalidKey,
            ),
            (
                "deniable to a recipient key of small order",
                seal(&pm(&w), &w.dev, &[0; 32], true),
                Error::InvalidKey,
            ),
        ] {
            assert_eq!(got, Err(want), "{name}");
        }
    }

    #[test]
    fn what_fails_to_open_or_to_read_is_unopened() {
        let w = world();
        let signed = sealed(&w, &pm(&w), false);
        let deniable = sealed(&w, &pm(&w), true);
        let mut flipped = signed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let mut swapped = deniable.clone();
        swapped[1..33].copy_from_slice(&DeviceKey::from_seed(&[9u8; 32]).public_enc());
        let mut zero_enc = signed.clone();
        zero_enc[1..33].fill(0);
        let signed_map = pm(&w).sign(&w.dev).unwrap();
        let unsigned_map = cbor::encode(&pm(&w).unsigned());
        let to_another = PrivateMessage {
            to: w.id.fingerprint(),
            ..pm(&w)
        };
        let base_as_deniable = {
            let (enc, ct) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem, _>(
                &OpModeS::Base,
                &public(&w.reader_dev.public_enc()).unwrap(),
                DENIABLE_INFO,
                &pad(&unsigned_map, true).unwrap(),
                &[DENIABLE_BOX],
                &mut Ikm(Some(&IKM)),
            )
            .unwrap();
            [
                &[DENIABLE_BOX][..],
                &w.dev.public_enc(),
                &enc.to_bytes(),
                &ct,
            ]
            .concat()
        };
        let mut nonzero_padding = pad(&signed_map, false).unwrap();
        *nonzero_padding.last_mut().unwrap() = 1;
        for (name, bytes, want) in [
            ("nothing", vec![], Error::OpenFailed),
            (
                "another leading byte",
                [&[3][..], &signed[1..]].concat(),
                Error::UnsupportedVersion(3),
            ),
            ("a ciphertext altered", flipped, Error::OpenFailed),
            (
                "an ephemeral key of small order",
                zero_enc,
                Error::OpenFailed,
            ),
            (
                "a deniable box with another pkS",
                swapped,
                Error::OpenFailed,
            ),
            (
                "a box of no size",
                signed[..signed.len() - 1].to_vec(),
                Error::BadField("padding"),
            ),
            (
                "a deniable box relabeled as a signed one",
                [&[SIGNED_BOX][..], &deniable[33..]].concat(),
                Error::BadField("padding"),
            ),
            (
                "a signed box relabeled as a deniable one",
                [&[DENIABLE_BOX][..], &w.dev.public_enc(), &signed[1..]].concat(),
                Error::BadField("padding"),
            ),
            (
                "0x02 sealed in base mode",
                base_as_deniable,
                Error::OpenFailed,
            ),
            (
                "a signed box sealed to another identity",
                sealed(&w, &to_another, false),
                Error::BadField("to"),
            ),
            (
                "a deniable box sealed to another identity",
                sealed(&w, &to_another, true),
                Error::BadField("to"),
            ),
            (
                "a deniable plaintext carrying sig",
                boxed(&w, &pad(&signed_map, true).unwrap(), Some(&w.dev)),
                Error::BadField("sig"),
            ),
            (
                "a signed plaintext without sig",
                boxed(&w, &pad(&unsigned_map, false).unwrap(), None),
                Error::MissingField("sig"),
            ),
            (
                "a deniable plaintext at a signed box's size",
                boxed(&w, &pad(&unsigned_map, false).unwrap(), Some(&w.dev)),
                Error::BadField("padding"),
            ),
            (
                "a nonzero padding byte",
                boxed(&w, &nonzero_padding, None),
                Error::BadField("padding"),
            ),
        ] {
            let got = open(&bytes, &w.reader_dev, &ctx(&w), &mut Memory::default());
            assert_eq!(state(&got), ("unopened", Some(want)), "{name}");
        }
        let elsewhere = open(&signed, &w.dev, &ctx(&w), &mut Memory::default());
        assert_eq!(state(&elsewhere), ("unopened", Some(Error::OpenFailed)));
    }

    #[test]
    fn the_sender_and_the_certificate_are_checked_and_a_failure_not_recorded() {
        let w = world();
        let mut login_only = DeviceCert::for_device(&w.id, &w.dev, SENT - 100, 100_000).unwrap();
        login_only.caps = Some(caps::LOGIN);
        let login_only = PrivateMessage {
            cert: login_only.sign(&w.id),
            ..pm(&w)
        };
        let forged = signed::seal(pm(&w).unsigned(), |b| {
            DeviceKey::from_seed(&[3u8; 32]).sign(MESSAGE_DOMAIN, b)
        });
        let other_enc = DeviceKey::from_seed(&[3u8; 32]);
        let unsigned_map = cbor::encode(&pm(&w).unsigned());
        let past_expiry = Opening {
            now: SENT + 100 + SKEW + 1,
            ..ctx(&w)
        };
        let named = |fp| Opening {
            sender: Sender::Named(fp),
            ..ctx(&w)
        };
        let unknown = Opening {
            sender: Sender::Unknown,
            ..ctx(&w)
        };
        for (name, bytes, c, want) in [
            (
                "a certificate expired now",
                sealed(
                    &w,
                    &PrivateMessage {
                        cert: short(&w),
                        ..pm(&w)
                    },
                    false,
                ),
                past_expiry,
                ("invalid", Some(Error::Expired)),
            ),
            (
                "a certificate without bit 1",
                boxed(
                    &w,
                    &pad(
                        &signed::seal(login_only.unsigned(), |b| w.dev.sign(MESSAGE_DOMAIN, b)),
                        false,
                    )
                    .unwrap(),
                    None,
                ),
                ctx(&w),
                ("invalid", Some(Error::CapabilityMissing)),
            ),
            (
                "a signature by another device",
                boxed(&w, &pad(&forged, false).unwrap(), None),
                ctx(&w),
                ("invalid", Some(Error::BadSignature)),
            ),
            (
                "a deniable box whose certificate names another device_enc",
                boxed(&w, &pad(&unsigned_map, true).unwrap(), Some(&other_enc)),
                ctx(&w),
                ("invalid", Some(Error::KeyMismatch)),
            ),
            (
                "a sender shown with another fingerprint",
                sealed(&w, &pm(&w), false),
                named(w.reader.fingerprint()),
                ("invalid", Some(Error::KeyMismatch)),
            ),
            (
                "a deniable box from a sender shown with another fingerprint",
                sealed(&w, &pm(&w), true),
                named(w.reader.fingerprint()),
                ("invalid", Some(Error::KeyMismatch)),
            ),
            (
                "a sender shown with none",
                sealed(&w, &pm(&w), false),
                unknown,
                ("unverified", None),
            ),
            (
                "a deniable box from a sender shown with none",
                sealed(&w, &pm(&w), true),
                unknown,
                ("unverified", None),
            ),
        ] {
            let mut memory = Memory::default();
            let got = open(&bytes, &w.reader_dev, &c, &mut memory);
            assert_eq!(state(&got), want, "{name}");
            assert!(memory.accepted.is_empty(), "{name}: recorded");
        }
    }

    #[test]
    fn a_stale_or_replayed_box_is_dropped_before_its_certificate_is_judged() {
        let w = world();
        let now = SENT + 30;
        let at = |sent: u64| {
            let m = PrivateMessage { sent, ..pm(&w) };
            sealed(&w, &m, false)
        };
        let clock = |latest| Memory {
            latest,
            ..Memory::default()
        };
        for (name, bytes, mut memory, want) in [
            ("sent H ago", at(now - HOLD), clock(0), "verified"),
            (
                "sent H and a second ago",
                at(now - HOLD - 1),
                clock(0),
                "dropped",
            ),
            ("sent S ahead", at(now + SKEW), clock(0), "verified"),
            (
                "sent S and a second ahead",
                at(now + SKEW + 1),
                clock(0),
                "dropped",
            ),
            (
                "a clock set back keeps the window it had",
                at(now - HOLD + 60),
                clock(now + 120),
                "dropped",
            ),
        ] {
            let got = open(&bytes, &w.reader_dev, &ctx(&w), &mut memory);
            assert_eq!(state(&got).0, want, "{name}");
        }

        // Accepted once, then replayed after its certificate expired:
        // the replay is dropped rather than shown as invalid, until it is
        // too old to be fresh.
        let m = PrivateMessage {
            cert: short(&w),
            ..pm(&w)
        };
        let bytes = sealed(&w, &m, false);
        let mut memory = Memory::default();
        let got = open(&bytes, &w.reader_dev, &ctx(&w), &mut memory);
        assert_eq!(state(&got).0, "verified");
        assert_eq!(memory.accepted[0].2, SENT + HOLD + SKEW);
        for (now, want) in [
            (SENT + 100 + SKEW + 1, Error::Replayed),
            (SENT + HOLD + 1, Error::ClockSkew),
        ] {
            let later = Opening { now, ..ctx(&w) };
            let got = open(&bytes, &w.reader_dev, &later, &mut memory);
            assert_eq!(state(&got), ("dropped", Some(want)), "{now}");
        }
    }
}
