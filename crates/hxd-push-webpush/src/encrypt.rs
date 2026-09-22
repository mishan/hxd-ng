//! RFC 8291 message encryption, over RFC 8188's `aes128gcm` content
//! coding.
//!
//! The whole of it is a key agreement and two HKDFs, and it is written
//! out here rather than taken from a crate because it is forty lines and
//! the alternative is a dependency with its own opinion about HTTP.
//!
//! **Nothing between this process and the subscriber's user agent holds
//! a key for what comes out of here** — not the push service, not a
//! relay (push-notifications.md §8.2). That is the property the sidecar
//! could not offer, because it performed this step itself over a
//! cleartext REST hop (§6 there).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;

/// The record size this sends: one record, so the whole payload is in
/// it, and the ceiling §4 of the design truncates against is derived
/// from this.
pub const RECORD_SIZE: u32 = 4096;

/// The largest plaintext one record can carry: the record size, less the
/// 86-byte header, less the AEAD tag and the one delimiter byte.
pub const MAX_PLAINTEXT: usize = RECORD_SIZE as usize - 86 - 16 - 1;

/// What went wrong, as far as a caller can act on it: a subscription key
/// that is not a key at all is the client's fault and retires the
/// device, and everything else is ours.
#[derive(Debug, PartialEq, Eq)]
pub enum EncryptError {
    /// `p256dh` is not a point on the curve.
    BadSubscriptionKey,
    /// The plaintext does not fit one record. The caller truncates
    /// before it gets here ([`MAX_PLAINTEXT`]); reaching this is a bug,
    /// and it is an error rather than a silent truncation because a
    /// notification cut in half by a layer that does not know what it is
    /// cutting is worse than one that does not arrive.
    TooLong,
    /// AES-GCM said no, which at this point means the machine is having
    /// a much worse day than this notification.
    Aead,
}

/// The ephemeral half of one encryption. Its own type so a test can fix
/// it and the caller cannot accidentally reuse one: **an ephemeral key
/// and salt are per message**, and reusing a `(key, nonce)` pair across
/// two AES-GCM messages is the failure that breaks the cipher outright.
pub struct Ephemeral {
    secret: SecretKey,
    salt: [u8; 16],
}

impl Ephemeral {
    /// A fresh keypair and salt from the OS CSPRNG.
    pub fn new() -> Self {
        let mut salt = [0u8; 16];
        getrandom_salt(&mut salt);
        Ephemeral {
            secret: SecretKey::random(&mut rand_core::OsRng),
            salt,
        }
    }

    /// The vector's own key and salt, for [RFC 8291 §5]. Test-only, and
    /// the reason it is `#[cfg(test)]` rather than merely documented is
    /// the paragraph on [`Ephemeral`].
    ///
    /// [RFC 8291 §5]: https://www.rfc-editor.org/rfc/rfc8291#section-5
    #[cfg(test)]
    pub fn fixed(secret: [u8; 32], salt: [u8; 16]) -> Self {
        Ephemeral {
            secret: SecretKey::from_slice(&secret).expect("a test key is a key"),
            salt,
        }
    }
}

impl Default for Ephemeral {
    fn default() -> Self {
        Self::new()
    }
}

fn getrandom_salt(salt: &mut [u8; 16]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(salt);
}

/// Encrypt `plaintext` to a subscription, answering the body to POST.
///
/// `ua_public` is the subscription's `p256dh` and `auth` its auth
/// secret, both exactly as the browser handed them to the client.
pub fn encrypt(
    plaintext: &[u8],
    ua_public: &[u8; 65],
    auth: &[u8; 16],
    ephemeral: &Ephemeral,
) -> Result<Vec<u8>, EncryptError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(EncryptError::TooLong);
    }
    let ua = PublicKey::from_sec1_bytes(ua_public).map_err(|_| EncryptError::BadSubscriptionKey)?;
    let as_public = ephemeral.secret.public_key().to_encoded_point(false);
    let as_public: &[u8] = as_public.as_bytes();

    // The agreement, then the key derivation of §3.3: the shared secret
    // is extracted under the *auth secret* as salt, and expanded under
    // an info string that names both public keys — which is what binds
    // the result to this subscription and this message.
    let shared = p256::ecdh::diffie_hellman(ephemeral.secret.to_nonzero_scalar(), ua.as_affine());
    let mut key_info = Vec::with_capacity(14 + 1 + 65 + 65);
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes())
        .expand(&key_info, &mut ikm)
        .map_err(|_| EncryptError::Aead)?;

    // RFC 8188's two: the content-encryption key and the nonce, both out
    // of the random salt that travels in the header.
    let prk = Hkdf::<Sha256>::new(Some(&ephemeral.salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .and_then(|()| prk.expand(b"Content-Encoding: nonce\0", &mut nonce))
        .map_err(|_| EncryptError::Aead)?;

    // One record, so the delimiter is 2 ("last record") rather than 1.
    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    record.push(2);
    let sealed = Aes128Gcm::new_from_slice(&cek)
        .map_err(|_| EncryptError::Aead)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &record,
                aad: b"",
            },
        )
        .map_err(|_| EncryptError::Aead)?;

    // The RFC 8188 header: salt, record size, then the sender's public
    // key as the key id, which is how the user agent knows what to agree
    // against.
    let mut body = Vec::with_capacity(86 + sealed.len());
    body.extend_from_slice(&ephemeral.salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(as_public);
    body.extend_from_slice(&sealed);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine;

    fn b64(s: &str) -> Vec<u8> {
        B64.decode(s).unwrap()
    }

    /// [RFC 8291 §5], byte for byte. Every constant in this module is
    /// load-bearing and none of them is checkable by reading: a wrong
    /// info string produces a body that looks perfect and decrypts to
    /// nothing on a phone nobody is holding.
    ///
    /// [RFC 8291 §5]: https://www.rfc-editor.org/rfc/rfc8291#section-5
    #[test]
    fn the_rfc_8291_vector_reproduces_exactly() {
        let ua_public: [u8; 65] = b64("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
            .try_into()
            .unwrap();
        let auth: [u8; 16] = b64("BTBZMqHH6r4Tts7J_aSIgg").try_into().unwrap();
        let secret: [u8; 32] = b64("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
            .try_into()
            .unwrap();
        let salt: [u8; 16] = b64("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();

        let body = encrypt(
            b"When I grow up, I want to be a watermelon",
            &ua_public,
            &auth,
            &Ephemeral::fixed(secret, salt),
        )
        .unwrap();

        assert_eq!(
            B64.encode(&body),
            concat!(
                "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml",
                "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT",
                "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
            ),
            "the RFC's own body"
        );
    }

    #[test]
    fn a_subscription_key_that_is_not_one_is_refused() {
        let err = encrypt(b"hi", &[0; 65], &[0; 16], &Ephemeral::new()).unwrap_err();
        assert_eq!(err, EncryptError::BadSubscriptionKey);
    }

    #[test]
    fn a_plaintext_past_one_record_is_refused_rather_than_cut() {
        let long = vec![b'x'; MAX_PLAINTEXT + 1];
        assert_eq!(
            encrypt(&long, &[0; 65], &[0; 16], &Ephemeral::new()).unwrap_err(),
            EncryptError::TooLong,
            "and before the key is even looked at"
        );
    }
}
