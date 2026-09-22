//! The server's push credential: a P-256 keypair, and the signed token
//! that proves a push came from it (RFC 8292).
//!
//! **This keypair is the server's identity to every push service its
//! users subscribed through.** A subscription is bound to the key it was
//! made with, so losing the file invalidates every registration on the
//! server and replacing it silently is indistinguishable from an outage:
//! the pushes are accepted by nobody and no client learns why. Hence
//! [`Vapid::load_or_create`], which creates only what is absent — and
//! only when the caller says an absent key really is a first start —
//! and refuses a file it cannot read rather than minting a second key
//! beside it; and [`Vapid::rekey`], the one deliberate replacement.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use sha2::{Digest, Sha256};

/// How long a signed token is good for. RFC 8292 caps it at 24 hours;
/// half that leaves room for a clock that disagrees with a push
/// service's without ever presenting a token it will refuse as stale.
pub const TOKEN_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Debug)]
pub enum VapidError {
    /// The file is there and is not a key, which is the one case that
    /// must never be answered by generating a new one.
    Unreadable(String),
    /// There is no key and the caller said there should be: devices are
    /// registered against a key this server no longer has. A deleted
    /// file and a changed `vapid_key` path look exactly like a first
    /// start, and minting a key here would invalidate every one of them.
    Missing(String),
    Io(String),
    /// `sub` is neither a `mailto:` nor an `https:` URL. A push service
    /// may refuse a token without a usable contact, so this is refused
    /// at startup rather than discovered per push.
    BadContact,
}

impl std::fmt::Display for VapidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VapidError::Unreadable(e) => write!(f, "the VAPID key is not a key: {e}"),
            VapidError::Missing(path) => write!(
                f,
                "{path} does not exist, and devices are registered against the key \
                 that was there. Restore it, point [push] vapid_key at it, or run \
                 `hxd push rekey` to start over with a new key and no devices"
            ),
            VapidError::Io(e) => write!(f, "the VAPID key file: {e}"),
            VapidError::BadContact => {
                write!(f, "[push] contact must be a mailto: or https: URL")
            }
        }
    }
}

/// The keypair, and the contact a push service can reach an operator at.
pub struct Vapid {
    key: SigningKey,
    /// Uncompressed SEC1, base64url: what the login reply offers and
    /// what rides in every `Authorization` header's `k=`.
    public_b64: String,
    contact: String,
    /// The `Topic` HMAC key: derived from the private key, so it needs no
    /// file of its own and changes exactly when the key does.
    topic_key: [u8; 32],
}

impl Vapid {
    /// Read the key at `path`, or create one there on first start.
    ///
    /// `first_start` is the caller's word that an absent file is a first
    /// start — in the server, that the device registry is empty. Without
    /// it an absent key is [`VapidError::Missing`] rather than a new one.
    ///
    /// The file is the operator's: PEM, mode `0600`, and never served.
    pub fn load_or_create(
        path: &Path,
        contact: &str,
        first_start: bool,
    ) -> Result<Self, VapidError> {
        check_contact(contact)?;
        let key = match fs::read_to_string(path) {
            Ok(pem) => SecretKey::from_sec1_pem(pem.trim())
                .map_err(|e| VapidError::Unreadable(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !first_start {
                    return Err(VapidError::Missing(path.display().to_string()));
                }
                let key = SecretKey::random(&mut rand_core::OsRng);
                write_private(path, &key, false)?;
                key
            }
            Err(e) => return Err(VapidError::Io(e.to_string())),
        };
        Ok(Self::of(&key, contact))
    }

    /// Replace the key at `path` with a new one, atomically: a reader
    /// sees the old file or the new one, never half of either. Every
    /// subscription made against the old key is dead from this moment,
    /// so the caller drops the device rows in the same step
    /// (`docs/webpush-gateway.md` §3).
    pub fn rekey(path: &Path, contact: &str) -> Result<Self, VapidError> {
        check_contact(contact)?;
        let key = SecretKey::random(&mut rand_core::OsRng);
        write_private(path, &key, true)?;
        Ok(Self::of(&key, contact))
    }

    fn of(key: &SecretKey, contact: &str) -> Self {
        let public = key.public_key().to_encoded_point(false);
        let mut h = Sha256::new();
        h.update(b"hxd-ng/push/topic/v1\0");
        h.update(key.to_bytes());
        Vapid {
            key: SigningKey::from(key),
            public_b64: B64.encode(public.as_bytes()),
            contact: contact.to_string(),
            topic_key: h.finalize().into(),
        }
    }

    /// The secret the `Topic` header is an HMAC under
    /// (`docs/webpush-gateway.md` §4).
    pub fn topic_key(&self) -> [u8; 32] {
        self.topic_key
    }

    /// The public key a client subscribes against, base64url.
    pub fn public_key(&self) -> &str {
        &self.public_b64
    }

    /// The `Authorization` header value for a push to `origin`, valid
    /// from `now`.
    ///
    /// `origin` is the endpoint's origin as [`origin_of`] serializes it
    /// — a token whose `aud` carried the path would name a different
    /// audience per subscription.
    pub fn authorization(&self, origin: &str, now: SystemTime) -> String {
        format!("vapid t={}, k={}", self.token(origin, now), self.public_b64)
    }

    fn token(&self, origin: &str, now: SystemTime) -> String {
        let exp = now
            .checked_add(TOKEN_LIFETIME)
            .unwrap_or(now)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Hand-built rather than through a JWT crate: two fixed fields
        // and three known ones, and the crate would bring its own
        // opinions about algorithms we do not want to be able to select.
        let header = B64.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = B64.encode(
            serde_json::json!({
                "aud": origin,
                "exp": exp,
                "sub": self.contact,
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        // ES256 is the raw `r || s` pair, not the DER encoding an
        // `ecdsa` crate hands out by default. A DER signature here is
        // accepted by nobody and looks entirely plausible in a log.
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64.encode(signature.to_bytes()))
    }
}

fn check_contact(contact: &str) -> Result<(), VapidError> {
    if contact.starts_with("mailto:") || contact.starts_with("https://") {
        Ok(())
    } else {
        Err(VapidError::BadContact)
    }
}

/// Write a key whole or not at all, with an owner-only mode from the
/// moment it exists.
///
/// Into a file of its own beside `path` first, created `0600` rather
/// than chmod'ed after — between the two there would be a private key
/// anyone can read — and synced; then linked into place. A crash
/// between creating and writing leaves a stray temporary file, never a
/// half-written key at `path` that the next start refuses to read. A
/// first key is hard-linked, so a key that appeared meanwhile is kept
/// rather than overwritten; a rekey renames over the old one.
fn write_private(path: &Path, key: &SecretKey, replace: bool) -> Result<(), VapidError> {
    let io = |e: std::io::Error| VapidError::Io(format!("{}: {e}", path.display()));
    let pem = key
        .to_sec1_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| VapidError::Unreadable(e.to_string()))?;
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut nonce = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", B64.encode(nonce)));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(pem.as_bytes())?;
        file.sync_all()
    });
    let placed = written.and_then(|()| {
        if replace {
            fs::rename(&tmp, path)
        } else {
            let linked = fs::hard_link(&tmp, path);
            let _ = fs::remove_file(&tmp);
            linked
        }
    });
    if placed.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    placed.map_err(io)?;
    // The directory entry is what makes the file findable after a crash.
    #[cfg(unix)]
    fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)?;
    Ok(())
}

/// An endpoint's origin as RFC 6454 serializes it, which is a token's
/// audience: the scheme and host lowercased, and the port only where it
/// is not the scheme's default. `None` for anything that is not an
/// absolute URL with a host — which [`crate::endpoint`] has already
/// refused by the time a push is sent, and which is checked again here
/// because a token signed for the wrong audience is a silent rejection
/// later.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
    if authority.is_empty() {
        return None;
    }
    let default = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let authority = match authority.strip_suffix(default) {
        // `[::1]:443` keeps its bracket, `host:443` loses the port, and
        // a bare IPv6 tail like `…::443` is not a port at all.
        Some(host) if !default.is_empty() && (host.ends_with(']') || !host.contains(':')) => {
            host.to_string()
        }
        _ => authority,
    };
    (!authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::VerifyingKey;
    use p256::PublicKey;

    fn vapid(dir: &Path) -> Vapid {
        Vapid::load_or_create(&dir.join("vapid.key"), "mailto:admin@example.org", true).unwrap()
    }

    /// The token this signs is verifiable with the key it advertises,
    /// and says what RFC 8292 §2 requires it to say. A push service is
    /// the only other thing that checks, and it does so silently.
    #[test]
    fn a_token_verifies_under_the_advertised_key() {
        let dir = tempdir();
        let v = vapid(dir.path());
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let header = v.authorization("https://push.example.net", now);

        let (t, k) = header
            .strip_prefix("vapid t=")
            .unwrap()
            .split_once(", k=")
            .unwrap();
        assert_eq!(k, v.public_key());
        let mut parts = t.split('.');
        let (h, c, s) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        assert!(parts.next().is_none(), "three parts, no more");

        assert_eq!(
            String::from_utf8(B64.decode(h).unwrap()).unwrap(),
            r#"{"typ":"JWT","alg":"ES256"}"#
        );
        let claims: serde_json::Value = serde_json::from_slice(&B64.decode(c).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://push.example.net");
        assert_eq!(claims["sub"], "mailto:admin@example.org");
        assert_eq!(claims["exp"], 1_700_000_000 + 12 * 60 * 60);

        let signature = B64.decode(s).unwrap();
        assert_eq!(signature.len(), 64, "raw r||s, never DER");
        let public = PublicKey::from_sec1_bytes(&B64.decode(v.public_key()).unwrap()).unwrap();
        VerifyingKey::from(public)
            .verify(
                format!("{h}.{c}").as_bytes(),
                &Signature::from_slice(&signature).unwrap(),
            )
            .expect("a push service can check this");
    }

    /// RFC 8292 §2.4's own example, checked the way a push service
    /// checks ours — so a verification path that would accept anything
    /// is caught here rather than trusted above.
    #[test]
    fn the_rfc_8292_example_verifies() {
        let token = concat!(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5u",
            "ZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb",
            "7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvo",
            "D1oA"
        );
        let k = "BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs";
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let public = PublicKey::from_sec1_bytes(&B64.decode(k).unwrap()).unwrap();
        VerifyingKey::from(public)
            .verify(
                signed.as_bytes(),
                &Signature::from_slice(&B64.decode(signature).unwrap()).unwrap(),
            )
            .expect("the RFC's own token");
    }

    #[test]
    fn a_key_is_created_once_and_then_read() {
        let dir = tempdir();
        let first = vapid(dir.path()).public_key().to_string();
        assert_eq!(
            vapid(dir.path()).public_key(),
            first,
            "a second start must not mint a second key"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("vapid.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "nobody else reads a private key");
        }
    }

    #[test]
    fn a_file_that_is_not_a_key_is_refused_rather_than_replaced() {
        let dir = tempdir();
        let path = dir.path().join("vapid.key");
        fs::write(&path, "not a key").unwrap();
        let err = Vapid::load_or_create(&path, "mailto:a@example.org", true)
            .err()
            .expect("a file that is not a key is an error");
        assert!(matches!(err, VapidError::Unreadable(_)), "{err}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "not a key",
            "and the operator's file is still there to look at"
        );
    }

    #[test]
    fn a_contact_a_push_service_cannot_use_is_refused_at_startup() {
        let dir = tempdir();
        let refused = Vapid::load_or_create(&dir.path().join("v.key"), "admin@example.org", true);
        assert!(matches!(refused.err(), Some(VapidError::BadContact)));
        assert!(
            !dir.path().join("v.key").exists(),
            "and nothing was written"
        );
    }

    #[test]
    fn an_origin_is_the_scheme_and_authority() {
        assert_eq!(
            origin_of("https://push.example.net/v/123?x=1").as_deref(),
            Some("https://push.example.net")
        );
        assert_eq!(
            origin_of("https://push.example.net").as_deref(),
            Some("https://push.example.net")
        );
        assert_eq!(origin_of("push.example.net/v/1"), None);
        assert_eq!(origin_of("https:///v/1"), None);
        assert_eq!(
            origin_of("https://Push.Example.NET:443/v").as_deref(),
            Some("https://push.example.net"),
            "RFC 6454: lowercase, and no default port"
        );
        assert_eq!(
            origin_of("https://push.example.net:8443/v").as_deref(),
            Some("https://push.example.net:8443")
        );
        assert_eq!(
            origin_of("https://[2606:4700::1]:443/v").as_deref(),
            Some("https://[2606:4700::1]")
        );
    }

    #[test]
    fn a_missing_key_is_not_a_first_start_when_devices_say_otherwise() {
        let dir = tempdir();
        let path = dir.path().join("vapid.key");
        let err = Vapid::load_or_create(&path, "mailto:a@example.org", false)
            .err()
            .expect("no key, and not a first start");
        assert!(matches!(err, VapidError::Missing(_)), "{err}");
        assert!(!path.exists(), "and nothing was minted");
    }

    #[test]
    fn a_rekey_replaces_the_key_and_nothing_else() {
        let dir = tempdir();
        let old = vapid(dir.path());
        let new = Vapid::rekey(&dir.path().join("vapid.key"), "mailto:a@example.org").unwrap();
        assert_ne!(old.public_key(), new.public_key());
        assert_ne!(old.topic_key(), new.topic_key(), "the Topic key follows it");
        assert_eq!(
            vapid(dir.path()).public_key(),
            new.public_key(),
            "and the next start reads the new one"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("vapid.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary file is left behind"
        );
    }

    /// A directory that cleans itself up, so this crate needs no
    /// `tempfile` for four tests.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tempdir() -> TempDir {
        let mut n = [0u8; 8];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut n);
        let dir = std::env::temp_dir().join(format!("hxd-vapid-{}", B64.encode(n)));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}
