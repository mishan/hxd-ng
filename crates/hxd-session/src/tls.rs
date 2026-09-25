//! TLS on the legacy wire: a dedicated port, TLS from byte zero, and the
//! ordinary Hotline protocol inside it, unchanged.
//!
//! There is no in-band negotiation in Hotline — no STARTTLS, no flag, no
//! opcode. A server that speaks TLS listens on a second port (5600 by
//! convention, the transfer port one above it), a client that connects
//! there handshakes at once, and everything after that is the same
//! bytes the plaintext port carries. That is the model GtkHx, Janus and
//! Mobius share, and the reason an `stunnel` in front of any server was
//! always an option: nothing here reaches past the stream.
//!
//! Trust is the client's business. Most Hotline servers are reached by
//! an address rather than a name and cannot hold a CA-issued
//! certificate, so clients pin the first one they see; the fingerprint
//! logged at load is what an operator publishes for them to compare.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// The certificate the TLS ports present, reloadable in place.
///
/// A reload swaps what the next handshake presents; a session already
/// up keeps the keys it negotiated, so renewing a certificate drops
/// nobody.
pub struct LegacyTls {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<Loaded>,
}

struct Loaded {
    config: Arc<ServerConfig>,
    fingerprint: String,
}

impl LegacyTls {
    /// Read a PEM certificate chain (leaf first) and its private key.
    pub fn load(cert: &Path, key: &Path) -> Result<Self, String> {
        let loaded = load(cert, key)?;
        Ok(Self {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
            current: RwLock::new(loaded),
        })
    }

    /// Re-read the files [`LegacyTls::load`] was given. On an error the
    /// certificate in use stays in use.
    pub fn reload(&self) -> Result<(), String> {
        let loaded = load(&self.cert, &self.key)?;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = loaded;
        Ok(())
    }

    /// An acceptor for one connection, holding the certificate current
    /// when it was taken.
    pub fn acceptor(&self) -> TlsAcceptor {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        TlsAcceptor::from(current.config.clone())
    }

    /// The leaf certificate's SHA-256, as `sha256:` and lowercase hex —
    /// the form a client's pin store (GtkHx's `known_hosts`) shows.
    pub fn fingerprint(&self) -> String {
        let current = self.current.read().unwrap_or_else(|e| e.into_inner());
        current.fingerprint.clone()
    }
}

fn load(cert_path: &Path, key_path: &Path) -> Result<Loaded, String> {
    let pem = std::fs::read(cert_path).map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", cert_path.display()))?;
    let Some(leaf) = chain.first() else {
        return Err(format!("{}: no PEM certificate", cert_path.display()));
    };
    let fingerprint = format!("sha256:{}", hex(&Sha256::digest(leaf.as_ref())));
    let pem = std::fs::read(key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    let key = PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|e| format!("{}: no usable PEM private key: {e}", key_path.display()))?;
    // The provider is named rather than taken from the process default:
    // more than one is linked into this binary, and rustls refuses to
    // guess between them.
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("{} and {}: {e}", cert_path.display(), key_path.display()))?;
    Ok(Loaded {
        config: Arc::new(config),
        fingerprint,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "hxd-tls-{name}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Dir(path)
        }

        /// A fresh self-signed pair, written as `cert.pem` / `key.pem`.
        fn issue(&self) -> (PathBuf, PathBuf) {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let (c, k) = (self.0.join("cert.pem"), self.0.join("key.pem"));
            std::fs::write(&c, cert.cert.pem()).unwrap();
            std::fs::write(&k, cert.signing_key.serialize_pem()).unwrap();
            (c, k)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn loads_a_pair_and_names_its_fingerprint() {
        let dir = Dir::new("load");
        let (cert, key) = dir.issue();
        let tls = LegacyTls::load(&cert, &key).unwrap();
        let fp = tls.fingerprint();
        assert!(fp.starts_with("sha256:"), "{fp}");
        assert_eq!(fp.len(), "sha256:".len() + 64);
    }

    #[test]
    fn reload_swaps_the_certificate_and_a_bad_one_keeps_the_old() {
        let dir = Dir::new("reload");
        let (cert, key) = dir.issue();
        let tls = LegacyTls::load(&cert, &key).unwrap();
        let first = tls.fingerprint();
        dir.issue();
        tls.reload().unwrap();
        let second = tls.fingerprint();
        assert_ne!(first, second);
        std::fs::write(&key, "not a key").unwrap();
        assert!(tls.reload().is_err());
        assert_eq!(tls.fingerprint(), second);
    }

    #[test]
    fn refuses_what_is_not_a_usable_pair() {
        let dir = Dir::new("refuse");
        let (cert, key) = dir.issue();
        let missing = dir.0.join("missing.pem");
        assert!(LegacyTls::load(&missing, &key).is_err());
        // A key file holds no certificate.
        let err = LegacyTls::load(&key, &key).err().unwrap();
        assert!(err.contains("no PEM certificate"), "{err}");
        // A certificate file holds no key.
        assert!(LegacyTls::load(&cert, &cert).is_err());
        // Another pair's key does not match this certificate.
        let other = Dir::new("refuse-other");
        let (_, other_key) = other.issue();
        assert!(LegacyTls::load(&cert, &other_key).is_err());
    }
}
