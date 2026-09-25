//! `[tls]`: the legacy wire over TLS, on ports of its own.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use hxd_session::LegacyTls;
use serde::Deserialize;

use crate::Config;

/// A TLS control port beside the plaintext one, and a TLS transfer port
/// beside the plaintext HTXF one when there are files. Nothing inside
/// the stream differs from the plaintext ports, so every legacy feature
/// works on both.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    /// The TLS control listener.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// PEM certificate chain, leaf first. Required, and best issued by
    /// a public CA — Let's Encrypt, for a server with a DNS name — so a
    /// client can check it without asking its user anything.
    pub cert: PathBuf,
    /// The certificate's PEM private key.
    pub key: PathBuf,
    /// Make a self-signed pair at `cert` and `key` on the first start
    /// that finds neither, and keep using it after. Off by default: a
    /// client can only pin a self-signed certificate on first sight, so
    /// it is for servers with no name a CA will certify, and the pin is
    /// only as good as the fingerprint its users compare it against.
    #[serde(default)]
    pub self_signed: bool,
    /// The TLS transfer listener, when `[files]` is on. Omitted means
    /// the TLS control port plus one, which is where GtkHx looks: it
    /// derives the transfer port rather than asking, so a port anywhere
    /// else is one its downloads will not find.
    pub files_bind: Option<String>,
}

fn default_bind() -> String {
    "0.0.0.0:5600".into()
}

/// The loaded certificate and the addresses it is served on.
pub struct Tls {
    pub tls: Arc<LegacyTls>,
    pub bind: String,
    /// Present exactly when `[files]` is.
    pub files_bind: Option<String>,
}

pub fn check(config: &Config) -> Result<(), String> {
    let Some(section) = config.tls.as_ref() else {
        return Ok(());
    };
    if section.files_bind.is_some() && config.files.is_none() {
        return Err(
            "[tls] files_bind needs [files]: there are no transfers to carry without it".into(),
        );
    }
    Ok(())
}

pub fn build(config: &Config) -> Result<Option<Tls>, String> {
    let Some(section) = config.tls.as_ref() else {
        return Ok(None);
    };
    check(config)?;
    if section.self_signed {
        provision(section, &config.server.name)?;
    }
    let tls = LegacyTls::load(&section.cert, &section.key).map_err(|e| format!("[tls] {e}"))?;
    let files_bind = match (&config.files, &section.files_bind) {
        (None, _) => None,
        (Some(_), Some(bind)) => Some(bind.clone()),
        (Some(_), None) => Some(transfer_bind(&section.bind)?),
    };
    Ok(Some(Tls {
        tls: Arc::new(tls),
        bind: section.bind.clone(),
        files_bind,
    }))
}

/// The self-signed pair, made once. Both files present is the pair a
/// previous start made (or the operator's, replacing it); one without
/// the other is refused rather than overwritten, since the one that is
/// there may be the half someone meant to keep.
fn provision(section: &TlsSection, server_name: &str) -> Result<(), String> {
    match (section.cert.exists(), section.key.exists()) {
        (true, true) => return Ok(()),
        (false, false) => {}
        (true, false) | (false, true) => {
            return Err(format!(
                "[tls] self_signed: one of {} and {} exists without the other; \
                 remove it to have a new pair made, or supply both",
                section.cert.display(),
                section.key.display()
            ))
        }
    }
    let (cert, key) = self_signed(server_name)?;
    // The key first and owner-only; a start that dies between the two
    // writes leaves the one-without-the-other case above, not a
    // certificate whose key is gone.
    crate::write_private(&section.key, &key)
        .map_err(|e| format!("[tls] {}: {e}", section.key.display()))?;
    std::fs::write(&section.cert, cert)
        .map_err(|e| format!("[tls] {}: {e}", section.cert.display()))?;
    tracing::warn!(
        "[tls] made a self-signed certificate at {}: clients will ask their users to \
         trust it on first connect. A certificate from Let's Encrypt avoids that for a \
         server with a DNS name (README, \"TLS on the legacy wire\")",
        section.cert.display()
    );
    Ok(())
}

/// A certificate naming the server, for the prompt a client shows. The
/// subject alternative name is `localhost` because a pinned certificate
/// is checked by fingerprint, not by name, and an address is not known
/// here to be the one clients use.
fn self_signed(server_name: &str) -> Result<(String, String), String> {
    let key = rcgen::KeyPair::generate().map_err(|e| format!("[tls] self_signed: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .map_err(|e| format!("[tls] self_signed: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, server_name);
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("[tls] self_signed: {e}"))?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn transfer_bind(control: &str) -> Result<String, String> {
    let mut address: SocketAddr = control.parse().map_err(|_| {
        "[tls] files_bind is required when [tls] bind is not a numeric socket address".to_string()
    })?;
    let port = address
        .port()
        .checked_add(1)
        .ok_or_else(|| "[tls] bind port has no following HTXF port".to_string())?;
    address.set_port(port);
    Ok(address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_listener_follows_the_tls_control_port() {
        assert_eq!(transfer_bind("0.0.0.0:5600").unwrap(), "0.0.0.0:5601");
        assert_eq!(
            transfer_bind("[::1]:65535").unwrap_err(),
            "[tls] bind port has no following HTXF port"
        );
        assert!(transfer_bind("localhost:5600").is_err());
    }

    #[test]
    fn files_bind_without_files_does_nothing_so_it_is_refused() {
        let config: Config = toml::from_str(
            "[tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nfiles_bind = \"0.0.0.0:5611\"\n",
        )
        .unwrap();
        assert!(check(&config).unwrap_err().contains("needs [files]"));
        let config: Config = toml::from_str("[tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\n").unwrap();
        let section = config.tls.as_ref().unwrap();
        assert_eq!(section.bind, "0.0.0.0:5600");
        check(&config).unwrap();
    }

    #[test]
    fn self_signed_makes_a_pair_once_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let config: Config = toml::from_str(&format!(
            "[server]\nname = \"Pinned\"\n[tls]\ncert = \"{0}/cert.pem\"\nkey = \"{0}/key.pem\"\n\
             self_signed = true\n",
            dir.path().display()
        ))
        .unwrap();
        let first = build(&config).unwrap().unwrap().tls.fingerprint();
        let again = build(&config).unwrap().unwrap().tls.fingerprint();
        assert_eq!(
            first, again,
            "a restart presents the certificate clients pinned"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "the key is the owner's alone");
        }
        std::fs::remove_file(dir.path().join("key.pem")).unwrap();
        let err = build(&config).err().unwrap();
        assert!(err.contains("without the other"), "{err}");
    }

    #[test]
    fn without_self_signed_a_missing_certificate_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config: Config = toml::from_str(&format!(
            "[tls]\ncert = \"{0}/cert.pem\"\nkey = \"{0}/key.pem\"\n",
            dir.path().display()
        ))
        .unwrap();
        assert!(build(&config).is_err());
        assert!(
            !dir.path().join("key.pem").exists(),
            "nothing is made unasked"
        );
    }

    #[test]
    fn a_tls_section_names_its_certificate() {
        let err = toml::from_str::<Config>("[tls]\nbind = \"0.0.0.0:5600\"\n").unwrap_err();
        assert!(err.to_string().contains("cert"), "{err}");
    }
}
