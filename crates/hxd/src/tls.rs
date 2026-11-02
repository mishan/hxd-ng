//! `[tls]`: the legacy wire over TLS, on ports of its own.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hxd_session::LegacyTls;
use serde::Deserialize;

use crate::Config;

/// A TLS control port beside the plaintext one, and a TLS transfer port
/// beside the plaintext HTXF one when there are files or a banner file. Nothing inside
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
    /// The TLS transfer listener, when `[files]` is on or `[banner]` has
    /// a file. Omitted means
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
    /// Present exactly when there is a plaintext HTXF listener.
    pub files_bind: Option<String>,
}

pub fn check(config: &Config) -> Result<(), String> {
    let Some(section) = config.tls.as_ref() else {
        if config
            .tracker
            .as_ref()
            .is_some_and(|t| t.advertised_tls_port.is_some())
        {
            return Err(
                "[tracker] advertised_tls_port needs [tls]: there is no TLS port to \
                 advertise without it"
                    .into(),
            );
        }
        return Ok(());
    };
    // One file can hold both halves of an operator's pair, but a pair
    // made here would write the certificate over the key it belongs to.
    if section.self_signed && section.cert == section.key {
        return Err("[tls] self_signed needs cert and key to be two different files".into());
    }
    if section.files_bind.is_some() && !crate::files::wants_htxf(config) {
        return Err(
            "[tls] files_bind needs [files] or a [banner] file: there are no transfers \
             to carry without one"
                .into(),
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
    let tls = LegacyTls::load(&section.cert, &section.key).map_err(|e| {
        if section.self_signed {
            format!("[tls] {e}; remove both files to have a new self-signed pair made")
        } else {
            format!("[tls] {e}")
        }
    })?;
    let files_bind = match (crate::files::wants_htxf(config), &section.files_bind) {
        (false, _) => None,
        (true, Some(bind)) => Some(bind.clone()),
        (true, None) => Some(transfer_bind(&section.bind)?),
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
    place(section, &cert, &key, Duration::from_secs(5))
}

/// Write the pair made for `section`.
fn place(section: &TlsSection, cert: &str, key: &str, wait: Duration) -> Result<(), String> {
    // Each file lands whole or not at all, and the key first: a start
    // that dies between the two leaves the one-without-the-other case
    // above, never a truncated file beside a complete one. A start that
    // finds a key placed meanwhile waits for the certificate of the
    // start that placed it, which is the one its key pairs with.
    if !write_new(&section.key, key.as_bytes())? {
        let deadline = std::time::Instant::now() + wait;
        while !section.cert.exists() {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "[tls] self_signed: another start placed {} and has not yet written {}; \
                     start again once it has",
                    section.key.display(),
                    section.cert.display()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        return Ok(());
    }
    write_new(&section.cert, cert.as_bytes())?;
    tracing::warn!(
        "[tls] made a self-signed certificate at {}: clients will ask their users to \
         trust it on first connect. A certificate from Let's Encrypt avoids that for a \
         server with a DNS name (docs/operating.md, \"TLS on the classic wire\")",
        section.cert.display()
    );
    Ok(())
}

/// Write `bytes` to `path` owner-only, unless a file is there already,
/// making the directory (owner-only) if it is not there yet.
fn write_new(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    let fail = |e: std::io::Error| format!("[tls] {}: {e}", path.display());
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if !dir.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir).map_err(fail)?;
    }
    hl_private_file::create(path, bytes).map_err(fail)
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
    // Port 0 is the system's choice, and the port after it is not one.
    if address.port() == 0 {
        return Err("[tls] files_bind is required when [tls] bind's port is 0".into());
    }
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
        assert!(transfer_bind("127.0.0.1:0").is_err());
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
    fn a_banner_file_is_a_transfer_the_tls_port_carries() {
        let config: Config = toml::from_str(
            "[tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nfiles_bind = \"0.0.0.0:5611\"\n\
             [banner]\nfile = \"b.gif\"\n",
        )
        .unwrap();
        check(&config).unwrap();
        let config: Config = toml::from_str(
            "[tls]\ncert = \"c.pem\"\nkey = \"k.pem\"\nfiles_bind = \"0.0.0.0:5611\"\n\
             [banner]\nurl = \"https://hl.example/b.gif\"\n",
        )
        .unwrap();
        assert!(check(&config).unwrap_err().contains("needs [files]"));
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
        // A pair that is there but unusable says how to start over.
        std::fs::write(dir.path().join("key.pem"), "truncated").unwrap();
        let err = build(&config).err().unwrap();
        assert!(err.contains("remove both files"), "{err}");
    }

    /// Under the longest names a directory entry can have, both files
    /// owner-only and nothing left beside them.
    #[test]
    fn self_signed_makes_the_directory_it_writes_into() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = (
            format!("{}.pem", "c".repeat(251)),
            format!("{}.pem", "k".repeat(251)),
        );
        let config: Config = toml::from_str(&format!(
            "[tls]\ncert = \"{0}/tls/{cert}\"\nkey = \"{0}/tls/{key}\"\nself_signed = true\n",
            dir.path().display()
        ))
        .unwrap();
        build(&config).unwrap();
        #[cfg(unix)]
        for name in [&cert, &key] {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(dir.path().join("tls").join(name)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
        }
        assert_eq!(
            std::fs::read_dir(dir.path().join("tls")).unwrap().count(),
            2
        );
    }

    /// A start that finds the key another start has just placed waits
    /// for that start's certificate, and if it never comes says so,
    /// rather than offering to remove a pair that is the other start's.
    #[test]
    fn a_start_that_loses_the_race_waits_for_the_winners_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let config: Config = toml::from_str(&format!(
            "[tls]\ncert = \"{0}/cert.pem\"\nkey = \"{0}/key.pem\"\nself_signed = true\n",
            dir.path().display()
        ))
        .unwrap();
        let section = config.tls.as_ref().unwrap();
        std::fs::write(&section.key, "theirs").unwrap();
        let err = place(section, "mine", "mine", Duration::from_millis(200)).unwrap_err();
        assert!(
            err.contains("another start") && !err.contains("remove"),
            "{err}"
        );
        assert!(!section.cert.exists());

        let cert = section.cert.clone();
        let winner = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            std::fs::write(cert, "theirs").unwrap();
        });
        place(section, "mine", "mine", Duration::from_secs(5)).unwrap();
        winner.join().unwrap();
        for path in [&section.cert, &section.key] {
            assert_eq!(std::fs::read_to_string(path).unwrap(), "theirs");
        }
    }

    #[test]
    fn self_signed_refuses_one_file_for_both_halves() {
        let config: Config =
            toml::from_str("[tls]\ncert = \"pair.pem\"\nkey = \"pair.pem\"\nself_signed = true\n")
                .unwrap();
        assert!(check(&config).unwrap_err().contains("two different files"));
        // Without self_signed, one file holding both is an operator's
        // choice and not this check's business.
        let config: Config =
            toml::from_str("[tls]\ncert = \"pair.pem\"\nkey = \"pair.pem\"\n").unwrap();
        check(&config).unwrap();
    }

    #[test]
    fn an_advertised_tls_port_without_tls_is_refused() {
        let config: Config = toml::from_str(
            "[tracker]\nadvertised_tls_port = 5600\n[[tracker.targets]]\naddress = \"t.example\"\n\
             protocol = \"v3\"\n",
        )
        .unwrap();
        assert!(check(&config)
            .unwrap_err()
            .contains("advertised_tls_port needs [tls]"));
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
