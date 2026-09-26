//! Construction of the optional Files service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_files::{
    DownloadTokens, EntryLimits, FileService, HttpManifestSource, HtxfTimeouts, LocalFileSource,
    LocalLimits, ManifestLimits, TransferRegistry,
};

use crate::Config;

/// A validated Files service and the legacy transfer listener it requires.
pub struct Files {
    pub service: Arc<FileService>,
    pub bind: String,
    pub timeouts: HtxfTimeouts,
}

pub fn build(config: &Config) -> Result<Option<Files>, String> {
    let Some(section) = config.files.as_ref() else {
        return Ok(None);
    };
    let (source, uploads): (Arc<dyn hxd_core::FileSource>, Option<Arc<LocalFileSource>>) =
        match (&section.manifest, &section.origin, &section.root) {
            (Some(manifest_path), Some(origin), None) => {
                let manifest = std::fs::read(manifest_path)
                    .map_err(|error| format!("{}: {error}", manifest_path.display()))?;
                let source = HttpManifestSource::from_json(
                    origin,
                    &manifest,
                    ManifestLimits {
                        max_file_size: section.max_file_size,
                        max_entries: section.max_entries,
                        max_concurrent: section.max_concurrent,
                        request_timeout: Duration::from_secs(section.request_timeout),
                    },
                )
                .map_err(|error| format!("[files]: {error}"))?;
                (Arc::new(source), None)
            }
            (None, None, Some(root)) => {
                let local = Arc::new(
                    LocalFileSource::open(
                        root,
                        LocalLimits {
                            max_file_size: section.max_file_size,
                            max_entries: section.max_entries,
                            max_concurrent: section.max_concurrent,
                            max_partial_bytes: section.max_partial_bytes,
                            max_partials: section.max_partials,
                            max_partials_per_account: section.max_partials_per_account,
                            io_timeout: Duration::from_secs(section.request_timeout),
                            upload_timeout: Duration::from_secs(section.upload_timeout),
                            partial_ttl: Duration::from_secs(section.partial_ttl),
                        },
                    )
                    .map_err(|error| format!("[files]: {error}"))?,
                );
                (local.clone(), Some(local))
            }
            _ => {
                return Err(
                "[files] requires either root, or both manifest and origin, but never both modes"
                    .into(),
            );
            }
        };
    let bind = section
        .bind
        .clone()
        .map(Ok)
        .unwrap_or_else(|| transfer_bind(&config.server.bind))?;
    let idle = Duration::from_secs(section.idle_timeout);
    let service = Arc::new(FileService::new(
        source,
        uploads,
        Arc::new(TransferRegistry::new(
            Duration::from_secs(section.reference_ttl),
            EntryLimits {
                total: section.max_references,
                per_session: section.max_references_per_session,
                per_account: section.max_references_per_account,
            },
        )),
        Arc::new(DownloadTokens::new(
            Duration::from_secs(section.download_ttl),
            EntryLimits {
                total: section.max_downloads,
                per_session: section.max_downloads_per_session,
                per_account: section.max_downloads_per_account,
            },
        )),
        idle,
    ));
    Ok(Some(Files {
        service,
        bind,
        timeouts: HtxfTimeouts {
            handshake: Duration::from_secs(section.handshake_timeout),
            idle,
        },
    }))
}

/// The HTXF listener: where it binds, what it redeems, and how long it
/// waits.
pub struct Htxf {
    pub registry: Arc<TransferRegistry>,
    pub bind: String,
    pub timeouts: HtxfTimeouts,
}

/// Whether anything is fetched over HTXF: files, or a banner held here.
pub fn wants_htxf(config: &Config) -> bool {
    config.files.is_some() || config.banner.as_ref().is_some_and(|b| b.file.is_some())
}

/// The HTXF listener `[files]` configures, or — on a server whose only
/// transfer is its banner — one on the port a client derives from the
/// control port, with `[files]`'s defaults.
pub fn htxf(config: &Config, files: Option<&Files>) -> Result<Option<Htxf>, String> {
    if let Some(files) = files {
        return Ok(Some(Htxf {
            registry: files.service.transfers.clone(),
            bind: files.bind.clone(),
            timeouts: files.timeouts,
        }));
    }
    if !wants_htxf(config) {
        return Ok(None);
    }
    Ok(Some(Htxf {
        registry: Arc::new(TransferRegistry::new(
            Duration::from_secs(crate::default_files_reference_ttl()),
            EntryLimits {
                total: crate::default_files_max_references(),
                per_session: crate::default_files_max_references_per_session(),
                per_account: crate::default_files_max_references_per_account(),
            },
        )),
        bind: transfer_bind(&config.server.bind)?,
        timeouts: HtxfTimeouts {
            handshake: Duration::from_secs(crate::default_files_handshake_timeout()),
            idle: Duration::from_secs(crate::default_files_idle_timeout()),
        },
    }))
}

fn transfer_bind(control: &str) -> Result<String, String> {
    let mut address: SocketAddr = control.parse().map_err(|_| {
        "[files] bind is required when [server] bind is not a numeric socket address".to_string()
    })?;
    let port = address
        .port()
        .checked_add(1)
        .ok_or_else(|| "[server] bind port has no following HTXF port".to_string())?;
    address.set_port(port);
    Ok(address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_banner_file_opens_a_transfer_listener_without_files() {
        let config = |toml: &str| -> Config { toml::from_str(toml).unwrap() };
        let banner = config("[server]\nbind = \"127.0.0.1:5500\"\n[banner]\nfile = \"b.gif\"\n");
        assert_eq!(htxf(&banner, None).unwrap().unwrap().bind, "127.0.0.1:5501");
        // A banner fetched from its URL transfers nothing here.
        let url = config("[banner]\nurl = \"https://hl.example/b.gif\"\n");
        assert!(htxf(&url, None).unwrap().is_none());
        assert!(htxf(&config(""), None).unwrap().is_none());
    }

    #[test]
    fn transfer_listener_follows_the_control_port() {
        assert_eq!(transfer_bind("127.0.0.1:5500").unwrap(), "127.0.0.1:5501");
        assert_eq!(
            transfer_bind("[::1]:65535").unwrap_err(),
            "[server] bind port has no following HTXF port"
        );
    }
}
