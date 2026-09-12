//! Construction of the optional Files service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_files::{
    DownloadTokens, FileService, HttpManifestSource, LocalFileSource, LocalLimits, ManifestLimits,
    TransferRegistry,
};

use crate::Config;

/// A validated Files service and the legacy transfer listener it requires.
pub struct Files {
    pub service: Arc<FileService>,
    pub bind: String,
    pub handshake_timeout: Duration,
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
    let service = Arc::new(FileService::new(
        source,
        uploads,
        Arc::new(TransferRegistry::new(Duration::from_secs(
            section.reference_ttl,
        ))),
        Arc::new(DownloadTokens::new(Duration::from_secs(
            section.download_ttl,
        ))),
    ));
    Ok(Some(Files {
        service,
        bind,
        handshake_timeout: Duration::from_secs(section.handshake_timeout),
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
    fn transfer_listener_follows_the_control_port() {
        assert_eq!(transfer_bind("127.0.0.1:5500").unwrap(), "127.0.0.1:5501");
        assert_eq!(
            transfer_bind("[::1]:65535").unwrap_err(),
            "[server] bind port has no following HTXF port"
        );
    }
}
