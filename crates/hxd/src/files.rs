//! Construction of the optional read-only Files service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hxd_files::{
    DownloadTokens, FileService, HttpManifestSource, ManifestLimits, TransferRegistry,
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
    let manifest = std::fs::read(&section.manifest)
        .map_err(|error| format!("{}: {error}", section.manifest.display()))?;
    let source = HttpManifestSource::from_json(
        &section.origin,
        &manifest,
        ManifestLimits {
            max_file_size: section.max_file_size,
            max_entries: section.max_entries,
            max_concurrent: section.max_concurrent,
            request_timeout: Duration::from_secs(section.request_timeout),
        },
    )
    .map_err(|error| format!("[files]: {error}"))?;
    let bind = section
        .bind
        .clone()
        .map(Ok)
        .unwrap_or_else(|| transfer_bind(&config.server.bind))?;
    let service = Arc::new(FileService::new(
        Arc::new(source),
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
