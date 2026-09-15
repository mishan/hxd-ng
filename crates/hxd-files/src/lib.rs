//! Read-only manifest-backed HTTP files and transfer authorization.

mod manifest;
mod registry;
mod transfer;

pub use manifest::{HttpManifestSource, ManifestLimits};
pub use registry::{
    DownloadGrant, DownloadTokens, EntryLimits, PreparedTransfer, TransferRegistry,
};
pub use transfer::{prepare_legacy, pump, serve_htxf, HtxfTimeouts, LegacyTransfer, Liveness};

use std::sync::Arc;
use std::time::Duration;

use hxd_core::FileSource;

/// The shared Files service mounted by both protocol frontends.
#[derive(Clone)]
pub struct FileService {
    pub source: Arc<dyn FileSource>,
    pub transfers: Arc<TransferRegistry>,
    pub downloads: Arc<DownloadTokens>,
    /// How long a download may make no progress toward its receiver, on
    /// either wire, before it is abandoned.
    pub idle_timeout: Duration,
}

impl FileService {
    pub fn new(
        source: Arc<dyn FileSource>,
        transfers: Arc<TransferRegistry>,
        downloads: Arc<DownloadTokens>,
        idle_timeout: Duration,
    ) -> Self {
        FileService {
            source,
            transfers,
            downloads,
            idle_timeout,
        }
    }
}
