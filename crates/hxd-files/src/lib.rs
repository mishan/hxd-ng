//! Read-only manifest-backed HTTP files and transfer authorization.

mod manifest;
mod registry;
mod transfer;

pub use manifest::{HttpManifestSource, ManifestLimits};
pub use registry::{DownloadGrant, DownloadTokens, PreparedTransfer, TransferRegistry};
pub use transfer::{prepare_legacy, serve_htxf, LegacyTransfer};

use std::sync::Arc;

use hxd_core::FileSource;

/// The shared Files service mounted by both protocol frontends.
#[derive(Clone)]
pub struct FileService {
    pub source: Arc<dyn FileSource>,
    pub transfers: Arc<TransferRegistry>,
    pub downloads: Arc<DownloadTokens>,
}

impl FileService {
    pub fn new(
        source: Arc<dyn FileSource>,
        transfers: Arc<TransferRegistry>,
        downloads: Arc<DownloadTokens>,
    ) -> Self {
        FileService {
            source,
            transfers,
            downloads,
        }
    }
}
