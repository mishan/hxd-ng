//! Bounded HTTP and capability-rooted local files with transfer authorization.

mod local;
mod manifest;
mod registry;
mod transfer;

pub use manifest::{HttpManifestSource, ManifestLimits};
pub use registry::{
    DownloadGrant, DownloadTokens, PreparedDownload, PreparedTransfer, PreparedUpload,
    TransferRegistry, UploadQuote,
};
pub use transfer::{prepare_legacy, prepare_upload, serve_htxf, LegacyTransfer, UploadTransfer};

use std::sync::Arc;

use hxd_core::FileSource;

/// The shared Files service mounted by both protocol frontends.
#[derive(Clone)]
pub struct FileService {
    pub source: Arc<dyn FileSource>,
    /// Present only for a capability-rooted local source.
    pub uploads: Option<Arc<LocalFileSource>>,
    pub transfers: Arc<TransferRegistry>,
    pub downloads: Arc<DownloadTokens>,
}

impl FileService {
    pub fn new(
        source: Arc<dyn FileSource>,
        uploads: Option<Arc<LocalFileSource>>,
        transfers: Arc<TransferRegistry>,
        downloads: Arc<DownloadTokens>,
    ) -> Self {
        FileService {
            source,
            uploads,
            transfers,
            downloads,
        }
    }
}
pub use local::{LocalFileSource, LocalLimits};
