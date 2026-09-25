//! Bounded HTTP and capability-rooted local files with transfer authorization.

mod local;
mod manifest;
mod registry;
mod transfer;

pub use manifest::{HttpManifestSource, ManifestLimits};
pub use registry::{
    DownloadGrant, DownloadTokens, EntryLimits, PreparedDownload, PreparedTransfer, PreparedUpload,
    TransferRegistry, UploadQuote,
};
pub use transfer::{
    prepare_legacy, prepare_upload, pump, serve_htxf, serve_htxf_with, HtxfSlots, HtxfStream,
    HtxfTimeouts, LegacyTransfer, Liveness, UploadTransfer,
};

use std::sync::Arc;
use std::time::Duration;

use hxd_core::FileSource;

/// The shared Files service mounted by both protocol frontends.
#[derive(Clone)]
pub struct FileService {
    pub source: Arc<dyn FileSource>,
    /// Present only for a capability-rooted local source.
    pub uploads: Option<Arc<LocalFileSource>>,
    pub transfers: Arc<TransferRegistry>,
    pub downloads: Arc<DownloadTokens>,
    /// How long a download may make no progress toward its receiver, on
    /// either wire, before it is abandoned.
    pub idle_timeout: Duration,
}

impl FileService {
    pub fn new(
        source: Arc<dyn FileSource>,
        uploads: Option<Arc<LocalFileSource>>,
        transfers: Arc<TransferRegistry>,
        downloads: Arc<DownloadTokens>,
        idle_timeout: Duration,
    ) -> Self {
        FileService {
            source,
            uploads,
            transfers,
            downloads,
            idle_timeout,
        }
    }
}
pub use local::{LocalFileSource, LocalLimits};
