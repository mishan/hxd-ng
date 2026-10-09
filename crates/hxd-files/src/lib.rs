//! Bounded HTTP and capability-rooted local files with transfer authorization.

mod local;
mod manifest;
mod registry;
mod sealed;
mod transfer;

pub use manifest::{HttpManifestSource, ManifestLimits};
pub use registry::{
    DecodeName, DownloadGrant, DownloadTokens, EntryLimits, FolderFile, FolderItem, PreparedBanner,
    PreparedDownload, PreparedFolder, PreparedFolderUpload, PreparedTransfer, PreparedUpload,
    SealKeys, TransferRegistry, UploadQuote,
};
pub use transfer::{
    prepare_folder, prepare_legacy, prepare_upload, pump, serve_htxf, serve_htxf_with,
    serve_tunnelled, FolderTransfer, HtxfSlots, HtxfStream, HtxfTimeouts, LegacyTransfer, Liveness,
    UploadTransfer,
};

use std::sync::Arc;
use std::time::Duration;

use hxd_core::FileSource;

/// The most items one folder transfer holds unless configured otherwise.
pub const MAX_FOLDER_ITEMS: usize = 100_000;

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
    /// The most items one folder download or upload may hold.
    pub max_folder_items: usize,
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
            max_folder_items: MAX_FOLDER_ITEMS,
        }
    }
}
pub use local::{LocalFileSource, LocalLimits};

/// `tokio::task::spawn_blocking`, with the pool's queue time and
/// occupancy reported under `what` (`hxd_core::instrument::blocking`).
pub(crate) fn spawn_blocking<R: Send + 'static>(
    what: &'static str,
    f: impl FnOnce() -> R + Send + 'static,
) -> tokio::task::JoinHandle<R> {
    tokio::task::spawn_blocking(hxd_core::instrument::blocking(what, f))
}
