use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hxd_core::{Core, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::ffo;
use hxfiles_xfer::htxf;

use crate::LocalFileSource;

const MAX_PENDING_TRANSFERS: usize = 4_096;
const MAX_DOWNLOAD_TOKENS: usize = 4_096;

#[derive(Clone)]
pub struct PreparedDownload {
    pub principal: FilePrincipal,
    pub path: FilePath,
    pub source: Arc<dyn FileSource>,
    pub offset: u64,
    pub resource_offset: u64,
    pub large: bool,
    pub encoded: ffo::Encoded,
}

impl std::fmt::Debug for PreparedDownload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedDownload")
            .field("principal", &self.principal)
            .field("path", &self.path)
            .field("offset", &self.offset)
            .field("resource_offset", &self.resource_offset)
            .field("large", &self.large)
            .field("transfer_len", &self.encoded.transfer_len)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadQuote {
    pub data_offset: u64,
    pub resource_offset: u64,
    pub digest: Option<[u8; htxf::RESUME_DIGEST_LEN]>,
}

#[derive(Clone)]
pub struct PreparedUpload {
    pub principal: FilePrincipal,
    pub path: FilePath,
    pub source: Arc<LocalFileSource>,
    pub owner: String,
    /// The HTXF payload size declared on FILE_PUT.
    pub transfer_len: u64,
    pub large: bool,
    pub quote: Option<UploadQuote>,
}

impl std::fmt::Debug for PreparedUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUpload")
            .field("principal", &self.principal)
            .field("path", &self.path)
            .field("owner", &self.owner)
            .field("transfer_len", &self.transfer_len)
            .field("large", &self.large)
            .field("quote", &self.quote)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub enum PreparedTransfer {
    Download(PreparedDownload),
    Upload(PreparedUpload),
}

impl PreparedTransfer {
    fn principal(&self) -> FilePrincipal {
        match self {
            PreparedTransfer::Download(value) => value.principal,
            PreparedTransfer::Upload(value) => value.principal,
        }
    }
}

struct Entry {
    transfer: PreparedTransfer,
    expires: Instant,
}

pub struct TransferRegistry {
    ttl: Duration,
    entries: Mutex<HashMap<u32, Entry>>,
}

impl TransferRegistry {
    pub fn new(ttl: Duration) -> Self {
        TransferRegistry {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, transfer: PreparedTransfer) -> Result<u32, FileError> {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, value| value.expires > Instant::now());
        if entries.len() >= MAX_PENDING_TRANSFERS {
            return Err(FileError::Busy);
        }
        for _ in 0..64 {
            let mut bytes = [0; 4];
            getrandom::getrandom(&mut bytes)
                .map_err(|e| FileError::Unavailable(format!("transfer reference: {e}")))?;
            let reference = u32::from_ne_bytes(bytes);
            if reference != 0 && !entries.contains_key(&reference) {
                entries.insert(
                    reference,
                    Entry {
                        transfer,
                        expires: Instant::now() + self.ttl,
                    },
                );
                return Ok(reference);
            }
        }
        Err(FileError::Unavailable(
            "could not allocate a transfer reference".into(),
        ))
    }

    pub fn claim(
        &self,
        core: &Core,
        preamble: &htxf::Preamble,
    ) -> Result<PreparedTransfer, FileError> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get(&preamble.reference)
            .ok_or(FileError::NotFound)?;
        let principal = entry.transfer.principal();
        if entry.expires <= Instant::now()
            || core.session_serial(principal.uid) != Some(principal.serial)
        {
            entries.remove(&preamble.reference);
            return Err(FileError::NotFound);
        }
        if preamble.type_code != 0 {
            return Err(FileError::InvalidPath);
        }
        match &entry.transfer {
            PreparedTransfer::Download(transfer) => {
                let large_flag = preamble.flags & htxf::FLAG_LARGE_FILE != 0;
                if large_flag != transfer.large
                    || preamble.flags & htxf::FLAG_RESUME != 0
                    || preamble.transfer_len != transfer.encoded.transfer_len
                {
                    return Err(FileError::InvalidPath);
                }
            }
            PreparedTransfer::Upload(transfer) => {
                let resume = transfer.quote.is_some();
                let resumed_bytes = transfer.quote.as_ref().map_or(0, |quote| {
                    quote.data_offset.saturating_add(quote.resource_offset)
                });
                let expected_len = transfer
                    .transfer_len
                    .checked_sub(resumed_bytes)
                    .ok_or(FileError::RangeInvalid)?;
                let expected_flags = if transfer.large {
                    htxf::FLAG_LARGE_FILE
                        | htxf::FLAG_SIZE64
                        | if resume { htxf::FLAG_RESUME } else { 0 }
                } else {
                    0
                };
                if preamble.flags != expected_flags || preamble.transfer_len != expected_len {
                    return Err(FileError::InvalidPath);
                }
                match (&transfer.quote, &preamble.resume_digest) {
                    (Some(quote), Some(echoed))
                        if quote.digest.as_ref().is_some_and(|expected| {
                            hxfiles_xfer::resume_digest::matches(expected, echoed)
                        }) => {}
                    (None, None) => {}
                    _ => return Err(FileError::InvalidPath),
                }
            }
        }
        Ok(entries
            .remove(&preamble.reference)
            .expect("entry checked under the same lock")
            .transfer)
    }
}

#[derive(Debug, Clone)]
pub struct DownloadGrant {
    pub principal: FilePrincipal,
    pub path: FilePath,
    pub expires_at: Instant,
}

pub struct DownloadTokens {
    ttl: Duration,
    grants: Mutex<HashMap<String, DownloadGrant>>,
}

impl DownloadTokens {
    pub fn new(ttl: Duration) -> Self {
        DownloadTokens {
            ttl,
            grants: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, principal: FilePrincipal, path: FilePath) -> Result<String, FileError> {
        let mut raw = [0; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|e| FileError::Unavailable(format!("download token: {e}")))?;
        let token = URL_SAFE_NO_PAD.encode(raw);
        let grant = DownloadGrant {
            principal,
            path,
            expires_at: Instant::now() + self.ttl,
        };
        let mut grants = self.grants.lock().unwrap();
        grants.retain(|_, value| value.expires_at > Instant::now());
        if grants.len() >= MAX_DOWNLOAD_TOKENS {
            return Err(FileError::Busy);
        }
        grants.insert(token.clone(), grant);
        Ok(token)
    }

    pub fn resolve(&self, token: &str, core: &Core) -> Option<DownloadGrant> {
        let mut grants = self.grants.lock().unwrap();
        let grant = grants.get(token)?.clone();
        if grant.expires_at <= Instant::now()
            || core.session_serial(grant.principal.uid) != Some(grant.principal.serial)
        {
            grants.remove(token);
            return None;
        }
        Some(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::{AccessBits, AttachInfo, FileBody, FileEntry, FileFuture, FileInfo, Transport};

    struct UnusedSource;

    impl FileSource for UnusedSource {
        fn list<'a>(&'a self, _path: &'a FilePath) -> FileFuture<'a, Vec<FileEntry>> {
            Box::pin(async { unreachable!("registry tests do not open their source") })
        }

        fn info<'a>(&'a self, _path: &'a FilePath) -> FileFuture<'a, FileInfo> {
            Box::pin(async { unreachable!("registry tests do not open their source") })
        }

        fn open<'a>(&'a self, _path: &'a FilePath, _from: u64) -> FileFuture<'a, FileBody> {
            Box::pin(async { unreachable!("registry tests do not open their source") })
        }
    }

    fn attach(core: &Core, login: &str) -> FilePrincipal {
        let (uid, _events) = core
            .attach(AttachInfo {
                nick: login.into(),
                icon: 0,
                admin: false,
                access: AccessBits::empty(),
                login: login.into(),
                addr: None,
                can_detach: false,
                transport: Transport::default(),
                has_inbox: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
            })
            .unwrap();
        FilePrincipal {
            uid,
            serial: core.session_serial(uid).unwrap(),
        }
    }

    fn prepared(principal: FilePrincipal) -> PreparedTransfer {
        let encoded = ffo::encode(
            &ffo::Metadata {
                name: b"file",
                type_code: *b"BINA",
                creator: *b"????",
                comment: b"",
                create_time: 0,
                modify_time: 0,
            },
            ffo::Forks {
                data_len: 1,
                data_offset: 0,
                resource_len: 0,
                resource_offset: 0,
            },
            false,
        )
        .unwrap();
        PreparedTransfer::Download(PreparedDownload {
            principal,
            path: FilePath::parse("file").unwrap(),
            source: Arc::new(UnusedSource),
            offset: 0,
            resource_offset: 0,
            large: false,
            encoded,
        })
    }

    #[test]
    fn transfer_references_reject_mismatched_handshakes_and_ended_sessions() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let registry = TransferRegistry::new(Duration::from_secs(30));
        let transfer = prepared(principal);
        let transfer_len = match &transfer {
            PreparedTransfer::Download(value) => value.encoded.transfer_len,
            PreparedTransfer::Upload(_) => unreachable!(),
        };
        let reference = registry.issue(transfer).unwrap();
        let mut preamble = htxf::Preamble {
            reference,
            transfer_len: transfer_len + 1,
            type_code: 1,
            flags: 0,
            resume_digest: None,
        };
        assert!(matches!(
            registry.claim(&core, &preamble),
            Err(FileError::InvalidPath)
        ));
        preamble.transfer_len = transfer_len;
        assert!(matches!(
            registry.claim(&core, &preamble),
            Err(FileError::InvalidPath)
        ));
        preamble.type_code = 0;
        core.end_session(principal.uid);
        assert!(matches!(
            registry.claim(&core, &preamble),
            Err(FileError::NotFound)
        ));
    }

    #[test]
    fn download_tokens_stop_authorizing_when_the_issuing_session_ends() {
        let core = Core::new();
        let first = attach(&core, "first");
        let tokens = DownloadTokens::new(Duration::from_secs(30));
        let token = tokens
            .issue(first, FilePath::parse("file").unwrap())
            .unwrap();
        assert!(tokens.resolve(&token, &core).is_some());

        core.end_session(first.uid);
        let second = attach(&core, "second");
        assert_ne!(second.serial, first.serial);
        assert!(tokens.resolve(&token, &core).is_none());
    }

    #[test]
    fn pending_authorizations_are_bounded() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let registry = TransferRegistry::new(Duration::from_secs(30));
        let transfer = prepared(principal);
        for _ in 0..MAX_PENDING_TRANSFERS {
            registry.issue(transfer.clone()).unwrap();
        }
        assert!(matches!(registry.issue(transfer), Err(FileError::Busy)));

        let tokens = DownloadTokens::new(Duration::from_secs(30));
        let path = FilePath::parse("file").unwrap();
        for _ in 0..MAX_DOWNLOAD_TOKENS {
            tokens.issue(principal, path.clone()).unwrap();
        }
        assert!(matches!(
            tokens.issue(principal, path),
            Err(FileError::Busy)
        ));
    }
}
