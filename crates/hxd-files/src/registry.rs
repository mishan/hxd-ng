use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hxd_core::{Core, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::ffo;
use hxfiles_xfer::htxf;

#[derive(Clone)]
pub struct PreparedTransfer {
    pub principal: FilePrincipal,
    pub path: FilePath,
    pub source: Arc<dyn FileSource>,
    pub offset: u64,
    pub large: bool,
    pub encoded: ffo::Encoded,
    pub(crate) expires: Instant,
}

impl std::fmt::Debug for PreparedTransfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedTransfer")
            .field("principal", &self.principal)
            .field("path", &self.path)
            .field("offset", &self.offset)
            .field("large", &self.large)
            .field("transfer_len", &self.encoded.transfer_len)
            .finish()
    }
}

pub struct TransferRegistry {
    ttl: Duration,
    entries: Mutex<HashMap<u32, PreparedTransfer>>,
}

impl TransferRegistry {
    pub fn new(ttl: Duration) -> Self {
        TransferRegistry {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, mut transfer: PreparedTransfer) -> Result<u32, FileError> {
        transfer.expires = Instant::now() + self.ttl;
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, value| value.expires > Instant::now());
        for _ in 0..64 {
            let mut bytes = [0; 4];
            getrandom::getrandom(&mut bytes)
                .map_err(|e| FileError::Unavailable(format!("transfer reference: {e}")))?;
            let reference = u32::from_ne_bytes(bytes);
            if reference != 0 && !entries.contains_key(&reference) {
                entries.insert(reference, transfer);
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
        let transfer = entries
            .get(&preamble.reference)
            .ok_or(FileError::NotFound)?;
        if transfer.expires <= Instant::now()
            || core.session_serial(transfer.principal.uid) != Some(transfer.principal.serial)
        {
            entries.remove(&preamble.reference);
            return Err(FileError::NotFound);
        }
        let large_flag = preamble.flags & htxf::FLAG_LARGE_FILE != 0;
        if large_flag != transfer.large
            || preamble.flags & htxf::FLAG_RESUME != 0
            || preamble.type_code != 1
            || preamble.transfer_len != transfer.encoded.transfer_len
        {
            return Err(FileError::InvalidPath);
        }
        Ok(entries
            .remove(&preamble.reference)
            .expect("entry checked under the same lock"))
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
        PreparedTransfer {
            principal,
            path: FilePath::parse("file").unwrap(),
            source: Arc::new(UnusedSource),
            offset: 0,
            large: false,
            encoded,
            expires: Instant::now(),
        }
    }

    #[test]
    fn transfer_references_reject_mismatched_handshakes_and_ended_sessions() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let registry = TransferRegistry::new(Duration::from_secs(30));
        let transfer = prepared(principal);
        let transfer_len = transfer.encoded.transfer_len;
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
}
