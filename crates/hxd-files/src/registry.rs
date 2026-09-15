use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hxd_core::{Core, FileError, FilePath, FilePrincipal, FileSource};
use hxfiles_xfer::ffo;
use hxfiles_xfer::htxf;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct PreparedTransfer {
    pub principal: FilePrincipal,
    /// The account behind `principal`. Sessions are cheap to open, so the
    /// per-session cap alone would let one account fill the registry.
    pub account: String,
    /// Where the control connection came from, when that address means
    /// something. A transfer connection from anywhere else is refused and
    /// spends the reference, as mhxd does (`htxf.c`, `got_hdr`). A tunnelled
    /// session has no such address: its peer is whoever terminated the
    /// WebSocket.
    pub peer: Option<IpAddr>,
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
            .field("account", &self.account)
            .field("peer", &self.peer)
            .field("path", &self.path)
            .field("offset", &self.offset)
            .field("large", &self.large)
            .field("transfer_len", &self.encoded.transfer_len)
            .finish()
    }
}

/// Per-session and per-account ceilings on outstanding entries.
#[derive(Debug, Clone, Copy)]
pub struct EntryLimits {
    pub total: usize,
    pub per_session: usize,
    pub per_account: usize,
}

impl EntryLimits {
    fn assert_valid(&self) {
        assert!(self.total > 0);
        assert!(self.per_session > 0);
        assert!(self.per_account > 0);
    }

    fn admits<'a>(
        &self,
        len: usize,
        mut owners: impl Iterator<Item = (&'a FilePrincipal, &'a str)>,
        principal: &FilePrincipal,
        account: &str,
    ) -> bool {
        if len >= self.total {
            return false;
        }
        let (mut by_session, mut by_account) = (0, 0);
        owners.all(|(owner, owner_account)| {
            by_session += usize::from(owner == principal);
            by_account += usize::from(owner_account == account);
            by_session < self.per_session && by_account < self.per_account
        })
    }
}

pub struct TransferRegistry {
    ttl: Duration,
    limits: EntryLimits,
    entries: Mutex<HashMap<u32, TransferEntry>>,
}

#[derive(Clone)]
struct TransferEntry {
    generation: [u8; 16],
    transfer: PreparedTransfer,
}

impl TransferRegistry {
    pub fn new(ttl: Duration, limits: EntryLimits) -> Self {
        limits.assert_valid();
        TransferRegistry {
            ttl,
            limits,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, mut transfer: PreparedTransfer) -> Result<u32, FileError> {
        transfer.expires = Instant::now() + self.ttl;
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, value| value.transfer.expires > Instant::now());
        if !self.limits.admits(
            entries.len(),
            entries
                .values()
                .map(|entry| (&entry.transfer.principal, entry.transfer.account.as_str())),
            &transfer.principal,
            &transfer.account,
        ) {
            return Err(FileError::Busy);
        }
        for _ in 0..64 {
            let mut bytes = [0; 4];
            getrandom::getrandom(&mut bytes)
                .map_err(|e| FileError::Unavailable(format!("transfer reference: {e}")))?;
            let reference = u32::from_ne_bytes(bytes);
            if reference != 0 && !entries.contains_key(&reference) {
                let mut generation = [0; 16];
                getrandom::getrandom(&mut generation)
                    .map_err(|e| FileError::Unavailable(format!("transfer generation: {e}")))?;
                entries.insert(
                    reference,
                    TransferEntry {
                        generation,
                        transfer,
                    },
                );
                return Ok(reference);
            }
        }
        Err(FileError::Unavailable(
            "could not allocate a transfer reference".into(),
        ))
    }

    /// Claims the reference a transfer connection from `peer` presented.
    ///
    /// A reference is spent by any presentation, the malformed and the
    /// misdirected included: a wrong guess must not leave it for the next.
    pub fn claim(
        &self,
        core: &Core,
        preamble: &htxf::Preamble,
        peer: IpAddr,
    ) -> Result<PreparedTransfer, FileError> {
        let entry = self
            .entries
            .lock()
            .unwrap()
            .get(&preamble.reference)
            .cloned()
            .ok_or(FileError::NotFound)?;
        let transfer = &entry.transfer;
        // Consulted with the registry unlocked; the generation check below
        // makes sure what is removed is still what was inspected.
        let live = transfer.expires > Instant::now()
            && core.session_serial(transfer.principal.uid) == Some(transfer.principal.serial);
        let from_peer = transfer
            .peer
            .is_none_or(|expected| expected.to_canonical() == peer.to_canonical());
        // The download handshake's Data size is not consulted. The protocol
        // has the client send 0 there (Hotline.md, Download File), mhxd
        // reads it only for uploads, and mhxd's own client echoes the
        // reply's transfer size instead, so both must work.
        let large_flag = preamble.flags & htxf::FLAG_LARGE_FILE != 0;
        let well_formed = large_flag == transfer.large
            && preamble.flags & htxf::FLAG_RESUME == 0
            && preamble.type_code == 0;
        let mut entries = self.entries.lock().unwrap();
        let transfer = match entries.get(&preamble.reference) {
            Some(current) if current.generation == entry.generation => {
                entries
                    .remove(&preamble.reference)
                    .expect("matching entry exists")
                    .transfer
            }
            _ => return Err(FileError::NotFound),
        };
        drop(entries);
        if !live || !from_peer {
            return Err(FileError::NotFound);
        }
        if !well_formed {
            return Err(FileError::InvalidPath);
        }
        Ok(transfer)
    }
}

#[derive(Debug, Clone)]
pub struct DownloadGrant {
    pub principal: FilePrincipal,
    pub account: String,
    pub path: FilePath,
    pub ranges: bool,
    pub expires_at: Instant,
}

pub struct DownloadTokens {
    ttl: Duration,
    limits: EntryLimits,
    grants: Mutex<HashMap<[u8; 32], DownloadGrant>>,
}

impl DownloadTokens {
    pub fn new(ttl: Duration, limits: EntryLimits) -> Self {
        limits.assert_valid();
        DownloadTokens {
            ttl,
            limits,
            grants: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(
        &self,
        principal: FilePrincipal,
        account: &str,
        path: FilePath,
        ranges: bool,
    ) -> Result<String, FileError> {
        let mut grants = self.grants.lock().unwrap();
        grants.retain(|_, value| value.expires_at > Instant::now());
        if !self.limits.admits(
            grants.len(),
            grants
                .values()
                .map(|grant| (&grant.principal, grant.account.as_str())),
            &principal,
            account,
        ) {
            return Err(FileError::Busy);
        }
        for _ in 0..64 {
            let mut raw = [0; 32];
            getrandom::getrandom(&mut raw)
                .map_err(|e| FileError::Unavailable(format!("download token: {e}")))?;
            let token = URL_SAFE_NO_PAD.encode(raw);
            let digest = token_digest(&token);
            if let std::collections::hash_map::Entry::Vacant(slot) = grants.entry(digest) {
                slot.insert(DownloadGrant {
                    principal,
                    account: account.to_owned(),
                    path: path.clone(),
                    ranges,
                    expires_at: Instant::now() + self.ttl,
                });
                return Ok(token);
            }
        }
        Err(FileError::Unavailable(
            "could not allocate a download token".into(),
        ))
    }

    pub fn resolve(&self, token: &str, core: &Core) -> Option<DownloadGrant> {
        let digest = token_digest(token);
        let grant = self.grants.lock().unwrap().get(&digest)?.clone();
        if grant.expires_at <= Instant::now()
            || core.session_serial(grant.principal.uid) != Some(grant.principal.serial)
        {
            let mut grants = self.grants.lock().unwrap();
            if grants.get(&digest).is_some_and(|current| {
                current.principal == grant.principal
                    && current.path == grant.path
                    && current.expires_at == grant.expires_at
            }) {
                grants.remove(&digest);
            }
            return None;
        }
        Some(grant)
    }
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::{AccessBits, AttachInfo, FileBody, FileEntry, FileFuture, FileInfo, Transport};

    const HERE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const ELSEWHERE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));

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

    fn limits(total: usize, per_session: usize, per_account: usize) -> EntryLimits {
        EntryLimits {
            total,
            per_session,
            per_account,
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

    fn prepared(principal: FilePrincipal, account: &str) -> PreparedTransfer {
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
            account: account.into(),
            peer: Some(HERE),
            path: FilePath::parse("file").unwrap(),
            source: Arc::new(UnusedSource),
            offset: 0,
            large: false,
            encoded,
            expires: Instant::now(),
        }
    }

    fn handshake(reference: u32, transfer_len: u64) -> htxf::Preamble {
        htxf::Preamble {
            reference,
            transfer_len,
            type_code: 0,
            flags: 0,
            resume_digest: None,
        }
    }

    #[test]
    fn a_download_handshake_may_send_zero_or_the_size_for_its_length() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 4, 4));
        let transfer = prepared(principal, "first");
        let echoed = transfer.encoded.transfer_len;
        let reference = registry.issue(transfer.clone()).unwrap();
        registry
            .claim(&core, &handshake(reference, 0), HERE)
            .expect("the protocol's own zero");
        let reference = registry.issue(transfer).unwrap();
        registry
            .claim(&core, &handshake(reference, echoed), HERE)
            .expect("mhxd's client echoes the transfer size");
    }

    #[test]
    fn references_are_single_use_and_spent_by_a_wrong_presentation() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 4, 4));

        let reference = registry.issue(prepared(principal, "first")).unwrap();
        registry
            .claim(&core, &handshake(reference, 0), HERE)
            .unwrap();
        assert_eq!(
            registry
                .claim(&core, &handshake(reference, 0), HERE)
                .unwrap_err(),
            FileError::NotFound
        );

        let reference = registry.issue(prepared(principal, "first")).unwrap();
        assert_eq!(
            registry
                .claim(&core, &handshake(reference, 0), ELSEWHERE)
                .unwrap_err(),
            FileError::NotFound
        );
        assert_eq!(
            registry
                .claim(&core, &handshake(reference, 0), HERE)
                .unwrap_err(),
            FileError::NotFound,
            "a reference presented from the wrong address is gone"
        );

        let reference = registry.issue(prepared(principal, "first")).unwrap();
        let mut malformed = handshake(reference, 0);
        malformed.type_code = 1;
        assert_eq!(
            registry.claim(&core, &malformed, HERE).unwrap_err(),
            FileError::InvalidPath
        );
        assert_eq!(
            registry
                .claim(&core, &handshake(reference, 0), HERE)
                .unwrap_err(),
            FileError::NotFound
        );

        let mut tunnelled = prepared(principal, "first");
        tunnelled.peer = None;
        let reference = registry.issue(tunnelled).unwrap();
        registry
            .claim(&core, &handshake(reference, 0), ELSEWHERE)
            .expect("a tunnelled session's reference has no address to match");
    }

    #[test]
    fn references_expire_and_die_with_their_session() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let expired = TransferRegistry::new(Duration::ZERO, limits(8, 4, 4));
        let reference = expired.issue(prepared(principal, "first")).unwrap();
        assert_eq!(
            expired
                .claim(&core, &handshake(reference, 0), HERE)
                .unwrap_err(),
            FileError::NotFound
        );

        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 4, 4));
        let reference = registry.issue(prepared(principal, "first")).unwrap();
        core.end_session(principal.uid);
        assert_eq!(
            registry
                .claim(&core, &handshake(reference, 0), HERE)
                .unwrap_err(),
            FileError::NotFound
        );
    }

    #[test]
    fn download_tokens_stop_authorizing_when_the_issuing_session_ends() {
        let core = Core::new();
        let first = attach(&core, "first");
        let tokens = DownloadTokens::new(Duration::from_secs(30), limits(8, 4, 4));
        let token = tokens
            .issue(first, "first", FilePath::parse("file").unwrap(), true)
            .unwrap();
        assert!(tokens.resolve(&token, &core).is_some());

        core.end_session(first.uid);
        let second = attach(&core, "second");
        assert_ne!(second.serial, first.serial);
        assert!(tokens.resolve(&token, &core).is_none());
    }

    #[test]
    fn registries_bound_global_per_session_and_per_account_entries() {
        let core = Core::new();
        let first = attach(&core, "first");
        let second = attach(&core, "second");
        let transfers = TransferRegistry::new(Duration::from_secs(30), limits(3, 2, 8));
        transfers.issue(prepared(first, "first")).unwrap();
        transfers.issue(prepared(first, "first")).unwrap();
        assert!(matches!(
            transfers.issue(prepared(first, "first")),
            Err(FileError::Busy)
        ));
        transfers.issue(prepared(second, "second")).unwrap();
        assert!(matches!(
            transfers.issue(prepared(second, "second")),
            Err(FileError::Busy)
        ));

        let downloads = DownloadTokens::new(Duration::from_secs(30), limits(3, 2, 8));
        let path = FilePath::parse("file").unwrap();
        downloads
            .issue(first, "first", path.clone(), false)
            .unwrap();
        downloads.issue(first, "first", path.clone(), true).unwrap();
        assert!(matches!(
            downloads.issue(first, "first", path.clone(), false),
            Err(FileError::Busy)
        ));
        downloads
            .issue(second, "second", path.clone(), false)
            .unwrap();
        assert!(matches!(
            downloads.issue(second, "second", path.clone(), false),
            Err(FileError::Busy)
        ));

        // One account across sessions: each session is under its own cap,
        // and the account's is what stops them.
        let third = attach(&core, "shared");
        let fourth = attach(&core, "shared");
        let shared = TransferRegistry::new(Duration::from_secs(30), limits(16, 2, 3));
        shared.issue(prepared(third, "shared")).unwrap();
        shared.issue(prepared(third, "shared")).unwrap();
        shared.issue(prepared(fourth, "shared")).unwrap();
        assert!(matches!(
            shared.issue(prepared(fourth, "shared")),
            Err(FileError::Busy)
        ));
        let tokens = DownloadTokens::new(Duration::from_secs(30), limits(16, 2, 3));
        tokens.issue(third, "shared", path.clone(), false).unwrap();
        tokens.issue(third, "shared", path.clone(), false).unwrap();
        tokens.issue(fourth, "shared", path.clone(), false).unwrap();
        assert!(matches!(
            tokens.issue(fourth, "shared", path, false),
            Err(FileError::Busy)
        ));
    }
}
