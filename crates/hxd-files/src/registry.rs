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

use crate::LocalFileSource;

#[derive(Clone)]
pub struct PreparedDownload {
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
    pub resource_offset: u64,
    pub large: bool,
    pub encoded: ffo::Encoded,
}

impl std::fmt::Debug for PreparedDownload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedDownload")
            .field("principal", &self.principal)
            .field("account", &self.account)
            .field("peer", &self.peer)
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
    pub generation: [u8; 16],
    pub digest: Option<[u8; htxf::RESUME_DIGEST_LEN]>,
}

#[derive(Clone)]
pub struct PreparedUpload {
    pub principal: FilePrincipal,
    /// As for [`PreparedDownload::peer`].
    pub peer: Option<IpAddr>,
    pub path: FilePath,
    pub source: Arc<LocalFileSource>,
    pub owner: String,
    /// The HTXF payload size declared on FILE_PUT. A request may leave it
    /// out, and then the claim resolves it from the handshake.
    pub transfer_len: Option<u64>,
    pub large: bool,
    pub quote: Option<UploadQuote>,
    /// The uploader negotiated UTF-8 text, so the comment in its INFO
    /// fork is UTF-8 and is converted to the sidecar's Mac Roman.
    pub comment_utf8: bool,
}

impl std::fmt::Debug for PreparedUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedUpload")
            .field("principal", &self.principal)
            .field("peer", &self.peer)
            .field("path", &self.path)
            .field("owner", &self.owner)
            .field("transfer_len", &self.transfer_len)
            .field("large", &self.large)
            .field("quote", &self.quote)
            .finish_non_exhaustive()
    }
}

/// The server banner, fetched raw: mhxd sends a banner's bytes with no
/// FILP framing around them (`htxf.c`, the `preview` path), and every
/// client that asks for one reads exactly that.
#[derive(Clone)]
pub struct PreparedBanner {
    pub principal: FilePrincipal,
    pub account: String,
    /// As for [`PreparedDownload::peer`].
    pub peer: Option<IpAddr>,
    /// The image as it was when the reference was issued, so the size in
    /// the reply is the size that arrives even if the banner is reloaded
    /// in between.
    pub bytes: Arc<[u8]>,
}

impl std::fmt::Debug for PreparedBanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedBanner")
            .field("principal", &self.principal)
            .field("account", &self.account)
            .field("peer", &self.peer)
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum PreparedTransfer {
    Download(PreparedDownload),
    Upload(PreparedUpload),
    Banner(PreparedBanner),
}

impl PreparedTransfer {
    fn principal(&self) -> FilePrincipal {
        match self {
            PreparedTransfer::Download(value) => value.principal,
            PreparedTransfer::Upload(value) => value.principal,
            PreparedTransfer::Banner(value) => value.principal,
        }
    }

    fn account(&self) -> &str {
        match self {
            PreparedTransfer::Download(value) => &value.account,
            PreparedTransfer::Upload(value) => &value.owner,
            PreparedTransfer::Banner(value) => &value.account,
        }
    }

    fn peer(&self) -> Option<IpAddr> {
        match self {
            PreparedTransfer::Download(value) => value.peer,
            PreparedTransfer::Upload(value) => value.peer,
            PreparedTransfer::Banner(value) => value.peer,
        }
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
        mut owners: impl Iterator<Item = (FilePrincipal, &'a str)>,
        principal: FilePrincipal,
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

#[derive(Clone)]
struct Entry {
    generation: [u8; 16],
    transfer: PreparedTransfer,
    expires: Instant,
}

pub struct TransferRegistry {
    ttl: Duration,
    limits: EntryLimits,
    entries: Mutex<HashMap<u32, Entry>>,
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

    pub fn issue(&self, transfer: PreparedTransfer) -> Result<u32, FileError> {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, value| value.expires > Instant::now());
        // A banner is one reference per login, fetched or not, and many
        // guests share one account: counted against the file limits, a
        // burst of logins whose clients never dial the transfer port would
        // leave the account no room to download. The session hands out one
        // at most, so only the total bounds them.
        let is_banner = |t: &PreparedTransfer| matches!(t, PreparedTransfer::Banner(_));
        let admitted = if is_banner(&transfer) {
            entries.len() < self.limits.total
        } else {
            self.limits.admits(
                entries.len(),
                entries
                    .values()
                    .filter(|entry| !is_banner(&entry.transfer))
                    .map(|entry| (entry.transfer.principal(), entry.transfer.account())),
                transfer.principal(),
                transfer.account(),
            )
        };
        if !admitted {
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
                    Entry {
                        generation,
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
        let principal = entry.transfer.principal();
        // Consulted with the registry unlocked; the generation check below
        // makes sure what is removed is still what was inspected.
        let live = entry.expires > Instant::now()
            && core.session_serial(principal.uid) == Some(principal.serial);
        let from_peer = entry
            .transfer
            .peer()
            .is_none_or(|expected| expected.to_canonical() == peer.to_canonical());
        {
            let mut entries = self.entries.lock().unwrap();
            match entries.get(&preamble.reference) {
                Some(current) if current.generation == entry.generation => {
                    entries.remove(&preamble.reference);
                }
                _ => return Err(FileError::NotFound),
            }
        }
        if !live || !from_peer {
            return Err(FileError::NotFound);
        }
        let (declined_quote, resolved_len) = match &entry.transfer {
            // A banner handshake names HTXF_TYPE_BANNER, which mhxd never
            // reads: the reference alone says what is being fetched, so
            // any type is taken. Nothing resumes a banner.
            PreparedTransfer::Banner(_) => {
                if preamble.flags & htxf::FLAG_RESUME != 0 {
                    return Err(FileError::InvalidPath);
                }
                (false, None)
            }
            _ if preamble.type_code != 0 => return Err(FileError::InvalidPath),
            PreparedTransfer::Download(transfer) => {
                // The download handshake's Data size is not consulted. The
                // protocol has the client send 0 there (Hotline.md,
                // Download File), mhxd reads it only for uploads, and
                // mhxd's own client echoes the reply's transfer size
                // instead, so both must work.
                let large_flag = preamble.flags & htxf::FLAG_LARGE_FILE != 0;
                if large_flag != transfer.large || preamble.flags & htxf::FLAG_RESUME != 0 {
                    return Err(FileError::InvalidPath);
                }
                (false, None)
            }
            PreparedTransfer::Upload(transfer) => {
                // Large-file mode is fixed when FILE_PUT is quoted, and the
                // handshake must agree with it. SIZE64 only frames the length:
                // a client may leave it off whenever 32 bits carry it (Large
                // File extension, "Handshake Flags and Length"). htxf::parse
                // has already checked how the flags relate to one another.
                if (preamble.flags & htxf::FLAG_LARGE_FILE != 0) != transfer.large {
                    return Err(FileError::InvalidPath);
                }
                let resumes = match (&transfer.quote, &preamble.resume_digest) {
                    // RESUME continues a quoted large-file partial, and only
                    // with the digest that quote carried.
                    (Some(quote), Some(echoed)) => {
                        if !quote.digest.as_ref().is_some_and(|expected| {
                            hxfiles_xfer::resume_digest::matches(expected, echoed)
                        }) {
                            return Err(FileError::InvalidPath);
                        }
                        true
                    }
                    // A classic resume carries no flag; its length says it.
                    (Some(_), None) if !transfer.large => true,
                    // A large-file client may turn a quote down and send the
                    // whole file, which then replaces the partial rather than
                    // extending it ("Resume Flow (Upload)").
                    (Some(_), None) => false,
                    // RESUME against a transfer that quoted no offset.
                    (None, Some(_)) => return Err(FileError::InvalidPath),
                    (None, None) => false,
                };
                let resumed_bytes = match &transfer.quote {
                    Some(quote) if resumes => {
                        quote.data_offset.saturating_add(quote.resource_offset)
                    }
                    _ => 0,
                };
                let total = match transfer.transfer_len {
                    Some(total) => {
                        let expected_len = total
                            .checked_sub(resumed_bytes)
                            .ok_or(FileError::RangeInvalid)?;
                        if preamble.transfer_len != expected_len {
                            return Err(FileError::InvalidPath);
                        }
                        total
                    }
                    // The size is optional (Hotline.md, Upload File): mhxd's
                    // own client never sends it, and a Large File resume
                    // request leaves it out ("Resume Flow (Upload)"). The
                    // handshake then states what is left to send, and the
                    // upload is capped by any quoted offset plus that length:
                    // begin_upload reserves it against the partial quota, and
                    // the receive path spends every fork against it before
                    // writing.
                    None => resumed_bytes
                        .checked_add(preamble.transfer_len)
                        .ok_or(FileError::TooLarge)?,
                };
                (transfer.quote.is_some() && !resumes, Some(total))
            }
        };
        let mut transfer = entry.transfer;
        if let PreparedTransfer::Upload(upload) = &mut transfer {
            if declined_quote {
                upload.quote = None;
            }
            upload.transfer_len = resolved_len;
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
                .map(|grant| (grant.principal, grant.account.as_str())),
            principal,
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
                attach_news: false,
                moderate: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        FilePrincipal {
            uid,
            serial: core.session_serial(uid).unwrap(),
        }
    }

    fn download(principal: FilePrincipal, account: &str) -> PreparedDownload {
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
        PreparedDownload {
            principal,
            account: account.into(),
            peer: Some(HERE),
            path: FilePath::parse("file").unwrap(),
            source: Arc::new(UnusedSource),
            offset: 0,
            resource_offset: 0,
            large: false,
            encoded,
        }
    }

    fn prepared(principal: FilePrincipal, account: &str) -> PreparedTransfer {
        PreparedTransfer::Download(download(principal, account))
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
        let transfer = download(principal, "first");
        let echoed = transfer.encoded.transfer_len;
        let reference = registry
            .issue(PreparedTransfer::Download(transfer.clone()))
            .unwrap();
        registry
            .claim(&core, &handshake(reference, 0), HERE)
            .expect("the protocol's own zero");
        let reference = registry
            .issue(PreparedTransfer::Download(transfer))
            .unwrap();
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

        let mut tunnelled = download(principal, "first");
        tunnelled.peer = None;
        let reference = registry
            .issue(PreparedTransfer::Download(tunnelled))
            .unwrap();
        registry
            .claim(&core, &handshake(reference, 0), ELSEWHERE)
            .expect("a tunnelled session's reference has no address to match");
    }

    fn banner(principal: FilePrincipal, account: &str) -> PreparedTransfer {
        PreparedTransfer::Banner(PreparedBanner {
            principal,
            account: account.into(),
            peer: Some(HERE),
            bytes: b"GIF89a".as_slice().into(),
        })
    }

    #[test]
    fn a_banner_reference_is_bound_like_a_download_but_takes_its_own_type() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let other = attach(&core, "second");
        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 4, 4));
        let mut banner_type = handshake(0, 6);
        banner_type.type_code = 2;

        // HTXF_TYPE_BANNER, as GtkHx and mhxd's client send it, and 0.
        for type_code in [2, 0] {
            let reference = registry.issue(banner(principal, "first")).unwrap();
            let claimed = registry
                .claim(
                    &core,
                    &htxf::Preamble {
                        reference,
                        type_code,
                        ..banner_type.clone()
                    },
                    HERE,
                )
                .unwrap();
            assert!(matches!(claimed, PreparedTransfer::Banner(_)));
        }

        // The banner's type is the banner's alone.
        let reference = registry.issue(prepared(other, "second")).unwrap();
        assert_eq!(
            registry
                .claim(
                    &core,
                    &htxf::Preamble {
                        reference,
                        ..banner_type.clone()
                    },
                    HERE
                )
                .unwrap_err(),
            FileError::InvalidPath
        );

        // From another address, spent.
        let reference = registry.issue(banner(principal, "first")).unwrap();
        let from = |r| htxf::Preamble {
            reference: r,
            ..banner_type.clone()
        };
        assert_eq!(
            registry
                .claim(&core, &from(reference), ELSEWHERE)
                .unwrap_err(),
            FileError::NotFound
        );
        assert_eq!(
            registry.claim(&core, &from(reference), HERE).unwrap_err(),
            FileError::NotFound
        );

        // Nothing resumes a banner, and asking spends the reference.
        let reference = registry.issue(banner(principal, "first")).unwrap();
        let mut resume = from(reference);
        resume.flags = htxf::FLAG_LARGE_FILE | htxf::FLAG_RESUME;
        resume.resume_digest = Some([0; htxf::RESUME_DIGEST_LEN]);
        assert_eq!(
            registry.claim(&core, &resume, HERE).unwrap_err(),
            FileError::InvalidPath
        );
        assert_eq!(
            registry.claim(&core, &from(reference), HERE).unwrap_err(),
            FileError::NotFound
        );
    }

    #[test]
    fn banners_leave_an_accounts_file_references_alone() {
        let core = Core::new();
        let guest = attach(&core, "guest");
        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 2, 2));
        for _ in 0..4 {
            registry.issue(banner(guest, "guest")).unwrap();
        }
        registry.issue(prepared(guest, "guest")).unwrap();
        registry.issue(prepared(guest, "guest")).unwrap();
        assert_eq!(
            registry.issue(prepared(guest, "guest")).unwrap_err(),
            FileError::Busy,
            "the file limit still holds for files"
        );
        // The total bounds banners too.
        registry.issue(banner(guest, "guest")).unwrap();
        registry.issue(banner(guest, "guest")).unwrap();
        assert_eq!(
            registry.issue(banner(guest, "guest")).unwrap_err(),
            FileError::Busy
        );
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
    fn classic_resume_claims_without_a_large_file_digest() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let temp = tempfile::tempdir().unwrap();
        let source =
            Arc::new(LocalFileSource::open(temp.path(), crate::LocalLimits::default()).unwrap());
        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 4, 4));
        let reference = registry
            .issue(PreparedTransfer::Upload(PreparedUpload {
                principal,
                peer: None,
                path: FilePath::parse("file").unwrap(),
                source,
                owner: "first".into(),
                transfer_len: Some(10),
                large: false,
                comment_utf8: false,
                quote: Some(UploadQuote {
                    data_offset: 3,
                    resource_offset: 2,
                    generation: [7; 16],
                    digest: None,
                }),
            }))
            .unwrap();
        let preamble = htxf::Preamble {
            reference,
            transfer_len: 5,
            type_code: 0,
            flags: 0,
            resume_digest: None,
        };

        assert!(matches!(
            registry.claim(&core, &preamble, HERE),
            Ok(PreparedTransfer::Upload(_))
        ));
    }

    fn large_upload(
        principal: FilePrincipal,
        source: Arc<LocalFileSource>,
        transfer_len: Option<u64>,
        quote: Option<UploadQuote>,
    ) -> PreparedTransfer {
        PreparedTransfer::Upload(PreparedUpload {
            principal,
            peer: None,
            path: FilePath::parse("file").unwrap(),
            source,
            owner: "first".into(),
            transfer_len,
            large: true,
            comment_utf8: false,
            quote,
        })
    }

    #[test]
    fn large_upload_claims_follow_the_spec_flags() {
        let core = Core::new();
        let principal = attach(&core, "first");
        let temp = tempfile::tempdir().unwrap();
        let source =
            Arc::new(LocalFileSource::open(temp.path(), crate::LocalLimits::default()).unwrap());
        let registry = TransferRegistry::new(Duration::from_secs(30), limits(8, 8, 8));
        let quote = UploadQuote {
            data_offset: 4,
            resource_offset: 0,
            generation: [7; 16],
            digest: Some([9; htxf::RESUME_DIGEST_LEN]),
        };
        let preamble = |reference, transfer_len, flags, resume_digest| htxf::Preamble {
            reference,
            transfer_len,
            type_code: 0,
            flags,
            resume_digest,
        };
        let sized = htxf::FLAG_LARGE_FILE | htxf::FLAG_SIZE64;
        let resume = sized | htxf::FLAG_RESUME;

        // SIZE64 is optional when 32 bits carry the length.
        let reference = registry
            .issue(large_upload(principal, source.clone(), Some(10), None))
            .unwrap();
        assert!(matches!(
            registry.claim(
                &core,
                &preamble(reference, 10, htxf::FLAG_LARGE_FILE, None),
                HERE
            ),
            Ok(PreparedTransfer::Upload(_))
        ));

        // RESUME needs a quoted offset to continue.
        let reference = registry
            .issue(large_upload(principal, source.clone(), Some(10), None))
            .unwrap();
        assert!(matches!(
            registry.claim(&core, &preamble(reference, 6, resume, quote.digest), HERE),
            Err(FileError::InvalidPath)
        ));

        // A quoted resume continues only with the quoted digest.
        let reference = registry
            .issue(large_upload(
                principal,
                source.clone(),
                Some(10),
                Some(quote.clone()),
            ))
            .unwrap();
        assert!(matches!(
            registry.claim(
                &core,
                &preamble(reference, 6, resume, Some([0; htxf::RESUME_DIGEST_LEN])),
                HERE
            ),
            Err(FileError::InvalidPath)
        ));
        // That spent the reference, so the client asks again.
        let reference = registry
            .issue(large_upload(
                principal,
                source.clone(),
                Some(10),
                Some(quote.clone()),
            ))
            .unwrap();
        match registry.claim(&core, &preamble(reference, 6, resume, quote.digest), HERE) {
            Ok(PreparedTransfer::Upload(upload)) => assert_eq!(upload.quote, Some(quote.clone())),
            other => panic!("resume claim: {other:?}"),
        }

        // Declining the quote means sending the whole file, and the quote
        // lapses so the partial is replaced.
        let reference = registry
            .issue(large_upload(
                principal,
                source.clone(),
                Some(10),
                Some(quote.clone()),
            ))
            .unwrap();
        assert!(matches!(
            registry.claim(&core, &preamble(reference, 6, sized, None), HERE),
            Err(FileError::InvalidPath)
        ));
        let reference = registry
            .issue(large_upload(
                principal,
                source.clone(),
                Some(10),
                Some(quote.clone()),
            ))
            .unwrap();
        match registry.claim(&core, &preamble(reference, 10, sized, None), HERE) {
            Ok(PreparedTransfer::Upload(upload)) => assert_eq!(upload.quote, None),
            other => panic!("declined claim: {other:?}"),
        }

        // A resume request may leave the size out. The handshake then states
        // what is left to send, and the claim resolves the total from it.
        let reference = registry
            .issue(large_upload(principal, source, None, Some(quote.clone())))
            .unwrap();
        match registry.claim(&core, &preamble(reference, 6, resume, quote.digest), HERE) {
            Ok(PreparedTransfer::Upload(upload)) => assert_eq!(upload.transfer_len, Some(10)),
            other => panic!("undeclared claim: {other:?}"),
        }
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
