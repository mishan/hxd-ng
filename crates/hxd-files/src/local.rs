use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirEntry, Metadata, OpenOptions, Permissions};
use hxd_core::{FileBody, FileEntry, FileError, FileInfo, FileKind, FilePath, FileSource};
use hxproto::text;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::UploadQuote;

const STATE_DIR: &str = ".hxd-state";
const PARTIAL_DIR: &str = "partials";
const METADATA_DIR: &str = "metadata";
const HEADER_EPOCH: u64 = 946_684_800;
const UPLOAD_GENERATION_LEN: usize = 16;
/// Every file a partial upload keeps, by suffix on its base name.
const PARTIAL_SUFFIXES: [&str; 4] = ["data", "rsrc", "fndrinfo", "generation"];
/// The longest name Linux and macOS filesystems store, in bytes.
const NAME_MAX: usize = 255;

#[derive(Debug, Clone, Copy)]
pub struct LocalLimits {
    pub max_file_size: u64,
    pub max_entries: usize,
    pub max_concurrent: usize,
    pub max_partial_bytes: u64,
    pub max_partials: usize,
    pub max_partials_per_account: usize,
    pub io_timeout: Duration,
    pub upload_timeout: Duration,
    pub partial_ttl: Duration,
}

impl Default for LocalLimits {
    fn default() -> Self {
        LocalLimits {
            max_file_size: 64 * 1024 * 1024 * 1024,
            max_entries: 100_000,
            max_concurrent: 8,
            max_partial_bytes: 64 * 1024 * 1024 * 1024,
            max_partials: 1_024,
            max_partials_per_account: 4,
            io_timeout: Duration::from_secs(30),
            upload_timeout: Duration::from_secs(60 * 60),
            partial_ttl: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

struct Inner {
    root: Arc<Dir>,
    partials: Arc<Dir>,
    metadata: Arc<Dir>,
    /// The state directory's identity. A case-folding filesystem resolves
    /// more spellings to it than a name check can know, so directories
    /// are refused by what they are rather than what they are called.
    state_id: Option<(u64, u64)>,
    limits: LocalLimits,
    permits: Arc<Semaphore>,
    active_uploads: Mutex<HashSet<String>>,
    publishing_paths: Mutex<HashSet<String>>,
    reserved_upload_bytes: Mutex<HashMap<String, u64>>,
}

#[derive(Clone)]
pub struct LocalFileSource {
    inner: Arc<Inner>,
}

struct VisibleEntry {
    name: String,
    kind: FileKind,
    metadata: Metadata,
}

impl LocalFileSource {
    pub fn open(path: &Path, limits: LocalLimits) -> Result<Self, FileError> {
        if limits.max_file_size == 0
            || limits.max_entries == 0
            || limits.max_concurrent == 0
            || limits.max_partial_bytes == 0
            || limits.max_partials == 0
            || limits.max_partials_per_account == 0
            || limits.io_timeout.is_zero()
            || limits.upload_timeout.is_zero()
            || limits.partial_ttl.is_zero()
        {
            return Err(FileError::Unavailable(
                "local file limits and timeouts must be non-zero".into(),
            ));
        }
        let root = Dir::open_ambient_dir(path, ambient_authority())
            .map_err(|error| unavailable("open local root", error))?;
        root.create_dir_all(Path::new(STATE_DIR).join(PARTIAL_DIR))
            .map_err(|error| unavailable("create partial directory", error))?;
        root.create_dir_all(Path::new(STATE_DIR).join(METADATA_DIR))
            .map_err(|error| unavailable("create metadata directory", error))?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt;
            root.set_permissions(STATE_DIR, Permissions::from_mode(0o700))
                .map_err(|error| unavailable("protect state directory", error))?;
        }
        let state = root
            .open_dir_nofollow(STATE_DIR)
            .map_err(|error| unavailable("open state directory", error))?;
        let state_id = identity(
            &state
                .dir_metadata()
                .map_err(|error| unavailable("stat state directory", error))?,
        );
        let partials = state
            .open_dir(PARTIAL_DIR)
            .map_err(|error| unavailable("open partial directory", error))?;
        let metadata = state
            .open_dir(METADATA_DIR)
            .map_err(|error| unavailable("open metadata directory", error))?;
        let source = LocalFileSource {
            inner: Arc::new(Inner {
                root: Arc::new(root),
                partials: Arc::new(partials),
                metadata: Arc::new(metadata),
                state_id,
                limits,
                permits: Arc::new(Semaphore::new(limits.max_concurrent)),
                active_uploads: Mutex::new(HashSet::new()),
                publishing_paths: Mutex::new(HashSet::new()),
                reserved_upload_bytes: Mutex::new(HashMap::new()),
            }),
        };
        source.sweep_partials()?;
        Ok(source)
    }

    pub fn limits(&self) -> LocalLimits {
        self.inner.limits
    }

    pub fn prepare_upload(
        &self,
        owner: &str,
        path: &FilePath,
        transfer_len: Option<u64>,
        large: bool,
        resume_requested: bool,
    ) -> Result<Option<UploadQuote>, FileError> {
        self.sweep_partials()?;
        Self::validate_path(path)?;
        if path.is_root() {
            return Err(FileError::InvalidPath);
        }
        let (parent, name) = self.open_parent(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => {
                // This account's partial for a path that now exists can
                // never be published, so it gives its slot back.
                self.discard_inactive_partial(&partial_base(owner, path));
                return Err(FileError::AlreadyExists);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_lookup_error(error)),
        }
        let overhead = if large { 0 } else { 1_024 };
        if transfer_len
            .is_some_and(|len| len > self.inner.limits.max_file_size.saturating_add(overhead))
        {
            return Err(FileError::TooLarge);
        }
        // Without a declared size only the partial count limits can apply
        // here; the bytes are reserved once the handshake states them.
        self.make_room(owner, &partial_base(owner, path))?;
        self.enforce_partial_quota(owner, path, transfer_len.unwrap_or(0))?;
        if !resume_requested {
            return Ok(None);
        }
        let base = partial_base(owner, path);
        let _quote_guard = self.lock_upload_base(&base)?;
        let data_offset = partial_len(&self.inner.partials, &format!("{base}.data"))?;
        let resource_offset = partial_len(&self.inner.partials, &format!("{base}.rsrc"))?;
        if data_offset == 0 && resource_offset == 0 {
            return Ok(None);
        }
        if large && resource_offset != 0 {
            return Err(FileError::InvalidPath);
        }
        let generation = self.read_upload_generation(&base)?;
        let digest = if large {
            Some(self.resume_digest(&base, data_offset)?)
        } else {
            None
        };
        Ok(Some(UploadQuote {
            data_offset,
            resource_offset,
            generation,
            digest,
        }))
    }

    fn lock_upload_base(&self, base: &str) -> Result<ActiveUploadGuard, FileError> {
        let mut active = self.inner.active_uploads.lock().unwrap();
        if !active.insert(base.to_owned()) {
            return Err(FileError::Busy);
        }
        Ok(ActiveUploadGuard {
            inner: self.inner.clone(),
            base: base.to_owned(),
        })
    }

    fn read_upload_generation(&self, base: &str) -> Result<[u8; UPLOAD_GENERATION_LEN], FileError> {
        let name = format!("{base}.generation");
        let mut file = match self.inner.partials.open(&name) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(FileError::OriginChanged);
            }
            Err(error) => return Err(map_lookup_error(error)),
        };
        if file
            .metadata()
            .map_err(|error| unavailable("stat partial generation", error))?
            .len()
            != UPLOAD_GENERATION_LEN as u64
        {
            return Err(FileError::OriginChanged);
        }
        let mut generation = [0; UPLOAD_GENERATION_LEN];
        file.read_exact(&mut generation)
            .map_err(|error| unavailable("read partial generation", error))?;
        Ok(generation)
    }

    fn replace_upload_generation(
        &self,
        base: &str,
    ) -> Result<[u8; UPLOAD_GENERATION_LEN], FileError> {
        let mut generation = [0; UPLOAD_GENERATION_LEN];
        getrandom::getrandom(&mut generation)
            .map_err(|error| FileError::Unavailable(format!("partial generation: {error}")))?;
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut file = self
            .inner
            .partials
            .open_with(format!("{base}.generation"), &options)
            .map_err(|error| unavailable("open partial generation", error))?;
        file.write_all(&generation)
            .map_err(|error| unavailable("write partial generation", error))?;
        file.sync_all()
            .map_err(|error| unavailable("sync partial generation", error))?;
        Ok(generation)
    }

    /// Makes room under the per-account partial cap for an upload to `base`
    /// by dropping that account's least recently touched partials. Refusing
    /// instead would let a few failed or abandoned uploads lock an account,
    /// and with it every guest, since guests share one, out of uploading
    /// for the whole retention period. A partial being uploaded to is never
    /// dropped; when every one is, the cap refuses as before.
    fn make_room(&self, owner: &str, base: &str) -> Result<(), FileError> {
        let owner_prefix = format!("{}-", owner_key(owner));
        let active = self.inner.active_uploads.lock().unwrap();
        let mut owned: Vec<_> = self
            .partial_bases()?
            .into_iter()
            .filter(|(name, state)| {
                name != base && name.starts_with(&owner_prefix) && state.has_data
            })
            .collect();
        let cap = self.inner.limits.max_partials_per_account;
        if owned.len() < cap {
            return Ok(());
        }
        let excess = owned.len() + 1 - cap;
        owned.retain(|(name, _)| !active.contains(name));
        owned.sort_by_key(|(_, state)| state.newest);
        for (_, state) in owned.iter().take(excess) {
            self.remove_partial_files(&state.names);
        }
        Ok(())
    }

    /// Removes `base`'s files unless an upload is using them.
    fn discard_inactive_partial(&self, base: &str) {
        let active = self.inner.active_uploads.lock().unwrap();
        if !active.contains(base) {
            self.remove_partial_files(&PARTIAL_SUFFIXES.map(|suffix| format!("{base}.{suffix}")));
        }
    }

    fn remove_partial_files(&self, names: &[String]) {
        for name in names {
            let _ = self.inner.partials.remove_file(name);
        }
    }

    /// Every partial on disk, by base name.
    fn partial_bases(&self) -> Result<HashMap<String, PartialState>, FileError> {
        let mut bases: HashMap<String, PartialState> = HashMap::new();
        for entry in self
            .inner
            .partials
            .entries()
            .map_err(|error| unavailable("scan partial directory", error))?
        {
            let entry = entry.map_err(|error| unavailable("scan partial entry", error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some((base, suffix)) = name.rsplit_once('.') else {
                continue;
            };
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            // A time that cannot be read counts as now: it keeps the
            // partial rather than expiring it early.
            let touched = metadata
                .modified()
                .map_or_else(|_| SystemTime::now(), |time| time.into_std());
            let state = bases.entry(base.to_owned()).or_insert(PartialState {
                newest: UNIX_EPOCH,
                has_data: false,
                names: Vec::new(),
            });
            state.newest = state.newest.max(touched);
            state.has_data |= suffix == "data";
            state.names.push(name);
        }
        Ok(bases)
    }

    fn enforce_partial_quota(
        &self,
        owner: &str,
        path: &FilePath,
        incoming: u64,
    ) -> Result<(), FileError> {
        let owner_prefix = format!("{}-", owner_key(owner));
        let current_base = partial_base(owner, path);
        let mut total = 0u64;
        let mut all_bases = HashSet::new();
        let mut owner_bases = HashSet::new();
        for entry in self
            .inner
            .partials
            .entries()
            .map_err(|error| unavailable("scan partial quota", error))?
        {
            let entry = entry.map_err(|error| unavailable("scan partial quota entry", error))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let metadata = entry
                .metadata()
                .map_err(|error| unavailable("stat partial quota entry", error))?;
            if !metadata.is_file() {
                continue;
            }
            if !name.starts_with(&current_base) && !name.ends_with(".generation") {
                total = total
                    .checked_add(metadata.len())
                    .ok_or(FileError::TooLarge)?;
            }
            if name.ends_with(".data") {
                all_bases.insert(name.trim_end_matches(".data").to_owned());
            }
            if name.starts_with(&owner_prefix) && name.ends_with(".data") {
                owner_bases.insert(name.trim_end_matches(".data").to_owned());
            }
        }
        if !all_bases.contains(&current_base) && all_bases.len() >= self.inner.limits.max_partials {
            return Err(FileError::Busy);
        }
        if !owner_bases.contains(&current_base)
            && owner_bases.len() >= self.inner.limits.max_partials_per_account
        {
            return Err(FileError::Busy);
        }
        if total.saturating_add(incoming) > self.inner.limits.max_partial_bytes {
            return Err(FileError::TooLarge);
        }
        Ok(())
    }

    fn resume_digest(
        &self,
        base: &str,
        offset: u64,
    ) -> Result<[u8; hxfiles_xfer::resume_digest::ENCODED_LEN], FileError> {
        let mut file = self
            .inner
            .partials
            .open(format!("{base}.data"))
            .map_err(map_lookup_error)?;
        let window_len = offset.min(hxfiles_xfer::resume_digest::DEFAULT_WINDOW);
        file.seek(SeekFrom::Start(offset - window_len))
            .map_err(|error| unavailable("seek partial digest window", error))?;
        let mut window = vec![0; window_len as usize];
        file.read_exact(&mut window)
            .map_err(|error| unavailable("read partial digest window", error))?;
        hxfiles_xfer::resume_digest::encode(offset, &window)
            .map_err(|_| FileError::Unavailable("partial digest window changed".into()))
    }

    pub(crate) fn begin_upload(
        &self,
        owner: &str,
        path: &FilePath,
        fresh: bool,
        reserve: u64,
    ) -> Result<UploadFiles, FileError> {
        self.sweep_partials()?;
        let base = partial_base(owner, path);
        let active = self.lock_upload_base(&base)?;
        self.make_room(owner, &base)?;
        let guard = UploadGuard {
            inner: self.inner.clone(),
            base: base.clone(),
            _active: active,
        };
        {
            let mut reservations = self.inner.reserved_upload_bytes.lock().unwrap();
            let reserved = reservations.values().try_fold(0u64, |total, value| {
                total.checked_add(*value).ok_or(FileError::TooLarge)
            })?;
            let mut partial_bytes = 0u64;
            let owner_prefix = format!("{}-", owner_key(owner));
            let mut all_bases: HashSet<String> = reservations.keys().cloned().collect();
            let mut owner_bases: HashSet<String> = reservations
                .keys()
                .filter(|name| name.starts_with(&owner_prefix))
                .cloned()
                .collect();
            for entry in self
                .inner
                .partials
                .entries()
                .map_err(|error| unavailable("scan active partial quota", error))?
            {
                let entry =
                    entry.map_err(|error| unavailable("scan active partial quota entry", error))?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let metadata = entry
                    .metadata()
                    .map_err(|error| unavailable("stat active partial quota entry", error))?;
                if metadata.is_file()
                    && !name.starts_with(&base)
                    && !name.ends_with(".generation")
                    && !reservations
                        .keys()
                        .any(|reserved_base| name.starts_with(reserved_base))
                {
                    partial_bytes = partial_bytes
                        .checked_add(metadata.len())
                        .ok_or(FileError::TooLarge)?;
                }
                if metadata.is_file() && name.starts_with(&owner_prefix) && name.ends_with(".data")
                {
                    owner_bases.insert(name.trim_end_matches(".data").to_owned());
                }
                if metadata.is_file() && name.ends_with(".data") {
                    all_bases.insert(name.trim_end_matches(".data").to_owned());
                }
            }
            all_bases.remove(&base);
            if all_bases.len() >= self.inner.limits.max_partials {
                return Err(FileError::Busy);
            }
            owner_bases.remove(&base);
            if owner_bases.len() >= self.inner.limits.max_partials_per_account {
                return Err(FileError::Busy);
            }
            if partial_bytes
                .saturating_add(reserved)
                .saturating_add(reserve)
                > self.inner.limits.max_partial_bytes
            {
                return Err(FileError::TooLarge);
            }
            reservations.insert(base.clone(), reserve);
        }
        let (parent, name) = self.open_parent(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(FileError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_lookup_error(error)),
        }
        if fresh {
            self.replace_upload_generation(&base)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(fresh);
        let data = self
            .inner
            .partials
            .open_with(format!("{base}.data"), &options)
            .map_err(|error| unavailable("open partial data fork", error))?;
        let resource = self
            .inner
            .partials
            .open_with(format!("{base}.rsrc"), &options)
            .map_err(|error| unavailable("open partial resource fork", error))?;
        Ok(UploadFiles {
            base,
            data: data.into_std(),
            resource: resource.into_std(),
            _guard: guard,
        })
    }

    pub(crate) fn recheck_resume(
        &self,
        files: &UploadFiles,
        quote: &UploadQuote,
    ) -> Result<(), FileError> {
        let data_len = files
            .data
            .metadata()
            .map_err(|error| unavailable("stat partial data fork", error))?
            .len();
        let resource_len = files
            .resource
            .metadata()
            .map_err(|error| unavailable("stat partial resource fork", error))?
            .len();
        if data_len != quote.data_offset || resource_len != quote.resource_offset {
            return Err(FileError::OriginChanged);
        }
        if self.read_upload_generation(&files.base)? != quote.generation {
            return Err(FileError::OriginChanged);
        }
        if let Some(expected) = &quote.digest {
            let actual = self.resume_digest(&files.base, data_len)?;
            if !hxfiles_xfer::resume_digest::matches(expected, &actual) {
                return Err(FileError::OriginChanged);
            }
        }
        Ok(())
    }

    pub(crate) fn publish_upload(
        &self,
        path: &FilePath,
        files: &UploadFiles,
        hfs: &hxhfs::HfsInfo,
    ) -> Result<(), FileError> {
        let publish_key = Self::metadata_key(path);
        {
            let mut publishing = self.inner.publishing_paths.lock().unwrap();
            if !publishing.insert(publish_key.clone()) {
                return Err(FileError::Busy);
            }
        }
        let _publish_guard = PublishGuard {
            inner: self.inner.clone(),
            key: publish_key.clone(),
        };
        files
            .data
            .sync_all()
            .map_err(|error| unavailable("sync partial data fork", error))?;
        files
            .resource
            .sync_all()
            .map_err(|error| unavailable("sync partial resource fork", error))?;
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        let mut finder = self
            .inner
            .partials
            .open_with(format!("{}.fndrinfo", files.base), &options)
            .map_err(|error| unavailable("open partial Finder metadata", error))?;
        finder
            .write_all(&hxhfs::hfs::encode_cap_info(hfs))
            .map_err(|error| unavailable("write partial Finder metadata", error))?;
        finder
            .sync_all()
            .map_err(|error| unavailable("sync partial Finder metadata", error))?;

        let (parent, name) = self.open_parent(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(FileError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_lookup_error(error)),
        }
        let final_finder = format!("{publish_key}.fndrinfo");
        let final_resource = format!("{publish_key}.rsrc");
        // These names are private server state. If the visible file is absent,
        // any matching entry is residue from a crash before publication.
        let _ = self.inner.metadata.remove_file(&final_finder);
        let _ = self.inner.metadata.remove_file(&final_resource);
        self.inner
            .partials
            .hard_link(
                format!("{}.fndrinfo", files.base),
                &self.inner.metadata,
                &final_finder,
            )
            .map_err(|error| unavailable("publish Finder metadata", error))?;
        // A link lives in its directory, so it is durable once that
        // directory is synced: the sidecars' before the data is linked, and
        // the destination's after.
        let resource_len = files
            .resource
            .metadata()
            .map_err(|error| unavailable("stat resource fork", error))?
            .len();
        if resource_len != 0 {
            if let Err(error) = self.inner.partials.hard_link(
                format!("{}.rsrc", files.base),
                &self.inner.metadata,
                &final_resource,
            ) {
                let _ = self.inner.metadata.remove_file(&final_finder);
                return Err(unavailable("publish resource fork", error));
            }
        }
        if let Err(error) = sync_dir(&self.inner.metadata) {
            let _ = self.inner.metadata.remove_file(&final_finder);
            let _ = self.inner.metadata.remove_file(&final_resource);
            return Err(error);
        }
        if let Err(error) =
            self.inner
                .partials
                .hard_link(format!("{}.data", files.base), &parent, &name)
        {
            let _ = self.inner.metadata.remove_file(&final_finder);
            let _ = self.inner.metadata.remove_file(&final_resource);
            return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                FileError::AlreadyExists
            } else {
                unavailable("publish data fork", error)
            });
        }
        // The upload is visible now, so a failed sync is not a failed
        // upload; it only leaves the link less durable than it should be.
        if let Err(error) = sync_dir(&parent) {
            tracing::warn!(%error, "upload published but its folder was not synced");
        }
        for suffix in PARTIAL_SUFFIXES {
            let _ = self
                .inner
                .partials
                .remove_file(format!("{}.{}", files.base, suffix));
        }
        Ok(())
    }

    /// The name check catches the plain spelling of the state directory
    /// early; [`Self::descend`] and [`Self::stat`] refuse it however a
    /// case-folding filesystem lets it be spelled. A component longer than
    /// a filesystem name can be is malformed rather than an I/O failure.
    fn validate_path(path: &FilePath) -> Result<(), FileError> {
        if path.components().any(|component| {
            component.eq_ignore_ascii_case(STATE_DIR) || component.len() > NAME_MAX
        }) {
            return Err(FileError::InvalidPath);
        }
        Ok(())
    }

    fn is_state_dir(&self, metadata: &Metadata) -> bool {
        metadata.is_dir()
            && self.inner.state_id.is_some()
            && identity(metadata) == self.inner.state_id
    }

    /// Opens `component` beneath `dir` as a directory, never through a
    /// symlink and never into the server's own state.
    fn descend(&self, dir: &Dir, component: &str) -> Result<Dir, FileError> {
        let metadata = dir.symlink_metadata(component).map_err(map_lookup_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(FileError::NotFolder);
        }
        // Checked above and opened here without following, so a symlink
        // swapped in between the two fails rather than being followed.
        let opened = dir.open_dir_nofollow(component).map_err(map_lookup_error)?;
        let metadata = opened
            .dir_metadata()
            .map_err(|error| unavailable("stat directory", error))?;
        if self.is_state_dir(&metadata) {
            return Err(FileError::InvalidPath);
        }
        Ok(opened)
    }

    fn open_parent(&self, path: &FilePath) -> Result<(Dir, String), FileError> {
        Self::validate_path(path)?;
        let mut components: Vec<_> = path.components().collect();
        let name = components.pop().ok_or(FileError::InvalidPath)?.to_owned();
        let mut dir = self
            .inner
            .root
            .try_clone()
            .map_err(|error| unavailable("clone root directory", error))?;
        for component in components {
            dir = self.descend(&dir, component)?;
        }
        Ok((dir, name))
    }

    fn open_dir(&self, path: &FilePath) -> Result<Dir, FileError> {
        Self::validate_path(path)?;
        let mut dir = self
            .inner
            .root
            .try_clone()
            .map_err(|error| unavailable("clone root directory", error))?;
        for component in path.components() {
            dir = self.descend(&dir, component)?;
        }
        Ok(dir)
    }

    fn stat(&self, path: &FilePath) -> Result<Metadata, FileError> {
        if path.is_root() {
            return self
                .inner
                .root
                .dir_metadata()
                .map_err(|error| unavailable("stat root directory", error));
        }
        let (dir, name) = self.open_parent(path)?;
        let metadata = dir.symlink_metadata(name).map_err(map_lookup_error)?;
        if metadata.file_type().is_symlink() {
            return Err(FileError::NotFound);
        }
        if self.is_state_dir(&metadata) {
            return Err(FileError::InvalidPath);
        }
        Ok(metadata)
    }

    fn metadata_key(path: &FilePath) -> String {
        let digest = Sha256::digest(path.as_slash_path().as_bytes());
        let mut out = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write;
            write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
        }
        out
    }

    fn hfs_info(&self, path: &FilePath) -> hxhfs::HfsInfo {
        let name = format!("{}.fndrinfo", Self::metadata_key(path));
        let Ok(mut file) = self.inner.metadata.open(name) else {
            return hxhfs::HfsInfo::default();
        };
        let mut bytes = [0; 300];
        if file.read_exact(&mut bytes).is_err() {
            return hxhfs::HfsInfo::default();
        }
        hxhfs::hfs::decode_cap_info(&bytes).unwrap_or_default()
    }

    fn resource_len(&self, path: &FilePath) -> u64 {
        let name = format!("{}.rsrc", Self::metadata_key(path));
        self.inner
            .metadata
            .symlink_metadata(name)
            .ok()
            .filter(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
            .map_or(0, |metadata| metadata.len())
    }

    fn visible_entry(
        &self,
        parent: &FilePath,
        entry: DirEntry,
    ) -> Result<Option<VisibleEntry>, FileError> {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            return Ok(None);
        };
        if name.eq_ignore_ascii_case(STATE_DIR) {
            return Ok(None);
        }
        let Ok(path) = parent.join(&name) else {
            return Ok(None);
        };
        let file_type = entry
            .file_type()
            .map_err(|error| unavailable("read file type", error))?;
        if file_type.is_symlink() {
            return Ok(None);
        }
        let kind = if file_type.is_dir() {
            FileKind::Folder
        } else if file_type.is_file() {
            FileKind::File
        } else {
            return Ok(None);
        };
        let metadata = entry
            .metadata()
            .map_err(|error| unavailable("read file metadata", error))?;
        if self.is_state_dir(&metadata) {
            return Ok(None);
        }
        if kind == FileKind::File
            && metadata.len().saturating_add(self.resource_len(&path))
                > self.inner.limits.max_file_size
        {
            return Ok(None);
        }
        Ok(Some(VisibleEntry {
            name,
            kind,
            metadata,
        }))
    }

    fn info_sync(&self, path: &FilePath) -> Result<FileInfo, FileError> {
        let metadata = self.stat(path)?;
        let kind = if metadata.is_dir() {
            FileKind::Folder
        } else if metadata.is_file() {
            FileKind::File
        } else {
            return Err(FileError::NotFound);
        };
        if kind == FileKind::File && metadata.len() > self.inner.limits.max_file_size {
            return Err(FileError::TooLarge);
        }
        let hfs = if kind == FileKind::File {
            self.hfs_info(path)
        } else {
            hxhfs::HfsInfo::default()
        };
        let type_code = (hfs.type_creator[..4] != [0; 4])
            .then(|| hfs.type_creator[..4].try_into().expect("four bytes"));
        let creator_code = (hfs.type_creator[4..] != [0; 4])
            .then(|| hfs.type_creator[4..].try_into().expect("four bytes"));
        let resource_size = if kind == FileKind::File {
            self.resource_len(path)
        } else {
            0
        };
        if kind == FileKind::File
            && metadata.len().saturating_add(resource_size) > self.inner.limits.max_file_size
        {
            return Err(FileError::TooLarge);
        }
        let size = if kind == FileKind::Folder {
            self.count_visible(path, false)?
        } else {
            metadata.len()
        };
        Ok(FileInfo {
            path: path.clone(),
            kind,
            size,
            resource_size,
            type_code,
            creator_code,
            media_type: None,
            created: hfs_header_time(hfs.create_time)
                .or_else(|| header_time(metadata.created().ok())),
            modified: hfs_header_time(hfs.modify_time)
                .or_else(|| header_time(metadata.modified().ok())),
            comment: (!hfs.comment.is_empty()).then(|| text::to_utf8(&hfs.comment)),
        })
    }

    /// The entries of the folder at `path` that a listing would show. As a
    /// size inside another listing, the count stops at the entry limit
    /// rather than failing the listing it appears in.
    fn count_visible(&self, path: &FilePath, capped: bool) -> Result<u64, FileError> {
        let dir = self.open_dir(path)?;
        let limit = self.inner.limits.max_entries as u64;
        let mut count = 0u64;
        for entry in dir
            .entries()
            .map_err(|error| unavailable("list folder metadata", error))?
        {
            let entry = entry.map_err(|error| unavailable("read folder metadata", error))?;
            if self.visible_entry(path, entry)?.is_none() {
                continue;
            }
            if count >= limit {
                return if capped {
                    Ok(limit)
                } else {
                    Err(FileError::TooLarge)
                };
            }
            count += 1;
        }
        Ok(count)
    }

    /// Expires partials whose every file is older than the retention
    /// period. A partial's files go together, judged by the newest of them:
    /// a resume touches the data but not the generation, and losing either
    /// alone would leave a partial that can neither resume nor give way.
    fn sweep_partials(&self) -> Result<(), FileError> {
        let cutoff = SystemTime::now()
            .checked_sub(self.inner.limits.partial_ttl)
            .unwrap_or(UNIX_EPOCH);
        // Hold this lock through the scan so begin_upload cannot make a base
        // active between the membership check and removal.
        let active = self.inner.active_uploads.lock().unwrap();
        for (base, state) in self.partial_bases()? {
            if state.newest < cutoff && !active.contains(&base) {
                self.remove_partial_files(&state.names);
            }
        }
        Ok(())
    }
}

struct PartialState {
    newest: SystemTime,
    has_data: bool,
    names: Vec<String>,
}

/// A directory's identity, which no spelling of its name can change.
fn identity(metadata: &Metadata) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn sync_dir(dir: &Dir) -> Result<(), FileError> {
    // A `Dir` is a path-only handle, which cannot be synced; a readable
    // handle on the same directory can.
    let mut options = OpenOptions::new();
    options.read(true).maybe_dir(true);
    dir.open_with(".", &options)
        .and_then(|file| file.sync_all())
        .map_err(|error| unavailable("sync directory", error))
}

pub(crate) struct UploadFiles {
    pub data: std::fs::File,
    pub resource: std::fs::File,
    base: String,
    _guard: UploadGuard,
}

impl Drop for UploadFiles {
    fn drop(&mut self) {
        // An upload that ends with nothing written leaves nothing to
        // resume, so it gives its partial slot back now rather than at
        // expiry. The base is still held here: the guards drop after this.
        let empty = |file: &std::fs::File| file.metadata().is_ok_and(|m| m.len() == 0);
        if empty(&self.data) && empty(&self.resource) {
            for suffix in PARTIAL_SUFFIXES {
                let _ = self
                    ._guard
                    .inner
                    .partials
                    .remove_file(format!("{}.{suffix}", self.base));
            }
        }
    }
}

struct UploadGuard {
    inner: Arc<Inner>,
    base: String,
    _active: ActiveUploadGuard,
}

struct ActiveUploadGuard {
    inner: Arc<Inner>,
    base: String,
}

struct PublishGuard {
    inner: Arc<Inner>,
    key: String,
}

impl Drop for PublishGuard {
    fn drop(&mut self) {
        self.inner
            .publishing_paths
            .lock()
            .unwrap()
            .remove(&self.key);
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        self.inner
            .reserved_upload_bytes
            .lock()
            .unwrap()
            .remove(&self.base);
    }
}

impl Drop for ActiveUploadGuard {
    fn drop(&mut self) {
        self.inner.active_uploads.lock().unwrap().remove(&self.base);
    }
}

fn owner_key(owner: &str) -> String {
    hex_digest([owner.as_bytes(), b"\0"].concat())
}

fn partial_base(owner: &str, path: &FilePath) -> String {
    format!(
        "{}-{}",
        owner_key(owner),
        hex_digest(path.as_slash_path().as_bytes())
    )
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn partial_len(dir: &Dir, name: &str) -> Result<u64, FileError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            Ok(metadata.len())
        }
        Ok(_) => Err(FileError::InvalidPath),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(unavailable("stat partial", error)),
    }
}

impl FileSource for LocalFileSource {
    fn list<'a>(&'a self, path: &'a FilePath) -> hxd_core::FileFuture<'a, Vec<FileEntry>> {
        let source = self.clone();
        let path = path.clone();
        Box::pin(async move {
            let _permit = source.acquire_io_permit().await?;
            crate::spawn_blocking("files", move || {
                let dir = source.open_dir(&path)?;
                let mut entries = Vec::new();
                for entry in dir
                    .entries()
                    .map_err(|error| unavailable("list directory", error))?
                {
                    let entry =
                        entry.map_err(|error| unavailable("read directory entry", error))?;
                    let Some(visible) = source.visible_entry(&path, entry)? else {
                        continue;
                    };
                    if entries.len() >= source.inner.limits.max_entries {
                        return Err(FileError::TooLarge);
                    }
                    // A classic client shows a folder's size as its item
                    // count, which is what mhxd sends.
                    let size = match visible.kind {
                        FileKind::Folder => {
                            source.count_visible(&path.join(&visible.name)?, true)?
                        }
                        FileKind::File => visible.metadata.len(),
                    };
                    entries.push(FileEntry {
                        name: visible.name,
                        kind: visible.kind,
                        size,
                        media_type: None,
                        modified: header_time(visible.metadata.modified().ok()),
                    });
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            })
            .await
            .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))?
        })
    }

    fn info<'a>(&'a self, path: &'a FilePath) -> hxd_core::FileFuture<'a, FileInfo> {
        let source = self.clone();
        let path = path.clone();
        Box::pin(async move {
            let _permit = source.acquire_io_permit().await?;
            crate::spawn_blocking("files", move || source.info_sync(&path))
                .await
                .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))?
        })
    }

    fn open<'a>(&'a self, path: &'a FilePath, from: u64) -> hxd_core::FileFuture<'a, FileBody> {
        let source = self.clone();
        let path = path.clone();
        Box::pin(async move { source.open_body(&path, from, false).await })
    }

    fn open_resource<'a>(
        &'a self,
        path: &'a FilePath,
        from: u64,
    ) -> hxd_core::FileFuture<'a, FileBody> {
        let source = self.clone();
        let path = path.clone();
        Box::pin(async move { source.open_body(&path, from, true).await })
    }

    fn supports_ranges(&self, _path: &FilePath) -> bool {
        true
    }
}

impl LocalFileSource {
    pub(crate) async fn acquire_io_permit(&self) -> Result<OwnedSemaphorePermit, FileError> {
        tokio::time::timeout(
            self.inner.limits.io_timeout,
            self.inner.permits.clone().acquire_owned(),
        )
        .await
        .map_err(|_| FileError::Busy)?
        .map_err(|_| FileError::Unavailable("local file source stopped".into()))
    }

    async fn open_body(
        &self,
        path: &FilePath,
        from: u64,
        resource: bool,
    ) -> Result<FileBody, FileError> {
        let permit = self.acquire_io_permit().await?;
        let source = self.clone();
        let path = path.clone();
        let (file, len) = crate::spawn_blocking("files", move || {
            let file = if resource {
                source.stat(&path)?;
                let name = format!("{}.rsrc", Self::metadata_key(&path));
                source.inner.metadata.open(name).map_err(map_lookup_error)?
            } else {
                let metadata = source.stat(&path)?;
                if !metadata.is_file() {
                    return Err(FileError::NotFile);
                }
                let (dir, name) = source.open_parent(&path)?;
                let mut options = OpenOptions::new();
                options.read(true).follow(FollowSymlinks::No);
                dir.open_with(name, &options).map_err(map_lookup_error)?
            };
            let metadata = file
                .metadata()
                .map_err(|error| unavailable("read open file metadata", error))?;
            if !metadata.is_file() || metadata.len() > source.inner.limits.max_file_size {
                return Err(FileError::TooLarge);
            }
            if from > metadata.len() {
                return Err(FileError::RangeInvalid);
            }
            Ok((file.into_std(), metadata.len()))
        })
        .await
        .map_err(|error| FileError::Unavailable(format!("local file worker: {error}")))??;
        let mut file = tokio::fs::File::from_std(file);
        file.seek(SeekFrom::Start(from))
            .await
            .map_err(|error| unavailable("seek local file", error))?;
        drop(permit);
        Ok(FileBody {
            len: len - from,
            reader: Box::pin(PermitReader::new(
                file,
                self.inner.permits.clone(),
                self.inner.limits.io_timeout,
            )),
        })
    }
}

fn header_time(time: Option<cap_std::time::SystemTime>) -> Option<u32> {
    let seconds = time?.into_std().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(
        seconds
            .saturating_sub(HEADER_EPOCH)
            .min(u64::from(u32::MAX)) as u32,
    )
}

fn hfs_header_time(bytes: [u8; 4]) -> Option<u32> {
    let value = u32::from_be_bytes(bytes);
    (value != 0).then_some(value)
}

fn map_lookup_error(error: std::io::Error) -> FileError {
    match error.kind() {
        std::io::ErrorKind::NotFound => FileError::NotFound,
        std::io::ErrorKind::NotADirectory => FileError::NotFolder,
        std::io::ErrorKind::PermissionDenied => FileError::NotFound,
        _ => unavailable("local path lookup", error),
    }
}

fn unavailable(context: &str, error: std::io::Error) -> FileError {
    FileError::Unavailable(format!("{context}: {error}"))
}

type PermitAcquire =
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, tokio::sync::AcquireError>> + Send>>;

struct PermitReader<R> {
    inner: R,
    permits: Arc<Semaphore>,
    acquire: Option<PermitAcquire>,
    permit: Option<OwnedSemaphorePermit>,
    timeout: Duration,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<R> PermitReader<R> {
    fn new(inner: R, permits: Arc<Semaphore>, timeout: Duration) -> Self {
        Self {
            inner,
            permits,
            acquire: None,
            permit: None,
            timeout,
            deadline: None,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PermitReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.permit.is_none() {
            if this.acquire.is_none() {
                this.acquire = Some(Box::pin(this.permits.clone().acquire_owned()));
                this.deadline = Some(Box::pin(tokio::time::sleep(this.timeout)));
            }
            match this
                .acquire
                .as_mut()
                .expect("acquire initialized")
                .as_mut()
                .poll(cx)
            {
                Poll::Ready(Ok(permit)) => {
                    this.acquire = None;
                    this.permit = Some(permit);
                }
                Poll::Ready(Err(_)) => {
                    this.acquire = None;
                    this.deadline = None;
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "local file source stopped",
                    )));
                }
                Poll::Pending => {
                    if this
                        .deadline
                        .as_mut()
                        .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
                    {
                        this.acquire = None;
                        this.deadline = None;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "local file read permit timed out",
                        )));
                    }
                    return Poll::Pending;
                }
            }
        }
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.permit = None;
                this.deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                if this
                    .deadline
                    .as_mut()
                    .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
                {
                    this.permit = None;
                    this.deadline = None;
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "local file read timed out",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn internal_state_and_symlinks_are_never_exposed() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("visible.txt"), b"visible").unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        assert_eq!(
            source
                .list(&FilePath::root())
                .await
                .unwrap()
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>(),
            ["visible.txt"]
        );
        assert!(matches!(
            source.info(&FilePath::parse(".hxd-state").unwrap()).await,
            Err(FileError::InvalidPath)
        ));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("visible.txt", temp.path().join("alias.txt")).unwrap();
            assert!(matches!(
                source.info(&FilePath::parse("alias.txt").unwrap()).await,
                Err(FileError::NotFound)
            ));
            assert!(!source
                .list(&FilePath::root())
                .await
                .unwrap()
                .iter()
                .any(|entry| entry.name == "alias.txt"));
        }
    }

    #[tokio::test]
    async fn listing_and_folder_counts_share_the_visibility_rules() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("visible"), b"x").unwrap();
        fs::write(temp.path().join("too-large"), b"xx").unwrap();
        #[cfg(unix)]
        fs::write(temp.path().join("bad\\name"), b"x").unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_file_size: 1,
                max_entries: 1,
                ..LocalLimits::default()
            },
        )
        .unwrap();

        let entries = source.list(&FilePath::root()).await.unwrap();
        assert_eq!(
            entries
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>(),
            ["visible"]
        );
        assert_eq!(source.info(&FilePath::root()).await.unwrap().size, 1);
    }

    #[tokio::test]
    async fn reads_are_bounded_and_support_exact_offsets() {
        use tokio::io::AsyncReadExt;

        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("file"), b"abcdef").unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_file_size: 6,
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let path = FilePath::parse("file").unwrap();
        let mut body = source.open(&path, 2).await.unwrap();
        let mut bytes = Vec::new();
        body.reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(body.len, 4);
        assert_eq!(bytes, b"cdef");
        assert!(matches!(
            source.open(&path, 7).await,
            Err(FileError::RangeInvalid)
        ));
    }

    #[tokio::test]
    async fn an_unpolled_download_does_not_hold_local_io_capacity() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("file"), b"abcdef").unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_concurrent: 1,
                io_timeout: Duration::from_millis(50),
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let path = FilePath::parse("file").unwrap();
        let _unpolled = source.open(&path, 0).await.unwrap();

        assert_eq!(source.info(&path).await.unwrap().size, 6);
    }

    #[tokio::test]
    async fn partials_are_private_owner_bound_and_publish_without_overwrite() {
        use std::io::Write;
        use tokio::io::AsyncReadExt;

        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        let path = FilePath::parse("upload.bin").unwrap();
        let mut partial = source.begin_upload("alice", &path, true, 128).unwrap();
        partial.data.write_all(b"abc").unwrap();
        partial.resource.write_all(b"rsrc").unwrap();
        drop(partial);
        assert!(source.list(&FilePath::root()).await.unwrap().is_empty());

        let quote = source
            .prepare_upload("alice", &path, Some(128), false, true)
            .unwrap()
            .unwrap();
        assert_eq!(quote.data_offset, 3);
        assert_eq!(quote.resource_offset, 4);
        assert!(quote.digest.is_none());
        assert!(source
            .prepare_upload("mallory", &path, Some(128), false, true)
            .unwrap()
            .is_none());

        let partial = source.begin_upload("alice", &path, false, 121).unwrap();
        source.recheck_resume(&partial, &quote).unwrap();
        let hfs = hxhfs::HfsInfo {
            type_creator: *b"BINA????",
            create_time: 5u32.to_be_bytes(),
            modify_time: 7u32.to_be_bytes(),
            rsrclen: 4,
            comment: b"safe".to_vec(),
        };
        source.publish_upload(&path, &partial, &hfs).unwrap();
        assert_eq!(fs::read(temp.path().join("upload.bin")).unwrap(), b"abc");
        let info = source.info(&path).await.unwrap();
        assert_eq!(info.resource_size, 4);
        assert_eq!(info.type_code, Some(*b"BINA"));
        assert_eq!(info.comment.as_deref(), Some("safe"));
        let mut resource = source.open_resource(&path, 0).await.unwrap();
        let mut bytes = Vec::new();
        resource.reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"rsrc");
        assert!(matches!(
            source.prepare_upload("alice", &path, Some(3), false, false),
            Err(FileError::AlreadyExists)
        ));
    }

    #[test]
    fn publication_is_serialized_by_destination_not_upload_owner() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        let path = FilePath::parse("shared.bin").unwrap();
        let mut alice = source.begin_upload("alice", &path, true, 1).unwrap();
        let mut bob = source.begin_upload("bob", &path, true, 1).unwrap();
        alice.data.write_all(b"a").unwrap();
        bob.data.write_all(b"b").unwrap();
        let hfs = hxhfs::HfsInfo {
            type_creator: *b"BINA????",
            create_time: 0u32.to_be_bytes(),
            modify_time: 0u32.to_be_bytes(),
            rsrclen: 0,
            comment: Vec::new(),
        };

        let publish_key = LocalFileSource::metadata_key(&path);
        source
            .inner
            .publishing_paths
            .lock()
            .unwrap()
            .insert(publish_key.clone());
        assert!(matches!(
            source.publish_upload(&path, &bob, &hfs),
            Err(FileError::Busy)
        ));
        assert!(!temp.path().join("shared.bin").exists());
        source
            .inner
            .publishing_paths
            .lock()
            .unwrap()
            .remove(&publish_key);

        source.publish_upload(&path, &alice, &hfs).unwrap();
        assert_eq!(fs::read(temp.path().join("shared.bin")).unwrap(), b"a");
    }

    #[test]
    fn large_resume_digest_is_bound_to_the_exact_partial_and_lock() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        let path = FilePath::parse("large.bin").unwrap();
        let mut partial = source.begin_upload("alice", &path, true, 20).unwrap();
        partial.data.write_all(b"partial").unwrap();
        assert!(matches!(
            source.begin_upload("alice", &path, false, 13),
            Err(FileError::Busy)
        ));
        drop(partial);

        let quote = source
            .prepare_upload("alice", &path, Some(20), true, true)
            .unwrap()
            .unwrap();
        assert_eq!(quote.data_offset, 7);
        assert_eq!(
            quote.digest,
            Some(hxfiles_xfer::resume_digest::encode(7, b"partial").unwrap())
        );
        let partial = source.begin_upload("alice", &path, false, 13).unwrap();
        source.recheck_resume(&partial, &quote).unwrap();
    }

    #[test]
    fn classic_resume_rejects_same_length_partial_replacement() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        let path = FilePath::parse("classic.bin").unwrap();
        let mut original = source.begin_upload("alice", &path, true, 5).unwrap();
        original.data.write_all(b"abc").unwrap();
        original.resource.write_all(b"rs").unwrap();
        drop(original);

        let quote = source
            .prepare_upload("alice", &path, Some(5), false, true)
            .unwrap()
            .unwrap();
        let mut replacement = source.begin_upload("alice", &path, true, 5).unwrap();
        replacement.data.write_all(b"xyz").unwrap();
        replacement.resource.write_all(b"RS").unwrap();
        drop(replacement);

        let resume = source.begin_upload("alice", &path, false, 0).unwrap();
        assert!(matches!(
            source.recheck_resume(&resume, &quote),
            Err(FileError::OriginChanged)
        ));
    }

    #[test]
    fn concurrent_uploads_reserve_the_global_partial_budget() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_partial_bytes: 10,
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let first = source
            .begin_upload("alice", &FilePath::parse("a").unwrap(), true, 6)
            .unwrap();
        assert!(matches!(
            source.begin_upload("alice", &FilePath::parse("b").unwrap(), true, 5),
            Err(FileError::TooLarge)
        ));
        drop(first);
        source
            .begin_upload("alice", &FilePath::parse("b").unwrap(), true, 5)
            .unwrap();
    }

    #[test]
    fn partials_are_globally_bounded_while_their_uploads_run() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_partials: 1,
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let first = source
            .begin_upload("alice", &FilePath::parse("a").unwrap(), true, 0)
            .unwrap();
        assert!(matches!(
            source.begin_upload("bob", &FilePath::parse("b").unwrap(), true, 0),
            Err(FileError::Busy)
        ));
        // Nothing was written, so the partial gives its slot back as the
        // upload ends rather than holding it until expiry.
        drop(first);
        source
            .begin_upload("bob", &FilePath::parse("b").unwrap(), true, 0)
            .unwrap();
    }

    fn partials_dir(root: &Path) -> std::path::PathBuf {
        root.join(STATE_DIR).join(PARTIAL_DIR)
    }

    /// Sets the named files of a partial back to `when`.
    fn touch_partial(root: &Path, base: &str, suffixes: &[&str], when: SystemTime) {
        for suffix in suffixes {
            std::fs::File::options()
                .write(true)
                .open(partials_dir(root).join(format!("{base}.{suffix}")))
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(when))
                .unwrap();
        }
    }

    fn begin_nonempty(source: &LocalFileSource, owner: &str, path: &str) -> String {
        use std::io::Write;

        let mut partial = source
            .begin_upload(owner, &FilePath::parse(path).unwrap(), true, 8)
            .unwrap();
        partial.data.write_all(b"abc").unwrap();
        partial.base.clone()
    }

    #[test]
    fn expired_inactive_partials_are_swept_before_quota_checks() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_partials: 1,
                partial_ttl: Duration::from_secs(1),
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let first = begin_nonempty(&source, "alice", "old");
        touch_partial(
            temp.path(),
            &first,
            &["data", "rsrc", "generation"],
            UNIX_EPOCH,
        );

        source
            .begin_upload("bob", &FilePath::parse("new").unwrap(), true, 0)
            .unwrap();
    }

    #[test]
    fn a_partial_expires_as_a_whole() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                partial_ttl: Duration::from_secs(60),
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let path = FilePath::parse("kept.bin").unwrap();
        let base = begin_nonempty(&source, "alice", "kept.bin");

        // A resume touches the data and not the generation; the partial is
        // as young as its newest file, and still resumes.
        touch_partial(temp.path(), &base, &["data"], UNIX_EPOCH);
        source.sweep_partials().unwrap();
        assert!(source
            .prepare_upload("alice", &path, Some(8), false, true)
            .unwrap()
            .is_some());

        touch_partial(
            temp.path(),
            &base,
            &["data", "rsrc", "generation"],
            UNIX_EPOCH,
        );
        source.sweep_partials().unwrap();
        assert!(fs::read_dir(partials_dir(temp.path()))
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn an_account_at_its_partial_cap_gives_up_its_oldest() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(
            temp.path(),
            LocalLimits {
                max_partials_per_account: 2,
                ..LocalLimits::default()
            },
        )
        .unwrap();
        let older = begin_nonempty(&source, "guest", "older");
        let newer = begin_nonempty(&source, "guest", "newer");
        touch_partial(
            temp.path(),
            &older,
            &["data", "rsrc", "generation"],
            SystemTime::now() - Duration::from_secs(3600),
        );

        source
            .begin_upload("guest", &FilePath::parse("third").unwrap(), true, 8)
            .unwrap();
        let exists = |base: &str| {
            partials_dir(temp.path())
                .join(format!("{base}.data"))
                .exists()
        };
        assert!(!exists(&older), "the least recently touched gave way");
        assert!(exists(&newer));
    }

    #[test]
    fn a_partial_whose_destination_now_exists_is_discarded() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        begin_nonempty(&source, "alice", "taken.bin");
        fs::write(temp.path().join("taken.bin"), b"someone else's").unwrap();

        assert!(matches!(
            source.prepare_upload(
                "alice",
                &FilePath::parse("taken.bin").unwrap(),
                Some(8),
                false,
                true
            ),
            Err(FileError::AlreadyExists)
        ));
        assert!(fs::read_dir(partials_dir(temp.path()))
            .unwrap()
            .next()
            .is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_state_directory_is_refused_by_identity_not_name() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        // Standing in for a spelling a case-folding filesystem resolves to
        // the same directory: the name no longer says what it is.
        fs::rename(temp.path().join(STATE_DIR), temp.path().join("renamed")).unwrap();
        let renamed = FilePath::parse("renamed").unwrap();
        assert!(matches!(
            source.list(&renamed).await,
            Err(FileError::InvalidPath)
        ));
        assert!(matches!(
            source.info(&renamed).await,
            Err(FileError::InvalidPath)
        ));
        assert!(matches!(
            source
                .list(&FilePath::parse("renamed/partials").unwrap())
                .await,
            Err(FileError::InvalidPath)
        ));
        assert!(source.list(&FilePath::root()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn listed_folders_carry_their_child_count() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("folder")).unwrap();
        fs::write(temp.path().join("folder/a"), b"a").unwrap();
        fs::write(temp.path().join("folder/b"), b"b").unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        let root = source.list(&FilePath::root()).await.unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].kind, FileKind::Folder);
        assert_eq!(root[0].size, 2);
    }

    #[test]
    fn names_longer_than_a_filesystem_allows_are_malformed() {
        let temp = tempfile::tempdir().unwrap();
        let source = LocalFileSource::open(temp.path(), LocalLimits::default()).unwrap();
        let long = FilePath::parse(&"x".repeat(NAME_MAX + 1)).unwrap();
        assert!(matches!(
            source.prepare_upload("alice", &long, Some(1), false, false),
            Err(FileError::InvalidPath)
        ));
    }
}
