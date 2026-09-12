use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, Metadata, OpenOptions, Permissions};
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
    limits: LocalLimits,
    permits: Arc<Semaphore>,
    active_uploads: Mutex<HashSet<String>>,
    reserved_upload_bytes: Mutex<HashMap<String, u64>>,
}

#[derive(Clone)]
pub struct LocalFileSource {
    inner: Arc<Inner>,
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
            .open_dir(STATE_DIR)
            .map_err(|error| unavailable("open state directory", error))?;
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
                limits,
                permits: Arc::new(Semaphore::new(limits.max_concurrent)),
                active_uploads: Mutex::new(HashSet::new()),
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
        transfer_len: u64,
        large: bool,
        resume_requested: bool,
    ) -> Result<Option<UploadQuote>, FileError> {
        Self::validate_path(path)?;
        if path.is_root() {
            return Err(FileError::InvalidPath);
        }
        let (parent, name) = self.open_parent(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(FileError::AlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_lookup_error(error)),
        }
        let overhead = if large { 0 } else { 1_024 };
        if transfer_len > self.inner.limits.max_file_size.saturating_add(overhead) {
            return Err(FileError::TooLarge);
        }
        self.enforce_partial_quota(owner, path, transfer_len)?;
        if !resume_requested {
            return Ok(None);
        }
        let base = partial_base(owner, path);
        let data_offset = partial_len(&self.inner.partials, &format!("{base}.data"))?;
        let resource_offset = partial_len(&self.inner.partials, &format!("{base}.rsrc"))?;
        if data_offset == 0 && resource_offset == 0 {
            return Ok(None);
        }
        if large && resource_offset != 0 {
            return Err(FileError::InvalidPath);
        }
        let digest = if large {
            Some(self.resume_digest(&base, data_offset)?)
        } else {
            None
        };
        Ok(Some(UploadQuote {
            data_offset,
            resource_offset,
            digest,
        }))
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
            if !name.starts_with(&current_base) {
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
        let base = partial_base(owner, path);
        {
            let mut active = self.inner.active_uploads.lock().unwrap();
            if !active.insert(base.clone()) {
                return Err(FileError::Busy);
            }
        }
        let guard = UploadGuard {
            inner: self.inner.clone(),
            base: base.clone(),
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
        let final_key = Self::metadata_key(path);
        let final_finder = format!("{final_key}.fndrinfo");
        let final_resource = format!("{final_key}.rsrc");
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
        for suffix in ["data", "rsrc", "fndrinfo"] {
            let _ = self
                .inner
                .partials
                .remove_file(format!("{}.{}", files.base, suffix));
        }
        Ok(())
    }

    fn validate_path(path: &FilePath) -> Result<(), FileError> {
        if path
            .components()
            .any(|component| component.eq_ignore_ascii_case(STATE_DIR))
        {
            return Err(FileError::InvalidPath);
        }
        Ok(())
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
            let metadata = dir.symlink_metadata(component).map_err(map_lookup_error)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(FileError::NotFolder);
            }
            dir = dir.open_dir(component).map_err(map_lookup_error)?;
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
            let metadata = dir.symlink_metadata(component).map_err(map_lookup_error)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(FileError::NotFolder);
            }
            dir = dir.open_dir(component).map_err(map_lookup_error)?;
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
            let dir = self.open_dir(path)?;
            let mut count = 0u64;
            for entry in dir
                .entries()
                .map_err(|error| unavailable("list folder metadata", error))?
            {
                let entry = entry.map_err(|error| unavailable("read folder metadata", error))?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let file_type = entry
                    .file_type()
                    .map_err(|error| unavailable("read folder entry type", error))?;
                if !name.eq_ignore_ascii_case(STATE_DIR)
                    && !file_type.is_symlink()
                    && (file_type.is_file() || file_type.is_dir())
                {
                    count += 1;
                    if count > self.inner.limits.max_entries as u64 {
                        return Err(FileError::TooLarge);
                    }
                }
            }
            count
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

    fn sweep_partials(&self) -> Result<(), FileError> {
        let cutoff = SystemTime::now()
            .checked_sub(self.inner.limits.partial_ttl)
            .unwrap_or(UNIX_EPOCH);
        for entry in self
            .inner
            .partials
            .entries()
            .map_err(|error| unavailable("scan partial directory", error))?
        {
            let entry = entry.map_err(|error| unavailable("scan partial entry", error))?;
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_file()
                && metadata
                    .modified()
                    .is_ok_and(|time| time.into_std() < cutoff)
            {
                let _ = self.inner.partials.remove_file(entry.file_name());
            }
        }
        Ok(())
    }
}

pub(crate) struct UploadFiles {
    pub data: std::fs::File,
    pub resource: std::fs::File,
    base: String,
    _guard: UploadGuard,
}

struct UploadGuard {
    inner: Arc<Inner>,
    base: String,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        self.inner.active_uploads.lock().unwrap().remove(&self.base);
        self.inner
            .reserved_upload_bytes
            .lock()
            .unwrap()
            .remove(&self.base);
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
            tokio::task::spawn_blocking(move || {
                let dir = source.open_dir(&path)?;
                let mut entries = Vec::new();
                for entry in dir
                    .entries()
                    .map_err(|error| unavailable("list directory", error))?
                {
                    if entries.len() >= source.inner.limits.max_entries {
                        return Err(FileError::TooLarge);
                    }
                    let entry =
                        entry.map_err(|error| unavailable("read directory entry", error))?;
                    let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if name.eq_ignore_ascii_case(STATE_DIR) {
                        continue;
                    }
                    let file_type = entry
                        .file_type()
                        .map_err(|error| unavailable("read file type", error))?;
                    if file_type.is_symlink() {
                        continue;
                    }
                    let kind = if file_type.is_dir() {
                        FileKind::Folder
                    } else if file_type.is_file() {
                        FileKind::File
                    } else {
                        continue;
                    };
                    let metadata = entry
                        .metadata()
                        .map_err(|error| unavailable("read file metadata", error))?;
                    if kind == FileKind::File && metadata.len() > source.inner.limits.max_file_size
                    {
                        continue;
                    }
                    entries.push(FileEntry {
                        name,
                        kind,
                        size: metadata.len(),
                        media_type: None,
                        modified: header_time(metadata.modified().ok()),
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
            tokio::task::spawn_blocking(move || source.info_sync(&path))
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
        let (file, len) = tokio::task::spawn_blocking(move || {
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
                dir.open(name).map_err(map_lookup_error)?
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
        Ok(FileBody {
            len: len - from,
            reader: Box::pin(PermitReader {
                inner: file,
                _permit: permit,
            }),
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

struct PermitReader<R> {
    inner: R,
    _permit: OwnedSemaphorePermit,
}

impl<R: AsyncRead + Unpin> AsyncRead for PermitReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
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
            .prepare_upload("alice", &path, 128, false, true)
            .unwrap()
            .unwrap();
        assert_eq!(quote.data_offset, 3);
        assert_eq!(quote.resource_offset, 4);
        assert!(quote.digest.is_none());
        assert!(source
            .prepare_upload("mallory", &path, 128, false, true)
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
            source.prepare_upload("alice", &path, 3, false, false),
            Err(FileError::AlreadyExists)
        ));
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
            .prepare_upload("alice", &path, 20, true, true)
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
    fn zero_length_partials_are_globally_bounded() {
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
        drop(first);
        assert!(matches!(
            source.begin_upload("bob", &FilePath::parse("b").unwrap(), true, 0),
            Err(FileError::Busy)
        ));
    }
}
