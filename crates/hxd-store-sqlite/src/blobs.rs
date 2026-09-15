//! Filesystem-backed durable news image bytes (`docs/news.md` §7.2).

use std::fs::{self, DirEntry, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use hxd_core::inbox::StoreError;
use hxd_core::news::{BlobId, BlobStore, BlobSurvey};
use sha2::{Digest, Sha256};
use tracing::warn;

static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

pub struct FileBlobStore {
    root: PathBuf,
}

impl FileBlobStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(StoreError::new)?;
        Ok(Self { root })
    }

    fn hex(id: &BlobId) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in id {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
        out
    }

    fn path(&self, id: &BlobId) -> PathBuf {
        let hex = Self::hex(id);
        self.root.join(&hex[..2]).join(&hex[2..4]).join(hex)
    }

    fn derivative_path(&self, id: &BlobId) -> PathBuf {
        self.path(id).with_extension("l")
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
        if path.exists() {
            return Ok(());
        }
        let parent = path
            .parent()
            .ok_or_else(|| StoreError::new("blob path has no parent"))?;
        fs::create_dir_all(parent).map_err(StoreError::new)?;
        let (temp, mut file) = loop {
            let serial = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
            let temp = parent.join(format!(".stage-{}-{serial}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => break (temp, file),
                // Left by an earlier process that had this pid and died
                // before its rename. The sweep will take it; this write
                // takes the next name.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(StoreError::new(e)),
            }
        };
        file.write_all(bytes).map_err(StoreError::new)?;
        file.sync_all().map_err(StoreError::new)?;
        match fs::rename(&temp, path) {
            Ok(()) => {}
            Err(_e) if path.exists() => {
                let _ = fs::remove_file(&temp);
                return Ok(());
            }
            Err(e) => {
                let _ = fs::remove_file(&temp);
                return Err(StoreError::new(e));
            }
        }
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(StoreError::new)
    }

    /// Every file two directories down, where [`Self::path`] puts them.
    /// The root failing is no store at all, and an error; below it, a
    /// directory that cannot be read is logged and passed over, so one
    /// bad directory does not hide the rest of the archive.
    fn files(&self) -> Result<Vec<PathBuf>, StoreError> {
        let firsts = fs::read_dir(&self.root).map_err(StoreError::new)?;
        let mut out = Vec::new();
        for first in firsts.filter_map(|e| Self::entry(&self.root, e)) {
            if !first.is_dir() {
                continue;
            }
            for second in Self::entries(&first) {
                if second.is_dir() {
                    out.extend(Self::entries(&second).into_iter().filter(|f| f.is_file()));
                }
            }
        }
        Ok(out)
    }

    fn entries(dir: &Path) -> Vec<PathBuf> {
        match fs::read_dir(dir) {
            Ok(read) => read.filter_map(|e| Self::entry(dir, e)).collect(),
            Err(e) => {
                warn!(dir = %dir.display(), "news blob sweep: {e}");
                Vec::new()
            }
        }
    }

    fn entry(dir: &Path, entry: std::io::Result<DirEntry>) -> Option<PathBuf> {
        entry
            .map(|e| e.path())
            .map_err(|e| warn!(dir = %dir.display(), "news blob sweep: {e}"))
            .ok()
    }

    fn id_from_path(path: &Path) -> Option<BlobId> {
        let name = path.file_stem()?.to_str()?;
        if name.len() != 64 {
            return None;
        }
        let mut id = [0u8; 32];
        for (i, slot) in id.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&name[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(id)
    }
}

impl BlobStore for FileBlobStore {
    fn put(&self, bytes: &[u8]) -> Result<BlobId, StoreError> {
        let id: BlobId = Sha256::digest(bytes).into();
        Self::write_atomic(&self.path(&id), bytes)?;
        Ok(id)
    }

    fn get(&self, id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.path(id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::new(e)),
        }
    }

    fn contains(&self, id: &BlobId) -> Result<bool, StoreError> {
        match fs::metadata(self.path(id)) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::new(e)),
        }
    }

    fn put_derivative(&self, id: &BlobId, bytes: &[u8]) -> Result<(), StoreError> {
        Self::write_atomic(&self.derivative_path(id), bytes)
    }

    fn derivative(&self, id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        match fs::read(self.derivative_path(id)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::new(e)),
        }
    }

    fn remove(&self, id: &BlobId) -> Result<(), StoreError> {
        for path in [self.path(id), self.derivative_path(id)] {
            if let Err(e) = fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(StoreError::new(e));
                }
            }
        }
        Ok(())
    }

    fn contains_derivative(&self, id: &BlobId) -> Result<bool, StoreError> {
        match fs::metadata(self.derivative_path(id)) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::new(e)),
        }
    }

    fn survey(&self, older_than: SystemTime) -> Result<BlobSurvey, StoreError> {
        let mut survey = BlobSurvey::default();
        for path in self.files()? {
            let old = fs::metadata(&path)
                .and_then(|m| m.modified())
                .is_ok_and(|at| at < older_than);
            let named = Self::id_from_path(&path);
            let placed =
                named.filter(|id| path == self.path(id) || path == self.derivative_path(id));
            let Some(id) = placed else {
                // Nothing this store would ever read: a write that died
                // between its temporary file and the rename, or a blob's
                // name away from its blob's path. Nothing will ever finish
                // or find it, and nothing else would ever unlink it; and a
                // write takes seconds, not the stage TTL, so an old one is
                // no write in flight. Any other file is not ours to judge.
                let temp = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".stage-"));
                if old && (temp || named.is_some()) {
                    match fs::remove_file(&path) {
                        Ok(()) => survey.strays += 1,
                        Err(e) => warn!(path = %path.display(), "news blob sweep: {e}"),
                    }
                }
                continue;
            };
            if path.extension().is_none() {
                survey.present.insert(id);
            }
            if old {
                survey.old.insert(id);
            }
        }
        Ok(survey)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_stale_temporary_name_is_stepped_over() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBlobStore::open(dir.path()).unwrap();
        let id: BlobId = Sha256::digest(b"after a crash").into();
        let parent = store.path(&id).parent().unwrap().to_owned();
        fs::create_dir_all(&parent).unwrap();
        // What a process that had this pid left behind when it died: the
        // very names this one is about to try.
        let next = TEMP_SERIAL.load(Ordering::Relaxed);
        for serial in next..next + 64 {
            let stale = parent.join(format!(".stage-{}-{serial}", std::process::id()));
            fs::write(stale, b"stale").unwrap();
        }
        assert_eq!(store.put(b"after a crash").unwrap(), id);
        assert!(store.contains(&id).unwrap());
    }

    #[test]
    fn bytes_are_content_addressed_and_derivatives_are_separate() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileBlobStore::open(dir.path()).unwrap();
        let id = store.put(b"canonical").unwrap();
        assert_eq!(store.put(b"canonical").unwrap(), id);
        assert_eq!(
            store.get(&id).unwrap().as_deref(),
            Some(b"canonical".as_slice())
        );
        store.put_derivative(&id, b"legacy").unwrap();
        assert_eq!(
            store.derivative(&id).unwrap().as_deref(),
            Some(b"legacy".as_slice())
        );
        assert!(store.contains_derivative(&id).unwrap());
        store.remove(&id).unwrap();
        assert!(store.get(&id).unwrap().is_none());
        assert!(store.derivative(&id).unwrap().is_none());
        assert!(!store.contains_derivative(&id).unwrap());

        let kept = store.put(b"kept").unwrap();
        let orphan = store.put(b"orphan").unwrap();
        store.put_derivative(&orphan, b"legacy orphan").unwrap();
        let stray = store.path(&kept).with_file_name(".stage-0-0");
        fs::write(&stray, b"half a write").unwrap();
        // A blob's name in a directory its hash does not lead to: nothing
        // looks there, so nothing would ever unlink it by its id.
        let misplaced = dir.path().join("00").join("00").join("ab".repeat(32));
        fs::create_dir_all(misplaced.parent().unwrap()).unwrap();
        fs::write(&misplaced, b"lost").unwrap();
        let operator = store.path(&kept).with_file_name("README");
        fs::write(&operator, b"not ours").unwrap();

        let fresh = store.survey(SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(fresh.present, HashSet::from([kept, orphan]));
        assert!(fresh.old.is_empty(), "nothing is old enough yet");
        assert_eq!(fresh.strays, 0);
        assert!(stray.exists(), "a write that may be in flight is left be");

        let later = store
            .survey(SystemTime::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(later.old, HashSet::from([kept, orphan]));
        assert_eq!(later.strays, 2);
        assert!(!stray.exists(), "the unfinished write is taken");
        assert!(!misplaced.exists(), "and the blob no path leads to");
        assert!(operator.exists(), "a file that is none of ours is left be");
        assert!(
            store.contains(&orphan).unwrap() && store.derivative(&orphan).unwrap().is_some(),
            "and nothing else: which blobs are orphans is the rows' to say"
        );
    }
}
