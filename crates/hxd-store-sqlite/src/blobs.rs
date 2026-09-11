//! Filesystem-backed durable news image bytes (`docs/news.md` §7.2).

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use hxd_core::inbox::StoreError;
use hxd_core::news::{BlobId, BlobStore};
use sha2::{Digest, Sha256};

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
        let serial = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".stage-{}-{serial}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(StoreError::new)?;
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

    fn files(&self) -> Result<Vec<PathBuf>, StoreError> {
        let mut out = Vec::new();
        for first in fs::read_dir(&self.root).map_err(StoreError::new)? {
            let first = first.map_err(StoreError::new)?.path();
            if !first.is_dir() {
                continue;
            }
            for second in fs::read_dir(first).map_err(StoreError::new)? {
                let second = second.map_err(StoreError::new)?.path();
                if !second.is_dir() {
                    continue;
                }
                for file in fs::read_dir(second).map_err(StoreError::new)? {
                    let file = file.map_err(StoreError::new)?.path();
                    if file.is_file() {
                        out.push(file);
                    }
                }
            }
        }
        Ok(out)
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

    fn sweep_orphans(
        &self,
        keep: &HashSet<BlobId>,
        older_than: SystemTime,
    ) -> Result<u64, StoreError> {
        let mut removed = 0;
        for path in self.files()? {
            let old = fs::metadata(&path)
                .and_then(|m| m.modified())
                .is_ok_and(|at| at < older_than);
            if !old {
                continue;
            }
            let orphan = match Self::id_from_path(&path) {
                Some(id) => !keep.contains(&id),
                // A write that died between its temporary file and the
                // rename. Nothing will ever finish it, and nothing else
                // would ever unlink it.
                None => path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(".stage-")),
            };
            if orphan {
                fs::remove_file(path).map_err(StoreError::new)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let removed = store
            .sweep_orphans(
                &HashSet::from([kept]),
                SystemTime::now() + std::time::Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            removed, 3,
            "the canonical and derivative files were reaped, and the unfinished write"
        );
        assert!(!stray.exists());
        assert!(store.contains(&kept).unwrap());
        assert!(!store.contains(&orphan).unwrap());
        assert!(store.derivative(&orphan).unwrap().is_none());
    }
}
