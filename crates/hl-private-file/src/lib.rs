//! Files only their owner can read, written whole.
//!
//! Each is written into a temporary file of its own beside the target,
//! created `0600` rather than chmodded after (between the two, anyone
//! could read it) and synced, then put in place and the directory
//! synced. A crash leaves a stray temporary file, never a truncated
//! file at the target. The temporary name is random and spelled from
//! nothing else, so a target named as long as a directory entry can be
//! still has room beside it, and processes sharing a volume (each pid 1
//! in its container) never share one. A stray is left alone: it may be
//! another process's, still being written.
//!
//! An error from the temporary file or the directory names it; one from
//! the target does not, since every caller names the target already.
//! Off Unix, the file gets the platform's default mode and the
//! directory is not synced.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` unless a file is there already: then nothing
/// is written and the answer is false. For a key, made once and never
/// overwritten.
///
/// Hard-linked into place, which fails rather than replace a file that
/// appeared meanwhile, so the caller reads the one that won. An error
/// [`placed`] answers true for came after the file was in place.
pub fn create(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let dir = dir_of(path);
    let tmp = write_temp(dir, bytes, None)?;
    let linked = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    // Whichever process placed the file, its entry is synced before
    // either uses it.
    let placed = match linked {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
            ) =>
        {
            return Err(io::Error::new(
                e.kind(),
                format!("{e} (placing it needs a filesystem with hard links)"),
            ))
        }
        Err(e) => return Err(e),
        Ok(()) => true,
    };
    synced(placed, sync_dir(dir))
}

/// `placed`, unless syncing the directory failed: then an error, which
/// says the file is in place only if this call put it there. A file
/// that was there already may not be durable either, and a caller that
/// went on to read it would trust what it cannot yet.
fn synced(placed: bool, sync: io::Result<()>) -> io::Result<bool> {
    match sync {
        Ok(()) => Ok(placed),
        Err(e) if placed => Err(unsynced(e)),
        Err(e) => Err(e),
    }
}

/// Write `bytes` to `path` in place of whatever is there, atomically: a
/// reader sees the old file or the new one, and a failed write leaves
/// the old one as it was.
///
/// The new file is `0600`, or the old file's mode when that is already
/// the owner's alone (`0400`, say); a file readable beyond its owner is
/// made owner-only by its rewrite. An error [`placed`] answers true for
/// came after the new file was in place.
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = dir_of(path);
    let tmp = write_temp(dir, bytes, kept_mode(path))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(dir).map_err(unsynced)
}

/// Whether `e`, from [`create`] or [`replace`], came after the file was
/// in place: readers see it, but a crash may yet take it back.
pub fn placed(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<Unsynced>())
}

#[derive(Debug)]
struct Unsynced(io::Error);

impl std::fmt::Display for Unsynced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (the file is in place, but may not outlast a crash)",
            self.0
        )
    }
}

impl std::error::Error for Unsynced {}

fn unsynced(e: io::Error) -> io::Error {
    io::Error::new(e.kind(), Unsynced(e))
}

fn dir_of(path: &Path) -> &Path {
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

#[cfg(unix)]
fn kept_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).ok()?.permissions().mode() & 0o7777;
    (mode & 0o077 == 0).then_some(mode & 0o700)
}

#[cfg(not(unix))]
fn kept_mode(_path: &Path) -> Option<u32> {
    None
}

/// `bytes` in a new temporary file in `dir`, synced, with `mode` set
/// before anything is written.
fn write_temp(dir: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<PathBuf> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let (tmp, mut f) = loop {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| io::Error::other(format!("the OS CSPRNG: {e}")))?;
        let tmp = dir.join(format!(".hxd-{:016x}.tmp", u64::from_be_bytes(nonce)));
        match opts.open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(named(&tmp, e)),
        }
    };
    let written = (|| {
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    match written {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(named(&tmp, e))
        }
    }
}

/// A rename or a link is only durable once its directory is synced.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| named(dir, e))
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

fn named(path: &Path, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Flavor {
        Create,
        Replace,
    }

    fn write(flavor: Flavor, path: &Path, bytes: &[u8]) -> io::Result<bool> {
        match flavor {
            Flavor::Create => create(path, bytes),
            Flavor::Replace => replace(path, bytes).map(|()| true),
        }
    }

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Owner-only and whole, under the longest name a directory entry
    /// can have, beside a stray another writer left, which is kept.
    #[test]
    fn a_new_file_is_written_whole_and_owner_only() {
        for flavor in [Flavor::Create, Flavor::Replace] {
            for name in ["secret.key".to_string(), "k".repeat(255)] {
                let dir = tempfile::tempdir().unwrap();
                let stray = dir.path().join(".hxd-0123456789abcdef.tmp");
                fs::write(&stray, "half").unwrap();
                #[cfg(unix)]
                chmod(&stray, 0o644);
                let path = dir.path().join(&name);
                assert!(write(flavor, &path, b"seed\n").unwrap(), "{flavor:?}");
                assert_eq!(fs::read(&path).unwrap(), b"seed\n", "{flavor:?}");
                #[cfg(unix)]
                assert_eq!(mode(&path), 0o600, "{flavor:?} {}", name.len());
                assert_eq!(fs::read_to_string(&stray).unwrap(), "half");
                let left = fs::read_dir(dir.path()).unwrap().count();
                assert_eq!(left, 2, "{flavor:?}: nothing beside it but the stray");
            }
        }
    }

    /// A file already there is kept by `create`, mode and all, and
    /// replaced by `replace`, which keeps its mode only while it is the
    /// owner's alone.
    #[cfg(unix)]
    #[test]
    fn a_file_already_there() {
        for (flavor, before, after, content) in [
            (Flavor::Create, 0o644, 0o644, "old"),
            (Flavor::Replace, 0o644, 0o600, "new"),
            (Flavor::Replace, 0o640, 0o600, "new"),
            (Flavor::Replace, 0o400, 0o400, "new"),
            (Flavor::Replace, 0o600, 0o600, "new"),
            (Flavor::Replace, 0o4600, 0o600, "new"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("accounts.toml");
            fs::write(&path, "old").unwrap();
            chmod(&path, before);
            let placed = write(flavor, &path, b"new").unwrap();
            assert_eq!(placed, matches!(flavor, Flavor::Replace), "{flavor:?}");
            assert_eq!(fs::read_to_string(&path).unwrap(), content, "{flavor:?}");
            assert_eq!(mode(&path), after, "{flavor:?} from {before:o}");
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    /// A failed directory sync is answered as one that came after the
    /// file was in place only when this call placed it: one that found
    /// a file there placed nothing.
    #[test]
    fn only_a_file_this_call_placed_is_placed() {
        for this_call in [true, false] {
            let err = synced(this_call, Err(io::ErrorKind::PermissionDenied.into())).unwrap_err();
            assert_eq!(placed(&err), this_call, "{err}");
        }
    }

    /// A write that cannot be made leaves what was there and nothing
    /// beside it, by failures an owner's privileges do not get past: a
    /// parent that is a file, and a target that is a directory.
    #[test]
    fn a_failed_write_leaves_the_old_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("file"), "old").unwrap();
        let err = create(&dir.path().join("file/server.key"), b"new").unwrap_err();
        assert!(err.to_string().contains("/.hxd-"), "{err}");
        assert_eq!(fs::read_to_string(dir.path().join("file")).unwrap(), "old");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.toml");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("inside"), "old").unwrap();
        replace(&path, b"new").unwrap_err();
        assert_eq!(fs::read_to_string(path.join("inside")).unwrap(), "old");
        assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary file left"
        );
    }
}
