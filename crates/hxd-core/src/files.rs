//! Wire-free contracts for a read-only file area.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

use tokio::io::AsyncRead;

use crate::Uid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FilePath(Vec<String>);

impl FilePath {
    pub fn root() -> Self {
        FilePath(Vec::new())
    }

    pub fn parse(path: &str) -> Result<Self, FileError> {
        if path.is_empty() || path == "/" {
            return Ok(Self::root());
        }
        if path.starts_with('/') || path.ends_with('/') {
            return Err(FileError::InvalidPath);
        }
        Self::from_components(path.split('/').map(str::to_owned))
    }

    pub fn from_components<I>(components: I) -> Result<Self, FileError>
    where
        I: IntoIterator<Item = String>,
    {
        let components: Vec<_> = components.into_iter().collect();
        if components.iter().any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains('/')
                || part.contains('\\')
                || part.contains('\0')
        }) {
            return Err(FileError::InvalidPath);
        }
        Ok(FilePath(components))
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    pub fn join(&self, component: &str) -> Result<Self, FileError> {
        let mut components = self.0.clone();
        components.push(component.to_owned());
        Self::from_components(components)
    }

    pub fn parent(&self) -> Option<Self> {
        let mut components = self.0.clone();
        components.pop()?;
        Some(FilePath(components))
    }

    pub fn name(&self) -> Option<&str> {
        self.0.last().map(String::as_str)
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_slash_path(&self) -> String {
        self.0.join("/")
    }
}

impl fmt::Display for FilePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            f.write_str("/")
        } else {
            f.write_str(&self.as_slash_path())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Folder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub path: FilePath,
    pub kind: FileKind,
    /// Data-fork bytes for a file, direct visible children for a folder.
    pub size: u64,
    /// Classic-Mac resource-fork bytes. Zero for sources without one.
    pub resource_size: u64,
    /// Finder type and creator metadata when the source preserves it.
    pub type_code: Option<[u8; 4]>,
    pub creator_code: Option<[u8; 4]>,
    pub media_type: Option<String>,
    /// Seconds since 2000-01-01, the Hotline header epoch.
    pub created: Option<u32>,
    pub modified: Option<u32>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub kind: FileKind,
    pub size: u64,
    pub media_type: Option<String>,
    pub modified: Option<u32>,
}

pub struct FileBody {
    pub len: u64,
    pub reader: Pin<Box<dyn AsyncRead + Send + 'static>>,
}

impl fmt::Debug for FileBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileBody").field("len", &self.len).finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    InvalidPath,
    NotFound,
    NotFolder,
    NotFile,
    AlreadyExists,
    RangeUnsupported,
    RangeInvalid,
    OriginChanged,
    TooLarge,
    Busy,
    Unavailable(String),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileError::InvalidPath => f.write_str("invalid file path"),
            FileError::NotFound => f.write_str("file not found"),
            FileError::NotFolder => f.write_str("path is not a folder"),
            FileError::NotFile => f.write_str("path is not a file"),
            FileError::AlreadyExists => f.write_str("file already exists"),
            FileError::RangeUnsupported => f.write_str("source does not support resume"),
            FileError::RangeInvalid => f.write_str("resume offset is outside the file"),
            FileError::OriginChanged => f.write_str("origin object changed"),
            FileError::TooLarge => f.write_str("file exceeds the configured size limit"),
            FileError::Busy => f.write_str("file source is busy"),
            FileError::Unavailable(reason) => write!(f, "file source unavailable: {reason}"),
        }
    }
}

impl std::error::Error for FileError {}

pub type FileFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FileError>> + Send + 'a>>;

pub trait FileSource: Send + Sync + 'static {
    fn list<'a>(&'a self, path: &'a FilePath) -> FileFuture<'a, Vec<FileEntry>>;
    fn info<'a>(&'a self, path: &'a FilePath) -> FileFuture<'a, FileInfo>;
    fn open<'a>(&'a self, path: &'a FilePath, from: u64) -> FileFuture<'a, FileBody>;

    fn open_resource<'a>(&'a self, _path: &'a FilePath, from: u64) -> FileFuture<'a, FileBody> {
        Box::pin(async move {
            if from != 0 {
                return Err(FileError::RangeInvalid);
            }
            Ok(FileBody {
                len: 0,
                reader: Box::pin(tokio::io::empty()),
            })
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FilePrincipal {
    pub uid: Uid,
    pub serial: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_hierarchical_and_cannot_escape() {
        let path = FilePath::parse("manuals/1998/read me.txt").unwrap();
        assert_eq!(
            path.components().collect::<Vec<_>>(),
            ["manuals", "1998", "read me.txt"]
        );
        assert_eq!(path.parent().unwrap().as_slash_path(), "manuals/1998");
        assert_eq!(path.name(), Some("read me.txt"));
        for bad in [
            "/absolute",
            "trailing/",
            "a//b",
            "a/../b",
            "a/./b",
            "a\\b",
            "a\0b",
        ] {
            assert_eq!(FilePath::parse(bad), Err(FileError::InvalidPath));
        }
        assert!(FilePath::parse("").unwrap().is_root());
        assert!(FilePath::parse("/").unwrap().is_root());
    }

    #[test]
    fn join_validates_one_component() {
        let root = FilePath::root();
        assert_eq!(root.join("folder").unwrap().to_string(), "folder");
        assert_eq!(root.join("a/b"), Err(FileError::InvalidPath));
        assert_eq!(root.join(".."), Err(FileError::InvalidPath));
    }
}
