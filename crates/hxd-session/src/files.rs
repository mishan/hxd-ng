//! Legacy-wire names, paths, and file reply payloads.

use std::collections::{HashMap, HashSet};

use hxd_core::{FileEntry, FileError, FileInfo, FileKind, FilePath, FileSource};
use hxproto::text;
use sha2::{Digest, Sha256};

pub(crate) const LIST_TAG: u16 = 0x00c8;
// The transfer-size field includes FILP, INFO, DATA, and MACR framing.
// Use the largest framing this server can emit so an entry visible to a
// classic client is guaranteed to remain downloadable after inspection.
const LEGACY_MAX_DATA: u64 = u32::MAX as u64 - 432;

#[derive(Debug, Clone)]
pub(crate) struct WireEntry {
    pub path: FilePath,
    pub entry: FileEntry,
    pub name: Vec<u8>,
}

pub(crate) async fn list(
    source: &dyn FileSource,
    path: &FilePath,
    large: bool,
) -> Result<Vec<WireEntry>, FileError> {
    let entries = source.list(path).await?;
    let visible: Vec<_> = entries
        .into_iter()
        .filter(|entry| large || entry.size <= LEGACY_MAX_DATA)
        .collect();
    let mut base_counts = HashMap::<Vec<u8>, usize>::new();
    let bases: Vec<_> = visible
        .iter()
        .map(|entry| {
            let base = base_name(&entry.name);
            *base_counts.entry(base.clone()).or_default() += 1;
            base
        })
        .collect();
    let mut used = HashSet::new();
    visible
        .into_iter()
        .zip(bases)
        .map(|(entry, base)| {
            let preferred = if base_counts[&base] == 1 {
                base
            } else {
                hashed_name(&entry.name)
            };
            let name = unique_name(&entry.name, preferred, &mut used);
            Ok(WireEntry {
                path: path.join(&entry.name)?,
                entry,
                name,
            })
        })
        .collect()
}

pub(crate) async fn resolve_dir(
    source: &dyn FileSource,
    bytes: Option<&[u8]>,
    large: bool,
) -> Result<FilePath, FileError> {
    let components = match bytes {
        Some(bytes) => parse_dir(bytes)?,
        None => Vec::new(),
    };
    let mut path = FilePath::root();
    for component in components {
        let found = list(source, &path, large)
            .await?
            .into_iter()
            .find(|entry| entry.entry.kind == FileKind::Folder && entry.name == component)
            .ok_or(FileError::NotFound)?;
        path = found.path;
    }
    Ok(path)
}

pub(crate) async fn resolve_file(
    source: &dyn FileSource,
    dir: Option<&[u8]>,
    name: &[u8],
    large: bool,
) -> Result<(FilePath, FileInfo, Vec<u8>), FileError> {
    let parent = resolve_dir(source, dir, large).await?;
    let found = list(source, &parent, large)
        .await?
        .into_iter()
        .find(|entry| entry.entry.kind == FileKind::File && entry.name == name)
        .ok_or(FileError::NotFound)?;
    let info = source.info(&found.path).await?;
    Ok((found.path, info, found.name))
}

pub(crate) fn list_payload(entry: &WireEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + entry.name.len());
    out.extend_from_slice(&type_creator(&entry.entry).0);
    out.extend_from_slice(&type_creator(&entry.entry).1);
    out.extend_from_slice(&(entry.entry.size.min(u32::MAX as u64) as u32).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(entry.name.len() as u32).to_be_bytes());
    out.extend_from_slice(&entry.name);
    out
}

pub(crate) fn type_creator(entry: &FileEntry) -> ([u8; 4], [u8; 4]) {
    if entry.kind == FileKind::Folder {
        return (*b"fldr", *b"MACS");
    }
    let ty = match entry
        .name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("txt" | "md" | "log") => *b"TEXT",
        Some("jpg" | "jpeg") => *b"JPEG",
        Some("png") => *b"PNGf",
        Some("gif") => *b"GIFf",
        Some("sit") => *b"SIT!",
        Some("zip") => *b"ZIP ",
        _ => *b"????",
    };
    (ty, *b"????")
}

pub(crate) fn date(value: Option<u32>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&2000u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&value.unwrap_or(0).to_be_bytes());
    out
}

fn base_name(name: &str) -> Vec<u8> {
    let mut bytes = text::from_utf8(name);
    // GtkHx can display slash-separated paths; keep a literal classic-Mac
    // delimiter from being mistaken for navigation by period clients.
    for byte in &mut bytes {
        if *byte == b':' {
            *byte = b'-';
        }
    }
    bytes.truncate(31);
    bytes
}

fn hashed_name(name: &str) -> Vec<u8> {
    let digest = Sha256::digest(name.as_bytes());
    let suffix = format!(
        "~{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    );
    let mut bytes = text::from_utf8(name);
    for byte in &mut bytes {
        if *byte == b':' {
            *byte = b'-';
        }
    }
    bytes.truncate(31 - suffix.len());
    bytes.extend_from_slice(suffix.as_bytes());
    bytes
}

fn unique_name(name: &str, preferred: Vec<u8>, used: &mut HashSet<Vec<u8>>) -> Vec<u8> {
    if used.insert(preferred.clone()) {
        return preferred;
    }
    let digest = Sha256::digest(name.as_bytes());
    for attempt in 1usize.. {
        let suffix = format!(
            "~{:02x}{:02x}{:02x}{:02x}-{attempt}",
            digest[0], digest[1], digest[2], digest[3]
        );
        let mut candidate = text::from_utf8(name);
        for byte in &mut candidate {
            if *byte == b':' {
                *byte = b'-';
            }
        }
        candidate.truncate(31usize.saturating_sub(suffix.len()));
        candidate.extend_from_slice(suffix.as_bytes());
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("the numeric suffix always offers another wire name")
}

fn parse_dir(bytes: &[u8]) -> Result<Vec<Vec<u8>>, FileError> {
    let count = bytes
        .get(..2)
        .map(|value| u16::from_be_bytes(value.try_into().expect("two bytes")) as usize)
        .ok_or(FileError::InvalidPath)?;
    let mut offset = 2usize;
    let mut components = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.get(offset..offset + 2) != Some(&[0, 0]) {
            return Err(FileError::InvalidPath);
        }
        let len = usize::from(*bytes.get(offset + 2).ok_or(FileError::InvalidPath)?);
        offset += 3;
        let end = offset.checked_add(len).ok_or(FileError::InvalidPath)?;
        let name = bytes.get(offset..end).ok_or(FileError::InvalidPath)?;
        if name.is_empty() {
            return Err(FileError::InvalidPath);
        }
        components.push(name.to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        return Err(FileError::InvalidPath);
    }
    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_parser_is_structural() {
        let bytes = b"\0\x02\0\0\x01a\0\0\x02bc";
        assert_eq!(parse_dir(bytes).unwrap(), [b"a".to_vec(), b"bc".to_vec()]);
        assert!(parse_dir(&bytes[..bytes.len() - 1]).is_err());
        assert!(parse_dir(b"\0\0x").is_err());
    }

    #[test]
    fn collision_suffix_is_stable_and_bounded() {
        let a = hashed_name("abcdefghijklmnopqrstuvwxyz-long-a");
        let b = hashed_name("abcdefghijklmnopqrstuvwxyz-long-b");
        assert_eq!(a.len(), 31);
        assert_eq!(b.len(), 31);
        assert_ne!(a, b);
        assert_eq!(hashed_name("same"), hashed_name("same"));

        let preferred = hashed_name("abcdefghijklmnopqrstuvwxyz-long-a");
        let mut used = HashSet::from([preferred.clone()]);
        let recovered = unique_name("abcdefghijklmnopqrstuvwxyz-long-a", preferred, &mut used);
        assert_eq!(recovered.len(), 31);
        assert_eq!(used.len(), 2);
    }
}
