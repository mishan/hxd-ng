//! Legacy-wire names, paths, and file reply payloads.
//!
//! A wire name is spelled in the connection's encoding, and it is also
//! how the client names the entry back: a path the client sends is matched
//! against the names this connection was listed, byte for byte. So one
//! encoding has to run through listing and resolving alike, and each
//! function here takes the connection's.

use std::collections::{HashMap, HashSet};

use hxd_core::{FileEntry, FileError, FileInfo, FileKind, FilePath, FileSource};
use sha2::{Digest, Sha256};

use crate::encoding::TextEncoding;

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
    enc: TextEncoding,
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
            let base = base_name(enc, &entry.name);
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
                hashed_name(enc, &entry.name)
            };
            let name = unique_name(enc, &entry.name, preferred, &mut used);
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
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<FilePath, FileError> {
    let components = match bytes {
        Some(bytes) => parse_dir(bytes)?,
        None => Vec::new(),
    };
    resolve_folders(source, &components, large, enc, drop_boxes).await
}

/// Whether the path a client spelled, DIR and then a name, names a drop
/// box: mhxd's `check_dropbox`, asked of the names as they were sent and
/// before any is looked up, so that the answer cannot turn on what
/// exists. A DIR that does not parse names nothing; resolving it refuses
/// it.
pub(crate) fn spells_drop_box(enc: TextEncoding, dir: Option<&[u8]>, name: Option<&[u8]>) -> bool {
    let components = dir
        .and_then(|bytes| parse_dir(bytes).ok())
        .unwrap_or_default();
    components
        .iter()
        .map(Vec::as_slice)
        .chain(name)
        .any(|name| enc.decode(name).to_ascii_lowercase().contains("drop box"))
}

/// A folder's entries, as a walk that names something inside it sees
/// them: none, when the folder is a drop box and the asker may not view
/// drop boxes (`drop_boxes`). What is in one is then "not found" whether
/// or not it exists, so a name that reaches one without spelling it (a
/// wire name cut short of "Drop Box") cannot be used to probe it either.
async fn list_within(
    source: &dyn FileSource,
    path: &FilePath,
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<Vec<WireEntry>, FileError> {
    if path.is_drop_box() && !drop_boxes {
        return Err(FileError::NotFound);
    }
    list(source, path, large, enc).await
}

/// What a folder download of `root` sends: every entry below it with its
/// wire names, depth first, each folder before what it holds, in wire-name
/// order. Names are the ones this connection is listed, so a client that
/// asks for one later finds it. A drop box the asker may not view is sent
/// as an empty folder, as a listing shows it. `None` past `max_items`.
pub(crate) async fn walk_folder(
    source: &dyn FileSource,
    root: &FilePath,
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
    max_items: usize,
) -> Result<Option<Vec<(Vec<Vec<u8>>, WireEntry)>>, FileError> {
    let children = |prefix: Vec<Vec<u8>>, path: FilePath| async move {
        let mut entries = match list_within(source, &path, large, enc, drop_boxes).await {
            Err(FileError::NotFound) if path.is_drop_box() => Vec::new(),
            listed => listed?,
        };
        // Reversed, so the stack below pops them in name order.
        entries.sort_by(|a, b| b.name.cmp(&a.name));
        Ok::<_, FileError>(entries.into_iter().map(move |entry| {
            let mut wire = prefix.clone();
            wire.push(entry.name.clone());
            (wire, entry)
        }))
    };
    let mut pending: Vec<_> = children(Vec::new(), root.clone()).await?.collect();
    let mut items = Vec::new();
    while let Some((wire, entry)) = pending.pop() {
        // A file whose name reads as a drop box is one FileGet refuses.
        if entry.entry.kind == FileKind::File && entry.path.is_drop_box() && !drop_boxes {
            continue;
        }
        if entry.entry.kind == FileKind::Folder {
            pending.extend(children(wire.clone(), entry.path.clone()).await?);
        }
        items.push((wire, entry));
        if items.len() + pending.len() > max_items {
            return Ok(None);
        }
    }
    Ok(Some(items))
}

/// The folder `components` name, each matched against the wire names its
/// parent lists.
pub(crate) async fn resolve_folders(
    source: &dyn FileSource,
    components: &[Vec<u8>],
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<FilePath, FileError> {
    let mut path = FilePath::root();
    for component in components {
        let found = list_within(source, &path, large, enc, drop_boxes)
            .await?
            .into_iter()
            .find(|entry| entry.entry.kind == FileKind::Folder && &entry.name == component)
            .ok_or(FileError::NotFound)?;
        path = found.path;
    }
    Ok(path)
}

/// The folder and name a request that acts on one entry names: FILE_NAME
/// in DIR, or, in mhxd's other form of Delete and New Folder, DIR alone,
/// whose last folder is the entry.
pub(crate) fn named(
    dir: Option<&[u8]>,
    name: Option<&[u8]>,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), FileError> {
    let mut components = match dir {
        Some(bytes) => parse_dir(bytes)?,
        None => Vec::new(),
    };
    match name.filter(|name| !name.is_empty()) {
        Some(name) => Ok((components, name.to_vec())),
        None => {
            let last = components.pop().ok_or(FileError::InvalidPath)?;
            Ok((components, last))
        }
    }
}

/// The listed entry `name` in the folder `components` name.
pub(crate) async fn resolve_in(
    source: &dyn FileSource,
    components: &[Vec<u8>],
    name: &[u8],
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<(FilePath, FileInfo, Vec<u8>), FileError> {
    let parent = resolve_folders(source, components, large, enc, drop_boxes).await?;
    let found = list_within(source, &parent, large, enc, drop_boxes)
        .await?
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or(FileError::NotFound)?;
    let info = source.info(&found.path).await?;
    Ok((found.path, info, found.name))
}

/// A name a client gives a new entry, in `parent`. Unlike a name it
/// selects, it is not matched against a listing: it is decoded.
pub(crate) fn new_name(
    parent: &FilePath,
    name: &[u8],
    enc: TextEncoding,
) -> Result<FilePath, FileError> {
    if name.is_empty() || name.len() > 128 {
        return Err(FileError::InvalidPath);
    }
    parent.join(&enc.decode(name))
}

pub(crate) async fn resolve_file(
    source: &dyn FileSource,
    dir: Option<&[u8]>,
    name: &[u8],
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<(FilePath, FileInfo, Vec<u8>), FileError> {
    resolve_named(
        source,
        dir,
        name,
        large,
        enc,
        drop_boxes,
        Some(FileKind::File),
    )
    .await
}

/// A named entry of either kind: Get Info asks about folders too.
pub(crate) async fn resolve_entry(
    source: &dyn FileSource,
    dir: Option<&[u8]>,
    name: &[u8],
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<(FilePath, FileInfo, Vec<u8>), FileError> {
    resolve_named(source, dir, name, large, enc, drop_boxes, None).await
}

async fn resolve_named(
    source: &dyn FileSource,
    dir: Option<&[u8]>,
    name: &[u8],
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
    kind: Option<FileKind>,
) -> Result<(FilePath, FileInfo, Vec<u8>), FileError> {
    let parent = resolve_dir(source, dir, large, enc, drop_boxes).await?;
    let found = list_within(source, &parent, large, enc, drop_boxes)
        .await?
        .into_iter()
        .find(|entry| kind.is_none_or(|kind| entry.entry.kind == kind) && entry.name == name)
        .ok_or(FileError::NotFound)?;
    let info = source.info(&found.path).await?;
    Ok((found.path, info, found.name))
}

/// An unsigned integer field of any width up to eight bytes, as mhxd's
/// `dh_getint` reads one.
pub(crate) fn wire_uint(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    Some(
        bytes
            .iter()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte)),
    )
}

pub(crate) async fn resolve_upload(
    source: &dyn FileSource,
    dir: Option<&[u8]>,
    name: &[u8],
    large: bool,
    enc: TextEncoding,
    drop_boxes: bool,
) -> Result<FilePath, FileError> {
    let parent = resolve_dir(source, dir, large, enc, drop_boxes).await?;
    new_name(&parent, name, enc)
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

/// A file's type, creator and wire comment, as a download sends them in
/// its object: what the area stores, else what its name suggests.
pub(crate) fn file_metadata(enc: TextEncoding, info: &FileInfo) -> ([u8; 4], [u8; 4], Vec<u8>) {
    let entry = FileEntry {
        name: info.path.name().unwrap_or_default().to_owned(),
        kind: info.kind,
        size: info.size,
        media_type: info.media_type.clone(),
        modified: info.modified,
    };
    let (inferred_type, inferred_creator) = type_creator(&entry);
    (
        info.type_code.unwrap_or(inferred_type),
        info.creator_code.unwrap_or(inferred_creator),
        enc.body_capped(info.comment.as_deref().unwrap_or_default(), 255),
    )
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

/// `name` on the wire, cut to `max` bytes at a character boundary.
///
/// GtkHx can display slash-separated paths; keep a literal classic-Mac
/// delimiter from being mistaken for navigation by period clients. The
/// swap is before the conversion and `:` is ASCII, so it is the same in
/// either encoding.
fn wire_name(enc: TextEncoding, name: &str, max: usize) -> Vec<u8> {
    enc.encode_capped(&name.replace(':', "-"), max)
}

fn base_name(enc: TextEncoding, name: &str) -> Vec<u8> {
    wire_name(enc, name, 31)
}

fn hashed_name(enc: TextEncoding, name: &str) -> Vec<u8> {
    let digest = Sha256::digest(name.as_bytes());
    let suffix = format!(
        "~{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    );
    let mut bytes = wire_name(enc, name, 31 - suffix.len());
    bytes.extend_from_slice(suffix.as_bytes());
    bytes
}

fn unique_name(
    enc: TextEncoding,
    name: &str,
    preferred: Vec<u8>,
    used: &mut HashSet<Vec<u8>>,
) -> Vec<u8> {
    if used.insert(preferred.clone()) {
        return preferred;
    }
    let digest = Sha256::digest(name.as_bytes());
    for attempt in 1usize.. {
        let suffix = format!(
            "~{:02x}{:02x}{:02x}{:02x}-{attempt}",
            digest[0], digest[1], digest[2], digest[3]
        );
        let mut candidate = wire_name(enc, name, 31usize.saturating_sub(suffix.len()));
        candidate.extend_from_slice(suffix.as_bytes());
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("the numeric suffix always offers another wire name")
}

pub(crate) fn parse_dir(bytes: &[u8]) -> Result<Vec<Vec<u8>>, FileError> {
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
    fn integer_fields_read_at_any_width() {
        assert_eq!(wire_uint(&[2]), Some(2));
        assert_eq!(wire_uint(&[0, 2]), Some(2));
        assert_eq!(wire_uint(&[0, 0, 0, 0]), Some(0));
        assert_eq!(wire_uint(&[1, 0, 0, 0, 0, 0, 0, 0]), Some(1 << 56));
        assert_eq!(wire_uint(&[]), None);
        assert_eq!(wire_uint(&[0; 9]), None);
    }

    #[test]
    fn dir_parser_is_structural() {
        let bytes = b"\0\x02\0\0\x01a\0\0\x02bc";
        assert_eq!(parse_dir(bytes).unwrap(), [b"a".to_vec(), b"bc".to_vec()]);
        assert!(parse_dir(&bytes[..bytes.len() - 1]).is_err());
        assert!(parse_dir(b"\0\0x").is_err());
    }

    #[test]
    fn an_entry_is_named_in_its_folder_or_as_the_last_folder() {
        let dir = b"\0\x02\0\0\x01a\0\0\x02bc";
        assert_eq!(
            named(Some(dir), Some(b"x")).unwrap(),
            (vec![b"a".to_vec(), b"bc".to_vec()], b"x".to_vec())
        );
        assert_eq!(
            named(None, Some(b"x")).unwrap(),
            (Vec::new(), b"x".to_vec())
        );
        // mhxd's other form: an empty or absent name, and the entry is
        // DIR's last folder.
        for name in [None, Some(&b""[..])] {
            assert_eq!(
                named(Some(dir), name).unwrap(),
                (vec![b"a".to_vec()], b"bc".to_vec())
            );
        }
        assert_eq!(named(None, None), Err(FileError::InvalidPath));
        assert_eq!(named(Some(b"\0\0"), None), Err(FileError::InvalidPath));
    }

    #[test]
    fn collision_suffix_is_stable_and_bounded() {
        let mr = TextEncoding::MacRoman;
        let a = hashed_name(mr, "abcdefghijklmnopqrstuvwxyz-long-a");
        let b = hashed_name(mr, "abcdefghijklmnopqrstuvwxyz-long-b");
        assert_eq!(a.len(), 31);
        assert_eq!(b.len(), 31);
        assert_ne!(a, b);
        assert_eq!(hashed_name(mr, "same"), hashed_name(mr, "same"));

        let preferred = hashed_name(mr, "abcdefghijklmnopqrstuvwxyz-long-a");
        let mut used = HashSet::from([preferred.clone()]);
        let recovered = unique_name(
            mr,
            "abcdefghijklmnopqrstuvwxyz-long-a",
            preferred,
            &mut used,
        );
        assert_eq!(recovered.len(), 31);
        assert_eq!(used.len(), 2);
    }

    #[test]
    fn a_utf8_wire_name_is_cut_on_a_character() {
        let u8 = TextEncoding::Utf8;
        let mr = TextEncoding::MacRoman;
        // Eleven three-byte characters are 33 bytes: the 31-byte field
        // holds ten of them, not ten and two-thirds.
        let name = "\u{3042}".repeat(11);
        assert_eq!(base_name(u8, &name), "\u{3042}".repeat(10).as_bytes());
        assert_eq!(base_name(mr, &name), b"?".repeat(11));
        // The delimiter swap is the same in both.
        assert_eq!(base_name(u8, "a:b\u{e9}"), "a-b\u{e9}".as_bytes());
        assert_eq!(base_name(mr, "a:b\u{e9}"), b"a-b\x8e");
        // A hashed name still fits, and still ends in its suffix.
        let hashed = hashed_name(u8, &name);
        assert!(hashed.len() <= 31);
        assert!(std::str::from_utf8(&hashed).is_ok());
    }
}
