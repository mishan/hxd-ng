//! Server emoji: a small catalog of images an operator curates, named
//! by shortcode and drawn by every capable reader (the Server Emoji
//! draft, `Capabilities-Server-Emoji.md`).
//!
//! An entry is known by its [`EmojiId`], which the store assigns and
//! never gives again, so a reference or a reaction naming it always
//! means the same picture. A name is a label that may move; an image is
//! never changed, only removed, and a removed entry keeps its id and
//! last name so what named it can still say `:name:`.
//!
//! The catalog has a revision, spent once by every change, so that a
//! client holding it at one revision fetches only what changed since.
//! Removed entries are kept up to a count and then forgotten lowest
//! revision first; `floor` is the highest revision forgotten, below
//! which a client can be told only the whole catalog.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::inbox::StoreError;
use crate::media::MediaType;

pub mod conformance;

/// A catalog entry's id, from 1. Deliberately not a
/// [`crate::media::Handle`]: an emoji is anyone's to fetch, a handle is
/// an authorization, and the draft forbids taking one for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmojiId(pub u32);

/// A shortcode, `[a-z0-9_]{2,32}`. Lowercase only, so `:Party:` and
/// `:party:` are never two emoji, and nothing a name holds can be markup,
/// a URL or a bidirectional control.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EmojiName(String);

impl EmojiName {
    pub fn parse(s: &str) -> Option<Self> {
        let ok = (2..=32).contains(&s.len())
            && s.bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'));
        ok.then(|| EmojiName(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EmojiName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A stored image, as the codec made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmojiImage {
    /// SHA-256 of `bytes`.
    pub hash: [u8; 32],
    pub mime: MediaType,
    pub width: u16,
    pub height: u16,
    pub animated: bool,
    pub bytes: Arc<[u8]>,
}

impl EmojiImage {
    /// The image with its hash measured from its bytes.
    pub fn new(
        mime: MediaType,
        width: u16,
        height: u16,
        animated: bool,
        bytes: impl Into<Arc<[u8]>>,
    ) -> Self {
        let bytes = bytes.into();
        EmojiImage {
            hash: Sha256::digest(&bytes).into(),
            mime,
            width,
            height,
            animated,
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmojiEntry {
    pub id: EmojiId,
    pub name: EmojiName,
    /// The catalog revision this entry last changed at.
    pub revision: u32,
    /// `None` once removed.
    pub image: Option<Arc<EmojiImage>>,
}

/// Every entry a store keeps, live and removed, in ascending id order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    pub revision: u32,
    /// The highest revision of an entry forgotten.
    pub floor: u32,
    pub entries: Vec<EmojiEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmojiStoreError {
    /// A live entry has that name.
    NameTaken,
    /// No live entry has that id.
    NoSuchEmoji,
    /// The live entries are at the count asked for.
    CatalogFull,
    Store(StoreError),
}

impl From<StoreError> for EmojiStoreError {
    fn from(e: StoreError) -> Self {
        EmojiStoreError::Store(e)
    }
}

impl std::fmt::Display for EmojiStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmojiStoreError::NameTaken => f.write_str("an emoji already has that name"),
            EmojiStoreError::NoSuchEmoji => f.write_str("no emoji has that id"),
            EmojiStoreError::CatalogFull => f.write_str("the emoji catalog is full"),
            EmojiStoreError::Store(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for EmojiStoreError {}

/// The most live entries a server may keep: the whole catalog is held in
/// memory, bytes and all, so this and [`MAX_BYTES_CEILING`] bound it.
pub const MAX_COUNT_CEILING: usize = 1000;
/// The codec refuses anything smaller ([`crate::media::CodecLimits`]'s
/// `min_bytes`), so a smaller limit would refuse every image.
pub const MIN_BYTES: usize = 64;
/// An image travels in one classic field.
pub const MAX_BYTES_CEILING: usize = 65535;
pub const MIN_DIMENSION: u32 = 64;
pub const MAX_DIMENSION_CEILING: u32 = 256;
pub const MIN_FRAMES: u32 = 16;
/// `[media] max_frames`'s default, which an emoji has no cause to pass.
pub const MAX_FRAMES_CEILING: u32 = 150;

/// `[emoji]`, as far as the domain is concerned. The defaults are the
/// draft's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmojiPolicy {
    /// Live entries; as many removed ones are kept.
    pub max_count: usize,
    pub max_bytes: usize,
    /// Images are fitted within this square.
    pub max_dimension: u32,
    pub max_frames: u32,
}

impl Default for EmojiPolicy {
    fn default() -> Self {
        EmojiPolicy {
            max_count: 200,
            max_bytes: 16384,
            max_dimension: 128,
            max_frames: 50,
        }
    }
}

/// Where the catalog is kept. Every write answers the catalog's revision
/// after it, and spends one only when it changed something.
pub trait EmojiStore: Send + Sync + 'static {
    fn load(&self) -> Result<Catalog, StoreError>;
    /// A new entry under a new id, unless `max_count` live entries exist.
    fn add(
        &self,
        name: &EmojiName,
        image: &EmojiImage,
        at: SystemTime,
        max_count: usize,
    ) -> Result<u32, EmojiStoreError>;
    /// A live entry's new name; its own name again changes nothing.
    fn rename(&self, id: EmojiId, name: &EmojiName) -> Result<u32, EmojiStoreError>;
    /// Marks a live entry removed and drops its image, then forgets the
    /// lowest-revision removed entries past `keep_removed`. By revision,
    /// never by time: the revision is the one order every writer agrees
    /// on, where clocks may not.
    fn remove(
        &self,
        id: EmojiId,
        at: SystemTime,
        keep_removed: usize,
    ) -> Result<u32, EmojiStoreError>;
}

/// The store the domain's tests use.
#[derive(Default)]
pub struct MemoryEmoji {
    inner: Mutex<(Catalog, u32)>,
}

impl EmojiStore for MemoryEmoji {
    fn load(&self) -> Result<Catalog, StoreError> {
        Ok(self.inner.lock().unwrap().0.clone())
    }

    fn add(
        &self,
        name: &EmojiName,
        image: &EmojiImage,
        _at: SystemTime,
        max_count: usize,
    ) -> Result<u32, EmojiStoreError> {
        let (catalog, last_id) = &mut *self.inner.lock().unwrap();
        let live = || catalog.entries.iter().filter(|e| e.image.is_some());
        if live().any(|e| e.name == *name) {
            return Err(EmojiStoreError::NameTaken);
        }
        if live().count() >= max_count {
            return Err(EmojiStoreError::CatalogFull);
        }
        *last_id += 1;
        catalog.revision += 1;
        catalog.entries.push(EmojiEntry {
            id: EmojiId(*last_id),
            name: name.clone(),
            revision: catalog.revision,
            image: Some(Arc::new(image.clone())),
        });
        Ok(catalog.revision)
    }

    fn rename(&self, id: EmojiId, name: &EmojiName) -> Result<u32, EmojiStoreError> {
        let (catalog, _) = &mut *self.inner.lock().unwrap();
        let Some(at) = catalog
            .entries
            .iter()
            .position(|e| e.id == id && e.image.is_some())
        else {
            return Err(EmojiStoreError::NoSuchEmoji);
        };
        if catalog.entries[at].name == *name {
            return Ok(catalog.revision);
        }
        if catalog
            .entries
            .iter()
            .any(|e| e.image.is_some() && e.name == *name)
        {
            return Err(EmojiStoreError::NameTaken);
        }
        catalog.revision += 1;
        let entry = &mut catalog.entries[at];
        entry.name = name.clone();
        entry.revision = catalog.revision;
        Ok(catalog.revision)
    }

    fn remove(
        &self,
        id: EmojiId,
        _at: SystemTime,
        keep_removed: usize,
    ) -> Result<u32, EmojiStoreError> {
        let (catalog, _) = &mut *self.inner.lock().unwrap();
        let Some(entry) = catalog
            .entries
            .iter_mut()
            .find(|e| e.id == id && e.image.is_some())
        else {
            return Err(EmojiStoreError::NoSuchEmoji);
        };
        catalog.revision += 1;
        entry.revision = catalog.revision;
        entry.image = None;
        let mut removed: Vec<u32> = catalog
            .entries
            .iter()
            .filter(|e| e.image.is_none())
            .map(|e| e.revision)
            .collect();
        if removed.len() > keep_removed {
            removed.sort_unstable();
            let last = removed[removed.len() - keep_removed - 1];
            catalog
                .entries
                .retain(|e| e.image.is_some() || e.revision > last);
            catalog.floor = catalog.floor.max(last);
        }
        Ok(catalog.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_lowercase_ascii_words_of_two_to_thirty_two() {
        for (name, ok) in [
            ("ab", true),
            ("party_parrot_2", true),
            ("_", false),
            ("a", false),
            ("", false),
            (&"x".repeat(32), true),
            (&"x".repeat(33), false),
            ("Party", false),
            ("party-parrot", false),
            (":party:", false),
            ("party parrot", false),
            ("p\u{e4}rty", false),
            ("party\u{202e}", false),
        ] {
            assert_eq!(EmojiName::parse(name).is_some(), ok, "{name:?}");
        }
    }

    #[test]
    fn the_memory_store_passes_the_conformance_suite() {
        conformance::run(&|| Box::new(MemoryEmoji::default()));
    }
}
