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
//!
//! The server holds the catalog whole, images and all, as a snapshot
//! that only [`Core::emoji_reload`] replaces: `hxd emoji` writes the
//! store beside a running server, and SIGHUP brings the snapshot up to
//! it. Every read is answered from the snapshot and never touches the
//! store.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use crate::inbox::StoreError;
use crate::media::MediaType;
use crate::Core;

pub mod conformance;
mod gemoji;

/// A catalog entry's id, from 1. Deliberately not a
/// [`crate::media::Handle`]: an emoji is anyone's to fetch, a handle is
/// an authorization, and the draft forbids taking one for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmojiId(pub u32);

/// A name, `[a-z0-9_]{2,32}`. Lowercase only, so `:Party:` and
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

/// A name an entry may be given, by an add or a rename: an
/// [`EmojiName`] that is not one of gemoji's shortcodes, which clients
/// draw as the Unicode emoji they name whatever the server holds. The
/// store's writes take only this, so every writer is held to it, while
/// an entry already named one, before the list had it, loads as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEmojiName(EmojiName);

/// Why a name may not be given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRefused {
    /// Not an [`EmojiName`].
    Malformed,
    /// A common emoji's shortcode.
    Shortcode,
}

impl NewEmojiName {
    pub fn parse(s: &str) -> Result<Self, NameRefused> {
        let name = EmojiName::parse(s).ok_or(NameRefused::Malformed)?;
        if gemoji::is_shortcode(name.as_str()) {
            return Err(NameRefused::Shortcode);
        }
        Ok(NewEmojiName(name))
    }

    pub fn name(&self) -> &EmojiName {
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
        name: &NewEmojiName,
        image: &EmojiImage,
        at: SystemTime,
        max_count: usize,
    ) -> Result<u32, EmojiStoreError>;
    /// A live entry's new name; its own name again changes nothing.
    fn rename(&self, id: EmojiId, name: &NewEmojiName) -> Result<u32, EmojiStoreError>;
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
        name: &NewEmojiName,
        image: &EmojiImage,
        _at: SystemTime,
        max_count: usize,
    ) -> Result<u32, EmojiStoreError> {
        let name = name.name();
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

    fn rename(&self, id: EmojiId, name: &NewEmojiName) -> Result<u32, EmojiStoreError> {
        let name = name.name();
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

/// What the server holds of its catalog ([`Core::with_emoji`]).
pub(crate) struct EmojiState {
    store: Arc<dyn EmojiStore>,
    policy: EmojiPolicy,
    /// A leaf lock: read, clone the `Arc`, release.
    snapshot: Mutex<Arc<Catalog>>,
}

/// One page of [`Core::emoji_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The catalog's revision as this page was read.
    pub revision: u32,
    /// Only what changed since the revision asked about; otherwise every
    /// entry kept, live and removed.
    pub delta: bool,
    /// In ascending id order.
    pub entries: Vec<EmojiEntry>,
    /// Entries past this page remain.
    pub more: bool,
}

impl Core {
    /// Give the server its catalog, loaded from `store` now. An error
    /// is the server's not to start: it would refuse every emoji it has.
    pub fn with_emoji(
        mut self,
        store: Arc<dyn EmojiStore>,
        policy: EmojiPolicy,
    ) -> Result<Self, StoreError> {
        let catalog = store.load()?;
        self.emoji = Some(EmojiState {
            store,
            policy,
            snapshot: Mutex::new(Arc::new(catalog)),
        });
        Ok(self)
    }

    fn emoji_catalog(&self) -> Option<Arc<Catalog>> {
        let state = self.emoji.as_ref()?;
        Some(state.snapshot.lock().unwrap().clone())
    }

    /// `[emoji]`, when the server keeps a catalog.
    pub fn emoji_policy(&self) -> Option<EmojiPolicy> {
        self.emoji.as_ref().map(|e| e.policy)
    }

    pub fn emoji_revision(&self) -> Option<u32> {
        self.emoji_catalog().map(|c| c.revision)
    }

    /// The entries a client holding the catalog at `since` needs, after
    /// `after`, at most `budget` of them. The budget is a count: a wire
    /// derives it from its size limit and the largest entry it can
    /// encode. Never zero, which would answer an empty page with more to
    /// come, forever.
    ///
    /// A revision below the floor may miss a forgotten entry, and one
    /// above the current revision is a catalog restored from before it,
    /// so either is answered whole.
    pub fn emoji_list(
        &self,
        since: Option<u32>,
        after: Option<EmojiId>,
        budget: usize,
    ) -> Option<Listing> {
        assert!(budget > 0, "an emoji listing of no entries a page");
        let catalog = self.emoji_catalog()?;
        let since = since.filter(|r| (catalog.floor..=catalog.revision).contains(r));
        let mut entries = catalog
            .entries
            .iter()
            .filter(|e| since.is_none_or(|r| e.revision > r))
            .filter(|e| after.is_none_or(|a| e.id > a));
        let page: Vec<EmojiEntry> = entries.by_ref().take(budget).cloned().collect();
        Some(Listing {
            revision: catalog.revision,
            delta: since.is_some(),
            entries: page,
            more: entries.next().is_some(),
        })
    }

    /// A live entry's image.
    pub fn emoji_image(&self, id: EmojiId) -> Option<Arc<EmojiImage>> {
        let catalog = self.emoji_catalog()?;
        let entry = catalog.entries.iter().find(|e| e.id == id)?;
        entry.image.clone()
    }

    /// A live entry's image by its hash.
    pub fn emoji_by_hash(&self, hash: &[u8; 32]) -> Option<Arc<EmojiImage>> {
        let catalog = self.emoji_catalog()?;
        catalog
            .entries
            .iter()
            .filter_map(|e| e.image.clone())
            .find(|i| i.hash == *hash)
    }

    /// Read the catalog again and serve it from now on, answering
    /// whether its revision moved. On an error the catalog served stays
    /// as it was. Store I/O: call it off the reactor.
    pub fn emoji_reload(&self) -> Result<bool, StoreError> {
        let Some(state) = self.emoji.as_ref() else {
            return Ok(false);
        };
        let catalog = Arc::new(state.store.load()?);
        let old = std::mem::replace(&mut *state.snapshot.lock().unwrap(), catalog.clone());
        Ok(old.revision != catalog.revision)
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
    fn a_new_name_is_never_a_common_emojis_shortcode() {
        for (name, given) in [
            ("thumbsup", Err(NameRefused::Shortcode)),
            ("joy", Err(NameRefused::Shortcode)),
            ("zzz", Err(NameRefused::Shortcode)),
            ("100", Err(NameRefused::Shortcode)),
            ("+1", Err(NameRefused::Malformed)),
            ("Party", Err(NameRefused::Malformed)),
            ("thumbsup2", Ok(())),
            ("joy_", Ok(())),
            ("party", Ok(())),
        ] {
            assert_eq!(NewEmojiName::parse(name).map(|_| ()), given, "{name:?}");
        }
    }

    #[test]
    fn gemojis_shortcodes_are_sorted_names() {
        let list = gemoji::SHORTCODES;
        assert!(
            list.windows(2).all(|w| w[0] < w[1]),
            "sorted, for the search"
        );
        assert!(list.iter().all(|n| EmojiName::parse(n).is_some()));
    }

    #[test]
    fn the_memory_store_passes_the_conformance_suite() {
        conformance::run(&|| Box::new(MemoryEmoji::default()));
    }

    /// A store whose reads fail while `failing` is set.
    #[derive(Default)]
    struct Flaky {
        inner: MemoryEmoji,
        failing: std::sync::atomic::AtomicBool,
    }

    impl EmojiStore for Flaky {
        fn load(&self) -> Result<Catalog, StoreError> {
            if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(StoreError("the disk is gone".into()));
            }
            self.inner.load()
        }
        fn add(
            &self,
            name: &NewEmojiName,
            image: &EmojiImage,
            at: SystemTime,
            max_count: usize,
        ) -> Result<u32, EmojiStoreError> {
            self.inner.add(name, image, at, max_count)
        }
        fn rename(&self, id: EmojiId, name: &NewEmojiName) -> Result<u32, EmojiStoreError> {
            self.inner.rename(id, name)
        }
        fn remove(
            &self,
            id: EmojiId,
            at: SystemTime,
            keep_removed: usize,
        ) -> Result<u32, EmojiStoreError> {
            self.inner.remove(id, at, keep_removed)
        }
    }

    fn add(store: &dyn EmojiStore, name: &str, seed: u8) -> EmojiId {
        store
            .add(
                &NewEmojiName::parse(name).unwrap(),
                &conformance::image(seed),
                SystemTime::UNIX_EPOCH,
                usize::MAX,
            )
            .unwrap();
        store.load().unwrap().entries.last().unwrap().id
    }

    fn served(store: Arc<dyn EmojiStore>) -> Core {
        Core::new()
            .with_emoji(store, EmojiPolicy::default())
            .unwrap()
    }

    #[test]
    fn a_listing_is_a_delta_from_a_revision_the_catalog_can_answer_and_whole_otherwise() {
        let store = Arc::new(MemoryEmoji::default());
        let [a, b, c, d] = ["aa", "bb", "cc", "dd"].map(|n| add(&*store, n, 1));
        let at = SystemTime::UNIX_EPOCH;
        store.remove(a, at, 0).unwrap(); // 5, forgotten at once: the floor
        store.remove(b, at, usize::MAX).unwrap(); // 6
        store
            .rename(c, &NewEmojiName::parse("ee").unwrap())
            .unwrap(); // 7
        let core = served(store);
        for (since, after, budget, delta, ids, more) in [
            (None, None, 10, false, vec![b, c, d], false),
            (Some(5), None, 10, true, vec![b, c], false),
            (Some(6), None, 10, true, vec![c], false),
            (Some(7), None, 10, true, vec![], false),
            (Some(4), None, 10, false, vec![b, c, d], false),
            (Some(8), None, 10, false, vec![b, c, d], false),
            (None, Some(b), 10, false, vec![c, d], false),
            (None, None, 2, false, vec![b, c], true),
            (None, Some(c), 2, false, vec![d], false),
            (Some(5), None, 1, true, vec![b], true),
        ] {
            let listing = core.emoji_list(since, after, budget).unwrap();
            let got: Vec<EmojiId> = listing.entries.iter().map(|e| e.id).collect();
            assert_eq!(
                (listing.revision, listing.delta, got, listing.more),
                (7, delta, ids, more),
                "since {since:?} after {after:?} budget {budget}"
            );
        }
    }

    #[test]
    fn a_change_between_pages_is_in_the_next_delta_from_the_first_pages_revision() {
        let store = Arc::new(MemoryEmoji::default());
        let [a, b] = ["aa", "bb"].map(|n| add(&*store, n, 1));
        let core = served(store.clone());
        let first = core.emoji_list(None, None, 1).unwrap();
        assert_eq!(first.entries[0].id, a);
        store
            .rename(a, &NewEmojiName::parse("cc").unwrap())
            .unwrap();
        core.emoji_reload().unwrap();
        let second = core.emoji_list(None, Some(a), 1).unwrap();
        assert_eq!(second.entries[0].id, b);
        assert!(!second.more);
        let next = core.emoji_list(Some(first.revision), None, 10).unwrap();
        assert!(next.delta);
        let renamed: Vec<(EmojiId, &str)> = next
            .entries
            .iter()
            .map(|e| (e.id, e.name.as_str()))
            .collect();
        assert_eq!(renamed, [(a, "cc")]);
    }

    #[test]
    fn the_server_serves_the_store_as_of_its_last_reload() {
        let unserved = Core::new();
        assert_eq!(unserved.emoji_policy(), None);
        assert_eq!(unserved.emoji_list(None, None, 10), None);
        assert_eq!(unserved.emoji_reload(), Ok(false));

        let store = Arc::new(MemoryEmoji::default());
        let kept = add(&*store, "kept", 2);
        let core = served(store.clone());
        assert_eq!(core.emoji_policy(), Some(EmojiPolicy::default()));
        assert_eq!(core.emoji_revision(), Some(1));
        let image = core.emoji_image(kept).expect("loaded with the server");
        assert_eq!(core.emoji_by_hash(&image.hash), Some(image));

        let party = add(&*store, "party", 4);
        assert_eq!(core.emoji_image(party), None, "not until a reload");
        assert_eq!(core.emoji_reload(), Ok(true));
        assert_eq!(core.emoji_reload(), Ok(false), "nothing moved since");
        assert_eq!(core.emoji_revision(), Some(2));
        let image = core.emoji_image(party).unwrap();

        store
            .remove(party, SystemTime::UNIX_EPOCH, usize::MAX)
            .unwrap();
        assert!(core.emoji_by_hash(&image.hash).is_some());
        core.emoji_reload().unwrap();
        assert_eq!(core.emoji_image(party), None, "live only");
        assert_eq!(core.emoji_by_hash(&image.hash), None, "live only");
        assert!(core.emoji_image(kept).is_some());
    }

    #[test]
    fn a_store_that_cannot_be_read_stops_the_start_and_leaves_a_reload_as_it_was() {
        let store = Arc::new(Flaky::default());
        let kept = add(&*store, "kept", 2);
        store
            .failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(Core::new()
            .with_emoji(store.clone(), EmojiPolicy::default())
            .is_err());

        store
            .failing
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let core = served(store.clone());
        add(&*store, "party", 4);
        store
            .failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(core.emoji_reload().is_err());
        assert_eq!(core.emoji_revision(), Some(1));
        assert!(core.emoji_image(kept).is_some());
    }
}
