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

/// A name bound to an id for one line or message, as its sender's client
/// sent it beside the text: what makes `:name:` there an emoji. The text
/// itself is never read for names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmojiRef {
    pub id: EmojiId,
    pub name: EmojiName,
}

/// The most refs one line or message keeps: the first this many sent,
/// the rest unread.
pub const MAX_REFS: usize = 32;

/// The refs a line or message kept ([`Core::emoji_keep`]): one to
/// [`MAX_REFS`] of them, each id once, each naming a live entry by its
/// name when it was sent. Made only there and by [`EmojiRefs::unpack`],
/// so a store holds none other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmojiRefs(Arc<[EmojiRef]>);

impl EmojiRefs {
    pub fn refs(&self) -> &[EmojiRef] {
        &self.0
    }

    /// How the stores keep them: a count, then each id and its name.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.packed_len());
        out.push(self.0.len() as u8);
        for r in self.0.iter() {
            out.extend_from_slice(&r.id.0.to_be_bytes());
            out.push(r.name.as_str().len() as u8);
            out.extend_from_slice(r.name.as_str().as_bytes());
        }
        out
    }

    pub(crate) fn packed_len(&self) -> usize {
        1 + self
            .0
            .iter()
            .map(|r| 5 + r.name.as_str().len())
            .sum::<usize>()
    }

    /// [`EmojiRefs::pack`]'s bytes back, or `None` for bytes it never
    /// wrote.
    pub fn unpack(b: &[u8]) -> Option<Self> {
        let (&n, mut rest) = b.split_first()?;
        let mut refs: Vec<EmojiRef> = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let id = EmojiId(u32::from_be_bytes(rest.get(..4)?.try_into().ok()?));
            let len = usize::from(*rest.get(4)?);
            let name = std::str::from_utf8(rest.get(5..5 + len)?).ok()?;
            refs.push(EmojiRef {
                id,
                name: EmojiName::parse(name)?,
            });
            rest = &rest[5 + len..];
        }
        let unique = refs
            .iter()
            .enumerate()
            .all(|(i, r)| refs[..i].iter().all(|k| k.id != r.id));
        (rest.is_empty() && (1..=MAX_REFS).contains(&refs.len()) && unique)
            .then(|| EmojiRefs(refs.into()))
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

    pub(crate) fn emoji_catalog(&self) -> Option<Arc<Catalog>> {
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

    /// What a line or message keeps of the refs its sender sent: of the
    /// first [`MAX_REFS`], each whose id names a live entry under exactly
    /// its name, then each id once, the first kept, in the order sent.
    /// Never an error: a message is never refused over its refs. Read
    /// from the snapshot, so a ref to an emoji added since the last
    /// reload is dropped and one removed since is kept.
    pub fn emoji_keep(&self, sent: &[EmojiRef]) -> Option<EmojiRefs> {
        if sent.is_empty() {
            return None;
        }
        let catalog = self.emoji_catalog()?;
        let mut kept: Vec<EmojiRef> = Vec::new();
        for r in sent.iter().take(MAX_REFS) {
            let named = catalog
                .entries
                .binary_search_by_key(&r.id, |e| e.id)
                .ok()
                .map(|at| &catalog.entries[at])
                .is_some_and(|e| e.image.is_some() && e.name == r.name);
            if named && kept.iter().all(|k| k.id != r.id) {
                kept.push(r.clone());
            }
        }
        (!kept.is_empty()).then(|| EmojiRefs(kept.into()))
    }

    /// Read the catalog again and serve it from now on, answering
    /// whether its revision moved. On an error the catalog served stays
    /// as it was. Store I/O: call it off the reactor.
    ///
    /// A move is told to every session that reads the catalog, once
    /// however many edits it covers, and after the swap: a session that
    /// read the revision before it hears of the new one.
    pub fn emoji_reload(&self) -> Result<bool, StoreError> {
        let Some(state) = self.emoji.as_ref() else {
            return Ok(false);
        };
        let catalog = Arc::new(state.store.load()?);
        let old = std::mem::replace(&mut *state.snapshot.lock().unwrap(), catalog.clone());
        let moved = old.revision != catalog.revision;
        if moved {
            let ev = crate::roster::Event::EmojiChanged {
                revision: catalog.revision,
            };
            let mut r = self.roster.lock().unwrap();
            let readers: Vec<crate::roster::Uid> = (r.users.iter())
                .filter(|(_, s)| s.info.transport.emoji)
                .map(|(uid, _)| *uid)
                .collect();
            for uid in readers {
                r.send_to(uid, ev.clone());
            }
        }
        Ok(moved)
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

    fn named(id: EmojiId, name: &str) -> EmojiRef {
        EmojiRef {
            id,
            name: EmojiName::parse(name).unwrap(),
        }
    }

    #[test]
    fn a_ref_is_kept_only_naming_a_live_emoji_by_its_name_once_as_sent() {
        let store = Arc::new(MemoryEmoji::default());
        let [party, polly, gone] = ["party", "old_name", "gone"].map(|n| add(&*store, n, 1));
        store
            .rename(polly, &NewEmojiName::parse("polly").unwrap())
            .unwrap();
        store
            .remove(gone, SystemTime::UNIX_EPOCH, usize::MAX)
            .unwrap();
        let core = served(store.clone());
        let fresh = add(&*store, "fresh", 2);
        let going = add(&*store, "going", 3);
        core.emoji_reload().unwrap();
        store
            .remove(going, SystemTime::UNIX_EPOCH, usize::MAX)
            .unwrap();
        add(&*store, "unread", 4);
        let filler = |n: usize| vec![named(EmojiId(999), "nobody"); n];
        for (case, sent, kept) in [
            (
                "live",
                vec![named(party, "party")],
                vec![named(party, "party")],
            ),
            (
                "renamed, by its old name",
                vec![named(polly, "old_name")],
                vec![],
            ),
            (
                "renamed, by its new one",
                vec![named(polly, "polly")],
                vec![named(polly, "polly")],
            ),
            ("removed", vec![named(gone, "gone")], vec![]),
            ("never given", vec![named(EmojiId(999), "party")], vec![]),
            ("another's name", vec![named(party, "polly")], vec![]),
            (
                "added since the reload",
                vec![named(EmojiId(6), "unread")],
                vec![],
            ),
            (
                "removed since it",
                vec![named(going, "going")],
                vec![named(going, "going")],
            ),
            (
                "the first that names it right",
                vec![
                    named(party, "bad"),
                    named(party, "party"),
                    named(party, "party"),
                ],
                vec![named(party, "party")],
            ),
            (
                "in the order sent",
                vec![
                    named(fresh, "fresh"),
                    named(gone, "gone"),
                    named(party, "party"),
                ],
                vec![named(fresh, "fresh"), named(party, "party")],
            ),
            (
                "within the first 32",
                [filler(MAX_REFS - 1), vec![named(party, "party")]].concat(),
                vec![named(party, "party")],
            ),
            (
                "past them",
                [filler(MAX_REFS), vec![named(party, "party")]].concat(),
                vec![],
            ),
            ("none sent", vec![], vec![]),
        ] {
            let got = core.emoji_keep(&sent);
            assert_eq!(
                got.as_ref().map_or(&[][..], |k| k.refs()),
                &kept[..],
                "{case}"
            );
        }
        assert_eq!(
            Core::new().emoji_keep(&[named(party, "party")]),
            None,
            "no catalog"
        );
    }

    #[test]
    fn kept_refs_pack_and_back_and_nothing_else_unpacks() {
        let store = Arc::new(MemoryEmoji::default());
        let ids: Vec<EmojiId> = (0..MAX_REFS)
            .map(|n| add(&*store, &format!("e{n}{}", "x".repeat(29)), 1))
            .collect();
        let core = served(store);
        let longest: Vec<EmojiRef> = (ids.iter().enumerate())
            .map(|(n, &id)| named(id, &format!("e{n}{}", "x".repeat(29))))
            .collect();
        for sent in [vec![longest[0].clone()], longest] {
            let kept = core.emoji_keep(&sent).unwrap();
            assert_eq!(kept.packed_len(), kept.pack().len());
            assert_eq!(EmojiRefs::unpack(&kept.pack()), Some(kept));
        }
        let one =
            |id: u32, name: &[u8]| [&id.to_be_bytes()[..], &[name.len() as u8], name].concat();
        let many = |n: u8| {
            [
                &[n][..],
                &(1..=u32::from(n))
                    .map(|i| one(i, b"ab"))
                    .collect::<Vec<_>>()
                    .concat(),
            ]
            .concat()
        };
        assert!(EmojiRefs::unpack(&many(MAX_REFS as u8)).is_some());
        for (case, bytes) in [
            ("nothing", vec![]),
            ("none", vec![0]),
            ("past the bound", many(MAX_REFS as u8 + 1)),
            ("cut short", many(2)[..12].to_vec()),
            ("more after", [many(1), vec![0]].concat()),
            ("no name", [vec![1], one(1, b"Party")].concat()),
            (
                "one id twice",
                [vec![2], one(1, b"ab"), one(1, b"cd")].concat(),
            ),
        ] {
            assert_eq!(EmojiRefs::unpack(&bytes), None, "{case}");
        }
    }

    #[test]
    fn a_reload_that_moves_the_catalog_tells_each_session_that_reads_it_once() {
        let store = Arc::new(MemoryEmoji::default());
        let core = served(store.clone());
        let attach = |login: &str, emoji: bool| {
            let transport = crate::roster::Transport {
                emoji,
                ..Default::default()
            };
            crate::roster::test_attach_on(&core, login, Default::default(), transport)
        };
        let (_reader, mut reader) = attach("reader", true);
        let (_other, mut other) = attach("other", false);
        let changes = |rx: &mut crate::roster::Events| {
            (crate::roster::drain(rx).into_iter())
                .filter_map(|ev| match ev {
                    crate::roster::Event::EmojiChanged { revision } => Some(revision),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        changes(&mut reader);
        changes(&mut other);
        add(&*store, "aa", 1);
        add(&*store, "bb", 1);
        assert_eq!(core.emoji_reload(), Ok(true));
        assert_eq!(core.emoji_reload(), Ok(false));
        assert_eq!(changes(&mut reader), [2]);
        assert_eq!(changes(&mut other), Vec::<u32>::new());
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
