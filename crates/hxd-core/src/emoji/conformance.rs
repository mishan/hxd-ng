//! A suite every [`EmojiStore`] must pass: the in-memory one here and
//! the SQLite one a server keeps its catalog in.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{EmojiEntry, EmojiId, EmojiImage, EmojiName, EmojiStore, EmojiStoreError};
use crate::media::MediaType;

/// The count the cases add and remove under, where the count is not the
/// subject: as large as it can be, so a store that narrows it is caught.
const ROOM: usize = usize::MAX;

/// Run every case against a freshly built store.
pub fn run(new_store: &dyn Fn() -> Box<dyn EmojiStore>) {
    ids_ascend_and_are_never_given_again(&*new_store());
    live_names_are_unique_and_a_removed_one_is_free(&*new_store());
    every_change_spends_one_revision_and_nothing_else_does(&*new_store());
    the_catalog_is_full_at_its_count_of_live_entries(&*new_store());
    a_removed_entry_keeps_its_id_and_name_and_loses_its_image(&*new_store());
    removed_entries_are_forgotten_lowest_revision_first_whatever_the_clock(&*new_store());
}

fn t(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn name(s: &str) -> EmojiName {
    EmojiName::parse(s).expect("a test name is a valid one")
}

pub fn image(seed: u8) -> EmojiImage {
    let (mime, animated) = match seed % 2 {
        0 => (MediaType::Png, false),
        _ => (MediaType::Gif, true),
    };
    EmojiImage::new(
        mime,
        32 + u16::from(seed),
        64,
        animated,
        vec![seed; 8 + usize::from(seed)],
    )
}

fn add(store: &dyn EmojiStore, n: &str, seed: u8) -> EmojiId {
    store.add(&name(n), &image(seed), t(1), ROOM).unwrap();
    store
        .load()
        .unwrap()
        .entries
        .into_iter()
        .rfind(|e| e.name.as_str() == n)
        .unwrap()
        .id
}

fn entry(store: &dyn EmojiStore, id: EmojiId) -> Option<EmojiEntry> {
    store
        .load()
        .unwrap()
        .entries
        .into_iter()
        .find(|e| e.id == id)
}

fn ids_ascend_and_are_never_given_again(store: &dyn EmojiStore) {
    let a = add(store, "aa", 1);
    let b = add(store, "bb", 2);
    assert!(a.0 >= 1 && b > a);
    store.remove(b, t(2), 0).unwrap();
    assert_eq!(entry(store, b), None, "forgotten at once");
    let c = add(store, "cc", 3);
    assert!(c > b, "the highest id forgotten is still never given again");
    let ids: Vec<EmojiId> = store.load().unwrap().entries.iter().map(|e| e.id).collect();
    assert_eq!(ids, [a, c]);
}

fn live_names_are_unique_and_a_removed_one_is_free(store: &dyn EmojiStore) {
    let party = add(store, "party", 1);
    let other = add(store, "other", 2);
    let rev = store.load().unwrap().revision;
    assert_eq!(
        store.add(&name("party"), &image(3), t(1), ROOM),
        Err(EmojiStoreError::NameTaken)
    );
    assert_eq!(
        store.rename(other, &name("party")),
        Err(EmojiStoreError::NameTaken)
    );
    assert_eq!(store.load().unwrap().revision, rev, "a refusal spends none");

    store.remove(party, t(2), ROOM).unwrap();
    let again = add(store, "party", 3);
    assert_ne!(again, party, "a new entry, under a new id");
    store.rename(again, &name("renamed")).unwrap();
    store.rename(other, &name("party")).unwrap();
    let names: Vec<(EmojiId, String, bool)> = store
        .load()
        .unwrap()
        .entries
        .iter()
        .map(|e| (e.id, e.name.to_string(), e.image.is_some()))
        .collect();
    assert_eq!(
        names,
        [
            (party, "party".into(), false),
            (other, "party".into(), true),
            (again, "renamed".into(), true)
        ]
    );
}

fn every_change_spends_one_revision_and_nothing_else_does(store: &dyn EmojiStore) {
    let empty = store.load().unwrap();
    assert_eq!((empty.revision, empty.floor), (0, 0));
    assert!(empty.entries.is_empty());

    assert_eq!(store.add(&name("aa"), &image(1), t(1), ROOM), Ok(1));
    assert_eq!(store.add(&name("bb"), &image(2), t(1), ROOM), Ok(2));
    let [a, b] = [0, 1].map(|i| store.load().unwrap().entries[i].id);
    assert_eq!(store.rename(a, &name("cc")), Ok(3));
    assert_eq!(store.rename(a, &name("cc")), Ok(3), "its own name again");
    assert_eq!(store.remove(b, t(2), ROOM), Ok(4));

    let unknown = EmojiId(b.0 + 100);
    for refused in [
        store.rename(unknown, &name("dd")),
        store.rename(b, &name("dd")),
        store.remove(unknown, t(3), ROOM),
        store.remove(b, t(3), ROOM),
    ] {
        assert_eq!(refused, Err(EmojiStoreError::NoSuchEmoji));
    }
    let catalog = store.load().unwrap();
    assert_eq!(catalog.revision, 4);
    let revisions: Vec<u32> = catalog.entries.iter().map(|e| e.revision).collect();
    assert_eq!(revisions, [3, 4], "each entry's last change");
}

fn the_catalog_is_full_at_its_count_of_live_entries(store: &dyn EmojiStore) {
    let full = |n: &str| store.add(&name(n), &image(1), t(1), 2);
    full("aa").unwrap();
    full("bb").unwrap();
    assert_eq!(full("cc"), Err(EmojiStoreError::CatalogFull));
    assert_eq!(store.load().unwrap().revision, 2);
    let first = store.load().unwrap().entries[0].id;
    store.remove(first, t(2), ROOM).unwrap();
    full("cc").expect("a removed entry is not counted");
}

fn a_removed_entry_keeps_its_id_and_name_and_loses_its_image(store: &dyn EmojiStore) {
    let still = add(store, "still", 2);
    let moving = add(store, "moving", 3);
    for (id, seed) in [(still, 2), (moving, 3)] {
        let img = entry(store, id).unwrap().image.unwrap();
        assert_eq!(*img, image(seed), "kept as given");
    }
    store.remove(moving, t(2), ROOM).unwrap();
    let rev = store.load().unwrap().revision;
    assert_eq!(
        entry(store, moving),
        Some(EmojiEntry {
            id: moving,
            name: name("moving"),
            revision: rev,
            image: None,
        })
    );
    assert_eq!(entry(store, still).unwrap().image, Some(Arc::new(image(2))));
}

fn removed_entries_are_forgotten_lowest_revision_first_whatever_the_clock(store: &dyn EmojiStore) {
    let [a, b, c, d] = ["aa", "bb", "cc", "dd"].map(|n| add(store, n, 1));
    // The clock runs backward between removals: b is removed first and
    // latest, so forgetting by time would keep it.
    store.remove(b, t(300), 2).unwrap();
    let b_gone_at = store.load().unwrap().revision;
    store.remove(a, t(200), 2).unwrap();
    store.remove(c, t(100), 2).unwrap();
    let catalog = store.load().unwrap();
    let ids: Vec<EmojiId> = catalog.entries.iter().map(|e| e.id).collect();
    assert_eq!(ids, [a, c, d]);
    assert_eq!(catalog.floor, b_gone_at);

    store.remove(d, t(50), 1).unwrap();
    let catalog = store.load().unwrap();
    let ids: Vec<EmojiId> = catalog.entries.iter().map(|e| e.id).collect();
    assert_eq!(ids, [d], "down to the one asked for");
    assert_eq!(catalog.floor, catalog.revision - 1, "c's removal");
}
