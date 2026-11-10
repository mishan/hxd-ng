//! Server emoji on the classic wire (the Server Emoji draft,
//! `docs/server-emoji.md`): capability bit 20, the catalog's
//! transactions 713 to 716, and the refs that ride a chat line, a
//! private message and an instant message.
//!
//! Only a session that negotiated bit 20 is answered here or sent any of
//! it; to every other the catalog does not exist, a ref it sends is
//! dropped and its text relayed, and the text it is sent reads `:name:`.
//! The catalog, what a ref keeps and who is told of a change are
//! `hxd_core::emoji`'s.
//!
//! The draft's numbers are kept here, as Structured Chat's are in
//! [`crate::structured`], until they are allocated.

use hxd_core::emoji::{EmojiEntry, EmojiId, EmojiName, EmojiPolicy, EmojiRef, EmojiRefs, MAX_REFS};
use hxd_core::Core;

use crate::frame::Frame;

type Chunks = Vec<(u16, Vec<u8>)>;

pub const GET_CATALOG: u32 = 713;
pub const GET_EMOJI: u32 = 714;
pub const CATALOG_CHANGED: u32 = 715;
pub const MANAGE: u32 = 716;

pub const DATA_EMOJI_ID: u16 = 0x0f38;
pub const DATA_EMOJI_IMAGE: u16 = 0x0f3a;
pub const DATA_EMOJI_ENTRY: u16 = 0x0f3b;
pub const DATA_EMOJI_REVISION: u16 = 0x0f3c;
pub const DATA_EMOJI_REFS: u16 = 0x0f3e;
pub const DATA_EMOJI_MORE: u16 = 0x0f3f;
pub const DATA_MAX_EMOJI: u16 = 0x0f40;
pub const DATA_MAX_EMOJI_BYTES: u16 = 0x0f41;
pub const DATA_MAX_EMOJI_DIMENSION: u16 = 0x0f42;

/// A Chat History entry's sub-field for a line's refs: in 700 alone, as
/// 106 carries them beside the entry.
pub const EMOJI_REFS: u16 = 0x0022;

/// The draft's reason codes, in Structured Chat's `DATA_CHAT_REASON`.
pub const NOT_ALLOWED: u16 = 2;
pub const RATE_LIMITED: u16 = 6;
pub const NO_SUCH_EMOJI: u16 = 7;

/// Get Emoji's allowance: enough that a client opening a busy chat
/// fetches every emoji it draws at once, and then two a second.
pub const FETCH_BURST: f64 = 100.0;
pub const FETCHES_PER_SECOND: f64 = 2.0;

/// The largest packed entry, a 32-byte name's, and the field around it.
const ENTRY_MAX: usize = 4 + 31 + 32;

/// What one Get Emoji Catalog reply's entries may come to: the reply
/// stays within 64 KiB, the bound chosen for it.
const PAGE_BYTES: usize = 0xffff - 32;

/// Is `ty` one of the draft's requests?
pub(crate) fn handles(ty: u32) -> bool {
    matches!(ty, GET_CATALOG | GET_EMOJI | MANAGE)
}

/// What each costs a session that negotiated bit 20: nothing. The
/// catalog and its images are fetched in bulk as a client joins, which at
/// mhxd's catch-all of 10 is a ban, and Get Emoji has its own ration;
/// Manage Emoji does nothing here.
pub(crate) fn price(ty: u32) -> Option<u32> {
    handles(ty).then_some(0)
}

/// The login reply's fields beside a confirmed bit 20, the revision read
/// after the session attached: a reload since is told by the change
/// that follows.
pub(crate) fn login_fields(core: &Core) -> Chunks {
    let (Some(revision), Some(policy)) = (core.emoji_revision(), core.emoji_policy()) else {
        return Vec::new();
    };
    let EmojiPolicy {
        max_count,
        max_bytes,
        max_dimension,
        ..
    } = policy;
    [
        (DATA_EMOJI_REVISION, revision),
        (DATA_MAX_EMOJI, max_count as u32),
        (DATA_MAX_EMOJI_BYTES, max_bytes as u32),
        (DATA_MAX_EMOJI_DIMENSION, max_dimension),
    ]
    .into_iter()
    .map(|(t, v)| (t, v.to_be_bytes().to_vec()))
    .collect()
}

/// `DATA_EMOJI_REFS` as sent: `u16 n`, then `n` entries of `u32 id`,
/// `u8 name_len` and the name. The first [`MAX_REFS`] are read and the
/// rest are not; an entry whose name is no name is skipped, and one cut
/// short ends the field. What is kept of them is the core's to say.
pub fn parse_refs(data: &[u8]) -> Vec<EmojiRef> {
    let Some((n, mut rest)) = data.split_first_chunk::<2>() else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    for _ in 0..usize::from(u16::from_be_bytes(*n)).min(MAX_REFS) {
        let Some((id, after)) = rest.split_first_chunk::<4>() else {
            break;
        };
        let Some((&len, after)) = after.split_first() else {
            break;
        };
        let Some((name, after)) = after.split_at_checked(usize::from(len)) else {
            break;
        };
        rest = after;
        if let Some(name) = std::str::from_utf8(name).ok().and_then(EmojiName::parse) {
            refs.push(EmojiRef {
                id: EmojiId(u32::from_be_bytes(*id)),
                name,
            });
        }
    }
    refs
}

/// The refs `f` carries in `DATA_EMOJI_REFS`, read only from a session
/// that negotiated bit 20: from any other they are dropped unread.
pub(crate) fn refs_in(f: &Frame, negotiated: bool) -> Vec<EmojiRef> {
    match f.chunks().find(|c| c.tag == DATA_EMOJI_REFS) {
        Some(c) if negotiated => parse_refs(c.data),
        _ => Vec::new(),
    }
}

/// Kept refs as `DATA_EMOJI_REFS`, and as a 700 entry's `EMOJI_REFS`.
pub(crate) fn refs_field(refs: &EmojiRefs) -> Vec<u8> {
    let refs = refs.refs();
    let mut out = (refs.len() as u16).to_be_bytes().to_vec();
    for r in refs {
        out.extend_from_slice(&r.id.0.to_be_bytes());
        out.push(r.name.as_str().len() as u8);
        out.extend_from_slice(r.name.as_str().as_bytes());
    }
    out
}

/// One packed `DATA_EMOJI_ENTRY`: `u32 id`, `u32 revision`, `u16 flags`
/// (bit 0 animated, bit 1 removed), `u16 width`, `u16 height`, the first
/// 16 bytes of the image's SHA-256, then the name with its length. A
/// removed entry's flags but the removed bit, size and hash are zero.
pub(crate) fn entry(e: &EmojiEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTRY_MAX - 4);
    out.extend_from_slice(&e.id.0.to_be_bytes());
    out.extend_from_slice(&e.revision.to_be_bytes());
    let (flags, width, height, hash) = match &e.image {
        Some(i) => (u16::from(i.animated), i.width, i.height, &i.hash[..16]),
        None => (2, 0, 0, &[0; 16][..]),
    };
    for v in [flags, width, height] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(hash);
    out.push(e.name.as_str().len() as u8);
    out.extend_from_slice(e.name.as_str().as_bytes());
    out
}

/// Get Emoji Catalog (713): the current revision, and what changed
/// since the one asked about or, when the catalog cannot tell, every
/// entry kept, in ascending id order after `DATA_EMOJI_ID`, as many as
/// fit one reply, with `DATA_EMOJI_MORE` when more remain.
pub(crate) fn catalog(core: &Core, f: &Frame) -> Option<Chunks> {
    let field = |tag| {
        f.chunks()
            .find(|c| c.tag == tag && matches!(c.data.len(), 2 | 4))
            .map(|c| c.as_uint())
    };
    let since = field(DATA_EMOJI_REVISION);
    let after = field(DATA_EMOJI_ID).map(EmojiId);
    let listing = core.emoji_list(since, after, PAGE_BYTES / ENTRY_MAX)?;
    let mut chunks = vec![(DATA_EMOJI_REVISION, listing.revision.to_be_bytes().to_vec())];
    chunks.extend(listing.entries.iter().map(|e| (DATA_EMOJI_ENTRY, entry(e))));
    if listing.more {
        chunks.push((DATA_EMOJI_MORE, vec![1]));
    }
    Some(chunks)
}

/// Get Emoji (714): a live entry's image, or `None` for one removed or
/// never given.
pub(crate) fn image(core: &Core, f: &Frame) -> Option<Chunks> {
    let id = f
        .chunks()
        .find(|c| c.tag == DATA_EMOJI_ID && matches!(c.data.len(), 2 | 4))
        .map(|c| c.as_uint())?;
    let image = core.emoji_image(EmojiId(id))?;
    Some(vec![
        (DATA_EMOJI_ID, id.to_be_bytes().to_vec()),
        (DATA_EMOJI_IMAGE, image.bytes.to_vec()),
    ])
}

/// Emoji Catalog Changed (715).
pub(crate) fn changed(revision: u32) -> Chunks {
    vec![(DATA_EMOJI_REVISION, revision.to_be_bytes().to_vec())]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> EmojiName {
        EmojiName::parse(s).unwrap()
    }

    /// One ref laid out as the draft lays it out.
    fn sent(id: u32, name: &[u8]) -> Vec<u8> {
        [&id.to_be_bytes()[..], &[name.len() as u8], name].concat()
    }

    #[test]
    fn refs_are_read_as_the_draft_lays_them_out() {
        let party = || EmojiRef {
            id: EmojiId(5),
            name: name("party"),
        };
        let field =
            |n: u16, entries: &[Vec<u8>]| [&n.to_be_bytes()[..], &entries.concat()].concat();
        let many: Vec<Vec<u8>> = (1..=40).map(|i| sent(i, b"ab")).collect();
        for (case, data, want) in [
            ("one", field(1, &[sent(5, b"party")]), vec![party()]),
            ("none said", field(0, &[sent(5, b"party")]), vec![]),
            ("empty", vec![], vec![]),
            ("a count cut short", vec![0], vec![]),
            (
                "an entry cut short ends the field",
                field(2, &[sent(5, b"party"), sent(6, b"party")[..6].to_vec()]),
                vec![party()],
            ),
            (
                "more said than sent",
                field(3, &[sent(5, b"party")]),
                vec![party()],
            ),
            (
                "a name that is no name is skipped",
                field(
                    3,
                    &[sent(1, b"Party"), sent(2, b"\xff\xfe"), sent(5, b"party")],
                ),
                vec![party()],
            ),
            (
                "an empty name is skipped",
                field(2, &[sent(1, b""), sent(5, b"party")]),
                vec![party()],
            ),
        ] {
            assert_eq!(parse_refs(&data), want, "{case}");
        }
        let read = parse_refs(&field(40, &many));
        assert_eq!(read.len(), MAX_REFS, "the rest unread");
        assert_eq!(read.last().unwrap().id, EmojiId(MAX_REFS as u32));
    }

    #[test]
    fn an_entry_is_packed_as_the_draft_lays_it_out() {
        let image = hxd_core::emoji::EmojiImage::new(
            hxd_core::media::MediaType::Gif,
            128,
            64,
            true,
            vec![1, 2, 3],
        );
        let live = EmojiEntry {
            id: EmojiId(0x0102_0304),
            name: name("party"),
            revision: 9,
            image: Some(std::sync::Arc::new(image.clone())),
        };
        let want = [
            &[1, 2, 3, 4][..],
            &[0, 0, 0, 9],
            &[0, 1],
            &[0, 128],
            &[0, 64],
            &image.hash[..16],
            &[5],
            b"party",
        ]
        .concat();
        assert_eq!(entry(&live), want);
        let removed = EmojiEntry {
            image: None,
            ..live
        };
        let want = [
            &[1, 2, 3, 4][..],
            &[0, 0, 0, 9],
            &[0, 2],
            &[0, 0, 0, 0],
            &[0; 16],
            &[5],
            b"party",
        ]
        .concat();
        assert_eq!(entry(&removed), want);
        let longest = EmojiEntry {
            name: name(&"x".repeat(32)),
            ..removed
        };
        assert_eq!(entry(&longest).len() + 4, ENTRY_MAX);
    }
}
