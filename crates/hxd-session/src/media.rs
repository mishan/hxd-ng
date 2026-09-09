//! Inline media on the legacy wire: transactions 750 and 751, the LOGIN
//! advertisement, and the companion fields that ride a chat line or a
//! private message.
//!
//! Everything here is encoding. Handles, authorization sets, quotas and
//! the image pipeline live in `hxd_core::media`; this module turns a
//! 1.x client's transactions into those calls and the resulting events
//! into the fields fogWraith's `Capabilities-Inline-Media.md` defines.
//!
//! The rule that shapes it is the spec's own: **the fields exist for a
//! session that negotiated capability bit 3 and for no other.** A
//! sender's `MEDIA_ID` is dropped on the floor if it did not negotiate;
//! a recipient's chat push carries no media fields if it did not. That
//! is per *connection*, which is why the decision lives in this
//! frontend and not in the domain — one relayed event becomes two
//! different frames for two clients in one room, and neither knows.
//!
//! The constants are `hxproto`'s: GtkHx speaks this extension already,
//! so the field ids and the error codes are shared vocabulary rather
//! than something this tree gets to invent (unlike video's, see
//! [`crate::video`]).

use hxd_core::media::{Handle, MediaConfig, MediaRef, MediaReject, HANDLE_LEN};
use hxproto::messages::tag;

/// Client → server transaction opcodes.
pub mod trans {
    /// Upload image bytes, single-shot or chunked, and get a handle.
    pub const UPLOAD_MEDIA: u32 = 750;
    /// Fetch the canonical bytes of a handle, one part at a time.
    pub const DOWNLOAD_MEDIA: u32 = 751;
}

/// Every download reply is sliced at this, and the LOGIN advert says so.
///
/// It is what GtkHx clamps any advertised chunk size down to and what it
/// uses when a server advertises none: it leaves room inside the
/// 65535-byte frame for the index, final and token fields around the
/// payload. Advertising more would be advertising a frame that cannot be
/// packed.
pub const CHUNK_SIZE: u32 = 60_000;

/// The six advisory limits, for the LOGIN reply of a session that
/// negotiated the bit. The spec makes them a MUST when the bit is
/// confirmed, and every one is a u32 BE.
pub fn limits_chunks(cfg: &MediaConfig) -> Chunks {
    let codec = &cfg.codec;
    [
        (tag::CHAT_MEDIA_MAX_BYTES, cfg.max_bytes as u32),
        (tag::CHAT_MEDIA_MAX_DIMENSION, codec.max_dimension),
        (
            tag::CHAT_MEDIA_MAX_PIXELS,
            codec.max_pixels.min(u32::MAX as u64) as u32,
        ),
        (tag::CHAT_MEDIA_CHUNK_SIZE, CHUNK_SIZE),
        (tag::CHAT_MEDIA_MAX_FRAMES, codec.max_frames),
        (tag::CHAT_MEDIA_MAX_DURATION_MS, codec.max_duration_ms),
    ]
    .into_iter()
    .map(|(t, v)| (t, v.to_be_bytes().to_vec()))
    .collect()
}

/// The fields a relayed chat line or private message carries when it had
/// an image and the recipient negotiated the bit.
///
/// `TYPE` is the canonical MIME this server produced, never the one the
/// sender declared. The dimensions and byte count are advisory: they let
/// a client size a placeholder row before the bytes arrive, which is the
/// difference between a chat pane that jumps and one that does not.
///
/// A reference whose bytes have gone — expired, evicted, revoked —
/// carries no `MEDIA_ID`, and the spec pairs `ID` and `TYPE`, so it
/// carries nothing at all: there is no handle to fetch and a client that
/// was given one would fetch it and be told no. The line's text stands
/// on its own, which is what a 1.x client would have seen anyway.
pub fn companion_chunks(media: &MediaRef) -> Chunks {
    let Some(id) = media.id else {
        return Vec::new();
    };
    vec![
        (tag::CHAT_MEDIA_ID, id.to_vec()),
        (tag::CHAT_MEDIA_TYPE, media.mime.mime().as_bytes().to_vec()),
        (tag::CHAT_MEDIA_WIDTH, media.width.to_be_bytes().to_vec()),
        (tag::CHAT_MEDIA_HEIGHT, media.height.to_be_bytes().to_vec()),
        (tag::CHAT_MEDIA_BYTES, media.bytes.to_be_bytes().to_vec()),
    ]
}

/// An unsigned field of whatever width the client chose.
///
/// `Chunk::as_uint` knows the two widths the base protocol uses; this
/// extension mixes them — `PART_FINAL` is a u8, the indices are u16, the
/// limits are u32 — and a client that writes a one-byte index is doing
/// something the spec allows for its neighbours. Be liberal here: the
/// alternative is reading a real value as zero.
pub fn uint(data: &[u8]) -> u32 {
    let tail = &data[data.len().saturating_sub(4)..];
    tail.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
}

/// A non-zero byte anywhere in the payload — the shape `PART_FINAL`
/// takes, and the same rule GtkHx's parser applies to ours.
pub fn flag(data: &[u8]) -> bool {
    data.iter().any(|&b| b != 0)
}

/// A handle as it arrives on an inbound transaction. Anything that is
/// not exactly sixteen bytes is not a handle this server issued.
pub fn parse_handle(data: &[u8]) -> Option<Handle> {
    (data.len() == HANDLE_LEN).then(|| {
        let mut h = [0u8; HANDLE_LEN];
        h.copy_from_slice(data);
        h
    })
}

/// The task-error fields for a refusal: the generic text the spec asks
/// for, plus the optional machine-readable category.
///
/// The text says no more than the code does, deliberately. A rejection
/// that explains which walker tripped or which limit was crossed is a
/// rejection that teaches the next attempt how to get past it; the real
/// reason goes to the log (`docs/inline-media.md` §10).
pub fn error_chunks(reject: MediaReject) -> Chunks {
    vec![(
        tag::CHAT_MEDIA_ERROR_CODE,
        reject.code().to_be_bytes().to_vec(),
    )]
}

/// The tagged fields of one reply or push, in the order they go on the
/// wire.
pub type Chunks = Vec<(u16, Vec<u8>)>;

/// One slice of a download reply.
///
/// `PART_COUNT` is the whole count on every part, so a client can size
/// its accumulator from the first reply; `PART_FINAL` is what actually
/// ends the transfer, because a count it did not read is a count it
/// cannot rely on.
pub fn download_chunks(bytes: &[u8], mime: &str, index: u16) -> Option<(Chunks, bool)> {
    let chunk = CHUNK_SIZE as usize;
    let count = bytes.len().div_ceil(chunk).max(1);
    let start = index as usize * chunk;
    if start >= bytes.len() && index != 0 {
        return None;
    }
    let end = (start + chunk).min(bytes.len());
    let last = end >= bytes.len();
    Some((
        vec![
            (tag::CHAT_MEDIA_PAYLOAD, bytes[start..end].to_vec()),
            (tag::CHAT_MEDIA_TYPE, mime.as_bytes().to_vec()),
            (
                tag::CHAT_MEDIA_PART_COUNT,
                (count as u16).to_be_bytes().to_vec(),
            ),
            (tag::CHAT_MEDIA_PART_FINAL, vec![u8::from(last)]),
        ],
        last,
    ))
}

/// The success reply to the final part of an upload: the handle, the
/// canonical type, and the canonical metadata.
pub fn upload_reply_chunks(media: &MediaRef) -> Chunks {
    let mut chunks = vec![(tag::CHAT_MEDIA_TYPE, media.mime.mime().as_bytes().to_vec())];
    if let Some(id) = media.id {
        chunks.insert(0, (tag::CHAT_MEDIA_ID, id.to_vec()));
    }
    chunks.push((tag::CHAT_MEDIA_WIDTH, media.width.to_be_bytes().to_vec()));
    chunks.push((tag::CHAT_MEDIA_HEIGHT, media.height.to_be_bytes().to_vec()));
    chunks.push((tag::CHAT_MEDIA_BYTES, media.bytes.to_be_bytes().to_vec()));
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::media::MediaType;

    fn reference(bytes: u32) -> MediaRef {
        MediaRef {
            id: Some([9u8; HANDLE_LEN]),
            mime: MediaType::Png,
            width: 8,
            height: 4,
            bytes,
        }
    }

    #[test]
    fn a_download_slices_at_the_advertised_chunk_size() {
        let bytes = vec![0u8; CHUNK_SIZE as usize + 10];
        let (first, last) = download_chunks(&bytes, "image/png", 0).unwrap();
        assert!(!last);
        let payload = &first
            .iter()
            .find(|(t, _)| *t == tag::CHAT_MEDIA_PAYLOAD)
            .unwrap()
            .1;
        assert_eq!(payload.len(), CHUNK_SIZE as usize);
        // The count is the whole count on every part, so an accumulator
        // can be sized from the first reply.
        let count = &first
            .iter()
            .find(|(t, _)| *t == tag::CHAT_MEDIA_PART_COUNT)
            .unwrap()
            .1;
        assert_eq!(count.as_slice(), &2u16.to_be_bytes());

        let (second, last) = download_chunks(&bytes, "image/png", 1).unwrap();
        assert!(last);
        let payload = &second
            .iter()
            .find(|(t, _)| *t == tag::CHAT_MEDIA_PAYLOAD)
            .unwrap()
            .1;
        assert_eq!(payload.len(), 10);
        // A part past the end is not an empty part; it is a bad request,
        // and the caller answers it the way it answers a bogus handle.
        assert!(download_chunks(&bytes, "image/png", 2).is_none());
    }

    #[test]
    fn an_empty_image_is_still_one_part() {
        let (chunks, last) = download_chunks(&[], "image/gif", 0).unwrap();
        assert!(last);
        let count = &chunks
            .iter()
            .find(|(t, _)| *t == tag::CHAT_MEDIA_PART_COUNT)
            .unwrap()
            .1;
        assert_eq!(count.as_slice(), &1u16.to_be_bytes());
    }

    #[test]
    fn a_reference_without_bytes_carries_no_companions() {
        // Both fields or neither, per the spec — and with the handle
        // gone there is nothing to fetch, so it is neither.
        let mut gone = reference(10);
        gone.id = None;
        assert!(companion_chunks(&gone).is_empty());
        assert_eq!(companion_chunks(&reference(10)).len(), 5);
    }

    #[test]
    fn the_part_fields_are_read_at_any_width() {
        // The extension mixes u8, u16 and u32 fields, and a `PART_FINAL`
        // read as zero is a chunked upload that never finishes.
        assert!(flag(&[1]));
        assert!(flag(&[0, 1]));
        assert!(!flag(&[0]));
        assert!(!flag(&[]));
        assert_eq!(uint(&[7]), 7);
        assert_eq!(uint(&[0, 7]), 7);
        assert_eq!(uint(&[0, 0, 0, 7]), 7);
        assert_eq!(uint(&[]), 0);
    }

    #[test]
    fn a_handle_is_exactly_sixteen_bytes() {
        assert!(parse_handle(&[1; HANDLE_LEN]).is_some());
        assert!(parse_handle(&[1; HANDLE_LEN - 1]).is_none());
        assert!(parse_handle(&[1; HANDLE_LEN + 1]).is_none());
        assert!(parse_handle(&[]).is_none());
    }
}
