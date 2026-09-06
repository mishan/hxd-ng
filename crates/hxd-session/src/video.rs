//! Video on the legacy wire: transactions 607–611 and fields
//! `0x0220`–`0x0225`.
//!
//! Everything here is encoding. The rooms, the slots, the subscription
//! sets and every cleanup path live in `hxd_core::video`; this module
//! turns those calls and events into the shapes a 1.x client with the
//! video extension expects, and turns its transactions back into calls.
//!
//! The same two rules that shape [`crate::voice`] shape this module.
//! Video transactions are only ever sent to a client that negotiated
//! `CAPABILITY_VIDEO` at login — which is what keeps the whole extension
//! invisible to every client that predates it. And 611 is a
//! server-initiated notification carrying **task id 0**, not the push
//! counter the rest of this frontend uses.
//!
//! **The opcodes and field ids live here rather than in `hotline-proto`.**
//! The shared crate carries the voice extension's because GtkHx speaks
//! it; nothing in the gtkhx tree speaks video yet, and inventing the
//! constants there would mean a submodule pin bump ahead of any client
//! that could use them. They move to `hotline_proto::messages` in the
//! same change that teaches GtkHx to render video, which is where the
//! two halves get tested against each other.

use hotline_proto::messages::tag;
use hxd_core::video::{
    VideoConfig, VideoError, VideoKind, VideoLimits, VideoPublication, VideoStream,
};

/// Client → server transaction opcodes.
///
/// 607–611 continue the voice extension's 600-block, which makes the 600s
/// as a whole the media-signalling block: clear of the base protocol
/// (101–355), the keepalive (500), chat history (700–709), inline media
/// (750–751) and GIF icons (1861–1864). 612–619 are reserved for later
/// revisions of the extension — simulcast most likely — and must not be
/// squatted on.
pub mod trans {
    /// Begin publishing a stream of a given kind.
    pub const VIDEO_START: u32 = 607;
    /// End a publication and release its slot.
    pub const VIDEO_STOP: u32 = 608;
    /// Pause or resume a publication. No renegotiation.
    pub const VIDEO_STATE: u32 = 609;
    /// Declare the complete set of streams this client wishes to receive.
    pub const VIDEO_SUBSCRIBE: u32 = 610;
    /// Server → client: the room's publications and their state.
    /// A notification — task id 0, no reply expected.
    pub const VIDEO_STATUS: u32 = 611;
}

/// Field ids. `0x0220`–`0x023F` belong to this extension; the unallocated
/// tail is reserved and must not be reused for anything else. The block
/// starts at `0x0220` because `0x01F5`–`0x01F9` are voice's, `0x01FA` is
/// the large-file extension's resume digest, and `0x0201`–`0x021F` are
/// inline media's.
pub mod field {
    /// Stream kind (u16 BE).
    pub const VIDEO_KIND: u16 = 0x0220;
    /// Paused state (u16 BE): 0 live, 1 paused.
    pub const VIDEO_PAUSED: u16 = 0x0221;
    /// Packed array of publication entries.
    pub const VIDEO_PUBLISHERS: u16 = 0x0222;
    /// Active video codec name for the room (ASCII).
    pub const VIDEO_CODEC: u16 = 0x0223;
    /// Server limits for one stream kind. Repeated, once per kind.
    pub const VIDEO_LIMITS: u16 = 0x0224;
    /// Packed array of the streams this client wishes to receive.
    pub const VIDEO_SUBSCRIPTIONS: u16 = 0x0225;
}

/// VP8's id in the publishers blob's codec field.
///
/// **A separate number space from voice's.** Codec id 0 is PCMU in
/// `DATA_VOICE_PARTICIPANTS` and VP8 in `DATA_VIDEO_PUBLISHERS`; the two
/// fields are never interchangeable and nothing may share a lookup table
/// between them.
const CODEC_VP8: u16 = 0;

/// Flags bit 0 of a publication entry.
const FLAG_PAUSED: u16 = 0x0001;

/// Bytes per `DATA_VIDEO_PUBLISHERS` entry.
const PUBLISHER_STRIDE: usize = 8;

/// Bytes per `DATA_VIDEO_SUBSCRIPTIONS` entry.
const SUBSCRIPTION_STRIDE: usize = 4;

/// The `DATA_VIDEO_PUBLISHERS` (`0x0222`) payload: a packed array of
/// eight-byte entries, `uid | kind | flags | codec id`, all big-endian.
/// A participant publishing both a camera and a screen produces two.
///
/// **A new field, not a widening of `DATA_VOICE_PARTICIPANTS`.** That
/// blob has a six-byte stride and deployed voice clients derive its count
/// by dividing the field length by six; growing the stride would
/// misparse silently in every one of them. Audio state stays there, video
/// state here, and a client correlates the two by user id.
pub fn publishers_payload(ps: &[VideoPublication]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ps.len() * PUBLISHER_STRIDE);
    for p in ps {
        v.extend_from_slice(&p.uid.to_be_bytes());
        v.extend_from_slice(&p.kind.wire().to_be_bytes());
        v.extend_from_slice(&(if p.paused { FLAG_PAUSED } else { 0 }).to_be_bytes());
        v.extend_from_slice(&CODEC_VP8.to_be_bytes());
    }
    v
}

/// Read a `DATA_VIDEO_SUBSCRIPTIONS` (`0x0225`) payload: the client's
/// **complete** desired receive set, four bytes an entry.
///
/// A trailing partial entry is ignored, as the spec requires, and so is
/// an entry naming a kind this revision doesn't define — a client from a
/// later revision asking for screen audio should lose that one stream,
/// not its whole subscription set. An absent or empty field is "no video
/// at all", which is the state every participant starts in.
pub fn parse_subscriptions(data: &[u8]) -> Vec<VideoStream> {
    data.chunks_exact(SUBSCRIPTION_STRIDE)
        .filter_map(|e| {
            let uid = u16::from_be_bytes([e[0], e[1]]);
            let kind = VideoKind::from_wire(u16::from_be_bytes([e[2], e[3]]))?;
            Some(VideoStream { uid, kind })
        })
        .collect()
}

/// One `DATA_VIDEO_LIMITS` (`0x0224`) field: the server's ceiling for one
/// stream kind, sixteen bytes in this revision.
///
/// A parser must accept a longer field and ignore the excess, so a later
/// revision can append; this encoder writes exactly the sixteen and
/// zeroes the reserved pair.
pub fn limits_payload(kind: VideoKind, l: &VideoLimits) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&kind.wire().to_be_bytes());
    v.extend_from_slice(&l.max_width.to_be_bytes());
    v.extend_from_slice(&l.max_height.to_be_bytes());
    v.extend_from_slice(&l.max_fps.to_be_bytes());
    v.extend_from_slice(&l.max_bitrate.to_be_bytes());
    v.extend_from_slice(&l.max_per_room.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v
}

/// The `DATA_VIDEO_LIMITS` chunks for a login reply — one per kind the
/// server supports, so a client can configure its encoders before the
/// first join rather than discovering the ceilings by rejection.
pub fn limits_chunks(config: &VideoConfig) -> Vec<(u16, Vec<u8>)> {
    VideoKind::ALL
        .iter()
        .map(|k| (field::VIDEO_LIMITS, limits_payload(*k, &config.limits(*k))))
        .collect()
}

/// Task-error text for a refused video operation. Human-readable and not
/// meant for programmatic parsing, per the spec.
pub fn err_text(e: VideoError) -> &'static str {
    match e {
        VideoError::Disabled => "Video is not available on this server.",
        VideoError::NotInVoice => "You are not in that voice chat.",
        VideoError::AlreadyPublishing => "You are already publishing that.",
        VideoError::NotPublishing => "You are not publishing that.",
        // The spec asks that the wording say *why*, so a client can say
        // so plainly: with one screen slot a room, this is the common
        // refusal and "the room is full" would be misleading — the room
        // has space, the slot doesn't.
        VideoError::Full => "Someone else is already sharing. Ask them to stop first.",
    }
}

/// The `CHAT_ID` chunk every video transaction carries.
pub fn chat_id(cid: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, cid.to_be_bytes().to_vec())
}

/// The `DATA_VIDEO_KIND` chunk.
pub fn kind_chunk(kind: VideoKind) -> (u16, Vec<u8>) {
    (field::VIDEO_KIND, kind.wire().to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transaction_numbers_continue_the_voice_block() {
        // 600-606 are voice's; video picks up at 607 and stops at 611,
        // leaving 612-619 reserved.
        assert_eq!(trans::VIDEO_START, 607);
        assert_eq!(trans::VIDEO_STOP, 608);
        assert_eq!(trans::VIDEO_STATE, 609);
        assert_eq!(trans::VIDEO_SUBSCRIBE, 610);
        assert_eq!(trans::VIDEO_STATUS, 611);
        // And the field block starts clear of inline media's 0x0201-0x021F.
        assert_eq!(field::VIDEO_KIND, 0x0220);
        assert_eq!(field::VIDEO_SUBSCRIPTIONS, 0x0225);
    }

    #[test]
    fn the_publishers_blob_is_eight_bytes_an_entry() {
        let ps = vec![
            VideoPublication {
                uid: 12,
                kind: VideoKind::Camera,
                paused: false,
            },
            VideoPublication {
                uid: 12,
                kind: VideoKind::Screen,
                paused: true,
            },
        ];
        let blob = publishers_payload(&ps);
        assert_eq!(blob.len(), 16, "eight bytes an entry, two entries");
        // Byte for byte, so a change to either side has to be deliberate.
        // One participant, two publications, correlated by user id.
        assert_eq!(
            blob,
            vec![
                0, 12, 0, 1, 0, 0, 0, 0, // uid 12, camera, live, VP8
                0, 12, 0, 2, 0, 1, 0, 0, // uid 12, screen, paused, VP8
            ]
        );
        assert!(publishers_payload(&[]).is_empty());
    }

    #[test]
    fn the_publishers_stride_is_not_the_voice_participants_stride() {
        // The mistake this field exists to avoid: a voice client derives
        // its participant count by dividing the field length by six, so
        // the two blobs must never be confused for one another.
        let one = publishers_payload(&[VideoPublication {
            uid: 1,
            kind: VideoKind::Camera,
            paused: false,
        }]);
        assert_eq!(one.len(), 8);
        assert_ne!(one.len(), 6);
    }

    #[test]
    fn subscriptions_round_trip_and_tolerate_junk() {
        // uid 5 camera, uid 9 screen, then a trailing partial entry the
        // spec says to ignore.
        let blob = vec![0, 5, 0, 1, 0, 9, 0, 2, 0, 7];
        assert_eq!(
            parse_subscriptions(&blob),
            vec![
                VideoStream {
                    uid: 5,
                    kind: VideoKind::Camera
                },
                VideoStream {
                    uid: 9,
                    kind: VideoKind::Screen
                },
            ]
        );
        // Kind 0 is deliberately invalid, so a zeroed field is caught
        // rather than read as a camera; kind 3 is a later revision's.
        assert!(parse_subscriptions(&[0, 5, 0, 0]).is_empty());
        assert!(parse_subscriptions(&[0, 5, 0, 3]).is_empty());
        // The empty set is the state everyone starts in, and it parses
        // rather than failing.
        assert!(parse_subscriptions(&[]).is_empty());
    }

    #[test]
    fn the_limits_field_is_sixteen_bytes_with_a_zero_tail() {
        let l = VideoLimits::CAMERA;
        let blob = limits_payload(VideoKind::Camera, &l);
        assert_eq!(blob.len(), 16);
        assert_eq!(
            blob,
            vec![
                0, 1, // camera
                5, 0, // 1280
                2, 0xd0, // 720
                0, 30, // fps
                0, 0x16, 0xe3, 0x60, // 1_500_000
                0, 8, // slots
                0, 0, // reserved, MUST be zero
            ]
        );
        // One field per kind, so a client configures both encoders from
        // the login reply.
        let chunks = limits_chunks(&VideoConfig::default());
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|(t, _)| *t == field::VIDEO_LIMITS));
        assert_eq!(chunks[1].1[0..2], [0, 2], "the screen kind follows");
    }
}
