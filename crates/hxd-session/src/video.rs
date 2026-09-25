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
//! The opcodes (`ClientHdr::Video*`, `ServerHdr::VideoStatus`), the field
//! ids (`tag::VIDEO_*`) and the byte layouts come from `hxproto`, the
//! crate GtkHx speaks video through, so the two ends of the wire read and
//! write one codec. What stays here is the mapping between that codec's
//! types and `hxd_core`'s, which is transport-free and keeps its own.
//!
//! 607–611 continue the voice extension's 600-block; 612–619 are reserved
//! for later revisions of the extension — simulcast most likely — and
//! `0x0220`–`0x023F` is video's field block. Neither may be squatted on.

use hxd_core::video::{
    VideoConfig, VideoError, VideoKind, VideoLimits, VideoPublication, VideoStream,
};
use hxproto::messages::tag;
use hxproto::video as wire;

/// `hxd_core`'s kind as the codec's. Both define the same two, so the
/// conversion cannot fail; the panic guards a later revision that grows
/// one side before the other.
fn to_wire(kind: VideoKind) -> wire::VideoKind {
    wire::VideoKind::from_wire(kind.wire()).expect("hxproto defines every hxd_core video kind")
}

/// The codec's kind as `hxd_core`'s. `None` for a kind the codec knows
/// and this server does not, which the caller drops like any other
/// unknown kind.
fn from_wire(kind: wire::VideoKind) -> Option<VideoKind> {
    VideoKind::from_wire(kind.wire())
}

/// The `DATA_VIDEO_PUBLISHERS` (`0x0222`) payload: a packed array of
/// eight-byte entries, `uid | kind | flags | codec id`. A participant
/// publishing both a camera and a screen produces two.
///
/// **A new field, not a widening of `DATA_VOICE_PARTICIPANTS`.** That
/// blob has a six-byte stride and deployed voice clients derive its count
/// by dividing the field length by six; growing the stride would
/// misparse silently in every one of them. Audio state stays there, video
/// state here, and a client correlates the two by user id.
///
/// Every entry says VP8. Video codec ids are their own number space: id 0
/// is PCMU in the voice participants blob and VP8 here.
pub fn publishers_payload(ps: &[VideoPublication]) -> Vec<u8> {
    ps.iter()
        .flat_map(|p| {
            wire::Publication {
                user_id: p.uid,
                kind: to_wire(p.kind),
                flags: if p.paused { wire::FLAG_PAUSED } else { 0 },
                codec_id: wire::CODEC_VP8,
            }
            .to_bytes()
        })
        .collect()
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
    wire::parse_video_subscriptions(data)
        .filter_map(|s| {
            Some(VideoStream {
                uid: s.user_id,
                kind: from_wire(s.kind)?,
            })
        })
        .collect()
}

/// One `DATA_VIDEO_LIMITS` (`0x0224`) field: the server's ceiling for one
/// stream kind, sixteen bytes in this revision with the reserved pair
/// zeroed. A parser must accept a longer field, so a later revision can
/// append.
pub fn limits_payload(kind: VideoKind, l: &VideoLimits) -> Vec<u8> {
    wire::Limits {
        kind: to_wire(kind),
        max_width: l.max_width,
        max_height: l.max_height,
        max_fps: l.max_fps,
        max_bitrate: l.max_bitrate,
        max_per_room: l.max_per_room,
    }
    .to_bytes()
    .to_vec()
}

/// The `DATA_VIDEO_LIMITS` chunks for a login reply — one per kind the
/// server supports, so a client can configure its encoders before the
/// first join rather than discovering the ceilings by rejection.
pub fn limits_chunks(config: &VideoConfig) -> Vec<(u16, Vec<u8>)> {
    VideoKind::ALL
        .iter()
        .map(|k| (tag::VIDEO_LIMITS, limits_payload(*k, &config.limits(*k))))
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
        // so plainly. With one screen slot a room, "the room is full"
        // would be misleading — the room has space, the slot doesn't —
        // and with eight camera slots the reverse is true: nobody in
        // particular is in the way, so telling the user to go and ask
        // someone to stop would send them after a person who doesn't
        // exist.
        VideoError::Full(VideoKind::Screen) => {
            "Someone else is already sharing. Ask them to stop first."
        }
        VideoError::Full(VideoKind::Camera) => "This room has as many cameras on as it allows.",
    }
}

/// The `CHAT_ID` chunk every video transaction carries.
pub fn chat_id(cid: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, cid.to_be_bytes().to_vec())
}

/// The `DATA_VIDEO_KIND` chunk.
pub fn kind_chunk(kind: VideoKind) -> (u16, Vec<u8>) {
    (tag::VIDEO_KIND, kind.wire().to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::access::bit;
    use hxproto::messages::{ClientHdr, ServerHdr};

    #[test]
    fn the_transaction_numbers_continue_the_voice_block() {
        // 600-606 are voice's; video picks up at 607 and stops at 611,
        // leaving 612-619 reserved.
        assert_eq!(ClientHdr::VideoStart.as_u32(), 607);
        assert_eq!(ClientHdr::VideoStop.as_u32(), 608);
        assert_eq!(ClientHdr::VideoState.as_u32(), 609);
        assert_eq!(ClientHdr::VideoSubscribe.as_u32(), 610);
        assert_eq!(ServerHdr::VideoStatus as u32, 611);
        // And the field block starts clear of inline media's 0x0201-0x021F.
        assert_eq!(tag::VIDEO_KIND, 0x0220);
        assert_eq!(tag::VIDEO_SUBSCRIPTIONS, 0x0225);
    }

    #[test]
    fn the_gates_agree_with_the_shared_codec() {
        // The capability and access bits are this server's own, shared
        // with the ng wire; the client reads hxproto's. They must name
        // the same bits.
        assert_eq!(1u64 << crate::caps::cap::VIDEO, wire::CAP_VIDEO);
        assert_eq!(u32::from(bit::VIDEO_CHAT), wire::ACCESS_VIDEO_CHAT);
        assert_eq!(u32::from(bit::SCREEN_SHARE), wire::ACCESS_SCREEN_SHARE);
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
        assert!(chunks.iter().all(|(t, _)| *t == tag::VIDEO_LIMITS));
        assert_eq!(chunks[1].1[0..2], [0, 2], "the screen kind follows");
    }
}
