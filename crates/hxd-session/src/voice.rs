//! Voice on the legacy wire: transactions 600–606 and fields
//! `0x01F5`–`0x01F9`.
//!
//! Everything here is encoding. The rooms, the one-room rule, the
//! serialisation of offers against answers and every cleanup path live in
//! `hxd_core::voice`; this module turns those calls and events into the
//! shapes a 1.x client with the voice extension expects, and turns its
//! transactions back into calls.
//!
//! Two rules from the spec shape the module. Voice transactions are only
//! ever sent to a client that negotiated `CAPABILITY_VOICE` at login —
//! which is what makes this invisible to every client that predates the
//! extension. And the three server-initiated notifications carry **task
//! id 0**, not the push counter the rest of this frontend uses; see
//! [`crate::session`]'s writer.

use hotline_proto::messages::tag;
use hotline_proto::voice::ice as wire_ice;
use hxd_core::voice::{IceCandidate, VoiceError, VoiceParticipant};

/// PCMU's id in the participants blob's codec field. The only codec the
/// spec defines, and the only one a room can be using.
const CODEC_PCMU: u16 = 0;

/// Flags bit 0 of a participant entry.
const FLAG_MUTED: u16 = 0x0001;

/// The `DATA_VOICE_PARTICIPANTS` (`0x01F9`) payload: a packed array of
/// six-byte entries, `uid | flags | codec id`, all big-endian.
///
/// `hotline_proto::voice::parse_voice_participants` is the client-side
/// half of this and the round-trip test in this module runs against it,
/// which is the check that actually matters — our encoder against the
/// decoder GtkHx really uses. The encoder itself stays here rather than
/// in the shared crate until the shared-crate extraction gives the two
/// halves a home together; six bytes an entry is not worth a coordinated
/// submodule bump.
pub fn participants_payload(ps: &[VoiceParticipant]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ps.len() * 6);
    for p in ps {
        v.extend_from_slice(&p.uid.to_be_bytes());
        v.extend_from_slice(&(if p.muted { FLAG_MUTED } else { 0 }).to_be_bytes());
        v.extend_from_slice(&CODEC_PCMU.to_be_bytes());
    }
    v
}

/// The `DATA_VOICE_ICE` (`0x01F6`) payload: the `RTCIceCandidateInit`
/// dictionary as a JSON string, which is what the spec puts on this wire
/// (the ng wire carries the same fields as an object — see
/// `docs/voice.md` §8).
pub fn ice_payload(c: &IceCandidate) -> Vec<u8> {
    wire_ice::build(&wire_ice::IceCandidate {
        candidate: Some(c.candidate.clone()),
        sdp_mid: c.sdp_mid.clone(),
        sdp_mline_index: c.sdp_mline_index,
        username_fragment: c.username_fragment.clone(),
    })
    .into_bytes()
}

/// How deeply a `DATA_VOICE_ICE` payload may nest objects and arrays
/// before [`parse_ice`] refuses it.
///
/// An `RTCIceCandidateInit` is a flat object of four scalar members, so
/// the shape the spec defines never gets past depth one. Eight leaves
/// room for a future member that is itself an object or an array —
/// forward compatibility is the point of the shared parser skipping
/// members it doesn't know — while staying far below anything that
/// troubles the stack.
const MAX_ICE_DEPTH: usize = 8;

/// Whether `data` nests no deeper than [`MAX_ICE_DEPTH`].
///
/// This is a backstop, not the fix. `wire_ice::parse`'s `skip_value`,
/// `skip_object` and `skip_array` are mutually recursive with no depth
/// limit, and unknown members are skipped before the required-key check
/// ever runs, so a few tens of thousands of `[` — still an order of
/// magnitude inside the 65535-byte chunk limit — overflow the stack and
/// abort the process. 604 is a notification any logged-in client that
/// negotiated voice may send, so that is one frame against every session
/// on both wires. One pass over bytes we are about to parse anyway is a
/// cheap price for closing it here.
///
/// The real fix belongs upstream in `hotline-proto`, which is a read-only
/// submodule to us: GtkHx runs the same parser on server-supplied 604s
/// and has the mirror-image exposure, which nothing on this side can help
/// with. Drop this guard once the shared parser carries its own depth
/// limit.
///
/// Braces inside a string literal are content, not nesting — a candidate
/// attribute may legitimately contain them — so the scan tracks strings
/// and their escapes rather than counting bytes blindly.
fn ice_depth_ok(data: &[u8]) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in data {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_ICE_DEPTH {
                    return false;
                }
            }
            // Unbalanced closers are the shared parser's business to
            // reject; here they only need to not underflow.
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Read a `DATA_VOICE_ICE` payload.
///
/// An empty field is the spec's end-of-candidates shorthand and is a
/// candidate with an empty string, not a parse failure. Anything else
/// that doesn't parse is dropped: 604 is a notification, so there is no
/// reply to carry an error and nothing useful to do with a malformed one.
/// A payload that nests too deeply is refused before the shared parser
/// sees it at all — see [`ice_depth_ok`].
pub fn parse_ice(data: &[u8]) -> Option<IceCandidate> {
    if data.is_empty() {
        return Some(IceCandidate::default());
    }
    if !ice_depth_ok(data) {
        return None;
    }
    let c = wire_ice::parse(data)?;
    Some(IceCandidate {
        candidate: c.candidate.unwrap_or_default(),
        sdp_mid: c.sdp_mid,
        sdp_mline_index: c.sdp_mline_index,
        username_fragment: c.username_fragment,
    })
}

/// Task-error text for a refused voice operation. The privilege refusal
/// is worded exactly as the spec writes it; the rest follow this
/// frontend's convention of saying something a human can act on.
pub fn err_text(e: VoiceError) -> &'static str {
    match e {
        VoiceError::Disabled => "Voice chat is not available on this server.",
        VoiceError::NoSuchChat => "That chat does not exist.",
        VoiceError::NotAMember => "You are not in that chat.",
        VoiceError::RoomFull => "That voice chat is full.",
        VoiceError::NotInVoice => "You are not in that voice chat.",
        VoiceError::BadAnswer => "Your client's voice session was rejected.",
    }
}

/// The `CHAT_ID` chunk every voice transaction carries.
pub fn chat_id(cid: u32) -> (u16, Vec<u8>) {
    (tag::CHAT_ID, cid.to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hotline_proto::voice::parse_voice_participants;

    #[test]
    fn the_participants_blob_round_trips_through_the_clients_parser() {
        let ps = vec![
            VoiceParticipant {
                uid: 1,
                muted: false,
            },
            VoiceParticipant {
                uid: 65535,
                muted: true,
            },
        ];
        let blob = participants_payload(&ps);
        assert_eq!(blob.len(), 12, "six bytes an entry");

        let decoded: Vec<_> = parse_voice_participants(&blob).collect();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].user_id, 1);
        assert!(!decoded[0].is_muted());
        assert_eq!(decoded[0].codec_id, CODEC_PCMU);
        assert_eq!(decoded[1].user_id, 65535);
        assert!(decoded[1].is_muted());

        // Byte for byte, so a change to either side has to be deliberate.
        assert_eq!(blob, vec![0, 1, 0, 0, 0, 0, 0xff, 0xff, 0, 1, 0, 0]);
        assert!(participants_payload(&[]).is_empty());
    }

    #[test]
    fn ice_candidates_round_trip_as_the_json_the_spec_names() {
        let c = IceCandidate {
            candidate: "candidate:1 1 UDP 2130706431 192.0.2.1 5504 typ host".into(),
            sdp_mid: Some("send".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("abc123".into()),
        };
        let json = ice_payload(&c);
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains("\"candidate\""));
        assert!(text.contains("\"sdpMid\":\"send\""));
        assert_eq!(parse_ice(&json), Some(c));
    }

    #[test]
    fn an_empty_ice_field_is_end_of_candidates() {
        let eoc = parse_ice(&[]).unwrap();
        assert!(eoc.is_end_of_candidates());
        // And the long form — an object with an empty candidate — reads
        // the same way, which is the shape the spec's example uses.
        let long = ice_payload(&IceCandidate::end_of_candidates("send"));
        assert!(parse_ice(&long).unwrap().is_end_of_candidates());
    }

    #[test]
    fn a_malformed_ice_payload_is_dropped_not_guessed_at() {
        assert_eq!(parse_ice(b"{not json"), None);
        assert_eq!(parse_ice(b"{}"), None);
    }

    #[test]
    fn a_deeply_nested_ice_payload_is_refused_before_it_overflows_the_stack() {
        // A thousand is far past the ceiling and cheap to build; the
        // payload that actually aborted the process needed some
        // twenty-six thousand, which the chunk limit still admits.
        let mut deep = b"{\"x\":".to_vec();
        deep.extend(std::iter::repeat_n(b'[', 1000));
        assert_eq!(parse_ice(&deep), None);
    }

    #[test]
    fn an_ice_candidate_with_an_unknown_member_still_parses() {
        let json = br#"{"candidate":"candidate:1 1 UDP 2130706431 192.0.2.1 5504 typ host",
                        "sdpMid":"send","futureThing":{"nested":[1,2]}}"#;
        let c = parse_ice(json).expect("an unknown member is skipped, not refused");
        assert_eq!(c.sdp_mid.as_deref(), Some("send"));
    }

    #[test]
    fn an_ice_candidate_whose_candidate_string_contains_brackets_still_parses() {
        // The depth scan has to know a brace inside a string literal is
        // content: IPv6 candidates bracket their addresses.
        let c = IceCandidate {
            candidate: "candidate:1 1 UDP 2130706431 [2001:db8::1] 5504 typ host {}".into(),
            sdp_mid: Some("send".into()),
            sdp_mline_index: None,
            username_fragment: None,
        };
        assert_eq!(parse_ice(&ice_payload(&c)), Some(c));
    }
}
