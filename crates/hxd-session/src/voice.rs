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

/// Read a `DATA_VOICE_ICE` payload.
///
/// An empty field is the spec's end-of-candidates shorthand and is a
/// candidate with an empty string, not a parse failure. Anything else
/// that doesn't parse is dropped: 604 is a notification, so there is no
/// reply to carry an error and nothing useful to do with a malformed one.
pub fn parse_ice(data: &[u8]) -> Option<IceCandidate> {
    if data.is_empty() {
        return Some(IceCandidate::default());
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
}
