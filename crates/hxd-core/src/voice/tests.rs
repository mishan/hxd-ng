//! The spec's sequence diagrams, replayed as call traces.
//!
//! Each test drives the domain the way a frontend would and asserts two
//! things: the exact series of calls the media layer received, and the
//! events each session's outbox got. No SDP is parsed and no socket is
//! opened — the fake's offers are distinguishable strings and that is all
//! the tests need them to be.

use std::sync::Arc;

use super::fake::{MediaCall, RecordingMedia};
use super::*;
use crate::access::AccessBits;
use crate::roster::{drain, test_attach, SeqEvent};
use crate::Core;
use tokio::sync::mpsc::UnboundedReceiver;

fn voiced(cap: usize) -> (Core, Arc<RecordingMedia>) {
    let media = Arc::new(RecordingMedia::new());
    let core = Core::new().with_voice(media.clone(), cap);
    (core, media)
}

/// Attach a user with no access bits. Its outbox starts quiet — an
/// arrival is broadcast to everyone *but* the newcomer — and stops being
/// quiet as soon as the next user attaches, so a test whose assertions
/// need an empty outbox `drain`s it immediately before the call it means
/// to assert on, not here.
fn quiet(core: &Core, nick: &str) -> (Uid, UnboundedReceiver<SeqEvent>) {
    test_attach(core, nick, AccessBits::empty())
}

fn offers(evs: &[Event]) -> Vec<String> {
    evs.iter()
        .filter_map(|e| match e {
            Event::VoiceOffer { sdp, .. } => Some(sdp.clone()),
            _ => None,
        })
        .collect()
}

fn statuses(evs: &[Event]) -> Vec<Vec<VoiceParticipant>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::VoiceStatus { participants, .. } => Some(participants.clone()),
            _ => None,
        })
        .collect()
}

fn uids(ps: &[VoiceParticipant]) -> Vec<Uid> {
    ps.iter().map(|p| p.uid).collect()
}

// --- The join / leave diagrams -----------------------------------------

#[test]
fn a_first_joiner_gets_an_offer_an_empty_list_and_its_own_status() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");

    let join = core.voice_join(a, 0).unwrap();
    assert_eq!(join.codec, "PCMU");
    assert!(
        join.participants.is_empty(),
        "the reply lists the room as the joiner found it"
    );
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::Join { uid: a, cid: 0 },
            MediaCall::Offer { uid: a, cid: 0 },
        ]
    );
    let evs = drain(&mut rx_a);
    assert!(offers(&evs).is_empty(), "the initial offer rides the reply");
    assert_eq!(
        statuses(&evs),
        vec![vec![VoiceParticipant {
            uid: a,
            muted: false
        }]]
    );
}

#[test]
fn b_joining_with_a_present_renegotiates_a_and_announces_both() {
    // The spec's "User B joins a room where User A is already in voice"
    // diagram, with A having answered its own initial offer first.
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");

    let a_join = core.voice_join(a, 0).unwrap();
    core.voice_answer(a, 0, format!("answer to {}", a_join.sdp))
        .unwrap();
    drain(&mut rx_a);
    media.take_calls();

    let b_join = core.voice_join(b, 0).unwrap();
    assert_eq!(
        uids(&b_join.participants),
        vec![a],
        "B's reply carries [A], the room before B"
    );
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::Join { uid: b, cid: 0 },
            MediaCall::Offer { uid: b, cid: 0 },
            // The renegotiation A needs to hear B at all.
            MediaCall::Offer { uid: a, cid: 0 },
        ]
    );

    // A: one fresh offer, then the room status naming both.
    let evs = drain(&mut rx_a);
    assert_eq!(offers(&evs).len(), 1);
    assert_ne!(
        offers(&evs)[0],
        a_join.sdp,
        "a renegotiation is a new offer, not the one A already answered"
    );
    assert_eq!(statuses(&evs).last().map(|p| uids(p)), Some(vec![a, b]));

    // B: no offer on the channel (its own rode the reply), and the same
    // status.
    let evs = drain(&mut rx_b);
    assert!(offers(&evs).is_empty());
    assert_eq!(statuses(&evs).last().map(|p| uids(p)), Some(vec![a, b]));
}

#[test]
fn b_leaving_renegotiates_a_and_announces_the_shorter_room() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    let sdp = core.voice_join(b, 0).unwrap().sdp;
    core.voice_answer(b, 0, sdp).unwrap();
    // A has an unanswered renegotiation from B's join; clear it so the
    // leave below isn't deferred.
    let a_offer = offers(&drain(&mut rx_a)).pop().unwrap();
    core.voice_answer(a, 0, a_offer).unwrap();
    media.take_calls();

    core.voice_leave(b, 0).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::Leave { uid: b, cid: 0 },
            MediaCall::Offer { uid: a, cid: 0 },
        ]
    );
    let evs = drain(&mut rx_a);
    assert_eq!(offers(&evs).len(), 1, "A is told the room changed");
    assert_eq!(statuses(&evs).last().map(|p| uids(p)), Some(vec![a]));

    assert_eq!(core.voice_room_of(b), None);
    assert_eq!(uids(&core.voice_participants(0)), vec![a]);
}

// --- Per-peer serialisation --------------------------------------------

#[test]
fn a_room_change_while_an_offer_is_outstanding_waits_for_the_answer() {
    // A joins and does *not* answer. Two more joiners change the room
    // under it. A must receive no second offer until it answers, and
    // then exactly one consolidated offer covering both changes.
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let (c, _rx_c) = quiet(&core, "carol");

    let a_join = core.voice_join(a, 0).unwrap();
    drain(&mut rx_a);
    core.voice_join(b, 0).unwrap();
    core.voice_join(c, 0).unwrap();

    let evs = drain(&mut rx_a);
    assert!(
        offers(&evs).is_empty(),
        "no second offer may go out while one is unanswered"
    );
    assert_eq!(
        statuses(&evs).len(),
        2,
        "status updates are not deferred — only offers are"
    );
    let offer_calls = media
        .calls()
        .iter()
        .filter(|c| matches!(c, MediaCall::Offer { uid, .. } if *uid == a))
        .count();
    assert_eq!(offer_calls, 1, "the media layer wasn't asked either");

    core.voice_answer(a, 0, format!("answer to {}", a_join.sdp))
        .unwrap();
    let evs = drain(&mut rx_a);
    assert_eq!(
        offers(&evs).len(),
        1,
        "the answer releases exactly one consolidated offer"
    );

    // And that one is now outstanding in its turn: answering it with
    // nothing pending produces no further offer.
    let sdp = offers(&evs)[0].clone();
    core.voice_answer(a, 0, sdp).unwrap();
    assert!(offers(&drain(&mut rx_a)).is_empty());
}

#[test]
fn a_leave_while_an_offer_is_outstanding_still_defers() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let a_join = core.voice_join(a, 0).unwrap();
    core.voice_join(b, 0).unwrap();
    drain(&mut rx_a);

    core.voice_leave(b, 0).unwrap();
    assert!(offers(&drain(&mut rx_a)).is_empty());

    core.voice_answer(a, 0, a_join.sdp).unwrap();
    let evs = drain(&mut rx_a);
    assert_eq!(offers(&evs).len(), 1);
}

// --- One room at a time -------------------------------------------------

#[test]
fn joining_a_second_room_completes_the_first_teardown_first() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    // A private chat both are in, so A may join its voice room.
    let (cid, _) = core.chat_create(a, b).unwrap();
    core.chat_join(cid, b, "").unwrap();

    // Both in the lobby's voice; B has answered so it can be renegotiated.
    let sdp = core.voice_join(b, 0).unwrap().sdp;
    core.voice_answer(b, 0, sdp).unwrap();
    core.voice_join(a, 0).unwrap();
    // B answers the renegotiation A's arrival caused, so the teardown
    // below isn't deferred behind an outstanding offer.
    let b_offer = offers(&drain(&mut rx_b)).pop().unwrap();
    core.voice_answer(b, 0, b_offer).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);
    media.take_calls();

    core.voice_join(a, cid).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![
            // The old room is torn down, and its survivor renegotiated,
            // before the new room is touched at all.
            MediaCall::Leave { uid: a, cid: 0 },
            MediaCall::Offer { uid: b, cid: 0 },
            MediaCall::Join { uid: a, cid },
            MediaCall::Offer { uid: a, cid },
        ]
    );
    // B hears about the lobby losing A.
    assert_eq!(
        statuses(&drain(&mut rx_b)).last().map(|p| uids(p)),
        Some(vec![b])
    );
    assert_eq!(core.voice_room_of(a), Some(cid));
    assert_eq!(uids(&core.voice_participants(0)), vec![b]);
}

#[test]
fn a_failed_second_join_leaves_the_user_in_no_room() {
    // "If the join in room B fails, the user is left in no voice room.
    // The server MUST NOT re-join the user to room A."
    let (core, _media) = voiced(1);
    let (a, _rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let (cid, _) = core.chat_create(a, b).unwrap();
    core.chat_join(cid, b, "").unwrap();

    core.voice_join(b, cid).unwrap(); // fills the room (cap 1)
    core.voice_join(a, 0).unwrap();
    assert_eq!(core.voice_room_of(a), Some(0));

    assert_eq!(core.voice_join(a, cid), Err(VoiceError::RoomFull));
    assert_eq!(core.voice_room_of(a), None, "not re-joined to the lobby");
    assert!(core.voice_participants(0).is_empty());
}

#[test]
fn rejoining_the_same_room_is_a_clean_teardown_and_rebuild() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    core.voice_join(a, 0).unwrap();
    media.take_calls();

    core.voice_join(a, 0).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::Leave { uid: a, cid: 0 },
            MediaCall::Join { uid: a, cid: 0 },
            MediaCall::Offer { uid: a, cid: 0 },
        ],
        "a rejoin gets a fresh session, not the stale one's credentials"
    );
    assert_eq!(uids(&core.voice_participants(0)), vec![a]);
}

// --- Who may be in which room ------------------------------------------

#[test]
fn a_private_rooms_membership_is_what_stops_a_guessed_id() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let (cid, _) = core.chat_create(a, b).unwrap();

    // B was invited but hasn't joined the chat: not a member, no voice.
    assert_eq!(core.voice_join(b, cid), Err(VoiceError::NotAMember));
    core.chat_join(cid, b, "").unwrap();
    assert!(core.voice_join(b, cid).is_ok());

    // A room that doesn't exist is not a room you can talk in.
    assert_eq!(core.voice_join(a, 0xdead_beef), Err(VoiceError::NoSuchChat));
    // The public chat needs no membership — the access bit, checked by
    // the frontend, is its whole gate.
    assert!(core.voice_join(a, 0).is_ok());
}

#[test]
fn the_room_cap_is_enforced_per_room() {
    let (core, _media) = voiced(2);
    let (a, _ra) = quiet(&core, "a");
    let (b, _rb) = quiet(&core, "b");
    let (c, _rc) = quiet(&core, "c");
    core.voice_join(a, 0).unwrap();
    core.voice_join(b, 0).unwrap();
    assert_eq!(core.voice_join(c, 0), Err(VoiceError::RoomFull));
    core.voice_leave(a, 0).unwrap();
    assert!(core.voice_join(c, 0).is_ok());
}

// --- Answers, mute, ICE -------------------------------------------------

#[test]
fn a_rejected_answer_tears_the_peer_down() {
    // "If a client's SDP answer does not include PCMU, the server MUST
    // reject the answer and tear down the pending peer connection."
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    let b_join = core.voice_join(b, 0).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);
    media.take_calls();

    media.reject_next_answer();
    assert_eq!(
        core.voice_answer(b, 0, b_join.sdp),
        Err(VoiceError::BadAnswer)
    );
    assert_eq!(core.voice_room_of(b), None, "the peer is gone, not pending");
    assert_eq!(uids(&core.voice_participants(0)), vec![a]);
    // A is renegotiated and re-announced exactly as for any other leave.
    assert_eq!(
        statuses(&drain(&mut rx_a)).last().map(|p| uids(p)),
        Some(vec![a])
    );
}

#[test]
fn an_answer_to_no_outstanding_offer_is_refused_and_costs_the_peer_nothing() {
    // The server is always the offerer, so a client may only answer while
    // it owes one. Without the check it could re-answer as often as it
    // liked, and each answer would bind another expected SSRC in the media
    // layer that nothing would ever retire.
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let join = core.voice_join(a, 0).unwrap();
    core.voice_answer(a, 0, format!("answer to {}", join.sdp))
        .unwrap();
    drain(&mut rx_a);
    media.take_calls();

    assert_eq!(
        core.voice_answer(a, 0, "answer to nothing at all".into()),
        Err(VoiceError::BadAnswer)
    );
    assert!(
        media.take_calls().is_empty(),
        "the media layer is never told about it, which is the point"
    );
    assert_eq!(
        core.voice_room_of(a),
        Some(0),
        "and the peer is not torn down for it — this is a client repeating \
         itself, not a client that cannot do PCMU"
    );
    assert!(drain(&mut rx_a).is_empty());
}

#[test]
fn the_gate_on_answers_still_lets_a_consolidated_follow_up_through() {
    // The refusal above must not cost renegotiation anything: the peer
    // that answers an offer and is immediately handed the follow-up its
    // dirty flag was holding has to be able to answer that one too.
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");

    let a_join = core.voice_join(a, 0).unwrap();
    drain(&mut rx_a);
    // B's arrival changes the room while A still owes an answer, so A goes
    // dirty rather than getting a second offer.
    core.voice_join(b, 0).unwrap();
    assert!(offers(&drain(&mut rx_a)).is_empty());

    // The good path: the answer to the offer that rode the join reply.
    core.voice_answer(a, 0, format!("answer to {}", a_join.sdp))
        .unwrap();
    let follow_up = offers(&drain(&mut rx_a))
        .pop()
        .expect("the dirty flag releases exactly one consolidated offer");

    // That follow-up is outstanding in its own right, so answering it is
    // allowed — once.
    assert_eq!(core.voice_answer(a, 0, follow_up.clone()), Ok(()));
    assert_eq!(
        core.voice_answer(a, 0, follow_up),
        Err(VoiceError::BadAnswer)
    );
    assert_eq!(core.voice_room_of(a), Some(0));
    assert_eq!(
        media
            .calls()
            .iter()
            .filter(|c| matches!(c, MediaCall::Answer { uid, .. } if *uid == a))
            .count(),
        2,
        "two offers, two answers — the third never reached the media layer"
    );
}

#[test]
fn mute_is_recorded_enforced_and_announced_once() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    core.voice_join(a, 0).unwrap();
    drain(&mut rx_a);
    media.take_calls();

    core.voice_mute(a, 0, true).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![MediaCall::SetMuted {
            uid: a,
            cid: 0,
            muted: true
        }]
    );
    assert_eq!(
        statuses(&drain(&mut rx_a)),
        vec![vec![VoiceParticipant {
            uid: a,
            muted: true
        }]]
    );

    // Push-to-talk bounces the same value repeatedly; a toggle that
    // changes nothing is acked and goes no further.
    core.voice_mute(a, 0, true).unwrap();
    assert!(media.take_calls().is_empty());
    assert!(drain(&mut rx_a).is_empty());

    core.voice_mute(a, 0, false).unwrap();
    assert_eq!(
        statuses(&drain(&mut rx_a)),
        vec![vec![VoiceParticipant {
            uid: a,
            muted: false
        }]]
    );
    // Mute never renegotiates: no tracks changed.
    assert!(!media
        .calls()
        .iter()
        .any(|c| matches!(c, MediaCall::Offer { .. })));
}

#[test]
fn ice_crosses_in_both_directions_and_only_for_the_users_own_room() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    core.voice_join(a, 0).unwrap();
    drain(&mut rx_a);
    media.take_calls();

    let cand = IceCandidate {
        candidate: "candidate:1 1 UDP 2130706431 192.0.2.1 5504 typ host".into(),
        sdp_mid: Some("send".into()),
        sdp_mline_index: Some(0),
        username_fragment: None,
    };
    assert_eq!(core.voice_ice(a, 0, cand.clone()), Ok(()));
    assert_eq!(
        media.take_calls(),
        vec![MediaCall::Ice {
            uid: a,
            cid: 0,
            candidate: cand
        }]
    );
    // A candidate for a room this user isn't in goes nowhere, and the
    // caller is told which it is. The legacy wire has no reply to carry
    // that and drops it; the ng wire answers `not_in_voice`, as its own
    // spec says it does.
    assert_eq!(
        core.voice_ice(a, 77, IceCandidate::default()),
        Err(VoiceError::NotInVoice)
    );
    assert!(media.take_calls().is_empty());

    // The server's own candidate comes back the other way.
    let eoc = IceCandidate::end_of_candidates("send");
    assert!(eoc.is_end_of_candidates());
    core.voice_media_event(MediaEvent::Ice {
        uid: a,
        cid: 0,
        candidate: eoc.clone(),
    });
    assert_eq!(
        drain(&mut rx_a),
        vec![Event::VoiceIce {
            cid: 0,
            candidate: eoc
        }]
    );
}

#[test]
fn a_media_failure_is_a_leave() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    core.voice_join(b, 0).unwrap();
    drain(&mut rx_a);

    // B's ICE never completes; the SFU gives up on it.
    core.voice_media_event(MediaEvent::Failed { uid: b, cid: 0 });
    assert_eq!(core.voice_room_of(b), None);
    assert_eq!(
        statuses(&drain(&mut rx_a)).last().map(|p| uids(p)),
        Some(vec![a])
    );
    // A stale failure for a room the peer already left changes nothing.
    core.voice_media_event(MediaEvent::Failed { uid: b, cid: 0 });
    assert_eq!(uids(&core.voice_participants(0)), vec![a]);
}

// --- Cleanup, on every path ---------------------------------------------

#[test]
fn a_user_removed_from_voice_is_told_even_with_no_reply_to_carry_it() {
    // An explicit leave has its own reply for an ack. A media timeout, a
    // kick from the chat and a lost connection have none, and a client
    // whose voice UI is still live needs to hear about it somehow.
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    core.voice_join(b, 0).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);

    core.voice_media_event(MediaEvent::Failed { uid: b, cid: 0 });
    assert_eq!(
        statuses(&drain(&mut rx_b)).last().map(|p| uids(p)),
        Some(vec![a]),
        "the failed peer is told it is out of the room"
    );

    // And the same for a chat part, which has no reply either.
    let (cid, _) = core.chat_create(a, b).unwrap();
    core.chat_join(cid, b, "").unwrap();
    core.voice_join(b, cid).unwrap();
    drain(&mut rx_b);
    core.chat_part(cid, b);
    assert_eq!(
        statuses(&drain(&mut rx_b)).last().map(|p| uids(p)),
        Some(vec![]),
    );
}

#[test]
fn ending_a_session_leaves_voice() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    core.voice_join(b, 0).unwrap();
    drain(&mut rx_a);
    media.take_calls();

    core.end_session(b);
    assert!(media
        .take_calls()
        .contains(&MediaCall::Leave { uid: b, cid: 0 }));
    let evs = drain(&mut rx_a);
    assert_eq!(statuses(&evs).last().map(|p| uids(p)), Some(vec![a]));
    assert!(evs.contains(&Event::Parted(b)));
}

#[test]
fn losing_the_connection_leaves_voice_even_when_the_session_survives() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = core
        .attach(crate::AttachInfo {
            nick: "mobile".into(),
            icon: 1,
            admin: false,
            access: AccessBits::empty(),
            login: "mobile".into(),
            addr: None,
            can_detach: true,
            transport: crate::Transport::default(),
            has_inbox: true,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
        })
        .unwrap();
    core.announce(b);
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    core.voice_join(b, 0).unwrap();
    drain(&mut rx_a);
    media.take_calls();

    assert!(core.connection_lost(b, 8), "the session detaches");
    assert!(media
        .take_calls()
        .contains(&MediaCall::Leave { uid: b, cid: 0 }));
    assert_eq!(
        core.voice_room_of(b),
        None,
        "a detached user is not in voice"
    );
    assert_eq!(
        statuses(&drain(&mut rx_a)).last().map(|p| uids(p)),
        Some(vec![a])
    );
}

#[test]
fn the_departure_from_voice_is_waiting_in_the_replay_tail() {
    // docs/voice.md §8: a resuming session finds the status saying it is
    // out of voice in its replay. That only holds if the outbox is
    // already buffering when the departure is sent — sent live, it goes
    // to the socket that just died and the client resumes to a voice UI
    // with nothing behind it.
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = core
        .attach(crate::AttachInfo {
            nick: "mobile".into(),
            icon: 1,
            admin: false,
            access: AccessBits::empty(),
            login: "mobile".into(),
            addr: None,
            can_detach: true,
            transport: crate::Transport::default(),
            has_inbox: true,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
        })
        .unwrap();
    core.announce(b);
    core.voice_join(a, 0).unwrap();
    core.voice_join(b, 0).unwrap();

    // Everything B has seen so far, so the resume asks only for what the
    // disconnect itself produced.
    let last_seq = std::iter::from_fn(|| rx_b.try_recv().ok())
        .map(|se| se.seq)
        .last()
        .expect("B saw its own join");
    drop(rx_b);

    assert!(core.connection_lost(b, 8), "the session detaches");
    let crate::Resume::Replayed(_rx, replay) = core.resume(b, last_seq) else {
        panic!("the buffer covers the gap");
    };
    let evs: Vec<Event> = replay.into_iter().map(|se| se.event).collect();
    assert_eq!(
        statuses(&evs).last().map(|p| uids(p)),
        Some(vec![a]),
        "B's own departure from voice is replayed to it — the room it \
         names is the one it is no longer in"
    );
}

#[test]
fn a_join_the_media_layer_cannot_seat_is_not_a_join() {
    // The offer sentinel at its most awkward: the media layer took the
    // join and then had no session to describe. Nobody has been told
    // this user arrived, so the room must look untouched afterwards.
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    core.voice_join(a, 0).unwrap();
    drain(&mut rx_a);
    media.take_calls();

    media.no_next_offer();
    assert_eq!(core.voice_join(b, 0), Err(VoiceError::RoomFull));
    assert_eq!(core.voice_room_of(b), None, "B is in no room");
    assert_eq!(
        uids(&core.voice_participants(0)),
        vec![a],
        "and the room is as it was"
    );
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::Join { uid: b, cid: 0 },
            MediaCall::Offer { uid: b, cid: 0 },
            MediaCall::Leave { uid: b, cid: 0 },
        ],
        "the media layer is told to drop what it took"
    );
    assert!(
        drain(&mut rx_a).is_empty(),
        "A is never offered a room containing a joiner that isn't there"
    );
    assert!(drain(&mut rx_b).is_empty());

    // And the next join is unaffected.
    core.voice_join(b, 0).unwrap();
    assert_eq!(uids(&core.voice_participants(0)), vec![a, b]);
}

#[test]
fn an_offer_the_media_layer_declines_is_not_sent_to_anyone() {
    // The same sentinel on the renegotiation path: B's departure makes A
    // want a fresh offer, and A turns out to have no session left.
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let (c, _rx_c) = quiet(&core, "carol");
    let sdp = core.voice_join(a, 0).unwrap().sdp;
    core.voice_answer(a, 0, sdp).unwrap();
    let sdp = core.voice_join(b, 0).unwrap().sdp;
    core.voice_answer(b, 0, sdp).unwrap();
    let a_offer = offers(&drain(&mut rx_a)).pop().unwrap();
    core.voice_answer(a, 0, a_offer).unwrap();
    drain(&mut rx_a);

    media.no_next_offer();
    core.voice_leave(b, 0).unwrap();
    assert!(
        offers(&drain(&mut rx_a)).is_empty(),
        "no zero-length SDP goes out in place of an offer"
    );

    // A owes nothing after that non-offer, so the next room change finds
    // it able to be offered again rather than looking like it still owes
    // an answer to something that was never sent.
    core.voice_join(c, 0).unwrap();
    assert_eq!(offers(&drain(&mut rx_a)).len(), 1);
}

#[test]
fn the_media_layers_reason_for_refusing_an_answer_is_the_clients() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    core.voice_join(a, 0).unwrap();

    // Not `BadAnswer`: the session died under us, and saying the SDP was
    // bad would send a client off debugging its own codecs.
    media.reject_next_answer_with(VoiceError::NotInVoice);
    assert_eq!(
        core.voice_answer(a, 0, "sdp".into()),
        Err(VoiceError::NotInVoice)
    );
    assert_eq!(
        core.voice_room_of(a),
        None,
        "and the peer goes with the refusal whatever the reason"
    );
}

#[test]
fn parting_a_chat_leaves_that_chats_voice_room_and_no_other() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    let (cid, _) = core.chat_create(a, b).unwrap();
    core.chat_join(cid, b, "").unwrap();

    core.voice_join(a, cid).unwrap();
    core.chat_part(cid, a);
    assert_eq!(core.voice_room_of(a), None);

    // The lobby's voice is nobody's chat membership: parting a private
    // chat while in the lobby's voice room leaves it alone.
    core.voice_join(a, 0).unwrap();
    core.chat_part(cid, a);
    assert_eq!(core.voice_room_of(a), Some(0));
}

#[test]
fn kicking_a_detached_user_takes_their_voice_with_them() {
    let (core, media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    core.voice_join(a, 0).unwrap();
    media.take_calls();

    core.kick(a, None).unwrap();
    // An attached session ends when its transport observes the kick;
    // here the transport is the test, so end_session stands in for it.
    core.end_session(a);
    assert!(media
        .take_calls()
        .contains(&MediaCall::Leave { uid: a, cid: 0 }));
    assert!(core.voice_participants(0).is_empty());
}

#[test]
fn the_last_participant_out_takes_the_room_with_them() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    core.voice_join(a, 0).unwrap();
    core.voice_leave(a, 0).unwrap();
    assert!(core.voice_participants(0).is_empty());
    assert_eq!(core.voice_leave(a, 0), Err(VoiceError::NotInVoice));
}

// --- Without an SFU -----------------------------------------------------

#[test]
fn every_voice_call_is_refused_without_a_media_layer() {
    let core = Core::new();
    let (a, mut rx_a) = quiet(&core, "alice");
    assert!(!core.voice_enabled());
    // Each method answers from the closed set `docs/voice.md` §8 lists
    // for it, and no method answers outside its own. `voice_disabled` is
    // in join's set and in nobody else's, which is right on both counts:
    // it is the honest answer to "let me in" and it would be a
    // gratuitously different answer to "let me out" — with no SFU nobody
    // is in voice, so `not_in_voice` is the accurate answer as well as
    // the documented one.
    assert_eq!(core.voice_join(a, 0), Err(VoiceError::Disabled));
    assert_eq!(core.voice_leave(a, 0), Err(VoiceError::NotInVoice));
    assert_eq!(
        core.voice_answer(a, 0, "x".into()),
        Err(VoiceError::NotInVoice)
    );
    assert_eq!(core.voice_mute(a, 0, true), Err(VoiceError::NotInVoice));
    assert_eq!(
        core.voice_ice(a, 0, IceCandidate::default()),
        Err(VoiceError::NotInVoice)
    );
    assert!(core.voice_participants(0).is_empty());
    // And a voice-free server is exactly the server it was before: no
    // session sees anything.
    assert!(drain(&mut rx_a).is_empty());
    core.end_session(a);
}

#[test]
fn operations_on_a_room_the_user_is_not_in_are_refused() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    let (a, _rx_a) = quiet(&core, "alice");
    assert_eq!(core.voice_leave(a, 0), Err(VoiceError::NotInVoice));
    assert_eq!(
        core.voice_answer(a, 0, "x".into()),
        Err(VoiceError::NotInVoice)
    );
    assert_eq!(core.voice_mute(a, 0, true), Err(VoiceError::NotInVoice));

    core.voice_join(a, 0).unwrap();
    // In voice, but not in *that* room.
    assert_eq!(core.voice_leave(a, 9), Err(VoiceError::NotInVoice));
    assert_eq!(core.voice_mute(a, 9, true), Err(VoiceError::NotInVoice));
}

#[test]
fn a_user_who_is_not_on_the_roster_cannot_join() {
    let (core, _media) = voiced(DEFAULT_MAX_PER_ROOM);
    assert_eq!(core.voice_join(4242, 0), Err(VoiceError::NotAMember));
}
