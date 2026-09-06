//! The video spec's rules, replayed as call traces.
//!
//! Same shape as the voice tests next door: drive the domain the way a
//! frontend would, then assert the exact series of calls the media layer
//! received and the events each session's outbox got. No SDP, no socket,
//! no WebRTC — the questions here are all policy ones.

use std::sync::Arc;

use super::*;
use crate::access::AccessBits;
use crate::roster::{drain, test_attach, SeqEvent};
use crate::voice::fake::{MediaCall, RecordingMedia};
use crate::voice::DEFAULT_MAX_PER_ROOM;
use crate::Core;
use tokio::sync::mpsc::UnboundedReceiver;

fn videoed() -> (Core, Arc<RecordingMedia>) {
    let media = Arc::new(RecordingMedia::new());
    let core = Core::new()
        .with_voice(media.clone(), DEFAULT_MAX_PER_ROOM)
        .with_video(VideoConfig::default());
    (core, media)
}

fn quiet(core: &Core, nick: &str) -> (Uid, UnboundedReceiver<SeqEvent>) {
    test_attach(core, nick, AccessBits::empty())
}

/// Join voice, answer the initial offer, and start from a quiet outbox —
/// the state every video test begins in, because video needs a voice
/// session under it.
fn in_voice(core: &Core, media: &RecordingMedia, uid: Uid, rx: &mut UnboundedReceiver<SeqEvent>) {
    let join = core.voice_join(uid, 0).unwrap();
    core.voice_answer(uid, 0, format!("answer to {}", join.sdp))
        .unwrap();
    drain(rx);
    media.take_calls();
}

/// The same for a whole room, **with every renegotiation answered**.
///
/// This matters more than it looks. Each join renegotiates everyone
/// already in the room, and the voice extension forbids a second offer
/// to a peer that still owes an answer — so a peer left holding one
/// silently absorbs the next video change into a consolidated follow-up
/// instead of getting its own offer. That is correct behaviour and it is
/// exactly what these tests must not accidentally be measuring, so the
/// room is settled before any of them starts.
fn joined(
    core: &Core,
    media: &RecordingMedia,
    users: &mut [(Uid, &mut UnboundedReceiver<SeqEvent>)],
) {
    for (uid, rx) in users.iter_mut() {
        let join = core.voice_join(*uid, 0).unwrap();
        core.voice_answer(*uid, 0, format!("answer to {}", join.sdp))
            .unwrap();
        drain(rx);
    }
    // An answer can itself release a deferred follow-up offer, so keep
    // going until nobody is holding one.
    loop {
        let mut answered = false;
        for (uid, rx) in users.iter_mut() {
            for ev in drain(rx) {
                if let Event::VoiceOffer { cid, sdp } = ev {
                    core.voice_answer(*uid, cid, format!("answer to {sdp}"))
                        .unwrap();
                    answered = true;
                }
            }
        }
        if !answered {
            break;
        }
    }
    media.take_calls();
}

/// Answer every offer sitting in one session's outbox. Between two video
/// changes a test wants to see separately, this is what clears the
/// serialisation rule out of the way — a peer still owing an answer has
/// its next change deferred into a consolidated follow-up rather than
/// getting an offer of its own.
fn answer_offers(core: &Core, uid: Uid, rx: &mut UnboundedReceiver<SeqEvent>) {
    for ev in drain(rx) {
        if let Event::VoiceOffer { cid, sdp } = ev {
            core.voice_answer(uid, cid, format!("answer to {sdp}"))
                .unwrap();
        }
    }
}

fn offer_targets(evs: &[Event]) -> usize {
    evs.iter()
        .filter(|e| matches!(e, Event::VoiceOffer { .. }))
        .count()
}

fn publications(evs: &[Event]) -> Vec<Vec<VideoPublication>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::VideoStatus { publications, .. } => Some(publications.clone()),
            _ => None,
        })
        .collect()
}

/// The last video status a session saw — a client replaces its whole view
/// on each one, so the last is the only one that describes the room now.
fn latest(evs: &[Event]) -> Vec<VideoPublication> {
    publications(evs).pop().unwrap_or_default()
}

fn cam(uid: Uid) -> VideoStream {
    VideoStream {
        uid,
        kind: VideoKind::Camera,
    }
}

fn screen(uid: Uid) -> VideoStream {
    VideoStream {
        uid,
        kind: VideoKind::Screen,
    }
}

// --- Starting and stopping ---------------------------------------------

#[test]
fn starting_renegotiates_the_publisher_alone_and_tells_the_room() {
    // The rule that makes the extension deployable: one camera starting
    // in a room does not renegotiate the room. It renegotiates the
    // publisher, to add its own send section, and notifies everyone else.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    drain(&mut rx_a);
    media.take_calls();

    assert_eq!(core.video_start(a, 0, VideoKind::Camera).unwrap(), "VP8");
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::Publish {
                uid: a,
                cid: 0,
                kind: VideoKind::Camera
            },
            MediaCall::Offer { uid: a, cid: 0 },
        ],
        "the publisher's offer, and nobody else's"
    );

    let evs_a = drain(&mut rx_a);
    let evs_b = drain(&mut rx_b);
    assert_eq!(offer_targets(&evs_a), 1);
    assert_eq!(
        offer_targets(&evs_b),
        0,
        "B has not subscribed, so B's connection is untouched"
    );
    // Both are told, though — B needs to know what exists before it can
    // decide whether to ask for it.
    let expected = vec![VideoPublication {
        uid: a,
        kind: VideoKind::Camera,
        paused: false,
    }];
    assert_eq!(latest(&evs_a), expected);
    assert_eq!(latest(&evs_b), expected);
}

#[test]
fn a_participant_may_hold_one_publication_of_each_kind() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);

    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_start(a, 0, VideoKind::Screen).unwrap();
    assert_eq!(
        core.video_start(a, 0, VideoKind::Camera),
        Err(VideoError::AlreadyPublishing)
    );
    // One participant, two publications — which is exactly why the
    // publishers blob is keyed by (uid, kind) and not by uid.
    assert_eq!(
        core.video_publications(0),
        vec![
            VideoPublication {
                uid: a,
                kind: VideoKind::Camera,
                paused: false
            },
            VideoPublication {
                uid: a,
                kind: VideoKind::Screen,
                paused: false
            },
        ]
    );
}

#[test]
fn screen_slots_are_room_wide_and_the_existing_share_is_never_preempted() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);

    core.video_start(a, 0, VideoKind::Screen).unwrap();
    assert_eq!(
        core.video_start(b, 0, VideoKind::Screen),
        Err(VideoError::Full),
        "one screen slot a room by default"
    );
    // Cameras have their own slots and are unaffected.
    core.video_start(b, 0, VideoKind::Camera).unwrap();
    // A's share is still A's.
    assert_eq!(
        core.video_publications(0)
            .iter()
            .find(|p| p.kind == VideoKind::Screen)
            .map(|p| p.uid),
        Some(a)
    );
}

#[test]
fn a_paused_publication_still_holds_its_slot() {
    // What makes pause cheap and stop meaningful. If pausing released the
    // slot, someone else could take it while a sharer stepped away.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);

    core.video_start(a, 0, VideoKind::Screen).unwrap();
    core.video_state(a, 0, VideoKind::Screen, true).unwrap();
    assert_eq!(
        core.video_start(b, 0, VideoKind::Screen),
        Err(VideoError::Full)
    );

    // Stopping does release it.
    core.video_stop(a, 0, Some(VideoKind::Screen)).unwrap();
    core.video_start(b, 0, VideoKind::Screen).unwrap();
}

#[test]
fn stopping_something_that_is_not_running_is_not_an_error() {
    // Leaving, being kicked and disconnecting all end publications on
    // their own, and a client's stop routinely races one of them.
    // Punishing the loser of that race would mean every client had to
    // tell a real failure from a lost one.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);

    core.video_stop(a, 0, Some(VideoKind::Camera)).unwrap();
    core.video_stop(a, 0, None).unwrap();
    assert!(
        media.take_calls().is_empty(),
        "and it costs the media layer nothing"
    );
}

#[test]
fn stop_without_a_kind_ends_everything_in_the_room() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_start(a, 0, VideoKind::Screen).unwrap();
    media.take_calls();

    core.video_stop(a, 0, None).unwrap();
    assert!(core.video_publications(0).is_empty());
    let calls = media.take_calls();
    assert!(calls.contains(&MediaCall::Unpublish {
        uid: a,
        cid: 0,
        kind: VideoKind::Camera
    }));
    assert!(calls.contains(&MediaCall::Unpublish {
        uid: a,
        cid: 0,
        kind: VideoKind::Screen
    }));
}

// --- Pause -------------------------------------------------------------

#[test]
fn pause_and_resume_never_renegotiate() {
    // Pause is to video what mute is to audio. A room of eight that
    // renegotiated on every camera toggle would spend its life in
    // offer/answer.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_subscribe(b, 0, &[cam(a)]).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);
    media.take_calls();

    core.video_state(a, 0, VideoKind::Camera, true).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![MediaCall::SetPaused {
            uid: a,
            cid: 0,
            kind: VideoKind::Camera,
            paused: true
        }],
        "no offer, to anyone — the section, the mid and the slot all stay"
    );
    let evs_b = drain(&mut rx_b);
    assert_eq!(offer_targets(&evs_b), 0);
    assert_eq!(
        latest(&evs_b),
        vec![VideoPublication {
            uid: a,
            kind: VideoKind::Camera,
            paused: true
        }],
        "the subscriber is told to show a paused tile, not to remove it"
    );
}

#[test]
fn a_toggle_that_changes_nothing_is_acked_and_nothing_else() {
    // The cheap half of the debounce the spec asks for. A client mashing
    // a camera button produces plenty of these.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_state(a, 0, VideoKind::Camera, true).unwrap();
    drain(&mut rx_a);
    media.take_calls();

    core.video_state(a, 0, VideoKind::Camera, true).unwrap();
    assert!(media.take_calls().is_empty());
    assert!(publications(&drain(&mut rx_a)).is_empty());
}

#[test]
fn pausing_something_you_are_not_publishing_is_an_error() {
    // Unlike stop. There is no race to be generous about here: a client
    // that pauses a publication it never started has a bug.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);
    assert_eq!(
        core.video_state(a, 0, VideoKind::Camera, true),
        Err(VideoError::NotPublishing)
    );
}

// --- Subscription ------------------------------------------------------

#[test]
fn nothing_is_delivered_until_it_is_asked_for() {
    // The whole compatibility story in one assertion: A publishes, B is
    // in the room, and B's media state is never touched.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    media.take_calls();

    core.video_start(a, 0, VideoKind::Camera).unwrap();
    let calls = media.take_calls();
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, MediaCall::SetSubscriptions { uid, .. } if *uid == b)),
        "B asked for nothing, so B is told nothing"
    );
    assert_eq!(offer_targets(&drain(&mut rx_b)), 0);
}

#[test]
fn subscribing_renegotiates_only_the_subscriber_and_tells_no_one() {
    // Who is watching whom is not published — not to the publisher, not
    // to the room.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);
    media.take_calls();

    core.video_subscribe(b, 0, &[cam(a)]).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::SetSubscriptions {
                uid: b,
                cid: 0,
                streams: vec![cam(a)]
            },
            MediaCall::Offer { uid: b, cid: 0 },
        ]
    );
    let evs_a = drain(&mut rx_a);
    assert_eq!(offer_targets(&evs_a), 0, "the publisher is untouched");
    assert!(
        publications(&evs_a).is_empty(),
        "and is not told it has a viewer"
    );
    assert_eq!(offer_targets(&drain(&mut rx_b)), 1);
}

#[test]
fn the_declared_set_is_absolute_and_one_request_costs_one_offer() {
    // Four separate subscribes would cost four renegotiations serialised
    // behind one another; one subscribe naming four streams costs one.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    let (c, mut rx_c) = quiet(&core, "carol");
    joined(
        &core,
        &media,
        &mut [(a, &mut rx_a), (b, &mut rx_b), (c, &mut rx_c)],
    );
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_start(a, 0, VideoKind::Screen).unwrap();
    core.video_start(b, 0, VideoKind::Camera).unwrap();
    drain(&mut rx_c);
    media.take_calls();

    core.video_subscribe(c, 0, &[cam(a), screen(a), cam(b)])
        .unwrap();
    assert_eq!(
        media
            .take_calls()
            .iter()
            .filter(|call| matches!(call, MediaCall::Offer { .. }))
            .count(),
        1,
        "three streams, one renegotiation"
    );

    // Re-declaring the same set is idempotent and costs nothing, which
    // matters on a protocol where a client may have to re-establish
    // state.
    answer_offers(&core, c, &mut rx_c);
    media.take_calls();
    core.video_subscribe(c, 0, &[cam(a), screen(a), cam(b)])
        .unwrap();
    assert!(media.take_calls().is_empty());

    // And an empty set turns it all off in one request.
    core.video_subscribe(c, 0, &[]).unwrap();
    assert_eq!(
        media.take_calls(),
        vec![
            MediaCall::SetSubscriptions {
                uid: c,
                cid: 0,
                streams: vec![]
            },
            MediaCall::Offer { uid: c, cid: 0 },
        ]
    );
}

#[test]
fn a_subscription_to_a_stream_that_does_not_exist_is_retained_and_activates() {
    // "Show me everyone" said once, without racing the room's state and
    // without polling.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    media.take_calls();

    // A is publishing nothing yet. Not an error, and nothing happens.
    core.video_subscribe(b, 0, &[cam(a)]).unwrap();
    assert!(
        media.take_calls().is_empty(),
        "nothing to activate, so no offer and no media call"
    );
    drain(&mut rx_b);

    // Now it appears — and B lights up without asking again.
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    let calls = media.take_calls();
    assert!(calls.contains(&MediaCall::SetSubscriptions {
        uid: b,
        cid: 0,
        streams: vec![cam(a)]
    }));
    assert!(calls.contains(&MediaCall::Offer { uid: b, cid: 0 }));
    assert_eq!(offer_targets(&drain(&mut rx_b)), 1);
}

#[test]
fn a_peer_never_subscribes_to_its_own_publication() {
    // There is no loopback section for it; a client renders its camera
    // from the local capture, which costs nothing and has no round trip.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    media.take_calls();

    core.video_subscribe(a, 0, &[cam(a)]).unwrap();
    assert!(media.take_calls().is_empty());
}

#[test]
fn a_publisher_stopping_looks_to_a_subscriber_like_unsubscribing() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_subscribe(b, 0, &[cam(a)]).unwrap();
    answer_offers(&core, b, &mut rx_b);
    media.take_calls();

    core.video_stop(a, 0, Some(VideoKind::Camera)).unwrap();
    let calls = media.take_calls();
    assert!(calls.contains(&MediaCall::SetSubscriptions {
        uid: b,
        cid: 0,
        streams: vec![]
    }));
    assert!(calls.contains(&MediaCall::Offer { uid: b, cid: 0 }));
    // The standing subscription survives, so a restart lights B back up
    // without B asking again.
    answer_offers(&core, b, &mut rx_b);
    media.take_calls();
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    assert!(media.take_calls().contains(&MediaCall::SetSubscriptions {
        uid: b,
        cid: 0,
        streams: vec![cam(a)]
    }));
}

#[test]
fn a_video_change_defers_behind_an_unanswered_offer_and_consolidates() {
    // The voice extension's serialisation rule, which video makes matter
    // much more: it multiplies the events that mutate a peer's offer, so
    // a burst of changes during one outstanding offer must produce
    // exactly one follow-up rather than a queue of them.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    let (c, mut rx_c) = quiet(&core, "carol");
    joined(
        &core,
        &media,
        &mut [(a, &mut rx_a), (b, &mut rx_b), (c, &mut rx_c)],
    );
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_start(b, 0, VideoKind::Camera).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);

    // C subscribes and is sent an offer it does not answer.
    core.video_subscribe(c, 0, &[cam(a)]).unwrap();
    let evs = drain(&mut rx_c);
    assert_eq!(offer_targets(&evs), 1);
    let outstanding = match evs
        .iter()
        .rev()
        .find(|e| matches!(e, Event::VoiceOffer { .. }))
    {
        Some(Event::VoiceOffer { cid, sdp }) => (*cid, sdp.clone()),
        _ => unreachable!("just asserted there is one"),
    };
    media.take_calls();

    // Three more changes land while it is outstanding. None of them may
    // put a second offer on the wire.
    core.video_subscribe(c, 0, &[cam(a), cam(b)]).unwrap();
    core.video_start(a, 0, VideoKind::Screen).unwrap();
    core.video_subscribe(c, 0, &[cam(b), screen(a)]).unwrap();
    assert_eq!(
        offer_targets(&drain(&mut rx_c)),
        0,
        "an overlapping offer is undefined behaviour in most stacks"
    );

    // The answer releases exactly one, describing the state as it now
    // stands rather than replaying the three changes.
    core.voice_answer(c, outstanding.0, format!("answer to {}", outstanding.1))
        .unwrap();
    assert_eq!(offer_targets(&drain(&mut rx_c)), 1);
}

// --- Cleanup -----------------------------------------------------------

#[test]
fn leaving_voice_ends_every_publication_and_resyncs_the_watchers() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_start(a, 0, VideoKind::Screen).unwrap();
    core.video_subscribe(b, 0, &[cam(a), screen(a)]).unwrap();
    drain(&mut rx_a);
    drain(&mut rx_b);
    media.take_calls();

    core.voice_leave(a, 0).unwrap();
    assert!(core.video_publications(0).is_empty());
    assert!(
        media.take_calls().contains(&MediaCall::SetSubscriptions {
            uid: b,
            cid: 0,
            streams: vec![]
        }),
        "B stops receiving before the offer describing that is built"
    );
    assert_eq!(latest(&drain(&mut rx_b)), vec![]);
    // The leaver hears it too — an implicit leave has no reply to carry
    // an ack, and its own video UI has to come down.
    assert_eq!(latest(&drain(&mut rx_a)), vec![]);
}

#[test]
fn an_implicit_leave_does_not_carry_a_screen_share_into_the_new_room() {
    // Consent is to a room, not to a server.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, _rx_b) = quiet(&core, "bob");
    in_voice(&core, &media, a, &mut rx_a);
    core.video_start(a, 0, VideoKind::Screen).unwrap();

    let (cid, _) = core.chat_create(a, b).unwrap();
    core.chat_join(cid, b, "").unwrap();
    core.voice_join(a, cid).unwrap();
    assert!(core.video_publications(0).is_empty());
    assert!(
        core.video_publications(cid).is_empty(),
        "a user who wants to share in room B says so in room B"
    );
}

#[test]
fn a_failed_publication_costs_the_publication_and_not_the_call() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    core.video_start(a, 0, VideoKind::Screen).unwrap();
    core.video_subscribe(b, 0, &[cam(a)]).unwrap();
    drain(&mut rx_b);
    media.take_calls();

    core.voice_media_event(crate::voice::MediaEvent::VideoFailed {
        uid: a,
        cid: 0,
        kind: VideoKind::Camera,
    });

    assert_eq!(
        core.voice_room_of(a),
        Some(0),
        "losing video is a degradation; losing the call is a failure"
    );
    assert_eq!(
        core.video_publications(0),
        vec![VideoPublication {
            uid: a,
            kind: VideoKind::Screen,
            paused: false
        }],
        "and it costs only the publication that failed"
    );
    assert!(media.take_calls().contains(&MediaCall::SetSubscriptions {
        uid: b,
        cid: 0,
        streams: vec![]
    }));
}

// --- Preconditions -----------------------------------------------------

#[test]
fn video_needs_a_voice_session_under_it() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");

    // In the room, but not in voice in it.
    assert_eq!(
        core.video_start(a, 0, VideoKind::Camera),
        Err(VideoError::NotInVoice)
    );
    assert_eq!(
        core.video_subscribe(a, 0, &[cam(a)]),
        Err(VideoError::NotInVoice)
    );

    // In voice in room 0, asking about another room.
    in_voice(&core, &media, a, &mut rx_a);
    let (b, _rx_b) = quiet(&core, "bob");
    let (cid, _) = core.chat_create(a, b).unwrap();
    assert_eq!(
        core.video_start(a, cid, VideoKind::Camera),
        Err(VideoError::NotInVoice)
    );
}

#[test]
fn a_server_without_video_refuses_every_video_operation() {
    // Voice on, video off: the whole extension answers `Disabled`, which
    // is what a client that ignored the capability echo deserves.
    let media = Arc::new(RecordingMedia::new());
    let core = Core::new().with_voice(media.clone(), DEFAULT_MAX_PER_ROOM);
    let (a, mut rx_a) = quiet(&core, "alice");
    in_voice(&core, &media, a, &mut rx_a);

    assert!(!core.video_enabled());
    assert_eq!(
        core.video_start(a, 0, VideoKind::Camera),
        Err(VideoError::Disabled)
    );
    assert_eq!(core.video_stop(a, 0, None), Err(VideoError::Disabled));
    assert_eq!(
        core.video_state(a, 0, VideoKind::Camera, true),
        Err(VideoError::Disabled)
    );
    assert_eq!(core.video_subscribe(a, 0, &[]), Err(VideoError::Disabled));
    // And no status is emitted into a room that can't have publications.
    assert!(publications(&drain(&mut rx_a)).is_empty());
}

#[test]
fn video_cannot_be_enabled_without_a_media_layer() {
    // The capability bit's dependency, made structural: video has no
    // meaning without the voice room that carries it.
    let core = Core::new().with_video(VideoConfig::default());
    assert!(!core.video_enabled());
}

#[test]
fn the_room_is_told_about_video_whether_or_not_it_can_render_it() {
    // A voice-only participant is entitled to know a camera is on in the
    // room it is sitting in. Whether its wire can say so is the
    // frontend's business; the domain sends to everyone.
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    joined(&core, &media, &mut [(a, &mut rx_a), (b, &mut rx_b)]);
    drain(&mut rx_b);

    core.video_start(a, 0, VideoKind::Camera).unwrap();
    assert_eq!(
        latest(&drain(&mut rx_b)).len(),
        1,
        "B is told, and B never sent a video transaction in its life"
    );
}

#[test]
fn a_joiner_learns_the_rooms_video_state_without_asking() {
    let (core, media) = videoed();
    let (a, mut rx_a) = quiet(&core, "alice");
    let (b, mut rx_b) = quiet(&core, "bob");
    in_voice(&core, &media, a, &mut rx_a);
    core.video_start(a, 0, VideoKind::Camera).unwrap();
    drain(&mut rx_b);

    core.voice_join(b, 0).unwrap();
    assert_eq!(
        latest(&drain(&mut rx_b)),
        vec![VideoPublication {
            uid: a,
            kind: VideoKind::Camera,
            paused: false
        }],
        "as a notification after the join reply, so voice's reply shape \
         is untouched"
    );
}

// --- Wire vocabulary ---------------------------------------------------

#[test]
fn kind_zero_is_invalid_so_a_zeroed_field_is_caught() {
    assert_eq!(VideoKind::from_wire(0), None);
    assert_eq!(VideoKind::from_wire(1), Some(VideoKind::Camera));
    assert_eq!(VideoKind::from_wire(2), Some(VideoKind::Screen));
    // Kind 3 is reserved for screen audio; a later revision's client
    // asking for it must not be answered with a camera.
    assert_eq!(VideoKind::from_wire(3), None);
    assert_eq!(VideoKind::from_wire(65535), None);

    // The two wires spell the same thing differently and must agree.
    for k in VideoKind::ALL {
        assert_eq!(VideoKind::from_wire(k.wire()), Some(k));
        assert_eq!(VideoKind::from_name(k.name()), Some(k));
    }
    assert_eq!(VideoKind::from_name("Camera"), None);
}

#[test]
fn the_default_ceilings_are_the_specs() {
    let c = VideoConfig::default();
    assert_eq!(c.camera.max_width, 1280);
    assert_eq!(c.camera.max_fps, 30);
    assert_eq!(c.camera.max_per_room, 8);
    // The screen default is deliberately higher in resolution and lower
    // in frame rate: a shared desktop is mostly still and wants detail.
    assert_eq!(c.screen.max_width, 1920);
    assert_eq!(c.screen.max_fps, 15);
    assert_eq!(c.screen.max_per_room, 1);
    // b=AS counts kilobits.
    assert_eq!(c.camera.bandwidth_kbps(), 1500);
    assert_eq!(c.screen.bandwidth_kbps(), 2500);
}
