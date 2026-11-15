//! A person in voice: one device at a time, under its row, and a second
//! device joining moving the person there rather than adding it twice.

use std::sync::Arc;

use super::tests::{session, ALICE};
use crate::roster::{drain, Core, Event, Events, Transport, Uid};
use crate::video::{VideoConfig, VideoKind, VideoPublication, VideoStream};
use crate::voice::fake::{MediaCall, RecordingMedia};
use crate::voice::{VoiceError, VoiceParticipant, DEFAULT_MAX_PER_ROOM};

fn voiced(coalesce: bool) -> (Core, Arc<RecordingMedia>) {
    let media = Arc::new(RecordingMedia::new());
    let core = Core::new()
        .with_voice(media.clone(), DEFAULT_MAX_PER_ROOM)
        .with_video(VideoConfig::default())
        .with_coalesce(coalesce);
    (core, media)
}

fn device(core: &Core) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(session(
            "alice",
            Some(ALICE),
            Some(ALICE),
            Transport::default(),
        ))
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

fn bob(core: &Core) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(session("bob", None, None, Transport::default()))
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

/// Join the lobby's voice and answer every offer outstanding, so what a
/// test asserts is the act it makes and not a deferred follow-up.
fn in_voice(core: &Core, media: &RecordingMedia, uid: Uid) -> Vec<VoiceParticipant> {
    let join = core.voice_join(uid, 0).unwrap();
    core.voice_answer(uid, 0, format!("answer to {}", join.sdp))
        .unwrap();
    media.take_calls();
    join.participants
}

/// Answer the offer `rx` holds, if any.
fn answer(core: &Core, uid: Uid, rx: &mut Events) {
    for e in drain(rx) {
        if let Event::VoiceOffer { cid, sdp } = e {
            core.voice_answer(uid, cid, format!("answer to {sdp}"))
                .unwrap();
        }
    }
}

fn statuses(evs: &[Event]) -> Vec<Vec<(Uid, bool, bool)>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::VoiceStatus { participants, .. } => Some(
                participants
                    .iter()
                    .map(|p| (p.uid, p.muted, p.camera))
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

fn video(evs: &[Event]) -> Vec<Vec<VideoPublication>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::VideoStatus { publications, .. } => Some(publications.clone()),
            _ => None,
        })
        .collect()
}

fn offered(evs: &[Event]) -> usize {
    evs.iter()
        .filter(|e| matches!(e, Event::VoiceOffer { .. }))
        .count()
}

#[test]
fn a_person_is_in_voice_under_its_row_whichever_device_joined() {
    let (core, media) = voiced(true);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let (b, mut rx_b) = bob(&core);
    in_voice(&core, &media, b);
    drain(&mut rx_b);

    let join = core.voice_join(a2, 0).unwrap();
    assert_eq!(
        media.take_calls()[..2],
        [
            MediaCall::Join { uid: a1, cid: 0 },
            MediaCall::Offer { uid: a1, cid: 0 },
        ],
        "the media layer knows the person by its row, as every mid names it"
    );
    assert_eq!(
        join.participants.iter().map(|p| p.uid).collect::<Vec<_>>(),
        [b]
    );
    assert_eq!(
        statuses(&drain(&mut rx_b)),
        [vec![(b, false, false), (a1, false, false)]]
    );
    assert_eq!(core.voice_room_of(a2), Some(0));
    assert_eq!(core.voice_room_of(a1), None);
}

#[test]
fn a_second_device_joining_moves_its_person_and_nobody_sees_it_go_or_come() {
    let (core, media) = voiced(true);
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (b, mut rx_b) = bob(&core);
    in_voice(&core, &media, a1);
    in_voice(&core, &media, b);
    answer(&core, a1, &mut rx1);
    drain(&mut rx1);
    drain(&mut rx2);
    drain(&mut rx_b);
    media.take_calls();

    let join = core.voice_join(a2, 0).unwrap();
    assert_eq!(
        join.participants.iter().map(|p| p.uid).collect::<Vec<_>>(),
        [b],
        "the room as the joiner found it, its person gone from it"
    );
    assert_eq!(
        media.take_calls(),
        [
            MediaCall::Leave { uid: a1, cid: 0 },
            MediaCall::Join { uid: a1, cid: 0 },
            MediaCall::Offer { uid: a1, cid: 0 },
            MediaCall::Offer { uid: b, cid: 0 },
        ],
        "the row's session is made again, as a rejoin, and bob renegotiated"
    );
    assert_eq!(core.voice_room_of(a1), None);
    assert_eq!(core.voice_room_of(a2), Some(0));

    // The leaver is told it is out: the room with its row absent.
    let left = drain(&mut rx1);
    assert_eq!(statuses(&left), [vec![(b, false, false)]]);
    assert_eq!(video(&left), [vec![]]);
    assert_eq!(offered(&left), 0);
    // The joiner learns the room with its row in it.
    let came = drain(&mut rx2);
    assert_eq!(
        statuses(&came),
        [vec![(a1, false, false), (b, false, false)]]
    );
    // Bob: a renegotiation, and no part, no join and no status.
    let watched = drain(&mut rx_b);
    assert_eq!(offered(&watched), 1);
    assert_eq!(statuses(&watched), Vec::<Vec<_>>::new());
    assert_eq!(video(&watched), Vec::<Vec<_>>::new());
}

#[test]
fn a_moved_person_keeps_its_mute() {
    for muted in [false, true] {
        let (core, media) = voiced(true);
        let (a1, _rx1) = device(&core);
        let (a2, mut rx2) = device(&core);
        in_voice(&core, &media, a1);
        core.voice_mute(a1, 0, muted).unwrap();
        media.take_calls();
        drain(&mut rx2);

        core.voice_join(a2, 0).unwrap();
        let calls = media.take_calls();
        assert_eq!(
            calls.contains(&MediaCall::SetMuted {
                uid: a1,
                cid: 0,
                muted: true
            }),
            muted,
            "{muted}: {calls:?}"
        );
        assert_eq!(
            statuses(&drain(&mut rx2)),
            [vec![(a1, muted, false)]],
            "{muted}"
        );
    }
}

#[test]
fn a_moved_persons_publications_end_and_so_do_the_subscriptions_to_them() {
    let (core, media) = voiced(true);
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (b, mut rx_b) = bob(&core);
    in_voice(&core, &media, a1);
    in_voice(&core, &media, b);
    answer(&core, a1, &mut rx1);
    core.video_start(a1, 0, VideoKind::Camera).unwrap();
    core.video_start(b, 0, VideoKind::Camera).unwrap();
    answer(&core, a1, &mut rx1);
    answer(&core, b, &mut rx_b);
    let camera = |uid| VideoStream {
        uid,
        kind: VideoKind::Camera,
    };
    core.video_subscribe(b, 0, &[camera(a1)]).unwrap();
    core.video_subscribe(a1, 0, &[camera(b)]).unwrap();
    answer(&core, a1, &mut rx1);
    answer(&core, b, &mut rx_b);
    drain(&mut rx1);
    drain(&mut rx2);
    drain(&mut rx_b);
    media.take_calls();

    core.voice_join(a2, 0).unwrap();
    let calls = media.take_calls();
    assert!(
        calls.contains(&MediaCall::SetSubscriptions {
            uid: b,
            cid: 0,
            streams: vec![]
        }),
        "bob's subscription to the camera went with it: {calls:?}"
    );
    assert!(
        !calls.iter().any(
            |c| matches!(c, MediaCall::SetSubscriptions { uid, streams, .. }
                if *uid == a1 && !streams.is_empty())
        ),
        "the joiner inherits no subscription of the leaver's: {calls:?}"
    );
    let bobs_camera = VideoPublication {
        uid: b,
        kind: VideoKind::Camera,
        paused: false,
    };
    let watched = drain(&mut rx_b);
    assert_eq!(
        statuses(&watched),
        [vec![(a1, false, false), (b, false, true)]],
        "the room is told the camera went, as a status and not a part"
    );
    assert_eq!(video(&watched), [vec![bobs_camera]]);
    assert_eq!(video(&drain(&mut rx1)), [vec![]]);

    // Bob's standing subscription lights up again when the person's new
    // device starts a camera of its own.
    answer(&core, a2, &mut rx2);
    answer(&core, b, &mut rx_b);
    media.take_calls();
    core.video_start(a2, 0, VideoKind::Camera).unwrap();
    assert!(media.take_calls().contains(&MediaCall::SetSubscriptions {
        uid: b,
        cid: 0,
        streams: vec![camera(a1)]
    }));
}

#[test]
fn a_move_whose_join_fails_takes_the_person_out_of_voice_and_says_so() {
    let (core, media) = voiced(true);
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (b, mut rx_b) = bob(&core);
    in_voice(&core, &media, a1);
    in_voice(&core, &media, b);
    answer(&core, a1, &mut rx1);
    drain(&mut rx1);
    drain(&mut rx2);
    drain(&mut rx_b);

    media.no_next_offer();
    assert_eq!(core.voice_join(a2, 0).unwrap_err(), VoiceError::RoomFull);
    assert_eq!(
        (core.voice_room_of(a1), core.voice_room_of(a2)),
        (None, None)
    );
    assert_eq!(
        core.voice_participants(0)
            .iter()
            .map(|p| p.uid)
            .collect::<Vec<_>>(),
        [b]
    );
    assert_eq!(statuses(&drain(&mut rx1)), [vec![(b, false, false)]]);
    assert_eq!(statuses(&drain(&mut rx_b)), [vec![(b, false, false)]]);
    assert_eq!(statuses(&drain(&mut rx2)), Vec::<Vec<_>>::new());
}

#[test]
fn a_device_not_in_voice_asks_nothing_of_its_persons_voice() {
    let (core, media) = voiced(true);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    in_voice(&core, &media, a1);
    assert_eq!(core.voice_leave(a2, 0), Err(VoiceError::NotInVoice));
    assert_eq!(core.voice_mute(a2, 0, true), Err(VoiceError::NotInVoice));
    assert_eq!(core.voice_room_of(a1), Some(0));
    assert_eq!(media.take_calls(), []);
}

#[test]
fn the_device_in_voice_ending_takes_its_person_out_of_voice() {
    let (core, media) = voiced(true);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let (b, mut rx_b) = bob(&core);
    in_voice(&core, &media, b);
    in_voice(&core, &media, a2);
    drain(&mut rx_b);

    core.end_session(a2);
    assert_eq!(statuses(&drain(&mut rx_b)), [vec![(b, false, false)]]);
    assert_eq!(media.take_calls()[0], MediaCall::Leave { uid: a1, cid: 0 });
}

#[test]
fn a_second_device_joining_voice_elsewhere_moves_its_person_out_of_the_first() {
    let (core, media) = voiced(true);
    let (a1, mut rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let (b, mut rx_b) = bob(&core);
    in_voice(&core, &media, b);
    in_voice(&core, &media, a1);
    core.voice_mute(a1, 0, true).unwrap();
    let (cid, _) = core.chat_create(b, a1).unwrap();
    core.chat_join(cid, a1, "").unwrap();
    core.chat_join(cid, a2, "").unwrap();
    drain(&mut rx1);
    drain(&mut rx_b);

    core.voice_join(a2, cid).unwrap();
    assert_eq!(core.voice_room_of(a1), None);
    assert_eq!(core.voice_room_of(a2), Some(cid));
    assert_eq!(
        statuses(&drain(&mut rx_b)),
        [vec![(b, false, false)]],
        "the lobby sees the person leave its voice"
    );
    assert_eq!(statuses(&drain(&mut rx1)), [vec![(b, false, false)]]);
    assert_eq!(
        core.voice_participants(cid),
        [VoiceParticipant {
            uid: a1,
            ..Default::default()
        }],
        "a move to another room is a room switch: it lands unmuted"
    );
}

#[test]
fn with_coalescing_off_each_session_is_in_voice_on_its_own() {
    let (core, media) = voiced(false);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    in_voice(&core, &media, a1);
    in_voice(&core, &media, a2);
    assert_eq!(
        core.voice_participants(0)
            .iter()
            .map(|p| p.uid)
            .collect::<Vec<_>>(),
        [a1, a2]
    );
    assert_eq!(
        (core.voice_room_of(a1), core.voice_room_of(a2)),
        (Some(0), Some(0))
    );
}

#[test]
fn a_device_not_yet_announced_may_not_join_voice() {
    let (core, media) = voiced(true);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = core
        .attach(session(
            "alice",
            Some(ALICE),
            Some(ALICE),
            Transport::default(),
        ))
        .unwrap();
    // A classic client at the agreement has a session, and no row yet:
    // one made now would be its own uid, not the person's.
    assert_eq!(core.voice_join(a2, 0).unwrap_err(), VoiceError::NotAMember);
    core.announce(a2);
    in_voice(&core, &media, a2);
    assert_eq!(core.voice_participants(0)[0].uid, a1);
}

#[test]
fn the_media_layers_word_about_a_person_reaches_the_device_in_voice_and_only_its_session() {
    use crate::voice::MediaEvent;
    type Case = fn(Uid, u64) -> MediaEvent;
    let cases: [(&str, Case); 3] = [
        ("failed", |uid, session| MediaEvent::Failed {
            uid,
            cid: 0,
            session,
        }),
        ("ice", |uid, session| MediaEvent::Ice {
            uid,
            cid: 0,
            session,
            candidate: crate::voice::IceCandidate::end_of_candidates("send"),
        }),
        ("camera", |uid, session| MediaEvent::VideoFailed {
            uid,
            cid: 0,
            session,
            kind: VideoKind::Camera,
        }),
    ];
    for (what, event) in cases {
        for current in [false, true] {
            let (core, media) = voiced(true);
            let (a1, mut rx1) = device(&core);
            let (a2, mut rx2) = device(&core);
            in_voice(&core, &media, a1);
            let stale = media.session(a1);
            in_voice(&core, &media, a2);
            answer(&core, a2, &mut rx2);
            core.video_start(a2, 0, VideoKind::Camera).unwrap();
            drain(&mut rx1);
            drain(&mut rx2);
            let session = if current { media.session(a1) } else { stale };

            core.voice_media_event(event(a1, session));
            let heard = drain(&mut rx2);
            let told = match what {
                "failed" => core.voice_room_of(a2).is_none(),
                "ice" => heard.iter().any(|e| matches!(e, Event::VoiceIce { .. })),
                _ => core.video_publications(0).is_empty(),
            };
            assert_eq!(told, current, "{what}, current {current}");
            assert!(
                drain(&mut rx1).is_empty(),
                "{what}: the old device hears nothing"
            );
        }
    }
}
