//! A person's rooms and private chats: one member for all its devices, a
//! window each device opens for itself, and one device leaving taking the
//! person out.

use std::sync::Arc;

use super::tests::{session, ALICE};
use crate::history::{HistoryPolicy, LineId, MemoryLog};
use crate::rooms::{MemoryRooms, RoomEdit, RoomPolicy};
use crate::roster::{drain, Core, Event, Events, Transport, Uid};
use crate::{ChatError, RoomError};

fn transport() -> Transport {
    Transport {
        inline_media: true,
        redactions: true,
        reactions: true,
        ..Transport::default()
    }
}

fn core(coalesce: bool) -> Core {
    rooms_core(coalesce, RoomPolicy::default())
}

fn rooms_core(coalesce: bool, policy: RoomPolicy) -> Core {
    let core = Core::new()
        .with_history(Arc::new(MemoryLog::default()), HistoryPolicy::default())
        .with_reactions(crate::ReactionPolicy::default())
        .with_rooms(Arc::new(MemoryRooms::default()), policy)
        .unwrap()
        .with_system(crate::SystemPolicy::default())
        .with_coalesce(coalesce);
    core.start_system_session().unwrap();
    core
}

/// The server's invitation to a person's own device, by the system
/// account.
fn from_server(core: &Core) -> String {
    format!("invite {}", core.system_uid().unwrap())
}

fn device(core: &Core) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(session("alice", Some(ALICE), Some(ALICE), transport()))
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

fn bob(core: &Core) -> (Uid, Events) {
    let mut info = session("bob", None, None, transport());
    info.manage_rooms = true;
    let (uid, rx) = core.attach(info).unwrap();
    core.announce(uid);
    (uid, rx)
}

fn room(core: &Core, by: Uid, name: &str) -> u32 {
    let edit = RoomEdit {
        name: Some(name.into()),
        ..RoomEdit::default()
    };
    core.room_create(by, edit).unwrap().id
}

fn say(core: &Core, uid: Uid, room: u32, text: &str) -> Result<Option<LineId>, ChatError> {
    core.chat_public_all(uid, room, vec![(text.into(), 0, None, None, vec![])])
        .pop()
        .unwrap()
}

/// What a session was told of chat or room `cid`: invitations, joins and
/// parts by the uid they name, and lines by their text.
fn heard(rx: &mut Events, cid: u32) -> Vec<String> {
    drain(rx)
        .into_iter()
        .filter_map(|e| match e {
            Event::InRoom { room, event } if room == cid => Some(*event),
            Event::InRoom { .. } => None,
            e => Some(e),
        })
        .filter_map(|e| match e {
            Event::ChatInvite { cid: c, from, .. } if c == cid => Some(format!("invite {from}")),
            Event::ChatUserJoined { cid: c, user } if c == cid => {
                Some(format!("join {}", user.uid))
            }
            Event::ChatUserParted { cid: c, uid } if c == cid => Some(format!("part {uid}")),
            Event::RoomParted { uid, .. } => Some(format!("parted {uid}")),
            Event::Chat {
                cid: c, text, from, ..
            } if c == cid => Some(format!("{}: {text}", from.uid)),
            Event::ReactionsChanged(_) => Some("reactions".into()),
            _ => None,
        })
        .collect()
}

fn uids(rows: &[crate::UserInfo]) -> Vec<Uid> {
    rows.iter().map(|u| u.uid).collect()
}

#[test]
fn a_persons_devices_are_one_member_of_a_private_chat_and_each_hears_it_once_joined() {
    let core = core(true);
    let (b, mut to_bob) = bob(&core);
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (cid, _) = core.chat_create(b, a1).unwrap();
    let invite = format!("invite {b}");
    assert_eq!(heard(&mut rx1, cid), vec![invite.clone()]);
    assert_eq!(heard(&mut rx2, cid), [invite], "both devices invited");

    let (rows, _) = core.chat_join(cid, a1, "").unwrap();
    assert_eq!(uids(&rows), [b, a1], "the person listed once");
    assert_eq!(heard(&mut to_bob, cid), [format!("join {a1}")]);
    core.chat_private(cid, b, "before".into(), 0, None, None, &[])
        .unwrap();
    drain(&mut to_bob);
    assert_eq!(heard(&mut rx1, cid), [format!("{b}: before")]);
    assert_eq!(heard(&mut rx2, cid), Vec::<String>::new(), "not joined");
    assert_eq!(
        core.chat_private(cid, a2, "x".into(), 0, None, None, &[]),
        Err(ChatError::NotAMember),
        "nor may it speak there"
    );

    let (rows, _) = core.chat_join(cid, a2, "").unwrap();
    assert_eq!(uids(&rows), [b, a1], "still listed once");
    assert_eq!(
        heard(&mut to_bob, cid),
        Vec::<String>::new(),
        "no second join"
    );
    assert_eq!(
        core.chat_join(cid, a2, "").map(|_| ()),
        Err(ChatError::AlreadyThere)
    );
    core.chat_private(cid, a2, "from the phone".into(), 0, None, None, &[])
        .unwrap();
    let line = format!("{a1}: from the phone");
    assert_eq!(heard(&mut to_bob, cid), vec![line.clone()], "as the row");
    assert_eq!(heard(&mut rx1, cid), vec![line.clone()]);
    assert_eq!(heard(&mut rx2, cid), [line]);
}

#[test]
fn a_chat_one_device_makes_or_joins_by_password_invites_its_persons_others() {
    let core = core(true);
    let (b, mut to_bob) = bob(&core);
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (cid, me) = core.chat_create(a2, b).unwrap();
    assert_eq!(me.uid, a1, "the creator's reply names its row");
    assert_eq!(heard(&mut to_bob, cid), [format!("invite {a1}")]);
    assert_eq!(heard(&mut rx1, cid), [from_server(&core)]);
    assert_eq!(heard(&mut rx2, cid), Vec::<String>::new());

    let (theirs, _) = core.chat_create(b, b).unwrap();
    core.chat_password(theirs, b, "pw".into()).unwrap();
    core.chat_join(theirs, a1, "pw").unwrap();
    assert_eq!(heard(&mut rx2, theirs), [from_server(&core)]);
    assert_eq!(heard(&mut rx1, theirs), Vec::<String>::new());
    core.chat_join(theirs, a2, "").unwrap();
}

#[test]
fn a_decline_closes_one_devices_invitation_and_the_last_closes_the_persons() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let (cid, _) = core.chat_create(b, a1).unwrap();
    core.chat_password(cid, b, "pw".into()).unwrap();
    core.chat_decline(cid, a1);
    assert_eq!(
        core.chat_join(cid, a1, "").map(|_| ()),
        Err(ChatError::WrongPassword),
        "its own declined"
    );
    core.chat_decline(cid, a2);
    assert_eq!(
        core.chat_join(cid, a2, "").map(|_| ()),
        Err(ChatError::WrongPassword),
        "and with both, the person's"
    );

    let (cid, _) = core.chat_create(b, a1).unwrap();
    core.chat_password(cid, b, "pw".into()).unwrap();
    core.chat_decline(cid, a1);
    assert!(
        core.chat_join(cid, a2, "").is_ok(),
        "the other still invited"
    );
}

#[test]
fn a_device_leaving_a_private_chat_takes_its_person_out() {
    for leaver in [0, 1] {
        let core = core(true);
        let (b, mut to_bob) = bob(&core);
        let (a1, rx1) = device(&core);
        let (a2, rx2) = device(&core);
        let (cid, _) = core.chat_create(b, a1).unwrap();
        core.chat_join(cid, a1, "").unwrap();
        core.chat_join(cid, a2, "").unwrap();
        let mut rxs = [rx1, rx2];
        for rx in &mut rxs {
            drain(rx);
        }
        drain(&mut to_bob);
        core.chat_part(cid, [a1, a2][leaver]);
        let part = format!("part {a1}");
        assert_eq!(heard(&mut to_bob, cid), vec![part.clone()], "{leaver}");
        assert_eq!(heard(&mut rxs[1 - leaver], cid), [part], "{leaver}");
        assert_eq!(heard(&mut rxs[leaver], cid), Vec::<String>::new());
        assert!(core.chats_of(a1).is_empty() && core.chats_of(a2).is_empty());
        core.chat_private(cid, b, "gone?".into(), 0, None, None, &[])
            .unwrap();
        assert!(rxs.iter_mut().all(|rx| heard(rx, cid).is_empty()));
    }
}

#[test]
fn a_device_hears_its_persons_room_once_it_joins_it_itself() {
    let core = core(true);
    let (b, mut to_bob) = bob(&core);
    let lounge = room(&core, b, "lounge");
    core.room_join(b, lounge).unwrap();
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (members, _) = core.room_join(a1, lounge).unwrap();
    assert_eq!(uids(&members), [b, a1]);
    assert_eq!(heard(&mut to_bob, lounge), [format!("join {a1}")]);
    say(&core, b, lounge, "before").unwrap();
    drain(&mut to_bob);
    assert_eq!(heard(&mut rx1, lounge), [format!("{b}: before")]);
    assert_eq!(heard(&mut rx2, lounge), Vec::<String>::new());
    assert_eq!(
        (core.rooms_of(a1), core.rooms_of(a2)),
        (vec![lounge], vec![])
    );
    assert_eq!(say(&core, a2, lounge, "x"), Err(ChatError::NotAMember));

    let (members, _) = core.room_join(a2, lounge).unwrap();
    assert_eq!(uids(&members), [b, a1], "listed once");
    assert_eq!(heard(&mut to_bob, lounge), Vec::<String>::new(), "no join");
    assert_eq!(core.rooms_of(a2), [lounge]);
    say(&core, a2, lounge, "from the phone").unwrap();
    let line = format!("{a1}: from the phone");
    assert_eq!(heard(&mut to_bob, lounge), vec![line.clone()], "as the row");
    assert_eq!(heard(&mut rx1, lounge), vec![line.clone()]);
    assert_eq!(heard(&mut rx2, lounge), [line]);
}

#[test]
fn a_device_reacts_and_hears_reactions_to_lines_said_once_it_joined() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let lounge = room(&core, b, "lounge");
    core.room_join(b, lounge).unwrap();
    let (a1, _rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    core.room_join(a1, lounge).unwrap();
    let before = say(&core, b, lounge, "before").unwrap().unwrap();
    core.react(b, lounge, before, &thumbs(), true).unwrap();
    flush(&core);
    assert_eq!(heard(&mut rx2, lounge), Vec::<String>::new());
    assert_eq!(
        core.react(a2, lounge, before, &thumbs(), true),
        Err(crate::ReactError::NoSuchTarget)
    );
    core.room_join(a2, lounge).unwrap();
    let after = say(&core, b, lounge, "after").unwrap().unwrap();
    drain(&mut rx2);
    core.react(b, lounge, after, &thumbs(), true).unwrap();
    flush(&core);
    assert_eq!(heard(&mut rx2, lounge), ["reactions"]);
    assert!(core.react(a2, lounge, after, &thumbs(), true).is_ok());
}

/// Tell what reactions are owed, a batch's window on.
fn flush(core: &Core) {
    let now = core.clock.now();
    if let Some(due) = core.reactions_flush(now) {
        // The clock moves in whole milliseconds.
        core.clock
            .advance(due - now + std::time::Duration::from_millis(1));
        core.reactions_flush(core.clock.now());
    }
}

fn thumbs() -> crate::ReactionKey {
    crate::ReactionKey::emoji("\u{1F44D}").unwrap()
}

#[test]
fn a_device_that_has_not_joined_its_persons_room_is_shown_none_of_its_images() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let lounge = room(&core, b, "lounge");
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    core.room_join(a1, lounge).unwrap();
    let audience = |core: &Core| -> Vec<Uid> {
        let r = core.roster.lock().unwrap();
        let members = r.rooms[&lounge].members.clone();
        r.media_audience_of(lounge, &members)
            .into_iter()
            .map(|p| match p {
                crate::media::Principal::Session { uid, .. } => uid,
                p => panic!("{p:?}"),
            })
            .collect()
    };
    assert_eq!(audience(&core), [a1]);
    core.room_join(a2, lounge).unwrap();
    let mut both = audience(&core);
    both.sort_unstable();
    assert_eq!(both, [a1, a2]);
}

#[test]
fn a_device_leaving_a_room_takes_its_person_out_and_tells_its_others() {
    for leaver in [0, 1] {
        let core = core(true);
        let (b, mut to_bob) = bob(&core);
        let lounge = room(&core, b, "lounge");
        core.room_join(b, lounge).unwrap();
        let (a1, rx1) = device(&core);
        let (a2, rx2) = device(&core);
        core.room_join(a1, lounge).unwrap();
        core.room_join(a2, lounge).unwrap();
        let mut rxs = [rx1, rx2];
        for rx in &mut rxs {
            drain(rx);
        }
        drain(&mut to_bob);
        core.room_part([a1, a2][leaver], lounge).unwrap();
        let part = format!("part {a1}");
        assert_eq!(heard(&mut to_bob, lounge), vec![part.clone()], "{leaver}");
        assert_eq!(heard(&mut rxs[1 - leaver], lounge), [part], "{leaver}");
        assert_eq!(heard(&mut rxs[leaver], lounge), Vec::<String>::new());
        assert!(core.rooms_of(a1).is_empty() && core.rooms_of(a2).is_empty());
        say(&core, b, lounge, "gone?").unwrap();
        assert!(rxs.iter_mut().all(|rx| heard(rx, lounge).is_empty()));
    }
}

#[test]
fn a_room_its_person_may_no_longer_be_in_is_told_to_the_devices_that_had_it_open() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let lounge = room(&core, b, "lounge");
    let (a1, mut rx1) = device(&core);
    let (_a2, mut rx2) = device(&core);
    core.room_join(a1, lounge).unwrap();
    drain(&mut rx1);
    let gate = RoomEdit {
        read: Some(vec!["bob".into()]),
        ..RoomEdit::default()
    };
    core.room_edit(b, lounge, gate).unwrap();
    assert_eq!(heard(&mut rx1, lounge), [format!("parted {a1}")]);
    assert_eq!(heard(&mut rx2, lounge), Vec::<String>::new());
}

#[test]
fn rooms_are_counted_against_a_person_not_each_device() {
    let policy = RoomPolicy {
        max_joined: 1,
        ..RoomPolicy::default()
    };
    let core = rooms_core(true, policy);
    let (b, _to_bob) = bob(&core);
    let (lounge, den) = (room(&core, b, "lounge"), room(&core, b, "den"));
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    core.room_join(a1, lounge).unwrap();
    assert_eq!(
        core.room_join(a2, den).map(|_| ()),
        Err(RoomError::TooManyRooms)
    );
    assert!(core.room_join(a2, lounge).is_ok(), "the person's one room");
}

#[test]
fn an_invitation_to_a_person_reaches_each_of_its_devices_from_its_inviters_row() {
    let core = core(true);
    let (a1, mut rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    let (b, mut to_bob) = bob(&core);
    let lounge = room(&core, b, "lounge");
    core.room_join(a2, lounge).unwrap();
    core.chat_invite(lounge, a2, b).unwrap();
    assert_eq!(heard(&mut to_bob, lounge), [format!("invite {a1}")]);
    core.room_join(b, lounge).unwrap();
    let (cid, _) = core.chat_create(b, b).unwrap();
    assert_eq!(
        core.chat_invite(cid, b, a2),
        Err(ChatError::NoSuchUser),
        "a device's own uid names nobody"
    );
    core.chat_invite(cid, b, a1).unwrap();
    assert_eq!(heard(&mut rx1, cid), [format!("invite {b}")]);
    assert_eq!(heard(&mut rx2, cid), [format!("invite {b}")]);
}

#[test]
fn with_coalescing_off_each_session_is_a_member_of_its_own() {
    let core = core(false);
    let (b, mut to_bob) = bob(&core);
    let lounge = room(&core, b, "lounge");
    core.room_join(b, lounge).unwrap();
    let (a1, _rx1) = device(&core);
    let (a2, mut rx2) = device(&core);
    core.room_join(a1, lounge).unwrap();
    let (members, _) = core.room_join(a2, lounge).unwrap();
    assert_eq!(uids(&members), [b, a1, a2]);
    assert_eq!(
        heard(&mut to_bob, lounge),
        [format!("join {a1}"), format!("join {a2}")]
    );
    core.room_part(a1, lounge).unwrap();
    assert_eq!(heard(&mut rx2, lounge), [format!("part {a1}")]);
    assert_eq!(core.rooms_of(a2), [lounge], "the other stays");
    let (cid, _) = core.chat_create(b, a1).unwrap();
    assert!(
        heard(&mut rx2, cid).is_empty(),
        "an invitation is one session's"
    );
}

#[test]
fn a_window_closed_late_parts_nobody_once_its_person_is_back_on_another_device() {
    for in_room in [false, true] {
        let core = core(true);
        let (b, mut to_bob) = bob(&core);
        let (a1, _rx1) = device(&core);
        let (a2, _rx2) = device(&core);
        let cid = match in_room {
            true => room(&core, b, "lounge"),
            false => core.chat_create(b, b).unwrap().0,
        };
        let join = |uid| match in_room {
            true => core.room_join(uid, cid).map(|_| ()).unwrap(),
            false => core.chat_join(cid, uid, "").map(|_| ()).unwrap(),
        };
        join(a1);
        join(a2);
        match in_room {
            true => core.room_part(a2, cid).unwrap(),
            false => core.chat_part(cid, a2),
        }
        join(a2);
        drain(&mut to_bob);
        // a1's window, closed by the part, is closed by its client late.
        match in_room {
            true => assert_eq!(core.room_part(a1, cid), Err(RoomError::NotAMember)),
            false => core.chat_part(cid, a1),
        }
        assert!(heard(&mut to_bob, cid).is_empty(), "room {in_room}");
        let still = match in_room {
            true => core.rooms_of(a2),
            false => core.chats_of(a2),
        };
        assert_eq!(still, [cid], "room {in_room}");
    }
}

#[test]
fn a_device_joins_voice_where_it_has_its_persons_room_or_chat_open() {
    use crate::voice::{fake::RecordingMedia, VoiceError};
    let core = core(true).with_voice(Arc::new(RecordingMedia::new()), 8);
    let (b, _to_bob) = bob(&core);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let lounge = room(&core, b, "lounge");
    let (cid, _) = core.chat_create(a1, b).unwrap();
    core.room_join(a1, lounge).unwrap();
    for id in [lounge, cid] {
        assert_eq!(
            core.voice_join(a2, id).map(|_| ()),
            Err(VoiceError::NotAMember)
        );
    }
    core.room_join(a2, lounge).unwrap();
    core.chat_join(cid, a2, "").unwrap();
    for id in [lounge, cid] {
        assert!(core.voice_join(a2, id).is_ok(), "{id}");
    }
}

#[test]
fn a_device_acts_on_a_chat_or_room_only_once_it_has_it_open() {
    type Act = fn(&Core, Uid, u32, u32, Uid) -> Result<(), ChatError>;
    let acts: [(&str, Act); 4] = [
        ("subject", |core, uid, cid, _, _| {
            core.chat_subject(cid, uid, "plans".into())
        }),
        ("password", |core, uid, cid, _, _| {
            core.chat_password(cid, uid, "pw".into())
        }),
        ("invite", |core, uid, cid, _, to| {
            core.chat_invite(cid, uid, to)
        }),
        ("room invite", |core, uid, _, room, to| {
            core.chat_invite(room, uid, to)
        }),
    ];
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let (carol, _rxc) = core
        .attach(session("carol", None, None, transport()))
        .unwrap();
    core.announce(carol);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let lounge = room(&core, b, "lounge");
    let (cid, _) = core.chat_create(a1, a1).unwrap();
    core.room_join(a1, lounge).unwrap();
    let tried = |core: &Core| -> Vec<(&str, Result<(), ChatError>)> {
        (acts.iter())
            .map(|(name, act)| (*name, act(core, a2, cid, lounge, carol)))
            .collect()
    };
    let refused: Vec<_> = acts
        .iter()
        .map(|(name, _)| (*name, Err(ChatError::NotAMember)))
        .collect();
    assert_eq!(tried(&core), refused);
    core.chat_join(cid, a2, "").unwrap();
    core.room_join(a2, lounge).unwrap();
    let made: Vec<_> = acts.iter().map(|(name, _)| (*name, Ok(()))).collect();
    assert_eq!(tried(&core), made);
}

#[test]
fn an_invitation_again_reopens_the_devices_that_declined_it() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let (a1, _rx1) = device(&core);
    // A device that has not declined keeps the person's invitation open.
    let _a2 = device(&core);
    let (cid, _) = core.chat_create(b, a1).unwrap();
    core.chat_password(cid, b, "pw".into()).unwrap();
    core.chat_decline(cid, a1);
    core.chat_invite(cid, b, a1).unwrap();
    assert!(core.chat_join(cid, a1, "").is_ok(), "invited again");
}

#[test]
fn a_devices_decline_goes_with_it() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    let (cid, _) = core.chat_create(b, a1).unwrap();
    core.chat_decline(cid, a2);
    core.end_session(a2);
    let r = core.roster.lock().unwrap();
    assert!(
        r.chats[&cid].declined.is_empty(),
        "nothing for a recycled uid"
    );
    assert!(r.chats[&cid].invited.contains(&r.row_of(a1)));
}

#[test]
fn a_device_joining_its_person_later_is_invited_to_its_private_chats() {
    let core = core(true);
    let (b, _to_bob) = bob(&core);
    let (a1, _rx1) = device(&core);
    let (cid, _) = core.chat_create(b, a1).unwrap();
    core.chat_password(cid, b, "pw".into()).unwrap();
    core.chat_join(cid, a1, "").unwrap();
    let (a2, mut rx2) = device(&core);
    assert_eq!(heard(&mut rx2, cid), [from_server(&core)]);
    assert!(core.chat_join(cid, a2, "").is_ok(), "its person's");
}

#[test]
fn the_last_device_with_a_room_or_chat_open_takes_its_person_out_as_it_ends() {
    for (in_room, other_open) in [(false, false), (true, false), (false, true), (true, true)] {
        let case = format!("room {in_room}, other open {other_open}");
        let core = core(true);
        let (b, mut to_bob) = bob(&core);
        let (a1, _rx1) = device(&core);
        let (a2, mut rx2) = device(&core);
        let cid = match in_room {
            true => room(&core, b, "lounge"),
            false => core.chat_create(b, b).unwrap().0,
        };
        let join = |uid| match in_room {
            true => core.room_join(uid, cid).map(|_| ()).unwrap(),
            false => core.chat_join(cid, uid, "").map(|_| ()).unwrap(),
        };
        if in_room {
            join(b);
        }
        join(a1);
        if other_open {
            join(a2);
        }
        drain(&mut to_bob);
        drain(&mut rx2);
        core.end_session(a1);
        let told = heard(&mut to_bob, cid);
        let still = match in_room {
            true => core.rooms_of(a2),
            false => core.chats_of(a2),
        };
        if other_open {
            assert!(told.is_empty(), "{case}: {told:?}");
            assert_eq!(still, [cid], "{case}");
        } else {
            assert_eq!(told, [format!("part {a1}")], "{case}");
            assert!(still.is_empty(), "{case}");
            assert!(heard(&mut rx2, cid).is_empty(), "{case}");
        }
    }
}

#[test]
fn a_person_out_of_its_last_room_is_free_to_join_another() {
    let policy = RoomPolicy {
        max_joined: 1,
        ..RoomPolicy::default()
    };
    let core = rooms_core(true, policy);
    let (b, _to_bob) = bob(&core);
    let (lounge, den) = (room(&core, b, "lounge"), room(&core, b, "den"));
    let (a1, _rx1) = device(&core);
    let (a2, _rx2) = device(&core);
    core.room_join(a1, lounge).unwrap();
    core.end_session(a1);
    assert!(core.room_join(a2, den).is_ok(), "max_joined freed");
}

#[test]
fn with_no_system_account_a_person_invites_its_own_devices_itself() {
    let core = Core::new()
        .with_rooms(Arc::new(MemoryRooms::default()), RoomPolicy::default())
        .unwrap()
        .with_coalesce(true);
    let (b, _to_bob) = bob(&core);
    let (a1, _rx1) = device(&core);
    let (_a2, mut rx2) = device(&core);
    let (cid, _) = core.chat_create(a1, b).unwrap();
    assert_eq!(heard(&mut rx2, cid), [format!("invite {a1}")]);
    let (_a3, mut rx3) = device(&core);
    assert_eq!(
        heard(&mut rx3, cid),
        [format!("invite {a1}")],
        "joining later"
    );
}
