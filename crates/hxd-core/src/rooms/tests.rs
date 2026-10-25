//! Rooms in the domain: who may do what, where a room's lines go and do
//! not go, the commit queue per room, ids, retention and the file.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::*;
use crate::access::AccessBits;
use crate::history::{ChatLog, HistoryPolicy, HistoryQuery, MemoryLog, NewLine};
use crate::media::{
    Canonical, MediaCodec, MediaConfig, MediaReject, MediaType, UploadOutcome, UploadPart,
};
use crate::roster::{drain, AttachInfo, Transport};
use crate::{ChatError, Events};

struct Who {
    login: String,
    access: AccessBits,
    manage: bool,
    moderate: bool,
    set_subject: bool,
}

fn member(login: &str) -> Who {
    Who {
        login: login.into(),
        access: AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT)
            .with(bit::SEND_MEDIA),
        manage: false,
        moderate: false,
        set_subject: false,
    }
}

fn manager(login: &str) -> Who {
    Who {
        manage: true,
        ..member(login)
    }
}

/// `who`'s account file, read as `who` has it.
fn account(who: &Who) -> crate::Account {
    let config = crate::AccountConfig {
        access: who.access,
        extra: crate::Extras {
            manage_rooms: Some(who.manage),
            moderate: Some(who.moderate),
            set_subject: Some(who.set_subject),
            ..Default::default()
        },
        ..Default::default()
    };
    crate::Account::new(
        who.login.clone(),
        who.login.clone(),
        true,
        Default::default(),
        config,
    )
}

fn attach(core: &Core, who: Who) -> (Uid, Events) {
    attach_from(core, who, None)
}

fn attach_from(core: &Core, who: Who, addr: Option<std::net::IpAddr>) -> (Uid, Events) {
    let account = Box::new(account(&who));
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: who.login.clone(),
            icon: 1,
            admin: false,
            access: who.access,
            login: who.login,
            addr,
            can_detach: true,
            transport: Transport {
                inline_media: true,
                redactions: true,
                ..Default::default()
            },
            has_inbox: false,
            attach_news: false,
            set_avatar: false,
            moderate: who.moderate,
            can_spam: false,
            manage_rooms: who.manage,
            set_subject: who.set_subject,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
            account: Some(account),
            system: false,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

fn with_rooms(core: Core) -> Core {
    core.with_rooms(Arc::new(MemoryRooms::default()), RoomPolicy::default())
        .unwrap()
}

fn named(name: &str) -> RoomEdit {
    RoomEdit {
        name: Some(name.into()),
        ..RoomEdit::default()
    }
}

fn say(core: &Core, uid: Uid, room: u32, text: &str) -> Result<Option<LineId>, ChatError> {
    core.chat_public_all(uid, room, vec![(text.into(), 0, None)])
        .pop()
        .unwrap()
}

/// What `events` said about `room`, unwrapped.
fn about(events: &[Event], room: u32) -> Vec<Event> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::InRoom { room: r, event } if *r == room => Some((**event).clone()),
            _ => None,
        })
        .collect()
}

fn heard_text(events: &[Event], text: &str) -> bool {
    let line = |e: &Event| matches!(e, Event::Chat { text: t, .. } if t == text);
    events.iter().any(|e| match e {
        Event::InRoom { event, .. } => line(event),
        e => line(e),
    })
}

fn logged(log: &dyn ChatLog, channel: u32) -> Vec<LineId> {
    log.query(&HistoryQuery {
        channel,
        before: None,
        after: None,
        limit: 1000,
    })
    .unwrap()
    .lines
    .iter()
    .map(|l| l.id)
    .collect()
}

/// Lines said at once in the lobby and in several rooms: each room's
/// members hear its lines in the order they were logged, ids rising.
#[test]
fn ids_ascend_in_each_room_in_the_order_its_members_hear_them() {
    let log = Arc::new(MemoryLog::default());
    let core = Arc::new(with_rooms(
        Core::new().with_history(log.clone(), HistoryPolicy::default()),
    ));
    let (boss, _) = attach(&core, manager("boss"));
    let rooms: Vec<u32> = ["a", "b", "c"]
        .iter()
        .map(|n| core.room_create(boss, named(n)).unwrap().id)
        .collect();
    let (ear, mut heard) = attach(&core, member("ear"));
    let senders: Vec<Uid> = (0..4)
        .map(|i| attach(&core, member(&format!("s{i}"))).0)
        .collect();
    for &room in &rooms {
        for &uid in senders.iter().chain([&ear]) {
            core.room_join(uid, room).unwrap();
        }
    }
    let channels: Vec<u32> = std::iter::once(0).chain(rooms.iter().copied()).collect();
    let threads: Vec<_> = senders
        .iter()
        .flat_map(|&uid| channels.iter().map(move |&room| (uid, room)))
        .map(|(uid, room)| {
            let core = core.clone();
            std::thread::spawn(move || {
                for n in 0..10 {
                    say(&core, uid, room, &format!("{room} {n}")).unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let events = drain(&mut heard);
    for &channel in &channels {
        let ids: Vec<LineId> = events
            .iter()
            .filter_map(|e| match e {
                Event::Chat {
                    cid: 0,
                    id: Some(id),
                    ..
                } if channel == 0 => Some(*id),
                Event::InRoom { room, event } if *room == channel => match **event {
                    Event::Chat {
                        cid, id: Some(id), ..
                    } if cid == channel => Some(id),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 40, "channel {channel}");
        assert!(ids.windows(2).all(|w| w[0] < w[1]), "channel {channel}");
        assert_eq!(ids, logged(&*log, channel), "channel {channel}");
    }
}

/// Decodes nothing; its canonical bytes are the input reversed.
struct FakeCodec;

impl MediaCodec for FakeCodec {
    fn canonicalize(&self, input: &[u8]) -> Result<Canonical, MediaReject> {
        Ok(Canonical {
            mime: MediaType::Png,
            width: 8,
            height: 4,
            bytes: input.iter().rev().copied().collect(),
        })
    }
}

/// A room's line, its image and its redaction reach the room's members
/// and nobody else: not a lobby reader outside it, not a linked server.
#[test]
fn a_room_line_its_image_and_its_redaction_stay_in_the_room() {
    let log = Arc::new(MemoryLog::default());
    let core = with_rooms(
        Core::new()
            .with_history(log.clone(), HistoryPolicy::default())
            .with_media(
                Arc::new(FakeCodec),
                MediaConfig {
                    upload_interval: Duration::ZERO,
                    ..Default::default()
                },
            )
            .with_moderation(
                Arc::new(crate::MemoryModeration::default()),
                crate::ModerationPolicy::default(),
            ),
    );
    let mut feed = core.peer_feed(64);
    let (boss, _) = attach(&core, manager("boss"));
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let (alice, _ra) = attach(&core, member("alice"));
    let (bob, mut rb) = attach(&core, member("bob"));
    let (carol, mut rc) = attach(&core, member("carol"));
    core.room_join(alice, room).unwrap();
    core.room_join(bob, room).unwrap();
    let upload = UploadPart {
        payload: b"an image",
        declared: None,
        token: None,
        index: 0,
        count: None,
        last: true,
    };
    let handle = match core.media_upload_part(alice, upload).unwrap() {
        UploadOutcome::Done(m) => m.id.unwrap(),
        UploadOutcome::Token(_) => panic!("a single-shot upload answered with a token"),
    };
    let id = core
        .chat_public_all(alice, room, vec![("look".into(), 0, Some(handle))])
        .pop()
        .unwrap()
        .unwrap()
        .expect("a logged line");
    assert_eq!(log.line(id).unwrap().unwrap().channel, room);
    let principal = |uid| core.principal_of(uid).unwrap();
    assert!(core.media_fetch_as(&principal(bob), &handle).is_some());
    assert!(core.media_fetch_as(&principal(carol), &handle).is_none());

    core.redact_line(crate::Actor::Operator, id, "spam")
        .unwrap();
    let to_bob = drain(&mut rb);
    assert!(heard_text(&to_bob, "look"));
    assert!(about(&to_bob, room).contains(&Event::ChatRedacted { id }));
    let to_carol = drain(&mut rc);
    assert!(
        !to_carol
            .iter()
            .any(|e| matches!(e, Event::InRoom { .. } | Event::ChatRedacted { .. })),
        "{to_carol:?}"
    );
    while let Ok((_, e)) = feed.try_recv() {
        assert!(
            !matches!(e, crate::server_link::PeerEvent::Chat { .. }),
            "a room's line crossed a link"
        );
    }
}

/// A guid is its sender's in one room: the same one in the lobby and in
/// a room is two lines, and sent again in the room is one, its guid on
/// the sender's copy alone.
#[test]
fn a_guid_is_held_per_room() {
    let core = with_rooms(
        Core::new().with_history(Arc::new(MemoryLog::default()), HistoryPolicy::default()),
    );
    let (boss, _) = attach(&core, manager("boss"));
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let (alice, mut ra) = attach(&core, member("alice"));
    let (bob, mut rb) = attach(&core, member("bob"));
    core.room_join(alice, room).unwrap();
    core.room_join(bob, room).unwrap();
    drain(&mut ra);
    drain(&mut rb);
    let guid = crate::inbox::MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
    let send = |room, text: &str| {
        core.chat_public_guid(alice, room, (text.into(), 0, None), Some(guid.clone()))
            .unwrap()
            .expect("a logged line")
    };
    let lobby = send(0, "lobby");
    let first = send(room, "room");
    assert_ne!(lobby, first);
    assert_eq!(send(room, "room again"), first);
    let said = |events: Vec<Event>| -> Vec<(String, Option<crate::inbox::MessageGuid>)> {
        about(&events, room)
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { text, guid, .. } => Some((text, guid)),
                _ => None,
            })
            .collect()
    };
    assert_eq!(
        said(drain(&mut ra)),
        [("room".to_string(), Some(guid.clone()))]
    );
    assert_eq!(said(drain(&mut rb)), [("room".to_string(), None)]);
}

#[test]
fn rooms_need_no_history() {
    let core = with_rooms(Core::new());
    let (boss, _) = attach(&core, manager("boss"));
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let (alice, _ra) = attach(&core, member("alice"));
    let (bob, mut rb) = attach(&core, member("bob"));
    core.room_join(alice, room).unwrap();
    core.room_join(bob, room).unwrap();
    assert_eq!(say(&core, alice, room, "hi"), Ok(None));
    assert!(matches!(
        &about(&drain(&mut rb), room)[..],
        [Event::Chat { text, id: None, .. }] if text == "hi"
    ));
}

/// `/rooms` is one private message: past its length the list is cut,
/// and says how to narrow it.
#[test]
fn a_long_room_list_is_cut_to_one_message() {
    let core = with_rooms(Core::new()).with_system(crate::SystemPolicy::default());
    let (boss, _) = attach(&core, manager("boss"));
    for i in 0..40 {
        let edit = RoomEdit {
            topic: Some("t".repeat(200)),
            ..named(&format!("room-{i:02}"))
        };
        core.room_create(boss, edit).unwrap();
    }
    let (alice, _ra) = attach(&core, member("alice"));
    let all = core.system_command(alice, "/rooms").unwrap();
    assert!(all.len() <= 4096, "{}", all.len());
    assert!(
        all.ends_with("\n… and more; /rooms <word> narrows it"),
        "{all}"
    );
    let narrowed = core.system_command(alice, "/rooms #room-1").unwrap();
    assert_eq!(narrowed.lines().count(), 10, "{narrowed}");
    assert!(narrowed.starts_with("#room-10 — "));
}

/// Guests share one login, so the lobby notice remembers a guest by its
/// address: a second guest from elsewhere is told, one from the same
/// address is not.
#[test]
fn the_lobby_notice_knows_a_guest_by_its_address() {
    let core = with_rooms(Core::new()).with_system(crate::SystemPolicy::default());
    let (boss, _) = attach(&core, manager("boss"));
    core.room_create(boss, named("lounge")).unwrap();
    let here: std::net::IpAddr = [192, 0, 2, 1].into();
    let there: std::net::IpAddr = [192, 0, 2, 2].into();
    for (addr, told) in [(here, true), (there, true), (here, false)] {
        let (uid, _rx) = attach_from(&core, member("guest"), Some(addr));
        assert_eq!(
            core.rooms_announcement(uid).is_some(),
            told,
            "{addr} told: {told}"
        );
    }
}

/// What a session may do in a room, by what the room and its account
/// allow; a room it may not see is one that does not exist.
#[test]
fn a_room_is_entered_and_spoken_in_as_its_gates_allow() {
    let core = with_rooms(Core::new());
    let (boss, _) = attach(&core, manager("boss"));
    let room = |name: &str, read: &[&str], post: &[&str]| {
        let gate = |l: &[&str]| Some(l.iter().map(|s| s.to_string()).collect());
        core.room_create(
            boss,
            RoomEdit {
                read: gate(read),
                post: gate(post),
                ..named(name)
            },
        )
        .unwrap()
        .id
    };
    let open = room("lounge", &[], &[]);
    let staff = room("staff", &["carol"], &[]);
    let news = room("news", &[], &["carol"]);
    let (alice, _) = attach(&core, member("alice"));
    let (carol, _) = attach(&core, member("carol"));
    let (mods, _) = attach(
        &core,
        Who {
            moderate: true,
            ..member("mods")
        },
    );
    let (mute, _) = attach(
        &core,
        Who {
            access: AccessBits::empty().with(bit::READ_CHAT),
            ..member("mute")
        },
    );
    for (who, room, joins, says) in [
        (alice, open, Ok(()), Ok(None)),
        (
            alice,
            staff,
            Err(RoomError::NoSuchRoom),
            Err(ChatError::NoSuchChat),
        ),
        (alice, news, Ok(()), Err(ChatError::ReadOnly)),
        (carol, staff, Ok(()), Ok(None)),
        (carol, news, Ok(()), Ok(None)),
        (mods, staff, Ok(()), Ok(None)),
        (mute, open, Ok(()), Err(ChatError::ReadOnly)),
    ] {
        let before = say(&core, who, room, "early");
        assert_eq!(
            core.room_join(who, room).map(|_| ()),
            joins,
            "{who} joins {room}"
        );
        if joins.is_ok() {
            assert_eq!(before, Err(ChatError::NotAMember), "{who} in {room}");
        }
        assert_eq!(say(&core, who, room, "hi"), says, "{who} says in {room}");
    }
    assert_eq!(core.room_part(alice, staff), Err(RoomError::NoSuchRoom));
    assert_eq!(core.room_part(carol, open), Err(RoomError::NotAMember));
    assert_eq!(
        core.room_topic(carol, news, "x".into()),
        Err(RoomError::AccessDenied),
        "a topic needs set_subject too"
    );
    assert_eq!(
        core.room_create(alice, named("mine")),
        Err(RoomError::AccessDenied)
    );
    assert_eq!(
        core.room_create(boss, named("lounge")),
        Err(RoomError::NameTaken)
    );
    assert!(matches!(
        core.room_create(
            boss,
            RoomEdit {
                read: Some(vec!["@moderators".into()]),
                ..named("roles")
            }
        ),
        Err(RoomError::Invalid(_))
    ));
}

#[test]
fn a_session_is_in_so_many_rooms_and_leaves_them_when_it_ends() {
    let core = Core::new()
        .with_rooms(
            Arc::new(MemoryRooms::default()),
            RoomPolicy {
                max_joined: 2,
                ..RoomPolicy::default()
            },
        )
        .unwrap();
    let (boss, _) = attach(&core, manager("boss"));
    let rooms: Vec<u32> = ["a", "b", "c"]
        .iter()
        .map(|n| core.room_create(boss, named(n)).unwrap().id)
        .collect();
    let (alice, _) = attach(&core, member("alice"));
    let (bob, mut rb) = attach(&core, member("bob"));
    core.room_join(bob, rooms[0]).unwrap();
    core.room_join(alice, rooms[0]).unwrap();
    core.room_join(alice, rooms[1]).unwrap();
    // A join of a room it is in already is answered again, not counted.
    core.room_join(alice, rooms[1]).unwrap();
    assert_eq!(
        core.room_join(alice, rooms[2]),
        Err(RoomError::TooManyRooms)
    );
    // A detach keeps them; the end of the session parts them all.
    assert!(core.connection_lost(alice, 8));
    let mut joined = rooms[..2].to_vec();
    joined.sort_unstable();
    assert_eq!(core.rooms_of(alice), joined);
    drain(&mut rb);
    core.end_session(alice);
    assert!(core.rooms_of(alice).is_empty());
    assert_eq!(
        about(&drain(&mut rb), rooms[0]),
        [Event::ChatUserParted {
            cid: rooms[0],
            uid: alice
        }]
    );
}

/// Whatever takes away a member's access parts it, and only it: a gate
/// narrowed, an archive, a file reloaded with the room gone.
#[test]
fn losing_access_to_a_room_parts_its_members() {
    type Change = fn(&Core, &MemoryRooms, Uid, u32);
    let narrow: Change = |core, _, boss, room| {
        let edit = RoomEdit {
            read: Some(vec!["alice".into()]),
            ..RoomEdit::default()
        };
        core.room_edit(boss, room, edit).unwrap();
    };
    let archive: Change = |core, _, boss, room| {
        core.room_archive(boss, room, true).unwrap();
    };
    let removed: Change = |core, store, _, _| {
        store.0.lock().unwrap().rooms.clear();
        core.reload_rooms().unwrap();
    };
    let unread: Change = |core, _, _, _| {
        core.apply_account(&account(&Who {
            access: AccessBits::empty().with(bit::SEND_CHAT),
            ..member("bob")
        }));
    };
    for (change, alice_stays) in [
        (narrow, true),
        (unread, true),
        (archive, false),
        (removed, false),
    ] {
        let store = Arc::new(MemoryRooms::default());
        let core = Core::new()
            .with_rooms(store.clone(), RoomPolicy::default())
            .unwrap();
        let (boss, _) = attach(&core, manager("boss"));
        let room = core.room_create(boss, named("lounge")).unwrap().id;
        let (alice, mut ra) = attach(&core, member("alice"));
        let (bob, _) = attach(&core, member("bob"));
        core.room_join(alice, room).unwrap();
        core.room_join(bob, room).unwrap();
        drain(&mut ra);
        change(&core, &store, boss, room);
        assert!(core.rooms_of(bob).is_empty());
        assert_eq!(core.rooms_of(alice).len(), usize::from(alice_stays));
        if alice_stays {
            assert_eq!(
                about(&drain(&mut ra), room),
                [Event::ChatUserParted {
                    cid: room,
                    uid: bob
                }]
            );
        }
    }
}

/// A session's mask takes away what its account gives: `manage_rooms`
/// and the rooms only a manager sees, and bit 9 every room.
#[test]
fn a_session_mask_takes_management_and_membership_away() {
    let core = with_rooms(Core::new());
    let (boss, mut rb) = attach(&core, manager("boss"));
    core.rooms_aware(boss);
    let open = core.room_create(boss, named("lounge")).unwrap().id;
    let staff = core
        .room_create(
            boss,
            RoomEdit {
                read: Some(vec!["carol".into()]),
                ..named("staff")
            },
        )
        .unwrap()
        .id;
    core.room_join(boss, staff).unwrap();
    let (alice, _) = attach(&core, member("alice"));
    core.room_join(alice, open).unwrap();
    let listed = |uid| -> Vec<u32> { core.room_list(uid).iter().map(|v| v.room.id).collect() };
    assert!(listed(boss).contains(&staff));
    drain(&mut rb);

    let unmanaged = crate::DenyMask {
        extra: crate::Extras {
            manage_rooms: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(core.set_session_mask(boss, unmanaged));
    assert_eq!(
        core.room_create(boss, named("other")).unwrap_err(),
        RoomError::AccessDenied
    );
    assert_eq!(listed(boss), [open]);
    assert!(core.rooms_of(boss).is_empty());
    assert!(drain(&mut rb).contains(&Event::RoomRemoved { room: staff }));

    let unread = crate::DenyMask {
        access: AccessBits::empty().with(bit::READ_CHAT),
        ..Default::default()
    };
    assert!(core.set_session_mask(alice, unread));
    assert!(core.rooms_of(alice).is_empty());
}

/// A listing's changes reach the rooms-aware alone, and a topic reaches
/// a member as the room's subject and anyone else as the room changed.
#[test]
fn a_topic_is_a_subject_to_members_and_a_change_to_the_rest_of_the_aware() {
    let core = with_rooms(Core::new());
    let (boss, _) = attach(&core, manager("boss"));
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let (inside, mut ri) = attach(&core, member("inside"));
    let (outside, mut ro) = attach(&core, member("outside"));
    let (_, mut unaware) = attach(&core, member("unaware"));
    for uid in [inside, outside] {
        core.rooms_aware(uid);
    }
    core.room_join(inside, room).unwrap();
    for rx in [&mut ri, &mut ro, &mut unaware] {
        drain(rx);
    }
    core.room_edit(
        boss,
        room,
        RoomEdit {
            topic: Some("quiet".into()),
            ..RoomEdit::default()
        },
    )
    .unwrap();
    assert_eq!(
        about(&drain(&mut ri), room),
        [Event::ChatSubject {
            cid: room,
            subject: "quiet".into()
        }]
    );
    let heard = drain(&mut ro);
    assert!(
        matches!(&heard[..], [Event::RoomChanged(v)] if v.room.topic.text == "quiet"),
        "{heard:?}"
    );
    core.room_archive(boss, room, true).unwrap();
    assert!(drain(&mut unaware).is_empty());
    assert_eq!(drain(&mut ro), [Event::RoomRemoved { room }]);
}

#[test]
fn an_entry_written_without_an_id_is_given_one_that_survives_a_reload() {
    let store = Arc::new(MemoryRooms::new(RoomFile {
        rooms: vec![Room {
            name: "lounge".into(),
            ..Room::default()
        }],
        ..RoomFile::default()
    }));
    let core = Core::new()
        .with_rooms(store.clone(), RoomPolicy::default())
        .unwrap();
    let id = store.load().unwrap().rooms[0].id;
    assert_ne!(id, 0);
    core.reload_rooms().unwrap();
    assert_eq!(store.load().unwrap().rooms[0].id, id);
    let (alice, _) = attach(&core, member("alice"));
    assert_eq!(core.room_list(alice)[0].room.id, id);
}

/// A room's id is never another's: not an archived room's, not a
/// tombstone's, not one whose tombstone was taken out of the file by
/// hand, and not a channel the log has lines in.
#[test]
fn a_room_id_is_never_drawn_again() {
    let log = Arc::new(MemoryLog::default());
    log.append(&NewLine {
        channel: 77,
        ghost: None,
        from_nick: "old".into(),
        from_login: None,
        from_fingerprint: None,
        icon: 0,
        text: "a line from before".into(),
        flags: Default::default(),
        at: SystemTime::now(),
        guid: None,
        signed: None,
    })
    .unwrap();
    let store = Arc::new(MemoryRooms::new(RoomFile {
        rooms: vec![
            Room {
                id: 5,
                name: "old-news".into(),
                archived_at: Some(SystemTime::now()),
                ..Room::default()
            },
            Room::tombstone(6),
            Room::tombstone(7),
        ],
        ..RoomFile::default()
    }));
    let core = Core::new()
        .with_history(log, HistoryPolicy::default())
        .with_rooms(store.clone(), RoomPolicy::default())
        .unwrap();
    store.0.lock().unwrap().rooms.retain(|r| r.id != 7);
    core.reload_rooms().unwrap();
    let r = core.roster.lock().unwrap();
    for id in [5, 6, 7, 77] {
        assert!(!r.chat_id_free(id), "{id}");
    }
}

#[test]
fn retention_keeps_a_quiet_rooms_lines_under_a_busy_lobby() {
    let log = Arc::new(MemoryLog::default());
    let core = with_rooms(Core::new().with_history(log.clone(), HistoryPolicy::default()));
    let (boss, _) = attach(&core, manager("boss"));
    let quiet = core.room_create(boss, named("quiet")).unwrap().id;
    let small = RoomEdit {
        max_lines: Some(Some(1)),
        ..named("small")
    };
    let small = core.room_create(boss, small).unwrap().id;
    let (alice, _) = attach(&core, member("alice"));
    core.room_join(alice, quiet).unwrap();
    core.room_join(alice, small).unwrap();
    for room in [quiet, small] {
        say(&core, alice, room, "one").unwrap();
        say(&core, alice, room, "two").unwrap();
    }
    for n in 0..10 {
        say(&core, alice, 0, &n.to_string()).unwrap();
    }
    core.prune_history(5, None);
    assert_eq!(logged(&*log, 0).len(), 5);
    assert_eq!(logged(&*log, quiet).len(), 2);
    assert_eq!(logged(&*log, small).len(), 1);
}

/// A store whose file stops parsing, or whose topics stop writing, when
/// told to.
#[derive(Default)]
struct Breakable {
    inner: MemoryRooms,
    broken: AtomicBool,
    topics_broken: AtomicBool,
}

impl RoomStore for Breakable {
    fn load(&self) -> Result<RoomFile, StoreError> {
        if self.broken.load(Ordering::Relaxed) {
            return Err(StoreError::new("rooms.toml: expected `=`"));
        }
        self.inner.load()
    }
    fn put(&self, room: &Room) -> Result<(), StoreError> {
        self.inner.put(room)
    }
    fn put_topic(&self, id: u32, topic: &Topic) -> Result<(), StoreError> {
        if self.topics_broken.load(Ordering::Relaxed) {
            return Err(StoreError::new("rooms.toml: read-only file system"));
        }
        self.inner.put_topic(id, topic)
    }
}

#[test]
fn a_file_that_does_not_parse_refuses_startup_and_leaves_a_running_server_alone() {
    let broken = Arc::new(Breakable::default());
    broken.broken.store(true, Ordering::Relaxed);
    assert!(Core::new()
        .with_rooms(broken, RoomPolicy::default())
        .is_err());

    let store = Arc::new(Breakable::default());
    store
        .inner
        .put(&Room {
            name: "lounge".into(),
            ..Room::default()
        })
        .unwrap();
    let core = Core::new()
        .with_rooms(store.clone(), RoomPolicy::default())
        .unwrap();
    let (alice, _) = attach(&core, member("alice"));
    let room = core.room_list(alice)[0].room.id;
    core.room_join(alice, room).unwrap();
    store.broken.store(true, Ordering::Relaxed);
    assert!(core.reload_rooms().is_err());
    assert_eq!(core.rooms_of(alice), [room]);
    assert_eq!(core.room_list(alice).len(), 1);
}

/// A topic is heard at once and reaches the file when it is flushed, the
/// lobby's as a room's.
#[test]
fn topics_are_kept_in_the_file() {
    let store = Arc::new(MemoryRooms::default());
    let core = Core::new()
        .with_rooms(store.clone(), RoomPolicy::default())
        .unwrap();
    let (boss, _) = attach(
        &core,
        Who {
            set_subject: true,
            ..manager("boss")
        },
    );
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    core.room_topic(boss, room, "anything goes".into()).unwrap();
    core.chat_subject(0, boss, "welcome".into()).unwrap();
    assert_eq!(store.load().unwrap().lobby.text, "");
    core.flush_room_topics(false);
    let file = store.load().unwrap();
    assert_eq!(file.lobby.text, "welcome");
    assert_eq!(file.rooms[0].topic.text, "anything goes");
    assert_eq!(file.rooms[0].topic.by, "boss");
    let again = Core::new()
        .with_rooms(store, RoomPolicy::default())
        .unwrap();
    assert_eq!(again.public_subject(), "welcome");
}

/// A room's voice room is its members', a room the session may not see is
/// a chat that does not exist, and leaving the room leaves its voice.
#[test]
fn a_rooms_voice_is_its_members_and_leaving_the_room_leaves_it() {
    let media = Arc::new(crate::voice::fake::RecordingMedia::new());
    let core = with_rooms(Core::new().with_voice(media, crate::DEFAULT_MAX_PER_ROOM));
    let (boss, _) = attach(&core, manager("boss"));
    let staff = RoomEdit {
        read: Some(vec!["alice".into()]),
        ..named("staff")
    };
    let staff = core.room_create(boss, staff).unwrap().id;
    let (alice, _) = attach(&core, member("alice"));
    let (bob, _) = attach(&core, member("bob"));
    assert_eq!(
        core.voice_join(bob, staff),
        Err(crate::VoiceError::NoSuchChat)
    );
    assert_eq!(
        core.voice_join(alice, staff),
        Err(crate::VoiceError::NotAMember)
    );
    core.room_join(alice, staff).unwrap();
    core.voice_join(alice, staff).unwrap();
    core.room_part(alice, staff).unwrap();
    assert_eq!(core.voice_room_of(alice), None);
}

/// An archive parts a whole room at once: each member is told once that
/// it was parted, and hears nothing of the others.
#[test]
fn archiving_a_full_room_tells_each_member_once() {
    let core = with_rooms(Core::new());
    let (boss, _) = attach(&core, manager("boss"));
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let mut members: Vec<(Uid, Events)> = (0..100)
        .map(|i| attach(&core, member(&format!("m{i}"))))
        .collect();
    for (uid, _) in &members {
        core.room_join(*uid, room).unwrap();
    }
    for (_, rx) in &mut members {
        drain(rx);
    }
    core.room_archive(boss, room, true).unwrap();
    for (uid, rx) in &mut members {
        assert_eq!(
            about(&drain(rx), room),
            [Event::RoomParted {
                uid: *uid,
                reason: PartReason::Archived
            }]
        );
    }
}

/// A tombstone takes the room's lines with it when the server first sees
/// it, and leaves every other channel's.
#[test]
fn a_deleted_rooms_lines_go_when_the_server_sees_its_tombstone() {
    let log = Arc::new(MemoryLog::default());
    let store = Arc::new(MemoryRooms::default());
    let core = Core::new()
        .with_history(log.clone(), HistoryPolicy::default())
        .with_rooms(store.clone(), RoomPolicy::default())
        .unwrap();
    let (boss, _) = attach(&core, manager("boss"));
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let (alice, _) = attach(&core, member("alice"));
    core.room_join(alice, room).unwrap();
    say(&core, alice, room, "gone soon").unwrap();
    say(&core, alice, 0, "staying").unwrap();
    store.put(&Room::tombstone(room)).unwrap();
    core.reload_rooms().unwrap();
    assert!(core.rooms_of(alice).is_empty());
    assert!(logged(&*log, room).is_empty());
    assert_eq!(logged(&*log, 0).len(), 1);
}

/// A topic the file would not take stays the room's until it does: a
/// reload keeps it rather than the file's, and a reload or the shutdown
/// flush writes it once the file can be written.
#[test]
fn a_topic_that_would_not_write_outlives_a_reload_and_is_written_later() {
    let store = Arc::new(Breakable::default());
    let core = Core::new()
        .with_rooms(store.clone(), RoomPolicy::default())
        .unwrap();
    let (boss, _) = attach(
        &core,
        Who {
            set_subject: true,
            ..manager("boss")
        },
    );
    let room = core.room_create(boss, named("lounge")).unwrap().id;
    let topic_of = |core: &Core| core.room_list(boss)[0].room.topic.text.clone();
    let filed = || store.inner.load().unwrap().rooms[0].topic.text.clone();
    store.topics_broken.store(true, Ordering::Relaxed);
    core.room_topic(boss, room, "first".into()).unwrap();
    core.flush_room_topics(false);
    core.reload_rooms().unwrap();
    assert_eq!(topic_of(&core), "first");
    store.topics_broken.store(false, Ordering::Relaxed);
    core.reload_rooms().unwrap();
    assert_eq!(filed(), "first");

    store.topics_broken.store(true, Ordering::Relaxed);
    core.room_topic(boss, room, "second".into()).unwrap();
    core.flush_room_topics(false);
    store.topics_broken.store(false, Ordering::Relaxed);
    core.flush_room_topics(true);
    assert_eq!(filed(), "second");
}
