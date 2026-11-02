//! The paths around the live announcements that a healthy store and a
//! quiet server never take: store failures, races, the bounds, and the
//! gates a session can lose between a change and its batch.

use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;

use super::tests::{batches, bits, hearing, ng, party, said, server, thumbs};
use super::*;
use crate::history::faulty::FaultyLog;
use crate::history::HistoryPolicy;
use crate::moderation::faulty::FaultyModeration;
use crate::roster::drain;
use crate::{Events, MemoryModeration, ModerationPolicy, ModerationStore, Transport};

/// A core on the fault-injecting log, moderated in `moderation`.
fn on_faulty(moderation: Arc<dyn ModerationStore>) -> (Arc<Core>, Arc<FaultyLog>) {
    let log = Arc::new(FaultyLog::default());
    let core = Core::new()
        .with_history(log.clone(), HistoryPolicy::default())
        .with_reactions(ReactionPolicy {
            burst: 1_000_000,
            ..ReactionPolicy::default()
        })
        .with_moderation(moderation, ModerationPolicy::default());
    (Arc::new(core), log)
}

/// Let a room's owed batch go: the clock moved past it, and flushed.
fn flush(core: &Core) {
    core.clock.advance(Duration::from_secs(5));
    core.reactions_flush(core.clock.now());
}

/// A batch whose summaries could not be read is owed again, and the
/// next flush tells it whole, a moderator's clear in it and in order.
#[test]
fn a_batch_that_could_not_be_read_goes_in_the_next() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let [one, two] = ["one", "two"].map(|t| said(&core, alice, t));
    core.react(alice, 0, two, &thumbs(), true).unwrap();
    flush(&core);
    drain(&mut ra);
    core.react(alice, 0, one, &party(), true).unwrap();
    core.react_clear(carol, 0, two).unwrap();
    log.fail("reactions", true);
    flush(&core);
    assert!(batches(&mut ra).is_empty(), "nothing could be told");
    log.fail("reactions", false);
    flush(&core);
    assert_eq!(
        batches(&mut ra),
        [vec![
            (one, Some((vec![(party(), 1)], vec![0]))),
            (two, None)
        ]]
    );
}

/// A clear whose act cannot be recorded takes nothing, and says so.
#[test]
fn a_clear_that_cannot_be_recorded_takes_nothing() {
    let moderation = Arc::new(FaultyModeration::default());
    let (core, _log) = on_faulty(moderation.clone());
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "one");
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    moderation.fail("record");
    assert_eq!(
        core.react_clear(carol, 0, line),
        Err(ReactError::ServerError)
    );
    let kept = core.line_reactions(alice, &[line]).unwrap();
    assert_eq!(kept[&line].keys, [(thumbs(), 1)]);
}

/// Past the server-wide bound, the oldest waiting anywhere goes,
/// whichever account it waits for.
#[test]
fn the_oldest_waiting_anywhere_goes_past_the_server_wide_bound() {
    let mut live = Live {
        im_keep: Duration::from_secs(3600),
        waiting_all: 3,
        ..Live::default()
    };
    let start = Instant::now();
    let now = start + Duration::from_secs(10);
    for (n, to) in ["bob", "carol", "dave", "erin"].into_iter().enumerate() {
        let guid =
            crate::inbox::MessageGuid::parse(&format!("5f5e1000-1234-4abc-89ab-{n:012x}")).unwrap();
        let w = Waiting {
            from: Mailbox::login("alice"),
            change: ReactionChange::Changed {
                target: Reply::im(to.into(), guid).unwrap(),
                key: thumbs(),
                add: true,
                from: "alice".into(),
            },
            at: start + Duration::from_secs(n as u64),
        };
        live.keep(Key::of(&Mailbox::login(to)), w, now);
    }
    let mut left: Vec<String> = (live.waiting.keys())
        .map(|k| match k {
            Key::Login(l) => l.clone(),
            Key::Identity(_) => unreachable!("logins alone here"),
        })
        .collect();
    left.sort();
    assert_eq!(left, ["carol", "dave", "erin"]);
    assert_eq!(live.waiting_len, 3);
}

/// A reaction applied as its line is redacted is never told after the
/// redaction as anything but cleared.
#[test]
fn a_reaction_racing_a_redaction_is_told_after_it_as_cleared() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "regrettable");
    drain(&mut ra);
    let at = Arc::new(Barrier::new(2));
    log.park_after("react", at.clone());
    let reacting = {
        let core = core.clone();
        thread::spawn(move || core.react(alice, 0, line, &thumbs(), true))
    };
    at.wait();
    core.redact_line(crate::Actor::Session(carol), line, "no")
        .unwrap();
    at.wait();
    reacting.join().unwrap().unwrap();
    flush(&core);
    let told = drain(&mut ra);
    let redacted = (told.iter())
        .position(|e| matches!(e, Event::ChatRedacted { id } if *id == line))
        .expect("the redaction is told");
    for e in &told[redacted..] {
        if let Event::ReactionsChanged(changes) = e {
            assert!(
                changes
                    .iter()
                    .all(|c| matches!(c, ReactionChange::Clear { .. })),
                "{changes:?}"
            );
        }
    }
}

/// What a clear records is exactly what it took, a reaction made while
/// it worked waiting for it and staying.
#[test]
fn a_clears_evidence_is_the_rows_it_took() {
    let moderation = Arc::new(MemoryModeration::default());
    let (core, log) = on_faulty(moderation.clone());
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (bob, _) = hearing(&core, "bob", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "vote");
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    let at = Arc::new(Barrier::new(2));
    log.park_after("reactions", at.clone());
    let clearing = {
        let core = core.clone();
        thread::spawn(move || core.react_clear(carol, 0, line))
    };
    at.wait();
    let reacting = {
        let core = core.clone();
        thread::spawn(move || core.react(bob, 0, line, &party(), true))
    };
    // Long enough for an unguarded reaction to land inside the clear.
    thread::sleep(Duration::from_millis(100));
    at.wait();
    clearing.join().unwrap().unwrap();
    reacting.join().unwrap().unwrap();
    let act = (moderation.acts(None, 10).unwrap().into_iter())
        .find(|a| a.kind == crate::ActKind::ClearReactions)
        .unwrap();
    assert_eq!(act.evidence.as_deref(), Some(&*format!("#{line}: 👍 1")));
    let kept = core.line_reactions(alice, &[line]).unwrap();
    assert_eq!(kept[&line].keys, [(party(), 1)], "made after the clear");
}

/// Reactions, a rekey holding the writes' lock while it tells the
/// roster, batches under a room's serial and a clear, all at once, in
/// the order the lock's declaration gives, finish.
#[test]
fn the_reaction_locks_are_taken_in_one_order() {
    let (core, _log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "busy");
    let (done, finished) = mpsc::channel();
    type Work = Box<dyn Fn(&Core) + Send>;
    let work: Vec<Work> = vec![
        Box::new(move |c| {
            let _ = c.react(alice, 0, line, &thumbs(), true);
            let _ = c.react(alice, 0, line, &thumbs(), false);
        }),
        Box::new(|c| {
            let (a, b) = (Mailbox::login("erin"), Mailbox::identified("erin", [3; 32]));
            c.rekey_reactions(&a, &b);
            c.rekey_reactions(&b, &a);
        }),
        Box::new(|c| {
            c.clock.advance(Duration::from_secs(2));
            c.reactions_flush(c.clock.now());
        }),
        Box::new(move |c| {
            let _ = c.react_clear(carol, 0, line);
        }),
    ];
    for w in work {
        let (core, done) = (core.clone(), done.clone());
        thread::spawn(move || {
            for _ in 0..500 {
                w(&core);
            }
            let _ = done.send(());
        });
    }
    for _ in 0..4 {
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("the reaction locks deadlocked");
    }
}

/// A session that loses its right to read a line between the change
/// and its batch is not told it.
#[test]
fn a_reader_that_lost_the_line_before_its_batch_hears_nothing() {
    type Lose = fn(&Core, Uid, Uid, u32);
    let cases: [(&str, Lose); 4] = [
        ("read_chat taken", |core, _, reader, _| {
            (core.roster.lock().unwrap().users.get_mut(&reader).unwrap()).access =
                bits(&[bit::SEND_CHAT]);
        }),
        ("left the room", |core, _, reader, room| {
            core.room_part(reader, room).unwrap();
        }),
        ("parted by its gate", |core, boss, _, room| {
            let edit = crate::rooms::RoomEdit {
                read: Some(vec!["boss".into()]),
                ..Default::default()
            };
            core.room_edit(boss, room, edit).unwrap();
        }),
        ("the room archived", |core, boss, _, room| {
            core.room_archive(boss, room, true).unwrap();
        }),
    ];
    for (case, lose) in cases {
        let core = Core::new()
            .with_history(
                Arc::new(crate::history::MemoryLog::default()),
                HistoryPolicy::default(),
            )
            .with_reactions(ReactionPolicy::default())
            .with_rooms(
                Arc::new(crate::rooms::MemoryRooms::default()),
                crate::RoomPolicy::default(),
            )
            .unwrap();
        let (boss, _) = hearing(&core, "boss", ng(), false);
        core.roster
            .lock()
            .unwrap()
            .users
            .get_mut(&boss)
            .unwrap()
            .manage_rooms = true;
        let (reader, mut rr) = hearing(&core, "reader", ng(), false);
        // The lobby's case reads the lobby; the rest a room.
        let room = match case {
            "read_chat taken" => 0,
            _ => {
                let edit = crate::rooms::RoomEdit {
                    name: Some("den".into()),
                    ..Default::default()
                };
                let room = core.room_create(boss, edit).unwrap().id;
                core.room_join(boss, room).unwrap();
                core.room_join(reader, room).unwrap();
                room
            }
        };
        let line = core
            .chat_public_all(boss, room, vec![("hi".into(), 0, None)])
            .pop()
            .unwrap()
            .unwrap()
            .unwrap();
        core.react(boss, room, line, &thumbs(), true).unwrap();
        lose(&core, boss, reader, room);
        drain(&mut rr);
        flush(&core);
        let told = drain(&mut rr);
        assert!(
            !told.iter().any(|e| matches!(e, Event::ReactionsChanged(_))),
            "{case}: {told:?}"
        );
    }
}

/// An account's deletion tells the live lines it had reacted to as they
/// now stand.
#[test]
fn an_accounts_deletion_tells_its_live_lines() {
    let (core, _log) = server(ReactionPolicy::default());
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (bob, _) = hearing(&core, "bob", ng(), false);
    let line = said(&core, alice, "one");
    core.react(bob, 0, line, &thumbs(), true).unwrap();
    core.react(alice, 0, line, &party(), true).unwrap();
    flush(&core);
    drain(&mut ra);
    core.inbox_purge(&Mailbox::login("bob"));
    flush(&core);
    assert_eq!(
        batches(&mut ra),
        [vec![(line, Some((vec![(party(), 1)], vec![0])))]]
    );
}

/// A reader that never reads is cut off by what it is owed, each batch
/// weighed for the summaries it carries, long before the queue's count
/// of events would: buffered for a while, never without end.
#[test]
fn a_reader_that_never_reads_is_cut_off_by_the_weight_of_its_batches() {
    let (core, _log) = on_faulty(Arc::new(MemoryModeration::default()));
    let reactors: Vec<Uid> = (0..4)
        .map(|i| hearing(&core, &format!("r{i}"), Transport::default(), false).0)
        .collect();
    let (stuck, _rx): (Uid, Events) = hearing(&core, "stuck", ng(), false);
    let keys: Vec<ReactionKey> = (0..20u32)
        .map(|i| ReactionKey::emoji(&char::from_u32(0x1F600 + i).unwrap().to_string()).unwrap())
        .collect();
    let lines: Vec<LineId> = (0..100)
        .map(|n| said(&core, reactors[0], &format!("l{n}")))
        .collect();
    for &line in &lines {
        for (i, key) in keys.iter().enumerate() {
            core.react(reactors[i / 5], 0, line, key, true).unwrap();
        }
    }
    let mut batches = 0;
    while !core.is_lagging(stuck) && batches < crate::roster::LIVE_QUEUE_CAP {
        for &line in &lines {
            core.react(reactors[0], 0, line, &keys[0], batches % 2 == 1)
                .unwrap();
        }
        flush(&core);
        batches += 1;
    }
    assert!(core.is_lagging(stuck), "never cut off");
    assert!(batches < 1000, "cut off by count, after {batches} batches");
}

/// A rotation moves what waits for the identity and what it reacted,
/// so either is still the account's under its successor.
#[test]
fn waiting_im_reactions_follow_a_rotation_as_recipient_and_reactor() {
    let (core, _log) = server(ReactionPolicy::default());
    let now = core.clock.now();
    let guid = crate::inbox::MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
    let change = |from: &str| ReactionChange::Changed {
        target: Reply::im("bob".into(), guid.clone()).unwrap(),
        key: thumbs(),
        add: true,
        from: from.into(),
    };
    {
        let mut r = core.roster.lock().unwrap();
        let to = Key::of(&Mailbox::identified("bob", [1; 32]));
        let from = Mailbox::identified("alice", [3; 32]);
        let w = Waiting {
            from,
            change: change("alice"),
            at: now,
        };
        r.live.keep(to, w, now);
    }
    core.rotate_identity(&[1; 32], &[2; 32]).unwrap();
    core.rotate_identity(&[3; 32], &[4; 32]).unwrap();
    let r = core.roster.lock().unwrap();
    let queue = r
        .live
        .waiting
        .get(&Key::Identity([2; 32]))
        .expect("moved to the successor");
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].from, Mailbox::identified("alice", [4; 32]));
    assert!(!r.live.waiting.contains_key(&Key::Identity([1; 32])));
}

/// The hourly sweep gives up what has waited past its age, so a party
/// that never comes back holds nothing for ever.
#[test]
fn the_sweep_gives_up_what_waited_too_long() {
    let (core, _log) = server(ReactionPolicy {
        im_keep: Duration::from_secs(60),
        ..ReactionPolicy::default()
    });
    let now = core.clock.now();
    let guid = crate::inbox::MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
    {
        let mut r = core.roster.lock().unwrap();
        let w = Waiting {
            from: Mailbox::login("alice"),
            change: ReactionChange::Changed {
                target: Reply::im("bob".into(), guid).unwrap(),
                key: thumbs(),
                add: true,
                from: "alice".into(),
            },
            at: now,
        };
        r.live.keep(Key::of(&Mailbox::login("bob")), w, now);
    }
    core.reactions_prune();
    assert_eq!(core.roster.lock().unwrap().live.waiting_len, 1, "not yet");
    core.clock.advance(Duration::from_secs(61));
    core.reactions_prune();
    let r = core.roster.lock().unwrap();
    assert!(r.live.waiting.is_empty() && r.live.waiting_len == 0);
}

/// A clear of a line with nothing on it changes nothing and records
/// nothing.
#[test]
fn a_clear_with_nothing_to_take_records_nothing() {
    let moderation = Arc::new(MemoryModeration::default());
    let (core, _log) = on_faulty(moderation.clone());
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "quiet");
    assert_eq!(core.react_clear(carol, 0, line), Ok(()));
    assert!(moderation.acts(None, 10).unwrap().is_empty());
    assert_eq!(core.reactions_flush(core.clock.now()), None);
}
