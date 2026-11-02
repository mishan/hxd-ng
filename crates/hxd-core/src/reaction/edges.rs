//! The paths through the reaction desk and the live announcements that a
//! healthy store and a quiet server never take: store failures, panics,
//! races, the order the locks are taken in, the bounds, and the gates a
//! session can lose between a change and its batch.

use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;

use super::tests::{batches, bits, hearing, ng, party, said, server, thumbs};
use super::*;
use crate::history::faulty::FaultyLog;
use crate::history::{ChatLog, HistoryPolicy};
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

/// Wait until `n` callers wait at the desk: a racer has arrived.
fn arrived(core: &Core, n: usize) {
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while core.desk.waiting() < n {
        assert!(
            std::time::Instant::now() < until,
            "{n} never arrived at the desk"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

/// Let a room's owed batch go: the clock moved past it, and flushed.
fn flush(core: &Core) {
    core.clock.advance(Duration::from_secs(5));
    core.reactions_flush(core.clock.now());
}

/// A batch whose summaries could not be read is owed again, and the
/// next flush tells it whole and in order: a removal as the line then
/// stands, a moderator's clear as cleared.
#[test]
fn a_batch_that_could_not_be_read_goes_in_the_next() {
    type Change = fn(&Core, Uid, Uid, LineId);
    let cases: [(&str, Change, Option<_>); 2] = [
        (
            "removed",
            |core, alice, _, two| {
                core.react(alice, 0, two, &thumbs(), false).unwrap();
            },
            Some((vec![], vec![])),
        ),
        (
            "cleared",
            |core, _, carol, two| core.react_clear(carol, 0, two, "spam").unwrap(),
            None,
        ),
    ];
    for (name, change, told) in cases {
        let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
        let (alice, mut ra) = hearing(&core, "alice", ng(), false);
        let (carol, _) = hearing(&core, "carol", ng(), true);
        let [one, two] = ["one", "two"].map(|t| said(&core, alice, t));
        core.react(alice, 0, two, &thumbs(), true).unwrap();
        flush(&core);
        drain(&mut ra);
        core.react(alice, 0, one, &party(), true).unwrap();
        change(&core, alice, carol, two);
        log.fail("reactions", true);
        flush(&core);
        assert!(batches(&mut ra).is_empty(), "{name}: nothing could be told");
        log.fail("reactions", false);
        flush(&core);
        assert_eq!(
            batches(&mut ra),
            [vec![
                (one, Some((vec![(party(), 1)], vec![0]))),
                (two, told)
            ]],
            "{name}"
        );
    }
}

/// A clear whose act cannot be recorded takes nothing; one recorded and
/// then refused by the log stands in the trail as attempted. Either way
/// the reactions stay and the moderator is told of a server error.
#[test]
fn a_clear_the_stores_refuse_takes_nothing() {
    for (fails, recorded) in [("record", false), ("clear_reactions", true)] {
        let moderation = Arc::new(FaultyModeration::default());
        let (core, log) = on_faulty(moderation.clone());
        let (alice, _) = hearing(&core, "alice", ng(), false);
        let (carol, _) = hearing(&core, "carol", ng(), true);
        let line = said(&core, alice, "one");
        core.react(alice, 0, line, &thumbs(), true).unwrap();
        match fails {
            "record" => moderation.fail("record"),
            _ => log.fail(fails, true),
        }
        assert_eq!(
            core.react_clear(carol, 0, line, "spam"),
            Err(ReactError::ServerError),
            "{fails}"
        );
        let kept = core.line_reactions(alice, &[line]).unwrap();
        assert_eq!(kept[&line].keys, [(thumbs(), 1)], "{fails}");
        let acts = moderation.acts(None, 10).unwrap();
        let act = acts
            .iter()
            .any(|a| a.kind == crate::ActKind::ReactionsClear);
        assert_eq!(act, recorded, "{fails}");
    }
}

/// A reaction applied as its line is redacted is never told after the
/// redaction as anything but cleared: the redaction waits at the desk
/// behind it, and its clear stands.
#[test]
fn a_reaction_racing_a_redaction_is_told_after_it_as_cleared() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "regrettable");
    drain(&mut ra);
    let at = Arc::new(Barrier::new(2));
    log.park_after("react_all", at.clone());
    let reacting = {
        let core = core.clone();
        thread::spawn(move || core.react(alice, 0, line, &thumbs(), true))
    };
    at.wait();
    let redacting = {
        let core = core.clone();
        thread::spawn(move || core.redact_line(crate::Actor::Session(carol), line, "no"))
    };
    arrived(&core, 1);
    at.wait();
    reacting.join().unwrap().unwrap();
    redacting.join().unwrap().unwrap();
    flush(&core);
    assert_nothing_but_clears_after_the_redaction(&drain(&mut ra), line);
}

/// After `line`'s redaction, `told` holds no summary of it.
fn assert_nothing_but_clears_after_the_redaction(told: &[Event], line: LineId) {
    let redacted = (told.iter())
        .position(|e| matches!(e, Event::ChatRedacted { id } if *id == line))
        .expect("the redaction is told");
    for e in &told[redacted..] {
        if let Event::ReactionsChanged(changes) = e {
            for c in changes {
                if let ReactionChange::Summary {
                    target: Reply::Line { id, .. },
                    ..
                } = c
                {
                    assert_ne!(*id, line, "a summary after the redaction: {told:?}");
                }
            }
        }
    }
}

/// A batch read while its line is redacted goes before the redaction,
/// under the room's serial, and the redaction's clear after it.
#[test]
fn a_batch_taken_as_its_line_is_redacted_goes_before_the_redaction() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "regrettable");
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    drain(&mut ra);
    core.clock.advance(Duration::from_secs(5));
    let at = Arc::new(Barrier::new(2));
    log.park_after("reactions", at.clone());
    let flushing = {
        let core = core.clone();
        thread::spawn(move || core.reactions_flush(core.clock.now()))
    };
    at.wait();
    let redacting = {
        let core = core.clone();
        thread::spawn(move || core.redact_line(crate::Actor::Session(carol), line, "no"))
    };
    // The redaction waits on the room's serial, which the desk does not
    // count; long enough for it to have reached it.
    thread::sleep(Duration::from_millis(100));
    at.wait();
    flushing.join().unwrap();
    redacting.join().unwrap().unwrap();
    flush(&core);
    let told = drain(&mut ra);
    assert_nothing_but_clears_after_the_redaction(&told, line);
    assert!(told.iter().any(|e| matches!(e, Event::ReactionsChanged(_))));
}

/// A redaction made while a clear is under way waits for it: the clear
/// takes what it recorded and answers so, and the line is a tombstone
/// after.
#[test]
fn a_redaction_during_a_clear_waits_for_it() {
    let moderation = Arc::new(MemoryModeration::default());
    let (core, log) = on_faulty(moderation.clone());
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "vote");
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    let at = Arc::new(Barrier::new(2));
    log.park_after("reactions", at.clone());
    let clearing = {
        let core = core.clone();
        thread::spawn(move || core.react_clear(carol, 0, line, "spam"))
    };
    at.wait();
    let redacting = {
        let core = core.clone();
        thread::spawn(move || core.redact_line(crate::Actor::Session(carol), line, "no"))
    };
    arrived(&core, 1);
    at.wait();
    assert_eq!(clearing.join().unwrap(), Ok(()));
    redacting.join().unwrap().unwrap();
    let after = log.inner.line(line).unwrap().unwrap();
    assert!(after.flags.contains(crate::history::LineFlags::DELETED));
}

/// A reaction made as a clear finishes is told as it stands after both,
/// never as the line emptied.
#[test]
fn a_reaction_just_after_a_clear_is_told_as_it_stands() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "vote");
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    flush(&core);
    drain(&mut ra);
    let at = Arc::new(Barrier::new(2));
    log.park_after("clear_reactions", at.clone());
    let clearing = {
        let core = core.clone();
        thread::spawn(move || core.react_clear(carol, 0, line, "spam"))
    };
    at.wait();
    let reacting = {
        let core = core.clone();
        thread::spawn(move || core.react(alice, 0, line, &party(), true))
    };
    arrived(&core, 1);
    at.wait();
    clearing.join().unwrap().unwrap();
    reacting.join().unwrap().unwrap();
    flush(&core);
    assert_eq!(
        batches(&mut ra),
        [vec![(line, Some((vec![(party(), 1)], vec![0])))]]
    );
}

/// A redaction that cannot read which of its lines had reactions tells
/// each as cleared, rather than leaving a reacted line uncleared.
#[test]
fn a_redaction_that_cannot_read_reactions_clears_its_lines() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "one");
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    flush(&core);
    drain(&mut ra);
    log.fail("reactions", true);
    core.redact_line(crate::Actor::Session(carol), line, "no")
        .unwrap();
    log.fail("reactions", false);
    flush(&core);
    assert_eq!(batches(&mut ra), [vec![(line, None)]]);
}

/// A batch owed while the last was being taken and sent is due a whole
/// batch after that one went, however long it took.
#[test]
fn a_batch_owed_while_the_last_went_is_due_a_batch_after_it() {
    let mut live = Live {
        window: 10,
        batch: Duration::from_secs(1),
        ..Live::default()
    };
    live.relayed(0, 1);
    let t = Instant::now();
    live.owe(1, Owe::Summary, t);
    live.sent(0, t + Duration::from_secs(3));
    assert!(live.owed[&0].due >= t + Duration::from_secs(4));
}

/// The lines a room owes stay within its live window between batches:
/// one the window moved past owes nothing.
#[test]
fn the_owed_lines_stay_within_the_window() {
    let (core, _log) = server(ReactionPolicy {
        live_window: 2,
        ..ReactionPolicy::default()
    });
    let (alice, _rx) = hearing(&core, "alice", ng(), false);
    let lines = [said(&core, alice, "a"), said(&core, alice, "b")];
    for line in lines {
        core.react(alice, 0, line, &thumbs(), true).unwrap();
    }
    for t in ["c", "d", "e"] {
        said(&core, alice, t);
    }
    // Whatever was posted is applied by the next op at the desk.
    core.desk(|_, _| ());
    let owed = core.desk.live().owed.get(&0).map_or(0, |o| o.lines.len());
    assert_eq!(owed, 0);
}

/// What one leader finds queued behind it goes to the log in one
/// transaction.
#[test]
fn reactions_queued_together_go_to_the_log_together() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let people: Vec<Uid> = (0..5)
        .map(|i| hearing(&core, &format!("p{i}"), ng(), false).0)
        .collect();
    let line = said(&core, people[0], "busy");
    let at = Arc::new(Barrier::new(2));
    log.park_after("react_all", at.clone());
    let react = |who: Uid| {
        let core = core.clone();
        thread::spawn(move || core.react(who, 0, line, &thumbs(), true))
    };
    let first = react(people[0]);
    at.wait();
    let rest: Vec<_> = people[1..].iter().map(|&p| react(p)).collect();
    arrived(&core, 4);
    at.wait();
    first.join().unwrap().unwrap();
    for r in rest {
        r.join().unwrap().unwrap();
    }
    assert_eq!(*log.runs.lock().unwrap(), [1, 4]);
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
        thread::spawn(move || core.react_clear(carol, 0, line, "spam"))
    };
    at.wait();
    let reacting = {
        let core = core.clone();
        thread::spawn(move || core.react(bob, 0, line, &party(), true))
    };
    arrived(&core, 1);
    at.wait();
    clearing.join().unwrap().unwrap();
    reacting.join().unwrap().unwrap();
    let act = (moderation.acts(None, 10).unwrap().into_iter())
        .find(|a| a.kind == crate::ActKind::ReactionsClear)
        .unwrap();
    assert_eq!(act.evidence.as_deref(), Some(&*format!("#{line}: 👍 1")));
    let kept = core.line_reactions(alice, &[line]).unwrap();
    assert_eq!(kept[&line].keys, [(party(), 1)], "made after the clear");
}

/// Every caller of the desk at once: lines said, which tell it from
/// under the roster; redactions, which wait on it holding a room's
/// serial; batches, taken and sent under the serial; reactions, rekeys
/// and clears. All of them finish.
#[test]
fn reactions_redactions_and_rekeys_together_finish() {
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
        Box::new(move |c| {
            let said = said(c, alice, "and gone");
            let _ = c.react(alice, 0, said, &party(), true);
            c.redact_line(crate::Actor::Session(carol), said, "no")
                .unwrap();
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
            let _ = c.react_clear(carol, 0, line, "spam");
        }),
    ];
    let n = work.len();
    for w in work {
        let (core, done) = (core.clone(), done.clone());
        thread::spawn(move || {
            for _ in 0..300 {
                w(&core);
            }
            let _ = done.send(());
        });
    }
    for _ in 0..n {
        finished
            .recv_timeout(Duration::from_secs(60))
            .expect("the reaction locks deadlocked");
    }
}

/// Starts a run of reactions behind one the desk's leader is parked
/// inside: `parked` runs once it is, `go` queues each, and once all have
/// arrived the leader goes on, and the queued ones go to the log
/// together.
fn queued_together(
    core: &Arc<Core>,
    log: &FaultyLog,
    (leader, line): (Uid, LineId),
    parked: impl FnOnce(),
    go: Vec<Box<dyn FnOnce() + Send>>,
) {
    let at = Arc::new(Barrier::new(2));
    log.park_after("react_all", at.clone());
    let leading = {
        let core = core.clone();
        thread::spawn(move || core.react(leader, 0, line, &thumbs(), true))
    };
    at.wait();
    parked();
    let n = go.len();
    let queued: Vec<_> = go.into_iter().map(thread::spawn).collect();
    arrived(core, n);
    at.wait();
    leading.join().unwrap().unwrap();
    for q in queued {
        let _ = q.join();
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

/// A clear of a line with nothing on it changes nothing and records
/// nothing.
#[test]
fn a_clear_with_nothing_to_take_records_nothing() {
    let moderation = Arc::new(MemoryModeration::default());
    let (core, _log) = on_faulty(moderation.clone());
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "quiet");
    assert_eq!(core.react_clear(carol, 0, line, "spam"), Ok(()));
    assert!(moderation.acts(None, 10).unwrap().is_empty());
    assert_eq!(core.reactions_flush(core.clock.now()), None);
}

/// A run whose one transaction fails is applied again an act at a time,
/// so each answers for itself: one applied, one of a line no longer
/// there refused.
#[test]
fn a_run_that_fails_together_is_tried_alone() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let [first, kept, gone] = ["first", "kept", "gone"].map(|t| said(&core, alice, t));
    core.redact_line(crate::Actor::Session(carol), gone, "no")
        .unwrap();
    let (answers, heard) = mpsc::channel();
    let react = |line: LineId| -> Box<dyn FnOnce() + Send> {
        let (core, answers) = (core.clone(), answers.clone());
        Box::new(move || {
            let _ = answers.send((line, core.react(alice, 0, line, &party(), true)));
        })
    };
    let go = vec![react(kept), react(gone)];
    let fail = || log.fail("react_all", true);
    queued_together(&core, &log, (alice, first), fail, go);
    let mut got: Vec<_> = heard.try_iter().collect();
    got.sort_by_key(|(line, _)| *line);
    assert_eq!(got, [(kept, Ok(1)), (gone, Err(ReactError::NoSuchTarget))]);
    assert_eq!(
        *log.runs.lock().unwrap(),
        [1],
        "only the leader's got through"
    );
}

/// A reaction whose log panics in a run is that reaction's panic: the
/// run is tried alone, and the reaction beside it applied.
#[test]
fn a_panic_under_one_reaction_of_a_run_is_its_own() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let [first, fine, bad] = ["first", "fine", "bad"].map(|t| said(&core, alice, t));
    let (answers, heard) = mpsc::channel();
    let react = |line: LineId| -> Box<dyn FnOnce() + Send> {
        let (core, answers) = (core.clone(), answers.clone());
        Box::new(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                core.react(alice, 0, line, &party(), true)
            }));
            let _ = answers.send((line, r.ok()));
        })
    };
    log.panic_on(bad);
    queued_together(
        &core,
        &log,
        (alice, first),
        || (),
        vec![react(fine), react(bad)],
    );
    let mut got: Vec<_> = heard.try_iter().collect();
    got.sort_by_key(|(line, _)| *line);
    assert_eq!(got, [(fine, Some(Ok(1))), (bad, None)]);
}

/// An op that panics in a run another caller leads is its own caller's
/// panic: the leader's op is answered, and the desk goes on.
#[test]
fn a_panic_in_an_op_behind_the_leader_is_its_own() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let first = said(&core, alice, "first");
    let at = Arc::new(Barrier::new(2));
    log.park_after("react_all", at.clone());
    let parked = {
        let core = core.clone();
        thread::spawn(move || core.react(alice, 0, first, &thumbs(), true))
    };
    at.wait();
    // The next run: an op that leads it, then one that panics.
    let leading = {
        let core = core.clone();
        thread::spawn(move || core.desk(|_, _| 7))
    };
    arrived(&core, 1);
    let panicking = {
        let core = core.clone();
        thread::spawn(move || {
            core.desk(|_, _| -> u8 { panic!("an op panicked, as the test asked") })
        })
    };
    arrived(&core, 2);
    at.wait();
    parked.join().unwrap().unwrap();
    assert_eq!(leading.join().unwrap(), 7);
    assert!(panicking.join().is_err());
    assert_eq!(core.desk(|_, _| 8), 8);
}

/// A tombstone that panics answers the redaction an error, not a panic
/// under the room's serial, which stays usable.
#[test]
fn a_panic_under_a_redaction_is_an_error() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "regrettable");
    log.panic_on(line);
    assert!(core
        .redact_line(crate::Actor::Session(carol), line, "no")
        .is_err());
    let next = said(&core, alice, "and on");
    assert!(core
        .redact_line(crate::Actor::Session(carol), next, "no")
        .is_ok());
}

/// A panic in the log under a run answers its caller as a panic, and the
/// desk goes on.
#[test]
fn a_panic_in_the_log_does_not_stop_the_desk() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let line = said(&core, alice, "one");
    log.panic_on(line);
    let c = core.clone();
    let reacted = thread::spawn(move || c.react(alice, 0, line, &thumbs(), true)).join();
    assert!(reacted.is_err(), "the react panicked");
    let (tx, rx) = mpsc::channel();
    let c = core.clone();
    thread::spawn(move || {
        c.desk(|_, _| ());
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("the desk stopped after a panic");
    let other = said(&core, alice, "two");
    assert_eq!(core.react(alice, 0, other, &thumbs(), true), Ok(1));
}

/// Lines relayed with nobody reacting wait for the desk no more than a
/// room's live window of them, however many there are.
#[test]
fn relayed_lines_wait_for_the_desk_within_the_window() {
    let (core, _log) = server(ReactionPolicy {
        live_window: 50,
        ..ReactionPolicy::default()
    });
    let (alice, _rx) = hearing(&core, "alice", ng(), false);
    for n in 0..300 {
        said(&core, alice, &format!("l{n}"));
    }
    assert_eq!(core.desk.backlog(), (0, 50));
}

/// A line reacted to and unreacted within one batch, then redacted, is
/// told after the redaction as nothing at all, not as a summary of none.
#[test]
fn a_redacted_line_whose_reactions_came_and_went_is_told_nothing_after() {
    let (core, _log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, mut ra) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "regrettable");
    drain(&mut ra);
    core.react(alice, 0, line, &thumbs(), true).unwrap();
    core.react(alice, 0, line, &thumbs(), false).unwrap();
    core.redact_line(crate::Actor::Session(carol), line, "no")
        .unwrap();
    flush(&core);
    assert_nothing_but_clears_after_the_redaction(&drain(&mut ra), line);
}

/// A redaction waits on the desk holding its room's serial and nothing
/// more: an op that takes the roster, ahead of it at the desk, finishes,
/// as it would not if the redaction held the roster while it waited.
/// Whatever leads the desk meanwhile, a reaction or a clear.
#[test]
fn a_redaction_waits_on_the_desk_without_the_roster() {
    for leads in ["react_all", "reactions"] {
        waits_without_the_roster(leads);
    }
}

fn waits_without_the_roster(parked_in: &'static str) {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "one");
    let gone = said(&core, alice, "two");
    if parked_in == "reactions" {
        core.react(alice, 0, line, &thumbs(), true).unwrap();
    }
    let at = Arc::new(Barrier::new(2));
    log.park_after(parked_in, at.clone());
    let leading = {
        let core = core.clone();
        thread::spawn(move || match parked_in {
            "reactions" => core.react_clear(carol, 0, line, "spam"),
            _ => core.react(alice, 0, line, &thumbs(), true).map(drop),
        })
    };
    at.wait();
    let (done, finished) = mpsc::channel();
    let rostering = {
        let (core, done) = (core.clone(), done.clone());
        thread::spawn(move || {
            core.desk(|c, _| drop(c.roster.lock().unwrap()));
            let _ = done.send(());
        })
    };
    arrived(&core, 1);
    let redacting = {
        let core = core.clone();
        thread::spawn(move || {
            core.redact_line(crate::Actor::Session(carol), gone, "no")
                .unwrap();
            let _ = done.send(());
        })
    };
    arrived(&core, 2);
    at.wait();
    leading.join().unwrap().unwrap();
    for _ in 0..2 {
        finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the desk and the roster deadlocked");
    }
    rostering.join().unwrap();
    redacting.join().unwrap();
}
