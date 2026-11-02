//! The paths through the reaction desk that a healthy store and a quiet
//! server never take: store failures, panics, races, and the order its
//! locks are taken in.

use std::sync::mpsc;
use std::sync::{Arc, Barrier};
use std::thread;

use super::tests::{hearing, ng, party, said, thumbs};
use super::*;
use crate::history::faulty::FaultyLog;
use crate::history::HistoryPolicy;
use crate::{MemoryModeration, ModerationPolicy, ModerationStore};

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

/// Every caller of the desk at once: redactions, which wait on it
/// holding a room's serial; reactions and rekeys. All of them finish.
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

/// A redaction waits on the desk holding its room's serial and nothing
/// more: an op that takes the roster, ahead of it at the desk, finishes,
/// as it would not if the redaction held the roster while it waited.
#[test]
fn a_redaction_waits_on_the_desk_without_the_roster() {
    let (core, log) = on_faulty(Arc::new(MemoryModeration::default()));
    let (alice, _) = hearing(&core, "alice", ng(), false);
    let (carol, _) = hearing(&core, "carol", ng(), true);
    let line = said(&core, alice, "one");
    let gone = said(&core, alice, "two");
    let at = Arc::new(Barrier::new(2));
    log.park_after("react_all", at.clone());
    let reacting = {
        let core = core.clone();
        thread::spawn(move || core.react(alice, 0, line, &thumbs(), true))
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
    reacting.join().unwrap().unwrap();
    for _ in 0..2 {
        finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the desk and the roster deadlocked");
    }
    rostering.join().unwrap();
    redacting.join().unwrap();
}
