//! The reaction desk: the one place reaction state changes.
//!
//! Every write to the log's reactions and every change to [`Live`] is an
//! op queued here and applied in order by whichever caller finds no op
//! being applied, as public chat is committed (`chat::ChatCommit`): no
//! thread of its own. The caller that leads takes what is queued, applies
//! it, answers each op's caller, and hands the lead to the next caller
//! waiting, so one busy caller cannot keep it.
//!
//! A run's reactions go to the log in one transaction (`ChatLog::
//! react_all`); if that transaction fails, each is tried again alone, so
//! one bad act fails itself and not its neighbors. Every other op is its
//! own step, in queue order.
//!
//! The order locks are taken in: a room's serial, then the desk (waiting
//! on an op, or leading), then the roster, then a store. Nothing waits on
//! the desk while it holds the roster; an op never takes a serial nor
//! waits on the desk itself; and ops are short, because a waiter may hold
//! a room's serial, so a long piece of work is many ops. What a caller
//! holding the roster must tell the desk is never waited on: a relayed
//! line goes to a buffer of each room's newest, at most its live window,
//! which the next run takes first, and a room archived is posted as an op
//! for the next leader.
//!
//! A panic in an op, or in the log under one, answers that op's caller
//! as a panic and nobody else's: the run goes on, the lead is handed on.

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::SystemTime;

use super::{Live, Owe, ReactAct, Reacted, ReactionKey};
use crate::history::LineId;
use crate::inbox::{Mailbox, StoreError};
use crate::Core;

/// The most ops one leader applies before it hands the lead on.
const RUN: usize = 256;

/// One reaction, owned, as it waits for the log.
pub(crate) struct Act {
    pub(crate) channel: u32,
    pub(crate) line: LineId,
    pub(crate) who: Mailbox,
    pub(crate) nick: String,
    pub(crate) key: ReactionKey,
    pub(crate) add: bool,
    pub(crate) at: SystemTime,
    pub(crate) max_keys: usize,
    pub(crate) max_per_user: usize,
}

impl Act {
    fn borrowed(&self) -> ReactAct<'_> {
        ReactAct {
            channel: self.channel,
            line: self.line,
            who: &self.who,
            nick: &self.nick,
            key: &self.key,
            add: self.add,
            at: self.at,
            max_keys: self.max_keys,
            max_per_user: self.max_per_user,
        }
    }
}

type Work = Box<dyn FnOnce(&Core, &mut Live) -> Box<dyn Any + Send> + Send>;

enum Op {
    React(Act),
    Work(Work),
}

enum Slot {
    Waiting,
    /// This op's caller leads the next run.
    Lead,
    Done(Box<dyn Any + Send>),
}

struct Ticket {
    op: Mutex<Option<Op>>,
    /// Someone waits on its answer; a posted op is answered to nobody
    /// and never leads.
    waited: bool,
    slot: Mutex<Slot>,
    ready: Condvar,
}

impl Ticket {
    fn set(&self, slot: Slot) {
        *self.slot.lock().unwrap() = slot;
        self.ready.notify_one();
    }
}

#[derive(Default)]
struct State {
    queue: VecDeque<Arc<Ticket>>,
    leading: bool,
}

#[derive(Default)]
pub(crate) struct Desk {
    state: Mutex<State>,
    /// Held by the leader alone while it applies a run.
    pub(crate) live: Mutex<Live>,
    /// Lines relayed since the last run, each room's newest, at most its
    /// live window: what the next run takes first.
    relayed: Mutex<HashMap<u32, VecDeque<LineId>>>,
}

/// An op that panicked, answered to its caller as that.
struct Panicked;

fn panicked() -> Box<dyn Any + Send> {
    Box::new(Panicked)
}

fn boxed(r: Result<Reacted, StoreError>) -> Box<dyn Any + Send> {
    Box::new(r)
}

impl Desk {
    pub(crate) fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `id` was relayed in `room`, told from under the roster: kept for
    /// the next run, no more of a room's than its window holds.
    pub(crate) fn relayed(&self, room: u32, id: LineId, window: usize) {
        let mut relayed = self.relayed.lock().unwrap_or_else(|e| e.into_inner());
        let ring = relayed.entry(room).or_default();
        ring.push_back(id);
        while ring.len() > window {
            ring.pop_front();
        }
    }

    /// How many callers wait at the desk, for a test to know its racer
    /// has arrived.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        let st = self.state.lock().unwrap();
        st.queue.iter().filter(|t| t.waited).count()
    }

    /// The tickets queued and the lines relayed and not yet taken.
    #[cfg(test)]
    pub(crate) fn backlog(&self) -> (usize, usize) {
        let queued = self.state.lock().unwrap().queue.len();
        let relayed = self.relayed.lock().unwrap();
        (queued, relayed.values().map(VecDeque::len).sum())
    }
}

impl Core {
    /// Apply `f` at the desk, in order with every other op, and answer
    /// what it does. Never called holding the roster's lock.
    pub(crate) fn desk<R: Send + 'static>(
        &self,
        f: impl FnOnce(&Core, &mut Live) -> R + Send + 'static,
    ) -> R {
        let work: Work = Box::new(move |c, l| Box::new(f(c, l)));
        match self.desk_submit(Op::Work(work)).downcast::<R>() {
            Ok(r) => *r,
            Err(_) => panic!("a reaction desk op panicked"),
        }
    }

    /// Queue `f` for the desk's next leader and go on: for a caller that
    /// holds the roster, which may not wait on the desk.
    pub(crate) fn desk_post(&self, f: impl FnOnce(&Core, &mut Live) + Send + 'static) {
        let work: Work = Box::new(move |c, l| {
            f(c, l);
            Box::new(())
        });
        let ticket = Arc::new(Ticket {
            op: Mutex::new(Some(Op::Work(work))),
            waited: false,
            slot: Mutex::new(Slot::Waiting),
            ready: Condvar::new(),
        });
        self.desk.state.lock().unwrap().queue.push_back(ticket);
    }

    /// One reaction to the log, in a run's one transaction, and the line
    /// owed a summary where it changed.
    pub(crate) fn desk_react(&self, act: Act) -> Result<Reacted, StoreError> {
        match self.desk_submit(Op::React(act)).downcast() {
            Ok(r) => *r,
            Err(_) => panic!("a reaction desk op panicked"),
        }
    }

    fn desk_submit(&self, op: Op) -> Box<dyn Any + Send> {
        let me = Arc::new(Ticket {
            op: Mutex::new(Some(op)),
            waited: true,
            slot: Mutex::new(Slot::Waiting),
            ready: Condvar::new(),
        });
        let lead = {
            let mut st = self.desk.state.lock().unwrap();
            st.queue.push_back(me.clone());
            !std::mem::replace(&mut st.leading, true)
        };
        if lead {
            me.set(Slot::Lead);
        }
        let mut slot = me.slot.lock().unwrap();
        loop {
            match std::mem::replace(&mut *slot, Slot::Waiting) {
                Slot::Waiting => slot = me.ready.wait(slot).unwrap(),
                Slot::Done(answer) => return answer,
                Slot::Lead => {
                    drop(slot);
                    return self.desk_lead(&me);
                }
            }
        }
    }

    /// Apply runs until `me`'s op is answered and nobody else is waiting
    /// behind ops only posted, then hand the lead on: `me`'s answer.
    fn desk_lead(&self, me: &Arc<Ticket>) -> Box<dyn Any + Send> {
        let mut mine = None;
        loop {
            let run: Vec<Arc<Ticket>> = {
                let mut st = self.desk.state.lock().unwrap();
                let n = st.queue.len().min(RUN);
                st.queue.drain(..n).collect()
            };
            // Whatever an op or the log under it does, every caller in the
            // run is answered and the lead goes on.
            let answers =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.desk_apply(&run)))
                    .unwrap_or_else(|_| run.iter().map(|_| panicked()).collect());
            for (t, answer) in run.iter().zip(answers) {
                if Arc::ptr_eq(t, me) {
                    mine = Some(answer);
                } else if t.waited {
                    t.set(Slot::Done(answer));
                }
            }
            let mut st = self.desk.state.lock().unwrap();
            let next = st.queue.iter().find(|t| t.waited).cloned();
            match (next, &mine, st.queue.is_empty()) {
                // Another caller waits: it leads, posted ops before it
                // in its run.
                (Some(next), Some(_), _) => {
                    next.set(Slot::Lead);
                    break;
                }
                (None, Some(_), true) => {
                    st.leading = false;
                    break;
                }
                // Mine is not answered yet, or only posted ops are
                // left, which nobody else would apply.
                _ => {}
            }
        }
        mine.expect("the leader's op is in a run it applied")
    }

    /// Apply a run in order: its reactions together in one transaction
    /// where they come together, every other op as itself.
    fn desk_apply(&self, run: &[Arc<Ticket>]) -> Vec<Box<dyn Any + Send>> {
        let mut live = self.desk.live();
        let relayed =
            std::mem::take(&mut *self.desk.relayed.lock().unwrap_or_else(|e| e.into_inner()));
        for (room, ids) in relayed {
            for id in ids {
                live.relayed(room, id);
            }
        }
        let mut answers: Vec<Box<dyn Any + Send>> = Vec::with_capacity(run.len());
        let ops: Vec<Op> = run
            .iter()
            .map(|t| t.op.lock().unwrap().take().expect("an op is applied once"))
            .collect();
        let mut ops = ops.into_iter().peekable();
        while let Some(op) = ops.next() {
            match op {
                Op::React(first) => {
                    let mut acts = vec![first];
                    while let Some(Op::React(_)) = ops.peek() {
                        if let Some(Op::React(a)) = ops.next() {
                            acts.push(a);
                        }
                    }
                    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.desk_react_all(&mut live, &acts)
                    }));
                    match done {
                        Ok(results) => answers.extend(results.into_iter().map(boxed)),
                        Err(_) => answers.extend(acts.iter().map(|_| panicked())),
                    }
                }
                Op::Work(work) => {
                    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        work(self, &mut live)
                    }));
                    answers.push(done.unwrap_or_else(|_| panicked()));
                }
            }
        }
        answers
    }

    fn desk_react_all(&self, live: &mut Live, acts: &[Act]) -> Vec<Result<Reacted, StoreError>> {
        let Some(log) = self.history.as_ref() else {
            return acts
                .iter()
                .map(|_| Err(StoreError::new("no chat log")))
                .collect();
        };
        let borrowed: Vec<ReactAct<'_>> = acts.iter().map(Act::borrowed).collect();
        let (results, retried) = match log.react_all(&borrowed) {
            Ok(all) => (all.into_iter().map(Ok).collect(), false),
            // One act's failure is its own: each again, alone.
            Err(_) => (
                borrowed.iter().map(|a| log.react(a)).collect::<Vec<_>>(),
                true,
            ),
        };
        let now = self.clock.now();
        for (act, r) in acts.iter().zip(&results) {
            // A store that applied some before it failed answers those
            // again as held: their lines changed all the same.
            if matches!(r, Ok(Reacted::Count(_))) || (retried && r.is_ok()) {
                live.owe(act.line, Owe::Summary, now);
            }
        }
        results
    }
}
