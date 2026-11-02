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
//! react_all`, all or none); if that transaction fails or panics, each is
//! tried again alone, so one bad act fails itself and not its neighbors.
//! Every other op is its own step, in queue order.
//!
//! The order locks are taken in: a room's serial, then the desk (waiting
//! on an op, or leading), then the roster, then a store. Nothing waits on
//! the desk while it holds the roster; an op never takes a serial nor
//! waits on the desk itself; and ops are short, because a waiter may hold
//! a room's serial, so a long piece of work is many ops.
//!
//! A panic in an op, or in the log under one, answers that op's caller
//! as a panic and nobody else's: the run goes on, the lead is handed on.
//! An op whose caller may hold a room's serial answers a panic as an
//! error instead ([`Core::desk_caught`]), so the serial is not poisoned.

use std::any::Any;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::SystemTime;

use super::{Live, ReactAct, Reacted, ReactionKey};
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
    pub(super) live: Mutex<Live>,
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
    pub(super) fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many callers wait at the desk, for a test to know its racer
    /// has arrived.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.state.lock().unwrap().queue.len()
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

    /// [`Core::desk`] for a caller that may hold a room's serial: a panic
    /// in `f` is answered `None` rather than raised.
    pub(crate) fn desk_caught<R: Send + 'static>(
        &self,
        f: impl FnOnce(&Core, &mut Live) -> R + Send + 'static,
    ) -> Option<R> {
        let work: Work = Box::new(move |c, l| Box::new(f(c, l)));
        self.desk_submit(Op::Work(work))
            .downcast::<R>()
            .ok()
            .map(|r| *r)
    }

    /// One reaction to the log, in a run's one transaction.
    pub(crate) fn desk_react(&self, act: Act) -> Result<Reacted, StoreError> {
        match self.desk_submit(Op::React(act)).downcast() {
            Ok(r) => *r,
            Err(_) => panic!("a reaction desk op panicked"),
        }
    }

    fn desk_submit(&self, op: Op) -> Box<dyn Any + Send> {
        let me = Arc::new(Ticket {
            op: Mutex::new(Some(op)),
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

    /// Apply runs until `me`'s op is answered, then hand the lead on:
    /// `me`'s answer.
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
                } else {
                    t.set(Slot::Done(answer));
                }
            }
            if mine.is_none() {
                continue;
            }
            let mut st = self.desk.state.lock().unwrap();
            match st.queue.front() {
                Some(next) => next.set(Slot::Lead),
                None => st.leading = false,
            }
            break;
        }
        mine.expect("the leader's op is in a run it applied")
    }

    /// Apply a run in order: its reactions together in one transaction
    /// where they come together, every other op as itself.
    fn desk_apply(&self, run: &[Arc<Ticket>]) -> Vec<Box<dyn Any + Send>> {
        let mut live = self.desk.live();
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
                    answers.extend(self.desk_react_all(&acts));
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

    /// A run's reactions, answered each: together in one transaction, or
    /// where that fails or panics, each again alone, so one act's error or
    /// panic is its own.
    fn desk_react_all(&self, acts: &[Act]) -> Vec<Box<dyn Any + Send>> {
        let Some(log) = self.history.as_ref() else {
            return (acts.iter())
                .map(|_| boxed(Err(StoreError::new("no chat log"))))
                .collect();
        };
        let borrowed: Vec<ReactAct<'_>> = acts.iter().map(Act::borrowed).collect();
        let together =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| log.react_all(&borrowed)));
        match together {
            Ok(Ok(all)) => return all.into_iter().map(|r| boxed(Ok(r))).collect(),
            Ok(Err(e)) => tracing::warn!(
                "chat log would not take {} reactions together: {e}",
                acts.len()
            ),
            Err(_) => tracing::warn!("chat log panicked under {} reactions together", acts.len()),
        }
        (borrowed.iter())
            .map(|a| {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| log.react(a)))
                    .map_or_else(|_| panicked(), boxed)
            })
            .collect()
    }
}
