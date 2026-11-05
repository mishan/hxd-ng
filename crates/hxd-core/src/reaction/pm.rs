//! Reactions on a stored private message (`docs/hotline-ng.md` §7.3,
//! `docs/private-messages.md` §5): kept by the inbox store, seen by each
//! party on its own side's terms, and changed under `Core::pm_reacting`
//! rather than at the desk, which keeps the log's.

use std::collections::HashMap;
use std::time::SystemTime;

use super::{
    reactor_key, MessageReactAct, MessageReacted, MessageState, ReactError, ReactionChange,
    ReactionKey, Reactions,
};
use crate::access::bit;
use crate::inbox::{Mailbox, MessageRef, StoreError};
use crate::reply::Reply;
use crate::roster::{Event, Uid, UserSession};
use crate::Core;

/// The most messages one announcement event names.
const PM_TOLD: usize = 50;

impl Core {
    /// `uid`'s account adds (`add`) or removes `key` on the stored
    /// private message `reference` names, answered once it is applied.
    ///
    /// Past who may react and the rate, every outcome but a store's
    /// failure is `Ok`: a message that is not the caller's on its side's
    /// terms, one either party has blocked the other over, and a cap are
    /// dropped and answered as an applied reaction is, so that nothing
    /// tells a sender whether its message was read.
    pub fn react_pm(
        &self,
        uid: Uid,
        reference: MessageRef,
        key: &ReactionKey,
        add: bool,
    ) -> Result<(), ReactError> {
        let policy = self.reaction_policy().ok_or(ReactError::NotAvailable)?;
        let store = self.inbox.as_ref().ok_or(ReactError::NotAvailable)?;
        let (who, nick) = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(ReactError::NotAllowed)?;
            // The store counts a shared `guest` mailbox and an identity
            // guest's sent mail as parties: this is what keeps them out.
            if !sess.is_person || sess.info.system || !sess.access.has(bit::SEND_CHAT) {
                return Err(ReactError::NotAllowed);
            }
            (sess.mailbox(), sess.info.nick.clone())
        };
        self.react_rate(uid, policy)?;
        let failed = |e: StoreError| {
            tracing::warn!("inbox would not take a reaction: {e}");
            ReactError::ServerError
        };
        let open_since = self.pm_open_since();
        let parties = store.message_party(&reference, &who, open_since);
        let Some(parties) = parties.map_err(failed)? else {
            return Ok(());
        };
        let recipient = &parties.recipient;
        let other = match who.matches(&recipient.login, recipient.fingerprint.as_ref()) {
            true => parties.sender,
            false => Some(parties.recipient),
        };
        // Outside any lock, as delivery reads them: a block placed
        // between here and the write is raced as a message is.
        if let (Some(rel), Some(other)) = (self.relationships.as_ref(), other) {
            if rel.is_blocked(&who, &other).map_err(failed)?
                || rel.is_blocked(&other, &who).map_err(failed)?
            {
                return Ok(());
            }
        }
        let _reacting = self.pm_reacting.lock().unwrap_or_else(|e| e.into_inner());
        let reacted = store
            .react_message(&MessageReactAct {
                reference,
                who: &who,
                nick: &nick,
                key,
                add,
                at: self.clock.wall(),
                open_since,
                max_keys: policy.max_keys,
                max_per_user: policy.max_per_user,
            })
            .map_err(failed)?;
        // Still under the mutex, so one message's summaries reach a
        // session in the order they were applied.
        if let MessageReacted::Applied(state) = reacted {
            self.pm_tell(&[*state], open_since, Some(uid));
        }
        Ok(())
    }

    /// Tell the newest of `refs`, at most a live window of them and
    /// [`PM_TOLD`] to an event, to whoever hears each as it now stands,
    /// for a change no session made, under the caller's hold of
    /// `pm_reacting`. The rest are left for `inbox` and `reactions` to
    /// show, as a line outside a room's live window is, so that no one
    /// change fills a session's queue.
    pub(crate) fn pm_announce(&self, refs: &[MessageRef]) {
        let (Some(policy), Some(store)) = (self.reaction_policy(), self.inbox.as_ref()) else {
            return;
        };
        let mut refs = refs.to_vec();
        refs.sort_unstable();
        refs.dedup();
        let mut states = match store.message_reaction_states(&refs) {
            Ok(states) => states,
            Err(e) => {
                tracing::warn!("inbox: reading reactions to announce: {e}");
                return;
            }
        };
        states.sort_unstable_by_key(|m| std::cmp::Reverse((m.sent_at, m.reference)));
        states.truncate(policy.live_window);
        let open_since = self.pm_open_since();
        for told in states.chunks(PM_TOLD) {
            self.pm_tell(told, open_since, None);
        }
    }

    /// Each session but `except` that hears any of `states` told them
    /// in one event, with its own account's keys.
    fn pm_tell(&self, states: &[MessageState], open_since: SystemTime, except: Option<Uid>) {
        let mut r = self.roster.lock().unwrap();
        let told: Vec<(Uid, Vec<ReactionChange>)> = (r.users.iter())
            .filter(|(uid, _)| Some(**uid) != except)
            .filter_map(|(uid, s)| {
                let heard: Vec<&MessageState> = (states.iter())
                    .filter(|m| pm_hears(s, m, open_since))
                    .collect();
                if heard.is_empty() {
                    return None;
                }
                let me = reactor_key(&s.mailbox());
                let changes = (heard.into_iter())
                    .map(|m| ReactionChange::Summary {
                        target: Reply::Pm(m.reference),
                        keys: m.keys.as_slice().into(),
                        mine: (m.keys.iter().enumerate())
                            .filter(|(_, (k, _))| {
                                m.held.iter().any(|(who, h)| *who == me && h == k)
                            })
                            .map(|(i, _)| i as u8)
                            .collect(),
                    })
                    .collect();
                Some((*uid, changes))
            })
            .collect();
        for (uid, changes) in told {
            r.send_to(uid, Event::ReactionsChanged(changes));
        }
    }

    /// The reactions on those of `refs` that are `uid`'s mail, for its
    /// `inbox` page: the recipient's view, which lasts with the row.
    /// Messages with none are left out, and a session of no one account
    /// holds none of them.
    pub fn message_reactions(
        &self,
        uid: Uid,
        refs: &[MessageRef],
    ) -> Result<HashMap<MessageRef, Reactions>, StoreError> {
        let Some(store) = self
            .inbox
            .as_ref()
            .filter(|_| self.reaction_policy().is_some())
        else {
            return Ok(HashMap::new());
        };
        let reader = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)
                .filter(|s| s.is_person)
                .map(|s| s.mailbox())
        };
        let Some(reader) = reader else {
            return Ok(HashMap::new());
        };
        let shown = store.message_reactions(refs, &reader, self.pm_open_since(), None)?;
        Ok(shown.into_iter().map(|(r, (s, _))| (r, s)).collect())
    }

    /// The earliest `sent_at` still inside a sender's window, floored as
    /// retention's cutoff is, so a long window on a young clock is the
    /// whole of time rather than a panic.
    pub(crate) fn pm_open_since(&self) -> SystemTime {
        (self.clock.wall())
            .checked_sub(self.inbox_policy.retain_unread)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

/// A session that hears and reads stored messages' reactions at all: a
/// person's, that declared them.
pub(crate) fn pm_reader(s: &UserSession) -> bool {
    s.is_person && s.info.transport.reactions
}

/// Does `s` hear `m`'s reactions change, on its side's terms? The
/// recipient's once the message has been handed over: until then they
/// ride the `msg` that hands it over, read under the flush's hold of
/// `pm_reacting`. A recipient can hold a pending message's ref from
/// `inbox` and react to it, and its other sessions then learn of that
/// from the `msg` or from `inbox`, rather than from a summary ahead of
/// the message it is about. The sender's until its window ends, the
/// same for a message read or not, and never asked whether it was
/// delivered.
fn pm_hears(s: &UserSession, m: &MessageState, open_since: SystemTime) -> bool {
    let is = |p: &Mailbox| p.matches(&s.login, s.identity.as_ref());
    pm_reader(s)
        && match is(&m.recipient) {
            true => m.delivered,
            false => m.sent_at >= open_since && m.sender.as_ref().is_some_and(is),
        }
}

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    use super::super::tests::{bits, said, thumbs};
    use super::super::{Asked, ReactionPolicy};
    use super::*;
    use crate::chat::inbox_tests::RacyStore;
    use crate::history::{HistoryPolicy, MemoryLog};
    use crate::inbox::{
        Delivery, MemoryStore, MessageId, MessageKind, MessageStore, NewMessage, Pushed,
    };
    use crate::relationships::{MemoryRelationships, RelationshipStore, SentOn};
    use crate::roster::{drain, AttachInfo, InboxPolicy, Resume};
    use crate::{AccessBits, AccountDirectory, Events, Transport};

    const DAY: Duration = Duration::from_secs(24 * 3600);
    const TICK: Duration = Duration::from_secs(2);

    struct Nobody;

    impl AccountDirectory for Nobody {
        fn inbox_account(&self, _: &str) -> Option<Mailbox> {
            None
        }
        fn mailbox_access(&self, _: &Mailbox) -> Option<AccessBits> {
            None
        }
    }

    /// alice writes to dave, and carol is neither. Each of the three
    /// hears reactions, as do a second session each of alice's and
    /// dave's, and `ears` keeps what each is sent, by name.
    struct Pm {
        core: Arc<Core>,
        inbox: Arc<dyn MessageStore>,
        rel: Arc<MemoryRelationships>,
        alice: Uid,
        dave: Uid,
        carol: Uid,
        ears: Vec<(&'static str, Events)>,
    }

    /// What one event told, message by message: its keys and the
    /// session's own.
    type Told = Vec<(MessageRef, Vec<(ReactionKey, u32)>, Vec<u8>)>;

    fn server(policy: ReactionPolicy) -> Pm {
        server_on(Arc::new(MemoryStore::new()), policy)
    }

    fn server_on(inbox: Arc<dyn MessageStore>, policy: ReactionPolicy) -> Pm {
        let rel = Arc::new(MemoryRelationships::new());
        let core = Core::new()
            .with_history(Arc::new(MemoryLog::default()), HistoryPolicy::default())
            .with_reactions(policy)
            .with_inbox(inbox.clone(), Arc::new(Nobody), InboxPolicy::default())
            .with_relationships(rel.clone());
        let core = Arc::new(core);
        let ear = |l| attach_rx(&core, l, |i| i.transport.reactions = true);
        let [(alice, a), (dave, d), (carol, c), (_, a2), (_, d2)] =
            ["alice", "dave", "carol", "alice", "dave"].map(ear);
        Pm {
            core,
            inbox,
            rel,
            alice,
            dave,
            carol,
            ears: vec![
                ("alice", a),
                ("dave", d),
                ("carol", c),
                ("alice's other", a2),
                ("dave's other", d2),
            ],
        }
    }

    /// A person's session that may chat, as `edit` leaves it.
    fn attach(core: &Core, login: &str, edit: impl FnOnce(&mut AttachInfo)) -> Uid {
        attach_rx(core, login, edit).0
    }

    /// [`attach`], and what the session is sent.
    fn attach_rx(core: &Core, login: &str, edit: impl FnOnce(&mut AttachInfo)) -> (Uid, Events) {
        use crate::access::bit::{READ_CHAT, SEND_CHAT};
        let mut info = AttachInfo {
            account: None,
            nick: login.to_string(),
            icon: 1,
            admin: false,
            access: bits(&[READ_CHAT, SEND_CHAT]),
            login: login.to_string(),
            addr: None,
            can_detach: false,
            transport: Transport::default(),
            has_inbox: true,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            manage_rooms: false,
            set_subject: false,
            is_person: true,
            reads_on_delivery: false,
            identity: None,
            system: false,
        };
        edit(&mut info);
        let (uid, rx) = core.attach(info).unwrap();
        core.announce(uid);
        (uid, rx)
    }

    /// The summaries among `events`, each event's as one [`Told`].
    fn summaries(events: Vec<Event>) -> Vec<Told> {
        (events.into_iter())
            .filter_map(|e| match e {
                Event::ReactionsChanged(changes) => Some(
                    (changes.into_iter())
                        .map(|c| match c {
                            ReactionChange::Summary {
                                target: Reply::Pm(r),
                                keys,
                                mine,
                            } => (r, keys.to_vec(), mine),
                            other => panic!("not a message's summary: {other:?}"),
                        })
                        .collect(),
                ),
                _ => None,
            })
            .collect()
    }

    fn key(emoji: &str) -> ReactionKey {
        ReactionKey::emoji(emoji).unwrap()
    }

    fn dave() -> Mailbox {
        Mailbox::login("dave")
    }

    impl Pm {
        /// A message to `to` from `from`, stored now and handed over,
        /// and its cursor.
        fn mail_as(
            &self,
            to: Mailbox,
            from: Mailbox,
            kind: MessageKind,
            friendship: Option<SentOn>,
        ) -> (MessageRef, u64) {
            let (r, cursor, id) = self.queued_as(to, from, kind, friendship);
            let now = self.core.clock().wall();
            self.inbox
                .mark_delivered(&[id], now, Delivery::Delivered)
                .unwrap();
            (r, cursor)
        }

        /// [`Self::mail_as`], left waiting to be handed over.
        fn queued_as(
            &self,
            to: Mailbox,
            from: Mailbox,
            kind: MessageKind,
            friendship: Option<SentOn>,
        ) -> (MessageRef, u64, MessageId) {
            let m = NewMessage {
                recipient: to,
                sender: Some(from),
                sender_nick: "someone".into(),
                body: "hi".into(),
                sent_at: self.core.clock().wall(),
                guid: None,
                kind,
                media: None,
                signed: None,
                friendship,
                sender_address: None,
                re: None,
            };
            match self.inbox.push(&m, 100).unwrap() {
                Pushed::Stored {
                    reference,
                    cursor,
                    id,
                } => (reference, cursor, id),
                other => panic!("not stored: {other:?}"),
            }
        }

        /// alice's private message to dave.
        fn mail(&self) -> (MessageRef, u64) {
            self.mail_as(dave(), Mailbox::login("alice"), MessageKind::Message, None)
        }

        /// alice's private message to dave, waiting.
        fn queued(&self) -> MessageRef {
            let alice = Mailbox::login("alice");
            self.queued_as(dave(), alice, MessageKind::Message, None).0
        }

        /// `who` holds `emoji` on `r`, written past every window and the
        /// rate.
        fn hold(&self, r: MessageRef, who: &Mailbox, emoji: &str) {
            let act = MessageReactAct {
                reference: r,
                who,
                nick: &who.login,
                key: &key(emoji),
                add: true,
                at: self.core.clock().wall(),
                open_since: SystemTime::UNIX_EPOCH,
                max_keys: 20,
                max_per_user: 5,
            };
            let reacted = self.inbox.react_message(&act).unwrap();
            assert!(matches!(reacted, MessageReacted::Applied(_)), "{reacted:?}");
        }

        /// What the session `name` was sent since last asked.
        fn heard(&mut self, name: &str) -> Vec<Event> {
            let (_, rx) = (self.ears.iter_mut()).find(|(n, _)| *n == name).unwrap();
            drain(rx)
        }

        /// The summaries each session was sent since last asked, of those
        /// that were sent any.
        fn told(&mut self) -> Vec<(&'static str, Vec<Told>)> {
            (self.ears.iter_mut())
                .map(|(name, rx)| (*name, summaries(drain(rx))))
                .filter(|(_, told)| !told.is_empty())
                .collect()
        }

        /// The sessions [`Self::told`] names.
        fn who(&mut self) -> Vec<&'static str> {
            self.told().into_iter().map(|(name, _)| name).collect()
        }

        fn read(&self, up_to: u64) {
            let now = self.core.clock().wall();
            self.inbox.mark_read(&dave(), up_to, now).unwrap();
        }

        fn wait(&self, d: Duration) {
            self.core.clock().advance(d);
        }

        fn react(&self, uid: Uid, r: MessageRef, emoji: &str) {
            assert_eq!(self.core.react_pm(uid, r, &key(emoji), true), Ok(()));
        }

        /// What `uid` is shown of `r`.
        fn shown(&self, uid: Uid, r: MessageRef) -> Reactions {
            let asked = self.core.reactions_asked(uid, &[Reply::Pm(r)], None);
            asked.unwrap().remove(0).shown
        }

        /// What is kept on `r`, whoever may see it.
        fn kept(&self, r: MessageRef) -> Vec<(ReactionKey, u32)> {
            let states = self.inbox.message_reaction_states(&[r]).unwrap();
            states.into_iter().flat_map(|s| s.keys).collect()
        }
    }

    /// Past who may react, every reaction is answered `{}`, whatever
    /// became of it, and only one applied is told: to the sessions of
    /// both parties that hear it but the reactor's, the sender's only
    /// inside its window.
    #[test]
    fn a_pm_reaction_is_answered_alike_whatever_became_of_it() {
        let policy = ReactionPolicy {
            max_keys: 3,
            max_per_user: 2,
            burst: 1000,
            ..ReactionPolicy::default()
        };
        let window = InboxPolicy::default().retain_unread;
        let read_for = InboxPolicy::default().retain_read;
        type Setup = fn(&Pm, Duration, Duration) -> (Uid, MessageRef, &'static str, bool);
        type Kept = &'static [(&'static str, u32)];
        let cases: [(&str, Setup, Kept, &[&str]); 15] = [
            (
                "no such message",
                |s, _, _| (s.dave, [7; 16], "👍", true),
                &[],
                &[],
            ),
            (
                "another pair's",
                |s, _, _| (s.carol, s.mail().0, "👍", true),
                &[],
                &[],
            ),
            (
                "a receipt",
                |s, _, _| {
                    let alice = Mailbox::login("alice");
                    let (r, _) = s.mail_as(dave(), alice, MessageKind::ReadReceipt, None);
                    (s.dave, r, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "a request",
                |s, _, _| {
                    let alice = Mailbox::login("alice");
                    let request = Some(SentOn::Request);
                    let (r, _) = s.mail_as(dave(), alice, MessageKind::Message, request);
                    (s.dave, r, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "an instant message",
                |s, _, _| {
                    let alice = Mailbox::login("alice");
                    let im = Some(SentOn::Relation(1));
                    let (r, _) = s.mail_as(dave(), alice, MessageKind::Message, im);
                    (s.dave, r, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "the sender, past its window on a row kept",
                |s, window, _| {
                    let (r, cursor) = s.mail();
                    s.wait(window - DAY);
                    s.read(cursor);
                    s.wait(DAY + TICK);
                    s.core.prune_inbox();
                    (s.alice, r, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "the recipient, on a stub past the window",
                |s, window, read_for| {
                    let (r, cursor) = s.mail();
                    s.read(cursor);
                    s.wait(read_for + TICK);
                    assert_eq!(s.core.prune_inbox(), 1);
                    s.wait(window - read_for);
                    (s.dave, r, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "blocked by the other party",
                |s, _, _| {
                    let (alice, now) = (Mailbox::login("alice"), SystemTime::now());
                    s.rel.set_blocked(&dave(), &alice, true, now).unwrap();
                    (s.alice, s.mail().0, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "blocking the other party",
                |s, _, _| {
                    let (alice, now) = (Mailbox::login("alice"), SystemTime::now());
                    s.rel.set_blocked(&alice, &dave(), true, now).unwrap();
                    (s.alice, s.mail().0, "👍", true)
                },
                &[],
                &[],
            ),
            (
                "past the message's keys",
                |s, _, _| {
                    let (r, _) = s.mail();
                    s.react(s.alice, r, "👍");
                    s.react(s.alice, r, "🎉");
                    s.react(s.dave, r, "🔥");
                    (s.dave, r, "😀", true)
                },
                &[("👍", 1), ("🎉", 1), ("🔥", 1)],
                &[],
            ),
            (
                "past the account's",
                |s, _, _| {
                    let (r, _) = s.mail();
                    s.react(s.alice, r, "👍");
                    s.react(s.alice, r, "🎉");
                    (s.alice, r, "🔥", true)
                },
                &[("👍", 1), ("🎉", 1)],
                &[],
            ),
            (
                "an add",
                |s, _, _| (s.dave, s.mail().0, "👍", true),
                &[("👍", 1)],
                &["alice", "alice's other", "dave's other"],
            ),
            (
                "a removal",
                |s, _, _| {
                    let (r, _) = s.mail();
                    s.react(s.alice, r, "👍");
                    s.react(s.dave, r, "🎉");
                    (s.dave, r, "🎉", false)
                },
                &[("👍", 1)],
                &["alice", "alice's other", "dave's other"],
            ),
            (
                "a key already held",
                |s, _, _| {
                    let (r, _) = s.mail();
                    s.react(s.dave, r, "👍");
                    (s.dave, r, "👍", true)
                },
                &[("👍", 1)],
                &[],
            ),
            (
                "the recipient, past the window on its row",
                |s, window, _| {
                    let (r, cursor) = s.mail();
                    s.wait(window - DAY);
                    s.read(cursor);
                    s.wait(DAY + TICK);
                    s.core.prune_inbox();
                    (s.dave, r, "👍", true)
                },
                &[("👍", 1)],
                &["dave's other"],
            ),
        ];
        for (case, setup, kept, told) in cases {
            let mut s = server(policy);
            let (uid, r, emoji, add) = setup(&s, window, read_for);
            s.told();
            assert_eq!(s.core.react_pm(uid, r, &key(emoji), add), Ok(()), "{case}");
            let kept: Vec<_> = kept.iter().map(|&(e, n)| (key(e), n)).collect();
            assert_eq!(s.kept(r), kept, "{case}");
            assert_eq!(s.who(), told, "{case}");
        }
    }

    /// Only a person who may chat reacts: never a guest, though the
    /// store counts its shared mailbox's mail as its own, nor an identity
    /// guest, though its sent mail is kept under its key. Those two read
    /// none either. A messenger session reacts to its mail.
    #[test]
    fn a_pm_reaction_needs_a_person_who_may_chat() {
        let s = server(ReactionPolicy::default());
        let guest = attach(&s.core, "guest", |i| i.is_person = false);
        let stranger = attach(&s.core, "guest", |i| {
            i.is_person = false;
            i.identity = Some([9; 32]);
        });
        let alice = Mailbox::login("alice");
        let (to_guest, _) = s.mail_as(
            Mailbox::login("guest"),
            alice.clone(),
            MessageKind::Message,
            None,
        );
        s.react(s.alice, to_guest, "👍");
        let unknown = Mailbox::identified("guest", [9; 32]);
        let (from_stranger, _) = s.mail_as(dave(), unknown, MessageKind::Message, None);
        s.react(s.dave, from_stranger, "👍");
        // Parties to dave's mail, so the gate is what refuses them; they
        // are people, and read it as dave does.
        let system = attach(&s.core, "dave", |i| i.system = true);
        let mute = attach(&s.core, "dave", |i| i.access = AccessBits::empty());
        let (to_dave, _) = s.mail();
        for (case, uid, r, guest) in [
            ("a guest", guest, to_guest, true),
            ("an identity guest", stranger, from_stranger, true),
            ("the system", system, to_dave, false),
            ("no send_chat", mute, to_dave, false),
        ] {
            assert_eq!(
                s.core.react_pm(uid, r, &thumbs(), true),
                Err(ReactError::NotAllowed),
                "{case}"
            );
            if guest {
                assert_eq!(s.shown(uid, r), Reactions::default(), "{case}");
                let read = s.core.message_reactions(uid, &[r]).unwrap();
                assert_eq!(read, HashMap::new(), "{case}");
            }
        }
        assert_eq!(s.kept(to_guest), [(thumbs(), 1)]);

        let messenger = attach(&s.core, "dave", |i| i.transport.messenger_session = true);
        let (r, _) = s.mail();
        s.react(messenger, r, "👍");
        assert_eq!(s.kept(r), [(thumbs(), 1)]);
    }

    #[test]
    fn a_pm_reaction_spends_the_accounts_reaction_rate() {
        let s = server(ReactionPolicy {
            burst: 2,
            ..ReactionPolicy::default()
        });
        let line = said(&s.core, s.alice, "hi");
        let (r, _) = s.mail();
        assert_eq!(s.core.react(s.dave, 0, line, &thumbs(), true), Ok(1));
        s.react(s.dave, r, "👍");
        assert!(matches!(
            s.core.react_pm(s.dave, r, &thumbs(), false),
            Err(ReactError::RateLimited(_))
        ));
    }

    /// One message read and pruned early, one never read and one read
    /// late and kept: their sender reacts to each and reads it back alike
    /// until its window ends, and reads nothing of any after.
    #[test]
    fn a_senders_view_is_alike_for_read_and_unread_messages_until_its_window_ends() {
        let s = server(ReactionPolicy {
            burst: 1000,
            ..ReactionPolicy::default()
        });
        let policy = InboxPolicy::default();
        let window = policy.retain_unread;
        let (early, cursor) = s.mail();
        let (late, late_cursor) = s.mail();
        let (unread, _) = s.mail();
        s.read(cursor);
        let mut now = Duration::ZERO;
        for at in [
            DAY,
            policy.retain_read + DAY,
            window - 2 * DAY,
            window - TICK,
            window + TICK,
            window + DAY,
        ] {
            s.wait(at - now);
            now = at;
            if at == window - 2 * DAY {
                s.read(late_cursor);
            }
            s.core.prune_inbox();
            let seen = [early, late, unread].map(|r| {
                assert_eq!(s.core.react_pm(s.alice, r, &thumbs(), true), Ok(()));
                s.shown(s.alice, r)
            });
            assert!(seen.iter().all(|x| *x == seen[0]), "{at:?}: {seen:?}");
            assert_eq!(seen[0].keys.is_empty(), at > window, "{at:?}: {seen:?}");
        }
    }

    /// A recipient's view lasts as long as its row, past its sender's
    /// window, and through a stub only inside it.
    #[test]
    fn a_recipients_view_lasts_with_its_row() {
        let s = server(ReactionPolicy::default());
        let policy = InboxPolicy::default();
        let (stubbed, cursor) = s.mail();
        let (kept, kept_cursor) = s.mail();
        s.read(cursor);
        s.wait(policy.retain_read + TICK);
        assert_eq!(s.core.prune_inbox(), 1);
        s.react(s.dave, stubbed, "👍");
        assert_eq!(s.shown(s.dave, stubbed).keys, [(thumbs(), 1)]);

        s.wait(policy.retain_unread - policy.retain_read - 2 * DAY);
        s.read(kept_cursor);
        s.wait(2 * DAY);
        s.react(s.dave, stubbed, "🎉");
        assert_eq!(s.shown(s.dave, stubbed), Reactions::default());
        s.react(s.dave, kept, "🎉");
        s.core.prune_inbox();
        assert_eq!(s.shown(s.dave, kept).keys, [(key("🎉"), 1)]);
    }

    /// Get Reactions answers a message the reader is no party to as it
    /// answers a party's message with no reactions.
    #[test]
    fn get_reactions_answers_a_non_party_as_a_party_with_none() {
        let s = server(ReactionPolicy::default());
        let (theirs, _) = s.mail();
        let (bare, _) = s.mail();
        s.react(s.dave, theirs, "👍");
        let none = |r: MessageRef, from: Option<Vec<String>>| Asked {
            target: Reply::Pm(r),
            shown: Reactions::default(),
            from,
        };
        for (uid, r) in [(s.carol, theirs), (s.carol, [7; 16]), (s.dave, bare)] {
            let asked = |key: Option<&ReactionKey>| {
                s.core.reactions_asked(uid, &[Reply::Pm(r)], key).unwrap()
            };
            assert_eq!(asked(None), [none(r, None)]);
            assert_eq!(asked(Some(&thumbs())), [none(r, Some(vec![]))]);
        }
    }

    /// A claim or a rotation moves the reactions with the mail, and a
    /// reaction made once the mail has moved and before its reactions
    /// have waits for both, landing under the key they moved to.
    #[test]
    fn a_pm_reaction_waits_for_a_claim_or_a_rotation_and_its_rekey() {
        for rotating in [false, true] {
            let racy = Arc::new(RacyStore::over(MemoryStore::new()));
            let s = server_on(racy.clone(), ReactionPolicy::default());
            let to = match rotating {
                true => Mailbox::identified("alice", [4; 32]),
                false => Mailbox::login("alice"),
            };
            let before = attach(&s.core, "alice", |i| i.identity = to.fingerprint);
            let (r, _) = s.mail_as(to, dave(), MessageKind::Message, None);
            s.react(before, r, "🎉");
            let linked = attach(&s.core, "alice", |i| i.identity = Some([5; 32]));
            let parked: Arc<Mutex<Option<bool>>> = Arc::default();
            let reacting = Arc::new(Mutex::new(None));
            let (core, slot, thread) = (s.core.clone(), parked.clone(), reacting.clone());
            *racy.during_move.lock().unwrap() = Some(Box::new(move || {
                let (done, finished) = mpsc::channel();
                *thread.lock().unwrap() = Some(std::thread::spawn(move || {
                    let out = core.react_pm(linked, r, &thumbs(), true);
                    let _ = done.send(());
                    out
                }));
                let early = finished.recv_timeout(Duration::from_millis(200)).is_ok();
                *slot.lock().unwrap() = Some(early);
            }));
            match rotating {
                true => s.core.rotate_identity(&[4; 32], &[5; 32]).unwrap(),
                false => assert_eq!(s.core.inbox_claim("alice", &[5; 32]), 1),
            }
            let thread = reacting.lock().unwrap().take().expect("moved");
            assert_eq!(thread.join().unwrap(), Ok(()), "rotating: {rotating}");
            assert_eq!(*parked.lock().unwrap(), Some(false), "rotating: {rotating}");
            let mine = s.inbox.message_reactions(
                &[r],
                &Mailbox::identified("alice", [5; 32]),
                SystemTime::UNIX_EPOCH,
                None,
            );
            assert_eq!(mine.unwrap()[&r].0.mine, [0, 1], "rotating: {rotating}");
        }
    }

    /// A summary carries each party's own keys, and reaches the
    /// reactor's other sessions but not the one that reacted.
    #[test]
    fn a_pm_reaction_is_told_to_both_parties_but_the_reactors_session() {
        let mut s = server(ReactionPolicy::default());
        let (r, _) = s.mail();
        s.react(s.alice, r, "👍");
        s.told();
        s.react(s.dave, r, "🎉");
        let keys = vec![(thumbs(), 1), (key("🎉"), 1)];
        let told = |mine: &[u8]| vec![vec![(r, keys.clone(), mine.to_vec())]];
        assert_eq!(
            s.told(),
            [
                ("alice", told(&[0])),
                ("alice's other", told(&[0])),
                ("dave's other", told(&[1])),
            ]
        );
    }

    /// A waiting message's reactions are told to none of its recipient's
    /// sessions, its own reaction's included, and ride the `msg` that
    /// hands it over to the sessions that hear them; once it is handed
    /// over they are told.
    #[test]
    fn a_queued_message_carries_its_reactions_and_its_recipient_hears_nothing_before() {
        let mut s = server(ReactionPolicy::default());
        let (_, plain) = attach_rx(&s.core, "dave", |_| {});
        s.ears.push(("dave's plain", plain));
        let r = s.queued();
        s.react(s.alice, r, "👍");
        s.react(s.dave, r, "🎉");
        assert_eq!(s.who(), ["alice", "alice's other"]);
        s.core.flush_mailbox(&dave());
        let shown = Reactions {
            keys: vec![(thumbs(), 1), (key("🎉"), 1)],
            mine: vec![1],
        };
        for (name, carried) in [
            ("dave", Some(&shown)),
            ("dave's other", Some(&shown)),
            ("dave's plain", None),
        ] {
            let msgs: Vec<_> = (s.heard(name).into_iter())
                .filter_map(|e| match e {
                    Event::Msg { reactions, .. } => Some(reactions),
                    _ => None,
                })
                .collect();
            assert_eq!(msgs, [carried.cloned().map(Box::new)], "{name}");
        }
        s.react(s.alice, r, "🔥");
        assert_eq!(s.who(), ["dave", "alice's other", "dave's other"]);
    }

    /// A reaction made while a flush is between handing a message over
    /// and stamping it delivered waits for the stamp and is told after
    /// the `msg`: it is never lost between the two.
    #[test]
    fn a_reaction_during_a_flush_reaches_the_recipient_once() {
        let racy = Arc::new(RacyStore::over(MemoryStore::new()));
        let mut s = server_on(racy.clone(), ReactionPolicy::default());
        let r = s.queued();
        let parked = Arc::new(Mutex::new(None));
        let (core, alice, slot) = (s.core.clone(), s.alice, parked.clone());
        *racy.during_stamp.lock().unwrap() = Some(Box::new(move || {
            let (done, finished) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                let out = core.react_pm(alice, r, &thumbs(), true);
                let _ = done.send(());
                out
            });
            let early = finished.recv_timeout(Duration::from_millis(200)).is_ok();
            *slot.lock().unwrap() = Some((thread, early));
        }));
        s.core.flush_mailbox(&dave());
        let (thread, early) = parked.lock().unwrap().take().expect("stamped");
        assert_eq!(thread.join().unwrap(), Ok(()));
        let heard: Vec<_> = (s.heard("dave").into_iter())
            .filter_map(|e| match e {
                Event::Msg { reactions, .. } => Some(format!("msg {reactions:?}")),
                e @ Event::ReactionsChanged(_) => Some(format!("{:?}", summaries(vec![e]))),
                _ => None,
            })
            .collect();
        let told: Vec<Told> = vec![vec![(r, vec![(thumbs(), 1)], vec![])]];
        assert_eq!(heard, ["msg None".to_string(), format!("{told:?}")]);
        assert!(!early);
    }

    /// A flush that could not read its messages' reactions hands them
    /// over without them and leaves them waiting, so the next flush
    /// hands them over again carrying them.
    #[test]
    fn a_message_whose_reactions_could_not_be_read_is_handed_over_again() {
        let racy = Arc::new(RacyStore::over(MemoryStore::new()));
        let mut s = server_on(racy.clone(), ReactionPolicy::default());
        let r = s.queued();
        s.react(s.alice, r, "👍");
        *racy.fail_reactions.lock().unwrap() = true;
        s.core.flush_mailbox(&dave());
        assert_eq!(s.inbox.pending_count(&dave()).unwrap(), 1);
        s.heard("dave");
        s.core.flush_mailbox(&dave());
        let msgs: Vec<_> = (s.heard("dave").into_iter())
            .filter_map(|e| match e {
                Event::Msg { reactions, .. } => Some(reactions.map(|r| r.keys)),
                _ => None,
            })
            .collect();
        assert_eq!(msgs, [Some(vec![(thumbs(), 1)])]);
    }

    /// Who hears a message's reactions is who may read them: never a
    /// guest on the shared guest mailbox, nor an identity guest on the
    /// mail it sent, though the store counts both as parties.
    #[test]
    fn who_hears_a_pm_reaction_is_who_may_read_it() {
        let mut s = server(ReactionPolicy::default());
        let declared = |i: &mut AttachInfo| {
            i.is_person = false;
            i.transport.reactions = true;
        };
        let (_, guest) = attach_rx(&s.core, "guest", declared);
        let (_, stranger) = attach_rx(&s.core, "guest", |i| {
            declared(i);
            i.identity = Some([9; 32]);
        });
        s.ears
            .extend([("a guest", guest), ("an identity guest", stranger)]);
        let alice = Mailbox::login("alice");
        let (to_guest, _) = s.mail_as(Mailbox::login("guest"), alice, MessageKind::Message, None);
        let unknown = Mailbox::identified("guest", [9; 32]);
        let (from_stranger, _) = s.mail_as(dave(), unknown, MessageKind::Message, None);
        s.react(s.alice, to_guest, "👍");
        assert_eq!(s.who(), ["alice's other"]);
        s.react(s.dave, from_stranger, "👍");
        assert_eq!(s.who(), ["dave's other"]);
    }

    /// Past its sender's window, a reaction a rekey or a purge takes is
    /// told to the recipient's session and to none of the sender's,
    /// each keyed as the change leaves its account.
    #[test]
    fn past_the_senders_window_a_purge_or_rekey_tells_the_sender_nothing() {
        let (four, five) = ([4; 32], [5; 32]);
        let (alice, alice4, alice5) = (
            Mailbox::login("alice"),
            Mailbox::identified("alice", four),
            Mailbox::identified("alice", five),
        );
        let dave5 = Mailbox::identified("dave", five);
        fn forget(s: &Pm, who: &Mailbox) {
            let _reacting = s.core.pm_reacting.lock().unwrap();
            let since = SystemTime::UNIX_EPOCH;
            s.core
                .pm_announce(&s.inbox.forget_message_reactions(who, since).unwrap());
        }
        type Step = Box<dyn Fn(&Pm, MessageRef)>;
        // The sender, and the two as the change leaves them.
        let cases: [(&str, Mailbox, [&Mailbox; 2], Step, Step); 5] = [
            (
                "the recipient's claim",
                alice.clone(),
                [&alice, &dave5],
                Box::new(|s, r| {
                    s.hold(r, &dave(), "👍");
                    s.inbox.claim("dave", &[5; 32]).unwrap();
                    s.hold(r, &Mailbox::identified("dave", [5; 32]), "👍");
                }),
                Box::new(|s, _| {
                    s.core.inbox_claim("dave", &[5; 32]);
                }),
            ),
            (
                "the sender's claim",
                alice.clone(),
                [&alice5, &dave()],
                Box::new(|s, r| {
                    s.hold(r, &Mailbox::login("alice"), "👍");
                    s.inbox.claim("alice", &[5; 32]).unwrap();
                    s.hold(r, &Mailbox::identified("alice", [5; 32]), "👍");
                }),
                Box::new(|s, _| {
                    s.core.inbox_claim("alice", &[5; 32]);
                }),
            ),
            (
                "the sender's rotation",
                alice4.clone(),
                [&alice5, &dave()],
                Box::new(|s, r| {
                    s.hold(r, &Mailbox::identified("alice", [4; 32]), "👍");
                    s.inbox.rotate(&[4; 32], &[5; 32]).unwrap();
                    s.hold(r, &Mailbox::identified("alice", [5; 32]), "👍");
                }),
                Box::new(|s, _| s.core.rotate_identity(&[4; 32], &[5; 32]).unwrap()),
            ),
            (
                "a purge of the sender's",
                alice.clone(),
                [&alice, &dave()],
                Box::new(|s, r| {
                    s.hold(r, &Mailbox::login("alice"), "👍");
                    s.hold(r, &dave(), "🎉");
                }),
                Box::new(|s, _| forget(s, &Mailbox::login("alice"))),
            ),
            (
                "a purge of the recipient's",
                alice.clone(),
                [&alice, &dave()],
                Box::new(|s, r| {
                    s.hold(r, &Mailbox::login("alice"), "👍");
                    s.hold(r, &dave(), "🎉");
                }),
                Box::new(|s, _| forget(s, &dave())),
            ),
        ];
        for (case, from, [sender, recipient], before, change) in cases {
            let mut s = server(ReactionPolicy::default());
            let (r, _) = s.mail_as(dave(), from, MessageKind::Message, None);
            before(&s, r);
            s.wait(InboxPolicy::default().retain_unread + TICK);
            s.ears.clear();
            for (name, m) in [("the sender", sender), ("the recipient", recipient)] {
                let (_, rx) = attach_rx(&s.core, &m.login, |i| {
                    i.transport.reactions = true;
                    i.identity = m.fingerprint;
                });
                s.ears.push((name, rx));
            }
            s.told();
            change(&s, r);
            assert_eq!(s.who(), ["the recipient"], "{case}");
        }
    }

    /// A rekey that took reactions from more messages than a live window
    /// tells the newest of them, newest first, fifty to an event.
    #[test]
    fn a_rekey_collision_is_told_in_chunks_of_the_newest() {
        let mut s = server(ReactionPolicy {
            live_window: 60,
            ..ReactionPolicy::default()
        });
        let (alice, linked) = (
            Mailbox::login("alice"),
            Mailbox::identified("alice", [5; 32]),
        );
        let mut sent: Vec<MessageRef> = (0..70)
            .map(|_| {
                let (r, _) = s.mail_as(alice.clone(), dave(), MessageKind::Message, None);
                s.hold(r, &alice, "👍");
                s.wait(TICK);
                r
            })
            .collect();
        s.inbox.claim("alice", &[5; 32]).unwrap();
        for r in &sent {
            s.hold(*r, &linked, "👍");
        }
        s.told();
        s.core.inbox_claim("alice", &[5; 32]);
        sent.reverse();
        let told = |refs: &[MessageRef]| -> Told {
            (refs.iter())
                .map(|r| (*r, vec![(thumbs(), 1)], vec![]))
                .collect()
        };
        let both = vec![told(&sent[..50]), told(&sent[50..60])];
        assert_eq!(s.told(), [("dave", both.clone()), ("dave's other", both)]);
    }

    /// A summary for a party that is away waits in its session's outbox
    /// and is replayed at its resume, in its place among its seqs.
    #[test]
    fn a_pm_summary_reaches_a_detached_party_through_its_outbox() {
        let s = server(ReactionPolicy::default());
        let (away, mut rx) = attach_rx(&s.core, "dave", |i| {
            i.transport.reactions = true;
            i.can_detach = true;
        });
        let (r, _) = s.mail();
        let last_seq = std::iter::from_fn(|| rx.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(s.core.connection_lost(away, 8));
        s.react(s.alice, r, "👍");
        let Resume::Replayed(_, replay) = s.core.resume(away, last_seq) else {
            panic!("not replayed");
        };
        let seqs: Vec<u64> = replay.iter().map(|se| se.seq).collect();
        assert_eq!(seqs, (last_seq + 1..).take(seqs.len()).collect::<Vec<_>>());
        let told = summaries(replay.into_iter().map(|se| se.event).collect());
        assert_eq!(told, [vec![(r, vec![(thumbs(), 1)], vec![])]]);
    }
}
