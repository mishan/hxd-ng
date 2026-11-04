//! Reactions on a stored private message (`docs/hotline-ng.md` §7.3,
//! `docs/private-messages.md` §5): kept by the inbox store, seen by each
//! party on its own side's terms, and changed under `Core::pm_reacting`
//! rather than at the desk, which keeps the log's.

use std::collections::HashMap;
use std::time::SystemTime;

use super::{MessageReactAct, ReactError, ReactionKey, Reactions};
use crate::access::bit;
use crate::inbox::{MessageRef, StoreError};
use crate::roster::Uid;
use crate::Core;

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
        store
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
        Ok(())
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

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    use super::super::tests::{bits, said, thumbs};
    use super::super::{Asked, ReactionPolicy};
    use super::*;
    use crate::chat::inbox_tests::RacyStore;
    use crate::history::{HistoryPolicy, MemoryLog};
    use crate::inbox::{Mailbox, MemoryStore, MessageKind, MessageStore, NewMessage, Pushed};
    use crate::relationships::{MemoryRelationships, RelationshipStore, SentOn};
    use crate::reply::Reply;
    use crate::roster::{AttachInfo, InboxPolicy};
    use crate::{AccessBits, AccountDirectory, Transport};

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

    /// alice writes to dave, and carol is neither.
    struct Pm {
        core: Arc<Core>,
        inbox: Arc<dyn MessageStore>,
        rel: Arc<MemoryRelationships>,
        alice: Uid,
        dave: Uid,
        carol: Uid,
    }

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
        let [alice, dave, carol] = ["alice", "dave", "carol"].map(|l| attach(&core, l, |_| {}));
        Pm {
            core,
            inbox,
            rel,
            alice,
            dave,
            carol,
        }
    }

    /// A person's session that may chat, as `edit` leaves it.
    fn attach(core: &Core, login: &str, edit: impl FnOnce(&mut AttachInfo)) -> Uid {
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
        let (uid, _rx) = core.attach(info).unwrap();
        core.announce(uid);
        uid
    }

    fn key(emoji: &str) -> ReactionKey {
        ReactionKey::emoji(emoji).unwrap()
    }

    fn dave() -> Mailbox {
        Mailbox::login("dave")
    }

    impl Pm {
        /// A message to `to` from `from`, stored now, and its cursor.
        fn mail_as(
            &self,
            to: Mailbox,
            from: Mailbox,
            kind: MessageKind,
            friendship: Option<SentOn>,
        ) -> (MessageRef, u64) {
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
                    reference, cursor, ..
                } => (reference, cursor),
                other => panic!("not stored: {other:?}"),
            }
        }

        /// alice's private message to dave.
        fn mail(&self) -> (MessageRef, u64) {
            self.mail_as(dave(), Mailbox::login("alice"), MessageKind::Message, None)
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
    /// became of it.
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
        let cases: [(&str, Setup, Kept); 15] = [
            (
                "no such message",
                |s, _, _| (s.dave, [7; 16], "👍", true),
                &[],
            ),
            (
                "another pair's",
                |s, _, _| (s.carol, s.mail().0, "👍", true),
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
            ),
            (
                "blocked by the other party",
                |s, _, _| {
                    let (alice, now) = (Mailbox::login("alice"), SystemTime::now());
                    s.rel.set_blocked(&dave(), &alice, true, now).unwrap();
                    (s.alice, s.mail().0, "👍", true)
                },
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
            ),
            (
                "an add",
                |s, _, _| (s.dave, s.mail().0, "👍", true),
                &[("👍", 1)],
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
            ),
            (
                "a key already held",
                |s, _, _| {
                    let (r, _) = s.mail();
                    s.react(s.dave, r, "👍");
                    (s.dave, r, "👍", true)
                },
                &[("👍", 1)],
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
            ),
        ];
        for (case, setup, kept) in cases {
            let s = server(policy);
            let (uid, r, emoji, add) = setup(&s, window, read_for);
            assert_eq!(s.core.react_pm(uid, r, &key(emoji), add), Ok(()), "{case}");
            let kept: Vec<_> = kept.iter().map(|&(e, n)| (key(e), n)).collect();
            assert_eq!(s.kept(r), kept, "{case}");
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
}
