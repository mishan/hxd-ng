//! A person's sessions as one row of the roster. With `[server] coalesce`
//! on, the sessions of one login whose identity is the account's linked
//! one share a row: its uid is the first session's, kept while any of
//! them lives; only the first live member is listed, under that uid and
//! the best status of them all; the roster is told of the person once, as
//! it joins and as its last session leaves. Each session keeps its own
//! uid, serial and outbox, and hears what the row hears.

use std::collections::HashMap;

use crate::roster::{Event, RosterInner, SessionStatus, Uid, UserInfo, UserSession};

/// One person on the roster.
pub(crate) struct Coalesced {
    /// The uid every wire shows for the person.
    pub(crate) row: Uid,
    /// Live members, in the order they joined; the first is the one listed.
    pub(crate) members: Vec<Uid>,
    /// The row as the roster was last told it, so a member's coming or
    /// going tells nobody anything unless the row changed.
    told: UserInfo,
}

/// The people on the roster, by login, and the logins their rows are for.
#[derive(Default)]
pub(crate) struct Persons {
    pub(crate) on: bool,
    pub(crate) by_login: HashMap<String, Coalesced>,
    pub(crate) rows: HashMap<Uid, String>,
}

/// What a session's announce made of it.
pub(crate) enum Joined {
    /// Its own row, as every session's was before coalescing.
    Alone,
    /// The first of a person: its row is shown as joining.
    First,
    /// Another of a person already shown: the row changes, if at all.
    Another(Option<Box<Event>>),
}

/// What a session's end made of its row.
pub(crate) enum Left {
    Alone,
    /// The person's last: its row parts.
    Last {
        row: Uid,
    },
    /// Others of the person live on: the row changes, if at all.
    Stays {
        row: Uid,
        changed: Option<Box<Event>>,
    },
}

/// Best first: a person is as present as its most present session.
fn rank(status: SessionStatus) -> u8 {
    match status {
        SessionStatus::Active => 0,
        SessionStatus::Idle => 1,
        SessionStatus::Detached => 2,
    }
}

impl RosterInner {
    /// Whether `sess` shares a row with its account's other sessions: a
    /// person's own account, logged in to as the identity linked to it,
    /// and not the system account, a messenger session or one masked apart.
    fn coalesces(&self, sess: &UserSession) -> bool {
        self.persons.on
            && sess.is_person
            && !sess.system
            && !sess.info.transport.messenger_session
            && sess.mask == crate::DenyMask::default()
            && sess.account.as_ref().is_some_and(|a| {
                a.identity.fingerprint.is_some() && a.identity.fingerprint == sess.identity
            })
    }

    /// Join `uid`, just announced, to its person if it has one.
    pub(crate) fn coalesce_join(&mut self, uid: Uid) -> Joined {
        let Some(sess) = self.users.get(&uid) else {
            return Joined::Alone;
        };
        if !self.coalesces(sess) {
            return Joined::Alone;
        }
        let login = sess.login.clone();
        let info = sess.info.clone();
        // A person is one identity: a session of the login under another
        // (its link changed while the first was on) stands apart.
        let identity = sess.identity;
        let other_identity = self.persons.by_login.get(&login).is_some_and(|p| {
            p.members
                .first()
                .and_then(|m| self.users.get(m))
                .is_some_and(|front| front.identity != identity)
        });
        if other_identity {
            return Joined::Alone;
        }
        self.users.get_mut(&uid).expect("got above").grouped = true;
        match self.persons.by_login.get_mut(&login) {
            Some(p) => {
                p.members.push(uid);
                Joined::Another(self.retell(&login).map(Box::new))
            }
            None => {
                self.persons.rows.insert(uid, login.clone());
                self.persons.by_login.insert(
                    login,
                    Coalesced {
                        row: uid,
                        members: vec![uid],
                        told: info,
                    },
                );
                Joined::First
            }
        }
    }

    /// Take `sess`, just removed from the roster as `uid`, out of its person.
    pub(crate) fn coalesce_leave(&mut self, uid: Uid, sess: &UserSession) -> Left {
        if !sess.grouped {
            return Left::Alone;
        }
        let Some(p) = self.persons.by_login.get_mut(&sess.login) else {
            return Left::Alone;
        };
        p.members.retain(|m| *m != uid);
        let row = p.row;
        if p.members.is_empty() {
            self.persons.by_login.remove(&sess.login);
            self.persons.rows.remove(&row);
            return Left::Last { row };
        }
        Left::Stays {
            row,
            changed: self.retell(&sess.login.clone()).map(Box::new),
        }
    }

    /// `info`, a row about to be told: a person's as it stands now, and
    /// noted as told, so a later change compares with what was sent.
    pub(crate) fn row_now(&mut self, info: UserInfo) -> UserInfo {
        let Some(login) = self.persons.rows.get(&info.uid).cloned() else {
            return info;
        };
        let Some(view) = self.person_view(&login) else {
            return info;
        };
        if let Some(p) = self.persons.by_login.get_mut(&login) {
            p.told = view.clone();
        }
        view
    }

    /// The person's row as it stands, if it is not as the roster was told.
    fn retell(&mut self, login: &str) -> Option<Event> {
        let view = self.person_view(login)?;
        let p = self.persons.by_login.get_mut(login)?;
        (p.told != view).then(|| {
            p.told = view.clone();
            Event::Changed(view)
        })
    }

    /// The row a person is shown as: its first member's, under its uid,
    /// as present as any of them.
    fn person_view(&self, login: &str) -> Option<UserInfo> {
        let p = self.persons.by_login.get(login)?;
        let front = self.users.get(p.members.first()?)?;
        let mut info = front.info.clone();
        info.uid = p.row;
        // Sealed to by device, which the row is not.
        if let Some(identity) = info.transport.identity.as_mut() {
            identity.sealed = None;
        }
        info.status = p
            .members
            .iter()
            .filter_map(|m| self.users.get(m))
            .map(|s| s.info.status)
            .min_by_key(|s| rank(*s))
            .unwrap_or(info.status);
        Some(info)
    }

    /// `sess` as the wire shows it: its person's row, or its own.
    pub(crate) fn row_view(&self, sess: &UserSession) -> UserInfo {
        if sess.grouped {
            if let Some(view) = self.person_view(&sess.login) {
                return view;
            }
        }
        sess.info.clone()
    }

    /// `info`, a session's, as the wire shows it.
    pub(crate) fn shown_info(&self, info: UserInfo) -> UserInfo {
        match self.users.get(&info.uid) {
            Some(sess) if sess.grouped => self.row_view(sess),
            _ => info,
        }
    }

    /// Whether `uid` is listed: a session alone, or its person's first.
    pub(crate) fn listed(&self, uid: Uid, sess: &UserSession) -> bool {
        !sess.grouped
            || self
                .persons
                .by_login
                .get(&sess.login)
                .is_none_or(|p| p.members.first() == Some(&uid))
    }

    /// What to tell the roster of a change to `uid`: its own row, or its
    /// person's if that changed.
    pub(crate) fn changed_event(&mut self, uid: Uid) -> Option<Event> {
        let sess = self.users.get(&uid).filter(|s| s.live())?;
        if sess.grouped {
            let login = sess.login.clone();
            return self.retell(&login);
        }
        Some(Event::Changed(sess.info.clone()))
    }

    /// The person a row uid stands for, and its members.
    pub(crate) fn person_members(&self, row: Uid) -> Option<&[Uid]> {
        let login = self.persons.rows.get(&row)?;
        self.persons
            .by_login
            .get(login)
            .map(|p| p.members.as_slice())
    }

    /// The row `session` is shown under.
    pub(crate) fn row_uid(&self, session: Uid) -> Uid {
        self.users
            .get(&session)
            .filter(|s| s.grouped)
            .and_then(|s| self.persons.by_login.get(&s.login))
            .map_or(session, |p| p.row)
    }

    /// Whether `uid` is one of a person's sessions and not its last.
    pub(crate) fn person_stays(&self, uid: Uid) -> bool {
        self.users
            .get(&uid)
            .filter(|s| s.grouped)
            .and_then(|s| self.persons.by_login.get(&s.login))
            .is_some_and(|p| p.members.len() > 1)
    }

    /// Whether `uid` is a person's row, held while the person lives.
    pub(crate) fn is_row(&self, uid: Uid) -> bool {
        self.persons.rows.contains_key(&uid)
    }
}

#[cfg(test)]
mod tests {
    use crate::access::{bit, AccessBits};
    use crate::account::{Account, AccountConfig, IdentityLink};
    use crate::roster::{drain, AttachInfo, Core, Event, Events, SessionStatus, Transport, Uid};

    const ALICE: [u8; 32] = [7; 32];

    /// A session of `login`, its account linking `linked`, proved as `identity`.
    fn attach(
        core: &Core,
        login: &str,
        identity: Option<[u8; 32]>,
        linked: Option<[u8; 32]>,
    ) -> (Uid, Events) {
        let link = IdentityLink {
            fingerprint: linked,
            ..IdentityLink::default()
        };
        let account = Account::new(
            login.into(),
            login.into(),
            true,
            link,
            AccountConfig::default(),
        );
        let (uid, rx) = core
            .attach(AttachInfo {
                account: Some(Box::new(account)),
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_CHAT),
                login: login.to_string(),
                addr: None,
                can_detach: true,
                transport: Transport::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: true,
                reads_on_delivery: false,
                identity,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    fn rows(core: &Core) -> Vec<(Uid, String, SessionStatus)> {
        core.snapshot()
            .into_iter()
            .map(|u| (u.uid, u.nick, u.status))
            .collect()
    }

    /// The joins, changes and parts `rx` has been told, as (kind, uid).
    fn told(rx: &mut Events) -> Vec<(&'static str, Uid)> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Joined(u) => Some(("joined", u.uid)),
                Event::Changed(u) => Some(("changed", u.uid)),
                Event::Parted(uid) => Some(("parted", uid)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_persons_sessions_are_one_row_that_joins_with_the_first_and_parts_with_the_last() {
        let core = Core::new().with_coalesce(true);
        let (bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a3, _rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert_eq!(told(&mut watching), [("joined", a1)]);
        let alice = (a1, "alice".to_string(), SessionStatus::Active);
        assert_eq!(
            rows(&core),
            [(bob, "bob".into(), SessionStatus::Active), alice.clone()]
        );

        // The first ends: the row is still alice's, under her first uid.
        core.end_session(a1);
        core.end_session(a3);
        assert_eq!(told(&mut watching), []);
        assert_eq!(rows(&core)[1], alice);
        core.end_session(a2);
        assert_eq!(told(&mut watching), [("parted", a1)]);
        assert_eq!(rows(&core).len(), 1);
    }

    #[test]
    fn a_person_is_as_present_as_its_most_present_session() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        let status = |uid, s| core.roster.lock().unwrap().set_status(uid, s);
        status(a2, SessionStatus::Detached);
        assert_eq!(told(&mut watching), [], "the phone away, the desktop not");
        status(a1, SessionStatus::Detached);
        assert_eq!(told(&mut watching), [("changed", a1)]);
        assert_eq!(rows(&core)[1].2, SessionStatus::Detached);
        status(a2, SessionStatus::Active);
        assert_eq!(told(&mut watching), [("changed", a1)]);
        assert_eq!(rows(&core)[1].2, SessionStatus::Active);
    }

    #[test]
    fn only_a_persons_own_account_logged_in_as_its_linked_identity_is_grouped() {
        let other = [8; 32];
        for (what, on, identity, linked) in [
            ("coalescing off", false, Some(ALICE), Some(ALICE)),
            ("no identity", true, None, Some(ALICE)),
            (
                "an identity the account does not link",
                true,
                Some(ALICE),
                None,
            ),
            (
                "another identity than the linked one",
                true,
                Some(other),
                Some(ALICE),
            ),
        ] {
            let core = Core::new().with_coalesce(on);
            attach(&core, "alice", identity, linked);
            attach(&core, "alice", identity, linked);
            assert_eq!(rows(&core).len(), 2, "{what}");
        }
    }

    #[test]
    fn a_uid_names_the_person_by_its_row_and_nobody_by_a_grouped_sessions_own() {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert_eq!(core.user_details(a1).map(|d| d.info.uid), Some(a1));
        assert!(core.user_details(a2).is_none());
        core.end_session(a1);
        assert_eq!(
            core.user_details(a1).map(|d| d.info.uid),
            Some(a1),
            "the row outlives its first session"
        );
    }

    #[test]
    fn a_row_is_given_to_nobody_else_while_its_person_lives() {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (_a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        core.end_session(a1);
        core.roster.lock().unwrap().last_uid = a1 - 1;
        let (next, _rx) = attach(&core, "bob", None, None);
        assert_ne!(next, a1);
    }

    #[test]
    fn a_line_from_any_of_a_persons_sessions_is_the_rows() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        core.chat_public(a2, "from the phone".into(), 0, None)
            .unwrap();
        let from: Vec<Uid> = drain(&mut watching)
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { from, .. } => Some(from.uid),
                _ => None,
            })
            .collect();
        assert_eq!(from, [a1]);
    }

    #[test]
    fn a_device_ending_leaves_its_person_in_its_chats() {
        let core = Core::new().with_coalesce(true);
        let (bob, _rxb) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (cid, _) = core.chat_create(a1, bob).unwrap();
        core.end_session(a1);
        assert_eq!(core.chats_of(a2), [cid]);
    }

    #[test]
    fn a_message_to_a_persons_row_reaches_each_of_its_sessions_from_the_row() {
        let core = Core::new().with_coalesce(true);
        let (bob, mut to_bob) = attach(&core, "bob", None, None);
        let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, mut rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let msgs = |rx: &mut Events| -> Vec<Uid> {
            drain(rx)
                .into_iter()
                .filter_map(|e| match e {
                    Event::Msg { from, .. } => Some(from),
                    _ => None,
                })
                .collect()
        };
        core.msg(bob, a1, "hi alice".into(), None, None).unwrap();
        assert_eq!((msgs(&mut rx1), msgs(&mut rx2)), (vec![bob], vec![bob]));
        core.msg(a2, bob, "hi bob".into(), None, None).unwrap();
        assert_eq!(
            msgs(&mut to_bob),
            [a1],
            "from the row, so a reply reaches her"
        );
        assert!(
            core.msg(bob, a2, "x".into(), None, None).is_err(),
            "a device's own uid names nobody"
        );
    }

    #[test]
    fn a_session_is_told_its_row_and_finds_itself_by_its_own_uid() {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert_eq!(core.user(a2).map(|u| u.uid), Some(a1));
        assert_eq!(core.own_details(a2).map(|d| d.login), Some("alice".into()));
        assert!(core.user_details(a2).is_none());
    }

    #[test]
    fn a_message_from_a_device_to_its_own_row_is_from_nobody() {
        let core = Core::new().with_coalesce(true);
        let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut rx1);
        core.msg(a2, a1, "note to self".into(), None, None).unwrap();
        let from: Vec<Uid> = drain(&mut rx1)
            .into_iter()
            .filter_map(|e| match e {
                Event::Msg { from, .. } => Some(from),
                _ => None,
            })
            .collect();
        assert_eq!(from, [0]);
    }

    #[test]
    fn a_session_under_another_identity_of_the_login_stands_apart() {
        let core = Core::new().with_coalesce(true);
        let relinked = [9; 32];
        attach(&core, "alice", Some(ALICE), Some(ALICE));
        attach(&core, "alice", Some(relinked), Some(relinked));
        assert_eq!(rows(&core).len(), 2);
    }
}
