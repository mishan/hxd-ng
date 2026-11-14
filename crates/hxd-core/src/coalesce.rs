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
    login: String,
    /// Live members, in the order they joined; the first is the one listed.
    pub(crate) members: Vec<Uid>,
    /// The row as the roster was last told it, so a member's coming or
    /// going tells nobody anything unless the row changed.
    told: UserInfo,
    /// Being kicked: every member is on its way out, and a login of its
    /// own forms a person of its own.
    ending: bool,
    /// Its chat lines and spam points, spent by every member.
    pub(crate) flood: crate::limits::Flood,
}

/// The people on the roster, by row.
#[derive(Default)]
pub(crate) struct Persons {
    pub(crate) on: bool,
    by_row: HashMap<Uid, Coalesced>,
    /// The person a login's sessions join as they announce.
    forming: HashMap<String, Uid>,
    /// Each grouped session's row.
    of: HashMap<Uid, Uid>,
}

/// What a session last sent of itself.
#[derive(Debug, Clone, Default)]
pub(crate) struct Sent {
    pub(crate) nick: String,
    pub(crate) icon: u16,
    pub(crate) color: Option<u32>,
}

impl Sent {
    pub(crate) fn note(
        &mut self,
        nick: Option<&str>,
        icon: Option<u16>,
        color: Option<Option<u32>>,
    ) {
        if let Some(n) = nick {
            n.clone_into(&mut self.nick);
        }
        if let Some(i) = icon {
            self.icon = i;
        }
        if let Some(c) = color {
            self.color = c;
        }
    }
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
    /// and not the system account or a messenger session. A mask does not
    /// set a session apart: it is the person's (`Core::set_session_mask`).
    fn coalesces(&self, sess: &UserSession) -> bool {
        self.persons.on
            && sess.is_person
            && !sess.system
            && !sess.info.transport.messenger_session
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
        let forming = self.persons.forming.get(&login).copied();
        let other_identity = forming
            .and_then(|row| self.persons.by_row.get(&row))
            .is_some_and(|p| {
                p.members
                    .first()
                    .and_then(|m| self.users.get(m))
                    .is_some_and(|front| front.identity != identity)
            });
        if other_identity {
            return Joined::Alone;
        }
        self.users.get_mut(&uid).expect("got above").grouped = true;
        // The person's name and look, written through: what the joiner
        // logged in with is its own to send, not the person's.
        let front = forming
            .and_then(|row| self.persons.by_row.get(&row))
            .and_then(|p| p.members.first())
            .and_then(|m| self.users.get(m))
            .map(|f| (f.info.nick.clone(), f.info.icon, f.info.color));
        if let Some((nick, icon, color)) = front {
            let joiner = &mut self.users.get_mut(&uid).expect("got above").info;
            (joiner.nick, joiner.icon, joiner.color) = (nick, icon, color);
        }
        match forming {
            Some(row) => {
                self.persons.of.insert(uid, row);
                if let Some(p) = self.persons.by_row.get_mut(&row) {
                    p.members.push(uid);
                }
                Joined::Another(self.retell(row).map(Box::new))
            }
            None => {
                self.persons.forming.insert(login.clone(), uid);
                self.persons.of.insert(uid, uid);
                self.persons.by_row.insert(
                    uid,
                    Coalesced {
                        login,
                        members: vec![uid],
                        told: info,
                        ending: false,
                        flood: Default::default(),
                    },
                );
                // As the roster is told it: the row, not the raw session.
                if let Some(view) = self.person_view(uid) {
                    if let Some(p) = self.persons.by_row.get_mut(&uid) {
                        p.told = view;
                    }
                }
                Joined::First
            }
        }
    }

    /// Take `sess`, just removed from the roster as `uid`, out of its person.
    pub(crate) fn coalesce_leave(&mut self, uid: Uid, sess: &UserSession) -> Left {
        if !sess.grouped {
            return Left::Alone;
        }
        let Some(row) = self.persons.of.remove(&uid) else {
            return Left::Alone;
        };
        let Some(p) = self.persons.by_row.get_mut(&row) else {
            return Left::Alone;
        };
        p.members.retain(|m| *m != uid);
        if p.members.is_empty() {
            let p = self.persons.by_row.remove(&row).expect("got above");
            if self.persons.forming.get(&p.login) == Some(&row) {
                self.persons.forming.remove(&p.login);
            }
            return Left::Last { row };
        }
        Left::Stays {
            row,
            changed: self.retell(row).map(Box::new),
        }
    }

    /// `info`, a row about to be told: a person's as it stands now, and
    /// noted as told, so a later change compares with what was sent.
    pub(crate) fn row_now(&mut self, info: UserInfo) -> UserInfo {
        let Some(view) = self.person_view(info.uid) else {
            return info;
        };
        if let Some(p) = self.persons.by_row.get_mut(&info.uid) {
            p.told = view.clone();
        }
        view
    }

    /// The person's row as it stands, if it is not as the roster was told.
    fn retell(&mut self, row: Uid) -> Option<Event> {
        // A person being kicked is told once, as it parts.
        if self.persons.by_row.get(&row)?.ending {
            return None;
        }
        let view = self.person_view(row)?;
        let p = self.persons.by_row.get_mut(&row)?;
        (p.told != view).then(|| {
            p.told = view.clone();
            Event::Changed(view)
        })
    }

    /// The row a person is shown as: its first member's, under its uid,
    /// as present as any of them.
    fn person_view(&self, row: Uid) -> Option<UserInfo> {
        let p = self.persons.by_row.get(&row)?;
        let front = self.users.get(p.members.first()?)?;
        let mut info = front.info.clone();
        info.uid = row;
        // As safe as its least safe device, and signing only if all do.
        let members: Vec<&UserSession> =
            p.members.iter().filter_map(|m| self.users.get(m)).collect();
        info.transport.encrypted = members.iter().all(|s| s.info.transport.encrypted);
        info.transport.assumed = members.iter().any(|s| s.info.transport.assumed);
        let signs = members
            .iter()
            .all(|s| s.info.transport.identity.as_ref().is_some_and(|i| i.signs));
        // Sealed to by device, which the row is not.
        // The person's identity, from whichever device shows one: a
        // password session of a linked account shows none of its own.
        info.transport.identity = members
            .iter()
            .find_map(|s| s.info.transport.identity.clone())
            .map(|mut identity| {
                identity.sealed = None;
                identity.device_cert = None;
                identity.signs = signs;
                identity
            });
        info.status = p
            .members
            .iter()
            .filter_map(|m| self.users.get(m))
            .map(|s| s.info.status)
            .min_by_key(|s| rank(*s))
            .unwrap_or(info.status);
        Some(info)
    }

    /// A change `uid`, one of a person's sessions, sent of itself. What it
    /// sent before is no change (a classic client sends its own again at
    /// every login and reconnect); the rest is the person's, written to
    /// every member. The row as told again, if it changed.
    pub(crate) fn person_update(
        &mut self,
        uid: Uid,
        nick: Option<String>,
        icon: Option<u16>,
        color: Option<Option<u32>>,
    ) -> Option<Event> {
        let sess = self.users.get_mut(&uid)?;
        let nick = nick.filter(|n| *n != sess.sent.nick);
        let icon = icon.filter(|i| *i != sess.sent.icon);
        let color = color.filter(|c| *c != sess.sent.color);
        sess.sent.note(nick.as_deref(), icon, color);
        let row = self.row_uid(uid);
        let members = self
            .person_members(row)
            .map(<[Uid]>::to_vec)
            .unwrap_or_default();
        for m in members {
            let Some(info) = self.users.get_mut(&m).map(|s| &mut s.info) else {
                continue;
            };
            if let Some(n) = &nick {
                info.nick.clone_from(n);
            }
            if let Some(i) = icon {
                info.icon = i;
            }
            if let Some(c) = color {
                info.color = c;
            }
        }
        self.retell(row)
    }

    /// Tell the roster of a change to a row: a person's to everyone else
    /// as its row, and to each of its own sessions as that session's own
    /// view of it (its status, transport and identity), once.
    pub(crate) fn tell_row(&mut self, ev: Event) {
        self.tell_row_where(ev, |_| true);
    }

    /// [`Self::tell_row`], to the sessions `pred` admits.
    pub(crate) fn tell_row_where(&mut self, ev: Event, pred: impl Fn(&UserSession) -> bool) {
        let members = match &ev {
            Event::Changed(info) => self.person_members(info.uid).map(<[Uid]>::to_vec),
            _ => None,
        };
        let Some(members) = members else {
            self.broadcast_where(&ev, None, pred);
            return;
        };
        self.broadcast_where(&ev, None, |s| !members.contains(&s.info.uid) && pred(s));
        for m in members {
            let own = self
                .own_row(m)
                .filter(|_| self.users.get(&m).is_some_and(&pred));
            if let Some(own) = own {
                self.send_to(m, Event::Changed(own));
            }
        }
    }

    /// `uid`'s own view of its row, a grouped session's: its person's,
    /// with its own status, transport and identity.
    pub(crate) fn own_row(&self, uid: Uid) -> Option<UserInfo> {
        let sess = self.users.get(&uid).filter(|s| s.grouped)?;
        Some(UserInfo {
            uid: self.row_uid(uid),
            ..sess.info.clone()
        })
    }

    /// `sess` as the wire shows it: its person's row, or its own.
    pub(crate) fn row_view(&self, sess: &UserSession) -> UserInfo {
        if sess.grouped {
            if let Some(view) = self.person_view(self.row_uid(sess.info.uid)) {
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
                .person_members(self.row_uid(uid))
                .is_none_or(|m| m.first() == Some(&uid))
    }

    /// What to tell the roster of a change to `uid`: its own row, or its
    /// person's if that changed.
    pub(crate) fn changed_event(&mut self, uid: Uid) -> Option<Event> {
        let sess = self.users.get(&uid).filter(|s| s.live())?;
        if sess.grouped {
            return self.retell(self.row_uid(uid));
        }
        Some(Event::Changed(sess.info.clone()))
    }

    /// The person a row uid stands for, and its members.
    pub(crate) fn person_members(&self, row: Uid) -> Option<&[Uid]> {
        self.persons.by_row.get(&row).map(|p| p.members.as_slice())
    }

    /// The row `session` is shown under.
    pub(crate) fn row_uid(&self, session: Uid) -> Uid {
        self.persons.of.get(&session).copied().unwrap_or(session)
    }

    /// Whether `uid` is one of a person's sessions and not its last.
    pub(crate) fn person_stays(&self, uid: Uid) -> bool {
        self.person_members(self.row_uid(uid))
            .is_some_and(|m| m.len() > 1)
    }

    /// Whether `uid` is a device of a person being kicked.
    pub(crate) fn ending(&self, uid: Uid) -> bool {
        self.persons
            .of
            .get(&uid)
            .and_then(|row| self.persons.by_row.get(row))
            .is_some_and(|p| p.ending)
    }

    /// Mark `uid`'s person as being kicked: from here every member is on
    /// its way out, and a login of the account forms a person of its own.
    /// The sessions to end: every member, or `uid` alone for a session
    /// alone.
    pub(crate) fn person_ending(&mut self, uid: Uid) -> Vec<Uid> {
        let Some(row) = self.persons.of.get(&uid).copied() else {
            return vec![uid];
        };
        let Some(p) = self.persons.by_row.get_mut(&row) else {
            return vec![uid];
        };
        p.ending = true;
        if self.persons.forming.get(&p.login) == Some(&row) {
            self.persons.forming.remove(&p.login);
        }
        p.members.clone()
    }

    /// Give `uid`, just joined to its person, the person's mask, told as
    /// a mask set on it is. Taken rather than required: a session logs in
    /// with no mask, and a mask set on the person is the new device's too.
    pub(crate) fn take_persons_mask(&mut self, uid: Uid) {
        let Some(front) = self
            .person_members(self.row_uid(uid))
            .and_then(|m| m.first())
        else {
            return;
        };
        let Some(mask) = self.users.get(front).map(|s| s.mask) else {
            return;
        };
        let Some(account) = self
            .users
            .get_mut(&uid)
            .filter(|s| s.mask != mask)
            .and_then(|s| {
                s.mask = mask;
                s.account.clone()
            })
        else {
            return;
        };
        // The person's row is its first device's, which this mask
        // already shows; nor does a mask change a role color.
        let _ = crate::admin::give_account(self, uid, &account, None);
    }

    /// The budgets `uid` spends: its person's, or its own.
    pub(crate) fn flood_of(&mut self, uid: Uid) -> Option<&mut crate::limits::Flood> {
        if let Some(row) = self.persons.of.get(&uid).copied() {
            if let Some(p) = self.persons.by_row.get_mut(&row) {
                return Some(&mut p.flood);
            }
        }
        self.users.get_mut(&uid).map(|s| &mut s.flood)
    }

    /// Whether `target`, a uid a client names, is `kicker`'s own person.
    pub(crate) fn is_own_row(&self, kicker: Uid, target: Uid) -> bool {
        self.persons.of.get(&kicker) == Some(&target)
    }

    /// The rows whose own sessions have ended, which no session holds.
    pub(crate) fn rows_alone(&self) -> usize {
        self.persons
            .by_row
            .keys()
            .filter(|row| !self.users.contains_key(row))
            .count()
    }

    /// Whether `uid` is a person's row, held while the person lives.
    pub(crate) fn is_row(&self, uid: Uid) -> bool {
        self.persons.by_row.contains_key(&uid)
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        attach_on(core, login, identity, linked, Transport::default())
    }

    fn attach_on(
        core: &Core,
        login: &str,
        identity: Option<[u8; 32]>,
        linked: Option<[u8; 32]>,
        transport: Transport,
    ) -> (Uid, Events) {
        let (uid, rx) = core
            .attach(session(login, identity, linked, transport))
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    /// One of alice's devices, as `f` makes it, announced or not.
    pub(crate) fn alice(
        core: &Core,
        announce: bool,
        f: impl FnOnce(&mut AttachInfo),
    ) -> (Uid, Events) {
        let mut info = session("alice", Some(ALICE), Some(ALICE), Transport::default());
        f(&mut info);
        let (uid, rx) = core.attach(info).unwrap();
        if announce {
            core.announce(uid);
        }
        (uid, rx)
    }

    pub(crate) fn at(addr: &str) -> impl FnOnce(&mut AttachInfo) + '_ {
        move |i| i.addr = Some(addr.parse().unwrap())
    }

    fn moderated() -> Core {
        Core::new()
            .with_moderation(
                std::sync::Arc::new(crate::moderation::MemoryModeration::default()),
                crate::moderation::ModerationPolicy::default(),
            )
            .with_coalesce(true)
    }

    pub(crate) fn session(
        login: &str,
        identity: Option<[u8; 32]>,
        linked: Option<[u8; 32]>,
        transport: Transport,
    ) -> AttachInfo {
        let link = IdentityLink {
            fingerprint: linked,
            ..IdentityLink::default()
        };
        let account = Account::new(
            login.into(),
            login.into(),
            true,
            link,
            AccountConfig {
                access: chatting(),
                ..AccountConfig::default()
            },
        );
        AttachInfo {
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
            transport,
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
        }
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

    #[test]
    fn a_nick_a_device_sends_again_is_no_rename_and_a_new_one_renames_the_person() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        let nick = |uid| core.user(uid).map(|u| u.nick);
        assert!(
            !core.update(a2, Some("alice".into()), None),
            "its login nick again"
        );
        assert!(core.update(a2, Some("Ally".into()), None));
        assert_eq!(told(&mut watching), [("changed", a1)]);
        assert_eq!(
            (nick(a1), nick(a2)),
            (Some("Ally".into()), Some("Ally".into()))
        );
        assert!(
            !core.update(a1, Some("alice".into()), None),
            "what a1 itself last sent"
        );
        assert_eq!(rows(&core)[1].1, "Ally");
        assert!(
            core.update(a1, Some("alice".into()), Some(2)),
            "its icon is new"
        );
        assert_eq!(rows(&core)[1].1, "Ally", "but its nick still is not");

        let (a3, _rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert_eq!(
            nick(a3),
            Some("Ally".into()),
            "a new device takes the person's"
        );
        assert_eq!(told(&mut watching), [("changed", a1)], "the icon only");
    }

    #[test]
    fn a_device_going_away_alone_is_told_its_own_status_and_nobody_else_anything() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, mut rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        drain(&mut rx2);
        core.roster
            .lock()
            .unwrap()
            .set_status(a2, SessionStatus::Idle);
        assert_eq!(told(&mut watching), []);
        assert!(drain(&mut rx2).iter().any(
            |e| matches!(e, Event::Changed(u) if u.uid == a1 && u.status == SessionStatus::Idle)
        ));
    }

    #[test]
    fn a_rename_from_one_device_reaches_the_links_for_each() {
        let core = Core::new().with_coalesce(true);
        let mut feed = core.peer_feed(16);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert!(core.update(a2, Some("Ally".into()), None));
        let mut renamed = vec![];
        while let Ok((_, e)) = feed.try_recv() {
            if let crate::server_link::PeerEvent::Changed(u) = e {
                renamed.push((u.uid, u.nick));
            }
        }
        renamed.sort();
        assert_eq!(renamed, [(a1, "Ally".into()), (a2, "Ally".into())]);
    }

    #[test]
    fn a_kick_ends_every_device_and_tells_the_roster_once() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let tls = Transport {
            encrypted: true,
            ..Transport::default()
        };
        let (a2, mut rx2) = attach_on(&core, "alice", Some(ALICE), Some(ALICE), tls);
        drain(&mut watching);
        core.kick(a1, None).unwrap();
        assert!(drain(&mut rx1).contains(&Event::Kicked));
        assert!(drain(&mut rx2).contains(&Event::Kicked));
        // Its devices go as their connections close: the safer one left
        // alone for a moment is no change worth telling.
        core.end_session(a1);
        core.end_session(a2);
        assert_eq!(told(&mut watching), [("parted", a1)]);
    }

    #[test]
    fn a_login_while_its_person_is_kicked_is_a_person_of_its_own() {
        let core = Core::new().with_coalesce(true);
        let (bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        let begun = core.kick_begin(a1, false).unwrap();
        let (a3, mut rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        core.kick_end(begun, None);
        assert!(!drain(&mut rx3).contains(&Event::Kicked));
        core.end_session(a1);
        core.end_session(a2);
        assert_eq!(told(&mut watching), [("joined", a3), ("parted", a1)]);
        let listed: Vec<Uid> = rows(&core).into_iter().map(|r| r.0).collect();
        assert_eq!(listed, [bob, a3]);
    }

    fn chatting() -> AccessBits {
        AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT)
    }

    /// The mask the tests set: no sending to public chat, and no
    /// disconnecting users, which the row shows as its admin flag.
    fn muted() -> crate::DenyMask {
        crate::DenyMask {
            access: AccessBits::empty()
                .with(bit::SEND_CHAT)
                .with(bit::DISCONNECT_USERS),
            ..Default::default()
        }
    }

    /// One of alice's devices whose account may disconnect users.
    fn admin(i: &mut AttachInfo) {
        let access = chatting().with(bit::DISCONNECT_USERS);
        let link = IdentityLink {
            fingerprint: Some(ALICE),
            ..IdentityLink::default()
        };
        let config = AccountConfig {
            access,
            ..AccountConfig::default()
        };
        let account = Account::new("alice".into(), "alice".into(), true, link, config);
        i.account = Some(Box::new(account));
        i.access = access;
        i.admin = true;
    }

    /// The admin flag of the rows `rx` was told changed, in order.
    fn admins(rx: &mut Events) -> Vec<bool> {
        drain(rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Changed(u) => Some(u.admin),
                _ => None,
            })
            .collect()
    }

    fn sends(core: &Core, uid: Uid) -> bool {
        core.access_of(uid).is_some_and(|a| a.has(bit::SEND_CHAT))
    }

    fn told_account(rx: &mut Events) -> Option<bool> {
        drain(rx).into_iter().rev().find_map(|e| match e {
            Event::AccountChanged(a) => Some(a.access.has(bit::SEND_CHAT)),
            _ => None,
        })
    }

    #[test]
    fn a_masked_session_still_joins_its_person() {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = alice(&core, true, |_| {});
        let (a2, _rx2) = alice(&core, false, |_| {});
        assert!(core.set_session_mask(a2, muted()));
        core.announce(a2);
        assert_eq!(core.row_uid(a2), a1);
        // A mask is the person's, so the person's replaces its own.
        assert_eq!(core.mask_of(a2), crate::DenyMask::default());
    }

    #[test]
    fn a_device_joining_a_masked_person_is_told_its_row_as_masked() {
        let core = Core::new().with_coalesce(true);
        let tls = |i: &mut AttachInfo| {
            admin(i);
            i.transport.encrypted = true;
        };
        let (a1, _rx1) = alice(&core, true, tls);
        assert!(core.set_session_mask(a1, muted()));
        // A plain device makes the row less safe: it is told the row.
        let (_a2, mut rx2) = alice(&core, true, admin);
        assert_eq!(admins(&mut rx2), [false]);
    }

    #[test]
    fn a_mask_set_on_a_row_whose_own_device_left_masks_the_person() {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = alice(&core, true, |_| {});
        let (a2, _rx2) = alice(&core, true, |_| {});
        core.end_session(a1);
        assert!(core.set_session_mask(a1, muted()));
        assert_eq!(core.mask_of(a2), muted());
        assert!(!sends(&core, a2));
    }

    #[test]
    fn a_mask_on_one_device_is_its_persons_and_lifts_from_every_device() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, mut rx1) = alice(&core, true, admin);
        let (a2, mut rx2) = alice(&core, true, admin);
        drain(&mut watching);
        assert!(core.set_session_mask(a2, muted()));
        assert_eq!(admins(&mut watching), [false], "one change, the row's");
        assert_eq!((sends(&core, a1), sends(&core, a2)), (false, false));
        assert_eq!(core.mask_of(a1), muted());
        assert_eq!(
            told_account(&mut rx1),
            Some(false),
            "the other device is told"
        );
        assert_eq!(told_account(&mut rx2), Some(false));
        assert!(core.set_session_mask(a1, crate::DenyMask::default()));
        assert_eq!((sends(&core, a1), sends(&core, a2)), (true, true));
        assert_eq!(told_account(&mut rx2), Some(true));
        assert_eq!(admins(&mut watching), [true], "one change, the row's");
    }

    #[test]
    fn a_device_joining_a_masked_person_is_masked() {
        let core = Core::new().with_coalesce(true);
        let (a1, _rx1) = alice(&core, true, |_| {});
        assert!(core.set_session_mask(a1, muted()));
        let (a2, mut rx2) = alice(&core, true, |_| {});
        assert_eq!(core.mask_of(a2), muted());
        assert!(!sends(&core, a2));
        assert_eq!(told_account(&mut rx2), Some(false));
    }

    #[test]
    fn with_coalescing_off_a_mask_is_one_sessions() {
        let core = Core::new();
        let (a1, _rx1) = alice(&core, true, |_| {});
        assert!(core.set_session_mask(a1, muted()));
        let (a2, _rx2) = alice(&core, true, |_| {});
        assert_eq!((sends(&core, a1), sends(&core, a2)), (false, true));
        assert_eq!(core.mask_of(a2), crate::DenyMask::default());
    }

    /// Accounts whose identity is linked: every login names one, linked
    /// to alice's identity.
    struct Linked;

    impl crate::AccountDirectory for Linked {
        fn inbox_account(&self, login: &str) -> Option<crate::inbox::Mailbox> {
            Some(crate::inbox::Mailbox::identified(login, ALICE))
        }

        fn mailbox_access(&self, _: &crate::inbox::Mailbox) -> Option<AccessBits> {
            Some(AccessBits::empty())
        }
    }

    #[test]
    fn a_kick_ban_ends_another_account_of_the_identity_at_the_agreement() {
        let core = moderated().with_accounts(std::sync::Arc::new(Linked));
        let (a1, _rx1) = alice(&core, true, at("192.0.2.1"));
        let (_other, mut waiting) = core
            .attach(session(
                "ally",
                Some(ALICE),
                Some(ALICE),
                Transport::default(),
            ))
            .unwrap();
        let ban = crate::KickBan {
            by: crate::Actor::Operator,
            for_: std::time::Duration::from_secs(60),
            reason: "spam".into(),
        };
        assert!(core.kick_by(a1, Some(ban)).unwrap().banned);
        assert!(
            drain(&mut waiting).contains(&Event::Kicked),
            "the identity is banned with the login"
        );
    }

    #[test]
    fn a_person_being_kicked_is_told_no_change() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        let begun = core.kick_begin(a1, false).unwrap();
        core.update(a2, Some("Ally".into()), None);
        core.kick_end(begun, None);
        assert_eq!(told(&mut watching), []);
    }

    #[test]
    fn a_person_already_being_kicked_is_not_kicked_again() {
        for flood_first in [false, true] {
            let core = Core::new()
                .with_coalesce(true)
                .with_flood_limits(crate::FloodLimits {
                    chat_lines: 1,
                    chat_per: std::time::Duration::from_secs(60),
                    spam_points: 0,
                    spam_per: std::time::Duration::from_secs(60),
                    ban_for: std::time::Duration::ZERO,
                });
            let (_bob, mut watching) = attach(&core, "bob", None, None);
            let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
            let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
            drain(&mut watching);
            if flood_first {
                let _ = core.chat_public(a2, "one\rtwo".into(), 0, None);
            } else {
                core.kick(a1, None).unwrap();
            }
            assert_eq!(
                core.kick(a1, None),
                Err(crate::ChatError::NoSuchUser),
                "flood first {flood_first}"
            );
        }
    }

    #[test]
    fn a_kick_purging_hears_no_device_from_its_first_step_on() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        let kicked = core.kick_with(a1, None, |c| {
            c.chat_public(a2, "between the purge and the kick".into(), 0, None)
        });
        let (kicked, between) = kicked;
        assert!(kicked.is_ok());
        assert_eq!(between, Some(Err(crate::ChatError::Flooding)));
        assert!(drain(&mut rx1).contains(&Event::Kicked));
        assert!(!drain(&mut watching)
            .iter()
            .any(|e| matches!(e, Event::Chat { .. })));
    }

    #[test]
    fn a_kick_whose_purge_fails_or_panics_still_ends_every_device() {
        for panics in [false, true] {
            let core = Core::new().with_coalesce(true);
            let (a1, mut rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
            let (_a2, mut rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
            let kicked = core.kick_with(a1, None, |_| -> Result<(), &str> {
                assert!(!panics, "a purge that panics");
                Err("the store failed")
            });
            let (kicked, purged) = kicked;
            assert!(kicked.is_ok(), "panics {panics}");
            let expected = (!panics).then_some(Err("the store failed"));
            assert_eq!(purged, expected, "panics {panics}");
            for rx in [&mut rx1, &mut rx2] {
                assert!(drain(rx).contains(&Event::Kicked), "panics {panics}");
            }
        }
    }

    #[test]
    fn a_purge_asked_of_a_target_that_left_is_still_made() {
        let core = moderated().with_coalesce(false).with_history(
            std::sync::Arc::new(crate::history::MemoryLog::default()),
            Default::default(),
        );
        let (a1, _rx1) = alice(&core, true, |_| {});
        let line = core
            .chat_public(a1, "buy now".into(), 0, None)
            .unwrap()
            .expect("logged");
        let check = core
            .purge_check(crate::Actor::Operator, &crate::PersonRef::Uid(a1), "spam")
            .unwrap();
        core.end_session(a1);
        let within = std::time::Duration::from_secs(3600);
        let (kicked, purged) = core.kick_purging(a1, None, Some((check, within)));
        assert_eq!(kicked, Err(crate::ChatError::NoSuchUser));
        assert_eq!(purged, Some(true));
        let line = core.history.as_ref().unwrap().line(line).unwrap().unwrap();
        assert!(line.flags.contains(crate::history::LineFlags::DELETED));
    }

    #[test]
    fn a_purge_of_a_persons_row_kicks_it_once_its_first_device_is_gone() {
        let core = moderated();
        let (a1, _rx1) = alice(&core, true, |_| {});
        let (_a2, mut rx2) = alice(&core, true, |_| {});
        let check = core
            .purge_check(crate::Actor::Operator, &crate::PersonRef::Uid(a1), "spam")
            .unwrap();
        core.end_session(a1);
        let within = std::time::Duration::from_secs(3600);
        let (kicked, _) = core.kick_purging(a1, None, Some((check, within)));
        assert!(kicked.is_ok());
        assert!(drain(&mut rx2).contains(&Event::Kicked));
    }

    #[test]
    fn a_purge_the_store_fails_still_kicks_every_device() {
        let store = std::sync::Arc::new(crate::moderation::faulty::FaultyModeration::default());
        let core = Core::new()
            .with_moderation(
                store.clone(),
                crate::moderation::ModerationPolicy::default(),
            )
            .with_coalesce(true);
        let (a1, mut rx1) = alice(&core, true, |_| {});
        let (_a2, mut rx2) = alice(&core, true, |_| {});
        let check = core
            .purge_check(crate::Actor::Operator, &crate::PersonRef::Uid(a1), "spam")
            .unwrap();
        store.fail("record");
        let within = std::time::Duration::from_secs(3600);
        let (kicked, purged) = core.kick_purging(a1, None, Some((check, within)));
        assert!(kicked.is_ok());
        assert_eq!(purged, Some(false));
        for rx in [&mut rx1, &mut rx2] {
            assert!(drain(rx).contains(&Event::Kicked));
        }
    }

    #[test]
    fn a_kick_ban_never_ends_its_kicker_who_shares_the_identity() {
        let core = moderated().with_accounts(std::sync::Arc::new(Linked));
        let (a1, mut rx1) = alice(&core, true, at("192.0.2.1"));
        let mut kicker = session("mod", Some(ALICE), Some(ALICE), Transport::default());
        kicker.moderate = true;
        let (moderator, mut rx_mod) = core.attach(kicker).unwrap();
        core.announce(moderator);
        let ban = crate::KickBan {
            by: crate::Actor::Session(moderator),
            for_: std::time::Duration::from_secs(60),
            reason: "spam".into(),
        };
        assert!(core.kick_by(a1, Some(ban)).unwrap().banned);
        assert!(drain(&mut rx1).contains(&Event::Kicked));
        assert!(!drain(&mut rx_mod).contains(&Event::Kicked), "the kicker");
        let bans = core.list_bans(true, None, 10).unwrap();
        assert!(
            !bans
                .iter()
                .any(|b| b.target == crate::ban::BanTarget::Identity(ALICE)),
            "the kicker's own identity, banned: {bans:?}"
        );
    }

    #[test]
    fn a_person_being_kicked_says_nothing_more() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        drain(&mut watching);
        let begun = core.kick_begin(a1, false).unwrap();
        assert_eq!(
            core.chat_public(a2, "a last word".into(), 0, None),
            Err(crate::ChatError::Flooding)
        );
        core.kick_end(begun, None);
        assert!(!drain(&mut watching)
            .iter()
            .any(|e| matches!(e, Event::Chat { .. })));
    }

    #[test]
    fn a_person_is_protected_whichever_device_holds_its_row() {
        let protected = |i: &mut AttachInfo| i.access = i.access.with(bit::CANT_BE_DISCONNECTED);
        for ended in [None, Some(0), Some(1)] {
            let core = Core::new().with_coalesce(true);
            let (a1, _rx1) = alice(&core, true, protected);
            let (a2, _rx2) = alice(&core, true, protected);
            let devices = [a1, a2];
            if let Some(i) = ended {
                core.end_session(devices[i]);
            }
            assert!(
                core.access_of(a1)
                    .is_some_and(|a| a.has(bit::CANT_BE_DISCONNECTED)),
                "the row, with device {ended:?} ended"
            );
        }
    }

    /// How a test ends a person: a moderator's kick, with or without its
    /// ban, or a spam kick and the ban it asks for.
    #[derive(Debug, Clone, Copy)]
    enum Kick {
        Plain,
        Banned,
        Spam,
    }

    #[test]
    fn a_kick_ends_every_live_device_and_its_ban_one_still_at_the_agreement() {
        use Kick::*;
        // Each device: announced (live) or still at the agreement, and
        // whether the kick ends it.
        for (devices, how) in [
            (&[(true, true)][..], Plain),
            (&[(true, true)][..], Banned),
            (&[(true, true)][..], Spam),
            (&[(true, true), (true, true)][..], Plain),
            (&[(true, true), (true, true)][..], Banned),
            (&[(true, true), (true, true)][..], Spam),
            (&[(true, true), (false, false)][..], Plain),
            (&[(true, true), (false, true)][..], Banned),
            (&[(true, true), (false, true)][..], Spam),
        ] {
            let core = moderated().with_flood_limits(crate::FloodLimits {
                spam_points: 1,
                ..crate::FloodLimits::MHXD
            });
            let (_bob, mut watching) = attach(&core, "bob", None, None);
            let mut sessions: Vec<(Uid, Events)> = devices
                .iter()
                .enumerate()
                .map(|(i, (live, _))| alice(&core, *live, at(["192.0.2.1", "198.51.100.1"][i])))
                .collect();
            drain(&mut watching);
            let first = sessions[0].0;
            match how {
                Plain => drop(core.kick(first, None).unwrap()),
                Banned => {
                    let ban = crate::KickBan {
                        by: crate::Actor::Operator,
                        for_: std::time::Duration::from_secs(60),
                        reason: "spam".into(),
                    };
                    assert!(core.kick_by(first, Some(ban)).unwrap().banned);
                }
                Spam => {
                    let flooded = core.spend_spam(first, 1, 105).unwrap_err();
                    core.place_spam_ban(flooded.ban.expect("a ban to place"));
                }
            }
            for (i, ((_, ends), (uid, rx))) in devices.iter().zip(&mut sessions).enumerate() {
                assert_eq!(
                    drain(rx).contains(&Event::Kicked),
                    *ends,
                    "{how:?} of {devices:?}: device {i}"
                );
                if *ends {
                    core.end_session(*uid);
                }
            }
            let parted = told(&mut watching)
                .into_iter()
                .filter(|(kind, _)| *kind == "parted")
                .collect::<Vec<_>>();
            assert_eq!(parted, [("parted", first)], "{how:?} of {devices:?}");
        }
    }

    #[test]
    fn a_kicked_persons_row_is_held_and_its_next_login_is_a_row_of_its_own() {
        let core = Core::new().with_coalesce(true);
        let (bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        core.kick(a1, None).unwrap();
        core.end_session(a1);
        core.end_session(a2);
        assert!(core.roster.lock().unwrap().freed_uids.holds(a1));
        drain(&mut watching);
        let (a3, _rx3) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert!(![a1, a2].contains(&a3), "a held uid given out: {a3}");
        assert_eq!(told(&mut watching), [("joined", a3)]);
        let listed: Vec<Uid> = rows(&core).into_iter().map(|r| r.0).collect();
        assert_eq!(listed, [bob, a3]);
    }

    #[test]
    fn a_ban_ends_the_devices_it_names_and_the_row_parts_with_the_last() {
        use crate::ban::BanTarget;
        let address = || BanTarget::address("192.0.2.1".parse().unwrap(), 32).unwrap();
        let one = ["192.0.2.1", "192.0.2.1"];
        let two = ["192.0.2.1", "198.51.100.1"];
        for (target, addrs, ended) in [
            (BanTarget::Login("alice".into()), one, [true, true]),
            (BanTarget::Login("alice".into()), two, [true, true]),
            (BanTarget::Identity(ALICE), one, [true, true]),
            (BanTarget::Identity(ALICE), two, [true, true]),
            (address(), one, [true, true]),
            (address(), two, [true, false]),
        ] {
            let core = moderated();
            let (_bob, mut watching) = attach(&core, "bob", None, None);
            let mut devices: Vec<(Uid, Events)> =
                addrs.iter().map(|a| alice(&core, true, at(a))).collect();
            let row = devices[0].0;
            drain(&mut watching);
            core.place_ban(
                crate::Actor::Operator,
                crate::ban::NewBan {
                    target: target.clone(),
                    reason: "spam".into(),
                    note: None,
                    expires_at: None,
                    source: crate::ban::BanSource::Cli,
                },
            )
            .unwrap();
            for ((uid, rx), ends) in devices.iter_mut().zip(ended) {
                assert_eq!(
                    drain(rx).contains(&Event::Kicked),
                    ends,
                    "{target:?} at {addrs:?}: {uid}"
                );
                if ends {
                    core.end_session(*uid);
                }
            }
            let parts = ended.iter().all(|e| *e);
            let expected: &[(&str, Uid)] = if parts { &[("parted", row)] } else { &[] };
            assert_eq!(told(&mut watching), expected, "{target:?} at {addrs:?}");
        }
    }

    #[test]
    fn a_person_floods_as_one_and_is_kicked_once() {
        for (spam, can_spam) in [(false, false), (true, false), (false, true), (true, true)] {
            let core = Core::new()
                .with_coalesce(true)
                .with_flood_limits(crate::FloodLimits {
                    chat_lines: 4,
                    chat_per: std::time::Duration::from_secs(60),
                    spam_points: 4,
                    spam_per: std::time::Duration::from_secs(60),
                    ban_for: std::time::Duration::ZERO,
                });
            let case = format!("spam {spam}, can_spam {can_spam}");
            let (_bob, mut watching) = attach(&core, "bob", None, None);
            let exempt = |i: &mut AttachInfo| i.can_spam = can_spam;
            let (a1, mut rx1) = alice(&core, true, exempt);
            let (a2, mut rx2) = alice(&core, true, exempt);
            drain(&mut watching);
            // Each device alone stays inside its budget.
            for _ in 0..3 {
                for uid in [a1, a2] {
                    if spam {
                        let _ = core.spend_spam(uid, 1, 105);
                    } else {
                        let _ = core.chat_public(uid, "hi".into(), 0, None);
                    }
                }
            }
            let notices = drain(&mut watching)
                .into_iter()
                .filter(|e| matches!(e, Event::Notice { .. }))
                .count();
            assert_eq!(notices, usize::from(!can_spam), "{case}");
            for rx in [&mut rx1, &mut rx2] {
                assert_eq!(drain(rx).contains(&Event::Kicked), !can_spam, "{case}");
            }
        }
    }

    #[test]
    fn with_coalescing_off_every_act_is_one_sessions_as_before() {
        let core = moderated()
            .with_coalesce(false)
            .with_flood_limits(crate::FloodLimits {
                chat_lines: 4,
                chat_per: std::time::Duration::from_secs(60),
                spam_points: 4,
                spam_per: std::time::Duration::from_secs(60),
                ban_for: std::time::Duration::ZERO,
            });
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let (a1, mut rx1) = alice(&core, true, at("192.0.2.1"));
        let (a2, mut rx2) = alice(&core, true, at("198.51.100.1"));
        assert_eq!(told(&mut watching), [("joined", a1), ("joined", a2)]);
        // Three lines and three points each: neither is past its own.
        for _ in 0..3 {
            for uid in [a1, a2] {
                let _ = core.chat_public(uid, "hi".into(), 0, None);
                let _ = core.spend_spam(uid, 1, 105);
            }
        }
        assert!(
            !core.kicks_own_row(a2, a1),
            "a session of one's own is anyone"
        );
        assert!(!drain(&mut rx1).contains(&Event::Kicked));
        let begun = core.kick_begin(a1, false).unwrap();
        assert!(
            core.chat_public(a2, "still here".into(), 0, None).is_ok(),
            "another session of the login is not being kicked"
        );
        core.kick_end(begun, None);
        assert!(drain(&mut rx1).contains(&Event::Kicked));
        assert!(!drain(&mut rx2).contains(&Event::Kicked));
        core.end_session(a1);
        drain(&mut watching);
        let (a3, mut rx3) = alice(&core, true, at("203.0.113.1"));
        let ban = crate::KickBan {
            by: crate::Actor::Operator,
            for_: std::time::Duration::from_secs(60),
            reason: "spam".into(),
        };
        assert!(core.kick_by(a2, Some(ban)).unwrap().banned);
        assert!(drain(&mut rx2).contains(&Event::Kicked));
        assert!(
            !drain(&mut rx3).contains(&Event::Kicked),
            "a kick's ban ends the session the kick does, and no other"
        );
        core.end_session(a2);
        assert_eq!(told(&mut watching), [("joined", a3), ("parted", a2)]);
    }

    #[test]
    fn a_kick_of_ones_own_row_is_refused_and_of_anyone_else_is_not() {
        let core = Core::new().with_coalesce(true);
        let (bob, _rxb) = attach(&core, "bob", None, None);
        let (a1, _rx1) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        let (a2, _rx2) = attach(&core, "alice", Some(ALICE), Some(ALICE));
        for (kicker, target, own) in [
            (a2, a1, true),
            (a1, a1, true),
            (bob, a1, false),
            (a1, bob, false),
            // A session alone kicks itself as it always could.
            (bob, bob, false),
        ] {
            assert_eq!(
                core.kicks_own_row(kicker, target),
                own,
                "{kicker} kicking {target}"
            );
        }
    }

    #[test]
    fn a_person_is_shown_as_safe_as_its_least_safe_device() {
        let core = Core::new().with_coalesce(true);
        let tls = Transport {
            encrypted: true,
            ..Transport::default()
        };
        attach_on(&core, "alice", Some(ALICE), Some(ALICE), tls);
        assert!(core.snapshot()[0].transport.encrypted);
        attach(&core, "alice", Some(ALICE), Some(ALICE));
        assert!(!core.snapshot()[0].transport.encrypted);
    }

    fn proved(signs: bool) -> Transport {
        Transport {
            identity: Some(crate::roster::IdentityTag {
                fingerprint: ALICE,
                device: [1; 32],
                handle: Some("alice@reg.example".into()),
                quiet_until: None,
                signs,
                can_sign: true,
                device_expires: 0,
                sealed: None,
                device_cert: None,
            }),
            ..Transport::default()
        }
    }

    #[test]
    fn a_person_shows_its_identity_whichever_device_is_first() {
        let core = Core::new().with_coalesce(true);
        // A password session of the linked account first, the key after.
        attach(&core, "alice", Some(ALICE), Some(ALICE));
        attach_on(&core, "alice", Some(ALICE), Some(ALICE), proved(true));
        let row = &core.snapshot()[0];
        let identity = row
            .transport
            .identity
            .as_ref()
            .expect("the person's identity");
        assert_eq!(identity.handle.as_deref(), Some("alice@reg.example"));
        assert!(!identity.signs, "one device does not sign");
    }

    #[test]
    fn each_of_a_persons_devices_is_told_its_own_view_of_the_row_once() {
        let core = Core::new().with_coalesce(true);
        let (_bob, mut watching) = attach(&core, "bob", None, None);
        let tls = Transport {
            encrypted: true,
            ..Transport::default()
        };
        let (a1, mut rx1) = attach_on(&core, "alice", Some(ALICE), Some(ALICE), tls);
        drain(&mut watching);
        drain(&mut rx1);
        attach(&core, "alice", Some(ALICE), Some(ALICE));
        let changed = |rx: &mut Events| -> Vec<(Uid, bool)> {
            drain(rx)
                .into_iter()
                .filter_map(|e| match e {
                    Event::Changed(u) => Some((u.uid, u.transport.encrypted)),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            changed(&mut watching),
            [(a1, false)],
            "the row, as safe as its least"
        );
        assert_eq!(changed(&mut rx1), [(a1, true)], "its own link, once");
    }
}
