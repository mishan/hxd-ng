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
    /// What the links know of it: one user, whichever devices it has.
    link: crate::server_link::PersonLink,
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
        /// Its leaving crosses the links as a ban.
        banned: bool,
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
    /// person's own account, logged in to as the identity linked to it
    /// or, where its file says `personal`, with no identity at all, and
    /// not the system account or a messenger session. Comparing with the
    /// account's link keeps a session under a key it does not link apart
    /// (a guest's identity login, or a snapshot taken before a link
    /// changed). A mask does not set a session apart: it is the person's
    /// (`Core::set_session_mask`).
    fn coalesces(&self, sess: &UserSession) -> bool {
        self.persons.on
            && sess.is_person
            && !sess.system
            && !sess.info.transport.messenger_session
            && sess.account.as_ref().is_some_and(|a| {
                a.identity.fingerprint == sess.identity
                    && (a.identity.fingerprint.is_some() || a.config.personal)
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
        // A personal account's row may hold password devices with no
        // identity beside ones carrying the link made since: those agree.
        // Any two identities that differ do not, whichever member has one.
        let personal = sess.account.as_ref().is_some_and(|a| a.config.personal);
        let forming = self.persons.forming.get(&login).copied();
        let other_identity = forming
            .and_then(|row| self.persons.by_row.get(&row))
            .is_some_and(|p| {
                let mut members = p.members.iter().filter_map(|m| self.users.get(m));
                if personal {
                    identity.is_some()
                        && members.any(|m| m.identity.is_some() && m.identity != identity)
                } else {
                    members
                        .next()
                        .is_some_and(|front| front.identity != identity)
                }
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
                        link: Default::default(),
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
        // Its leaving crosses the links as a ban if any device's did.
        p.link.banned |= sess.banned;
        if p.members.is_empty() {
            let p = self.persons.by_row.remove(&row).expect("got above");
            if self.persons.forming.get(&p.login) == Some(&row) {
                self.persons.forming.remove(&p.login);
            }
            return Left::Last {
                row,
                banned: p.link.banned,
            };
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
    pub(crate) fn person_view(&self, row: Uid) -> Option<UserInfo> {
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
        // password session of a linked account shows none of its own, and
        // a personal account's row shows the identity linked since (§12 J).
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

    /// The person a row uid names, for what the links know of it.
    pub(crate) fn person_link(&self, row: Uid) -> Option<&crate::server_link::PersonLink> {
        self.persons.by_row.get(&row).map(|p| &p.link)
    }

    pub(crate) fn person_link_mut(
        &mut self,
        row: Uid,
    ) -> Option<&mut crate::server_link::PersonLink> {
        self.persons.by_row.get_mut(&row).map(|p| &mut p.link)
    }

    /// Whether person `row` is being kicked.
    pub(crate) fn row_ending(&self, row: Uid) -> bool {
        self.persons.by_row.get(&row).is_some_and(|p| p.ending)
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
pub(crate) mod tests;
