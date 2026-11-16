//! A person's sessions as one row of the roster. With `[server] coalesce`
//! on, the sessions of one login whose identity is the account's linked
//! one share a row: its uid is the first session's, kept while any of
//! them lives; only the first live member is listed, under that uid and
//! the best status of them all; the roster is told of the person once, as
//! it joins and as its last session leaves. Each session keeps its own
//! uid, serial and outbox, and hears what the row hears.

use std::collections::HashMap;
use std::sync::Arc;

use unicode_normalization::UnicodeNormalization;

use crate::access::bit;
use crate::roster::{Event, RosterInner, SessionStatus, Uid, UserInfo, UserSession};

/// One device under a person's row, as a viewer that may see it is shown
/// it: the server's facts about it first, and the client's label, a hint
/// that decides nothing, last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device: u64,
    /// The ng wire, or the classic one.
    pub ng: bool,
    /// It proved the identity with its device key; otherwise it logged
    /// in with the account's password.
    pub proved: bool,
    pub encrypted: bool,
    pub status: SessionStatus,
    /// When it attached, as unix seconds.
    pub since: u64,
    pub label: Option<String>,
    pub sealed: bool,
    pub signs: bool,
}

/// The longest label kept, in characters.
pub const LABEL_MAX_CHARS: usize = 32;

/// What a client calls its device, as it may be shown: NFC, at most
/// [`LABEL_MAX_CHARS`], and held to hl-identity's rule for a name shown
/// beside a fingerprint, which is where a label sits too: something in
/// it, no space around it, nothing that renders as nothing or as
/// something else. A label that fails is dropped rather than refused: it
/// is a hint, so a login never fails over one.
pub fn device_label(raw: &str) -> Option<String> {
    // Far past what NFC could bring back under the bound: not worth
    // normalizing.
    if raw.chars().nth(4 * LABEL_MAX_CHARS).is_some() {
        return None;
    }
    let label: String = raw.nfc().collect();
    (label.chars().count() <= LABEL_MAX_CHARS && hl_identity::names::is_shown_name(&label))
        .then_some(label)
}

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
    /// Its devices as last told to the viewers that see them all, and to
    /// its password devices, which see only each other: a password of a
    /// linked account is enough to be grouped, so it is not enough to see
    /// or end the devices that proved the identity. A change neither saw
    /// tells nobody.
    told_all: Vec<Device>,
    told_password: Vec<Device>,
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
                        told_all: Vec::new(),
                        told_password: Vec::new(),
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
        // What the front's wire declared is the device's, never shown on
        // a row, so a change of front between wires is no change to it.
        info.transport.ng = false;
        info.transport.persons = false;
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
    /// view of it (its status, transport and identity), once. A session
    /// that may see the person's devices is told the row with them
    /// instead.
    pub(crate) fn tell_row(&mut self, ev: Event) {
        self.tell_row_where(ev, |_| true);
    }

    /// [`Self::tell_row`], to the sessions `pred` admits.
    pub(crate) fn tell_row_where(&mut self, ev: Event, pred: impl Fn(&UserSession) -> bool) {
        let members = match &ev {
            Event::Changed(info) => self.person_members(info.uid).map(<[Uid]>::to_vec),
            _ => None,
        };
        let (Some(members), Event::Changed(info)) = (members, &ev) else {
            self.broadcast_where(&ev, None, pred);
            return;
        };
        let row = info.uid;
        let seers = self.seers(row, |s| pred(s));
        self.broadcast_where(&ev, None, |s| {
            !members.contains(&s.info.uid)
                && !seers.iter().any(|(u, _)| *u == s.info.uid)
                && pred(s)
        });
        for m in members {
            if seers.iter().any(|(u, _)| *u == m) {
                continue;
            }
            let own = self
                .own_row(m)
                .filter(|_| self.users.get(&m).is_some_and(&pred));
            if let Some(own) = own {
                self.send_to(m, Event::Changed(own));
            }
        }
        self.tell_seers(row, info.clone(), &seers, false);
    }

    /// The sessions `pred` admits that may see `row`'s devices, with
    /// whether they see them all or its password devices alone.
    fn seers(&self, row: Uid, pred: impl Fn(&UserSession) -> bool) -> Vec<(Uid, bool)> {
        if !self.persons.by_row.contains_key(&row) {
            return Vec::new();
        }
        self.users
            .iter()
            .filter(|(_, s)| pred(s))
            .filter_map(|(uid, s)| self.devices_seen(s, row).map(|all| (*uid, all)))
            .collect()
    }

    /// Tell `seers` the row `user` with its devices as they stand, and
    /// note them as told.
    fn tell_seers(&mut self, row: Uid, user: UserInfo, seers: &[(Uid, bool)], joined: bool) {
        let all = self.devices_of(row);
        let password: Vec<Device> = all.iter().filter(|d| !d.proved).cloned().collect();
        let (all_arc, password_arc): (Arc<[Device]>, Arc<[Device]>) =
            (all.clone().into(), password.clone().into());
        for (uid, sees_all) in seers {
            let devices = if *sees_all {
                all_arc.clone()
            } else {
                password_arc.clone()
            };
            self.send_to(
                *uid,
                Event::PersonRow {
                    joined,
                    user: user.clone(),
                    devices,
                },
            );
        }
        if let Some(p) = self.persons.by_row.get_mut(&row) {
            p.told_all = all;
            p.told_password = password;
        }
    }

    /// Tell the sessions that see `row`'s devices of a change to them
    /// alone: a device came, went, or changed. Nobody else hears of it,
    /// so it costs no other session a seq.
    pub(crate) fn tell_devices(&mut self, row: Uid) {
        let Some(p) = self.persons.by_row.get(&row) else {
            return;
        };
        // A person being kicked is told once, as it parts.
        if p.ending {
            return;
        }
        let all = self.devices_of(row);
        let all_changed = p.told_all != all;
        let password_changed = p.told_password.iter().ne(all.iter().filter(|d| !d.proved));
        if !all_changed && !password_changed {
            return;
        }
        let Some(view) = self.person_view(row) else {
            return;
        };
        let seers: Vec<(Uid, bool)> = self
            .seers(row, |_| true)
            .into_iter()
            .filter(|(_, sees_all)| {
                if *sees_all {
                    all_changed
                } else {
                    password_changed
                }
            })
            .collect();
        self.tell_seers(row, view, &seers, false);
    }

    /// Tell the roster that `info`'s avatar changed: as
    /// [`Self::tell_row`] does a change, so a session that sees the
    /// devices under a person's row is told the row with them.
    pub(crate) fn tell_avatar(&mut self, info: UserInfo) {
        let row = info.uid;
        let seers = self.seers(row, |_| true);
        self.broadcast_where(&Event::AvatarChanged(info.clone()), None, |s| {
            !seers.iter().any(|(u, _)| *u == s.info.uid)
        });
        if !seers.is_empty() {
            self.tell_seers(row, info, &seers, false);
        }
    }

    /// Tell the roster that `uid`, just announced, joined: its own row,
    /// or its person's first, which the sessions that may see devices
    /// are told with its one device.
    pub(crate) fn tell_joined(&mut self, uid: Uid) {
        let view = self.row_view(&self.users[&uid]);
        let row = view.uid;
        let seers: Vec<(Uid, bool)> = self
            .seers(row, |_| true)
            .into_iter()
            .filter(|(u, _)| *u != uid)
            .collect();
        self.broadcast_where(&Event::Joined(view.clone()), Some(uid), |s| {
            !seers.iter().any(|(u, _)| *u == s.info.uid)
        });
        if self.persons.by_row.contains_key(&row) {
            self.tell_seers(row, view, &seers, true);
        }
    }

    /// Whether `viewer` may see the devices under `row`, and if so
    /// whether all of them or its password devices alone: its own
    /// person's, all of them where it proved the identity, and any
    /// person's, all of them, where it has the kick bit. Only for a
    /// session that declared `persons`, and only for a person's row.
    pub(crate) fn devices_seen(&self, viewer: &UserSession, row: Uid) -> Option<bool> {
        if !viewer.info.transport.persons || !viewer.live() {
            return None;
        }
        if !self.persons.by_row.contains_key(&row) {
            return None;
        }
        if self.persons.of.get(&viewer.info.uid) == Some(&row) {
            return Some(viewer.info.transport.identity.is_some());
        }
        viewer.access.has(bit::DISCONNECT_USERS).then_some(true)
    }

    /// The devices under `row`, in the order they joined it.
    pub(crate) fn devices_of(&self, row: Uid) -> Vec<Device> {
        self.person_members(row)
            .unwrap_or_default()
            .iter()
            .filter_map(|m| self.users.get(m))
            .map(|s| {
                let identity = s.info.transport.identity.as_ref();
                Device {
                    device: s.device,
                    ng: s.info.transport.ng,
                    proved: identity.is_some(),
                    encrypted: s.info.transport.encrypted,
                    status: s.info.status,
                    since: s.since,
                    label: s.label.clone(),
                    sealed: identity.is_some_and(|i| i.sealed.is_some()),
                    signs: identity.is_some_and(|i| i.signs),
                }
            })
            .collect()
    }

    /// The devices `viewer` is shown under `row`, if any.
    pub(crate) fn devices_for(&self, viewer: Uid, row: Uid) -> Option<Vec<Device>> {
        let all = self.devices_seen(self.users.get(&viewer)?, row)?;
        let mut devices = self.devices_of(row);
        if !all {
            devices.retain(|d| !d.proved);
        }
        Some(devices)
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
        let _ = crate::admin::give_account_as(self, uid, &account, None, false);
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

impl crate::roster::Core {
    /// Whether this server makes one row of a person's devices
    /// (`[server] coalesce`).
    pub fn groups_persons(&self) -> bool {
        self.roster.lock().unwrap().persons.on
    }

    /// Keep what `uid`'s client calls its device, as [`device_label`]
    /// lets it be shown; at login, before the device is announced.
    pub fn label_device(&self, uid: Uid, raw: &str) {
        let label = device_label(raw);
        let mut r = self.roster.lock().unwrap();
        if let Some(sess) = r.users.get_mut(&uid) {
            sess.label = label;
        }
    }

    /// `uid` as its own session is shown itself: the row the roster
    /// shows it under, with its device id, and for a session that
    /// declared `persons` and is one of a person's devices, the merged
    /// row and the devices it may see under it.
    pub fn self_view(&self, uid: Uid) -> Option<SelfView> {
        let r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid)?;
        let row = r.row_uid(uid);
        let persons = sess.info.transport.persons;
        let info = match r.person_view(row) {
            Some(view) if persons && sess.grouped => view,
            _ => UserInfo {
                uid: row,
                ..sess.info.clone()
            },
        };
        Some(SelfView {
            info,
            device: persons.then_some(sess.device),
            devices: r.devices_for(uid, row),
        })
    }

    /// The user list as `viewer` is shown it: the rows, and the devices
    /// under each person's row that it may see.
    pub fn roster_for(&self, viewer: Uid) -> (Vec<UserInfo>, HashMap<Uid, Vec<Device>>) {
        let r = self.roster.lock().unwrap();
        let rows = r.roster_rows_locked();
        let devices = rows
            .iter()
            .filter_map(|u| r.devices_for(viewer, u.uid).map(|d| (u.uid, d)))
            .collect();
        (rows, devices)
    }
}

/// What [`crate::roster::Core::self_view`] answers.
#[derive(Debug, Clone)]
pub struct SelfView {
    pub info: UserInfo,
    /// Its device id, for a session that declared `persons`.
    pub device: Option<u64>,
    /// The devices under its person's row it may see.
    pub devices: Option<Vec<Device>>,
}

#[cfg(test)]
pub(crate) mod tests;
