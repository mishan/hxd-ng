//! Revocation at this server (`docs/identity-registrar.md` §7.3): identity
//! and device fingerprints the operator has refused by hand, with no
//! registrar involved, and those refused by what the registrars this
//! server trusts publish (`docs/identity-records.md`). Either refuses.
//!
//! The only other remedy for a stolen device key is its certificate's
//! expiry, and for a stolen identity key a successor committed in
//! advance. This one works today, on the one server the operator runs.
//! Refusing the next login is half of it; the other half is that a key
//! revoked while its holder is connected, or detached and waiting to
//! resume, stops being on the roster at all — so installing a list ends
//! every session it now refuses.
//!
//! What is compared is the *transport* identity: the key a socket
//! proved, not the fingerprint an account is linked to. An account
//! whose linked identity is revoked can still be reached by its
//! password, because a password is not the key that was stolen.

use std::collections::{HashMap, HashSet};

use tracing::info;

use crate::ending::EndedBy;
use crate::push::Unrevoked;
use crate::roster::{is_buffering, Core, Event, IdentityTag, Uid, UserSession};

/// A device certificate as the lists judge it: the identity that signed
/// it, the device key it certifies, and the device epoch it was issued
/// in (`docs/hotline-ng-identity.md` §3.3). Asked with all three, so no
/// caller can leave the epoch out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertRef {
    /// SHA-256 of the identity key.
    pub identity: [u8; 32],
    /// SHA-256 of the device key.
    pub device: [u8; 32],
    pub epoch: u64,
}

/// The fingerprints refused by hand: identity keys, which refuse every
/// device of the identity, and device keys, which refuse one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocations {
    pub identities: HashSet<[u8; 32]>,
    pub devices: HashSet<[u8; 32]>,
}

impl Revocations {
    /// Does this list refuse a socket that proved `tag`?
    pub fn refuses(&self, tag: &IdentityTag) -> bool {
        self.is_revoked(&tag.fingerprint, &tag.device)
    }

    /// Is either the identity or the device on the list?
    fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.identities.contains(identity) || self.devices.contains(device)
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty() && self.devices.is_empty()
    }
}

/// What the registrars this server trusts publish against keys: the
/// identities refused, and the devices refused *with the identity that
/// revoked them*. A device revocation is its identity's to make, and a
/// registrar takes one naming any device key, so a device refused alone
/// would let one identity end another's sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Published {
    pub identities: HashSet<[u8; 32]>,
    /// `(identity, device)`.
    pub devices: HashSet<([u8; 32], [u8; 32])>,
    /// The identities whose records this list was made from. Only for
    /// those does a key missing from it mean the key is not refused.
    pub covered: HashSet<[u8; 32]>,
    /// Identities refused without being revoked: frozen, which can be
    /// lifted, or rotated away from with no anchors here to refuse them
    /// by. A resume of one of their sessions is not told `revoked`, but
    /// their push registrations go as a revoked identity's do.
    pub unrevoked: HashSet<[u8; 32]>,
    /// Each identity's device epoch floor, the highest `epoch` of the
    /// device epoch records its registrars publish: every certificate of
    /// the identity issued below it is revoked
    /// (`identity-registrar.md` §4.10, §7.3).
    pub floors: HashMap<[u8; 32], u64>,
}

impl Published {
    /// Is this identity, or this device of it, refused, whatever the
    /// certificate's epoch?
    fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.unrevoked.contains(identity) || self.revokes(identity, device)
    }

    fn revokes(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.identities.contains(identity) || self.devices.contains(&(*identity, *device))
    }

    /// The floor `cert` was issued below, if it was.
    fn below_floor(&self, cert: &CertRef) -> Option<u64> {
        self.floors
            .get(&cert.identity)
            .copied()
            .filter(|floor| cert.epoch < *floor)
    }

    /// Why a session that proved `cert` is ended as revoked, if it is.
    fn revoked_why(&self, cert: &CertRef) -> Option<EndedBy> {
        match self.revokes(&cert.identity, &cert.device) {
            true => Some(EndedBy::Revoked),
            false => self.below_floor(cert).map(EndedBy::BelowFloor),
        }
    }

    /// Is every device of `identity` refused, revoked or not?
    fn refuses_identity(&self, identity: &[u8; 32]) -> bool {
        self.identities.contains(identity) || self.unrevoked.contains(identity)
    }

    fn refuses(&self, cert: &CertRef) -> bool {
        self.is_revoked(&cert.identity, &cert.device) || self.below_floor(cert).is_some()
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
            && self.devices.is_empty()
            && self.unrevoked.is_empty()
            && self.floors.is_empty()
    }

    /// Add what `other` refuses, and the identities it was made from.
    pub fn merge(&mut self, other: &Published) {
        // Destructured, so a field added is a field merged.
        let Published {
            identities,
            devices,
            covered,
            unrevoked,
            floors,
        } = other;
        self.identities.extend(identities);
        self.devices.extend(devices);
        self.covered.extend(covered);
        self.unrevoked.extend(unrevoked);
        for (identity, floor) in floors {
            let held = self.floors.entry(*identity).or_default();
            *held = (*held).max(*floor);
        }
    }
}

/// Both lists, the operator's and the registrars', and the keys rotated
/// away from, which stay refused.
#[derive(Debug, Default)]
pub(crate) struct Refused {
    pub(crate) local: Revocations,
    pub(crate) published: Published,
    pub(crate) rotated: HashSet<[u8; 32]>,
}

impl Refused {
    pub(crate) fn refuses(&self, tag: &IdentityTag) -> bool {
        self.refuses_cert(&tag.cert())
    }

    fn refuses_cert(&self, cert: &CertRef) -> bool {
        self.local.is_revoked(&cert.identity, &cert.device)
            || self.published.refuses(cert)
            || self.rotated.contains(&cert.identity)
    }

    /// Was `d` registered by a key the lists refuse now: a device's own
    /// row, filed under its fingerprint, in a mailbox its identity's
    /// revocation or the device's reaches? A password device's never is.
    pub(crate) fn refuses_row(&self, d: &crate::push::Device) -> bool {
        let Some(dev) = d.devid.device_fingerprint() else {
            return false;
        };
        self.local.devices.contains(&dev)
            || d.owner.fingerprint.is_some_and(|i| {
                self.local.identities.contains(&i)
                    || self.rotated.contains(&i)
                    || self.published.is_revoked(&i, &dev)
            })
    }

    /// Every revoked key that refuses `tag`, each lifted on its own, whose
    /// rows a registration by `tag` must not leave. Empty if none does.
    pub(crate) fn pending_for(&self, tag: &IdentityTag) -> Vec<Unrevoked> {
        let (i, d) = (tag.fingerprint, tag.device);
        [
            self.local
                .devices
                .contains(&d)
                .then_some(Unrevoked::LocalDevice(d)),
            (self.local.identities.contains(&i) || self.rotated.contains(&i))
                .then_some(Unrevoked::LocalIdentity(i)),
            self.published
                .refuses_identity(&i)
                .then_some(Unrevoked::PublishedIdentity(i)),
            self.published
                .devices
                .contains(&(i, d))
                .then_some(Unrevoked::PublishedDevice(i, d)),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// Has `key` been lifted? The operator's once their list leaves it
    /// out. A registrar's only once a list made from its identity's
    /// records does: one made without them says nothing about it.
    pub(crate) fn lifts(&self, key: &Unrevoked) -> bool {
        let p = &self.published;
        match key {
            Unrevoked::LocalDevice(d) => !self.local.devices.contains(d),
            Unrevoked::LocalIdentity(i) => {
                !self.local.identities.contains(i) && !self.rotated.contains(i)
            }
            Unrevoked::PublishedDevice(i, d) => p.covered.contains(i) && !p.is_revoked(i, d),
            Unrevoked::PublishedIdentity(i) => p.covered.contains(i) && !p.refuses_identity(i),
        }
    }

    fn refusal(&self, cert: &CertRef) -> Option<KeyRefusal> {
        let (identity, device) = (&cert.identity, &cert.device);
        if self.local.is_revoked(identity, device)
            || self.published.revokes(identity, device)
            || self.rotated.contains(identity)
        {
            Some(KeyRefusal::Revoked)
        } else if let Some(floor) = self.published.below_floor(cert) {
            Some(KeyRefusal::BelowFloor(floor))
        } else {
            self.published
                .unrevoked
                .contains(identity)
                .then_some(KeyRefusal::Unrevoked)
        }
    }
}

/// Why a key is refused here, for the words a refused login is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// Revoked, or rotated away from.
    Revoked,
    /// Its certificate was issued below its identity's device epoch
    /// floor, this one: revoked by a reset.
    BelowFloor(u64),
    /// Refused by what a registrar publishes without being revoked
    /// ([`Published::unrevoked`]): the records say why.
    Unrevoked,
}

impl Core {
    /// Is this certificate refused here: its identity or its device
    /// revoked, or rotated away from, or the certificate issued below
    /// its identity's floor?
    pub fn refuses(&self, cert: &CertRef) -> bool {
        self.revoked.read().unwrap().refuses_cert(cert)
    }

    /// Why [`Self::refuses`] refuses this certificate, if it does.
    pub fn key_refusal(&self, cert: &CertRef) -> Option<KeyRefusal> {
        self.revoked.read().unwrap().refusal(cert)
    }

    /// Does the current list refuse this session's transport identity?
    /// Asked under the roster lock, which is the lock order `attach` set.
    pub(crate) fn refuses_session(&self, sess: &UserSession) -> bool {
        sess.info
            .transport
            .identity
            .as_ref()
            .is_some_and(|tag| self.revoked.read().unwrap().refuses(tag))
    }

    /// Install a revocation list, replacing the last, and end every
    /// session it refuses. Answers the sessions it ended, as uid and
    /// nick, for the log.
    ///
    /// A live session is sent `Kicked`, which its frontend answers by
    /// closing the connection; a detached one has no connection to hear
    /// it and is ended here, as a kick ends it. A live one whose socket
    /// fails before the kick is read would otherwise park detached, so
    /// `connection_lost` ends a refused session rather than detaching it,
    /// and `resume` refuses one outright. Either way the resume token
    /// dies with the session, which is the point: an attacker holding
    /// one should not be able to come back through it.
    ///
    /// The presentations a newly revoked device made are dropped too
    /// (`docs/proposals/portable-friends.md` §6), and the push
    /// registrations newly revoked keys made (push-notifications.md
    /// §5.1): store work, so this is called off the reactor.
    pub fn set_revocations(&self, list: Revocations) -> Vec<(Uid, String)> {
        let (identities, devices): (Vec<_>, Vec<_>) = {
            let mut refused = self.revoked.write().unwrap();
            let new = list
                .devices
                .difference(&refused.local.devices)
                .map(|d| (None, *d))
                .collect();
            let ids = list
                .identities
                .difference(&refused.local.identities)
                .copied()
                .collect();
            refused.local = list.clone();
            (ids, new)
        };
        let keys = devices.iter().map(|(_, d)| Unrevoked::LocalDevice(*d));
        let ids = identities.iter().map(|i| Unrevoked::LocalIdentity(*i));
        // Sessions first: the lists already hide the rows, and the
        // deletes may wait on registrations.
        let ended = match list.is_empty() {
            true => Vec::new(),
            false => self.end_revoked(|tag| list.refuses(tag), |_| Some(EndedBy::Revoked)),
        };
        // Even an empty list: a key lifted is forgotten by a retry too.
        self.take_revoked(keys.chain(ids).collect());
        if !list.is_empty() {
            self.drop_revoked_presentations(&devices);
        }
        ended
    }

    /// The identity keys of every session on the roster, live or
    /// detached: the ones whose records a sweep keeps current.
    pub fn session_identities(&self) -> Vec<[u8; 32]> {
        let r = self.roster.lock().unwrap();
        let mut ids: Vec<[u8; 32]> = r
            .users
            .values()
            .filter_map(|s| s.info.transport.identity.as_ref().map(|t| t.fingerprint))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Install what the registrars this server trusts publish against
    /// keys, replacing the last, and end every session it now refuses, as
    /// [`Self::set_revocations`] does for the operator's own list.
    /// Called off the reactor, as [`Self::set_revocations`] is.
    pub fn set_published_revocations(&self, list: Published) -> Vec<(Uid, String)> {
        let (identities, devices): (Vec<_>, Vec<_>) = {
            let mut refused = self.revoked.write().unwrap();
            let new = list
                .devices
                .difference(&refused.published.devices)
                .map(|(i, d)| (Some(*i), *d))
                .collect();
            let ids = list
                .identities
                .union(&list.unrevoked)
                .filter(|i| !refused.published.refuses_identity(i))
                .copied()
                .collect();
            refused.published = list.clone();
            (ids, new)
        };
        let keys = devices
            .iter()
            .filter_map(|(i, d)| i.map(|i| Unrevoked::PublishedDevice(i, *d)));
        let ids = identities.iter().map(|i| Unrevoked::PublishedIdentity(*i));
        // Sessions first: the lists already hide the rows, and the
        // deletes may wait on registrations.
        let ended = match list.is_empty() {
            true => Vec::new(),
            false => self.end_revoked(
                |tag| list.refuses(&tag.cert()),
                |tag| list.revoked_why(&tag.cert()),
            ),
        };
        // Even an empty list: a key lifted is forgotten by a retry too.
        self.take_revoked(keys.chain(ids).collect());
        if !list.is_empty() {
            self.drop_revoked_presentations(&devices);
        }
        ended
    }

    /// Raise `identity`'s device epoch floor to `floor`, as a list fetched
    /// at an admission publishes it before the sweep installs it, and end
    /// the sessions below it as the sweep would. `None` if the floor held
    /// is that high already. The sweep's next install replaces it with
    /// what the lists it reads say. Called off the reactor.
    pub fn raise_floor(&self, identity: [u8; 32], floor: u64) -> Option<Vec<(Uid, String)>> {
        let below = |refused: &Refused| {
            refused
                .published
                .floors
                .get(&identity)
                .copied()
                .unwrap_or(0)
                < floor
        };
        // Every identity login asks: most are answered under the read lock.
        if floor == 0 || !below(&self.revoked.read().unwrap()) {
            return None;
        }
        {
            let mut refused = self.revoked.write().unwrap();
            if !below(&refused) {
                return None;
            }
            refused.published.floors.insert(identity, floor);
        }
        Some(self.end_revoked(
            |tag| tag.fingerprint == identity && tag.device_epoch < floor,
            |_| Some(EndedBy::BelowFloor(floor)),
        ))
    }

    /// Refuse `identity` from now on, as a key its holder rotated away
    /// from (`identity-registrar.md` §7.4), and end its sessions.
    pub fn refuse_rotated(&self, identity: [u8; 32]) -> Vec<(Uid, String)> {
        if !self.revoked.write().unwrap().rotated.insert(identity) {
            return Vec::new();
        }
        // Its successor logs in, so its resume is told only that it is gone.
        self.end_sessions(
            |s| {
                s.info
                    .transport
                    .identity
                    .as_ref()
                    .is_some_and(|tag| tag.fingerprint == identity)
            },
            |_| None,
        )
    }

    /// How long `uid`'s key must wait to chat, message or post, as a key
    /// new here (`identity-registrar.md` §7.3), or `None` if it need not.
    pub fn newcomer_wait(&self, uid: Uid) -> Option<std::time::Duration> {
        let until = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)?
                .info
                .transport
                .identity
                .as_ref()?
                .quiet_until?
        };
        let now = self.clock.unix();
        (until > now).then(|| std::time::Duration::from_secs(until - now))
    }

    /// End every session keyed by `identity`, whether it proved the key
    /// or logged into the account the key linked with a password: once a
    /// rotation has moved that account, what such a session writes
    /// under the old key would be stranded there.
    pub(crate) fn end_identity(&self, identity: [u8; 32]) -> Vec<(Uid, String)> {
        self.end_sessions(
            |s| {
                s.identity == Some(identity)
                    || s.info
                        .transport
                        .identity
                        .as_ref()
                        .is_some_and(|t| t.fingerprint == identity)
            },
            |_| None,
        )
    }

    /// The sessions `list` refuses, ended, each that `revoked` names a
    /// reason for as revoked. Run after the list is written, and with
    /// nothing else held: an `attach` from then on is refused, and one
    /// that got in before is on the roster to be found here.
    fn end_revoked(
        &self,
        refuses: impl Fn(&IdentityTag) -> bool,
        revoked: impl Fn(&IdentityTag) -> Option<EndedBy>,
    ) -> Vec<(Uid, String)> {
        self.end_sessions(
            |s| s.info.transport.identity.as_ref().is_some_and(&refuses),
            |s| s.info.transport.identity.as_ref().and_then(&revoked),
        )
    }

    /// End the sessions `ends` picks, as kicked; a resume of one is told
    /// it was revoked where `revoked` says why (`docs/hotline-ng.md` §6.2).
    fn end_sessions(
        &self,
        ends: impl Fn(&UserSession) -> bool,
        revoked: impl Fn(&UserSession) -> Option<EndedBy>,
    ) -> Vec<(Uid, String)> {
        let mut r = self.roster.lock().unwrap();
        let ended: Vec<(Uid, String, Option<EndedBy>)> = r
            .users
            .iter()
            .filter(|(_, s)| ends(s))
            .map(|(uid, s)| (*uid, s.info.nick.clone(), revoked(s)))
            .collect();
        for (uid, nick, why) in &ended {
            info!(uid, nick = %nick, revoked = why.is_some(), "ending a session its key no longer admits");
            // On its way out, as a kicked session is: no kick or device
            // act takes it for a target meanwhile.
            if let Some(sess) = r.users.get_mut(uid) {
                sess.kicked = true;
            }
            if let Some(why) = why {
                r.remember_end(*uid, why.clone());
            }
            r.send_to(*uid, Event::Kicked);
            r.export_leaving(*uid);
            if r.users.get(uid).is_some_and(is_buffering) {
                r.end_session(*uid);
            }
        }
        ended
            .into_iter()
            .map(|(uid, nick, _)| (uid, nick))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Events;

    use crate::roster::{drain, AttachInfo, Transport};

    fn tag(identity: u8, device: u8) -> IdentityTag {
        IdentityTag {
            fingerprint: [identity; 32],
            device: [device; 32],
            handle: None,
            quiet_until: None,
            signs: false,
            can_sign: false,
            device_expires: u64::MAX,
            device_epoch: 0,
            sealed: None,
            device_cert: None,
        }
    }

    #[test]
    fn a_newcomer_waits_until_its_time_on_the_core_s_clock() {
        let core = Core::new();
        let until = core.clock().unix() + 120;
        let newcomer = IdentityTag {
            quiet_until: Some(until),
            ..tag(1, 1)
        };
        let (uid, _rx) = attach(&core, "new", Some(newcomer)).unwrap();
        let (known, _rx2) = attach(&core, "known", Some(tag(2, 2))).unwrap();
        assert!(core.newcomer_wait(uid).is_some_and(|w| w.as_secs() <= 120));
        assert_eq!(core.newcomer_wait(known), None);
        core.clock().advance(std::time::Duration::from_secs(120));
        assert_eq!(core.newcomer_wait(uid), None);
    }

    fn attach(core: &Core, nick: &str, identity: Option<IdentityTag>) -> Option<(Uid, Events)> {
        let (uid, rx) = core.attach(AttachInfo {
            account: None,
            nick: nick.into(),
            icon: 0,
            admin: false,
            access: crate::AccessBits::empty(),
            login: nick.into(),
            addr: None,
            can_detach: true,
            transport: Transport {
                identity,
                ..Transport::default()
            },
            has_inbox: false,
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
        })?;
        core.announce(uid);
        Some((uid, rx))
    }

    fn list(identities: &[u8], devices: &[u8]) -> Revocations {
        Revocations {
            identities: identities.iter().map(|b| [*b; 32]).collect(),
            devices: devices.iter().map(|b| [*b; 32]).collect(),
        }
    }

    #[test]
    fn an_identity_revocation_refuses_every_device_and_a_device_one_only_itself() {
        let r = list(&[1], &[20]);
        assert!(r.refuses(&tag(1, 10)));
        assert!(r.refuses(&tag(1, 11)));
        assert!(r.refuses(&tag(2, 20)));
        assert!(!r.refuses(&tag(2, 21)));
    }

    #[test]
    fn installing_a_list_ends_what_it_refuses_and_nothing_else() {
        let core = Core::new();
        let (stolen, mut rx) = attach(&core, "stolen", Some(tag(1, 10))).unwrap();
        let (other_device, _a) = attach(&core, "laptop", Some(tag(2, 20))).unwrap();
        let (plain, _b) = attach(&core, "plain", None).unwrap();
        // A detached session is on the roster with nobody to hear a kick.
        let (away, _c) = attach(&core, "away", Some(tag(1, 11))).unwrap();
        assert!(core.connection_lost(away, 10));
        drain(&mut rx);

        let mut ended = core.set_revocations(list(&[1], &[]));
        ended.sort();
        assert_eq!(
            ended,
            [(stolen, "stolen".to_string()), (away, "away".to_string())]
        );
        assert!(
            drain(&mut rx).iter().any(|e| matches!(e, Event::Kicked)),
            "the live one is told to go"
        );
        let on = |uid| core.snapshot().iter().any(|u| u.uid == uid);
        assert!(!on(away), "the detached one is gone at once");
        assert!(on(other_device) && on(plain), "nobody else is touched");
    }

    #[test]
    fn a_revoked_session_whose_socket_fails_first_neither_parks_nor_resumes() {
        let core = Core::new();
        // Live when the list lands, so all it gets is `Kicked`; its
        // socket then fails before the frontend reads that far.
        let (live, _rx) = attach(&core, "live", Some(tag(1, 10))).unwrap();
        core.set_revocations(list(&[1], &[]));
        assert!(
            !core.connection_lost(live, 10),
            "a refused session ends rather than detaching"
        );
        assert!(core.user(live).is_none());

        // And a session that somehow is parked is not resumed.
        let (parked, _rx) = attach(&core, "parked", Some(tag(2, 20))).unwrap();
        assert!(core.connection_lost(parked, 10));
        core.revoked.write().unwrap().local = list(&[2], &[]);
        assert!(matches!(
            core.resume(parked, 0),
            crate::roster::Resume::Gone
        ));
        assert!(core.user(parked).is_none(), "and it is ended");
    }

    #[test]
    fn a_floor_ends_the_certificates_below_it_and_tells_their_resume_the_floor() {
        let core = Core::new();
        let at = |identity, device, epoch| IdentityTag {
            device_epoch: epoch,
            ..tag(identity, device)
        };
        let (old, mut rx) = attach(&core, "old", Some(at(1, 10, 0))).unwrap();
        let (away, _a) = attach(&core, "away", Some(at(1, 11, 1))).unwrap();
        assert!(core.connection_lost(away, 10));
        let (current, _b) = attach(&core, "current", Some(at(1, 12, 2))).unwrap();
        let (other, _c) = attach(&core, "other", Some(at(2, 20, 0))).unwrap();
        let serials = [old, away].map(|uid| (uid, core.session_serial(uid).unwrap()));
        drain(&mut rx);

        let mut ended = core.set_published_revocations(Published {
            floors: [([1; 32], 2)].into(),
            ..Published::default()
        });
        ended.sort();
        assert_eq!(ended, [(old, "old".into()), (away, "away".into())]);
        assert!(drain(&mut rx).iter().any(|e| matches!(e, Event::Kicked)));
        let hour = std::time::Duration::from_secs(3600);
        for (uid, serial) in serials {
            assert_eq!(
                core.ended_by(uid, serial, hour),
                Some(EndedBy::BelowFloor(2))
            );
        }
        let on = |uid| core.snapshot().iter().any(|u| u.uid == uid);
        assert!(
            on(current) && on(other),
            "the floor itself and another identity stay"
        );
        assert_eq!(
            core.key_refusal(&at(1, 13, 1).cert()),
            Some(KeyRefusal::BelowFloor(2))
        );
        assert!(attach(&core, "again", Some(at(1, 13, 1))).is_none());
        assert_eq!(core.key_refusal(&at(1, 13, 2).cert()), None);

        core.set_published_revocations(Published {
            floors: [([1; 32], 2)].into(),
            devices: [([1; 32], [13; 32])].into(),
            ..Published::default()
        });
        assert_eq!(
            core.key_refusal(&at(1, 13, 1).cert()),
            Some(KeyRefusal::Revoked),
            "a revoked device is told so, whatever its epoch"
        );
    }

    #[test]
    fn a_revoked_key_cannot_attach_and_a_lifted_one_can() {
        let core = Core::new();
        core.set_revocations(list(&[], &[10]));
        assert!(core.refuses(&tag(9, 10).cert()));
        assert!(attach(&core, "stolen", Some(tag(1, 10))).is_none());
        assert!(
            attach(&core, "other", Some(tag(1, 11))).is_some(),
            "a device revocation leaves the identity's other devices in"
        );
        assert!(core.set_revocations(Revocations::default()).is_empty());
        assert!(attach(&core, "stolen", Some(tag(1, 10))).is_some());
    }
}
