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

use std::collections::HashSet;

use tracing::info;

use crate::roster::{is_buffering, Core, Event, IdentityTag, Uid, UserSession};

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
    pub fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
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
}

impl Published {
    fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.identities.contains(identity) || self.devices.contains(&(*identity, *device))
    }

    fn refuses(&self, tag: &IdentityTag) -> bool {
        self.is_revoked(&tag.fingerprint, &tag.device)
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty() && self.devices.is_empty()
    }
}

/// Both lists, the operator's and the registrars', and the keys rotated
/// away from, which stay refused.
#[derive(Debug, Default)]
pub(crate) struct Refused {
    local: Revocations,
    published: Published,
    rotated: HashSet<[u8; 32]>,
}

impl Refused {
    pub(crate) fn refuses(&self, tag: &IdentityTag) -> bool {
        self.local.refuses(tag)
            || self.published.refuses(tag)
            || self.rotated.contains(&tag.fingerprint)
    }

    fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.local.is_revoked(identity, device)
            || self.published.is_revoked(identity, device)
            || self.rotated.contains(identity)
    }
}

impl Core {
    /// Is this identity, or this device of it, revoked here?
    pub fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.revoked.read().unwrap().is_revoked(identity, device)
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
    pub fn set_revocations(&self, list: Revocations) -> Vec<(Uid, String)> {
        self.revoked.write().unwrap().local = list.clone();
        if list.is_empty() {
            return Vec::new();
        }
        self.end_revoked(|tag| list.refuses(tag))
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
    pub fn set_published_revocations(&self, list: Published) -> Vec<(Uid, String)> {
        self.revoked.write().unwrap().published = list.clone();
        if list.is_empty() {
            return Vec::new();
        }
        self.end_revoked(|tag| list.refuses(tag))
    }

    /// Refuse `identity` from now on, as a key its holder rotated away
    /// from (`identity-registrar.md` §7.4), and end its sessions.
    pub fn refuse_rotated(&self, identity: [u8; 32]) -> Vec<(Uid, String)> {
        if !self.revoked.write().unwrap().rotated.insert(identity) {
            return Vec::new();
        }
        self.end_revoked(|tag| tag.fingerprint == identity)
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
        self.end_sessions(|s| {
            s.identity == Some(identity)
                || s.info
                    .transport
                    .identity
                    .as_ref()
                    .is_some_and(|t| t.fingerprint == identity)
        })
    }

    /// The sessions `list` refuses, ended. Run after the list is written,
    /// and with nothing else held: an `attach` from then on is refused,
    /// and one that got in before is on the roster to be found here.
    fn end_revoked(&self, refuses: impl Fn(&IdentityTag) -> bool) -> Vec<(Uid, String)> {
        self.end_sessions(|s| s.info.transport.identity.as_ref().is_some_and(&refuses))
    }

    fn end_sessions(&self, ends: impl Fn(&UserSession) -> bool) -> Vec<(Uid, String)> {
        let mut r = self.roster.lock().unwrap();
        let ended: Vec<(Uid, String)> = r
            .users
            .iter()
            .filter(|(_, s)| ends(s))
            .map(|(uid, s)| (*uid, s.info.nick.clone()))
            .collect();
        for (uid, nick) in &ended {
            info!(uid, nick = %nick, "ending a session whose key is revoked");
            r.send_to(*uid, Event::Kicked);
            if r.users.get(uid).is_some_and(is_buffering) {
                r.end_session(*uid);
            }
        }
        ended
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
            sealed: None,
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
    fn a_revoked_key_cannot_attach_and_a_lifted_one_can() {
        let core = Core::new();
        core.set_revocations(list(&[], &[10]));
        assert!(core.is_revoked(&[9; 32], &[10; 32]));
        assert!(attach(&core, "stolen", Some(tag(1, 10))).is_none());
        assert!(
            attach(&core, "other", Some(tag(1, 11))).is_some(),
            "a device revocation leaves the identity's other devices in"
        );
        assert!(core.set_revocations(Revocations::default()).is_empty());
        assert!(attach(&core, "stolen", Some(tag(1, 10))).is_some());
    }
}
