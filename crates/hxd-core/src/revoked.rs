//! Server-local revocation (`docs/identity-registrar.md`): identity and
//! device fingerprints the operator has refused by hand, with no
//! registrar involved.
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

use crate::roster::{is_buffering, Core, Event, IdentityTag, Uid};

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

impl Core {
    /// Is this identity, or this device of it, revoked here?
    pub fn is_revoked(&self, identity: &[u8; 32], device: &[u8; 32]) -> bool {
        self.revoked.read().unwrap().is_revoked(identity, device)
    }

    /// Install a revocation list, replacing the last, and end every
    /// session it refuses. Answers the sessions it ended, as uid and
    /// nick, for the log.
    ///
    /// A live session is sent `Kicked`, which its frontend answers by
    /// closing the connection; a detached one has no connection to hear
    /// it and is ended here, as a kick ends it. Either way the resume
    /// token dies with the session, which is the point: an attacker
    /// holding one should not be able to come back through it.
    pub fn set_revocations(&self, list: Revocations) -> Vec<(Uid, String)> {
        // Written first and with nothing else held: an `attach` from here
        // on is refused, and one that got in before is on the roster for
        // the sweep below to find.
        *self.revoked.write().unwrap() = list.clone();
        if list.is_empty() {
            return Vec::new();
        }
        let mut r = self.roster.lock().unwrap();
        let ended: Vec<(Uid, String)> = r
            .users
            .iter()
            .filter(|(_, s)| {
                s.info
                    .transport
                    .identity
                    .as_ref()
                    .is_some_and(|tag| list.refuses(tag))
            })
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
    use tokio::sync::mpsc::UnboundedReceiver;

    use crate::roster::{drain, AttachInfo, SeqEvent, Transport};

    fn tag(identity: u8, device: u8) -> IdentityTag {
        IdentityTag {
            fingerprint: [identity; 32],
            device: [device; 32],
            handle: None,
        }
    }

    fn attach(
        core: &Core,
        nick: &str,
        identity: Option<IdentityTag>,
    ) -> Option<(Uid, UnboundedReceiver<SeqEvent>)> {
        let (uid, rx) = core.attach(AttachInfo {
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
            is_person: true,
            reads_on_delivery: false,
            identity: None,
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
