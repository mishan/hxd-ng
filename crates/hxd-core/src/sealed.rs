//! Sealed private messages as a server carries them
//! (`docs/e2e-messages.md` §4.1–§4.5): boxes this server can never open,
//! delivered to the one session of the device they were sealed to while
//! it is attached or detached and waiting to resume, and never stored
//! (§10). What a box holds is checked by its reader alone; here only who
//! may send one, and whether the device it names is the one there now.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use sha2::{Digest, Sha256};

use crate::roster::{Core, Event, Uid};

/// The device a session proved, as a session that can open sealed
/// messages offers it (§4.1, §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDevice {
    /// The certificate exactly as the session proved it.
    pub cert: Vec<u8>,
    /// Its `device_enc` key, which every box to this session is sealed to.
    pub enc: [u8; 32],
    /// When the certificate expires, as unix seconds.
    pub expires: u64,
}

/// What a detached session holds of sealed messages, from one sender and
/// in all (§4.3): a held box has no durable copy, so one sender must not
/// be able to push out what others sent.
#[derive(Debug, Clone, Copy)]
pub struct SealedHolds {
    pub per_sender: usize,
    pub all: usize,
}

impl Default for SealedHolds {
    fn default() -> Self {
        SealedHolds {
            per_sender: 64 * 1024,
            all: 256 * 1024,
        }
    }
}

/// `device_cert` is what a client would scrape to watch who logs in with
/// which device, so it is rationed on top of the request limit (§4.2).
pub(crate) const DEVICE_CERTS: u32 = 20;
pub(crate) const DEVICE_CERTS_PER: Duration = Duration::from_secs(60);

/// Why a sealed message, or a certificate to seal one to, was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedError {
    /// The asking session did not say it can open sealed messages.
    SelfNotSealed,
    /// The target cannot open them, or its certificate has expired.
    NotSealed,
    /// The box names a `device_enc` key other than the target's now.
    CertChanged,
    NoSuchUser,
    Blocked,
    /// The detached target holds as many sealed messages as it may.
    HeldFull,
    /// `device_cert` past its ration; retry after this.
    RateLimited(Duration),
    ServerError,
}

impl Core {
    pub fn with_sealed_holds(mut self, holds: SealedHolds) -> Self {
        self.sealed_holds = holds;
        self
    }

    /// [`Core::resume`], with whether `uid` can open sealed messages and
    /// its `signs` ([`Core::set_signs`]), as the `resume` says them again
    /// (§4.1, §4.6), set under the same lock, so of two resumes racing
    /// the one attached last has its own marks, and a change to either
    /// told as one change to the row. Losing `sealed` makes every sealed
    /// message held for the session the placeholder, in place, so the
    /// outbox keeps its seqs.
    pub fn resume_sealed(
        &self,
        uid: Uid,
        last_seq: u64,
        sealed: Option<SealedDevice>,
        (signs, can_sign): (bool, bool),
    ) -> crate::Resume {
        let mut r = self.roster.lock().unwrap();
        // `|`, not `||`: both are set whatever the first did.
        let changed = set_sealed(&mut r, uid, sealed) | r.set_signs(uid, signs, can_sign);
        let was_active = r
            .users
            .get(&uid)
            .is_some_and(|s| s.info.status == crate::roster::SessionStatus::Active);
        let resumed = self.resume_locked(&mut r, uid, last_seq);
        // Told once the new connection holds the session, so a takeover's
        // seqs still meet and a resume refused tells nothing; a session
        // coming back from detached is told the row in its status change.
        if changed && was_active && !matches!(resumed, crate::Resume::Gone) {
            r.row_changed(uid);
        }
        resumed
    }

    /// The certificate of the device `of`'s session proves now, for a
    /// session that can open sealed messages to seal to (§4.2).
    pub fn device_cert(&self, asker: Uid, of: Uid) -> Result<Vec<u8>, SealedError> {
        let (owner, other) = {
            let mut r = self.roster.lock().unwrap();
            let sess = r.users.get_mut(&asker).ok_or(SealedError::NoSuchUser)?;
            if sealed_of(sess).is_none() {
                return Err(SealedError::SelfNotSealed);
            }
            if let Some(bucket) = sess.device_certs.as_mut() {
                bucket
                    .spend(1, Instant::now())
                    .map_err(SealedError::RateLimited)?;
            }
            let asker = sess.mailbox();
            let target = r
                .users
                .get(&of)
                .filter(|s| s.visible)
                .ok_or(SealedError::NoSuchUser)?;
            (target.mailbox(), asker)
        };
        self.blocks(&owner, &other)?;
        let r = self.roster.lock().unwrap();
        let target = r
            .users
            .get(&of)
            .filter(|s| s.visible && s.mailbox() == owner)
            .ok_or(SealedError::NoSuchUser)?;
        let device = self.sealable(target).ok_or(SealedError::NotSealed)?;
        Ok(device.cert.clone())
    }

    /// A sealed message from `from` to the session `to`, sealed to the
    /// `device_enc` key whose SHA-256 is `sealed_to` (§4.3). Its frontend
    /// checked its size and, for a deniable box, its sender key. Delivered
    /// to that session alone, live or into its outbox while it is
    /// detached, and never stored, so there is no inbox to fall back on.
    pub fn msg_sealed(
        &self,
        from: Uid,
        to: Uid,
        sealed: Vec<u8>,
        sealed_to: [u8; 32],
    ) -> Result<(), SealedError> {
        let (owner, other, serial) = {
            let r = self.roster.lock().unwrap();
            let sender = r.users.get(&from).ok_or(SealedError::NoSuchUser)?;
            if sealed_of(sender).is_none() {
                return Err(SealedError::SelfNotSealed);
            }
            let target = r
                .users
                .get(&to)
                .filter(|s| s.visible)
                .ok_or(SealedError::NoSuchUser)?;
            self.sealed_to(target, &sealed_to)?;
            (target.mailbox(), sender.mailbox(), target.serial)
        };
        self.blocks(&owner, &other)?;
        // Again, under the lock it is delivered under: a resume in
        // between may have changed the device, or the uid its session.
        let mut r = self.roster.lock().unwrap();
        let sender = r.users.get(&from).ok_or(SealedError::NoSuchUser)?;
        let (from_nick, from_login) = (
            sender.info.nick.clone(),
            sender.has_inbox.then(|| sender.login.clone()),
        );
        let from_fingerprint = sender
            .info
            .transport
            .identity
            .as_ref()
            .filter(|id| id.sealed.is_some())
            .ok_or(SealedError::SelfNotSealed)?
            .fingerprint;
        let target = r
            .users
            .get(&to)
            .filter(|s| s.visible && s.serial == serial)
            .ok_or(SealedError::NoSuchUser)?;
        self.sealed_to(target, &sealed_to)?;
        if let Some((mine, all)) = target.outbox.sealed_held(&from_fingerprint) {
            let holds = self.sealed_holds;
            if mine + sealed.len() > holds.per_sender || all + sealed.len() > holds.all {
                return Err(SealedError::HeldFull);
            }
        }
        r.send_to(
            to,
            Event::Sealed {
                from,
                from_nick,
                from_login,
                from_fingerprint,
                sealed: Some(sealed),
                at: SystemTime::now(),
            },
        );
        Ok(())
    }

    /// Whether `target` can open a box sealed to the key `sealed_to` hashes.
    fn sealed_to(
        &self,
        target: &crate::roster::UserSession,
        sealed_to: &[u8; 32],
    ) -> Result<(), SealedError> {
        let device = self.sealable(target).ok_or(SealedError::NotSealed)?;
        if <[u8; 32]>::from(Sha256::digest(device.enc)) != *sealed_to {
            return Err(SealedError::CertChanged);
        }
        Ok(())
    }

    /// The device `target` can open sealed messages with now: unexpired,
    /// and not a session a kick or a revocation has ended but whose
    /// connection has yet to hear it (§4.2, §4.3).
    fn sealable<'a>(&self, target: &'a crate::roster::UserSession) -> Option<&'a SealedDevice> {
        if target.kicked || self.refuses_session(target) {
            return None;
        }
        sealed_of(target).filter(|d| d.expires > self.clock.unix())
    }

    /// Whether `owner` refuses messages from `other`, with no lock held.
    fn blocks(
        &self,
        owner: &crate::inbox::Mailbox,
        other: &crate::inbox::Mailbox,
    ) -> Result<(), SealedError> {
        let Some(store) = self.inbox.as_ref() else {
            return Ok(());
        };
        match store.is_blocked(owner, other) {
            Ok(false) => Ok(()),
            Ok(true) => Err(SealedError::Blocked),
            Err(e) => {
                tracing::warn!("inbox: {e}");
                Err(SealedError::ServerError)
            }
        }
    }
}

/// Whether the row changed.
fn set_sealed(r: &mut crate::roster::RosterInner, uid: Uid, sealed: Option<SealedDevice>) -> bool {
    let Some(sess) = r.users.get_mut(&uid) else {
        return false;
    };
    let Some(id) = sess.info.transport.identity.as_mut() else {
        return false;
    };
    if id.sealed.as_deref() == sealed.as_ref() {
        return false;
    }
    let lost = sealed.is_none();
    id.sealed = sealed.map(Arc::new);
    if lost {
        sess.outbox.lose_sealed();
    }
    true
}

pub(crate) fn sealed_of(sess: &crate::roster::UserSession) -> Option<&SealedDevice> {
    sess.info.transport.identity.as_ref()?.sealed.as_deref()
}
