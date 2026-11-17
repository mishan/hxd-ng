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
    /// The device named is not one of the user's.
    NoSuchDevice,
}

/// What `device_cert` answers (§4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCerts {
    /// The one device: a session alone's, the one named, or a person's
    /// only one.
    One(Vec<u8>),
    /// Each device of a person it can be sealed to, by its device id.
    Devices(Vec<(u64, Vec<u8>)>),
}

/// One box of a sealed message to a person, for one of its devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBox {
    pub device: u64,
    pub sealed: Vec<u8>,
    /// The SHA-256 of the `device_enc` key it was sealed to.
    pub sealed_to: [u8; 32],
}

/// Why boxes to a person were refused (§4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoxesError {
    Sealed(SealedError),
    /// The boxes are not one for each device it can be sealed to: those
    /// devices now, to seal again.
    DevicesChanged(Vec<(u64, Vec<u8>)>),
    /// The box for this device names another key than the device's now.
    CertChanged(u64),
}

impl From<SealedError> for BoxesError {
    fn from(e: SealedError) -> Self {
        BoxesError::Sealed(e)
    }
}

/// A device a sealed message may go to, as a sender is given it.
struct SealingTo {
    uid: Uid,
    device: u64,
    cert: Vec<u8>,
    enc: [u8; 32],
}

/// Who sealed a message, as its reader is told.
struct Sender {
    uid: Uid,
    nick: String,
    login: Option<String>,
    fingerprint: [u8; 32],
    device: Option<u64>,
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

    /// Take `sealed` and `signs` from every session whose certificate has
    /// expired, as a resume without them would: nothing can be sealed to
    /// it or signed with it any more, and its row and the links say so
    /// once. Run by the ng sweeper.
    pub fn expire_device_keys(&self) {
        let now = self.clock.unix();
        let mut r = self.roster.lock().unwrap();
        let expired: Vec<Uid> = r
            .users
            .values()
            .filter(|s| {
                s.info.transport.identity.as_ref().is_some_and(|id| {
                    id.device_expires <= now && (id.sealed.is_some() || id.can_sign)
                })
            })
            .map(|s| s.info.uid)
            .collect();
        for uid in expired {
            if set_sealed(&mut r, uid, None) | r.set_signs(uid, false, false) {
                r.row_changed(uid);
            }
        }
    }

    /// The certificate of the device `of` names, for a session that can
    /// open sealed messages to seal to (§4.2): a session alone's, or one
    /// device of a person's by `device`; for a person with no device
    /// named, every device it can be sealed to, to an asker that declared
    /// `persons`, and to any other the one device when it has exactly one.
    /// Rationed per answer, and a person's list one more for each device
    /// past its first.
    pub fn device_cert(
        &self,
        asker: Uid,
        of: Uid,
        device: Option<u64>,
    ) -> Result<DeviceCerts, SealedError> {
        let (owners, other, persons) = {
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
            let (other, persons) = (sess.mailbox(), sess.info.transport.persons);
            (mailboxes(&r, of)?, other, persons)
        };
        self.blocks(&owners, &other)?;
        let mut r = self.roster.lock().unwrap();
        let row = sealing_row(&r, of, &owners)?;
        let set = self.sealing_set(&r, of, &row, asker);
        if let Some(device) = device {
            if !row
                .iter()
                .any(|m| r.users.get(m).is_some_and(|s| s.device == device))
            {
                return Err(SealedError::NoSuchDevice);
            }
            return set
                .into_iter()
                .find(|d| d.device == device)
                .map(|d| DeviceCerts::One(d.cert))
                .ok_or(SealedError::NotSealed);
        }
        match (r.person_members(of).is_some() && persons, set.len()) {
            (_, 0) => Err(SealedError::NotSealed),
            (true, n) => {
                charge_devices(&mut r, asker, n - 1);
                Ok(DeviceCerts::Devices(
                    set.into_iter().map(|d| (d.device, d.cert)).collect(),
                ))
            }
            (false, 1) => Ok(DeviceCerts::One(set.into_iter().next().expect("one").cert)),
            // A person with more than one: only a client that knows of
            // devices can seal to each.
            (false, _) => Err(SealedError::NotSealed),
        }
    }

    /// A sealed message from `from` to `to`, sealed to the `device_enc`
    /// key whose SHA-256 is `sealed_to` (§4.3): a session alone, or a
    /// person with exactly one device it can be sealed to. Its frontend
    /// checked its size and, for a deniable box, its sender key.
    /// Delivered to that session alone, live or into its outbox while it
    /// is detached, and never stored, so there is no inbox to fall back
    /// on.
    pub fn msg_sealed(
        &self,
        from: Uid,
        to: Uid,
        sealed: Vec<u8>,
        sealed_to: [u8; 32],
    ) -> Result<(), SealedError> {
        let (owners, other) = self.sealing_parties(from, to)?;
        self.blocks(&owners, &other)?;
        // Again, under the lock it is delivered under: a resume in
        // between may have changed the device, or the uid its session.
        let mut r = self.roster.lock().unwrap();
        let row = sealing_row(&r, to, &owners)?;
        let set = self.sealing_set(&r, to, &row, from);
        let [target] = set.as_slice() else {
            return Err(SealedError::NotSealed);
        };
        if <[u8; 32]>::from(Sha256::digest(target.enc)) != sealed_to {
            return Err(SealedError::CertChanged);
        }
        let target = target.uid;
        let sender = self.sender(&r, from)?;
        if self.held_full(&r, target, &sender.fingerprint, sealed.len()) {
            return Err(SealedError::HeldFull);
        }
        self.deliver_sealed(&mut r, &sender, target, sealed);
        Ok(())
    }

    /// A box for each device `to` can be sealed to, from a session that
    /// declared `persons` (§4.3): to a person, or to a session alone as
    /// its one device. Refused whole unless the boxes are one for each
    /// such device and no other, so no device silently misses a message,
    /// and unless each names its device's key. A device holding as much
    /// as it may is skipped and the rest delivered: the devices skipped.
    pub fn msg_boxes(
        &self,
        from: Uid,
        to: Uid,
        boxes: Vec<SealedBox>,
    ) -> Result<Vec<u64>, BoxesError> {
        let (owners, other) = self.sealing_parties(from, to)?;
        self.blocks(&owners, &other)?;
        let mut r = self.roster.lock().unwrap();
        let row = sealing_row(&r, to, &owners)?;
        let set = self.sealing_set(&r, to, &row, from);
        if set.is_empty() {
            return Err(SealedError::NotSealed.into());
        }
        let mut asked: Vec<u64> = boxes.iter().map(|b| b.device).collect();
        let mut have: Vec<u64> = set.iter().map(|d| d.device).collect();
        asked.sort_unstable();
        have.sort_unstable();
        // Each refusal tells what `device_cert` would, so is rationed as
        // that is: a sender cannot read a person's devices off refusals
        // any faster.
        if asked != have {
            spend_device_cert(&mut r, from)?;
            charge_devices(&mut r, from, set.len() - 1);
            return Err(BoxesError::DevicesChanged(
                set.into_iter().map(|d| (d.device, d.cert)).collect(),
            ));
        }
        let mut to_deliver = Vec::new();
        for b in boxes {
            let d = set.iter().find(|d| d.device == b.device).expect("checked");
            if <[u8; 32]>::from(Sha256::digest(d.enc)) != b.sealed_to {
                spend_device_cert(&mut r, from)?;
                return Err(BoxesError::CertChanged(b.device));
            }
            to_deliver.push((d.uid, d.device, b.sealed));
        }
        let sender = self.sender(&r, from).map_err(BoxesError::Sealed)?;
        let mut held_full = Vec::new();
        to_deliver.retain(|(uid, device, sealed)| {
            let full = self.held_full(&r, *uid, &sender.fingerprint, sealed.len());
            if full {
                held_full.push(*device);
            }
            !full
        });
        if to_deliver.is_empty() {
            return Err(BoxesError::Sealed(SealedError::HeldFull));
        }
        for (uid, _, sealed) in to_deliver {
            self.deliver_sealed(&mut r, &sender, uid, sealed);
        }
        Ok(held_full)
    }

    /// Who is sealing to whom, for the check of blocks with no lock held:
    /// the target's mailboxes and the sender's.
    fn sealing_parties(
        &self,
        from: Uid,
        to: Uid,
    ) -> Result<(Vec<crate::inbox::Mailbox>, crate::inbox::Mailbox), SealedError> {
        let r = self.roster.lock().unwrap();
        let sender = r.users.get(&from).ok_or(SealedError::NoSuchUser)?;
        if sealed_of(sender).is_none() {
            return Err(SealedError::SelfNotSealed);
        }
        Ok((mailboxes(&r, to)?, sender.mailbox()))
    }

    /// The devices of `row` that can be sealed to now, but the sender's
    /// own when `named` is its person: one predicate behind every list a
    /// sender is given and every box delivered, so the two cannot
    /// disagree. A session alone may seal to itself.
    fn sealing_set(
        &self,
        r: &crate::roster::RosterInner,
        named: Uid,
        row: &[Uid],
        from: Uid,
    ) -> Vec<SealingTo> {
        let except = r.person_members(named).map(|_| from);
        row.iter()
            .filter(|m| Some(**m) != except)
            .filter_map(|m| r.users.get(m))
            .filter(|s| s.live())
            .filter_map(|s| {
                r.sealable(s).map(|d| SealingTo {
                    uid: s.info.uid,
                    device: s.device,
                    cert: d.cert.clone(),
                    enc: d.enc,
                })
            })
            .collect()
    }

    /// The sender as a sealed message names it, under the lock it is
    /// delivered under.
    fn sender(&self, r: &crate::roster::RosterInner, from: Uid) -> Result<Sender, SealedError> {
        let sender = r.users.get(&from).ok_or(SealedError::NoSuchUser)?;
        let fingerprint = sender
            .info
            .transport
            .identity
            .as_ref()
            .filter(|id| id.sealed.is_some())
            .ok_or(SealedError::SelfNotSealed)?
            .fingerprint;
        Ok(Sender {
            // A person's device seals as its row, the uid its reader
            // knows and answers, even to its own person, where a plain
            // message shows nobody: a reply to it seals to the row by
            // device, and the box is checked against the row's key.
            uid: r.row_uid(from),
            nick: sender.info.nick.clone(),
            login: sender.has_inbox.then(|| sender.login.clone()),
            fingerprint,
            device: sender.grouped.then_some(sender.device),
        })
    }

    /// Whether `to`, detached, holds as much as it may of what this
    /// sender sealed, or in all, to take `len` bytes more (§4.3).
    fn held_full(
        &self,
        r: &crate::roster::RosterInner,
        to: Uid,
        fingerprint: &[u8; 32],
        len: usize,
    ) -> bool {
        r.users
            .get(&to)
            .and_then(|s| s.outbox.sealed_held(fingerprint))
            .is_some_and(|(mine, all)| {
                let holds = self.sealed_holds;
                mine + len > holds.per_sender || all + len > holds.all
            })
    }

    fn deliver_sealed(
        &self,
        r: &mut crate::roster::RosterInner,
        sender: &Sender,
        to: Uid,
        sealed: Vec<u8>,
    ) {
        let persons = r.users.get(&to).is_some_and(|s| s.info.transport.persons);
        r.send_to(
            to,
            Event::Sealed {
                from: sender.uid,
                from_nick: sender.nick.clone(),
                from_login: sender.login.clone(),
                from_fingerprint: sender.fingerprint,
                from_device: sender.device.filter(|_| persons),
                sealed: Some(sealed),
                at: SystemTime::now(),
            },
        );
    }

    /// Whether any of `owners` refuses messages from `other`, with no
    /// lock held.
    fn blocks(
        &self,
        owners: &[crate::inbox::Mailbox],
        other: &crate::inbox::Mailbox,
    ) -> Result<(), SealedError> {
        let Some(store) = self.relationships.as_ref() else {
            return Ok(());
        };
        for owner in owners {
            match store.is_blocked(owner, other) {
                Ok(false) => {}
                Ok(true) => return Err(SealedError::Blocked),
                Err(e) => {
                    tracing::warn!("inbox: {e}");
                    return Err(SealedError::ServerError);
                }
            }
        }
        Ok(())
    }
}

/// Every mailbox among the sessions `named` stands for: a personal
/// account's person can hold password devices under its login alone
/// beside linked ones under its identity, and a block made from either
/// is the person's.
fn mailboxes(
    r: &crate::roster::RosterInner,
    named: Uid,
) -> Result<Vec<crate::inbox::Mailbox>, SealedError> {
    let mut owners = Vec::new();
    for s in r
        .named_sessions(named)
        .iter()
        .filter_map(|m| r.users.get(m))
    {
        let mailbox = s.mailbox();
        if s.live() && !owners.contains(&mailbox) {
            owners.push(mailbox);
        }
    }
    if owners.is_empty() {
        return Err(SealedError::NoSuchUser);
    }
    Ok(owners)
}

/// The sessions `named` stands for now whose mailbox is one the blocks
/// were checked against: a device under another, or a uid let go of and
/// given out again in between, is no one the sender was cleared for.
fn sealing_row(
    r: &crate::roster::RosterInner,
    named: Uid,
    owners: &[crate::inbox::Mailbox],
) -> Result<Vec<Uid>, SealedError> {
    let row: Vec<Uid> = r
        .named_sessions(named)
        .into_iter()
        .filter(|m| {
            r.users
                .get(m)
                .is_some_and(|s| s.live() && owners.contains(&s.mailbox()))
        })
        .collect();
    if row.is_empty() {
        return Err(SealedError::NoSuchUser);
    }
    Ok(row)
}

/// One answer of `device_cert`'s, from `asker`'s ration.
fn spend_device_cert(r: &mut crate::roster::RosterInner, asker: Uid) -> Result<(), BoxesError> {
    match r
        .users
        .get_mut(&asker)
        .and_then(|s| s.device_certs.as_mut())
    {
        Some(bucket) => bucket
            .spend(1, Instant::now())
            .map_err(|wait| SealedError::RateLimited(wait).into()),
        None => Ok(()),
    }
}

/// The devices of a list past its first, counted against `asker`'s
/// ration once the list is given (§4.2).
fn charge_devices(r: &mut crate::roster::RosterInner, asker: Uid, extra: usize) {
    if let Some(bucket) = r
        .users
        .get_mut(&asker)
        .and_then(|s| s.device_certs.as_mut())
    {
        bucket.charge(u32::try_from(extra).unwrap_or(u32::MAX), Instant::now());
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

/// The device `sess` can be sealed to at `now`: it said `sealed` with a
/// certificate that allowed it, the certificate is unexpired, and no
/// kick or revocation (`refused`) has ended the session yet. What every
/// shown `sealed`, every list a sender is given and every delivery asks.
pub(crate) fn sealable_at<'a>(
    sess: &'a crate::roster::UserSession,
    now: u64,
    refused: &std::sync::RwLock<crate::revoked::Refused>,
) -> Option<&'a SealedDevice> {
    if sess.kicked {
        return None;
    }
    let tag = sess.info.transport.identity.as_ref()?;
    if refused.read().unwrap().refuses(tag) {
        return None;
    }
    sealed_of(sess).filter(|d| d.expires > now)
}

impl crate::roster::RosterInner {
    /// [`sealable_at`] now.
    pub(crate) fn sealable<'a>(
        &self,
        sess: &'a crate::roster::UserSession,
    ) -> Option<&'a SealedDevice> {
        sealable_at(sess, self.clock.unix(), &self.revoked)
    }
}
