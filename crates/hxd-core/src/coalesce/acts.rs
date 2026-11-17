//! What one device of a person may have done to it alone: ended by
//! another of its person's devices or by itself, or kicked while the rest
//! of its person stays.

use crate::roster::{Core, Event, RosterInner, Uid};

/// Why a device act was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRefusal {
    /// Nobody by that uid, or a person already being kicked, as a second
    /// kick of one is answered.
    NoSuchUser,
    /// Not a live device of that row, or not one the actor may end.
    NoSuchDevice,
}

/// What a device kick came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKick {
    /// That device is ended; its person stays.
    Ended,
    /// It is its row's last device, so the kick is of the whole person,
    /// which the caller makes as a kick, with its notice. Nothing is done
    /// yet, and it is not asked again: a device that joins meanwhile is
    /// kicked with the person, which is what kicking its last device
    /// asked, and a person gone meanwhile is nobody to kick.
    Last,
}

impl RosterInner {
    /// The live session under `row` whose device is `device`: one of a
    /// person's, or the session alone that `row` names.
    fn device_member(&self, row: Uid, device: u64) -> Option<Uid> {
        let members = self
            .person_members(row)
            .map_or_else(|| vec![row], <[Uid]>::to_vec);
        members.into_iter().find(|m| {
            self.users
                .get(m)
                .is_some_and(|s| s.live() && !s.kicked && s.device == device)
        })
    }

    /// End `uid`, one device, telling it `why`. Marked as kicked, so it
    /// may not detach, resume or be taken over on its way out; a detached
    /// one has no connection to see the event, and ends here.
    fn end_device(&mut self, uid: Uid, why: Event) {
        if let Some(s) = self.users.get_mut(&uid) {
            s.kicked = true;
        }
        self.send_to(uid, why);
        if self
            .users
            .get(&uid)
            .is_some_and(crate::roster::is_buffering)
        {
            self.end_session(uid);
        }
    }
}

impl Core {
    /// `actor` ends `device`, one of its own person's devices or itself,
    /// which is a logout of it; the last ending is its person's end. A
    /// session that logged in with the account's password ends only the
    /// person's other password sessions: a password of a linked account is
    /// enough to be grouped, and not enough to reach the devices that
    /// proved the identity.
    pub fn device_end(&self, actor: Uid, device: u64) -> Result<(), DeviceRefusal> {
        let mut r = self.roster.lock().unwrap();
        let sess = r
            .users
            .get(&actor)
            .filter(|s| s.live() && !s.kicked)
            .ok_or(DeviceRefusal::NoSuchUser)?;
        let proved = sess.info.transport.identity.is_some();
        if r.ending(actor) {
            return Err(DeviceRefusal::NoSuchUser);
        }
        let row = r.row_uid(actor);
        let target = r
            .device_member(row, device)
            .ok_or(DeviceRefusal::NoSuchDevice)?;
        if !proved && r.users[&target].info.transport.identity.is_some() {
            return Err(DeviceRefusal::NoSuchDevice);
        }
        // A client that never declared `persons` has no `ended` to hear
        // and would take its close for a lost connection, resume, and log
        // back in: it is told it was kicked. One that did still cannot
        // tell another device's ending it from a moderator's kick.
        let why = if r.users[&target].info.transport.persons {
            Event::Ended
        } else {
            Event::Kicked
        };
        r.end_device(target, why);
        Ok(())
    }

    /// Kick `device`, one device of the row `uid` names, leaving the rest
    /// of its person here: no notice, since the person has not gone. The
    /// kick bit and who may be kicked are the caller's to ask, as for a
    /// kick.
    pub fn kick_device(&self, uid: Uid, device: u64) -> Result<DeviceKick, DeviceRefusal> {
        let mut r = self.roster.lock().unwrap();
        let named = r.named(uid).ok_or(DeviceRefusal::NoSuchUser)?.info.uid;
        if r.ending(named) {
            return Err(DeviceRefusal::NoSuchUser);
        }
        let row = r.row_uid(named);
        let target = r
            .device_member(row, device)
            .ok_or(DeviceRefusal::NoSuchDevice)?;
        // Counted without those already on their way out, so the last
        // device standing is kicked as its person, with its notice.
        let staying = r.person_members(row).map_or(1, |members| {
            members
                .iter()
                .filter(|m| r.users.get(m).is_some_and(|s| !s.kicked))
                .count()
        });
        if staying <= 1 {
            return Ok(DeviceKick::Last);
        }
        r.end_device(target, Event::Kicked);
        Ok(DeviceKick::Ended)
    }
}
