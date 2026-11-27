//! An identity rotated to a successor key (`identity-registrar.md` §7.4,
//! `docs/identity-records.md` §4): what this server keeps under the
//! predecessor's fingerprint becomes the successor's.

use std::time::SystemTime;

use crate::avatar::AvatarOwner;
use crate::ban::{Ban, BanTarget};
use crate::inbox::StoreError;
use crate::messaging::Key;
use crate::push::PushStore;
use crate::relationships::{destination, Cause, Report, Work};
use crate::Core;

impl Core {
    /// Move `from`'s mail, blocks, news subscriptions and authorship,
    /// avatar and standing bans to `to`, or to where `to`'s went
    /// ([`destination`]), and drop its push devices, which
    /// the successor has not vouched for. Every step is idempotent, so a
    /// caller that gets an error calls again until it succeeds; a ban
    /// moved this way ends the successor's sessions as any new ban does.
    /// For a caller with no account link to move: see
    /// [`Self::rotate_identity_linking`].
    pub fn rotate_identity(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<(), StoreError> {
        self.rotate_identity_linking(from, to, false, |to| *to, |_| Ok(()))
    }

    /// [`Self::rotate_identity`], moving the account link first, with
    /// `link`, to the key everything else then moves to: the destination
    /// is read once, and rotations are made one at a time, so a rotation
    /// of `to` on cannot land between the link and the rest. Where `link`
    /// fails, nothing has moved. Every session still keyed by `from` is
    /// ended once the link has moved and before anything else does, so
    /// nothing is written there while the rest moves. `at_start` for a
    /// caller on the reactor as the server starts, leaving the
    /// predecessor's friendships to the pass a start makes over them
    /// ([`Self::reconcile_kept`]). `lands` says, under the hold, where a
    /// rotation into `to` lands by the caller's record of rotations, for
    /// the store's moves to resolve further.
    pub fn rotate_identity_linking(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        at_start: bool,
        lands: impl FnOnce(&[u8; 32]) -> [u8; 32],
        link: impl FnOnce(&[u8; 32]) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        // A rotation to itself moves nothing.
        if from == to {
            return Ok(());
        }
        let _rotating = self.rotations.lock().unwrap_or_else(|e| e.into_inner());
        // One hold from the link's move to the roster's following the
        // friendships and what their merge left settled: an act of a
        // session ended below that is under way finishes first and its
        // rows move, and one after it is refused; no keep lands between
        // the judging and the merge, which keeps the later cutoff of two
        // for one key whichever stands; and no act finds the store moved
        // and the roster not.
        let writing = self.friend_writes();
        // Work owed in memory alone is written first, or none of it could
        // follow the rows; until it can be, the rotation waits.
        self.flush_unwritten()?;
        let to = &lands(to);
        let dest = match self.relationships.as_ref() {
            Some(store) => destination(from, to, store.moved(to)?).unwrap_or(*to),
            None => *to,
        };
        let to = &dest;
        // What an unlink of a key linked again still owes is moot, settled
        // before the link moves on: once it has, the key reads as unlinked
        // until the rows follow, and a drop between would take its offers.
        self.settle_relinked(from)?;
        link(to)?;
        for (uid, nick) in self.end_identity(*from) {
            tracing::info!(uid, nick = %nick, "session ended: its key rotated away");
        }
        let (old, new) = (
            crate::inbox::Mailbox::identified(String::new(), *from),
            crate::inbox::Mailbox::identified(String::new(), *to),
        );
        // By the login the account link now gives it, so a friend with no
        // row of its own naming the successor is told too.
        let account = (self.directory.as_ref()).and_then(|d| d.account_by_key(to));
        let linked = account.is_some();
        let successor = account.map_or_else(|| new.clone(), |(m, _)| m);
        if let Some(store) = self.inbox.as_ref() {
            // As a send writes under it, and as a claim holds the other.
            let _flushing = self.flushing.lock().unwrap_or_else(|e| e.into_inner());
            let _reacting = self.pm_reacting.lock().unwrap_or_else(|e| e.into_inner());
            store.rotate(from, to)?;
            let lost = store.rekey_message_reactions(&old, &new)?;
            self.pm_announce(&lost);
        }
        if let Some(store) = self.relationships.as_ref() {
            self.drop_dead_withdrawals(&[*from, *to])?;
            // Every party either key had anything with, upgrades waiting
            // for either included: one the merge leaves nothing with the
            // successor is told so, no row being left to tell it by.
            let wall = self.clock.wall();
            let mut audience = self.counterparts_of(store, from, wall)?;
            audience.extend(self.counterparts_of(store, to, wall)?);
            let mut seen = std::collections::HashSet::new();
            audience.retain(|(_, other)| seen.insert(Key::of(other)));
            let report = Report {
                pairs: audience
                    .into_iter()
                    .map(|(_, other)| (successor.clone(), other))
                    .collect(),
                now: wall,
            };
            // What the merge leaves to settle is owed in its step, and so is
            // the drop of what an identity no account links holds.
            let mut owe = vec![(Work::Settle(*to), Cause::Always)];
            if !linked {
                owe.push((Work::DropOffersNaming(*to), Cause::Unlinked));
                owe.push((Work::DropPresentationsOf(*to), Cause::Unlinked));
            }
            let (rekeyed, left) = store.rotate_reporting(from, to, &report, &owe)?;
            let (audience, ended_left) = left.split_at(report.pairs.len());
            let merged = rekeyed.dropped.iter().flat_map(|p| [p.presenter, p.other]);
            self.unjudge(store, [*from, *to].into_iter().chain(merged));
            #[cfg(test)]
            self.rotated.at("rotated");
            if let Err(e) = self.restamp(&rekeyed.merged) {
                tracing::warn!("inbox: re-stamping a rotation's merged friendships: {e}");
            }
            self.rekey_friends(&writing, &old, &successor);
            self.merge_dropped(&writing, store, &rekeyed, ended_left);
            if self.after_merge(&writing, &successor) {
                let settling: Vec<_> = rekeyed.owed.first().copied().into_iter().collect();
                if let Err(e) = store.settle(&settling) {
                    tracing::warn!("relationships: settling a rotation's merge: {e}");
                }
            }
            let ended: Vec<_> = rekeyed
                .ended
                .iter()
                .flat_map(|e| e.parties.iter().map(|m| m.fingerprint))
                .collect();
            // One the merge left nothing with the successor, told so from
            // what it left: one the edge's ending told, or of a successor no
            // account here names, is told nothing more.
            for left in audience {
                let told = ended.contains(&left.pair[1].fingerprint) || successor.login.is_empty();
                if !told && left.rows == [None, None] {
                    self.tell_left(left, [false, true]);
                }
            }
        }
        drop(writing);
        if !at_start {
            self.reconcile_predecessor(*from);
        }
        self.news_rotate(from, to)?;
        self.rekey_all_reactions(&old, &new)?;
        if let Some(store) = self.devices.as_ref() {
            let taken = store.devices_rotate(from, to)?;
            self.devices_changed(false, &taken);
        }
        if let Some(avatars) = self.avatars.as_ref() {
            let (old, new) = (AvatarOwner::Identity(*from), AvatarOwner::Identity(*to));
            if let Some(avatar) = avatars.store.load(&old)? {
                if avatars.store.load(&new)?.is_none() {
                    avatars.store.save(&new, Some(&avatar))?;
                }
                avatars.store.save(&old, None)?;
            }
        }
        if let Some(store) = self.moderation.as_ref() {
            let placed = {
                let _writing = self.ban_writes.lock().unwrap();
                let standing = store.bans(Some(SystemTime::now()), None, usize::MAX)?;
                let mut placed = Vec::new();
                for ban in standing
                    .into_iter()
                    .filter(|b| b.target == BanTarget::Identity(*from))
                {
                    let row = store.ban(&Ban {
                        target: BanTarget::Identity(*to),
                        ..ban
                    })?;
                    self.bans.write().unwrap().insert(&row);
                    placed.push(row);
                }
                placed
            };
            for row in &placed {
                self.end_refused(&row.target, None);
            }
        }
        // Again, for a login that read the account before its link moved
        // and was admitted since.
        for (uid, nick) in self.end_identity(*from) {
            tracing::info!(uid, nick = %nick, "session ended: its key rotated away");
        }
        Ok(())
    }
}
