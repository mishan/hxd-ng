//! An identity rotated to a successor key (`identity-registrar.md` §7.4,
//! `docs/identity-records.md` §4): what this server keeps under the
//! predecessor's fingerprint becomes the successor's.

use std::time::SystemTime;

use crate::avatar::AvatarOwner;
use crate::ban::{Ban, BanTarget};
use crate::inbox::StoreError;
use crate::push::PushStore;
use crate::Core;

impl Core {
    /// Move `from`'s mail, blocks, news subscriptions and authorship,
    /// avatar and standing bans to `to`, and drop its push devices, which
    /// the successor has not vouched for. Every step is idempotent, so a
    /// caller that gets an error calls again until it succeeds; a ban
    /// moved this way ends the successor's sessions as any new ban does.
    /// Called once the account link has moved, it ends every session
    /// still keyed by `from` before anything moves, so nothing is written
    /// there while the rest does.
    pub fn rotate_identity(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<(), StoreError> {
        for (uid, nick) in self.end_identity(*from) {
            tracing::info!(uid, nick = %nick, "session ended: its key rotated away");
        }
        let (old, new) = (
            crate::inbox::Mailbox::identified(String::new(), *from),
            crate::inbox::Mailbox::identified(String::new(), *to),
        );
        // By the login the account link now gives it, so a friend with no
        // row of its own naming the successor is told too.
        let successor = self
            .directory
            .as_ref()
            .and_then(|d| d.account_by_key(to))
            .map_or_else(|| new.clone(), |(m, _)| m);
        // One hold from before the mail moves to the roster's following
        // the friendships and what their merge left settled: an act of a
        // session ended above that is under way finishes first and its
        // rows move, and one after it is refused; no keep lands between
        // the judging and the merge, which keeps the later cutoff of two
        // for one key whichever stands; and no act finds the store moved
        // and the roster not.
        let writing = self.friend_writes();
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
            let rekeyed = store.rotate(from, to)?;
            let merged = rekeyed.dropped.iter().flat_map(|p| [p.presenter, p.other]);
            self.unjudge([*from, *to].into_iter().chain(merged));
            #[cfg(test)]
            self.rotated.at("rotated");
            if let Err(e) = self.restamp(&rekeyed.merged) {
                tracing::warn!("inbox: re-stamping a rotation's merged friendships: {e}");
            }
            self.rekey_friends(&writing, &old, &successor);
            self.merge_dropped(&writing, store, &rekeyed);
            self.after_merge(&writing, &successor);
        }
        drop(writing);
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
