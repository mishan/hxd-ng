//! An identity rotated to a successor key (`identity-registrar.md` §7.4,
//! `docs/identity-records.md` §4): what this server keeps under the
//! predecessor's fingerprint becomes the successor's.

use std::time::SystemTime;

use crate::avatar::AvatarOwner;
use crate::ban::{Ban, BanTarget};
use crate::inbox::StoreError;
use crate::Core;

impl Core {
    /// Move `from`'s mail, blocks, news subscriptions and authorship,
    /// avatar and standing bans to `to`, and drop its push devices, which
    /// the successor has not vouched for. Every step is idempotent, so a
    /// caller that gets an error calls again until it succeeds; a ban
    /// moved this way ends the successor's sessions as any new ban does.
    /// Called once the account link has moved, it ends every session
    /// still keyed by `from`, so nothing is written there afterwards.
    pub fn rotate_identity(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<(), StoreError> {
        if let Some(store) = self.inbox.as_ref() {
            store.rotate(from, to)?;
        }
        if let Some(store) = self.relationships.as_ref() {
            let rekeyed = store.rotate(from, to)?;
            if let Err(e) = self.restamp(&rekeyed.merged) {
                tracing::warn!("inbox: re-stamping a rotation's merged friendships: {e}");
            }
            // By the login the account link now gives it, so a friend
            // with no row of its own naming the successor is told too.
            let successor = self
                .directory
                .as_ref()
                .and_then(|d| d.account_by_key(to))
                .map_or_else(
                    || crate::inbox::Mailbox::identified(String::new(), *to),
                    |(m, _)| m,
                );
            self.rekey_friends(
                &crate::inbox::Mailbox::identified(String::new(), *from),
                &successor,
            );
            self.after_merge(&successor);
        }
        self.news_rotate(from, to)?;
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
        for (uid, nick) in self.end_identity(*from) {
            tracing::info!(uid, nick = %nick, "session ended: its key rotated away");
        }
        Ok(())
    }
}
