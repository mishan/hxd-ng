//! Avatars: a user's picture, the same on both wires (`docs/avatars.md`).
//!
//! An avatar is an image the codec re-encoded and fitted, in two
//! renditions — the canonical bytes the ng wire serves, and the small GIF
//! the legacy GIF-icon extension carries — and it belongs to an **owner**
//! rather than to a session: a named account, or the identity of a guest
//! that proved one (§2). A session shows its owner's avatar, loaded before
//! it is announced; a guest with neither has one only for the session.
//!
//! **Store calls never happen under the roster lock**, as for every other
//! store on [`Core`]. A change takes [`Core::avatar_serial`] first, then
//! writes the store, then (briefly) the roster, so the store and the
//! roster agree about the last change and two changes for one owner land
//! in one order.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::inbox::StoreError;
use crate::media::{Canonical, MediaCodec, MediaReject, MediaType};
use crate::roster::{Event, Uid, UserSession};
use crate::Core;

/// SHA-256 of an avatar's canonical bytes. Content-addressed, so a given
/// id always names the same picture and a client may cache it for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AvatarId(pub [u8; 32]);

impl AvatarId {
    pub fn of(bytes: &[u8]) -> Self {
        AvatarId(Sha256::digest(bytes).into())
    }

    /// Lowercase hex, as it appears on the ng wire and in a URL.
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(pair[0])?;
            let lo = hex_digit(pair[1])?;
            out[i] = hi << 4 | lo;
        }
        Some(AvatarId(out))
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

impl std::fmt::Display for AvatarId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// What a roster row carries: enough to render a placeholder and to fetch
/// the picture, never the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarRef {
    pub id: AvatarId,
    pub mime: MediaType,
    pub width: u32,
    pub height: u32,
}

/// An avatar and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avatar {
    pub meta: AvatarRef,
    pub bytes: Arc<[u8]>,
    /// The legacy GIF rendition, or `None` when none fits the ceiling
    /// and GIF-icon clients see no avatar for this user.
    pub legacy_gif: Option<Arc<[u8]>>,
}

impl Avatar {
    /// Assemble an avatar from what the codec produced.
    pub fn from_images(images: AvatarImages) -> Self {
        let id = AvatarId::of(&images.canonical.bytes);
        Avatar {
            meta: AvatarRef {
                id,
                mime: images.canonical.mime,
                width: images.canonical.width,
                height: images.canonical.height,
            },
            bytes: images.canonical.bytes.into(),
            legacy_gif: images.legacy_gif.map(Into::into),
        }
    }
}

/// Who an avatar belongs to (`docs/avatars.md` §2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AvatarOwner {
    /// A named account, by login.
    Account(String),
    /// A guest session that proved an identity, by fingerprint.
    Identity([u8; 32]),
}

/// What the codec is asked to make an avatar within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvatarLimits {
    /// The largest upload.
    pub max_bytes: usize,
    /// What the canonical rendition is fitted to, on its longer side.
    pub max_dimension: u32,
    /// The legacy GIF rendition's ceiling.
    pub legacy_max_bytes: usize,
}

/// The codec's two renditions of one avatar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarImages {
    pub canonical: Canonical,
    pub legacy_gif: Option<Vec<u8>>,
}

/// `[avatars]`, as far as the domain is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvatarPolicy {
    pub limits: AvatarLimits,
    /// Time one session must leave between two changes: each is pushed to
    /// every session on the server.
    pub set_interval: Duration,
}

impl Default for AvatarPolicy {
    fn default() -> Self {
        AvatarPolicy {
            limits: AvatarLimits {
                max_bytes: 256 * 1024,
                max_dimension: 128,
                legacy_max_bytes: 32 * 1024,
            },
            set_interval: Duration::from_secs(10),
        }
    }
}

/// Where owners' avatars are kept between sessions.
pub trait AvatarStore: Send + Sync + 'static {
    fn load(&self, owner: &AvatarOwner) -> Result<Option<Avatar>, StoreError>;
    /// Replace the owner's avatar, or with `None` remove it.
    fn save(&self, owner: &AvatarOwner, avatar: Option<&Avatar>) -> Result<(), StoreError>;
    /// Any stored avatar with this id, whoever owns it.
    fn by_id(&self, id: &AvatarId) -> Result<Option<Avatar>, StoreError>;
}

/// The store a server with no database keeps: an account's avatar
/// survives from one session to the next until the process ends.
#[derive(Default)]
pub struct MemoryAvatars {
    by_owner: Mutex<HashMap<AvatarOwner, Avatar>>,
}

impl AvatarStore for MemoryAvatars {
    fn load(&self, owner: &AvatarOwner) -> Result<Option<Avatar>, StoreError> {
        Ok(self.by_owner.lock().unwrap().get(owner).cloned())
    }

    fn save(&self, owner: &AvatarOwner, avatar: Option<&Avatar>) -> Result<(), StoreError> {
        let mut map = self.by_owner.lock().unwrap();
        match avatar {
            Some(a) => {
                map.insert(owner.clone(), a.clone());
            }
            None => {
                map.remove(owner);
            }
        }
        Ok(())
    }

    fn by_id(&self, id: &AvatarId) -> Result<Option<Avatar>, StoreError> {
        Ok(self
            .by_owner
            .lock()
            .unwrap()
            .values()
            .find(|a| a.meta.id == *id)
            .cloned())
    }
}

/// The avatar machinery a server with `[avatars]` has.
pub(crate) struct AvatarState {
    pub(crate) store: Arc<dyn AvatarStore>,
    pub(crate) codec: Arc<dyn MediaCodec>,
    pub(crate) policy: AvatarPolicy,
}

/// The owner a session's avatar belongs to, or `None` for a guest with
/// nothing durable to key it on.
pub(crate) fn owner_of(sess: &UserSession) -> Option<AvatarOwner> {
    if sess.system {
        None
    } else if sess.is_person {
        Some(AvatarOwner::Account(sess.login.clone()))
    } else {
        sess.identity.map(AvatarOwner::Identity)
    }
}

impl Core {
    /// Give the domain avatars. Without this neither wire offers them.
    pub fn with_avatars(
        mut self,
        store: Arc<dyn AvatarStore>,
        codec: Arc<dyn MediaCodec>,
        policy: AvatarPolicy,
    ) -> Self {
        self.avatars = Some(AvatarState {
            store,
            codec,
            policy,
        });
        self
    }

    /// `[avatars]`, when the server has it.
    pub fn avatar_policy(&self) -> Option<AvatarPolicy> {
        self.avatars.as_ref().map(|a| a.policy)
    }

    /// Load a session's owner's avatar. The frontends call this after
    /// `attach` and before `announce`, so the join carries the picture.
    /// Store I/O: call it off the reactor.
    pub fn restore_avatar(&self, uid: Uid) {
        let Some(state) = self.avatars.as_ref() else {
            return;
        };
        let _serial = self.avatar_serial.lock().unwrap();
        let (owner, serial) = {
            let r = self.roster.lock().unwrap();
            let Some(sess) = r.users.get(&uid) else {
                return;
            };
            (owner_of(sess), sess.serial)
        };
        let Some(owner) = owner else {
            return;
        };
        let avatar = match state.store.load(&owner) {
            Ok(avatar) => avatar,
            Err(e) => {
                tracing::warn!(target: "avatar", uid, "load: {e}");
                return;
            }
        };
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid).filter(|s| s.serial == serial) else {
            return;
        };
        if sess.avatar == avatar {
            return;
        }
        sess.info.avatar = avatar.as_ref().map(|a| a.meta.clone());
        sess.avatar = avatar;
        if sess.visible {
            let ev = Event::AvatarChanged(sess.info.clone());
            r.broadcast_where(&ev, None, |_| true);
        }
    }

    /// Set a session's owner's avatar from uploaded bytes. The decode is
    /// the codec's: call this off the reactor.
    pub fn set_avatar(&self, uid: Uid, input: &[u8]) -> Result<AvatarRef, MediaReject> {
        let state = self.avatars.as_ref().ok_or(MediaReject::Unsupported)?;
        if input.len() > state.policy.limits.max_bytes {
            return Err(MediaReject::TooLarge);
        }
        self.take_avatar_turn(uid, state.policy.set_interval)?;
        let images = state.codec.avatar(input, &state.policy.limits)?;
        let avatar = Avatar::from_images(images);
        let meta = avatar.meta.clone();
        self.change_avatar(uid, Some(avatar))
            .map_err(|_| MediaReject::Generic)?;
        Ok(meta)
    }

    /// Clear a session's owner's avatar. `Ok(false)` when there was none.
    pub fn clear_avatar(&self, uid: Uid) -> Result<bool, MediaReject> {
        let state = self.avatars.as_ref().ok_or(MediaReject::Unsupported)?;
        let had = self
            .roster
            .lock()
            .unwrap()
            .users
            .get(&uid)
            .is_some_and(|s| s.avatar.is_some());
        if !had {
            return Ok(false);
        }
        self.take_avatar_turn(uid, state.policy.set_interval)?;
        self.change_avatar(uid, None)
            .map_err(|_| MediaReject::Generic)?;
        Ok(true)
    }

    /// One change per `interval` per session.
    fn take_avatar_turn(&self, uid: Uid, interval: Duration) -> Result<(), MediaReject> {
        let mut r = self.roster.lock().unwrap();
        let sess = r.users.get_mut(&uid).ok_or(MediaReject::Generic)?;
        let now = Instant::now();
        if sess
            .avatar_changed_at
            .is_some_and(|at| now.duration_since(at) < interval)
        {
            return Err(MediaReject::RateLimited);
        }
        sess.avatar_changed_at = Some(now);
        Ok(())
    }

    /// Store the change, then show it on every live session of the owner.
    fn change_avatar(&self, uid: Uid, avatar: Option<Avatar>) -> Result<(), StoreError> {
        let state = self.avatars.as_ref().expect("checked by the caller");
        let _serial = self.avatar_serial.lock().unwrap();
        let owner = {
            let r = self.roster.lock().unwrap();
            let Some(sess) = r.users.get(&uid) else {
                return Ok(());
            };
            owner_of(sess)
        };
        if let Some(owner) = &owner {
            state.store.save(owner, avatar.as_ref())?;
        }
        let mut r = self.roster.lock().unwrap();
        let meta = avatar.as_ref().map(|a| a.meta.clone());
        let mut changed = Vec::new();
        for (u, sess) in r.users.iter_mut() {
            let mine = match &owner {
                Some(owner) => owner_of(sess).as_ref() == Some(owner),
                None => *u == uid,
            };
            if !mine || sess.avatar == avatar {
                continue;
            }
            sess.avatar = avatar.clone();
            sess.info.avatar = meta.clone();
            if sess.visible {
                changed.push(sess.info.clone());
            }
        }
        for info in changed {
            r.broadcast_where(&Event::AvatarChanged(info), None, |_| true);
        }
        Ok(())
    }

    /// A session's avatar with its bytes.
    pub fn avatar_of(&self, uid: Uid) -> Option<Avatar> {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .filter(|s| s.visible)
            .and_then(|s| s.avatar.clone())
    }

    /// Every visible session's avatar, in uid order.
    pub fn avatars(&self) -> Vec<(Uid, Avatar)> {
        let r = self.roster.lock().unwrap();
        let mut all: Vec<_> = r
            .users
            .iter()
            .filter(|(_, s)| s.visible)
            .filter_map(|(uid, s)| s.avatar.clone().map(|a| (*uid, a)))
            .collect();
        all.sort_by_key(|(uid, _)| *uid);
        all
    }

    /// An avatar by id: one a session on the roster shows, or one stored
    /// for an owner. Store I/O on a miss: call it off the reactor.
    pub fn avatar_by_id(&self, id: &AvatarId) -> Option<Avatar> {
        let state = self.avatars.as_ref()?;
        let live = {
            let r = self.roster.lock().unwrap();
            r.users
                .values()
                .filter_map(|s| s.avatar.as_ref())
                .find(|a| a.meta.id == *id)
                .cloned()
        };
        live.or_else(|| match state.store.by_id(id) {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!(target: "avatar", "by id: {e}");
                None
            }
        })
    }
}

/// A suite every [`AvatarStore`] must pass: the in-memory one here and
/// the SQLite one a server keeps its avatars in.
pub mod conformance {
    use super::*;

    /// Run every case against a freshly built store.
    pub fn run(new_store: &dyn Fn() -> Box<dyn AvatarStore>) {
        an_owner_has_one_avatar_until_it_is_removed(&*new_store());
        owners_of_either_kind_never_meet(&*new_store());
        an_avatar_is_found_by_id_whoever_owns_it(&*new_store());
        an_avatar_without_a_legacy_rendition_stays_without_one(&*new_store());
    }

    pub fn avatar(seed: u8, mime: MediaType) -> Avatar {
        let bytes = vec![seed; 16 + seed as usize];
        Avatar {
            meta: AvatarRef {
                id: AvatarId::of(&bytes),
                mime,
                width: 32 + u32::from(seed),
                height: 16,
            },
            bytes: bytes.into(),
            legacy_gif: Some(vec![b'G', seed].into()),
        }
    }

    fn an_owner_has_one_avatar_until_it_is_removed(store: &dyn AvatarStore) {
        let alice = AvatarOwner::Account("alice".into());
        assert_eq!(store.load(&alice).unwrap(), None);
        let first = avatar(1, MediaType::Png);
        store.save(&alice, Some(&first)).unwrap();
        assert_eq!(store.load(&alice).unwrap(), Some(first));
        let second = avatar(2, MediaType::Gif);
        store.save(&alice, Some(&second)).unwrap();
        assert_eq!(store.load(&alice).unwrap(), Some(second));
        store.save(&alice, None).unwrap();
        assert_eq!(store.load(&alice).unwrap(), None);
        // Removing what is not there is not an error.
        store.save(&alice, None).unwrap();
    }

    fn owners_of_either_kind_never_meet(store: &dyn AvatarStore) {
        let account = AvatarOwner::Account("bob".into());
        let identity = AvatarOwner::Identity([7; 32]);
        store
            .save(&account, Some(&avatar(3, MediaType::Jpeg)))
            .unwrap();
        assert_eq!(store.load(&identity).unwrap(), None);
        store
            .save(&identity, Some(&avatar(4, MediaType::Png)))
            .unwrap();
        assert_eq!(
            store.load(&account).unwrap(),
            Some(avatar(3, MediaType::Jpeg))
        );
        assert_eq!(
            store.load(&identity).unwrap(),
            Some(avatar(4, MediaType::Png))
        );
        assert_eq!(
            store.load(&AvatarOwner::Account("Bob".into())).unwrap(),
            None,
            "logins are compared as given"
        );
    }

    fn an_avatar_is_found_by_id_whoever_owns_it(store: &dyn AvatarStore) {
        let shared = avatar(5, MediaType::Png);
        store
            .save(&AvatarOwner::Account("carol".into()), Some(&shared))
            .unwrap();
        store
            .save(&AvatarOwner::Identity([9; 32]), Some(&shared))
            .unwrap();
        assert_eq!(store.by_id(&shared.meta.id).unwrap(), Some(shared.clone()));
        store
            .save(&AvatarOwner::Account("carol".into()), None)
            .unwrap();
        assert_eq!(store.by_id(&shared.meta.id).unwrap(), Some(shared.clone()));
        store.save(&AvatarOwner::Identity([9; 32]), None).unwrap();
        assert_eq!(store.by_id(&shared.meta.id).unwrap(), None);
    }

    fn an_avatar_without_a_legacy_rendition_stays_without_one(store: &dyn AvatarStore) {
        let owner = AvatarOwner::Account("dave".into());
        let mut plain = avatar(6, MediaType::Jpeg);
        plain.legacy_gif = None;
        store.save(&owner, Some(&plain)).unwrap();
        assert_eq!(store.load(&owner).unwrap(), Some(plain));
    }
}

#[cfg(test)]
mod tests;
