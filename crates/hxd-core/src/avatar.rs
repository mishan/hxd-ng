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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

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
    /// Time one owner must leave between two changes: each is pushed to
    /// every session on the server.
    pub set_interval: Duration,
    /// How long an identity's avatar is kept once the identity stops
    /// logging in; zero keeps it for good. Accounts' are not aged.
    pub identity_retention: Duration,
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
            identity_retention: Duration::from_secs(90 * 24 * 3600),
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
    /// Record that `owner` was on the server at `at`. Saving an avatar
    /// counts as being seen; nothing happens for an owner with none.
    fn seen(&self, owner: &AvatarOwner, at: SystemTime) -> Result<(), StoreError>;
    /// Delete every identity's avatar last seen before `before`, and say
    /// how many went. Accounts' are never aged out: an account is a file
    /// an operator wrote, where an identity is a key anyone can mint, so
    /// only the second kind can grow the table without anyone's say.
    fn prune_identities(&self, before: SystemTime) -> Result<usize, StoreError>;
}

/// The store a server with no database keeps: an account's avatar
/// survives from one session to the next until the process ends.
#[derive(Default)]
pub struct MemoryAvatars {
    by_owner: Mutex<HashMap<AvatarOwner, (Avatar, SystemTime)>>,
}

impl AvatarStore for MemoryAvatars {
    fn load(&self, owner: &AvatarOwner) -> Result<Option<Avatar>, StoreError> {
        Ok(self
            .by_owner
            .lock()
            .unwrap()
            .get(owner)
            .map(|(a, _)| a.clone()))
    }

    fn save(&self, owner: &AvatarOwner, avatar: Option<&Avatar>) -> Result<(), StoreError> {
        let mut map = self.by_owner.lock().unwrap();
        match avatar {
            Some(a) => {
                map.insert(owner.clone(), (a.clone(), SystemTime::now()));
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
            .find(|(a, _)| a.meta.id == *id)
            .map(|(a, _)| a.clone()))
    }

    fn seen(&self, owner: &AvatarOwner, at: SystemTime) -> Result<(), StoreError> {
        if let Some((_, seen)) = self.by_owner.lock().unwrap().get_mut(owner) {
            *seen = at;
        }
        Ok(())
    }

    fn prune_identities(&self, before: SystemTime) -> Result<usize, StoreError> {
        let mut map = self.by_owner.lock().unwrap();
        let was = map.len();
        map.retain(|owner, (_, seen)| matches!(owner, AvatarOwner::Account(_)) || *seen >= before);
        Ok(was - map.len())
    }
}

/// The avatar machinery a server with `[avatars]` has.
pub(crate) struct AvatarState {
    pub(crate) store: Arc<dyn AvatarStore>,
    pub(crate) codec: Arc<dyn MediaCodec>,
    pub(crate) policy: AvatarPolicy,
}

/// Whether `owner` is the owner of `sess`'s avatar: [`owner_of`] without
/// the allocation, for the loop over the whole roster.
fn owns(sess: &UserSession, owner: &AvatarOwner) -> bool {
    if sess.system {
        return false;
    }
    match owner {
        AvatarOwner::Account(login) => sess.is_person && sess.login == *login,
        AvatarOwner::Identity(fp) => !sess.is_person && sess.identity.as_ref() == Some(fp),
    }
}

/// The session a change is for, pinned by serial.
struct Changer {
    uid: Uid,
    serial: u64,
    owner: Option<AvatarOwner>,
}

/// What a change allowance is kept against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Turn {
    Owner(AvatarOwner),
    /// A guest's address, as [`crate::limits::limit_key`] has it.
    Address(IpAddr),
    Session(Uid, u64),
}

/// Every allowance a change by `sess` spends; it may go ahead only when
/// all of them are free. An account is its owner, however many sessions
/// and addresses it has. A guest is its address as well as its identity,
/// if it proved one: a fresh key is free to make and a reconnect is a
/// fresh session, so neither may be a fresh turn. Only a guest with no
/// address to key on is its session.
fn turns_of(uid: Uid, sess: &UserSession, owner: &Option<AvatarOwner>) -> Vec<Turn> {
    let mut turns = Vec::new();
    if let Some(owner) = owner {
        turns.push(Turn::Owner(owner.clone()));
    }
    if !sess.is_person {
        match sess.addr {
            Some(addr) => turns.push(Turn::Address(crate::limits::limit_key(addr))),
            None if owner.is_none() => turns.push(Turn::Session(uid, sess.serial)),
            None => {}
        }
    }
    turns
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
        // A login is what keeps an identity's avatar from being aged out
        // (`prune_avatars`); an account's is never aged, so its logins
        // cost no write.
        if avatar.is_some() && matches!(owner, AvatarOwner::Identity(_)) {
            if let Err(e) = state.store.seen(&owner, SystemTime::now()) {
                tracing::warn!(target: "avatar", uid, "seen: {e}");
            }
        }
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
    ///
    /// `NotAuthorized` for a session whose account may not (`[extra]
    /// set_avatar`), before anything is spent: no turn and no decode.
    pub fn set_avatar(&self, uid: Uid, input: &[u8]) -> Result<AvatarRef, MediaReject> {
        let state = self.avatars.as_ref().ok_or(MediaReject::Unsupported)?;
        let allowed = {
            let r = self.roster.lock().unwrap();
            r.users.get(&uid).ok_or(MediaReject::Generic)?.set_avatar
        };
        if !allowed {
            return Err(MediaReject::NotAuthorized);
        }
        if input.len() > state.policy.limits.max_bytes {
            return Err(MediaReject::TooLarge);
        }
        let who = self.avatar_turn(uid, state.policy.set_interval)?;
        let images = state.codec.avatar(input, &state.policy.limits)?;
        let avatar = Avatar::from_images(images);
        let meta = avatar.meta.clone();
        self.change_avatar(&who, Some(avatar))?;
        Ok(meta)
    }

    /// Clear a session's owner's avatar. `Ok(false)` when there was none.
    /// Not gated on `set_avatar`: a session may always take its picture
    /// down, as one that lost the permission may still be wearing one.
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
        let who = self.avatar_turn(uid, state.policy.set_interval)?;
        self.change_avatar(&who, None)?;
        Ok(true)
    }

    /// Who is asking, and whether they may change an avatar now: one
    /// change per `interval` **per owner**, because a change is shown on
    /// every session of the owner and each is announced to everyone — an
    /// account open on several sessions must not get a turn for each and
    /// make every announcement several times over. A guest is held by its
    /// address too ([`turns_of`]), so reconnecting does not buy a turn.
    /// The turn is spent before the decode, so a refused upload costs one
    /// too.
    fn avatar_turn(&self, uid: Uid, interval: Duration) -> Result<Changer, MediaReject> {
        let (who, keys) = self.avatar_changer(uid)?;
        let now = Instant::now();
        let mut turns = self.avatar_turns.lock().unwrap();
        // Everything older than the interval has no say; dropping it keeps
        // the map to the owners who changed something recently.
        turns.retain(|_, at| now.duration_since(*at) < interval);
        if keys.iter().any(|k| turns.contains_key(k)) {
            return Err(MediaReject::RateLimited);
        }
        for key in keys {
            turns.insert(key, now);
        }
        Ok(who)
    }

    /// Would a change this session asks for now be allowed and have its
    /// turn? What [`Core::set_avatar`] asks first, asked without spending
    /// the turn, so a frontend can refuse an upload before it reads the
    /// bytes.
    pub fn avatar_change_admits(&self, uid: Uid) -> Result<(), MediaReject> {
        let state = self.avatars.as_ref().ok_or(MediaReject::Unsupported)?;
        let allowed = {
            let r = self.roster.lock().unwrap();
            r.users.get(&uid).ok_or(MediaReject::Generic)?.set_avatar
        };
        if !allowed {
            return Err(MediaReject::NotAuthorized);
        }
        let (_, keys) = self.avatar_changer(uid)?;
        let turns = self.avatar_turns.lock().unwrap();
        let spent = keys.iter().any(|k| {
            turns
                .get(k)
                .is_some_and(|at| at.elapsed() < state.policy.set_interval)
        });
        if spent {
            return Err(MediaReject::RateLimited);
        }
        Ok(())
    }

    /// Who is asking, and the turns a change of theirs spends
    /// ([`turns_of`]).
    fn avatar_changer(&self, uid: Uid) -> Result<(Changer, Vec<Turn>), MediaReject> {
        let (who, keys) = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(MediaReject::Generic)?;
            let owner = owner_of(sess);
            let keys = turns_of(uid, sess, &owner);
            let who = Changer {
                uid,
                serial: sess.serial,
                owner,
            };
            (who, keys)
        };
        Ok((who, keys))
    }

    /// Age out identities' avatars (`AvatarPolicy::identity_retention`),
    /// and say how many went. An identity still on the roster is seen
    /// now, so a session that outlasts the window does not lose its
    /// picture at its next login. Store I/O: call it off the reactor.
    pub fn prune_avatars(&self, now: SystemTime) -> usize {
        let Some(state) = self.avatars.as_ref() else {
            return 0;
        };
        if state.policy.identity_retention.is_zero() {
            return 0;
        }
        let Some(before) = now.checked_sub(state.policy.identity_retention) else {
            return 0;
        };
        // Copied out, then the store: never under the roster's lock.
        let live: std::collections::HashSet<AvatarOwner> = {
            let r = self.roster.lock().unwrap();
            r.users
                .values()
                .filter(|s| s.avatar.is_some())
                .filter_map(owner_of)
                .filter(|o| matches!(o, AvatarOwner::Identity(_)))
                .collect()
        };
        for owner in &live {
            if let Err(e) = state.store.seen(owner, now) {
                tracing::warn!(target: "avatar", "seen: {e}");
            }
        }
        match state.store.prune_identities(before) {
            Ok(gone) => gone,
            Err(e) => {
                tracing::warn!(target: "avatar", "prune: {e}");
                0
            }
        }
    }

    /// Store the change, then show it on every live session of the owner.
    /// The session that asked must still be the one it was: a uid recycles,
    /// and a picture uploaded by one session must never land on the next
    /// holder of its uid. `Generic` when it is gone.
    fn change_avatar(&self, who: &Changer, avatar: Option<Avatar>) -> Result<(), MediaReject> {
        let state = self.avatars.as_ref().expect("checked by the caller");
        let _serial = self.avatar_serial.lock().unwrap();
        let still_here = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&who.uid)
                .is_some_and(|s| s.serial == who.serial)
        };
        if !still_here {
            return Err(MediaReject::Generic);
        }
        if let Some(owner) = &who.owner {
            state.store.save(owner, avatar.as_ref()).map_err(|e| {
                tracing::warn!(target: "avatar", uid = who.uid, "save: {e}");
                MediaReject::Generic
            })?;
        }
        let mut r = self.roster.lock().unwrap();
        let meta = avatar.as_ref().map(|a| a.meta.clone());
        let mut changed = Vec::new();
        for (u, sess) in r.users.iter_mut() {
            let mine = match &who.owner {
                Some(owner) => owns(sess, owner),
                None => *u == who.uid && sess.serial == who.serial,
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
        identities_unseen_are_aged_out_and_accounts_never_are(&*new_store());
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

    fn identities_unseen_are_aged_out_and_accounts_never_are(store: &dyn AvatarStore) {
        let day = Duration::from_secs(24 * 3600);
        let now = SystemTime::now();
        let account = AvatarOwner::Account("erin".into());
        let regular = AvatarOwner::Identity([1; 32]);
        let lapsed = AvatarOwner::Identity([2; 32]);
        store
            .save(&account, Some(&avatar(7, MediaType::Png)))
            .unwrap();
        store
            .save(&regular, Some(&avatar(8, MediaType::Png)))
            .unwrap();
        store
            .save(&lapsed, Some(&avatar(9, MediaType::Png)))
            .unwrap();
        // A save is a sighting: nothing just saved is older than a day.
        assert_eq!(store.prune_identities(now - day).unwrap(), 0);

        // Seeing an owner with no avatar is not an error, and keeps
        // nothing it could later find.
        store
            .seen(&AvatarOwner::Identity([3; 32]), now + 30 * day)
            .unwrap();
        assert_eq!(store.load(&AvatarOwner::Identity([3; 32])).unwrap(), None);

        // Weeks on, the identity that came back stays, the one that did
        // not goes, and the account stays whatever its age.
        store.seen(&regular, now + 30 * day).unwrap();
        assert_eq!(store.prune_identities(now + 20 * day).unwrap(), 1);
        assert_eq!(store.load(&lapsed).unwrap(), None);
        assert_eq!(
            store.by_id(&avatar(9, MediaType::Png).meta.id).unwrap(),
            None,
            "gone by id too"
        );
        assert_eq!(
            store.load(&regular).unwrap(),
            Some(avatar(8, MediaType::Png))
        );
        assert_eq!(
            store.load(&account).unwrap(),
            Some(avatar(7, MediaType::Png))
        );
        assert_eq!(store.prune_identities(now + 20 * day).unwrap(), 0);
        assert_eq!(store.prune_identities(now + 365 * day).unwrap(), 1);
        assert_eq!(
            store.load(&account).unwrap(),
            Some(avatar(7, MediaType::Png))
        );
    }
}

#[cfg(test)]
mod tests;
