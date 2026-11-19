//! The device registry behind push notifications.
//!
//! Designed in `docs/webpush-gateway.md` §2. The short version: a device
//! is a row keyed `(mailbox, devid)`, and registering over that key
//! *replaces*. The sidecar design this supersedes could not do that —
//! its delivery points were identified by a hash of their own contents,
//! so a phone whose endpoint changed became a second device and the old
//! one was pushed at until a vendor retired it (push-notifications.md
//! §5). Here the key is ours, so a device that re-provisions converges
//! on one row.
//!
//! **The mailbox rule again, and for the third time deliberately.** Mail
//! ([`crate::inbox::Mailbox`]), news subscriptions and now devices are
//! all addressed by identity fingerprint where there is one and by login
//! where there is not, and none of the three ever matches across that
//! line. A device registered against a login that has since changed
//! hands would push a stranger's private messages to the wrong phone,
//! which is the same failure the inbox exists to prevent, one wire
//! further out. The three obligations a login-keyed row owes — claim on
//! linking, purge on deletion, and rotation — are paid at the same call
//! sites, and [`crate::roster::Core::inbox_claim`] and its siblings pay
//! all three at once so that no site can pay one and forget another.
//!
//! **Rotation drops rather than moves** ([`PushStore::devices_rotate`]).
//! That is the one place this store deliberately differs from its two
//! siblings, and the reason is in push-notifications.md §5.1: a
//! successor identity has not vouched for the predecessor's devices, and
//! moving the rows would keep delivering to a phone the new key never
//! approved. The devices re-register at their next login.
//!
//! **The trait is synchronous**, as [`crate::inbox::MessageStore`] is
//! and for the same reason: `Core` is sync all the way down. The
//! *sending* is not — that is the gateway's, it is spawned, and it never
//! happens under a lock (`crate::notify`).

use std::time::SystemTime;

use crate::inbox::{Mailbox, StoreError};
use crate::roster::{IdentityTag, Uid};

/// How many devices a mailbox may hold when the configuration does not
/// say (`[push] max_devices`).
pub const DEFAULT_MAX_DEVICES: usize = 20;

pub mod conformance;
pub mod endpoint;
pub mod memory;
pub(crate) mod revoking;

pub use memory::MemoryDevices;

/// The key a mailbox names one of its devices by.
///
/// On an identity session this is the fingerprint of the device
/// certificate the socket authenticated with, and the client's own
/// suggestion is ignored (push-notifications.md §5.1): the device names
/// itself, so a re-installed app on the same key replaces its own row
/// instead of accumulating a second. On a password session it is the
/// client's own opaque value, one per install.
///
/// Parsed rather than stored as it arrives, for the reason
/// [`crate::inbox::MessageGuid`] is: this is a primary key column, and a
/// key column that accepts arbitrary client text is a place to put
/// anything. Printable ASCII, 8 to 64 bytes, no spaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn parse(s: &str) -> Option<Self> {
        let ok = (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic());
        ok.then(|| DeviceId(s.to_string()))
    }

    /// The device fingerprint's own spelling, for an identity session:
    /// lowercase hex, which is 64 characters and therefore always a
    /// [`DeviceId`] without asking.
    pub fn of_device(fingerprint: &[u8; 32]) -> Self {
        let mut s = String::with_capacity(64);
        for b in fingerprint {
            s.push_str(&format!("{b:02x}"));
        }
        DeviceId(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Is this spelled the way [`Self::of_device`] spells a device
    /// fingerprint? Such an id is an identity device's, and a session
    /// without that device's certificate may not claim it.
    pub fn is_device_fingerprint(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

/// Where a push goes, and what it is encrypted to.
///
/// The three fields a Web Push subscription is made of (RFC 8291) plus
/// the bookkeeping that decides whether we still send to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub owner: Mailbox,
    pub devid: DeviceId,
    /// Absolute `https` URL. Checked before it is stored and again
    /// before every send (`docs/webpush-gateway.md` §6) — the client
    /// chooses it, and it is a URL this server then fetches.
    pub endpoint: String,
    /// The subscription's public key: P-256, uncompressed, 65 bytes.
    pub p256dh: [u8; 65],
    /// The subscription's auth secret, 16 bytes.
    pub auth: [u8; 16],
    /// When the device certificate expires, for a device that has one.
    /// Past it the row is skipped and then swept, which is how a lost
    /// identity device stops buzzing without anyone remembering to
    /// unregister it (push-notifications.md §5.1). `None` for a password
    /// device, which expires only when it is removed.
    pub expires: Option<SystemTime>,
    pub registered_at: SystemTime,
    /// Advanced on every accepted send, so an operator can see which
    /// devices are live without reading a provider's logs.
    pub last_push_at: Option<SystemTime>,
    /// The name a sidecar gave this row's subscription, for a gateway
    /// that keeps a second copy of the registry: `None` until it has one
    /// (push-notifications.md §4.1). Pushes name these, so a row without
    /// one is not pushed at through the sidecar.
    pub delivery_point: Option<String>,
}

impl Device {
    /// Does `other` hold the subscription this row holds? A sidecar names
    /// a device by its mailbox and these three, so two rows that agree on
    /// them are one device there.
    pub fn same_subscription(&self, other: &Device) -> bool {
        self.endpoint == other.endpoint && self.p256dh == other.p256dh && self.auth == other.auth
    }
}

/// What a sidecar gateway was last told, kept beside the rows it
/// subscribed (push-notifications.md §4.1): which service, which VAPID
/// public key and contact it handed over, and how far it has read the
/// sidecar's log of removals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarRecord {
    pub service: String,
    pub public_key: String,
    pub contact: String,
    pub cursor: Option<String>,
}

/// What [`PushStore::register`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// A device the mailbox did not have.
    Added,
    /// A device it had, re-provisioned: same key, new subscription.
    Replaced,
    /// Nothing: the mailbox already holds as many devices as it may, and
    /// this one is not among them (`docs/webpush-gateway.md` §2).
    Full,
}

/// The device registry. One implementation in memory, one in SQLite, one
/// conformance suite over both ([`conformance`]). A read that leads to a
/// delivery is filtered in `revoking`, which the gateways read through.
pub trait PushStore: Send + Sync + 'static {
    /// Store `device`, replacing any row the same `(owner, devid)`
    /// already has — endpoint, keys, expiry and all.
    ///
    /// A new `devid` is refused, as [`Registered::Full`], when the
    /// mailbox already holds `max` devices. A replacement never is: it
    /// does not grow the mailbox. Before counting, the mailbox's own
    /// expired rows (at `registered_at`) are deleted, so a user whose
    /// certificates lapsed is not refused on account of devices nothing
    /// will push at again. Counting and inserting are one step, so two
    /// registrations racing cannot both slip under the cap.
    ///
    /// `registered_at` is taken from the argument and `last_push_at` is
    /// cleared: a re-registration is a new subscription even when the
    /// key it is filed under is old. Its `delivery_point` is kept from
    /// the row it replaces when that row held the same subscription, and
    /// is `None` otherwise, whatever `device` says.
    ///
    /// Answers with the rows it took as well: the mailbox's expired ones,
    /// and the one it replaced where the subscription changed.
    fn register(
        &self,
        device: &Device,
        max: usize,
    ) -> Result<(Registered, Vec<Device>), StoreError>;

    /// Forget one device, answering with it if there was one.
    fn unregister(&self, owner: &Mailbox, devid: &DeviceId) -> Result<Option<Device>, StoreError>;

    /// Forget one device **only if it still has `endpoint`**, answering
    /// whether it did. This is the gateway's delete, for a push service
    /// that answered `404` or `410`: that answer is about the endpoint
    /// that was sent to, and a client that re-subscribed while the push
    /// was in flight has already replaced the row with one the answer
    /// says nothing about.
    fn retire(&self, owner: &Mailbox, devid: &DeviceId, endpoint: &str)
        -> Result<bool, StoreError>;

    /// Forget every device of every mailbox, answering how many went.
    /// `hxd push rekey`'s half of a rekey: every row is bound to the
    /// key being replaced (`docs/webpush-gateway.md` §3).
    fn devices_clear(&self) -> Result<usize, StoreError>;

    /// Does the registry hold any device at all? Asked at startup, when
    /// the VAPID key is missing, to tell a first start from a lost key.
    fn any_devices(&self) -> Result<bool, StoreError>;

    /// Forget every device of a mailbox — `push_unregister { all: true }`
    /// — answering with the rows that went.
    fn unregister_all(&self, owner: &Mailbox) -> Result<Vec<Device>, StoreError>;

    /// The devices a push to `owner` should reach, newest registration
    /// first. **Expired rows are not returned**: `now` is compared
    /// against each `expires`, so a certificate that lapsed silently
    /// stops being pushed at without waiting for a sweep.
    fn devices(&self, owner: &Mailbox, now: SystemTime) -> Result<Vec<Device>, StoreError>;

    /// Stamp a device's `last_push_at`. Best effort from the gateway's
    /// point of view: a failure here loses a timestamp, not a push.
    fn touch(&self, owner: &Mailbox, devid: &DeviceId, at: SystemTime) -> Result<(), StoreError>;

    /// Delete every row whose certificate expired before `now`, answering
    /// with the rows that went. The comparison in [`Self::devices`] is
    /// what keeps an expired device from being pushed at; this is only
    /// housekeeping, and a server that never calls it is correct and
    /// slightly fatter.
    fn sweep_expired(&self, now: SystemTime) -> Result<Vec<Device>, StoreError>;

    /// An account linked an identity: stamp its rows with the
    /// fingerprint. The twin of [`crate::inbox::MessageStore::claim`],
    /// owed at the same call sites. A row the identity already holds for
    /// the same `devid` wins, because it is the one the device itself
    /// last registered.
    ///
    /// Answers with every row the login held, as it was: each has left
    /// the login's subscriber, and a moved row's delivery point is
    /// cleared, since a sidecar knows it under the subscriber it left.
    fn devices_claim(&self, login: &str, fingerprint: &[u8; 32])
        -> Result<Vec<Device>, StoreError>;

    /// An identity rotated to a successor key: **drop** the
    /// predecessor's devices, answering with the rows that went.
    ///
    /// `Core::rotate_identity` calls it beside
    /// [`crate::news::NewsStore::subs_rotate`] and the mail's, but the
    /// behavior deliberately differs. See this module's header, and
    /// push-notifications.md §5.1.
    fn devices_rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Vec<Device>, StoreError>;

    /// A device key was revoked here: forget the rows it registered,
    /// which are filed under its fingerprint (push-notifications.md
    /// §5.1), answering with them. Only `identity`'s where one is named,
    /// since a registrar's device revocation is that identity's to make.
    fn devices_revoke_device(
        &self,
        identity: Option<&[u8; 32]>,
        devid: &DeviceId,
    ) -> Result<Vec<Device>, StoreError>;

    /// An identity key was revoked here: forget every row its devices
    /// registered, answering with them. A password device's row stays,
    /// because a password is not the key that was revoked.
    fn devices_revoke_identity(&self, identity: &[u8; 32]) -> Result<Vec<Device>, StoreError>;

    /// An account went: take its devices with it, so a later holder of
    /// the freed login inherits nobody's phone.
    fn devices_purge(&self, of: &Mailbox) -> Result<Vec<Device>, StoreError>;

    /// Record the delivery point a sidecar named this row's subscription
    /// by, **only while the row still holds that subscription**, and
    /// answer whether it did. A subscribe overtaken by a replacement
    /// writes nothing (push-notifications.md §4.1).
    fn set_delivery_point(&self, device: &Device, delivery_point: &str)
        -> Result<bool, StoreError>;

    /// Forget the delivery point on each of `owner`'s rows that has it,
    /// answering how many did: the sidecar does not have it, and those
    /// rows are subscribed again.
    fn clear_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<usize, StoreError>;

    /// Forget every delivery point, answering how many there were: the
    /// sidecar may have lost any of them.
    fn clear_delivery_points(&self) -> Result<usize, StoreError>;

    /// The live rows a sidecar has not named yet, oldest registration
    /// first.
    fn unsubscribed(&self, now: SystemTime) -> Result<Vec<Device>, StoreError>;

    /// Delete each of `owner`'s rows that has `delivery_point`, answering
    /// with them: the sidecar pruned that device. A row subscribed afresh
    /// since has another, or none yet, and stays.
    fn retire_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<Vec<Device>, StoreError>;

    /// What a sidecar gateway was last told, if one ever was.
    fn sidecar(&self) -> Result<Option<SidecarRecord>, StoreError>;

    fn set_sidecar(&self, record: &SidecarRecord) -> Result<(), StoreError>;
}

/// A revoked key whose rows are still to be taken, by whose list it is
/// revoked: the operator's lifts a key when it leaves it out, and a
/// registrar's does not (`Refused::lifts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unrevoked {
    /// A device the operator revoked: its rows in every mailbox.
    LocalDevice([u8; 32]),
    /// An identity the operator revoked, or one rotated away from.
    LocalIdentity([u8; 32]),
    /// A device an identity revoked at a registrar: its rows in that
    /// identity's mailboxes.
    PublishedDevice([u8; 32], [u8; 32]),
    PublishedIdentity([u8; 32]),
}

impl Unrevoked {
    fn take(&self, store: &dyn PushStore) -> Result<Vec<Device>, StoreError> {
        match self {
            Unrevoked::LocalDevice(d) => store.devices_revoke_device(None, &DeviceId::of_device(d)),
            Unrevoked::PublishedDevice(i, d) => {
                store.devices_revoke_device(Some(i), &DeviceId::of_device(d))
            }
            Unrevoked::LocalIdentity(i) | Unrevoked::PublishedIdentity(i) => {
                store.devices_revoke_identity(i)
            }
        }
    }
}

/// Why a device was not registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// No `[push]`, so there is no registry and nothing would ever be
    /// sent. The same shape news gives a server with no `[news.notify]`.
    NotAvailable,
    /// A guest. There is nothing durable to deliver to, so there is
    /// nothing to wake someone about (private-messages.md §2).
    NoMailbox,
    /// The session is gone.
    NoSession,
    /// The subscription is not one: an endpoint that is not an `https`
    /// URL we may fetch, or keys of the wrong size.
    BadSubscription(&'static str),
    /// The key the session's socket proved is revoked here, and the
    /// session is being ended.
    Revoked,
    /// A new device past the mailbox's cap (`docs/webpush-gateway.md`
    /// §2). A device it already has may always re-register.
    TooManyDevices,
    /// The store would not answer. An operator's problem, said as one.
    StoreFailed,
}

/// `[push]`'s limits on a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushPolicy {
    /// Devices a mailbox may hold.
    pub max_devices: usize,
    /// Lift the address check, for the operator whose push service is
    /// on their own network — at registration here, as the gateway lifts
    /// it at send.
    pub allow_private_endpoints: bool,
}

impl Default for PushPolicy {
    fn default() -> Self {
        PushPolicy {
            max_devices: DEFAULT_MAX_DEVICES,
            allow_private_endpoints: false,
        }
    }
}

/// What a client sent to register a device, once the frontend has
/// decoded it. The `devid` is **not** in it: on an identity session it
/// is the certificate's and the client does not choose it, and on a
/// password session the frontend has parsed the client's own
/// (push-notifications.md §5.1), so by here it is settled either way.
#[derive(Debug, Clone)]
pub struct Registration {
    pub devid: DeviceId,
    pub endpoint: String,
    pub p256dh: [u8; 65],
    pub auth: [u8; 16],
    /// The device certificate's expiry, for a session that has one.
    pub expires: Option<SystemTime>,
}

/// The domain's side of the registry: registration, the three
/// obligations a mailbox owes, paid from
/// [`crate::roster::Core::inbox_claim`] and its siblings, and the expiry
/// sweep the binary runs on an interval.
///
/// Each is a store call whose failure is logged and swallowed, as mail's
/// and news's are: an operator's disk problem must not take down a
/// login, and a device left behind is a push that goes nowhere, not a
/// message that is lost.
impl crate::roster::Core {
    /// Is there a registry at all? What the login reply's `push` block
    /// and the `push` capability are present for.
    pub fn push_enabled(&self) -> bool {
        self.devices.is_some()
    }

    /// Register `uid`'s device, answering whether it replaced a row —
    /// which is a device that re-provisioned rather than a new one.
    ///
    /// The account comes from the session and never from the request:
    /// otherwise anyone could register a device against anyone's account
    /// and subscribe to their private messages (push-notifications.md
    /// §7). Whether the *device* may do this — its certificate's
    /// `message` bit — is the frontend's, because it is a fact about the
    /// transport and the domain has never seen a certificate.
    pub fn push_register(&self, uid: Uid, r: Registration) -> Result<bool, PushError> {
        let store = self.devices.as_ref().ok_or(PushError::NotAvailable)?;
        let (owner, key) = self.push_mailbox(uid)?;
        // The shape check a client can be told about. The address it
        // resolves to is the gateway's to check, before every send.
        let policy = self.push_policy;
        let devid = r.devid;
        endpoint::registrable(&r.endpoint, policy.allow_private_endpoints)
            .map_err(|_| PushError::BadSubscription("That is not a push endpoint."))?;
        let registered = store
            .register(
                &Device {
                    owner: owner.clone(),
                    devid: devid.clone(),
                    endpoint: r.endpoint,
                    p256dh: r.p256dh,
                    auth: r.auth,
                    expires: r.expires,
                    registered_at: SystemTime::now(),
                    last_push_at: None,
                    delivery_point: None,
                },
                policy.max_devices,
            )
            .map_err(|e| {
                tracing::warn!("push: registering a device: {e}");
                PushError::StoreFailed
            })?;
        let (registered, mut taken) = registered;
        // Asked once the row is stored, so a revocation either finds the
        // row to take or is found here.
        let pending = key
            .as_ref()
            .and_then(|k| self.revoked.read().unwrap().pending_for(k));
        let revoked = pending.is_some();
        if let Some(k) = pending.filter(|_| registered != Registered::Full) {
            match store.unregister(&owner, &devid) {
                Ok(row) => taken.extend(row),
                Err(e) => {
                    tracing::warn!("push: forgetting a revoked device: {e}");
                    self.take_revoked(vec![k]);
                }
            }
        }
        self.devices_changed(!revoked && registered != Registered::Full, &taken);
        if revoked {
            return Err(PushError::Revoked);
        }
        match registered {
            Registered::Added => Ok(false),
            Registered::Replaced => Ok(true),
            Registered::Full => Err(PushError::TooManyDevices),
        }
    }

    /// Forget one of `uid`'s devices, or all of them.
    ///
    /// Answers nothing about how many there were: telling a client the
    /// size of an account's device list is not this request's business,
    /// and the answer is the same whether or not there was anything to
    /// take.
    pub fn push_unregister(&self, uid: Uid, devid: Option<DeviceId>) -> Result<(), PushError> {
        let store = self.devices.as_ref().ok_or(PushError::NotAvailable)?;
        let (owner, _) = self.push_mailbox(uid)?;
        let taken = match devid {
            Some(devid) => store
                .unregister(&owner, &devid)
                .map(|d| d.into_iter().collect()),
            None => store.unregister_all(&owner),
        }
        .map_err(|e| {
            tracing::warn!("push: unregistering a device of {}: {e}", owner.login);
            PushError::StoreFailed
        })?;
        self.devices_changed(false, &taken);
        Ok(())
    }

    /// Tell the gateway what the registry gained and lost, for one that
    /// keeps a copy of its own (`NotificationGateway::devices_changed`).
    pub(crate) fn devices_changed(&self, added: bool, taken: &[Device]) {
        if let Some(gateway) = self.gateway.as_ref() {
            if added || !taken.is_empty() {
                gateway.devices_changed(added, taken);
            }
        }
    }

    /// The mailbox a registration belongs to: a session's own, and only
    /// where it has one. With the key its socket proved, if it did.
    fn push_mailbox(&self, uid: Uid) -> Result<(Mailbox, Option<IdentityTag>), PushError> {
        let r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid).ok_or(PushError::NoSession)?;
        if !sess.has_inbox {
            return Err(PushError::NoMailbox);
        }
        Ok((sess.mailbox(), sess.info.transport.identity.clone()))
    }

    pub(crate) fn devices_claim(&self, login: &str, fingerprint: &[u8; 32]) {
        if let Some(store) = self.devices.as_ref() {
            match store.devices_claim(login, fingerprint) {
                Ok(taken) => self.devices_changed(!taken.is_empty(), &taken),
                Err(e) => tracing::warn!("push: claiming {login}'s devices: {e}"),
            }
        }
    }

    pub(crate) fn devices_purge(&self, of: &Mailbox) {
        if let Some(store) = self.devices.as_ref() {
            match store.devices_purge(of) {
                Ok(taken) => self.devices_changed(false, &taken),
                Err(e) => tracing::warn!("push: purging {}'s devices: {e}", of.login),
            }
        }
    }

    /// Take the rows of `keys`, keys now revoked here, and of every key a
    /// store error left. Each is pending, its rows hidden from the
    /// gateways, until a delete succeeds or the key is lifted: a revoked
    /// key's row must not outlive one failed delete. The lists are read
    /// only to choose the keys, so no store call is made under them.
    pub(crate) fn take_revoked(&self, keys: Vec<Unrevoked>) {
        let Some(store) = self.devices.as_ref() else {
            return;
        };
        let keys = {
            let refused = self.revoked.read().unwrap();
            let mut pending = store.pending.lock().unwrap();
            for key in keys {
                if !pending.contains(&key) {
                    pending.push(key);
                }
            }
            pending.retain(|k| !refused.lifts(k));
            pending.clone()
        };
        for key in keys {
            let taken = key.take(&**store);
            let forget = match &taken {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!("push: forgetting a revoked key's devices: {e}");
                    self.revoked.read().unwrap().lifts(&key)
                }
            };
            if forget {
                store.pending.lock().unwrap().retain(|k| *k != key);
            }
            if let Ok(taken) = taken {
                self.devices_changed(false, &taken);
            }
        }
    }

    /// Delete the rows whose device certificates have expired. The
    /// binary runs this next to the inbox's retention pass; skipping it
    /// costs rows, never a wrong push, because [`PushStore::devices`]
    /// compares expiry itself. And take again what a store error left of
    /// a revoked key's.
    pub fn sweep_devices(&self) -> usize {
        let Some(store) = self.devices.as_ref() else {
            return 0;
        };
        self.take_revoked(Vec::new());
        match store.sweep_expired(SystemTime::now()) {
            Ok(taken) => {
                self.devices_changed(false, &taken);
                taken.len()
            }
            Err(e) => {
                tracing::warn!("push: sweeping expired devices: {e}");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::roster::Core;

    fn device(owner: Mailbox, id: &str) -> Device {
        Device {
            owner,
            devid: DeviceId::parse(id).unwrap(),
            endpoint: "https://push.example/1".into(),
            p256dh: [4; 65],
            auth: [9; 16],
            expires: None,
            registered_at: SystemTime::now(),
            last_push_at: None,
            delivery_point: None,
        }
    }

    /// The obligations are paid *through* `Core`, which is the only way
    /// they can be paid by the sites that already pay mail's: a store
    /// that is right and a `Core` that never calls it is the bug this
    /// test is for.
    #[test]
    fn linking_deleting_and_rotating_reach_the_registry() {
        let devices = Arc::new(MemoryDevices::new());
        let core = Core::new().with_devices(devices.clone());
        let fp = [7u8; 32];
        let now = SystemTime::now();

        devices
            .register(&device(Mailbox::login("alice"), "alices-phone"), 8)
            .unwrap();
        core.inbox_claim("alice", &fp);
        assert!(devices
            .devices(&Mailbox::login("alice"), now)
            .unwrap()
            .is_empty());
        assert_eq!(
            devices
                .devices(&Mailbox::identified("alice", fp), now)
                .unwrap()
                .len(),
            1,
            "linking moved the device with the mail"
        );

        core.rotate_identity(&fp, &[8u8; 32]).unwrap();
        assert!(
            devices
                .devices(&Mailbox::identified("alice", fp), now)
                .unwrap()
                .is_empty()
                && devices
                    .devices(&Mailbox::identified("alice", [8u8; 32]), now)
                    .unwrap()
                    .is_empty(),
            "rotation drops rather than moves"
        );

        devices
            .register(&device(Mailbox::login("bob"), "bobs-phone!!"), 8)
            .unwrap();
        core.inbox_purge(&Mailbox::login("bob"));
        assert!(devices
            .devices(&Mailbox::login("bob"), now)
            .unwrap()
            .is_empty());
    }

    /// A gateway that keeps a copy of the registry hears every row the
    /// obligations take, as it was, and that a claim gave rows to
    /// subscribe under the identity.
    #[test]
    fn the_gateway_hears_what_the_obligations_take() {
        #[derive(Default)]
        struct Heard(std::sync::Mutex<Vec<(bool, Vec<String>)>>);
        impl crate::notify::NotificationGateway for Heard {
            fn notify(&self, _: &crate::notify::Notification<'_>) {}
            fn devices_changed(&self, added: bool, taken: &[Device]) {
                let taken = taken.iter().map(|d| d.devid.as_str().to_string()).collect();
                self.0.lock().unwrap().push((added, taken));
            }
        }
        let devices = Arc::new(MemoryDevices::new());
        let heard = Arc::new(Heard::default());
        let core = Core::new()
            .with_devices(devices.clone())
            .with_notifications(heard.clone());
        let fp = [7u8; 32];
        let last = || heard.0.lock().unwrap().pop();

        devices
            .register(&device(Mailbox::login("alice"), "alices-phone"), 8)
            .unwrap();
        core.inbox_claim("alice", &fp);
        assert_eq!(last(), Some((true, vec!["alices-phone".into()])));
        core.rotate_identity(&fp, &[8u8; 32]).unwrap();
        assert_eq!(last(), Some((false, vec!["alices-phone".into()])));

        devices
            .register(&device(Mailbox::login("bob"), "bobs-phone!!"), 8)
            .unwrap();
        core.inbox_purge(&Mailbox::login("bob"));
        assert_eq!(last(), Some((false, vec!["bobs-phone!!".into()])));

        let mut lapsed = device(Mailbox::login("carol"), "carols-phone");
        lapsed.expires = Some(SystemTime::now() - std::time::Duration::from_secs(1));
        devices.register(&lapsed, 8).unwrap();
        core.sweep_devices();
        assert_eq!(last(), Some((false, vec!["carols-phone".into()])));

        core.sweep_devices();
        assert_eq!(last(), None, "nothing taken, nothing said");
    }

    /// An account `bob` with a mailbox, its socket having proved
    /// `identity` if given.
    fn attach(core: &Core, identity: Option<IdentityTag>) -> (Uid, crate::Events) {
        core.attach(crate::roster::AttachInfo {
            account: None,
            nick: "bob".into(),
            icon: 1,
            admin: false,
            access: crate::access::AccessBits::empty(),
            login: "bob".into(),
            addr: None,
            can_detach: true,
            transport: crate::roster::Transport {
                identity,
                ..Default::default()
            },
            has_inbox: true,
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
        })
        .unwrap()
    }

    /// A key revoked here takes the rows its devices registered, and the
    /// gateway hears each row go (push-notifications.md §5.1).
    #[test]
    fn a_revoked_key_takes_its_devices_and_the_gateway_hears() {
        #[derive(Default)]
        struct Heard(std::sync::Mutex<Vec<String>>);
        impl crate::notify::NotificationGateway for Heard {
            fn notify(&self, _: &crate::notify::Notification<'_>) {}
            fn devices_changed(&self, _: bool, taken: &[Device]) {
                let mut heard = self.0.lock().unwrap();
                heard.extend(taken.iter().map(|d| d.devid.as_str().to_string()));
            }
        }
        let devices = Arc::new(MemoryDevices::new());
        let heard = Arc::new(Heard::default());
        let core = Core::new()
            .with_devices(devices.clone())
            .with_notifications(heard.clone());
        let (fp, phone, laptop) = ([7u8; 32], [10u8; 32], [11u8; 32]);
        let alice = Mailbox::identified("alice", fp);
        for id in [
            DeviceId::of_device(&phone),
            DeviceId::of_device(&laptop),
            DeviceId::parse("alices-password").unwrap(),
        ] {
            devices
                .register(&device(alice.clone(), id.as_str()), 8)
                .unwrap();
        }
        let left = || devices.devices(&alice, SystemTime::now()).unwrap().len();

        core.set_published_revocations(crate::Published {
            devices: [(fp, phone)].into(),
            ..Default::default()
        });
        assert_eq!(left(), 2, "the phone went");
        assert_eq!(
            *heard.0.lock().unwrap(),
            [DeviceId::of_device(&phone).as_str()]
        );

        core.set_revocations(crate::Revocations {
            identities: [fp].into(),
            ..Default::default()
        });
        assert_eq!(left(), 1, "and the laptop, but not the password device");
        assert_eq!(heard.0.lock().unwrap().len(), 2);
    }

    /// What a socket that proved `device` of identity `[7; 32]` carries.
    fn tag(device: [u8; 32]) -> IdentityTag {
        IdentityTag {
            fingerprint: [7; 32],
            device,
            handle: None,
            quiet_until: None,
            signs: false,
            can_sign: false,
            device_expires: u64::MAX,
            sealed: None,
            device_cert: None,
        }
    }

    fn registration(device: [u8; 32]) -> Registration {
        Registration {
            devid: DeviceId::of_device(&device),
            endpoint: "https://push.example/1".into(),
            p256dh: [4; 65],
            auth: [9; 16],
            expires: None,
        }
    }

    /// A revoked device whose session is not yet gone registers nothing.
    #[test]
    fn a_revoked_device_cannot_register() {
        let devices = Arc::new(MemoryDevices::new());
        let core = Core::new().with_devices(devices.clone());
        let (uid, _events) = attach(&core, Some(tag([10; 32])));
        // The list is in, and the session's kick not yet acted on.
        core.revoked.write().unwrap().local.devices.insert([10; 32]);
        let registered = core.push_register(uid, registration([10; 32]));
        assert_eq!(registered, Err(PushError::Revoked));
        assert!(devices
            .devices(&Mailbox::login("bob"), SystemTime::now())
            .unwrap()
            .is_empty());
    }

    /// A delete that fails does not leave a revoked key's row for good:
    /// the sweep takes it, whether the revocation's own delete failed or
    /// a racing registration's taking itself back did.
    #[test]
    fn a_revoked_keys_row_outlives_no_store_error() {
        use std::sync::atomic::Ordering::SeqCst;
        let devices = Arc::new(MemoryDevices::new());
        let core = Core::new().with_devices(devices.clone());
        let rows = |m: &Mailbox| devices.devices(m, SystemTime::now()).unwrap().len();
        // What a gateway reads to deliver and to subscribe, empty for `m`.
        let gateway = core.push_store().unwrap();
        let read = |m: &Mailbox| {
            gateway.devices(m, SystemTime::now()).unwrap().is_empty()
                && !gateway
                    .unsubscribed(SystemTime::now())
                    .unwrap()
                    .iter()
                    .any(|d| d.owner == *m)
        };

        let alice = Mailbox::identified("alice", [7; 32]);
        let phone = DeviceId::of_device(&[10; 32]);
        devices
            .register(&device(alice.clone(), phone.as_str()), 8)
            .unwrap();
        devices.failing_deletes.store(1, SeqCst);
        core.set_published_revocations(crate::Published {
            devices: [([7; 32], [10; 32])].into(),
            ..Default::default()
        });
        assert_eq!(rows(&alice), 1, "the revocation's delete failed");
        assert!(read(&alice), "and no gateway is handed the row");
        core.sweep_devices();
        assert_eq!(rows(&alice), 0, "and the sweep took the row");

        let bob = Mailbox::login("bob");
        let (uid, _events) = attach(&core, Some(tag([11; 32])));
        core.revoked.write().unwrap().local.devices.insert([11; 32]);
        // Its own delete, and the retry of it there and then.
        devices.failing_deletes.store(2, SeqCst);
        let registered = core.push_register(uid, registration([11; 32]));
        assert_eq!(registered, Err(PushError::Revoked));
        assert_eq!(rows(&bob), 1, "taking itself back failed");
        assert!(read(&bob), "and no gateway is handed the row");
        core.sweep_devices();
        assert_eq!(rows(&bob), 0, "and the sweep took the row");
    }

    /// A key the operator lifts while its delete waits is forgotten: the
    /// device registered again after the lift keeps its row, and is read.
    #[test]
    fn a_lifted_key_takes_no_row_on_retry() {
        use std::sync::atomic::Ordering::SeqCst;
        let devices = Arc::new(MemoryDevices::new());
        let core = Core::new().with_devices(devices.clone());
        let bob = Mailbox::login("bob");
        let row = device(bob.clone(), DeviceId::of_device(&[12; 32]).as_str());
        devices.register(&row, 8).unwrap();
        // The revocation's delete, and any retry before the sweep.
        devices.failing_deletes.store(2, SeqCst);
        core.set_revocations(crate::Revocations {
            devices: [[12; 32]].into(),
            ..Default::default()
        });
        core.set_revocations(crate::Revocations::default());
        devices
            .register(
                &Device {
                    endpoint: "https://push.example/again".into(),
                    ..row
                },
                8,
            )
            .unwrap();
        core.sweep_devices();
        let gateway = core.push_store().unwrap();
        assert_eq!(gateway.devices(&bob, SystemTime::now()).unwrap().len(), 1);
    }

    /// A registrar's revocation is not lifted by a list made without its
    /// identity's records, which is every list once the identity has no
    /// session here: the row stays hidden, and the sweep takes it.
    #[test]
    fn a_registrars_key_outlives_a_list_that_does_not_cover_it() {
        use std::sync::atomic::Ordering::SeqCst;
        let devices = Arc::new(MemoryDevices::new());
        let core = Core::new().with_devices(devices.clone());
        let alice = Mailbox::identified("alice", [7; 32]);
        devices
            .register(
                &device(alice.clone(), DeviceId::of_device(&[10; 32]).as_str()),
                8,
            )
            .unwrap();
        devices.failing_deletes.store(1, SeqCst);
        core.set_published_revocations(crate::Published {
            devices: [([7; 32], [10; 32])].into(),
            covered: [[7; 32]].into(),
            ..Default::default()
        });
        core.set_published_revocations(crate::Published::default());
        let gateway = core.push_store().unwrap();
        assert!(gateway
            .devices(&alice, SystemTime::now())
            .unwrap()
            .is_empty());
        core.sweep_devices();
        assert!(devices
            .devices(&alice, SystemTime::now())
            .unwrap()
            .is_empty());
    }

    /// A retry hides every pending row until its own delete is done: a
    /// gateway reading while the first key's rows go does not find the
    /// second's.
    #[test]
    fn a_read_during_a_retry_finds_no_pending_row() {
        use std::sync::atomic::Ordering::SeqCst;
        type Store = std::sync::OnceLock<Arc<dyn PushStore>>;
        #[derive(Default)]
        struct Reader(Store, std::sync::Mutex<Vec<String>>);
        impl crate::notify::NotificationGateway for Reader {
            fn notify(&self, _: &crate::notify::Notification<'_>) {}
            fn devices_changed(&self, _: bool, _: &[Device]) {
                let store = self.0.get().unwrap();
                for owner in [Mailbox::login("alice"), Mailbox::login("bob")] {
                    let rows = store.devices(&owner, SystemTime::now()).unwrap();
                    self.1
                        .lock()
                        .unwrap()
                        .extend(rows.into_iter().map(|d| d.endpoint));
                }
            }
        }
        let devices = Arc::new(MemoryDevices::new());
        let reader = Arc::new(Reader::default());
        let core = Core::new().with_devices(devices.clone());
        let _ = reader.0.set(core.push_store().unwrap());
        let core = core.with_notifications(reader.clone());
        for (owner, d) in [("alice", 10u8), ("bob", 11)] {
            let id = DeviceId::of_device(&[d; 32]);
            devices
                .register(&device(Mailbox::login(owner), id.as_str()), 8)
                .unwrap();
        }
        devices.failing_deletes.store(2, SeqCst);
        core.set_revocations(crate::Revocations {
            devices: [[10; 32], [11; 32]].into(),
            ..Default::default()
        });
        core.sweep_devices();
        assert!(devices
            .devices(&Mailbox::login("bob"), SystemTime::now())
            .unwrap()
            .is_empty());
        assert_eq!(*reader.1.lock().unwrap(), Vec::<String>::new());
    }

    /// A registration and an unregistration reach the gateway too: the
    /// subscription a re-registration replaced, and the row taken.
    #[test]
    fn registering_and_unregistering_reach_the_gateway() {
        #[derive(Default)]
        struct Heard(std::sync::Mutex<Vec<(bool, Vec<String>)>>);
        impl crate::notify::NotificationGateway for Heard {
            fn notify(&self, _: &crate::notify::Notification<'_>) {}
            fn devices_changed(&self, added: bool, taken: &[Device]) {
                let taken = taken.iter().map(|d| d.endpoint.clone()).collect();
                self.0.lock().unwrap().push((added, taken));
            }
        }
        let heard = Arc::new(Heard::default());
        let core = Core::new()
            .with_devices(Arc::new(MemoryDevices::new()))
            .with_notifications(heard.clone());
        let (uid, _events) = attach(&core, None);
        let registration = |endpoint: &str| Registration {
            devid: DeviceId::parse("phone-install").unwrap(),
            endpoint: endpoint.into(),
            p256dh: [4; 65],
            auth: [9; 16],
            expires: None,
        };
        let last = || heard.0.lock().unwrap().pop();

        core.push_register(uid, registration("https://push.example/1"))
            .unwrap();
        assert_eq!(last(), Some((true, vec![])));
        core.push_register(uid, registration("https://push.example/2"))
            .unwrap();
        assert_eq!(
            last(),
            Some((true, vec!["https://push.example/1".into()])),
            "the subscription it replaced"
        );
        core.push_unregister(uid, DeviceId::parse("phone-install"))
            .unwrap();
        assert_eq!(last(), Some((false, vec!["https://push.example/2".into()])));
        core.push_unregister(uid, None).unwrap();
        assert_eq!(last(), None, "nothing taken, nothing said");
    }

    /// A server with no `[push]` pays nothing and says nothing.
    #[test]
    fn without_a_registry_the_obligations_are_no_ops() {
        let core = Core::new();
        core.inbox_claim("alice", &[7; 32]);
        core.rotate_identity(&[7; 32], &[8; 32]).unwrap();
        core.inbox_purge(&Mailbox::login("alice"));
        assert_eq!(core.sweep_devices(), 0);
    }

    #[test]
    fn the_sweep_takes_what_expired() {
        let devices = Arc::new(MemoryDevices::new());
        let core = Core::new().with_devices(devices.clone());
        // The live one first: registering prunes the mailbox's own
        // expired rows, and this test is about the sweep.
        devices
            .register(&device(Mailbox::login("alice"), "alices-lapto"), 8)
            .unwrap();
        let mut lapsed = device(Mailbox::login("alice"), "alices-phone");
        lapsed.expires = Some(SystemTime::now() - std::time::Duration::from_secs(1));
        devices.register(&lapsed, 8).unwrap();
        assert_eq!(core.sweep_devices(), 1);
        assert_eq!(
            devices
                .devices(&Mailbox::login("alice"), SystemTime::now())
                .unwrap()
                .len(),
            1
        );
    }
}
