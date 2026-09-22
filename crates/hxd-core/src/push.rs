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

/// How many devices a mailbox may hold when the configuration does not
/// say (`[push] max_devices`).
pub const DEFAULT_MAX_DEVICES: usize = 20;

pub mod conformance;
pub mod memory;

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
/// conformance suite over both ([`conformance`]).
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
    /// key it is filed under is old.
    fn register(&self, device: &Device, max: usize) -> Result<Registered, StoreError>;

    /// Forget one device, answering whether there was one.
    fn unregister(&self, owner: &Mailbox, devid: &DeviceId) -> Result<bool, StoreError>;

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
    /// — answering how many went.
    fn unregister_all(&self, owner: &Mailbox) -> Result<usize, StoreError>;

    /// The devices a push to `owner` should reach, newest registration
    /// first. **Expired rows are not returned**: `now` is compared
    /// against each `expires`, so a certificate that lapsed silently
    /// stops being pushed at without waiting for a sweep.
    fn devices(&self, owner: &Mailbox, now: SystemTime) -> Result<Vec<Device>, StoreError>;

    /// Stamp a device's `last_push_at`. Best effort from the gateway's
    /// point of view: a failure here loses a timestamp, not a push.
    fn touch(&self, owner: &Mailbox, devid: &DeviceId, at: SystemTime) -> Result<(), StoreError>;

    /// Delete every row whose certificate expired before `now`, answering
    /// how many went. The comparison in [`Self::devices`] is what keeps
    /// an expired device from being pushed at; this is only housekeeping,
    /// and a server that never calls it is correct and slightly fatter.
    fn sweep_expired(&self, now: SystemTime) -> Result<usize, StoreError>;

    /// An account linked an identity: stamp its rows with the
    /// fingerprint. The twin of [`crate::inbox::MessageStore::claim`],
    /// owed at the same call sites. A row the identity already holds for
    /// the same `devid` wins, because it is the one the device itself
    /// last registered.
    fn devices_claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError>;

    /// An identity rotated to a successor key: **drop** the
    /// predecessor's devices, answering how many went.
    ///
    /// The signature matches [`Self::devices_claim`] and
    /// [`crate::news::NewsStore::subs_rotate`] so that whoever lands
    /// rotation cannot pay one obligation and miss this one — but the
    /// behavior deliberately differs. See this module's header, and
    /// push-notifications.md §5.1.
    fn devices_rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError>;

    /// An account went: take its devices with it, so a later holder of
    /// the freed login inherits nobody's phone.
    fn devices_purge(&self, of: &Mailbox) -> Result<usize, StoreError>;
}

/// The domain's side of the registry: the three obligations a mailbox
/// owes, paid from [`crate::roster::Core::inbox_claim`] and its
/// siblings, and the expiry sweep the binary runs on an interval.
///
/// Each is a store call whose failure is logged and swallowed, as mail's
/// and news's are: an operator's disk problem must not take down a
/// login, and a device left behind is a push that goes nowhere, not a
/// message that is lost.
impl crate::roster::Core {
    pub(crate) fn devices_claim(&self, login: &str, fingerprint: &[u8; 32]) {
        if let Some(store) = self.devices.as_ref() {
            if let Err(e) = store.devices_claim(login, fingerprint) {
                tracing::warn!("push: claiming {login}'s devices: {e}");
            }
        }
    }

    pub(crate) fn devices_rotate(&self, from: &[u8; 32], to: &[u8; 32]) {
        if let Some(store) = self.devices.as_ref() {
            if let Err(e) = store.devices_rotate(from, to) {
                tracing::warn!("push: dropping a rotated identity's devices: {e}");
            }
        }
    }

    pub(crate) fn devices_purge(&self, of: &Mailbox) {
        if let Some(store) = self.devices.as_ref() {
            if let Err(e) = store.devices_purge(of) {
                tracing::warn!("push: purging {}'s devices: {e}", of.login);
            }
        }
    }

    /// Delete the rows whose device certificates have expired. The
    /// binary runs this next to the inbox's retention pass; skipping it
    /// costs rows, never a wrong push, because [`PushStore::devices`]
    /// compares expiry itself.
    pub fn sweep_devices(&self) -> usize {
        let Some(store) = self.devices.as_ref() else {
            return 0;
        };
        match store.sweep_expired(SystemTime::now()) {
            Ok(n) => n,
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

        core.inbox_rotate(&fp, &[8u8; 32]);
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

    /// A server with no `[push]` pays nothing and says nothing.
    #[test]
    fn without_a_registry_the_obligations_are_no_ops() {
        let core = Core::new();
        core.inbox_claim("alice", &[7; 32]);
        core.inbox_rotate(&[7; 32], &[8; 32]);
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
