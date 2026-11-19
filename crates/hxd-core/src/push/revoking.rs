//! The registry as the domain and the gateways see it: the store, less
//! the rows of a revoked key that a store error kept.
//!
//! A revoked key's rows are deleted when its revocation is applied, and a
//! failed delete is retried (`Core::sweep_devices`), but until then the
//! rows are still the store's, and both gateways read the rows they
//! deliver to and subscribe from the store. So the two reads that lead to
//! a delivery, [`PushStore::devices`] and [`PushStore::unsubscribed`],
//! leave out every row of a key the lists refuse now, and of a key still
//! to be taken here, whatever order the rows are written and deleted in.
//!
//! The pending keys are not kept across a restart. The operator's list
//! is applied at startup, which takes its keys' rows again; a
//! registrar's revocation is applied, and its rows taken, once its
//! identity has a session here again.

use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use super::{Device, DeviceId, PushStore, Registered, SidecarRecord, Unrevoked};
use crate::inbox::{Mailbox, StoreError};
use crate::revoked::Refused;

pub(crate) struct Revoking {
    store: Arc<dyn PushStore>,
    /// Revoked keys whose rows a store error kept, each with the count
    /// of the last time it was added, so a retry that took its rows
    /// before it was added again does not forget it.
    pub(crate) pending: Mutex<(u64, Vec<(u64, Unrevoked)>)>,
    /// The core's lists.
    revoked: Arc<RwLock<Refused>>,
}

impl Revoking {
    pub(crate) fn new(store: Arc<dyn PushStore>, revoked: Arc<RwLock<Refused>>) -> Self {
        Revoking {
            store,
            pending: Mutex::default(),
            revoked,
        }
    }

    /// What `read` answers, less the rows of a revoked key. The pending
    /// keys are copied before it reads, so a retry that takes a row and
    /// forgets its key meanwhile cannot let a copy of the row through.
    fn live(
        &self,
        read: impl FnOnce() -> Result<Vec<Device>, StoreError>,
    ) -> Result<Vec<Device>, StoreError> {
        let pending = self.pending.lock().unwrap().1.clone();
        let mut rows = read()?;
        let refused = self.revoked.read().unwrap();
        rows.retain(|d| !refused.refuses_row(d) && !pending.iter().any(|(_, k)| k.made(d)));
        Ok(rows)
    }
}

impl Unrevoked {
    /// Did this key's device register `d`?
    fn made(&self, d: &Device) -> bool {
        match self {
            Unrevoked::LocalDevice(device) => d.devid == DeviceId::of_device(device),
            Unrevoked::PublishedDevice(i, device) => {
                d.devid == DeviceId::of_device(device) && d.owner.fingerprint == Some(*i)
            }
            Unrevoked::LocalIdentity(i) | Unrevoked::PublishedIdentity(i) => {
                d.owner.fingerprint == Some(*i) && d.devid.is_device_fingerprint()
            }
        }
    }
}

impl PushStore for Revoking {
    fn devices(&self, owner: &Mailbox, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        self.live(|| self.store.devices(owner, now))
    }

    fn unsubscribed(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        self.live(|| self.store.unsubscribed(now))
    }

    fn register(
        &self,
        device: &Device,
        max: usize,
    ) -> Result<(Registered, Vec<Device>), StoreError> {
        self.store.register(device, max)
    }

    fn unregister(&self, owner: &Mailbox, devid: &DeviceId) -> Result<Option<Device>, StoreError> {
        self.store.unregister(owner, devid)
    }

    fn retire(
        &self,
        owner: &Mailbox,
        devid: &DeviceId,
        endpoint: &str,
    ) -> Result<bool, StoreError> {
        self.store.retire(owner, devid, endpoint)
    }

    fn devices_clear(&self) -> Result<usize, StoreError> {
        self.store.devices_clear()
    }

    fn any_devices(&self) -> Result<bool, StoreError> {
        self.store.any_devices()
    }

    fn unregister_all(&self, owner: &Mailbox) -> Result<Vec<Device>, StoreError> {
        self.store.unregister_all(owner)
    }

    fn touch(&self, owner: &Mailbox, devid: &DeviceId, at: SystemTime) -> Result<(), StoreError> {
        self.store.touch(owner, devid, at)
    }

    fn sweep_expired(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        self.store.sweep_expired(now)
    }

    fn devices_claim(
        &self,
        login: &str,
        fingerprint: &[u8; 32],
    ) -> Result<Vec<Device>, StoreError> {
        self.store.devices_claim(login, fingerprint)
    }

    fn devices_rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Vec<Device>, StoreError> {
        self.store.devices_rotate(from, to)
    }

    fn devices_revoke_device(
        &self,
        identity: Option<&[u8; 32]>,
        devid: &DeviceId,
    ) -> Result<Vec<Device>, StoreError> {
        self.store.devices_revoke_device(identity, devid)
    }

    fn devices_revoke_identity(&self, identity: &[u8; 32]) -> Result<Vec<Device>, StoreError> {
        self.store.devices_revoke_identity(identity)
    }

    fn devices_purge(&self, of: &Mailbox) -> Result<Vec<Device>, StoreError> {
        self.store.devices_purge(of)
    }

    fn set_delivery_point(
        &self,
        device: &Device,
        delivery_point: &str,
    ) -> Result<bool, StoreError> {
        self.store.set_delivery_point(device, delivery_point)
    }

    fn clear_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<usize, StoreError> {
        self.store.clear_delivery_point(owner, delivery_point)
    }

    fn clear_delivery_points(&self) -> Result<usize, StoreError> {
        self.store.clear_delivery_points()
    }

    fn retire_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<Vec<Device>, StoreError> {
        self.store.retire_delivery_point(owner, delivery_point)
    }

    fn sidecar(&self) -> Result<Option<SidecarRecord>, StoreError> {
        self.store.sidecar()
    }

    fn set_sidecar(&self, record: &SidecarRecord) -> Result<(), StoreError> {
        self.store.set_sidecar(record)
    }
}
