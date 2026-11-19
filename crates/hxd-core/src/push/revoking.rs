//! The registry as the domain and the gateways see it: the store, less
//! the rows of a revoked key that a store error kept.
//!
//! A failed delete is retried (`Core::sweep_devices`), but until it
//! succeeds the row is still the store's, and both gateways read the
//! rows they deliver to and subscribe from the store. So the keys still
//! to be taken are kept here, and the two reads that lead to a delivery,
//! [`PushStore::devices`] and [`PushStore::unsubscribed`], leave their
//! rows out.
//!
//! The pending keys are not kept across a restart. The operator's list
//! is applied at startup, which takes its keys' rows again; a
//! registrar's revocation is applied, and its rows taken, once its
//! identity has a session here again.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use super::{Device, DeviceId, PushStore, Registered, SidecarRecord, Unrevoked};
use crate::inbox::{Mailbox, StoreError};

pub(crate) struct Revoking {
    store: Arc<dyn PushStore>,
    /// Revoked keys whose rows a store error kept.
    pub(crate) pending: Mutex<Vec<Unrevoked>>,
}

impl Revoking {
    pub(crate) fn new(store: Arc<dyn PushStore>) -> Self {
        Revoking {
            store,
            pending: Mutex::default(),
        }
    }

    fn live(&self, mut rows: Vec<Device>) -> Vec<Device> {
        let pending = self.pending.lock().unwrap();
        if !pending.is_empty() {
            rows.retain(|d| !pending.iter().any(|k| k.made(d)));
        }
        rows
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
        Ok(self.live(self.store.devices(owner, now)?))
    }

    fn unsubscribed(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        Ok(self.live(self.store.unsubscribed(now)?))
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
