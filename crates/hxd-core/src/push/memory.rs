//! An in-memory [`PushStore`]: the domain's tests, and a server that
//! wants push within one run of the process.
//!
//! Public rather than `#[cfg(test)]` for the reason
//! [`crate::inbox::MemoryStore`] is. Where the SQLite store says a rule
//! in SQL this says it in Rust, and [`super::conformance`] holds the two
//! to the same answers.

use std::sync::Mutex;
use std::time::SystemTime;

use super::{Device, DeviceId, PushStore, Registered, SidecarRecord};
use crate::inbox::{Mailbox, StoreError};

/// Does a row owned by `row` belong to `who`? The mailbox rule, which is
/// the only way a device is ever found.
fn owns(who: &Mailbox, row: &Mailbox) -> bool {
    who.matches(&row.login, row.fingerprint.as_ref())
}

/// Has `expires` passed by `now`? A device with no certificate never
/// expires.
fn live(d: &Device, now: SystemTime) -> bool {
    d.expires.is_none_or(|e| e > now)
}

#[derive(Default)]
pub struct MemoryDevices {
    /// In registration order, which is what "newest first" reverses.
    rows: Mutex<Vec<Device>>,
    sidecar: Mutex<Option<SidecarRecord>>,
}

/// Take the rows `gone` picks out of `rows`, answering with them.
fn take(rows: &mut Vec<Device>, gone: impl Fn(&Device) -> bool) -> Vec<Device> {
    let (taken, kept) = std::mem::take(rows).into_iter().partition(gone);
    *rows = kept;
    taken
}

impl MemoryDevices {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PushStore for MemoryDevices {
    fn register(
        &self,
        device: &Device,
        max: usize,
    ) -> Result<(Registered, Vec<Device>), StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let mut taken = take(&mut rows, |r| {
            owns(&device.owner, &r.owner) && !live(r, device.registered_at)
        });
        let had = rows
            .iter()
            .position(|r| r.devid == device.devid && owns(&device.owner, &r.owner));
        let mut delivery_point = None;
        match had {
            Some(i) => {
                let old = rows.remove(i);
                if old.same_subscription(device) {
                    delivery_point = old.delivery_point;
                } else {
                    taken.push(old);
                }
            }
            None => {
                if rows
                    .iter()
                    .filter(|r| owns(&device.owner, &r.owner))
                    .count()
                    >= max
                {
                    return Ok((Registered::Full, taken));
                }
            }
        }
        rows.push(Device {
            last_push_at: None,
            delivery_point,
            ..device.clone()
        });
        let registered = if had.is_some() {
            Registered::Replaced
        } else {
            Registered::Added
        };
        Ok((registered, taken))
    }

    fn unregister(&self, owner: &Mailbox, devid: &DeviceId) -> Result<Option<Device>, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(take(&mut rows, |r| r.devid == *devid && owns(owner, &r.owner)).pop())
    }

    fn retire(
        &self,
        owner: &Mailbox,
        devid: &DeviceId,
        endpoint: &str,
    ) -> Result<bool, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| !(r.devid == *devid && owns(owner, &r.owner) && r.endpoint == endpoint));
        Ok(rows.len() != before)
    }

    fn devices_clear(&self) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let n = rows.len();
        rows.clear();
        Ok(n)
    }

    fn any_devices(&self) -> Result<bool, StoreError> {
        Ok(!self.rows.lock().unwrap().is_empty())
    }

    fn unregister_all(&self, owner: &Mailbox) -> Result<Vec<Device>, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(take(&mut rows, |r| owns(owner, &r.owner)))
    }

    fn devices(&self, owner: &Mailbox, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .rev()
            .filter(|r| owns(owner, &r.owner) && live(r, now))
            .cloned()
            .collect())
    }

    fn touch(&self, owner: &Mailbox, devid: &DeviceId, at: SystemTime) -> Result<(), StoreError> {
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows
            .iter_mut()
            .find(|r| r.devid == *devid && owns(owner, &r.owner))
        {
            r.last_push_at = Some(at);
        }
        Ok(())
    }

    fn sweep_expired(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(take(&mut rows, |r| !live(r, now)))
    }

    fn devices_claim(
        &self,
        login: &str,
        fingerprint: &[u8; 32],
    ) -> Result<Vec<Device>, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let identified = Mailbox::identified(login, *fingerprint);
        let held: Vec<DeviceId> = rows
            .iter()
            .filter(|r| owns(&identified, &r.owner))
            .map(|r| r.devid.clone())
            .collect();
        let mut moved = Vec::new();
        rows.retain_mut(|r| {
            if r.owner.fingerprint.is_some() || r.owner.login != login {
                return true;
            }
            moved.push(r.clone());
            // The identity's own row for that device is the one the
            // device last registered; the login's is the older fact.
            if held.contains(&r.devid) {
                return false;
            }
            r.owner.fingerprint = Some(*fingerprint);
            r.delivery_point = None;
            true
        });
        Ok(moved)
    }

    fn devices_rotate(&self, from: &[u8; 32], _to: &[u8; 32]) -> Result<Vec<Device>, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(take(&mut rows, |r| {
            r.owner.fingerprint.as_ref() == Some(from)
        }))
    }

    fn devices_purge(&self, of: &Mailbox) -> Result<Vec<Device>, StoreError> {
        self.unregister_all(of)
    }

    fn set_delivery_point(
        &self,
        device: &Device,
        delivery_point: &str,
    ) -> Result<bool, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.iter_mut().find(|r| {
            r.devid == device.devid && owns(&device.owner, &r.owner) && r.same_subscription(device)
        });
        Ok(row
            .map(|r| r.delivery_point = Some(delivery_point.to_string()))
            .is_some())
    }

    fn clear_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let mut n = 0;
        for r in rows.iter_mut().filter(|r| {
            owns(owner, &r.owner) && r.delivery_point.as_deref() == Some(delivery_point)
        }) {
            r.delivery_point = None;
            n += 1;
        }
        Ok(n)
    }

    fn clear_delivery_points(&self) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(rows
            .iter_mut()
            .filter_map(|r| r.delivery_point.take())
            .count())
    }

    fn unsubscribed(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .filter(|r| r.delivery_point.is_none() && live(r, now))
            .cloned()
            .collect())
    }

    fn retire_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<Vec<Device>, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(take(&mut rows, |r| {
            owns(owner, &r.owner) && r.delivery_point.as_deref() == Some(delivery_point)
        }))
    }

    fn sidecar(&self) -> Result<Option<SidecarRecord>, StoreError> {
        Ok(self.sidecar.lock().unwrap().clone())
    }

    fn set_sidecar(&self, record: &SidecarRecord) -> Result<(), StoreError> {
        *self.sidecar.lock().unwrap() = Some(record.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::conformance;
    use super::*;
    use std::sync::Arc;

    #[test]
    fn memory_devices_pass_the_conformance_suite() {
        conformance::run(&|| Box::new(MemoryDevices::new()));
    }

    #[test]
    fn a_device_id_is_printable_and_bounded() {
        assert!(DeviceId::parse("install-01").is_some());
        assert!(DeviceId::parse("short").is_none(), "under eight bytes");
        assert!(
            DeviceId::parse(&"x".repeat(65)).is_none(),
            "over sixty-four"
        );
        assert!(DeviceId::parse("has a space").is_none());
        assert!(DeviceId::parse("nul\0in it!").is_none());
        assert_eq!(
            DeviceId::of_device(&[0xab; 32]).as_str(),
            "ab".repeat(32),
            "a fingerprint is its own id, and always a valid one"
        );
    }

    /// The store is behind an `Arc<dyn>` in `Core`; nothing here needs a
    /// concrete type.
    #[test]
    fn it_is_object_safe() {
        let _: Arc<dyn PushStore> = Arc::new(MemoryDevices::new());
    }
}
