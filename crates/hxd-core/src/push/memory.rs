//! An in-memory [`PushStore`]: the domain's tests, and a server that
//! wants push within one run of the process.
//!
//! Public rather than `#[cfg(test)]` for the reason
//! [`crate::inbox::MemoryStore`] is. Where the SQLite store says a rule
//! in SQL this says it in Rust, and [`super::conformance`] holds the two
//! to the same answers.

use std::sync::Mutex;
use std::time::SystemTime;

use super::{Device, DeviceId, PushStore, Registered};
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
}

impl MemoryDevices {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PushStore for MemoryDevices {
    fn register(&self, device: &Device, max: usize) -> Result<Registered, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|r| !owns(&device.owner, &r.owner) || live(r, device.registered_at));
        let had = rows
            .iter()
            .position(|r| r.devid == device.devid && owns(&device.owner, &r.owner));
        match had {
            Some(i) => {
                rows.remove(i);
            }
            None => {
                if rows
                    .iter()
                    .filter(|r| owns(&device.owner, &r.owner))
                    .count()
                    >= max
                {
                    return Ok(Registered::Full);
                }
            }
        }
        rows.push(Device {
            last_push_at: None,
            ..device.clone()
        });
        Ok(if had.is_some() {
            Registered::Replaced
        } else {
            Registered::Added
        })
    }

    fn unregister(&self, owner: &Mailbox, devid: &DeviceId) -> Result<bool, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| !(r.devid == *devid && owns(owner, &r.owner)));
        Ok(rows.len() != before)
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

    fn unregister_all(&self, owner: &Mailbox) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| !owns(owner, &r.owner));
        Ok(before - rows.len())
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

    fn sweep_expired(&self, now: SystemTime) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| live(r, now));
        Ok(before - rows.len())
    }

    fn devices_claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let identified = Mailbox::identified(login, *fingerprint);
        let held: Vec<DeviceId> = rows
            .iter()
            .filter(|r| owns(&identified, &r.owner))
            .map(|r| r.devid.clone())
            .collect();
        let mut moved = 0;
        rows.retain_mut(|r| {
            if r.owner.fingerprint.is_some() || r.owner.login != login {
                return true;
            }
            moved += 1;
            // The identity's own row for that device is the one the
            // device last registered; the login's is the older fact.
            if held.contains(&r.devid) {
                return false;
            }
            r.owner.fingerprint = Some(*fingerprint);
            true
        });
        Ok(moved)
    }

    fn devices_rotate(&self, from: &[u8; 32], _to: &[u8; 32]) -> Result<usize, StoreError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| r.owner.fingerprint.as_ref() != Some(from));
        Ok(before - rows.len())
    }

    fn devices_purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        self.unregister_all(of)
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
