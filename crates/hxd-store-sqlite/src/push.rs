//! The device registry on SQLite (`docs/webpush-gateway.md` §2).
//!
//! One table, the mailbox rule in two partial unique indexes, and
//! nothing clever: the interesting decisions are all in the trait's
//! documentation, and this is them in SQL. What is worth saying here is
//! that `register` deletes and inserts inside one immediate transaction
//! rather than `INSERT … ON CONFLICT`, because the conflict target
//! differs by the kind of mailbox — one index for an identified owner
//! and another for a login — and an upsert would have to name one of
//! them.

use std::time::SystemTime;

use hxd_core::inbox::{Mailbox, StoreError};
use hxd_core::push::{Device, DeviceId, PushStore, Registered, SidecarRecord};
use rusqlite::{params, Connection, OptionalExtension, Params, TransactionBehavior};

use super::{bind, fp_hex, from_unix, mailbox_sql, unix, SqliteStore};

const COLUMNS: &str = "owner, owner_fp, devid, endpoint, p256dh, auth, expires, \
                       registered_at, last_push_at, delivery_point";

/// `sql` in the parent module's sense: a rusqlite error is an operator's
/// problem, said once.
fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

/// A row of [`COLUMNS`] as a [`Device`], or a store error if the
/// database holds something the type cannot: a key of the wrong length,
/// or a fingerprint that is not hex.
fn device_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Device, StoreError>> {
    let login: String = r.get(0)?;
    let fp: Option<String> = r.get(1)?;
    let devid: String = r.get(2)?;
    let endpoint: String = r.get(3)?;
    let p256dh: Vec<u8> = r.get(4)?;
    let auth: Vec<u8> = r.get(5)?;
    let expires: Option<i64> = r.get(6)?;
    let registered_at: i64 = r.get(7)?;
    let last_push_at: Option<i64> = r.get(8)?;
    let delivery_point: Option<String> = r.get(9)?;
    Ok((|| {
        let owner = match fp {
            Some(hex) => Mailbox::identified(login.clone(), super::fp_from_hex(&hex)?),
            None => Mailbox::login(login.clone()),
        };
        Ok(Device {
            owner,
            devid: DeviceId::parse(&devid)
                .ok_or_else(|| StoreError("a stored devid is not one".into()))?,
            endpoint,
            p256dh: p256dh
                .try_into()
                .map_err(|_| StoreError("a stored p256dh is not 65 bytes".into()))?,
            auth: auth
                .try_into()
                .map_err(|_| StoreError("a stored auth secret is not 16 bytes".into()))?,
            expires: expires.map(from_unix),
            registered_at: from_unix(registered_at),
            last_push_at: last_push_at.map(from_unix),
            delivery_point,
        })
    })())
}

/// The rows a statement answers with, as devices: a `SELECT` of
/// [`COLUMNS`], or a `DELETE ... RETURNING` them.
fn collect(conn: &Connection, sql_text: &str, p: impl Params) -> Result<Vec<Device>, StoreError> {
    let mut stmt = sql(conn.prepare(sql_text))?;
    let rows = sql(stmt.query_map(p, device_of))?.collect::<rusqlite::Result<Vec<_>>>();
    sql(rows)?.into_iter().collect()
}

/// Every device of `owner`, newest registration first, optionally only
/// the ones live at `now`.
fn rows_of(
    conn: &Connection,
    owner: &Mailbox,
    now: Option<SystemTime>,
) -> Result<Vec<Device>, StoreError> {
    let live = match now {
        Some(_) => " AND (expires IS NULL OR expires > ?2)",
        None => "",
    };
    let mut stmt = sql(conn.prepare(&format!(
        "SELECT {COLUMNS} FROM push_device WHERE {}{live} ORDER BY id DESC",
        mailbox_sql(owner, "owner", 1)
    )))?;
    let rows = match now {
        Some(t) => sql(stmt.query_map(params![bind(owner), unix(t)], device_of))?
            .collect::<rusqlite::Result<Vec<_>>>(),
        None => sql(stmt.query_map(params![bind(owner)], device_of))?
            .collect::<rusqlite::Result<Vec<_>>>(),
    };
    sql(rows)?.into_iter().collect()
}

impl PushStore for SqliteStore {
    fn register(
        &self,
        device: &Device,
        max: usize,
    ) -> Result<(Registered, Vec<Device>), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let owner = mailbox_sql(&device.owner, "owner", 1);
        // The mailbox's own lapsed rows first, so they do not count
        // against the cap they will never be pushed under again.
        let mut taken = collect(
            &tx,
            &format!(
                "DELETE FROM push_device WHERE {owner} \
                   AND expires IS NOT NULL AND expires <= ?2 RETURNING {COLUMNS}"
            ),
            params![bind(&device.owner), unix(device.registered_at)],
        )?;
        let old = collect(
            &tx,
            &format!("DELETE FROM push_device WHERE {owner} AND devid = ?2 RETURNING {COLUMNS}"),
            params![bind(&device.owner), device.devid.as_str()],
        )?
        .pop();
        let replaced = old.is_some();
        let delivery_point = match old {
            Some(old) if old.same_subscription(device) => old.delivery_point,
            Some(old) => {
                taken.push(old);
                None
            }
            None => None,
        };
        if !replaced {
            let held: i64 = sql(tx.query_row(
                &format!("SELECT COUNT(*) FROM push_device WHERE {owner}"),
                params![bind(&device.owner)],
                |r| r.get(0),
            ))?;
            if held as u64 >= max as u64 {
                sql(tx.commit())?;
                return Ok((Registered::Full, taken));
            }
        }
        sql(tx.execute(
            &format!(
                "INSERT INTO push_device ({COLUMNS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9)"
            ),
            params![
                device.owner.login,
                device.owner.fingerprint.as_ref().map(fp_hex),
                device.devid.as_str(),
                device.endpoint,
                device.p256dh.as_slice(),
                device.auth.as_slice(),
                device.expires.map(unix),
                unix(device.registered_at),
                delivery_point,
            ],
        ))?;
        sql(tx.commit())?;
        let registered = if replaced {
            Registered::Replaced
        } else {
            Registered::Added
        };
        Ok((registered, taken))
    }

    fn retire(
        &self,
        owner: &Mailbox,
        devid: &DeviceId,
        endpoint: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let gone = sql(conn.execute(
            &format!(
                "DELETE FROM push_device WHERE {} AND devid = ?2 AND endpoint = ?3",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), devid.as_str(), endpoint],
        ))?;
        Ok(gone > 0)
    }

    fn devices_clear(&self) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute("DELETE FROM push_device", []))
    }

    fn any_devices(&self) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(
            conn.query_row("SELECT EXISTS (SELECT 1 FROM push_device)", [], |r| {
                r.get(0)
            }),
        )
    }

    fn unregister(&self, owner: &Mailbox, devid: &DeviceId) -> Result<Option<Device>, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(collect(
            &conn,
            &format!(
                "DELETE FROM push_device WHERE {} AND devid = ?2 RETURNING {COLUMNS}",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), devid.as_str()],
        )?
        .pop())
    }

    fn unregister_all(&self, owner: &Mailbox) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().unwrap();
        collect(
            &conn,
            &format!(
                "DELETE FROM push_device WHERE {} RETURNING {COLUMNS}",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner)],
        )
    }

    fn devices(&self, owner: &Mailbox, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().unwrap();
        rows_of(&conn, owner, Some(now))
    }

    fn touch(&self, owner: &Mailbox, devid: &DeviceId, at: SystemTime) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            &format!(
                "UPDATE push_device SET last_push_at = ?2 WHERE {} AND devid = ?3",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), unix(at), devid.as_str()],
        ))?;
        Ok(())
    }

    fn sweep_expired(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().unwrap();
        collect(
            &conn,
            &format!(
                "DELETE FROM push_device WHERE expires IS NOT NULL AND expires <= ?1 \
                 RETURNING {COLUMNS}"
            ),
            params![unix(now)],
        )
    }

    fn devices_claim(
        &self,
        login: &str,
        fingerprint: &[u8; 32],
    ) -> Result<Vec<Device>, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let fp = fp_hex(fingerprint);
        let held = collect(
            &tx,
            &format!(
                "SELECT {COLUMNS} FROM push_device WHERE owner_fp IS NULL AND owner = ?1 \
                 ORDER BY id"
            ),
            params![login],
        )?;
        // A device the identity already holds keeps the identity's row:
        // that is the one the device itself last registered, and the
        // login's is the older fact.
        sql(tx.execute(
            "DELETE FROM push_device \
              WHERE owner_fp IS NULL AND owner = ?1 \
                AND devid IN (SELECT devid FROM push_device WHERE owner_fp = ?2)",
            params![login, fp],
        ))?;
        sql(tx.execute(
            "UPDATE push_device SET owner_fp = ?2, delivery_point = NULL \
              WHERE owner_fp IS NULL AND owner = ?1",
            params![login, fp],
        ))?;
        sql(tx.commit())?;
        Ok(held)
    }

    fn devices_rotate(&self, from: &[u8; 32], _to: &[u8; 32]) -> Result<Vec<Device>, StoreError> {
        // Drops, and does not move: see the trait's documentation and
        // push-notifications.md §5.1.
        let conn = self.conn.lock().unwrap();
        collect(
            &conn,
            &format!("DELETE FROM push_device WHERE owner_fp = ?1 RETURNING {COLUMNS}"),
            params![fp_hex(from)],
        )
    }

    fn devices_purge(&self, of: &Mailbox) -> Result<Vec<Device>, StoreError> {
        self.unregister_all(of)
    }

    fn set_delivery_point(
        &self,
        device: &Device,
        delivery_point: &str,
    ) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let set = sql(conn.execute(
            &format!(
                "UPDATE push_device SET delivery_point = ?2 \
                  WHERE {} AND devid = ?3 AND endpoint = ?4 AND p256dh = ?5 AND auth = ?6",
                mailbox_sql(&device.owner, "owner", 1)
            ),
            params![
                bind(&device.owner),
                delivery_point,
                device.devid.as_str(),
                device.endpoint,
                device.p256dh.as_slice(),
                device.auth.as_slice(),
            ],
        ))?;
        Ok(set > 0)
    }

    fn clear_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            &format!(
                "UPDATE push_device SET delivery_point = NULL WHERE {} AND delivery_point = ?2",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), delivery_point],
        ))
    }

    fn clear_delivery_points(&self) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "UPDATE push_device SET delivery_point = NULL WHERE delivery_point IS NOT NULL",
            [],
        ))
    }

    fn unsubscribed(&self, now: SystemTime) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().unwrap();
        collect(
            &conn,
            &format!(
                "SELECT {COLUMNS} FROM push_device \
                  WHERE delivery_point IS NULL AND (expires IS NULL OR expires > ?1) \
                  ORDER BY id"
            ),
            params![unix(now)],
        )
    }

    fn retire_delivery_point(
        &self,
        owner: &Mailbox,
        delivery_point: &str,
    ) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().unwrap();
        collect(
            &conn,
            &format!(
                "DELETE FROM push_device WHERE {} AND delivery_point = ?2 RETURNING {COLUMNS}",
                mailbox_sql(owner, "owner", 1)
            ),
            params![bind(owner), delivery_point],
        )
    }

    fn sidecar(&self) -> Result<Option<SidecarRecord>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                "SELECT service, public_key, contact, cursor FROM push_sidecar",
                [],
                |r| {
                    Ok(SidecarRecord {
                        service: r.get(0)?,
                        public_key: r.get(1)?,
                        contact: r.get(2)?,
                        cursor: r.get(3)?,
                    })
                },
            )
            .optional())
    }

    fn set_sidecar(&self, record: &SidecarRecord) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT OR REPLACE INTO push_sidecar (id, service, public_key, contact, cursor) \
             VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                record.service,
                record.public_key,
                record.contact,
                record.cursor
            ],
        ))?;
        Ok(())
    }
}
