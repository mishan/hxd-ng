//! Registrars' record lists on SQLite (`docs/identity-records.md` §2):
//! one row per identity and registrar, the last list fetched; and one
//! per identity and device epoch, the earliest record of it seen.

use hxd_core::identity_records::{CachedList, KeptEpoch, RecordCache, FIRST_SEEN_KEPT};
use hxd_core::inbox::StoreError;
use rusqlite::{params, OptionalExtension};

use super::SqliteStore;

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

/// Pages one after another, each behind its length.
fn encode(pages: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for page in pages {
        out.extend_from_slice(&u32::try_from(page.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(page);
    }
    out
}

/// What [`encode`] wrote; a row cut short loses the pages past the cut,
/// which the list then fails to verify without.
fn decode(mut bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut pages = Vec::new();
    while let Some((len, rest)) = bytes.split_first_chunk::<4>() {
        let len = u32::from_be_bytes(*len) as usize;
        let Some(page) = rest.get(..len) else { break };
        pages.push(page.to_vec());
        bytes = &rest[len..];
    }
    pages
}

/// A key and its `until`, `u64::MAX` for none.
fn key(b: &[u8]) -> ([u8; 32], Option<u64>) {
    let (k, until) = b.split_at(32);
    let until = u64::from_be_bytes(until.try_into().expect("8 bytes"));
    (
        k.try_into().expect("32 bytes"),
        (until != u64::MAX).then_some(until),
    )
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CachedList> {
    let fetched: i64 = r.get(2)?;
    let keys: Vec<u8> = r.get(3)?;
    Ok(CachedList {
        registrar: r.get(0)?,
        pages: decode(&r.get::<_, Vec<u8>>(1)?),
        fetched: u64::try_from(fetched).unwrap_or(0),
        keys: keys.chunks_exact(40).map(key).collect(),
    })
}

/// Write `list` for `identity` with `insert`, whose parameters are
/// identity, registrar, list, fetched and keys.
fn write(
    store: &SqliteStore,
    insert: &str,
    identity: &[u8; 32],
    list: &CachedList,
) -> Result<(), StoreError> {
    let conn = store.conn.lock().unwrap();
    sql(conn.execute(
        insert,
        params![
            identity.to_vec(),
            list.registrar,
            encode(&list.pages),
            i64::try_from(list.fetched).unwrap_or(i64::MAX),
            list.keys
                .iter()
                .flat_map(|(k, until)| [&k[..], &until.unwrap_or(u64::MAX).to_be_bytes()].concat())
                .collect::<Vec<u8>>(),
        ],
    ))?;
    Ok(())
}

/// Every list `table` holds for `identity`.
fn read(
    store: &SqliteStore,
    table: &str,
    identity: &[u8; 32],
) -> Result<Vec<CachedList>, StoreError> {
    let conn = store.conn.lock().unwrap();
    let mut stmt = sql(conn.prepare_cached(&format!(
        "SELECT registrar, list, fetched, keys FROM {table} WHERE identity = ?1"
    )))?;
    let rows = sql(stmt.query_map(params![identity.to_vec()], row))?;
    rows.map(sql).collect()
}

impl RecordCache for SqliteStore {
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        write(
            self,
            "INSERT INTO identity_records (identity, registrar, list, fetched, keys)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (identity, registrar) DO UPDATE
               SET list = excluded.list, fetched = excluded.fetched, keys = excluded.keys",
            identity,
            list,
        )
    }

    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        read(self, "identity_records", identity)
    }

    fn hold_superseded(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        write(
            self,
            "INSERT OR REPLACE INTO identity_records_superseded
               (identity, registrar, list, fetched, keys)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            identity,
            list,
        )
    }

    fn superseded(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        read(self, "identity_records_superseded", identity)
    }

    fn release_superseded(&self, identity: &[u8; 32]) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "DELETE FROM identity_records_superseded WHERE identity = ?1",
            params![identity.to_vec()],
        ))?;
        Ok(())
    }

    fn first_seen(&self, identity: &[u8; 32], now: u64) -> Result<u64, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction())?;
        let stale = i64::try_from(now.saturating_sub(FIRST_SEEN_KEPT)).unwrap_or(i64::MAX);
        let kept: Option<i64> = sql(tx
            .query_row(
                "SELECT first_seen FROM identity_first_seen WHERE identity = ?1 AND first_seen > ?2",
                params![identity.to_vec(), stale],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(at) = kept {
            return Ok(u64::try_from(at).unwrap_or(0));
        }
        // A first sighting is when the table is kept to a day: rare, and
        // the index makes it a range delete.
        sql(tx.execute(
            "DELETE FROM identity_first_seen WHERE first_seen <= ?1",
            params![stale],
        ))?;
        sql(tx.execute(
            "INSERT INTO identity_first_seen (identity, first_seen) VALUES (?1, ?2)",
            params![identity.to_vec(), i64::try_from(now).unwrap_or(i64::MAX)],
        ))?;
        sql(tx.commit())?;
        Ok(now)
    }

    fn keep_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT INTO identity_device_floor (identity, epoch, time, record)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (identity, epoch) DO UPDATE
               SET time = excluded.time, record = excluded.record
               WHERE excluded.time < identity_device_floor.time",
            params![
                identity.to_vec(),
                i64::try_from(kept.epoch).unwrap_or(i64::MAX),
                i64::try_from(kept.time).unwrap_or(i64::MAX),
                kept.record,
            ],
        ))?;
        Ok(())
    }

    fn replace_epoch(&self, identity: &[u8; 32], kept: &KeptEpoch) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT OR REPLACE INTO identity_device_floor (identity, epoch, time, record)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                identity.to_vec(),
                i64::try_from(kept.epoch).unwrap_or(i64::MAX),
                i64::try_from(kept.time).unwrap_or(i64::MAX),
                kept.record,
            ],
        ))?;
        Ok(())
    }

    fn epochs(&self, identity: &[u8; 32]) -> Result<Vec<KeptEpoch>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT epoch, time, record FROM identity_device_floor WHERE identity = ?1",
        ))?;
        let rows = sql(stmt.query_map(params![identity.to_vec()], |r| {
            let (epoch, time): (i64, i64) = (r.get(0)?, r.get(1)?);
            Ok(KeptEpoch {
                epoch: u64::try_from(epoch).unwrap_or(0),
                time: u64::try_from(time).unwrap_or(0),
                record: r.get(2)?,
            })
        }))?;
        rows.map(sql).collect()
    }

    fn identities_with_epochs(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            sql(conn.prepare_cached("SELECT DISTINCT identity FROM identity_device_floor"))?;
        let rows = sql(stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)))?;
        rows.map(|r| {
            let id = sql(r)?;
            id.try_into()
                .map_err(|_| StoreError("a kept identity is not 32 bytes".into()))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_conformance_suite() {
        hxd_core::identity_records::conformance::run(&|| {
            Box::new(SqliteStore::in_memory().unwrap())
        });
    }

    #[test]
    fn a_list_comes_back_with_its_keys_deadlines() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            SqliteStore::open(dir.path().join("server.db"), crate::Synchronous::Normal).unwrap();
        let list = CachedList {
            registrar: "hl.example".into(),
            pages: vec![vec![1, 2, 3], vec![4]],
            keys: vec![([1; 32], None), ([2; 32], Some(1_700_000_000))],
            fetched: 1_600_000_000,
        };
        store.put(&[9; 32], &list).unwrap();
        assert_eq!(store.lists(&[9; 32]).unwrap(), vec![list]);
    }

    #[test]
    fn a_first_sighting_is_kept_a_day() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            SqliteStore::open(dir.path().join("server.db"), crate::Synchronous::Normal).unwrap();
        let t = 1_700_000_000;
        assert_eq!(store.first_seen(&[1; 32], t).unwrap(), t);
        assert_eq!(store.first_seen(&[1; 32], t + 60).unwrap(), t);
        assert_eq!(store.first_seen(&[2; 32], t + 60).unwrap(), t + 60);
        let later = t + FIRST_SEEN_KEPT;
        assert_eq!(store.first_seen(&[1; 32], later).unwrap(), later);
    }
}
