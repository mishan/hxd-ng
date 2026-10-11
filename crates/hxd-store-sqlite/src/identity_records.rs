//! Registrars' record lists on SQLite (`docs/identity-records.md` §2):
//! one row per identity and registrar, the last list fetched.

use hxd_core::identity_records::{CachedList, RecordCache};
use hxd_core::inbox::StoreError;
use rusqlite::params;

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

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<([u8; 32], CachedList)> {
    let identity: Vec<u8> = r.get(0)?;
    let fetched: i64 = r.get(3)?;
    let keys: Vec<u8> = r.get(4)?;
    Ok((
        identity.try_into().unwrap_or([0; 32]),
        CachedList {
            registrar: r.get(1)?,
            pages: decode(&r.get::<_, Vec<u8>>(2)?),
            fetched: u64::try_from(fetched).unwrap_or(0),
            keys: keys.chunks_exact(40).map(key).collect(),
        },
    ))
}

impl RecordCache for SqliteStore {
    fn put(&self, identity: &[u8; 32], list: &CachedList) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT INTO identity_records (identity, registrar, list, fetched, keys)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (identity, registrar) DO UPDATE
               SET list = excluded.list, fetched = excluded.fetched, keys = excluded.keys",
            params![
                identity.to_vec(),
                list.registrar,
                encode(&list.pages),
                i64::try_from(list.fetched).unwrap_or(i64::MAX),
                list.keys
                    .iter()
                    .flat_map(
                        |(k, until)| [&k[..], &until.unwrap_or(u64::MAX).to_be_bytes()].concat()
                    )
                    .collect::<Vec<u8>>(),
            ],
        ))?;
        Ok(())
    }

    fn lists(&self, identity: &[u8; 32]) -> Result<Vec<CachedList>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT identity, registrar, list, fetched, keys FROM identity_records WHERE identity = ?1",
        ))?;
        let rows = sql(stmt.query_map(params![identity.to_vec()], row))?;
        rows.map(|r| sql(r).map(|(_, list)| list)).collect()
    }

    fn all(&self) -> Result<Vec<([u8; 32], CachedList)>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT identity, registrar, list, fetched, keys FROM identity_records",
        ))?;
        let rows = sql(stmt.query_map([], row))?;
        rows.map(sql).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
