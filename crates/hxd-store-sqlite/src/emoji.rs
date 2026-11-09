//! The emoji catalog on SQLite (`SCHEMA_V37`). Every write is one
//! `BEGIN IMMEDIATE` transaction, so its checks, its revision and its
//! rows agree whichever connection writes the file.

use std::sync::Arc;
use std::time::SystemTime;

use hxd_core::emoji::{
    Catalog, EmojiEntry, EmojiId, EmojiImage, EmojiName, EmojiStore, EmojiStoreError,
};
use hxd_core::inbox::StoreError;
use hxd_core::media::MediaType;
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use super::{unix, SqliteStore};

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

/// The next revision, spent.
fn bump(tx: &Transaction<'_>) -> Result<u32, StoreError> {
    sql(tx.query_row(
        "UPDATE emoji_meta SET revision = revision + 1 RETURNING revision",
        [],
        |r| r.get(0),
    ))
}

fn revision(tx: &Transaction<'_>) -> Result<u32, StoreError> {
    sql(tx.query_row("SELECT revision FROM emoji_meta", [], |r| r.get(0)))
}

fn name_live(tx: &Transaction<'_>, name: &EmojiName) -> Result<bool, StoreError> {
    sql(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM emoji WHERE name = ?1 AND removed_at IS NULL)",
        params![name.as_str()],
        |r| r.get(0),
    ))
}

/// A live row's name, or `None` for a removed or unknown id.
fn live_name(tx: &Transaction<'_>, id: EmojiId) -> Result<Option<String>, StoreError> {
    sql(tx
        .query_row(
            "SELECT name FROM emoji WHERE id = ?1 AND removed_at IS NULL",
            params![id.0],
            |r| r.get(0),
        )
        .optional())
}

type Row = (
    u32,
    String,
    u32,
    Option<Vec<u8>>,
    Option<String>,
    Option<u16>,
    Option<u16>,
    bool,
    Option<Vec<u8>>,
);

fn entry_of(
    (id, name, revision, hash, mime, width, height, animated, bytes): Row,
) -> Result<EmojiEntry, StoreError> {
    let bad = |what: &str| StoreError(format!("emoji {id} with {what}"));
    let name = EmojiName::parse(&name).ok_or_else(|| bad("an invalid name"))?;
    let image = match (hash, mime, width, height, bytes) {
        (None, None, None, None, None) => None,
        (Some(hash), Some(mime), Some(width), Some(height), Some(bytes)) => {
            Some(Arc::new(EmojiImage {
                hash: hash.try_into().map_err(|_| bad("a malformed hash"))?,
                mime: MediaType::from_mime(&mime).ok_or_else(|| bad("an unknown type"))?,
                width,
                height,
                animated,
                bytes: bytes.into(),
            }))
        }
        _ => return Err(bad("part of an image")),
    };
    Ok(EmojiEntry {
        id: EmojiId(id),
        name,
        revision,
        image,
    })
}

impl EmojiStore for SqliteStore {
    fn load(&self) -> Result<Catalog, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        // One read transaction, so the revision is the rows'.
        let tx = sql(conn.transaction())?;
        let (revision, floor) = sql(tx.query_row(
            "SELECT revision, floor FROM emoji_meta",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        let rows: Vec<Row> = {
            let mut stmt = sql(tx.prepare(
                "SELECT id, name, revision, hash, mime, width, height, animated, bytes
                   FROM emoji ORDER BY id",
            ))?;
            let rows = sql(stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            }))?;
            sql(rows.collect())?
        };
        Ok(Catalog {
            revision,
            floor,
            entries: rows.into_iter().map(entry_of).collect::<Result<_, _>>()?,
        })
    }

    fn add(
        &self,
        name: &EmojiName,
        image: &EmojiImage,
        at: SystemTime,
        max_count: usize,
    ) -> Result<u32, EmojiStoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if name_live(&tx, name)? {
            return Err(EmojiStoreError::NameTaken);
        }
        let live: i64 = sql(tx.query_row(
            "SELECT COUNT(*) FROM emoji WHERE removed_at IS NULL",
            [],
            |r| r.get(0),
        ))?;
        if live as usize >= max_count {
            return Err(EmojiStoreError::CatalogFull);
        }
        let revision = bump(&tx)?;
        sql(tx.execute(
            "INSERT INTO emoji
               (name, revision, hash, mime, width, height, animated, bytes, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                name.as_str(),
                revision,
                &image.hash[..],
                image.mime.mime(),
                image.width,
                image.height,
                image.animated,
                &image.bytes[..],
                unix(at),
            ],
        ))?;
        sql(tx.commit())?;
        Ok(revision)
    }

    fn rename(&self, id: EmojiId, name: &EmojiName) -> Result<u32, EmojiStoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        match live_name(&tx, id)? {
            None => return Err(EmojiStoreError::NoSuchEmoji),
            Some(current) if current == name.as_str() => return Ok(revision(&tx)?),
            Some(_) => {}
        }
        if name_live(&tx, name)? {
            return Err(EmojiStoreError::NameTaken);
        }
        let revision = bump(&tx)?;
        sql(tx.execute(
            "UPDATE emoji SET name = ?2, revision = ?3 WHERE id = ?1",
            params![id.0, name.as_str(), revision],
        ))?;
        sql(tx.commit())?;
        Ok(revision)
    }

    fn remove(
        &self,
        id: EmojiId,
        at: SystemTime,
        keep_removed: usize,
    ) -> Result<u32, EmojiStoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        if live_name(&tx, id)?.is_none() {
            return Err(EmojiStoreError::NoSuchEmoji);
        }
        let revision = bump(&tx)?;
        sql(tx.execute(
            "UPDATE emoji SET revision = ?2, hash = NULL, mime = NULL, width = NULL,
                    height = NULL, animated = 0, bytes = NULL, removed_at = ?3
              WHERE id = ?1",
            params![id.0, revision, unix(at)],
        ))?;
        let removed: i64 = sql(tx.query_row(
            "SELECT COUNT(*) FROM emoji WHERE removed_at IS NOT NULL",
            [],
            |r| r.get(0),
        ))?;
        let past = removed - keep_removed as i64;
        if past > 0 {
            sql(tx.execute(
                "UPDATE emoji_meta SET floor = MAX(floor, (
                   SELECT MAX(revision) FROM (
                     SELECT revision FROM emoji WHERE removed_at IS NOT NULL
                      ORDER BY revision LIMIT ?1)))",
                params![past],
            ))?;
            sql(tx.execute(
                "DELETE FROM emoji WHERE id IN (
                   SELECT id FROM emoji WHERE removed_at IS NOT NULL
                    ORDER BY revision LIMIT ?1)",
                params![past],
            ))?;
        }
        sql(tx.commit())?;
        Ok(revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_conformance_suite() {
        hxd_core::emoji::conformance::run(&|| Box::new(SqliteStore::in_memory().unwrap()));
    }
}
