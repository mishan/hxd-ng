//! Avatars on SQLite (`docs/avatars.md` §2): one row per owner, both
//! renditions in it.

use std::time::SystemTime;

use hxd_core::avatar::{Avatar, AvatarId, AvatarOwner, AvatarRef, AvatarStore};
use hxd_core::inbox::StoreError;
use hxd_core::media::MediaType;
use rusqlite::{params, OptionalExtension};

use super::{fp_hex, unix, SqliteStore};

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

/// The key column. The two kinds of owner never meet: a login cannot
/// start `i:`, since the prefix is this module's and not the account's.
fn key(owner: &AvatarOwner) -> String {
    match owner {
        AvatarOwner::Account(login) => format!("a:{login}"),
        AvatarOwner::Identity(fp) => format!("i:{}", fp_hex(fp)),
    }
}

const COLUMNS: &str = "id, mime, width, height, bytes, legacy_gif";

fn avatar_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Avatar, StoreError>> {
    let id: Vec<u8> = r.get(0)?;
    let mime: String = r.get(1)?;
    let width: u32 = r.get(2)?;
    let height: u32 = r.get(3)?;
    let bytes: Vec<u8> = r.get(4)?;
    let legacy_gif: Option<Vec<u8>> = r.get(5)?;
    Ok((|| {
        let id: [u8; 32] = id
            .try_into()
            .map_err(|_| StoreError("avatar row with a malformed id".into()))?;
        let mime = MediaType::from_mime(&mime)
            .ok_or_else(|| StoreError(format!("avatar row with type {mime:?}")))?;
        Ok(Avatar {
            meta: AvatarRef {
                id: AvatarId(id),
                mime,
                width,
                height,
            },
            bytes: bytes.into(),
            legacy_gif: legacy_gif.map(Into::into),
        })
    })())
}

impl AvatarStore for SqliteStore {
    fn load(&self, owner: &AvatarOwner) -> Result<Option<Avatar>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM avatar WHERE owner = ?1"),
                params![key(owner)],
                avatar_of,
            )
            .optional())?
        .transpose()
    }

    fn save(&self, owner: &AvatarOwner, avatar: Option<&Avatar>) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        match avatar {
            Some(a) => sql(conn.execute(
                "INSERT INTO avatar (owner, id, mime, width, height, bytes, legacy_gif, set_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT (owner) DO UPDATE SET
                   id = excluded.id, mime = excluded.mime, width = excluded.width,
                   height = excluded.height, bytes = excluded.bytes,
                   legacy_gif = excluded.legacy_gif, set_at = excluded.set_at",
                params![
                    key(owner),
                    &a.meta.id.0[..],
                    a.meta.mime.mime(),
                    a.meta.width,
                    a.meta.height,
                    &a.bytes[..],
                    a.legacy_gif.as_deref(),
                    unix(SystemTime::now()),
                ],
            ))?,
            None => sql(conn.execute("DELETE FROM avatar WHERE owner = ?1", params![key(owner)]))?,
        };
        Ok(())
    }

    fn by_id(&self, id: &AvatarId) -> Result<Option<Avatar>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM avatar WHERE id = ?1 LIMIT 1"),
                params![&id.0[..]],
                avatar_of,
            )
            .optional())?
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_conformance_suite() {
        hxd_core::avatar::conformance::run(&|| Box::new(SqliteStore::in_memory().unwrap()));
    }
}
