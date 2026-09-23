//! The registrar's store on SQLite (`docs/identity-registrar.md` §12).
//!
//! Its own file and its own schema version, apart from the inbox's: a
//! registrar and a message store are different things with different
//! backups, and a registrar can run on a server with no inbox at all.
//! The version lives in a table of its own rather than in `user_version`
//! for the same reason — pointing `[registrar] store` at the inbox's
//! file by mistake must not let either schema read the other's number.
//!
//! Sequence numbers are `AUTOINCREMENT` keys, so a `seq` is never reused
//! even after the row it named is gone, which is the monotonic promise
//! the record list and the log both make (§4.9, §6.6).
//!
//! Times and `until`s are Unix seconds stored as `INTEGER`. SQLite's
//! integers are signed, so a value past `i64::MAX` — only ever an `until`
//! a client chose — is stored as `i64::MAX`, which compares the same
//! against any clock this will run under.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use hxd_registrar::store::entry_cost;
use hxd_registrar::{
    Counts, Effect, HandleRow, IdentityRow, Issue, Issued, Key, Page, Pending, Publish,
    RecordFilter, RecordKind, Recovery, RegistrarStore, StoreError,
};
use rusqlite::{
    params, Connection, OptionalExtension, Row, Savepoint, Transaction, TransactionBehavior,
};
use sha2::{Digest, Sha256};

use crate::Synchronous;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_V1: &str = "
CREATE TABLE registrar_identity (
  key         BLOB    PRIMARY KEY,
  fingerprint BLOB    NOT NULL UNIQUE,
  commitment  BLOB,
  frozen      INTEGER NOT NULL DEFAULT 0,
  revoked     INTEGER NOT NULL DEFAULT 0,
  rotated_to  BLOB,
  created     INTEGER NOT NULL
);
CREATE TABLE registrar_handle (
  name       TEXT    PRIMARY KEY,
  identity   BLOB    NOT NULL,
  registered INTEGER NOT NULL,
  expires    INTEGER NOT NULL,
  lapsed_at  INTEGER,
  barred     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX registrar_handle_identity ON registrar_handle (identity);
-- The issuance log (§6.6): append-only, every attestation including
-- reissues.
CREATE TABLE registrar_log (
  seq      INTEGER PRIMARY KEY AUTOINCREMENT,
  identity BLOB    NOT NULL,
  handle   TEXT    NOT NULL,
  issued   INTEGER NOT NULL,
  expires  INTEGER NOT NULL,
  first    INTEGER NOT NULL,
  bytes    BLOB    NOT NULL
);
CREATE INDEX registrar_log_identity ON registrar_log (identity, handle, issued);
CREATE INDEX registrar_log_first ON registrar_log (issued) WHERE first = 1;
-- `other` is what makes the per-identity list find a rotation under the
-- successor (§12).
CREATE TABLE registrar_record (
  seq      INTEGER PRIMARY KEY AUTOINCREMENT,
  kind     TEXT    NOT NULL,
  identity BLOB    NOT NULL,
  other    BLOB,
  until    INTEGER,
  digest   BLOB    NOT NULL UNIQUE,
  bytes    BLOB    NOT NULL
);
CREATE INDEX registrar_record_identity ON registrar_record (identity);
CREATE INDEX registrar_record_other ON registrar_record (other) WHERE other IS NOT NULL;
CREATE TABLE registrar_pending (
  identity   BLOB    PRIMARY KEY,
  successor  BLOB    NOT NULL,
  publish_at INTEGER NOT NULL,
  digest     BLOB    NOT NULL,
  bytes      BLOB    NOT NULL
);
CREATE TABLE registrar_recovery (
  handle      TEXT    PRIMARY KEY,
  fingerprint BLOB    NOT NULL,
  keep_age    INTEGER NOT NULL,
  granted     INTEGER NOT NULL
);
CREATE TABLE registrar_invite (
  code_hash BLOB    PRIMARY KEY,
  used_by   BLOB,
  used_at   INTEGER
);
";

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

/// Unix seconds as SQLite holds them.
fn int(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn uint(n: i64) -> u64 {
    n.max(0) as u64
}

fn key32(b: Vec<u8>, what: &str) -> Result<[u8; 32], StoreError> {
    b.try_into()
        .map_err(|_| StoreError(format!("a stored {what} is not 32 bytes")))
}

fn fingerprint(key: &Key) -> [u8; 32] {
    Sha256::digest(key).into()
}

const IDENTITY_COLUMNS: &str = "key, commitment, frozen, revoked, rotated_to, created";

fn identity_of(r: &Row<'_>) -> rusqlite::Result<Result<IdentityRow, StoreError>> {
    let key: Vec<u8> = r.get(0)?;
    let commitment: Option<Vec<u8>> = r.get(1)?;
    let frozen: bool = r.get(2)?;
    let revoked: bool = r.get(3)?;
    let rotated_to: Option<Vec<u8>> = r.get(4)?;
    let created: i64 = r.get(5)?;
    Ok((|| {
        Ok(IdentityRow {
            key: key32(key, "identity key")?,
            commitment: commitment.map(|c| key32(c, "commitment")).transpose()?,
            frozen,
            revoked,
            rotated_to: rotated_to.map(|k| key32(k, "successor")).transpose()?,
            created: uint(created),
        })
    })())
}

const HANDLE_COLUMNS: &str = "name, identity, registered, expires, lapsed_at, barred";

fn handle_of(r: &Row<'_>) -> rusqlite::Result<Result<HandleRow, StoreError>> {
    let name: String = r.get(0)?;
    let identity: Vec<u8> = r.get(1)?;
    let registered: i64 = r.get(2)?;
    let expires: i64 = r.get(3)?;
    let lapsed_at: Option<i64> = r.get(4)?;
    let barred: bool = r.get(5)?;
    Ok(key32(identity, "handle holder").map(|identity| HandleRow {
        name,
        identity,
        registered: uint(registered),
        expires: uint(expires),
        lapsed_at: lapsed_at.map(uint),
        barred,
    }))
}

const PENDING_COLUMNS: &str = "identity, successor, publish_at, digest, bytes";

fn pending_of(r: &Row<'_>) -> rusqlite::Result<Result<Pending, StoreError>> {
    let identity: Vec<u8> = r.get(0)?;
    let successor: Vec<u8> = r.get(1)?;
    let publish_at: i64 = r.get(2)?;
    let digest: Vec<u8> = r.get(3)?;
    let bytes: Vec<u8> = r.get(4)?;
    Ok((|| {
        Ok(Pending {
            identity: key32(identity, "pending identity")?,
            successor: key32(successor, "pending successor")?,
            publish_at: uint(publish_at),
            digest: key32(digest, "pending digest")?,
            bytes,
        })
    })())
}

/// Collect `(seq, bytes)` rows into a page cut at `budget`, the way
/// [`hxd_registrar::memory::MemoryStore`] cuts them.
fn page_of(rows: &mut rusqlite::Rows<'_>, budget: usize) -> Result<Page, StoreError> {
    let mut out = Page::default();
    let mut used = 0;
    while let Some(row) = sql(rows.next())? {
        let seq: i64 = sql(row.get(0))?;
        let bytes: Vec<u8> = sql(row.get(1))?;
        let cost = entry_cost(&bytes);
        if !out.entries.is_empty() && used + cost > budget {
            out.more = true;
            break;
        }
        used += cost;
        out.entries.push((uint(seq), bytes));
    }
    Ok(out)
}

#[derive(Debug)]
pub struct SqliteRegistrarStore {
    conn: Mutex<Connection>,
}

impl SqliteRegistrarStore {
    /// Open (creating if absent) the registrar database at `path`.
    pub fn open(path: impl AsRef<Path>, sync: Synchronous) -> Result<Self, StoreError> {
        let conn = sql(Connection::open(path))?;
        // An operator's `hxd registrar freeze` writes while the server
        // runs; either waits for the other rather than failing.
        sql(conn.busy_timeout(Duration::from_secs(5)))?;
        let _: String = sql(conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)))?;
        sql(conn.pragma_update(None, "synchronous", sync.pragma()))?;
        migrate(&conn)?;
        Ok(SqliteRegistrarStore {
            conn: Mutex::new(conn),
        })
    }

    /// An in-memory database, for tests.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:", Synchronous::Normal)
    }
}

fn migrate(conn: &Connection) -> Result<(), StoreError> {
    sql(conn.execute_batch("CREATE TABLE IF NOT EXISTS registrar_meta (version INTEGER NOT NULL)"))?;
    let version: Option<i64> = sql(conn
        .query_row("SELECT version FROM registrar_meta", [], |r| r.get(0))
        .optional())?;
    match version {
        Some(SCHEMA_VERSION) => Ok(()),
        Some(v) if v > SCHEMA_VERSION => Err(StoreError(format!(
            "registrar database is schema version {v}, but this build writes \
             {SCHEMA_VERSION} — it was made by a newer hxd"
        ))),
        Some(v) => Err(StoreError(format!(
            "registrar database is schema version {v}, which this build cannot migrate"
        ))),
        // The schema and the row declaring it go in together, so a crash
        // between them cannot leave tables with no version.
        None => sql(conn.execute_batch(&format!(
            "BEGIN IMMEDIATE;\n{SCHEMA_V1}\n\
             INSERT INTO registrar_meta (version) VALUES ({SCHEMA_VERSION});\nCOMMIT;"
        ))),
    }
}

/// One write's atomicity: its own transaction, or — inside the one
/// [`RegistrarStore::begin`] opened — a savepoint in that, which commits
/// with it. Dropped without `commit`, either rolls back.
enum Write<'c> {
    Tx(Transaction<'c>),
    Savepoint(Savepoint<'c>),
}

impl Write<'_> {
    fn open(conn: &mut Connection) -> rusqlite::Result<Write<'_>> {
        if conn.is_autocommit() {
            conn.transaction_with_behavior(TransactionBehavior::Immediate)
                .map(Write::Tx)
        } else {
            conn.savepoint().map(Write::Savepoint)
        }
    }

    fn commit(self) -> rusqlite::Result<()> {
        match self {
            Write::Tx(tx) => tx.commit(),
            Write::Savepoint(sp) => sp.commit(),
        }
    }
}

impl std::ops::Deref for Write<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        match self {
            Write::Tx(tx) => tx,
            Write::Savepoint(sp) => sp,
        }
    }
}

fn apply(tx: &Connection, e: &Effect) -> rusqlite::Result<()> {
    match e {
        Effect::SetFrozen(key, frozen) => {
            tx.execute(
                "UPDATE registrar_identity SET frozen = ?2 WHERE key = ?1",
                params![&key[..], frozen],
            )?;
        }
        Effect::Revoke(key) => {
            tx.execute(
                "UPDATE registrar_identity SET revoked = 1 WHERE key = ?1",
                params![&key[..]],
            )?;
        }
        Effect::Rotate { from, to, at } => {
            tx.execute(
                "UPDATE registrar_identity SET rotated_to = ?2 WHERE key = ?1",
                params![&from[..], &to[..]],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO registrar_identity (key, fingerprint, created)
                 VALUES (?1, ?2, ?3)",
                params![&to[..], &fingerprint(to)[..], int(*at)],
            )?;
            tx.execute(
                "UPDATE registrar_handle SET identity = ?2 WHERE identity = ?1",
                params![&from[..], &to[..]],
            )?;
        }
        Effect::LapseHandles { identity, at } => {
            tx.execute(
                "UPDATE registrar_handle SET lapsed_at = ?2
                 WHERE identity = ?1 AND lapsed_at IS NULL",
                params![&identity[..], int(*at)],
            )?;
        }
        Effect::LapseHandle { name, at, barred } => {
            tx.execute(
                "UPDATE registrar_handle
                 SET lapsed_at = IFNULL(lapsed_at, ?2), barred = barred OR ?3
                 WHERE name = ?1",
                params![name, int(*at), barred],
            )?;
        }
        Effect::GrantRecovery(r) => {
            tx.execute(
                "INSERT OR REPLACE INTO registrar_recovery (handle, fingerprint, keep_age, granted)
                 VALUES (?1, ?2, ?3, ?4)",
                params![r.handle, &r.fingerprint[..], r.keep_age, int(r.granted)],
            )?;
        }
        Effect::SetPending(p) => {
            tx.execute(
                &format!(
                    "INSERT OR REPLACE INTO registrar_pending ({PENDING_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5)"
                ),
                params![
                    &p.identity[..],
                    &p.successor[..],
                    int(p.publish_at),
                    &p.digest[..],
                    p.bytes
                ],
            )?;
        }
        Effect::DropPending(key) => {
            tx.execute(
                "DELETE FROM registrar_pending WHERE identity = ?1",
                params![&key[..]],
            )?;
        }
    }
    Ok(())
}

impl RegistrarStore for SqliteRegistrarStore {
    fn identity(&self, key: &Key) -> Result<Option<IdentityRow>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!("SELECT {IDENTITY_COLUMNS} FROM registrar_identity WHERE key = ?1"),
                params![&key[..]],
                identity_of,
            )
            .optional())?
        .transpose()
    }

    fn identity_by_fingerprint(&self, fp: &[u8; 32]) -> Result<Option<IdentityRow>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!(
                    "SELECT {IDENTITY_COLUMNS} FROM registrar_identity WHERE fingerprint = ?1"
                ),
                params![&fp[..]],
                identity_of,
            )
            .optional())?
        .transpose()
    }

    fn handle(&self, name: &str) -> Result<Option<HandleRow>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!("SELECT {HANDLE_COLUMNS} FROM registrar_handle WHERE name = ?1"),
                params![name],
                handle_of,
            )
            .optional())?
        .transpose()
    }

    fn handles_of(&self, key: &Key) -> Result<Vec<HandleRow>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare(&format!(
            "SELECT {HANDLE_COLUMNS} FROM registrar_handle WHERE identity = ?1 ORDER BY name"
        )))?;
        let rows = sql(stmt.query_map(params![&key[..]], handle_of))?;
        rows.map(|r| sql(r)?).collect()
    }

    fn recovery(&self, handle: &str) -> Result<Option<Recovery>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let row = sql(conn
            .query_row(
                "SELECT fingerprint, keep_age, granted FROM registrar_recovery WHERE handle = ?1",
                params![handle],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, bool>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional())?;
        row.map(|(fp, keep_age, granted)| {
            Ok(Recovery {
                handle: handle.to_owned(),
                fingerprint: key32(fp, "recovery fingerprint")?,
                keep_age,
                granted: uint(granted),
            })
        })
        .transpose()
    }

    fn issue(&self, w: &Issue) -> Result<Issued, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(Write::open(&mut conn))?;
        if let Some(hash) = &w.invite {
            let spent = sql(tx.execute(
                "UPDATE registrar_invite SET used_by = ?2, used_at = ?3
                 WHERE code_hash = ?1 AND used_by IS NULL",
                params![&hash[..], &w.identity[..], int(w.issued)],
            ))?;
            if spent == 0 {
                // Dropping the transaction rolls it back; nothing else
                // was written yet anyway.
                return Ok(Issued::InviteSpent);
            }
        }
        sql(tx.execute(
            "INSERT OR IGNORE INTO registrar_identity (key, fingerprint, created)
             VALUES (?1, ?2, ?3)",
            params![
                &w.identity[..],
                &fingerprint(&w.identity)[..],
                int(w.issued)
            ],
        ))?;
        if let Some(c) = &w.commitment {
            sql(tx.execute(
                "UPDATE registrar_identity SET commitment = ?2
                 WHERE key = ?1 AND commitment IS NULL",
                params![&w.identity[..], &c[..]],
            ))?;
        }
        let h = &w.handle;
        sql(tx.execute(
            &format!(
                "INSERT OR REPLACE INTO registrar_handle ({HANDLE_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
            ),
            params![
                h.name,
                &h.identity[..],
                int(h.registered),
                int(h.expires),
                h.lapsed_at.map(int),
                h.barred
            ],
        ))?;
        if let Some(name) = &w.recovery {
            sql(tx.execute(
                "DELETE FROM registrar_recovery WHERE handle = ?1",
                params![name],
            ))?;
        }
        sql(tx.execute(
            "INSERT INTO registrar_log (identity, handle, issued, expires, first, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &w.identity[..],
                h.name,
                int(w.issued),
                int(h.expires),
                w.first,
                w.attestation
            ],
        ))?;
        let seq = tx.last_insert_rowid();
        sql(tx.commit())?;
        Ok(Issued::Logged(uint(seq)))
    }

    fn attestations_expire(
        &self,
        identity: &Key,
        handle: &str,
        issued_up_to: u64,
    ) -> Result<Option<u64>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let max: Option<i64> = sql(conn.query_row(
            "SELECT MAX(expires) FROM registrar_log
             WHERE identity = ?1 AND handle = ?2 AND issued <= ?3",
            params![&identity[..], handle, int(issued_up_to)],
            |r| r.get(0),
        ))?;
        Ok(max.map(uint))
    }

    fn publish(&self, p: &Publish) -> Result<Vec<u64>, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(Write::open(&mut conn))?;
        let mut seqs = Vec::with_capacity(p.records.len());
        for r in &p.records {
            let held: Option<i64> = sql(tx
                .query_row(
                    "SELECT seq FROM registrar_record WHERE digest = ?1",
                    params![&r.digest[..]],
                    |row| row.get(0),
                )
                .optional())?;
            if let Some(seq) = held {
                seqs.push(uint(seq));
                continue;
            }
            sql(tx.execute(
                "INSERT INTO registrar_record (kind, identity, other, until, digest, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    r.kind.as_str(),
                    &r.identity[..],
                    r.other.as_ref().map(|k| &k[..]),
                    r.until.map(int),
                    &r.digest[..],
                    r.bytes
                ],
            ))?;
            seqs.push(uint(tx.last_insert_rowid()));
        }
        for e in &p.effects {
            sql(apply(&tx, e))?;
        }
        sql(tx.commit())?;
        Ok(seqs)
    }

    fn record_seq(&self, digest: &[u8; 32]) -> Result<Option<u64>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let seq: Option<i64> = sql(conn
            .query_row(
                "SELECT seq FROM registrar_record WHERE digest = ?1",
                params![&digest[..]],
                |r| r.get(0),
            )
            .optional())?;
        Ok(seq.map(uint))
    }

    fn begin(&self) -> Result<(), StoreError> {
        // IMMEDIATE takes the database's write lock now rather than at the
        // first write, so a decision's reads see the last writer's commit
        // and no other writer's until this one is done. `busy_timeout`
        // makes each side wait for the other.
        sql(self.conn.lock().unwrap().execute_batch("BEGIN IMMEDIATE"))
    }

    fn commit(&self) -> Result<(), StoreError> {
        sql(self.conn.lock().unwrap().execute_batch("COMMIT"))
    }

    fn rollback(&self) {
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if !conn.is_autocommit() {
            if let Err(e) = conn.execute_batch("ROLLBACK") {
                tracing::error!("registrar store: rollback failed: {e}");
            }
        }
    }

    fn set_commitment(&self, key: &Key, commitment: &[u8; 32]) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let n = sql(conn.execute(
            "UPDATE registrar_identity SET commitment = ?2 WHERE key = ?1 AND commitment IS NULL",
            params![&key[..], &commitment[..]],
        ))?;
        Ok(n > 0)
    }

    fn pending(&self, key: &Key) -> Result<Option<Pending>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!("SELECT {PENDING_COLUMNS} FROM registrar_pending WHERE identity = ?1"),
                params![&key[..]],
                pending_of,
            )
            .optional())?
        .transpose()
    }

    fn pending_due(&self, now: u64) -> Result<Vec<Pending>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare(&format!(
            "SELECT {PENDING_COLUMNS} FROM registrar_pending
             WHERE publish_at <= ?1 ORDER BY publish_at, identity"
        )))?;
        let rows = sql(stmt.query_map(params![int(now)], pending_of))?;
        rows.map(|r| sql(r)?).collect()
    }

    fn records_page(
        &self,
        filter: RecordFilter,
        since: u64,
        budget: usize,
    ) -> Result<Page, StoreError> {
        let conn = self.conn.lock().unwrap();
        match filter {
            RecordFilter::Identity(key) => {
                let mut stmt = sql(conn.prepare(
                    "SELECT seq, bytes FROM registrar_record
                     WHERE seq > ?1 AND (identity = ?2 OR other = ?2)
                     ORDER BY seq",
                ))?;
                let mut rows = sql(stmt.query(params![int(since), &key[..]]))?;
                page_of(&mut rows, budget)
            }
            RecordFilter::All { now, device_cap } => {
                // Each identity's device revocations are ranked by
                // `until`, latest first (ties to the later seq), over the
                // whole table — the cap is on what the list carries, not
                // on what a page happens to start from.
                let mut stmt = sql(conn.prepare(
                    "WITH ranked AS (
                       SELECT seq, kind, until, bytes,
                              ROW_NUMBER() OVER (
                                PARTITION BY identity, kind
                                ORDER BY IFNULL(until, 9223372036854775807) DESC, seq DESC
                              ) AS rank
                       FROM registrar_record
                     )
                     SELECT seq, bytes FROM ranked
                     WHERE seq > ?1
                       AND (kind NOT IN ('revoke_device', 'revoke_attestation')
                            OR until IS NULL OR until >= ?2)
                       AND (kind != 'revoke_device' OR rank <= ?3)
                     ORDER BY seq",
                ))?;
                let cap = i64::try_from(device_cap).unwrap_or(i64::MAX);
                let mut rows = sql(stmt.query(params![int(since), int(now), cap]))?;
                page_of(&mut rows, budget)
            }
        }
    }

    fn log_page(&self, since: u64, budget: usize) -> Result<Page, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            sql(conn.prepare("SELECT seq, bytes FROM registrar_log WHERE seq > ?1 ORDER BY seq"))?;
        let mut rows = sql(stmt.query(params![int(since)]))?;
        page_of(&mut rows, budget)
    }

    fn counts(&self, now: u64) -> Result<Counts, StoreError> {
        let conn = self.conn.lock().unwrap();
        let one = |q: &str, p: &[&dyn rusqlite::ToSql]| -> Result<u64, StoreError> {
            sql(conn.query_row(q, p, |r| r.get::<_, i64>(0))).map(uint)
        };
        let now_i = int(now);
        let first_since = |since: u64| {
            one(
                "SELECT COUNT(*) FROM registrar_log WHERE first = 1 AND issued > ?1",
                &[&int(since)],
            )
        };
        Ok(Counts {
            identities: one(
                "SELECT COUNT(DISTINCT identity) FROM registrar_handle
                 WHERE lapsed_at IS NULL AND expires > ?1",
                &[&now_i],
            )?,
            issued_24h: first_since(now.saturating_sub(86_400))?,
            issued_7d: first_since(now.saturating_sub(7 * 86_400))?,
            issued_total: one("SELECT COUNT(*) FROM registrar_log WHERE first = 1", &[])?,
            revoked_total: one(
                "SELECT COUNT(*) FROM registrar_record WHERE kind = ?1",
                &[&RecordKind::RevokeAttestation.as_str()],
            )?,
            frozen: one(
                "SELECT COUNT(*) FROM registrar_identity WHERE frozen = 1",
                &[],
            )?,
            log_seq: one("SELECT IFNULL(MAX(seq), 0) FROM registrar_log", &[])?,
        })
    }

    fn invite_open(&self, hash: &[u8; 32]) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let open: Option<bool> = sql(conn
            .query_row(
                "SELECT used_by IS NULL FROM registrar_invite WHERE code_hash = ?1",
                params![&hash[..]],
                |r| r.get(0),
            )
            .optional())?;
        Ok(open == Some(true))
    }

    fn add_invites(&self, hashes: &[[u8; 32]]) -> Result<usize, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(Write::open(&mut conn))?;
        let mut added = 0;
        for h in hashes {
            added += sql(tx.execute(
                "INSERT OR IGNORE INTO registrar_invite (code_hash) VALUES (?1)",
                params![&h[..]],
            ))?;
        }
        sql(tx.commit())?;
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_the_conformance_suite() {
        hxd_registrar::conformance::run(&|| Box::new(SqliteRegistrarStore::in_memory().unwrap()));
    }

    #[test]
    fn a_file_keeps_its_schema_and_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registrar.db");
        {
            let s = SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();
            s.add_invites(&[[1; 32]]).unwrap();
        }
        let s = SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();
        assert!(s.invite_open(&[1; 32]).unwrap());
    }

    /// An operator's `hxd registrar` command opens the server's file from
    /// another process; `begin` is what keeps its writes out of the
    /// server's decisions, and the server's out of its.
    #[test]
    fn a_begun_write_holds_off_another_opener_until_it_commits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registrar.db");
        let server = SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();
        let operator = SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();

        server.begin().unwrap();
        let waiting = std::thread::spawn(move || operator.add_invites(&[[2; 32]]));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!waiting.is_finished(), "the other writer did not wait");
        assert_eq!(server.add_invites(&[[1; 32]]).unwrap(), 1);
        server.commit().unwrap();
        assert_eq!(waiting.join().unwrap().unwrap(), 1);
        assert!(server.invite_open(&[1; 32]).unwrap());
        assert!(server.invite_open(&[2; 32]).unwrap());

        // Rolled back, a begun write leaves nothing, and the store is
        // back to writing on its own.
        server.begin().unwrap();
        server.add_invites(&[[3; 32]]).unwrap();
        server.rollback();
        assert!(!server.invite_open(&[3; 32]).unwrap());
        assert_eq!(server.add_invites(&[[3; 32]]).unwrap(), 1);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registrar.db");
        SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute("UPDATE registrar_meta SET version = 99", [])
            .unwrap();
        let err = SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap_err();
        assert!(err.0.contains("newer hxd"), "{err}");
    }

    #[test]
    fn it_can_share_a_file_with_the_inbox_without_either_misreading_the_other() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        crate::SqliteStore::open(&path, Synchronous::Normal).unwrap();
        SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();
        crate::SqliteStore::open(&path, Synchronous::Normal).unwrap();
        SqliteRegistrarStore::open(&path, Synchronous::Normal).unwrap();
    }
}
