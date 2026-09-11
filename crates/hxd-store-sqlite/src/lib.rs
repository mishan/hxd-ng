//! The private-message inbox and public-chat history on SQLite.
//!
//! A [`MessageStore`] backed by one file, so a server gains offline
//! messages without gaining an operations problem. Design and the
//! rusqlite-rather-than-sqlx reasoning: `docs/private-messages.md` §4.
//!
//! **One connection behind a mutex.** Not a pool: this store has exactly
//! one writer (the domain's message path) and its reads are single-row or
//! single-page lookups on an indexed column. Serialising them costs
//! nothing at the scale this server is for, and it means no connection can
//! be holding a transaction open while another waits on the write lock. A
//! pool is the answer if that ever stops being true; it is not the answer
//! to a problem nobody has.
//!
//! **Times are unix seconds** at this boundary. `SystemTime` is the
//! domain's type; the conversion is here and nowhere else, and it floors
//! at the epoch rather than failing — a clock set before 1970 should not
//! be able to refuse a message.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hxd_core::history::{
    ChatLog, HistoryPage, HistoryQuery, LineFlags, LineId, LogLine, MediaMeta, NewLine,
};
use hxd_core::inbox::{
    Delivery, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageStore, NewMessage,
    Pushed, StoreError, StoredMessage,
};
use rusqlite::{params, Connection, OptionalExtension, Row};

/// How hard a commit tries to survive the machine losing power.
///
/// `Normal` survives a process crash — which is the failure this subsystem
/// exists for — and not a power cut, because it does not fsync the WAL on
/// every commit. `Full` does, at a per-message cost the operator can
/// decide is worth paying.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Synchronous {
    #[default]
    Normal,
    Full,
}

impl Synchronous {
    fn pragma(self) -> &'static str {
        match self {
            Synchronous::Normal => "NORMAL",
            Synchronous::Full => "FULL",
        }
    }
}

mod news;

/// The schema this build writes. Bumping it means adding an arm to
/// [`migrate`].
const SCHEMA_VERSION: i64 = 3;

const SCHEMA_V1: &str = "
CREATE TABLE message (
  id           INTEGER PRIMARY KEY,
  kind         INTEGER NOT NULL DEFAULT 0,
  recipient    TEXT    NOT NULL,
  recipient_fp TEXT,
  sender       TEXT,
  sender_fp    TEXT,
  sender_nick  TEXT    NOT NULL,
  body         TEXT    NOT NULL,
  guid         TEXT,
  sent_at      INTEGER NOT NULL,
  delivered_at INTEGER,
  read_at      INTEGER
);
-- Two index shapes, because a mailbox is addressed two ways and one
-- index cannot lead with both. A query for an identified mailbox filters
-- on recipient_fp alone; one for a bare login filters on recipient with
-- recipient_fp IS NULL. A single (recipient_fp, recipient, …) index made
-- the second read every row on a server with no identities — which is
-- every server today — and then sort them in a temp b-tree.
CREATE INDEX message_by_fp ON message (recipient_fp, kind, id)
  WHERE recipient_fp IS NOT NULL;
CREATE INDEX message_by_login ON message (recipient, kind, id)
  WHERE recipient_fp IS NULL;
CREATE INDEX message_pending_fp ON message (recipient_fp, kind, id)
  WHERE recipient_fp IS NOT NULL AND delivered_at IS NULL;
CREATE INDEX message_pending_login ON message (recipient, kind, id)
  WHERE recipient_fp IS NULL AND delivered_at IS NULL;
CREATE INDEX message_by_sender ON message (sender_fp, sender);
-- Retention scans these rather than the whole table.
CREATE INDEX message_read_at ON message (read_at) WHERE read_at IS NOT NULL;
CREATE INDEX message_unread_age ON message (sent_at) WHERE read_at IS NULL;
-- Retry safety: one message per (sender, recipient, guid). Leading with
-- `guid` is what makes this usable as a lookup index and not only as a
-- constraint.
--
-- The key is *the mailbox*, not the mailbox's two columns: an identified
-- mailbox is its fingerprint and an unidentified one is its login, and
-- including both meant (X, alice, ...) and (NULL, alice, ...) were
-- distinct rows -- until claim tried to stamp the second with X, hit the
-- constraint, rolled back the transaction, and stranded *all* of alice's
-- bare-login mail. Reachable by unlink, retry with the same guid, relink.
CREATE UNIQUE INDEX message_guid ON message (
  guid,
  IFNULL(recipient_fp, recipient),
  IFNULL(sender_fp, IFNULL(sender, ''))
) WHERE guid IS NOT NULL;

CREATE TABLE block (
  id         INTEGER PRIMARY KEY,
  owner      TEXT    NOT NULL,
  owner_fp   TEXT,
  other      TEXT    NOT NULL,
  other_fp   TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX block_by_owner ON block (owner_fp, owner, id);
CREATE INDEX block_by_other ON block (other_fp, other, id);
";

// History, media persistence seams, and moderation share one additive
// migration. Some tables are not called until their later stages land, but
// reserving their exact schema now prevents a build that already stamped v2
// from having to pretend the same version means two different databases.
const SCHEMA_V2: &str = "
ALTER TABLE message ADD COLUMN media_id BLOB;
ALTER TABLE message ADD COLUMN media_type TEXT;
ALTER TABLE message ADD COLUMN media_w INTEGER;
ALTER TABLE message ADD COLUMN media_h INTEGER;
ALTER TABLE message ADD COLUMN media_bytes INTEGER;

CREATE TABLE chat_line (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  channel     INTEGER NOT NULL DEFAULT 0,
  nick        TEXT    NOT NULL,
  login       TEXT,
  login_fp    TEXT,
  icon        INTEGER NOT NULL DEFAULT 0,
  flags       INTEGER NOT NULL DEFAULT 0,
  body        TEXT    NOT NULL,
  at          INTEGER NOT NULL,
  deleted_at  INTEGER,
  deleted_by  TEXT,
  media_id    BLOB,
  media_type  TEXT,
  media_w     INTEGER,
  media_h     INTEGER,
  media_bytes INTEGER
);
CREATE INDEX chat_line_by_channel ON chat_line (channel, id);
CREATE INDEX chat_line_at ON chat_line (at);

CREATE TABLE moderation (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         INTEGER NOT NULL,
  actor        TEXT    NOT NULL,
  actor_fp     TEXT,
  target_line  INTEGER,
  target_media BLOB,
  target_login TEXT,
  target_fp    TEXT,
  reason       TEXT    NOT NULL,
  evidence     TEXT,
  media_hash   BLOB,
  at           INTEGER NOT NULL
);
CREATE TABLE report (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  kind         INTEGER NOT NULL,
  reporter     TEXT,
  reporter_fp  TEXT,
  target_line  INTEGER,
  target_media BLOB,
  target_msg   INTEGER,
  target_login TEXT,
  target_fp    TEXT,
  reason       TEXT    NOT NULL,
  evidence     TEXT,
  verified     INTEGER NOT NULL DEFAULT 1,
  at           INTEGER NOT NULL,
  closed_at    INTEGER,
  closed_by    TEXT,
  outcome      INTEGER,
  note         TEXT,
  duplicate_of INTEGER
);
CREATE INDEX report_open ON report (id) WHERE closed_at IS NULL;
CREATE TABLE media_block (
  hash BLOB PRIMARY KEY,
  at   INTEGER NOT NULL,
  by   TEXT NOT NULL
);
";

// The news tree (`docs/news.md` §4): what threaded news with plain bodies
// needs, and nothing its later stages have not settled yet. The search
// index, the attachment tables and subscriptions are further additive
// versions when they land, each with the code that fills them — a table
// nothing writes is a table whose contents a later build has to guess at.
//
// `news_article_root` is not in the design's list. It is what makes a
// thread's aggregates (reply count, last post) and retention's grouping a
// lookup by root rather than a scan, and it costs one index.
const SCHEMA_V3: &str = "
CREATE TABLE news_node (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  parent     INTEGER REFERENCES news_node(id),
  kind       INTEGER NOT NULL,
  name       TEXT    NOT NULL,
  guid       BLOB    NOT NULL,
  add_sn     INTEGER NOT NULL DEFAULT 1,
  delete_sn  INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
-- IFNULL because SQLite treats NULLs as distinct in a unique index, and
-- two root-level nodes named alike must collide like any other siblings.
CREATE UNIQUE INDEX news_node_sibling ON news_node (IFNULL(parent, 0), name);

CREATE TABLE news_article (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  category   INTEGER NOT NULL REFERENCES news_node(id),
  parent     INTEGER REFERENCES news_article(id),
  root       INTEGER NOT NULL,
  path       BLOB    NOT NULL,
  depth      INTEGER NOT NULL,
  nick       TEXT    NOT NULL,
  login      TEXT,
  login_fp   TEXT,
  subject    TEXT    NOT NULL,
  body       TEXT    NOT NULL,
  mime       TEXT    NOT NULL DEFAULT 'text/plain',
  plain      TEXT,
  attach_names TEXT,
  at         INTEGER NOT NULL,
  deleted_at INTEGER,
  deleted_by TEXT,
  -- What the search index reads, by name (docs/news.md §6.1). Computed
  -- on read and stored nowhere, so the text exists once. Here from the
  -- start, with `attach_names` in the expression before anything writes
  -- it, because a generated column's expression cannot be changed
  -- without rebuilding the table.
  author      TEXT GENERATED ALWAYS AS (nick || ' ' || IFNULL(login, '')) VIRTUAL,
  search_body TEXT GENERATED ALWAYS AS
    (COALESCE(plain, body) || IFNULL(char(10) || attach_names, '')) VIRTUAL
);
CREATE INDEX news_article_thread ON news_article (category, path);
CREATE INDEX news_article_roots  ON news_article (category, id) WHERE parent IS NULL;
CREATE INDEX news_article_root   ON news_article (root, id);
CREATE INDEX news_article_author ON news_article (login_fp, login, id);
CREATE INDEX news_article_at     ON news_article (at);

CREATE TABLE news_ref (
  src  INTEGER NOT NULL REFERENCES news_article(id),
  dst  INTEGER NOT NULL REFERENCES news_article(id),
  ord  INTEGER NOT NULL,
  PRIMARY KEY (src, dst)
) WITHOUT ROWID;
CREATE INDEX news_ref_dst ON news_ref (dst, src);
";

/// The mailbox-matching rule (`hxd_core::inbox::Mailbox`) as a SQL
/// predicate over a `(<col>, <col>_fp)` pair — **one shape per kind of
/// mailbox**, and one bind either way ([`bind`] supplies it).
///
/// An identified mailbox is `<col>_fp = ?n`; an unidentified one is
/// `<col>_fp IS NULL AND <col> = ?n`. What neither ever does is let one
/// kind match the other — see `Mailbox`'s docs for why that strictness is
/// the point.
///
/// The earlier single shape, `<col>_fp IS ?a AND (?a IS NOT NULL OR <col>
/// = ?b)`, was right and unindexable: SQLite could only use the leading
/// `recipient_fp` column, so on a server with no identities — which is
/// every server today, `recipient_fp` NULL on every row — it read the
/// whole table and sorted it in a temp b-tree. Two shapes, two partial
/// indexes, and each query touches only its own rows.
fn mailbox_sql(m: &Mailbox, col: &str, n: usize) -> String {
    match m.fingerprint {
        Some(_) => format!("{col}_fp = ?{n}"),
        None => format!("{col}_fp IS NULL AND {col} = ?{n}"),
    }
}

/// The single bind value [`mailbox_sql`] expects: the fingerprint's
/// storage spelling, or the login.
fn bind(m: &Mailbox) -> String {
    match m.fingerprint.as_ref() {
        Some(fp) => fp_hex(fp),
        None => m.login.clone(),
    }
}

#[derive(Debug)]
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (creating if absent) the store database at `path`.
    pub fn open(path: impl AsRef<Path>, sync: Synchronous) -> Result<Self, StoreError> {
        Self::open_inner(path, sync, false)
    }

    /// Open an existing database without changing it: no migration, no
    /// WAL switch, no database created, and the file itself byte-identical
    /// afterwards.
    ///
    /// For `hxd inbox purge --dry-run`, whose whole promise is that it
    /// changes nothing. Opening normally created the file when it was
    /// missing and *migrated* it when it was not, so a dry run against a
    /// server one version back did the upgrade the operator was still
    /// deciding about. A read-only handle answers the same questions.
    ///
    /// The promise is about the database, not about the directory around
    /// it. Reading a WAL database needs its `-shm` sidecar, and where the
    /// directory allows it SQLite creates that — and an empty `-wal` —
    /// rather than refusing the read. So an ordinary dry run against a
    /// stopped server does leave the two sidecars behind, holding nothing
    /// the next `hxd` run does not rebuild. Only the case that cannot
    /// afford them takes the path that needs neither — see
    /// `can_use_immutable`.
    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_inner(path, Synchronous::Normal, true)
    }

    fn open_inner(
        path: impl AsRef<Path>,
        sync: Synchronous,
        read_only: bool,
    ) -> Result<Self, StoreError> {
        if read_only {
            use rusqlite::OpenFlags;
            let path = path.as_ref();
            // The ordinary read: it may create the `-shm` the WAL format
            // needs, which is why this is not the path for a directory
            // nothing can be written in. Immutable mode needs no sidecar,
            // but it also *ignores* one, so it is taken only where nothing
            // can be writing at all.
            let conn = if can_use_immutable(path) {
                Connection::open_with_flags(
                    immutable_uri(path)?,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
                )
            } else {
                Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            }
            .map_err(StoreError::new)?;
            conn.busy_timeout(Duration::from_secs(5))
                .map_err(StoreError::new)?;
            // The version is still checked: a database from a newer hxd
            // must not be read with this build's idea of the schema.
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(StoreError::new)?;
            if version == 0 {
                return Err(StoreError(
                    "inbox database has no schema yet, so it holds no messages".into(),
                ));
            }
            if version != SCHEMA_VERSION {
                return Err(StoreError(format!(
                    "inbox database is schema version {version}, but this build \
                     reads {SCHEMA_VERSION}; run hxd normally to migrate it"
                )));
            }
            return Ok(SqliteStore {
                conn: Mutex::new(conn),
            });
        }
        let conn = Connection::open(path).map_err(StoreError::new)?;
        // A write should wait for a concurrent one rather than failing the
        // send; five seconds is far longer than any statement here takes,
        // so hitting it means something is genuinely wrong.
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(StoreError::new)?;
        // journal_mode returns the mode it settled on, so it is a query
        // rather than an exec. In-memory databases answer "memory" and
        // that is fine — there is no WAL to want.
        let _: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(StoreError::new)?;
        conn.pragma_update(None, "synchronous", sync.pragma())
            .map_err(StoreError::new)?;
        migrate(&conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// An in-memory database. For tests, and for anyone who wants the
    /// SQLite implementation's exact semantics without a file.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:", Synchronous::Normal)
    }
}

#[cfg(unix)]
fn can_use_immutable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let directory_is_read_only = path
        .parent()
        .and_then(|p| p.metadata().ok())
        .is_some_and(|m| m.permissions().mode() & 0o222 == 0);
    // Existing sidecars can belong to a live writer, or hold committed
    // data not checkpointed into the main file. Immutable mode ignores
    // them, so it is allowed only for a clean, stopped database. The
    // rollback journal is checked beside the two WAL ones: this store runs
    // in WAL mode, but a database interrupted before that switch would
    // leave a `-journal`, and immutable mode would read straight past the
    // rollback it describes.
    //
    // "No process can write here", rather than "this one cannot": a
    // directory the server's own user can still write is one where a
    // checkpoint can start mid-read, and an unlocked reader of the main
    // file would see it torn. A dry run that answers wrongly is worse than
    // one that leaves two sidecars behind.
    directory_is_read_only
        && ["-wal", "-shm", "-journal"]
            .iter()
            .all(|suffix| !sidecar(path, suffix).exists())
}

#[cfg(not(unix))]
fn can_use_immutable(_path: &Path) -> bool {
    false
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// A SQLite `file:` URI for immutable reads. Percent-encoding the path is
/// load-bearing: `?` and `#` are valid filename bytes and URI delimiters.
fn immutable_uri(path: &Path) -> Result<String, StoreError> {
    let path = path.canonicalize().map_err(StoreError::new)?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = path
        .to_str()
        .ok_or_else(|| StoreError("inbox path is not valid Unicode".into()))?
        .as_bytes()
        .to_vec();
    let mut uri = String::from("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~' | b':') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(uri, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(StoreError::new)?;
    if version == SCHEMA_VERSION {
        return Ok(());
    }
    if version > SCHEMA_VERSION {
        return Err(StoreError(format!(
            "inbox database is schema version {version}, but this build \
             writes {SCHEMA_VERSION} — it was made by a newer hxd"
        )));
    }
    // The schema and the version it declares go in together. Separately,
    // a crash between them leaves tables with user_version 0, and the
    // next open runs CREATE TABLE against tables that already exist.
    // `user_version` can't be a bound parameter, hence the format.
    let mut steps = String::from("BEGIN IMMEDIATE;\n");
    if version == 0 {
        steps.push_str(SCHEMA_V1);
    }
    if version < 2 {
        steps.push_str(SCHEMA_V2);
    }
    if version < 3 {
        steps.push_str(SCHEMA_V3);
    }
    steps.push_str(&format!(
        "\nPRAGMA user_version = {SCHEMA_VERSION};\nCOMMIT;\n"
    ));
    conn.execute_batch(&steps).map_err(StoreError::new)?;
    Ok(())
}

/// `SystemTime` → unix seconds, floored at the epoch.
fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn from_unix(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64)
}

/// `now - back`, floored at the epoch: a retention window longer than the
/// clock has been running prunes nothing rather than wrapping.
fn cutoff(now: SystemTime, back: Duration) -> i64 {
    unix(now.checked_sub(back).unwrap_or(UNIX_EPOCH))
}

/// When a merge would move a row into a guid that is already taken
/// (`message_guid`), which row goes: one predicate per half of that
/// index's key, because both halves move. `?1` is the destination
/// fingerprint and `?2` is what is being merged away (a login for
/// `claim`, the old fingerprint for `rotate`).
///
/// Each names the row this merge moves (`dup`) against a row already at
/// the destination (`kept`), so whichever half runs first, one of any
/// colliding pair survives. The comparison on the *other* half is over
/// the key as it will be after the merge: a row that keeps its recipient
/// can still collide because its sender is the one moving.
///
/// What they deliberately do not compare is the login text beside the
/// fingerprint. The unique index keys on `IFNULL(<col>_fp, <col>)`, so
/// after a rename the kept row carries an older login, and comparing
/// them would miss exactly the collision the index is about to raise.
struct Collapse {
    /// What makes `kept` the row that stays.
    destination: &'static str,
    /// What makes `dup` a row this merge moves onto `kept`'s key.
    duplicate: &'static str,
}

const CLAIM_COLLAPSE: [Collapse; 2] = [
    // Recipient side: rows addressed to the bare login.
    Collapse {
        destination: "kept.recipient_fp = ?1",
        duplicate: "dup.guid = kept.guid
                AND dup.id <> kept.id
                AND dup.recipient_fp IS NULL AND dup.recipient = ?2
                AND CASE WHEN dup.sender_fp IS NULL AND dup.sender = ?2 THEN ?1
                         ELSE IFNULL(dup.sender_fp, IFNULL(dup.sender, '')) END
                  = CASE WHEN kept.sender_fp IS NULL AND kept.sender = ?2 THEN ?1
                         ELSE IFNULL(kept.sender_fp, IFNULL(kept.sender, '')) END",
    },
    // Sender side: rows this login sent while it had no fingerprint.
    Collapse {
        destination: "kept.sender_fp = ?1",
        duplicate: "dup.guid = kept.guid
                AND dup.id <> kept.id
                AND dup.sender_fp IS NULL AND dup.sender = ?2
                AND CASE WHEN dup.recipient_fp IS NULL AND dup.recipient = ?2 THEN ?1
                         ELSE IFNULL(dup.recipient_fp, dup.recipient) END
                  = CASE WHEN kept.recipient_fp IS NULL AND kept.recipient = ?2 THEN ?1
                         ELSE IFNULL(kept.recipient_fp, kept.recipient) END",
    },
];

/// The same two, for a rotation: the rows that move are the ones
/// carrying the old fingerprint.
const ROTATE_COLLAPSE: [Collapse; 2] = [
    Collapse {
        destination: "kept.recipient_fp = ?1",
        duplicate: "dup.guid = kept.guid
                AND dup.id <> kept.id
                AND dup.recipient_fp = ?2
                AND CASE WHEN dup.sender_fp = ?2 THEN ?1
                         ELSE IFNULL(dup.sender_fp, IFNULL(dup.sender, '')) END
                  = CASE WHEN kept.sender_fp = ?2 THEN ?1
                         ELSE IFNULL(kept.sender_fp, IFNULL(kept.sender, '')) END",
    },
    Collapse {
        destination: "kept.sender_fp = ?1",
        duplicate: "dup.guid = kept.guid
                AND dup.id <> kept.id
                AND dup.sender_fp = ?2
                AND CASE WHEN dup.recipient_fp = ?2 THEN ?1
                         ELSE IFNULL(dup.recipient_fp, dup.recipient) END
                  = CASE WHEN kept.recipient_fp = ?2 THEN ?1
                         ELSE IFNULL(kept.recipient_fp, kept.recipient) END",
    },
];

impl Collapse {
    /// Carry what the duplicate knows onto the row that survives it.
    ///
    /// The two rows are one message by the guid rule, so what happened to
    /// either happened to the message: a duplicate that was delivered, or
    /// read, makes the survivor delivered or read. Without this the
    /// survivor is whichever row the merge happens to keep, and the
    /// obvious sequence — mail arrives while linked, the account unlinks,
    /// the sender retries, the reader reads the *retry*, the account
    /// relinks — deletes the row that was read and flushes the survivor
    /// again as unread.
    fn promote(&self) -> String {
        let (dest, dup) = (self.destination, self.duplicate);
        format!(
            "UPDATE message AS kept
                SET delivered_at = COALESCE(kept.delivered_at,
                      (SELECT MIN(dup.delivered_at) FROM message AS dup WHERE {dup})),
                    read_at = COALESCE(kept.read_at,
                      (SELECT MIN(dup.read_at) FROM message AS dup WHERE {dup}))
              WHERE {dest} AND kept.guid IS NOT NULL
                AND EXISTS (SELECT 1 FROM message AS dup WHERE {dup})"
        )
    }

    /// Then the duplicate goes.
    fn delete(&self) -> String {
        let (dest, dup) = (self.destination, self.duplicate);
        format!(
            "DELETE FROM message AS dup
              WHERE dup.guid IS NOT NULL
                AND EXISTS (SELECT 1 FROM message AS kept WHERE {dest} AND {dup})"
        )
    }
}

/// One block per pair of mailboxes. The `block` table has no unique
/// index to collide with, so a merge leaves duplicates instead: block
/// while linked, unlink, block again, relink, and the same pair is
/// listed twice — after which the two stores disagreed about what
/// `unblock` meant, SQLite deleting every match and the memory store
/// one. De-duplicating at the merge is what keeps that from being a
/// question either store has to answer.
/// Scoped to the fingerprint the merge moved things onto (`?1`): those
/// are the only rows whose key changed, so they are the only ones that
/// can have become duplicates. Unscoped this was a whole-table group-by
/// on an unindexed expression, run inside every `claim` — which is every
/// login of a linked account.
const MERGE_BLOCKS: &str = "DELETE FROM block
  WHERE (owner_fp = ?1 OR other_fp = ?1)
    AND id NOT IN (
      SELECT MIN(id) FROM block
       WHERE owner_fp = ?1 OR other_fp = ?1
       GROUP BY IFNULL(owner_fp, owner), IFNULL(other_fp, other))";

/// A fingerprint's storage spelling: lowercase hex, chosen here and
/// nowhere else. The domain's key is the raw 32 bytes (see `Mailbox`), so
/// this is the only place a fingerprint is text at all — which is what
/// keeps two spellings of one key from ever meeting.
fn fp_hex(fp: &[u8; 32]) -> String {
    fp.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn fp_from_hex(s: &str) -> Result<[u8; 32], StoreError> {
    // `is_ascii` before the byte slicing below: a hand-edited row with a
    // multibyte character in it would otherwise panic on a char boundary
    // inside `row()`, under the connection mutex — poisoning it, so every
    // later store call panics too.
    let bytes: Option<Vec<u8>> = (s.len() == 64 && s.is_ascii())
        .then(|| {
            (0..32)
                .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
                .collect()
        })
        .flatten();
    bytes
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| StoreError(format!("stored fingerprint is not 32 hex bytes: {s:?}")))
}

const COLUMNS: &str = "id, kind, recipient, recipient_fp, sender, sender_fp, \
                       sender_nick, body, guid, sent_at, delivered_at, read_at, \
                       media_id, media_type, media_w, media_h, media_bytes";

/// Every read path the inbox exposes is mail only — a kind the wire
/// cannot carry must not be listed, counted, or handed to a flush.
const MAIL_ONLY: &str = "kind = 0";

fn mailbox(login: String, fingerprint: Option<String>) -> Result<Mailbox, StoreError> {
    Ok(Mailbox {
        login,
        fingerprint: fingerprint.as_deref().map(fp_from_hex).transpose()?,
    })
}

/// A row's own corruption is not a reason to lose the whole page, but it
/// is a reason to stop: these columns are written by this file alone, so
/// anything unreadable in them means the database was edited by hand or
/// damaged, and guessing at a mailbox key is how mail reaches the wrong
/// person.
/// The five media columns, which `message` and `chat_line` both carry
/// in the same order and the same types. All five or none: a row with
/// some of them is a row this file did not write.
fn media_columns(
    r: &Row<'_>,
    first: usize,
) -> rusqlite::Result<Result<Option<MediaMeta>, StoreError>> {
    let id: Option<Vec<u8>> = r.get(first)?;
    let mime: Option<String> = r.get(first + 1)?;
    let width: Option<i64> = r.get(first + 2)?;
    let height: Option<i64> = r.get(first + 3)?;
    let bytes: Option<i64> = r.get(first + 4)?;
    Ok((|| match (id, mime, width, height, bytes) {
        (None, None, None, None, None) => Ok(None),
        (Some(id), Some(mime), Some(width), Some(height), Some(bytes)) => Ok(Some(MediaMeta {
            id,
            mime,
            width: u32::try_from(width)
                .map_err(|_| StoreError::new("stored media width is not a u32"))?,
            height: u32::try_from(height)
                .map_err(|_| StoreError::new("stored media height is not a u32"))?,
            bytes: u32::try_from(bytes)
                .map_err(|_| StoreError::new("stored media size is not a u32"))?,
        })),
        _ => Err(StoreError::new("stored media metadata is incomplete")),
    })())
}

fn row(r: &Row<'_>) -> rusqlite::Result<Result<StoredMessage, StoreError>> {
    let sender_login: Option<String> = r.get(4)?;
    let (id, kind): (i64, i64) = (r.get(0)?, r.get(1)?);
    let (rl, rfp): (String, Option<String>) = (r.get(2)?, r.get(3)?);
    let sfp: Option<String> = r.get(5)?;
    let (nick, body, guid): (String, String, Option<String>) = (r.get(6)?, r.get(7)?, r.get(8)?);
    let sent_at: i64 = r.get(9)?;
    let delivered: Option<i64> = r.get(10)?;
    let read: Option<i64> = r.get(11)?;
    let media = media_columns(r, 12)?;
    Ok((|| {
        Ok(StoredMessage {
            // `INTEGER PRIMARY KEY` is signed and `MessageId` is not, so
            // a hand-edited negative id would wrap. It is not a mailbox
            // key, so it cannot misdeliver anything, but a wrapped id is
            // a cursor nobody can page from: refuse the row instead.
            id: MessageId::try_from(id)
                .map_err(|_| StoreError::new(format!("message id {id} is not an id")))?,
            kind: MessageKind::from_i64(kind)
                .ok_or_else(|| StoreError(format!("unknown message kind {kind}")))?,
            recipient: mailbox(rl, rfp)?,
            sender: match sender_login {
                Some(login) => Some(mailbox(login, sfp)?),
                None => None,
            },
            sender_nick: nick,
            body,
            guid: match guid {
                Some(g) => Some(
                    MessageGuid::parse(&g)
                        .ok_or_else(|| StoreError(format!("stored guid is malformed: {g:?}")))?,
                ),
                None => None,
            },
            sent_at: from_unix(sent_at),
            delivered_at: delivered.map(from_unix),
            read_at: read.map(from_unix),
            media: media?,
        })
    })())
}

/// Collect a query's rows, surfacing the first unreadable one.
fn collect(
    rows: impl Iterator<Item = rusqlite::Result<Result<StoredMessage, StoreError>>>,
) -> Result<Vec<StoredMessage>, StoreError> {
    rows.map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
        .collect()
}

impl MessageStore for SqliteStore {
    fn push(&self, m: &NewMessage, cap: usize) -> Result<Pushed, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        // One transaction, so the dedup lookup and the cap count both see
        // the state the insert lands in. Done as separate calls they are
        // check-then-insert, and the retry a guid exists for is exactly
        // what races the first while a parallel sender races the second.
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(StoreError::new)?;
        if let Some(guid) = m.guid.as_ref() {
            if let Some(existing) = find_guid_in(&tx, &m.recipient, m.sender.as_ref(), guid)? {
                return Ok(Pushed::Existing(Box::new(existing)));
            }
        }
        if m.kind == MessageKind::Message {
            let sql = format!(
                "SELECT COUNT(*) FROM message
                  WHERE {} AND {MAIL_ONLY} AND delivered_at IS NULL",
                mailbox_sql(&m.recipient, "recipient", 1)
            );
            let waiting: i64 = tx
                .query_row(&sql, params![bind(&m.recipient)], |r| r.get(0))
                .map_err(StoreError::new)?;
            if waiting as usize >= cap {
                return Ok(Pushed::Full);
            }
        }
        tx.execute(
            "INSERT INTO message
               (kind, recipient, recipient_fp, sender, sender_fp, sender_nick,
                body, guid, sent_at, read_at,
                media_id, media_type, media_w, media_h, media_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                m.kind.as_i64(),
                m.recipient.login,
                m.recipient.fingerprint.as_ref().map(fp_hex),
                m.sender.as_ref().map(|s| &s.login),
                m.sender
                    .as_ref()
                    .and_then(|s| s.fingerprint.as_ref())
                    .map(fp_hex),
                m.sender_nick,
                m.body,
                m.guid.as_ref().map(|g| g.as_str()),
                unix(m.sent_at),
                // A receipt is not something anyone reads; stamping it on
                // arrival keeps it out of unread counts and ages it on the
                // read clock without prune needing to know what kinds are.
                (m.kind != MessageKind::Message).then(|| unix(m.sent_at)),
                m.media.as_ref().map(|x| &x.id),
                m.media.as_ref().map(|x| &x.mime),
                m.media.as_ref().map(|x| x.width),
                m.media.as_ref().map(|x| x.height),
                m.media.as_ref().map(|x| x.bytes),
            ],
        )
        .map_err(StoreError::new)?;
        let id = tx.last_insert_rowid() as MessageId;
        tx.commit().map_err(StoreError::new)?;
        Ok(Pushed::Stored(id))
    }

    fn find_guid(
        &self,
        to: &Mailbox,
        from: Option<&Mailbox>,
        guid: &MessageGuid,
    ) -> Result<Option<StoredMessage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        find_guid_in(&conn, to, from, guid)
    }

    fn pending(&self, to: &Mailbox, limit: usize) -> Result<Vec<StoredMessage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {COLUMNS} FROM message
             WHERE {} AND {MAIL_ONLY} AND delivered_at IS NULL
             ORDER BY id LIMIT ?2",
            mailbox_sql(to, "recipient", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        let rows = stmt
            .query_map(params![bind(to), limit as i64], row)
            .map_err(StoreError::new)?;
        collect(rows)
    }

    fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT COUNT(*) FROM message WHERE {} AND {MAIL_ONLY} AND delivered_at IS NULL",
            mailbox_sql(to, "recipient", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        stmt.query_row(params![bind(to)], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
            .map_err(StoreError::new)
    }

    fn is_pending(&self, to: &Mailbox, id: MessageId) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT 1 FROM message
              WHERE id = ?2 AND {} AND {MAIL_ONLY} AND delivered_at IS NULL",
            mailbox_sql(to, "recipient", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        let found: Option<i64> = stmt
            .query_row(params![bind(to), clamp_id(id)], |r| r.get(0))
            .optional()
            .map_err(StoreError::new)?;
        Ok(found.is_some())
    }

    fn mark_delivered(
        &self,
        ids: &[MessageId],
        at: SystemTime,
        what: Delivery,
    ) -> Result<(), StoreError> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(StoreError::new)?;
        {
            // On the legacy wire the flush is the read (see `Delivery`),
            // so `read_at` is stamped in the same statement rather than
            // left for a `msg_read` that wire can never send.
            let sql = match what {
                Delivery::Delivered => {
                    "UPDATE message SET delivered_at = COALESCE(delivered_at, ?1)
                      WHERE id = ?2 AND delivered_at IS NULL"
                }
                Delivery::Read => {
                    "UPDATE message
                        SET delivered_at = COALESCE(delivered_at, ?1),
                            read_at = COALESCE(read_at, ?1)
                      WHERE id = ?2 AND (delivered_at IS NULL OR read_at IS NULL)"
                }
            };
            let mut stmt = tx.prepare_cached(sql).map_err(StoreError::new)?;
            for id in ids {
                stmt.execute(params![unix(at), clamp_id(*id)])
                    .map_err(StoreError::new)?;
            }
        }
        tx.commit().map_err(StoreError::new)
    }

    fn mark_read(
        &self,
        to: &Mailbox,
        up_to: MessageId,
        at: SystemTime,
    ) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        // COALESCE on delivered_at: a message read straight out of `list`
        // was never flushed, and stamping it here is what keeps `pending`
        // from handing it over a second time.
        let sql = format!(
            "UPDATE message
                SET read_at = ?2, delivered_at = COALESCE(delivered_at, ?2)
              WHERE {} AND {MAIL_ONLY} AND id <= ?3 AND read_at IS NULL",
            mailbox_sql(to, "recipient", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        stmt.execute(params![bind(to), unix(at), clamp_id(up_to)])
            .map_err(StoreError::new)
    }

    fn list(
        &self,
        to: &Mailbox,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT {COLUMNS} FROM message
             WHERE {} AND {MAIL_ONLY} AND (?2 IS NULL OR id < ?2)
             ORDER BY id DESC LIMIT ?3",
            mailbox_sql(to, "recipient", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        let before = before.map(clamp_id);
        let rows = stmt
            .query_map(params![bind(to), before, limit as i64], row)
            .map_err(StoreError::new)?;
        collect(rows)
    }

    fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT COUNT(*), COALESCE(SUM(read_at IS NULL), 0)
               FROM message WHERE {} AND {MAIL_ONLY}",
            mailbox_sql(to, "recipient", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        let got = stmt
            .query_row(params![bind(to)], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            })
            .optional()
            .map_err(StoreError::new)?;
        let (total, unread) = got.unwrap_or((0, 0));
        Ok(InboxCounts {
            unread: unread as usize,
            total: total as usize,
        })
    }

    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
        let fingerprint = fp_hex(fingerprint);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(StoreError::new)?;
        // A guid is unique *per pair of mailboxes*, and this call merges
        // two mailboxes into one — so the same guid can legitimately
        // exist on both sides of the merge. Unlink, retry with the same
        // guid, relink, and the UPDATEs below would hit the constraint
        // and roll the whole transaction back, stranding every one of
        // this login's messages rather than the one that collided. On
        // the recipient side that strands mail *to* this login; on the
        // sender side it strands the same mail just as thoroughly,
        // because the transaction is one.
        //
        // After the merge those rows *are* one message by the guid rule
        // ("two sends of the same guid between the same pair are one
        // message"), and the one already on the fingerprint is the older
        // claim on the name. So collapse rather than collide, on both
        // sides.
        let mut collapsed = 0;
        for half in CLAIM_COLLAPSE {
            tx.execute(&half.promote(), params![fingerprint, login])
                .map_err(StoreError::new)?;
            collapsed += tx
                .execute(&half.delete(), params![fingerprint, login])
                .map_err(StoreError::new)?;
        }
        if collapsed > 0 {
            tracing::info!(
                collapsed,
                login,
                "claim: duplicate guids merged with the identity's mailbox"
            );
        }
        let mut moved = 0;
        for sql in [
            "UPDATE message SET recipient_fp = ?1 WHERE recipient = ?2 AND recipient_fp IS NULL",
            "UPDATE message SET sender_fp = ?1 WHERE sender = ?2 AND sender_fp IS NULL",
            "UPDATE block SET owner_fp = ?1 WHERE owner = ?2 AND owner_fp IS NULL",
            "UPDATE block SET other_fp = ?1 WHERE other = ?2 AND other_fp IS NULL",
        ] {
            moved += tx
                .execute(sql, params![fingerprint, login])
                .map_err(StoreError::new)?;
        }
        let dupes = tx
            .execute(MERGE_BLOCKS, params![fingerprint])
            .map_err(StoreError::new)?;
        if dupes > 0 {
            tracing::info!(dupes, login, "claim: duplicate blocks merged");
        }
        tx.commit().map_err(StoreError::new)?;
        Ok(moved)
    }

    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError> {
        let (from, to) = (fp_hex(from), fp_hex(to));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(StoreError::new)?;
        // The same merge `claim` does, for the same reason: a successor
        // key that already holds a row with this guid makes the update
        // hit the unique index, and a rotation that fails outright over
        // one duplicate strands every message the identity had.
        let mut collapsed = 0;
        for half in ROTATE_COLLAPSE {
            tx.execute(&half.promote(), params![to, from])
                .map_err(StoreError::new)?;
            collapsed += tx
                .execute(&half.delete(), params![to, from])
                .map_err(StoreError::new)?;
        }
        if collapsed > 0 {
            tracing::info!(
                collapsed,
                "rotate: duplicate guids merged with the successor"
            );
        }
        let mut moved = 0;
        for sql in [
            "UPDATE message SET recipient_fp = ?1 WHERE recipient_fp = ?2",
            "UPDATE message SET sender_fp = ?1 WHERE sender_fp = ?2",
            "UPDATE block SET owner_fp = ?1 WHERE owner_fp = ?2",
            "UPDATE block SET other_fp = ?1 WHERE other_fp = ?2",
        ] {
            moved += tx
                .execute(sql, params![to, from])
                .map_err(StoreError::new)?;
        }
        let dupes = tx
            .execute(MERGE_BLOCKS, params![to])
            .map_err(StoreError::new)?;
        if dupes > 0 {
            tracing::info!(dupes, "rotate: duplicate blocks merged");
        }
        tx.commit().map_err(StoreError::new)?;
        Ok(moved)
    }

    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(StoreError::new)?;
        let mut gone = 0;
        for sql in [
            format!(
                "DELETE FROM message WHERE {}",
                mailbox_sql(of, "recipient", 1)
            ),
            format!("DELETE FROM message WHERE {}", mailbox_sql(of, "sender", 1)),
            format!("DELETE FROM block WHERE {}", mailbox_sql(of, "owner", 1)),
            format!("DELETE FROM block WHERE {}", mailbox_sql(of, "other", 1)),
        ] {
            gone += tx
                .execute(&sql, params![bind(of)])
                .map_err(StoreError::new)?;
        }
        tx.commit().map_err(StoreError::new)?;
        Ok(gone)
    }

    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT
               (SELECT COUNT(*) FROM message WHERE ({}) OR ({})) +
               (SELECT COUNT(*) FROM block WHERE ({}) OR ({}))",
            mailbox_sql(of, "recipient", 1),
            mailbox_sql(of, "sender", 1),
            mailbox_sql(of, "owner", 1),
            mailbox_sql(of, "other", 1),
        );
        conn.query_row(&sql, params![bind(of)], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
            .map_err(StoreError::new)
    }

    fn prune(
        &self,
        now: SystemTime,
        unread: Duration,
        read: Duration,
    ) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM message
              WHERE (read_at IS NOT NULL AND read_at < ?1)
                 OR (read_at IS NULL AND sent_at < ?2)",
            params![cutoff(now, read), cutoff(now, unread)],
        )
        .map_err(StoreError::new)
    }

    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        let pair = format!(
            "{} AND {}",
            mailbox_sql(owner, "owner", 1),
            mailbox_sql(other, "other", 2)
        );
        let conn = self.conn.lock().unwrap();
        let (o, t) = (bind(owner), bind(other));
        if !blocked {
            conn.execute(&format!("DELETE FROM block WHERE {pair}"), params![o, t])
                .map(|_| ())
                .map_err(StoreError::new)?;
            return Ok(());
        }
        // Checked inline rather than by calling `is_blocked`, which would
        // take this same non-reentrant lock. Checked at all rather than
        // upserted because the uniqueness we want is over the *matching
        // rule* — two mailboxes being the same one — which no unique index
        // over four columns can express.
        let held: Option<i64> = conn
            .query_row(
                &format!("SELECT 1 FROM block WHERE {pair} LIMIT 1"),
                params![o, t],
                |r| r.get(0),
            )
            .optional()
            .map_err(StoreError::new)?;
        if held.is_some() {
            return Ok(());
        }
        conn.execute(
            "INSERT INTO block (owner, owner_fp, other, other_fp, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                owner.login,
                owner.fingerprint.as_ref().map(fp_hex),
                other.login,
                other.fingerprint.as_ref().map(fp_hex),
                unix(at)
            ],
        )
        .map(|_| ())
        .map_err(StoreError::new)
    }

    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT 1 FROM block WHERE {} AND {} LIMIT 1",
            mailbox_sql(owner, "owner", 1),
            mailbox_sql(other, "other", 2)
        );
        let found: Option<i64> = conn
            .query_row(&sql, params![bind(owner), bind(other)], |r| r.get(0))
            .optional()
            .map_err(StoreError::new)?;
        Ok(found.is_some())
    }

    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT other, other_fp FROM block WHERE {} ORDER BY id",
            mailbox_sql(owner, "owner", 1)
        );
        let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
        let rows = stmt
            .query_map(params![bind(owner)], |r| Ok(mailbox(r.get(0)?, r.get(1)?)))
            .map_err(StoreError::new)?;
        rows.map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
            .collect()
    }
}

/// `find_guid` against whatever connection the caller holds — `push` runs
/// it inside its own transaction, so it cannot go back through the
/// non-reentrant connection mutex.
fn find_guid_in(
    conn: &Connection,
    to: &Mailbox,
    from: Option<&Mailbox>,
    guid: &MessageGuid,
) -> Result<Option<StoredMessage>, StoreError> {
    // A sender with no mailbox at all is its own scope, and `Mailbox`
    // cannot describe it — a mailbox always has a login. So that case
    // gets its own clause rather than an empty string standing in for
    // NULL, which would match nothing and silently duplicate.
    let sender_clause = match from {
        Some(m) => mailbox_sql(m, "sender", 3),
        // The `sender IS NULL` clause takes no bind, so the parameter
        // list is a bind shorter in that branch.
        None => "sender IS NULL AND sender_fp IS NULL".to_string(),
    };
    let sql = format!(
        "SELECT {COLUMNS} FROM message
         WHERE guid = ?1 AND {} AND {sender_clause}
         LIMIT 1",
        mailbox_sql(to, "recipient", 2)
    );
    let found = match from {
        Some(m) => conn
            .query_row(&sql, params![guid.as_str(), bind(to), bind(m)], row)
            .optional(),
        None => conn
            .query_row(&sql, params![guid.as_str(), bind(to)], row)
            .optional(),
    }
    .map_err(StoreError::new)?;
    found.transpose()
}

/// A `MessageId` as SQLite can hold it. Ids are `u64` in the domain and
/// `INTEGER PRIMARY KEY` here, so anything past `i64::MAX` is not an id
/// this store ever issued — clamping makes `msg_read {up_to: 2^63}` mean
/// "everything", which is what the in-memory store already does with it.
fn clamp_id(id: MessageId) -> i64 {
    id.min(i64::MAX as u64) as i64
}

const HISTORY_COLUMNS: &str = "id, channel, nick, login, login_fp, icon, flags, body, at, \
                               media_id, media_type, media_w, media_h, media_bytes";

fn history_row(r: &Row<'_>) -> rusqlite::Result<Result<LogLine, StoreError>> {
    let id: i64 = r.get(0)?;
    let channel: i64 = r.get(1)?;
    let nick: String = r.get(2)?;
    let login: Option<String> = r.get(3)?;
    let login_fp: Option<String> = r.get(4)?;
    let icon: i64 = r.get(5)?;
    let flags: i64 = r.get(6)?;
    let body: String = r.get(7)?;
    let at: i64 = r.get(8)?;
    let media = media_columns(r, 9)?;
    Ok((|| {
        let media = media?;
        Ok(LogLine {
            id: LineId::try_from(id)
                .map_err(|_| StoreError::new(format!("chat line id {id} is not an id")))?,
            channel: u32::try_from(channel)
                .map_err(|_| StoreError::new(format!("chat channel {channel} is not a u32")))?,
            from_nick: nick,
            from_login: login,
            from_fingerprint: login_fp.as_deref().map(fp_from_hex).transpose()?,
            icon: u16::try_from(icon)
                .map_err(|_| StoreError::new(format!("chat icon {icon} is not a u16")))?,
            text: body,
            flags: LineFlags::from_bits(
                u16::try_from(flags)
                    .map_err(|_| StoreError::new(format!("chat flags {flags} are not a u16")))?,
            ),
            at: from_unix(at),
            media,
        })
    })())
}

fn collect_history(
    rows: impl Iterator<Item = rusqlite::Result<Result<LogLine, StoreError>>>,
) -> Result<Vec<LogLine>, StoreError> {
    rows.map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
        .collect()
}

impl ChatLog for SqliteStore {
    fn append(&self, line: &NewLine) -> Result<LineId, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO chat_line
               (channel, nick, login, login_fp, icon, flags, body, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                i64::from(line.channel),
                line.from_nick,
                line.from_login,
                line.from_fingerprint.as_ref().map(fp_hex),
                i64::from(line.icon),
                i64::from(line.flags.bits()),
                line.text,
                unix(line.at),
            ],
        )
        .map_err(StoreError::new)?;
        LineId::try_from(conn.last_insert_rowid())
            .map_err(|_| StoreError::new("SQLite issued a negative chat line id"))
    }

    fn query(&self, query: &HistoryQuery) -> Result<HistoryPage, StoreError> {
        let query = query.check()?;
        let conn = self.conn.lock().unwrap();
        let take = query.limit.saturating_add(1).min(i64::MAX as usize) as i64;
        let mut lines = if let Some(after) = query.after {
            let sql = if query.before.is_some() {
                format!(
                    "SELECT {HISTORY_COLUMNS} FROM chat_line
                      WHERE channel = ?1 AND id > ?2 AND id < ?3
                      ORDER BY id ASC LIMIT ?4"
                )
            } else {
                format!(
                    "SELECT {HISTORY_COLUMNS} FROM chat_line
                      WHERE channel = ?1 AND id > ?2 ORDER BY id ASC LIMIT ?3"
                )
            };
            let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
            let rows = match query.before {
                Some(before) => stmt
                    .query_map(
                        params![
                            i64::from(query.channel),
                            clamp_id(after),
                            clamp_id(before),
                            take
                        ],
                        history_row,
                    )
                    .map_err(StoreError::new)?,
                None => stmt
                    .query_map(
                        params![i64::from(query.channel), clamp_id(after), take],
                        history_row,
                    )
                    .map_err(StoreError::new)?,
            };
            collect_history(rows)?
        } else {
            let sql = if query.before.is_some() {
                format!(
                    "SELECT {HISTORY_COLUMNS} FROM chat_line
                      WHERE channel = ?1 AND id < ?2 ORDER BY id DESC LIMIT ?3"
                )
            } else {
                format!(
                    "SELECT {HISTORY_COLUMNS} FROM chat_line
                      WHERE channel = ?1 ORDER BY id DESC LIMIT ?2"
                )
            };
            let mut stmt = conn.prepare_cached(&sql).map_err(StoreError::new)?;
            let rows = match query.before {
                Some(before) => stmt
                    .query_map(
                        params![i64::from(query.channel), clamp_id(before), take],
                        history_row,
                    )
                    .map_err(StoreError::new)?,
                None => stmt
                    .query_map(params![i64::from(query.channel), take], history_row)
                    .map_err(StoreError::new)?,
            };
            let mut rows = collect_history(rows)?;
            rows.reverse();
            rows
        };
        let has_more = lines.len() > query.limit;
        if has_more {
            if query.after.is_some() {
                lines.truncate(query.limit);
            } else {
                lines.remove(0);
            }
        }
        Ok(HistoryPage { lines, has_more })
    }

    fn tombstone(&self, id: LineId, at: SystemTime) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE chat_line
                    SET nick = '', body = '', flags = flags | ?1, deleted_at = ?2
                  WHERE id = ?3",
                params![i64::from(LineFlags::DELETED.bits()), unix(at), clamp_id(id)],
            )
            .map_err(StoreError::new)?;
        Ok(changed != 0)
    }

    fn prune(
        &self,
        max_lines: usize,
        max_age: Option<Duration>,
        now: SystemTime,
    ) -> Result<usize, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(StoreError::new)?;
        let mut gone = 0;
        if let Some(age) = max_age {
            gone += tx
                .execute(
                    "DELETE FROM chat_line WHERE at < ?1",
                    params![cutoff(now, age)],
                )
                .map_err(StoreError::new)?;
        }
        if max_lines > 0 {
            gone += tx
                .execute(
                    "DELETE FROM chat_line WHERE id IN (
                       SELECT id FROM chat_line ORDER BY id DESC LIMIT -1 OFFSET ?1
                     )",
                    params![max_lines.min(i64::MAX as usize) as i64],
                )
                .map_err(StoreError::new)?;
        }
        tx.commit().map_err(StoreError::new)?;
        Ok(gone)
    }

    fn attach_media(&self, id: LineId, media: &MediaMeta) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = conn
            .execute(
                "UPDATE chat_line SET media_id = ?1, media_type = ?2,
                                      media_w = ?3, media_h = ?4, media_bytes = ?5
                  WHERE id = ?6",
                params![
                    media.id,
                    media.mime,
                    i64::from(media.width),
                    i64::from(media.height),
                    i64::from(media.bytes),
                    clamp_id(id),
                ],
            )
            .map_err(StoreError::new)?;
        if changed == 0 {
            return Err(StoreError::new("no such chat line"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hxd_core::inbox::conformance;

    #[test]
    fn passes_the_conformance_suite() {
        conformance::run(&|| Box::new(SqliteStore::in_memory().unwrap()));
    }

    #[test]
    fn chat_log_passes_the_conformance_suite() {
        hxd_core::history::conformance::run(&|| Box::new(SqliteStore::in_memory().unwrap()));
    }

    #[test]
    fn news_passes_the_conformance_suite() {
        hxd_core::news::conformance::run(&|| Box::new(SqliteStore::in_memory().unwrap()));
    }

    #[test]
    fn the_article_table_is_ready_for_its_search_index() {
        // The index is the search stage's, and this is its precondition:
        // an external-content FTS5 table reads `subject`, `search_body`
        // and `author` from `news_article` by name, so they must exist,
        // hold the right text, and serve a snippet — on the bundled
        // SQLite this crate actually ships.
        use hxd_core::news::{Author, BodyType, NewNode, NewPost, NewsStore, NodeKind};
        let store = SqliteStore::in_memory().unwrap();
        let cat = store
            .create_node(
                &NewNode {
                    parent: None,
                    kind: NodeKind::Category,
                    name: "General".into(),
                    guid: [0; 16],
                    at: UNIX_EPOCH,
                },
                16,
            )
            .unwrap();
        let post = |body: &str, nick: &str, login: Option<&str>| {
            store
                .post(
                    &NewPost {
                        category: cat.id,
                        parent: None,
                        author: Author {
                            nick: nick.into(),
                            login: login.map(str::to_string),
                            fingerprint: None,
                        },
                        subject: "Attachment sizes".into(),
                        body: body.into(),
                        mime: BodyType::Plain,
                        refs: Vec::new(),
                        at: UNIX_EPOCH,
                    },
                    32,
                    32,
                )
                .unwrap()
                .id
        };
        let id = post("the derivative is a u16", "Alice", Some("alice"));
        let guest = post("a guest says the same derivative", "guest", None);

        let conn = store.conn.lock().unwrap();
        let computed = |id: u32| -> (String, String) {
            conn.query_row(
                "SELECT author, search_body FROM news_article WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        };
        assert_eq!(
            computed(id),
            ("Alice alice".into(), "the derivative is a u16".into())
        );
        assert_eq!(computed(guest).0, "guest ");

        // The downgrade stands in for the body where there is one, and
        // attachment names follow it on their own line.
        conn.execute(
            "UPDATE news_article SET plain = 'the plain text', attach_names = 'crash.png'
              WHERE id = ?1",
            [id],
        )
        .unwrap();
        assert_eq!(computed(id).1, "the plain text\ncrash.png");
        conn.execute(
            "UPDATE news_article SET plain = NULL, attach_names = NULL WHERE id = ?1",
            [id],
        )
        .unwrap();

        // Built as §6.1 has the search stage build it, secure-delete
        // included, so the tombstone below overwrites what it removes.
        conn.execute_batch(
            "CREATE VIRTUAL TABLE fts USING fts5(
               subject, search_body, author,
               content = 'news_article', content_rowid = 'id',
               tokenize = 'unicode61 remove_diacritics 2');
             INSERT INTO fts(fts, rank) VALUES ('secure-delete', 1);
             INSERT INTO fts(fts) VALUES ('rebuild');",
        )
        .unwrap();
        let hits: Vec<(u32, String)> = conn
            .prepare("SELECT rowid, snippet(fts, 1, '[', ']', '…', 8) FROM fts WHERE fts MATCH ?1")
            .unwrap()
            .query_map(["derivative AND author:alice"], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(hits, [(id, "the [derivative] is a u16".to_string())]);

        // A tombstone leaves the index with the values it was indexed
        // under, read off the row itself before the row is blanked.
        conn.execute(
            "INSERT INTO fts (fts, rowid, subject, search_body, author)
             SELECT 'delete', id, subject, search_body, author FROM news_article WHERE id = ?1",
            [id],
        )
        .unwrap();
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM fts WHERE fts MATCH 'derivative'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 1, "only the guest's article still matches");
    }

    #[test]
    fn version_two_migrates_without_losing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute_batch(SCHEMA_V2).unwrap();
            conn.execute(
                "INSERT INTO message (recipient, sender_nick, body, sent_at)
                 VALUES ('dave', 'alice', 'before news', 1)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chat_line (nick, body, at) VALUES ('alice', 'a line', 1)",
                [],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 2).unwrap();
        }
        let store = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        assert_eq!(
            store.pending(&Mailbox::login("dave"), 10).unwrap()[0].body,
            "before news"
        );
        let page = store
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.lines[0].text, "a line");
        use hxd_core::news::NewsStore;
        assert!(store.nodes(None).unwrap().is_empty(), "news starts empty");
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn a_reopened_database_still_has_the_mail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        let dave = Mailbox::identified("dave", [7u8; 32]);
        {
            let s = SqliteStore::open(&path, Synchronous::Full).unwrap();
            s.push(
                &NewMessage {
                    recipient: dave.clone(),
                    sender: Some(Mailbox::login("alice")),
                    sender_nick: "alice".into(),
                    body: "still here?".into(),
                    sent_at: UNIX_EPOCH + Duration::from_secs(1),
                    guid: None,
                    kind: hxd_core::inbox::MessageKind::Message,
                    media: None,
                },
                100,
            )
            .unwrap();
            s.set_blocked(&dave, &Mailbox::login("spammer"), true, SystemTime::now())
                .unwrap();
        }
        let s = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        assert_eq!(s.pending(&dave, 10).unwrap()[0].body, "still here?");
        assert!(s.is_blocked(&dave, &Mailbox::login("spammer")).unwrap());
        // Reopening migrates to a no-op, rather than a second CREATE TABLE.
        assert_eq!(s.counts(&dave).unwrap().total, 1);
    }

    #[test]
    fn version_one_migrates_without_losing_inbox_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute(
                "INSERT INTO message
                   (recipient, sender_nick, body, sent_at)
                 VALUES ('dave', 'alice', 'before history', 1)",
                [],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
        }

        let store = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        let pending = store.pending(&Mailbox::login("dave"), 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].body, "before history");
        assert!(store
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap()
            .lines
            .is_empty());

        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        for table in ["chat_line", "moderation", "report", "media_block"] {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                                    WHERE type = 'table' AND name = ?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "schema v2 must reserve {table}");
        }
    }

    #[test]
    fn a_database_from_the_future_is_refused_rather_than_mangled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = SqliteStore::open(&path, Synchronous::Normal).unwrap_err();
        assert!(err.0.contains("newer hxd"), "{err}");
    }

    #[test]
    fn a_half_created_schema_is_not_left_behind() {
        // The tables and the `user_version` that declares them go in one
        // transaction. Apart, a crash between them left tables with
        // version 0 and the next open failed at CREATE TABLE.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        {
            let conn = Connection::open(&path).unwrap();
            // Exactly the state the old code could leave: the schema
            // present, the version not.
            conn.execute_batch(SCHEMA_V1).unwrap();
            let v: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, 0, "the version was never written");
        }
        let err = SqliteStore::open(&path, Synchronous::Normal).unwrap_err();
        assert!(
            err.0.contains("already exists"),
            "the recovery is the operator's, and the error has to say so: {err}"
        );
        // And a clean create really does declare its version.
        let fresh = dir.path().join("fresh.db");
        SqliteStore::open(&fresh, Synchronous::Normal).unwrap();
        let conn = Connection::open(&fresh).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn a_malformed_row_is_an_error_and_not_a_panic() {
        // These columns are written by this file alone, so anything
        // unreadable means a hand edit or damage — and guessing at a
        // mailbox key is how mail reaches the wrong person. What it must
        // never be is a panic inside `row()`, which runs under the
        // connection mutex and would poison it for every later call.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        let store = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        let dave = Mailbox::identified("dave", [7u8; 32]);
        store
            .push(
                &NewMessage {
                    recipient: dave.clone(),
                    sender: Some(Mailbox::login("alice")),
                    sender_nick: "alice".into(),
                    body: "hi".into(),
                    sent_at: UNIX_EPOCH + Duration::from_secs(1),
                    guid: None,
                    kind: MessageKind::Message,
                    media: None,
                },
                100,
            )
            .unwrap();
        {
            let conn = Connection::open(&path).unwrap();
            // 64 *bytes*, not 64 characters: the old code sliced by byte
            // index after a byte-length check, so this landed mid-char.
            let multibyte = format!("é{}", "a".repeat(62));
            assert_eq!(multibyte.len(), 64);
            // The *sender's* fingerprint, so the row is still selected by
            // the recipient's mailbox and `row()` has to read it.
            conn.execute("UPDATE message SET sender_fp = ?1", params![multibyte])
                .unwrap();
        }
        let store = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        let err = store.pending(&dave, 10).unwrap_err();
        assert!(err.0.contains("fingerprint"), "{err}");
        // The connection is still usable, which is the part that matters.
        assert_eq!(store.counts(&Mailbox::login("bob")).unwrap().total, 0);
        assert!(
            store.pending(&dave, 10).is_err(),
            "still an error, still not a panic"
        );
    }

    #[test]
    fn a_second_connection_sees_committed_writes_and_waits_its_turn() {
        // WAL, and the five-second busy timeout: a write should wait for
        // a concurrent one rather than failing somebody's send.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("messages.db");
        let a = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        let b = SqliteStore::open(&path, Synchronous::Normal).unwrap();
        let dave = Mailbox::login("dave");
        let write = |s: &SqliteStore, body: &str| {
            s.push(
                &NewMessage {
                    recipient: dave.clone(),
                    sender: Some(Mailbox::login("alice")),
                    sender_nick: "alice".into(),
                    body: body.into(),
                    sent_at: UNIX_EPOCH + Duration::from_secs(1),
                    guid: None,
                    kind: MessageKind::Message,
                    media: None,
                },
                100,
            )
            .unwrap()
        };
        write(&a, "from a");
        assert_eq!(
            b.counts(&dave).unwrap().total,
            1,
            "a committed write is visible to the other connection"
        );
        write(&b, "from b");
        assert_eq!(a.counts(&dave).unwrap().total, 2);
        // And the dedup constraint holds across connections, which is
        // what makes it a constraint rather than a convention.
        let mut m = NewMessage {
            recipient: dave.clone(),
            sender: Some(Mailbox::login("alice")),
            sender_nick: "alice".into(),
            body: "once".into(),
            sent_at: UNIX_EPOCH + Duration::from_secs(2),
            guid: MessageGuid::parse("11111111-2222-4333-8444-555555555555"),
            kind: MessageKind::Message,
            media: None,
        };
        assert!(matches!(a.push(&m, 100).unwrap(), Pushed::Stored(_)));
        m.body = "twice".into();
        assert!(
            matches!(b.push(&m, 100).unwrap(), Pushed::Existing(_)),
            "the retry is the same message from either connection"
        );
        assert_eq!(a.counts(&dave).unwrap().total, 3);
    }

    #[test]
    fn claim_survives_a_guid_the_bare_login_already_used() {
        // Unlink, retry with the same guid, relink. With the login beside
        // the fingerprint in the unique index, `(X, alice, …)` and
        // `(NULL, alice, …)` were distinct rows — and `claim`'s UPDATE
        // then hit the constraint, rolled its transaction back, and
        // stranded *every* one of alice's bare-login messages.
        let store = SqliteStore::in_memory().unwrap();
        let fp = [0x2bu8; 32];
        let g = MessageGuid::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap();
        let note = |to: &Mailbox, body: &str| NewMessage {
            recipient: to.clone(),
            sender: Some(Mailbox::login("bob")),
            sender_nick: "bob".into(),
            body: body.into(),
            sent_at: UNIX_EPOCH + Duration::from_secs(1),
            guid: Some(g.clone()),
            kind: MessageKind::Message,
            media: None,
        };
        // While alice was linked, then after she unlinked: same guid,
        // two mailboxes as far as the store is concerned.
        store
            .push(&note(&Mailbox::identified("alice", fp), "linked"), 100)
            .unwrap();
        store
            .push(&note(&Mailbox::login("alice"), "unlinked"), 100)
            .unwrap();
        // And ordinary bare-login mail alongside it, which is what the
        // old rollback stranded: the collision was one row, the damage
        // was all of them.
        let mut plain = note(&Mailbox::login("alice"), "ordinary");
        plain.guid = None;
        store.push(&plain, 100).unwrap();

        // She links again.
        let moved = store.claim("alice", &fp).unwrap();
        assert!(moved > 0, "the bare-login mail moved onto the fingerprint");
        let mine = store
            .pending(&Mailbox::identified("alice", fp), 10)
            .unwrap();
        let bodies: Vec<&str> = mine.iter().map(|m| m.body.as_str()).collect();
        assert_eq!(
            bodies,
            ["linked", "ordinary"],
            "the duplicate guid collapsed into the row already on the \
             fingerprint; everything else came across"
        );
        assert!(
            store
                .pending(&Mailbox::login("alice"), 10)
                .unwrap()
                .is_empty(),
            "and nothing was left stranded under the bare login"
        );
    }

    #[test]
    fn a_mac_roman_body_survives_the_round_trip() {
        // The legacy edge converts Mac Roman to UTF-8 before the domain
        // sees it, so what reaches the store is UTF-8 — including the
        // characters a 1.5 client can actually type.
        let store = SqliteStore::in_memory().unwrap();
        let dave = Mailbox::login("dave");
        let body = "café — naïve ½ ünïcøde ‰ Ω";
        store
            .push(
                &NewMessage {
                    recipient: dave.clone(),
                    sender: Some(Mailbox::login("alice")),
                    sender_nick: "älice".into(),
                    body: body.into(),
                    sent_at: UNIX_EPOCH + Duration::from_secs(1),
                    guid: None,
                    kind: MessageKind::Message,
                    media: None,
                },
                100,
            )
            .unwrap();
        let back = store.pending(&dave, 10).unwrap();
        assert_eq!(back[0].body, body);
        assert_eq!(back[0].sender_nick, "älice");
    }
}
