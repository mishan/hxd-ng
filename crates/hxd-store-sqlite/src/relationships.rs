//! The relationship store on SQLite (`docs/instant-messaging.md` §3),
//! schema version 28.
//!
//! A row is read into a [`Relationship`], changed and written back, in
//! one transaction, so the rules about what a row may hold
//! ([`Relationship::settle`], [`Relationship::absorb`]) are the domain
//! type's, the same ones the in-memory store keeps.

use std::time::SystemTime;

use hxd_core::inbox::{Mailbox, MessageGuid, Sent, StoreError};
use hxd_core::relationships::{
    AccountUpdate, Birthdate, Ignore, IgnoreMode, LedgerEntry, MessagingAccount, PendingOut,
    Profile, Recorded, Rekeyed, RelationId, Relationship, RelationshipStore, RequestKind,
    Requester, MAX_LANGUAGES,
};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row, TransactionBehavior};

use super::{bind, fp_hex, from_unix, mailbox, mailbox_sql, unix, SqliteStore};

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

const FRIENDSHIP: i64 = 1;
const APPROVAL: i64 = 2;

const COLUMNS: &str = "id, owner, owner_fp, other, other_fp, alias, blocked_at, friendship, \
                       approval, pending_at, pending_lapses, pending_delivered, pending_note, \
                       ignore_mode, ignore_until";

fn id_of(n: i64) -> Result<RelationId, StoreError> {
    RelationId::try_from(n).map_err(|_| StoreError(format!("relation id {n} is not an id")))
}

fn row(r: &Row<'_>) -> rusqlite::Result<Result<(i64, Relationship), StoreError>> {
    let id: i64 = r.get(0)?;
    let (owner, owner_fp): (String, Option<String>) = (r.get(1)?, r.get(2)?);
    let (other, other_fp): (String, Option<String>) = (r.get(3)?, r.get(4)?);
    let alias: Option<String> = r.get(5)?;
    let blocked_at: Option<i64> = r.get(6)?;
    let (friendship, approval): (Option<i64>, Option<i64>) = (r.get(7)?, r.get(8)?);
    let pending: (Option<i64>, Option<i64>, Option<bool>, Option<String>) =
        (r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?);
    let (mode, until): (Option<i64>, Option<i64>) = (r.get(13)?, r.get(14)?);
    Ok((|| {
        Ok((
            id,
            Relationship {
                owner: mailbox(owner, owner_fp)?,
                other: mailbox(other, other_fp)?,
                alias,
                blocked_at: blocked_at.map(from_unix),
                friendship: friendship.map(id_of).transpose()?,
                approval: approval.map(id_of).transpose()?,
                pending_out: match pending {
                    (None, None, None, None) => None,
                    (Some(sent), Some(lapses), Some(delivered), note) => Some(PendingOut {
                        sent_at: from_unix(sent),
                        lapses_at: from_unix(lapses),
                        delivered,
                        note,
                    }),
                    _ => return Err(StoreError::new("a pending request is half stored")),
                },
                ignore: match mode {
                    None => None,
                    Some(m) => Some(Ignore {
                        mode: IgnoreMode::from_i64(m)
                            .ok_or_else(|| StoreError(format!("unknown ignore mode {m}")))?,
                        until: until.map(from_unix),
                    }),
                },
            },
        ))
    })())
}

fn rows(
    conn: &Connection,
    sql_text: &str,
    binds: &[&dyn rusqlite::ToSql],
) -> Result<Vec<(i64, Relationship)>, StoreError> {
    let mut stmt = sql(conn.prepare_cached(sql_text))?;
    let found = sql(stmt.query_map(binds, row))?;
    found
        .map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
        .collect()
}

fn load_pair(
    conn: &Connection,
    owner: &Mailbox,
    other: &Mailbox,
) -> Result<Option<(i64, Relationship)>, StoreError> {
    let text = format!(
        "SELECT {COLUMNS} FROM relationship WHERE {} AND {}",
        mailbox_sql(owner, "owner", 1),
        mailbox_sql(other, "other", 2)
    );
    Ok(rows(conn, &text, &[&bind(owner), &bind(other)])?.pop())
}

fn load_id(conn: &Connection, id: i64) -> Result<Option<Relationship>, StoreError> {
    let text = format!("SELECT {COLUMNS} FROM relationship WHERE id = ?1");
    Ok(rows(conn, &text, &[&id])?.pop().map(|(_, r)| r))
}

/// Write a row back, or delete it if nothing is left in it.
fn write(conn: &Connection, id: Option<i64>, rel: &mut Relationship) -> Result<(), StoreError> {
    rel.settle();
    if rel.is_empty() {
        if let Some(id) = id {
            sql(conn.execute("DELETE FROM relationship WHERE id = ?1", params![id]))?;
        }
        return Ok(());
    }
    let p = rel.pending_out.as_ref();
    let values = params![
        rel.owner.login,
        rel.owner.fingerprint.as_ref().map(fp_hex),
        rel.other.login,
        rel.other.fingerprint.as_ref().map(fp_hex),
        rel.alias,
        rel.blocked_at.map(unix),
        rel.friendship.map(|n| n as i64),
        rel.approval.map(|n| n as i64),
        p.map(|p| unix(p.sent_at)),
        p.map(|p| unix(p.lapses_at)),
        p.map(|p| p.delivered),
        p.and_then(|p| p.note.as_ref()),
        rel.ignore.as_ref().map(|i| i.mode.as_i64()),
        rel.ignore.as_ref().and_then(|i| i.until).map(unix),
        id,
    ];
    sql(match id {
        Some(_) => conn.execute(
            "UPDATE relationship SET owner = ?1, owner_fp = ?2, other = ?3, other_fp = ?4,
                    alias = ?5, blocked_at = ?6, friendship = ?7, approval = ?8,
                    pending_at = ?9, pending_lapses = ?10, pending_delivered = ?11,
                    pending_note = ?12, ignore_mode = ?13, ignore_until = ?14
              WHERE id = ?15",
            values,
        ),
        None => conn.execute(
            "INSERT INTO relationship (owner, owner_fp, other, other_fp, alias, blocked_at,
                    friendship, approval, pending_at, pending_lapses, pending_delivered,
                    pending_note, ignore_mode, ignore_until)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            &values[..14],
        ),
    })?;
    Ok(())
}

fn mint(conn: &Connection, kind: i64, at: SystemTime) -> Result<RelationId, StoreError> {
    sql(conn.execute(
        "INSERT INTO relation (kind, made_at) VALUES (?1, ?2)",
        params![kind, unix(at)],
    ))?;
    id_of(conn.last_insert_rowid())
}

/// Drop the ids no row points at any more.
fn forget(conn: &Connection, ids: impl IntoIterator<Item = RelationId>) -> Result<(), StoreError> {
    for id in ids {
        sql(conn.execute(
            "DELETE FROM relation WHERE id = ?1
               AND NOT EXISTS (SELECT 1 FROM relationship WHERE friendship = ?1)
               AND NOT EXISTS (SELECT 1 FROM relationship WHERE approval = ?1)",
            params![id as i64],
        ))?;
    }
    Ok(())
}

/// A hold's match on its owner: either key.
fn loosely(col: &str, n: usize) -> String {
    format!("({col} = ?{n} OR {col}_fp = ?{})", n + 1)
}

fn loose_binds(m: &Mailbox) -> [Value; 2] {
    [
        Value::Text(m.login.clone()),
        m.fingerprint
            .as_ref()
            .map_or(Value::Null, |fp| Value::Text(fp_hex(fp))),
    ]
}

/// A hold's match on who is held, from `?n`.
fn held_sql(who: &Requester, n: usize) -> (String, Vec<Value>) {
    match who {
        Requester::Account(m) => (loosely("held", n), loose_binds(m).to_vec()),
        Requester::Address(a) => (format!("held_address = ?{n}"), vec![Value::Text(a.clone())]),
    }
}

/// A ledger entry's match on its sender, from `?n`.
fn sender_sql(who: &Requester, n: usize) -> (String, Value) {
    match who {
        Requester::Account(m) => (mailbox_sql(m, "sender", n), Value::Text(bind(m))),
        Requester::Address(a) => (
            format!("sender IS NULL AND address = ?{n}"),
            Value::Text(a.clone()),
        ),
    }
}

const LEDGER_COLUMNS: &str =
    "kind, sender, sender_fp, address, recipient, recipient_fp, guid, bytes, at";

fn ledger_row(r: &Row<'_>) -> rusqlite::Result<Result<LedgerEntry, StoreError>> {
    let kind: i64 = r.get(0)?;
    let (sender, sender_fp): (Option<String>, Option<String>) = (r.get(1)?, r.get(2)?);
    let address: Option<String> = r.get(3)?;
    let (recipient, recipient_fp): (String, Option<String>) = (r.get(4)?, r.get(5)?);
    let guid: Option<String> = r.get(6)?;
    let (bytes, at): (i64, i64) = (r.get(7)?, r.get(8)?);
    Ok((|| {
        Ok(LedgerEntry {
            kind: RequestKind::from_i64(kind)
                .ok_or_else(|| StoreError(format!("unknown request kind {kind}")))?,
            sender: sender.map(|s| mailbox(s, sender_fp)).transpose()?,
            address,
            recipient: mailbox(recipient, recipient_fp)?,
            guid: guid
                .map(|g| {
                    MessageGuid::parse(&g)
                        .ok_or_else(|| StoreError(format!("stored guid is malformed: {g:?}")))
                })
                .transpose()?,
            bytes: bytes.max(0) as u64,
            at: from_unix(at),
        })
    })())
}

const ACCOUNT_COLUMNS: &str = "id, status_text, discoverable, takes_requests, \
                               requests_opted_at, requests_dropped, nickname, first_name, \
                               last_name, email, gender, birth_year, birth_month, birth_day, \
                               country, postcode, language1, language2, language3";

fn load_account(
    conn: &Connection,
    of: &Mailbox,
) -> Result<Option<(i64, MessagingAccount, u64)>, StoreError> {
    let text = format!(
        "SELECT {ACCOUNT_COLUMNS} FROM messaging_account WHERE {}",
        mailbox_sql(of, "owner", 1)
    );
    sql(conn
        .query_row(&text, params![bind(of)], |r| {
            let languages: [Option<String>; MAX_LANGUAGES] = [r.get(16)?, r.get(17)?, r.get(18)?];
            Ok((
                r.get::<_, i64>(0)?,
                MessagingAccount {
                    status_text: r.get(1)?,
                    discoverable: r.get(2)?,
                    takes_requests: r.get(3)?,
                    requests_opted_at: r.get::<_, Option<i64>>(4)?.map(from_unix),
                    profile: Profile {
                        nickname: r.get(6)?,
                        first_name: r.get(7)?,
                        last_name: r.get(8)?,
                        email: r.get(9)?,
                        gender: r.get(10)?,
                        birthdate: Birthdate {
                            year: r.get(11)?,
                            month: r.get(12)?,
                            day: r.get(13)?,
                        },
                        country: r.get(14)?,
                        postcode: r.get(15)?,
                        languages: languages.into_iter().flatten().collect(),
                    },
                },
                r.get::<_, i64>(5)?.max(0) as u64,
            ))
        })
        .optional())
}

fn write_account(
    conn: &Connection,
    of: &Mailbox,
    id: Option<i64>,
    a: &MessagingAccount,
    dropped: u64,
) -> Result<(), StoreError> {
    let p = &a.profile;
    let lang = |i: usize| p.languages.get(i).cloned();
    let values = params![
        of.login,
        of.fingerprint.as_ref().map(fp_hex),
        a.status_text,
        a.discoverable,
        a.takes_requests,
        a.requests_opted_at.map(unix),
        dropped as i64,
        p.nickname,
        p.first_name,
        p.last_name,
        p.email,
        p.gender,
        p.birthdate.year,
        p.birthdate.month,
        p.birthdate.day,
        p.country,
        p.postcode,
        lang(0),
        lang(1),
        lang(2),
        id,
    ];
    sql(match id {
        Some(_) => conn.execute(
            "UPDATE messaging_account SET owner = ?1, owner_fp = ?2, status_text = ?3,
                    discoverable = ?4, takes_requests = ?5, requests_opted_at = ?6,
                    requests_dropped = ?7, nickname = ?8, first_name = ?9, last_name = ?10,
                    email = ?11, gender = ?12, birth_year = ?13, birth_month = ?14,
                    birth_day = ?15, country = ?16, postcode = ?17, language1 = ?18,
                    language2 = ?19, language3 = ?20
              WHERE id = ?21",
            values,
        ),
        None => conn.execute(
            "INSERT INTO messaging_account (owner, owner_fp, status_text, discoverable,
                    takes_requests, requests_opted_at, requests_dropped, nickname, first_name,
                    last_name, email, gender, birth_year, birth_month, birth_day, country,
                    postcode, language1, language2, language3)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20)",
            &values[..20],
        ),
    })?;
    Ok(())
}

/// How `claim` and `rotate` name what moves: a column of a row aliased
/// `r`, against the destination fingerprint `?1` and what is merged away,
/// `?2`.
type Moves = fn(&str, &str) -> String;

fn claim_moves(r: &str, col: &str) -> String {
    format!("({r}.{col}_fp IS NULL AND {r}.{col} = ?2)")
}

/// Never NULL, so `NOT` of it is never NULL either: a bare column on the
/// other side must not hide a row from the merge.
fn rotate_moves(r: &str, col: &str) -> String {
    format!("({r}.{col}_fp IS NOT NULL AND {r}.{col}_fp = ?2)")
}

impl SqliteStore {
    fn with_tx<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sql(conn.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let out = f(&tx)?;
        sql(tx.commit())?;
        Ok(out)
    }

    fn edit<T>(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        f: impl FnOnce(&mut Relationship) -> T,
    ) -> Result<T, StoreError> {
        self.with_tx(|tx| {
            let (id, mut rel) = match load_pair(tx, owner, other)? {
                Some((id, rel)) => (Some(id), rel),
                None => (None, Relationship::new(owner, other)),
            };
            let out = f(&mut rel);
            write(tx, id, &mut rel)?;
            Ok(out)
        })
    }

    fn account_edit<T>(
        &self,
        of: &Mailbox,
        f: impl FnOnce(&mut MessagingAccount, &mut u64) -> T,
    ) -> Result<T, StoreError> {
        self.with_tx(|tx| {
            let (id, mut a, mut dropped) = match load_account(tx, of)? {
                Some((id, a, d)) => (Some(id), a, d),
                None => (None, MessagingAccount::default(), 0),
            };
            let out = f(&mut a, &mut dropped);
            write_account(tx, of, id, &a, dropped)?;
            Ok(out)
        })
    }

    /// Fold the rows a re-key makes duplicates of into the rows already
    /// at the destination, then re-key everything else.
    fn rekey(&self, moves: Moves, to: &str, from: &str) -> Result<Rekeyed, StoreError> {
        self.with_tx(|tx| {
            let after = |r: &str, col: &str| {
                format!(
                    "CASE WHEN {} THEN ?1 ELSE IFNULL({r}.{col}_fp, {r}.{col}) END",
                    moves(r, col)
                )
            };
            let pairs: Vec<(i64, i64)> = {
                let text = format!(
                    "SELECT dup.id, kept.id FROM relationship AS dup
                       JOIN relationship AS kept
                         ON IFNULL(kept.owner_fp, kept.owner) = {}
                        AND IFNULL(kept.other_fp, kept.other) = {}
                        AND kept.id <> dup.id
                      WHERE ({} OR {}) AND NOT ({} OR {})",
                    after("dup", "owner"),
                    after("dup", "other"),
                    moves("dup", "owner"),
                    moves("dup", "other"),
                    moves("kept", "owner"),
                    moves("kept", "other"),
                );
                let mut stmt = sql(tx.prepare(&text))?;
                let found = sql(stmt.query_map(params![to, from], |r| Ok((r.get(0)?, r.get(1)?))))?;
                sql(found.collect())?
            };
            let mut merged = Vec::new();
            let mut n = 0;
            for (dup, kept) in pairs {
                let (Some(d), Some(mut k)) = (load_id(tx, dup)?, load_id(tx, kept)?) else {
                    continue;
                };
                sql(tx.execute("DELETE FROM relationship WHERE id = ?1", params![dup]))?;
                let lost = k.absorb(d);
                write(tx, Some(kept), &mut k)?;
                forget(tx, lost.iter().map(|(l, _)| *l))?;
                merged.extend(lost);
                n += 1;
            }
            sql(tx.execute(
                &format!(
                    "DELETE FROM messaging_account AS r WHERE {}
                       AND EXISTS (SELECT 1 FROM messaging_account WHERE owner_fp = ?1)",
                    moves("r", "owner")
                ),
                params![to, from],
            ))?;
            for (table, col) in [
                ("relationship", "owner"),
                ("relationship", "other"),
                ("request_hold", "owner"),
                ("request_hold", "held"),
                ("request_ledger", "sender"),
                ("request_ledger", "recipient"),
                ("messaging_account", "owner"),
            ] {
                n += sql(tx.execute(
                    &format!(
                        "UPDATE {table} AS r SET {col}_fp = ?1 WHERE {}",
                        moves("r", col)
                    ),
                    params![to, from],
                ))?;
            }
            merged.sort_unstable();
            merged.dedup();
            Ok(Rekeyed { moved: n, merged })
        })
    }
}

impl RelationshipStore for SqliteStore {
    fn relationship(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        now: SystemTime,
    ) -> Result<Option<Relationship>, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(load_pair(&conn, owner, other)?.and_then(|(_, r)| r.as_of(now)))
    }

    fn relationships(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let text = format!(
            "SELECT {COLUMNS} FROM relationship WHERE {} ORDER BY id",
            mailbox_sql(owner, "owner", 1)
        );
        Ok(rows(&conn, &text, &[&bind(owner)])?
            .into_iter()
            .filter_map(|(_, r)| r.as_of(now))
            .collect())
    }

    fn pending_in(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let text = format!(
            "SELECT {COLUMNS} FROM relationship
              WHERE {} AND pending_delivered AND pending_lapses > ?2
              ORDER BY pending_at, id",
            mailbox_sql(owner, "other", 1)
        );
        Ok(rows(&conn, &text, &[&bind(owner), &unix(now)])?
            .into_iter()
            .filter_map(|(_, r)| r.as_of(now))
            .collect())
    }

    fn roster_size(&self, owner: &Mailbox, now: SystemTime) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let text = format!(
            "SELECT COUNT(*) FROM relationship
              WHERE {} AND (blocked_at IS NOT NULL OR friendship IS NOT NULL
                    OR approval IS NOT NULL OR pending_lapses > ?2
                    OR (ignore_mode IS NOT NULL AND (ignore_until IS NULL OR ignore_until > ?2)))",
            mailbox_sql(owner, "owner", 1)
        );
        let n: i64 = sql(conn.query_row(&text, params![bind(owner), unix(now)], |r| r.get(0)))?;
        Ok(n.max(0) as usize)
    }

    fn set_alias(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        alias: Option<&str>,
    ) -> Result<(), StoreError> {
        self.edit(owner, other, |r| r.alias = alias.map(str::to_owned))
    }

    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        self.edit(owner, other, |r| {
            r.blocked_at = if blocked {
                r.blocked_at.or(Some(at))
            } else {
                None
            }
        })
    }

    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let text = format!(
            "SELECT 1 FROM relationship WHERE {} AND {} AND blocked_at IS NOT NULL",
            mailbox_sql(owner, "owner", 1),
            mailbox_sql(other, "other", 2)
        );
        let found: Option<i64> = sql(conn
            .query_row(&text, params![bind(owner), bind(other)], |r| r.get(0))
            .optional())?;
        Ok(found.is_some())
    }

    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let text = format!(
            "SELECT other, other_fp FROM relationship
              WHERE {} AND blocked_at IS NOT NULL ORDER BY blocked_at, id",
            mailbox_sql(owner, "owner", 1)
        );
        let mut stmt = sql(conn.prepare_cached(&text))?;
        let found =
            sql(stmt.query_map(params![bind(owner)], |r| Ok(mailbox(r.get(0)?, r.get(1)?))))?;
        found
            .map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
            .collect()
    }

    fn set_pending_out(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        pending: Option<&PendingOut>,
    ) -> Result<(), StoreError> {
        self.edit(owner, other, |r| r.pending_out = pending.cloned())
    }

    fn set_ignore(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        ignore: Option<&Ignore>,
    ) -> Result<(), StoreError> {
        self.edit(owner, other, |r| r.ignore = ignore.cloned())
    }

    fn befriend(&self, a: &Mailbox, b: &Mailbox, at: SystemTime) -> Result<RelationId, StoreError> {
        self.with_tx(|tx| {
            let ab = load_pair(tx, a, b)?;
            let ba = load_pair(tx, b, a)?;
            let held = |x: &Option<(i64, Relationship)>| x.as_ref().and_then(|(_, r)| r.friendship);
            let (old_ab, old_ba) = (held(&ab), held(&ba));
            if let (Some(x), Some(y)) = (old_ab, old_ba) {
                if x == y {
                    return Ok(x);
                }
            }
            let id = mint(tx, FRIENDSHIP, at)?;
            let mut ended: Vec<RelationId> = old_ab.into_iter().chain(old_ba).collect();
            for (row, (x, y)) in [(ab, (a, b)), (ba, (b, a))] {
                let (rid, mut rel) = match row {
                    Some((rid, rel)) => (Some(rid), rel),
                    None => (None, Relationship::new(x, y)),
                };
                rel.friendship = Some(id);
                rel.pending_out = None;
                ended.extend(rel.approval.take());
                write(tx, rid, &mut rel)?;
            }
            forget(tx, ended)?;
            Ok(id)
        })
    }

    fn unfriend(&self, a: &Mailbox, b: &Mailbox) -> Result<Option<RelationId>, StoreError> {
        self.with_tx(|tx| {
            let mut ended = Vec::new();
            for (x, y) in [(a, b), (b, a)] {
                if let Some((rid, mut rel)) = load_pair(tx, x, y)? {
                    ended.extend(rel.friendship.take());
                    write(tx, Some(rid), &mut rel)?;
                }
            }
            forget(tx, ended.iter().copied())?;
            Ok(ended.first().copied())
        })
    }

    fn approve(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        at: SystemTime,
    ) -> Result<RelationId, StoreError> {
        self.with_tx(|tx| {
            let (rid, mut rel) = match load_pair(tx, owner, other)? {
                Some((rid, rel)) => (Some(rid), rel),
                None => (None, Relationship::new(owner, other)),
            };
            if let Some(id) = rel.approval {
                return Ok(id);
            }
            let id = mint(tx, APPROVAL, at)?;
            rel.approval = Some(id);
            write(tx, rid, &mut rel)?;
            Ok(id)
        })
    }

    fn end_approval(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
    ) -> Result<Option<RelationId>, StoreError> {
        self.with_tx(|tx| {
            let Some((rid, mut rel)) = load_pair(tx, owner, other)? else {
                return Ok(None);
            };
            let id = rel.approval.take();
            write(tx, Some(rid), &mut rel)?;
            forget(tx, id)?;
            Ok(id)
        })
    }

    fn hold(&self, owner: &Mailbox, held: &Requester, until: SystemTime) -> Result<(), StoreError> {
        let (login, fp, address) = match held {
            Requester::Account(m) => (Some(&m.login), m.fingerprint.as_ref().map(fp_hex), None),
            Requester::Address(a) => (None, None, Some(a)),
        };
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT INTO request_hold (owner, owner_fp, held, held_fp, held_address, until)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                owner.login,
                owner.fingerprint.as_ref().map(fp_hex),
                login,
                fp,
                address,
                unix(until)
            ],
        ))?;
        Ok(())
    }

    fn is_held(
        &self,
        owner: &Mailbox,
        sender: &Requester,
        now: SystemTime,
    ) -> Result<bool, StoreError> {
        let (held, held_binds) = held_sql(sender, 4);
        let text = format!(
            "SELECT 1 FROM request_hold WHERE until > ?1 AND {} AND {held} LIMIT 1",
            loosely("owner", 2)
        );
        let mut binds = vec![Value::Integer(unix(now))];
        binds.extend(loose_binds(owner));
        binds.extend(held_binds);
        let conn = self.conn.lock().unwrap();
        let found: Option<i64> = sql(conn
            .query_row(&text, params_from_iter(binds), |r| r.get(0))
            .optional())?;
        Ok(found.is_some())
    }

    fn record_request(&self, entry: &LedgerEntry) -> Result<Recorded, StoreError> {
        self.with_tx(|tx| {
            if let Some(guid) = entry.guid.as_ref() {
                let from = match &entry.sender {
                    Some(m) => Requester::Account(m.clone()),
                    None => Requester::Address(entry.address.clone().unwrap_or_default()),
                };
                let (sender, sender_bind) = sender_sql(&from, 3);
                let text = format!(
                    "SELECT {LEDGER_COLUMNS} FROM request_ledger
                      WHERE guid = ?1 AND {} AND {sender} ORDER BY id LIMIT 1",
                    mailbox_sql(&entry.recipient, "recipient", 2)
                );
                let found = sql(tx
                    .query_row(
                        &text,
                        params![guid.as_str(), bind(&entry.recipient), sender_bind],
                        ledger_row,
                    )
                    .optional())?;
                if let Some(e) = found {
                    return Ok(Recorded::Retry(Box::new(e?)));
                }
            }
            sql(tx.execute(
                "INSERT INTO request_ledger
                   (kind, sender, sender_fp, address, recipient, recipient_fp, guid, bytes, at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    entry.kind.as_i64(),
                    entry.sender.as_ref().map(|s| &s.login),
                    entry
                        .sender
                        .as_ref()
                        .and_then(|s| s.fingerprint.as_ref())
                        .map(fp_hex),
                    entry.address,
                    entry.recipient.login,
                    entry.recipient.fingerprint.as_ref().map(fp_hex),
                    entry.guid.as_ref().map(|g| g.as_str()),
                    entry.bytes as i64,
                    unix(entry.at),
                ],
            ))?;
            Ok(Recorded::New)
        })
    }

    fn find_request(
        &self,
        from: &Requester,
        to: Option<&Mailbox>,
        guid: &MessageGuid,
    ) -> Result<Option<LedgerEntry>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let (sender, sender_bind) = sender_sql(from, 3);
        let text = format!(
            "SELECT {LEDGER_COLUMNS} FROM request_ledger
              WHERE guid = ?1 AND {} AND {sender} ORDER BY id LIMIT 1",
            to.map_or_else(|| "?2 IS NULL".into(), |to| mailbox_sql(to, "recipient", 2))
        );
        sql(conn
            .query_row(
                &text,
                params![guid.as_str(), to.map(bind), sender_bind],
                ledger_row,
            )
            .optional())?
        .transpose()
    }

    fn requests_to(
        &self,
        from: &Requester,
        to: &Mailbox,
        kind: RequestKind,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let (sender, sender_bind) = sender_sql(from, 1);
        let text = format!(
            "SELECT COUNT(*) FROM request_ledger
              WHERE {sender} AND {} AND kind = ?3 AND at >= ?4",
            mailbox_sql(to, "recipient", 2)
        );
        let conn = self.conn.lock().unwrap();
        let n: i64 = sql(conn.query_row(
            &text,
            params![sender_bind, bind(to), kind.as_i64(), unix(since)],
            |r| r.get(0),
        ))?;
        Ok(n.max(0) as usize)
    }

    fn recipients_since(&self, from: &Requester, since: SystemTime) -> Result<usize, StoreError> {
        let (sender, sender_bind) = sender_sql(from, 1);
        let text = format!(
            "SELECT COUNT(DISTINCT IFNULL(recipient_fp, recipient)) FROM request_ledger
              WHERE {sender} AND at >= ?2"
        );
        let conn = self.conn.lock().unwrap();
        let n: i64 = sql(conn.query_row(&text, params![sender_bind, unix(since)], |r| r.get(0)))?;
        Ok(n.max(0) as usize)
    }

    fn recipients_from_address(
        &self,
        address: &str,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = sql(conn.query_row(
            "SELECT COUNT(DISTINCT IFNULL(recipient_fp, recipient)) FROM request_ledger
              WHERE address = ?1 AND at >= ?2",
            params![address, unix(since)],
            |r| r.get(0),
        ))?;
        Ok(n.max(0) as usize)
    }

    fn requested_since(&self, from: &Requester, since: SystemTime) -> Result<Sent, StoreError> {
        let (sender, sender_bind) = sender_sql(from, 1);
        let text = format!(
            "SELECT COUNT(*), IFNULL(SUM(bytes), 0) FROM request_ledger
              WHERE {sender} AND kind = ?3 AND at >= ?2"
        );
        let conn = self.conn.lock().unwrap();
        let (messages, bytes): (i64, i64) = sql(conn.query_row(
            &text,
            params![sender_bind, unix(since), RequestKind::Message.as_i64()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        Ok(Sent {
            messages: messages.max(0) as usize,
            bytes: bytes.max(0) as u64,
        })
    }

    fn request_dropped(&self, owner: &Mailbox) -> Result<(), StoreError> {
        self.account_edit(owner, |_, dropped| *dropped += 1)
    }

    fn requests_listed(&self, owner: &Mailbox) -> Result<u64, StoreError> {
        self.account_edit(owner, |_, dropped| std::mem::take(dropped))
    }

    fn account(&self, of: &Mailbox) -> Result<MessagingAccount, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(load_account(&conn, of)?
            .map(|(_, a, _)| a)
            .unwrap_or_default())
    }

    fn update_account(&self, of: &Mailbox, update: &AccountUpdate) -> Result<(), StoreError> {
        self.account_edit(of, |a, _| {
            if let Some(text) = &update.status_text {
                a.status_text = text.clone();
            }
            if let Some(on) = update.discoverable {
                a.discoverable = on;
            }
            if let Some(on) = update.takes_requests {
                a.takes_requests = on;
                if !on {
                    a.requests_opted_at = None;
                }
            }
            if let Some(at) = update.opted_at {
                a.requests_opted_at = Some(at);
            }
            if let Some(profile) = &update.profile {
                a.profile = profile.clone();
                a.profile.languages.truncate(MAX_LANGUAGES);
            }
        })
    }

    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<Rekeyed, StoreError> {
        self.rekey(claim_moves, &fp_hex(fingerprint), login)
    }

    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Rekeyed, StoreError> {
        self.rekey(rotate_moves, &fp_hex(to), &fp_hex(from))
    }

    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let (owner, other) = (mailbox_sql(of, "owner", 1), mailbox_sql(of, "other", 1));
        self.with_tx(|tx| {
            let ids: Vec<(Option<i64>, Option<i64>)> = {
                let mut stmt = sql(tx.prepare(&format!(
                    "SELECT friendship, approval FROM relationship WHERE ({owner}) OR ({other})"
                )))?;
                let found = sql(stmt.query_map(params![bind(of)], |r| Ok((r.get(0)?, r.get(1)?))))?;
                sql(found.collect())?
            };
            let mut n = 0;
            for (text, binds) in purges(of) {
                n += sql(tx.execute(&text, params_from_iter(binds)))?;
            }
            for col in ["owner", "held"] {
                sql(tx.execute(
                    &format!(
                        "UPDATE request_hold SET {col} = NULL
                          WHERE {col} = ?1 AND {col}_fp IS NOT NULL"
                    ),
                    params![of.login],
                ))?;
            }
            let ids: Vec<RelationId> = ids
                .into_iter()
                .flat_map(|(f, a)| [f, a])
                .flatten()
                .map(id_of)
                .collect::<Result<_, _>>()?;
            forget(tx, ids)?;
            Ok(n)
        })
    }

    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut n = 0;
        for (text, binds) in purges(of) {
            let count = text.replacen("DELETE FROM", "SELECT COUNT(*) FROM", 1);
            n += sql(conn.query_row(&count, params_from_iter(binds), |r| r.get::<_, i64>(0)))?
                .max(0) as usize;
        }
        Ok(n)
    }

    fn cleanup(
        &self,
        lapsed_before: SystemTime,
        ledger_before: SystemTime,
        batch: usize,
    ) -> Result<usize, StoreError> {
        let batch = i64::try_from(batch).unwrap_or(i64::MAX);
        let lapsed = unix(lapsed_before);
        self.with_tx(|tx| {
            let mut n = sql(tx.execute(
                "DELETE FROM request_hold WHERE id IN
                   (SELECT id FROM request_hold WHERE until <= ?1 LIMIT ?2)",
                params![lapsed, batch],
            ))?;
            let ids: Vec<i64> = {
                let mut stmt = sql(tx.prepare(
                    "SELECT id FROM relationship WHERE pending_lapses <= ?1
                     UNION SELECT id FROM relationship WHERE ignore_until <= ?1
                     ORDER BY id LIMIT ?2",
                ))?;
                let found = sql(stmt.query_map(params![lapsed, batch], |r| r.get(0)))?;
                sql(found.collect())?
            };
            for id in ids {
                match load_id(tx, id)?.and_then(|r| r.as_of(lapsed_before)) {
                    Some(mut rel) => write(tx, Some(id), &mut rel)?,
                    None => {
                        sql(tx.execute("DELETE FROM relationship WHERE id = ?1", params![id]))?;
                    }
                }
                n += 1;
            }
            n += sql(tx.execute(
                "DELETE FROM request_ledger WHERE id IN
                   (SELECT id FROM request_ledger WHERE at < ?1 LIMIT ?2)",
                params![unix(ledger_before), batch],
            ))?;
            Ok(n)
        })
    }
}

/// A hold's side that a purge of the mailbox bound to `?1` (its login)
/// and `?2` (its fingerprint, or NULL) takes: its fingerprint, or its
/// login with no fingerprint beside it.
fn purged(col: &str) -> String {
    format!("(({col}_fp IS NULL AND {col} = ?1) OR {col}_fp = ?2)")
}

/// What a purge deletes, each a statement over one table, so the dry run
/// counts exactly the same rows.
fn purges(of: &Mailbox) -> Vec<(String, Vec<Value>)> {
    let key = || vec![Value::Text(bind(of))];
    let loose = loose_binds(of).to_vec();
    vec![
        (
            format!(
                "DELETE FROM relationship WHERE ({}) OR ({})",
                mailbox_sql(of, "owner", 1),
                mailbox_sql(of, "other", 1)
            ),
            key(),
        ),
        (
            format!(
                "DELETE FROM request_hold WHERE {} OR {}",
                purged("owner"),
                purged("held")
            ),
            loose,
        ),
        (
            format!(
                "DELETE FROM request_ledger WHERE ({}) OR ({})",
                mailbox_sql(of, "recipient", 1),
                mailbox_sql(of, "sender", 1)
            ),
            key(),
        ),
        (
            format!(
                "DELETE FROM messaging_account WHERE {}",
                mailbox_sql(of, "owner", 1)
            ),
            key(),
        ),
    ]
}
