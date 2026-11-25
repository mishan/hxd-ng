//! The relationship store on SQLite (`docs/instant-messaging.md` §3),
//! schema version 28, and the portable friendships of version 30.
//!
//! A row is read into a [`Relationship`], changed and written back, in
//! one transaction, so the rules about what a row may hold
//! ([`Relationship::settle`], [`Relationship::absorb`]) are the domain
//! type's, the same ones the in-memory store keeps.

use std::time::SystemTime;

use hxd_core::inbox::{Mailbox, MessageGuid, Sent, StoreError};
use hxd_core::relationships::{
    AccountUpdate, Birthdate, Cause, Charge, Did, Ended, EndedEdge, Ending, FpPair, HeldWithdrawal,
    Ignore, IgnoreMode, LedgerEntry, Left, MessagingAccount, Owed, OwedId, Part, PendingOut,
    Presentation, Profile, Recorded, Rekeyed, RelationId, Relationship, RelationshipStore, Report,
    RequestKind, Requester, RotationRecord, StoredOffer, Work, MAX_LANGUAGES,
};
use rusqlite::types::Value;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row, TransactionBehavior};

use super::{bind, fp_from_hex, fp_hex, from_unix, mailbox, mailbox_sql, unix, SqliteStore};

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

const FRIENDSHIP: i64 = 1;
const APPROVAL: i64 = 2;

const COLUMNS: &str = "id, owner, owner_fp, other, other_fp, alias, blocked_at, friendship, \
                       approval, pending_at, pending_lapses, pending_delivered, pending_note, \
                       ignore_mode, ignore_until, pending_offer, pending_offer_lapses, \
                       pending_upgrade";

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
    let offer: (Option<Vec<u8>>, Option<i64>) = (r.get(15)?, r.get(16)?);
    let upgrade: bool = r.get(17)?;
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
                        offer: match offer {
                            (Some(offer), Some(lapses)) => Some(StoredOffer {
                                offer,
                                lapses_at: from_unix(lapses),
                            }),
                            _ => None,
                        },
                        upgrade,
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
        p.and_then(|p| p.offer.as_ref()).map(|o| &o.offer),
        p.and_then(|p| p.offer.as_ref()).map(|o| unix(o.lapses_at)),
        p.is_some_and(|p| p.upgrade),
        id,
    ];
    sql(match id {
        Some(_) => conn.execute(
            "UPDATE relationship SET owner = ?1, owner_fp = ?2, other = ?3, other_fp = ?4,
                    alias = ?5, blocked_at = ?6, friendship = ?7, approval = ?8,
                    pending_at = ?9, pending_lapses = ?10, pending_delivered = ?11,
                    pending_note = ?12, ignore_mode = ?13, ignore_until = ?14,
                    pending_offer = ?15, pending_offer_lapses = ?16, pending_upgrade = ?17
              WHERE id = ?18",
            values,
        ),
        None => conn.execute(
            "INSERT INTO relationship (owner, owner_fp, other, other_fp, alias, blocked_at,
                    friendship, approval, pending_at, pending_lapses, pending_delivered,
                    pending_note, ignore_mode, ignore_until, pending_offer,
                    pending_offer_lapses, pending_upgrade)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17)",
            &values[..17],
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
        Requester::Identity(fp) => (format!("held_fp = ?{n}"), vec![Value::Text(fp_hex(fp))]),
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
        Requester::Identity(fp) => (format!("sender_fp = ?{n}"), Value::Text(fp_hex(fp))),
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
                               country, postcode, language1, language2, language3, shown_text";

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
                    shown_text: r.get(19)?,
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
        a.shown_text,
        id,
    ];
    sql(match id {
        Some(_) => conn.execute(
            "UPDATE messaging_account SET owner = ?1, owner_fp = ?2, status_text = ?3,
                    discoverable = ?4, takes_requests = ?5, requests_opted_at = ?6,
                    requests_dropped = ?7, nickname = ?8, first_name = ?9, last_name = ?10,
                    email = ?11, gender = ?12, birth_year = ?13, birth_month = ?14,
                    birth_day = ?15, country = ?16, postcode = ?17, language1 = ?18,
                    language2 = ?19, language3 = ?20, shown_text = ?21
              WHERE id = ?22",
            values,
        ),
        None => conn.execute(
            "INSERT INTO messaging_account (owner, owner_fp, status_text, discoverable,
                    takes_requests, requests_opted_at, requests_dropped, nickname, first_name,
                    last_name, email, gender, birth_year, birth_month, birth_day, country,
                    postcode, language1, language2, language3, shown_text)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20, ?21)",
            &values[..21],
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

/// Every mailbox column a re-key stamps, by its table.
const REKEYED: [(&str, &str); 7] = [
    ("relationship", "owner"),
    ("relationship", "other"),
    ("request_hold", "owner"),
    ("request_hold", "held"),
    ("request_ledger", "sender"),
    ("request_ledger", "recipient"),
    ("messaging_account", "owner"),
];

const PRESENTATION_COLUMNS: &str =
    "presenter, other, name_mine, name_other, pair, hash, friendship, device, edge, at, taken, reset";

fn bytes32(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::new("a stored key is not 32 bytes"))
}

fn presentation_row(r: &Row<'_>) -> rusqlite::Result<Result<Presentation, StoreError>> {
    let (presenter, other): (String, String) = (r.get(0)?, r.get(1)?);
    let names: (Vec<u8>, Vec<u8>) = (r.get(2)?, r.get(3)?);
    let (pair, hash): (Vec<u8>, Vec<u8>) = (r.get(4)?, r.get(5)?);
    let friendship: Option<Vec<u8>> = r.get(6)?;
    let device: Vec<u8> = r.get(7)?;
    let edge: Option<i64> = r.get(8)?;
    let at: i64 = r.get(9)?;
    let taken: i64 = r.get(10)?;
    let reset: Option<Vec<u8>> = r.get(11)?;
    Ok((|| {
        Ok(Presentation {
            presenter: fp_from_hex(&presenter)?,
            other: fp_from_hex(&other)?,
            names: [bytes32(names.0)?, bytes32(names.1)?],
            pair: bytes32(pair)?,
            hash: bytes32(hash)?,
            friendship,
            reset,
            device: bytes32(device)?,
            edge: edge.map(id_of).transpose()?,
            at: from_unix(at),
            taken: from_unix(taken),
        })
    })())
}

/// [`RelationshipStore::present`] within `tx`.
fn present(tx: &Connection, p: &Presentation) -> Result<Option<Presentation>, StoreError> {
    let (presenter, other) = (fp_hex(&p.presenter), fp_hex(&p.other));
    let old =
        presentations_where(tx, "presenter = ?1 AND other = ?2", &[&presenter, &other])?.pop();
    if old
        .as_ref()
        .is_some_and(|o| o.reset.is_some() && o.reset != p.reset)
    {
        drop_upgrade(tx, &other, &presenter)?;
    }
    sql(tx.execute(
        "DELETE FROM friend_presentation WHERE presenter = ?1 AND other = ?2",
        params![presenter, other],
    ))?;
    sql(tx.execute(
        "INSERT INTO friend_presentation (presenter, other, name_mine, name_other, pair,
                    hash, friendship, device, edge, at, taken, reset)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            presenter,
            other,
            p.names[0].as_slice(),
            p.names[1].as_slice(),
            p.pair.as_slice(),
            p.hash.as_slice(),
            p.friendship,
            p.device.as_slice(),
            p.edge.map(|n| n as i64),
            unix(p.at),
            unix(p.taken),
            p.reset,
        ],
    ))?;
    Ok(old)
}

/// [`RelationshipStore::drop_presentations`] within `tx`.
fn drop_pair(
    tx: &Connection,
    a: &[u8; 32],
    b: &[u8; 32],
    presenters: &[[u8; 32]],
) -> Result<Ended, StoreError> {
    let (x, y) = (fp_hex(a), fp_hex(b));
    let had = evidence_both_ways(tx, &x, &y)?;
    let gone = unpresent_pair(tx, &x, &y, presenters)?;
    let mut ended = None;
    if had && !evidence_both_ways(tx, &x, &y)? {
        ended = end_edge(
            tx,
            &Mailbox::identified("", *a),
            &Mailbox::identified("", *b),
        )?;
        if let Some(e) = &ended {
            set_edge(tx, &x, &y, Some(e.id))?;
        }
    }
    Ok(Ended { gone, ended })
}

/// Rows `clause` names left holding nothing, gone.
fn reclaim(
    tx: &Connection,
    clause: &str,
    binds: &[&dyn rusqlite::ToSql],
) -> Result<(), StoreError> {
    sql(tx.execute(
        &format!(
            "DELETE FROM relationship
              WHERE ({clause}) AND blocked_at IS NULL AND friendship IS NULL
                AND approval IS NULL AND pending_at IS NULL AND ignore_mode IS NULL"
        ),
        binds,
    ))?;
    Ok(())
}

/// [`RelationshipStore::drop_offers`] for the offers whose upgrade rows
/// `upgrades` names and whose request rows `requests` does: an upgrade
/// offer with the pending out it showed its owner, a request's offer
/// alone.
fn drop_offers_where(
    tx: &Connection,
    upgrades: &str,
    requests: &str,
    binds: &[&dyn rusqlite::ToSql],
) -> Result<(), StoreError> {
    sql(tx.execute(&format!("DELETE FROM friend_offer WHERE {upgrades}"), binds))?;
    sql(tx.execute(
        &format!(
            "UPDATE relationship SET pending_at = NULL, pending_lapses = NULL,
                    pending_delivered = NULL, pending_note = NULL, pending_upgrade = 0
              WHERE ({requests}) AND pending_upgrade"
        ),
        binds,
    ))?;
    sql(tx.execute(
        &format!(
            "UPDATE relationship SET pending_offer = NULL, pending_offer_lapses = NULL
              WHERE {requests}"
        ),
        binds,
    ))?;
    reclaim(tx, requests, binds)
}

/// The friendships the pair `x`, `y`'s `Reset` records kept, gone, their
/// hashes left.
fn forget_resets(tx: &Connection, x: &str, y: &str) -> Result<(), StoreError> {
    sql(tx.execute(
        "UPDATE friend_presentation SET reset = NULL
          WHERE (presenter = ?1 AND other = ?2) OR (presenter = ?2 AND other = ?1)",
        params![x, y],
    ))?;
    Ok(())
}

fn presentations_where(
    conn: &Connection,
    clause: &str,
    binds: &[&dyn rusqlite::ToSql],
) -> Result<Vec<Presentation>, StoreError> {
    let text = format!(
        "SELECT {PRESENTATION_COLUMNS} FROM friend_presentation WHERE {clause} ORDER BY id"
    );
    let mut stmt = sql(conn.prepare_cached(&text))?;
    let found = sql(stmt.query_map(binds, presentation_row))?;
    found
        .map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
        .collect()
}

fn withdrawal_row(r: &Row<'_>) -> rusqlite::Result<Result<HeldWithdrawal, StoreError>> {
    let owner: String = r.get(0)?;
    let (pair, party): (Vec<u8>, Vec<u8>) = (r.get(1)?, r.get(2)?);
    let before: i64 = r.get(3)?;
    let withdrawal: Option<Vec<u8>> = r.get(4)?;
    let checked: bool = r.get(5)?;
    let at: i64 = r.get(6)?;
    Ok((|| {
        Ok(HeldWithdrawal {
            owner: fp_from_hex(&owner)?,
            pair: bytes32(pair)?,
            party: bytes32(party)?,
            before: before.max(0) as u64,
            withdrawal,
            checked,
            at: from_unix(at),
        })
    })())
}

/// The portable part of a rotation, as the in-memory store does it: what
/// moves onto a pair the successor already holds is dropped, and the edge
/// of each pair that loses its evidence both ways so, ended.
fn rotate_portable(
    tx: &Connection,
    from: &str,
    to: &str,
    rekeyed: &mut Rekeyed,
) -> Result<(), StoreError> {
    let mut n = 0;
    let moving = presentations_where(tx, "presenter = ?1 OR other = ?1", &[&from])?;
    let other = |p: &Presentation| {
        let (x, y) = (fp_hex(&p.presenter), fp_hex(&p.other));
        if x == from || x == to {
            y
        } else {
            x
        }
    };
    let mut had = Vec::new();
    for o in moving.iter().map(other) {
        if evidence_both_ways(tx, from, &o)? || evidence_both_ways(tx, to, &o)? {
            had.push(o);
        }
    }
    for (table, a, b) in [
        ("friend_presentation", "presenter", "other"),
        ("friend_offer", "owner", "other"),
    ] {
        n += sql(tx.execute(
            &format!(
                "DELETE FROM {table} AS r WHERE ({a} = ?2 OR {b} = ?2) AND EXISTS
                   (SELECT 1 FROM {table} AS k
                     WHERE k.{a} = CASE WHEN r.{a} = ?2 THEN ?1 ELSE r.{a} END
                       AND k.{b} = CASE WHEN r.{b} = ?2 THEN ?1 ELSE r.{b} END
                       AND k.{a} <> ?2 AND k.{b} <> ?2)"
            ),
            params![to, from],
        ))?;
        // Two moved onto one pair: the first kept, as in memory.
        for col in [a, b] {
            n += sql(tx.execute(
                &format!("UPDATE OR IGNORE {table} SET {col} = ?1 WHERE {col} = ?2"),
                params![to, from],
            ))?;
            sql(tx.execute(
                &format!("DELETE FROM {table} WHERE {col} = ?1"),
                params![from],
            ))?;
        }
    }
    let successor = fp_from_hex(to)?;
    for mut p in moving {
        for k in [&mut p.presenter, &mut p.other] {
            if fp_hex(k) == from {
                *k = successor;
            }
        }
        let now = presentations_where(
            tx,
            "presenter = ?1 AND other = ?2",
            &[&fp_hex(&p.presenter), &fp_hex(&p.other)],
        )?;
        if !now.contains(&p) {
            rekeyed.dropped.push(p);
        }
    }
    let mut ended: Vec<String> = Vec::new();
    for o in rekeyed.dropped.iter().map(other) {
        if ended.contains(&o) || !had.contains(&o) || evidence_both_ways(tx, to, &o)? {
            continue;
        }
        let (a, b) = (
            Mailbox::identified("", successor),
            Mailbox::identified("", fp_from_hex(&o)?),
        );
        if let Some(e) = end_edge(tx, &a, &b)? {
            set_edge(tx, to, &o, Some(e.id))?;
            rekeyed.ended.push(e);
        }
        ended.push(o);
    }
    // Of a successor's withdrawal and a moved one for the same pair,
    // party and kind, the later cutoff stands, with its object.
    for (kept, gone, wins) in [("?2", "?1", ">="), ("?1", "?2", ">")] {
        sql(tx.execute(
            &format!(
                "DELETE FROM friend_withdrawal AS g WHERE g.owner = {gone} AND EXISTS
                   (SELECT 1 FROM friend_withdrawal AS k
                     WHERE k.owner = {kept} AND k.pair = g.pair AND k.party = g.party
                       AND k.own = g.own AND k.before {wins} g.before)"
            ),
            params![to, from],
        ))?;
    }
    n += sql(tx.execute(
        "UPDATE friend_withdrawal SET owner = ?1 WHERE owner = ?2",
        params![to, from],
    ))?;
    rekeyed.moved += n;
    Ok(())
}

fn hold(
    conn: &Connection,
    owner: &Mailbox,
    held: &Requester,
    until: SystemTime,
) -> Result<(), StoreError> {
    let (login, fp, address) = match held {
        Requester::Account(m) => (Some(&m.login), m.fingerprint.as_ref().map(fp_hex), None),
        Requester::Address(a) => (None, None, Some(a)),
        Requester::Identity(fp) => (None, Some(fp_hex(fp)), None),
    };
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

fn keep_withdrawal(tx: &Connection, w: &HeldWithdrawal, cap: usize) -> Result<(), StoreError> {
    let owner = fp_hex(&w.owner);
    let cap = i64::try_from(cap).unwrap_or(i64::MAX);
    // A replacement is a new row, so that it is the owner's newest, as
    // the cap reads them; one whose cutoff is older is refused by the key.
    sql(tx.execute(
        "DELETE FROM friend_withdrawal
          WHERE owner = ?1 AND pair = ?2 AND party = ?3 AND own = ?4 AND before <= ?5",
        params![
            owner,
            w.pair.as_slice(),
            w.party.as_slice(),
            w.withdrawal.is_none(),
            w.before as i64,
        ],
    ))?;
    sql(tx.execute(
        "INSERT OR IGNORE INTO friend_withdrawal
                (owner, pair, party, before, withdrawal, own, checked, at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            owner,
            w.pair.as_slice(),
            w.party.as_slice(),
            w.before as i64,
            w.withdrawal,
            w.withdrawal.is_none(),
            w.checked,
            unix(w.at),
        ],
    ))?;
    sql(tx.execute(
        "DELETE FROM friend_withdrawal WHERE id IN
           (SELECT id FROM friend_withdrawal WHERE owner = ?1
             ORDER BY withdrawal IS NULL, at, id
             LIMIT MAX(0, (SELECT COUNT(*) FROM friend_withdrawal WHERE owner = ?1) - ?2))",
        params![owner, cap],
    ))?;
    Ok(())
}

/// The presentations of the pair `a`, `b`, either way.
const PAIR: &str = "(presenter = ?1 AND other = ?2) OR (presenter = ?2 AND other = ?1)";

fn evidence_both_ways(tx: &Connection, a: &str, b: &str) -> Result<bool, StoreError> {
    let held = presentations_where(tx, PAIR, &[&a, &b])?;
    Ok([(a, b), (b, a)].into_iter().all(|(p, q)| {
        held.iter()
            .any(|x| fp_hex(&x.presenter) == p && fp_hex(&x.other) == q && x.evidence())
    }))
}

fn unpresent_pair(
    tx: &Connection,
    a: &str,
    b: &str,
    presenters: &[[u8; 32]],
) -> Result<Vec<Presentation>, StoreError> {
    let mut gone = Vec::new();
    for presenter in presenters.iter().map(fp_hex) {
        let other = if presenter == a {
            b
        } else if presenter == b {
            a
        } else {
            continue;
        };
        let clause = "presenter = ?1 AND other = ?2";
        let was = presentations_where(tx, clause, &[&presenter, &other])?;
        sql(tx.execute(
            "DELETE FROM friend_presentation WHERE presenter = ?1 AND other = ?2",
            params![presenter, other],
        ))?;
        if was.iter().any(|p| p.reset.is_some()) {
            drop_upgrade(tx, other, &presenter)?;
        }
        gone.extend(was);
    }
    Ok(gone)
}

fn end_friendship(
    tx: &Connection,
    a: &Mailbox,
    b: &Mailbox,
    end: &Ending,
) -> Result<Ended, StoreError> {
    assert!(
        end.withdrawals.is_empty() || end.cap > 0,
        "a cap to keep under"
    );
    let fps = a
        .fingerprint
        .zip(b.fingerprint)
        .map(|(x, y)| (fp_hex(&x), fp_hex(&y)));

    for w in &end.withdrawals {
        keep_withdrawal(tx, w, end.cap)?;
    }
    let mut gone = Vec::new();
    if let Some((x, y)) = &fps {
        gone = unpresent_pair(tx, x, y, &end.presentations)?;
        for (o, t) in [(x, y), (y, x)] {
            let named = end.offers.iter().any(|f| fp_hex(f) == *o);
            if named || end.block.is_some() {
                drop_offers_where(
                    tx,
                    "owner = ?1 AND other = ?2",
                    "owner_fp = ?1 AND other_fp = ?2",
                    &[o, t],
                )?;
            }
        }
        if end.block.is_some() {
            forget_resets(tx, x, y)?;
        }
    }
    if end.pending {
        if let Some((rid, mut rel)) = load_pair(tx, b, a)? {
            rel.pending_out = None;
            write(tx, Some(rid), &mut rel)?;
        }
        if let Some((x, y)) = &fps {
            sql(tx.execute(
                "DELETE FROM friend_offer WHERE owner = ?1 AND other = ?2",
                params![y, x],
            ))?;
        }
    }
    if let Some(at) = end.block {
        let (rid, mut rel) = match load_pair(tx, a, b)? {
            Some((rid, rel)) => (Some(rid), rel),
            None => (None, Relationship::new(a, b)),
        };
        rel.blocked_at = rel.blocked_at.or(Some(at));
        write(tx, rid, &mut rel)?;
        let mut lost = Vec::new();
        for (x, y) in [(a, b), (b, a)] {
            if let Some((rid, mut rel)) = load_pair(tx, x, y)? {
                rel.pending_out = None;
                lost.extend(rel.approval.take());
                write(tx, Some(rid), &mut rel)?;
            }
        }
        forget(tx, lost)?;
    }
    let ended = if end.friendship {
        end_edge(tx, a, b)?
    } else {
        None
    };
    if let Some(e) = &ended {
        if let Some((x, y)) = &fps {
            set_edge(tx, x, y, None)?;
        }
        if let Some(until) = end.hold {
            let held = Requester::Account(e.parties[1].clone());
            hold(tx, &e.parties[0], &held, until)?;
        }
    }
    if let Some(until) = end.declined {
        hold(tx, a, &Requester::Account(b.clone()), until)?;
    }
    Ok(Ended { gone, ended })
}

fn set_offer(
    conn: &Connection,
    owner: &[u8; 32],
    other: &[u8; 32],
    offer: Option<&StoredOffer>,
) -> Result<(), StoreError> {
    let (owner, other) = (fp_hex(owner), fp_hex(other));
    sql(match offer {
        Some(o) => conn.execute(
            "INSERT OR REPLACE INTO friend_offer (owner, other, offer, lapses)
             VALUES (?1, ?2, ?3, ?4)",
            params![owner, other, o.offer, unix(o.lapses_at)],
        ),
        None => conn.execute(
            "DELETE FROM friend_offer WHERE owner = ?1 AND other = ?2",
            params![owner, other],
        ),
    })?;
    Ok(())
}

fn drop_offers(tx: &Connection, pairs: &[FpPair]) -> Result<(), StoreError> {
    for (x, y) in pairs {
        drop_offers_where(
            tx,
            "owner = ?1 AND other = ?2",
            "owner_fp = ?1 AND other_fp = ?2",
            &[&fp_hex(x), &fp_hex(y)],
        )?;
    }
    Ok(())
}

fn drop_offers_naming(tx: &Connection, fp: &[u8; 32]) -> Result<Vec<FpPair>, StoreError> {
    let f = fp_hex(fp);
    let mut stmt = sql(tx.prepare(
        "SELECT owner, other FROM friend_offer WHERE owner = ?1 OR other = ?1
             UNION SELECT owner_fp, other_fp FROM relationship
              WHERE (owner_fp = ?1 OR other_fp = ?1)
                AND (pending_offer IS NOT NULL OR pending_upgrade)",
    ))?;
    let found: Vec<(String, String)> =
        sql(sql(stmt.query_map(params![f], |r| Ok((r.get(0)?, r.get(1)?))))?.collect())?;
    drop(stmt);
    drop_offers_where(
        tx,
        "owner = ?1 OR other = ?1",
        "owner_fp = ?1 OR other_fp = ?1",
        &[&f],
    )?;
    found
        .iter()
        .map(|(o, t)| Ok((fp_from_hex(o)?, fp_from_hex(t)?)))
        .collect()
}

fn drop_withdrawal(
    conn: &Connection,
    owner: &[u8; 32],
    pair: &[u8; 32],
    party: &[u8; 32],
    withdrawal: &[u8],
) -> Result<(), StoreError> {
    sql(conn.execute(
        "DELETE FROM friend_withdrawal
          WHERE owner = ?1 AND pair = ?2 AND party = ?3 AND withdrawal = ?4",
        params![fp_hex(owner), pair.as_slice(), party.as_slice(), withdrawal],
    ))?;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn answer_reset(
    tx: &Connection,
    drops: &[([u8; 32], [u8; 32], Vec<[u8; 32]>)],
    record: Option<&Presentation>,
    upgrade: Option<(&Mailbox, &Mailbox)>,
) -> Result<(Vec<Ended>, Option<Presentation>), StoreError> {
    let mut ended = Vec::new();
    for (a, b, presenters) in drops {
        ended.push(drop_pair(tx, a, b, presenters)?);
    }
    let replaced = match record {
        Some(p) => present(tx, p)?,
        None => None,
    };
    let Some((owner, other)) = upgrade else {
        return Ok((ended, replaced));
    };
    let (Some((id, mut rel)), Some((x, y))) = (
        load_pair(tx, owner, other)?,
        owner.fingerprint.zip(other.fingerprint),
    ) else {
        return Ok((ended, replaced));
    };
    let Some(p) = rel.pending_out.as_mut() else {
        return Ok((ended, replaced));
    };
    let Some(o) = p.offer.take() else {
        return Ok((ended, replaced));
    };
    p.upgrade = true;
    let lapses = o.lapses_at.min(p.lapses_at);
    write(tx, Some(id), &mut rel)?;
    sql(tx.execute(
        "INSERT OR REPLACE INTO friend_offer (owner, other, offer, lapses)
             VALUES (?1, ?2, ?3, ?4)",
        params![fp_hex(&x), fp_hex(&y), o.offer, unix(lapses)],
    ))?;
    Ok((ended, replaced))
}

#[allow(clippy::type_complexity)]
fn present_befriending(
    tx: &Connection,
    a: &Mailbox,
    b: &Mailbox,
    rows: &[Presentation],
    friends: Option<Option<RelationId>>,
    at: SystemTime,
) -> Result<(Vec<Option<Presentation>>, Option<RelationId>), StoreError> {
    let replaced = rows
        .iter()
        .map(|p| present(tx, p))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some((x, y)) = a.fingerprint.zip(b.fingerprint) {
        sql(tx.execute(
            "DELETE FROM friend_offer
                  WHERE (owner = ?1 AND other = ?2) OR (owner = ?2 AND other = ?1)",
            params![fp_hex(&x), fp_hex(&y)],
        ))?;
    }
    let id = match friends {
        Some(Some(id)) => Some(refriend(tx, a, b, id, at).map(|()| id)?),
        Some(None) => Some(befriend(tx, a, b, at)?),
        None => None,
    };
    Ok((replaced, id))
}

fn befriend_dropping(
    tx: &Connection,
    a: &Mailbox,
    b: &Mailbox,
    at: SystemTime,
    id: Option<RelationId>,
    drop: &[[u8; 32]],
) -> Result<RelationId, StoreError> {
    if let Some((x, y)) = a.fingerprint.zip(b.fingerprint) {
        let (x, y) = (fp_hex(&x), fp_hex(&y));
        unpresent_pair(tx, &x, &y, drop)?;
        forget_resets(tx, &x, &y)?;
    }
    match id {
        Some(id) => refriend(tx, a, b, id, at).map(|()| id),
        None => befriend(tx, a, b, at),
    }
}

const OWED_COLUMNS: &str = "id, kind, key, other, device, cause, cause_a, cause_b";

/// A piece of work's columns, the id's aside: `(kind, key, other, device)`
/// and `(cause, cause_a, cause_b)`, a key that is absent `''`. The kind
/// and cause numbers are on disk: never reused, and one added comes with
/// a schema version, since a row this build cannot read fails the whole
/// record's read.
type OwedRow = ((i64, String, String, String), (i64, String, String));

fn owed_columns(work: &Work, cause: &Cause) -> OwedRow {
    let hex = fp_hex;
    let maybe = |k: &Option<[u8; 32]>| k.as_ref().map(fp_hex).unwrap_or_default();
    let none = String::new;
    let work = match work {
        Work::DropOffersBy { under, device } => (1, maybe(under), none(), hex(device)),
        Work::DropOffersNaming(k) => (2, hex(k), none(), none()),
        Work::DropPresentedBy { under, device } => (3, maybe(under), none(), hex(device)),
        Work::DropPresentationsOf(k) => (4, hex(k), none(), none()),
        Work::Judge(a, b) => (5, hex(a), hex(b), none()),
        Work::Settle(k) => (6, hex(k), none(), none()),
    };
    let cause = match cause {
        Cause::OperatorDevice(d) => (1, hex(d), none()),
        Cause::OperatorIdentity(i) => (2, hex(i), none()),
        Cause::PublishedDevice { identity, device } => (3, hex(identity), hex(device)),
        Cause::PublishedIdentity(i) => (4, hex(i), none()),
        Cause::Unlinked => (5, none(), none()),
        Cause::Always => (6, none(), none()),
    };
    (work, cause)
}

fn owed_from_columns(
    id: i64,
    ((kind, key, other, device), (cause, a, b)): OwedRow,
) -> Result<Owed, StoreError> {
    let maybe = |k: &str| (!k.is_empty()).then(|| fp_from_hex(k)).transpose();
    let work = match kind {
        1 => Work::DropOffersBy {
            under: maybe(&key)?,
            device: fp_from_hex(&device)?,
        },
        2 => Work::DropOffersNaming(fp_from_hex(&key)?),
        3 => Work::DropPresentedBy {
            under: maybe(&key)?,
            device: fp_from_hex(&device)?,
        },
        4 => Work::DropPresentationsOf(fp_from_hex(&key)?),
        5 => Work::Judge(fp_from_hex(&key)?, fp_from_hex(&other)?),
        6 => Work::Settle(fp_from_hex(&key)?),
        n => return Err(StoreError(format!("owed work of unknown kind {n}"))),
    };
    let cause = match cause {
        1 => Cause::OperatorDevice(fp_from_hex(&a)?),
        2 => Cause::OperatorIdentity(fp_from_hex(&a)?),
        3 => Cause::PublishedDevice {
            identity: fp_from_hex(&a)?,
            device: fp_from_hex(&b)?,
        },
        4 => Cause::PublishedIdentity(fp_from_hex(&a)?),
        5 => Cause::Unlinked,
        6 => Cause::Always,
        n => return Err(StoreError(format!("owed work of unknown cause {n}"))),
    };
    Ok(Owed {
        id: id as OwedId,
        work,
        cause,
    })
}

/// A row of [`OWED_COLUMNS`], as its columns.
fn owed_raw(r: &Row<'_>) -> rusqlite::Result<(i64, OwedRow)> {
    let work = (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
    Ok((r.get(0)?, (work, (r.get(5)?, r.get(6)?, r.get(7)?))))
}

fn owed_row(r: &Row<'_>) -> rusqlite::Result<Result<Owed, StoreError>> {
    let (id, row) = owed_raw(r)?;
    Ok(owed_from_columns(id, row))
}

/// The id of the row holding exactly these columns.
fn owed_id(
    tx: &Connection,
    ((kind, key, other, device), (cause, a, b)): &OwedRow,
) -> Result<Option<i64>, StoreError> {
    sql(tx
        .query_row(
            "SELECT id FROM friend_owed
              WHERE kind = ?1 AND key = ?2 AND other = ?3 AND device = ?4
                AND cause = ?5 AND cause_a = ?6 AND cause_b = ?7",
            params![kind, key, other, device, cause, a, b],
            |r| r.get(0),
        )
        .optional())
}

fn owe(tx: &Connection, work: &Work, cause: &Cause) -> Result<OwedId, StoreError> {
    let row = owed_columns(work, cause);
    if let Some(id) = owed_id(tx, &row)? {
        return Ok(id as OwedId);
    }
    let ((kind, key, other, device), (cause, a, b)) = row;
    sql(tx.execute(
        "INSERT INTO friend_owed (kind, key, other, device, cause, cause_a, cause_b)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![kind, key, other, device, cause, a, b],
    ))?;
    Ok(tx.last_insert_rowid() as OwedId)
}

fn settle(tx: &Connection, id: OwedId) -> Result<(), StoreError> {
    sql(tx.execute("DELETE FROM friend_owed WHERE id = ?1", params![id as i64]))?;
    Ok(())
}

/// A rotation's re-stamp of owed work's keys, in id order, never its
/// device's or its cause's: a piece that becomes one already owed is
/// folded into it.
fn restamp_owed(
    tx: &Connection,
    from: &str,
    to: &str,
) -> Result<Vec<(OwedId, OwedId)>, StoreError> {
    let moving: Vec<(i64, OwedRow)> = {
        let mut stmt = sql(tx.prepare(&format!(
            "SELECT {OWED_COLUMNS} FROM friend_owed WHERE key = ?1 OR other = ?1 ORDER BY id"
        )))?;
        let rows = sql(stmt.query_map(params![from], owed_raw))?;
        sql(rows.collect())?
    };
    let mut merged = Vec::new();
    for (id, mut row) in moving {
        for k in [&mut row.0 .1, &mut row.0 .2] {
            if k == from {
                *k = to.to_string();
            }
        }
        match owed_id(tx, &row)? {
            Some(kept) if kept != id => {
                settle(tx, id as OwedId)?;
                merged.push((id as OwedId, kept as OwedId));
            }
            _ => {
                sql(tx.execute(
                    "UPDATE friend_owed SET key = ?2, other = ?3 WHERE id = ?1",
                    params![id, row.0 .1, row.0 .2],
                ))?;
            }
        }
    }
    Ok(merged)
}

/// One part of a write, as its method does it.
fn part(tx: &Connection, part: &Part) -> Result<Did, StoreError> {
    #[allow(unreachable_patterns)]
    Ok(match part {
        Part::DropPresentations(a, b, presenters) => Did::Ended(drop_pair(tx, a, b, presenters)?),
        Part::EndFriendship(a, b, end) => Did::Ended(end_friendship(tx, a, b, end)?),
        Part::Present(p) => Did::Replaced(present(tx, p)?),
        Part::PresentBefriending {
            a,
            b,
            rows,
            befriend,
            at,
        } => {
            let (replaced, id) = present_befriending(tx, a, b, rows, *befriend, *at)?;
            Did::Befriended(replaced, id)
        }
        Part::AnswerReset {
            drops,
            record,
            upgrade,
        } => {
            let upgrade = upgrade.as_ref().map(|(o, t)| (o, t));
            let (ended, replaced) = answer_reset(tx, drops, record.as_ref(), upgrade)?;
            Did::Reset(ended, replaced)
        }
        Part::SetOffer(owner, other, offer) => {
            set_offer(tx, owner, other, offer.as_ref())?;
            Did::Nothing
        }
        Part::DropOffers(pairs) => {
            drop_offers(tx, pairs)?;
            Did::Nothing
        }
        Part::DropOffersNaming(fp) => Did::Named(drop_offers_naming(tx, fp)?),
        Part::BefriendDropping { a, b, at, id, drop } => {
            Did::Friends(befriend_dropping(tx, a, b, *at, *id, drop)?)
        }
        Part::KeepWithdrawal(w, cap) => {
            keep_withdrawal(tx, w, *cap)?;
            Did::Nothing
        }
        Part::DropWithdrawal(owner, pair, party, w) => {
            drop_withdrawal(tx, owner, pair, party, w)?;
            Did::Nothing
        }
        Part::SetAlias(owner, other, alias) => {
            edit_in(tx, owner, other, |r| r.alias = alias.clone())?;
            Did::Nothing
        }
        Part::SetBlocked(owner, other, blocked, at) => {
            edit_in(tx, owner, other, |r| {
                r.blocked_at = if *blocked {
                    r.blocked_at.or(Some(*at))
                } else {
                    None
                }
            })?;
            Did::Nothing
        }
        Part::SetPendingOut(owner, other, pending) => {
            edit_in(tx, owner, other, |r| r.pending_out = pending.clone())?;
            Did::Nothing
        }
        Part::Owe(work, cause) => Did::Owed(owe(tx, work, cause)?),
        Part::Settle(id) => {
            settle(tx, *id)?;
            Did::Nothing
        }
        _ if part.fails() => return Err(StoreError("a part of the write failed".into())),
        _ => unreachable!("every part is one of the above"),
    })
}

/// `owner`'s row about `other`, made where there is none, changed by `f`
/// and written in `tx`.
fn edit_in<T>(
    tx: &Connection,
    owner: &Mailbox,
    other: &Mailbox,
    f: impl FnOnce(&mut Relationship) -> T,
) -> Result<T, StoreError> {
    let (id, mut rel) = match load_pair(tx, owner, other)? {
        Some((id, rel)) => (Some(id), rel),
        None => (None, Relationship::new(owner, other)),
    };
    let out = f(&mut rel);
    write(tx, id, &mut rel)?;
    Ok(out)
}

/// What `report` asks of, as it stands in `conn`.
fn left(conn: &Connection, report: &Report) -> Result<Vec<Left>, StoreError> {
    let now = report.now;
    let mut out = Vec::new();
    for (a, b) in &report.pairs {
        let row = |x: &Mailbox, y: &Mailbox| -> Result<_, StoreError> {
            Ok(load_pair(conn, x, y)?.and_then(|(_, r)| r.as_of(now)))
        };
        let presentation = |x: &[u8; 32], y: &[u8; 32]| -> Result<_, StoreError> {
            Ok(presentations_where(
                conn,
                "presenter = ?1 AND other = ?2",
                &[&fp_hex(x), &fp_hex(y)],
            )?
            .pop())
        };
        let offer = |x: &[u8; 32], y: &[u8; 32]| -> Result<Option<StoredOffer>, StoreError> {
            sql(conn
                .query_row(
                    "SELECT offer, lapses FROM friend_offer
                      WHERE owner = ?1 AND other = ?2 AND lapses > ?3",
                    params![fp_hex(x), fp_hex(y), unix(now)],
                    |r| {
                        Ok(StoredOffer {
                            offer: r.get(0)?,
                            lapses_at: from_unix(r.get(1)?),
                        })
                    },
                )
                .optional())
        };
        let shown = |m: &Mailbox| -> Result<_, StoreError> {
            Ok(load_account(conn, m)?.and_then(|(_, a, _)| a.shown_text))
        };
        let (presentations, offers) = match a.fingerprint.zip(b.fingerprint) {
            Some((x, y)) => (
                [presentation(&x, &y)?, presentation(&y, &x)?],
                [offer(&x, &y)?, offer(&y, &x)?],
            ),
            None => Default::default(),
        };
        out.push(Left {
            pair: [a.clone(), b.clone()],
            rows: [row(a, b)?, row(b, a)?],
            presentations,
            offers,
            shown: [shown(a)?, shown(b)?],
        });
    }
    Ok(out)
}

/// Each upgrade `from` has waiting, as the other party, with the bytes of
/// the record it was taken on, where `to` has nothing pending for that
/// party.
fn moving_upgrades(
    tx: &Connection,
    from: &str,
    to: &str,
) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
    let mut stmt = sql(tx.prepare(
        "SELECT r.other_fp, p.reset FROM relationship r
           JOIN friend_presentation p ON p.presenter = r.other_fp AND p.other = r.owner_fp
          WHERE r.pending_upgrade AND p.reset IS NOT NULL AND r.owner_fp = ?1
            AND NOT EXISTS (SELECT 1 FROM relationship s
                             WHERE s.owner_fp = ?2 AND s.other_fp = r.other_fp
                               AND s.pending_at IS NOT NULL)",
    ))?;
    let found = sql(stmt.query_map(params![from, to], |r| Ok((r.get(0)?, r.get(1)?))))?;
    sql(found.collect())
}

/// A ledger entry, inserted.
fn insert_ledger(tx: &Connection, entry: &LedgerEntry) -> Result<(), StoreError> {
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
    Ok(())
}

/// What a rotation merged onto `fp`, made one state a direction again: an
/// upgrade offer off a friendship stands only as its sender's pending out
/// shows it and while the record it was taken on does, and never beside a
/// request.
fn settle_upgrades(tx: &Connection, fp: &str) -> Result<(), StoreError> {
    let recorded = "EXISTS (SELECT 1 FROM friend_presentation p
                     WHERE p.presenter = r.other_fp AND p.other = r.owner_fp
                       AND p.reset IS NOT NULL)";
    sql(tx.execute(
        &format!(
            "UPDATE relationship AS r SET pending_at = NULL, pending_lapses = NULL,
                    pending_delivered = NULL, pending_note = NULL, pending_upgrade = 0
              WHERE (r.owner_fp = ?1 OR r.other_fp = ?1) AND r.pending_upgrade
                AND NOT {recorded}"
        ),
        params![fp],
    ))?;
    // Nor any pending out beside the friendship a merge left.
    sql(tx.execute(
        "UPDATE relationship SET pending_at = NULL, pending_lapses = NULL,
                pending_delivered = NULL, pending_note = NULL, pending_upgrade = 0,
                pending_offer = NULL, pending_offer_lapses = NULL
          WHERE (owner_fp = ?1 OR other_fp = ?1) AND friendship IS NOT NULL
            AND pending_at IS NOT NULL",
        params![fp],
    ))?;
    sql(tx.execute(
        "DELETE FROM friend_offer AS f
          WHERE (f.owner = ?1 OR f.other = ?1)
            AND NOT EXISTS (SELECT 1 FROM relationship r
                             WHERE r.owner_fp = f.owner AND r.other_fp = f.other
                               AND (r.friendship IS NOT NULL OR r.pending_upgrade))",
        params![fp],
    ))?;
    reclaim(tx, "owner_fp = ?1 OR other_fp = ?1", &[&fp])
}

/// The upgrade offer `x` has waiting for `y` on an edge a reset left
/// inactive, gone with the record `y` kept for it, and the pending out it
/// showed `x` with it.
fn drop_upgrade(tx: &Connection, x: &str, y: &str) -> Result<(), StoreError> {
    let shown = sql(tx.execute(
        "UPDATE relationship SET pending_at = NULL, pending_lapses = NULL,
                pending_delivered = NULL, pending_note = NULL, pending_upgrade = 0
          WHERE owner_fp = ?1 AND other_fp = ?2 AND pending_upgrade",
        params![x, y],
    ))?;
    if shown > 0 {
        sql(tx.execute(
            "DELETE FROM friend_offer WHERE owner = ?1 AND other = ?2",
            params![x, y],
        ))?;
        reclaim(tx, "owner_fp = ?1 AND other_fp = ?2", &[&x, &y])?;
    }
    Ok(())
}

fn befriend(
    tx: &Connection,
    a: &Mailbox,
    b: &Mailbox,
    at: SystemTime,
) -> Result<RelationId, StoreError> {
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
}

fn refriend(
    tx: &Connection,
    a: &Mailbox,
    b: &Mailbox,
    id: RelationId,
    at: SystemTime,
) -> Result<(), StoreError> {
    sql(tx.execute(
        "INSERT OR IGNORE INTO relation (id, kind, made_at) VALUES (?1, ?2, ?3)",
        params![id as i64, FRIENDSHIP, unix(at)],
    ))?;
    let mut ended = Vec::new();
    for (x, y) in [(a, b), (b, a)] {
        let (rid, mut rel) = match load_pair(tx, x, y)? {
            Some((rid, rel)) => (Some(rid), rel),
            None => (None, Relationship::new(x, y)),
        };
        ended.extend(rel.friendship.replace(id).filter(|old| *old != id));
        rel.pending_out = None;
        ended.extend(rel.approval.take());
        write(tx, rid, &mut rel)?;
    }
    forget(tx, ended)
}

fn set_edge(tx: &Connection, a: &str, b: &str, edge: Option<RelationId>) -> Result<(), StoreError> {
    sql(tx.execute(
        &format!("UPDATE friend_presentation SET edge = ?3 WHERE {PAIR}"),
        params![a, b, edge.map(|n| n as i64)],
    ))?;
    Ok(())
}

/// The friendship on the pair's rows, ended.
fn end_edge(tx: &Connection, a: &Mailbox, b: &Mailbox) -> Result<Option<EndedEdge>, StoreError> {
    let (ab, ba) = (load_pair(tx, a, b)?, load_pair(tx, b, a)?);
    let Some(id) = [&ab, &ba]
        .into_iter()
        .flatten()
        .find_map(|(_, r)| r.friendship)
    else {
        return Ok(None);
    };
    let parties = match (&ab, &ba) {
        (Some((_, r)), _) => [r.owner.clone(), r.other.clone()],
        (None, Some((_, r))) => [r.other.clone(), r.owner.clone()],
        (None, None) => return Ok(None),
    };
    let mut ended = Vec::new();
    for (rid, mut rel) in [ab, ba].into_iter().flatten() {
        ended.extend(rel.friendship.take());
        write(tx, Some(rid), &mut rel)?;
    }
    forget(tx, ended)?;
    // An upgrade offer stood beside the friendship, and goes with it.
    if let Some((x, y)) = parties[0].fingerprint.zip(parties[1].fingerprint) {
        sql(tx.execute(
            "DELETE FROM friend_offer
              WHERE (owner = ?1 AND other = ?2) OR (owner = ?2 AND other = ?1)",
            params![fp_hex(&x), fp_hex(&y)],
        ))?;
    }
    Ok(Some(EndedEdge { id, parties }))
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
        self.with_tx(|tx| edit_in(tx, owner, other, f))
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
    /// With `portable`, a rotation's: presentations, offers and
    /// withdrawals move in the same transaction.
    fn rekey(
        &self,
        moves: Moves,
        to: &str,
        from: &str,
        portable: bool,
        report: &Report,
    ) -> Result<(Rekeyed, Vec<Left>), StoreError> {
        self.with_tx(|tx| {
            // What waits for the key that retires goes first; then each
            // upgrade the key that moves has waiting, with the record it
            // was taken on, where the successor has nothing pending for
            // the same party to keep in its place.
            if portable {
                drop_offers_where(tx, "other = ?1", "other_fp = ?1", &[&from])?;
            }
            let moving = match portable {
                true => moving_upgrades(tx, from, to)?,
                false => Vec::new(),
            };
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
                for (l, k) in &lost {
                    sql(tx.execute(
                        "UPDATE friend_presentation SET edge = ?2 WHERE edge = ?1",
                        params![*l as i64, *k as i64],
                    ))?;
                }
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
            for (table, col) in REKEYED {
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
            let mut rekeyed = Rekeyed {
                moved: n,
                merged,
                ..Rekeyed::default()
            };
            if portable {
                rotate_portable(tx, from, to, &mut rekeyed)?;
                rekeyed.owed_merged = restamp_owed(tx, from, to)?;
                settle_upgrades(tx, to)?;
                for (other, record) in moving {
                    let owner = to.to_string();
                    let kept: Option<Vec<u8>> = sql(tx
                        .query_row(
                            "SELECT reset FROM friend_presentation
                              WHERE presenter = ?1 AND other = ?2",
                            params![other, owner],
                            |r| r.get(0),
                        )
                        .optional())?
                    .flatten();
                    if kept.as_ref() != Some(&record) {
                        drop_upgrade(tx, &owner, &other)?;
                    }
                }
            }
            let left = left(tx, &report.and_ended(&rekeyed.ended))?;
            Ok((rekeyed, left))
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

    fn upgrades_to(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let text = format!(
            "SELECT {COLUMNS} FROM relationship
              WHERE {} AND pending_upgrade AND pending_lapses > ?2 ORDER BY id",
            mailbox_sql(owner, "other", 1)
        );
        Ok(rows(&conn, &text, &[&bind(owner), &unix(now)])?
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
              WHERE {} AND pending_delivered AND NOT pending_upgrade AND pending_lapses > ?2
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
        let alias = alias.map(str::to_owned);
        let part = Part::SetAlias(owner.clone(), other.clone(), alias);
        self.write(&[part], &Report::none()).map(drop)
    }

    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        let part = Part::SetBlocked(owner.clone(), other.clone(), blocked, at);
        self.write(&[part], &Report::none()).map(drop)
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
        let part = Part::SetPendingOut(owner.clone(), other.clone(), pending.cloned());
        self.write(&[part], &Report::none()).map(drop)
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
        self.with_tx(|tx| befriend(tx, a, b, at))
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
        hold(&self.conn.lock().unwrap(), owner, held, until)
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
            insert_ledger(tx, entry)?;
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

    fn request_addresses(
        &self,
        to: &Mailbox,
        since: SystemTime,
        before: Option<SystemTime>,
    ) -> Result<Vec<String>, StoreError> {
        let text = format!(
            "SELECT address FROM request_ledger
              WHERE sender IS NULL AND address IS NOT NULL AND {} AND at >= ?2
                AND (?3 IS NULL OR at < ?3)
              GROUP BY address ORDER BY MIN(id)",
            mailbox_sql(to, "recipient", 1)
        );
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare(&text))?;
        let rows = sql(
            stmt.query_map(params![bind(to), unix(since), before.map(unix)], |r| {
                r.get(0)
            }),
        )?;
        rows.map(sql).collect()
    }

    fn guest_requests_to(
        &self,
        address: &str,
        to: &Mailbox,
        since: SystemTime,
    ) -> Result<usize, StoreError> {
        let text = format!(
            "SELECT COUNT(*) FROM request_ledger
              WHERE address = ?1 AND (sender IS NULL OR sender = 'guest') AND {}
                AND kind = ?3 AND at >= ?4",
            mailbox_sql(to, "recipient", 2)
        );
        let conn = self.conn.lock().unwrap();
        let n: i64 = sql(conn.query_row(
            &text,
            params![
                address,
                bind(to),
                RequestKind::Message.as_i64(),
                unix(since)
            ],
            |r| r.get(0),
        ))?;
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
            if let Some(text) = &update.shown_text {
                a.shown_text = text.clone();
            }
            if let Some(on) = update.discoverable {
                a.discoverable = on;
            }
            if let Some(at) = update.takes_requests {
                a.takes_requests = at.is_some();
                if at.is_some() {
                    a.requests_opted_at = at;
                }
            }
            if let Some(profile) = &update.profile {
                a.profile = profile.clone();
                a.profile.languages.truncate(MAX_LANGUAGES);
            }
        })
    }

    fn refriend(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        id: RelationId,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        self.with_tx(|tx| refriend(tx, a, b, id, at))
    }

    fn befriend_dropping(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        at: SystemTime,
        id: Option<RelationId>,
        drop: &[[u8; 32]],
    ) -> Result<RelationId, StoreError> {
        self.with_tx(|tx| befriend_dropping(tx, a, b, at, id, drop))
    }

    fn made_at(&self, id: RelationId) -> Result<Option<SystemTime>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let made: Option<i64> = sql(conn
            .query_row(
                "SELECT made_at FROM relation WHERE id = ?1",
                params![id as i64],
                |r| r.get(0),
            )
            .optional())?;
        Ok(made.map(from_unix))
    }

    fn present(&self, p: &Presentation) -> Result<Option<Presentation>, StoreError> {
        self.with_tx(|tx| present(tx, p))
    }

    fn present_befriending(
        &self,
        a: &Mailbox,
        b: &Mailbox,
        rows: &[Presentation],
        friends: Option<Option<RelationId>>,
        at: SystemTime,
    ) -> Result<(Vec<Option<Presentation>>, Option<RelationId>), StoreError> {
        self.with_tx(|tx| present_befriending(tx, a, b, rows, friends, at))
    }

    fn lapse_resets(&self, before: SystemTime, now: SystemTime) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let n = sql(conn.execute(
            "UPDATE friend_presentation SET reset = NULL
              WHERE reset IS NOT NULL AND at <= ?1
                AND NOT EXISTS (SELECT 1 FROM friend_offer o
                                 WHERE o.owner = friend_presentation.other
                                   AND o.other = friend_presentation.presenter
                                   AND o.lapses > ?2)
                AND NOT EXISTS (SELECT 1 FROM relationship r
                                 WHERE r.owner_fp = friend_presentation.other
                                   AND r.other_fp = friend_presentation.presenter
                                   AND r.pending_upgrade AND r.pending_lapses > ?2)",
            params![unix(before), unix(now)],
        ))?;
        Ok(n)
    }

    fn presentation(
        &self,
        presenter: &[u8; 32],
        other: &[u8; 32],
    ) -> Result<Option<Presentation>, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(presentations_where(
            &conn,
            "presenter = ?1 AND other = ?2",
            &[&fp_hex(presenter), &fp_hex(other)],
        )?
        .pop())
    }

    fn presentations(&self, of: &[u8; 32]) -> Result<Vec<Presentation>, StoreError> {
        let conn = self.conn.lock().unwrap();
        presentations_where(&conn, "presenter = ?1 OR other = ?1", &[&fp_hex(of)])
    }

    fn unpresent(
        &self,
        presenter: &[u8; 32],
        other: &[u8; 32],
    ) -> Result<Option<Presentation>, StoreError> {
        let (a, b) = (fp_hex(presenter), fp_hex(other));
        self.with_tx(|tx| Ok(unpresent_pair(tx, &a, &b, &[*presenter])?.pop()))
    }

    fn drop_presentations(
        &self,
        a: &[u8; 32],
        b: &[u8; 32],
        presenters: &[[u8; 32]],
    ) -> Result<Ended, StoreError> {
        self.with_tx(|tx| drop_pair(tx, a, b, presenters))
    }

    fn end_friendship(&self, a: &Mailbox, b: &Mailbox, end: &Ending) -> Result<Ended, StoreError> {
        self.with_tx(|tx| end_friendship(tx, a, b, end))
    }

    fn presented_by(&self, device: &[u8; 32]) -> Result<Vec<Presentation>, StoreError> {
        let conn = self.conn.lock().unwrap();
        presentations_where(&conn, "device = ?1", &[&device.as_slice()])
    }

    fn keep_withdrawal(&self, w: &HeldWithdrawal, cap: usize) -> Result<(), StoreError> {
        self.with_tx(|tx| keep_withdrawal(tx, w, cap))
    }

    fn withdrawals(&self, pair: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT owner, pair, party, before, withdrawal, checked, at
               FROM friend_withdrawal WHERE pair = ?1 ORDER BY id",
        ))?;
        let found = sql(stmt.query_map(params![pair.as_slice()], withdrawal_row))?;
        found
            .map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
            .collect()
    }

    fn withdrawals_by(&self, owner: &[u8; 32]) -> Result<Vec<HeldWithdrawal>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT owner, pair, party, before, withdrawal, checked, at
               FROM friend_withdrawal WHERE owner = ?1 ORDER BY id",
        ))?;
        let found = sql(stmt.query_map(params![fp_hex(owner)], withdrawal_row))?;
        found
            .map(|r| r.map_err(StoreError::new).and_then(|inner| inner))
            .collect()
    }

    fn drop_withdrawal(
        &self,
        owner: &[u8; 32],
        pair: &[u8; 32],
        party: &[u8; 32],
        withdrawal: &[u8],
    ) -> Result<(), StoreError> {
        drop_withdrawal(&self.conn.lock().unwrap(), owner, pair, party, withdrawal)
    }

    fn set_offer(
        &self,
        owner: &[u8; 32],
        other: &[u8; 32],
        offer: Option<&StoredOffer>,
    ) -> Result<(), StoreError> {
        set_offer(&self.conn.lock().unwrap(), owner, other, offer)
    }

    fn ask(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        pending: &PendingOut,
        upgrade: Option<&StoredOffer>,
        charge: Option<&Charge>,
        report: &Report,
    ) -> Result<Vec<Left>, StoreError> {
        self.with_tx(|tx| {
            if let Some(c) = charge {
                insert_ledger(tx, &c.entry)?;
                if c.dropped {
                    let (id, a, dropped) = match load_account(tx, other)? {
                        Some((id, a, d)) => (Some(id), a, d),
                        None => (None, MessagingAccount::default(), 0),
                    };
                    write_account(tx, other, id, &a, dropped + 1)?;
                }
            }
            let (id, mut rel) = match load_pair(tx, owner, other)? {
                Some((id, rel)) => (Some(id), rel),
                None => (None, Relationship::new(owner, other)),
            };
            rel.pending_out = Some(pending.clone());
            write(tx, id, &mut rel)?;
            let Some((x, y)) = owner.fingerprint.zip(other.fingerprint) else {
                return left(tx, report);
            };
            let (x, y) = (fp_hex(&x), fp_hex(&y));
            sql(tx.execute(
                "DELETE FROM friend_offer WHERE owner = ?1 AND other = ?2",
                params![x, y],
            ))?;
            if let Some(o) = upgrade {
                sql(tx.execute(
                    "INSERT INTO friend_offer (owner, other, offer, lapses) VALUES (?1, ?2, ?3, ?4)",
                    params![x, y, o.offer, unix(o.lapses_at)],
                ))?;
            }
            left(tx, report)
        })
    }

    fn answer_reset(
        &self,
        drops: &[([u8; 32], [u8; 32], Vec<[u8; 32]>)],
        record: Option<&Presentation>,
        upgrade: Option<(&Mailbox, &Mailbox)>,
    ) -> Result<(Vec<Ended>, Option<Presentation>), StoreError> {
        self.with_tx(|tx| answer_reset(tx, drops, record, upgrade))
    }

    fn write(&self, parts: &[Part], report: &Report) -> Result<(Vec<Did>, Vec<Left>), StoreError> {
        self.with_tx(|tx| {
            let did = parts
                .iter()
                .map(|p| part(tx, p))
                .collect::<Result<Vec<_>, _>>()?;
            Ok((did, left(tx, report)?))
        })
    }

    fn drop_offers(&self, pairs: &[FpPair]) -> Result<(), StoreError> {
        self.with_tx(|tx| drop_offers(tx, pairs))
    }

    fn drop_offers_naming(&self, fp: &[u8; 32]) -> Result<Vec<FpPair>, StoreError> {
        self.with_tx(|tx| drop_offers_naming(tx, fp))
    }

    fn offer(
        &self,
        owner: &[u8; 32],
        other: &[u8; 32],
        now: SystemTime,
    ) -> Result<Option<StoredOffer>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                "SELECT offer, lapses FROM friend_offer
                  WHERE owner = ?1 AND other = ?2 AND lapses > ?3",
                params![fp_hex(owner), fp_hex(other), unix(now)],
                |r| {
                    Ok(StoredOffer {
                        offer: r.get(0)?,
                        lapses_at: from_unix(r.get(1)?),
                    })
                },
            )
            .optional())
    }

    fn offerers(&self, now: SystemTime) -> Result<Vec<[u8; 32]>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT owner FROM friend_offer WHERE lapses > ?1
             UNION
             SELECT owner_fp FROM relationship
              WHERE owner_fp IS NOT NULL AND pending_offer IS NOT NULL
                AND pending_offer_lapses > ?1 AND pending_lapses > ?1
             ORDER BY 1",
        ))?;
        let found = sql(stmt.query_map(params![unix(now)], |r| r.get::<_, String>(0)))?;
        found
            .map(|r| fp_from_hex(&r.map_err(StoreError::new)?))
            .collect()
    }

    fn offers_from(
        &self,
        owner: &[u8; 32],
        now: SystemTime,
    ) -> Result<Vec<([u8; 32], StoredOffer)>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(
            "SELECT other, offer, lapses FROM friend_offer WHERE owner = ?1 AND lapses > ?2
             UNION ALL
             SELECT other_fp, pending_offer, pending_offer_lapses FROM relationship
              WHERE owner_fp = ?1 AND pending_offer IS NOT NULL AND pending_offer_lapses > ?2
                AND pending_lapses > ?2
             ORDER BY 1",
        ))?;
        let found = sql(stmt.query_map(params![fp_hex(owner), unix(now)], |r| {
            let other: String = r.get(0)?;
            let offer = StoredOffer {
                offer: r.get(1)?,
                lapses_at: from_unix(r.get(2)?),
            };
            Ok((other, offer))
        }))?;
        found
            .map(|r| {
                let (other, offer) = r.map_err(StoreError::new)?;
                Ok((fp_from_hex(&other)?, offer))
            })
            .collect()
    }

    fn keep_rotation(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        record: &[u8],
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT OR IGNORE INTO identity_rotation (predecessor, successor, record)
             VALUES (?1, ?2, ?3)",
            params![fp_hex(from), fp_hex(to), record],
        ))?;
        Ok(())
    }

    fn rotation_from(&self, from: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let found: Option<(String, Vec<u8>)> = sql(conn
            .query_row(
                "SELECT successor, record FROM identity_rotation WHERE predecessor = ?1",
                params![fp_hex(from)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        found
            .map(|(to, record)| Ok((fp_from_hex(&to)?, record)))
            .transpose()
    }

    fn owe(&self, owed: &[(Work, Cause)]) -> Result<Vec<OwedId>, StoreError> {
        self.with_tx(|tx| owed.iter().map(|(w, c)| owe(tx, w, c)).collect())
    }

    fn owed(&self) -> Result<Vec<Owed>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare(&format!(
            "SELECT {OWED_COLUMNS} FROM friend_owed ORDER BY id"
        )))?;
        let rows = sql(stmt.query_map([], owed_row))?;
        sql(rows.collect::<Result<Vec<_>, _>>())?
            .into_iter()
            .collect()
    }

    fn settle(&self, ids: &[OwedId]) -> Result<(), StoreError> {
        self.with_tx(|tx| ids.iter().try_for_each(|id| settle(tx, *id)))
    }

    fn rotation_to(&self, to: &[u8; 32]) -> Result<Option<RotationRecord>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let found: Option<(String, Vec<u8>)> = sql(conn
            .query_row(
                "SELECT predecessor, record FROM identity_rotation WHERE successor = ?1
                  ORDER BY rowid LIMIT 1",
                params![fp_hex(to)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        found
            .map(|(from, record)| Ok((fp_from_hex(&from)?, record)))
            .transpose()
    }

    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<Rekeyed, StoreError> {
        self.rekey(
            claim_moves,
            &fp_hex(fingerprint),
            login,
            false,
            &Report::none(),
        )
        .map(|(rekeyed, _)| rekeyed)
    }

    fn claimable(&self, login: &str) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        for (table, col) in REKEYED {
            let text = format!(
                "SELECT EXISTS (SELECT 1 FROM {table} WHERE {col}_fp IS NULL AND {col} = ?1)"
            );
            if sql(conn.query_row(&text, params![login], |r| r.get::<_, bool>(0)))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn rotate_reporting(
        &self,
        from: &[u8; 32],
        to: &[u8; 32],
        report: &Report,
    ) -> Result<(Rekeyed, Vec<Left>), StoreError> {
        self.rekey(rotate_moves, &fp_hex(to), &fp_hex(from), true, report)
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
                     UNION SELECT id FROM relationship WHERE pending_offer_lapses <= ?1
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
            n += sql(tx.execute(
                "DELETE FROM friend_offer WHERE rowid IN
                   (SELECT rowid FROM friend_offer WHERE lapses <= ?1 LIMIT ?2)",
                params![lapsed, batch],
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
    let mut out = vec![
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
    ];
    if let Some(fp) = of.fingerprint.as_ref() {
        let fp = || vec![Value::Text(fp_hex(fp))];
        out.push((
            "DELETE FROM friend_presentation WHERE presenter = ?1".into(),
            fp(),
        ));
        out.push((
            "DELETE FROM friend_offer WHERE owner = ?1 OR other = ?1".into(),
            fp(),
        ));
    }
    out
}
