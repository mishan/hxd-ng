//! The audit trail, the reports and the block list on SQLite
//! (`docs/moderation.md` §7): the three tables version 2 reserved, the
//! columns version 8 added for news and for naming a report, and nothing
//! clever. The decisions are the trait's; this is them in SQL.

use std::time::SystemTime;

use hxd_core::inbox::{Mailbox, StoreError};
use hxd_core::moderation::{
    Act, ActId, ActKind, Closed, ModerationStore, Outcome, Report, ReportFilter, ReportId,
    ReportTarget, Subject,
};
use rusqlite::{params, OptionalExtension, Row};

use super::{fp_from_hex, fp_hex, from_unix, unix, SqliteStore};

fn sql<T>(r: rusqlite::Result<T>) -> Result<T, StoreError> {
    r.map_err(StoreError::new)
}

fn id_of(n: i64, what: &str) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::new(format!("stored {what} {n} is not an id")))
}

fn clamp(id: u64) -> i64 {
    id.min(i64::MAX as u64) as i64
}

fn fp(hex: Option<String>) -> Result<Option<[u8; 32]>, StoreError> {
    hex.as_deref().map(fp_from_hex).transpose()
}

fn handle(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 16]>, StoreError> {
    bytes
        .map(|b| {
            <[u8; 16]>::try_from(b.as_slice())
                .map_err(|_| StoreError::new("a stored media handle is not 16 bytes"))
        })
        .transpose()
}

fn hash(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, StoreError> {
    bytes
        .map(|b| {
            <[u8; 32]>::try_from(b.as_slice())
                .map_err(|_| StoreError::new("a stored media hash is not 32 bytes"))
        })
        .transpose()
}

const ACT_COLUMNS: &str = "id, kind, actor, actor_fp, target_line, target_media, \
                           target_article, target_report, target_login, target_fp, \
                           reason, evidence, media_hash, at";

fn act_of(r: &Row<'_>) -> rusqlite::Result<Result<Act, StoreError>> {
    let id: i64 = r.get(0)?;
    let kind: i64 = r.get(1)?;
    let actor: String = r.get(2)?;
    let actor_fp: Option<String> = r.get(3)?;
    let line: Option<i64> = r.get(4)?;
    let media: Option<Vec<u8>> = r.get(5)?;
    let article: Option<i64> = r.get(6)?;
    let report: Option<i64> = r.get(7)?;
    let login: Option<String> = r.get(8)?;
    let target_fp: Option<String> = r.get(9)?;
    let reason: String = r.get(10)?;
    let evidence: Option<String> = r.get(11)?;
    let media_hash: Option<Vec<u8>> = r.get(12)?;
    let at: i64 = r.get(13)?;
    Ok((|| {
        Ok(Act {
            id: id_of(id, "act id")?,
            kind: ActKind::from_i64(kind)
                .ok_or_else(|| StoreError::new(format!("stored act kind {kind} is unknown")))?,
            actor,
            actor_fp: fp(actor_fp)?,
            line: line.map(|n| id_of(n, "line id")).transpose()?,
            media: handle(media)?,
            article: article
                .map(|n| {
                    u32::try_from(n)
                        .map_err(|_| StoreError::new(format!("stored article {n} is not an id")))
                })
                .transpose()?,
            report: report.map(|n| id_of(n, "report id")).transpose()?,
            login,
            fingerprint: fp(target_fp)?,
            reason,
            evidence,
            media_hash: hash(media_hash)?,
            at: from_unix(at),
        })
    })())
}

const REPORT_COLUMNS: &str = "id, kind, reporter, reporter_fp, target_line, target_media, \
                              target_msg, target_article, target_login, target_fp, \
                              target_nick, reason, evidence, verified, at, closed_at, \
                              closed_by, outcome, note, duplicate_of";

fn report_of(r: &Row<'_>) -> rusqlite::Result<Result<Report, StoreError>> {
    let id: i64 = r.get(0)?;
    let kind: i64 = r.get(1)?;
    let reporter: Option<String> = r.get(2)?;
    let reporter_fp: Option<String> = r.get(3)?;
    let line: Option<i64> = r.get(4)?;
    let media: Option<Vec<u8>> = r.get(5)?;
    let msg: Option<i64> = r.get(6)?;
    let article: Option<i64> = r.get(7)?;
    let login: Option<String> = r.get(8)?;
    let target_fp: Option<String> = r.get(9)?;
    let nick: Option<String> = r.get(10)?;
    let reason: String = r.get(11)?;
    let evidence: Option<String> = r.get(12)?;
    let verified: bool = r.get(13)?;
    let at: i64 = r.get(14)?;
    let closed_at: Option<i64> = r.get(15)?;
    let closed_by: Option<String> = r.get(16)?;
    let outcome: Option<i64> = r.get(17)?;
    let note: Option<String> = r.get(18)?;
    let duplicate_of: Option<i64> = r.get(19)?;
    Ok((|| {
        let missing = || StoreError::new(format!("stored report {id} names no target"));
        let media = handle(media)?;
        let target = match kind {
            1 => ReportTarget::Line(id_of(line.ok_or_else(missing)?, "line id")?),
            2 => ReportTarget::Media(media.ok_or_else(missing)?),
            3 => ReportTarget::Msg(id_of(msg.ok_or_else(missing)?, "message id")?),
            4 => ReportTarget::User,
            5 => {
                let n = article.ok_or_else(missing)?;
                ReportTarget::Article(
                    u32::try_from(n)
                        .map_err(|_| StoreError::new(format!("stored article {n} is not an id")))?,
                )
            }
            _ => {
                return Err(StoreError::new(format!(
                    "stored report kind {kind} is unknown"
                )))
            }
        };
        let reporter = match reporter {
            Some(login) => Some(Mailbox {
                login,
                fingerprint: fp(reporter_fp)?,
            }),
            None => None,
        };
        let closed = match (closed_at, closed_by, outcome) {
            (None, None, None) => None,
            (Some(at), Some(by), Some(o)) => Some(Closed {
                at: from_unix(at),
                by,
                outcome: Outcome::from_i64(o)
                    .ok_or_else(|| StoreError::new(format!("stored outcome {o} is unknown")))?,
                note,
                duplicate_of: duplicate_of.map(|n| id_of(n, "report id")).transpose()?,
            }),
            _ => return Err(StoreError::new(format!("report {id} is half closed"))),
        };
        Ok(Report {
            id: id_of(id, "report id")?,
            at: from_unix(at),
            reporter,
            target,
            about: Subject {
                login,
                fingerprint: fp(target_fp)?,
                nick: nick.unwrap_or_default(),
            },
            reason,
            evidence,
            verified,
            media,
            closed,
        })
    })())
}

fn collect<T>(
    rows: impl Iterator<Item = rusqlite::Result<Result<T, StoreError>>>,
) -> Result<Vec<T>, StoreError> {
    rows.map(|r| sql(r).and_then(|inner| inner)).collect()
}

/// A report's target as its kind and one column: which column, and the
/// value for it.
fn target_where(t: &ReportTarget) -> (i64, &'static str, rusqlite::types::Value) {
    use rusqlite::types::Value;
    match t {
        ReportTarget::Line(id) => (t.kind_i64(), "target_line", Value::Integer(clamp(*id))),
        ReportTarget::Media(h) => (t.kind_i64(), "target_media", Value::Blob(h.to_vec())),
        ReportTarget::Msg(id) => (t.kind_i64(), "target_msg", Value::Integer(clamp(*id))),
        ReportTarget::Article(id) => (
            t.kind_i64(),
            "target_article",
            Value::Integer(i64::from(*id)),
        ),
        // Every open report on a person: the caller narrows by whom.
        ReportTarget::User => (t.kind_i64(), "1", Value::Integer(1)),
    }
}

impl ModerationStore for SqliteStore {
    fn record(&self, act: &Act) -> Result<ActId, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "INSERT INTO moderation
               (kind, actor, actor_fp, target_line, target_media, target_article,
                target_report, target_login, target_fp, reason, evidence, media_hash, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                act.kind.as_i64(),
                act.actor,
                act.actor_fp.as_ref().map(fp_hex),
                act.line.map(clamp),
                act.media.map(|h| h.to_vec()),
                act.article.map(i64::from),
                act.report.map(clamp),
                act.login,
                act.fingerprint.as_ref().map(fp_hex),
                act.reason,
                act.evidence,
                act.media_hash.map(|h| h.to_vec()),
                unix(act.at),
            ],
        ))?;
        id_of(conn.last_insert_rowid(), "act id")
    }

    fn acts(&self, before: Option<ActId>, limit: usize) -> Result<Vec<Act>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached(&format!(
            "SELECT {ACT_COLUMNS} FROM moderation
              WHERE (?1 IS NULL OR id < ?1) ORDER BY id DESC LIMIT ?2"
        )))?;
        let rows = sql(stmt.query_map(
            params![before.map(clamp), limit.min(i64::MAX as usize) as i64],
            act_of,
        ))?;
        collect(rows)
    }

    fn file(&self, report: &Report) -> Result<ReportId, StoreError> {
        let conn = self.conn.lock().unwrap();
        // `target_media` is the report's image whatever its kind: the
        // handle for an image report, the one a reported line carried.
        let (line, media, msg, article) = match report.target {
            ReportTarget::Line(id) => (
                Some(clamp(id)),
                report.media.map(|h| h.to_vec()),
                None,
                None,
            ),
            ReportTarget::Media(h) => (None, Some(h.to_vec()), None, None),
            ReportTarget::Msg(id) => (None, None, Some(clamp(id)), None),
            ReportTarget::Article(id) => (None, None, None, Some(i64::from(id))),
            ReportTarget::User => (None, None, None, None),
        };
        let closed = report.closed.as_ref();
        sql(conn.execute(
            "INSERT INTO report
               (kind, reporter, reporter_fp, target_line, target_media, target_msg,
                target_article, target_login, target_fp, target_nick, reason, evidence,
                verified, at, closed_at, closed_by, outcome, note, duplicate_of)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                     ?16, ?17, ?18, ?19)",
            params![
                report.target.kind_i64(),
                report.reporter.as_ref().map(|m| m.login.clone()),
                report
                    .reporter
                    .as_ref()
                    .and_then(|m| m.fingerprint.as_ref())
                    .map(fp_hex),
                line,
                media,
                msg,
                article,
                report.about.login,
                report.about.fingerprint.as_ref().map(fp_hex),
                (!report.about.nick.is_empty()).then(|| report.about.nick.clone()),
                report.reason,
                report.evidence,
                report.verified,
                unix(report.at),
                closed.map(|c| unix(c.at)),
                closed.map(|c| c.by.clone()),
                closed.map(|c| c.outcome.as_i64()),
                closed.and_then(|c| c.note.clone()),
                closed.and_then(|c| c.duplicate_of).map(clamp),
            ],
        ))?;
        id_of(conn.last_insert_rowid(), "report id")
    }

    fn report(&self, id: ReportId) -> Result<Option<Report>, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn
            .query_row(
                &format!("SELECT {REPORT_COLUMNS} FROM report WHERE id = ?1"),
                params![clamp(id)],
                report_of,
            )
            .optional())?
        .transpose()
    }

    fn reports(
        &self,
        filter: ReportFilter,
        before: Option<ReportId>,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let status = match filter {
            ReportFilter::Open => "closed_at IS NULL",
            ReportFilter::Closed => "closed_at IS NOT NULL",
            ReportFilter::All => "1",
        };
        let mut stmt = sql(conn.prepare_cached(&format!(
            "SELECT {REPORT_COLUMNS} FROM report
              WHERE {status} AND (?1 IS NULL OR id < ?1) ORDER BY id DESC LIMIT ?2"
        )))?;
        let rows = sql(stmt.query_map(
            params![before.map(clamp), limit.min(i64::MAX as usize) as i64],
            report_of,
        ))?;
        collect(rows)
    }

    fn open_count(&self) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = sql(conn.query_row(
            "SELECT COUNT(*) FROM report WHERE closed_at IS NULL",
            [],
            |r| r.get(0),
        ))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    fn open_on(&self, target: &ReportTarget) -> Result<Vec<Report>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let (kind, column, value) = target_where(target);
        // `report_open` covers the open rows, which are few: the kind and
        // the column narrow what it hands back.
        let mut stmt = sql(conn.prepare_cached(&format!(
            "SELECT {REPORT_COLUMNS} FROM report
              WHERE closed_at IS NULL AND kind = ?1 AND {column} = ?2 ORDER BY id ASC"
        )))?;
        let rows = sql(stmt.query_map(params![kind, value], report_of))?;
        collect(rows)
    }

    fn close(&self, id: ReportId, closed: &Closed) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let changed = sql(conn.execute(
            "UPDATE report
                SET closed_at = ?1, closed_by = ?2, outcome = ?3, note = ?4, duplicate_of = ?5
              WHERE id = ?6 AND closed_at IS NULL",
            params![
                unix(closed.at),
                closed.by,
                closed.outcome.as_i64(),
                closed.note,
                closed.duplicate_of.map(clamp),
                clamp(id),
            ],
        ))?;
        Ok(changed != 0)
    }

    fn holds_media(&self, handle: &[u8; 16]) -> Result<bool, StoreError> {
        let conn = self.conn.lock().unwrap();
        let found: Option<i64> = sql(conn
            .query_row(
                "SELECT 1 FROM report WHERE closed_at IS NULL AND target_media = ?1 LIMIT 1",
                params![handle.as_slice()],
                |r| r.get(0),
            )
            .optional())?;
        Ok(found.is_some())
    }

    fn block_hash(&self, hash: &[u8; 32], by: &str, at: SystemTime) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        // The first block stands: who blocked it and when is the record.
        sql(conn.execute(
            "INSERT OR IGNORE INTO media_block (hash, at, by) VALUES (?1, ?2, ?3)",
            params![hash.as_slice(), unix(at), by],
        ))?;
        Ok(())
    }

    fn blocked_hashes(&self) -> Result<Vec<[u8; 32]>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sql(conn.prepare_cached("SELECT hash FROM media_block"))?;
        let rows = sql(stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)))?;
        rows.map(|r| {
            let bytes = sql(r)?;
            hash(Some(bytes)).map(|h| h.expect("present"))
        })
        .collect()
    }

    fn scrub_evidence(&self, before: SystemTime) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "UPDATE moderation SET evidence = ''
              WHERE at < ?1 AND kind != ?2 AND evidence IS NOT NULL AND evidence != ''",
            params![unix(before), ActKind::Close.as_i64()],
        ))
    }

    fn prune_reports(&self, before: SystemTime) -> Result<usize, StoreError> {
        let conn = self.conn.lock().unwrap();
        sql(conn.execute(
            "DELETE FROM report WHERE closed_at IS NOT NULL AND closed_at < ?1",
            params![unix(before)],
        ))
    }
}
