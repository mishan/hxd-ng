//! `[moderation]`, where the audit trail lives, its sweeper, and the
//! operator's commands (`docs/moderation.md` §7).
//!
//! The commands act as `cli` in the audit trail and run against the
//! store directly, so they work while the server is down: a `Core` is
//! built around the same files the server opens, with no roster, and the
//! acts run through it exactly as a moderator's would. A running server
//! sees the change on its next read. Images are the exception — they
//! live in the running server's memory — and `media revoke` says so.

use std::sync::Arc;
use std::time::Duration;

use hxd_core::moderation::{ActKind, Outcome, Report, ReportFilter, ReportTarget};
use hxd_core::{Actor, Core, PersonRef};
use serde::Deserialize;

use crate::Config;

/// `[moderation]` (§7). Every key optional, and the section too: a
/// server has moderation whenever it has something to moderate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerationSection {
    /// Days a redacted line's text stays readable to moderators in the
    /// audit trail. 0 keeps it forever.
    #[serde(default = "default_evidence_days")]
    pub evidence_days: u32,
    /// Days a closed report is kept. 0 keeps it forever.
    #[serde(default = "default_report_days")]
    pub report_days: u32,
    /// Days a reported image may outlive its handle's TTL.
    #[serde(default = "default_pin_days")]
    pub pin_days: u32,
    /// Reports as private messages to moderators on the legacy wire.
    #[serde(default = "crate::default_true")]
    pub notify_legacy: bool,
    /// Seconds of a kicked user's output a legacy kick purges; 0 = none.
    #[serde(default)]
    pub kick_purges: u64,
}

impl Default for ModerationSection {
    fn default() -> Self {
        ModerationSection {
            evidence_days: default_evidence_days(),
            report_days: default_report_days(),
            pin_days: default_pin_days(),
            notify_legacy: true,
            kick_purges: 0,
        }
    }
}

fn default_evidence_days() -> u32 {
    30
}

fn default_report_days() -> u32 {
    90
}

fn default_pin_days() -> u32 {
    7
}

impl ModerationSection {
    pub fn to_policy(&self) -> hxd_core::ModerationPolicy {
        hxd_core::ModerationPolicy {
            evidence_days: self.evidence_days,
            report_days: self.report_days,
            pin_days: self.pin_days,
            notify_legacy: self.notify_legacy,
            kick_purges: Duration::from_secs(self.kick_purges),
        }
    }

    pub fn check(&self) -> Result<(), String> {
        if self.pin_days == 0 {
            return Err(
                "[moderation] pin_days must be at least 1: a reported image has to outlive \
                 the moderator's first look at it"
                    .into(),
            );
        }
        Ok(())
    }
}

/// The policy the config asks for, the section's defaults without one.
pub(crate) fn policy(config: &Config) -> hxd_core::ModerationPolicy {
    config.moderation.as_ref().map_or_else(
        || ModerationSection::default().to_policy(),
        |m| m.to_policy(),
    )
}

/// Where the audit trail and the reports are kept: the file `[inbox]`
/// names, else `[history]`'s, else `[news]`'s — the order the server
/// opens them in, written down once so the commands below look where
/// the server writes. `None` is a server with no database, whose reports
/// live in memory until it stops.
#[cfg(feature = "inbox")]
pub(crate) fn db(config: &Config) -> Option<std::path::PathBuf> {
    config
        .inbox
        .as_ref()
        .map(|i| i.db.clone())
        .or_else(|| config.history.as_ref().and_then(|h| h.db.clone()))
        .or_else(|| config.news.as_ref().and_then(|n| n.db.clone()))
}

/// Retention for the trail and the reports: hourly, on the blocking
/// pool, like every other sweeper.
pub async fn pruner(core: Arc<Core>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let core = core.clone();
        let (scrubbed, pruned) = crate::spawn_blocking("prune", move || core.prune_moderation())
            .await
            .unwrap_or((0, 0));
        if scrubbed + pruned > 0 {
            tracing::debug!(scrubbed, pruned, "moderation retention");
        }
    }
}

/// A duration as an operator types one: `90s`, `30m`, `1h`, `7d`, bare
/// seconds, or `all`.
pub fn parse_since(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if text == "all" {
        return Ok(Duration::from_secs(u64::MAX / 2));
    }
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => text.split_at(i),
        None => (text, "s"),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("--since {text:?}: expected e.g. 90s, 30m, 1h, 7d or all"))?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 24 * 3600,
        _ => return Err(format!("--since {text:?}: the unit is s, m, h or d")),
    };
    n.checked_mul(scale)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("--since {text:?} is too long"))
}

fn refused(e: hxd_core::ModError) -> String {
    use hxd_core::ModError::*;
    match e {
        Disabled => "that is not kept on this server".into(),
        AccessDenied => "not allowed".into(),
        BadRequest(why) => why.to_string(),
        NoSuchLine => "no such chat line".into(),
        NoSuchMedia => "no such image".into(),
        NoSuchUser => "nobody by that name".into(),
        NoSuchReport => "no such report".into(),
        NoSuchTarget => "no such target".into(),
        Protected => "protected".into(),
        NoIdentity => "a guest has no identity to purge by".into(),
        OwnReport => "that report is about you".into(),
        RateLimited => "rate limited".into(),
        NoSession => "no session".into(),
        Store(e) => e.to_string(),
    }
}

/// A `Core` around the server's own stores, for the operator to act
/// through. `read_only` opens nothing for writing and migrates nothing,
/// for `--dry-run`.
#[cfg(feature = "inbox")]
fn operator_core(config: &Config, read_only: bool) -> Result<Core, String> {
    use hxd_store_sqlite::{SqliteStore, Synchronous};
    let path = db(config).ok_or(
        "there is no database to moderate: [inbox], [history] or [news] names the file \
         the audit trail and the reports are kept in",
    )?;
    if !path.exists() {
        return Err(format!(
            "{}: no database yet, so nothing to moderate",
            path.display()
        ));
    }
    let store = if read_only {
        Arc::new(
            SqliteStore::open_read_only(&path).map_err(|e| format!("{}: {e}", path.display()))?,
        )
    } else {
        crate::open_sqlite(&path, Synchronous::Normal)?
    };
    let core = Core::new().with_accounts(Arc::new(hxd_auth_file::FileAuth::new(
        &config.paths.accounts,
    )));
    // Only what shares the trail's file is reachable here: a `[news]`
    // with a database of its own keeps its articles where this cannot
    // see them, and a purge says what it took rather than guessing.
    let key = crate::database_path(&path)?;
    let here = |p: &Option<std::path::PathBuf>| {
        p.as_ref()
            .is_none_or(|p| crate::database_path(p).is_ok_and(|k| k == key))
    };
    let core = match config.history.as_ref() {
        Some(h) if here(&h.db) => core.with_history(
            store.clone(),
            hxd_core::history::HistoryPolicy {
                max_lines: h.max_lines,
                max_days: h.max_days,
                max_page: h.max_page,
                replay: h.replay,
            },
        ),
        _ => core,
    };
    let core = match config.news.as_ref() {
        Some(n) if here(&n.db) => core.with_news(store.clone(), n.to_policy()),
        _ => core,
    };
    Ok(core.with_moderation(store, policy(config)))
}

#[cfg(not(feature = "inbox"))]
fn operator_core(_config: &Config, _read_only: bool) -> Result<Core, String> {
    Err("this build has no moderation store (built without the `inbox` feature)".into())
}

/// `hxd history redact <id> --reason R`.
pub fn redact(config: &Config, id: u64, reason: &str) -> Result<(), String> {
    operator_core(config, false)?
        .redact_line(Actor::Operator, id, reason)
        .map_err(refused)
}

/// `hxd media revoke`: images live in the running server's memory, and
/// this process is not that server.
pub fn media_revoke() -> Result<(), String> {
    Err(
        "media revoke needs the running server: images live in its memory, not in the \
         database. Revoke from an ng client (the `revoke` request), which records it here \
         like any other act."
            .into(),
    )
}

/// What a purge took, or would.
pub struct PurgeReport {
    pub lines: usize,
    pub articles: usize,
}

/// `hxd purge <login> [--fingerprint FP] [--since 1h] --reason R
/// [--dry-run]`. Images live in the running server's memory and are not
/// reachable from here; lines and articles are.
pub fn purge(
    config: &Config,
    login: &str,
    fingerprint: Option<&str>,
    since: Duration,
    reason: &str,
    dry_run: bool,
) -> Result<PurgeReport, String> {
    let who = match fingerprint {
        Some(text) => PersonRef::Fingerprint(crate::parse_fingerprint(text)?),
        None => PersonRef::Login(login.to_string()),
    };
    let core = operator_core(config, dry_run)?;
    let purged = if dry_run {
        core.purge_preview(&who, since)
    } else {
        core.purge_sender(Actor::Operator, &who, since, reason)
    }
    .map_err(refused)?;
    Ok(PurgeReport {
        lines: purged.lines.len(),
        articles: purged.articles.len(),
    })
}

fn report_line(r: &Report) -> String {
    let status = match &r.closed {
        None => "open".to_string(),
        Some(c) => format!("{} by {}", c.outcome.name(), c.by),
    };
    let target = match r.target {
        ReportTarget::Line(id) => format!(" (line {id})"),
        ReportTarget::Media(h) => format!(" (image {})", hxd_core::media::handle_str(&h)),
        ReportTarget::Msg(id) => format!(" (message {id})"),
        ReportTarget::User | ReportTarget::Article(_) => String::new(),
    };
    let mut out = format!(
        "{}  {}  {}{target}",
        hxd_session::session::stamp(r.at),
        status,
        r.summary()
    );
    if let Some(evidence) = &r.evidence {
        let label = if r.verified {
            "evidence"
        } else {
            "pasted, unverified"
        };
        out.push_str(&format!(
            "\n    {label}: {}",
            evidence.replace('\n', "\n    ")
        ));
    }
    if let Some(note) = r.closed.as_ref().and_then(|c| c.note.as_ref()) {
        out.push_str(&format!("\n    note: {note}"));
    }
    out
}

/// `hxd reports [--all]`: the open reports, or every one, newest first.
pub fn reports(config: &Config, all: bool) -> Result<String, String> {
    let core = operator_core(config, true)?;
    let filter = if all {
        ReportFilter::All
    } else {
        ReportFilter::Open
    };
    let mut out = Vec::new();
    let mut before = None;
    loop {
        let (page, more) = core
            .reports(Actor::Operator, filter, before, 100)
            .map_err(refused)?;
        before = page.last().map(|r| r.id);
        out.extend(page.iter().map(report_line));
        if !more {
            break;
        }
    }
    if out.is_empty() {
        return Ok(if all { "no reports" } else { "no open reports" }.into());
    }
    Ok(out.join("\n"))
}

/// `hxd reports close <id> --outcome dismissed|duplicate [--note N]
/// [--of ID]`.
pub fn reports_close(
    config: &Config,
    id: u64,
    outcome: &str,
    note: Option<String>,
    of: Option<u64>,
) -> Result<(), String> {
    let outcome = match Outcome::from_name(outcome) {
        Some(o @ (Outcome::Dismissed | Outcome::Duplicate)) => o,
        _ => return Err("--outcome is dismissed or duplicate".into()),
    };
    operator_core(config, false)?
        .report_close(Actor::Operator, id, outcome, note, of)
        .map_err(refused)
}

/// `hxd moderation log [--limit N]`: the audit trail, newest first.
pub fn log(config: &Config, limit: usize) -> Result<String, String> {
    let core = operator_core(config, true)?;
    let (acts, _) = core
        .moderation_log(Actor::Operator, None, limit)
        .map_err(refused)?;
    if acts.is_empty() {
        return Ok("nothing has been moderated".into());
    }
    let lines: Vec<String> = acts
        .iter()
        .map(|a| {
            let mut target = Vec::new();
            if let Some(line) = a.line {
                target.push(format!("line {line}"));
            }
            if let Some(media) = &a.media {
                target.push(format!("image {}", hxd_core::media::handle_str(media)));
            }
            if let Some(article) = a.article {
                target.push(format!("article #{article}"));
            }
            if let Some(report) = a.report {
                target.push(format!("report #{report}"));
            }
            if let Some(login) = &a.login {
                target.push(format!("of {login}"));
            }
            let why = if a.reason.is_empty() && a.kind == ActKind::NewsDelete {
                "(no reason given)"
            } else {
                a.reason.as_str()
            };
            let mut out = format!(
                "#{}  {}  {} by {}: {}  — {why}",
                a.id,
                hxd_session::session::stamp(a.at),
                a.kind.name(),
                a.actor,
                target.join(", "),
            );
            if let Some(evidence) = a.evidence.as_ref().filter(|e| !e.is_empty()) {
                out.push_str(&format!("\n    {}", evidence.replace('\n', "\n    ")));
            }
            out
        })
        .collect();
    Ok(lines.join("\n"))
}
