//! Moderation on the ng wire (`docs/moderation.md` §5): the requests,
//! the objects they answer with, and the events a moderator and a
//! reporter receive.
//!
//! Everything here is a translation. Who may act on whom, and what an
//! act leaves behind, are the domain's decisions; this file parses a
//! request, calls the core off the reactor, and writes the answer down.

use std::time::Duration;

use hxd_core::access::bit;
use hxd_core::moderation::{Act, Closed, Report, ReportTarget, Subject};
use hxd_core::{Actor, ModError, Outcome, PersonRef, ReportFilter, ReportRequest};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, SessState};
use crate::proto::{reply_err, reply_ok, unix, ReqEnvelope};
use crate::NgCtx;

/// The longest ban a `kick` asks for is a year: past that is a mistake,
/// not a sentence.
const MAX_BAN: Duration = Duration::from_secs(365 * 24 * 3600);
/// What `purge` takes when `since` is not said (§3.3).
const DEFAULT_PURGE: Duration = Duration::from_secs(3600);

/// The error code and text for a refused moderation request: the closed
/// set §5 lists.
pub fn mod_err(e: &ModError) -> (&'static str, &'static str) {
    match e {
        ModError::Disabled => (
            "not_available",
            "Moderation of that is not available on this server.",
        ),
        ModError::AccessDenied => ("access_denied", "You are not allowed to do that."),
        ModError::BadRequest(text) => ("bad_request", text),
        ModError::NoSuchLine => ("no_such_line", "There is no such chat line."),
        ModError::NoSuchMedia => ("no_such_media", "No such media."),
        ModError::NoSuchUser => ("no_such_user", "There is nobody by that name."),
        ModError::NoSuchReport => ("no_such_report", "There is no such report."),
        ModError::NoSuchTarget => ("no_such_target", "There is nothing like that to report."),
        ModError::Protected => ("protected", "That user cannot be moderated by you."),
        ModError::NoIdentity => (
            "bad_request",
            "A guest has no identity to purge by. Kick them instead.",
        ),
        ModError::OwnReport => (
            "own_report",
            "That report is about you: another moderator closes it.",
        ),
        ModError::RateLimited => ("rate_limited", "Slow down."),
        ModError::NoSession | ModError::Store(_) => ("server_error", "Server error."),
    }
}

fn fingerprint_str(fp: &[u8; 32]) -> String {
    hl_identity::Fingerprint(*fp).to_string()
}

/// Whose a thing is, as far as a moderator is shown. Every field absent
/// that is not known, so a client can test for the key.
fn subject_json(s: &Subject) -> Value {
    let mut v = json!({});
    if let Some(login) = &s.login {
        v["login"] = json!(login);
    }
    if !s.nick.is_empty() {
        v["nick"] = json!(s.nick);
    }
    if let Some(fp) = &s.fingerprint {
        v["fingerprint"] = json!(fingerprint_str(fp));
    }
    v
}

fn closed_json(c: &Closed) -> Value {
    let mut v = json!({
        "at": unix(c.at),
        "by": c.by,
        "outcome": c.outcome.name(),
    });
    if let Some(note) = &c.note {
        v["note"] = json!(note);
    }
    if let Some(of) = c.duplicate_of {
        v["of"] = json!(of);
    }
    v
}

/// A report object (§5).
pub fn report_json(r: &Report) -> Value {
    let mut target = json!({ "kind": r.target.name(), "from": subject_json(&r.about) });
    match r.target {
        // The image a reported line carried, so a moderator's client can
        // show it beside the line: the report made it theirs to fetch.
        ReportTarget::Line(id) => {
            target["line"] = json!(id);
            if let Some(h) = &r.media {
                target["media"] = json!(hxd_core::media::handle_str(h));
            }
        }
        ReportTarget::Media(h) => target["media"] = json!(hxd_core::media::handle_str(&h)),
        ReportTarget::Msg(id) => target["msg"] = json!(id),
        ReportTarget::Article(id) => target["article"] = json!(id),
        ReportTarget::User => {}
    }
    let mut v = json!({
        "id": r.id,
        "at": unix(r.at),
        "status": if r.closed.is_some() { "closed" } else { "open" },
        "target": target,
        "reason": r.reason,
        "verified": r.verified,
    });
    // Absent for a guest reporter, who has no name to give.
    if let Some(by) = &r.reporter {
        v["by"] = json!({ "login": by.login });
    }
    if let Some(evidence) = &r.evidence {
        v["evidence"] = json!(evidence);
    }
    if let Some(closed) = &r.closed {
        v["closed"] = closed_json(closed);
    }
    v
}

/// One `moderation_log` entry.
fn act_json(a: &Act) -> Value {
    let mut target = json!({});
    if let Some(line) = a.line {
        target["line"] = json!(line);
    }
    if let Some(media) = &a.media {
        target["media"] = json!(hxd_core::media::handle_str(media));
    }
    if let Some(article) = a.article {
        target["article"] = json!(article);
    }
    if let Some(report) = a.report {
        target["report"] = json!(report);
    }
    if let Some(login) = &a.login {
        target["login"] = json!(login);
    }
    if let Some(fp) = &a.fingerprint {
        target["fingerprint"] = json!(fingerprint_str(fp));
    }
    let mut v = json!({
        "id": a.id,
        "kind": a.kind.name(),
        "at": unix(a.at),
        "by": a.actor,
        "target": target,
        "reason": a.reason,
    });
    // Scrubbed evidence is an empty string, and says so by being absent:
    // "there was something here" is the audit row's own job.
    if let Some(evidence) = a.evidence.as_ref().filter(|e| !e.is_empty()) {
        v["evidence"] = json!(evidence);
    }
    v
}

/// The login reply's `moderation` block: present for a moderator on a
/// server that keeps reports, so a client can badge before any event.
pub fn login_json(core: &hxd_core::Core, uid: hxd_core::Uid) -> Option<Value> {
    core.moderation_open(uid)
        .map(|open| json!({ "open": open }))
}

#[derive(Debug, Default, Deserialize)]
struct UserParams {
    #[serde(default)]
    uid: Option<hxd_core::Uid>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
}

impl UserParams {
    /// Exactly one of the three, or nothing.
    fn person(&self) -> Option<PersonRef> {
        match (self.uid, &self.login, &self.fingerprint) {
            (Some(uid), None, None) => Some(PersonRef::Uid(uid)),
            (None, Some(login), None) => Some(PersonRef::Login(login.clone())),
            (None, None, Some(fp)) => {
                hl_identity::Fingerprint::parse(fp).map(|f| PersonRef::Fingerprint(f.0))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReportParams {
    #[serde(default)]
    line: Option<u64>,
    #[serde(default)]
    media: Option<String>,
    #[serde(default)]
    msg: Option<u64>,
    #[serde(default)]
    user: Option<UserParams>,
    #[serde(default)]
    article: Option<hxd_core::ArticleId>,
    reason: String,
    #[serde(default)]
    evidence: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PageParams {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    before: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct CloseParams {
    id: u64,
    outcome: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    of: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RedactParams {
    id: u64,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct RevokeParams {
    media: String,
    reason: String,
    #[serde(default)]
    block: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PurgeParams {
    #[serde(flatten)]
    who: UserParams,
    #[serde(default)]
    since: Option<u64>,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct KickParams {
    uid: hxd_core::Uid,
    #[serde(default)]
    ban: Option<u64>,
    #[serde(default)]
    purge: Option<u64>,
    #[serde(default)]
    reason: Option<String>,
}

/// Is this one of ours?
pub(crate) fn handles(req: &str) -> bool {
    matches!(
        req,
        "report"
            | "reports"
            | "report_close"
            | "redact"
            | "revoke"
            | "purge"
            | "kick"
            | "moderation_log"
    )
}

/// Handle one moderation request and return the frame that answers it.
pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    let id = req.id;
    let uid = state.uid;
    let by = Actor::Session(uid);
    let refused = |e: ModError| {
        let (code, text) = mod_err(&e);
        reply_err(id, code, text)
    };
    let params = if req.params.is_null() {
        json!({})
    } else {
        req.params.clone()
    };
    fn parse<T: DeserializeOwned>(v: Value) -> Option<T> {
        serde_json::from_value(v).ok()
    }
    let malformed = || reply_err(id, "bad_request", "Malformed moderation request.");
    let answer = |r: Option<Result<Value, ModError>>| match r {
        Some(Ok(ok)) => reply_ok(id, ok),
        Some(Err(e)) => refused(e),
        None => reply_err(id, "server_error", "Server error."),
    };
    let core = &ctx.core;

    match req.req.as_str() {
        "report" => {
            let Some(p) = parse::<ReportParams>(params) else {
                return malformed();
            };
            let named = [
                p.line.is_some(),
                p.media.is_some(),
                p.msg.is_some(),
                p.user.is_some(),
                p.article.is_some(),
            ];
            if named.iter().filter(|n| **n).count() != 1 {
                return reply_err(
                    id,
                    "bad_request",
                    "A report names exactly one of line, media, msg, user or article.",
                );
            }
            let what = if let Some(line) = p.line {
                ReportRequest::Line(line)
            } else if let Some(media) = &p.media {
                match hxd_core::media::handle_from_str(media) {
                    Some(h) => ReportRequest::Media(h),
                    // A handle that does not parse names nothing, and is
                    // answered as one that names nothing it was shown.
                    None => return refused(ModError::NoSuchTarget),
                }
            } else if let Some(msg) = p.msg {
                ReportRequest::Msg(msg)
            } else if let Some(article) = p.article {
                ReportRequest::Article(article)
            } else {
                match p.user.as_ref().and_then(UserParams::person) {
                    Some(who) => ReportRequest::User(who),
                    None => {
                        return reply_err(
                            id,
                            "bad_request",
                            "A user is named by exactly one of uid, login or fingerprint.",
                        )
                    }
                }
            };
            answer(
                off_reactor(core, move |c| {
                    c.report(uid, what, &p.reason, p.evidence).map(|f| {
                        json!({
                            "id": f.id,
                            "outcome": f.outcome.map_or("open", Outcome::name),
                            "follow_up": f.follow_up,
                        })
                    })
                })
                .await,
            )
        }

        "reports" => {
            let Some(p) = parse::<PageParams>(params) else {
                return malformed();
            };
            let filter = match p.status.as_deref() {
                None | Some("open") => ReportFilter::Open,
                Some("closed") => ReportFilter::Closed,
                Some("all") => ReportFilter::All,
                Some(_) => return reply_err(id, "bad_request", "`status` is open, closed or all."),
            };
            if p.limit.is_some_and(|n| !(1..=100).contains(&n)) {
                return reply_err(id, "bad_request", "`limit` is between 1 and 100.");
            }
            let limit = p.limit.unwrap_or(50);
            answer(
                off_reactor(core, move |c| {
                    c.reports(by, filter, p.before, limit).map(|(page, more)| {
                        json!({
                            "reports": page.iter().map(report_json).collect::<Vec<_>>(),
                            "has_more": more,
                        })
                    })
                })
                .await,
            )
        }

        "report_close" => {
            let Some(p) = parse::<CloseParams>(params) else {
                return malformed();
            };
            let outcome = match Outcome::from_name(&p.outcome) {
                Some(o @ (Outcome::Dismissed | Outcome::Duplicate)) => o,
                _ => return reply_err(id, "bad_request", "`outcome` is dismissed or duplicate."),
            };
            answer(
                off_reactor(core, move |c| {
                    c.report_close(by, p.id, outcome, p.note, p.of)
                        .map(|()| json!({}))
                })
                .await,
            )
        }

        "redact" => {
            let Some(p) = parse::<RedactParams>(params) else {
                return malformed();
            };
            answer(
                off_reactor(core, move |c| {
                    c.redact_line(by, p.id, &p.reason).map(|()| json!({}))
                })
                .await,
            )
        }

        "revoke" => {
            let Some(p) = parse::<RevokeParams>(params) else {
                return malformed();
            };
            let Some(handle) = hxd_core::media::handle_from_str(&p.media) else {
                return refused(ModError::NoSuchMedia);
            };
            let block = p.block.unwrap_or(true);
            answer(
                off_reactor(core, move |c| {
                    c.revoke_media(by, &handle, &p.reason, block)
                        .map(|()| json!({}))
                })
                .await,
            )
        }

        "purge" => {
            let Some(p) = parse::<PurgeParams>(params) else {
                return malformed();
            };
            let Some(who) = p.who.person() else {
                return reply_err(
                    id,
                    "bad_request",
                    "A purge names exactly one of uid, login or fingerprint.",
                );
            };
            let within = p.since.map_or(DEFAULT_PURGE, Duration::from_secs);
            answer(
                off_reactor(core, move |c| {
                    c.purge_sender(by, &who, within, &p.reason).map(|purged| {
                        json!({
                            "lines": purged.lines.len(),
                            "media": purged.media.len(),
                            "articles": purged.articles.len(),
                        })
                    })
                })
                .await,
            )
        }

        // New to this wire, which has only ever *received* `kicked`. It
        // asks what a legacy kick asks, in the same order and with the
        // same public announcement; `purge` inside it asks for
        // `moderate` too, as the purge request does (§5).
        "kick" => {
            let Some(p) = parse::<KickParams>(params) else {
                return malformed();
            };
            if !state.access.has(bit::DISCONNECT_USERS) {
                return reply_err(
                    id,
                    "access_denied",
                    "You are not allowed to disconnect users.",
                );
            }
            if core.user(p.uid).is_none() {
                return refused(ModError::NoSuchUser);
            }
            if core
                .access_of(p.uid)
                .is_some_and(|a| a.has(bit::CANT_BE_DISCONNECTED))
            {
                return refused(ModError::Protected);
            }
            if let Some(secs) = p.purge {
                let why = p.reason.clone().unwrap_or_default();
                let who = PersonRef::Uid(p.uid);
                let within = Duration::from_secs(secs);
                let purged =
                    off_reactor(core, move |c| c.purge_sender(by, &who, within, &why)).await;
                match purged {
                    // A guest has nothing to purge by, and is exactly who
                    // this button is pressed on: the kick still happens,
                    // as the legacy `kick_purges` path does.
                    Some(Ok(_)) | Some(Err(ModError::NoIdentity)) => {}
                    Some(Err(e)) => return refused(e),
                    None => return reply_err(id, "server_error", "Server error."),
                }
            }
            let ban = p.ban.map(|s| Duration::from_secs(s).min(MAX_BAN));
            match core.kick(p.uid, ban) {
                Ok(nick) => {
                    // The reference server's wording, which the legacy
                    // kick uses too: one room, one announcement.
                    let by_nick = core.user(uid).map(|u| u.nick).unwrap_or_default();
                    let verb = if ban.is_some() { "banned" } else { "kicked" };
                    core.chat_notice(0, uid, format!("{nick} has been {verb} by {by_nick}"));
                    reply_ok(id, json!({}))
                }
                Err(_) => refused(ModError::NoSuchUser),
            }
        }

        "moderation_log" => {
            let Some(p) = parse::<PageParams>(params) else {
                return malformed();
            };
            if p.status.is_some() {
                return malformed();
            }
            if p.limit.is_some_and(|n| !(1..=100).contains(&n)) {
                return reply_err(id, "bad_request", "`limit` is between 1 and 100.");
            }
            let limit = p.limit.unwrap_or(50);
            answer(
                off_reactor(core, move |c| {
                    c.moderation_log(by, p.before, limit).map(|(page, more)| {
                        json!({
                            "entries": page.iter().map(act_json).collect::<Vec<_>>(),
                            "has_more": more,
                        })
                    })
                })
                .await,
            )
        }

        _ => reply_err(id, "unknown_method", "Unknown request."),
    }
}
