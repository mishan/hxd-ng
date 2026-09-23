//! Moderation (`docs/moderation.md`): taking bad content back, and
//! hearing about it.
//!
//! Three acts — redact a public line, revoke an image, purge a person's
//! recent output — and a fourth the news brings (`docs/news.md` §11): a
//! delete of someone else's article. Every one runs here, takes who is
//! acting and why, **writes the audit row first** and then does the
//! thing. Reports are rows too, delivered to whoever can act on them the
//! moment they are filed and closed with an outcome the reporter hears.
//!
//! **Who may** is the session's `moderate` (§2), the account's `[extra]`
//! key, defaulting to the kick bit. **Whom** is the kick ladder: a target
//! holding cant-be-disconnected is protected from anyone without
//! delete-users, so "can be kicked by" and "can be moderated by" are one
//! question. The operator, acting from the command line, is below
//! neither.
//!
//! **Store calls never happen under the roster lock**, the rule the
//! inbox, the log and the news keep: what a call needs from the roster
//! is copied out and the lock released before any store is touched.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tracing::warn;

use crate::access::bit;
use crate::history::{LineFlags, LineId, LogLine};
use crate::inbox::{Mailbox, MessageId, StoreError};
use crate::media::{Handle, Principal};
use crate::news::{ArticleId, Author, NewsError};
use crate::roster::{reads_public_chat, Core, Event, Uid};

pub mod conformance;
mod memory;

pub use memory::MemoryModeration;

pub type ActId = u64;
pub type ReportId = u64;

/// The longest reason an act takes, in characters (§3).
pub const MAX_ACT_REASON: usize = 512;
/// The longest reason a report takes, in characters (§4.1).
pub const MAX_REPORT_REASON: usize = 1024;
/// The longest note a moderator closes a report with.
pub const MAX_NOTE: usize = 1024;
/// Pasted evidence, in characters: a private message body's worth.
pub const MAX_EVIDENCE: usize = 4096;
/// Reports one reporter may file in an hour (§4.4).
pub const REPORTS_PER_HOUR: u32 = 10;
/// Who a report closed with no moderator involved was closed by (§4.4).
pub const CLOSED_BY_SERVER: &str = "server";
/// Who the operator's command line acts as in the audit trail (§7).
pub const OPERATOR: &str = "cli";

/// `[moderation]` (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModerationPolicy {
    /// How long a redacted line's text stays readable to moderators in
    /// the audit trail before the sweeper scrubs it. 0 keeps it.
    pub evidence_days: u32,
    /// How long a closed report is kept. 0 keeps it.
    pub report_days: u32,
    /// How long a reported image may outlive its handle's TTL.
    pub pin_days: u32,
    /// Tell moderators on the legacy wire about reports, as private
    /// messages from the system account (§4.5).
    pub notify_legacy: bool,
    /// How much of a kicked user's output a legacy kick purges. Zero —
    /// the default — is none, because a kick over that wire has meant
    /// one thing for twenty-five years (§6).
    pub kick_purges: Duration,
}

impl Default for ModerationPolicy {
    fn default() -> Self {
        ModerationPolicy {
            evidence_days: 30,
            report_days: 90,
            pin_days: 7,
            notify_legacy: true,
            kick_purges: Duration::ZERO,
        }
    }
}

/// What kind of act an audit row records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActKind {
    Redact,
    Revoke,
    Purge,
    /// A report closed by a moderator. One closed as a consequence of an
    /// act is that act's business, not a row of its own.
    Close,
    /// Someone else's news article deleted (`docs/news.md` §11).
    NewsDelete,
    /// A news category deleted, and every article in it.
    NodeDelete,
}

impl ActKind {
    pub fn as_i64(self) -> i64 {
        match self {
            ActKind::Redact => 1,
            ActKind::Revoke => 2,
            ActKind::Purge => 3,
            ActKind::Close => 4,
            ActKind::NewsDelete => 5,
            ActKind::NodeDelete => 6,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        Some(match n {
            1 => ActKind::Redact,
            2 => ActKind::Revoke,
            3 => ActKind::Purge,
            4 => ActKind::Close,
            5 => ActKind::NewsDelete,
            6 => ActKind::NodeDelete,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ActKind::Redact => "redact",
            ActKind::Revoke => "revoke",
            ActKind::Purge => "purge",
            ActKind::Close => "close",
            ActKind::NewsDelete => "news_delete",
            ActKind::NodeDelete => "news_node_delete",
        }
    }
}

/// One row of the audit trail. `id` is 0 until the store records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Act {
    pub id: ActId,
    pub kind: ActKind,
    /// The acting account's login, or [`OPERATOR`].
    pub actor: String,
    pub actor_fp: Option<[u8; 32]>,
    pub line: Option<LineId>,
    pub media: Option<Handle>,
    pub article: Option<ArticleId>,
    pub report: Option<ReportId>,
    /// Whose content it was.
    pub login: Option<String>,
    pub fingerprint: Option<[u8; 32]>,
    pub reason: String,
    /// What was removed, for moderators to read until the sweeper
    /// scrubs it to nothing (§3.1). The row stays.
    pub evidence: Option<String>,
    pub media_hash: Option<[u8; 32]>,
    pub at: SystemTime,
}

impl Act {
    fn new(kind: ActKind, by: &Acting, reason: String) -> Self {
        Act {
            id: 0,
            kind,
            actor: by.name.clone(),
            actor_fp: by.fingerprint,
            line: None,
            media: None,
            article: None,
            report: None,
            login: None,
            fingerprint: None,
            reason,
            evidence: None,
            media_hash: None,
            at: SystemTime::now(),
        }
    }

    fn about(mut self, who: &Subject) -> Self {
        self.login = who.login.clone();
        self.fingerprint = who.fingerprint;
        self
    }
}

/// Whose a reported or removed thing is: the durable identity where
/// there is one, and the name they went by.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Subject {
    /// Absent for a guest, whose `guest` login names nobody.
    pub login: Option<String>,
    pub fingerprint: Option<[u8; 32]>,
    pub nick: String,
}

impl Subject {
    /// The mailbox rule's key for this person, or `None` for someone
    /// with no durable identity at all.
    pub fn mailbox(&self) -> Option<Mailbox> {
        match (&self.login, self.fingerprint) {
            (login, Some(fp)) => Some(Mailbox::identified(login.clone().unwrap_or_default(), fp)),
            (Some(login), None) => Some(Mailbox::login(login.clone())),
            (None, None) => None,
        }
    }

    /// Is this the same person as `other`, by the mailbox rule? Never
    /// for someone with no durable identity: two guests are two people,
    /// and nothing says which of them anyone meant.
    pub fn same_person(&self, other: &Subject) -> bool {
        match (self.mailbox(), other.mailbox()) {
            (Some(a), Some(b)) => a.matches(&b.login, b.fingerprint.as_ref()),
            _ => false,
        }
    }

    fn of_mailbox(m: &Mailbox, nick: String) -> Self {
        Subject {
            login: (!m.login.is_empty()).then(|| m.login.clone()),
            fingerprint: m.fingerprint,
            nick,
        }
    }

    fn of_author(a: &Author) -> Self {
        Subject {
            login: a.login.clone(),
            fingerprint: a.fingerprint,
            nick: a.nick.clone(),
        }
    }

    fn of_line(line: &LogLine) -> Self {
        Subject {
            login: line.from_login.clone(),
            fingerprint: line.from_fingerprint,
            nick: line.from_nick.clone(),
        }
    }
}

/// What a report is filed against (§4.1, and `docs/news.md` §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportTarget {
    Line(LineId),
    Media(Handle),
    /// An inbox row, reported by its recipient.
    Msg(MessageId),
    /// A person, named by the report's [`Report::about`].
    User,
    Article(ArticleId),
}

impl ReportTarget {
    pub fn kind_i64(self) -> i64 {
        match self {
            ReportTarget::Line(_) => 1,
            ReportTarget::Media(_) => 2,
            ReportTarget::Msg(_) => 3,
            ReportTarget::User => 4,
            ReportTarget::Article(_) => 5,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ReportTarget::Line(_) => "line",
            ReportTarget::Media(_) => "media",
            ReportTarget::Msg(_) => "msg",
            ReportTarget::User => "user",
            ReportTarget::Article(_) => "article",
        }
    }
}

/// How a report was closed (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// A moderator redacted, revoked, purged or deleted what it named —
    /// or it was gone before anyone looked.
    Removed,
    Dismissed,
    Duplicate,
}

impl Outcome {
    pub fn as_i64(self) -> i64 {
        match self {
            Outcome::Removed => 1,
            Outcome::Dismissed => 2,
            Outcome::Duplicate => 3,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        Some(match n {
            1 => Outcome::Removed,
            2 => Outcome::Dismissed,
            3 => Outcome::Duplicate,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Outcome::Removed => "removed",
            Outcome::Dismissed => "dismissed",
            Outcome::Duplicate => "duplicate",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "removed" => Outcome::Removed,
            "dismissed" => Outcome::Dismissed,
            "duplicate" => Outcome::Duplicate,
            _ => return None,
        })
    }
}

/// A report's close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    pub at: SystemTime,
    pub by: String,
    pub outcome: Outcome,
    pub note: Option<String>,
    pub duplicate_of: Option<ReportId>,
}

/// One report. `id` is 0 until the store files it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub id: ReportId,
    pub at: SystemTime,
    /// `None` for a guest, who cannot be told the outcome later.
    pub reporter: Option<Mailbox>,
    pub target: ReportTarget,
    /// Whose the target is: the line's sender, the image's uploader, the
    /// message's sender, the article's author, or the person reported.
    pub about: Subject,
    pub reason: String,
    /// A private message's body, copied in at the moment of reporting,
    /// or what a reporter pasted.
    pub evidence: Option<String>,
    /// `false` when the evidence is only the reporter's word — pasted,
    /// rather than read out of the store (§4.2).
    pub verified: bool,
    /// The image the report makes a moderator's to see: the reported
    /// handle, or the one a reported chat line carried. Pinned and
    /// granted to moderators while the report is open (§4.3).
    pub media: Option<Handle>,
    pub closed: Option<Closed>,
}

impl Report {
    /// One line for a wire that has only text to carry it in — the
    /// legacy moderator's private message (§4.5):
    /// `[report #17] alice reported an image from bob: "…reason…"`.
    pub fn summary(&self) -> String {
        let reporter = self
            .reporter
            .as_ref()
            .map_or("a guest", |m| m.login.as_str());
        let about = self
            .about
            .login
            .as_deref()
            .filter(|l| !l.is_empty())
            .unwrap_or(if self.about.nick.is_empty() {
                "someone"
            } else {
                &self.about.nick
            });
        let what = match self.target {
            ReportTarget::Line(_) => "a chat line from ".to_string(),
            ReportTarget::Media(_) => "an image from ".to_string(),
            ReportTarget::Msg(_) => "a private message from ".to_string(),
            ReportTarget::User => String::new(),
            ReportTarget::Article(id) => format!("article #{id} by "),
        };
        let mut reason: String = self.reason.chars().take(200).collect();
        if reason.len() < self.reason.len() {
            reason.push('…');
        }
        format!(
            "[report #{}] {reporter} reported {what}{about}: \"{reason}\"",
            self.id
        )
    }
}

/// Which reports a listing wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFilter {
    Open,
    Closed,
    All,
}

impl ReportFilter {
    pub fn admits(self, r: &Report) -> bool {
        match self {
            ReportFilter::Open => r.closed.is_none(),
            ReportFilter::Closed => r.closed.is_some(),
            ReportFilter::All => true,
        }
    }
}

/// The audit trail and the reports. Synchronous, like every store the
/// domain holds, and called only off the roster lock.
pub trait ModerationStore: Send + Sync + 'static {
    /// Append an audit row; `act.id` is ignored.
    fn record(&self, act: &Act) -> Result<ActId, StoreError>;
    /// The trail, newest first, from before `before` (exclusive).
    fn acts(&self, before: Option<ActId>, limit: usize) -> Result<Vec<Act>, StoreError>;

    /// File a report; `report.id` is ignored. A report may arrive
    /// already closed — one against something already gone (§4.4).
    fn file(&self, report: &Report) -> Result<ReportId, StoreError>;
    fn report(&self, id: ReportId) -> Result<Option<Report>, StoreError>;
    /// Reports, newest first, from before `before` (exclusive).
    fn reports(
        &self,
        filter: ReportFilter,
        before: Option<ReportId>,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError>;
    fn open_count(&self) -> Result<usize, StoreError>;
    /// The open reports on `target`, oldest first. For
    /// [`ReportTarget::User`] that is every open report on a person; the
    /// caller narrows by [`Report::about`].
    fn open_on(&self, target: &ReportTarget) -> Result<Vec<Report>, StoreError>;
    /// Close an open report. `false` when there is no open report `id`.
    fn close(&self, id: ReportId, closed: &Closed) -> Result<bool, StoreError>;
    /// Does any open report hold this image ([`Report::media`])? What
    /// decides whether closing one unpins it.
    fn holds_media(&self, handle: &Handle) -> Result<bool, StoreError>;

    /// Refuse a canonical image hash from now on, in chat and in news
    /// (`docs/news.md` §11). Idempotent.
    fn block_hash(&self, hash: &[u8; 32], by: &str, at: SystemTime) -> Result<(), StoreError>;
    fn blocked_hashes(&self) -> Result<Vec<[u8; 32]>, StoreError>;

    /// Scrub the evidence of every act recorded before `before` to an
    /// empty string, leaving the rows (§3.1). Returns how many changed.
    /// A close's evidence is its outcome, not anything removed, and is
    /// kept.
    fn scrub_evidence(&self, before: SystemTime) -> Result<usize, StoreError>;
    /// Delete reports closed before `before`. Returns how many went.
    fn prune_reports(&self, before: SystemTime) -> Result<usize, StoreError>;
}

/// Why a moderation request did not happen. Each is a distinct ng error
/// code (§5); the mapping lives in the frontends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModError {
    /// This server keeps no moderation store, or not the thing named
    /// (no history to redact from, no media to revoke).
    Disabled,
    AccessDenied,
    BadRequest(&'static str),
    NoSuchLine,
    NoSuchMedia,
    NoSuchUser,
    NoSuchReport,
    /// A report's target does not exist, or is not the reporter's to
    /// name — one answer, so a report cannot probe for either.
    NoSuchTarget,
    /// The target holds cant-be-disconnected and the moderator does not
    /// hold delete-users (§2).
    Protected,
    /// A purge named a plain guest, who has no identity to select rows
    /// by. A kick with a purge still kicks.
    NoIdentity,
    /// A moderator may not close a report about themselves.
    OwnReport,
    RateLimited,
    NoSession,
    Store(StoreError),
}

impl From<StoreError> for ModError {
    fn from(e: StoreError) -> Self {
        warn!("moderation store: {e}");
        ModError::Store(e)
    }
}

/// Who is acting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    Session(Uid),
    /// The operator's command line: every act, on anyone, as [`OPERATOR`].
    Operator,
}

/// A person named by a request: on the roster, by account, or by key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersonRef {
    Uid(Uid),
    Login(String),
    Fingerprint([u8; 32]),
}

/// What a report is filed against, as a request names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportRequest {
    Line(LineId),
    Media(Handle),
    Msg(MessageId),
    User(PersonRef),
    Article(ArticleId),
}

/// What filing a report did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Filed {
    pub id: ReportId,
    /// `None` while it is open; `Removed` when what it named was
    /// already gone.
    pub outcome: Option<Outcome>,
    /// Whether the reporter will hear how it ends: a guest has no
    /// mailbox to be told at (§4.1).
    pub follow_up: bool,
}

/// What a purge took.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Purged {
    pub lines: Vec<LineId>,
    pub media: Vec<Handle>,
    pub articles: Vec<ArticleId>,
}

/// The acting principal, copied out of the roster.
#[derive(Debug, Clone)]
pub(crate) struct Acting {
    pub(crate) name: String,
    pub(crate) fingerprint: Option<[u8; 32]>,
    /// Holds delete-users, or is the operator: the ladder does not apply.
    pub(crate) overrides: bool,
    pub(crate) uid: Option<Uid>,
    /// Who the acting session is, as a report's subject would name them.
    /// `None` for the operator.
    pub(crate) person: Option<Subject>,
}

/// Who a report rate is kept against: a mailbox, or a guest's session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum ReporterKey {
    Mailbox(Option<[u8; 32]>, String),
    Session(Uid, u64),
    /// Every guest at one address, together: a guest who reconnects is a
    /// new session with a fresh ration, and the address is what stays.
    Addr(std::net::IpAddr),
}

/// Entries past which the report ration forgets full buckets.
const RATES_KEPT: usize = 4096;

fn days(n: u32) -> Duration {
    Duration::from_secs(u64::from(n) * 24 * 3600)
}

/// A reason: required, and bounded. "No reason" is a legitimate reason,
/// but it has to be typed (§3).
fn reason(text: &str, max: usize) -> Result<String, ModError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(ModError::BadRequest("A reason is required."));
    }
    if text.chars().count() > max {
        return Err(ModError::BadRequest("That reason is too long."));
    }
    Ok(text.to_string())
}

fn bounded(
    text: Option<String>,
    max: usize,
    what: &'static str,
) -> Result<Option<String>, ModError> {
    match text.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()) {
        Some(t) if t.chars().count() > max => Err(ModError::BadRequest(what)),
        other => Ok(other),
    }
}

fn line_evidence(line: &LogLine) -> String {
    format!("#{} {}: {}", line.id, line.from_nick, line.text)
}

impl Core {
    /// Give the domain its audit trail and reports. Without one, the
    /// acts and reports are answered as a server without the feature
    /// answers them. The durable block list is read into the media
    /// store here, so a restart does not forget a revocation.
    pub fn with_moderation(
        mut self,
        store: Arc<dyn ModerationStore>,
        policy: ModerationPolicy,
    ) -> Self {
        match store.blocked_hashes() {
            Ok(hashes) => self.media_block_hashes(hashes),
            Err(e) => warn!("moderation: the block list would not load: {e}"),
        }
        self.moderation = Some(store);
        self.moderation_policy = policy;
        self
    }

    pub fn moderation_enabled(&self) -> bool {
        self.moderation.is_some()
    }

    pub fn moderation_policy(&self) -> ModerationPolicy {
        self.moderation_policy
    }

    fn moderation_store(&self) -> Result<&Arc<dyn ModerationStore>, ModError> {
        self.moderation.as_ref().ok_or(ModError::Disabled)
    }

    /// May this session moderate?
    pub fn is_moderator(&self, uid: Uid) -> bool {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).is_some_and(|s| s.moderate)
    }

    /// Open reports, for a moderator's login badge (§4.5). `None` for
    /// anyone else, and on a server that keeps none.
    pub fn moderation_open(&self, uid: Uid) -> Option<usize> {
        let store = self.moderation.as_ref()?;
        if !self.is_moderator(uid) {
            return None;
        }
        match store.open_count() {
            Ok(n) => Some(n),
            Err(e) => {
                warn!("moderation store: {e}");
                Some(0)
            }
        }
    }

    pub(crate) fn acting(&self, by: Actor) -> Result<Acting, ModError> {
        match by {
            Actor::Operator => Ok(Acting {
                name: OPERATOR.into(),
                fingerprint: None,
                overrides: true,
                uid: None,
                person: None,
            }),
            Actor::Session(uid) => {
                let r = self.roster.lock().unwrap();
                let sess = r.users.get(&uid).ok_or(ModError::NoSession)?;
                if !sess.moderate {
                    return Err(ModError::AccessDenied);
                }
                Ok(Acting {
                    name: sess.login.clone(),
                    fingerprint: sess.identity,
                    overrides: sess.access.has(bit::DELETE_USERS),
                    uid: Some(uid),
                    person: Some(Subject {
                        login: sess.is_person.then(|| sess.login.clone()),
                        fingerprint: sess.identity,
                        nick: sess.info.nick.clone(),
                    }),
                })
            }
        }
    }

    /// Does the ladder protect `who` from `by` (§2)? Asked of every
    /// session the person holds, and of their account when they hold
    /// none — the author of a line is usually long gone.
    pub(crate) fn protected(&self, overrides: bool, who: Option<&Mailbox>) -> bool {
        if overrides {
            return false;
        }
        let Some(who) = who else {
            return false;
        };
        let on_roster = {
            let r = self.roster.lock().unwrap();
            r.users.values().any(|s| {
                !s.system
                    && s.access.has(bit::CANT_BE_DISCONNECTED)
                    && who.matches(&s.login, s.identity.as_ref())
            })
        };
        if on_roster {
            return true;
        }
        let Some(directory) = self.directory.as_ref() else {
            return false;
        };
        // Every account the person could be, whether or not it keeps a
        // mailbox: the one their key links, and the one their login
        // names — which covers rows written before the account linked
        // an identity. A login recycled since protects its new holder's
        // predecessor too, and over-protecting is this rule's safe side.
        let by_key = who
            .fingerprint
            .and_then(|fp| directory.account_by_key(&fp))
            .map(|(_, access)| access);
        let by_login = (!who.login.is_empty())
            .then(|| directory.account(&who.login))
            .flatten()
            .map(|(_, access)| access);
        [by_key, by_login, directory.mailbox_access(who)]
            .into_iter()
            .flatten()
            .any(|a| a.has(bit::CANT_BE_DISCONNECTED))
    }

    /// The account a login names, as the mailbox rule keys it: the one
    /// on the roster, else the account file whether or not it keeps
    /// mail.
    fn account_of_login(&self, login: &str) -> Option<Mailbox> {
        let on_roster = {
            let r = self.roster.lock().unwrap();
            r.users
                .values()
                .find(|s| s.visible && s.is_person && s.login == login)
                .map(|s| s.mailbox())
        };
        on_roster.or_else(|| Some(self.directory.as_ref()?.account(login)?.0))
    }

    /// The sessions of everyone who may moderate, and the principals an
    /// image grant hands each.
    fn moderators(&self) -> Vec<(Uid, Vec<Principal>)> {
        let r = self.roster.lock().unwrap();
        r.users
            .iter()
            .filter(|(_, s)| s.visible && s.moderate)
            .map(|(uid, s)| {
                let mut who = vec![Principal::Session {
                    uid: *uid,
                    serial: s.serial,
                }];
                if s.has_inbox {
                    who.push(Principal::Mailbox(s.mailbox()));
                }
                (*uid, who)
            })
            .collect()
    }

    // --- The acts (§3) ------------------------------------------------

    /// Redact a public line (§3.1): the audit row takes its words, the
    /// log keeps its id and time, and every reader is told to blank it.
    /// An image it carried is revoked in the same act.
    pub fn redact_line(&self, by: Actor, id: LineId, why: &str) -> Result<(), ModError> {
        let acting = self.acting(by)?;
        let why = reason(why, MAX_ACT_REASON)?;
        let store = self.moderation_store()?.clone();
        let log = self.history.as_ref().ok_or(ModError::Disabled)?;
        let line = log
            .line(id)?
            .filter(|l| l.channel == 0)
            .ok_or(ModError::NoSuchLine)?;
        if line.flags.contains(LineFlags::DELETED) {
            // Somebody got there first. Still an answer the reports on
            // it are owed.
            self.close_reports_on(&acting, &ReportTarget::Line(id), None);
            return Ok(());
        }
        let author = Subject::of_line(&line);
        if self.protected(acting.overrides, author.mailbox().as_ref()) {
            return Err(ModError::Protected);
        }
        let media = line
            .media
            .as_ref()
            .and_then(|m| Handle::try_from(m.id.as_slice()).ok());
        let record = media.as_ref().and_then(|h| self.media_record(h));
        let mut act = Act::new(ActKind::Redact, &acting, why).about(&author);
        act.line = Some(id);
        act.media = media;
        act.media_hash = record.as_ref().map(|r| r.hash);
        act.evidence = Some(line_evidence(&line));
        store.record(&act)?;

        self.tombstone_lines(&acting, &[id])?;
        if let (Some(handle), Some(record)) = (media, record) {
            self.revoke_quietly(&acting, &handle, record.hash, true);
            self.close_reports_on(&acting, &ReportTarget::Media(handle), None);
        }
        self.close_reports_on(&acting, &ReportTarget::Line(id), None);
        Ok(())
    }

    /// Revoke an image (§3.2): its bytes go now, and with `block` its
    /// canonical hash is refused from then on, in chat and in news.
    pub fn revoke_media(
        &self,
        by: Actor,
        handle: &Handle,
        why: &str,
        block: bool,
    ) -> Result<(), ModError> {
        let acting = self.acting(by)?;
        let why = reason(why, MAX_ACT_REASON)?;
        let store = self.moderation_store()?.clone();
        if !self.media_enabled() {
            return Err(ModError::Disabled);
        }
        let record = self.media_record(handle).ok_or(ModError::NoSuchMedia)?;
        let uploader = match &record.uploader {
            Some(m) => Subject::of_mailbox(m, record.uploader_login.clone()),
            None => Subject {
                nick: record.uploader_login.clone(),
                ..Subject::default()
            },
        };
        if self.protected(acting.overrides, record.uploader.as_ref()) {
            return Err(ModError::Protected);
        }
        let r = &record.reference;
        let mut act = Act::new(ActKind::Revoke, &acting, why).about(&uploader);
        act.media = Some(*handle);
        act.media_hash = Some(record.hash);
        act.evidence = Some(format!(
            "{} {}x{}, {} bytes, uploaded by {}",
            r.mime.mime(),
            r.width,
            r.height,
            r.bytes,
            record.uploader_login
        ));
        store.record(&act)?;
        self.revoke_quietly(&acting, handle, record.hash, block);
        self.close_reports_on(&acting, &ReportTarget::Media(*handle), None);
        Ok(())
    }

    /// Who a purge is of, as a mailbox and the name to show.
    fn resolve_person(&self, who: &PersonRef) -> Result<Subject, ModError> {
        match who {
            PersonRef::Uid(uid) => {
                let r = self.roster.lock().unwrap();
                let sess = r
                    .users
                    .get(uid)
                    .filter(|s| s.visible && !s.system)
                    .ok_or(ModError::NoSuchUser)?;
                if !(sess.is_person || sess.identity.is_some()) {
                    return Err(ModError::NoIdentity);
                }
                Ok(Subject {
                    login: sess.is_person.then(|| sess.login.clone()),
                    fingerprint: sess.identity,
                    nick: sess.info.nick.clone(),
                })
            }
            PersonRef::Login(login) => {
                let login = login.trim().to_ascii_lowercase();
                if login.is_empty() || login == "guest" || self.is_system_login(&login) {
                    return Err(ModError::NoSuchUser);
                }
                // The account's own view of its mailbox where it still
                // exists, so an identity-linked author is found by key
                // whether or not the account takes mail. A login that
                // names no account now can still name the rows someone
                // left under it.
                let mailbox = self
                    .account_of_login(&login)
                    .unwrap_or_else(|| Mailbox::login(login.clone()));
                Ok(Subject::of_mailbox(&mailbox, login))
            }
            PersonRef::Fingerprint(fp) => {
                let named = {
                    let r = self.roster.lock().unwrap();
                    r.users
                        .values()
                        .find(|s| s.visible && s.identity == Some(*fp))
                        .map(|s| (s.is_person.then(|| s.login.clone()), s.info.nick.clone()))
                };
                // Not here: the account the key links, for a name.
                let (login, nick) = named.unwrap_or_else(|| {
                    let login = self
                        .directory
                        .as_ref()
                        .and_then(|d| d.account_by_key(fp))
                        .map(|(m, _)| m.login)
                        .filter(|l| !l.is_empty());
                    (login.clone(), login.unwrap_or_default())
                });
                Ok(Subject {
                    login,
                    fingerprint: Some(*fp),
                    nick,
                })
            }
        }
    }

    /// What a purge of `who` over the last `within` would take, taking
    /// nothing: the operator's `--dry-run`, and the selection the purge
    /// itself acts on.
    pub fn purge_preview(&self, who: &PersonRef, within: Duration) -> Result<Purged, ModError> {
        let subject = self.resolve_person(who)?;
        let mailbox = subject.mailbox().ok_or(ModError::NoSuchUser)?;
        Ok(self.purge_selection(&mailbox, within)?.0)
    }

    fn purge_selection(
        &self,
        who: &Mailbox,
        within: Duration,
    ) -> Result<(Purged, Vec<LogLine>), ModError> {
        let since = SystemTime::now()
            .checked_sub(within)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let lines = match self.history.as_ref() {
            Some(log) => log.lines_by(0, who, since)?,
            None => Vec::new(),
        };
        let articles = match self.news.as_ref() {
            Some(news) => news.articles_by(who, since)?,
            None => Vec::new(),
        };
        Ok((
            Purged {
                lines: lines.iter().map(|l| l.id).collect(),
                media: self.media_uploaded_by(who, within),
                articles,
            },
            lines,
        ))
    }

    /// Purge a person (§3.3): every line they sent in the window is
    /// redacted, every image they uploaded in it revoked, every article
    /// they wrote in it deleted — by sender identity rather than by uid,
    /// because the sender may be gone and the uid someone else's. One
    /// audit row records the lot.
    pub fn purge_sender(
        &self,
        by: Actor,
        who: &PersonRef,
        within: Duration,
        why: &str,
    ) -> Result<Purged, ModError> {
        let acting = self.acting(by)?;
        let why = reason(why, MAX_ACT_REASON)?;
        let store = self.moderation_store()?.clone();
        let subject = self.resolve_person(who)?;
        let mailbox = subject.mailbox().ok_or(ModError::NoSuchUser)?;
        if self.protected(acting.overrides, Some(&mailbox)) {
            return Err(ModError::Protected);
        }
        let (purged, lines) = self.purge_selection(&mailbox, within)?;
        let mut evidence: Vec<String> = lines.iter().map(line_evidence).collect();
        if !purged.media.is_empty() {
            evidence.push(format!("{} images", purged.media.len()));
        }
        if !purged.articles.is_empty() {
            let ids: Vec<String> = purged.articles.iter().map(|a| format!("#{a}")).collect();
            evidence.push(format!("articles {}", ids.join(", ")));
        }
        let mut act = Act::new(ActKind::Purge, &acting, why).about(&subject);
        act.evidence = Some(evidence.join("\n"));
        store.record(&act)?;

        self.tombstone_lines(&acting, &purged.lines)?;
        for handle in &purged.media {
            if let Some(record) = self.media_record(handle) {
                self.revoke_quietly(&acting, handle, record.hash, true);
            }
            self.close_reports_on(&acting, &ReportTarget::Media(*handle), None);
        }
        if let Some(news) = self.news.as_ref() {
            let now = SystemTime::now();
            for id in &purged.articles {
                match news.tombstone(*id, &acting.name, now) {
                    Ok(Some(was)) => self.news_fan_out(Event::NewsDeleted {
                        id: *id,
                        category: was.category,
                    }),
                    Ok(None) => {}
                    Err(e) => warn!("purge: article {id}: {e}"),
                }
                self.close_reports_on(&acting, &ReportTarget::Article(*id), None);
            }
            if !purged.articles.is_empty() {
                self.news_remove_unreferenced(news);
            }
        }
        for id in &purged.lines {
            self.close_reports_on(&acting, &ReportTarget::Line(*id), None);
        }
        self.close_reports_on(&acting, &ReportTarget::User, Some(&mailbox));
        Ok(purged)
    }

    /// Tombstone lines and tell every reader, in log order with the
    /// sends: under the log's own lock, so a redaction can never reach a
    /// client ahead of the line it blanks.
    fn tombstone_lines(&self, acting: &Acting, ids: &[LineId]) -> Result<(), ModError> {
        if ids.is_empty() {
            return Ok(());
        }
        let log = self.history.as_ref().ok_or(ModError::Disabled)?;
        let _serial = self.log_serial.lock().unwrap();
        let now = SystemTime::now();
        let mut gone = Vec::with_capacity(ids.len());
        for id in ids {
            if log.tombstone(*id, &acting.name, now)? {
                gone.push(*id);
            }
        }
        let mut r = self.roster.lock().unwrap();
        for id in gone {
            r.broadcast_where(&Event::ChatRedacted { id }, None, reads_public_chat);
        }
        Ok(())
    }

    /// The bytes and, with `block`, the hash: in memory now, and in the
    /// durable list for the next start and for news.
    fn revoke_quietly(&self, acting: &Acting, handle: &Handle, hash: [u8; 32], block: bool) {
        self.media_revoke(handle, block);
        if block {
            if let Some(store) = self.moderation.as_ref() {
                if let Err(e) = store.block_hash(&hash, &acting.name, SystemTime::now()) {
                    warn!("moderation: a block would not persist: {e}");
                }
            }
        }
    }

    /// A delete of someone else's article is a moderation act
    /// (`docs/news.md` §11): the ladder first, then the audit row with
    /// the article's words, taken before the store clears them.
    pub(crate) fn news_moderation_check(&self, uid: Uid, author: &Author) -> Result<(), NewsError> {
        let overrides = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)
                .is_some_and(|s| s.access.has(bit::DELETE_USERS))
        };
        let who = Subject::of_author(author).mailbox();
        if self.protected(overrides, who.as_ref()) {
            return Err(NewsError::Protected);
        }
        Ok(())
    }

    /// The session as an actor, whether or not it may moderate: a news
    /// delete is the delete-articles bit's to allow, and is recorded all
    /// the same.
    fn session_acting(&self, uid: Uid) -> Option<Acting> {
        let r = self.roster.lock().unwrap();
        let sess = r.users.get(&uid)?;
        Some(Acting {
            name: sess.login.clone(),
            fingerprint: sess.identity,
            overrides: sess.access.has(bit::DELETE_USERS),
            uid: Some(uid),
            person: Some(Subject {
                login: sess.is_person.then(|| sess.login.clone()),
                fingerprint: sess.identity,
                nick: sess.info.nick.clone(),
            }),
        })
    }

    /// The audit row for a delete of someone else's article, from the
    /// article as the tombstone found it.
    pub(crate) fn news_moderation_record(
        &self,
        uid: Uid,
        article: &crate::news::Article,
        why: &str,
    ) {
        let Some(store) = self.moderation.as_ref() else {
            return;
        };
        let Some(acting) = self.session_acting(uid) else {
            return;
        };
        let mut evidence = format!("{}\n\n{}", article.subject, article.body);
        for a in &article.attachments {
            evidence.push_str(&format!(
                "\n[attachment {} {}x{}{}]",
                crate::media::handle_str(&a.id),
                a.width,
                a.height,
                a.name.as_ref().map(|n| format!(" {n}")).unwrap_or_default()
            ));
        }
        // The legacy wire carries no reason, and a period client's
        // delete should not be refused for lacking one.
        let mut act = Act::new(ActKind::NewsDelete, &acting, why.trim().to_string())
            .about(&Subject::of_author(&article.author));
        act.article = Some(article.id);
        act.evidence = Some(evidence);
        if let Err(e) = store.record(&act) {
            warn!("moderation store: {e}");
        }
    }

    pub(crate) fn news_moderation_closed(&self, uid: Uid, id: ArticleId) {
        if let Some(acting) = self.session_acting(uid) {
            self.close_reports_on(&acting, &ReportTarget::Article(id), None);
        }
    }

    /// Everything a category holds, tombstones and all, read before a
    /// delete takes it.
    pub(crate) fn news_category_contents(
        &self,
        store: &Arc<dyn crate::news::NewsStore>,
        id: crate::news::NodeId,
    ) -> Vec<crate::news::Listed> {
        store.listing(id, usize::MAX).unwrap_or_else(|e| {
            warn!("news: category {id} would not list before its delete: {e:?}");
            Vec::new()
        })
    }

    /// A category delete takes every article in it in one click, which
    /// is exactly what an audit trail is for: one row with the category's
    /// name, how many articles went and whose they were, and the reports
    /// waiting on any of them answered (`docs/news.md` §11). Not the
    /// articles' words — a category can hold thousands — and not the
    /// ladder, which a delete-categories holder is trusted above.
    pub(crate) fn news_node_moderation_record(
        &self,
        uid: Uid,
        node: &crate::news::Node,
        gone: u64,
        listed: &[crate::news::Listed],
    ) {
        let Some(store) = self.moderation.as_ref() else {
            return;
        };
        let Some(acting) = self.session_acting(uid) else {
            return;
        };
        let mut authors: Vec<(String, usize)> = Vec::new();
        for a in listed.iter().filter(|a| !a.deleted) {
            match authors.iter_mut().find(|(nick, _)| *nick == a.nick) {
                Some((_, n)) => *n += 1,
                None => authors.push((a.nick.clone(), 1)),
            }
        }
        authors.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let by: Vec<String> = authors
            .iter()
            .map(|(nick, n)| format!("{nick} ({n})"))
            .collect();
        let mut act = Act::new(ActKind::NodeDelete, &acting, String::new());
        act.evidence = Some(format!(
            "category {:?} (#{}): {gone} articles{}",
            node.name,
            node.id,
            if by.is_empty() {
                String::new()
            } else {
                format!(" by {}", by.join(", "))
            }
        ));
        if let Err(e) = store.record(&act) {
            warn!("moderation store: {e}");
        }
        for a in listed {
            self.close_reports_on(&acting, &ReportTarget::Article(a.id), None);
        }
    }

    // --- Reports (§4) -------------------------------------------------

    /// Take one report from every ration in `keys`, or from none of
    /// them: a guest pays from its session's and from its address's.
    fn report_rate_allows(&self, keys: &[ReporterKey]) -> bool {
        let per_hour = f64::from(REPORTS_PER_HOUR);
        let now = Instant::now();
        let refill = |at: Instant, tokens: f64| {
            (tokens + now.duration_since(at).as_secs_f64() * per_hour / 3600.0).min(per_hour)
        };
        let mut rates = self.report_rate.lock().unwrap();
        if rates.len() + keys.len() > RATES_KEPT {
            // Forget the buckets that have refilled: they hold nothing.
            rates.retain(|_, (at, tokens)| refill(*at, *tokens) < per_hour);
            if rates.len() + keys.len() > RATES_KEPT {
                // Still full of spent buckets: bounded memory beats a
                // perfect ration, as the system account's has it. The
                // address rations are what a flood runs into first.
                rates.clear();
            }
        }
        let allowed = keys.iter().all(|key| {
            rates
                .get(key)
                .is_none_or(|(at, tokens)| refill(*at, *tokens) >= 1.0)
        });
        if allowed {
            for key in keys {
                let (at, tokens) = rates.entry(key.clone()).or_insert((now, per_hour));
                *tokens = refill(*at, *tokens) - 1.0;
                *at = now;
            }
        }
        allowed
    }

    /// File a report (§4). Delivered to every moderator the moment it is
    /// filed; one against something already gone is closed as removed
    /// at once, so the reporter is told rather than ignored.
    pub fn report(
        &self,
        by: Uid,
        what: ReportRequest,
        why: &str,
        evidence: Option<String>,
    ) -> Result<Filed, ModError> {
        let store = self.moderation_store()?.clone();
        let why = reason(why, MAX_REPORT_REASON)?;
        let evidence = bounded(evidence, MAX_EVIDENCE, "That evidence is too long.")?;
        let (reporter, keys) = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&by).ok_or(ModError::NoSession)?;
            let mailbox = sess.has_inbox.then(|| sess.mailbox());
            // An account is one person, and people behind one address —
            // a household, an office — each have their own ration. A
            // guest is a session, and a new one is a reconnect away, so
            // its address pays as well.
            let keys = match &mailbox {
                Some(m) => vec![ReporterKey::Mailbox(m.fingerprint, m.login.clone())],
                None => std::iter::once(ReporterKey::Session(by, sess.serial))
                    .chain(sess.addr.map(ReporterKey::Addr))
                    .collect(),
            };
            (mailbox, keys)
        };

        let mut media = None;
        let (target, about, gone, evidence, verified) = match what {
            ReportRequest::Line(id) => {
                let log = self.history.as_ref().ok_or(ModError::Disabled)?;
                let line = log
                    .line(id)?
                    .filter(|l| l.channel == 0)
                    .ok_or(ModError::NoSuchTarget)?;
                let gone = line.flags.contains(LineFlags::DELETED);
                // The image a line carried is part of what was reported:
                // a moderator judging the line has to be able to see it.
                media = line
                    .media
                    .as_ref()
                    .and_then(|m| Handle::try_from(m.id.as_slice()).ok());
                (
                    ReportTarget::Line(id),
                    Subject::of_line(&line),
                    gone,
                    None,
                    true,
                )
            }
            ReportRequest::Media(handle) => {
                let record = self
                    .media_shown_to(by, &handle)
                    .ok_or(ModError::NoSuchTarget)?;
                let about = match &record.uploader {
                    Some(m) => Subject::of_mailbox(m, record.uploader_login.clone()),
                    None => Subject {
                        nick: record.uploader_login.clone(),
                        ..Subject::default()
                    },
                };
                let gone = record.reference.id.is_none();
                media = Some(handle);
                (ReportTarget::Media(handle), about, gone, None, true)
            }
            ReportRequest::Msg(id) => {
                // Only the recipient may show a moderator their mail,
                // and the store already scopes reads by mailbox (§4.2).
                let inbox = self.inbox.as_ref().ok_or(ModError::NoSuchTarget)?;
                let mine = reporter.as_ref().ok_or(ModError::NoSuchTarget)?;
                let msg = inbox
                    .list(mine, id.checked_add(1), 1)?
                    .into_iter()
                    .find(|m| m.id == id)
                    .ok_or(ModError::NoSuchTarget)?;
                let about = match &msg.sender {
                    Some(m) => Subject::of_mailbox(m, msg.sender_nick.clone()),
                    None => Subject {
                        nick: msg.sender_nick.clone(),
                        ..Subject::default()
                    },
                };
                (ReportTarget::Msg(id), about, false, Some(msg.body), true)
            }
            ReportRequest::User(who) => {
                let about = match &who {
                    PersonRef::Uid(uid) => {
                        let r = self.roster.lock().unwrap();
                        let sess = r
                            .users
                            .get(uid)
                            .filter(|s| s.visible && !s.system)
                            .ok_or(ModError::NoSuchTarget)?;
                        Subject {
                            login: sess.is_person.then(|| sess.login.clone()),
                            fingerprint: sess.identity,
                            nick: sess.info.nick.clone(),
                        }
                    }
                    PersonRef::Login(login) => {
                        let login = login.trim().to_ascii_lowercase();
                        if login.is_empty() || login == "guest" || self.is_system_login(&login) {
                            return Err(ModError::NoSuchTarget);
                        }
                        let mailbox = self
                            .account_of_login(&login)
                            .ok_or(ModError::NoSuchTarget)?;
                        Subject::of_mailbox(&mailbox, login)
                    }
                    PersonRef::Fingerprint(_) => self.resolve_person(&who)?,
                };
                // A pasted private message is the reporter's word, and
                // the moderator is shown that it is (§4.2).
                let verified = evidence.is_none();
                (ReportTarget::User, about, false, evidence, verified)
            }
            ReportRequest::Article(id) => {
                let article = self.news_article(by, id).map_err(|e| match e {
                    NewsError::Disabled => ModError::Disabled,
                    NewsError::AccessDenied => ModError::AccessDenied,
                    NewsError::NoSession => ModError::NoSession,
                    _ => ModError::NoSuchTarget,
                })?;
                (
                    ReportTarget::Article(id),
                    Subject::of_author(&article.author),
                    article.deleted,
                    None,
                    true,
                )
            }
        };

        // A second report of the same thing by the same reporter is the
        // first one, and costs nothing.
        if let Some(mine) = &reporter {
            let first = store.open_on(&target)?.into_iter().find(|r| {
                r.reporter
                    .as_ref()
                    .is_some_and(|m| mine.matches(&m.login, m.fingerprint.as_ref()))
                    && (target != ReportTarget::User || r.about.same_person(&about))
            });
            if let Some(first) = first {
                return Ok(Filed {
                    id: first.id,
                    outcome: None,
                    follow_up: true,
                });
            }
        }
        if !self.report_rate_allows(&keys) {
            return Err(ModError::RateLimited);
        }

        let now = SystemTime::now();
        let mut report = Report {
            id: 0,
            at: now,
            reporter: reporter.clone(),
            target,
            about,
            reason: why,
            evidence,
            verified,
            media,
            closed: gone.then(|| Closed {
                at: now,
                by: CLOSED_BY_SERVER.into(),
                outcome: Outcome::Removed,
                note: None,
                duplicate_of: None,
            }),
        };
        report.id = store.file(&report)?;
        if !gone {
            let moderators = self.moderators();
            // A moderator who cannot see what was reported cannot judge
            // it: the handle outlives its TTL while the report is open,
            // and moderators join its set — the one widening the media
            // design allows (§4.3).
            if let Some(handle) = media {
                // Nothing to hold once the bytes are gone; the pin and
                // the grant both refuse a dead handle themselves.
                self.media_pin(&handle, days(self.moderation_policy.pin_days));
                for (_, who) in &moderators {
                    for p in who {
                        self.media_grant(&handle, p.clone());
                    }
                }
            }
            let mut r = self.roster.lock().unwrap();
            for (uid, _) in &moderators {
                r.send_to(*uid, Event::Report(report.clone()));
            }
        }
        Ok(Filed {
            id: report.id,
            outcome: gone.then_some(Outcome::Removed),
            follow_up: reporter.is_some(),
        })
    }

    /// Reports, newest first, for a moderator. Listing an open image
    /// report grants the moderator the image, so one who was not online
    /// when it was filed can still see what they are judging.
    pub fn reports(
        &self,
        by: Actor,
        filter: ReportFilter,
        before: Option<ReportId>,
        limit: usize,
    ) -> Result<(Vec<Report>, bool), ModError> {
        let acting = self.acting(by)?;
        let store = self.moderation_store()?;
        let limit = limit.clamp(1, 100);
        let mut page = store.reports(filter, before, limit + 1)?;
        let more = page.len() > limit;
        page.truncate(limit);
        if let Some(uid) = acting.uid {
            let who = self
                .moderators()
                .into_iter()
                .find(|(u, _)| *u == uid)
                .map(|(_, who)| who)
                .unwrap_or_default();
            for handle in page
                .iter()
                .filter(|r| r.closed.is_none())
                .filter_map(|r| r.media)
            {
                for p in &who {
                    self.media_grant(&handle, p.clone());
                }
            }
        }
        Ok((page, more))
    }

    /// Close a report as dismissed, or as a duplicate of another (§4.4).
    /// `removed` is not a thing a moderator says: it is what an act
    /// does.
    pub fn report_close(
        &self,
        by: Actor,
        id: ReportId,
        outcome: Outcome,
        note: Option<String>,
        of: Option<ReportId>,
    ) -> Result<(), ModError> {
        let acting = self.acting(by)?;
        let store = self.moderation_store()?.clone();
        let note = bounded(note, MAX_NOTE, "That note is too long.")?;
        let duplicate_of = match (outcome, of) {
            (Outcome::Removed, _) => {
                return Err(ModError::BadRequest(
                    "A report is closed as removed by removing what it names.",
                ))
            }
            (Outcome::Duplicate, None) => {
                return Err(ModError::BadRequest(
                    "A duplicate names the report it repeats.",
                ))
            }
            (Outcome::Duplicate, Some(of)) if of == id => {
                return Err(ModError::BadRequest("A report cannot repeat itself."))
            }
            (Outcome::Duplicate, Some(of)) => {
                store.report(of)?.ok_or(ModError::NoSuchReport)?;
                Some(of)
            }
            (Outcome::Dismissed, _) => None,
        };
        let report = store.report(id)?.ok_or(ModError::NoSuchReport)?;
        if report.closed.is_some() {
            return Err(ModError::BadRequest("That report is closed already."));
        }
        // Nobody dismisses a report about themselves: that is another
        // moderator's judgment, or the operator's. Closing by removing
        // what was reported is still open to them — an act is its own
        // record, and it removes rather than excuses.
        if let Some(me) = acting.person.as_ref() {
            if report.about.same_person(me) {
                return Err(ModError::OwnReport);
            }
        }
        let closed = Closed {
            at: SystemTime::now(),
            by: acting.name.clone(),
            outcome,
            note: note.clone(),
            duplicate_of,
        };
        // The close first, and the audit row only for a close that
        // happened: two moderators closing one report at once must not
        // leave a row for the one that lost.
        if !store.close(id, &closed)? {
            return Err(ModError::BadRequest("That report is closed already."));
        }
        let mut act =
            Act::new(ActKind::Close, &acting, note.unwrap_or_default()).about(&report.about);
        act.report = Some(id);
        act.evidence = Some(outcome.name().into());
        if let Err(e) = store.record(&act) {
            warn!("moderation: report #{id} closed and not recorded: {e}");
        }
        // The pin was for the moderator's judgment, which is in — unless
        // another open report still asks for the same image.
        if let Some(handle) = report.media {
            if !store.holds_media(&handle)? {
                self.media_unpin(&handle);
            }
        }
        self.announce_closed(&report, outcome);
        Ok(())
    }

    /// Close every open report on `target` as removed — what an act does
    /// to the reports that asked for it. For a person, only the reports
    /// `about` them.
    fn close_reports_on(&self, acting: &Acting, target: &ReportTarget, about: Option<&Mailbox>) {
        let Some(store) = self.moderation.as_ref() else {
            return;
        };
        let open = match store.open_on(target) {
            Ok(open) => open,
            Err(e) => {
                warn!("moderation store: {e}");
                return;
            }
        };
        for report in open {
            if let Some(who) = about {
                let theirs = report
                    .about
                    .mailbox()
                    .is_some_and(|m| who.matches(&m.login, m.fingerprint.as_ref()));
                if !theirs {
                    continue;
                }
            }
            let closed = Closed {
                at: SystemTime::now(),
                by: acting.name.clone(),
                outcome: Outcome::Removed,
                note: None,
                duplicate_of: None,
            };
            match store.close(report.id, &closed) {
                Ok(true) => self.announce_closed(&report, Outcome::Removed),
                Ok(false) => {}
                Err(e) => warn!("moderation store: {e}"),
            }
        }
    }

    /// `report_closed`: to the reporter, if they have a mailbox and a
    /// session, and to the moderators (§5).
    fn announce_closed(&self, report: &Report, outcome: Outcome) {
        let mut r = self.roster.lock().unwrap();
        let reporter: HashSet<Uid> = report
            .reporter
            .as_ref()
            .map(|m| crate::chat::sessions_of(&r, m).into_iter().collect())
            .unwrap_or_default();
        let moderators: Vec<Uid> = r
            .users
            .iter()
            .filter(|(uid, s)| s.visible && s.moderate && !reporter.contains(uid))
            .map(|(uid, _)| *uid)
            .collect();
        for uid in reporter {
            r.send_to(
                uid,
                Event::ReportClosed {
                    id: report.id,
                    outcome,
                    yours: true,
                },
            );
        }
        for uid in moderators {
            r.send_to(
                uid,
                Event::ReportClosed {
                    id: report.id,
                    outcome,
                    yours: false,
                },
            );
        }
    }

    /// The audit trail, newest first, for a moderator.
    pub fn moderation_log(
        &self,
        by: Actor,
        before: Option<ActId>,
        limit: usize,
    ) -> Result<(Vec<Act>, bool), ModError> {
        self.acting(by)?;
        let store = self.moderation_store()?;
        let limit = limit.clamp(1, 100);
        let mut page = store.acts(before, limit + 1)?;
        let more = page.len() > limit;
        page.truncate(limit);
        Ok((page, more))
    }

    /// The sweeper's work (§3.1, §4.4): evidence past its window is
    /// scrubbed, closed reports past theirs deleted. Returns both counts.
    pub fn prune_moderation(&self) -> (usize, usize) {
        let Some(store) = self.moderation.as_ref() else {
            return (0, 0);
        };
        let now = SystemTime::now();
        let before = |d: u32| now.checked_sub(days(d)).unwrap_or(SystemTime::UNIX_EPOCH);
        let policy = self.moderation_policy;
        let scrubbed = if policy.evidence_days == 0 {
            0
        } else {
            store
                .scrub_evidence(before(policy.evidence_days))
                .unwrap_or_else(|e| {
                    warn!("moderation evidence scrub: {e}");
                    0
                })
        };
        let pruned = if policy.report_days == 0 {
            0
        } else {
            store
                .prune_reports(before(policy.report_days))
                .unwrap_or_else(|e| {
                    warn!("moderation report retention: {e}");
                    0
                })
        };
        (scrubbed, pruned)
    }
}

/// The report ration's map type, named for `Core`'s field.
pub(crate) type ReportRates = HashMap<ReporterKey, (Instant, f64)>;

#[cfg(test)]
mod tests;
