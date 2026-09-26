//! Server assembly: configuration file, context wiring, and the accept
//! loop. `main.rs` is a thin CLI over this; the integration tests drive
//! [`build_ctx`] + `hxd_session::serve` directly on an ephemeral port.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use hl_identity::ServerKey;
use hxd_auth_file::FileAuth;
use hxd_core::{Core, LinkAuthority, Transport};
use hxd_ng_session::{
    ForwardedHeader, IdentityConfig, IdentityState, NewAccounts, NgConfig, NgCtx, Registry,
    TrustedProxies, TunnelSink, TunnelStream, Unattested,
};
use hxd_session::{cap, Caps, ServerConfig, ServerCtx, TrtpLogin};
use serde::Deserialize;

pub mod banner;
pub mod files;
pub mod moderation;
pub mod push;
pub mod registrar;
pub mod tls;
pub mod voice;
pub use files::Files;
pub use push::Push;
pub use voice::Voice;
pub mod tracker;

/// The `hxd-ng.toml` schema. Everything has a default; an absent file is a
/// runnable server.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub paths: PathsSection,
    /// The Hotline-ng WebSocket frontend. Absent = disabled.
    pub ng: Option<NgSection>,
    /// Voice chat. Absent = disabled, which is the spec's default and
    /// the right one for a subsystem that opens a UDP port.
    pub voice: Option<VoiceSection>,
    /// Portable identity (`docs/hotline-ng-identity.md`). Absent =
    /// disabled: no identity endpoints, no TRTP tunnel path. Needs `[ng]`.
    pub identity: Option<IdentitySection>,
    /// The durable private-message inbox. Absent = disabled, and then
    /// private messaging behaves exactly as it did before there was one.
    pub inbox: Option<InboxSection>,
    /// Server-held public-chat scrollback. Absent = disabled.
    pub history: Option<HistorySection>,
    /// Inline media (`docs/inline-media.md` §11). Absent = disabled: no
    /// capability bit 3 on the legacy wire, no `media` cap on the ng
    /// one, and no `/media` routes.
    pub media: Option<MediaSection>,
    /// Threaded news (`docs/news.md` §13). Absent = no news on either
    /// wire, answered the way a server without the feature answers.
    pub news: Option<NewsSection>,
    /// Manifest-backed or capability-rooted local files. Absent means no Files capability,
    /// control transactions, transfer listener, or ng download routes.
    pub files: Option<FilesSection>,
    /// UDP registration with Hotline trackers. Absent = the server stays
    /// unlisted and opens no registration sockets.
    pub tracker: Option<tracker::TrackerSection>,
    /// The reserved server account (`docs/system-account.md`). Absent =
    /// no account on the roster, and a private message is a private
    /// message on every wire.
    pub system: Option<SystemSection>,
    /// Web Push notifications (`docs/webpush-gateway.md` §8). Absent =
    /// no gateway, no `push` capability, and `push_register` answered
    /// `not_available`.
    pub push: Option<PushSection>,
    /// The identity registrar (`docs/identity-registrar.md` §11). Absent
    /// = not a registrar: discovery's `registrar` block is `null` and
    /// the `/registrar` routes 404. Needs `[identity]`.
    pub registrar: Option<registrar::RegistrarSection>,
    /// Moderation's retention and legacy behavior
    /// (`docs/moderation.md` §7). Absent = the defaults: moderation is
    /// always on, its trail kept in the database `[inbox]`, `[history]`
    /// or `[news]` names, and in memory on a server with none.
    pub moderation: Option<moderation::ModerationSection>,
    /// The legacy wire over TLS, on a port of its own. Absent = the
    /// plaintext port only, as every Hotline server has always had.
    pub tls: Option<tls::TlsSection>,
    /// The server banner. Absent = none, as on a server that never had
    /// one: the login reply's banner id is 0 either way.
    pub banner: Option<banner::BannerSection>,
}

/// `[push]`: where a notification goes when nobody is watching.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushSection {
    /// The VAPID `sub`: a `mailto:` or `https:` URL a push service can
    /// reach the operator at. Not decoration — a service may refuse a
    /// push without one, so it is required rather than defaulted.
    pub contact: String,
    /// How much of a message leaves the server: `full`, `sender` or
    /// `generic`. On Web Push the payload is encrypted to the device's
    /// own key and the push service cannot read it, which is what makes
    /// `full` a defensible default elsewhere; `sender` is the default
    /// here because a notification on a lock screen is read by whoever
    /// is looking at it.
    #[serde(default = "default_push_content")]
    pub content: String,
    /// The server's VAPID keypair. Created on first start with
    /// owner-only permissions, and never replaced: every subscription on
    /// the server is bound to it.
    #[serde(default = "default_vapid_key")]
    pub vapid_key: PathBuf,
    /// Where the devices are kept. Defaults to the file `[inbox]`,
    /// `[history]` or `[news]` names, in that order, which it then
    /// shares; with none of those it is required.
    pub db: Option<PathBuf>,
    /// Seconds to wait for a push service before giving up on one
    /// notification.
    #[serde(default = "default_push_timeout")]
    pub timeout: u64,
    /// How long a push service should hold a private message's
    /// notification for a device that is offline.
    #[serde(default = "default_message_ttl")]
    pub message_ttl: u64,
    /// The same for a news notice, which is worth much less by tomorrow.
    #[serde(default = "default_news_ttl")]
    pub news_ttl: u64,
    /// Consecutive failures before an origin is skipped outright.
    #[serde(default = "default_breaker_failures")]
    pub breaker_failures: u32,
    /// Seconds it stays skipped, after which one probe is let through.
    #[serde(default = "default_breaker_cooldown")]
    pub breaker_cooldown: u64,
    /// Pushes in flight at once, across every account.
    #[serde(default = "default_max_inflight")]
    pub max_inflight: usize,
    /// Pushes in flight at once to any one push service, so that one
    /// answering slowly cannot hold every permit.
    #[serde(default = "default_max_inflight_per_origin")]
    pub max_inflight_per_origin: usize,
    /// Devices one account may register. Past it a new one is refused
    /// `too_many_devices`; one it already has may always re-register.
    #[serde(default = "default_max_devices")]
    pub max_devices: usize,
    /// For the operator running their own push service on a private
    /// network, and for nobody else.
    #[serde(default)]
    pub allow_private_endpoints: bool,
}

fn default_push_content() -> String {
    "sender".into()
}
fn default_vapid_key() -> PathBuf {
    PathBuf::from("vapid.key")
}
fn default_push_timeout() -> u64 {
    10
}
fn default_message_ttl() -> u64 {
    4 * 7 * 24 * 60 * 60
}
fn default_news_ttl() -> u64 {
    24 * 60 * 60
}
fn default_breaker_failures() -> u32 {
    5
}
fn default_breaker_cooldown() -> u64 {
    60
}
fn default_max_inflight() -> usize {
    64
}
fn default_max_inflight_per_origin() -> usize {
    8
}
fn default_max_devices() -> usize {
    hxd_core::push::DEFAULT_MAX_DEVICES
}

/// `[system]`: the account commands are addressed to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSection {
    /// The reserved login. Nobody can authenticate as it, whatever
    /// account file of that name a migrated server may have.
    #[serde(default = "default_system_login")]
    pub login: String,
    /// What the roster shows.
    #[serde(default = "default_system_nick")]
    pub nick: String,
    #[serde(default)]
    pub icon: u16,
    /// Parse private messages to it. Off, it stays on the roster as the
    /// account notifications come from, and answers every message with
    /// one line saying commands are off.
    #[serde(default = "default_true")]
    pub commands: bool,
    /// Commands a minute, per session.
    #[serde(default = "default_system_rate")]
    pub rate: u32,
}

fn default_system_login() -> String {
    hxd_core::SystemPolicy::default().login
}
fn default_system_nick() -> String {
    hxd_core::SystemPolicy::default().nick
}
fn default_system_rate() -> u32 {
    hxd_core::SystemPolicy::default().rate
}

impl SystemSection {
    pub fn to_policy(&self) -> hxd_core::SystemPolicy {
        hxd_core::SystemPolicy {
            login: self.login.to_ascii_lowercase(),
            nick: self.nick.clone(),
            icon: self.icon,
            commands: self.commands,
            rate: self.rate,
        }
    }

    fn check(&self) -> Result<(), String> {
        if self.login.trim().is_empty() {
            return Err("[system] login must be a login".into());
        }
        if self.nick.trim().is_empty() {
            return Err("[system] nick must be a name".into());
        }
        Ok(())
    }
}

/// The Files service (`docs/files-plan.md`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesSection {
    /// Local JSON manifest. Must be paired with `origin` and excludes `root`.
    pub manifest: Option<PathBuf>,
    /// Fixed HTTP(S) base URL. Must be paired with `manifest` and excludes `root`.
    pub origin: Option<String>,
    /// Capability root for a writable local file area. Excludes manifest mode.
    pub root: Option<PathBuf>,
    /// HTXF listener. Omitted means the legacy control port plus one.
    pub bind: Option<String>,
    #[serde(default = "default_files_max_size")]
    pub max_file_size: u64,
    #[serde(default = "default_files_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_files_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_files_max_partial_bytes")]
    pub max_partial_bytes: u64,
    #[serde(default = "default_files_max_partials")]
    pub max_partials: usize,
    #[serde(default = "default_files_max_partials_per_account")]
    pub max_partials_per_account: usize,
    #[serde(default = "default_files_request_timeout")]
    pub request_timeout: u64,
    #[serde(default = "default_files_reference_ttl")]
    pub reference_ttl: u64,
    #[serde(default = "default_files_max_references")]
    pub max_references: usize,
    #[serde(default = "default_files_max_references_per_session")]
    pub max_references_per_session: usize,
    #[serde(default = "default_files_max_references_per_account")]
    pub max_references_per_account: usize,
    #[serde(default = "default_files_download_ttl")]
    pub download_ttl: u64,
    #[serde(default = "default_files_max_downloads")]
    pub max_downloads: usize,
    #[serde(default = "default_files_max_downloads_per_session")]
    pub max_downloads_per_session: usize,
    #[serde(default = "default_files_max_downloads_per_account")]
    pub max_downloads_per_account: usize,
    #[serde(default = "default_files_handshake_timeout")]
    pub handshake_timeout: u64,
    /// Seconds a download may make no progress toward its receiver, on
    /// either wire, before it is abandoned.
    #[serde(default = "default_files_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default = "default_files_partial_ttl")]
    pub partial_ttl: u64,
    #[serde(default = "default_files_upload_timeout")]
    pub upload_timeout: u64,
}

fn default_files_max_size() -> u64 {
    64 * 1024 * 1024 * 1024
}
fn default_files_max_entries() -> usize {
    100_000
}
fn default_files_max_concurrent() -> usize {
    8
}
fn default_files_max_partial_bytes() -> u64 {
    64 * 1024 * 1024 * 1024
}
fn default_files_max_partials() -> usize {
    1_024
}
fn default_files_max_partials_per_account() -> usize {
    4
}
fn default_files_request_timeout() -> u64 {
    15
}
fn default_files_reference_ttl() -> u64 {
    60
}
fn default_files_max_references() -> usize {
    4096
}
fn default_files_max_references_per_session() -> usize {
    64
}
fn default_files_max_references_per_account() -> usize {
    256
}
fn default_files_download_ttl() -> u64 {
    60
}
fn default_files_max_downloads() -> usize {
    4096
}
fn default_files_max_downloads_per_session() -> usize {
    64
}
fn default_files_max_downloads_per_account() -> usize {
    256
}
fn default_files_handshake_timeout() -> u64 {
    10
}
fn default_files_idle_timeout() -> u64 {
    60
}
fn default_files_partial_ttl() -> u64 {
    7 * 24 * 60 * 60
}
fn default_files_upload_timeout() -> u64 {
    60 * 60
}

/// Threaded news (`docs/news.md` §13).
///
/// Only the keys this build acts on: naming another is a startup error
/// rather than a promise the server quietly does not keep.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewsSection {
    /// The SQLite file. May be omitted when `[inbox]` or `[history]`
    /// names one; the sections then share it and one connection.
    pub db: Option<PathBuf>,
    /// Filesystem root for durable content-addressed attachment bytes.
    #[serde(default = "default_news_blobs")]
    pub blobs: PathBuf,
    /// The legacy `NEWSDATA` ceiling. ↓ freely, ↑ never: 65 535 is what
    /// the 1.5 wire can carry in one chunk (§12.4).
    #[serde(default = "default_news_max_body")]
    pub max_body: usize,
    /// The 1.5 pstring: 255 at most.
    #[serde(default = "default_news_max_subject")]
    pub max_subject: usize,
    /// `"render"` (markdown accepted, and parsed for the plain-text
    /// downgrade), `"source"` (accepted and stored, nothing parsed) or
    /// `"off"` (§5.5). The default is `"render"` in a build with the
    /// `markdown` feature and `"off"` in one without, where asking for
    /// `"render"` is a startup error.
    #[serde(default = "default_news_markdown")]
    pub markdown: String,
    /// References recorded per article; past that they stay as text.
    #[serde(default = "default_news_max_refs")]
    pub max_refs: usize,
    /// Reply nesting.
    #[serde(default = "default_news_max_depth")]
    pub max_depth: u16,
    /// Bundle nesting.
    #[serde(default = "default_news_max_node_depth")]
    pub max_node_depth: u16,
    /// The largest page of threads one request may ask for.
    #[serde(default = "default_news_max_page")]
    pub max_page: usize,
    /// Days a thread survives its last post. 0 keeps everything.
    #[serde(default)]
    pub retain_days: u32,
    /// May an author delete their own article? `false` is the period
    /// behavior, where only `delete_articles` can.
    #[serde(default = "default_true")]
    pub self_delete: bool,
    /// Answer `news_search`. `false` turns the request off and leaves the
    /// index alone — it is kept either way, so turning search back on
    /// needs no rebuild.
    #[serde(default = "default_true")]
    pub search: bool,
    /// The deepest a search pages, and the count past which a total is
    /// reported as capped.
    #[serde(default = "default_news_search_max_results")]
    pub search_max_results: usize,
    /// Searches per session per minute.
    #[serde(default = "default_news_search_per_minute")]
    pub search_per_minute: u32,
    /// `[news.notify]`: subscriptions and the notifications they earn
    /// (§10). Absent = neither; present, even empty, = the defaults.
    #[serde(default)]
    pub notify: Option<NewsNotifySection>,
    /// `[news.attach]`: durable image staging and article attachments.
    #[serde(default)]
    pub attach: Option<NewsAttachSection>,
    /// The most articles one 1.5 category listing carries (§12.3). The
    /// listing is one chunk, so 65 535 bytes may decide first.
    #[serde(default = "default_news_legacy_catlist_max")]
    pub legacy_catlist_max: usize,
    /// The category 1.2 clients read and post into (§12.5), by its names
    /// from the root with `/` between. Absent: a 1.2 client is told this
    /// server's news is threaded. A category whose own name contains `/`
    /// cannot be named here; rename it, or pick another.
    #[serde(default)]
    pub flat_category: Option<String>,
    /// The most entries in the 1.2 document; 65 535 bytes usually decides
    /// first.
    #[serde(default = "default_news_flat_articles")]
    pub flat_articles: usize,
    /// Where a 1.2 post with no `Re:` goes: `"newest_thread"` (under the
    /// root of the newest live thread) or `"new_thread"` (a thread of its
    /// own, for an announcements feed).
    #[serde(default = "default_news_flat_reply")]
    pub flat_reply: String,
    /// The subject of a post whose body gives none to derive: a 1.2
    /// post, or a 1.5 one that sends no subject, flat view or not.
    #[serde(default = "default_news_flat_default_subject")]
    pub flat_default_subject: String,
    /// The line above the 1.2 document's entries. Absent: a built-in one
    /// naming the category and the two headers. `""`: none at all. At
    /// most `hxd_session::news::MASTHEAD_MAX` bytes.
    #[serde(default)]
    pub flat_masthead: Option<String>,
}

fn default_news_legacy_catlist_max() -> usize {
    hxd_session::LegacyNews::default().catlist_max
}
fn default_news_flat_articles() -> usize {
    100
}
fn default_news_flat_reply() -> String {
    "newest_thread".into()
}
fn default_news_flat_default_subject() -> String {
    "(no subject)".into()
}

/// `flat_category`'s names, root first.
fn flat_names(path: &str) -> Vec<String> {
    path.split('/')
        .map(|name| name.trim().to_string())
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewsAttachSection {
    #[serde(default = "default_news_attach_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_news_attach_max_count")]
    pub max_count: usize,
    #[serde(default = "default_news_attach_max_total_bytes")]
    pub max_total_bytes: u64,
    #[serde(default = "default_news_attach_stage_ttl")]
    pub stage_ttl: u64,
    #[serde(default = "default_news_attach_per_hour")]
    pub per_hour: u32,
    #[serde(default = "default_true")]
    pub legacy_derivative: bool,
}

fn default_news_blobs() -> PathBuf {
    PathBuf::from("news-blobs")
}
fn default_news_attach_max_bytes() -> usize {
    2 * 1024 * 1024
}
fn default_news_attach_max_count() -> usize {
    8
}
fn default_news_attach_max_total_bytes() -> u64 {
    8 * 1024 * 1024 * 1024
}
fn default_news_attach_stage_ttl() -> u64 {
    1800
}
fn default_news_attach_per_hour() -> u32 {
    20
}

/// `[news.notify]` (`docs/news.md` §10, §13). Needs no feature and no
/// gateway: without `[push]` an attached client still gets its badge, and
/// only the doorbell for an absent one is missing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewsNotifySection {
    /// `"participated"` (posting anything in a thread follows it),
    /// `"own_thread"`, or `"off"`.
    #[serde(default = "default_news_auto_subscribe")]
    pub auto_subscribe: String,
    /// Does citing someone's article notify them?
    #[serde(default = "default_true")]
    pub reference: bool,
    /// Threads and categories one account may follow or mute.
    #[serde(default = "default_news_max_subs")]
    pub max_subs: usize,
    /// News pushes per account per hour, every scope together. 0 is
    /// badges and events with no pushes at all.
    #[serde(default = "default_news_max_per_hour")]
    pub max_per_hour: u32,
    /// Seconds a scope may stay un-caught-up before it rings anyway
    /// (§10.7). Without it a client that never marks anything seen hears
    /// about a scope once and never again. 0 disables the floor.
    #[serde(default = "default_news_stale_after")]
    pub stale_after: u64,
}

fn default_news_auto_subscribe() -> String {
    hxd_core::NotifyPolicy::default()
        .auto_subscribe
        .name()
        .into()
}
fn default_news_max_subs() -> usize {
    hxd_core::NotifyPolicy::default().max_subs
}
fn default_news_max_per_hour() -> u32 {
    hxd_core::NotifyPolicy::default().max_per_hour
}
fn default_news_stale_after() -> u64 {
    hxd_core::NotifyPolicy::default().stale_after.as_secs()
}

impl NewsSection {
    pub fn to_policy(&self) -> hxd_core::NewsPolicy {
        hxd_core::NewsPolicy {
            max_body: self.max_body,
            max_subject: self.max_subject,
            max_refs: self.max_refs,
            max_depth: self.max_depth,
            max_node_depth: self.max_node_depth,
            max_page: self.max_page,
            self_delete: self.self_delete,
            retain_days: self.retain_days,
            search: self.search,
            search_max_results: self.search_max_results,
            search_per_minute: self.search_per_minute,
            notify: self.notify.as_ref().map(|n| hxd_core::NotifyPolicy {
                // `check` has refused any other spelling by now.
                auto_subscribe: hxd_core::AutoSubscribe::from_name(&n.auto_subscribe)
                    .unwrap_or(hxd_core::AutoSubscribe::Participated),
                reference: n.reference,
                max_subs: n.max_subs,
                max_per_hour: n.max_per_hour,
                stale_after: Duration::from_secs(n.stale_after),
            }),
            markdown: hxd_core::MarkdownMode::from_name(&self.markdown)
                .unwrap_or(hxd_core::MarkdownMode::Off),
            attach: self.attach.as_ref().map(|a| hxd_core::AttachmentPolicy {
                max_bytes: a.max_bytes,
                max_count: a.max_count,
                max_total_bytes: a.max_total_bytes,
                stage_ttl: Duration::from_secs(a.stage_ttl),
                per_hour: a.per_hour,
                legacy_derivative: a.legacy_derivative,
            }),
        }
    }

    /// How `[news]` reaches the legacy wire (§12).
    pub fn to_legacy(&self) -> hxd_session::LegacyNews {
        hxd_session::LegacyNews {
            catlist_max: self.legacy_catlist_max,
            default_subject: self.flat_default_subject.clone(),
            flat: self
                .flat_category
                .as_deref()
                .map(|path| hxd_session::FlatNews {
                    category: flat_names(path),
                    articles: self.flat_articles,
                    // `check` has refused any other spelling by now.
                    reply: hxd_session::FlatReply::from_name(&self.flat_reply)
                        .unwrap_or(hxd_session::FlatReply::NewestThread),
                    masthead: self.flat_masthead.clone(),
                }),
        }
    }

    /// The numbers a `Deserialize` cannot check. Each bound is a wire's:
    /// a body or subject past the legacy one is an article a 1.5 client
    /// truncates, and a page past the ng one is a request nobody sends.
    fn check(&self) -> Result<(), String> {
        match self.markdown.as_str() {
            "off" | "source" => {}
            "render" if cfg!(feature = "markdown") => {}
            "render" => {
                return Err(
                    "[news] markdown = \"render\": this build has no markdown parser \
                     (built without the `markdown` feature); \"source\" stores markdown \
                     without one"
                        .into(),
                )
            }
            other => {
                return Err(format!(
                    "[news] markdown = {other:?}: it is \"render\", \"source\" or \"off\""
                ))
            }
        }
        if !(1..=65_535).contains(&self.max_body) {
            return Err("[news] max_body must be between 1 and 65535".into());
        }
        if !(1..=255).contains(&self.max_subject) {
            return Err("[news] max_subject must be between 1 and 255".into());
        }
        if self.max_refs > 256 {
            return Err("[news] max_refs must be at most 256".into());
        }
        if !(1..=64).contains(&self.max_depth) {
            return Err("[news] max_depth must be between 1 and 64".into());
        }
        if !(1..=32).contains(&self.max_node_depth) {
            return Err("[news] max_node_depth must be between 1 and 32".into());
        }
        if !(1..=200).contains(&self.max_page) {
            return Err("[news] max_page must be between 1 and 200".into());
        }
        // Zero is not "unlimited" in either: one reaches no result at all,
        // the other answers no search ever.
        if !(1..=10_000).contains(&self.search_max_results) {
            return Err("[news] search_max_results must be between 1 and 10000".into());
        }
        if !(1..=600).contains(&self.search_per_minute) {
            return Err("[news] search_per_minute must be between 1 and 600".into());
        }
        if !(1..=10_000).contains(&self.legacy_catlist_max) {
            return Err("[news] legacy_catlist_max must be between 1 and 10000".into());
        }
        if let Some(path) = &self.flat_category {
            let names = flat_names(path);
            if names.iter().any(|name| name.is_empty()) {
                return Err(format!(
                    "[news] flat_category = {path:?}: it is a category's names from \
                     the root, with / between"
                ));
            }
        }
        if !(1..=1000).contains(&self.flat_articles) {
            return Err("[news] flat_articles must be between 1 and 1000".into());
        }
        // The document it heads is one chunk, and a masthead near it
        // would leave no room for the news.
        if self
            .flat_masthead
            .as_ref()
            .is_some_and(|m| m.len() > hxd_session::news::MASTHEAD_MAX)
        {
            return Err(format!(
                "[news] flat_masthead must be at most {} bytes: it heads a document \
                 that is one 65535-byte chunk, and the news needs the room",
                hxd_session::news::MASTHEAD_MAX
            ));
        }
        if hxd_session::FlatReply::from_name(&self.flat_reply).is_none() {
            return Err(format!(
                "[news] flat_reply = {:?}: it is \"newest_thread\" or \"new_thread\"",
                self.flat_reply
            ));
        }
        let subject = self.flat_default_subject.trim();
        if subject.is_empty()
            || subject.len() > self.max_subject
            || subject.chars().any(char::is_control)
        {
            return Err(
                "[news] flat_default_subject must be one line, and no longer than max_subject"
                    .into(),
            );
        }
        if let Some(notify) = &self.notify {
            if hxd_core::AutoSubscribe::from_name(&notify.auto_subscribe).is_none() {
                return Err(format!(
                    "[news.notify] auto_subscribe = {:?}: it is \"participated\", \
                     \"own_thread\" or \"off\"",
                    notify.auto_subscribe
                ));
            }
            // Zero would be a section that turns subscriptions on and then
            // lets nobody hold one.
            if !(1..=10_000).contains(&notify.max_subs) {
                return Err("[news.notify] max_subs must be between 1 and 10000".into());
            }
            if notify.max_per_hour > 3600 {
                return Err("[news.notify] max_per_hour must be at most 3600".into());
            }
        }
        if let Some(attach) = &self.attach {
            if !cfg!(feature = "media") {
                return Err(
                    "[news.attach] is configured, but this build has no image pipeline \
                     (built without the `media` feature)"
                        .into(),
                );
            }
            if attach.max_bytes == 0
                || attach.max_count == 0
                || attach.max_total_bytes == 0
                || attach.stage_ttl == 0
                || attach.per_hour == 0
            {
                return Err("[news.attach] limits must all be greater than zero".into());
            }
        }
        Ok(())
    }
}

fn default_news_search_max_results() -> usize {
    hxd_core::NewsPolicy::default().search_max_results
}
fn default_news_search_per_minute() -> u32 {
    hxd_core::NewsPolicy::default().search_per_minute
}

fn default_news_max_body() -> usize {
    hxd_core::NewsPolicy::default().max_body
}
fn default_news_max_subject() -> usize {
    hxd_core::NewsPolicy::default().max_subject
}
fn default_news_markdown() -> String {
    if cfg!(feature = "markdown") {
        "render"
    } else {
        "off"
    }
    .into()
}
fn default_news_max_refs() -> usize {
    hxd_core::NewsPolicy::default().max_refs
}
fn default_news_max_depth() -> u16 {
    hxd_core::NewsPolicy::default().max_depth
}
fn default_news_max_node_depth() -> u16 {
    hxd_core::NewsPolicy::default().max_node_depth
}
fn default_news_max_page() -> usize {
    hxd_core::NewsPolicy::default().max_page
}

/// Inline media (`docs/inline-media.md` §11).
///
/// Every figure here is the spec's recommended default. Tightening any
/// of them is free; relaxing one is the operator saying they know what
/// it costs, which is why the comments name the direction rather than
/// just the number.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaSection {
    /// The largest upload accepted, before canonicalization. ↓ freely.
    #[serde(default = "default_media_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_media_max_dimension")]
    pub max_dimension: u32,
    #[serde(default = "default_media_max_pixels")]
    pub max_pixels: u64,
    #[serde(default = "default_media_max_frames")]
    pub max_frames: u32,
    #[serde(default = "default_media_max_duration")]
    pub max_duration_ms: u32,
    /// How many images may be decoded at once. A decode holds a blocking
    /// thread and cannot be interrupted, so this is what bounds the
    /// damage a slow one does.
    #[serde(default = "default_media_decodes")]
    pub max_concurrent_decodes: usize,
    /// How long a handle answers, in seconds. The spec's clients are
    /// told not to cache handles across sessions, so this is a ceiling
    /// rather than a promise.
    #[serde(default = "default_media_ttl")]
    pub handle_ttl: u64,
    /// Canonical bytes held across every live handle. When an upload
    /// would cross it the oldest handles go, because evicting an old
    /// image beats refusing a new one.
    #[serde(default = "default_media_total")]
    pub max_total_bytes: usize,
    /// Whether reading a line out of the chat log grants the reader the
    /// image that line carried: `"recipients"` (the spec's answer, and
    /// the default) or `"readers"` (public chat only). See
    /// `docs/inline-media.md` §5.4.
    #[serde(default = "default_history_access")]
    pub history_access: String,
    #[serde(default)]
    pub rate: MediaRateSection,
}

/// `[media.rate]` — the quotas, all of them per hour except where the
/// name says otherwise.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaRateSection {
    /// Seconds between one account's uploads.
    #[serde(default = "default_upload_interval")]
    pub upload_interval: u64,
    #[serde(default = "default_upload_per_hour")]
    pub upload_per_hour: u32,
    /// Every guest shares the `guest` account's bucket, so this is what
    /// tells two guests apart.
    #[serde(default = "default_upload_per_hour_per_addr")]
    pub upload_per_hour_per_addr: u32,
    /// Downloads per minute, per session.
    #[serde(default = "default_download_per_minute")]
    pub download_per_minute: u32,
    /// Chunked uploads one account may have in flight at once.
    #[serde(default = "default_upload_sessions")]
    pub upload_sessions: usize,
}

impl Default for MediaRateSection {
    fn default() -> Self {
        MediaRateSection {
            upload_interval: default_upload_interval(),
            upload_per_hour: default_upload_per_hour(),
            upload_per_hour_per_addr: default_upload_per_hour_per_addr(),
            download_per_minute: default_download_per_minute(),
            upload_sessions: default_upload_sessions(),
        }
    }
}

impl MediaSection {
    /// The domain's view of this section, with the two halves — what the
    /// store enforces and what the codec does — filled from one place so
    /// no wire can advertise a number the pipeline does not hold.
    pub fn to_media_config(&self) -> Result<hxd_core::MediaConfig, String> {
        let history_access = match self.history_access.as_str() {
            "recipients" => hxd_core::HistoryAccess::Recipients,
            "readers" => hxd_core::HistoryAccess::Readers,
            other => {
                return Err(format!(
                    "[media] history_access: {other:?} is not one of \"recipients\", \"readers\""
                ))
            }
        };
        let defaults = hxd_core::CodecLimits::default();
        Ok(hxd_core::MediaConfig {
            max_bytes: self.max_bytes,
            handle_ttl: Duration::from_secs(self.handle_ttl),
            max_total_bytes: self.max_total_bytes,
            upload_interval: Duration::from_secs(self.rate.upload_interval),
            upload_per_hour: self.rate.upload_per_hour,
            upload_per_hour_per_addr: self.rate.upload_per_hour_per_addr,
            download_per_minute: self.rate.download_per_minute,
            upload_sessions: self.rate.upload_sessions,
            upload_idle: Duration::from_secs(30),
            history_access,
            codec: hxd_core::CodecLimits {
                max_bytes: self.max_bytes,
                max_dimension: self.max_dimension,
                max_pixels: self.max_pixels,
                max_frames: self.max_frames,
                max_duration_ms: self.max_duration_ms,
                max_concurrent_decodes: self.max_concurrent_decodes,
                ..defaults
            },
        })
    }
}

fn default_media_max_bytes() -> usize {
    256 * 1024
}

fn default_media_max_dimension() -> u32 {
    2048
}

fn default_media_max_pixels() -> u64 {
    2048 * 2048
}

fn default_media_max_frames() -> u32 {
    150
}

fn default_media_max_duration() -> u32 {
    15_000
}

fn default_media_decodes() -> usize {
    2
}

fn default_media_ttl() -> u64 {
    24 * 60 * 60
}

fn default_media_total() -> usize {
    256 * 1024 * 1024
}

fn default_history_access() -> String {
    "recipients".into()
}

fn default_upload_interval() -> u64 {
    10
}

fn default_upload_per_hour() -> u32 {
    30
}

fn default_upload_per_hour_per_addr() -> u32 {
    100
}

fn default_download_per_minute() -> u32 {
    60
}

fn default_upload_sessions() -> usize {
    2
}

/// Public chat history (`docs/chat-history.md` §9).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySection {
    /// SQLite file. May be omitted when `[inbox]` exists; both then share
    /// the inbox database and one connection.
    pub db: Option<PathBuf>,
    #[serde(default = "default_history_max_lines")]
    pub max_lines: u32,
    #[serde(default)]
    pub max_days: u32,
    #[serde(default = "default_history_max_page")]
    pub max_page: usize,
    #[serde(default)]
    pub replay: usize,
}

/// The private-message inbox (docs/private-messages.md §8).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxSection {
    /// The SQLite file. Required — naming it is what turns the inbox on.
    ///
    /// **It holds every private message on this server in the clear**, so
    /// give it the same treatment as the accounts directory: readable by
    /// the server user and nobody else.
    pub db: PathBuf,
    /// Messages one account may have *waiting* before further sends to
    /// it are refused. A full mailbox refuses rather than evicting, so a
    /// sender is never told a message was delivered that then quietly
    /// disappeared.
    ///
    /// Queue depth, not unread count: a message the recipient already has
    /// and hasn't marked read is not congestion, and counting it would
    /// let a client that never marks anything read lock its own mailbox.
    #[serde(default = "default_max_queued")]
    pub max_queued: usize,
    /// How many queued messages one flush hands a client. The cap is for
    /// the legacy wire, where each private message opens a window; what
    /// is left waits for the next login rather than being dropped.
    #[serde(default = "default_deliver_at_flush")]
    pub deliver_at_flush: usize,
    /// Seconds an *unread* message is kept, measured from when it was
    /// sent. Default 30 days.
    #[serde(default = "default_retain_unread")]
    pub retain_unread: u64,
    /// Seconds a *read* message is kept, measured from when it was read.
    /// Default 7 days.
    #[serde(default = "default_retain_read")]
    pub retain_read: u64,
    /// How hard a commit tries to survive the machine losing power.
    /// `normal` survives a process crash and not a power cut; `full`
    /// fsyncs every commit.
    #[serde(default)]
    pub sync: InboxSync,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InboxSync {
    #[default]
    Normal,
    Full,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceSection {
    /// UDP listen address for WebRTC media. Default: the legacy bind
    /// address with the spec's base-port-plus-four.
    pub bind: Option<String>,
    /// The addresses clients should be told to send media to — the
    /// server's ICE candidates. Defaults to `bind` when that names a
    /// concrete address; required when it doesn't, because ICE-lite
    /// gives a client nothing else to go on. List both a v4 and a v6
    /// address to serve both.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// The spec's `VoiceMaxPerRoom`, capped at [`MAX_PER_ROOM_CEILING`]
    /// because the participant list has to fit on the legacy wire.
    #[serde(
        default = "default_max_per_room",
        deserialize_with = "deserialize_max_per_room"
    )]
    pub max_per_room: usize,
    /// Video chat. Absent = disabled, which is the video spec's
    /// `EnableVideo` default.
    ///
    /// It lives **inside** `[voice]` rather than beside it because video
    /// is layered on voice and shares its transport: the same peer
    /// connection, the same UDP port, the same room. A `[video]` section
    /// of its own would suggest there is a second thing to bind, and
    /// there isn't.
    pub video: Option<VideoSection>,
}

/// The largest `[voice] max_per_room` this server will accept.
///
/// The hard limit is the legacy wire's. A room's membership is sent as
/// the `DATA_VOICE_PARTICIPANTS` chunk, six bytes per participant, and a
/// Hotline chunk carries a `u16` length — so 10,922 participants is the
/// point at which `hxd_session::frame::pack_frame` can no longer encode
/// the blob at all. That limit is enforced by an assertion in a spawned
/// writer task, which is the worst place to hit it: the process lives,
/// that one connection's writer dies, and the session goes on reading
/// frames and answering none of them.
///
/// So the ceiling sits an order of magnitude below it. 4096 participants
/// is 24 KiB of blob against a 64 KiB chunk, which leaves the rest of the
/// frame — the cid, and whatever else a future notification carries
/// beside the roster — room it doesn't have to account for, and it is
/// still far past any room a human would speak in. The spec's default is
/// 16.
pub const MAX_PER_ROOM_CEILING: usize = 4096;

/// Refuse a `max_per_room` the wire can't carry, rather than clamping it.
///
/// A bad value here is a config error like any other in this file: the
/// video limits are `u16` and a `70000` in the TOML is rejected by serde
/// with the field named, and [`Config::load`] refuses a broken file
/// outright instead of half-configuring a server. Silently serving 4096
/// when the operator wrote 50000 would be the same kind of quiet
/// disagreement between config and behaviour that the cap exists to
/// prevent.
fn deserialize_max_per_room<'de, D>(d: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let n = usize::deserialize(d)?;
    if n > MAX_PER_ROOM_CEILING {
        return Err(serde::de::Error::custom(format!(
            "[voice] max_per_room {n} is above the {MAX_PER_ROOM_CEILING} this server \
             can send a room's participant list for"
        )));
    }
    Ok(n)
}

impl VoiceSection {
    /// The per-kind ceilings this section describes.
    pub fn video_config(&self) -> hxd_core::VideoConfig {
        self.video.as_ref().map_or_else(
            hxd_core::VideoConfig::default,
            VideoSection::to_video_config,
        )
    }
}

/// The video ceilings, named after the spec's settings table
/// (`VideoMaxWidth`, `ScreenMaxFPS` and friends) so the two can be read
/// side by side.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoSection {
    /// `VideoMaxCamerasPerRoom` — simultaneous camera publications.
    #[serde(default = "default_max_cameras")]
    pub max_cameras_per_room: u16,
    /// `VideoMaxScreensPerRoom`. One by default: a second sharer is
    /// refused rather than preempting the first, and operators who want
    /// a free-for-all raise it.
    #[serde(default = "default_max_screens")]
    pub max_screens_per_room: u16,
    #[serde(default = "default_video_width")]
    pub max_width: u16,
    #[serde(default = "default_video_height")]
    pub max_height: u16,
    #[serde(default = "default_video_fps")]
    pub max_fps: u16,
    /// Bits per second.
    #[serde(default = "default_video_bitrate")]
    pub max_bitrate: u32,
    #[serde(default = "default_screen_width")]
    pub screen_max_width: u16,
    #[serde(default = "default_screen_height")]
    pub screen_max_height: u16,
    /// Lower than the camera's on purpose, and the resolution higher: a
    /// shared desktop is mostly still and wants detail, a face moves and
    /// doesn't.
    #[serde(default = "default_screen_fps")]
    pub screen_max_fps: u16,
    #[serde(default = "default_screen_bitrate")]
    pub screen_max_bitrate: u32,
}

impl VideoSection {
    fn to_video_config(&self) -> hxd_core::VideoConfig {
        hxd_core::VideoConfig {
            camera: hxd_core::VideoLimits {
                max_width: self.max_width,
                max_height: self.max_height,
                max_fps: self.max_fps,
                max_bitrate: self.max_bitrate,
                max_per_room: self.max_cameras_per_room,
            },
            screen: hxd_core::VideoLimits {
                max_width: self.screen_max_width,
                max_height: self.screen_max_height,
                max_fps: self.screen_max_fps,
                max_bitrate: self.screen_max_bitrate,
                max_per_room: self.max_screens_per_room,
            },
        }
    }
}

fn default_max_per_room() -> usize {
    hxd_core::DEFAULT_MAX_PER_ROOM
}
fn default_max_cameras() -> u16 {
    hxd_core::VideoLimits::CAMERA.max_per_room
}
fn default_max_screens() -> u16 {
    hxd_core::VideoLimits::SCREEN.max_per_room
}
fn default_video_width() -> u16 {
    hxd_core::VideoLimits::CAMERA.max_width
}
fn default_video_height() -> u16 {
    hxd_core::VideoLimits::CAMERA.max_height
}
fn default_video_fps() -> u16 {
    hxd_core::VideoLimits::CAMERA.max_fps
}
fn default_video_bitrate() -> u32 {
    hxd_core::VideoLimits::CAMERA.max_bitrate
}
fn default_screen_width() -> u16 {
    hxd_core::VideoLimits::SCREEN.max_width
}
fn default_screen_height() -> u16 {
    hxd_core::VideoLimits::SCREEN.max_height
}
fn default_screen_fps() -> u16 {
    hxd_core::VideoLimits::SCREEN.max_fps
}
fn default_screen_bitrate() -> u32 {
    hxd_core::VideoLimits::SCREEN.max_bitrate
}

/// `[identity]`, per `docs/hotline-ng-identity.md` §12.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Where the server's Ed25519 seed lives; generated on first run.
    #[serde(default = "default_identity_key")]
    pub key: PathBuf,
    /// `deny`, `guest`, or `create` (spec §8.1).
    #[serde(default = "default_new_accounts")]
    pub new_accounts: String,
    /// Fingerprints or handles; non-empty restricts identity login to
    /// these.
    #[serde(default)]
    pub allow_list: Vec<String>,
    #[serde(default)]
    pub min_attestation_age: u64,
    /// `deny`, `guest`, or `allow`.
    #[serde(default = "default_unattested")]
    pub unattested: String,
    /// Registrar host → base64url public key. Static until the registrar
    /// spec's discovery fetch exists.
    #[serde(default)]
    pub registrar_keys: HashMap<String, String>,
    #[serde(default = "default_clock_skew")]
    pub clock_skew: u64,
    /// Serve the TRTP-over-WebSocket path.
    #[serde(default = "default_true")]
    pub trtp: bool,
    /// `verify` or `trust` (spec §8.3): how a tunnelled classic login
    /// reconciles with the socket's identity.
    #[serde(default = "default_trtp_login")]
    pub trtp_login: String,
    /// Access bits for accounts made by `new_accounts = create`, as
    /// `[identity.default_access]` with the same key names as an account
    /// file's `[access]`. Absent means "whatever the guest account has",
    /// resolved at creation.
    #[serde(default)]
    pub default_access: Option<HashMap<String, bool>>,
    /// Ceiling on accounts `new_accounts = create` may write per hour.
    /// 0 disables creation; past the ceiling identities are admitted as
    /// guests. Only meaningful with `new_accounts = create`.
    #[serde(default = "default_max_new_accounts")]
    pub max_new_accounts_per_hour: usize,
    /// Where successor commitments (§3.4) are kept across restarts.
    /// Set it to `""` to keep them per-process, which the threat model
    /// calls the weaker mode: a restart forgets the commitment, and
    /// making the caches forget is the attack it exists to stop.
    #[serde(default = "default_anchors")]
    pub successors: PathBuf,
    /// Identity fingerprints refused by hand, every device of each
    /// (`docs/identity-registrar.md`). Consulted before anything
    /// else, and needs no registrar. Re-read on SIGHUP, which also ends
    /// the sessions a new entry refuses.
    #[serde(default)]
    pub revoked_identities: Vec<String>,
    /// Device fingerprints refused by hand: one stolen device, leaving
    /// the identity's others in. Re-read on SIGHUP with the other list.
    #[serde(default)]
    pub revoked_devices: Vec<String>,
    /// Serve the enrollment mailbox (`docs/identity-enrollment.md` §10).
    /// Off, the routes 404 and discovery omits the endpoint, so a device
    /// enrolls by the paste as before.
    #[serde(default = "default_true")]
    pub enroll: bool,
    /// Open enrollment sessions at once, server-wide.
    #[serde(default = "default_enroll_sessions")]
    pub enroll_sessions: usize,
    /// Open sessions and pending requests per source address.
    #[serde(default = "default_enroll_per_address")]
    pub enroll_per_address: usize,
    /// Where a web client for this server lives, advertised in discovery
    /// so a holder can render a QR code that opens it with the pairing
    /// code already filled in (§5.6). Absent means the holder prints the
    /// code alone, which is not a lesser flow, only a slower one.
    #[serde(default)]
    pub web: Option<String>,
}

fn default_enroll_sessions() -> usize {
    256
}
fn default_enroll_per_address() -> usize {
    4
}

fn default_identity_key() -> PathBuf {
    "identity-server.key".into()
}
fn default_new_accounts() -> String {
    "guest".into()
}
fn default_unattested() -> String {
    "guest".into()
}
fn default_clock_skew() -> u64 {
    300
}
fn default_true() -> bool {
    true
}
fn default_max_new_accounts() -> usize {
    60
}
fn default_anchors() -> PathBuf {
    "identity-successors".into()
}
fn default_trtp_login() -> String {
    "verify".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NgSection {
    /// Listen address for the WebSocket endpoint. Plaintext — production
    /// puts a TLS-terminating reverse proxy in front (docs/hotline-ng.md).
    #[serde(default = "default_ng_bind")]
    pub bind: String,
    /// Seconds a detached session survives without a connection.
    #[serde(default = "default_grace")]
    pub grace: u64,
    /// Detached-sessions-per-address backstop.
    #[serde(default = "default_max_detached")]
    pub max_detached_per_addr: usize,
    /// Reverse-proxy addresses whose `X-Hotline-Client-Cert` header is
    /// believed (docs/hotline-ng-auth.md §6.3). Empty = mTLS binding off.
    /// Single addresses or CIDR blocks, e.g. `["127.0.0.1", "10.0.0.0/8"]`.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Which header a trusted proxy writes the client's address into
    /// (docs/hotline-ng-auth.md §6.3): `"x-forwarded-for"` (the default),
    /// `"forwarded"`, or `"none"` to believe neither.
    #[serde(default = "default_forwarded_header")]
    pub forwarded_header: String,
}

fn default_forwarded_header() -> String {
    "x-forwarded-for".into()
}

fn default_ng_bind() -> String {
    "127.0.0.1:5700".into()
}
fn default_grace() -> u64 {
    300
}
fn default_max_detached() -> usize {
    2
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// Listen address.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// Advertised server name.
    #[serde(default = "default_name")]
    pub name: String,
    /// Advertised server version; 0 mimics a pre-1.5 server (no agreement
    /// flow, uid-only login reply).
    #[serde(default = "default_version")]
    pub version: u16,
    /// Seconds a connection may take to complete its login.
    #[serde(default = "default_login_timeout")]
    pub login_timeout: u64,
    /// Seconds a kick-with-ban keeps the address banned.
    #[serde(default = "default_ban_time")]
    pub ban_time: u64,
    /// Set the cleartext marker bit in legacy user flags for unencrypted
    /// sessions (docs/hotline-ng-auth.md §8). Off until proven against every 1.x
    /// client we care about.
    #[serde(default)]
    pub mark_cleartext: bool,
    /// Mark a private message that waited in the inbox with the time it
    /// was sent, on the legacy wire (the ng wire carries `at` and
    /// `queued` as fields and renders them itself).
    #[serde(default = "default_stamp_queued")]
    pub stamp_queued: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsSection {
    /// Accounts directory (one TOML per account). Created with a guest
    /// account on first run.
    #[serde(default = "default_accounts")]
    pub accounts: PathBuf,
    /// Agreement text file (UTF-8). Optional; absent = no agreement.
    pub agreement: Option<PathBuf>,
}

fn default_bind() -> String {
    "0.0.0.0:5500".into()
}
fn default_name() -> String {
    "hxd-ng".into()
}
fn default_version() -> u16 {
    185
}
fn default_login_timeout() -> u64 {
    10
}
fn default_ban_time() -> u64 {
    1800
}
fn default_accounts() -> PathBuf {
    "accounts".into()
}
fn default_stamp_queued() -> bool {
    true
}
fn default_max_queued() -> usize {
    200
}
fn default_deliver_at_flush() -> usize {
    25
}
fn default_retain_unread() -> u64 {
    30 * 24 * 3600
}
fn default_retain_read() -> u64 {
    7 * 24 * 3600
}
fn default_history_max_lines() -> u32 {
    10_000
}
fn default_history_max_page() -> usize {
    200
}

impl Default for ServerSection {
    fn default() -> Self {
        ServerSection {
            bind: default_bind(),
            name: default_name(),
            version: default_version(),
            login_timeout: default_login_timeout(),
            ban_time: default_ban_time(),
            mark_cleartext: false,
            stamp_queued: default_stamp_queued(),
        }
    }
}

impl Default for PathsSection {
    fn default() -> Self {
        PathsSection {
            accounts: default_accounts(),
            agreement: None,
        }
    }
}

impl Config {
    /// Load from a TOML file; a missing file yields the defaults, a broken
    /// one is an error (never silently half-configure a server).
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }
}

/// The `DATA_CAPABILITIES` bits this build can honor for a legacy
/// session. A capability lands here only once the code behind it is
/// wired and enabled — never from a config key alone, because the echo
/// is a promise that the extension's transactions will work.
fn legacy_caps(config: &Config, voice: Option<&Voice>, files: Option<&Files>) -> Caps {
    // Text-Encoding has nothing to wire: the domain is UTF-8 already, and
    // the session only has to stop converting. So it is always offered.
    let mut caps = Caps::empty().with(cap::TEXT_ENCODING);
    if config.history.is_some() {
        caps = caps.with(cap::CHAT_HISTORY);
    }
    if config.media.is_some() && cfg!(feature = "media") {
        caps = caps.with(cap::INLINE_MEDIA);
    }
    if voice.is_some() {
        caps = caps.with(cap::VOICE);
        // Bit 10 never without bit 2, and never from a config key alone:
        // an SFU has to be wired in for a video start to work, and the
        // echo is a promise that it will.
        if video_enabled(config) {
            caps = caps.with(cap::VIDEO);
        }
    }
    if files.is_some() {
        caps = caps.with(cap::LARGE_FILES);
    }
    caps
}

/// Is video both configured and servable? `[voice.video]` present, with
/// a `[voice]` section that actually produced an SFU.
fn video_enabled(config: &Config) -> bool {
    config.voice.as_ref().is_some_and(|v| v.video.is_some())
}

/// The same answer for the ng wire, where capabilities are names rather
/// than bits. Kept beside [`legacy_caps`] so the two wires can't drift
/// into advertising different things.
fn ng_caps(config: &Config, voice: Option<&Voice>, files: Option<&Files>) -> Vec<String> {
    let mut caps = Vec::new();
    if config.history.is_some() {
        caps.push("history".to_string());
    }
    if voice.is_some() {
        caps.push("voice".to_string());
        // As on the classic wire, `"video"` never appears without
        // `"voice"` — which this ordering makes structural rather than a
        // rule to remember.
        if video_enabled(config) {
            caps.push("video".to_string());
        }
    }
    if config.inbox.is_some() {
        caps.push("inbox".to_string());
    }
    // `media` is also pushed by the login reply when a pipeline is
    // configured, which is what a server built without the feature
    // relies on; naming it here keeps the two wires' lists side by side.
    if config.media.is_some() && cfg!(feature = "media") {
        caps.push("media".to_string());
    }
    // ng only for now: the legacy news transactions are `docs/news.md`
    // W9, and 1.5 clients have never needed a capability bit for news.
    if config.news.is_some() && cfg!(feature = "inbox") {
        caps.push("news".to_string());
    }
    if files.is_some() {
        caps.push("files".to_string());
    }
    caps
}

/// Give the domain an image pipeline when `[media]` asks for one.
#[cfg(feature = "media")]
fn with_media(core: Core, config: &Config) -> Result<Core, String> {
    let media = config
        .media
        .as_ref()
        .map(|m| m.to_media_config())
        .transpose()?;
    // One pipeline, and so one decode budget, for the whole server. News
    // attachments take a larger upload than chat and get their own byte
    // ceiling over the same limits and permits, so `[media]`'s caps and
    // `max_concurrent_decodes` hold for both (`docs/news.md` §7.1).
    let codec = hxd_media::Codec::new(media.as_ref().map_or_else(Default::default, |m| m.codec));
    let core = with_news_attachments(core, config, &codec)?;
    Ok(match media {
        Some(cfg) => core.with_media(Arc::new(codec), cfg),
        None => core,
    })
}

#[cfg(all(feature = "media", feature = "inbox"))]
fn with_news_attachments(
    core: Core,
    config: &Config,
    codec: &hxd_media::Codec,
) -> Result<Core, String> {
    let Some(news) = config.news.as_ref() else {
        return Ok(core);
    };
    let Some(attach) = news.attach.as_ref() else {
        return Ok(core);
    };
    let blobs = hxd_store_sqlite::FileBlobStore::open(&news.blobs)
        .map_err(|e| format!("{}: {e}", news.blobs.display()))?;
    Ok(core.with_news_attachments(
        Arc::new(blobs),
        Arc::new(codec.with_max_bytes(attach.max_bytes)),
    ))
}

#[cfg(all(feature = "media", not(feature = "inbox")))]
fn with_news_attachments(
    core: Core,
    config: &Config,
    _codec: &hxd_media::Codec,
) -> Result<Core, String> {
    if config.news.as_ref().is_some_and(|n| n.attach.is_some()) {
        return Err("[news.attach] requires the `media` and `inbox` features".into());
    }
    Ok(core)
}

/// The parser behind `[news] markdown = "render"`. Only then: `"source"`
/// is the reading for an operator who does not want one running.
#[cfg(feature = "markdown")]
fn with_markdown(core: Core, config: &Config) -> Core {
    match config.news.as_ref().map(|n| n.markdown.as_str()) {
        Some("render") => core.with_body_renderer(Arc::new(hxd_markdown::Markdown)),
        _ => core,
    }
}

/// Without the feature there is nothing to give it, and `check` has
/// already refused a config that asked for `"render"`.
#[cfg(not(feature = "markdown"))]
fn with_markdown(core: Core, _config: &Config) -> Core {
    core
}

/// Without the feature there is no pipeline to give it, and a `[media]`
/// section is an operator promising their users something this binary
/// cannot do. Say so at startup rather than at the first upload.
#[cfg(not(feature = "media"))]
fn with_media(core: Core, config: &Config) -> Result<Core, String> {
    if config.media.is_some() {
        return Err(
            "[media] is configured, but this build has no image pipeline \
                    (built without the `media` feature)"
                .into(),
        );
    }
    if config.news.as_ref().is_some_and(|n| n.attach.is_some()) {
        return Err("[news.attach] requires the `media` and `inbox` features".into());
    }
    Ok(core)
}

/// The TRTP tunnel's other end: the legacy frontend, run on the byte
/// stream the ng layer hands over (docs/hotline-ng-auth.md §7.3).
pub struct LegacyTunnel(pub ServerCtx);

impl TunnelSink for LegacyTunnel {
    fn run(
        &self,
        stream: TunnelStream,
        peer: SocketAddr,
        transport: Transport,
        link: LinkAuthority,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let ctx = self.0.clone();
        Box::pin(async move {
            let span = tracing::info_span!("tunnel", %peer);
            tracing::Instrument::instrument(
                hxd_session::run_session(stream, peer, ctx, transport, link),
                span,
            )
            .await
        })
    }
}

/// Load or create a signing key: the server's identity key, or the
/// registrar's. Created with mode 0600 on Unix; the file is a 32-byte
/// seed, hex-encoded, so it can be backed up with the account directory.
pub(crate) fn load_key(path: &Path, what: &str) -> Result<ServerKey, String> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = ServerKey::generate();
            let hex: String = key.seed().iter().map(|b| format!("{b:02x}")).collect();
            write_private(path, &hex).map_err(|e| format!("{}: {e}", path.display()))?;
            tracing::info!("generated {what} key at {}", path.display());
            Ok(key)
        }
        _ => read_key(path),
    }
}

/// Read a key [`load_key`] wrote, failing if there is none.
pub(crate) fn read_key(path: &Path) -> Result<ServerKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let hex = text.trim();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| format!("{}: not a hex seed", path.display()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{}: seed must be 32 bytes", path.display()))?;
    Ok(ServerKey::from_seed(&seed))
}

/// A public key as configuration and discovery spell it: base64url, 32
/// bytes.
pub(crate) fn decode_key(b64: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.trim())
        .map_err(|_| "not base64url".to_string())?
        .try_into()
        .map_err(|_| "key must be 32 bytes".to_string())
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    writeln!(f, "{text}")
}

impl IdentitySection {
    /// The two revocation lists, as the core holds them. Every entry must
    /// be a fingerprint in its display form: a typo that silently revoked
    /// nothing would leave a stolen key in, so it is a startup error, and
    /// on a reload the old lists stay.
    pub fn revocations(&self) -> Result<hxd_core::Revocations, String> {
        let parse = |key: &str, list: &[String]| {
            list.iter()
                .map(|entry| {
                    hl_identity::Fingerprint::parse(entry.trim())
                        .map(|fp| fp.0)
                        .ok_or_else(|| format!("[identity] {key}: {entry:?} is not a fingerprint"))
                })
                .collect::<Result<std::collections::HashSet<_>, _>>()
        };
        Ok(hxd_core::Revocations {
            identities: parse("revoked_identities", &self.revoked_identities)?,
            devices: parse("revoked_devices", &self.revoked_devices)?,
        })
    }
}

/// Re-read `[identity]`'s revocation lists from the config file and
/// install them, ending every session they now refuse. What SIGHUP does,
/// and all it does: nothing else in the file is re-read, and a file that
/// no longer loads, or no longer checks, leaves the lists as they were.
/// A file with no `[identity]` section at all revokes nothing.
///
/// A missing file is one that no longer loads, not an empty config:
/// `Config::load` reads it as the defaults, which would lift every
/// revocation because the file was moved.
///
/// Answers how many keys are listed and the sessions ended.
pub fn reload_revocations(
    core: &Core,
    path: &Path,
) -> Result<(usize, Vec<(hxd_core::Uid, String)>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let config: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    check_config(&config)?;
    let list = match &config.identity {
        Some(section) => section.revocations()?,
        None => hxd_core::Revocations::default(),
    };
    let listed = list.identities.len() + list.devices.len();
    Ok((listed, core.set_revocations(list)))
}

/// Which of `[identity]`'s two lists `hxd identity revoke` edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeWhat {
    /// `revoked_identities`: every device of the identity.
    Identity,
    /// `revoked_devices`: the one device.
    Device,
}

/// What `hxd identity revoke` changed.
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// The fingerprint was added (or, with `lift`, removed).
    Changed,
    /// It was already listed (or, with `lift`, already absent); the file
    /// is untouched.
    Unchanged,
}

/// `hxd identity revoke`: add a fingerprint to one of `[identity]`'s
/// revocation lists in the config file at `path`, or with `lift` take it
/// out, and answer the fingerprint as written. Applied by the next
/// SIGHUP, or restart, of the server reading that file.
///
/// The file is edited rather than rewritten, so an operator's comments
/// and layout survive, and it is checked the way the server will check it
/// before anything is written: a command that left a config the server
/// then refused to reload would have revoked nothing. The write is a
/// rename, so a server reloading at the same moment reads the old file
/// or the new one, never half of either.
///
/// The temporary file beside it is also the lock: created exclusively
/// before the file is read, so a second command at the same moment is
/// refused rather than rewriting from the same original and dropping
/// the first one's entry.
pub fn revoke_command(
    path: &Path,
    fingerprint: &str,
    what: RevokeWhat,
    lift: bool,
) -> Result<(String, RevokeOutcome), String> {
    let fp = parse_fingerprint(fingerprint).map_err(|_| {
        format!("{fingerprint:?} is not a fingerprint: give the 52-character form hlid prints, or 64 hex characters")
    })?;
    let spelled = hl_identity::Fingerprint(fp).to_string();
    // The file itself, not a symlink to it: renaming over a link would
    // replace the link and leave the file it named unedited.
    let path = &std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let tmp = path.with_extension("toml.revoke");
    // Owner-only from its first byte: a config file can hold tracker
    // passwords and HMAC secrets, and one left behind by a command that
    // died must not be readable by anyone the original was not.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&tmp).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{} exists: another revoke is editing {}, or one died and left it (remove it if so)",
                tmp.display(),
                path.display()
            )
        } else {
            format!("{}: {e}", tmp.display())
        }
    })?;
    let result = revoke_locked(path, &tmp, file, fp, spelled, what, lift);
    if !matches!(result, Ok((_, RevokeOutcome::Changed))) {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// `revoke_command` with `tmp` held: read, edit, check, and rename `tmp`
/// over `path`. The caller removes `tmp` on anything but a rename.
fn revoke_locked(
    path: &Path,
    tmp: &Path,
    mut file: std::fs::File,
    fp: [u8; 32],
    spelled: String,
    what: RevokeWhat,
    lift: bool,
) -> Result<(String, RevokeOutcome), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let identity = doc
        .get_mut("identity")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or_else(|| {
            format!(
                "{} has no [identity] section: identity login is off, so there is no key to revoke",
                path.display()
            )
        })?;
    let key = match what {
        RevokeWhat::Identity => "revoked_identities",
        RevokeWhat::Device => "revoked_devices",
    };
    if !identity.contains_key(key) {
        identity.insert(key, toml_edit::value(toml_edit::Array::new()));
    }
    let list = identity[key]
        .as_array_mut()
        .ok_or_else(|| format!("[identity] {key} is not a list"))?;
    // Compared as fingerprints rather than as text, so an entry written
    // in another case, or with the confusables the form tolerates, is
    // still the same key.
    let listed = |v: &toml_edit::Value| {
        v.as_str()
            .and_then(|s| hl_identity::Fingerprint::parse(s.trim()))
            .is_some_and(|f| f.0 == fp)
    };
    let present = list.iter().any(listed);
    let outcome = match (lift, present) {
        (false, true) | (true, false) => return Ok((spelled, RevokeOutcome::Unchanged)),
        (false, false) => {
            list.push(spelled.as_str());
            RevokeOutcome::Changed
        }
        (true, true) => {
            list.retain(|v| !listed(v));
            RevokeOutcome::Changed
        }
    };
    let edited = doc.to_string();
    let config: Config = toml::from_str(&edited).map_err(|e| format!("{}: {e}", path.display()))?;
    check_config(&config)?;
    {
        use std::io::Write;
        file.write_all(edited.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    // Then the original's mode, which is what the renamed file will have
    // anyway: an operator who made it owner-only keeps it owner-only, and
    // one who made it group-readable is not surprised by 0600.
    let perms = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .permissions();
    std::fs::set_permissions(tmp, perms).map_err(|e| format!("{}: {e}", tmp.display()))?;
    // Renamed only on the way out, so `revoke_command` sees `Changed`
    // exactly when `tmp` is gone.
    std::fs::rename(tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((spelled, outcome))
}

fn build_identity(
    section: &IdentitySection,
    auth: Arc<dyn hxd_core::AuthBackend>,
    core: Arc<Core>,
) -> Result<IdentityState, String> {
    let key = load_key(&section.key, "server identity")?;
    let new_accounts = match section.new_accounts.as_str() {
        "deny" => NewAccounts::Deny,
        "guest" => NewAccounts::Guest,
        "create" => NewAccounts::Create,
        other => return Err(format!("[identity] new_accounts: unknown value {other:?}")),
    };
    let unattested = match section.unattested.as_str() {
        "deny" => Unattested::Deny,
        "guest" => Unattested::Guest,
        "allow" => Unattested::Allow,
        other => return Err(format!("[identity] unattested: unknown value {other:?}")),
    };
    let mut registrar_keys = HashMap::new();
    for (host, b64) in &section.registrar_keys {
        let key = decode_key(b64).map_err(|e| format!("[identity] registrar_keys.{host}: {e}"))?;
        registrar_keys.insert(host.to_lowercase(), key);
    }
    let default_access = match &section.default_access {
        None => None,
        Some(named) => {
            let mut bits = hxd_core::AccessBits::empty();
            for (key, on) in named {
                if !on {
                    continue;
                }
                match hxd_auth_file::named_bit(key) {
                    Some(b) => bits = bits.with(b),
                    None => {
                        return Err(format!(
                            "[identity.default_access]: unknown access key {key:?}"
                        ))
                    }
                }
            }
            Some(bits)
        }
    };
    if section.new_accounts != "create" && section.default_access.is_some() {
        tracing::warn!("[identity] default_access has no effect unless new_accounts = create");
    }
    Ok(IdentityState::new(
        key,
        IdentityConfig {
            new_accounts,
            allow_list: section.allow_list.clone(),
            min_attestation_age: section.min_attestation_age,
            unattested,
            registrar_keys,
            clock_skew: section.clock_skew,
            trtp: section.trtp,
            default_access,
            max_new_accounts_per_hour: Some(section.max_new_accounts_per_hour),
            anchors: if section.successors.as_os_str().is_empty() {
                None
            } else {
                Some(section.successors.clone())
            },
        },
        auth,
        core,
    ))
}

/// Config-level checks a `Deserialize` can't make: sections whose
/// meaning depends on another section's presence, and values whose
/// validity depends on more than their own type.
///
/// Run before anything is built, so the operator hears about it at
/// startup rather than wondering why identity does nothing, or why
/// messages never arrive.
pub fn check_config(config: &Config) -> Result<(), String> {
    if config.identity.is_some() && config.ng.is_none() {
        return Err(
            "[identity] needs [ng]: the identity endpoints and the TRTP tunnel are \
             served by the ng listener, so [identity] without [ng] does nothing"
                .into(),
        );
    }
    if let Some(identity) = &config.identity {
        identity.revocations()?;
    }
    registrar::check(config)?;
    tls::check(config)?;
    banner::check(config)?;
    if let Some(inbox) = &config.inbox {
        hxd_core::InboxPolicy {
            max_queued: inbox.max_queued,
            deliver_at_flush: inbox.deliver_at_flush,
        }
        .check()?;
    }
    if let Some(history) = &config.history {
        if history.db.is_none() && config.inbox.is_none() {
            return Err("[history] needs db unless [inbox] names the shared database".into());
        }
        if !(1..=200).contains(&history.max_page) {
            return Err("[history] max_page must be between 1 and 200".into());
        }
    }
    if let Some(news) = &config.news {
        let shared =
            config.inbox.is_some() || config.history.as_ref().is_some_and(|h| h.db.is_some());
        if news.db.is_none() && !shared {
            return Err(
                "[news] needs db unless [inbox] or [history] names the shared database".into(),
            );
        }
        news.check()?;
    }
    if let Some(push) = &config.push {
        // Caught here, where the operator is told, rather than as "store
        // was not opened" after the key file has been written.
        let shared = config.inbox.is_some()
            || config.history.as_ref().is_some_and(|h| h.db.is_some())
            || config.news.as_ref().is_some_and(|n| n.db.is_some());
        if push.db.is_none() && !shared {
            return Err(
                "[push] needs db unless [inbox], [history] or [news] names the shared database"
                    .into(),
            );
        }
        if push.max_devices == 0 {
            return Err("[push] max_devices must be at least 1".into());
        }
    }
    if let Some(system) = &config.system {
        system.check()?;
    }
    if let Some(moderation) = &config.moderation {
        moderation.check()?;
    }
    if let Some(files) = &config.files {
        if !matches!(
            (&files.manifest, &files.origin, &files.root),
            (Some(_), Some(_), None) | (None, None, Some(_))
        ) {
            return Err(
                "[files] requires either root, or both manifest and origin, but never both modes"
                    .into(),
            );
        }
        if files.max_file_size == 0 {
            return Err("[files] max_file_size must be non-zero".into());
        }
        if files.max_entries == 0
            || files.max_concurrent == 0
            || files.max_partial_bytes == 0
            || files.max_partials == 0
            || files.max_partials_per_account == 0
        {
            return Err(
                "[files] size, entry, concurrency, and partial limits must be non-zero".into(),
            );
        }
        if files.max_references == 0
            || files.max_references_per_session == 0
            || files.max_references_per_account == 0
            || files.max_downloads == 0
            || files.max_downloads_per_session == 0
            || files.max_downloads_per_account == 0
        {
            return Err("[files] registry limits must be non-zero".into());
        }
        if files.request_timeout == 0
            || files.reference_ttl == 0
            || files.download_ttl == 0
            || files.handshake_timeout == 0
            || files.idle_timeout == 0
            || files.partial_ttl == 0
            || files.upload_timeout == 0
        {
            return Err("[files] timeout and TTL values must be non-zero".into());
        }
    }
    if let Some(tracker) = &config.tracker {
        tracker.check(&config.server.name)?;
    }
    Ok(())
}

#[cfg(feature = "inbox")]
fn open_sqlite(
    path: &Path,
    sync: hxd_store_sqlite::Synchronous,
) -> Result<Arc<hxd_store_sqlite::SqliteStore>, String> {
    // History and inbox bodies are both cleartext. Create the main file
    // private before SQLite opens it, then apply the same mode to WAL
    // sidecars after migration.
    #[cfg(unix)]
    if !path.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let store = Arc::new(
        hxd_store_sqlite::SqliteStore::open(path, sync)
            .map_err(|e| format!("{}: {e}", path.display()))?,
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_os_string();
            p.push(suffix);
            let p = PathBuf::from(p);
            if p.exists() {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("{}: {e}", p.display()))?;
            }
        }
    }
    Ok(store)
}

#[cfg(feature = "inbox")]
struct RuntimeStores {
    inbox: Option<Arc<dyn hxd_core::MessageStore>>,
    history: Option<Arc<dyn hxd_core::ChatLog>>,
    news: Option<Arc<dyn hxd_core::NewsStore>>,
    devices: Option<Arc<dyn hxd_core::PushStore>>,
    moderation: Option<Arc<dyn hxd_core::ModerationStore>>,
}

/// Open the databases the config names, **one store object per file**
/// however many sections name it. Two objects on one file would be two
/// schema owners, each migrating on open and each holding its own
/// connection mutex — the one-writer design the store rests on, undone
/// by a config that spelled a path twice.
#[cfg(feature = "inbox")]
fn open_runtime_stores(config: &Config) -> Result<RuntimeStores, String> {
    use hxd_store_sqlite::{SqliteStore, Synchronous};
    let inbox_path = config.inbox.as_ref().map(|i| i.db.clone());
    let history_path = config
        .history
        .as_ref()
        .and_then(|h| h.db.clone().or_else(|| inbox_path.clone()));
    let news_path = config.news.as_ref().and_then(|n| {
        n.db.clone()
            .or_else(|| inbox_path.clone())
            .or_else(|| history_path.clone())
    });
    // Devices share whatever file there is, as news does, in the order
    // `push_db` writes down — the same order the purge looks in.
    let push_path = config.push.as_ref().and_then(|_| push_db(config));
    let inbox_sync = config
        .inbox
        .as_ref()
        .map_or(Synchronous::Normal, |i| match i.sync {
            InboxSync::Normal => Synchronous::Normal,
            InboxSync::Full => Synchronous::Full,
        });

    // Every path is resolved before any file is opened: opening creates
    // the file, and a path compared before and after its file exists is
    // resolved two different ways.
    let keyed = |p: &Option<PathBuf>| -> Result<Option<(PathBuf, PathBuf)>, String> {
        p.as_ref()
            .map(|p| Ok((p.clone(), database_path(p)?)))
            .transpose()
    };
    let (inbox_path, history_path, news_path, push_path) = (
        keyed(&inbox_path)?,
        keyed(&history_path)?,
        keyed(&news_path)?,
        keyed(&push_path)?,
    );

    let mut opened: Vec<(PathBuf, Arc<SqliteStore>)> = Vec::new();
    let mut open = |(path, key): &(PathBuf, PathBuf), sync| -> Result<Arc<SqliteStore>, String> {
        if let Some((_, store)) = opened.iter().find(|(k, _)| k == key) {
            return Ok(store.clone());
        }
        let store = open_sqlite(path, sync)?;
        opened.push((key.clone(), store.clone()));
        Ok(store)
    };
    // The inbox first, so a shared file gets the inbox's `sync`: it is
    // the section that asked for durability.
    let inbox = match &inbox_path {
        Some(p) => Some(open(p, inbox_sync)? as Arc<dyn hxd_core::MessageStore>),
        None => None,
    };
    let history = match &history_path {
        Some(p) => Some(open(p, Synchronous::Normal)? as Arc<dyn hxd_core::ChatLog>),
        None => None,
    };
    let news = match &news_path {
        Some(p) => Some(open(p, Synchronous::Normal)? as Arc<dyn hxd_core::NewsStore>),
        None => None,
    };
    let devices = match &push_path {
        Some(p) => Some(open(p, Synchronous::Normal)? as Arc<dyn hxd_core::PushStore>),
        None => None,
    };
    // Already open: the trail shares whichever of those files comes first
    // in `moderation::db`'s order.
    let moderation = match keyed(&moderation::db(config))? {
        Some(p) => Some(open(&p, Synchronous::Normal)? as Arc<dyn hxd_core::ModerationStore>),
        None => None,
    };
    Ok(RuntimeStores {
        inbox,
        history,
        news,
        devices,
        moderation,
    })
}

/// Resolve enough of a possibly-new database path to compare two spellings.
///
/// The database itself need not exist yet, so canonicalise its parent and
/// put the final component back. This catches `db` versus `./db` and a
/// symlinked directory without creating either file just to compare them.
#[cfg(feature = "inbox")]
fn database_path(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        return path
            .canonicalize()
            .map_err(|e| format!("{}: {e}", path.display()));
    }
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} is not a database filename", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent
        .canonicalize()
        .map(|parent| parent.join(name))
        .map_err(|e| format!("{}: {e}", parent.display()))
}

#[cfg(not(feature = "inbox"))]
struct RuntimeStores {
    inbox: Option<Arc<dyn hxd_core::MessageStore>>,
    history: Option<Arc<dyn hxd_core::ChatLog>>,
    news: Option<Arc<dyn hxd_core::NewsStore>>,
    devices: Option<Arc<dyn hxd_core::PushStore>>,
    moderation: Option<Arc<dyn hxd_core::ModerationStore>>,
}

#[cfg(not(feature = "inbox"))]
fn open_runtime_stores(config: &Config) -> Result<RuntimeStores, String> {
    if config.inbox.is_some()
        || config.history.is_some()
        || config.news.is_some()
        || config.push.is_some()
    {
        return Err(
            "[inbox], [history], [news] or [push] is configured, but this build has no \
                    SQLite store (built without the `inbox` feature)"
                .into(),
        );
    }
    Ok(RuntimeStores {
        inbox: None,
        history: None,
        news: None,
        devices: None,
        moderation: None,
    })
}

/// Open the inbox database named by `[inbox]`, if any, creating and
/// migrating it the way startup does.
///
/// Startup itself goes through [`open_runtime_stores`], which opens the
/// one file the inbox and the chat log may share; this is what
/// `inbox purge` needs when it is about to write. A build without the
/// feature refuses a config that asks for a store in
/// `open_runtime_stores`, so there is no second shape of this to keep.
#[cfg(feature = "inbox")]
fn open_inbox(config: &Config) -> Result<Option<Arc<dyn hxd_core::MessageStore>>, String> {
    use hxd_store_sqlite::{SqliteStore, Synchronous};
    let Some(section) = &config.inbox else {
        return Ok(None);
    };
    let sync = match section.sync {
        InboxSync::Normal => Synchronous::Normal,
        InboxSync::Full => Synchronous::Full,
    };
    // Every private message on the server, in the clear. The README says
    // "the same permissions as accounts/"; make that true rather than
    // leaving it to whatever the process umask happens to be.
    //
    // The empty file is created here rather than chmodded after
    // `migrate`: SQLite creating it under the umask left a window,
    // however short, in which the file another process could open was
    // world-readable. An existing database is left alone until the loop
    // below.
    #[cfg(unix)]
    if !section.db.exists() {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&section.db)
            .map_err(|e| format!("{}: {e}", section.db.display()))?;
    }
    let store = SqliteStore::open(&section.db, sync)
        .map_err(|e| format!("{}: {e}", section.db.display()))?;
    // WAL adds a `-wal` and a `-shm` beside the file, and they carry the
    // same data.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for suffix in ["", "-wal", "-shm"] {
            let mut p = section.db.clone().into_os_string();
            p.push(suffix);
            let p = PathBuf::from(p);
            if p.exists() {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("{}: {e}", p.display()))?;
            }
        }
    }
    Ok(Some(Arc::new(store)))
}

/// What an operator command finds where the inbox database should be.
#[cfg(feature = "inbox")]
enum InboxKind {
    /// No `[inbox]` section at all.
    Unconfigured,
    /// Configured, and no file there yet.
    Missing(PathBuf),
    At(PathBuf),
}

#[cfg(feature = "inbox")]
fn open_inbox_kind(config: &Config) -> Result<InboxKind, String> {
    let Some(section) = &config.inbox else {
        return Ok(InboxKind::Unconfigured);
    };
    Ok(if section.db.exists() {
        InboxKind::At(section.db.clone())
    } else {
        InboxKind::Missing(section.db.clone())
    })
}

/// A handle that reads and does not write, for `--dry-run`.
#[cfg(feature = "inbox")]
fn open_read_only(path: &Path) -> Result<Arc<dyn hxd_core::MessageStore>, String> {
    let store = hxd_store_sqlite::SqliteStore::open_read_only(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Arc::new(store))
}

/// `hxd inbox purge <login> [--fingerprint HEX]`: take an account's mail
/// with it (`docs/private-messages.md` §4), and its news subscriptions,
/// which are keyed the same way (`docs/news.md` §10.2).
///
/// Deleting an account is `rm accounts/alice.toml`, which leaves the
/// login free for someone else — and, without this, leaves the previous
/// holder's mail sitting in a login-keyed mailbox for the next `alice` to
/// inherit. The store has always had `purge`; nothing called it.
///
/// The account file is read when it is still there, so an identity-linked
/// mailbox is purged by its fingerprint rather than by a login that no
/// longer addresses it. For an account already deleted, pass
/// `--fingerprint` — the value from its `[identity]` table, which is the
/// 52-character form an operator can actually copy from a file or a log.
#[cfg(feature = "inbox")]
pub fn inbox_purge(
    config: &Config,
    login: &str,
    fingerprint: Option<&str>,
    dry_run: bool,
) -> Result<usize, String> {
    // `open_inbox` creates the database when it is missing and migrates
    // it when it is not, the way startup does. Both are wrong for an
    // operator command, and `--dry-run`'s whole promise is that it
    // changes nothing — a dry run against a server one version back was
    // doing the schema upgrade the operator was still deciding about,
    // and against a server with no mail yet it left a file behind.
    //
    // So: the feature check first (a build without an inbox should say
    // that, not "no database"), then the file, then a handle that
    // matches what the command is for.
    let fingerprint = match fingerprint {
        Some(text) => Some(parse_fingerprint(text)?),
        None => None,
    };
    let mailbox = match fingerprint {
        Some(fp) => hxd_core::inbox::Mailbox::identified(login.to_ascii_lowercase(), fp),
        None => {
            let auth = FileAuth::new(&config.paths.accounts);
            // The account's own view of its mailbox where it still
            // exists, so a linked one is purged by fingerprint.
            hxd_core::account::AccountDirectory::inbox_account(&auth, login)
                .unwrap_or_else(|| hxd_core::inbox::Mailbox::login(login.to_ascii_lowercase()))
        }
    };
    // The news and push halves need no inbox: either may keep a
    // database of its own, and a later holder of the login must not
    // inherit what the previous one followed, or their phone, on a
    // server that keeps no mail.
    let others =
        news_db(config).is_some_and(|p| p.exists()) || push_db(config).is_some_and(|p| p.exists());
    let mail = match (dry_run, open_inbox_kind(config)?) {
        (_, InboxKind::Unconfigured | InboxKind::Missing(_)) if others => 0,
        (_, InboxKind::Unconfigured) => {
            return Err("[inbox] is not configured; there is nothing to purge".into())
        }
        (_, InboxKind::Missing(path)) => {
            return Err(format!(
                "{}: no inbox database, so there is nothing to purge",
                path.display()
            ))
        }
        // What `purge` would take: everything in the mailbox, read or
        // not. Deleting mail is not undoable and the operator has just
        // deleted the account file, so it is worth being able to look
        // first.
        (true, InboxKind::At(path)) => open_read_only(&path)?
            .purge_count(&mailbox)
            .map_err(|e| e.to_string())?,
        (false, InboxKind::At(_)) => match open_inbox(config)? {
            Some(store) => store.purge(&mailbox).map_err(|e| e.to_string())?,
            None => return Err("[inbox] is not configured; there is nothing to purge".into()),
        },
    };
    Ok(mail
        + purge_news_subs(config, &mailbox, dry_run)?
        + purge_devices(config, &mailbox, dry_run)?)
}

/// Where the shared store file is: `[news]`'s own `db`, or the file
/// `[inbox]` or `[history]` names, which every other table then shares.
///
/// Answered without a `[news]` section too. With news turned off, the
/// shared file still holds whatever it wrote, and a purge that stopped
/// looking there would leave a login's subscriptions to be found again
/// when news came back. A `db` of its own is only known while the section
/// names it.
#[cfg(feature = "inbox")]
fn news_db(config: &Config) -> Option<PathBuf> {
    config
        .news
        .as_ref()
        .and_then(|n| n.db.clone())
        .or_else(|| config.inbox.as_ref().map(|i| i.db.clone()))
        .or_else(|| config.history.as_ref().and_then(|h| h.db.clone()))
}

/// The news half of a purge. Subscriptions are keyed as mail is
/// (`docs/news.md` §10.2), so a later holder of the login must not
/// inherit those either — and a later holder would be rung about threads
/// the previous one followed. Counted on a dry run, the way mail is.
#[cfg(feature = "inbox")]
fn purge_news_subs(
    config: &Config,
    mailbox: &hxd_core::inbox::Mailbox,
    dry_run: bool,
) -> Result<usize, String> {
    let Some(path) = news_db(config).filter(|p| p.exists()) else {
        return Ok(0);
    };
    if dry_run {
        let store = hxd_store_sqlite::SqliteStore::open_read_only(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        return hxd_core::NewsStore::subscriptions(&store, mailbox)
            .map(|subs| subs.len())
            .map_err(|e| e.to_string());
    }
    let store = open_sqlite(&path, hxd_store_sqlite::Synchronous::Normal)?;
    hxd_core::NewsStore::subs_purge(&*store, mailbox).map_err(|e| e.to_string())
}

/// Where push devices are kept: `[push]`'s own `db`, else the file
/// `[inbox]` names, else `[history]`'s, else `[news]`'s — the order the
/// server itself opens them in, and the one place that order is written
/// down, so a purge cannot look in one file while the server writes to
/// another. Answered without a `[push]` section too, for the reason
/// [`news_db`] is: push turned off leaves its rows where they were.
#[cfg(feature = "inbox")]
pub(crate) fn push_db(config: &Config) -> Option<PathBuf> {
    config
        .push
        .as_ref()
        .and_then(|p| p.db.clone())
        .or_else(|| config.inbox.as_ref().map(|i| i.db.clone()))
        .or_else(|| config.history.as_ref().and_then(|h| h.db.clone()))
        .or_else(|| config.news.as_ref().and_then(|n| n.db.clone()))
}

/// The push half of a purge (`docs/webpush-gateway.md` §2). Devices are
/// keyed as mail is, so a later holder of the login must not inherit the
/// previous one's phone — which would be that phone buzzing for a
/// stranger's private messages, the failure the mailbox rule exists to
/// prevent. Counted on a dry run, the way mail and subscriptions are.
#[cfg(feature = "inbox")]
fn purge_devices(
    config: &Config,
    mailbox: &hxd_core::inbox::Mailbox,
    dry_run: bool,
) -> Result<usize, String> {
    let Some(path) = push_db(config).filter(|p| p.exists()) else {
        return Ok(0);
    };
    if dry_run {
        let store = hxd_store_sqlite::SqliteStore::open_read_only(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        // Every device, expired ones included: a dry run reports what a
        // purge would take, and a purge takes them all.
        return hxd_core::PushStore::devices(&store, mailbox, SystemTime::UNIX_EPOCH)
            .map(|d| d.len())
            .map_err(|e| e.to_string());
    }
    let store = open_sqlite(&path, hxd_store_sqlite::Synchronous::Normal)?;
    hxd_core::PushStore::devices_purge(&*store, mailbox).map_err(|e| e.to_string())
}

/// Without the feature there is no store to inspect, and saying so beats
/// saying "no database" about a build that could not read one anyway.
#[cfg(not(feature = "inbox"))]
pub fn inbox_purge(
    _config: &Config,
    _login: &str,
    _fingerprint: Option<&str>,
    _dry_run: bool,
) -> Result<usize, String> {
    Err("this build has no inbox (built without the `inbox` feature)".to_string())
}

/// `hxd news-reindex`: rebuild the news search index from the articles
/// (`docs/news.md` §6.4) — the repair for an index that has drifted.
///
/// It opens the database the way startup does, migration included: an
/// index is only rebuilt on a schema that has one. The database must
/// already exist, though; a reindex that created an empty one would be
/// an operator's typo answered with a new file.
#[cfg(feature = "inbox")]
pub fn news_reindex(config: &Config) -> Result<u64, String> {
    if config.news.is_none() {
        return Err("[news] is not configured; there is no index to rebuild".into());
    }
    let path = news_db(config).ok_or("[news] names no database")?;
    if !path.exists() {
        return Err(format!(
            "{}: no news database, so there is nothing to index",
            path.display()
        ));
    }
    let store = open_sqlite(&path, hxd_store_sqlite::Synchronous::Normal)?;
    hxd_core::NewsStore::reindex(&*store).map_err(|e| e.to_string())
}

#[cfg(not(feature = "inbox"))]
pub fn news_reindex(_config: &Config) -> Result<u64, String> {
    Err("this build has no news store (built without the `inbox` feature)".to_string())
}

/// A fingerprint as an operator has it: the 52-character Crockford form
/// the account file's `[identity]` table and the roster both show, or
/// raw hex for anyone reading it out of a hash. Crockford first — the
/// tooling that tells the operator to run this prints that form, and
/// requiring hex meant `rm alice.toml` left the mailbox unpurgeable.
// Not behind `inbox`: `hxd identity revoke` reads fingerprints too.
pub(crate) fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim();
    if let Some(fp) = hl_identity::Fingerprint::parse(text) {
        return Ok(fp.0);
    }
    let hex: Option<Vec<u8>> = (text.len() == 64 && text.is_ascii())
        .then(|| {
            (0..32)
                .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
                .collect()
        })
        .flatten();
    hex.and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| {
            "--fingerprint must be the account file's 52-character form, or 64 hex characters"
                .to_string()
        })
}

/// Retention: drop unread messages older than their window, and read ones
/// read longer ago than theirs. Runs beside the ng frontend's detached
/// sweeper, but is not its business — a legacy-only server has inboxes too.
pub async fn inbox_pruner(core: Arc<Core>, unread: Duration, read: Duration) {
    // Hourly: retention is measured in days, so anything finer is work
    // for its own sake.
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        // On the blocking pool like every other store call: this is a
        // `DELETE` with a five-second busy timeout, and an external
        // `sqlite3` holding a write lock would otherwise stall every
        // session the reactor thread is carrying.
        let core = core.clone();
        let gone = tokio::task::spawn_blocking(move || core.prune_inbox(unread, read))
            .await
            .unwrap_or(0);
        if gone > 0 {
            tracing::debug!(gone, "inbox messages pruned");
        }
    }
}

/// Public-chat retention, kept off the request and append paths.
pub async fn history_pruner(core: Arc<Core>, max_lines: u32, max_days: u32) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let core = core.clone();
        let max_age = (max_days != 0).then(|| Duration::from_secs(u64::from(max_days) * 24 * 3600));
        let gone =
            tokio::task::spawn_blocking(move || core.prune_history(max_lines as usize, max_age))
                .await
                .unwrap_or(0);
        if gone > 0 {
            tracing::debug!(gone, "chat-history lines pruned");
        }
    }
}

/// News retention: whole threads whose last post is older than `[news]
/// retain_days`, then the attachment sweep — abandoned stages, and files
/// no row keeps (`docs/news.md` §7.2). Hourly and on the blocking pool,
/// like the other two — never on the request path.
pub async fn news_pruner(core: Arc<Core>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let core = core.clone();
        let gone = tokio::task::spawn_blocking(move || {
            let gone = core.prune_news();
            match core.news_expire_attachments(SystemTime::now()) {
                // A server without `[news.attach]`, which prunes anyway.
                Ok(_) | Err(hxd_core::NewsError::Disabled) => {}
                Err(e) => tracing::warn!("news attachment sweep: {e:?}"),
            }
            gone
        })
        .await
        .unwrap_or(0);
        if gone > 0 {
            tracing::debug!(gone, "news articles pruned");
        }
    }
}

/// Delete the device rows whose certificates have expired. Skipping it
/// costs rows and never a wrong push: the gateway compares expiry
/// itself, so a lapsed device stops being sent to the moment it lapses
/// rather than the next time this runs.
pub async fn device_sweeper(core: Arc<Core>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let core = core.clone();
        let gone = tokio::task::spawn_blocking(move || core.sweep_devices())
            .await
            .unwrap_or(0);
        if gone > 0 {
            tracing::debug!(gone, "push devices expired");
        }
    }
}

/// Media retention: expired handles and abandoned upload sessions.
///
/// Hourly, like the others, because a handle lives a day. Every
/// access re-checks expiry itself, so this is housekeeping — it frees
/// memory rather than deciding what is servable, and nothing is served
/// between sweeps that a sweep would have taken.
pub async fn media_sweeper(core: Arc<Core>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let gone = core.media_sweep();
        if gone > 0 {
            tracing::debug!(gone, "media handles expired");
        }
    }
}

/// Build the ng frontend context sharing the legacy context's core and
/// auth. `None` when the config has no `[ng]` section.
pub fn build_ng_ctx(
    config: &Config,
    legacy: &ServerCtx,
    voice: Option<&Voice>,
    files: Option<&Files>,
    push: Option<&Push>,
) -> Result<Option<NgCtx>, String> {
    let Some(ng) = config.ng.as_ref() else {
        return Ok(None);
    };
    let registrar = registrar::build(config)?;
    let identity = match config.identity.as_ref() {
        Some(section) => {
            // Installed before anything can connect, so there is no
            // session yet for it to end.
            legacy.core.set_revocations(section.revocations()?);
            Some(Arc::new(
                build_identity(section, legacy.auth.clone(), legacy.core.clone())?
                    .with_registrar(registrar.clone()),
            ))
        }
        None => None,
    };
    let tunnel: Option<Arc<dyn TunnelSink>> = identity
        .as_ref()
        .map(|_| Arc::new(LegacyTunnel(legacy.clone())) as Arc<dyn TunnelSink>);
    // Needs `[identity]` for the same reason the other identity routes
    // do — it is part of that surface — but nothing inside it: the
    // mailbox reads no account and holds no key.
    let enroll = config.identity.as_ref().filter(|s| s.enroll).map(|s| {
        Arc::new(hxd_ng_session::enroll::Mailbox::new(
            hxd_ng_session::enroll::MailboxConfig {
                max_sessions: s.enroll_sessions,
                per_address: s.enroll_per_address,
            },
        ))
    });
    Ok(Some(NgCtx {
        core: legacy.core.clone(),
        auth: legacy.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: config.server.name.clone(),
            web_client: config.identity.as_ref().and_then(|i| i.web.clone()),
            agreement: legacy.cfg.agreement.clone(),
            login_timeout: Duration::from_secs(config.server.login_timeout),
            grace: Duration::from_secs(ng.grace),
            max_detached_per_addr: ng.max_detached_per_addr,
            caps: ng_caps(config, voice, files),
            trusted_proxies: TrustedProxies::parse(&ng.trusted_proxies)?,
            forwarded_header: ForwardedHeader::parse(&ng.forwarded_header)?,
        }),
        registry: Arc::new(Registry::new()),
        identity,
        tunnel,
        enroll,
        files: files.map(|value| value.service.clone()),
        push: push.and_then(Push::info),
        registrar,
        banner: legacy.banner.clone().map(|b| {
            Arc::new(banner::NgBanner(b)) as Arc<dyn hxd_ng_session::banner::BannerSource>
        }),
    }))
}

/// Assemble the shared server context from a config: bootstrap the accounts
/// directory, read the agreement file, wire the domain core and backend.
pub fn build_ctx(
    config: &Config,
    voice: Option<&Voice>,
    files: Option<&Files>,
    push: Option<&Push>,
    banner: Option<Arc<hxd_session::Banner>>,
) -> Result<ServerCtx, String> {
    FileAuth::bootstrap(&config.paths.accounts)
        .map_err(|e| format!("{}: {e}", config.paths.accounts.display()))?;

    let agreement = match &config.paths.agreement {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?),
        None => None,
    };

    let core = match voice {
        Some(v) => {
            let core = Core::new().with_voice(v.media(), v.max_per_room());
            // `with_video` is a no-op without a media layer, so the
            // dependency holds even if this ordering ever changes.
            if video_enabled(config) {
                core.with_video(
                    config
                        .voice
                        .as_ref()
                        .map_or_else(hxd_core::VideoConfig::default, |s| s.video_config()),
                )
            } else {
                core
            }
        }
        None => Core::new(),
    };

    // The reserved login is refused at the one place every frontend's
    // login goes through, so none of them can miss it.
    let auth = Arc::new(match config.system.as_ref() {
        Some(system) => FileAuth::new(&config.paths.accounts).reserving(&system.login),
        None => FileAuth::new(&config.paths.accounts),
    });
    // Say at startup what an operator would otherwise learn from a user:
    // an account file that does not parse, or one nothing can log in to.
    auth.audit();
    let stores = open_runtime_stores(config)?;
    let core = match stores.inbox {
        // The same FileAuth answers both "is this person who they say
        // they are" and "is there someone by that name to leave a message
        // for" — two traits, one backend.
        Some(store) => core.with_inbox(
            store,
            auth.clone(),
            hxd_core::InboxPolicy {
                max_queued: config.inbox.as_ref().map_or(200, |i| i.max_queued),
                deliver_at_flush: config.inbox.as_ref().map_or(25, |i| i.deliver_at_flush),
            },
        ),
        None => core,
    };
    let core = match (stores.history, config.history.as_ref()) {
        (Some(log), Some(history)) => core.with_history(
            log,
            hxd_core::history::HistoryPolicy {
                max_lines: history.max_lines,
                max_days: history.max_days,
                max_page: history.max_page,
                replay: history.replay,
            },
        ),
        (None, None) => core,
        _ => return Err("[history] store was not opened".into()),
    };
    let core = match (stores.news, config.news.as_ref()) {
        // The accounts too, whether or not there is an inbox: whether a
        // subscriber may still read the news is a question about an
        // account nobody may be logged into (§10.5).
        (Some(store), Some(news)) => core
            .with_news(store, news.to_policy())
            .with_accounts(auth.clone()),
        (None, None) => core,
        _ => return Err("[news] store was not opened".into()),
    };
    let core = match config.system.as_ref() {
        Some(system) => core.with_system(system.to_policy()),
        None => core,
    };
    let core = with_markdown(core, config);
    let core = with_media(core, config)?;
    // After media, so the durable block list reaches the image store.
    // Always on: kick and ban never needed a database, and reports on a
    // server with none are kept until it stops.
    let core = core.with_moderation(
        stores
            .moderation
            .unwrap_or_else(|| Arc::new(hxd_core::MemoryModeration::default())),
        moderation::policy(config),
    );
    // The registry and the gateway together or not at all: a registry
    // with nothing to send from would take registrations and drop every
    // notification, which is worse than saying there is no push.
    let core = match (stores.devices, push) {
        (Some(devices), Some(push)) => core
            .with_devices(devices.clone())
            .with_push_policy(push.policy())
            .with_notifications(push.start(devices)?),
        (_, None) => core,
        (None, Some(_)) => return Err("[push] store was not opened".into()),
    };

    Ok(ServerCtx {
        core: Arc::new(core),
        auth,
        cfg: Arc::new(ServerConfig {
            name: config.server.name.clone(),
            version: config.server.version,
            agreement,
            login_timeout: Duration::from_secs(config.server.login_timeout),
            ban_time: Duration::from_secs(config.server.ban_time),
            stamp_queued: config.server.stamp_queued,
            caps: legacy_caps(config, voice, files),
            mark_cleartext: config.server.mark_cleartext,
            trtp_login: match config.identity.as_ref().map(|i| i.trtp_login.as_str()) {
                None | Some("verify") => TrtpLogin::Verify,
                Some("trust") => TrtpLogin::Trust,
                Some(other) => {
                    return Err(format!("[identity] trtp_login: unknown value {other:?}"))
                }
            },
            news: config
                .news
                .as_ref()
                .map(NewsSection::to_legacy)
                .unwrap_or_default(),
        }),
        files: files.map(|value| value.service.clone()),
        banner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hxd identity revoke` against a file an operator wrote by hand.
    #[test]
    fn revoke_edits_the_file_in_place_and_keeps_what_the_operator_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hxd-ng.toml");
        let original =
            "# my server\n[ng]\n\n[identity]\n# lost laptop, 2026-09\nnew_accounts = \"guest\"\n";
        std::fs::write(&path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let fp = hl_identity::Fingerprint([7; 32]);
        let hex: String = [7u8; 32].iter().map(|b| format!("{b:02x}")).collect();

        // Hex in, the display form written, and the comments still there.
        let (spelled, outcome) = revoke_command(&path, &hex, RevokeWhat::Identity, false).unwrap();
        assert_eq!(
            (spelled.as_str(), outcome),
            (fp.to_string().as_str(), RevokeOutcome::Changed)
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("# my server") && text.contains("# lost laptop"),
            "{text}"
        );
        let listed = || {
            let config = Config::load(&path).unwrap();
            config.identity.unwrap().revocations().unwrap()
        };
        assert!(listed().identities.contains(&[7; 32]));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "an owner-only file stays owner-only");
        }

        // Again is nothing, in any spelling of the same key.
        let upper = fp.to_string().to_uppercase();
        assert_eq!(
            revoke_command(&path, &upper, RevokeWhat::Identity, false)
                .unwrap()
                .1,
            RevokeOutcome::Unchanged
        );

        // A device goes on the other list.
        revoke_command(
            &path,
            &hl_identity::Fingerprint([8; 32]).to_string(),
            RevokeWhat::Device,
            false,
        )
        .unwrap();
        assert!(listed().devices.contains(&[8; 32]));

        // Lifting takes it out, and lifting twice is nothing.
        assert_eq!(
            revoke_command(&path, &hex, RevokeWhat::Identity, true)
                .unwrap()
                .1,
            RevokeOutcome::Changed
        );
        assert!(listed().identities.is_empty());
        assert_eq!(
            revoke_command(&path, &hex, RevokeWhat::Identity, true)
                .unwrap()
                .1,
            RevokeOutcome::Unchanged
        );
    }

    #[test]
    fn revoke_holds_its_temporary_file_as_a_lock_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hxd-ng.toml");
        std::fs::write(&path, "[ng]\n[identity]\n").unwrap();
        let tmp = dir.path().join("hxd-ng.toml.revoke");
        let fp = |b: u8| hl_identity::Fingerprint([b; 32]).to_string();

        // Another command mid-edit: refused, and its file is left alone.
        std::fs::write(&tmp, "theirs").unwrap();
        let err = revoke_command(&path, &fp(7), RevokeWhat::Identity, false).unwrap_err();
        assert!(err.contains("another revoke"), "{err}");
        assert_eq!(std::fs::read_to_string(&tmp).unwrap(), "theirs");
        std::fs::remove_file(&tmp).unwrap();

        // Changed, unchanged or refused, the lock goes with the command.
        revoke_command(&path, &fp(7), RevokeWhat::Identity, false).unwrap();
        assert!(!tmp.exists());
        revoke_command(&path, &fp(7), RevokeWhat::Identity, false).unwrap();
        assert!(!tmp.exists());
        revoke_command(&path, "not-a-key", RevokeWhat::Identity, false).unwrap_err();
        assert!(!tmp.exists());
    }

    #[test]
    fn a_reload_from_a_missing_file_keeps_the_lists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hxd-ng.toml");
        let core = Core::new();
        core.set_revocations(hxd_core::Revocations {
            identities: [[7; 32]].into_iter().collect(),
            devices: Default::default(),
        });
        let err = reload_revocations(&core, &path).unwrap_err();
        assert!(err.contains("hxd-ng.toml"), "{err}");
        assert!(core.is_revoked(&[7; 32], &[0; 32]), "nothing was lifted");
    }

    #[test]
    fn revoke_refuses_what_would_revoke_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hxd-ng.toml");
        let fp = hl_identity::Fingerprint([7; 32]).to_string();

        std::fs::write(&path, "[ng]\n[identity]\n").unwrap();
        let err = revoke_command(&path, "not-a-key", RevokeWhat::Identity, false).unwrap_err();
        assert!(err.contains("not a fingerprint"), "{err}");

        // No [identity]: identity login is off, and a list there would be
        // read by nothing.
        std::fs::write(&path, "[ng]\n").unwrap();
        let err = revoke_command(&path, &fp, RevokeWhat::Identity, false).unwrap_err();
        assert!(err.contains("no [identity] section"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[ng]\n");

        // A file the server would refuse to load is not written, so the
        // command never leaves a reload that fails.
        std::fs::write(&path, "[identity]\n").unwrap();
        let err = revoke_command(&path, &fp, RevokeWhat::Identity, false).unwrap_err();
        assert!(err.contains("needs [ng]"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[identity]\n");
    }

    #[test]
    fn tracker_configuration_is_explicit_validated_and_redacts_secrets() {
        let cfg = parse(
            r#"
[server]
name = "Listed server"

[tracker]
description = "A community"
interval = 300
advertised_port = 5500
ack_timeout_ms = 1500

[tracker.v3]
hostname = "hl.example"
country_code = "US"
language = "en"
maturity = 1
listing_category = 10
tags = "chat,retro"

[[tracker.targets]]
address = "classic.example"
protocol = "v1"
password = "old secret"

[[tracker.targets]]
address = "[2001:db8::1]:5499"
protocol = "v3"
hmac_secret = "new secret"
"#,
        )
        .unwrap();
        check_config(&cfg).unwrap();
        let tracker = cfg.tracker.as_ref().unwrap();
        assert_eq!(tracker.targets.len(), 2);
        assert_eq!(tracker.targets[0].protocol, tracker::TrackerProtocol::V1);
        assert_eq!(tracker.targets[1].protocol, tracker::TrackerProtocol::V3);
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("old secret"));
        assert!(!debug.contains("new secret"));
        assert!(debug.contains("[redacted]"));

        let empty = parse("[tracker]\n").unwrap();
        assert!(check_config(&empty).unwrap_err().contains("targets"));
        let typo =
            parse("[tracker]\n[[tracker.targets]]\naddress = \"example.com\"\nprotocol = \"v4\"\n");
        assert!(typo.is_err());
    }

    #[test]
    fn the_inbox_section_parses_and_refuses_numbers_that_disable_it() {
        let cfg = parse(
            r#"
[inbox]
db = "messages.db"
max_queued = 50
deliver_at_flush = 5
retain_unread = 100
retain_read = 10
sync = "full"
"#,
        )
        .unwrap();
        let inbox = cfg.inbox.as_ref().unwrap();
        assert_eq!(inbox.db, PathBuf::from("messages.db"));
        assert_eq!(inbox.max_queued, 50);
        assert_eq!(inbox.deliver_at_flush, 5);
        assert_eq!(inbox.retain_unread, 100);
        assert_eq!(inbox.retain_read, 10);
        assert_eq!(inbox.sync, InboxSync::Full);
        check_config(&cfg).unwrap();

        // The defaults are the documented ones.
        let cfg = parse("[inbox]\ndb = \"messages.db\"\n").unwrap();
        let inbox = cfg.inbox.as_ref().unwrap();
        assert_eq!(inbox.max_queued, 200);
        assert_eq!(inbox.deliver_at_flush, 25);
        assert_eq!(inbox.sync, InboxSync::Normal);

        // Zero is not "unlimited" in either: one stores nothing, the
        // other delivers nothing and never flushes what it stored.
        for key in ["max_queued", "deliver_at_flush"] {
            let cfg = parse(&format!("[inbox]\ndb = \"m.db\"\n{key} = 0\n")).unwrap();
            let err = check_config(&cfg).unwrap_err();
            assert!(err.contains(key), "{err}");
        }
        assert!(
            parse("[inbox]\nmax_queued = 5\n").is_err(),
            "db is required"
        );
        assert!(
            parse("[inbox]\ndb = \"m.db\"\nmax_qeued = 5\n").is_err(),
            "a misspelled key is a startup error, not a silent default"
        );
    }

    #[test]
    fn history_defaults_validates_and_is_advertised_on_both_wires() {
        let cfg = parse("[inbox]\ndb = \"server.sqlite\"\n[history]\n").unwrap();
        check_config(&cfg).unwrap();
        let history = cfg.history.as_ref().unwrap();
        assert_eq!(history.db, None);
        assert_eq!(history.max_lines, 10_000);
        assert_eq!(history.max_days, 0);
        assert_eq!(history.max_page, 200);
        assert_eq!(history.replay, 0);
        assert!(legacy_caps(&cfg, None, None).has(cap::CHAT_HISTORY));
        assert_eq!(
            ng_caps(&cfg, None, None),
            vec!["history".to_string(), "inbox".to_string()]
        );

        let no_db = parse("[history]\n").unwrap();
        assert!(check_config(&no_db).unwrap_err().contains("needs db"));
        let zero_page = parse("[history]\ndb = \"h.sqlite\"\nmax_page = 0\n").unwrap();
        assert!(check_config(&zero_page).unwrap_err().contains("max_page"));
        let huge_page = parse("[history]\ndb = \"h.sqlite\"\nmax_page = 201\n").unwrap();
        assert!(check_config(&huge_page).unwrap_err().contains("max_page"));
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn inbox_and_history_share_one_store_when_their_path_is_shared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.sqlite");
        let cfg = parse(&format!(
            "[inbox]\ndb = {:?}\n[history]\n",
            path.to_string_lossy()
        ))
        .unwrap();
        let stores = open_runtime_stores(&cfg).unwrap();
        let inbox = stores.inbox.unwrap();
        let history = stores.history.unwrap();
        assert_eq!(
            Arc::as_ptr(&inbox) as *const (),
            Arc::as_ptr(&history) as *const (),
            "one SQLite object must own the shared schema and connection"
        );
    }

    #[test]
    fn the_news_section_defaults_validates_and_is_advertised() {
        let cfg = parse("[inbox]\ndb = \"server.sqlite\"\n[news]\n").unwrap();
        check_config(&cfg).unwrap();
        let news = cfg.news.as_ref().unwrap();
        assert_eq!(news.db, None);
        let markdown = if cfg!(feature = "markdown") {
            hxd_core::MarkdownMode::Render
        } else {
            hxd_core::MarkdownMode::Off
        };
        assert_eq!(
            news.to_policy(),
            hxd_core::NewsPolicy {
                markdown,
                ..hxd_core::NewsPolicy::default()
            },
            "render wherever there is a parser to render with"
        );
        #[cfg(feature = "inbox")]
        assert!(ng_caps(&cfg, None, None).contains(&"news".to_string()));
        assert!(
            !legacy_caps(&cfg, None, None).has(cap::CHAT_HISTORY),
            "news claims no legacy capability bit"
        );

        let alone = parse("[news]\n").unwrap();
        assert!(check_config(&alone).unwrap_err().contains("needs db"));
        let own = parse("[news]\ndb = \"news.sqlite\"\n").unwrap();
        check_config(&own).unwrap();
        let beside_history = parse("[history]\ndb = \"h.sqlite\"\n[news]\n").unwrap();
        check_config(&beside_history).unwrap();

        for (key, value) in [
            ("max_body", "65536"),
            ("max_body", "0"),
            ("max_subject", "256"),
            ("max_depth", "0"),
            ("max_node_depth", "33"),
            ("max_page", "201"),
            ("max_refs", "1000"),
            ("markdown", "\"html\""),
            ("search_max_results", "0"),
            ("search_per_minute", "0"),
            ("search_per_minute", "601"),
        ] {
            let cfg = parse(&format!("[news]\ndb = \"n.sqlite\"\n{key} = {value}\n")).unwrap();
            let err = check_config(&cfg).unwrap_err();
            assert!(err.contains(key), "{key} = {value}: {err}");
        }
        let searchless = parse("[news]\ndb = \"n.sqlite\"\nsearch = false\n").unwrap();
        check_config(&searchless).unwrap();
        assert!(!searchless.news.unwrap().to_policy().search);
        if cfg!(feature = "media") {
            let attached = parse(
                "[news]\ndb = \"n.sqlite\"\nblobs = \"pictures\"\n[news.attach]\nmax_count = 3\n",
            )
            .unwrap();
            check_config(&attached).unwrap();
            let news = attached.news.unwrap();
            assert_eq!(news.blobs, PathBuf::from("pictures"));
            assert_eq!(news.to_policy().attach.unwrap().max_count, 3);

            let zero = parse("[news]\ndb = \"n.sqlite\"\n[news.attach]\nstage_ttl = 0\n").unwrap();
            assert!(check_config(&zero).unwrap_err().contains("news.attach"));
        }
        assert!(
            parse("[news]\ndb = \"n.sqlite\"\nflat_category = \"General\"\n").is_ok(),
            "the 1.2 view is built"
        );
        assert!(
            parse("[news]\ndb = \"n.sqlite\"\nimport = \"old-news\"\n").is_err(),
            "a key for a stage this build does not have is refused, not ignored"
        );
        let legacy = parse(
            "[news]\ndb = \"n.sqlite\"\nflat_category = \"Projects / General\"\n\
             flat_reply = \"new_thread\"\nflat_masthead = \"\"\nlegacy_catlist_max = 50\n",
        )
        .unwrap();
        check_config(&legacy).unwrap();
        let legacy = legacy.news.unwrap().to_legacy();
        assert_eq!(legacy.catlist_max, 50);
        let flat = legacy.flat.unwrap();
        assert_eq!(flat.category, ["Projects", "General"]);
        assert_eq!(flat.reply, hxd_session::FlatReply::NewThread);
        assert_eq!(flat.masthead.as_deref(), Some(""));
        assert_eq!(flat.articles, 100);
        assert_eq!(legacy.default_subject, "(no subject)");
        let unflat = parse("[news]\ndb = \"n.sqlite\"\n").unwrap();
        assert!(unflat.news.unwrap().to_legacy().flat.is_none());
        for bad in [
            "flat_category = \"General//Old\"",
            "flat_reply = \"newest\"",
            "flat_articles = 0",
            "flat_default_subject = \"\"",
            "legacy_catlist_max = 0",
        ] {
            let cfg = parse(&format!("[news]\ndb = \"n.sqlite\"\n{bad}\n")).unwrap();
            assert!(check_config(&cfg).is_err(), "{bad} is refused");
        }
        let masthead = |len: usize| {
            parse(&format!(
                "[news]\ndb = \"n.sqlite\"\nflat_category = \"General\"\n\
                 flat_masthead = \"{}\"\n",
                "x".repeat(len)
            ))
            .unwrap()
        };
        let max = hxd_session::news::MASTHEAD_MAX;
        check_config(&masthead(max)).unwrap();
        let err = check_config(&masthead(max + 1)).unwrap_err();
        assert!(err.contains("flat_masthead"), "{err}");
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn every_section_naming_one_file_shares_one_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.sqlite");
        let cfg = parse(&format!(
            "[inbox]\ndb = {:?}\n[history]\n[news]\n",
            path.to_string_lossy()
        ))
        .unwrap();
        let stores = open_runtime_stores(&cfg).unwrap();
        let inbox = Arc::as_ptr(&stores.inbox.unwrap()) as *const ();
        assert_eq!(inbox, Arc::as_ptr(&stores.history.unwrap()) as *const ());
        assert_eq!(inbox, Arc::as_ptr(&stores.news.unwrap()) as *const ());

        let apart = dir.path().join("news.sqlite");
        let cfg = parse(&format!(
            "[inbox]\ndb = {:?}\n[news]\ndb = {:?}\n",
            path.to_string_lossy(),
            apart.to_string_lossy()
        ))
        .unwrap();
        let stores = open_runtime_stores(&cfg).unwrap();
        assert_ne!(
            Arc::as_ptr(&stores.inbox.unwrap()) as *const (),
            Arc::as_ptr(&stores.news.unwrap()) as *const (),
            "a section naming its own file gets its own store"
        );
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn equivalent_database_paths_share_one_store() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("server.sqlite");
        let dotted = dir.path().join(".").join("server.sqlite");
        let cfg = parse(&format!(
            "[inbox]\ndb = {:?}\n[history]\ndb = {:?}\n",
            plain.to_string_lossy(),
            dotted.to_string_lossy()
        ))
        .unwrap();
        let stores = open_runtime_stores(&cfg).unwrap();
        let inbox = stores.inbox.unwrap();
        let history = stores.history.unwrap();
        assert_eq!(
            Arc::as_ptr(&inbox) as *const (),
            Arc::as_ptr(&history) as *const (),
            "equivalent paths must not create two schema owners"
        );
        assert_eq!(
            database_path(Path::new("server.sqlite")).unwrap(),
            std::env::current_dir().unwrap().join("server.sqlite")
        );
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn a_fingerprint_is_accepted_in_the_form_an_operator_has_it() {
        // The account file's `[identity] fingerprint` and the roster
        // both carry the 52-character form; requiring hex meant that
        // after `rm alice.toml` there was no way to purge her mail.
        let raw = [0x5au8; 32];
        let text = hl_identity::Fingerprint(raw).to_string();
        assert_eq!(text.len(), 52);
        assert_eq!(parse_fingerprint(&text), Ok(raw));
        assert_eq!(parse_fingerprint(&format!("  {text}  ")), Ok(raw));
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_fingerprint(&hex), Ok(raw));
        assert!(parse_fingerprint("nonsense").is_err());
    }

    #[test]
    fn the_ng_sections_forwarded_header_is_optional_and_checked() {
        let cfg = parse("[ng]\nbind = \"127.0.0.1:5700\"\n").unwrap();
        assert_eq!(cfg.ng.as_ref().unwrap().forwarded_header, "x-forwarded-for");
        let cfg = parse("[ng]\nforwarded_header = \"none\"\n").unwrap();
        assert_eq!(
            ForwardedHeader::parse(&cfg.ng.unwrap().forwarded_header).unwrap(),
            ForwardedHeader::None
        );
        // A header we don't read is a startup error: an operator who
        // names one is asserting their proxy writes it, and believing
        // the wrong one is what §5.3 is about.
        let cfg = parse("[ng]\nforwarded_header = \"x-real-ip\"\n").unwrap();
        assert!(ForwardedHeader::parse(&cfg.ng.unwrap().forwarded_header).is_err());
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn purging_a_server_with_no_database_makes_none() {
        // `open_inbox` creates the file when it is missing, which is
        // right at startup and wrong for an operator command —
        // `--dry-run` in particular, whose whole promise is that it
        // changes nothing.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("messages.db");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = db.clone();
        let err = inbox_purge(&cfg, "alice", None, true).unwrap_err();
        assert!(err.contains("nothing to purge"), "{err}");
        assert!(!db.exists(), "a dry run must not create a database");
        let err = inbox_purge(&cfg, "alice", None, false).unwrap_err();
        assert!(err.contains("nothing to purge"), "{err}");
        assert!(!db.exists());
    }

    #[test]
    fn a_push_section_is_checked_before_anything_binds() {
        let ok = parse("[push]\ncontact = \"mailto:admin@example.org\"\n")
            .expect("contact is the only key the section itself requires");
        let push = ok.push.unwrap();
        assert_eq!(push.content, "sender", "the default is not `full`");
        assert_eq!(push.vapid_key, PathBuf::from("vapid.key"));
        assert_eq!(push.max_inflight, 64);

        // The checks that happen where the operator can be told, rather
        // than at the first notification nobody was watching for.
        let refused = |toml: &str| {
            let config = parse(toml).expect("it parses; it is the section that is wrong");
            match crate::push::build(&config) {
                Err(e) => e,
                Ok(_) => panic!("{toml:?} should have been refused"),
            }
        };
        assert!(
            refused("[push]\ncontact = \"mailto:a@example.org\"\ncontent = \"loud\"\n")
                .contains("content")
        );
        assert!(
            refused("[push]\ncontact = \"admin@example.org\"\n").contains("mailto:"),
            "a contact a push service cannot use is refused at startup"
        );
        assert!(
            refused("[push]\ncontact = \"mailto:a@example.org\"\nmax_inflight = 0\n")
                .contains("max_inflight")
        );

        // And where the devices go is a startup question, not a "store
        // was not opened" after the key file has been written.
        let alone = parse("[push]\ncontact = \"mailto:a@example.org\"\n").unwrap();
        assert!(check_config(&alone)
            .unwrap_err()
            .contains("[push] needs db"));
        for toml in [
            "[push]\ncontact = \"mailto:a@example.org\"\ndb = \"push.sqlite\"\n",
            "[inbox]\ndb = \"inbox.sqlite\"\n\n[push]\ncontact = \"mailto:a@example.org\"\n",
            "[news]\ndb = \"news.sqlite\"\n\n[push]\ncontact = \"mailto:a@example.org\"\n",
        ] {
            check_config(&parse(toml).unwrap()).unwrap_or_else(|e| panic!("{toml:?}: {e}"));
        }
        let none =
            parse("[push]\ncontact = \"mailto:a@example.org\"\ndb = \"p\"\nmax_devices = 0\n")
                .unwrap();
        assert!(check_config(&none).unwrap_err().contains("max_devices"));
    }

    /// A missing key is a first start only when there are no devices: a
    /// deleted file, or a moved `vapid_key`, must not mint a key every
    /// registered device is already invalid against.
    #[cfg(feature = "push")]
    #[tokio::test]
    async fn a_lost_key_with_devices_registered_refuses_to_start() {
        use hxd_core::push::{Device, DeviceId, MemoryDevices};
        use hxd_core::PushStore;

        let dir = tempfile::tempdir().unwrap();
        let mut config = parse("[push]\ncontact = \"mailto:a@example.org\"\ndb = \"p\"\n").unwrap();
        config.push.as_mut().unwrap().vapid_key = dir.path().join("vapid.key");
        let push = crate::push::build(&config).unwrap().unwrap();

        let devices = Arc::new(MemoryDevices::new());
        devices
            .register(
                &Device {
                    owner: hxd_core::inbox::Mailbox::login("alice"),
                    devid: DeviceId::parse("alices-phone").unwrap(),
                    endpoint: "https://push.example/1".into(),
                    p256dh: [4; 65],
                    auth: [9; 16],
                    expires: None,
                    registered_at: std::time::SystemTime::now(),
                    last_push_at: None,
                },
                8,
            )
            .unwrap();
        let refused = match push.start(devices) {
            Err(e) => e,
            Ok(_) => panic!("a missing key with devices registered must not start"),
        };
        assert!(refused.contains("push rekey"), "{refused}");
        assert!(
            !dir.path().join("vapid.key").exists(),
            "and nothing was minted"
        );

        // An empty registry is a first start.
        push.start(Arc::new(MemoryDevices::new())).unwrap();
        assert!(dir.path().join("vapid.key").exists());
        assert!(push.info().is_some(), "and the login block has its key");
    }

    /// `hxd push rekey` replaces the key and drops the rows it
    /// invalidated, in the file the server keeps them in.
    #[cfg(feature = "push")]
    #[test]
    fn a_rekey_takes_the_devices_with_the_old_key() {
        use hxd_core::push::{Device, DeviceId};
        use hxd_core::PushStore;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("push.sqlite");
        let mut config = parse("[push]\ncontact = \"mailto:a@example.org\"\ndb = \"p\"\n").unwrap();
        let section = config.push.as_mut().unwrap();
        section.db = Some(db.clone());
        section.vapid_key = dir.path().join("vapid.key");
        let old = hxd_push_webpush::Vapid::load_or_create(
            &dir.path().join("vapid.key"),
            "mailto:a@example.org",
            true,
        )
        .unwrap()
        .public_key()
        .to_string();
        {
            let store =
                hxd_store_sqlite::SqliteStore::open(&db, hxd_store_sqlite::Synchronous::Normal)
                    .unwrap();
            store
                .register(
                    &Device {
                        owner: hxd_core::inbox::Mailbox::login("alice"),
                        devid: DeviceId::parse("alices-phone").unwrap(),
                        endpoint: "https://push.example/1".into(),
                        p256dh: [4; 65],
                        auth: [9; 16],
                        expires: None,
                        registered_at: std::time::SystemTime::now(),
                        last_push_at: None,
                    },
                    8,
                )
                .unwrap();
        }
        let (dropped, new) = crate::push::rekey(&config).unwrap();
        assert_eq!(dropped, 1);
        assert_ne!(new, old);
        let store = hxd_store_sqlite::SqliteStore::open(&db, hxd_store_sqlite::Synchronous::Normal)
            .unwrap();
        assert!(!store.any_devices().unwrap());
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn a_purge_takes_the_push_devices_too() {
        use hxd_core::push::{Device, DeviceId};
        use hxd_core::PushStore;

        // A database at `path` in which alice has registered a phone.
        fn alice_has_a_phone(path: &Path) {
            let store =
                hxd_store_sqlite::SqliteStore::open(path, hxd_store_sqlite::Synchronous::Normal)
                    .unwrap();
            store
                .register(
                    &Device {
                        owner: hxd_core::inbox::Mailbox::login("alice"),
                        devid: DeviceId::parse("alices-phone").unwrap(),
                        endpoint: "https://push.example/1".into(),
                        p256dh: [4; 65],
                        auth: [9; 16],
                        expires: None,
                        registered_at: std::time::SystemTime::now(),
                        last_push_at: None,
                    },
                    8,
                )
                .unwrap();
        }

        // The shared file, found the way the news subscriptions are: a
        // later holder of the login must not inherit someone's phone.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("server.sqlite");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = db.clone();
        cfg.paths.accounts = dir.path().join("accounts");
        alice_has_a_phone(&db);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 1);
        assert_eq!(
            inbox_purge(&cfg, "alice", None, true).unwrap(),
            0,
            "and the next alice is pushed at nobody's phone"
        );

        // News keeping a file of its own does not move the devices: they
        // are where the server keeps them, beside the mail.
        let mail = dir.path().join("mail.sqlite");
        let news = dir.path().join("own-news.sqlite");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n\n[news]\n\n[news.notify]\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = mail.clone();
        cfg.news.as_mut().unwrap().db = Some(news);
        cfg.paths.accounts = dir.path().join("accounts");
        alice_has_a_phone(&mail);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 0);

        // `[push]` keeping a file of its own is where the server writes
        // them, so it is where the purge looks — beside mail or with no
        // mail at all.
        let own = dir.path().join("own-push.sqlite");
        let push = format!("[push]\ncontact = \"mailto:a@example.org\"\ndb = {own:?}\n");
        let mut cfg = parse(&format!("[inbox]\ndb = \"placeholder\"\n\n{push}")).unwrap();
        cfg.inbox.as_mut().unwrap().db = dir.path().join("mail-too.sqlite");
        cfg.paths.accounts = dir.path().join("accounts");
        alice_has_a_phone(&own);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 1);

        let mut cfg = parse(&push).unwrap();
        cfg.paths.accounts = dir.path().join("accounts");
        alice_has_a_phone(&own);
        assert_eq!(
            inbox_purge(&cfg, "alice", None, false).unwrap(),
            1,
            "a server that keeps push and no mail is purged too, not refused"
        );
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn a_purge_takes_the_news_subscriptions_too() {
        use hxd_core::news::{NewNode, NodeKind, SubScope};
        use hxd_core::NewsStore;

        // A database at `path` in which alice follows one category.
        fn alice_follows_one(path: &Path) {
            let store =
                hxd_store_sqlite::SqliteStore::open(path, hxd_store_sqlite::Synchronous::Normal)
                    .unwrap();
            let node = NewNode {
                parent: None,
                kind: NodeKind::Category,
                name: "General".into(),
                guid: [1; 16],
                at: std::time::SystemTime::now(),
            };
            let cat = store.create_node(&node, 16).unwrap().id;
            store
                .subscribe(
                    &hxd_core::inbox::Mailbox::login("alice"),
                    SubScope::Category(cat),
                    10,
                    std::time::SystemTime::now(),
                )
                .unwrap();
        }

        // No `db` of its own: news shares the inbox's file, as the design
        // recommends, and the purge has to find it there.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("server.sqlite");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n\n[news]\n\n[news.notify]\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = db.clone();
        cfg.paths.accounts = dir.path().join("accounts");
        alice_follows_one(&db);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 1);
        assert_eq!(
            inbox_purge(&cfg, "alice", None, true).unwrap(),
            0,
            "a later alice follows nothing she did not ask for"
        );

        // And on a server that keeps news and no mail at all.
        let news_only = dir.path().join("news.sqlite");
        let mut cfg = parse("[news]\ndb = \"placeholder\"\n\n[news.notify]\n").unwrap();
        cfg.news.as_mut().unwrap().db = Some(news_only.clone());
        cfg.paths.accounts = dir.path().join("accounts");
        alice_follows_one(&news_only);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 0);

        // And with `[news]` taken out since: the file it shared keeps what
        // it wrote, for a later alice to find when news comes back.
        let shared = dir.path().join("news-off.sqlite");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = shared.clone();
        cfg.paths.accounts = dir.path().join("accounts");
        alice_follows_one(&shared);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 1);
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 0);
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn a_dry_run_against_a_real_database_leaves_the_database_alone() {
        // The other half: an existing file was opened the startup way,
        // which switches it to WAL and *migrates* it — so a dry run
        // against a server one version back did the upgrade the operator
        // was still deciding about, and one against a fresh 0-byte file
        // wrote a whole schema.
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("messages.db");
        std::fs::write(&db, b"").unwrap();
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = db.clone();

        // A file with no schema in it holds no mail, and says so
        // without writing one.
        let err = inbox_purge(&cfg, "alice", None, true).unwrap_err();
        assert!(err.contains("no schema"), "{err}");
        assert_eq!(
            std::fs::metadata(&db).unwrap().len(),
            0,
            "a dry run must not create a schema"
        );
        assert!(
            !dir.path().join("messages.db-wal").exists(),
            "nor switch the journal mode"
        );

        // A real database, as a running server leaves it.
        inbox_purge(&cfg, "alice", None, false).unwrap();
        let before = std::fs::read(&db).unwrap();
        assert!(!before.is_empty());

        // And a dry run over that one reads it and leaves it alone.
        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 0);
        assert_eq!(
            std::fs::read(&db).unwrap(),
            before,
            "a dry run must not migrate, vacuum or otherwise touch the file"
        );
        // What it does not promise is an untouched *directory*: reading a
        // WAL database creates the `-shm` the format needs, and an empty
        // `-wal` with it, wherever the directory allows. Asserted rather
        // than left implied, because the sibling test below asserts the
        // absence of both for the one case that cannot afford them, and
        // the difference between the two is the whole contract.
        assert!(
            dir.path().join("messages.db-shm").exists(),
            "the ordinary read takes the sidecar path"
        );
    }

    #[cfg(feature = "inbox")]
    #[test]
    fn a_dry_run_counts_every_row_the_real_purge_removes() {
        use hxd_core::inbox::{Mailbox, MessageKind, MessageStore, NewMessage};
        use std::time::SystemTime;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("messages.db");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = db.clone();
        let store = hxd_store_sqlite::SqliteStore::open(&db, hxd_store_sqlite::Synchronous::Normal)
            .unwrap();
        let alice = Mailbox::login("alice");
        let bob = Mailbox::login("bob");
        let carol = Mailbox::login("carol");
        let push = |to: &Mailbox, from: &Mailbox, kind| {
            store
                .push(
                    &NewMessage {
                        recipient: to.clone(),
                        sender: Some(from.clone()),
                        sender_nick: from.login.clone(),
                        body: "row".into(),
                        sent_at: SystemTime::UNIX_EPOCH,
                        guid: None,
                        kind,
                        media: None,
                    },
                    usize::MAX,
                )
                .unwrap();
        };
        push(&alice, &bob, MessageKind::Message);
        push(&alice, &carol, MessageKind::Message);
        push(&alice, &bob, MessageKind::ReadReceipt);
        for _ in 0..3 {
            push(&bob, &alice, MessageKind::Message);
        }
        store
            .set_blocked(&alice, &bob, true, SystemTime::UNIX_EPOCH)
            .unwrap();
        store
            .set_blocked(&carol, &alice, true, SystemTime::UNIX_EPOCH)
            .unwrap();
        drop(store);

        assert_eq!(inbox_purge(&cfg, "alice", None, true).unwrap(), 8);
        assert_eq!(inbox_purge(&cfg, "alice", None, false).unwrap(), 8);
    }

    #[cfg(all(feature = "inbox", unix))]
    #[test]
    fn a_stopped_inbox_can_be_dry_run_from_a_read_only_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("messages.db");
        let mut cfg = parse("[inbox]\ndb = \"placeholder\"\n").unwrap();
        cfg.inbox.as_mut().unwrap().db = db.clone();
        drop(
            hxd_store_sqlite::SqliteStore::open(&db, hxd_store_sqlite::Synchronous::Normal)
                .unwrap(),
        );

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let result = inbox_purge(&cfg, "alice", None, true);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result.unwrap(), 0);
        assert!(!dir.path().join("messages.db-shm").exists());
        assert!(!dir.path().join("messages.db-wal").exists());
    }

    /// Parse a config the way [`Config::load`] would, without a file.
    fn parse(toml_text: &str) -> Result<Config, String> {
        toml::from_str(toml_text).map_err(|e| e.to_string())
    }

    /// A `[voice.video]` section with every field distinct, so a limit
    /// copied into the wrong slot shows up as a mismatched number rather
    /// than an equal one.
    fn distinct_video() -> VideoSection {
        VideoSection {
            max_cameras_per_room: 11,
            max_screens_per_room: 12,
            max_width: 1281,
            max_height: 721,
            max_fps: 31,
            max_bitrate: 1_500_001,
            screen_max_width: 1921,
            screen_max_height: 1081,
            screen_max_fps: 16,
            screen_max_bitrate: 2_500_001,
        }
    }

    #[test]
    fn every_video_limit_lands_on_the_kind_it_names() {
        let cfg = distinct_video().to_video_config();
        assert_eq!(cfg.camera.max_width, 1281);
        assert_eq!(cfg.camera.max_height, 721);
        assert_eq!(cfg.camera.max_fps, 31);
        assert_eq!(cfg.camera.max_bitrate, 1_500_001);
        assert_eq!(cfg.camera.max_per_room, 11);
        assert_eq!(cfg.screen.max_width, 1921);
        assert_eq!(cfg.screen.max_height, 1081);
        assert_eq!(cfg.screen.max_fps, 16);
        assert_eq!(cfg.screen.max_bitrate, 2_500_001);
        assert_eq!(cfg.screen.max_per_room, 12);
    }

    #[test]
    fn a_video_section_is_read_out_of_the_voice_table() {
        // Nested, not beside `[voice]`: video shares the voice room's
        // transport, so the TOML nests the way the subsystems do.
        let c = parse(
            r#"
            [server]
            bind = "0.0.0.0:5500"

            [voice]
            advertise = ["198.51.100.9:5504"]
            max_per_room = 24

            [voice.video]
            max_cameras_per_room = 4
            max_screens_per_room = 2
            max_width = 1280
            max_height = 720
            max_fps = 24
            max_bitrate = 1200000
            "#,
        )
        .expect("a realistic voice-with-video config");
        let voice = c.voice.as_ref().expect("[voice]");
        assert_eq!(voice.max_per_room, 24);
        let video = voice.video.as_ref().expect("[voice.video]");
        assert_eq!(video.max_cameras_per_room, 4);
        assert_eq!(video.max_width, 1280);
        // Anything the snippet left out keeps the spec's default rather
        // than becoming zero.
        assert_eq!(video.screen_max_fps, default_screen_fps());
        assert!(video_enabled(&c));
    }

    #[test]
    fn a_voice_section_without_a_video_table_leaves_video_off() {
        let c = parse(
            r#"
            [voice]
            advertise = ["198.51.100.9:5504"]
            "#,
        )
        .expect("voice without video");
        assert!(c.voice.as_ref().unwrap().video.is_none());
        assert!(!video_enabled(&c));
        // And the ceilings still resolve, to the built-in defaults, so
        // nothing downstream has to special-case the absence.
        assert_eq!(
            c.voice.as_ref().unwrap().video_config().camera.max_width,
            hxd_core::VideoLimits::CAMERA.max_width
        );
    }

    #[test]
    fn max_per_room_defaults_to_the_spec_value_and_may_reach_the_ceiling() {
        let c = parse("[voice]\nadvertise = [\"198.51.100.9:5504\"]\n").unwrap();
        assert_eq!(
            c.voice.as_ref().unwrap().max_per_room,
            hxd_core::DEFAULT_MAX_PER_ROOM
        );
        let c = parse(&format!(
            "[voice]\nadvertise = [\"198.51.100.9:5504\"]\nmax_per_room = {MAX_PER_ROOM_CEILING}\n"
        ))
        .expect("the ceiling itself is a legal value");
        assert_eq!(c.voice.unwrap().max_per_room, MAX_PER_ROOM_CEILING);
    }

    #[test]
    fn a_max_per_room_the_wire_cannot_carry_is_a_config_error() {
        // Six bytes a participant in a `u16`-length chunk, so a room this
        // size would trip the assertion in `pack_frame` inside a writer
        // task and leave that connection mute. The operator hears about
        // it now instead.
        let err = parse(&format!(
            "[voice]\nadvertise = [\"198.51.100.9:5504\"]\nmax_per_room = {}\n",
            u16::MAX as usize / 6 + 1
        ))
        .unwrap_err();
        assert!(err.contains(&MAX_PER_ROOM_CEILING.to_string()), "{err}");
        assert!(err.contains("max_per_room"), "{err}");
    }

    #[test]
    fn neither_wire_advertises_voice_or_video_without_an_sfu() {
        // `[voice.video]` in the file is not enough: the bits and the
        // strings follow the SFU that was actually built, never the
        // config alone.
        let c = parse(
            r#"
            [voice]
            advertise = ["198.51.100.9:5504"]

            [voice.video]
            max_width = 1280
            "#,
        )
        .unwrap();
        assert!(video_enabled(&c));
        // Text-Encoding is the one bit that needs nothing built.
        assert_eq!(
            legacy_caps(&c, None, None),
            Caps::empty().with(cap::TEXT_ENCODING)
        );
        assert!(ng_caps(&c, None, None).is_empty());
    }

    /// The capability answers with a real SFU behind them. Building one
    /// binds a UDP socket, which is all `Voice` needs — no `Core`, no
    /// listener, no session — so these can be unit tests. An ephemeral
    /// port keeps them from colliding with anything.
    #[cfg(feature = "voice")]
    mod with_an_sfu {
        use super::*;

        fn voiced(video: bool) -> (Config, Voice) {
            let mut text = String::from(
                "[voice]\nbind = \"127.0.0.1:0\"\nadvertise = [\"198.51.100.9:5504\"]\n",
            );
            if video {
                text.push_str("\n[voice.video]\nmax_width = 1280\n");
            }
            let config = parse(&text).unwrap();
            let voice = voice::build(&config)
                .expect("a concrete bind and one advertised address")
                .expect("[voice] is present");
            (config, voice)
        }

        #[test]
        fn voice_alone_is_advertised_when_video_is_not_configured() {
            let (config, voice) = voiced(false);
            let caps = legacy_caps(&config, Some(&voice), None);
            assert!(caps.has(cap::VOICE));
            assert!(!caps.has(cap::VIDEO));
            assert_eq!(
                ng_caps(&config, Some(&voice), None),
                vec!["voice".to_string()]
            );
        }

        #[test]
        fn video_is_advertised_only_alongside_voice() {
            let (config, voice) = voiced(true);
            let caps = legacy_caps(&config, Some(&voice), None);
            assert!(caps.has(cap::VOICE));
            assert!(caps.has(cap::VIDEO));
            assert_eq!(
                ng_caps(&config, Some(&voice), None),
                vec!["voice".to_string(), "video".to_string()]
            );
        }
    }

    #[test]
    fn files_requires_exactly_one_source_mode_and_secure_nonzero_limits() {
        let local = parse("[files]\nroot = \"files\"\n").unwrap();
        check_config(&local).unwrap();
        let files = local.files.unwrap();
        assert_eq!(files.root, Some(PathBuf::from("files")));
        assert!(files.manifest.is_none());
        assert_eq!(files.max_partials, 1_024);
        assert_eq!(files.max_partials_per_account, 4);
        assert_eq!(files.upload_timeout, 60 * 60);

        let manifest =
            parse("[files]\nmanifest = \"files.json\"\norigin = \"https://example.test/\"\n")
                .unwrap();
        check_config(&manifest).unwrap();

        for invalid in [
            "[files]\n",
            "[files]\nmanifest = \"files.json\"\n",
            "[files]\norigin = \"https://example.test/\"\n",
            "[files]\nroot = \"files\"\nmanifest = \"files.json\"\norigin = \"https://example.test/\"\n",
        ] {
            let config = parse(invalid).unwrap();
            assert!(check_config(&config).unwrap_err().contains("either root"));
        }
        for key in [
            "max_partial_bytes",
            "max_partials",
            "max_partials_per_account",
            "upload_timeout",
            "partial_ttl",
        ] {
            let config = parse(&format!("[files]\nroot = \"files\"\n{key} = 0\n")).unwrap();
            assert!(check_config(&config).is_err(), "{key}");
        }
    }
}
