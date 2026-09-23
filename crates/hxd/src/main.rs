//! The hxd-ng binary.
//!
//! ```text
//! hxd [--config hxd-ng.toml]
//! ```
//!
//! Debug categories go through `HXD_DEBUG` (comma-separated; `proto` is the
//! wire trace, `all` is everything), mirroring gtkhx's `GTKHX_DEBUG` so a
//! client trace and a server trace of the same session line up. `RUST_LOG`
//! still works and wins when set.

use std::path::PathBuf;

use hxd::{build_ctx, Config};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    let filter = if let Ok(spec) = std::env::var("RUST_LOG") {
        EnvFilter::new(spec)
    } else if let Ok(cats) = std::env::var("HXD_DEBUG") {
        let mut spec = String::from("info");
        for cat in cats.split(',').map(str::trim).filter(|c| !c.is_empty()) {
            if cat == "all" {
                spec = String::from("debug");
                break;
            }
            // Each category is a tracing target: HXD_DEBUG=proto turns on
            // the wire trace, etc.
            spec.push_str(&format!(",{cat}=debug"));
        }
        EnvFilter::new(spec)
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// SIGHUP re-reads `[identity]`'s revocation lists, and — on a
/// registrar — the names it reserves and its invites file, and nothing
/// else (`docs/identity-registrar.md`): an operator locking out a stolen
/// key should not have to restart the server and drop everyone else to
/// do it. `systemctl reload` sends exactly this.
#[cfg(unix)]
async fn reload_on_hangup(
    core: std::sync::Arc<hxd_core::Core>,
    registrar: Option<std::sync::Arc<hxd_registrar::Registrar>>,
    path: PathBuf,
) {
    let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("install SIGHUP handler: {e}; revocations need a restart");
            return;
        }
    };
    while hangup.recv().await.is_some() {
        match hxd::reload_revocations(&core, &path) {
            Ok((listed, ended)) => tracing::info!(
                "SIGHUP: {listed} revoked keys installed from {}; {} sessions ended",
                path.display(),
                ended.len()
            ),
            Err(e) => tracing::error!("SIGHUP: {e}; the revocation lists are unchanged"),
        }
        if let Some(reg) = registrar.as_deref() {
            match hxd::registrar::reload(reg, &path) {
                Ok((reserved, invites)) => tracing::info!(
                    "SIGHUP: registrar reserves {reserved} names; {invites} new invites"
                ),
                Err(e) => tracing::error!("SIGHUP: registrar: {e}"),
            }
        }
    }
}

async fn shutdown_signal() -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| format!("install SIGTERM handler: {e}"))?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|e| format!("install Ctrl-C handler: {e}"))
            }
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("install Ctrl-C handler: {e}"))
}

/// What the command line asked for.
enum Command {
    Serve,
    /// `inbox purge <login> [--fingerprint FP] [--dry-run]`.
    InboxPurge {
        login: String,
        fingerprint: Option<String>,
        dry_run: bool,
    },
    /// `news-reindex`.
    NewsReindex,
    /// `push rekey`.
    PushRekey,
    /// `identity revoke <fingerprint> [--device] [--lift]`.
    IdentityRevoke {
        fingerprint: String,
        what: hxd::RevokeWhat,
        lift: bool,
    },
    /// `registrar freeze <fingerprint> [--lift]`.
    RegistrarFreeze {
        fingerprint: String,
        lift: bool,
    },
    /// `registrar revoke <handle> --reason R`.
    RegistrarRevoke {
        handle: String,
        reason: String,
    },
    /// `registrar recover <handle> --identity FP [--keep-age]`.
    RegistrarRecover {
        handle: String,
        identity: String,
        keep_age: bool,
    },
    /// `registrar invites --add N`.
    RegistrarInvites {
        add: usize,
    },
    /// `registrar inspect <host>`.
    RegistrarInspect {
        target: String,
    },
    /// `history redact <id> --reason R`.
    HistoryRedact {
        id: u64,
        reason: String,
    },
    /// `media revoke <handle> --reason R [--no-block]`.
    MediaRevoke,
    /// `purge <login> [--fingerprint FP] [--since 1h] --reason R [--dry-run]`.
    Purge {
        login: String,
        fingerprint: Option<String>,
        since: std::time::Duration,
        reason: String,
        dry_run: bool,
    },
    /// `reports [--all]`.
    Reports {
        all: bool,
    },
    /// `reports close <id> --outcome O [--note N] [--of ID]`.
    ReportsClose {
        id: u64,
        outcome: String,
        note: Option<String>,
        of: Option<u64>,
    },
    /// `moderation log [--limit N]`.
    ModerationLog {
        limit: usize,
    },
}

const USAGE: &str = "usage:\n  \
hxd [--config hxd-ng.toml]\n  \
hxd [--config …] inbox purge <login> [--fingerprint FP] [--dry-run]\n  \
hxd [--config …] news-reindex\n  \
hxd [--config …] push rekey\n  \
hxd [--config …] identity revoke <fingerprint> [--device] [--lift]\n  \
hxd [--config …] registrar freeze <fingerprint> [--lift]\n  \
hxd [--config …] registrar revoke <handle> --reason abuse|lapsed|unspecified\n  \
hxd [--config …] registrar recover <handle> --identity <fingerprint> [--keep-age]\n  \
hxd [--config …] registrar invites --add N\n  \
hxd registrar inspect <host>\n  \
hxd [--config …] history redact <line-id> --reason R\n  \
hxd [--config …] media revoke <handle> --reason R [--no-block]\n  \
hxd [--config …] purge <login> [--fingerprint FP] [--since 1h] --reason R [--dry-run]\n  \
hxd [--config …] reports [--all]\n  \
hxd [--config …] reports close <id> --outcome dismissed|duplicate [--note N] [--of ID]\n  \
hxd [--config …] moderation log [--limit N]\n\n\
`news-reindex` rebuilds the news search index from the articles: the\n\
repair for an index that has drifted.\n\n\
`push rekey` replaces the server's VAPID key and drops every registered\n\
push device, which the old key's subscriptions were bound to; clients\n\
re-register at their next login. Stop the server first.\n\n\
`identity revoke` adds an identity's fingerprint to [identity]\n\
revoked_identities in the config file, or with --device a device's to\n\
revoked_devices; --lift takes it out again. Nothing changes in a running\n\
server until it is sent SIGHUP (`systemctl reload`), which ends every\n\
session the key holds.\n\n\
`registrar freeze` publishes a signed freeze of an identity this\n\
registrar attests (--lift publishes the lift); `revoke` withdraws the\n\
attestations of a handle, and with --reason abuse keeps its holder from\n\
reissuing it; `recover` gives a handle to a new key after the holder\n\
proved themselves out of band; `invites --add` prints new invite codes\n\
and appends them to the invites file. All of them act on the running\n\
server's store directly. `inspect` fetches another registrar's log and\n\
stats, verifies them, and prints the shape of the last month.\n\n\
`inbox purge` takes an account's mail, news subscriptions and push\n\
devices with it when the account is deleted — otherwise the freed\n\
login's next holder inherits them.\n\
Pass --fingerprint (the value in the account's [identity] table, or\n\
its hex) when the account file is already gone. --dry-run says how\n\
much would go without taking it.\n\n\
The moderation commands act as `cli` in the audit trail, against the\n\
database directly, so they work with the server down; a running server\n\
sees the change on its next read. `history redact` blanks a public\n\
line and keeps its words for moderators; `purge` redacts a person's\n\
lines and deletes their articles from the last --since (1h unless\n\
said; `all` for everything). Images live in the running server's\n\
memory, so `media revoke` — and a purge's images — are an ng\n\
moderator's to do. `reports` lists what is open (--all for\n\
everything) and `reports close` dismisses one or marks it a\n\
duplicate --of another; `moderation log` is the audit trail.";

fn parse_args() -> Result<(PathBuf, Command), String> {
    let mut config = PathBuf::from("hxd-ng.toml");
    let mut rest = Vec::new();
    let mut fingerprint = None;
    let mut dry_run = false;
    let mut device = false;
    let mut lift = false;
    let mut reason = None;
    let mut identity = None;
    let mut keep_age = false;
    let mut add = None;
    let mut since = None;
    let mut no_block = false;
    let mut all = false;
    let mut outcome = None;
    let mut note = None;
    let mut of = None;
    let mut limit = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--config needs a path".to_string())?;
            }
            "--fingerprint" => {
                fingerprint = Some(
                    args.next()
                        .ok_or_else(|| "--fingerprint needs a value".to_string())?,
                );
            }
            "--dry-run" => dry_run = true,
            "--device" => device = true,
            "--lift" => lift = true,
            "--keep-age" => keep_age = true,
            "--reason" => {
                reason = Some(
                    args.next()
                        .ok_or_else(|| "--reason needs a value".to_string())?,
                );
            }
            "--identity" => {
                identity = Some(
                    args.next()
                        .ok_or_else(|| "--identity needs a fingerprint".to_string())?,
                );
            }
            "--add" => {
                add = Some(
                    args.next()
                        .and_then(|n| n.parse::<usize>().ok())
                        .filter(|n| *n > 0)
                        .ok_or_else(|| "--add needs a positive number".to_string())?,
                );
            }
            "--since" => {
                since = Some(hxd::moderation::parse_since(
                    &args
                        .next()
                        .ok_or_else(|| "--since needs a duration".to_string())?,
                )?);
            }
            "--no-block" => no_block = true,
            "--all" => all = true,
            "--outcome" => {
                outcome = Some(
                    args.next()
                        .ok_or_else(|| "--outcome needs dismissed or duplicate".to_string())?,
                );
            }
            "--note" => {
                note = Some(
                    args.next()
                        .ok_or_else(|| "--note needs a value".to_string())?,
                );
            }
            "--of" => {
                of = Some(
                    args.next()
                        .and_then(|n| n.parse::<u64>().ok())
                        .ok_or_else(|| "--of needs a report id".to_string())?,
                );
            }
            "--limit" => {
                limit = Some(
                    args.next()
                        .and_then(|n| n.parse::<usize>().ok())
                        .filter(|n| (1..=100).contains(n))
                        .ok_or_else(|| "--limit needs a number from 1 to 100".to_string())?,
                );
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') => return Err(format!("unknown argument {other:?}")),
            other => rest.push(other.to_string()),
        }
    }
    // A flag that belongs to one subcommand is refused on any other, as
    // `--fingerprint` always was: `hxd --lift identity revok …` should
    // not quietly start a server.
    let words = rest.iter().map(String::as_str).collect::<Vec<_>>();
    if device && !matches!(words[..], ["identity", "revoke", _]) {
        return Err("--device belongs to `identity revoke`".to_string());
    }
    if lift
        && !matches!(
            words[..],
            ["identity", "revoke", _] | ["registrar", "freeze", _]
        )
    {
        return Err("--lift belongs to `identity revoke` and `registrar freeze`".to_string());
    }
    if reason.is_some()
        && !matches!(
            words[..],
            ["registrar", "revoke", _]
                | ["history", "redact", _]
                | ["media", "revoke", _]
                | ["purge", _]
        )
    {
        return Err(
            "--reason belongs to `registrar revoke`, `history redact`, `media revoke` and \
             `purge`"
                .to_string(),
        );
    }
    if since.is_some() && !matches!(words[..], ["purge", _]) {
        return Err("--since belongs to `purge`".to_string());
    }
    if no_block && !matches!(words[..], ["media", "revoke", _]) {
        return Err("--no-block belongs to `media revoke`".to_string());
    }
    if all && !matches!(words[..], ["reports"]) {
        return Err("--all belongs to `reports`".to_string());
    }
    if (outcome.is_some() || note.is_some() || of.is_some())
        && !matches!(words[..], ["reports", "close", _])
    {
        return Err("--outcome, --note and --of belong to `reports close`".to_string());
    }
    if limit.is_some() && !matches!(words[..], ["moderation", "log"]) {
        return Err("--limit belongs to `moderation log`".to_string());
    }
    if (fingerprint.is_some() || dry_run)
        && matches!(
            words.first(),
            Some(&"history" | &"media" | &"reports" | &"moderation")
        )
    {
        return Err("--fingerprint and --dry-run belong to `inbox purge` and `purge`".to_string());
    }
    if (identity.is_some() || keep_age) && !matches!(words[..], ["registrar", "recover", _]) {
        return Err("--identity and --keep-age belong to `registrar recover`".to_string());
    }
    if add.is_some() && !matches!(words[..], ["registrar", "invites"]) {
        return Err("--add belongs to `registrar invites`".to_string());
    }
    if (fingerprint.is_some() || dry_run) && words.first() == Some(&"registrar") {
        return Err("--fingerprint and --dry-run belong to `inbox purge`".to_string());
    }
    // `purge` shares `--fingerprint` and `--dry-run` with `inbox purge`,
    // and is the only other command that does. After every other flag's
    // check, so a stray one is refused here as anywhere.
    if let ["purge", login] = words[..] {
        // A dry run changes nothing, so it has nothing to say why about.
        let reason = match (reason, dry_run) {
            (Some(reason), _) => reason,
            (None, true) => String::new(),
            (None, false) => return Err("`purge` needs --reason: every act says why".into()),
        };
        return Ok((
            config,
            Command::Purge {
                login: login.to_string(),
                fingerprint,
                since: since.unwrap_or(std::time::Duration::from_secs(3600)),
                reason,
                dry_run,
            },
        ));
    }
    let command = match words[..] {
        // A flag that belongs to a subcommand is an error on the way to
        // serving, not something to accept and ignore: an operator who
        // typed `hxd --fingerprint … inbox purge` with a typo in the
        // subcommand would otherwise get a running server.
        [] if fingerprint.is_some() || dry_run => {
            return Err("--fingerprint and --dry-run belong to `inbox purge`".to_string())
        }
        [] => Command::Serve,
        ["news-reindex"] if fingerprint.is_some() || dry_run => {
            return Err("--fingerprint and --dry-run belong to `inbox purge`".to_string())
        }
        ["news-reindex"] => Command::NewsReindex,
        ["push", "rekey"] if fingerprint.is_some() || dry_run => {
            return Err("--fingerprint and --dry-run belong to `inbox purge`".to_string())
        }
        ["push", "rekey"] => Command::PushRekey,
        ["identity", "revoke", _] if fingerprint.is_some() || dry_run => {
            return Err("--fingerprint and --dry-run belong to `inbox purge`".to_string())
        }
        ["identity", "revoke", fp] => Command::IdentityRevoke {
            fingerprint: fp.to_string(),
            what: if device {
                hxd::RevokeWhat::Device
            } else {
                hxd::RevokeWhat::Identity
            },
            lift,
        },
        ["registrar", "freeze", fp] => Command::RegistrarFreeze {
            fingerprint: fp.to_string(),
            lift,
        },
        ["registrar", "revoke", handle] => Command::RegistrarRevoke {
            handle: handle.to_string(),
            reason: reason
                .ok_or("`registrar revoke` needs --reason: abuse, lapsed or unspecified")?,
        },
        ["registrar", "recover", handle] => Command::RegistrarRecover {
            handle: handle.to_string(),
            identity: identity
                .ok_or("`registrar recover` needs --identity <the new key's fingerprint>")?,
            keep_age,
        },
        ["registrar", "invites"] => Command::RegistrarInvites {
            add: add.ok_or("`registrar invites` needs --add N")?,
        },
        ["registrar", "inspect", target] => Command::RegistrarInspect {
            target: target.to_string(),
        },
        ["history", "redact", id] => Command::HistoryRedact {
            id: id
                .parse()
                .map_err(|_| format!("{id:?} is not a chat line id"))?,
            reason: reason.ok_or("`history redact` needs --reason: every act says why")?,
        },
        ["media", "revoke", _] => Command::MediaRevoke,
        ["reports"] => Command::Reports { all },
        ["reports", "close", id] => Command::ReportsClose {
            id: id
                .parse()
                .map_err(|_| format!("{id:?} is not a report id"))?,
            outcome: outcome.ok_or("`reports close` needs --outcome dismissed|duplicate")?,
            note,
            of,
        },
        ["moderation", "log"] => Command::ModerationLog {
            limit: limit.unwrap_or(50),
        },
        ["inbox", "purge", login] => Command::InboxPurge {
            login: login.to_string(),
            fingerprint,
            dry_run,
        },
        _ => return Err(USAGE.to_string()),
    };
    Ok((config, command))
}

#[tokio::main]
async fn main() {
    init_tracing();

    let result = async {
        let (config_path, command) = parse_args()?;
        // Another registrar's business, not this server's: no config.
        if let Command::RegistrarInspect { target } = &command {
            let target = target.clone();
            let report = tokio::task::spawn_blocking(move || hxd::registrar::inspect(&target))
                .await
                .map_err(|e| e.to_string())??;
            print!("{report}");
            return Ok(());
        }
        let config = Config::load(&config_path)?;
        hxd::check_config(&config)?;
        if let Command::InboxPurge {
            login,
            fingerprint,
            dry_run,
        } = &command
        {
            let n = hxd::inbox_purge(&config, login, fingerprint.as_deref(), *dry_run)?;
            if *dry_run {
                println!("{n} rows belonging to {login} would be purged");
            } else {
                println!("purged {n} rows belonging to {login}");
            }
            return Ok(());
        }
        if let Command::IdentityRevoke {
            fingerprint,
            what,
            lift,
        } = &command
        {
            let (fp, outcome) = hxd::revoke_command(&config_path, fingerprint, *what, *lift)?;
            let kind = match what {
                hxd::RevokeWhat::Identity => "identity",
                hxd::RevokeWhat::Device => "device",
            };
            match (outcome, *lift) {
                (hxd::RevokeOutcome::Unchanged, false) => {
                    println!("{kind} {fp} is already revoked")
                }
                (hxd::RevokeOutcome::Unchanged, true) => println!("{kind} {fp} is not revoked"),
                (hxd::RevokeOutcome::Changed, false) => println!(
                    "revoked {kind} {fp} in {}\n\
                     a running server applies it on SIGHUP (`systemctl reload`), \
                     which ends every session it holds",
                    config_path.display()
                ),
                (hxd::RevokeOutcome::Changed, true) => println!(
                    "lifted the revocation of {kind} {fp} in {}\n\
                     a running server applies it on SIGHUP (`systemctl reload`)",
                    config_path.display()
                ),
            }
            return Ok(());
        }
        match &command {
            Command::RegistrarFreeze { fingerprint, lift } => {
                let seq = hxd::registrar::freeze(&config, fingerprint, *lift)?;
                println!(
                    "{} {fingerprint}: published as record {seq}",
                    if *lift {
                        "lifted the freeze of"
                    } else {
                        "froze"
                    }
                );
                return Ok(());
            }
            Command::RegistrarRevoke { handle, reason } => {
                let seq = hxd::registrar::revoke(&config, handle, reason)?;
                println!("revoked the attestations of {handle} ({reason}): record {seq}");
                return Ok(());
            }
            Command::RegistrarRecover {
                handle,
                identity,
                keep_age,
            } => {
                let seq = hxd::registrar::recover(&config, handle, identity, *keep_age)?;
                println!(
                    "{handle}'s attestations to the old key are revoked (record {seq}); its \
                     next registration from {identity} is a reissue{}",
                    if *keep_age {
                        ", keeping its age"
                    } else {
                        " with a fresh age"
                    }
                );
                return Ok(());
            }
            Command::RegistrarInvites { add } => {
                for code in hxd::registrar::invites_add(&config, *add)? {
                    println!("{code}");
                }
                return Ok(());
            }
            _ => {}
        }
        match &command {
            Command::HistoryRedact { id, reason } => {
                hxd::moderation::redact(&config, *id, reason)?;
                println!("redacted line {id}");
                return Ok(());
            }
            Command::MediaRevoke => return hxd::moderation::media_revoke(),
            Command::Purge {
                login,
                fingerprint,
                since,
                reason,
                dry_run,
            } => {
                let took = hxd::moderation::purge(
                    &config,
                    login,
                    fingerprint.as_deref(),
                    *since,
                    reason,
                    *dry_run,
                )?;
                let verb = if *dry_run { "would purge" } else { "purged" };
                println!(
                    "{verb} {} chat lines and {} articles by {login}",
                    took.lines, took.articles
                );
                return Ok(());
            }
            Command::Reports { all } => {
                println!("{}", hxd::moderation::reports(&config, *all)?);
                return Ok(());
            }
            Command::ReportsClose {
                id,
                outcome,
                note,
                of,
            } => {
                hxd::moderation::reports_close(&config, *id, outcome, note.clone(), *of)?;
                println!("closed report #{id} as {outcome}");
                return Ok(());
            }
            Command::ModerationLog { limit } => {
                println!("{}", hxd::moderation::log(&config, *limit)?);
                return Ok(());
            }
            _ => {}
        }
        if let Command::PushRekey = command {
            let (dropped, public) = hxd::push::rekey(&config)?;
            println!("new VAPID key {public}; dropped {dropped} registered devices");
            return Ok(());
        }
        if let Command::NewsReindex = command {
            let n = hxd::news_reindex(&config)?;
            println!("indexed {n} articles");
            return Ok(());
        }
        let voice = hxd::voice::build(&config)?;
        let files = hxd::files::build(&config)?;
        // The push configuration is checked here; the VAPID key is read
        // in `build_ctx`, once the device registry is open to say whether
        // a missing key is a first start — and still before anything
        // binds, because every subscription is bound to that key.
        let push = hxd::push::build(&config)?;
        // Bind HTXF before either frontend advertises Files. A configured
        // but unavailable transfer port is a startup failure, never a
        // capability promise that downloads cannot fulfill.
        let files_listener = match files.as_ref() {
            Some(files) => Some(
                TcpListener::bind(&files.bind)
                    .await
                    .map_err(|e| format!("files bind {}: {e}", files.bind))?,
            ),
            None => None,
        };
        let ctx = build_ctx(&config, voice.as_ref(), files.as_ref(), push.as_ref())?;
        // The reserved account takes its uid before any client can
        // connect: a period client needs a real uid on a private
        // message for a window to open, and needs it to still be there
        // when the user hits reply.
        if let Some(uid) = ctx.core.start_system_session() {
            let system = config.system.as_ref().expect("a session means a section");
            tracing::info!(
                uid,
                "{} is on the roster as {:?}{}",
                system.login,
                system.nick,
                if system.commands {
                    ""
                } else {
                    " (commands off)"
                }
            );
        }

        let listener = TcpListener::bind(&config.server.bind)
            .await
            .map_err(|e| format!("bind {}: {e}", config.server.bind))?;
        let legacy_addr = listener
            .local_addr()
            .map_err(|e| format!("legacy listener address: {e}"))?;
        tracing::info!(
            "hxd-ng listening on {} (server name {:?}, version {})",
            config.server.bind,
            config.server.name,
            config.server.version
        );

        // The ng context is built before voice is consumed below, so its
        // capability list can see it.
        let ng_ctx =
            hxd::build_ng_ctx(&config, &ctx, voice.as_ref(), files.as_ref(), push.as_ref())?;

        if let (Some(files), Some(listener)) = (files.as_ref(), files_listener) {
            let section = config.files.as_ref().expect("Files service has config");
            let source = section
                .root
                .as_ref()
                .map(|path| format!("local root {}", path.display()))
                .or_else(|| {
                    section
                        .origin
                        .as_ref()
                        .map(|origin| format!("HTTP origin {origin}"))
                })
                .expect("validated Files source");
            tracing::info!("Files from {} with HTXF on {}", source, files.bind);
            let service = files.service.clone();
            let core = ctx.core.clone();
            let timeouts = files.timeouts;
            tokio::spawn(async move {
                if let Err(error) =
                    hxd_files::serve_htxf(listener, service.transfers.clone(), core, timeouts).await
                {
                    tracing::error!("HTXF accept loop: {error}");
                }
            });
        }

        // Bind every configured listener before telling a tracker this
        // process is available. A bad ng bind must not leave a transient
        // listing for a server whose startup failed.
        let ng_listener = match &config.ng {
            Some(ng) => Some(
                TcpListener::bind(&ng.bind)
                    .await
                    .map_err(|e| format!("ng bind {}: {e}", ng.bind))?,
            ),
            None => None,
        };

        let tracker = match &config.tracker {
            Some(section) => {
                let advertised_port = section.advertised_port.unwrap_or(legacy_addr.port());
                tracing::info!(
                    "tracker registration to {} target(s), advertising TCP port {}",
                    section.targets.len(),
                    advertised_port
                );
                Some(hxd::tracker::start(
                    section,
                    hxd::tracker::Advertisement {
                        name: config.server.name.clone(),
                        description: section.description.clone(),
                        port: advertised_port,
                        protocol_version: config.server.version,
                        inline_media: config.media.is_some() && cfg!(feature = "media"),
                        voice: voice.is_some(),
                        large_files: files.is_some(),
                    },
                    ctx.core.clone(),
                )?)
            }
            None => None,
        };

        // Voice: the UDP media socket and the pump that drives it. Both
        // wires advertise the capability only because building this
        // succeeded, so the bit is never a promise the server can't keep.
        if let Some(voice) = voice {
            tracing::info!(
                "voice media on {} (UDP) — clients need that port reachable",
                voice.bind()
            );
            let core = ctx.core.clone();
            tokio::spawn(async move {
                if let Err(e) = voice.serve(core).await {
                    tracing::error!("voice media socket: {e}");
                }
            });
        }

        // Inbox retention, when there is an inbox. Not the ng frontend's
        // business: a legacy-only server has inboxes too.
        if let Some(inbox) = &config.inbox {
            tracing::info!(
                "private-message inbox at {} — it holds message bodies in the clear",
                inbox.db.display()
            );
            tokio::spawn(hxd::inbox_pruner(
                ctx.core.clone(),
                std::time::Duration::from_secs(inbox.retain_unread),
                std::time::Duration::from_secs(inbox.retain_read),
            ));
        }

        if let Some(history) = &config.history {
            let db = history
                .db
                .as_ref()
                .or_else(|| config.inbox.as_ref().map(|i| &i.db))
                .expect("configuration validation requires a history database");
            tracing::info!(
                "public-chat history at {} — it holds chat bodies in the clear",
                db.display()
            );
            tokio::spawn(hxd::history_pruner(
                ctx.core.clone(),
                history.max_lines,
                history.max_days,
            ));
        }

        if let Some(news) = &config.news {
            let db = news
                .db
                .as_ref()
                .or_else(|| config.inbox.as_ref().map(|i| &i.db))
                .or_else(|| config.history.as_ref().and_then(|h| h.db.as_ref()))
                .expect("configuration validation requires a news database");
            tracing::info!("threaded news at {}", db.display());
            if news.retain_days > 0 || news.attach.is_some() {
                tokio::spawn(hxd::news_pruner(ctx.core.clone()));
            }
        }

        if let Some(media) = &config.media {
            tracing::info!(
                "inline media on: up to {} KiB per image, handles live {}h, {} MiB held at most",
                media.max_bytes / 1024,
                media.handle_ttl / 3600,
                media.max_total_bytes / (1024 * 1024),
            );
            tokio::spawn(hxd::media_sweeper(ctx.core.clone()));
        }
        if ctx.core.push_enabled() {
            tokio::spawn(hxd::device_sweeper(ctx.core.clone()));
        }
        // The audit trail's evidence window and closed reports' retention.
        tokio::spawn(hxd::moderation::pruner(ctx.core.clone()));
        #[cfg(unix)]
        tokio::spawn(reload_on_hangup(
            ctx.core.clone(),
            ng_ctx.as_ref().and_then(|n| n.registrar.clone()),
            config_path.clone(),
        ));

        // The Hotline-ng WebSocket frontend, when configured: its accept
        // loop plus the detached-session sweeper.
        if let (Some(ng_ctx), Some(ng_listener)) = (ng_ctx, ng_listener) {
            let ng = config.ng.as_ref().unwrap();
            tracing::info!(
                "hotline-ng WebSocket on {} (grace {}s) — TLS is the reverse proxy's job",
                ng.bind,
                ng.grace
            );
            if let Some(id) = ng_ctx.identity.as_ref() {
                tracing::info!(
                    "identity enabled (server key {}, TRTP tunnel {})",
                    hl_identity::Fingerprint::of(&id.server_key()).short(),
                    if id.config().trtp { "on" } else { "off" }
                );
            }
            let grace = ng_ctx.cfg.grace;
            tokio::spawn(hxd_ng_session::sweeper(
                ng_ctx.core.clone(),
                ng_ctx.registry.clone(),
                grace,
                ng_ctx.enroll.clone(),
            ));
            tokio::spawn(hxd_ng_session::serve(ng_listener, ng_ctx));
        }

        let outcome = tokio::select! {
            r = hxd_session::serve(listener, ctx) => {
                r.map_err(|e| format!("accept loop: {e}"))
            }
            signal = shutdown_signal() => {
                signal?;
                tracing::info!("shutting down");
                Ok(())
            }
        };
        if let Some(tracker) = tracker {
            tracker.shutdown().await;
        }
        outcome
    }
    .await;

    if let Err(e) = result {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}
