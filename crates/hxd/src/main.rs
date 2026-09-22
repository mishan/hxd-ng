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
}

const USAGE: &str = "usage:\n  \
hxd [--config hxd-ng.toml]\n  \
hxd [--config …] inbox purge <login> [--fingerprint FP] [--dry-run]\n  \
hxd [--config …] news-reindex\n  \
hxd [--config …] push rekey\n\n\
`news-reindex` rebuilds the news search index from the articles: the\n\
repair for an index that has drifted.\n\n\
`push rekey` replaces the server's VAPID key and drops every registered\n\
push device, which the old key's subscriptions were bound to; clients\n\
re-register at their next login. Stop the server first.\n\n\
`inbox purge` takes an account's mail, news subscriptions and push\n\
devices with it when the account is deleted — otherwise the freed\n\
login's next holder inherits them.\n\
Pass --fingerprint (the value in the account's [identity] table, or\n\
its hex) when the account file is already gone. --dry-run says how\n\
much would go without taking it.";

fn parse_args() -> Result<(PathBuf, Command), String> {
    let mut config = PathBuf::from("hxd-ng.toml");
    let mut rest = Vec::new();
    let mut fingerprint = None;
    let mut dry_run = false;
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
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') => return Err(format!("unknown argument {other:?}")),
            other => rest.push(other.to_string()),
        }
    }
    let command = match rest.iter().map(String::as_str).collect::<Vec<_>>()[..] {
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
