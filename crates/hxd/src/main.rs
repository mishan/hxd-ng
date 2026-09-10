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

/// What the command line asked for.
enum Command {
    Serve,
    /// `inbox purge <login> [--fingerprint FP] [--dry-run]`.
    InboxPurge {
        login: String,
        fingerprint: Option<String>,
        dry_run: bool,
    },
}

const USAGE: &str = "usage:\n  \
hxd [--config hxd-ng.toml]\n  \
hxd [--config …] inbox purge <login> [--fingerprint FP] [--dry-run]\n\n\
`inbox purge` takes an account's mail with it when the account is\n\
deleted — otherwise the freed login's next holder inherits it.\n\
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
        let voice = hxd::voice::build(&config)?;
        let ctx = build_ctx(&config, voice.as_ref())?;

        let listener = TcpListener::bind(&config.server.bind)
            .await
            .map_err(|e| format!("bind {}: {e}", config.server.bind))?;
        tracing::info!(
            "hxd-ng listening on {} (server name {:?}, version {})",
            config.server.bind,
            config.server.name,
            config.server.version
        );

        // The ng context is built before voice is consumed below, so its
        // capability list can see it.
        let ng_ctx = hxd::build_ng_ctx(&config, &ctx, voice.as_ref())?;

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
            if news.retain_days > 0 {
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

        // The Hotline-ng WebSocket frontend, when configured: its accept
        // loop plus the detached-session sweeper.
        if let Some(ng_ctx) = ng_ctx {
            let ng = config.ng.as_ref().unwrap();
            let ng_listener = TcpListener::bind(&ng.bind)
                .await
                .map_err(|e| format!("ng bind {}: {e}", ng.bind))?;
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

        tokio::select! {
            r = hxd_session::serve(listener, ctx) => {
                r.map_err(|e| format!("accept loop: {e}"))
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                Ok(())
            }
        }
    }
    .await;

    if let Err(e) = result {
        tracing::error!("{e}");
        std::process::exit(1);
    }
}
