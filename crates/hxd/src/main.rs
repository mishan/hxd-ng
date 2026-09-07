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

fn parse_args() -> Result<PathBuf, String> {
    let mut config = PathBuf::from("hxd-ng.toml");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                config = args
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--config needs a path".to_string())?;
            }
            "--help" | "-h" => {
                println!("usage: hxd [--config hxd-ng.toml]");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(config)
}

#[tokio::main]
async fn main() {
    init_tracing();

    let result = async {
        let config_path = parse_args()?;
        let config = Config::load(&config_path)?;
        hxd::check_config(&config)?;
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
