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
        let ctx = build_ctx(&config)?;

        let listener = TcpListener::bind(&config.server.bind)
            .await
            .map_err(|e| format!("bind {}: {e}", config.server.bind))?;
        tracing::info!(
            "hxd-ng listening on {} (server name {:?}, version {})",
            config.server.bind,
            config.server.name,
            config.server.version
        );

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
