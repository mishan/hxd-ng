//! Server assembly: configuration file, context wiring, and the accept
//! loop. `main.rs` is a thin CLI over this; the integration tests drive
//! [`build_ctx`] + `hxd_session::serve` directly on an ephemeral port.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hxd_auth_file::FileAuth;
use hxd_core::Core;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::{ServerConfig, ServerCtx};
use serde::Deserialize;

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

impl Default for ServerSection {
    fn default() -> Self {
        ServerSection {
            bind: default_bind(),
            name: default_name(),
            version: default_version(),
            login_timeout: default_login_timeout(),
            ban_time: default_ban_time(),
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

/// Build the ng frontend context sharing the legacy context's core and
/// auth. `None` when the config has no `[ng]` section.
pub fn build_ng_ctx(config: &Config, legacy: &ServerCtx) -> Option<NgCtx> {
    let ng = config.ng.as_ref()?;
    Some(NgCtx {
        core: legacy.core.clone(),
        auth: legacy.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: config.server.name.clone(),
            agreement: legacy.cfg.agreement.clone(),
            login_timeout: Duration::from_secs(config.server.login_timeout),
            grace: Duration::from_secs(ng.grace),
            max_detached_per_addr: ng.max_detached_per_addr,
        }),
        registry: Arc::new(Registry::new()),
    })
}

/// Assemble the shared server context from a config: bootstrap the accounts
/// directory, read the agreement file, wire the domain core and backend.
pub fn build_ctx(config: &Config) -> Result<ServerCtx, String> {
    FileAuth::bootstrap(&config.paths.accounts)
        .map_err(|e| format!("{}: {e}", config.paths.accounts.display()))?;

    let agreement = match &config.paths.agreement {
        Some(p) => Some(std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?),
        None => None,
    };

    Ok(ServerCtx {
        core: Arc::new(Core::new()),
        auth: Arc::new(FileAuth::new(&config.paths.accounts)),
        cfg: Arc::new(ServerConfig {
            name: config.server.name.clone(),
            version: config.server.version,
            agreement,
            login_timeout: Duration::from_secs(config.server.login_timeout),
            ban_time: Duration::from_secs(config.server.ban_time),
        }),
    })
}
