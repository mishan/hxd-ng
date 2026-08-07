//! Server assembly: configuration file, context wiring, and the accept
//! loop. `main.rs` is a thin CLI over this; the integration tests drive
//! [`build_ctx`] + `hxd_session::serve` directly on an ephemeral port.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hxd_auth_file::FileAuth;
use hxd_core::Core;
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
        }),
    })
}
