//! Server assembly: configuration file, context wiring, and the accept
//! loop. `main.rs` is a thin CLI over this; the integration tests drive
//! [`build_ctx`] + `hxd_session::serve` directly on an ephemeral port.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hxd_auth_file::FileAuth;
use hxd_core::Core;
use hxd_ng_session::{NgConfig, NgCtx, Registry};
use hxd_session::{cap, Caps, ServerConfig, ServerCtx};
use serde::Deserialize;

pub mod voice;
pub use voice::Voice;

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
    /// The spec's `VoiceMaxPerRoom`.
    #[serde(default = "default_max_per_room")]
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

/// The `DATA_CAPABILITIES` bits this build can honor for a legacy
/// session. A capability lands here only once the code behind it is
/// wired and enabled — never from a config key alone, because the echo
/// is a promise that the extension's transactions will work.
fn legacy_caps(config: &Config, voice: Option<&Voice>) -> Caps {
    let mut caps = Caps::empty();
    if voice.is_some() {
        caps = caps.with(cap::VOICE);
        // Bit 10 never without bit 2, and never from a config key alone:
        // an SFU has to be wired in for a video start to work, and the
        // echo is a promise that it will.
        if video_enabled(config) {
            caps = caps.with(cap::VIDEO);
        }
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
fn ng_caps(config: &Config, voice: Option<&Voice>) -> Vec<String> {
    let mut caps = Vec::new();
    if voice.is_some() {
        caps.push("voice".to_string());
        // As on the classic wire, `"video"` never appears without
        // `"voice"` — which this ordering makes structural rather than a
        // rule to remember.
        if video_enabled(config) {
            caps.push("video".to_string());
        }
    }
    caps
}

/// Build the ng frontend context sharing the legacy context's core and
/// auth. `None` when the config has no `[ng]` section.
pub fn build_ng_ctx(config: &Config, legacy: &ServerCtx, voice: Option<&Voice>) -> Option<NgCtx> {
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
            caps: ng_caps(config, voice),
        }),
        registry: Arc::new(Registry::new()),
    })
}

/// Assemble the shared server context from a config: bootstrap the accounts
/// directory, read the agreement file, wire the domain core and backend.
pub fn build_ctx(config: &Config, voice: Option<&Voice>) -> Result<ServerCtx, String> {
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

    Ok(ServerCtx {
        core: Arc::new(core),
        auth: Arc::new(FileAuth::new(&config.paths.accounts)),
        cfg: Arc::new(ServerConfig {
            name: config.server.name.clone(),
            version: config.server.version,
            agreement,
            login_timeout: Duration::from_secs(config.server.login_timeout),
            ban_time: Duration::from_secs(config.server.ban_time),
            caps: legacy_caps(config, voice),
        }),
    })
}
