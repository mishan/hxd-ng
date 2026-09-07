//! Server assembly: configuration file, context wiring, and the accept
//! loop. `main.rs` is a thin CLI over this; the integration tests drive
//! [`build_ctx`] + `hxd_session::serve` directly on an ephemeral port.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use hl_identity::ServerKey;
use hxd_auth_file::FileAuth;
use hxd_core::{Core, LinkAuthority, Transport};
use hxd_ng_session::{
    IdentityConfig, IdentityState, NewAccounts, NgConfig, NgCtx, Registry, TrustedProxies,
    TunnelSink, TunnelStream, Unattested,
};
use hxd_session::{cap, Caps, ServerConfig, ServerCtx, TrtpLogin};
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
    /// Portable identity (`docs/hotline-ng-identity.md`). Absent =
    /// disabled: no identity endpoints, no TRTP tunnel path. Needs `[ng]`.
    pub identity: Option<IdentitySection>,
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
    /// believed (identity spec §5.3). Empty = mTLS binding off.
    /// Single addresses or CIDR blocks, e.g. `["127.0.0.1", "10.0.0.0/8"]`.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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
    /// sessions (identity spec §10). Off until proven against every 1.x
    /// client we care about.
    #[serde(default)]
    pub mark_cleartext: bool,
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
            mark_cleartext: false,
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

/// The TRTP tunnel's other end: the legacy frontend, run on the byte
/// stream the ng layer hands over (identity spec §6.3).
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

/// Load or create the server's identity key. Created with mode 0600 on
/// Unix; the file is a 32-byte seed, hex-encoded, so it can be backed up
/// with the account directory.
fn load_server_key(path: &Path) -> Result<ServerKey, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
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
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = ServerKey::generate();
            let hex: String = key.seed().iter().map(|b| format!("{b:02x}")).collect();
            write_private(path, &hex).map_err(|e| format!("{}: {e}", path.display()))?;
            tracing::info!("generated server identity key at {}", path.display());
            Ok(key)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
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

fn build_identity(
    section: &IdentitySection,
    auth: Arc<dyn hxd_core::AuthBackend>,
) -> Result<IdentityState, String> {
    use base64::Engine;
    let key = load_server_key(&section.key)?;
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
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| format!("[identity] registrar_keys.{host}: not base64url"))?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("[identity] registrar_keys.{host}: key must be 32 bytes"))?;
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
    ))
}

/// Config-level checks a `Deserialize` can't make: sections whose
/// meaning depends on another section's presence.
///
/// Run before anything is built, so the operator hears about it at
/// startup rather than wondering why identity does nothing.
pub fn check_config(config: &Config) -> Result<(), String> {
    if config.identity.is_some() && config.ng.is_none() {
        return Err(
            "[identity] needs [ng]: the identity endpoints and the TRTP tunnel are \
             served by the ng listener, so [identity] without [ng] does nothing"
                .into(),
        );
    }
    Ok(())
}

/// Build the ng frontend context sharing the legacy context's core and
/// auth. `None` when the config has no `[ng]` section.
pub fn build_ng_ctx(
    config: &Config,
    legacy: &ServerCtx,
    voice: Option<&Voice>,
) -> Result<Option<NgCtx>, String> {
    let Some(ng) = config.ng.as_ref() else {
        return Ok(None);
    };
    let identity = match config.identity.as_ref() {
        Some(section) => Some(Arc::new(build_identity(section, legacy.auth.clone())?)),
        None => None,
    };
    let tunnel: Option<Arc<dyn TunnelSink>> = identity
        .as_ref()
        .map(|_| Arc::new(LegacyTunnel(legacy.clone())) as Arc<dyn TunnelSink>);
    Ok(Some(NgCtx {
        core: legacy.core.clone(),
        auth: legacy.auth.clone(),
        cfg: Arc::new(NgConfig {
            server_name: config.server.name.clone(),
            agreement: legacy.cfg.agreement.clone(),
            login_timeout: Duration::from_secs(config.server.login_timeout),
            grace: Duration::from_secs(ng.grace),
            max_detached_per_addr: ng.max_detached_per_addr,
            caps: ng_caps(config, voice),
            trusted_proxies: TrustedProxies::parse(&ng.trusted_proxies)?,
        }),
        registry: Arc::new(Registry::new()),
        identity,
        tunnel,
    }))
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
            mark_cleartext: config.server.mark_cleartext,
            trtp_login: match config.identity.as_ref().map(|i| i.trtp_login.as_str()) {
                None | Some("verify") => TrtpLogin::Verify,
                Some("trust") => TrtpLogin::Trust,
                Some(other) => {
                    return Err(format!("[identity] trtp_login: unknown value {other:?}"))
                }
            },
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(legacy_caps(&c, None).is_empty());
        assert!(ng_caps(&c, None).is_empty());
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
            let caps = legacy_caps(&config, Some(&voice));
            assert!(caps.has(cap::VOICE));
            assert!(!caps.has(cap::VIDEO));
            assert_eq!(ng_caps(&config, Some(&voice)), vec!["voice".to_string()]);
        }

        #[test]
        fn video_is_advertised_only_alongside_voice() {
            let (config, voice) = voiced(true);
            let caps = legacy_caps(&config, Some(&voice));
            assert!(caps.has(cap::VOICE));
            assert!(caps.has(cap::VIDEO));
            assert_eq!(
                ng_caps(&config, Some(&voice)),
                vec!["voice".to_string(), "video".to_string()]
            );
        }
    }
}
