//! Hotline tracker registration (HTRK v1 and v3).
//!
//! Trackers are directory servers. A Hotline server announces itself with
//! periodic UDP datagrams; clients fetch the resulting listing over a
//! separate TCP protocol. This module is only the registering-server side.
//! Each target runs independently so one dead tracker cannot delay another,
//! and no tracker failure can take down the Hotline listener.

use std::fmt;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use hxd_core::Core;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::Sha256;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const VERSION_V1: u16 = 0x0001;
const VERSION_V3: u16 = 0x0003;
const V3_MAGIC: u16 = 0x4833;
const DEFAULT_TRACKER_PORT: u16 = 5499;
const DEFAULT_INTERVAL: u64 = 300;
const DEFAULT_ACK_TIMEOUT_MS: u64 = 2_000;
const MIN_INTERVAL: u64 = 30;
const MAX_INTERVAL: u64 = 86_400;
const MAX_DATAGRAM: usize = 65_507;
const MAX_ACK: usize = 4_096;
const MAX_TOKEN: usize = 1_024;

const TLV_DEREGISTER: u16 = 0x0010;
const TLV_ADDRESS_IPV6: u16 = 0x0100;
const TLV_HOSTNAME: u16 = 0x0101;
const TLV_SERVER_SOFTWARE: u16 = 0x0200;
const TLV_COUNTRY_CODE: u16 = 0x0201;
const TLV_REGION: u16 = 0x0202;
const TLV_LANGUAGE: u16 = 0x0203;
const TLV_MATURITY: u16 = 0x0205;
const TLV_UPTIME: u16 = 0x0206;
const TLV_RULES_URL: u16 = 0x0207;
const TLV_BANNER_URL: u16 = 0x0208;
const TLV_ICON_URL: u16 = 0x0209;
const TLV_LINK_DOWN_MBIT: u16 = 0x020a;
const TLV_LINK_UP_MBIT: u16 = 0x020b;
const TLV_TIMEZONE_OFFSET: u16 = 0x020c;
const TLV_CONTACT_URL: u16 = 0x020d;
const TLV_SERVER_LAUNCHED: u16 = 0x020e;
const TLV_PROTOCOL_VERSION: u16 = 0x0300;
const TLV_SUPPORTS_INLINE_MEDIA: u16 = 0x0304;
const TLV_SUPPORTS_VOICE: u16 = 0x0305;
const TLV_SUPPORTS_LARGE_FILES: u16 = 0x0306;
const TLV_SUPPORTS_IPV6: u16 = 0x0307;
const TLV_TAGS: u16 = 0x0310;
const TLV_PRIVATE_LISTING: u16 = 0x0500;
const TLV_LISTING_CATEGORY: u16 = 0x0501;
const TLV_LISTING_LANGUAGE_STRICT: u16 = 0x0502;
const TLV_REG_TOKEN: u16 = 0x0800;
const TLV_HMAC_SHA256: u16 = 0x0801;
const TLV_NONCE: u16 = 0x0802;
const TLV_ERROR_MSG: u16 = 0x0810;
const TLV_TRACKER_NAME: u16 = 0x0811;

type HmacSha256 = Hmac<Sha256>;

/// Optional tracker registration. No section means no network activity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerSection {
    /// Text shown under the server name in tracker listings.
    #[serde(default)]
    pub description: String,
    /// Fallback heartbeat interval. A valid v3 acknowledgment may replace it
    /// for that one target.
    #[serde(default = "default_interval")]
    pub interval: u64,
    /// Public legacy TCP port. Absent means the port actually bound by the
    /// legacy listener; set it when a NAT maps a different external port.
    pub advertised_port: Option<u16>,
    /// How long to wait for an optional v3 acknowledgment.
    #[serde(default = "default_ack_timeout_ms")]
    pub ack_timeout_ms: u64,
    #[serde(default)]
    pub v3: TrackerV3Metadata,
    #[serde(default)]
    pub targets: Vec<TrackerTarget>,
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL
}

fn default_ack_timeout_ms() -> u64 {
    DEFAULT_ACK_TIMEOUT_MS
}

/// One UDP registration endpoint. The protocol is explicit because UDP gives
/// a server no reliable way to probe a silent v1 tracker and discover v3.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerTarget {
    /// `host:port`; the protocol default is 5499 when only a host is given.
    pub address: String,
    pub protocol: TrackerProtocol,
    /// The legacy Pascal-string password. A v3 target may use it as the
    /// specification's cleartext fallback when no HMAC secret is configured.
    pub password: Option<String>,
    /// Shared secret for v3 HMAC-SHA256 registration.
    pub hmac_secret: Option<String>,
}

impl fmt::Debug for TrackerTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackerTarget")
            .field("address", &self.address)
            .field("protocol", &self.protocol)
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field(
                "hmac_secret",
                &self.hmac_secret.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrackerProtocol {
    V1,
    V3,
}

/// Operator-declared v3 fields. Live values and capabilities are supplied by
/// the running server instead of duplicated in configuration.
///
/// `MAX_USERS` and `MIN_PROTOCOL_VERSION` are deliberately absent: the spec
/// defines them as limits the server enforces at login, and hxd-ng has no
/// user cap or client-version floor to report.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerV3Metadata {
    pub ipv6: Option<Ipv6Addr>,
    pub hostname: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub language: Option<String>,
    pub maturity: Option<u8>,
    pub rules_url: Option<String>,
    pub banner_url: Option<String>,
    pub icon_url: Option<String>,
    pub link_down_mbit: Option<u32>,
    pub link_up_mbit: Option<u32>,
    pub timezone_offset_min: Option<i16>,
    pub contact_url: Option<String>,
    pub server_launched: Option<u32>,
    pub tags: Option<String>,
    #[serde(default)]
    pub private_listing: bool,
    pub listing_category: Option<u8>,
    #[serde(default)]
    pub listing_language_strict: bool,
}

impl TrackerSection {
    pub(crate) fn check(&self, server_name: &str) -> Result<(), String> {
        if self.targets.is_empty() {
            return Err("[tracker] needs at least one [[tracker.targets]] entry".into());
        }
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&self.interval) {
            return Err(format!(
                "[tracker] interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} seconds"
            ));
        }
        if !(100..=10_000).contains(&self.ack_timeout_ms) {
            return Err("[tracker] ack_timeout_ms must be between 100 and 10000".into());
        }
        if self.advertised_port == Some(0) {
            return Err("[tracker] advertised_port must not be 0".into());
        }

        let need_v1 = self
            .targets
            .iter()
            .any(|target| target.protocol == TrackerProtocol::V1);
        let need_v3 = self
            .targets
            .iter()
            .any(|target| target.protocol == TrackerProtocol::V3);
        if need_v1 {
            check_legacy_string("[server] name", server_name)?;
            check_legacy_string("[tracker] description", &self.description)?;
        }
        if need_v3 {
            check_pascal_utf8("[server] name", server_name)?;
            check_pascal_utf8("[tracker] description", &self.description)?;
        }

        for (index, target) in self.targets.iter().enumerate() {
            let where_ = format!("[[tracker.targets]] entry {}", index + 1);
            validate_address(&target.address).map_err(|error| format!("{where_}: {error}"))?;
            if target.protocol == TrackerProtocol::V1 && target.hmac_secret.is_some() {
                return Err(format!("{where_}: hmac_secret requires protocol = \"v3\""));
            }
            if target.hmac_secret.as_deref() == Some("") {
                return Err(format!("{where_}: hmac_secret must not be empty"));
            }
            if let Some(password) = &target.password {
                match target.protocol {
                    TrackerProtocol::V1 => check_legacy_credential("tracker password", password)
                        .map_err(|error| format!("{where_}: {error}"))?,
                    TrackerProtocol::V3 => check_pascal_utf8("tracker password", password)
                        .map_err(|error| format!("{where_}: {error}"))?,
                }
            }
            if target.protocol == TrackerProtocol::V3 {
                let advertisement = Advertisement {
                    name: server_name.to_owned(),
                    description: self.description.clone(),
                    port: self.advertised_port.unwrap_or(1),
                    protocol_version: 0,
                    inline_media: true,
                    voice: true,
                    large_files: true,
                };
                let base = build_v3(
                    &advertisement,
                    &self.v3,
                    1,
                    0,
                    target.password.as_deref(),
                    None,
                    None,
                    false,
                )?
                .len();
                let security = usize::from(target.hmac_secret.is_some()) * (4 + 8 + 4 + 32);
                let token = 4 + MAX_TOKEN;
                if base + security + token > MAX_DATAGRAM {
                    return Err(format!(
                        "{where_}: v3 registration metadata leaves no room for a registration token"
                    ));
                }
            }
        }
        if !need_v3 && !self.v3.is_empty() {
            return Err("[tracker.v3] needs a protocol = \"v3\" target".into());
        }
        self.v3.check()?;
        Ok(())
    }
}

impl TrackerV3Metadata {
    fn is_empty(&self) -> bool {
        self.ipv6.is_none()
            && self.hostname.is_none()
            && self.country_code.is_none()
            && self.region.is_none()
            && self.language.is_none()
            && self.maturity.is_none()
            && self.rules_url.is_none()
            && self.banner_url.is_none()
            && self.icon_url.is_none()
            && self.link_down_mbit.is_none()
            && self.link_up_mbit.is_none()
            && self.timezone_offset_min.is_none()
            && self.contact_url.is_none()
            && self.server_launched.is_none()
            && self.tags.is_none()
            && !self.private_listing
            && self.listing_category.is_none()
            && !self.listing_language_strict
    }

    fn check(&self) -> Result<(), String> {
        if let Some(value) = self.maturity {
            if value > 3 {
                return Err("[tracker.v3] maturity must be between 0 and 3".into());
            }
        }
        if let Some(value) = self.listing_category {
            if value > 12 {
                return Err("[tracker.v3] listing_category must be between 0 and 12".into());
            }
        }
        if let Some(value) = &self.country_code {
            if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
                return Err("[tracker.v3] country_code must be two uppercase ASCII letters".into());
            }
        }
        if let Some(value) = &self.language {
            if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_lowercase()) {
                return Err("[tracker.v3] language must be two lowercase ASCII letters".into());
            }
        }
        for (name, value) in [
            ("hostname", self.hostname.as_deref()),
            ("region", self.region.as_deref()),
            ("rules_url", self.rules_url.as_deref()),
            ("banner_url", self.banner_url.as_deref()),
            ("icon_url", self.icon_url.as_deref()),
            ("contact_url", self.contact_url.as_deref()),
            ("tags", self.tags.as_deref()),
        ] {
            if let Some(value) = value {
                if value.is_empty() {
                    return Err(format!("[tracker.v3] {name} must not be empty"));
                }
                if value.len() > u16::MAX as usize {
                    return Err(format!("[tracker.v3] {name} exceeds 65535 bytes"));
                }
            }
        }
        Ok(())
    }
}

fn check_legacy_string(name: &str, value: &str) -> Result<(), String> {
    if hxproto::text::from_utf8(value).len() > u8::MAX as usize {
        return Err(format!("{name} exceeds 255 Mac Roman bytes for tracker v1"));
    }
    Ok(())
}

/// A credential must survive Mac Roman conversion exactly. Display text may
/// degrade to `?` on the wire, but a password that does would never match,
/// and a v1 tracker drops a bad password without saying so.
fn check_legacy_credential(name: &str, value: &str) -> Result<(), String> {
    let mut buf = [0u8; 4];
    if let Some(ch) = value
        .chars()
        .find(|&ch| ch != '?' && hxproto::text::from_utf8(ch.encode_utf8(&mut buf)) == b"?")
    {
        return Err(format!(
            "{name} contains {ch:?}, which Mac Roman cannot represent for tracker v1"
        ));
    }
    check_legacy_string(name, value)
}

fn check_pascal_utf8(name: &str, value: &str) -> Result<(), String> {
    if value.len() > u8::MAX as usize {
        return Err(format!("{name} exceeds 255 UTF-8 bytes for tracker v3"));
    }
    Ok(())
}

fn validate_address(address: &str) -> Result<(), String> {
    if address.is_empty() || address.trim() != address {
        return Err("address must not be empty or surrounded by whitespace".into());
    }
    if let Ok(address) = address.parse::<SocketAddr>() {
        return if address.port() == 0 {
            Err("address port must not be 0".into())
        } else {
            Ok(())
        };
    }
    if address.starts_with('[') {
        return match address.strip_suffix(']') {
            Some(inner) if inner[1..].parse::<Ipv6Addr>().is_ok() => Ok(()),
            _ => Err("bracketed address must be [IPv6] or [IPv6]:port".into()),
        };
    }
    // `2001:db8::1:5499` is both a bare address and an address with a port;
    // brackets are the only unambiguous spelling.
    if address.matches(':').count() > 1 {
        return Err("an IPv6 address must be bracketed: [IPv6] or [IPv6]:port".into());
    }
    if !address.contains(':') {
        return Ok(());
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return Err("address must be host or host:port".into());
    };
    if host.is_empty() || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
        return Err("address must be host or host:port with a nonzero port".into());
    }
    Ok(())
}

fn service_address(address: &str) -> String {
    if address.parse::<SocketAddr>().is_ok() {
        address.to_owned()
    } else if address.starts_with('[') && address.ends_with(']') {
        format!("{address}:{DEFAULT_TRACKER_PORT}")
    } else if address.rsplit_once(':').is_some() {
        address.to_owned()
    } else {
        format!("{address}:{DEFAULT_TRACKER_PORT}")
    }
}

/// Values learned from the actual runtime rather than operator claims.
#[derive(Debug, Clone)]
pub struct Advertisement {
    pub name: String,
    pub description: String,
    pub port: u16,
    pub protocol_version: u16,
    pub inline_media: bool,
    pub voice: bool,
    /// 64-bit transfers, on exactly the condition both wires echo the
    /// large-file capability: a Files service was built.
    pub large_files: bool,
}

/// Running per-target registration tasks.
pub struct RegistrationService {
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl RegistrationService {
    /// Ask every v3 target to remove this process instance immediately and
    /// wait briefly for the datagrams to leave. v1 entries expire naturally.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        let tasks = std::mem::take(&mut self.tasks);
        let wait = async {
            for task in tasks {
                let _ = task.await;
            }
        };
        if tokio::time::timeout(Duration::from_secs(8), wait)
            .await
            .is_err()
        {
            tracing::warn!(target: "tracker", "tracker deregistration timed out");
        }
    }
}

impl Drop for RegistrationService {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// Start one independent heartbeat loop per configured target.
pub fn start(
    section: &TrackerSection,
    advertisement: Advertisement,
    core: Arc<Core>,
) -> Result<RegistrationService, String> {
    let mut pass_id_bytes = [0u8; 4];
    OsRng
        .try_fill_bytes(&mut pass_id_bytes)
        .map_err(|error| format!("tracker PassID randomness: {error}"))?;
    let mut pass_id = u32::from_be_bytes(pass_id_bytes);
    if pass_id == 0 {
        pass_id = 1;
    }

    let (stop, receiver) = watch::channel(false);
    let mut tasks = Vec::with_capacity(section.targets.len());
    for target in section.targets.clone() {
        if target.protocol == TrackerProtocol::V3
            && target.password.is_some()
            && target.hmac_secret.is_some()
        {
            // Legal, and a fallback for a tracker without HMAC support, but a
            // conforming v3 tracker ignores the password while it still
            // crosses the network in the clear.
            tracing::warn!(
                target: "tracker",
                tracker = %target.address,
                "v3 target has both hmac_secret and a cleartext password; \
                 the password is sent unencrypted and ignored by HMAC-capable trackers"
            );
        }
        let receiver = receiver.clone();
        let advertisement = advertisement.clone();
        let metadata = section.v3.clone();
        let core = core.clone();
        let interval = Duration::from_secs(section.interval);
        let ack_timeout = Duration::from_millis(section.ack_timeout_ms);
        tasks.push(tokio::spawn(run_target(
            target,
            advertisement,
            metadata,
            core,
            pass_id,
            interval,
            ack_timeout,
            receiver,
        )));
    }
    Ok(RegistrationService { stop, tasks })
}

#[allow(clippy::too_many_arguments)]
async fn run_target(
    target: TrackerTarget,
    advertisement: Advertisement,
    metadata: TrackerV3Metadata,
    core: Arc<Core>,
    pass_id: u32,
    configured_interval: Duration,
    ack_timeout: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let address = service_address(&target.address);
    let mut token = None;
    let mut interval = configured_interval;

    loop {
        if *stop.borrow() {
            break;
        }
        // People, not rows: the reserved server account sits on the
        // roster so a private message to it has a uid to open a window
        // on, and a tracker listing that counted it would show every
        // empty server with one user (`docs/system-account.md` §2).
        let users = core
            .snapshot()
            .iter()
            .filter(|u| !u.system)
            .count()
            .min(u16::MAX as usize) as u16;
        let heartbeat = tokio::select! {
            result = send_heartbeat(
                &address,
                &target,
                &advertisement,
                &metadata,
                pass_id,
                users,
                token.as_deref(),
                ack_timeout,
            ) => result,
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
                continue;
            }
        };
        match heartbeat {
            Ok(Some(ack)) => {
                if ack.status == AckStatus::Ok {
                    if let Some(new_token) = ack.token {
                        token = Some(new_token);
                    }
                    if (MIN_INTERVAL..=MAX_INTERVAL).contains(&u64::from(ack.interval)) {
                        interval = Duration::from_secs(u64::from(ack.interval));
                    } else if ack.interval != 0 {
                        tracing::warn!(
                            target: "tracker",
                            tracker = %target.address,
                            interval = ack.interval,
                            "ignored unsafe tracker-requested heartbeat interval"
                        );
                    }
                    tracing::debug!(
                        target: "tracker",
                        tracker = %target.address,
                        tracker_name = ack.tracker_name.as_deref().unwrap_or(""),
                        "tracker registration accepted"
                    );
                } else {
                    // A tracker restart invalidates its in-memory tokens. A
                    // tokenless retry from the original source address is the
                    // v3 recovery path, so do not wedge on a stale token.
                    token = None;
                    tracing::warn!(
                        target: "tracker",
                        tracker = %target.address,
                        status = ack.status.name(),
                        reason = ack.error.as_deref().unwrap_or(""),
                        "tracker registration refused"
                    );
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(
                target: "tracker",
                tracker = %target.address,
                "tracker registration failed: {error}"
            ),
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
        }
    }

    if target.protocol == TrackerProtocol::V3 {
        if let Err(error) = send_deregister(
            &address,
            &target,
            &advertisement,
            &metadata,
            pass_id,
            token.as_deref(),
        )
        .await
        {
            tracing::warn!(
                target: "tracker",
                tracker = %target.address,
                "tracker deregistration failed: {error}"
            );
        }
    }
}

async fn connected_socket(address: &str) -> Result<UdpSocket, String> {
    let resolved: Vec<_> = tokio::time::timeout(Duration::from_secs(5), lookup_host(address))
        .await
        .map_err(|_| "DNS resolution timed out".to_string())?
        .map_err(|error| format!("resolve: {error}"))?
        .collect();
    if resolved.is_empty() {
        return Err("resolved to no addresses".into());
    }
    let mut last_error = None;
    for address in resolved {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = match UdpSocket::bind(bind).await {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(format!("UDP bind: {error}"));
                continue;
            }
        };
        match socket.connect(address).await {
            Ok(()) => return Ok(socket),
            Err(error) => last_error = Some(format!("UDP connect: {error}")),
        }
    }
    Err(last_error.unwrap_or_else(|| "could not open a UDP socket".into()))
}

#[allow(clippy::too_many_arguments)]
async fn send_heartbeat(
    address: &str,
    target: &TrackerTarget,
    advertisement: &Advertisement,
    metadata: &TrackerV3Metadata,
    pass_id: u32,
    users: u16,
    token: Option<&[u8]>,
    ack_timeout: Duration,
) -> Result<Option<Ack>, String> {
    let packet = match target.protocol {
        TrackerProtocol::V1 => build_v1(advertisement, pass_id, users, target.password.as_deref())?,
        TrackerProtocol::V3 => build_v3(
            advertisement,
            metadata,
            pass_id,
            users,
            target.password.as_deref(),
            target.hmac_secret.as_deref(),
            token,
            false,
        )?,
    };
    let socket = connected_socket(address).await?;
    socket
        .send(&packet)
        .await
        .map_err(|error| format!("UDP send: {error}"))?;
    tracing::debug!(
        target: "tracker",
        tracker = %target.address,
        protocol = ?target.protocol,
        users,
        "sent tracker registration"
    );
    if target.protocol == TrackerProtocol::V1 {
        return Ok(None);
    }
    let mut reply = [0u8; MAX_ACK + 1];
    let length = match tokio::time::timeout(ack_timeout, socket.recv(&mut reply)).await {
        Err(_) => return Ok(None),
        Ok(Err(error)) => return Err(format!("UDP receive: {error}")),
        Ok(Ok(length)) => length,
    };
    if length > MAX_ACK {
        return Err(format!("v3 acknowledgment exceeds {MAX_ACK} bytes"));
    }
    parse_ack(&reply[..length]).map(Some)
}

async fn send_deregister(
    address: &str,
    target: &TrackerTarget,
    advertisement: &Advertisement,
    metadata: &TrackerV3Metadata,
    pass_id: u32,
    token: Option<&[u8]>,
) -> Result<(), String> {
    let packet = build_v3(
        advertisement,
        metadata,
        pass_id,
        0,
        target.password.as_deref(),
        target.hmac_secret.as_deref(),
        token,
        true,
    )?;
    let socket = connected_socket(address).await?;
    socket
        .send(&packet)
        .await
        .map_err(|error| format!("UDP send: {error}"))?;
    tracing::debug!(target: "tracker", tracker = %target.address, "sent tracker deregistration");
    Ok(())
}

fn build_v1(
    advertisement: &Advertisement,
    pass_id: u32,
    users: u16,
    password: Option<&str>,
) -> Result<Vec<u8>, String> {
    let name = hxproto::text::from_utf8(&advertisement.name);
    let description = hxproto::text::from_utf8(&advertisement.description);
    let password = password.map(hxproto::text::from_utf8).unwrap_or_default();
    build_base(
        VERSION_V1,
        advertisement.port,
        users,
        pass_id,
        &name,
        &description,
        &password,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_v3(
    advertisement: &Advertisement,
    metadata: &TrackerV3Metadata,
    pass_id: u32,
    users: u16,
    password: Option<&str>,
    hmac_secret: Option<&str>,
    token: Option<&[u8]>,
    deregister: bool,
) -> Result<Vec<u8>, String> {
    let mut packet = build_base(
        VERSION_V3,
        advertisement.port,
        users,
        pass_id,
        advertisement.name.as_bytes(),
        advertisement.description.as_bytes(),
        password.unwrap_or("").as_bytes(),
    )?;
    packet.extend_from_slice(&V3_MAGIC.to_be_bytes());
    let count_at = packet.len();
    packet.extend_from_slice(&0u16.to_be_bytes());
    let mut count = 0u16;

    if deregister {
        push_tlv(&mut packet, &mut count, TLV_DEREGISTER, &[1])?;
    } else {
        push_tlv(
            &mut packet,
            &mut count,
            TLV_SERVER_SOFTWARE,
            format!("hxd-ng/{}", env!("CARGO_PKG_VERSION")).as_bytes(),
        )?;
        push_tlv(
            &mut packet,
            &mut count,
            TLV_PROTOCOL_VERSION,
            &advertisement.protocol_version.to_be_bytes(),
        )?;
        let uptime = Instant::now()
            .duration_since(process_start())
            .as_secs()
            .min(u32::MAX as u64) as u32;
        push_tlv(&mut packet, &mut count, TLV_UPTIME, &uptime.to_be_bytes())?;
        if advertisement.inline_media {
            push_tlv(&mut packet, &mut count, TLV_SUPPORTS_INLINE_MEDIA, &[1])?;
        }
        if advertisement.voice {
            push_tlv(&mut packet, &mut count, TLV_SUPPORTS_VOICE, &[1])?;
        }
        if advertisement.large_files {
            push_tlv(&mut packet, &mut count, TLV_SUPPORTS_LARGE_FILES, &[1])?;
        }
        push_metadata(&mut packet, &mut count, metadata)?;
    }
    if let Some(token) = token {
        push_tlv(&mut packet, &mut count, TLV_REG_TOKEN, token)?;
    }

    let hmac_value_at = if let Some(secret) = hmac_secret {
        let mut nonce = [0u8; 8];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|error| format!("tracker nonce randomness: {error}"))?;
        push_tlv(&mut packet, &mut count, TLV_NONCE, &nonce)?;
        let before = packet.len();
        push_tlv(&mut packet, &mut count, TLV_HMAC_SHA256, &[0; 32])?;
        Some((before + 4, secret))
    } else {
        None
    };
    packet[count_at..count_at + 2].copy_from_slice(&count.to_be_bytes());
    if packet.len() > MAX_DATAGRAM {
        return Err(format!(
            "tracker registration is {} bytes; UDP permits at most {MAX_DATAGRAM}",
            packet.len()
        ));
    }
    if let Some((value_at, secret)) = hmac_value_at {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| "invalid tracker HMAC secret".to_string())?;
        mac.update(&packet);
        packet[value_at..value_at + 32].copy_from_slice(&mac.finalize().into_bytes());
    }
    Ok(packet)
}

fn process_start() -> Instant {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

fn build_base(
    version: u16,
    port: u16,
    users: u16,
    pass_id: u32,
    name: &[u8],
    description: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, String> {
    for (field, value) in [
        ("name", name),
        ("description", description),
        ("password", password),
    ] {
        if value.len() > u8::MAX as usize {
            return Err(format!("tracker {field} exceeds 255 bytes"));
        }
    }
    let mut packet = Vec::with_capacity(15 + name.len() + description.len() + password.len());
    packet.extend_from_slice(&version.to_be_bytes());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(&users.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&pass_id.to_be_bytes());
    push_pascal(&mut packet, name);
    push_pascal(&mut packet, description);
    push_pascal(&mut packet, password);
    Ok(packet)
}

fn push_pascal(packet: &mut Vec<u8>, value: &[u8]) {
    assert!(value.len() <= u8::MAX as usize);
    packet.push(value.len() as u8);
    packet.extend_from_slice(value);
}

fn push_tlv(packet: &mut Vec<u8>, count: &mut u16, id: u16, value: &[u8]) -> Result<(), String> {
    let length = u16::try_from(value.len())
        .map_err(|_| format!("tracker v3 field 0x{id:04x} exceeds 65535 bytes"))?;
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(value);
    *count = count
        .checked_add(1)
        .ok_or_else(|| "too many tracker v3 fields".to_string())?;
    Ok(())
}

fn push_metadata(
    packet: &mut Vec<u8>,
    count: &mut u16,
    metadata: &TrackerV3Metadata,
) -> Result<(), String> {
    macro_rules! string {
        ($field:ident, $id:expr) => {
            if let Some(value) = &metadata.$field {
                push_tlv(packet, count, $id, value.as_bytes())?;
            }
        };
    }
    macro_rules! number {
        ($field:ident, $id:expr) => {
            if let Some(value) = metadata.$field {
                push_tlv(packet, count, $id, &value.to_be_bytes())?;
            }
        };
    }
    if let Some(value) = metadata.ipv6 {
        push_tlv(packet, count, TLV_ADDRESS_IPV6, &value.octets())?;
    }
    string!(hostname, TLV_HOSTNAME);
    string!(country_code, TLV_COUNTRY_CODE);
    string!(region, TLV_REGION);
    string!(language, TLV_LANGUAGE);
    if let Some(value) = metadata.maturity {
        push_tlv(packet, count, TLV_MATURITY, &[value])?;
    }
    string!(rules_url, TLV_RULES_URL);
    string!(banner_url, TLV_BANNER_URL);
    string!(icon_url, TLV_ICON_URL);
    number!(link_down_mbit, TLV_LINK_DOWN_MBIT);
    number!(link_up_mbit, TLV_LINK_UP_MBIT);
    number!(timezone_offset_min, TLV_TIMEZONE_OFFSET);
    string!(contact_url, TLV_CONTACT_URL);
    number!(server_launched, TLV_SERVER_LAUNCHED);
    string!(tags, TLV_TAGS);
    if metadata.ipv6.is_some() {
        push_tlv(packet, count, TLV_SUPPORTS_IPV6, &[1])?;
    }
    if metadata.private_listing {
        push_tlv(packet, count, TLV_PRIVATE_LISTING, &[1])?;
    }
    if let Some(category) = metadata.listing_category.filter(|value| *value != 0) {
        push_tlv(packet, count, TLV_LISTING_CATEGORY, &[category])?;
    }
    if metadata.listing_language_strict {
        push_tlv(packet, count, TLV_LISTING_LANGUAGE_STRICT, &[1])?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckStatus {
    Ok,
    Denied,
    Banned,
    Quota,
    Full,
    Invalid,
    Error,
}

impl AckStatus {
    fn parse(value: u8) -> Result<Self, String> {
        match value {
            0x00 => Ok(Self::Ok),
            0x01 => Ok(Self::Denied),
            0x02 => Ok(Self::Banned),
            0x03 => Ok(Self::Quota),
            0x04 => Ok(Self::Full),
            0x05 => Ok(Self::Invalid),
            0xff => Ok(Self::Error),
            _ => Err(format!("unknown v3 acknowledgment status 0x{value:02x}")),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Banned => "banned",
            Self::Quota => "quota",
            Self::Full => "full",
            Self::Invalid => "invalid",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Ack {
    status: AckStatus,
    interval: u16,
    token: Option<Vec<u8>>,
    error: Option<String>,
    tracker_name: Option<String>,
}

fn parse_ack(packet: &[u8]) -> Result<Ack, String> {
    if packet.len() < 7 {
        return Err("v3 acknowledgment is shorter than 7 bytes".into());
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != V3_MAGIC {
        return Err("v3 acknowledgment has bad magic".into());
    }
    let status = AckStatus::parse(packet[2])?;
    let interval = u16::from_be_bytes([packet[3], packet[4]]);
    let count = u16::from_be_bytes([packet[5], packet[6]]);
    let mut offset = 7usize;
    let mut token = None;
    let mut error = None;
    let mut tracker_name = None;
    for _ in 0..count {
        let header = packet
            .get(offset..offset + 4)
            .ok_or_else(|| "v3 acknowledgment has a truncated TLV header".to_string())?;
        let id = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        offset += 4;
        let value = packet
            .get(offset..offset + length)
            .ok_or_else(|| format!("v3 acknowledgment field 0x{id:04x} is truncated"))?;
        offset += length;
        match id {
            TLV_REG_TOKEN if value.len() <= MAX_TOKEN => token = Some(value.to_vec()),
            TLV_REG_TOKEN => {
                return Err(format!(
                    "v3 acknowledgment registration token exceeds {MAX_TOKEN} bytes"
                ))
            }
            TLV_ERROR_MSG => {
                error = Some(
                    std::str::from_utf8(value)
                        .map_err(|_| "v3 acknowledgment error message is not UTF-8")?
                        .to_owned(),
                )
            }
            TLV_TRACKER_NAME => {
                tracker_name = Some(
                    std::str::from_utf8(value)
                        .map_err(|_| "v3 acknowledgment tracker name is not UTF-8")?
                        .to_owned(),
                )
            }
            _ => {}
        }
    }
    if offset != packet.len() {
        return Err(format!(
            "v3 acknowledgment has {} trailing bytes",
            packet.len() - offset
        ));
    }
    Ok(Ack {
        status,
        interval,
        token,
        error,
        tracker_name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn advertisement() -> Advertisement {
        Advertisement {
            name: "Café".into(),
            description: "A test".into(),
            port: 5500,
            protocol_version: 185,
            inline_media: true,
            voice: false,
            large_files: true,
        }
    }

    fn target(address: String, protocol: TrackerProtocol) -> TrackerTarget {
        TrackerTarget {
            address,
            protocol,
            password: None,
            hmac_secret: None,
        }
    }

    #[test]
    fn v1_packet_is_the_classic_big_endian_mac_roman_shape() {
        let packet = build_v1(&advertisement(), 0x1234_5678, 4, Some("é")).unwrap();
        assert_eq!(
            packet,
            [
                0x00, 0x01, 0x15, 0x7c, 0x00, 0x04, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x04, b'C',
                b'a', b'f', 0x8e, 0x06, b'A', b' ', b't', b'e', b's', b't', 0x01, 0x8e,
            ]
        );
    }

    #[test]
    fn v3_packet_carries_utf8_metadata_token_nonce_and_valid_hmac() {
        let metadata = TrackerV3Metadata {
            hostname: Some("hl.example".into()),
            country_code: Some("US".into()),
            listing_category: Some(10),
            ..TrackerV3Metadata::default()
        };
        let packet = build_v3(
            &advertisement(),
            &metadata,
            0xcafe_babe,
            12,
            None,
            Some("secret"),
            Some(b"token"),
            false,
        )
        .unwrap();
        assert_eq!(
            &packet[0..12],
            &[0, 3, 0x15, 0x7c, 0, 12, 0, 0, 0xca, 0xfe, 0xba, 0xbe]
        );
        assert!(packet
            .windows("Café".len())
            .any(|window| window == "Café".as_bytes()));
        assert!(packet
            .windows(2)
            .any(|window| window == V3_MAGIC.to_be_bytes()));
        assert!(packet
            .windows(9)
            .any(|window| window == b"\x08\x00\x00\x05token"));

        verify_hmac(&packet, b"secret");
    }

    #[test]
    fn v3_deregistration_keeps_the_token_and_is_authenticated() {
        let packet = build_v3(
            &advertisement(),
            &TrackerV3Metadata::default(),
            0xcafe_babe,
            0,
            None,
            Some("secret"),
            Some(b"token"),
            true,
        )
        .unwrap();
        assert!(packet
            .windows(5)
            .any(|window| window == b"\x00\x10\x00\x01\x01"));
        assert!(packet
            .windows(9)
            .any(|window| window == b"\x08\x00\x00\x05token"));
        verify_hmac(&packet, b"secret");
    }

    #[test]
    fn v3_operator_metadata_uses_the_spec_ids_and_integer_widths() {
        let ipv6: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let metadata = TrackerV3Metadata {
            ipv6: Some(ipv6),
            hostname: Some("hl.example".into()),
            country_code: Some("US".into()),
            region: Some("California".into()),
            language: Some("en".into()),
            maturity: Some(2),
            rules_url: Some("https://hl.example/rules".into()),
            banner_url: Some("https://hl.example/banner.png".into()),
            icon_url: Some("https://hl.example/icon.png".into()),
            link_down_mbit: Some(1_000),
            link_up_mbit: Some(100),
            timezone_offset_min: Some(-420),
            contact_url: Some("mailto:admin@hl.example".into()),
            server_launched: Some(1_700_000_000),
            tags: Some("chat,retro".into()),
            private_listing: true,
            listing_category: Some(10),
            listing_language_strict: true,
        };
        let packet = build_v3(&advertisement(), &metadata, 1, 2, None, None, None, false).unwrap();
        let fields: BTreeMap<_, _> = packet_tlvs(&packet)
            .into_iter()
            .map(|(id, value)| (id, value.to_vec()))
            .collect();
        assert_eq!(
            fields[&TLV_SERVER_SOFTWARE],
            format!("hxd-ng/{}", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        assert_eq!(fields[&TLV_PROTOCOL_VERSION], 185u16.to_be_bytes());
        assert_eq!(fields[&TLV_UPTIME].len(), 4);
        assert_eq!(fields[&TLV_SUPPORTS_INLINE_MEDIA], [1]);
        assert!(!fields.contains_key(&TLV_SUPPORTS_VOICE));
        assert_eq!(fields[&TLV_SUPPORTS_LARGE_FILES], [1]);
        assert_eq!(fields[&TLV_ADDRESS_IPV6], ipv6.octets());
        assert_eq!(fields[&TLV_HOSTNAME], b"hl.example");
        assert_eq!(fields[&TLV_COUNTRY_CODE], b"US");
        assert_eq!(fields[&TLV_REGION], b"California");
        assert_eq!(fields[&TLV_LANGUAGE], b"en");
        assert_eq!(fields[&TLV_MATURITY], [2]);
        assert_eq!(fields[&TLV_RULES_URL], b"https://hl.example/rules");
        assert_eq!(fields[&TLV_BANNER_URL], b"https://hl.example/banner.png");
        assert_eq!(fields[&TLV_ICON_URL], b"https://hl.example/icon.png");
        assert_eq!(fields[&TLV_LINK_DOWN_MBIT], 1_000u32.to_be_bytes());
        assert_eq!(fields[&TLV_LINK_UP_MBIT], 100u32.to_be_bytes());
        assert_eq!(fields[&TLV_TIMEZONE_OFFSET], (-420i16).to_be_bytes());
        assert_eq!(fields[&TLV_CONTACT_URL], b"mailto:admin@hl.example");
        assert_eq!(fields[&TLV_SERVER_LAUNCHED], 1_700_000_000u32.to_be_bytes());
        assert_eq!(fields[&TLV_TAGS], b"chat,retro");
        assert_eq!(fields[&TLV_SUPPORTS_IPV6], [1]);
        assert_eq!(fields[&TLV_PRIVATE_LISTING], [1]);
        assert_eq!(fields[&TLV_LISTING_CATEGORY], [10]);
        assert_eq!(fields[&TLV_LISTING_LANGUAGE_STRICT], [1]);
    }

    fn verify_hmac(packet: &[u8], secret: &[u8]) {
        let (hmac_at, nonce) = find_security_fields(packet);
        assert_eq!(nonce.len(), 8);
        let transmitted = packet[hmac_at..hmac_at + 32].to_vec();
        let mut unsigned = packet.to_vec();
        unsigned[hmac_at..hmac_at + 32].fill(0);
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&unsigned);
        assert_eq!(
            transmitted.as_slice(),
            mac.finalize().into_bytes().as_slice()
        );
    }

    fn find_security_fields(packet: &[u8]) -> (usize, &[u8]) {
        let fields = packet_tlvs_with_offsets(packet);
        let hmac = fields
            .iter()
            .find(|(id, _, _)| *id == TLV_HMAC_SHA256)
            .unwrap();
        let nonce = fields.iter().find(|(id, _, _)| *id == TLV_NONCE).unwrap();
        (hmac.1, nonce.2)
    }

    fn packet_tlvs(packet: &[u8]) -> Vec<(u16, &[u8])> {
        packet_tlvs_with_offsets(packet)
            .into_iter()
            .map(|(id, _, value)| (id, value))
            .collect()
    }

    fn packet_tlvs_with_offsets(packet: &[u8]) -> Vec<(u16, usize, &[u8])> {
        let mut offset = 12;
        for _ in 0..3 {
            let length = usize::from(packet[offset]);
            offset += 1 + length;
        }
        assert_eq!(
            u16::from_be_bytes([packet[offset], packet[offset + 1]]),
            V3_MAGIC
        );
        let count = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        offset += 4;
        let mut fields = Vec::new();
        for _ in 0..count {
            let id = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let length = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
            offset += 4;
            fields.push((id, offset, &packet[offset..offset + length]));
            offset += length;
        }
        assert_eq!(offset, packet.len());
        fields
    }

    #[test]
    fn acknowledgment_parser_is_bounded_and_forward_compatible() {
        let mut packet = vec![0x48, 0x33, 0x00, 0x01, 0x2c, 0x00, 0x03];
        append_tlv(&mut packet, TLV_REG_TOKEN, b"token");
        append_tlv(&mut packet, TLV_TRACKER_NAME, b"Argus");
        append_tlv(&mut packet, 0xf123, b"future");
        assert_eq!(
            parse_ack(&packet).unwrap(),
            Ack {
                status: AckStatus::Ok,
                interval: 300,
                token: Some(b"token".to_vec()),
                error: None,
                tracker_name: Some("Argus".into()),
            }
        );
        assert!(parse_ack(&packet[..packet.len() - 1]).is_err());
        let mut trailing = packet;
        trailing.push(0);
        assert!(parse_ack(&trailing).is_err());
    }

    fn append_tlv(packet: &mut Vec<u8>, id: u16, value: &[u8]) {
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
        packet.extend_from_slice(value);
    }

    #[tokio::test]
    async fn loops_send_both_protocols_and_v3_deregisters() {
        let v1_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let v3_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let section = TrackerSection {
            description: "A test".into(),
            interval: 30,
            advertised_port: None,
            ack_timeout_ms: 100,
            v3: TrackerV3Metadata::default(),
            targets: vec![
                target(
                    v1_receiver.local_addr().unwrap().to_string(),
                    TrackerProtocol::V1,
                ),
                target(
                    v3_receiver.local_addr().unwrap().to_string(),
                    TrackerProtocol::V3,
                ),
            ],
        };
        let core = Arc::new(Core::new());
        let (uid, _events) = core
            .attach(hxd_core::AttachInfo {
                nick: "Visible".into(),
                icon: 1,
                admin: false,
                access: hxd_core::AccessBits::empty(),
                login: "visible".into(),
                addr: None,
                can_detach: false,
                transport: hxd_core::Transport::default(),
                has_inbox: false,
                attach_news: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        let service = start(&section, advertisement(), core).unwrap();
        let mut buf = [0u8; 1024];
        let v1_len = tokio::time::timeout(Duration::from_secs(1), v1_receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..2], &VERSION_V1.to_be_bytes());
        assert_eq!(&buf[4..6], &1u16.to_be_bytes());
        assert!(v1_len >= 15);
        let v3_len = tokio::time::timeout(Duration::from_secs(1), v3_receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..2], &VERSION_V3.to_be_bytes());
        assert_eq!(&buf[4..6], &1u16.to_be_bytes());
        assert!(v3_len >= 19);

        service.shutdown().await;
        let dereg_len = tokio::time::timeout(Duration::from_secs(1), v3_receiver.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..2], &VERSION_V3.to_be_bytes());
        assert!(buf[..dereg_len]
            .windows(5)
            .any(|window| window == [0x00, 0x10, 0x00, 0x01, 0x01]));
    }

    #[test]
    fn configuration_rejects_protocol_confusion_and_bad_vocabularies() {
        let mut section = TrackerSection {
            description: String::new(),
            interval: 300,
            advertised_port: None,
            ack_timeout_ms: 2_000,
            v3: TrackerV3Metadata::default(),
            targets: vec![target("tracker.example".into(), TrackerProtocol::V1)],
        };
        section.targets[0].hmac_secret = Some("secret".into());
        assert!(section
            .check("server")
            .unwrap_err()
            .contains("requires protocol"));
        section.targets[0].protocol = TrackerProtocol::V3;
        section.v3.maturity = Some(4);
        assert!(section.check("server").unwrap_err().contains("maturity"));
        section.v3.maturity = None;
        section.v3.listing_category = Some(13);
        assert!(section
            .check("server")
            .unwrap_err()
            .contains("listing_category"));
    }

    #[test]
    fn a_v1_password_must_survive_mac_roman_exactly() {
        let mut section = TrackerSection {
            description: String::new(),
            interval: 300,
            advertised_port: None,
            ack_timeout_ms: 2_000,
            v3: TrackerV3Metadata::default(),
            targets: vec![target("tracker.example".into(), TrackerProtocol::V1)],
        };
        for accepted in ["plain", "café", "what?"] {
            section.targets[0].password = Some(accepted.into());
            section.check("server").unwrap();
        }
        section.targets[0].password = Some("пароль".into());
        assert!(section.check("server").unwrap_err().contains("Mac Roman"));
        // v3 carries the password as UTF-8, so the same text is fine there.
        section.targets[0].protocol = TrackerProtocol::V3;
        section.check("server").unwrap();
    }

    #[test]
    fn addresses_default_the_port_and_require_bracketed_ipv6() {
        for (address, service) in [
            ("tracker.example", "tracker.example:5499"),
            ("tracker.example:6000", "tracker.example:6000"),
            ("192.0.2.1", "192.0.2.1:5499"),
            ("192.0.2.1:6000", "192.0.2.1:6000"),
            ("[2001:db8::1]", "[2001:db8::1]:5499"),
            ("[2001:db8::1]:6000", "[2001:db8::1]:6000"),
        ] {
            validate_address(address).unwrap();
            assert_eq!(service_address(address), service);
        }
        for rejected in [
            "2001:db8::1",
            "2001:db8::1:5499",
            "[2001:db8::1",
            "[tracker.example]",
            "[2001:db8::1]:0",
            "tracker.example:0",
            ":5499",
        ] {
            assert!(validate_address(rejected).is_err(), "{rejected}");
        }
    }
}
