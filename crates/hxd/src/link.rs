//! `[link]`: joining a network of linked servers under fogWraith's Server
//! Linking Extension (`docs/server-link.md` §8). Links are accepted only on
//! the TLS port, by server keys, so `[link]` needs `[tls]`.

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use serde::Deserialize;

use crate::Config;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSection {
    /// This server's tag: 1-8 printable ASCII, unique in the network.
    pub tag: String,
    /// The color this server suggests for its users elsewhere, 0xRRGGBB.
    pub color: Option<u32>,
    /// This server's key. Its own file, kept out of the accounts
    /// directory: copying the accounts to set up another server must not
    /// copy the server's identity, or the two are refused as a loop.
    #[serde(default = "default_key")]
    pub key: PathBuf,
    /// Put the home server's tag in every ghost's name, for operators
    /// whose users mostly run clients that show no colors.
    #[serde(default)]
    pub show_tags: bool,
    /// The most other servers' users shown here, across every link: well
    /// below a session's queue cap, since a netsplit is one event per user
    /// to every local session at once.
    #[serde(default = "default_max_ghosts")]
    pub max_ghosts: usize,
    /// Seconds what an interrupted link learned is kept, so a brief outage
    /// shows nobody leaving and coming back. Peers reload on SIGHUP; this
    /// takes a restart, like the rest of `[link]`.
    #[serde(default = "default_grace")]
    pub grace: u64,
    #[serde(default)]
    pub peer: Vec<PeerSection>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSection {
    pub name: String,
    /// The peer's TLS port, for a peer this server dials.
    pub dial: Option<String>,
    /// Set for a peer that dials this server.
    #[serde(default)]
    pub accept: bool,
    /// Only `"key"` so far: verified TLS and passwords come later.
    pub protection: String,
    /// The peer's public key, base64url as Hotline-ng discovery shows it.
    pub key: String,
    /// The login the peer issued this server, or the one this server
    /// expects from it. Not an account: a key-mode link is authorized by
    /// this entry, and no account is made for it.
    pub account: String,
    #[serde(default)]
    pub features: Vec<String>,
    /// The most of this peer's side of the network shown here.
    #[serde(default = "default_ghosts")]
    pub ghosts: usize,
}

fn default_key() -> PathBuf {
    "link-server.key".into()
}

fn default_max_ghosts() -> usize {
    2000
}

fn default_grace() -> u64 {
    60
}

fn default_ghosts() -> usize {
    1000
}

fn peer_key(peer: &PeerSection) -> Result<[u8; 32], String> {
    // Janus writes a key `ed25519:` and base64url, and an operator pastes
    // it as given.
    let b64 = peer.key.trim();
    let key = crate::decode_key(b64.strip_prefix("ed25519:").unwrap_or(b64))
        .map_err(|e| format!("[[link.peer]] {}: key: {e}", peer.name))?;
    hxd_link::check_public(&key)
        .map_err(|e| format!("[[link.peer]] {}: key refused: {e:?}", peer.name))?;
    Ok(key)
}

fn features(peer: &PeerSection) -> Result<u32, String> {
    use hxd_link::wire::feature;
    peer.features.iter().try_fold(0, |acc, f| {
        Ok(acc
            | match f.as_str() {
                "chat" => feature::PUBLIC_CHAT,
                "msgs" => feature::PRIVATE_MESSAGES,
                "info" => feature::USER_INFO,
                "transit" => feature::TRANSIT,
                other => {
                    return Err(format!(
                        "[[link.peer]] {}: unknown feature {other:?}",
                        peer.name
                    ))
                }
            })
    })
}

pub fn check(config: &Config) -> Result<(), String> {
    let Some(section) = config.link.as_ref() else {
        return Ok(());
    };
    if config.tls.is_none() {
        return Err(
            "[link] needs [tls]: links are accepted on the TLS port, by server keys".into(),
        );
    }
    hxd_link::server::check_tag(&section.tag).map_err(|e| format!("[link] tag: {e:?}"))?;
    // A netsplit is one event per ghost to every local session at once.
    if section.max_ghosts > hxd_core::roster::LIVE_QUEUE_CAP / 2 {
        return Err(format!(
            "[link] max_ghosts must be at most {}, half a session's queue",
            hxd_core::roster::LIVE_QUEUE_CAP / 2
        ));
    }
    let mut names = std::collections::HashSet::new();
    let mut accepted = std::collections::HashSet::new();
    for peer in &section.peer {
        if !names.insert(peer.name.as_str()) {
            return Err(format!("[[link.peer]] {}: named twice", peer.name));
        }
        // The classic wire reads a login as at most 31 characters, so a
        // longer one could never match.
        if peer.account.is_empty() || peer.account.chars().count() > 31 {
            return Err(format!(
                "[[link.peer]] {}: account must be 1-31 characters",
                peer.name
            ));
        }
        if peer.accept && !accepted.insert(peer.account.as_str()) {
            return Err(format!(
                "[[link.peer]] {}: another accepting entry expects the login {:?}",
                peer.name, peer.account
            ));
        }
        if peer.dial.is_some() == peer.accept {
            return Err(format!(
                "[[link.peer]] {}: set exactly one of dial or accept",
                peer.name
            ));
        }
        if peer.protection != "key" {
            return Err(format!(
                "[[link.peer]] {}: protection {:?} is not supported; use \"key\"",
                peer.name, peer.protection
            ));
        }
        peer_key(peer)?;
        features(peer)?;
    }
    Ok(())
}

fn entries(section: &LinkSection) -> Result<Vec<hxd_link::PeerEntry>, String> {
    section
        .peer
        .iter()
        .map(|p| {
            Ok(hxd_link::PeerEntry {
                name: p.name.clone(),
                dial: p.dial.clone(),
                key: peer_key(p)?,
                account: p.account.clone(),
                features: features(p)?,
                ghosts: p.ghosts,
            })
        })
        .collect()
}

pub fn build(config: &Config, core: Arc<hxd_core::Core>) -> Result<Option<hxd_link::Hub>, String> {
    let Some(section) = config.link.as_ref() else {
        return Ok(None);
    };
    let seed = crate::load_secret(&section.key, "link server")?;
    let peers = entries(section)?;
    let hub = hxd_link::Hub::new(
        &seed,
        hxd_link::HubConfig {
            tag: section.tag.clone(),
            name: config.server.name.clone(),
            color: section.color,
            show_tags: section.show_tags,
            max_ghosts: section.max_ghosts,
            grace: std::time::Duration::from_secs(section.grace),
            peers,
        },
        core,
    );
    // Before anything dials.
    hub.suspend(suspensions(section)?);
    tracing::info!(
        server = ?hub.server_id(),
        key = %format!("ed25519:{}", B64.encode(hub.public())),
        fingerprint = %hub.fingerprint(),
        "linking as {}",
        section.tag
    );
    Ok(Some(hub))
}

/// SIGHUP: re-read `[[link.peer]]` from the config at `path`, and the
/// suspensions. The rest of `[link]` (the tag, the color, the key) takes
/// a restart.
pub fn reload(hub: &hxd_link::Hub, path: &std::path::Path) -> Result<usize, String> {
    let config = Config::load(path)?;
    check(&config)?;
    let section = config
        .link
        .as_ref()
        .ok_or("[link] is gone; removing it takes a restart")?;
    let peers = entries(section)?;
    let suspended = suspensions(section)?;
    let n = peers.len();
    hub.reload_peers(peers);
    hub.suspend(suspended);
    Ok(n)
}

/// What the operator has set for the links (`hxd link suspend`), kept
/// beside the server key and applied on SIGHUP. A suspension outlasts a
/// restart: a link that quietly came back mid-incident is what it exists
/// to prevent.
#[derive(Debug, Default, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct LinkState {
    #[serde(default)]
    suspended: Vec<String>,
}

fn beside_key(section: &LinkSection, name: &str) -> PathBuf {
    section.key.with_file_name(name)
}

pub fn state_path(section: &LinkSection) -> PathBuf {
    beside_key(section, "link-state.toml")
}

/// Where a running server says how its links stand, for `hxd link status`.
pub fn status_path(section: &LinkSection) -> PathBuf {
    beside_key(section, "link-status.toml")
}

fn read_state(path: &std::path::Path) -> Result<LinkState, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LinkState::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Replace `path` whole, so a reader never sees half of it.
fn write_whole(path: &std::path::Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn suspensions(section: &LinkSection) -> Result<std::collections::HashSet<String>, String> {
    Ok(read_state(&state_path(section))?
        .suspended
        .into_iter()
        .collect())
}

/// A running server's report, rewritten as links change and at least
/// every `STATUS_REFRESH`, so one left by a server that died reads stale.
#[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
struct Status {
    written: u64,
    server: String,
    #[serde(default)]
    peer: Vec<PeerStatus>,
}

#[derive(Debug, Deserialize, serde::Serialize, PartialEq)]
struct PeerStatus {
    name: String,
    dials: bool,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    servers: usize,
    ghosts: usize,
}

const STATUS_EVERY: std::time::Duration = std::time::Duration::from_secs(2);
const STATUS_REFRESH: u64 = 60;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn peers_of(hub: &hxd_link::Hub) -> Vec<PeerStatus> {
    use hxd_link::PeerState;
    hub.report()
        .into_iter()
        .map(|p| {
            let (state, server) = match p.state {
                PeerState::Linked(id) => ("linked", Some(id)),
                PeerState::Linking => ("linking", None),
                PeerState::Held(id) => ("interrupted", Some(id)),
                PeerState::Suspended => ("suspended", None),
                PeerState::Down => ("down", None),
            };
            PeerStatus {
                name: p.name,
                dials: p.dials,
                state: state.into(),
                server: server.map(|id| format!("{id:?}")),
                servers: p.servers,
                ghosts: p.ghosts,
            }
        })
        .collect()
}

/// Keep the status file current while the server runs.
pub async fn write_status(hub: hxd_link::Hub, path: PathBuf) {
    let server = format!("{:?}", hub.server_id());
    let mut last: Option<(u64, Vec<PeerStatus>)> = None;
    loop {
        let peer = peers_of(&hub);
        let now = now_secs();
        let due = last
            .as_ref()
            .is_none_or(|(at, was)| *was != peer || now.saturating_sub(*at) >= STATUS_REFRESH);
        if due {
            let status = Status {
                written: now,
                server: server.clone(),
                peer,
            };
            match toml::to_string(&status).map_err(|e| e.to_string()) {
                Ok(text) => {
                    if let Err(e) = write_whole(&path, &text) {
                        tracing::warn!("link status: {e}");
                    }
                }
                Err(e) => tracing::warn!("link status: {e}"),
            }
            last = Some((now, status.peer));
        }
        tokio::time::sleep(STATUS_EVERY).await;
    }
}

/// The status a running server last wrote, or `None` when none is
/// running: no file, or one older than a server would leave it.
fn running_status(section: &LinkSection) -> Result<Option<Status>, String> {
    let path = status_path(section);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let status: Status = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((now_secs().saturating_sub(status.written) <= 3 * STATUS_REFRESH).then_some(status))
}

fn section(config: &Config) -> Result<&LinkSection, String> {
    config
        .link
        .as_ref()
        .ok_or_else(|| "there is no [link] section: this server links with nobody".into())
}

/// `hxd link status`: each configured peer, as the running server last
/// said it stands, or as configured when it is not running.
pub fn status(config: &Config) -> Result<String, String> {
    let section = section(config)?;
    let suspended = suspensions(section)?;
    let mut out = Vec::new();
    let peers = match running_status(section)? {
        Some(status) => {
            out.push(format!("server {}", status.server));
            status.peer
        }
        None => {
            out.push("not running".into());
            section
                .peer
                .iter()
                .map(|p| PeerStatus {
                    name: p.name.clone(),
                    dials: p.dial.is_some(),
                    state: match suspended.contains(&p.name) {
                        true => "suspended",
                        false => "down",
                    }
                    .into(),
                    server: None,
                    servers: 0,
                    ghosts: 0,
                })
                .collect()
        }
    };
    for p in peers {
        let mut line = format!(
            "{} ({}): {}",
            p.name,
            if p.dials { "dials" } else { "accepts" },
            p.state
        );
        if let Some(id) = p.server {
            line += &format!(" as {id}, {} servers behind, {} users", p.servers, p.ghosts);
        }
        // Written on SIGHUP, so a change not yet sent one is shown as such.
        match (suspended.contains(&p.name), p.state == "suspended") {
            (true, false) => line += " (suspended on the next SIGHUP)",
            (false, true) => line += " (resumed on the next SIGHUP)",
            _ => {}
        }
        out.push(line);
    }
    Ok(out.join("\n"))
}

/// `hxd link suspend` and `resume`: pause a configured peer's link or
/// end the pause, in the state file a running server reads on SIGHUP.
pub fn set_suspended(config: &Config, peer: &str, suspend: bool) -> Result<String, String> {
    let section = section(config)?;
    if !section.peer.iter().any(|p| p.name == peer) {
        return Err(format!("no [[link.peer]] is named {peer:?}"));
    }
    let path = state_path(section);
    let mut state = read_state(&path)?;
    let was = state.suspended.iter().any(|p| p == peer);
    if was == suspend {
        return Ok(format!(
            "{peer} is already {}",
            if suspend {
                "suspended"
            } else {
                "not suspended"
            }
        ));
    }
    state.suspended.retain(|p| p != peer);
    if suspend {
        state.suspended.push(peer.to_owned());
    }
    write_whole(&path, &toml::to_string(&state).map_err(|e| e.to_string())?)?;
    Ok(format!(
        "{peer} {}; a running server applies it on SIGHUP",
        if suspend { "suspended" } else { "resumed" }
    ))
}

/// `hxd link reset-id`: a new server key, so a new server ID. Only on a
/// stopped server: a running one would go on proving the old key, and
/// its restart is what peers take as an interruption.
pub fn reset_id(config: &Config) -> Result<String, String> {
    let section = section(config)?;
    if running_status(section)?.is_some() {
        return Err(format!(
            "the server is running; stop it first ({} is fresh)",
            status_path(section).display()
        ));
    }
    let mut old = section.key.clone().into_os_string();
    old.push(".old");
    let old = PathBuf::from(old);
    // Before the key moves, so a database that cannot be read stops it.
    let bans = crate::moderation::network_bans_standing(config)?;
    match std::fs::rename(&section.key, &old) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{}: no key yet, so no ID to reset",
                section.key.display()
            ))
        }
        Err(e) => return Err(format!("{}: {e}", section.key.display())),
    }
    let seed = crate::load_secret(&section.key, "link server")?;
    let key = hxd_link::LinkKey::from_seed(&seed);
    let mut out = vec![
        format!("server {:?}", key.server_id()),
        format!("key ed25519:{}", B64.encode(key.public())),
        format!(
            "the old key is kept at {}; putting it back restores the old ID",
            old.display()
        ),
        "every peer configures this server's key: each must change its entry \
         to the one above, or it refuses the link"
            .into(),
    ];
    if bans > 0 {
        out.push(format!(
            "{bans} bans this server asked linked servers for still stand, \
             and can no longer be lifted under the new ID"
        ));
    }
    Ok(out.join("\n"))
}
