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
}

fn default_key() -> PathBuf {
    "link-server.key".into()
}

fn peer_key(peer: &PeerSection) -> Result<[u8; 32], String> {
    let key = crate::decode_key(&peer.key)
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
            })
        })
        .collect()
}

pub fn build(
    config: &Config,
    budget: Arc<hxd_core::QueueBudget>,
) -> Result<Option<hxd_link::Hub>, String> {
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
            peers,
        },
        budget,
    );
    tracing::info!(
        server = ?hub.server_id(),
        key = %B64.encode(hub.public()),
        fingerprint = %hub.fingerprint(),
        "linking as {}",
        section.tag
    );
    Ok(Some(hub))
}

/// SIGHUP: re-read `[[link.peer]]` from the config at `path`. The rest of
/// `[link]` (the tag, the color, the key) takes a restart.
pub fn reload(hub: &hxd_link::Hub, path: &std::path::Path) -> Result<usize, String> {
    let config = Config::load(path)?;
    check(&config)?;
    let section = config
        .link
        .as_ref()
        .ok_or("[link] is gone; removing it takes a restart")?;
    let peers = entries(section)?;
    let n = peers.len();
    hub.reload_peers(peers);
    Ok(n)
}
