//! The hub: what every link shares (`docs/server-link.md` §7.4). The
//! server table that loop and tag checks consult, which link is live for
//! each peer, and this server's key and identity.
//!
//! It is a lock rather than a task of its own: nothing holds it across an
//! await, and every link consults it in passing.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use hxd_session::peer::{LinkGrant, LinkIo, LinkLogin, PeerAcceptor};
use hxd_session::{cap, Caps};
use tokio::sync::oneshot;

use crate::key::{check_public, verify_proof, LinkKey, Role};
use crate::server::{same_tag, ServerGroup, ServerId};
use crate::wire::{field, Hello, Reason, VERSION};

/// Links between this server and the farthest one it will accept.
pub const MAX_HOPS: u16 = 8;

/// The link features this build implements. Each side offers what its
/// operator enabled for a peer, and only this much of it.
pub const SUPPORTED: u32 = 0;

/// One peer this server links with, from `[[link.peer]]`.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub name: String,
    /// The peer's address, for a peer this server dials; `None` for one
    /// that dials it.
    pub dial: Option<String>,
    /// The peer's public key, already checked by [`check_public`].
    pub key: [u8; 32],
    /// The login a dialer logs in as: the one the peer issued this server,
    /// or the one this server expects from it.
    pub account: String,
    pub features: u32,
}

#[derive(Debug, Clone)]
pub struct HubConfig {
    pub tag: String,
    pub name: String,
    pub color: Option<u32>,
    pub peers: Vec<PeerEntry>,
}

/// A live link, as `hxd link status` would show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStatus {
    pub peer: String,
    pub server: ServerId,
    pub servers: usize,
}

#[derive(Clone)]
pub struct Hub(Arc<Inner>);

struct Inner {
    key: LinkKey,
    epoch: [u8; 8],
    config: Mutex<HubConfig>,
    budget: Arc<hxd_core::QueueBudget>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    links: HashMap<String, Live>,
    generation: u64,
    /// Peers with a dial loop running, so a reload never starts a second.
    dialing: std::collections::HashSet<String>,
}

struct Live {
    generation: u64,
    close: Option<oneshot::Sender<Reason>>,
    /// The peer itself, once its Hello was accepted.
    peer: Option<ServerGroup>,
    /// Servers learned over this link, the peer excluded.
    servers: HashMap<ServerId, ServerGroup>,
}

/// A link login the hub confirmed.
struct Granted {
    entry: PeerEntry,
}

impl Hub {
    pub fn new(seed: &[u8; 32], config: HubConfig, budget: Arc<hxd_core::QueueBudget>) -> Hub {
        let mut epoch = [0u8; 8];
        getrandom::getrandom(&mut epoch).expect("the OS CSPRNG");
        Hub(Arc::new(Inner {
            key: LinkKey::from_seed(seed),
            epoch,
            config: Mutex::new(config),
            budget,
            state: Mutex::default(),
        }))
    }

    pub fn server_id(&self) -> ServerId {
        self.0.key.server_id()
    }

    pub fn public(&self) -> [u8; 32] {
        self.0.key.public()
    }

    pub fn fingerprint(&self) -> hl_identity::Fingerprint {
        self.0.key.fingerprint()
    }

    pub(crate) fn key(&self) -> &LinkKey {
        &self.0.key
    }

    pub(crate) fn budget(&self) -> &Arc<hxd_core::QueueBudget> {
        &self.0.budget
    }

    /// Dial every peer this server dials, each on a task of its own that
    /// reconnects for as long as its entry stays configured.
    pub fn spawn_dialers(&self) {
        let entries: Vec<PeerEntry> = self.0.config.lock().unwrap().peers.clone();
        for entry in entries.into_iter().filter(|e| e.dial.is_some()) {
            self.spawn_dialer(entry.name);
        }
    }

    pub(crate) fn spawn_dialer(&self, peer: String) {
        if self.0.state.lock().unwrap().dialing.insert(peer.clone()) {
            tokio::spawn(crate::dial::dial_loop(self.clone(), peer));
        }
    }

    pub(crate) fn dialer_stopped(&self, peer: &str) {
        self.0.state.lock().unwrap().dialing.remove(peer);
    }

    /// Whether `entry` is still the one configured for its peer: a link
    /// authorized under an entry a reload has since removed or changed
    /// must not come up.
    pub(crate) fn authorizes(&self, entry: &PeerEntry) -> bool {
        self.entry(&entry.name)
            .is_some_and(|now| same_terms(&now, entry))
    }

    pub(crate) fn servers_behind(&self, peer: &str, generation: u64) -> usize {
        let state = self.0.state.lock().unwrap();
        state
            .links
            .get(peer)
            .filter(|l| l.generation == generation)
            .map_or(0, |l| l.servers.len())
    }

    pub(crate) fn knows_behind(&self, peer: &str, generation: u64, id: ServerId) -> bool {
        let state = self.0.state.lock().unwrap();
        state
            .links
            .get(peer)
            .filter(|l| l.generation == generation)
            .is_some_and(|l| l.servers.contains_key(&id))
    }

    /// The entry configured for `peer` now.
    pub(crate) fn entry(&self, peer: &str) -> Option<PeerEntry> {
        let config = self.0.config.lock().unwrap();
        config.peers.iter().find(|p| p.name == peer).cloned()
    }

    /// New `[[link.peer]]` entries, as SIGHUP re-reads them. Authorization
    /// is continuous: a link whose entry went is closed with `Unlinked`,
    /// one whose key changed with `ProtocolError`, which its dialer
    /// retries, so a key rotation staged on both sides completes on its
    /// own. A new dialing entry starts dialing; a removed one stops at its
    /// next attempt.
    pub fn reload_peers(&self, peers: Vec<PeerEntry>) {
        let old = std::mem::replace(&mut self.0.config.lock().unwrap().peers, peers.clone());
        let mut state = self.0.state.lock().unwrap();
        for (name, live) in &mut state.links {
            let reason = match (
                old.iter().find(|p| &p.name == name),
                peers.iter().find(|p| &p.name == name),
            ) {
                (_, None) => Reason::Unlinked,
                (Some(was), Some(now)) if !same_terms(was, now) => Reason::ProtocolError,
                _ => continue,
            };
            if let Some(close) = live.close.take() {
                let _ = close.send(reason);
            }
        }
        drop(state);
        // Only an entry that is new or changed: a dialer that stopped on
        // Unlinked, Replaced or VersionUnsupported waits for its operator
        // to act on it, and a SIGHUP sent for something else (a renewed
        // certificate) is not that.
        for entry in peers.into_iter().filter(|e| e.dial.is_some()) {
            if old
                .iter()
                .find(|p| p.name == entry.name)
                .is_none_or(|was| !same_terms(was, &entry))
            {
                self.spawn_dialer(entry.name);
            }
        }
    }

    /// Links whose peer has been accepted.
    pub fn status(&self) -> Vec<LinkStatus> {
        let state = self.0.state.lock().unwrap();
        let mut out: Vec<LinkStatus> = state
            .links
            .iter()
            .filter_map(|(name, live)| {
                Some(LinkStatus {
                    peer: name.clone(),
                    server: live.peer.as_ref()?.id,
                    servers: live.servers.len(),
                })
            })
            .collect();
        out.sort_by(|a, b| a.peer.cmp(&b.peer));
        out
    }

    pub(crate) fn hello(&self, features: u32) -> Hello {
        let config = self.0.config.lock().unwrap();
        Hello {
            version: VERSION,
            features,
            epoch: self.0.epoch,
            server: ServerGroup {
                id: self.server_id(),
                tag: config.tag.clone(),
                name: config.name.clone(),
                hops: 0,
                color: config.color,
                extra: vec![],
            },
        }
    }

    /// A link for `peer` is starting. Newest wins: a link already live for
    /// it is closed with `Replaced`, which is what lets a peer redial over
    /// a connection it has given up on.
    pub(crate) fn register(&self, peer: &str) -> (u64, oneshot::Receiver<Reason>) {
        let (tx, rx) = oneshot::channel();
        let mut state = self.0.state.lock().unwrap();
        state.generation += 1;
        let generation = state.generation;
        let old = state.links.insert(
            peer.to_owned(),
            Live {
                generation,
                close: Some(tx),
                peer: None,
                servers: HashMap::new(),
            },
        );
        if let Some(close) = old.and_then(|mut old| old.close.take()) {
            let _ = close.send(Reason::Replaced);
        }
        (generation, rx)
    }

    pub(crate) fn unregister(&self, peer: &str, generation: u64) {
        let mut state = self.0.state.lock().unwrap();
        if state
            .links
            .get(peer)
            .is_some_and(|l| l.generation == generation)
        {
            state.links.remove(peer);
        }
    }

    /// Accept a server group arriving over `peer`'s link (the extension's
    /// Loop Prevention and Tag checks), and record it. `own` is the peer's
    /// group from its Hello.
    pub(crate) fn accept_server(
        &self,
        peer: &str,
        generation: u64,
        group: ServerGroup,
        own: bool,
    ) -> Result<(), Reason> {
        let own_tag = self.0.config.lock().unwrap().tag.clone();
        let mut state = self.0.state.lock().unwrap();
        // A replaced link is told so before anything about the group.
        if !state
            .links
            .get(peer)
            .is_some_and(|l| l.generation == generation)
        {
            return Err(Reason::Replaced);
        }
        if group.id == self.server_id() {
            return Err(Reason::Loop);
        }
        // An update about the peer itself (a new tag or name) replaces
        // what its Hello said rather than adding a second server.
        let own = own
            || state.links[peer]
                .peer
                .as_ref()
                .is_some_and(|p| p.id == group.id);
        if !own && group.hops.saturating_add(1) > MAX_HOPS {
            return Err(Reason::HopLimit);
        }
        if same_tag(&group.tag, &own_tag) {
            return Err(Reason::TagConflict);
        }
        for (name, live) in &state.links {
            let this = name == peer && live.generation == generation;
            for known in live.peer.iter().chain(live.servers.values()) {
                if known.id == group.id && !this {
                    return Err(Reason::Loop);
                }
                if known.id != group.id && same_tag(&known.tag, &group.tag) {
                    return Err(Reason::TagConflict);
                }
            }
        }
        let live = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
            .ok_or(Reason::Replaced)?;
        if own {
            live.peer = Some(group);
        } else {
            live.servers.insert(group.id, group);
        }
        Ok(())
    }

    pub(crate) fn forget_server(&self, peer: &str, generation: u64, id: ServerId) {
        let mut state = self.0.state.lock().unwrap();
        if let Some(live) = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
        {
            live.servers.remove(&id);
        }
    }
}

/// Whether two entries for a peer authorize the same link: the same key,
/// the same login, and the same address to dial.
fn same_terms(a: &PeerEntry, b: &PeerEntry) -> bool {
    a.key == b.key && a.account == b.account && a.dial == b.dial
}

impl PeerAcceptor for Hub {
    fn authorize(&self, login: LinkLogin) -> Result<LinkGrant, &'static str> {
        const REFUSED: &str = "Login failed.";
        // Before the entry is looked up, so the answer says nothing about
        // which logins are links.
        let exporter = login
            .exporter
            .ok_or("Server links by key need TLS 1.3 on the TLS port.")?;
        if !login.text_encoding {
            return Err(REFUSED);
        }
        let entry = self
            .0
            .config
            .lock()
            .unwrap()
            .peers
            .iter()
            .find(|p| p.dial.is_none() && p.account == login.login)
            .cloned()
            .ok_or(REFUSED)?;
        let (Some(key), Some(proof)) = (login.server_key, login.proof) else {
            return Err(REFUSED);
        };
        let configured = check_public(&entry.key).map_err(|_| REFUSED)?;
        if key != entry.key
            || !verify_proof(
                &configured,
                Role::Dialer,
                &exporter,
                &self.0.key.public(),
                &proof,
            )
        {
            return Err(REFUSED);
        }
        let caps = Caps::empty()
            .with(cap::TEXT_ENCODING)
            .with(cap::SERVER_LINK);
        let reply = vec![
            (hxproto::messages::tag::CAPABILITIES, caps.to_wire()),
            (field::SERVER_KEY, self.0.key.public().to_vec()),
            (
                field::KEY_PROOF,
                self.0
                    .key
                    .prove(Role::Acceptor, &exporter, &entry.key)
                    .to_vec(),
            ),
        ];
        Ok(LinkGrant {
            reply,
            state: Box::new(Granted { entry }),
        })
    }

    fn accept(
        &self,
        grant: LinkGrant,
        io: LinkIo,
    ) -> Pin<Box<dyn Future<Output = &'static str> + Send + 'static>> {
        let hub = self.clone();
        let entry = match grant.state.downcast::<Granted>() {
            Ok(g) => g.entry,
            Err(_) => return Box::pin(async { "protocol_error" }),
        };
        Box::pin(async move { crate::link::run(hub, entry, io).await.label })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> Hub {
        Hub::new(
            &[1; 32],
            HubConfig {
                tag: "hx".into(),
                name: "here".into(),
                color: None,
                peers: vec![],
            },
            hxd_core::QueueBudget::new(1 << 20),
        )
    }

    fn group(id: u8, tag: &str, hops: u16) -> ServerGroup {
        ServerGroup {
            id: ServerId([id; 8]),
            tag: tag.into(),
            name: tag.into(),
            hops,
            color: None,
            extra: vec![],
        }
    }

    #[test]
    fn servers_that_would_close_a_loop_clash_or_lie_too_far_are_refused() {
        let h = hub();
        let (a, _ra) = h.register("a");
        let (b, _rb) = h.register("b");
        h.accept_server("a", a, group(2, "two", 0), true).unwrap();
        h.accept_server("a", a, group(3, "three", 1), false)
            .unwrap();
        for (link, generation, g, own, want) in [
            // This server itself, reached around a loop.
            (
                "b",
                b,
                group(0, "me", 0).with_id(h.server_id()),
                true,
                Reason::Loop,
            ),
            // A server already reached over the other link.
            ("b", b, group(3, "three", 1), false, Reason::Loop),
            // Tags are unique and compared case-insensitively.
            ("b", b, group(4, "HX", 1), false, Reason::TagConflict),
            ("b", b, group(4, "Two", 1), false, Reason::TagConflict),
            ("b", b, group(4, "far", MAX_HOPS), false, Reason::HopLimit),
        ] {
            assert_eq!(h.accept_server(link, generation, g, own), Err(want));
        }
        // An update to a server already known over the same link is fine.
        assert_eq!(h.accept_server("a", a, group(3, "three", 2), false), Ok(()));
    }

    #[test]
    fn a_new_link_for_a_peer_replaces_the_old_one() {
        let h = hub();
        let (first, mut closed) = h.register("a");
        let (second, _) = h.register("a");
        assert_eq!(closed.try_recv(), Ok(Reason::Replaced));
        // The replaced link ending leaves the new one alone.
        h.unregister("a", first);
        assert_eq!(
            h.accept_server("a", second, group(2, "two", 0), true),
            Ok(())
        );
    }

    #[test]
    fn an_update_about_the_peer_replaces_what_its_hello_said() {
        let h = hub();
        let (a, _ra) = h.register("a");
        h.accept_server("a", a, group(2, "two", 0), true).unwrap();
        h.accept_server("a", a, group(2, "renamed", 0), false)
            .unwrap();
        let status = h.status();
        assert_eq!(status[0].servers, 0);
        // Its old tag is free again for another server behind it.
        assert_eq!(h.accept_server("a", a, group(3, "two", 1), false), Ok(()));
    }

    impl ServerGroup {
        fn with_id(mut self, id: ServerId) -> ServerGroup {
            self.id = id;
            self
        }
    }
}
