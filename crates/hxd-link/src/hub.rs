//! The hub: what every link shares (`docs/server-link.md` §7.4). The
//! server table that loop and tag checks consult, which link is live for
//! each peer, each link's ghosts, and this server's key and identity.
//!
//! Its state is a lock that nothing holds across an await, and that is
//! taken before the roster's whenever both are, never after. One task
//! takes the core's export feed and hands each event to every link.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use hxd_core::instrument;
use hxd_core::roster::Uid;
use hxd_core::server_link::{
    GhostBan, GhostInfo, GhostLine, LocalUser, NetworkBan, PeerEvent, PeerRefusal, PeerRouter,
    RemoteRef, Requester, PEER_WAIT,
};
use hxd_core::Core;
use hxd_session::peer::{LinkGrant, LinkIo, LinkLogin, PeerAcceptor};
use hxd_session::{cap, Caps};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::key::{check_public, verify_proof, LinkKey, Role};
use crate::server::{same_tag, ServerGroup, ServerId};
use crate::users::{flag, UserGroup};
use crate::wire::{feature, field, find, tx, Field, Hello, Reason, VERSION};

/// Events the core may hold for the hub before the feed counts as fallen
/// behind, and events one link may hold before it does.
const FEED_CAP: usize = 16384;
const EXPORT_CAP: usize = 4096;

/// An export event, numbered in the roster's order.
pub(crate) type Export = (u64, PeerEvent);

/// Links between this server and the farthest one it will accept.
pub const MAX_HOPS: u16 = 8;

/// The link features this build implements. Each side offers what its
/// operator enabled for a peer, and only this much of it.
pub const SUPPORTED: u32 =
    feature::PUBLIC_CHAT | feature::PRIVATE_MESSAGES | feature::USER_INFO | feature::TRANSIT;

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
    /// The most ghosts this link may show here, counting every user
    /// behind it.
    pub ghosts: usize,
}

#[derive(Debug, Clone)]
pub struct HubConfig {
    pub tag: String,
    pub name: String,
    pub color: Option<u32>,
    /// Put the home server's tag in every ghost's name.
    pub show_tags: bool,
    /// The most ghosts shown here across every link, well below a
    /// session's queue cap: a netsplit is one event per ghost to every
    /// local session at once.
    pub max_ghosts: usize,
    /// How long what a link learned is kept once it is interrupted, so a
    /// brief outage shows nobody leaving and coming back.
    pub grace: std::time::Duration,
    pub peers: Vec<PeerEntry>,
}

/// A live link, as `hxd link status` would show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStatus {
    pub peer: String,
    pub server: ServerId,
    pub servers: usize,
    pub ghosts: usize,
}

#[derive(Clone)]
pub struct Hub(Arc<Inner>);

struct Inner {
    key: LinkKey,
    epoch: [u8; 8],
    config: Mutex<HubConfig>,
    core: Arc<Core>,
    state: Mutex<State>,
    /// Ghosts' chat lines, in the order their links received them, on
    /// their way to the one task that logs them: a commit blocks, and a
    /// link's reader must not.
    chat: mpsc::Sender<GhostLine>,
    chat_rx: Mutex<Option<mpsc::Receiver<GhostLine>>>,
}

/// Ghosts' lines waiting to be logged, across every link. Past it a line
/// is not shown here, and is logged as dropped.
const CHAT_CAP: usize = 1024;

#[derive(Default)]
struct State {
    links: HashMap<String, Live>,
    /// What interrupted links learned, kept for the grace period.
    held: HashMap<String, Held>,
    /// Numbers what links pass on to each other, in the order it happened.
    relay_seq: u64,
    generation: u64,
    /// Stopping: no link is let in or dialed, so peers hold this server's
    /// users rather than take them into a link it is about to drop.
    shutting_down: bool,
    /// Peers with a dial loop running, so a reload never starts a second.
    dialing: std::collections::HashSet<String>,
}

/// An interrupted link's servers and ghosts, kept without telling anyone
/// until it comes back or the grace period runs out (the extension's
/// Interruption and Resynchronisation).
struct Held {
    /// Which interruption this is, for the timer that ends it.
    generation: u64,
    peer: ServerGroup,
    epoch: [u8; 8],
    /// The features the link had: what was relayed from it, and how.
    features: u32,
    servers: HashMap<ServerId, ServerGroup>,
    ghosts: HashMap<u16, Slot>,
}

struct Live {
    generation: u64,
    /// The peer's epoch from its Hello: a different one on its return
    /// means its user IDs name other people now.
    epoch: Option<[u8; 8]>,
    /// Held ghosts of a peer that came back with a new epoch, until its
    /// snapshot says which of them are still there.
    stale: Vec<Slot>,
    /// Held servers not yet named again in the peer's Link Servers.
    unconfirmed: std::collections::HashSet<ServerId>,
    close: Option<oneshot::Sender<Reason>>,
    /// The peer itself, once its Hello was accepted.
    peer: Option<ServerGroup>,
    /// Servers learned over this link, the peer excluded.
    servers: HashMap<ServerId, ServerGroup>,
    features: u32,
    /// Where the export feed reaches this link, once it is established.
    exports: Option<mpsc::Sender<Export>>,
    /// Requests this server sends the peer, once the link is established.
    requests: Option<mpsc::Sender<Request>>,
    /// What other links pass on to this one, from its Link Servers on.
    relays: Option<mpsc::Sender<Relayed>>,
    /// The peer's users shown here, by the ID the peer gives them.
    ghosts: HashMap<u16, Slot>,
}

struct Slot {
    uid: hxd_core::roster::Uid,
    /// The group as the peer last sent it, to show the ghost again when
    /// its home server changes and, later, to relay it whole.
    group: UserGroup,
}

/// A request for the peer (905, 906), and where its reply's fields go.
pub(crate) struct Request {
    pub(crate) ty: u32,
    pub(crate) fields: Vec<Field>,
    pub(crate) reply: oneshot::Sender<Reply>,
}

/// A reply's fields, and whether it was marked an error.
pub(crate) type Reply = (bool, Vec<Field>);

/// Requests one link may have waiting to be sent.
const REQUEST_CAP: usize = 64;

/// A link login the hub confirmed.
struct Granted {
    entry: PeerEntry,
}

impl Hub {
    pub fn new(seed: &[u8; 32], config: HubConfig, core: Arc<Core>) -> Hub {
        let mut epoch = [0u8; 8];
        getrandom::getrandom(&mut epoch).expect("the OS CSPRNG");
        let (chat, chat_rx) = mpsc::channel(CHAT_CAP);
        Hub(Arc::new(Inner {
            key: LinkKey::from_seed(seed),
            epoch,
            config: Mutex::new(config),
            core,
            state: Mutex::default(),
            chat,
            chat_rx: Mutex::new(Some(chat_rx)),
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
        self.0.core.queue_budget()
    }

    /// Start linking: the task that hands the core's export feed to every
    /// link, and a dialer for every peer this server dials, each on a
    /// task of its own that reconnects while its entry stays configured.
    pub fn start(&self) {
        // Installed before anything can link: a link that subscribed while
        // no feed was installed would never hear what changed after.
        let rx = self.0.core.peer_feed(FEED_CAP);
        tokio::spawn(feed(self.clone(), rx));
        self.0
            .core
            .set_peer_router(Arc::new(Router(Arc::downgrade(&self.0))));
        if let Some(mut lines) = self.0.chat_rx.lock().unwrap().take() {
            let core = self.0.core.clone();
            tokio::task::spawn_blocking(move || {
                while let Some(line) = lines.blocking_recv() {
                    instrument::link_queue_depth("chat", lines.len());
                    core.ghost_chat(line);
                }
            });
        }
        self.spawn_dialers();
    }

    fn spawn_dialers(&self) {
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
        // A peer removed while its link was interrupted is not coming back.
        let removed: Vec<String> = state
            .held
            .keys()
            .filter(|name| !peers.iter().any(|p| &p.name == *name))
            .cloned()
            .collect();
        let mut gone = Vec::new();
        for name in &removed {
            if let Some(held) = state.held.remove(name) {
                if held.features & feature::TRANSIT != 0 {
                    servers_gone(&mut state, name, &held.peer, held.servers.keys());
                }
                gone.extend(held.ghosts.into_values());
            }
        }
        drop(state);
        self.part(gone);
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

    /// Close every link for a `Shutdown`, which peers keep what they
    /// learned through for their grace period, and wait a moment for the
    /// Close to be written.
    pub async fn shutdown(&self) {
        self.0.state.lock().unwrap().shutting_down = true;
        self.close_all(Reason::Shutdown);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !self.0.state.lock().unwrap().links.is_empty()
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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
                    ghosts: live.ghosts.len(),
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
        // Told to close as soon as it starts, when this server is stopping.
        let close = match state.shutting_down {
            true => {
                let _ = tx.send(Reason::Shutdown);
                None
            }
            false => Some(tx),
        };
        let old = state.links.insert(
            peer.to_owned(),
            Live {
                generation,
                epoch: None,
                stale: Vec::new(),
                unconfirmed: Default::default(),
                close,
                peer: None,
                servers: HashMap::new(),
                features: 0,
                exports: None,
                ghosts: HashMap::new(),
                requests: None,
                relays: None,
            },
        );
        if let Some(mut old) = old {
            if let Some(close) = old.close.take() {
                let _ = close.send(Reason::Replaced);
            }
            // Its late frames can no longer touch the new link, and its
            // own ending finds a newer generation. What it learned is the
            // new link's to take back: a redial over a half-open link is
            // an interruption too.
            self.hold(&mut state, peer, old);
        }
        (generation, rx)
    }

    /// Keep what `live` learned for the grace period, under the hub's
    /// lock; a link that never got as far as its peer's Hello has nothing
    /// to keep, and its ghosts, if any, go.
    fn hold(&self, state: &mut State, peer: &str, live: Live) {
        // Ghosts of a restarted peer not yet matched against its snapshot:
        // under IDs nothing can match any more.
        let mut gone = live.stale;
        let (Some(server), Some(epoch)) = (live.peer, live.epoch) else {
            gone.extend(live.ghosts.into_values());
            self.part_later(gone);
            return;
        };
        let generation = live.generation;
        let features = live.features;
        let held = Held {
            generation,
            peer: server,
            epoch,
            features,
            servers: live.servers,
            ghosts: live.ghosts,
        };
        // An earlier hold is resumed before a later one can begin, so one
        // left here is a link's that never took it back: its ghosts go.
        if let Some(earlier) = state.held.insert(peer.to_owned(), held) {
            gone.extend(earlier.ghosts.into_values());
        }
        if features & feature::TRANSIT != 0 {
            for slot in &gone {
                relay(
                    state,
                    peer,
                    Relay::UserGone(gone_fields(slot.uid, Reason::Disconnected)),
                );
            }
        }
        self.part_later(gone);
        let (hub, peer) = (self.clone(), peer.to_owned());
        tokio::spawn(async move {
            // Read here, off the state lock it was held under: config and
            // state are never taken together.
            let grace = hub.0.config.lock().unwrap().grace;
            tokio::time::sleep(grace).await;
            hub.expire(&peer, generation);
        });
    }

    /// Part ghosts from under the hub's lock, on a task of their own.
    fn part_later(&self, slots: Vec<Slot>) {
        if slots.is_empty() {
            return;
        }
        let core = self.0.core.clone();
        tokio::spawn(async move {
            for slot in slots {
                core.ghost_part(slot.uid);
            }
        });
    }

    /// The grace period, while what `peer`'s interrupted link learned is
    /// held for it.
    pub(crate) fn holding(&self, peer: &str) -> Option<std::time::Duration> {
        let held = self.0.state.lock().unwrap().held.contains_key(peer);
        held.then(|| self.0.config.lock().unwrap().grace)
    }

    /// Whether this server is stopping, for a dialer to give up.
    pub(crate) fn shutting_down(&self) -> bool {
        self.0.state.lock().unwrap().shutting_down
    }

    /// The grace period of the interruption `generation` has run out
    /// without the link coming back: everything it learned goes.
    fn expire(&self, peer: &str, generation: u64) {
        let mut state = self.0.state.lock().unwrap();
        if !state
            .held
            .get(peer)
            .is_some_and(|h| h.generation == generation)
        {
            return;
        }
        let held = state.held.remove(peer).expect("checked");
        if held.features & feature::TRANSIT != 0 {
            servers_gone(&mut state, peer, &held.peer, held.servers.keys());
        }
        drop(state);
        tracing::info!(%peer, ghosts = held.ghosts.len(), "link not back within the grace period");
        self.part(held.ghosts.into_values());
    }

    /// The peer is back: take what its interrupted link learned, to be
    /// reconciled against what it sends now. A Hello naming another
    /// server means the old one is gone; a new epoch, that its user IDs
    /// name other people, so its ghosts wait for the snapshot to say which
    /// are still there.
    pub(crate) fn resume(
        &self,
        peer: &str,
        generation: u64,
        server: ServerId,
        epoch: [u8; 8],
        features: u32,
    ) {
        let mut state = self.0.state.lock().unwrap();
        let held = state.held.remove(peer);
        if !state
            .links
            .get(peer)
            .is_some_and(|l| l.generation == generation)
        {
            if let Some(held) = held {
                state.held.insert(peer.to_owned(), held);
            }
            return;
        }
        let transit = features & feature::TRANSIT != 0;
        // Back as another server, or back without the transit it had: what
        // the other links were shown of it is gone.
        let mut gone = Vec::new();
        let held = match held {
            Some(h) if h.peer.id != server || (h.features & feature::TRANSIT != 0 && !transit) => {
                if h.features & feature::TRANSIT != 0 {
                    servers_gone(&mut state, peer, &h.peer, h.servers.keys());
                }
                gone.extend(h.ghosts.into_values());
                None
            }
            held => held,
        };
        // Features and what was held settled under one lock, so no other
        // link opening meanwhile sees one without the other.
        let live = state.links.get_mut(peer).expect("checked");
        live.epoch = Some(epoch);
        live.features = features;
        let mut servers: Vec<ServerGroup> = Vec::new();
        let mut users: Vec<Vec<Field>> = Vec::new();
        if let Some(h) = held {
            // Held without transit and back with it: the other links have
            // been shown none of this yet.
            let gained = transit && h.features & feature::TRANSIT == 0;
            live.unconfirmed = h.servers.keys().copied().collect();
            if gained {
                servers.extend(h.servers.values().map(farther));
            }
            live.servers.extend(h.servers);
            if h.epoch == epoch {
                if gained {
                    users.extend(
                        h.ghosts
                            .values()
                            .map(|s| relayed_group(s.uid, &s.group, features)),
                    );
                }
                live.ghosts = h.ghosts;
            } else {
                live.stale = h.ghosts.into_values().collect();
            }
        }
        // The peer, then what lies behind it, then whom: announced to the
        // other transit links before anything homed on them.
        if let Some(own) = live.peer.clone().filter(|_| transit) {
            relay(&mut state, peer, Relay::Server(farther(&own)));
            for group in servers {
                relay(&mut state, peer, Relay::Server(group));
            }
            for group in users {
                relay(&mut state, peer, Relay::User(group));
            }
        }
        drop(state);
        self.part(gone);
    }

    /// The peer's Link Servers is complete: a held server it no longer
    /// names is gone, with its users.
    pub(crate) fn servers_settled(&self, peer: &str, generation: u64) {
        let gone: Vec<ServerId> = {
            let mut state = self.0.state.lock().unwrap();
            let Some(live) = state
                .links
                .get_mut(peer)
                .filter(|l| l.generation == generation)
            else {
                return;
            };
            live.unconfirmed.drain().collect()
        };
        for id in gone {
            self.forget_server(peer, generation, id, None);
        }
    }

    /// Ghosts leave, after the hub's lock is released: each is a broadcast
    /// to every local session, and the feed waits on that lock.
    fn part(&self, slots: impl IntoIterator<Item = Slot>) {
        for slot in slots {
            self.0.core.ghost_part(slot.uid);
        }
    }

    /// The link has ended. Interrupted (dropped, or closed for a
    /// `Shutdown`), what it learned is kept for the grace period; ended
    /// for good, everyone shown over it leaves now.
    pub(crate) fn unregister(&self, peer: &str, generation: u64, interrupted: bool) {
        let mut state = self.0.state.lock().unwrap();
        if !state
            .links
            .get(peer)
            .is_some_and(|l| l.generation == generation)
        {
            return;
        }
        let live = state.links.remove(peer).expect("checked");
        if interrupted {
            self.hold(&mut state, peer, live);
            return;
        }
        // Ended for good: nothing held for it stays either, and the other
        // links hear that everything behind it has gone.
        let held = state.held.remove(peer);
        if live.features & feature::TRANSIT != 0 {
            if let Some(server) = &live.peer {
                servers_gone(&mut state, peer, server, live.servers.keys());
            }
        }
        if let Some(h) = held.as_ref().filter(|h| h.features & feature::TRANSIT != 0) {
            servers_gone(&mut state, peer, &h.peer, h.servers.keys());
        }
        drop(state);
        self.part(
            live.ghosts
                .into_values()
                .chain(live.stale)
                .chain(held.into_iter().flat_map(|h| h.ghosts.into_values())),
        );
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
        let (own_tag, show_tags) = {
            let config = self.0.config.lock().unwrap();
            (config.tag.clone(), config.show_tags)
        };
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
        // Servers held for another peer's interrupted link are still its.
        for (_, held) in state.held.iter().filter(|(name, _)| *name != peer) {
            for known in std::iter::once(&held.peer).chain(held.servers.values()) {
                if known.id == group.id {
                    return Err(Reason::Loop);
                }
                if same_tag(&known.tag, &group.tag) {
                    return Err(Reason::TagConflict);
                }
            }
        }
        let live = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
            .ok_or(Reason::Replaced)?;
        let id = group.id;
        live.unconfirmed.remove(&id);
        // Passed on before any of its users; the peer's own group in its
        // Hello waits for the features that Hello settles (`resume`).
        let passed = (live.features & feature::TRANSIT != 0).then(|| farther(&group));
        if own {
            live.peer = Some(group);
        } else {
            live.servers.insert(id, group);
        }
        // A server's new tag, name or color reaches the ghosts already
        // shown from it, not only those shown after.
        let refreshed: Vec<(hxd_core::roster::Uid, GhostInfo)> = live
            .ghosts
            .values()
            .filter(|slot| slot.group.home == id)
            .filter_map(|slot| Some((slot.uid, self.ghost_info(live, &slot.group, show_tags)?)))
            .collect();
        if let Some(group) = passed {
            relay(&mut state, peer, Relay::Server(group));
        }
        drop(state);
        for (uid, info) in refreshed {
            self.0.core.ghost_update(uid, info);
        }
        Ok(())
    }

    /// A server is no longer reachable over the link: it goes, and every
    /// user homed there with it.
    pub(crate) fn forget_server(
        &self,
        peer: &str,
        generation: u64,
        id: ServerId,
        came: Option<Vec<Field>>,
    ) {
        let mut state = self.0.state.lock().unwrap();
        if let Some(live) = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
        {
            // Only a server this link put behind it: a peer speaks for its
            // own side of the network, never for another link's or this one.
            if live.servers.remove(&id).is_none() {
                return;
            }
            let transit = live.features & feature::TRANSIT != 0;
            let homed: Vec<u16> = live
                .ghosts
                .iter()
                .filter(|(_, slot)| slot.group.home == id)
                .map(|(peer_id, _)| *peer_id)
                .collect();
            let gone: Vec<Slot> = homed
                .iter()
                .filter_map(|peer_id| live.ghosts.remove(peer_id))
                .collect();
            // Server Gone stands for its users' departures: no User Gone.
            if transit {
                let fields = came.unwrap_or_else(|| vec![Field::new(field::SERVER_ID, id.0)]);
                relay(&mut state, peer, Relay::ServerGone(fields));
            }
            drop(state);
            self.part(gone);
        }
    }

    /// The link is established: from here every export reaches it. The
    /// snapshot is taken under the same lock the feed task hands events
    /// out under, so nothing numbered after it can have been handed out
    /// before; events numbered up to it are the link's to skip.
    pub(crate) fn subscribe(&self, peer: &str, generation: u64) -> Option<Subscribed> {
        let mut state = self.0.state.lock().unwrap();
        let live = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)?;
        let (since, users) = self.0.core.peer_snapshot();
        let (tx, exports) = mpsc::channel(EXPORT_CAP);
        live.exports = Some(tx);
        let (tx, requests) = mpsc::channel(REQUEST_CAP);
        live.requests = Some(tx);
        let transit = live.features & feature::TRANSIT != 0;
        // The users of the other transit links, as of this relay number:
        // what was passed on before it is in here.
        let relayed = if transit {
            let links = state
                .links
                .iter()
                .filter(|(name, l)| *name != peer && l.features & feature::TRANSIT != 0)
                .map(|(_, l)| (l.features, &l.ghosts));
            let held = state
                .held
                .iter()
                .filter(|(name, h)| *name != peer && h.features & feature::TRANSIT != 0)
                .map(|(_, h)| (h.features, &h.ghosts));
            links
                .chain(held)
                .flat_map(|(features, ghosts)| {
                    ghosts
                        .values()
                        .map(move |slot| relayed_group(slot.uid, &slot.group, features))
                })
                .collect()
        } else {
            Vec::new()
        };
        Some(Subscribed {
            since,
            users,
            exports,
            requests,
            relayed,
            relayed_up_to: state.relay_seq,
        })
    }

    /// What this link's Link Servers says, and where what other links pass
    /// on to it arrives from now: the servers behind the other transit
    /// links, one hop farther, over a link that negotiated transit itself.
    pub(crate) fn relay_open(
        &self,
        peer: &str,
        generation: u64,
    ) -> (Vec<ServerGroup>, Option<mpsc::Receiver<Relayed>>) {
        let mut state = self.0.state.lock().unwrap();
        let transit = state
            .links
            .get(peer)
            .filter(|l| l.generation == generation)
            .is_some_and(|l| l.features & feature::TRANSIT != 0);
        if !transit {
            return (Vec::new(), None);
        }
        let links = state
            .links
            .iter()
            .filter(|(name, l)| *name != peer && l.features & feature::TRANSIT != 0)
            .flat_map(|(_, l)| l.peer.iter().chain(l.servers.values()));
        let held = state
            .held
            .iter()
            .filter(|(name, h)| *name != peer && h.features & feature::TRANSIT != 0)
            .flat_map(|(_, h)| std::iter::once(&h.peer).chain(h.servers.values()));
        let servers = links.chain(held).map(farther).collect();
        let (tx, rx) = mpsc::channel(RELAY_CAP);
        let live = state.links.get_mut(peer).expect("checked");
        live.relays = Some(tx);
        (servers, Some(rx))
    }

    /// A request from `from`'s peer about a user this server shows it as
    /// `target`: `None` when that is no ghost, so the request is this
    /// server's to answer. A ghost's goes on to the link it came from, its
    /// IDs translated (`sender` is the peer's ID for the user it is from,
    /// in a private message), over links that both negotiated transit, as
    /// only then was the ghost shown to this peer.
    pub(crate) fn forward(
        &self,
        from: &str,
        generation: u64,
        target: Uid,
        request: &hxd_session::frame::Frame,
        feature: u32,
        sender: Option<u16>,
    ) -> Option<Result<oneshot::Receiver<Reply>, Reason>> {
        let state = self.0.state.lock().unwrap();
        let found = state.links.iter().find_map(|(name, l)| {
            l.ghosts
                .iter()
                .find(|(_, slot)| slot.uid == target)
                .map(|(id, _)| (name, l, *id))
        });
        let Some((name, live, id)) = found else {
            // Kept while its link is interrupted: there, but out of reach.
            let held = state
                .held
                .values()
                .any(|h| h.ghosts.values().any(|slot| slot.uid == target));
            return held.then_some(Err(Reason::Unreachable));
        };
        let origin = state.links.get(from).filter(|l| l.generation == generation);
        let Some(origin) = origin.filter(|o| {
            name != from
                && o.features & feature::TRANSIT != 0
                && live.features & feature::TRANSIT != 0
        }) else {
            return Some(Err(Reason::UnknownUser));
        };
        if feature != 0 && live.features & feature == 0 {
            return Some(Err(Reason::FeatureNotNegotiated));
        }
        let from_uid = match sender {
            None => None,
            Some(s) => match origin.ghosts.get(&s) {
                Some(slot) => Some(slot.uid),
                None => return Some(Err(Reason::UnknownUser)),
            },
        };
        let mut passed = crate::wire::fields(request);
        for f in &mut passed {
            match f.id {
                field::TARGET_ID => *f = Field::u16(field::TARGET_ID, id),
                field::USER_ID => {
                    if let Some(uid) = from_uid {
                        *f = Field::u16(field::USER_ID, uid);
                    }
                }
                _ => {}
            }
        }
        Some(enqueue(live, request.ty, passed).map_err(reason_of))
    }

    /// The server `id` as the link knows it, when it lies behind the link:
    /// the peer, or a server learned over it. A moderation request names
    /// no other (the extension's requester check).
    pub(crate) fn requester(&self, peer: &str, generation: u64, id: ServerId) -> Option<Requester> {
        let state = self.0.state.lock().unwrap();
        let live = state
            .links
            .get(peer)
            .filter(|l| l.generation == generation)?;
        live.peer
            .iter()
            .chain(live.servers.values())
            .find(|s| s.id == id)
            .map(|s| Requester {
                id: s.id.0,
                tag: s.tag.clone(),
                name: s.name.clone(),
            })
    }

    /// Where ghost `uid` is from: its home server's ID and tag, and its
    /// own name.
    fn ghost_home(&self, uid: Uid) -> Option<(ServerId, String, String)> {
        let state = self.0.state.lock().unwrap();
        state.links.values().find_map(|live| {
            let slot = live.ghosts.values().find(|s| s.uid == uid)?;
            let home = live
                .peer
                .iter()
                .chain(live.servers.values())
                .find(|s| s.id == slot.group.home)?;
            Some((home.id, home.tag.clone(), slot.group.name.clone()))
        })
    }

    /// The ghost the peer calls `id` on this link.
    pub(crate) fn ghost_uid(&self, peer: &str, generation: u64, id: u16) -> Option<Uid> {
        let state = self.0.state.lock().unwrap();
        state
            .links
            .get(peer)
            .filter(|l| l.generation == generation)
            .and_then(|l| l.ghosts.get(&id))
            .map(|slot| slot.uid)
    }

    /// Send the peer that shows ghost `uid` a request built from the ID
    /// the peer gave it, over a link that negotiated `feature`.
    fn request(
        &self,
        uid: Uid,
        feature: u32,
        ty: u32,
        build: impl FnOnce(u16) -> Vec<Field>,
    ) -> Result<oneshot::Receiver<Reply>, PeerRefusal> {
        let state = self.0.state.lock().unwrap();
        let found = state.links.values().find_map(|l| {
            l.ghosts
                .iter()
                .find(|(_, slot)| slot.uid == uid)
                .map(|(id, _)| (l, *id))
        });
        let Some((live, id)) = found else {
            // Kept while its link is interrupted: there, but out of reach.
            let held = state
                .held
                .values()
                .any(|h| h.ghosts.values().any(|slot| slot.uid == uid));
            return Err(if held {
                PeerRefusal::Unreachable
            } else {
                PeerRefusal::UnknownUser
            });
        };
        // Zero is moderation, which every link carries.
        if feature != 0 && live.features & feature == 0 {
            return Err(PeerRefusal::FeatureNotNegotiated);
        }
        enqueue(live, ty, build(id))
    }

    /// Send a request for server `home` over the link it lies behind,
    /// never back over the link `except` it came in on.
    pub(crate) fn request_for(
        &self,
        home: ServerId,
        ty: u32,
        fields: Vec<Field>,
        except: Option<&str>,
    ) -> Result<oneshot::Receiver<Reply>, PeerRefusal> {
        let state = self.0.state.lock().unwrap();
        let live = state
            .links
            .iter()
            .filter(|(name, _)| Some(name.as_str()) != except)
            .map(|(_, l)| l)
            // Relayed from another link: only over one with transit.
            .filter(|l| except.is_none() || l.features & feature::TRANSIT != 0)
            .find(|l| {
                l.peer
                    .iter()
                    .chain(l.servers.values())
                    .any(|s| s.id == home)
            })
            .ok_or(PeerRefusal::Unreachable)?;
        enqueue(live, ty, fields)
    }

    /// The bans this server's operator asked lifted, sent to their home
    /// servers: on a reload, after `hxd ban lift`. One the home server
    /// lifts, or no longer knows, is marked lifted; one it cannot be
    /// asked about now waits for the next reload. Called off the reactor:
    /// the bans are read from the store.
    pub fn send_unbans(&self) {
        let me = self.server_id();
        for ban in self.0.core.network_unbans_asked() {
            // Asked under a key this server no longer has: its home server
            // would answer any other requester `UnknownBan`, which reads as
            // lifted while the ban stands.
            if ban.requester != me.0 {
                warn!(id = ban.id, home = %ban.home_tag, "network ban asked under another server key; its home server's operator must lift it");
                continue;
            }
            let home = ServerId(ban.home);
            let fields = vec![
                Field::new(field::BAN_ID, ban.handle),
                Field::new(field::SERVER_ID, ban.home),
                Field::new(field::REQUESTER, me.0),
            ];
            let answer = match self.request_for(home, tx::UNBAN, fields, None) {
                Ok(answer) => answer,
                Err(why) => {
                    warn!(id = ban.id, home = %ban.home_tag, ?why, "network unban not sent; again at the next reload");
                    continue;
                }
            };
            let core = self.0.core.clone();
            tokio::spawn(async move {
                let result = match tokio::time::timeout(PEER_WAIT, answer).await {
                    Ok(Ok((error, fields))) => refusal(error, &fields),
                    _ => Some(PeerRefusal::Unreachable),
                };
                match result {
                    None | Some(PeerRefusal::UnknownBan) => {
                        tracing::info!(id = ban.id, home = %ban.home_tag, "network ban lifted");
                        tokio::task::spawn_blocking(move || core.network_unbanned(ban.id));
                    }
                    Some(why) => {
                        warn!(id = ban.id, home = %ban.home_tag, ?why, "network unban refused; again at the next reload")
                    }
                }
            });
        }
    }

    /// Hand one export to every established link. A link too far behind
    /// to take it is closed and starts over from a snapshot.
    fn fan_out(&self, export: Export) {
        let mut state = self.0.state.lock().unwrap();
        for live in state.links.values_mut() {
            let Some(tx) = &live.exports else { continue };
            if let Err(e) = tx.try_send(export.clone()) {
                // Closed is a link already ending for its own reason.
                if matches!(e, mpsc::error::TrySendError::Full(_)) {
                    instrument::link_lagged("export");
                }
                live.exports = None;
                if let Some(close) = live.close.take() {
                    let _ = close.send(Reason::Shutdown);
                }
            }
        }
    }

    /// Every link, closed: the feed fell behind, so every link may have
    /// missed something, and each starts over from a snapshot.
    fn close_all(&self, reason: Reason) {
        let mut state = self.0.state.lock().unwrap();
        for live in state.links.values_mut() {
            if let Some(close) = live.close.take() {
                let _ = close.send(reason);
            }
        }
    }

    /// One user of the peer's, new or changed. A user homed anywhere but
    /// behind this link is refused: a peer presents only its own side of
    /// the network.
    pub(crate) fn apply_user(
        &self,
        peer: &str,
        generation: u64,
        g: UserGroup,
    ) -> Result<(), &'static str> {
        let (show_tags, max_ghosts, limit) = {
            let config = self.0.config.lock().unwrap();
            let limit = config
                .peers
                .iter()
                .find(|p| p.name == peer)
                .map_or(0, |p| p.ghosts);
            (config.show_tags, config.max_ghosts, limit)
        };
        let mut state = self.0.state.lock().unwrap();
        let live = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
            .ok_or("link replaced")?;
        let info = self
            .ghost_info(live, &g, show_tags)
            .ok_or("not homed behind this link")?;
        // Attached and counted under the hub's lock, so two links cannot
        // both take the last place under the caps.
        let transit = live.features & feature::TRANSIT != 0;
        if let Some(slot) = live.ghosts.get_mut(&g.id) {
            // A snapshot resends everyone: only a change goes on.
            let changed = slot.group != g;
            slot.group = g;
            self.0.core.ghost_update(slot.uid, info);
            let passed = relayed_group(slot.uid, &slot.group, live.features);
            if transit && changed {
                relay(&mut state, peer, Relay::User(passed));
            }
            return Ok(());
        }
        if live.ghosts.len() >= limit || self.0.core.ghost_count() >= max_ghosts {
            instrument::link_dropped("ghost");
            return Err("ghost bound reached");
        }
        let Some(uid) = self.0.core.ghost_attach(info) else {
            instrument::link_dropped("ghost");
            return Err("no uid to give a ghost");
        };
        let passed = relayed_group(uid, &g, live.features);
        live.ghosts.insert(g.id, Slot { uid, group: g });
        if transit {
            relay(&mut state, peer, Relay::User(passed));
        }
        Ok(())
    }

    /// How a user of the peer's is shown here, or `None` if it is homed
    /// anywhere but behind this link.
    fn ghost_info(&self, live: &Live, g: &UserGroup, show_tags: bool) -> Option<GhostInfo> {
        let home = live
            .peer
            .iter()
            .chain(live.servers.values())
            .find(|s| s.id == g.home)?;
        Some(GhostInfo {
            // Cut to a local name's length for display only; the group
            // keeps the name whole for relaying.
            nick: g.name.chars().take(31).collect(),
            icon: g.icon,
            away: g.flags & flag::AWAY != 0,
            color: home.color.unwrap_or_else(|| derived_color(&home.tag)),
            remote: RemoteRef {
                home_tag: home.tag.clone(),
                home_name: home.name.clone(),
                tagged: show_tags,
                refuses_msgs: g.flags & flag::REFUSES_MESSAGES != 0
                    || live.features & feature::PRIVATE_MESSAGES == 0,
            },
            visible: !g.exclude.contains(&self.server_id()),
        })
    }

    /// A chat line from one of the peer's users, shown here unless the
    /// core declines to.
    pub(crate) fn chat(
        &self,
        peer: &str,
        generation: u64,
        id: u16,
        text: String,
        style: u16,
        fields: &[Field],
    ) -> Result<(), &'static str> {
        let uid = {
            let mut state = self.0.state.lock().unwrap();
            let live = state
                .links
                .get(peer)
                .filter(|l| l.generation == generation)
                .ok_or("no such user on this link")?;
            let uid = live.ghosts.get(&id).ok_or("no such user on this link")?.uid;
            // Passed on whatever this server shows, its speaker named by
            // the ID this server gives it.
            let both = feature::TRANSIT | feature::PUBLIC_CHAT;
            if live.features & both == both {
                let mut passed = fields.to_vec();
                for f in passed.iter_mut().filter(|f| f.id == field::USER_ID) {
                    *f = Field::u16(field::USER_ID, uid);
                }
                relay(&mut state, peer, Relay::Chat(passed));
            }
            uid
        };
        let Some(line) = self.0.core.ghost_line(uid, text, style) else {
            return Ok(());
        };
        self.0.chat.try_send(line).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => {
                instrument::link_dropped("chat");
                "too many lines waiting to be logged"
            }
            mpsc::error::TrySendError::Closed(_) => "the task logging lines has ended",
        })
    }

    pub(crate) fn core(&self) -> &Core {
        &self.0.core
    }

    pub(crate) fn core_arc(&self) -> Arc<Core> {
        self.0.core.clone()
    }

    pub(crate) fn epoch(&self) -> [u8; 8] {
        self.0.epoch
    }

    pub(crate) fn user_gone(&self, peer: &str, generation: u64, id: u16, came: Vec<Field>) {
        let mut state = self.0.state.lock().unwrap();
        if let Some(live) = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
        {
            let transit = live.features & feature::TRANSIT != 0;
            let gone = live.ghosts.remove(&id);
            if let Some(slot) = gone.as_ref().filter(|_| transit) {
                let passed = came
                    .into_iter()
                    .map(|f| match f.id {
                        field::USER_ID => Field::u16(field::USER_ID, slot.uid),
                        _ => f,
                    })
                    .collect();
                relay(&mut state, peer, Relay::UserGone(passed));
            }
            drop(state);
            self.part(gone);
        }
    }

    /// A whole snapshot: everyone in it shown, everyone shown before and
    /// not in it gone.
    pub(crate) fn apply_snapshot(&self, peer: &str, generation: u64, groups: Vec<UserGroup>) {
        // A peer back with a new epoch: a held ghost is the same user as
        // one it now shows from the same home server under the same name
        // and icon, under the ID it now uses; the rest are gone.
        let unclaimed: Vec<Slot> = {
            let mut state = self.0.state.lock().unwrap();
            match state
                .links
                .get_mut(peer)
                .filter(|l| l.generation == generation)
            {
                Some(live) => {
                    let mut stale = std::mem::take(&mut live.stale);
                    for g in &groups {
                        // Homed where this link still reaches, and an ID
                        // the snapshot gives once: a repeat claims nothing.
                        let homed = live
                            .peer
                            .iter()
                            .chain(live.servers.values())
                            .any(|s| s.id == g.home);
                        if !homed || live.ghosts.contains_key(&g.id) {
                            continue;
                        }
                        let same = stale.iter().position(|s| {
                            s.group.home == g.home
                                && s.group.name == g.name
                                && s.group.icon == g.icon
                        });
                        if let Some(at) = same {
                            live.ghosts.insert(g.id, stale.swap_remove(at));
                        }
                    }
                    if live.features & feature::TRANSIT != 0 {
                        for slot in &stale {
                            relay(
                                &mut state,
                                peer,
                                Relay::UserGone(gone_fields(slot.uid, Reason::Disconnected)),
                            );
                        }
                    }
                    stale
                }
                None => Vec::new(),
            }
        };
        self.part(unclaimed);
        let ids: std::collections::HashSet<u16> = groups.iter().map(|g| g.id).collect();
        let stale: Vec<u16> = {
            let state = self.0.state.lock().unwrap();
            state
                .links
                .get(peer)
                .filter(|l| l.generation == generation)
                .map(|l| {
                    l.ghosts
                        .keys()
                        .filter(|id| !ids.contains(id))
                        .copied()
                        .collect()
                })
                .unwrap_or_default()
        };
        for id in stale {
            self.user_gone(peer, generation, id, gone_fields(id, Reason::Disconnected));
        }
        for g in groups {
            if let Err(why) = self.apply_user(peer, generation, g) {
                warn!(%peer, "user in snapshot not shown: {why}");
            }
        }
    }
}

/// The color a server's users are shown in when it suggests none: one of
/// its own, from its tag, the same wherever it is shown.
fn derived_color(tag: &str) -> u32 {
    let d = Sha256::digest(tag.to_ascii_lowercase().as_bytes());
    u32::from_be_bytes([0, d[0], d[1], d[2]])
}

/// Hand the core's export feed to every link, for as long as the process
/// runs. A feed the core closed fell behind: every link starts over.
async fn feed(hub: Hub, mut rx: mpsc::Receiver<Export>) {
    loop {
        while let Some(export) = rx.recv().await {
            instrument::link_queue_depth("feed", rx.len());
            hub.fan_out(export);
        }
        warn!("the link export feed fell behind; every link starts over");
        // A new feed before the links close, so none can subscribe while
        // there is none to hear what changed after its snapshot.
        rx = hub.0.core.peer_feed(FEED_CAP);
        hub.close_all(Reason::Shutdown);
    }
}

/// Whether two entries for a peer describe the same link: the same key,
/// login and address, and the same features and ghost bound, which are
/// settled when a link starts.
fn same_terms(a: &PeerEntry, b: &PeerEntry) -> bool {
    a.key == b.key
        && a.account == b.account
        && a.dial == b.dial
        && a.features == b.features
        && a.ghosts == b.ghosts
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

/// What links pass on to each other (L7), numbered in the order it
/// happened, as the export feed numbers what the core does.
#[derive(Debug, Clone)]
pub(crate) enum Relay {
    /// A server newly reachable, or changed, at this server's distance.
    Server(ServerGroup),
    /// A server no longer reachable, with every user homed on it: the
    /// Server Gone as it came, every field passed on.
    ServerGone(Vec<Field>),
    /// A ghost's user group, under this server's ID for it.
    User(Vec<Field>),
    /// A User Gone as it came, under this server's ID for the user.
    UserGone(Vec<Field>),
    /// A public chat line, its speaker under this server's ID for them.
    Chat(Vec<Field>),
}

pub(crate) type Relayed = (u64, Relay);

/// What one link may have waiting from the others; past it the link is
/// too slow, and starts over.
const RELAY_CAP: usize = 16384;

/// Pass `what` from `from`'s link to every other established link that
/// negotiated transit (and public chat, for a line), under the hub's lock
/// so the order is the hub's. A link too far behind is closed.
fn relay(state: &mut State, from: &str, what: Relay) {
    state.relay_seq += 1;
    let seq = state.relay_seq;
    let chat = matches!(what, Relay::Chat(_));
    for (name, live) in state.links.iter_mut() {
        if name == from || live.features & feature::TRANSIT == 0 {
            continue;
        }
        if chat && live.features & feature::PUBLIC_CHAT == 0 {
            continue;
        }
        let Some(tx) = &live.relays else { continue };
        if let Err(e) = tx.try_send((seq, what.clone())) {
            if matches!(e, mpsc::error::TrySendError::Full(_)) {
                instrument::link_lagged("relay");
            }
            live.relays = None;
            if let Some(close) = live.close.take() {
                let _ = close.send(Reason::Shutdown);
            }
        }
    }
}

/// Everything behind a link gone: the peer and the servers learned over
/// it, each passed on as one Server Gone standing for its users.
fn servers_gone<'a>(
    state: &mut State,
    from: &str,
    peer: &ServerGroup,
    servers: impl Iterator<Item = &'a ServerId>,
) {
    let ids: Vec<ServerId> = std::iter::once(peer.id).chain(servers.copied()).collect();
    for id in ids {
        relay(
            state,
            from,
            Relay::ServerGone(vec![Field::new(field::SERVER_ID, id.0)]),
        );
    }
}

/// A User Gone this server makes itself, for a user it gives `uid`.
fn gone_fields(uid: Uid, why: Reason) -> Vec<Field> {
    vec![
        Field::u16(field::USER_ID, uid),
        Field::u16(field::REASON, why as u16),
    ]
}

/// A server group as this server passes it on: one hop farther.
fn farther(group: &ServerGroup) -> ServerGroup {
    ServerGroup {
        hops: group.hops.saturating_add(1),
        ..group.clone()
    }
}

/// A ghost's user group as this server passes it on: every field as it
/// came, but the ID this server gives the user and this server's own flag
/// rules, which refuse messages over a link that cannot carry them and
/// never pass on an admin.
fn relayed_group(uid: Uid, g: &UserGroup, features: u32) -> Vec<Field> {
    // Private chat never crosses a link, so every ghost refuses it.
    let mut flags = g.flags & (flag::AWAY | flag::REFUSES_MESSAGES) | flag::REFUSES_CHAT;
    if features & feature::PRIVATE_MESSAGES == 0 {
        flags |= flag::REFUSES_MESSAGES;
    }
    g.fields
        .iter()
        .map(|f| match f.id {
            field::USER_ID => Field::u16(field::USER_ID, uid),
            field::USER_FLAGS => Field::u16(field::USER_FLAGS, flags),
            _ => f.clone(),
        })
        .collect()
}

/// Hand a request to a link's session loop.
fn enqueue(
    live: &Live,
    ty: u32,
    fields: Vec<Field>,
) -> Result<oneshot::Receiver<Reply>, PeerRefusal> {
    let (reply, answer) = oneshot::channel();
    let request = Request { ty, fields, reply };
    match live.requests.as_ref().map(|r| r.try_send(request)) {
        Some(Ok(())) => Ok(answer),
        Some(Err(mpsc::error::TrySendError::Full(_))) => {
            instrument::link_dropped("request");
            Err(PeerRefusal::RateLimited)
        }
        _ => Err(PeerRefusal::Unreachable),
    }
}

/// What a link hands its session loop when it is established.
pub(crate) struct Subscribed {
    /// The feed's number at the snapshot: events up to it are in `users`.
    pub(crate) since: u64,
    pub(crate) users: Vec<LocalUser>,
    pub(crate) exports: mpsc::Receiver<Export>,
    pub(crate) requests: mpsc::Receiver<Request>,
    /// The other transit links' users, as user groups this server passes
    /// on, and the relay number they stand at.
    pub(crate) relayed: Vec<Vec<Field>>,
    pub(crate) relayed_up_to: u64,
}

/// The hub as the core's [`PeerRouter`]: weak, so the core holding it
/// does not keep the hub alive.
struct Router(std::sync::Weak<Inner>);

impl Router {
    /// Send a request and hand its reply's fields to `answer`, once they
    /// come; a link that ends first answers `Unreachable`.
    fn send<T: Send + 'static>(
        &self,
        uid: Uid,
        feature: u32,
        ty: u32,
        build: impl FnOnce(u16) -> Vec<Field>,
        answer: impl FnOnce(Vec<Field>) -> Result<T, PeerRefusal> + Send + 'static,
    ) -> oneshot::Receiver<Result<T, PeerRefusal>> {
        let (tx, rx) = oneshot::channel();
        let sent = match self.0.upgrade() {
            Some(inner) => Hub(inner).request(uid, feature, ty, build),
            None => Err(PeerRefusal::Unreachable),
        };
        match sent {
            Err(why) => {
                let _ = tx.send(Err(why));
            }
            Ok(reply) => {
                tokio::spawn(async move {
                    // Given up on after the extension's per-hop wait, so
                    // the link forgets a request a peer never answers.
                    let result = match tokio::time::timeout(PEER_WAIT, reply).await {
                        Ok(Ok((error, fields))) => match refusal(error, &fields) {
                            Some(why) => Err(why),
                            None => answer(fields),
                        },
                        _ => Err(PeerRefusal::Unreachable),
                    };
                    let _ = tx.send(result);
                });
            }
        }
        rx
    }
}

/// A reply's refusal, as the core names it: a reason other than `Ok`,
/// or a reply marked an error, which need not carry one.
fn refusal(error: bool, fields: &[Field]) -> Option<PeerRefusal> {
    let reason = find(fields, field::REASON)
        .and_then(Field::uint)
        .and_then(|v| u16::try_from(v).ok())
        .map(Reason::from_wire);
    Some(match reason {
        None if !error => return None,
        Some(Some(Reason::Ok)) if !error => return None,
        Some(Some(Reason::UnknownUser)) => PeerRefusal::UnknownUser,
        Some(Some(Reason::RefusesMessages)) => PeerRefusal::RefusesMessages,
        Some(Some(Reason::Excluded)) => PeerRefusal::Excluded,
        Some(Some(Reason::RateLimited)) => PeerRefusal::RateLimited,
        Some(Some(Reason::FeatureNotNegotiated)) => PeerRefusal::FeatureNotNegotiated,
        Some(Some(Reason::Unreachable)) => PeerRefusal::Unreachable,
        Some(Some(Reason::UnknownBan)) => PeerRefusal::UnknownBan,
        _ => PeerRefusal::Refused,
    })
}

/// The reason a refusal is answered with on the wire.
pub(crate) fn reason_of(why: PeerRefusal) -> Reason {
    match why {
        PeerRefusal::UnknownUser | PeerRefusal::NotExported => Reason::UnknownUser,
        PeerRefusal::RefusesMessages => Reason::RefusesMessages,
        PeerRefusal::Excluded => Reason::Excluded,
        PeerRefusal::RateLimited => Reason::RateLimited,
        PeerRefusal::FeatureNotNegotiated => Reason::FeatureNotNegotiated,
        PeerRefusal::Unreachable => Reason::Unreachable,
        PeerRefusal::Refused | PeerRefusal::CannotCross => Reason::RefusedFields,
        PeerRefusal::UnknownBan => Reason::UnknownBan,
    }
}

impl PeerRouter for Router {
    fn msg(&self, from: Uid, to: Uid, text: String) -> oneshot::Receiver<Result<(), PeerRefusal>> {
        let text = crate::link::link_line_endings(&text);
        self.send(
            to,
            feature::PRIVATE_MESSAGES,
            tx::PRIVATE_MESSAGE,
            |id| {
                vec![
                    Field::u16(field::USER_ID, from),
                    Field::u16(field::TARGET_ID, id),
                    Field::new(field::DATA, text.into_bytes()),
                ]
            },
            |_| Ok(()),
        )
    }

    fn kick(
        &self,
        of: Uid,
        ban: Option<GhostBan>,
        by: String,
    ) -> oneshot::Receiver<Result<(), PeerRefusal>> {
        let hub = self.0.upgrade().map(Hub);
        let me = hub.as_ref().map(Hub::server_id);
        // What this server keeps of a ban once placed, taken now: the
        // ghost may be gone by the time the answer comes.
        let record = ban.as_ref().and_then(|ban| {
            let hub = hub.as_ref()?;
            let (home, home_tag, nick) = hub.ghost_home(of)?;
            let now = std::time::SystemTime::now();
            Some((
                hub.0.core.clone(),
                NetworkBan {
                    id: 0,
                    requester: hub.server_id().0,
                    home: home.0,
                    home_tag,
                    handle: [0; 16],
                    nick,
                    reason: ban.reason.clone(),
                    actor: by,
                    created_at: now,
                    expires_at: ban.for_.and_then(|d| now.checked_add(d)),
                    lift_asked: None,
                    lifted_at: None,
                },
            ))
        });
        let ty = if ban.is_some() { tx::BAN } else { tx::KICK };
        self.send(
            of,
            0,
            ty,
            |id| {
                let mut f = vec![Field::u16(field::TARGET_ID, id)];
                if let Some(me) = me {
                    f.push(Field::new(field::REQUESTER, me.0));
                }
                if let Some(ban) = ban {
                    let secs = ban
                        .for_
                        .map_or(0, |d| d.as_secs().clamp(1, u32::MAX.into()));
                    f.push(Field::u32(field::DURATION, secs as u32));
                    if !ban.reason.is_empty() {
                        f.push(Field::new(field::DATA, ban.reason.into_bytes()));
                    }
                }
                f
            },
            move |fields| {
                let handle = find(&fields, field::BAN_ID).and_then(Field::fixed::<16>);
                if let (Some((core, ban)), Some(handle)) = (record, handle) {
                    tokio::task::spawn_blocking(move || {
                        core.record_network_ban(NetworkBan { handle, ..ban })
                    });
                }
                Ok(())
            },
        )
    }

    fn user_info(&self, of: Uid) -> oneshot::Receiver<Result<String, PeerRefusal>> {
        self.send(
            of,
            feature::USER_INFO,
            tx::USER_INFO,
            |id| vec![Field::u16(field::TARGET_ID, id)],
            |fields| {
                find(&fields, field::DATA)
                    .and_then(|d| String::from_utf8(d.data.clone()).ok())
                    .ok_or(PeerRefusal::Refused)
            },
        )
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
                show_tags: false,
                max_ghosts: 100,
                grace: std::time::Duration::from_secs(60),
                peers: vec![],
            },
            Arc::new(Core::new()),
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

    #[tokio::test(start_paused = true)]
    async fn a_request_the_peer_never_answers_is_given_up_and_forgotten() {
        let h = hub_with_peer("a");
        let (generation, _) = h.register("a");
        h.accept_server("a", generation, group(2, "two", 0), true)
            .unwrap();
        h.resume(
            "a",
            generation,
            ServerId([2; 8]),
            [1; 8],
            feature::PRIVATE_MESSAGES,
        );
        h.apply_user("a", generation, user(9, 2)).unwrap();
        let mut link = h.subscribe("a", generation).unwrap();
        let ghost = h.ghost_uid("a", generation, 9).unwrap();
        let answer = Router(Arc::downgrade(&h.0)).msg(1, ghost, "hi".into());
        let sent = link.requests.recv().await.unwrap();
        tokio::time::sleep(PEER_WAIT + std::time::Duration::from_secs(1)).await;
        assert_eq!(answer.await.unwrap(), Err(PeerRefusal::Unreachable));
        assert!(sent.reply.is_closed(), "the link may forget it");
    }

    #[test]
    fn a_reply_marked_an_error_is_a_refusal_whatever_it_carries() {
        let ok = [Field::u16(field::REASON, Reason::Ok as u16)];
        assert_eq!(refusal(false, &ok), None);
        assert_eq!(refusal(false, &[]), None);
        assert_eq!(refusal(true, &[]), Some(PeerRefusal::Refused));
        assert_eq!(refusal(true, &ok), Some(PeerRefusal::Refused));
        let busy = [Field::u16(field::REASON, Reason::RateLimited as u16)];
        assert_eq!(refusal(true, &busy), Some(PeerRefusal::RateLimited));
    }

    #[test]
    fn users_of_a_server_behind_the_peer_follow_that_servers_changes() {
        let h = hub_with_peer("a");
        let (link, _) = h.register("a");
        h.accept_server("a", link, group(2, "two", 0), true)
            .unwrap();
        h.accept_server("a", link, group(3, "three", 1), false)
            .unwrap();
        h.apply_user("a", link, user(9, 3)).unwrap();
        let ghost = h.ghost_uid("a", link, 9).unwrap();
        let tag = |h: &Hub| {
            let row = h.0.core.roster_rows().into_iter().find(|u| u.uid == ghost);
            row.and_then(|u| u.remote).map(|r| r.home_tag)
        };
        assert_eq!(tag(&h).as_deref(), Some("three"));
        h.accept_server("a", link, group(3, "drei", 1), false)
            .unwrap();
        assert_eq!(tag(&h).as_deref(), Some("drei"), "a 913 reaches it");
        h.forget_server("a", link, ServerId([3; 8]), None);
        assert_eq!(h.0.core.ghost_count(), 0, "a 914 takes it away");
    }

    #[test]
    fn only_a_server_behind_the_link_may_ask_for_moderation() {
        let h = hub_with_peer("a");
        let (link, _) = h.register("a");
        h.accept_server("a", link, group(2, "two", 0), true)
            .unwrap();
        h.accept_server("a", link, group(3, "three", 1), false)
            .unwrap();
        let asks = |id: u8| h.requester("a", link, ServerId([id; 8])).map(|r| r.tag);
        assert_eq!(asks(2).as_deref(), Some("two"), "the peer");
        assert_eq!(asks(3).as_deref(), Some("three"), "behind it");
        assert_eq!(asks(4), None, "anyone else");
        assert_eq!(asks(1), None, "this server itself");
        assert!(
            h.requester("a", link + 1, ServerId([2; 8])).is_none(),
            "a replaced link"
        );
    }

    /// A link up to its snapshot, with the peer at `epoch` showing `users`.
    fn linked(h: &Hub, epoch: u8, users: &[(u16, &str)]) -> u64 {
        let (link, _) = h.register("a");
        h.accept_server("a", link, group(2, "two", 0), true)
            .unwrap();
        h.resume("a", link, ServerId([2; 8]), [epoch; 8], 0);
        h.servers_settled("a", link);
        let groups = users.iter().map(|(id, nick)| named(*id, nick)).collect();
        h.apply_snapshot("a", link, groups);
        link
    }

    fn named(id: u16, nick: &str) -> UserGroup {
        let local = LocalUser {
            uid: id,
            nick: nick.into(),
            icon: 1,
            away: false,
            color: None,
            exclude: vec![],
        };
        UserGroup::parse(&crate::users::of_local(&local, ServerId([2; 8]))).unwrap()
    }

    fn uids(h: &Hub) -> Vec<Uid> {
        h.0.core.roster_rows().iter().map(|u| u.uid).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn an_interrupted_link_shows_nothing_and_comes_back_as_it_was() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[(9, "bob"), (10, "eve")]);
        let shown = uids(&h);
        h.unregister("a", first, true);
        assert_eq!(uids(&h), shown, "kept through the interruption");
        // Back with the same epoch: the IDs still name the same people.
        linked(&h, 1, &[(9, "bob")]);
        assert_eq!(uids(&h), shown[..1], "eve left meanwhile, bob kept his uid");
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_back_with_a_new_epoch_keeps_whom_it_still_shows() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[(9, "bob"), (10, "eve")]);
        let bob = uids(&h)[0];
        h.unregister("a", first, true);
        // Restarted: bob is now 3, eve gone, carol new.
        linked(&h, 2, &[(3, "bob"), (4, "carol")]);
        let rows = h.0.core.roster_rows();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().any(|u| u.uid == bob && u.nick == "bob"),
            "{rows:?}"
        );
        assert!(rows.iter().any(|u| u.nick == "carol"));
    }

    #[tokio::test(start_paused = true)]
    async fn an_interruption_past_the_grace_period_takes_everyone() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[(9, "bob")]);
        h.unregister("a", first, true);
        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        assert_eq!(h.0.core.ghost_count(), 0);
        // Ended for good: at once.
        let second = linked(&h, 1, &[(9, "bob")]);
        h.unregister("a", second, false);
        assert_eq!(h.0.core.ghost_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnection_that_fails_inside_the_grace_discards_nothing() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[(9, "bob")]);
        let shown = uids(&h);
        h.unregister("a", first, true);
        // Back and gone again before its snapshot: still held.
        let (second, _) = h.register("a");
        h.accept_server("a", second, group(2, "two", 0), true)
            .unwrap();
        h.resume("a", second, ServerId([2; 8]), [1; 8], 0);
        h.unregister("a", second, true);
        linked(&h, 1, &[(9, "bob")]);
        assert_eq!(uids(&h), shown);
    }

    #[tokio::test(start_paused = true)]
    async fn a_restarted_peers_unmatched_ghosts_go_if_its_snapshot_never_comes() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[(9, "bob")]);
        h.unregister("a", first, true);
        let (second, _) = h.register("a");
        h.accept_server("a", second, group(2, "two", 0), true)
            .unwrap();
        h.resume("a", second, ServerId([2; 8]), [2; 8], 0);
        h.unregister("a", second, false);
        tokio::task::yield_now().await;
        assert_eq!(h.0.core.ghost_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_held_server_is_still_its_links_to_the_loop_check() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[]);
        h.unregister("a", first, true);
        let (other, _) = h.register("b");
        assert_eq!(
            h.accept_server("b", other, group(2, "two", 0), true),
            Err(Reason::Loop)
        );
    }

    #[test]
    fn a_peer_cannot_take_away_a_server_another_link_put_there() {
        let h = hub();
        let (a, _ra) = h.register("a");
        let (b, _rb) = h.register("b");
        h.accept_server("a", a, group(2, "two", 0), true).unwrap();
        h.accept_server("b", b, group(4, "four", 0), true).unwrap();
        h.accept_server("b", b, group(5, "five", 1), false).unwrap();
        h.forget_server("a", a, ServerId([5; 8]), None);
        h.forget_server("a", a, h.server_id(), None);
        assert!(h.knows_behind("b", b, ServerId([5; 8])), "still b's");
    }

    #[tokio::test(start_paused = true)]
    async fn a_replaced_link_hands_its_ghosts_to_the_new_one() {
        let h = hub_with_peer("a");
        let first = linked(&h, 1, &[(9, "bob")]);
        let shown = uids(&h);
        let second = linked(&h, 1, &[(9, "bob")]);
        assert_eq!(uids(&h), shown);
        // The replaced link ending, late, leaves the new one's alone.
        h.unregister("a", first, false);
        assert_eq!(uids(&h), shown);
        h.unregister("a", second, false);
        assert!(uids(&h).is_empty());
    }

    #[test]
    fn a_new_link_for_a_peer_replaces_the_old_one() {
        let h = hub();
        let (first, mut closed) = h.register("a");
        let (second, _) = h.register("a");
        assert_eq!(closed.try_recv(), Ok(Reason::Replaced));
        // The replaced link ending leaves the new one alone.
        h.unregister("a", first, false);
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

    fn hub_with_peer(name: &str) -> Hub {
        let h = hub();
        h.0.config.lock().unwrap().peers.push(PeerEntry {
            name: name.into(),
            dial: None,
            key: [0; 32],
            account: "link".into(),
            features: 0,
            ghosts: 10,
        });
        h
    }

    fn user(id: u16, home: u8) -> UserGroup {
        let local = LocalUser {
            uid: id,
            nick: "bob".into(),
            icon: 1,
            away: false,
            color: None,
            exclude: vec![],
        };
        UserGroup::parse(&crate::users::of_local(&local, ServerId([home; 8]))).unwrap()
    }

    impl ServerGroup {
        fn with_id(mut self, id: ServerId) -> ServerGroup {
            self.id = id;
            self
        }
    }
}
