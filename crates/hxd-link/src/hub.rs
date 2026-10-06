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

use hxd_core::roster::Uid;
use hxd_core::server_link::{
    GhostInfo, GhostLine, LocalUser, PeerEvent, PeerRefusal, PeerRouter, RemoteRef, PEER_WAIT,
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
pub const SUPPORTED: u32 = feature::PUBLIC_CHAT | feature::PRIVATE_MESSAGES | feature::USER_INFO;

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
    features: u32,
    /// Where the export feed reaches this link, once it is established.
    exports: Option<mpsc::Sender<Export>>,
    /// Requests this server sends the peer, once the link is established.
    requests: Option<mpsc::Sender<Request>>,
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
        let old = state.links.insert(
            peer.to_owned(),
            Live {
                generation,
                close: Some(tx),
                peer: None,
                servers: HashMap::new(),
                features: 0,
                exports: None,
                ghosts: HashMap::new(),
                requests: None,
            },
        );
        drop(state);
        if let Some(mut old) = old {
            if let Some(close) = old.close.take() {
                let _ = close.send(Reason::Replaced);
            }
            // Its late frames can no longer touch the new link, and its
            // own ending finds a newer generation; its ghosts go now.
            self.part(old.ghosts.into_values());
        }
        (generation, rx)
    }

    /// Ghosts leave, after the hub's lock is released: each is a broadcast
    /// to every local session, and the feed waits on that lock.
    fn part(&self, slots: impl IntoIterator<Item = Slot>) {
        for slot in slots {
            self.0.core.ghost_part(slot.uid);
        }
    }

    /// The link has ended: everyone shown over it leaves.
    pub(crate) fn unregister(&self, peer: &str, generation: u64) {
        let mut state = self.0.state.lock().unwrap();
        if !state
            .links
            .get(peer)
            .is_some_and(|l| l.generation == generation)
        {
            return;
        }
        let gone = state.links.remove(peer);
        drop(state);
        if let Some(live) = gone {
            self.part(live.ghosts.into_values());
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
        let live = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
            .ok_or(Reason::Replaced)?;
        let id = group.id;
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
        drop(state);
        for (uid, info) in refreshed {
            self.0.core.ghost_update(uid, info);
        }
        Ok(())
    }

    /// A server is no longer reachable over the link: it goes, and every
    /// user homed there with it.
    pub(crate) fn forget_server(&self, peer: &str, generation: u64, id: ServerId) {
        let mut state = self.0.state.lock().unwrap();
        if let Some(live) = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
        {
            live.servers.remove(&id);
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
            drop(state);
            self.part(gone);
        }
    }

    pub(crate) fn set_features(&self, peer: &str, generation: u64, features: u32) {
        let mut state = self.0.state.lock().unwrap();
        if let Some(live) = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
        {
            live.features = features;
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
        Some(Subscribed {
            since,
            users,
            exports,
            requests,
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
        let (live, id) = state
            .links
            .values()
            .find_map(|l| {
                l.ghosts
                    .iter()
                    .find(|(_, slot)| slot.uid == uid)
                    .map(|(id, _)| (l, *id))
            })
            .ok_or(PeerRefusal::UnknownUser)?;
        if live.features & feature == 0 {
            return Err(PeerRefusal::FeatureNotNegotiated);
        }
        let (reply, answer) = oneshot::channel();
        let request = Request {
            ty,
            fields: build(id),
            reply,
        };
        match live.requests.as_ref().map(|r| r.try_send(request)) {
            Some(Ok(())) => Ok(answer),
            Some(Err(mpsc::error::TrySendError::Full(_))) => Err(PeerRefusal::RateLimited),
            _ => Err(PeerRefusal::Unreachable),
        }
    }

    /// Hand one export to every established link. A link too far behind
    /// to take it is closed and starts over from a snapshot.
    fn fan_out(&self, export: Export) {
        let mut state = self.0.state.lock().unwrap();
        for live in state.links.values_mut() {
            let Some(tx) = &live.exports else { continue };
            if tx.try_send(export.clone()).is_err() {
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
        if let Some(slot) = live.ghosts.get_mut(&g.id) {
            slot.group = g;
            self.0.core.ghost_update(slot.uid, info);
            return Ok(());
        }
        if live.ghosts.len() >= limit || self.0.core.ghost_count() >= max_ghosts {
            return Err("ghost bound reached");
        }
        let uid = self
            .0
            .core
            .ghost_attach(info)
            .ok_or("no uid to give a ghost")?;
        live.ghosts.insert(g.id, Slot { uid, group: g });
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
    ) -> Result<(), &'static str> {
        let uid = self
            .ghost_uid(peer, generation, id)
            .ok_or("no such user on this link")?;
        let Some(line) = self.0.core.ghost_line(uid, text, style) else {
            return Ok(());
        };
        self.0.chat.try_send(line).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => "too many lines waiting to be logged",
            mpsc::error::TrySendError::Closed(_) => "the task logging lines has ended",
        })
    }

    pub(crate) fn core(&self) -> &Core {
        &self.0.core
    }

    pub(crate) fn epoch(&self) -> [u8; 8] {
        self.0.epoch
    }

    pub(crate) fn user_gone(&self, peer: &str, generation: u64, id: u16) {
        let mut state = self.0.state.lock().unwrap();
        if let Some(live) = state
            .links
            .get_mut(peer)
            .filter(|l| l.generation == generation)
        {
            let gone = live.ghosts.remove(&id);
            drop(state);
            self.part(gone);
        }
    }

    /// A whole snapshot: everyone in it shown, everyone shown before and
    /// not in it gone.
    pub(crate) fn apply_snapshot(&self, peer: &str, generation: u64, groups: Vec<UserGroup>) {
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
            self.user_gone(peer, generation, id);
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

/// What a link hands its session loop when it is established.
pub(crate) struct Subscribed {
    /// The feed's number at the snapshot: events up to it are in `users`.
    pub(crate) since: u64,
    pub(crate) users: Vec<LocalUser>,
    pub(crate) exports: mpsc::Receiver<Export>,
    pub(crate) requests: mpsc::Receiver<Request>,
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
        h.set_features("a", generation, feature::PRIVATE_MESSAGES);
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
    fn a_replaced_link_takes_its_ghosts_with_it() {
        let h = hub_with_peer("a");
        let (first, _) = h.register("a");
        h.accept_server("a", first, group(2, "two", 0), true)
            .unwrap();
        h.apply_user("a", first, user(9, 2)).unwrap();
        assert_eq!(h.0.core.ghost_count(), 1);
        let (second, _) = h.register("a");
        assert_eq!(h.0.core.ghost_count(), 0);
        // The replaced link ending, late, leaves the new one's alone.
        h.accept_server("a", second, group(2, "two", 0), true)
            .unwrap();
        h.apply_user("a", second, user(9, 2)).unwrap();
        h.unregister("a", first);
        assert_eq!(h.0.core.ghost_count(), 1);
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
