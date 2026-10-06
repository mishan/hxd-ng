//! One link session, the same whichever side dialed (the extension's Link
//! Lifecycle): Hello each way, this server's Link Servers and the peer's,
//! then the snapshots, then pings and whatever the peer sends.
//!
//! Users cross both ways (stage L2 of `docs/server-link.md`): this
//! server's own, from the core's export feed, and the peer's, shown here as
//! ghosts. Chat does not yet (L3), and this server relays nothing, so its
//! server list is empty.

use std::time::Duration;

use hxd_session::frame::Frame;
use hxd_session::peer::LinkIo;
use tokio::sync::oneshot;
use tokio::time::{interval, sleep_until, Instant, MissedTickBehavior};
use tracing::{debug, info, warn};

use hxd_core::server_link::{GoneReason, PeerEvent};

use crate::hub::{Hub, PeerEntry};
use crate::server::{ServerGroup, ServerId};
use crate::users::{of_local, UserGroup};
use crate::wire::{chunks, field, fields, find, tx, Field, Hello, Reason};

/// The most a snapshot part this server sends carries, well below the
/// frame limit either end reads with.
const SNAPSHOT_PART: usize = 32 * 1024;

/// How long a peer has for each step of establishment: its Hello after
/// the login reply, then its whole Link Servers. Pings do not extend it.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
/// A Ping after this long without sending anything else.
pub(crate) const PING_AFTER: Duration = Duration::from_secs(60);
/// A link is dead after three ping intervals without hearing from it.
const DEAD_AFTER: Duration = Duration::from_secs(180);
/// The most servers one link may put behind it. The extension leaves the
/// bound to each receiver, which must not rely on the sender's.
const MAX_SERVERS: usize = 256;

/// How a link ended: why, for the logs and metrics; the reason the peer
/// gave if it closed the link itself; and whether it was ever established,
/// which with that reason decides how soon a dialer tries again.
pub(crate) struct End {
    pub(crate) label: &'static str,
    pub(crate) peer_reason: Option<Reason>,
    pub(crate) established: bool,
    /// How long it was established for, zero if never.
    pub(crate) lasted: Duration,
}

/// What interrupted establishment.
enum Stop {
    Frame(Frame),
    End(End),
}

pub(crate) async fn run(hub: Hub, entry: PeerEntry, mut io: LinkIo) -> End {
    let (generation, mut closed) = hub.register(&entry.name);
    let mut link = Link {
        hub: &hub,
        entry: &entry,
        generation,
        last_sent: Instant::now(),
        next_trans: 1,
        established: None,
        snapshot: None,
    };
    // A reload between the login and here found no link to close: the
    // entry this link was authorized under must still be the one in force.
    let end = if hub.authorizes(&entry) {
        link.session(&mut io, &mut closed).await
    } else if hub.entry(&entry.name).is_some() {
        // Changed, not removed: as a reload would have closed it.
        link.close(&io, Reason::ProtocolError, "changed")
    } else {
        link.close(&io, Reason::Unlinked, "unlinked")
    };
    hub.unregister(&entry.name, generation);
    info!(peer = %entry.name, reason = end.label, "link ended");
    end
}

struct Link<'a> {
    hub: &'a Hub,
    entry: &'a PeerEntry,
    generation: u64,
    last_sent: Instant,
    next_trans: u32,
    /// When the link was established, once it is.
    established: Option<Instant>,
    /// The peer's snapshot while its parts arrive: nothing else about its
    /// users may come between them.
    snapshot: Option<Vec<UserGroup>>,
}

impl Link<'_> {
    fn end(&self, label: &'static str, peer_reason: Option<Reason>) -> End {
        End {
            label,
            peer_reason,
            established: self.established.is_some(),
            lasted: self.established.map_or(Duration::ZERO, |at| at.elapsed()),
        }
    }

    fn notify(&mut self, io: &LinkIo, ty: u32, f: &[Field]) {
        io.out.notify(ty, chunks(f));
        self.last_sent = Instant::now();
    }

    fn close(&mut self, io: &LinkIo, reason: Reason, label: &'static str) -> End {
        self.notify(io, tx::CLOSE, &[Field::u16(field::REASON, reason as u16)]);
        self.end(label, None)
    }

    /// The next transaction during establishment, answering pings, ending
    /// on the peer's Close, a reload or replacement here, or the deadline.
    async fn establishing(
        &mut self,
        io: &mut LinkIo,
        closed: &mut oneshot::Receiver<Reason>,
        deadline: Instant,
    ) -> Stop {
        loop {
            let f = tokio::select! {
                biased;
                reason = &mut *closed => {
                    return Stop::End(self.close(io, reason.unwrap_or(Reason::Shutdown), "closed_here"));
                }
                () = sleep_until(deadline) => {
                    return Stop::End(self.close(io, Reason::ProtocolError, "establish_timeout"));
                }
                f = io.frames.recv() => match f {
                    Some(f) => f,
                    None => return Stop::End(self.end("eof", None)),
                },
            };
            if is_reply(&f) {
                continue;
            }
            match f.ty {
                tx::PING => io.out.reply(f.trans, false, vec![]),
                tx::CLOSE => return Stop::End(self.peer_closed(&f)),
                _ => return Stop::Frame(f),
            }
        }
    }

    fn peer_closed(&self, f: &Frame) -> End {
        let reason = find(&fields(f), field::REASON)
            .and_then(Field::uint)
            .and_then(|v| u16::try_from(v).ok())
            .and_then(Reason::from_wire);
        info!(peer = %self.entry.name, ?reason, "peer closed the link");
        self.end("closed_by_peer", reason)
    }

    async fn session(&mut self, io: &mut LinkIo, closed: &mut oneshot::Receiver<Reason>) -> End {
        let features = self.entry.features & crate::hub::SUPPORTED;
        let hello = self.hub.hello(features);
        self.notify(io, tx::HELLO, &hello.to_fields());

        let f = match self
            .establishing(io, closed, Instant::now() + STEP_TIMEOUT)
            .await
        {
            Stop::Frame(f) => f,
            Stop::End(end) => return end,
        };
        if f.ty != tx::HELLO {
            warn!(peer = %self.entry.name, ty = f.ty, "link transaction before Hello");
            return self.close(io, Reason::ProtocolError, "protocol_error");
        }
        let peer = match Hello::parse(&fields(&f)) {
            Ok(h) => h,
            Err(e) => {
                warn!(peer = %self.entry.name, "unreadable Hello: {e:?}");
                return self.close(io, Reason::ProtocolError, "protocol_error");
            }
        };
        if peer.version == 0 {
            return self.close(io, Reason::VersionUnsupported, "version");
        }
        if let Err(why) = peer.server.admissible() {
            warn!(peer = %self.entry.name, "Hello's server group refused: {why}");
            return self.close(io, Reason::ProtocolError, "protocol_error");
        }
        if peer.server.id != ServerId::of_key(&self.entry.key) {
            warn!(peer = %self.entry.name, "Hello names a server other than the key it proved");
            return self.close(io, Reason::ProtocolError, "protocol_error");
        }
        if let Err(reason) =
            self.hub
                .accept_server(&self.entry.name, self.generation, peer.server.clone(), true)
        {
            warn!(peer = %self.entry.name, ?reason, "peer refused at Hello");
            return self.close(io, reason, "refused");
        }

        self.hub
            .set_features(&self.entry.name, self.generation, features & peer.features);

        // Nothing to relay yet, so this server's list is empty.
        self.notify(io, tx::SERVERS, &[]);
        if let Err(end) = self.receive_servers(io, closed).await {
            return end;
        }
        let Some((since, users, mut exports)) =
            self.hub.subscribe(&self.entry.name, self.generation)
        else {
            return self.end("replaced", None);
        };
        let own = self.hub.server_id();
        let groups: Vec<Vec<Field>> = users.iter().map(|u| of_local(u, own)).collect();
        self.send_snapshot(io, groups);
        self.established = Some(Instant::now());
        info!(peer = %self.entry.name, server = ?peer.server.id, tag = %peer.server.tag, "link up");

        let mut tick = interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_heard = Instant::now();
        loop {
            tokio::select! {
                biased;
                reason = &mut *closed => {
                    let reason = reason.unwrap_or(Reason::Shutdown);
                    return self.close(io, reason, "closed_here");
                }
                // Named as a client that stops reading is, so the writer
                // is stopped at once rather than flushed for a while.
                () = io.out.lagged() => return self.end("slow_consumer", None),
                export = exports.recv() => match export {
                    Some((n, event)) if n > since => self.export(io, own, event),
                    Some(_) => {}
                    // The hub dropped this link's channel: it fell behind.
                    None => return self.close(io, Reason::Shutdown, "slow_consumer"),
                },
                f = io.frames.recv() => {
                    let Some(f) = f else { return self.end("eof", None) };
                    last_heard = Instant::now();
                    if let Some(end) = self.handle(io, f) {
                        return end;
                    }
                }
                _ = tick.tick() => {
                    if last_heard.elapsed() >= DEAD_AFTER {
                        return self.end("dead", None);
                    }
                    if self.last_sent.elapsed() >= PING_AFTER {
                        let trans = self.next_trans;
                        self.next_trans = self.next_trans.wrapping_add(1).max(1);
                        io.out.request(tx::PING, trans, vec![]);
                        self.last_sent = Instant::now();
                    }
                }
            }
        }
    }

    /// The peer's Link Servers, every part of it, each group checked.
    async fn receive_servers(
        &mut self,
        io: &mut LinkIo,
        closed: &mut oneshot::Receiver<Reason>,
    ) -> Result<(), End> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        loop {
            let f = match self.establishing(io, closed, deadline).await {
                Stop::Frame(f) => f,
                Stop::End(end) => return Err(end),
            };
            if f.ty != tx::SERVERS {
                warn!(peer = %self.entry.name, ty = f.ty, "expected Link Servers");
                return Err(self.close(io, Reason::ProtocolError, "protocol_error"));
            }
            let fs = fields(&f);
            let groups = match ServerGroup::parse_all(&fs) {
                Ok(g) => g,
                Err(e) => {
                    warn!(peer = %self.entry.name, "unreadable Link Servers: {e:?}");
                    return Err(self.close(io, Reason::ProtocolError, "protocol_error"));
                }
            };
            for g in groups {
                if let Some(end) = self.take_server(io, g, true) {
                    return Err(end);
                }
            }
            if find(&fs, field::MORE).and_then(Field::uint) != Some(1) {
                return Ok(());
            }
        }
    }

    /// Accept one server group from the peer, or end the link. At
    /// establishment every refusal ends it; afterwards only a loop does,
    /// and the rest are ignored, as the extension says.
    fn take_server(&mut self, io: &LinkIo, g: ServerGroup, establishing: bool) -> Option<End> {
        if let Err(why) = g.admissible() {
            // Relaying Fields: a group the bounds or the fields that never
            // cross refuse is dropped whole.
            warn!(peer = %self.entry.name, server = ?g.id, "server group dropped: {why}");
            return None;
        }
        if self.hub.servers_behind(&self.entry.name, self.generation) >= MAX_SERVERS
            && !self
                .hub
                .knows_behind(&self.entry.name, self.generation, g.id)
        {
            warn!(peer = %self.entry.name, "more servers than a link may put behind it");
            return Some(self.close(io, Reason::ProtocolError, "too_many_servers"));
        }
        match self
            .hub
            .accept_server(&self.entry.name, self.generation, g, false)
        {
            Ok(()) => None,
            Err(reason) if establishing || reason == Reason::Loop => {
                warn!(peer = %self.entry.name, ?reason, "peer's server refused");
                Some(self.close(io, reason, "refused"))
            }
            Err(reason) => {
                warn!(peer = %self.entry.name, ?reason, "server update ignored");
                None
            }
        }
    }

    /// This server's users, as the snapshot it owes the peer: in parts
    /// marked `DATA_LINK_MORE` but the last, one part if there is nobody.
    fn send_snapshot(&mut self, io: &LinkIo, groups: Vec<Vec<Field>>) {
        let mut part: Vec<Field> = Vec::new();
        let mut size = 0;
        for g in groups {
            let len: usize = g.iter().map(|f| 4 + f.data.len()).sum();
            if size + len > SNAPSHOT_PART && !part.is_empty() {
                part.push(Field::u16(field::MORE, 1));
                self.notify(io, tx::SNAPSHOT, &std::mem::take(&mut part));
                size = 0;
            }
            size += len;
            part.extend(g);
        }
        self.notify(io, tx::SNAPSHOT, &part);
    }

    /// One change to a local user, as the peer must hear it.
    fn export(&mut self, io: &LinkIo, own: ServerId, event: PeerEvent) {
        match event {
            PeerEvent::Shown(u) | PeerEvent::Changed(u) => {
                self.notify(io, tx::USER_UPDATE, &of_local(&u, own));
            }
            PeerEvent::Gone(uid, GoneReason::Disconnected) => self.notify(
                io,
                tx::USER_GONE,
                &[
                    Field::u16(field::USER_ID, uid),
                    Field::u16(field::REASON, Reason::Disconnected as u16),
                ],
            ),
        }
    }

    /// One part of the peer's snapshot. Nothing is shown until the last
    /// part, so the snapshot is applied as one.
    fn snapshot_part(&mut self, f: &Frame) {
        let fs = fields(f);
        let pending = self.snapshot.get_or_insert_with(Vec::new);
        for g in UserGroup::parse_all(&fs) {
            match g {
                // Held to the link's ghost bound, so a peer that never
                // sends its last part costs no more than it could show.
                Ok(_) if pending.len() >= self.entry.ghosts => {}
                Ok(g) => pending.push(g),
                Err(e) => warn!(peer = %self.entry.name, "user in snapshot dropped: {e:?}"),
            }
        }
        if find(&fs, field::MORE).and_then(Field::uint) != Some(1) {
            let groups = self.snapshot.take().unwrap_or_default();
            self.hub
                .apply_snapshot(&self.entry.name, self.generation, groups);
        }
    }

    /// One transaction once the link is established. `Some` ends the link.
    fn handle(&mut self, io: &LinkIo, f: Frame) -> Option<End> {
        if is_reply(&f) {
            // Only pings are sent so far, and their replies say nothing.
            return None;
        }
        match f.ty {
            tx::PING => io.out.reply(f.trans, false, vec![]),
            tx::CLOSE => return Some(self.peer_closed(&f)),
            tx::SERVER_UPDATE => match ServerGroup::parse(&fields(&f)) {
                Ok(g) => return self.take_server(io, g, false),
                Err(e) => {
                    warn!(peer = %self.entry.name, "unreadable server update: {e:?}");
                    return Some(self.close(io, Reason::ProtocolError, "protocol_error"));
                }
            },
            tx::SERVER_GONE => {
                if let Some(id) = find(&fields(&f), field::SERVER_ID).and_then(Field::fixed) {
                    self.hub
                        .forget_server(&self.entry.name, self.generation, ServerId(id));
                }
            }
            tx::SNAPSHOT => self.snapshot_part(&f),
            tx::USER_UPDATE | tx::USER_GONE if self.snapshot.is_some() => {
                warn!(peer = %self.entry.name, "user transaction between snapshot parts dropped");
            }
            tx::USER_UPDATE => match UserGroup::parse(&fields(&f)) {
                Ok(g) => {
                    if let Err(why) = self.hub.apply_user(&self.entry.name, self.generation, g) {
                        warn!(peer = %self.entry.name, "user update dropped: {why}");
                    }
                }
                // Over a bound, or carrying what never crosses: dropped
                // whole, as Relaying Fields says.
                Err(e @ crate::users::UserGroupError::Inadmissible(_)) => {
                    warn!(peer = %self.entry.name, "user update dropped: {e:?}")
                }
                // State this server can no longer trust.
                Err(e) => {
                    warn!(peer = %self.entry.name, "unreadable user update: {e:?}");
                    return Some(self.close(io, Reason::ProtocolError, "protocol_error"));
                }
            },
            tx::USER_GONE => {
                if let Some(id) = find(&fields(&f), field::USER_ID).and_then(Field::fixed) {
                    self.hub
                        .user_gone(&self.entry.name, self.generation, u16::from_be_bytes(id));
                }
            }
            // Chat arrives in L3.
            tx::CHAT => {}
            tx::PRIVATE_MESSAGE | tx::USER_INFO => refuse(io, &f, Reason::FeatureNotNegotiated),
            // This server carries out no moderation for a peer yet (L5):
            // refused, never pretended.
            tx::KICK | tx::BAN | tx::UNBAN => refuse(io, &f, Reason::FeatureNotNegotiated),
            // Link Session Restrictions: a request the link does not
            // define is refused with an error, never silently processed.
            other if f.trans != 0 => {
                debug!(peer = %self.entry.name, ty = other, "request a link does not define refused");
                io.out.reply(f.trans, true, vec![]);
            }
            other => debug!(peer = %self.entry.name, ty = other, "unknown notification dropped"),
        }
        None
    }
}

/// The reply flag sits in the type word's second byte.
fn is_reply(f: &Frame) -> bool {
    (f.ty >> 16) & 0xff == 1
}

fn refuse(io: &LinkIo, f: &Frame, reason: Reason) {
    // A notification has no task to answer.
    if f.trans == 0 {
        return;
    }
    io.out.reply(
        f.trans,
        true,
        vec![(field::REASON, (reason as u16).to_be_bytes().to_vec())],
    );
}
