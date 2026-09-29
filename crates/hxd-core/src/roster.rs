//! The presence roster: who is on the server, and the event fan-out.
//!
//! **Presence is user-scoped, not connection-scoped** (a roadmap
//! commitment). A [`UserSession`] is a user's presence on the server; a
//! transport attaches to it. The legacy frontend keeps the degenerate
//! mapping — its connection's death calls [`Core::end_session`] — while the
//! Hotline-ng frontend calls [`Core::connection_lost`], which (permission
//! and caps allowing) parks the session `Detached` and buffers its events
//! for a later [`Core::resume`].
//!
//! **The outbox.** Every event a session should see is stamped with a
//! per-session monotonic sequence number. With a connection attached the
//! event goes straight out on a channel; detached, it buffers (bounded —
//! overflow marks the buffer broken and a resume then requires a fresh
//! sync). See `docs/hotline-ng.md` §3 and §6, and
//! `docs/hotline-ng-rationale.md` §4/D3.
//!
//! **The domain is UTF-8.** Nicks, chat text, subjects — everything textual
//! is a `String`. The legacy frontend converts Mac Roman ↔ UTF-8 at its
//! edges (lossless for legacy-origin text: Mac Roman → UTF-8 is injective
//! and round-trips exactly); the ng frontend is UTF-8 natively. The domain
//! also carries no wire presentation: `admin` is a bool and status an enum —
//! the legacy color bitfield (bit 1 away, bit 2 admin) is derived at the
//! legacy edge.
//!
//! Chat rooms, messaging and moderation live in [`crate::chat`], as further
//! `impl Core` blocks over the same state.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::mpsc::{self, error::TrySendError};

use crate::access::{bit, AccessBits};
use crate::chat::PrivateChat;
use crate::instrument::{self, TimedMutex};

/// A user id, as seen on the wire (16-bit, never 0 for a real user).
pub type Uid = u16;

/// How many events a detached session's outbox holds before it gives up
/// and demands a resync.
pub const OUTBOX_BUFFER_CAP: usize = 512;

/// How many events an attached session's channel holds before its client
/// is judged not to be keeping up.
///
/// **A client that will not drain is disconnected, not buffered for.**
/// Before this bound a connection that stopped reading made the server
/// hold every event addressed to it, for as long as the socket stayed
/// open, and one such client was enough to grow the server without
/// limit. The frontends drain this channel as fast as they can write:
/// the classic one into its writer's queue, which has a bound of its
/// own, and the ng one straight to the socket. So what fills it is a
/// client whose socket has stopped taking bytes, and at this size that
/// is seconds of the busiest room's traffic, not a slow link's
/// ordinary backlog.
pub const LIVE_QUEUE_CAP: usize = 8192;

/// And how many bytes, near enough ([`Event::weight`]). The event count
/// alone would let one stalled connection hold 8192 chat lines of 4 KB
/// each; this keeps what any one client can cost the server to a figure
/// that does not depend on what the room is saying. A classic writer's
/// queue has a byte bound of its own (4 MiB); this one is the larger
/// because an ng client is sent JSON.
pub const LIVE_QUEUE_BYTES: usize = 16 << 20;

/// A session's event stream, as the one connection attached to it reads
/// it: the channel, and the connection's own signal that the domain has
/// cut it off for falling behind.
///
/// **The signal is the connection's, not the session's.** A session
/// outlives its connections — a resume attaches a new one and the old one
/// drains what it was sent and ends — so "is this session lagging?" can be
/// the new connection's news reaching the old one. Each attach and resume
/// makes a fresh `Events`, and every question a frontend asks about its
/// own connection ([`Events::lagged`], [`Core::connection_lost_from`])
/// goes through it.
pub struct Events {
    rx: mpsc::Receiver<SeqEvent>,
    conn: Arc<ConnState>,
}

/// What one connection shares with its session's sink.
pub(crate) struct ConnState {
    lagged: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    /// What the queued events weigh ([`Event::weight`]), drawn on the
    /// server's budget ([`crate::budget`]): taken when one is sent, given
    /// back when the frontend receives it.
    share: crate::budget::Share,
}

impl ConnState {
    fn lag(&self) {
        self.lagged
            .store(true, std::sync::atomic::Ordering::Release);
        // A stored permit: the frontend may not be waiting right now.
        self.notify.notify_one();
    }
}

impl Events {
    fn channel(
        budget: &Arc<crate::budget::QueueBudget>,
    ) -> (mpsc::Sender<SeqEvent>, Arc<ConnState>, Events) {
        let (tx, rx) = mpsc::channel(LIVE_QUEUE_CAP);
        let conn = Arc::new(ConnState {
            lagged: Default::default(),
            notify: Default::default(),
            share: budget.share(),
        });
        (tx, conn.clone(), Events { rx, conn })
    }

    /// The next event; `None` once the stream has ended — this connection
    /// was taken over, or cut off ([`Events::lagged`] says which).
    pub async fn recv(&mut self) -> Option<SeqEvent> {
        let se = self.rx.recv().await?;
        self.took(&se);
        Some(se)
    }

    pub fn try_recv(&mut self) -> Result<SeqEvent, mpsc::error::TryRecvError> {
        let se = self.rx.try_recv()?;
        self.took(&se);
        Ok(se)
    }

    fn took(&self, se: &SeqEvent) {
        self.conn.share.give(se.event.weight());
    }

    /// Events waiting.
    pub fn len(&self) -> usize {
        self.rx.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }

    /// Did the domain cut this connection off for falling
    /// [`LIVE_QUEUE_CAP`] events behind?
    pub fn lagged(&self) -> bool {
        self.conn.lagged.load(std::sync::atomic::Ordering::Acquire)
    }

    /// This connection's lag signal, apart from the channel, for a
    /// `select!` that also receives from it.
    pub fn lag(&self) -> Lag {
        Lag(self.conn.clone())
    }
}

/// One connection's signal that the domain has cut it off for falling
/// behind ([`Events::lag`]).
#[derive(Clone)]
pub struct Lag(Arc<ConnState>);

impl Lag {
    /// Resolves once the connection has been cut off. Cancel-safe, and
    /// meant for a `select!` beside whatever the connection is blocked on
    /// — a send to a client that is not reading, most of all — so that the
    /// cut takes effect at once rather than after the events already
    /// queued have been pushed at it.
    pub async fn wait(&self) {
        loop {
            // Registered before the check, so a lag between the two is not
            // missed.
            let notified = self.0.notify.notified();
            if self.0.lagged.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// A session's presence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionStatus {
    /// A connection is attached.
    #[default]
    Active,
    /// Attached but quiet / away.
    Idle,
    /// No connection attached; grace window running.
    Detached,
}

/// What the session layer knows about the connection carrying a session,
/// as far as other users are entitled to see it (`docs/hotline-ng-auth.md`
/// §7.2, §8). Purely descriptive: the domain never acts on it, it only
/// carries it to the roster so frontends can mark sessions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transport {
    /// The link to this session's client is encrypted end to end
    /// (TLS WebSocket, or a tunnelled legacy client). A plain TCP legacy
    /// session is not, and other users get warned before PMing it.
    pub encrypted: bool,
    /// The transport identity, when the connection was authenticated
    /// with one. Never inferred — set only by a frontend that verified it.
    pub identity: Option<IdentityTag>,
    /// This link can carry an inline-media reference
    /// (`docs/inline-media.md` §5.2).
    ///
    /// The one thing the domain learns about what a session negotiated,
    /// and it exists because the authorization set has to be captured
    /// during fan-out, which happens here. The legacy frontend sets it
    /// from capability bit 3; the ng frontend sets it true, because an
    /// ng client is told what it may ignore rather than asked what it
    /// supports. Everything else about per-recipient capability stays in
    /// the frontends, where each connection's encoder already lives.
    pub inline_media: bool,
    /// This link can blank a chat line it already rendered, so a
    /// redaction is worth telling it about.
    ///
    /// A classic client cannot: nothing on its wire takes a line back, so
    /// the classic frontend drops the event unread. Sending it anyway
    /// costs a slot in the session's bounded channel per line, and a
    /// purge of thousands of lines is thousands of slots at once — enough
    /// to cut a period client off over events it would never show. The
    /// ng frontend sets it; nothing else does.
    pub redactions: bool,
}

/// The public part of a transport identity: enough for a roster row and
/// for a reserved-name check, nothing that could authorize anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityTag {
    /// SHA-256 of the identity public key.
    pub fingerprint: [u8; 32],
    /// SHA-256 of the device key the socket authenticated with: what a
    /// device revocation names (`crate::revoked`). Not shown to anyone.
    pub device: [u8; 32],
    /// `handle@registrar`, when an attestation was accepted.
    pub handle: Option<String>,
}

/// The visible-to-others part of a session: what a user-list row shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub uid: Uid,
    pub transport: Transport,
    /// Nickname, UTF-8.
    pub nick: String,
    pub icon: u16,
    /// Administrator affordance (the legacy edge renders it as color
    /// bit 2).
    pub admin: bool,
    /// The reserved server account (`docs/system-account.md` §2). A
    /// client may draw it differently; a legacy one sees an admin, which
    /// is the closest that wire has to "not a person".
    pub system: bool,
    pub status: SessionStatus,
    /// The picture shown in place of the icon by a client that can show
    /// one (`docs/avatars.md`). The icon is still what the rest see.
    pub avatar: Option<crate::avatar::AvatarRef>,
}

/// The fuller view one session may request of another (the user-info op).
#[derive(Debug, Clone)]
pub struct UserDetails {
    pub info: UserInfo,
    pub login: String,
    pub addr: Option<IpAddr>,
    pub connected_at: Instant,
}

/// A domain event, delivered on session channels. The session layer encodes
/// these to wire pushes; a future frontend encodes them differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A session became visible. Not delivered to the joiner itself.
    Joined(UserInfo),
    /// A visible session changed nick/icon/status. Delivered to everyone,
    /// including the changer (matching the reference server, whose clients
    /// rely on the echo).
    Changed(UserInfo),
    /// A visible session left. Not delivered to the leaver.
    Parted(Uid),
    /// A visible session's avatar was set, replaced or cleared. Delivered
    /// to everyone, the changer included. Its own event rather than a
    /// [`Event::Changed`], because the legacy wire says it with a
    /// transaction of its own (GIF Icons' Icon Change) and nothing about
    /// the user-list row changed.
    AvatarChanged(UserInfo),
    /// A chat line (semantic: unformatted). `cid` 0 is the public chat.
    /// `style` 1 is an action (`/me`). Delivered to the sender too.
    Chat {
        cid: u32,
        from: UserInfo,
        text: String,
        style: u16,
        /// The durable public-log row. Private chats and servers with no
        /// history configured carry `None`.
        id: Option<crate::history::LineId>,
        /// Server receive time. Unlike `id`, every chat event has one so
        /// the ng wire can render live timestamps without enabling history.
        at: SystemTime,
        /// The image this line carried, canonical metadata and all
        /// (`docs/inline-media.md` §7.4). Each frontend emits the
        /// reference to the connections that negotiated the capability
        /// and strips it for the rest, which is where per-recipient
        /// capability already lives.
        media: Option<crate::media::MediaRef>,
    },
    /// A server notice into a chat (kick announcements and the like).
    /// Semantic text; each frontend formats it (legacy: `\r<text>`).
    Notice {
        cid: u32,
        from: Uid,
        text: String,
        /// Said in the action form (legacy: `\r *** text`) rather than
        /// as a notice: mhxd's own chat-spamming notice is, and the
        /// classic wire says it byte for byte. The ng wire does not
        /// tell the two apart.
        action: bool,
    },
    /// A chat (or, for cid 0, server) subject change.
    ChatSubject {
        cid: u32,
        subject: String,
    },
    /// A private chat's password change, announced to its members
    /// (reference-server behavior).
    ChatPassword {
        cid: u32,
        password: String,
    },
    /// An invitation to a private chat.
    ChatInvite {
        cid: u32,
        from: Uid,
        from_nick: String,
    },
    /// Someone joined a private chat the recipient is in.
    ChatUserJoined {
        cid: u32,
        user: UserInfo,
    },
    /// Someone left a private chat the recipient is in.
    ChatUserParted {
        cid: u32,
        uid: Uid,
    },
    /// A private message to the recipient.
    ///
    /// A message out of the inbox ([`crate::inbox`]) carries `queued`,
    /// and its `from` uid is resolved **at delivery time by login**: the
    /// sending session is long gone and its uid may now belong to someone
    /// else, so it is that account's current session's uid if it has one
    /// and `0` if it does not. `from_login` carries the identity either
    /// way; a uid never does.
    Msg {
        from: Uid,
        from_nick: String,
        /// The sender's account, when the sender is someone the recipient
        /// could reply to by name. `None` for a guest — `guest` is a
        /// login several people share, not an address.
        from_login: Option<String>,
        text: String,
        /// The inbox row this came from, and the handle a client marks
        /// read. `None` when nothing was stored (the recipient has no
        /// inbox, or the server has none configured).
        id: Option<crate::inbox::MessageId>,
        /// When the sender sent it — not when it arrived.
        sent_at: std::time::SystemTime,
        /// It waited in the inbox rather than arriving in the moment.
        /// Frontends key their presentation on this and not on comparing
        /// `sent_at` against a threshold, because a threshold is a bug
        /// waiting for a slow network.
        queued: bool,
        /// The image that came with it. A message read within the
        /// handle's life carries one with an `id` the recipient can
        /// fetch; one read after it carries the metadata alone, and the
        /// client renders the placeholder (`docs/inline-media.md` §9).
        media: Option<crate::media::MediaRef>,
    },
    /// An administrator broadcast. Delivered to everyone, sender included
    /// (the wire push carries the sender, matching the reference server).
    Broadcast {
        from: Uid,
        from_nick: String,
        text: String,
    },
    /// The recipient has been kicked; its transport should close.
    Kicked,
    /// A public line was redacted (`docs/moderation.md` §3.1). Delivered
    /// to every session that reads public chat; a client that rendered
    /// the line blanks it in place, and one that has not never sees it
    /// as anything but the tombstone history returns.
    ChatRedacted {
        id: crate::history::LineId,
    },
    /// Many public lines blanked at once, by a purge: one event where
    /// [`Event::ChatRedacted`] would be one per line (`docs/moderation.md`
    /// §5). At most [`crate::moderation::PURGE_EVENT_IDS`] ids each.
    ChatPurged {
        ids: Vec<crate::history::LineId>,
    },
    /// A report was filed (`docs/moderation.md` §4.5). To moderators
    /// only, and only while it is open.
    Report(crate::moderation::Report),
    /// A report was closed. `yours` is true for the reporter's own
    /// sessions, false for the moderators', so a wire that can only say
    /// one of the two things says the right one.
    ReportClosed {
        id: crate::moderation::ReportId,
        outcome: crate::moderation::Outcome,
        yours: bool,
    },
    /// An image the recipient could fetch has been revoked by a
    /// moderator (moderation.md §3.2). Delivered to everyone in the
    /// handle's authorization set that still holds a session — the
    /// people who may have it on screen. The line or message that
    /// carried it keeps its metadata, so a client drops the image and
    /// keeps the placeholder.
    MediaRevoked {
        id: crate::media::Handle,
    },

    // --- Voice (see [`crate::voice`]) ---------------------------------
    /// An SDP offer for the recipient's own peer connection: the initial
    /// one answering a join, or a renegotiation. Opaque to the domain —
    /// both frontends carry the string verbatim.
    VoiceOffer {
        cid: u32,
        sdp: String,
    },
    /// A server ICE candidate, or (empty candidate) end-of-candidates.
    VoiceIce {
        cid: u32,
        candidate: crate::voice::IceCandidate,
    },
    /// The voice room's participant list changed — someone joined, left,
    /// or changed mute state.
    VoiceStatus {
        cid: u32,
        participants: Vec<crate::voice::VoiceParticipant>,
    },

    // --- Video (see [`crate::video`]) ---------------------------------
    /// The room's video publications changed — a start, a stop, a pause,
    /// a resume, or a publisher leaving. **Always the complete list**,
    /// never a delta: a client replaces its whole view of the room's
    /// video state on each one, which is what makes the notification
    /// idempotent and a missed one self-healing.
    ///
    /// Delivered to every participant in the room, video-capable or not.
    /// A voice-only participant is entitled to know a camera is on in
    /// the room it is sitting in; whether its wire can say so is the
    /// frontend's business, not the domain's.
    VideoStatus {
        cid: u32,
        publications: Vec<crate::video::VideoPublication>,
    },

    // --- News (see [`crate::news`]) -----------------------------------
    //
    // "Your copy is stale", sent to every session holding read-news —
    // what `NEWSFILE_POST` has always been, carried forward
    // (`docs/news.md` §9.3). Never a notification: what is addressed to
    // one person is a different event with a different audience.
    /// An article was posted. A header rather than the article, because
    /// the cheap refresh is usually no refetch at all.
    NewsPosted {
        id: crate::news::ArticleId,
        category: crate::news::NodeId,
        root: crate::news::ArticleId,
        parent: Option<crate::news::ArticleId>,
        subject: String,
        from_nick: String,
        at: SystemTime,
        attachments: u32,
    },
    /// An article became a tombstone.
    NewsDeleted {
        id: crate::news::ArticleId,
        category: crate::news::NodeId,
    },
    /// A moderator's purge tombstoned these articles, each an `(id,
    /// category)` pair: what [`Event::NewsDeleted`] would be one per
    /// article (`docs/news.md` §9.3). At most
    /// [`crate::moderation::PURGE_EVENT_IDS`] each.
    NewsPurged {
        articles: Vec<(crate::news::ArticleId, crate::news::NodeId)>,
    },
    /// A node was created or renamed.
    NewsNode(crate::news::Node),
    NewsNodeDeleted {
        id: crate::news::NodeId,
    },
    /// A post is this session's account's business — a reply to its
    /// article, a citation of one, or news in something it follows
    /// (`docs/news.md` §10.6). **Targeted**, where the four above go to
    /// every reader: this is the one a client raises a badge on.
    NewsNotify(crate::news::Notified),
}

impl Event {
    /// Roughly what this event holds, in bytes: its own size and the text
    /// that dominates it. For the live channel's byte budget, which needs
    /// the same number on the way in and on the way out and a fair
    /// estimate, not an exact one.
    pub fn weight(&self) -> usize {
        let text = match self {
            Event::Chat { text, from, .. } => text.len() + from.nick.len(),
            Event::Notice { text, .. } => text.len(),
            Event::ChatSubject { subject, .. } => subject.len(),
            Event::Msg {
                from_nick,
                text,
                from_login,
                ..
            } => from_nick.len() + text.len() + from_login.as_ref().map_or(0, String::len),
            Event::Broadcast {
                from_nick, text, ..
            } => from_nick.len() + text.len(),
            Event::Report(r) => r.reason.len() + r.evidence.as_ref().map_or(0, String::len),
            Event::VoiceOffer { sdp, .. } => sdp.len(),
            Event::NewsPosted {
                subject, from_nick, ..
            } => subject.len() + from_nick.len(),
            Event::Joined(u) | Event::Changed(u) | Event::AvatarChanged(u) => u.nick.len(),
            Event::ChatPurged { ids } => ids.len() * std::mem::size_of::<crate::history::LineId>(),
            Event::NewsPurged { articles } => {
                articles.len()
                    * std::mem::size_of::<(crate::news::ArticleId, crate::news::NodeId)>()
            }
            _ => 0,
        };
        std::mem::size_of::<SeqEvent>() + text
    }

    /// The event's name as a metric label (`crate::instrument`).
    pub fn kind(&self) -> &'static str {
        match self {
            Event::Joined(..) => "joined",
            Event::Changed(..) => "changed",
            Event::Parted(..) => "parted",
            Event::AvatarChanged(..) => "avatar_changed",
            Event::Chat { .. } => "chat",
            Event::Notice { .. } => "notice",
            Event::ChatSubject { .. } => "chat_subject",
            Event::ChatPassword { .. } => "chat_password",
            Event::ChatInvite { .. } => "chat_invite",
            Event::ChatUserJoined { .. } => "chat_user_joined",
            Event::ChatUserParted { .. } => "chat_user_parted",
            Event::Msg { .. } => "msg",
            Event::Broadcast { .. } => "broadcast",
            Event::Kicked => "kicked",
            Event::ChatRedacted { .. } => "chat_redacted",
            Event::ChatPurged { .. } => "chat_purged",
            Event::Report(..) => "report",
            Event::ReportClosed { .. } => "report_closed",
            Event::MediaRevoked { .. } => "media_revoked",
            Event::VoiceOffer { .. } => "voice_offer",
            Event::VoiceIce { .. } => "voice_ice",
            Event::VoiceStatus { .. } => "voice_status",
            Event::VideoStatus { .. } => "video_status",
            Event::NewsPosted { .. } => "news_posted",
            Event::NewsDeleted { .. } => "news_deleted",
            Event::NewsPurged { .. } => "news_purged",
            Event::NewsNode(..) => "news_node",
            Event::NewsNodeDeleted { .. } => "news_node_deleted",
            Event::NewsNotify(..) => "news_notify",
        }
    }
}

/// An event stamped with its position in the session's stream. `seq` is
/// per-session, monotonic from 1, gapless — the resume protocol's
/// substrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeqEvent {
    pub seq: u64,
    pub event: Event,
}

/// Where a session's events currently go.
enum Sink {
    /// A connection is attached; events flow on the channel.
    Live(mpsc::Sender<SeqEvent>, Arc<ConnState>),
    /// A connection is attached, but fell [`LIVE_QUEUE_CAP`] events
    /// behind. Its channel is closed — the frontend sees the stream end
    /// once it has drained what was sent, and asks [`Core::is_lagging`]
    /// why — and every event from here on is lost to it, seq and all. A
    /// resume can therefore only be a resync.
    Lagged(Arc<ConnState>),
    /// Detached: events buffer for replay.
    Buffering {
        /// When the connection was lost (grace accounting).
        since: Instant,
        /// The seq of the first event that went unbuffered-and-undelivered
        /// — i.e. `next_seq` at detach time. A resume with `last_seq + 1 <
        /// start_seq` predates the buffer and cannot be replayed.
        start_seq: u64,
        buf: VecDeque<SeqEvent>,
        /// What the buffer weighs, drawn on the server's budget like a
        /// live channel ([`crate::budget`]). Refused, the buffer breaks.
        share: crate::budget::Share,
        /// The buffer overflowed; replay is impossible, a fresh sync is
        /// needed. The buffer is dropped when this trips.
        broken: bool,
    },
}

/// The seq-stamped per-session event stream.
pub(crate) struct Outbox {
    next_seq: u64,
    sink: Sink,
}

impl Outbox {
    fn live(tx: mpsc::Sender<SeqEvent>, conn: Arc<ConnState>) -> Self {
        Outbox {
            next_seq: 1,
            sink: Sink::Live(tx, conn),
        }
    }

    fn push(&mut self, event: Event) -> instrument::Pushed {
        let seq = self.next_seq;
        self.next_seq += 1;
        let se = SeqEvent { seq, event };
        match &mut self.sink {
            Sink::Live(tx, conn) => {
                let weight = se.event.weight();
                // Past the connection's byte bound, or past the server's
                // budget while holding more than its share of it, is the
                // same verdict as a full channel, reached by another road.
                let sent = match conn.share.take(weight, LIVE_QUEUE_BYTES) {
                    Err(over) => Err((TrySendError::Full(se), over.label())),
                    Ok(()) => tx.try_send(se).map_err(|e| {
                        conn.share.give(weight);
                        (e, "count")
                    }),
                };
                match sent {
                    Ok(()) => instrument::Pushed::Live,
                    Err((TrySendError::Full(_), bound)) => {
                        let conn = conn.clone();
                        conn.lag();
                        // Dropping the sender is what closes the channel.
                        self.sink = Sink::Lagged(conn);
                        instrument::outbox_lagged(bound);
                        instrument::Pushed::Dropped
                    }
                    // Nobody reads this channel: a frontend that is gone and
                    // has not said so yet, or the server account, which reads
                    // nothing.
                    Err((TrySendError::Closed(_), _)) => instrument::Pushed::Closed,
                }
            }
            Sink::Lagged(_) => instrument::Pushed::Dropped,
            Sink::Buffering {
                buf, share, broken, ..
            } => {
                if *broken {
                    return instrument::Pushed::Dropped;
                }
                // Past its count, or past the server's budget while holding
                // more than its share: either way the resume is a resync.
                if buf.len() >= OUTBOX_BUFFER_CAP
                    || share.take(se.event.weight(), usize::MAX).is_err()
                {
                    *broken = true;
                    buf.clear(); // Nothing partial is replayable; free it.
                    share.give(share.held());
                    instrument::outbox_broken();
                    return instrument::Pushed::Dropped;
                }
                buf.push_back(se);
                instrument::Pushed::Buffered
            }
        }
    }
}

/// One user's presence and its outbox.
pub(crate) struct UserSession {
    /// Distinguishes this session from any other that ever held the same
    /// uid (uids recycle after 65k sessions; serials never). External
    /// registries key trust decisions on (uid, serial).
    pub(crate) serial: u64,
    pub(crate) info: UserInfo,
    pub(crate) access: AccessBits,
    pub(crate) login: String,
    pub(crate) addr: Option<IpAddr>,
    pub(crate) connected_at: Instant,
    /// Account policy: may this session survive its connection? (The
    /// `[extra] can_detach` flag; guests default to no.)
    pub(crate) can_detach: bool,
    /// Moderation kicked this session. Its `Kicked` event may still be in
    /// the channel, or may have failed to send, when the connection
    /// drops: set, this makes `connection_lost` end the session rather
    /// than park it, and `resume` refuse it, so a kick is never undone
    /// by the socket dying at the wrong moment.
    pub(crate) kicked: bool,
    /// Account policy: may private messages be stored for this account
    /// and delivered later? (The `[extra] inbox` flag; guests default to
    /// no.) It doubles as "is this session a repliable identity" — the
    /// sender of a stored message is recorded only when it is true.
    pub(crate) has_inbox: bool,
    pub(crate) attach_news: bool,
    /// See [`AttachInfo::set_avatar`].
    pub(crate) set_avatar: bool,
    /// See [`AttachInfo::moderate`].
    pub(crate) moderate: bool,
    /// See [`AttachInfo::can_spam`].
    pub(crate) can_spam: bool,
    /// What this session has spent of its flood allowances.
    pub(crate) flood: crate::limits::Flood,
    /// And of its voice signaling allowances (`crate::voice`).
    pub(crate) voice_flood: crate::voice::VoiceFlood,
    /// What it has left of its ng request limit, or `None` when there is
    /// no limit ([`Core::spend_request`]). The session's rather than a
    /// connection's, as the flood allowances are, so a resume carries on
    /// from where the dropped connection left it.
    pub(crate) requests: Option<crate::RateBucket>,
    /// See [`AttachInfo::is_person`].
    pub(crate) is_person: bool,
    /// See [`AttachInfo::reads_on_delivery`].
    pub(crate) reads_on_delivery: bool,
    /// The reserved server account (`crate::system`). One session ever,
    /// made at startup: it cannot be kicked or banned, a tracker is not
    /// told about it, and a private message to it is a command rather
    /// than mail.
    pub(crate) system: bool,
    /// This session's identity fingerprint — the durable half of its
    /// mailbox key. See [`AttachInfo::identity`].
    pub(crate) identity: Option<[u8; 32]>,
    /// History request throttling is session state, so it survives an ng
    /// transport detach/resume instead of resetting on every WebSocket.
    pub(crate) history_refill: Instant,
    pub(crate) history_tokens: f64,
    /// News search's ration, kept the same way and for the same reason.
    pub(crate) search_refill: Instant,
    pub(crate) search_tokens: f64,
    /// Whether this session has been announced (shows on the user list,
    /// generates events). False between login and login-completion.
    pub(crate) visible: bool,
    /// The avatar `info.avatar` describes, with its bytes.
    pub(crate) avatar: Option<crate::avatar::Avatar>,
    pub(crate) outbox: Outbox,
}

/// What a transport hands the roster at login.
#[derive(Debug, Clone)]
pub struct AttachInfo {
    pub nick: String,
    pub icon: u16,
    pub admin: bool,
    pub access: AccessBits,
    pub login: String,
    pub addr: Option<IpAddr>,
    pub can_detach: bool,
    pub transport: Transport,
    /// May private messages be stored for this account and delivered
    /// later? (The `[extra] inbox` flag; guests default to no.)
    pub has_inbox: bool,
    /// May this session stage durable news attachments?
    pub attach_news: bool,
    /// May this session set its owner's avatar? The account's `[extra]
    /// set_avatar`, which defaults to a password or a linked identity.
    pub set_avatar: bool,
    /// May this session moderate (`docs/moderation.md` §2)? The
    /// account's `[extra] moderate`, which defaults to the kick bit.
    pub moderate: bool,
    /// Is this session held to no flood limit (`crate::limits`)? The
    /// account's `[extra] can_spam`, mhxd's, which defaults to the kick
    /// bit.
    pub can_spam: bool,
    /// Is exactly one person behind this account? [`Account::is_person`]:
    /// what news records authorship against, independent of `has_inbox`.
    ///
    /// [`Account::is_person`]: crate::Account::is_person
    pub is_person: bool,
    /// This session's wire cannot say it has read a message, so handing
    /// one over *is* the read (`docs/private-messages.md` §11).
    ///
    /// True for the legacy wire, where a private message is a window that
    /// opens and nothing comes back; false for ng, which has `msg_read`.
    /// A property of the session rather than of a particular flush,
    /// because a live delivery is as much a read as a queued one — and
    /// getting that wrong leaves a 1.5 user's inbox permanently unread,
    /// their badge wrong on every other client they own, and their mail
    /// ageing on the 30-day unread clock instead of the 7-day read one.
    pub reads_on_delivery: bool,
    /// This session is the reserved server account
    /// (`docs/system-account.md` §2). Set by
    /// [`Core::start_system_session`] and by nothing else — a login can
    /// never ask for it.
    pub system: bool,
    /// The identity this session belongs to: **the account's linked
    /// fingerprint** where there is one, and otherwise the fingerprint
    /// the transport authenticated with.
    ///
    /// The precedence matters. A mailbox belongs to the account link, so
    /// that it is the same mailbox whether its owner logged in with a
    /// password or with their key. The transport's fingerprint stands in
    /// only where there is no link — an identity user admitted as a guest
    /// — which gives that session something durable to be blocked by and
    /// to be resolved to at delivery, without giving it a mailbox it must
    /// not have (the `guest` login is shared; see `has_inbox`).
    ///
    /// The two cannot disagree for a linked account: the identity spec
    /// admits a session to an account only when the account is linked to
    /// that identity or is unlinked.
    pub identity: Option<[u8; 32]>,
}

/// The outcome of a [`Core::resume`].
pub enum Resume {
    /// The buffer covered the gap: replay these, then live events follow
    /// on the channel.
    Replayed(Events, Vec<SeqEvent>),
    /// The session is alive and the channel is attached, but the gap can't
    /// be replayed (overflow, or `last_seq` predates the buffer). The
    /// client must do a fresh sync; events flow from the session's current
    /// seq onward.
    ResyncRequired(Events),
    /// No such session (grace lapsed, ended, or never existed).
    Gone,
}

#[derive(Default)]
pub(crate) struct RosterInner {
    pub(crate) users: HashMap<Uid, UserSession>,
    last_uid: Uid,
    last_serial: u64,
    pub(crate) public_subject: String,
    pub(crate) chats: HashMap<u32, PrivateChat>,
    pub(crate) voice: crate::voice::VoiceState,
}

impl RosterInner {
    fn next_uid(&mut self) -> Option<Uid> {
        // Sequential with wrap, skipping 0 and in-use ids — stable ids for
        // the lifetime of a session, no reuse while alive.
        for _ in 0..=u16::MAX {
            self.last_uid = self.last_uid.wrapping_add(1);
            if self.last_uid == 0 {
                continue;
            }
            if !self.users.contains_key(&self.last_uid) {
                return Some(self.last_uid);
            }
        }
        None
    }

    /// Allocate a private chat's id: nonzero, unused, and from the OS
    /// CSPRNG. `None` if the CSPRNG refuses (or, absurdly, if the id
    /// space is so full that a hundred draws all collide).
    ///
    /// **Random rather than sequential, and unconditionally.** A chat id
    /// is opaque to every client — nothing on either wire derives meaning
    /// from its value — but it is also the whole address of a voice room
    /// (fogWraith Capabilities-Voice.md, "Room Membership"), which a
    /// voice-capable client can name directly. Sequential ids are
    /// guessable, so they would let such a client name a private chat's
    /// voice room it was never invited to. Membership checks are the real
    /// defence and live where the joins are; this is the cheap layer
    /// underneath, and doing it always is one less mode than doing it
    /// only when voice is enabled.
    pub(crate) fn next_chat_id(&mut self) -> Option<u32> {
        for _ in 0..100 {
            let mut raw = [0u8; 4];
            getrandom::getrandom(&mut raw).ok()?;
            let cid = u32::from_be_bytes(raw);
            // 0 is the public chat and never appears in the registry.
            if cid != 0 && !self.chats.contains_key(&cid) {
                return Some(cid);
            }
        }
        None
    }

    pub(crate) fn send_to(&mut self, uid: Uid, ev: Event) {
        if let Some(sess) = self.users.get_mut(&uid) {
            let mut tally = instrument::Tally::default();
            tally.add(sess.outbox.push(ev));
            tally.record();
        }
    }

    /// Deliver to every *visible* session matching `pred` (skipping `skip`).
    pub(crate) fn broadcast_where<F: Fn(&UserSession) -> bool>(
        &mut self,
        ev: &Event,
        skip: Option<Uid>,
        pred: F,
    ) {
        let took = instrument::Timer::start();
        let mut tally = instrument::Tally::default();
        let mut reached = 0;
        for (uid, sess) in self.users.iter_mut() {
            if Some(*uid) == skip || !sess.visible || !pred(sess) {
                continue;
            }
            tally.add(sess.outbox.push(ev.clone()));
            reached += 1;
        }
        // Once per fan-out, whatever its reach: still under the lock, but
        // a constant rather than a cost per recipient.
        instrument::fanout(ev.kind(), reached, took);
        tally.record();
    }

    fn broadcast(&mut self, ev: &Event, skip: Option<Uid>) {
        self.broadcast_where(ev, skip, |_| true);
    }

    /// Who a fan-out just showed an image to: the same sessions
    /// [`Self::broadcast_where`] reached, narrowed to the ones whose
    /// wire can carry a media reference. The narrowing is the point —
    /// a session that was sent the line with its media fields stripped
    /// was not shown the image and has no business fetching it.
    pub(crate) fn media_audience<F: Fn(&UserSession) -> bool>(
        &self,
        skip: Option<Uid>,
        pred: F,
    ) -> Vec<crate::media::Principal> {
        self.users
            .iter()
            .filter(|(uid, sess)| {
                Some(**uid) != skip
                    && sess.visible
                    && sess.info.transport.inline_media
                    && pred(sess)
            })
            .map(|(uid, sess)| crate::media::Principal::Session {
                uid: *uid,
                serial: sess.serial,
            })
            .collect()
    }

    /// The same, for a named set of sessions (a private room's members).
    pub(crate) fn media_audience_of(&self, uids: &[Uid]) -> Vec<crate::media::Principal> {
        uids.iter()
            .filter_map(|uid| self.users.get(uid).map(|s| (uid, s)))
            .filter(|(_, sess)| sess.info.transport.inline_media)
            .map(|(uid, sess)| crate::media::Principal::Session {
                uid: *uid,
                serial: sess.serial,
            })
            .collect()
    }

    /// Full teardown: leave voice and chats, remove, announce the part.
    pub(crate) fn end_session(&mut self, uid: Uid) {
        // Voice first, while the session is still on the roster: the
        // room it leaves has to be renegotiated and re-announced, and
        // that has nothing to do with the chat rooms below.
        self.voice_part(uid);
        crate::Core::leave_all_chats(self, uid);
        let Some(sess) = self.users.remove(&uid) else {
            return;
        };
        if sess.visible {
            self.broadcast(&Event::Parted(uid), Some(uid));
        }
    }

    /// Flip status and tell the roster (a status change is a user change).
    fn set_status(&mut self, uid: Uid, status: SessionStatus) {
        let Some(sess) = self.users.get_mut(&uid) else {
            return;
        };
        if sess.info.status == status {
            return;
        }
        sess.info.status = status;
        if sess.visible {
            let ev = Event::Changed(sess.info.clone());
            self.broadcast(&ev, None);
        }
    }
}

/// How the inbox behaves, as far as the domain is concerned. The binary
/// fills this from the `[inbox]` config block.
#[derive(Debug, Clone, Copy)]
pub struct InboxPolicy {
    /// Messages an account may have *waiting* before further sends to it
    /// are refused. A full mailbox refuses rather than evicting: a message
    /// a sender was told was delivered and which then quietly disappeared
    /// is the failure mode that destroys trust in a messaging system.
    ///
    /// Queue depth, not unread count. A message the recipient received
    /// live and has not marked read is not congestion, and counting it as
    /// such would let a client that never marks anything read lock its own
    /// mailbox against everyone. fogWraith's `MaxOfflineQueue` measures
    /// the same thing; what bounds the rest is retention.
    pub max_queued: usize,
    /// How many queued messages one flush hands a client. The cap is for
    /// the legacy wire, where each private message opens a window; the
    /// remainder stays pending rather than being dropped.
    pub deliver_at_flush: usize,
    /// Messages one sender may *store* in a rolling day, delivered or
    /// waiting; 0 for no quota. `max_queued` bounds a mailbox's queue,
    /// and retention keeps every row besides — a delivered one for a
    /// week once read — so without this one account could fill the disk
    /// at the rate the flood limit allows. Past it, mail that would have
    /// to wait is refused; mail to someone attached still reaches them,
    /// unstored (`docs/private-messages.md` §9).
    pub max_sent_per_day: usize,
    /// Body bytes, likewise; 0 for no quota.
    pub max_sent_bytes_per_day: u64,
}

impl Default for InboxPolicy {
    fn default() -> Self {
        InboxPolicy {
            max_queued: 200,
            deliver_at_flush: 25,
            max_sent_per_day: 1_000,
            max_sent_bytes_per_day: 8 << 20,
        }
    }
}

impl InboxPolicy {
    /// Both numbers must be at least 1, and the binary refuses a config
    /// that says otherwise. Zero is not "unlimited" in either: with
    /// `max_queued = 0` nothing can be stored at all, and with
    /// `deliver_at_flush = 0` every flush reads an empty batch, so a
    /// message to an attached recipient is stored, never delivered live,
    /// and never flushed afterwards either.
    pub fn check(&self) -> Result<(), String> {
        if self.max_queued == 0 {
            return Err("[inbox] max_queued must be at least 1 (0 stores nothing)".into());
        }
        if self.deliver_at_flush == 0 {
            return Err(
                "[inbox] deliver_at_flush must be at least 1 (0 never delivers anything)".into(),
            );
        }
        Ok(())
    }
}

/// The domain core. One per server; shared across sessions.
#[derive(Default)]
pub struct Core {
    pub(crate) roster: TimedMutex<RosterInner>,
    /// What every queue waiting on a client draws on (`crate::budget`):
    /// the live channels here, and the frontends' own write queues.
    pub(crate) queue_budget: Arc<crate::budget::QueueBudget>,
    /// Logins the server is working on at once ([`Core::admit_login`]).
    pub(crate) login_gate: LoginGate,
    /// Connections each address holds ([`Core::admit_connection`]).
    pub(crate) conn_gate: crate::limits::ConnGate,
    /// Failed logins each address has made at each login
    /// ([`Core::login_attempt`]).
    pub(crate) login_failures: crate::limits::RateGate,
    /// Failed logins each address has made at every login together.
    pub(crate) login_failures_per_addr: crate::limits::RateGate,
    /// How fast one session may talk (`crate::limits`).
    pub(crate) flood_limits: crate::limits::FloodLimits,
    /// How many private chats may be open (`crate::limits`).
    pub(crate) chat_limits: crate::limits::ChatLimits,
    /// How fast one ng session may ask and one account post news
    /// (`crate::limits`).
    pub(crate) request_limits: crate::limits::RequestLimits,
    /// What each account has left of its news posts. Its own lock, taken
    /// with nothing else held.
    pub(crate) post_rates: crate::limits::PostRates,
    /// Every standing ban, for matching without the store
    /// (`crate::ban`).
    pub(crate) bans: std::sync::RwLock<crate::ban::BanMatcher>,
    /// Ids for bans placed with no store to number them.
    pub(crate) ban_ids: std::sync::atomic::AtomicU64,
    /// Held by whatever changes the bans — a place, a lift, a reread —
    /// across its store call and its matcher update, so none lands
    /// between another's two halves. Taken before `bans`, never while
    /// the roster lock is held.
    pub(crate) ban_writes: Mutex<()>,
    /// The durable private-message inbox, or `None` — in which case
    /// private messaging behaves exactly as it did before the inbox
    /// existed, which is what a server that configures no database gets.
    ///
    /// **It lives on `Core` and not in `RosterInner` on purpose.** Store
    /// calls are disk I/O and must not happen under the roster lock; a
    /// field the locked state cannot reach is a structural reminder.
    pub(crate) inbox: Option<Arc<dyn crate::inbox::MessageStore>>,
    /// Durable public-chat scrollback, or `None` when history is off.
    /// Store calls never happen under `roster`.
    pub(crate) history: Option<Arc<dyn crate::history::ChatLog>>,
    pub(crate) history_policy: crate::history::HistoryPolicy,
    /// The news tree, or `None` when no `[news]` section asked for one.
    /// On `Core` rather than in `RosterInner` for the reason `inbox` is:
    /// store calls are disk I/O and never happen under the roster lock.
    pub(crate) news: Option<Arc<dyn crate::news::NewsStore>>,
    pub(crate) news_policy: crate::news::NewsPolicy,
    /// The markdown parser behind `[news] markdown = "render"`, or `None`.
    pub(crate) body_renderer: Option<Arc<dyn crate::news::BodyRenderer>>,
    pub(crate) directory: Option<Arc<dyn crate::account::AccountDirectory>>,
    pub(crate) inbox_policy: InboxPolicy,
    /// Where push notifications go, or `None` — which is the no-op, and
    /// the default. See [`crate::notify`].
    pub(crate) gateway: Option<Arc<dyn crate::notify::NotificationGateway>>,
    /// The devices a gateway pushes to, or `None` when no `[push]`
    /// section configured one. On `Core` because the three mailbox
    /// obligations are paid here, beside mail's and news's; the gateway
    /// holds its own handle to the same store and does the sending.
    pub(crate) devices: Option<Arc<dyn crate::push::PushStore>>,
    /// What a registration may do: how many devices a mailbox holds, and
    /// whether an endpoint on a private network is acceptable.
    pub(crate) push_policy: crate::push::PushPolicy,
    /// The reserved server account, or `None` when `[system]` did not
    /// ask for one. See [`crate::system`].
    pub(crate) system: Option<crate::system::SystemState>,
    /// What each account has left of its hourly news pushes
    /// (`[news.notify] max_per_hour`), keyed by the mailbox rule. Its own
    /// lock, taken with nothing else held.
    #[allow(clippy::type_complexity)]
    pub(crate) news_push: Mutex<HashMap<(Option<[u8; 32]>, String), (Instant, f64)>>,
    /// News attachment staging rate, keyed by uploader mailbox.
    #[allow(clippy::type_complexity)]
    pub(crate) news_attach_rate: Mutex<HashMap<(Option<[u8; 32]>, String), (Instant, f64)>>,
    /// Serialises inbox flushes.
    ///
    /// A flush reads the pending rows, sends them under the roster lock,
    /// and stamps them delivered after releasing it. Two flushes for one
    /// mailbox — a sender's post-store flush racing the recipient's login
    /// flush, or two senders racing each other — both read the same rows
    /// and both send them, and the recipient sees every message twice.
    ///
    /// A lock of its own rather than the roster's, so the no-disk-under-
    /// the-roster-lock rule survives. Order is always this lock first,
    /// then the roster's.
    pub(crate) flushing: Mutex<()>,
    /// The image pipeline and its handles, or `None` when no `[media]`
    /// section configured one — in which case neither wire ever offers
    /// the capability. It carries its own mutex; the roster's may be
    /// taken before it and never after (`crate::media`).
    pub(crate) media: Option<crate::media::MediaStore>,
    /// Durable news bytes and the shared hostile-image pipeline. Kept
    /// outside the roster lock: both can do disk or decode work.
    pub(crate) news_blobs: Option<Arc<dyn crate::news::BlobStore>>,
    pub(crate) news_codec: Option<Arc<dyn crate::media::MediaCodec>>,
    /// Serializes attachment filesystem and metadata transitions.
    pub(crate) news_blob_serial: Mutex<()>,
    /// Holds a post's check against the news ceilings and its write
    /// together, so two posts cannot both take the last place. Nothing
    /// is taken under it but the news store's own lock.
    pub(crate) news_post_serial: Mutex<()>,
    /// Makes persisted id order and live fan-out order the same fact.
    /// Nothing but public chat takes this lock; order is it first, then
    /// (briefly) `roster`.
    pub(crate) log_serial: TimedMutex<LogSerial>,
    /// Public lines waiting to be committed together (`crate::chat`).
    pub(crate) chat_commit: crate::chat::ChatCommit,
    /// Keys the operator has refused by hand (`crate::revoked`). Read
    /// under the roster lock by `attach`, and written with nothing held,
    /// so the order is roster first, then this.
    pub(crate) revoked: std::sync::RwLock<crate::revoked::Revocations>,
    /// The audit trail and the reports, or `None` — in which case every
    /// act and report is refused as a server without the feature
    /// refuses it. Store calls never happen under `roster`.
    pub(crate) moderation: Option<Arc<dyn crate::moderation::ModerationStore>>,
    pub(crate) moderation_policy: crate::moderation::ModerationPolicy,
    /// What each reporter has left of their hourly reports. Its own
    /// lock, taken with nothing else held.
    pub(crate) report_rate: Mutex<crate::moderation::ReportRates>,
    /// Avatars, or `None` when no `[avatars]` section asked for them.
    pub(crate) avatars: Option<crate::avatar::AvatarState>,
    /// Serializes avatar changes: taken before the store is written and
    /// held until the roster shows the change, so the two agree. Order
    /// is it first, then `roster`.
    pub(crate) avatar_serial: Mutex<()>,
    /// When each owner last changed its avatar (`AvatarPolicy`'s
    /// interval). Its own lock, taken with nothing else held.
    pub(crate) avatar_turns: Mutex<HashMap<crate::avatar::Turn, Instant>>,
}

/// [`Core::census`]: the roster in numbers. `system` is the reserved
/// server account, counted apart so that "nobody is on" reads as zero
/// attached and zero detached whether or not the server has one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Census {
    pub attached: usize,
    pub detached: usize,
    /// On the roster but not yet announced (mid-login), and counted in
    /// neither of the two above.
    pub hidden: usize,
    pub system: usize,
    /// Detached sessions whose buffer overflowed.
    pub broken: usize,
    /// Attached sessions whose client fell behind and whose connection
    /// is about to end (counted in `attached` too).
    pub lagging: usize,
    /// Events waiting in detached sessions' buffers, in all and at most.
    pub buffered: usize,
    pub buffered_max: usize,
    /// Private chat rooms open.
    pub chats: usize,
    /// Events waiting in attached connections' channels, hidden sessions'
    /// included, and what they weigh ([`Event::weight`]), in all and at
    /// most.
    pub live: usize,
    pub live_bytes: usize,
    pub live_bytes_max: usize,
}

/// How many logins the server works on at once, by default.
pub const LOGINS_IN_FLIGHT: usize = 32;

/// The logins in progress, bounded.
///
/// **Past capacity a login is refused at once, not queued.** Every login
/// costs everyone present a join, and later a part, so a server taking
/// logins faster than it can tell the room about them falls further
/// behind with each: they take longer, the sessions they leave stay
/// longer, and every join then goes to more people. The load baseline
/// saw logins go from fast to seconds within one step of the rate, and
/// not come back while arrivals continued. Bounding the work
/// in progress bounds that: when logins slow down, fewer are admitted,
/// and the ones refused are told to come back rather than left waiting.
/// Only the server's own work holds a place, from the login request to
/// its answer, so a client that is slow to send one holds nothing. And one
/// address holds at most a quarter of the places, so a storm from one
/// source leaves room for everyone else — until the login is known to be
/// a person's ([`LoginPermit::logged_in`]), when the address is given its
/// share back: the people behind one carrier's address are not held to
/// a quarter of the server between them for any longer than it takes to
/// tell who they are.
pub(crate) struct LoginGate(Arc<GateInner>);

pub(crate) struct GateInner {
    places: Arc<tokio::sync::Semaphore>,
    per_addr: usize,
    by_addr: std::sync::Mutex<HashMap<IpAddr, usize>>,
}

impl LoginGate {
    fn new(n: usize) -> LoginGate {
        LoginGate(Arc::new(GateInner {
            places: Arc::new(tokio::sync::Semaphore::new(n)),
            per_addr: (n / 4).max(1),
            by_addr: Default::default(),
        }))
    }
}

impl Default for LoginGate {
    fn default() -> Self {
        LoginGate::new(LOGINS_IN_FLIGHT)
    }
}

/// A place among the logins in progress; dropping it gives it back.
pub struct LoginPermit {
    _place: tokio::sync::OwnedSemaphorePermit,
    addr: Option<(Arc<GateInner>, IpAddr)>,
}

impl Drop for LoginPermit {
    fn drop(&mut self) {
        self.release_addr();
    }
}

impl LoginPermit {
    /// The login has authenticated as an account with one person behind
    /// it: its address's share is given back, and it keeps its place
    /// among every login in progress until it is done. Its connection
    /// counts against its account from here ([`Core::admit_account`]),
    /// and the account's cap bounds how many of its logins can be in
    /// progress at once.
    pub fn logged_in(&mut self) {
        self.release_addr();
    }

    fn release_addr(&mut self) {
        if let Some((gate, addr)) = self.addr.take() {
            let mut by = gate.by_addr.lock().unwrap();
            if let Some(n) = by.get_mut(&addr) {
                *n -= 1;
                if *n == 0 {
                    by.remove(&addr);
                }
            }
        }
    }
}

/// What `Core::log_serial` guards: nothing but an order. A type of its
/// own so the lock's metrics carry a name (`TimedMutex`'s default).
#[derive(Default)]
pub(crate) struct LogSerial;

impl Core {
    pub fn new() -> Self {
        Self::default()
    }

    /// Give the domain a durable inbox. Without one, a private message to
    /// a detached session buffers in its outbox as before and a message to
    /// an account with no session is refused.
    pub fn with_inbox(
        mut self,
        store: Arc<dyn crate::inbox::MessageStore>,
        directory: Arc<dyn crate::account::AccountDirectory>,
        policy: InboxPolicy,
    ) -> Self {
        self.inbox = Some(store);
        self.directory = Some(directory);
        self.inbox_policy = policy;
        self
    }

    /// Bound what the server holds for its clients, all together, to
    /// `bytes` rather than [`crate::QUEUE_BUDGET`].
    pub fn with_queue_budget(mut self, bytes: usize) -> Self {
        self.queue_budget = crate::budget::QueueBudget::new(bytes);
        self
    }

    /// Work on at most `n` logins at once rather than
    /// [`LOGINS_IN_FLIGHT`].
    pub fn with_logins_in_flight(mut self, n: usize) -> Self {
        self.login_gate = LoginGate::new(n);
        self
    }

    /// A place for one login from `addr`, or `None` when the server is
    /// already working on as many as it takes, or on as many from that
    /// address as one may have: the frontend refuses the login as busy
    /// ([`LoginGate`]). Held from the login request until the session is
    /// announced.
    pub fn admit_login(&self, addr: Option<IpAddr>) -> Option<LoginPermit> {
        let gate = &self.login_gate.0;
        // An address exempt from `[limits]` has no share of its own to
        // run out of: loopback, by default, where the tests, the load
        // harness and an operator's tools log many in at once.
        let addr = addr.filter(|ip| !self.conn_gate.exempt(*ip));
        let permit = (|| {
            let place = gate.places.clone().try_acquire_owned().ok()?;
            let Some(addr) = addr else {
                return Some(LoginPermit {
                    _place: place,
                    addr: None,
                });
            };
            let mut by = gate.by_addr.lock().unwrap();
            let n = by.entry(addr).or_insert(0);
            if *n >= gate.per_addr {
                return None;
            }
            *n += 1;
            Some(LoginPermit {
                _place: place,
                addr: Some((gate.clone(), addr)),
            })
        })();
        if permit.is_none() {
            instrument::login_refused_busy();
        }
        permit
    }

    /// Hold connections from one address to `limits` rather than
    /// [`crate::ConnLimits::default`].
    pub fn with_conn_limits(mut self, limits: crate::ConnLimits) -> Self {
        self.conn_gate = crate::limits::ConnGate::new(limits);
        self
    }

    /// Hold sessions to `limits` rather than
    /// [`crate::FloodLimits::default`].
    pub fn with_flood_limits(mut self, limits: crate::FloodLimits) -> Self {
        self.flood_limits = limits;
        self
    }

    /// Hold private chats to `limits` rather than
    /// [`crate::ChatLimits::default`].
    pub fn with_chat_limits(mut self, limits: crate::ChatLimits) -> Self {
        self.chat_limits = limits;
        self
    }

    /// Hold ng sessions and news posts to `limits` rather than
    /// [`crate::RequestLimits::default`].
    pub fn with_request_limits(mut self, limits: crate::RequestLimits) -> Self {
        self.request_limits = limits;
        self
    }

    /// Spend `cost` of `uid`'s ng request limit
    /// ([`crate::RequestLimits`]), or say how long until it could be; a
    /// refusal spends nothing. The bucket is the session's, filled at
    /// login and kept across a detach and resume, so a client cannot
    /// buy a fresh one by dropping its socket. A session held to none
    /// spends nothing: no limit is set, its account `can_spam` (held to
    /// no request limit, as it is held to no flood limit), it is the
    /// server account, or it has gone.
    pub fn spend_request(&self, uid: Uid, cost: u32) -> Result<(), Duration> {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return Ok(());
        };
        if sess.can_spam || sess.info.system {
            return Ok(());
        }
        match sess.requests.as_mut() {
            Some(bucket) => bucket.spend(cost, Instant::now()),
            None => Ok(()),
        }
    }

    /// A place for one connection from `addr`, held for as long as the
    /// connection is open, or why there is none: the frontend closes the
    /// connection unanswered (`crate::limits`). Asked once per
    /// connection that can carry a session, with the client's address.
    pub fn admit_connection(
        &self,
        addr: std::net::IpAddr,
    ) -> Result<crate::ConnPermit, crate::ConnRefused> {
        self.conn_gate.admit(addr)
    }

    /// A connection has logged in as `login`: when the account has one
    /// person behind it (`is_person`, [`crate::Account::is_person`]),
    /// move `place` from its address's count to the account's, or refuse
    /// with [`crate::AccountRefused`] when the account already holds as
    /// many connections as it may, or has been logging in faster than it
    /// may (`crate::limits`). A guest, or any
    /// account with neither a password nor an identity, stays counted
    /// against its address and is never refused here. Asked once the
    /// login has authenticated, before the session is attached, on
    /// every wire.
    pub fn admit_account(
        &self,
        place: &mut crate::ConnPermit,
        login: &str,
        is_person: bool,
    ) -> Result<(), crate::AccountRefused> {
        if !is_person {
            return Ok(());
        }
        let refused = self.conn_gate.admit_account(place, login, 0);
        if refused.is_err() {
            instrument::throttled("account");
        }
        refused
    }

    /// [`Core::admit_account`] for a connection resuming `uid`, whose
    /// account it takes from the session. A session taken over from a
    /// connection that has not yet noticed it is gone may go one past
    /// the cap, for as long as that connection takes to close: the
    /// account is not holding a connection more than it was, and a
    /// phone that has changed networks resumes that way. A session that has gone is none of this gate's
    /// business; the resume answers it.
    pub fn admit_resume(
        &self,
        place: &mut crate::ConnPermit,
        uid: Uid,
    ) -> Result<(), crate::AccountRefused> {
        let who = {
            let r = self.roster.lock().unwrap();
            r.users.get(&uid).map(|s| {
                (
                    s.login.clone(),
                    s.is_person,
                    !matches!(s.outbox.sink, Sink::Buffering { .. }),
                )
            })
        };
        let Some((login, is_person, live)) = who else {
            return Ok(());
        };
        if !is_person {
            return Ok(());
        }
        let refused = self
            .conn_gate
            .admit_account(place, &login, usize::from(live));
        if refused.is_err() {
            instrument::throttled("account");
        }
        refused
    }

    /// The budget, for a frontend's queues to draw on too.
    pub fn queue_budget(&self) -> &Arc<crate::budget::QueueBudget> {
        &self.queue_budget
    }

    /// Let the domain ask about accounts nobody is logged into, without an
    /// inbox. [`Self::with_inbox`] takes one too; news notifications need
    /// it on a server that keeps news and no mail, because a subscription
    /// outlives its owner's session and whether they may still read the
    /// news is a question about the account (`docs/news.md` §10.5).
    pub fn with_accounts(mut self, directory: Arc<dyn crate::account::AccountDirectory>) -> Self {
        self.directory = Some(directory);
        self
    }

    /// Give the domain a durable public-chat log. The same store object may
    /// also implement the inbox; the binary shares it when both sections
    /// name the same SQLite file.
    pub fn with_history(
        mut self,
        log: Arc<dyn crate::history::ChatLog>,
        policy: crate::history::HistoryPolicy,
    ) -> Self {
        self.history = Some(log);
        self.history_policy = policy;
        self
    }

    /// Send push notifications for private messages that arrive for
    /// someone who isn't watching. Without a gateway nothing is sent,
    /// which is what a server that has configured no push gets.
    ///
    /// It does nothing useful without an inbox: the rule is computed on
    /// the stored-message path, and a push about a message that was never
    /// stored is a notification about nothing.
    pub fn with_notifications(
        mut self,
        gateway: Arc<dyn crate::notify::NotificationGateway>,
    ) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// The device registry (`docs/webpush-gateway.md` §2).
    ///
    /// The domain keeps it for the obligations a mailbox owes — linking,
    /// deletion and rotation move or drop devices exactly as they move
    /// mail and subscriptions — and for the expiry sweep. Sending is the
    /// gateway's, and a gateway is given the same `Arc`.
    pub fn with_devices(mut self, devices: Arc<dyn crate::push::PushStore>) -> Self {
        self.devices = Some(devices);
        self
    }

    /// `[push]`'s limits on a registration (`docs/webpush-gateway.md` §2,
    /// §6). The defaults without it are the configuration's defaults.
    pub fn with_push_policy(mut self, policy: crate::push::PushPolicy) -> Self {
        self.push_policy = policy;
        self
    }

    /// Register a new session and allocate its uid. The session is not yet
    /// visible (no join broadcast) — that's [`Core::announce`], after the
    /// login flow decides the final name/icon. The returned receiver is the
    /// session's event feed; events start arriving immediately, which is
    /// fine — a client merges user-change events it receives before its
    /// user-list fetch.
    ///
    /// Returns `None` when all 65535 uids are in use, or when the transport identity is
    /// one the operator has revoked. The frontends check revocation
    /// before they get here and say so; this is the backstop for a socket
    /// that authenticated before a revocation arrived, and it is asked
    /// under the roster lock so a revocation's sweep cannot miss a
    /// session that attaches while it runs.
    pub fn attach(&self, info: AttachInfo) -> Option<(Uid, Events)> {
        let mut r = self.roster.lock().unwrap();
        if info
            .transport
            .identity
            .as_ref()
            .is_some_and(|tag| self.revoked.read().unwrap().refuses(tag))
        {
            return None;
        }
        let uid = r.next_uid()?;
        r.last_serial += 1;
        let serial = r.last_serial;
        let (tx, conn, rx) = Events::channel(&self.queue_budget);
        r.users.insert(
            uid,
            UserSession {
                serial,
                info: UserInfo {
                    uid,
                    transport: info.transport,
                    nick: info.nick,
                    icon: info.icon,
                    system: info.system,
                    admin: info.admin,
                    status: SessionStatus::Active,
                    avatar: None,
                },
                access: info.access,
                login: info.login,
                addr: info.addr,
                connected_at: Instant::now(),
                can_detach: info.can_detach,
                kicked: false,
                has_inbox: info.has_inbox,
                attach_news: info.attach_news,
                set_avatar: info.set_avatar,
                moderate: info.moderate,
                can_spam: info.can_spam,
                flood: Default::default(),
                voice_flood: Default::default(),
                requests: crate::RateBucket::new(
                    self.request_limits.requests,
                    self.request_limits.requests_per,
                    Instant::now(),
                ),
                is_person: info.is_person,
                reads_on_delivery: info.reads_on_delivery,
                system: info.system,
                identity: info.identity,
                history_refill: Instant::now(),
                history_tokens: 10.0,
                search_refill: Instant::now(),
                search_tokens: f64::from(self.news_policy.search_per_minute),
                visible: false,
                avatar: None,
                outbox: Outbox::live(tx, conn),
            },
        );
        Some((uid, rx))
    }

    /// Make an attached session visible and broadcast its join to everyone
    /// else. Idempotent.
    pub fn announce(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return;
        };
        if sess.visible {
            return;
        }
        sess.visible = true;
        let ev = Event::Joined(sess.info.clone());
        r.broadcast(&ev, Some(uid));
    }

    /// Update a session's nick and/or icon. Broadcasts a change event (to
    /// everyone, echo included) only if something actually changed and the
    /// session is visible. Returns whether anything changed.
    pub fn update(&self, uid: Uid, nick: Option<String>, icon: Option<u16>) -> bool {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return false;
        };
        let mut changed = false;
        if let Some(n) = nick {
            if sess.info.nick != n {
                sess.info.nick = n;
                changed = true;
            }
        }
        if let Some(i) = icon {
            if sess.info.icon != i {
                sess.info.icon = i;
                changed = true;
            }
        }
        if changed && sess.visible {
            let ev = Event::Changed(sess.info.clone());
            r.broadcast(&ev, None);
        }
        changed
    }

    /// End a session outright: leave every private chat (announcing the
    /// parts), remove from the roster, broadcast the part. The legacy
    /// frontend calls this when its socket dies; `logout` and moderation
    /// use it too.
    pub fn end_session(&self, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        r.end_session(uid);
    }

    /// The attached transport died. If the account may detach (and the
    /// per-address cap allows), the session parks `Detached`, buffering
    /// events for a resume, and everyone sees the status change; otherwise
    /// the session ends as if [`Core::end_session`] were called.
    ///
    /// Returns `true` when the session survives detached.
    pub fn connection_lost(&self, uid: Uid, max_detached_per_addr: usize) -> bool {
        let mut r = self.roster.lock().unwrap();
        self.lose(&mut r, uid, max_detached_per_addr)
    }

    fn lose(&self, r: &mut RosterInner, uid: Uid, max_detached_per_addr: usize) -> bool {
        let Some(sess) = r.users.get_mut(&uid) else {
            return false;
        };
        // A revoked key's session never parks: its `Kicked` may not have
        // reached the frontend before the socket failed, and a detached
        // session would keep a resume token alive for whoever stole it.
        if !sess.can_detach || sess.kicked || self.refuses_session(sess) {
            r.end_session(uid);
            return false;
        }
        // Buffer first, *then* leave voice. A detached session's media
        // path is dead or about to be — the UDP flow went with the
        // control connection, and a client that resumes re-joins voice
        // explicitly — so the departure has to happen here. But the
        // status announcing it is the one event of this whole teardown
        // the resuming client must see: without it (docs/voice.md §8)
        // the client comes back to a voice UI that is live with nothing
        // behind it. Sent while the sink is still `Live` it would go to
        // the socket that just died. So the order is load-bearing, and
        // it is also what makes the buffer's voice content exactly the
        // tail of this departure and nothing else.
        // A connection that lost events to lagging has nothing a resume
        // could replay from: the buffer starts broken.
        let lagged = matches!(sess.outbox.sink, Sink::Lagged(_));
        sess.outbox.sink = Sink::Buffering {
            since: Instant::now(),
            start_seq: sess.outbox.next_seq,
            buf: VecDeque::new(),
            share: self.queue_budget.share(),
            broken: lagged,
        };
        let addr = sess.addr;
        r.voice_part(uid);
        if !r.users.contains_key(&uid) {
            return false;
        }
        r.set_status(uid, SessionStatus::Detached);

        // Per-address backstop: a spammer with detach permission still
        // can't park an unbounded crowd. Oldest detached at this address
        // goes first (docs/hotline-ng.md §2).
        if let Some(addr) = addr {
            loop {
                let mut detached: Vec<(Uid, Instant)> = r
                    .users
                    .iter()
                    .filter(|(_, s)| s.addr == Some(addr))
                    .filter_map(|(u, s)| match s.outbox.sink {
                        Sink::Buffering { since, .. } => Some((*u, since)),
                        Sink::Live(..) | Sink::Lagged(_) => None,
                    })
                    .collect();
                if detached.len() <= max_detached_per_addr {
                    break;
                }
                detached.sort_by_key(|(_, since)| *since);
                let (oldest, _) = detached[0];
                r.end_session(oldest);
            }
        }
        true
    }

    /// Re-attach a connection to a detached (or live — takeover) session.
    pub fn resume(&self, uid: Uid, last_seq: u64) -> Resume {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return Resume::Gone;
        };
        // The backstop to `connection_lost`'s check: a token is no way
        // back for a key revoked since it was issued, or into a session
        // that was kicked while another connection held it.
        if sess.kicked || self.refuses_session(sess) {
            r.end_session(uid);
            return Resume::Gone;
        }
        let (tx, conn, rx) = Events::channel(&self.queue_budget);
        let old = std::mem::replace(&mut sess.outbox.sink, Sink::Live(tx, conn));
        let next_seq = sess.outbox.next_seq;
        let outcome = match old {
            Sink::Buffering {
                start_seq,
                buf,
                broken,
                ..
            } => {
                if broken || last_seq + 1 < start_seq || last_seq + 1 > next_seq {
                    Resume::ResyncRequired(rx)
                } else {
                    let replay: Vec<SeqEvent> =
                        buf.into_iter().filter(|se| se.seq > last_seq).collect();
                    Resume::Replayed(rx, replay)
                }
            }
            // Takeover of a live session: the old channel's sender is gone,
            // so the old connection sees a closed event stream and shuts
            // down ("last device wins"). Events already sent to the old
            // channel can't be replayed.
            Sink::Live(..) => {
                if last_seq + 1 == next_seq {
                    Resume::Replayed(rx, Vec::new())
                } else {
                    Resume::ResyncRequired(rx)
                }
            }
            // Taking over a connection that lagged: what it lost is lost.
            Sink::Lagged(_) => Resume::ResyncRequired(rx),
        };
        r.set_status(uid, SessionStatus::Active);
        outcome
    }

    /// End every detached session whose grace has lapsed. The binary runs
    /// this on an interval. Returns how many ended.
    pub fn sweep_detached(&self, grace: Duration) -> usize {
        let mut r = self.roster.lock().unwrap();
        let now = Instant::now();
        let lapsed: Vec<Uid> = r
            .users
            .iter()
            .filter_map(|(u, s)| match s.outbox.sink {
                Sink::Buffering { since, .. } if now.duration_since(since) >= grace => Some(*u),
                _ => None,
            })
            .collect();
        let n = lapsed.len();
        for uid in lapsed {
            r.end_session(uid);
        }
        n
    }

    /// One session's presence state, or `None` when no session holds the
    /// uid. The notify decision reads it (see [`crate::notify`]).
    pub fn status_of(&self, uid: Uid) -> Option<SessionStatus> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.info.status)
    }

    /// Who is on the roster, counted, for a metrics scrape. One pass
    /// under the lock, nothing cloned.
    pub fn census(&self) -> Census {
        let r = self.roster.lock().unwrap();
        let mut c = Census {
            chats: r.chats.len(),
            ..Census::default()
        };
        for sess in r.users.values() {
            if sess.info.system {
                c.system += 1;
                continue;
            }
            if let Sink::Live(tx, conn) = &sess.outbox.sink {
                let bytes = conn.share.held();
                c.live += tx.max_capacity() - tx.capacity();
                c.live_bytes += bytes;
                c.live_bytes_max = c.live_bytes_max.max(bytes);
            }
            if !sess.visible {
                c.hidden += 1;
                continue;
            }
            match &sess.outbox.sink {
                Sink::Live(..) => c.attached += 1,
                Sink::Lagged(_) => {
                    c.attached += 1;
                    c.lagging += 1;
                }
                Sink::Buffering { buf, broken, .. } => {
                    c.detached += 1;
                    c.broken += usize::from(*broken);
                    c.buffered += buf.len();
                    c.buffered_max = c.buffered_max.max(buf.len());
                }
            }
        }
        c
    }

    /// Did this session's connection fall [`LIVE_QUEUE_CAP`] events
    /// behind? What a frontend asks when its event stream ends: if so, the
    /// client is not keeping up and the connection is to be dropped as
    /// lost (`slow_consumer`), rather than having been taken over.
    pub fn is_lagging(&self, uid: Uid) -> bool {
        self.roster
            .lock()
            .unwrap()
            .users
            .get(&uid)
            .is_some_and(|s| matches!(s.outbox.sink, Sink::Lagged(_)))
    }

    /// [`Core::connection_lost`], asked by the connection that lost it:
    /// `None`, and nothing done, when `events` is no longer the session's
    /// connection — it was taken over, and the session belongs to the
    /// connection that took it. Without this, an old connection that
    /// failed while draining would detach the new one out from under it.
    pub fn connection_lost_from(
        &self,
        events: &Events,
        uid: Uid,
        max_detached_per_addr: usize,
    ) -> Option<bool> {
        // One hold of the lock for the look and the act, so that a resume
        // cannot take the session over in between.
        let mut r = self.roster.lock().unwrap();
        let ours = r.users.get(&uid).is_some_and(|s| match &s.outbox.sink {
            Sink::Live(_, c) | Sink::Lagged(c) => Arc::ptr_eq(c, &events.conn),
            Sink::Buffering { .. } => false,
        });
        ours.then(|| self.lose(&mut r, uid, max_detached_per_addr))
    }

    /// Is this session currently detached? (Moderation and tests.)
    pub fn is_detached(&self, uid: Uid) -> bool {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .is_some_and(|s| matches!(s.outbox.sink, Sink::Buffering { .. }))
    }

    /// The visible users, in uid order (stable output for lists and tests).
    pub fn snapshot(&self) -> Vec<UserInfo> {
        let r = self.roster.lock().unwrap();
        let mut v: Vec<_> = r
            .users
            .values()
            .filter(|s| s.visible)
            .map(|s| s.info.clone())
            .collect();
        v.sort_by_key(|u| u.uid);
        v
    }

    /// One attached user's info, announced or not — the login-completion
    /// path reads it *before* the session becomes visible. (Use
    /// [`Core::user_details`] when visibility must gate the answer.)
    pub fn user(&self, uid: Uid) -> Option<UserInfo> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.info.clone())
    }

    /// The fuller view of a *visible* user (the user-info op).
    pub fn user_details(&self, uid: Uid) -> Option<UserDetails> {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .filter(|s| s.visible)
            .map(|s| UserDetails {
                info: s.info.clone(),
                login: s.login.clone(),
                addr: s.addr,
                connected_at: s.connected_at,
            })
    }

    /// The session's serial — the anti-uid-recycling token for external
    /// registries. `None` when no session holds the uid.
    pub fn session_serial(&self, uid: Uid) -> Option<u64> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.serial)
    }

    /// The last event seq this session has emitted (0 if none yet) — what
    /// a fresh sync reports so the client can resume from there.
    pub fn current_seq(&self, uid: Uid) -> Option<u64> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.outbox.next_seq - 1)
    }

    /// Is there a durable inbox at all? Frontends advertise the feature
    /// on this, and it is what a client feature-detects against.
    pub fn inbox_enabled(&self) -> bool {
        self.inbox.is_some()
    }

    pub fn history_enabled(&self) -> bool {
        self.history.is_some()
    }

    pub fn history_policy(&self) -> Option<crate::history::HistoryPolicy> {
        self.history.as_ref().map(|_| self.history_policy)
    }

    /// The public chat subject.
    pub fn public_subject(&self) -> String {
        self.roster.lock().unwrap().public_subject.clone()
    }
}

impl UserSession {
    /// This session's mailbox key: its identity fingerprint where it has
    /// one, its login where it does not. See [`crate::inbox::Mailbox`].
    pub(crate) fn mailbox(&self) -> crate::inbox::Mailbox {
        crate::inbox::Mailbox {
            login: self.login.clone(),
            fingerprint: self.identity,
        }
    }
}

/// Convenience for chat delivery: does this session receive public chat?
pub(crate) fn reads_public_chat(sess: &UserSession) -> bool {
    sess.access.has(bit::READ_CHAT)
}

/// Is this session's outbox buffering (i.e. detached)? For moderation
/// paths inside the lock.
pub(crate) fn is_buffering(sess: &UserSession) -> bool {
    matches!(sess.outbox.sink, Sink::Buffering { .. })
}

/// Does an event pushed to this session now reach a connection? Not when
/// it is detached, and not when its connection has been cut off for
/// falling behind and is on its way out: what is decided on delivery —
/// mail stamped delivered, a notification skipped — must not be decided
/// on a sink that drops.
pub(crate) fn is_live(sess: &UserSession) -> bool {
    matches!(sess.outbox.sink, Sink::Live(..))
}

#[cfg(test)]
pub(crate) fn test_attach(core: &Core, nick: &str, access: AccessBits) -> (Uid, Events) {
    let (uid, rx) = core
        .attach(AttachInfo {
            nick: nick.to_string(),
            icon: 1,
            admin: false,
            access,
            login: nick.to_string(),
            addr: None,
            can_detach: false,
            transport: Transport::default(),
            has_inbox: false,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            is_person: false,
            reads_on_delivery: false,
            identity: None,
            system: false,
        })
        .unwrap();
    core.announce(uid);
    (uid, rx)
}

#[cfg(test)]
pub(crate) fn drain(rx: &mut Events) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(se) = rx.try_recv() {
        out.push(se.event);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ng_attach(core: &Core, nick: &str, addr: &str) -> (Uid, Events) {
        let (uid, rx) = core
            .attach(AttachInfo {
                nick: nick.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_CHAT),
                login: nick.to_string(),
                addr: Some(addr.parse().unwrap()),
                can_detach: true,
                transport: Transport::default(),
                has_inbox: true,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    #[test]
    fn join_is_broadcast_to_others_not_self() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (_b, mut rx_b) = test_attach(&core, "bob", AccessBits::empty());

        let evs = drain(&mut rx_a);
        assert_eq!(evs.len(), 1);
        assert!(matches!(&evs[0], Event::Joined(u) if u.nick == "bob"));
        assert!(drain(&mut rx_b).is_empty());
    }

    #[test]
    fn seq_numbers_are_monotonic_and_gapless_from_one() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        for _ in 0..3 {
            let (b, _rb) = test_attach(&core, "x", AccessBits::empty());
            core.end_session(b);
        }
        let seqs: Vec<u64> = std::iter::from_fn(|| rx_a.try_recv().ok())
            .map(|se| se.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn change_echoes_to_everyone_and_only_on_diff() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());

        assert!(!core.update(a, Some("alice".into()), Some(1)));
        assert!(drain(&mut rx_a).is_empty());

        assert!(core.update(a, Some("al".into()), None));
        let evs = drain(&mut rx_a);
        assert!(matches!(&evs[0], Event::Changed(u) if u.nick == "al" && u.uid == a));
    }

    #[test]
    fn part_reaches_survivors_and_frees_the_uid_slot() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (b, _rx_b) = test_attach(&core, "bob", AccessBits::empty());
        drain(&mut rx_a);

        core.end_session(b);
        let evs = drain(&mut rx_a);
        assert_eq!(evs, vec![Event::Parted(b)]);
        assert_eq!(core.snapshot().len(), 1);
    }

    #[test]
    fn unannounced_sessions_are_invisible_and_part_silently() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (b, _rx_b) = core
            .attach(AttachInfo {
                nick: "ghost".into(),
                icon: 2,
                admin: false,
                access: AccessBits::empty(),
                login: "ghost".into(),
                addr: None,
                can_detach: false,
                transport: Transport::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                is_person: false,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();

        assert_eq!(core.snapshot().len(), 1);
        core.end_session(b);
        assert!(drain(&mut rx_a).is_empty());
    }

    #[test]
    fn uids_are_sequential_and_skip_zero_and_live_ids() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, "a", AccessBits::empty());
        let (b, _rb) = test_attach(&core, "b", AccessBits::empty());
        assert_eq!((a, b), (1, 2));
        core.end_session(a);
        let (c, _rc) = test_attach(&core, "c", AccessBits::empty());
        // Sequential, not first-free: c gets 3, not the freed 1.
        assert_eq!(c, 3);
    }

    #[test]
    fn user_details_carry_login_and_visibility_gate() {
        let core = Core::new();
        let (a, _ra) = test_attach(&core, "alice", AccessBits::empty());
        let d = core.user_details(a).unwrap();
        assert_eq!(d.login, "alice");
        assert_eq!(d.info.status, SessionStatus::Active);
    }

    #[test]
    fn non_ascii_nicks_are_preserved_verbatim() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (_b, _rx_b) = test_attach(&core, "Мишенька 🎈", AccessBits::empty());
        let evs = drain(&mut rx_a);
        assert!(matches!(&evs[0], Event::Joined(u) if u.nick == "Мишенька 🎈"));
    }

    // --- Detach / resume ------------------------------------------------

    #[test]
    fn detach_buffers_and_resume_replays_the_gap() {
        let core = Core::new();
        let (a, mut rx_a) = ng_attach(&core, "app", "10.0.0.1");
        let (b, mut rx_b) = ng_attach(&core, "buddy", "10.0.0.2");
        // Read what a has seen so far (buddy's join) to learn its last_seq
        // — the client-side bookkeeping the resume protocol relies on.
        let seen: Vec<SeqEvent> = std::iter::from_fn(|| rx_a.try_recv().ok()).collect();
        let last_seq = seen.last().map_or(0, |se| se.seq);
        assert_eq!(last_seq, 1);

        assert!(core.connection_lost(a, 8));
        assert!(core.is_detached(a));
        // Others see the status flip to detached.
        assert!(matches!(
            drain(&mut rx_b).as_slice(),
            [Event::Changed(u)] if u.uid == a && u.status == SessionStatus::Detached
        ));

        // Traffic while detached buffers.
        core.chat_public(b, "you there?".into(), 0, None).unwrap();
        core.chat_public(b, "hello?".into(), 0, None).unwrap();

        let Resume::Replayed(mut rx_a2, replay) = core.resume(a, last_seq) else {
            panic!("resume should replay");
        };
        // The replay: the status-change echo + both chat lines, gapless.
        let texts: Vec<String> = replay
            .iter()
            .filter_map(|se| match &se.event {
                Event::Chat { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(texts, vec!["you there?", "hello?"]);
        let seqs: Vec<u64> = replay.iter().map(|se| se.seq).collect();
        assert_eq!(
            seqs,
            (last_seq + 1..=last_seq + replay.len() as u64).collect::<Vec<_>>()
        );

        // Live again: buddy sees Active (after its own two chat echoes),
        // and new traffic flows on the channel.
        let evs = drain(&mut rx_b);
        assert!(matches!(
            evs.last(),
            Some(Event::Changed(u)) if u.status == SessionStatus::Active
        ));
        core.chat_public(b, "welcome back".into(), 0, None).unwrap();
        assert!(drain(&mut rx_a2)
            .iter()
            .any(|e| matches!(e, Event::Chat { text, .. } if text == "welcome back")));
    }

    #[test]
    fn no_permission_means_connection_loss_ends_the_session() {
        let core = Core::new();
        let (_a, mut rx_a) = test_attach(&core, "alice", AccessBits::empty());
        let (g, _rx_g) = test_attach(&core, "guest", AccessBits::empty());
        drain(&mut rx_a);

        assert!(!core.connection_lost(g, 8)); // can_detach = false
        assert_eq!(drain(&mut rx_a), vec![Event::Parted(g)]);
        assert!(matches!(core.resume(g, 0), Resume::Gone));
    }

    #[test]
    fn overflow_breaks_the_buffer_and_forces_resync() {
        let core = Core::new();
        let (a, mut rx_a) = ng_attach(&core, "app", "10.0.0.1");
        let (b, _rx_b) = ng_attach(&core, "chatty", "10.0.0.2");
        let last_seq = std::iter::from_fn(|| rx_a.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(core.connection_lost(a, 8));

        for i in 0..(OUTBOX_BUFFER_CAP + 10) {
            core.chat_public(b, format!("spam {i}"), 0, None).unwrap();
        }
        match core.resume(a, last_seq) {
            Resume::ResyncRequired(_rx) => {}
            _ => panic!("overflowed buffer must demand resync"),
        }
    }

    #[test]
    fn stale_last_seq_predating_the_buffer_forces_resync() {
        let core = Core::new();
        let (a, mut rx_a) = ng_attach(&core, "app", "10.0.0.1");
        let (_b, _rx_b) = ng_attach(&core, "buddy", "10.0.0.2");
        // a has seen events but claims last_seq 0 — those live deliveries
        // predate the buffer and cannot be replayed.
        assert!(rx_a.try_recv().is_ok());
        assert!(core.connection_lost(a, 8));
        match core.resume(a, 0) {
            Resume::ResyncRequired(_rx) => {}
            _ => panic!("pre-buffer last_seq must demand resync"),
        }
    }

    #[test]
    fn a_client_that_falls_a_channel_behind_is_cut_off_and_resumes_into_a_resync() {
        let core = Core::new();
        let (slow, mut rx) = ng_attach(&core, "slow", "10.0.0.1");
        let (busy, mut busy_rx) = ng_attach(&core, "busy", "10.0.0.2");
        // Everything `busy` does is an event for `slow`, which reads none
        // of them; `busy` hears its own too, and keeps up.
        for i in 0..LIVE_QUEUE_CAP + 10 {
            core.update(busy, Some(format!("n{i}")), None);
            while busy_rx.try_recv().is_ok() {}
        }
        assert!(core.is_lagging(slow));
        assert!(!core.is_lagging(busy));
        assert_eq!(core.census().lagging, 1);
        // What was queued is still there to read, in order; then the
        // stream ends, where a takeover would end it too.
        let mut seqs = Vec::new();
        while let Ok(se) = rx.try_recv() {
            seqs.push(se.seq);
        }
        assert_eq!(seqs.len(), LIVE_QUEUE_CAP);
        assert!(seqs.windows(2).all(|w| w[1] == w[0] + 1));
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        // The events it missed still took their seqs.
        let before = core.current_seq(slow).unwrap();
        core.update(busy, Some("more".into()), None);
        assert_eq!(core.current_seq(slow).unwrap(), before + 1);

        // Its connection goes as lost; the session detaches with nothing
        // it could replay, so the resume is a resync.
        let last = *seqs.last().unwrap();
        assert!(core.connection_lost(slow, 2));
        assert!(!core.is_lagging(slow));
        assert!(matches!(core.resume(slow, last), Resume::ResyncRequired(_)));
    }

    #[test]
    fn big_lines_cut_off_on_bytes_long_before_the_event_count() {
        let core = Core::new();
        let (_slow, mut slow_rx) = ng_attach(&core, "slow", "10.0.0.1");
        let (_steady, mut steady_rx) = ng_attach(&core, "steady", "10.0.0.2");
        let (talker, mut talker_rx) = ng_attach(&core, "talker", "10.0.0.3");
        let line = "x".repeat(4000);
        // The joins it has heard so far, so the budget starts empty.
        while slow_rx.try_recv().is_ok() {}
        let mut sent = 0;
        while !slow_rx.lagged() {
            core.chat_public(talker, line.clone(), 0, None).unwrap();
            sent += 1;
            // These two keep up: what they have taken off their channel is
            // off their budget too.
            while talker_rx.try_recv().is_ok() {}
            while steady_rx.try_recv().is_ok() {}
            assert!(sent < LIVE_QUEUE_CAP, "never cut off on bytes");
        }
        let weight = Event::Chat {
            cid: 0,
            from: core.user(talker).unwrap(),
            text: line.clone(),
            style: 0,
            id: None,
            at: SystemTime::now(),
            media: None,
        }
        .weight();
        assert_eq!(
            sent - 1,
            LIVE_QUEUE_BYTES / weight,
            "cut at the byte budget"
        );
        assert!(!steady_rx.lagged() && !talker_rx.lagged());
        // What was queued for it is still there, then the end.
        let mut got = 0;
        while slow_rx.try_recv().is_ok() {
            got += 1;
        }
        assert_eq!(got, sent - 1);
    }

    /// Connections each well inside their own bounds are cut off once
    /// what they hold together passes the server's budget: the ones
    /// behind, and not the ones keeping up.
    #[test]
    fn past_the_server_budget_the_connections_behind_are_cut_off() {
        let budget = 64 << 10;
        let core = Core::new().with_queue_budget(budget);
        let mut stalled: Vec<_> = (0..3)
            .map(|i| ng_attach(&core, &format!("stalled{i}"), "10.0.0.1").1)
            .collect();
        let (_reader, mut reader_rx) = ng_attach(&core, "reader", "10.0.0.2");
        let (talker, mut talker_rx) = ng_attach(&core, "talker", "10.0.0.3");
        for rx in stalled.iter_mut() {
            while rx.try_recv().is_ok() {}
        }
        let line = "x".repeat(1000);
        let mut sent = 0;
        while !stalled.iter().all(Events::lagged) {
            core.chat_public(talker, line.clone(), 0, None).unwrap();
            sent += 1;
            while talker_rx.try_recv().is_ok() {}
            while reader_rx.try_recv().is_ok() {}
            assert!(
                core.queue_budget().held() <= budget + 2 * line.len() + 512,
                "held to the budget"
            );
            assert!(sent < 1000, "never cut off by the budget");
        }
        // Each was far inside its own bounds when it went.
        assert!(sent * 1100 < LIVE_QUEUE_BYTES && sent < LIVE_QUEUE_CAP);
        assert!(!reader_rx.lagged() && !talker_rx.lagged());
        // And what they held goes back once their connections end.
        let uids: Vec<Uid> = core.snapshot().iter().map(|u| u.uid).collect();
        drop(stalled);
        for uid in uids {
            if core.is_lagging(uid) {
                core.end_session(uid);
            }
        }
        assert!(core.queue_budget().held() < 4096);
    }

    /// A detached session's buffer draws on the budget too, and past it
    /// breaks, as it does past its count: the resume is a resync.
    #[test]
    fn a_detached_buffer_past_the_server_budget_breaks() {
        let core = Core::new().with_queue_budget(16 << 10);
        let (away, _away_rx) = ng_attach(&core, "away", "10.0.0.1");
        let (talker, mut talker_rx) = ng_attach(&core, "talker", "10.0.0.2");
        assert!(core.connection_lost(away, 2));
        let line = "x".repeat(1000);
        for _ in 0..(OUTBOX_BUFFER_CAP / 4) {
            core.chat_public(talker, line.clone(), 0, None).unwrap();
            while talker_rx.try_recv().is_ok() {}
        }
        let c = core.census();
        assert_eq!((c.detached, c.broken, c.buffered), (1, 1, 0));
        assert!(core.queue_budget().held() < 4096, "the buffer gave it back");
        assert!(matches!(core.resume(away, 0), Resume::ResyncRequired(_)));
    }

    #[test]
    fn logins_past_the_gate_are_refused_until_a_place_frees() {
        let core = Core::new().with_logins_in_flight(2);
        let a = core.admit_login(None).expect("a place");
        let _b = core.admit_login(None).expect("a place");
        assert!(core.admit_login(None).is_none(), "the gate is full");
        drop(a);
        assert!(core.admit_login(None).is_some(), "and a place came back");
    }

    #[test]
    fn an_exempt_address_has_no_share_of_the_login_places_to_run_out_of() {
        let core = Core::new().with_logins_in_flight(8);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..8)
            .map(|_| core.admit_login(Some(loopback)).expect("a place"))
            .collect();
        assert!(
            core.admit_login(Some(loopback)).is_none(),
            "the gate is full"
        );
        drop(held);
    }

    #[test]
    fn one_address_holds_at_most_a_quarter_of_the_places() {
        let core = Core::new().with_logins_in_flight(8);
        let one: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let a = core.admit_login(Some(one)).expect("a place");
        let _b = core.admit_login(Some(one)).expect("a place");
        assert!(core.admit_login(Some(one)).is_none(), "its share is taken");
        assert!(core.admit_login(Some(other)).is_some(), "not everyone's");
        drop(a);
        assert!(core.admit_login(Some(one)).is_some(), "and it came back");
    }

    #[test]
    fn a_login_known_to_be_a_persons_gives_its_address_its_share_back() {
        let core = Core::new().with_logins_in_flight(8);
        let one: IpAddr = "10.0.0.1".parse().unwrap();
        let mut a = core.admit_login(Some(one)).expect("a place");
        let mut b = core.admit_login(Some(one)).expect("a place");
        assert!(core.admit_login(Some(one)).is_none(), "its share is taken");
        a.logged_in();
        b.logged_in();
        let held: Vec<_> = (0..2)
            .map(|_| core.admit_login(Some(one)).expect("the share is back"))
            .collect();
        assert!(core.admit_login(Some(one)).is_none());
        // Each still holds its place among everyone's.
        let others: Vec<_> = (0..4)
            .filter_map(|i| core.admit_login(Some(IpAddr::from([10, 0, 1, i]))))
            .collect();
        assert_eq!(others.len(), 4);
        assert!(
            core.admit_login(Some("10.0.2.1".parse().unwrap()))
                .is_none(),
            "the gate is full"
        );
        drop((a, b, held, others));
    }

    #[test]
    fn only_the_connection_that_holds_a_session_can_lose_it() {
        let core = Core::new();
        let (uid, old) = ng_attach(&core, "two-devices", "10.0.0.1");
        // A second connection takes the session over; the first drains
        // what it was sent and then fails, as a dead socket does.
        let new = match core.resume(uid, 0) {
            Resume::Replayed(rx, _) | Resume::ResyncRequired(rx) => rx,
            Resume::Gone => panic!("the session is there"),
        };
        assert_eq!(core.connection_lost_from(&old, uid, 2), None);
        assert!(
            !core.is_detached(uid),
            "the old connection detached the new"
        );
        // The new connection's own loss still counts.
        assert_eq!(core.connection_lost_from(&new, uid, 2), Some(true));
        assert!(core.is_detached(uid));
    }

    #[test]
    fn a_lag_is_the_connections_that_lagged_and_no_other() {
        let core = Core::new();
        let (uid, old) = ng_attach(&core, "slow", "10.0.0.1");
        let (busy, mut busy_rx) = ng_attach(&core, "busy", "10.0.0.2");
        let new = match core.resume(uid, 0) {
            Resume::Replayed(rx, _) | Resume::ResyncRequired(rx) => rx,
            Resume::Gone => panic!("the session is there"),
        };
        for i in 0..LIVE_QUEUE_CAP + 10 {
            core.update(busy, Some(format!("n{i}")), None);
            while busy_rx.try_recv().is_ok() {}
        }
        // The new connection lagged; the old one, taken over before it
        // saw any of this, did not, and must not read the news as its own.
        assert!(new.lagged());
        assert!(!old.lagged());
        assert_eq!(core.connection_lost_from(&old, uid, 2), None);
        assert_eq!(core.connection_lost_from(&new, uid, 2), Some(true));
    }

    #[test]
    fn a_lag_wakes_whoever_waits_on_it() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let core = Core::new();
            let (_slow, rx) = ng_attach(&core, "slow", "10.0.0.1");
            let (busy, mut busy_rx) = ng_attach(&core, "busy", "10.0.0.2");
            let lag = rx.lag();
            let waiting = tokio::time::timeout(std::time::Duration::from_millis(50), lag.wait());
            assert!(waiting.await.is_err(), "no lag yet");
            for i in 0..LIVE_QUEUE_CAP + 1 {
                core.update(busy, Some(format!("n{i}")), None);
                while busy_rx.try_recv().is_ok() {}
            }
            tokio::time::timeout(std::time::Duration::from_secs(1), lag.wait())
                .await
                .expect("the lag is signalled");
        });
    }

    #[test]
    fn census_counts_attached_detached_and_what_the_detached_hold() {
        let core = Core::new();
        assert_eq!(core.census(), Census::default());
        let (a, _ra) = ng_attach(&core, "one", "10.0.0.1");
        let (b, _rb) = ng_attach(&core, "two", "10.0.0.2");
        let (third, _rc) = ng_attach(&core, "three", "10.0.0.3");
        assert!(core.connection_lost(a, 2));
        assert!(core.connection_lost(b, 2));
        // What becomes of `b` is buffered for `a`, and `b` is gone.
        core.end_session(b);
        let c = core.census();
        assert_eq!((c.attached, c.detached, c.hidden, c.system), (1, 1, 0, 0));
        assert!(c.buffered > 0);
        assert_eq!((c.buffered_max, c.broken), (c.buffered, 0));

        // Overflow breaks the buffer, which then holds nothing.
        for i in 0..=OUTBOX_BUFFER_CAP {
            core.update(third, Some(format!("n{i}")), None);
        }
        let c = core.census();
        assert_eq!((c.detached, c.broken, c.buffered), (1, 1, 0));
    }

    #[test]
    fn per_address_cap_ends_the_oldest_detached() {
        let core = Core::new();
        let (a1, _r1) = ng_attach(&core, "one", "10.0.0.9");
        let (a2, _r2) = ng_attach(&core, "two", "10.0.0.9");
        let (a3, _r3) = ng_attach(&core, "three", "10.0.0.9");

        assert!(core.connection_lost(a1, 2));
        assert!(core.connection_lost(a2, 2));
        // Third detach at the same address exceeds the cap of 2 → the
        // oldest (a1) is ended.
        assert!(core.connection_lost(a3, 2));
        assert!(matches!(core.resume(a1, 0), Resume::Gone));
        assert!(core.is_detached(a2));
        assert!(core.is_detached(a3));
    }

    #[test]
    fn sweep_ends_lapsed_sessions() {
        let core = Core::new();
        let (a, _ra) = ng_attach(&core, "app", "10.0.0.1");
        assert!(core.connection_lost(a, 8));
        assert_eq!(core.sweep_detached(Duration::from_secs(3600)), 0);
        assert_eq!(core.sweep_detached(Duration::ZERO), 1);
        assert!(matches!(core.resume(a, 0), Resume::Gone));
        assert!(core.snapshot().is_empty());
    }

    #[test]
    fn takeover_replaces_the_live_channel() {
        let core = Core::new();
        let (a, mut rx_old) = ng_attach(&core, "app", "10.0.0.1");
        let (b, _rb) = ng_attach(&core, "buddy", "10.0.0.2");
        let last_seq = std::iter::from_fn(|| rx_old.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);

        let Resume::Replayed(mut rx_new, replay) = core.resume(a, last_seq) else {
            panic!("up-to-date takeover should attach cleanly");
        };
        assert!(replay.is_empty());
        // The old channel is dead; the new one gets traffic.
        core.chat_public(b, "hi".into(), 0, None).unwrap();
        assert!(rx_old.try_recv().is_err());
        assert_eq!(drain(&mut rx_new).len(), 1);
    }

    #[test]
    fn a_kicked_session_does_not_detach_when_its_socket_dies() {
        // The `Kicked` event is in the channel, but the socket failed
        // before the frontend read it (or while sending it): the kick
        // must still end the session, whatever the account's policy.
        let core = Core::new();
        let (a, _ra) = ng_attach(&core, "app", "10.0.0.1");
        core.kick(a, None).unwrap();
        assert!(!core.connection_lost(a, 8));
        assert!(matches!(core.resume(a, 0), Resume::Gone));
        assert!(core.snapshot().is_empty());
    }

    #[test]
    fn a_kicked_session_cannot_be_taken_over() {
        // Kicked while a connection holds it, and resumed from another
        // before the first connection acts on the kick: the resume must
        // not inherit the session and leave the kick in a dead channel.
        let core = Core::new();
        let (a, mut rx) = ng_attach(&core, "app", "10.0.0.1");
        let last_seq = std::iter::from_fn(|| rx.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        core.kick(a, None).unwrap();
        assert!(matches!(core.resume(a, last_seq), Resume::Gone));
        assert!(core.snapshot().is_empty());
    }
}
