//! Chat rooms, messaging, and moderation — further `impl Core` blocks over
//! the roster state.
//!
//! Structural rules (membership, invitations, chat lifecycle) are enforced
//! here; *policy* (the access bitmap) is enforced by the frontend before it
//! calls in, because policy wording belongs with the wire ("You are not
//! allowed to send chat") and future frontends may gate differently. The
//! one exception is delivery-side filtering: public chat only reaches
//! sessions whose account can read chat, mirroring the reference server.
//!
//! Private chat semantics mirror mhxd's `chat.c`: numeric refs (0 is the
//! public chat and is never in the registry), invitation is optional — any
//! member can invite, joining an un-passworded chat needs no invitation,
//! an invitation bypasses the password, the last part deletes the chat.
//! One deliberate departure from the reference: chat ids come from the OS
//! CSPRNG rather than a counter, because the id is also a voice room's
//! whole address — see `RosterInner::next_chat_id`.
//!
//! All text is UTF-8 (`String`) — see the roster module docs for the
//! conversion rules at the legacy edge.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tracing::{debug, warn};

use crate::history::{HistoryPage, HistoryQuery, LineFlags, LineHome, NewLine, Signature};
use crate::inbox::{
    Cursor, Delivery, InboxCounts, Mailbox, MessageGuid, MessageId, MessageKind, MessageRef,
    MessageStore, NewMessage, StoreError, StoredMessage,
};
use crate::relationships::RelationshipStore;
use crate::reply::Reply;
use crate::roster::{is_live, reads_public_chat, Event, RosterInner, Uid, UserInfo};
use crate::Core;

/// Who a private message is from, resolved once under the roster lock.
struct Sender {
    uid: Uid,
    nick: String,
    /// The sender's mailbox, when the sender is durable enough to be
    /// named later — held to reply to, and held to block.
    ///
    /// An account with an inbox qualifies. So does a session carrying an
    /// identity but no inbox: under `new_accounts = guest` an identity
    /// user is a *guest session with a fingerprint*, and a fingerprint is
    /// exactly what a block can be held against. What does not qualify is
    /// a plain guest, because `guest` is a login several people share
    /// rather than an address, and there is nothing there to block that
    /// would not also block everyone else who walks through that door.
    mailbox: Option<Mailbox>,
    /// The login a recipient can *reply* to, which is not the same
    /// question as the one above. An identity user admitted as a guest
    /// has a mailbox — a fingerprint is something a block can be held
    /// against — but its login is `guest`, and `msg_login` to `guest`
    /// answers `no_such_user`. Handing that login to a client as the
    /// sender is handing it a reply button that cannot work.
    reply_login: Option<String>,
    /// What this sender's uploads are held under, and half of the set a
    /// message with an image captures: the sender's mailbox where there
    /// is one, and the session itself for a plain guest
    /// (`docs/inline-media.md` §5.1).
    principal: crate::media::Principal,
    /// Its message is stored nowhere, though its mailbox stays to be
    /// blocked by: an approved identity guest's, unless
    /// `queue_identity_guests` (`docs/instant-messaging.md` §4.1).
    live_only: bool,
}

impl Sender {
    fn resolve(r: &RosterInner, uid: Uid) -> Result<Sender, ChatError> {
        let sess = r.users.get(&uid).ok_or(ChatError::NoSuchUser)?;
        let durable = sess.has_inbox || sess.identity.is_some();
        let mailbox = durable.then(|| sess.mailbox());
        Ok(Sender {
            uid,
            nick: sess.info.nick.clone(),
            // A sender with a mailbox keeps its images across a
            // reconnect; a plain guest's are its session's, and go when
            // the session does.
            principal: match mailbox.clone() {
                Some(m) => crate::media::Principal::Mailbox(m),
                None => crate::media::Principal::Session {
                    uid,
                    serial: sess.serial,
                },
            },
            mailbox,
            reply_login: sess.has_inbox.then(|| sess.login.clone()),
            live_only: false,
        })
    }
}

/// Who a chat guid is held under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum GuidSender {
    /// The account where one person is behind it, else the identity the
    /// session proved, as the log keeps it
    /// ([`crate::history::guid_sender_key`]): a new login retries the
    /// same line.
    Kept(String),
    /// Anyone else, whose guids are its session's alone, since `guest`
    /// is a login many people share.
    Session { uid: Uid, serial: u64 },
}

/// By the fact rather than by `has_inbox`, which an operator may turn on
/// for `guest` or off for a person.
fn guid_sender(uid: Uid, sess: &crate::roster::UserSession) -> GuidSender {
    let login = sess.is_person.then_some(sess.login.as_str());
    match crate::history::guid_sender_key(login, sess.identity.as_ref()) {
        Some(key) => GuidSender::Kept(key),
        None => GuidSender::Session {
            uid,
            serial: sess.serial,
        },
    }
}

/// A stored message's image as it stands at delivery: the live handle
/// where the store still has one, and the row's own metadata with no
/// handle where it does not. Never `None` for a row that had an image —
/// "[an image was here]" is worth rendering and an empty message is not.
fn media_now(
    handles: &HashMap<Vec<u8>, crate::media::MediaRef>,
    meta: &crate::history::MediaMeta,
) -> Option<crate::media::MediaRef> {
    handles.get(&meta.id).cloned().or_else(|| {
        crate::media::MediaRef::from_meta(meta).map(|r| crate::media::MediaRef { id: None, ..r })
    })
}

/// Who it is for: a mailbox, and its session if it has one.
struct Recipient {
    uid: Option<Uid>,
    mailbox: Mailbox,
    has_inbox: bool,
    /// The other half of a media set: this account's mailbox, or the
    /// session where there is no mailbox to hold a grant.
    principal: crate::media::Principal,
}

/// Which of a mailbox's sessions a flush should hand its mail to.
enum Target {
    /// This session or nobody: a session that has just attached asking
    /// for its own mail. If it is gone again, the mail stays pending.
    Only(Uid),
    /// The session the sender named, if it is attached, and otherwise
    /// whichever is (lowest uid). A legacy user clicking a name in the
    /// user list is naming a *device*: an account with a phone on uid 2
    /// and a laptop on uid 3, both live, should hear it on the one that
    /// was clicked. §15's multi-device question, answered: prefer the
    /// named session, else the lowest attached but the sender's.
    ///
    /// With no uid the message named the account, and every attached
    /// session but the sender's is handed it: picking one would leave the
    /// device its reader is holding without it whenever another, say a
    /// forgotten tab, came first.
    Named { uid: Option<Uid>, sender: Uid },
    /// Those of these sessions still attached, but the sender's.
    Each { uids: Vec<Uid>, sender: Uid },
}

/// Every visible session owning `mailbox`, lowest uid first.
///
/// Matching is [`Mailbox`]'s rule, not a login comparison: a session
/// logged in as `alice` with identity B must not be handed mail addressed
/// to the `alice` who held that login before, and that is exactly what
/// comparing logins would do.
pub(crate) fn sessions_of(r: &RosterInner, mailbox: &Mailbox) -> Vec<Uid> {
    let mut uids: Vec<Uid> = r
        .users
        .iter()
        .filter(|(_, s)| s.visible && mailbox.matches(&s.login, s.identity.as_ref()))
        .map(|(uid, _)| *uid)
        .collect();
    uids.sort_unstable();
    uids
}

/// The sessions to hand `mailbox`'s mail to: the *attached* ones, lowest
/// uid first, or none at all.
///
/// Lowest-uid-wins over every session was wrong, and quietly. An account
/// with a detached phone on uid 5 and an attached laptop on uid 9 had
/// every message aimed at the phone, which is buffering — so nothing was
/// delivered live and the laptop learned about it at its next sync.
///
/// And no fallback to a detached session: its outbox buffer is bounded
/// and dies with the grace window, so a message put there is a message
/// stamped delivered and then lost. Mail stays pending until somebody is
/// actually holding a socket.
///
/// Never the sender's own session: a message to one's own account is
/// for its other sessions, and handed back to the one that wrote it, it
/// reads as a reply from the account and is answered to itself.
fn attached_sessions_of(r: &RosterInner, mailbox: &Mailbox, sender: Uid) -> Vec<Uid> {
    sessions_of(r, mailbox)
        .into_iter()
        .filter(|uid| *uid != sender && r.users.get(uid).is_some_and(is_live))
        .collect()
}

/// Is `uid` an attached session holding `mailbox`, as it stands now? A
/// uid resolved under an earlier hold of the roster lock may have been
/// reused since. [`Mailbox`]'s rule, as [`sessions_of`] has it: an
/// identity's session keeps its mailbox under a login it has not
/// caught up with.
fn holds(r: &RosterInner, mailbox: &Mailbox, uid: &Uid) -> bool {
    r.users
        .get(uid)
        .is_some_and(|s| mailbox.matches(&s.login, s.identity.as_ref()) && is_live(s))
}

/// Who [`Target::Named`] hands mail to: the named session if it is
/// attached, else the lowest attached of [`attached_sessions_of`]; and
/// all of them for a message that named the account.
fn named_sessions(r: &RosterInner, mailbox: &Mailbox, named: Option<Uid>, sender: Uid) -> Vec<Uid> {
    match named {
        Some(uid) if holds(r, mailbox, &uid) => vec![uid],
        Some(_) => attached_sessions_of(r, mailbox, sender)
            .into_iter()
            .take(1)
            .collect(),
        None => attached_sessions_of(r, mailbox, sender),
    }
}

/// A store that would not answer is a server-side failure, not the
/// client's fault. The detail goes to the log; the client gets the
/// generic error, like every other backend failure here.
/// Refuse a cursor `mailbox` never issued ([`ChatError::UnknownCursor`]).
fn issued(
    store: &dyn MessageStore,
    mailbox: &Mailbox,
    cursor: Option<Cursor>,
) -> Result<(), ChatError> {
    match cursor {
        Some(c) if c > store.last_cursor(mailbox).map_err(store_failed)? => {
            Err(ChatError::UnknownCursor)
        }
        _ => Ok(()),
    }
}

fn store_failed(e: StoreError) -> ChatError {
    warn!("inbox: {e}");
    ChatError::ServerError
}

fn history_store_failed(e: StoreError) -> ChatError {
    warn!("history: {e}");
    ChatError::ServerError
}

/// A private chat room. (`cid` 0 — the public chat — is represented by the
/// roster itself, not an entry here.)
#[derive(Default)]
pub(crate) struct PrivateChat {
    /// Who opened it, while that session lasts: what
    /// [`crate::ChatLimits::per_creator`] counts. Cleared when the
    /// session ends, so a recycled uid inherits nothing.
    pub(crate) creator: Option<Uid>,
    pub(crate) members: Vec<Uid>,
    pub(crate) invited: Vec<Uid>,
    pub(crate) subject: String,
    pub(crate) password: String,
}

/// The ban a kick places (`Core::kick_by`).
#[derive(Debug, Clone)]
pub struct KickBan {
    /// Who kicked: named on the ban as its actor.
    pub by: crate::moderation::Actor,
    pub for_: Duration,
    /// Shown to the banned client where its wire can show it.
    pub reason: String,
}

/// Why [`Core::spend_spam`] refused a transaction: its sender was
/// kicked for it, or had been already.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a spam kick's ban is placed only by `Core::place_spam_ban`"]
pub struct Flooded {
    /// The ban the kick asks for, when it asks for one: for the caller
    /// to hand to [`Core::place_spam_ban`] off the reactor, since it is
    /// a store write.
    pub ban: Option<SpamBan>,
}

/// The ban a spam kick places, chosen when the kick was made
/// (`Core::spend_spam`).
#[derive(Debug, PartialEq, Eq)]
pub struct SpamBan {
    uid: Uid,
    /// Never empty: [`Core::kick_ban_targets`], one act.
    targets: Vec<crate::ban::BanTarget>,
    for_: Duration,
}

/// A kick made ([`Core::kick_by`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kicked {
    /// The kicked session's nick, for the announcement.
    pub nick: String,
    /// Whether a ban was placed with it: the announcement says
    /// "banned" only then. A kick asked to ban may place none, when the
    /// session had nothing of its own to ban ([`Core::kick_ban_targets`])
    /// or the store refused it.
    pub banned: bool,
}

/// Is `v6` an IPv6 address a kick-ban takes alone, as /128, rather
/// than with its `ban_v6_prefix` block? Loopback and the unspecified
/// address, whose `::/64` is every other address a local client could
/// come from; and the addresses that stand for an IPv4 host, where the
/// block is every IPv4 client at once: the NAT64 well-known prefix
/// `64:ff9b::/96` (RFC 6052), which on a NAT64 or SIIT deployment is
/// where every IPv4 client appears, its local-use `64:ff9b:1::/48`
/// (RFC 8215), and the IPv4-compatible `::/96`, which holds loopback
/// and the unspecified address too. An IPv4-mapped address is an IPv4
/// one by then (`IpAddr::to_canonical`).
fn v6_stands_alone(v6: std::net::Ipv6Addr) -> bool {
    let s = v6.segments();
    let nat64 = s[..6] == [0x64, 0xff9b, 0, 0, 0, 0];
    let nat64_local = s[..3] == [0x64, 0xff9b, 1];
    let compatible = s[..6] == [0; 6];
    v6.is_loopback() || v6.is_unspecified() || nat64 || nat64_local || compatible
}

/// A public line on its way to the log and the room.
pub(crate) struct Staged {
    info: UserInfo,
    login: Option<String>,
    fingerprint: Option<[u8; 32]>,
    /// The sending session; `None` for a linked server's user, a ghost,
    /// which has no session and attaches no media.
    principal: Option<crate::media::Principal>,
    /// A ghost's key, which its logged lines are marked with.
    ghost: Option<[u8; 16]>,
    text: String,
    style: u16,
    media: Option<(crate::media::Handle, crate::media::MediaRef)>,
    at: SystemTime,
    /// The client's id for the line, and who it is held under.
    guid: Option<GuidKey>,
    signed: Option<Signature>,
    /// A signed lobby line's link form, the only form it may cross a
    /// link in (`docs/e2e-messages.md` §4.11).
    link: Option<crate::server_link::LinkForm>,
    /// What it answers. Never a ghost's: no reference crosses a link.
    re: Option<Reply>,
}

impl Staged {
    pub(crate) fn ghost(
        info: UserInfo,
        key: [u8; 16],
        text: String,
        style: u16,
        signed: Option<Signature>,
    ) -> Staged {
        Staged {
            info,
            login: None,
            fingerprint: None,
            principal: None,
            ghost: Some(key),
            text,
            style,
            media: None,
            at: SystemTime::now(),
            guid: None,
            signed,
            link: None,
            re: None,
        }
    }
}

/// The most public lines one commit takes.
const COMMIT_BATCH: usize = 256;

/// Public chat, committed in groups.
///
/// **A line at a time, the log was the ceiling.** Every line was its own
/// transaction, under the log's lock, so lines went through one commit
/// after another: with `sync = "full"` one disk sync each, a couple of
/// hundred lines a second on a fast disk, and with `normal` several pages
/// of the log written again for every line. Now a line joins a queue,
/// and whoever finds no commit under way leads one: it takes what is
/// queued, itself first, logs it in one transaction and relays it in
/// order, then hands the lead to the next line waiting, if any, and
/// returns. Lines that arrive while a commit is under way wait for the
/// next, and share it. A lone line is a batch of one, at once.
///
/// Order is the queue's, which is the order lines reached it; the log's
/// lock is taken per batch, so a redaction or a purge still falls between
/// two batches and never overtakes a line it names.
///
/// One for the lobby, room 0, and one for each room (`crate::rooms`).
#[derive(Default)]
pub(crate) struct ChatCommit {
    room: u32,
    state: Mutex<CommitState>,
    /// Kept under the room's serial and asked again there, so a repeat
    /// that waited in the queue behind its original finds it.
    recent: Mutex<RecentGuids>,
}

/// How long a line's guid is remembered, and for how many of a room's
/// lines at most: long enough for a client to notice a lost reply,
/// reconnect and send again; and bounded in count, so what a room holds
/// does not grow with how fast its senders can make up guids.
const GUID_WINDOW: Duration = Duration::from_secs(10 * 60);
const GUID_KEEP: usize = 1024;

/// The guids a room's lines were sent under lately, oldest first, each
/// with the id its line was answered and, for a signed line, what it
/// said. Shared by the room's senders, so a busy one can push out
/// another's before its window ends. Expired entries go only when the
/// room is next sent to, so a room archived or deleted keeps what it
/// held, which is no more than the bound.
#[derive(Default)]
struct RecentGuids {
    order: std::collections::VecDeque<(Instant, GuidKey)>,
    ids: HashMap<GuidKey, Remembered>,
}

/// What a line sent under a guid was answered, and what it said.
type Remembered = (Option<crate::history::LineId>, Said);

/// What a line said, as far as a signed repeat is held to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Said {
    Unsigned,
    /// The hash of a signed line's content ([`Signature::content`]).
    Signed([u8; 32]),
    /// Redacted: nothing of what it said is kept to hold a repeat to.
    Forgotten,
}

impl Said {
    fn of(signed: Option<&Signature>) -> Said {
        signed.map_or(Said::Unsigned, |s| Said::Signed(s.content))
    }
}

/// A repeat is answered as its line was, unless it is signed and says
/// something else, an unsigned line being something else: one id, one
/// message (`docs/e2e-messages.md` §3.6).
fn repeat_of(
    (id, was): Remembered,
    now: Option<&Signature>,
) -> Result<Option<crate::history::LineId>, ChatError> {
    match (was, now) {
        (_, None) | (Said::Forgotten, _) => Ok(id),
        (Said::Signed(was), Some(now)) if was == now.content => Ok(id),
        _ => Err(ChatError::Equivocation),
    }
}

/// A guid and who it is held under ([`guid_sender`]).
type GuidKey = (GuidSender, MessageGuid);

impl RecentGuids {
    /// What the line sent under `key` was answered, if that is still
    /// remembered.
    fn find(&mut self, now: Instant, key: &GuidKey) -> Option<Remembered> {
        self.expire(now);
        self.ids.get(key).copied()
    }

    fn remember(&mut self, now: Instant, key: GuidKey, id: Remembered) {
        self.expire(now);
        if self.ids.contains_key(&key) {
            return;
        }
        if self.order.len() >= GUID_KEEP {
            self.forget_oldest();
        }
        self.ids.insert(key.clone(), id);
        self.order.push_back((now, key));
    }

    fn expire(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|(at, _)| now.saturating_duration_since(*at) >= GUID_WINDOW)
        {
            self.forget_oldest();
        }
    }

    /// A redaction leaves nothing of what its lines said.
    fn forget_said(&mut self, lines: &[crate::history::LineId]) {
        for (id, said) in self.ids.values_mut() {
            if id.is_some_and(|id| lines.contains(&id)) {
                *said = Said::Forgotten;
            }
        }
    }

    fn forget_oldest(&mut self) {
        if let Some((_, key)) = self.order.pop_front() {
            self.ids.remove(&key);
        }
    }
}

#[derive(Default)]
struct CommitState {
    queue: std::collections::VecDeque<Arc<Pending>>,
    /// A commit is under way, or its leader is about to start one.
    leading: bool,
}

struct Pending {
    line: Mutex<Option<Staged>>,
    slot: Mutex<Slot>,
    ready: Condvar,
}

enum Slot {
    Waiting,
    /// This line is at the head of the queue and leads the next commit.
    Lead,
    Done(Result<Option<crate::history::LineId>, ChatError>),
}

impl Pending {
    fn set(&self, slot: Slot) {
        *self.slot.lock().unwrap() = slot;
        self.ready.notify_one();
    }
}

impl ChatCommit {
    pub(crate) fn for_room(room: u32) -> ChatCommit {
        ChatCommit {
            room,
            state: Mutex::default(),
            recent: Mutex::default(),
        }
    }

    /// Lines just redacted: a repeat of one is no longer held to what it
    /// said, which is gone.
    pub(crate) fn forget_said(&self, lines: &[crate::history::LineId]) {
        self.recent.lock().unwrap().forget_said(lines);
    }

    /// Lines from one caller, queued together in their order and answered
    /// in it: they share a commit, as lines from many callers at once do,
    /// rather than one each when the caller sends them one at a time.
    /// Whenever one of them reaches the head of the queue the caller
    /// leads that commit.
    fn submit_all(
        &self,
        core: &Core,
        lines: Vec<Staged>,
    ) -> Vec<Result<Option<crate::history::LineId>, ChatError>> {
        // Nothing to queue must not take the lead: nobody would hand it on.
        if lines.is_empty() {
            return Vec::new();
        }
        let mine: Vec<Arc<Pending>> = lines
            .into_iter()
            .map(|line| {
                Arc::new(Pending {
                    line: Mutex::new(Some(line)),
                    slot: Mutex::new(Slot::Waiting),
                    ready: Condvar::new(),
                })
            })
            .collect();
        let lead = {
            let mut st = self.state.lock().unwrap();
            st.queue.extend(mine.iter().cloned());
            !std::mem::replace(&mut st.leading, true)
        };
        if let (true, Some(first)) = (lead, mine.first()) {
            first.set(Slot::Lead);
        }
        // A panic while leading goes on its way only once every line of
        // this caller's is answered: one left in the queue would be led by
        // nobody, and nothing behind it would be logged again.
        let mut panicked = None;
        let mut results = Vec::with_capacity(mine.len());
        for p in &mine {
            let mut slot = p.slot.lock().unwrap();
            let result = loop {
                match std::mem::replace(&mut *slot, Slot::Waiting) {
                    Slot::Waiting => slot = p.ready.wait(slot).unwrap(),
                    Slot::Done(result) => break result,
                    Slot::Lead => {
                        drop(slot);
                        let (result, panic) = self.lead(core, p);
                        panicked = panicked.or(panic);
                        break result;
                    }
                }
            };
            results.push(result);
        }
        if let Some(panic) = panicked {
            std::panic::resume_unwind(panic);
        }
        results
    }

    /// Commit the batch at the head of the queue, which `me` heads, answer
    /// its lines and hand the lead on: `me`'s answer, and a panic the
    /// commit raised, for the caller to raise once it is done.
    #[allow(clippy::type_complexity)]
    fn lead(
        &self,
        core: &Core,
        me: &Arc<Pending>,
    ) -> (
        Result<Option<crate::history::LineId>, ChatError>,
        Option<Box<dyn std::any::Any + Send>>,
    ) {
        let batch: Vec<Arc<Pending>> = {
            let mut st = self.state.lock().unwrap();
            let n = st.queue.len().min(COMMIT_BATCH);
            st.queue.drain(..n).collect()
        };
        let lines = batch
            .iter()
            .map(|p| {
                p.line
                    .lock()
                    .unwrap()
                    .take()
                    .expect("a line is committed once")
            })
            .collect();
        // A panic in the commit must not strand the lines waiting on it,
        // or the next ones: they are answered and the lead is handed on.
        let (results, panicked) =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                core.chat_commit_batch(self.room, lines)
            })) {
                Ok(results) => (results, None),
                Err(panic) => (
                    batch.iter().map(|_| Err(ChatError::ServerError)).collect(),
                    Some(panic),
                ),
            };
        let mut mine = None;
        for (p, result) in batch.iter().zip(results) {
            if Arc::ptr_eq(p, me) {
                mine = Some(result);
            } else {
                p.set(Slot::Done(result));
            }
        }
        // The next line waiting leads the next commit.
        {
            let mut st = self.state.lock().unwrap();
            match st.queue.front() {
                Some(next) => next.set(Slot::Lead),
                None => st.leading = false,
            }
        }
        (
            mine.expect("the leader's line is in its own batch"),
            panicked,
        )
    }
}

/// Why a chat operation was refused. The frontend maps these to task-error
/// text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    NoSuchUser,
    NoSuchChat,
    NotAMember,
    AlreadyThere,
    WrongPassword,
    /// The recipient has as many messages waiting as the server allows. Refusing is deliberate: a message the sender was told was
    /// delivered and which then quietly disappeared is the failure mode
    /// that destroys trust in a messaging system.
    MailboxFull,
    /// The recipient is not attached, and the sender has stored as much
    /// mail today as `[inbox]` allows. Refused the way a full mailbox
    /// is, and about the sender rather than the recipient.
    SendQuota,
    /// The creator has as many private chats open as `[limits]` allows,
    /// or the server has.
    TooManyChats,
    /// The recipient has blocked the sender. Named rather than hidden,
    /// matching fogWraith's `Blocked` (reason 3) so the two subsystems
    /// answer alike — see docs/private-messages.md §14 for the argument
    /// against, which is real and which interoperability outweighs.
    Blocked,
    /// This session has no mailbox of its own, so there is nowhere to
    /// keep a block or a read mark. Distinct from `NoSuchUser`, which is
    /// about whoever was named: telling a guest "no such user" when the
    /// answer is "you have no inbox" sends them looking for a typo.
    NoInbox,
    /// The handle a sender attached is not theirs, has expired, or was
    /// revoked. One answer for all three, so a sender cannot use a chat
    /// send to test whether someone else's handle exists.
    NoSuchMedia,
    /// The sender talked faster than it may (`crate::limits`) and has
    /// been kicked for it, or had been kicked already and is on its way
    /// out.
    Flooding,
    /// The sender may read the room and not send in it.
    ReadOnly,
    /// An unsigned line into a room that requires signed lines, from a
    /// sender its gates let post (`docs/e2e-messages.md` §4.8).
    SignatureRequired,
    /// A signed line or message under an id its signer already used for
    /// something else (`docs/e2e-messages.md` §3.6).
    Equivocation,
    /// A signed message to someone other than the identity it names.
    SignedElsewhere,
    /// A signed message to a recipient with no identity to sign it to.
    NoIdentity,
    /// A message by login to someone taking part in instant messaging
    /// who is no friend, where it cannot be a request
    /// (`docs/instant-messaging.md` §4.1).
    NotFriends,
    /// As many requests to one recipient as a sender may send.
    RequestFull,
    /// A reply that would approve a conversation past the replier's
    /// roster limit.
    RosterFull,
    /// A cursor the caller's mailbox never issued. An id from before
    /// schema 33 was the server's, larger than any cursor, and read as
    /// one would page or mark mail the client never saw.
    UnknownCursor,
    /// A reply naming a line of another room, or a message outside the
    /// conversation it is sent in (`docs/hotline-ng.md` §7.3).
    ReplyScope,
    /// The server couldn't complete the operation — a chat id the OS
    /// CSPRNG refused to produce, or an inbox that would not write. Not
    /// the client's fault and not something it can retry usefully.
    ServerError,
}

/// A signed public line's signature and, for a lobby line that can
/// take one, its link form (`docs/e2e-messages.md` §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedLine {
    pub signature: Signature,
    pub link: Option<crate::server_link::LinkForm>,
}

/// A signed private message's signature, and the recipient fingerprint
/// it names (`docs/e2e-messages.md` §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMsg {
    pub signature: Signature,
    pub to: [u8; 32],
}

/// What became of a private message, and the reference a stored one is
/// named by, which the sender holds as the recipient does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgOutcome {
    /// Handed to a live connection; `None` when nothing was stored.
    Delivered(Option<MessageRef>),
    /// Stored for a recipient who wasn't there to take it.
    Queued(MessageRef),
    /// A message request (`docs/instant-messaging.md` §4.2), however it
    /// was stored, held or dropped.
    Requested,
}

impl Core {
    // --- Chat lines -----------------------------------------------------

    /// A public chat line. Delivered (sender included) to every visible
    /// session allowed to read chat.
    pub fn chat_public(
        &self,
        from: Uid,
        text: String,
        style: u16,
        media: Option<crate::media::Handle>,
    ) -> Result<Option<crate::history::LineId>, ChatError> {
        self.chat_public_all(from, 0, vec![(text, style, media)])
            .pop()
            .expect("an answer for each line")
    }

    /// Public chat lines one session sent one after another into `room`,
    /// the lobby for 0, `(text, style, media)`, answered in their order:
    /// they share a commit rather than wait for one each, so a sender that
    /// got ahead of the log catches up at once. Each is judged as
    /// [`Core::chat_public`] judges one; a line that tips its sender over
    /// its chat lines kicks it, and none from then on is logged. A room's
    /// lines go to its members, from a member that may send there.
    pub fn chat_public_all(
        &self,
        from: Uid,
        room: u32,
        lines: Vec<(String, u16, Option<crate::media::Handle>)>,
    ) -> Vec<Result<Option<crate::history::LineId>, ChatError>> {
        self.chat_public_lines(
            from,
            room,
            lines.into_iter().map(|l| (l, None, None, None)).collect(),
        )
    }

    /// One line into `room`, as [`Core::chat_public_all`] sends one,
    /// under the client's own `guid` for it: a line its sender already
    /// sent under that guid, in that room and lately, is answered as it
    /// was and not sent again, nor, once it is logged, counted against
    /// the sender's chat lines. The sender is its mailbox where it has
    /// one, so a retry from a new login of the same account is the same
    /// line.
    pub fn chat_public_guid(
        &self,
        from: Uid,
        room: u32,
        line: (String, u16, Option<crate::media::Handle>),
        guid: Option<MessageGuid>,
    ) -> Result<Option<crate::history::LineId>, ChatError> {
        self.chat_public_signed(from, room, line, guid, None, None)
    }

    /// [`Core::chat_public_guid`], for a line that may be signed: its
    /// frontend checked the signature, and that its id is `guid` and its
    /// signer the sender's identity. A signed line its signer already
    /// said under that id is answered as that line when it says the same
    /// thing in the same room, and refused as an equivocation otherwise
    /// (`docs/e2e-messages.md` §4.7), as far as the log and the room's
    /// memory of guids remember. `re` is what it answers, which must be
    /// a line of this room, if a line at all.
    pub fn chat_public_signed(
        &self,
        from: Uid,
        room: u32,
        line: (String, u16, Option<crate::media::Handle>),
        guid: Option<MessageGuid>,
        signed: Option<SignedLine>,
        re: Option<Reply>,
    ) -> Result<Option<crate::history::LineId>, ChatError> {
        self.chat_public_lines(from, room, vec![(line, guid, signed, re)])
            .pop()
            .expect("an answer for each line")
    }

    /// What the signed line `signer` said under `guid` was answered, from
    /// the log's index of signed lines, which spans rooms: `None` when
    /// it holds none.
    fn signed_answer(
        &self,
        room: u32,
        signer: &[u8; 32],
        guid: &MessageGuid,
        signed: &Signature,
    ) -> Result<Option<Option<crate::history::LineId>>, ChatError> {
        let Some(log) = self.history.as_ref() else {
            return Ok(None);
        };
        match log.find_signed(signer, guid) {
            Ok(Some(at)) if at.channel == room && at.content == signed.content => {
                Ok(Some(Some(at.id)))
            }
            Ok(Some(_)) => Err(ChatError::Equivocation),
            Ok(None) => Ok(None),
            Err(e) => Err(history_store_failed(e)),
        }
    }

    /// What the line sent under `key` into `room` was answered, if that is
    /// remembered here or, for a kept sender, the log still keeps the
    /// line, as after a restart: then it is remembered here too. The
    /// store is asked without the memory's lock held. A log that will not
    /// answer is a miss, and the commit's own conflict the backstop.
    fn guid_answer(
        &self,
        recent: &Mutex<RecentGuids>,
        room: u32,
        key: &GuidKey,
    ) -> Option<Remembered> {
        if let Some(found) = recent.lock().unwrap().find(self.clock.now(), key) {
            return Some(found);
        }
        let (GuidSender::Kept(sender), guid) = key else {
            return None;
        };
        match self.history.as_ref()?.find_guid(room, sender, guid) {
            // A signed line the log keeps was asked about by its
            // signer's index first, so this one is unsigned or redacted.
            Ok(Some(id)) => {
                let redacted = match self.history.as_ref()?.line(id) {
                    Ok(line) => line.is_some_and(|l| l.flags.contains(LineFlags::DELETED)),
                    Err(e) => {
                        warn!("chat log would not read a line: {e}");
                        false
                    }
                };
                let said = if redacted {
                    Said::Forgotten
                } else {
                    Said::Unsigned
                };
                recent
                    .lock()
                    .unwrap()
                    .remember(self.clock.now(), key.clone(), (Some(id), said));
                Some((Some(id), said))
            }
            Ok(None) => None,
            Err(e) => {
                warn!("chat log would not look up a guid: {e}");
                None
            }
        }
    }

    /// Does `uid`'s account keep mail of its own? What decides whether a
    /// queued message's id is its sender's to be told
    /// (`docs/hotline-ng.md` §7.1).
    pub fn has_inbox(&self, uid: Uid) -> bool {
        self.roster
            .lock()
            .unwrap()
            .users
            .get(&uid)
            .is_some_and(|s| s.has_inbox)
    }

    #[allow(clippy::type_complexity)]
    fn chat_public_lines(
        &self,
        from: Uid,
        room: u32,
        lines: Vec<(
            (String, u16, Option<crate::media::Handle>),
            Option<MessageGuid>,
            Option<SignedLine>,
            Option<Reply>,
        )>,
    ) -> Vec<Result<Option<crate::history::LineId>, ChatError>> {
        // Before the lines are counted, as a private chat's are.
        let mut signed_only = false;
        if room != 0 {
            if let Err(e) = self.room_may_send(from, room) {
                return lines.iter().map(|_| Err(e)).collect();
            }
            signed_only = self.room_signed(room);
        }
        let channel = (room != 0).then(|| self.room_channel(room));
        let commit = channel.as_ref().map_or(&self.chat_commit, |c| &c.commit);
        let mut results = vec![None; lines.len()];
        let mut staged = Vec::with_capacity(lines.len());
        let mut at = Vec::with_capacity(lines.len());
        // The line that tips its sender over: the lines before it are
        // heard before the room hears of the kick, as they would have
        // been sent one at a time.
        let mut tipped = None;
        for (i, ((mut text, style, media), guid, signed, re)) in lines.into_iter().enumerate() {
            let in_room = |re: &Reply| match re {
                Reply::Line { room: r, .. } => *r == room,
                Reply::Signed { .. } => true,
                Reply::Im(_) | Reply::Pm(_) => false,
            };
            if re.as_ref().is_some_and(|re| !in_room(re)) {
                results[i] = Some(Err(ChatError::ReplyScope));
                continue;
            }
            let (signed, link) = match signed {
                Some(s) => (Some(s.signature), s.link),
                None => (None, None),
            };
            // Neither counted as a line nor answered as a repeat
            // (`docs/e2e-messages.md` §4.8).
            if signed_only && signed.is_none() {
                results[i] = Some(Err(ChatError::SignatureRequired));
                continue;
            }
            // A repeat puts nothing in the room, so it spends no chat
            // lines. One still in the queue behind its original is not
            // found here, and is found when its commit comes.
            let guid = match guid {
                None => None,
                Some(guid) => {
                    let r = self.roster.lock().unwrap();
                    let Some((sender, signer)) = r
                        .users
                        .get(&from)
                        .map(|s| (guid_sender(from, s), s.identity))
                    else {
                        results[i] = Some(Err(ChatError::NoSuchUser));
                        continue;
                    };
                    drop(r);
                    if let (Some(signed), Some(signer)) = (&signed, signer) {
                        match self.signed_answer(room, &signer, &guid, signed) {
                            Ok(None) => {}
                            Ok(Some(id)) => {
                                results[i] = Some(Ok(id));
                                continue;
                            }
                            Err(e) => {
                                results[i] = Some(Err(e));
                                continue;
                            }
                        }
                    }
                    let key = (sender, guid);
                    if let Some(found) = self.guid_answer(&commit.recent, room, &key) {
                        results[i] = Some(repeat_of(found, signed.as_ref()));
                        continue;
                    }
                    Some(key)
                }
            };
            match self.chat_flood_count(from, &text) {
                Ok(true) => {}
                Ok(false) => {
                    tipped = Some(i);
                    break;
                }
                Err(e) => {
                    results[i] = Some(Err(e));
                    continue;
                }
            }
            let (info, login, fingerprint, principal) = {
                let r = self.roster.lock().unwrap();
                let Some(sess) = r.users.get(&from) else {
                    results[i] = Some(Err(ChatError::NoSuchUser));
                    continue;
                };
                // Only the lobby crosses a link.
                if room == 0 && r.linked() {
                    crate::server_link::cut_to_link_bound(&mut text);
                }
                (
                    sess.info.clone(),
                    (sess.login != "guest").then(|| sess.login.clone()),
                    sess.identity,
                    crate::media::Principal::Session {
                        uid: from,
                        serial: sess.serial,
                    },
                )
            };
            // Before the line is logged: a handle that is not this
            // sender's, or whose bytes have gone, means no line at all
            // rather than a line whose reference resolves for nobody.
            let media = match media {
                Some(handle) => match self.media_for_send(from, &handle) {
                    Ok(reference) => Some((handle, reference)),
                    Err(_) => {
                        results[i] = Some(Err(ChatError::NoSuchMedia));
                        continue;
                    }
                },
                None => None,
            };
            staged.push(Staged {
                info,
                login,
                fingerprint,
                principal: Some(principal),
                ghost: None,
                text,
                style,
                media,
                at: SystemTime::now(),
                guid,
                signed,
                link,
                re,
            });
            at.push(i);
        }
        for (i, result) in at.into_iter().zip(commit.submit_all(self, staged)) {
            results[i] = Some(result);
        }
        if let Some(i) = tipped {
            let e = self.chat_flood_kick(from, room);
            results[i..].fill(Some(Err(e)));
        }
        results
            .into_iter()
            .map(|r| r.expect("every line answered"))
            .collect()
    }

    /// A line a ghost said, logged and shown as a local one is. Blocking,
    /// like [`Core::chat_public`]: the caller runs it off the reactor.
    pub fn ghost_chat(&self, line: crate::server_link::GhostLine) {
        self.ghost_chat_all(vec![line]);
    }

    /// Ghosts' lines, logged together in their order: a link's lines come
    /// to one task that logs them, and handed over one at a time they
    /// would each take a commit of their own. Answers each line's id in
    /// the log, as a local line's is.
    pub fn ghost_chat_all(
        &self,
        lines: Vec<crate::server_link::GhostLine>,
    ) -> Vec<Result<Option<crate::history::LineId>, ChatError>> {
        self.chat_commit
            .submit_all(self, lines.into_iter().map(|l| l.0).collect())
    }

    /// Log a batch of `room`'s lines in one commit and relay them in
    /// order, under the room's serial, so a line's id order and the order
    /// the room hears it in are one fact, as they were a line at a time.
    /// The lobby's lines go to every reader and the links, a room's to its
    /// members alone.
    fn chat_commit_batch(
        &self,
        room: u32,
        mut batch: Vec<Staged>,
    ) -> Vec<Result<Option<crate::history::LineId>, ChatError>> {
        let channel = (room != 0).then(|| self.room_channel(room));
        let serial = channel.as_ref().map_or(&self.log_serial, |c| &c.serial);
        let commit = channel.as_ref().map_or(&self.chat_commit, |c| &c.commit);
        let _serial = serial.lock().unwrap();
        let mut results: Vec<Option<Result<Option<crate::history::LineId>, ChatError>>> =
            vec![None; batch.len()];
        // A line waited in the queue, and the room may have moved on: its
        // sender kicked and purged, gone, renamed, or its image revoked.
        // Asked again now, under the log's lock, a line from a session
        // that is no longer there is not logged, so a purge between two
        // batches misses nothing; and a line goes out under the name its
        // sender has now, or with an image only if the image is still
        // theirs to send.
        {
            let r = self.roster.lock().unwrap();
            for (s, result) in batch.iter_mut().zip(results.iter_mut()) {
                let Some(crate::media::Principal::Session { uid, serial }) = s.principal else {
                    // A ghost hidden since is not shown; one gone since
                    // still is, as it was, so its last line is not lost.
                    if s.principal.is_none() {
                        match r.ghosts.get(&s.info.uid) {
                            Some(g) if !g.visible => *result = Some(Err(ChatError::NoSuchUser)),
                            Some(g) => s.info = g.info.clone(),
                            None => {}
                        }
                    }
                    continue;
                };
                match r.users.get(&uid) {
                    Some(sess) if sess.serial == serial => {
                        // Parted from the room meanwhile, or no longer let
                        // post there: not heard there.
                        match (room != 0).then(|| r.room_send_check(room, uid, sess)) {
                            Some(Err(e)) => *result = Some(Err(e)),
                            _ => s.info = sess.info.clone(),
                        }
                    }
                    _ => *result = Some(Err(ChatError::NoSuchUser)),
                }
            }
        }
        // A repeat of a line already logged is answered as that line was,
        // and one of a line earlier in this batch as that one will be:
        // neither is logged or heard. Before the image is asked about
        // again, so a repeat whose handle has gone since is still its
        // line.
        let now = self.clock.now();
        let mut repeats = Vec::new();
        {
            let mut recent = commit.recent.lock().unwrap();
            let mut first_seen: HashMap<&GuidKey, usize> = HashMap::new();
            for (i, s) in batch.iter().enumerate() {
                let Some(key) = s.guid.as_ref().filter(|_| results[i].is_none()) else {
                    continue;
                };
                if let Some(found) = recent.find(now, key) {
                    results[i] = Some(repeat_of(found, s.signed.as_ref()));
                } else if let Some(&first) = first_seen.get(key) {
                    let said = Said::of(batch[first].signed.as_ref());
                    match repeat_of((None, said), s.signed.as_ref()) {
                        Ok(_) => repeats.push((i, first)),
                        Err(e) => results[i] = Some(Err(e)),
                    }
                } else {
                    first_seen.insert(key, i);
                }
            }
        }
        for &(i, _) in &repeats {
            results[i] = Some(Ok(None));
        }
        for (s, result) in batch.iter_mut().zip(results.iter_mut()) {
            if let (None, Some((handle, _))) = (&result, &s.media) {
                match self.media_for_send(s.info.uid, handle) {
                    Ok(reference) => s.media = Some((*handle, reference)),
                    Err(_) => *result = Some(Err(ChatError::NoSuchMedia)),
                }
            }
        }
        let live: Vec<usize> = (0..batch.len()).filter(|&i| results[i].is_none()).collect();
        let ids: Vec<crate::history::Appended> = match self.history.as_ref() {
            Some(log) => {
                let lines: Vec<NewLine> = live
                    .iter()
                    .map(|&i| {
                        let s = &batch[i];
                        // A tagged ghost is logged as it is shown, so a
                        // replay does not pass it off as a local user.
                        let from_nick = match s.info.remote.as_ref().filter(|r| r.tagged) {
                            Some(r) => format!("{}@{}", s.info.nick, r.home_tag),
                            None => s.info.nick.clone(),
                        };
                        NewLine {
                            channel: room,
                            ghost: s.ghost,
                            from_nick,
                            from_login: s.login.clone(),
                            from_fingerprint: s.fingerprint,
                            icon: s.info.icon,
                            text: s.text.clone(),
                            flags: if s.style == 1 {
                                LineFlags::ACTION
                            } else {
                                LineFlags::default()
                            },
                            at: s.at,
                            guid: match &s.guid {
                                Some((GuidSender::Kept(sender), g)) => {
                                    Some((sender.clone(), g.clone()))
                                }
                                _ => None,
                            },
                            signed: s.signed.clone(),
                            home_key: s
                                .signed
                                .as_ref()
                                .and(s.info.remote.as_ref())
                                .and_then(|r| r.server_key),
                            home: s.info.remote.as_ref().map(|r| LineHome {
                                name: r.home_name.clone(),
                                tag: r.home_tag.clone(),
                                tagged: r.tagged,
                            }),
                            re: s.re.clone(),
                        }
                    })
                    .collect();
                match log.append_all(&lines) {
                    Ok(ids) => {
                        // One id a line, or the lines past the end would
                        // wait for an answer that never comes.
                        assert_eq!(ids.len(), lines.len(), "one id for each line logged");
                        ids
                    }
                    Err(e) => {
                        let e = history_store_failed(e);
                        for &(i, _) in &repeats {
                            results[i] = None;
                        }
                        return results.into_iter().map(|r| r.unwrap_or(Err(e))).collect();
                    }
                }
            }
            None => live
                .iter()
                .map(|_| crate::history::Appended { id: 0, new: true })
                .collect(),
        };
        let logged = self.history.is_some();
        // A line the log already held under its guid, as after a restart
        // the memory missed, is a repeat too: answered, and not heard.
        let mut heard = Vec::with_capacity(live.len());
        {
            let mut recent = commit.recent.lock().unwrap();
            for (i, done) in live.into_iter().zip(ids) {
                let id = logged.then_some(done.id);
                if let Some(guid) = batch[i].guid.clone() {
                    let said = Said::of(batch[i].signed.as_ref());
                    recent.remember(now, guid, (id, said));
                }
                if done.new {
                    heard.push((i, id));
                } else {
                    results[i] = Some(Ok(id));
                }
            }
        }
        // The log keeps the canonical metadata beside the line, so a
        // history entry can still render a placeholder once the bytes are
        // gone (docs/inline-media.md §9, chat-history.md §8). A store
        // write, so before the roster is taken, not under it.
        if let Some(log) = self.history.as_ref() {
            for &(i, id) in &heard {
                if let (Some(id), Some((_, reference))) = (id, &batch[i].media) {
                    if let Err(e) = log.attach_media(id, &reference.to_meta()) {
                        warn!("chat log would not record media: {e}");
                    }
                }
            }
        }
        let mut batch: Vec<Option<Staged>> = batch.into_iter().map(Some).collect();
        for (i, id) in heard {
            let s = batch[i].take().expect("each line relayed once");
            let sender = s.info.uid;
            // A signed line crosses a link with its signature or not at
            // all (`docs/e2e-messages.md` §4.11).
            let crosses = s.signed.is_none() || s.link.is_some();
            let ev = Event::Chat {
                cid: room,
                from: s.info,
                text: s.text,
                style: s.style,
                id,
                at: s.at,
                media: s.media.as_ref().map(|(_, r)| r.clone()),
                guid: None,
                signed: s.signed.map(|s| s.form),
                re: s.re.map(Box::new),
            };
            // The sender's own copy carries its guid; nobody else's does.
            let mine = s.guid.as_ref().map(|(_, g)| {
                let mut mine = ev.clone();
                if let Event::Chat { guid, .. } = &mut mine {
                    *guid = Some(g.clone());
                }
                mine
            });
            let skip = mine.as_ref().map(|_| sender);
            // The roster a line at a time, so a long batch does not hold
            // everyone else's roster work for all of it: the log's lock is
            // what keeps the lines in order.
            let mut r = self.roster.lock().unwrap();
            if let Some(id) = id {
                r.last_ids.insert(room, id);
                r.live.relayed(room, id);
            }
            // The authorization set, fixed at relay time: the sender, and
            // every session this line just went to whose wire can carry
            // the reference. Captured under the roster's lock and stored
            // under the media store's, which is the one order those two
            // are ever taken in.
            let audience = if room == 0 {
                r.broadcast_where(&ev, skip, reads_public_chat);
                if let Some(mine) = mine {
                    if r.users
                        .get(&sender)
                        .is_some_and(|u| u.visible && reads_public_chat(u))
                    {
                        r.send_to(sender, mine);
                    }
                }
                if let Event::Chat {
                    from, text, style, ..
                } = &ev
                {
                    if s.principal.is_some() && !text.is_empty() && crosses {
                        r.export_chat(from.uid, text, *style, s.link.clone());
                    }
                }
                s.media
                    .as_ref()
                    .map(|_| r.media_audience(None, reads_public_chat))
            } else {
                r.room_send_where(room, ev, |u| Some(u.info.uid) != skip);
                if let Some(mine) = mine {
                    r.room_send_where(room, mine, |u| u.info.uid == sender);
                }
                let members = r.rooms.get(&room).map(|e| e.members.clone());
                s.media
                    .as_ref()
                    .map(|_| r.media_audience_of(&members.unwrap_or_default()))
            };
            if let (Some((handle, _)), Some(audience)) = (&s.media, audience) {
                self.media_capture(handle, audience.into_iter().chain(s.principal));
            }
            drop(r);
            results[i] = Some(Ok(id));
        }
        for (i, first) in repeats {
            results[i] = results[first];
        }
        results
            .into_iter()
            .map(|r| r.expect("every line answered"))
            .collect()
    }

    /// A private chat line; membership is the only gate.
    pub fn chat_private(
        &self,
        cid: u32,
        from: Uid,
        text: String,
        style: u16,
        media: Option<crate::media::Handle>,
    ) -> Result<(), ChatError> {
        // Membership is checked before the handle is resolved, and the
        // handle before anything is sent: a non-member learns nothing
        // about a room from the order of these refusals.
        let principal = {
            let r = self.roster.lock().unwrap();
            let Some(chat) = r.chats.get(&cid) else {
                return Err(ChatError::NoSuchChat);
            };
            if !chat.members.contains(&from) {
                return Err(ChatError::NotAMember);
            }
            let Some(sess) = r.users.get(&from) else {
                return Err(ChatError::NoSuchUser);
            };
            crate::media::Principal::Session {
                uid: from,
                serial: sess.serial,
            }
        };
        // After membership, as mhxd's `rcv_chat` drops a line to a room
        // its sender is not in before `hxd_rcv_chat` counts it.
        self.chat_flood_check(from, cid, &text)?;
        let media = match media {
            Some(handle) => Some((
                handle,
                self.media_for_send(from, &handle)
                    .map_err(|_| ChatError::NoSuchMedia)?,
            )),
            None => None,
        };
        let mut r = self.roster.lock().unwrap();
        let Some(chat) = r.chats.get(&cid) else {
            return Err(ChatError::NoSuchChat);
        };
        if !chat.members.contains(&from) {
            return Err(ChatError::NotAMember);
        }
        let members = chat.members.clone();
        let Some(info) = r.users.get(&from).map(|s| s.info.clone()) else {
            return Err(ChatError::NoSuchUser);
        };
        let ev = Event::Chat {
            cid,
            from: info,
            text,
            style,
            id: None,
            at: SystemTime::now(),
            media: media.as_ref().map(|(_, r)| r.clone()),
            guid: None,
            signed: None,
            re: None,
        };
        for uid in &members {
            r.send_to(*uid, ev.clone());
        }
        // A room's set is its membership at this moment, media-capable
        // members only, and nothing is added to it afterwards — someone
        // who joins the room later did not receive this line.
        if let Some((handle, _)) = &media {
            let audience = r.media_audience_of(&members);
            self.media_capture(handle, audience.into_iter().chain([principal]));
        }
        Ok(())
    }

    /// Page the durable public log. Policy is checked by the frontend; the
    /// uid check prevents a stale transport from reading after teardown.
    pub fn history(&self, uid: Uid, query: HistoryQuery) -> Result<HistoryPage, ChatError> {
        if !self.roster.lock().unwrap().users.contains_key(&uid) {
            return Err(ChatError::NoSuchUser);
        }
        if query.channel != 0 && !self.room_readable(uid, query.channel) {
            return Err(ChatError::NoSuchChat);
        }
        self.history
            .as_ref()
            .ok_or(ChatError::ServerError)?
            .query(&query)
            .map_err(history_store_failed)
    }

    /// The lines of `room` among `ids`, ascending, under the same checks
    /// as [`Core::history`]: the quotes a page of replies draws. A line of
    /// another room is left out as one that does not exist is.
    pub fn history_ids(
        &self,
        uid: Uid,
        room: u32,
        ids: &[crate::history::LineId],
    ) -> Result<Vec<crate::history::LogLine>, ChatError> {
        if !self.roster.lock().unwrap().users.contains_key(&uid) {
            return Err(ChatError::NoSuchUser);
        }
        if room != 0 && !self.room_readable(uid, room) {
            return Err(ChatError::NoSuchChat);
        }
        self.history
            .as_ref()
            .ok_or(ChatError::ServerError)?
            .lines(room, ids)
            .map_err(history_store_failed)
    }

    /// Ten history pages per second, scoped to the logical user session.
    /// Keeping this beside the roster means an ng reconnect cannot reset it.
    pub fn allow_history_request(&self, uid: Uid) -> Result<bool, ChatError> {
        let mut roster = self.roster.lock().unwrap();
        let session = roster.users.get_mut(&uid).ok_or(ChatError::NoSuchUser)?;
        let now = Instant::now();
        session.history_tokens = (session.history_tokens
            + now.duration_since(session.history_refill).as_secs_f64() * 10.0)
            .min(10.0);
        session.history_refill = now;
        if session.history_tokens < 1.0 {
            return Ok(false);
        }
        session.history_tokens -= 1.0;
        Ok(true)
    }

    /// Each stored reference in a batch, as the media store has it now.
    /// Keyed by the stored handle bytes, which is what the row carries.
    fn media_states(
        &self,
        batch: &[crate::inbox::StoredMessage],
    ) -> HashMap<Vec<u8>, crate::media::MediaRef> {
        let mut out = HashMap::new();
        for m in batch {
            let Some(meta) = m.media.as_ref() else {
                continue;
            };
            let Ok(handle) = <crate::media::Handle>::try_from(meta.id.as_slice()) else {
                continue;
            };
            if let Some(reference) = self.media_meta(&handle) {
                out.insert(meta.id.clone(), reference);
            }
        }
        out
    }

    /// Retention work for the binary's hourly sweeper: `max_lines` and
    /// `max_age` for each channel, and a room's own where it has one.
    pub fn prune_history(&self, max_lines: usize, max_age: Option<Duration>) -> usize {
        let keep = crate::history::Retention {
            max_lines,
            max_age,
            channels: self.room_retention(max_lines, max_age),
        };
        self.history
            .as_ref()
            .and_then(|log| match log.prune(&keep, SystemTime::now()) {
                Ok(gone) => Some(gone),
                Err(e) => {
                    warn!("history retention: {e}");
                    None
                }
            })
            .unwrap_or(0)
    }

    /// Count a chat send's lines against `uid`'s `chat_lines`, as
    /// mhxd's `hxd_rcv_chat` counts them (`crate::limits::chat_lines`),
    /// or kick it. Past the window's allowance the session is kicked,
    /// without a ban, the send is refused whole — mhxd overwrites the
    /// lines it had formatted with the notice — and the room it was sent
    /// to hears mhxd's `\r *** X was kicked for chat spamming`, from the
    /// spammer. A session whose account `can_spam`, and the server
    /// account, spend nothing; a uid not on the roster spends nothing
    /// either, since the caller refuses it for that.
    ///
    /// mhxd skips the count for a line that starts with `/`, because it
    /// runs that line as a command instead of relaying it. This server
    /// has no chat commands and relays such a line like any other, so it
    /// counts like any other.
    pub(crate) fn chat_flood_check(&self, uid: Uid, cid: u32, text: &str) -> Result<(), ChatError> {
        match self.chat_flood_count(uid, text)? {
            true => Ok(()),
            false => Err(self.chat_flood_kick(uid, cid)),
        }
    }

    /// [`Core::chat_flood_check`]'s count alone: whether `text` is within
    /// `uid`'s chat lines, the kick it earns when it is not left to
    /// [`Core::chat_flood_kick`].
    fn chat_flood_count(&self, uid: Uid, text: &str) -> Result<bool, ChatError> {
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return Ok(true);
        };
        // On its way out: every line it had in flight would kick it
        // again and tell the room again.
        if sess.kicked {
            return Err(ChatError::Flooding);
        }
        if sess.can_spam || sess.info.system {
            return Ok(true);
        }
        let lines = crate::limits::chat_lines(text);
        Ok(sess
            .flood
            .chat(lines, &self.flood_limits, std::time::Instant::now()))
    }

    fn chat_flood_kick(&self, uid: Uid, cid: u32) -> ChatError {
        let nick = match kick_in(&mut self.roster.lock().unwrap(), uid) {
            Ok(nick) => nick,
            Err(_) => return ChatError::Flooding,
        };
        warn!(uid, nick = %nick, "kicked for chat spamming");
        crate::instrument::flood_kick("chat");
        self.notice(
            cid,
            uid,
            format!("{nick} was kicked for chat spamming"),
            true,
        );
        ChatError::Flooding
    }

    /// The spam points `uid` may still spend without being kicked for
    /// it: none once it has been, and every one for a session no budget
    /// holds.
    pub fn spam_room(&self, uid: Uid) -> u32 {
        let limits = self.flood_limits;
        let mut r = self.roster.lock().unwrap();
        let Some(sess) = r.users.get_mut(&uid) else {
            return u32::MAX;
        };
        if sess.kicked {
            return 0;
        }
        if sess.can_spam || sess.info.system || limits.spam_points == 0 || limits.spam_per.is_zero()
        {
            return u32::MAX;
        }
        let (spent, _) = sess.flood.spam(0, &limits, std::time::Instant::now());
        limits.spam_points.saturating_sub(spent).saturating_sub(1)
    }

    /// Spend `points` of `uid`'s spam points on a transaction it sent,
    /// mhxd's `spam_update` at the top of `hxd_rcv`: `trans` is the
    /// transaction's type on the classic wire, or the type of the one an
    /// ng request stands for there, and only the announcement uses it.
    /// When the window's total reaches `spam_points` the session is
    /// kicked, and public chat hears mhxd's `<X has been banned by X:
    /// spam_max exceeded: …>` ("kicked" when nothing is banned); the
    /// transaction is refused, and so is
    /// every one after it from a session already kicked, which is neither
    /// kicked nor announced again. A session whose account `can_spam`,
    /// and the server account, spend nothing.
    ///
    /// The kick is made here, at once; the ban it asks for, for
    /// `ban_for` (none when that is zero), comes back in [`Flooded`]
    /// for the caller to place off the reactor with
    /// [`Core::place_spam_ban`], as it is a store write. What it bans is
    /// chosen now, while the session is on the roster to be read.
    pub fn spend_spam(&self, uid: Uid, points: u32, trans: u32) -> Result<(), Flooded> {
        let limits = self.flood_limits;
        let (nick, total, targets, shown) = {
            let mut r = self.roster.lock().unwrap();
            let Some(sess) = r.users.get_mut(&uid) else {
                return Ok(());
            };
            if sess.kicked {
                return Err(Flooded { ban: None });
            }
            if sess.can_spam || sess.info.system {
                return Ok(());
            }
            let (total, under) = sess.flood.spam(points, &limits, std::time::Instant::now());
            if under {
                return Ok(());
            }
            let targets = if limits.ban_for.is_zero() {
                Vec::new()
            } else {
                self.kick_ban_targets(sess)
            };
            let shown = sess.visible;
            // Kicked under the lock that found it over, so a burst in
            // flight kicks it once; banned once the lock is let go.
            match kick_in(&mut r, uid) {
                Ok(nick) => (nick, total, targets, shown),
                Err(_) => return Err(Flooded { ban: None }),
            }
        };
        let verb = if targets.is_empty() {
            "kicked"
        } else {
            "banned"
        };
        warn!(uid, nick = %nick, total, trans, "{verb} for spam_max");
        crate::instrument::flood_kick("spam");
        // mhxd's `user_kick` with the spammer as its own kicker, and the
        // reason its `hxd_rcv` gives; never of a session no list shows,
        // whose leaving the lobby would learn of from nothing else.
        if shown {
            self.chat_notice(
                0,
                uid,
                format!(
                    "{nick} has been {verb} by {nick}: spam_max exceeded: {total} >= {}, \
                     last transaction: 0x{trans:x}",
                    limits.spam_points
                ),
            );
        }
        Err(Flooded {
            ban: (!targets.is_empty()).then_some(SpamBan {
                uid,
                targets,
                for_: limits.ban_for,
            }),
        })
    }

    /// What a kick-with-ban of `sess` bans, a moderator's or a spam
    /// kick's: the person, and the address they came from unless it is
    /// one `[limits] exempt` holds to nothing. Every row belongs to one
    /// act, so lifting any lifts them all.
    ///
    /// mhxd bans the address alone, and so did this server; the
    /// deviation is deliberate. An exempt address is one many people
    /// share on purpose (loopback, Docker's userland proxy, a TCP proxy
    /// that hides its clients, a CGNAT an operator has listed), and
    /// banning it for one person locks everyone behind it out for the
    /// ban's length. And an address alone is a ban a person walks out of
    /// by reconnecting from another one, which the login they came back
    /// as would not let them.
    ///
    /// The person is the account's login when it is a person's
    /// (`is_person`: which bans the identity it links too,
    /// `Core::place_ban`), else the identity the session proved, if it
    /// proved one. A guest with neither, on an exempt address, is only
    /// kicked: there is nothing of theirs alone to ban.
    pub(crate) fn kick_ban_targets(
        &self,
        sess: &crate::roster::UserSession,
    ) -> Vec<crate::ban::BanTarget> {
        use crate::ban::BanTarget;
        let login = sess
            .is_person
            .then(|| BanTarget::login(&sess.login).ok())
            .flatten()
            // Everyone's login is no one person's: `place_ban` refuses it.
            .filter(|t| *t != BanTarget::Login("guest".into()));
        let person = login.or_else(|| sess.identity.map(BanTarget::Identity));
        let address = sess
            .addr
            .filter(|a| !self.conn_gate.exempt(*a))
            .and_then(|a| self.address_ban_target(a));
        person.into_iter().chain(address).collect()
    }

    /// Place the ban a spam kick asked for ([`Core::spend_spam`]). A
    /// store write: called off the reactor. Said in the log when it
    /// cannot be placed; the kick stands either way.
    pub fn place_spam_ban(&self, ban: SpamBan) {
        self.place_kick_ban(
            ban.uid,
            ban.targets,
            KickBan {
                by: crate::moderation::Actor::Operator,
                for_: ban.for_,
                reason: "spam_max exceeded".into(),
            },
        );
    }

    /// A server notice into a chat (kick announcements and the like).
    /// Semantic text — each frontend formats it. Public delivery honors the
    /// read-chat filter.
    pub fn chat_notice(&self, cid: u32, from: Uid, text: String) {
        self.notice(cid, from, text, false);
    }

    /// [`Core::chat_notice`], in the action form when `action` is set.
    fn notice(&self, cid: u32, from: Uid, text: String, action: bool) {
        let mut r = self.roster.lock().unwrap();
        let ev = Event::Notice {
            cid,
            from,
            text,
            action,
        };
        if cid == 0 {
            r.broadcast_where(&ev, None, reads_public_chat);
        } else if r.rooms.contains_key(&cid) {
            r.room_send_where(cid, ev, |_| true);
        } else if let Some(members) = r.chats.get(&cid).map(|c| c.members.clone()) {
            for uid in members {
                r.send_to(uid, ev.clone());
            }
        }
    }

    // --- Private chat lifecycle ----------------------------------------

    /// Create a private chat with `creator` as its first member, inviting
    /// `invitee` (unless it's the creator). Returns the new chat id and the
    /// creator's row (the reply carries it).
    pub fn chat_create(&self, creator: Uid, invitee: Uid) -> Result<(u32, UserInfo), ChatError> {
        let mut r = self.roster.lock().unwrap();
        // A session no list shows is nobody to invite.
        if !r.users.get(&invitee).is_some_and(|s| s.visible) {
            return Err(ChatError::NoSuchUser);
        }
        let me = r
            .users
            .get(&creator)
            .map(|s| s.info.clone())
            .ok_or(ChatError::NoSuchUser)?;
        // Counted as they stand, under the lock that creates: a chat
        // stays open, and counted against whoever opened it, until its
        // last member leaves, whether or not that was the creator.
        let limits = self.chat_limits;
        if (limits.total > 0 && r.chats.len() >= limits.total)
            || (limits.per_creator > 0
                && r.chats
                    .values()
                    .filter(|c| c.creator == Some(creator))
                    .count()
                    >= limits.per_creator)
        {
            return Err(ChatError::TooManyChats);
        }
        let cid = r.next_chat_id().ok_or(ChatError::ServerError)?;
        let mut chat = PrivateChat {
            creator: Some(creator),
            members: vec![creator],
            ..Default::default()
        };
        if invitee != creator {
            chat.invited.push(invitee);
        }
        r.chats.insert(cid, chat);
        if invitee != creator {
            let ev = Event::ChatInvite {
                cid,
                from: creator,
                from_nick: me.nick.clone(),
            };
            r.send_to(invitee, ev);
        }
        Ok((cid, me))
    }

    /// Invite `target` to a chat the inviter is in, or to a room.
    pub fn chat_invite(&self, cid: u32, by: Uid, target: Uid) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        if r.rooms.contains_key(&cid) {
            return r.room_invite(cid, by, target);
        }
        let by_nick = r
            .users
            .get(&by)
            .map(|s| s.info.nick.clone())
            .ok_or(ChatError::NoSuchUser)?;
        if !r.users.get(&target).is_some_and(|s| s.visible) {
            return Err(ChatError::NoSuchUser);
        }
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if !chat.members.contains(&by) {
            return Err(ChatError::NotAMember);
        }
        if chat.members.contains(&target) {
            return Err(ChatError::AlreadyThere);
        }
        if !chat.invited.contains(&target) {
            chat.invited.push(target);
        }
        let ev = Event::ChatInvite {
            cid,
            from: by,
            from_nick: by_nick,
        };
        r.send_to(target, ev);
        Ok(())
    }

    /// Decline an invitation (or quietly drop a stale one).
    pub fn chat_decline(&self, cid: u32, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        if let Some(chat) = r.chats.get_mut(&cid) {
            chat.invited.retain(|u| *u != uid);
        }
    }

    /// Join a chat. An invitation bypasses the password; without one, a
    /// passworded chat requires the password. Returns the member rows
    /// (joiner included) and the subject, for the reply; other members get
    /// the join push.
    pub fn chat_join(
        &self,
        cid: u32,
        uid: Uid,
        password: &str,
    ) -> Result<(Vec<UserInfo>, String), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let me = r
            .users
            .get(&uid)
            .map(|s| s.info.clone())
            .ok_or(ChatError::NoSuchUser)?;
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if chat.members.contains(&uid) {
            return Err(ChatError::AlreadyThere);
        }
        if let Some(pos) = chat.invited.iter().position(|u| *u == uid) {
            chat.invited.remove(pos);
        } else if !chat.password.is_empty() && chat.password != password {
            return Err(ChatError::WrongPassword);
        }
        chat.members.push(uid);
        let members = chat.members.clone();
        let subject = chat.subject.clone();
        let ev = Event::ChatUserJoined { cid, user: me };
        let mut rows = Vec::with_capacity(members.len());
        for m in &members {
            if *m != uid {
                r.send_to(*m, ev.clone());
            }
            if let Some(s) = r.users.get(m) {
                rows.push(s.info.clone());
            }
        }
        Ok((rows, subject))
    }

    /// Leave a chat; the last member out deletes it.
    pub fn chat_part(&self, cid: u32, uid: Uid) {
        let mut r = self.roster.lock().unwrap();
        Self::part_one(&mut r, cid, uid);
    }

    /// Set a chat's subject. cid 0 is the public subject (policy-gated by
    /// the caller), kept in the rooms file where there is one; private
    /// chats require membership.
    pub fn chat_subject(&self, cid: u32, uid: Uid, subject: String) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let ev = Event::ChatSubject {
            cid,
            subject: subject.clone(),
        };
        if cid == 0 {
            r.lobby_topic = crate::rooms::Topic {
                text: subject,
                by: r
                    .users
                    .get(&uid)
                    .map(|s| s.info.nick.clone())
                    .unwrap_or_default(),
                at: Some(SystemTime::now()),
            };
            r.broadcast_where(&ev, None, |_| true);
            drop(r);
            self.topic_changed(0);
            return Ok(());
        }
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if !chat.members.contains(&uid) {
            return Err(ChatError::NotAMember);
        }
        chat.subject = subject;
        for m in chat.members.clone() {
            r.send_to(m, ev.clone());
        }
        Ok(())
    }

    /// Set a private chat's password (members only; announced to members,
    /// mirroring the reference server).
    pub fn chat_password(&self, cid: u32, uid: Uid, password: String) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let chat = r.chats.get_mut(&cid).ok_or(ChatError::NoSuchChat)?;
        if !chat.members.contains(&uid) {
            return Err(ChatError::NotAMember);
        }
        chat.password = password.clone();
        let ev = Event::ChatPassword { cid, password };
        for m in chat.members.clone() {
            r.send_to(m, ev.clone());
        }
        Ok(())
    }

    /// The private chats `uid` is currently in (used by tests and, later,
    /// the info views).
    pub fn chats_of(&self, uid: Uid) -> Vec<u32> {
        let r = self.roster.lock().unwrap();
        let mut v: Vec<u32> = r
            .chats
            .iter()
            .filter(|(_, c)| c.members.contains(&uid))
            .map(|(cid, _)| *cid)
            .collect();
        v.sort_unstable();
        v
    }

    pub(crate) fn leave_all_chats(r: &mut RosterInner, uid: Uid) {
        for chat in r.chats.values_mut() {
            if chat.creator == Some(uid) {
                chat.creator = None;
            }
        }
        let cids: Vec<u32> = r
            .chats
            .iter()
            .filter(|(_, c)| c.members.contains(&uid) || c.invited.contains(&uid))
            .map(|(cid, _)| *cid)
            .collect();
        for cid in cids {
            Self::part_one(r, cid, uid);
        }
    }

    fn part_one(r: &mut RosterInner, cid: u32, uid: Uid) {
        // Leaving a chat leaves its voice room — the spec's "if a user is
        // kicked from a chat room, their voice session MUST also be
        // terminated", and the same is true of walking out voluntarily.
        // Ahead of the early returns below: voice outlives a chat whose
        // membership has already been torn up.
        r.voice_part_room(uid, cid);
        let Some(chat) = r.chats.get_mut(&cid) else {
            return;
        };
        chat.invited.retain(|u| *u != uid);
        let Some(pos) = chat.members.iter().position(|u| *u == uid) else {
            return;
        };
        chat.members.remove(pos);
        if chat.members.is_empty() {
            r.chats.remove(&cid);
            return;
        }
        let members = chat.members.clone();
        let ev = Event::ChatUserParted { cid, uid };
        for m in members {
            r.send_to(m, ev.clone());
        }
    }

    // --- Messaging ------------------------------------------------------
    //
    // The rule, from docs/private-messages.md §5: a private message to an
    // account that has an inbox is persisted *before* the sender is acked,
    // and live delivery is a state change on the stored row rather than an
    // alternative to storing it. A recipient with no inbox (a guest), or a
    // server with no store configured, takes the path this module had
    // before the inbox existed — straight to the outbox, nothing
    // persisted.

    /// A private message to a session on the roster. The sender's ack is
    /// the frontend's task reply.
    pub fn msg(
        &self,
        from: Uid,
        to: Uid,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
    ) -> Result<MsgOutcome, ChatError> {
        self.msg_signed(from, to, text, guid, media, None, None)
    }

    /// [`Core::msg`], for a message that may be signed: its frontend
    /// checked the signature, and that its id is `guid` and its signer
    /// the sender's identity; `to` is the recipient fingerprint it names,
    /// which must be the recipient's (`docs/e2e-messages.md` §4.9).
    /// `re` is what it answers, which must be between the two of them.
    #[allow(clippy::too_many_arguments)]
    pub fn msg_signed(
        &self,
        from: Uid,
        to: Uid,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
        signed: Option<SignedMsg>,
        re: Option<Reply>,
    ) -> Result<MsgOutcome, ChatError> {
        // A message to the reserved account is a command line, not mail
        // (`docs/system-account.md` §1). Answered, never delivered and
        // never stored — there is nobody behind it to read it.
        if Some(to) == self.system_uid() {
            if signed.is_some() {
                return Err(ChatError::NoIdentity);
            }
            return self.run_system_command(from, &text);
        }
        let (sender, recipient) = {
            let r = self.roster.lock().unwrap();
            let sender = Sender::resolve(&r, from)?;
            let sess = r
                .users
                .get(&to)
                .filter(|s| s.visible)
                .ok_or(ChatError::NoSuchUser)?;
            (
                sender,
                Recipient {
                    uid: Some(to),
                    mailbox: sess.mailbox(),
                    has_inbox: sess.has_inbox,
                    // A guest has no mailbox to hold the grant, so the
                    // session it is sitting in is the address.
                    principal: match (sess.has_inbox, sess.mailbox()) {
                        (true, mailbox) => crate::media::Principal::Mailbox(mailbox),
                        (false, _) => crate::media::Principal::Session {
                            uid: to,
                            serial: sess.serial,
                        },
                    },
                },
            )
        };
        let sent = self.deliver(sender, recipient, text, guid, media, signed, re);
        if sent.is_ok() {
            self.guest_written_back(from, to);
        }
        sent
    }

    /// A private message to an *account*, whether or not it holds a
    /// session. This is what the ng wire's `to_login` calls; the legacy
    /// wire has no way to name a user who isn't on its list, and does not
    /// call it.
    pub fn msg_login(
        &self,
        from: Uid,
        to: &str,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
    ) -> Result<MsgOutcome, ChatError> {
        self.msg_login_signed(from, to, text, guid, media, None, None)
    }

    /// [`Core::msg_login`], as [`Core::msg_signed`] is [`Core::msg`]:
    /// the account's linked identity is the fingerprint it must name.
    #[allow(clippy::too_many_arguments)]
    pub fn msg_login_signed(
        &self,
        from: Uid,
        to: &str,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
        signed: Option<SignedMsg>,
        re: Option<Reply>,
    ) -> Result<MsgOutcome, ChatError> {
        // The same account by name, for a client that addresses by login.
        if self.is_system_login(to) {
            if signed.is_some() {
                return Err(ChatError::NoIdentity);
            }
            return self.run_system_command(from, &text);
        }
        if let Some(routed) =
            self.messaging_route(from, to, &text, &guid, media.is_some(), &signed, &re)
        {
            return routed;
        }
        let directory = self.directory.as_ref().ok_or(ChatError::NoSuchUser)?;
        // One `None` for "no such account" and "that account takes no
        // offline messages", so this path cannot be used to tell them
        // apart — see AccountDirectory::inbox_account.
        let mailbox = directory.inbox_account(to).ok_or(ChatError::NoSuchUser)?;
        let mut sender = Sender::resolve(&self.roster.lock().unwrap(), from)?;
        sender.live_only = self.guest_live_only(from, to);
        self.deliver(
            sender,
            Recipient {
                principal: crate::media::Principal::Mailbox(mailbox.clone()),
                uid: None,
                mailbox,
                has_inbox: true,
            },
            text,
            guid,
            media,
            signed,
            re,
        )
    }

    /// Has `from` used the signed id `guid` toward someone other than
    /// `to` (`docs/e2e-messages.md` §3.6)? The request ledger is asked
    /// too, which keeps what a recipient held or deleted, so the answer
    /// never tells the sender what became of a request
    /// (`docs/instant-messaging.md` §4.2).
    pub(crate) fn signed_elsewhere(
        &self,
        from: &Mailbox,
        to: &Mailbox,
        guid: &MessageGuid,
    ) -> Result<bool, StoreError> {
        let other = |m: &Mailbox| !to.matches(&m.login, m.fingerprint.as_ref());
        if let Some(store) = self.inbox.as_ref() {
            if store
                .find_sent(from, guid)?
                .is_some_and(|m| other(&m.recipient))
            {
                return Ok(true);
            }
        }
        let sender = crate::relationships::Requester::Account(from.clone());
        Ok(match self.relationships.as_ref() {
            Some(rel) => rel
                .find_request(&sender, None, guid)?
                .is_some_and(|e| other(&e.recipient)),
            None => false,
        })
    }

    /// Has `from` stored its day's allowance of mail, or would `adds`
    /// more bytes take it past? A rolling day, read from the store, so a
    /// restart forgets nothing.
    pub(crate) fn send_quota_spent(
        &self,
        store: &dyn MessageStore,
        from: &crate::relationships::Requester,
        adds: usize,
        now: SystemTime,
    ) -> Result<bool, ChatError> {
        let p = self.inbox_policy;
        if p.max_sent_per_day == 0 && p.max_sent_bytes_per_day == 0 {
            return Ok(false);
        }
        let since = now
            .checked_sub(Duration::from_secs(24 * 3600))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let mut sent = match from {
            crate::relationships::Requester::Account(m) => {
                store.sent_since(m, since).map_err(store_failed)?
            }
            crate::relationships::Requester::Identity(fp) => store
                .sent_since(&Mailbox::identified("guest", *fp), since)
                .map_err(store_failed)?,
            // Mail is stored under an account; an address's only sends
            // are requests.
            crate::relationships::Requester::Address(_) => crate::inbox::Sent::default(),
        };
        // Message requests count toward it by what was sent
        // (`docs/instant-messaging.md` §4.4).
        if let Some(rel) = self.relationships.as_ref() {
            let asked = rel.requested_since(from, since).map_err(store_failed)?;
            sent.messages += asked.messages;
            sent.bytes += asked.bytes;
        }
        Ok(
            (p.max_sent_per_day > 0 && sent.messages >= p.max_sent_per_day)
                || (p.max_sent_bytes_per_day > 0
                    && sent.bytes.saturating_add(adds as u64) > p.max_sent_bytes_per_day),
        )
    }

    /// Parse, act, answer. The sender's ack is `Delivered`, because
    /// from the wire's point of view the message arrived: what happened
    /// to it is in the answer, which is on its way back as a private
    /// message of its own.
    fn run_system_command(&self, from: Uid, text: &str) -> Result<MsgOutcome, ChatError> {
        // A session that is not on the roster is not one that can be
        // answered, and this is the same refusal any other message path
        // would give it.
        {
            let r = self.roster.lock().unwrap();
            r.users.get(&from).ok_or(ChatError::NoSuchUser)?;
        }
        if let Some(answer) = self.system_command(from, text) {
            self.system_reply(from, answer);
        }
        Ok(MsgOutcome::Delivered(None))
    }

    /// Does a private message's `re` stay between `me` and `them`? By
    /// what it names alone, never by what the store holds, which would
    /// tell the sender whether a message still exists. A `pm` is any
    /// reference: a reader resolves it from its own mail, where another
    /// pair's resolves to nothing. A signed target is bound by its own
    /// signature.
    pub(crate) fn reply_in_scope(re: &Reply, me: &str, them: &str) -> Result<(), ChatError> {
        let ok = match re {
            Reply::Line { .. } => false,
            Reply::Signed { .. } | Reply::Pm(_) => true,
            Reply::Im(im) => {
                im.login().eq_ignore_ascii_case(me) || im.login().eq_ignore_ascii_case(them)
            }
        };
        if ok {
            Ok(())
        } else {
            Err(ChatError::ReplyScope)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn deliver(
        &self,
        sender: Sender,
        to: Recipient,
        text: String,
        guid: Option<MessageGuid>,
        media: Option<crate::media::Handle>,
        signed: Option<SignedMsg>,
        re: Option<Reply>,
    ) -> Result<MsgOutcome, ChatError> {
        let now = SystemTime::now();
        let from = sender.uid;
        let sender_login = sender.reply_login.clone().unwrap_or_default();
        let sender_login = sender_login.as_str();
        // Against the recipient as resolved here, which is who the message
        // goes to: a uid named a moment ago may be someone else's now.
        let signed = match signed {
            None => None,
            Some(s) => match to.mailbox.fingerprint {
                None => return Err(ChatError::NoIdentity),
                Some(fp) if fp != s.to => return Err(ChatError::SignedElsewhere),
                Some(_) => Some(s.signature),
            },
        };

        // The handle resolves before anything is delivered or stored: a
        // message carrying an image this sender may not attach is
        // refused outright rather than sent without it.
        //
        // The *audience* is a separate act, and it happens at each point
        // below where the message actually goes out — never here. The
        // set is what a relay showed someone, and a send that comes back
        // `Blocked`, `MailboxFull` or `NoSuchUser` relayed nothing;
        // capturing up here would leave the refused recipient a
        // permanent grant on an image they were never sent, and the set
        // is only ever extended. Both principals are taken now because
        // `sender` is consumed on the way down.
        let image = media;
        let audience = [sender.principal.clone(), to.principal.clone()];
        let media = match image.as_ref() {
            Some(handle) => Some(
                self.media_for_send(sender.uid, handle)
                    .map_err(|_| ChatError::NoSuchMedia)?,
            ),
            None => None,
        };

        // Two reasons not to touch the store, and the same consequence.
        //
        // The recipient may simply have no inbox. Or the *sender* may
        // have no mailbox — a plain guest — and §9's "anyone with an
        // account can put mail in anyone's mailbox" does not cover it:
        // a guest has no account, cannot be blocked (there is nothing
        // durable to hold a block against, and `guest` is a login several
        // people share), and could therefore fill any mailbox on the
        // server to its cap and stay unstoppable. So a guest may reach a
        // session, live, and may not queue anything.
        let durable = to.has_inbox && sender.mailbox.is_some() && !sender.live_only;
        let Some(store) = self.inbox.as_ref().filter(|_| durable) else {
            // A block placed since routing let this sender in is still a
            // block, answered as routing answers one: no such account.
            if let Some(m) = sender.mailbox.as_ref().filter(|_| sender.live_only) {
                if self
                    .relationships()?
                    .is_blocked(&to.mailbox, m)
                    .map_err(store_failed)?
                {
                    return Err(ChatError::NoSuchUser);
                }
            }
            // After the block, so a blocked sender hears the block.
            if let Some(re) = &re {
                Self::reply_in_scope(re, sender_login, &to.mailbox.login)?;
            }
            // A recipient with no session cannot be reached this way.
            let mut r = self.roster.lock().unwrap();
            // The same resolution the durable path does, for the same
            // reasons and in the same order: the session the sender named
            // if it is attached (§15 — clicking a name in a user list is
            // naming a *device*, and an account with a phone on uid 2 and
            // a laptop on uid 3 should hear it on the one that was
            // clicked), else whichever session is attached, and every one
            // for a message that named the account. Preferring
            // the lowest attached uid over a named one that is *also*
            // attached was the durable path's old bug, still living here:
            // this is the path for every plain-guest sender, and for
            // every sender at all on a server with no `[inbox]`.
            //
            // Falling back to a detached uid is still right here and
            // wrong there: this path stores nothing, so the outbox buffer
            // is the only copy there can be.
            //
            // Only where the mailbox is a real address, though. A guest's
            // mailbox is `guest`, a login several people share, and
            // resolving *that* would hand the message to whichever guest
            // answered first. There the uid is the address.
            // Every candidate is checked against the mailbox as it
            // stands *now*: `msg` resolved this uid under an earlier
            // hold of the roster lock, and a uid is reused once the
            // counter wraps, so a session that ended in between must not
            // inherit the message. `holds` covers the attached ones; the
            // last resort is the same check without the attached part,
            // since a detached session is still the right addressee here.
            let owns = |uid: &Uid| r.users.get(uid).is_some_and(|s| s.mailbox() == to.mailbox);
            let uids = if to.has_inbox {
                let uids = named_sessions(&r, &to.mailbox, to.uid, from);
                match to.uid.filter(owns) {
                    Some(uid) if uids.is_empty() => vec![uid],
                    _ => uids,
                }
            } else {
                to.uid.into_iter().collect()
            };
            if uids.is_empty() {
                return Err(ChatError::NoSuchUser);
            }
            // There is a recipient and the event is about to go out, so
            // now the image has been shown. Under the roster lock, which
            // is why `media_capture` takes principals rather than
            // looking them up.
            if let Some(handle) = &image {
                self.media_capture(handle, audience.clone());
            }
            let ev = Event::Msg {
                from: sender.uid,
                from_nick: sender.nick,
                from_login: sender.reply_login,
                text,
                cursor: None,
                reference: None,
                sent_at: now,
                queued: false,
                media,
                signed: signed.map(|s| s.form),
                re: re.map(Box::new),
            };
            for uid in uids {
                r.send_to(uid, ev.clone());
            }
            return Ok(MsgOutcome::Delivered(None));
        };

        // Blocking, before anything is written. It applies to a message
        // named by uid exactly as to one named by login: a block a
        // recipient can sidestep by clicking a name in the user list is
        // not a block.
        let from_mailbox = sender.mailbox.clone().expect("checked by `durable`");
        if self
            .relationships()?
            .is_blocked(&to.mailbox, &from_mailbox)
            .map_err(store_failed)?
        {
            return Err(ChatError::Blocked);
        }
        if let Some(re) = &re {
            Self::reply_in_scope(re, sender_login, &to.mailbox.login)?;
        }
        // A signed id is its signer's across recipients (§3.6): one this
        // sender used toward someone else is another message. Toward this
        // recipient, `push` finds it.
        if let (Some(_), Some(g)) = (&signed, &guid) {
            if self
                .signed_elsewhere(&from_mailbox, &to.mailbox, g)
                .map_err(store_failed)?
            {
                return Err(ChatError::Equivocation);
            }
        }

        // The sender's quota (`docs/private-messages.md` §9): what one
        // account may *store* in a day, delivered or not, since retention
        // keeps both. It bounds storage and never conversation. Past it,
        // a message to someone attached still reaches them — live, with
        // no row and no id, as it would on mhxd, which stores nothing at
        // all — and only one that would have to wait is refused.
        // Checked rather than reserved, so sends in flight at once can
        // each pass it: a daily ceiling can afford that.
        //
        // A retry of a message already stored is not a new message and
        // stores nothing, so it is not the quota's to refuse: it goes on
        // to `push`, which recognizes it and answers it as the first
        // send was answered. Otherwise the client whose last in-quota
        // message lost its ack would hear `quota_exceeded` for a message
        // we have, and an attached recipient would be handed it twice,
        // the second time live with no id. Looked up only once the quota
        // is spent, so the ordinary send costs nothing more; a retry
        // racing its own first send past the quota can still miss it,
        // which is the narrow case the store's own dedupe cannot reach
        // from here.
        let retry = |guid: &Option<MessageGuid>| -> Result<bool, ChatError> {
            match guid {
                Some(g) => Ok(store
                    .find_guid(&to.mailbox, Some(&from_mailbox), g)
                    .map_err(store_failed)?
                    .is_some()),
                None => Ok(false),
            }
        };
        let quota = crate::relationships::Requester::Account(from_mailbox.clone());
        if self.send_quota_spent(&**store, &quota, text.len(), now)? && !retry(&guid)? {
            let mut r = self.roster.lock().unwrap();
            // Attached only: a detached session's outbox is not a place
            // to leave what the store was just refused.
            let uids = named_sessions(&r, &to.mailbox, to.uid, from);
            if uids.is_empty() {
                return Err(ChatError::SendQuota);
            }
            if let Some(handle) = &image {
                self.media_capture(handle, audience.clone());
            }
            let ev = Event::Msg {
                from: sender.uid,
                from_nick: sender.nick,
                from_login: sender.reply_login,
                text,
                cursor: None,
                reference: None,
                sent_at: now,
                queued: false,
                media,
                signed: signed.map(|s| s.form),
                re: re.map(Box::new),
            };
            for uid in uids {
                r.send_to(uid, ev.clone());
            }
            return Ok(MsgOutcome::Delivered(None));
        }

        // The store decides both of the questions that used to be asked
        // here and answered a moment later: whether this guid is already
        // stored, and whether the mailbox is at its cap. Both were
        // check-then-insert, and both are racy in exactly the case they
        // exist for — a client retrying a send, and a sender sending in
        // parallel.
        //
        // A retry of a message we already have is that message, not a
        // second one. Answering it what the first send was answered is
        // what makes a client safe to retry after a socket died mid-ack.
        let (sender_nick, body) = (sender.nick.clone(), text);
        let (id, reference, cursor) = match store
            .push(
                &NewMessage {
                    recipient: to.mailbox.clone(),
                    sender: sender.mailbox,
                    sender_nick: sender.nick,
                    body: body.clone(),
                    sent_at: now,
                    guid,
                    kind: MessageKind::Message,
                    media: media.as_ref().map(|m| m.to_meta()),
                    signed: signed.clone(),
                    friendship: None,
                    sender_address: None,
                    re,
                },
                self.inbox_policy.max_queued,
            )
            .map_err(store_failed)?
        {
            // Stored: the row is durable and carries the image's
            // metadata, so whoever eventually reads it must be able to
            // fetch the bytes. A retry (`Existing`) captured on its
            // original send, and re-capturing here would grant the
            // recipient a *different* handle if the retry named one.
            crate::inbox::Pushed::Stored {
                id,
                reference,
                cursor,
            } => {
                if let Some(handle) = &image {
                    self.media_capture(handle, audience.clone());
                }
                (id, reference, cursor)
            }
            crate::inbox::Pushed::Existing(m) => {
                // An unsigned message under the id says something else.
                if let Some(now) = &signed {
                    if m.signed.as_ref().map(|was| was.content) != Some(now.content) {
                        return Err(ChatError::Equivocation);
                    }
                }
                // A retry is that same message, and it gets the answer
                // the first send would get *now* rather than the one it
                // got then. The recipient may have attached in between:
                // flushing here is what hands it over, instead of
                // leaving it for their next login or sync while they are
                // sitting right there. No notification — the original
                // send already decided that question.
                if m.delivered_at.is_some() {
                    return Ok(MsgOutcome::Delivered(Some(m.reference)));
                }
                // `fresh` is `None`: this row has been in the inbox
                // since the original send, however short a time that
                // was, so it carries `queued` like anything else that
                // waited. Naming it fresh would tell the recipient a
                // message that sat there arrived just now.
                let delivered = self
                    .flush_to(
                        Target::Named {
                            uid: to.uid,
                            sender: from,
                        },
                        &to.mailbox,
                        None,
                    )
                    .contains(&m.id)
                    || !store
                        .is_pending(&to.mailbox, m.id)
                        .map_err(store_failed)
                        .unwrap_or(true);
                return Ok(if delivered {
                    MsgOutcome::Delivered(Some(m.reference))
                } else {
                    MsgOutcome::Queued(m.reference)
                });
            }
            crate::inbox::Pushed::Full => return Err(ChatError::MailboxFull),
        };

        // **Store, then resolve.** The roster lock was dropped for the
        // write, so who should receive this — and whether anyone should —
        // is decided now rather than before. Resolving it earlier meant a
        // recipient who attached in between was never handed the message
        // live, and, worse, that a recipient with a detached session and
        // an attached one had the message aimed at whichever had the
        // lower uid.
        //
        // Flushing (rather than sending this one row) is what keeps
        // delivery in id order when two senders race.
        let delivered = self
            .flush_to(
                Target::Named {
                    uid: to.uid,
                    sender: from,
                },
                &to.mailbox,
                Some(id),
            )
            .contains(&id);
        // A concurrent flush may have been the one that carried it — in
        // which case ours came back without it, and telling the sender
        // "queued" for a message the recipient is reading would be wrong.
        // The same question answers the case where a backlog past
        // `deliver_at_flush` pushed this row out of the batch.
        let delivered = delivered
            || !store
                .is_pending(&to.mailbox, id)
                .map_err(store_failed)
                .unwrap_or(true);

        // The notify decision (docs/push-notifications.md §6), computed
        // here so that both wires reach it — the legacy path skipping it
        // by being written somewhere else is the failure that document
        // calls out by name.
        //
        // Anything but an *attentive* session earns a notification:
        // detached, or no session at all, plainly; and `idle` too, even
        // though a connection is attached and got the event, because the
        // app is backgrounded and the OS is the one that decides whether
        // to make noise. (Nothing sets `idle` yet — hotline-ng.md §12
        // still owes it a definition — but the rule is the rule.)
        //
        // Across *every* session that owns the mailbox, not one chosen
        // uid: an account reading on its laptop with a sleeping phone is
        // attentive, and the phone should not buzz.
        let attentive = {
            let r = self.roster.lock().unwrap();
            sessions_of(&r, &to.mailbox).into_iter().any(|uid| {
                r.users
                    .get(&uid)
                    .is_some_and(|s| s.info.status == crate::SessionStatus::Active && is_live(s))
            })
        };
        // A message to yourself from your own other session is not news.
        let to_self = from_mailbox == to.mailbox;
        if !attentive && !to_self {
            if let Some(gateway) = &self.gateway {
                let unread = store.counts(&to.mailbox).map(|c| c.unread).unwrap_or(0);
                gateway.notify(&crate::notify::Notification::Message(
                    crate::notify::MessageNotice {
                        to: &to.mailbox,
                        from: Some(&from_mailbox),
                        from_nick: &sender_nick,
                        text: &body,
                        id: cursor,
                        unread,
                    },
                ));
            }
        }

        if delivered {
            return Ok(MsgOutcome::Delivered(Some(reference)));
        }
        Ok(MsgOutcome::Queued(reference))
    }

    /// Hand a session its waiting mail. Called at login completion (after
    /// `announce`, so the roster is coherent first), at resume, and after
    /// a `sync`. Idempotent, and safe to call on a server with no inbox.
    ///
    /// Whether the flush also stamps the rows read is the *receiving
    /// session's* business, not the caller's — see
    /// [`crate::AttachInfo::reads_on_delivery`]. A live delivery is as
    /// much a read as a queued one on a wire that cannot say otherwise,
    /// so the decision belongs where the session is resolved.
    ///
    /// Returns how many messages went out.
    pub fn flush_inbox(&self, uid: Uid) -> usize {
        let mailbox = {
            let r = self.roster.lock().unwrap();
            match r.users.get(&uid).filter(|s| s.has_inbox) {
                Some(sess) => sess.mailbox(),
                None => return 0,
            }
        };
        self.flush_to(Target::Only(uid), &mailbox, None).len()
    }

    /// Hand every attached session of `mailbox` its waiting mail, as a
    /// message by login is handed over.
    pub(crate) fn flush_mailbox(&self, mailbox: &Mailbox) {
        self.flush_to(
            Target::Named {
                uid: None,
                sender: 0,
            },
            mailbox,
            None,
        );
    }

    /// [`Self::flush_to`] those of `uids` still attached, for a message
    /// `sender` just sent.
    pub(crate) fn flush_each(
        &self,
        uids: Vec<Uid>,
        mailbox: &Mailbox,
        fresh: Option<MessageId>,
        sender: Uid,
    ) -> Vec<MessageId> {
        self.flush_to(Target::Each { uids, sender }, mailbox, fresh)
    }

    /// Who a flush to `target` reaches, and what it reads for each: a
    /// session that speaks the friend family is handed a friend's
    /// instant messages at its roster read instead, and what an approval
    /// carries waits for a session that understands requests where the
    /// account ever took them (`docs/instant-messaging.md` §5, §4.6).
    fn flush_reads(&self, target: &Target, mailbox: &Mailbox) -> Vec<(Uid, crate::inbox::Pending)> {
        let sessions: Vec<(Uid, bool, bool)> = {
            let r = self.roster.lock().unwrap();
            let uids = match target {
                Target::Only(uid) => Some(*uid)
                    .filter(|u| holds(&r, mailbox, u))
                    .into_iter()
                    .collect(),
                Target::Named { uid, sender } => named_sessions(&r, mailbox, *uid, *sender),
                Target::Each { uids, sender } => attached_sessions_of(&r, mailbox, *sender)
                    .into_iter()
                    .filter(|u| uids.contains(u))
                    .collect(),
            };
            uids.into_iter()
                .filter_map(|u| {
                    let s = r.users.get(&u)?;
                    Some((
                        u,
                        crate::messaging::is_messenger(s),
                        crate::messaging::understands_requests(s),
                    ))
                })
                .collect()
        };
        // A store read, so outside the roster lock, and once.
        let never_took = std::cell::OnceCell::new();
        let never_took = || *never_took.get_or_init(|| self.never_took_requests(mailbox));
        sessions
            .into_iter()
            .map(|(uid, messenger, understands)| {
                let which = if messenger && !understands && never_took() {
                    crate::inbox::Pending::MailApproved
                } else if messenger {
                    crate::inbox::Pending::Mail
                } else if self.messaging_enabled() && !never_took() {
                    crate::inbox::Pending::Unapproved
                } else {
                    crate::inbox::Pending::All
                };
                (uid, which)
            })
            .collect()
    }

    /// The login a reply may name, per distinct sender in a batch.
    ///
    /// Not simply the stored login: an identity guest's mailbox is keyed
    /// by fingerprint and named `guest`, and a reply to `guest` answers
    /// `no_such_user`. Asking the directory also catches a sender whose
    /// account has since been deleted or renamed — the login is free,
    /// and it is not theirs. One lookup per sender, since a batch is
    /// usually one conversation, and each one is a file read.
    ///
    /// **What this costs, and where.** It runs inside the `flushing`
    /// lock — it has to, because the batch it is about is the one
    /// `pending` just read under that lock — so up to
    /// `deliver_at_flush` (default 25) file reads are on the critical
    /// path of every other flush on the server. Off the reactor, on a
    /// lock no roster operation waits behind, and one read in the usual
    /// case of a message from one sender; but it is the ceiling to look
    /// at first if flushes ever start queueing. `inbox_list` does the
    /// same lookups for up to 200 rows, outside this lock.
    fn reply_addresses(&self, batch: &[StoredMessage]) -> HashMap<Mailbox, Option<String>> {
        let mut out: HashMap<Mailbox, Option<String>> = HashMap::new();
        for m in batch {
            let Some(sender) = m.sender.as_ref() else {
                continue;
            };
            if out.contains_key(sender) {
                continue;
            }
            let named = self
                .directory
                .as_ref()
                .and_then(|d| d.inbox_account(&sender.login))
                .filter(|named| named == sender)
                .map(|_| sender.login.clone());
            out.insert(sender.clone(), named);
        }
        out
    }

    /// `target` says which of the mailbox's sessions receives; see
    /// [`Target`].
    ///
    /// `fresh` names the message this same call has just stored, if any.
    /// It is the one message in the batch that did *not* wait for
    /// anything, so it is the one that does not carry `queued` — a
    /// recipient who was there the whole time should not be told their
    /// message is old news. Everything else in the batch genuinely sat in
    /// the inbox, however briefly.
    ///
    /// Returns the ids delivered.
    fn flush_to(
        &self,
        target: Target,
        mailbox: &Mailbox,
        fresh: Option<MessageId>,
    ) -> Vec<MessageId> {
        let Some(store) = self.inbox.as_ref() else {
            return Vec::new();
        };
        // One flush per server at a time.
        //
        // `pending` reads rows, the send happens under the roster lock,
        // and `mark_delivered` runs after that lock is released — so two
        // flushes for one mailbox (a sender's post-store flush against
        // the recipient's login flush, or two senders racing) both read
        // the same rows and both push them, and the recipient gets every
        // message twice. Not the roster lock, which would put disk I/O
        // under it; a lock of its own, taken *before* the roster lock and
        // never the other way round.
        let _flushing = self.flushing.lock().unwrap_or_else(|e| e.into_inner());

        let limit = self.inbox_policy.deliver_at_flush;
        let targets = self.flush_reads(&target, mailbox);
        // One read for each kind of session among them: on a server
        // without messaging, one read.
        let mut batches: Vec<(crate::inbox::Pending, Vec<StoredMessage>)> = Vec::new();
        for (_, which) in &targets {
            if batches.iter().any(|(w, _)| w == which) {
                continue;
            }
            match store.pending_of(mailbox, limit, *which) {
                Ok(b) => batches.push((*which, b)),
                Err(e) => {
                    warn!("inbox: reading pending mail for {}: {e}", mailbox.login);
                    return Vec::new();
                }
            }
        }
        if batches.iter().all(|(_, b)| b.is_empty()) {
            return Vec::new();
        }

        // The reply address for each row, resolved *before* the roster
        // lock: `inbox_account` reads and parses an account file, and
        // the roster mutex is the one every chat, join, part and voice
        // operation on the server waits behind (roster.rs, §6.2). A
        // 25-message login flush was 25 file reads under it.
        //
        // And which of the batch's images are still fetchable, resolved
        // in the same breath and for the same reason: a handle from
        // yesterday may have expired, and the answer belongs to the
        // event this flush is about to build.
        let (mut from_logins, mut handles) = (HashMap::new(), HashMap::new());
        for (_, batch) in &batches {
            from_logins.extend(self.reply_addresses(batch));
            handles.extend(self.media_states(batch));
        }

        let mut delivered = Vec::new();
        // Handed to a session that can say it has read them, so it is
        // left to say so: a row is read on delivery only when every
        // session it reached is one whose wire cannot.
        let mut unread = HashSet::new();
        let mut reached = Vec::with_capacity(targets.len());
        let sending = match target {
            Target::Named { sender, .. } | Target::Each { sender, .. } => Some(sender),
            Target::Only(_) => None,
        };
        {
            let mut r = self.roster.lock().unwrap();
            for (uid, which) in targets {
                // Only an attached session receives, and the lock was let
                // go for the read. A detached one leaves its mail pending
                // rather than filling an outbox buffer that is bounded and
                // dies with the grace window — the durable copy is the
                // copy.
                if !holds(&r, mailbox, &uid) {
                    continue;
                }
                let s = &r.users[&uid];
                let serial = s.serial;
                let Some((_, batch)) = batches.iter().find(|(w, _)| *w == which) else {
                    continue;
                };
                // Whose wire this is decides whether handing a message
                // over counts as reading it. Read here, where the session
                // is finally known, rather than passed in: `deliver`
                // reaches this for a live send too, and a legacy user
                // reading a message the instant it arrives has read it
                // just as much as one who read it at login.
                let reads = s.reads_on_delivery;
                // Read for another session than this one, the batch can
                // hold a friend's instant messages that this one is
                // handed at its roster read instead.
                let messenger = crate::messaging::is_messenger(s);
                // An approval's rows were read for a session that cannot
                // be handed them as IMs, so it is handed them as mail.
                let approvals = which == crate::inbox::Pending::MailApproved
                    && !crate::messaging::understands_requests(s);
                for m in batch {
                    if messenger && m.friendship.is_some() && !approvals {
                        continue;
                    }
                    // The message just sent names the session that sent
                    // it. Older ones resolve their sender now and by
                    // mailbox: the sending session is long gone and its
                    // uid may belong to someone else by now. Same
                    // identity, same person; nobody there, no uid. Never
                    // the recipient's own uid, which is what mail between
                    // two sessions of one account would otherwise name,
                    // and a reply to it is to oneself.
                    let from = sending
                        .filter(|s| Some(m.id) == fresh && r.users.contains_key(s))
                        .or_else(|| {
                            // The plain guests share one mailbox, which
                            // names none of their sessions.
                            let s = m
                                .sender
                                .as_ref()
                                .filter(|s| s.fingerprint.is_some() || s.login != "guest")?;
                            sessions_of(&r, s).into_iter().find(|u| *u != uid)
                        })
                        .unwrap_or(0);
                    let from_login = m
                        .sender
                        .as_ref()
                        .and_then(|s| from_logins.get(s).cloned().flatten());
                    r.send_to(
                        uid,
                        Event::Msg {
                            from,
                            from_nick: m.sender_nick.clone(),
                            from_login,
                            text: m.body.clone(),
                            cursor: Some(m.cursor),
                            reference: Some(m.reference),
                            sent_at: m.sent_at,
                            queued: Some(m.id) != fresh,
                            media: m.media.as_ref().and_then(|meta| media_now(&handles, meta)),
                            signed: m.signed.as_ref().map(|s| s.form.clone()),
                            re: m.re.clone().map(Box::new),
                        },
                    );
                    if !delivered.contains(&m.id) {
                        delivered.push(m.id);
                    }
                    if !reads {
                        unread.insert(m.id);
                    }
                }
                reached.push((uid, serial, which, messenger));
            }
        }

        // Stamped after the events are in the outbox: if this fails, the
        // message is delivered twice on the next flush, which is the right
        // way round to be wrong. (On the legacy wire it is the *only* way
        // round available: `delivered` there means "handed to the writer
        // task", and a socket that dies before the bytes go out loses
        // them for good — there is no resume on that wire. See
        // `docs/private-messages.md` §11.)
        let (left_unread, read): (Vec<MessageId>, Vec<MessageId>) =
            delivered.iter().partition(|id| unread.contains(id));
        for (ids, what) in [(read, Delivery::Read), (left_unread, Delivery::Delivered)] {
            if ids.is_empty() {
                continue;
            }
            if let Err(e) = store.mark_delivered(&ids, SystemTime::now(), what) {
                warn!("inbox: marking {} messages delivered: {e}", ids.len());
            }
        }

        // The cap is for the legacy wire, where each private message opens
        // a window. What it leaves behind is still there — say so, in the
        // one place a client of either wire will see it, rather than
        // inventing a digest format.
        let mut notices = Vec::new();
        let mut counted: Vec<(Option<crate::inbox::Pending>, Result<usize, StoreError>)> =
            Vec::new();
        for (uid, serial, which, messenger) in reached {
            // `None` is the count the mailbox cap is measured against.
            let of = match (messenger, which) {
                (false, crate::inbox::Pending::All) => None,
                (true, w) if w != crate::inbox::Pending::MailApproved => {
                    Some(crate::inbox::Pending::Mail)
                }
                (_, which) => Some(which),
            };
            let left = match counted.iter().find(|(o, _)| *o == of) {
                Some((_, left)) => left.clone(),
                None => {
                    let left = match of {
                        None => store.pending_count(mailbox),
                        Some(which) => store.pending_count_of(mailbox, which),
                    };
                    counted.push((of, left.clone()));
                    left
                }
            };
            match left {
                Ok(0) => {}
                Ok(n) => notices.push((uid, serial, n)),
                Err(e) => warn!("inbox: counting what is left for {}: {e}", mailbox.login),
            }
        }
        if !notices.is_empty() {
            let mut r = self.roster.lock().unwrap();
            for (uid, serial, n) in notices {
                // The uid may have been reused while the counts were read.
                if !holds(&r, mailbox, &uid) || r.users[&uid].serial != serial {
                    continue;
                }
                r.send_to(
                    uid,
                    Event::Notice {
                        cid: 0,
                        from: 0,
                        text: format!("{n} more queued messages are waiting."),
                        action: false,
                    },
                );
            }
        }

        delivered
    }

    /// One session's inbox, newest first — what a client that woke to a
    /// push calls to find out what it was woken for.
    pub fn inbox_list(
        &self,
        uid: Uid,
        before: Option<Cursor>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        issued(store.as_ref(), &mailbox, before)?;
        let mut rows = store.list(&mailbox, before, limit).map_err(store_failed)?;
        // The same reply-address rule the delivered event carries: a row
        // whose sender no longer names an account a reply can reach
        // keeps its nick and loses its address, rather than offering a
        // `guest` login that answers `no_such_user`.
        let addresses = self.reply_addresses(&rows);
        for m in &mut rows {
            let reachable = m
                .sender
                .as_ref()
                .is_some_and(|s| addresses.get(s).is_some_and(Option::is_some));
            if !reachable {
                m.sender = None;
            }
        }
        Ok(rows)
    }

    /// Unread and total for a mailbox named directly, rather than by a
    /// session holding it. For operator tooling and for tests that need
    /// to look at a mailbox nobody is logged in to.
    pub fn inbox_counts_of(&self, mailbox: &Mailbox) -> InboxCounts {
        self.inbox
            .as_ref()
            .and_then(|s| s.counts(mailbox).ok())
            .unwrap_or_default()
    }

    /// Unread and total for one session's mailbox.
    pub fn inbox_counts(&self, uid: Uid) -> Result<InboxCounts, ChatError> {
        let Ok((store, mailbox)) = self.inbox_of(uid) else {
            return Ok(InboxCounts::default());
        };
        store.counts(&mailbox).map_err(store_failed)
    }

    /// Mark one session's mail read up to and including `up_to`, and
    /// answer with what is left.
    ///
    /// `up_to` is a cursor in this mailbox, and what the store scopes is
    /// the mailbox — no call here can mark another account's mail read.
    pub fn inbox_mark_read(&self, uid: Uid, up_to: Cursor) -> Result<InboxCounts, ChatError> {
        let (store, mailbox) = self.inbox_of(uid)?;
        issued(store.as_ref(), &mailbox, Some(up_to))?;
        store
            .mark_read(&mailbox, up_to, SystemTime::now())
            .map_err(store_failed)?;
        store.counts(&mailbox).map_err(store_failed)
    }

    /// Block or unblock an account, by login.
    ///
    /// Blocking works between accounts that have inboxes, because that is
    /// what a durable block can be about: an account with no inbox cannot
    /// queue anything for you and has no identity to hold the block
    /// against. Naming anything else answers `NoSuchUser`, the same one
    /// answer `msg_login` gives.
    pub fn inbox_block(&self, uid: Uid, other: &str, blocked: bool) -> Result<(), ChatError> {
        let (store, mailbox) = self.relationships_of(uid)?;
        let directory = self.directory.as_ref().ok_or(ChatError::NoSuchUser)?;
        let other = directory
            .inbox_account(other)
            .ok_or(ChatError::NoSuchUser)?;
        if other == mailbox {
            // Blocking yourself is not a thing worth storing, and a
            // mailbox that cannot receive its own mail is a support
            // question waiting to happen.
            return Err(ChatError::NoSuchUser);
        }
        store
            .set_blocked(&mailbox, &other, blocked, SystemTime::now())
            .map_err(store_failed)?;
        self.block_changed(&mailbox, &other, blocked);
        Ok(())
    }

    /// Block or unblock whoever holds `uid` on the roster.
    ///
    /// The uid form exists for the sender a login cannot name: an
    /// identity user admitted as a guest has a fingerprint to hold a
    /// block against but no account of its own, and a recipient who just
    /// received a message from one can only point at the roster row.
    pub fn inbox_block_uid(&self, uid: Uid, other: Uid, blocked: bool) -> Result<(), ChatError> {
        if let Some(done) = self.block_ghost(uid, other, blocked) {
            return done;
        }
        let (store, mailbox) = self.relationships_of(uid)?;
        let other = {
            let r = self.roster.lock().unwrap();
            let sess = r
                .users
                .get(&other)
                .filter(|s| s.visible && (s.has_inbox || s.identity.is_some()))
                .ok_or(ChatError::NoSuchUser)?;
            sess.mailbox()
        };
        if other == mailbox {
            return Err(ChatError::NoSuchUser);
        }
        store
            .set_blocked(&mailbox, &other, blocked, SystemTime::now())
            .map_err(store_failed)?;
        self.block_changed(&mailbox, &other, blocked);
        Ok(())
    }

    /// Who this session has blocked.
    ///
    /// Mailboxes, not logins: an identity guest is blocked as
    /// `{guest, fingerprint}`, and a list of logins showed `guest` — a
    /// name `unblock` then couldn't resolve and the roster couldn't
    /// answer for once they left. The fingerprint is what identifies
    /// that block, so it is what the list carries.
    pub fn inbox_blocked(&self, uid: Uid) -> Result<Vec<Mailbox>, ChatError> {
        let (store, mailbox) = self.relationships_of(uid)?;
        store.blocked(&mailbox).map_err(store_failed)
    }

    /// Unblock by fingerprint: the form that works for a sender who has
    /// left and has no account to name — the identity guest of
    /// `inbox_block_uid`. Blocking still needs a login or a roster row;
    /// you cannot block someone you have never seen.
    pub fn inbox_unblock_fingerprint(
        &self,
        uid: Uid,
        fingerprint: &[u8; 32],
    ) -> Result<(), ChatError> {
        let (store, mailbox) = self.relationships_of(uid)?;
        let other = store
            .blocked(&mailbox)
            .map_err(store_failed)?
            .into_iter()
            .find(|m| m.fingerprint.as_ref() == Some(fingerprint))
            .ok_or(ChatError::NoSuchUser)?;
        store
            .set_blocked(&mailbox, &other, false, SystemTime::now())
            .map_err(store_failed)?;
        self.block_changed(&mailbox, &other, false);
        Ok(())
    }

    /// An account gave up its link to `fingerprint`: its bare login's
    /// cursors count on past the identity mailbox's
    /// ([`MessageStore::unlinked`]).
    pub fn inbox_unlinked(&self, login: &str, fingerprint: &[u8; 32]) {
        if let Some(Err(e)) = self.inbox.as_ref().map(|s| s.unlinked(login, fingerprint)) {
            warn!("inbox: {login} unlinking: {e}");
        }
    }

    /// An account has linked an identity: move its mail onto the
    /// fingerprint. The account-linking path owes this call — see
    /// [`crate::inbox::MessageStore::claim`]. Relationships, news
    /// subscriptions and push devices are keyed the same way and move in
    /// the same call, so every link site that pays one obligation pays
    /// them all. Returns how much mail moved.
    pub fn inbox_claim(&self, login: &str, fingerprint: &[u8; 32]) -> usize {
        self.news_subs_claim(login, fingerprint);
        self.devices_claim(login, fingerprint);
        let rekeyed = match self
            .relationships
            .as_ref()
            .map(|s| s.claim(login, fingerprint))
        {
            Some(Ok(rekeyed)) => rekeyed,
            Some(Err(e)) => {
                warn!("relationships: claiming {login}'s: {e}");
                crate::relationships::Rekeyed::default()
            }
            None => crate::relationships::Rekeyed::default(),
        };
        let moved = match self.inbox.as_ref().map(|s| s.claim(login, fingerprint)) {
            Some(Ok(n)) => n,
            Some(Err(e)) => {
                warn!("inbox: claiming {login}'s mail: {e}");
                0
            }
            None => 0,
        };
        if let Err(e) = self.restamp(&rekeyed.merged) {
            warn!("inbox: re-stamping {login}'s merged friendships: {e}");
        }
        let claimed = Mailbox::identified(login, *fingerprint);
        self.rekey_reactions(&Mailbox::login(login), &claimed);
        self.rekey_friends(&Mailbox::login(login), &claimed);
        // A claim runs at every login of a linked account; only one
        // that moved rows can have folded a block beside a friendship.
        if rekeyed.moved > 0 {
            self.after_merge(&claimed);
        }
        moved
    }

    /// Messages sent on a friendship or approval a merge ended now
    /// belong to the one that stands in its place.
    pub(crate) fn restamp(
        &self,
        merged: &[(crate::RelationId, crate::RelationId)],
    ) -> Result<usize, StoreError> {
        match self.inbox.as_ref() {
            Some(store) if !merged.is_empty() => store.restamp(merged),
            _ => Ok(0),
        }
    }

    /// An account has been deleted: take its mail, its relationships, its
    /// news subscriptions and its push devices with it, so a later holder of
    /// the freed login inherits none of them. Its news push budget goes too, but that is
    /// memory, and only a purge in the server's own process reaches it —
    /// `hxd inbox purge` purges the stores from a process of its own (see
    /// `news_rotate`). Returns how much mail went.
    pub fn inbox_purge(&self, of: &Mailbox) -> usize {
        self.forget_reactions(of, Duration::MAX);
        self.news_subs_purge(of);
        self.devices_purge(of);
        self.purge_relationships(of);
        let Some(store) = self.inbox.as_ref() else {
            return 0;
        };
        match store.purge(of) {
            Ok(n) => n,
            Err(e) => {
                warn!("inbox: purging {}: {e}", of.login);
                0
            }
        }
    }

    /// Retention. The binary runs this on an interval, next to the
    /// detached-session sweeper. Returns how many messages went.
    pub fn prune_inbox(&self, unread: Duration, read: Duration) -> usize {
        let Some(store) = self.inbox.as_ref() else {
            return 0;
        };
        match store.prune(SystemTime::now(), unread, read) {
            Ok(n) => n,
            Err(e) => {
                warn!("inbox: pruning: {e}");
                0
            }
        }
    }

    /// The relationship store and `uid`'s mailbox in it, on the terms
    /// [`Self::inbox_of`] gives the inbox: blocks are between accounts
    /// that have inboxes.
    fn relationships_of(
        &self,
        uid: Uid,
    ) -> Result<(&Arc<dyn RelationshipStore>, Mailbox), ChatError> {
        let (_, mailbox) = self.inbox_of(uid)?;
        Ok((self.relationships()?, mailbox))
    }

    fn relationships(&self) -> Result<&Arc<dyn RelationshipStore>, ChatError> {
        self.relationships.as_ref().ok_or(ChatError::NoInbox)
    }

    /// The store and the mailbox behind a session, when both exist.
    fn inbox_of(&self, uid: Uid) -> Result<(&Arc<dyn MessageStore>, Mailbox), ChatError> {
        let store = self.inbox.as_ref().ok_or(ChatError::NoInbox)?;
        let r = self.roster.lock().unwrap();
        let sess = r
            .users
            .get(&uid)
            .filter(|s| s.has_inbox)
            .ok_or(ChatError::NoInbox)?;
        Ok((store, sess.mailbox()))
    }

    /// An administrator broadcast, to everyone (sender included).
    pub fn broadcast(&self, from: Uid, text: String) -> Result<(), ChatError> {
        let mut r = self.roster.lock().unwrap();
        let from_nick = r
            .users
            .get(&from)
            .map(|s| s.info.nick.clone())
            .ok_or(ChatError::NoSuchUser)?;
        r.broadcast_where(
            &Event::Broadcast {
                from,
                from_nick,
                text,
            },
            None,
            |_| true,
        );
        Ok(())
    }

    // --- Moderation -----------------------------------------------------

    /// Kick `target`, optionally banning it for `ban_for`, on the
    /// operator's word. [`Core::kick_by`] with no one to name; returns
    /// the target's nick.
    pub fn kick(&self, target: Uid, ban_for: Option<Duration>) -> Result<String, ChatError> {
        self.kick_by(
            target,
            ban_for.map(|for_| KickBan {
                by: crate::moderation::Actor::Operator,
                for_,
                reason: "kicked with a ban".into(),
            }),
        )
        .map(|k| k.nick)
    }

    /// Kick `target`, and with `ban` ban it too. The target session
    /// receives [`Event::Kicked`] and its transport closes; the
    /// public-chat announcement is the caller's job (it owns the
    /// wording, and [`Kicked::banned`] says which verb). The
    /// cant-be-disconnected check is policy and lives in the caller,
    /// which has the target's access via [`Core::access_of`].
    ///
    /// The ban is a durable one (`crate::ban`), on the person and on the
    /// address the session came from ([`Core::kick_ban_targets`]; an
    /// IPv4 address alone, an IPv6 one with its `[moderation]
    /// ban_v6_prefix` block), not on an exempt address. It ends no other
    /// session, as the reference server's kick-with-ban does not: they
    /// are refused at their next connection.
    pub fn kick_by(&self, target: Uid, ban: Option<KickBan>) -> Result<Kicked, ChatError> {
        let (nick, targets, serial) = {
            let mut r = self.roster.lock().unwrap();
            // A session no list shows is nobody to kick by uid, as it is
            // nobody to message or ask about: a messenger session
            // (`Transport::messenger_session`) is ended by a ban.
            let sess = r
                .users
                .get_mut(&target)
                .filter(|s| s.visible)
                .ok_or(ChatError::NoSuchUser)?;
            // The server cannot be kicked off its own roster
            // (`docs/system-account.md` §2). Refused the same way a kick
            // of somebody who is not there is refused, because from the
            // moderator's point of view there is nobody there to kick.
            if sess.system {
                return Err(ChatError::NoSuchUser);
            }
            let targets = match ban {
                Some(_) => self.kick_ban_targets(sess),
                None => Vec::new(),
            };
            // So its leaving crosses links as a ban; the session ends
            // either way, so an unplaced ban leaves nothing stale.
            sess.banned |= !targets.is_empty();
            (sess.info.nick.clone(), targets, sess.serial)
        };
        let banned = ban.is_some_and(|ban| self.place_kick_ban(target, targets, ban));
        let mut r = self.roster.lock().unwrap();
        // The roster lock was let go while the ban was written. A target
        // that left meanwhile is gone, and its uid, if it has been given
        // out again, is somebody else's.
        if r.users.get(&target).map(|s| s.serial) != Some(serial) {
            return Ok(Kicked { nick, banned });
        }
        kick_in(&mut r, target).map(|nick| Kicked { nick, banned })
    }

    /// The address block a kick-with-ban from `addr` bans: the address
    /// itself on IPv4, its `[moderation] ban_v6_prefix` block on IPv6.
    /// An IPv6 address whose /64 is no subscriber's block is banned
    /// alone, as /128 ([`v6_stands_alone`]).
    fn address_ban_target(&self, addr: IpAddr) -> Option<crate::ban::BanTarget> {
        let prefix = match addr.to_canonical() {
            IpAddr::V4(_) => 32,
            IpAddr::V6(v6) if v6_stands_alone(v6) => 128,
            IpAddr::V6(_) => self.moderation_policy.ban_v6_prefix,
        };
        crate::ban::BanTarget::address(addr, prefix)
            .map_err(|e| warn!("kick: no ban on {addr}: {e}"))
            .ok()
    }

    /// Place a kick's ban on `targets` ([`Core::kick_ban_targets`]), as
    /// one act. Said in the log when it cannot be placed, and the kick
    /// goes ahead either way. Whether any of it was placed.
    fn place_kick_ban(&self, uid: Uid, targets: Vec<crate::ban::BanTarget>, ban: KickBan) -> bool {
        use crate::ban::BanTarget;
        if targets.is_empty() {
            debug!(target = uid, "kicked: nothing of theirs alone to ban");
            return false;
        }
        let placed = self.acting_kicker(ban.by).and_then(|acting| {
            // A moderator kicking another session of their own does not
            // ban themselves, which `place_ban` refuses outright: the
            // address is banned without them. Only a session is anyone
            // to leave out: the operator's name is no login of its own,
            // and an account that shares it is banned like any other.
            let mut targets: Vec<BanTarget> = match acting.uid {
                Some(_) => targets
                    .into_iter()
                    .filter(|t| match t {
                        BanTarget::Login(l) => *l != acting.name.to_lowercase(),
                        BanTarget::Identity(fp) => acting.fingerprint.as_ref() != Some(fp),
                        _ => true,
                    })
                    .collect(),
                None => targets,
            };
            if targets.is_empty() {
                debug!(target = uid, "kicked: nothing but the kicker to ban");
                return None;
            }
            let first = targets.remove(0);
            self.place_bans_as(
                &acting,
                crate::ban::NewBan {
                    target: first,
                    reason: ban.reason,
                    note: None,
                    // Past what the clock can say is until lifted.
                    expires_at: SystemTime::now().checked_add(ban.for_),
                    source: crate::ban::BanSource::Kick,
                },
                targets,
            )
            .map_err(|e| warn!("kick: the ban was not placed: {e:?}"))
            .ok()
        });
        if placed.is_none() {
            warn!(target = uid, "kicked without the ban it asked for");
        }
        placed.is_some()
    }

    /// A user's access bits (for policy checks against a *target*, e.g.
    /// cant-be-disconnected).
    pub fn access_of(&self, uid: Uid) -> Option<crate::AccessBits> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.access)
    }

    /// Is this address banned (`crate::ban`)?
    pub fn is_banned(&self, addr: IpAddr) -> bool {
        self.address_banned(addr).is_some()
    }
}

/// [`Core::kick`], without its ban, under a roster lock the caller
/// already holds: a ban is written to the store, and that is not done
/// under the roster's lock.
pub(crate) fn kick_in(r: &mut RosterInner, target: Uid) -> Result<String, ChatError> {
    let sess = r.users.get(&target).ok_or(ChatError::NoSuchUser)?;
    // The server cannot be kicked off its own roster
    // (`docs/system-account.md` §2). Refused the same way a kick of
    // somebody who is not there is refused, because from the
    // moderator's point of view there is nobody there to kick.
    if sess.system {
        return Err(ChatError::NoSuchUser);
    }
    let nick = sess.info.nick.clone();
    if let Some(sess) = r.users.get_mut(&target) {
        sess.kicked = true;
    }
    r.send_to(target, Event::Kicked);
    // A detached session has no connection to observe the event; the
    // kick must end it here or it would linger on the roster.
    if r.users
        .get(&target)
        .is_some_and(crate::roster::is_buffering)
    {
        r.end_session(target);
    }
    Ok(nick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::bit;
    use crate::roster::drain;
    use crate::roster::test_attach;
    use crate::AccessBits;

    fn chatter() -> AccessBits {
        AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT)
    }

    /// A log whose commits take a while and that says how many lines each
    /// one carried.
    struct SlowLog {
        inner: crate::history::MemoryLog,
        commits: Mutex<Vec<usize>>,
    }

    impl crate::history::ChatLog for SlowLog {
        fn lines(
            &self,
            channel: u32,
            ids: &[crate::history::LineId],
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.inner.lines(channel, ids)
        }
        fn lines_by_ghost(
            &self,
            channel: Option<u32>,
            ghost: [u8; 16],
            since: SystemTime,
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.inner.lines_by_ghost(channel, ghost, since)
        }
        fn append_all(
            &self,
            lines: &[NewLine],
        ) -> Result<Vec<crate::history::Appended>, StoreError> {
            std::thread::sleep(Duration::from_millis(5));
            self.commits.lock().unwrap().push(lines.len());
            self.inner.append_all(lines)
        }
        fn query(&self, q: &HistoryQuery) -> Result<HistoryPage, StoreError> {
            self.inner.query(q)
        }
        fn line(
            &self,
            id: crate::history::LineId,
        ) -> Result<Option<crate::history::LogLine>, StoreError> {
            self.inner.line(id)
        }
        fn lines_by(
            &self,
            channel: Option<u32>,
            who: &Mailbox,
            since: SystemTime,
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.inner.lines_by(channel, who, since)
        }
        fn tombstone(
            &self,
            id: crate::history::LineId,
            by: &str,
            at: SystemTime,
        ) -> Result<bool, StoreError> {
            self.inner.tombstone(id, by, at)
        }
        fn prune(
            &self,
            keep: &crate::history::Retention,
            now: SystemTime,
        ) -> Result<usize, StoreError> {
            self.inner.prune(keep, now)
        }
        fn channels(&self) -> Result<Vec<(u32, crate::history::LineId)>, StoreError> {
            self.inner.channels()
        }
        fn delete_channel(&self, channel: u32) -> Result<usize, StoreError> {
            self.inner.delete_channel(channel)
        }
        fn find_guid(
            &self,
            channel: u32,
            sender: &str,
            guid: &MessageGuid,
        ) -> Result<Option<crate::history::LineId>, StoreError> {
            self.inner.find_guid(channel, sender, guid)
        }
        fn find_signed(
            &self,
            signer: &[u8; 32],
            guid: &MessageGuid,
        ) -> Result<Option<crate::history::SignedAt>, StoreError> {
            self.inner.find_signed(signer, guid)
        }
        fn room_marks(&self) -> Result<HashMap<u32, bool>, StoreError> {
            self.inner.room_marks()
        }
        fn set_room_mark(&self, room: u32, signed: bool) -> Result<(), StoreError> {
            self.inner.set_room_mark(room, signed)
        }
        fn holds_unsigned(&self, channel: u32) -> Result<bool, StoreError> {
            self.inner.holds_unsigned(channel)
        }
        fn restore_signed(
            &self,
            id: crate::history::LineId,
            form: &[u8],
        ) -> Result<(), StoreError> {
            self.inner.restore_signed(id, form)
        }
        fn holds_home_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
            self.inner.holds_home_key(key)
        }
        fn react(
            &self,
            act: &crate::reaction::ReactAct,
        ) -> Result<crate::reaction::Reacted, StoreError> {
            self.inner.react(act)
        }
        fn reactions(
            &self,
            ids: &[crate::history::LineId],
            reader: Option<&Mailbox>,
        ) -> Result<HashMap<crate::history::LineId, crate::reaction::Reactions>, StoreError>
        {
            self.inner.reactions(ids, reader)
        }
        fn forget_reactions(
            &self,
            who: &Mailbox,
            since: SystemTime,
        ) -> Result<Vec<crate::history::LineId>, StoreError> {
            self.inner.forget_reactions(who, since)
        }
        fn rekey_reactions(
            &self,
            from: &Mailbox,
            to: &Mailbox,
        ) -> Result<Vec<crate::history::LineId>, StoreError> {
            self.inner.rekey_reactions(from, to)
        }
        fn reactors_on(
            &self,
            ids: &[crate::history::LineId],
        ) -> Result<Vec<(crate::history::LineId, String, crate::reaction::ReactionKey)>, StoreError>
        {
            self.inner.reactors_on(ids)
        }
        fn clear_reactions(
            &self,
            channel: u32,
            line: crate::history::LineId,
        ) -> Result<Option<usize>, StoreError> {
            self.inner.clear_reactions(channel, line)
        }
        fn attach_media(
            &self,
            id: crate::history::LineId,
            media: &crate::history::MediaMeta,
        ) -> Result<(), StoreError> {
            self.inner.attach_media(id, media)
        }
    }

    /// Lines sent at once share commits, and are still logged and heard in
    /// one order: every reader hears every line once, ids rising, and every
    /// sender is told its own lines' ids.
    #[test]
    fn lines_sent_at_once_share_commits_and_keep_one_order() {
        let log = Arc::new(SlowLog {
            inner: Default::default(),
            commits: Default::default(),
        });
        let core = Arc::new(Core::new().with_history(log.clone(), Default::default()));
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let senders: Vec<Uid> = (0..8)
            .map(|i| test_attach(&core, &format!("s{i}"), chatter()).0)
            .collect();
        drain(&mut rx);
        let threads: Vec<_> = senders
            .iter()
            .map(|&uid| {
                let core = core.clone();
                std::thread::spawn(move || {
                    (0..25)
                        .map(|n| {
                            let text = format!("{uid} {n}");
                            (
                                text.clone(),
                                core.chat_public(uid, text, 0, None).unwrap().unwrap(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let sent: HashMap<String, crate::history::LineId> = threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect();
        let heard: Vec<(String, crate::history::LineId)> = drain(&mut rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { text, id, .. } => Some((text, id.unwrap())),
                _ => None,
            })
            .collect();
        assert_eq!(heard.len(), 8 * 25, "every line, once");
        assert!(heard.windows(2).all(|w| w[0].1 < w[1].1), "one order");
        for (text, id) in &heard {
            assert_eq!(sent[text], *id, "each sender is told its line's id");
        }
        let commits = log.commits.lock().unwrap();
        assert!(commits.len() < heard.len(), "shared: {commits:?}");
        assert!(commits.iter().all(|&n| n <= COMMIT_BATCH));
    }

    #[test]
    fn one_callers_lines_share_commits_beside_others_and_keep_their_order() {
        let log = Arc::new(SlowLog {
            inner: Default::default(),
            commits: Default::default(),
        });
        let core = Arc::new(Core::new().with_history(log.clone(), Default::default()));
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let (sender, _) = test_attach(&core, "local", chatter());
        let ghost = core.user(sender).unwrap();
        drain(&mut rx);
        let n = COMMIT_BATCH * 2 + 10;
        let ghosts = {
            let core = core.clone();
            std::thread::spawn(move || {
                let lines = (0..n)
                    .map(|i| Staged::ghost(ghost.clone(), [7; 16], format!("g {i}"), 0, None))
                    .collect();
                core.chat_commit.submit_all(&core, lines)
            })
        };
        let locals = {
            let core = core.clone();
            std::thread::spawn(move || {
                for i in 0..20 {
                    core.chat_public(sender, format!("l {i}"), 0, None).unwrap();
                }
            })
        };
        let answered = ghosts.join().unwrap();
        locals.join().unwrap();
        assert!(answered.iter().all(|r| matches!(r, Ok(Some(_)))));
        let heard: Vec<String> = drain(&mut rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { text, .. } if text.starts_with("g ") => Some(text),
                _ => None,
            })
            .collect();
        let want: Vec<String> = (0..n).map(|i| format!("g {i}")).collect();
        assert_eq!(heard, want, "every ghost line, once, in its order");
        let commits = log.commits.lock().unwrap();
        assert!(commits.len() < n / 10, "shared: {commits:?}");
        assert!(commits.iter().all(|&c| c <= COMMIT_BATCH));
    }

    #[test]
    fn a_senders_run_is_one_commit_and_its_flood_heard_after_the_lines_before() {
        let log = Arc::new(SlowLog {
            inner: Default::default(),
            commits: Default::default(),
        });
        let core = Arc::new(
            Core::new()
                .with_history(log.clone(), Default::default())
                .with_flood_limits(flood_limits()),
        );
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let (sender, _) = test_attach(&core, "spammer", chatter());
        drain(&mut rx);
        let lines = ["one", "two", "three", "four", "five"]
            .map(|t| (t.to_string(), 0, None))
            .into();
        let answered = core.chat_public_all(sender, 0, lines);
        assert!(answered[..3].iter().all(|r| matches!(r, Ok(Some(_)))));
        assert!(answered[3..].iter().all(|r| *r == Err(ChatError::Flooding)));
        let heard: Vec<String> = drain(&mut rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { text, .. } | Event::Notice { text, .. } => Some(text),
                _ => None,
            })
            .collect();
        assert_eq!(
            heard,
            [
                "one",
                "two",
                "three",
                "spammer was kicked for chat spamming"
            ]
        );
        assert_eq!(*log.commits.lock().unwrap(), [3], "one commit");
    }

    #[test]
    fn no_lines_at_all_leave_the_room_free_to_talk() {
        let core = Core::new().with_history(
            Arc::new(crate::history::MemoryLog::default()),
            Default::default(),
        );
        let (sender, _rx) = test_attach(&core, "local", chatter());
        core.ghost_chat_all(Vec::new());
        assert!(core
            .chat_public(sender, "still here".into(), 0, None)
            .is_ok());
    }

    /// A log whose commits wait at a gate the test opens.
    struct GatedLog {
        inner: crate::history::MemoryLog,
        gate: Mutex<bool>,
        opened: Condvar,
    }

    impl crate::history::ChatLog for GatedLog {
        fn lines(
            &self,
            channel: u32,
            ids: &[crate::history::LineId],
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.inner.lines(channel, ids)
        }
        fn lines_by_ghost(
            &self,
            channel: Option<u32>,
            ghost: [u8; 16],
            since: SystemTime,
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.inner.lines_by_ghost(channel, ghost, since)
        }
        fn append_all(
            &self,
            lines: &[NewLine],
        ) -> Result<Vec<crate::history::Appended>, StoreError> {
            let mut open = self.gate.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
            self.inner.append_all(lines)
        }
        fn query(&self, q: &HistoryQuery) -> Result<HistoryPage, StoreError> {
            self.inner.query(q)
        }
        fn line(
            &self,
            id: crate::history::LineId,
        ) -> Result<Option<crate::history::LogLine>, StoreError> {
            self.inner.line(id)
        }
        fn lines_by(
            &self,
            channel: Option<u32>,
            who: &Mailbox,
            since: SystemTime,
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.inner.lines_by(channel, who, since)
        }
        fn tombstone(
            &self,
            id: crate::history::LineId,
            by: &str,
            at: SystemTime,
        ) -> Result<bool, StoreError> {
            self.inner.tombstone(id, by, at)
        }
        fn prune(
            &self,
            keep: &crate::history::Retention,
            now: SystemTime,
        ) -> Result<usize, StoreError> {
            self.inner.prune(keep, now)
        }
        fn channels(&self) -> Result<Vec<(u32, crate::history::LineId)>, StoreError> {
            self.inner.channels()
        }
        fn delete_channel(&self, channel: u32) -> Result<usize, StoreError> {
            self.inner.delete_channel(channel)
        }
        fn find_guid(
            &self,
            channel: u32,
            sender: &str,
            guid: &MessageGuid,
        ) -> Result<Option<crate::history::LineId>, StoreError> {
            self.inner.find_guid(channel, sender, guid)
        }
        fn find_signed(
            &self,
            signer: &[u8; 32],
            guid: &MessageGuid,
        ) -> Result<Option<crate::history::SignedAt>, StoreError> {
            self.inner.find_signed(signer, guid)
        }
        fn room_marks(&self) -> Result<HashMap<u32, bool>, StoreError> {
            self.inner.room_marks()
        }
        fn set_room_mark(&self, room: u32, signed: bool) -> Result<(), StoreError> {
            self.inner.set_room_mark(room, signed)
        }
        fn holds_unsigned(&self, channel: u32) -> Result<bool, StoreError> {
            self.inner.holds_unsigned(channel)
        }
        fn restore_signed(
            &self,
            id: crate::history::LineId,
            form: &[u8],
        ) -> Result<(), StoreError> {
            self.inner.restore_signed(id, form)
        }
        fn holds_home_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
            self.inner.holds_home_key(key)
        }
        fn react(
            &self,
            act: &crate::reaction::ReactAct,
        ) -> Result<crate::reaction::Reacted, StoreError> {
            self.inner.react(act)
        }
        fn reactions(
            &self,
            ids: &[crate::history::LineId],
            reader: Option<&Mailbox>,
        ) -> Result<HashMap<crate::history::LineId, crate::reaction::Reactions>, StoreError>
        {
            self.inner.reactions(ids, reader)
        }
        fn forget_reactions(
            &self,
            who: &Mailbox,
            since: SystemTime,
        ) -> Result<Vec<crate::history::LineId>, StoreError> {
            self.inner.forget_reactions(who, since)
        }
        fn rekey_reactions(
            &self,
            from: &Mailbox,
            to: &Mailbox,
        ) -> Result<Vec<crate::history::LineId>, StoreError> {
            self.inner.rekey_reactions(from, to)
        }
        fn reactors_on(
            &self,
            ids: &[crate::history::LineId],
        ) -> Result<Vec<(crate::history::LineId, String, crate::reaction::ReactionKey)>, StoreError>
        {
            self.inner.reactors_on(ids)
        }
        fn clear_reactions(
            &self,
            channel: u32,
            line: crate::history::LineId,
        ) -> Result<Option<usize>, StoreError> {
            self.inner.clear_reactions(channel, line)
        }
        fn attach_media(
            &self,
            id: crate::history::LineId,
            media: &crate::history::MediaMeta,
        ) -> Result<(), StoreError> {
            self.inner.attach_media(id, media)
        }
    }

    /// A line that waited in the queue is asked about again when its turn
    /// comes: one whose sender has gone is not logged or heard — a kick
    /// with a purge between two batches misses nothing — and one whose
    /// sender was renamed goes out under the new name.
    #[test]
    fn a_waiting_line_is_asked_about_again_when_its_commit_comes() {
        let log = Arc::new(GatedLog {
            inner: Default::default(),
            gate: Mutex::new(false),
            opened: Condvar::new(),
        });
        let core = Arc::new(Core::new().with_history(log.clone(), Default::default()));
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let (first, _) = test_attach(&core, "first", chatter());
        let (leaving, _) = test_attach(&core, "leaving", chatter());
        let (renamed, _) = test_attach(&core, "renamed", chatter());
        drain(&mut rx);
        let send = |uid, text: &'static str| {
            let core = core.clone();
            std::thread::spawn(move || core.chat_public(uid, text.into(), 0, None))
        };
        // The first line leads a commit that waits at the gate; the others
        // queue behind it.
        let a = send(first, "one");
        while !core.chat_commit.state.lock().unwrap().leading {
            std::thread::yield_now();
        }
        let b = send(leaving, "two");
        let c = send(renamed, "three");
        while core.chat_commit.state.lock().unwrap().queue.len() < 2 {
            std::thread::yield_now();
        }
        core.end_session(leaving);
        core.update(renamed, Some("new name".into()), None);
        *log.gate.lock().unwrap() = true;
        log.opened.notify_all();

        assert!(a.join().unwrap().is_ok());
        assert_eq!(b.join().unwrap(), Err(ChatError::NoSuchUser));
        assert!(c.join().unwrap().is_ok());
        let heard: Vec<(String, String)> = drain(&mut rx)
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { text, from, .. } => Some((text, from.nick)),
                _ => None,
            })
            .collect();
        assert_eq!(
            heard,
            [
                ("one".to_string(), "first".to_string()),
                ("three".to_string(), "new name".to_string())
            ]
        );
    }

    fn a_guid() -> MessageGuid {
        MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap()
    }

    fn said_with_guid(events: Vec<Event>) -> Vec<(String, Option<MessageGuid>)> {
        events
            .into_iter()
            .filter_map(|e| match e {
                Event::Chat { text, guid, .. } => Some((text, guid)),
                _ => None,
            })
            .collect()
    }

    /// A session as `login`, with one person behind it or not, an inbox
    /// or not, and an identity or not: the three facts a guid's sender
    /// could be read from.
    fn attach_as(
        core: &Core,
        (login, person, inbox, identity): (&str, bool, bool, Option<[u8; 32]>),
    ) -> (Uid, crate::Events) {
        let (uid, rx) = core
            .attach(crate::roster::AttachInfo {
                account: None,
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: login.to_string(),
                addr: None,
                can_detach: false,
                transport: crate::Transport::default(),
                has_inbox: inbox,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: person,
                reads_on_delivery: false,
                identity,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    /// Who sends a guid again decides whether it is the line it repeats:
    /// the sender is its account where one person is behind it, or its
    /// identity, whatever its inbox; and anyone else's session. A repeat
    /// is answered with the line's id and heard by nobody.
    #[test]
    fn a_guid_sent_again_by_its_sender_is_one_line() {
        let person = ("alice", true, true, None);
        let bob = ("bob", true, true, None);
        let guest = ("guest", false, false, None);
        let mailed_guest = ("guest", false, true, None);
        let unmailed = ("alice", true, false, None);
        let (seven, eight) = (
            ("guest", false, false, Some([7; 32])),
            ("guest", false, false, Some([8; 32])),
        );
        // (case, first sender, second sender, from a second session,
        // one line)
        let cases = [
            ("its session", person, person, false, true),
            ("its account", person, person, true, true),
            ("another account", person, bob, true, false),
            ("its guest session", guest, guest, false, true),
            ("another guest", guest, guest, true, false),
            ("guests with mail", mailed_guest, mailed_guest, true, false),
            ("a person without mail", unmailed, unmailed, true, true),
            ("its identity as a guest", seven, seven, true, true),
            ("another identity as a guest", seven, eight, true, false),
        ];
        for (case, first, second, new_session, one) in cases {
            let core = Core::new().with_history(
                Arc::new(crate::history::MemoryLog::default()),
                Default::default(),
            );
            let (_reader, mut rx) = test_attach(&core, "reader", chatter());
            let (a, _ra) = attach_as(&core, first);
            let (b, _rb) = match new_session {
                true => {
                    let (b, rb) = attach_as(&core, second);
                    (b, Some(rb))
                }
                false => (a, None),
            };
            drain(&mut rx);
            let say = |uid, text: &str| {
                core.chat_public_guid(uid, 0, (text.into(), 0, None), Some(a_guid()))
                    .unwrap()
                    .expect("a logged line")
            };
            let (original, again) = (say(a, "hi"), say(b, "hi again"));
            let heard: Vec<String> = said_with_guid(drain(&mut rx))
                .into_iter()
                .map(|(text, _)| text)
                .collect();
            if one {
                assert_eq!(again, original, "{case}");
                assert_eq!(heard, ["hi"], "{case}");
            } else {
                assert_ne!(again, original, "{case}");
                assert_eq!(heard, ["hi", "hi again"], "{case}");
            }
        }
    }

    /// The guid rides on the sending session's copy of its line and on
    /// nobody else's, its own account's other session included.
    #[test]
    fn a_lines_guid_reaches_its_sending_session_alone() {
        let core = Core::new();
        let (a, mut ra) = super::inbox_tests::attach(&core, "alice", true);
        let (_, mut other) = super::inbox_tests::attach(&core, "alice", true);
        drain(&mut ra);
        drain(&mut other);
        core.chat_public_guid(a, 0, ("hi".into(), 0, None), Some(a_guid()))
            .unwrap();
        assert_eq!(
            said_with_guid(drain(&mut ra)),
            [("hi".to_string(), Some(a_guid()))]
        );
        assert_eq!(
            said_with_guid(drain(&mut other)),
            [("hi".to_string(), None)]
        );
    }

    /// Past the in-memory window a guid is remembered only where the log
    /// keeps its line: with history, by a person, a repeat is still its
    /// line; without history, or from a guest, it is a second one.
    #[test]
    fn past_its_window_a_guid_is_held_by_the_log_alone() {
        // (case, a log, a person, lines heard)
        let cases = [
            ("the log keeps it", true, true, 1),
            ("no log", false, true, 2),
            ("a guest's", true, false, 2),
        ];
        for (case, logged, person, heard) in cases {
            let mut core = Core::new();
            if logged {
                core = core.with_history(
                    Arc::new(crate::history::MemoryLog::default()),
                    Default::default(),
                );
            }
            let (a, mut ra) = attach_as(&core, ("alice", person, person, None));
            drain(&mut ra);
            let say = || core.chat_public_guid(a, 0, ("hi".into(), 0, None), Some(a_guid()));
            let original = say().unwrap();
            core.clock().advance(GUID_WINDOW - Duration::from_secs(1));
            assert_eq!(say().unwrap(), original, "{case}: inside the window");
            core.clock().advance(Duration::from_secs(1));
            say().unwrap();
            assert_eq!(said_with_guid(drain(&mut ra)).len(), heard, "{case}");
        }
    }

    /// A log that finds no guid, so the lookup before staging always
    /// misses and only its conflict on append can tell a repeat.
    struct ForgetfulLog(crate::history::MemoryLog);

    impl crate::history::ChatLog for ForgetfulLog {
        fn lines(
            &self,
            channel: u32,
            ids: &[crate::history::LineId],
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.0.lines(channel, ids)
        }
        fn append_all(
            &self,
            lines: &[NewLine],
        ) -> Result<Vec<crate::history::Appended>, StoreError> {
            self.0.append_all(lines)
        }
        fn query(&self, q: &HistoryQuery) -> Result<HistoryPage, StoreError> {
            self.0.query(q)
        }
        fn line(
            &self,
            id: crate::history::LineId,
        ) -> Result<Option<crate::history::LogLine>, StoreError> {
            self.0.line(id)
        }
        fn lines_by(
            &self,
            channel: Option<u32>,
            who: &Mailbox,
            since: SystemTime,
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.0.lines_by(channel, who, since)
        }
        fn lines_by_ghost(
            &self,
            channel: Option<u32>,
            ghost: [u8; 16],
            since: SystemTime,
        ) -> Result<Vec<crate::history::LogLine>, StoreError> {
            self.0.lines_by_ghost(channel, ghost, since)
        }
        fn tombstone(
            &self,
            id: crate::history::LineId,
            by: &str,
            at: SystemTime,
        ) -> Result<bool, StoreError> {
            self.0.tombstone(id, by, at)
        }
        fn prune(
            &self,
            keep: &crate::history::Retention,
            now: SystemTime,
        ) -> Result<usize, StoreError> {
            self.0.prune(keep, now)
        }
        fn channels(&self) -> Result<Vec<(u32, crate::history::LineId)>, StoreError> {
            self.0.channels()
        }
        fn delete_channel(&self, channel: u32) -> Result<usize, StoreError> {
            self.0.delete_channel(channel)
        }
        fn attach_media(
            &self,
            id: crate::history::LineId,
            media: &crate::history::MediaMeta,
        ) -> Result<(), StoreError> {
            self.0.attach_media(id, media)
        }
        fn find_guid(
            &self,
            _: u32,
            _: &str,
            _: &MessageGuid,
        ) -> Result<Option<crate::history::LineId>, StoreError> {
            Ok(None)
        }
        fn find_signed(
            &self,
            _: &[u8; 32],
            _: &MessageGuid,
        ) -> Result<Option<crate::history::SignedAt>, StoreError> {
            Ok(None)
        }
        fn room_marks(&self) -> Result<HashMap<u32, bool>, StoreError> {
            self.0.room_marks()
        }
        fn set_room_mark(&self, room: u32, signed: bool) -> Result<(), StoreError> {
            self.0.set_room_mark(room, signed)
        }
        fn holds_unsigned(&self, channel: u32) -> Result<bool, StoreError> {
            self.0.holds_unsigned(channel)
        }
        fn restore_signed(
            &self,
            id: crate::history::LineId,
            form: &[u8],
        ) -> Result<(), StoreError> {
            self.0.restore_signed(id, form)
        }
        fn holds_home_key(&self, key: &[u8; 32]) -> Result<bool, StoreError> {
            self.0.holds_home_key(key)
        }
        fn react(
            &self,
            act: &crate::reaction::ReactAct,
        ) -> Result<crate::reaction::Reacted, StoreError> {
            self.0.react(act)
        }
        fn reactions(
            &self,
            ids: &[crate::history::LineId],
            reader: Option<&Mailbox>,
        ) -> Result<HashMap<crate::history::LineId, crate::reaction::Reactions>, StoreError>
        {
            self.0.reactions(ids, reader)
        }
        fn forget_reactions(
            &self,
            who: &Mailbox,
            since: SystemTime,
        ) -> Result<Vec<crate::history::LineId>, StoreError> {
            self.0.forget_reactions(who, since)
        }
        fn rekey_reactions(
            &self,
            from: &Mailbox,
            to: &Mailbox,
        ) -> Result<Vec<crate::history::LineId>, StoreError> {
            self.0.rekey_reactions(from, to)
        }
        fn reactors_on(
            &self,
            ids: &[crate::history::LineId],
        ) -> Result<Vec<(crate::history::LineId, String, crate::reaction::ReactionKey)>, StoreError>
        {
            self.0.reactors_on(ids)
        }
        fn clear_reactions(
            &self,
            channel: u32,
            line: crate::history::LineId,
        ) -> Result<Option<usize>, StoreError> {
            self.0.clear_reactions(channel, line)
        }
    }

    /// A line the log already holds under its guid, which nothing before
    /// the commit found, is a repeat by the log's own conflict: its
    /// sender is answered the line's id, and nobody hears anything.
    #[test]
    fn a_guid_only_the_logs_conflict_finds_is_one_line() {
        use crate::history::ChatLog;
        let log = Arc::new(ForgetfulLog(Default::default()));
        let id = log
            .append(&NewLine {
                home_key: None,
                home: None,
                re: None,
                channel: 0,
                ghost: None,
                from_nick: "alice".into(),
                from_login: Some("alice".into()),
                from_fingerprint: None,
                icon: 1,
                text: "hi".into(),
                flags: LineFlags::default(),
                at: SystemTime::now(),
                guid: Some(("login:alice".into(), a_guid())),
                signed: None,
            })
            .unwrap();
        let core = Core::new().with_history(log.clone(), Default::default());
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let (a, mut ra) = attach_as(&core, ("alice", true, true, None));
        drain(&mut rx);
        drain(&mut ra);
        let again = core.chat_public_guid(a, 0, ("hi".into(), 0, None), Some(a_guid()));
        assert_eq!(again, Ok(Some(id)));
        assert!(drain(&mut rx).is_empty(), "the room heard nothing");
        assert!(drain(&mut ra).is_empty(), "nor did its sender");
        let page = log
            .query(&HistoryQuery {
                channel: 0,
                before: None,
                after: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(page.lines.len(), 1, "and nothing was logged");
    }

    /// A room keeps so many guids and forgets the oldest first.
    #[test]
    fn a_rooms_guids_are_bounded_and_the_oldest_forgotten() {
        let mut recent = RecentGuids::default();
        let now = Instant::now();
        let sender = GuidSender::Session { uid: 1, serial: 1 };
        let guid = |n: usize| MessageGuid::parse(&format!("{n:032x}")).unwrap();
        for n in 0..=GUID_KEEP {
            recent.remember(
                now,
                (sender.clone(), guid(n)),
                (Some(n as u64), Said::Unsigned),
            );
        }
        assert_eq!(
            (recent.order.len(), recent.ids.len()),
            (GUID_KEEP, GUID_KEEP)
        );
        assert_eq!(recent.find(now, &(sender.clone(), guid(0))), None);
        assert_eq!(
            recent.find(now, &(sender, guid(1))),
            Some((Some(1), Said::Unsigned))
        );
    }

    /// A repeat that reaches the queue while its original is still
    /// waiting to be logged is that line too, once the commit comes.
    #[test]
    fn a_guid_sent_again_while_its_line_waits_in_the_queue_is_one_line() {
        let log = Arc::new(GatedLog {
            inner: Default::default(),
            gate: Mutex::new(false),
            opened: Condvar::new(),
        });
        let core = Arc::new(Core::new().with_history(log.clone(), Default::default()));
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let (first, _) = test_attach(&core, "first", chatter());
        let (sender, _) = test_attach(&core, "sender", chatter());
        drain(&mut rx);
        let send = |uid, guid: Option<MessageGuid>| {
            let core = core.clone();
            std::thread::spawn(move || core.chat_public_guid(uid, 0, ("hi".into(), 0, None), guid))
        };
        // A line leads a commit that waits at the gate; the original and
        // its repeat queue behind it.
        let lead = send(first, None);
        while {
            let st = core.chat_commit.state.lock().unwrap();
            !st.leading || !st.queue.is_empty()
        } {
            std::thread::yield_now();
        }
        let original = send(sender, Some(a_guid()));
        while core.chat_commit.state.lock().unwrap().queue.is_empty() {
            std::thread::yield_now();
        }
        let again = send(sender, Some(a_guid()));
        while core.chat_commit.state.lock().unwrap().queue.len() < 2 {
            std::thread::yield_now();
        }
        *log.gate.lock().unwrap() = true;
        log.opened.notify_all();

        assert!(lead.join().unwrap().is_ok());
        let original = original.join().unwrap().unwrap();
        assert!(original.is_some());
        assert_eq!(again.join().unwrap().unwrap(), original);
        assert_eq!(said_with_guid(drain(&mut rx)).len(), 2, "the lead and one");
    }

    /// A repeat that missed its original's answer on the way in, because
    /// that was still being logged, and reached a later commit, is
    /// answered there as that line was.
    #[test]
    fn a_guid_sent_again_in_a_later_commit_is_one_line() {
        let log = Arc::new(GatedLog {
            inner: Default::default(),
            gate: Mutex::new(false),
            opened: Condvar::new(),
        });
        let core = Arc::new(Core::new().with_history(log.clone(), Default::default()));
        let (_reader, mut rx) = test_attach(&core, "reader", chatter());
        let (sender, _) = test_attach(&core, "sender", chatter());
        drain(&mut rx);
        let send = || {
            let core = core.clone();
            std::thread::spawn(move || {
                core.chat_public_guid(sender, 0, ("hi".into(), 0, None), Some(a_guid()))
            })
        };
        // The original leads a commit held at the gate; the repeat, which
        // found nothing remembered, waits for the next.
        let original = send();
        while {
            let st = core.chat_commit.state.lock().unwrap();
            !st.leading || !st.queue.is_empty()
        } {
            std::thread::yield_now();
        }
        let again = send();
        while core.chat_commit.state.lock().unwrap().queue.is_empty() {
            std::thread::yield_now();
        }
        *log.gate.lock().unwrap() = true;
        log.opened.notify_all();

        let original = original.join().unwrap().unwrap();
        assert!(original.is_some());
        assert_eq!(again.join().unwrap().unwrap(), original);
        assert_eq!(said_with_guid(drain(&mut rx)).len(), 1);
    }

    fn flood_limits() -> crate::FloodLimits {
        crate::FloodLimits {
            chat_lines: 3,
            chat_per: Duration::from_secs(60),
            spam_points: 10,
            spam_per: Duration::from_secs(60),
            ban_for: Duration::from_secs(60),
        }
    }

    fn spam_notices(evs: &[Event]) -> Vec<(u32, Uid, String, bool)> {
        evs.iter()
            .filter_map(|e| match e {
                Event::Notice {
                    cid,
                    from,
                    text,
                    action,
                } if text.contains("spam") => Some((*cid, *from, text.clone(), *action)),
                _ => None,
            })
            .collect()
    }

    /// Past `chat_lines` a session is kicked and the room told, in mhxd's
    /// action form and from the spammer; every line of a multi-line send
    /// counts, and a send that crosses the limit is refused whole, as
    /// mhxd drops the lines it had formatted. Everything it had in flight
    /// after that is refused too, without a second kick or notice.
    #[test]
    fn a_session_past_its_chat_lines_is_kicked_once_and_the_room_told() {
        let core = Core::new().with_flood_limits(flood_limits());
        let (spammer, mut rx_s) = test_attach(&core, "spammer", chatter());
        let (admin, _rx_a) = test_attach(&core, "admin", chatter());
        let (_reader, mut rx_r) = test_attach(&core, "reader", chatter());
        core.roster
            .lock()
            .unwrap()
            .users
            .get_mut(&admin)
            .unwrap()
            .can_spam = true;
        drain(&mut rx_s);
        drain(&mut rx_r);
        core.chat_public(spammer, "one\rtwo".into(), 0, None)
            .unwrap();
        assert_eq!(
            core.chat_public(spammer, "three\rfour".into(), 0, None),
            Err(ChatError::Flooding),
            "two more lines are one too many"
        );
        for i in 0..50 {
            assert_eq!(
                core.chat_public(spammer, format!("{i}"), 0, None),
                Err(ChatError::Flooding)
            );
        }
        let mine = drain(&mut rx_s);
        assert_eq!(mine.iter().filter(|e| **e == Event::Kicked).count(), 1);
        let heard = drain(&mut rx_r);
        assert_eq!(
            spam_notices(&heard),
            [(
                0,
                spammer,
                "spammer was kicked for chat spamming".to_string(),
                true
            )],
            "one notice, in the action form, from the spammer"
        );
        let lines: Vec<_> = heard
            .iter()
            .filter_map(|e| match e {
                Event::Chat { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(lines, ["one\rtwo"], "nothing of the send that crossed it");

        for i in 0..10 {
            core.chat_public(admin, format!("{i}"), 0, None).unwrap();
        }
    }

    /// A flood in a private chat is announced to that chat, as mhxd's
    /// `snd_chat(chat, …)` sends it, and not to public chat.
    #[test]
    fn a_private_chat_flood_is_announced_in_that_chat() {
        let core = Core::new().with_flood_limits(flood_limits());
        let (spammer, mut rx_s) = test_attach(&core, "spammer", chatter());
        let (member, mut rx_m) = test_attach(&core, "member", chatter());
        let (_outsider, mut rx_o) = test_attach(&core, "outsider", chatter());
        let (cid, _) = core.chat_create(spammer, member).unwrap();
        core.chat_join(cid, member, "").unwrap();
        drain(&mut rx_s);
        drain(&mut rx_m);
        drain(&mut rx_o);
        assert_eq!(
            core.chat_private(cid, spammer, "a\rb\rc\rd".into(), 0, None),
            Err(ChatError::Flooding)
        );
        assert_eq!(
            spam_notices(&drain(&mut rx_m)),
            [(
                cid,
                spammer,
                "spammer was kicked for chat spamming".to_string(),
                true
            )]
        );
        assert!(spam_notices(&drain(&mut rx_o)).is_empty());
    }

    /// mhxd's spam points: a transaction that brings the window to the
    /// budget kicks and bans its sender, and public chat hears mhxd's
    /// announcement; nothing after it spends, kicks or announces again.
    #[test]
    fn a_session_that_spends_its_spam_points_is_banned_once() {
        let core = Core::new().with_flood_limits(flood_limits());
        let (talker, mut rx_t) = core
            .attach(crate::AttachInfo {
                account: None,
                nick: "talker".into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: "talker".into(),
                addr: Some("192.0.2.7".parse().unwrap()),
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                set_avatar: false,
                is_person: false,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(talker);
        let (_reader, mut rx_r) = test_attach(&core, "reader", chatter());
        drain(&mut rx_t);
        drain(&mut rx_r);
        for _ in 0..4 {
            core.spend_spam(talker, 2, 0x6c).unwrap();
        }
        let ban = core.spend_spam(talker, 2, 0x6c).unwrap_err().ban;
        assert!(
            !core.is_banned("192.0.2.7".parse().unwrap()),
            "the kick is at once, its ban the caller's to place"
        );
        core.place_spam_ban(ban.expect("a ban to place"));
        for _ in 0..20 {
            assert_eq!(core.spend_spam(talker, 2, 0x6c), Err(Flooded { ban: None }));
        }
        assert_eq!(
            drain(&mut rx_t)
                .iter()
                .filter(|e| **e == Event::Kicked)
                .count(),
            1
        );
        assert_eq!(
            spam_notices(&drain(&mut rx_r)),
            [(
                0,
                talker,
                "talker has been banned by talker: spam_max exceeded: 10 >= 10, \
                 last transaction: 0x6c"
                    .to_string(),
                false
            )]
        );
        assert!(core.is_banned("192.0.2.7".parse().unwrap()), "its address");
    }

    /// The ng request limit is a session's, kept across a detach and
    /// resume and filled again only by a fresh login, and a `can_spam`
    /// account is held to none, as it is held to no flood budget; the
    /// news-post limit is an account's, across its sessions, and a
    /// guest's is its session's.
    #[test]
    fn request_and_post_limits_are_held_by_whom_they_say() {
        let core = Core::new().with_request_limits(crate::RequestLimits {
            requests: 4,
            requests_per: Duration::from_secs(60),
            news_posts: 1,
            news_posts_per: Duration::from_secs(60),
            folders: 2,
            folders_per: Duration::from_secs(60),
        });
        let who = |login: &str, can_spam: bool, is_person: bool| crate::AttachInfo {
            account: None,
            nick: login.into(),
            icon: 1,
            admin: false,
            access: chatter(),
            login: login.into(),
            addr: None,
            can_detach: is_person,
            transport: Default::default(),
            has_inbox: false,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam,
            manage_rooms: false,
            set_subject: false,
            is_person,
            reads_on_delivery: false,
            identity: None,
            system: false,
        };
        let (alice, _rx1) = core.attach(who("alice", false, true)).unwrap();
        let (alice_again, _rx2) = core.attach(who("alice", false, true)).unwrap();
        let (admin, _rx3) = core.attach(who("admin", true, true)).unwrap();
        let (guest, _rx4) = core.attach(who("guest", false, false)).unwrap();
        let (guest_too, _rx5) = core.attach(who("guest", false, false)).unwrap();

        for _ in 0..2 {
            core.spend_request(alice, 2).unwrap();
        }
        assert!(core.spend_request(alice, 1).is_err(), "spent");
        assert!(core.connection_lost(alice, 8), "detached");
        assert!(!matches!(core.resume(alice, 0), crate::Resume::Gone));
        assert!(
            core.spend_request(alice, 1).is_err(),
            "a resume is no fresh bucket"
        );
        core.spend_request(alice_again, 4)
            .expect("another login's is its own");
        for _ in 0..10 {
            core.spend_request(admin, 4).expect("can_spam");
        }
        let unlimited = Core::new();
        let (bob, _rx6) = unlimited.attach(who("bob", false, true)).unwrap();
        for _ in 0..10 {
            unlimited.spend_request(bob, 4).expect("no limit set");
        }

        core.news_post_reserve(alice).unwrap();
        assert!(
            core.news_post_reserve(alice_again).is_err(),
            "one account, two sessions"
        );
        core.news_post_refund(alice);
        core.news_post_reserve(alice_again)
            .expect("a post that did not land is given back");
        for _ in 0..3 {
            core.news_post_counted(admin);
        }
        assert_eq!(core.news_post_reserve(admin), Ok(()), "can_spam");
        core.news_post_counted(guest);
        assert_eq!(core.news_post_reserve(guest_too), Ok(()), "another guest");
        assert!(core.news_post_reserve(guest).is_err());

        // Folders are an account's like its posts, in a budget of their own.
        core.folder_reserve(alice).unwrap();
        core.folder_reserve(alice_again).unwrap();
        assert!(core.folder_reserve(alice).is_err(), "one account");
        core.folder_refund(alice);
        core.folder_reserve(alice_again)
            .expect("a folder that was not made is given back");
        for _ in 0..3 {
            core.folder_reserve(admin).expect("can_spam");
        }
    }

    /// Behind an address `[limits] exempt` — loopback here, a shared
    /// proxy in production — a spam kick bans the person, never the
    /// address everyone behind it shares, and a guest with nothing of
    /// its own to ban is only kicked.
    #[test]
    fn a_spam_kick_on_an_exempt_address_bans_the_person_not_the_address() {
        let core = Core::new()
            .with_flood_limits(flood_limits())
            .with_moderation(
                Arc::new(crate::moderation::MemoryModeration::default()),
                crate::moderation::ModerationPolicy::default(),
            );
        let shared: IpAddr = "127.0.0.1".parse().unwrap();
        let attach = |login: &str, is_person: bool| {
            core.attach(crate::AttachInfo {
                account: None,
                nick: login.into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: login.into(),
                addr: Some(shared),
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap()
        };
        let flood = |uid| {
            for _ in 0..4 {
                core.spend_spam(uid, 2, 0x6c).unwrap();
            }
            core.spend_spam(uid, 2, 0x6c).unwrap_err().ban
        };
        let (_reader, mut rx_r) = test_attach(&core, "reader", chatter());

        let (alice, _rx_a) = attach("alice", true);
        core.announce(alice);
        drain(&mut rx_r);
        core.place_spam_ban(flood(alice).expect("alice's login is hers to lose"));
        assert!(!core.is_banned(shared), "not the address everyone shares");
        assert!(core.person_banned(Some("alice"), None, None).is_some());
        assert!(spam_notices(&drain(&mut rx_r))[0]
            .2
            .starts_with("alice has been banned by alice"));

        let (guest, _rx_g) = attach("guest", false);
        core.announce(guest);
        drain(&mut rx_r);
        assert_eq!(flood(guest), None, "a guest here has nothing to ban");
        assert!(!core.is_banned(shared));
        assert!(spam_notices(&drain(&mut rx_r))[0]
            .2
            .starts_with("guest has been kicked by guest"));
    }

    /// The operator acts under a name no reserved login is, and is
    /// nobody's session: an account that shares the name is banned like
    /// any other, by the operator's kick and by the spam kick, which
    /// acts as the operator, and what is announced is what was placed.
    /// Only a session is left out of its own ban.
    #[test]
    fn only_a_session_is_left_out_of_its_own_kick_ban() {
        let core = Core::new()
            .with_flood_limits(flood_limits())
            .with_moderation(
                Arc::new(crate::moderation::MemoryModeration::default()),
                crate::moderation::ModerationPolicy::default(),
            );
        let shared: IpAddr = "127.0.0.1".parse().unwrap();
        let attach = |login: &str, moderate: bool| {
            core.attach(crate::AttachInfo {
                account: None,
                nick: login.into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: login.into(),
                addr: Some(shared),
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap()
        };
        let kick_ban = |uid, by| {
            // A kick names a session on the roster, as only a shown one is.
            core.announce(uid);
            core.kick_by(
                uid,
                Some(KickBan {
                    by,
                    for_: Duration::from_secs(60),
                    reason: "spam".into(),
                }),
            )
            .unwrap()
        };
        let operator = crate::moderation::OPERATOR;

        let (named, _rx) = attach(operator, false);
        assert!(
            kick_ban(named, crate::moderation::Actor::Operator).banned,
            "an account named {operator} is not the operator"
        );
        assert!(core.person_banned(Some(operator), None, None).is_some());
        for ban in core.list_bans(true, None, 10).unwrap() {
            core.lift_ban(crate::moderation::Actor::Operator, ban.id)
                .unwrap();
        }

        // The spam kick bans as the operator: announced as a ban, and one.
        let (named, _rx) = attach(operator, false);
        for _ in 0..4 {
            core.spend_spam(named, 2, 0x6c).unwrap();
        }
        let ban = core.spend_spam(named, 2, 0x6c).unwrap_err().ban;
        core.place_spam_ban(ban.expect("announced as banned"));
        assert!(core.person_banned(Some(operator), None, None).is_some());
        for ban in core.list_bans(true, None, 10).unwrap() {
            core.lift_ban(crate::moderation::Actor::Operator, ban.id)
                .unwrap();
        }

        // A moderator kicking another session of their own, on an address
        // nobody may ban, has nothing to place, and says so.
        let (mod_a, _rx_a) = attach("carol", true);
        let (mod_b, _rx_b) = attach("carol", true);
        let kicked = kick_ban(mod_b, crate::moderation::Actor::Session(mod_a));
        assert!(!kicked.banned, "not banned: nothing but herself to ban");
        assert!(core.person_banned(Some("carol"), None, None).is_none());
        assert!(core.list_bans(true, None, 10).unwrap().is_empty());
    }

    /// A store that fails partway through a kick's ban leaves what it
    /// wrote standing, and the kick says it banned: the person is
    /// refused, so the announcement is true of them. One that writes
    /// nothing says it only kicked.
    #[test]
    fn a_kick_ban_the_store_half_wrote_is_reported_as_what_stands() {
        let store = Arc::new(crate::moderation::MemoryModeration::default());
        let core = Core::new().with_moderation(
            store.clone(),
            crate::moderation::ModerationPolicy::default(),
        );
        let attach = |login: &str, addr: &str| {
            core.attach(crate::AttachInfo {
                account: None,
                nick: login.into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: login.into(),
                addr: Some(addr.parse().unwrap()),
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: true,
                reads_on_delivery: false,
                identity: None,
                system: false,
            })
            .unwrap()
        };
        let kick_ban = |uid| {
            // A kick names a session on the roster, as only a shown one is.
            core.announce(uid);
            core.kick_by(
                uid,
                Some(KickBan {
                    by: crate::moderation::Actor::Operator,
                    for_: Duration::from_secs(60),
                    reason: "spam".into(),
                }),
            )
            .unwrap()
        };
        let (alice, _rx_a) = attach("alice", "192.0.2.7");
        store.fail_bans_after(1);
        assert!(kick_ban(alice).banned, "the person's row was written");
        assert!(core.person_banned(Some("alice"), None, None).is_some());
        assert!(
            !core.is_banned("192.0.2.7".parse().unwrap()),
            "the address's was not"
        );
        let (bob, _rx_b) = attach("bob", "192.0.2.8");
        store.fail_bans_after(0);
        assert!(!kick_ban(bob).banned, "nothing was written");
        assert!(core.person_banned(Some("bob"), None, None).is_none());
    }

    /// A kick-with-ban bans the person, and the address too unless
    /// `[limits] exempt` holds it (loopback, by default): an account's
    /// login when it is a person's, else the identity the session
    /// proved. A plain guest on an exempt address has nothing of its own
    /// to ban.
    #[test]
    fn a_kick_ban_takes_the_person_and_an_address_that_is_not_exempt() {
        use crate::ban::BanTarget;
        let core = Core::new().with_moderation(
            Arc::new(crate::moderation::MemoryModeration::default()),
            crate::moderation::ModerationPolicy::default(),
        );
        let attach = |login: &str, is_person: bool, identity, addr: &str| {
            core.attach(crate::AttachInfo {
                account: None,
                nick: login.into(),
                icon: 1,
                admin: false,
                access: chatter(),
                login: login.into(),
                addr: Some(addr.parse().unwrap()),
                can_detach: false,
                transport: Default::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person,
                reads_on_delivery: false,
                identity,
                system: false,
            })
            .unwrap()
            .0
        };
        let targets = |uid| {
            let r = core.roster.lock().unwrap();
            core.kick_ban_targets(&r.users[&uid])
        };
        let login = |l: &str| BanTarget::login(l).unwrap();
        let addr = |a: &str| BanTarget::parse(a, |_| None).unwrap();

        let alice = attach("alice", true, None, "192.0.2.7");
        assert_eq!(
            targets(alice),
            [login("alice"), addr("192.0.2.7")],
            "the person, and an address nobody exempted"
        );
        let alice_here = attach("alice", true, None, "127.0.0.1");
        assert_eq!(targets(alice_here), [login("alice")], "not loopback");
        let guest = attach("guest", false, None, "127.0.0.1");
        assert_eq!(targets(guest), [], "nothing of a plain guest's alone");
        let far_guest = attach("guest", false, None, "192.0.2.9");
        assert_eq!(targets(far_guest), [addr("192.0.2.9")], "mhxd's ban");
        let keyed = attach("guest", false, Some([7; 32]), "127.0.0.1");
        assert_eq!(targets(keyed), [BanTarget::Identity([7; 32])]);
        let keyed_far = attach("guest", false, Some([8; 32]), "192.0.2.10");
        assert_eq!(
            targets(keyed_far),
            [BanTarget::Identity([8; 32]), addr("192.0.2.10")]
        );
        // A person's `guest` login is everyone's: its identity instead.
        let odd = attach("guest", true, Some([9; 32]), "127.0.0.1");
        assert_eq!(targets(odd), [BanTarget::Identity([9; 32])]);

        // Placed, the person and the address are one act, which one lift
        // undoes whole.
        let ban = |uid| {
            // A kick names a session on the roster, as only a shown one is.
            core.announce(uid);
            core.kick_by(
                uid,
                Some(KickBan {
                    by: crate::moderation::Actor::Operator,
                    for_: Duration::from_secs(60),
                    reason: "spam".into(),
                }),
            )
            .unwrap()
        };
        assert_eq!(
            ban(guest),
            Kicked {
                nick: "guest".into(),
                banned: false
            },
            "only kicked"
        );
        assert!(!core.is_banned("127.0.0.1".parse().unwrap()));
        assert!(ban(alice).banned);
        assert!(core.is_banned("192.0.2.7".parse().unwrap()));
        assert!(core.person_banned(Some("alice"), None, None).is_some());
        assert!(
            !core.is_banned("127.0.0.1".parse().unwrap()),
            "alice's other session's address is none of this ban's"
        );
        let bans = core.list_bans(true, None, 10).unwrap();
        assert_eq!(bans.len(), 2);
        assert_eq!(bans[0].act, bans[1].act);
        let lifted = core
            .lift_ban(crate::moderation::Actor::Operator, bans[1].id)
            .unwrap();
        assert_eq!(lifted.len(), 2, "lifting one row lifts the act");
        assert!(!core.is_banned("192.0.2.7".parse().unwrap()));
        assert!(core.person_banned(Some("alice"), None, None).is_none());
    }

    /// A kick-with-ban of an IPv6 loopback peer bans `::1` alone: its
    /// /64 would be `::/64`, no subscriber's block. So does one of an
    /// address standing for an IPv4 host, whose /64 is every IPv4
    /// client behind the translator.
    #[test]
    fn a_kick_ban_of_ipv6_loopback_bans_it_alone() {
        let core = Core::new().with_moderation(
            Arc::new(crate::moderation::MemoryModeration::default()),
            crate::moderation::ModerationPolicy::default(),
        );
        let target = |ip: &str| core.address_ban_target(ip.parse().unwrap()).unwrap();
        assert_eq!(
            target("::1"),
            crate::ban::BanTarget::parse("::1/128", |_| None).unwrap()
        );
        assert_eq!(
            target("2001:db8::7"),
            crate::ban::BanTarget::parse("2001:db8::/64", |_| None).unwrap()
        );
        assert_eq!(
            target("::ffff:192.0.2.7"),
            crate::ban::BanTarget::parse("192.0.2.7", |_| None).unwrap()
        );
        for alone in [
            "::",
            "64:ff9b::c000:207",
            "64:ff9b:1::c000:207",
            "64:ff9b:1:ffff::c000:207",
            "::c000:207",
        ] {
            assert_eq!(
                target(alone),
                crate::ban::BanTarget::parse(&format!("{alone}/128"), |_| None).unwrap(),
                "{alone} alone"
            );
        }
        // Just outside the NAT64 prefixes: a subscriber's /64 as usual.
        for (ip, block) in [
            ("64:ff9b:0:1::7", "64:ff9b:0:1::/64"),
            ("64:ff9b:2::7", "64:ff9b:2::/64"),
        ] {
            assert_eq!(
                target(ip),
                crate::ban::BanTarget::parse(block, |_| None).unwrap(),
                "{ip}"
            );
        }
    }

    #[test]
    fn public_chat_reaches_readers_only_including_sender() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (_b, mut rx_b) = test_attach(&core, "bob", chatter());
        let (_m, mut rx_m) = test_attach(&core, "mute", AccessBits::empty());
        drain(&mut rx_a);
        drain(&mut rx_b);

        core.chat_public(a, "hi".into(), 0, None).unwrap();
        assert!(
            matches!(&drain(&mut rx_a)[..], [Event::Chat { cid: 0, text, .. }] if text == "hi")
        );
        assert_eq!(drain(&mut rx_b).len(), 1);
        assert!(drain(&mut rx_m).is_empty());
    }

    #[test]
    fn a_reply_names_a_line_of_its_own_room_and_is_never_refused_as_dangling() {
        use crate::reply::Reply;
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (_b, mut rx_b) = test_attach(&core, "bob", chatter());
        let say = |re| core.chat_public_signed(a, 0, ("yes".into(), 0, None), None, None, Some(re));
        for re in [Reply::Line { room: 7, id: 1 }, Reply::Pm([1; 16])] {
            assert_eq!(say(re.clone()), Err(ChatError::ReplyScope), "{re:?}");
        }
        drain(&mut rx_a);
        drain(&mut rx_b);
        let never_said = Reply::Line { room: 0, id: 4242 };
        say(never_said.clone()).unwrap();
        for rx in [&mut rx_a, &mut rx_b] {
            assert!(
                matches!(&drain(rx)[..], [Event::Chat { re: Some(re), .. }] if **re == never_said)
            );
        }
    }

    #[test]
    fn private_chat_lifecycle_create_invite_join_part() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, mut rx_b) = test_attach(&core, "bob", chatter());
        drain(&mut rx_a);

        let (cid, me) = core.chat_create(a, b).unwrap();
        assert_eq!(me.uid, a);
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::ChatInvite { cid: c, from, .. }] if *c == cid && *from == a)
        );

        // Chatting before joining is refused; joining via invite skips the
        // password.
        assert_eq!(
            core.chat_private(cid, b, "early".into(), 0, None),
            Err(ChatError::NotAMember)
        );
        let (rows, _subject) = core.chat_join(cid, b, "").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            matches!(&drain(&mut rx_a)[..], [Event::ChatUserJoined { user, .. }] if user.uid == b)
        );

        core.chat_private(cid, b, "hello".into(), 0, None).unwrap();
        assert_eq!(drain(&mut rx_a).len(), 1);
        assert_eq!(drain(&mut rx_b).len(), 1);

        // Parting announces to the survivor; last one out deletes the chat.
        core.chat_part(cid, b);
        assert!(matches!(&drain(&mut rx_a)[..], [Event::ChatUserParted { uid, .. }] if *uid == b));
        core.chat_part(cid, a);
        assert_eq!(core.chat_join(cid, a, ""), Err(ChatError::NoSuchChat));
    }

    #[test]
    fn chat_ids_are_unguessable_and_never_zero() {
        let core = Core::new();
        let (a, _rx_a) = test_attach(&core, "alice", chatter());
        let cids: Vec<u32> = (0..16).map(|_| core.chat_create(a, a).unwrap().0).collect();

        assert!(cids.iter().all(|c| *c != 0), "0 is the public chat");
        let unique: std::collections::HashSet<_> = cids.iter().collect();
        assert_eq!(unique.len(), cids.len(), "ids collide");
        // The property that matters: knowing one id tells you nothing
        // about the next. A counter would fail this on every pair.
        assert!(
            cids.windows(2).all(|w| w[1] != w[0].wrapping_add(1)),
            "ids look sequential: {cids:?}"
        );
        // And they're spread across the space rather than clustered
        // low. With sixteen draws a false failure is one run in 65536;
        // the two checks above carry the claim, so this one only has to
        // be cheap and honest about what it's asserting.
        let high = cids.iter().filter(|c| **c > u32::MAX / 2).count();
        assert!(high > 0 && high < cids.len(), "not spread: {cids:?}");
    }

    #[test]
    fn passworded_chat_gates_uninvited_joiners() {
        let core = Core::new();
        let (a, _rx_a) = test_attach(&core, "alice", chatter());
        let (b, _rx_b) = test_attach(&core, "bob", chatter());
        let (cid, _) = core.chat_create(a, a).unwrap();
        core.chat_password(cid, a, "sesame".into()).unwrap();

        assert_eq!(
            core.chat_join(cid, b, "wrong"),
            Err(ChatError::WrongPassword)
        );
        assert!(core.chat_join(cid, b, "sesame").is_ok());
    }

    #[test]
    fn detach_parts_every_chat() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, _rx_b) = test_attach(&core, "bob", chatter());
        let (cid, _) = core.chat_create(b, a).unwrap();
        core.chat_join(cid, a, "").unwrap();
        drain(&mut rx_a);

        core.end_session(b);
        let evs = drain(&mut rx_a);
        assert!(evs.contains(&Event::ChatUserParted { cid, uid: b }));
        assert!(evs.contains(&Event::Parted(b)));
        // Alice is now alone in the chat; it survives until she leaves.
        assert_eq!(core.chats_of(a), vec![cid]);
    }

    #[test]
    fn subjects_public_and_private() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, mut rx_b) = test_attach(&core, "bob", AccessBits::empty());
        drain(&mut rx_a);

        core.chat_subject(0, a, "welcome!".into()).unwrap();
        // Public subject reaches everyone, even non-chat-readers.
        assert_eq!(drain(&mut rx_b).len(), 1);
        assert_eq!(core.public_subject(), "welcome!");

        let (cid, _) = core.chat_create(a, a).unwrap();
        assert_eq!(
            core.chat_subject(cid, b, "x".into()),
            Err(ChatError::NotAMember)
        );
        core.chat_subject(cid, a, "private".into()).unwrap();
        let (_rows, subject) = {
            core.chat_invite(cid, a, b).unwrap();
            core.chat_join(cid, b, "").unwrap()
        };
        assert_eq!(subject, "private");
    }

    #[test]
    fn msg_broadcast_notice_and_kick_ban() {
        let core = Core::new();
        let (a, mut rx_a) = test_attach(&core, "alice", chatter());
        let (b, mut rx_b) = test_attach(&core, "bob", chatter());
        drain(&mut rx_a);

        core.msg(a, b, "psst".into(), None, None).unwrap();
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::Msg { from, text, .. }] if *from == a && text == "psst")
        );
        assert_eq!(
            core.msg(a, 999, "x".into(), None, None),
            Err(ChatError::NoSuchUser)
        );

        core.broadcast(a, "attention".into()).unwrap();
        assert_eq!(drain(&mut rx_a).len(), 1);
        assert_eq!(drain(&mut rx_b).len(), 1);

        core.chat_notice(0, a, "bob has been warned".into());
        assert!(
            matches!(&drain(&mut rx_b)[..], [Event::Notice { cid: 0, text, .. }] if text == "bob has been warned")
        );

        let nick = core.kick(b, Some(Duration::from_secs(60))).unwrap();
        assert_eq!(nick, "bob");
        assert!(drain(&mut rx_b).contains(&Event::Kicked));
        // No address on test sessions, so nothing bannable by IP — but the
        // expiry path shouldn't panic.
        assert!(!core.is_banned("127.0.0.1".parse().unwrap()));
    }
}

#[cfg(test)]
mod inbox_tests {
    //! The private-message inbox, at the domain level: which messages get
    //! stored, who gets them and when, and what a queued one looks like
    //! when it finally arrives. See docs/private-messages.md §5.

    use std::sync::{Arc, Mutex, Weak};

    use crate::Events;

    use super::*;
    use crate::access::bit;
    use crate::inbox::MemoryStore;
    use crate::roster::{drain, AttachInfo, InboxPolicy};
    use crate::{AccessBits, AccountDirectory, Resume};

    /// The accounts that exist and take mail, and the identity each is
    /// linked to. Anything else is the one `None` that covers both "no
    /// such account" and "takes no mail".
    struct Directory(Vec<Mailbox>);

    impl Directory {
        fn of(logins: &[&str]) -> Directory {
            Directory(logins.iter().map(|l| Mailbox::login(*l)).collect())
        }
    }

    impl AccountDirectory for Directory {
        fn inbox_account(&self, login: &str) -> Option<Mailbox> {
            let l = login.to_ascii_lowercase();
            self.0.iter().find(|m| m.login == l).cloned()
        }

        fn mailbox_access(&self, who: &Mailbox) -> Option<AccessBits> {
            self.0
                .iter()
                .any(|m| who.matches(&m.login, m.fingerprint.as_ref()))
                .then(AccessBits::empty)
        }
    }

    /// A core with an inbox, and optionally somewhere to send
    /// notifications. Shared with `super::notify_tests`.
    pub(super) fn server_arc(
        policy: InboxPolicy,
        logins: &[&str],
        gateway: Option<Arc<dyn crate::NotificationGateway>>,
    ) -> (Arc<Core>, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let dir = Arc::new(Directory::of(logins));
        let mut core = Core::new().with_inbox(store.clone(), dir, policy);
        if let Some(gw) = gateway {
            core = core.with_notifications(gw);
        }
        (Arc::new(core), store)
    }

    fn server_with(policy: InboxPolicy, logins: &[&str]) -> (Arc<Core>, Arc<MemoryStore>) {
        server_arc(policy, logins, None)
    }

    fn server(logins: &[&str]) -> (Arc<Core>, Arc<MemoryStore>) {
        server_with(InboxPolicy::default(), logins)
    }

    /// Attach a session whose account is linked to an identity.
    pub(super) fn attach_identified(
        core: &Core,
        login: &str,
        fingerprint: [u8; 32],
    ) -> (Uid, Events) {
        let (uid, rx) = core
            .attach(AttachInfo {
                account: None,
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_MSGS),
                login: login.to_string(),
                addr: Some("10.0.0.1".parse().unwrap()),
                can_detach: true,
                transport: crate::Transport::default(),
                has_inbox: true,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: true,
                reads_on_delivery: false,
                identity: Some(fingerprint),
                system: false,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    pub(super) fn attach(core: &Core, login: &str, has_inbox: bool) -> (Uid, Events) {
        attach_wire(core, login, has_inbox, false)
    }

    /// [`attach`], on the classic wire when `classic`.
    fn attach_wire(core: &Core, login: &str, has_inbox: bool, classic: bool) -> (Uid, Events) {
        let (uid, rx) = core
            .attach(AttachInfo {
                account: None,
                nick: login.to_string(),
                icon: 1,
                admin: false,
                access: AccessBits::empty()
                    .with(bit::READ_CHAT)
                    .with(bit::SEND_MSGS),
                login: login.to_string(),
                addr: Some("10.0.0.1".parse().unwrap()),
                can_detach: true,
                transport: crate::Transport::default(),
                has_inbox,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: has_inbox,
                reads_on_delivery: classic,
                identity: None,
                system: false,
            })
            .unwrap();
        core.announce(uid);
        (uid, rx)
    }

    /// A distinguishable identity fingerprint.
    fn fp(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn msgs(evs: Vec<Event>) -> Vec<Event> {
        evs.into_iter()
            .filter(|e| matches!(e, Event::Msg { .. }))
            .collect()
    }

    #[test]
    fn a_reply_is_kept_and_held_to_what_it_names() {
        let (core, store) = server(&["alice", "dave", "carol"]);
        let (a, mut ra) = attach(&core, "alice", true);
        let (d, _rd) = attach(&core, "dave", true);
        let (c, _rc) = attach(&core, "carol", true);
        let Ok(MsgOutcome::Delivered(Some(asked))) = core.msg(a, d, "lunch?".into(), None, None)
        else {
            panic!("stored and delivered");
        };
        let guid = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
        let send = |from, to, re: Reply| {
            core.msg_signed(from, to, "yes".into(), None, None, None, Some(re))
        };
        let carols = Reply::im("carol".into(), guid.clone()).unwrap();
        for (case, re) in [
            ("an im of a third party's", carols),
            ("a public line", Reply::Line { room: 0, id: 1 }),
        ] {
            assert_eq!(send(d, a, re), Err(ChatError::ReplyScope), "{case}");
        }
        // Whatever the store holds: refusing another pair's reference
        // would tell the sender whether that message still exists.
        assert!(send(c, d, Reply::Pm(asked)).is_ok());
        core.inbox_block(c, "dave", true).unwrap();
        assert_eq!(
            send(d, c, Reply::Line { room: 0, id: 1 }),
            Err(ChatError::Blocked),
            "a blocked sender hears the block"
        );
        drain(&mut ra);
        for re in [
            Reply::Pm(asked),
            Reply::Pm([0xee; 16]),
            Reply::im("alice".into(), guid).unwrap(),
        ] {
            assert!(send(d, a, re.clone()).is_ok(), "{re:?}");
            assert!(
                matches!(&msgs(drain(&mut ra))[..], [Event::Msg { re: Some(got), .. }] if **got == re),
                "{re:?} reaches its reader as sent"
            );
            let kept = store.list(&Mailbox::login("alice"), None, 1).unwrap();
            assert_eq!(
                kept[0].re.as_ref(),
                Some(&re),
                "and is kept with the message"
            );
        }
    }

    #[test]
    fn a_message_to_someone_present_is_stored_and_handed_over_at_once() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        let MsgOutcome::Delivered(Some(sent)) = core.msg(a, m, "hi".into(), None, None).unwrap()
        else {
            panic!("a recipient who is there gets it now, and it is stored");
        };
        match &msgs(drain(&mut rm))[..] {
            [Event::Msg {
                from,
                from_login,
                text,
                cursor,
                reference,
                queued,
                ..
            }] => {
                assert_eq!(*from, a);
                assert_eq!(from_login.as_deref(), Some("alice"));
                assert_eq!(text, "hi");
                assert!(cursor.is_some(), "stored, so it has a cursor to mark read");
                assert_eq!(*reference, Some(sent), "and the name its sender holds");
                assert!(!queued, "it did not wait for anything");
            }
            other => panic!("expected one message, got {other:?}"),
        }
        // Persisted anyway: the durable copy is what a dropped socket or a
        // second device asks for later.
        let stored = store.all();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].delivered_at.is_some(), "and marked delivered");
        assert!(stored[0].read_at.is_none(), "delivered is not read");
    }

    #[test]
    fn a_detached_session_gets_no_outbox_copy_and_finds_it_on_resume() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        let last_seq = std::iter::from_fn(|| rm.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(core.connection_lost(m, 8));

        assert!(matches!(
            core.msg(a, m, "you there?".into(), None, None).unwrap(),
            MsgOutcome::Queued(_)
        ));
        assert_eq!(store.all().len(), 1);
        assert!(
            store.all()[0].delivered_at.is_none(),
            "a detached session is not a live connection"
        );

        let Resume::Replayed(mut rm2, replay) = core.resume(m, last_seq) else {
            panic!("resume should replay");
        };
        assert!(
            !replay
                .iter()
                .any(|se| matches!(se.event, Event::Msg { .. })),
            "the outbox must not carry a second copy — one message, one place"
        );

        assert_eq!(core.flush_inbox(m), 1);
        match &msgs(drain(&mut rm2))[..] {
            [Event::Msg { text, queued, .. }] => {
                assert_eq!(text, "you there?");
                assert!(queued, "this one waited");
            }
            other => panic!("expected the queued message, got {other:?}"),
        }
    }

    #[test]
    fn a_message_outlives_the_session_it_was_addressed_to() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);
        // The grace window lapses and the session is gone entirely.
        core.end_session(m);
        assert!(core.user(m).is_none());

        assert!(matches!(
            core.msg_login(a, "dave", "call me".into(), None, None)
                .unwrap(),
            MsgOutcome::Queued(_)
        ));

        // A fresh session, a different uid, the same account.
        let (m2, mut rm2) = attach(&core, "dave", true);
        assert_ne!(m2, m);
        assert_eq!(core.flush_inbox(m2), 1);
        assert!(matches!(
            &msgs(drain(&mut rm2))[..],
            [Event::Msg { text, queued: true, .. }] if text == "call me"
        ));
        // And only once.
        assert_eq!(core.flush_inbox(m2), 0);
    }

    #[test]
    fn a_recipient_without_an_inbox_is_live_only() {
        let (core, store) = server(&["alice"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (g, mut rg) = attach(&core, "guest", false);
        drain(&mut rg);

        assert!(matches!(
            core.msg(a, g, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered(_)
        ));
        assert!(
            matches!(
                &msgs(drain(&mut rg))[..],
                [Event::Msg {
                    cursor: None,
                    reference: None,
                    ..
                }]
            ),
            "nothing stored means no handle to mark read"
        );
        assert!(store.all().is_empty());
    }

    #[test]
    fn a_guest_may_reach_a_session_and_may_not_fill_a_mailbox() {
        // §9's "anyone with an account can put mail in anyone's mailbox"
        // does not cover a guest, which has no account. A guest cannot be
        // blocked — `guest` is a login several people share, so there is
        // nothing durable to hold a block against — so a guest that could
        // queue mail could fill any mailbox on the server to its cap and
        // stay unstoppable. Every other sender is then refused
        // `mailbox_full` until the owner clears it by hand.
        let (core, store) = server(&["dave"]);
        let (g, _rg) = attach(&core, "guest", false);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        // Live delivery to a session that is right there: fine, and the
        // nick shows, as it always did.
        assert!(matches!(
            core.msg(g, m, "hello".into(), None, None).unwrap(),
            MsgOutcome::Delivered(_)
        ));
        match &msgs(drain(&mut rm))[..] {
            [Event::Msg {
                cursor: None,
                from_nick,
                from_login,
                ..
            }] => {
                assert_eq!(from_nick, "guest");
                assert_eq!(*from_login, None, "nowhere to reply");
            }
            other => panic!("{other:?}"),
        }
        assert!(store.all().is_empty(), "nothing durable was written");

        // With nobody there, there is nothing a guest can do.
        core.end_session(m);
        assert_eq!(
            core.msg_login(g, "dave", "still here?".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        assert!(store.all().is_empty());
    }

    #[test]
    fn a_guest_cannot_fill_a_mailbox_against_everyone_else() {
        let (core, store) = server(&["dave", "alice"]);
        let policy = core.inbox_policy;
        let (g, _rg) = attach(&core, "guest", false);
        let (a, _ra) = attach(&core, "alice", true);
        // Dave is offline. The guest tries the whole cap and more.
        for i in 0..policy.max_queued + 5 {
            assert_eq!(
                core.msg_login(g, "dave", format!("flood {i}"), None, None),
                Err(ChatError::NoSuchUser)
            );
        }
        assert!(store.all().is_empty());
        // An account can still reach him, which is the point.
        assert!(matches!(
            core.msg_login(a, "dave", "dinner?".into(), None, None),
            Ok(MsgOutcome::Queued(_))
        ));
        assert_eq!(store.all().len(), 1);
    }

    #[test]
    fn concurrent_flushes_do_not_deliver_a_message_twice() {
        // Two senders storing for one recipient, both flushing. Without a
        // lock across pending -> send -> mark, both read the same rows
        // and both push them, and the recipient sees every message twice
        // — an ng client gets two `msg` events with the same id, a 1.5
        // client gets two windows.
        use std::sync::Arc;
        let (core, _store) = server(&["dave", "a1", "a2", "a3", "a4"]);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);
        let senders: Vec<Uid> = (1..=4)
            .map(|n| attach(&core, &format!("a{n}"), true).0)
            .collect();

        let handles: Vec<_> = senders
            .iter()
            .enumerate()
            .map(|(i, &from)| {
                let core: Arc<Core> = core.clone();
                std::thread::spawn(move || {
                    for j in 0..10 {
                        core.msg(from, m, format!("s{i}-{j}"), None, None).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // And a flush racing them from the recipient's own side.
        core.flush_inbox(m);

        let mut ids = Vec::new();
        let mut bodies = Vec::new();
        for e in msgs(drain(&mut rm)) {
            if let Event::Msg { cursor, text, .. } = e {
                ids.push(cursor.expect("stored mail carries a cursor"));
                bodies.push(text);
            }
        }
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "every message exactly once; got {} events for {} ids",
            ids.len(),
            unique.len()
        );
        assert_eq!(bodies.len(), 40, "and all of them arrived");
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "in id order");
    }

    #[test]
    fn a_retry_hands_over_a_message_the_recipient_can_now_receive() {
        // A client retries after a socket died mid-ack. The store
        // answers "that is the message you already sent" — and the
        // answer to give the sender is the one the first send would get
        // *now*: the recipient may have arrived in between, and leaving
        // the mail pending until their next login while they are sitting
        // there is a message that waits for no reason.
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let g = crate::inbox::MessageGuid::parse("00000001-0000-4000-8000-000000000000").unwrap();

        assert!(matches!(
            core.msg_login(a, "dave", "you there?".into(), Some(g.clone()), None)
                .unwrap(),
            MsgOutcome::Queued(_)
        ));

        // Dave logs in. The retry finds him.
        let (_m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);
        assert!(
            matches!(
                core.msg_login(a, "dave", "you there?".into(), Some(g), None)
                    .unwrap(),
                MsgOutcome::Delivered(_)
            ),
            "the retry is answered as of now, not as of the first send"
        );
        assert!(
            matches!(
                &msgs(drain(&mut rm))[..],
                [Event::Msg { text, queued: true, .. }] if text == "you there?"
            ),
            "the message went with the answer, and it waited: a retry is \
             not a fresh send however briefly the row sat there"
        );
    }

    #[test]
    fn a_message_reaches_the_attached_session_not_the_lowest_uid() {
        // Two sessions on one account: a detached phone and an attached
        // laptop. Resolving the recipient by lowest uid aimed everything
        // at the phone, which is buffering — so nothing was delivered
        // live and the laptop learned about it at its next sync.
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (phone, _rp) = attach(&core, "dave", true);
        let (laptop, mut rl) = attach(&core, "dave", true);
        assert!(phone < laptop, "the detached one has the lower uid");
        drain(&mut rl);
        assert!(core.connection_lost(phone, 8));

        assert!(
            matches!(
                core.msg_login(a, "dave", "dinner?".into(), None, None)
                    .unwrap(),
                MsgOutcome::Delivered(_)
            ),
            "the laptop is right there"
        );
        assert!(
            matches!(&msgs(drain(&mut rl))[..], [Event::Msg { text, .. }] if text == "dinner?"),
            "and it is the laptop that got it"
        );
    }

    #[test]
    fn a_message_by_login_reaches_every_attached_session_of_the_account() {
        // Each case is the wires of dave's sessions, classic or not.
        for wires in [
            &[false][..],
            &[true],
            &[false, false],
            &[true, false],
            &[true, true],
        ] {
            let (core, store) = server(&["alice", "dave"]);
            let (a, _ra) = attach(&core, "alice", true);
            let (_a2, mut ra2) = attach(&core, "alice", true);
            let mut daves: Vec<(Uid, Events)> = wires
                .iter()
                .map(|classic| attach_wire(&core, "dave", true, *classic))
                .collect();
            for (_, rx) in &mut daves {
                drain(rx);
            }

            assert!(
                matches!(
                    core.msg_login(a, "dave", "dinner?".into(), None, None),
                    Ok(MsgOutcome::Delivered(_))
                ),
                "{wires:?}"
            );
            let stored = store.all();
            assert_eq!(stored.len(), 1, "{wires:?}: stored once");
            for (_, rx) in &mut daves {
                assert!(
                    matches!(
                        &msgs(drain(rx))[..],
                        [Event::Msg { text, reference: Some(r), queued: false, .. }]
                            if text == "dinner?" && *r == stored[0].reference
                    ),
                    "{wires:?}: every session hears it, once"
                );
            }
            assert!(
                msgs(drain(&mut ra2)).is_empty(),
                "{wires:?}: not the sender's"
            );
            assert!(stored[0].delivered_at.is_some(), "{wires:?}");
            // Read only where no session that got it can say so itself.
            assert_eq!(
                stored[0].read_at.is_some(),
                wires.iter().all(|classic| *classic),
                "{wires:?}"
            );

            // A uid still names one session.
            let first = daves[0].0;
            core.msg(a, first, "you".into(), None, None).unwrap();
            assert_eq!(msgs(drain(&mut daves[0].1)).len(), 1, "{wires:?}");
            for (_, rx) in &mut daves[1..] {
                assert!(msgs(drain(rx)).is_empty(), "{wires:?}: only the named one");
            }

            // To one's own account, for its other sessions, and waiting
            // where there are none.
            let outcome = core.msg_login(first, "dave", "note".into(), None, None);
            assert!(msgs(drain(&mut daves[0].1)).is_empty(), "{wires:?}");
            for (_, rx) in &mut daves[1..] {
                assert_eq!(msgs(drain(rx)).len(), 1, "{wires:?}");
            }
            assert_eq!(
                matches!(outcome, Ok(MsgOutcome::Queued(_))),
                daves.len() == 1,
                "{wires:?}"
            );
        }
    }

    #[test]
    fn a_message_by_login_that_stores_nothing_reaches_every_attached_session() {
        let quota = InboxPolicy {
            max_sent_per_day: 1,
            ..InboxPolicy::default()
        };
        for (what, guest) in [("past the sender's quota", false), ("from a guest", true)] {
            let (core, store) = server_with(quota, &["alice", "dave"]);
            let (from, _rf) = if guest {
                attach(&core, "guest", false)
            } else {
                attach(&core, "alice", true)
            };
            if !guest {
                core.msg_login(from, "dave", "spent".into(), None, None)
                    .unwrap();
            }
            let rows = store.all().len();
            let (_d1, mut r1) = attach(&core, "dave", true);
            let (_d2, mut r2) = attach_wire(&core, "dave", true, true);
            assert!(
                matches!(
                    core.msg_login(from, "dave", "live".into(), None, None),
                    Ok(MsgOutcome::Delivered(_))
                ),
                "{what}"
            );
            for rx in [&mut r1, &mut r2] {
                assert!(
                    matches!(
                        &msgs(drain(rx))[..],
                        [Event::Msg { cursor: None, text, .. }] if text == "live"
                    ),
                    "{what}: each session hears it, with no row"
                );
            }
            assert_eq!(store.all().len(), rows, "{what}");
        }
    }

    #[test]
    fn a_send_that_stores_nothing_still_goes_to_the_session_that_was_named() {
        // The non-durable path — every plain-guest sender on a server
        // with `[inbox]`, and *every* sender on a server without one.
        // It resolved by lowest attached uid, which overrode the uid the
        // sender named even when that session was attached too: the
        // phone got what was clicked on the laptop (§15).
        for (what, core) in [
            ("no store at all", Arc::new(Core::new())),
            ("a guest sender", server(&["dave"]).0),
        ] {
            // A guest has no mailbox, so nothing it sends is stored;
            // with no store nothing is stored either way.
            let (guest, _rg) = attach(&core, "guest", false);
            let (phone, mut rp) = attach(&core, "dave", true);
            let (laptop, mut rl) = attach(&core, "dave", true);
            assert!(phone < laptop, "{what}: the named one has the higher uid");
            drain(&mut rp);
            drain(&mut rl);

            assert!(
                matches!(
                    core.msg(guest, laptop, "over here".into(), None, None)
                        .unwrap(),
                    MsgOutcome::Delivered(_)
                ),
                "{what}"
            );
            assert!(
                matches!(&msgs(drain(&mut rl))[..], [Event::Msg { text, .. }] if text == "over here"),
                "{what}: the session the sender clicked is the one that hears it"
            );
            assert!(msgs(drain(&mut rp)).is_empty(), "{what}: not the other one");

            // And naming the phone still reaches the phone.
            core.msg(guest, phone, "and here".into(), None, None)
                .unwrap();
            assert!(
                matches!(&msgs(drain(&mut rp))[..], [Event::Msg { text, .. }] if text == "and here"),
                "{what}"
            );
            assert!(msgs(drain(&mut rl)).is_empty(), "{what}");

            // A named session that is *detached* still falls back to one
            // that can hear it: this path has nowhere to queue.
            assert!(core.connection_lost(laptop, 8));
            core.msg(guest, laptop, "anyone".into(), None, None)
                .unwrap();
            assert!(
                matches!(&msgs(drain(&mut rp))[..], [Event::Msg { text, .. }] if text == "anyone"),
                "{what}: a detached named session is not an address"
            );
        }
    }

    #[test]
    fn addressing_an_account_that_takes_no_mail_is_the_same_answer_as_a_typo() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        assert_eq!(
            core.msg_login(a, "nobody", "hi".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        assert_eq!(
            core.msg_login(a, "guest", "hi".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        // And the canonical form is the directory's, not the client's.
        assert!(core.msg_login(a, "DaVe", "hi".into(), None, None).is_ok());
    }

    #[test]
    fn addressing_a_login_that_is_online_delivers_rather_than_queues() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        assert!(matches!(
            core.msg_login(a, "dave", "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered(_)
        ));
        assert!(matches!(
            &msgs(drain(&mut rm))[..],
            [Event::Msg { queued: false, .. }]
        ));
        assert_eq!(
            core.inbox_counts(m).unwrap(),
            InboxCounts {
                unread: 1,
                total: 1
            },
            "delivered, and still waiting to be read"
        );
    }

    #[test]
    fn a_queued_messages_sender_uid_is_resolved_at_delivery_by_login() {
        let (core, _store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);
        core.end_session(m);

        core.msg_login(a, "dave", "first".into(), None, None)
            .unwrap();
        core.end_session(a); // the sender leaves before it is delivered

        let (m2, mut rm2) = attach(&core, "dave", true);
        core.flush_inbox(m2);
        assert!(
            matches!(
                &msgs(drain(&mut rm2))[..],
                [Event::Msg { from: 0, from_login, .. }]
                    if from_login.as_deref() == Some("alice")
            ),
            "no session, no uid — the login carries the identity"
        );
        core.end_session(m2);

        // Again, but this time the sender is back by the time it is
        // delivered — on a *different* uid, which is the one a reply
        // should reach, because it is the same account.
        let (a2, _ra2) = attach(&core, "alice", true);
        core.msg_login(a2, "dave", "second".into(), None, None)
            .unwrap();
        core.end_session(a2);
        let (a3, _ra3) = attach(&core, "alice", true);
        assert_ne!(a3, a2, "a fresh session, a fresh uid");

        let (m3, mut rm3) = attach(&core, "dave", true);
        core.flush_inbox(m3);
        assert!(
            matches!(&msgs(drain(&mut rm3))[..], [Event::Msg { from, .. }] if *from == a3),
            "resolved now and by login, never by the uid that sent it"
        );
    }

    #[test]
    fn a_senders_quota_bounds_what_is_stored_and_never_a_live_message() {
        let (core, store) = server_with(
            InboxPolicy {
                max_sent_per_day: 2,
                max_sent_bytes_per_day: 20,
                ..InboxPolicy::default()
            },
            &["alice", "bob", "dave"],
        );
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "one".into(), None, None).unwrap();
        // A delivered message counts: retention keeps it all the same.
        let (m, _rm) = attach(&core, "dave", true);
        core.msg_login(a, "dave", "two".into(), None, None).unwrap();
        core.end_session(m);
        assert_eq!(
            core.msg_login(a, "dave", "three".into(), None, None),
            Err(ChatError::SendQuota),
            "nobody is there, and the day's storage is spent"
        );
        assert_eq!(store.all().len(), 2);

        // Someone who is there hears it, with no row kept and no id.
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);
        assert!(matches!(
            core.msg_login(a, "dave", "live".into(), None, None),
            Ok(MsgOutcome::Delivered(_))
        ));
        assert!(matches!(
            &msgs(drain(&mut rm))[..],
            [Event::Msg { cursor: None, text, .. }] if text == "live"
        ));
        assert_eq!(store.all().len(), 2, "nothing stored past the quota");
        core.end_session(m);

        // Another sender's day is their own, and bytes count as well as
        // messages: this one fits the count and not the bytes.
        let (b, _rb) = attach(&core, "bob", true);
        core.msg_login(b, "dave", "x".repeat(20), None, None)
            .unwrap();
        assert_eq!(
            core.msg_login(b, "dave", "y".into(), None, None),
            Err(ChatError::SendQuota)
        );
    }

    #[test]
    fn a_retry_of_a_stored_message_is_answered_past_the_quota() {
        let (core, store) = server_with(
            InboxPolicy {
                max_sent_per_day: 1,
                ..InboxPolicy::default()
            },
            &["alice", "dave"],
        );
        let g = crate::inbox::MessageGuid::parse("00000002-0000-4000-8000-000000000000").unwrap();
        let (a, _ra) = attach(&core, "alice", true);
        // The last message the day allows, stored while nobody is there;
        // its ack is what the client lost.
        let first = core
            .msg_login(a, "dave", "last one".into(), Some(g.clone()), None)
            .unwrap();
        let MsgOutcome::Queued(id) = first else {
            panic!("queued, got {first:?}");
        };
        assert_eq!(
            core.msg_login(a, "dave", "last one".into(), Some(g.clone()), None),
            Ok(MsgOutcome::Queued(id)),
            "the retry is the message we have, not one past the quota"
        );

        // The recipient attaches before the next retry: they are handed
        // the stored row once, with its id, and never a live copy beside it.
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);
        assert_eq!(
            core.msg_login(a, "dave", "last one".into(), Some(g), None),
            Ok(MsgOutcome::Delivered(Some(id))),
            "the one stored"
        );
        assert!(
            matches!(
                &msgs(drain(&mut rm))[..],
                [Event::Msg { reference: Some(got), .. }] if *got == id
            ),
            "one copy, the stored one"
        );
        assert_eq!(store.all().len(), 1);
        core.end_session(m);
    }

    #[test]
    fn private_chats_are_capped_per_creator_and_per_server_until_they_close() {
        let core = Core::new().with_chat_limits(crate::ChatLimits {
            per_creator: 2,
            total: 3,
        });
        let anyone = crate::AccessBits::default();
        let (a, _ra) = crate::roster::test_attach(&core, "alice", anyone);
        let (b, _rb) = crate::roster::test_attach(&core, "bob", anyone);
        let (first, _) = core.chat_create(a, b).unwrap();
        core.chat_create(a, b).unwrap();
        assert_eq!(core.chat_create(a, b).err(), Some(ChatError::TooManyChats));
        let (bobs, _) = core.chat_create(b, a).unwrap();
        assert_eq!(
            core.chat_create(b, a).err(),
            Some(ChatError::TooManyChats),
            "the server's are spent"
        );
        // Still open with bob in it after alice walks out: still hers.
        core.chat_join(first, b, "").unwrap();
        core.chat_part(first, a);
        core.chat_part(bobs, b);
        assert_eq!(core.chat_create(a, b).err(), Some(ChatError::TooManyChats));
        core.chat_part(first, b);
        core.chat_create(a, b).unwrap();
    }

    #[test]
    fn a_full_mailbox_refuses_rather_than_dropping_the_oldest() {
        let (core, store) = server_with(
            InboxPolicy {
                max_queued: 2,
                ..InboxPolicy::default()
            },
            &["alice", "dave"],
        );
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "one".into(), None, None).unwrap();
        core.msg_login(a, "dave", "two".into(), None, None).unwrap();
        assert_eq!(
            core.msg_login(a, "dave", "three".into(), None, None),
            Err(ChatError::MailboxFull),
            "the sender is told, rather than the message vanishing"
        );
        assert_eq!(store.all().len(), 2, "and nothing was evicted to fit it");

        // Collecting the mail is what makes room — not reading it. A
        // client that never marks anything read must not be able to lock
        // its own mailbox against every sender.
        let (m, _rm) = attach(&core, "dave", true);
        assert_eq!(core.flush_inbox(m), 2);
        assert_eq!(
            core.inbox_counts(m).unwrap().unread,
            2,
            "still unread, and no longer in the way"
        );
        assert!(core
            .msg_login(a, "dave", "three".into(), None, None)
            .is_ok());
    }

    #[test]
    fn the_flush_cap_leaves_the_rest_pending_and_says_how_many() {
        let (core, _store) = server_with(
            InboxPolicy {
                deliver_at_flush: 2,
                ..InboxPolicy::default()
            },
            &["alice", "dave"],
        );
        let (a, _ra) = attach(&core, "alice", true);
        for i in 0..5 {
            core.msg_login(a, "dave", format!("m{i}"), None, None)
                .unwrap();
        }

        let (m, mut rm) = attach(&core, "dave", true);
        assert_eq!(core.flush_inbox(m), 2, "one window at a time");
        let evs = drain(&mut rm);
        assert_eq!(msgs(evs.clone()).len(), 2);
        assert!(
            matches!(evs.last(), Some(Event::Notice { text, .. }) if text.starts_with("3 more")),
            "what is left is still there, and says so: {evs:?}"
        );
        // The next login picks up where this one stopped.
        assert_eq!(core.flush_inbox(m), 2);
        assert_eq!(core.flush_inbox(m), 1);
        assert_eq!(core.flush_inbox(m), 0);
    }

    /// An id from before schema 33 was the server's, so larger than any
    /// cursor: read as one, it would mark or page mail the client never
    /// saw. A cursor the mailbox never issued is refused instead.
    #[test]
    fn a_cursor_the_mailbox_never_issued_is_refused() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        for text in ["one", "two"] {
            core.msg_login(a, "alice", text.into(), None, None).unwrap();
        }
        let (m, _rm) = attach(&core, "dave", true);
        core.msg_login(m, "alice", "three".into(), None, None)
            .unwrap();
        assert_eq!(store.all().len(), 3);
        assert_eq!(
            core.inbox_mark_read(a, 4),
            Err(ChatError::UnknownCursor),
            "past the last"
        );
        assert_eq!(core.inbox_counts(a).unwrap().unread, 3, "nothing marked");
        assert_eq!(
            core.inbox_list(a, Some(4), 10),
            Err(ChatError::UnknownCursor)
        );
        assert_eq!(core.inbox_mark_read(a, 3).unwrap().unread, 0, "the last is");
        assert_eq!(core.inbox_list(a, Some(3), 10).unwrap().len(), 2);
    }

    #[test]
    fn counts_and_marking_read_are_scoped_to_the_callers_own_account() {
        let (core, store) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "one".into(), None, None).unwrap();
        core.msg_login(a, "alice", "to myself".into(), None, None)
            .unwrap();
        let (dave_msg, alice_msg) = (store.all()[0].cursor, store.all()[1].cursor);
        assert_eq!(alice_msg, dave_msg, "each the first of its mailbox");

        // Alice naming a cursor dave's mail has too marks only her own.
        let left = core.inbox_mark_read(a, alice_msg).unwrap();
        assert_eq!(left.unread, 0, "alice's own is read");
        let (m, _rm) = attach(&core, "dave", true);
        assert_eq!(
            core.inbox_counts(m).unwrap().unread,
            1,
            "dave's is untouched"
        );
    }

    #[test]
    fn a_server_with_no_inbox_behaves_exactly_as_it_did_before_there_was_one() {
        let core = Core::new();
        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        drain(&mut rm);

        assert!(matches!(
            core.msg(a, m, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered(_)
        ));
        assert!(matches!(
            &msgs(drain(&mut rm))[..],
            [Event::Msg {
                cursor: None,
                queued: false,
                ..
            }]
        ));
        // Addressing an account is an inbox feature and is simply absent.
        assert_eq!(
            core.msg_login(a, "dave", "hi".into(), None, None),
            Err(ChatError::NoSuchUser)
        );
        assert_eq!(core.flush_inbox(m), 0);
        assert_eq!(core.inbox_counts(m).unwrap(), InboxCounts::default());

        // And a detached session still buffers in its outbox, as before.
        let last_seq = core.current_seq(m).unwrap();
        assert!(core.connection_lost(m, 8));
        core.msg(a, m, "still there?".into(), None, None).unwrap();
        let Resume::Replayed(_rm2, replay) = core.resume(m, last_seq) else {
            panic!("resume should replay");
        };
        assert!(replay.iter().any(|se| matches!(&se.event,
            Event::Msg { text, .. } if text == "still there?")));
    }

    // --- The mailbox key (docs/private-messages.md §5.4) -----------------

    #[test]
    fn a_rotation_takes_the_mailbox_the_blocks_and_the_subscriptions() {
        use crate::news::{MemoryNews, NewNode, NewsPolicy, NewsStore, NodeKind, SubScope};
        let store = Arc::new(MemoryStore::new());
        let relationships = Arc::new(crate::relationships::MemoryRelationships::new());
        let news = Arc::new(MemoryNews::new());
        let dir = Arc::new(Directory(vec![
            Mailbox::identified("alice", fp(10)),
            Mailbox::login("sender"),
        ]));
        let core = Arc::new(
            Core::new()
                .with_inbox(store.clone(), dir, InboxPolicy::default())
                .with_relationships(relationships.clone())
                .with_news(news.clone(), NewsPolicy::default()),
        );
        let (s, _rs) = attach(&core, "sender", true);
        core.msg_login(s, "alice", "private".into(), None, None)
            .unwrap();
        let (old, new) = (
            Mailbox::identified("alice", fp(10)),
            Mailbox::identified("alice", fp(12)),
        );
        let now = SystemTime::now();
        relationships
            .set_blocked(&old, &Mailbox::login("sender"), true, now)
            .unwrap();
        let node = NewNode {
            parent: None,
            kind: NodeKind::Category,
            name: "General".into(),
            guid: [1; 16],
            at: now,
        };
        let cat = news.create_node(&node, 16).unwrap().id;
        news.subscribe(&old, SubScope::Category(cat), 16, now)
            .unwrap();

        // A session on the account's old key, as a password login to it
        // has: what it would write next would stay behind, so it ends.
        let (_stale, mut stale) = attach_identified(&core, "alice", fp(10));

        core.rotate_identity(&fp(10), &fp(12)).unwrap();
        assert!(drain(&mut stale).iter().any(|e| matches!(e, Event::Kicked)));
        let (alice, mut ra) = attach_identified(&core, "alice", fp(12));
        assert_eq!(core.flush_inbox(alice), 1);
        assert!(matches!(
            &msgs(drain(&mut ra))[..],
            [Event::Msg { text, .. }] if text == "private"
        ));
        assert_eq!(
            relationships.blocked(&new).unwrap(),
            [Mailbox::login("sender")]
        );
        assert_eq!(news.subscriptions(&new).unwrap().len(), 1);
    }

    #[test]
    fn a_rename_takes_the_mailbox_and_the_freed_login_inherits_nothing() {
        let store = Arc::new(MemoryStore::new());
        // The directory knows alice by her identity, not just her login.
        let dir = Arc::new(Directory(vec![
            Mailbox::identified("alice", fp(10)),
            Mailbox::login("sender"),
        ]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));
        let (s, _rs) = attach(&core, "sender", true);
        core.msg_login(s, "alice", "private".into(), None, None)
            .unwrap();

        // She renames. Same identity, new login, same mail.
        let (alicia, mut r_alicia) = attach_identified(&core, "alicia", fp(10));
        assert_eq!(core.flush_inbox(alicia), 1);
        assert!(matches!(
            &msgs(drain(&mut r_alicia))[..],
            [Event::Msg { text, .. }] if text == "private"
        ));
        // And live, under the login the directory still has.
        assert!(matches!(
            core.msg_login(s, "alice", "again".into(), None, None),
            Ok(MsgOutcome::Delivered(_))
        ));
        assert!(matches!(
            &msgs(drain(&mut r_alicia))[..],
            [Event::Msg { text, .. }] if text == "again"
        ));
        core.end_session(alicia);

        // Someone else takes the freed login — with an identity of their
        // own, and without one. Neither inherits a word of it.
        let (b, mut rb) = attach_identified(&core, "alice", fp(11));
        assert_eq!(core.flush_inbox(b), 0, "a different identity, same login");
        assert!(msgs(drain(&mut rb)).is_empty());
        core.end_session(b);

        let (bare, _rbare) = attach(&core, "alice", true);
        assert_eq!(core.flush_inbox(bare), 0, "nor a bare login");
    }

    #[test]
    fn a_queued_senders_uid_resolves_to_the_identity_not_the_login() {
        let store = Arc::new(MemoryStore::new());
        let dir = Arc::new(Directory(vec![
            Mailbox::login("dave"),
            Mailbox::identified("alice", fp(10)),
        ]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));

        // Alice, identity A, sends while dave is away, then leaves.
        let (a, _ra) = attach_identified(&core, "alice", fp(10));
        core.msg_login(a, "dave", "from the real alice".into(), None, None)
            .unwrap();
        core.end_session(a);

        // An impostor takes the freed login with no identity, and is on
        // the roster when the mail is delivered.
        let (impostor, _ri) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        core.flush_inbox(m);
        assert!(
            matches!(&msgs(drain(&mut rm))[..], [Event::Msg { from: 0, .. }]),
            "a reply must not be addressed to whoever holds the name now"
        );
        let _ = impostor;
    }

    // --- Blocking (docs/private-messages.md §9) --------------------------

    #[test]
    fn a_block_refuses_the_message_however_it_is_addressed() {
        let (core, store) = server(&["dave", "spammer"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (sp, _rsp) = attach(&core, "spammer", true);
        core.inbox_block(m, "spammer", true).unwrap();

        assert_eq!(
            core.msg_login(sp, "dave", "buy this".into(), None, None),
            Err(ChatError::Blocked)
        );
        // And naming the roster row instead does not get round it: a
        // block a recipient can sidestep by clicking a name is no block.
        assert_eq!(
            core.msg(sp, m, "buy this".into(), None, None),
            Err(ChatError::Blocked)
        );
        assert!(store.all().is_empty(), "and nothing was stored either way");

        core.inbox_block(m, "spammer", false).unwrap();
        assert!(core.msg(sp, m, "sorry".into(), None, None).is_ok());
    }

    #[test]
    fn mail_from_an_identity_guest_is_listed_with_no_one_to_reply_to() {
        // Their mailbox is keyed by fingerprint and named `guest`, which
        // is a login several people share and one a reply would answer
        // `no_such_user` for. The delivered event has applied that rule
        // since the flush learned it; the stored list used to print the
        // login verbatim, so `inbox` offered a reply address that
        // couldn't be used.
        let (core, _store) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (g, _rg) = core
            .attach(AttachInfo {
                account: None,
                nick: "drifter".into(),
                icon: 1,
                admin: false,
                access: AccessBits::empty().with(bit::SEND_MSGS),
                login: "guest".into(),
                addr: Some("10.0.0.9".parse().unwrap()),
                can_detach: false,
                transport: crate::Transport::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: false,
                reads_on_delivery: false,
                identity: Some(fp(3)),
                system: false,
            })
            .unwrap();
        core.announce(g);

        core.msg(g, m, "from a passer-by".into(), None, None)
            .unwrap();
        let listed = core.inbox_list(m, None, 10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].sender_nick, "drifter", "the nick still shows");
        assert!(
            listed[0].sender.is_none(),
            "and there is no login to reply to"
        );
    }

    #[test]
    fn a_block_on_an_identity_guest_outlives_them_and_can_still_be_lifted() {
        // An identity user admitted as a guest has a fingerprint to hold
        // a block against and no account of its own. The list used to
        // report the login — `guest` — which `unblock` could not resolve
        // and which the roster could not answer for once they left, so
        // the block was permanent.
        let (core, _store) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (g, _rg) = core
            .attach(AttachInfo {
                account: None,
                nick: "drifter".into(),
                icon: 1,
                admin: false,
                access: AccessBits::empty().with(bit::SEND_MSGS),
                login: "guest".into(),
                addr: Some("10.0.0.9".parse().unwrap()),
                can_detach: false,
                transport: crate::Transport::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: false,
                reads_on_delivery: false,
                identity: Some(fp(7)),
                system: false,
            })
            .unwrap();
        core.announce(g);

        core.inbox_block_uid(m, g, true).unwrap();
        let blocked = core.inbox_blocked(m).unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].login, "guest");
        assert_eq!(blocked[0].fingerprint, Some(fp(7)), "keyed by the key");

        // They leave. There is no roster row to name, and `guest` names
        // no mailbox — the fingerprint is all that is left.
        core.end_session(g);
        assert!(core.inbox_block(m, "guest", false).is_err());
        core.inbox_unblock_fingerprint(m, &fp(7)).unwrap();
        assert!(core.inbox_blocked(m).unwrap().is_empty());
        assert_eq!(
            core.inbox_unblock_fingerprint(m, &fp(7)),
            Err(ChatError::NoSuchUser),
            "and a fingerprint that holds no block is not a block"
        );
    }

    #[test]
    fn a_live_only_identity_guest_is_refused_by_a_block_placed_after_routing() {
        let (core, store) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (g, _rg) = core
            .attach(AttachInfo {
                account: None,
                nick: "drifter".into(),
                icon: 1,
                admin: false,
                access: AccessBits::empty().with(bit::SEND_MSGS),
                login: "guest".into(),
                addr: Some("10.0.0.9".parse().unwrap()),
                can_detach: false,
                transport: crate::Transport::default(),
                has_inbox: false,
                attach_news: false,
                set_avatar: false,
                moderate: false,
                can_spam: false,
                manage_rooms: false,
                set_subject: false,
                is_person: false,
                reads_on_delivery: false,
                identity: Some(fp(7)),
                system: false,
            })
            .unwrap();
        core.announce(g);
        // What `msg_login` hands delivery once routing has let it in.
        let send = |text: &str| {
            let mut sender = Sender::resolve(&core.roster.lock().unwrap(), g).unwrap();
            sender.live_only = true;
            let dave = Mailbox::login("dave");
            let to = Recipient {
                principal: crate::media::Principal::Mailbox(dave.clone()),
                uid: None,
                mailbox: dave,
                has_inbox: true,
            };
            core.deliver(sender, to, text.into(), None, None, None, None)
        };
        assert!(matches!(send("hi"), Ok(MsgOutcome::Delivered(None))));
        core.inbox_block_uid(m, g, true).unwrap();
        assert_eq!(send("again"), Err(ChatError::NoSuchUser));
        assert!(
            store
                .pending(&Mailbox::login("dave"), 10)
                .unwrap()
                .is_empty(),
            "stored nowhere either way"
        );
    }

    #[test]
    fn a_block_is_one_way_and_listed_and_says_nothing_about_who_exists() {
        let (core, _store) = server(&["dave", "spammer"]);
        let (m, _rm) = attach(&core, "dave", true);
        let (sp, _rsp) = attach(&core, "spammer", true);

        core.inbox_block(m, "spammer", true).unwrap();
        assert_eq!(
            core.inbox_blocked(m).unwrap(),
            vec![Mailbox::login("spammer")]
        );
        assert!(
            core.inbox_blocked(sp).unwrap().is_empty(),
            "blocking is one-way, and the blocked account is not told"
        );
        assert!(core
            .msg(m, sp, "you are blocked".into(), None, None)
            .is_ok());

        // Blocking a name that names no mailbox is the same one answer
        // msg_login gives, so this cannot enumerate accounts either.
        assert_eq!(
            core.inbox_block(m, "nobody", true),
            Err(ChatError::NoSuchUser)
        );
        assert_eq!(
            core.inbox_block(m, "dave", true),
            Err(ChatError::NoSuchUser),
            "and blocking yourself is not a thing"
        );
    }

    #[test]
    fn a_guest_cannot_be_blocked_because_there_is_nothing_to_block() {
        let (core, _store) = server(&["dave"]);
        let (m, mut rm) = attach(&core, "dave", true);
        let (g, _rg) = attach(&core, "guest", false);
        drain(&mut rm);

        assert_eq!(
            core.inbox_block(m, "guest", true),
            Err(ChatError::NoSuchUser)
        );
        // A guest reaches the mailbox as before; what bounds it is the
        // roster, where it can be kicked and banned.
        assert!(core.msg(g, m, "hello".into(), None, None).is_ok());
        assert_eq!(msgs(drain(&mut rm)).len(), 1);
    }

    // --- The store-then-re-check window (docs/private-messages.md §5.2) --

    /// A store that lets a test run something *during* `push` — inside the
    /// window where the domain has dropped the roster lock to write and
    /// has not taken it back to deliver.
    struct RacyStore {
        inner: MemoryStore,
        during_push: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl RacyStore {
        fn new() -> Self {
            RacyStore {
                inner: MemoryStore::new(),
                during_push: Mutex::new(None),
            }
        }
    }

    impl MessageStore for RacyStore {
        fn push(&self, m: &NewMessage, cap: usize) -> Result<crate::inbox::Pushed, StoreError> {
            let out = self.inner.push(m, cap)?;
            if let Some(f) = self.during_push.lock().unwrap().take() {
                f();
            }
            Ok(out)
        }
        fn is_pending(&self, to: &Mailbox, id: MessageId) -> Result<bool, StoreError> {
            self.inner.is_pending(to, id)
        }
        fn find_sent(
            &self,
            from: &Mailbox,
            guid: &MessageGuid,
        ) -> Result<Option<StoredMessage>, StoreError> {
            self.inner.find_sent(from, guid)
        }
        fn pending_of(
            &self,
            to: &Mailbox,
            limit: usize,
            which: crate::inbox::Pending,
        ) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.pending_of(to, limit, which)
        }
        fn pending_count_of(
            &self,
            to: &Mailbox,
            which: crate::inbox::Pending,
        ) -> Result<usize, StoreError> {
            self.inner.pending_count_of(to, which)
        }
        fn mark_handed(
            &self,
            ids: &[MessageId],
            at: std::time::SystemTime,
        ) -> Result<(), StoreError> {
            self.inner.mark_handed(ids, at)
        }
        fn receipt_told(
            &self,
            id: MessageId,
            at: std::time::SystemTime,
        ) -> Result<bool, StoreError> {
            self.inner.receipt_told(id, at)
        }
        fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError> {
            self.inner.pending_count(to)
        }
        fn mark_delivered(
            &self,
            ids: &[MessageId],
            at: std::time::SystemTime,
            what: Delivery,
        ) -> Result<(), StoreError> {
            self.inner.mark_delivered(ids, at, what)
        }
        fn mark_read(
            &self,
            to: &Mailbox,
            up_to: Cursor,
            at: std::time::SystemTime,
        ) -> Result<usize, StoreError> {
            self.inner.mark_read(to, up_to, at)
        }
        fn list(
            &self,
            to: &Mailbox,
            before: Option<Cursor>,
            limit: usize,
        ) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.list(to, before, limit)
        }
        fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError> {
            self.inner.counts(to)
        }
        fn last_cursor(&self, of: &Mailbox) -> Result<Cursor, StoreError> {
            self.inner.last_cursor(of)
        }
        fn unlinked(&self, login: &str, fingerprint: &[u8; 32]) -> Result<(), StoreError> {
            self.inner.unlinked(login, fingerprint)
        }
        fn find_guid(
            &self,
            to: &Mailbox,
            from: Option<&Mailbox>,
            guid: &MessageGuid,
        ) -> Result<Option<StoredMessage>, StoreError> {
            self.inner.find_guid(to, from, guid)
        }
        fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError> {
            self.inner.claim(login, fingerprint)
        }
        fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError> {
            self.inner.rotate(from, to)
        }
        fn purge(&self, of: &Mailbox) -> Result<usize, StoreError> {
            self.inner.purge(of)
        }
        fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError> {
            self.inner.purge_count(of)
        }
        fn prune(
            &self,
            now: std::time::SystemTime,
            unread: Duration,
            read: Duration,
        ) -> Result<usize, StoreError> {
            self.inner.prune(now, unread, read)
        }
        fn sent_since(
            &self,
            from: &Mailbox,
            since: SystemTime,
        ) -> Result<crate::inbox::Sent, StoreError> {
            self.inner.sent_since(from, since)
        }

        fn restamp(
            &self,
            merged: &[(crate::RelationId, crate::RelationId)],
        ) -> Result<usize, StoreError> {
            self.inner.restamp(merged)
        }
        fn requests(
            &self,
            to: &Mailbox,
            since: SystemTime,
            limit: usize,
        ) -> Result<Vec<StoredMessage>, StoreError> {
            self.inner.requests(to, since, limit)
        }
        fn release_requests(
            &self,
            to: &Mailbox,
            from: &Mailbox,
            on: crate::RelationId,
            since: SystemTime,
        ) -> Result<usize, StoreError> {
            self.inner.release_requests(to, from, on, since)
        }
        fn requests_to_mail(
            &self,
            to: &Mailbox,
            from: &Mailbox,
            address: Option<&str>,
            since: SystemTime,
        ) -> Result<usize, StoreError> {
            self.inner.requests_to_mail(to, from, address, since)
        }
        fn delete_requests_from(
            &self,
            to: &Mailbox,
            from: &Mailbox,
            address: &str,
        ) -> Result<usize, StoreError> {
            self.inner.delete_requests_from(to, from, address)
        }
        fn delete_requests(&self, to: &Mailbox, from: &Mailbox) -> Result<usize, StoreError> {
            self.inner.delete_requests(to, from)
        }
    }

    #[test]
    fn a_recipient_who_reattaches_mid_write_still_gets_it_now() {
        let store = Arc::new(RacyStore::new());
        let dir = Arc::new(Directory::of(&["alice", "dave"]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));

        let (a, _ra) = attach(&core, "alice", true);
        let (m, mut rm) = attach(&core, "dave", true);
        let last_seq = std::iter::from_fn(|| rm.try_recv().ok())
            .last()
            .map_or(0, |se| se.seq);
        assert!(core.connection_lost(m, 8));

        // Dave's phone comes back exactly while the message is being
        // written — after the decision to store, before delivery.
        let resumed: Arc<Mutex<Option<Events>>> = Arc::new(Mutex::new(None));
        let weak: Weak<Core> = Arc::downgrade(&core);
        let slot = resumed.clone();
        *store.during_push.lock().unwrap() = Some(Box::new(move || {
            let core = weak.upgrade().expect("core outlives the store call");
            if let Resume::Replayed(rx, _) | Resume::ResyncRequired(rx) = core.resume(m, last_seq) {
                *slot.lock().unwrap() = Some(rx);
            }
        }));

        assert!(
            matches!(
                core.msg(a, m, "are you there".into(), None, None).unwrap(),
                MsgOutcome::Delivered(_)
            ),
            "the re-check after the write is what catches this"
        );
        let mut rx = resumed.lock().unwrap().take().expect("resumed");
        assert!(
            matches!(
                &msgs(drain(&mut rx))[..],
                [Event::Msg { text, .. }] if text == "are you there"
            ),
            "otherwise it sits unread until the next login — while they watch"
        );
    }

    #[test]
    fn a_recipient_with_no_session_at_all_who_attaches_mid_write_gets_it_now() {
        // The `to_login` half of the same race, and the half the re-check
        // could not close: with no session at store time there was no uid
        // to re-check *against*, so a recipient who logged in while the
        // row was being written waited until their next login for a
        // message sent while they were watching the screen.
        let store = Arc::new(RacyStore::new());
        let dir = Arc::new(Directory::of(&["alice", "dave"]));
        let core = Arc::new(Core::new().with_inbox(store.clone(), dir, InboxPolicy::default()));
        let (a, _ra) = attach(&core, "alice", true);

        let arrived: Arc<Mutex<Option<Events>>> = Arc::new(Mutex::new(None));
        let weak: Weak<Core> = Arc::downgrade(&core);
        let slot = arrived.clone();
        *store.during_push.lock().unwrap() = Some(Box::new(move || {
            let core = weak.upgrade().expect("core outlives the store call");
            let (_uid, rx) = attach(&core, "dave", true);
            *slot.lock().unwrap() = Some(rx);
        }));

        assert!(
            matches!(
                core.msg_login(a, "dave", "still up?".into(), None, None)
                    .unwrap(),
                MsgOutcome::Delivered(_)
            ),
            "they were there by the time the row existed"
        );
        let mut rx = arrived.lock().unwrap().take().expect("attached");
        assert!(
            matches!(&msgs(drain(&mut rx))[..], [Event::Msg { text, .. }] if text == "still up?")
        );
    }
}

#[cfg(test)]
mod notify_tests {
    //! The notify decision — which arriving message earns a push, and
    //! which does not. See docs/push-notifications.md §6 and §11: the rule
    //! lives here rather than in a frontend precisely so that neither wire
    //! can skip it, and these are the cases that would go quietly wrong.

    use std::sync::{Arc, Mutex};

    use super::inbox_tests::{attach, server_arc};
    use super::*;
    use crate::notify::{Notification, NotificationGateway};
    use crate::{Core, InboxPolicy};

    /// A gateway that records what it was asked to send. No network, no
    /// runtime, nothing to wait for — the decision is the whole subject.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, String, usize)>>,
    }

    impl Recorder {
        /// `(recipient login, text, unread)`, in order.
        fn sent(&self) -> Vec<(String, String, usize)> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl NotificationGateway for Recorder {
        fn notify(&self, n: &Notification<'_>) {
            let Notification::Message(m) = n else {
                panic!("a private message notified something else: {n:?}");
            };
            self.sent
                .lock()
                .unwrap()
                .push((m.to.login.clone(), m.text.to_string(), m.unread));
        }
    }

    fn server(logins: &[&str]) -> (Arc<Core>, Arc<Recorder>) {
        let gw = Arc::new(Recorder::default());
        let (core, _store) = server_arc(InboxPolicy::default(), logins, Some(gw.clone()));
        (core, gw)
    }

    #[test]
    fn nobody_there_earns_a_notification() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        core.msg_login(a, "dave", "wake up".into(), None, None)
            .unwrap();
        assert_eq!(
            gw.sent(),
            vec![("dave".to_string(), "wake up".to_string(), 1)]
        );
    }

    #[test]
    fn a_detached_session_earns_one_too() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);
        assert!(core.connection_lost(m, 8));

        core.msg(a, m, "still asleep?".into(), None, None).unwrap();
        assert_eq!(gw.sent().len(), 1, "the phone is what the push is for");
        assert_eq!(gw.sent()[0].2, 1, "and it carries the badge number");
    }

    #[test]
    fn someone_watching_the_screen_earns_nothing() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (m, _rm) = attach(&core, "dave", true);

        assert!(matches!(
            core.msg(a, m, "hi".into(), None, None).unwrap(),
            MsgOutcome::Delivered(_)
        ));
        assert!(
            gw.sent().is_empty(),
            "a connection is attached and it got the event"
        );
    }

    #[test]
    fn a_message_to_your_own_account_is_not_news() {
        let (core, gw) = server(&["dave"]);
        let (m, _rm) = attach(&core, "dave", true);
        core.msg_login(m, "dave", "note to self".into(), None, None)
            .unwrap();
        // Stored, so a second device finds it; not pushed, because the
        // person who wrote it does not need telling.
        assert_eq!(core.inbox_counts(m).unwrap().unread, 1);
        assert!(gw.sent().is_empty());
    }

    #[test]
    fn a_recipient_with_no_inbox_earns_nothing() {
        let (core, gw) = server(&["alice"]);
        let (a, _ra) = attach(&core, "alice", true);
        let (g, _rg) = attach(&core, "guest", false);
        core.msg(a, g, "hi".into(), None, None).unwrap();
        assert!(
            gw.sent().is_empty(),
            "a push about a message that was never stored is a doorbell for nothing"
        );
    }

    #[test]
    fn the_badge_counts_everything_unread_not_just_this_one() {
        let (core, gw) = server(&["alice", "dave"]);
        let (a, _ra) = attach(&core, "alice", true);
        for i in 0..3 {
            core.msg_login(a, "dave", format!("m{i}"), None, None)
                .unwrap();
        }
        assert_eq!(
            gw.sent().iter().map(|s| s.2).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn no_gateway_means_no_calls_and_no_difference() {
        let (core, _store) =
            super::inbox_tests::server_arc(InboxPolicy::default(), &["alice", "dave"], None);
        let (a, _ra) = attach(&core, "alice", true);
        // The only assertion available is that nothing panics and the
        // message still lands — which is the point: push is optional.
        assert!(matches!(
            core.msg_login(a, "dave", "hi".into(), None, None).unwrap(),
            MsgOutcome::Queued(_)
        ));
    }
}
