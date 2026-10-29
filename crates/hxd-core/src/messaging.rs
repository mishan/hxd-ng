//! Instant messaging's domain (`docs/instant-messaging.md`): friends made
//! by request and response, presence summed across a login's sessions,
//! and what a stranger may learn of an account, over the relationship
//! store ([`crate::relationships`]).
//!
//! **Who takes part.** An account holding `AccessMessaging`
//! ([`crate::access::bit::MESSAGING`]), on a server whose `[messaging]`
//! is on, and never `admin` or `guest`, whatever their bits: `guest` is a
//! door several people share and `admin` a published handle on a
//! privileged account, as the extension has it.
//!
//! **What is told, and to whom.** Every event here goes to a
//! *messenger* session alone: one whose wire speaks the friend family,
//! or that has asked something of it. A client that never has is sent
//! nothing it could not read, which is what keeps both wires' existing
//! clients as they were. Instant messages are `im`'s, and message
//! requests and approvals `requests`'.
//!
//! **Presence is found in memory.** Each mailbox with a session taking
//! part keeps an entry on the roster: its sessions and its friends,
//! loaded from the store at its first session's announce and kept in
//! step by every friendship made or ended here, so a presence change is
//! fanned out under the roster lock without a store read. A burst of
//! changes is announced once with its final state, as voice's mute
//! flips are ([`Core::presence_flush`]).
//!
//! Store calls are made with the roster lock released, under
//! `Core::friend_writes`, which is taken first, so a friendship made
//! while a mailbox's entry is being loaded is in the entry either way.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tracing::warn;

use crate::access::bit;
use crate::inbox::{Mailbox, StoreError};
use crate::relationships::{
    AccountUpdate, LedgerEntry, PendingOut, Profile, RelationId, Relationship, RelationshipStore,
    RequestKind, Requester,
};
use crate::roster::{Event, RosterInner, SessionStatus, Uid, UserSession};
use crate::Core;

mod im;
mod requests;
#[cfg(test)]
mod tests;

pub(crate) use im::understands_requests;
pub use im::{Im, ImSent};
pub use requests::{Cleared, RequestAction, RequestGroup, RequestsListing};

/// What `[messaging]` says, as far as the domain is concerned.
#[derive(Debug, Clone, Copy)]
pub struct MessagingPolicy {
    /// Off unless an operator turns it on, as the extension has it.
    pub enabled: bool,
    /// `MaxRosterSize`: what an account's rows may hold, every state and
    /// a request it sent counted, a request it was sent not.
    pub max_roster: usize,
    /// How long a friend request waits before it lapses, and a hold
    /// lasts (`request_retention_days`).
    pub request_retention: Duration,
    /// Friend requests delivered and waiting for one recipient; past it
    /// a new one is dropped.
    pub max_friend_requests: usize,
    /// Distinct recipients one sender may send requests in a rolling day.
    pub requests_per_day: usize,
    /// Distinct recipients requested from one address in a rolling day,
    /// whoever sent them (`[limits] requests_per_address`).
    pub requests_per_address: usize,
    /// How long a burst of presence changes is held back to be told once.
    pub presence_debounce: Duration,
    /// `MaxMessageBytes`: an instant message's text, in UTF-8 bytes.
    pub max_message_bytes: usize,
    /// Message requests one sender may send one recipient within
    /// `request_retention`.
    pub request_messages: usize,
    /// Senders whose requests one recipient may have waiting; past it a
    /// new one is dropped.
    pub max_requests: usize,
}

impl Default for MessagingPolicy {
    fn default() -> Self {
        MessagingPolicy {
            enabled: false,
            max_roster: 500,
            request_retention: Duration::from_secs(30 * 24 * 3600),
            max_friend_requests: 50,
            requests_per_day: 20,
            requests_per_address: 100,
            presence_debounce: Duration::from_secs(1),
            max_message_bytes: 4096,
            request_messages: 5,
            max_requests: 50,
        }
    }
}

/// A login's presence, as the extension's `DATA_PRESENCE_STATE` has it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Presence {
    /// Only ever told; a session never sets it.
    Offline,
    #[default]
    Online,
    Away,
    /// The account's, not a session's: it hides every session from the
    /// account's friends.
    Invisible,
    Busy,
}

impl Presence {
    /// The most available of a login's sessions is what is shown.
    fn rank(self) -> u8 {
        match self {
            Presence::Online => 3,
            Presence::Busy => 2,
            Presence::Away => 1,
            Presence::Offline | Presence::Invisible => 0,
        }
    }
}

/// A roster row's state, as the extension's `DATA_ROSTER_STATE` has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterState {
    /// Only in a Roster Entry (801): the row is gone.
    Removed,
    PendingOut,
    PendingIn,
    Accepted,
    Blocked,
}

/// One roster row as its owner sees it: what Get Roster (800) lists and
/// a Roster Entry (801) carries, whole, since a client replaces its copy
/// rather than merging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriendEntry {
    pub login: String,
    pub fingerprint: Option<[u8; 32]>,
    pub state: RosterState,
    pub alias: Option<String>,
    /// [`Presence::Offline`] for anything but a friend.
    pub presence: Presence,
    /// A friend's, whenever it keeps one: the text is not presence.
    pub status_text: Option<String>,
    /// A waiting request's `DATA_REQUEST_NOTE`, for the 804 a roster
    /// read owes it.
    pub note: Option<String>,
}

impl FriendEntry {
    fn removed(of: &Mailbox) -> FriendEntry {
        FriendEntry {
            login: of.login.clone(),
            fingerprint: of.fingerprint,
            state: RosterState::Removed,
            alias: None,
            presence: Presence::Offline,
            status_text: None,
            note: None,
        }
    }

    fn asking(of: &Mailbox, note: Option<String>) -> FriendEntry {
        FriendEntry {
            state: RosterState::PendingIn,
            note,
            ..FriendEntry::removed(of)
        }
    }
}

/// What Find User (822) and Get User Info (825) answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundUser {
    pub login: String,
    /// The display name: the profile's nickname, or the login.
    pub name: String,
    /// Shown to a friend and to the account itself, never to anyone
    /// else, and never read as presence by its absence.
    pub presence: Option<(Presence, Option<String>)>,
    /// The whole profile, likewise; `None` is the extension's
    /// `NotFriends` beside the name.
    pub profile: Option<Profile>,
}

/// A Set Presence (808): each `None` leaves its part as it was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresenceUpdate {
    /// [`Presence::Offline`] is not a state a session sets, and changes
    /// nothing.
    pub state: Option<Presence>,
    /// `Some(None)` clears the text.
    pub status_text: Option<Option<String>>,
    pub discoverable: Option<bool>,
    pub takes_requests: Option<bool>,
}

/// Why a messaging request was refused, by the extension's reason codes
/// where it has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessagingError {
    /// The caller does not take part (`NotMessagingEnabled`).
    NotEnabled,
    /// No such account, one outside messaging, or one that has blocked
    /// the caller: one answer for all three.
    AccountNotFound,
    /// The caller has blocked them.
    Blocked,
    AlreadyFriends,
    RequestPending,
    NotFriends,
    RosterFull,
    /// A bound of `docs/instant-messaging.md` §4.4.
    RateLimited,
    /// Past `max_message_bytes`.
    MessageTooLong,
    /// The recipient has as many messages waiting as it may.
    QueueFull,
    /// A signature that does not name the recipient's identity.
    SignedElsewhere,
    /// A signed id already used for other words or another recipient.
    Equivocation,
    /// As many requests to one recipient as a sender may send
    /// (`request_full`).
    RequestFull,
    /// No request or approval of that sender's to answer.
    NoSuchRequest,
    ServerError,
}

fn store_failed(e: StoreError) -> MessagingError {
    warn!("relationships: {e}");
    MessagingError::ServerError
}

/// What an entry is keyed by: a mailbox's fingerprint where it has one,
/// so a row read with the login an identity once had still finds it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Key {
    Identity([u8; 32]),
    Login(String),
}

impl Key {
    pub(crate) fn of(m: &Mailbox) -> Key {
        match m.fingerprint {
            Some(fp) => Key::Identity(fp),
            None => Key::Login(m.login.clone()),
        }
    }
}

/// What a session taking part keeps.
#[derive(Debug, Clone, Default)]
pub(crate) struct SessionState {
    /// What its last Set Presence said: online, away or busy.
    pub(crate) state: Presence,
    /// Its wire speaks the friend family, or it has asked something of
    /// it, so it is told.
    pub(crate) messenger: bool,
    /// It understands message requests (§4.1), having said whether its
    /// account takes them or listed them this login, so it sends
    /// requests of its own, is told what becomes of them, and is shown
    /// what an approval carries and that requests changed.
    pub(crate) understands_requests: bool,
}

/// What friends are told of a login: its state and its text.
type Shown = (Presence, Option<String>);

/// A mailbox with sessions taking part.
pub(crate) struct Entry {
    mailbox: Mailbox,
    uids: Vec<Uid>,
    friends: HashSet<Key>,
    invisible: bool,
    status_text: Option<String>,
    /// What its friends were last told.
    told: Shown,
}

/// Every entry, and the announcements owed.
#[derive(Default)]
pub(crate) struct Presences {
    by: HashMap<Key, Entry>,
    owed: HashMap<Key, Instant>,
    debounce: Duration,
    wake: Arc<tokio::sync::Notify>,
}

fn session_presence(s: &UserSession) -> Presence {
    let state = s.messaging.as_ref().map_or(Presence::Online, |m| m.state);
    // A quiet or detached session is away, whatever it last said.
    if state == Presence::Online && s.info.status != SessionStatus::Active {
        Presence::Away
    } else {
        state
    }
}

impl RosterInner {
    fn shown(&self, e: &Entry) -> Shown {
        if e.invisible {
            return (Presence::Offline, None);
        }
        e.uids
            .iter()
            .filter_map(|u| self.users.get(u))
            .map(session_presence)
            .max_by_key(|p| p.rank())
            .map_or((Presence::Offline, None), |p| (p, e.status_text.clone()))
    }

    /// What `of`'s own sessions show of it now.
    fn presence_of(&self, of: &Mailbox) -> Shown {
        self.presences
            .by
            .get(&Key::of(of))
            .map_or((Presence::Offline, None), |e| self.shown(e))
    }

    /// What `of`'s friends were last told of it, which is what a friend
    /// reading it is shown too, so that a read never runs ahead of an
    /// announcement still owed: one that a change back within the
    /// debounce makes no change would leave the read uncorrected.
    fn told_of(&self, of: &Mailbox) -> Shown {
        self.presences
            .by
            .get(&Key::of(of))
            .map_or((Presence::Offline, None), |e| e.told.clone())
    }

    /// The sessions of a mailbox taking part.
    pub(crate) fn taking_part(&self, of: &Mailbox) -> Vec<Uid> {
        self.presences
            .by
            .get(&Key::of(of))
            .map_or_else(Vec::new, |e| e.uids.clone())
    }

    /// The messenger sessions of a mailbox.
    fn messengers(&self, of: &Key) -> Vec<Uid> {
        let Some(e) = self.presences.by.get(of) else {
            return Vec::new();
        };
        e.uids
            .iter()
            .copied()
            .filter(|u| self.users.get(u).is_some_and(is_messenger))
            .collect()
    }

    pub(crate) fn tell_mailbox(&mut self, of: &Mailbox, ev: Event) {
        for uid in self.messengers(&Key::of(of)) {
            self.send_to(uid, ev.clone());
        }
    }

    /// `of`'s presence has changed: told once its debounce window
    /// closes, or now with none.
    pub(crate) fn presence_soon(&mut self, of: &Key) {
        if self.presences.debounce.is_zero() {
            self.presence_tell(of);
            return;
        }
        if !self.presences.owed.contains_key(of) {
            let due = Instant::now() + self.presences.debounce;
            self.presences.owed.insert(of.clone(), due);
            self.presences.wake.notify_one();
        }
    }

    fn presence_tell(&mut self, of: &Key) {
        let Some(e) = self.presences.by.get(of) else {
            return;
        };
        let now = self.shown(e);
        if now != e.told {
            let (state, status_text) = now.clone();
            let ev = Event::Presence {
                login: e.mailbox.login.clone(),
                fingerprint: e.mailbox.fingerprint,
                state,
                status_text,
            };
            let to: Vec<Uid> = e.friends.iter().flat_map(|f| self.messengers(f)).collect();
            for uid in to {
                self.send_to(uid, ev.clone());
            }
        }
        let e = self.presences.by.get_mut(of).expect("read above");
        e.told = now;
        if e.uids.is_empty() {
            self.presences.by.remove(of);
        }
    }

    /// A session taking part has left the roster, or is about to.
    pub(crate) fn presence_leave(&mut self, uid: Uid, of: &Mailbox) {
        let key = Key::of(of);
        if let Some(e) = self.presences.by.get_mut(&key) {
            e.uids.retain(|u| *u != uid);
            self.presence_soon(&key);
        }
    }

    /// `a` and `b` are friends now, or no longer are.
    fn friends_changed(&mut self, a: &Mailbox, b: &Mailbox, friends: bool) {
        for (x, y) in [(a, b), (b, a)] {
            if let Some(e) = self.presences.by.get_mut(&Key::of(x)) {
                if friends {
                    e.friends.insert(Key::of(y));
                } else {
                    e.friends.remove(&Key::of(y));
                }
            }
        }
    }

    /// The roster row `owner` has about `other`, as it would list it:
    /// `asked` is the other's request to the owner, where one waits, and
    /// `text` a friend's stored status text.
    fn entry_of(
        &self,
        row: &Relationship,
        asked: Option<&PendingOut>,
        text: Option<String>,
    ) -> Option<FriendEntry> {
        let state = if row.blocked_at.is_some() {
            RosterState::Blocked
        } else if row.friendship.is_some() {
            RosterState::Accepted
        } else if row.pending_out.is_some() {
            RosterState::PendingOut
        } else if asked.is_some() {
            RosterState::PendingIn
        } else {
            return None;
        };
        let accepted = state == RosterState::Accepted;
        Some(FriendEntry {
            login: row.other.login.clone(),
            fingerprint: row.other.fingerprint,
            state,
            alias: row.alias.clone(),
            presence: if accepted {
                self.told_of(&row.other).0
            } else {
                Presence::Offline
            },
            status_text: text.filter(|_| accepted),
            note: asked
                .filter(|_| state == RosterState::PendingIn)
                .and_then(|p| p.note.clone()),
        })
    }
}

/// Is this a session taking part that is told of the friend family?
pub(crate) fn is_messenger(s: &UserSession) -> bool {
    s.messaging.as_ref().is_some_and(|m| m.messenger)
}

/// May an account with these bits and this login take part?
fn takes_part(login: &str, access: crate::AccessBits) -> bool {
    access.has(bit::MESSAGING) && !matches!(login, "admin" | "guest")
}

/// May this session take part, on a server where messaging is on?
pub(crate) fn session_takes_part(s: &UserSession) -> bool {
    s.is_person && takes_part(&s.login, s.access)
}

/// The caller, as a friend operation sees it.
struct Me {
    mailbox: Mailbox,
    /// Its session understands requests.
    understands: bool,
}

impl Core {
    /// Turn instant messaging on, under `policy`. It needs the
    /// relationship store and the accounts an inbox brings
    /// ([`Core::with_inbox`]).
    pub fn with_messaging(mut self, policy: MessagingPolicy) -> Self {
        self.messaging_policy = policy;
        self.roster.lock().unwrap().presences.debounce = policy.presence_debounce;
        self
    }

    pub fn messaging_enabled(&self) -> bool {
        self.messaging_policy.enabled && self.relationships.is_some() && self.directory.is_some()
    }

    fn friends_store(&self) -> Result<&Arc<dyn RelationshipStore>, MessagingError> {
        match self.relationships.as_ref() {
            Some(s) if self.messaging_enabled() => Ok(s),
            _ => Err(MessagingError::NotEnabled),
        }
    }

    /// The caller, marked a messenger session, if it takes part.
    fn messenger(&self, uid: Uid) -> Result<Me, MessagingError> {
        if !self.messaging_enabled() {
            return Err(MessagingError::NotEnabled);
        }
        let mut r = self.roster.lock().unwrap();
        let sess = r.users.get_mut(&uid).ok_or(MessagingError::NotEnabled)?;
        let state = sess.messaging.as_mut().ok_or(MessagingError::NotEnabled)?;
        state.messenger = true;
        Ok(Me {
            understands: state.understands_requests,
            mailbox: sess.mailbox(),
        })
    }

    /// The account `login` names, if it takes part.
    fn messaging_account(&self, login: &str) -> Result<Mailbox, MessagingError> {
        let directory = self
            .directory
            .as_ref()
            .ok_or(MessagingError::AccountNotFound)?;
        match directory.account(login) {
            Some((mailbox, access)) if takes_part(&mailbox.login, access) => Ok(mailbox),
            _ => Err(MessagingError::AccountNotFound),
        }
    }

    /// The account `login` names, as the caller may name it: not itself,
    /// and not one that has blocked it, which reads as no account at all
    /// (`docs/instant-messaging.md` §4.1, step 1).
    fn other(&self, me: &Me, login: &str) -> Result<Mailbox, MessagingError> {
        let them = self.messaging_account(login)?;
        if Key::of(&them) == Key::of(&me.mailbox)
            || self
                .friends_store()?
                .is_blocked(&them, &me.mailbox)
                .map_err(store_failed)?
        {
            return Err(MessagingError::AccountNotFound);
        }
        Ok(them)
    }

    fn friend_writes(&self) -> std::sync::MutexGuard<'_, ()> {
        self.friend_writes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `of`'s roster row about `other`, sent to `of`'s messenger
    /// sessions: what it is now, or that it is gone.
    fn tell_entry(&self, of: &Mailbox, other: &Mailbox) {
        let Ok(store) = self.friends_store() else {
            return;
        };
        let now = self.clock.wall();
        let row = store.relationship(of, other, now).ok().flatten();
        let asked = store
            .relationship(other, of, now)
            .ok()
            .flatten()
            .and_then(|t| t.pending_out)
            .filter(|p| p.delivered);
        let text = self.status_text(row.as_ref());
        let mut r = self.roster.lock().unwrap();
        let entry = row
            .and_then(|row| r.entry_of(&row, asked.as_ref(), text))
            .or_else(|| asked.map(|p| FriendEntry::asking(other, p.note)))
            .unwrap_or_else(|| FriendEntry::removed(other));
        r.tell_mailbox(of, Event::FriendEntry(Box::new(entry)));
    }

    /// A friend's stored status text, for its roster row.
    fn status_text(&self, row: Option<&Relationship>) -> Option<String> {
        let row = row.filter(|r| r.friendship.is_some())?;
        self.relationships
            .as_ref()?
            .account(&row.other)
            .ok()?
            .status_text
    }

    // --- Presence ------------------------------------------------------

    /// A session taking part is being announced: its mailbox's entry,
    /// loaded from the store if it has none yet. Called by `announce`
    /// before it takes the roster lock, and held until the entry is in.
    pub(crate) fn presence_load(&self, uid: Uid) -> Option<PresenceLoad<'_>> {
        if !self.messaging_enabled() {
            return None;
        }
        let mailbox = {
            let r = self.roster.lock().unwrap();
            let sess = r
                .users
                .get(&uid)
                .filter(|s| !s.visible && session_takes_part(s))?;
            sess.mailbox()
        };
        // Read whether or not the mailbox has an entry now: one in the
        // roster may be gone by the join, when its last session's
        // announcement is told, and the join would build it empty.
        let guard = self.friend_writes();
        let fresh = {
            let store = self.relationships.as_ref()?;
            let now = self.clock.wall();
            let friends = match store.relationships(&mailbox, now) {
                Ok(rows) => rows
                    .iter()
                    .filter(|r| r.friendship.is_some() && r.blocked_at.is_none())
                    .map(|r| Key::of(&r.other))
                    .collect(),
                Err(e) => {
                    warn!("relationships: loading {}'s friends: {e}", mailbox.login);
                    HashSet::new()
                }
            };
            let status_text = store
                .account(&mailbox)
                .map(|a| a.status_text)
                .unwrap_or_default();
            (friends, status_text)
        };
        Some(PresenceLoad {
            _guard: guard,
            mailbox,
            fresh,
        })
    }

    /// Set what the caller's presence, status text and settings say
    /// (Set Presence, 808).
    pub fn set_presence(&self, uid: Uid, update: PresenceUpdate) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let store = self.friends_store()?;
        // So two updates land in the store and in the entry in one order,
        // and an entry being loaded reads the text either before or after.
        let _writing = self.friend_writes();
        // Taking requests is an opt-in, by a session, that lapses
        // (`docs/instant-messaging.md` §4.1).
        let account = AccountUpdate {
            status_text: update.status_text.clone(),
            discoverable: update.discoverable,
            takes_requests: update
                .takes_requests
                .map(|on| on.then(|| self.clock.wall())),
            profile: None,
        };
        if account != AccountUpdate::default() {
            store
                .update_account(&me.mailbox, &account)
                .map_err(store_failed)?;
        }
        let mut r = self.roster.lock().unwrap();
        // Either answer says the session understands requests; only the
        // account's switch is turned off by a 0.
        if let (Some(_), Some(m)) = (
            update.takes_requests,
            r.users.get_mut(&uid).and_then(|s| s.messaging.as_mut()),
        ) {
            m.understands_requests = true;
        }
        let key = Key::of(&me.mailbox);
        match update.state {
            Some(Presence::Invisible) => {
                if let Some(e) = r.presences.by.get_mut(&key) {
                    e.invisible = true;
                }
            }
            Some(state @ (Presence::Online | Presence::Away | Presence::Busy)) => {
                if let Some(m) = r.users.get_mut(&uid).and_then(|s| s.messaging.as_mut()) {
                    m.state = state;
                }
                if let Some(e) = r.presences.by.get_mut(&key) {
                    e.invisible = false;
                }
            }
            Some(Presence::Offline) | None => {}
        }
        if let (Some(text), Some(e)) = (update.status_text, r.presences.by.get_mut(&key)) {
            e.status_text = text;
        }
        r.presence_soon(&key);
        Ok(())
    }

    /// Tell each login whose debounce window has closed what its friends
    /// should now see of it, and answer when the next one is due. The
    /// domain schedules nothing, so the binary runs this from a task
    /// woken by [`Core::presence_wake`] and by the deadline it returns.
    pub fn presence_flush(&self, now: Instant) -> Option<Instant> {
        let mut r = self.roster.lock().unwrap();
        let due: Vec<Key> = r
            .presences
            .owed
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in due {
            r.presences.owed.remove(&key);
            r.presence_tell(&key);
        }
        r.presences.owed.values().min().copied()
    }

    /// Notified when a login first owes an announcement.
    pub fn presence_wake(&self) -> Arc<tokio::sync::Notify> {
        self.roster.lock().unwrap().presences.wake.clone()
    }

    // --- The roster ----------------------------------------------------

    /// The caller's roster (Get Roster, 800): its friends with their
    /// presence, its blocks, the requests it sent and those waiting for
    /// it. An approval is no roster entry and is not listed.
    pub fn friends_roster(&self, uid: Uid) -> Result<Vec<FriendEntry>, MessagingError> {
        let me = self.messenger(uid)?;
        let store = self.friends_store()?;
        let now = self.clock.wall();
        let rows = store
            .relationships(&me.mailbox, now)
            .map_err(store_failed)?;
        let waiting = store.pending_in(&me.mailbox, now).map_err(store_failed)?;
        let texts: Vec<Option<String>> = rows.iter().map(|r| self.status_text(Some(r))).collect();
        let r = self.roster.lock().unwrap();
        let mut out: Vec<FriendEntry> = rows
            .iter()
            .zip(texts)
            .filter_map(|(row, text)| r.entry_of(row, None, text))
            .collect();
        let listed: HashSet<Key> = out
            .iter()
            .map(|e| {
                Key::of(&Mailbox {
                    login: e.login.clone(),
                    fingerprint: e.fingerprint,
                })
            })
            .collect();
        for theirs in waiting {
            if listed.contains(&Key::of(&theirs.owner)) {
                continue;
            }
            out.push(FriendEntry::asking(
                &theirs.owner,
                theirs.pending_out.and_then(|p| p.note),
            ));
        }
        drop(r);
        self.im_drain(uid, &me.mailbox);
        Ok(out)
    }

    /// Add Friend (802): ask `login` for friendship, or accept the
    /// request it already sent the caller (`docs/instant-messaging.md`
    /// §3). Answers `PendingOut` for a request, whether it was
    /// delivered, held or dropped (§4.4), and `Accepted` for a
    /// friendship.
    pub fn friend_add(
        &self,
        uid: Uid,
        login: &str,
        note: Option<String>,
    ) -> Result<RosterState, MessagingError> {
        let me = self.messenger(uid)?;
        let them = self.other(&me, login)?;
        let store = self.friends_store()?;
        let p = self.messaging_policy;
        if note.as_ref().is_some_and(|n| n.len() > p.max_message_bytes) {
            return Err(MessagingError::MessageTooLong);
        }
        let now = self.clock.wall();
        let _writing = self.friend_writes();
        // Again under the lock a block's cleanup takes, so a block made
        // since `other` looked is seen here or ends what this writes.
        if store.is_blocked(&them, &me.mailbox).map_err(store_failed)? {
            return Err(MessagingError::AccountNotFound);
        }
        if store.is_blocked(&me.mailbox, &them).map_err(store_failed)? {
            return Err(MessagingError::Blocked);
        }
        let mine = store
            .relationship(&me.mailbox, &them, now)
            .map_err(store_failed)?;
        if mine.as_ref().is_some_and(|m| m.friendship.is_some()) {
            return Err(MessagingError::AlreadyFriends);
        }
        if mine.as_ref().is_some_and(|m| m.pending_out.is_some()) {
            return Err(MessagingError::RequestPending);
        }
        let crossing = store
            .relationship(&them, &me.mailbox, now)
            .map_err(store_failed)?
            .is_some_and(|t| t.pending_out.is_some());
        // Two crossing requests accept each other only from a session
        // that understands requests; any other is answered as the extension
        // answers it. Either way, whether or not the first was
        // delivered, so the answer says nothing of whether it was held.
        if crossing && !me.understands {
            return Err(MessagingError::RequestPending);
        }
        if store.roster_size(&me.mailbox, now).map_err(store_failed)? >= p.max_roster {
            return Err(MessagingError::RosterFull);
        }
        if crossing {
            self.befriend(store, &me.mailbox, &them, now)?;
            return Ok(RosterState::Accepted);
        }

        let addr = self.request_address(uid);
        let sender = Requester::Account(me.mailbox.clone());
        self.request_bounds(store, &sender, addr.as_deref(), &them, now)?;
        let bytes = note.as_ref().map_or(0, |n| n.len() as u64);
        store
            .record_request(&LedgerEntry {
                kind: RequestKind::Friend,
                sender: Some(me.mailbox.clone()),
                address: addr,
                recipient: them.clone(),
                guid: None,
                bytes,
                at: now,
            })
            .map_err(store_failed)?;
        let held = store.is_held(&them, &sender, now).map_err(store_failed)?;
        let full = !held
            && store.pending_in(&them, now).map_err(store_failed)?.len() >= p.max_friend_requests;
        if full {
            store.request_dropped(&them).map_err(store_failed)?;
        }
        let delivered = !held && !full;
        store
            .set_pending_out(
                &me.mailbox,
                &them,
                Some(&PendingOut {
                    sent_at: now,
                    lapses_at: now + p.request_retention,
                    delivered,
                    note: note.clone(),
                }),
            )
            .map_err(store_failed)?;
        self.tell_entry(&me.mailbox, &them);
        if delivered {
            let mut r = self.roster.lock().unwrap();
            r.tell_mailbox(
                &them,
                Event::FriendRequest {
                    login: me.mailbox.login.clone(),
                    fingerprint: me.mailbox.fingerprint,
                    note,
                },
            );
        }
        Ok(RosterState::PendingOut)
    }

    /// Friend Response (805): accept or decline the request `login`
    /// sent the caller. A decline holds its sender (§4.4).
    pub fn friend_respond(
        &self,
        uid: Uid,
        login: &str,
        accept: bool,
    ) -> Result<RosterState, MessagingError> {
        let me = self.messenger(uid)?;
        let them = self.other(&me, login)?;
        let store = self.friends_store()?;
        let now = self.clock.wall();
        let _writing = self.friend_writes();
        let asked = store
            .relationship(&them, &me.mailbox, now)
            .map_err(store_failed)?
            .and_then(|t| t.pending_out)
            .is_some_and(|p| p.delivered);
        if !asked {
            return Err(MessagingError::NotFriends);
        }
        if !accept {
            self.decline(store, &me.mailbox, &them, now)?;
            return Ok(RosterState::Removed);
        }
        // A request waiting takes no place, so accepting one at the cap
        // is refused and leaves it as it was.
        if store.roster_size(&me.mailbox, now).map_err(store_failed)?
            >= self.messaging_policy.max_roster
        {
            return Err(MessagingError::RosterFull);
        }
        self.befriend(store, &me.mailbox, &them, now)?;
        Ok(RosterState::Accepted)
    }

    /// Remove Friend (803): end a friendship, which is mutual, withdraw
    /// a request the caller sent, or decline one it was sent. Removing a
    /// friend holds them, as declining does (§4.4).
    pub fn friend_remove(&self, uid: Uid, login: &str) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let them = self.other(&me, login)?;
        let store = self.friends_store()?;
        let now = self.clock.wall();
        let p = self.messaging_policy;
        let _writing = self.friend_writes();
        let mine = store
            .relationship(&me.mailbox, &them, now)
            .map_err(store_failed)?;
        if mine.as_ref().is_some_and(|m| m.friendship.is_some()) {
            store.unfriend(&me.mailbox, &them).map_err(store_failed)?;
            store
                .hold(
                    &me.mailbox,
                    &Requester::Account(them.clone()),
                    now + p.request_retention,
                )
                .map_err(store_failed)?;
            self.roster
                .lock()
                .unwrap()
                .friends_changed(&me.mailbox, &them, false);
            self.tell_entry(&me.mailbox, &them);
            self.tell_entry(&them, &me.mailbox);
            return Ok(());
        }
        if let Some(sent) = mine.and_then(|m| m.pending_out) {
            store
                .set_pending_out(&me.mailbox, &them, None)
                .map_err(store_failed)?;
            self.tell_entry(&me.mailbox, &them);
            if sent.delivered {
                self.tell_entry(&them, &me.mailbox);
            }
            return Ok(());
        }
        let asked = store
            .relationship(&them, &me.mailbox, now)
            .map_err(store_failed)?
            .and_then(|t| t.pending_out)
            .is_some_and(|p| p.delivered);
        if asked {
            return self.decline(store, &me.mailbox, &them, now);
        }
        Err(MessagingError::NotFriends)
    }

    /// Set or clear the caller's alias for a friend.
    pub fn friend_alias(
        &self,
        uid: Uid,
        login: &str,
        alias: Option<&str>,
    ) -> Result<(), MessagingError> {
        let me = self.messenger(uid)?;
        let them = self.other(&me, login)?;
        let store = self.friends_store()?;
        let _writing = self.friend_writes();
        let friends = store
            .relationship(&me.mailbox, &them, self.clock.wall())
            .map_err(store_failed)?
            .is_some_and(|r| r.friendship.is_some() && r.blocked_at.is_none());
        if !friends {
            return Err(MessagingError::NotFriends);
        }
        store
            .set_alias(&me.mailbox, &them, alias)
            .map_err(store_failed)?;
        self.tell_entry(&me.mailbox, &them);
        Ok(())
    }

    fn befriend(
        &self,
        store: &Arc<dyn RelationshipStore>,
        a: &Mailbox,
        b: &Mailbox,
        now: SystemTime,
    ) -> Result<RelationId, MessagingError> {
        let mut approvals = Vec::new();
        for (x, y) in [(a, b), (b, a)] {
            if let Some(id) = store
                .relationship(x, y, now)
                .map_err(store_failed)?
                .and_then(|r| r.approval)
            {
                approvals.push(id);
            }
        }
        let id = store.befriend(a, b, now).map_err(store_failed)?;
        self.roster.lock().unwrap().friends_changed(a, b, true);
        self.tell_entry(a, b);
        self.tell_entry(b, a);
        self.friendship_releases(a, b, id, &approvals);
        Ok(id)
    }

    /// `me` declines `them`'s friend request: both told it is gone, and
    /// `them` held.
    fn decline(
        &self,
        store: &Arc<dyn RelationshipStore>,
        me: &Mailbox,
        them: &Mailbox,
        now: SystemTime,
    ) -> Result<(), MessagingError> {
        store
            .set_pending_out(them, me, None)
            .map_err(store_failed)?;
        store
            .hold(
                me,
                &Requester::Account(them.clone()),
                now + self.messaging_policy.request_retention,
            )
            .map_err(store_failed)?;
        self.tell_entry(me, them);
        self.tell_entry(them, me);
        Ok(())
    }

    /// The opaque key of the address `uid` connected from, where the
    /// per-address bound applies to it.
    fn request_address(&self, uid: Uid) -> Option<String> {
        let addr = self.roster.lock().unwrap().users.get(&uid)?.addr?;
        if self.conn_gate.exempt(addr) {
            return None;
        }
        Some(self.news_guest_keyer.key(addr).to_hex())
    }

    /// The per-sender and per-address bounds a new request is held to,
    /// counting what was sent whatever became of it (§4.4). A recipient
    /// already requested today is not a new one.
    fn request_bounds(
        &self,
        store: &Arc<dyn RelationshipStore>,
        sender: &Requester,
        addr: Option<&str>,
        to: &Mailbox,
        now: SystemTime,
    ) -> Result<(), MessagingError> {
        let p = self.messaging_policy;
        let day = now
            .checked_sub(Duration::from_secs(24 * 3600))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let again = [RequestKind::Message, RequestKind::Friend]
            .into_iter()
            .map(|kind| store.requests_to(sender, to, kind, day))
            .try_fold(0, |n, c| c.map(|c| n + c))
            .map_err(store_failed)?
            > 0;
        if again {
            return Ok(());
        }
        if store.recipients_since(sender, day).map_err(store_failed)? >= p.requests_per_day {
            return Err(MessagingError::RateLimited);
        }
        if let Some(addr) = addr {
            if store
                .recipients_from_address(addr, day)
                .map_err(store_failed)?
                >= p.requests_per_address
            {
                return Err(MessagingError::RateLimited);
            }
        }
        Ok(())
    }

    // --- Blocks --------------------------------------------------------

    /// `blocker` has blocked `blocked`, or unblocked it: what a block
    /// ends, ended, and each party told as the extension tells it. The
    /// blocked party hears only that the row is gone, never of the
    /// block. Called with the block already written.
    pub(crate) fn block_changed(&self, blocker: &Mailbox, blocked: &Mailbox, now_blocked: bool) {
        let Ok(store) = self.friends_store() else {
            return;
        };
        let _writing = self.friend_writes();
        if now_blocked {
            let ended = |r: Result<Option<RelationId>, StoreError>| match r {
                Ok(id) => id.is_some(),
                Err(e) => {
                    warn!("relationships: ending what a block ends: {e}");
                    false
                }
            };
            // Whether the blocked had a row to see go: only then is it
            // told, so a block on a stranger tells it nothing.
            let shown = store
                .relationship(blocker, blocked, self.clock.wall())
                .ok()
                .flatten()
                .and_then(|r| r.pending_out)
                .is_some_and(|p| p.delivered);
            let unfriended = ended(store.unfriend(blocker, blocked));
            if unfriended {
                self.roster
                    .lock()
                    .unwrap()
                    .friends_changed(blocker, blocked, false);
            }
            // An approval ends silently: it is never in 800 or 801 (§4.6).
            ended(store.end_approval(blocker, blocked));
            ended(store.end_approval(blocked, blocker));
            for (a, b) in [(blocker, blocked), (blocked, blocker)] {
                if let Err(e) = store.set_pending_out(a, b, None) {
                    warn!("relationships: ending a request a block ends: {e}");
                }
            }
            if unfriended || shown {
                self.tell_entry(blocked, blocker);
            }
            self.block_deletes_requests(blocker, blocked);
        }
        self.tell_entry(blocker, blocked);
    }

    /// The fold a claim or a rotation made can leave a block beside a
    /// live friendship or approval, or a request beside a friendship:
    /// end each, and tell both parties, as the act that would have ended
    /// it would have (`docs/instant-messaging.md` §6).
    pub(crate) fn after_merge(&self, me: &Mailbox) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        let now = self.clock.wall();
        let _writing = self.friend_writes();
        let rows = match store.relationships(me, now) {
            Ok(rows) => rows,
            Err(e) => {
                warn!("relationships: reading {}'s after a merge: {e}", me.login);
                return;
            }
        };
        let mut told = Vec::new();
        for mine in rows {
            let other = mine.other.clone();
            let theirs = store.relationship(&other, me, now).ok().flatten();
            // A rotation the directory has no account for names the
            // successor by its key alone; the friend's row has the login
            // it is known by.
            let me = &Mailbox {
                login: theirs
                    .as_ref()
                    .map_or_else(|| me.login.clone(), |t| t.other.login.clone()),
                fingerprint: me.fingerprint,
            };
            let blocked = mine.blocked_at.is_some()
                || theirs.as_ref().is_some_and(|t| t.blocked_at.is_some());
            let mut changed = false;
            let mut fix = |r: Result<(), StoreError>| {
                if let Err(e) = r {
                    warn!("relationships: settling a merge: {e}");
                }
                changed = true;
            };
            if blocked && mine.friendship.is_some() {
                fix(store.unfriend(me, &other).map(|_| ()));
                self.roster
                    .lock()
                    .unwrap()
                    .friends_changed(me, &other, false);
            }
            if blocked && mine.approval.is_some() {
                fix(store.end_approval(me, &other).map(|_| ()));
            }
            if blocked && theirs.as_ref().is_some_and(|t| t.approval.is_some()) {
                fix(store.end_approval(&other, me).map(|_| ()));
            }
            let friends = mine.friendship.is_some() && !blocked;
            if (friends || blocked) && mine.pending_out.is_some() {
                fix(store.set_pending_out(me, &other, None));
            }
            if (friends || blocked) && theirs.as_ref().is_some_and(|t| t.pending_out.is_some()) {
                fix(store.set_pending_out(&other, me, None));
            }
            if changed {
                told.push((me.clone(), other));
            }
        }
        for (me, other) in told {
            self.tell_entry(&me, &other);
            // With no row of the friend's to give the login a rotation's
            // successor is known by, there is no entry to name.
            if !me.login.is_empty() {
                self.tell_entry(&other, &me);
            }
        }
    }

    /// Everything a claim or a rotation re-keyed from `from` to `to` is
    /// known by `to` in the roster's friend sets too.
    pub(crate) fn rekey_friends(&self, from: &Mailbox, to: &Mailbox) {
        let (from, to) = (Key::of(from), Key::of(to));
        let _writing = self.friend_writes();
        let mut r = self.roster.lock().unwrap();
        for e in r.presences.by.values_mut() {
            if e.friends.remove(&from) {
                e.friends.insert(to.clone());
            }
        }
    }

    /// Purge `of`'s relationships, telling everyone it had a friendship
    /// or a request with that its row is gone.
    pub(crate) fn purge_relationships(&self, of: &Mailbox) {
        let Some(store) = self.relationships.as_ref() else {
            return;
        };
        let now = self.clock.wall();
        let _writing = self.friend_writes();
        let mut audience: Vec<Mailbox> = store
            .relationships(of, now)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                r.friendship.is_some() || r.pending_out.as_ref().is_some_and(|p| p.delivered)
            })
            .map(|r| r.other)
            .collect();
        audience.extend(
            store
                .pending_in(of, now)
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.owner),
        );
        if let Err(e) = store.purge(of) {
            warn!("relationships: purging {}: {e}", of.login);
            return;
        }
        let mut r = self.roster.lock().unwrap();
        for other in &audience {
            r.friends_changed(of, other, false);
            r.tell_mailbox(
                other,
                Event::FriendEntry(Box::new(FriendEntry::removed(of))),
            );
        }
    }

    // --- Discovery -----------------------------------------------------

    /// Find User (822): the account `login` names, as the caller may see
    /// it. Presence for a friend alone.
    pub fn find_user(&self, uid: Uid, login: &str) -> Result<FoundUser, MessagingError> {
        self.found(uid, login, false)
    }

    /// Get User Info (825): the same, with the whole profile for a
    /// friend or the account itself.
    pub fn messaging_user_info(&self, uid: Uid, login: &str) -> Result<FoundUser, MessagingError> {
        self.found(uid, login, true)
    }

    fn found(&self, uid: Uid, login: &str, profile: bool) -> Result<FoundUser, MessagingError> {
        let me = self.messenger(uid)?;
        let store = self.friends_store()?;
        let them = if Key::of(&self.messaging_account(login)?) == Key::of(&me.mailbox) {
            me.mailbox.clone()
        } else {
            self.other(&me, login)?
        };
        let now = self.clock.wall();
        let shown = Key::of(&them) == Key::of(&me.mailbox)
            || store
                .relationship(&me.mailbox, &them, now)
                .map_err(store_failed)?
                .is_some_and(|r| r.friendship.is_some() && r.blocked_at.is_none());
        let account = store.account(&them).map_err(store_failed)?;
        let name = account
            .profile
            .nickname
            .clone()
            .unwrap_or_else(|| them.login.clone());
        let presence = shown.then(|| {
            let r = self.roster.lock().unwrap();
            if Key::of(&them) == Key::of(&me.mailbox) {
                r.presence_of(&them)
            } else {
                r.told_of(&them)
            }
        });
        Ok(FoundUser {
            login: them.login,
            name,
            presence,
            profile: (shown && profile).then_some(account.profile),
        })
    }
}

/// A mailbox's entry being loaded at its session's announce, holding
/// `Core::friend_writes` until it is in.
pub(crate) struct PresenceLoad<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
    mailbox: Mailbox,
    /// The friends and status text read, for an entry made by the join.
    fresh: (HashSet<Key>, Option<String>),
}

impl RosterInner {
    /// `uid` is announced, taking part: in its mailbox's entry, and its
    /// friends told.
    pub(crate) fn presence_join(&mut self, uid: Uid, load: PresenceLoad<'_>) {
        let key = Key::of(&load.mailbox);
        if let Some(sess) = self.users.get_mut(&uid) {
            sess.messaging = Some(SessionState {
                messenger: sess.info.transport.messaging,
                ..SessionState::default()
            });
        }
        let (friends, status_text) = load.fresh;
        let e = match self.presences.by.entry(key.clone()) {
            std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => v.insert(Entry {
                mailbox: load.mailbox.clone(),
                uids: Vec::new(),
                friends,
                invisible: false,
                status_text,
                told: (Presence::Offline, None),
            }),
        };
        // A new session starts online, whatever another said before,
        // so signing on is announced.
        if !e.uids.contains(&uid) {
            e.uids.push(uid);
            e.invisible = false;
        }
        self.presence_soon(&key);
    }
}
