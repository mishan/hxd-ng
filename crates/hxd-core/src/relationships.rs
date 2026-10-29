//! The relationship store (`docs/instant-messaging.md` §3): blocks,
//! friendships, approvals, pending friend requests, ignores, the holds
//! and the ledger of message requests (§4.4), and what each account keeps
//! about itself for messaging (its status text, its profile and whether
//! it may be found or written to by strangers).
//!
//! **A row is directed**: one per `(owner, other)` pair, each keyed as the
//! inbox keys a mailbox ([`Mailbox`]), by fingerprint where the account
//! has an identity and by login otherwise, matched strictly, so what an
//! identified account decided survives its rename and is inherited by
//! nobody who takes its old login. A row holds what its owner decided
//! about the other, each part on its own, and the store never infers one
//! part from another: a block does not end a friendship here, because the
//! domain must tell the parties what ended, and it is the domain that
//! knows who to tell.
//!
//! **A friendship is a fact about the pair**, an id both rows point to;
//! an approval is an id on its approver's row alone. The two share one
//! sequence and an id is never reused, so a message queued on a
//! friendship that has since ended and been made again does not belong
//! to the new one (§5).
//!
//! **Lapsing is the reader's.** What lapses is stored with when, and every
//! read takes the time and answers as if a lapsed part were gone; the
//! cleanup reclaims it later, and changes no answer by doing so (§3).
//! Every time is kept and compared to the second, as SQLite keeps it.
//!
//! Synchronous, for the reason [`crate::inbox`] gives.

use std::time::SystemTime;

use crate::inbox::{Mailbox, MessageGuid, Sent, StoreError};

pub mod conformance;
pub mod memory;

pub use memory::MemoryRelationships;

/// A friendship's or an approval's id: never reused, so a queued message
/// that carries one belongs to that friendship and to no later one.
pub type RelationId = u64;

/// What an inbox row was sent on (the inbox's friendship column): a
/// friendship or an approval, by its id, or a message request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentOn {
    Request,
    Relation(RelationId),
}

impl SentOn {
    pub fn as_i64(self) -> i64 {
        match self {
            SentOn::Request => 0,
            SentOn::Relation(id) => i64::try_from(id).unwrap_or(i64::MAX),
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        match n {
            0 => Some(SentOn::Request),
            n if n > 0 => Some(SentOn::Relation(n as RelationId)),
            _ => None,
        }
    }
}

/// What an ignore hides (§10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreMode {
    Messages,
    Presence,
    Chat,
    All,
}

impl IgnoreMode {
    pub fn as_i64(self) -> i64 {
        match self {
            IgnoreMode::Messages => 1,
            IgnoreMode::Presence => 2,
            IgnoreMode::Chat => 3,
            IgnoreMode::All => 4,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        match n {
            1 => Some(IgnoreMode::Messages),
            2 => Some(IgnoreMode::Presence),
            3 => Some(IgnoreMode::Chat),
            4 => Some(IgnoreMode::All),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignore {
    pub mode: IgnoreMode,
    /// When it lapses; `None` keeps it until it is lifted.
    pub until: Option<SystemTime>,
}

/// A friend request the owner sent and the other has not answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOut {
    pub sent_at: SystemTime,
    pub lapses_at: SystemTime,
    /// Whether the other was told of it. A held or dropped sender's
    /// request is pending out all the same, and its target never sees it
    /// (§4.4).
    pub delivered: bool,
    /// `DATA_REQUEST_NOTE`, kept for a delivery at the target's next
    /// login.
    pub note: Option<String>,
}

/// What `owner` has decided about `other`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    pub owner: Mailbox,
    pub other: Mailbox,
    /// `DATA_FRIEND_NICKNAME`: kept only beside a friendship or a block.
    pub alias: Option<String>,
    pub blocked_at: Option<SystemTime>,
    pub friendship: Option<RelationId>,
    /// The owner's approval of the other's messages (§4.6).
    pub approval: Option<RelationId>,
    pub pending_out: Option<PendingOut>,
    pub ignore: Option<Ignore>,
}

impl Relationship {
    /// A row about `other` with nothing decided yet.
    pub fn new(owner: &Mailbox, other: &Mailbox) -> Self {
        Relationship {
            owner: owner.clone(),
            other: other.clone(),
            alias: None,
            blocked_at: None,
            friendship: None,
            approval: None,
            pending_out: None,
            ignore: None,
        }
    }

    /// The row as it reads at `now`: a lapsed request or ignore gone, and
    /// `None` where nothing is left. The one lapsing rule, here so the
    /// two stores cannot disagree about it.
    pub fn as_of(mut self, now: SystemTime) -> Option<Self> {
        if self
            .pending_out
            .as_ref()
            .is_some_and(|p| p.lapses_at <= now)
        {
            self.pending_out = None;
        }
        if self
            .ignore
            .as_ref()
            .is_some_and(|i| i.until.is_some_and(|u| u <= now))
        {
            self.ignore = None;
        }
        self.settle();
        (!self.is_empty()).then_some(self)
    }

    /// An alias outlives neither the friendship nor the block it was
    /// kept for.
    pub fn settle(&mut self) {
        if self.friendship.is_none() && self.blocked_at.is_none() {
            self.alias = None;
        }
    }

    /// Nothing decided, so nothing to keep.
    pub fn is_empty(&self) -> bool {
        self.blocked_at.is_none()
            && self.friendship.is_none()
            && self.approval.is_none()
            && self.pending_out.is_none()
            && self.ignore.is_none()
    }

    /// Fold in a row a claim or a rotation has made a duplicate of this
    /// one: the same pair, reached under two keys. Each part is this
    /// row's where it has one, as the inbox keeps the row already at the
    /// destination, and the duplicate's otherwise; a block is the older
    /// of the two. Returns each id of the duplicate's that lost to this
    /// row's, beside the id that kept its place, so the messages sent on
    /// the lost one can be re-stamped.
    ///
    /// The parts are folded without judging them, so the result can hold
    /// what no single act makes: a block beside a live friendship, or a
    /// request or an approval beside one. Ending what that leaves, and
    /// telling the parties, is the domain's.
    pub fn absorb(&mut self, dup: Relationship) -> Vec<(RelationId, RelationId)> {
        let mut lost = Vec::new();
        for (mine, theirs) in [
            (&mut self.friendship, dup.friendship),
            (&mut self.approval, dup.approval),
        ] {
            match (*mine, theirs) {
                (None, t) => *mine = t,
                (Some(m), Some(t)) if m != t => lost.push((t, m)),
                _ => {}
            }
        }
        self.blocked_at = match (self.blocked_at, dup.blocked_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.alias = self.alias.take().or(dup.alias);
        self.pending_out = self.pending_out.take().or(dup.pending_out);
        self.ignore = self.ignore.take().or(dup.ignore);
        self.settle();
        lost
    }
}

/// What [`RelationshipStore::claim`] or [`RelationshipStore::rotate`]
/// did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rekeyed {
    /// Rows whose key changed.
    pub moved: usize,
    /// `(lost, kept)`: a friendship or approval id that a merge ended,
    /// and the one of the same pair that stands in its place, once each,
    /// in order.
    pub merged: Vec<(RelationId, RelationId)>,
}

/// Who sent a request, as its bounds and holds count it: an account by
/// its mailbox, or a guest by its address, since guests share one
/// account and reconnecting must earn a guest nothing (§4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requester {
    Account(Mailbox),
    /// The opaque key the domain derives from the address, never the
    /// address itself.
    Address(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// A message request (§4).
    Message,
    /// A friend request (802).
    Friend,
}

impl RequestKind {
    pub fn as_i64(self) -> i64 {
        match self {
            RequestKind::Message => 1,
            RequestKind::Friend => 2,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        match n {
            1 => Some(RequestKind::Message),
            2 => Some(RequestKind::Friend),
            _ => None,
        }
    }
}

/// What a sender sent, whatever became of it (§4.4): every bound counts
/// these, so what the recipient did never changes what the sender is
/// told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub kind: RequestKind,
    /// `None` for a guest, which is counted by `address`.
    pub sender: Option<Mailbox>,
    /// The opaque key of the address the request arrived from, where the
    /// per-address bound applies to it.
    pub address: Option<String>,
    pub recipient: Mailbox,
    pub guid: Option<MessageGuid>,
    pub bytes: u64,
    pub at: SystemTime,
}

/// What [`RelationshipStore::record_request`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    New,
    /// The sender already sent this recipient this guid: the original,
    /// which a retry is answered from and not counted again.
    Retry(Box<LedgerEntry>),
}

/// A date of birth whose parts are each optional: 0 is "not given".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Birthdate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

/// The extension's profile (Set User Info, 826). Stored as given: what
/// is bounded, truncated or normalized is the domain's to decide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub nickname: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub gender: u16,
    pub birthdate: Birthdate,
    pub country: Option<String>,
    pub postcode: Option<String>,
    /// At most [`MAX_LANGUAGES`]; a store keeps the first of a longer
    /// list.
    pub languages: Vec<String>,
}

pub const MAX_LANGUAGES: usize = 3;

/// What an account keeps about itself for messaging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagingAccount {
    pub status_text: Option<String>,
    /// Found by User Search (823). Off until the account turns it on.
    pub discoverable: bool,
    /// The profile's switch for message requests (§4.1). On by default:
    /// an account takes requests only once a client of it has listed them
    /// as well, which `requests_listed_at` says.
    pub takes_requests: bool,
    pub requests_listed_at: Option<SystemTime>,
    pub profile: Profile,
}

impl Default for MessagingAccount {
    fn default() -> Self {
        MessagingAccount {
            status_text: None,
            discoverable: false,
            takes_requests: true,
            requests_listed_at: None,
            profile: Profile::default(),
        }
    }
}

/// A change to a [`MessagingAccount`]: each `None` leaves its part as it
/// was, since the classic wire sets the status and `takes_requests` in
/// 808 and the profile in the whole-profile 826.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountUpdate {
    /// `Some(None)` clears the text.
    pub status_text: Option<Option<String>>,
    pub discoverable: Option<bool>,
    pub takes_requests: Option<bool>,
    pub profile: Option<Profile>,
}

/// The relationship store, behind a trait as the inbox is, so the
/// in-memory store can carry the domain's tests and SQLite's the server.
pub trait RelationshipStore: Send + Sync + 'static {
    // --- Rows --------------------------------------------------------------

    /// What `owner` has decided about `other`, as it reads at `now`.
    fn relationship(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        now: SystemTime,
    ) -> Result<Option<Relationship>, StoreError>;

    /// Every row `owner` has, oldest first.
    fn relationships(
        &self,
        owner: &Mailbox,
        now: SystemTime,
    ) -> Result<Vec<Relationship>, StoreError>;

    /// The friend requests waiting for `owner`: others' rows whose
    /// pending out names it and was delivered, oldest request first. The
    /// extension's `PendingIn`.
    fn pending_in(&self, owner: &Mailbox, now: SystemTime)
        -> Result<Vec<Relationship>, StoreError>;

    /// What counts toward `owner`'s `MaxRosterSize`: each of its rows that
    /// holds anything, a friendship, a block, an approval, a request it
    /// sent or an ignore, once. Requests others sent it do not count.
    fn roster_size(&self, owner: &Mailbox, now: SystemTime) -> Result<usize, StoreError>;

    /// Set or clear the alias. One is kept only beside a friendship or a
    /// block, and setting one on a row with neither keeps nothing.
    fn set_alias(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        alias: Option<&str>,
    ) -> Result<(), StoreError>;

    /// Block or unblock. Idempotent both ways; blocking again keeps the
    /// first block's time.
    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError>;

    /// Has `owner` blocked `other`?
    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError>;

    /// Who `owner` has blocked, oldest block first.
    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError>;

    /// Set or clear `owner`'s friend request to `other`.
    fn set_pending_out(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        pending: Option<&PendingOut>,
    ) -> Result<(), StoreError>;

    /// Set, replace or lift an ignore.
    fn set_ignore(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        ignore: Option<&Ignore>,
    ) -> Result<(), StoreError>;

    // --- Friendships and approvals ---------------------------------------

    /// Make `a` and `b` friends, answering each one's request and ending
    /// each one's approval of the other (§4.6), and return the
    /// friendship's id; one they already share is returned as it is.
    fn befriend(&self, a: &Mailbox, b: &Mailbox, at: SystemTime) -> Result<RelationId, StoreError>;

    /// End the friendship between `a` and `b`, returning its id if there
    /// was one. Its id is never given out again.
    fn unfriend(&self, a: &Mailbox, b: &Mailbox) -> Result<Option<RelationId>, StoreError>;

    /// `owner` approves `other`'s messages; an approval it already holds is
    /// returned as it is.
    fn approve(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        at: SystemTime,
    ) -> Result<RelationId, StoreError>;

    /// End `owner`'s approval of `other`, returning its id if there was
    /// one.
    fn end_approval(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
    ) -> Result<Option<RelationId>, StoreError>;

    // --- Requests (§4.4) ---------------------------------------------------

    /// Hold `held`'s requests to `owner` until `until`. Recorded under
    /// both keys of each mailbox, its login and its fingerprint, and
    /// matched by either, so linking or unlinking an identity on either
    /// side does not shed it. A purge of a bare login takes that login
    /// off the holds that carry a fingerprint too, so a rename's purge
    /// leaves them to the identity alone.
    fn hold(&self, owner: &Mailbox, held: &Requester, until: SystemTime) -> Result<(), StoreError>;

    /// Is `sender` held from `owner` at `now`?
    fn is_held(
        &self,
        owner: &Mailbox,
        sender: &Requester,
        now: SystemTime,
    ) -> Result<bool, StoreError>;

    /// Write a request into the ledger, unless its sender already sent
    /// its recipient its guid: then nothing is written, and the original
    /// is returned. The two are one step for the reason
    /// [`crate::inbox::MessageStore::push`] gives.
    fn record_request(&self, entry: &LedgerEntry) -> Result<Recorded, StoreError>;

    /// How many requests of `kind` `from` has sent `to` since `since`.
    fn requests_to(
        &self,
        from: &Requester,
        to: &Mailbox,
        kind: RequestKind,
        since: SystemTime,
    ) -> Result<usize, StoreError>;

    /// How many distinct recipients `from` has sent requests of either
    /// kind since `since`.
    fn recipients_since(&self, from: &Requester, since: SystemTime) -> Result<usize, StoreError>;

    /// How many distinct recipients have been sent requests from
    /// `address` since `since`, whoever sent them.
    fn recipients_from_address(
        &self,
        address: &str,
        since: SystemTime,
    ) -> Result<usize, StoreError>;

    /// What `from` has sent as message requests since `since`, which the
    /// inbox's daily quota counts beside its stored mail.
    fn requested_since(&self, from: &Requester, since: SystemTime) -> Result<Sent, StoreError>;

    /// A request to `owner` was dropped (§4.4).
    fn request_dropped(&self, owner: &Mailbox) -> Result<(), StoreError>;

    /// A client of `owner` has listed its requests: stamp when, and
    /// return how many were dropped since the listing before.
    fn requests_listed(&self, owner: &Mailbox, at: SystemTime) -> Result<u64, StoreError>;

    // --- The account -------------------------------------------------------

    /// What `of` keeps about itself; the defaults where it has kept
    /// nothing.
    fn account(&self, of: &Mailbox) -> Result<MessagingAccount, StoreError>;

    fn update_account(&self, of: &Mailbox, update: &AccountUpdate) -> Result<(), StoreError>;

    // --- Lifecycle (§6) ----------------------------------------------------

    /// An account linked an identity: stamp everything keyed by its bare
    /// login with the fingerprint, its rows and the rows naming it, its
    /// holds and its ledger, so it follows the identity. Two rows for one
    /// pair become one ([`Relationship::absorb`]), and an account's own
    /// record already on the fingerprint is the one kept. Idempotent.
    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<Rekeyed, StoreError>;

    /// The identity rotated to a successor key: re-stamp everything keyed
    /// by `from` with `to`, merging as `claim` does.
    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Rekeyed, StoreError>;

    /// An account was deleted: its rows and the rows naming it, the
    /// friendships and approvals on them, the holds it placed or is held
    /// by, its ledger either way and its own record. Returns how many
    /// rows went. Holds are the purged mailbox's where they carry its
    /// fingerprint, or its login and no fingerprint; its login is taken
    /// off the rest ([`RelationshipStore::hold`]).
    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError>;

    /// How many rows [`RelationshipStore::purge`] would delete.
    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError>;

    /// Reclaim at most `batch` of each kind of row: what lapsed before
    /// `lapsed_before`, and ledger entries from before `ledger_before`.
    /// Changes no answer, since a lapsed part already reads as gone.
    /// Returns how many rows changed, so a caller can go on until none
    /// do.
    fn cleanup(
        &self,
        lapsed_before: SystemTime,
        ledger_before: SystemTime,
        batch: usize,
    ) -> Result<usize, StoreError>;
}
