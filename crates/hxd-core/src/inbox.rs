//! The durable private-message inbox.
//!
//! Designed in `docs/private-messages.md`. The short version: a private
//! message to an account that has an inbox is persisted *before* the
//! sender is acked, and live delivery is a state change on the stored row
//! (`delivered_at`) rather than an alternative to storing it. That is what
//! makes a message handed to a socket dying in the same instant
//! recoverable, and it is what gives read state somewhere to live.
//!
//! **A mailbox belongs to an identity, and falls back to a login.** uids
//! are the 16-bit legacy ids and they recycle within minutes; a login
//! recycles too, just slowly — rename an account and the old name is free
//! for someone else. Either way, mail addressed to a name that has changed
//! hands is a stranger's private message delivered to the wrong person,
//! which is the worst bug this subsystem can have. So the durable key is
//! the identity fingerprint where there is one, exactly as fogWraith's
//! messaging-identity amendment makes it the durable roster row key, and
//! the login only where there is not. See [`Mailbox`].
//!
//! **The trait is synchronous**, like [`crate::AuthBackend`] and for the
//! same reason: `Core` is sync all the way down, so one async store call
//! would make the whole domain async — a change with nothing to do with
//! messaging. When a database backend lands (the persistence phase) this
//! trait goes async as part of that work.
//!
//! **Wall clock, not `Instant`.** The roster measures with `Instant`
//! because it only ever asks "how long since"; a stored message needs a
//! time it can show a human next week. The two are not interchangeable.

use std::time::{Duration, SystemTime};

pub mod conformance;
pub mod memory;

pub use memory::MemoryStore;

/// A stored message's identity and its ordering: monotonic per store,
/// which is also what makes it a pagination cursor.
pub type MessageId = u64;

/// Whose mailbox this is — the durable answer to "who".
///
/// Two keys, and **exactly one of them addresses any given mailbox**:
///
/// - An account with a linked identity is keyed by its **fingerprint**.
///   That survives a rename, which is the whole point: the account can
///   change its login and its mail follows, and the login it vacated can
///   be taken by someone else without their inheriting a word of it.
/// - An account with no identity is keyed by its **login**, and only
///   matches rows that have no fingerprint either.
///
/// The strictness is deliberate. A looser rule — "fingerprint, or the
/// login as a fallback" — would let an identity-linked account pick up
/// mail addressed to whoever held that login before it, which is the
/// failure this type exists to prevent. The cost is that mail queued for
/// an account *before* it linked an identity would be stranded, and
/// [`MessageStore::claim`] is what pays it: linking an identity stamps
/// that account's existing mail with the new fingerprint, in one shot, so
/// nothing is stranded and nothing is inherited.
///
/// **The fingerprint is the raw 32 bytes, never a rendering of them.**
/// It arrives that way (`Account`'s identity link holds `[u8; 32]`) and
/// only becomes text at the storage boundary, where one function decides
/// the spelling. A `String` here would be a key that compares by
/// spelling: an operator's hand-typed capital letter, or a registrar's
/// Crockford form meeting a hex one, and mail stranded in a mailbox
/// nobody can open. Bytes cannot have that bug.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mailbox {
    /// The canonical account login. Always present: it is what the wire
    /// addresses and what an operator reads in a log.
    pub login: String,
    /// The linked identity's key fingerprint, when the account has one.
    pub fingerprint: Option<[u8; 32]>,
}

impl Mailbox {
    /// A mailbox keyed by login — an account with no linked identity, or
    /// a server that has no identity subsystem at all.
    pub fn login(login: impl Into<String>) -> Self {
        Mailbox {
            login: login.into(),
            fingerprint: None,
        }
    }

    /// A mailbox keyed by an identity fingerprint.
    pub fn identified(login: impl Into<String>, fingerprint: [u8; 32]) -> Self {
        Mailbox {
            login: login.into(),
            fingerprint: Some(fingerprint),
        }
    }

    /// Does a stored row addressed to `(login, fingerprint)` belong to
    /// this mailbox? The one rule, in one place, so the in-memory and
    /// SQLite stores cannot disagree about it.
    pub fn matches(&self, row_login: &str, row_fingerprint: Option<&[u8; 32]>) -> bool {
        match (self.fingerprint.as_ref(), row_fingerprint) {
            (Some(mine), Some(theirs)) => mine == theirs,
            (None, None) => self.login == row_login,
            // An identified mailbox never claims unidentified rows, and an
            // unidentified one never claims identified rows.
            _ => false,
        }
    }
}

/// A client-supplied message id, for retry without duplication.
///
/// fogWraith's `DATA_MESSAGE_GUID` has clients generate one per message
/// and "retry idempotently"; our own row id is a server rowid and cannot
/// do that job, because the retry arrives before the client learned it.
/// Parsing rather than storing what arrives is the point: this indexes a
/// column, and an index over arbitrary client text is a place to put
/// anything.
///
/// Accepts the two shapes a UUID is written in — 36 characters with
/// hyphens, or 32 bare hex digits, in either case — and canonicalises
/// both to the lowercase hyphenated form, so a client that retries in a
/// different spelling still deduplicates.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageGuid(String);

impl MessageGuid {
    pub fn parse(s: &str) -> Option<Self> {
        let bare: String = match s.len() {
            32 => s.to_ascii_lowercase(),
            36 => {
                let b = s.as_bytes();
                if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
                    return None;
                }
                s.replace('-', "").to_ascii_lowercase()
            }
            _ => return None,
        };
        if bare.len() != 32 || !bare.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(MessageGuid(format!(
            "{}-{}-{}-{}-{}",
            &bare[0..8],
            &bare[8..12],
            &bare[12..16],
            &bare[16..20],
            &bare[20..32]
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MessageGuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a stored row is. The inbox carries more than mail.
///
/// A receipt is addressed to the *original sender* — `recipient` is who
/// sent the message, `sender` is who read it — so every operation the
/// store already has (claim, rotate, purge, prune, the mailbox rule)
/// applies to it unchanged, which is why this is a column rather than a
/// second table. Only a wire that can express a receipt branches on it.
///
/// **Nothing writes a receipt yet.** The wire that will is fogWraith's
/// `IM Acknowledge (812)`; until then the column exists so that adding
/// receipts is not a migration, and every read path the inbox exposes
/// filters to [`MessageKind::Message`] so a row of another kind can
/// never be rendered as mail.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MessageKind {
    #[default]
    Message,
    /// "Your message was read", addressed back to its sender. `body` is
    /// the acked message's guid, or its id where there was none.
    ReadReceipt,
}

impl MessageKind {
    pub fn as_i64(self) -> i64 {
        match self {
            MessageKind::Message => 0,
            MessageKind::ReadReceipt => 1,
        }
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        match n {
            0 => Some(MessageKind::Message),
            1 => Some(MessageKind::ReadReceipt),
            _ => None,
        }
    }
}

/// A message on its way into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    pub recipient: Mailbox,
    /// The sender, when the sender is someone the recipient could reply
    /// to. `None` when the sender had no account of its own — a guest,
    /// whose `guest` login several people share.
    pub sender: Option<Mailbox>,
    /// The sender's nickname as displayed when it was sent. Nicks are
    /// neither unique nor stable, so this is presentation, not identity.
    pub sender_nick: String,
    pub body: String,
    pub sent_at: SystemTime,
    /// The client's own id for this message, when it gave one. Two sends
    /// of the same guid between the same pair are one message.
    pub guid: Option<MessageGuid>,
    pub kind: MessageKind,
}

/// A message as the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub id: MessageId,
    pub recipient: Mailbox,
    pub sender: Option<Mailbox>,
    pub sender_nick: String,
    pub body: String,
    pub sent_at: SystemTime,
    pub guid: Option<MessageGuid>,
    pub kind: MessageKind,
    /// When the server handed this to a live connection — *not* when a
    /// client rendered it. A stronger guarantee needs per-message client
    /// acks, which is what fogWraith's `IM Acknowledge (812)` is for and
    /// what this becomes when that lands.
    pub delivered_at: Option<SystemTime>,
    /// When a client said it had been read. A legacy session has no way to
    /// say so, so on that wire delivery *is* the read (the flush sets
    /// both) — the truth about what that wire can express.
    pub read_at: Option<SystemTime>,
}

/// What an account's inbox holds, for badge counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InboxCounts {
    pub unread: usize,
    pub total: usize,
}

/// What [`MessageStore::push`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pushed {
    /// A new row, with its id.
    Stored(MessageId),
    /// This sender had already sent this recipient this guid; here is
    /// the row that exists. Nothing was written. Boxed because it dwarfs
    /// the other two variants and this is a hot return value.
    Existing(Box<StoredMessage>),
    /// The recipient already has `cap` messages waiting. Nothing was
    /// written.
    Full,
}

/// What a flush stamps on the rows it hands out.
///
/// The ng wire has `msg_read`, so a client says for itself when it has
/// read something. The legacy wire has no way to say it — a private
/// message is a window that opens, and nothing comes back — so on that
/// wire the flush *is* the read, which is what
/// `docs/private-messages.md` §11 says and what the unread count and the
/// retention clock both depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Delivered; the client will say when it has read them.
    Delivered,
    /// Delivered and read in the same step.
    Read,
}

/// A store operation failed. The string is for the log, not for a client —
/// same convention as [`crate::AuthError::Backend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl StoreError {
    pub fn new(e: impl std::fmt::Display) -> Self {
        StoreError(e.to_string())
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "message store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// The durable inbox behind a trait, so the in-memory implementation can
/// carry the domain's unit tests and a database one can arrive later
/// without the rule above it changing.
pub trait MessageStore: Send + Sync + 'static {
    /// Persist a message, unless it duplicates one already stored or the
    /// mailbox is at `cap` messages waiting.
    ///
    /// **Both checks happen here**, not in the caller. `find_guid` then
    /// `push` is check-then-insert, and the case guids exist for — a
    /// client retrying after its socket died mid-ack — is precisely the
    /// case that races it; `pending_count` then `push` is the same shape,
    /// and a sender that can send in parallel is exactly the sender the
    /// cap is meant to hold. What a duplicate or a full mailbox should
    /// *answer the sender* is still the domain's decision; which row
    /// exists is storage's.
    fn push(&self, m: &NewMessage, cap: usize) -> Result<Pushed, StoreError>;

    /// The message this sender already sent this recipient under `guid`,
    /// if there is one. Scoped to the pair, so two people cannot collide
    /// on each other's guids and one person may reuse a guid toward two
    /// recipients.
    fn find_guid(
        &self,
        to: &Mailbox,
        from: Option<&Mailbox>,
        guid: &MessageGuid,
    ) -> Result<Option<StoredMessage>, StoreError>;

    /// Undelivered messages for one mailbox, **oldest first** — the
    /// login/resume flush. `limit` bounds what a single flush hands a
    /// client; the rest stay pending.
    ///
    /// Messages only, like every read path here: a kind the wire cannot
    /// carry must not occupy a flush slot and come back forever unsent.
    /// This gains a kind filter when there is a wire for the other kinds.
    fn pending(&self, to: &Mailbox, limit: usize) -> Result<Vec<StoredMessage>, StoreError>;

    /// How many messages are waiting to be flushed. Messages only: a
    /// chatty reader's receipts must not fill the mailbox they are
    /// acking into.
    ///
    /// This is the number the mailbox cap is measured against, and it is
    /// deliberately not the unread count: a message the recipient received
    /// live and has not got round to marking read is not congestion, and
    /// treating it as such would let a client that never marks anything
    /// read lock its own mailbox against every sender. fogWraith's
    /// `MaxOfflineQueue` counts the same thing.
    fn pending_count(&self, to: &Mailbox) -> Result<usize, StoreError>;

    /// Stamp messages as handed to a live connection. Ids already
    /// delivered keep their original timestamp — the flush is idempotent.
    /// `what` decides whether they are stamped read as well; see
    /// [`Delivery`].
    fn mark_delivered(
        &self,
        ids: &[MessageId],
        at: SystemTime,
        what: Delivery,
    ) -> Result<(), StoreError>;

    /// Is `id` still waiting to be flushed to `to`?
    ///
    /// The sender's "did it go out live?" when some *other* flush was the
    /// one that delivered it — two sends to one recipient race, one
    /// flush carries both rows, and the sender whose flush came back
    /// empty would otherwise be told its message is queued when the
    /// recipient is reading it.
    fn is_pending(&self, to: &Mailbox, id: MessageId) -> Result<bool, StoreError>;

    /// Mark everything belonging to `to` up to and including `up_to` as
    /// read, stamping `delivered_at` too where it is unset (a message read
    /// straight out of [`MessageStore::list`] was never flushed, and must
    /// not be flushed later). Returns how many rows this marked.
    ///
    /// **Scoped by mailbox on purpose**: a client can only ever mark its
    /// own mail, whatever id it names.
    fn mark_read(
        &self,
        to: &Mailbox,
        up_to: MessageId,
        at: SystemTime,
    ) -> Result<usize, StoreError>;

    /// One mailbox's messages, **newest first**, paginating backwards from
    /// `before` (exclusive). This is what a client that woke to a push
    /// calls to find out what it was woken for.
    fn list(
        &self,
        to: &Mailbox,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, StoreError>;

    /// Unread and total for one mailbox.
    fn counts(&self, to: &Mailbox) -> Result<InboxCounts, StoreError>;

    /// The link moved to a successor key (`docs/hotline-ng-identity.md`
    /// §8.5): re-stamp everything keyed by `from` with `to`. Returns how
    /// many rows moved.
    ///
    /// **Key rotation must call this**, or a rotated identity loses its
    /// mailbox and its blocks quietly stop applying — the second being
    /// the worse half, because a block that has stopped working looks
    /// exactly like a block that was never made. Nothing calls it today;
    /// nothing rotates today either (identity spec §8.5).
    fn rotate(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<usize, StoreError>;

    /// An account has linked an identity: stamp everything currently
    /// keyed by its bare login — mail to it, mail from it, blocks either
    /// side — with the fingerprint, so the mailbox follows the identity
    /// from here on. Returns how many rows moved.
    ///
    /// **The account-linking path must call this**, or an account's
    /// existing mail is stranded the moment it gains an identity ([`Mailbox`]
    /// explains why the alternative is worse). It is idempotent: a second
    /// call finds nothing left to stamp.
    fn claim(&self, login: &str, fingerprint: &[u8; 32]) -> Result<usize, StoreError>;

    /// Delete everything belonging to a mailbox — mail to it, mail from
    /// it, and its blocks. Returns how many rows went.
    ///
    /// **Deleting an account must call this.** A login freed by deletion
    /// can be registered by someone else, and [`MessageStore::claim`]
    /// would then hand them the previous holder's mail.
    fn purge(&self, of: &Mailbox) -> Result<usize, StoreError>;

    /// How many rows [`MessageStore::purge`] would delete, without changing
    /// the store. Messages and blocks are both counted, and a row that names
    /// the mailbox on both sides counts once.
    fn purge_count(&self, of: &Mailbox) -> Result<usize, StoreError>;

    /// Drop read messages read longer ago than `read`, and unread ones
    /// sent longer ago than `unread`. Returns how many went. The two
    /// clocks differ on purpose: an unread message ages from when it was
    /// sent, a read one from when the recipient was done with it.
    fn prune(&self, now: SystemTime, unread: Duration, read: Duration)
        -> Result<usize, StoreError>;

    // --- Blocking -------------------------------------------------------
    //
    // A minimum viable version of fogWraith's Block User (806), here
    // rather than in a roster because there is no roster yet and the
    // mailbox needs it now: account addressing means anyone can put mail
    // in anyone's queue, and a queue has a cap. Without a block, filling
    // someone's mailbox locks every other sender out of it. When the
    // friend graph arrives the block list belongs with it, and this moves.

    /// Block or unblock. Idempotent in both directions.
    ///
    /// `at` is when, passed in like every other time here: the domain
    /// owns the clock, and a store that reads its own is a store whose
    /// rows a test cannot place in time.
    fn set_blocked(
        &self,
        owner: &Mailbox,
        other: &Mailbox,
        blocked: bool,
        at: SystemTime,
    ) -> Result<(), StoreError>;

    /// Has `owner` blocked `other`?
    fn is_blocked(&self, owner: &Mailbox, other: &Mailbox) -> Result<bool, StoreError>;

    /// Who `owner` has blocked, oldest first.
    fn blocked(&self, owner: &Mailbox) -> Result<Vec<Mailbox>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guid_parses_both_spellings_and_canonicalises_them() {
        let hyphenated = "5F5E1000-1234-4abc-89AB-000000000001";
        let bare = "5f5e100012344abc89ab000000000001";
        let a = MessageGuid::parse(hyphenated).expect("hyphenated");
        let b = MessageGuid::parse(bare).expect("bare");
        assert_eq!(a, b, "the same id in two spellings is one id");
        assert_eq!(
            a.as_str(),
            "5f5e1000-1234-4abc-89ab-000000000001",
            "canonical form is lowercase and hyphenated"
        );
    }

    #[test]
    fn anything_that_is_not_a_uuid_is_refused() {
        // An index over arbitrary client text is a place to put anything.
        for bad in [
            "",
            "hello",
            "5f5e1000-1234-4abc-89ab-00000000000", // too short
            "5f5e1000-1234-4abc-89ab-0000000000012", // too long
            "5f5e10001234-4abc-89ab-000000000001", // hyphens misplaced
            "5f5e1000-1234-4abc-89ab-00000000000g", // not hex
            "../../etc/passwd",
        ] {
            assert!(MessageGuid::parse(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_mailbox_never_confuses_its_two_kinds_of_key() {
        let bare = Mailbox::login("alice");
        let one = Mailbox::identified("alice", [1u8; 32]);
        let two = Mailbox::identified("alice", [2u8; 32]);

        assert!(bare.matches("alice", None));
        assert!(
            !bare.matches("alice", Some(&[1u8; 32])),
            "login vs identity"
        );
        assert!(
            one.matches("anything-at-all", Some(&[1u8; 32])),
            "the key is the fingerprint"
        );
        assert!(!one.matches("alice", None), "identity vs login");
        assert!(
            !one.matches("alice", Some(&[2u8; 32])),
            "one identity is not another"
        );
        assert_ne!(one, two);
    }
}
