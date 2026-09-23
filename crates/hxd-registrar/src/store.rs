//! What the registrar keeps, behind a trait (`identity-registrar.md` §12).
//!
//! Two implementations: [`crate::memory::MemoryStore`], which the domain's
//! tests run on, and the SQLite one in `hxd-store-sqlite`, which a server
//! keeps. [`crate::conformance`] holds both to one set of answers.
//!
//! The trait is shaped around the registrar's two kinds of write rather
//! than around its tables. [`RegistrarStore::issue`] is one attestation:
//! the identity, the handle, the log entry and whatever the issuance
//! consumed. [`RegistrarStore::publish`] is one or more records *and
//! everything they change*, in one transaction — a freeze that is
//! recorded but not published, or published but not recorded, is the
//! failure that matters most (§12), and making the record and its effect
//! one call is what rules it out.
//!
//! The store decides nothing. Whether a handle may be issued, whether a
//! rotation is acceptable, what a list may carry: the domain works those
//! out and hands the store the result. The one exception is the invite,
//! which the store consumes atomically with the issuance it paid for, so
//! that two registrations racing on one code cannot both win.

use std::fmt;

/// An Ed25519 public key.
pub type Key = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl StoreError {
    pub fn new(e: impl fmt::Display) -> Self {
        StoreError(e.to_string())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "registrar store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// An identity the registrar has attested at least once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    pub key: Key,
    /// `SHA-256` of the committed successor (§5.4). Once set, immutable.
    pub commitment: Option<[u8; 32]>,
    pub frozen: bool,
    /// An identity revocation was accepted (§4.5).
    pub revoked: bool,
    /// A rotation was published, to this key (§4.6).
    pub rotated_to: Option<Key>,
    pub created: u64,
}

/// Where a handle is in its lifecycle (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleState {
    /// Attested to an identity, attestation unexpired.
    Held,
    /// Expired or revoked, and still within the hold: only the identity
    /// that lost it may have it back.
    Lapsed,
    /// The hold passed; anyone may register it.
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleRow {
    /// The canonical local part. Handles are issued only in lowercase
    /// (§5.1), so equality here is the case-insensitive comparison the
    /// spec asks for.
    pub name: String,
    pub identity: Key,
    /// The first registration by this line of identities (§4.3); kept
    /// across reissue and rotation.
    pub registered: u64,
    /// The latest attestation's `expires`.
    pub expires: u64,
    /// When the handle lapsed early: the attestation was revoked, or the
    /// identity was. `None` means it lapses when `expires` passes.
    pub lapsed_at: Option<u64>,
    /// Revoked for abuse: lapsed, and the identity that held it may not
    /// have it back. The hold still keeps everyone else off it.
    pub barred: bool,
}

impl HandleRow {
    /// When the handle stopped being held, if it has.
    pub fn lapsed(&self, now: u64) -> Option<u64> {
        match self.lapsed_at {
            Some(at) => Some(at.min(self.expires)),
            None if self.expires <= now => Some(self.expires),
            None => None,
        }
    }

    pub fn state(&self, now: u64, hold_secs: u64) -> HandleState {
        match self.lapsed(now) {
            None => HandleState::Held,
            Some(at) if now < at.saturating_add(hold_secs) => HandleState::Lapsed,
            Some(_) => HandleState::Released,
        }
    }
}

/// One attestation, and everything its issuance writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub identity: Key,
    /// Created with the identity row, or set on it when it has none.
    /// Never replaces one: the domain refuses a request that disagrees.
    pub commitment: Option<[u8; 32]>,
    /// The handle as it stands after this issuance.
    pub handle: HandleRow,
    /// A first registration of the handle, rather than a reissue. What
    /// the stats count.
    pub first: bool,
    pub issued: u64,
    /// The signed attestation: the log entry.
    pub attestation: Vec<u8>,
    /// The hash of the invite this registration spends.
    pub invite: Option<[u8; 32]>,
    /// The recovery grant this reissue redeems, by handle.
    pub recovery: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issued {
    /// The issuance's `seq` in the log.
    Logged(u64),
    /// The invite was spent, or never existed, by the time the write
    /// happened. Nothing was written.
    InviteSpent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    RevokeDevice,
    RevokeIdentity,
    Rotate,
    Freeze,
    RevokeAttestation,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::RevokeDevice => "revoke_device",
            RecordKind::RevokeIdentity => "revoke_identity",
            RecordKind::Rotate => "rotate",
            RecordKind::Freeze => "freeze",
            RecordKind::RevokeAttestation => "revoke_attestation",
        }
    }

    pub fn parse(s: &str) -> Option<RecordKind> {
        Some(match s {
            "revoke_device" => RecordKind::RevokeDevice,
            "revoke_identity" => RecordKind::RevokeIdentity,
            "rotate" => RecordKind::Rotate,
            "freeze" => RecordKind::Freeze,
            "revoke_attestation" => RecordKind::RevokeAttestation,
            _ => return None,
        })
    }
}

/// A record to publish, with what the lists index it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecord {
    pub kind: RecordKind,
    /// The key the record is about: the owner of a revoked device, the
    /// predecessor of a rotation.
    pub identity: Key,
    /// A rotation's successor, so the successor's list carries it too.
    pub other: Option<Key>,
    /// When the record stops mattering to the *full* list (§4.9): a
    /// device revocation's `until`, and for an attestation revocation
    /// the last expiry among the attestations it voids. `None` is never.
    pub until: Option<u64>,
    /// `SHA-256` of `bytes`: a record already held is answered with its
    /// existing `seq` (§6.2).
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
}

/// A rotation accepted and held back by `rotation_delay` (§5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub identity: Key,
    pub successor: Key,
    pub publish_at: u64,
    pub digest: [u8; 32],
    pub bytes: Vec<u8>,
}

/// An operator's recovery (§8.3): the handle's next registration from
/// `fingerprint` is a reissue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub handle: String,
    pub fingerprint: [u8; 32],
    /// Whether `registered` survives. Visible to anyone in the log.
    pub keep_age: bool,
    pub granted: u64,
}

/// What a published record changes. Applied in order, in the same
/// transaction as the records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    SetFrozen(Key, bool),
    /// The identity is revoked (§4.5).
    Revoke(Key),
    /// `from` is rotated to `to`: `to` gets an identity row if it has
    /// none (created `at`), and every handle `from` holds moves to it
    /// with `registered` kept (§5.4).
    Rotate {
        from: Key,
        to: Key,
        at: u64,
    },
    /// Every handle of the identity that has not lapsed lapses `at`.
    LapseHandles {
        identity: Key,
        at: u64,
    },
    /// One handle lapses `at`, and with `barred` its holder may not
    /// reissue it.
    LapseHandle {
        name: String,
        at: u64,
        barred: bool,
    },
    GrantRecovery(Recovery),
    SetPending(Pending),
    DropPending(Key),
}

/// One or more records and their effects: one transaction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Publish {
    pub records: Vec<NewRecord>,
    pub effects: Vec<Effect>,
}

/// Which records a page is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordFilter {
    /// Every record naming this key, as `identity` or as `other`; none
    /// ever pruned.
    Identity(Key),
    /// The full list at `now`: device revocations past `until` and
    /// attestation revocations past `until` are gone, and so are an
    /// identity's device revocations beyond the `device_cap` latest by
    /// `until` (§10). Rotations, identity revocations and freezes stay.
    All { now: u64, device_cap: usize },
}

/// A page of `[seq, bytes]`, cut before `budget` bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub entries: Vec<(u64, Vec<u8>)>,
    pub more: bool,
}

/// What `stats` counts (§6.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub identities: u64,
    pub issued_24h: u64,
    pub issued_7d: u64,
    pub issued_total: u64,
    pub revoked_total: u64,
    pub frozen: u64,
    pub log_seq: u64,
}

/// How much one entry costs a page's `budget`: its bytes and the most
/// its `[seq, bytes]` framing can add. Both stores cut pages with this,
/// so they cut them in the same place.
pub fn entry_cost(bytes: &[u8]) -> usize {
    bytes.len() + hl_identity::SignedList::ENTRY_OVERHEAD
}

pub trait RegistrarStore: Send + Sync + 'static {
    /// Open a transaction spanning the calls that follow until
    /// [`commit`](Self::commit) or [`rollback`](Self::rollback), holding
    /// off every other writer to this store — in another process too —
    /// until then. The registrar brackets each decision and its writes
    /// with it, one at a time; the writes inside stay atomic on their own.
    /// A store only one process can open needs nothing here, since the
    /// registrar's own lock already serializes it.
    fn begin(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn commit(&self) -> Result<(), StoreError> {
        Ok(())
    }
    /// Undo what [`begin`](Self::begin) opened, if anything is open.
    fn rollback(&self) {}

    fn identity(&self, key: &Key) -> Result<Option<IdentityRow>, StoreError>;
    /// By `SHA-256(key)`, which is what URLs and operators name.
    fn identity_by_fingerprint(&self, fp: &[u8; 32]) -> Result<Option<IdentityRow>, StoreError>;
    fn handle(&self, name: &str) -> Result<Option<HandleRow>, StoreError>;
    /// Every handle row naming the identity, in name order, whatever its
    /// state.
    fn handles_of(&self, key: &Key) -> Result<Vec<HandleRow>, StoreError>;
    fn recovery(&self, handle: &str) -> Result<Option<Recovery>, StoreError>;

    /// Write one issuance (see [`Issue`]). With `invite` set, spend it
    /// first, and write nothing if it cannot be spent.
    fn issue(&self, w: &Issue) -> Result<Issued, StoreError>;
    /// The latest `expires` among this identity's attestations for this
    /// handle issued at or before `issued_up_to` — what an attestation
    /// revocation at that time voids, and so how long it matters.
    fn attestations_expire(
        &self,
        identity: &Key,
        handle: &str,
        issued_up_to: u64,
    ) -> Result<Option<u64>, StoreError>;

    /// Write records and their effects. Returns each record's `seq`, in
    /// order; a record whose digest is already held is not written again
    /// and answers with the `seq` it has.
    fn publish(&self, p: &Publish) -> Result<Vec<u64>, StoreError>;
    fn record_seq(&self, digest: &[u8; 32]) -> Result<Option<u64>, StoreError>;
    /// Set the identity's commitment if it has none. `false` when it
    /// already had one, or there is no such identity.
    fn set_commitment(&self, key: &Key, commitment: &[u8; 32]) -> Result<bool, StoreError>;

    fn pending(&self, key: &Key) -> Result<Option<Pending>, StoreError>;
    /// Pending rotations whose `publish_at` is at or before `now`.
    fn pending_due(&self, now: u64) -> Result<Vec<Pending>, StoreError>;

    /// Records with `seq > since`, in `seq` order, stopping before the
    /// page would pass `budget` by [`entry_cost`] — but always at least
    /// one entry when there is one, so a page makes progress.
    fn records_page(
        &self,
        filter: RecordFilter,
        since: u64,
        budget: usize,
    ) -> Result<Page, StoreError>;
    /// The issuance log the same way.
    fn log_page(&self, since: u64, budget: usize) -> Result<Page, StoreError>;
    fn counts(&self, now: u64) -> Result<Counts, StoreError>;

    /// Whether this invite exists and is unspent.
    fn invite_open(&self, hash: &[u8; 32]) -> Result<bool, StoreError>;
    /// Add invites; ones already known, spent or not, are left alone.
    /// Returns how many were new.
    fn add_invites(&self, hashes: &[[u8; 32]]) -> Result<usize, StoreError>;
}
