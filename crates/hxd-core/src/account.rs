//! Accounts and the pluggable authentication backend.
//!
//! The backend trait is the modular-auth seam from the roadmap: the
//! flat-file implementation (hxd-auth-file) ships first; the persistence
//! phase adds a database one behind the same trait.
//!
//! **On password storage:** the legacy wire constrains us. A 1.5 login
//! carries the password XOR-0xff — effectively plaintext — and the HOPE
//! login (with the secure-login work) proves knowledge of the password
//! via HMAC, which the
//! server can only verify by holding a plaintext-equivalent secret. So
//! backends store recoverable secrets for legacy-capable accounts; real
//! password hashing arrives with the Hotline-ng protocol and applies only
//! to accounts that opt out of legacy access.

use crate::access::AccessBits;

/// A resolved account: what the auth backend hands the session layer after
/// a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The canonical login name (lowercase by convention).
    pub login: String,
    /// The display name used when the account doesn't grant
    /// `use_any_name` (UTF-8; the session layer converts to Mac Roman).
    pub name: String,
    /// The access bitmap.
    pub access: AccessBits,
    /// Server-local policy, not wire vocabulary (the account file's
    /// `[extra]` section — mhxd's `access_extra` concept). May this
    /// account's sessions survive their connection (Hotline-ng detach)?
    /// Backend default: only password-protected accounts.
    pub can_detach: bool,
    /// May this account set the public chat subject? Backend default:
    /// tracks the disconnect-users (admin) bit.
    pub set_subject: bool,
    /// Whether a non-empty password is set. Identity unlinking refuses
    /// to orphan an account that has no other way in.
    pub has_password: bool,
    /// Portable-identity association (`docs/hotline-ng-identity.md` §8).
    pub identity: IdentityLink,
}

/// How an account relates to a portable identity. All server-local
/// policy; nothing here crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityLink {
    /// The linked identity's fingerprint (SHA-256 of its public key), if
    /// any. At most one per account; at most one account per identity.
    pub fingerprint: Option<[u8; 32]>,
    /// May the linked identity log in without a password? Operator
    /// switch; backend default true.
    pub identity_login: bool,
    /// May a user link an identity to this account themself (with the
    /// password) rather than the operator doing it? Backend default true.
    pub allow_self_link: bool,
    /// Is this account's login name reserved as a display name on the
    /// server (§9)? Backend default false.
    pub reserve_name: bool,
}

/// What [`AuthBackend::link_identity`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The link was written; the account as it now reads.
    Linked(Account),
    /// The account already linked this identity; nothing written.
    Already(Account),
    /// The identity already links a different account — which one.
    Taken(Account),
    /// The account links another identity, or forbids self-linking.
    Refused(Account),
}

/// What [`AuthBackend::unlink_identity`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlinkOutcome {
    /// The link was cleared; the account as it read before.
    Unlinked(Account),
    /// No account links this identity here.
    NotLinked,
    /// The account has no password, so the link is its only way in
    /// (§8.4). Set a password first.
    WouldOrphan(Account),
}

/// What a transport-authenticated socket may change about account
/// association (`docs/hotline-ng-identity.md` §8.2): the device
/// certificate's `manage` capability, carried alongside `Transport`
/// rather than inside it — `Transport` is descriptive and roster-visible,
/// and this authorizes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkAuthority {
    /// The device certificate grants `manage`.
    pub may_link: bool,
}

/// The client's proof of identity.
///
/// `Plain` is the classic login (already de-obfuscated from the wire's
/// XOR-0xff form). HOPE HMAC proofs join as a second variant when secure
/// login lands — that's why this is an enum and not a bare byte slice.
#[derive(Debug)]
pub enum Proof<'a> {
    /// The password as typed, raw bytes (clients send Mac Roman).
    Plain(&'a [u8]),
}

/// Why an authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No such account.
    NoSuchAccount,
    /// The proof didn't verify.
    BadProof,
    /// The backend itself failed (I/O, parse). The string is for the log,
    /// not the client.
    Backend(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::NoSuchAccount => write!(f, "no such account"),
            AuthError::BadProof => write!(f, "wrong password"),
            AuthError::Backend(e) => write!(f, "auth backend error: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The pluggable authentication backend.
///
/// Synchronous by design for now: the file backend is a couple of small
/// reads, and the session layer calls it on the blocking pool. When a
/// database backend lands (persistence phase) this trait goes async as
/// part of that work — the shared crates refactor freely (`publish =
/// false` everywhere), so we don't pre-pay for it.
pub trait AuthBackend: Send + Sync + 'static {
    /// Authenticate `login` with `proof`. An empty login means guest;
    /// backends decide whether a guest account exists.
    ///
    /// An account that has no password but *does* link an identity must
    /// be refused here, whatever the proof (§8.3): for those accounts the
    /// device key is the credential, and an empty password is not one.
    /// Otherwise every account `new_accounts = create` writes is open to
    /// anyone who types its login and presses return on the legacy port.
    /// The identity paths reach such accounts through
    /// [`AuthBackend::lookup`], having proved the key first.
    fn authenticate(&self, login: &str, proof: Proof<'_>) -> Result<Account, AuthError>;

    /// Load an account without a proof. For the identity paths, where
    /// possession of the key stood in for the password; callers must
    /// have established that before calling.
    fn lookup(&self, login: &str) -> Result<Account, AuthError>;

    /// The account linked to an identity, if any.
    fn find_by_fingerprint(&self, fingerprint: &[u8; 32]) -> Result<Option<Account>, AuthError>;

    /// Link `fingerprint` to `login`, enforcing the one-to-one rule.
    ///
    /// **The whole decision happens inside the backend**, because the
    /// callers can't make it safely: read the account, check whether the
    /// identity is spoken for, and write, all as one step. Done as
    /// separate calls, two concurrent logins by one identity naming two
    /// different accounts both see "not linked" and both write, and the
    /// identity ends up linked to two accounts.
    fn link_identity(&self, login: &str, fingerprint: &[u8; 32]) -> Result<LinkOutcome, AuthError>;

    /// Clear the link on whichever account `fingerprint` links (§8.4).
    /// Atomic for the same reason as [`AuthBackend::link_identity`], and
    /// it refuses to leave a password-less account with no way in.
    fn unlink_identity(&self, fingerprint: &[u8; 32]) -> Result<UnlinkOutcome, AuthError>;

    /// The account linked to `fingerprint`, creating one if there is
    /// none (`new_accounts = create`). `proposed` is the caller's
    /// suggested login; the backend may pick another if it collides.
    /// `access` is the initial bitmap, and the account gets no password
    /// — so it is reachable only by proving the identity.
    ///
    /// The `bool` is true when the account was created by this call.
    /// Atomic: without that, two logins by one never-seen identity make
    /// two accounts for it.
    fn find_or_create_linked(
        &self,
        proposed: &str,
        name: &str,
        fingerprint: &[u8; 32],
        access: AccessBits,
    ) -> Result<(Account, bool), AuthError>;

    /// Which account, if any, reserves `name` as a display name (§9):
    /// an account with `reserve_name` whose login equals `name`,
    /// case-insensitively. Returns the login.
    fn reserved_by(&self, name: &str) -> Result<Option<String>, AuthError>;
}
