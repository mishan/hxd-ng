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
#[derive(Debug, Clone)]
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
    fn authenticate(&self, login: &str, proof: Proof<'_>) -> Result<Account, AuthError>;

    /// Load an account without a proof. For the identity paths, where
    /// possession of the key stood in for the password; callers must
    /// have established that before calling.
    fn lookup(&self, login: &str) -> Result<Account, AuthError>;

    /// The account linked to an identity, if any.
    fn find_by_fingerprint(&self, fingerprint: &[u8; 32]) -> Result<Option<Account>, AuthError>;

    /// Set or clear an account's identity link. Callers enforce the
    /// one-to-one rule; the backend just writes.
    fn set_identity_link(
        &self,
        login: &str,
        fingerprint: Option<[u8; 32]>,
    ) -> Result<(), AuthError>;

    /// Create an account linked to an identity (`new_accounts = create`).
    /// `login` is the caller's proposal; the backend may return a
    /// different one if it had to disambiguate. `access` is the initial
    /// bitmap; the account gets no password.
    fn create_linked(
        &self,
        login: &str,
        name: &str,
        fingerprint: [u8; 32],
        access: AccessBits,
    ) -> Result<Account, AuthError>;

    /// Which account, if any, reserves `name` as a display name (§9):
    /// an account with `reserve_name` whose login equals `name`,
    /// case-insensitively. Returns the login.
    fn reserved_by(&self, name: &str) -> Result<Option<String>, AuthError>;
}
