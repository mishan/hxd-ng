//! Accounts and the pluggable authentication backend.
//!
//! The backend trait is the modular-auth seam from the roadmap: Phase 1
//! ships a flat-file implementation (hxd-auth-file); the persistence phase
//! adds a database one behind the same trait.
//!
//! **On password storage:** the legacy wire constrains us. A 1.5 login
//! carries the password XOR-0xff — effectively plaintext — and the HOPE
//! login (Phase 2) proves knowledge of the password via HMAC, which the
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
}

/// The client's proof of identity.
///
/// `Plain` is the classic login (already de-obfuscated from the wire's
/// XOR-0xff form). HOPE HMAC proofs join in Phase 2 as a second variant —
/// that's why this is an enum and not a bare byte slice.
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
}
