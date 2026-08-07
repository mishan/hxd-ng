//! hxd-ng's domain layer.
//!
//! Everything in this crate is wire-format-free: no transaction types, no
//! chunk tags, no sockets. The session layer (hxd-session) translates between
//! the Hotline wire and these types; a future protocol frontend (the
//! Hotline-ng phase) talks to the same types. Keeping wire vocabulary out of
//! this crate's API is a roadmap commitment, not an accident — see
//! ROADMAP.md's architecture section.

pub mod access;
pub mod account;
pub mod chat;
pub mod roster;

pub use access::AccessBits;
pub use account::{Account, AuthBackend, AuthError, Proof};
pub use chat::ChatError;
pub use roster::{AttachInfo, Core, Event, SessionStatus, Uid, UserDetails, UserInfo};
