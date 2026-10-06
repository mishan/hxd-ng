//! The link wire of fogWraith's Server Linking Extension
//! (`docs/server-link.md`): the 900-block of transactions a linked server
//! speaks to its peer, the groups they carry, and the key proof that
//! authenticates a link by server keys.
//!
//! Knows nothing about classic clients or the ng wire. What crosses a link
//! reaches the domain through `hxd-core`, and what a link session needs
//! from the classic frontend (framing) it takes from `hxd-session`.

mod dial;
pub mod hub;
pub mod key;
mod link;
pub mod server;
pub mod wire;

pub use hub::{Hub, HubConfig, LinkStatus, PeerEntry};
pub use key::{check_public, KeyError, LinkKey, Role};
pub use server::{ServerGroup, ServerId, TagError};
pub use wire::{Field, Hello};
