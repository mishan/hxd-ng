//! The half of the destination check that needs a resolver
//! (`docs/webpush-gateway.md` §6).
//!
//! The URL's shape, and a literal address in it, are
//! [`hxd_core::push::endpoint`]'s and are checked when a device
//! registers. What is left for here is the one thing a registration
//! cannot settle: what a *name* resolves to, which is asked again before
//! every send, because DNS moves and a host that answered publicly last
//! week can answer `127.0.0.1` today. The transport checks literals and
//! names alike against the addresses it is about to connect to, so the
//! shape is all it takes from here.

pub use hxd_core::push::endpoint::{is_public, shape as check, Refused, Target};
