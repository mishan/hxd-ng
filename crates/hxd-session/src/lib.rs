//! hxd-ng's legacy-wire session layer: TRTP handshake, transaction framing,
//! dispatch, and the per-connection actor pair (reader + writer). The
//! Hotline-ng protocol frontend will be a sibling of this crate, not an
//! extension of it — both speak to `hxd-core`.

pub mod caps;
pub mod frame;
pub mod session;
pub mod video;
pub mod voice;

pub use caps::{cap, Caps};
pub use session::{run_session, serve, ServerConfig, ServerCtx};
