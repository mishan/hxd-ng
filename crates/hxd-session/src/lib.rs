//! hxd-ng's legacy-wire session layer: TRTP handshake, transaction framing,
//! dispatch, and the per-connection actor pair (reader + writer). The
//! Hotline-ng protocol frontend will be a sibling of this crate, not an
//! extension of it — both speak to `hxd-core`.

pub mod caps;
pub mod encoding;
mod files;
pub mod frame;
pub mod media;
pub mod news;
pub mod session;
pub mod tls;
pub mod video;
pub mod voice;

pub use caps::{cap, Caps};
pub use encoding::TextEncoding;
pub use news::{FlatNews, FlatReply, LegacyNews};
pub use session::{run_session, serve, serve_tls, ServerConfig, ServerCtx, TrtpLogin};
pub use tls::LegacyTls;
