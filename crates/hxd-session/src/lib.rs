//! hxd-ng's legacy-wire session layer: TRTP handshake, transaction framing,
//! dispatch, and the per-connection actor pair (reader + writer). The
//! Hotline-ng protocol frontend will be a sibling of this crate, not an
//! extension of it — both speak to `hxd-core`.

mod accounts;
pub mod banner;
pub mod caps;
pub mod encoding;
mod file_manage;
mod files;
pub mod frame;
pub mod media;
pub mod news;
pub mod peer;
pub mod session;
pub mod tls;
pub mod video;
pub mod voice;

pub use banner::Banner;
pub use caps::{cap, Caps};
pub use encoding::TextEncoding;
pub use news::{FlatNews, FlatPushes, FlatReply, LegacyNews};
pub use peer::{LinkGrant, LinkIo, LinkLogin, LinkOut, PeerAcceptor};
pub use session::{
    run_session, serve, serve_tls, serve_tls_with_peers, ServerConfig, ServerCtx, TrtpLogin,
    NAMES_A_USER,
};
pub use tls::LegacyTls;
