//! The Hotline-ng frontend: WebSocket/JSON sessions over `hxd-core`, with
//! the detach/resume machinery the legacy wire can't express. Protocol
//! spec: `docs/hotline-ng.md`. Sibling of `hxd-session` (the legacy
//! frontend); both speak to the same domain core, so legacy and ng users
//! share one roster and one chat.

mod conn;
mod http;
pub mod identity;
pub mod proto;
mod registry;
mod tunnel;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{AuthBackend, Core, Transport};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{info, Instrument};

pub use identity::{IdentityConfig, IdentityState, NewAccounts, Unattested};
pub use registry::Registry;

/// A byte stream handed to the legacy frontend by the TRTP-over-WebSocket
/// path (`docs/hotline-ng-identity.md` §6.3).
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}
pub type TunnelStream = Box<dyn ByteStream>;

/// Who runs a tunnelled legacy session. The binary implements this with
/// `hxd_session::run_session`; this crate deliberately doesn't depend on
/// the legacy frontend — the tunnel is transport, and what's inside it
/// is the caller's protocol.
pub trait TunnelSink: Send + Sync {
    fn run(
        &self,
        stream: TunnelStream,
        peer: SocketAddr,
        transport: Transport,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// Configuration for the ng listener.
#[derive(Debug, Clone)]
pub struct NgConfig {
    /// Advertised server name (shared with the legacy frontend's).
    pub server_name: String,
    /// Agreement text, if any — display-only in ng (no accept round-trip).
    pub agreement: Option<String>,
    /// How long a handshake (first request) may take.
    pub login_timeout: Duration,
    /// The detach grace window.
    pub grace: Duration,
    /// Detached-sessions-per-address backstop.
    pub max_detached_per_addr: usize,
    /// Optional protocol extensions this server offers, reported in the
    /// login reply's `caps` list so clients feature-detect instead of
    /// version-sniffing (`docs/hotline-ng.md` §11). The ng twin of the
    /// legacy wire's `DATA_CAPABILITIES` bitmask — a list of names
    /// because the transport is already JSON and a name outlives a bit
    /// allocation.
    pub caps: Vec<String>,
    /// Reverse-proxy addresses whose `X-Hotline-Client-Cert` header is
    /// believed (`docs/hotline-ng-identity.md` §5.3). Empty = the mTLS
    /// binding is off.
    pub trusted_proxies: Vec<IpAddr>,
}

impl Default for NgConfig {
    fn default() -> Self {
        NgConfig {
            server_name: "hxd-ng".into(),
            agreement: None,
            login_timeout: Duration::from_secs(10),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: Vec::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

/// Everything an ng connection needs. Cheap to clone.
#[derive(Clone)]
pub struct NgCtx {
    pub core: Arc<Core>,
    pub auth: Arc<dyn AuthBackend>,
    pub cfg: Arc<NgConfig>,
    pub registry: Arc<Registry>,
    /// Identity state, when `[identity]` is enabled. `None` means the
    /// identity endpoints 404 and every socket is unauthenticated.
    pub identity: Option<Arc<IdentityState>>,
    /// Who runs TRTP tunnels. `None` means the `/trtp` path is off.
    pub tunnel: Option<Arc<dyn TunnelSink>>,
}

/// Accept loop: one connection task per socket. Each is HTTP until it
/// upgrades (`http.rs`).
pub async fn serve(listener: TcpListener, ctx: NgCtx) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let span = tracing::info_span!("ng", %peer);
            http::serve_connection(stream, peer, ctx)
                .instrument(span)
                .await;
        });
    }
}

/// The periodic maintenance the binary runs: end detached sessions whose
/// grace lapsed, and drop registry entries whose sessions are gone.
pub async fn sweeper(core: Arc<Core>, registry: Arc<Registry>, grace: Duration) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let ended = core.sweep_detached(grace);
        if ended > 0 {
            info!(ended, "detached sessions swept");
        }
        registry.prune(&core);
    }
}
