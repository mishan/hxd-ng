//! The Hotline-ng frontend: WebSocket/JSON sessions over `hxd-core`, with
//! the detach/resume machinery the legacy wire can't express. Protocol
//! spec: `docs/hotline-ng.md`. Sibling of `hxd-session` (the legacy
//! frontend); both speak to the same domain core, so legacy and ng users
//! share one roster and one chat.

mod conn;
pub mod proto;
mod registry;

use std::sync::Arc;
use std::time::Duration;

use hxd_core::{AuthBackend, Core};
use tokio::net::TcpListener;
use tracing::{info, Instrument};

pub use registry::Registry;

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
}

impl Default for NgConfig {
    fn default() -> Self {
        NgConfig {
            server_name: "hxd-ng".into(),
            agreement: None,
            login_timeout: Duration::from_secs(10),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
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
}

/// Accept loop: one connection task per WebSocket.
pub async fn serve(listener: TcpListener, ctx: NgCtx) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let span = tracing::info_span!("ng", %peer);
            conn::run(stream, peer, ctx).instrument(span).await;
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
