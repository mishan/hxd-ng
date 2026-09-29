//! The Hotline-ng frontend: WebSocket/JSON sessions over `hxd-core`, with
//! the detach/resume machinery the legacy wire can't express. Protocol
//! spec: `docs/hotline-ng.md`. Sibling of `hxd-session` (the legacy
//! frontend); both speak to the same domain core, so legacy and ng users
//! share one roster and one chat.

pub mod avatar;
pub mod banner;
mod conn;
pub mod enroll;
mod files;
mod http;
pub mod identity;
pub mod media;
pub mod metrics;
pub mod moderation;
pub mod news;
mod news_blob;
pub mod proto;
pub mod push;
mod registrar;
mod registry;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{AuthBackend, Core, LinkAuthority, Transport};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{info, warn, Instrument};

pub use identity::{
    AuthRequest, ClassicLogin, Downstream, IdentityConfig, IdentityState, NewAccounts, Unattested,
};
pub use registry::Registry;

/// A byte stream handed to the legacy frontend by the TRTP-over-WebSocket
/// path (`docs/hotline-ng-auth.md` §7.3).
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
        // `link` is what the socket's device certificate lets a tunnelled
        // login change about account association (§8.2) — separate from
        // `transport`, which is descriptive; this authorizes.
        link: LinkAuthority,
        // The connection's place in its address's count, taken at the
        // upgrade and held for as long as the session runs, moved to its
        // account's count if it logs in as a person, and carrying the
        // socket's place in the port's own per-address count with it.
        place: hxd_core::ConnPermit,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Serve one file transfer a tunnelled session was issued, arriving
    /// on `/htxf` (`hotline-ng-auth.md` §7.4) from a socket that proved
    /// `identity`. `None` when this server has no transfers to serve, and
    /// then the path is not offered.
    fn transfer(
        &self,
        _stream: TunnelStream,
        _peer: SocketAddr,
        _identity: [u8; 32],
    ) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        None
    }

    /// Whether [`TunnelSink::transfer`] has anything to serve.
    fn has_transfers(&self) -> bool {
        false
    }
}

/// Configuration for the ng listener.
#[derive(Debug, Clone)]
pub struct NgConfig {
    /// Advertised server name (shared with the legacy frontend's).
    pub server_name: String,
    /// Where a web client for this server lives, advertised in discovery
    /// (`identity-enrollment.md` §3). `None` omits the key, and a holder
    /// with nowhere to point a QR code prints the pairing code alone.
    pub web_client: Option<String>,
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
    /// version-sniffing (`docs/hotline-ng.md` §4). The ng twin of the
    /// legacy wire's `DATA_CAPABILITIES` bitmask — a list of names
    /// because the transport is already JSON and a name outlives a bit
    /// allocation.
    pub caps: Vec<String>,
    /// Reverse-proxy addresses whose `X-Hotline-Client-Cert` header is
    /// believed (`docs/hotline-ng-auth.md` §6.3). Empty = the mTLS
    /// binding is off.
    pub trusted_proxies: TrustedProxies,
    /// Which forwarded-address header a trusted proxy is configured to
    /// write (§6.3). Only this one is read, because a header the proxy
    /// doesn't write is one the client gets to choose.
    pub forwarded_header: ForwardedHeader,
    /// What the HTTP layer holds addresses, and everyone, to.
    pub http_limits: HttpLimits,
}

/// What the ng port holds one address to, and everyone together
/// (`[limits]`), before and beside the limits on the sessions it
/// carries (`hxd_core::limits`). 0 is no limit, in each.
///
/// Every connection to the port holds a place in both counts from
/// accept until it closes, whatever it turns out to carry — a WebSocket
/// included, for its whole life — so they bound the descriptors the
/// port can take. An ng session's socket also holds a place in the
/// address's shared count, the one the classic wire's connections
/// count against; the count here is separate and larger, because one
/// browser page opens several connections at once beside its socket
/// and would be refused by the classic wire's allowance of five. A
/// socket whose session logs in as a person gives up its places in
/// both per-address counts for one in its account's
/// (`hxd_core::Core::admit_account`), and keeps its place among
/// everyone's.
///
/// **Behind a trusted proxy** (`[ng] trusted_proxies`) the connection
/// at accept is the proxy's, and it carries requests for everyone
/// behind it, so the per-address count does not apply to it: the
/// proxy is the place to limit connections per client. The request
/// limits still apply, to the forwarded address, as every other
/// per-address rule on this port does.
///
/// An IPv6 address is its /64 here as everywhere (`hxd_core::limits`),
/// and the /64s of one /48 are held to a wider count between them, so
/// that one subscriber's delegation cannot fill `connections` by
/// itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// Connections one address may hold to the port at once.
    pub connections_per_addr: usize,
    /// Connections the /64s of one IPv6 /48 may hold to the port at
    /// once between them.
    pub connections_per_v6_48: usize,
    /// Connections everyone together may hold to the port at once.
    /// Past it a new one is closed unanswered; it is what stands
    /// between a crowd of addresses and the process's descriptors,
    /// which the classic port and the databases share. Addresses
    /// `[limits]` exempts have a few places kept past it, so a flood
    /// does not shut out the operator's own tools.
    pub connections: usize,
    /// `POST /identity/challenge` one address may make a minute.
    pub challenges_per_minute: u32,
    /// `GET /avatars/{id}` one address may make a minute.
    pub avatar_fetches_per_minute: u32,
}

impl HttpLimits {
    pub const RECOMMENDED: HttpLimits = HttpLimits {
        connections_per_addr: 16,
        // Four addresses' worth, as the shared count's is: a site's few
        // machines get in, and it takes many /48s rather than one to
        // fill `connections`.
        connections_per_v6_48: 64,
        connections: 4096,
        challenges_per_minute: 30,
        avatar_fetches_per_minute: 600,
    };
}

impl Default for HttpLimits {
    fn default() -> Self {
        HttpLimits::RECOMMENDED
    }
}

/// The header a trusted proxy uses to say who it is speaking for.
///
/// The distinction matters because proxies pass headers they don't know
/// about straight through: nginx configured with
/// `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` writes
/// that header and forwards a client-supplied `Forwarded:` untouched, so
/// believing both would mean believing whichever one the client filled
/// in. The operator says which one their proxy owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForwardedHeader {
    /// `X-Forwarded-For`, what the stock nginx and HAProxy directives
    /// write.
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded`.
    Forwarded,
    /// Neither: every client behind the proxy shares its address.
    None,
}

impl ForwardedHeader {
    /// Parse the `[ng] forwarded_header` value. The error names what was
    /// wrong; it reaches the operator at startup.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "x-forwarded-for" => Ok(ForwardedHeader::XForwardedFor),
            "forwarded" => Ok(ForwardedHeader::Forwarded),
            "none" => Ok(ForwardedHeader::None),
            other => Err(format!(
                "forwarded_header: {other:?} is not one of \"x-forwarded-for\", \"forwarded\", \"none\""
            )),
        }
    }
}

/// Addresses whose mTLS header is believed: single addresses or CIDR
/// blocks.
///
/// Both sides are canonicalised before comparing. A proxy on 127.0.0.1
/// reaching a server bound to `[::]` arrives as `::ffff:127.0.0.1`, and
/// an exact `IpAddr` comparison would silently never match — the mTLS
/// binding would look configured and be off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(hxd_core::AddrSet);

impl TrustedProxies {
    /// Parse `"192.0.2.7"`, `"10.0.0.0/8"`, `"2001:db8::/32"`. The error
    /// names the offending entry; it reaches the operator at startup.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, String> {
        hxd_core::AddrSet::parse(entries)
            .map(TrustedProxies)
            .map_err(|e| format!("trusted_proxies: {e}"))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, peer: IpAddr) -> bool {
        self.0.contains(peer)
    }
}

impl Default for NgConfig {
    fn default() -> Self {
        NgConfig {
            server_name: "hxd-ng".into(),
            web_client: None,
            agreement: None,
            login_timeout: Duration::from_secs(10),
            grace: Duration::from_secs(300),
            max_detached_per_addr: 2,
            caps: Vec::new(),
            trusted_proxies: TrustedProxies::default(),
            forwarded_header: ForwardedHeader::default(),
            http_limits: HttpLimits::default(),
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
    /// The enrollment mailbox, when `[identity] enroll` is on. `None`
    /// means the `/identity/enroll` routes 404 and discovery omits the
    /// endpoint. It holds no keys and reads nothing else on the server,
    /// so it is beside `identity` rather than inside it — a registrar
    /// would mount this and nothing more.
    pub enroll: Option<Arc<enroll::Mailbox>>,
    /// Shared read-only file source and authorization registries.
    pub files: Option<Arc<hxd_files::FileService>>,
    /// What to tell a client about push, when a gateway is configured.
    /// `None` means the capability is absent, the login reply has no
    /// `push` block, and `push_register` answers `not_available`.
    pub push: Option<Arc<push::PushInfo>>,
    /// The registrar, when `[registrar]` is configured. `None` means the
    /// `/registrar` routes 404 and discovery's `registrar` block is
    /// `null`. Beside `identity` rather than inside it for the mailbox's
    /// reason: it reads no account and knows no session.
    pub registrar: Option<Arc<hxd_registrar::Registrar>>,
    /// The server banner, when `[banner]` is configured. `None` means the
    /// `banner` capability is absent and `GET /banner` is 404.
    pub banner: Option<Arc<dyn banner::BannerSource>>,
    /// The server's numbers, when built with the `metrics` feature and
    /// `[metrics]` is configured. `None` means `GET /metrics` is 404.
    pub metrics: Option<Arc<dyn metrics::MetricsSource>>,
}

/// Accept loop: one connection task per socket. Each is HTTP until it
/// upgrades (`http.rs`), and holds its places in [`HttpLimits`]' counts
/// until it closes. Never returns: an accept error — descriptors
/// exhausted, most often, which the counts make hard for anyone but a
/// crowd to cause, and the classic port or the databases might anyway —
/// is waited out. Returned, it ended this task, and the ng port stopped
/// answering while the rest of the server ran on without it.
pub async fn serve(listener: TcpListener, ctx: NgCtx) {
    let gates = Arc::new(http::Gates::new(&ctx));
    let mut backoff = Duration::from_millis(10);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => {
                backoff = Duration::from_millis(10);
                accepted
            }
            Err(e) => {
                warn!("ng accept failed; retrying: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let ctx = ctx.clone();
        let gates = gates.clone();
        tokio::spawn(async move {
            let span = tracing::info_span!("ng", %peer);
            http::serve_connection(stream, peer, ctx, gates)
                .instrument(span)
                .await;
        });
    }
}

/// The periodic maintenance the binary runs: end detached sessions whose
/// grace lapsed, and drop registry entries whose sessions are gone.
pub async fn sweeper(
    core: Arc<Core>,
    registry: Arc<Registry>,
    grace: Duration,
    enroll: Option<Arc<enroll::Mailbox>>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let ended = core.sweep_detached(grace);
        if ended > 0 {
            info!(ended, "detached sessions swept");
        }
        registry.prune(&core);
        // Every mailbox call sweeps what it touches, so this is only for
        // a mailbox nobody is using — where the sessions would otherwise
        // sit until someone happened to open another.
        if let Some(mb) = enroll.as_ref() {
            let dropped = mb.sweep();
            if dropped > 0 {
                info!(dropped, "enrollment sessions expired");
            }
        }
    }
}

/// `tokio::task::spawn_blocking`, with the pool's queue time and
/// occupancy reported under `what` (`hxd_core::instrument::blocking`).
pub(crate) fn spawn_blocking<R: Send + 'static>(
    what: &'static str,
    f: impl FnOnce() -> R + Send + 'static,
) -> tokio::task::JoinHandle<R> {
    tokio::task::spawn_blocking(hxd_core::instrument::blocking(what, f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_forwarded_header_is_named_by_the_operator() {
        assert_eq!(
            ForwardedHeader::parse("x-forwarded-for").unwrap(),
            ForwardedHeader::XForwardedFor
        );
        // The default is what the stock proxy directives write.
        assert_eq!(ForwardedHeader::default(), ForwardedHeader::XForwardedFor);
        // Spelling is the operator's, not ours.
        assert_eq!(
            ForwardedHeader::parse(" X_Forwarded_For ").unwrap(),
            ForwardedHeader::XForwardedFor
        );
        assert_eq!(
            ForwardedHeader::parse("Forwarded").unwrap(),
            ForwardedHeader::Forwarded
        );
        assert_eq!(
            ForwardedHeader::parse("none").unwrap(),
            ForwardedHeader::None
        );
        // And a typo is a startup error naming the value, not a silent
        // fallback to believing the wrong header.
        let e = ForwardedHeader::parse("x-real-ip").unwrap_err();
        assert!(e.contains("x-real-ip"), "{e}");
    }

    #[test]
    fn trusted_proxies_match_by_prefix_and_across_ipv4_mapping() {
        let t = TrustedProxies::parse(&["127.0.0.1", "10.0.0.0/8", "2001:db8::/32"]).unwrap();
        assert!(t.contains("127.0.0.1".parse().unwrap()));
        assert!(!t.contains("127.0.0.2".parse().unwrap()));
        assert!(t.contains("10.9.8.7".parse().unwrap()));
        assert!(!t.contains("11.0.0.1".parse().unwrap()));
        assert!(t.contains("2001:db8::5".parse().unwrap()));
        assert!(!t.contains("2001:db9::5".parse().unwrap()));
        // A `[::]` bind reports IPv4 peers in their mapped form; §12 says
        // those match the IPv4 entry, and the proxy is usually loopback.
        assert!(t.contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(t.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!t.contains("::ffff:11.1.2.3".parse().unwrap()));
        // And a mapped entry in the config matches a plain IPv4 peer.
        let t = TrustedProxies::parse(&["::ffff:192.0.2.7"]).unwrap();
        assert!(t.contains("192.0.2.7".parse().unwrap()));

        // Prefixes that aren't whole octets.
        let t = TrustedProxies::parse(&["192.0.2.0/26"]).unwrap();
        assert!(t.contains("192.0.2.63".parse().unwrap()));
        assert!(!t.contains("192.0.2.64".parse().unwrap()));

        assert!(TrustedProxies::parse(&["10.0.0.0/33"]).is_err());
        assert!(TrustedProxies::parse(&["not-an-address"]).is_err());
        assert!(TrustedProxies::default().is_empty());
        assert!(!TrustedProxies::default().contains("127.0.0.1".parse().unwrap()));
    }
}
