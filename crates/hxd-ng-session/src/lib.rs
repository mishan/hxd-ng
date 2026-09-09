//! The Hotline-ng frontend: WebSocket/JSON sessions over `hxd-core`, with
//! the detach/resume machinery the legacy wire can't express. Protocol
//! spec: `docs/hotline-ng.md`. Sibling of `hxd-session` (the legacy
//! frontend); both speak to the same domain core, so legacy and ng users
//! share one roster and one chat.

mod conn;
pub mod enroll;
mod http;
pub mod identity;
pub mod media;
pub mod proto;
mod registry;
mod tunnel;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use hxd_core::{AuthBackend, Core, LinkAuthority, Transport};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{info, Instrument};

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
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
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
    /// version-sniffing (`docs/hotline-ng.md` §11). The ng twin of the
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
pub struct TrustedProxies(Vec<(IpAddr, u32)>);

impl TrustedProxies {
    /// Parse `"192.0.2.7"`, `"10.0.0.0/8"`, `"2001:db8::/32"`. The error
    /// names the offending entry; it reaches the operator at startup.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, String> {
        let mut out = Vec::new();
        for e in entries {
            let e = e.as_ref().trim();
            let (addr, prefix) = match e.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (e, None),
            };
            let addr: IpAddr = addr
                .parse()
                .map_err(|_| format!("trusted_proxies: {e:?} is not an IP address"))?;
            let addr = addr.to_canonical();
            let full = if addr.is_ipv4() { 32 } else { 128 };
            let bits = match prefix {
                None => full,
                Some(p) => {
                    let bits: u32 = p
                        .parse()
                        .map_err(|_| format!("trusted_proxies: {e:?} has a bad prefix length"))?;
                    if bits > full {
                        return Err(format!("trusted_proxies: {e:?} prefix exceeds {full} bits"));
                    }
                    bits
                }
            };
            out.push((addr, bits));
        }
        Ok(TrustedProxies(out))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.0
            .iter()
            .any(|(net, bits)| prefix_eq(peer, *net, *bits))
    }
}

fn prefix_eq(a: IpAddr, b: IpAddr, bits: u32) -> bool {
    fn octets(ip: IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        }
    }
    if a.is_ipv4() != b.is_ipv4() {
        return false;
    }
    let (a, b) = (octets(a), octets(b));
    let (whole, rest) = ((bits / 8) as usize, bits % 8);
    if a[..whole] != b[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    a[whole] & mask == b[whole] & mask
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
