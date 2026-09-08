//! Wiring the SFU into the server.
//!
//! Voice is a Cargo feature as well as a config section, because WebRTC
//! is a non-trivial dependency and a server that doesn't want it
//! shouldn't have to build it. This module is the whole of the feature's
//! surface: with `voice` off, [`Voice`] is an uninhabited type and the
//! rest of the binary compiles unchanged rather than growing `cfg`
//! branches.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use hxd_core::Core;

use crate::Config;

/// Parse and validate the `[voice]` section: the socket to bind, the
/// addresses to advertise as ICE candidates, and the room cap.
///
/// Absent section means voice is off, which is the spec's `EnableVoice`
/// default and the safe one — it is an open UDP port on the internet.
///
/// The addressing rules below are checked here, at startup, because the
/// media plane has no way to complain about them later: a datagram whose
/// local address doesn't match one of the SFU's candidates is dropped
/// inside str0m's ICE agent — after `Rtc::accepts` has already claimed it
/// by ufrag, so it isn't even a stray packet anyone could log. The
/// symptom is a join that gets a perfectly good offer, never connects,
/// and dies on the 30 s ICE timeout, with nothing in the server log but
/// the address it is listening on. An operator can't debug that, so a
/// configuration that can only produce it has to be refused before the
/// port is ever opened — which is what `NoAdvertisableAddress` already
/// does for the emptier version of the same mistake.
pub(crate) fn addresses(config: &Config) -> Result<Option<(SocketAddr, Vec<SocketAddr>)>, String> {
    let Some(v) = &config.voice else {
        return Ok(None);
    };
    // The spec's port convention: base port + 4. Derived from the
    // configured legacy bind so a server that moved its base port gets a
    // matching media port without being told twice.
    let bind: SocketAddr = match &v.bind {
        Some(b) => b.parse().map_err(|e| format!("[voice] bind {b:?}: {e}"))?,
        None => {
            // `[server] bind` is a listen spec, not necessarily a
            // literal address: the legacy listener hands it to
            // `TcpListener::bind`, which takes `localhost:5500` and
            // `example.org:5500` too. Parsing it as a `SocketAddr` here
            // would refuse a config the rest of the server is perfectly
            // happy with — and only when voice was switched on, which is
            // a surprising place to find out. So resolve it the same way
            // the listener does and derive the port from that.
            let base = resolve(&config.server.bind)?;
            let port = base.port().checked_add(4).ok_or_else(|| {
                format!(
                    "[server] bind port {} leaves no room for the voice port \
                     (base + 4); set [voice] bind explicitly",
                    base.port()
                )
            })?;
            SocketAddr::new(base.ip(), port)
        }
    };
    let mut advertise = Vec::new();
    for a in &v.advertise {
        advertise.push(
            a.parse::<SocketAddr>()
                .map_err(|e| format!("[voice] advertise {a:?}: {e}"))?,
        );
    }
    if advertise.is_empty() {
        // A wildcard bind tells a client nothing it can connect to, and
        // ICE-lite means our candidates are all a client ever gets. Say
        // so at startup rather than handing out 0.0.0.0 and letting every
        // session time out.
        if bind.ip().is_unspecified() {
            return Err(format!(
                "[voice] bind is {bind}, so there is no address to advertise: \
                 set [voice] advertise to the address clients reach this server on"
            ));
        }
        advertise.push(bind);
    }
    // A wildcard bind gives the socket no address of its own to report,
    // so the media plane can only decide which advertised address a
    // datagram arrived on by matching address families. Two of a family
    // are therefore indistinguishable, and whichever one loses the guess
    // is unreachable: clients that nominate it are discarded. One address
    // per family is the shape the docs describe ("list both a v4 and a v6
    // address to serve both") and the only one a wildcard can serve, so
    // this refuses a config that was already silently broken.
    if bind.ip().is_unspecified() {
        if let Some((a, b)) = same_family_pair(&advertise) {
            return Err(format!(
                "[voice] bind is {bind}, so an incoming datagram can only be matched to \
                 an advertised address by family, and {a} and {b} share one: give each \
                 address its own concrete [voice] bind, or advertise one address per family"
            ));
        }
    }
    Ok(Some((bind, advertise)))
}

/// The first two advertised addresses of the same family, if any — the
/// pair a wildcard bind cannot tell apart.
fn same_family_pair(advertise: &[SocketAddr]) -> Option<(SocketAddr, SocketAddr)> {
    for (i, a) in advertise.iter().enumerate() {
        for b in &advertise[i + 1..] {
            if a.is_ipv4() == b.is_ipv4() {
                return Some((*a, *b));
            }
        }
    }
    None
}

/// `[server] bind` as an address, resolving a host name the way the
/// legacy listener will. The first answer wins, as it does for
/// `TcpListener::bind`.
fn resolve(spec: &str) -> Result<SocketAddr, String> {
    let hint = |why: String| {
        format!(
            "[server] bind {spec:?} can't be resolved to derive the voice port ({why}); \
             set [voice] bind explicitly"
        )
    };
    spec.to_socket_addrs()
        .map_err(|e| hint(e.to_string()))?
        .next()
        .ok_or_else(|| hint("it names no address".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerSection, VoiceSection};

    fn config(server_bind: &str, voice: Option<VoiceSection>) -> Config {
        Config {
            server: ServerSection {
                bind: server_bind.into(),
                ..ServerSection::default()
            },
            paths: Default::default(),
            ng: None,
            voice,
            identity: None,
            inbox: None,
        }
    }

    fn voice_section(bind: Option<&str>, advertise: &[&str]) -> VoiceSection {
        VoiceSection {
            bind: bind.map(str::to_string),
            advertise: advertise.iter().map(|s| s.to_string()).collect(),
            max_per_room: 16,
            video: None,
        }
    }

    #[test]
    fn no_section_means_no_voice() {
        assert_eq!(addresses(&config("0.0.0.0:5500", None)), Ok(None));
    }

    #[test]
    fn the_default_port_is_the_legacy_one_plus_four() {
        let c = config("127.0.0.1:5500", Some(voice_section(None, &[])));
        let (bind, advertise) = addresses(&c).unwrap().unwrap();
        assert_eq!(bind, "127.0.0.1:5504".parse().unwrap());
        assert_eq!(advertise, vec![bind]);
    }

    #[test]
    fn a_named_host_in_the_server_bind_is_resolved_not_rejected() {
        // `bind = "localhost:5500"` is a config the legacy listener
        // accepts, so switching voice on must not be what makes it
        // invalid.
        let c = config("localhost:5500", Some(voice_section(None, &[])));
        let (bind, _) = addresses(&c)
            .expect("a host name the listener would accept")
            .unwrap();
        assert!(bind.ip().is_loopback());
        assert_eq!(bind.port(), 5504);
    }

    #[test]
    fn a_server_bind_that_resolves_to_nothing_says_what_to_do_about_it() {
        // Unresolvable rather than merely unparseable, and deliberately
        // decided without asking a DNS server: this is the branch an
        // operator hits when the name in `[server] bind` is wrong, and
        // the error has to name the way out of it.
        let c = config("localhost", Some(voice_section(None, &[])));
        let err = addresses(&c).unwrap_err();
        assert!(err.contains("set [voice] bind explicitly"), "{err}");
    }

    #[test]
    fn a_wildcard_bind_with_nothing_advertised_is_refused() {
        let c = config("0.0.0.0:5500", Some(voice_section(None, &[])));
        let err = addresses(&c).unwrap_err();
        assert!(err.contains("advertise"), "{err}");
    }

    #[test]
    fn a_wildcard_bind_advertising_two_addresses_of_one_family_is_refused() {
        // The dual-homed host: both addresses are real and reachable, but
        // a wildcard socket can't say which one a datagram came in on, so
        // one of the two would silently never connect.
        let c = config(
            "0.0.0.0:5500",
            Some(voice_section(
                None,
                &["198.51.100.9:5504", "203.0.113.7:5504"],
            )),
        );
        let err = addresses(&c).unwrap_err();
        assert!(err.contains("198.51.100.9:5504"), "{err}");
        assert!(err.contains("203.0.113.7:5504"), "{err}");
        assert!(err.contains("one address per family"), "{err}");
    }

    #[test]
    fn a_wildcard_bind_may_advertise_one_address_per_family() {
        // The documented way to serve v4 and v6 clients from a single
        // socket, which the same-family check must not catch.
        let c = config(
            "0.0.0.0:5500",
            Some(voice_section(
                None,
                &["198.51.100.9:5504", "[2001:db8::1]:5504"],
            )),
        );
        let (_, advertise) = addresses(&c).unwrap().unwrap();
        assert_eq!(advertise.len(), 2);
    }

    #[test]
    fn a_concrete_bind_may_advertise_as_many_addresses_as_it_likes() {
        // With a real address on the socket the media plane knows what it
        // received a datagram on without guessing, so several addresses
        // of one family — a NAT's public address alongside the private
        // one, say — are fine.
        let c = config(
            "127.0.0.1:5500",
            Some(voice_section(
                Some("10.0.0.5:5504"),
                &["203.0.113.7:5504", "10.0.0.5:5504"],
            )),
        );
        let (bind, advertise) = addresses(&c).unwrap().unwrap();
        assert_eq!(bind, "10.0.0.5:5504".parse().unwrap());
        assert_eq!(advertise.len(), 2);
    }

    #[test]
    fn an_explicit_voice_bind_is_taken_as_written() {
        let c = config(
            "localhost:5500",
            Some(voice_section(Some("198.51.100.9:7000"), &[])),
        );
        let (bind, advertise) = addresses(&c).unwrap().unwrap();
        assert_eq!(bind, "198.51.100.9:7000".parse().unwrap());
        assert_eq!(advertise, vec![bind]);
    }
}

#[cfg(feature = "voice")]
mod imp {
    use super::*;
    use hxd_core::video::VideoConfig;
    use hxd_core::voice::MediaEvent;
    use hxd_core::VoiceMedia;
    use hxd_voice::Sfu;
    use tokio::sync::mpsc::UnboundedReceiver;

    /// A configured voice subsystem, socket already bound.
    pub struct Voice {
        sfu: Arc<Sfu>,
        events: UnboundedReceiver<MediaEvent>,
        socket: std::net::UdpSocket,
        bind: SocketAddr,
        max_per_room: usize,
    }

    /// `None` when voice isn't configured.
    pub fn build(config: &Config) -> Result<Option<Voice>, String> {
        let Some((bind, advertise)) = addresses(config)? else {
            return Ok(None);
        };
        let max_per_room = config
            .voice
            .as_ref()
            .map_or(hxd_core::DEFAULT_MAX_PER_ROOM, |v| v.max_per_room);
        let video = config
            .voice
            .as_ref()
            .map_or_else(VideoConfig::default, |v| v.video_config());
        // The bind address goes in as a local candidate that is never
        // advertised. A server behind NAT binds a private address and
        // advertises the public one it is port-forwarded from, and ICE
        // discards an inbound STUN request whose destination is not one
        // of its local candidates — silently, inside the agent, after the
        // datagram has already been claimed by ufrag. Naming it here is
        // what makes that configuration work; not advertising it is what
        // keeps the offer honest, since a client should still only ever
        // be pointed at an address the operator says it can reach.
        let (sfu, events) = Sfu::with_locals(
            &advertise,
            &[bind],
            video,
            Box::new(std::time::Instant::now),
        )
        .map_err(|e| e.to_string())?;
        // Bind here, not in `serve`. Everything downstream — the
        // capability bit on both wires, `Core::with_voice`, the room
        // state — is a promise that a join will work, and a port that
        // turns out to be taken would leave those promises made and the
        // pump never running: no media, and (because the pump is what
        // drives the clock) no session timeouts either. Failing at
        // startup is the honest answer.
        let socket =
            std::net::UdpSocket::bind(bind).map_err(|e| format!("[voice] bind {bind}: {e}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("[voice] bind {bind}: {e}"))?;
        Ok(Some(Voice {
            sfu,
            events,
            socket,
            bind,
            max_per_room,
        }))
    }

    impl Voice {
        pub fn media(&self) -> Arc<dyn VoiceMedia> {
            self.sfu.clone()
        }

        pub fn max_per_room(&self) -> usize {
            self.max_per_room
        }

        pub fn bind(&self) -> SocketAddr {
            self.bind
        }

        /// Run the SFU: the UDP pump, plus the task that feeds what the
        /// media plane notices back into the domain.
        ///
        /// The two directions are separate tasks on purpose. The SFU is
        /// called *into* with the roster lock held, so it must never call
        /// back; everything it has to say arrives here instead, on a
        /// channel, and is delivered by a task that takes the roster lock
        /// itself.
        pub async fn serve(self, core: Arc<Core>) -> std::io::Result<()> {
            let socket = tokio::net::UdpSocket::from_std(self.socket)?;
            let mut events = self.events;
            tokio::spawn(async move {
                while let Some(ev) = events.recv().await {
                    core.voice_media_event(ev);
                }
            });
            hxd_voice::run(self.sfu, socket).await
        }
    }
}

#[cfg(not(feature = "voice"))]
mod imp {
    use super::*;
    use hxd_core::VoiceMedia;

    /// The voice subsystem, in a build without it: a type nothing can
    /// construct, so every use site type-checks and none can run.
    pub enum Voice {}

    pub fn build(config: &Config) -> Result<Option<Voice>, String> {
        // Validate the section anyway, so a config that asks for voice
        // gets told this build can't serve it instead of starting a
        // server that quietly has none.
        if addresses(config)?.is_some() {
            return Err("[voice] is configured but this build has no voice support \
                 (rebuild with --features voice)"
                .into());
        }
        Ok(None)
    }

    impl Voice {
        pub fn media(&self) -> Arc<dyn VoiceMedia> {
            match *self {}
        }
        pub fn max_per_room(&self) -> usize {
            match *self {}
        }
        pub fn bind(&self) -> SocketAddr {
            match *self {}
        }
        pub async fn serve(self, _core: Arc<Core>) -> std::io::Result<()> {
            match self {}
        }
    }
}

pub use imp::{build, Voice};
