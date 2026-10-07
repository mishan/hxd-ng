//! Dialing a peer (`docs/server-link.md` §7.2): TCP, TLS 1.3, the TRTP
//! handshake, a Login (107) with bit 11 and the key proof, then the link,
//! and again with backoff when it ends.

use std::sync::Arc;
use std::time::Duration;

use hxd_session::frame::{pack_frame, read_frame};
use hxd_session::{cap, Caps};
use hxproto::messages::{tag, ClientHdr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::{
    ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, ProtocolVersion, SignatureScheme};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::hub::{Hub, PeerEntry};
use crate::key::{check_public, verify_proof, Role, EXPORTER_LABEL, EXPORTER_LEN};
use crate::wire::{field, Reason};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_RETRY: Duration = Duration::from_secs(1);
const SLOWEST: Duration = Duration::from_secs(300);
/// The slowest a peer this dialer has been linked to is tried again: an
/// outage past the grace should end in a link as soon as the peer is
/// back, not when a backoff that doubled through it next comes round.
/// Slow enough that a peer gone for good costs one handshake a while.
const RELINK_SLOWEST: Duration = Duration::from_secs(30);

/// Why a dial ended, and so how soon to try again.
enum Next {
    /// The link came up and later ended: start the backoff over.
    Again,
    /// It never came up: back off.
    Backoff,
    /// A refusal an operator has to look at (a key that did not check, a
    /// login refused, `Suspended`): keep trying, at the slowest pace.
    Slow,
    /// `Unlinked`, `VersionUnsupported` or `Replaced`: not without an
    /// operator.
    Stop,
}

pub(crate) async fn dial_loop(hub: Hub, peer: String) {
    let unconfigured = dial(&hub, &peer).await;
    hub.dialer_stopped(&peer);
    // A reload that put the entry back while this loop was finding it gone
    // started no dialer, since this one still counted.
    if unconfigured && hub.entry(&peer).is_some_and(|e| e.dial.is_some()) {
        hub.spawn_dialer(peer);
    }
}

/// Dial until the link ends for good. True when it ends because the
/// entry is gone, false when the peer said not to come back.
async fn dial(hub: &Hub, peer: &str) -> bool {
    let mut wait = FIRST_RETRY;
    let mut linked = false;
    loop {
        // A stopping server dials nobody: its peers hold its users.
        if hub.shutting_down() {
            return false;
        }
        // Re-read each time: SIGHUP may have changed or removed the entry.
        let Some(entry) = hub.entry(peer).filter(|e| e.dial.is_some()) else {
            info!(%peer, "no longer configured; not dialing");
            return true;
        };
        let next = dial_once(hub, &entry, &mut linked).await;
        if matches!(next, Next::Stop) {
            warn!(peer = %entry.name, "not redialing without an operator");
            return false;
        }
        wait = next_wait(wait, next, hub.holding(peer), linked);
        tokio::time::sleep(jitter(wait)).await;
    }
}

/// How long to wait before dialing again. While an interrupted link's
/// servers and ghosts are held for the grace period, the peer is tried at
/// least every quarter of it: an outage that ends inside the grace must
/// come back inside it too, not whenever a backoff that doubled through
/// the outage next gets round to it, by which time a short outage may
/// have outlasted the grace and become a netsplit. Past the grace, a peer
/// once linked is still tried at least every `RELINK_SLOWEST`.
fn next_wait(wait: Duration, next: Next, holding: Option<Duration>, linked: bool) -> Duration {
    let slowest = if linked { RELINK_SLOWEST } else { SLOWEST };
    let wait = match next {
        Next::Again => FIRST_RETRY,
        Next::Backoff => (wait * 2).min(slowest),
        Next::Slow | Next::Stop => SLOWEST,
    };
    match holding {
        Some(grace) => wait.min((grace / 4).max(FIRST_RETRY)),
        None => wait,
    }
}

/// Up to a quarter either way, so dialers that failed together do not
/// retry together.
fn jitter(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    let _ = getrandom::getrandom(&mut b);
    let f = 0.75 + f64::from(u16::from_be_bytes(b)) / f64::from(u16::MAX) / 2.0;
    d.mul_f64(f)
}

/// One dial; `linked` is set once a link it made was established.
async fn dial_once(hub: &Hub, entry: &PeerEntry, linked: &mut bool) -> Next {
    let Some(addr) = entry.dial.as_deref() else {
        return Next::Stop;
    };
    let Ok(peer_key) = check_public(&entry.key) else {
        return Next::Stop;
    };
    let tcp = match timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            info!(peer = %entry.name, "dial failed: {e}");
            return Next::Backoff;
        }
        Err(_) => return Next::Backoff,
    };
    let _ = tcp.set_nodelay(true);
    let peer_addr = match tcp.peer_addr() {
        Ok(a) => a,
        Err(_) => return Next::Backoff,
    };
    let host = addr
        .rsplit_once(':')
        .map_or(addr, |(h, _)| h)
        .trim_start_matches('[')
        .trim_end_matches(']');
    let name = ServerName::try_from(host.to_owned())
        .unwrap_or_else(|_| ServerName::try_from("hotline-link").expect("a valid name"));
    let mut tls = match timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(any_certificate()).connect(name, tcp),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        _ => {
            info!(peer = %entry.name, "TLS handshake failed");
            return Next::Backoff;
        }
    };
    let exporter = {
        let conn = tls.get_ref().1;
        if conn.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            warn!(peer = %entry.name, "peer did not negotiate TLS 1.3; a key-mode link needs it");
            return Next::Slow;
        }
        match conn.export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, Some(&[])) {
            Ok(e) => e,
            Err(_) => return Next::Backoff,
        }
    };

    if tls.write_all(b"TRTPHOTL\x00\x01\x00\x02").await.is_err() {
        return Next::Backoff;
    }
    let mut magic = [0u8; 8];
    match timeout(CONNECT_TIMEOUT, tls.read_exact(&mut magic)).await {
        Ok(Ok(_)) if &magic == b"TRTP\x00\x00\x00\x00" => {}
        _ => return Next::Backoff,
    }

    let caps = Caps::empty()
        .with(cap::TEXT_ENCODING)
        .with(cap::SERVER_LINK);
    let proof = hub.key().prove(Role::Dialer, &exporter, &entry.key);
    let login = pack_frame(
        ClientHdr::Login.as_u32(),
        1,
        0,
        &[
            (tag::LOGIN, entry.account.bytes().map(|b| !b).collect()),
            (tag::CAPABILITIES, caps.to_wire()),
            (field::SERVER_KEY, hub.key().public().to_vec()),
            (field::KEY_PROOF, proof.to_vec()),
        ],
    );
    if tls.write_all(&login).await.is_err() || tls.flush().await.is_err() {
        return Next::Backoff;
    }
    let reply = match timeout(CONNECT_TIMEOUT, read_frame(&mut tls)).await {
        Ok(Ok(f)) => f,
        _ => return Next::Backoff,
    };
    if let Err(why) = check_reply(
        reply.flag,
        &crate::wire::fields(&reply),
        &peer_key,
        &exporter,
        &hub.key().public(),
    ) {
        warn!(peer = %entry.name, "{why}");
        return Next::Slow;
    }

    let (io, tasks) = hxd_session::peer::dialed(tls, peer_addr, hub.budget());
    let end = crate::link::run(hub.clone(), entry.clone(), io).await;
    tasks.close().await;
    *linked |= end.established;
    match end.peer_reason {
        Some(Reason::Unlinked | Reason::VersionUnsupported | Reason::Replaced) => Next::Stop,
        Some(Reason::Suspended) => Next::Slow,
        Some(Reason::Loop | Reason::TagConflict | Reason::HopLimit) => Next::Backoff,
        // A link that failed before it was established, on either side, or
        // soon after, would fail the same way again at once.
        _ if !end.established || end.lasted < crate::link::PING_AFTER => Next::Backoff,
        _ => Next::Again,
    }
}

/// The acceptor's login reply, checked: not a refusal, bits 1 and 11
/// confirmed, and the key the operator configured for the peer proven over
/// this TLS session in the acceptor's role, to this server's key. Anything
/// else is answered at the slowest pace, since an operator has to look.
fn check_reply(
    flag: u32,
    reply: &[crate::wire::Field],
    peer_key: &ed25519_dalek::VerifyingKey,
    exporter: &[u8; EXPORTER_LEN],
    own: &[u8; 32],
) -> Result<(), String> {
    let get = |id| crate::wire::find(reply, id);
    if flag != 0 {
        let text = get(tag::TASK_ERROR)
            .map(|f| String::from_utf8_lossy(&f.data).into_owned())
            .unwrap_or_default();
        return Err(format!("link login refused: {text}"));
    }
    let caps = get(tag::CAPABILITIES).map(|f| Caps::from_wire(&f.data));
    if !caps.is_some_and(|c| c.has(cap::SERVER_LINK) && c.has(cap::TEXT_ENCODING)) {
        return Err("peer did not confirm bits 1 and 11: a configuration error on one side".into());
    }
    let key = get(field::SERVER_KEY).and_then(|f| f.fixed::<32>());
    let proof = get(field::KEY_PROOF).and_then(|f| f.fixed::<64>());
    let proven = key == Some(peer_key.to_bytes())
        && proof.is_some_and(|p| verify_proof(peer_key, Role::Acceptor, exporter, own, &p));
    if !proven {
        return Err("peer's key did not check: possible impersonation".into());
    }
    Ok(())
}

/// Trust any certificate: in key mode the proof authenticates the peer,
/// bound to this TLS session, and the certificate is not asked to.
fn any_certificate() -> Arc<ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    Arc::new(
        ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct AnyCertificate(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Field;
    use crate::LinkKey;

    #[test]
    fn a_held_link_is_redialed_often_enough_to_return_inside_its_grace() {
        let grace = Duration::from_secs(60);
        let mut held = FIRST_RETRY;
        let mut free = FIRST_RETRY;
        for _ in 0..10 {
            held = next_wait(held, Next::Backoff, Some(grace), false);
            free = next_wait(free, Next::Backoff, None, false);
            assert!(held <= grace / 4, "{held:?}");
        }
        assert_eq!(free, SLOWEST);
        // A grace shorter than the first retry does not make a dialer spin.
        let short = next_wait(FIRST_RETRY, Next::Backoff, Some(Duration::ZERO), false);
        assert_eq!(short, FIRST_RETRY);
    }

    #[test]
    fn a_peer_once_linked_is_redialed_soon_after_an_outage_past_its_grace() {
        let mut wait = FIRST_RETRY;
        for _ in 0..10 {
            wait = next_wait(wait, Next::Backoff, None, true);
            assert!(wait <= RELINK_SLOWEST, "{wait:?}");
        }
        // An operator's refusal is still waited out at the slowest pace.
        assert_eq!(next_wait(wait, Next::Slow, None, true), SLOWEST);
    }

    #[test]
    fn a_reply_is_accepted_only_with_the_configured_key_proven_to_this_server() {
        let (us, them, stranger) = (
            LinkKey::from_seed(&[1; 32]),
            LinkKey::from_seed(&[2; 32]),
            LinkKey::from_seed(&[3; 32]),
        );
        let configured = check_public(&them.public()).unwrap();
        let exporter = [7; EXPORTER_LEN];
        let caps = Caps::empty()
            .with(cap::TEXT_ENCODING)
            .with(cap::SERVER_LINK);
        let reply = |key: &LinkKey, proof: [u8; 64], caps: Caps| {
            vec![
                Field::new(tag::CAPABILITIES, caps.to_wire()),
                Field::new(field::SERVER_KEY, key.public()),
                Field::new(field::KEY_PROOF, proof),
            ]
        };
        let good = them.prove(Role::Acceptor, &exporter, &us.public());
        let check = |flag, fields: &[Field]| {
            check_reply(flag, fields, &configured, &exporter, &us.public()).is_ok()
        };

        assert!(check(0, &reply(&them, good, caps)));
        for (why, flag, fields) in [
            ("refused", 1, reply(&them, good, caps)),
            (
                "bit 11 unconfirmed",
                0,
                reply(&them, good, Caps::empty().with(cap::TEXT_ENCODING)),
            ),
            (
                "another key",
                0,
                reply(
                    &stranger,
                    stranger.prove(Role::Acceptor, &exporter, &us.public()),
                    caps,
                ),
            ),
            (
                "the dialer's role",
                0,
                reply(
                    &them,
                    them.prove(Role::Dialer, &exporter, &us.public()),
                    caps,
                ),
            ),
            (
                "another session",
                0,
                reply(
                    &them,
                    them.prove(Role::Acceptor, &[8; EXPORTER_LEN], &us.public()),
                    caps,
                ),
            ),
            (
                "proven to someone else",
                0,
                reply(
                    &them,
                    them.prove(Role::Acceptor, &exporter, &stranger.public()),
                    caps,
                ),
            ),
            ("no proof", 0, reply(&them, good, caps)[..2].to_vec()),
        ] {
            assert!(!check(flag, &fields), "{why}");
        }
    }
}
