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
    dial(&hub, &peer).await;
    hub.dialer_stopped(&peer);
}

async fn dial(hub: &Hub, peer: &str) {
    let mut wait = FIRST_RETRY;
    loop {
        // Re-read each time: SIGHUP may have changed or removed the entry.
        let Some(entry) = hub.entry(peer).filter(|e| e.dial.is_some()) else {
            info!(%peer, "no longer configured; not dialing");
            return;
        };
        let next = dial_once(hub, &entry).await;
        wait = match next {
            Next::Stop => {
                warn!(peer = %entry.name, "not redialing without an operator");
                return;
            }
            Next::Again => FIRST_RETRY,
            Next::Backoff => (wait * 2).min(SLOWEST),
            Next::Slow => SLOWEST,
        };
        tokio::time::sleep(jitter(wait)).await;
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

async fn dial_once(hub: &Hub, entry: &PeerEntry) -> Next {
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
    if reply.flag != 0 {
        let text = reply
            .chunks()
            .find(|c| c.tag == tag::TASK_ERROR)
            .map(|c| String::from_utf8_lossy(c.data).into_owned())
            .unwrap_or_default();
        warn!(peer = %entry.name, "link login refused: {text}");
        return Next::Slow;
    }
    let confirmed = reply
        .chunks()
        .find(|c| c.tag == tag::CAPABILITIES)
        .map(|c| Caps::from_wire(c.data))
        .is_some_and(|c| c.has(cap::SERVER_LINK) && c.has(cap::TEXT_ENCODING));
    if !confirmed {
        warn!(peer = %entry.name, "peer did not confirm bits 1 and 11: a configuration error on one side");
        return Next::Slow;
    }
    let key = reply
        .chunks()
        .find(|c| c.tag == field::SERVER_KEY)
        .map(|c| c.data.to_vec());
    let their_proof: Option<[u8; 64]> = reply
        .chunks()
        .find(|c| c.tag == field::KEY_PROOF)
        .and_then(|c| c.data.try_into().ok());
    let proven = key.as_deref() == Some(entry.key.as_slice())
        && their_proof.is_some_and(|p| {
            verify_proof(
                &peer_key,
                Role::Acceptor,
                &exporter,
                &hub.key().public(),
                &p,
            )
        });
    if !proven {
        warn!(peer = %entry.name, "peer's key did not check: possible impersonation");
        return Next::Slow;
    }

    let (io, tasks) = hxd_session::peer::dialed(tls, peer_addr, hub.budget());
    let end = crate::link::run(hub.clone(), entry.clone(), io).await;
    tasks.close().await;
    match end.peer_reason {
        Some(Reason::Unlinked | Reason::VersionUnsupported | Reason::Replaced) => Next::Stop,
        Some(Reason::Suspended) => Next::Slow,
        Some(Reason::Loop | Reason::TagConflict | Reason::HopLimit) => Next::Backoff,
        // A link that failed before it was established, on either side,
        // would fail the same way again at once.
        _ if !end.established => Next::Backoff,
        _ => Next::Again,
    }
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
