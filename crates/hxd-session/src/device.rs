//! Device proof on the classic wire (`docs/proposals/portable-friends.md`
//! §3): Get Device Challenge (1020) and Prove Device (1021), for a
//! session that negotiated capability bit 14, whatever else it did.
//!
//! What a proof is checked against and whom it admits are the identity
//! state's, behind [`DeviceProver`], which the binary wires to the ng
//! port's, as it wires [`crate::PeerAcceptor`] to the link hub. This
//! crate holds what only the connection knows: the one challenge its
//! session holds, the listener it arrived on and its TLS exporter.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use hxd_core::IdentityTag;
use hxproto::messages::{tag, ClientHdr};
use hxproto::messaging::{MAX_DEVICE_CERT_LEN, MAX_DEVICE_PROOF_LEN, MAX_USER_CARD_LEN};

use crate::frame::Frame;

/// The TLS 1.3 exporter a proof on the TLS port is bound with, with an
/// empty context, labeled as the server link's key proof labels its own.
pub const EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-hl-identity-device-proof";

/// How long a challenge may be answered, as at the ng port.
const CHALLENGE_TTL: Duration = Duration::from_secs(60);

/// The two answers a refused Prove Device has: a clock the user can fix,
/// and everything else alike, so that the answer says nothing of why.
pub(crate) const SKEWED: &str =
    "This device's clock is too far from the server's to prove it. Set the clock and try again.";
pub(crate) const NOT_PROVED: &str = "The device could not be proved.";
/// What a Get Device Challenge this server will not answer is told.
pub(crate) const NO_CHALLENGE: &str = "This server gives no device challenge for that address.";
/// And one past its rate (`Core::device_proof_spend`).
pub(crate) const TOO_MANY: &str = "Too many device challenges. Try again shortly.";

/// Prove Device, as the session read it.
pub struct ProveRequest {
    pub proof: Vec<u8>,
    pub cert: Vec<u8>,
    /// The identity's card, shown to link the account, or `None` for the
    /// one the server holds.
    pub card: Option<Vec<u8>>,
    /// The challenge the session held, and the host it was given for.
    pub challenge: [u8; 32],
    pub host: String,
    /// The connection's exporter value, on TLS 1.3 alone.
    pub exporter: Option<[u8; 32]>,
    /// The session's account.
    pub login: String,
    /// `hotline-ng-auth.md` §8 counts the session encrypted: TLS, or HOPE
    /// with a cipher.
    pub encrypted: bool,
    /// Encrypted as a proof that links must be: TLS 1.3, whose exporter
    /// binds the proof to the connection, or HOPE with a cipher.
    pub may_link: bool,
}

/// Why Prove Device was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProveRefused {
    /// The proof's time is outside the server's clock-skew tolerance.
    ClockSkew,
    Refused,
}

pub trait DeviceProver: Send + Sync + 'static {
    /// `challenge` signed for `host`, the address the client says it
    /// dialed, or `None` where this server does not answer as that host
    /// on `port`, the listener the request arrived on.
    fn challenge(&self, challenge: &[u8; 32], host: &str, port: u16) -> Option<Vec<u8>>;

    /// Check a proof and admit its device to the session, answering the
    /// transport identity the session has from now on.
    fn prove(
        &self,
        req: ProveRequest,
    ) -> Pin<Box<dyn Future<Output = Result<IdentityTag, ProveRefused>> + Send>>;
}

/// What only the connection knows.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Arrival {
    /// The port of the listener it arrived on; `None` through a tunnel,
    /// whose listener is the ng port's.
    pub(crate) port: Option<u16>,
    /// Its exporter value under [`EXPORTER_LABEL`], on TLS 1.3 alone.
    pub(crate) exporter: Option<[u8; 32]>,
    /// It arrived over TLS: on the TLS port, or through a tunnel, whose
    /// exporter is not this server's to read.
    pub(crate) tls: bool,
}

/// The challenge a session holds: one at a time, spent by the proof that
/// answers it or the request that replaces it.
pub(crate) struct Held {
    challenge: [u8; 32],
    host: String,
    at: Instant,
}

pub(crate) fn handles(ty: u32) -> bool {
    ty == ClientHdr::GetDeviceChallenge.as_u32() || ty == ClientHdr::ProveDevice.as_u32()
}

/// The spam points each costs a session that negotiated bit 14: none.
/// They are paced by their own rate (`Core::device_proof_spend`), not
/// kicked for (`docs/proposals/portable-friends.md` §4.3).
pub(crate) fn price(ty: u32) -> Option<u32> {
    handles(ty).then_some(0)
}

/// Get Device Challenge's host, at most `DATA_PROOF_HOST`'s bound.
pub(crate) fn host(f: &Frame) -> Option<String> {
    let c = f.chunks().find(|c| c.tag == tag::PROOF_HOST)?;
    if c.data.len() > hxproto::messaging::MAX_PROOF_HOST_LEN {
        return None;
    }
    String::from_utf8(c.data.to_vec()).ok()
}

/// A challenge for `host` given now.
pub(crate) fn held(challenge: [u8; 32], host: String) -> Held {
    Held {
        challenge,
        host,
        at: Instant::now(),
    }
}

/// Prove Device's fields, answering `held` if it is still current: `None`
/// for a request that cannot be one, which is refused as any other is.
pub(crate) fn request(
    f: &Frame,
    held: Option<Held>,
    arrival: Arrival,
    login: &str,
    encrypted: bool,
) -> Option<ProveRequest> {
    let held = held.filter(|h| h.at.elapsed() < CHALLENGE_TTL)?;
    let field = |t: u16, max: usize| {
        f.chunks()
            .find(|c| c.tag == t)
            .map(|c| c.data.to_vec())
            .filter(|d| !d.is_empty() && d.len() <= max)
    };
    let card = match f.chunks().any(|c| c.tag == tag::USER_CARD) {
        true => Some(field(tag::USER_CARD, MAX_USER_CARD_LEN)?),
        false => None,
    };
    Some(ProveRequest {
        proof: field(tag::DEVICE_PROOF, MAX_DEVICE_PROOF_LEN)?,
        cert: field(tag::DEVICE_CERT, MAX_DEVICE_CERT_LEN)?,
        card,
        challenge: held.challenge,
        host: held.host,
        exporter: arrival.exporter,
        login: login.to_owned(),
        encrypted,
        may_link: encrypted && (arrival.exporter.is_some() || !arrival.tls),
    })
}
