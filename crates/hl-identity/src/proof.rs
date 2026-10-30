//! The login proof (`docs/hotline-ng-auth.md` §6.2): the device key's
//! answer to a server challenge, bound to that server's key and, from
//! `v = 2`, to the host the client addressed, so that a server relaying
//! another's challenge cannot spend the answer there. And the server's
//! side of the same exchange: its key vouching for the challenge it gave
//! a client that addressed it by a host. And the two the classic wire's
//! Prove Device makes of them (`docs/proposals/portable-friends.md` §3),
//! the same shapes under domains of their own.

use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{DeviceKey, PublicKey, ServerKey};
use crate::signed::{self, Envelope};

/// Both versions of the proof sign under this one domain; `v`, which the
/// signature covers, is what tells them apart.
pub const DOMAIN: &str = "hl-identity/login/v1";
pub const SERVER_DOMAIN: &str = "hl-identity/server-challenge/v1";
/// A server challenge given over TRTP, by Get Device Challenge.
pub const TRTP_SERVER_DOMAIN: &str = "hl-identity/server-challenge-trtp/v1";
/// The answer to one, by Prove Device.
pub const DEVICE_DOMAIN: &str = "hl-identity/device-proof/v1";

/// The proof that carries `host`.
pub const HOST_VERSION: u64 = 2;

/// The form a host is signed and compared in (§6.2): `host[:port]` as the
/// WHATWG URL Standard serializes it (lowercase, an IDN as its A-label,
/// IPv6 compressed in brackets, a trailing dot kept, which makes it
/// another name), with port 80 or 443 dropped whatever the scheme,
/// because a server behind a TLS proxy cannot tell which of the two the
/// client used. `None` for anything that is not an authority alone.
pub fn canonical_host(authority: &str) -> Option<String> {
    if authority.is_empty() || authority.contains(['/', '\\', '?', '#', '@']) {
        return None;
    }
    let url = url::Url::parse(&format!("http://{authority}/")).ok()?;
    let host = url.host_str().filter(|h| !h.is_empty())?;
    Some(match url.port() {
        Some(port) if port != 443 => format!("{host}:{port}"),
        _ => host.to_owned(),
    })
}

/// A `host` field: present, and already in [`canonical_host`] form, so
/// that two implementations comparing it compare the same bytes.
fn host_field(v: &Value) -> Result<String, Error> {
    let host = signed::text(v, "host")?;
    if canonical_host(&host).as_deref() != Some(host.as_str()) {
        return Err(Error::BadField("host"));
    }
    Ok(host)
}

fn canonical(host: &str) -> Result<String, Error> {
    canonical_host(host).ok_or(Error::BadField("host"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginProof {
    pub challenge: [u8; 32],
    pub server_key: PublicKey,
    /// `None` for a `v = 1` proof, which names no host and so can be
    /// relayed by a server that publishes another's key (§6.2).
    pub host: Option<String>,
    pub device: PublicKey,
    pub time: u64,
}

impl LoginProof {
    /// Build and sign a `v = 2` proof in one step. `host` is the
    /// authority the client sent `challenge` and `auth` to, signed in
    /// [`canonical_host`] form; one that is not an authority is an error.
    pub fn sign(
        device: &DeviceKey,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        host: &str,
        time: u64,
    ) -> Result<Vec<u8>, Error> {
        let host = canonical(host)?;
        Ok(Self::seal(device, challenge, server_key, Some(&host), time))
    }

    /// A `v = 1` proof, which a server accepts only while it still takes
    /// them from clients that have not moved to `v = 2`.
    pub fn sign_v1(
        device: &DeviceKey,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        time: u64,
    ) -> Vec<u8> {
        Self::seal(device, challenge, server_key, None, time)
    }

    fn seal(
        device: &DeviceKey,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        host: Option<&str>,
        time: u64,
    ) -> Vec<u8> {
        let v = if host.is_some() { HOST_VERSION } else { 1 };
        seal_answer(DOMAIN, v, device, challenge, server_key, host, time, None)
    }

    /// Decode and verify the signature against the embedded device key.
    /// Whether that device key is one the server should trust is the
    /// certificate's business (see [`crate::verify_login`]).
    pub fn parse(bytes: &[u8]) -> Result<LoginProof, Error> {
        let env = Envelope::open_upto(bytes, HOST_VERSION)?;
        let a = Answer::read(&env.value)?;
        let p = LoginProof {
            challenge: a.challenge,
            server_key: a.server_key,
            // A `v = 1` proof's `host` is an unknown key, ignored on read.
            host: match env.v {
                HOST_VERSION => Some(host_field(&env.value)?),
                _ => None,
            },
            device: a.device,
            time: a.time,
        };
        env.verify(&p.device, DOMAIN)?;
        Ok(p)
    }

    /// The server's side: does this proof answer *my* challenge, for *my*
    /// key, at roughly *now*, and — from `v = 2` — for the host the
    /// request carrying it was sent to (`host`, its `Host` header)?
    pub fn check(
        &self,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        host: Option<&str>,
        now: u64,
        skew: u64,
    ) -> Result<(), Error> {
        let answer = Answer {
            challenge: self.challenge,
            server_key: self.server_key,
            device: self.device,
            time: self.time,
        };
        answer.check(challenge, server_key, now, skew, || match &self.host {
            Some(signed_for) => host.and_then(canonical_host).as_deref() == Some(signed_for),
            None => true,
        })
    }
}

/// What a login proof and a device proof both say: which challenge they
/// answer, under which server key, by which device, and when.
struct Answer {
    challenge: [u8; 32],
    server_key: PublicKey,
    device: PublicKey,
    time: u64,
}

impl Answer {
    fn read(v: &Value) -> Result<Answer, Error> {
        Ok(Answer {
            challenge: signed::bytes32(v, "challenge")?,
            server_key: signed::bytes32(v, "server_key")?,
            device: signed::bytes32(v, "device")?,
            time: signed::uint(v, "time")?,
        })
    }

    /// The server's side, in the order a client is best told of: the
    /// challenge and key, then the host (`host_ok`), then the clock.
    fn check(
        &self,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        now: u64,
        skew: u64,
        host_ok: impl FnOnce() -> bool,
    ) -> Result<(), Error> {
        if &self.challenge != challenge || &self.server_key != server_key {
            return Err(Error::ChallengeMismatch);
        }
        if !host_ok() {
            return Err(Error::HostMismatch);
        }
        if self.time.abs_diff(now) > skew {
            return Err(Error::ClockSkew);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_answer(
    domain: &str,
    v: u64,
    device: &DeviceKey,
    challenge: &[u8; 32],
    server_key: &PublicKey,
    host: Option<&str>,
    time: u64,
    exporter: Option<&[u8; 32]>,
) -> Vec<u8> {
    let unsigned = map(vec![
        ("v", Some(Value::Uint(v))),
        ("challenge", Some(Value::Bytes(challenge.to_vec()))),
        ("server_key", Some(Value::Bytes(server_key.to_vec()))),
        ("host", host.map(|h| Value::Text(h.to_owned()))),
        ("device", Some(Value::Bytes(device.public().to_vec()))),
        ("time", Some(Value::Uint(time))),
        ("exporter", exporter.map(|e| Value::Bytes(e.to_vec()))),
    ]);
    signed::seal(unsigned, |body| device.sign(domain, body))
}

/// A device key's answer to a TRTP server challenge
/// (`docs/proposals/portable-friends.md` §3): a `v = 2` login proof's
/// fields at `v = 1` under [`DEVICE_DOMAIN`], so that neither is ever
/// taken for the other, and on a TLS 1.3 connection its exporter value,
/// so that it cannot be carried onto another connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProof {
    pub challenge: [u8; 32],
    pub server_key: PublicKey,
    pub host: String,
    pub device: PublicKey,
    pub time: u64,
    pub exporter: Option<[u8; 32]>,
}

impl DeviceProof {
    /// `host` is the authority the client dialed, signed in
    /// [`canonical_host`] form; `exporter` the connection's, on TLS 1.3.
    pub fn sign(
        device: &DeviceKey,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        host: &str,
        time: u64,
        exporter: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, Error> {
        let host = canonical(host)?;
        Ok(seal_answer(
            DEVICE_DOMAIN,
            signed::VERSION,
            device,
            challenge,
            server_key,
            Some(&host),
            time,
            exporter,
        ))
    }

    /// Decode and verify the signature against the embedded device key.
    pub fn parse(bytes: &[u8]) -> Result<DeviceProof, Error> {
        let env = Envelope::open(bytes)?;
        let a = Answer::read(&env.value)?;
        let p = DeviceProof {
            challenge: a.challenge,
            server_key: a.server_key,
            host: host_field(&env.value)?,
            device: a.device,
            time: a.time,
            exporter: signed::opt_bytes32(&env.value, "exporter")?,
        };
        env.verify(&p.device, DEVICE_DOMAIN)?;
        Ok(p)
    }

    /// The server's side: does this answer the challenge the session
    /// holds, for this server's key and the `host` it was given for, on
    /// this connection (`exporter`, the server's own value, present only
    /// on TLS 1.3), at roughly `now`?
    pub fn check(
        &self,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        host: &str,
        exporter: Option<&[u8; 32]>,
        now: u64,
        skew: u64,
    ) -> Result<(), Error> {
        if self.exporter.as_ref() != exporter {
            return Err(Error::ChallengeMismatch);
        }
        let answer = Answer {
            challenge: self.challenge,
            server_key: self.server_key,
            device: self.device,
            time: self.time,
        };
        answer.check(challenge, server_key, now, skew, || {
            canonical_host(host).as_deref() == Some(self.host.as_str())
        })
    }
}

/// The server's answer to `challenge` (§6.2), signed with its key: the
/// proof that the server a client addressed as `host` holds the key it
/// names, which a client checks before it signs anything for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerChallenge {
    pub challenge: [u8; 32],
    pub server_key: PublicKey,
    pub host: String,
    pub expires: u64,
    /// The commitment to the key that will follow `server_key`
    /// (`server-key-handover.md` §2).
    pub next: Option<[u8; 32]>,
}

impl ServerChallenge {
    /// `host` is the request's `Host`, as the server received it.
    pub fn sign(
        key: &ServerKey,
        challenge: &[u8; 32],
        host: &str,
        expires: u64,
        next: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, Error> {
        Self::sign_under(SERVER_DOMAIN, key, challenge, host, expires, next)
    }

    /// [`Self::sign`] for Get Device Challenge, under
    /// [`TRTP_SERVER_DOMAIN`]: `host` is the one the client said it
    /// dialed.
    pub fn sign_trtp(
        key: &ServerKey,
        challenge: &[u8; 32],
        host: &str,
        expires: u64,
        next: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, Error> {
        Self::sign_under(TRTP_SERVER_DOMAIN, key, challenge, host, expires, next)
    }

    fn sign_under(
        domain: &str,
        key: &ServerKey,
        challenge: &[u8; 32],
        host: &str,
        expires: u64,
        next: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, Error> {
        let unsigned = map(vec![
            ("v", Some(Value::Uint(signed::VERSION))),
            ("challenge", Some(Value::Bytes(challenge.to_vec()))),
            ("server_key", Some(Value::Bytes(key.public().to_vec()))),
            ("host", Some(Value::Text(canonical(host)?))),
            ("expires", Some(Value::Uint(expires))),
            ("next", next.map(|n| Value::Bytes(n.to_vec()))),
        ]);
        Ok(signed::seal(unsigned, |body| key.sign(domain, body)))
    }

    /// Decode and verify the signature against the embedded server key;
    /// whether that is the key the client expects is [`Self::check`]'s.
    pub fn parse(bytes: &[u8]) -> Result<ServerChallenge, Error> {
        Self::parse_under(bytes, SERVER_DOMAIN)
    }

    /// [`Self::parse`] for a challenge Get Device Challenge answered with.
    pub fn parse_trtp(bytes: &[u8]) -> Result<ServerChallenge, Error> {
        Self::parse_under(bytes, TRTP_SERVER_DOMAIN)
    }

    fn parse_under(bytes: &[u8], domain: &str) -> Result<ServerChallenge, Error> {
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let c = ServerChallenge {
            challenge: signed::bytes32(v, "challenge")?,
            server_key: signed::bytes32(v, "server_key")?,
            host: host_field(v)?,
            expires: signed::uint(v, "expires")?,
            next: signed::opt_bytes32(v, "next")?,
        };
        env.verify(&c.server_key, domain)?;
        Ok(c)
    }

    /// The client's side: is this the challenge it was given, under the
    /// key it was told, for the host it addressed, and not yet expired?
    pub fn check(
        &self,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        host: &str,
        now: u64,
        skew: u64,
    ) -> Result<(), Error> {
        if &self.challenge != challenge || &self.server_key != server_key {
            return Err(Error::ChallengeMismatch);
        }
        if canonical_host(host).as_deref() != Some(self.host.as_str()) {
            return Err(Error::HostMismatch);
        }
        if self.expires.saturating_add(skew) < now {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn proof_binds_challenge_server_and_host() {
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let srv = ServerKey::from_seed(&[5u8; 32]).public();
        let other = ServerKey::from_seed(&[6u8; 32]).public();
        let ch = [0xabu8; 32];
        let p =
            LoginProof::parse(&LoginProof::sign(&dev, &ch, &srv, "A.example:443", NOW).unwrap())
                .unwrap();
        assert_eq!(p.host.as_deref(), Some("a.example"));
        let later = NOW + 100;
        for (name, ch, key, host, now, want) in [
            ("as sent", ch, srv, Some("a.example"), later, Ok(())),
            (
                "Host in another case, port 80",
                ch,
                srv,
                Some("A.EXAMPLE:80"),
                later,
                Ok(()),
            ),
            (
                "another challenge",
                [0; 32],
                srv,
                Some("a.example"),
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "another server key",
                ch,
                other,
                Some("a.example"),
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "relayed by b",
                ch,
                srv,
                Some("b.example"),
                later,
                Err(Error::HostMismatch),
            ),
            (
                "another port",
                ch,
                srv,
                Some("a.example:5700"),
                later,
                Err(Error::HostMismatch),
            ),
            ("no Host", ch, srv, None, later, Err(Error::HostMismatch)),
            (
                "stale",
                ch,
                srv,
                Some("a.example"),
                NOW + 1000,
                Err(Error::ClockSkew),
            ),
        ] {
            assert_eq!(p.check(&ch, &key, host, now, 300), want, "{name}");
        }
    }

    #[test]
    fn a_v1_proof_names_no_host_and_is_held_to_none() {
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let srv = ServerKey::from_seed(&[5u8; 32]).public();
        let ch = [0xabu8; 32];
        let p = LoginProof::parse(&LoginProof::sign_v1(&dev, &ch, &srv, NOW)).unwrap();
        assert_eq!(p.host, None);
        assert_eq!(p.check(&ch, &srv, Some("b.example"), NOW, 300), Ok(()));
    }

    /// A `v = 2` map built by hand, signed properly, so that what is
    /// refused is its `host` and not its signature.
    fn v2_with(host: Option<Value>) -> Vec<u8> {
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let unsigned = map(vec![
            ("v", Some(Value::Uint(HOST_VERSION))),
            ("challenge", Some(Value::Bytes(vec![1; 32]))),
            ("server_key", Some(Value::Bytes(vec![2; 32]))),
            ("host", host),
            ("device", Some(Value::Bytes(dev.public().to_vec()))),
            ("time", Some(Value::Uint(NOW))),
        ]);
        signed::seal(unsigned, |body| dev.sign(DOMAIN, body))
    }

    #[test]
    fn a_v2_proof_must_carry_a_canonical_host() {
        for (name, host, want) in [
            ("missing", None, Error::MissingField("host")),
            ("not text", Some(Value::Uint(1)), Error::BadField("host")),
            (
                "empty",
                Some(Value::Text(String::new())),
                Error::BadField("host"),
            ),
            (
                "uppercase",
                Some(Value::Text("A.example".into())),
                Error::BadField("host"),
            ),
            (
                "default port",
                Some(Value::Text("a.example:443".into())),
                Error::BadField("host"),
            ),
            (
                "a URL",
                Some(Value::Text("https://a.example".into())),
                Error::BadField("host"),
            ),
            (
                "a U-label",
                Some(Value::Text("b\u{fc}cher.example".into())),
                Error::BadField("host"),
            ),
        ] {
            assert_eq!(LoginProof::parse(&v2_with(host)), Err(want), "{name}");
        }
        let ok = LoginProof::parse(&v2_with(Some(Value::Text("[2001:db8::1]:5700".into()))));
        assert_eq!(ok.unwrap().host.as_deref(), Some("[2001:db8::1]:5700"));
    }

    #[test]
    fn canonical_hosts() {
        for (given, want) in [
            ("HL.Example", Some("hl.example")),
            ("hl.example:443", Some("hl.example")),
            ("hl.example:80", Some("hl.example")),
            ("hl.example:080", Some("hl.example")),
            ("hl.example:5700", Some("hl.example:5700")),
            ("hl.example.", Some("hl.example.")),
            ("[2001:DB8:0:0:0:0:0:1]:443", Some("[2001:db8::1]")),
            ("[::1]:5700", Some("[::1]:5700")),
            ("[fe80::1%25eth0]", None),
            ("127.0.0.1:80", Some("127.0.0.1")),
            ("b\u{fc}cher.example", Some("xn--bcher-kva.example")),
            ("", None),
            ("hl.example/path", None),
            ("user@hl.example", None),
            ("hl example", None),
            ("hl.example:99999", None),
        ] {
            assert_eq!(canonical_host(given).as_deref(), want, "{given:?}");
        }
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        assert_eq!(
            LoginProof::sign(&dev, &[0; 32], &[0; 32], "https://hl.example", NOW),
            Err(Error::BadField("host"))
        );
    }

    #[test]
    fn a_server_challenge_vouches_for_the_host_it_was_asked_under() {
        let key = ServerKey::from_seed(&[5u8; 32]);
        let srv = key.public();
        let other = ServerKey::from_seed(&[6u8; 32]).public();
        let ch = [0xabu8; 32];
        let c = ServerChallenge::parse(
            &ServerChallenge::sign(&key, &ch, "A.example", NOW + 60, None).unwrap(),
        )
        .unwrap();
        assert_eq!(c.host, "a.example");
        for (name, ch, key, host, now, want) in [
            ("addressed as signed", ch, srv, "a.example:443", NOW, Ok(())),
            (
                "another challenge",
                [0; 32],
                srv,
                "a.example",
                NOW,
                Err(Error::ChallengeMismatch),
            ),
            (
                "another key than discovery's",
                ch,
                other,
                "a.example",
                NOW,
                Err(Error::ChallengeMismatch),
            ),
            (
                "addressed as b",
                ch,
                srv,
                "b.example",
                NOW,
                Err(Error::HostMismatch),
            ),
            (
                "expired",
                ch,
                srv,
                "a.example",
                NOW + 1000,
                Err(Error::Expired),
            ),
        ] {
            assert_eq!(c.check(&ch, &key, host, now, 300), want, "{name}");
        }

        // Signed by a key other than the one it names.
        let forged = map(vec![
            ("v", Some(Value::Uint(1))),
            ("challenge", Some(Value::Bytes(ch.to_vec()))),
            ("server_key", Some(Value::Bytes(other.to_vec()))),
            ("host", Some(Value::Text("a.example".into()))),
            ("expires", Some(Value::Uint(NOW))),
        ]);
        let forged = signed::seal(forged, |body| key.sign(SERVER_DOMAIN, body));
        assert_eq!(ServerChallenge::parse(&forged), Err(Error::BadSignature));
    }

    #[test]
    fn a_device_proof_binds_challenge_server_host_and_connection() {
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let srv = ServerKey::from_seed(&[5u8; 32]).public();
        let other = ServerKey::from_seed(&[6u8; 32]).public();
        let ch = [0xabu8; 32];
        let tls = [0x13u8; 32];
        let sign = |exporter| {
            DeviceProof::parse(
                &DeviceProof::sign(&dev, &ch, &srv, "HL.example:5500", NOW, exporter).unwrap(),
            )
            .unwrap()
        };
        let (plain, bound) = (sign(None), sign(Some(&tls)));
        assert_eq!(plain.host, "hl.example:5500");
        assert_eq!(bound.exporter, Some(tls));
        let later = NOW + 100;
        for (name, p, ch, key, host, exporter, now, want) in [
            (
                "plain",
                &plain,
                ch,
                srv,
                "hl.example:5500",
                None,
                later,
                Ok(()),
            ),
            (
                "on TLS 1.3",
                &bound,
                ch,
                srv,
                "hl.example:5500",
                Some(tls),
                later,
                Ok(()),
            ),
            (
                "another challenge",
                &plain,
                [0; 32],
                srv,
                "hl.example:5500",
                None,
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "another server key",
                &plain,
                ch,
                other,
                "hl.example:5500",
                None,
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "another port",
                &plain,
                ch,
                srv,
                "hl.example:5501",
                None,
                later,
                Err(Error::HostMismatch),
            ),
            (
                "another connection",
                &bound,
                ch,
                srv,
                "hl.example:5500",
                Some([0x14; 32]),
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "an exporter where there is none",
                &bound,
                ch,
                srv,
                "hl.example:5500",
                None,
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "none where there is one",
                &plain,
                ch,
                srv,
                "hl.example:5500",
                Some(tls),
                later,
                Err(Error::ChallengeMismatch),
            ),
            (
                "stale",
                &plain,
                ch,
                srv,
                "hl.example:5500",
                None,
                NOW + 1000,
                Err(Error::ClockSkew),
            ),
        ] {
            let got = p.check(&ch, &key, host, exporter.as_ref(), now, 300);
            assert_eq!(got, want, "{name}");
        }
    }

    /// The classic wire's two objects are the ng port's shapes, and each
    /// is refused by the signature where the other is read.
    #[test]
    fn no_object_verifies_as_its_ng_counterpart() {
        let key = ServerKey::from_seed(&[5u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let ch = [0xabu8; 32];
        let trtp = ServerChallenge::sign_trtp(&key, &ch, "hl.example:5500", NOW, None).unwrap();
        let ng = ServerChallenge::sign(&key, &ch, "hl.example:5500", NOW, None).unwrap();
        assert_eq!(ServerChallenge::parse(&trtp), Err(Error::BadSignature));
        assert_eq!(ServerChallenge::parse_trtp(&ng), Err(Error::BadSignature));
        assert_eq!(
            ServerChallenge::parse_trtp(&trtp).unwrap().host,
            "hl.example:5500"
        );

        let proof = DeviceProof::sign(&dev, &ch, &key.public(), "hl.example:5500", NOW, None);
        assert_eq!(LoginProof::parse(&proof.unwrap()), Err(Error::BadSignature));
        // A login proof with every key a device proof has, at its `v`.
        let login = signed::seal(
            map(vec![
                ("v", Some(Value::Uint(1))),
                ("challenge", Some(Value::Bytes(ch.to_vec()))),
                ("server_key", Some(Value::Bytes(key.public().to_vec()))),
                ("host", Some(Value::Text("hl.example:5500".into()))),
                ("device", Some(Value::Bytes(dev.public().to_vec()))),
                ("time", Some(Value::Uint(NOW))),
            ]),
            |body| dev.sign(DOMAIN, body),
        );
        assert!(LoginProof::parse(&login).is_ok());
        assert_eq!(DeviceProof::parse(&login), Err(Error::BadSignature));
    }
}
