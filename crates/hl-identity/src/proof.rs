//! The login proof (`docs/hotline-ng-auth.md` §6.2): the device key's
//! answer to a server challenge, bound to that server's key and, from
//! `v = 2`, to the host the client addressed, so that a server relaying
//! another's challenge cannot spend the answer there. And the server's
//! side of the same exchange: its key vouching for the challenge it gave
//! a client that addressed it by a host.

use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{DeviceKey, PublicKey, ServerKey};
use crate::signed::{self, Envelope};

/// Both versions of the proof sign under this one domain; `v`, which the
/// signature covers, is what tells them apart.
pub const DOMAIN: &str = "hl-identity/login/v1";
pub const SERVER_DOMAIN: &str = "hl-identity/server-challenge/v1";

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
        let unsigned = map(vec![
            ("v", Some(Value::Uint(v))),
            ("challenge", Some(Value::Bytes(challenge.to_vec()))),
            ("server_key", Some(Value::Bytes(server_key.to_vec()))),
            ("host", host.map(|h| Value::Text(h.to_owned()))),
            ("device", Some(Value::Bytes(device.public().to_vec()))),
            ("time", Some(Value::Uint(time))),
        ]);
        signed::seal(unsigned, |body| device.sign(DOMAIN, body))
    }

    /// Decode and verify the signature against the embedded device key.
    /// Whether that device key is one the server should trust is the
    /// certificate's business (see [`crate::verify_login`]).
    pub fn parse(bytes: &[u8]) -> Result<LoginProof, Error> {
        let env = Envelope::open_upto(bytes, HOST_VERSION)?;
        let v = &env.value;
        let p = LoginProof {
            challenge: signed::bytes32(v, "challenge")?,
            server_key: signed::bytes32(v, "server_key")?,
            // A `v = 1` proof's `host` is an unknown key, ignored on read.
            host: match env.v {
                HOST_VERSION => Some(host_field(v)?),
                _ => None,
            },
            device: signed::bytes32(v, "device")?,
            time: signed::uint(v, "time")?,
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
        if &self.challenge != challenge || &self.server_key != server_key {
            return Err(Error::ChallengeMismatch);
        }
        if let Some(signed_for) = &self.host {
            if host.and_then(canonical_host).as_deref() != Some(signed_for.as_str()) {
                return Err(Error::HostMismatch);
            }
        }
        if self.time.abs_diff(now) > skew {
            return Err(Error::ClockSkew);
        }
        Ok(())
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
}

impl ServerChallenge {
    /// `host` is the request's `Host`, as the server received it.
    pub fn sign(
        key: &ServerKey,
        challenge: &[u8; 32],
        host: &str,
        expires: u64,
    ) -> Result<Vec<u8>, Error> {
        let unsigned = map(vec![
            ("v", Some(Value::Uint(signed::VERSION))),
            ("challenge", Some(Value::Bytes(challenge.to_vec()))),
            ("server_key", Some(Value::Bytes(key.public().to_vec()))),
            ("host", Some(Value::Text(canonical(host)?))),
            ("expires", Some(Value::Uint(expires))),
        ]);
        Ok(signed::seal(unsigned, |body| key.sign(SERVER_DOMAIN, body)))
    }

    /// Decode and verify the signature against the embedded server key;
    /// whether that is the key the client expects is [`Self::check`]'s.
    pub fn parse(bytes: &[u8]) -> Result<ServerChallenge, Error> {
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let c = ServerChallenge {
            challenge: signed::bytes32(v, "challenge")?,
            server_key: signed::bytes32(v, "server_key")?,
            host: host_field(v)?,
            expires: signed::uint(v, "expires")?,
        };
        env.verify(&c.server_key, SERVER_DOMAIN)?;
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
            &ServerChallenge::sign(&key, &ch, "A.example", NOW + 60).unwrap(),
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
}
