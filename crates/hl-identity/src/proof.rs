//! The login proof (`docs/hotline-ng-auth.md` §6.2): the device key's
//! answer to a server challenge, bound to that server's key so a challenge
//! relayed from elsewhere is useless.

use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{DeviceKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/login/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginProof {
    pub challenge: [u8; 32],
    pub server_key: PublicKey,
    pub device: PublicKey,
    pub time: u64,
}

impl LoginProof {
    /// Build and sign in one step; there is nothing to adjust between.
    pub fn sign(
        device: &DeviceKey,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        time: u64,
    ) -> Vec<u8> {
        let unsigned = map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("challenge", Some(Value::Bytes(challenge.to_vec()))),
            ("server_key", Some(Value::Bytes(server_key.to_vec()))),
            ("device", Some(Value::Bytes(device.public().to_vec()))),
            ("time", Some(Value::Uint(time))),
        ]);
        signed::seal(unsigned, |body| device.sign(DOMAIN, body))
    }

    /// Decode and verify the signature against the embedded device key.
    /// Whether that device key is one the server should trust is the
    /// certificate's business (see [`crate::verify_login`]).
    pub fn parse(bytes: &[u8]) -> Result<LoginProof, Error> {
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let p = LoginProof {
            challenge: signed::bytes32(v, "challenge")?,
            server_key: signed::bytes32(v, "server_key")?,
            device: signed::bytes32(v, "device")?,
            time: signed::uint(v, "time")?,
        };
        env.verify(&p.device, DOMAIN)?;
        Ok(p)
    }

    /// The server's side: does this proof answer *my* challenge, for *my*
    /// key, at roughly *now*?
    pub fn check(
        &self,
        challenge: &[u8; 32],
        server_key: &PublicKey,
        now: u64,
        skew: u64,
    ) -> Result<(), Error> {
        if &self.challenge != challenge || &self.server_key != server_key {
            return Err(Error::ChallengeMismatch);
        }
        if self.time.abs_diff(now) > skew {
            return Err(Error::ClockSkew);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ServerKey;

    #[test]
    fn proof_binds_challenge_and_server() {
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let srv = ServerKey::from_seed(&[5u8; 32]);
        let other = ServerKey::from_seed(&[6u8; 32]);
        let ch = [0xabu8; 32];
        let bytes = LoginProof::sign(&dev, &ch, &srv.public(), 1_700_000_000);
        let p = LoginProof::parse(&bytes).unwrap();
        assert!(p.check(&ch, &srv.public(), 1_700_000_100, 300).is_ok());
        assert_eq!(
            p.check(&[0u8; 32], &srv.public(), 1_700_000_100, 300),
            Err(Error::ChallengeMismatch)
        );
        assert_eq!(
            p.check(&ch, &other.public(), 1_700_000_100, 300),
            Err(Error::ChallengeMismatch)
        );
        assert_eq!(
            p.check(&ch, &srv.public(), 1_700_001_000, 300),
            Err(Error::ClockSkew)
        );
    }
}
