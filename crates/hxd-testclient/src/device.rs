//! Device proof on the classic wire (`docs/proposals/portable-friends.md`
//! §3), as a client that holds its own device key speaks it: Get Device
//! Challenge (1020) and Prove Device (1021) built by `hxproto`'s
//! builders, and a login that leaves its name for Agreed (121), so that
//! it can prove its device before it joins.

use hxproto::messages::{tag, ClientHdr};
use hxproto::messaging as m;

use crate::legacy::{push, Client, Frame, Login};
use crate::messaging::{built, Chunks};
use crate::{Error, Result};

pub fn get_device_challenge(host: &str) -> Chunks {
    built(|c, s| m::build_get_device_challenge_chunks(host.as_bytes(), c, s))
}

pub fn prove_device(proof: &[u8], cert: &[u8], card: Option<&[u8]>) -> Chunks {
    built(|c, s| m::build_prove_device_chunks(proof, cert, card, c, s))
}

impl Client {
    /// Log in as [`Client::login`] does with the name and icon left out,
    /// so that the session waits for [`Client::join`] to be announced.
    pub async fn login_unannounced(&mut self, login: &Login) -> Result<Frame> {
        if login.version < 150 {
            return Err(Error::Protocol("only a 1.5 client joins at 121".into()));
        }
        let chunks: Chunks = login
            .chunks()
            .into_iter()
            .filter(|(t, _)| *t != tag::NAME && *t != tag::ICON)
            .collect();
        let reply = self.call(ClientHdr::Login.as_u32(), &chunks).await?;
        self.uid = reply.uint(tag::UID).map(|u| u as u16);
        self.recv_type(push::AGREEMENT).await?;
        Ok(reply)
    }

    /// Agreed (121), with the name and icon the login left out.
    pub async fn join(&mut self, login: &Login) -> Result<Frame> {
        self.call(
            ClientHdr::AgreementAgree.as_u32(),
            &[
                (tag::NAME, login.nick.as_bytes().to_vec()),
                (tag::ICON, login.icon.to_be_bytes().to_vec()),
            ],
        )
        .await
    }
}
