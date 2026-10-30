//! The classic wire's device proof (`docs/proposals/portable-friends.md`
//! §3), checked by the ng port's identity state as a login there is: the
//! proof, then what the identity's registrars publish, then admission.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hxd_core::IdentityTag;
use hxd_ng_session::identity::AuthRefused;
use hxd_ng_session::{ClassicProof, IdentityState, NgCtx};
use hxd_session::{DeviceProver, ProveRefused, ProveRequest};

pub struct Prover {
    identity: Arc<IdentityState>,
    registrar: Option<Arc<hxd_registrar::Registrar>>,
}

/// What checks a classic session's device proof: the ng port's identity
/// state, where it answers as a classic host.
pub fn prover(ng: Option<&NgCtx>) -> Option<Arc<dyn DeviceProver>> {
    let ng = ng?;
    let identity = ng
        .identity
        .clone()
        .filter(|i| !i.config().classic_hosts.is_empty())?;
    Some(Arc::new(Prover {
        identity,
        registrar: ng.registrar.clone(),
    }))
}

impl DeviceProver for Prover {
    fn challenge(&self, challenge: &[u8; 32], host: &str, port: u16) -> Option<Vec<u8>> {
        self.identity.sign_trtp_challenge(challenge, host, port)
    }

    fn prove(
        &self,
        req: ProveRequest,
    ) -> Pin<Box<dyn Future<Output = Result<IdentityTag, ProveRefused>> + Send>> {
        let st = self.identity.clone();
        let registrar = self.registrar.clone();
        Box::pin(async move {
            let proved = admit(&st, registrar, req).await;
            match proved {
                Ok(ident) => Ok(ident.tag().on_account(Some(ident.fingerprint.0))),
                Err(AuthRefused::ClockSkew) => Err(ProveRefused::ClockSkew),
                Err(e) => {
                    tracing::info!(reason = e.code(), "device proof refused");
                    Err(ProveRefused::Refused)
                }
            }
        })
    }
}

async fn admit(
    st: &Arc<IdentityState>,
    registrar: Option<Arc<hxd_registrar::Registrar>>,
    req: ProveRequest,
) -> Result<hxd_ng_session::identity::TransportIdentity, AuthRefused> {
    if st.config().classic_proof == ClassicProof::Encrypted && !req.encrypted {
        return Err(AuthRefused::Denied);
    }
    let ProveRequest {
        proof,
        cert,
        card,
        challenge,
        host,
        exporter,
        login,
        may_link,
        ..
    } = req;
    let shown = card.clone();
    let verifier = st.clone();
    let verified = crate::spawn_blocking("identity", move || {
        verifier.verify_device_proof(
            card.as_deref(),
            &cert,
            &proof,
            &challenge,
            &host,
            exporter.as_ref(),
        )
    })
    .await
    .map_err(|_| AuthRefused::Backend)??;
    // Only a device that proved its key sends this server to a registrar.
    if let Some(registrars) = st.registrars() {
        registrars
            .refresh(
                verified.identity(),
                verified.attestations(),
                st.clock().unix(),
            )
            .await;
    }
    let st = st.clone();
    crate::spawn_blocking("identity", move || {
        let admitted = st.admit_device(verified, &login, shown.is_some(), may_link);
        // A card shown is recorded by this server's registrar as one shown
        // at the ng port's `auth` is.
        if let (Ok(_), Some(reg), Some(card)) = (&admitted, &registrar, &shown) {
            if let Ok(card) = hl_identity::Card::parse(card) {
                if let Err(e) = reg.note_card(&card) {
                    tracing::warn!("registrar could not record a card's commitment: {e}");
                }
            }
        }
        admitted
    })
    .await
    .map_err(|_| AuthRefused::Backend)?
}
