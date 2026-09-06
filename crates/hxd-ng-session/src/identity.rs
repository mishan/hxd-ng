//! Server-side identity state (`docs/hotline-ng-identity.md` §4–§7):
//! the server key, outstanding challenges, transport tokens, and the
//! per-device certificate and per-identity card caches.
//!
//! This module holds state and decides; it does not speak HTTP. `http.rs`
//! parses requests, calls in here, and encodes the answers. Everything
//! cryptographic is `hl-identity`'s; what's here is the bookkeeping a
//! server adds on top — and the policy knobs from the spec's §12.
//!
//! Not yet here, deliberately: revocation (needs a registrar to fetch
//! from), account association (needs the auth backend to grow a
//! fingerprint lookup), rate limiting (should share the login-attempt
//! limiter when that exists). Each is marked where it would go.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hl_identity::{Attestation, Fingerprint, LoginContext, PublicKey, ServerKey};
use hxd_core::IdentityTag;
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Challenge and token lifetime (§5.1, §5.2).
const TTL: Duration = Duration::from_secs(60);

/// What to do with an identity that has no linked account (§8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewAccounts {
    Deny,
    Guest,
    /// Not implemented yet: treated as `Guest` and logged. Account
    /// creation needs the auth backend to grow a fingerprint column.
    Create,
}

/// How to treat an identity with no acceptable attestation (§12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unattested {
    Deny,
    Guest,
    Allow,
}

/// The `[identity]` section, already parsed. See the spec's §12 for the
/// meaning of each.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub new_accounts: NewAccounts,
    pub allow_list: Vec<String>,
    pub min_attestation_age: u64,
    pub unattested: Unattested,
    /// Registrar host → public key. A static table for now; the registrar
    /// spec's discovery fetch replaces it. Empty means no attestation can
    /// be accepted, which is a valid (if lonely) configuration.
    pub registrar_keys: HashMap<String, PublicKey>,
    pub clock_skew: u64,
    /// Serve the TRTP-over-WebSocket path.
    pub trtp: bool,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        IdentityConfig {
            new_accounts: NewAccounts::Guest,
            allow_list: Vec::new(),
            min_attestation_age: 0,
            unattested: Unattested::Guest,
            registrar_keys: HashMap::new(),
            clock_skew: 300,
            trtp: true,
        }
    }
}

/// What the server decided an identity will get at application login
/// (§5.2 `outcome`, §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Linked,
    WillCreate,
    Guest,
    UnattestedGuest,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Linked => "linked",
            Outcome::WillCreate => "will_create",
            Outcome::Guest => "guest",
            Outcome::UnattestedGuest => "unattested_guest",
        }
    }
}

/// A socket's transport identity: what an authenticated upgrade carries
/// into the application protocol (§5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportIdentity {
    pub identity: PublicKey,
    pub device: PublicKey,
    pub fingerprint: Fingerprint,
    pub handle: Option<String>,
    /// Seconds since the oldest accepted attestation's `registered`; 0
    /// when unattested.
    pub age: u64,
    pub outcome: Outcome,
}

impl TransportIdentity {
    /// The roster-visible part.
    pub fn tag(&self) -> IdentityTag {
        IdentityTag {
            fingerprint: self.fingerprint.0,
            handle: self.handle.clone(),
        }
    }
}

/// Why `/identity/auth` refused (§5.2 failure codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRefused {
    BadCard,
    BadCert,
    BadProof,
    Revoked,
    Denied,
    CardTooLarge,
    UnknownChallenge,
}

impl AuthRefused {
    pub fn code(self) -> &'static str {
        match self {
            AuthRefused::BadCard => "bad_card",
            AuthRefused::BadCert => "bad_cert",
            AuthRefused::BadProof => "bad_proof",
            AuthRefused::Revoked => "revoked",
            AuthRefused::Denied => "denied",
            AuthRefused::CardTooLarge => "card_too_large",
            AuthRefused::UnknownChallenge => "unknown_challenge",
        }
    }

    /// 401 for "prove it again", 403 for "no".
    pub fn status(self) -> u16 {
        match self {
            AuthRefused::Denied | AuthRefused::Revoked => 403,
            _ => 401,
        }
    }
}

struct DeviceRecord {
    cert: Vec<u8>,
    identity: PublicKey,
    expires: u64,
}

struct CardRecord {
    updated: u64,
    bytes: Vec<u8>,
}

struct Tables {
    challenges: HashMap<[u8; 32], Instant>,
    /// Keyed by SHA-256 of the token, as session tokens are.
    tokens: HashMap<[u8; 32], (TransportIdentity, Instant)>,
    devices: HashMap<PublicKey, DeviceRecord>,
    cards: HashMap<Fingerprint, CardRecord>,
}

/// See the module docs.
pub struct IdentityState {
    key: ServerKey,
    cfg: IdentityConfig,
    tables: Mutex<Tables>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    b
}

fn hash(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

impl IdentityState {
    pub fn new(key: ServerKey, cfg: IdentityConfig) -> Self {
        IdentityState {
            key,
            cfg,
            tables: Mutex::new(Tables {
                challenges: HashMap::new(),
                tokens: HashMap::new(),
                devices: HashMap::new(),
                cards: HashMap::new(),
            }),
        }
    }

    pub fn config(&self) -> &IdentityConfig {
        &self.cfg
    }

    pub fn server_key(&self) -> PublicKey {
        self.key.public()
    }

    /// `POST /identity/challenge`. Expired challenges are swept here so a
    /// client that never follows up costs 32 bytes for a minute, not
    /// forever.
    pub fn issue_challenge(&self) -> [u8; 32] {
        let ch = random32();
        let mut t = self.tables.lock().unwrap();
        let now = Instant::now();
        t.challenges
            .retain(|_, issued| now.duration_since(*issued) < TTL);
        t.challenges.insert(ch, now);
        ch
    }

    /// `POST /identity/auth`, challenge binding: the spec's step list
    /// (§5.2) with steps 4 and 6's revocation half stubbed. Consumes the
    /// challenge whether or not verification succeeds — a failed attempt
    /// doesn't get to retry against the same nonce.
    pub fn auth_with_proof(
        &self,
        card: &[u8],
        cert: &[u8],
        proof: &[u8],
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        // Peek at the challenge inside the proof so we can consume it
        // before doing any signature work; a bad proof still burns it.
        let challenge = match hl_identity::LoginProof::parse(proof) {
            Ok(p) => p.challenge,
            Err(_) => return Err(AuthRefused::BadProof),
        };
        {
            let mut t = self.tables.lock().unwrap();
            match t.challenges.remove(&challenge) {
                Some(issued) if issued.elapsed() < TTL => {}
                _ => return Err(AuthRefused::UnknownChallenge),
            }
        }
        let ctx = LoginContext {
            challenge: &challenge,
            server_key: &self.key.public(),
            now: now_unix(),
            skew: self.cfg.clock_skew,
        };
        let v = hl_identity::verify_login(card, cert, proof, ctx).map_err(|e| {
            debug!("identity auth refused: {e}");
            classify(&e, card.len())
        })?;
        self.admit(v.card, v.cert, cert.to_vec(), card.to_vec())
    }

    /// `POST /identity/auth`, mTLS binding (§5.3): `device` is the key the
    /// reverse proxy vouched for.
    pub fn auth_presented(
        &self,
        card: &[u8],
        cert: &[u8],
        device: &PublicKey,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        let (c, dc) =
            hl_identity::verify_presented(card, cert, device, now_unix(), self.cfg.clock_skew)
                .map_err(|e| classify(&e, card.len()))?;
        self.admit(c, dc, cert.to_vec(), card.to_vec())
    }

    /// Steps 5–6 and the token issue, shared by both bindings.
    fn admit(
        &self,
        card: hl_identity::Card,
        cert: hl_identity::DeviceCert,
        cert_bytes: Vec<u8>,
        card_bytes: Vec<u8>,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        // Step 4, revocation: no registrar to ask yet. When there is one,
        // this is where a cached revocation list is consulted and
        // `Revoked` returned.

        // Step 5: attestations against the trusted table.
        let now = now_unix();
        let (handle, age) = self.accept_attestations(&card.attestations, now);
        let fingerprint = Fingerprint::of(&card.identity);

        // Step 6: policy.
        if !self.cfg.allow_list.is_empty() {
            let fp = fingerprint.to_string();
            let listed = self
                .cfg
                .allow_list
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&fp) || handle.as_deref() == Some(e.as_str()));
            if !listed {
                return Err(AuthRefused::Denied);
            }
        }
        let attested = handle.is_some() && age >= self.cfg.min_attestation_age;
        let outcome = if attested {
            match self.cfg.new_accounts {
                NewAccounts::Deny => return Err(AuthRefused::Denied),
                NewAccounts::Guest => Outcome::Guest,
                NewAccounts::Create => {
                    info!("new_accounts = create not implemented; treating as guest");
                    Outcome::Guest
                }
            }
        } else {
            match self.cfg.unattested {
                Unattested::Deny => return Err(AuthRefused::Denied),
                Unattested::Guest => Outcome::UnattestedGuest,
                Unattested::Allow => match self.cfg.new_accounts {
                    NewAccounts::Deny => return Err(AuthRefused::Denied),
                    _ => Outcome::Guest,
                },
            }
        };
        // Account association (Linked / WillCreate) arrives with the
        // fingerprint lookup on the auth backend; until then every
        // identity is a guest that knows who it is.

        let ident = TransportIdentity {
            identity: card.identity,
            device: cert.device,
            fingerprint,
            handle,
            age,
            outcome,
        };

        let token = random32();
        let mut t = self.tables.lock().unwrap();
        let inst = Instant::now();
        t.tokens
            .retain(|_, (_, issued)| inst.duration_since(*issued) < TTL);
        t.tokens.insert(hash(&token), (ident.clone(), inst));
        t.devices.insert(
            cert.device,
            DeviceRecord {
                cert: cert_bytes,
                identity: cert.identity,
                expires: cert.expires,
            },
        );
        let entry = t.cards.entry(fingerprint).or_insert(CardRecord {
            updated: 0,
            bytes: Vec::new(),
        });
        if card.updated >= entry.updated {
            *entry = CardRecord {
                updated: card.updated,
                bytes: card_bytes,
            };
        }
        Ok((b64(&token), ident))
    }

    fn accept_attestations(&self, atts: &[Attestation], now: u64) -> (Option<String>, u64) {
        let mut best: Option<(String, u64)> = None;
        for a in atts {
            let Some(expected) = self.cfg.registrar_keys.get(&a.registrar) else {
                continue;
            };
            if a.verify_registrar(expected, now, self.cfg.clock_skew)
                .is_err()
            {
                continue;
            }
            let age = now.saturating_sub(a.registered);
            match &best {
                Some((_, b)) if *b >= age => {}
                _ => best = Some((a.full_handle(), age)),
            }
        }
        match best {
            Some((h, age)) => (Some(h), age),
            None => (None, 0),
        }
    }

    /// Redeem a transport token presented at upgrade (§6.1). Single use.
    pub fn redeem(&self, token: &str) -> Option<TransportIdentity> {
        let raw = unb64(token)?;
        let mut t = self.tables.lock().unwrap();
        let (ident, issued) = t.tokens.remove(&hash(&raw))?;
        if issued.elapsed() >= TTL {
            return None;
        }
        Some(ident)
    }

    /// The mTLS "connection is the credential" path (§5.3): a device on
    /// file with a still-valid certificate needs no token.
    pub fn identity_for_device(&self, device: &PublicKey) -> Option<TransportIdentity> {
        let t = self.tables.lock().unwrap();
        let rec = t.devices.get(device)?;
        if rec.expires + self.cfg.clock_skew < now_unix() {
            return None;
        }
        let card_bytes = t.cards.get(&Fingerprint::of(&rec.identity))?.bytes.clone();
        let cert_bytes = rec.cert.clone();
        drop(t);
        // Re-run the checks rather than trusting the cache's shape; it's
        // two signature verifications.
        self.auth_presented(&card_bytes, &cert_bytes, device)
            .ok()
            .map(|(_, ident)| ident)
    }

    /// `GET /identity/card/<fingerprint>`: the exact cached bytes.
    pub fn card(&self, fp: &Fingerprint) -> Option<(u64, Vec<u8>)> {
        let t = self.tables.lock().unwrap();
        t.cards.get(fp).map(|c| (c.updated, c.bytes.clone()))
    }

    /// `PUT /identity/card` for the identity a token or device proved.
    /// Returns the outcome so the caller can broadcast a change.
    pub fn update_card(&self, identity: &PublicKey, bytes: &[u8]) -> Result<bool, AuthRefused> {
        let card = hl_identity::Card::parse(bytes).map_err(|e| classify(&e, bytes.len()))?;
        if &card.identity != identity {
            return Err(AuthRefused::BadCard);
        }
        let fp = Fingerprint::of(identity);
        let mut t = self.tables.lock().unwrap();
        let entry = t.cards.entry(fp).or_insert(CardRecord {
            updated: 0,
            bytes: Vec::new(),
        });
        if card.updated <= entry.updated {
            return Ok(false);
        }
        *entry = CardRecord {
            updated: card.updated,
            bytes: bytes.to_vec(),
        };
        Ok(true)
    }
}

/// Map a verification error to the spec's refusal codes.
fn classify(e: &hl_identity::Error, card_len: usize) -> AuthRefused {
    use hl_identity::Error as E;
    match e {
        E::TooLarge if card_len > hl_identity::card::MAX_BYTES => AuthRefused::CardTooLarge,
        E::ChallengeMismatch | E::ClockSkew => AuthRefused::BadProof,
        E::Expired | E::NotYetValid | E::CapabilityMissing => AuthRefused::BadCert,
        // KeyMismatch is "these objects aren't about the same keys";
        // the proof is the one the client is most likely to have gotten
        // wrong, and `bad_proof` is what a client should retry from.
        E::KeyMismatch => AuthRefused::BadProof,
        _ => AuthRefused::BadCard,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::{cert, Card, DeviceCert, DeviceKey, IdentityKey, LoginProof};

    fn state(cfg: IdentityConfig) -> IdentityState {
        IdentityState::new(ServerKey::from_seed(&[5u8; 32]), cfg)
    }

    fn objects(id: &IdentityKey, dev: &DeviceKey) -> (Vec<u8>, Vec<u8>) {
        let now = now_unix();
        let card = Card::new(id, "Misha", now).sign(id, vec![]).unwrap();
        let cert = DeviceCert::for_device(id, dev, now - 10, cert::RECOMMENDED_LIFETIME).sign(id);
        (card, cert)
    }

    #[test]
    fn challenge_auth_token_round_trip() {
        let st = state(IdentityConfig {
            unattested: Unattested::Guest,
            ..Default::default()
        });
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let (card, cert) = objects(&id, &dev);
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        let (token, ident) = st.auth_with_proof(&card, &cert, &proof).unwrap();
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);
        assert_eq!(ident.fingerprint, id.fingerprint());
        let redeemed = st.redeem(&token).unwrap();
        assert_eq!(redeemed.device, dev.public());
        assert!(st.redeem(&token).is_none(), "single use");
        // The challenge is consumed too.
        let proof2 = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof2),
            Err(AuthRefused::UnknownChallenge)
        );
        // And the card is cached byte-exactly.
        assert_eq!(st.card(&id.fingerprint()).unwrap().1, card);
    }

    #[test]
    fn unattested_deny_and_allow_list() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let (card, cert) = objects(&id, &dev);

        let st = state(IdentityConfig {
            unattested: Unattested::Deny,
            ..Default::default()
        });
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof).unwrap_err(),
            AuthRefused::Denied
        );

        let st = state(IdentityConfig {
            allow_list: vec![id.fingerprint().to_string()],
            ..Default::default()
        });
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert!(st.auth_with_proof(&card, &cert, &proof).is_ok());

        let st = state(IdentityConfig {
            allow_list: vec!["someone-else".into()],
            ..Default::default()
        });
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof).unwrap_err(),
            AuthRefused::Denied
        );
    }

    #[test]
    fn attestation_from_a_trusted_registrar_gives_a_handle() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let now = now_unix();
        let att = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "misha".into(),
            registered: now - 1000,
            issued: now - 10,
            expires: now + 1000,
            level: None,
        };
        let card = Card::new(&id, "Misha", now)
            .sign(&id, vec![att.signed_value(&reg)])
            .unwrap();
        let cert = DeviceCert::for_device(&id, &dev, now - 10, 1000).sign(&id);

        let mut cfg = IdentityConfig {
            new_accounts: NewAccounts::Guest,
            ..Default::default()
        };
        cfg.registrar_keys.insert("hl.example".into(), reg.public());
        let st = state(cfg);
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now);
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof).unwrap();
        assert_eq!(ident.handle.as_deref(), Some("misha@hl.example"));
        assert!(ident.age >= 1000);
        assert_eq!(ident.outcome, Outcome::Guest);

        // Same card, registrar not trusted: unattested.
        let st = state(IdentityConfig::default());
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now);
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof).unwrap();
        assert_eq!(ident.handle, None);
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);
    }

    #[test]
    fn card_update_needs_a_newer_timestamp() {
        let st = state(IdentityConfig::default());
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let now = now_unix();
        let c1 = Card::new(&id, "One", now).sign(&id, vec![]).unwrap();
        let c2 = Card::new(&id, "Two", now + 1).sign(&id, vec![]).unwrap();
        assert!(st.update_card(&id.public(), &c2).unwrap());
        assert!(!st.update_card(&id.public(), &c1).unwrap());
        assert_eq!(st.card(&id.fingerprint()).unwrap().1, c2);
        let other = IdentityKey::from_seed(&[9u8; 32]);
        assert_eq!(
            st.update_card(&other.public(), &c2).unwrap_err(),
            AuthRefused::BadCard
        );
    }
}
