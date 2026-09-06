//! Server-side identity state (`docs/hotline-ng-identity.md` §4–§7):
//! the server key, outstanding challenges, transport tokens, and the
//! per-device certificate and per-identity card caches.
//!
//! This module holds state and decides; it does not speak HTTP. `http.rs`
//! parses requests, calls in here, and encodes the answers. Everything
//! cryptographic is `hl-identity`'s; what's here is the bookkeeping a
//! server adds on top — and the policy knobs from the spec's §12.
//!
//! Account association (§8) lives here too: `/identity/auth` decides
//! what an identity will get at application login, and the link /
//! unlink / create paths write through the auth backend. Everything that
//! touches the backend is synchronous file I/O — `http.rs` calls in from
//! the blocking pool.
//!
//! Not yet here, deliberately: revocation (needs a registrar to fetch
//! from) and rate limiting (should share the login-attempt limiter when
//! that exists). Each is marked where it would go.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hl_identity::{caps, Attestation, Fingerprint, LoginContext, PublicKey, ServerKey};
use hxd_core::{AccessBits, Account, AuthBackend, AuthError, IdentityTag, Proof};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Challenge and token lifetime (§5.1, §5.2).
const TTL: Duration = Duration::from_secs(60);

/// What to do with an identity that has no linked account (§8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewAccounts {
    Deny,
    Guest,
    /// Create and link an account named from the handle (or the
    /// fingerprint), with `IdentityConfig::default_access`.
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
    /// Access bitmap for accounts made by `new_accounts = create`. `None`
    /// means "whatever the guest account has", resolved at creation.
    pub default_access: Option<AccessBits>,
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
            default_access: None,
        }
    }
}

/// What the server decided an identity will get at application login
/// (§5.2 `outcome`, §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An account links this identity; login lands on it.
    Linked,
    /// `new_accounts = create`: the account was created at auth time.
    /// Reported as its own value so a client can say "welcome" rather
    /// than "welcome back".
    Created,
    Guest,
    UnattestedGuest,
    /// `login`/`password` named an account that couldn't be linked
    /// (someone else's identity, or self-linking off); the session will
    /// be a guest and the operator has to resolve it.
    ClassicPendingLink,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Linked => "linked",
            Outcome::Created => "created",
            Outcome::Guest => "guest",
            Outcome::UnattestedGuest => "unattested_guest",
            Outcome::ClassicPendingLink => "classic_pending_link",
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
    /// The device certificate's capability mask (`None` = all).
    pub device_caps: Option<u64>,
    /// The linked account's login when `outcome` is `Linked` or
    /// `Created`. The application login re-reads the account; this is
    /// which one.
    pub account: Option<String>,
}

impl TransportIdentity {
    pub fn allows(&self, cap: u64) -> bool {
        self.device_caps.is_none_or(|c| c & cap == cap)
    }
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
    /// `login`/`password` didn't verify (§5.4).
    LoginFailed,
    /// The device certificate lacks the manage bit (§8.2, §8.4).
    NoManage,
    /// This identity already links a different account here (§8.2).
    AlreadyLinked,
    /// Unlinking would leave a password-less account with no way in.
    WouldOrphan,
    /// The account isn't linked, or is linked to someone else.
    NotLinked,
    /// The auth backend failed; logged, not shown.
    Backend,
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
            AuthRefused::LoginFailed => "login_failed",
            AuthRefused::NoManage => "no_manage",
            AuthRefused::AlreadyLinked => "already_linked",
            AuthRefused::WouldOrphan => "would_orphan",
            AuthRefused::NotLinked => "not_linked",
            AuthRefused::Backend => "server_error",
        }
    }

    /// 401 for "prove it again", 403 for "no", 409 for "that conflicts
    /// with the account's state", 500 for us.
    pub fn status(self) -> u16 {
        match self {
            AuthRefused::Denied | AuthRefused::Revoked | AuthRefused::NoManage => 403,
            AuthRefused::AlreadyLinked | AuthRefused::WouldOrphan | AuthRefused::NotLinked => 409,
            AuthRefused::Backend => 500,
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
    auth: Arc<dyn AuthBackend>,
    tables: Mutex<Tables>,
}

/// Credentials a client may add to `/identity/auth` (§5.4) to verify a
/// classic account and link it in the same step.
pub struct ClassicLogin<'a> {
    pub login: &'a str,
    pub password: &'a [u8],
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
    pub fn new(key: ServerKey, cfg: IdentityConfig, auth: Arc<dyn AuthBackend>) -> Self {
        IdentityState {
            key,
            cfg,
            auth,
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
        classic: Option<ClassicLogin<'_>>,
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
        self.admit(v.card, v.cert, cert.to_vec(), card.to_vec(), classic)
    }

    /// `POST /identity/auth`, mTLS binding (§5.3): `device` is the key the
    /// reverse proxy vouched for.
    pub fn auth_presented(
        &self,
        card: &[u8],
        cert: &[u8],
        device: &PublicKey,
        classic: Option<ClassicLogin<'_>>,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        let (c, dc) =
            hl_identity::verify_presented(card, cert, device, now_unix(), self.cfg.clock_skew)
                .map_err(|e| classify(&e, card.len()))?;
        self.admit(c, dc, cert.to_vec(), card.to_vec(), classic)
    }

    /// Steps 5–6, account association (§8.1–§8.2), and the token issue,
    /// shared by both bindings.
    fn admit(
        &self,
        card: hl_identity::Card,
        cert: hl_identity::DeviceCert,
        cert_bytes: Vec<u8>,
        card_bytes: Vec<u8>,
        classic: Option<ClassicLogin<'_>>,
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
        if !attested {
            match self.cfg.unattested {
                Unattested::Deny => return Err(AuthRefused::Denied),
                Unattested::Guest | Unattested::Allow => {}
            }
        }

        // §8.2 "at auth": classic credentials, verified as for a normal
        // login, then linked if the account allows it.
        let mut linked: Option<Account> = None;
        let mut pending = false;
        if let Some(c) = classic {
            let account = match self.auth.authenticate(c.login, Proof::Plain(c.password)) {
                Ok(a) => a,
                Err(AuthError::NoSuchAccount | AuthError::BadProof) => {
                    return Err(AuthRefused::LoginFailed)
                }
                Err(AuthError::Backend(e)) => {
                    tracing::warn!("auth backend failure: {e}");
                    return Err(AuthRefused::Backend);
                }
            };
            if account.login == "guest" {
                // Logging in as guest names no account to link.
            } else if account.identity.fingerprint == Some(fingerprint.0) {
                linked = Some(account);
            } else if account.identity.fingerprint.is_none() && account.identity.allow_self_link {
                match self.find_linked(&fingerprint)? {
                    Some(other) => {
                        debug!(login = %other.login, "identity already links another account");
                        return Err(AuthRefused::AlreadyLinked);
                    }
                    None => {
                        self.auth
                            .set_identity_link(&account.login, Some(fingerprint.0))
                            .map_err(|e| {
                                tracing::warn!("link write failed: {e}");
                                AuthRefused::Backend
                            })?;
                        info!(login = %account.login, fingerprint = %fingerprint.short(), "identity linked at auth");
                        linked = self.auth.lookup(&account.login).ok();
                    }
                }
            } else {
                pending = true;
            }
        }

        // §8.1: an existing link, else the new_accounts policy.
        if linked.is_none() {
            linked = self.find_linked(&fingerprint)?;
        }
        let (outcome, account) = match linked {
            Some(a) if a.identity.identity_login => (Outcome::Linked, Some(a.login)),
            Some(a) => {
                debug!(login = %a.login, "identity_login is off for the linked account");
                return Err(AuthRefused::Denied);
            }
            None if pending => (Outcome::ClassicPendingLink, None),
            None if !attested && self.cfg.unattested == Unattested::Guest => {
                (Outcome::UnattestedGuest, None)
            }
            None => match self.cfg.new_accounts {
                NewAccounts::Deny => return Err(AuthRefused::Denied),
                NewAccounts::Guest => (Outcome::Guest, None),
                NewAccounts::Create => {
                    let proposed = match &handle {
                        Some(h) => h.split('@').next().unwrap_or("").to_owned(),
                        None => format!("id-{}", fingerprint.short()),
                    };
                    let access = match self.cfg.default_access {
                        Some(a) => a,
                        None => self
                            .auth
                            .lookup("")
                            .map(|g| g.access)
                            .unwrap_or_else(|_| AccessBits::empty()),
                    };
                    let created = self
                        .auth
                        .create_linked(&proposed, &card.name, fingerprint.0, access)
                        .map_err(|e| {
                            tracing::warn!("account creation failed: {e}");
                            AuthRefused::Backend
                        })?;
                    info!(login = %created.login, fingerprint = %fingerprint.short(), "account created for identity");
                    (Outcome::Created, Some(created.login))
                }
            },
        };

        let ident = TransportIdentity {
            identity: card.identity,
            device: cert.device,
            fingerprint,
            handle,
            age,
            outcome,
            device_caps: cert.caps,
            account,
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

    fn find_linked(&self, fp: &Fingerprint) -> Result<Option<Account>, AuthRefused> {
        self.auth.find_by_fingerprint(&fp.0).map_err(|e| {
            tracing::warn!("fingerprint lookup failed: {e}");
            AuthRefused::Backend
        })
    }

    /// `POST /identity/link` (§8.2 "after auth"): verify the password,
    /// then link if the account allows it and neither side is taken.
    pub fn link(
        &self,
        ident: &TransportIdentity,
        login: &str,
        password: &[u8],
    ) -> Result<Account, AuthRefused> {
        if !ident.allows(caps::MANAGE) {
            return Err(AuthRefused::NoManage);
        }
        let account = match self.auth.authenticate(login, Proof::Plain(password)) {
            Ok(a) if a.login != "guest" => a,
            Ok(_) | Err(AuthError::NoSuchAccount | AuthError::BadProof) => {
                return Err(AuthRefused::LoginFailed)
            }
            Err(AuthError::Backend(e)) => {
                tracing::warn!("auth backend failure: {e}");
                return Err(AuthRefused::Backend);
            }
        };
        if account.identity.fingerprint == Some(ident.fingerprint.0) {
            return Ok(account);
        }
        if account.identity.fingerprint.is_some() || !account.identity.allow_self_link {
            return Err(AuthRefused::Denied);
        }
        if self.find_linked(&ident.fingerprint)?.is_some() {
            return Err(AuthRefused::AlreadyLinked);
        }
        self.auth
            .set_identity_link(&account.login, Some(ident.fingerprint.0))
            .map_err(|e| {
                tracing::warn!("link write failed: {e}");
                AuthRefused::Backend
            })?;
        info!(login = %account.login, fingerprint = %ident.fingerprint.short(), "identity linked");
        self.auth
            .lookup(&account.login)
            .map_err(|_| AuthRefused::Backend)
    }

    /// `POST /identity/unlink` (§8.4).
    pub fn unlink(&self, ident: &TransportIdentity) -> Result<Account, AuthRefused> {
        if !ident.allows(caps::MANAGE) {
            return Err(AuthRefused::NoManage);
        }
        let Some(account) = self.find_linked(&ident.fingerprint)? else {
            return Err(AuthRefused::NotLinked);
        };
        if !account.has_password {
            return Err(AuthRefused::WouldOrphan);
        }
        self.auth
            .set_identity_link(&account.login, None)
            .map_err(|e| {
                tracing::warn!("unlink write failed: {e}");
                AuthRefused::Backend
            })?;
        info!(login = %account.login, fingerprint = %ident.fingerprint.short(), "identity unlinked");
        Ok(account)
    }

    /// The account an authenticated socket's application login lands on
    /// (§8.1), re-read from the backend so a link made between auth and
    /// upgrade is honoured. `None` = guest.
    pub fn account_for(&self, ident: &TransportIdentity) -> Result<Option<Account>, AuthRefused> {
        match self.find_linked(&ident.fingerprint)? {
            Some(a) if a.identity.identity_login => Ok(Some(a)),
            Some(_) => Err(AuthRefused::Denied),
            None => Ok(None),
        }
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
        self.auth_presented(&card_bytes, &cert_bytes, device, None)
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

    /// An in-memory backend: `guest` (no password) and `misha` (password
    /// `pw`), plus whatever `create_linked` adds.
    #[derive(Default)]
    struct MemAuth {
        accounts: Mutex<HashMap<String, Account>>,
    }

    fn account(login: &str, password: bool) -> Account {
        Account {
            login: login.into(),
            name: login.into(),
            access: AccessBits::empty(),
            can_detach: password,
            set_subject: false,
            has_password: password,
            identity: hxd_core::IdentityLink {
                identity_login: true,
                allow_self_link: true,
                ..Default::default()
            },
        }
    }

    impl MemAuth {
        fn new() -> Arc<Self> {
            let m = MemAuth::default();
            let mut a = m.accounts.lock().unwrap();
            a.insert("guest".into(), account("guest", false));
            a.insert("misha".into(), account("misha", true));
            drop(a);
            Arc::new(m)
        }
    }

    impl AuthBackend for MemAuth {
        fn authenticate(&self, login: &str, proof: Proof<'_>) -> Result<Account, AuthError> {
            let login = if login.is_empty() { "guest" } else { login };
            let a = self.lookup(login)?;
            let Proof::Plain(pw) = proof;
            let want: &[u8] = if a.has_password { b"pw" } else { b"" };
            if pw != want {
                return Err(AuthError::BadProof);
            }
            Ok(a)
        }
        fn lookup(&self, login: &str) -> Result<Account, AuthError> {
            let login = if login.is_empty() { "guest" } else { login };
            self.accounts
                .lock()
                .unwrap()
                .get(login)
                .cloned()
                .ok_or(AuthError::NoSuchAccount)
        }
        fn find_by_fingerprint(&self, fp: &[u8; 32]) -> Result<Option<Account>, AuthError> {
            Ok(self
                .accounts
                .lock()
                .unwrap()
                .values()
                .find(|a| a.identity.fingerprint == Some(*fp))
                .cloned())
        }
        fn set_identity_link(&self, login: &str, fp: Option<[u8; 32]>) -> Result<(), AuthError> {
            let mut a = self.accounts.lock().unwrap();
            a.get_mut(login)
                .ok_or(AuthError::NoSuchAccount)?
                .identity
                .fingerprint = fp;
            Ok(())
        }
        fn create_linked(
            &self,
            login: &str,
            name: &str,
            fp: [u8; 32],
            access: AccessBits,
        ) -> Result<Account, AuthError> {
            let mut a = self.accounts.lock().unwrap();
            let login = if a.contains_key(login) {
                format!("{login}-2")
            } else {
                login.to_owned()
            };
            let mut acct = account(&login, false);
            acct.name = name.into();
            acct.access = access;
            acct.identity.fingerprint = Some(fp);
            a.insert(login.clone(), acct.clone());
            Ok(acct)
        }
        fn reserved_by(&self, name: &str) -> Result<Option<String>, AuthError> {
            Ok(self
                .accounts
                .lock()
                .unwrap()
                .get(&name.to_ascii_lowercase())
                .filter(|a| a.identity.reserve_name)
                .map(|a| a.login.clone()))
        }
    }

    fn state(cfg: IdentityConfig) -> IdentityState {
        IdentityState::new(ServerKey::from_seed(&[5u8; 32]), cfg, MemAuth::new())
    }

    fn state_with(cfg: IdentityConfig, auth: Arc<MemAuth>) -> IdentityState {
        IdentityState::new(ServerKey::from_seed(&[5u8; 32]), cfg, auth)
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
        let (token, ident) = st.auth_with_proof(&card, &cert, &proof, None).unwrap();
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);
        assert_eq!(ident.fingerprint, id.fingerprint());
        let redeemed = st.redeem(&token).unwrap();
        assert_eq!(redeemed.device, dev.public());
        assert!(st.redeem(&token).is_none(), "single use");
        // The challenge is consumed too.
        let proof2 = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof2, None),
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
            st.auth_with_proof(&card, &cert, &proof, None).unwrap_err(),
            AuthRefused::Denied
        );

        let st = state(IdentityConfig {
            allow_list: vec![id.fingerprint().to_string()],
            ..Default::default()
        });
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert!(st.auth_with_proof(&card, &cert, &proof, None).is_ok());

        let st = state(IdentityConfig {
            allow_list: vec!["someone-else".into()],
            ..Default::default()
        });
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, None).unwrap_err(),
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
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof, None).unwrap();
        assert_eq!(ident.handle.as_deref(), Some("misha@hl.example"));
        assert!(ident.age >= 1000);
        assert_eq!(ident.outcome, Outcome::Guest);

        // Same card, registrar not trusted: unattested.
        let st = state(IdentityConfig::default());
        let ch = st.issue_challenge();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now);
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof, None).unwrap();
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

    fn proof_for(st: &IdentityState, dev: &DeviceKey) -> Vec<u8> {
        let ch = st.issue_challenge();
        LoginProof::sign(dev, &ch, &st.server_key(), now_unix())
    }

    #[test]
    fn linking_at_auth_then_linked_outcome_then_unlink() {
        let auth = MemAuth::new();
        let st = state_with(IdentityConfig::default(), auth.clone());
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let (card, cert) = objects(&id, &dev);

        // Wrong password: refused, nothing linked.
        let proof = proof_for(&st, &dev);
        let bad = ClassicLogin {
            login: "misha",
            password: b"nope",
        };
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, Some(bad))
                .unwrap_err(),
            AuthRefused::LoginFailed
        );
        assert!(auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .is_none());

        // Right password: linked in the same step.
        let proof = proof_for(&st, &dev);
        let ok = ClassicLogin {
            login: "misha",
            password: b"pw",
        };
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof, Some(ok)).unwrap();
        assert_eq!(ident.outcome, Outcome::Linked);
        assert_eq!(ident.account.as_deref(), Some("misha"));
        assert_eq!(
            auth.find_by_fingerprint(&id.fingerprint().0)
                .unwrap()
                .unwrap()
                .login,
            "misha"
        );

        // Next auth with no credentials finds the link.
        let proof = proof_for(&st, &dev);
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof, None).unwrap();
        assert_eq!(ident.outcome, Outcome::Linked);
        assert_eq!(st.account_for(&ident).unwrap().unwrap().login, "misha");

        // A second identity can't take the same account.
        let id2 = IdentityKey::from_seed(&[11u8; 32]);
        let dev2 = DeviceKey::from_seed(&[12u8; 32]);
        let (card2, cert2) = objects(&id2, &dev2);
        let proof = proof_for(&st, &dev2);
        let (_, ident2) = st
            .auth_with_proof(
                &card2,
                &cert2,
                &proof,
                Some(ClassicLogin {
                    login: "misha",
                    password: b"pw",
                }),
            )
            .unwrap();
        assert_eq!(ident2.outcome, Outcome::ClassicPendingLink);
        assert_eq!(
            st.link(&ident2, "misha", b"pw").unwrap_err(),
            AuthRefused::Denied
        );

        // Unlink needs the manage bit and a password on the account.
        let mut no_manage = ident.clone();
        no_manage.device_caps = Some(caps::WEB);
        assert_eq!(st.unlink(&no_manage).unwrap_err(), AuthRefused::NoManage);
        assert_eq!(st.unlink(&ident).unwrap().login, "misha");
        assert_eq!(st.unlink(&ident).unwrap_err(), AuthRefused::NotLinked);
        assert!(auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .is_none());

        // Link after auth, then a password-less account can't be unlinked.
        assert_eq!(st.link(&ident, "misha", b"pw").unwrap().login, "misha");
        auth.accounts
            .lock()
            .unwrap()
            .get_mut("misha")
            .unwrap()
            .has_password = false;
        assert_eq!(st.unlink(&ident).unwrap_err(), AuthRefused::WouldOrphan);
    }

    #[test]
    fn new_accounts_create_makes_a_linked_account() {
        let auth = MemAuth::new();
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let mut cfg = IdentityConfig {
            new_accounts: NewAccounts::Create,
            ..Default::default()
        };
        cfg.registrar_keys.insert("hl.example".into(), reg.public());
        cfg.default_access = Some(AccessBits::empty().with(hxd_core::access::bit::SEND_CHAT));
        let st = state_with(cfg, auth.clone());

        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
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
        let card = Card::new(&id, "Misha N", now)
            .sign(&id, vec![att.signed_value(&reg)])
            .unwrap();
        let cert = DeviceCert::for_device(&id, &dev, now - 10, 1000).sign(&id);
        let proof = proof_for(&st, &dev);
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof, None).unwrap();
        assert_eq!(ident.outcome, Outcome::Created);
        // `misha` exists already, so the handle's local part got a suffix.
        assert_eq!(ident.account.as_deref(), Some("misha-2"));
        let a = auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .unwrap();
        assert_eq!(a.name, "Misha N");
        assert!(a.access.has(hxd_core::access::bit::SEND_CHAT));

        // Unattested identities don't get accounts; they're guests.
        let id3 = IdentityKey::from_seed(&[31u8; 32]);
        let dev3 = DeviceKey::from_seed(&[32u8; 32]);
        let (card3, cert3) = objects(&id3, &dev3);
        let proof = proof_for(&st, &dev3);
        let (_, ident3) = st.auth_with_proof(&card3, &cert3, &proof, None).unwrap();
        assert_eq!(ident3.outcome, Outcome::UnattestedGuest);
    }
}
