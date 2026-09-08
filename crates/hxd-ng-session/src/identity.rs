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
use hxd_core::{
    AccessBits, Account, AuthBackend, AuthError, IdentityTag, LinkOutcome, Proof, UnlinkOutcome,
};
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
    /// Ceiling on `new_accounts = create` account files per hour. `None`
    /// is unlimited, which on a public server is a disk-filling
    /// primitive; the config default is a number.
    pub max_new_accounts_per_hour: Option<usize>,
    /// Where successor commitments (§3.4) are persisted. `None` keeps
    /// them per-process, which the spec's §12 marks as the weaker mode.
    pub anchors: Option<std::path::PathBuf>,
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
            max_new_accounts_per_hour: Some(60),
            anchors: None,
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
    /// The client said at `/identity/auth` that what it forwards for
    /// arrives over a cleartext hop (a tunnel listening off loopback,
    /// §11.1). The session is marked `cleartext` on the roster so the PM
    /// warning fires; the server has no way to check this and takes the
    /// conservative claim at face value.
    pub downstream_cleartext: bool,
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

/// How many devices and cards an unauthenticated caller may make the
/// server remember. Both tables are filled by `/identity/auth`, which
/// with the default `unattested = guest` any fresh key can reach — so
/// they need a ceiling that doesn't depend on rate limiting existing.
/// A card is up to 16 KiB, so this bounds the card table at ~64 MiB.
const MAX_DEVICES: usize = 8192;
const MAX_CARDS: usize = 4096;
/// Outstanding challenges. Each is 32 bytes for at most `TTL`.
const MAX_CHALLENGES: usize = 65536;
/// Sweep expiry every this many inserts, rather than walking the whole
/// map on every request — the sweep was O(n) per unauthenticated call.
const SWEEP_EVERY: usize = 256;

struct DeviceRecord {
    cert: Vec<u8>,
    identity: PublicKey,
    expires: u64,
    /// When this record was last written, for eviction order.
    seen: Instant,
}

struct CardRecord {
    updated: u64,
    /// The pre-committed successor, once seen. Immutable for the life of
    /// the identity (threat model: it is the anchor an attacker holding
    /// the key can't move). Mirrored to `anchors` so it survives a
    /// restart — a commitment only this process remembers is exactly
    /// "make the caches forget".
    successor: Option<[u8; 32]>,
    bytes: Vec<u8>,
    seen: Instant,
}

struct Tables {
    /// Keyed by SHA-256 of the challenge, as tokens are: §13 says every
    /// nonce this layer holds is stored hashed, and a nonce is cheap to
    /// hash.
    challenges: HashMap<[u8; 32], Instant>,
    /// Keyed by SHA-256 of the token, as session tokens are.
    tokens: HashMap<[u8; 32], (TransportIdentity, Instant)>,
    devices: HashMap<PublicKey, DeviceRecord>,
    cards: HashMap<Fingerprint, CardRecord>,
    /// Inserts since the last expiry sweep of `challenges`, and when
    /// that sweep last ran.
    since_sweep: usize,
    swept: Instant,
    /// When accounts were created by `new_accounts = create`, newest
    /// last; trimmed to the last hour.
    created: Vec<Instant>,
}

/// What association work `admit` is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assoc {
    /// A fresh `/identity/auth`: may link and may create.
    Write,
    /// Re-admitting a device already on file (§5.3, the "connection is
    /// the credential" path). Existing links are honoured; nothing is
    /// written, so an upgrade can't repeat the side effects of the auth
    /// that first recorded the device.
    ReadOnly,
}

/// See the module docs.
pub struct IdentityState {
    key: ServerKey,
    cfg: IdentityConfig,
    auth: Arc<dyn AuthBackend>,
    tables: Mutex<Tables>,
    /// Persisted successor commitments (§3.4), by fingerprint. `None`
    /// when the operator configured no path, in which case anchoring is
    /// per-process and `docs/hotline-ng-identity.md` §12 says so.
    anchors: Option<Anchors>,
}

/// Credentials a client may add to `/identity/auth` (§5.4) to verify a
/// classic account and link it in the same step.
///
/// `Debug` is hand-written: this rides in `AuthRequest`, which is a
/// parameter of every admission path, so a derived one puts a
/// plaintext-equivalent password one `{:?}` away from a log line.
#[derive(Clone, Copy)]
pub struct ClassicLogin<'a> {
    pub login: &'a str,
    pub password: &'a [u8],
}

impl std::fmt::Debug for ClassicLogin<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassicLogin")
            .field("login", &self.login)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// What a client asks for at `/identity/auth` beyond proving its key.
#[derive(Debug, Clone, Copy)]
pub struct AuthRequest<'a> {
    /// §5.4: classic credentials, to verify and link in the same step.
    pub classic: Option<ClassicLogin<'a>>,
    /// §5.2: what the client says about the hop behind it.
    pub downstream: Downstream,
    /// §8.2: may the server create an account for a never-seen identity
    /// under `new_accounts = create`? A client that means to link an
    /// existing classic account sends `false` — otherwise the first auth
    /// creates one, and `/identity/link` then answers `already_linked`
    /// forever, which made linking an existing account impossible on
    /// such a server.
    pub create: bool,
}

impl Default for AuthRequest<'_> {
    fn default() -> Self {
        AuthRequest {
            classic: None,
            downstream: Downstream::Local,
            create: true,
        }
    }
}

/// What a client declares about the hop *behind* it (§5.2 `downstream`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Downstream {
    /// The client is the endpoint, or forwards only over loopback.
    #[default]
    Local,
    /// The client forwards over a cleartext network hop.
    Cleartext,
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
        let anchors = cfg.anchors.clone().map(Anchors::load);
        IdentityState {
            key,
            cfg,
            auth,
            tables: Mutex::new(Tables {
                challenges: HashMap::new(),
                tokens: HashMap::new(),
                devices: HashMap::new(),
                cards: HashMap::new(),
                since_sweep: 0,
                swept: Instant::now(),
                created: Vec::new(),
            }),
            anchors,
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
    /// forever — but every `SWEEP_EVERY` calls, not every call: the whole
    /// map was being walked per request by anyone who could reach the
    /// endpoint, which needs no verification at all.
    pub fn issue_challenge(&self) -> Option<[u8; 32]> {
        let ch = random32();
        let now = Instant::now();
        let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
        t.since_sweep += 1;
        // Two triggers. The first is the ordinary one, every
        // `SWEEP_EVERY` inserts — including at a full table, so the walk
        // there is one request in 256, not every one, which is what it
        // used to be when the second trigger read "the table is full".
        // The second adds a sweep for a full table whose counter hasn't
        // come round yet, at most once a second: often enough to notice
        // the minute-long TTL expiring, and cheap enough that a caller
        // who found the table full can retry.
        let full = t.challenges.len() >= MAX_CHALLENGES;
        if t.since_sweep >= SWEEP_EVERY
            || (full && now.duration_since(t.swept) >= Duration::from_secs(1))
        {
            t.since_sweep = 0;
            t.swept = now;
            t.challenges
                .retain(|_, issued| now.duration_since(*issued) < TTL);
        }
        if t.challenges.len() >= MAX_CHALLENGES {
            // Every outstanding challenge is live and the table is full:
            // shed rather than grow. The client can retry in a minute.
            return None;
        }
        t.challenges.insert(hash(&ch), now);
        Some(ch)
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
        req: AuthRequest<'_>,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        // Peek at the challenge inside the proof so we can consume it
        // before doing any signature work; a bad proof still burns it.
        let challenge = match hl_identity::LoginProof::parse(proof) {
            Ok(p) => p.challenge,
            Err(_) => return Err(AuthRefused::BadProof),
        };
        {
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            match t.challenges.remove(&hash(&challenge)) {
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
        // The certificate's own limit, checked before anything is
        // parsed: `TooLarge` from inside `verify_login` cannot say which
        // object it was about, and answering `card_too_large` for a
        // certificate sends a client to look at the wrong one.
        if cert.len() > hl_identity::cert::MAX_BYTES {
            return Err(AuthRefused::BadCert);
        }
        let v = hl_identity::verify_login(card, cert, proof, ctx).map_err(|e| {
            debug!("identity auth refused: {e}");
            classify(&e, card.len())
        })?;
        self.admit(
            v.card,
            v.cert,
            cert.to_vec(),
            card.to_vec(),
            req,
            Assoc::Write,
        )
    }

    /// `POST /identity/auth`, mTLS binding (§5.3): `device` is the key the
    /// reverse proxy vouched for.
    pub fn auth_presented(
        &self,
        card: &[u8],
        cert: &[u8],
        device: &PublicKey,
        req: AuthRequest<'_>,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        if cert.len() > hl_identity::cert::MAX_BYTES {
            return Err(AuthRefused::BadCert);
        }
        let (c, dc) =
            hl_identity::verify_presented(card, cert, device, now_unix(), self.cfg.clock_skew)
                .map_err(|e| classify(&e, card.len()))?;
        self.admit(c, dc, cert.to_vec(), card.to_vec(), req, Assoc::Write)
    }

    /// Steps 5–6, account association (§8.1–§8.2), and the token issue,
    /// shared by both bindings.
    fn admit(
        &self,
        card: hl_identity::Card,
        cert: hl_identity::DeviceCert,
        cert_bytes: Vec<u8>,
        card_bytes: Vec<u8>,
        req: AuthRequest<'_>,
        assoc: Assoc,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        let classic_offered = req.classic.is_some();
        // Step 4, revocation: no registrar to ask yet. When there is one,
        // this is where a cached revocation list is consulted and
        // `Revoked` returned.

        // Step 5: attestations against the trusted table.
        let now = now_unix();
        let (handle, age) = self.accept_attestations(&card.attestations, now);
        let fingerprint = Fingerprint::of(&card.identity);

        // A card that moves a committed successor is refused outright —
        // *first*, before any account is linked or created. Checking it
        // after the writes meant a refused auth could still leave a link
        // behind, which is the opposite of what the anchor is for.
        if successor_changed(self.committed_successor(&fingerprint), &card) {
            debug!(fingerprint = %fingerprint.short(), "card changes a committed successor");
            return Err(AuthRefused::BadCard);
        }

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
        if let Some(c) = req.classic {
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
            } else if assoc == Assoc::ReadOnly {
                // Re-admitting a device on file never writes a link.
                pending = true;
            } else if !cert.allows(caps::MANAGE) {
                // §8.2: writing a link is account management, and this
                // is one of the three ways to write one. It used to be
                // the way around `no_manage` on `/identity/link`.
                debug!("link at auth refused: the device certificate lacks manage");
                return Err(AuthRefused::NoManage);
            } else {
                // One call: the backend reads, decides and writes under
                // its own lock, so two concurrent auths by this identity
                // can't both conclude "not linked yet".
                match self.link_exclusive(&account.login, &fingerprint)? {
                    LinkOutcome::Linked(a) => {
                        info!(login = %a.login, fingerprint = %fingerprint.short(), "identity linked at auth");
                        linked = Some(a);
                    }
                    LinkOutcome::Already(a) => linked = Some(a),
                    LinkOutcome::Taken(other) => {
                        debug!(login = %other.login, "identity already links another account");
                        return Err(AuthRefused::AlreadyLinked);
                    }
                    LinkOutcome::Refused(_) => pending = true,
                }
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
            // §8.1: `deny` is decided before any of the guest fallbacks,
            // because it has to hold on every path that admits — the
            // unattested one, the pending-link one, and re-admission of
            // a device already on file. A device cached while its
            // account was linked used to be let in as a guest on every
            // upgrade after the operator removed the link, for the life
            // of its certificate, which left `deny` no way to lock
            // anyone out. `classic_pending_link` was the same hole with
            // a password on it: a `manage` device that could verify an
            // account but not link it (no self-linking, or a
            // password-less file) got a token, upgraded, and landed as
            // an identity-tagged guest — which is the one thing §8.1
            // says `deny` never gives.
            None if self.cfg.new_accounts == NewAccounts::Deny => return Err(AuthRefused::Denied),
            // The classic credentials verified against a real account;
            // the link is the only thing that didn't happen, and the
            // operator is who resolves it (§8.2).
            None if pending => (Outcome::ClassicPendingLink, None),
            None if !attested && self.cfg.unattested == Unattested::Guest => {
                (Outcome::UnattestedGuest, None)
            }
            None if assoc == Assoc::ReadOnly => (Outcome::Guest, None),
            None => match self.cfg.new_accounts {
                // Refused above, ahead of the fallbacks.
                NewAccounts::Deny => return Err(AuthRefused::Denied),
                NewAccounts::Guest => (Outcome::Guest, None),
                // §8.2: `create` used to make `/identity/link`
                // unreachable — the first token-only auth created an
                // account, and `link` then answered `already_linked`
                // forever. A client that means to link an existing
                // account says so, and gets a guest session to do it from.
                NewAccounts::Create if classic_offered || !req.create => (Outcome::Guest, None),
                NewAccounts::Create => {
                    if !self.creation_allowed() {
                        tracing::warn!(
                            fingerprint = %fingerprint.short(),
                            "account-creation rate limit reached; admitting as a guest"
                        );
                        (Outcome::Guest, None)
                    } else {
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
                        let (created, is_new) = self
                            .auth
                            .find_or_create_linked(&proposed, &card.name, &fingerprint.0, access)
                            .map_err(|e| {
                                tracing::warn!("account creation failed: {e}");
                                AuthRefused::Backend
                            })?;
                        if is_new {
                            // Charged here rather than before the call:
                            // an identity that already had an account
                            // isn't creating one, and a failed create
                            // shouldn't cost the next caller its slot.
                            self.charge_creation();
                            info!(login = %created.login, fingerprint = %fingerprint.short(), "account created for identity");
                        }
                        (
                            if is_new {
                                Outcome::Created
                            } else {
                                Outcome::Linked
                            },
                            Some(created.login),
                        )
                    }
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
            downstream_cleartext: req.downstream == Downstream::Cleartext,
        };

        let token = random32();
        let inst = Instant::now();
        {
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            t.tokens
                .retain(|_, (_, issued)| inst.duration_since(*issued) < TTL);
            t.tokens.insert(hash(&token), (ident.clone(), inst));
            remember_device(
                &mut t.devices,
                cert.device,
                DeviceRecord {
                    cert: cert_bytes,
                    identity: cert.identity,
                    expires: cert.expires,
                    seen: inst,
                },
                now,
            );
            remember_card(&mut t.cards, fingerprint, &card, card_bytes, inst);
        }
        // Anchor a first commitment outside the table lock — it writes a
        // file. A changed one was refused at the top of this function.
        //
        // Only for an identity with standing here: an account (linked or
        // just created) or an attestation this server accepted. §13 says
        // every table an unauthenticated caller can grow is bounded, and
        // with `unattested = guest` a durable line per fresh key is not
        // that. What the commitment protects is an identity people on
        // this server have a relationship with; a key nobody knows has
        // nothing to protect yet, and anchors on its first login here.
        if let Some(s) = card.successor {
            self.anchor(&ident, s);
        }
        Ok((b64(&token), ident))
    }

    fn find_linked(&self, fp: &Fingerprint) -> Result<Option<Account>, AuthRefused> {
        self.auth.find_by_fingerprint(&fp.0).map_err(|e| {
            tracing::warn!("fingerprint lookup failed: {e}");
            AuthRefused::Backend
        })
    }

    /// One backend call that reads, decides and writes a link, so two
    /// concurrent auths by one identity cannot both conclude it is free.
    fn link_exclusive(&self, login: &str, fp: &Fingerprint) -> Result<LinkOutcome, AuthRefused> {
        let outcome = self.auth.link_identity(login, &fp.0).map_err(|e| {
            tracing::warn!("link write failed: {e}");
            AuthRefused::Backend
        })?;
        Ok(outcome)
    }

    /// §12 `max_new_accounts_per_hour`: `new_accounts = create` writes an
    /// account file per never-seen key, and with `unattested = guest`
    /// any fresh key qualifies. Past the ceiling, identities are still
    /// admitted — as guests — so a flood degrades the feature rather
    /// than the server.
    ///
    /// Check and charge are two calls with the account write between
    /// them, so concurrent creations can overshoot the ceiling by as
    /// many as are in flight — bounded by the blocking pool's width, and
    /// the alternative is holding the table lock across a file write.
    /// The knob is a flood ceiling, not a quota.
    fn creation_allowed(&self) -> bool {
        let Some(limit) = self.cfg.max_new_accounts_per_hour else {
            return true;
        };
        let now = Instant::now();
        let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
        t.created
            .retain(|at| now.duration_since(*at) < Duration::from_secs(3600));
        t.created.len() < limit
    }

    /// Count one account against the hour's ceiling.
    fn charge_creation(&self) {
        if self.cfg.max_new_accounts_per_hour.is_some() {
            self.tables
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .created
                .push(Instant::now());
        }
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
        match self.link_exclusive(&account.login, &ident.fingerprint)? {
            LinkOutcome::Linked(a) => {
                info!(login = %a.login, fingerprint = %ident.fingerprint.short(), "identity linked");
                Ok(a)
            }
            LinkOutcome::Already(a) => Ok(a),
            LinkOutcome::Taken(_) => Err(AuthRefused::AlreadyLinked),
            LinkOutcome::Refused(_) => Err(AuthRefused::Denied),
        }
    }

    /// `POST /identity/unlink` (§8.4).
    pub fn unlink(&self, ident: &TransportIdentity) -> Result<Account, AuthRefused> {
        if !ident.allows(caps::MANAGE) {
            return Err(AuthRefused::NoManage);
        }
        let outcome = self
            .auth
            .unlink_identity(&ident.fingerprint.0)
            .map_err(|e| {
                tracing::warn!("unlink write failed: {e}");
                AuthRefused::Backend
            })?;
        match outcome {
            UnlinkOutcome::Unlinked(a) => {
                info!(login = %a.login, fingerprint = %ident.fingerprint.short(), "identity unlinked");
                Ok(a)
            }
            UnlinkOutcome::NotLinked => Err(AuthRefused::NotLinked),
            UnlinkOutcome::WouldOrphan(_) => Err(AuthRefused::WouldOrphan),
        }
    }

    /// The account an authenticated socket's application login lands on
    /// (§8.1), re-read from the backend so a link made between auth and
    /// upgrade is honoured. `None` = guest.
    ///
    /// The policy is re-read with it. A token lives 60 s and an upgrade
    /// can come at the end of that: `identity_login` turned off, or the
    /// link removed under `new_accounts = deny`, has to bite here too,
    /// or a token minted while the account existed carries a guest
    /// session past the refusal for the rest of its life.
    pub fn account_for(&self, ident: &TransportIdentity) -> Result<Option<Account>, AuthRefused> {
        match self.find_linked(&ident.fingerprint)? {
            Some(a) if a.identity.identity_login => Ok(Some(a)),
            Some(_) => Err(AuthRefused::Denied),
            None if self.cfg.new_accounts == NewAccounts::Deny => Err(AuthRefused::Denied),
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

    /// Redeem a transport token (§6.1). `consume` spends it, which the
    /// upgrade does and the management endpoints don't — see `Consume`
    /// in `http.rs`. Either way it stops working after `TTL`.
    pub fn redeem(&self, token: &str, consume: bool) -> Option<TransportIdentity> {
        let raw = unb64(token)?;
        let key = hash(&raw);
        let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
        let expired = t
            .tokens
            .get(&key)
            .is_none_or(|(_, issued)| issued.elapsed() >= TTL);
        if expired {
            t.tokens.remove(&key);
            return None;
        }
        if consume {
            return t.tokens.remove(&key).map(|(ident, _)| ident);
        }
        t.tokens.get(&key).map(|(ident, _)| ident.clone())
    }

    /// The mTLS "connection is the credential" path (§5.3): a device on
    /// file with a still-valid certificate needs no token.
    ///
    /// Re-admits read-only. The upgrade that lands here is not a fresh
    /// `/identity/auth`, so it doesn't get to repeat that call's side
    /// effects — no link and no account creation. It shares `admit`'s
    /// token issue, so a token is minted and dropped unread; that costs
    /// one map insert, and having one code path decide admission is
    /// worth more than saving it. Signatures *are* re-checked rather than the
    /// cache's shape trusted; that's two verifications, which is why
    /// callers run this on the blocking pool.
    pub fn identity_for_device(&self, device: &PublicKey) -> Option<TransportIdentity> {
        let (card_bytes, cert_bytes) = {
            let t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            let rec = t.devices.get(device)?;
            if rec.expires + self.cfg.clock_skew < now_unix() {
                return None;
            }
            let card = t.cards.get(&Fingerprint::of(&rec.identity))?.bytes.clone();
            (card, rec.cert.clone())
        };
        let (c, dc) = hl_identity::verify_presented(
            &card_bytes,
            &cert_bytes,
            device,
            now_unix(),
            self.cfg.clock_skew,
        )
        .ok()?;
        self.admit(
            c,
            dc,
            cert_bytes,
            card_bytes,
            AuthRequest::default(),
            Assoc::ReadOnly,
        )
        .ok()
        .map(|(_, ident)| ident)
    }

    /// `GET /identity/card/<fingerprint>`: the exact cached bytes.
    pub fn card(&self, fp: &Fingerprint) -> Option<(u64, Vec<u8>)> {
        let t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
        t.cards.get(fp).map(|c| (c.updated, c.bytes.clone()))
    }

    /// `PUT /identity/card` for the identity a token or device proved.
    /// Returns the outcome so the caller can broadcast a change.
    pub fn update_card(
        &self,
        ident: &TransportIdentity,
        bytes: &[u8],
    ) -> Result<bool, AuthRefused> {
        let card = hl_identity::Card::parse(bytes).map_err(|e| classify(&e, bytes.len()))?;
        if card.identity != ident.identity {
            return Err(AuthRefused::BadCard);
        }
        let fp = ident.fingerprint;
        if successor_changed(self.committed_successor(&fp), &card) {
            return Err(AuthRefused::BadCard);
        }
        {
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            if t.cards.get(&fp).is_some_and(|e| card.updated <= e.updated) {
                return Ok(false);
            }
            remember_card(&mut t.cards, fp, &card, bytes.to_vec(), Instant::now());
        }
        if let Some(s) = card.successor {
            self.anchor(ident, s);
        }
        Ok(true)
    }

    /// Persist a successor commitment for an identity with standing —
    /// see the call in `admit` for why standing is the rule.
    fn anchor(&self, ident: &TransportIdentity, successor: [u8; 32]) {
        let Some(anchors) = self.anchors.as_ref() else {
            return;
        };
        // "Standing" is an account here, or an attestation this server
        // *accepted* — which is the same `attested` the policy in
        // `admit` uses, `min_attestation_age` included. A bare handle is
        // not enough: on a server that trusts a registrar which
        // registers freely, throwaway registrations would each anchor a
        // line and fill `MAX_ANCHORS`, after which the people the
        // commitment is for stop being anchored.
        let attested = ident.handle.is_some() && ident.age >= self.cfg.min_attestation_age;
        if ident.account.is_some() || attested {
            anchors.commit(&ident.fingerprint, successor);
        }
    }

    /// The successor this server has anchored for an identity, if any.
    /// Rotation (registrar spec) consults it: with a commitment on file,
    /// only a rotation to that key is accepted here. The on-disk anchor
    /// outranks the cache, which a restart empties.
    pub fn committed_successor(&self, fp: &Fingerprint) -> Option<[u8; 32]> {
        if let Some(s) = self.anchors.as_ref().and_then(|a| a.get(fp)) {
            return Some(s);
        }
        self.tables
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cards
            .get(fp)
            .and_then(|c| c.successor)
    }
}

/// Insert a device record, evicting expired entries and then the
/// least-recently-seen if the table is at its ceiling.
fn remember_device(
    devices: &mut HashMap<PublicKey, DeviceRecord>,
    key: PublicKey,
    rec: DeviceRecord,
    now: u64,
) {
    if devices.len() >= MAX_DEVICES && !devices.contains_key(&key) {
        devices.retain(|_, r| r.expires >= now);
        if devices.len() >= MAX_DEVICES {
            if let Some(oldest) = devices.iter().min_by_key(|(_, r)| r.seen).map(|(k, _)| *k) {
                devices.remove(&oldest);
            }
        }
    }
    devices.insert(key, rec);
}

/// Insert or refresh a card record, under the same ceiling. A card whose
/// `updated` isn't newer keeps the stored bytes; the successor, once
/// seen, is never dropped.
fn remember_card(
    cards: &mut HashMap<Fingerprint, CardRecord>,
    fp: Fingerprint,
    card: &hl_identity::Card,
    bytes: Vec<u8>,
    seen: Instant,
) {
    if cards.len() >= MAX_CARDS && !cards.contains_key(&fp) {
        if let Some(oldest) = cards.iter().min_by_key(|(_, r)| r.seen).map(|(k, _)| *k) {
            cards.remove(&oldest);
        }
    }
    let entry = cards.entry(fp).or_insert(CardRecord {
        updated: 0,
        successor: None,
        bytes: Vec::new(),
        seen,
    });
    entry.seen = seen;
    entry.successor = entry.successor.or(card.successor);
    // Strictly newer, matching what `update_card` accepts. With `>=`,
    // two cards signed in the same second could share an ETag and carry
    // different bytes, and §7 promises a strong validator. The empty
    // check is the fresh entry above, whose `updated` is 0.
    if entry.bytes.is_empty() || card.updated > entry.updated {
        entry.updated = card.updated;
        entry.bytes = bytes;
    }
}

/// A card may set a successor commitment once, and never change or drop
/// it afterwards. Dropping is refused too: the attack this defends
/// against is precisely "make the caches forget".
fn successor_changed(committed: Option<[u8; 32]>, card: &hl_identity::Card) -> bool {
    match committed {
        Some(committed) => card.successor != Some(committed),
        None => false,
    }
}

/// Successor commitments on disk (`docs/hotline-ng-identity.md` §3.4).
///
/// The threat model says every server that cached a card "holds the
/// commitment"; a table that only lives in the process holds it until the
/// next restart, and a restart is cheap for the attacker to arrange. One
/// line per identity, `fingerprint = successor`, both base64url —
/// readable enough for an operator to audit.
///
/// Append-only, and written only for identities with standing: rewriting
/// the whole file under the lock on every insert made one line from an
/// unauthenticated caller cost a rewrite of every line before it, and
/// §13's "the growth of every table an unauthenticated caller can touch
/// is bounded" was not true of this one. Duplicates and junk from an
/// older build or an interrupted write are compacted away once, at load.
struct Anchors {
    path: std::path::PathBuf,
    /// Fingerprint → committed successor, mirroring the file. Read on
    /// every auth and every card update, so no I/O happens under it.
    map: Mutex<HashMap<Fingerprint, [u8; 32]>>,
    /// Serialises appends without holding `map`.
    io: Mutex<()>,
    /// False when the file exists and could not be read. Writing from
    /// the empty map we would otherwise start with is "make the caches
    /// forget", done durably, by a transient `EACCES`.
    writable: bool,
}

/// Ceiling on anchored identities. Standing (an account here, or an
/// accepted attestation) is the real bound; this is the backstop that
/// doesn't depend on the operator's policy being restrictive.
const MAX_ANCHORS: usize = 16384;

const ANCHORS_HEADER: &str = "\
# Successor commitments (docs/hotline-ng-identity.md §3.4).
# One line per identity: <fingerprint> = <successor, base64url>.
# Deleting a line un-anchors that identity; that is the attack.
";

impl Anchors {
    /// Load, tolerating a missing file. A malformed line is skipped with
    /// a warning rather than refusing to start: losing one anchor is bad,
    /// but a server that won't boot is worse, and the operator sees it.
    /// Any other read failure leaves the table read-only for the run.
    fn load(path: std::path::PathBuf) -> Anchors {
        use std::collections::hash_map::Entry;
        let mut map: HashMap<Fingerprint, [u8; 32]> = HashMap::new();
        let mut writable = true;
        let mut compact = false;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for (n, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let parsed = line.split_once('=').and_then(|(fp, s)| {
                        let fp = Fingerprint::parse(fp.trim())?;
                        let s: [u8; 32] = unb64(s.trim())?.try_into().ok()?;
                        Some((fp, s))
                    });
                    match parsed {
                        // The first line for an identity wins: the
                        // commitment is immutable, so a later line is
                        // not a change to honour. Compacted away below.
                        Some((fp, s)) => match map.entry(fp) {
                            Entry::Occupied(e) => {
                                compact = true;
                                if *e.get() != s {
                                    tracing::warn!(
                                        "{}:{}: second successor for {}, keeping the first",
                                        path.display(),
                                        n + 1,
                                        fp.short()
                                    );
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert(s);
                            }
                        },
                        None => {
                            compact = true;
                            tracing::warn!(
                                "{}:{}: malformed successor anchor, skipped",
                                path.display(),
                                n + 1
                            );
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!(
                    "{}: {e}; successor anchors not loaded, and none will be written until \
                     this is fixed and the server restarted",
                    path.display()
                );
                writable = false;
            }
        }
        info!(anchors = map.len(), path = %path.display(), "successor commitments loaded");
        if writable && compact {
            let mut text = String::from(ANCHORS_HEADER);
            let mut lines: Vec<_> = map.iter().collect();
            lines.sort_by_key(|(fp, _)| fp.to_string());
            for (fp, s) in lines {
                text.push_str(&format!("{fp} = {}\n", b64(s)));
            }
            if let Err(e) = write_private(&path, &text) {
                tracing::warn!("{}: {e}; successor anchors not compacted", path.display());
            }
        }
        Anchors {
            path,
            map: Mutex::new(map),
            io: Mutex::new(()),
            writable,
        }
    }

    fn get(&self, fp: &Fingerprint) -> Option<[u8; 32]> {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(fp)
            .copied()
    }

    /// Record a first commitment. Never overwrites: a changed successor
    /// is refused before we get here, and a second value for an identity
    /// already on file is dropped rather than replacing the anchor in
    /// memory — memory outranks disk in `committed_successor`, so the
    /// key holder could otherwise make their own card unusable until the
    /// next restart.
    fn commit(&self, fp: &Fingerprint, successor: [u8; 32]) {
        if !self.writable {
            return;
        }
        {
            use std::collections::hash_map::Entry;
            let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
            if map.len() >= MAX_ANCHORS && !map.contains_key(fp) {
                tracing::warn!(
                    anchors = map.len(),
                    "successor anchor table is full; {} not anchored",
                    fp.short()
                );
                return;
            }
            match map.entry(*fp) {
                Entry::Occupied(_) => return,
                Entry::Vacant(v) => v.insert(successor),
            };
        }
        // The file, outside the map lock: `get` runs on every auth.
        let _io = self.io.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = append_private(&self.path, &format!("{fp} = {}\n", b64(&successor))) {
            // Memory keeps the commitment, which is the safe direction:
            // it is enforced for this run and lost at the next restart.
            tracing::error!(
                "{}: {e}; successor anchor not persisted",
                self.path.display()
            );
        }
    }
}

/// Append one line to a 0600 file, fsynced, creating it with its header
/// if it isn't there yet.
fn append_private(path: &std::path::Path, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    if f.metadata()?.len() == 0 {
        f.write_all(ANCHORS_HEADER.as_bytes())?;
    }
    f.write_all(line.as_bytes())?;
    f.sync_all()
}

/// Write a file 0600 through a temp-and-rename, fsynced.
fn write_private(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Map a verification error to the spec's refusal codes.
///
/// `card_len` is what makes `TooLarge` answerable: the error says an
/// object was over its limit and not which one, and the two objects a
/// request carries have different limits and different codes. The card's
/// own length decides, and a caller with no card in hand passes 0 — an
/// oversized certificate alongside an oversized card used to be reported
/// as `card_too_large` whichever of them the parser reached first.
fn classify(e: &hl_identity::Error, card_len: usize) -> AuthRefused {
    use hl_identity::Error as E;
    match e {
        E::TooLarge if card_len > hl_identity::card::MAX_BYTES => AuthRefused::CardTooLarge,
        // The public auth entry points pre-check certificate size so they
        // can name it precisely. Keep this as the defensive answer for any
        // future caller that reaches verification without that pre-check.
        E::TooLarge => AuthRefused::BadCert,
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

    /// An in-memory backend: `guest` (no password) and `alice` (password
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
            a.insert("alice".into(), account("alice", true));
            drop(a);
            Arc::new(m)
        }
    }

    impl AuthBackend for MemAuth {
        fn authenticate(&self, login: &str, proof: Proof<'_>) -> Result<Account, AuthError> {
            let login = if login.is_empty() { "guest" } else { login };
            let a = self.lookup(login)?;
            // Same rule the file backend enforces (§8.3): no password
            // plus a linked identity means the key is the credential.
            if !a.has_password && a.identity.fingerprint.is_some() {
                return Err(AuthError::BadProof);
            }
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
        fn link_identity(&self, login: &str, fp: &[u8; 32]) -> Result<LinkOutcome, AuthError> {
            // The whole decision under one lock, as the trait requires.
            let mut a = self.accounts.lock().unwrap();
            let account = a.get(login).cloned().ok_or(AuthError::NoSuchAccount)?;
            if account.identity.fingerprint == Some(*fp) {
                return Ok(LinkOutcome::Already(account));
            }
            // The file backend refuses a password-less account here, in
            // the one place all three link paths meet (§8.2): it
            // verifies for anybody, so self-linking one would hand it to
            // whoever asked. Mirrored so the unit suite sees the same
            // shape the server does.
            if account.identity.fingerprint.is_some()
                || !account.identity.allow_self_link
                || !account.has_password
            {
                return Ok(LinkOutcome::Refused(account));
            }
            if let Some(other) = a.values().find(|x| x.identity.fingerprint == Some(*fp)) {
                return Ok(LinkOutcome::Taken(other.clone()));
            }
            let entry = a.get_mut(login).expect("read above");
            entry.identity.fingerprint = Some(*fp);
            Ok(LinkOutcome::Linked(entry.clone()))
        }
        fn unlink_identity(&self, fp: &[u8; 32]) -> Result<UnlinkOutcome, AuthError> {
            let mut a = self.accounts.lock().unwrap();
            let Some(login) = a
                .values()
                .find(|x| x.identity.fingerprint == Some(*fp))
                .map(|x| x.login.clone())
            else {
                return Ok(UnlinkOutcome::NotLinked);
            };
            let entry = a.get_mut(&login).expect("found above");
            if !entry.has_password {
                return Ok(UnlinkOutcome::WouldOrphan(entry.clone()));
            }
            let before = entry.clone();
            entry.identity.fingerprint = None;
            Ok(UnlinkOutcome::Unlinked(before))
        }
        fn find_or_create_linked(
            &self,
            proposed: &str,
            name: &str,
            fp: &[u8; 32],
            access: AccessBits,
        ) -> Result<(Account, bool), AuthError> {
            let mut a = self.accounts.lock().unwrap();
            if let Some(existing) = a.values().find(|x| x.identity.fingerprint == Some(*fp)) {
                return Ok((existing.clone(), false));
            }
            let login = if a.contains_key(proposed) {
                format!("{proposed}-2")
            } else {
                proposed.to_owned()
            };
            let mut acct = account(&login, false);
            acct.name = name.into();
            acct.access = access;
            acct.identity.fingerprint = Some(*fp);
            a.insert(login.clone(), acct.clone());
            Ok((acct, true))
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
        let card = Card::new(id, "Alice", now).sign(id, vec![]).unwrap();
        let cert = DeviceCert::for_device(id, dev, now - 10, cert::RECOMMENDED_LIFETIME)
            .unwrap()
            .sign(id);
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
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        let (token, ident) = st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .unwrap();
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);
        assert_eq!(ident.fingerprint, id.fingerprint());
        let redeemed = st.redeem(&token, true).unwrap();
        assert_eq!(redeemed.device, dev.public());
        assert!(st.redeem(&token, true).is_none(), "single use");
        // The challenge is consumed too.
        let proof2 = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof2, AuthRequest::default()),
            Err(AuthRefused::UnknownChallenge)
        );
        // And the card is cached byte-exactly.
        assert_eq!(st.card(&id.fingerprint()).unwrap().1, card);
    }

    #[test]
    fn an_oversized_certificate_is_classified_as_a_bad_certificate() {
        let st = state(IdentityConfig::default());
        let id = IdentityKey::from_seed(&[11u8; 32]);
        let dev = DeviceKey::from_seed(&[12u8; 32]);
        let (card, mut cert) = objects(&id, &dev);
        cert.resize(cert::MAX_BYTES + 1, 0);
        let proof = proof_for(&st, &dev);
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, AuthRequest::default()),
            Err(AuthRefused::BadCert)
        );
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
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, AuthRequest::default())
                .unwrap_err(),
            AuthRefused::Denied
        );

        let st = state(IdentityConfig {
            allow_list: vec![id.fingerprint().to_string()],
            ..Default::default()
        });
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert!(st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .is_ok());

        let st = state(IdentityConfig {
            allow_list: vec!["someone-else".into()],
            ..Default::default()
        });
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now_unix());
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, AuthRequest::default())
                .unwrap_err(),
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
            handle: "alice".into(),
            registered: now - 1000,
            issued: now - 10,
            expires: now + 1000,
            level: None,
        };
        let card = Card::new(&id, "Alice", now)
            .sign(&id, vec![att.signed_value(&reg)])
            .unwrap();
        let cert = DeviceCert::for_device(&id, &dev, now - 10, 1000)
            .unwrap()
            .sign(&id);

        let mut cfg = IdentityConfig {
            new_accounts: NewAccounts::Guest,
            ..Default::default()
        };
        cfg.registrar_keys.insert("hl.example".into(), reg.public());
        let st = state(cfg);
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now);
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .unwrap();
        assert_eq!(ident.handle.as_deref(), Some("alice@hl.example"));
        assert!(ident.age >= 1000);
        assert_eq!(ident.outcome, Outcome::Guest);

        // Trusted, but the registration is younger than the server
        // asks for: §12's `min_attestation_age`, which is the knob for
        // "a handle registered this morning is not standing".
        let mut cfg = IdentityConfig {
            min_attestation_age: 100_000_000,
            ..Default::default()
        };
        cfg.registrar_keys.insert("hl.example".into(), reg.public());
        let st = state(cfg);
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now);
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .unwrap();
        // The handle is still reported — it verified — but the identity
        // counts as unattested for policy.
        assert_eq!(ident.handle.as_deref(), Some("alice@hl.example"));
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);

        // Same card, registrar not trusted: unattested.
        let st = state(IdentityConfig::default());
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), now);
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .unwrap();
        assert_eq!(ident.handle, None);
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);
    }

    /// The transport identity a token or a client certificate would
    /// have left behind, for the endpoints that take one.
    fn transport_of(id: &IdentityKey, dev: &DeviceKey, handle: Option<&str>) -> TransportIdentity {
        TransportIdentity {
            identity: id.public(),
            device: dev.public(),
            fingerprint: id.fingerprint(),
            handle: handle.map(str::to_owned),
            age: 0,
            outcome: Outcome::Guest,
            device_caps: None,
            account: None,
            downstream_cleartext: false,
        }
    }

    #[test]
    fn card_update_needs_a_newer_timestamp() {
        let st = state(IdentityConfig::default());
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let ident = transport_of(&id, &dev, None);
        let now = now_unix();
        let c1 = Card::new(&id, "One", now).sign(&id, vec![]).unwrap();
        let c2 = Card::new(&id, "Two", now + 1).sign(&id, vec![]).unwrap();
        let c3 = Card::new(&id, "Three", now + 1).sign(&id, vec![]).unwrap();
        assert!(st.update_card(&ident, &c2).unwrap());
        assert!(!st.update_card(&ident, &c1).unwrap());
        // Equal `updated` doesn't replace the bytes either: the ETag is
        // `updated`, and §7 calls it a strong validator.
        assert!(!st.update_card(&ident, &c3).unwrap());
        assert_eq!(st.card(&id.fingerprint()).unwrap().1, c2);
        let other = IdentityKey::from_seed(&[9u8; 32]);
        assert_eq!(
            st.update_card(&transport_of(&other, &dev, None), &c2)
                .unwrap_err(),
            AuthRefused::BadCard
        );
    }

    fn proof_for(st: &IdentityState, dev: &DeviceKey) -> Vec<u8> {
        let ch = st.issue_challenge().unwrap();
        LoginProof::sign(dev, &ch, &st.server_key(), now_unix())
    }

    #[test]
    fn deny_outranks_a_pending_classic_link() {
        // §8.1: `deny` is decided ahead of every fallback that admits an
        // identity with no linked account, and `classic_pending_link` is
        // one of those. A `manage` device that can verify an account but
        // not link it — self-linking off here — used to get a token, and
        // the ng `login` behind it landed as an identity-tagged guest,
        // which is what `deny` exists to refuse.
        let auth = MemAuth::new();
        auth.accounts
            .lock()
            .unwrap()
            .get_mut("alice")
            .unwrap()
            .identity
            .allow_self_link = false;
        let st = state_with(
            IdentityConfig {
                new_accounts: NewAccounts::Deny,
                unattested: Unattested::Allow,
                ..Default::default()
            },
            auth.clone(),
        );
        let id = IdentityKey::from_seed(&[41u8; 32]);
        let dev = DeviceKey::from_seed(&[42u8; 32]);
        let (card, cert) = objects(&id, &dev);
        let classic = || AuthRequest {
            classic: Some(ClassicLogin {
                login: "alice",
                password: b"pw",
            }),
            ..Default::default()
        };
        let proof = proof_for(&st, &dev);
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, classic())
                .unwrap_err(),
            AuthRefused::Denied
        );
        // Nothing was linked on the way to the refusal.
        assert!(auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .is_none());

        // Under `guest` the same auth is the pending-link outcome, so
        // the assertion above is about `deny` and not about the arm.
        let st = state_with(
            IdentityConfig {
                new_accounts: NewAccounts::Guest,
                unattested: Unattested::Allow,
                ..Default::default()
            },
            auth,
        );
        let proof = proof_for(&st, &dev);
        let (_, ident) = st.auth_with_proof(&card, &cert, &proof, classic()).unwrap();
        assert_eq!(ident.outcome, Outcome::ClassicPendingLink);
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
            login: "alice",
            password: b"nope",
        };
        assert_eq!(
            st.auth_with_proof(
                &card,
                &cert,
                &proof,
                AuthRequest {
                    classic: Some(bad),
                    ..Default::default()
                },
            )
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
            login: "alice",
            password: b"pw",
        };
        let (_, ident) = st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                AuthRequest {
                    classic: Some(ok),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(ident.outcome, Outcome::Linked);
        assert_eq!(ident.account.as_deref(), Some("alice"));
        assert_eq!(
            auth.find_by_fingerprint(&id.fingerprint().0)
                .unwrap()
                .unwrap()
                .login,
            "alice"
        );

        // Next auth with no credentials finds the link.
        let proof = proof_for(&st, &dev);
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .unwrap();
        assert_eq!(ident.outcome, Outcome::Linked);
        assert_eq!(st.account_for(&ident).unwrap().unwrap().login, "alice");

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
                AuthRequest {
                    classic: Some(ClassicLogin {
                        login: "alice",
                        password: b"pw",
                    }),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(ident2.outcome, Outcome::ClassicPendingLink);
        assert_eq!(
            st.link(&ident2, "alice", b"pw").unwrap_err(),
            AuthRefused::Denied
        );

        // Unlink needs the manage bit and a password on the account.
        let mut no_manage = ident.clone();
        no_manage.device_caps = Some(caps::WEB);
        assert_eq!(st.unlink(&no_manage).unwrap_err(), AuthRefused::NoManage);
        assert_eq!(st.unlink(&ident).unwrap().login, "alice");
        assert_eq!(st.unlink(&ident).unwrap_err(), AuthRefused::NotLinked);
        assert!(auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .is_none());

        // Link after auth, then a password-less account can't be unlinked.
        assert_eq!(st.link(&ident, "alice", b"pw").unwrap().login, "alice");
        auth.accounts
            .lock()
            .unwrap()
            .get_mut("alice")
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
            handle: "alice".into(),
            registered: now - 1000,
            issued: now - 10,
            expires: now + 1000,
            level: None,
        };
        let card = Card::new(&id, "Alice N", now)
            .sign(&id, vec![att.signed_value(&reg)])
            .unwrap();
        let cert = DeviceCert::for_device(&id, &dev, now - 10, 1000)
            .unwrap()
            .sign(&id);
        let proof = proof_for(&st, &dev);
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, AuthRequest::default())
            .unwrap();
        assert_eq!(ident.outcome, Outcome::Created);
        // `alice` exists already, so the handle's local part got a suffix.
        assert_eq!(ident.account.as_deref(), Some("alice-2"));
        let a = auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .unwrap();
        assert_eq!(a.name, "Alice N");
        assert!(a.access.has(hxd_core::access::bit::SEND_CHAT));

        // Unattested identities don't get accounts; they're guests.
        let id3 = IdentityKey::from_seed(&[31u8; 32]);
        let dev3 = DeviceKey::from_seed(&[32u8; 32]);
        let (card3, cert3) = objects(&id3, &dev3);
        let proof = proof_for(&st, &dev3);
        let (_, ident3) = st
            .auth_with_proof(&card3, &cert3, &proof, AuthRequest::default())
            .unwrap();
        assert_eq!(ident3.outcome, Outcome::UnattestedGuest);
    }
}
