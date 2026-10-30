//! Server-side identity state (`docs/hotline-ng-auth.md` §5–§6, `docs/hotline-ng-identity.md` §4–§7):
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
//! Revocation is the operator's own list (`identity-registrar.md`),
//! held by the core so that installing it can end the sessions it
//! refuses, and then what the registrars that attested the identity
//! publish against it (§7.3 there), which `crate::registrars` fetches
//! and keeps.
//! Rate limiting is the HTTP layer's, in front of this: challenges per
//! address, and the core's count of failed logins, which a password
//! checked here shares with both wires' logins.

use std::collections::HashMap;

use futures_util::StreamExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hl_identity::{caps, Attestation, Fingerprint, LoginContext, PublicKey, Record, ServerKey};
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

/// What a freeze at a registrar does here (`identity-registrar.md` §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frozen {
    Deny,
    /// Admit the identity as though it were unattested.
    Guest,
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
    pub frozen: Frozen,
    /// Registrar hosts whose identities are refused outright
    /// (`identity-registrar.md` §7.3).
    pub banned_registrars: Vec<String>,
    /// Seconds a key nobody here answers for waits, from when it was
    /// first seen, before it may chat, message or post
    /// (`identity-registrar.md` §7.3). 0 is none.
    pub newcomer_delay: u64,
    /// The hosts this server answers as, in `canonical_host` form
    /// (`hotline-ng-auth.md` §6.2). Only these are vouched for and
    /// accepted in a `v = 2` proof: a `Host` is whatever the sender put
    /// there, so taking any would let another server name itself to
    /// this one and be vouched for under its own name. Empty, there are
    /// none, and no identity logs in unless `login_proof_v1` is on.
    pub hosts: Vec<String>,
    /// Accept a `v = 1` login proof, which names no host and so can be
    /// relayed (`hotline-ng-auth.md` §6.2).
    pub login_proof_v1: bool,
    /// The hosts the classic ports answer as, in `canonical_host` form,
    /// each with the port it names, which that form leaves off for 80 and
    /// 443: what Get Device Challenge signs for
    /// (`docs/proposals/portable-friends.md` §3). Apart from `hosts`,
    /// since these carry the classic ports.
    pub classic_hosts: Vec<(String, u16)>,
    /// Which classic sessions may prove a device.
    pub classic_proof: ClassicProof,
}

/// `[identity] classic_proof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicProof {
    Any,
    /// Only a session `hotline-ng-auth.md` §8 counts encrypted: TLS, or
    /// HOPE with a cipher.
    Encrypted,
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
            frozen: Frozen::Deny,
            banned_registrars: Vec::new(),
            newcomer_delay: 0,
            hosts: Vec::new(),
            login_proof_v1: false,
            classic_hosts: Vec::new(),
            classic_proof: ClassicProof::Any,
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
    /// When that certificate expires, as unix seconds. A device's push
    /// registration lives exactly this long: past it the gateway stops
    /// sending and the row is swept, which is how a lost identity device
    /// stops buzzing without anyone remembering to unregister it
    /// (push-notifications.md §5.1).
    pub device_expires: u64,
    /// The certificate as it was proved, and its `device_enc` key: what a
    /// sealed message to this device is sealed to
    /// (`docs/e2e-messages.md` §4.2).
    pub device_cert: Vec<u8>,
    pub device_enc: [u8; 32],
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
    /// Unix seconds before which a key new here may not chat, message or
    /// post (`identity-registrar.md` §7.3).
    pub quiet_until: Option<u64>,
}

impl TransportIdentity {
    pub fn allows(&self, cap: u64) -> bool {
        self.device_caps.is_none_or(|c| c & cap == cap)
    }

    pub fn may_message(&self) -> bool {
        self.allows(hl_identity::caps::MESSAGE)
    }
}

impl TransportIdentity {
    /// The roster-visible part.
    pub fn tag(&self) -> IdentityTag {
        IdentityTag {
            fingerprint: self.fingerprint.0,
            device: Fingerprint::of(&self.device).0,
            handle: self.handle.clone(),
            quiet_until: self.quiet_until,
            signs: false,
            can_sign: false,
            device_expires: self.device_expires,
            sealed: None,
            device_cert: (self.may_message() && self.device_cert.len() <= 512)
                .then(|| std::sync::Arc::new(self.device_cert.clone())),
        }
    }
}

/// A login whose certificate, card and proof have verified, waiting to
/// be admitted (`IdentityState::admit_verified`).
pub struct Verified {
    card: hl_identity::Card,
    cert: hl_identity::DeviceCert,
    card_bytes: Vec<u8>,
    cert_bytes: Vec<u8>,
}

impl Verified {
    pub fn identity(&self) -> &PublicKey {
        &self.card.identity
    }

    pub fn attestations(&self) -> &[Attestation] {
        &self.card.attestations
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
    /// A `v = 2` proof made for a host other than the one the request
    /// was sent to, or than any this server answers as: a relay, or a
    /// proxy that rewrites `Host`.
    WrongHost,
    /// A `v = 1` proof, with `[identity] login_proof_v1 = false`.
    UnsupportedProof,
    /// `login`/`password` didn't verify (§5.4).
    LoginFailed,
    /// `login`/`password` named the guest account, which links to no
    /// one. The client is told `login_failed`, exactly as for a wrong
    /// password, but the password was not wrong: it is not a guess, and
    /// the failed-login count does not hear of it.
    GuestLink,
    /// The device certificate lacks the manage bit (§8.2, §8.4).
    NoManage,
    /// This identity already links a different account here (§8.2).
    AlreadyLinked,
    /// Unlinking would leave a password-less account with no way in.
    WouldOrphan,
    /// The account isn't linked, or is linked to someone else.
    NotLinked,
    /// A ban on this identity, or on the registrar that issued its
    /// handle (`docs/moderation.md` §3.5).
    Banned,
    /// The identity has rotated to `successor` (`identity-registrar.md`
    /// §7.4); the client is told which key to use.
    Rotated {
        successor: Fingerprint,
    },
    /// The auth backend failed; logged, not shown.
    Backend,
    /// A device proof's `time` is outside `clock_skew`, which the classic
    /// wire tells apart so that the user can fix the clock.
    ClockSkew,
}

impl AuthRefused {
    pub fn code(self) -> &'static str {
        match self {
            AuthRefused::BadCard => "bad_card",
            AuthRefused::BadCert => "bad_cert",
            AuthRefused::BadProof | AuthRefused::ClockSkew => "bad_proof",
            AuthRefused::Revoked => "revoked",
            AuthRefused::Denied => "denied",
            AuthRefused::CardTooLarge => "card_too_large",
            AuthRefused::UnknownChallenge => "unknown_challenge",
            AuthRefused::WrongHost => "wrong_host",
            AuthRefused::UnsupportedProof => "unsupported_proof",
            AuthRefused::LoginFailed | AuthRefused::GuestLink => "login_failed",
            AuthRefused::NoManage => "no_manage",
            AuthRefused::AlreadyLinked => "already_linked",
            AuthRefused::WouldOrphan => "would_orphan",
            AuthRefused::NotLinked => "not_linked",
            AuthRefused::Banned => "banned",
            AuthRefused::Rotated { .. } => "rotated",
            AuthRefused::Backend => "server_error",
        }
    }

    /// 401 for "prove it again", 403 for "no", 409 for "that conflicts
    /// with the account's state", 421 for "not the server you meant",
    /// 500 for us.
    pub fn status(self) -> u16 {
        match self {
            AuthRefused::Denied
            | AuthRefused::Revoked
            | AuthRefused::NoManage
            | AuthRefused::Banned
            | AuthRefused::Rotated { .. } => 403,
            AuthRefused::AlreadyLinked | AuthRefused::WouldOrphan | AuthRefused::NotLinked => 409,
            AuthRefused::WrongHost => 421,
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
/// Unredeemed transport tokens. Each lives at most `TTL`, but any fresh
/// key can mint one under the default guest policy, so a minute's worth
/// is still a table an unauthenticated caller grows.
const MAX_TOKENS: usize = 65536;
/// Sweep expiry every this many inserts, rather than walking the whole
/// map on every request — the sweep was O(n) per unauthenticated call.
const SWEEP_EVERY: usize = 256;

struct DeviceRecord {
    cert: Vec<u8>,
    identity: PublicKey,
    expires: u64,
    /// What the device last declared at `/identity/auth` about the hop
    /// behind it. The key-on-file upgrade makes no declaration of its
    /// own, so this is what it inherits: without it, a tunnel that said
    /// `cleartext` came back through its certificate marked encrypted.
    downstream: Downstream,
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
    /// When a `v = 1` login was last warned about.
    v1_warned: Option<Instant>,
}

/// What [`IdentityState::standing`] found of an identity.
struct Standing {
    fingerprint: Fingerprint,
    /// The accepted attestation's handle, and its age.
    handle: Option<String>,
    age: u64,
    /// Attested, and long enough ago.
    attested: bool,
    now: u64,
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
    /// The domain, for the obligations a link carries with it —
    /// `docs/private-messages.md` §4. Every write of a link has to tell
    /// the inbox, or the account's mail is stranded the moment it gains
    /// an identity; going through `Core` rather than the store is what
    /// keeps that call on the right side of the locking discipline.
    core: Arc<hxd_core::Core>,
    /// The core's, read for every time this state keeps or checks.
    clock: hxd_core::clock::Clock,
    /// Where first sightings are kept: the core's record cache, durable
    /// with a store.
    seen: Arc<dyn hxd_core::identity_records::RecordCache>,
    tables: Mutex<Tables>,
    /// Persisted successor commitments (§3.4), by fingerprint. `None`
    /// when the operator configured no path, in which case anchoring is
    /// per-process and `docs/hotline-ng-identity.md` §12 says so.
    anchors: Option<Anchors>,
    /// This server's registrar, when it is one. The commitments it holds
    /// bind a card shown here as the anchors do (§3.4): its `PUT` path
    /// checks them, and admission must too, or `auth` with the card is a
    /// way around the check.
    registrar: Option<Arc<hxd_registrar::Registrar>>,
    /// The registrars this server trusts, their keys and their records.
    registrars: Option<Arc<crate::registrars::Registrars>>,
    handovers: Mutex<Arc<Handovers>>,
}

/// What the server commits to and has handed over
/// (`docs/server-key-handover.md` §2, §4).
#[derive(Debug, Clone, Default)]
pub struct Handovers {
    /// The commitment every challenge carries.
    pub next: Option<[u8; 32]>,
    /// The handovers served in discovery, oldest first, each as signed.
    pub chain: Vec<Vec<u8>>,
}

/// Whether `h` is what a server under `key` may serve at `now`: a chain a
/// first-pinning client takes whole (§5.1), which is only so when it ends
/// at `key` and at the commitment the challenges carry.
pub fn check_handovers(key: &PublicKey, h: &Handovers, now: u64) -> Result<(), String> {
    use hl_identity::handover::{self, Handover, MAX_CHAIN};
    if h.chain.len() > MAX_CHAIN {
        return Err(format!("more than {MAX_CHAIN} handovers"));
    }
    let Some(last) = h.chain.last() else {
        return Ok(());
    };
    let last = Handover::parse(last).map_err(|e| format!("the last handover: {e}"))?;
    if &last.new != key {
        return Err(format!(
            "the last handover is to {}, not to the server key {}",
            b64(&last.new),
            b64(key)
        ));
    }
    if last.next != h.next {
        return Err("the last handover commits to another successor than the server does".into());
    }
    // Of a challenge, a client's chain check reads the key and `next`.
    let challenge = hl_identity::ServerChallenge {
        challenge: [0; 32],
        server_key: *key,
        host: String::new(),
        expires: 0,
        next: h.next,
    };
    if handover::pin(&h.chain, &challenge, now).len() != h.chain.len() {
        return Err(
            "the handovers do not form a chain: each must verify, be from the \
             one before's new key to the key it committed to, later than it, and to \
             a key not seen before"
                .into(),
        );
    }
    Ok(())
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
    /// §5.1: a rotation record naming this identity as the successor.
    pub rotation: Option<&'a [u8]>,
}

impl Default for AuthRequest<'_> {
    fn default() -> Self {
        AuthRequest {
            classic: None,
            downstream: Downstream::Local,
            create: true,
            rotation: None,
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

#[cfg(test)]
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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

/// The port `host[:port]` names, before `canonical_host` drops 80 and
/// 443, or `None` where it names none.
pub fn host_port(host: &str) -> Option<u16> {
    host.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
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
    pub fn new(
        key: ServerKey,
        cfg: IdentityConfig,
        auth: Arc<dyn AuthBackend>,
        core: Arc<hxd_core::Core>,
    ) -> Self {
        let anchors = cfg.anchors.clone().map(Anchors::load);
        for from in anchors.iter().flat_map(Anchors::rotated_from) {
            core.refuse_rotated(from.0);
        }
        let clock = core.clock().clone();
        let seen = core
            .record_cache()
            .unwrap_or_else(|| Arc::new(hxd_core::identity_records::MemoryRecordCache::default()));
        let state = IdentityState {
            key,
            cfg,
            auth,
            core,
            clock: clock.clone(),
            seen,
            tables: Mutex::new(Tables {
                challenges: HashMap::new(),
                tokens: HashMap::new(),
                devices: HashMap::new(),
                cards: HashMap::new(),
                since_sweep: 0,
                swept: clock.now(),
                created: Vec::new(),
                v1_warned: None,
            }),
            anchors,
            registrar: None,
            registrars: None,
            handovers: Mutex::default(),
        };
        state.finish_rotations(None);
        state
    }

    /// Hold cards to `registrar`'s commitments as well as the anchors'.
    pub fn with_registrar(mut self, registrar: Option<Arc<hxd_registrar::Registrar>>) -> Self {
        self.registrar = registrar;
        self
    }

    pub fn with_registrars(mut self, registrars: Arc<crate::registrars::Registrars>) -> Self {
        self.registrars = Some(registrars);
        self
    }

    pub fn clock(&self) -> &hxd_core::clock::Clock {
        &self.clock
    }

    pub fn registrars(&self) -> Option<&Arc<crate::registrars::Registrars>> {
        self.registrars.as_ref()
    }

    pub fn config(&self) -> &IdentityConfig {
        &self.cfg
    }

    pub fn server_key(&self) -> PublicKey {
        self.key.public()
    }

    pub fn handovers(&self) -> Arc<Handovers> {
        self.handovers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Serve `h` from now on, if [`check_handovers`] passes it; otherwise
    /// what was served stays.
    pub fn set_handovers(&self, h: Handovers) -> Result<(), String> {
        check_handovers(&self.key.public(), &h, self.clock.unix())?;
        *self.handovers.lock().unwrap_or_else(|e| e.into_inner()) = Arc::new(h);
        Ok(())
    }

    /// `POST /identity/challenge`. Expired challenges are swept here so a
    /// client that never follows up costs 32 bytes for a minute, not
    /// forever — but every `SWEEP_EVERY` calls, not every call: the whole
    /// map was being walked per request by anyone who could reach the
    /// endpoint, which needs no verification at all.
    pub fn issue_challenge(&self) -> Option<[u8; 32]> {
        let ch = random32();
        let now = self.clock.now();
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

    /// Whether `host`, a request's `Host`, is one of the names this
    /// server was configured with.
    pub fn answers_as(&self, host: Option<&str>) -> bool {
        host.and_then(hl_identity::proof::canonical_host)
            .is_some_and(|h| self.cfg.hosts.contains(&h))
    }

    /// The server key's signature over a challenge issued to a request
    /// sent with `host` (§6.2), or `None` for a host this server does not
    /// answer as — which a `v = 2` client then refuses to sign for.
    pub fn sign_challenge(&self, challenge: &[u8; 32], host: Option<&str>) -> Option<Vec<u8>> {
        let host = host.filter(|h| self.answers_as(Some(h)))?;
        let expires = self.clock.unix() + TTL.as_secs();
        let next = self.handovers().next;
        hl_identity::ServerChallenge::sign(&self.key, challenge, host, expires, next.as_ref()).ok()
    }

    /// Get Device Challenge (`docs/proposals/portable-friends.md` §3):
    /// `challenge` signed for `host`, under the TRTP domain, when it is one
    /// of `classic_hosts` on `port`, the listener the request arrived on,
    /// so that a challenge for the TLS port is never signed on the plain
    /// one. The port is read from `host` as the client sent it
    /// ([`host_port`]), since `canonical_host` leaves off 80 and 443.
    pub fn sign_trtp_challenge(
        &self,
        challenge: &[u8; 32],
        host: &str,
        port: u16,
    ) -> Option<Vec<u8>> {
        let sent = host_port(host).filter(|p| *p == port)?;
        let host = hl_identity::proof::canonical_host(host)
            .filter(|h| self.cfg.classic_hosts.contains(&(h.clone(), sent)))?;
        let expires = self.clock.unix() + TTL.as_secs();
        let next = self.handovers().next;
        hl_identity::ServerChallenge::sign_trtp(&self.key, challenge, &host, expires, next.as_ref())
            .ok()
    }

    /// Prove Device's checks (`docs/proposals/portable-friends.md` §3):
    /// §6.2's on the proof, against the `challenge` the session holds and
    /// the `host` it was given for, on the connection whose exporter is
    /// `exporter`, and then the certificate's and the card's as the ng
    /// port checks them — `card`, or the one held here for the
    /// certificate's identity.
    pub fn verify_device_proof(
        &self,
        card: Option<&[u8]>,
        cert: &[u8],
        proof: &[u8],
        challenge: &[u8; 32],
        host: &str,
        exporter: Option<&[u8; 32]>,
    ) -> Result<Verified, AuthRefused> {
        if cert.len() > hl_identity::cert::MAX_BYTES {
            return Err(AuthRefused::BadCert);
        }
        let now = self.clock.unix();
        let skew = self.cfg.clock_skew;
        let p = hl_identity::DeviceProof::parse(proof).map_err(|_| AuthRefused::BadProof)?;
        p.check(challenge, &self.key.public(), host, exporter, now, skew)
            .map_err(|e| match e {
                hl_identity::Error::ClockSkew => AuthRefused::ClockSkew,
                e => classify(&e, 0),
            })?;
        let card = match card {
            Some(card) => card.to_vec(),
            None => {
                let cert =
                    hl_identity::DeviceCert::parse(cert).map_err(|_| AuthRefused::BadCert)?;
                self.card(&Fingerprint::of(&cert.identity))
                    .ok_or(AuthRefused::BadCard)?
                    .1
            }
        };
        let (c, dc) = hl_identity::verify_presented(&card, cert, &p.device, now, skew)
            .map_err(|e| classify(&e, card.len()))?;
        Ok(Verified {
            card: c,
            cert: dc,
            card_bytes: card,
            cert_bytes: cert.to_vec(),
        })
    }

    /// Admit a device [`Self::verify_device_proof`] verified to the
    /// classic session of the account `login`: steps 4 to 6 as for an ng
    /// login, and then the identity must be the one the account links
    /// now, on an account that allows identity login. One that links
    /// none is linked by a proof that showed its card (`card_shown`), as
    /// §8.2 "at auth" links one: from a certificate that may `manage`, on
    /// an `encrypted` session, to an identity linked to no other account.
    pub fn admit_device(
        &self,
        v: Verified,
        login: &str,
        card_shown: bool,
        encrypted: bool,
    ) -> Result<TransportIdentity, AuthRefused> {
        let Standing {
            fingerprint,
            handle,
            age,
            ..
        } = self.standing(&v.card, &v.cert, None, Assoc::Write)?;
        let account = self.auth.lookup(login).map_err(|e| {
            tracing::warn!("account lookup failed: {e}");
            AuthRefused::Backend
        })?;
        let account = match account.identity.fingerprint {
            Some(f) if f == fingerprint.0 => account,
            Some(_) => return Err(AuthRefused::NotLinked),
            None if !card_shown => return Err(AuthRefused::NotLinked),
            // Logging in as guest names no account to link.
            None if account.login == "guest" => return Err(AuthRefused::GuestLink),
            None if !v.cert.allows(caps::MANAGE) => return Err(AuthRefused::NoManage),
            // Someone riding a plain session could link the account to an
            // identity of their own.
            None if !encrypted => return Err(AuthRefused::Denied),
            // Refused below once linked, so the link is never written.
            None if !account.identity.identity_login => return Err(AuthRefused::Denied),
            None => {
                if self
                    .core
                    .person_banned(Some(&account.login), None, None)
                    .is_some()
                {
                    return Err(AuthRefused::Banned);
                }
                match self.link_exclusive(&account.login, &fingerprint)? {
                    LinkOutcome::Linked(a) => {
                        info!(login = %a.login, fingerprint = %fingerprint.short(), "identity linked by device proof");
                        a
                    }
                    LinkOutcome::Already(a) => a,
                    LinkOutcome::Taken(_) => return Err(AuthRefused::AlreadyLinked),
                    LinkOutcome::Refused(_) => return Err(AuthRefused::Denied),
                }
            }
        };
        if !account.identity.identity_login {
            return Err(AuthRefused::Denied);
        }
        let ident = TransportIdentity {
            identity: v.card.identity,
            device: v.cert.device,
            fingerprint,
            handle,
            age,
            outcome: Outcome::Linked,
            device_caps: v.cert.caps,
            device_expires: v.cert.expires,
            device_cert: v.cert_bytes,
            device_enc: v.cert.device_enc,
            account: Some(account.login),
            downstream_cleartext: false,
            quiet_until: None,
        };
        self.keep(&ident, None, &v.card, v.card_bytes, Downstream::Local);
        Ok(ident)
    }

    /// `POST /identity/auth`, challenge binding: the spec's step list
    /// (§5.2) with steps 4 and 6's revocation half stubbed. Consumes the
    /// challenge whether or not verification succeeds — a failed attempt
    /// doesn't get to retry against the same nonce. `host` is the
    /// request's `Host`, as for [`Self::verify_proof`].
    pub fn auth_with_proof(
        &self,
        card: &[u8],
        cert: &[u8],
        proof: &[u8],
        host: Option<&str>,
        req: AuthRequest<'_>,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        self.admit_verified(self.verify_proof(card, cert, proof, host)?, req)
    }

    /// Steps 1–3 of the proof binding (§5.2): the challenge spent, and the
    /// certificate, card and proof verified. `host` is the request's
    /// `Host`, which a `v = 2` proof must name.
    pub fn verify_proof(
        &self,
        card: &[u8],
        cert: &[u8],
        proof: &[u8],
        host: Option<&str>,
    ) -> Result<Verified, AuthRefused> {
        // Peek at the challenge inside the proof so we can consume it
        // before doing any signature work; a bad proof still burns it.
        let (challenge, v1) = match hl_identity::LoginProof::parse(proof) {
            Ok(p) => (p.challenge, p.host.is_none()),
            Err(_) => return Err(AuthRefused::BadProof),
        };
        {
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            match t.challenges.remove(&hash(&challenge)) {
                Some(issued) if self.clock.since(issued) < TTL => {}
                _ => return Err(AuthRefused::UnknownChallenge),
            }
        }
        if v1 && !self.cfg.login_proof_v1 {
            return Err(AuthRefused::UnsupportedProof);
        }
        if !v1 && !self.answers_as(host) {
            return Err(AuthRefused::WrongHost);
        }
        let ctx = LoginContext {
            challenge: &challenge,
            server_key: &self.key.public(),
            host,
            now: self.clock.unix(),
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
        if v1 {
            self.warn_v1(&v.fingerprint());
        }
        Ok(Verified {
            card: v.card,
            cert: v.cert,
            card_bytes: card.to_vec(),
            cert_bytes: cert.to_vec(),
        })
    }

    /// A `v = 1` login is one a relaying server could have made, so the
    /// operator hears of them, once a minute at most, until clients have
    /// moved on and `login_proof_v1` can be turned off.
    fn warn_v1(&self, fingerprint: &Fingerprint) {
        let now = self.clock.now();
        let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
        if t.v1_warned
            .is_some_and(|at| now.duration_since(at) < Duration::from_secs(60))
        {
            return;
        }
        t.v1_warned = Some(now);
        drop(t);
        tracing::warn!(
            fingerprint = %fingerprint.short(),
            "accepted a v1 login proof, which a relaying server can forward \
             (hotline-ng-auth.md §6.2); turning [identity] login_proof_v1 off refuses them"
        );
    }

    /// Admit a login [`Self::verify_proof`] or [`Self::verify_presented`]
    /// verified: steps 4 onward. Between the two, the caller fetches what
    /// the registrars publish against the identity, so that only a login
    /// that proved its key can send this server to a registrar.
    pub fn admit_verified(
        &self,
        v: Verified,
        req: AuthRequest<'_>,
    ) -> Result<(String, TransportIdentity), AuthRefused> {
        self.admit(
            v.card,
            v.cert,
            v.cert_bytes,
            v.card_bytes,
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
        self.admit_verified(self.verify_presented(card, cert, device)?, req)
    }

    /// Steps 1–3 of the mTLS binding (§5.3).
    pub fn verify_presented(
        &self,
        card: &[u8],
        cert: &[u8],
        device: &PublicKey,
    ) -> Result<Verified, AuthRefused> {
        if cert.len() > hl_identity::cert::MAX_BYTES {
            return Err(AuthRefused::BadCert);
        }
        let (c, dc) = hl_identity::verify_presented(
            card,
            cert,
            device,
            self.clock.unix(),
            self.cfg.clock_skew,
        )
        .map_err(|e| classify(&e, card.len()))?;
        Ok(Verified {
            card: c,
            cert: dc,
            card_bytes: card.to_vec(),
            cert_bytes: cert.to_vec(),
        })
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
        let Standing {
            fingerprint,
            handle,
            age,
            attested,
            now,
        } = self.standing(&card, &cert, req.rotation, assoc)?;

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
            } else if assoc == Assoc::Write
                && self
                    .core
                    .person_banned(Some(&account.login), None, None)
                    .is_some()
            {
                // A banned account gains no identity: the link would
                // outlive the ban as a second way in. Its password
                // verified, so saying why tells nobody anything new.
                return Err(AuthRefused::Banned);
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
                // A link its account refuses identity login by is refused
                // below once written, so where one would be written it is
                // refused first.
                let writes = account.identity.fingerprint.is_none()
                    && account.has_password
                    && account.identity.allow_self_link;
                if writes
                    && !account.identity.identity_login
                    && self.find_linked(&fingerprint)?.is_none()
                {
                    debug!(login = %account.login, "link at auth refused: identity_login is off");
                    return Err(AuthRefused::Denied);
                }
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
                            // Nothing to claim — the account is new — but
                            // called anyway so "linking claims" has no
                            // exception anyone has to remember (§4).
                            self.core.inbox_claim(&created.login, &fingerprint.0);
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

        // §7.3: a key nobody here answers for, with no accepted
        // attestation and no account, waits `newcomer_delay` from when it
        // was first seen before it may chat, message or post. Counted
        // from the first sighting, so reconnecting does not reset it.
        let quiet_until = (self.cfg.newcomer_delay > 0 && handle.is_none() && account.is_none())
            .then(|| {
                let first = self
                    .seen
                    .first_seen(&fingerprint.0, now)
                    .unwrap_or_else(|e| {
                        tracing::warn!("first sightings: {}", e.0);
                        now
                    });
                first.saturating_add(self.cfg.newcomer_delay)
            })
            .filter(|until| *until > now);

        let ident = TransportIdentity {
            identity: card.identity,
            device: cert.device,
            fingerprint,
            handle,
            age,
            outcome,
            device_caps: cert.caps,
            device_expires: cert.expires,
            device_cert: cert_bytes,
            device_enc: cert.device_enc,
            account,
            downstream_cleartext: req.downstream == Downstream::Cleartext,
            quiet_until,
        };

        // A token only for a fresh `/identity/auth`. Re-admitting a device
        // on file hands its identity straight to the upgrade that asked,
        // and a token minted there would sit unread in the table for a
        // minute per upgrade.
        let token = (assoc == Assoc::Write).then(random32);
        self.keep(&ident, token.as_ref(), &card, card_bytes, req.downstream);
        Ok((token.as_ref().map(|t| b64(t)).unwrap_or_default(), ident))
    }

    /// What an admission leaves behind: the token, when there is one, the
    /// device and the card, and the card's commitment.
    fn keep(
        &self,
        ident: &TransportIdentity,
        token: Option<&[u8; 32]>,
        card: &hl_identity::Card,
        card_bytes: Vec<u8>,
        downstream: Downstream,
    ) {
        let inst = self.clock.now();
        {
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(token) = token {
                remember_token(&mut t.tokens, hash(token), ident.clone(), inst, MAX_TOKENS);
            }
            remember_device(
                &mut t.devices,
                ident.device,
                DeviceRecord {
                    cert: ident.device_cert.clone(),
                    identity: ident.identity,
                    expires: ident.device_expires,
                    downstream,
                    seen: inst,
                },
                self.clock.unix(),
            );
            remember_card(&mut t.cards, ident.fingerprint, card, card_bytes, inst);
        }
        // Anchor a first commitment outside the table lock — it writes a
        // file. A changed one was refused by `standing`.
        //
        // Only for an identity with standing here: an account (linked or
        // just created) or an attestation this server accepted. §13 says
        // every table an unauthenticated caller can grow is bounded, and
        // with `unattested = guest` a durable line per fresh key is not
        // that. What the commitment protects is an identity people on
        // this server have a relationship with; a key nobody knows has
        // nothing to protect yet, and anchors on its first login here.
        if let Some(s) = card.successor {
            self.anchor(ident, s);
        }
    }

    /// Steps 4 to 6 (§5.2), as far as they are about the identity rather
    /// than an account: revocation, the registrars' records, attestations,
    /// the card's commitments, bans and the admission policy. `assoc`
    /// says whether what follows writes, and so whether bans are read
    /// here.
    fn standing(
        &self,
        card: &hl_identity::Card,
        cert: &hl_identity::DeviceCert,
        rotation: Option<&[u8]>,
        assoc: Assoc,
    ) -> Result<Standing, AuthRefused> {
        let fingerprint = Fingerprint::of(&card.identity);

        // Step 4, revocation: the operator's own list, consulted first and
        // needing no registrar (`identity-registrar.md`). A revoked
        // device's cached certificate goes with it, so the mTLS
        // path cannot re-admit it from the cache. The registrar's
        // published records, when there is a registrar to fetch them
        // from, are consulted here too.
        // A key rotated away from is told where it went, which
        // `is_revoked` would not say.
        if let Some(successor) = self.rotated_to(&fingerprint) {
            debug!(fingerprint = %fingerprint.short(), successor = %successor.short(), "identity auth refused: rotated");
            return Err(AuthRefused::Rotated { successor });
        }
        if let Some(bytes) = rotation {
            self.rotation_shown(bytes, &fingerprint);
        }
        self.finish_rotations(Some(&fingerprint));
        let device = Fingerprint::of(&cert.device);
        if self.core.is_revoked(&fingerprint.0, &device.0) {
            debug!(
                fingerprint = %fingerprint.short(),
                device = %device.short(),
                "identity auth refused: revoked here"
            );
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            t.devices.remove(&cert.device);
            return Err(AuthRefused::Revoked);
        }

        // A banned registrar refuses every identity that carries its
        // attestation, verified or not, and whatever else the card
        // carries: a card is its holder's own signature, so what is on it
        // its holder chose, and nobody can put it on another's.
        if card
            .attestations
            .iter()
            .any(|a| self.cfg.banned_registrars.contains(&a.registrar))
        {
            info!(fingerprint = %fingerprint.short(), "identity auth refused: a banned registrar's attestation");
            return Err(AuthRefused::Denied);
        }

        // Step 4, continued: what the registrars that attested it publish.
        let now = self.clock.unix();
        let attestations = self.apply_records(card, cert, now)?;
        // A rotation to this key whose moves have not all landed would
        // leave it to be admitted without the predecessor's account, and
        // `new_accounts = create` to make it another one; it is admitted
        // once the moves land, which this admission has just retried.
        if self
            .anchors
            .as_ref()
            .is_some_and(|a| !a.unmoved(Some(&fingerprint)).is_empty())
        {
            tracing::warn!(fingerprint = %fingerprint.short(), "identity auth refused: its rotation's moves have not all landed");
            return Err(AuthRefused::Backend);
        }

        // Step 5: attestations against the trusted registrars' keys.
        let (handle, age) = match &attestations {
            Some(atts) => self.accept_attestations(atts, now),
            None => (None, 0),
        };

        // A card that moves a committed successor is refused outright —
        // *first*, before any account is linked or created. Checking it
        // after the writes meant a refused auth could still leave a link
        // behind, which is the opposite of what the anchor is for.
        if successor_changed(self.committed_successor(&fingerprint), card) {
            debug!(fingerprint = %fingerprint.short(), "card changes a committed successor");
            return Err(AuthRefused::BadCard);
        }
        if let Some(reg) = &self.registrar {
            match reg.check_card(card) {
                Ok(()) => {}
                Err(hxd_registrar::Refusal::SuccessorMismatch) => {
                    debug!(
                        fingerprint = %fingerprint.short(),
                        "card changes the successor this server's registrar holds"
                    );
                    return Err(AuthRefused::BadCard);
                }
                Err(e) => {
                    tracing::warn!("registrar could not check a card: {e}");
                    return Err(AuthRefused::Backend);
                }
            }
        }

        // A banned person is refused before anything below writes: an
        // account created for a banned identity, or a link to one, is a
        // way back in that the ban was meant to close. Re-admitting a
        // device on file writes nothing, and the login on the socket it
        // opens is refused with the ban's reason, so that is left to it.
        if assoc == Assoc::Write {
            // A ban's `*@host` is the registrar's, so it reads every
            // handle the card names, as `banned_registrars` does.
            let named = card.attestations.iter().map(|a| Some(a.full_handle()));
            let hit = std::iter::once(handle.clone()).chain(named).find_map(|h| {
                self.core
                    .person_banned(None, Some(&fingerprint.0), h.as_deref())
            });
            if let Some(hit) = hit {
                info!(fingerprint = %fingerprint.short(), ban = hit.id, "identity auth refused: banned");
                return Err(AuthRefused::Banned);
            }
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
        Ok(Standing {
            fingerprint,
            handle,
            age,
            attested,
            now,
        })
    }

    fn find_linked(&self, fp: &Fingerprint) -> Result<Option<Account>, AuthRefused> {
        self.auth.find_by_fingerprint(&fp.0).map_err(|e| {
            tracing::warn!("fingerprint lookup failed: {e}");
            AuthRefused::Backend
        })
    }

    /// One backend call that reads, decides and writes a link — and the
    /// obligation that comes with writing one.
    ///
    /// §4 of `docs/private-messages.md`: an account's existing mail is
    /// keyed by its bare login, and the mailbox rule is strict, so
    /// without `claim` the mail is stranded the instant the account
    /// gains a fingerprint. Called here rather than at each of the three
    /// link sites, so there is one place to forget it and it isn't
    /// forgotten.
    fn link_exclusive(&self, login: &str, fp: &Fingerprint) -> Result<LinkOutcome, AuthRefused> {
        let outcome = self.auth.link_identity(login, &fp.0).map_err(|e| {
            tracing::warn!("link write failed: {e}");
            AuthRefused::Backend
        })?;
        if let LinkOutcome::Linked(a) = &outcome {
            let moved = self.core.inbox_claim(&a.login, &fp.0);
            if moved > 0 {
                info!(login = %a.login, moved, "inbox claimed by the new identity link");
            }
        }
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
        let now = self.clock.now();
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
                .push(self.clock.now());
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
            Ok(_) => return Err(AuthRefused::GuestLink),
            Err(AuthError::NoSuchAccount | AuthError::BadProof) => {
                return Err(AuthRefused::LoginFailed)
            }
            Err(AuthError::Backend(e)) => {
                tracing::warn!("auth backend failure: {e}");
                return Err(AuthRefused::Backend);
            }
        };
        // Neither a banned identity nor a banned account is linked: the
        // link would carry the one past the other's ban.
        if self
            .core
            .person_banned(
                Some(&account.login),
                Some(&ident.fingerprint.0),
                ident.handle.as_deref(),
            )
            .is_some()
        {
            return Err(AuthRefused::Banned);
        }
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

    /// `POST /identity/unlink` (§8.4). The `usize` is how many stored
    /// messages stay with the identity rather than with the account.
    ///
    /// Mail is addressed to a person, and under the strict mailbox rule
    /// (`docs/private-messages.md` §4) the fingerprint *is* the person:
    /// an account that gives up its link gives up the mailbox that link
    /// addressed, and that mail travels with the identity to wherever it
    /// links next. That is deliberate — the alternative hands one
    /// person's correspondence to whoever links to the account
    /// afterwards — but it is also invisible from the account's side, so
    /// say the number out loud rather than letting a user discover their
    /// inbox has emptied.
    pub fn unlink(&self, ident: &TransportIdentity) -> Result<(Account, usize), AuthRefused> {
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
                self.core.friendships_unlinked(&ident.fingerprint.0);
                let stays = self
                    .core
                    .inbox_counts_of(&hxd_core::inbox::Mailbox::identified(
                        a.login.clone(),
                        ident.fingerprint.0,
                    ))
                    .total;
                info!(login = %a.login, fingerprint = %ident.fingerprint.short(), stays, "identity unlinked");
                Ok((a, stays))
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

    /// `identity-registrar.md` §7.3: the records the registrars that
    /// attested the identity publish against it, applied in time order.
    /// A revocation of it or of this device refuses; a freeze, or records
    /// past their lifetime, refuse or downgrade as configured. Answers the
    /// attestations that survive, or `None` when the identity is to be
    /// taken as unattested.
    fn apply_records(
        &self,
        card: &hl_identity::Card,
        cert: &hl_identity::DeviceCert,
        now: u64,
    ) -> Result<Option<Vec<Attestation>>, AuthRefused> {
        let Some(registrars) = &self.registrars else {
            return Ok(Some(card.attestations.clone()));
        };
        let fingerprint = Fingerprint::of(&card.identity);
        // Only an attestation under a key its registrar publishes was
        // fetched for, so only its registrar can be stale.
        let hosts: Vec<String> = card
            .attestations
            .iter()
            .filter(|a| {
                registrars
                    .keys(&a.registrar, &a.identity, now)
                    .contains(&a.registrar_key)
            })
            .map(|a| a.registrar.clone())
            .collect();
        let found = registrars.lookup(&card.identity, &hosts, now);
        let mut unattested = false;
        if found.stale {
            match registrars.config().stale {
                crate::registrars::Stale::Cached => {
                    info!(fingerprint = %fingerprint.short(), "registrar records past their lifetime; using what is held");
                }
                crate::registrars::Stale::Guest => unattested = true,
                crate::registrars::Stale::Deny => return Err(AuthRefused::Denied),
            }
        }
        let mut attestations = card.attestations.clone();
        // A registrar's latest freeze record is its word; any registrar's
        // standing freeze holds.
        let mut frozen: HashMap<&str, bool> = HashMap::new();
        for record in &found.records {
            match record {
                Record::RevokeIdentity(_) => {
                    info!(fingerprint = %fingerprint.short(), "identity auth refused: revoked at its registrar");
                    return Err(AuthRefused::Revoked);
                }
                Record::RevokeDevice(r) if r.device == cert.device => {
                    info!(fingerprint = %fingerprint.short(), "identity auth refused: device revoked at its registrar");
                    let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
                    t.devices.remove(&cert.device);
                    return Err(AuthRefused::Revoked);
                }
                Record::Freeze(f) => {
                    frozen.insert(&f.registrar, f.frozen);
                }
                Record::RevokeAttestation(r) => attestations.retain(|a| !r.voids(a)),
                Record::Rotate(r) => {
                    let (from, to) = (Fingerprint::of(&r.identity), Fingerprint::of(&r.successor));
                    let record = found
                        .rotations
                        .iter()
                        .find(|(f, t, _)| *f == from && *t == to);
                    self.accept_rotation(
                        from,
                        to,
                        "a registrar's records",
                        record.map(|(_, _, b)| b.as_slice()),
                    );
                    // Refused only to a rotation accepted here, so one
                    // the anchor overrules names nobody; with no file to
                    // keep rotations in, the record is all there is.
                    let accepted = match &self.anchors {
                        Some(_) => self.rotated_to(&from),
                        None => Some(to),
                    };
                    if let Some(successor) = accepted.filter(|_| from == fingerprint) {
                        return Err(AuthRefused::Rotated { successor });
                    }
                }
                Record::RevokeDevice(_) => {}
            }
        }
        if frozen.values().any(|f| *f) {
            match self.cfg.frozen {
                Frozen::Deny => {
                    info!(fingerprint = %fingerprint.short(), "identity auth refused: frozen at its registrar");
                    return Err(AuthRefused::Denied);
                }
                Frozen::Guest => unattested = true,
            }
        }
        Ok((!unattested).then_some(attestations))
    }

    fn accept_attestations(&self, atts: &[Attestation], now: u64) -> (Option<String>, u64) {
        let mut best: Option<(String, u64)> = None;
        for a in atts {
            let keys = match &self.registrars {
                Some(registrars) => registrars.keys(&a.registrar, &a.identity, now),
                None => self
                    .cfg
                    .registrar_keys
                    .get(&a.registrar)
                    .into_iter()
                    .copied()
                    .collect(),
            };
            if !keys
                .iter()
                .any(|k| a.verify_registrar(k, now, self.cfg.clock_skew).is_ok())
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
            .is_none_or(|(_, issued)| self.clock.since(*issued) >= TTL);
        if expired {
            t.tokens.remove(&key);
            return None;
        }
        // A token minted before its key was revoked is not a way round the
        // revocation: it dies here, whichever caller holds it.
        let revoked = t.tokens.get(&key).is_some_and(|(ident, _)| {
            self.core
                .is_revoked(&ident.fingerprint.0, &Fingerprint::of(&ident.device).0)
        });
        if revoked {
            t.tokens.remove(&key);
            return None;
        }
        if consume {
            return t.tokens.remove(&key).map(|(ident, _)| ident);
        }
        t.tokens.get(&key).map(|(ident, _)| ident.clone())
    }

    /// `identity-records.md` §2: the lists of every identity with a
    /// session here refreshed where they are due, a few at a time, and
    /// what they now refuse installed in the core, which ends the
    /// sessions it refuses there and then. Answers those, for the log.
    ///
    /// The lists asked for are the ones admission fetched, by the
    /// identity's fingerprint, never the card it shows now: a card can be
    /// replaced with one that names no registrar, and fall out of the
    /// cache, while the session it was admitted under goes on.
    pub async fn sweep_records(self: &Arc<Self>) -> Vec<(hxd_core::Uid, String)> {
        let Some(registrars) = self.registrars.clone() else {
            return Vec::new();
        };
        let live: Vec<Fingerprint> = self
            .core
            .session_identities()
            .into_iter()
            .map(Fingerprint)
            .collect();
        let (now, sweep) = (self.clock.unix(), self.clock.now());
        registrars.retain_attested(&live);
        futures_util::stream::iter(&live)
            .for_each_concurrent(8, |fp| {
                let registrars = registrars.clone();
                async move { registrars.refresh_held(*fp, now, sweep).await }
            })
            .await;
        let frozen_refuses = self.cfg.frozen == Frozen::Deny;
        let this = self.clone();
        // A rotation found is accepted as at an admission, which refuses
        // its predecessor unless an anchor here overrules it; with no
        // file to keep rotations in, the record refuses it here.
        crate::spawn_blocking("identity", move || {
            let (mut refused, rotations) = registrars.refused(&live, frozen_refuses);
            for (from, to, record) in rotations {
                this.accept_rotation(from, to, "a registrar's records", Some(&record));
                if this.anchors.is_none() {
                    refused.identities.insert(from.0);
                }
            }
            // Here too: installing it drops what newly revoked devices
            // presented, from the store.
            this.core.set_published_revocations(refused)
        })
        .await
        .unwrap_or_default()
    }

    /// The card a device on file is admitted under, as `identity_for_device`
    /// would read it: for the caller to fetch its records first. Verifies
    /// the card: called off the reactor.
    pub fn card_for_device(&self, device: &PublicKey) -> Option<hl_identity::Card> {
        let bytes = {
            let t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            let rec = t.devices.get(device)?;
            t.cards.get(&Fingerprint::of(&rec.identity))?.bytes.clone()
        };
        hl_identity::Card::parse(&bytes).ok()
    }

    /// The mTLS "connection is the credential" path (§5.3): a device on
    /// file with a still-valid certificate needs no token.
    ///
    /// Re-admits read-only. The upgrade that lands here is not a fresh
    /// `/identity/auth`, so it doesn't get to repeat that call's side
    /// effects — no link, no account creation, and no token. It does
    /// carry the `downstream` the device last declared there, since it
    /// has no way to declare one itself. A rotation learned here still
    /// moves what it moves, as at any admission. Signatures *are* re-checked
    /// rather than the cache's shape trusted; that's two verifications,
    /// which is why callers run this on the blocking pool.
    pub fn identity_for_device(&self, device: &PublicKey) -> Option<TransportIdentity> {
        let (card_bytes, cert_bytes, downstream) = {
            let t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            let rec = t.devices.get(device)?;
            if rec.expires + self.cfg.clock_skew < self.clock.unix() {
                return None;
            }
            let card = t.cards.get(&Fingerprint::of(&rec.identity))?.bytes.clone();
            (card, rec.cert.clone(), rec.downstream)
        };
        let (c, dc) = hl_identity::verify_presented(
            &card_bytes,
            &cert_bytes,
            device,
            self.clock.unix(),
            self.cfg.clock_skew,
        )
        .ok()?;
        self.admit(
            c,
            dc,
            cert_bytes,
            card_bytes,
            AuthRequest {
                downstream,
                ..AuthRequest::default()
            },
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
            remember_card(&mut t.cards, fp, &card, bytes.to_vec(), self.clock.now());
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

    /// The key `fp` rotated to, as accepted here.
    pub fn rotated_to(&self, fp: &Fingerprint) -> Option<Fingerprint> {
        self.anchors.as_ref().and_then(|a| a.rotated(fp))
    }

    /// A rotation an `auth` request carries for the identity it admits
    /// (§7.4): accepted only to the successor this server anchored for
    /// the predecessor. Without an anchor nobody here can say the old
    /// owner consented, so it is ignored, and the key is simply new.
    fn rotation_shown(&self, bytes: &[u8], successor: &Fingerprint) {
        let r = match hl_identity::Rotation::parse(bytes) {
            Ok(r) if Fingerprint::of(&r.successor) == *successor => r,
            Ok(_) => return debug!("rotation shown for another key; ignored"),
            Err(e) => return debug!("rotation shown did not verify: {e}"),
        };
        let from = Fingerprint::of(&r.identity);
        // The anchor on file, not the card cache behind
        // `committed_successor`: a card a thief showed after the cache
        // forgot the owner's would otherwise be the consent.
        if self.anchors.as_ref().and_then(|a| a.get(&from)) == Some(successor.0) {
            self.accept_rotation(from, *successor, "the successor's auth", Some(bytes));
        } else {
            debug!(predecessor = %from.short(), "rotation shown for a key not anchored to it; ignored");
        }
    }

    /// Accept `from`'s rotation to `to`, verified by whoever calls: it is
    /// written beside the anchors, and `from`'s cached cards, devices and
    /// tokens are dropped. The first rotation accepted for a key is the
    /// one that stands, and one to a key other than the successor this
    /// server anchored for it is ignored: the commitment exists to beat a
    /// thief who signs a rotation with a stolen key, whoever publishes it.
    ///
    /// The rotation's `record`, where the caller has it, is kept with the
    /// core once the rotation stands here, for the friends of the identity
    /// to fetch and check it by (`docs/proposals/portable-friends.md` §10).
    fn accept_rotation(
        &self,
        from: Fingerprint,
        to: Fingerprint,
        source: &str,
        record: Option<&[u8]>,
    ) {
        let Some(anchors) = &self.anchors else {
            return;
        };
        let keep = |r: Option<&[u8]>| {
            if let Some(r) = r.filter(|r| !r.is_empty()) {
                self.core.keep_rotation_record(r);
            }
        };
        if let Some(stands) = anchors.rotated(&from) {
            if stands == to {
                keep(record);
            }
            return;
        }
        if self.committed_successor(&from).is_some_and(|c| c != to.0) {
            tracing::warn!(predecessor = %from.short(), successor = %to.short(), source, "rotation to a key other than the one anchored; ignored");
            return;
        }
        if !anchors.rotate(&from, &to) {
            return;
        }
        keep(record);
        info!(predecessor = %from, successor = %to, source, "identity rotated");
        for (uid, nick) in self.core.refuse_rotated(from.0) {
            info!(uid, nick = %nick, "session ended: its key rotated away");
        }
        {
            let mut t = self.tables.lock().unwrap_or_else(|e| e.into_inner());
            t.cards.remove(&from);
            t.devices
                .retain(|_, d| Fingerprint::of(&d.identity) != from);
            t.tokens.retain(|_, (ident, _)| ident.fingerprint != from);
        }
        self.finish_rotation(from, to);
    }

    /// Move what `from`'s rotation to `to` moves (`docs/identity-records.md`
    /// §4): its account link, then what the core keeps under its key. It
    /// is noted done only once all of it has moved; until then it is
    /// asked again at each start and at every admission of the successor,
    /// which every step allows.
    fn finish_rotation(&self, from: Fingerprint, to: Fingerprint) {
        let Some(anchors) = &self.anchors else {
            return;
        };
        let account = match self.auth.rotate_link(&from.0, &to.0) {
            Ok(account) => account,
            Err(e) => {
                tracing::warn!(predecessor = %from.short(), "rotation: the account link did not move: {e}");
                return;
            }
        };
        if let Err(e) = self.core.rotate_identity(&from.0, &to.0) {
            tracing::warn!(predecessor = %from.short(), "rotation: what the server keeps did not all move: {e}");
            return;
        }
        if let Some(account) = account {
            info!(account = %account.login, successor = %to.short(), "rotation: the account now links the successor");
        }
        anchors.moved(&from);
    }

    /// [`Self::finish_rotation`] for each rotation, to `to` or to
    /// anyone, whose moves have not all landed.
    fn finish_rotations(&self, to: Option<&Fingerprint>) {
        for (from, to) in self.anchors.iter().flat_map(|a| a.unmoved(to)) {
            self.finish_rotation(from, to);
        }
    }
}

/// Insert a device record, evicting expired entries and then the
/// least-recently-seen if the table is at its ceiling.
/// Insert a transport token, dropping expired ones and then, if the
/// table is still at `cap`, the oldest. Evicting costs whoever held the
/// oldest token a 401 and a second `/identity/auth`; refusing would cost
/// every caller that, for as long as the flood lasts.
fn remember_token(
    tokens: &mut HashMap<[u8; 32], (TransportIdentity, Instant)>,
    key: [u8; 32],
    ident: TransportIdentity,
    now: Instant,
    cap: usize,
) {
    tokens.retain(|_, (_, issued)| now.duration_since(*issued) < TTL);
    if tokens.len() >= cap {
        if let Some(oldest) = tokens
            .iter()
            .min_by_key(|(_, (_, issued))| *issued)
            .map(|(k, _)| *k)
        {
            tokens.remove(&oldest);
        }
    }
    tokens.insert(key, (ident, now));
}

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
    /// Predecessor → successor, for each rotation accepted (§7.4), and
    /// whether what it moves has all moved.
    rotated: Mutex<HashMap<Fingerprint, (Fingerprint, bool)>>,
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
# A rotation accepted: <predecessor fingerprint> => <successor fingerprint>,
# then again, ending in the word moved, once everything it moves has moved.
";

impl Anchors {
    /// Load, tolerating a missing file. A malformed line is skipped with
    /// a warning rather than refusing to start: losing one anchor is bad,
    /// but a server that won't boot is worse, and the operator sees it.
    /// Any other read failure leaves the table read-only for the run.
    fn load(path: std::path::PathBuf) -> Anchors {
        use std::collections::hash_map::Entry;
        let mut map: HashMap<Fingerprint, [u8; 32]> = HashMap::new();
        let mut rotated: HashMap<Fingerprint, (Fingerprint, bool)> = HashMap::new();
        let mut writable = true;
        let mut compact = false;
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for (n, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((from, to)) = line.split_once("=>") {
                        let (to, moved) = match to.trim().strip_suffix("moved") {
                            Some(to) => (to, true),
                            None => (to, false),
                        };
                        match (
                            Fingerprint::parse(from.trim()),
                            Fingerprint::parse(to.trim()),
                        ) {
                            // The first rotation on file stands, as
                            // `rotate` keeps it; a later line can only
                            // say it has moved.
                            (Some(from), Some(to)) => match rotated.entry(from) {
                                Entry::Occupied(mut e) => {
                                    compact = true;
                                    if e.get().0 == to {
                                        e.get_mut().1 |= moved;
                                    }
                                }
                                Entry::Vacant(v) => {
                                    v.insert((to, moved));
                                }
                            },
                            _ => {
                                compact = true;
                                tracing::warn!(
                                    "{}:{}: malformed rotation, skipped",
                                    path.display(),
                                    n + 1
                                );
                            }
                        }
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
            let mut lines: Vec<_> = rotated.iter().collect();
            lines.sort_by_key(|(fp, _)| fp.to_string());
            for (from, (to, moved)) in lines {
                let moved = if *moved { " moved" } else { "" };
                text.push_str(&format!("{from} => {to}{moved}\n"));
            }
            if let Err(e) = write_private(&path, &text) {
                tracing::warn!("{}: {e}; successor anchors not compacted", path.display());
            }
        }
        Anchors {
            path,
            map: Mutex::new(map),
            rotated: Mutex::new(rotated),
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

    fn rotated_from(&self) -> Vec<Fingerprint> {
        let rotated = self.rotated.lock().unwrap_or_else(|e| e.into_inner());
        rotated.keys().copied().collect()
    }

    fn rotated(&self, fp: &Fingerprint) -> Option<Fingerprint> {
        self.rotated
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(fp)
            .map(|(to, _)| *to)
    }

    /// The rotations whose moves have not all landed, to `to` or, with
    /// `None`, to anyone.
    fn unmoved(&self, to: Option<&Fingerprint>) -> Vec<(Fingerprint, Fingerprint)> {
        let rotated = self.rotated.lock().unwrap_or_else(|e| e.into_inner());
        rotated
            .iter()
            .filter(|(_, (t, moved))| !moved && to.is_none_or(|to| t == to))
            .map(|(from, (t, _))| (*from, *t))
            .collect()
    }

    /// Note that `from`'s rotation has moved all it moves.
    fn moved(&self, from: &Fingerprint) {
        let to = {
            let mut rotated = self.rotated.lock().unwrap_or_else(|e| e.into_inner());
            match rotated.get_mut(from) {
                Some((to, moved)) if !*moved => {
                    *moved = true;
                    *to
                }
                _ => return,
            }
        };
        if !self.writable {
            return;
        }
        let _io = self.io.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = append_private(&self.path, &format!("{from} => {to} moved\n")) {
            tracing::error!("{}: {e}; a rotation's moves not noted", self.path.display());
        }
    }

    /// Record `from`'s rotation to `to`, unless one is on file for it
    /// already. False when nothing was recorded.
    /// Kept in memory whether or not the file can take it: refusing the
    /// predecessor is the safe direction, as an anchor kept only in
    /// memory is.
    fn rotate(&self, from: &Fingerprint, to: &Fingerprint) -> bool {
        let full = {
            let mut rotated = self.rotated.lock().unwrap_or_else(|e| e.into_inner());
            if rotated.contains_key(from) {
                return false;
            }
            rotated.insert(*from, (*to, false));
            rotated.len() > MAX_ANCHORS
        };
        if !self.writable || full {
            tracing::warn!(predecessor = %from.short(), "rotation kept for this run only: the successor file is unwritable or full");
            return true;
        }
        let _io = self.io.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = append_private(&self.path, &format!("{from} => {to}\n")) {
            tracing::error!("{}: {e}; rotation not persisted", self.path.display());
        }
        true
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
        E::HostMismatch => AuthRefused::WrongHost,
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
        Account::new(
            login.into(),
            login.into(),
            password,
            hxd_core::IdentityLink {
                identity_login: true,
                allow_self_link: true,
                ..Default::default()
            },
            Default::default(),
        )
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
            let want = if a.has_password { "pw" } else { "" };
            let ok = match proof {
                Proof::Plain(pw) => pw == want.as_bytes(),
                Proof::Keyed(check) => check(want),
            };
            if !ok {
                return Err(AuthError::BadProof);
            }
            Ok(a)
        }
        fn logins(&self) -> Result<Vec<String>, AuthError> {
            Ok(self.accounts.lock().unwrap().keys().cloned().collect())
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
        fn rotate_link(
            &self,
            from: &[u8; 32],
            to: &[u8; 32],
        ) -> Result<Option<Account>, AuthError> {
            let mut a = self.accounts.lock().unwrap();
            if a.values().any(|x| x.identity.fingerprint == Some(*to)) {
                return Ok(None);
            }
            let found = a
                .values_mut()
                .find(|x| x.identity.fingerprint == Some(*from));
            Ok(found.map(|x| {
                x.identity.fingerprint = Some(*to);
                x.clone()
            }))
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

    /// The name the tests' requests are addressed to.
    const TEST_HOST: &str = "hl.example";

    fn state(mut cfg: IdentityConfig) -> IdentityState {
        cfg.hosts.push(TEST_HOST.into());
        IdentityState::new(
            ServerKey::from_seed(&[5u8; 32]),
            cfg,
            MemAuth::new(),
            Arc::new(hxd_core::Core::new()),
        )
    }

    fn state_with(mut cfg: IdentityConfig, auth: Arc<MemAuth>) -> IdentityState {
        cfg.hosts.push(TEST_HOST.into());
        IdentityState::new(
            ServerKey::from_seed(&[5u8; 32]),
            cfg,
            auth,
            Arc::new(hxd_core::Core::new()),
        )
    }

    #[test]
    fn a_rotation_is_kept_beside_the_anchors_and_refused_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("successors");
        let (old, new, other) = (
            IdentityKey::from_seed(&[1; 32]),
            IdentityKey::from_seed(&[2; 32]),
            IdentityKey::from_seed(&[3; 32]),
        );
        let anchors = Anchors::load(path.clone());
        anchors.commit(&old.fingerprint(), new.fingerprint().0);
        assert!(anchors.rotate(&old.fingerprint(), &new.fingerprint()));
        assert!(!anchors.rotate(&old.fingerprint(), &other.fingerprint()));

        assert_eq!(anchors.unmoved(None).len(), 1);

        // A start finishes what the rotation moves, and the file says so.
        let st = state(IdentityConfig {
            anchors: Some(path.clone()),
            ..Default::default()
        });
        assert!(Anchors::load(path).unmoved(None).is_empty());
        assert_eq!(st.rotated_to(&old.fingerprint()), Some(new.fingerprint()));
        assert_eq!(
            st.committed_successor(&old.fingerprint()),
            Some(new.fingerprint().0)
        );
        let dev = DeviceKey::from_seed(&[9; 32]);
        let (card, cert) = objects(&old, &dev);
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap();
        assert_eq!(
            st.auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default()
            )
            .map(|_| ()),
            Err(AuthRefused::Rotated {
                successor: new.fingerprint()
            })
        );
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
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap();
        let (token, ident) = st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
            .unwrap();
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);
        assert_eq!(ident.fingerprint, id.fingerprint());
        let redeemed = st.redeem(&token, true).unwrap();
        assert_eq!(redeemed.device, dev.public());
        assert!(st.redeem(&token, true).is_none(), "single use");
        // The challenge is consumed too.
        let proof2 = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap();
        assert_eq!(
            st.auth_with_proof(
                &card,
                &cert,
                &proof2,
                Some(TEST_HOST),
                AuthRequest::default()
            ),
            Err(AuthRefused::UnknownChallenge)
        );
        // And the card is cached byte-exactly.
        assert_eq!(st.card(&id.fingerprint()).unwrap().1, card);
    }

    #[test]
    fn a_device_on_file_keeps_the_downstream_it_declared() {
        // A tunnel that said `cleartext` at auth, then upgrades on its
        // certificate alone, must still be marked cleartext: the upgrade
        // has nowhere to say it again.
        let st = state(IdentityConfig {
            unattested: Unattested::Guest,
            ..Default::default()
        });
        let id = IdentityKey::from_seed(&[21u8; 32]);
        let dev = DeviceKey::from_seed(&[22u8; 32]);
        let (card, cert) = objects(&id, &dev);
        let proof = proof_for(&st, &dev);
        let req = AuthRequest {
            downstream: Downstream::Cleartext,
            ..AuthRequest::default()
        };
        st.auth_with_proof(&card, &cert, &proof, Some(TEST_HOST), req)
            .unwrap();

        let tokens = st.tables.lock().unwrap().tokens.len();
        let on_file = st.identity_for_device(&dev.public()).unwrap();
        assert!(on_file.downstream_cleartext);
        // And re-admitting mints no token nobody will redeem.
        assert_eq!(st.tables.lock().unwrap().tokens.len(), tokens);

        // A later auth that says `local` is what the device is now.
        let proof = proof_for(&st, &dev);
        st.auth_with_proof(
            &card,
            &cert,
            &proof,
            Some(TEST_HOST),
            AuthRequest::default(),
        )
        .unwrap();
        assert!(
            !st.identity_for_device(&dev.public())
                .unwrap()
                .downstream_cleartext
        );
    }

    #[test]
    fn the_token_table_is_bounded() {
        let st = state(IdentityConfig {
            unattested: Unattested::Guest,
            ..Default::default()
        });
        let id = IdentityKey::from_seed(&[23u8; 32]);
        let dev = DeviceKey::from_seed(&[24u8; 32]);
        let (card, cert) = objects(&id, &dev);
        let proof = proof_for(&st, &dev);
        let (_, ident) = st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
            .unwrap();

        let mut tokens = HashMap::new();
        let start = Instant::now();
        for i in 0..3u8 {
            let at = start + Duration::from_millis(u64::from(i));
            remember_token(&mut tokens, [i; 32], ident.clone(), at, 2);
        }
        assert_eq!(tokens.len(), 2);
        assert!(!tokens.contains_key(&[0u8; 32]), "the oldest goes first");
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
            st.auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default()
            ),
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
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap();
        assert_eq!(
            st.auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default()
            )
            .unwrap_err(),
            AuthRefused::Denied
        );

        let st = state(IdentityConfig {
            allow_list: vec![id.fingerprint().to_string()],
            ..Default::default()
        });
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap();
        assert!(st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default()
            )
            .is_ok());

        let st = state(IdentityConfig {
            allow_list: vec!["someone-else".into()],
            ..Default::default()
        });
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap();
        assert_eq!(
            st.auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default()
            )
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
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now).unwrap();
        let (_, ident) = st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
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
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now).unwrap();
        let (_, ident) = st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
            .unwrap();
        // The handle is still reported — it verified — but the identity
        // counts as unattested for policy.
        assert_eq!(ident.handle.as_deref(), Some("alice@hl.example"));
        assert_eq!(ident.outcome, Outcome::UnattestedGuest);

        // Same card, registrar not trusted: unattested.
        let st = state(IdentityConfig::default());
        let ch = st.issue_challenge().unwrap();
        let proof = LoginProof::sign(&dev, &ch, &st.server_key(), TEST_HOST, now).unwrap();
        let (_, ident) = st
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
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
            device_expires: u64::MAX,
            device_cert: Vec::new(),
            device_enc: [0; 32],
            account: None,
            downstream_cleartext: false,
            quiet_until: None,
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

    #[test]
    fn only_a_configured_host_is_vouched_for_or_logged_in_as() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let (card, cert) = objects(&id, &dev);
        for (hosts, host, signed, login) in [
            (vec![], "b.example", false, Err(AuthRefused::WrongHost)),
            (
                vec!["hl.example".to_owned()],
                "b.example",
                false,
                Err(AuthRefused::WrongHost),
            ),
            (
                vec!["hl.example".to_owned()],
                "HL.example:443",
                true,
                Ok(()),
            ),
        ] {
            let st = IdentityState::new(
                ServerKey::from_seed(&[5u8; 32]),
                IdentityConfig {
                    hosts: hosts.clone(),
                    ..Default::default()
                },
                MemAuth::new(),
                Arc::new(hxd_core::Core::new()),
            );
            let ch = st.issue_challenge().unwrap();
            assert_eq!(
                st.sign_challenge(&ch, Some(host)).is_some(),
                signed,
                "{hosts:?} {host}"
            );
            let proof = LoginProof::sign(&dev, &ch, &st.server_key(), host, now_unix()).unwrap();
            assert_eq!(
                st.verify_proof(&card, &cert, &proof, Some(host))
                    .map(|_| ()),
                login,
                "{hosts:?} {host}"
            );
        }
    }

    fn proof_for(st: &IdentityState, dev: &DeviceKey) -> Vec<u8> {
        let ch = st.issue_challenge().unwrap();
        LoginProof::sign(dev, &ch, &st.server_key(), TEST_HOST, now_unix()).unwrap()
    }

    #[test]
    fn a_key_nobody_answers_for_waits_from_when_it_was_first_seen() {
        let st = state(IdentityConfig {
            newcomer_delay: 120,
            ..Default::default()
        });
        let id = IdentityKey::from_seed(&[40u8; 32]);
        let dev = DeviceKey::from_seed(&[41u8; 32]);
        let (card, cert) = objects(&id, &dev);
        let auth = || {
            let proof = proof_for(&st, &dev);
            st.auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
            .unwrap()
            .1
            .quiet_until
        };
        let first = auth().expect("a stranger waits");
        assert!(first > now_unix() && first <= now_unix() + 120);
        // Reconnecting does not start the clock again.
        st.clock().advance(Duration::from_secs(60));
        assert_eq!(auth(), Some(first));
        st.clock().advance(Duration::from_secs(61));
        assert_eq!(auth(), None);
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
            st.auth_with_proof(&card, &cert, &proof, Some(TEST_HOST), classic())
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
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, Some(TEST_HOST), classic())
            .unwrap();
        assert_eq!(ident.outcome, Outcome::ClassicPendingLink);
    }

    #[test]
    fn a_trtp_challenge_is_signed_only_on_the_port_the_client_names() {
        let st = state(IdentityConfig {
            classic_hosts: vec![("hl.example".into(), 443), ("hl.example:5500".into(), 5500)],
            ..Default::default()
        });
        let ch = [9u8; 32];
        for (host, port, signed) in [
            ("hl.example:5500", 5500, true),
            ("hl.example:443", 443, true),
            ("HL.example:443", 443, true),
            ("hl.example:443", 80, false),
            ("hl.example:80", 80, false),
            ("hl.example:80", 443, false),
            ("hl.example", 443, false),
            ("hl.example:5500", 5600, false),
            ("other.example:5500", 5500, false),
        ] {
            let c = st.sign_trtp_challenge(&ch, host, port);
            assert_eq!(c.is_some(), signed, "{host} on {port}");
        }
    }

    #[test]
    fn credentials_of_an_account_that_refuses_the_link_leave_the_linked_one() {
        let auth = MemAuth::new();
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let mut kiosk = account("kiosk", true);
        kiosk.identity.identity_login = false;
        kiosk.identity.allow_self_link = false;
        {
            let mut a = auth.accounts.lock().unwrap();
            a.insert("kiosk".into(), kiosk);
            a.get_mut("alice").unwrap().identity.fingerprint = Some(id.fingerprint().0);
        }
        let st = state_with(IdentityConfig::default(), auth.clone());
        let (card, cert) = objects(&id, &dev);
        let proof = proof_for(&st, &dev);
        let classic = ClassicLogin {
            login: "kiosk",
            password: b"pw",
        };
        let req = AuthRequest {
            classic: Some(classic),
            ..Default::default()
        };
        let (_, ident) = st
            .auth_with_proof(&card, &cert, &proof, Some(TEST_HOST), req)
            .unwrap();
        assert_eq!(ident.outcome, Outcome::Linked);
        assert_eq!(ident.account.as_deref(), Some("alice"));
    }

    #[test]
    fn a_link_its_account_would_refuse_is_never_written() {
        let auth = MemAuth::new();
        let mut kiosk = account("kiosk", true);
        kiosk.identity.identity_login = false;
        auth.accounts.lock().unwrap().insert("kiosk".into(), kiosk);
        let st = state_with(IdentityConfig::default(), auth.clone());
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let (card, cert) = objects(&id, &dev);
        let proof = proof_for(&st, &dev);
        let classic = ClassicLogin {
            login: "kiosk",
            password: b"pw",
        };
        let req = AuthRequest {
            classic: Some(classic),
            ..Default::default()
        };
        assert_eq!(
            st.auth_with_proof(&card, &cert, &proof, Some(TEST_HOST), req)
                .unwrap_err(),
            AuthRefused::Denied
        );
        assert!(auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .is_none());
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
                Some(TEST_HOST),
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
                Some(TEST_HOST),
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
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
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
                Some(TEST_HOST),
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
        assert_eq!(st.unlink(&ident).unwrap().0.login, "alice");
        assert_eq!(st.unlink(&ident).unwrap_err(), AuthRefused::NotLinked);
        assert!(auth
            .find_by_fingerprint(&id.fingerprint().0)
            .unwrap()
            .is_none());

        // A wrong password and the guest account are both `login_failed`
        // to the client, but only the first is a guess the failed-login
        // count should hear of.
        assert_eq!(
            st.link(&ident, "alice", b"nope").unwrap_err(),
            AuthRefused::LoginFailed
        );
        let guest = st.link(&ident, "guest", b"").unwrap_err();
        assert_eq!(guest, AuthRefused::GuestLink);
        assert_eq!(guest.code(), AuthRefused::LoginFailed.code());
        assert_eq!(guest.status(), AuthRefused::LoginFailed.status());

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
            .auth_with_proof(
                &card,
                &cert,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
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
            .auth_with_proof(
                &card3,
                &cert3,
                &proof,
                Some(TEST_HOST),
                AuthRequest::default(),
            )
            .unwrap();
        assert_eq!(ident3.outcome, Outcome::UnattestedGuest);
    }
}
