//! Accounts and the pluggable authentication backend.
//!
//! The backend trait is the modular-auth seam from the roadmap: the
//! flat-file implementation (hxd-auth-file) ships first; the persistence
//! phase adds a database one behind the same trait.
//!
//! **On password storage:** the legacy wire constrains us. A 1.5 login
//! carries the password XOR-0xff — effectively plaintext — and the HOPE
//! login (with the secure-login work) proves knowledge of the password
//! via HMAC, which the
//! server can only verify by holding a plaintext-equivalent secret. So
//! backends store recoverable secrets for legacy-capable accounts; real
//! password hashing arrives with the Hotline-ng protocol and applies only
//! to accounts that opt out of legacy access.

use crate::access::{bit, AccessBits};

/// A resolved account: what the auth backend hands the session layer after
/// a successful authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The canonical login name (lowercase by convention).
    pub login: String,
    /// The display name used when the account doesn't grant
    /// `use_any_name` (UTF-8; the session layer converts to Mac Roman).
    pub name: String,
    /// The access bitmap.
    pub access: AccessBits,
    /// Server-local policy, not wire vocabulary (the account file's
    /// `[extra]` section — mhxd's `access_extra` concept). May this
    /// account's sessions survive their connection (Hotline-ng detach)?
    /// Backend default: only password-protected accounts.
    pub can_detach: bool,
    /// May this account set the public chat subject? Backend default:
    /// tracks the disconnect-users (admin) bit.
    pub set_subject: bool,
    /// May this account list folders? The access bitmap has no bit for it;
    /// this is mhxd's `file_list` extra. Backend default: yes, as mhxd's.
    pub file_list: bool,
    /// May this account ask for a file's or folder's info? mhxd's
    /// `file_getinfo` extra. Backend default: yes, as mhxd's.
    pub file_getinfo: bool,
    /// Whether a non-empty password is set. Identity unlinking refuses
    /// to orphan an account that has no other way in.
    pub has_password: bool,
    /// May private messages be stored for this account and delivered
    /// later ([`crate::inbox`])?
    ///
    /// Backend default: **a password or a linked identity**, and for the
    /// same reason `can_detach` derives that way. What disqualifies an
    /// account is not the absence of a password but the absence of a
    /// person behind it: everyone who walks through `guest` shares one
    /// login, so queuing mail there hands it to whoever logs in next. A
    /// linked identity is proof of exactly one person, the same way a
    /// password is — which matters because the identity work creates
    /// password-less accounts on purpose (`new_accounts = create`, and
    /// linked accounts with `identity_login`), and those are precisely
    /// the accounts the fingerprint keying exists for.
    pub has_inbox: bool,
    /// May this account stage images for news posts? Server-local policy;
    /// defaults to the shared send-media access bit.
    pub attach_news: bool,
    /// May this account set an avatar (`docs/avatars.md` §2)? Server-local
    /// policy, the `[extra] set_avatar` key: neither GIF Icons nor the
    /// access bitmap has a bit for it. Backend default: a password or a
    /// linked identity, as `can_detach` — a change is decoded by this
    /// server and announced to every session on it, and a door everyone
    /// walks through should not be handed either.
    pub set_avatar: bool,
    /// May this account redact, revoke, purge and read reports
    /// (`docs/moderation.md` §2)? Server-local policy, the `[extra]
    /// moderate` key. Backend default: the disconnect-users (kick) bit —
    /// someone trusted to disconnect a person is trusted to take down
    /// what they posted.
    pub moderate: bool,
    /// Is this account held to no flood limit (`crate::limits`)? mhxd's
    /// `can_spam` extra, the `[extra] can_spam` key. Backend default: the
    /// disconnect-users (kick) bit, as mhxd's administrators have it.
    pub can_spam: bool,
    /// May this account create and edit roles (`docs/roles.md` §5)? The
    /// `[extra] manage_roles` key. Backend default: no.
    pub manage_roles: bool,
    /// May this account make, change and archive rooms, and see, join
    /// and send in every one (`docs/chat-rooms.md` §5)? The `[extra]
    /// manage_rooms` key. Backend default: no, even for an administrator,
    /// since an operator usually wants one person reorganizing the rooms.
    pub manage_rooms: bool,
    /// The roles the account's file lists, as listed: for display and
    /// editors. What they grant is already in the fields above.
    pub roles: Vec<String>,
    /// Portable-identity association (`docs/hotline-ng-identity.md` §8).
    /// Its `fingerprint` is the durable half of a
    /// [`crate::inbox::Mailbox`]: a login can be renamed and
    /// re-registered, a fingerprint cannot.
    pub identity: IdentityLink,
    /// What the fields above were derived from, kept so a session's mask
    /// can derive them again rather than mask what has derived already.
    pub config: AccountConfig,
}

impl Account {
    /// An account as `config` resolves for it, with nothing masked.
    pub fn new(
        login: String,
        name: String,
        has_password: bool,
        identity: IdentityLink,
        config: AccountConfig,
    ) -> Self {
        let mut account = Account {
            login,
            name,
            access: AccessBits::empty(),
            can_detach: false,
            set_subject: false,
            file_list: false,
            file_getinfo: false,
            has_password,
            has_inbox: false,
            attach_news: false,
            set_avatar: false,
            moderate: false,
            can_spam: false,
            manage_roles: false,
            manage_rooms: false,
            roles: Vec::new(),
            identity,
            config,
        };
        account.derive(&DenyMask::default());
        account
    }

    /// This account as a session under `mask` has it. With nothing
    /// masked it is the account as it reads.
    pub fn masked(&self, mask: &DenyMask) -> Account {
        let mut account = self.clone();
        if *mask != DenyMask::default() {
            account.derive(mask);
        }
        account
    }

    fn derive(&mut self, mask: &DenyMask) {
        let (access, x) = self.config.derive(self.is_person(), mask);
        self.access = access;
        self.can_detach = x.can_detach;
        self.set_subject = x.set_subject;
        self.has_inbox = x.inbox;
        self.file_list = x.file_list;
        self.file_getinfo = x.file_getinfo;
        self.attach_news = x.attach_news;
        self.set_avatar = x.set_avatar;
        self.moderate = x.moderate;
        self.can_spam = x.can_spam;
        self.manage_roles = x.manage_roles;
        self.manage_rooms = x.manage_rooms;
    }

    /// Is exactly one person behind this account — a password, or a
    /// linked identity? The rule `has_inbox` defaults to, but a fact
    /// about the account rather than a switch an operator can flip: it
    /// is what authorship is recorded against (`docs/news.md` §3.1), and
    /// turning off an account's mail should not make its articles
    /// nobody's, nor turning it on for `guest` make them everybody's.
    pub fn is_person(&self) -> bool {
        self.has_password || self.identity.fingerprint.is_some()
    }
}

/// One value per `[extra]` key (`docs/access-bits.md` §4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extras<T> {
    pub can_detach: T,
    pub set_subject: T,
    pub inbox: T,
    pub file_list: T,
    pub file_getinfo: T,
    pub attach_news: T,
    pub set_avatar: T,
    pub moderate: T,
    pub can_spam: T,
    pub manage_roles: T,
    pub manage_rooms: T,
}

impl<T: Copy> Extras<T> {
    /// Each key of `self` and `other` combined by `f`.
    pub fn zip_with<U: Copy, V>(self, other: Extras<U>, f: impl Fn(T, U) -> V) -> Extras<V> {
        Extras {
            can_detach: f(self.can_detach, other.can_detach),
            set_subject: f(self.set_subject, other.set_subject),
            inbox: f(self.inbox, other.inbox),
            file_list: f(self.file_list, other.file_list),
            file_getinfo: f(self.file_getinfo, other.file_getinfo),
            attach_news: f(self.attach_news, other.attach_news),
            set_avatar: f(self.set_avatar, other.set_avatar),
            moderate: f(self.moderate, other.moderate),
            can_spam: f(self.can_spam, other.can_spam),
            manage_roles: f(self.manage_roles, other.manage_roles),
            manage_rooms: f(self.manage_rooms, other.manage_rooms),
        }
    }
}

/// What an account's files say, before any default derives: the
/// configuration half of `docs/roles.md` §3.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountConfig {
    /// Every bit granted, before bit 56 follows bit 9.
    pub access: AccessBits,
    /// Was bit 56 named, either way? Only then does it not follow bit 9.
    pub history_named: bool,
    /// Each `[extra]` key as named, `None` where it is left to derive.
    pub extra: Extras<Option<bool>>,
    /// The bits the account's own file grants, whatever its roles do.
    pub grant: AccessBits,
    /// The bits the account's own file withholds, whatever its roles do.
    pub deny: AccessBits,
}

/// What a session is denied whatever its account says: probation's and
/// restrictions' half of `docs/roles.md` §3. It only ever takes away.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DenyMask {
    pub access: AccessBits,
    pub extra: Extras<bool>,
}

impl AccountConfig {
    /// The access bits and `[extra]` keys this configuration resolves to
    /// under `mask`, for an account that is one person (`person`, see
    /// [`Account::is_person`]) or not.
    ///
    /// Defaults derive after the mask, so a denied bit leaves nothing
    /// derived from it behind; and a denied bit takes what derives from
    /// it even where the configuration named that, since otherwise a
    /// mask would mean less on an account whose file spelled it out.
    pub fn derive(&self, person: bool, mask: &DenyMask) -> (AccessBits, Extras<bool>) {
        let denied = |b| mask.access.has(b);
        let mut access = AccessBits::from_raw(self.access.raw() & !mask.access.raw());
        // fogWraith's fallback: on an access system where bit 56 has not
        // been assigned explicitly, history follows ordinary read-chat.
        if !self.history_named && access.has(bit::READ_CHAT) {
            access = access.with(bit::CHAT_HISTORY);
        }
        if denied(bit::READ_CHAT) || denied(bit::CHAT_HISTORY) {
            access = access.without(bit::CHAT_HISTORY);
        }
        let kick = access.has(bit::DISCONNECT_USERS);
        let unkick = denied(bit::DISCONNECT_USERS);
        let media = access.has(bit::SEND_MEDIA);
        let (x, m) = (&self.extra, &mask.extra);
        let key =
            |named: Option<bool>, default: bool, masked: bool| !masked && named.unwrap_or(default);
        let extras = Extras {
            // A password makes an account a person rather than a door,
            // and so does a linked identity: `guest` is one login many
            // people share, so detaching, mail and an avatar are each
            // handed to whoever walks through it next.
            can_detach: key(x.can_detach, person, m.can_detach),
            inbox: key(x.inbox, person, m.inbox),
            set_avatar: key(x.set_avatar, person, m.set_avatar),
            // mhxd's, on for every account that does not turn it off.
            file_list: key(x.file_list, true, m.file_list),
            file_getinfo: key(x.file_getinfo, true, m.file_getinfo),
            set_subject: key(x.set_subject, kick, m.set_subject || unkick),
            moderate: key(x.moderate, kick, m.moderate || unkick),
            can_spam: key(x.can_spam, kick, m.can_spam || unkick),
            manage_roles: key(x.manage_roles, false, m.manage_roles),
            manage_rooms: key(x.manage_rooms, false, m.manage_rooms),
            attach_news: key(
                x.attach_news,
                media,
                m.attach_news || denied(bit::SEND_MEDIA),
            ),
        };
        (access, extras)
    }
}

/// How an account relates to a portable identity. All server-local
/// policy; nothing here crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityLink {
    /// The linked identity's fingerprint (SHA-256 of its public key), if
    /// any. At most one per account; at most one account per identity.
    pub fingerprint: Option<[u8; 32]>,
    /// May the linked identity log in without a password? Operator
    /// switch; backend default true.
    pub identity_login: bool,
    /// May a user link an identity to this account themself (with the
    /// password) rather than the operator doing it? Backend default true.
    pub allow_self_link: bool,
    /// Is this account's login name reserved as a display name on the
    /// server (§9)? Backend default false.
    pub reserve_name: bool,
}

/// What [`AuthBackend::link_identity`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    /// The link was written; the account as it now reads.
    Linked(Account),
    /// The account already linked this identity; nothing written.
    Already(Account),
    /// The identity already links a different account — which one.
    Taken(Account),
    /// The account links another identity, forbids self-linking, or has
    /// no password — see [`AuthBackend::link_identity`].
    Refused(Account),
}

/// What [`AuthBackend::unlink_identity`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlinkOutcome {
    /// The link was cleared; the account as it read before.
    Unlinked(Account),
    /// No account links this identity here.
    NotLinked,
    /// The account has no password, so the link is its only way in
    /// (§8.4). Set a password first.
    WouldOrphan(Account),
}

/// What a transport-authenticated socket may change about account
/// association (`docs/hotline-ng-identity.md` §8.2): the device
/// certificate's `manage` capability, carried alongside `Transport`
/// rather than inside it — `Transport` is descriptive and roster-visible,
/// and this authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkAuthority {
    /// The device certificate grants `manage`.
    pub may_link: bool,
    /// May an identity with no linked account be admitted at all? This
    /// is §8.1's `new_accounts` policy, carried to a wire that cannot
    /// consult it: `false` is `deny`, where a socket that proved an
    /// identity and turns out to link nothing is refused rather than
    /// falling through to a guest session. It travels with `may_link`
    /// because both are what the *socket's* identity is allowed to
    /// become, and both are decided by the layer that authenticated it.
    pub unlinked_ok: bool,
}

impl Default for LinkAuthority {
    /// What a plain TCP session gets: no identity to link, and no
    /// identity policy to apply. `unlinked_ok` is `true` so that a wire
    /// with no identity at all is never refused by a rule about
    /// identities — the check it guards runs only for a socket that
    /// proved one.
    fn default() -> Self {
        LinkAuthority {
            may_link: false,
            unlinked_ok: true,
        }
    }
}

/// The client's proof of identity.
///
/// `Plain` is the classic login (already de-obfuscated from the wire's
/// XOR-0xff form); `Keyed` is HOPE's.
pub enum Proof<'a> {
    /// The password as typed, raw bytes (clients send Mac Roman).
    Plain(&'a [u8]),
    /// A check the caller makes of the stored password itself: HOPE's MAC
    /// of it, which also derives the session's keys from it, so the
    /// password goes to the check and never back to the caller.
    Keyed(&'a dyn Fn(&str) -> bool),
}

impl std::fmt::Debug for Proof<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Proof::Plain(_) => "Plain",
            Proof::Keyed(_) => "Keyed",
        })
    }
}

/// Why an authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No such account.
    NoSuchAccount,
    /// The proof didn't verify.
    BadProof,
    /// The backend itself failed (I/O, parse). The string is for the log,
    /// not the client.
    Backend(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::NoSuchAccount => write!(f, "no such account"),
            AuthError::BadProof => write!(f, "wrong password"),
            AuthError::Backend(e) => write!(f, "auth backend error: {e}"),
        }
    }
}

impl std::error::Error for AuthError {}

/// The pluggable authentication backend.
///
/// Synchronous by design for now: the file backend is a couple of small
/// reads, and the session layer calls it on the blocking pool. When a
/// database backend lands (persistence phase) this trait goes async as
/// part of that work — the shared crates refactor freely (`publish =
/// false` everywhere), so we don't pre-pay for it.
pub trait AuthBackend: Send + Sync + 'static {
    /// Authenticate `login` with `proof`. An empty login means guest;
    /// backends decide whether a guest account exists.
    ///
    /// An account that has no password but *does* link an identity must
    /// be refused here, whatever the proof (§8.3): for those accounts the
    /// device key is the credential, and an empty password is not one.
    /// Otherwise every account `new_accounts = create` writes is open to
    /// anyone who types its login and presses return on the legacy port.
    /// The identity paths reach such accounts through
    /// [`AuthBackend::lookup`], having proved the key first.
    fn authenticate(&self, login: &str, proof: Proof<'_>) -> Result<Account, AuthError>;

    /// Every login an account exists for: what HOPE, which names its login
    /// only as a MAC, has to try each of.
    fn logins(&self) -> Result<Vec<String>, AuthError>;

    /// Load an account without a proof. For the identity paths, where
    /// possession of the key stood in for the password; callers must
    /// have established that before calling.
    fn lookup(&self, login: &str) -> Result<Account, AuthError>;

    /// The account linked to an identity, if any.
    fn find_by_fingerprint(&self, fingerprint: &[u8; 32]) -> Result<Option<Account>, AuthError>;

    /// Link `fingerprint` to `login`, enforcing the one-to-one rule.
    ///
    /// **The whole decision happens inside the backend**, because the
    /// callers can't make it safely: read the account, check whether the
    /// identity is spoken for, and write, all as one step. Done as
    /// separate calls, two concurrent logins by one identity naming two
    /// different accounts both see "not linked" and both write, and the
    /// identity ends up linked to two accounts.
    ///
    /// A password-less account is refused here, for the same reason
    /// [`AuthBackend::authenticate`] refuses one that is already linked:
    /// every caller verifies the password first, and for such an account
    /// the empty password verifies for anyone. Self-linking is "prove
    /// you own the account, then bind it to your key"; without a
    /// password there is nothing to prove.
    fn link_identity(&self, login: &str, fingerprint: &[u8; 32]) -> Result<LinkOutcome, AuthError>;

    /// Clear the link on whichever account `fingerprint` links (§8.4).
    /// Atomic for the same reason as [`AuthBackend::link_identity`], and
    /// it refuses to leave a password-less account with no way in.
    fn unlink_identity(&self, fingerprint: &[u8; 32]) -> Result<UnlinkOutcome, AuthError>;

    /// The identity `from` links rotated to `to` (`identity-registrar.md`
    /// §7.4): its account links `to` instead, and is answered. Done once
    /// `from` links nothing, so a retry is safe. An account `to` already
    /// links keeps that link, and `from`'s is left where it is, refused
    /// with its key, for the operator: one key cannot hold two accounts.
    fn rotate_link(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Option<Account>, AuthError>;

    /// The account linked to `fingerprint`, creating one if there is
    /// none (`new_accounts = create`). `proposed` is the caller's
    /// suggested login; the backend may pick another if it collides.
    /// `access` is the initial bitmap, and the account gets no password
    /// — so it is reachable only by proving the identity.
    ///
    /// The `bool` is true when the account was created by this call.
    /// Atomic: without that, two logins by one never-seen identity make
    /// two accounts for it.
    fn find_or_create_linked(
        &self,
        proposed: &str,
        name: &str,
        fingerprint: &[u8; 32],
        access: AccessBits,
    ) -> Result<(Account, bool), AuthError>;

    /// Which account, if any, reserves `name` as a display name (§9):
    /// an account with `reserve_name` whose login equals `name`,
    /// case-insensitively. Returns the login.
    fn reserved_by(&self, name: &str) -> Result<Option<String>, AuthError>;
}

/// The longest login, name or password an account takes, in
/// characters: the classic wire cuts each there, so a longer one could
/// never be typed on it.
pub const FIELD_MAX_CHARS: usize = 31;

/// An administrator's change to one account. `None` keeps what the
/// account has; a new account takes its login as its name, no password
/// and no access.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountEdit {
    pub login: String,
    pub name: Option<String>,
    /// `Some("")` clears the password.
    pub password: Option<String>,
    pub access: Option<AccessBits>,
    /// The highest bit of `access` the editor it came from can show (the
    /// tiers of fogWraith's Extended Privilege extension); `None` for one
    /// that shows them all. The bits above it are not this edit's to say:
    /// the account keeps them as its file has them, so a bit it never
    /// named goes on following its roles, or, for bit 56, `read_chat`.
    pub editor_tier: Option<u8>,
    /// The bits the editor was shown when it opened the account. A bit
    /// `access` leaves as it was shown is not this edit's to say either:
    /// it keeps what the account has now, so a role changed while the
    /// editor was open is not written back as an override.
    pub shown: Option<AccessBits>,
    /// Roles to give or take away, by name (`docs/roles.md` §5).
    pub roles: Vec<RoleChange>,
}

/// One role given to an account, or taken from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleChange {
    Add(String),
    Remove(String),
}

/// A role as an administrator lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleView {
    pub name: String,
    pub title: String,
    /// `0xRRGGBB`.
    pub color: Option<u32>,
    /// Display order, highest first.
    pub position: i64,
    pub mentionable: bool,
    /// The bits it grants.
    pub access: AccessBits,
    /// The `[extra]` keys it grants, by name.
    pub extra: Vec<&'static str>,
}

/// Why an account was not read, written or deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    /// The asking session lacks the access bit the act needs.
    NotAllowed,
    /// The account may, or would be allowed to, do something the asking
    /// session's account may not.
    Outranked,
    NoSuchAccount,
    /// An edit gave a role there is none of, or `everyone`, which every
    /// account holds already, or took one the account does not list.
    NoSuchRole,
    /// A create named a login an account already has.
    Exists,
    /// Not a login this backend can store, or one reserved for the
    /// server or for roles.
    InvalidLogin,
    /// This server has no account administration.
    Unsupported,
    /// The backend itself failed. For the log, not the client.
    Backend(String),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AdminError::NotAllowed => "You are not allowed to do that.",
            AdminError::Outranked => {
                "That account may do, or would be allowed to do, something you may not."
            }
            AdminError::NoSuchAccount => "There is no such account.",
            AdminError::NoSuchRole => "There is no such role.",
            AdminError::Exists => "That account already exists.",
            AdminError::InvalidLogin => {
                "A login is up to 31 letters, digits and _ - . @, not starting with a dot or @."
            }
            AdminError::Unsupported => "This server does not administer accounts.",
            AdminError::Backend(e) => return write!(f, "account store: {e}"),
        })
    }
}

/// What a write asks before it lands: the account as it is (`None` when
/// there is none) and as the edit would leave it. Run by the backend with
/// its writes held, so nothing changes the account between the two.
pub type WriteCheck<'a> = &'a dyn Fn(Option<&Account>, &Account) -> Result<(), AdminError>;

/// Account administration: reading and writing accounts on an
/// administrator's behalf. Separate from [`AuthBackend`], which answers
/// for a login and never changes who may do what.
pub trait AccountAdmin: Send + Sync + 'static {
    /// The account `login` names, exactly: an empty login is no account,
    /// not the guest one.
    fn read_account(&self, login: &str) -> Result<Account, AdminError>;

    /// Every account, by login.
    fn list_accounts(&self) -> Result<Vec<Account>, AdminError>;

    /// Apply `edit`, making the account if there is none, once `check`
    /// has passed; refusing is `check`'s. Answers the account as it now
    /// reads. Whatever the backend keeps beside what an edit names —
    /// identity links, server-local policy — is left as it was.
    fn write_account(
        &self,
        edit: &AccountEdit,
        check: WriteCheck<'_>,
    ) -> Result<Account, AdminError>;

    /// Delete the account `login` names, once `check` has passed on it.
    fn delete_account(
        &self,
        login: &str,
        check: &dyn Fn(&Account) -> Result<(), AdminError>,
    ) -> Result<(), AdminError>;

    /// Every role, highest position first.
    fn roles(&self) -> Vec<RoleView> {
        Vec::new()
    }

    /// The keys `login`'s own record sets over its roles, as `key=value`
    /// (`extra.` before an `[extra]` key's name).
    fn own_keys(&self, login: &str) -> Result<Vec<String>, AdminError> {
        self.read_account(login).map(|_| Vec::new())
    }

    /// Read again what the backend keeps beside the accounts, such as
    /// roles, for [`crate::Core::reload_accounts`]. On failure what it
    /// had stays in force, and the answer says why.
    fn reload(&self) -> Result<(), String> {
        Ok(())
    }
}

/// A read-only look at accounts nobody is logged into.
///
/// Authentication answers "is this person who they say they are"; this
/// answers "is there someone by that name, and may I leave a message for
/// them" — which the private-message path needs precisely when there is no
/// session to ask. Separate from [`AuthBackend`] because it takes no proof
/// and grants nothing.
pub trait AccountDirectory: Send + Sync + 'static {
    /// The mailbox `login` names, if it names an account that accepts
    /// offline messages — canonical login, plus the identity fingerprint
    /// when the account has one. `None` otherwise.
    ///
    /// **One answer for two questions on purpose.** "No such account" and
    /// "that account takes no offline messages" are the same `None`, so
    /// the private-message path cannot be used to find out which — the
    /// same reason the login flow answers `login_failed` to both a wrong
    /// name and a wrong password.
    fn inbox_account(&self, login: &str) -> Option<crate::inbox::Mailbox>;

    /// What the account `who` names *now* may do, when it still names one
    /// that keeps a mailbox; `None` otherwise.
    ///
    /// The question a news notification asks about someone who is not
    /// here (`docs/news.md` §10.5): a subscription made last year belongs
    /// to an account whose read-news bit may since have been revoked, and
    /// the revocation has to stop the pushes. Resolved by the mailbox
    /// rule — an identified mailbox by its fingerprint, whatever the
    /// account is called now, and an unidentified one only by a login
    /// whose account has no identity — so a login someone else has since
    /// taken answers for nobody.
    fn mailbox_access(&self, who: &crate::inbox::Mailbox) -> Option<AccessBits>;

    /// The account `login` names, as its mailbox key and what it may do,
    /// **whether or not it keeps a mailbox**. Moderation's question
    /// (`docs/moderation.md` §2): the ladder protects an account for
    /// what it may do, not for whether it takes mail, and a purge by
    /// login must find an identity-linked account's rows by its key.
    ///
    /// The default is [`Self::inbox_account`] and [`Self::mailbox_access`]
    /// together, which is right for a directory that has no accounts
    /// without mailboxes.
    fn account(&self, login: &str) -> Option<(crate::inbox::Mailbox, AccessBits)> {
        let mailbox = self.inbox_account(login)?;
        let access = self.mailbox_access(&mailbox)?;
        Some((mailbox, access))
    }

    /// The account linked to `fingerprint`, the same way.
    fn account_by_key(
        &self,
        fingerprint: &[u8; 32],
    ) -> Option<(crate::inbox::Mailbox, AccessBits)> {
        let mailbox = crate::inbox::Mailbox::identified(String::new(), *fingerprint);
        let access = self.mailbox_access(&mailbox)?;
        Some((mailbox, access))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot<'a, T>(x: &'a mut Extras<T>, key: &str) -> &'a mut T {
        match key {
            "attach_news" => &mut x.attach_news,
            "moderate" => &mut x.moderate,
            "can_spam" => &mut x.can_spam,
            "set_subject" => &mut x.set_subject,
            "manage_rooms" => &mut x.manage_rooms,
            _ => unreachable!("{key}"),
        }
    }

    fn bits(bits: &[u8]) -> AccessBits {
        bits.iter().fold(AccessBits::empty(), |a, b| a.with(*b))
    }

    /// The key, the bits granted, the key as named, the bits denied,
    /// whether the key is denied, and what the key resolves to.
    type Row = (
        &'static str,
        &'static [u8],
        Option<bool>,
        &'static [u8],
        bool,
        bool,
    );

    #[test]
    fn defaults_derive_after_the_mask_and_a_denial_takes_what_derives_from_it() {
        const HISTORY: &str = "read_chat_history";
        use bit::{DISCONNECT_USERS as KICK, READ_CHAT as READ, SEND_MEDIA as MEDIA};
        let mut rows: Vec<Row> = vec![
            (HISTORY, &[READ], None, &[], false, true),
            (HISTORY, &[READ], None, &[READ], false, false),
            (HISTORY, &[READ], None, &[], true, false),
            (HISTORY, &[READ], Some(false), &[], false, false),
            (HISTORY, &[READ], Some(true), &[], false, true),
            (HISTORY, &[READ], Some(true), &[READ], false, false),
            (HISTORY, &[], Some(true), &[], false, true),
            (HISTORY, &[], None, &[], false, false),
            ("attach_news", &[MEDIA], None, &[], false, true),
            ("attach_news", &[MEDIA], None, &[MEDIA], false, false),
            ("attach_news", &[MEDIA], None, &[], true, false),
            ("attach_news", &[MEDIA], Some(false), &[], false, false),
            ("attach_news", &[], Some(true), &[], false, true),
            ("attach_news", &[], Some(true), &[MEDIA], false, false),
            ("attach_news", &[], None, &[], false, false),
            // Not even an administrator's unless named.
            ("manage_rooms", &[KICK], None, &[], false, false),
            ("manage_rooms", &[], Some(true), &[], false, true),
            ("manage_rooms", &[], Some(true), &[], true, false),
        ];
        for key in ["moderate", "can_spam", "set_subject"] {
            rows.extend([
                (key, &[KICK][..], None, &[][..], false, true),
                (key, &[KICK], None, &[KICK], false, false),
                (key, &[KICK], None, &[], true, false),
                (key, &[KICK], Some(false), &[], false, false),
                (key, &[], Some(true), &[], false, true),
                (key, &[], Some(true), &[KICK], false, false),
                (key, &[], Some(true), &[], true, false),
                (key, &[], None, &[KICK], false, false),
            ]);
        }
        for (key, granted, named, denied, key_denied, want) in rows {
            let mut config = AccountConfig {
                access: bits(granted),
                ..Default::default()
            };
            let mut mask = DenyMask {
                access: bits(denied),
                ..Default::default()
            };
            if key == HISTORY {
                config.history_named = named.is_some();
                if named == Some(true) {
                    config.access = config.access.with(bit::CHAT_HISTORY);
                }
                if key_denied {
                    mask.access = mask.access.with(bit::CHAT_HISTORY);
                }
            } else {
                *slot(&mut config.extra, key) = named;
                *slot(&mut mask.extra, key) = key_denied;
            }
            let (access, mut extras) = config.derive(false, &mask);
            let got = if key == HISTORY {
                access.has(bit::CHAT_HISTORY)
            } else {
                *slot(&mut extras, key)
            };
            assert_eq!(
                got, want,
                "{key}: granted {granted:?}, named {named:?}, denied {denied:?}, key denied {key_denied}"
            );
        }
    }
}
