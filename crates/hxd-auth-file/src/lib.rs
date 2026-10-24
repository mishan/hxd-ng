//! Flat-file account backend: one TOML file per account in an accounts
//! directory. Human-editable by design — unlike hxd's binary `UserData`
//! format. (An importer for hxd/mhxd account trees is future work; see
//! ROADMAP.md.)
//!
//! ```toml
//! # accounts/alice.toml
//! name = "Alice"
//! password = "secret"     # omit or leave empty for password-less accounts
//! roles = ["moderators"]  # what they grant comes first (`roles.rs`)
//!
//! [access]
//! use_any_name = true
//! send_msgs = true
//! read_users = true
//! send_media = false      # false withholds what a role grants
//! # any named bit below; plus raw_bits = [55] as an escape hatch, and
//! # raw_deny = [58] to withhold a bit with no name
//!
//! [identity]              # portable identity (docs/hotline-ng-identity.md §8)
//! fingerprint = "318s87c…" # 52-char fingerprint of the linked identity; set by
//!                         # linking, or by hand
//! login = true            # may the identity log in without the password
//! allow_self_link = true  # may the user link with just the password
//! reserve_name = false    # is the login name reserved as a display name (§9)
//! ```
//!
//! Identity links are written back with `toml_edit`, so comments and
//! layout in a hand-maintained file survive. Lookups by fingerprint scan
//! the directory; fine for the account counts a Hotline server has.
//!
//! The password is a plaintext-equivalent secret — a legacy-wire
//! constraint, not an oversight; see `hxd_core::account`'s module docs.
//! Keep the accounts directory readable by the server user only.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use hxd_core::access::{self, bit, AccessBits, NAMES};
use hxd_core::inbox::Mailbox;
use hxd_core::{
    Account, AccountAdmin, AccountConfig, AccountDirectory, AccountEdit, AdminError, AuthBackend,
    AuthError, Extras, IdentityLink, LinkOutcome, Proof, UnlinkOutcome, WriteCheck,
};
use serde::Deserialize;

pub mod roles;
pub use roles::{Role, Roles, EVERYONE};

/// The bit an account file's access key names, if any. Exposed so the
/// binary can validate `[identity.default_access]` against the same
/// table an account file is read with, rather than a second copy of it.
pub fn named_bit(key: &str) -> Option<u8> {
    // Accepted for account files written while the capability bit existed
    // but the server side did not. New files use the spec's access name.
    if key == "chat_history" {
        return Some(bit::CHAT_HISTORY);
    }
    access::named(key)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFile {
    /// Display name; defaults to the login.
    name: Option<String>,
    /// Plaintext-equivalent secret; omit/empty = password-less.
    password: Option<String>,
    /// The roles whose grants come before this file's own keys.
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    access: AccessTable,
    /// Server-local policy that never crosses the wire (mhxd's
    /// `access_extra` concept). Absent keys fall back to derived defaults
    /// — see `AccountConfig::derive`.
    #[serde(default)]
    extra: ExtraTable,
    #[serde(default)]
    identity: IdentityTable,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityTable {
    fingerprint: Option<String>,
    login: Option<bool>,
    allow_self_link: Option<bool>,
    reserve_name: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtraTable {
    /// May sessions survive their connection (Hotline-ng detach)?
    /// Default: true iff the account has a password — a drive-by guest
    /// shouldn't get to park a nick on the roster.
    can_detach: Option<bool>,
    /// May this account set the public chat subject? Default: tracks the
    /// disconnect_users (admin) bit, preserving the reference server's
    /// spirit (a config-granted privilege, not a wire access bit).
    set_subject: Option<bool>,
    /// May private messages be stored for this account and delivered
    /// later? Default: a password *or* a linked identity — either is
    /// proof of one person, where a bare `guest` login is shared by
    /// everyone who walks through it and queuing mail there hands it to
    /// whoever logs in next.
    inbox: Option<bool>,
    /// May this account list folders? Default: true, as mhxd's
    /// `file_list` extra is for every account that does not turn it off.
    file_list: Option<bool>,
    /// May this account ask for file and folder info? Default: true, as
    /// mhxd's `file_getinfo` extra.
    file_getinfo: Option<bool>,
    /// May this account stage durable news attachments? Default: the
    /// shared send-media access bit.
    attach_news: Option<bool>,
    /// May this account set an avatar? Default: a password or a linked
    /// identity, as `can_detach` — the bootstrap guest cannot, since
    /// every change is decoded here and announced to everyone.
    set_avatar: Option<bool>,
    /// May this account redact, revoke, purge and read reports? Default:
    /// the disconnect_users (kick) bit (`docs/moderation.md` §2).
    moderate: Option<bool>,
    /// Is this account held to no flood limit? mhxd's `can_spam`.
    /// Default: the disconnect_users (kick) bit.
    can_spam: Option<bool>,
    /// May this account create and edit roles? Default: false.
    manage_roles: Option<bool>,
    /// May this account manage rooms (`docs/chat-rooms.md` §5)? Default:
    /// false, even for an administrator.
    manage_rooms: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct AccessTable {
    /// Escape hatch for bits without a name (reserved / future).
    #[serde(default)]
    raw_bits: Vec<u8>,
    /// Bits withheld by number, whatever a role grants: a list of numbers
    /// has no way to say `false`.
    #[serde(default)]
    raw_deny: Vec<u8>,
    /// Named bits — collected loosely so a typo is a startup-log warning,
    /// not a silently ignored key.
    #[serde(flatten)]
    named: BTreeMap<String, bool>,
}

impl AccountFile {
    /// Everything but the password check: shared by `authenticate` and
    /// `lookup`.
    fn into_account(self, login: String, roles: &Roles) -> Account {
        let stored = self.password.as_deref().unwrap_or("");
        let has_password = !stored.is_empty();
        let fingerprint = self
            .identity
            .fingerprint
            .as_deref()
            .and_then(hl_identity::Fingerprint::parse)
            .map(|fp| fp.0);
        let config = self.configure(roles);
        let identity = IdentityLink {
            fingerprint,
            // Derived true on an account with no password, whatever
            // the file says, as the identity spec has it: there the
            // flag would refuse the only way in, and an account nobody can reach
            // is a state worth making unrepresentable rather than
            // warning about. The flag is the account's own only where
            // a password is left to fall back on.
            identity_login: !has_password || self.identity.login.unwrap_or(true),
            allow_self_link: self.identity.allow_self_link.unwrap_or(true),
            reserve_name: self.identity.reserve_name.unwrap_or(false),
        };
        let name = self.name.unwrap_or_else(|| login.clone());
        let mut account = Account::new(login, name, has_password, identity, config);
        account.roles = self.roles;
        account
    }

    /// The configuration half of `docs/roles.md` §3: what `everyone` and
    /// the listed roles grant, then this file's own keys over it either
    /// way. A role names bit 56 only by granting it; the file names it
    /// with either key or by withholding it in `raw_deny`.
    fn configure(&self, roles: &Roles) -> AccountConfig {
        let (mut access, granted) = roles.held(&self.roles).fold(
            (AccessBits::empty(), Extras::<bool>::default()),
            |(access, extra), role| {
                (
                    AccessBits::from_raw(access.raw() | role.access.raw()),
                    extra.zip_with(role.extra, |a, b| a || b),
                )
            },
        );
        let mut history_named = access.has(bit::CHAT_HISTORY);
        for (key, on) in &self.access.named {
            if let Some(b) = named_bit(key) {
                access = if *on {
                    access.with(b)
                } else {
                    access.without(b)
                };
                history_named |= b == bit::CHAT_HISTORY;
            }
        }
        for b in &self.access.raw_bits {
            access = access.with(*b);
        }
        for b in &self.access.raw_deny {
            access = access.without(*b);
            history_named |= *b == bit::CHAT_HISTORY;
        }
        let x = &self.extra;
        let own = Extras {
            can_detach: x.can_detach,
            set_subject: x.set_subject,
            inbox: x.inbox,
            file_list: x.file_list,
            file_getinfo: x.file_getinfo,
            attach_news: x.attach_news,
            set_avatar: x.set_avatar,
            moderate: x.moderate,
            can_spam: x.can_spam,
            manage_roles: x.manage_roles,
            manage_rooms: x.manage_rooms,
        };
        AccountConfig {
            access,
            history_named,
            extra: own.zip_with(granted, |own, role| own.or(role.then_some(true))),
        }
    }

    /// Is this a combination an operator should be told about at
    /// startup? An invalid fingerprint on a password-less
    /// file locks everyone out; `identity.login = false` on one would
    /// too, so it is read as true, and the operator who wrote it is told
    /// their setting is not the one in force.
    fn unreachable_reason(&self) -> Option<&'static str> {
        let has_password = !self.password.as_deref().unwrap_or("").is_empty();
        if has_password {
            return None;
        }
        match self.identity.fingerprint.as_deref() {
            Some(fp) if hl_identity::Fingerprint::parse(fp).is_none() => Some(
                "no password and identity.fingerprint is invalid, so neither password nor \
                 identity login can reach this account; fix the fingerprint or set a password",
            ),
            Some(_) if !self.identity.login.unwrap_or(true) => Some(
                "identity.login = false is ignored on an account with no password, because it \
                 would leave nothing able to log in; set a password for it to take effect",
            ),
            _ => None,
        }
    }
}

/// The flat-file backend.
pub struct FileAuth {
    dir: PathBuf,
    /// Serialises every read-decide-write sequence over identity links.
    /// The trait's association methods promise atomicity; on a directory
    /// of files this is what provides it. Never held across anything but
    /// this backend's own I/O.
    assoc: Mutex<()>,
    /// login → (file identity, fingerprint text) for every account file
    /// seen. Lets `find_by_fingerprint` stat the directory instead of
    /// reading and parsing every account on every identity auth; a file
    /// whose size or mtime moved is re-read, so a hand edit still counts.
    index: Mutex<HashMap<String, (FileStamp, Option<String>)>>,
    /// A login nobody may authenticate as, lowercase: the reserved
    /// server account (`docs/system-account.md` §2). It is on the roster
    /// and it is a mailbox, and it is reachable by nobody — which for
    /// this one account is the intended state rather than the
    /// misconfiguration the identity spec warns about. Enforced here
    /// rather than in each frontend, so no login path can miss it, and
    /// answered `NoSuchAccount` because as far as a would-be logger-in
    /// is concerned there is no account there.
    reserved: Option<String>,
    /// The roles file, when there is one to read again on a reload.
    roles_file: Option<PathBuf>,
    roles: RwLock<Arc<Roles>>,
}

/// Enough of a file's metadata to notice an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
}

impl FileAuth {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileAuth {
            dir: dir.into(),
            assoc: Mutex::new(()),
            index: Mutex::new(HashMap::new()),
            reserved: None,
            roles_file: None,
            roles: RwLock::new(Arc::new(Roles::default())),
        }
    }

    /// Resolve accounts with the roles the file at `path` defines, none
    /// if there is no file there. One that does not parse is an error:
    /// a server must not come up without roles it was configured with.
    pub fn with_roles(mut self, path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        self.roles = RwLock::new(Arc::new(Roles::load(&path)?));
        self.roles_file = Some(path);
        Ok(self)
    }

    /// The roles accounts are resolved with now.
    pub fn roles(&self) -> Arc<Roles> {
        self.roles.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The account file `login` names, as written, for an editor that
    /// shows or copies what the file says rather than what it resolves to.
    pub fn document(&self, login: &str) -> Result<toml_edit::DocumentMut, AdminError> {
        let login = admin_login(login)?;
        if self.is_reserved(&login) {
            return Err(AdminError::NoSuchAccount);
        }
        let path = self.dir.join(format!("{login}.toml"));
        let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AdminError::NoSuchAccount,
            _ => AdminError::Backend(format!("{}: {e}", path.display())),
        })?;
        text.parse()
            .map_err(|e| AdminError::Backend(format!("{}: {e}", path.display())))
    }

    /// Change the existing account file `login` names with `f`, keeping
    /// its comments, for the operator's commands that set single keys:
    /// what `f` leaves must read as an account. Answers the account as
    /// it now reads.
    pub fn edit_account(
        &self,
        login: &str,
        f: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<(), String>,
    ) -> Result<Account, AdminError> {
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        let mut doc = self.document(login)?;
        f(&mut doc).map_err(AdminError::Backend)?;
        let login = admin_login(login)?;
        let path = self.dir.join(format!("{login}.toml"));
        let failed =
            |e: &dyn std::fmt::Display| AdminError::Backend(format!("{}: {e}", path.display()));
        let text = doc.to_string();
        let file: AccountFile = toml::from_str(&text).map_err(|e| failed(&e))?;
        write_atomic(&path, &text).map_err(|e| failed(&e))?;
        Ok(file.into_account(login, &self.roles()))
    }

    /// Reserve a login. Nothing authenticates as it and nothing looks it
    /// up; an account file of that name, from a server migrated from
    /// something else, stops being a way in.
    pub fn reserving(mut self, login: &str) -> Self {
        self.reserved = Some(login.to_ascii_lowercase());
        self
    }

    fn is_reserved(&self, login: &str) -> bool {
        self.reserved.as_deref() == Some(login)
    }

    /// Every login with an account file, lowercased — what a registrar
    /// on this server reserves, so that nobody is issued a handle that
    /// `new_accounts = create` would turn into an existing account's
    /// name (`identity-registrar.md` §5.2). A directory that cannot be
    /// read yields nothing, and says so.
    pub fn logins(&self) -> Vec<String> {
        match self.entries() {
            Ok(entries) => entries
                .into_iter()
                .map(|(login, _)| login.to_ascii_lowercase())
                .collect(),
            Err(e) => {
                tracing::warn!("{}: {e}", self.dir.display());
                Vec::new()
            }
        }
    }

    /// Read every account file and report what an operator would want to
    /// know: files that do not parse, unreachable accounts, filenames that
    /// lookup canonicalization cannot reach, ignored identity/access
    /// fields, and roles that do not exist.
    ///
    /// At startup, because that is where an operator looks. Warning from
    /// the *read* instead put the message where only the locked-out
    /// device would trigger it — and then repeated it for every flush and
    /// every inbox page that resolved the account as a mail address.
    /// Returns what it warned about, so a test can see it without
    /// installing a tracing subscriber.
    pub fn audit(&self) -> Vec<String> {
        let entries = match self.entries() {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("{}: {e}", self.dir.display());
                return Vec::new();
            }
        };
        let mut found = Vec::new();
        let roles = self.roles();
        if let Some(everyone) = roles.get(EVERYONE) {
            // What `everyone` grants, the guest gets too.
            let weighty = [
                bit::CREATE_USERS,
                bit::DELETE_USERS,
                bit::READ_USERS,
                bit::MODIFY_USERS,
                bit::DISCONNECT_USERS,
                bit::CANT_BE_DISCONNECTED,
            ]
            .into_iter()
            .fold(AccessBits::empty(), AccessBits::with);
            let mut given =
                access::names_of(AccessBits::from_raw(everyone.access.raw() & weighty.raw())).0;
            if everyone.extra.manage_roles {
                given.push("manage_roles");
            }
            if everyone.extra.manage_rooms {
                given.push("manage_rooms");
            }
            if !given.is_empty() {
                let complaint = format!(
                    "role {EVERYONE} grants {}, and every account holds it, the guest included",
                    given.join(", ")
                );
                tracing::warn!("{complaint}");
                found.push(complaint);
            }
        }
        for (login, _) in entries {
            if login != login.to_ascii_lowercase() {
                let complaint = format!(
                    "{login}.toml: account filenames must be lowercase; rename it to {}.toml",
                    login.to_ascii_lowercase()
                );
                tracing::warn!("{complaint}");
                found.push(complaint);
            }
            if is_role_login(&login) {
                let complaint = format!(
                    "{login}.toml: logins beginning with @ are reserved for roles; the \
                     account still logs in, but no editor will change it, and @role \
                     editing will be disabled while it exists; rename or remove the file to clear it"
                );
                tracing::warn!("{complaint}");
                found.push(complaint);
            }
            match self.load(&login) {
                Ok(f) => {
                    if let Some(reason) = f.unreachable_reason() {
                        let complaint = format!("{login}.toml: {reason}");
                        tracing::warn!("{complaint}");
                        found.push(complaint);
                    } else if f
                        .identity
                        .fingerprint
                        .as_deref()
                        .is_some_and(|fp| hl_identity::Fingerprint::parse(fp).is_none())
                    {
                        let complaint = format!(
                            "{login}.toml: identity.fingerprint is not a valid fingerprint; \
                             identity login will ignore it"
                        );
                        tracing::warn!("{complaint}");
                        found.push(complaint);
                    }
                    for name in f.roles.iter().filter(|name| roles.get(name).is_none()) {
                        let complaint =
                            format!("{login}.toml: no role {name:?}; it grants nothing");
                        tracing::warn!("{complaint}");
                        found.push(complaint);
                    }
                    for key in f.access.named.keys().filter(|key| named_bit(key).is_none()) {
                        let complaint = format!(
                            "{login}.toml: unknown access key {key:?} ignored \
                             (see hxd-auth-file docs)"
                        );
                        tracing::warn!("{complaint}");
                        found.push(complaint);
                    }
                }
                Err(AuthError::NoSuchAccount) => {}
                Err(e) => {
                    let complaint = format!("{e}; this account will be skipped");
                    tracing::warn!("{complaint}");
                    found.push(complaint);
                }
            }
        }
        found
    }

    /// Create the accounts directory and a default guest account if the
    /// directory doesn't exist yet. First-run convenience; never overwrites.
    pub fn bootstrap(dir: &Path) -> std::io::Result<()> {
        if dir.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        write_new(
            &dir.join("guest.toml"),
            "# Default guest account, created on first run. Delete this file\n\
             # to disable guest logins.\n\
             name = \"guest\"\n\n\
             [access]\n\
             read_chat = true\n\
             read_chat_history = true\n\
             send_chat = true\n\
             create_pchats = true\n\
             send_msgs = true\n\
             get_user_info = true\n\
             use_any_name = true\n\
             # Guests may not post images. Uncomment to let them, and\n\
             # read docs/inline-media.md first — this is the one bit\n\
             # that lets a stranger put a picture on everyone's screen.\n\
             # send_media = true\n",
        )?;
        Ok(())
    }

    fn load(&self, login: &str) -> Result<AccountFile, AuthError> {
        if self.is_reserved(login) {
            return Err(AuthError::NoSuchAccount);
        }
        let path = self.dir.join(format!("{login}.toml"));
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AuthError::NoSuchAccount
            } else {
                AuthError::Backend(format!("{}: {e}", path.display()))
            }
        })?;
        let parsed: AccountFile = toml::from_str(&text)
            .map_err(|e| AuthError::Backend(format!("{}: {e}", path.display())))?;
        Ok(parsed)
    }
}

/// Has this file's stamp settled? A file modified within the last second
/// may be edited again at the same length inside one mtime tick — some
/// filesystems only keep whole seconds — and the index would not see it.
/// So a just-touched file is re-read on every lookup until it stops
/// being just-touched, which costs one read on a file someone is editing.
fn settled(stamp: &FileStamp, now: SystemTime) -> bool {
    stamp
        .modified
        .and_then(|m| now.duration_since(m).ok())
        .is_some_and(|age| age >= std::time::Duration::from_secs(1))
}

/// A login is a filename component; keep it boring. Same character set the
/// original servers accepted in practice.
fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 31
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@'))
        && !login.starts_with('.')
}

/// A login beginning with `@` names a role in the period user editor
/// (`roles.md` §6.4), so nothing here writes one. A file that already has
/// one stays an account, and `audit` says so.
fn is_role_login(login: &str) -> bool {
    login.starts_with('@')
}

/// Logins the server gives its own meaning to, so an account created
/// for an identity may not be named one.
fn is_reserved_login(login: &str) -> bool {
    login == "guest"
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

impl AuthBackend for FileAuth {
    fn authenticate(&self, login: &str, proof: Proof<'_>) -> Result<Account, AuthError> {
        let login = if login.is_empty() { "guest" } else { login };
        let login = login.to_ascii_lowercase();
        if !valid_login(&login) {
            return Err(AuthError::NoSuchAccount);
        }
        let file = self.load(&login)?;
        let stored = file.password.as_deref().unwrap_or("");
        // §8.3: an account whose only credential is a linked identity is
        // not reachable by password, and "" is not an exemption. Note the
        // check is on the *stored text*, not on whether it parses: a
        // fingerprint we can't read is a broken link, not an open door.
        if stored.is_empty() && file.identity.fingerprint.is_some() {
            return Err(AuthError::BadProof);
        }
        match proof {
            Proof::Plain(given) => {
                if !constant_time_eq(stored.as_bytes(), given) {
                    return Err(AuthError::BadProof);
                }
            }
            Proof::Keyed(check) => {
                if !check(stored) {
                    return Err(AuthError::BadProof);
                }
            }
        }
        Ok(file.into_account(login, &self.roles()))
    }

    fn logins(&self) -> Result<Vec<String>, AuthError> {
        Ok(self
            .entries()?
            .into_iter()
            .map(|(login, _)| login.to_ascii_lowercase())
            .collect())
    }

    fn lookup(&self, login: &str) -> Result<Account, AuthError> {
        let login = if login.is_empty() { "guest" } else { login };
        let login = login.to_ascii_lowercase();
        if !valid_login(&login) {
            return Err(AuthError::NoSuchAccount);
        }
        let file = self.load(&login)?;
        Ok(file.into_account(login, &self.roles()))
    }

    fn find_by_fingerprint(&self, fingerprint: &[u8; 32]) -> Result<Option<Account>, AuthError> {
        match self.login_for(fingerprint)? {
            Some(login) => match self.lookup(&login) {
                Ok(a) => Ok(Some(a)),
                // Raced with a delete between the scan and the read.
                Err(AuthError::NoSuchAccount) => Ok(None),
                Err(e) => Err(e),
            },
            None => Ok(None),
        }
    }

    fn link_identity(&self, login: &str, fingerprint: &[u8; 32]) -> Result<LinkOutcome, AuthError> {
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        let account = self.lookup(login)?;
        if account.identity.fingerprint == Some(*fingerprint) {
            return Ok(LinkOutcome::Already(account));
        }
        // A password-less account has nothing to prove: `authenticate`
        // admits it on `""`, so every link site's "verify the credentials
        // first" step passes for anyone. Linking one would hand the
        // account to whoever asked, and the link then makes the password
        // path refuse everybody else (§8.3) while `unlink` answers
        // `would_orphan` — a capture only a hand edit undoes.
        if !account.has_password
            || account.identity.fingerprint.is_some()
            || !account.identity.allow_self_link
        {
            return Ok(LinkOutcome::Refused(account));
        }
        if let Some(other) = self.find_by_fingerprint(fingerprint)? {
            return Ok(LinkOutcome::Taken(other));
        }
        self.write_link(&account.login, Some(*fingerprint))?;
        Ok(LinkOutcome::Linked(self.lookup(&account.login)?))
    }

    fn rotate_link(&self, from: &[u8; 32], to: &[u8; 32]) -> Result<Option<Account>, AuthError> {
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(login) = self.login_for(from)? else {
            return Ok(None);
        };
        if let Some(other) = self.login_for(to)? {
            tracing::warn!(
                "{login}: its identity rotated to a key that account {other} already links; left as it was"
            );
            return Ok(None);
        }
        self.write_link(&login, Some(*to))?;
        self.lookup(&login).map(Some)
    }

    fn unlink_identity(&self, fingerprint: &[u8; 32]) -> Result<UnlinkOutcome, AuthError> {
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(account) = self.find_by_fingerprint(fingerprint)? else {
            return Ok(UnlinkOutcome::NotLinked);
        };
        if !account.has_password {
            return Ok(UnlinkOutcome::WouldOrphan(account));
        }
        self.write_link(&account.login, None)?;
        Ok(UnlinkOutcome::Unlinked(account))
    }

    fn find_or_create_linked(
        &self,
        proposed: &str,
        name: &str,
        fingerprint: &[u8; 32],
        access: AccessBits,
    ) -> Result<(Account, bool), AuthError> {
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = self.find_by_fingerprint(fingerprint)? {
            return Ok((existing, false));
        }
        let base: String = proposed
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .take(24)
            .collect();
        let base = base.trim_start_matches(['.', '-']).to_owned();
        let base = if base.is_empty() {
            format!("id-{}", hl_identity::Fingerprint(*fingerprint).short())
        } else {
            base
        };
        let mut doc = toml_edit::DocumentMut::new();
        doc["name"] = toml_edit::value(name);
        // The template is usually the guest account, which is where an
        // operator puts a `raw_bits` entry for a bit this build has no
        // name for yet; `write_access` keeps those.
        let mut acc = toml_edit::Table::new();
        write_access(&mut acc, access, self.roles().granted(&[]), None);
        doc["access"] = toml_edit::Item::Table(acc);
        let mut id = toml_edit::Table::new();
        id["fingerprint"] = toml_edit::value(hl_identity::Fingerprint(*fingerprint).to_string());
        doc["identity"] = toml_edit::Item::Table(id);
        doc.decor_mut()
            .set_prefix("# Created by identity login (new_accounts = create).\n");
        let text = doc.to_string();
        // First free of base, base-2, base-3, … decided by the create
        // itself: `exists()` then `create_new` is a race even under the
        // lock, since an operator can drop a file in at any moment.
        let mut candidate = base.clone();
        for n in 2..=1001 {
            // `guest` is the login every wire resolves an empty one to,
            // and the one the identity paths special-case; a handle of
            // `guest@registrar` on a server with no guest account would
            // otherwise write a password-less `guest.toml` with a
            // fingerprint in it, and `lookup("")` would find it. An
            // existing account file collides on its own, which covers
            // reserved names. The server's own login is skipped the same
            // way: a file written under it could never be logged in to,
            // and the handle behind it would be left holding a login that
            // refuses it and an orphan with its fingerprint in.
            if !valid_login(&candidate)
                || is_reserved_login(&candidate)
                || self.is_reserved(&candidate)
            {
                candidate = format!("{base}-{n}");
                continue;
            }
            let path = self.dir.join(format!("{candidate}.toml"));
            match write_new(&path, &text) {
                Ok(()) => return Ok((self.lookup(&candidate)?, true)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(AuthError::Backend(format!("{}: {e}", path.display()))),
            }
            candidate = format!("{base}-{n}");
        }
        Err(AuthError::Backend(format!("no free login for {base}")))
    }

    fn reserved_by(&self, name: &str) -> Result<Option<String>, AuthError> {
        let login = name.to_ascii_lowercase();
        if !valid_login(&login) {
            return Ok(None);
        }
        match self.load(&login) {
            Ok(f) if f.identity.reserve_name.unwrap_or(false) => Ok(Some(login)),
            Ok(_) | Err(AuthError::NoSuchAccount) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl AccountAdmin for FileAuth {
    fn read_account(&self, login: &str) -> Result<Account, AdminError> {
        let login = admin_login(login)?;
        self.load(&login)
            .map(|file| file.into_account(login, &self.roles()))
            .map_err(admin_error)
    }

    fn list_accounts(&self) -> Result<Vec<Account>, AdminError> {
        let entries = self.entries().map_err(admin_error)?;
        Ok(entries
            .into_iter()
            .filter(|(login, _)| !self.is_reserved(login))
            // A file that does not read is named at startup by `audit`;
            // it does not hide the rest.
            .filter_map(|(login, _)| self.read_account(&login).ok())
            .collect())
    }

    fn write_account(
        &self,
        edit: &AccountEdit,
        check: WriteCheck<'_>,
    ) -> Result<Account, AdminError> {
        let login = admin_login(&edit.login)?;
        if self.is_reserved(&login) || is_role_login(&login) {
            return Err(AdminError::InvalidLogin);
        }
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        let path = self.dir.join(format!("{login}.toml"));
        let failed =
            |e: &dyn std::fmt::Display| AdminError::Backend(format!("{}: {e}", path.display()));
        let roles = self.roles();
        let read = |text: &str| -> Result<Account, AdminError> {
            let file: AccountFile = toml::from_str(text).map_err(|e| failed(&e))?;
            Ok(file.into_account(login.clone(), &roles))
        };
        let old = match std::fs::read_to_string(&path) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(failed(&e)),
        };
        let existing = old.as_deref().map(read).transpose()?;
        let mut doc: toml_edit::DocumentMut = match &old {
            Some(text) => text.parse().map_err(|e| failed(&e))?,
            None => toml_edit::DocumentMut::new(),
        };
        if let Some(name) = &edit.name {
            doc["name"] = toml_edit::value(name.as_str());
        }
        match edit.password.as_deref() {
            Some("") => {
                doc.remove("password");
            }
            Some(password) => doc["password"] = toml_edit::value(password),
            None => {}
        }
        if old.is_none() || edit.access.is_some() {
            let table = doc["access"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
            let table = table
                .as_table_like_mut()
                .ok_or_else(|| failed(&"access is not a table"))?;
            let listed = existing.as_ref().map_or(&[][..], |a| &a.roles[..]);
            let baseline = roles.granted(listed);
            write_access(
                table,
                edit.access.unwrap_or_default(),
                baseline,
                edit.editor_tier,
            );
        }
        let text = doc.to_string();
        // Also what makes sure no file is left behind that the next login
        // cannot read.
        let after = read(&text)?;
        check(existing.as_ref(), &after)?;
        if old.is_none() {
            write_new(&path, &text).map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => AdminError::Exists,
                _ => failed(&e),
            })?;
        } else {
            write_atomic(&path, &text).map_err(|e| failed(&e))?;
        }
        Ok(after)
    }

    fn reload(&self) -> Result<(), String> {
        let Some(path) = &self.roles_file else {
            return Ok(());
        };
        let roles =
            Roles::load(path).map_err(|e| format!("{e}; the roles in use are unchanged"))?;
        *self.roles.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(roles);
        Ok(())
    }

    fn delete_account(
        &self,
        login: &str,
        check: &dyn Fn(&Account) -> Result<(), AdminError>,
    ) -> Result<(), AdminError> {
        let login = admin_login(login)?;
        let _guard = self.assoc.lock().unwrap_or_else(|e| e.into_inner());
        check(&self.read_account(&login)?)?;
        let path = self.dir.join(format!("{login}.toml"));
        std::fs::remove_file(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => AdminError::NoSuchAccount,
            _ => AdminError::Backend(format!("{}: {e}", path.display())),
        })
    }
}

/// An administrator's login, canonical, or why it names no file.
fn admin_login(login: &str) -> Result<String, AdminError> {
    let login = login.to_ascii_lowercase();
    if valid_login(&login) {
        Ok(login)
    } else {
        Err(AdminError::InvalidLogin)
    }
}

fn admin_error(e: AuthError) -> AdminError {
    match e {
        AuthError::NoSuchAccount => AdminError::NoSuchAccount,
        e => AdminError::Backend(e.to_string()),
    }
}

/// Make an `[access]` table say `access`, over the bits its roles give
/// (`baseline`), changing no more of it than that takes
/// (`docs/roles.md` §6.1). A bit no role gives keeps the old rule: a key
/// whose bit already reads right is left as written, comment and all, and
/// a set bit with no key gets one. A bit a role gives has no key while it
/// is set, so it goes on following the role, and `false` while it is not.
/// `raw_bits` becomes the set bits that have no name and no role, and
/// `raw_deny` gains the unset ones a role gives and loses any set bit.
/// Read-chat-history with no key follows read-chat, so it is written only
/// where it parts from it. A bit above `tier` is not touched at all: its
/// key, `raw_bits` entry or `raw_deny` entry stays as written.
fn write_access(
    table: &mut dyn toml_edit::TableLike,
    access: AccessBits,
    baseline: AccessBits,
    tier: Option<u8>,
) {
    let said = AccessBits::from_raw(tier.map_or(u64::MAX, |t| u64::MAX << (63 - t.min(63))));
    let unsaid = |b: i64| u8::try_from(b).is_ok_and(|b| b < 64 && !said.has(b));
    let access = AccessBits::from_raw(access.raw() & said.raw());
    let baseline = AccessBits::from_raw(baseline.raw() & said.raw());
    if !unsaid(bit::CHAT_HISTORY.into()) {
        if let Some(old) = table.remove("chat_history") {
            if !table.contains_key("read_chat_history") {
                table.insert("read_chat_history", old);
            }
        }
    }
    for (key, b) in NAMES {
        if unsaid((*b).into()) {
            continue;
        }
        let history = *b == bit::CHAT_HISTORY;
        let on = access.has(*b);
        if baseline.has(*b) {
            if on {
                table.remove(key);
            } else {
                set_bool(table, key, false);
            }
            continue;
        }
        match table.get(key).and_then(|item| item.as_value()) {
            Some(v) if v.as_bool() == Some(on) => {}
            Some(_) => set_bool(table, key, on),
            None if (on && !history) || (history && on != access.has(bit::READ_CHAT)) => {
                table.insert(key, toml_edit::value(on));
            }
            None => {}
        }
    }
    let listed = |table: &dyn toml_edit::TableLike, key: &str| -> Vec<i64> {
        table
            .get(key)
            .and_then(|item| item.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_integer()).collect())
            .unwrap_or_default()
    };
    let unnamed = |bits: AccessBits| -> Vec<i64> {
        access::names_of(bits)
            .1
            .into_iter()
            .map(i64::from)
            .collect()
    };
    let mut raw = unnamed(AccessBits::from_raw(access.raw() & !baseline.raw()));
    raw.extend(listed(table, "raw_bits").into_iter().filter(|b| unsaid(*b)));
    // An operator's own denial stays while the bit stays unset.
    let mut deny: Vec<i64> = listed(table, "raw_deny")
        .into_iter()
        .filter(|b| u8::try_from(*b).is_ok_and(|b| !access.has(b)))
        .collect();
    deny.extend(unnamed(AccessBits::from_raw(
        baseline.raw() & !access.raw(),
    )));
    set_numbers(table, "raw_bits", raw);
    set_numbers(table, "raw_deny", deny);
}

/// Set `key` to `on`, keeping the comment on a value already there.
fn set_bool(table: &mut dyn toml_edit::TableLike, key: &str, on: bool) {
    match table.get_mut(key).and_then(|item| item.as_value_mut()) {
        Some(v) => {
            let decor = v.decor().clone();
            *v = on.into();
            *v.decor_mut() = decor;
        }
        None => {
            table.insert(key, toml_edit::value(on));
        }
    }
}

/// Make the list of bit numbers at `key` say `bits`, untouched if it does.
fn set_numbers(table: &mut dyn toml_edit::TableLike, key: &str, mut bits: Vec<i64>) {
    bits.sort_unstable();
    bits.dedup();
    let same = table
        .get(key)
        .and_then(|item| item.as_array())
        .is_some_and(|a| {
            a.iter()
                .map(|v| v.as_integer())
                .eq(bits.iter().map(|b| Some(*b)))
        });
    if bits.is_empty() {
        table.remove(key);
    } else if !same {
        table.insert(
            key,
            toml_edit::value(bits.into_iter().collect::<toml_edit::Array>()),
        );
    }
}

impl FileAuth {
    /// Every account file's login and current stamp.
    fn entries(&self) -> Result<Vec<(String, FileStamp)>, AuthError> {
        let rd = std::fs::read_dir(&self.dir)
            .map_err(|e| AuthError::Backend(format!("{}: {e}", self.dir.display())))?;
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| AuthError::Backend(e.to_string()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(login) = name.strip_suffix(".toml") else {
                continue;
            };
            if !valid_login(login) {
                continue;
            }
            let stamp = match entry.metadata() {
                Ok(m) => FileStamp {
                    len: m.len(),
                    modified: m.modified().ok(),
                },
                // Vanished mid-scan; the read below would say the same.
                Err(_) => continue,
            };
            out.push((login.to_owned(), stamp));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// Which account, if any, carries `fingerprint`.
    ///
    /// A directory scan on every identity auth was reading and parsing
    /// every account file; this reads only files whose size or mtime
    /// changed since last time, so a steady server does one `stat` per
    /// account instead. Comparison is on the stored text, case-folded,
    /// so an unreadable value in one file can't affect another account.
    fn login_for(&self, fingerprint: &[u8; 32]) -> Result<Option<String>, AuthError> {
        let want = hl_identity::Fingerprint(*fingerprint).to_string();
        let entries = self.entries()?;
        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        // `entries` is sorted by login, so this is a binary search per
        // index key rather than a scan: the prune runs on every identity
        // auth, under the index mutex, and a directory of any size made
        // it the most expensive thing in the lookup it was protecting.
        index.retain(|login, _| {
            entries
                .binary_search_by(|(l, _)| l.as_str().cmp(login))
                .is_ok()
        });
        let now = SystemTime::now();
        let mut found = None;
        for (login, stamp) in entries {
            // A stamp that hasn't settled is used for this lookup and
            // then forgotten. Remembering it was the same bug the
            // `settled` gate exists for, one step later: an auth between
            // two edits inside one mtime tick recorded the *first*
            // file's fingerprint against a stamp that stops changing as
            // soon as the tick passes — after which the gate opens and
            // the stale value is served until something else touches the
            // file. A fingerprint is always 52 characters, so the length
            // never gives it away.
            let settled = settled(&stamp, now);
            let cached = settled && index.get(&login).is_some_and(|(s, _)| *s == stamp);
            let fp = if cached {
                index.get(&login).and_then(|(_, fp)| fp.clone())
            } else {
                let fp = match self.load(&login) {
                    Ok(f) => f.identity.fingerprint,
                    Err(AuthError::NoSuchAccount) => continue,
                    // One malformed account file used to make every
                    // identity auth on the server a 500. Skip it, loudly.
                    Err(e) => {
                        tracing::warn!("{login}.toml: {e}; skipped in fingerprint lookup");
                        None
                    }
                };
                if settled {
                    index.insert(login.clone(), (stamp, fp.clone()));
                }
                fp
            };
            if found.is_none()
                && fp
                    .as_deref()
                    .is_some_and(|fp| fp.eq_ignore_ascii_case(&want))
            {
                found = Some(login);
            }
        }
        Ok(found)
    }

    /// Set or clear one account's `identity.fingerprint`, preserving the
    /// rest of the file. Callers hold `assoc`.
    fn write_link(&self, login: &str, fingerprint: Option<[u8; 32]>) -> Result<(), AuthError> {
        let login = login.to_ascii_lowercase();
        if !valid_login(&login) {
            return Err(AuthError::NoSuchAccount);
        }
        let path = self.dir.join(format!("{login}.toml"));
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                AuthError::NoSuchAccount
            } else {
                AuthError::Backend(format!("{}: {e}", path.display()))
            }
        })?;
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e| AuthError::Backend(format!("{}: {e}", path.display())))?;
        match fingerprint {
            Some(fp) => {
                let table =
                    doc["identity"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
                table["fingerprint"] = toml_edit::value(hl_identity::Fingerprint(fp).to_string());
            }
            None => {
                // `as_table_like_mut`, not `as_table_mut`: an inline
                // `identity = { fingerprint = "…" }` is a table too, and
                // the narrower cast made unlinking one a silent no-op
                // that still answered 200.
                if let Some(table) = doc.get_mut("identity").and_then(|i| i.as_table_like_mut()) {
                    table.remove("fingerprint");
                }
            }
        }
        write_atomic(&path, &doc.to_string())
            .map_err(|e| AuthError::Backend(format!("{}: {e}", path.display())))
    }
}

/// Account files hold plaintext-equivalent secrets, so they are written
/// 0600 like the server key — never at whatever the process umask
/// happens to be.
#[cfg(unix)]
fn private_opts(opts: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

#[cfg(not(unix))]
fn private_opts(_opts: &mut std::fs::OpenOptions) {}

/// Write via a temp file and rename, so a crash mid-write can't leave a
/// half-written account file. The data is fsynced before the rename:
/// without that, a crash can leave the rename durable and the contents
/// not, which is a zero-length account file.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    // Keep whatever the operator set on the original.
    let mode = std::fs::metadata(path).ok().map(file_mode);
    let tmp = write_tmp(path, text, mode)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    sync_dir(path);
    Ok(())
}

#[cfg(unix)]
fn file_mode(m: std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_m: std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Write a file that must not exist yet. Written and synced under a
/// name of its own and then linked into place, which fails if the name
/// is taken: created in place, it would be an empty account file for a
/// moment — no password and no access, which `""` logs in to — or for
/// good after a crash.
fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = write_tmp(path, text, None)?;
    let linked = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    linked?;
    sync_dir(path);
    Ok(())
}

/// `text` in a temp file beside `path`, synced, with `mode` if given.
/// One per process: `hxd account` writes beside a running server.
fn write_tmp(path: &Path, text: &str, mode: Option<u32>) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let tmp = path.with_extension(format!("toml.{}.tmp", std::process::id()));
    let written = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        private_opts(&mut opts);
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        if let Some(mode) = mode {
            set_file_mode(&tmp, mode)?;
        }
        Ok(())
    })();
    match written {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// A rename or a link is only durable once its directory is synced.
fn sync_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
}

impl AccountDirectory for FileAuth {
    fn inbox_account(&self, login: &str) -> Option<Mailbox> {
        // No guest fallback here, deliberately: an empty login means
        // "guest" when someone is logging in, and means nothing at all
        // when someone is addressing a message.
        let login = login.to_ascii_lowercase();
        if !valid_login(&login) {
            return None;
        }
        // Through `into_account`, so the mailbox key and the account's
        // own view of its identity cannot drift apart: this is the one
        // place a fingerprint is parsed.
        let account = self.load(&login).ok()?.into_account(login, &self.roles());
        account
            .has_inbox
            .then(|| match account.identity.fingerprint {
                Some(fp) => Mailbox::identified(account.login, fp),
                None => Mailbox::login(account.login),
            })
    }

    fn mailbox_access(&self, who: &Mailbox) -> Option<AccessBits> {
        let account = match who.fingerprint {
            // Whatever the account is called now: the fingerprint is the
            // person, and a rename is not a reason to stop reaching them.
            Some(fp) => self.find_by_fingerprint(&fp).ok()??,
            None => {
                let login = who.login.to_ascii_lowercase();
                if !valid_login(&login) {
                    return None;
                }
                let account = self.load(&login).ok()?.into_account(login, &self.roles());
                // An unidentified mailbox names an account with no
                // identity and nothing else. One that has linked since is
                // addressed by its fingerprint now, and its subscriptions
                // were stamped with it when it linked.
                if account.identity.fingerprint.is_some() {
                    return None;
                }
                account
            }
        };
        account.has_inbox.then_some(account.access)
    }

    fn account(&self, login: &str) -> Option<(Mailbox, AccessBits)> {
        let login = login.to_ascii_lowercase();
        if !valid_login(&login) {
            return None;
        }
        let account = self.load(&login).ok()?.into_account(login, &self.roles());
        Some(keyed(account))
    }

    fn account_by_key(&self, fingerprint: &[u8; 32]) -> Option<(Mailbox, AccessBits)> {
        Some(keyed(self.find_by_fingerprint(fingerprint).ok()??))
    }
}

/// An account as the mailbox rule keys it, and what it may do.
fn keyed(account: Account) -> (Mailbox, AccessBits) {
    let mailbox = match account.identity.fingerprint {
        Some(fp) => Mailbox::identified(account.login, fp),
        None => Mailbox::login(account.login),
    };
    (mailbox, account.access)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    fn backend() -> (tempfile::TempDir, FileAuth) {
        let td = tempfile::tempdir().unwrap();
        let auth = FileAuth::new(td.path());
        (td, auth)
    }

    #[test]
    fn authenticates_with_password_and_access_bits() {
        let (td, auth) = backend();
        write(
            td.path(),
            "alice.toml",
            "name = \"Alice\"\npassword = \"s3cret\"\n[access]\nuse_any_name = true\ndisconnect_users = true\n",
        );
        let acct = auth.authenticate("alice", Proof::Plain(b"s3cret")).unwrap();
        assert_eq!(acct.name, "Alice");
        assert!(acct.access.has(bit::USE_ANY_NAME));
        assert!(acct.access.has(bit::DISCONNECT_USERS));
        assert!(!acct.access.has(bit::DELETE_FILES));
    }

    #[test]
    fn wrong_password_and_missing_account_are_distinct() {
        let (td, auth) = backend();
        write(td.path(), "alice.toml", "password = \"x\"\n");
        assert_eq!(
            auth.authenticate("alice", Proof::Plain(b"y")).unwrap_err(),
            AuthError::BadProof
        );
        assert_eq!(
            auth.authenticate("nobody", Proof::Plain(b"")).unwrap_err(),
            AuthError::NoSuchAccount
        );
    }

    #[test]
    fn empty_login_is_guest_and_login_is_case_folded() {
        let (td, auth) = backend();
        write(td.path(), "guest.toml", "name = \"guest\"\n");
        assert_eq!(
            auth.authenticate("", Proof::Plain(b"")).unwrap().login,
            "guest"
        );
        write(td.path(), "alice.toml", "");
        assert_eq!(
            auth.authenticate("AlIce", Proof::Plain(b"")).unwrap().login,
            "alice"
        );
    }

    #[test]
    fn non_ascii_passwords_match_in_canonical_utf8() {
        // The wire edges canonicalize credentials to UTF-8 before the
        // backend sees them (Mac Roman → UTF-8 for legacy clients), so a
        // non-ASCII stored password compares in one canonical form. This
        // lifts the earlier ASCII-only guard.
        let (td, auth) = backend();
        write(td.path(), "cafe.toml", "password = \"café\"\n");
        assert!(auth
            .authenticate("cafe", Proof::Plain("café".as_bytes()))
            .is_ok());
        assert!(matches!(
            auth.authenticate("cafe", Proof::Plain("cafe".as_bytes())),
            Err(AuthError::BadProof)
        ));
    }

    #[test]
    fn path_traversal_logins_are_rejected() {
        let (_td, auth) = backend();
        for bad in [
            "../guest",
            "a/b",
            "a\\b",
            ".hidden",
            "x".repeat(40).as_str(),
        ] {
            assert_eq!(
                auth.authenticate(bad, Proof::Plain(b"")).unwrap_err(),
                AuthError::NoSuchAccount,
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn extra_defaults_derive_from_password_and_admin_bit() {
        let (td, auth) = backend();
        // Password-less: no detach; no admin bit: no subject.
        write(td.path(), "guest.toml", "");
        let g = auth.authenticate("guest", Proof::Plain(b"")).unwrap();
        assert!(!g.can_detach);
        assert!(!g.set_subject);
        assert!(!g.attach_news);
        assert!(!g.moderate);
        assert!(!g.set_avatar, "the bootstrap guest sets no avatar");
        // Passworded admin: both derived on.
        write(
            td.path(),
            "root.toml",
            "password = \"pw\"\n[access]\ndisconnect_users = true\nsend_media = true\n",
        );
        let r = auth.authenticate("root", Proof::Plain(b"pw")).unwrap();
        assert!(r.can_detach);
        assert!(r.set_subject);
        assert!(r.attach_news);
        assert!(r.set_avatar);
        // The kick bit makes a moderator (`docs/moderation.md` §2).
        assert!(r.moderate);
        // Explicit overrides beat the derivation, both directions.
        write(
            td.path(),
            "kiosk.toml",
            "[extra]\ncan_detach = true\nset_subject = true\nattach_news = true\nmoderate = true\n\
             set_avatar = true\n",
        );
        let k = auth.authenticate("kiosk", Proof::Plain(b"")).unwrap();
        assert!(k.can_detach && k.set_subject && k.attach_news && k.moderate && k.set_avatar);
        write(
            td.path(),
            "bouncer.toml",
            "password = \"pw\"\n[access]\ndisconnect_users = true\n[extra]\nmoderate = false\n",
        );
        let b = auth.authenticate("bouncer", Proof::Plain(b"pw")).unwrap();
        assert!(
            !b.moderate,
            "an operator may keep the kick and withhold redaction"
        );
        write(
            td.path(),
            "probation.toml",
            "password = \"pw\"\n[access]\nsend_media = true\n[extra]\ncan_detach = false\nattach_news = false\n\
             set_avatar = false\n",
        );
        let p = auth.authenticate("probation", Proof::Plain(b"pw")).unwrap();
        assert!(!p.can_detach);
        assert!(!p.set_avatar);
        assert!(!p.attach_news);
    }

    #[test]
    fn file_extras_are_on_unless_turned_off_one_at_a_time() {
        let (td, auth) = backend();
        write(td.path(), "guest.toml", "");
        let g = auth.authenticate("guest", Proof::Plain(b"")).unwrap();
        assert!(g.file_list && g.file_getinfo);
        write(td.path(), "nolist.toml", "[extra]\nfile_list = false\n");
        let l = auth.lookup("nolist").unwrap();
        assert!(!l.file_list && l.file_getinfo);
        write(td.path(), "noinfo.toml", "[extra]\nfile_getinfo = false\n");
        let i = auth.lookup("noinfo").unwrap();
        assert!(i.file_list && !i.file_getinfo);
    }

    #[test]
    fn raw_bits_escape_hatch_and_bootstrap() {
        let (td, auth) = backend();
        write(td.path(), "v.toml", "[access]\nraw_bits = [55]\n");
        assert!(auth
            .authenticate("v", Proof::Plain(b""))
            .unwrap()
            .access
            .has(bit::VOICE_CHAT));

        let sub = td.path().join("fresh");
        FileAuth::bootstrap(&sub).unwrap();
        let auth2 = FileAuth::new(&sub);
        let guest = auth2.authenticate("", Proof::Plain(b"")).unwrap();
        assert!(guest.access.has(bit::READ_CHAT));
        assert!(guest.access.has(bit::CHAT_HISTORY));
        // Never overwrites an existing dir.
        std::fs::remove_file(sub.join("guest.toml")).unwrap();
        FileAuth::bootstrap(&sub).unwrap();
        assert!(!sub.join("guest.toml").exists());
    }

    #[test]
    fn chat_history_defaults_to_read_chat_but_an_explicit_key_wins() {
        let (td, auth) = backend();
        write(td.path(), "reader.toml", "[access]\nread_chat = true\n");
        assert!(auth.lookup("reader").unwrap().access.has(bit::CHAT_HISTORY));

        write(
            td.path(),
            "private.toml",
            "[access]\nread_chat = true\nread_chat_history = false\n",
        );
        assert!(!auth
            .lookup("private")
            .unwrap()
            .access
            .has(bit::CHAT_HISTORY));

        write(
            td.path(),
            "old-name.toml",
            "[access]\nread_chat = true\nchat_history = false\n",
        );
        assert!(!auth
            .lookup("old-name")
            .unwrap()
            .access
            .has(bit::CHAT_HISTORY));
    }

    #[test]
    fn identity_link_round_trip_preserves_comments() {
        let (td, auth) = backend();
        write(
            td.path(),
            "alice.toml",
            "# Alice's account\nname = \"Alice\"\npassword = \"pw\" # keep\n\n[access]\nsend_chat = true\n",
        );
        let fp = [0xabu8; 32];
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        assert!(matches!(
            auth.link_identity("alice", &fp).unwrap(),
            LinkOutcome::Linked(_)
        ));
        let text = std::fs::read_to_string(td.path().join("alice.toml")).unwrap();
        assert!(text.starts_with("# Alice's account\n"), "{text}");
        assert!(text.contains("password = \"pw\" # keep"), "{text}");
        assert!(text.contains("[identity]"), "{text}");
        let a = auth.find_by_fingerprint(&fp).unwrap().unwrap();
        assert_eq!(a.login, "alice");
        assert_eq!(a.identity.fingerprint, Some(fp));
        assert!(
            a.identity.identity_login && a.identity.allow_self_link && !a.identity.reserve_name
        );
        assert!(a.has_password);
        // lookup() agrees and needs no password.
        assert_eq!(auth.lookup("Alice").unwrap().identity.fingerprint, Some(fp));
        // Linking again is a no-op, not an error.
        assert!(matches!(
            auth.link_identity("alice", &fp).unwrap(),
            LinkOutcome::Already(_)
        ));
        // Unlink removes only the fingerprint.
        assert!(matches!(
            auth.unlink_identity(&fp).unwrap(),
            UnlinkOutcome::Unlinked(_)
        ));
        let text = std::fs::read_to_string(td.path().join("alice.toml")).unwrap();
        assert!(!text.contains("fingerprint"), "{text}");
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        assert_eq!(auth.unlink_identity(&fp).unwrap(), UnlinkOutcome::NotLinked);
        assert_eq!(
            auth.link_identity("nobody", &fp).unwrap_err(),
            AuthError::NoSuchAccount
        );
    }

    #[test]
    fn unlink_clears_an_inline_identity_table() {
        // `as_table_mut` returns None for an inline table, so unlinking
        // one used to report success and change nothing.
        let (td, auth) = backend();
        let fp = [0x5au8; 32];
        let text = format!(
            "password = \"pw\"\nidentity = {{ fingerprint = \"{}\" }}\n",
            hl_identity::Fingerprint(fp)
        );
        write(td.path(), "alice.toml", &text);
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "alice"
        );
        assert!(matches!(
            auth.unlink_identity(&fp).unwrap(),
            UnlinkOutcome::Unlinked(_)
        ));
        let text = std::fs::read_to_string(td.path().join("alice.toml")).unwrap();
        assert!(!text.contains("fingerprint"), "{text}");
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
    }

    #[test]
    fn a_linked_account_without_a_password_is_not_reachable_by_password() {
        // §8.3: for these accounts the device key is the credential.
        // Without this, everything `new_accounts = create` writes is open
        // to anyone who types the login and an empty password on :5500.
        let (td, auth) = backend();
        let fp = [3u8; 32];
        write(
            td.path(),
            "created.toml",
            &format!(
                "name = \"Created\"\n[identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        assert_eq!(
            auth.authenticate("created", Proof::Plain(b"")).unwrap_err(),
            AuthError::BadProof
        );
        assert_eq!(
            auth.authenticate("created", Proof::Plain(b"guess"))
                .unwrap_err(),
            AuthError::BadProof
        );
        // The identity path reaches it, having proved the key first.
        assert_eq!(auth.lookup("created").unwrap().login, "created");
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "created"
        );
        // A password-less account with no link is still an open door on
        // purpose — that's what a kiosk or guest account is.
        write(td.path(), "kiosk.toml", "name = \"Kiosk\"\n");
        assert!(auth.authenticate("kiosk", Proof::Plain(b"")).is_ok());
        // And an unreadable fingerprint is a broken link, not an opening.
        write(
            td.path(),
            "broken.toml",
            "[identity]\nfingerprint = \"junk\"\n",
        );
        assert_eq!(
            auth.authenticate("broken", Proof::Plain(b"")).unwrap_err(),
            AuthError::BadProof
        );
    }

    #[test]
    fn linking_enforces_one_account_per_identity() {
        let (td, auth) = backend();
        write(td.path(), "alice.toml", "password = \"pw\"\n");
        write(td.path(), "other.toml", "password = \"pw\"\n");
        write(
            td.path(),
            "closed.toml",
            "password = \"pw\"\n[identity]\nallow_self_link = false\n",
        );
        let fp = [1u8; 32];
        assert!(matches!(
            auth.link_identity("alice", &fp).unwrap(),
            LinkOutcome::Linked(_)
        ));
        match auth.link_identity("other", &fp).unwrap() {
            LinkOutcome::Taken(a) => assert_eq!(a.login, "alice"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            auth.link_identity("closed", &[2u8; 32]).unwrap(),
            LinkOutcome::Refused(_)
        ));
        // An account that already links someone else refuses too.
        assert!(matches!(
            auth.link_identity("alice", &[2u8; 32]).unwrap(),
            LinkOutcome::Refused(_)
        ));
    }

    #[test]
    fn a_password_less_account_cannot_be_captured_by_linking() {
        // The empty password verifies for anyone, so every link site's
        // "check the credentials first" step passes; linking would then
        // shut everyone else out of a kiosk account, and `unlink` would
        // answer `would_orphan`. Self-linking needs something to prove.
        let (td, auth) = backend();
        write(td.path(), "kiosk.toml", "name = \"Kiosk\"\n");
        assert!(matches!(
            auth.link_identity("kiosk", &[9u8; 32]).unwrap(),
            LinkOutcome::Refused(_)
        ));
        assert!(auth.lookup("kiosk").unwrap().identity.fingerprint.is_none());
        // With a password it links as usual.
        write(td.path(), "kiosk.toml", "password = \"pw\"\n");
        assert!(matches!(
            auth.link_identity("kiosk", &[9u8; 32]).unwrap(),
            LinkOutcome::Linked(_)
        ));
    }

    #[test]
    fn unlink_refuses_to_orphan_a_password_less_account() {
        let (td, auth) = backend();
        let fp = [4u8; 32];
        write(
            td.path(),
            "created.toml",
            &format!(
                "[identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        match auth.unlink_identity(&fp).unwrap() {
            UnlinkOutcome::WouldOrphan(a) => assert_eq!(a.login, "created"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn one_malformed_account_file_does_not_break_every_lookup() {
        let (td, auth) = backend();
        let fp = [6u8; 32];
        write(td.path(), "broken.toml", "name = \"unclosed\n");
        write(
            td.path(),
            "alice.toml",
            &format!(
                "[identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "alice"
        );
    }

    #[test]
    fn the_fingerprint_index_notices_an_edited_file() {
        let (td, auth) = backend();
        let fp = [8u8; 32];
        let mine = hl_identity::Fingerprint(fp).to_string();
        let other = hl_identity::Fingerprint([9u8; 32]).to_string();
        let file = |f: &str| format!("password = \"pw\"\n[identity]\nfingerprint = \"{f}\"\n");
        write(td.path(), "alice.toml", &file(&other));
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        // A hand edit, not one of ours — and the same length, inside one
        // mtime tick, which is all the stamp has to go on. A file this
        // fresh is re-read rather than trusted.
        write(td.path(), "alice.toml", &file(&mine));
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "alice"
        );
        // And a deleted account leaves the index.
        std::fs::remove_file(td.path().join("alice.toml")).unwrap();
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
    }

    #[test]
    fn the_startup_audit_names_what_an_operator_would_want_told() {
        let (td, auth) = backend();
        assert!(auth.audit().is_empty(), "a healthy directory says nothing");

        // §8.3's lockout: no password, a link, and identity login off.
        // `unlink` refuses to write this state; an operator can type it,
        // and it is read as identity login on, and said so.
        write(
            td.path(),
            "kiosk.toml",
            "[identity]\nfingerprint = \"6htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0\"\n\
             login = false\n",
        );
        write(td.path(), "broken.toml", "password = [1, 2]\n");
        // Two sibling lockout shapes: an invalid identity key on a
        // password-less file, and a filename lookups can never reach after
        // they canonicalize the login to lowercase.
        write(
            td.path(),
            "orphan.toml",
            "[identity]\nfingerprint = \"not-a-fingerprint\"\n",
        );
        write(td.path(), "Alice.toml", "password = \"pw\"\n");
        // Access typos are startup warnings, not warnings repeated by every
        // account lookup.
        write(
            td.path(),
            "typo.toml",
            "password = \"pw\"\n[access]\nsend_mesgs = true\n",
        );
        let said = auth.audit();
        assert_eq!(said.len(), 5, "{said:?}");
        assert!(
            said.iter()
                .any(|s| s.starts_with("kiosk.toml")
                    && s.contains("identity.login = false is ignored")),
            "{said:?}"
        );
        assert!(
            auth.lookup("kiosk").unwrap().identity.identity_login,
            "the flag that would lock everyone out is not the one in force"
        );
        assert!(
            said.iter()
                .any(|s| s.contains("broken.toml") && s.contains("skipped")),
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|s| s.starts_with("orphan.toml")
                    && s.contains("identity.fingerprint is invalid")),
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|s| s.starts_with("Alice.toml") && s.contains("filenames must be lowercase")),
            "{said:?}"
        );
        assert!(
            said.iter()
                .any(|s| s.starts_with("typo.toml") && s.contains("send_mesgs")),
            "{said:?}"
        );

        // A password makes the flag the account's own again: the
        // password is the way in, and the key is refused.
        write(
            td.path(),
            "kiosk.toml",
            "password = \"pw\"\n[identity]\nfingerprint = \"6htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0\"\n\
             login = false\n",
        );
        for name in ["broken.toml", "orphan.toml", "Alice.toml", "typo.toml"] {
            std::fs::remove_file(td.path().join(name)).unwrap();
        }
        assert!(auth.audit().is_empty());
        assert!(!auth.lookup("kiosk").unwrap().identity.identity_login);
    }

    #[test]
    fn an_unsettled_stamp_is_not_remembered() {
        // The `settled` gate stops an unsettled stamp being *believed*;
        // it also has to stop it being *stored*. Two edits inside one
        // mtime tick with a lookup between them: the lookup records the
        // first file's fingerprint against a stamp that never changes
        // again, and once the tick passes the gate opens on stale data.
        let (td, auth) = backend();
        let fp = [8u8; 32];
        let mine = hl_identity::Fingerprint(fp).to_string();
        let other = hl_identity::Fingerprint([9u8; 32]).to_string();
        let file = |f: &str| format!("password = \"pw\"\n[identity]\nfingerprint = \"{f}\"\n");
        let path = td.path().join("alice.toml");
        let touch = |at: SystemTime| {
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(at)
                .unwrap()
        };
        // One mtime for both writes, as a filesystem with one-second
        // granularity would give them — and the same length either way,
        // because every fingerprint is 52 characters. `now` leaves the
        // whole second of slack before it settles, so a stall between
        // here and the lookup below cannot turn the case being tested
        // into a different one.
        let tick = SystemTime::now();
        write(td.path(), "alice.toml", &file(&other));
        touch(tick);
        let stamp = |at: SystemTime| FileStamp {
            len: std::fs::metadata(&path).unwrap().len(),
            modified: Some(at),
        };
        assert!(
            !settled(&stamp(tick), SystemTime::now()),
            "the case is a lookup while the file is still fresh"
        );
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        write(td.path(), "alice.toml", &file(&mine));
        touch(tick);

        // Wait out the tick rather than guessing at it. The stamp is the
        // one the lookup above saw, so an index that kept it now answers
        // from it.
        while !settled(&stamp(tick), SystemTime::now()) {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "alice",
            "an unsettled stamp must not be cached"
        );
    }

    #[cfg(unix)]
    #[test]
    fn written_account_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (td, auth) = backend();
        let a = auth
            .find_or_create_linked("alice", "Alice", &[9u8; 32], AccessBits::empty())
            .unwrap()
            .0;
        let mode = std::fs::metadata(td.path().join(format!("{}.toml", a.login)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "account files hold secrets");
        // And a rewrite keeps whatever the operator set.
        std::fs::set_permissions(
            td.path().join("alice.toml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        auth.link_identity("alice", &[10u8; 32]).unwrap();
        let mode = std::fs::metadata(td.path().join("alice.toml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o640);
    }

    #[test]
    fn identity_flags_and_reserved_names() {
        let (td, auth) = backend();
        write(
            td.path(),
            "alice.toml",
            "password = \"pw\"\n[identity]\nfingerprint = \"junk\"\nlogin = false\nallow_self_link = false\nreserve_name = true\n",
        );
        let a = auth.lookup("alice").unwrap();
        assert_eq!(
            a.identity.fingerprint, None,
            "unparseable fingerprint is ignored, not fatal"
        );
        assert!(
            !a.identity.identity_login && !a.identity.allow_self_link && a.identity.reserve_name
        );
        assert_eq!(auth.reserved_by("ALICE").unwrap(), Some("alice".into()));
        assert_eq!(auth.reserved_by("guest").unwrap(), None);
        assert_eq!(auth.reserved_by("../alice").unwrap(), None);
    }

    #[test]
    fn a_created_account_keeps_bits_this_build_has_no_name_for() {
        // The guest account is the usual template, and `raw_bits` is
        // where an operator puts an allocation this build predates —
        // the messaging extension's access bit 58, for one. Emitting
        // only `NAMES` dropped them on the floor.
        let (td, auth) = backend();
        let access = AccessBits::empty().with(bit::SEND_CHAT).with(58).with(61);
        let (a, created) = auth
            .find_or_create_linked("newbie", "Newbie", &[5u8; 32], access)
            .unwrap();
        assert!(created);
        let text = std::fs::read_to_string(td.path().join(format!("{}.toml", a.login))).unwrap();
        assert!(text.contains("raw_bits"), "{text}");
        // And it reads back as exactly what went in.
        let back = auth.lookup(&a.login).unwrap();
        assert_eq!(back.access, access);
    }

    #[test]
    fn create_never_writes_the_guest_account() {
        // `guest` is what an empty login resolves to and what the
        // identity paths special-case. A handle of `guest@registrar`
        // used to write a password-less `guest.toml` with a fingerprint.
        let (td, auth) = backend();
        let (acct, made) = auth
            .find_or_create_linked("guest", "Guest", &[5u8; 32], AccessBits::empty())
            .unwrap();
        assert!(made);
        assert_eq!(acct.login, "guest-2");
        assert!(!td.path().join("guest.toml").exists());
    }

    #[test]
    fn the_reserved_login_is_nobody_to_log_in_as() {
        // A migrated server's account file of the same name, password
        // and all, stops being a way in.
        let (td, auth) = backend();
        write(td.path(), "server.toml", "password = \"hunter2\"\n");
        let auth = auth.reserving("Server");
        assert!(matches!(
            auth.authenticate("server", Proof::Plain(b"hunter2")),
            Err(AuthError::NoSuchAccount)
        ));
        assert!(matches!(
            auth.lookup("SERVER"),
            Err(AuthError::NoSuchAccount)
        ));
    }

    #[test]
    fn create_never_writes_the_reserved_login() {
        let (td, auth) = backend();
        let auth = auth.reserving("server");
        let (acct, made) = auth
            .find_or_create_linked("server", "Server", &[6u8; 32], AccessBits::empty())
            .unwrap();
        assert!(made);
        assert_eq!(acct.login, "server-2");
        assert!(!td.path().join("server.toml").exists());
    }

    #[test]
    fn a_login_beginning_with_at_is_left_to_roles() {
        let (td, auth) = backend();
        write(td.path(), "@old.toml", "password = \"pw\"\n");
        assert_eq!(
            auth.authenticate("@old", Proof::Plain(b"pw"))
                .unwrap()
                .login,
            "@old"
        );
        assert!(
            auth.audit()
                .iter()
                .any(|s| s.starts_with("@old.toml") && s.contains("reserved for roles")),
            "an account already holding one is named at startup"
        );
        assert_eq!(
            auth.authenticate("@mods", Proof::Plain(b"")).unwrap_err(),
            AuthError::NoSuchAccount
        );
        for login in ["@mods", "@old"] {
            let edit = AccountEdit {
                login: login.into(),
                ..Default::default()
            };
            assert_eq!(
                auth.write_account(&edit, &|_, _| Ok(())).unwrap_err(),
                AdminError::InvalidLogin,
                "{login}"
            );
        }
        assert!(!td.path().join("@mods.toml").exists());
        let (made, _) = auth
            .find_or_create_linked("@mods", "Mods", &[5u8; 32], AccessBits::empty())
            .unwrap();
        assert_eq!(made.login, "mods");
    }

    #[test]
    fn create_linked_picks_a_free_login() {
        let (td, auth) = backend();
        write(td.path(), "alice.toml", "name = \"Alice\"\n");
        let fp = [7u8; 32];
        let access = AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT);
        let (a, created) = auth
            .find_or_create_linked("alice", "Alice", &fp, access)
            .unwrap();
        assert!(created);
        assert_eq!(a.login, "alice-2");
        assert_eq!(a.name, "Alice");
        assert_eq!(a.identity.fingerprint, Some(fp));
        assert!(!a.has_password);
        assert!(
            a.can_detach,
            "a linked, password-less account is still a person"
        );
        assert!(a.set_avatar);
        assert!(a.access.has(bit::SEND_CHAT) && !a.access.has(bit::DELETE_FILES));
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "alice-2"
        );
        // Called again for the same identity it finds, never creates.
        let (again, created) = auth
            .find_or_create_linked("alice", "Alice", &fp, access)
            .unwrap();
        assert!(!created);
        assert_eq!(again.login, "alice-2");
        // Hostile proposals are sanitised.
        let b = auth
            .find_or_create_linked("../../etc", "x", &[8u8; 32], AccessBits::empty())
            .unwrap()
            .0;
        assert_eq!(b.login, "etc");
        let c = auth
            .find_or_create_linked("", "x", &[9u8; 32], AccessBits::empty())
            .unwrap()
            .0;
        assert!(c.login.starts_with("id-"), "{}", c.login);
    }

    #[test]
    fn concurrent_links_and_creates_settle_on_one_account() {
        use std::sync::Arc;
        let td = tempfile::tempdir().unwrap();
        let auth = Arc::new(FileAuth::new(td.path()));
        for n in 0..8 {
            write(td.path(), &format!("a{n}.toml"), "password = \"pw\"\n");
        }
        let fp = [0x2bu8; 32];

        // Eight threads, one identity, eight different accounts: exactly
        // one link may be written.
        let linked: Vec<_> = (0..8)
            .map(|n| {
                let auth = auth.clone();
                std::thread::spawn(move || auth.link_identity(&format!("a{n}"), &fp).unwrap())
            })
            .map(|h| h.join().unwrap())
            .collect();
        let wrote = linked
            .iter()
            .filter(|o| matches!(o, LinkOutcome::Linked(_)))
            .count();
        assert_eq!(wrote, 1, "{linked:?}");
        let holders = auth
            .entries()
            .unwrap()
            .into_iter()
            .filter(|(l, _)| {
                auth.lookup(l)
                    .map(|a| a.identity.fingerprint == Some(fp))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(holders, 1);

        // And eight threads creating for one never-seen identity make
        // one account, not eight.
        let fp2 = [0x3cu8; 32];
        let made: Vec<_> = (0..8)
            .map(|_| {
                let auth = auth.clone();
                std::thread::spawn(move || {
                    auth.find_or_create_linked("newbie", "Newbie", &fp2, AccessBits::empty())
                        .unwrap()
                })
            })
            .map(|h| h.join().unwrap())
            .collect();
        assert_eq!(made.iter().filter(|(_, created)| *created).count(), 1);
        let logins: std::collections::HashSet<_> =
            made.iter().map(|(a, _)| a.login.clone()).collect();
        assert_eq!(logins.len(), 1, "{logins:?}");
    }

    #[test]
    fn an_inbox_follows_having_a_password_unless_told_otherwise() {
        let (td, auth) = backend();
        write(td.path(), "plain.toml", "password = \"pw\"\n");
        write(td.path(), "open.toml", "");
        write(
            td.path(),
            "quiet.toml",
            "password = \"pw\"\n[extra]\ninbox = false\n",
        );
        write(td.path(), "kiosk.toml", "[extra]\ninbox = true\n");

        let has = |l: &str, pw: &[u8]| auth.authenticate(l, Proof::Plain(pw)).unwrap().has_inbox;
        assert!(has("plain", b"pw"));
        assert!(!has("open", b""), "a shared door is not an address");
        assert!(!has("quiet", b"pw"));
        assert!(has("kiosk", b""));

        // Whether a person is behind the account is not the switch: news
        // authorship follows the password, whatever the mail policy says.
        let person =
            |l: &str, pw: &[u8]| auth.authenticate(l, Proof::Plain(pw)).unwrap().is_person();
        assert!(person("plain", b"pw"));
        assert!(!person("open", b""));
        assert!(person("quiet", b"pw"));
        assert!(!person("kiosk", b""));
    }

    #[test]
    fn the_directory_canonicalises_and_answers_one_none_for_two_questions() {
        let (td, auth) = backend();
        write(td.path(), "alice.toml", "password = \"pw\"\n");
        write(
            td.path(),
            "quiet.toml",
            "password = \"pw\"\n[extra]\ninbox = false\n",
        );

        assert_eq!(auth.inbox_account("AlIce"), Some(Mailbox::login("alice")));
        // "No such account" and "that account takes no mail" are the same
        // answer: the message path must not tell them apart.
        assert_eq!(auth.inbox_account("nobody"), None);
        assert_eq!(auth.inbox_account("quiet"), None);
        // A login that could never name a file is refused before the
        // filesystem is touched at all.
        assert_eq!(auth.inbox_account("../../etc/passwd"), None);
        assert_eq!(auth.inbox_account(""), None);
    }

    #[test]
    fn a_mailbox_is_found_by_its_fingerprint_whatever_the_login_is_now() {
        let (td, auth) = backend();
        let fp = [0x3cu8; 32];
        let text = format!(
            "password = \"pw\"\n[access]\nread_news = true\n[identity]\nfingerprint = \"{}\"\n",
            hl_identity::Fingerprint(fp)
        );
        write(td.path(), "alice.toml", &text);
        // Renamed since the subscription was made: the fingerprint is
        // the person, and the login the row was stamped with is history.
        std::fs::rename(td.path().join("alice.toml"), td.path().join("alicia.toml")).unwrap();
        let access = auth.mailbox_access(&Mailbox::identified("alice", fp));
        assert!(access.is_some_and(|a| a.has(bit::READ_NEWS)), "{access:?}");
        assert_eq!(
            auth.mailbox_access(&Mailbox::identified("alicia", [0x3du8; 32])),
            None,
            "another identity is nobody, whatever login it carries"
        );
    }

    #[test]
    fn an_account_is_found_for_moderation_whether_or_not_it_takes_mail() {
        let (td, auth) = backend();
        let fp = [0x4eu8; 32];
        write(
            td.path(),
            "boss.toml",
            &format!(
                "password = \"pw\"\n[access]\ncant_be_disconnected = true\n\
                 [extra]\ninbox = false\n[identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        // Nothing for mail: the account keeps none.
        assert_eq!(auth.inbox_account("boss"), None);
        assert_eq!(auth.mailbox_access(&Mailbox::identified("boss", fp)), None);
        // Everything for the ladder, by login and by key.
        let (mailbox, access) = auth.account("Boss").expect("by login");
        assert_eq!(mailbox, Mailbox::identified("boss", fp));
        assert!(access.has(bit::CANT_BE_DISCONNECTED));
        let (mailbox, access) = auth.account_by_key(&fp).expect("by key");
        assert_eq!(mailbox.login, "boss");
        assert!(access.has(bit::CANT_BE_DISCONNECTED));
        assert_eq!(auth.account("nobody"), None);
        assert_eq!(auth.account_by_key(&[0x4fu8; 32]), None);
    }

    #[test]
    fn a_login_keyed_mailbox_is_nobody_once_its_account_has_linked() {
        let (td, auth) = backend();
        write(
            td.path(),
            "carol.toml",
            "password = \"pw\"\n[access]\nread_news = true\n",
        );
        let by_login = Mailbox::login("Carol");
        let access = auth.mailbox_access(&by_login);
        assert!(access.is_some_and(|a| a.has(bit::READ_NEWS)), "{access:?}");

        // Linked since: the account is addressed by its fingerprint now,
        // and a row still keyed by the login answers for nobody. That is
        // what stops a reused login being rung for its previous holder.
        let fp = [0x4eu8; 32];
        assert!(matches!(
            auth.link_identity("carol", &fp).unwrap(),
            LinkOutcome::Linked(_)
        ));
        assert_eq!(auth.mailbox_access(&by_login), None);
        assert!(auth
            .mailbox_access(&Mailbox::identified("carol", fp))
            .is_some());
    }

    #[test]
    fn an_account_without_an_inbox_is_nobody_either_way() {
        let (td, auth) = backend();
        let fp = [0x5fu8; 32];
        write(
            td.path(),
            "quiet.toml",
            "password = \"pw\"\n[access]\nread_news = true\n[extra]\ninbox = false\n",
        );
        write(
            td.path(),
            "hush.toml",
            &format!(
                "password = \"pw\"\n[access]\nread_news = true\n[extra]\ninbox = false\n\
                 [identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        assert_eq!(auth.mailbox_access(&Mailbox::login("quiet")), None);
        assert_eq!(auth.mailbox_access(&Mailbox::identified("hush", fp)), None);
        // And the answers for "no such account" are the same `None`.
        assert_eq!(auth.mailbox_access(&Mailbox::login("nobody")), None);
        assert_eq!(auth.mailbox_access(&Mailbox::login("../quiet")), None);
    }

    /// What `key` resolves to: a named bit, `raw:N`, or an `[extra]` key.
    fn has(a: &Account, key: &str) -> bool {
        match key {
            "moderate" => a.moderate,
            "attach_news" => a.attach_news,
            "manage_roles" => a.manage_roles,
            "manage_rooms" => a.manage_rooms,
            _ => match key.strip_prefix("raw:") {
                Some(n) => a.access.has(n.parse().unwrap()),
                None => a.access.has(named_bit(key).unwrap()),
            },
        }
    }

    #[test]
    fn roles_grant_and_the_account_file_overrides_either_way() {
        const MEDIA: &str = "[role.r]\naccess = { send_media = true }\n";
        const HISTORY: &str = "[role.r]\naccess = { read_chat_history = true }\n";
        const READ: &str = "[role.r]\naccess = { read_chat = true }\n";
        const KICK: &str = "[role.r]\naccess = { disconnect_users = true }\n";
        const MODERATE: &str = "[role.r]\nextra = { moderate = true }\n";
        const RAW: &str = "[role.r]\naccess = { raw_bits = [58] }\n";
        const LISTED: &str = "roles = [\"r\"]\n";
        // The roles file, the account file, the key, what it resolves to.
        let rows: &[(&str, &str, &str, bool)] = &[
            (MEDIA, LISTED, "send_media", true),
            (
                MEDIA,
                "roles = [\"r\"]\n[access]\nsend_media = false\n",
                "send_media",
                false,
            ),
            (MEDIA, "", "send_media", false),
            ("", "[access]\nsend_media = true\n", "send_media", true),
            ("", "[access]\nsend_media = false\n", "send_media", false),
            ("", "", "send_media", false),
            // Bit 56 follows bit 9 where nothing names it.
            (
                "",
                "[access]\nread_chat = true\n",
                "read_chat_history",
                true,
            ),
            (
                "",
                "[access]\nread_chat = true\nread_chat_history = false\n",
                "read_chat_history",
                false,
            ),
            (READ, LISTED, "read_chat_history", true),
            (HISTORY, LISTED, "read_chat_history", true),
            (
                HISTORY,
                "roles = [\"r\"]\n[access]\nread_chat = true\nread_chat_history = false\n",
                "read_chat_history",
                false,
            ),
            (
                "",
                "[access]\nread_chat = true\nraw_deny = [56]\n",
                "read_chat_history",
                false,
            ),
            // A derived key derives from the bits as roles and file leave them.
            (KICK, LISTED, "moderate", true),
            (
                KICK,
                "roles = [\"r\"]\n[extra]\nmoderate = false\n",
                "moderate",
                false,
            ),
            (
                KICK,
                "roles = [\"r\"]\n[access]\ndisconnect_users = false\n",
                "moderate",
                false,
            ),
            (MODERATE, LISTED, "moderate", true),
            (
                MODERATE,
                "roles = [\"r\"]\n[extra]\nmoderate = false\n",
                "moderate",
                false,
            ),
            (MEDIA, LISTED, "attach_news", true),
            ("", "", "manage_roles", false),
            (
                "[role.r]\nextra = { manage_roles = true }\n",
                LISTED,
                "manage_roles",
                true,
            ),
            ("", "", "manage_rooms", false),
            (
                "[role.r]\nextra = { manage_rooms = true }\n",
                LISTED,
                "manage_rooms",
                true,
            ),
            (RAW, LISTED, "raw:58", true),
            (
                RAW,
                "roles = [\"r\"]\n[access]\nraw_deny = [58]\n",
                "raw:58",
                false,
            ),
            ("", "[access]\nraw_bits = [58]\n", "raw:58", true),
            // `everyone` reaches an account that lists nothing, the guest's.
            (
                "[role.everyone]\naccess = { read_news = true }\n",
                "name = \"guest\"\n",
                "read_news",
                true,
            ),
            (
                "[role.everyone]\naccess = { send_media = true }\n",
                "[access]\nsend_media = false\n",
                "send_media",
                false,
            ),
        ];
        for (roles, account, key, want) in rows {
            let roles = Roles::parse(roles).unwrap();
            let file: AccountFile = toml::from_str(account).unwrap();
            let got = has(&file.into_account("x".into(), &roles), key);
            assert_eq!(
                got, *want,
                "{key} with roles {roles:?} and account {account:?}"
            );
        }
    }

    #[test]
    fn a_roles_file_that_would_grant_wrongly_does_not_load() {
        let rows = [
            ("[role.r]\nextra = { can_detach = true }\n", "one person"),
            ("[role.r]\nextra = { inbox = true }\n", "one person"),
            ("[role.r]\nextra = { flying = true }\n", "no [extra] key"),
            ("[role.Mods]\n", "lowercase"),
            ("[role.-mods]\n", "starting with"),
            (&*format!("[role.{}]\n", "a".repeat(31)), "1 to 30"),
            ("[role.muted]\nkind = \"restriction\"\n", "not supported"),
            (
                "[role.muted]\ndeny = { send_chat = true }\n",
                "not supported",
            ),
            ("[role.r]\naccess = { send_msg = true }\n", "no access key"),
            ("[role.r]\naccess = { raw_deny = [58] }\n", "raw_deny"),
            (
                &*format!("[role.r]\ntitle = \"{}\"\n", "t".repeat(32)),
                "31",
            ),
        ];
        for (text, said) in rows {
            let e = Roles::parse(text).unwrap_err();
            assert!(e.contains(said), "{text:?}: {e}");
        }
    }

    #[test]
    fn an_unknown_role_is_told_and_grants_nothing_and_a_bad_reload_keeps_the_roles() {
        let td = tempfile::tempdir().unwrap();
        let roles = td.path().join("roles.toml");
        let accounts = td.path().join("accounts");
        std::fs::create_dir(&accounts).unwrap();
        write(
            &accounts,
            "al.toml",
            "password = \"pw\"\nroles = [\"ghost\", \"staff\"]\n",
        );
        write(
            td.path(),
            "roles.toml",
            "[role.staff]\naccess = { send_media = true }\n",
        );
        let auth = FileAuth::new(&accounts).with_roles(&roles).unwrap();
        assert!(auth
            .audit()
            .iter()
            .any(|c| c.contains("al.toml: no role \"ghost\"")));
        write(
            td.path(),
            "roles.toml",
            "[role.everyone]\naccess = { read_news = true, disconnect_users = true }\n",
        );
        auth.reload().unwrap();
        let said = auth.audit();
        assert!(
            said.iter()
                .any(|c| c.contains("everyone grants disconnect_users,")),
            "{said:?}"
        );
        write(
            td.path(),
            "roles.toml",
            "[role.staff]\naccess = { send_media = true }\n",
        );
        auth.reload().unwrap();
        let al = auth.lookup("al").unwrap();
        assert_eq!(al.roles, ["ghost", "staff"]);
        assert!(al.access.has(bit::SEND_MEDIA));

        write(
            td.path(),
            "roles.toml",
            "[role.staff]\nkind = \"restriction\"\n",
        );
        assert!(FileAuth::new(&accounts).with_roles(&roles).is_err());
        assert!(auth.reload().is_err());
        assert!(auth.lookup("al").unwrap().access.has(bit::SEND_MEDIA));
        write(td.path(), "roles.toml", "");
        auth.reload().unwrap();
        assert!(!auth.lookup("al").unwrap().access.has(bit::SEND_MEDIA));
    }

    #[test]
    fn a_save_writes_only_where_the_editor_parts_from_the_roles() {
        const ROLES: &str = "[role.r]\naccess = { send_media = true, \
            read_chat_history = true, raw_bits = [58] }\n";
        const HELD: &str = "password = \"pw\"\nroles = [\"r\"]\n[access]\nread_chat = true\n";
        const PLAIN: &str = "password = \"pw\"\n# kept\n[access]\nread_chat = true # mine\n\
            send_chat = true\nraw_bits = [41]\nraw_deny = [42]\n";
        const UNREAD: &str = "password = \"pw\"\nroles = [\"r\"]\n[access]\nread_chat = false\n";
        use bit::{CHAT_HISTORY as HISTORY, READ_CHAT as READ, SEND_MEDIA as MEDIA};
        // The file, the bits the editor flips from what it opened, the
        // highest bit it can show, and the file the save leaves.
        type Row<'a> = (&'a str, &'a [(u8, bool)], Option<u8>, String);
        let rows: &[Row] = &[
            (HELD, &[], Some(40), HELD.into()),
            (HELD, &[], None, HELD.into()),
            (PLAIN, &[], Some(40), PLAIN.into()),
            (
                HELD,
                &[(MEDIA, false)],
                None,
                format!("{HELD}send_media = false\n"),
            ),
            (
                &format!("{HELD}send_media = false\n"),
                &[(MEDIA, true)],
                None,
                HELD.into(),
            ),
            (
                HELD,
                &[(58, false)],
                None,
                format!("{HELD}raw_deny = [58]\n"),
            ),
            (
                &format!("{HELD}raw_deny = [58]\n"),
                &[(58, true)],
                None,
                HELD.into(),
            ),
            // Bit 56 a role gives is the role's on the ng editor too,
            // whatever read-chat does.
            (
                HELD,
                &[(HISTORY, false)],
                None,
                format!("{HELD}read_chat_history = false\n"),
            ),
            (
                &format!("{HELD}read_chat_history = false\n"),
                &[(HISTORY, true)],
                None,
                HELD.into(),
            ),
            (HELD, &[(READ, false)], None, UNREAD.into()),
            (
                HELD,
                &[(READ, false), (HISTORY, false)],
                None,
                format!("{UNREAD}read_chat_history = false\n"),
            ),
        ];
        for (before, flips, tier, after) in rows {
            let td = tempfile::tempdir().unwrap();
            write(td.path(), "roles.toml", ROLES);
            write(td.path(), "al.toml", before);
            let auth = FileAuth::new(td.path())
                .with_roles(td.path().join("roles.toml"))
                .unwrap();
            let mut access = auth.read_account("al").unwrap().access;
            for (b, on) in flips.iter() {
                access = if *on {
                    access.with(*b)
                } else {
                    access.without(*b)
                };
            }
            let edit = AccountEdit {
                login: "al".into(),
                access: Some(access),
                editor_tier: *tier,
                ..Default::default()
            };
            auth.write_account(&edit, &|_, _| Ok(())).unwrap();
            let saved = std::fs::read_to_string(td.path().join("al.toml")).unwrap();
            assert_eq!(&saved, after, "{before:?} with {flips:?}, tier {tier:?}");
            assert_eq!(auth.read_account("al").unwrap().access, access);
        }

        // A save leaves a role's bit the role's, so taking it from the
        // role later takes it from the account.
        let td = tempfile::tempdir().unwrap();
        write(td.path(), "roles.toml", ROLES);
        write(td.path(), "al.toml", HELD);
        let auth = FileAuth::new(td.path())
            .with_roles(td.path().join("roles.toml"))
            .unwrap();
        let edit = AccountEdit {
            login: "al".into(),
            access: Some(auth.read_account("al").unwrap().access),
            ..Default::default()
        };
        auth.write_account(&edit, &|_, _| Ok(())).unwrap();
        write(td.path(), "roles.toml", "");
        auth.reload().unwrap();
        let access = auth.read_account("al").unwrap().access;
        assert!(!access.has(bit::SEND_MEDIA) && !access.has(58));
    }

    #[test]
    fn a_save_keeps_the_bits_above_its_editor_as_the_file_has_them() {
        const ROLES: &str = "[role.r]\naccess = { send_media = true, raw_bits = [58] }\n";
        const FILE: &str = "password = \"pw\"\nroles = [\"r\"]\n[access]\nread_chat = true\n\
            can_broadcast = true\nsend_msgs = true\nvoice_chat = true\nvideo_chat = false\n\
            raw_bits = [41, 61]\nraw_deny = [58]\n";
        let unsent = FILE.replace("send_msgs = true", "send_msgs = false");
        let unraw = FILE.replace("raw_bits = [41, 61]", "raw_bits = [61]");
        // The highest bit the editor shows, a bit it clears, and the file
        // the save leaves. It sends every bit above its tier clear.
        let rows: &[(u8, Option<u8>, &str)] = &[
            (31, None, FILE),
            (40, None, FILE),
            (54, None, FILE),
            (31, Some(bit::SEND_MSGS), FILE),
            (40, Some(bit::SEND_MSGS), &unsent),
            (40, Some(41), FILE),
            (54, Some(41), &unraw),
            (63, Some(bit::SEND_MSGS), &unsent),
        ];
        for (tier, clear, after) in rows {
            let td = tempfile::tempdir().unwrap();
            write(td.path(), "roles.toml", ROLES);
            write(td.path(), "al.toml", FILE);
            let auth = FileAuth::new(td.path())
                .with_roles(td.path().join("roles.toml"))
                .unwrap();
            let opened = auth.read_account("al").unwrap().access;
            let shown = AccessBits::from_raw(opened.raw() & u64::MAX << (63 - tier));
            let edit = AccountEdit {
                login: "al".into(),
                access: Some(clear.map_or(shown, |b| shown.without(b))),
                editor_tier: Some(*tier),
                ..Default::default()
            };
            auth.write_account(&edit, &|_, _| Ok(())).unwrap();
            let saved = std::fs::read_to_string(td.path().join("al.toml")).unwrap();
            assert_eq!(&saved, after, "tier {tier}, clearing {clear:?}");
            let expected = match clear {
                Some(b) if b <= tier => opened.without(*b),
                _ => opened,
            };
            assert_eq!(auth.read_account("al").unwrap().access, expected);
        }
    }

    #[test]
    fn an_account_an_identity_makes_follows_everyone() {
        let (td, _) = backend();
        let elsewhere = tempfile::tempdir().unwrap();
        let roles = elsewhere.path().join("roles.toml");
        std::fs::write(&roles, "[role.everyone]\naccess = { read_news = true }\n").unwrap();
        let auth = FileAuth::new(td.path()).with_roles(roles).unwrap();
        // What the guest account resolves to, `everyone` included.
        let access = AccessBits::empty()
            .with(bit::READ_NEWS)
            .with(bit::SEND_CHAT);
        let (account, created) = auth
            .find_or_create_linked("newbie", "Newbie", &[5u8; 32], access)
            .unwrap();
        assert!(created);
        assert_eq!(account.access, access);
        let file =
            std::fs::read_to_string(td.path().join(format!("{}.toml", account.login))).unwrap();
        assert!(
            file.contains("send_chat = true") && !file.contains("read_news"),
            "{file}"
        );
    }
}
