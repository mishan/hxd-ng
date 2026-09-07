//! Flat-file account backend: one TOML file per account in an accounts
//! directory. Human-editable by design — unlike hxd's binary `UserData`
//! format. (An importer for hxd/mhxd account trees is future work; see
//! ROADMAP.md.)
//!
//! ```toml
//! # accounts/misha.toml
//! name = "Misha"
//! password = "secret"     # omit or leave empty for password-less accounts
//!
//! [access]
//! use_any_name = true
//! send_msgs = true
//! read_users = true
//! # any named bit below; plus raw_bits = [55] as an escape hatch
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
use std::sync::Mutex;
use std::time::SystemTime;

use hxd_core::access::{bit, AccessBits};
use hxd_core::{Account, AuthBackend, AuthError, IdentityLink, LinkOutcome, Proof, UnlinkOutcome};
use serde::Deserialize;

/// Named access keys, mapped to protocol bit numbers. Names mirror
/// `hxd_core::access::bit` (and therefore mhxd's field names).
const NAMED_BITS: &[(&str, u8)] = &[
    ("delete_files", bit::DELETE_FILES),
    ("upload_files", bit::UPLOAD_FILES),
    ("download_files", bit::DOWNLOAD_FILES),
    ("rename_files", bit::RENAME_FILES),
    ("move_files", bit::MOVE_FILES),
    ("create_folders", bit::CREATE_FOLDERS),
    ("delete_folders", bit::DELETE_FOLDERS),
    ("rename_folders", bit::RENAME_FOLDERS),
    ("move_folders", bit::MOVE_FOLDERS),
    ("read_chat", bit::READ_CHAT),
    ("send_chat", bit::SEND_CHAT),
    ("create_pchats", bit::CREATE_PCHATS),
    ("create_users", bit::CREATE_USERS),
    ("delete_users", bit::DELETE_USERS),
    ("read_users", bit::READ_USERS),
    ("modify_users", bit::MODIFY_USERS),
    ("read_news", bit::READ_NEWS),
    ("post_news", bit::POST_NEWS),
    ("disconnect_users", bit::DISCONNECT_USERS),
    ("cant_be_disconnected", bit::CANT_BE_DISCONNECTED),
    ("get_user_info", bit::GET_USER_INFO),
    ("upload_anywhere", bit::UPLOAD_ANYWHERE),
    ("use_any_name", bit::USE_ANY_NAME),
    ("dont_show_agreement", bit::DONT_SHOW_AGREEMENT),
    ("comment_files", bit::COMMENT_FILES),
    ("comment_folders", bit::COMMENT_FOLDERS),
    ("view_drop_boxes", bit::VIEW_DROP_BOXES),
    ("make_aliases", bit::MAKE_ALIASES),
    ("can_broadcast", bit::CAN_BROADCAST),
    ("delete_articles", bit::DELETE_ARTICLES),
    ("create_categories", bit::CREATE_CATEGORIES),
    ("delete_categories", bit::DELETE_CATEGORIES),
    ("create_news_bundles", bit::CREATE_NEWS_BUNDLES),
    ("delete_news_bundles", bit::DELETE_NEWS_BUNDLES),
    ("upload_folders", bit::UPLOAD_FOLDERS),
    ("download_folders", bit::DOWNLOAD_FOLDERS),
    ("send_msgs", bit::SEND_MSGS),
    ("voice_chat", bit::VOICE_CHAT),
    ("chat_history", bit::CHAT_HISTORY),
    ("video_chat", bit::VIDEO_CHAT),
    // Off for guests by default, per the video spec: a screen share can
    // leak documents, credentials and other people's messages in a way a
    // camera generally cannot. Bootstrap's guest account grants neither.
    ("screen_share", bit::SCREEN_SHARE),
];

/// The bit an account file's access key names, if any. Exposed so the
/// binary can validate `[identity.default_access]` against the same
/// table an account file is read with, rather than a second copy of it.
pub fn named_bit(key: &str) -> Option<u8> {
    NAMED_BITS.iter().find(|(n, _)| *n == key).map(|(_, b)| *b)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFile {
    /// Display name; defaults to the login.
    name: Option<String>,
    /// Plaintext-equivalent secret; omit/empty = password-less.
    password: Option<String>,
    #[serde(default)]
    access: AccessTable,
    /// Server-local policy that never crosses the wire (mhxd's
    /// `access_extra` concept). Absent keys fall back to derived defaults
    /// — see `authenticate`.
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
}

#[derive(Debug, Default, Deserialize)]
struct AccessTable {
    /// Escape hatch for bits without a name (reserved / future).
    #[serde(default)]
    raw_bits: Vec<u8>,
    /// Named bits — collected loosely so a typo is a startup-log warning,
    /// not a silently ignored key.
    #[serde(flatten)]
    named: BTreeMap<String, bool>,
}

impl AccountFile {
    /// Everything but the password check: shared by `authenticate` and
    /// `lookup`.
    fn into_account(self, login: String, path: &Path) -> Account {
        let access = self.access_bits(path);
        let stored = self.password.as_deref().unwrap_or("");
        let has_password = !stored.is_empty();
        let fingerprint = self.identity.fingerprint.as_deref().and_then(|f| {
            let parsed = hl_identity::Fingerprint::parse(f);
            if parsed.is_none() {
                tracing::warn!(
                    "{}: identity.fingerprint is not a valid fingerprint; ignored",
                    path.display()
                );
            }
            parsed.map(|fp| fp.0)
        });
        Account {
            name: self.name.clone().unwrap_or_else(|| login.clone()),
            // A password makes an account a person rather than a door,
            // and so does a linked identity: accounts made by
            // `new_accounts = create` have no password and are still
            // exactly one person's.
            can_detach: self
                .extra
                .can_detach
                .unwrap_or(has_password || fingerprint.is_some()),
            set_subject: self
                .extra
                .set_subject
                .unwrap_or_else(|| access.has(bit::DISCONNECT_USERS)),
            has_password,
            identity: IdentityLink {
                fingerprint,
                identity_login: self.identity.login.unwrap_or(true),
                allow_self_link: self.identity.allow_self_link.unwrap_or(true),
                reserve_name: self.identity.reserve_name.unwrap_or(false),
            },
            access,
            login,
        }
    }

    fn access_bits(&self, source: &Path) -> AccessBits {
        let mut acc = AccessBits::empty();
        for (key, on) in &self.access.named {
            match NAMED_BITS.iter().find(|(n, _)| n == key) {
                Some((_, b)) if *on => acc = acc.with(*b),
                Some(_) => {}
                None => tracing::warn!(
                    "{}: unknown access key {key:?} ignored (see hxd-auth-file docs)",
                    source.display()
                ),
            }
        }
        for b in &self.access.raw_bits {
            acc = acc.with(*b);
        }
        acc
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
        }
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
             send_chat = true\n\
             create_pchats = true\n\
             send_msgs = true\n\
             get_user_info = true\n\
             use_any_name = true\n",
        )?;
        Ok(())
    }

    fn load(&self, login: &str) -> Result<AccountFile, AuthError> {
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
        }
        let path = self.dir.join(format!("{login}.toml"));
        Ok(file.into_account(login, &path))
    }

    fn lookup(&self, login: &str) -> Result<Account, AuthError> {
        let login = if login.is_empty() { "guest" } else { login };
        let login = login.to_ascii_lowercase();
        if !valid_login(&login) {
            return Err(AuthError::NoSuchAccount);
        }
        let file = self.load(&login)?;
        let path = self.dir.join(format!("{login}.toml"));
        Ok(file.into_account(login, &path))
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
        if account.identity.fingerprint.is_some() || !account.identity.allow_self_link {
            return Ok(LinkOutcome::Refused(account));
        }
        if let Some(other) = self.find_by_fingerprint(fingerprint)? {
            return Ok(LinkOutcome::Taken(other));
        }
        self.write_link(&account.login, Some(*fingerprint))?;
        Ok(LinkOutcome::Linked(self.lookup(&account.login)?))
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
        let mut acc = toml_edit::Table::new();
        for (key, b) in NAMED_BITS {
            if access.has(*b) {
                acc[key] = toml_edit::value(true);
            }
        }
        // Whatever is set and has no name goes to `raw_bits`, the same
        // escape hatch a hand-written file uses. Writing only the named
        // ones silently dropped every reserved or future allocation —
        // and the template these accounts are created from is usually
        // the guest account, which is exactly where an operator puts a
        // `raw_bits` entry for a bit this build has no name for yet.
        let unnamed: Vec<u8> = (0..64)
            .filter(|b| access.has(*b) && !NAMED_BITS.iter().any(|(_, n)| n == b))
            .collect();
        if !unnamed.is_empty() {
            let mut arr = toml_edit::Array::new();
            for b in unnamed {
                arr.push(i64::from(b));
            }
            acc["raw_bits"] = toml_edit::value(arr);
        }
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
        index.retain(|login, _| entries.iter().any(|(l, _)| l == login));
        let mut found = None;
        for (login, stamp) in entries {
            let fresh = index.get(&login).is_some_and(|(s, _)| *s == stamp);
            if !fresh {
                let fp = match self.load(&login) {
                    Ok(f) => f.identity.fingerprint,
                    Err(AuthError::NoSuchAccount) => continue,
                    // One malformed account file used to make every
                    // identity auth on the server a 500. Skip it, loudly.
                    Err(e) => {
                        tracing::warn!("{login}.toml: {e}; skipped in fingerprint lookup");
                        index.insert(login, (stamp, None));
                        continue;
                    }
                };
                index.insert(login.clone(), (stamp, fp));
            }
            if found.is_none()
                && index
                    .get(&login)
                    .and_then(|(_, fp)| fp.as_deref())
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
    use std::io::Write;
    let tmp = path.with_extension("toml.tmp");
    let mode = std::fs::metadata(path).ok().map(file_mode);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        private_opts(&mut opts);
        let mut f = opts.open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    // Keep whatever the operator set on the original.
    if let Some(mode) = mode {
        set_file_mode(&tmp, mode)?;
    }
    std::fs::rename(&tmp, path)?;
    // The rename itself is only durable once the directory is synced.
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
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

fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    private_opts(&mut opts);
    let mut f = opts.open(path)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()
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
            "misha.toml",
            "name = \"Misha\"\npassword = \"s3cret\"\n[access]\nuse_any_name = true\ndisconnect_users = true\n",
        );
        let acct = auth.authenticate("misha", Proof::Plain(b"s3cret")).unwrap();
        assert_eq!(acct.name, "Misha");
        assert!(acct.access.has(bit::USE_ANY_NAME));
        assert!(acct.access.has(bit::DISCONNECT_USERS));
        assert!(!acct.access.has(bit::DELETE_FILES));
    }

    #[test]
    fn wrong_password_and_missing_account_are_distinct() {
        let (td, auth) = backend();
        write(td.path(), "misha.toml", "password = \"x\"\n");
        assert_eq!(
            auth.authenticate("misha", Proof::Plain(b"y")).unwrap_err(),
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
        write(td.path(), "misha.toml", "");
        assert_eq!(
            auth.authenticate("MiSha", Proof::Plain(b"")).unwrap().login,
            "misha"
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
        // Passworded admin: both derived on.
        write(
            td.path(),
            "root.toml",
            "password = \"pw\"\n[access]\ndisconnect_users = true\n",
        );
        let r = auth.authenticate("root", Proof::Plain(b"pw")).unwrap();
        assert!(r.can_detach);
        assert!(r.set_subject);
        // Explicit overrides beat the derivation, both directions.
        write(
            td.path(),
            "kiosk.toml",
            "[extra]\ncan_detach = true\nset_subject = true\n",
        );
        let k = auth.authenticate("kiosk", Proof::Plain(b"")).unwrap();
        assert!(k.can_detach && k.set_subject);
        write(
            td.path(),
            "probation.toml",
            "password = \"pw\"\n[extra]\ncan_detach = false\n",
        );
        let p = auth.authenticate("probation", Proof::Plain(b"pw")).unwrap();
        assert!(!p.can_detach);
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
        // Never overwrites an existing dir.
        std::fs::remove_file(sub.join("guest.toml")).unwrap();
        FileAuth::bootstrap(&sub).unwrap();
        assert!(!sub.join("guest.toml").exists());
    }

    #[test]
    fn identity_link_round_trip_preserves_comments() {
        let (td, auth) = backend();
        write(
            td.path(),
            "misha.toml",
            "# Misha's account\nname = \"Misha\"\npassword = \"pw\" # keep\n\n[access]\nsend_chat = true\n",
        );
        let fp = [0xabu8; 32];
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        assert!(matches!(
            auth.link_identity("misha", &fp).unwrap(),
            LinkOutcome::Linked(_)
        ));
        let text = std::fs::read_to_string(td.path().join("misha.toml")).unwrap();
        assert!(text.starts_with("# Misha's account\n"), "{text}");
        assert!(text.contains("password = \"pw\" # keep"), "{text}");
        assert!(text.contains("[identity]"), "{text}");
        let a = auth.find_by_fingerprint(&fp).unwrap().unwrap();
        assert_eq!(a.login, "misha");
        assert_eq!(a.identity.fingerprint, Some(fp));
        assert!(
            a.identity.identity_login && a.identity.allow_self_link && !a.identity.reserve_name
        );
        assert!(a.has_password);
        // lookup() agrees and needs no password.
        assert_eq!(auth.lookup("Misha").unwrap().identity.fingerprint, Some(fp));
        // Linking again is a no-op, not an error.
        assert!(matches!(
            auth.link_identity("misha", &fp).unwrap(),
            LinkOutcome::Already(_)
        ));
        // Unlink removes only the fingerprint.
        assert!(matches!(
            auth.unlink_identity(&fp).unwrap(),
            UnlinkOutcome::Unlinked(_)
        ));
        let text = std::fs::read_to_string(td.path().join("misha.toml")).unwrap();
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
        write(td.path(), "misha.toml", &text);
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "misha"
        );
        assert!(matches!(
            auth.unlink_identity(&fp).unwrap(),
            UnlinkOutcome::Unlinked(_)
        ));
        let text = std::fs::read_to_string(td.path().join("misha.toml")).unwrap();
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
        write(td.path(), "misha.toml", "password = \"pw\"\n");
        write(td.path(), "other.toml", "password = \"pw\"\n");
        write(
            td.path(),
            "closed.toml",
            "password = \"pw\"\n[identity]\nallow_self_link = false\n",
        );
        let fp = [1u8; 32];
        assert!(matches!(
            auth.link_identity("misha", &fp).unwrap(),
            LinkOutcome::Linked(_)
        ));
        match auth.link_identity("other", &fp).unwrap() {
            LinkOutcome::Taken(a) => assert_eq!(a.login, "misha"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            auth.link_identity("closed", &[2u8; 32]).unwrap(),
            LinkOutcome::Refused(_)
        ));
        // An account that already links someone else refuses too.
        assert!(matches!(
            auth.link_identity("misha", &[2u8; 32]).unwrap(),
            LinkOutcome::Refused(_)
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
            "misha.toml",
            &format!(
                "[identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "misha"
        );
    }

    #[test]
    fn the_fingerprint_index_notices_an_edited_file() {
        let (td, auth) = backend();
        let fp = [8u8; 32];
        write(td.path(), "misha.toml", "password = \"pw\"\n");
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        // A hand edit, not one of ours. Sleep past the mtime granularity
        // some filesystems have; the length changes too, which is the
        // other half of the stamp.
        std::thread::sleep(std::time::Duration::from_millis(10));
        write(
            td.path(),
            "misha.toml",
            &format!(
                "password = \"pw\"\n[identity]\nfingerprint = \"{}\"\n",
                hl_identity::Fingerprint(fp)
            ),
        );
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "misha"
        );
        // And a deleted account leaves the index.
        std::fs::remove_file(td.path().join("misha.toml")).unwrap();
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn written_account_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (td, auth) = backend();
        let a = auth
            .find_or_create_linked("misha", "Misha", &[9u8; 32], AccessBits::empty())
            .unwrap()
            .0;
        let mode = std::fs::metadata(td.path().join(format!("{}.toml", a.login)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "account files hold secrets");
        // And a rewrite keeps whatever the operator set.
        std::fs::set_permissions(
            td.path().join("misha.toml"),
            std::fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        auth.link_identity("misha", &[10u8; 32]).unwrap();
        let mode = std::fs::metadata(td.path().join("misha.toml"))
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
            "misha.toml",
            "[identity]\nfingerprint = \"junk\"\nlogin = false\nallow_self_link = false\nreserve_name = true\n",
        );
        let a = auth.lookup("misha").unwrap();
        assert_eq!(
            a.identity.fingerprint, None,
            "unparseable fingerprint is ignored, not fatal"
        );
        assert!(
            !a.identity.identity_login && !a.identity.allow_self_link && a.identity.reserve_name
        );
        assert_eq!(auth.reserved_by("MISHA").unwrap(), Some("misha".into()));
        assert_eq!(auth.reserved_by("guest").unwrap(), None);
        assert_eq!(auth.reserved_by("../misha").unwrap(), None);
    }

    #[test]
    fn a_created_account_keeps_bits_this_build_has_no_name_for() {
        // The guest account is the usual template, and `raw_bits` is
        // where an operator puts an allocation this build predates —
        // the messaging extension's access bit 58, for one. Emitting
        // only `NAMED_BITS` dropped them on the floor.
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
    fn create_linked_picks_a_free_login() {
        let (td, auth) = backend();
        write(td.path(), "misha.toml", "name = \"Misha\"\n");
        let fp = [7u8; 32];
        let access = AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT);
        let (a, created) = auth
            .find_or_create_linked("misha", "Misha", &fp, access)
            .unwrap();
        assert!(created);
        assert_eq!(a.login, "misha-2");
        assert_eq!(a.name, "Misha");
        assert_eq!(a.identity.fingerprint, Some(fp));
        assert!(!a.has_password);
        assert!(
            a.can_detach,
            "a linked, password-less account is still a person"
        );
        assert!(a.access.has(bit::SEND_CHAT) && !a.access.has(bit::DELETE_FILES));
        assert_eq!(
            auth.find_by_fingerprint(&fp).unwrap().unwrap().login,
            "misha-2"
        );
        // Called again for the same identity it finds, never creates.
        let (again, created) = auth
            .find_or_create_linked("misha", "Misha", &fp, access)
            .unwrap();
        assert!(!created);
        assert_eq!(again.login, "misha-2");
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
}
