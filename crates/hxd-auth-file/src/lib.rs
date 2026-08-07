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
//! ```
//!
//! The password is a plaintext-equivalent secret — a legacy-wire
//! constraint, not an oversight; see `hxd_core::account`'s module docs.
//! Keep the accounts directory readable by the server user only.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hxd_core::access::{bit, AccessBits};
use hxd_core::{Account, AuthBackend, AuthError, Proof};
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
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountFile {
    /// Display name; defaults to the login.
    name: Option<String>,
    /// Plaintext-equivalent secret; omit/empty = password-less.
    password: Option<String>,
    #[serde(default)]
    access: AccessTable,
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
}

impl FileAuth {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        FileAuth { dir: dir.into() }
    }

    /// Create the accounts directory and a default guest account if the
    /// directory doesn't exist yet. First-run convenience; never overwrites.
    pub fn bootstrap(dir: &Path) -> std::io::Result<()> {
        if dir.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(dir)?;
        std::fs::write(
            dir.join("guest.toml"),
            "# Default guest account, created on first run. Delete this file\n\
             # to disable guest logins.\n\
             name = \"guest\"\n\n\
             [access]\n\
             read_chat = true\n\
             send_chat = true\n\
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
        match proof {
            Proof::Plain(given) => {
                if !constant_time_eq(stored.as_bytes(), given) {
                    return Err(AuthError::BadProof);
                }
            }
        }
        let path = self.dir.join(format!("{login}.toml"));
        Ok(Account {
            name: file.name.clone().unwrap_or_else(|| login.clone()),
            access: file.access_bits(&path),
            login,
        })
    }
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
}
