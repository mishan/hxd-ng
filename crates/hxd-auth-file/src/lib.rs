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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hxd_core::access::{bit, AccessBits};
use hxd_core::{Account, AuthBackend, AuthError, IdentityLink, Proof};
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
        let want = hl_identity::Fingerprint(*fingerprint).to_string();
        for login in self.logins()? {
            let file = match self.load(&login) {
                Ok(f) => f,
                Err(AuthError::NoSuchAccount) => continue,
                Err(e) => return Err(e),
            };
            // Compare the stored text form (case-folded) before parsing:
            // an unparseable value in some other account file shouldn't
            // break lookups for everyone.
            if file
                .identity
                .fingerprint
                .as_deref()
                .is_some_and(|f| f.eq_ignore_ascii_case(&want))
            {
                let path = self.dir.join(format!("{login}.toml"));
                return Ok(Some(file.into_account(login, &path)));
            }
        }
        Ok(None)
    }

    fn set_identity_link(
        &self,
        login: &str,
        fingerprint: Option<[u8; 32]>,
    ) -> Result<(), AuthError> {
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
                if let Some(table) = doc.get_mut("identity").and_then(|i| i.as_table_mut()) {
                    table.remove("fingerprint");
                }
            }
        }
        write_atomic(&path, &doc.to_string())
            .map_err(|e| AuthError::Backend(format!("{}: {e}", path.display())))
    }

    fn create_linked(
        &self,
        login: &str,
        name: &str,
        fingerprint: [u8; 32],
        access: AccessBits,
    ) -> Result<Account, AuthError> {
        let base: String = login
            .to_ascii_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .take(24)
            .collect();
        let base = base.trim_start_matches(['.', '-']).to_owned();
        let base = if base.is_empty() {
            format!("id-{}", &hl_identity::Fingerprint(fingerprint).short())
        } else {
            base
        };
        // First free of base, base-2, base-3, …
        let mut candidate = base.clone();
        let mut n = 1;
        loop {
            if !self.dir.join(format!("{candidate}.toml")).exists() {
                break;
            }
            n += 1;
            if n > 1000 {
                return Err(AuthError::Backend(format!("no free login for {base}")));
            }
            candidate = format!("{base}-{n}");
        }
        let mut doc = toml_edit::DocumentMut::new();
        doc["name"] = toml_edit::value(name);
        let mut acc = toml_edit::Table::new();
        for (key, b) in NAMED_BITS {
            if access.has(*b) {
                acc[key] = toml_edit::value(true);
            }
        }
        doc["access"] = toml_edit::Item::Table(acc);
        let mut id = toml_edit::Table::new();
        id["fingerprint"] = toml_edit::value(hl_identity::Fingerprint(fingerprint).to_string());
        doc["identity"] = toml_edit::Item::Table(id);
        doc.decor_mut()
            .set_prefix("# Created by identity login (new_accounts = create).\n");
        let path = self.dir.join(format!("{candidate}.toml"));
        write_new(&path, &doc.to_string())
            .map_err(|e| AuthError::Backend(format!("{}: {e}", path.display())))?;
        self.lookup(&candidate)
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
    fn logins(&self) -> Result<Vec<String>, AuthError> {
        let rd = std::fs::read_dir(&self.dir)
            .map_err(|e| AuthError::Backend(format!("{}: {e}", self.dir.display())))?;
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| AuthError::Backend(e.to_string()))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(login) = name.strip_suffix(".toml") {
                if valid_login(login) {
                    out.push(login.to_owned());
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Write via a temp file and rename, so a crash mid-write can't leave a
/// half-written account file.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

fn write_new(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(text.as_bytes())
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
        auth.set_identity_link("misha", Some(fp)).unwrap();
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
        // Unlink removes only the fingerprint.
        auth.set_identity_link("misha", None).unwrap();
        let text = std::fs::read_to_string(td.path().join("misha.toml")).unwrap();
        assert!(!text.contains("fingerprint"), "{text}");
        assert!(auth.find_by_fingerprint(&fp).unwrap().is_none());
        assert_eq!(
            auth.set_identity_link("nobody", Some(fp)).unwrap_err(),
            AuthError::NoSuchAccount
        );
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
    fn create_linked_picks_a_free_login() {
        let (td, auth) = backend();
        write(td.path(), "misha.toml", "name = \"Misha\"\n");
        let fp = [7u8; 32];
        let access = AccessBits::empty()
            .with(bit::READ_CHAT)
            .with(bit::SEND_CHAT);
        let a = auth.create_linked("misha", "Misha", fp, access).unwrap();
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
        // Hostile proposals are sanitised.
        let b = auth
            .create_linked("../../etc", "x", [8u8; 32], AccessBits::empty())
            .unwrap();
        assert_eq!(b.login, "etc");
        let c = auth
            .create_linked("", "x", [9u8; 32], AccessBits::empty())
            .unwrap();
        assert!(c.login.starts_with("id-"), "{}", c.login);
    }
}
