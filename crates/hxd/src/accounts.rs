//! `hxd account`: the operator's account administration, against the
//! accounts directory directly, so it works with the server down. A
//! running server applies an edit to whoever is logged in as the account
//! on SIGHUP (`Core::reload_accounts`); a new login sees it at once.
//!
//! The operator is above the rule a session is held to: any account may
//! be given anything.

use hxd_auth_file::FileAuth;
use hxd_core::access::{self, bit, AccessBits};
use hxd_core::account::FIELD_MAX_CHARS;
use hxd_core::{Account, AccountAdmin, AccountEdit, AdminError};

use crate::Config;

/// Where a password comes from. Never the command line, where anyone on
/// the machine can read it out of `ps`.
pub enum Password {
    Stdin,
    File(std::path::PathBuf),
    None,
}

impl Password {
    fn read(&self) -> Result<Option<String>, String> {
        let text = match self {
            Password::Stdin => {
                let mut s = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
                    .map_err(|e| format!("--password-stdin: {e}"))?;
                s
            }
            Password::File(path) => {
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?
            }
            Password::None => return Ok(None),
        };
        let password = text.trim_end_matches(['\r', '\n']).to_owned();
        if password.is_empty() {
            return Err("the password is empty".into());
        }
        // A classic login cuts its password there, so a longer one could
        // never be typed on that wire.
        if password.chars().count() > FIELD_MAX_CHARS {
            return Err("a password is at most 31 characters".into());
        }
        Ok(Some(password))
    }
}

fn backend(config: &Config) -> FileAuth {
    match config.system.as_ref() {
        Some(system) => FileAuth::new(&config.paths.accounts).reserving(&system.login),
        None => FileAuth::new(&config.paths.accounts),
    }
}

fn refused(login: &str, e: AdminError) -> String {
    match e {
        AdminError::NoSuchAccount => format!("there is no account {login:?}"),
        AdminError::Exists => format!("{login:?} already exists"),
        AdminError::InvalidLogin => format!(
            "{login:?} is not a login: up to 31 letters, digits and _ - . @, \
             not the server's own"
        ),
        e => format!("{login}: {e}"),
    }
}

/// Access from `key,key` names, refusing a name with no bit.
fn parse_access(list: &str) -> Result<AccessBits, String> {
    list.split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .try_fold(AccessBits::empty(), |a, key| {
            access::named(key)
                .map(|b| a.with(b))
                .ok_or_else(|| format!("no access key {key:?}"))
        })
}

fn describe(a: &Account) -> String {
    let (names, raw) = access::names_of(a.access);
    let mut out = format!(
        "{}\n  name: {}\n  password: {}\n",
        a.login,
        a.name,
        if a.has_password { "set" } else { "none" }
    );
    if let Some(fp) = &a.identity.fingerprint {
        out += &format!("  identity: {}\n", hl_identity::Fingerprint(*fp));
    }
    out += &format!("  access: {}", names.join(" "));
    if !raw.is_empty() {
        out += &format!("\n  raw_bits: {raw:?}");
    }
    out
}

/// `hxd account list`.
pub fn list(config: &Config) -> Result<String, String> {
    let all = backend(config)
        .list_accounts()
        .map_err(|e| refused("", e))?;
    Ok(all
        .iter()
        .map(|a| {
            format!(
                "{:<20} {:<24} {}{}",
                a.login,
                a.name,
                if a.has_password {
                    "password"
                } else {
                    "no password"
                },
                if a.identity.fingerprint.is_some() {
                    ", identity"
                } else {
                    ""
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

/// `hxd account show <login>`.
pub fn show(config: &Config, login: &str) -> Result<String, String> {
    let account = backend(config)
        .read_account(login)
        .map_err(|e| refused(login, e))?;
    Ok(describe(&account))
}

/// `hxd account add <login>`: access from `--access`, else from the
/// account `--like` names, else none.
pub fn add(
    config: &Config,
    login: &str,
    name: Option<String>,
    like: Option<&str>,
    access: Option<&str>,
    password: &Password,
) -> Result<String, String> {
    let auth = backend(config);
    let access = match (access, like) {
        (Some(list), _) => parse_access(list)?,
        (None, Some(like)) => {
            auth.read_account(like)
                .map_err(|e| refused(like, e))?
                .access
        }
        (None, None) => AccessBits::empty(),
    };
    let edit = AccountEdit {
        login: login.to_owned(),
        name,
        password: password.read()?,
        access: Some(access),
        history_unsaid: false,
    };
    let account = auth
        .write_account(&edit, &|existing, _| match existing {
            Some(_) => Err(AdminError::Exists),
            None => Ok(()),
        })
        .map_err(|e| refused(login, e))?;
    Ok(describe(&account))
}

/// What an edit of an account that must already exist checks.
fn exists(existing: Option<&Account>, _: &Account) -> Result<(), AdminError> {
    existing.map(|_| ()).ok_or(AdminError::NoSuchAccount)
}

/// `hxd account passwd <login>`.
pub fn passwd(config: &Config, login: &str, password: &Password) -> Result<String, String> {
    let edit = AccountEdit {
        login: login.to_owned(),
        password: Some(
            password
                .read()?
                .ok_or("say where the password comes from")?,
        ),
        ..Default::default()
    };
    backend(config)
        .write_account(&edit, &exists)
        .map_err(|e| refused(login, e))?;
    Ok(format!(
        "{login}'s password is changed; sessions already logged in keep going"
    ))
}

/// `hxd account access <login> key=on|off…`.
pub fn set_access(config: &Config, login: &str, changes: &[String]) -> Result<String, String> {
    let auth = backend(config);
    let mut access = auth
        .read_account(login)
        .map_err(|e| refused(login, e))?
        .access;
    // History that follows read-chat goes on following it unless this
    // command says otherwise.
    let follows = access.has(bit::CHAT_HISTORY) == access.has(bit::READ_CHAT)
        && !changes.iter().any(|c| c.starts_with("read_chat_history="));
    for change in changes {
        let (key, on) = change
            .split_once('=')
            .and_then(|(k, v)| match v {
                "on" | "true" | "yes" => Some((k, true)),
                "off" | "false" | "no" => Some((k, false)),
                _ => None,
            })
            .ok_or_else(|| format!("{change:?} is not key=on or key=off"))?;
        let b = access::named(key).ok_or_else(|| format!("no access key {key:?}"))?;
        access = if on {
            access.with(b)
        } else {
            access.without(b)
        };
    }
    if follows {
        access = if access.has(bit::READ_CHAT) {
            access.with(bit::CHAT_HISTORY)
        } else {
            access.without(bit::CHAT_HISTORY)
        };
    }
    let edit = AccountEdit {
        login: login.to_owned(),
        access: Some(access),
        ..Default::default()
    };
    let account = auth
        .write_account(&edit, &exists)
        .map_err(|e| refused(login, e))?;
    Ok(describe(&account))
}

/// `hxd account rm <login>`.
pub fn remove(config: &Config, login: &str) -> Result<String, String> {
    backend(config)
        .delete_account(login, &|_| Ok(()))
        .map_err(|e| refused(login, e))?;
    Ok(format!(
        "deleted {login}; `hxd inbox purge {login}` takes its mail and subscriptions too"
    ))
}
