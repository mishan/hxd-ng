//! `hxd account`: the operator's account administration, against the
//! accounts directory directly, so it works with the server down. A
//! running server applies an edit to whoever is logged in as the account
//! on SIGHUP (`Core::reload_accounts`); a new login sees it at once.
//! Commands that set single keys edit the file's own keys, never what
//! its roles give it, so a role's grant is not copied into the file.
//!
//! The operator is above the rule a session is held to: any account may
//! be given anything.

use hxd_auth_file::{edit_listed, FileAuth, EVERYONE};
use hxd_core::access::{self, AccessBits};
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

/// The accounts as the server reads them, its roles included.
pub(crate) fn backend(config: &Config) -> Result<FileAuth, String> {
    let auth = FileAuth::new(&config.paths.accounts).with_roles(&config.roles.file)?;
    Ok(match config.system.as_ref() {
        Some(system) => auth.reserving(&system.login),
        None => auth,
    })
}

/// `key=on` or `key=off`.
pub(crate) fn parse_change(change: &str) -> Result<(&str, bool), String> {
    change
        .split_once('=')
        .and_then(|(k, v)| match v {
            "on" | "true" | "yes" => Some((k, true)),
            "off" | "false" | "no" => Some((k, false)),
            _ => None,
        })
        .ok_or_else(|| format!("{change:?} is not key=on or key=off"))
}

/// Set `key` in `table`, keeping the comment on a value already there.
fn set_key(table: &mut dyn toml_edit::TableLike, key: &str, on: bool) {
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

/// Take bit `b` out of the list of numbers at `key`, and the list with it
/// once empty.
fn drop_number(table: &mut dyn toml_edit::TableLike, key: &str, b: u8) {
    let Some(list) = table.get_mut(key).and_then(|item| item.as_array_mut()) else {
        return;
    };
    list.retain(|v| v.as_integer() != Some(b.into()));
    if list.is_empty() {
        table.remove(key);
    }
}

fn refused(login: &str, e: AdminError) -> String {
    match e {
        AdminError::NoSuchAccount => format!("there is no account {login:?}"),
        AdminError::Exists => format!("{login:?} already exists"),
        AdminError::InvalidLogin => format!(
            "{login:?} is not a login: up to 31 letters, digits and _ - . @, \
             not starting with . or @, not the server's own"
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
    if !a.roles.is_empty() {
        out += &format!("  roles: {}\n", a.roles.join(" "));
    }
    out += &format!("  access: {}", names.join(" "));
    if !raw.is_empty() {
        out += &format!("\n  raw_bits: {raw:?}");
    }
    out
}

/// `hxd account list`.
pub fn list(config: &Config) -> Result<String, String> {
    let all = backend(config)?
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

/// `hxd account show <login>`: the account as it resolves, and the keys
/// its own file sets over its roles.
pub fn show(config: &Config, login: &str) -> Result<String, String> {
    let auth = backend(config)?;
    let account = auth.read_account(login).map_err(|e| refused(login, e))?;
    let mut own = auth.own_keys(login).map_err(|e| refused(login, e))?;
    if own.is_empty() {
        own.push("none".into());
    }
    Ok(format!(
        "{}\n  own keys: {}",
        describe(&account),
        own.join(" ")
    ))
}

/// `hxd account add <login>`: access from `--access`, else the roles
/// and `[access]` keys of the account `--like` names, else what
/// `everyone` gives.
pub fn add(
    config: &Config,
    login: &str,
    name: Option<String>,
    like: Option<&str>,
    access: Option<&str>,
    password: &Password,
) -> Result<String, String> {
    let auth = backend(config)?;
    let template = like
        .map(|like| auth.document(like).map_err(|e| refused(like, e)))
        .transpose()?;
    // With no list, a new account follows `everyone` rather than
    // withholding what it grants.
    let access = access
        .map(parse_access)
        .transpose()?
        .unwrap_or_else(|| auth.roles().granted(&[]));
    let edit = AccountEdit {
        login: login.to_owned(),
        name,
        password: password.read()?,
        access: Some(access),
        ..Default::default()
    };
    let mut account = auth
        .write_account(&edit, &|existing, _| match existing {
            Some(_) => Err(AdminError::Exists),
            None => Ok(()),
        })
        .map_err(|e| refused(login, e))?;
    if let Some(template) = template {
        account = auth
            .edit_account(login, |doc| {
                for key in ["roles", "access"] {
                    if let Some(item) = template.get(key) {
                        doc[key] = item.clone();
                    }
                }
                Ok(())
            })
            .map_err(|e| refused(login, e))?;
    }
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
    backend(config)?
        .write_account(&edit, &exists)
        .map_err(|e| refused(login, e))?;
    Ok(format!(
        "{login}'s password is changed; sessions already logged in keep going"
    ))
}

/// `hxd account access <login> key=on|off…`: each key set in the file,
/// where `off` withholds what a role grants. Turning off a bit nothing
/// gives the account writes nothing.
pub fn set_access(config: &Config, login: &str, changes: &[String]) -> Result<String, String> {
    let auth = backend(config)?;
    let changes = changes
        .iter()
        .map(|c| {
            let (key, on) = parse_change(c)?;
            let b = access::named(key).ok_or_else(|| format!("no access key {key:?}"))?;
            Ok((key, b, on))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let had = auth
        .read_account(login)
        .map_err(|e| refused(login, e))?
        .access;
    let account = auth
        .edit_account(login, |doc| {
            let table = doc["access"]
                .or_insert(toml_edit::Item::Table(toml_edit::Table::new()))
                .as_table_like_mut()
                .ok_or("access is not a table")?;
            if changes
                .iter()
                .any(|(_, b, _)| *b == access::bit::CHAT_HISTORY)
            {
                if let Some(old) = table.remove("chat_history") {
                    if !table.contains_key("read_chat_history") {
                        table.insert("read_chat_history", old);
                    }
                }
            }
            for (key, b, on) in &changes {
                // A number would outvote the name: `raw_bits` is applied
                // after the named keys, and `raw_deny` after that.
                for list in ["raw_bits", "raw_deny"] {
                    drop_number(table, list, *b);
                }
                if *on || table.contains_key(key) || had.has(*b) {
                    set_key(table, key, *on);
                }
            }
            Ok(())
        })
        .map_err(|e| refused(login, e))?;
    Ok(describe(&account))
}

/// `hxd account roles <login> [+role|-role…]`: with no changes, the roles
/// the account lists.
pub fn set_roles(config: &Config, login: &str, changes: &[String]) -> Result<String, String> {
    let auth = backend(config)?;
    let roles = auth.roles();
    let mut edits = Vec::new();
    for change in changes {
        match (change.get(..1), change.get(1..)) {
            (Some("+"), Some(EVERYONE)) => {
                return Err(format!("every account holds {EVERYONE} already"))
            }
            (Some("+"), Some(name)) if roles.get(name).is_none() => {
                return Err(format!("there is no role {name:?}"))
            }
            (Some(sign @ ("+" | "-")), Some(name)) => edits.push((sign == "+", name)),
            _ => return Err(format!("{change:?} is not +role or -role")),
        }
    }
    let account = if edits.is_empty() {
        auth.read_account(login)
    } else {
        auth.edit_account(login, |doc| {
            edit_listed(doc, |listed| {
                for (add, name) in edits {
                    if !add {
                        listed.retain(|n| n != name);
                    } else if !listed.iter().any(|n| n == name) {
                        listed.push(name.to_owned());
                    }
                }
            });
            Ok(())
        })
    }
    .map_err(|e| refused(login, e))?;
    Ok(describe(&account))
}

/// `hxd account rm <login>`.
pub fn remove(config: &Config, login: &str) -> Result<String, String> {
    let auth = backend(config)?;
    // Read first: once the file is gone, nothing says which identity's
    // mail, subscriptions and devices were the account's.
    let account = auth.read_account(login).map_err(|e| refused(login, e))?;
    auth.delete_account(login, &|_| Ok(()))
        .map_err(|e| refused(login, e))?;
    let purge = match account.identity.fingerprint {
        Some(fp) => format!(
            "hxd inbox purge {} --fingerprint {}",
            account.login,
            hl_identity::Fingerprint(fp)
        ),
        None => format!("hxd inbox purge {}", account.login),
    };
    Ok(format!(
        "deleted {}; `{purge}` takes its mail and subscriptions too",
        account.login
    ))
}
