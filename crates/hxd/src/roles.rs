//! `hxd role`: the operator's roles (`docs/roles.md` §13), against the
//! roles file directly, so it works with the server down. A running
//! server reads the file again on SIGHUP, with the accounts, and every
//! session is told what its account now resolves to.

use hxd_auth_file::roles::{self, role_table, roles_table, valid_name};
use hxd_auth_file::{edit_listed, named_bit, Role, Roles, EVERYONE};
use hxd_core::access;
use hxd_core::AccountAdmin;

use crate::accounts::{backend, parse_change};
use crate::Config;

fn load(config: &Config) -> Result<Roles, String> {
    Roles::load(&config.roles.file)
}

/// Turn each `key=on|off` of `changes` in role `name`'s `table` (`access`
/// or `extra`) on or off. Off removes the key: a role only grants.
fn set_keys(
    config: &Config,
    name: &str,
    table: &str,
    changes: &[String],
    check: impl Fn(&str) -> Result<(), String>,
) -> Result<String, String> {
    let changes = changes
        .iter()
        .map(|c| parse_change(c).and_then(|(key, on)| check(key).map(|()| (key, on))))
        .collect::<Result<Vec<_>, String>>()?;
    let roles = roles::edit(&config.roles.file, |doc| {
        let role = role_table(doc, name)?;
        let keys = role
            .entry(table)
            .or_insert(toml_edit::value(toml_edit::InlineTable::new()))
            .as_table_like_mut()
            .ok_or_else(|| format!("{table} is not a table"))?;
        for (key, on) in &changes {
            if *on {
                keys.insert(key, toml_edit::value(true));
            } else {
                keys.remove(key);
            }
        }
        if keys.is_empty() {
            role.remove(table);
        }
        Ok(())
    })?;
    describe(config, roles.get(name).ok_or("the role is gone")?)
}

fn describe(config: &Config, role: &Role) -> Result<String, String> {
    let (names, raw) = access::names_of(role.access);
    let mut out = format!("{}\n  title: {}\n", role.name, role.title);
    if let Some(color) = role.color {
        out += &format!("  color: 0x{color:06x}\n");
    }
    out += &format!(
        "  position: {}\n  mentionable: {}\n  access: {}\n",
        role.position,
        role.mentionable,
        names.join(" ")
    );
    if !raw.is_empty() {
        out += &format!("  raw_bits: {raw:?}\n");
    }
    out += &format!("  extra: {}\n", role.extra_names().join(" "));
    if role.name == EVERYONE {
        out += "  held by: every account";
    } else {
        let holders: Vec<String> = backend(config)?
            .list_accounts()
            .map_err(|e| e.to_string())?
            .into_iter()
            .filter(|a| a.roles.contains(&role.name))
            .map(|a| a.login)
            .collect();
        out += &format!("  held by: {}", holders.join(" "));
    }
    Ok(out)
}

/// `hxd role list`: highest position first, as clients order them.
pub fn list(config: &Config) -> Result<String, String> {
    let roles = load(config)?;
    let mut all: Vec<&Role> = roles.iter().collect();
    all.sort_by(|a, b| b.position.cmp(&a.position).then(a.name.cmp(&b.name)));
    Ok(all
        .iter()
        .map(|r| format!("{:<30} {:<31} {}", r.name, r.title, r.position))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// `hxd role show <name>`.
pub fn show(config: &Config, name: &str) -> Result<String, String> {
    let roles = load(config)?;
    describe(
        config,
        roles
            .get(name)
            .ok_or_else(|| format!("there is no role {name:?}"))?,
    )
}

/// A color as `0xRRGGBB` or `#RRGGBB`.
fn parse_color(text: &str) -> Result<u32, String> {
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix('#'))
        .unwrap_or(text);
    (hex.len() == 6)
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
        .ok_or_else(|| format!("{text:?} is not a color: 0xRRGGBB"))
}

/// `hxd role add <name> [--title T] [--color 0xRRGGBB] [--position N]
/// [--access KEY,…]`.
pub fn add(
    config: &Config,
    name: &str,
    title: Option<&str>,
    color: Option<&str>,
    position: Option<i64>,
    access: Option<&str>,
) -> Result<String, String> {
    if name == EVERYONE {
        return Err(format!(
            "{EVERYONE} always exists; give it access with `hxd role access {EVERYONE} KEY=on`"
        ));
    }
    if !valid_name(name) {
        return Err(format!(
            "{name:?} is not a role name: 1 to 30 lowercase letters, digits, - and _, \
             starting with a letter or digit"
        ));
    }
    let color = color.map(parse_color).transpose()?;
    let keys = access
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|key| {
            named_bit(key)
                .map(|_| key)
                .ok_or_else(|| format!("no access key {key:?}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let roles = roles::edit(&config.roles.file, |doc| {
        let table = roles_table(doc)?;
        if table.contains_key(name) {
            return Err(format!("there is a role {name:?} already"));
        }
        let mut role = toml_edit::Table::new();
        if let Some(title) = title {
            role["title"] = toml_edit::value(title);
        }
        if let Some(color) = color {
            let hex: toml_edit::Value = format!("0x{color:06x}")
                .parse()
                .map_err(|e| format!("{e}"))?;
            role["color"] = toml_edit::value(hex);
        }
        if let Some(position) = position {
            role["position"] = toml_edit::value(position);
        }
        if !keys.is_empty() {
            let mut grants = toml_edit::InlineTable::new();
            for key in &keys {
                grants.insert(*key, true.into());
            }
            role["access"] = toml_edit::value(grants);
        }
        table.insert(name, toml_edit::Item::Table(role));
        Ok(())
    })?;
    describe(config, roles.get(name).ok_or("the role is gone")?)
}

/// `hxd role access <name> KEY=on|off…`.
pub fn set_access(config: &Config, name: &str, changes: &[String]) -> Result<String, String> {
    set_keys(config, name, "access", changes, |key| {
        named_bit(key)
            .map(|_| ())
            .ok_or_else(|| format!("no access key {key:?}"))
    })
}

/// `hxd role extra <name> KEY=on|off…`: only the keys a role may grant.
pub fn set_extra(config: &Config, name: &str, changes: &[String]) -> Result<String, String> {
    set_keys(config, name, "extra", changes, |key| {
        if roles::EXTRA_KEYS.contains(&key) {
            Ok(())
        } else {
            Err(format!(
                "a role grants only the [extra] keys {}",
                roles::EXTRA_KEYS.join(", ")
            ))
        }
    })
}

/// `hxd role rm <name>`: taken out of every account file listing it
/// first, so that a removal cut short can be run again.
pub fn remove(config: &Config, name: &str) -> Result<String, String> {
    if name == EVERYONE {
        return Err(format!("{EVERYONE} cannot be removed; it is every account"));
    }
    if load(config)?.get(name).is_none() {
        return Err(format!("there is no role {name:?}"));
    }
    let auth = backend(config)?;
    let mut held = 0;
    for login in auth.logins() {
        let account = match auth.read_account(&login) {
            Ok(account) => account,
            Err(hxd_core::AdminError::NoSuchAccount) => continue,
            // Said, so a file that cannot be read is not left holding the
            // name unnoticed.
            Err(e) => {
                tracing::warn!("{login}.toml: {e}; not read, so not checked for {name}");
                continue;
            }
        };
        if account.roles.iter().any(|n| n == name) {
            auth.edit_account(&account.login, |doc| {
                edit_listed(doc, |listed| listed.retain(|n| n != name));
                Ok(())
            })
            .map_err(|e| format!("{}: {e}", account.login))?;
            held += 1;
        }
    }
    roles::edit(&config.roles.file, |doc| {
        roles_table(doc)?.remove(name);
        Ok(())
    })?;
    Ok(format!(
        "deleted role {name}; {held} accounts listed it and no longer do"
    ))
}

/// A `roles_changed` held back so as not to follow another too closely
/// goes once it may (`hxd_core::admin::ROLES_CHANGED_EVERY`).
pub async fn roles_flusher(core: std::sync::Arc<hxd_core::Core>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        core.flush_roles_changed();
    }
}
