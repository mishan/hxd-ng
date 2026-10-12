//! Roles: grants shared by name (`docs/roles.md` §2), read from one
//! file, `[roles] file`.
//!
//! ```toml
//! [role.everyone]
//! access = { read_news = true }
//!
//! [role.moderators]
//! title = "Moderators"
//! color = 0x2e8b57
//! position = 20
//! mentionable = true
//! access = { disconnect_users = true, get_user_info = true }
//! extra = { moderate = true }
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use hxd_core::account::FIELD_MAX_CHARS;
use hxd_core::{AccessBits, Extras};
use serde::Deserialize;

use crate::{named_bit, AccessTable};

/// The role every account holds, the guest included. It always exists,
/// granting nothing until the file says otherwise.
pub const EVERYONE: &str = "everyone";

/// What a new roles file starts with: the warning `everyone` needs.
const HEADER: &str = "# Roles on this server (docs/roles.md). `hxd role` edits this file.\n\
    # `everyone` is held by every account, the guest included.\n";

/// One role, as its file defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    /// What clients show; the name unless the file gives one.
    pub title: String,
    /// `0xRRGGBB`.
    pub color: Option<u32>,
    /// Display order, and nothing else: not authority.
    pub position: i64,
    pub mentionable: bool,
    /// The bits it grants.
    pub access: AccessBits,
    /// The `[extra]` keys it grants.
    pub extra: Extras<bool>,
}

impl Role {
    /// The `[extra]` keys it grants, by name.
    pub fn extra_names(&self) -> Vec<&'static str> {
        let mut x = self.extra;
        EXTRA_KEYS
            .iter()
            .filter(|key| extra_slot(&mut x, key).is_some_and(|on| *on))
            .copied()
            .collect()
    }

    fn empty(name: &str) -> Role {
        Role {
            name: name.to_owned(),
            title: name.to_owned(),
            color: None,
            position: 0,
            mentionable: false,
            access: AccessBits::empty(),
            extra: Extras::default(),
        }
    }
}

/// Every role the file defines, and `everyone` whether it does or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roles(BTreeMap<String, Role>);

impl Default for Roles {
    /// No roles file: `everyone`, granting nothing.
    fn default() -> Self {
        Roles(BTreeMap::from([(
            EVERYONE.to_owned(),
            Role::empty(EVERYONE),
        )]))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesFile {
    #[serde(default)]
    role: BTreeMap<String, RoleEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleEntry {
    title: Option<String>,
    color: Option<u32>,
    #[serde(default)]
    position: i64,
    #[serde(default)]
    mentionable: bool,
    #[serde(default)]
    access: AccessTable,
    #[serde(default)]
    extra: BTreeMap<String, bool>,
    // A restriction's keys, read only to refuse them by name.
    kind: Option<toml::Value>,
    deny: Option<toml::Value>,
}

/// Is `name` a role's name: 1 to 30 lowercase ASCII letters, digits, `-`
/// and `_`, starting with a letter or digit? Thirty, so that `@name` fits
/// a classic login's 31; never a leading `-`, which a command line would
/// read as taking a role away.
pub fn valid_name(name: &str) -> bool {
    (1..=30).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// The `[extra]` keys a role may grant (`docs/roles.md` §5): those
/// `hxd_core::admin` compares when it decides who may change whom, so an
/// administrator cannot hand out through a role what it may not itself
/// do. Never the keys that say an account is one person.
pub const EXTRA_KEYS: &[&str] = &[
    "set_subject",
    "file_list",
    "file_getinfo",
    "attach_news",
    "moderate",
    "can_spam",
    "manage_roles",
];

fn extra_slot<'a>(x: &'a mut Extras<bool>, key: &str) -> Option<&'a mut bool> {
    Some(match key {
        "set_subject" => &mut x.set_subject,
        "file_list" => &mut x.file_list,
        "file_getinfo" => &mut x.file_getinfo,
        "attach_news" => &mut x.attach_news,
        "moderate" => &mut x.moderate,
        "can_spam" => &mut x.can_spam,
        "manage_roles" => &mut x.manage_roles,
        _ => return None,
    })
}

impl RoleEntry {
    fn into_role(self, name: &str) -> Result<Role, String> {
        if !valid_name(name) {
            return Err(
                "a role's name is 1 to 30 lowercase letters, digits, - and _, \
                 starting with a letter or digit"
                    .into(),
            );
        }
        // A file written for a server that enforces restrictions must not
        // be read by one that would silently enforce nothing.
        if self.kind.is_some() || self.deny.is_some() {
            return Err(
                "restrictions (kind, deny) are not supported by this server yet; \
                 remove the entry until they are"
                    .into(),
            );
        }
        let title = self.title.unwrap_or_else(|| name.to_owned());
        if title.chars().count() > FIELD_MAX_CHARS {
            return Err("a title is at most 31 characters".into());
        }
        if self.color.is_some_and(|c| c > 0xff_ffff) {
            return Err("a color is 0xRRGGBB".into());
        }
        if !self.access.raw_deny.is_empty() {
            return Err("raw_deny belongs in an account file: a role only grants".into());
        }
        // An unknown key is an error here, where an account's is a
        // warning: a typo in a role silently fails every holder.
        let mut access = AccessBits::empty();
        for (key, on) in &self.access.named {
            let b = named_bit(key).ok_or_else(|| format!("no access key {key:?}"))?;
            if *on {
                access = access.with(b);
            }
        }
        for b in &self.access.raw_bits {
            access = access.with(*b);
        }
        let mut extra = Extras::<bool>::default();
        for (key, on) in &self.extra {
            if matches!(
                key.as_str(),
                "can_detach" | "inbox" | "set_avatar" | "vouch"
            ) {
                return Err(format!(
                    "extra.{key} says an account is one person, so a role, which \
                     accounts share, cannot grant it"
                ));
            }
            *extra_slot(&mut extra, key)
                .ok_or_else(|| format!("no [extra] key {key:?} that a role may grant"))? = *on;
        }
        Ok(Role {
            name: name.to_owned(),
            title,
            color: self.color,
            position: self.position,
            mentionable: self.mentionable,
            access,
            extra,
        })
    }
}

impl Roles {
    pub fn parse(text: &str) -> Result<Roles, String> {
        let file: RolesFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut roles = Roles::default();
        for (name, entry) in file.role {
            let role = entry
                .into_role(&name)
                .map_err(|e| format!("role {name:?}: {e}"))?;
            roles.0.insert(name, role);
        }
        Ok(roles)
    }

    /// The roles file at `path`; none there is no roles.
    pub fn load(path: &Path) -> Result<Roles, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Roles::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Roles::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn get(&self, name: &str) -> Option<&Role> {
        self.0.get(name)
    }

    /// Every role, by name.
    pub fn iter(&self) -> impl Iterator<Item = &Role> {
        self.0.values()
    }

    /// The bits `everyone` and the roles of `listed` grant together.
    pub fn granted(&self, listed: &[String]) -> AccessBits {
        self.held(listed).fold(AccessBits::empty(), |a, role| {
            AccessBits::from_raw(a.raw() | role.access.raw())
        })
    }

    /// `everyone`, and each role of `listed` that exists.
    pub(crate) fn held<'a>(&'a self, listed: &'a [String]) -> impl Iterator<Item = &'a Role> {
        std::iter::once(EVERYONE)
            .chain(listed.iter().map(String::as_str))
            .filter_map(|name| self.get(name))
    }
}

/// Change the roles file at `path` with `f`, keeping its comments: what
/// `f` leaves must parse, and is written whole and renamed into place.
/// An absent file starts as a new one.
pub fn edit(
    path: &Path,
    f: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<(), String>,
) -> Result<Roles, String> {
    let failed = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let old = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(failed(&e)),
    };
    let mut doc: toml_edit::DocumentMut = old
        .as_deref()
        .unwrap_or_default()
        .parse()
        .map_err(|e| failed(&e))?;
    f(&mut doc)?;
    let text = match old {
        Some(_) => doc.to_string(),
        None => format!("{HEADER}\n{doc}"),
    };
    let roles = Roles::parse(&text).map_err(|e| failed(&e))?;
    crate::write_atomic(path, &text).map_err(|e| failed(&e))?;
    Ok(roles)
}
