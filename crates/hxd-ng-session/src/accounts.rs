//! Account administration on the ng wire (`docs/account-admin.md` §5):
//! the `accounts` family's requests, its login block and its event.
//!
//! A translation, as moderation's is: who may change whom is
//! `hxd_core::admin`'s, and this file parses, calls the core off the
//! reactor and writes the answer down.

use hxd_core::access::{self, AccessBits};
use hxd_core::account::FIELD_MAX_CHARS;
use hxd_core::admin::WriteMode;
use hxd_core::{Account, AccountEdit, AdminError, RoleEdit, RoleView};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, SessState};
use crate::proto::{reply_err, reply_ok, ReqEnvelope};
use crate::NgCtx;

pub(crate) fn handles(req: &str) -> bool {
    matches!(
        req,
        "account_list"
            | "account_get"
            | "account_create"
            | "account_update"
            | "account_delete"
            | "role_list"
            | "role_get"
            | "role_create"
            | "role_update"
            | "role_delete"
    )
}

/// What an access bitmap holds, as names and the numbers of the bits
/// that have none: the login block, the event and every account object.
pub fn access_json(a: AccessBits) -> Value {
    let (names, raw) = access::names_of(a);
    json!({ "access": names, "raw_bits": raw })
}

/// An account's configuration, never its mask (`docs/roles.md` §7.2),
/// and the keys its own record sets over its roles.
fn account_json(a: &Account) -> Value {
    let mut v = access_json(a.access);
    v["login"] = json!(a.login);
    v["name"] = json!(a.name);
    v["password"] = json!(a.has_password);
    if let Some(fp) = &a.identity.fingerprint {
        v["identity"] = json!(hl_identity::Fingerprint(*fp).to_string());
    }
    v["roles"] = json!(a.roles);
    let (grant, raw_grant) = access::names_of(a.config.grant);
    let (deny, raw_deny) = access::names_of(a.config.deny);
    v["grant"] = json!(grant);
    v["deny"] = json!(deny);
    v["raw_grant"] = json!(raw_grant);
    v["raw_deny"] = json!(raw_deny);
    v
}

/// A role as the login block lists it: what a user list is drawn with.
pub(crate) fn role_shown_json(r: &RoleView) -> Value {
    let mut v = json!({ "name": r.name, "title": r.title, "position": r.position });
    if let Some(color) = r.color {
        v["color"] = json!(color);
    }
    if r.mentionable {
        v["mentionable"] = json!(true);
    }
    v
}

/// A role with its grants, for `role_list` and `role_get`.
fn role_json(r: &RoleView) -> Value {
    let mut v = role_shown_json(r);
    let access = access_json(r.access);
    v["access"] = access["access"].clone();
    v["raw_bits"] = access["raw_bits"].clone();
    v["extra"] = json!(r.extra);
    v
}

/// The login reply's and `sync`'s `roles` block, when the server
/// administers accounts (`docs/roles.md` §7.1).
pub(crate) fn roles_block(core: &hxd_core::Core, uid: hxd_core::Uid) -> Option<Value> {
    if !core.accounts_enabled() {
        return None;
    }
    let list: Vec<Value> = core.roles_shown().iter().map(role_shown_json).collect();
    let mut v = json!({ "list": list });
    if core.manages_roles(uid) {
        v["manage_roles"] = json!(true);
    }
    Some(v)
}

fn admin_err(e: AdminError) -> (&'static str, String) {
    let code = match &e {
        AdminError::NotAllowed => "access_denied",
        AdminError::Outranked => "outranked",
        AdminError::NoSuchAccount => "no_such_account",
        AdminError::NoSuchRole => "no_such_role",
        AdminError::BadRole(_) => "bad_request",
        AdminError::Exists => "already_exists",
        AdminError::InvalidLogin => "invalid_login",
        AdminError::Unsupported => "not_available",
        AdminError::Backend(e) => {
            tracing::warn!("account administration failed: {e}");
            return ("server_error", "Server error.".into());
        }
    };
    (code, e.to_string())
}

#[derive(Deserialize)]
struct LoginParams {
    login: String,
}

#[derive(Deserialize)]
struct EditParams {
    login: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    access: Option<Vec<String>>,
    #[serde(default)]
    raw_bits: Option<Vec<u8>>,
}

impl EditParams {
    fn edit(self) -> Result<AccountEdit, &'static str> {
        if self
            .name
            .as_ref()
            .is_some_and(|n| n.chars().count() > FIELD_MAX_CHARS)
        {
            return Err("A name is at most 31 characters.");
        }
        if self
            .password
            .as_ref()
            .is_some_and(|p| p.chars().count() > FIELD_MAX_CHARS)
        {
            return Err("A password is at most 31 characters.");
        }
        let access = match (self.access, self.raw_bits) {
            (None, None) => None,
            (None, Some(_)) => return Err("raw_bits goes with access."),
            (Some(names), raw) => {
                let mut a = AccessBits::empty();
                for name in &names {
                    a = a.with(access::named(name).ok_or("No such access name.")?);
                }
                for b in raw.unwrap_or_default() {
                    if b >= 64 {
                        return Err("raw_bits are 0 to 63.");
                    }
                    a = a.with(b);
                }
                Some(a)
            }
        };
        Ok(AccountEdit {
            login: self.login,
            name: self.name.filter(|n| !n.is_empty()),
            password: self.password,
            access,
            ..Default::default()
        })
    }
}

/// A field that is there, `null` or not, as `Some`: so `color: null`
/// clears where an absent `color` keeps.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct RoleParams {
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default, deserialize_with = "present")]
    color: Option<Value>,
    #[serde(default)]
    position: Option<i64>,
    #[serde(default)]
    mentionable: Option<bool>,
    #[serde(default)]
    access: Option<Vec<String>>,
    #[serde(default)]
    raw_bits: Option<Vec<u8>>,
    #[serde(default)]
    extra: Option<Vec<String>>,
    // A restriction's, read only to refuse it.
    #[serde(default, deserialize_with = "present")]
    kind: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    deny: Option<Value>,
}

impl RoleParams {
    fn edit(self) -> Result<RoleEdit, &'static str> {
        if self.kind.is_some() || self.deny.is_some() {
            return Err("This server has no restrictions yet.");
        }
        let color = match self.color {
            None => None,
            Some(Value::Null) => Some(None),
            Some(v) => Some(Some(
                v.as_u64()
                    .and_then(|c| u32::try_from(c).ok())
                    .ok_or("A color is 0xRRGGBB.")?,
            )),
        };
        let access = match (self.access, self.raw_bits) {
            (None, None) => None,
            (None, Some(_)) => return Err("raw_bits goes with access."),
            (Some(names), raw) => {
                let mut a = AccessBits::empty();
                for name in &names {
                    a = a.with(access::named(name).ok_or("No such access name.")?);
                }
                for b in raw.unwrap_or_default() {
                    if b >= 64 {
                        return Err("raw_bits are 0 to 63.");
                    }
                    a = a.with(b);
                }
                Some(a)
            }
        };
        Ok(RoleEdit {
            name: self.name,
            title: self.title,
            color,
            position: self.position,
            mentionable: self.mentionable,
            access,
            extra: self.extra,
        })
    }
}

/// Answer one `accounts` request.
pub(crate) async fn handle(ctx: &NgCtx, state: &SessState, req: &ReqEnvelope) -> String {
    let (id, uid) = (req.id, state.uid);
    let params = req.params.clone();
    let bad = |text: &str| reply_err(id, "bad_request", text);
    let done = match req.req.as_str() {
        "account_list" => {
            off_reactor(&ctx.core, move |c| {
                c.account_list(uid).map(|all| {
                    let listed: Vec<Value> = all
                        .iter()
                        .map(|a| json!({ "login": a.login, "name": a.name }))
                        .collect();
                    json!({ "accounts": listed })
                })
            })
            .await
        }
        "role_list" => {
            off_reactor(&ctx.core, move |c| {
                c.role_list(uid).map(|all| {
                    let listed: Vec<Value> = all
                        .iter()
                        .map(|(role, held)| {
                            let mut v = role_json(role);
                            v["holder_count"] = json!(held);
                            v
                        })
                        .collect();
                    json!({ "roles": listed })
                })
            })
            .await
        }
        "role_get" => {
            #[derive(Deserialize)]
            struct NameParams {
                name: String,
            }
            let Ok(p) = serde_json::from_value::<NameParams>(params) else {
                return bad("Malformed role request.");
            };
            off_reactor(&ctx.core, move |c| {
                c.role_get(uid, &p.name)
                    .map(|(role, holders)| json!({ "role": role_json(&role), "holders": holders }))
            })
            .await
        }
        "role_create" | "role_update" => {
            let Ok(p) = serde_json::from_value::<RoleParams>(params) else {
                return bad("Malformed role request.");
            };
            let edit = match p.edit() {
                Ok(edit) => edit,
                Err(text) => return bad(text),
            };
            let create = req.req == "role_create";
            off_reactor(&ctx.core, move |c| {
                c.role_write(uid, &edit, create)
                    .map(|role| json!({ "role": role_json(&role) }))
            })
            .await
        }
        "role_delete" => {
            #[derive(Deserialize)]
            struct NameParams {
                name: String,
            }
            let Ok(p) = serde_json::from_value::<NameParams>(params) else {
                return bad("Malformed role request.");
            };
            off_reactor(&ctx.core, move |c| {
                c.role_delete(uid, &p.name).map(|()| json!({}))
            })
            .await
        }
        "account_get" | "account_delete" => {
            let Ok(p) = serde_json::from_value::<LoginParams>(params) else {
                return bad("Malformed account request.");
            };
            let delete = req.req == "account_delete";
            off_reactor(&ctx.core, move |c| {
                if delete {
                    c.account_delete(uid, &p.login).map(|()| json!({}))
                } else {
                    c.account_read(uid, &p.login)
                        .map(|a| json!({ "account": account_json(&a) }))
                }
            })
            .await
        }
        _ => {
            let Ok(p) = serde_json::from_value::<EditParams>(params) else {
                return bad("Malformed account request.");
            };
            let edit = match p.edit() {
                Ok(edit) => edit,
                Err(text) => return bad(text),
            };
            let mode = if req.req == "account_create" {
                WriteMode::Create
            } else {
                WriteMode::Modify
            };
            off_reactor(&ctx.core, move |c| {
                c.account_write(uid, &edit, mode)
                    .map(|a| json!({ "account": account_json(&a) }))
            })
            .await
        }
    };
    match done {
        Some(Ok(ok)) => reply_ok(id, ok),
        Some(Err(e)) => {
            let (code, text) = admin_err(e);
            reply_err(id, code, &text)
        }
        None => reply_err(id, "server_error", "Server error."),
    }
}
