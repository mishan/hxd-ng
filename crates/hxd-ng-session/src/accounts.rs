//! Account administration on the ng wire (`docs/account-admin.md` §5):
//! the `accounts` family's requests, its login block and its event.
//!
//! A translation, as moderation's is: who may change whom is
//! `hxd_core::admin`'s, and this file parses, calls the core off the
//! reactor and writes the answer down.

use hxd_core::access::{self, AccessBits};
use hxd_core::account::FIELD_MAX_CHARS;
use hxd_core::admin::WriteMode;
use hxd_core::{Account, AccountEdit, AdminError};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::conn::{off_reactor, SessState};
use crate::proto::{reply_err, reply_ok, ReqEnvelope};
use crate::NgCtx;

pub(crate) fn handles(req: &str) -> bool {
    matches!(
        req,
        "account_list" | "account_get" | "account_create" | "account_update" | "account_delete"
    )
}

/// What an access bitmap holds, as names and the numbers of the bits
/// that have none: the login block, the event and every account object.
pub fn access_json(a: AccessBits) -> Value {
    let (names, raw) = access::names_of(a);
    json!({ "access": names, "raw_bits": raw })
}

fn account_json(a: &Account) -> Value {
    let mut v = access_json(a.access);
    v["login"] = json!(a.login);
    v["name"] = json!(a.name);
    v["password"] = json!(a.has_password);
    if let Some(fp) = &a.identity.fingerprint {
        v["identity"] = json!(hl_identity::Fingerprint(*fp).to_string());
    }
    v
}

fn admin_err(e: AdminError) -> (&'static str, String) {
    let code = match &e {
        AdminError::NotAllowed => "access_denied",
        AdminError::Outranked => "outranked",
        AdminError::NoSuchAccount => "no_such_account",
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
            history_unsaid: false,
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
