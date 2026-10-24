//! Account administration on the legacy wire, the 1.5 user editor: New
//! User (350), Delete User (351), Open User (352) and Set User (353).
//!
//! mhxd is the reference for what each carries: Open User names its
//! login in the clear and every other request obfuscates it, a reply
//! never carries the password — a single NUL stands in for it — and a
//! Set User password of that one NUL keeps the password the account has,
//! where a Set User with no password at all clears it: a period client's
//! editor leaves the field out when its box is emptied.
//! Who may change whom is the domain's (`hxd_core::admin`).

use hxd_core::account::FIELD_MAX_CHARS;
use hxd_core::admin::WriteMode;
use hxd_core::{AccessBits, AccountEdit, AdminError, Core, Uid};
use hxproto::messages::{tag, ClientHdr};

use crate::encoding::TextEncoding;

/// New User and Delete User, which `hxproto` has no names for.
pub(crate) const ACCOUNT_CREATE: u32 = 0x015e;
pub(crate) const ACCOUNT_DELETE: u32 = 0x015f;

/// The transactions answered here.
pub(crate) fn handles(ty: u32) -> bool {
    ty == ACCOUNT_CREATE
        || ty == ACCOUNT_DELETE
        || ty == ClientHdr::AccountRead.as_u32()
        || ty == ClientHdr::AccountModify.as_u32()
}

/// The highest access bit the user editor of a client that logged in
/// with `version` can show, by the tiers of fogWraith's Extended
/// Privilege extension: 1.2 sends no version, GLoarbLine sends 197, and
/// anything else is taken for 1.5 or 1.9. A save keeps the bits above it
/// as the account has them, since an editor that cannot show a bit sends
/// it clear.
pub(crate) fn editor_tier(version: Option<u16>) -> u8 {
    match version {
        None => 31,
        Some(197) => 54,
        Some(_) => 40,
    }
}

/// Answer one request for session `uid`, whose editor shows the access
/// bits up to `tier`: the reply's fields, or the task error's text.
pub(crate) fn transaction(
    core: &Core,
    uid: Uid,
    enc: TextEncoding,
    tier: u8,
    ty: u32,
    fields: &[(u16, Vec<u8>)],
) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let field = |want: u16| fields.iter().find(|(t, _)| *t == want).map(|(_, d)| &d[..]);
    let text = |bytes: &[u8]| enc.decode_chars(bytes, FIELD_MAX_CHARS);
    let obfuscated = |bytes: &[u8]| text(&bytes.iter().map(|b| !b).collect::<Vec<_>>());
    let login = field(tag::LOGIN).unwrap_or_default();
    if ty == ClientHdr::AccountRead.as_u32() {
        let account = core.account_read(uid, &text(login)).map_err(err_text)?;
        return Ok(vec![
            (tag::NAME, enc.encode_capped(&account.name, FIELD_MAX_CHARS)),
            (
                tag::LOGIN,
                enc.encode(&account.login).iter().map(|b| !b).collect(),
            ),
            (tag::PASSWORD, vec![0]),
            (tag::ACCESS, account.access.to_wire().to_vec()),
        ]);
    }
    let login = obfuscated(login);
    if ty == ACCOUNT_DELETE {
        core.account_delete(uid, &login).map_err(err_text)?;
        return Ok(Vec::new());
    }
    let edit = AccountEdit {
        login,
        name: field(tag::NAME).filter(|n| !n.is_empty()).map(text),
        password: match field(tag::PASSWORD) {
            Some([0]) => None,
            Some(p) => Some(obfuscated(p)),
            None if ty == ACCOUNT_CREATE => None,
            None => Some(String::new()),
        },
        access: field(tag::ACCESS)
            .and_then(|a| a.get(..8))
            .map(|a| AccessBits::from_wire(a.try_into().expect("eight bytes"))),
        editor_tier: Some(tier),
    };
    let mode = if ty == ACCOUNT_CREATE {
        WriteMode::Create
    } else {
        WriteMode::CreateOrModify
    };
    core.account_write(uid, &edit, mode).map_err(err_text)?;
    Ok(Vec::new())
}

fn err_text(e: AdminError) -> String {
    if let AdminError::Backend(e) = &e {
        tracing::warn!("account administration failed: {e}");
        return "The server could not reach its accounts.".into();
    }
    e.to_string()
}
