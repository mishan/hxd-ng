//! Account administration on a session's behalf, whichever wire it
//! came in on (`docs/account-admin.md`).
//!
//! **Who may** is the access bit each act has always needed: read-users,
//! create-users, modify-users, delete-users. **Whom** is narrower than
//! the reference server's answer, which was anyone: an administrator may
//! write or delete only an account that may do nothing their own account
//! may not — its access bits and the server-local policy its file grants
//! alike — and may not make one that could. Otherwise modify-users is
//! every privilege there is, one edit of one's own account away.
//!
//! A change reaches the account's sessions at once: what they may do,
//! their administrator color, and the name of one that may not choose
//! its own. A deleted account's sessions are disconnected — mhxd's
//! `kick_transients`, on by default there — all but the deleter's own.
//! An edit made beside the server reaches them on SIGHUP.

use crate::access::bit;
use crate::account::{Account, AccountAdmin, AccountEdit, AdminError, FIELD_MAX_CHARS};
use crate::roster::{Core, Event, Uid};

/// What [`Core::account_write`] may do about whether the account exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Make a new account; one that exists is refused.
    Create,
    /// Change an existing account; one that does not exist is refused.
    Modify,
    /// Change the account, or make it for a session that may also
    /// create: the reference server's modify is its create too, and
    /// GtkHx makes new accounts with it.
    CreateOrModify,
}

/// May `target` do anything `actor` may not: hold an access bit, or a
/// policy its account file grants? Not detaching, mail or an avatar:
/// those follow from a password, and say an account is one person
/// rather than what it may do to anyone else.
fn beyond(actor: &Account, target: &Account) -> bool {
    target.access.raw() & !actor.access.raw() != 0
        || [
            (target.set_subject, actor.set_subject),
            (target.file_list, actor.file_list),
            (target.file_getinfo, actor.file_getinfo),
            (target.attach_news, actor.attach_news),
            (target.moderate, actor.moderate),
            (target.can_spam, actor.can_spam),
        ]
        .iter()
        .any(|(t, a)| *t && !*a)
}

/// The account `login` names, as its file reads now — inside the
/// backend's writes, so it is not demoted between this and the write —
/// holding `need` there as well as on the roster. What an account it
/// touches is measured against.
fn actor(admin: &dyn AccountAdmin, login: &str, need: u8) -> Result<Account, AdminError> {
    let account = admin.read_account(login).map_err(|e| match e {
        AdminError::NoSuchAccount => AdminError::NotAllowed,
        e => e,
    })?;
    if !account.access.has(need) {
        return Err(AdminError::NotAllowed);
    }
    Ok(account)
}

impl Core {
    /// Does this server administer accounts at all?
    pub fn accounts_enabled(&self) -> bool {
        self.admin.is_some()
    }

    /// The account `login` names, for a session holding read-users.
    pub fn account_read(&self, uid: Uid, login: &str) -> Result<Account, AdminError> {
        self.admin_backend(uid, bit::READ_USERS)?
            .read_account(login)
    }

    /// Every account, for a session holding read-users.
    pub fn account_list(&self, uid: Uid) -> Result<Vec<Account>, AdminError> {
        self.admin_backend(uid, bit::READ_USERS)?.list_accounts()
    }

    /// Apply `edit` for session `uid`, as `mode` says.
    pub fn account_write(
        &self,
        uid: Uid,
        edit: &AccountEdit,
        mode: WriteMode,
    ) -> Result<Account, AdminError> {
        let need = match mode {
            WriteMode::Create => bit::CREATE_USERS,
            WriteMode::Modify | WriteMode::CreateOrModify => bit::MODIFY_USERS,
        };
        let admin = self.admin_backend(uid, need)?;
        let login = self.login_of(uid)?;
        let account = admin.write_account(edit, &|existing, after| {
            let actor = actor(admin, &login, need)?;
            match (mode, existing) {
                (WriteMode::Create, Some(_)) => return Err(AdminError::Exists),
                (WriteMode::Modify, None) => return Err(AdminError::NoSuchAccount),
                (_, None) if !actor.access.has(bit::CREATE_USERS) => {
                    return Err(AdminError::NotAllowed)
                }
                _ => {}
            }
            if existing.is_some_and(|a| beyond(&actor, a)) || beyond(&actor, after) {
                return Err(AdminError::Outranked);
            }
            Ok(())
        })?;
        self.apply_account(&account);
        Ok(account)
    }

    /// Delete the account `login` names for session `uid`, and
    /// disconnect every other session logged in as it.
    pub fn account_delete(&self, uid: Uid, login: &str) -> Result<(), AdminError> {
        let admin = self.admin_backend(uid, bit::DELETE_USERS)?;
        let actor_login = self.login_of(uid)?;
        admin.delete_account(login, &|account| {
            if beyond(&actor(admin, &actor_login, bit::DELETE_USERS)?, account) {
                return Err(AdminError::Outranked);
            }
            Ok(())
        })?;
        self.end_account(&login.to_ascii_lowercase(), Some(uid));
        Ok(())
    }

    /// The backend, for a session holding `need`. A server without one
    /// says so to everybody, whatever they hold.
    fn admin_backend(&self, uid: Uid, need: u8) -> Result<&dyn AccountAdmin, AdminError> {
        let admin = self.admin.as_deref().ok_or(AdminError::Unsupported)?;
        if !self.access_of(uid).is_some_and(|a| a.has(need)) {
            return Err(AdminError::NotAllowed);
        }
        Ok(admin)
    }

    fn login_of(&self, uid: Uid) -> Result<String, AdminError> {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .map(|s| s.login.clone())
            .ok_or(AdminError::NotAllowed)
    }

    /// Bring every session up to date with its account file, for an
    /// operator who edited accounts outside the server (`hxd account`,
    /// or by hand) and sent SIGHUP: each account is applied as an
    /// administrator's edit is, and the sessions of one that is gone are
    /// disconnected. Answers how many sessions were told and ended.
    pub fn reload_accounts(&self) -> (usize, usize) {
        let Some(admin) = self.admin.as_deref() else {
            return (0, 0);
        };
        let mut logins: Vec<String> = {
            let r = self.roster.lock().unwrap();
            r.users
                .values()
                .filter(|s| !s.system)
                .map(|s| s.login.clone())
                .collect()
        };
        logins.sort();
        logins.dedup();
        let (mut told, mut ended) = (0, 0);
        // Read with the roster unlocked: the store is file I/O.
        for login in logins {
            match admin.read_account(&login) {
                Ok(account) => told += self.apply_account(&account),
                Err(AdminError::NoSuchAccount) => ended += self.end_account(&login, None),
                Err(e) => tracing::warn!(login, "account reload skipped: {e}"),
            }
        }
        (told, ended)
    }

    /// Disconnect every session logged in as `login` but `keep`.
    fn end_account(&self, login: &str, keep: Option<Uid>) -> usize {
        let mut r = self.roster.lock().unwrap();
        let ended: Vec<Uid> = r
            .users
            .iter()
            .filter(|(u, s)| Some(**u) != keep && !s.system && s.login == login)
            .map(|(u, _)| *u)
            .collect();
        for target in &ended {
            let _ = crate::chat::kick_in(&mut r, *target);
        }
        ended.len()
    }

    /// Give every session logged in as `account` what it now says.
    /// Answers how many were told.
    fn apply_account(&self, account: &Account) -> usize {
        let mut r = self.roster.lock().unwrap();
        let uids: Vec<Uid> = r
            .users
            .iter()
            .filter(|(_, s)| !s.system && s.login == account.login)
            .map(|(u, _)| *u)
            .collect();
        let admin = account.access.has(bit::DISCONNECT_USERS);
        let name = (!account.access.has(bit::USE_ANY_NAME)).then(|| {
            account
                .name
                .chars()
                .take(FIELD_MAX_CHARS)
                .collect::<String>()
        });
        for &uid in &uids {
            let Some(s) = r.users.get_mut(&uid) else {
                continue;
            };
            s.access = account.access;
            s.can_detach = account.can_detach;
            s.has_inbox = account.has_inbox;
            s.attach_news = account.attach_news;
            s.set_avatar = account.set_avatar;
            s.moderate = account.moderate;
            s.can_spam = account.can_spam;
            s.is_person = account.is_person();
            let mut shown = s.info.admin != admin;
            s.info.admin = admin;
            if let Some(name) = &name {
                shown |= s.info.nick != *name;
                s.info.nick = name.clone();
            }
            let shown = (shown && s.visible).then(|| s.info.clone());
            r.send_to(uid, Event::AccountChanged(Box::new(account.clone())));
            if let Some(info) = shown {
                r.broadcast_where(&Event::Changed(info), None, |_| true);
            }
        }
        uids.len()
    }
}
