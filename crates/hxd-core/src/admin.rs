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
use crate::account::{
    Account, AccountAdmin, AccountEdit, AdminError, DenyMask, RoleEdit, RoleView, FIELD_MAX_CHARS,
};
use crate::roster::{Core, Event, RosterInner, Uid};

/// The role every account holds (`docs/roles.md` §2.2).
pub const EVERYONE: &str = "everyone";

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

/// May `target` do anything `actor` may not: hold an access bit, a
/// policy its account file grants, or a role a gate names (`gated`)?
/// Not detaching, mail or an avatar: those follow from a password, and
/// say an account is one person rather than what it may do to anyone
/// else. A gated role is a way in, so whoever could give it could let
/// themselves into what it gates (`docs/roles.md` §5); `manage_roles`
/// may, as it may make the role.
fn beyond(actor: &Account, target: &Account, gated: &[String]) -> bool {
    let let_in = |r: &String| gated.contains(r) && !actor.config.roles.contains(r);
    (!actor.manage_roles && target.config.roles.iter().any(let_in))
        || target.access.raw() & !actor.access.raw() != 0
        || [
            (target.set_subject, actor.set_subject),
            (target.file_list, actor.file_list),
            (target.file_getinfo, actor.file_getinfo),
            (target.attach_news, actor.attach_news),
            (target.moderate, actor.moderate),
            (target.can_spam, actor.can_spam),
            (target.manage_roles, actor.manage_roles),
            (target.manage_rooms, actor.manage_rooms),
        ]
        .iter()
        .any(|(t, a)| *t && !*a)
}

/// Does `role` grant anything `actor` may not do (`docs/roles.md` §5)?
fn grants_beyond(actor: &Account, role: &RoleView) -> bool {
    role.access.raw() & !actor.access.raw() != 0
        || role.extra.iter().any(|key| !match *key {
            "set_subject" => actor.set_subject,
            "file_list" => actor.file_list,
            "file_getinfo" => actor.file_getinfo,
            "attach_news" => actor.attach_news,
            "moderate" => actor.moderate,
            "can_spam" => actor.can_spam,
            "manage_roles" => actor.manage_roles,
            "manage_rooms" => actor.manage_rooms,
            _ => false,
        })
}

/// How long `roles_changed` waits after one before another may go: an
/// administrator editing a role field by field is one redraw a client
/// makes, not one a field (`docs/roles.md` §4).
pub const ROLES_CHANGED_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// How many roster rows one change sends a `user_changed` for, by
/// default, before `roster_stale` goes instead (`docs/roles.md` §4).
pub const BULK_ROWS: usize = 64;

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

    /// Every role, highest first, with how many accounts hold it, for a
    /// session holding read-users.
    pub fn role_list(&self, uid: Uid) -> Result<Vec<(RoleView, usize)>, AdminError> {
        let admin = self.admin_backend(uid, bit::READ_USERS)?;
        let accounts = admin.list_accounts()?;
        Ok(admin
            .roles()
            .into_iter()
            .map(|role| {
                let held = accounts
                    .iter()
                    .filter(|a| role.name == EVERYONE || a.roles.contains(&role.name))
                    .count();
                (role, held)
            })
            .collect())
    }

    /// One role and the logins holding it, for a session holding
    /// read-users.
    pub fn role_get(&self, uid: Uid, name: &str) -> Result<(RoleView, Vec<String>), AdminError> {
        let admin = self.admin_backend(uid, bit::READ_USERS)?;
        let role = admin
            .roles()
            .into_iter()
            .find(|r| r.name == name)
            .ok_or(AdminError::NoSuchRole)?;
        let holders = admin
            .list_accounts()?
            .into_iter()
            .filter(|a| name == EVERYONE || a.roles.iter().any(|r| r == name))
            .map(|a| a.login)
            .collect();
        Ok((role, holders))
    }

    /// Every role, highest first, as every session may see them: their
    /// names, titles and colors are what a user list is drawn with.
    pub fn roles_shown(&self) -> Vec<RoleView> {
        self.admin.as_deref().map_or_else(Vec::new, |a| a.roles())
    }

    /// May session `uid` create, edit and delete roles?
    pub fn manages_roles(&self, uid: Uid) -> bool {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .and_then(|s| s.account.as_ref().map(|a| a.masked(&s.mask)))
            .is_some_and(|a| a.manage_roles)
    }

    /// Make or change a role for session `uid`, which must manage roles
    /// and may give out through it nothing it may not do, nor touch a
    /// role anyone it could not edit holds (`docs/roles.md` §5).
    pub fn role_write(
        &self,
        uid: Uid,
        edit: &RoleEdit,
        create: bool,
    ) -> Result<RoleView, AdminError> {
        let admin = self.admin.as_deref().ok_or(AdminError::Unsupported)?;
        if !self.manages_roles(uid) {
            return Err(AdminError::NotAllowed);
        }
        let login = self.login_of(uid)?;
        let _writing = self.begin_account_write();
        let shown_before = admin.roles().into_iter().find(|r| r.name == edit.name);
        let role = admin.write_role(edit, create, &|before, after, now, then| {
            role_may(admin, &login, before, after, now, then)
        })?;
        // Before any holder is told: a color never travels as their rows.
        self.refresh_role_colors();
        // A change to what it looks like alone is told as `roles_changed`,
        // not to each holder as though what they may do had changed. A
        // new one may already be listed by accounts waiting for it.
        let grants = |r: &RoleView| (r.access, r.extra.clone());
        if shown_before.as_ref().map(grants) != Some(grants(&role)) {
            let name = role.name.clone();
            self.reapply(|a| name == EVERYONE || a.roles.contains(&name));
        }
        let shown = |r: &RoleView| (r.title.clone(), r.color, r.position, r.mentionable);
        if shown_before.as_ref().map(shown) != Some(shown(&role)) {
            self.roles_changed();
        }
        Ok(role)
    }

    /// Delete a role for session `uid`, under [`Core::role_write`]'s rule.
    pub fn role_delete(&self, uid: Uid, name: &str) -> Result<(), AdminError> {
        let admin = self.admin.as_deref().ok_or(AdminError::Unsupported)?;
        if !self.manages_roles(uid) {
            return Err(AdminError::NotAllowed);
        }
        let login = self.login_of(uid)?;
        let _writing = self.begin_account_write();
        // Held through the delete, so no gate comes to name it meanwhile.
        let _rooms = self.room_state.writes.lock().unwrap();
        let gated = self.gated_roles();
        if gated.iter().any(|g| g == name) {
            return Err(AdminError::RoleInUse);
        }
        let deleted = admin.delete_role(name, &|before, after, now, then| {
            role_may(admin, &login, before, after, now, then)
        });
        // Even one cut short may have taken it from some of its holders.
        self.refresh_role_colors();
        self.reapply(|a| a.roles.iter().any(|r| r == name));
        deleted?;
        self.roles_changed();
        Ok(())
    }

    /// Read again the accounts of the sessions `holds` picks, and give
    /// each what it now says. Under the account-write lock.
    fn reapply(&self, holds: impl Fn(&Account) -> bool) {
        let Some(admin) = self.admin.as_deref() else {
            return;
        };
        let mut logins: Vec<String> = {
            let r = self.roster.lock().unwrap();
            r.users
                .values()
                .filter(|s| !s.system && s.account.as_ref().is_some_and(|a| holds(a)))
                .map(|s| s.login.clone())
                .collect()
        };
        logins.sort();
        logins.dedup();
        let accounts: std::collections::HashMap<String, Account> = logins
            .into_iter()
            .filter_map(|login| Some((login.clone(), admin.read_account(&login).ok()?)))
            .collect();
        self.apply_accounts(|l| accounts.get(l));
    }

    /// Give every session the color its roles now give it, telling nobody:
    /// a role's color reaches a classic client with its holders' next
    /// change or login, never as a burst of its own (`docs/roles.md` §4).
    fn refresh_role_colors(&self) {
        let roles = self.roles_shown();
        let mut r = self.roster.lock().unwrap();
        for s in r.users.values_mut() {
            if let Some(account) = &s.account {
                s.info.role_color = role_color(&roles, &account.roles);
            }
        }
    }

    /// Tell every session that shows roles what they now are, or, if one
    /// was told too recently, leave it for [`Core::flush_roles_changed`].
    fn roles_changed(&self) {
        let mut note = self.roles_note.lock().unwrap();
        let now = self.clock.now();
        if note
            .0
            .is_some_and(|at| now.duration_since(at) < ROLES_CHANGED_EVERY)
        {
            note.1 = true;
            return;
        }
        *note = (Some(now), false);
        drop(note);
        self.send_roles_changed();
    }

    /// Send a `roles_changed` held back by [`ROLES_CHANGED_EVERY`] once
    /// it has passed. Called every second by the binary.
    pub fn flush_roles_changed(&self) {
        let mut note = self.roles_note.lock().unwrap();
        let now = self.clock.now();
        match *note {
            (Some(at), true) if now.duration_since(at) >= ROLES_CHANGED_EVERY => {
                *note = (Some(now), false);
            }
            _ => return,
        }
        drop(note);
        self.send_roles_changed();
    }

    fn send_roles_changed(&self) {
        let list: std::sync::Arc<[RoleView]> = self.roles_shown().into();
        let mut r = self.roster.lock().unwrap();
        r.broadcast_where(&Event::RolesChanged(list), None, |s| s.info.transport.roles);
    }

    /// The titles of the roles `listed` names that exist, highest first,
    /// for display. `everyone` is left out: it says nothing about anyone.
    pub fn role_titles(&self, listed: &[String]) -> Vec<String> {
        let Some(admin) = self.admin.as_deref() else {
            return Vec::new();
        };
        admin
            .roles()
            .into_iter()
            .filter(|role| role.name != EVERYONE && listed.contains(&role.name))
            .map(|role| role.title)
            .collect()
    }

    /// The keys the account `login` names sets over its roles, for a
    /// session holding read-users.
    pub fn account_own_keys(&self, uid: Uid, login: &str) -> Result<Vec<String>, AdminError> {
        self.admin_backend(uid, bit::READ_USERS)?.own_keys(login)
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
        let _writing = self.begin_account_write();
        // So no gate comes to name a role this edit gives meanwhile.
        let _rooms = self.room_state.writes.lock().unwrap();
        let gated = self.gated_roles();
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
            if existing.is_some_and(|a| beyond(&actor, a, &gated)) || beyond(&actor, after, &gated)
            {
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
        let _writing = self.begin_account_write();
        let gated = self.gated_roles();
        admin.delete_account(login, &|account| {
            if beyond(
                &actor(admin, &actor_login, bit::DELETE_USERS)?,
                account,
                &gated,
            ) {
                return Err(AdminError::Outranked);
            }
            Ok(())
        })?;
        let login = login.to_ascii_lowercase();
        self.end_account(|l| l == login, Some(uid));
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

    /// Hold account writes, and say one has begun.
    fn begin_account_write(&self) -> std::sync::MutexGuard<'_, ()> {
        let guard = self
            .account_writes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.account_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        guard
    }

    /// How many account writes have begun: read by a login before it
    /// authenticates, for [`Core::account_settled`].
    pub fn account_epoch(&self) -> u64 {
        self.account_epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// A login's last word on its account, once its session `uid` is on
    /// the roster: an account write that began since `epoch` may have
    /// told the account's sessions before this one was among them, so the
    /// account is read again and applied. `false` when it is gone, and
    /// the caller ends the session. Store I/O, so off the reactor.
    pub fn account_settled(&self, uid: Uid, epoch: u64) -> bool {
        let Some(admin) = self.admin.as_deref() else {
            return true;
        };
        if self.account_epoch() == epoch {
            return true;
        }
        let Ok(login) = self.login_of(uid) else {
            return true;
        };
        let _writing = self
            .account_writes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match admin.read_account(&login) {
            Ok(account) => {
                self.apply_account(&account);
                true
            }
            Err(AdminError::NoSuchAccount) => false,
            Err(e) => {
                tracing::warn!(login, "account recheck skipped: {e}");
                true
            }
        }
    }

    fn login_of(&self, uid: Uid) -> Result<String, AdminError> {
        let r = self.roster.lock().unwrap();
        r.users
            .get(&uid)
            .map(|s| s.login.clone())
            .ok_or(AdminError::NotAllowed)
    }

    /// Bring every session up to date with its account file, for an
    /// operator who edited accounts or roles outside the server (`hxd
    /// account`, `hxd role`, or by hand) and sent SIGHUP: each account is
    /// applied as an administrator's edit is, and the sessions of one
    /// that is gone are disconnected. Answers how many sessions were told
    /// and ended.
    pub fn reload_accounts(&self) -> (usize, usize) {
        let Some(admin) = self.admin.as_deref() else {
            return (0, 0);
        };
        let _writing = self.begin_account_write();
        if let Err(e) = admin.reload() {
            tracing::error!("account reload: {e}");
        }
        // A role recolored by hand: its holders' classic rows take it
        // silently, and ng clients redraw from `roles_changed`.
        self.refresh_role_colors();
        self.roles_changed();
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
        let mut accounts = std::collections::HashMap::new();
        let mut gone = std::collections::HashSet::new();
        // Read with the roster unlocked: the store is file I/O.
        for login in logins {
            match admin.read_account(&login) {
                Ok(account) => {
                    accounts.insert(login, account);
                }
                Err(AdminError::NoSuchAccount) => {
                    gone.insert(login);
                }
                Err(e) => tracing::warn!(login, "account reload skipped: {e}"),
            }
        }
        // Each step once for every session together, not once an
        // account: each walks the roster or the rooms.
        let ended = self.end_account(|l| gone.contains(l), None);
        (self.apply_accounts(|l| accounts.get(l)), ended)
    }

    /// Disconnect every session logged in as a login `gone` names but
    /// `keep`.
    fn end_account(&self, gone: impl Fn(&str) -> bool, keep: Option<Uid>) -> usize {
        let mut r = self.roster.lock().unwrap();
        let ended: Vec<Uid> = r
            .users
            .iter()
            .filter(|(u, s)| Some(**u) != keep && !s.system && gone(&s.login))
            .map(|(u, _)| *u)
            .collect();
        for target in &ended {
            let _ = crate::chat::kick_in(&mut r, *target);
        }
        ended.len()
    }

    /// Give every session logged in as `account` what it now says.
    /// Answers how many were told.
    pub(crate) fn apply_account(&self, account: &Account) -> usize {
        self.apply_accounts(|l| (l == account.login).then_some(account))
    }

    /// Give every session whose login `account_of` answers that account.
    fn apply_accounts<'a>(&self, account_of: impl Fn(&str) -> Option<&'a Account>) -> usize {
        let roles = self.roles_shown();
        let mut r = self.roster.lock().unwrap();
        let told: Vec<(Uid, &Account)> = r
            .users
            .iter()
            .filter(|(_, s)| !s.system)
            .filter_map(|(u, s)| Some((*u, account_of(&s.login)?)))
            .collect();
        let uids: Vec<Uid> = told.iter().map(|(u, _)| *u).collect();
        let listed_before = r.room_shown(None, Some(&uids));
        let rows: Vec<Row> = told
            .iter()
            .filter_map(|&(uid, account)| give_account(&mut r, uid, account, &roles))
            .collect();
        announce(&mut r, rows, self.bulk_rows.unwrap_or(BULK_ROWS));
        // What it may read may have narrowed (docs/chat-rooms.md §5).
        r.room_reconcile();
        r.room_announce(listed_before, None, Some(&uids));
        uids.len()
    }

    /// Deny session `uid` what `mask` names, whatever its account says,
    /// and tell it as an account edit is told; an empty mask lifts it.
    /// `false` when there is no such session, or no account behind it to
    /// derive what is left from.
    pub fn set_session_mask(&self, uid: Uid, mask: DenyMask) -> bool {
        let roles = self.roles_shown();
        let mut r = self.roster.lock().unwrap();
        let Some(s) = r.users.get_mut(&uid) else {
            return false;
        };
        let Some(account) = s.account.clone() else {
            return false;
        };
        s.mask = mask;
        let listed_before = r.room_shown(None, Some(&[uid]));
        let rows = give_account(&mut r, uid, &account, &roles)
            .into_iter()
            .collect();
        announce(&mut r, rows, self.bulk_rows.unwrap_or(BULK_ROWS));
        r.room_reconcile();
        r.room_announce(listed_before, None, Some(&[uid]));
        true
    }

    /// Session `uid`'s mask, for a frontend that reads its account again.
    pub fn mask_of(&self, uid: Uid) -> DenyMask {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| s.mask).unwrap_or_default()
    }
}

/// May the account `login` names make a role `before` into `after`,
/// with its holders reading as `now` and then as `then`: it manages
/// roles, the role grants nothing it lacks either side of the edit, and
/// every holder is one it could edit and could have made so, as
/// account-admin.md §1 has it for an account. Read inside the backend's
/// writes, as [`actor`] is.
fn role_may(
    admin: &dyn AccountAdmin,
    login: &str,
    before: Option<&RoleView>,
    after: Option<&RoleView>,
    now: &[Account],
    then: &[Account],
) -> Result<(), AdminError> {
    let actor = admin.read_account(login).map_err(|e| match e {
        AdminError::NoSuchAccount => AdminError::NotAllowed,
        e => e,
    })?;
    if !actor.manage_roles {
        return Err(AdminError::NotAllowed);
    }
    if before
        .into_iter()
        .chain(after)
        .any(|r| grants_beyond(&actor, r))
        // No gate is beyond one who may manage roles.
        || now.iter().chain(then).any(|h| beyond(&actor, h, &[]))
    {
        return Err(AdminError::Outranked);
    }
    Ok(())
}

/// A roster row an account change altered, for [`announce`]: the row,
/// and whether only its roles changed.
type Row = (crate::UserInfo, bool);

/// Tell everyone of `rows`, or, past `bulk` of them, tell a wire that can
/// sync that its roster is stale rather than send it each one: one change
/// may not push a session near its queue's cap.
fn announce(r: &mut RosterInner, rows: Vec<Row>, bulk: usize) {
    let stale = rows.len() > bulk;
    if stale {
        r.broadcast_where(&Event::RosterStale, None, |s| s.info.transport.roles);
    }
    for (info, only_roles) in rows {
        r.broadcast_where(&Event::Changed(info), None, |s| {
            let syncs = s.info.transport.roles;
            !(stale && syncs) && (!only_roles || syncs)
        });
    }
}

/// The color of the highest colored role of `listed` that exists, from
/// `roles`, highest first (`docs/roles.md` §8).
pub(crate) fn role_color(roles: &[RoleView], listed: &[String]) -> Option<u32> {
    roles
        .iter()
        .filter(|r| listed.contains(&r.name))
        .find_map(|r| r.color)
}

/// Give session `uid` `account` as its mask leaves it, and tell it.
/// Answers its roster row if that changed, for the caller to announce.
fn give_account(
    r: &mut RosterInner,
    uid: Uid,
    account: &Account,
    roles: &[RoleView],
) -> Option<Row> {
    let s = r.users.get_mut(&uid)?;
    let effective = account.masked(&s.mask);
    s.account = Some(Box::new(account.clone()));
    let admin = effective.access.has(bit::DISCONNECT_USERS);
    let name = (!effective.access.has(bit::USE_ANY_NAME)).then(|| {
        effective
            .name
            .chars()
            .take(FIELD_MAX_CHARS)
            .collect::<String>()
    });
    s.access = effective.access;
    s.can_detach = effective.can_detach;
    s.has_inbox = effective.has_inbox;
    s.attach_news = effective.attach_news;
    s.set_avatar = effective.set_avatar;
    s.moderate = effective.moderate;
    s.can_spam = effective.can_spam;
    s.manage_rooms = effective.manage_rooms;
    s.set_subject = effective.set_subject;
    s.is_person = effective.is_person();
    let role_color = role_color(roles, &account.roles);
    // A color a classic client draws, so not a change of roles alone.
    let mut shown = s.info.admin != admin || s.info.role_color != role_color;
    let roles_changed = s.info.roles != account.roles;
    s.info.admin = admin;
    s.info.role_color = role_color;
    s.info.roles.clone_from(&account.roles);
    let renamed = name.as_ref().is_some_and(|n| s.info.nick != *n);
    if let Some(name) = name {
        s.info.nick = name;
    }
    shown |= renamed;
    // A change to its roles alone, to the wires that can show one.
    let only_roles = !shown && roles_changed;
    let shown = ((shown || roles_changed) && s.visible).then(|| s.info.clone());
    r.send_to(uid, Event::AccountChanged(Box::new(effective)));
    // The admin bit never crosses a link; only the name does.
    if shown.is_some() && renamed {
        r.export_changed(uid);
    }
    shown.map(|info| (info, only_roles))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::account::{AccountConfig, IdentityLink, WriteCheck};
    use crate::roster::{test_attach, test_attach_on};
    use crate::AccessBits;

    /// Accounts in a map, for what this module decides apart from files.
    #[derive(Default)]
    struct Accounts(Mutex<HashMap<String, Account>>);

    fn account(login: &str, access: AccessBits) -> Account {
        let config = AccountConfig {
            access,
            ..Default::default()
        };
        Account::new(
            login.into(),
            login.into(),
            true,
            IdentityLink::default(),
            config,
        )
    }

    impl AccountAdmin for Accounts {
        fn read_account(&self, login: &str) -> Result<Account, AdminError> {
            self.0
                .lock()
                .unwrap()
                .get(login)
                .cloned()
                .ok_or(AdminError::NoSuchAccount)
        }
        fn list_accounts(&self) -> Result<Vec<Account>, AdminError> {
            Ok(self.0.lock().unwrap().values().cloned().collect())
        }
        fn write_account(
            &self,
            edit: &AccountEdit,
            check: WriteCheck<'_>,
        ) -> Result<Account, AdminError> {
            // Unlocked for the check, which reads accounts too.
            let existing = self.read_account(&edit.login).ok();
            let mut after = existing
                .clone()
                .unwrap_or_else(|| account(&edit.login, AccessBits::empty()));
            if let Some(access) = edit.access {
                after = account(&edit.login, access);
            }
            check(existing.as_ref(), &after)?;
            self.0
                .lock()
                .unwrap()
                .insert(edit.login.clone(), after.clone());
            Ok(after)
        }
        fn delete_account(
            &self,
            login: &str,
            check: &dyn Fn(&Account) -> Result<(), AdminError>,
        ) -> Result<(), AdminError> {
            check(&self.read_account(login)?)?;
            self.0.lock().unwrap().remove(login);
            Ok(())
        }
    }

    const USERS: [u8; 4] = [
        bit::READ_USERS,
        bit::CREATE_USERS,
        bit::MODIFY_USERS,
        bit::DELETE_USERS,
    ];

    /// A core with `root`, who may do anything to accounts, logged in, and
    /// `bob`, who may chat, not yet.
    fn server() -> (Core, Arc<Accounts>, Uid) {
        let accounts = Arc::new(Accounts::default());
        let chat = AccessBits::empty().with(bit::SEND_CHAT);
        let root = USERS.iter().fold(chat, |a, b| a.with(*b));
        for a in [account("root", root), account("bob", chat)] {
            accounts.0.lock().unwrap().insert(a.login.clone(), a);
        }
        let core = Core::new().with_admin(accounts.clone());
        let (uid, _) = test_attach(&core, "root", root);
        (core, accounts, uid)
    }

    #[test]
    fn a_login_attached_after_its_account_changed_is_brought_up_to_date() {
        let (core, _, root) = server();
        // Bob's login reads the account, then root curbs it before bob's
        // session is on the roster to be told.
        let epoch = core.account_epoch();
        let edit = AccountEdit {
            login: "bob".into(),
            access: Some(AccessBits::empty()),
            ..Default::default()
        };
        core.account_write(root, &edit, WriteMode::Modify).unwrap();
        let (bob, _) = test_attach(&core, "bob", AccessBits::empty().with(bit::SEND_CHAT));
        assert!(core.account_settled(bob, epoch));
        assert_eq!(core.access_of(bob), Some(AccessBits::empty()));
    }

    #[test]
    fn a_login_attached_after_its_account_was_deleted_is_refused() {
        let (core, _, root) = server();
        let epoch = core.account_epoch();
        core.account_delete(root, "bob").unwrap();
        let (bob, _) = test_attach(&core, "bob", AccessBits::empty().with(bit::SEND_CHAT));
        assert!(!core.account_settled(bob, epoch));
    }

    #[test]
    fn a_login_nothing_changed_under_is_not_read_again() {
        let (core, accounts, _) = server();
        let epoch = core.account_epoch();
        let (bob, _) = test_attach(&core, "bob", AccessBits::empty().with(bit::SEND_CHAT));
        // Gone from the store, unbeknownst to anyone who would bump the
        // epoch: a settled login does not look.
        accounts.0.lock().unwrap().remove("bob");
        assert!(core.account_settled(bob, epoch));
    }

    fn bits(bits: &[u8]) -> AccessBits {
        bits.iter().fold(AccessBits::empty(), |a, b| a.with(*b))
    }

    /// What session `uid` may do as the roster has it, and as it was
    /// last told.
    fn seen(core: &Core, uid: Uid, rx: &mut crate::Events) -> (AccessBits, bool, Option<Account>) {
        let told = crate::roster::drain(rx)
            .into_iter()
            .rev()
            .find_map(|e| match e {
                Event::AccountChanged(a) => Some(*a),
                _ => None,
            });
        let r = core.roster.lock().unwrap();
        let s = &r.users[&uid];
        (s.access, s.attach_news, told)
    }

    #[test]
    fn past_bulk_rows_a_wire_that_syncs_is_told_its_roster_is_stale() {
        let ng = crate::Transport {
            roles: true,
            ..Default::default()
        };
        // How many accounts change, whether only their roles do, and what
        // each wire hears: user_changed and roster_stale on ng, then
        // user_changed on classic.
        for (n, only_roles, heard) in [
            (2, false, (2, 0, 2)),
            (3, false, (0, 1, 3)),
            (2, true, (2, 0, 0)),
            (3, true, (0, 1, 0)),
        ] {
            let accounts = Arc::new(Accounts::default());
            let core = Core::new().with_admin(accounts.clone()).with_bulk_rows(2);
            let logins: Vec<String> = (0..n).map(|i| format!("u{i}")).collect();
            for login in logins.iter().map(String::as_str).chain(["ng", "classic"]) {
                let a = account(login, AccessBits::empty());
                accounts.0.lock().unwrap().insert(a.login.clone(), a);
            }
            let (_, mut on_ng) = test_attach_on(&core, "ng", AccessBits::empty(), ng.clone());
            let (_, mut on_classic) = test_attach(&core, "classic", AccessBits::empty());
            for login in &logins {
                test_attach(&core, login, AccessBits::empty());
                let mut a = account(login, AccessBits::empty());
                if only_roles {
                    a.roles = vec!["r".into()];
                } else {
                    a = account(login, bits(&[bit::DISCONNECT_USERS]));
                }
                accounts.0.lock().unwrap().insert(a.login.clone(), a);
            }
            crate::roster::drain(&mut on_ng);
            crate::roster::drain(&mut on_classic);
            core.reload_accounts();
            let count = |events: &[Event]| {
                let changed = events
                    .iter()
                    .filter(|e| matches!(e, Event::Changed(_)))
                    .count();
                let stale = events
                    .iter()
                    .filter(|e| matches!(e, Event::RosterStale))
                    .count();
                (changed, stale)
            };
            let (ng_changed, ng_stale) = count(&crate::roster::drain(&mut on_ng));
            let (classic_changed, classic_stale) = count(&crate::roster::drain(&mut on_classic));
            assert_eq!(classic_stale, 0);
            assert_eq!(
                (ng_changed, ng_stale, classic_changed),
                heard,
                "{n} {only_roles}"
            );
        }
    }

    #[test]
    fn a_sessions_mask_outlasts_edits_and_reloads_of_its_account() {
        let (core, accounts, root) = server();
        let chat = bits(&[bit::READ_CHAT, bit::SEND_CHAT, bit::SEND_MEDIA]);
        let root_bits = USERS
            .iter()
            .fold(chat.with(bit::SEND_MSGS), |a, b| a.with(*b));
        for a in [account("root", root_bits), account("bob", chat)] {
            accounts.0.lock().unwrap().insert(a.login.clone(), a);
        }
        let (bob, mut rx) = test_attach(&core, "bob", AccessBits::empty());
        let mask = DenyMask {
            access: bits(&[bit::READ_CHAT, bit::SEND_MEDIA]),
            ..Default::default()
        };
        assert!(
            !core.set_session_mask(bob, mask),
            "no account to derive from"
        );
        core.reload_accounts();
        assert_eq!(seen(&core, bob, &mut rx).0, chat.with(bit::CHAT_HISTORY));

        // Bit 56 and attach_news derive from what the mask denies, so
        // they go with it.
        assert!(core.set_session_mask(bob, mask));
        let (access, attach_news, told) = seen(&core, bob, &mut rx);
        assert_eq!(access, bits(&[bit::SEND_CHAT]));
        assert!(!attach_news);
        let told = told.unwrap();
        assert_eq!((told.access, told.attach_news), (access, false));

        let edit = AccountEdit {
            login: "bob".into(),
            access: Some(chat.with(bit::SEND_MSGS)),
            ..Default::default()
        };
        core.account_write(root, &edit, WriteMode::Modify).unwrap();
        let (access, attach_news, told) = seen(&core, bob, &mut rx);
        assert_eq!(access, bits(&[bit::SEND_CHAT, bit::SEND_MSGS]));
        assert!(!attach_news);
        assert_eq!(told.unwrap().access, access);

        accounts
            .0
            .lock()
            .unwrap()
            .insert("bob".into(), account("bob", chat.with(bit::VOICE_CHAT)));
        core.reload_accounts();
        let (access, attach_news, _) = seen(&core, bob, &mut rx);
        assert_eq!(access, bits(&[bit::SEND_CHAT, bit::VOICE_CHAT]));
        assert!(!attach_news);

        assert!(core.set_session_mask(bob, DenyMask::default()));
        let (access, attach_news, told) = seen(&core, bob, &mut rx);
        assert_eq!(access, chat.with(bit::VOICE_CHAT).with(bit::CHAT_HISTORY));
        assert!(attach_news);
        assert_eq!(told.unwrap().access, access);
    }

    #[test]
    fn whom_an_administrator_may_change_is_judged_by_their_account_unmasked() {
        let (core, accounts, root) = server();
        let media = bits(&[bit::SEND_CHAT, bit::SEND_MEDIA]);
        let root_bits = USERS.iter().fold(media, |a, b| a.with(*b));
        accounts
            .0
            .lock()
            .unwrap()
            .insert("root".into(), account("root", root_bits));
        core.reload_accounts();
        let mask = DenyMask {
            access: bits(&[bit::SEND_MEDIA]),
            ..Default::default()
        };
        assert!(core.set_session_mask(root, mask));
        let edit = AccountEdit {
            login: "bob".into(),
            access: Some(media),
            ..Default::default()
        };
        core.account_write(root, &edit, WriteMode::Modify).unwrap();
    }
}
