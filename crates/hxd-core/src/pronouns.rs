//! An account's pronouns: a short free text its user sets, shown beside
//! the name. Kept in the account's file (`[profile] pronouns`), set by
//! the user alone, and shown where `[extra] pronouns` and `[server]
//! pronouns` allow.

use std::time::Duration;

use crate::account::{Account, DenyMask};
use crate::roster::{Core, RosterInner, Uid, UserSession};

/// The longest value, in characters.
pub const MAX_CHARS: usize = 32;

/// How long an account waits after a change before it may make another:
/// each is a file write, and is shown wherever the account is.
pub const INTERVAL: Duration = Duration::from_secs(10);

/// What User Change (304) costs in mhxd's spam table, which a set from
/// the system account's `/pronouns` costs too.
pub const SPAM_POINTS: u32 = 20;

/// Whether `value` may be someone's pronouns: 1 to [`MAX_CHARS`]
/// characters, held to a display name's rules, and never two spaces in a
/// row, which a classic client's Get User Info could wrap into what
/// looks like a line of its own.
pub fn valid(value: &str) -> bool {
    value.chars().count() <= MAX_CHARS
        && hl_identity::names::is_shown_name(value)
        && !value.contains("  ")
}

/// Why pronouns were not set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PronounsError {
    /// This server shows none (`[server] pronouns`), or keeps no
    /// accounts to set them in.
    Off,
    /// The session has no account of its own to keep them, or its
    /// account may not show them (`[extra] pronouns`).
    NotAllowed,
    /// Not a value [`valid`] accepts.
    BadValue,
    /// The account changed them less than [`INTERVAL`] ago; it may again
    /// after this long.
    RateLimited(Duration),
    /// The account store failed; it is in the log.
    Failed,
}

/// The pronouns `account` shows under `mask`, on a server that shows
/// any.
pub(crate) fn shown(account: &Account, mask: &DenyMask) -> Option<String> {
    let (_, x) = account.config.derive(account.is_person(), mask);
    account.pronouns.clone().filter(|_| x.pronouns)
}

impl RosterInner {
    /// The pronouns `s` shows.
    pub(crate) fn pronouns_shown(&self, s: &UserSession) -> Option<String> {
        shown(
            s.account.as_deref().filter(|_| !self.pronouns_off)?,
            &s.mask,
        )
    }
}

impl Core {
    /// Show no pronouns, and take none (`[server] pronouns = false`).
    pub fn with_pronouns(self, on: bool) -> Self {
        self.roster.lock().unwrap().pronouns_off = !on;
        self
    }

    /// Does this server show pronouns, and keep accounts to set them in?
    pub fn pronouns_enabled(&self) -> bool {
        self.admin.is_some() && !self.roster.lock().unwrap().pronouns_off
    }

    /// The pronouns session `uid` shows.
    pub fn pronouns_of(&self, uid: Uid) -> Option<String> {
        let r = self.roster.lock().unwrap();
        r.pronouns_shown(r.users.get(&uid)?)
    }

    /// Set session `uid`'s account's pronouns, or clear them with
    /// `None`. A value is refused, never cut. Answers whether they
    /// changed: setting what is there writes nothing and spends no turn.
    /// Store I/O, so off the reactor.
    pub fn set_pronouns(&self, uid: Uid, value: Option<&str>) -> Result<bool, PronounsError> {
        let admin = self.admin.as_deref().ok_or(PronounsError::Off)?;
        let (login, account, mask) = {
            let r = self.roster.lock().unwrap();
            if r.pronouns_off {
                return Err(PronounsError::Off);
            }
            let s = r.users.get(&uid).ok_or(PronounsError::NotAllowed)?;
            let account = s.account.as_deref().filter(|_| !s.system);
            let account = account.ok_or(PronounsError::NotAllowed)?;
            (s.login.clone(), account.clone(), s.mask)
        };
        // A shared login keeps nothing of anyone's. Clearing is never
        // refused to the account's own user: what is hidden may still
        // be taken down.
        let (_, x) = account.config.derive(account.is_person(), &mask);
        if !account.is_person() || (value.is_some() && !x.pronouns) {
            return Err(PronounsError::NotAllowed);
        }
        if value.is_some_and(|v| !valid(v)) {
            return Err(PronounsError::BadValue);
        }
        let _writing = self.begin_account_write();
        // As it is now: another session of the account may have changed
        // it while this one waited.
        let now_set = {
            let r = self.roster.lock().unwrap();
            r.users
                .get(&uid)
                .and_then(|s| s.account.as_ref()?.pronouns.clone())
        };
        if now_set.as_deref() == value {
            return Ok(false);
        }
        let now = self.clock.now();
        {
            let mut turns = self.pronoun_turns.lock().unwrap();
            turns.retain(|_, at| now.saturating_duration_since(*at) < INTERVAL);
            if let Some(at) = turns.get(&login) {
                return Err(PronounsError::RateLimited(
                    INTERVAL - now.saturating_duration_since(*at),
                ));
            }
        }
        let written = admin.write_pronouns(&login, value).map_err(|e| {
            tracing::warn!(login, "pronouns: {e}");
            PronounsError::Failed
        })?;
        self.pronoun_turns
            .lock()
            .unwrap()
            .insert(login.clone(), now);
        // Only the value: what else the file says now reaches the
        // account's sessions as an edit's would, on the next reload.
        let mut r = self.roster.lock().unwrap();
        for s in r.users.values_mut().filter(|s| s.login == login) {
            if let Some(a) = s.account.as_mut() {
                a.pronouns.clone_from(&written.pronouns);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_is_held_to_a_names_rules_and_its_length() {
        let max = "a".repeat(MAX_CHARS);
        let over = "a".repeat(MAX_CHARS + 1);
        // Four bytes a character: the bound is characters.
        let wide = "\u{1f308}".repeat(MAX_CHARS);
        for (value, ok) in [
            ("she/her", true),
            ("any pronouns", true),
            ("\u{5f7c}/\u{5979}", true),
            (max.as_str(), true),
            (wide.as_str(), true),
            (over.as_str(), false),
            ("", false),
            (" ", false),
            (" she/her", false),
            ("she/her ", false),
            ("she  her", false),
            ("she/her\r   login: admin", false),
            ("she\nher", false),
            ("she\ther", false),
            ("she\u{200b}her", false),
            ("she\u{202e}her", false),
        ] {
            assert_eq!(valid(value), ok, "{value:?}");
        }
    }
}
