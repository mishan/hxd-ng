//! Users on a link (the extension's "The User Group"): one user, as a group
//! of fields opened by `DATA_LINK_USER_ID`, kept whole as it arrived so a
//! relay can pass it on (Relaying Fields).

use hxd_core::server_link::LocalUser;

use crate::server::{admissible_extra, ServerId};
use crate::wire::{field, Field};

/// The longest name a user group may carry, in bytes (Text on a Link).
pub const MAX_NAME: usize = 255;

pub mod flag {
    pub const AWAY: u16 = 1 << 0;
    pub const ADMIN: u16 = 1 << 1;
    pub const REFUSES_MESSAGES: u16 = 1 << 2;
    pub const REFUSES_CHAT: u16 = 1 << 3;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserGroup {
    /// The user's ID as the sender of the group uses it.
    pub id: u16,
    pub home: ServerId,
    pub name: String,
    pub icon: u16,
    pub flags: u16,
    pub color: Option<u32>,
    pub exclude: Vec<ServerId>,
    /// The group as it arrived, every field in order.
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserGroupError {
    NotAGroup,
    Missing(u16),
    Malformed(u16),
    /// Over a bound, or carrying a field that never crosses a link: a
    /// group like that is dropped whole, never trimmed.
    Inadmissible(&'static str),
}

/// A local user's group, as this server exports it.
pub fn of_local(user: &LocalUser, home: ServerId) -> Vec<Field> {
    let mut f = vec![
        Field::u16(field::USER_ID, user.uid),
        Field::new(field::SERVER_ID, home.0),
        Field::new(field::USER_NAME, user.nick.as_bytes()),
        Field::u16(field::USER_ICON, user.icon),
        // Private chat never crosses a link.
        Field::u16(
            field::USER_FLAGS,
            flag::REFUSES_CHAT | if user.away { flag::AWAY } else { 0 },
        ),
    ];
    if let Some(c) = user.color {
        f.push(Field::u32(field::COLOR, c));
    }
    f.extend(
        user.exclude
            .iter()
            .map(|id| Field::new(field::EXCLUDE, *id)),
    );
    f
}

impl UserGroup {
    /// The group that opens `fields`, which must start with its user ID
    /// and runs to the next one.
    pub fn parse(fields: &[Field]) -> Result<UserGroup, UserGroupError> {
        let (first, rest) = fields.split_first().ok_or(UserGroupError::NotAGroup)?;
        if first.id != field::USER_ID {
            return Err(UserGroupError::NotAGroup);
        }
        let id = u16::from_be_bytes(
            first
                .fixed()
                .ok_or(UserGroupError::Malformed(field::USER_ID))?,
        );
        let (mut home, mut name, mut icon, mut flags, mut color) = (None, None, None, None, None);
        let mut exclude = Vec::new();
        let mut extra = Vec::new();
        let mut kept = vec![first.clone()];
        let malformed = |f: &Field| UserGroupError::Malformed(f.id);
        // A baseline field given twice is not a later value: which one a
        // relay or a client would honor is anyone's guess.
        let once = |given: bool, f: &Field| match given {
            true => Err(malformed(f)),
            false => Ok(()),
        };
        let short = |f: &Field| {
            f.uint()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| malformed(f))
        };
        for f in rest.iter().take_while(|f| f.id != field::USER_ID) {
            match f.id {
                // The transaction's, not the group's, wherever it sits.
                field::MORE => continue,
                field::SERVER_ID => {
                    once(home.is_some(), f)?;
                    home = Some(ServerId(f.fixed().ok_or_else(|| malformed(f))?))
                }
                field::USER_NAME => {
                    once(name.is_some(), f)?;
                    name = Some(String::from_utf8(f.data.clone()).map_err(|_| malformed(f))?)
                }
                field::USER_ICON => {
                    once(icon.is_some(), f)?;
                    icon = Some(short(f)?)
                }
                field::USER_FLAGS => {
                    once(flags.is_some(), f)?;
                    flags = Some(short(f)?)
                }
                field::COLOR => {
                    once(color.is_some(), f)?;
                    color = Some(f.uint().ok_or_else(|| malformed(f))?)
                }
                field::EXCLUDE => exclude.push(ServerId(f.fixed().ok_or_else(|| malformed(f))?)),
                _ => extra.push(f.clone()),
            }
            kept.push(f.clone());
        }
        let name = name.ok_or(UserGroupError::Missing(field::USER_NAME))?;
        if name.len() > MAX_NAME {
            return Err(UserGroupError::Inadmissible("name too long"));
        }
        admissible_extra(&extra).map_err(UserGroupError::Inadmissible)?;
        Ok(UserGroup {
            id,
            home: home.ok_or(UserGroupError::Missing(field::SERVER_ID))?,
            name,
            icon: icon.ok_or(UserGroupError::Missing(field::USER_ICON))?,
            flags: flags.ok_or(UserGroupError::Missing(field::USER_FLAGS))?,
            color,
            exclude,
            fields: kept,
        })
    }

    /// Every group in a Link Snapshot (901) part, in order. A group that
    /// cannot be accepted is reported where it stands, so the rest can be.
    pub fn parse_all(fields: &[Field]) -> Vec<Result<UserGroup, UserGroupError>> {
        fields
            .iter()
            .enumerate()
            .filter(|(_, f)| f.id == field::USER_ID)
            .map(|(i, _)| UserGroup::parse(&fields[i..]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(uid: u16, nick: &str) -> LocalUser {
        LocalUser {
            uid,
            nick: nick.into(),
            icon: 128,
            away: true,
            color: Some(0xff8000),
            exclude: vec![],
        }
    }

    #[test]
    fn exported_groups_parse_back_with_unknown_fields_kept_in_place() {
        let home = ServerId([5; 8]);
        let mut fields = of_local(&local(3, "ann"), home);
        fields.push(Field::new(0x0700, b"later".to_vec()));
        fields.push(Field::new(field::EXCLUDE, [9; 8]));
        fields.extend(of_local(&local(4, "bob"), home));
        fields.push(Field::u16(field::MORE, 1));
        let parsed: Vec<UserGroup> = UserGroup::parse_all(&fields)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert_eq!((parsed[0].id, parsed[0].name.as_str()), (3, "ann"));
        assert_eq!(parsed[0].flags, flag::AWAY | flag::REFUSES_CHAT);
        assert_eq!(parsed[0].exclude, [ServerId([9; 8])]);
        assert_eq!(
            parsed[0].fields.len(),
            8,
            "every field of its own, the unknown one included"
        );
        assert_eq!(parsed[1].fields, of_local(&local(4, "bob"), home));
    }

    #[test]
    fn a_group_that_cannot_cross_is_refused_whole() {
        let home = ServerId([5; 8]);
        let long = of_local(&local(3, &"n".repeat(MAX_NAME + 1)), home);
        assert_eq!(
            UserGroup::parse(&long),
            Err(UserGroupError::Inadmissible("name too long"))
        );
        let mut login = of_local(&local(3, "ann"), home);
        login.push(Field::new(105, b"ann-login".to_vec()));
        assert!(matches!(
            UserGroup::parse(&login),
            Err(UserGroupError::Inadmissible(_))
        ));
        let mut no_home = of_local(&local(3, "ann"), home);
        no_home.retain(|f| f.id != field::SERVER_ID);
        assert_eq!(
            UserGroup::parse(&no_home),
            Err(UserGroupError::Missing(field::SERVER_ID))
        );
        let mut twice = of_local(&local(3, "ann"), home);
        twice.push(Field::new(field::USER_NAME, b"bob".to_vec()));
        assert_eq!(
            UserGroup::parse(&twice),
            Err(UserGroupError::Malformed(field::USER_NAME))
        );
    }

    #[test]
    fn numbers_may_come_in_either_width_the_wire_allows() {
        let mut wide = of_local(&local(3, "ann"), ServerId([5; 8]));
        for f in &mut wide {
            if f.id == field::USER_ICON {
                *f = Field::u32(field::USER_ICON, 128);
            }
        }
        assert_eq!(UserGroup::parse(&wide).unwrap().icon, 128);
        for f in &mut wide {
            if f.id == field::USER_FLAGS {
                *f = Field::u32(field::USER_FLAGS, 1 << 16);
            }
        }
        assert_eq!(
            UserGroup::parse(&wide),
            Err(UserGroupError::Malformed(field::USER_FLAGS))
        );
    }
}
