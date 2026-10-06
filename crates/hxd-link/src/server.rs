//! Servers on a network: their IDs, tags, and the group that describes
//! one (the extension's "The Server Group").

use std::fmt;

use sha2::{Digest, Sha256};

use crate::wire::{field, Field};

/// A server's permanent, network-unique identifier. For a server with a
/// key, the first 8 bytes of the SHA-256 digest of its public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServerId(pub [u8; 8]);

impl ServerId {
    pub fn of_key(public: &[u8; 32]) -> ServerId {
        let digest = Sha256::digest(public);
        ServerId(
            digest[..8]
                .try_into()
                .expect("a SHA-256 digest is 32 bytes"),
        )
    }
}

impl fmt::Debug for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagError {
    Length,
    Character,
}

/// A tag is 1-8 characters of printable ASCII, excluding `@` and
/// whitespace, and compared case-insensitively.
pub fn check_tag(tag: &str) -> Result<(), TagError> {
    if tag.is_empty() || tag.len() > 8 {
        return Err(TagError::Length);
    }
    if !tag.bytes().all(|b| b.is_ascii_graphic() && b != b'@') {
        return Err(TagError::Character);
    }
    Ok(())
}

pub fn same_tag(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The most bytes of fields outside the baseline a group may carry, field
/// headers included (Relaying Fields). A group over it is dropped whole.
pub const MAX_EXTRA: usize = 1024;

/// The longest server name accepted, in bytes: the extension's bound on a
/// user name, for want of one of its own.
pub const MAX_NAME: usize = 255;

/// Fields that carry what a link must never carry (Relaying Fields,
/// "Fields that never cross"): a login, password material, access
/// privileges, a messaging Login, and HOPE's login fields.
fn never_crosses(id: u16) -> bool {
    matches!(id, 105 | 106 | 110 | 0x0600 | 0x0e00..=0x0eff)
}

/// One server, as a group of fields opened by `DATA_LINK_SERVER_ID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerGroup {
    pub id: ServerId,
    pub tag: String,
    pub name: String,
    pub hops: u16,
    pub color: Option<u32>,
    /// Fields outside what this crate reads, kept in order so the group
    /// can be passed on whole (Relaying Fields).
    pub extra: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerGroupError {
    NotAGroup,
    Missing(u16),
    Malformed(u16),
    Tag(TagError),
}

impl ServerGroup {
    /// Whether a received group may be kept and passed on: within the
    /// bounds, and carrying nothing that never crosses a link.
    pub fn admissible(&self) -> Result<(), &'static str> {
        if self.name.len() > MAX_NAME {
            return Err("server name too long");
        }
        if self.extra.iter().any(|f| never_crosses(f.id)) {
            return Err("a field that never crosses a link");
        }
        if self.extra.iter().map(|f| 4 + f.data.len()).sum::<usize>() > MAX_EXTRA {
            return Err("over the field bound");
        }
        Ok(())
    }

    pub fn to_fields(&self) -> Vec<Field> {
        let mut f = vec![
            Field::new(field::SERVER_ID, self.id.0),
            Field::new(field::TAG, self.tag.as_bytes()),
            Field::new(field::SERVER_NAME, self.name.as_bytes()),
            Field::u16(field::HOPS, self.hops),
        ];
        if let Some(c) = self.color {
            f.push(Field::u32(field::COLOR, c));
        }
        f.extend(self.extra.iter().cloned());
        f
    }

    /// The group that opens `fields`, which must start with its server ID
    /// and runs to the next one.
    pub fn parse(fields: &[Field]) -> Result<ServerGroup, ServerGroupError> {
        let (first, rest) = fields.split_first().ok_or(ServerGroupError::NotAGroup)?;
        if first.id != field::SERVER_ID {
            return Err(ServerGroupError::NotAGroup);
        }
        let id = ServerId(
            first
                .fixed()
                .ok_or(ServerGroupError::Malformed(field::SERVER_ID))?,
        );
        let (mut tag, mut name, mut hops, mut color) = (None, None, None, None);
        let mut extra = Vec::new();
        for f in rest.iter().take_while(|f| f.id != field::SERVER_ID) {
            let text =
                || String::from_utf8(f.data.clone()).map_err(|_| ServerGroupError::Malformed(f.id));
            match f.id {
                field::TAG => tag = Some(text()?),
                field::SERVER_NAME => name = Some(text()?),
                field::HOPS => {
                    hops = Some(u16::from_be_bytes(
                        f.fixed().ok_or(ServerGroupError::Malformed(f.id))?,
                    ))
                }
                field::COLOR => color = Some(f.uint().ok_or(ServerGroupError::Malformed(f.id))?),
                // The transaction's, not the group's, wherever it sits.
                field::MORE => {}
                _ => extra.push(f.clone()),
            }
        }
        let tag = tag.ok_or(ServerGroupError::Missing(field::TAG))?;
        check_tag(&tag).map_err(ServerGroupError::Tag)?;
        Ok(ServerGroup {
            id,
            tag,
            name: name.ok_or(ServerGroupError::Missing(field::SERVER_NAME))?,
            hops: hops.ok_or(ServerGroupError::Missing(field::HOPS))?,
            color,
            extra,
        })
    }

    /// Every group in a Link Servers (912) part, in order.
    pub fn parse_all(fields: &[Field]) -> Result<Vec<ServerGroup>, ServerGroupError> {
        let starts: Vec<usize> = fields
            .iter()
            .enumerate()
            .filter(|(_, f)| f.id == field::SERVER_ID)
            .map(|(i, _)| i)
            .collect();
        starts
            .iter()
            .map(|&i| ServerGroup::parse(&fields[i..]))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: u8, tag: &str) -> ServerGroup {
        ServerGroup {
            id: ServerId([id; 8]),
            tag: tag.into(),
            name: format!("server {id}"),
            hops: 1,
            color: None,
            extra: vec![],
        }
    }

    #[test]
    fn tags_follow_the_extensions_rules() {
        for (tag, ok) in [
            ("hl2", true),
            ("ABCDEFGH", true),
            ("", false),
            ("ABCDEFGHI", false),
            ("a@b", false),
            ("a b", false),
            ("caf\u{e9}", false),
        ] {
            assert_eq!(check_tag(tag).is_ok(), ok, "{tag:?}");
        }
        assert!(same_tag("HL2", "hl2"));
    }

    #[test]
    fn groups_split_at_each_server_id_and_keep_unknown_fields_in_order() {
        let mut a = group(1, "a");
        a.extra = vec![
            Field::new(0x0700, b"x".to_vec()),
            Field::new(0x0701, b"y".to_vec()),
        ];
        let b = group(2, "b");
        let mut fields = a.to_fields();
        fields.extend(b.to_fields());
        fields.push(Field::u16(field::MORE, 1));
        let parsed = ServerGroup::parse_all(&fields).unwrap();
        assert_eq!(parsed, vec![a, b]);
    }

    #[test]
    fn a_group_over_its_bounds_or_carrying_what_never_crosses_is_not_admissible() {
        let with = |name: &str, extra: Vec<Field>| ServerGroup {
            name: name.into(),
            extra,
            ..group(1, "a")
        };
        assert!(with("ok", vec![Field::new(0x0700, vec![0; 1020])])
            .admissible()
            .is_ok());
        for g in [
            with(&"n".repeat(MAX_NAME + 1), vec![]),
            with("ok", vec![Field::new(0x0700, vec![0; 1021])]),
            with("ok", vec![Field::new(105, b"login".to_vec())]),
            with("ok", vec![Field::new(0x0e05, vec![1])]),
        ] {
            assert!(g.admissible().is_err(), "{g:?}");
        }
    }

    #[test]
    fn a_group_without_its_required_fields_or_with_a_bad_tag_is_refused() {
        let mut f = group(1, "a").to_fields();
        f.retain(|f| f.id != field::HOPS);
        assert_eq!(
            ServerGroup::parse(&f),
            Err(ServerGroupError::Missing(field::HOPS))
        );
        let f = group(1, "a@b").to_fields();
        assert_eq!(
            ServerGroup::parse(&f),
            Err(ServerGroupError::Tag(TagError::Character))
        );
    }
}
