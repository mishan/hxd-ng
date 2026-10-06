//! The extension's numbers, and transactions as ordered field lists.
//!
//! A link transaction is an ordinary Hotline frame whose fields belong to
//! groups by position: everything from a group's opening field up to the
//! next one. Relaying Fields requires a relay to pass a group on whole and
//! in order, including fields it does not know, so a transaction is kept
//! as the list it arrived as, not parsed into a struct and rebuilt.

use crate::server::{ServerGroup, ServerGroupError};

/// The link protocol version this crate speaks.
pub const VERSION: u16 = 1;

pub mod tx {
    pub const HELLO: u32 = 900;
    pub const SNAPSHOT: u32 = 901;
    pub const USER_UPDATE: u32 = 902;
    pub const USER_GONE: u32 = 903;
    pub const CHAT: u32 = 904;
    pub const PRIVATE_MESSAGE: u32 = 905;
    pub const USER_INFO: u32 = 906;
    pub const KICK: u32 = 907;
    pub const BAN: u32 = 908;
    pub const UNBAN: u32 = 909;
    pub const PING: u32 = 910;
    pub const CLOSE: u32 = 911;
    pub const SERVERS: u32 = 912;
    pub const SERVER_UPDATE: u32 = 913;
    pub const SERVER_GONE: u32 = 914;
}

pub mod field {
    pub const ERROR: u16 = 100;
    pub const DATA: u16 = 101;
    pub const USER_NAME: u16 = 102;
    pub const USER_ICON: u16 = 104;
    pub const CHAT_OPTIONS: u16 = 109;
    pub const USER_FLAGS: u16 = 112;
    pub const OPTIONS: u16 = 113;
    pub const QUOTING: u16 = 214;
    pub const COLOR: u16 = 0x0500;

    pub const LINK_VERSION: u16 = 0x0630;
    pub const FEATURES: u16 = 0x0631;
    pub const SERVER_NAME: u16 = 0x0632;
    pub const EPOCH: u16 = 0x0633;
    pub const USER_ID: u16 = 0x0634;
    pub const TARGET_ID: u16 = 0x0635;
    pub const MORE: u16 = 0x0636;
    pub const REASON: u16 = 0x0637;
    pub const BAN_ID: u16 = 0x0638;
    pub const DURATION: u16 = 0x0639;
    pub const SERVER_ID: u16 = 0x063A;
    pub const TAG: u16 = 0x063B;
    pub const HOPS: u16 = 0x063C;
    pub const EXCLUDE: u16 = 0x063D;
    pub const REQUESTER: u16 = 0x063E;
    pub const LINE_ID: u16 = 0x063F;
    pub use hxd_session::peer::field::{KEY_PROOF, SERVER_KEY};
}

pub mod feature {
    pub const PUBLIC_CHAT: u32 = 1 << 0;
    pub const PRIVATE_MESSAGES: u32 = 1 << 1;
    pub const USER_INFO: u32 = 1 << 2;
    pub const TRANSIT: u32 = 1 << 3;
}

/// `DATA_LINK_REASON`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Reason {
    Ok = 0,
    Disconnected = 1,
    NotExported = 2,
    UnknownUser = 3,
    RefusesMessages = 4,
    RateLimited = 5,
    FeatureNotNegotiated = 6,
    UnknownBan = 7,
    Unreachable = 8,
    Excluded = 9,
    Banned = 10,
    InvalidRequester = 11,
    RefusedFields = 12,
    Shutdown = 16,
    Unlinked = 17,
    ProtocolError = 18,
    VersionUnsupported = 19,
    Replaced = 20,
    Loop = 21,
    TagConflict = 22,
    HopLimit = 23,
    Suspended = 24,
}

impl Reason {
    pub fn from_wire(v: u16) -> Option<Reason> {
        use Reason::*;
        Some(match v {
            0 => Ok,
            1 => Disconnected,
            2 => NotExported,
            3 => UnknownUser,
            4 => RefusesMessages,
            5 => RateLimited,
            6 => FeatureNotNegotiated,
            7 => UnknownBan,
            8 => Unreachable,
            9 => Excluded,
            10 => Banned,
            11 => InvalidRequester,
            12 => RefusedFields,
            16 => Shutdown,
            17 => Unlinked,
            18 => ProtocolError,
            19 => VersionUnsupported,
            20 => Replaced,
            21 => Loop,
            22 => TagConflict,
            23 => HopLimit,
            24 => Suspended,
            _ => return None,
        })
    }
}

/// One field of a transaction, kept as it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub id: u16,
    pub data: Vec<u8>,
}

impl Field {
    pub fn new(id: u16, data: impl Into<Vec<u8>>) -> Field {
        Field {
            id,
            data: data.into(),
        }
    }

    pub fn u16(id: u16, v: u16) -> Field {
        Field::new(id, v.to_be_bytes())
    }

    pub fn u32(id: u16, v: u32) -> Field {
        Field::new(id, v.to_be_bytes())
    }

    /// A UInt16 or UInt32 field's value; anything else is malformed.
    pub fn uint(&self) -> Option<u32> {
        match *self.data.as_slice() {
            [a, b] => Some(u16::from_be_bytes([a, b]).into()),
            [a, b, c, d] => Some(u32::from_be_bytes([a, b, c, d])),
            _ => None,
        }
    }

    pub fn fixed<const N: usize>(&self) -> Option<[u8; N]> {
        self.data.as_slice().try_into().ok()
    }
}

/// A frame's fields, in order.
pub fn fields(frame: &hxd_session::frame::Frame) -> Vec<Field> {
    frame
        .chunks()
        .map(|c| Field::new(c.tag, c.data.to_vec()))
        .collect()
}

/// Fields as `pack_frame` takes them.
pub fn chunks(fields: &[Field]) -> Vec<(u16, Vec<u8>)> {
    fields.iter().map(|f| (f.id, f.data.clone())).collect()
}

/// The first field `id` in `fields`.
pub fn find(fields: &[Field], id: u16) -> Option<&Field> {
    fields.iter().find(|f| f.id == id)
}

/// Link Hello (900): the first link transaction in each direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u16,
    pub features: u32,
    pub epoch: [u8; 8],
    pub server: ServerGroup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelloError {
    Missing(u16),
    Server(ServerGroupError),
    /// Hello describes the sender, which is no hops away.
    Hops,
}

impl Hello {
    pub fn to_fields(&self) -> Vec<Field> {
        let mut f = vec![
            Field::u16(field::LINK_VERSION, self.version),
            Field::u32(field::FEATURES, self.features),
            Field::new(field::EPOCH, self.epoch),
        ];
        f.extend(self.server.to_fields());
        f
    }

    pub fn parse(fields: &[Field]) -> Result<Hello, HelloError> {
        let get = |id| find(fields, id).ok_or(HelloError::Missing(id));
        let version = u16::from_be_bytes(
            get(field::LINK_VERSION)?
                .fixed()
                .ok_or(HelloError::Missing(field::LINK_VERSION))?,
        );
        let features = get(field::FEATURES)?
            .uint()
            .ok_or(HelloError::Missing(field::FEATURES))?;
        let epoch = get(field::EPOCH)?
            .fixed()
            .ok_or(HelloError::Missing(field::EPOCH))?;
        let start = fields
            .iter()
            .position(|f| f.id == field::SERVER_ID)
            .ok_or(HelloError::Missing(field::SERVER_ID))?;
        let server = ServerGroup::parse(&fields[start..]).map_err(HelloError::Server)?;
        if server.hops != 0 {
            return Err(HelloError::Hops);
        }
        Ok(Hello {
            version,
            features,
            epoch,
            server,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> Hello {
        Hello {
            version: VERSION,
            features: feature::PUBLIC_CHAT | feature::PRIVATE_MESSAGES,
            epoch: [7; 8],
            server: ServerGroup {
                id: crate::ServerId([1; 8]),
                tag: "hx".into(),
                name: "hxd-ng".into(),
                hops: 0,
                color: Some(0x3a7bd5),
                extra: vec![],
            },
        }
    }

    #[test]
    fn hello_round_trips_and_ignores_fields_before_its_server_group() {
        let h = hello();
        let mut f = vec![Field::new(0x0700, b"from a later version".to_vec())];
        f.extend(h.to_fields());
        assert_eq!(Hello::parse(&f), Ok(h));
    }

    #[test]
    fn a_hello_that_is_not_about_its_sender_is_refused() {
        let mut h = hello();
        h.server.hops = 1;
        assert_eq!(Hello::parse(&h.to_fields()), Err(HelloError::Hops));
        let mut f = hello().to_fields();
        f.retain(|f| f.id != field::EPOCH);
        assert_eq!(Hello::parse(&f), Err(HelloError::Missing(field::EPOCH)));
    }
}
