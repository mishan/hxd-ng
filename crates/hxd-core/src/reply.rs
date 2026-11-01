//! What a line or message answers (`docs/hotline-ng.md` §7.3): a
//! reference its sender's client names beside the text, kept and relayed
//! as sent and never resolved or quoted by the server. The server checks
//! only that it stays within the conversation it is sent in
//! ([`crate::chat::ChatError::ReplyScope`]).

use crate::history::LineId;
use crate::inbox::{MessageGuid, MessageRef};

/// What a reply's reference may take, packed: one target, never a
/// client's bytes passed on unparsed.
pub const MAX_PACKED: usize = 128;

/// The message a reply answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A public line, by its log id, in the room it was said in (0 for
    /// the lobby), which is the room the reply is said in.
    Line { room: u32, id: LineId },
    /// An instant message, by its sender's login and its guid, which
    /// both parties hold.
    Im { login: String, guid: MessageGuid },
    /// A stored private or instant message, by its reference.
    Pm(MessageRef),
    /// A signed line or message, by its signer, its id and the hash of
    /// its signed object. Unsigned targets carry no hash: the server
    /// could rewrite a line and its hash together.
    Signed {
        signer: [u8; 32],
        id: [u8; 16],
        hash: [u8; 32],
    },
}

const LINE: u8 = 1;
const IM: u8 = 2;
const SIGNED: u8 = 3;
const PM: u8 = 5;

/// The 16 bytes a guid spells, as a signed object's id is.
pub fn guid_bytes(g: &MessageGuid) -> [u8; 16] {
    let hex = g.as_str().replace('-', "");
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("a guid is hex");
    }
    out
}

/// [`guid_bytes`] back: any 16 bytes are a guid.
pub fn guid_of(b: &[u8]) -> Option<MessageGuid> {
    MessageGuid::parse(&b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

impl Reply {
    /// An instant message target, unless its login is too long to keep.
    pub fn im(login: String, guid: MessageGuid) -> Option<Self> {
        (!login.is_empty() && 18 + login.len() <= MAX_PACKED).then_some(Reply::Im { login, guid })
    }

    /// How the stores keep it: a kind byte and the kind's fields.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_PACKED);
        match self {
            Reply::Line { room, id } => {
                out.push(LINE);
                out.extend_from_slice(&room.to_be_bytes());
                out.extend_from_slice(&id.to_be_bytes());
            }
            Reply::Im { login, guid } => {
                out.push(IM);
                out.extend_from_slice(&guid_bytes(guid));
                out.push(login.len() as u8);
                out.extend_from_slice(login.as_bytes());
            }
            Reply::Signed { signer, id, hash } => {
                out.push(SIGNED);
                out.extend_from_slice(signer);
                out.extend_from_slice(id);
                out.extend_from_slice(hash);
            }
            Reply::Pm(r) => {
                out.push(PM);
                out.extend_from_slice(r);
            }
        }
        out
    }

    /// [`Reply::pack`]'s bytes back, or `None` for bytes it never wrote.
    pub fn unpack(b: &[u8]) -> Option<Self> {
        let (&kind, rest) = b.split_first()?;
        match kind {
            LINE if rest.len() == 12 => Some(Reply::Line {
                room: u32::from_be_bytes(rest[..4].try_into().ok()?),
                id: u64::from_be_bytes(rest[4..].try_into().ok()?),
            }),
            IM if rest.len() > 17 && rest.len() == 17 + usize::from(rest[16]) => Reply::im(
                String::from_utf8(rest[17..].to_vec()).ok()?,
                guid_of(&rest[..16])?,
            ),
            SIGNED if rest.len() == 80 => Some(Reply::Signed {
                signer: rest[..32].try_into().ok()?,
                id: rest[32..48].try_into().ok()?,
                hash: rest[48..].try_into().ok()?,
            }),
            PM if rest.len() == 16 => Some(Reply::Pm(rest.try_into().ok()?)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_packs_within_its_bound_and_back() {
        let guid = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
        for re in [
            Reply::Line { room: 7, id: 98124 },
            Reply::im("alice".into(), guid.clone()).unwrap(),
            Reply::im("a".repeat(MAX_PACKED - 18), guid).unwrap(),
            Reply::Pm([9; 16]),
            Reply::Signed {
                signer: [1; 32],
                id: [2; 16],
                hash: [3; 32],
            },
        ] {
            let packed = re.pack();
            assert!(packed.len() <= MAX_PACKED, "{re:?}");
            assert_eq!(Reply::unpack(&packed), Some(re));
        }
    }

    #[test]
    fn what_was_never_packed_does_not_unpack() {
        let guid = MessageGuid::parse("5f5e1000-1234-4abc-89ab-000000000001").unwrap();
        assert_eq!(Reply::im("a".repeat(MAX_PACKED - 17), guid), None);
        let line = Reply::Line { room: 0, id: 1 }.pack();
        for bad in [&[][..], &[0], &[4, 0], &line[..12], &[PM; 16]] {
            assert_eq!(Reply::unpack(bad), None, "{bad:?}");
        }
    }
}
