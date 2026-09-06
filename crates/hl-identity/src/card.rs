//! The user card (`docs/hotline-ng-identity.md` §3.4).
//!
//! A card is the identity's public face: display name, icon, profile, and
//! the attestations it chooses to carry. Servers cache the exact bytes and
//! re-serve them; the `updated` field is the only thing that lets a newer
//! card replace an older one.

use crate::attestation::Attestation;
use crate::cbor::{map, Value};
use crate::error::Error;
use crate::keys::{IdentityKey, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const DOMAIN: &str = "hl-identity/card/v1";

/// Encoded size limit (§3.4).
pub const MAX_BYTES: usize = 16 * 1024;
/// Display-name length limits in characters (§3.4).
pub const NAME_MAX_CHARS: usize = 32;
/// Profile text limit in bytes (§3.4).
pub const PROFILE_MAX_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    pub identity: PublicKey,
    pub updated: u64,
    /// Display name. Callers are expected to NFC-normalise before signing;
    /// this crate checks length only, so two cards can carry visually
    /// identical names with different code points. Servers that enforce
    /// reserved names should normalise on their side too.
    pub name: String,
    pub icon: Option<u64>,
    pub profile: Option<String>,
    /// Attestations that parsed and whose embedded signature verified
    /// against their embedded registrar key. Confirming the registrar key
    /// is the caller's job ([`Attestation::verify_registrar`]).
    pub attestations: Vec<Attestation>,
    /// Vouch objects, unparsed — the federation spec defines them. Kept
    /// as values so a server that doesn't implement vouches can still
    /// re-serve the card byte-exactly (it already does; this is for
    /// callers that want to inspect them).
    pub vouches: Vec<Value>,
    pub links: Vec<String>,
}

impl Card {
    /// A minimal card: identity, name, and the time. Everything else is
    /// set by the caller before signing.
    pub fn new(identity: &IdentityKey, name: impl Into<String>, updated: u64) -> Self {
        Card {
            identity: identity.public(),
            updated,
            name: name.into(),
            icon: None,
            profile: None,
            attestations: Vec::new(),
            vouches: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Build the unsigned map. `attestations` must already be signed
    /// values (see [`Attestation::signed_value`]) because the card's
    /// signer usually isn't the registrar.
    fn unsigned(&self, attestations: Vec<Value>) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("identity", Some(Value::Bytes(self.identity.to_vec()))),
            ("updated", Some(Value::Uint(self.updated))),
            ("name", Some(Value::Text(self.name.clone()))),
            ("icon", self.icon.map(Value::Uint)),
            ("profile", self.profile.clone().map(Value::Text)),
            (
                "attestations",
                if attestations.is_empty() {
                    None
                } else {
                    Some(Value::Array(attestations))
                },
            ),
            (
                "vouches",
                if self.vouches.is_empty() {
                    None
                } else {
                    Some(Value::Array(self.vouches.clone()))
                },
            ),
            (
                "links",
                if self.links.is_empty() {
                    None
                } else {
                    Some(Value::Array(
                        self.links.iter().cloned().map(Value::Text).collect(),
                    ))
                },
            ),
        ])
    }

    /// Sign with the identity key. `attestations` are the signed
    /// attestation objects to embed (the `attestations` field on `self`
    /// is ignored here, since parsed attestations have lost their
    /// signatures). Returns [`Error::TooLarge`] rather than a card no
    /// server will accept.
    pub fn sign(&self, identity: &IdentityKey, attestations: Vec<Value>) -> Result<Vec<u8>, Error> {
        debug_assert_eq!(identity.public(), self.identity);
        self.check_fields()?;
        let bytes = signed::seal(self.unsigned(attestations), |body| {
            identity.sign(DOMAIN, body)
        });
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    fn check_fields(&self) -> Result<(), Error> {
        let chars = self.name.chars().count();
        if chars == 0 || chars > NAME_MAX_CHARS {
            return Err(Error::BadField("name"));
        }
        if self
            .profile
            .as_ref()
            .is_some_and(|p| p.len() > PROFILE_MAX_BYTES)
        {
            return Err(Error::BadField("profile"));
        }
        Ok(())
    }

    /// Decode, check size and fields, verify the card signature against
    /// the embedded identity key, and parse each attestation (an
    /// attestation that fails to parse fails the card: a signer who
    /// embeds garbage is not someone whose card should be cached).
    pub fn parse(bytes: &[u8]) -> Result<Card, Error> {
        if bytes.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let env = Envelope::open(bytes)?;
        let v = &env.value;
        let attestations = signed::opt_array(v, "attestations")?
            .into_iter()
            .map(Attestation::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let links = signed::opt_array(v, "links")?
            .into_iter()
            .map(|l| match l {
                Value::Text(s) => Ok(s),
                _ => Err(Error::BadField("links")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let card = Card {
            identity: signed::bytes32(v, "identity")?,
            updated: signed::uint(v, "updated")?,
            name: signed::text(v, "name")?,
            icon: signed::opt_uint(v, "icon")?,
            profile: signed::opt_text(v, "profile")?,
            attestations,
            vouches: signed::opt_array(v, "vouches")?,
            links,
        };
        card.check_fields()?;
        if card
            .attestations
            .iter()
            .any(|a| a.identity != card.identity)
        {
            return Err(Error::KeyMismatch);
        }
        env.verify(&card.identity, DOMAIN)?;
        Ok(card)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ServerKey;

    #[test]
    fn round_trip_with_attestation() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: id.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "misha".into(),
            registered: 1_600_000_000,
            issued: 1_700_000_000,
            expires: 1_800_000_000,
            level: None,
        };
        let mut card = Card::new(&id, "Misha", 1_700_000_001);
        card.icon = Some(128);
        card.profile = Some("hxd-ng".into());
        card.links = vec!["https://misha.nasledov.com".into()];
        let bytes = card.sign(&id, vec![att.signed_value(&reg)]).unwrap();
        let back = Card::parse(&bytes).unwrap();
        assert_eq!(back.name, "Misha");
        assert_eq!(back.icon, Some(128));
        assert_eq!(back.links, card.links);
        assert_eq!(back.attestations, vec![att]);
    }

    #[test]
    fn attestation_for_another_identity_is_rejected() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let other = IdentityKey::from_seed(&[2u8; 32]);
        let reg = ServerKey::from_seed(&[3u8; 32]);
        let att = Attestation {
            identity: other.public(),
            registrar: "hl.example".into(),
            registrar_key: reg.public(),
            handle: "someone".into(),
            registered: 1,
            issued: 2,
            expires: 3,
            level: None,
        };
        let card = Card::new(&id, "Misha", 10);
        let bytes = card.sign(&id, vec![att.signed_value(&reg)]).unwrap();
        assert_eq!(Card::parse(&bytes), Err(Error::KeyMismatch));
    }

    #[test]
    fn size_and_name_limits() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let card = Card::new(&id, "", 10);
        assert_eq!(card.sign(&id, vec![]), Err(Error::BadField("name")));
        let card = Card::new(&id, "x".repeat(33), 10);
        assert_eq!(card.sign(&id, vec![]), Err(Error::BadField("name")));
        let mut card = Card::new(&id, "Misha", 10);
        card.profile = Some("p".repeat(PROFILE_MAX_BYTES + 1));
        assert_eq!(card.sign(&id, vec![]), Err(Error::BadField("profile")));
        let mut card = Card::new(&id, "Misha", 10);
        card.links = (0..600)
            .map(|i| format!("https://example.com/{i:030}"))
            .collect();
        assert_eq!(card.sign(&id, vec![]), Err(Error::TooLarge));
    }
}
