//! `DATA_CAPABILITIES` (`0x01F0`) — per-session extension negotiation.
//!
//! The client advertises a bitmask of the extensions it implements in its
//! LOGIN; the server replies with the subset it agrees to enable for the
//! session. Both sides ignore bits they don't recognize, and an absent
//! field on either side means "standard Hotline, no extensions". Source:
//! fogWraith `Docs/Protocol/Capabilities.md`.
//!
//! **The bit numbering is not the access bitmap's.** Capability bit
//! *n* is `1 << n` in a big-endian integer — capability 0 is the *least*
//! significant bit, so the two-byte payload for voice (bit 2) is
//! `00 04`. `hxd_core::AccessBits` runs the other way (bit 0 is the MSB of
//! byte 0). Getting these two confused produces a bitmask that looks
//! plausible and negotiates the wrong extension, so they deliberately
//! don't share a type.
//!
//! The field is a variable-width big-endian unsigned integer: clients send
//! two bytes today and the spec allows up to eight. We accept any width
//! and answer in the narrowest that fits.

/// A `DATA_CAPABILITIES` bitmask: what a client offers, what a server
/// supports, or (their intersection) what a session negotiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Caps(u64);

impl Caps {
    /// No extensions.
    pub const fn empty() -> Self {
        Caps(0)
    }

    /// From the raw bitmask value.
    pub const fn from_bits(bits: u64) -> Self {
        Caps(bits)
    }

    /// The raw bitmask value.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Decode a wire payload: a big-endian unsigned integer of any width.
    ///
    /// A payload wider than eight bytes keeps its *low* 64 bits — those
    /// are the ones carrying the capabilities we could possibly know
    /// about, and per the spec the rest are bits to ignore. An empty
    /// payload is no capabilities (some clients send the field bare).
    pub fn from_wire(bytes: &[u8]) -> Self {
        let tail = &bytes[bytes.len().saturating_sub(8)..];
        let mut bits: u64 = 0;
        for &b in tail {
            bits = (bits << 8) | b as u64;
        }
        Caps(bits)
    }

    /// Encode for the wire in the narrowest width that holds the mask:
    /// two bytes for everything defined today, eight if a bit above 15
    /// is ever allocated. Clients decode the field by width, so a
    /// two-byte answer to a two-byte offer is what every deployed
    /// implementation expects.
    pub fn to_wire(self) -> Vec<u8> {
        if self.0 <= u16::MAX as u64 {
            (self.0 as u16).to_be_bytes().to_vec()
        } else {
            self.0.to_be_bytes().to_vec()
        }
    }

    /// Is capability bit `n` set? Bits ≥ 64 read as unset.
    pub const fn has(self, n: u8) -> bool {
        n < 64 && self.0 & (1u64 << n) != 0
    }

    /// A copy with capability bit `n` set. Bits ≥ 64 are ignored.
    #[must_use]
    pub const fn with(self, n: u8) -> Self {
        if n < 64 {
            Caps(self.0 | (1u64 << n))
        } else {
            self
        }
    }

    /// The bits present in both — the negotiation itself: what the client
    /// offered and the server supports.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Caps(self.0 & other.0)
    }

    /// Nothing negotiated (the reply omits the field entirely).
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Capability bit numbers, from the fogWraith allocation table. Named
/// after the spec's `CAPABILITY_*` constants (and gtkhx's `HTLC_CAP_*`)
/// so they stay greppable across the two trees.
pub mod cap {
    pub const LARGE_FILES: u8 = 0;
    pub const TEXT_ENCODING: u8 = 1;
    pub const VOICE: u8 = 2;
    pub const INLINE_MEDIA: u8 = 3;
    pub const CHAT_HISTORY: u8 = 4;
    pub const EXTENDED_PRIV: u8 = 5;
    pub const MESSAGING: u8 = 6;
    pub const DIRECT_TRANSFER: u8 = 7;
    pub const MESSENGER_SESSION: u8 = 8;
    pub const MODERN_DATES: u8 = 9;
    /// Camera video and screen sharing in voice rooms
    /// (`docs/capabilities-video.md`). **Depends on [`VOICE`]** — the
    /// server must not confirm this bit without confirming that one in
    /// the same login reply, because video has no meaning without the
    /// voice room that carries it.
    pub const VIDEO: u8 = 10;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_numbering_matches_the_spec_masks() {
        // The spec's table, and gtkhx's HTLC_CAP_* constants, byte for
        // byte: capability n is 1 << n, low bit first.
        assert_eq!(Caps::empty().with(cap::LARGE_FILES).to_wire(), vec![0, 1]);
        assert_eq!(Caps::empty().with(cap::TEXT_ENCODING).to_wire(), vec![0, 2]);
        assert_eq!(Caps::empty().with(cap::VOICE).to_wire(), vec![0, 4]);
        assert_eq!(
            Caps::empty().with(cap::CHAT_HISTORY).to_wire(),
            vec![0, 0x10]
        );
        assert_eq!(Caps::empty().with(cap::MODERN_DATES).to_wire(), vec![2, 0]);
        // Video is bit 10, the next one after modern dates: 0x0400.
        assert_eq!(Caps::empty().with(cap::VIDEO).to_wire(), vec![0x04, 0x00]);
        // "When all three extensions are active (large files, text
        // encoding, voice), the capability bitmask is 0x0007."
        let three = Caps::empty()
            .with(cap::LARGE_FILES)
            .with(cap::TEXT_ENCODING)
            .with(cap::VOICE);
        assert_eq!(three.to_wire(), vec![0x00, 0x07]);
    }

    #[test]
    fn wire_widths_round_trip() {
        assert_eq!(
            Caps::from_wire(&[0x00, 0x04]),
            Caps::empty().with(cap::VOICE)
        );
        // One byte, eight bytes, and a bare field are all legal offers.
        assert_eq!(Caps::from_wire(&[0x04]), Caps::empty().with(cap::VOICE));
        assert_eq!(
            Caps::from_wire(&[0, 0, 0, 0, 0, 0, 0, 0x04]),
            Caps::empty().with(cap::VOICE)
        );
        assert_eq!(Caps::from_wire(&[]), Caps::empty());
        // Wider than a u64: the low bits are the ones we can act on.
        assert_eq!(
            Caps::from_wire(&[0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0x04]),
            Caps::empty().with(cap::VOICE)
        );
        // A bit above 15 forces the eight-byte form.
        assert_eq!(Caps::from_bits(1 << 40).to_wire().len(), 8);
    }

    #[test]
    fn negotiation_is_an_intersection() {
        let offered = Caps::empty()
            .with(cap::TEXT_ENCODING)
            .with(cap::VOICE)
            .with(cap::MESSAGING);
        let supported = Caps::empty().with(cap::VOICE).with(cap::LARGE_FILES);
        let agreed = offered.intersect(supported);
        assert!(agreed.has(cap::VOICE));
        assert!(!agreed.has(cap::TEXT_ENCODING)); // offered, unsupported
        assert!(!agreed.has(cap::LARGE_FILES)); // supported, unoffered
        assert!(Caps::empty().intersect(supported).is_empty());
    }

    #[test]
    fn out_of_range_bits_are_inert() {
        assert!(!Caps::empty().has(64));
        assert_eq!(Caps::empty().with(64), Caps::empty());
    }
}
