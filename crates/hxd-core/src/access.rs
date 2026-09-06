//! The Hotline access bitmap.
//!
//! An 8-byte big-endian bitmap where **bit 0 is the MSB of byte 0** and bit
//! 63 is the LSB of byte 7. The bit assignments are the canonical ones from
//! mhxd's `struct hl_access_bits` (mirrored in gtkhx's `src/hl_access.h`);
//! the numbering here must match those files bit for bit, because these
//! bytes go on the wire in `HTLS_DATA_ACCESS` and are interpreted by every
//! client ever shipped.
//!
//! Bits marked reserved in the reference headers are representable (the
//! escape hatch is [`AccessBits::with`] on a raw number) but deliberately
//! have no named constant — some deployed servers use them privately.

/// The 64-bit access bitmap. Internally bit *n* (protocol numbering) is
/// stored at `1 << (63 - n)`, so [`AccessBits::to_wire`] is just the
/// big-endian byte dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessBits(u64);

impl AccessBits {
    /// No permissions at all.
    pub const fn empty() -> Self {
        AccessBits(0)
    }

    /// From the 8 wire bytes (`HTLS_DATA_ACCESS` payload).
    pub const fn from_wire(bytes: [u8; 8]) -> Self {
        AccessBits(u64::from_be_bytes(bytes))
    }

    /// The 8 wire bytes.
    pub const fn to_wire(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// From the raw internal representation (for storage round-trips).
    pub const fn from_raw(raw: u64) -> Self {
        AccessBits(raw)
    }

    /// The raw internal representation.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Is protocol bit `n` set? Bits ≥ 64 read as unset.
    pub const fn has(self, n: u8) -> bool {
        n < 64 && self.0 & (1u64 << (63 - n)) != 0
    }

    /// A copy with protocol bit `n` set. Bits ≥ 64 are ignored.
    #[must_use]
    pub const fn with(self, n: u8) -> Self {
        if n < 64 {
            AccessBits(self.0 | (1u64 << (63 - n)))
        } else {
            self
        }
    }
}

/// Protocol bit numbers, named after the mhxd struct fields so they stay
/// greppable against the reference implementation.
pub mod bit {
    // Files (0–7)
    pub const DELETE_FILES: u8 = 0;
    pub const UPLOAD_FILES: u8 = 1;
    pub const DOWNLOAD_FILES: u8 = 2;
    pub const RENAME_FILES: u8 = 3;
    pub const MOVE_FILES: u8 = 4;
    pub const CREATE_FOLDERS: u8 = 5;
    pub const DELETE_FOLDERS: u8 = 6;
    pub const RENAME_FOLDERS: u8 = 7;
    // Folders / chat / users (8–15)
    pub const MOVE_FOLDERS: u8 = 8;
    pub const READ_CHAT: u8 = 9;
    pub const SEND_CHAT: u8 = 10;
    pub const CREATE_PCHATS: u8 = 11;
    pub const CREATE_USERS: u8 = 14;
    pub const DELETE_USERS: u8 = 15;
    // Users / classic news / disconnect (16–23)
    pub const READ_USERS: u8 = 16;
    pub const MODIFY_USERS: u8 = 17;
    pub const READ_NEWS: u8 = 20;
    pub const POST_NEWS: u8 = 21;
    pub const DISCONNECT_USERS: u8 = 22;
    pub const CANT_BE_DISCONNECTED: u8 = 23;
    // Misc (24–31)
    pub const GET_USER_INFO: u8 = 24;
    pub const UPLOAD_ANYWHERE: u8 = 25;
    pub const USE_ANY_NAME: u8 = 26;
    pub const DONT_SHOW_AGREEMENT: u8 = 27;
    pub const COMMENT_FILES: u8 = 28;
    pub const COMMENT_FOLDERS: u8 = 29;
    pub const VIEW_DROP_BOXES: u8 = 30;
    pub const MAKE_ALIASES: u8 = 31;
    // 1.5+ news / folder transfers (32–39)
    pub const CAN_BROADCAST: u8 = 32;
    pub const DELETE_ARTICLES: u8 = 33;
    pub const CREATE_CATEGORIES: u8 = 34;
    pub const DELETE_CATEGORIES: u8 = 35;
    pub const CREATE_NEWS_BUNDLES: u8 = 36;
    pub const DELETE_NEWS_BUNDLES: u8 = 37;
    pub const UPLOAD_FOLDERS: u8 = 38;
    pub const DOWNLOAD_FOLDERS: u8 = 39;
    // Private messages (40)
    pub const SEND_MSGS: u8 = 40;
    // Extensions (fogWraith allocations)
    pub const VOICE_CHAT: u8 = 55;
    pub const CHAT_HISTORY: u8 = 56;
    // 57 AccessSendMedia and 58 AccessMessaging are allocated by the
    // inline-media and messaging extensions; neither is implemented here
    // yet, and the numbers stay reserved so video's don't drift.
    /// May publish camera video in a voice room
    /// (`docs/capabilities-video.md` §"Access Privileges").
    pub const VIDEO_CHAT: u8 = 59;
    /// May publish a screen share. **Its own bit, deliberately**:
    /// showing your face and showing your desktop are different trust
    /// decisions, and a screen share can leak documents, credentials and
    /// other people's messages in a way a camera generally cannot.
    /// Neither bit implies the other.
    pub const SCREEN_SHARE: u8 = 60;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_zero_is_msb_of_byte_zero() {
        let a = AccessBits::empty().with(bit::DELETE_FILES);
        assert_eq!(a.to_wire()[0], 0x80);
        assert!(a.has(0));
        assert!(!a.has(1));
    }

    #[test]
    fn bit_63_is_lsb_of_byte_seven() {
        let a = AccessBits::empty().with(63);
        assert_eq!(a.to_wire(), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn the_extension_bits_are_pinned_to_their_wire_positions() {
        // Every other privilege test in this tree is symmetric: a toml
        // key names a constant, and the assertion is against that same
        // constant. Renumbering one of these three would keep all of
        // them green while silently breaking interop with every other
        // implementation of the extensions, so they are pinned here to
        // their numbers *and* to the bytes they set — the way
        // `hxd_session::caps` pins the capability bitmask.
        //
        // Bit 55 is `accessVoiceChat` (fogWraith `Capabilities-Voice.md`
        // §"Access Privileges"). Bits 59 and 60 are `accessVideoChat`
        // and `accessScreenShare` (`docs/capabilities-video.md`
        // §"Access Privileges"), which follow the inline-media (57) and
        // messaging (58) allocations this server does not implement.
        assert_eq!(bit::VOICE_CHAT, 55);
        assert_eq!(bit::VIDEO_CHAT, 59);
        assert_eq!(bit::SCREEN_SHARE, 60);

        // Bit 55 is the LSB of byte 6; bits 59 and 60 are 0x10 and 0x08
        // of byte 7. A client reading these bytes is what makes the
        // numbering matter, so assert on the bytes.
        assert_eq!(
            AccessBits::empty().with(bit::VOICE_CHAT).to_wire(),
            [0, 0, 0, 0, 0, 0, 0x01, 0x00]
        );
        assert_eq!(
            AccessBits::empty().with(bit::VIDEO_CHAT).to_wire(),
            [0, 0, 0, 0, 0, 0, 0x00, 0x10]
        );
        assert_eq!(
            AccessBits::empty().with(bit::SCREEN_SHARE).to_wire(),
            [0, 0, 0, 0, 0, 0, 0x00, 0x08]
        );

        // Showing your face and showing your desktop are separate trust
        // decisions, and neither is voice's: granting one must never
        // read back as granting another.
        let cam = AccessBits::empty().with(bit::VIDEO_CHAT);
        assert!(cam.has(bit::VIDEO_CHAT));
        assert!(!cam.has(bit::SCREEN_SHARE));
        assert!(!cam.has(bit::VOICE_CHAT));
        let screen = AccessBits::empty().with(bit::SCREEN_SHARE);
        assert!(!screen.has(bit::VIDEO_CHAT));

        // And from the other direction: an account granted both video
        // bits sets exactly those two, leaving the reserved 57 and 58
        // clear so a later extension can still have them.
        let both = AccessBits::from_wire([0, 0, 0, 0, 0, 0, 0x00, 0x18]);
        assert!(both.has(bit::VIDEO_CHAT));
        assert!(both.has(bit::SCREEN_SHARE));
        assert!(!both.has(57));
        assert!(!both.has(58));
        assert_eq!(both, cam.with(bit::SCREEN_SHARE));
    }

    #[test]
    fn matches_mhxd_fakeaccess_constant() {
        // mhxd's "everything enabled" SELFINFO constant is the byte pair
        // 0xfff3cfef / 0xff800000 — a handy cross-check that our bit
        // numbering agrees with the reference server's struct layout.
        let wire = [0xff, 0xf3, 0xcf, 0xef, 0xff, 0x80, 0x00, 0x00];
        let a = AccessBits::from_wire(wire);
        // Bits 12–13 are the reserved gap inside 0xf3 (1111 0011).
        assert!(a.has(bit::CREATE_PCHATS));
        assert!(!a.has(12));
        assert!(!a.has(13));
        assert!(a.has(bit::CREATE_USERS));
        // 0xcf (1100 1111): bits 18–19 reserved-clear.
        assert!(a.has(bit::MODIFY_USERS));
        assert!(!a.has(18));
        assert!(!a.has(19));
        assert!(a.has(bit::READ_NEWS));
        // 0xef (1110 1111): bit 27 (dont_show_agreement) clear.
        assert!(!a.has(bit::DONT_SHOW_AGREEMENT));
        assert!(a.has(bit::USE_ANY_NAME));
        // Tail: bit 40 set, everything after clear.
        assert!(a.has(bit::SEND_MSGS));
        assert!(!a.has(41));
        assert_eq!(a.to_wire(), wire);
    }

    #[test]
    fn out_of_range_bits_are_inert() {
        assert!(!AccessBits::empty().has(64));
        assert_eq!(AccessBits::empty().with(64), AccessBits::empty());
        assert!(!AccessBits::empty().has(255));
    }
}
