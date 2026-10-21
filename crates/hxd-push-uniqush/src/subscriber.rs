//! A mailbox as a uniqush subscriber, and back
//! (`docs/push-notifications.md` §5).
//!
//! `hx-f-` and the fingerprint where there is one, `hx-l-` and the login
//! where there is not, both in lowercase hex: inside the characters
//! uniqush accepts whatever a login holds, never a uid, and never the
//! same subscriber for an identity and a login, which is the mailbox
//! rule carried one hop further out. Reversible, so a removal uniqush
//! reports names the mailbox it came from.

use hxd_core::inbox::Mailbox;

const IDENTIFIED: &str = "hx-f-";
const LOGIN: &str = "hx-l-";

pub fn of(m: &Mailbox) -> String {
    match &m.fingerprint {
        Some(fp) => format!("{IDENTIFIED}{}", hex(fp)),
        None => format!("{LOGIN}{}", hex(m.login.as_bytes())),
    }
}

/// The mailbox a subscriber is, or `None` for one this server could not
/// have made. An identified mailbox is found by its fingerprint alone, so
/// the login it answers with is empty.
pub fn mailbox(subscriber: &str) -> Option<Mailbox> {
    if let Some(h) = subscriber.strip_prefix(IDENTIFIED) {
        return Some(Mailbox::identified(
            String::new(),
            unhex(h)?.try_into().ok()?,
        ));
    }
    let login = String::from_utf8(unhex(subscriber.strip_prefix(LOGIN)?)?).ok()?;
    Some(Mailbox::login(login))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subscriber_is_its_mailbox_and_nothing_else() {
        let alice = Mailbox::login("Alice \u{dc}n\u{ef}code");
        let s = of(&alice);
        assert!(s.starts_with("hx-l-"));
        assert!(
            s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "inside what uniqush accepts: {s}"
        );
        assert_eq!(mailbox(&s), Some(alice));

        let fp = [0xab; 32];
        let identified = Mailbox::identified("alice", fp);
        let s = of(&identified);
        assert_eq!(s, format!("hx-f-{}", "ab".repeat(32)));
        assert!(
            mailbox(&s).unwrap().matches("anyone", Some(&fp)),
            "found by the fingerprint, whatever the login"
        );
        assert_ne!(
            of(&Mailbox::login("alice")),
            of(&identified),
            "an identity never shares a subscriber with its login"
        );

        for foreign in ["alice", "hx-l-zz", "hx-l-abc", "hx-f-abab", "hx-l-ff"] {
            assert_eq!(mailbox(foreign), None, "{foreign}");
        }
    }
}
