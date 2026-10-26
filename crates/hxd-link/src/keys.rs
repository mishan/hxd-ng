//! The user keys draft's signed messages on a link
//! (`docs/e2e-messages.md` §5): the certificates this server fetched for
//! its ghosts' signed lines, kept by hash; the lines logged before theirs
//! came; how a ghost's line or message is checked once one has; and the
//! local sessions this server has seen sign, whose certificates it hands
//! a linked server that asks in its own name.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hl_identity::message::{Object, Signed};
use hl_identity::Error;
use hxd_core::history::{LineId, Signature};
use hxd_core::roster::Uid;
use sha2::{Digest, Sha256};

/// Certificates held, in number and in bytes: every one is at most 512,
/// so the count is the usual bound and the bytes the one that holds
/// whatever the draft later allows.
const MAX_CERTS: usize = 1024;
const MAX_CERT_BYTES: usize = 256 * 1024;
/// Logged lines waiting for their certificate, across every hash, and
/// for the fetches over one link.
const MAX_WAITING: usize = 1024;
const WAITING_PER_LINK: usize = MAX_WAITING / 4;
/// Fetches under way at once, across every link and over one, so a peer
/// whose certificates never come cannot hold every place.
const MAX_FETCHING: usize = 32;
const FETCHING_PER_LINK: usize = MAX_FETCHING / 4;
/// A certificate that could not be had is not asked for again sooner:
/// its session has left, moved device, or its home server will not say.
const RETRY_AFTER: Duration = Duration::from_secs(60);

/// A ghost's signed line as it arrived, for checking once its certificate
/// is held.
#[derive(Debug, Clone)]
pub(crate) struct Unchecked {
    pub(crate) form: Vec<u8>,
    /// Its canonical text.
    pub(crate) text: String,
    pub(crate) act: bool,
    /// The fingerprint its sender's user group gives.
    pub(crate) signer: Option<[u8; 32]>,
    /// Its home server's discovery key.
    pub(crate) home: Option<[u8; 32]>,
    /// When this server received it, unix seconds.
    pub(crate) at: u64,
}

/// What checking a ghost's signed line or message found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Checked {
    /// It verifies as far as this server can tell: its detached form with
    /// the certificate back in it, and what it says.
    Whole(Signature),
    /// The certificate held is not the one it names: as if none were.
    Unverifiable,
    /// Invalid, signed by someone other than its sender's group says, or
    /// for another scope: not shown, and a message is refused.
    Failed,
}

/// Check a link form against `cert` (§3.5, §5): the signature, the
/// signer against the fingerprint the sender's group gives, and the
/// scope `scoped` asks about.
pub(crate) fn check<T: Object>(
    form: &[u8],
    texts: T::Texts<'_>,
    cert: &[u8],
    at: u64,
    signer: Option<[u8; 32]>,
    scoped: impl FnOnce(&T) -> bool,
) -> Checked {
    match Signed::<T>::parse_link(form, texts, cert, at) {
        Err(Error::CertMismatch) => Checked::Unverifiable,
        Err(_) => Checked::Failed,
        // The cache is by hash, so a certificate held may be another
        // user's: without a fingerprint to hold it to, nothing is known.
        Ok(_) if signer.is_none() => Checked::Unverifiable,
        Ok(s) if signer.is_some_and(|fp| fp != s.signer().0) || !scoped(&s.message) => {
            Checked::Failed
        }
        Ok(s) => match s.detached() {
            Ok(form) => Checked::Whole(Signature {
                form,
                content: s.content_sha256(),
            }),
            Err(_) => Checked::Failed,
        },
    }
}

impl Unchecked {
    /// Whether the link form, before its certificate is held, is of a
    /// lobby line in this style and of its home server: what a line
    /// shown at once is held to, as one checked whole would be.
    pub(crate) fn in_scope(&self) -> bool {
        use hl_identity::cbor::{decode_canonical, Value};
        let Ok(map) = decode_canonical(&self.form) else {
            return false;
        };
        let Some(scope) = map.get("in") else {
            return false;
        };
        let act = matches!(map.get("act"), Some(Value::Bool(true)));
        let home = match (self.home, scope.get("server")) {
            (None, _) => true,
            (Some(k), Some(Value::Bytes(b))) => b[..] == k,
            _ => false,
        };
        matches!(scope.get("room"), Some(Value::Uint(0))) && act == self.act && home
    }

    /// A lobby line's scope is its home server's key and room 0; one
    /// whose home server gave no key has its scope left to its readers,
    /// who show it unverified.
    pub(crate) fn check(&self, cert: &[u8]) -> Checked {
        check::<hl_identity::message::ChatLine>(
            &self.form,
            [&self.text],
            cert,
            self.at,
            self.signer,
            |l| l.room == 0 && l.act == self.act && self.home.is_none_or(|k| k == l.server),
        )
    }
}

/// Whether a signed private message's form says it is an automatic
/// response.
pub(crate) fn automatic(form: &[u8]) -> bool {
    hl_identity::cbor::decode_canonical(form)
        .is_ok_and(|m| matches!(m.get("auto"), Some(hl_identity::cbor::Value::Bool(true))))
}

/// A logged line waiting for its certificate.
struct Waiting {
    id: LineId,
    line: Unchecked,
}

/// A certificate fetched, and the lines that waited for it.
pub(crate) type Fetched = (Arc<[u8]>, Vec<(LineId, Unchecked)>);

/// Certificates by hash, and what waits on them.
#[derive(Default)]
pub(crate) struct Certs {
    held: HashMap<[u8; 32], Arc<[u8]>>,
    /// Oldest first, for eviction.
    order: VecDeque<[u8; 32]>,
    bytes: usize,
    /// The link each fetch under way went over.
    fetching: HashMap<[u8; 32], String>,
    tried: HashMap<[u8; 32], Instant>,
    waiting: HashMap<[u8; 32], Vec<Waiting>>,
    waiting_lines: usize,
}

impl Certs {
    pub(crate) fn get(&self, hash: &[u8; 32]) -> Option<Arc<[u8]>> {
        self.held.get(hash).cloned()
    }

    fn insert(&mut self, hash: [u8; 32], cert: Arc<[u8]>) {
        if self.held.contains_key(&hash) {
            return;
        }
        self.bytes += cert.len();
        self.held.insert(hash, cert);
        self.order.push_back(hash);
        while self.held.len() > MAX_CERTS || self.bytes > MAX_CERT_BYTES {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(gone) = self.held.remove(&old) {
                self.bytes -= gone.len();
            }
        }
    }

    /// Whether to fetch `hash` over `link` now, marking it under way if
    /// so: not held, not under way already, not tried lately, and room
    /// for another, over that link and in all.
    pub(crate) fn should_fetch(&mut self, hash: [u8; 32], link: &str, now: Instant) -> bool {
        self.tried
            .retain(|_, at| now.duration_since(*at) < RETRY_AFTER);
        if self.held.contains_key(&hash)
            || self.fetching.contains_key(&hash)
            || self.tried.contains_key(&hash)
            || self.fetching.len() >= MAX_FETCHING
            || self.fetching.values().filter(|l| *l == link).count() >= FETCHING_PER_LINK
        {
            return false;
        }
        self.fetching.insert(hash, link.to_owned());
        true
    }

    /// A fetch of `hash` has ended, with `cert` if it came and hashes to
    /// it: kept, and the lines that waited for it handed back with it.
    pub(crate) fn fetched(
        &mut self,
        hash: [u8; 32],
        cert: Option<Vec<u8>>,
        now: Instant,
    ) -> Option<Fetched> {
        self.fetching.remove(&hash);
        let waiting = self.waiting.remove(&hash).unwrap_or_default();
        self.waiting_lines -= waiting.len();
        let cert = cert.filter(|c| {
            c.len() <= hl_identity::message::CERT_MAX_BYTES
                && <[u8; 32]>::from(Sha256::digest(c)) == hash
        });
        let Some(cert) = cert else {
            if self.tried.len() >= MAX_CERTS {
                let oldest = self
                    .tried
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(h, _)| *h);
                oldest.map(|h| self.tried.remove(&h));
            }
            self.tried.insert(hash, now);
            return None;
        };
        let cert: Arc<[u8]> = cert.into();
        self.insert(hash, cert.clone());
        Some((cert, waiting.into_iter().map(|w| (w.id, w.line)).collect()))
    }

    /// Line `id`, logged in its link form: the certificate to check it
    /// with now if it is held, or `None` once it waits for one under way.
    /// Past the bound, or with no fetch under way, it stays as logged.
    pub(crate) fn logged(
        &mut self,
        hash: [u8; 32],
        id: LineId,
        line: Unchecked,
    ) -> Option<(Arc<[u8]>, Unchecked)> {
        if let Some(cert) = self.held.get(&hash) {
            return Some((cert.clone(), line));
        }
        let link = self.fetching.get(&hash)?;
        let over_link: usize = self
            .fetching
            .iter()
            .filter(|(_, l)| *l == link)
            .filter_map(|(h, _)| self.waiting.get(h))
            .map(Vec::len)
            .sum();
        if self.waiting_lines < MAX_WAITING && over_link < WAITING_PER_LINK {
            self.waiting
                .entry(hash)
                .or_default()
                .push(Waiting { id, line });
            self.waiting_lines += 1;
        }
        None
    }
}

/// A local session this server has seen sign: the certificate it signed
/// with, and where its signatures went.
struct SeenSession {
    cert: Arc<[u8]>,
    /// It signed a lobby line, which every link carried.
    lobby: bool,
    /// The links it sent signed private messages over.
    links: HashSet<String>,
}

/// Sessions seen to sign, the only ones a server's own Link Device Keys
/// is answered for (the draft's Fetching the Certificate).
#[derive(Default)]
pub(crate) struct Seen(HashMap<Uid, SeenSession>);

impl Seen {
    /// `uid` signed with `cert`: a lobby line for `over` = `None`, a
    /// private message sent over that link otherwise.
    pub(crate) fn saw(&mut self, uid: Uid, cert: Arc<[u8]>, over: Option<&str>) {
        let s = self.0.entry(uid).or_insert_with(|| SeenSession {
            cert: cert.clone(),
            lobby: false,
            links: HashSet::new(),
        });
        s.cert = cert;
        match over {
            None => s.lobby = true,
            Some(link) => {
                s.links.insert(link.to_owned());
            }
        }
    }

    pub(crate) fn gone(&mut self, uid: Uid) {
        self.0.remove(&uid);
    }

    /// Only `uids`, the sessions still there: what the export feed would
    /// have said of the rest is lost when it falls behind.
    pub(crate) fn keep(&mut self, uids: &HashSet<Uid>) {
        self.0.retain(|uid, _| uids.contains(uid));
    }

    /// The certificate `uid` signed with, for a server's own request over
    /// `link`.
    pub(crate) fn cert_for(&self, uid: Uid, link: &str) -> Option<Arc<[u8]>> {
        self.0
            .get(&uid)
            .filter(|s| s.lobby || s.links.contains(link))
            .map(|s| s.cert.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line() -> Unchecked {
        Unchecked {
            form: vec![],
            text: String::new(),
            act: false,
            signer: None,
            home: None,
            at: 0,
        }
    }

    fn hash(cert: &[u8]) -> [u8; 32] {
        Sha256::digest(cert).into()
    }

    #[test]
    fn a_ghosts_signed_line_or_message_is_checked_against_its_sender_and_scope() {
        use hl_identity::message::{ChatLine, PrivateMessage};
        use hl_identity::{cert, DeviceCert, DeviceKey, Fingerprint, IdentityKey};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = IdentityKey::from_seed(&[1; 32]);
        let device = |seed| {
            let dev = DeviceKey::from_seed(&[seed; 32]);
            let cert = DeviceCert::for_device(&id, &dev, now - 60, cert::RECOMMENDED_LIFETIME)
                .unwrap()
                .sign(&id);
            (dev, cert)
        };
        let ((dev, cert), (_, other)) = (device(2), device(3));
        let me = Fingerprint::of(&id.public()).0;
        let (to, home) = ([9; 32], [8; 32]);
        let msg = PrivateMessage {
            id: [1; 16],
            sent: now,
            to: Fingerprint(to),
            cert: cert.clone(),
            text: "hi".into(),
            quote: None,
            auto: false,
        };
        let msg = Signed::<PrivateMessage>::parse(&msg.sign(&dev).unwrap(), now)
            .unwrap()
            .link()
            .unwrap();
        let line = ChatLine {
            id: [1; 16],
            sent: now,
            server: home,
            room: 0,
            cert: cert.clone(),
            text: "hi".into(),
            act: false,
        };
        let line = Signed::<ChatLine>::parse(&line.sign(&dev).unwrap(), now)
            .unwrap()
            .link()
            .unwrap();
        let to_msg = |text: &str, cert: &[u8], signer, scope: [u8; 32]| {
            check::<PrivateMessage>(&msg, [text], cert, now, signer, |m| m.to.0 == scope)
        };
        let to_line = |home, act| {
            Unchecked {
                form: line.clone(),
                text: "hi".into(),
                act,
                signer: Some(me),
                home,
                at: now,
            }
            .check(&cert)
        };
        let kind = |c: Checked| match c {
            Checked::Whole(_) => "whole",
            Checked::Unverifiable => "unverifiable",
            Checked::Failed => "failed",
        };
        for (name, got, want) in [
            ("as signed", to_msg("hi", &cert, Some(me), to), "whole"),
            (
                "from a ghost of no fingerprint",
                to_msg("hi", &cert, None, to),
                "unverifiable",
            ),
            (
                "its text altered",
                to_msg("ho", &cert, Some(me), to),
                "failed",
            ),
            (
                "by another than its sender",
                to_msg("hi", &cert, Some([4; 32]), to),
                "failed",
            ),
            (
                "to someone else",
                to_msg("hi", &cert, Some(me), [5; 32]),
                "failed",
            ),
            (
                "under another certificate",
                to_msg("hi", &other, Some(me), to),
                "unverifiable",
            ),
            ("a line said here", to_line(Some(home), false), "whole"),
            ("a line of no known home", to_line(None, false), "whole"),
            (
                "a line said elsewhere",
                to_line(Some([6; 32]), false),
                "failed",
            ),
            (
                "a line in another style",
                to_line(Some(home), true),
                "failed",
            ),
        ] {
            assert_eq!(kind(got), want, "{name}");
        }
    }

    #[test]
    fn certificates_are_held_within_their_bounds_oldest_going_first() {
        let now = Instant::now();
        let mut certs = Certs::default();
        let cert = |n: usize, len: usize| n.to_be_bytes().repeat(len / 8);
        for n in 0..=MAX_CERTS {
            let c = cert(n, 32);
            assert!(certs.fetched(hash(&c), Some(c), now).is_some());
        }
        assert_eq!(certs.held.len(), MAX_CERTS);
        assert!(certs.get(&hash(&cert(0, 32))).is_none(), "the oldest went");
        assert!(certs.get(&hash(&cert(MAX_CERTS, 32))).is_some());
        for n in 0..MAX_CERTS {
            let c = cert(n, hl_identity::message::CERT_MAX_BYTES);
            certs.fetched(hash(&c), Some(c), now);
        }
        assert!(certs.bytes <= MAX_CERT_BYTES);
        assert_eq!(
            certs.held.len(),
            MAX_CERT_BYTES / hl_identity::message::CERT_MAX_BYTES
        );
        let big = vec![7; hl_identity::message::CERT_MAX_BYTES + 1];
        assert!(
            certs.fetched(hash(&big), Some(big.clone()), now).is_none(),
            "larger than a message may name"
        );
    }

    #[test]
    fn a_fetch_is_made_once_and_one_that_failed_waits_before_another() {
        let now = Instant::now();
        let mut certs = Certs::default();
        let cert = b"cert".to_vec();
        let h = hash(&cert);
        assert!(certs.should_fetch(h, "bb", now));
        assert!(!certs.should_fetch(h, "bb", now), "under way");
        assert!(certs.logged(h, 1, line()).is_none(), "waits");
        // Another certificate under the hash is not it.
        assert!(certs.fetched(h, Some(b"other".to_vec()), now).is_none());
        assert!(!certs.should_fetch(h, "bb", now + Duration::from_secs(1)));
        assert!(certs.should_fetch(h, "bb", now + RETRY_AFTER));
        let (_, waited) = certs.fetched(h, Some(cert), now + RETRY_AFTER).unwrap();
        assert!(waited.is_empty(), "the first fetch's line went with it");
        assert!(certs.logged(h, 2, line()).is_some(), "held now");
        // One link holds its share of the fetches, and no more.
        for n in 0..FETCHING_PER_LINK {
            assert!(certs.should_fetch(hash(&n.to_be_bytes()), "bb", now));
        }
        assert!(!certs.should_fetch(hash(b"one more"), "bb", now));
        assert!(certs.should_fetch(hash(b"one more"), "cc", now));
    }

    #[test]
    fn a_servers_own_request_is_answered_only_where_the_session_signed() {
        let mut seen = Seen::default();
        let cert: Arc<[u8]> = b"cert".to_vec().into();
        assert!(seen.cert_for(5, "bb").is_none(), "never signed");
        seen.saw(5, cert.clone(), Some("bb"));
        assert!(seen.cert_for(5, "bb").is_some());
        assert!(seen.cert_for(5, "cc").is_none(), "not over that link");
        seen.saw(5, cert, None);
        assert!(
            seen.cert_for(5, "cc").is_some(),
            "a lobby line goes everywhere"
        );
        seen.gone(5);
        assert!(seen.cert_for(5, "bb").is_none());
    }
}
