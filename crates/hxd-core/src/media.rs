//! Inline media: handles, canonical bytes, authorization and quotas.
//!
//! The domain half of [`docs/inline-media.md`](../../../docs/inline-media.md).
//! What lives here is everything about an image that is *not* image
//! processing: who may upload one, what a handle is, who may fetch it,
//! how long it lives, and how much of the process it is allowed to
//! occupy. The bytes themselves are validated, canonicalized and
//! re-encoded behind the [`MediaCodec`] trait, which `hxd-media`
//! implements and this crate only calls — the domain links no image
//! decoder, the same arrangement [`crate::voice`] has with the SFU.
//!
//! **Nothing here touches disk.** A handle lives for its TTL in memory
//! and dies with the process, which the extension's own spec allows for
//! (clients are told not to cache handles across sessions). The two
//! places a handle is *recorded* — an inbox row and a chat-log line —
//! keep the canonical metadata beside it, so a reference whose bytes
//! have gone still renders as a placeholder rather than as nothing.
//!
//! **Authorization is by principal, not by uid.** A uid is recycled
//! within minutes and a session outlives its socket, so the set captured
//! when a line is relayed is stated in terms that survive both: a
//! `(uid, serial)` session for chat fan-out, a mailbox for a private
//! message, so mail that waited a day is still readable, image included,
//! by whatever session of that account picks it up.
//!
//! **Lock order: the roster's lock may be taken before the store's,
//! never after.** Fan-out needs both — it computes the audience from the
//! roster and records it here — while every path that starts here
//! (upload, fetch, revoke) copies what it needs out of the roster first,
//! or reaches the roster only after releasing this lock. An image copy
//! never happens under the roster's lock, which is the rule that matters
//! for latency; this one is the rule that matters for deadlock.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::access::bit;
use crate::inbox::Mailbox;
use crate::roster::{Core, Event, Uid};

/// A handle is 128 bits from the OS CSPRNG, as the spec requires. On the
/// legacy wire those bytes are the payload of `DATA_CHAT_MEDIA_ID`; on
/// the ng wire they are spelled base64url, which is also the path
/// segment of `GET /media/{id}`.
pub const HANDLE_LEN: usize = 16;

/// An opaque media handle.
pub type Handle = [u8; HANDLE_LEN];

/// The base64url (unpadded) spelling of a handle — the ng wire's form.
pub fn handle_str(h: &Handle) -> String {
    b64url(h)
}

/// Parse the ng wire's spelling back. Rejects anything that is not
/// exactly a handle, so a path segment cannot become a shorter key.
pub fn handle_from_str(s: &str) -> Option<Handle> {
    let raw = unb64url(s)?;
    raw.try_into().ok()
}

/// The first characters of a handle's spelling: what a log line may say.
/// Enough to correlate an upload with a download in one operator's log,
/// and not enough to fetch with (§10).
pub fn handle_prefix(h: &Handle) -> String {
    let mut s = handle_str(h);
    s.truncate(6);
    s
}

/// The three formats the capability allows, and the only three MIME
/// types that ever leave this server as media. SVG, WebP, AVIF, HEIC,
/// TIFF and ICO are forbidden by the spec by name; the codec refuses
/// them at the sniff, and this type is why nothing downstream has to
/// re-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    Jpeg,
    Png,
    Gif,
}

impl MediaType {
    pub const fn mime(self) -> &'static str {
        match self {
            MediaType::Jpeg => "image/jpeg",
            MediaType::Png => "image/png",
            MediaType::Gif => "image/gif",
        }
    }

    /// The MIME types a client's file picker may filter on, in the order
    /// the login reply lists them.
    pub const ALL: [MediaType; 3] = [MediaType::Jpeg, MediaType::Png, MediaType::Gif];

    /// Parse a canonical MIME string. Only the three exact spellings —
    /// this reads what this server wrote (a stored row, a config), never
    /// a client's `DECLARED_TYPE`, which is a hint the pipeline ignores.
    pub fn from_mime(s: &str) -> Option<Self> {
        match s {
            "image/jpeg" => Some(MediaType::Jpeg),
            "image/png" => Some(MediaType::Png),
            "image/gif" => Some(MediaType::Gif),
            _ => None,
        }
    }
}

/// Why an upload or a download was refused: fogWraith's coarse
/// `DATA_CHAT_MEDIA_ERROR_CODE` categories, which are also the only
/// thing a client is ever told. The real reason goes to the log
/// (§10) — a rejection that explains which walker tripped is a rejection
/// that teaches someone how to get past it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaReject {
    /// No other category applies — a malformed upload session, a handle
    /// that is not this sender's, a blocked hash.
    Generic,
    /// Encoded size, dimensions, pixel count, frame count or duration
    /// over a cap.
    TooLarge,
    /// The sniff failed, the walk failed, or the container is not one of
    /// the three.
    Unsupported,
    /// A rate or volume cap.
    RateLimited,
    /// No send-media permission, not on the handle's set, or no such
    /// handle — one answer for all three, so none can be told apart.
    NotAuthorized,
    /// The decode budget or the concurrency limit; try again.
    Busy,
}

impl MediaReject {
    /// The wire code (`0x0212`, u16 BE).
    pub const fn code(self) -> u16 {
        match self {
            MediaReject::Generic => 0,
            MediaReject::TooLarge => 1,
            MediaReject::Unsupported => 2,
            MediaReject::RateLimited => 3,
            MediaReject::NotAuthorized => 4,
            MediaReject::Busy => 5,
        }
    }

    /// The human text, which is deliberately one of a handful of generic
    /// strings. `DATA_ERROR` is what a period client shows in a dialog,
    /// and it says no more than the code does.
    pub const fn text(self) -> &'static str {
        match self {
            MediaReject::TooLarge => "Media too large",
            MediaReject::Unsupported => "Unsupported media",
            MediaReject::RateLimited => "Slow down",
            MediaReject::Busy => "Server busy",
            MediaReject::Generic | MediaReject::NotAuthorized => "Media rejected",
        }
    }
}

/// What the codec produced: bytes this server encoded itself, from
/// pixels it decoded itself, carrying no metadata of any kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    pub mime: MediaType,
    pub width: u32,
    pub height: u32,
    pub bytes: Vec<u8>,
}

/// The ceilings the codec enforces. Separate from [`MediaConfig`], which
/// is what the store enforces, because these travel into a crate that
/// knows nothing about Hotline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecLimits {
    /// Smallest plausible image. Below this there is nothing to decode
    /// and the payload is someone probing.
    pub min_bytes: usize,
    pub max_bytes: usize,
    pub max_dimension: u32,
    pub max_pixels: u64,
    pub max_frames: u32,
    pub max_duration_ms: u32,
    /// The decoder's allocation ceiling — the bound that makes a
    /// decompression bomb an error rather than an OOM.
    pub max_alloc_bytes: u64,
    /// How many decodes may be in flight at once. A decode holds a
    /// blocking thread and cannot be interrupted from outside, so this
    /// is what bounds the damage a slow one does.
    pub max_concurrent_decodes: usize,
    /// How long a caller will wait for a permit before giving up with
    /// [`MediaReject::Busy`].
    pub permit_wait: Duration,
}

impl Default for CodecLimits {
    fn default() -> Self {
        CodecLimits {
            min_bytes: 64,
            max_bytes: 256 * 1024,
            max_dimension: 2048,
            max_pixels: 2048 * 2048,
            max_frames: 150,
            max_duration_ms: 15_000,
            max_alloc_bytes: 64 * 1024 * 1024,
            max_concurrent_decodes: 2,
            permit_wait: Duration::from_secs(2),
        }
    }
}

/// The image pipeline, behind one trait so the domain can be tested
/// without linking a decoder — the arrangement [`crate::voice::VoiceMedia`]
/// has with the SFU, for the same reason.
///
/// The implementation is `hxd-media`. It must treat every input as
/// hostile: sniff before anything else, walk the container to its exact
/// end, probe the header before allocating, decode under a hard
/// allocation ceiling, and re-encode from the decoded pixels so that
/// stripping metadata is a property of the construction rather than of a
/// filter that could miss a chunk type.
pub trait MediaCodec: Send + Sync + 'static {
    /// Validate, canonicalize and re-encode. Never panics, whatever the
    /// input.
    fn canonicalize(&self, input: &[u8]) -> Result<Canonical, MediaReject>;

    /// Make the bounded still image the legacy news wire can carry.
    /// `None` means the source is valid but no derivative can meet the
    /// byte ceiling. Implementations used outside news need not provide
    /// one.
    fn legacy_derivative(
        &self,
        _canonical: &Canonical,
        _max_dimension: u32,
        _max_bytes: usize,
    ) -> Result<Option<Canonical>, MediaReject> {
        Ok(None)
    }
}

/// Who a download is for. Never a bare uid: uids recycle, and a set
/// captured at relay time has to outlive the sockets it was captured
/// from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
    /// One session on the roster. `serial` is what distinguishes it from
    /// any other session that ever held that uid.
    Session { uid: Uid, serial: u64 },
    /// An account, keyed exactly as the inbox keys a mailbox — which is
    /// what lets a queued private message's image be read by whichever
    /// session of that account eventually collects it.
    Mailbox(Mailbox),
}

/// A media reference as it rides on an event, a stored message or a log
/// line: the canonical metadata, plus the handle while there is one.
///
/// `id` is `None` once the bytes are gone — expired, evicted or revoked
/// — and the rest survives, because "[an image was here, 800×600 PNG]"
/// is worth rendering and an empty line is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaRef {
    pub id: Option<Handle>,
    pub mime: MediaType,
    pub width: u32,
    pub height: u32,
    pub bytes: u32,
}

impl MediaRef {
    /// The durable spelling, for a store column.
    pub fn to_meta(&self) -> crate::history::MediaMeta {
        crate::history::MediaMeta {
            id: self.id.map(|h| h.to_vec()).unwrap_or_default(),
            mime: self.mime.mime().to_string(),
            width: self.width,
            height: self.height,
            bytes: self.bytes,
        }
    }

    /// Back from a store column. An unparseable MIME or a handle that is
    /// not handle-shaped reads as metadata without a handle rather than
    /// as an error: the row is a record of something that happened, and
    /// the placeholder is still true.
    pub fn from_meta(m: &crate::history::MediaMeta) -> Option<Self> {
        let mime = MediaType::from_mime(&m.mime)?;
        Some(MediaRef {
            id: m.id.as_slice().try_into().ok(),
            mime,
            width: m.width,
            height: m.height,
            bytes: m.bytes,
        })
    }
}

/// The canonical bytes, handed out for one download.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub mime: MediaType,
    /// Shared, never copied: a download is a slice of this, and several
    /// recipients of one image hold the same allocation.
    pub bytes: Arc<Vec<u8>>,
}

/// Whether reading a line out of the chat log grants the reader the
/// image that line carried (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HistoryAccess {
    /// The spec's answer, and the default: gaining read access does not
    /// grant retroactive download rights. A history entry carries the
    /// handle and a download resolves only for principals captured when
    /// the line was relayed.
    #[default]
    Recipients,
    /// Public chat only: serving a line adds the reading session to that
    /// handle's set, on the argument that a public line's audience is
    /// everyone who holds read-chat. Never for a private room, never for
    /// a private message.
    Readers,
}

/// What the store enforces, as against what the codec does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaConfig {
    /// The assembled payload ceiling. The codec has the same number; this
    /// one refuses a chunked upload before the bytes are held, rather
    /// than after.
    pub max_bytes: usize,
    pub handle_ttl: Duration,
    pub max_total_bytes: usize,
    /// Seconds between one account's uploads.
    pub upload_interval: Duration,
    pub upload_per_hour: u32,
    pub upload_per_hour_per_addr: u32,
    /// Enforced by the frontends, advertised here so both read one number.
    pub download_per_minute: u32,
    pub upload_sessions: usize,
    /// How long a chunked upload may sit between parts.
    pub upload_idle: Duration,
    pub history_access: HistoryAccess,
    pub codec: CodecLimits,
}

impl Default for MediaConfig {
    fn default() -> Self {
        let codec = CodecLimits::default();
        MediaConfig {
            max_bytes: codec.max_bytes,
            handle_ttl: Duration::from_secs(24 * 60 * 60),
            max_total_bytes: 256 * 1024 * 1024,
            upload_interval: Duration::from_secs(10),
            upload_per_hour: 30,
            upload_per_hour_per_addr: 100,
            download_per_minute: 60,
            upload_sessions: 2,
            upload_idle: Duration::from_secs(30),
            history_access: HistoryAccess::default(),
            codec,
        }
    }
}

/// One part of an upload, as either wire hands it over.
///
/// A single-shot upload is `last` with no token and no count (or a count
/// of one); a chunked one opens with `count ≥ 2` and no token, and every
/// follow-up carries the token its first reply issued.
#[derive(Debug, Clone)]
pub struct UploadPart<'a> {
    pub payload: &'a [u8],
    /// The client's MIME hint. Recorded in the debug log and otherwise
    /// ignored: the sniff decides, and the reply overwrites.
    pub declared: Option<&'a str>,
    pub token: Option<Handle>,
    pub index: u16,
    pub count: Option<u16>,
    pub last: bool,
}

/// What a part did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadOutcome {
    /// More parts expected; echo this token on each.
    Token(Handle),
    /// The pipeline ran and this is the handle.
    Done(MediaRef),
}

/// What one part did to its upload session.
enum Assembly {
    /// The session is open and expects more; this is its key.
    Waiting(Handle),
    /// Everything has arrived: the payload, and the type the client
    /// declared on the part that opened it.
    Whole(Vec<u8>, Option<String>),
}

/// A live handle's record.
struct Entry {
    mime: MediaType,
    width: u32,
    height: u32,
    /// The canonical byte count, kept separately because `bytes` is
    /// dropped by a revocation and the metadata outlives it.
    size: u32,
    bytes: Option<Arc<Vec<u8>>>,
    /// SHA-256 of the canonical bytes — what a revocation's re-upload
    /// block is keyed on (moderation.md §3.2).
    hash: [u8; 32],
    uploader: Principal,
    /// The uploader's account, for the operator's log and for a purge by
    /// sender identity.
    uploader_login: String,
    created: Instant,
    expires: Instant,
    /// A report pins a handle past its TTL while a moderator judges it
    /// (moderation.md §4.3).
    pinned_until: Option<Instant>,
    audience: HashSet<Principal>,
}

impl Entry {
    fn live(&self, now: Instant) -> bool {
        self.bytes.is_some() && !self.dead(now)
    }

    fn dead(&self, now: Instant) -> bool {
        let until = match self.pinned_until {
            Some(pin) if pin > self.expires => pin,
            _ => self.expires,
        };
        now >= until
    }

    fn media_ref(&self, id: Handle, now: Instant) -> MediaRef {
        MediaRef {
            id: self.live(now).then_some(id),
            mime: self.mime,
            width: self.width,
            height: self.height,
            bytes: self.size,
        }
    }
}

/// A chunked upload in flight.
struct Upload {
    login: String,
    principal: Principal,
    declared: Option<String>,
    count: u16,
    /// The next index this session expects. Out-of-order and duplicate
    /// parts discard the session rather than being reordered: a client
    /// that cannot count its own chunks is one whose bytes should not be
    /// assembled on trust.
    next: u16,
    buf: Vec<u8>,
    last_seen: Instant,
}

/// A sliding window of recent events, for one quota.
#[derive(Default)]
struct Window {
    hits: VecDeque<Instant>,
}

impl Window {
    /// Would one more fit? Prunes what has aged out, then answers, and
    /// records nothing — so a refused attempt does not count against the
    /// next, and a caller holding two of these can ask both before it
    /// charges either.
    fn would_admit(&mut self, now: Instant, span: Duration, max: u32) -> bool {
        while let Some(&front) = self.hits.front() {
            if now.duration_since(front) >= span {
                self.hits.pop_front();
            } else {
                break;
            }
        }
        (self.hits.len() as u32) < max
    }

    /// Spend the slot `would_admit` just said was there. Pruning already
    /// happened there, so this only records.
    fn charge(&mut self, now: Instant) {
        self.hits.push_back(now);
    }

    /// Nothing left inside the window, so the whole bucket is
    /// indistinguishable from a fresh one and the sweep may drop it.
    fn stale(&self, now: Instant, span: Duration) -> bool {
        self.hits
            .back()
            .is_none_or(|&last| now.duration_since(last) >= span)
    }
}

#[derive(Default)]
struct AccountRate {
    last_upload: Option<Instant>,
    hour: Window,
}

#[derive(Default)]
struct StoreInner {
    items: HashMap<Handle, Entry>,
    /// Handles oldest-first, for eviction. A handle is pushed once and
    /// removed when it goes, so this is the insertion order and nothing
    /// re-sorts it.
    order: VecDeque<Handle>,
    total_bytes: usize,
    uploads: HashMap<Handle, Upload>,
    per_account: HashMap<String, AccountRate>,
    per_addr: HashMap<IpAddr, Window>,
    /// Canonical hashes a moderator has blocked. Nuisance filtering: the
    /// same file re-uploaded is caught, a recompressed one is not, and
    /// the config says so.
    blocked: HashSet<[u8; 32]>,
}

/// The in-memory media store.
pub(crate) struct MediaStore {
    codec: Arc<dyn MediaCodec>,
    cfg: MediaConfig,
    inner: Mutex<StoreInner>,
}

impl MediaStore {
    fn new(codec: Arc<dyn MediaCodec>, cfg: MediaConfig) -> Self {
        MediaStore {
            codec,
            cfg,
            inner: Mutex::new(StoreInner::default()),
        }
    }
}

/// What the roster knows about an uploading session, copied out before
/// anything expensive happens so the roster's lock is not held across a
/// decode.
struct Uploader {
    login: String,
    addr: Option<IpAddr>,
    principal: Principal,
}

impl Core {
    /// Give the domain an image pipeline. Without one there is no
    /// `[media]` section, the legacy wire never confirms bit 3, the ng
    /// wire never lists the cap, and every media call refuses.
    pub fn with_media(mut self, codec: Arc<dyn MediaCodec>, cfg: MediaConfig) -> Self {
        self.media = Some(MediaStore::new(codec, cfg));
        self
    }

    /// Is inline media configured at all?
    pub fn media_enabled(&self) -> bool {
        self.media.is_some()
    }

    /// The limits, for the two wires to advertise. Both read this one
    /// place so a client is never told a number the store does not hold.
    pub fn media_config(&self) -> Option<&MediaConfig> {
        self.media.as_ref().map(|m| &m.cfg)
    }

    /// This session's principal, which is what a download presents.
    pub fn principal_of(&self, uid: Uid) -> Option<Principal> {
        let r = self.roster.lock().unwrap();
        r.users.get(&uid).map(|s| Principal::Session {
            uid,
            serial: s.serial,
        })
    }

    /// Accept one part of an upload, running the pipeline when the last
    /// one lands.
    ///
    /// Callers must be off the reactor: the final part decodes and
    /// re-encodes an image on this thread.
    pub fn media_upload_part(
        &self,
        uid: Uid,
        part: UploadPart<'_>,
    ) -> Result<UploadOutcome, MediaReject> {
        let store = self.media.as_ref().ok_or(MediaReject::NotAuthorized)?;
        let who = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&uid).ok_or(MediaReject::NotAuthorized)?;
            // The spec has operators grant this explicitly; an account
            // file that says nothing says no, and the bootstrap guest
            // says nothing.
            if !sess.access.has(bit::SEND_MEDIA) {
                return Err(MediaReject::NotAuthorized);
            }
            Uploader {
                login: sess.login.clone(),
                addr: sess.addr,
                principal: Principal::Session {
                    uid,
                    serial: sess.serial,
                },
            }
        };
        store.accept_part(&who, part)
    }

    /// The bytes, for a session that may have them.
    ///
    /// A session presents **two** principals: itself, and its mailbox
    /// where it has one. That is what makes a private message's image
    /// readable by the account it was sent to rather than only by the
    /// socket that happened to be attached when it arrived — the set
    /// captured a mailbox, and this is the other end of that.
    ///
    /// The mailbox is offered only by a session that actually owns one
    /// (`has_inbox`). A guest's mailbox is `guest`, a login several
    /// people share, and presenting *that* would let any guest fetch an
    /// image sent to another.
    pub fn media_fetch(&self, viewer: Uid, id: &Handle) -> Option<Fetched> {
        let (session, mailbox) = {
            let r = self.roster.lock().unwrap();
            let sess = r.users.get(&viewer)?;
            (
                Principal::Session {
                    uid: viewer,
                    serial: sess.serial,
                },
                sess.has_inbox.then(|| Principal::Mailbox(sess.mailbox())),
            )
        };
        self.media_fetch_as(&session, id)
            .or_else(|| mailbox.and_then(|m| self.media_fetch_as(&m, id)))
    }

    /// The same, for one named principal: what a moderator's tooling
    /// and the domain's own tests use. One answer — `None` — for "no
    /// such handle", "expired", "revoked" and "not yours", so a download
    /// cannot be used to test whether a handle exists.
    pub fn media_fetch_as(&self, who: &Principal, id: &Handle) -> Option<Fetched> {
        let store = self.media.as_ref()?;
        let now = Instant::now();
        let inner = store.inner.lock().unwrap();
        let entry = inner.items.get(id)?;
        // Not on the set, no such handle, expired, revoked: one answer,
        // so a download cannot be used to test whether a handle exists.
        if !entry.live(now) || !(entry.uploader == *who || entry.audience.contains(who)) {
            return None;
        }
        Some(Fetched {
            mime: entry.mime,
            bytes: entry.bytes.clone()?,
        })
    }

    /// The metadata alone, with the handle only while the bytes are
    /// there. What a stored row resolves through before it goes on an
    /// event.
    pub fn media_meta(&self, id: &Handle) -> Option<MediaRef> {
        let store = self.media.as_ref()?;
        let now = Instant::now();
        let inner = store.inner.lock().unwrap();
        inner.items.get(id).map(|e| e.media_ref(*id, now))
    }

    /// Add a principal to a handle's set. The narrow exception to
    /// "fixed at relay time": `[media] history_access = "readers"` for
    /// public chat (§5.4), and a report handing moderators the image
    /// they have to judge (moderation.md §4.3). Both are deliberate and
    /// both are the operator's decision.
    pub fn media_grant(&self, id: &Handle, who: Principal) -> bool {
        let Some(store) = self.media.as_ref() else {
            return false;
        };
        let now = Instant::now();
        let mut inner = store.inner.lock().unwrap();
        match inner.items.get_mut(id) {
            Some(e) if e.live(now) => {
                e.audience.insert(who);
                true
            }
            _ => false,
        }
    }

    /// Hold a handle past its TTL while a report on it is open.
    pub fn media_pin(&self, id: &Handle, until: Duration) -> bool {
        let Some(store) = self.media.as_ref() else {
            return false;
        };
        let now = Instant::now();
        let mut inner = store.inner.lock().unwrap();
        match inner.items.get_mut(id) {
            Some(e) if e.bytes.is_some() => {
                e.pinned_until = Some(now + until);
                true
            }
            _ => false,
        }
    }

    /// Drop an image's bytes now, and optionally refuse its canonical
    /// hash from then on (moderation.md §3.2).
    ///
    /// The metadata stays for the handle's remaining life, so lines and
    /// inbox rows that reference it keep rendering a placeholder rather
    /// than nothing, and everyone who could have it on screen is told.
    pub fn media_revoke(&self, id: &Handle, block: bool) -> Option<MediaRef> {
        let store = self.media.as_ref()?;
        let now = Instant::now();
        let (reference, audience) = {
            let mut inner = store.inner.lock().unwrap();
            let entry = inner.items.get_mut(id)?;
            let freed = entry.bytes.take().map(|b| b.len()).unwrap_or(0);
            let hash = entry.hash;
            let reference = MediaRef {
                id: None,
                mime: entry.mime,
                width: entry.width,
                height: entry.height,
                bytes: entry.size,
            };
            let audience: Vec<Principal> = entry
                .audience
                .iter()
                .cloned()
                .chain(std::iter::once(entry.uploader.clone()))
                .collect();
            inner.total_bytes = inner.total_bytes.saturating_sub(freed);
            if block {
                inner.blocked.insert(hash);
            }
            (reference, audience)
        };
        // The store's lock is released before the roster's is taken: the
        // one direction this pair is ever allowed in.
        let mut r = self.roster.lock().unwrap();
        let ev = Event::MediaRevoked { id: *id };
        for who in audience {
            if let Principal::Session { uid, serial } = who {
                if r.users.get(&uid).is_some_and(|s| s.serial == serial) {
                    r.send_to(uid, ev.clone());
                }
            }
        }
        let _ = now;
        Some(reference)
    }

    /// Who uploaded a handle, and when — what a moderator's audit row
    /// records about an image (moderation.md §3.2) and what an operator
    /// answering "where did this come from?" reads. Never reaches a
    /// client.
    pub fn media_owner(&self, id: &Handle) -> Option<(String, [u8; 32], Duration)> {
        let store = self.media.as_ref()?;
        let now = Instant::now();
        let inner = store.inner.lock().unwrap();
        let entry = inner.items.get(id)?;
        Some((
            entry.uploader_login.clone(),
            entry.hash,
            now.duration_since(entry.created),
        ))
    }

    /// Is this canonical hash blocked? The upload path asks; a caller
    /// re-uploading a revoked file gets the generic rejection.
    pub fn media_hash_blocked(&self, hash: &[u8; 32]) -> bool {
        self.media
            .as_ref()
            .is_some_and(|s| s.inner.lock().unwrap().blocked.contains(hash))
    }

    /// Drop expired handles and abandoned upload sessions. The hourly
    /// maintenance task calls this; every access re-checks expiry
    /// itself, so nothing is served between sweeps that a sweep would
    /// have taken.
    pub fn media_sweep(&self) -> usize {
        let Some(store) = self.media.as_ref() else {
            return 0;
        };
        let now = Instant::now();
        let mut inner = store.inner.lock().unwrap();
        let idle = store.cfg.upload_idle;
        inner
            .uploads
            .retain(|_, u| now.duration_since(u.last_seen) < idle);
        let dead: Vec<Handle> = inner
            .items
            .iter()
            .filter(|(_, e)| e.dead(now))
            .map(|(h, _)| *h)
            .collect();
        for h in &dead {
            inner.remove(h);
        }
        dead.len()
    }

    /// Resolve a handle a sender has attached to a chat line or a
    /// message, capturing nothing yet.
    ///
    /// Only the session that uploaded it may attach it, and only while
    /// the bytes live: a handle someone else uploaded is not this
    /// sender's to republish, and one whose bytes have gone would relay
    /// a reference that resolves for nobody.
    ///
    /// **Ownership is the session, not the account**, which is the one
    /// place these two differ. A private message's *audience* is stated
    /// in mailboxes, so that mail read tomorrow still resolves; but an
    /// upload happened in a session, and "did you upload this" is a
    /// question about that session rather than about everyone who has
    /// ever logged in as you.
    pub(crate) fn media_for_send(&self, sender: Uid, id: &Handle) -> Result<MediaRef, MediaReject> {
        // The roster's lock is taken and released before the store's,
        // which is the order this pair is allowed in.
        let who = self
            .principal_of(sender)
            .ok_or(MediaReject::NotAuthorized)?;
        let store = self.media.as_ref().ok_or(MediaReject::NotAuthorized)?;
        let now = Instant::now();
        let inner = store.inner.lock().unwrap();
        let entry = inner.items.get(id).ok_or(MediaReject::NotAuthorized)?;
        if !entry.live(now) || entry.uploader != who {
            return Err(MediaReject::NotAuthorized);
        }
        Ok(entry.media_ref(*id, now))
    }

    /// Record who a relay just showed an image to. Called with the
    /// roster's lock held, which is why it takes principals rather than
    /// looking anything up.
    pub(crate) fn media_capture<I: IntoIterator<Item = Principal>>(&self, id: &Handle, who: I) {
        let Some(store) = self.media.as_ref() else {
            return;
        };
        let mut inner = store.inner.lock().unwrap();
        if let Some(entry) = inner.items.get_mut(id) {
            entry.audience.extend(who);
        }
    }
}

impl StoreInner {
    fn remove(&mut self, id: &Handle) {
        if let Some(e) = self.items.remove(id) {
            if let Some(b) = e.bytes {
                self.total_bytes = self.total_bytes.saturating_sub(b.len());
            }
        }
        if let Some(pos) = self.order.iter().position(|h| h == id) {
            self.order.remove(pos);
        }
    }
}

impl MediaStore {
    /// The upload state machine, and then the pipeline.
    fn accept_part(
        &self,
        who: &Uploader,
        part: UploadPart<'_>,
    ) -> Result<UploadOutcome, MediaReject> {
        let now = Instant::now();
        // Phase one, under the store's lock: quotas, session bookkeeping,
        // assembly. Nothing here is more expensive than a memcpy.
        let phase_one = {
            let mut inner = self.inner.lock().unwrap();
            inner.sweep(now, self.cfg.upload_idle);
            match part.token {
                None => self.open(&mut inner, who, &part, now)?,
                Some(token) => self.continue_upload(&mut inner, who, &part, token, now)?,
            }
        };
        let (assembled, declared) = match phase_one {
            // More parts to come. The token the client echoes is the key
            // its session is stored under — the same value, not another
            // draw from the CSPRNG.
            Assembly::Waiting(token) => return Ok(UploadOutcome::Token(token)),
            Assembly::Whole(bytes, declared) => (bytes, declared),
        };

        // Phase two, with no lock held: decode, re-encode, hash.
        let canonical = self.codec.canonicalize(&assembled)?;
        // The hint travels with the *first* chunk of a chunked upload,
        // so it is the session's, not this part's.
        if let Some(declared) = declared.filter(|d| d != canonical.mime.mime()) {
            // Not an error — the declared type is a hint and the sniff
            // decides — but a client whose hint is routinely wrong is
            // worth being able to see.
            tracing::debug!(
                target: "media",
                login = %who.login,
                declared = %declared,
                canonical = canonical.mime.mime(),
                "declared media type is not what arrived",
            );
        }
        let hash: [u8; 32] = Sha256::digest(&canonical.bytes).into();

        // Phase three, under the lock again: the block list, eviction,
        // and the handle.
        let mut inner = self.inner.lock().unwrap();
        if inner.blocked.contains(&hash) {
            // Not at debug: an upload of something a moderator revoked
            // is worth an operator seeing without turning anything on.
            tracing::info!(
                target: "media",
                login = %who.login,
                "upload refused: canonical hash is blocked",
            );
            return Err(MediaReject::Generic);
        }
        let id = new_handle().ok_or(MediaReject::Generic)?;
        let size = canonical.bytes.len();
        // Evicting the oldest beats refusing the newest: the spec lets a
        // server drop handles early, and the per-account and per-address
        // quotas are the real bound on a hostile uploader. This cap is
        // what keeps the process alive when those are set generously.
        inner.evict_to_fit(size, self.cfg.max_total_bytes, now);
        let entry = Entry {
            mime: canonical.mime,
            width: canonical.width,
            height: canonical.height,
            size: size as u32,
            bytes: Some(Arc::new(canonical.bytes)),
            hash,
            uploader: who.principal.clone(),
            uploader_login: who.login.clone(),
            created: now,
            expires: now + self.cfg.handle_ttl,
            pinned_until: None,
            audience: HashSet::new(),
        };
        // The handle it was just issued, whatever the clock says about
        // an expiry that has not been reached yet. `media_ref` is for
        // *resolving* a handle later, where "gone" is a real answer;
        // here there is nothing to resolve.
        let reference = MediaRef {
            id: Some(id),
            mime: entry.mime,
            width: entry.width,
            height: entry.height,
            bytes: entry.size,
        };
        inner.total_bytes += size;
        inner.items.insert(id, entry);
        inner.order.push_back(id);
        // The operator's line about an image, and everything it is
        // allowed to say: a handle *prefix*, enough to pair an upload
        // with a download in one log and not enough to fetch with
        // (§10). Never a byte of the image itself.
        tracing::debug!(
            target: "media",
            "accepted [image: {}, {size} bytes, {}x{}] from {} as {}…",
            canonical.mime.mime(),
            canonical.width,
            canonical.height,
            who.login,
            handle_prefix(&id),
        );
        Ok(UploadOutcome::Done(reference))
    }

    /// A part with no token: either the whole image or the first chunk.
    /// Returns the assembled bytes when there is nothing more to wait
    /// for.
    fn open(
        &self,
        inner: &mut StoreInner,
        who: &Uploader,
        part: &UploadPart<'_>,
        now: Instant,
    ) -> Result<Assembly, MediaReject> {
        // The rate limit is checked once, when an upload starts, so a
        // chunked upload costs what a single-shot one costs.
        self.check_rate(inner, who, now)?;
        if part.payload.len() > self.cfg.max_bytes {
            return Err(MediaReject::TooLarge);
        }
        let count = part.count.unwrap_or(1);
        if part.last && count <= 1 {
            if part.index != 0 {
                return Err(MediaReject::Generic);
            }
            return Ok(Assembly::Whole(
                part.payload.to_vec(),
                part.declared.map(str::to_owned),
            ));
        }
        if part.last || count < 2 || part.index != 0 {
            // "final with a count above one", "not final with a count
            // below two", "a first chunk that is not index zero": each
            // is a client that cannot count its own chunks.
            return Err(MediaReject::Generic);
        }
        let open = inner
            .uploads
            .values()
            .filter(|u| u.login == who.login)
            .count();
        if open >= self.cfg.upload_sessions {
            return Err(MediaReject::Busy);
        }
        let token = new_handle().ok_or(MediaReject::Generic)?;
        inner.uploads.insert(
            token,
            Upload {
                login: who.login.clone(),
                principal: who.principal.clone(),
                declared: part.declared.map(str::to_owned),
                count,
                next: 1,
                buf: part.payload.to_vec(),
                last_seen: now,
            },
        );
        Ok(Assembly::Waiting(token))
    }

    /// A part carrying a token: a follow-up chunk.
    fn continue_upload(
        &self,
        inner: &mut StoreInner,
        who: &Uploader,
        part: &UploadPart<'_>,
        token: Handle,
        now: Instant,
    ) -> Result<Assembly, MediaReject> {
        let Some(upload) = inner.uploads.get(&token) else {
            return Err(MediaReject::Generic);
        };
        // A token is a bearer credential for one upload session, and the
        // session belongs to the account that opened it.
        if upload.principal != who.principal {
            return Err(MediaReject::NotAuthorized);
        }
        // Out of order, over the cap, or a final flag that disagrees
        // with the declared count: each discards the session rather than
        // being accommodated. A client that cannot count its own chunks
        // is one whose bytes should not be assembled on trust.
        let over = upload.buf.len() + part.payload.len() > self.cfg.max_bytes;
        let malformed = part.index != upload.next || part.last != (part.index + 1 == upload.count);
        if over || malformed {
            inner.uploads.remove(&token);
            return Err(if malformed {
                MediaReject::Generic
            } else {
                MediaReject::TooLarge
            });
        }
        let upload = inner.uploads.get_mut(&token).expect("just resolved");
        upload.buf.extend_from_slice(part.payload);
        upload.next += 1;
        upload.last_seen = now;
        if part.last {
            let done = inner.uploads.remove(&token).expect("just borrowed");
            return Ok(Assembly::Whole(done.buf, done.declared));
        }
        Ok(Assembly::Waiting(token))
    }

    fn check_rate(
        &self,
        inner: &mut StoreInner,
        who: &Uploader,
        now: Instant,
    ) -> Result<(), MediaReject> {
        let hour = Duration::from_secs(3600);
        // Both buckets are *asked* before either is charged. Charging as
        // we go would let a refusal from the second one still spend the
        // first's allowance, so two guests behind one address could
        // drain the shared `guest` account's hour without a single
        // upload landing — the opposite of what a quota is for.
        let account = inner.per_account.entry(who.login.clone()).or_default();
        if account
            .last_upload
            .is_some_and(|t| now.duration_since(t) < self.cfg.upload_interval)
        {
            return Err(MediaReject::RateLimited);
        }
        if !account
            .hour
            .would_admit(now, hour, self.cfg.upload_per_hour)
        {
            return Err(MediaReject::RateLimited);
        }
        // Every guest shares the `guest` account's bucket, deliberately:
        // the shared door is the one that needs the throttle most. The
        // address bucket is what tells two guests apart.
        if let Some(addr) = who.addr {
            let per_addr = inner.per_addr.entry(addr).or_default();
            if !per_addr.would_admit(now, hour, self.cfg.upload_per_hour_per_addr) {
                return Err(MediaReject::RateLimited);
            }
        }
        // Nothing can refuse it now, so both buckets pay.
        let account = inner.per_account.entry(who.login.clone()).or_default();
        account.hour.charge(now);
        account.last_upload = Some(now);
        if let Some(addr) = who.addr {
            inner.per_addr.entry(addr).or_default().charge(now);
        }
        Ok(())
    }
}

impl StoreInner {
    fn sweep(&mut self, now: Instant, idle: Duration) {
        self.uploads
            .retain(|_, u| now.duration_since(u.last_seen) < idle);
        // The rate-limit maps too, or they are a slow leak keyed on
        // whatever address ever uploaded: an entry with no hits inside
        // the window and no interval left to enforce says nothing a
        // fresh default would not.
        let hour = Duration::from_secs(3600);
        self.per_addr.retain(|_, w| !w.stale(now, hour));
        self.per_account.retain(|_, a| {
            !a.hour.stale(now, hour) || a.last_upload.is_some_and(|t| now.duration_since(t) < hour)
        });
        let dead: Vec<Handle> = self
            .items
            .iter()
            .filter(|(_, e)| e.dead(now))
            .map(|(h, _)| *h)
            .collect();
        for h in &dead {
            self.remove(h);
        }
    }

    /// Drop oldest-first until the incoming image fits, **skipping
    /// anything a report has pinned**.
    ///
    /// A pin exists so a handle outlives its TTL while a moderator
    /// judges it (`moderation.md` §4.3), and a pinned handle is by
    /// definition an old one — so it sits at the front of `order`, which
    /// is exactly where a plain oldest-first eviction reaches first. The
    /// next upload after a report would otherwise drop the evidence.
    /// Falling short of the cap is the right failure here: the pinned
    /// set is bounded by what moderators have asked for, and refusing to
    /// evict is recoverable where losing a report is not.
    fn evict_to_fit(&mut self, incoming: usize, cap: usize, now: Instant) {
        let mut skipped = 0;
        while self.total_bytes + incoming > cap {
            let Some(&oldest) = self.order.get(skipped) else {
                return;
            };
            if self
                .items
                .get(&oldest)
                .is_some_and(|e| e.pinned_until.is_some_and(|pin| pin > now))
            {
                skipped += 1;
                continue;
            }
            self.remove(&oldest);
        }
    }
}

/// A handle, or `None` if the OS CSPRNG refused — which is not the
/// client's fault and not something it can retry usefully.
fn new_handle() -> Option<Handle> {
    let mut h = [0u8; HANDLE_LEN];
    getrandom::getrandom(&mut h).ok()?;
    Some(h)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding. Hand-rolled rather than a dependency: the
/// domain encodes exactly one sixteen-byte thing, and the alphabet is
/// the point.
fn b64url(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
    for group in raw.chunks(3) {
        let b = [
            group[0],
            *group.get(1).unwrap_or(&0),
            *group.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let chars = [
            B64[(n >> 18) as usize & 63],
            B64[(n >> 12) as usize & 63],
            B64[(n >> 6) as usize & 63],
            B64[n as usize & 63],
        ];
        // One character per six bits that actually carry input.
        let keep = group.len() + 1;
        for &c in chars.iter().take(keep) {
            out.push(c as char);
        }
    }
    out
}

fn unb64url(s: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut have = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for c in s.bytes() {
        let v = B64.iter().position(|&b| b == c)? as u32;
        bits = (bits << 6) | v;
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push((bits >> have) as u8);
        }
    }
    // Trailing bits must be zero padding, not dropped input.
    if bits & ((1 << have) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests;
