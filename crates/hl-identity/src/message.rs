//! Signed messages (`docs/e2e-messages.md` §3.1–§3.7): a private message,
//! a line of public chat and a news article, each signed by the sender
//! device's key and bound to its scope; their detached form and its link
//! form (§5); the order a reader checks them in (§3.5), ending in the
//! states a client shows (§8); and the padding a sealed one is sent in.
//!
//! Every form is checked by turning it back into the whole map, whose
//! signature is the one that verifies: a detached form gets its text
//! back, and a link form its certificate first.

use sha2::{Digest, Sha256};

use crate::cbor::{self, map, Value};
use crate::cert::{caps, DeviceCert};
use crate::error::Error;
use crate::keys::{DeviceKey, Fingerprint, PublicKey};
use crate::signed::{self, Envelope, VERSION};

pub const MESSAGE_DOMAIN: &str = "hl-identity/message/v1";
pub const CHAT_DOMAIN: &str = "hl-identity/chat/v1";
pub const NEWS_DOMAIN: &str = "hl-identity/news/v1";

/// `S`, the skew allowance (§3.1), in seconds.
pub const SKEW: u64 = 600;
/// A certificate a message carries crosses the network in full (§2).
pub const CERT_MAX_BYTES: usize = 512;
/// The bound the classic wire's `DATA_MESSAGE_SIGNED` shares (§3.1).
pub const DETACHED_MAX_BYTES: usize = 1020;
/// A link form leaves room for other extensions beside a 904 (§5).
pub const LINK_MAX_BYTES: usize = 256;

/// The sizes a sealed message's plaintext is padded to (§3.7). A
/// deniable box's are each 32 bytes less, for the key it carries.
pub const PAD_SIZES: [usize; 6] = [512, 1024, 2048, 4096, 8192, 17_103];
const DENIABLE_KEY_BYTES: usize = 32;

/// Each CR LF pair, then each lone CR, as one LF (§3.1). Nothing else
/// changes: a verifier re-checks the bytes it was given.
pub fn canonicalize(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// Holds no C0 control but LF and TAB, so no CR: what a server refuses
/// in a signed request rather than canonicalize (§3.1, §4.7).
pub fn is_canonical(text: &str) -> bool {
    !text.chars().any(|c| c < ' ' && c != '\n' && c != '\t')
}

/// The three signed objects, for the code they share.
pub trait Object: Sized {
    const DOMAIN: &'static str;
    /// The texts a detached form is carried beside, one per key of
    /// [`Object::TEXT_KEYS`], so a reader cannot hand over too few.
    type Texts<'a>: Copy + IntoIterator<Item = &'a str>;
    /// The keys a detached form leaves out, in the order a reader hands
    /// their texts over.
    const TEXT_KEYS: Self::Texts<'static>;
    /// Bounds a whole map before it is decoded.
    const WHOLE_MAX_BYTES: usize;
    /// What a reader checks the object's scope against.
    type Scope;

    fn id(&self) -> [u8; 16];
    fn sent(&self) -> u64;
    fn cert(&self) -> &[u8];
    /// The map without `sig`, its texts canonical.
    fn unsigned(&self) -> Value;
    /// Read and check the fields of a whole map, under the limits of the
    /// form it arrived in.
    fn from_value(v: &Value, detached: bool) -> Result<Self, Error>;
    fn place(&self, expect: &Self::Scope) -> Place;

    /// Sign with the device key the certificate names, refusing anything
    /// a reader would: a field out of bounds, or a certificate that does
    /// not allow messages or is not valid at `sent`.
    fn sign(&self, device: &DeviceKey) -> Result<Vec<u8>, Error> {
        let unsigned = self.unsigned();
        Self::from_value(&unsigned, false)?;
        let cert = check_cert(self.cert(), self.sent(), self.sent())?;
        if cert.device != device.public() {
            return Err(Error::KeyMismatch);
        }
        Ok(signed::seal(unsigned, |body| {
            device.sign(Self::DOMAIN, body)
        }))
    }
}

/// How an object's scope compares with where it is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    Here,
    Elsewhere,
    /// The reader has nothing to compare it with.
    Unknown,
}

/// A private message (§3.2), bound to its recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateMessage {
    pub id: [u8; 16],
    pub sent: u64,
    pub to: Fingerprint,
    pub cert: Vec<u8>,
    pub text: String,
    /// Whole maps only.
    pub quote: Option<String>,
    pub auto: bool,
}

/// A line of public chat (§3.3), bound to its server and room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatLine {
    pub id: [u8; 16],
    pub sent: u64,
    pub server: PublicKey,
    /// 0 for the lobby, or a curated room's id.
    pub room: u64,
    pub cert: Vec<u8>,
    pub text: String,
    pub act: bool,
}

/// A news article (§3.4), bound to its server and category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Article {
    pub id: [u8; 16],
    pub sent: u64,
    pub server: PublicKey,
    /// The category's node guid.
    pub category: [u8; 16],
    pub parent: Option<Parent>,
    pub cert: Vec<u8>,
    pub subject: String,
    pub body: String,
    pub mime: String,
}

/// The article a reply answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parent {
    /// Its article id on the server the reply's scope names.
    pub article: u64,
    /// Its own `id` and its signer's fingerprint, when it is signed.
    pub signed: Option<([u8; 16], Fingerprint)>,
}

/// Where a public line is shown: the server key it should name, `None`
/// when the reader has none for it (a ghost whose row has no
/// `server_key`), and the room, 0 for the lobby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatScope {
    pub server: Option<PublicKey>,
    pub room: u64,
}

/// Where an article is shown: this server, the category it is listed
/// in, and the article it is threaded under, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewsScope {
    pub server: PublicKey,
    pub category: [u8; 16],
    pub parent: Option<Parent>,
}

impl Object for PrivateMessage {
    const DOMAIN: &'static str = MESSAGE_DOMAIN;
    type Texts<'a> = [&'a str; 1];
    const TEXT_KEYS: [&'static str; 1] = ["text"];
    /// The largest plaintext a sealed message is padded to (§3.7).
    const WHOLE_MAX_BYTES: usize = PAD_SIZES[PAD_SIZES.len() - 1];
    /// The identity the reader's session proved, if any.
    type Scope = Option<Fingerprint>;

    fn id(&self) -> [u8; 16] {
        self.id
    }

    fn sent(&self) -> u64 {
        self.sent
    }

    fn cert(&self) -> &[u8] {
        &self.cert
    }

    fn unsigned(&self) -> Value {
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("id", Some(Value::Bytes(self.id.to_vec()))),
            ("sent", Some(Value::Uint(self.sent))),
            ("to", Some(Value::Bytes(self.to.0.to_vec()))),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
            ("text", Some(Value::Text(canonicalize(&self.text)))),
            ("quote", self.quote.as_deref().map(canonical_value)),
            ("auto", self.auto.then_some(Value::Bool(true))),
        ])
    }

    fn from_value(v: &Value, detached: bool) -> Result<Self, Error> {
        refuse(v, "in")?;
        let (id, sent, cert) = common(v)?;
        let quote = signed::opt_text(v, "quote")?;
        if let Some(q) = &quote {
            if detached {
                return Err(Error::BadField("quote"));
            }
            check_text(q, "quote", 1, 8192)?;
        }
        let text = signed::text(v, "text")?;
        check_text(&text, "text", 1, if detached { 4096 } else { 8192 })?;
        Ok(PrivateMessage {
            id,
            sent,
            to: Fingerprint(signed::bytes32(v, "to")?),
            cert,
            text,
            quote,
            auto: only_true(v, "auto")?,
        })
    }

    fn place(&self, reader: &Option<Fingerprint>) -> Place {
        match reader {
            None => Place::Unknown,
            Some(fp) if *fp == self.to => Place::Here,
            Some(_) => Place::Elsewhere,
        }
    }
}

impl Object for ChatLine {
    const DOMAIN: &'static str = CHAT_DOMAIN;
    type Texts<'a> = [&'a str; 1];
    const TEXT_KEYS: [&'static str; 1] = ["text"];
    /// Its detached form's bound, its text at its longest and the byte
    /// a longer map head can take.
    const WHOLE_MAX_BYTES: usize = DETACHED_MAX_BYTES + text_entry(4, 4096) + 1;
    type Scope = ChatScope;

    fn id(&self) -> [u8; 16] {
        self.id
    }

    fn sent(&self) -> u64 {
        self.sent
    }

    fn cert(&self) -> &[u8] {
        &self.cert
    }

    fn unsigned(&self) -> Value {
        let scope = map(vec![
            ("server", Some(Value::Bytes(self.server.to_vec()))),
            ("room", Some(Value::Uint(self.room))),
        ]);
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("id", Some(Value::Bytes(self.id.to_vec()))),
            ("sent", Some(Value::Uint(self.sent))),
            ("in", Some(scope)),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
            ("text", Some(Value::Text(canonicalize(&self.text)))),
            ("act", self.act.then_some(Value::Bool(true))),
        ])
    }

    fn from_value(v: &Value, _detached: bool) -> Result<Self, Error> {
        refuse(v, "to")?;
        let (id, sent, cert) = common(v)?;
        let scope = exact(v, "in", &["server", "room"])?;
        let text = signed::text(v, "text")?;
        check_text(&text, "text", 1, 4096)?;
        Ok(ChatLine {
            id,
            sent,
            server: signed::bytes32(scope, "server").map_err(|_| Error::BadField("in"))?,
            room: signed::uint(scope, "room").map_err(|_| Error::BadField("in"))?,
            cert,
            text,
            act: only_true(v, "act")?,
        })
    }

    fn place(&self, expect: &ChatScope) -> Place {
        match expect.server {
            None => Place::Unknown,
            Some(server) if server == self.server && expect.room == self.room => Place::Here,
            Some(_) => Place::Elsewhere,
        }
    }
}

impl Object for Article {
    const DOMAIN: &'static str = NEWS_DOMAIN;
    type Texts<'a> = [&'a str; 2];
    const TEXT_KEYS: [&'static str; 2] = ["subject", "body"];
    /// As a line's, with both its texts.
    const WHOLE_MAX_BYTES: usize =
        DETACHED_MAX_BYTES + text_entry(7, 255) + text_entry(4, 65_535) + 1;
    type Scope = NewsScope;

    fn id(&self) -> [u8; 16] {
        self.id
    }

    fn sent(&self) -> u64 {
        self.sent
    }

    fn cert(&self) -> &[u8] {
        &self.cert
    }

    fn unsigned(&self) -> Value {
        let scope = map(vec![
            ("server", Some(Value::Bytes(self.server.to_vec()))),
            ("category", Some(Value::Bytes(self.category.to_vec()))),
        ]);
        let parent = self.parent.map(|p| {
            map(vec![
                ("article", Some(Value::Uint(p.article))),
                ("id", p.signed.map(|(id, _)| Value::Bytes(id.to_vec()))),
                ("by", p.signed.map(|(_, by)| Value::Bytes(by.0.to_vec()))),
            ])
        });
        map(vec![
            ("v", Some(Value::Uint(VERSION))),
            ("id", Some(Value::Bytes(self.id.to_vec()))),
            ("sent", Some(Value::Uint(self.sent))),
            ("in", Some(scope)),
            ("parent", parent),
            ("cert", Some(Value::Bytes(self.cert.clone()))),
            ("subject", Some(canonical_value(&self.subject))),
            ("body", Some(canonical_value(&self.body))),
            ("mime", Some(Value::Text(self.mime.clone()))),
        ])
    }

    fn from_value(v: &Value, _detached: bool) -> Result<Self, Error> {
        refuse(v, "to")?;
        let (id, sent, cert) = common(v)?;
        let scope = exact(v, "in", &["server", "category"])?;
        let parent = match v.get("parent") {
            None => None,
            Some(_) => {
                let p = exact(v, "parent", &["article", "id", "by"])?;
                let bad = |_| Error::BadField("parent");
                let signed = match (
                    opt_bytes16(p, "id").map_err(bad)?,
                    signed::opt_bytes32(p, "by").map_err(bad)?,
                ) {
                    (Some(id), Some(by)) => Some((id, Fingerprint(by))),
                    (None, None) => None,
                    _ => return Err(Error::BadField("parent")),
                };
                Some(Parent {
                    article: signed::uint(p, "article").map_err(bad)?,
                    signed,
                })
            }
        };
        let subject = signed::text(v, "subject")?;
        check_text(&subject, "subject", 1, 255)?;
        if subject.contains('\n') {
            return Err(Error::BadField("subject"));
        }
        let body = signed::text(v, "body")?;
        check_text(&body, "body", 0, 65_535)?;
        let mime = signed::text(v, "mime")?;
        if mime != "text/plain" && mime != "text/markdown" {
            return Err(Error::BadField("mime"));
        }
        Ok(Article {
            id,
            sent,
            server: signed::bytes32(scope, "server").map_err(|_| Error::BadField("in"))?,
            category: bytes16(scope, "category").map_err(|_| Error::BadField("in"))?,
            parent,
            cert,
            subject,
            body,
            mime,
        })
    }

    fn place(&self, expect: &NewsScope) -> Place {
        if expect.server == self.server
            && expect.category == self.category
            && expect.parent == self.parent
        {
            Place::Here
        } else {
            Place::Elsewhere
        }
    }
}

/// A signed object that passed §3.5's three steps: its map, its
/// certificate and its signature. Holds the whole map, unknown keys
/// included, so every form made from it is covered by the same `sig`.
#[derive(Debug, Clone)]
pub struct Signed<T> {
    pub message: T,
    pub cert: DeviceCert,
    pub(crate) whole: Value,
}

/// What a reader was handed. The texts of a detached or link form come
/// in [`Object::TEXT_KEYS`] order, as received: they are canonicalized
/// here.
pub enum Form<'a, T: Object> {
    Whole(&'a [u8]),
    Detached {
        bytes: &'a [u8],
        texts: T::Texts<'a>,
    },
    /// `cert` is the certificate fetched for it, `None` if none was.
    Link {
        bytes: &'a [u8],
        texts: T::Texts<'a>,
        cert: Option<&'a [u8]>,
    },
}

/// Who the server says sent a message (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    /// The fingerprint it names: a roster row's, or an article's
    /// `from.fingerprint`.
    Named(Fingerprint),
    /// Nothing names one, so the certificate's is the name: a history
    /// line, an inbox row, a ghost's line before user keys cross.
    Certificate,
    /// A sender the server shows without an identity to check against.
    Unknown,
}

/// What a reader knows about a message it was handed.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a, S> {
    /// When the reader's server received it (`at`).
    pub at: u64,
    pub sender: Sender,
    pub scope: &'a S,
}

/// §8's states for a signed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `sent_apart`: `sent` is more than [`SKEW`] from `at`, so it is
    /// shown as sent at its signed time.
    Verified {
        signer: Fingerprint,
        sent_apart: bool,
    },
    /// Valid, and signed for another scope: never shown as said here.
    Elsewhere {
        signer: Fingerprint,
        sent_apart: bool,
    },
    /// Valid or uncheckable, with nothing to check it against. `None`
    /// for a link form whose certificate was not fetched, or was and
    /// does not match.
    Unverified {
        signer: Option<Fingerprint>,
    },
    Invalid(Error),
}

impl<T: Object> Signed<T> {
    /// A whole map, which `at` is when the reader's server received.
    pub fn parse(whole: &[u8], at: u64) -> Result<Self, Error> {
        if whole.len() > T::WHOLE_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Self::verify(cbor::decode_canonical(whole)?, false, at)
    }

    /// A detached form and the texts it was carried beside.
    pub fn parse_detached(bytes: &[u8], texts: T::Texts<'_>, at: u64) -> Result<Self, Error> {
        if bytes.len() > DETACHED_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Self::reassemble(cbor::decode_canonical(bytes)?, texts, at)
    }

    /// A link form with the certificate fetched for it, which must hash
    /// to its `cert_sha256` before anything else is looked at: one that
    /// does not is [`Error::CertMismatch`], which a reader treats as a
    /// certificate it could not fetch (§5).
    pub fn parse_link(
        bytes: &[u8],
        texts: T::Texts<'_>,
        cert: &[u8],
        at: u64,
    ) -> Result<Self, Error> {
        let (value, hash) = link_value(bytes)?;
        if <[u8; 32]>::from(Sha256::digest(cert)) != hash {
            return Err(Error::CertMismatch);
        }
        let Value::Map(mut entries) = value.without("cert_sha256") else {
            unreachable!("link_value returns maps")
        };
        entries.push((Value::Text("cert".into()), Value::Bytes(cert.to_vec())));
        Self::reassemble(Value::Map(entries), texts, at)
    }

    /// [`Signed::content_sha256`] of a link form and its texts, from
    /// before its certificate is held: what a reader keeps of a message
    /// it could not check yet. A form that is not one is refused.
    pub fn link_content_sha256(bytes: &[u8], texts: T::Texts<'_>) -> Result<[u8; 32], Error> {
        let (value, _) = link_value(bytes)?;
        let Value::Map(mut entries) = value.without("cert_sha256").without("sent").without("sig")
        else {
            unreachable!("link_value returns maps")
        };
        for (key, text) in T::TEXT_KEYS.into_iter().zip(texts) {
            entries.push((Value::Text((*key).into()), canonical_value(text)));
        }
        Ok(Sha256::digest(cbor::encode(&Value::Map(entries))).into())
    }

    /// §3.5 in order, then the sender and the scope: the state a reader
    /// shows the message in.
    pub fn read(form: Form<'_, T>, ctx: &Context<'_, T::Scope>) -> Outcome {
        let parsed = match form {
            Form::Whole(bytes) => Self::parse(bytes, ctx.at),
            Form::Detached { bytes, texts } => Self::parse_detached(bytes, texts, ctx.at),
            Form::Link {
                bytes,
                texts,
                cert: Some(cert),
            } => Self::parse_link(bytes, texts, cert, ctx.at),
            Form::Link {
                bytes, cert: None, ..
            } => match link_value(bytes) {
                Ok(_) => return Outcome::Unverified { signer: None },
                Err(e) => Err(e),
            },
        };
        match parsed {
            Ok(signed) => signed.check(ctx),
            Err(Error::CertMismatch) => Outcome::Unverified { signer: None },
            Err(e) => Outcome::Invalid(e),
        }
    }

    /// The sender and the scope (§3.5, §8), for a message already
    /// parsed. A signer other than the one the server names outweighs
    /// the scope; a scope shown to differ outweighs having nothing to
    /// check the rest against.
    pub fn check(&self, ctx: &Context<'_, T::Scope>) -> Outcome {
        let signer = self.signer();
        if matches!(ctx.sender, Sender::Named(fp) if fp != signer) {
            return Outcome::Invalid(Error::KeyMismatch);
        }
        let sent_apart = self.message.sent().abs_diff(ctx.at) > SKEW;
        match (self.message.place(ctx.scope), ctx.sender) {
            (Place::Elsewhere, _) => Outcome::Elsewhere { signer, sent_apart },
            (Place::Unknown, _) | (_, Sender::Unknown) => Outcome::Unverified {
                signer: Some(signer),
            },
            (Place::Here, _) => Outcome::Verified { signer, sent_apart },
        }
    }

    /// SHA-256 of the certificate's identity key, never what a server
    /// says.
    pub fn signer(&self) -> Fingerprint {
        Fingerprint::of(&self.cert.identity)
    }

    pub fn whole(&self) -> Vec<u8> {
        cbor::encode(&self.whole)
    }

    /// Whether two messages say the same thing (§3.6): one signed again,
    /// differing only in `sent`, `cert` and `sig`, is the same message.
    pub fn same_content(&self, other: &Self) -> bool {
        self.content_sha256() == other.content_sha256()
    }

    /// SHA-256 of what [`Signed::same_content`] compares, for a reader
    /// that keeps a message's content without the message.
    pub fn content_sha256(&self) -> [u8; 32] {
        let content = self.whole.without("sent").without("cert").without("sig");
        Sha256::digest(cbor::encode(&content)).into()
    }

    /// The map without its texts, refused where its form's limits are
    /// tighter than a whole map's (a private message's).
    pub fn detached(&self) -> Result<Vec<u8>, Error> {
        T::from_value(&self.whole, true)?;
        let bytes = cbor::encode(&self.detached_value());
        if bytes.len() > DETACHED_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    /// The detached form with `cert` replaced by its SHA-256 (§5).
    pub fn link(&self) -> Result<Vec<u8>, Error> {
        self.detached()?;
        let Value::Map(mut entries) = self.detached_value().without("cert") else {
            unreachable!("a signed object is a map")
        };
        let hash = Sha256::digest(self.message.cert()).to_vec();
        entries.push((Value::Text("cert_sha256".into()), Value::Bytes(hash)));
        let bytes = cbor::encode(&Value::Map(entries));
        if bytes.len() > LINK_MAX_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }

    fn detached_value(&self) -> Value {
        T::TEXT_KEYS
            .into_iter()
            .fold(self.whole.clone(), |v, key| v.without(key))
    }

    fn reassemble(value: Value, texts: T::Texts<'_>, at: u64) -> Result<Self, Error> {
        let Value::Map(mut entries) = value else {
            return Err(Error::NotAMap);
        };
        for (key, text) in T::TEXT_KEYS.into_iter().zip(texts) {
            if entries
                .iter()
                .any(|(k, _)| matches!(k, Value::Text(t) if t == key))
            {
                return Err(Error::BadField(key));
            }
            entries.push((Value::Text((*key).into()), canonical_value(text)));
        }
        Self::verify(Value::Map(entries), true, at)
    }

    fn verify(value: Value, detached: bool, at: u64) -> Result<Self, Error> {
        let env = Envelope::from_value(value)?;
        let message = T::from_value(&env.value, detached)?;
        let cert = check_cert(message.cert(), message.sent(), at)?;
        env.verify(&cert.device, T::DOMAIN)?;
        Ok(Signed {
            message,
            cert,
            whole: env.value,
        })
    }
}

/// Pad a private message's whole map to the smallest size it fits
/// (§3.7), less the sender's key for a deniable box.
pub fn pad(map: &[u8], deniable: bool) -> Result<Vec<u8>, Error> {
    let size = pad_sizes(deniable)
        .find(|&size| map.len() <= size)
        .ok_or(Error::TooLarge)?;
    let mut padded = map.to_vec();
    padded.resize(size, 0);
    Ok(padded)
}

/// The map a padded plaintext holds: exactly one CBOR item from the
/// start, every byte after it zero, at one of its form's sizes.
pub fn unpad(padded: &[u8], deniable: bool) -> Result<&[u8], Error> {
    if !pad_sizes(deniable).any(|size| size == padded.len()) {
        return Err(Error::BadField("padding"));
    }
    let end = cbor::item_len(padded)?;
    if padded[end..].iter().any(|&b| b != 0) {
        return Err(Error::BadField("padding"));
    }
    Ok(&padded[..end])
}

fn pad_sizes(deniable: bool) -> impl Iterator<Item = usize> {
    let less = if deniable { DENIABLE_KEY_BYTES } else { 0 };
    PAD_SIZES.into_iter().map(move |size| size - less)
}

/// §3.5 step 2: a certificate that allows messages, at most
/// [`CERT_MAX_BYTES`], valid at `sent` and at `at`.
pub(crate) fn check_cert(bytes: &[u8], sent: u64, at: u64) -> Result<DeviceCert, Error> {
    if bytes.len() > CERT_MAX_BYTES {
        return Err(Error::BadField("cert"));
    }
    let cert = DeviceCert::parse(bytes)?;
    cert.require(caps::MESSAGE)?;
    signed::check_window(cert.issued, cert.expires, sent, SKEW)?;
    signed::check_window(cert.issued, cert.expires, at, SKEW)?;
    Ok(cert)
}

/// The hash a link form names its certificate by, which a server keeps
/// certificates under (§5).
pub fn link_cert_sha256(bytes: &[u8]) -> Result<[u8; 32], Error> {
    link_value(bytes).map(|(_, hash)| hash)
}

/// A link form's map and the hash it names its certificate by.
fn link_value(bytes: &[u8]) -> Result<(Value, [u8; 32]), Error> {
    if bytes.len() > LINK_MAX_BYTES {
        return Err(Error::TooLarge);
    }
    let value = cbor::decode_canonical(bytes)?;
    if !matches!(value, Value::Map(_)) {
        return Err(Error::NotAMap);
    }
    if value.get("cert").is_some() {
        return Err(Error::BadField("cert"));
    }
    let hash = signed::bytes32(&value, "cert_sha256")?;
    Ok((value, hash))
}

/// The fields all three share, and the key only a link form carries.
fn common(v: &Value) -> Result<([u8; 16], u64, Vec<u8>), Error> {
    refuse(v, "cert_sha256")?;
    Ok((
        bytes16(v, "id")?,
        signed::uint(v, "sent")?,
        signed::bytes(v, "cert")?,
    ))
}

/// A key whose presence would let one object pass for another (§3.1).
fn refuse(v: &Value, key: &'static str) -> Result<(), Error> {
    match v.get(key) {
        Some(_) => Err(Error::BadField(key)),
        None => Ok(()),
    }
}

/// A nested map holding no keys but `allowed`.
fn exact<'a>(v: &'a Value, key: &'static str, allowed: &[&str]) -> Result<&'a Value, Error> {
    match v.get(key) {
        Some(inner @ Value::Map(entries))
            if entries
                .iter()
                .all(|(k, _)| matches!(k, Value::Text(t) if allowed.contains(&t.as_str()))) =>
        {
            Ok(inner)
        }
        Some(_) => Err(Error::BadField(key)),
        None => Err(Error::MissingField(key)),
    }
}

/// A flag present only when true.
fn only_true(v: &Value, key: &'static str) -> Result<bool, Error> {
    match signed::opt_bool(v, key)? {
        Some(false) => Err(Error::BadField(key)),
        flag => Ok(flag.is_some()),
    }
}

/// Canonical and within `min..=max` bytes.
fn check_text(text: &str, key: &'static str, min: usize, max: usize) -> Result<(), Error> {
    if !is_canonical(text) || text.len() < min || text.len() > max {
        return Err(Error::BadField(key));
    }
    Ok(())
}

/// A text key of `key_len` bytes and a text of `max`, encoded.
const fn text_entry(key_len: usize, max: usize) -> usize {
    head_len(key_len) + key_len + head_len(max) + max
}

const fn head_len(n: usize) -> usize {
    match n {
        0..24 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        _ => 5,
    }
}

fn canonical_value(text: &str) -> Value {
    Value::Text(canonicalize(text))
}

pub(crate) fn bytes16(v: &Value, key: &'static str) -> Result<[u8; 16], Error> {
    opt_bytes16(v, key)?.ok_or(Error::MissingField(key))
}

fn opt_bytes16(v: &Value, key: &'static str) -> Result<Option<[u8; 16]>, Error> {
    signed::opt_bytes(v, key)?
        .map(|b| b.as_slice().try_into().map_err(|_| Error::BadField(key)))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKey, ServerKey};

    const SENT: u64 = 1_700_000_000;

    struct World {
        id: IdentityKey,
        dev: DeviceKey,
        server: PublicKey,
        cert: Vec<u8>,
    }

    fn world() -> World {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = DeviceKey::from_seed(&[2u8; 32]);
        let mut c = DeviceCert::for_device(&id, &dev, SENT - 100, 1000).unwrap();
        c.caps = Some(caps::WEB);
        World {
            cert: c.sign(&id),
            id,
            dev,
            server: ServerKey::from_seed(&[5u8; 32]).public(),
        }
    }

    fn line(w: &World, text: &str) -> ChatLine {
        ChatLine {
            id: [9; 16],
            sent: SENT,
            server: w.server,
            room: 0,
            cert: w.cert.clone(),
            text: text.into(),
            act: false,
        }
    }

    fn pm(w: &World, text: &str) -> PrivateMessage {
        PrivateMessage {
            id: [8; 16],
            sent: SENT,
            to: Fingerprint([7; 32]),
            cert: w.cert.clone(),
            text: text.into(),
            quote: None,
            auto: false,
        }
    }

    fn whole<T: Object>(w: &World, m: &T) -> Signed<T> {
        Signed::parse(&m.sign(&w.dev).unwrap(), SENT).unwrap()
    }

    #[test]
    fn a_signer_canonicalizes_and_a_verifier_canonicalizes_what_it_was_handed() {
        let w = world();
        let s = whole(&w, &line(&w, "a\r\nb\rc"));
        assert_eq!(s.message.text, "a\nb\nc");
        assert!(is_canonical(&s.message.text));
        assert!(!is_canonical("a\r\nb"));
        let detached = s.detached().unwrap();
        for received in ["a\nb\nc", "a\rb\rc", "a\r\nb\r\nc"] {
            let back = Signed::<ChatLine>::parse_detached(&detached, [received], SENT).unwrap();
            assert_eq!(back.whole(), s.whole(), "{received:?}");
        }
        assert_eq!(
            Signed::<ChatLine>::parse_detached(&detached, ["a\nb\nd"], SENT).err(),
            Some(Error::BadSignature)
        );
    }

    #[test]
    fn sign_refuses_what_a_reader_would() {
        let w = world();
        let stranger = DeviceKey::from_seed(&[3u8; 32]);
        let mut login_only = DeviceCert::for_device(&w.id, &w.dev, SENT - 100, 1000).unwrap();
        login_only.caps = Some(caps::LOGIN);
        let login_only = login_only.sign(&w.id);
        let expired = DeviceCert::for_device(&w.id, &w.dev, SENT - 5000, 1000)
            .unwrap()
            .sign(&w.id);
        let mut quoted = pm(&w, "hi");
        quoted.quote = Some(String::new());
        let cases = [
            (
                "another device",
                line(&w, "hi").sign(&stranger),
                Error::KeyMismatch,
            ),
            (
                "certificate without bit 1",
                ChatLine {
                    cert: login_only,
                    ..line(&w, "hi")
                }
                .sign(&w.dev),
                Error::CapabilityMissing,
            ),
            (
                "certificate expired at sent",
                ChatLine {
                    cert: expired,
                    ..line(&w, "hi")
                }
                .sign(&w.dev),
                Error::Expired,
            ),
            (
                "empty text",
                line(&w, "").sign(&w.dev),
                Error::BadField("text"),
            ),
            (
                "a bell",
                line(&w, "\u{7}").sign(&w.dev),
                Error::BadField("text"),
            ),
            ("empty quote", quoted.sign(&w.dev), Error::BadField("quote")),
            (
                "message text past a whole map's bound",
                pm(&w, &"x".repeat(8193)).sign(&w.dev),
                Error::BadField("text"),
            ),
        ];
        for (name, got, want) in cases {
            assert_eq!(got, Err(want), "{name}");
        }
    }

    #[test]
    fn a_private_message_detaches_only_within_the_cleartext_limits() {
        let w = world();
        let long = whole(&w, &pm(&w, &"x".repeat(4097)));
        assert_eq!(long.detached(), Err(Error::BadField("text")));
        assert_eq!(long.link(), Err(Error::BadField("text")));
        let mut quoted = pm(&w, "hi");
        quoted.quote = Some("earlier".into());
        assert_eq!(whole(&w, &quoted).detached(), Err(Error::BadField("quote")));
        assert!(whole(&w, &pm(&w, &"x".repeat(4096))).detached().is_ok());
    }

    #[test]
    fn an_article_body_is_bounded_and_may_be_empty() {
        let w = world();
        let article = |body: &str| Article {
            id: [4; 16],
            sent: SENT,
            server: w.server,
            category: [6; 16],
            parent: None,
            cert: w.cert.clone(),
            subject: "s".into(),
            body: body.into(),
            mime: "text/plain".into(),
        };
        assert!(article("").sign(&w.dev).is_ok());
        let longest = Article {
            subject: "s".repeat(255),
            ..article(&"b".repeat(65_535))
        };
        let bytes = longest.sign(&w.dev).unwrap();
        assert!(Signed::<Article>::parse(&bytes, SENT).is_ok());
        assert_eq!(
            article(&"b".repeat(65_536)).sign(&w.dev),
            Err(Error::BadField("body"))
        );
    }

    #[test]
    fn the_certificate_is_checked_at_sent_and_at_receipt() {
        let w = world();
        let bytes = line(&w, "hi").sign(&w.dev).unwrap();
        // The certificate expires at SENT + 900.
        for (at, want) in [
            (SENT + 900 + SKEW, Ok(())),
            (SENT + 900 + SKEW + 1, Err(Error::Expired)),
            (SENT - 100 - SKEW, Ok(())),
            (SENT - 100 - SKEW - 1, Err(Error::NotYetValid)),
        ] {
            assert_eq!(
                Signed::<ChatLine>::parse(&bytes, at).map(drop),
                want,
                "{at}"
            );
        }
    }

    #[test]
    fn what_a_reader_is_shown() {
        let w = world();
        let me = w.id.fingerprint();
        let other = Fingerprint([3; 32]);
        let s = whole(&w, &line(&w, "hi"));
        let lobby = ChatScope {
            server: Some(w.server),
            room: 0,
        };
        let room = ChatScope {
            server: Some(w.server),
            room: 5,
        };
        let unknown = ChatScope {
            server: None,
            room: 0,
        };
        let ctx = |at, sender, scope| Context { at, sender, scope };
        let verified = Outcome::Verified {
            signer: me,
            sent_apart: false,
        };
        let elsewhere = Outcome::Elsewhere {
            signer: me,
            sent_apart: false,
        };
        let unverified = Outcome::Unverified { signer: Some(me) };
        for (name, c, want) in [
            (
                "here",
                ctx(SENT, Sender::Named(me), &lobby),
                verified.clone(),
            ),
            (
                "by its certificate",
                ctx(SENT, Sender::Certificate, &lobby),
                verified,
            ),
            (
                "received later than S after it was sent",
                ctx(SENT + SKEW + 1, Sender::Named(me), &lobby),
                Outcome::Verified {
                    signer: me,
                    sent_apart: true,
                },
            ),
            (
                "in another room",
                ctx(SENT, Sender::Named(me), &room),
                elsewhere.clone(),
            ),
            (
                "elsewhere outweighs a sender with no identity",
                ctx(SENT, Sender::Unknown, &room),
                elsewhere,
            ),
            (
                "a sender with no identity",
                ctx(SENT, Sender::Unknown, &lobby),
                unverified.clone(),
            ),
            (
                "no server key",
                ctx(SENT, Sender::Named(me), &unknown),
                unverified,
            ),
            (
                "another signer outweighs the scope",
                ctx(SENT, Sender::Named(other), &room),
                Outcome::Invalid(Error::KeyMismatch),
            ),
        ] {
            assert_eq!(s.check(&c), want, "{name}");
        }
    }

    #[test]
    fn unknown_keys_are_covered_and_carried_through_every_form() {
        let w = world();
        let Value::Map(mut entries) = line(&w, "hi").unsigned() else {
            unreachable!()
        };
        entries.push((Value::Text("future".into()), Value::Uint(1)));
        let bytes = signed::seal(Value::Map(entries), |b| w.dev.sign(CHAT_DOMAIN, b));
        let s = Signed::<ChatLine>::parse(&bytes, SENT).unwrap();
        let link = s.link().unwrap();
        let back = Signed::<ChatLine>::parse_link(&link, ["hi"], &w.cert, SENT).unwrap();
        assert_eq!(back.whole(), bytes);
        assert_eq!(
            Signed::<ChatLine>::parse_link(&link, ["hi"], &w.cert[1..], SENT).err(),
            Some(Error::CertMismatch)
        );
        assert_eq!(
            link_cert_sha256(&link),
            Ok(<[u8; 32]>::from(Sha256::digest(&w.cert)))
        );
        assert_eq!(
            Signed::<ChatLine>::link_content_sha256(&link, ["hi"]),
            Ok(s.content_sha256())
        );
    }

    #[test]
    fn a_form_past_its_bound_is_not_made() {
        let w = world();
        let Value::Map(mut entries) = line(&w, "hi").unsigned() else {
            unreachable!()
        };
        entries.push((Value::Text("future".into()), Value::Bytes(vec![0; 100])));
        let bytes = signed::seal(Value::Map(entries.clone()), |b| w.dev.sign(CHAT_DOMAIN, b));
        let s = Signed::<ChatLine>::parse(&bytes, SENT).unwrap();
        assert!(s.detached().is_ok());
        assert_eq!(s.link(), Err(Error::TooLarge));
        entries.push((Value::Text("more".into()), Value::Bytes(vec![0; 700])));
        let bytes = signed::seal(Value::Map(entries), |b| w.dev.sign(CHAT_DOMAIN, b));
        let s = Signed::<ChatLine>::parse(&bytes, SENT).unwrap();
        assert_eq!(s.detached(), Err(Error::TooLarge));

        let longest = line(&w, &"x".repeat(4096)).sign(&w.dev).unwrap();
        assert!(Signed::<ChatLine>::parse(&longest, SENT).is_ok());
        let Value::Map(mut entries) = line(&w, "hi").unsigned() else {
            unreachable!()
        };
        entries.push((Value::Text("future".into()), Value::Bytes(vec![0; 5000])));
        let bytes = signed::seal(Value::Map(entries), |b| w.dev.sign(CHAT_DOMAIN, b));
        assert_eq!(
            Signed::<ChatLine>::parse(&bytes, SENT).err(),
            Some(Error::TooLarge)
        );
    }

    #[test]
    fn a_line_signed_again_is_the_same_line_and_another_text_is_not() {
        let w = world();
        let first = whole(&w, &line(&w, "hi"));
        let again = whole(
            &w,
            &ChatLine {
                sent: SENT + 60,
                ..line(&w, "hi")
            },
        );
        assert_ne!(first.whole(), again.whole());
        assert!(first.same_content(&again));
        assert!(!first.same_content(&whole(&w, &line(&w, "ho"))));
        let in_a_room = whole(
            &w,
            &ChatLine {
                room: 5,
                ..line(&w, "hi")
            },
        );
        assert!(!first.same_content(&in_a_room));
    }

    #[test]
    fn padding_fills_each_size_and_spills_into_the_next() {
        // A byte string's head is three bytes at every size here, so an
        // item can be made exactly as long as a size, or one longer.
        let item = |len: usize| cbor::encode(&Value::Bytes(vec![0xaa; len - 3]));
        for deniable in [false, true] {
            let sizes: Vec<usize> = pad_sizes(deniable).collect();
            for (i, &size) in sizes.iter().enumerate() {
                let exact = item(size);
                let padded = pad(&exact, deniable).unwrap();
                assert_eq!(padded, exact, "{size}");
                assert_eq!(unpad(&padded, deniable), Ok(&exact[..]), "{size}");

                let over = item(size + 1);
                match sizes.get(i + 1) {
                    Some(&next) => {
                        let padded = pad(&over, deniable).unwrap();
                        assert_eq!(padded.len(), next, "{size}");
                        assert_eq!(unpad(&padded, deniable), Ok(&over[..]), "{size}");
                    }
                    None => assert_eq!(pad(&over, deniable), Err(Error::TooLarge)),
                }
            }
        }
    }
}
