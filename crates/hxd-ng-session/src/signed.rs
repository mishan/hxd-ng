//! Signed lines, messages and articles as they arrive
//! (`docs/e2e-messages.md` §4.6, §4.11): every one is checked before it
//! is relayed or stored, so an invalid signature in a client's view is a
//! sign of tampering rather than of another client's bug, and what the
//! domain keeps is a form it never has to read.

use hl_identity::message::{
    Article, ChatLine, Object, PrivateMessage, Signed, DETACHED_MAX_BYTES, SKEW,
};
use hl_identity::{cbor, Error, Fingerprint};
use hxd_core::history::Signature;
use hxd_core::inbox::MessageGuid;
use hxd_core::news::{ArticleId, ArticleSignature, SignedPost};
use hxd_core::server_link::LinkForm;
use hxd_core::{SignedLine, SignedMsg};

use crate::conn::SessState;
use crate::proto::reply_err;
use crate::NgCtx;

/// Why a signed request was refused, as the wire says it.
pub(crate) enum Refused {
    BadRequest(&'static str),
    BadSignature(&'static str),
}

impl Refused {
    pub(crate) fn reply(&self, id: u64) -> String {
        match self {
            Refused::BadRequest(text) => reply_err(id, "bad_request", text),
            Refused::BadSignature(text) => reply_err(id, "bad_signature", text),
        }
    }
}

/// Whether this server carries signed messages: it publishes a server
/// key for them to be scoped to, and names the hosts a client pins it by
/// (§4.6). `chat_guid`, the other condition, it always offers. A link
/// carries them only where it tries the user keys draft, and a signed
/// line or message goes nowhere else (§4.11, §5).
pub(crate) fn offered(ctx: &NgCtx) -> bool {
    ctx.identity
        .as_ref()
        .is_some_and(|i| !i.config().hosts.is_empty())
}

/// The form a signed lobby line or private message crosses a link in
/// (§5): `None` for one too large to take it, which crosses no link.
fn link_form<T: Object>(signed: &Signed<T>) -> Option<LinkForm> {
    Some(LinkForm {
        form: signed.link().ok()?.into(),
        cert: signed.message.cert().into(),
    })
}

/// A text a signature covers, as a request carries it: canonical and
/// within its limit, or refused, never cut (§3.1, §4.7).
fn text_ok(text: &str) -> Result<(), Refused> {
    if !hl_identity::message::is_canonical(text) {
        return Err(Refused::BadRequest(
            "Signed text holds no CR and no control character but LF and TAB.",
        ));
    }
    if text.is_empty() || text.len() > 4096 {
        return Err(Refused::BadRequest(
            "Signed text is 1 to 4096 bytes; it is never cut.",
        ));
    }
    Ok(())
}

fn decode(signed: &str) -> Result<Vec<u8>, Refused> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signed)
        .map_err(|_| Refused::BadRequest("`signed` is not base64url."))
}

/// §3.5's steps, named for the client that failed them.
fn invalid(e: Error) -> Refused {
    Refused::BadSignature(match e {
        Error::TooLarge => "The signed form is too large.",
        Error::Expired | Error::NotYetValid => {
            "The certificate is not valid at the time it was signed or now."
        }
        Error::CapabilityMissing => "The certificate does not allow messages.",
        Error::BadSignature | Error::InvalidKey | Error::KeyMismatch => {
            "The signature does not verify."
        }
        _ => "The signed form is malformed.",
    })
}

/// What a signed request must be besides valid (§4.11): this session's
/// device under this session's identity, and signed lately.
fn of_this_session<T: Object>(
    state: &SessState,
    signed: &Signed<T>,
    now: u64,
) -> Result<(), Refused> {
    let Some(device) = state.device.as_ref() else {
        return Err(Refused::BadSignature(
            "This session proved no device key to sign with.",
        ));
    };
    if signed.signer() != device.identity {
        return Err(Refused::BadSignature("Signed by another identity."));
    }
    if signed.cert.device != device.key {
        return Err(Refused::BadSignature("Signed by another device."));
    }
    if signed.message.sent().abs_diff(now) > SKEW {
        return Err(Refused::BadSignature("signed too long ago; sign it again"));
    }
    Ok(())
}

/// A `chat`'s or a `msg`'s guid, which is its signed id.
fn under_guid<T: Object>(signed: &Signed<T>, guid: Option<&MessageGuid>) -> Result<(), Refused> {
    match guid {
        None => Err(Refused::BadRequest("A signed message carries its `guid`.")),
        Some(g) if id_of(g) != signed.message.id() => Err(Refused::BadSignature(
            "The signed id is not the request's `guid`.",
        )),
        Some(_) => Ok(()),
    }
}

/// The 16 bytes a guid's hex digits spell.
fn id_of(guid: &MessageGuid) -> [u8; 16] {
    let hex: Vec<u8> = guid.as_str().bytes().filter(|b| *b != b'-').collect();
    let mut id = [0; 16];
    for (byte, pair) in id.iter_mut().zip(hex.chunks(2)) {
        let digits = std::str::from_utf8(pair).expect("a parsed guid is hex");
        *byte = u8::from_str_radix(digits, 16).expect("a parsed guid is hex");
    }
    id
}

/// The server's clock, which an ingest check reads as now.
fn now(ctx: &NgCtx) -> Result<u64, Refused> {
    match ctx.identity.as_ref() {
        Some(st) if offered(ctx) => Ok(st.clock().unix()),
        _ => Err(Refused::BadRequest(
            "This server does not carry signed messages.",
        )),
    }
}

/// A `chat`'s `signed`, for a line of `text` said into `room` (§4.7).
pub(crate) fn line(
    ctx: &NgCtx,
    state: &SessState,
    room: u32,
    guid: Option<&MessageGuid>,
    (text, action): (&str, bool),
    signed: &str,
) -> Result<SignedLine, Refused> {
    let now = now(ctx)?;
    text_ok(text)?;
    let form = decode(signed)?;
    let line = Signed::<ChatLine>::parse_detached(&form, [text], now).map_err(invalid)?;
    of_this_session(state, &line, now)?;
    under_guid(&line, guid)?;
    let server = ctx.identity.as_ref().map(|st| st.server_key());
    if Some(line.message.server) != server {
        return Err(Refused::BadSignature("Signed for another server."));
    }
    if line.message.room != u64::from(room) {
        return Err(Refused::BadSignature("Signed for another room."));
    }
    if line.message.act != action {
        return Err(Refused::BadSignature("Signed in another style."));
    }
    Ok(SignedLine {
        signature: Signature {
            content: line.content_sha256(),
            form,
        },
        link: if room == 0 { link_form(&line) } else { None },
    })
}

/// A `msg`'s `signed` (§4.9). Who it is to is the domain's to check,
/// against the recipient as it resolves them.
pub(crate) fn msg(
    ctx: &NgCtx,
    state: &SessState,
    guid: Option<&MessageGuid>,
    text: &str,
    signed: &str,
) -> Result<(SignedMsg, Option<LinkForm>), Refused> {
    let now = now(ctx)?;
    text_ok(text)?;
    let form = decode(signed)?;
    let msg = Signed::<PrivateMessage>::parse_detached(&form, [text], now).map_err(invalid)?;
    of_this_session(state, &msg, now)?;
    under_guid(&msg, guid)?;
    Ok((
        SignedMsg {
            to: msg.message.to.0,
            signature: Signature {
                content: msg.content_sha256(),
                form,
            },
        },
        link_form(&msg),
    ))
}

/// A `news_post`'s `signed` (§4.10), for an article of `subject` and
/// `body` as `mime`, replying to `parent`. The category's guid and the
/// parent's signature are the domain's to check, against the store.
pub(crate) fn article(
    ctx: &NgCtx,
    state: &SessState,
    (subject, body, mime): (&str, &str, Option<&str>),
    parent: Option<ArticleId>,
    signed: &str,
) -> Result<SignedPost, Refused> {
    let now = now(ctx)?;
    if !(hl_identity::message::is_canonical(subject) && hl_identity::message::is_canonical(body)) {
        return Err(Refused::BadRequest(
            "Signed text holds no CR and no control character but LF and TAB.",
        ));
    }
    if subject.is_empty() || subject.len() > 255 || subject.contains('\n') {
        return Err(Refused::BadRequest(
            "A signed subject is one line of 1 to 255 bytes; it is never cut.",
        ));
    }
    if body.len() > 65_535 {
        return Err(Refused::BadRequest(
            "A signed body is at most 65 535 bytes; it is never cut.",
        ));
    }
    let Some(mime) = mime else {
        return Err(Refused::BadRequest("A signed article sends its `mime`."));
    };
    let form = decode(signed)?;
    let article =
        Signed::<Article>::parse_detached(&form, [subject, body], now).map_err(invalid)?;
    of_this_session(state, &article, now)?;
    let server = ctx.identity.as_ref().map(|st| st.server_key());
    if Some(article.message.server) != server {
        return Err(Refused::BadSignature("Signed for another server."));
    }
    if article.message.mime != mime {
        return Err(Refused::BadSignature("Signed as another `mime`."));
    }
    if article.message.parent.map(|p| p.article) != parent.map(u64::from) {
        return Err(Refused::BadSignature(
            "Signed as a reply to another article.",
        ));
    }
    Ok(SignedPost {
        signature: ArticleSignature {
            content: article.content_sha256(),
            signer: article.signer().0,
            id: article.message.id,
            form,
        },
        category: article.message.category,
        parent: article
            .message
            .parent
            .and_then(|p| p.signed)
            .map(|(id, by)| (id, by.0)),
    })
}

/// Signed evidence a reporter pasted (§4.12), as it is kept.
pub(crate) struct Pasted {
    pub(crate) form: Vec<u8>,
    pub(crate) signer: [u8; 32],
    /// The text the signature covers.
    pub(crate) text: String,
    /// The key a line is scoped to when it is not this server's: a linked
    /// server's, which this server must know for it to stand (§4.12).
    pub(crate) elsewhere: Option<[u8; 32]>,
}

/// `report`'s `signed`: a public line's or a private message's detached
/// form beside `evidence`, or with none a whole private message. Checked
/// as a reader checks one, with the certificate at `sent` alone, since
/// this server never received it; a line's scope against this server's
/// key, or, left to the caller as [`Pasted::elsewhere`], a linked
/// server's, and a message's against the reporter's identity.
pub(crate) fn pasted(
    ctx: &NgCtx,
    state: &SessState,
    evidence: Option<&str>,
    signed: &str,
) -> Result<Pasted, Refused> {
    now(ctx)?;
    let form = decode(signed)?;
    // Before it is decoded: a detached form beside its text, or a whole
    // message, each to its own bound.
    let most = match evidence {
        Some(_) => DETACHED_MAX_BYTES,
        None => PrivateMessage::WHOLE_MAX_BYTES,
    };
    if form.len() > most {
        return Err(invalid(Error::TooLarge));
    }
    let map = cbor::decode_canonical(&form).map_err(|e| invalid(Error::Cbor(e)))?;
    let Some(cbor::Value::Uint(sent)) = map.get("sent") else {
        return Err(invalid(Error::MissingField("sent")));
    };
    let reporter = state.device.as_ref().map(|d| d.identity);
    let mut elsewhere = None;
    let (signer, text) = match (evidence, map.get("in").is_some()) {
        (Some(text), true) => {
            let line = Signed::<ChatLine>::parse_detached(&form, [text], *sent).map_err(invalid)?;
            let server = ctx.identity.as_ref().map(|st| st.server_key());
            if Some(line.message.server) != server {
                elsewhere = Some(line.message.server);
            }
            (line.signer(), line.message.text)
        }
        (Some(text), false) => {
            let msg =
                Signed::<PrivateMessage>::parse_detached(&form, [text], *sent).map_err(invalid)?;
            to_reporter(&msg, reporter)?;
            (msg.signer(), msg.message.text)
        }
        (None, _) => {
            let msg = Signed::<PrivateMessage>::parse(&form, *sent).map_err(invalid)?;
            to_reporter(&msg, reporter)?;
            (msg.signer(), msg.message.text)
        }
    };
    Ok(Pasted {
        form,
        signer: signer.0,
        text,
        elsewhere,
    })
}

fn to_reporter(msg: &Signed<PrivateMessage>, reporter: Option<Fingerprint>) -> Result<(), Refused> {
    if Some(msg.message.to) == reporter {
        Ok(())
    } else {
        Err(Refused::BadSignature("Signed to someone else."))
    }
}
