//! `hlid enroll` — the holder's side of `docs/identity-enrollment.md`.
//!
//! The identity key never leaves this machine and the browser never sees
//! it, so certifying a browser has always meant a trip to wherever the
//! key lives: read two public keys off one screen, run `hlid cert`, and
//! paste the result back. This replaces the trip with a code. The holder
//! opens a session at the server's mailbox, shows a pairing code, waits
//! for the device that was given it, shows the user what it is about to
//! certify, and signs if they say yes.
//!
//! **The prompt is the security boundary of the whole flow** (§9). The
//! mailbox verifies nothing and is trusted with nothing but delivery: it
//! can drop a request, and it can put a request of its own in front of
//! the user. What it cannot do is produce a certificate, because only
//! this process holds the key, and this process only signs what a human
//! said yes to. So everything the human needs is on the screen and
//! nothing else is, the default answer is no, and what is displayed is
//! computed from the request this code verified rather than from
//! anything the mailbox said about it.

use std::io::Write;
use std::time::Duration;

use hl_identity::enroll::{session_key, PAIRING_SECRET_BYTES};
use hl_identity::{
    Bundle, Card, DeviceCert, EnrollRequest, Fingerprint, IdentityKey, SessionClaim,
};
use serde_json::{json, Value};

use crate::{
    b64, caps_words, now, parse_caps, read_file, read_seed, refuse_unreadable, seconds,
    server_base, unb64, CARD_FILE, IDENTITY_KEY, R,
};

/// Longer than the mailbox's 30-second long poll, so a poll that comes
/// back empty is the server answering rather than this giving up.
const POLL_TIMEOUT: Duration = Duration::from_secs(45);

/// How long to wait after a poll that returned work this holder could
/// not answer. The mailbox's own long poll, so a stuck request costs the
/// same as an idle one and no more.
const IDLE_BACKOFF: Duration = Duration::from_secs(30);

/// What a holder asks a human. A trait because the point of putting this
/// flow behind a mailbox rather than a clipboard is that the prompt can
/// move — to a tray app, an Electron window, a native client — without
/// the protocol changing (§7).
pub(crate) trait Prompt {
    /// `false` is the safe answer and must be what any failure returns.
    fn confirm(&mut self, screen: &str, default_yes: bool) -> bool;
    fn tell(&mut self, line: &str);
}

pub(crate) struct Terminal;

impl Prompt for Terminal {
    fn confirm(&mut self, screen: &str, default_yes: bool) -> bool {
        eprint!(
            "{screen}\n{}  ",
            if default_yes { "[Y/n]" } else { "[y/N]" }
        );
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            // End of input: there is nobody there to answer. That is not
            // an empty line — an empty line is somebody pressing Return
            // and meaning the default — and reading it as one would
            // auto-approve every renewal for a holder whose stdin has
            // closed, which is exactly what §6 says must not happen.
            Ok(0) => false,
            // No terminal, or it went away mid-read. Same answer.
            Err(_) => false,
            Ok(_) => match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => true,
                "" => default_yes,
                _ => false,
            },
        }
    }

    fn tell(&mut self, line: &str) {
        eprintln!("{line}");
    }
}

/// The holder's policy: what it would have granted at the terminal.
/// Nothing a request says can widen this (§6).
pub(crate) struct Policy {
    /// `None` is unrestricted, matching a certificate's own `caps`.
    pub caps: Option<u64>,
    pub days: u64,
}

/// What a request asked for, intersected with what this holder gives.
///
/// Pure, and separate from everything that talks to a server or a human,
/// because it is the one piece of the flow where being wrong hands out
/// authority. `None` caps on either side means unrestricted, so the
/// intersection of two `None`s is `None` and anything else is a mask.
pub(crate) fn grant(
    policy: &Policy,
    asked_caps: Option<u64>,
    asked_days: Option<u64>,
) -> (Option<u64>, u64) {
    let caps = match (policy.caps, asked_caps) {
        (None, asked) => asked,
        (Some(allowed), None) => Some(allowed),
        (Some(allowed), Some(asked)) => Some(allowed & asked),
    };
    let days = asked_days.map_or(policy.days, |d| d.min(policy.days));
    (caps, days)
}

/// "The same or less" (§8), applied to what the holder would otherwise
/// grant. A renewal must not widen what the old certificate carried,
/// even when the holder's policy has grown since it was issued.
///
/// `None` on either side is unrestricted, as it is in a certificate.
fn renewed_caps(granted: Option<u64>, prev: &DeviceCert) -> Option<u64> {
    match (granted, prev.caps) {
        (g, None) => g,
        (None, Some(had)) => Some(had),
        (Some(g), Some(had)) => Some(g & had),
    }
}

/// The lifetime the old certificate was issued for, in whole days —
/// what a renewal may ask for again and not exceed (§8).
///
/// Rounded up, so a certificate issued for less than a day renews to a
/// day rather than to nothing; rounding down would hand back a
/// certificate that had already expired.
fn prev_days(prev: &DeviceCert) -> u64 {
    prev.expires
        .saturating_sub(prev.issued)
        .div_ceil(86_400)
        .max(1)
}

/// "The same or less" again, for the lifetime. `grant` has already
/// bounded the ask by the holder's policy; this bounds it by what the
/// certificate being renewed actually carried, so a device that holds a
/// seven-day certificate cannot come back for the holder's ninety.
fn renewed_days(granted: u64, prev: &DeviceCert) -> u64 {
    granted.min(prev_days(prev))
}

/// Clock-skew tolerance for a renewal's `time` and its certificate's
/// expiry, matching `[identity] clock_skew`'s default. Both ends are
/// checked against a wall clock nobody synchronizes for them.
const RENEWAL_SKEW: u64 = 300;

/// A renewal is "the same device asking for the same or less" (§8). What
/// can be checked without the holder's policy is checked here; what the
/// device gets is still `grant`'s answer, narrowed by `renewed_caps`.
fn renewal_is_sane(
    prev: &DeviceCert,
    req: &EnrollRequest,
    identity: &IdentityKey,
    now: u64,
) -> Result<(), String> {
    if prev.identity != identity.public() {
        return Err("the certificate it wants renewed was signed by a different identity".into());
    }
    if prev.device != req.device {
        return Err("the certificate it wants renewed is for a different device".into());
    }
    // §4 says a holder outside its skew tolerance treats a request as a
    // replay, and until this was here, none did: `time` was carried,
    // documented and never read. A renewal is the one shape where that
    // matters, because a renewal under `--renew auto` is granted with no
    // human in the loop, and a request replayed out of a log or a proxy
    // would be granted again.
    if req.time > now.saturating_add(RENEWAL_SKEW) {
        return Err("it is dated in the future".into());
    }
    if req.time.saturating_add(RENEWAL_SKEW) < now {
        return Err("it is too old to still be the request it claims to be".into());
    }
    // The lifetime exists to bound how long a copied profile keeps
    // logging in as you (§8). A certificate that has already run out has
    // spent that bound, so renewing it hands the bound back — silently,
    // under `--renew auto`, which is exactly the case the prompt was
    // there to cover. Expired means a fresh enrollment, with a code and
    // a human.
    if prev.expires.saturating_add(RENEWAL_SKEW) < now {
        return Err("the certificate it wants renewed has already expired".into());
    }
    // `caps` means different things in the two objects, and conflating
    // them is easy: absent in a *certificate* is unrestricted, absent in
    // a *request* is "whatever your policy gives" (§4). So only an
    // explicit ask can be a widening. An absent one is not a request for
    // everything — it is a request for the holder's default, which
    // `grant` bounds, and which `renewed_caps` bounds again against what
    // the old certificate carried.
    if let (Some(had), Some(asked)) = (prev.caps, req.caps) {
        if asked & !had != 0 {
            return Err("it asks for capabilities its certificate does not have".into());
        }
    }
    // And the same for the lifetime, which had no check at all: §8's rule
    // is `days` no longer than `prev`'s lifetime. Without it a device
    // holding a seven-day certificate renewed straight to the holder's
    // ninety — under `--renew auto`, with nobody watching, which is the
    // one path where a silent widening costs the most. An *absent* ask is
    // not a widening, as with caps: it means the holder's default, which
    // `renewed_days` then bounds.
    if let Some(asked) = req.days {
        if asked > prev_days(prev) {
            return Err("it asks for a longer lifetime than its certificate has".into());
        }
    }
    Ok(())
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(timeout).build()
}

/// What discovery says about enrolling here.
struct Discovered {
    /// The mailbox's absolute base.
    mailbox: String,
    /// Where a web client for this server lives (§3), if the operator
    /// said and the user did not say otherwise. Absent means no QR code:
    /// there is nowhere to point a phone, and the code gets typed.
    web: Option<String>,
}

/// `scheme://host[:port]`, or the whole string if it does not look like a
/// URL. Compared rather than parsed: the two inputs are `--server`, which
/// `server_base` has already checked, and a discovery field.
fn origin(url: &str) -> &str {
    match url.split_once("://") {
        Some((_, rest)) => &url[..url.len() - rest.len() + rest.find('/').unwrap_or(rest.len())],
        None => url,
    }
}

/// Read `identity.endpoints.enroll` out of discovery. Absent means this
/// server hosts no mailbox, which is not a failure of anything — it is
/// the case the paste still exists for.
///
/// `web` is taken only when it is on the same origin as `base` — the
/// address the user typed. It is the mailbox that answers discovery, and
/// the QR built from `web` carries the pairing secret in its fragment, so
/// a mailbox free to name any origin could send the phone to a page of
/// its own, read the secret off the fragment, and mint a `pair` for a
/// device key of its own — which is precisely the substituted request
/// §9 claims a scanned enrollment cannot suffer. Same-origin does not
/// make the page trustworthy, but it does mean the phone only ever goes
/// where the user already chose to go; a client hosted elsewhere is a
/// `--web` away, and that is the user saying it, not the server.
fn discover(base: &str, web_override: Option<&str>) -> R<Discovered> {
    let doc: Value = agent(Duration::from_secs(10))
        .get(&format!("{base}/.well-known/hotline"))
        .call()
        .map_err(|e| format!("discovery: {e}"))?
        .into_json()
        .map_err(|e| format!("discovery: {e}"))?;
    let endpoint = doc["identity"]["endpoints"]["enroll"]
        .as_str()
        .ok_or_else(|| {
            format!(
                "{base} serves no enrollment mailbox; certify the device with \
                 `hlid cert --device-pub … --device-enc-pub … --bundle` and paste the result"
            )
        })?;
    Ok(Discovered {
        mailbox: format!("{base}{endpoint}"),
        web: web_client(base, doc["identity"]["web"].as_str(), web_override),
    })
}

/// Which web client the QR code points at, if any: what the user named,
/// else what discovery advertised — but only on the origin of the server
/// the user typed. See `discover` for why the second is not enough on its
/// own.
fn web_client(base: &str, advertised: Option<&str>, chosen: Option<&str>) -> Option<String> {
    match chosen {
        Some(w) => Some(w.to_owned()),
        None => advertised
            .filter(|w| origin(w) == origin(base))
            .map(str::to_owned),
    }
}

/// The URL a QR code carries (§5.6).
///
/// Everything is in the fragment, which browsers do not send to the
/// server — so none of it reaches an access log, and the pairing secret
/// in particular never leaves the two devices that need it.
///
/// The four fields do four different jobs. `enroll` and `mailbox` mean
/// the user types nothing and cannot pick the wrong server. `identity`
/// means the enrollee pins the fingerprint *before it asks* rather than
/// learning it from the answer. And `pair` is what the enrollee folds
/// into its request, proving to the holder that it is talking to
/// whoever photographed this terminal.
fn scan_url(
    web: &str,
    code: &str,
    mailbox_host: &str,
    identity: &Fingerprint,
    secret: &[u8; PAIRING_SECRET_BYTES],
) -> String {
    format!(
        "{}#enroll={}&mailbox={}&identity={}&pair={}",
        web.trim_end_matches('#'),
        code,
        mailbox_host,
        identity,
        b64(secret),
    )
}

/// Render a QR code as half-block characters, two rows of modules per
/// line, so it comes out roughly square in a terminal cell grid.
///
/// Colours are set explicitly rather than left to the terminal's theme.
/// A QR code is dark modules on a light field and many scanners will not
/// read the inverse, so relying on "the background is probably dark"
/// would make this work on one machine and not the next.
fn qr_block(url: &str) -> R<String> {
    use qrcodegen::{QrCode, QrCodeEcc};
    // Medium correction: this is read off a screen at arm's length, not
    // off a printed label that might be scuffed.
    let qr = QrCode::encode_text(url, QrCodeEcc::Medium)
        .map_err(|e| format!("the enrollment URL will not fit in a QR code: {e}"))?;
    let size = qr.size();
    // Four modules of quiet zone, which the spec requires and scanners
    // genuinely need.
    let quiet = 4;
    let dark = |x: i32, y: i32| qr.get_module(x - quiet, y - quiet);
    let full = size + quiet * 2;

    let mut out = String::new();
    out.push_str("\x1b[47m\x1b[30m"); // white field, black modules
    for row in (0..full).step_by(2) {
        for x in 0..full {
            let top = dark(x, row);
            let bottom = row + 1 < full && dark(x, row + 1);
            out.push(match (top, bottom) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push_str("\x1b[K\n");
    }
    out.push_str("\x1b[0m");
    Ok(out)
}

pub(crate) fn enroll_cmd(args: &[String]) -> R<()> {
    with_holder(args, Some(1))
}

/// `hlid agent`: the same loop with no budget, and a standing session so
/// renewals arrive without a code (§7, §8).
pub(crate) fn agent_cmd(args: &[String]) -> R<()> {
    with_holder(args, None)
}

fn with_holder(args: &[String], budget: Option<usize>) -> R<()> {
    let a = crate::parse(args);
    let id = IdentityKey::from_seed(&read_seed(&a.file("identity", IDENTITY_KEY)?)?);
    let card_path = a.file("card", CARD_FILE)?;
    let card = read_file(&card_path)?;
    let parsed_card = Card::parse(&card).map_err(|e| format!("{}: {e}", card_path.display()))?;
    if parsed_card.identity != id.public() {
        return Err(format!(
            "{} is the card of a different identity than the key signing certificates",
            card_path.display()
        ));
    }

    // `--caps web` by default: login and message, never vouch or manage.
    // A device this holder did not generate should not be able to
    // certify others or rewrite the card (§6).
    let policy = Policy {
        caps: parse_caps(Some(a.opt("caps").unwrap_or("web")))?,
        days: a.u64("days", 90)?,
    };
    let base = server_base(&a)?;
    // `--web` survives the agent rewrite: the QR's fragment carries the
    // pairing secret, so which origin the phone is sent to is the user's
    // statement or the server's own, never a third one the mailbox named
    // (see `discover`).
    let web = a.opt("web");
    if let Some(w) = web {
        if !(w.starts_with("http://") || w.starts_with("https://")) {
            return Err("--web must start with http:// or https://".into());
        }
    }
    let found = discover(&base, web)?;
    let holder = Holder {
        id: &id,
        card: &card,
        card_name: &parsed_card.name,
        policy: &policy,
        found: &found,
        show_url: a.has("show-url"),
        renew: Renew::parse(a.opt("renew"))?,
        http: agent(Duration::from_secs(10)),
        poll: agent(POLL_TIMEOUT),
    };
    run(&holder, budget, &mut Terminal)
}

/// What to do about a renewal (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Renew {
    /// Prompt, defaulting to yes. One keypress a quarter, and the user
    /// sees it.
    Ask,
    /// Approve without asking. For someone who has read §8's argument
    /// and owns the machine outright.
    Auto,
    /// Hold no standing session, so renewals arrive through a code like
    /// a first enrollment — and are answered like one too, defaulting to
    /// no rather than to yes. Somebody who asked for renewals to cost a
    /// code did not ask for them to cost a code and one Return.
    Deny,
}

impl Renew {
    fn parse(s: Option<&str>) -> R<Renew> {
        match s {
            None | Some("ask") => Ok(Renew::Ask),
            Some("auto") => Ok(Renew::Auto),
            Some("deny") => Ok(Renew::Deny),
            Some(other) => Err(format!(
                "--renew: unknown value {other:?}; ask, auto or deny"
            )),
        }
    }

    /// What the renewal prompt defaults to, for the two settings that
    /// reach a prompt at all.
    ///
    /// `ask` defaults to yes: it is one keypress a quarter, and §8's whole
    /// argument is that the user should *see* it, not that they should
    /// have to fight it. `deny` holds no standing session, so a renewal
    /// only ever reaches it through a code somebody typed — which §8 calls
    /// "like a first enrollment", and a first enrollment defaults to no.
    /// Defaulting to yes there handed back most of what the flag turned
    /// off.
    fn prompt_default_yes(self) -> bool {
        matches!(self, Renew::Ask)
    }
}

/// One open session: what the mailbox gave back, plus the pairing secret
/// this end drew and never sent.
struct Session {
    secret: String,
    code: String,
    pairing: [u8; PAIRING_SECRET_BYTES],
    expires_in: u64,
}

/// Everything the loop needs that does not change between sessions.
struct Holder<'a> {
    id: &'a IdentityKey,
    card: &'a [u8],
    card_name: &'a str,
    policy: &'a Policy,
    found: &'a Discovered,
    show_url: bool,
    renew: Renew,
    http: ureq::Agent,
    poll: ureq::Agent,
}

impl Holder<'_> {
    fn mailbox(&self) -> &str {
        &self.found.mailbox
    }

    /// The mailbox's host, shown beside the code: the enrollee has to
    /// use the same one, and nothing else on the screen says which.
    fn host(&self) -> &str {
        self.mailbox()
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .unwrap_or(self.mailbox())
    }

    /// §5.1. `standing` offers to hold renewals for this identity, which
    /// is what lets a browser renew without anybody typing anything.
    fn open(&self, standing: bool) -> R<Session> {
        let opened: Value = self
            .http
            .post(&format!("{}/sessions", self.mailbox()))
            .send_json(json!({}))
            .map_err(|e| format!("opening a session: {e}"))?
            .into_json()
            .map_err(|e| format!("opening a session: {e}"))?;

        // Drawn here and never sent to the mailbox (§5.1). It reaches
        // the enrollee only by being photographed off this screen, which
        // is exactly the property that makes the scanned path safe
        // without a human comparing fingerprints.
        //
        // Through a throwaway key, as `keygen` does, rather than adding
        // a second randomness dependency to this crate.
        let mut seed = [0u8; 32];
        crate::getrandom_seed(&mut seed);
        let mut pairing = [0u8; PAIRING_SECRET_BYTES];
        pairing.copy_from_slice(&seed[..PAIRING_SECRET_BYTES]);

        let session = Session {
            secret: opened["session"]
                .as_str()
                .ok_or("the mailbox returned no session")?
                .to_owned(),
            code: opened["code"]
                .as_str()
                .ok_or("the mailbox returned no code")?
                .to_owned(),
            pairing,
            expires_in: opened["expires_in"].as_u64().unwrap_or(600),
        };
        if standing {
            self.claim(&session)?;
        }
        Ok(session)
    }

    /// §5.1. Ask the mailbox to route this identity's renewals here, and
    /// prove the identity key is held.
    ///
    /// A separate call rather than a field in the open, because the
    /// proof has to name the session and the session does not exist
    /// until the open returns. Signing the session — rather than a
    /// timestamp — is what makes a captured claim worthless: it is for
    /// one session key, which only this process and the mailbox ever
    /// saw.
    ///
    /// A failure here is fatal to the standing session rather than
    /// something to carry on past. An agent whose claim did not land
    /// looks exactly like an agent that is working, right up until the
    /// renewal that silently never arrives.
    fn claim(&self, s: &Session) -> R<()> {
        let claim = SessionClaim::new(self.id.public(), session_key(&s.secret)).sign(self.id);
        self.http
            .post(&format!(
                "{}/sessions/{}/identity",
                self.mailbox(),
                s.secret
            ))
            .send_json(json!({ "claim": b64(&claim) }))
            .map_err(|e| format!("standing by for renewals: {e}"))?;
        Ok(())
    }

    /// Give a session back before its ten minutes are out (§5.1).
    ///
    /// Best effort, and deliberately: this runs when the holder has
    /// already opened a replacement, so the only thing a failure costs
    /// is the old session sitting in the mailbox until it expires.
    /// Turning that into an error would take an agent down over
    /// housekeeping.
    fn close(&self, s: &Session, ui: &mut dyn Prompt) {
        let url = format!("{}/sessions/{}", self.mailbox(), s.secret);
        if let Err(e) = self.http.request("DELETE", &url).call() {
            ui.tell(&format!("(Could not close the previous session: {e})"));
        }
    }

    fn show(&self, s: &Session, ui: &mut dyn Prompt) {
        if let Some(web) = self.found.web.as_deref() {
            let url = scan_url(
                web,
                &s.code,
                self.host(),
                &self.id.fingerprint(),
                &s.pairing,
            );
            // The origin, above the code it is drawn from: scanning hands
            // the pairing secret to whatever is served there, and that is
            // part of the ceremony rather than a detail. Same-origin with
            // `--server` unless the user passed `--web`, so this is a line
            // the user can recognize — and notice when it is not what they
            // expected.
            match qr_block(&url) {
                Ok(block) => ui.tell(&format!(
                    "\nScan this to open {}, or type the code below:\n\n{block}",
                    origin(web)
                )),
                // A URL too long for a QR code is a reason to fall back
                // to typing, not a reason to fail: the typed path is
                // complete on its own.
                Err(why) => ui.tell(&format!("\n(No QR code: {why})")),
            }
            // Not by default: the URL carries the pairing secret, and
            // unlike the QR code — on screen for ten minutes and then
            // gone — a line of text lives in the scrollback and in
            // whatever is logging it.
            if self.show_url {
                ui.tell(&format!("\n{url}\n"));
            }
        }
        // Minutes *and* seconds. `expires_in` is 600 at every open today,
        // so `{}:00` was right by luck; a mailbox that answered 412 would
        // have had it printing "6:00" for six minutes fifty-two.
        ui.tell(&format!(
            "\nEnroll a device at {}: enter code  {}  (expires in {}:{:02})\nThis identity: {}  {}\n",
            self.host(),
            s.code,
            s.expires_in / 60,
            s.expires_in % 60,
            self.card_name,
            self.id.fingerprint().short(),
        ));
    }

    /// One long poll. `None` means the session is gone — expired, or
    /// swept — and the caller decides whether to open another.
    fn poll_once(&self, s: &Session, wait: Option<u64>) -> R<Option<Value>> {
        let url = match wait {
            Some(w) => format!("{}/sessions/{}?wait={w}", self.mailbox(), s.secret),
            None => format!("{}/sessions/{}", self.mailbox(), s.secret),
        };
        let res = self.poll.get(&url).call();
        match res {
            Ok(r) => Ok(Some(
                r.into_json()
                    .map_err(|e| format!("waiting for a device: {e}"))?,
            )),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(format!("waiting for a device: {e}")),
        }
    }

    fn answer(&self, s: &Session, body: Value) -> R<()> {
        self.http
            .post(&format!("{}/sessions/{}/answers", self.mailbox(), s.secret))
            .send_json(body)
            .map_err(|e| format!("answering: {e}"))?;
        Ok(())
    }

    /// Verify one request, ask about it, and answer. Errors here are
    /// about *this* request; a standing agent reports them and carries
    /// on rather than exiting.
    fn handle(&self, s: &Session, id_of_request: &str, raw: &[u8], ui: &mut dyn Prompt) -> R<()> {
        // Everything shown below is computed from this, and never from
        // anything the mailbox said about it.
        //
        // Answered before it is reported, like every other refusal here.
        // Returning without answering would leave the request pending,
        // and a pending request is what the next poll returns —
        // instantly, since there is something to return. Anyone who can
        // post a request the mailbox routes but this cannot parse could
        // otherwise spin a standing agent at full tilt for the request's
        // whole lifetime, and refresh it for as long as they liked.
        let request = match EnrollRequest::parse(raw) {
            Ok(r) => r,
            Err(e) => {
                self.answer(s, json!({ "id": id_of_request, "denied": "bad_request" }))?;
                return Err(format!(
                    "the mailbox delivered something that is not a request: {e}"
                ));
            }
        };
        let device_fp = Fingerprint::of(&request.device);
        let named = request.name.clone().unwrap_or_else(|| "unnamed".into());

        let renewal = match request.prev_cert() {
            Some(Ok(prev)) => match renewal_is_sane(&prev, &request, self.id, now()) {
                Ok(()) => Some(prev),
                Err(why) => {
                    self.answer(s, json!({ "id": id_of_request, "denied": "bad_renewal" }))?;
                    return Err(format!("refused a renewal: {why}"));
                }
            },
            Some(Err(e)) => {
                self.answer(s, json!({ "id": id_of_request, "denied": "bad_renewal" }))?;
                return Err(format!(
                    "refused a renewal whose certificate is not usable: {e}"
                ));
            }
            None => None,
        };

        // A `pair` that does not verify is refused outright and never
        // shown (§6): the only way to produce one is to have guessed,
        // and a guess is not something to put in front of a user.
        let scanned = match request.pair {
            None => false,
            Some(_) if request.pair_matches(&s.pairing) => true,
            Some(_) => {
                self.answer(s, json!({ "id": id_of_request, "denied": "bad_pair" }))?;
                return Err("refused a request whose pairing proof does not verify".into());
            }
        };

        let (mut caps, mut days) = grant(self.policy, request.caps, request.days);
        if let Some(prev) = &renewal {
            caps = renewed_caps(caps, prev);
            days = renewed_days(days, prev);
        }
        let approved = match &renewal {
            Some(prev) => {
                let left = prev.expires.saturating_sub(now()) / 86_400;
                let ask = format!(
                    "Renew  {named:?}  {}  (expires in {left} days)?",
                    device_fp.short()
                );
                match self.renew {
                    // Not silent, and this is the decision in the flow
                    // worth defending. The lifetime exists to bound how
                    // long a *copied profile* keeps logging in as you; a
                    // holder that renews any correctly-signed request
                    // without asking renews the copy too, forever, and
                    // the lifetime bounds nothing. Asking turns the
                    // copy's renewal into something the user sees.
                    Renew::Ask | Renew::Deny => ui.confirm(&ask, self.renew.prompt_default_yes()),
                    Renew::Auto => {
                        ui.tell(&format!("{ask} yes (--renew auto)"));
                        true
                    }
                }
            }
            None => ui.confirm(
                &screen(
                    self.host(),
                    &s.code,
                    &device_fp,
                    &named,
                    &request,
                    caps,
                    days,
                    scanned,
                ),
                false,
            ),
        };
        if !approved {
            self.answer(s, json!({ "id": id_of_request, "denied": "declined" }))?;
            ui.tell("Declined; nothing was signed.");
            return Ok(());
        }

        let mut cert = DeviceCert::for_keys(
            self.id,
            request.device,
            request.device_enc,
            now(),
            seconds(days)?,
        )
        .map_err(|e| format!("--days: {e}"))?;
        cert.caps = caps;
        cert.name = request.name.clone();
        let cert_bytes = cert.sign(self.id);
        DeviceCert::parse(&cert_bytes).map_err(|e| refuse_unreadable("device certificate", e))?;
        let bundle = Bundle {
            cert: cert_bytes,
            card: self.card.to_vec(),
        }
        .encode();

        self.answer(s, json!({ "id": id_of_request, "bundle": b64(&bundle) }))?;
        ui.tell(&format!(
            "Certified {named:?} {} for {days} days.",
            device_fp.short()
        ));
        Ok(())
    }
}

/// The loop both commands are. `budget` is how many requests to handle
/// before returning: `Some(1)` is `enroll`, `None` is `agent`.
fn run(holder: &Holder, budget: Option<usize>, ui: &mut dyn Prompt) -> R<()> {
    // A standing session is what lets the mailbox route a renewal here
    // with no code typed (§8). `--renew deny` declines to hold one, so
    // renewals have to come through a code like anything else.
    let standing = budget.is_none() && holder.renew != Renew::Deny;
    let mut session = holder.open(standing)?;
    holder.show(&session, ui);

    let mut handled = 0usize;
    loop {
        let Some(answer) = holder.poll_once(&session, None)? else {
            if budget.is_some() {
                return Err("the session expired before a device asked".into());
            }
            session = holder.open(standing)?;
            holder.show(&session, ui);
            continue;
        };

        let took = take(holder, &session, &answer, budget, &mut handled, ui)?;
        if took.done {
            return Ok(());
        }
        // A poll that came back with work and answered none of it will
        // come back with the same work immediately, since a pending
        // request is what makes the long poll return early. Only a
        // mailbox that is malfunctioning or hostile produces that, and
        // the answer to both is to stop asking so fast rather than to
        // exit: waiting out the long poll turns a spin into the same
        // once-every-thirty-seconds this loop does when idle.
        if !answer["pending"].as_array().is_none_or(|p| p.is_empty()) && !took.progress {
            std::thread::sleep(IDLE_BACKOFF);
        }

        // A code is single-use, so once it has admitted its request this
        // session can still collect renewals but can no longer enroll
        // anything. Rather than go on displaying a code that does not
        // work, open another.
        if answer["code_live"] == json!(false) {
            // Open the replacement *before* letting go of this session.
            // Opening is what moves the mailbox's identity index to the
            // new session, and it does that under the mailbox's own
            // lock — so once it returns, every renewal either already
            // landed here (and the sweep below finds it) or lands there.
            // Reopening first and sweeping after is the whole fix:
            // doing it the other way round leaves a window in which a
            // renewal arrives on a session nobody will poll again, and
            // it sits until it expires.
            let previous = std::mem::replace(&mut session, holder.open(standing)?);
            holder.show(&session, ui);
            // Swept, *then* closed. Answering a request is a call on
            // the session that holds it, so closing first would 404 the
            // answer to whatever the sweep just found — the same
            // dropped renewal the reopen-first ordering above exists to
            // prevent, reintroduced two lines later.
            let swept = match holder.poll_once(&previous, Some(0))? {
                Some(last) => take(holder, &previous, &last, budget, &mut handled, ui)?,
                None => Took::NOTHING,
            };
            // Handing the session back keeps a rotating agent from
            // filling its own `enroll_per_address` allowance with
            // sessions it has finished with: four rotations inside the
            // ten-minute TTL and the mailbox starts refusing to open the
            // next one, which is a holder rate-limiting itself out of
            // its own mailbox.
            holder.close(&previous, ui);
            if swept.done {
                return Ok(());
            }
        }
    }
}

/// What one poll's answer came to.
struct Took {
    /// The budget is spent and the caller should stop.
    done: bool,
    /// At least one request was answered, so the next poll will not be
    /// handed the same work again.
    progress: bool,
}

impl Took {
    /// A session that was gone by the time it was swept.
    const NOTHING: Took = Took {
        done: false,
        progress: false,
    };
}

/// Handle every request in one poll's answer.
fn take(
    holder: &Holder,
    session: &Session,
    answer: &Value,
    budget: Option<usize>,
    handled: &mut usize,
    ui: &mut dyn Prompt,
) -> R<Took> {
    let mut progress = false;
    for pending in answer["pending"].as_array().cloned().unwrap_or_default() {
        // No id, no answer: everything after this identifies the request
        // being certified or refused, and an empty name would mean
        // answering something the mailbox never described. So this one
        // cannot be refused on the wire, only skipped — and a skipped
        // request stays pending, which is why `run` treats a poll that
        // answered nothing as a reason to wait rather than to poll again.
        let id_of_request = pending["id"].as_str().unwrap_or_default().to_owned();
        if id_of_request.is_empty() {
            unanswerable(ui, budget, "the mailbox delivered a request with no id")?;
            continue;
        }
        let raw = match unb64(pending["request"].as_str().unwrap_or("")) {
            Ok(raw) => raw,
            Err(why) => {
                unanswerable(ui, budget, &why)?;
                continue;
            }
        };
        match holder.handle(session, &id_of_request, &raw, ui) {
            Ok(()) => {}
            // One bad request is not a reason to stop holding the key:
            // an agent that exits on the first stranger is an agent a
            // stranger can turn off. `handle` answers before it returns
            // an error, so the request is spent either way.
            Err(why) if budget.is_none() => ui.tell(&format!("Refused: {why}")),
            Err(why) => return Err(why),
        }
        progress = true;
        *handled += 1;
        if budget.is_some_and(|b| *handled >= b) {
            return Ok(Took {
                done: true,
                progress,
            });
        }
    }
    Ok(Took {
        done: false,
        progress,
    })
}

/// A pending entry this holder cannot answer, because the mailbox did
/// not describe it well enough to name in an answer.
///
/// Fatal to a one-shot `enroll`, which has a person waiting on exactly
/// one request and nothing useful to do with a mailbox talking nonsense.
/// Reported and survived by a standing `agent`, which is the same rule
/// the refusal path above follows and for the same reason.
fn unanswerable(ui: &mut dyn Prompt, budget: Option<usize>, why: &str) -> R<()> {
    if budget.is_some() {
        return Err(why.to_owned());
    }
    ui.tell(&format!("Ignored: {why}"));
    Ok(())
}

/// §6's prompt. Everything that matters and nothing else: what is
/// asking, what it asked for, what it will actually get, and the one
/// comparison only a human can make.
#[allow(clippy::too_many_arguments)]
fn screen(
    host: &str,
    code: &str,
    device: &Fingerprint,
    named: &str,
    request: &EnrollRequest,
    caps: Option<u64>,
    days: u64,
    scanned: bool,
) -> String {
    // `None` in a *request* means "whatever your policy gives" (§4),
    // unlike `None` in a certificate, which is unrestricted. Rendering
    // it as "everything" would have the prompt report a device asking
    // for far more than it did — on the one screen where being
    // misleading is the whole risk.
    let asked_caps = request
        .caps
        .map_or("the default".to_string(), |c| caps_words(Some(c)));
    let asked_days = request
        .days
        .map_or("the default".to_string(), |d| format!("{d} days"));
    // A scanned request has already passed, in software, the check the
    // typed path asks the human to make: the pairing secret came off
    // this screen and the mailbox never saw it (§5.6). So the comparison
    // line goes, and what is left is the decision itself.
    let ask = if scanned {
        "Certify?  (scanned)"
    } else {
        "Compare the device fingerprint with the one the browser is showing.\nCertify?"
    };
    format!(
        "\nEnrollment request via {host}, code {code}\n\n  \
         device      {}  ({named:?})\n  \
         asks for    {asked_caps} · {asked_days}\n  \
         will get    {} · {days} days\n\n\
         {ask}",
        device.short(),
        caps_words(caps),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hl_identity::caps;

    fn web() -> Policy {
        Policy {
            caps: Some(caps::WEB),
            days: 90,
        }
    }

    #[test]
    fn a_request_never_gets_more_than_the_holder_would_have_given() {
        // The whole point of §6: a request that asks for `manage` is
        // shown asking for it and shown not getting it. Nothing it says
        // can widen the holder's policy.
        let (c, d) = grant(&web(), Some(caps::MANAGE | caps::LOGIN), Some(3650));
        assert_eq!(c, Some(caps::LOGIN), "manage is not on offer");
        assert_eq!(d, 90, "the lifetime is the holder's ceiling");
    }

    #[test]
    fn asking_for_nothing_in_particular_gets_the_holders_default() {
        let (c, d) = grant(&web(), None, None);
        assert_eq!(c, Some(caps::WEB));
        assert_eq!(d, 90);
    }

    #[test]
    fn a_request_may_ask_for_less_and_get_less() {
        // Narrowing is the one direction a request can move the answer.
        let (c, d) = grant(&web(), Some(caps::LOGIN), Some(7));
        assert_eq!(c, Some(caps::LOGIN));
        assert_eq!(d, 7);
    }

    #[test]
    fn an_unrestricted_holder_still_honours_a_narrower_request() {
        let all = Policy {
            caps: None,
            days: 90,
        };
        assert_eq!(grant(&all, Some(caps::LOGIN), None).0, Some(caps::LOGIN));
        // And an unrestricted request against an unrestricted holder is
        // the only way to get unrestricted, which `hlid enroll` does not
        // do by default.
        assert_eq!(grant(&all, None, None).0, None);
    }

    #[test]
    fn a_renewal_may_not_widen_what_it_had() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let other = IdentityKey::from_seed(&[2u8; 32]);
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        let stranger = hl_identity::DeviceKey::from_seed(&[4u8; 32]);

        let mut prev = DeviceCert::for_device(&id, &dev, 1_000, 86_400).unwrap();
        prev.caps = Some(caps::WEB);

        let mut req = EnrollRequest::new(&dev, 2_000);
        req.caps = Some(caps::WEB);
        assert!(renewal_is_sane(&prev, &req, &id, 2_000).is_ok());

        // Asking for more than the old certificate carried.
        req.caps = Some(caps::WEB | caps::MANAGE);
        assert!(renewal_is_sane(&prev, &req, &id, 2_000).is_err());

        // Asking for nothing in particular is *not* asking for
        // everything: absent `caps` in a request means "whatever your
        // policy gives" (§4), unlike absent `caps` in a certificate,
        // which is unrestricted. A browser renewing without naming
        // capabilities is the ordinary case, and refusing it here made
        // every renewal fail.
        req.caps = None;
        assert!(renewal_is_sane(&prev, &req, &id, 2_000).is_ok());

        // Somebody else's certificate, and somebody else's device.
        req.caps = Some(caps::WEB);
        assert!(renewal_is_sane(&prev, &req, &other, 2_000).is_err());
        let theirs = DeviceCert::for_device(&id, &stranger, 1_000, 86_400).unwrap();
        assert!(renewal_is_sane(&theirs, &req, &id, 2_000).is_err());
    }

    #[test]
    fn a_lapsed_certificate_is_not_renewed() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        // Issued at 1_000 and good for a day, so it lapses at 87_400.
        let prev = DeviceCert::for_device(&id, &dev, 1_000, 86_400).unwrap();

        // The last moment it still renews, and the first it does not.
        // Skew applies to both, since the two clocks are nobody's job to
        // agree.
        let inside = EnrollRequest::new(&dev, 87_400 + RENEWAL_SKEW);
        assert!(renewal_is_sane(&prev, &inside, &id, 87_400 + RENEWAL_SKEW).is_ok());
        let outside = EnrollRequest::new(&dev, 87_401 + RENEWAL_SKEW);
        assert!(renewal_is_sane(&prev, &outside, &id, 87_401 + RENEWAL_SKEW).is_err());
    }

    #[test]
    fn a_stale_or_post_dated_request_is_a_replay() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        let prev = DeviceCert::for_device(&id, &dev, 1_000, 86_400).unwrap();

        // The certificate is live throughout; it is the request's own
        // `time` that decides these. Signed once and replayed an hour
        // later is the case `--renew auto` would otherwise grant again.
        let req = EnrollRequest::new(&dev, 40_000);
        assert!(renewal_is_sane(&prev, &req, &id, 40_000).is_ok());
        assert!(renewal_is_sane(&prev, &req, &id, 40_000 + RENEWAL_SKEW).is_ok());
        assert!(renewal_is_sane(&prev, &req, &id, 40_000 + RENEWAL_SKEW + 1).is_err());
        assert!(renewal_is_sane(&prev, &req, &id, 40_000 - RENEWAL_SKEW - 1).is_err());
    }

    #[test]
    fn the_prompt_shows_the_ask_and_the_grant_when_they_differ() {
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        let mut req = EnrollRequest::new(&dev, 1_000);
        req.caps = Some(caps::MANAGE | caps::LOGIN);
        req.days = Some(3650);
        req.name = Some("Firefox on the laptop".into());

        let (caps_granted, days) = grant(&web(), req.caps, req.days);
        let s = screen(
            "hl.example",
            "K7PM-4XWE",
            &Fingerprint::of(&req.device),
            "Firefox on the laptop",
            &req,
            caps_granted,
            days,
            false,
        );
        assert!(s.contains("asks for    login, manage · 3650 days"), "{s}");
        assert!(s.contains("will get    login · 90 days"), "{s}");
        // The comparison is the step a hostile mailbox cannot fake, so
        // it has to be on the screen (§9).
        assert!(s.contains("Compare the device fingerprint"), "{s}");
        assert!(s.contains(&Fingerprint::of(&req.device).short()), "{s}");

        // A scanned request has had that check made in software, so the
        // line goes — but the device and what it will get do not.
        let scanned = screen(
            "hl.example",
            "K7PM-4XWE",
            &Fingerprint::of(&req.device),
            "Firefox on the laptop",
            &req,
            caps_granted,
            days,
            true,
        );
        assert!(
            !scanned.contains("Compare the device fingerprint"),
            "{scanned}"
        );
        assert!(scanned.contains("(scanned)"), "{scanned}");
        assert!(scanned.contains("will get    login · 90 days"), "{scanned}");
        assert!(
            scanned.contains(&Fingerprint::of(&req.device).short()),
            "{scanned}"
        );
    }

    /// Drop ANSI SGR/erase sequences, so a test can look at what a
    /// terminal would actually show.
    fn without_escapes(line: &str) -> String {
        let mut out = String::new();
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c != '\u{1b}' {
                out.push(c);
                continue;
            }
            // CSI: '[' then parameters, ended by a letter.
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        }
        out
    }

    /// Read the half-block rendering back into a module grid, so a test
    /// can compare it against what the encoder actually produced. A QR
    /// code that is transposed, shifted by a module, or has its polarity
    /// inverted still *looks* like a QR code, and nothing else here
    /// would notice.
    fn modules_from(block: &str) -> Vec<Vec<bool>> {
        let mut rows: Vec<Vec<bool>> = Vec::new();
        for line in block.lines() {
            let line = without_escapes(line);
            if line.is_empty() {
                continue;
            }
            let mut top = Vec::new();
            let mut bottom = Vec::new();
            for c in line.chars() {
                let (t, b) = match c {
                    '\u{2588}' => (true, true),
                    '\u{2580}' => (true, false),
                    '\u{2584}' => (false, true),
                    ' ' => (false, false),
                    other => panic!("unexpected glyph {other:?}"),
                };
                top.push(t);
                bottom.push(b);
            }
            rows.push(top);
            rows.push(bottom);
        }
        rows
    }

    #[test]
    fn the_rendering_is_a_faithful_transcription_of_the_code() {
        use qrcodegen::{QrCode, QrCodeEcc};
        let url = "https://hl.example/app/#enroll=K7PM-4XWE&mailbox=hl.example";
        let qr = QrCode::encode_text(url, QrCodeEcc::Medium).unwrap();
        let grid = modules_from(&qr_block(url).unwrap());

        let quiet = 4;
        let size = qr.size();
        // The rendering pads to an even number of module rows, so it may
        // carry one blank row past the quiet zone.
        assert!(grid.len() >= (size + quiet * 2) as usize);
        for y in 0..size {
            for x in 0..size {
                assert_eq!(
                    grid[(y + quiet) as usize][(x + quiet) as usize],
                    qr.get_module(x, y),
                    "module ({x}, {y}) does not match the encoder"
                );
            }
        }

        // And the quiet zone really is quiet on every side, which is
        // what scanners need to find the symbol at all.
        for row in grid.iter().take(quiet as usize) {
            assert!(!row.iter().any(|m| *m), "top quiet zone is not blank");
        }
        for row in grid
            .iter()
            .take((size + quiet) as usize)
            .skip(quiet as usize)
        {
            assert!(!row[..quiet as usize].iter().any(|m| *m), "left quiet zone");
            assert!(
                !row[(size + quiet) as usize..].iter().any(|m| *m),
                "right quiet zone"
            );
        }
    }

    #[test]
    fn the_origin_is_the_scheme_host_and_port_only() {
        assert_eq!(origin("https://hl.example/app/"), "https://hl.example");
        assert_eq!(origin("https://hl.example"), "https://hl.example");
        assert_eq!(
            origin("http://hl.example:5700/app/#x"),
            "http://hl.example:5700"
        );
        // A different port or scheme is a different origin, as it is to
        // a browser — the QR would open somewhere else.
        assert_ne!(
            origin("https://hl.example:5700/"),
            origin("https://hl.example/")
        );
        assert_ne!(origin("http://hl.example/"), origin("https://hl.example/"));
        // Prefix matching would call these equal; they are not.
        assert_ne!(
            origin("https://hl.example.evil.test/app/"),
            origin("https://hl.example/")
        );
    }

    #[test]
    fn a_web_client_on_another_origin_is_only_taken_from_the_user() {
        // The mailbox answers discovery, and the QR's fragment carries
        // the pairing secret. A `web` the mailbox can point anywhere is
        // a `web` that hands it the secret, and with the secret it can
        // mint a `pair` for a device key of its own — the substituted
        // request §9 says a scanned enrollment does not suffer.
        let base = "https://hl.example";
        assert_eq!(
            web_client(base, Some("https://hl.example/app/"), None).as_deref(),
            Some("https://hl.example/app/"),
            "the operator's own client, on the origin the user typed"
        );
        assert_eq!(
            web_client(base, Some("https://evil.test/app/"), None),
            None,
            "a third-party origin the server named is no QR code at all"
        );
        assert_eq!(
            web_client(
                base,
                Some("https://evil.test/app/"),
                Some("https://mine.test/app/")
            )
            .as_deref(),
            Some("https://mine.test/app/"),
            "--web is the user saying it, and outranks discovery"
        );
        assert_eq!(
            web_client(base, None, None),
            None,
            "no client advertised is no QR code, and the code gets typed"
        );
    }

    #[test]
    fn a_renewal_is_narrowed_by_the_certificate_it_replaces() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        let mut prev = DeviceCert::for_device(&id, &dev, 1_000, 86_400).unwrap();
        prev.caps = Some(caps::LOGIN);

        // The holder's policy has grown since the old certificate was
        // issued. "The same or less" means the renewal does not inherit
        // that: it stays what it was.
        assert_eq!(renewed_caps(Some(caps::WEB), &prev), Some(caps::LOGIN));
        assert_eq!(renewed_caps(None, &prev), Some(caps::LOGIN));

        // An unrestricted old certificate bounds nothing, so the
        // holder's answer stands.
        prev.caps = None;
        assert_eq!(renewed_caps(Some(caps::WEB), &prev), Some(caps::WEB));
        assert_eq!(renewed_caps(None, &prev), None);

        // And the lifetime, which is the half that had no bound at all.
        // A seven-day certificate renews to seven days even when the
        // holder's policy would have given ninety.
        let week = DeviceCert::for_device(&id, &dev, 1_000, 7 * 86_400).unwrap();
        assert_eq!(prev_days(&week), 7);
        assert_eq!(renewed_days(90, &week), 7);
        assert_eq!(
            renewed_days(3, &week),
            3,
            "and asking for less still gets less"
        );

        // A certificate shorter than a day renews to a day: rounding
        // down would hand back one that had already expired.
        let hour = DeviceCert::for_device(&id, &dev, 1_000, 3_600).unwrap();
        assert_eq!(prev_days(&hour), 1);
        assert_eq!(renewed_days(90, &hour), 1);
    }

    #[test]
    fn a_renewal_may_not_ask_for_a_longer_life_than_it_has() {
        // The client that renews by pressing a button sends the days it
        // has in a field, and one that defaults that field to ninety
        // would walk a short-lived certificate up to the holder's full
        // policy — under `--renew auto`, with nobody watching.
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        let prev = DeviceCert::for_device(&id, &dev, 1_000, 7 * 86_400).unwrap();

        let mut req = EnrollRequest::new(&dev, 2_000);
        req.days = Some(7);
        assert!(renewal_is_sane(&prev, &req, &id, 2_000).is_ok());
        req.days = Some(3);
        assert!(renewal_is_sane(&prev, &req, &id, 2_000).is_ok());
        req.days = Some(90);
        assert!(
            renewal_is_sane(&prev, &req, &id, 2_000).is_err(),
            "a renewal asking for more than its certificate's lifetime"
        );

        // Absent is the holder's default, not a demand for everything —
        // the same asymmetry `caps` has. `renewed_days` bounds it.
        req.days = None;
        assert!(renewal_is_sane(&prev, &req, &id, 2_000).is_ok());
        let (_, days) = grant(&web(), req.caps, req.days);
        assert_eq!(renewed_days(days, &prev), 7);
    }

    #[test]
    fn renew_modes_parse_and_only_deny_declines_to_stand_by() {
        assert_eq!(Renew::parse(None).unwrap(), Renew::Ask);
        assert_eq!(Renew::parse(Some("ask")).unwrap(), Renew::Ask);
        assert_eq!(Renew::parse(Some("auto")).unwrap(), Renew::Auto);
        assert_eq!(Renew::parse(Some("deny")).unwrap(), Renew::Deny);
        assert!(Renew::parse(Some("sometimes")).is_err());

        // `deny` means no standing session, so the mailbox has nowhere
        // to route a codeless renewal and the browser is told
        // `no_holder` — which is how a renewal ends up coming through a
        // code like a first enrollment (§8).
        for (renew, standing) in [
            (Renew::Ask, true),
            (Renew::Auto, true),
            (Renew::Deny, false),
        ] {
            assert_eq!(renew != Renew::Deny, standing, "{renew:?}");
        }

        // And when one does arrive through a code, `deny` answers it like
        // a first enrollment rather than like a renewal: the default is
        // no. A user who said renewals should cost a code did not say
        // they should cost a code and one Return.
        assert!(Renew::Ask.prompt_default_yes());
        assert!(!Renew::Deny.prompt_default_yes());
    }

    #[test]
    fn the_scan_url_keeps_everything_in_the_fragment() {
        let id = IdentityKey::from_seed(&[1u8; 32]);
        let secret = [0x5au8; PAIRING_SECRET_BYTES];
        let url = scan_url(
            "https://hl.example/app/",
            "K7PM-4XWE",
            "hl.example",
            &id.fingerprint(),
            &secret,
        );

        // Everything after the '#' — browsers do not send a fragment to
        // the server, so none of this reaches an access log, and the
        // pairing secret in particular never leaves the two devices that
        // need it (§5.6).
        let (before, after) = url.split_once('#').expect("a fragment");
        assert_eq!(before, "https://hl.example/app/");
        for field in ["enroll=K7PM-4XWE", "mailbox=hl.example"] {
            assert!(after.contains(field), "{url}");
        }
        assert!(
            after.contains(&format!("identity={}", id.fingerprint())),
            "{url}"
        );
        assert!(after.contains(&format!("pair={}", b64(&secret))), "{url}");
    }

    #[test]
    fn a_qr_code_renders_with_its_quiet_zone_and_fixed_colours() {
        let block = qr_block("https://hl.example/app/#enroll=K7PM-4XWE").unwrap();
        // Colours are set rather than inherited: a QR code is dark on
        // light and many scanners will not read the inverse, so relying
        // on the terminal's theme would work on one machine and not the
        // next.
        assert!(block.starts_with("\x1b[47m\x1b[30m"), "no explicit colours");
        assert!(block.ends_with("\x1b[0m"), "colours not reset");

        // Two module rows per line, and the four-module quiet zone means
        // the first and last lines are blank field.
        let lines: Vec<&str> = block.lines().collect();
        assert!(lines.len() > 10, "suspiciously small: {}", lines.len());
        assert!(
            without_escapes(lines[1]).trim().is_empty(),
            "the quiet zone should be blank, got {:?}",
            without_escapes(lines[1])
        );
    }

    #[test]
    fn capability_words_never_understate_a_grant() {
        assert_eq!(caps_words(None), "everything");
        assert_eq!(caps_words(Some(caps::WEB)), "login, message");
        assert_eq!(caps_words(Some(0)), "nothing");
        // A bit from a newer build still shows up, rather than a prompt
        // quietly granting something it has no word for.
        assert_eq!(caps_words(Some(caps::LOGIN | 1 << 20)), "login, +0x100000");
    }
}
