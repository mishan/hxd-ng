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

use hl_identity::{Bundle, Card, DeviceCert, EnrollRequest, Fingerprint, IdentityKey};
use serde_json::{json, Value};

use crate::{
    b64, caps_words, now, parse_caps, read_file, read_seed, refuse_unreadable, seconds,
    server_base, unb64, CARD_FILE, IDENTITY_KEY, R,
};

/// Longer than the mailbox's 30-second long poll, so a poll that comes
/// back empty is the server answering rather than this giving up.
const POLL_TIMEOUT: Duration = Duration::from_secs(45);

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

/// A renewal is "the same device asking for the same or less" (§8). What
/// can be checked without the holder's policy is checked here; what the
/// device gets is still `grant`'s answer.
fn renewal_is_sane(
    prev: &DeviceCert,
    req: &EnrollRequest,
    identity: &IdentityKey,
) -> Result<(), String> {
    if prev.identity != identity.public() {
        return Err("the certificate it wants renewed was signed by a different identity".into());
    }
    if prev.device != req.device {
        return Err("the certificate it wants renewed is for a different device".into());
    }
    // `None` is unrestricted, so an old certificate with `None` bounds
    // nothing and a request for `None` against a bounded old one is a
    // widening.
    match (prev.caps, req.caps) {
        (Some(_), None) => return Err("it asks for more capabilities than it has".into()),
        (Some(had), Some(asked)) if asked & !had != 0 => {
            return Err("it asks for capabilities its certificate does not have".into())
        }
        _ => {}
    }
    Ok(())
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new().timeout(timeout).build()
}

/// Read `identity.endpoints.enroll` out of discovery. Absent means this
/// server hosts no mailbox, which is not a failure of anything — it is
/// the case the paste still exists for.
fn mailbox_base(base: &str) -> R<String> {
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
    Ok(format!("{base}{endpoint}"))
}

pub(crate) fn enroll_cmd(args: &[String]) -> R<()> {
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
    let mailbox = mailbox_base(&base)?;

    run(&id, &card, &parsed_card, &policy, &mailbox, &mut Terminal)
}

fn run(
    id: &IdentityKey,
    card: &[u8],
    parsed_card: &Card,
    policy: &Policy,
    mailbox: &str,
    ui: &mut dyn Prompt,
) -> R<()> {
    let http = agent(Duration::from_secs(10));
    let opened: Value = http
        .post(&format!("{mailbox}/sessions"))
        .send_json(json!({}))
        .map_err(|e| format!("opening a session: {e}"))?
        .into_json()
        .map_err(|e| format!("opening a session: {e}"))?;
    let session = opened["session"]
        .as_str()
        .ok_or("the mailbox returned no session")?
        .to_owned();
    let code = opened["code"]
        .as_str()
        .ok_or("the mailbox returned no code")?
        .to_owned();
    let minutes = opened["expires_in"].as_u64().unwrap_or(600) / 60;

    // The host beside the code, because the enrollee has to use the same
    // mailbox and there is nothing else on the screen that says which.
    let host = mailbox
        .split("://")
        .nth(1)
        .and_then(|r| r.split('/').next())
        .unwrap_or(mailbox);
    ui.tell(&format!(
        "\nEnroll a device at {host}: enter code  {code}  (expires in {minutes}:00)\n\
         This identity: {}  {}\n",
        parsed_card.name,
        id.fingerprint().short(),
    ));

    // One request, then exit: `enroll` is `agent` with a budget of one.
    let poll = agent(POLL_TIMEOUT);
    let (id_of_request, request) = loop {
        let answer: Value = poll
            .get(&format!("{mailbox}/sessions/{session}"))
            .call()
            .map_err(|e| format!("waiting for a device: {e}"))?
            .into_json()
            .map_err(|e| format!("waiting for a device: {e}"))?;
        let pending = answer["pending"].as_array().cloned().unwrap_or_default();
        if let Some(first) = pending.first() {
            // No id, no answer: everything after this identifies the
            // request being certified or refused, and an empty name
            // would mean answering something the mailbox never
            // described.
            let id = first["id"].as_str().unwrap_or_default();
            if id.is_empty() {
                return Err("the mailbox delivered a request with no id".into());
            }
            let raw = unb64(first["request"].as_str().unwrap_or(""))?;
            // Verified here, and everything shown below is computed from
            // this rather than from anything the mailbox said.
            let req = EnrollRequest::parse(&raw).map_err(|e| {
                format!("the mailbox delivered something that is not a request: {e}")
            })?;
            break (id.to_owned(), req);
        }
        if answer["expires_in"].as_u64() == Some(0) {
            return Err("the session expired before a device asked".into());
        }
    };

    let device_fp = Fingerprint::of(&request.device);
    let named = request.name.clone().unwrap_or_else(|| "unnamed".into());

    // A renewal is a different question, and gets a different default.
    let renewal = match request.prev_cert() {
        Some(Ok(prev)) => match renewal_is_sane(&prev, &request, id) {
            Ok(()) => Some(prev),
            Err(why) => {
                deny(&http, mailbox, &session, &id_of_request, "bad_renewal")?;
                return Err(format!("refused a renewal: {why}"));
            }
        },
        Some(Err(e)) => {
            deny(&http, mailbox, &session, &id_of_request, "bad_renewal")?;
            return Err(format!(
                "refused a renewal whose certificate is not usable: {e}"
            ));
        }
        None => None,
    };

    // `pair` is the scanned path's proof (§5.6), which this command does
    // not offer yet. A request carrying one was made against a QR code
    // nobody here drew, so it cannot verify and must not be shown: the
    // only way to produce one is to have guessed (§6).
    if request.pair.is_some() {
        deny(&http, mailbox, &session, &id_of_request, "bad_pair")?;
        return Err("refused a request claiming to have been scanned; no QR code was shown".into());
    }

    let (caps, days) = grant(policy, request.caps, request.days);
    let approved = match &renewal {
        Some(prev) => {
            let left = prev.expires.saturating_sub(now()) / 86_400;
            ui.confirm(
                &format!(
                    "Renew  {named:?}  {}  (expires in {left} days)?",
                    device_fp.short()
                ),
                true,
            )
        }
        None => ui.confirm(
            &screen(host, &code, &device_fp, &named, &request, caps, days),
            false,
        ),
    };
    if !approved {
        deny(&http, mailbox, &session, &id_of_request, "declined")?;
        ui.tell("Declined; nothing was signed.");
        return Ok(());
    }

    let mut cert = DeviceCert::for_keys(
        id,
        request.device,
        request.device_enc,
        now(),
        seconds(days)?,
    )
    .map_err(|e| format!("--days: {e}"))?;
    cert.caps = caps;
    cert.name = request.name.clone();
    let cert_bytes = cert.sign(id);
    DeviceCert::parse(&cert_bytes).map_err(|e| refuse_unreadable("device certificate", e))?;
    let bundle = Bundle {
        cert: cert_bytes,
        card: card.to_vec(),
    }
    .encode();

    http.post(&format!("{mailbox}/sessions/{session}/answers"))
        .send_json(json!({ "id": id_of_request, "bundle": b64(&bundle) }))
        .map_err(|e| format!("answering: {e}"))?;
    ui.tell(&format!(
        "Certified {named:?} {} for {days} days.",
        device_fp.short()
    ));
    Ok(())
}

fn deny(http: &ureq::Agent, mailbox: &str, session: &str, id: &str, reason: &str) -> R<()> {
    http.post(&format!("{mailbox}/sessions/{session}/answers"))
        .send_json(json!({ "id": id, "denied": reason }))
        .map_err(|e| format!("answering: {e}"))?;
    Ok(())
}

/// §6's prompt. Everything that matters and nothing else: what is
/// asking, what it asked for, what it will actually get, and the one
/// comparison only a human can make.
fn screen(
    host: &str,
    code: &str,
    device: &Fingerprint,
    named: &str,
    request: &EnrollRequest,
    caps: Option<u64>,
    days: u64,
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
    format!(
        "\nEnrollment request via {host}, code {code}\n\n  \
         device      {}  ({named:?})\n  \
         asks for    {asked_caps} · {asked_days}\n  \
         will get    {} · {days} days\n\n\
         Compare the device fingerprint with the one the browser is showing.\n\
         Certify?",
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
        assert!(renewal_is_sane(&prev, &req, &id).is_ok());

        // Asking for more than the old certificate carried.
        req.caps = Some(caps::WEB | caps::MANAGE);
        assert!(renewal_is_sane(&prev, &req, &id).is_err());

        // Asking for unrestricted, which is more than any mask.
        req.caps = None;
        assert!(renewal_is_sane(&prev, &req, &id).is_err());

        // Somebody else's certificate, and somebody else's device.
        req.caps = Some(caps::WEB);
        assert!(renewal_is_sane(&prev, &req, &other).is_err());
        let theirs = DeviceCert::for_device(&id, &stranger, 1_000, 86_400).unwrap();
        assert!(renewal_is_sane(&theirs, &req, &id).is_err());
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
        );
        assert!(s.contains("asks for    login, manage · 3650 days"), "{s}");
        assert!(s.contains("will get    login · 90 days"), "{s}");
        // The comparison is the step a hostile mailbox cannot fake, so
        // it has to be on the screen (§9).
        assert!(s.contains("Compare the device fingerprint"), "{s}");
        assert!(s.contains(&Fingerprint::of(&req.device).short()), "{s}");
    }

    #[test]
    fn the_prompt_does_not_report_an_unstated_ask_as_everything() {
        // The bug this guards is on the one screen where being
        // misleading is the whole risk: `None` in a request means
        // "whatever your policy gives" (§4), and rendering it with the
        // certificate's meaning would show a browser asking for
        // everything when it asked for nothing in particular.
        let dev = hl_identity::DeviceKey::from_seed(&[3u8; 32]);
        let req = EnrollRequest::new(&dev, 1_000);
        assert_eq!(req.caps, None);

        let (caps, days) = grant(&web(), req.caps, req.days);
        let s = screen(
            "hl.example",
            "K7PM-4XWE",
            &Fingerprint::of(&req.device),
            "unnamed",
            &req,
            caps,
            days,
        );
        assert!(s.contains("asks for    the default"), "{s}");
        assert!(!s.contains("asks for    everything"), "{s}");
        // The grant is still shown with the certificate's meaning,
        // because that is the object it is going into.
        assert!(s.contains("will get    login, message"), "{s}");
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
