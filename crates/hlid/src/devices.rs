//! Device epochs from the holder's side (`docs/identity-registrar.md`
//! §4.10 and §6.2, `docs/identity-enrollment.md` §8): `hlid devices
//! reset`, the epoch every certificate is minted at, and the registrars'
//! records a holder reads before it mints.
//!
//! The registrars' per-identity lists are the truth. `holder.json` in
//! `$HLID_HOME` keeps, per identity, the highest floor this holder has
//! learned, the highest epoch `hlid cert`, `enroll` or `agent` minted a
//! certificate at, the
//! registrars it registered at, and a reset not yet done everywhere with
//! the hashes of the records it posted for it, so a rerun finishes that
//! reset rather than starting another.

use std::path::PathBuf;
use std::time::Duration;

use hl_identity::{
    DeviceCert, DeviceEpoch, Fingerprint, IdentityKey, ListKind, PublicKey, Record, RegistrarKeys,
    SignedList,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::registrar::{base_of, discover_at, identity, Registrar};
use crate::{b64, now, parse, refuse_unreadable, unb64, Args, CARD_FILE, R};

/// How far one published device epoch may move a registrar's floor
/// (§6.2 step 5).
const STEP_MAX: u64 = 16;

/// Posts whose reply was lost before a registrar is reported not done.
const TRIES: usize = 3;

/// Posts to one registrar for one target, at most: a catch-up from 0 to
/// the top of the range is far fewer.
const POSTS_MAX: usize = 64;

/// Pages of one per-identity list read, at most.
const LIST_PAGES: usize = 16;

/// A record post's reply, read at most.
const REPLY_MAX: u64 = 64 * 1024;

/// A server keeps a session's certificate for `signs` and `sealed` only
/// up to this (`hotline-ng-identity.md` §3.3).
pub(crate) const CERT_CARRIED_MAX: usize = 512;

const HOLDER_FILE: &str = "holder.json";

/// Beside it: whoever holds a lock on this has the file to itself.
const LOCK_FILE: &str = "holder.lock";

// --- What this holder keeps ----------------------------------------------

/// A reset not yet done at every registrar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Reset {
    pub(crate) target: u64,
    /// Every record this holder signed for it, catch-up steps and
    /// retries included: an answer naming one of them is its own post.
    pub(crate) hashes: Vec<[u8; 32]>,
}

/// `holder.json`: per identity fingerprint, its floor, the highest
/// epoch `hlid cert`, `enroll` or `agent` minted at, its registrars (as
/// `[url, host]`) and its reset in progress.
///
/// A `Holder` holds `holder.lock` from load until it is dropped, so a
/// mint and a reset are ordered (enrollment §8), and no two processes
/// read and write the file over each other. A reset holds it for its
/// whole run, and a mint from reading the epoch to recording it. Never
/// load a second while one is held: the lock is per open file, so it
/// would wait on itself. Off Unix there is no lock, and two `hlid` runs
/// at once are not safe there.
pub(crate) struct Holder {
    path: Option<PathBuf>,
    doc: Value,
    fp: String,
    _lock: Option<std::fs::File>,
}

impl Holder {
    pub(crate) fn load(identity: &PublicKey) -> R<Holder> {
        let home = crate::hlid_home().ok();
        let lock = match &home {
            Some(h) if h.is_dir() => Some(lock(&h.join(LOCK_FILE))?),
            _ => None,
        };
        let path = home.map(|h| h.join(HOLDER_FILE));
        let failed =
            |e: &dyn std::fmt::Display| format!("{}: {e}", path.as_ref().unwrap().display());
        let doc: Value = match path.as_ref().map(std::fs::read) {
            Some(Ok(bytes)) => serde_json::from_slice(&bytes).map_err(|e| failed(&e))?,
            Some(Err(e)) if e.kind() != std::io::ErrorKind::NotFound => return Err(failed(&e)),
            _ => json!({}),
        };
        if !doc.is_object() {
            return Err(failed(&"not a JSON object"));
        }
        Ok(Holder {
            path,
            doc,
            fp: Fingerprint::of(identity).to_string(),
            _lock: lock,
        })
    }

    fn entry(&self) -> &Value {
        &self.doc[&self.fp]
    }

    fn entry_mut(&mut self) -> &mut Value {
        if !self.doc[&self.fp].is_object() {
            self.doc[&self.fp] = json!({});
        }
        &mut self.doc[&self.fp]
    }

    /// The highest floor this holder knows for the identity.
    pub(crate) fn epoch(&self) -> u64 {
        self.entry()["epoch"].as_u64().unwrap_or(0)
    }

    pub(crate) fn raise(&mut self, epoch: u64) {
        if epoch > self.epoch() {
            self.entry_mut()["epoch"] = json!(epoch);
        }
    }

    fn minted_at(&self) -> u64 {
        self.entry()["minted"].as_u64().unwrap_or(0)
    }

    /// Record a certificate minted at `epoch`, other than this machine's
    /// own renewed by a reset. A reset
    /// in progress at or below it would leave that device signed in, so
    /// it is not finished but passed (see [`target`]).
    pub(crate) fn minted(&mut self, epoch: u64) {
        if epoch >= self.minted_at() {
            self.entry_mut()["minted"] = json!(epoch);
        }
    }

    fn registrars(&self) -> Vec<(String, String)> {
        self.entry()["registrars"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| Some((r[0].as_str()?.to_owned(), r[1].as_str()?.to_owned())))
            .collect()
    }

    pub(crate) fn add_registrar(&mut self, url: &str, host: &str) {
        if self.registrars().iter().any(|(u, _)| u == url) {
            return;
        }
        let e = self.entry_mut();
        if !e["registrars"].is_array() {
            e["registrars"] = json!([]);
        }
        e["registrars"]
            .as_array_mut()
            .unwrap()
            .push(json!([url, host]));
    }

    fn reset(&self) -> Option<Reset> {
        let r = &self.entry()["reset"];
        Some(Reset {
            target: r["target"].as_u64()?,
            hashes: r["hashes"]
                .as_array()?
                .iter()
                .filter_map(|h| unb64(h.as_str()?).ok()?.try_into().ok())
                .collect(),
        })
    }

    fn set_reset(&mut self, r: Option<&Reset>) {
        let e = self.entry_mut();
        match r {
            Some(r) => {
                let hashes: Vec<String> = r.hashes.iter().map(|h| b64(h)).collect();
                let targets = e["reset"]["targets"].clone();
                e["reset"] = json!({ "target": r.target, "hashes": hashes });
                if targets.is_array() {
                    e["reset"]["targets"] = targets;
                }
            }
            None => {
                e.as_object_mut().unwrap().remove("reset");
            }
        }
    }

    /// The registrars a reset in progress was started for, so a rerun
    /// without the same `--registrar` leaves none of them out.
    fn reset_targets(&self) -> Vec<Target> {
        self.entry()["reset"]["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|t| Some((t[0].as_str()?.to_owned(), t[1].as_str().map(str::to_owned))))
            .collect()
    }

    fn set_reset_targets(&mut self, targets: &[Target]) {
        if self.entry()["reset"].is_object() {
            self.entry_mut()["reset"]["targets"] = json!(targets);
        }
    }

    /// The highest epoch this holder certified `device` at.
    pub(crate) fn certified_at(&self, device: &PublicKey) -> Option<u64> {
        self.entry()["devices"][crate::hex(device)].as_u64()
    }

    /// Record that `device` was certified at `epoch`, so that once a reset
    /// passes it the key is refused (enrollment §8).
    pub(crate) fn certified(&mut self, device: &PublicKey, epoch: u64) {
        if self.certified_at(device).is_some_and(|e| e >= epoch) {
            return;
        }
        let e = self.entry_mut();
        if !e["devices"].is_object() {
            e["devices"] = json!({});
        }
        e["devices"][crate::hex(device)] = json!(epoch);
    }

    /// Whether there is a `$HLID_HOME` to keep this in.
    pub(crate) fn has_home(&self) -> bool {
        self.path.is_some()
    }

    pub(crate) fn save(&self) -> R<()> {
        let path = self
            .path
            .as_ref()
            .ok_or("there is no $HLID_HOME or $HOME to keep the device epoch in")?;
        let text = serde_json::to_vec_pretty(&self.doc).map_err(|e| e.to_string())?;
        hl_private_file::replace(path, &text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Take `path`'s lock, waiting for whoever has it.
fn lock(path: &std::path::Path) -> R<std::fs::File> {
    let failed = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| failed(&e))?;
    #[cfg(unix)]
    {
        use rustix::fs::{flock, FlockOperation};
        if flock(&f, FlockOperation::NonBlockingLockExclusive).is_err() {
            eprintln!("hlid: waiting for another hlid ({})", path.display());
            flock(&f, FlockOperation::LockExclusive).map_err(|e| failed(&e))?;
        }
    }
    Ok(f)
}

/// A registrar to read, and the host its discovery must name when it is
/// known: the one it named when registered at, or an attestation's.
pub(crate) type Target = (String, Option<String>);

/// Where a reset goes: every registrar the identity is registered at,
/// and each `--registrar` too, so that naming one never leaves another
/// out. One named that is known keeps the host it is known by.
fn targets(a: &Args, holder: &Holder, identity: &PublicKey) -> Vec<Target> {
    let mut out = known(a, holder, identity);
    for named in a.many("registrar").into_iter().map(base_of) {
        if !out.iter().any(|(u, _)| *u == named) {
            out.push((named, None));
        }
    }
    out
}

/// Where the identity is registered: the registrars `hlid register`
/// kept, and the host of every attestation the card carries that none of
/// those is.
fn known(a: &Args, holder: &Holder, identity: &PublicKey) -> Vec<Target> {
    let kept = holder.registrars();
    let card = a
        .file_opt("card", CARD_FILE)
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| hl_identity::Card::parse(&b).ok())
        .filter(|c| c.identity == *identity);
    let mut out: Vec<Target> = kept
        .iter()
        .map(|(u, h)| (base_of(u), Some(h.clone())))
        .collect();
    for att in card.iter().flat_map(|c| &c.attestations) {
        let url = format!("https://{}", att.registrar);
        if !kept.iter().any(|(_, h)| *h == att.registrar) && !out.iter().any(|(u, _)| *u == url) {
            out.push((url, Some(att.registrar.clone())));
        }
    }
    out
}

// --- Reading a registrar's list ------------------------------------------

/// A registrar's current device epoch record for the identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Current {
    /// 0 for none.
    pub(crate) epoch: u64,
    pub(crate) time: u64,
    pub(crate) hash: Option<[u8; 32]>,
}

/// What a per-identity list says about the identity's devices.
#[derive(Debug, Default)]
pub(crate) struct Listed {
    pub(crate) current: Current,
    /// Device keys a device revocation names.
    pub(crate) revoked: Vec<PublicKey>,
    /// Devices that signed a record, with their certificate's epoch.
    pub(crate) signers: Vec<(PublicKey, u64)>,
}

impl Listed {
    /// The entries of a verified list, each verified, read for
    /// `identity`.
    fn of(entries: &[(u64, Vec<u8>)], rk: RegistrarKeys<'_>, identity: &PublicKey) -> Listed {
        let mut l = Listed::default();
        for (_, bytes) in entries {
            match Record::parse(bytes, Some(rk)) {
                Ok(Record::DeviceEpoch(r))
                    if r.identity == *identity && r.epoch >= l.current.epoch =>
                {
                    l.current = Current {
                        epoch: r.epoch,
                        time: r.time,
                        hash: Some(Sha256::digest(bytes).into()),
                    }
                }
                Ok(Record::RevokeDevice(r)) if r.identity == *identity => {
                    l.revoked.push(r.device);
                    if let (Some(signer), Some(epoch)) = (r.signer, r.signer_epoch()) {
                        l.signers.push((signer, epoch));
                    }
                }
                _ => {}
            }
        }
        l
    }
}

/// The per-identity list, past any cache (§6.2), every page of it.
fn read_list(reg: &Registrar, identity: &PublicKey) -> R<Listed> {
    let fp = Fingerprint::of(identity);
    let keys = reg.keys();
    let rk = RegistrarKeys {
        host: &reg.host,
        keys: &keys,
    };
    let mut entries = Vec::new();
    let mut since: Option<u64> = None;
    for _ in 0..LIST_PAGES {
        let url = match since {
            None => format!("{}/{fp}", reg.records),
            Some(s) => format!("{}/{fp}?since={s}", reg.records),
        };
        let resp = crate::registrar::agent()
            .get(&url)
            .set("Cache-Control", "no-cache")
            .call()
            .map_err(|e| format!("{url}: {e}"))?;
        let mut body = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(
                resp.into_reader(),
                hl_identity::registrar::LIST_MAX_BYTES as u64 + 1,
            ),
            &mut body,
        )
        .map_err(|e| format!("{url}: {e}"))?;
        let list = SignedList::parse(&body, ListKind::Records, rk)
            .map_err(|e| format!("{url}: the list does not verify: {e}"))?;
        if list.fingerprint != Some(fp.0) {
            return Err(format!("{url}: the list is not the one asked for"));
        }
        if !list.more {
            entries.extend(list.entries);
            return Ok(Listed::of(&entries, rk, identity));
        }
        // `parse` holds every seq past `since`, and a page with `more`
        // has an entry, so each page moves on.
        since = list.entries.last().map(|(seq, _)| *seq);
        entries.extend(list.entries);
    }
    Err(format!(
        "{}/{fp}: more than {LIST_PAGES} pages of records",
        reg.records
    ))
}

/// The floor `reg` holds for `identity`.
pub(crate) fn floor_at(reg: &Registrar, identity: &PublicKey) -> R<u64> {
    Ok(read_list(reg, identity)?.current.epoch)
}

/// Discovery and the list, for each of `targets`; the failures as
/// sentences.
fn read_all(targets: &[Target], identity: &PublicKey) -> (Vec<(Registrar, Listed)>, Vec<String>) {
    let (mut read, mut failed) = (Vec::new(), Vec::new());
    for (url, host) in targets {
        let found = discover_at(url).and_then(|reg| match host {
            Some(h) if *h != reg.host => Err(format!(
                "it names itself {}, where the identity is registered at {h}",
                reg.host
            )),
            _ => Ok((read_list(&reg, identity)?, reg)),
        });
        match found {
            Ok((l, reg)) => read.push((reg, l)),
            Err(e) => failed.push(format!("{url}: {e}")),
        }
    }
    (read, failed)
}

// --- Posting ---------------------------------------------------------------

/// A registrar's answer to a device epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// Where the identity stands there: its current record's `epoch` and
    /// hash.
    At {
        epoch: u64,
        hash: [u8; 32],
    },
    /// No reply, or one that says nothing about the post.
    Lost(String),
    Refused(String),
}

fn read_json(resp: ureq::Response) -> Result<Value, String> {
    let mut body = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(resp.into_reader(), REPLY_MAX),
        &mut body,
    )
    .map_err(|e| e.to_string())?;
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

fn post(reg: &Registrar, bytes: &[u8]) -> Answer {
    let url = &reg.records;
    let reply = crate::registrar::agent()
        .post(url)
        .send_json(json!({ "record": b64(bytes) }));
    let answer = match reply {
        Ok(resp) => match read_json(resp) {
            Ok(v) => match (
                v["epoch"].as_u64(),
                v["hash"]
                    .as_str()
                    .and_then(|h| unb64(h).ok()?.try_into().ok()),
            ) {
                (Some(epoch), Some(hash)) => return Answer::At { epoch, hash },
                _ => Answer::Refused(format!(
                    "{url} does not take device epochs (it answered {v})"
                )),
            },
            Err(e) => Answer::Lost(format!("{url}: {e}")),
        },
        Err(ureq::Error::Status(code, resp)) => {
            let body = read_json(resp).unwrap_or(Value::Null);
            let error = body["error"].as_str().unwrap_or("?");
            let mut why = format!(
                "refused ({code} {error}): {}",
                body["text"].as_str().unwrap_or("")
            );
            if let Some(after) = body["retry_after"].as_u64() {
                why.push_str(&format!("; try again in {after} seconds"));
            }
            if code >= 500 {
                Answer::Lost(why)
            } else {
                Answer::Refused(why)
            }
        }
        Err(e) => Answer::Lost(format!("{url}: {e}")),
    };
    if let Answer::Lost(_) = answer {
        std::thread::sleep(Duration::from_secs(1));
    }
    answer
}

/// What bringing one registrar to a target came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Done,
    /// Another holder reset meanwhile, the registrar answering this
    /// epoch: read every list again and choose the target afresh, at
    /// least past it.
    Again(u64),
    NotDone(String),
}

/// Bring a registrar whose current record is `at` to `target`: `at +
/// 16` first while it is further behind than that, each post signed
/// afresh at the later of now and the registrar's current record's
/// `time`, and its hash kept in `reset` before it is sent. With `exact`,
/// the target is done only when the registrar names a record this holder
/// posted; without, any record at or past it will do.
pub(crate) fn drive(
    target: u64,
    exact: bool,
    mut at: Current,
    reset: &mut Reset,
    id: &IdentityKey,
    post: &mut dyn FnMut(&[u8]) -> Answer,
    keep: &mut dyn FnMut(&Reset) -> R<()>,
) -> R<Outcome> {
    let mut lost = 0;
    for _ in 0..POSTS_MAX {
        let epoch = target.min(at.epoch.saturating_add(STEP_MAX));
        let time = now().max(at.time);
        let bytes = DeviceEpoch {
            identity: id.public(),
            epoch,
            time,
        }
        .sign(id)
        .map_err(|e| refuse_unreadable("device epoch", e))?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        if !reset.hashes.contains(&hash) {
            reset.hashes.push(hash);
            keep(reset)?;
        }
        match post(&bytes) {
            Answer::At { epoch: e, hash: h } => {
                lost = 0;
                // An honest registrar answers at least what it was sent:
                // it published it, or holds more.
                if e < epoch {
                    return Ok(Outcome::NotDone(format!(
                        "answered epoch {e} to a post of {epoch}"
                    )));
                }
                let ours = reset.hashes.contains(&h);
                if !exact && e >= target {
                    return Ok(Outcome::Done);
                }
                // One above the target, or another holder's at it, leaves
                // the devices minted since at that epoch signed in.
                if e > target || (e == target && !ours) {
                    return Ok(Outcome::Again(e));
                }
                if e == target {
                    return Ok(Outcome::Done);
                }
                if !ours {
                    // Another holder's below the target, whose `time`
                    // this cannot know without the list.
                    return Ok(Outcome::Again(e));
                }
                at = Current {
                    epoch: e,
                    time,
                    hash: Some(h),
                };
            }
            Answer::Lost(why) => {
                lost += 1;
                if lost >= TRIES {
                    return Ok(Outcome::NotDone(why));
                }
            }
            Answer::Refused(why) => return Ok(Outcome::NotDone(why)),
        }
    }
    Ok(Outcome::NotDone(format!(
        "{POSTS_MAX} posts did not bring it to epoch {target}"
    )))
}

/// The target of a reset, from what every registrar read holds: the one
/// in progress while nothing has been minted at it, and no registrar is
/// past it or at it with a record this holder did not post; else one past
/// the highest floor known.
pub(crate) fn target(known: u64, minted: u64, pending: Option<&Reset>, held: &[Current]) -> u64 {
    let highest = held.iter().map(|c| c.epoch).fold(known, u64::max);
    match pending {
        Some(r)
            if r.target >= highest
                && minted < r.target
                && held.iter().all(|c| {
                    c.epoch < r.target || c.hash.is_some_and(|h| r.hashes.contains(&h))
                }) =>
        {
            r.target
        }
        _ => highest + 1,
    }
}

/// What one round of a reset came to, by registrar.
#[derive(Debug, Default, PartialEq, Eq)]
struct Round {
    done: Vec<String>,
    not_done: Vec<String>,
    /// The highest epoch an `Again` answered.
    again: Option<u64>,
}

/// Drive each of `bases` in turn. Another holder's reset found at one
/// makes the target stale, so the round stops there rather than spend
/// the rest's daily resets on it; unless that registrar did so in an
/// earlier round (`causes`), when the rest are driven anyway, so that no
/// set of registrars answering so holds up the others.
fn round(
    bases: &[&str],
    causes: &mut Vec<String>,
    drive: &mut dyn FnMut(usize) -> R<Outcome>,
) -> R<Round> {
    let mut r = Round::default();
    for (i, base) in bases.iter().enumerate() {
        match drive(i)? {
            Outcome::Done => r.done.push(base.to_string()),
            Outcome::NotDone(why) => r.not_done.push(format!("{base}: {why}")),
            Outcome::Again(e) => {
                r.again = r.again.max(Some(e));
                if !causes.iter().any(|c| c == base) {
                    causes.push(base.to_string());
                    break;
                }
            }
        }
    }
    Ok(r)
}

// --- hlid devices reset ----------------------------------------------------

pub(crate) fn devices_cmd(args: &[String]) -> R<()> {
    match args.first().map(String::as_str) {
        Some("reset") => reset_cmd(&args[1..]),
        Some("renew") => renew_cmd(&args[1..]),
        _ => crate::usage(),
    }
}

/// `hlid devices reset [--registrar HOST|URL]...`: sign out every device
/// the identity certified, at every registrar it is registered at
/// (§6.2 "A holder's reset"). The holder's lock is held throughout, so
/// nothing this holder mints falls between choosing the target and
/// reaching it.
fn reset_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = identity(&a)?;
    let mut holder = Holder::load(&id.public())?;
    let mut targets = targets(&a, &holder, &id.public());
    // `--fresh` sets aside a reset in progress, for when another machine
    // may have certified a device at its epoch since: `minted` is this
    // holder's alone.
    let mut pending = holder.reset().filter(|_| !a.has("fresh"));
    if holder.reset().is_some() {
        for t in holder.reset_targets() {
            if !targets.iter().any(|(u, _)| *u == t.0) {
                targets.push(t);
            }
        }
    }
    if targets.is_empty() {
        return Err(
            "the identity is registered at no registrar this holder knows of; \
             name one with --registrar"
                .into(),
        );
    }
    let mut causes = Vec::new();
    // The highest epoch a registrar answered past the target. An answer
    // is not signed, so it only sends this back to the lists: a target
    // rises from what they verify, and none is posted while they show
    // less than was answered.
    let mut seen = 0;
    for _ in 0..8 {
        let (read, unread) = read_all(&targets, &id.public());
        for why in &unread {
            eprintln!("hlid: {why}");
        }
        if read.is_empty() {
            return Err(
                "no registrar could be reached, so nothing was reset: a reset no server \
                 can fetch signs nothing out. Try again once one can be"
                    .into(),
            );
        }
        let held: Vec<Current> = read.iter().map(|(_, l)| l.current).collect();
        let listed = held.iter().map(|c| c.epoch).max().unwrap_or(0);
        if seen > listed {
            return Err(format!(
                "a registrar answered epoch {seen}, past what any list read shows ({listed}); \
                 nothing more was posted. Run `hlid devices reset` again once its list can be \
                 read"
            ));
        }
        holder.raise(listed);
        let mut reset = Reset {
            target: target(holder.epoch(), holder.minted_at(), pending.as_ref(), &held),
            hashes: pending.take().map(|r| r.hashes).unwrap_or_default(),
        };
        if reset.target > hl_identity::cert::EPOCH_MAX {
            return Err("the identity has no epoch left to reset to; rotate it instead".into());
        }
        holder.set_reset(Some(&reset));
        holder.set_reset_targets(&targets);
        holder.save()?;

        let bases: Vec<&str> = read.iter().map(|(reg, _)| reg.base.as_str()).collect();
        let Round {
            done,
            not_done,
            again,
        } = round(&bases, &mut causes, &mut |i| {
            let (reg, listed) = &read[i];
            let c = listed.current;
            let outcome =
                if c.epoch == reset.target && c.hash.is_some_and(|h| reset.hashes.contains(&h)) {
                    Outcome::Done
                } else {
                    drive(
                        reset.target,
                        true,
                        c,
                        &mut reset,
                        &id,
                        &mut |bytes| post(reg, bytes),
                        &mut |r| {
                            holder.set_reset(Some(r));
                            holder.save()
                        },
                    )?
                };
            // Kept before the next registrar is posted to, so a failure
            // there leaves this holder minting at the floor this one holds.
            if outcome == Outcome::Done {
                holder.raise(reset.target);
                holder.save()?;
            }
            Ok(outcome)
        })?;
        if let Some(e) = again {
            // Equal to the target, it is another holder's record at it;
            // past it, a reset past it. Either way the lists say which.
            seen = seen.max(e);
            eprintln!("another holder reset meanwhile; resetting past it");
            pending = holder.reset();
            holder.save()?;
            continue;
        }
        let complete = not_done.is_empty() && unread.is_empty();
        if complete {
            holder.set_reset(None);
        }
        holder.save()?;
        for base in &done {
            println!("devices reset to epoch {} at {base}", reset.target);
        }
        let renewed = if done.is_empty() {
            Ok(())
        } else {
            renew_own(&a, &id, &mut holder).map(drop)
        };
        if complete {
            println!(
                "these registrars publish epoch {}: a server that reads their records \
                 refuses every device certified below it. Enroll each one you still use \
                 again, with a new device key",
                reset.target
            );
            return renewed.map_err(|e| {
                format!("{e}; the reset is done, and `hlid devices renew` renews it")
            });
        }
        if let Err(e) = renewed {
            eprintln!("hlid: {e}; `hlid devices renew` renews it");
        }
        return Err(format!(
            "the reset to epoch {} is not done at {}; run `hlid devices reset` again to \
             finish it",
            reset.target,
            not_done
                .iter()
                .chain(&unread)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    Err("registrars kept answering with another holder's resets; try again later".into())
}

/// This machine's own certificate again at the new floor, with the same
/// key: the reset is not about the machine holding the identity key.
/// Nothing to renew is not a failure; one that could not be written is.
fn renew_own(a: &Args, id: &IdentityKey, holder: &mut Holder) -> R<Renewed> {
    let Some(path) = a.file_opt("cert", crate::CERT_FILE) else {
        return Ok(Renewed::Nothing("there is no cert.bin".into()));
    };
    let old = match std::fs::read(&path)
        .map_err(|e| e.to_string())
        .and_then(|b| DeviceCert::parse(&b).map_err(|e| e.to_string()))
    {
        Ok(old) if old.identity == id.public() => old,
        Ok(_) => {
            return Ok(Renewed::Nothing(format!(
                "{} is another identity's",
                path.display()
            )))
        }
        Err(e) => return Ok(Renewed::Nothing(format!("{}: {e}", path.display()))),
    };
    if old.epoch >= holder.epoch() {
        return Ok(Renewed::Nothing(format!(
            "{} is at epoch {} already",
            path.display(),
            old.epoch
        )));
    }
    let renewed = DeviceCert::for_keys(
        id,
        old.device,
        old.device_enc,
        now(),
        old.expires.saturating_sub(old.issued),
    )
    .map(|mut c| {
        c.caps = old.caps;
        c.name = old.name.clone();
        c.epoch = holder.epoch();
        c
    })
    .map_err(|e| e.to_string())
    .and_then(|c| mint(&c, id))
    .and_then(|bytes| {
        hl_private_file::replace(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))
    });
    renewed.map_err(|e| format!("{} was not renewed: {e}", path.display()))?;
    println!("{} renewed at epoch {}", path.display(), holder.epoch());
    holder.certified(&old.device, holder.epoch());
    holder.save()?;
    Ok(Renewed::Done)
}

/// What [`renew_own`] did.
enum Renewed {
    Done,
    /// Why there was nothing to do.
    Nothing(String),
}

/// `hlid devices renew`: this machine's certificate at the floor the
/// registrars hold, read first, with no reset, for when a reset's own
/// renewal of it failed.
fn renew_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = identity(&a)?;
    sync(&a, &id, &mut |line| eprintln!("hlid: {line}"))?;
    let mut holder = Holder::load(&id.public())?;
    if let Renewed::Nothing(why) = renew_own(&a, &id, &mut holder)? {
        println!("nothing renewed: {why}");
    }
    Ok(())
}

/// Sign a certificate, checked as every reader will check it, and warn
/// when it is past what a server keeps for `signs` and `sealed`.
pub(crate) fn mint(c: &DeviceCert, id: &IdentityKey) -> R<Vec<u8>> {
    let bytes = c.sign(id);
    DeviceCert::parse(&bytes).map_err(|e| refuse_unreadable("device certificate", e))?;
    if bytes.len() > CERT_CARRIED_MAX {
        eprintln!(
            "hlid: this certificate is {} bytes, past the {CERT_CARRIED_MAX} a server keeps \
             for signing and sealing; a shorter --name keeps it under",
            bytes.len()
        );
    }
    Ok(bytes)
}

// --- Before a mint ----------------------------------------------------------

/// What a holder knows of the identity's devices before it mints.
#[derive(Debug, Default, Clone)]
pub(crate) struct Floor {
    pub(crate) epoch: u64,
    /// Keys a reset signed out: revoked by a device revocation, or the
    /// signer of one with a certificate below the floor (enrollment §8).
    /// Device revocations alone: a vouch is not a `Record`. Read from the
    /// lists that could be fetched, so with none it is empty and refuses
    /// nothing: a holder offline mints as it last knew, the residual of
    /// a SHOULD.
    pub(crate) reset_keys: Vec<PublicKey>,
}

impl Floor {
    fn of(known: u64, lists: &[&Listed]) -> Floor {
        let epoch = lists.iter().map(|l| l.current.epoch).fold(known, u64::max);
        let mut reset_keys = Vec::new();
        for l in lists {
            reset_keys.extend(&l.revoked);
            reset_keys.extend(l.signers.iter().filter(|(_, e)| *e < epoch).map(|(k, _)| k));
        }
        Floor { epoch, reset_keys }
    }
}

/// Read every registrar the identity is registered at, raise the kept
/// floor to what they hold, and post the current record again to each
/// whose list lacks it (§6.2). Failures are told, never fatal: a holder
/// offline mints at the floor it last learned.
///
/// The holder's lock is not held across the network, so a slow registrar
/// here never holds up a reset: the file is read, then written again
/// with the floor raised.
pub(crate) fn sync(a: &Args, id: &IdentityKey, tell: &mut dyn FnMut(&str)) -> R<Floor> {
    let (known, kept) = {
        let holder = Holder::load(&id.public())?;
        (known(a, &holder, &id.public()), holder.epoch())
    };
    let (read, unread) = read_all(&known, &id.public());
    for why in unread {
        tell(&format!("Could not read the records at {why}"));
    }
    let floor = Floor::of(kept, &read.iter().map(|(_, l)| l).collect::<Vec<_>>());
    let mut holder = Holder::load(&id.public())?;
    if floor.epoch > holder.epoch() {
        holder.raise(floor.epoch);
        holder.save()?;
    }
    drop(holder);
    for (reg, l) in &read {
        if floor.epoch == 0 || l.current.epoch >= floor.epoch {
            continue;
        }
        // A reset run meanwhile has moved past this floor and posts its
        // own: one this lower would be stale.
        if Holder::load(&id.public())?.epoch() > floor.epoch {
            break;
        }
        // A post that brings a registrar to a reset in progress is that
        // reset's own, so it is journaled with it, before it is sent: a
        // rerun then knows the record for this holder's.
        let mut posts = Reset {
            target: floor.epoch,
            hashes: Vec::new(),
        };
        let outcome = drive(
            floor.epoch,
            false,
            l.current,
            &mut posts,
            id,
            &mut |bytes| post(reg, bytes),
            &mut |r| {
                let mut holder = Holder::load(&id.public())?;
                match holder.reset() {
                    Some(mut pending) if pending.target == r.target => {
                        for h in &r.hashes {
                            if !pending.hashes.contains(h) {
                                pending.hashes.push(*h);
                            }
                        }
                        holder.set_reset(Some(&pending));
                        holder.save()
                    }
                    _ => Ok(()),
                }
            },
        )?;
        match outcome {
            Outcome::NotDone(why) => tell(&format!(
                "{} lacks the device epoch {}: {why}",
                reg.base, floor.epoch
            )),
            Outcome::Done => tell(&format!(
                "posted the device epoch {} to {}",
                floor.epoch, reg.base
            )),
            Outcome::Again(_) => tell(&format!(
                "{} answered with a device epoch below {} that this holder did not post, \
                 and still lacks {}",
                reg.base, floor.epoch, floor.epoch
            )),
        }
    }
    Ok(floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registrar deciding device epochs as §6.2 does.
    struct Desk {
        cur: Option<(u64, u64, [u8; 32])>,
        /// Posts whose reply is lost after they land.
        lose: usize,
        posted: Vec<u64>,
        refuse: Option<String>,
    }

    impl Desk {
        fn at(epoch: u64, time: u64) -> Desk {
            Desk {
                cur: (epoch > 0).then_some((epoch, time, [0xaa; 32])),
                lose: 0,
                posted: Vec::new(),
                refuse: None,
            }
        }

        fn post(&mut self, bytes: &[u8]) -> Answer {
            if let Some(why) = &self.refuse {
                return Answer::Refused(why.clone());
            }
            let r = DeviceEpoch::parse(bytes).unwrap();
            let (cur, cur_time, _) = self.cur.unwrap_or((0, 0, [0; 32]));
            if r.epoch > cur {
                assert!(r.epoch <= cur + STEP_MAX, "past the step bound");
                assert!(r.time >= cur_time, "dated before the last one");
                self.cur = Some((r.epoch, r.time, Sha256::digest(bytes).into()));
                self.posted.push(r.epoch);
            }
            if self.lose > 0 {
                self.lose -= 1;
                return Answer::Lost("no reply".into());
            }
            let (epoch, _, hash) = self.cur.unwrap();
            Answer::At { epoch, hash }
        }

        fn current(&self) -> Current {
            self.cur
                .map_or(Current::default(), |(epoch, time, hash)| Current {
                    epoch,
                    time,
                    hash: Some(hash),
                })
        }
    }

    fn run(desk: &mut Desk, target: u64, reset: &mut Reset) -> Outcome {
        let id = IdentityKey::from_seed(&[1; 32]);
        drive(
            target,
            true,
            desk.current(),
            reset,
            &id,
            &mut |b| desk.post(b),
            &mut |_| Ok(()),
        )
        .unwrap()
    }

    #[test]
    fn a_registrar_far_behind_is_caught_up_sixteen_at_a_time_and_dated_after_its_last() {
        let later = now() + 1_000;
        let mut desk = Desk::at(3, later);
        let mut reset = Reset::default();
        assert_eq!(run(&mut desk, 40, &mut reset), Outcome::Done);
        assert_eq!(desk.posted, vec![19, 35, 40]);
        assert_eq!(reset.hashes.len(), 3);
    }

    #[test]
    fn a_lost_reply_is_retried_and_known_by_its_hash() {
        let mut desk = Desk::at(0, 0);
        desk.lose = 1;
        let mut reset = Reset::default();
        assert_eq!(run(&mut desk, 1, &mut reset), Outcome::Done);
        assert_eq!(desk.posted, vec![1]);
        let mut desk = Desk::at(0, 0);
        desk.lose = TRIES;
        assert!(matches!(
            run(&mut desk, 1, &mut Reset::default()),
            Outcome::NotDone(_)
        ));
    }

    #[test]
    fn another_holders_record_at_or_past_the_target_means_resetting_again() {
        // Another holder's reset to the same epoch first.
        let mut desk = Desk::at(4, 0);
        let mut reset = Reset::default();
        assert_eq!(run(&mut desk, 4, &mut reset), Outcome::Again(4));
        // And past it.
        let mut desk = Desk::at(9, 0);
        assert_eq!(run(&mut desk, 5, &mut reset), Outcome::Again(9));
        assert!(desk.posted.is_empty());
    }

    #[test]
    fn an_answer_below_what_was_posted_is_not_done_and_not_posted_to_again() {
        let id = IdentityKey::from_seed(&[1; 32]);
        let mut first = None;
        let mut posts = 0;
        let outcome = drive(
            40,
            true,
            Current::default(),
            &mut Reset::default(),
            &id,
            &mut |b| {
                posts += 1;
                let hash = *first.get_or_insert(Sha256::digest(b).into());
                Answer::At { epoch: 3, hash }
            },
            &mut |_| Ok(()),
        )
        .unwrap();
        assert!(matches!(outcome, Outcome::NotDone(_)), "{outcome:?}");
        assert_eq!(posts, 1);
    }

    #[test]
    fn registrars_taking_turns_at_another_holders_resets_hold_up_none_of_the_rest() {
        let bases = ["a", "b", "c"];
        let mut causes = Vec::new();
        let mut c_posted = false;
        for _ in 0..8 {
            let r = round(&bases, &mut causes, &mut |i| {
                Ok(match i {
                    2 => {
                        c_posted = true;
                        Outcome::Done
                    }
                    _ => Outcome::Again(1),
                })
            })
            .unwrap();
            assert_eq!(r.again, Some(1));
        }
        assert!(c_posted);
    }

    #[test]
    fn spellings_of_one_registrar_are_one_target() {
        for (a, b) in [
            ("https://R.example:443/", "r.example"),
            ("http://r.example:80", "http://r.example"),
            ("HTTP://127.0.0.1:8080/", "http://127.0.0.1:8080"),
        ] {
            assert_eq!(base_of(a), base_of(b), "{a} and {b}");
        }
        assert_ne!(base_of("https://r.example:8443"), base_of("r.example"));
    }

    #[test]
    fn a_refusal_is_not_done_and_says_why() {
        let mut desk = Desk::at(0, 0);
        desk.refuse = Some("refused (429 rate_limited): ; try again in 60 seconds".into());
        assert_eq!(
            run(&mut desk, 1, &mut Reset::default()),
            Outcome::NotDone("refused (429 rate_limited): ; try again in 60 seconds".into())
        );
    }

    #[test]
    fn a_reset_in_progress_is_finished_unless_another_holder_passed_it() {
        let mine = [1; 32];
        let pending = Reset {
            target: 5,
            hashes: vec![mine],
        };
        let at = |epoch, hash| Current {
            epoch,
            time: 0,
            hash: Some(hash),
        };
        assert_eq!(target(0, 0, None, &[at(3, [9; 32]), Current::default()]), 4);
        assert_eq!(target(7, 0, None, &[at(3, [9; 32])]), 8);
        let part = [at(5, mine), at(2, [9; 32])];
        assert_eq!(target(5, 4, Some(&pending), &part), 5);
        assert_eq!(target(5, 0, Some(&pending), &[at(5, [9; 32])]), 6);
        assert_eq!(target(0, 0, Some(&pending), &[at(6, [9; 32])]), 7);
        // A device minted at the target since leaves it not worth finishing.
        assert_eq!(target(5, 5, Some(&pending), &part), 6);
    }

    #[test]
    fn a_key_a_reset_signed_out_is_known_from_the_lists() {
        let (old, new, revoked) = ([1; 32], [2; 32], [3; 32]);
        let a = Listed {
            current: Current {
                epoch: 2,
                ..Current::default()
            },
            revoked: vec![revoked],
            signers: vec![(old, 1), (new, 2)],
        };
        let floor = Floor::of(0, &[&a, &Listed::default()]);
        assert_eq!(floor.epoch, 2);
        assert_eq!(floor.reset_keys, vec![revoked, old]);
        assert_eq!(Floor::of(5, &[&a]).epoch, 5);
    }
}
