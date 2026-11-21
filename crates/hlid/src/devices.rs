//! Device epochs from the holder's side (`docs/identity-registrar.md`
//! §4.10 and §6.2, `docs/identity-enrollment.md` §8): `hlid devices
//! reset`, and the epoch certificates are minted at.
//!
//! A reset keeps nothing about itself between runs. Each run reads every
//! registrar's per-identity list, resets one past the highest epoch any
//! verified list shows or this holder has learned, and is done at a
//! registrar once its answer is at that epoch and names a record this run
//! posted. A run cut short is not finished by the next one: the next one
//! resets once more, an epoch further. `holder.json` keeps the highest
//! floor learned and the registrars the identity is registered at,
//! nothing else.

use std::path::PathBuf;
use std::time::Duration;

use hl_identity::{
    Card, DeviceCert, DeviceEpoch, DeviceKey, Fingerprint, IdentityKey, ListKind, PublicKey,
    Record, RegistrarKeys, SignedList,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::registrar::{base_of, discover_at, identity, Registrar};
use crate::{b64, now, parse, refuse_unreadable, unb64, Args, CARD_FILE, CERT_FILE, R};

/// How far one published device epoch may move a registrar's floor
/// (§6.2 step 5).
const STEP_MAX: u64 = 16;

/// Posts whose reply was lost before a registrar is reported not done.
const TRIES: usize = 3;

/// Posts to one registrar for one target, at most. Its daily limit stops
/// a catch-up long before this; the bound is for one that never says so.
const POSTS_MAX: usize = 64;

/// Times the lists are read in one run: a re-read follows an answer
/// above what was posted, and another holder resetting each time is
/// given up on rather than chased.
const ROUNDS: usize = 5;

/// Pages of one per-identity list read, at most.
const LIST_PAGES: usize = 16;

/// A record post's reply, read at most.
const REPLY_MAX: u64 = 64 * 1024;

const HOLDER_FILE: &str = "holder.json";

/// Beside it: whoever holds a lock on this has the file to itself.
const LOCK_FILE: &str = "holder.lock";

const NO_HOME: &str = "neither $HLID_HOME nor $HOME is set, so there is nowhere to keep the \
                       device epoch; set one";

// --- What this holder keeps ----------------------------------------------

/// `holder.json`, per identity fingerprint: `epoch`, the highest floor
/// learned, and `registrars`, each `[url, host]`, where it is registered.
///
/// A `Holder` holds an exclusive lock on `holder.lock` from [`open`]
/// until it is dropped, so a mint reading the floor and a reset raising
/// it are ordered, and no two processes write the file over each other.
/// Never open a second while one is held: the lock is per open file, so
/// it would wait on itself. Off Unix there is no lock.
///
/// [`open`]: Holder::open
pub(crate) struct Holder {
    path: PathBuf,
    doc: Value,
    fp: String,
    _lock: std::fs::File,
}

impl Holder {
    /// `None` when there is no `$HLID_HOME` or `$HOME`, or with `make`
    /// unset, no such directory. With it, the directory is made if it is
    /// not there, so the file is locked from the first.
    pub(crate) fn open(identity: &PublicKey, make: bool) -> R<Option<Holder>> {
        let Ok(home) = crate::hlid_home() else {
            return Ok(None);
        };
        if !make && !home.is_dir() {
            return Ok(None);
        }
        crate::create_private_dir(&home)?;
        let lock = lock(&home.join(LOCK_FILE))?;
        let path = home.join(HOLDER_FILE);
        let failed = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
        let doc: Value = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| failed(&e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
            Err(e) => return Err(failed(&e)),
        };
        if !doc.is_object() {
            return Err(failed(&"not a JSON object"));
        }
        Ok(Some(Holder {
            doc,
            fp: Fingerprint::of(identity).to_string(),
            path,
            _lock: lock,
        }))
    }

    fn entry_mut(&mut self) -> &mut Value {
        if !self.doc[&self.fp].is_object() {
            self.doc[&self.fp] = json!({});
        }
        &mut self.doc[&self.fp]
    }

    /// The highest floor this holder knows for the identity.
    pub(crate) fn floor(&self) -> u64 {
        self.doc[&self.fp]["epoch"].as_u64().unwrap_or(0)
    }

    /// Floors only rise.
    pub(crate) fn raise(&mut self, epoch: u64) -> R<()> {
        if epoch <= self.floor() {
            return Ok(());
        }
        self.entry_mut()["epoch"] = json!(epoch);
        self.save()
    }

    pub(crate) fn registrars(&self) -> Vec<(String, String)> {
        self.doc[&self.fp]["registrars"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| Some((r[0].as_str()?.to_owned(), r[1].as_str()?.to_owned())))
            .collect()
    }

    pub(crate) fn add_registrar(&mut self, url: &str, host: &str) -> R<()> {
        let kept = (url.to_owned(), host.to_owned());
        let mut all = self.registrars();
        if all.contains(&kept) {
            return Ok(());
        }
        // A registrar named again under another host is where the
        // identity is registered now, and is not forgotten.
        all.retain(|(u, _)| *u != kept.0);
        all.push(kept);
        let mut forgotten = self.forgotten();
        forgotten.retain(|(u, _)| *u != url);
        let e = self.entry_mut();
        e["registrars"] = json!(all);
        e["forgotten"] = json!(forgotten);
        self.save()
    }

    /// The registrars `--forget` dropped, each `[url, host]`, the host the
    /// one it was registered at named, if it was: a card's attestation of
    /// either is left out too.
    pub(crate) fn forgotten(&self) -> Vec<(String, Option<String>)> {
        self.doc[&self.fp]["forgotten"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| Some((r[0].as_str()?.to_owned(), r[1].as_str().map(str::to_owned))))
            .collect()
    }

    pub(crate) fn forget(&mut self, url: &str) -> R<()> {
        let mut all = self.registrars();
        let host = all
            .iter()
            .find(|(u, _)| base_of(u) == url)
            .map(|(_, h)| h.clone());
        all.retain(|(u, _)| base_of(u) != url);
        let mut forgotten = self.forgotten();
        if forgotten.iter().any(|(u, _)| u == url) && host.is_none() {
            return Ok(());
        }
        forgotten.retain(|(u, _)| u != url);
        forgotten.push((url.to_owned(), host));
        let e = self.entry_mut();
        e["registrars"] = json!(all);
        e["forgotten"] = json!(forgotten);
        self.save()
    }

    fn save(&self) -> R<()> {
        let text = serde_json::to_vec_pretty(&self.doc).map_err(|e| e.to_string())?;
        hl_private_file::replace(&self.path, &text)
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

/// Take `path`'s lock, saying so when this waits for whoever has it.
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

// --- Where a reset goes ---------------------------------------------------

/// A registrar to reset at, and the host its discovery must name when
/// one is expected: the one it named when registered at, or an
/// attestation's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) base: String,
    pub(crate) host: Option<String>,
}

/// Every registrar the identity is registered at (`kept`), the host of
/// each attestation its card carries that none of those is, and each
/// `--registrar`, spelled one way and each once. A target named twice
/// keeps the host either expects. An attestation of a registrar
/// `forgotten`, by its URL or by the host it named, is left out; one
/// named with `--registrar` is not.
pub(crate) fn targets(
    kept: &[(String, String)],
    attested: &[String],
    named: &[&str],
    forgotten: &[(String, Option<String>)],
) -> Vec<Target> {
    let mut out: Vec<Target> = Vec::new();
    let mut add = |base: &str, host: Option<&str>| {
        let base = base_of(base);
        match out.iter_mut().find(|t| t.base == base) {
            Some(t) => {
                if t.host.is_none() {
                    t.host = host.map(str::to_owned);
                }
            }
            None => out.push(Target {
                base,
                host: host.map(str::to_owned),
            }),
        }
    };
    for (url, host) in kept {
        add(url, Some(host));
    }
    let gone = |host: &String| {
        forgotten
            .iter()
            .any(|(u, h)| h.as_ref() == Some(host) || *u == base_of(host))
    };
    for host in attested {
        if !kept.iter().any(|(_, h)| h == host) && !gone(host) {
            add(host, Some(host));
        }
    }
    for url in named {
        add(url, None);
    }
    out
}

// --- One registrar --------------------------------------------------------

/// A registrar's current device epoch record for the identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Current {
    /// 0 for none.
    pub(crate) epoch: u64,
    pub(crate) time: u64,
    pub(crate) hash: Option<[u8; 32]>,
}

/// What a reset needs of a registrar.
pub(crate) trait Desk {
    /// The host its discovery names.
    fn discover(&mut self) -> R<String>;
    /// Its per-identity list read past any cache, verified against its
    /// keys, reduced to the current device epoch record.
    fn read(&mut self) -> R<Current>;
    /// Post a record: the status and JSON body, or why there was none.
    fn post(&mut self, record: &[u8]) -> Result<(u16, Value), String>;
    /// Before a post whose reply was lost is tried again.
    fn pause(&self) {}
}

/// A registrar over HTTP, reached at its base URL.
struct Remote {
    base: String,
    identity: PublicKey,
    reg: Option<Registrar>,
}

impl Remote {
    fn reg(&self) -> R<&Registrar> {
        self.reg.as_ref().ok_or_else(|| "not discovered".into())
    }
}

impl Desk for Remote {
    fn discover(&mut self) -> R<String> {
        let reg = discover_at(&self.base)?;
        let host = reg.host.clone();
        self.reg = Some(reg);
        Ok(host)
    }

    fn read(&mut self) -> R<Current> {
        let reg = self.reg()?;
        let fp = Fingerprint::of(&self.identity);
        let keys = reg.keys();
        let rk = RegistrarKeys {
            host: &reg.host,
            keys: &keys,
        };
        let mut current = Current::default();
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
            for (_, bytes) in &list.entries {
                if let Ok(Record::DeviceEpoch(r)) = Record::parse(bytes, Some(rk)) {
                    if r.identity == self.identity && r.epoch >= current.epoch {
                        current = Current {
                            epoch: r.epoch,
                            time: r.time,
                            hash: Some(Sha256::digest(bytes).into()),
                        };
                    }
                }
            }
            if !list.more {
                return Ok(current);
            }
            // `parse` holds every seq past `since`, and a page with
            // `more` has an entry, so each page moves on.
            since = list.entries.last().map(|(seq, _)| *seq);
        }
        Err(format!(
            "{}/{fp}: more than {LIST_PAGES} pages of records",
            reg.records
        ))
    }

    fn post(&mut self, record: &[u8]) -> Result<(u16, Value), String> {
        let url = self.reg()?.records.clone();
        let read = |resp: ureq::Response| -> Result<Value, String> {
            let mut body = Vec::new();
            std::io::Read::read_to_end(
                &mut std::io::Read::take(resp.into_reader(), REPLY_MAX),
                &mut body,
            )
            .map_err(|e| format!("{url}: {e}"))?;
            serde_json::from_slice(&body).map_err(|e| format!("{url}: {e}"))
        };
        match crate::registrar::agent()
            .post(&url)
            .send_json(json!({ "record": b64(record) }))
        {
            Ok(resp) => Ok((200, read(resp)?)),
            Err(ureq::Error::Status(code, resp)) => Ok((code, read(resp).unwrap_or(Value::Null))),
            Err(e) => Err(format!("{url}: {e}")),
        }
    }

    fn pause(&self) {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// A registrar's reply to a device epoch.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// Where the identity stands there: the current record's `epoch` and
    /// hash. Unsigned, so it is believed only as far as a list bears out.
    At {
        epoch: u64,
        hash: [u8; 32],
    },
    /// No reply, or a failure on the registrar's side.
    Lost(String),
    Refused(String),
}

fn answer(base: &str, reply: Result<(u16, Value), String>) -> Answer {
    let (code, body) = match reply {
        Ok(r) => r,
        Err(e) => return Answer::Lost(e),
    };
    if code == 200 {
        let hash = body["hash"]
            .as_str()
            .and_then(|h| unb64(h).ok()?.try_into().ok());
        return match (body["epoch"].as_u64(), hash) {
            (Some(epoch), Some(hash)) => Answer::At { epoch, hash },
            _ => Answer::Refused(format!(
                "it does not take device epochs (it answered {body})"
            )),
        };
    }
    if body["error"] == "not_registered" {
        return Answer::Refused(format!(
            "the identity is not registered there; drop it with --forget {base}"
        ));
    }
    let mut why = format!(
        "refused ({code} {}): {}",
        body["error"].as_str().unwrap_or("?"),
        body["text"].as_str().unwrap_or("")
    );
    if let Some(after) = body["retry_after"].as_u64() {
        why.push_str(&format!("; try again in {after} seconds"));
    }
    match code >= 500 {
        true => Answer::Lost(why),
        false => Answer::Refused(why),
    }
}

/// What bringing one registrar to a target came to.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// It answered at the target with a record this run posted, which its
    /// list must bear out before it is done.
    Answered,
    NotDone(String),
    /// It answered above what was posted, or at it with a record this run
    /// did not post: another holder's reset, if its list bears it out.
    Claimed(u64),
}

/// Bring a registrar whose current record is `cur` to `target`, `cur +
/// 16` at a time, each post signed afresh at the later of now and the
/// registrar's current record's `time`, its hash kept in `posted` before
/// it is sent.
fn drive(
    base: &str,
    target: u64,
    mut cur: Current,
    id: &IdentityKey,
    posted: &mut Vec<[u8; 32]>,
    desk: &mut dyn Desk,
) -> R<Step> {
    let mut lost = 0;
    for _ in 0..POSTS_MAX {
        let epoch = target.min(cur.epoch.saturating_add(STEP_MAX));
        let time = now().max(cur.time);
        let bytes = DeviceEpoch {
            identity: id.public(),
            epoch,
            time,
        }
        .sign(id)
        .map_err(|e| refuse_unreadable("device epoch", e))?;
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        if !posted.contains(&hash) {
            posted.push(hash);
        }
        match answer(base, desk.post(&bytes)) {
            Answer::At { epoch: e, hash: h } => {
                lost = 0;
                if e < epoch {
                    return Ok(Step::NotDone(format!(
                        "it answered epoch {e} to a post of {epoch}"
                    )));
                }
                if e > epoch || !posted.contains(&h) {
                    return Ok(Step::Claimed(e));
                }
                if e == target {
                    return Ok(Step::Answered);
                }
                cur = Current {
                    epoch: e,
                    time,
                    hash: Some(h),
                };
            }
            Answer::Lost(why) => {
                lost += 1;
                if lost >= TRIES {
                    return Ok(Step::NotDone(why));
                }
                desk.pause();
            }
            Answer::Refused(why) => return Ok(Step::NotDone(why)),
        }
    }
    Ok(Step::NotDone(format!(
        "{POSTS_MAX} posts did not bring it to epoch {target}"
    )))
}

// --- A reset at every registrar ---------------------------------------------

enum State {
    Open,
    /// Answered at the target; to be read again.
    Answered,
    Done,
    Out(String),
}

struct Slot<'a> {
    base: String,
    desk: &'a mut dyn Desk,
    state: State,
    cur: Current,
    /// What it answered in the last round that its list must bear out.
    claim: Option<u64>,
}

/// What a reset came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) target: u64,
    pub(crate) done: Vec<String>,
    /// Each with why.
    pub(crate) not_done: Vec<String>,
}

/// Reset at every one of `desks`, from the floor this holder knows.
/// `raise` keeps a floor learned: from the lists as they are read, and
/// the target before anything is posted for it. With no list read there
/// is no reset, and nothing raised. A registrar is done only once a read
/// of its list shows the target with a record this run posted: answers
/// are not signed.
pub(crate) fn reset_all(
    id: &IdentityKey,
    floor: u64,
    desks: Vec<(Target, &mut dyn Desk)>,
    raise: &mut dyn FnMut(u64) -> R<()>,
    tell: &mut dyn FnMut(&str),
) -> R<Report> {
    let mut slots: Vec<Slot> = desks
        .into_iter()
        .map(|(t, desk)| {
            let state = match desk.discover() {
                Ok(named) => match t.host {
                    Some(h) if h != named => State::Out(format!(
                        "it names itself {named}, where the identity is registered at {h}"
                    )),
                    _ => State::Open,
                },
                Err(e) => State::Out(e),
            };
            Slot {
                base: t.base,
                desk,
                state,
                cur: Current::default(),
                claim: None,
            }
        })
        .collect();
    let mut posted: Vec<[u8; 32]> = Vec::new();
    let ours = |c: &Current, posted: &[[u8; 32]]| c.hash.is_some_and(|h| posted.contains(&h));
    let mut known = floor;
    let mut target = 0;
    // The target last posted, which a re-target in the last round passed.
    let mut posted_at = None;
    for round in 0..ROUNDS {
        let mut read = Vec::new();
        for (i, s) in slots.iter_mut().enumerate() {
            if matches!(s.state, State::Out(_)) {
                continue;
            }
            match s.desk.read() {
                Ok(c) => {
                    s.cur = c;
                    read.push(i);
                }
                Err(e) => s.state = State::Out(format!("its list could not be read: {e}")),
            }
        }
        if round == 0 && read.is_empty() {
            let why: Vec<String> = slots
                .iter()
                .filter_map(|s| match &s.state {
                    State::Out(why) => Some(format!("{}: {why}", s.base)),
                    _ => None,
                })
                .collect();
            return Err(format!(
                "no registrar could be reached, so nothing was reset: a reset no server can \
                 fetch signs nothing out ({})",
                why.join("; ")
            ));
        }
        let listed = read.iter().map(|&i| slots[i].cur.epoch).max().unwrap_or(0);
        known = known.max(listed);
        raise(known)?;

        // An answer is not signed: one its list does not bear out is
        // reported, and not chased.
        for s in &mut slots {
            let landed = s.cur.epoch == target && ours(&s.cur, &posted);
            match (&s.state, landed) {
                (State::Open | State::Answered, true) => s.state = State::Done,
                // Read again and no longer there, as after a restore.
                (State::Done, false) => s.state = State::Open,
                _ => {}
            }
            let claim = match (s.claim.take(), &s.state) {
                (Some(claim), State::Open) => claim,
                (_, State::Answered) => target,
                _ => continue,
            };
            if s.cur.epoch < claim {
                s.state = State::Out(format!(
                    "it answered epoch {claim}, and its list shows {}",
                    s.cur.epoch
                ));
            } else {
                s.state = State::Open;
            }
        }
        // Another holder at or past the target leaves the devices it
        // minted there signed in, so the reset goes past it everywhere.
        let stale = round == 0
            || read.iter().any(|&i| {
                let c = &slots[i].cur;
                c.epoch > target || (c.epoch == target && !ours(c, &posted))
            });
        if stale {
            if round > 0 {
                tell("another holder reset meanwhile; resetting past it");
            }
            target = known
                .checked_add(1)
                .filter(|t| *t <= hl_identity::cert::EPOCH_MAX)
                .ok_or("the identity has no epoch left to reset to; rotate it instead")?;
            known = target;
            raise(target)?;
            for s in &mut slots {
                if matches!(s.state, State::Done) {
                    s.state = State::Open;
                }
            }
        }
        // The last round only reads, so every answer is read back.
        if round + 1 == ROUNDS || !slots.iter().any(|s| matches!(s.state, State::Open)) {
            break;
        }
        posted_at = Some(target);
        for s in &mut slots {
            if !matches!(s.state, State::Open) {
                continue;
            }
            match drive(&s.base, target, s.cur, id, &mut posted, &mut *s.desk)? {
                Step::Answered => s.state = State::Answered,
                Step::NotDone(why) => s.state = State::Out(why),
                Step::Claimed(e) => {
                    s.claim = Some(e);
                    // The target is stale for everyone; the rest's daily
                    // resets are not spent on it.
                    if e >= target {
                        break;
                    }
                }
            }
        }
    }
    let mut report = Report {
        target: posted_at.unwrap_or(target),
        done: Vec::new(),
        not_done: Vec::new(),
    };
    for s in slots {
        match s.state {
            State::Done => report.done.push(s.base),
            State::Out(why) => report.not_done.push(format!("{}: {why}", s.base)),
            State::Open | State::Answered => report.not_done.push(format!(
                "{}: another holder reset past epoch {} meanwhile; run it again",
                s.base, report.target
            )),
        }
    }
    Ok(report)
}

// --- hlid devices reset ----------------------------------------------------

pub(crate) fn devices_cmd(args: &[String]) -> R<()> {
    match args.first().map(String::as_str) {
        Some("reset") => reset_cmd(&args[1..]),
        _ => crate::usage(),
    }
}

fn holder(identity: &PublicKey) -> R<Holder> {
    Holder::open(identity, true)?.ok_or_else(|| NO_HOME.to_string())
}

/// The registrars the identity's card attests it at. A card named with
/// `--card` must be the identity's; with none read, a reset may miss a
/// registrar this holder never registered at, so it says so.
fn attested(a: &Args, id: &PublicKey) -> R<Vec<String>> {
    let read = a.file_opt("card", CARD_FILE).map(|p| {
        std::fs::read(&p)
            .map_err(|e| e.to_string())
            .and_then(|b| Card::parse(&b).map_err(|e| e.to_string()))
            .and_then(|c| match c.identity == *id {
                true => Ok(c),
                false => Err("it is another identity's card".into()),
            })
            .map_err(|e| format!("{}: {e}", p.display()))
    });
    match read {
        Some(Ok(card)) => Ok(card
            .attestations
            .iter()
            .map(|t| t.registrar.clone())
            .collect()),
        Some(Err(e)) if a.has("card") => Err(e),
        other => {
            let why = match other {
                Some(Err(e)) => e,
                _ => format!("there is no {CARD_FILE}"),
            };
            eprintln!(
                "hlid: no card was read ({why}), so this resets only at the registrars \
                 `hlid register` kept and those named with --registrar; a registrar the \
                 card attests the identity at and not among them is left as it was"
            );
            Ok(Vec::new())
        }
    }
}

/// `hlid devices reset [--registrar HOST|URL]... [--forget URL]...`: sign
/// out every device the identity certified, at every registrar it is
/// registered at (§6.2, "A holder's reset"). The holder's lock is taken
/// to read and to raise the floor, never across the network.
fn reset_cmd(args: &[String]) -> R<()> {
    let a = parse(args);
    let id = identity(&a)?;
    let attested = attested(&a, &id.public())?;
    let (floor, kept, forgotten) = {
        let mut h = holder(&id.public())?;
        for url in a.many("forget") {
            h.forget(&base_of(url))?;
        }
        (h.floor(), h.registrars(), h.forgotten())
    };
    let targets = targets(&kept, &attested, &a.many("registrar"), &forgotten);
    if targets.is_empty() {
        return Err(
            "the identity is registered at no registrar this holder knows of; \
                    name one with --registrar"
                .into(),
        );
    }
    let mut remotes: Vec<Remote> = targets
        .iter()
        .map(|t| Remote {
            base: t.base.clone(),
            identity: id.public(),
            reg: None,
        })
        .collect();
    let desks = targets
        .into_iter()
        .zip(remotes.iter_mut().map(|r| r as &mut dyn Desk))
        .collect();
    let report = reset_all(
        &id,
        floor,
        desks,
        &mut |epoch| holder(&id.public())?.raise(epoch),
        &mut |line| eprintln!("hlid: {line}"),
    )?;
    for base in &report.done {
        println!("epoch {} published at {base}", report.target);
    }
    let renewed = match report.done.is_empty() {
        true => Ok(()),
        false => renew_own(&a, &id),
    };
    if report.not_done.is_empty() {
        println!(
            "{} {} epoch {}, and servers that enforce device epochs refuse certificates below \
             it. Enroll each device you still use again, with a new device key",
            report.done.join(", "),
            match report.done.len() {
                1 => "publishes",
                _ => "publish",
            },
            report.target
        );
        return renewed.map_err(|e| format!("the reset is done, but {e}"));
    }
    if let Err(e) = renewed {
        eprintln!("hlid: {e}");
    }
    Err(format!(
        "the reset to epoch {} is not done at {}. Running `hlid devices reset` again resets \
         once more",
        report.target,
        report.not_done.join("; ")
    ))
}

/// This machine's own certificate again at the floor, with the same key,
/// caps, name and lifetime: the reset is not about the machine holding
/// the identity key. Only this machine's: a certificate of another
/// device renewed with its key would undo the reset for that key
/// (enrollment §8). Nothing to renew is not a failure; a renewal that
/// could not be made is.
fn renew_own(a: &Args, id: &IdentityKey) -> R<()> {
    let Some(path) = a.file_opt("cert", CERT_FILE) else {
        return Ok(());
    };
    let failed = |e: &dyn std::fmt::Display| format!("{} was not renewed: {e}", path.display());
    let old = std::fs::read(&path)
        .map_err(|e| failed(&e))
        .and_then(|b| DeviceCert::parse(&b).map_err(|e| failed(&e)))?;
    if old.identity != id.public() {
        return Ok(());
    }
    let own = a
        .file_opt("device", crate::DEVICE_KEY)
        .map(|p| crate::read_seed(&p).map(|seed| DeviceKey::from_seed(&seed).public()))
        .transpose()?;
    let Some(own) = own else {
        println!(
            "no device key was found, so {} is not renewed",
            path.display()
        );
        return Ok(());
    };
    if own != old.device {
        println!(
            "{} is not this machine's device's certificate, so it is not renewed: enroll that \
             device again with a new key",
            path.display()
        );
        return Ok(());
    }
    // Read under the lock, as every mint is.
    let holder = holder(&id.public())?;
    if old.epoch >= holder.floor() {
        return Ok(());
    }
    let mut c = DeviceCert::for_keys(
        id,
        old.device,
        old.device_enc,
        now(),
        old.expires.saturating_sub(old.issued),
    )
    .map_err(|e| failed(&e))?;
    c.caps = old.caps;
    c.name = old.name.clone();
    c.epoch = holder.floor();
    let bytes = c.sign(id);
    DeviceCert::parse(&bytes).map_err(|e| failed(&refuse_unreadable("device certificate", e)))?;
    hl_private_file::replace(&path, &bytes).map_err(|e| failed(&e))?;
    println!("{} renewed at epoch {}", path.display(), c.epoch);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A registrar deciding device epochs as §6.2 does, with what can go
    /// wrong between it and a holder.
    #[derive(Default)]
    struct Sim {
        host: String,
        unreachable: bool,
        /// Published, in order: epoch, time, hash.
        held: Vec<(u64, u64, [u8; 32])>,
        /// Posts whose reply is lost after they land.
        lose: usize,
        /// Published just before the next post lands, as another
        /// holder's would be.
        race: Option<Vec<u8>>,
        /// Publishes nothing, and answers this.
        lie: Option<u64>,
        /// Publications it takes before it answers `rate_limited`.
        allowance: Option<usize>,
        /// Publishes nothing, and answers each post as if it had.
        pretend: bool,
        /// Answers one below what it publishes, naming the record posted.
        below: bool,
        /// Answers `not_registered`.
        unregistered: bool,
        /// Drops its latest record at this read, as a restore would.
        rollback_at: Option<usize>,
        reads: usize,
        posts: usize,
    }

    impl Sim {
        fn named(host: &str) -> Sim {
            Sim {
                host: host.into(),
                ..Sim::default()
            }
        }

        fn epochs(&self) -> Vec<u64> {
            self.held.iter().map(|(e, _, _)| *e).collect()
        }

        fn cur(&self) -> (u64, u64, [u8; 32]) {
            self.held.last().copied().unwrap_or((0, 0, [0; 32]))
        }

        fn land(&mut self, bytes: &[u8]) -> Result<(), (u16, Value)> {
            let r = DeviceEpoch::parse(bytes).unwrap();
            let (cur, cur_time, _) = self.cur();
            if r.epoch <= cur {
                return Ok(());
            }
            assert!(r.epoch <= cur + STEP_MAX, "past the step bound");
            assert!(r.time >= cur_time, "dated before the last one");
            if self.allowance == Some(0) {
                return Err((
                    429,
                    json!({ "error": "rate_limited", "text": "too many requests; try again later",
                            "retry_after": 3600 }),
                ));
            }
            if let Some(n) = &mut self.allowance {
                *n -= 1;
            }
            self.held
                .push((r.epoch, r.time, Sha256::digest(bytes).into()));
            Ok(())
        }
    }

    impl Desk for Sim {
        fn discover(&mut self) -> R<String> {
            match self.unreachable {
                true => Err("connection refused".into()),
                false => Ok(self.host.clone()),
            }
        }

        fn read(&mut self) -> R<Current> {
            self.reads += 1;
            if self.rollback_at == Some(self.reads) {
                self.held.pop();
            }
            Ok(self
                .held
                .last()
                .map_or(Current::default(), |&(epoch, time, hash)| Current {
                    epoch,
                    time,
                    hash: Some(hash),
                }))
        }

        fn post(&mut self, record: &[u8]) -> Result<(u16, Value), String> {
            self.posts += 1;
            if let Some(epoch) = self.lie {
                return Ok((
                    200,
                    json!({ "seq": 1, "epoch": epoch, "hash": b64(&[7; 32]) }),
                ));
            }
            let hash = b64(&Sha256::digest(record));
            let epoch = DeviceEpoch::parse(record).unwrap().epoch;
            if self.pretend {
                return Ok((200, json!({ "seq": 1, "epoch": epoch, "hash": hash })));
            }
            if self.unregistered {
                let body = json!({ "error": "not_registered", "text": "not registered here" });
                return Ok((404, body));
            }
            if let Some(theirs) = self.race.take() {
                self.land(&theirs).unwrap();
            }
            if let Err(refusal) = self.land(record) {
                return Ok(refusal);
            }
            if self.lose > 0 {
                self.lose -= 1;
                return Err("connection reset".into());
            }
            if self.below {
                return Ok((200, json!({ "seq": 1, "epoch": epoch - 1, "hash": hash })));
            }
            let (epoch, _, hash) = self.cur();
            Ok((
                200,
                json!({ "seq": 1, "published": true, "epoch": epoch, "hash": b64(&hash) }),
            ))
        }
    }

    fn alice() -> IdentityKey {
        IdentityKey::from_seed(&[1; 32])
    }

    fn reset(floor: u64, sims: &mut [&mut Sim]) -> (R<Report>, u64) {
        let mut kept = floor;
        let desks = sims
            .iter_mut()
            .enumerate()
            .map(|(i, s)| {
                let t = Target {
                    base: format!("r{i}"),
                    host: Some(s.host.clone()),
                };
                (t, &mut **s as &mut dyn Desk)
            })
            .collect();
        let report = reset_all(
            &alice(),
            floor,
            desks,
            &mut |e| {
                kept = kept.max(e);
                Ok(())
            },
            &mut |_| {},
        );
        (report, kept)
    }

    fn signed(epoch: u64, time: u64) -> Vec<u8> {
        DeviceEpoch {
            identity: alice().public(),
            epoch,
            time,
        }
        .sign(&alice())
        .unwrap()
    }

    fn all_done(target: u64, n: usize) -> Report {
        Report {
            target,
            done: (0..n).map(|i| format!("r{i}")).collect(),
            not_done: vec![],
        }
    }

    #[test]
    fn a_registrar_far_behind_is_caught_up_sixteen_at_a_time_and_dated_after_its_last() {
        let later = now() + 1_000;
        let mut behind = Sim::named("a");
        behind.land(&signed(3, later)).unwrap();
        let mut ahead = Sim::named("b");
        ahead.held.push((39, 0, [9; 32]));
        let (report, kept) = reset(0, &mut [&mut behind, &mut ahead]);
        assert_eq!(report.unwrap(), all_done(40, 2));
        assert_eq!(behind.epochs(), vec![3, 19, 35, 40]);
        assert_eq!(ahead.epochs(), vec![39, 40]);
        assert_eq!(kept, 40);
    }

    #[test]
    fn a_lost_reply_is_posted_again_and_known_by_its_hash() {
        let mut sim = Sim::named("a");
        sim.lose = 1;
        let (report, _) = reset(0, &mut [&mut sim]);
        assert_eq!(report.unwrap(), all_done(1, 1));
        assert_eq!((sim.epochs(), sim.posts), (vec![1], 2));

        let mut sim = Sim::named("a");
        sim.lose = TRIES;
        let report = reset(0, &mut [&mut sim]).0.unwrap();
        assert_eq!(report.done, Vec::<String>::new());
        assert_eq!(report.not_done, vec!["r0: connection reset".to_string()]);
    }

    #[test]
    fn another_holders_record_at_or_past_the_target_is_reset_past_everywhere() {
        for theirs in [1, 5] {
            let mut a = Sim::named("a");
            let mut b = Sim::named("b");
            // Signed a little later than this holder signs, so the bytes
            // are not this holder's own.
            b.race = Some(signed(theirs, now() + 5));
            let (report, kept) = reset(0, &mut [&mut a, &mut b]);
            let target = theirs + 1;
            assert_eq!(report.unwrap(), all_done(target, 2), "theirs at {theirs}");
            assert_eq!(a.epochs(), vec![1, target]);
            assert_eq!(b.epochs(), vec![theirs, target]);
            assert_eq!(kept, target);
        }
    }

    #[test]
    fn a_registrar_claiming_more_than_its_list_shows_is_reported_and_spends_nothing() {
        let mut liar = Sim::named("a");
        liar.lie = Some(1_000_000);
        let mut honest = Sim::named("b");
        let (report, kept) = reset(0, &mut [&mut liar, &mut honest]);
        assert_eq!(
            report.unwrap(),
            Report {
                target: 1,
                done: vec!["r1".into()],
                not_done: vec!["r0: it answered epoch 1000000, and its list shows 0".into()],
            }
        );
        assert_eq!((honest.epochs(), honest.posts), (vec![1], 1));
        assert_eq!(liar.posts, 1);
        assert_eq!(kept, 1);
    }

    #[test]
    fn a_rate_limited_registrar_is_not_done_and_says_when_to_try_again() {
        let mut limited = Sim::named("a");
        limited.allowance = Some(0);
        let mut other = Sim::named("b");
        let report = reset(0, &mut [&mut limited, &mut other]).0.unwrap();
        assert_eq!(report.done, vec!["r1".to_string()]);
        assert_eq!(
            report.not_done,
            vec![
                "r0: refused (429 rate_limited): too many requests; try again later; \
                  try again in 3600 seconds"
                    .to_string()
            ]
        );
    }

    #[test]
    fn a_registrar_naming_another_host_is_refused_and_none_reached_resets_nothing() {
        let mut elsewhere = Sim::named("a");
        let mut b = Sim::named("b");
        let desks = vec![
            (
                Target {
                    base: "r0".into(),
                    host: Some("expected".into()),
                },
                &mut elsewhere as &mut dyn Desk,
            ),
            (
                Target {
                    base: "r1".into(),
                    host: None,
                },
                &mut b as &mut dyn Desk,
            ),
        ];
        let report = reset_all(&alice(), 0, desks, &mut |_| Ok(()), &mut |_| {}).unwrap();
        assert_eq!(report.done, vec!["r1".to_string()]);
        assert_eq!(
            report.not_done,
            vec!["r0: it names itself a, where the identity is registered at expected".to_string()]
        );
        assert_eq!(elsewhere.posts, 0);

        let mut down = Sim::named("a");
        down.unreachable = true;
        let (report, kept) = reset(3, &mut [&mut down]);
        assert!(report
            .unwrap_err()
            .contains("no registrar could be reached"));
        assert_eq!(kept, 3);
    }

    #[test]
    fn a_registrar_read_below_the_target_after_it_was_done_is_posted_again() {
        // Already at 19, it is done at 20 in one post, and loses that
        // record by the time it is read again, which happens because `b`,
        // caught up from 0, met another holder's 16 on the way.
        let mut restored = Sim::named("a");
        restored.held.push((19, 0, [9; 32]));
        restored.rollback_at = Some(3);
        let mut b = Sim::named("b");
        b.race = Some(signed(16, now() + 5));
        let (report, _) = reset(19, &mut [&mut restored, &mut b]);
        assert_eq!(report.unwrap(), all_done(20, 2));
        assert_eq!((restored.epochs(), restored.posts), (vec![19, 20], 2));
        assert_eq!(b.epochs(), vec![16, 20]);
    }

    #[test]
    fn an_answer_its_list_does_not_bear_out_is_not_done() {
        let mut pretender = Sim::named("a");
        pretender.pretend = true;
        let mut below = Sim::named("b");
        below.below = true;
        let mut gone = Sim::named("c");
        gone.unregistered = true;
        let report = reset(0, &mut [&mut pretender, &mut below, &mut gone])
            .0
            .unwrap();
        assert_eq!(
            report,
            Report {
                target: 1,
                done: vec![],
                not_done: vec![
                    "r0: it answered epoch 1, and its list shows 0".into(),
                    "r1: it answered epoch 0 to a post of 1".into(),
                    "r2: the identity is not registered there; drop it with --forget r2".into(),
                ],
            }
        );
        assert_eq!((pretender.posts, below.posts), (1, 1));
    }

    #[test]
    fn spellings_of_one_registrar_are_one_target_keeping_the_host_expected() {
        let kept = [("https://r.example".to_string(), "r.example".to_string())];
        let attested = ["r.example".to_string(), "s.example".to_string()];
        let named = [
            "R.example:443/",
            "s.example/",
            "HTTP://127.0.0.1:80/",
            "http://127.0.0.1",
            "https://r.example:8443",
        ];
        assert_eq!(
            targets(&kept, &attested, &named, &[]),
            vec![
                Target {
                    base: "https://r.example".into(),
                    host: Some("r.example".into()),
                },
                Target {
                    base: "https://s.example".into(),
                    host: Some("s.example".into()),
                },
                Target {
                    base: "http://127.0.0.1".into(),
                    host: None,
                },
                Target {
                    base: "https://r.example:8443".into(),
                    host: None,
                },
            ]
        );
        // A card's attestation of a registrar forgotten is left out,
        // by the host it was registered under or by its URL.
        let forgotten = [
            (
                "https://r.example".to_string(),
                Some("r.example".to_string()),
            ),
            ("https://s.example".to_string(), None),
        ];
        assert_eq!(targets(&[], &attested, &[], &forgotten), vec![]);
        let renamed = [("http://127.0.0.1:1".to_string(), Some("r.example".into()))];
        assert_eq!(
            targets(&[], &attested, &["r.example"], &renamed),
            vec![
                Target {
                    base: "https://s.example".into(),
                    host: Some("s.example".into()),
                },
                Target {
                    base: "https://r.example".into(),
                    host: None,
                },
            ]
        );
    }
}
