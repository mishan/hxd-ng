//! A client of either wire, as a scenario sees one: joined under a nick,
//! split into halves while it works, rejoined to leave.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hxd_testclient::legacy::{self, Login};
use hxd_testclient::{ng, tls, Error};
use hxproto::messages::tag;
use serde::Serialize;
use serde_json::{json, Value};

use crate::config::Server;
use crate::Ctx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    Legacy,
    LegacyTls,
    Ng,
}

impl Wire {
    pub fn name(self) -> &'static str {
        match self {
            Wire::Legacy => "legacy",
            Wire::LegacyTls => "legacy_tls",
            Wire::Ng => "ng",
        }
    }

    pub fn letter(self) -> char {
        match self {
            Wire::Legacy => 'L',
            Wire::LegacyTls => 'T',
            Wire::Ng => 'N',
        }
    }
}

pub enum Conn {
    Legacy(legacy::Client),
    Ng(ng::Client),
}

pub struct Member {
    pub nick: String,
    pub wire: Wire,
    pub conn: Conn,
}

/// Credentials, or a guest.
pub type Creds = Option<(String, String)>;

impl Member {
    /// Connect client `i` on `wire` and log in: to an account when given
    /// one, else as a guest.
    pub async fn join(ctx: &Ctx, wire: Wire, i: usize, creds: Creds) -> Result<Member, Error> {
        Member::join_on(ctx, 0, wire, i, creds).await
    }

    /// The same, on the run's server `server` (`Ctx::servers`).
    pub async fn join_on(
        ctx: &Ctx,
        server: usize,
        wire: Wire,
        i: usize,
        creds: Creds,
    ) -> Result<Member, Error> {
        let nick = ctx.nick(wire.letter(), i);
        Member::join_at(ctx, &ctx.servers[server], wire, nick, creds).await
    }

    /// The same, under a nick the caller chose: the observer's and the
    /// moderator's, which must not be any client's the checks look for.
    pub async fn join_as(
        ctx: &Ctx,
        wire: Wire,
        nick: String,
        creds: Creds,
    ) -> Result<Member, Error> {
        Member::join_at(ctx, &ctx.servers[0], wire, nick, creds).await
    }

    /// The same, on `at`, under a nick the caller chose.
    pub async fn join_at(
        ctx: &Ctx,
        at: &Server,
        wire: Wire,
        nick: String,
        creds: Creds,
    ) -> Result<Member, Error> {
        retry_busy(ctx, || {
            Member::join_once(ctx, at, wire, nick.clone(), creds.clone())
        })
        .await
    }

    /// One try at it, on a connection of its own: the server closes one
    /// whose login it refused.
    async fn join_once(
        ctx: &Ctx,
        t: &Server,
        wire: Wire,
        nick: String,
        creds: Creds,
    ) -> Result<Member, Error> {
        let conn = match wire {
            Wire::Legacy | Wire::LegacyTls => {
                let mut c = if wire == Wire::Legacy {
                    legacy::Client::connect(t.legacy.expect("checked by the scenario")).await?
                } else {
                    legacy::Client::connect_tls(
                        t.legacy_tls.expect("checked by the scenario"),
                        &ctx.scenario.target.tls_name,
                        tls::any(),
                    )
                    .await?
                };
                let login = match &creds {
                    Some((l, p)) => Login::account(&nick, l, p),
                    None => Login::guest(&nick),
                };
                c.login(&login).await?;
                Conn::Legacy(c)
            }
            Wire::Ng => {
                let mut c = ng::Client::connect(t.ng.expect("checked by the scenario")).await?;
                let params = match &creds {
                    Some((l, p)) => json!({ "login": l, "password": p, "nick": nick }),
                    None => json!({ "nick": nick }),
                };
                c.login(params).await?;
                Conn::Ng(c)
            }
        };
        Ok(Member { nick, wire, conn })
    }

    /// The nicks on this client's user list.
    pub async fn nicks(&mut self) -> Result<BTreeSet<String>, Error> {
        Ok(self.nick_list().await?.into_iter().collect())
    }

    /// The same, one per user: two users under one nick are two entries.
    pub async fn nick_list(&mut self) -> Result<Vec<String>, Error> {
        Ok(match &mut self.conn {
            Conn::Legacy(c) => c
                .user_list()
                .await?
                .into_iter()
                .map(|r| String::from_utf8_lossy(&r.nick).into_owned())
                .collect(),
            Conn::Ng(c) => {
                let ok = c.sync().await?;
                ok["users"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|u| u["nick"].as_str().map(str::to_owned))
                    .collect()
            }
        })
    }

    /// Leave for good: EOF on the classic wire, `logout` on ng, so that
    /// a session that could detach does not.
    pub async fn leave(self) -> Result<(), Error> {
        match self.conn {
            Conn::Legacy(mut c) => c.shutdown().await,
            Conn::Ng(c) => c.logout().await,
        }
    }

    pub fn split(self) -> (Tx, Rx, Parts) {
        let (tx, rx, parts) = match self.conn {
            Conn::Legacy(c) => {
                let uid = c.uid;
                let (tx, rx) = c.split();
                (Tx::Legacy(tx), Rx::Legacy(rx), Session::Legacy(uid))
            }
            Conn::Ng(c) => {
                let session = (c.session.clone(), c.uid);
                let (tx, rx) = c.split();
                (Tx::Ng(tx), Rx::Ng(rx), Session::Ng(session.0, session.1))
            }
        };
        let parts = Parts {
            nick: self.nick,
            wire: self.wire,
            session: parts,
        };
        (tx, rx, parts)
    }

    pub fn rejoin(tx: Tx, rx: Rx, parts: Parts) -> Member {
        let conn = match (tx, rx, parts.session) {
            (Tx::Legacy(tx), Rx::Legacy(rx), Session::Legacy(uid)) => {
                Conn::Legacy(legacy::Client { tx, rx, uid })
            }
            (Tx::Ng(tx), Rx::Ng(rx), Session::Ng(session, uid)) => Conn::Ng(ng::Client {
                tx,
                rx,
                session,
                uid,
            }),
            _ => unreachable!("halves of one member"),
        };
        Member {
            nick: parts.nick,
            wire: parts.wire,
            conn,
        }
    }
}

/// What a split member keeps beside its halves.
pub struct Parts {
    pub nick: String,
    pub wire: Wire,
    session: Session,
}

enum Session {
    Legacy(Option<u16>),
    Ng(Option<(String, String)>, Option<u64>),
}

pub enum Tx {
    Legacy(legacy::Sender),
    Ng(ng::Sender),
}

impl Tx {
    /// Send a chat line without waiting for anything: the classic wire
    /// answers none, and an ng reply is the receiver's to read.
    pub async fn chat(&mut self, text: &str) -> Result<(), Error> {
        match self {
            Tx::Legacy(tx) => tx.chat(text.as_bytes()).await,
            Tx::Ng(tx) => tx.send("chat", json!({ "text": text })).await.map(|_| ()),
        }
    }
}

pub enum Rx {
    Legacy(legacy::Receiver),
    Ng(ng::Receiver),
}

/// What a receiver heard that a scenario cares about.
pub enum Got {
    /// A public chat line's text.
    Chat(String),
    /// An ng request refused.
    Refused(Value),
    /// A user joined, or on the classic wire possibly changed.
    Joined {
        nick: String,
        uid: Option<u64>,
    },
    /// A user left.
    Parted(Option<u64>),
    /// The server ended this session.
    Kicked,
    Other,
}

impl Rx {
    /// The next thing heard, waiting as long as it takes.
    pub async fn next(&mut self) -> Result<Got, Error> {
        match self {
            Rx::Legacy(rx) => {
                let f = rx.recv_forever().await?;
                Ok(match f.ty {
                    legacy::push::CHAT if f.chunk(tag::CHAT_ID).is_none() => Got::Chat(
                        String::from_utf8_lossy(&f.bytes(tag::BODY).unwrap_or_default())
                            .into_owned(),
                    ),
                    legacy::push::DISCONNECT_MSG => Got::Kicked,
                    legacy::push::USER_PART => Got::Parted(f.uint(tag::UID).map(u64::from)),
                    legacy::push::USER_CHANGE => Got::Joined {
                        nick: String::from_utf8_lossy(&f.bytes(tag::NAME).unwrap_or_default())
                            .into_owned(),
                        uid: f.uint(tag::UID).map(u64::from),
                    },
                    _ => Got::Other,
                })
            }
            Rx::Ng(rx) => Ok(match rx.next_forever().await? {
                ng::Incoming::Reply(v) if v.get("error").is_some() => Got::Refused(v),
                ng::Incoming::Reply(_) => Got::Other,
                ng::Incoming::Event(e) if e.ev == "chat" => {
                    Got::Chat(e.data["text"].as_str().unwrap_or_default().to_owned())
                }
                ng::Incoming::Event(e) if e.ev == "kicked" => Got::Kicked,
                ng::Incoming::Event(e) if e.ev == "user_parted" => {
                    Got::Parted(e.data["uid"].as_u64())
                }
                ng::Incoming::Event(e) if e.ev == "user_joined" => Got::Joined {
                    nick: e.data["user"]["nick"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    uid: e.data["user"]["uid"].as_u64(),
                },
                ng::Incoming::Event(_) => Got::Other,
            }),
        }
    }

    /// The ng seq faults this receiver saw, if it is an ng one.
    pub fn seq_faults(&self) -> &[ng::SeqFault] {
        match self {
            Rx::Ng(rx) => &rx.seq_faults,
            Rx::Legacy(_) => &[],
        }
    }
}

/// Once things are quiet, every member's user list shows exactly this
/// run's `members`, with nobody missing and nobody extra. `either` are
/// this run's clients that may or may not still be listed — stalled ones
/// the server may rightly have disconnected — and are not looked for.
pub async fn roster_agrees(ctx: &Ctx, members: &mut [Member], either: &[String]) {
    let expect: BTreeSet<String> = members.iter().map(|m| m.nick.clone()).collect();
    for m in members.iter_mut() {
        match m.nicks().await {
            Ok(nicks) => {
                let ours: BTreeSet<String> = nicks
                    .into_iter()
                    .filter(|n| ctx.ours(n) && !either.contains(n))
                    .collect();
                ctx.checks.check("roster.agrees", ours == expect, || {
                    let missing: Vec<_> = expect.difference(&ours).collect();
                    let extra: Vec<_> = ours.difference(&expect).collect();
                    format!("{}'s list: missing {missing:?}, extra {extra:?}", m.nick)
                });
            }
            Err(e) => ctx.stats.error("roster.list", &e.to_string()),
        }
    }
}

/// After everyone this run brought has left, nobody of theirs is still
/// on the roster of the run's server `k`: seen by a fresh client's user
/// list, and, with metrics, by the server's own count of sessions
/// returning to where it was, and of ghosts when servers are linked.
pub async fn no_ghosts(ctx: &Ctx, k: usize, before: Option<&crate::target::Scrape>) {
    let deadline = Instant::now() + Duration::from_secs_f64(ctx.scenario.run.teardown);
    let t = &ctx.servers[k];
    let wire = if t.ng.is_some() {
        Wire::Ng
    } else {
        Wire::Legacy
    };
    match Member::join_at(ctx, t, wire, ctx.nick('O', k), None).await {
        Ok(mut observer) => {
            let observer_nick = observer.nick.clone();
            let mut left = BTreeSet::new();
            loop {
                match observer.nicks().await {
                    Ok(nicks) => {
                        left = nicks
                            .into_iter()
                            .filter(|n| ctx.ours(n) && *n != observer_nick)
                            .collect();
                    }
                    Err(e) => ctx.stats.error("roster.list", &e.to_string()),
                }
                if left.is_empty() || Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            ctx.checks.check("roster.no_ghosts", left.is_empty(), || {
                format!("still listed at {} after teardown: {left:?}", t.name)
            });
            let _ = observer.leave().await;
        }
        Err(e) => ctx.stats.error("roster.observer", &e.to_string()),
    }

    let (Some(before), Some(ng)) = (before.filter(|b| b.sessions().is_some()), t.ng) else {
        return;
    };
    // Linked, the run's users are ghosts on the other servers, so a count
    // above the one before is someone of this run's still shown here.
    let linked = ctx.servers.len() > 1;
    let ghosts = |s: &crate::target::Scrape| s.get("hxd_ghosts") <= before.get("hxd_ghosts");
    let mut now = None;
    loop {
        if let Ok(s) = crate::target::scrape(ng).await {
            now = Some(s);
        }
        let settled = now
            .as_ref()
            .is_some_and(|s| s.sessions() <= before.sessions() && (!linked || ghosts(s)));
        if settled || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let sessions = now.as_ref().and_then(|s| s.sessions());
    ctx.checks.check(
        "roster.sessions_return",
        sessions.is_some_and(|n| Some(n) <= before.sessions()),
        || {
            format!(
                "{} counts {sessions:?} sessions, {:?} before the run",
                t.name,
                before.sessions()
            )
        },
    );
    if linked {
        ctx.checks
            .check("link.no_ghosts", now.as_ref().is_some_and(ghosts), || {
                format!(
                    "{} shows {:?} ghosts, {:?} before the run",
                    t.name,
                    now.as_ref().and_then(|s| s.get("hxd_ghosts")),
                    before.get("hxd_ghosts")
                )
            });
    }
}

/// Whether the server refused a login as busy: past the logins it works
/// on at once, or on at once from one address, which every client of a
/// run on one machine shares. The ng wire says `rate_limited`; the
/// classic wire has no codes, only the task error's text.
pub fn busy(e: &Error) -> bool {
    match e {
        Error::Refused { code, .. } if code == "rate_limited" => true,
        Error::Refused { code, text } => code.is_empty() && text.contains("busy"),
        _ => false,
    }
}

/// How long a login refused as busy keeps trying before the refusal
/// stands.
const BUSY_PATIENCE: Duration = Duration::from_secs(15);

/// The logins the server refused as busy over a run, kept apart from the
/// operations' errors because a refusal the retry absorbs is not one: it
/// fails nothing, and without its own line in the report a gate that
/// leaked login places, refusing more and for longer as a run went on,
/// would show only as latency.
#[derive(Default)]
pub struct BusyLogins {
    refusals: AtomicU64,
    logins: AtomicU64,
    gave_up: AtomicU64,
    longest_wait_us: AtomicU64,
}

/// `BusyLogins` as the report carries it.
#[derive(Debug, Clone, Serialize)]
pub struct BusySummary {
    /// Every refusal, each one a try that was not the last.
    pub refusals: u64,
    /// Logins refused at least once.
    pub logins: u64,
    /// Logins still refused after `BUSY_PATIENCE`: those failed.
    pub gave_up: u64,
    /// The longest a refused login spent from its first try to its
    /// last.
    pub longest_wait_ms: f64,
}

impl BusyLogins {
    pub fn summary(&self) -> BusySummary {
        BusySummary {
            refusals: self.refusals.load(Ordering::Relaxed),
            logins: self.logins.load(Ordering::Relaxed),
            gave_up: self.gave_up.load(Ordering::Relaxed),
            longest_wait_ms: self.longest_wait_us.load(Ordering::Relaxed) as f64 / 1000.0,
        }
    }
}

/// Run `attempt`, a whole connect-and-log-in, again after a short and
/// growing wait each time the server refuses it as busy, as a real
/// client does: the server refuses at once rather than queue a login,
/// and a harness that took the refusal as final failed runs on a slow
/// machine for no fault of the server's. Each refusal is counted
/// (`BusyLogins`), so the report still shows the gate at work. Past
/// `BUSY_PATIENCE` the refusal is returned like any other error.
pub async fn retry_busy<T, F, Fut>(ctx: &Ctx, mut attempt: F) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let started = Instant::now();
    let give_up = started + BUSY_PATIENCE;
    let mut wait = Duration::from_millis(20);
    let mut refused = false;
    loop {
        let got = attempt().await;
        let is_busy = matches!(&got, Err(e) if busy(e));
        if is_busy {
            ctx.busy.refusals.fetch_add(1, Ordering::Relaxed);
            if !refused {
                refused = true;
                ctx.busy.logins.fetch_add(1, Ordering::Relaxed);
            }
            if Instant::now() + wait < give_up {
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(1));
                continue;
            }
            ctx.busy.gave_up.fetch_add(1, Ordering::Relaxed);
        }
        if refused {
            let us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
            ctx.busy.longest_wait_us.fetch_max(us, Ordering::Relaxed);
        }
        return got;
    }
}
