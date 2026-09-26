//! A client of either wire, as a scenario sees one: joined under a nick,
//! split into halves while it works, rejoined to leave.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use hxd_testclient::legacy::{self, Login};
use hxd_testclient::{ng, tls, Error};
use hxproto::messages::tag;
use serde_json::{json, Value};

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

    fn letter(self) -> char {
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
        let nick = ctx.nick(wire.letter(), i);
        let t = &ctx.scenario.target;
        let conn = match wire {
            Wire::Legacy | Wire::LegacyTls => {
                let mut c = if wire == Wire::Legacy {
                    legacy::Client::connect(t.legacy.expect("checked by the scenario")).await?
                } else {
                    legacy::Client::connect_tls(
                        t.legacy_tls.expect("checked by the scenario"),
                        &t.tls_name,
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
/// run's clients who are still here — `members`, and `also`, whose lists
/// are not asked for — with nobody missing and nobody extra.
pub async fn roster_agrees(ctx: &Ctx, members: &mut [Member], also: &[String]) {
    let expect: BTreeSet<String> = members
        .iter()
        .map(|m| m.nick.clone())
        .chain(also.iter().cloned())
        .collect();
    for m in members.iter_mut() {
        match m.nicks().await {
            Ok(nicks) => {
                let ours: BTreeSet<String> = nicks.into_iter().filter(|n| ctx.ours(n)).collect();
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
/// on the roster: seen by a fresh client's user list, and, with metrics,
/// by the server's own count returning to where it was.
pub async fn no_ghosts(ctx: &Ctx, before: Option<&crate::target::Scrape>) {
    let deadline = Instant::now() + Duration::from_secs_f64(ctx.scenario.run.teardown);
    let t = &ctx.scenario.target;
    let wire = if t.ng.is_some() {
        Wire::Ng
    } else {
        Wire::Legacy
    };
    match Member::join(ctx, wire, 0, None).await {
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
                format!("still listed after teardown: {left:?}")
            });
            let _ = observer.leave().await;
        }
        Err(e) => ctx.stats.error("roster.observer", &e.to_string()),
    }

    let (Some(before), Some(ng)) = (before.and_then(|b| b.sessions()), t.ng) else {
        return;
    };
    let mut now = None;
    loop {
        if let Ok(s) = crate::target::scrape(ng).await {
            now = s.sessions();
        }
        if now.is_some_and(|n| n <= before) || Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ctx.checks.check(
        "roster.sessions_return",
        now.is_some_and(|n| n <= before),
        || format!("the server counts {now:?} sessions, {before} before the run"),
    );
}
