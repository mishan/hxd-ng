//! L-6, requests: private messages and user info sent from `[target]` to
//! the users of the servers linked to it, as there are more of them
//! (`docs/load-testing.md` §8.3).
//!
//! Each count in `[requests] ghosts` is a step: idle users join the
//! linked servers until there are that many, `[target]` is waited for to
//! show every one, and then for `step` seconds the requesters send
//! `rate` requests a second, open-loop, each to a ghost picked at random:
//! a message on either wire, or on the classic wire, user info. A request
//! finds its ghost's link by looking through every link's ghosts, so
//! what is measured is its round trip as they grow, step by step.
//!
//! A request the server refuses (too many waiting for the peer, say) is
//! counted, never a violation: it is right to refuse. So is user info
//! answered with the ghost's server alone, which is what the classic wire
//! gives when the peer did not answer, and a message queued rather than
//! delivered. What must hold is that every message accepted is heard by
//! its recipient once, and every one refused never (one the server calls
//! unconfirmed, sent and not answered in time, is held to neither: it
//! may arrive or not), checked after each
//! step and again once the run is quiet (`link.msgs_delivered`); and that
//! a requester is answered rather than cut off (`link.requests_answered`):
//! one that is not is dropped from the run, and the rest go on.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hdrhistogram::Histogram;
use hxd_testclient::Error;
use hxproto::messages::{tag, ClientHdr};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::ledger;
use crate::member::{Conn, Got, Member, Parts, Rx, Tx, Wire};
use crate::stats::{self, Summary};
use crate::Ctx;

/// How long a requester waits for an answer: past the server's own wait
/// for the peer (`PEER_WAIT`, ten seconds), so a peer slow to answer
/// shows as the server's refusal, not as a requester giving up.
const ANSWER_WAIT: Duration = Duration::from_secs(15);

/// How long the run is let go quiet before every message is accounted
/// for again, so a duplicate or a refused one delivered late is seen.
const QUIET: Duration = Duration::from_secs(1);

/// Each message, by requester and that requester's count, and how many
/// times its recipient heard it.
type Heard = Arc<Mutex<HashMap<(usize, u64), u32>>>;

#[derive(Serialize)]
struct StepReport {
    ghosts: usize,
    sent: u64,
    refused: u64,
    /// Refusals by the code or text the server gave.
    refusals: BTreeMap<String, u64>,
    msg: Summary,
    info: Summary,
}

#[derive(Clone, Copy)]
enum Ask {
    Msg,
    Info,
}

/// What one requester did in a step.
struct Done {
    accepted: Vec<(usize, u64)>,
    refused: Vec<(usize, u64)>,
    refusals: BTreeMap<String, u64>,
    msg: Histogram<u64>,
    info: Histogram<u64>,
}

pub async fn run(ctx: &Arc<Ctx>, proxy: Option<&crate::proxy::Proxy>) -> Result<Value, String> {
    let r = &ctx.scenario.requests;
    let (stop_tx, stop) = watch::channel(false);
    let heard: Heard = Arc::default();

    // By index for the whole run, so a requester's messages keep its
    // number; `None` once one is cut off.
    let mut requesters: Vec<Option<Member>> = Vec::new();
    for (wire, n) in [
        (Wire::Legacy, r.requesters_legacy),
        (Wire::Ng, r.requesters_ng),
    ] {
        for _ in 0..n {
            let k = requesters.len();
            let mut m = Member::join_at(ctx, &ctx.servers[0], wire, ctx.nick('K', k), None)
                .await
                .map_err(|e| format!("requester {k} could not join: {e}"))?;
            match &mut m.conn {
                Conn::Legacy(c) => c.rx.timeout = ANSWER_WAIT,
                Conn::Ng(c) => c.rx.timeout = ANSWER_WAIT,
            }
            requesters.push(Some(m));
        }
    }
    let (mut all_accepted, mut all_refused) = (Vec::new(), Vec::new());

    let linked: Vec<usize> = (1..ctx.servers.len()).collect();
    let mut nicks = Vec::new();
    let mut population: Vec<JoinHandle<(Tx, Rx, Parts)>> = Vec::new();
    let mut seqs = vec![0u64; requesters.len()];
    let mut steps = Vec::new();
    for &ghosts in &r.ghosts {
        // The ghosts cross at full speed, the requests slowed after.
        if let (Some(p), Some(_)) = (proxy, r.peer_latency_ms) {
            p.set_latency(Duration::ZERO);
        }
        while nicks.len() < ghosts {
            let i = nicks.len();
            let wire = if i % 2 == 0 { Wire::Legacy } else { Wire::Ng };
            let m = Member::join_on(ctx, linked[i % linked.len()], wire, i, None)
                .await
                .map_err(|e| format!("user {i} could not join: {e}"))?;
            nicks.push(m.nick.clone());
            population.push(listen(ctx.clone(), m, stop.clone(), heard.clone()));
        }
        let Some(looker) = requesters.iter_mut().flatten().next() else {
            break;
        };
        let Some(uids) = shown(ctx, looker, &nicks).await else {
            ctx.checks.violated(
                "link.ghosts_shown",
                format!("{} never showed all {ghosts} users", ctx.servers[0].name),
            );
            break;
        };
        ctx.checks.held("link.ghosts_shown");
        if let (Some(p), Some(ms)) = (proxy, r.peer_latency_ms) {
            p.set_latency(Duration::from_millis(ms));
        }

        let (back, done) = step(ctx, requesters, &uids, &mut seqs).await;
        requesters = back;
        let (mut msg, mut info) = (stats::local(), stats::local());
        let (mut accepted, mut refused) = (Vec::new(), Vec::new());
        let mut refusals = BTreeMap::new();
        for d in done {
            let _ = msg.add(&d.msg);
            let _ = info.add(&d.info);
            accepted.extend(d.accepted);
            refused.extend(d.refused);
            for (why, n) in d.refusals {
                *refusals.entry(why).or_default() += n;
            }
        }
        ctx.stats.merge("request.msg", &msg);
        ctx.stats.merge("request.info", &info);
        let refused_n: u64 = refusals.values().sum();
        steps.push(StepReport {
            ghosts,
            sent: msg.len() + info.len() + refused_n,
            refused: refused_n,
            refusals,
            msg: Summary::of(&msg, &Default::default()),
            info: Summary::of(&info, &Default::default()),
        });
        delivered(ctx, &heard, &accepted, &refused).await;
        all_accepted.extend(accepted);
        all_refused.extend(refused);
    }

    tokio::time::sleep(QUIET).await;
    recount(ctx, &heard, &all_accepted, &all_refused);
    let _ = stop_tx.send(true);
    for p in population {
        let (tx, rx, parts) = p.await.expect("a listener does not panic");
        let _ = Member::rejoin(tx, rx, parts).leave().await;
    }
    for m in requesters.into_iter().flatten() {
        let _ = m.leave().await;
    }
    Ok(json!({ "steps": steps }))
}

/// One step: `rate` requests a second for `step` seconds, request `j`
/// due at `j / rate` and sent by requester `j` modulo their number.
async fn step(
    ctx: &Arc<Ctx>,
    requesters: Vec<Option<Member>>,
    uids: &[u64],
    seqs: &mut [u64],
) -> (Vec<Option<Member>>, Vec<Done>) {
    let r = &ctx.scenario.requests;
    let start = ctx.t0.elapsed() + Duration::from_millis(100);
    let total = (r.rate * r.step).round() as usize;
    let live: Vec<usize> = (0..requesters.len())
        .filter(|&k| requesters[k].is_some())
        .collect();
    let mut plans: Vec<Vec<(Duration, u64, Ask, u64)>> = vec![Vec::new(); requesters.len()];
    for j in 0..total {
        let k = live[j % live.len()];
        let due = start + Duration::from_secs_f64(j as f64 / r.rate);
        let wire = requesters[k].as_ref().map(|m| m.wire);
        let ask = match wire.expect("live") {
            Wire::Ng => Ask::Msg,
            _ if ctx.random() < r.info_share => Ask::Info,
            _ => Ask::Msg,
        };
        let to = uids[((ctx.random() * uids.len() as f64) as usize).min(uids.len() - 1)];
        seqs[k] += 1;
        plans[k].push((due, seqs[k], ask, to));
    }
    let tasks: Vec<_> = requesters
        .into_iter()
        .zip(plans)
        .enumerate()
        .map(|(k, (m, plan))| {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                match m {
                    Some(m) => ask(ctx, k, m, plan).await,
                    None => (None, Done::new()),
                }
            })
        })
        .collect();
    let mut back = Vec::new();
    let mut done = Vec::new();
    for t in tasks {
        let (m, d) = t.await.expect("a requester does not panic");
        back.push(m);
        done.push(d);
    }
    (back, done)
}

/// Send one requester's requests, each when it is due, and time each
/// from then to its answer.
async fn ask(
    ctx: Arc<Ctx>,
    k: usize,
    mut m: Member,
    plan: Vec<(Duration, u64, Ask, u64)>,
) -> (Option<Member>, Done) {
    let mut d = Done::new();
    for (due, seq, what, to) in plan {
        tokio::time::sleep_until((ctx.t0 + due).into()).await;
        let line = ledger::line(&ctx.run, k, seq, due, 8);
        let uid = (to as u16).to_be_bytes().to_vec();
        let answered = match (&mut m.conn, what) {
            (Conn::Legacy(c), Ask::Msg) => c
                .call(
                    ClientHdr::Msg.as_u32(),
                    &[(tag::UID, uid), (tag::BODY, line.into_bytes())],
                )
                .await
                .map(|_| ()),
            // A ghost's info is always answered, with a line naming its
            // server first; nothing after it is the peer not answering.
            (Conn::Legacy(c), Ask::Info) => c
                .call(ClientHdr::UserGetInfo.as_u32(), &[(tag::UID, uid)])
                .await
                .and_then(|f| {
                    let body = String::from_utf8_lossy(&f.bytes(tag::BODY).unwrap_or_default())
                        .into_owned();
                    let rest = body.split_once('\r').map_or("", |(_, rest)| rest);
                    if rest.trim().is_empty() {
                        Err(refusal("unanswered"))
                    } else {
                        Ok(())
                    }
                }),
            (Conn::Ng(c), _) => c
                .request("msg", json!({ "to": to, "text": line }))
                .await
                .and_then(|ok| {
                    if ok["queued"] == true {
                        Err(refusal("queued"))
                    } else {
                        Ok(())
                    }
                }),
        };
        // What else it was sent meanwhile is not this scenario's.
        match &mut m.conn {
            Conn::Legacy(c) => drop(c.rx.take_backlog()),
            Conn::Ng(c) => drop(c.rx.take_backlog()),
        }
        let took = ctx.t0.elapsed().saturating_sub(due);
        let msg = matches!(what, Ask::Msg);
        match answered {
            Ok(()) if msg => {
                stats::sample(&mut d.msg, took);
                d.accepted.push((k, seq));
            }
            Ok(()) => stats::sample(&mut d.info, took),
            Err(Error::Refused { code, text }) => {
                // Sent, and unanswered in time: it may yet arrive, so it
                // is held to neither accounting.
                let unknown = code == "unconfirmed" || text.contains("not known");
                let why = if code.is_empty() { text } else { code };
                *d.refusals.entry(why).or_default() += 1;
                if msg && !unknown {
                    d.refused.push((k, seq));
                }
            }
            Err(e) => {
                ctx.checks.violated(
                    "link.requests_answered",
                    format!("{} was not answered: {e}", m.nick),
                );
                // Its connection may still owe an answer; not used again.
                return (None, d);
            }
        }
    }
    ctx.checks.held("link.requests_answered");
    (Some(m), d)
}

impl Done {
    fn new() -> Done {
        Done {
            accepted: Vec::new(),
            refused: Vec::new(),
            refusals: BTreeMap::new(),
            msg: stats::local(),
            info: stats::local(),
        }
    }
}

/// A refusal the harness reads from an answer, kept with the server's.
fn refusal(why: &str) -> Error {
    Error::Refused {
        code: why.into(),
        text: String::new(),
    }
}

/// The uids `[target]` shows `nicks` under, in their order, once it
/// shows them all, within `settle`.
async fn shown(ctx: &Ctx, looker: &mut Member, nicks: &[String]) -> Option<Vec<u64>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(ctx.scenario.run.settle);
    loop {
        if let Ok(users) = looker.users().await {
            let by_nick: HashMap<String, u64> = users.into_iter().collect();
            if let Some(uids) = nicks.iter().map(|n| by_nick.get(n).copied()).collect() {
                return Some(uids);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Hear the messages a user is sent until the run stops, timing each
/// from when it was due.
fn listen(
    ctx: Arc<Ctx>,
    m: Member,
    mut stop: watch::Receiver<bool>,
    heard: Heard,
) -> JoinHandle<(Tx, Rx, Parts)> {
    let (tx, mut rx, parts) = m.split();
    tokio::spawn(async move {
        let mut delivery = stats::local();
        loop {
            tokio::select! {
                _ = stop.wait_for(|s| *s) => break,
                got = rx.next() => match got {
                    Ok(Got::Msg(text)) => {
                        if let Some((k, seq, due)) = ledger::parse(&ctx.run, &text) {
                            stats::sample(&mut delivery, ctx.t0.elapsed().saturating_sub(due));
                            *heard.lock().unwrap().entry((k, seq)).or_default() += 1;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        ctx.checks.violated("link.msgs_delivered", format!("{} lost its connection: {e}", parts.nick));
                        break;
                    }
                },
            }
        }
        ctx.stats.merge("link.msg.delivery", &delivery);
        (tx, rx, parts)
    })
}

/// The same accounting as each step's, made again once the run is
/// quiet: only what changed since is reported, as a violation.
fn recount(ctx: &Ctx, heard: &Heard, accepted: &[(usize, u64)], refused: &[(usize, u64)]) {
    let h = heard.lock().unwrap();
    let count = |m: &(usize, u64)| h.get(m).copied().unwrap_or(0);
    for m in accepted.iter().filter(|m| count(m) > 1) {
        ctx.checks.violated(
            "link.msgs_delivered",
            format!(
                "requester {}'s message {} heard {} times by the end",
                m.0,
                m.1,
                count(m)
            ),
        );
    }
    for m in refused.iter().filter(|m| count(m) > 0) {
        ctx.checks.violated(
            "link.msgs_delivered",
            format!(
                "requester {}'s message {} refused and heard by the end",
                m.0, m.1
            ),
        );
    }
}

/// Every message accepted heard once within `settle`, every one refused
/// never.
async fn delivered(ctx: &Ctx, heard: &Heard, accepted: &[(usize, u64)], refused: &[(usize, u64)]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(ctx.scenario.run.settle);
    while tokio::time::Instant::now() < deadline {
        let all = {
            let h = heard.lock().unwrap();
            accepted.iter().all(|m| h.contains_key(m))
        };
        if all {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let h = heard.lock().unwrap();
    let count = |m: &(usize, u64)| h.get(m).copied().unwrap_or(0);
    for m in accepted {
        ctx.checks.check("link.msgs_delivered", count(m) == 1, || {
            format!(
                "requester {}'s message {} accepted and heard {} times",
                m.0,
                m.1,
                count(m)
            )
        });
    }
    for m in refused {
        ctx.checks.check("link.msgs_delivered", count(m) == 0, || {
            format!(
                "requester {}'s message {} refused and heard {} times",
                m.0,
                m.1,
                count(m)
            )
        });
    }
}
