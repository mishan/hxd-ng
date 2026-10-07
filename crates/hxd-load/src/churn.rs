//! S6, churn: everything that ends or resumes a session, at once.
//!
//! - ng account sessions drop their connection and resume it, over and
//!   over, with chat flowing so there is always something to replay.
//!   Every seq they are handed is checked, across every resume.
//! - Classic guests come and go: some leave cleanly, some vanish, some
//!   die after the magic or with a login half sent.
//! - With `[target] admin`, a moderator kicks someone every so often,
//!   attached or detached.
//!
//! What must hold: seqs stay gapless across resumes and never go back
//! across a resync; a detached session is still there when it comes back
//! unless it was kicked; an attached connection is lost only to a kick,
//! and only a kicked session is told so; and, once everyone has gone,
//! nobody is left behind.
//!
//! What is measured rather than held: how many resumes replayed and how
//! many were told to resync. The protocol allows a resync not only when
//! the buffer overflowed but whenever events went out on the lost
//! connection unread (`docs/hotline-ng.md` §6.2), and nothing a client
//! sees tells it which events those were. So a churner drops its
//! connection only after a `ping` has come back, having read everything
//! sent before it: a resync then means an event crossed that narrow
//! window, and a run that shows many is worth looking into.
//!
//! With linked servers (L-5 of `docs/load-testing.md` §8), the churn
//! is on `[target]`, and once its time is up it is held: every churner
//! and the moderator say when they have stopped dropping, leaving and
//! kicking, and then every linked server's list must be exactly the run's
//! users `[target]` lists, user for user, so a stale ghost under a nick
//! still in use counts (`link.mirrors`). Whether or not it is linked, a
//! watcher on every server holds each uid it saw leave to the server's
//! quarantine (`roster.uid_quarantined`): what that guards is an
//! allocator that hands a freed uid out early, since the sequential one
//! comes round to a uid again only after the whole space.
//!
//! The server must let this many sessions detach from one address: set
//! its `[ng] max_detached_per_addr` to at least `[churn] ng`, and keep
//! `[churn] away` well under its `[ng] grace`. Otherwise the server is
//! right to end sessions this run expects to find again.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hxd_testclient::legacy::{self, Login};
use hxd_testclient::ng::{self, Incoming, Resumed};
use hxd_testclient::Error;
use hxproto::messages::ClientHdr;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::member::{retry_busy, Got, Member, Parts, Rx, Tx, Wire};
use crate::{ledger, Ctx};

/// Sessions the moderator may kick, by uid, each with the flag it sets
/// before it does, so the session's own task knows its ending was meant.
type Targets = Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>;

pub async fn run(ctx: &Arc<Ctx>) -> Result<Value, String> {
    let c = &ctx.scenario.churn;
    let (stop, stopped) = watch::channel(false);
    let (hold, held) = watch::channel(false);
    let (no_kicks, kicks_stopped) = watch::channel(false);
    let holding: Arc<Holding> = Arc::default();
    let targets: Targets = Arc::default();
    let mut tasks = Vec::new();

    let mut watchers = Vec::new();
    for (k, server) in ctx.servers.iter().enumerate() {
        let wire = if server.ng.is_some() {
            Wire::Ng
        } else {
            Wire::Legacy
        };
        let m = Member::join_at(ctx, server, wire, ctx.nick('Q', k), None)
            .await
            .map_err(|e| format!("a watcher on {} could not join: {e}", server.name))?;
        watchers.push(tokio::spawn(watch_uids(ctx.clone(), m, stopped.clone())));
    }

    // The steady talkers, one per wire that has a port.
    let mut talkers = Vec::new();
    for (k, wire) in [(0, Wire::Legacy), (1, Wire::Ng)] {
        let has = match wire {
            Wire::Ng => ctx.scenario.target.ng.is_some(),
            _ => ctx.scenario.target.legacy.is_some(),
        };
        if has && c.chat_rate > 0.0 {
            let m = Member::join(ctx, wire, 9000 + k, None)
                .await
                .map_err(|e| format!("talker could not join: {e}"))?;
            talkers.push(m);
        }
    }
    let per = talkers.len().max(1) as f64;
    for (k, m) in talkers.into_iter().enumerate() {
        let every = Duration::from_secs_f64(per / c.chat_rate);
        tasks.push(tokio::spawn(talker(
            ctx.clone(),
            m,
            k,
            every,
            stopped.clone(),
        )));
    }
    for i in 0..c.ng {
        tasks.push(tokio::spawn(ng_churner(
            ctx.clone(),
            i,
            targets.clone(),
            stopped.clone(),
            held.clone(),
            holding.clone(),
        )));
    }
    for i in 0..c.legacy {
        tasks.push(tokio::spawn(legacy_churner(
            ctx.clone(),
            i,
            targets.clone(),
            stopped.clone(),
            held.clone(),
            holding.clone(),
        )));
    }
    if let Some(admin) = ctx.scenario.target.admin.clone() {
        let creds = Some((admin.login, admin.password));
        let m = Member::join_as(ctx, Wire::Ng, ctx.nick('M', 0), creds)
            .await
            .map_err(|e| format!("the admin could not log in: {e}"))?;
        tasks.push(tokio::spawn(moderator(
            ctx.clone(),
            m,
            targets.clone(),
            stopped.clone(),
            kicks_stopped.clone(),
            holding.clone(),
        )));
    } else {
        holding.kicks_done.store(true, Ordering::SeqCst);
    }

    tokio::time::sleep(ctx.duration()).await;
    if ctx.servers.len() > 1 {
        // The kicks first, so that none is in flight once the churners
        // say they are held: a kicked churner logs in again.
        let _ = no_kicks.send(true);
        let settle = Duration::from_secs_f64(ctx.scenario.run.settle);
        let deadline = tokio::time::Instant::now() + settle;
        while !holding.kicks_done.load(Ordering::SeqCst) {
            if tokio::time::Instant::now() >= deadline {
                ctx.checks.violated(
                    "churn.kicks_stopped",
                    "the moderator did not stop within settle",
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _ = hold.send(true);
        let deadline = tokio::time::Instant::now() + settle;
        let all = c.ng + c.legacy;
        while holding.churners.load(Ordering::SeqCst) < all {
            if tokio::time::Instant::now() >= deadline {
                ctx.checks.violated(
                    "link.mirrors",
                    format!(
                        "{} of {all} churners held within settle",
                        holding.churners.load(Ordering::SeqCst)
                    ),
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        mirrored(ctx).await;
    }
    let _ = stop.send(true);
    for t in tasks {
        let _ = t.await;
    }
    for w in watchers {
        let (tx, rx, parts) = w.await.expect("a watcher does not panic");
        let _ = Member::rejoin(tx, rx, parts).leave().await;
    }
    Ok(json!({}))
}

/// Who has stopped churning once the run is held: the moderator, its
/// last kick answered, then each churner, held where it is.
#[derive(Default)]
struct Holding {
    kicks_done: AtomicBool,
    churners: AtomicUsize,
}

impl Holding {
    /// A churner held, counted once.
    fn held(&self, said: &mut bool) {
        if !*said {
            *said = true;
            self.churners.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// How long the server keeps a freed uid from anyone else: hxd-core's
/// `UID_QUARANTINE`, which this must not outgrow unnoticed.
const UID_QUARANTINE: Duration = Duration::from_secs(5 * 60);

/// Hear users come and go until the run stops, holding every uid seen
/// leaving to its quarantine.
async fn watch_uids(ctx: Arc<Ctx>, m: Member, mut stop: watch::Receiver<bool>) -> (Tx, Rx, Parts) {
    let (tx, mut rx, parts) = m.split();
    let mut parted: HashMap<u64, std::time::Instant> = HashMap::new();
    loop {
        tokio::select! {
            _ = stop.wait_for(|s| *s) => break,
            got = rx.next() => match got {
                Ok(Got::Parted(Some(uid))) => {
                    parted.insert(uid, std::time::Instant::now());
                }
                // Counted only with a freed uid to hold it to: a join with
                // none proves nothing.
                Ok(Got::Joined { nick, uid: Some(uid) }) if !parted.is_empty() => {
                    let early = parted
                        .remove(&uid)
                        .filter(|at| at.elapsed() < UID_QUARANTINE);
                    ctx.checks.check("roster.uid_quarantined", early.is_none(), || {
                        format!("{} saw uid {uid} given to {nick} {:?} after it was freed", parts.nick, early.map(|at| at.elapsed()))
                    });
                }
                Ok(_) => {}
                Err(e) => {
                    ctx.checks.violated(
                        "roster.uid_quarantined",
                        format!("{} stopped watching: {e}", parts.nick),
                    );
                    break;
                }
            },
        }
    }
    (tx, rx, parts)
}

/// With the churn held, every linked server lists exactly the run's
/// users `[target]` lists, within `settle`: seen by a fresh client on
/// each, apart from the watchers and these clients themselves.
async fn mirrored(ctx: &Ctx) {
    let mut lookers = Vec::new();
    for (k, server) in ctx.servers.iter().enumerate() {
        let wire = if server.ng.is_some() {
            Wire::Ng
        } else {
            Wire::Legacy
        };
        match Member::join_at(ctx, server, wire, ctx.nick('V', k), None).await {
            Ok(m) => lookers.push(m),
            Err(e) => {
                ctx.checks
                    .violated("link.mirrors", format!("no client on {}: {e}", server.name));
                return;
            }
        }
    }
    let ours = |nick: &String| {
        ctx.ours(nick)
            && !(0..ctx.servers.len())
                .any(|k| *nick == ctx.nick('V', k) || *nick == ctx.nick('Q', k))
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(ctx.scenario.run.settle);
    // User for user, not nick for nick: a ghost left behind by a session
    // that ended shares its nick with the churner's session now.
    let mut lists: Vec<Vec<String>> = Vec::new();
    loop {
        lists.clear();
        for l in &mut lookers {
            match l.nick_list().await {
                Ok(nicks) => {
                    let mut ours: Vec<String> = nicks.into_iter().filter(|n| ours(n)).collect();
                    ours.sort();
                    lists.push(ours);
                }
                Err(e) => {
                    ctx.checks
                        .violated("link.mirrors", format!("{} could not list: {e}", l.nick));
                    return;
                }
            }
        }
        if lists.iter().all(|l| *l == lists[0]) || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The talkers and the held sessions at least: an empty list would
    // match an empty one and prove nothing.
    if lists[0].is_empty() {
        ctx.checks.violated(
            "link.mirrors",
            format!("{} lists none of the run's users", ctx.servers[0].name),
        );
    }
    for (k, list) in lists.iter().enumerate().skip(1) {
        ctx.checks.check("link.mirrors", *list == lists[0], || {
            let missing: Vec<_> = lists[0].iter().filter(|n| !list.contains(n)).collect();
            let extra: Vec<_> = list.iter().filter(|n| !lists[0].contains(n)).collect();
            format!(
                "{} lists {} of the run's users to {}'s {}: missing {missing:?}, extra {extra:?}",
                ctx.servers[k].name,
                list.len(),
                ctx.servers[0].name,
                lists[0].len()
            )
        });
    }
    for l in lookers {
        let _ = l.leave().await;
    }
}

/// Chat on a schedule, and read (and discard) everything, so that the
/// talker is not itself a slow consumer.
async fn talker(
    ctx: Arc<Ctx>,
    m: Member,
    k: usize,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let (mut tx, mut rx, parts) = m.split();
    let mut n = 0u64;
    let first = ctx.t0.elapsed();
    loop {
        let due = first + every.mul_f64(n as f64);
        tokio::select! {
            _ = stop.changed() => break,
            got = rx.next() => {
                if let Err(e) = got {
                    ctx.stats.error("churn.talker", &e.to_string());
                    return;
                }
            }
            _ = tokio::time::sleep_until((ctx.t0 + due).into()) => {
                n += 1;
                let line = ledger::line(&ctx.run, 100 + k, n, due, 16);
                if let Err(e) = tx.chat(&line).await {
                    ctx.stats.error("churn.talker", &e.to_string());
                    return;
                }
            }
        }
    }
    let _ = Member::rejoin(tx, rx, parts).leave().await;
}

/// One ng account session, dropping and resuming until the run ends.
///
/// A session is only ever given up when it is over: kicked, or expired
/// on the server's word. Anything else — a lost connection, a resume
/// that timed out — goes back through `resume` rather than a fresh
/// login, which would leave the old session detached on the roster for
/// the server's whole grace window and blame the server for the ghost.
async fn ng_churner(
    ctx: Arc<Ctx>,
    i: usize,
    targets: Targets,
    mut stop: watch::Receiver<bool>,
    mut hold: watch::Receiver<bool>,
    holding: Arc<Holding>,
) {
    let mut said = false;
    let addr = ctx.scenario.target.ng.expect("checked by the scenario");
    let accounts = ctx
        .scenario
        .target
        .accounts
        .clone()
        .expect("checked by the scenario");
    let nick = ctx.nick('N', i);
    let params = json!({ "login": accounts.login(i), "password": accounts.password, "nick": nick });

    let mut session: Option<(ng::Client, Arc<AtomicBool>)> = None;
    loop {
        if *stop.borrow() {
            // Whatever session is held ends here rather than detaching,
            // or it would outlive the run.
            if let Some((c, kicked)) = session.take() {
                finish(&ctx, &nick, &c.rx.seq_faults, &kicked, &targets);
                leave(&ctx, addr, c).await;
            }
            break;
        }
        let (mut c, kicked) = match session.take() {
            Some(s) => s,
            None => match login(&ctx, addr, &params, &targets).await {
                Some(s) => s,
                None => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };

        // Attached: read for a while, or once held, until the run stops.
        let until = tokio::time::Instant::now()
            + if *hold.borrow() {
                holding.held(&mut said);
                Duration::from_secs(24 * 3600)
            } else {
                ctx.exp(ctx.scenario.churn.cycle)
            };
        let mut lost = false;
        let was_held = *hold.borrow();
        loop {
            tokio::select! {
                _ = stop.changed() => break,
                _ = tokio::time::sleep_until(until) => break,
                // Held mid-read: stop the cycle here, and stay attached.
                _ = hold.wait_for(|h| *h), if !was_held => break,
                got = c.rx.next_forever() => match got {
                    Ok(Incoming::Event(e)) if e.ev == "kicked" => {
                        ctx.checks.check("churn.ended_only_by_kick", kicked.load(Ordering::SeqCst), || {
                            format!("{nick} was told it was kicked, and nobody kicked it")
                        });
                        lost = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        if !kicked.load(Ordering::SeqCst) {
                            ctx.checks.violated(
                                "churn.connection_kept",
                                format!("{nick} lost an attached connection: {e}"),
                            );
                        }
                        lost = true;
                        break;
                    }
                },
            }
        }
        if lost && kicked.load(Ordering::SeqCst) {
            // Over: kicked sessions end, attached or not.
            finish(&ctx, &nick, &c.rx.seq_faults, &kicked, &targets);
            continue;
        }
        if !lost && (*stop.borrow() || *hold.borrow()) {
            session = Some((c, kicked));
            continue;
        }

        // Read up to a ping's reply, so what was sent before it has been
        // accounted for; then drop the connection (if it is not gone
        // already), stay away a moment, and come back.
        if !lost {
            if let Err(e) = c.request("ping", Value::Null).await {
                ctx.stats.error("churn.ping", &e.to_string());
            }
            c.rx.take_backlog();
        }
        let from = c.session.clone().expect("a logged-in session has one");
        let (last_seq, faults) = (c.rx.last_seq, c.rx.seq_faults.clone());
        if ctx.random() < 0.5 {
            let _ = c.close().await;
        } else {
            drop(c);
        }
        tokio::time::sleep(ctx.exp(ctx.scenario.churn.away)).await;
        session = come_back(&ctx, addr, &nick, from, last_seq, faults, kicked, &targets).await;
    }
}

/// Resume a dropped session, a few times if need be. `None` when the
/// session is over — expired, on the server's word — or out of reach.
#[allow(clippy::too_many_arguments)]
async fn come_back(
    ctx: &Ctx,
    addr: std::net::SocketAddr,
    nick: &str,
    from: (String, String),
    last_seq: u64,
    faults: Vec<ng::SeqFault>,
    kicked: Arc<AtomicBool>,
    targets: &Targets,
) -> Option<(ng::Client, Arc<AtomicBool>)> {
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let took = std::time::Instant::now();
        match ng::Client::resume(addr, from.clone(), last_seq, faults.clone()).await {
            Ok((c, Resumed::Replayed(_))) => {
                ctx.stats.record("churn.resume.replayed", took.elapsed());
                ctx.checks.held("churn.resumed");
                return Some((c, kicked));
            }
            Ok((mut c, Resumed::ResyncRequired)) => match c.sync().await {
                Ok(ok) => {
                    ctx.stats.record("churn.resume.resync", took.elapsed());
                    let now = ok["seq"].as_u64().unwrap_or(0);
                    ctx.checks
                        .check("churn.seq_never_back", now >= last_seq, || {
                            format!("{nick} resynced to seq {now}, having had {last_seq}")
                        });
                    return Some((c, kicked));
                }
                Err(e) => ctx.stats.error("churn.sync", &e.to_string()),
            },
            Err(Error::Refused { code, text }) if code == "session_expired" => {
                let meant = kicked.load(Ordering::SeqCst);
                ctx.checks.check("churn.session_kept", meant, || {
                    format!(
                        "{nick}'s detached session was gone when it came back ({text}); \
                         check [ng] max_detached_per_addr and grace"
                    )
                });
                finish(ctx, nick, &faults, &kicked, targets);
                return None;
            }
            Err(e) => ctx.stats.error("churn.resume", &e.to_string()),
        }
    }
    // Out of reach: its seqs are still accounted for, and the error
    // counts above say why the session could not be brought back.
    finish(ctx, nick, &faults, &kicked, targets);
    None
}

/// Log a session out; if its connection is already gone, resume it
/// first, so that it ends instead of detaching.
async fn leave(ctx: &Ctx, addr: std::net::SocketAddr, c: ng::Client) {
    let from = c.session.clone();
    let last_seq = c.rx.last_seq;
    if c.logout().await.is_ok() {
        return;
    }
    let Some(from) = from else { return };
    match ng::Client::resume(addr, from, last_seq, Vec::new()).await {
        Ok((c, _)) => {
            if let Err(e) = c.logout().await {
                ctx.stats.error("churn.logout", &e.to_string());
            }
        }
        Err(Error::Refused { code, .. }) if code == "session_expired" => {}
        Err(e) => ctx.stats.error("churn.logout", &e.to_string()),
    }
}

async fn login(
    ctx: &Ctx,
    addr: std::net::SocketAddr,
    params: &Value,
    targets: &Targets,
) -> Option<(ng::Client, Arc<AtomicBool>)> {
    let took = std::time::Instant::now();
    let attempt = || async {
        let mut c = ng::Client::connect(addr).await?;
        c.login(params.clone()).await?;
        Ok(c)
    };
    let c = match retry_busy(ctx, attempt).await {
        Ok(c) => c,
        Err(e) => {
            ctx.stats.error("churn.login", &e.to_string());
            return None;
        }
    };
    ctx.stats.record("churn.login", took.elapsed());
    let flag = Arc::new(AtomicBool::new(false));
    if let Some(uid) = c.uid {
        targets.lock().unwrap().insert(uid, flag.clone());
    }
    Some((c, flag))
}

/// A session is over: its seqs, all of them, must have been gapless.
fn finish(
    ctx: &Ctx,
    nick: &str,
    faults: &[ng::SeqFault],
    kicked: &Arc<AtomicBool>,
    targets: &Targets,
) {
    record_faults(ctx, nick, faults);
    deregister(targets, kicked);
}

fn record_faults(ctx: &Ctx, nick: &str, faults: &[ng::SeqFault]) {
    ctx.checks.check("ng.seq_gapless", faults.is_empty(), || {
        format!("{nick}: {faults:?}")
    });
}

fn deregister(targets: &Targets, flag: &Arc<AtomicBool>) {
    targets.lock().unwrap().retain(|_, f| !Arc::ptr_eq(f, flag));
}

/// A classic guest that comes and goes, in one of four ways.
async fn legacy_churner(
    ctx: Arc<Ctx>,
    i: usize,
    targets: Targets,
    mut stop: watch::Receiver<bool>,
    mut hold: watch::Receiver<bool>,
    holding: Arc<Holding>,
) {
    let mut said = false;
    let addr = ctx.scenario.target.legacy.expect("checked by the scenario");
    let nick = ctx.nick('L', i);
    while !*stop.borrow() {
        // Held while out: stay out.
        if *hold.borrow() {
            holding.held(&mut said);
            let _ = stop.wait_for(|s| *s).await;
            break;
        }
        let way = (ctx.random() * 4.0) as u32;
        let outcome: Result<(), Error> = async {
            match way {
                // Gone after the magic.
                0 => drop(legacy::Client::connect(addr).await?),
                // Gone with the login sent and its reply unread.
                1 => {
                    let mut c = legacy::Client::connect(addr).await?;
                    c.send(
                        ClientHdr::Login.as_u32(),
                        &[(hxproto::messages::tag::NAME, nick.as_bytes().to_vec())],
                    )
                    .await?;
                }
                // Logged in, a while, then gone: cleanly, or not.
                _ => {
                    let login = Login::guest(&nick);
                    let c = retry_busy(&ctx, || legacy::Client::login_at(addr, &login)).await?;
                    let flag = Arc::new(AtomicBool::new(false));
                    if let Some(uid) = c.uid {
                        targets.lock().unwrap().insert(uid as u64, flag.clone());
                    }
                    let (tx, rx) = c.split();
                    let mut rx = crate::member::Rx::Legacy(rx);
                    let until = tokio::time::Instant::now() + ctx.exp(ctx.scenario.churn.cycle);
                    loop {
                        let held = *hold.borrow();
                        if held {
                            holding.held(&mut said);
                        }
                        tokio::select! {
                            _ = stop.changed() => break,
                            // Held while in: stay in.
                            _ = tokio::time::sleep_until(until), if !held => break,
                            _ = hold.changed(), if !held => {}
                            got = rx.next() => match got {
                                Ok(Got::Kicked) | Err(_) => break,
                                Ok(_) => {}
                            },
                        }
                    }
                    deregister(&targets, &flag);
                    if way == 2 {
                        let mut tx = tx;
                        tx.shutdown().await?;
                    }
                }
            }
            Ok(())
        }
        .await;
        if let Err(e) = outcome {
            ctx.stats.error("churn.legacy", &e.to_string());
        }
        tokio::select! {
            _ = stop.changed() => {}
            _ = hold.wait_for(|h| *h) => {}
            _ = tokio::time::sleep(ctx.exp(ctx.scenario.churn.cycle)) => {}
        }
    }
}

/// Kick someone every so often.
async fn moderator(
    ctx: Arc<Ctx>,
    m: Member,
    targets: Targets,
    mut stop: watch::Receiver<bool>,
    mut no_kicks: watch::Receiver<bool>,
    holding: Arc<Holding>,
) {
    let crate::member::Conn::Ng(mut c) = m.conn else {
        unreachable!("the moderator is on ng");
    };
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = no_kicks.wait_for(|n| *n) => {}
            _ = tokio::time::sleep(ctx.exp(ctx.scenario.churn.kick_every)) => {}
        }
        // Told to stop: no kick is in flight, since the last one was
        // answered before this.
        if *no_kicks.borrow() {
            holding.kicks_done.store(true, Ordering::SeqCst);
            let _ = stop.wait_for(|s| *s).await;
            break;
        }
        let pick = {
            let t = targets.lock().unwrap();
            if t.is_empty() {
                None
            } else {
                let k = (ctx.random() * t.len() as f64) as usize;
                t.iter()
                    .nth(k.min(t.len() - 1))
                    .map(|(u, f)| (*u, f.clone()))
            }
        };
        let Some((uid, flag)) = pick else { continue };
        flag.store(true, Ordering::SeqCst);
        match c.request("kick", json!({ "uid": uid })).await {
            Ok(_) => ctx.checks.held("churn.kicked"),
            // Gone already, most likely: it left, or was dropped and
            // ended, between the pick and the kick.
            Err(Error::Refused { code, .. }) => ctx.stats.error("churn.kick", &code),
            Err(e) => {
                ctx.stats.error("churn.kick", &e.to_string());
                break;
            }
        }
        // Nothing here reads events; do not let them pile up.
        c.rx.take_backlog();
    }
    // Done kicking however it ended, so the hold does not wait on it.
    holding.kicks_done.store(true, Ordering::SeqCst);
    let _ = c.logout().await;
}
