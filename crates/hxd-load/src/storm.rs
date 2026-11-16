//! S1, the login storm: arrivals at a rising rate, each one a whole
//! classic or ng login — connect, log in, agree, fetch the user list —
//! timed from when it was due. The client lingers a moment and leaves,
//! so the population stays bounded and what is measured is the login.
//!
//! The rate steps up every `ramp_every` seconds, and each step is
//! reported on its own. The knee is the first step whose p99 is more
//! than twice the first step's, or whose errors pass one in a hundred.
//! A login the server refuses as busy tries again, as a client would
//! (`member::retry_busy`), so the server's login gate shows as latency
//! and in the report's `busy_logins` rather than as failed logins.
//!
//! With `mail`, every account has private messages waiting before the
//! first arrival, and an arrival logging in to one for the first time
//! times when the first of them reached its socket (`mail.first`); with
//! `msg_rate`, senders keep messaging the accounts throughout
//! (`mail.sent`, due to answered). Both go through the server's one
//! inbox hand-over lock (`InboxFlush` in `docs/metrics.md`).
//!
//! With linked servers, observers on each of them time when each arrival
//! is heard to join there (`link.join`), from when it was due, and each
//! must hear every arrival that logged in (`link.joins_heard`).
//!
//! With `devices` above one, an arrival is a person: that many
//! connections to one account, each logged in after the last, timed until
//! the last has its user list (`login.person`). An ng watcher on the
//! server counts the joins it hears, and with `grouped` each person must
//! be heard to join once, not once a device (`login.person_joins`): a
//! server that makes one row of a person's devices tells everyone else
//! half as many joins as there are logins.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;

use crate::member::{Conn, Got, Member, Parts, Rx, Tx, Wire};
use crate::stats::{self, Summary};
use crate::Ctx;

struct Step {
    rate: f64,
    latency: Histogram<u64>,
    attempted: u64,
    errors: u64,
    shed: u64,
}

#[derive(Serialize)]
struct StepReport {
    rate: f64,
    attempted: u64,
    /// Logins that did not complete. Not `errors`: the flattened latency
    /// summary has a field of that name.
    failed: u64,
    shed: u64,
    #[serde(flatten)]
    latency: Summary,
}

pub async fn run(ctx: &Arc<Ctx>) -> Result<Value, String> {
    let s = &ctx.scenario.login_storm;
    let weights = [
        (Wire::Legacy, s.legacy),
        (Wire::LegacyTls, s.legacy_tls),
        (Wire::Ng, s.ng),
    ];
    let total: u32 = weights.iter().map(|w| w.1).sum();
    if total == 0 {
        return Err("[login_storm] weighs every wire at zero".into());
    }
    let arrivals = Arc::new(Arrivals::default());
    let (done_tx, done_rx) = watch::channel(None);
    let observers = observe(ctx, &arrivals, done_rx).await?;
    let senders = seed(ctx).await?;
    let watcher = if s.devices > 1 {
        Some(watch_persons(ctx, done_tx.subscribe()).await?)
    } else {
        None
    };
    let in_flight = Arc::new(Semaphore::new(s.max_in_flight));
    let free = Arc::new(Free::new(ctx));
    let steps: Arc<Mutex<Vec<Step>>> = Arc::new(Mutex::new(Vec::new()));
    let start = ctx.t0.elapsed() + Duration::from_millis(100);
    let end = start + ctx.duration();
    let every = Duration::from_secs_f64(s.ramp_every);
    let senders = send_until(ctx, senders, start, end);
    let mut tasks = Vec::new();
    let mut due = start;
    let mut i = 0usize;
    while due < end {
        let step = ((due - start).as_secs_f64() / every.as_secs_f64()) as usize;
        let rate = s.rate + s.ramp_step * step as f64;
        {
            let mut st = steps.lock().unwrap();
            while st.len() <= step {
                let r = s.rate + s.ramp_step * st.len() as f64;
                st.push(Step {
                    rate: r,
                    latency: stats::local(),
                    attempted: 0,
                    errors: 0,
                    shed: 0,
                });
            }
        }
        tokio::time::sleep_until((ctx.t0 + due).into()).await;
        // The wire, by weight.
        let mut pick = (ctx.random() * total as f64) as u32;
        let wire = weights
            .iter()
            .find(|(_, w)| {
                if pick < *w {
                    true
                } else {
                    pick -= w;
                    false
                }
            })
            .map_or(Wire::Ng, |(w, _)| *w);
        // A person's other devices, each on a wire of its own.
        let mut wires = vec![wire];
        for _ in 1..s.devices {
            let mut pick = (ctx.random() * total as f64) as u32;
            wires.push(
                weights
                    .iter()
                    .find(|(_, w)| {
                        if pick < *w {
                            true
                        } else {
                            pick -= w;
                            false
                        }
                    })
                    .map_or(Wire::Ng, |(w, _)| *w),
            );
        }
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            steps.lock().unwrap()[step].shed += 1;
            ctx.stats.error("login.shed", "max_in_flight");
            due += Duration::from_secs_f64(1.0 / rate);
            continue;
        };
        // A person holds an account of its own until its devices have
        // left. With no more in flight than accounts one is always free;
        // were none, the arrival is the generator's to shed, as above.
        let lease = if wires.len() > 1 {
            let Some(lease) = Free::take(&free) else {
                steps.lock().unwrap()[step].shed += 1;
                ctx.stats.error("login.shed", "no_free_account");
                due += Duration::from_secs_f64(1.0 / rate);
                continue;
            };
            Some(lease)
        } else {
            None
        };
        let (ctx2, steps2, arrivals2) = (ctx.clone(), steps.clone(), arrivals.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            if let Some(lease) = lease {
                arrive_person(&ctx2, &wires, i, lease, due, step, &steps2, &arrivals2).await;
            } else {
                arrive(&ctx2, wire, i, due, step, &steps2, &arrivals2).await;
            }
        }));
        i += 1;
        due += Duration::from_secs_f64(1.0 / rate);
    }
    for t in tasks {
        let _ = t.await;
    }
    for t in senders {
        let m = t.await.expect("a sender task does not panic");
        if let Err(e) = m.leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
    let logged_in: HashSet<String> = arrivals
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, (_, ok))| *ok)
        .map(|(nick, _)| nick.clone())
        .collect();
    let _ = done_tx.send(Some(Arc::new(logged_in)));
    if let Some(w) = watcher {
        let m = w.await.expect("the watcher's task does not panic");
        if let Err(e) = m.leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
    for o in observers {
        let (tx, rx, parts) = o.await.expect("an observer task does not panic");
        if let Err(e) = Member::rejoin(tx, rx, parts).leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }

    let steps = std::mem::take(&mut *steps.lock().unwrap());
    let reports: Vec<StepReport> = steps
        .iter()
        .map(|st| StepReport {
            rate: st.rate,
            attempted: st.attempted,
            failed: st.errors,
            shed: st.shed,
            latency: Summary::of(&st.latency, &Default::default()),
        })
        .collect();
    let base = reports.first().map_or(0.0, |r| r.latency.p99_ms);
    let knee = reports.iter().find(|r| {
        r.latency.p99_ms > 2.0 * base || (r.attempted > 0 && r.failed * 100 > r.attempted)
    });
    Ok(json!({
        "steps": reports,
        "knee_rate": knee.map(|k| k.rate),
    }))
}

async fn arrive(
    ctx: &Ctx,
    wire: Wire,
    i: usize,
    due: Duration,
    step: usize,
    steps: &Mutex<Vec<Step>>,
    arrivals: &Arrivals,
) {
    let s = &ctx.scenario.login_storm;
    let creds = if s.accounts {
        ctx.scenario
            .target
            .accounts
            .as_ref()
            .map(|a| (a.login(i), a.password.clone()))
    } else {
        None
    };
    let op = format!("login.{}", wire.name());
    let nick = ctx.nick(wire.letter(), i);
    arrivals
        .0
        .lock()
        .unwrap()
        .insert(nick.clone(), (due, false));
    let joined = async {
        let mut m = Member::join(ctx, wire, i, creds).await?;
        m.nicks().await?;
        Ok::<_, hxd_testclient::Error>(m)
    }
    .await;
    let took = ctx.t0.elapsed().saturating_sub(due);
    {
        let mut st = steps.lock().unwrap();
        st[step].attempted += 1;
        match &joined {
            Ok(_) => stats::sample(&mut st[step].latency, took),
            Err(_) => st[step].errors += 1,
        }
    }
    match joined {
        Ok(m) => {
            if let Some(a) = arrivals.0.lock().unwrap().get_mut(&nick) {
                a.1 = true;
            }
            ctx.stats.record(&op, took);
            let linger = tokio::time::sleep(lingers(ctx));
            let first_login = ctx
                .scenario
                .target
                .accounts
                .as_ref()
                .is_some_and(|a| i < a.count);
            let m = if s.mail > 0 && first_login {
                let (tx, mut rx, parts) = m.split();
                tokio::pin!(linger);
                // A classic client is shown a waiting message under a
                // stamp, so the tag is looked for anywhere in it.
                let waiting = waiting(ctx);
                let heard = tokio::select! {
                    heard = async {
                        loop {
                            match rx.next().await {
                                Ok(Got::Msg(text, at)) if text.contains(&waiting) => {
                                    return Ok(at)
                                }
                                Ok(_) => {}
                                Err(e) => return Err(e.to_string()),
                            }
                        }
                    } => heard,
                    () = &mut linger => Err("no waiting message heard".into()),
                };
                match heard {
                    Ok(at) => ctx.stats.record(
                        "mail.first",
                        at.saturating_duration_since(ctx.t0).saturating_sub(due),
                    ),
                    Err(e) => ctx.stats.error("mail.first", &e),
                }
                linger.await;
                Member::rejoin(tx, rx, parts)
            } else {
                linger.await;
                m
            };
            if let Err(e) = m.leave().await {
                ctx.stats.error("leave", &e.to_string());
            }
        }
        Err(e) => ctx.stats.error(&op, &e.to_string()),
    }
}

/// How long an arrival stays: `linger`, and up to `linger_spread` more
/// picked at random, so arrivals that came in order can end out of it.
fn lingers(ctx: &Ctx) -> Duration {
    let s = &ctx.scenario.login_storm;
    Duration::from_secs_f64(s.linger + ctx.random() * s.linger_spread)
}

/// The accounts no person in flight holds. Arrivals end out of order, so
/// taking account `i % count` could hand a later arrival one an earlier
/// still holds, and its devices would join that person.
struct Free(Mutex<Vec<usize>>);

impl Free {
    fn new(ctx: &Ctx) -> Free {
        let count = ctx.scenario.target.accounts.as_ref().map_or(0, |a| a.count);
        Free(Mutex::new((0..count).rev().collect()))
    }

    fn take(free: &Arc<Free>) -> Option<Lease> {
        let account = free.0.lock().unwrap().pop()?;
        Some(Lease {
            account,
            free: free.clone(),
        })
    }
}

/// An account a person holds, back in the pool when it is dropped.
struct Lease {
    account: usize,
    free: Arc<Free>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.free.0.lock().unwrap().push(self.account);
    }
}

/// A person: one connection to its account for each of `wires`, each
/// logged in once the one before has its user list, all under one nick
/// so no device renames it. Timed until the last device is in, then all
/// linger and leave together.
#[allow(clippy::too_many_arguments)]
async fn arrive_person(
    ctx: &Ctx,
    wires: &[Wire],
    i: usize,
    lease: Lease,
    due: Duration,
    step: usize,
    steps: &Mutex<Vec<Step>>,
    arrivals: &Arrivals,
) {
    let accounts = ctx
        .scenario
        .target
        .accounts
        .as_ref()
        .expect("checked by the scenario");
    let creds = (accounts.login(lease.account), accounts.password.clone());
    let nick = ctx.nick('D', i);
    arrivals
        .0
        .lock()
        .unwrap()
        .insert(nick.clone(), (due, false));
    let mut devices = Vec::new();
    let mut failed = None;
    for wire in wires {
        let joined = async {
            let mut m = Member::join_as(ctx, *wire, nick.clone(), Some(creds.clone())).await?;
            m.nicks().await?;
            Ok::<_, hxd_testclient::Error>(m)
        }
        .await;
        match joined {
            Ok(m) => devices.push(m),
            Err(e) => {
                failed = Some(e.to_string());
                break;
            }
        }
    }
    let took = ctx.t0.elapsed().saturating_sub(due);
    {
        let mut st = steps.lock().unwrap();
        st[step].attempted += 1;
        match failed {
            None => stats::sample(&mut st[step].latency, took),
            Some(_) => st[step].errors += 1,
        }
    }
    match &failed {
        None => {
            if let Some(a) = arrivals.0.lock().unwrap().get_mut(&nick) {
                a.1 = true;
            }
            ctx.stats.record("login.person", took);
        }
        Some(e) => ctx.stats.error("login.person", e),
    }
    tokio::time::sleep(lingers(ctx)).await;
    for m in devices {
        if let Err(e) = m.leave().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
}

/// An ng watcher on the server, counting the joins it hears of each
/// person until `settle` has passed since the last arrival ended, so a
/// late join is heard too; then `login.person_joins` holds each person
/// that logged in to one join with `grouped`, or one a device without it.
async fn watch_persons(ctx: &Arc<Ctx>, mut done: Done) -> Result<JoinHandle<Member>, String> {
    let m = Member::join_as(ctx, Wire::Ng, ctx.nick('V', 0), None)
        .await
        .map_err(|e| format!("the persons' watcher could not join: {e}"))?;
    let ctx = ctx.clone();
    Ok(tokio::spawn(async move {
        let (tx, mut rx, parts) = m.split();
        let settle = Duration::from_secs_f64(ctx.scenario.run.settle);
        let mut joins: HashMap<String, u64> = HashMap::new();
        let mut deadline = None::<tokio::time::Instant>;
        loop {
            let logged_in = done.borrow().clone();
            if logged_in.is_some() {
                let d = *deadline.get_or_insert_with(|| tokio::time::Instant::now() + settle);
                if tokio::time::Instant::now() >= d {
                    break;
                }
            }
            let wait = deadline.unwrap_or_else(|| tokio::time::Instant::now() + settle);
            tokio::select! {
                changed = done.changed(), if logged_in.is_none() => if changed.is_err() { break },
                _ = tokio::time::sleep_until(wait) => {}
                got = rx.next() => match got {
                    Ok(Got::Joined { nick, .. }) => *joins.entry(nick).or_default() += 1,
                    Ok(_) => {}
                    Err(e) => {
                        ctx.checks.violated(
                            "login.person_joins",
                            format!("the persons' watcher lost its connection: {e}"),
                        );
                        break;
                    }
                },
            }
        }
        let s = &ctx.scenario.login_storm;
        let each = if s.grouped { 1 } else { s.devices as u64 };
        let all = done.borrow().clone().unwrap_or_default();
        for nick in all.iter() {
            let heard = joins.get(nick).copied().unwrap_or(0);
            ctx.checks.check("login.person_joins", heard == each, || {
                format!(
                    "{nick} on {} devices was heard to join {heard} times, not {each}",
                    s.devices
                )
            });
        }
        Member::rejoin(tx, rx, parts)
    }))
}

/// The senders, logged in to `[target] admin`, once they have sent
/// `mail` messages to every one of `[target] accounts`; none, having
/// left, when there is no `msg_rate` for them to send.
async fn seed(ctx: &Arc<Ctx>) -> Result<Vec<Member>, String> {
    let s = &ctx.scenario.login_storm;
    if s.mail == 0 && s.msg_rate == 0.0 {
        return Ok(Vec::new());
    }
    let admin = ctx
        .scenario
        .target
        .admin
        .as_ref()
        .expect("checked by the scenario");
    let count = ctx.scenario.target.accounts.as_ref().map_or(0, |a| a.count);
    let began = Instant::now();
    let mut joined = Vec::new();
    for k in 0..s.senders {
        let creds = Some((admin.login.clone(), admin.password.clone()));
        joined.push(
            Member::join_as(ctx, Wire::Ng, ctx.nick('P', k), creds)
                .await
                .map_err(|e| format!("sender {k} could not join: {e}"))?,
        );
    }
    let mut tasks = joined
        .into_iter()
        .enumerate()
        .map(|(k, mut m)| {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let waiting = waiting(&ctx);
                for j in (k..count).step_by(ctx.scenario.login_storm.senders) {
                    for n in 0..ctx.scenario.login_storm.mail {
                        send(&ctx, &mut m, j, &format!("{waiting} {n}")).await?;
                    }
                }
                Ok::<_, String>(m)
            })
        })
        .collect::<Vec<_>>()
        .into_iter();
    let mut senders = Vec::new();
    while let Some(t) = tasks.next() {
        match t.await.expect("a seeding task does not panic") {
            Ok(m) => senders.push(m),
            Err(e) => {
                tasks.for_each(|t| t.abort());
                return Err(format!("seeding: {e}"));
            }
        }
    }
    eprintln!(
        "login_storm: {} messages waiting for {count} accounts, sent in {:.1}s",
        count * s.mail,
        began.elapsed().as_secs_f64()
    );
    if s.msg_rate == 0.0 {
        for m in senders {
            if let Err(e) = m.leave().await {
                ctx.stats.error("leave", &e.to_string());
            }
        }
        return Ok(Vec::new());
    }
    Ok(senders)
}

/// The senders' share of `msg_rate` each, from `start` to `end`, each
/// timed from when it was due; each task hands its sender back.
fn send_until(
    ctx: &Arc<Ctx>,
    senders: Vec<Member>,
    start: Duration,
    end: Duration,
) -> Vec<JoinHandle<Member>> {
    let s = &ctx.scenario.login_storm;
    let n = senders.len();
    senders
        .into_iter()
        .enumerate()
        .map(|(k, mut m)| {
            let ctx = ctx.clone();
            let rate = s.msg_rate;
            tokio::spawn(async move {
                let count = ctx.scenario.target.accounts.as_ref().map_or(1, |a| a.count);
                for seq in 0.. {
                    // Compared before it is a `Duration`: a tiny rate puts
                    // the offset past what one can hold.
                    let offset = (seq * n + k) as f64 / rate;
                    if offset >= end.saturating_sub(start).as_secs_f64() {
                        break;
                    }
                    let due = start + Duration::from_secs_f64(offset);
                    if let Err(e) = drain_until(&mut m, ctx.t0 + due).await {
                        ctx.stats.error("mail.sent", &e.to_string());
                        break;
                    }
                    let to = (ctx.random() * count as f64) as usize;
                    match send(&ctx, &mut m, to, &format!("live {seq}")).await {
                        Ok(()) => ctx
                            .stats
                            .record("mail.sent", ctx.t0.elapsed().saturating_sub(due)),
                        Err(e) => ctx.stats.error("mail.sent", &e),
                    }
                }
                m
            })
        })
        .collect()
}

/// The tag every waiting message carries, unique to the run.
fn waiting(ctx: &Ctx) -> String {
    format!("{} waiting", ctx.run)
}

/// Read and drop what a sender is sent until `at`: the storm's joins and
/// parts, which a sender that stopped reading would be dropped for.
async fn drain_until(m: &mut Member, at: Instant) -> Result<(), hxd_testclient::Error> {
    let Conn::Ng(c) = &mut m.conn else {
        unreachable!("senders are ng");
    };
    drop(c.rx.take_backlog());
    let at = tokio::time::Instant::from_std(at);
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(at) => return Ok(()),
            got = c.rx.next_forever() => drop(got?),
        }
    }
}

/// A private message to account `j`, answered.
async fn send(ctx: &Ctx, m: &mut Member, j: usize, text: &str) -> Result<(), String> {
    let Conn::Ng(c) = &mut m.conn else {
        unreachable!("senders are ng");
    };
    let to = ctx
        .scenario
        .target
        .accounts
        .as_ref()
        .expect("checked by the scenario")
        .login(j);
    let sent = c
        .request("msg", json!({ "to_login": to, "text": text }))
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    // The storm's joins and parts, which are not a sender's business.
    drop(c.rx.take_backlog());
    sent
}

/// Each arrival by nick: when it was due, and whether it logged in.
#[derive(Default)]
struct Arrivals(Mutex<HashMap<String, (Duration, bool)>>);

/// The arrivals that logged in, once the last has.
type Done = watch::Receiver<Option<Arc<HashSet<String>>>>;

/// Join the observers on every linked server, each on a task that hears
/// arrivals join until it has heard every one that logged in, or
/// `settle` has passed since the last did.
async fn observe(
    ctx: &Arc<Ctx>,
    arrivals: &Arc<Arrivals>,
    done: Done,
) -> Result<Vec<JoinHandle<(Tx, Rx, Parts)>>, String> {
    let s = &ctx.scenario.login_storm;
    let mut tasks = Vec::new();
    let mut n = 0;
    for (k, server) in ctx.servers.iter().enumerate().skip(1) {
        for wire in std::iter::repeat_n(Wire::Legacy, s.observers_legacy)
            .chain(std::iter::repeat_n(Wire::Ng, s.observers_ng))
        {
            let m = Member::join_at(ctx, server, wire, ctx.nick('W', n), None)
                .await
                .map_err(|e| format!("observer {n} on {} could not join: {e}", server.name))?;
            n += 1;
            let (tx, rx, parts) = m.split();
            let (ctx, arrivals, done) = (ctx.clone(), arrivals.clone(), done.clone());
            tasks.push(tokio::spawn(async move {
                let rx = watch_joins(&ctx, rx, &parts, k, &arrivals, done).await;
                (tx, rx, parts)
            }));
        }
    }
    Ok(tasks)
}

async fn watch_joins(
    ctx: &Ctx,
    mut rx: Rx,
    parts: &Parts,
    k: usize,
    arrivals: &Arrivals,
    mut done: Done,
) -> Rx {
    let settle = Duration::from_secs_f64(ctx.scenario.run.settle);
    let mut heard = HashSet::new();
    let mut latency = stats::local();
    let mut deadline = None::<tokio::time::Instant>;
    loop {
        let logged_in = done.borrow().clone();
        if let Some(all) = &logged_in {
            if all.is_subset(&heard) {
                break;
            }
            let d = *deadline.get_or_insert_with(|| tokio::time::Instant::now() + settle);
            if tokio::time::Instant::now() >= d {
                break;
            }
        }
        let wait = deadline.unwrap_or_else(|| tokio::time::Instant::now() + settle);
        tokio::select! {
            // The run gave up before the last arrival: nothing left to hear.
            changed = done.changed(), if logged_in.is_none() => if changed.is_err() { break },
            _ = tokio::time::sleep_until(wait) => {}
            got = rx.next() => match got {
                Ok(Got::Joined { nick, .. }) => {
                    let due = arrivals.0.lock().unwrap().get(&nick).map(|a| a.0);
                    if let Some(due) = due.filter(|_| heard.insert(nick)) {
                        stats::sample(&mut latency, ctx.t0.elapsed().saturating_sub(due));
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    ctx.checks.violated(
                        "link.joins_heard",
                        format!("{} lost its connection: {e}", parts.nick),
                    );
                    break;
                }
            },
        }
    }
    ctx.stats.merge("link.join", &latency);
    let all = done.borrow().clone().unwrap_or_default();
    let missed = all.difference(&heard).count();
    ctx.checks.check("link.joins_heard", missed == 0, || {
        format!(
            "{} on {} heard {} of {} arrivals join",
            parts.nick,
            ctx.servers[k].name,
            all.len() - missed,
            all.len()
        )
    });
    rx
}
