//! R-1, a reaction storm: ng clients reacting to the room's most recent
//! lines as fast as they are let, while others read and a few stop
//! reading altogether.
//!
//! Whatever the rate, a reader is owed one `reactions_changed` per batch
//! at most, its seqs stay gapless, and once the storm is over each line's
//! last summary it heard is the line as `history` shows it. A client that
//! stops reading is sent one batch a window, not one event a reaction, so
//! what waits for it grows with time and not with the storm.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hxd_testclient::ng::{self, Incoming};
use hxd_testclient::Error;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::member;
use crate::Ctx;

/// The reaction keys a storm picks from.
const KEYS: &[&str] = &["\u{1F44D}", "\u{1F389}", "\u{1F525}", "\u{1F440}"];

/// How long the stalled clients are read from afterwards.
const PROBE_FOR: Duration = Duration::from_secs(5);

/// One client's summaries, line by line, as last heard.
type Heard = HashMap<u64, Value>;

pub async fn run(ctx: &Arc<Ctx>) -> Result<Value, String> {
    let r = &ctx.scenario.reactions;
    let accounts = ctx
        .scenario
        .target
        .accounts
        .clone()
        .ok_or("[reactions] needs [target] accounts")?;
    let mut reactors = Vec::new();
    for i in 0..r.reactors {
        let creds = (format!("{}{i}", accounts.prefix), accounts.password.clone());
        reactors.push(join(ctx, ctx.nick('R', i), Some(creds)).await?);
    }
    let mut readers = Vec::new();
    for i in 0..r.readers {
        readers.push(join(ctx, ctx.nick('N', i), None).await?);
    }
    let mut stalled = Vec::new();
    for i in 0..r.stalled {
        stalled.push(join(ctx, ctx.nick('S', i), None).await?);
    }
    let mut lines = Vec::new();
    for n in 0..r.lines {
        let said = reactors[0]
            .request("chat", json!({ "text": format!("{} line {n}", ctx.run) }))
            .await
            .map_err(|e| format!("a line was not said: {e}"))?;
        lines.push(said["id"].as_u64().ok_or("a line without an id")?);
    }
    let started = Instant::now();
    // From here on the stalled read nothing until the probe.
    let stalled: Vec<_> = stalled.into_iter().map(|c| c.split()).collect();

    let (stop, stopped) = watch::channel(false);
    let mut readings = Vec::new();
    let mut senders = Vec::new();
    for c in readers.into_iter().chain(reactors) {
        let (tx, rx) = c.split();
        readings.push(tokio::spawn(read(ctx.clone(), rx, stopped.clone())));
        senders.push(tx);
    }
    let every = Duration::from_secs_f64(r.reactors as f64 / r.rate);
    let mut storms = Vec::new();
    for (k, tx) in senders.drain(r.readers..).enumerate() {
        let offset = every.mul_f64(k as f64 / r.reactors as f64);
        storms.push(tokio::spawn(storm(
            ctx.clone(),
            tx,
            lines.clone(),
            offset,
            every,
        )));
    }
    let mut sent = 0;
    for s in storms {
        let (tx, n) = s.await.expect("a reactor task does not panic");
        sent += n;
        senders.push(tx);
    }
    // Every batch owed by the storm's end goes within a batch or two.
    let settle = Duration::from_secs_f64(r.batch * 2.0 + ctx.scenario.run.settle);
    tokio::time::sleep(settle).await;
    let _ = stop.send(true);

    let mut heard = Vec::new();
    for (reading, tx) in readings.into_iter().zip(senders) {
        let (rx, h) = reading.await.expect("a reader task does not panic");
        heard.push(h);
        let c = ng::Client {
            tx,
            rx,
            session: None,
            uid: None,
        };
        if let Err(e) = c.logout().await {
            ctx.stats.error("leave", &e.to_string());
        }
    }
    let observer = (format!("{}0", accounts.prefix), accounts.password.clone());
    converged(ctx, observer, &lines, &heard).await;

    let elapsed = started.elapsed();
    let mut probed = Vec::new();
    for (tx, rx) in stalled {
        let (closed, batches) = probe(rx).await;
        // One batch a window, whatever the storm: a backlog the reaction
        // rate could grow would have more.
        let most = (elapsed.as_secs_f64() / r.batch).ceil() as u64 + 1;
        ctx.checks
            .check("reactions.backlog_bounded", batches <= most, || {
                format!("a stalled client was owed {batches} batches in {elapsed:?}, past {most}")
            });
        probed.push(json!({ "disconnected": closed, "batches": batches }));
        drop(tx);
    }
    Ok(json!({ "reactions_sent": sent, "lines": lines.len(), "stalled": probed }))
}

/// An ng client that declared reactions, logged in to `creds` or as a
/// guest.
async fn join(
    ctx: &Ctx,
    nick: String,
    creds: Option<(String, String)>,
) -> Result<ng::Client, String> {
    let at = ctx.scenario.target.ng.expect("checked by the scenario");
    let mut params = json!({ "nick": nick, "reactions": true, "replies": true });
    if let Some((login, password)) = creds {
        params["login"] = json!(login);
        params["password"] = json!(password);
    }
    member::retry_busy(ctx, || {
        let params = params.clone();
        async move {
            let mut c = ng::Client::connect(at).await?;
            c.login(params).await?;
            Ok::<_, Error>(c)
        }
    })
    .await
    .map_err(|e| format!("{nick} could not join: {e}"))
}

/// React on schedule until the run's duration is up: reaction `n` due at
/// `offset + n * every`, a key on one of `lines` added, or taken away
/// where this reactor last added it. Answers how many were sent.
async fn storm(
    ctx: Arc<Ctx>,
    mut tx: ng::Sender,
    lines: Vec<u64>,
    offset: Duration,
    every: Duration,
) -> (ng::Sender, u64) {
    let start = ctx.t0.elapsed() + offset;
    let end = start + ctx.duration();
    let mut held: HashMap<(u64, usize), bool> = HashMap::new();
    let mut n = 0u64;
    loop {
        let due = start + every.mul_f64(n as f64);
        if due >= end {
            break;
        }
        tokio::time::sleep_until((ctx.t0 + due).into()).await;
        let line = lines[(ctx.random() * lines.len() as f64) as usize % lines.len()];
        let key = (ctx.random() * KEYS.len() as f64) as usize % KEYS.len();
        let had = held.entry((line, key)).or_default();
        let params = json!({
            "target": { "line": line },
            "key": { "emoji": KEYS[key] },
            "remove": *had,
        });
        *had = !*had;
        match tx.send("react", params).await {
            Ok(_) => n += 1,
            Err(e) => {
                ctx.stats.error("reactions.react", &e.to_string());
                break;
            }
        }
    }
    (tx, n)
}

/// Read until told to stop: the summaries each line was last given, and
/// no two batches less than a batch apart. Refused reactions are the
/// reactors' errors, which a rate the server's own outpaces will have.
async fn read(
    ctx: Arc<Ctx>,
    mut rx: ng::Receiver,
    mut stop: watch::Receiver<bool>,
) -> (ng::Receiver, Heard) {
    let batch = Duration::from_secs_f64(ctx.scenario.reactions.batch);
    let mut heard = Heard::new();
    let mut last: Option<Instant> = None;
    loop {
        let got = tokio::select! {
            _ = stop.changed() => break,
            got = rx.next_forever() => got,
        };
        match got {
            Ok(Incoming::Event(e)) if e.ev == "reactions_changed" => {
                let now = Instant::now();
                if let Some(before) = last {
                    let gap = now - before;
                    ctx.checks.check(
                        "reactions.one_per_window",
                        // The server spaces them a whole batch; half
                        // leaves room for a busy host delivering one late.
                        gap * 2 >= batch,
                        || format!("two batches {gap:?} apart"),
                    );
                }
                last = Some(now);
                for g in e.data["changes"].as_array().into_iter().flatten() {
                    if let Some(line) = g["target"]["line"].as_u64() {
                        heard.insert(line, g["keys"].clone());
                    }
                }
            }
            Ok(Incoming::Reply(v)) if v.get("error").is_some() => {
                ctx.stats
                    .error("reactions.react", &v["error"]["code"].to_string());
            }
            Ok(_) => {}
            Err(e) => {
                ctx.checks.violated(
                    "reactions.stayed",
                    format!("a reader lost its connection: {e}"),
                );
                break;
            }
        }
    }
    let faults = &rx.seq_faults;
    ctx.checks.check("ng.seq_gapless", faults.is_empty(), || {
        format!("{faults:?}")
    });
    (rx, heard)
}

/// Every reader's last summary of each line is the line as `history`
/// shows it once the storm has passed: no change lost, none told out of
/// order.
async fn converged(ctx: &Ctx, creds: (String, String), lines: &[u64], heard: &[Heard]) {
    // Unchecked is not held: a run that could not look fails.
    let mut observer = match join(ctx, ctx.nick('V', 0), Some(creds)).await {
        Ok(c) => c,
        Err(e) => return ctx.checks.violated("reactions.converged", e),
    };
    let shown = match observer.request("history", json!({ "ids": lines })).await {
        Ok(v) => v,
        Err(e) => {
            let _ = observer.logout().await;
            let why = format!("history could not be read: {e}");
            return ctx.checks.violated("reactions.converged", why);
        }
    };
    let _ = observer.logout().await;
    let kept: HashMap<u64, Value> = (shown["lines"].as_array().into_iter().flatten())
        .filter_map(|l| Some((l["id"].as_u64()?, l["reactions"].clone())))
        .collect();
    for h in heard {
        for line in lines {
            let want = kept.get(line).filter(|v| !v.is_null());
            let got = h
                .get(line)
                .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()));
            ctx.checks.check("reactions.converged", want == got, || {
                format!("line {line}: history has {want:?}, a reader last heard {got:?}")
            });
        }
    }
}

/// Read what the server still has for a stalled client, until it hangs
/// up or goes quiet: whether it hung up, and how many batches waited.
async fn probe(mut rx: ng::Receiver) -> (bool, u64) {
    let until = tokio::time::Instant::now() + PROBE_FOR;
    let mut batches = 0;
    loop {
        let quiet = tokio::time::Instant::now() + Duration::from_millis(500);
        match tokio::time::timeout_at(quiet.min(until), rx.next_forever()).await {
            Err(_) => return (false, batches),
            Ok(Ok(Incoming::Event(e))) if e.ev == "reactions_changed" => batches += 1,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return (true, batches),
        }
    }
}
