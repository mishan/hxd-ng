//! S1, the login storm: arrivals at a rising rate, each one a whole
//! classic or ng login — connect, log in, agree, fetch the user list —
//! timed from when it was due. The client lingers a moment and leaves,
//! so the population stays bounded and what is measured is the login.
//!
//! The rate steps up every `ramp_every` seconds, and each step is
//! reported on its own. The knee is the first step whose p99 is more
//! than twice the first step's, or whose errors pass one in a hundred.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hdrhistogram::Histogram;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::member::{Member, Wire};
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
    let in_flight = Arc::new(Semaphore::new(s.max_in_flight));
    let steps: Arc<Mutex<Vec<Step>>> = Arc::new(Mutex::new(Vec::new()));
    let start = ctx.t0.elapsed() + Duration::from_millis(100);
    let end = start + ctx.duration();
    let every = Duration::from_secs_f64(s.ramp_every);
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
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            steps.lock().unwrap()[step].shed += 1;
            ctx.stats.error("login.shed", "max_in_flight");
            due += Duration::from_secs_f64(1.0 / rate);
            continue;
        };
        let (ctx2, steps2) = (ctx.clone(), steps.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            arrive(&ctx2, wire, i, due, step, &steps2).await;
        }));
        i += 1;
        due += Duration::from_secs_f64(1.0 / rate);
    }
    for t in tasks {
        let _ = t.await;
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
            ctx.stats.record(&op, took);
            tokio::time::sleep(Duration::from_secs_f64(s.linger)).await;
            if let Err(e) = m.leave().await {
                ctx.stats.error("leave", &e.to_string());
            }
        }
        Err(e) => ctx.stats.error(&op, &e.to_string()),
    }
}
