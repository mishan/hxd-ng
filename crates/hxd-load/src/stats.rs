//! Latencies and counts, per operation.
//!
//! A latency is measured from when the operation was *due*, not from
//! when it was sent: an arrival schedule is fixed in advance, so a server
//! that stalls shows up as latency rather than as a generator that
//! quietly sent less (coordinated omission).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use hdrhistogram::Histogram;
use serde::Serialize;

/// Microseconds, one to an hour, three significant figures.
fn histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 3_600_000_000, 3).expect("bounds are valid")
}

#[derive(Default)]
pub struct Stats {
    ops: Mutex<BTreeMap<String, Op>>,
}

struct Op {
    latency: Histogram<u64>,
    errors: BTreeMap<String, u64>,
}

impl Default for Op {
    fn default() -> Self {
        Op {
            latency: histogram(),
            errors: BTreeMap::new(),
        }
    }
}

impl Stats {
    pub fn record(&self, op: &str, took: Duration) {
        let us = took.as_micros().clamp(1, 3_600_000_000) as u64;
        let mut ops = self.ops.lock().unwrap();
        let o = ops.entry(op.to_owned()).or_default();
        o.latency.saturating_record(us);
    }

    /// Many samples at once, from a task that kept its own histogram.
    pub fn merge(&self, op: &str, h: &Histogram<u64>) {
        let mut ops = self.ops.lock().unwrap();
        let o = ops.entry(op.to_owned()).or_default();
        let _ = o.latency.add(h);
    }

    pub fn error(&self, op: &str, what: &str) {
        let mut ops = self.ops.lock().unwrap();
        let o = ops.entry(op.to_owned()).or_default();
        *o.errors.entry(what.to_owned()).or_default() += 1;
    }

    pub fn count(&self, op: &str) -> u64 {
        self.ops
            .lock()
            .unwrap()
            .get(op)
            .map_or(0, |o| o.latency.len())
    }

    pub fn errors(&self, op: &str) -> u64 {
        self.ops
            .lock()
            .unwrap()
            .get(op)
            .map_or(0, |o| o.errors.values().sum())
    }

    pub fn summary(&self) -> BTreeMap<String, Summary> {
        self.ops
            .lock()
            .unwrap()
            .iter()
            .map(|(k, o)| (k.clone(), Summary::of(&o.latency, &o.errors)))
            .collect()
    }
}

/// One operation's numbers, in milliseconds.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub count: u64,
    pub errors: BTreeMap<String, u64>,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
}

impl Summary {
    pub fn of(h: &Histogram<u64>, errors: &BTreeMap<String, u64>) -> Summary {
        let ms = |us: u64| us as f64 / 1000.0;
        let q = |q: f64| {
            if h.is_empty() {
                0.0
            } else {
                ms(h.value_at_quantile(q))
            }
        };
        Summary {
            count: h.len(),
            errors: errors.clone(),
            mean_ms: if h.is_empty() { 0.0 } else { h.mean() / 1000.0 },
            p50_ms: q(0.5),
            p90_ms: q(0.9),
            p99_ms: q(0.99),
            p999_ms: q(0.999),
            max_ms: if h.is_empty() { 0.0 } else { ms(h.max()) },
        }
    }
}

/// A histogram a task keeps for itself and merges at the end, so the hot
/// path takes no shared lock.
pub fn local() -> Histogram<u64> {
    histogram()
}

pub fn sample(h: &mut Histogram<u64>, took: Duration) {
    h.saturating_record(took.as_micros().clamp(1, 3_600_000_000) as u64);
}
