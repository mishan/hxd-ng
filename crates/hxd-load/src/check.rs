//! The invariants a run checks, and what it found.
//!
//! A check is named, counts how many times it held, and keeps the first
//! few violations word for word. A run with any violation fails: the
//! point of loading a server is to find what only breaks under load, and
//! a number that looks fine beside a line delivered twice is not fine.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::Serialize;

/// How many violations of one check are kept verbatim.
const EXAMPLES: usize = 10;

#[derive(Default)]
pub struct Checks {
    checks: Mutex<BTreeMap<String, Check>>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Check {
    pub held: u64,
    pub violated: u64,
    pub examples: Vec<String>,
}

impl Checks {
    pub fn held(&self, name: &str) {
        self.held_n(name, 1);
    }

    pub fn held_n(&self, name: &str, n: u64) {
        let mut c = self.checks.lock().unwrap();
        c.entry(name.to_owned()).or_default().held += n;
    }

    pub fn violated(&self, name: &str, what: impl Into<String>) {
        let mut c = self.checks.lock().unwrap();
        let check = c.entry(name.to_owned()).or_default();
        check.violated += 1;
        if check.examples.len() < EXAMPLES {
            check.examples.push(what.into());
        }
    }

    /// `held` or `violated`, by `ok`.
    pub fn check(&self, name: &str, ok: bool, what: impl FnOnce() -> String) {
        if ok {
            self.held(name);
        } else {
            self.violated(name, what());
        }
    }

    pub fn violations(&self) -> u64 {
        self.checks
            .lock()
            .unwrap()
            .values()
            .map(|c| c.violated)
            .sum()
    }

    pub fn report(&self) -> BTreeMap<String, Check> {
        self.checks.lock().unwrap().clone()
    }
}
