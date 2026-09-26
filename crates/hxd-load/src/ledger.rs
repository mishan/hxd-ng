//! Chat lines, tagged so that every reader can account for every one.
//!
//! A line carries `lt:<run>:<sender>:<seq>:<due>` and padding: the run's
//! tag (so other traffic on the server is ignored), the sending client,
//! that client's own count from 1, and when the line was due, in
//! microseconds since the run's clock started. One clock, in one process,
//! so a reader can take a line's latency from its tag alone.
//!
//! A reader keeps, per sender, the last seq it heard. The next must be
//! one more: less is a line heard twice or out of order, more is lines
//! missing. At the end every reader must have heard every line every
//! sender sent — membership is fixed for the whole run, so there is no
//! excuse for a gap.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;

use crate::check::Checks;
use crate::stats;

pub fn line(run: &str, sender: usize, seq: u64, due: Duration, pad: usize) -> String {
    let mut s = format!("lt:{run}:{sender}:{seq}:{} ", due.as_micros());
    s.extend(std::iter::repeat_n('x', pad));
    s
}

/// `(sender, seq, due)` from a line of this run, found anywhere in `text`
/// (the classic wire prefixes the sender's nick).
pub fn parse(run: &str, text: &str) -> Option<(usize, u64, Duration)> {
    let tag = format!("lt:{run}:");
    let rest = &text[text.find(&tag)? + tag.len()..];
    let mut parts = rest.splitn(4, [':', ' ']);
    let sender = parts.next()?.parse().ok()?;
    let seq = parts.next()?.parse().ok()?;
    let due = Duration::from_micros(parts.next()?.parse().ok()?);
    Some((sender, seq, due))
}

/// One reader's account of what it heard.
pub struct Heard {
    pub me: String,
    /// When this reader is also a sender, its own id: its echo is timed
    /// separately.
    pub own: Option<usize>,
    last: HashMap<usize, u64>,
    pub delivery: Histogram<u64>,
    pub echo: Histogram<u64>,
}

impl Heard {
    pub fn new(me: String, own: Option<usize>) -> Heard {
        Heard {
            me,
            own,
            last: HashMap::new(),
            delivery: stats::local(),
            echo: stats::local(),
        }
    }

    /// A chat line arrived; `t0` is the run's clock.
    pub fn hear(&mut self, run: &str, text: &str, t0: Instant, checks: &Checks) {
        let Some((sender, seq, due)) = parse(run, text) else {
            return;
        };
        let late = t0.elapsed().saturating_sub(due);
        if self.own == Some(sender) {
            stats::sample(&mut self.echo, late);
        }
        stats::sample(&mut self.delivery, late);
        let last = self.last.entry(sender).or_insert(0);
        if seq == *last + 1 {
            checks.held("chat.in_order_once");
        } else if seq <= *last {
            checks.violated(
                "chat.in_order_once",
                format!(
                    "{} heard sender {sender}'s line {seq} after line {last}",
                    self.me
                ),
            );
        } else {
            checks.violated(
                "chat.in_order_once",
                format!(
                    "{} heard sender {sender}'s line {seq} after line {last}: {} missing",
                    self.me,
                    seq - *last - 1
                ),
            );
        }
        *last = (*last).max(seq);
    }

    /// Whether every line in `sent` has been heard.
    pub fn has_all(&self, sent: &[u64]) -> bool {
        sent.iter()
            .enumerate()
            .all(|(s, &n)| self.last.get(&s).copied().unwrap_or(0) >= n)
    }

    /// At the end: every line of every sender, all of them heard.
    pub fn account(&self, sent: &[u64], checks: &Checks) {
        for (sender, &n) in sent.iter().enumerate() {
            let got = self.last.get(&sender).copied().unwrap_or(0);
            checks.check("chat.all_heard", got == n, || {
                format!("{} heard {got} of sender {sender}'s {n} lines", self.me)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_parses_back_from_inside_a_classic_chat_body() {
        let l = line("r1", 3, 17, Duration::from_micros(123456), 4);
        let body = format!("\r        alice:  {l}");
        assert_eq!(
            parse("r1", &body),
            Some((3, 17, Duration::from_micros(123456)))
        );
        assert_eq!(parse("r2", &body), None);
    }

    #[test]
    fn a_duplicate_and_a_gap_are_both_violations() {
        let checks = Checks::default();
        let t0 = Instant::now();
        let mut h = Heard::new("reader".into(), None);
        for seq in [1, 2, 2, 5] {
            h.hear("r", &line("r", 0, seq, Duration::ZERO, 0), t0, &checks);
        }
        let r = checks.report();
        assert_eq!(r["chat.in_order_once"].held, 2);
        assert_eq!(r["chat.in_order_once"].violated, 2);
        h.account(&[6], &checks);
        assert_eq!(checks.report()["chat.all_heard"].violated, 1);
    }
}
