//! Inbound rate policing: what one publisher may make the room carry.
//!
//! An SFU multiplies. Every packet a publisher sends is written once per
//! listener, so a client that ignores its `b=AS` ceiling and sends ten
//! times what it was told costs the server ten times that for each other
//! person in the room — and the ceiling is only advertised, never
//! trusted. So each inbound stream (a peer's audio, and each of its
//! video publications) passes through a token bucket before it is
//! forwarded, and what arrives beyond it is dropped rather than
//! multiplied.
//!
//! **The rate is a multiple of the ceiling, not the ceiling.** An encoder
//! aims at its target on average and overshoots it in the short term — a
//! VP8 keyframe is several times the size of the frames either side of
//! it, and congestion control probes above its estimate before settling
//! — and `b=AS` is a figure the client's own stack rounds and pads. A
//! policer at exactly the ceiling would drop honest traffic every time
//! a keyframe landed. [`DEFAULT_FACTOR`] is the headroom that absorbs
//! that and nothing more: an encoder that respects its ceiling never
//! touches it, and one that doesn't is held to half again what it was
//! promised. The bucket holds a second of that rate, so a keyframe
//! arriving on top of a steady stream fits.
//!
//! **Dropping is packet-level and asks for nothing.** A dropped packet
//! breaks the frame it belonged to, and each receiver's own stack
//! notices the sequence gap and asks for a keyframe, which the SFU
//! relays at most once a second per publication. The policer does not
//! ask on its own account: a keyframe is the largest thing a publisher
//! sends, and requesting one the moment a stream was policed is how a
//! policer and an encoder talk each other into a loop.
//!
//! **A stream that stays far over is ended.** Dropping protects the
//! room, but a publisher sending at several times its rate for seconds
//! on end is not an encoder overshooting; it is spending the server's
//! inbound bandwidth and decryption for nothing. [`Verdict::End`] says
//! so, and the SFU ends the stream: the publication, for video, since
//! losing video is a degradation and never a reason to end the call —
//! or the voice session, for audio, which has no smaller unit to lose.

use std::time::{Duration, Instant};

/// The default headroom over a stream's ceiling. See the module note.
pub const DEFAULT_FACTOR: f64 = 1.5;

/// What PCMU carries, in bits per second of payload: 8000 samples a
/// second of one byte each. Fixed by the codec rather than configured.
pub const PCMU_BITRATE: u32 = 64_000;

/// What an RTP packet costs beyond its payload, counted so a flood of
/// tiny packets is not free. The fixed header; extensions and SRTP's tag
/// make the real figure larger, which only makes this generous.
pub const RTP_HEADER_BYTES: usize = 12;

/// How much of the policed rate the bucket holds: one second's worth.
const DEPTH: Duration = Duration::from_secs(1);

/// The window over which a stream's arrival rate is judged for ending.
const WINDOW: Duration = Duration::from_secs(1);

/// "Far over": arriving at this multiple of the policed rate, which with
/// the default factor is three times the ceiling. Well past anything an
/// encoder does by accident.
const FAR_OVER: f64 = 2.0;

/// Consecutive windows far over before the stream is ended. Long enough
/// that a burst — a screen share of a scrolling page, a network that
/// held packets and released them at once — never reaches it.
const STRIKES: u32 = 10;

/// What to do with one inbound packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Within the rate: forward it.
    Pass,
    /// Over the rate: drop it.
    Drop,
    /// Dropped, and the stream has been far over for long enough that it
    /// should be ended.
    End,
}

/// One inbound stream's bucket, and the record of how far over it has
/// been lately.
#[derive(Debug, Clone)]
pub struct Policer {
    /// Bytes per second admitted; zero is no policing at all.
    rate: f64,
    depth: f64,
    tokens: f64,
    at: Option<Instant>,
    window_start: Option<Instant>,
    window_bytes: f64,
    strikes: u32,
}

impl Policer {
    /// A policer for a stream whose ceiling is `bitrate` bits per second,
    /// admitting `factor` times it. A factor of zero, or a ceiling of
    /// zero, polices nothing.
    pub fn new(bitrate: u32, factor: f64) -> Policer {
        let rate = if factor > 0.0 && factor.is_finite() {
            f64::from(bitrate) / 8.0 * factor
        } else {
            0.0
        };
        let depth = rate * DEPTH.as_secs_f64();
        Policer {
            rate,
            depth,
            tokens: depth,
            at: None,
            window_start: None,
            window_bytes: 0.0,
            strikes: 0,
        }
    }

    /// A policer that admits everything.
    pub fn off() -> Policer {
        Policer::new(0, 0.0)
    }

    /// Account for one packet of `bytes` (payload and header) arriving
    /// at `now`.
    pub fn admit(&mut self, bytes: usize, now: Instant) -> Verdict {
        if self.rate <= 0.0 {
            return Verdict::Pass;
        }
        let bytes = bytes as f64;
        let far_over = self.judge(bytes, now);
        let elapsed = self
            .at
            .map_or(0.0, |t| now.saturating_duration_since(t).as_secs_f64());
        self.tokens = (self.tokens + elapsed * self.rate).min(self.depth);
        self.at = Some(now);
        if self.tokens >= bytes {
            self.tokens -= bytes;
            return Verdict::Pass;
        }
        if far_over {
            Verdict::End
        } else {
            Verdict::Drop
        }
    }

    /// Count `bytes` into the current window, closing it first if it has
    /// run its length. Returns whether the stream has now been far over
    /// for [`STRIKES`] windows in a row.
    ///
    /// A window is judged on what arrived over the time it actually
    /// spanned, so a stream that went quiet between two packets is judged
    /// on the quiet too and a gap is never a strike.
    fn judge(&mut self, bytes: f64, now: Instant) -> bool {
        let start = *self.window_start.get_or_insert(now);
        let span = now.saturating_duration_since(start);
        if span >= WINDOW {
            let allowed = FAR_OVER * self.rate * span.as_secs_f64();
            if self.window_bytes > allowed {
                self.strikes += 1;
            } else {
                self.strikes = 0;
            }
            self.window_start = Some(now);
            self.window_bytes = 0.0;
        }
        self.window_bytes += bytes;
        self.strikes >= STRIKES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    /// A stream of `size`-byte packets, `per_second` of them, for
    /// `seconds`, through `p`: how many of each verdict it drew.
    fn stream(
        p: &mut Policer,
        t0: Instant,
        size: usize,
        per_second: u32,
        seconds: u32,
    ) -> (u32, u32, u32) {
        let (mut pass, mut drop, mut end) = (0, 0, 0);
        let gap = Duration::from_secs(1) / per_second;
        for i in 0..per_second * seconds {
            match p.admit(size, t0 + gap * i) {
                Verdict::Pass => pass += 1,
                Verdict::Drop => drop += 1,
                Verdict::End => end += 1,
            }
        }
        (pass, drop, end)
    }

    #[test]
    fn a_stream_within_its_ceiling_is_never_touched() {
        // PCMU at 20 ms: fifty packets a second of 160 bytes, which is
        // the ceiling exactly once the header is counted too.
        let mut p = Policer::new(PCMU_BITRATE, DEFAULT_FACTOR);
        let (pass, drop, end) = stream(&mut p, Instant::now(), 160 + RTP_HEADER_BYTES, 50, 30);
        assert_eq!((pass, drop, end), (1500, 0, 0));
    }

    #[test]
    fn a_keyframe_on_top_of_a_steady_stream_fits_in_the_bucket() {
        // A camera at its ceiling, and then a keyframe several times a
        // second's worth of frames at once: the burst the headroom is for.
        let mut p = Policer::new(1_500_000, DEFAULT_FACTOR);
        let t0 = Instant::now();
        let (_, drop, _) = stream(&mut p, t0, 1200, 150, 5);
        assert_eq!(drop, 0);
        let at = t0 + Duration::from_secs(5);
        for i in 0..100 {
            assert_eq!(p.admit(1200, at + MS * i / 10), Verdict::Pass, "packet {i}");
        }
    }

    #[test]
    fn packets_over_the_budget_are_dropped_and_under_it_forwarded() {
        // Twice the ceiling: a third of it over the policed rate. Once
        // the second's worth in the bucket is spent, what passes is the
        // policed rate and the rest is dropped.
        let mut p = Policer::new(PCMU_BITRATE, DEFAULT_FACTOR);
        let size = 160;
        let (pass, drop, end) = stream(&mut p, Instant::now(), size, 100, 20);
        assert_eq!(end, 0, "twice the ceiling is over, not far over");
        let admitted = f64::from(pass) * size as f64;
        let policed = f64::from(PCMU_BITRATE) / 8.0 * DEFAULT_FACTOR;
        // Twenty seconds of the rate plus the bucket, near enough.
        let expected = policed * 21.0;
        assert!(
            (admitted - expected).abs() < expected * 0.02,
            "admitted {admitted} bytes against {expected}"
        );
        assert!(drop > 400, "dropped only {drop}");
        // And the moment the stream comes back within its rate, it all
        // passes again.
        let t = Instant::now() + Duration::from_secs(21);
        let (_, drop, _) = stream(&mut p, t, size, 50, 5);
        assert_eq!(drop, 0);
    }

    #[test]
    fn a_stream_far_over_for_long_enough_is_ended() {
        let mut p = Policer::new(PCMU_BITRATE, DEFAULT_FACTOR);
        let t0 = Instant::now();
        // Ten times the ceiling. A few seconds of it is dropped, not
        // ended: a burst is not a pattern.
        let (_, drop, end) = stream(&mut p, t0, 800, 100, 5);
        assert!(drop > 0);
        assert_eq!(end, 0, "five seconds is not sustained");
        // Kept up, it is.
        let (_, _, end) = stream(&mut p, t0 + Duration::from_secs(5), 800, 100, 10);
        assert!(end > 0, "ten more seconds far over ends the stream");
    }

    #[test]
    fn a_gap_is_never_a_strike() {
        let mut p = Policer::new(PCMU_BITRATE, DEFAULT_FACTOR);
        let t0 = Instant::now();
        // A burst far over, then silence, then another: each window is
        // judged over the time it really spanned.
        for round in 0..20u32 {
            let at = t0 + Duration::from_secs(10) * round;
            for i in 0..50u32 {
                assert_ne!(p.admit(800, at + MS * i), Verdict::End, "round {round}");
            }
        }
    }

    #[test]
    fn a_factor_of_zero_polices_nothing() {
        let mut p = Policer::new(PCMU_BITRATE, 0.0);
        let (_, drop, end) = stream(&mut p, Instant::now(), 1400, 1000, 20);
        assert_eq!((drop, end), (0, 0));
        let mut p = Policer::off();
        assert_eq!(p.admit(usize::MAX / 2, Instant::now()), Verdict::Pass);
    }
}
