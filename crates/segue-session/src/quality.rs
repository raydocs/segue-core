//! Per-exit path quality from session-layer evidence.
//!
//! The kernel picks an exit for a new session. Up/down is not enough on a
//! lossy path (WAN findings 2026-11-18: two exits can both be "up" while
//! one loses a tenth of its carriers), so the session layer measures the
//! path and the kernel scores it:
//!
//! - **RTT** from the control stream's PING/PONG round trips
//!   ([`QualityTracker::on_rtt`]), smoothed with the TCP SRTT weight.
//! - **Loss** from bytes replayed onto a new carrier after a carrier died
//!   ([`QualityTracker::on_replay`]): the fraction of sent bytes the path
//!   made us send twice, aged on the PING clock so a clean path recovers.
//! - **Stalls** from carrier deaths with something expected on them
//!   ([`QualityTracker::on_carrier_lost`]).
//!
//! The tracker is a plain accumulator: the sans-IO client and the control
//! stream feed it, and [`QualityTracker::snapshot`] is what the kernel
//! reads. It never blocks and holds no clock: the control PING is its
//! clock, and each RTT sample also ages the loss estimate, so a burst of
//! loss on a path that has since been clean fades instead of penalising
//! the exit for the kernel's whole lifetime (a roaming client changes
//! paths often).

use std::time::Duration;

/// Weight of a new RTT sample in the smoothed RTT (the TCP SRTT alpha).
const RTT_ALPHA: f64 = 0.125;

/// Per control-PING EWMA decay factor applied to both sent and replayed byte
/// counters. With the default 5 s PING period this is a ~33 s half-life: old
/// traffic ages out symmetrically so clean periods heal past loss and new loss
/// stays observable even after gigabytes of prior clean transfer.
const LOSS_DECAY: f64 = 0.9;

/// A snapshot of one path's measured quality.
///
/// `Default` is "no evidence yet": no RTT sample, no loss, no stalls. The
/// kernel treats that as a tie and falls back to config order.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Quality {
    /// Smoothed RTT from control PING/PONG, `None` until the first sample.
    pub srtt: Option<Duration>,
    /// Fraction of sent bytes that had to be replayed, in `[0, 1]`.
    pub loss: f64,
    /// Carrier deaths counted (a carrier given up with something expected
    /// on it).
    pub stalls: u64,
}

impl Quality {
    /// Whether this snapshot carries any measurement at all.
    pub fn is_measured(&self) -> bool {
        self.srtt.is_some() || self.loss > 0.0 || self.stalls > 0
    }
}

/// One piece of path evidence a session reports to its exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QualityEvent {
    /// A carrier was given up with something expected on it (a stall, a
    /// STALL hint, a hold timeout, an unanswered attach).
    CarrierLost,
    /// `sent` new bytes went out since the last report, and `replayed` of
    /// the session's already-sent bytes had to go out again on a new
    /// carrier. Both are deltas, so the tracker sums them across sessions
    /// and the ratio is the true fraction of sent bytes replayed.
    Replay { sent: u64, replayed: u64 },
}

/// Accumulates [`Quality`] from session-layer events.
#[derive(Clone, Debug, Default)]
pub struct QualityTracker {
    srtt: Option<Duration>,
    /// Aged sent-byte denominator of the loss ratio.
    sent: f64,
    /// Aged replayed-byte numerator of the loss ratio.
    replayed: f64,
    stalls: u64,
}

impl QualityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// A control PING/PONG round trip: smooth it into the RTT estimate,
    /// and age the loss estimate symmetrically (the PING is the tracker's clock).
    pub fn on_rtt(&mut self, sample: Duration) {
        self.srtt = Some(match self.srtt {
            None => sample,
            Some(s) => s.mul_f64(1.0 - RTT_ALPHA) + sample.mul_f64(RTT_ALPHA),
        });
        self.sent *= LOSS_DECAY;
        self.replayed *= LOSS_DECAY;
        if self.sent < 1e-3 {
            self.sent = 0.0;
            self.replayed = 0.0;
        }
    }

    /// A carrier was given up with something expected on it (a stall, a
    /// STALL hint, a hold timeout, an unanswered attach).
    pub fn on_carrier_lost(&mut self) {
        self.stalls = self.stalls.saturating_add(1);
    }

    /// `sent` new bytes went out, and `replayed` of the already-sent bytes
    /// had to go out again on a new carrier. Both are deltas.
    pub fn on_replay(&mut self, sent: u64, replayed: u64) {
        self.sent += sent as f64;
        self.replayed += replayed as f64;
    }

    /// Apply one session event.
    pub fn on_event(&mut self, e: QualityEvent) {
        match e {
            QualityEvent::CarrierLost => self.on_carrier_lost(),
            QualityEvent::Replay { sent, replayed } => self.on_replay(sent, replayed),
        }
    }

    /// Fraction of sent bytes replayed, in `[0, 1]`.
    pub fn loss(&self) -> f64 {
        if self.sent <= 0.0 {
            0.0
        } else {
            (self.replayed / self.sent).clamp(0.0, 1.0)
        }
    }

    pub fn snapshot(&self) -> Quality {
        Quality {
            srtt: self.srtt,
            loss: self.loss(),
            stalls: self.stalls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_evidence_is_the_default() {
        let q = QualityTracker::new().snapshot();
        assert_eq!(q, Quality::default());
        assert!(!q.is_measured());
    }

    #[test]
    fn rtt_is_smoothed_toward_new_samples() {
        let mut t = QualityTracker::new();
        t.on_rtt(Duration::from_millis(100));
        assert_eq!(t.snapshot().srtt, Some(Duration::from_millis(100)));
        // One 200 ms sample moves the 100 ms estimate by 1/8 of the gap.
        t.on_rtt(Duration::from_millis(200));
        let srtt = t.snapshot().srtt.unwrap();
        assert!(
            srtt > Duration::from_millis(100) && srtt < Duration::from_millis(200),
            "{srtt:?}"
        );
        assert_eq!(srtt, Duration::from_micros(112_500));
    }

    #[test]
    fn loss_is_replayed_over_sent() {
        let mut t = QualityTracker::new();
        assert_eq!(t.loss(), 0.0, "nothing sent yet");
        t.on_replay(1000, 100);
        assert!((t.loss() - 0.1).abs() < 1e-9, "{}", t.loss());
        // Deltas accumulate: 200 more sent, 100 more replayed: 200/1200.
        t.on_replay(200, 100);
        assert!((t.loss() - 200.0 / 1200.0).abs() < 1e-9, "{}", t.loss());
        // The ratio is capped at 1 even if replays outrun the sent bytes.
        t.on_replay(0, 10_000);
        assert_eq!(t.loss(), 1.0);
    }

    #[test]
    fn two_sessions_sum_their_deltas() {
        let mut t = QualityTracker::new();
        // Two sessions each send 1000 bytes; one replays 100. The exit's
        // loss is 100/2000, not 100/1000.
        t.on_replay(1000, 0);
        t.on_replay(1000, 100);
        assert!((t.loss() - 0.05).abs() < 1e-9, "{}", t.loss());
    }

    #[test]
    fn loss_fades_on_a_path_that_became_clean() {
        let mut t = QualityTracker::new();
        t.on_replay(1000, 200);
        assert!((t.loss() - 0.2).abs() < 1e-9);
        // A clean path keeps sending; each PING ages the old replays.
        for _ in 0..20 {
            t.on_replay(1000, 0);
            t.on_rtt(Duration::from_millis(100));
        }
        assert!(t.loss() < 0.01, "old loss did not fade: {}", t.loss());
    }

    #[test]
    fn stalls_count_carrier_deaths() {
        let mut t = QualityTracker::new();
        t.on_carrier_lost();
        t.on_carrier_lost();
        assert_eq!(t.snapshot().stalls, 2);
        assert!(t.snapshot().is_measured());
    }

    #[test]
    fn new_loss_is_detected_after_prior_clean_traffic() {
        let mut t = QualityTracker::new();
        t.on_replay(100_000, 0);
        for _ in 0..40 {
            t.on_rtt(Duration::from_millis(100));
        }
        t.on_replay(10_000, 5_000);
        assert!(
            t.loss() > 0.30,
            "new loss masked by aged clean denominator: {}",
            t.loss()
        );
    }
}
