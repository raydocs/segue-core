//! Quality-based `Auto` exit choice with hysteresis.
//!
//! `Auto` used to take the first exit whose carrier is up. On a lossy path
//! that is not enough (WAN findings 2026-11-18): two exits can both be up
//! while one loses a tenth of its carriers. This module scores each exit
//! from the session layer's measured [`Quality`] and prefers lower loss,
//! then lower RTT.
//!
//! Switching is hysteretic so a noisy sample cannot flap the choice: a
//! challenger must beat the incumbent by a margin ([`LOSS_MARGIN`] or
//! [`RTT_MARGIN`]) for [`SWITCH_SAMPLES`] consecutive observations. A
//! failover (the incumbent is no longer up) is immediate: that is not
//! flapping, it is the exit being gone.

use std::cmp::Ordering;
use std::time::Duration;

use segue_session::quality::Quality;

/// Loss margin (fraction of sent bytes) a challenger must beat the
/// incumbent by before it can take over.
pub const LOSS_MARGIN: f64 = 0.05;
/// RTT margin a challenger must beat the incumbent by when loss is close.
pub const RTT_MARGIN: Duration = Duration::from_millis(30);
/// Consecutive observations a challenger must stay better before `Auto`
/// switches to it.
pub const SWITCH_SAMPLES: u32 = 3;

/// Whether `a` is better than `b` by the switch margin: lower loss first,
/// then lower RTT. Both must carry evidence; otherwise they tie (no
/// evidence never wins).
pub fn better_by_margin(a: &Quality, b: &Quality) -> bool {
    if !a.is_measured() || !b.is_measured() {
        return false;
    }
    if a.loss + LOSS_MARGIN <= b.loss {
        return true;
    }
    if b.loss + LOSS_MARGIN <= a.loss {
        return false;
    }
    match (a.srtt, b.srtt) {
        (Some(x), Some(y)) => x + RTT_MARGIN <= y,
        _ => false,
    }
}

/// Order two measured qualities, lower loss then lower RTT being better.
/// `Greater` means `a` is the better exit.
fn cmp_quality(a: &Quality, b: &Quality) -> Ordering {
    a.loss
        .partial_cmp(&b.loss)
        .unwrap_or(Ordering::Equal)
        .then_with(|| match (a.srtt, b.srtt) {
            (Some(x), Some(y)) => y.cmp(&x),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        })
}

/// The `Auto` choice's sticky decision and its challenger streak.
#[derive(Clone, Debug, Default)]
pub struct AutoChoice {
    current: Option<usize>,
    /// The exit that has been better for `n` consecutive observations.
    challenger: Option<(usize, u32)>,
    /// The evidence of the last observation. `observe` is called from
    /// `status()` too, which the UI polls; identical evidence must not
    /// advance the streak, or a poll rate would decide the switch.
    last: Option<(Vec<bool>, Vec<Quality>)>,
}

impl AutoChoice {
    /// The exit `Auto` is on, if it has settled on one.
    pub fn current(&self) -> Option<usize> {
        self.current
    }

    /// Feed one round of evidence: `up[i]` and `quality[i]` per exit.
    /// Returns the exit `Auto` should use now.
    ///
    /// - No exit up: the incumbent is kept (the caller's own fallback
    ///   decides what to do with a down exit).
    /// - The incumbent is down or unset: fail over at once to the first
    ///   up exit, no hysteresis.
    /// - Otherwise a challenger that beats the incumbent by the margin
    ///   must do so for [`SWITCH_SAMPLES`] observations in a row.
    pub fn observe(&mut self, up: &[bool], quality: &[Quality]) -> Option<usize> {
        // The same evidence twice (a UI polling `status()`) is one
        // observation, not two.
        if self
            .last
            .as_ref()
            .is_some_and(|(u, q)| u.as_slice() == up && q.as_slice() == quality)
        {
            return self.current;
        }
        self.last = Some((up.to_vec(), quality.to_vec()));
        if !up.iter().any(|&u| u) {
            return self.current;
        }
        let incumbent_up = self
            .current
            .is_some_and(|i| up.get(i).copied().unwrap_or(false));
        if !incumbent_up {
            let i = (0..up.len()).find(|&i| up[i])?;
            self.current = Some(i);
            self.challenger = None;
            return self.current;
        }
        let cur = self.current.expect("checked above");
        let mut best: Option<usize> = None;
        for i in 0..up.len() {
            if i == cur || !up[i] || !better_by_margin(&quality[i], &quality[cur]) {
                continue;
            }
            best = match best {
                None => Some(i),
                Some(b) if cmp_quality(&quality[i], &quality[b]) == Ordering::Greater => Some(i),
                Some(b) => Some(b),
            };
        }
        match best {
            Some(i) => {
                let streak = match self.challenger {
                    Some((c, n)) if c == i => n + 1,
                    _ => 1,
                };
                self.challenger = Some((i, streak));
                if streak >= SWITCH_SAMPLES {
                    self.current = Some(i);
                    self.challenger = None;
                }
            }
            None => self.challenger = None,
        }
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(loss: f64, srtt_ms: u64) -> Quality {
        Quality {
            srtt: Some(Duration::from_millis(srtt_ms)),
            loss,
            stalls: 0,
        }
    }

    /// `n` fresh observations of the same underlying quality: each round
    /// nudges the RTT by a millisecond so it is new evidence (a real
    /// sample is never byte-identical to the last). The counter is
    /// process-wide so consecutive calls never repeat a sample.
    fn rounds(a: &mut AutoChoice, up: &[bool], quality: &[Quality], n: usize) -> Option<usize> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TICK: AtomicU64 = AtomicU64::new(0);
        let mut last = None;
        for _ in 0..n {
            let k = TICK.fetch_add(1, Ordering::Relaxed);
            let q: Vec<Quality> = quality
                .iter()
                .map(|x| Quality {
                    srtt: x.srtt.map(|s| s + Duration::from_millis(k + 1)),
                    ..*x
                })
                .collect();
            last = a.observe(up, &q);
        }
        last
    }

    #[test]
    fn lower_loss_wins_by_the_margin() {
        assert!(better_by_margin(&q(0.0, 200), &q(0.10, 100)));
        assert!(!better_by_margin(&q(0.10, 100), &q(0.0, 200)));
        // Within the loss margin: the RTT decides.
        assert!(better_by_margin(&q(0.02, 100), &q(0.04, 200)));
        assert!(!better_by_margin(&q(0.02, 200), &q(0.04, 100)));
    }

    #[test]
    fn rtt_must_beat_the_margin() {
        assert!(better_by_margin(&q(0.0, 100), &q(0.0, 200)));
        assert!(
            !better_by_margin(&q(0.0, 100), &q(0.0, 120)),
            "within 30 ms"
        );
        assert!(!better_by_margin(&q(0.0, 200), &q(0.0, 100)));
    }

    #[test]
    fn no_evidence_never_wins() {
        let none = Quality::default();
        assert!(!better_by_margin(&none, &q(0.0, 100)));
        assert!(!better_by_margin(&q(0.0, 100), &none));
        assert!(!better_by_margin(&none, &none));
    }

    #[test]
    fn failover_is_immediate() {
        let mut a = AutoChoice::default();
        let up = [true, true];
        let quality = [q(0.0, 100), q(0.0, 200)];
        assert_eq!(a.observe(&up, &quality), Some(0), "first up exit");
        // Exit 0 goes down: switch at once, no streak.
        let up = [false, true];
        assert_eq!(a.observe(&up, &quality), Some(1));
        assert_eq!(a.current(), Some(1));
    }

    #[test]
    fn a_better_challenger_needs_three_samples() {
        let mut a = AutoChoice::default();
        let up = [true, true];
        // Exit 0 is the incumbent (first up), exit 1 is clearly better.
        let quality = [q(0.10, 200), q(0.0, 100)];
        assert_eq!(a.observe(&up, &quality), Some(0));
        assert_eq!(rounds(&mut a, &up, &quality, 1), Some(0), "one sample");
        assert_eq!(rounds(&mut a, &up, &quality, 1), Some(0), "two samples");
        assert_eq!(rounds(&mut a, &up, &quality, 1), Some(1), "three: switch");
        assert_eq!(a.current(), Some(1));
    }

    #[test]
    fn a_noisy_challenger_does_not_flap() {
        let mut a = AutoChoice::default();
        let up = [true, true];
        let good = [q(0.0, 100), q(0.10, 200)];
        let better = [q(0.10, 200), q(0.0, 100)];
        assert_eq!(a.observe(&up, &good), Some(0));
        // Exit 1 is better for two samples, then not: the streak resets.
        assert_eq!(rounds(&mut a, &up, &better, 2), Some(0));
        assert_eq!(rounds(&mut a, &up, &good, 1), Some(0), "streak reset");
        assert_eq!(rounds(&mut a, &up, &better, 2), Some(0), "two again");
        assert_eq!(rounds(&mut a, &up, &better, 1), Some(1), "three in a row");
    }

    #[test]
    fn a_different_challenger_restarts_the_streak() {
        let mut a = AutoChoice::default();
        let up = [true, true, true];
        let base = [q(0.10, 200), q(0.10, 200), q(0.10, 200)];
        assert_eq!(a.observe(&up, &base), Some(0));
        // Exit 1 better twice, then exit 2 better twice: no switch.
        let one = [q(0.10, 200), q(0.0, 100), q(0.10, 200)];
        let two = [q(0.10, 200), q(0.10, 200), q(0.0, 100)];
        assert_eq!(rounds(&mut a, &up, &one, 2), Some(0));
        assert_eq!(rounds(&mut a, &up, &two, 2), Some(0));
        // Exit 2 for a third time: switch.
        assert_eq!(rounds(&mut a, &up, &two, 1), Some(2));
    }

    #[test]
    fn repeated_identical_evidence_is_one_observation() {
        let mut a = AutoChoice::default();
        let up = [true, true];
        let quality = [q(0.10, 200), q(0.0, 100)];
        assert_eq!(a.observe(&up, &quality), Some(0));
        // A UI polling status() sees the same evidence many times: it
        // must not count as the three samples a switch needs.
        for _ in 0..10 {
            assert_eq!(a.observe(&up, &quality), Some(0));
        }
    }

    #[test]
    fn no_exit_up_keeps_the_incumbent() {
        let mut a = AutoChoice::default();
        let up = [true, true];
        let quality = [q(0.0, 100), q(0.0, 200)];
        assert_eq!(a.observe(&up, &quality), Some(0));
        let down = [false, false];
        assert_eq!(a.observe(&down, &quality), Some(0), "kept for the fallback");
    }
}
