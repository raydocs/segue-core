//! PARK request matching (§5.6, R2-2c).
//!
//! PARK / WAKE as a whole is a later milestone (M9+). Only the rule that
//! decides whether a PARK_ACK takes effect is implemented: at most one
//! pending PARK per session; a PARK_ACK counts only if its `req_id` equals
//! the pending one and its `attach_gen` equals the current generation. New
//! data cancels the pending request without waiting for the ACK.

use crate::codec::ParkAckEntry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkDecision {
    /// The session is now parked (relay generation `park_gen`).
    Parked(u32),
    /// The relay refused; the session stays ACTIVE.
    Refused,
    /// Late, stale or unsolicited: no effect.
    Ignored,
}

#[derive(Debug, Default)]
pub struct ParkTracker {
    next_req: u64,
    pending: Option<(u64, u32)>,
}

impl ParkTracker {
    /// Start a PARK for generation `gen`; returns its `req_id`. A previous
    /// pending request is superseded.
    pub fn request(&mut self, gen: u32) -> u64 {
        self.next_req += 1;
        self.pending = Some((self.next_req, gen));
        self.next_req
    }

    pub fn pending(&self) -> Option<u64> {
        self.pending.map(|p| p.0)
    }

    /// New data to send, or a re-attach: the pending PARK no longer applies.
    pub fn cancel(&mut self) {
        self.pending = None;
    }

    pub fn on_ack(&mut self, ack: &ParkAckEntry, current_gen: u32) -> ParkDecision {
        match self.pending {
            Some((req, gen))
                if req == ack.req_id && gen == ack.attach_gen && gen == current_gen =>
            {
                self.pending = None;
                if ack.accepted {
                    ParkDecision::Parked(ack.park_gen)
                } else {
                    ParkDecision::Refused
                }
            }
            _ => ParkDecision::Ignored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(req_id: u64, attach_gen: u32, accepted: bool) -> ParkAckEntry {
        ParkAckEntry {
            session_id: [0; 16],
            req_id,
            attach_gen,
            accepted,
            park_gen: 9,
        }
    }

    #[test]
    fn only_matching_ack_parks() {
        let mut t = ParkTracker::default();
        let r1 = t.request(3);
        assert_eq!(t.on_ack(&ack(r1 + 1, 3, true), 3), ParkDecision::Ignored);
        assert_eq!(t.on_ack(&ack(r1, 2, true), 3), ParkDecision::Ignored);
        assert_eq!(t.on_ack(&ack(r1, 3, true), 3), ParkDecision::Parked(9));
        assert_eq!(
            t.on_ack(&ack(r1, 3, true), 3),
            ParkDecision::Ignored,
            "duplicate"
        );
    }

    #[test]
    fn late_ack_after_resume_is_ignored() {
        let mut t = ParkTracker::default();
        let r1 = t.request(3);
        // Re-attach to gen 4 before the ACK arrives.
        t.cancel();
        assert_eq!(t.on_ack(&ack(r1, 3, true), 4), ParkDecision::Ignored);
        // Even a new request at gen 4 does not accept the old req_id.
        let r2 = t.request(4);
        assert_eq!(t.on_ack(&ack(r1, 3, true), 4), ParkDecision::Ignored);
        assert_eq!(t.on_ack(&ack(r2, 4, false), 4), ParkDecision::Refused);
        assert_eq!(t.pending(), None);
    }

    #[test]
    fn superseded_request_is_ignored() {
        let mut t = ParkTracker::default();
        let r1 = t.request(1);
        let r2 = t.request(1);
        assert_eq!(t.on_ack(&ack(r1, 1, true), 1), ParkDecision::Ignored);
        assert_eq!(t.on_ack(&ack(r2, 1, true), 1), ParkDecision::Parked(9));
    }
}
