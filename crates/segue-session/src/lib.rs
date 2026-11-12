//! Segue L5 session layer (SESSION_PROTOCOL v0.4).
//!
//! Layout:
//! - [`codec`]: frame format (§2).
//! - [`pool`]: global receive/replay pool with per-session credit (§4 rule 8).
//! - [`flow`]: per-direction offsets, flow control and replay (§4).
//! - [`client`] / [`relay`]: sans-IO state machines (§5). They take `now` as
//!   an argument and never block, so tests can drive them deterministically.
//! - [`park`]: the PARK request matching rule (§5.6, R2-2c). PARK/WAKE as a
//!   whole is M9+; only the pending-request rule is implemented.
//! - [`driver`]: async glue over any `AsyncRead + AsyncWrite` carrier.
//!
//! Not implemented here: ticket verification (a hook, [`relay::Authorizer`]),
//! revocation, REFRESH, RESOLVE, UDP (DGRAM is codec only), cross-instance
//! hand-off (§9.2: any `anchor_instance_id` other than ours is answered with
//! `unknown_session`), cross-node forwarding and WAKE (M9+).

pub mod client;
pub mod codec;
pub mod driver;
pub mod flow;
pub mod park;
pub mod pipe;
pub mod pool;
pub mod relay;

use std::time::Duration;

/// Fatal protocol errors (the carrier, and for a current carrier the
/// session, is closed with `RST(protocol)`).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    #[error("malformed frame")]
    Malformed,
    #[error("unsupported version {0}")]
    Version(u8),
    #[error("unknown frame type {0:#04x}")]
    UnknownFrame(u8),
    #[error("frame longer than 16384")]
    FrameTooLong,
    #[error("protocol violation: {0}")]
    Violation(&'static str),
}

/// Timers (§5, all **待仿真** in the spec; these are its defaults).
#[derive(Clone, Debug)]
pub struct Timing {
    /// Client: give up on one attach attempt and retry with a new carrier.
    pub t_attach: Duration,
    /// Client: unacked data and nothing received for this long → re-attach
    /// (KERNEL_SPEC §7.2 "数据停滞", `max(1 s, 4 × SRTT)`; SRTT not modelled).
    pub t_stall: Duration,
    /// Relay: unacked downlink and no ACK progress → DETACHED.
    pub t_live: Duration,
    /// Both: how long a session may stay without a working carrier.
    pub t_detached: Duration,
    /// Client: how long OPEN may be retried before the local connection is reset.
    pub t_open_retry: Duration,
    /// Relay: tombstone lifetime.
    pub t_tomb: Duration,
    /// Delayed-ACK timer (spec: `jitter × SRTT/2`, floor 20 ms).
    pub ack_delay: Duration,
    /// Receive credit falls back to the floor after this long without data.
    pub idle_after: Duration,
    /// Relay: absolute session lifetime from OPEN; RESUME does not extend
    /// it (§5.2 "会话超过最长寿命 → RST(max_lifetime)").
    pub max_lifetime: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            t_attach: Duration::from_secs(2),
            t_stall: Duration::from_secs(1),
            t_live: Duration::from_secs(3),
            t_detached: Duration::from_secs(30),
            t_open_retry: Duration::from_secs(15),
            t_tomb: Duration::from_secs(60),
            ack_delay: Duration::from_millis(20),
            idle_after: Duration::from_secs(1),
            max_lifetime: Duration::from_secs(24 * 3600),
        }
    }
}

/// Buffer limits (§4).
#[derive(Clone, Debug)]
pub struct Limits {
    /// Credit both ends assume before any OPENED/ACK: OPEN carries no
    /// window, so this is fixed by the protocol, not configurable per peer.
    pub initial_credit: usize,
    /// Receive credit floor.
    pub min_credit: usize,
    /// Receive window cap.
    pub window_cap: usize,
    /// Replay buffer cap (spec: ≤ 2 × cap).
    pub replay_cap: usize,
}

/// Initial credit fixed by this implementation of v0.4 (§4 rule 8).
pub const INITIAL_CREDIT: usize = 16 * 1024;

impl Default for Limits {
    fn default() -> Self {
        Self {
            initial_credit: INITIAL_CREDIT,
            min_credit: pool::BLOCK,
            window_cap: 256 * 1024,
            replay_cap: 512 * 1024,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub timing: Timing,
    pub limits: Limits,
}

/// Constant-time comparison for `resume_secret` (§3).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    std::hint::black_box(d) == 0
}
