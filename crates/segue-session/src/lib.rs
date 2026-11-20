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
pub mod dgram;
pub mod driver;
pub mod flow;
pub mod park;
pub mod pipe;
pub mod pool;
pub mod quality;
pub mod relay;

pub use dgram::{DgramConfig, DgramStats};

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
    /// An AI session waits [`Self::t_stall_ai`] instead, spare or not.
    pub t_stall: Duration,
    /// Client, AI sessions only (`exit_class` [`EXIT_CLASS_AI`]): unacked
    /// silence, and a relay `STALL` hint, wait this long before the carrier
    /// is given up. A bound spare is swapped; with none the session
    /// re-attaches. Other sessions ignore it and use [`Self::t_stall`].
    pub t_stall_ai: Duration,
    /// Relay: unacked downlink and no ACK progress → DETACHED. An AI
    /// session waits [`Self::t_live_ai`] instead, so it does not give the
    /// carrier up while the client is still inside [`Self::t_stall_ai`].
    pub t_live: Duration,
    /// Relay, AI sessions only: the [`Self::t_live`] bound. Matches
    /// [`Self::t_stall_ai`].
    pub t_live_ai: Duration,
    /// Both: how long a session may stay without a working carrier.
    /// Sessions whose OPEN carried [`EXIT_CLASS_AI`] use
    /// [`Self::t_detached_ai`] instead.
    pub t_detached: Duration,
    /// Both: detach bound for an AI session ([`EXIT_CLASS_AI`]). Under the
    /// 180 s after which an AI client aborts a stream it cannot resume.
    /// Other sessions keep [`Self::t_detached`].
    pub t_detached_ai: Duration,
    /// Both: a carrier demoted by a stall stays the spare this long with no
    /// frame received, then it is dropped. A frame resets the wait: the
    /// carrier is a live standby again.
    pub t_detached_standby: Duration,
    /// Both, AI sessions only: send a lightweight keepalive ACK when a live
    /// carrier has had no traffic in either direction for this long, keeping
    /// underlying Hysteria2/TUIC/HTTP2 carriers below their 30 s idle timeout
    /// during long LLM thinking pauses. [`Duration::ZERO`] disables it.
    pub t_keepalive_ai: Duration,
    /// Client: how long OPEN may be retried before the local connection is reset.
    pub t_open_retry: Duration,
    /// Relay: tombstone lifetime.
    pub t_tomb: Duration,
    /// Delayed-ACK timer (spec: `jitter × SRTT/2`, floor 20 ms).
    pub ack_delay: Duration,
    /// Receive credit falls back to the floor after this long without data.
    pub idle_after: Duration,
    /// Receive credit retention across LLM thinking pauses on AI sessions
    /// ([`EXIT_CLASS_AI`]) when the global pool is not under pressure.
    pub idle_after_ai: Duration,
    /// Relay: absolute session lifetime from OPEN; RESUME does not extend
    /// it (§5.2 "会话超过最长寿命 → RST(max_lifetime)").
    pub max_lifetime: Duration,
    /// Relay: a control stream that sends nothing (no PING) for this long
    /// is closed. Clients PING every 5 s and judge the stream dead after
    /// 12 s, so a live client never comes near it.
    pub t_ctrl_idle: Duration,
    /// Relay: once the client's FIN and every byte before it arrived, the
    /// site writer is reset if the site accepts no upload byte (and the
    /// write side is not shut down) for this long. Progress-based: a slow
    /// site that keeps reading is never cut by it (review r7 #9).
    pub site_flush_idle: Duration,
    /// Relay: overall bound, from the same point, on handing the rest of
    /// the upload to the site and shutting its write side down, however
    /// slowly it progresses. Past either bound the session is reset
    /// (`site_reset`), never CLEAN.
    pub site_flush_max: Duration,
}

/// The shortest client stall bound (`t_stall`) a relay serves keepalives
/// for: an announced bound below it is taken as this floor, so a peer
/// cannot make the relay send ACKs in a loop. A client configured below
/// it is refused by [`Timing::validate_client`] (r10 N3), so the floor
/// only ever applies to a misbehaving peer.
pub const MIN_CLIENT_STALL: Duration = Duration::from_millis(100);

/// OPEN `exit_class` hint for an AI / home session. Both sides use it to
/// pick [`Timing::t_detached_ai`]. The relay still classifies exits on its
/// own; this is only the hint the client put on OPEN. Matches the kernel's
/// `EXIT_AI`.
pub const EXIT_CLASS_AI: u8 = 1;

/// A client timing the protocol cannot honour.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimingError {
    #[error("t_stall {0:?} is below the {MIN_CLIENT_STALL:?} a relay serves keepalives for")]
    StallTooShort(Duration),
    #[error("t_stall {0:?} does not fit the wire field")]
    StallTooLong(Duration),
}

impl Timing {
    /// Check a client configuration (r10 N3): the stall bound sent to the
    /// relay (`t_stall_ms`) is [`Self::t_stall`], or [`Self::t_stall_ai`] for
    /// an AI session. The relay keeps a session alive at half of that
    /// announcement, but never below [`MIN_CLIENT_STALL`]. A shorter client
    /// bound would take live carriers for stalled ones, so it is refused
    /// here rather than floored silently on the relay.
    pub fn validate_client(&self) -> Result<(), TimingError> {
        for stall in [self.t_stall, self.t_stall_ai] {
            if stall < MIN_CLIENT_STALL {
                return Err(TimingError::StallTooShort(stall));
            }
            if stall.as_millis() > u128::from(codec::STALL_MS_MAX) {
                return Err(TimingError::StallTooLong(stall));
            }
        }
        Ok(())
    }

    /// How long the relay waits for ACK progress before it gives a carrier up.
    pub fn live_for(&self, exit_class: u8) -> Duration {
        if exit_class == EXIT_CLASS_AI {
            self.t_live_ai
        } else {
            self.t_live
        }
    }

    /// How long a session of `exit_class` may stay without a working carrier.
    pub fn detach_for(&self, exit_class: u8) -> Duration {
        if exit_class == EXIT_CLASS_AI {
            self.t_detached_ai
        } else {
            self.t_detached
        }
    }

    /// How long receive credit stays elevated without data for `exit_class`.
    pub fn idle_after_for(&self, exit_class: u8) -> Duration {
        if exit_class == EXIT_CLASS_AI {
            self.idle_after_ai
        } else {
            self.idle_after
        }
    }

    /// Carrier keepalive interval for an idle active session of `exit_class`,
    /// or `None` when disabled.
    pub fn keepalive_ai_for(&self, exit_class: u8) -> Option<Duration> {
        if exit_class == EXIT_CLASS_AI && !self.t_keepalive_ai.is_zero() {
            Some(self.t_keepalive_ai)
        } else {
            None
        }
    }

    /// Periodic lightweight ACK probe interval for a stall-demoted standby
    /// carrier so a recovered path clears `demoted_at` before
    /// [`Self::t_detached_standby`] expires.
    pub(crate) fn demoted_probe_interval(&self) -> Option<Duration> {
        if self.t_detached_standby < Duration::from_millis(250) {
            return None;
        }
        Some(
            (self.t_detached_standby / 5).clamp(Duration::from_millis(100), Duration::from_secs(2)),
        )
    }
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            t_attach: Duration::from_secs(2),
            t_stall: Duration::from_secs(1),
            t_stall_ai: Duration::from_secs(5),
            t_live: Duration::from_secs(3),
            t_live_ai: Duration::from_secs(5),
            t_detached: Duration::from_secs(30),
            t_detached_ai: Duration::from_secs(150),
            t_detached_standby: Duration::from_secs(10),
            t_keepalive_ai: Duration::from_secs(20),
            t_open_retry: Duration::from_secs(15),
            t_tomb: Duration::from_secs(60),
            ack_delay: Duration::from_millis(20),
            idle_after: Duration::from_secs(1),
            idle_after_ai: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(24 * 3600),
            t_ctrl_idle: Duration::from_secs(30),
            site_flush_idle: Duration::from_secs(30),
            site_flush_max: Duration::from_secs(300),
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
            window_cap: 1024 * 1024,
            replay_cap: 2 * 1024 * 1024,
        }
    }
}

/// Stage 2 small-frame duplication policy on a bound redundant carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedundancyMode {
    /// Stage 1 only: keep the standby bound and swap on stall, with no `DATA` duplication.
    Off,
    /// Staggered proactive duplication of small unacked frames (`<= max_frame_bytes`).
    Dup { delay: Duration },
    /// Delayed tail hedge when primary acknowledgement has not arrived after `delay`.
    Hedge { delay: Duration },
}

impl Default for RedundancyMode {
    fn default() -> Self {
        Self::Dup {
            delay: Duration::from_millis(30),
        }
    }
}

/// Configuration for Stage 2 small-frame redundancy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedundancyConfig {
    pub mode: RedundancyMode,
    /// Maximum `DATA` payload length eligible for redundant queuing.
    pub max_frame_bytes: usize,
    /// When `true` (default), Stage 2 `DATA` duplication applies only to AI
    /// sessions ([`EXIT_CLASS_AI`]).
    pub ai_only: bool,
}

impl Default for RedundancyConfig {
    fn default() -> Self {
        Self {
            mode: RedundancyMode::default(),
            max_frame_bytes: 1024,
            ai_only: true,
        }
    }
}

impl RedundancyConfig {
    /// Delay before duplicating a small unacked frame for `exit_class`, or
    /// `None` when Stage 2 `DATA` duplication is disabled for that class.
    pub fn dup_delay_for(&self, exit_class: u8) -> Option<Duration> {
        if self.ai_only && exit_class != EXIT_CLASS_AI {
            return None;
        }
        match self.mode {
            RedundancyMode::Off => None,
            RedundancyMode::Dup { delay } | RedundancyMode::Hedge { delay } => Some(delay),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub timing: Timing,
    pub limits: Limits,
    pub redundancy: RedundancyConfig,
    pub dgram: DgramConfig,
}

/// Why the client gave up the carrier it was using.
///
/// A hard loss (closed, write or decode error, `REJECT`) is not a stall.
/// Counters live on [`MoveStats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoveReason {
    /// Confirmed, with unacked bytes, and nothing received for `t_stall`.
    Stall,
    /// A frame on the carrier stopped moving (transport hold).
    Hold,
    /// A `STALL` hint from the relay.
    RelayStall,
    /// The carrier closed, or read EOF.
    Closed,
    /// A write failed, or a frame failed to decode.
    Io,
    /// `REJECT` on the current carrier (not an ignored stale generation).
    Reject,
    /// No `OPENED` or `RESUMED` within `t_attach`.
    Attach,
}

/// Per-session move counters.
///
/// The client fills every field except `t_live` and `stall_hints`. The relay
/// fills those two and leaves the rest at zero. [`client::ClientSession::move_stats`]
/// and [`relay::RelayTable::move_stats`] return a copy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MoveStats {
    /// [`MoveReason::Stall`].
    pub stall: u64,
    /// [`MoveReason::Hold`].
    pub hold: u64,
    /// [`MoveReason::RelayStall`].
    pub relay_stall: u64,
    /// [`MoveReason::Closed`].
    pub closed: u64,
    /// [`MoveReason::Io`].
    pub io: u64,
    /// [`MoveReason::Reject`].
    pub reject: u64,
    /// [`MoveReason::Attach`].
    pub attach: u64,
    /// Stall-type promotions that left the old carrier bound.
    pub swaps: u64,
    /// A bound spare became the current carrier. Includes `swaps`.
    pub promotions: u64,
    /// `RESUME` sent on a new carrier (the generation moved).
    pub resumes: u64,
    /// Bytes sent again after a promotion or a `RESUME`.
    pub bytes_replayed: u64,
    /// Sum of the waits from a loss until the next byte of progress, in
    /// microseconds. A loss the session never recovered from is not included.
    pub recovery_us_sum: u64,
    /// Longest of those waits, microseconds.
    pub recovery_us_max: u64,
    /// How many waits `recovery_us_sum` includes.
    pub recoveries: u64,
    /// Relay: `t_live` expiries, whether or not a spare was promoted.
    pub t_live: u64,
    /// Relay: `STALL` entries actually queued on a control stream.
    pub stall_hints: u64,
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
