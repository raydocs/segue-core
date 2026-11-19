//! Userspace link impairment proxy for local WAN-like tests.
//!
//! A small async UDP/TCP relay that sits between a client and an upstream and
//! applies fixed delay, jitter, uniform loss, Gilbert-Elliott burst loss,
//! a bandwidth cap and reordering. Everything is driven by a seeded PRNG, so a
//! run is reproducible from `(profile, seed)`.
//!
//! No root, no `tc netem`, no host route changes: the relay only binds the
//! loopback addresses it is told to. TCP is a reliable byte stream, so loss and
//! reordering are applied to UDP only unless [`TcpLoss::Emulate`] is on. With
//! the mode off, TCP gets delay, jitter and the bandwidth cap (dropping bytes
//! there would corrupt the stream rather than emulate a retransmission).
//!
//! # TCP loss-recovery emulation
//!
//! [`TcpLoss::Emulate`] (CLI `--tcp-loss emulate`, off by default) never drops
//! a TCP byte. Each read chunk, capped at `TCP_SEGMENT_CAP` (1400 B), is one
//! segment. A segment the profile's [`LossModel`] marks lost is delivered
//! later, and every segment behind it waits (head-of-line), then flushes in
//! order. This is a model of TCP recovery, not TCP, and a Linux `tc netem`
//! job will calibrate it later.
//!
//! Loss is drawn once per segment, per direction, from the seeded [`Rng`].
//! The retransmission is drawn again at once on the same model (a burst can
//! consume the retry). Drawing it up front, rather than when the timer fires,
//! keeps the loss sequence a function of `(profile, seed, segment sizes)` and
//! not of the clock.
//!
//! `rtt` is twice the profile's one-way `delay` (jitter is not part of it).
//! `inflight` is the number of later segments sent within one `rtt` of the
//! lost one. A lost segment is delivered after:
//!
//! - `inflight >= 3`: fast retransmit, one `rtt`;
//! - otherwise a tail-loss probe, `2 × rtt`;
//! - each lost retransmission adds an RTO of `max(200 ms, 3 × rtt)`, doubling
//!   per further loss, each step capped at 8 s, and at most
//!   `TCP_MAX_RETX` retries.
//!
//! The first segment in each direction stands for the SYN / first handshake
//! flight: a loss delays it 1 s (macOS initial RTO), and a lost retransmission
//! delays it another 1 s. Further losses of that flight use the RTO ladder.
//! Segments that were not lost still take the profile's one-way delay, jitter,
//! reorder extra and bandwidth cap. A lost segment's recovery delay replaces
//! that one-way delay (the round trip already includes it), and it does not
//! consume the bandwidth cap.
//!
//! # TCP faults
//!
//! Three extra TCP faults, off unless a run asks for one. They apply to both
//! [`TcpLoss`] modes and never to UDP. Times on the CLI are milliseconds from
//! when the TCP listener starts; [`TcpRelay`] can arm the same faults mid-run.
//!
//! - **Blackout** (`--blackout <t0_ms>:<duration_ms>`, [`TcpRelay::arm_blackout`]):
//!   between `t0` and `t0 + duration` the relay forwards nothing in either
//!   direction and keeps the sockets open. Bytes read during the window are
//!   held and written after it (delayed, never dropped).
//! - **Reset** (`--reset-at <t0_ms>`, [`TcpRelay::arm_reset`]): at `t0`, close
//!   both directions of every relayed connection that already exists, once.
//!   Connections accepted afterwards are left alone.
//! - **Silent drop** (`--silent-drop-at <t0_ms>`, [`TcpRelay::arm_silent_drop`]):
//!   at `t0`, stop forwarding on the connections that exist then, forever,
//!   without closing them (a dead NAT mapping). Later connections work.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep_until, Instant};

use crate::{parse_u64, required_value, BenchError};

/// Largest chunk treated as one TCP segment in loss-recovery emulation.
const TCP_SEGMENT_CAP: usize = 1400;
/// Later segments inside one RTT that trigger fast retransmit instead of a tail-loss probe.
const TCP_FAST_RETRANS_INFLIGHT: usize = 3;
/// macOS initial RTO for the SYN / first flight.
const TCP_SYN_RTO: Duration = Duration::from_secs(1);
/// Floor on a data RTO. The model uses 200 ms, not RFC 6298's 1 s.
const TCP_RTO_FLOOR: Duration = Duration::from_millis(200);
/// Data RTO is at least this many round trips.
const TCP_RTO_RTT_FACTOR: u32 = 3;
/// Cap on a single RTO backoff step.
const TCP_RTO_CAP: Duration = Duration::from_secs(8);
/// Stop redrawing a retransmission after this many losses so a certain-loss
/// profile cannot spin. The 8 s step cap still applies to every step.
const TCP_MAX_RETX: u32 = 16;
/// Splits the two directions so they do not share one loss sequence.
const DIRECTION_SEED_XOR: u64 = 0x5DEE_CE66_D1CE_4E5B;

fn direction_seed(seed: u64, toward_client: bool) -> u64 {
    if toward_client {
        seed ^ DIRECTION_SEED_XOR
    } else {
        seed
    }
}

/// Round trip used by TCP recovery emulation: twice the profile's one-way delay.
fn profile_rtt(profile: &ImpairProfile) -> Duration {
    profile.delay.saturating_mul(2)
}

fn add_instant(base: Instant, delay: Duration) -> Instant {
    base.checked_add(delay).unwrap_or(base)
}

/// Initial data RTO: `max(200 ms, 3 × rtt)`, capped at 8 s.
fn rto_step(rtt: Duration) -> Duration {
    TCP_RTO_FLOOR
        .max(rtt.saturating_mul(TCP_RTO_RTT_FACTOR))
        .min(TCP_RTO_CAP)
}

/// Extra delay from `losses` failed retransmissions. Each step doubles, capped at 8 s.
fn rto_ladder(rtt: Duration, losses: u32) -> Duration {
    let mut step = rto_step(rtt);
    let mut extra = Duration::ZERO;
    for _ in 0..losses {
        extra = extra.saturating_add(step);
        step = TCP_RTO_CAP.min(step.saturating_mul(2));
    }
    extra
}

/// SYN / first-flight recovery: 1 s, plus another 1 s if that retry is lost.
/// Anything beyond the second loss uses the data RTO ladder.
fn syn_recovery(rtt: Duration, retx_losses: u32) -> Duration {
    let mut delay = TCP_SYN_RTO;
    if retx_losses >= 1 {
        delay = delay.saturating_add(TCP_SYN_RTO);
    }
    delay.saturating_add(rto_ladder(rtt, retx_losses.saturating_sub(1)))
}

/// Data-segment recovery once `inflight` is known.
fn data_recovery(rtt: Duration, inflight: usize, retx_losses: u32) -> Duration {
    let base = if inflight >= TCP_FAST_RETRANS_INFLIGHT {
        rtt
    } else {
        rtt.saturating_mul(2)
    };
    base.saturating_add(rto_ladder(rtt, retx_losses))
}

/// SplitMix64. Small, fast and good enough for impairment decisions; keeping it
/// local avoids pulling `rand` into the bench crate just for this.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[low, high)`; returns `low` when the range is empty.
    pub fn next_range(&mut self, low: f64, high: f64) -> f64 {
        if high <= low {
            return low;
        }
        low + (high - low) * self.next_f64()
    }
}

/// Two-state Gilbert-Elliott burst-loss model.
///
/// The channel is in a good or a bad state; each packet first transitions
/// between states, then is dropped with the loss probability of the state it
/// lands in. A bad state therefore produces a run of consecutive drops whose
/// mean length is `1 / bad_to_good` packets.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GilbertElliott {
    pub good_to_bad: f64,
    pub bad_to_good: f64,
    pub loss_good: f64,
    pub loss_bad: f64,
}

impl GilbertElliott {
    /// Long-run fraction of packets spent in the bad state.
    pub fn bad_state_fraction(&self) -> f64 {
        let total = self.good_to_bad + self.bad_to_good;
        if total <= 0.0 {
            0.0
        } else {
            self.good_to_bad / total
        }
    }

    /// Mean number of consecutive packets dropped in one bad burst.
    pub fn mean_burst_len(&self) -> f64 {
        if self.bad_to_good <= 0.0 {
            f64::INFINITY
        } else {
            1.0 / self.bad_to_good
        }
    }

    /// Long-run drop probability of the model on its own.
    pub fn steady_state_loss(&self) -> f64 {
        let bad = self.bad_state_fraction();
        (1.0 - bad) * self.loss_good + bad * self.loss_bad
    }
}

/// Combined uniform + burst loss model with the state carried across packets.
#[derive(Debug, Clone)]
pub struct LossModel {
    uniform: f64,
    ge: Option<GilbertElliott>,
    in_bad_state: bool,
}

impl LossModel {
    pub fn new(uniform: f64, ge: Option<GilbertElliott>) -> Self {
        Self {
            uniform: uniform.clamp(0.0, 1.0),
            ge,
            in_bad_state: false,
        }
    }

    /// Long-run drop probability of the whole model.
    pub fn steady_state_loss(&self) -> f64 {
        match self.ge {
            Some(ge) => self.uniform + (1.0 - self.uniform) * ge.steady_state_loss(),
            None => self.uniform,
        }
    }

    /// Decide whether the next packet is dropped, advancing the burst state.
    pub fn drop_packet(&mut self, rng: &mut Rng) -> bool {
        let burst_drop = match self.ge {
            Some(ge) => {
                if self.in_bad_state {
                    if rng.next_f64() < ge.bad_to_good {
                        self.in_bad_state = false;
                    }
                } else if rng.next_f64() < ge.good_to_bad {
                    self.in_bad_state = true;
                }
                let state_loss = if self.in_bad_state {
                    ge.loss_bad
                } else {
                    ge.loss_good
                };
                rng.next_f64() < state_loss
            }
            None => false,
        };
        burst_drop || rng.next_f64() < self.uniform
    }
}

/// One named impairment profile.
#[derive(Debug, Clone, PartialEq)]
pub struct ImpairProfile {
    pub name: &'static str,
    /// One-way delay applied to every packet.
    pub delay: Duration,
    /// One-way jitter; the applied delay is uniform in `[delay - jitter, delay + jitter]`.
    pub jitter: Duration,
    /// Uniform per-packet loss, applied on top of the burst model.
    pub loss: f64,
    pub burst: Option<GilbertElliott>,
    /// Per-direction bandwidth cap in bytes per second.
    pub bandwidth: Option<u64>,
    /// Probability that a packet is pushed behind the next one.
    pub reorder: f64,
    /// Extra delay applied to a reordered packet.
    pub reorder_extra: Duration,
}

impl ImpairProfile {
    pub fn loss_model(&self) -> LossModel {
        LossModel::new(self.loss, self.burst)
    }

    /// Long-run drop probability of this profile.
    pub fn steady_state_loss(&self) -> f64 {
        self.loss_model().steady_state_loss()
    }
}

/// Names accepted by `--profile`, in the order they are documented.
pub const PROFILE_NAMES: &[&str] = &[
    "clean",
    "rtt170",
    "rtt170-loss2",
    "cn163-peak",
    "cn163-offpeak",
];

/// Look up a named profile. `None` for an unknown name.
pub fn profile(name: &str) -> Option<ImpairProfile> {
    // 172 ms RTT one way is 86 ms; the burst model is tuned so that a bad
    // state lasts ~3 packets on average and the long-run loss matches the
    // measured China Telecom 163 evening/off-peak figures.
    let cn163 = |name, bad_fraction: f64| ImpairProfile {
        name,
        delay: Duration::from_millis(86),
        jitter: Duration::from_millis(5),
        loss: 0.0,
        burst: Some(GilbertElliott {
            good_to_bad: bad_fraction * (1.0 / 3.0) / (1.0 - bad_fraction),
            bad_to_good: 1.0 / 3.0,
            loss_good: 0.0,
            loss_bad: 1.0,
        }),
        bandwidth: None,
        reorder: 0.01,
        reorder_extra: Duration::from_millis(15),
    };
    match name {
        "clean" => Some(ImpairProfile {
            name: "clean",
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss: 0.0,
            burst: None,
            bandwidth: None,
            reorder: 0.0,
            reorder_extra: Duration::ZERO,
        }),
        "rtt170" => Some(ImpairProfile {
            name: "rtt170",
            delay: Duration::from_millis(85),
            jitter: Duration::from_millis(2),
            loss: 0.0,
            burst: None,
            bandwidth: None,
            reorder: 0.0,
            reorder_extra: Duration::ZERO,
        }),
        "rtt170-loss2" => Some(ImpairProfile {
            name: "rtt170-loss2",
            delay: Duration::from_millis(85),
            jitter: Duration::from_millis(2),
            loss: 0.02,
            burst: None,
            bandwidth: None,
            reorder: 0.0,
            reorder_extra: Duration::ZERO,
        }),
        "cn163-peak" => Some(cn163("cn163-peak", 0.08)),
        "cn163-offpeak" => Some(cn163("cn163-offpeak", 0.02)),
        _ => None,
    }
}

/// Per-direction packet scheduler: decides drop, release time and ordering.
#[derive(Debug, Clone)]
pub struct Shaper {
    profile: ImpairProfile,
    rng: Rng,
    loss: LossModel,
    /// Earliest instant the link is free again, for the bandwidth cap.
    next_free: Instant,
}

impl Shaper {
    pub fn new(profile: ImpairProfile, seed: u64) -> Self {
        let loss = profile.loss_model();
        Self {
            profile,
            rng: Rng::new(seed),
            loss,
            next_free: Instant::now(),
        }
    }

    /// Schedule one packet of `len` bytes arriving at `now`.
    ///
    /// Returns `None` when the packet is dropped, otherwise the instant it
    /// should leave the link.
    pub fn schedule(&mut self, now: Instant, len: usize) -> Option<Instant> {
        if self.loss.drop_packet(&mut self.rng) {
            return None;
        }
        let start = now.max(self.next_free);
        if let Some(rate) = self.profile.bandwidth {
            if rate > 0 {
                let seconds = len as f64 / rate as f64;
                self.next_free = start + Duration::from_secs_f64(seconds);
            }
        }
        let jitter = self.profile.jitter.as_secs_f64();
        let offset = if jitter > 0.0 {
            self.rng.next_range(-jitter, jitter)
        } else {
            0.0
        };
        let mut delay = self.profile.delay.as_secs_f64() + offset;
        if self.profile.reorder > 0.0 && self.rng.next_f64() < self.profile.reorder {
            delay += self.profile.reorder_extra.as_secs_f64();
        }
        Some(start + Duration::from_secs_f64(delay.max(0.0)))
    }
}

/// Packets waiting for their release instant, kept in release order.
#[derive(Default)]
struct Pending {
    entries: Vec<(Instant, u64, Vec<u8>)>,
    next_seq: u64,
}

impl Pending {
    fn push(&mut self, release: Instant, payload: Vec<u8>) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.entries.push((release, seq, payload));
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn next_release(&self) -> Option<Instant> {
        self.entries.iter().map(|entry| entry.0).min()
    }

    /// Remove and return the earliest entry if it is due at `now`.
    fn pop_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| (entry.0, entry.1))
            .map(|(index, _)| index)?;
        if self.entries[index].0 > now {
            return None;
        }
        Some(self.entries.swap_remove(index).2)
    }
}

/// Options for `segue-bench impair`.
///
/// `Eq` is implemented by hand because the profile carries `f64` rates; every
/// value comes from a constant table or a parsed integer, so none is NaN.
#[derive(Debug, Clone, PartialEq)]
pub struct ImpairOptions {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub profile: ImpairProfile,
    pub seed: u64,
    pub udp: bool,
    pub tcp: bool,
    /// TCP loss recovery emulation. Off keeps the historical TCP path.
    pub tcp_loss: TcpLoss,
    /// Stop after this long; `None` runs until Ctrl-C.
    pub duration: Option<Duration>,
    /// TCP blackout / reset / silent-drop. Default is off: the relay forwards
    /// exactly as it did before these faults existed.
    pub faults: FaultSchedule,
}

/// How the TCP relay treats the profile's loss model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpLoss {
    /// Delay, jitter and the bandwidth cap only. Loss draws are ignored and
    /// every byte is forwarded. This is the historical behaviour.
    #[default]
    Off,
    /// Delay a lost segment by the recovery model in the module docs.
    /// Bytes are never dropped.
    Emulate,
}

/// One blackout window, relative to TCP-listener start on the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlackoutSpec {
    /// When the blackout starts.
    pub after: Duration,
    /// How long it lasts. Zero is rejected by the parser.
    pub duration: Duration,
}

/// TCP faults for one impair run. Every field `None` leaves the relay unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FaultSchedule {
    /// Hold bytes in both directions for `duration`, starting `after` from
    /// listener start.
    pub blackout: Option<BlackoutSpec>,
    /// Close connections that exist at this offset from listener start, once.
    pub reset_after: Option<Duration>,
    /// Stop forwarding on connections that exist at this offset, forever,
    /// without closing them.
    pub silent_drop_after: Option<Duration>,
}

/// What to do with bytes on one relayed connection at `now`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultEffect {
    /// Write them now.
    Forward,
    /// Keep them until `until`, then write them. Sockets stay open.
    HoldUntil(Instant),
    /// Close both directions. Only a connection that existed at the reset.
    Close,
    /// Discard them and leave the sockets open.
    Silent,
}

/// Shared switches for every connection on one TCP relay.
#[derive(Clone)]
struct FaultPlan {
    blackout: watch::Sender<Option<(Instant, Instant)>>,
    reset_at: watch::Sender<Option<Instant>>,
    silent_at: watch::Sender<Option<Instant>>,
}

/// One connection's view of a [`FaultPlan`].
struct FaultWatch {
    blackout: watch::Receiver<Option<(Instant, Instant)>>,
    reset_at: watch::Receiver<Option<Instant>>,
    silent_at: watch::Receiver<Option<Instant>>,
}

impl FaultPlan {
    fn new() -> Self {
        let (blackout, _) = watch::channel(None);
        let (reset_at, _) = watch::channel(None);
        let (silent_at, _) = watch::channel(None);
        Self {
            blackout,
            reset_at,
            silent_at,
        }
    }

    fn subscribe(&self) -> FaultWatch {
        FaultWatch {
            blackout: self.blackout.subscribe(),
            reset_at: self.reset_at.subscribe(),
            silent_at: self.silent_at.subscribe(),
        }
    }

    fn install(&self, origin: Instant, schedule: &FaultSchedule) {
        // `send` drops the value when nothing is subscribed yet (the listener
        // starts before any connection). `send_replace` keeps it for the
        // receivers that subscribe afterwards.
        if let Some(spec) = schedule.blackout {
            let start = origin + spec.after;
            let _ = self
                .blackout
                .send_replace(Some((start, start + spec.duration)));
        }
        if let Some(after) = schedule.reset_after {
            let _ = self.reset_at.send_replace(Some(origin + after));
        }
        if let Some(after) = schedule.silent_drop_after {
            let _ = self.silent_at.send_replace(Some(origin + after));
        }
    }

    fn arm_blackout(&self, duration: Duration) {
        let start = Instant::now();
        let _ = self.blackout.send_replace(Some((start, start + duration)));
    }

    fn arm_reset(&self) {
        let _ = self.reset_at.send_replace(Some(Instant::now()));
    }

    fn arm_silent_drop(&self) {
        let _ = self.silent_at.send_replace(Some(Instant::now()));
    }
}

impl FaultWatch {
    fn snapshot(&self) -> (Option<(Instant, Instant)>, Option<Instant>, Option<Instant>) {
        (
            *self.blackout.borrow(),
            *self.reset_at.borrow(),
            *self.silent_at.borrow(),
        )
    }

    fn effect(&self, now: Instant, accepted_at: Instant, reset_done: bool) -> FaultEffect {
        let (blackout, reset_at, silent_at) = self.snapshot();
        fault_effect(now, accepted_at, blackout, reset_at, silent_at, reset_done)
    }

    /// Next instant strictly after `now` at which [`Self::effect`] might change.
    fn next_wake(&self, now: Instant, accepted_at: Instant) -> Option<Instant> {
        let (blackout, reset_at, silent_at) = self.snapshot();
        let mut wake = None;
        let mut consider = |instant: Instant| {
            if instant > now {
                wake = Some(match wake {
                    Some(earlier) if earlier < instant => earlier,
                    _ => instant,
                });
            }
        };
        if let Some((start, end)) = blackout {
            consider(start);
            consider(end);
        }
        if let Some(t0) = reset_at {
            if accepted_at <= t0 {
                consider(t0);
            }
        }
        if let Some(t0) = silent_at {
            if accepted_at <= t0 {
                consider(t0);
            }
        }
        wake
    }
}

/// `accepted_at <= reset_at` / `silent_at` means the connection existed when
/// the fault fired. A blackout holds every connection, including new ones.
fn fault_effect(
    now: Instant,
    accepted_at: Instant,
    blackout: Option<(Instant, Instant)>,
    reset_at: Option<Instant>,
    silent_at: Option<Instant>,
    reset_done: bool,
) -> FaultEffect {
    if let Some(t0) = reset_at {
        if !reset_done && accepted_at <= t0 && now >= t0 {
            return FaultEffect::Close;
        }
    }
    if let Some(t0) = silent_at {
        if accepted_at <= t0 && now >= t0 {
            return FaultEffect::Silent;
        }
    }
    if let Some((start, end)) = blackout {
        if now >= start && now < end {
            return FaultEffect::HoldUntil(end);
        }
    }
    FaultEffect::Forward
}

async fn fault_changed(watch: &mut FaultWatch) {
    tokio::select! {
        biased;
        result = watch.blackout.changed() => {
            let _ = result;
        }
        result = watch.reset_at.changed() => {
            let _ = result;
        }
        result = watch.silent_at.changed() => {
            let _ = result;
        }
    }
}

async fn sleep_or_pending(at: Option<Instant>) {
    match at {
        Some(instant) => sleep_until(instant).await,
        None => std::future::pending::<()>().await,
    }
}

fn earliest(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Per-direction counters and the fault watch for one connection.
struct DirCtl<'a> {
    bytes: &'a RelayBytes,
    toward_upstream: bool,
    watch: &'a mut FaultWatch,
    accepted_at: Instant,
}

/// Bytes the TCP relay has written, per direction.
#[derive(Debug, Default)]
pub struct RelayBytes {
    /// Client → upstream.
    pub up: AtomicU64,
    /// Upstream → client.
    pub down: AtomicU64,
}

/// A loopback TCP impairment relay. Dropping it asks the accept loop to stop.
pub struct TcpRelay {
    pub local: SocketAddr,
    pub bytes: Arc<RelayBytes>,
    stop: watch::Sender<bool>,
    plan: FaultPlan,
    accepted: Arc<AtomicU64>,
}

impl Drop for TcpRelay {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

impl TcpRelay {
    pub fn up_bytes(&self) -> u64 {
        self.bytes.up.load(Ordering::Relaxed)
    }

    pub fn down_bytes(&self) -> u64 {
        self.bytes.down.load(Ordering::Relaxed)
    }

    /// TCP connections this relay has accepted, including ones later dropped.
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Hold every TCP byte in both directions for `duration`, starting now.
    /// Sockets stay open. Bytes read in the window are written after it.
    pub fn arm_blackout(&self, duration: Duration) {
        self.plan.arm_blackout(duration);
    }

    /// Close both directions of every connection that exists now, once.
    /// Connections accepted after this call are not closed.
    pub fn arm_reset(&self) {
        self.plan.arm_reset();
    }

    /// Stop forwarding on connections that exist now, forever, without closing
    /// them. Connections accepted after this call forward normally.
    pub fn arm_silent_drop(&self) {
        self.plan.arm_silent_drop();
    }
}

impl Eq for ImpairOptions {}

pub fn parse_impair_args(args: &[String]) -> Result<ImpairOptions, BenchError> {
    let mut listen = None;
    let mut upstream = None;
    let mut profile_name = "clean".to_owned();
    let mut seed = 0u64;
    let mut udp = true;
    let mut tcp = true;
    let mut tcp_loss = TcpLoss::Off;
    let mut duration = None;
    let mut faults = FaultSchedule::default();

    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--listen" => {
                let raw = required_value(args, &mut index, flag)?;
                listen = Some(raw.parse::<SocketAddr>().map_err(|_| {
                    BenchError::InvalidArguments(format!(
                        "invalid socket address `{raw}` for {flag}"
                    ))
                })?);
            }
            "--upstream" => {
                let raw = required_value(args, &mut index, flag)?;
                upstream = Some(raw.parse::<SocketAddr>().map_err(|_| {
                    BenchError::InvalidArguments(format!(
                        "invalid socket address `{raw}` for {flag}"
                    ))
                })?);
            }
            "--profile" => {
                profile_name = required_value(args, &mut index, flag)?.to_owned();
            }
            "--seed" => {
                seed = parse_u64(required_value(args, &mut index, flag)?, flag)?;
            }
            "--protocol" => match required_value(args, &mut index, flag)? {
                "udp" => {
                    udp = true;
                    tcp = false;
                }
                "tcp" => {
                    udp = false;
                    tcp = true;
                }
                "both" => {
                    udp = true;
                    tcp = true;
                }
                other => {
                    return Err(BenchError::InvalidArguments(format!(
                        "unsupported protocol `{other}` (expected udp, tcp or both)"
                    )))
                }
            },
            "--duration-ms" => {
                duration = Some(Duration::from_millis(parse_u64(
                    required_value(args, &mut index, flag)?,
                    flag,
                )?));
            }
            "--tcp-loss" => match required_value(args, &mut index, flag)? {
                "off" => tcp_loss = TcpLoss::Off,
                "emulate" => tcp_loss = TcpLoss::Emulate,
                other => {
                    return Err(BenchError::InvalidArguments(format!(
                        "unsupported tcp loss mode `{other}` (expected off or emulate)"
                    )))
                }
            },
            "--blackout" => {
                let raw = required_value(args, &mut index, flag)?;
                let (after, duration) = parse_blackout(raw)?;
                faults.blackout = Some(BlackoutSpec { after, duration });
            }
            "--reset-at" => {
                faults.reset_after = Some(Duration::from_millis(parse_u64(
                    required_value(args, &mut index, flag)?,
                    flag,
                )?));
            }
            "--silent-drop-at" => {
                faults.silent_drop_after = Some(Duration::from_millis(parse_u64(
                    required_value(args, &mut index, flag)?,
                    flag,
                )?));
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{}",
                    crate::USAGE
                )))
            }
        }
    }

    let listen = listen.ok_or_else(|| {
        BenchError::InvalidArguments("impair requires --listen <addr>".to_owned())
    })?;
    let upstream = upstream.ok_or_else(|| {
        BenchError::InvalidArguments("impair requires --upstream <addr>".to_owned())
    })?;
    let profile = profile(&profile_name).ok_or_else(|| {
        BenchError::InvalidArguments(format!(
            "unknown profile `{profile_name}` (expected one of {})",
            PROFILE_NAMES.join(", ")
        ))
    })?;
    Ok(ImpairOptions {
        listen,
        upstream,
        profile,
        seed,
        udp,
        tcp,
        tcp_loss,
        duration,
        faults,
    })
}

/// `--blackout <t0_ms>:<duration_ms>`. Both numbers are milliseconds.
fn parse_blackout(raw: &str) -> Result<(Duration, Duration), BenchError> {
    let Some((start, dur)) = raw.split_once(':') else {
        return Err(BenchError::InvalidArguments(format!(
            "invalid --blackout `{raw}` (expected <t0_ms>:<duration_ms>)"
        )));
    };
    if dur.contains(':') {
        return Err(BenchError::InvalidArguments(format!(
            "invalid --blackout `{raw}` (expected <t0_ms>:<duration_ms>)"
        )));
    }
    let after = Duration::from_millis(parse_u64(start, "--blackout")?);
    let duration = Duration::from_millis(parse_u64(dur, "--blackout")?);
    if duration.is_zero() {
        return Err(BenchError::InvalidArguments(
            "--blackout duration must be > 0".to_owned(),
        ));
    }
    Ok((after, duration))
}

/// Run the relay until the duration elapses or Ctrl-C is received.
pub async fn run(options: ImpairOptions) -> Result<(), BenchError> {
    let mut tasks = Vec::new();
    if options.udp {
        let udp = options.clone();
        tasks.push(tokio::spawn(async move { run_udp(udp).await }));
    }
    if options.tcp {
        let tcp = options.clone();
        tasks.push(tokio::spawn(async move { run_tcp(tcp).await }));
    }
    if tasks.is_empty() {
        return Err(BenchError::InvalidArguments(
            "impair needs at least one protocol".to_owned(),
        ));
    }

    let stop = async {
        match options.duration {
            Some(duration) => sleep_until(Instant::now() + duration).await,
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    };
    tokio::pin!(stop);

    let mut tasks = tasks.into_iter();
    let first = tasks.next().expect("at least one protocol task");
    tokio::select! {
        _ = &mut stop => {}
        result = first => {
            return result.map_err(|error| BenchError::InvalidArguments(error.to_string()))?;
        }
    }
    for task in tasks {
        task.abort();
    }
    Ok(())
}

async fn run_udp(options: ImpairOptions) -> Result<(), BenchError> {
    let listen =
        Arc::new(
            UdpSocket::bind(options.listen)
                .await
                .map_err(|source| BenchError::Io {
                    action: format!("binding UDP {}", options.listen),
                    source,
                })?,
        );
    let mut clients: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buffer = vec![0u8; 65_535];
    loop {
        let (len, from) = listen
            .recv_from(&mut buffer)
            .await
            .map_err(|source| BenchError::Io {
                action: "receiving on the impair UDP listener".to_owned(),
                source,
            })?;
        let payload = buffer[..len].to_vec();
        if let Some(sender) = clients.get(&from) {
            if sender.send(payload.clone()).await.is_ok() {
                continue;
            }
            clients.remove(&from);
        }
        let upstream = UdpSocket::bind((options.listen.ip(), 0))
            .await
            .map_err(|source| BenchError::Io {
                action: "binding the impair upstream UDP socket".to_owned(),
                source,
            })?;
        upstream
            .connect(options.upstream)
            .await
            .map_err(|source| BenchError::Io {
                action: format!("connecting UDP to {}", options.upstream),
                source,
            })?;
        let (sender, receiver) = mpsc::channel(1024);
        let _ = sender.send(payload).await;
        clients.insert(from, sender);
        let profile = options.profile.clone();
        let seed = options.seed;
        let listen = Arc::clone(&listen);
        tokio::spawn(async move {
            let _ = relay_udp_client(receiver, upstream, listen, from, profile, seed).await;
        });
    }
}

async fn relay_udp_client(
    mut inbound: mpsc::Receiver<Vec<u8>>,
    upstream: UdpSocket,
    listen: Arc<UdpSocket>,
    client: SocketAddr,
    profile: ImpairProfile,
    seed: u64,
) -> Result<(), BenchError> {
    let mut up_shaper = Shaper::new(profile.clone(), direction_seed(seed, false));
    let mut down_shaper = Shaper::new(profile, direction_seed(seed, true));
    let mut up_pending = Pending::default();
    let mut down_pending = Pending::default();
    let mut buffer = vec![0u8; 65_535];

    loop {
        let wake = match (up_pending.next_release(), down_pending.next_release()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let sleep = async {
            match wake {
                Some(instant) => sleep_until(instant).await,
                None => std::future::pending::<()>().await,
            }
        };

        tokio::select! {
            incoming = inbound.recv() => {
                let Some(payload) = incoming else { return Ok(()) };
                let now = Instant::now();
                if let Some(release) = up_shaper.schedule(now, payload.len()) {
                    up_pending.push(release, payload);
                }
            }
            received = upstream.recv(&mut buffer) => {
                let len = received.map_err(|source| BenchError::Io {
                    action: "receiving from the impair upstream".to_owned(),
                    source,
                })?;
                let payload = buffer[..len].to_vec();
                let now = Instant::now();
                if let Some(release) = down_shaper.schedule(now, payload.len()) {
                    down_pending.push(release, payload);
                }
            }
            _ = sleep => {}
        }

        let now = Instant::now();
        while let Some(payload) = up_pending.pop_due(now) {
            upstream
                .send(&payload)
                .await
                .map_err(|source| BenchError::Io {
                    action: "sending to the impair upstream".to_owned(),
                    source,
                })?;
        }
        while let Some(payload) = down_pending.pop_due(now) {
            listen
                .send_to(&payload, client)
                .await
                .map_err(|source| BenchError::Io {
                    action: "sending to the impair client".to_owned(),
                    source,
                })?;
        }
        if up_pending.is_empty() && down_pending.is_empty() && inbound.is_closed() {
            return Ok(());
        }
    }
}

async fn run_tcp(options: ImpairOptions) -> Result<(), BenchError> {
    let listener = TcpListener::bind(options.listen)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("binding TCP {}", options.listen),
            source,
        })?;
    let plan = FaultPlan::new();
    plan.install(Instant::now(), &options.faults);
    let shared = TcpShared {
        upstream: options.upstream,
        profile: options.profile,
        seed: options.seed,
        tcp_loss: options.tcp_loss,
        bytes: Arc::new(RelayBytes::default()),
        plan,
        accepted: Arc::new(AtomicU64::new(0)),
    };
    let (_stop_tx, stop_rx) = watch::channel(false);
    accept_tcp(listener, shared, stop_rx).await
}

/// Bind a TCP impairment relay. `listen` may be port 0; [`TcpRelay::local`] is
/// the bound address. Used by in-process tests. The CLI uses [`run`].
pub async fn serve_tcp(
    listen: SocketAddr,
    upstream: SocketAddr,
    profile: ImpairProfile,
    seed: u64,
    tcp_loss: TcpLoss,
) -> Result<TcpRelay, BenchError> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("binding TCP {listen}"),
            source,
        })?;
    let local = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading the impair TCP listen address".to_owned(),
        source,
    })?;
    let bytes = Arc::new(RelayBytes::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let plan = FaultPlan::new();
    let accepted = Arc::new(AtomicU64::new(0));
    let shared = TcpShared {
        upstream,
        profile,
        seed,
        tcp_loss,
        bytes: Arc::clone(&bytes),
        plan: plan.clone(),
        accepted: Arc::clone(&accepted),
    };
    tokio::spawn(async move {
        let _ = accept_tcp(listener, shared, stop_rx).await;
    });
    Ok(TcpRelay {
        local,
        bytes,
        stop: stop_tx,
        plan,
        accepted,
    })
}

/// State shared by every connection on one TCP listener.
struct TcpShared {
    upstream: SocketAddr,
    profile: ImpairProfile,
    seed: u64,
    tcp_loss: TcpLoss,
    bytes: Arc<RelayBytes>,
    plan: FaultPlan,
    accepted: Arc<AtomicU64>,
}

async fn accept_tcp(
    listener: TcpListener,
    shared: TcpShared,
    mut stop: watch::Receiver<bool>,
) -> Result<(), BenchError> {
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (client, _) = accepted.map_err(|source| BenchError::Io {
                    action: "accepting on the impair TCP listener".to_owned(),
                    source,
                })?;
                shared.accepted.fetch_add(1, Ordering::Relaxed);
                let accepted_at = Instant::now();
                let conn = ConnIn {
                    profile: shared.profile.clone(),
                    seed: shared.seed,
                    tcp_loss: shared.tcp_loss,
                    bytes: Arc::clone(&shared.bytes),
                    plan: shared.plan.clone(),
                    accepted_at,
                };
                let upstream = shared.upstream;
                tokio::spawn(async move {
                    let _ = relay_tcp_client(client, upstream, conn).await;
                });
            }
        }
    }
}

struct ConnIn {
    profile: ImpairProfile,
    seed: u64,
    tcp_loss: TcpLoss,
    bytes: Arc<RelayBytes>,
    plan: FaultPlan,
    accepted_at: Instant,
}

async fn relay_tcp_client(
    client: TcpStream,
    upstream_addr: SocketAddr,
    conn: ConnIn,
) -> Result<(), BenchError> {
    let ConnIn {
        profile,
        seed,
        tcp_loss,
        bytes,
        plan,
        accepted_at,
    } = conn;
    let upstream = TcpStream::connect(upstream_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting TCP to {upstream_addr}"),
            source,
        })?;
    if tcp_loss == TcpLoss::Emulate {
        // Small segments must not sit in Nagle while a recovery timer runs.
        // Off mode does not set this: that path's timing stays as it was.
        let _ = client.set_nodelay(true);
        let _ = upstream.set_nodelay(true);
    }
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let up_bytes = Arc::clone(&bytes);
    let down_bytes = bytes;
    let up_profile = profile.clone();
    let up_plan = plan.clone();
    let up = tokio::spawn(async move {
        let mut watch = up_plan.subscribe();
        let mut ctl = DirCtl {
            bytes: &up_bytes,
            toward_upstream: true,
            watch: &mut watch,
            accepted_at,
        };
        match tcp_loss {
            TcpLoss::Off => {
                relay_tcp_direction(
                    client_read,
                    upstream_write,
                    up_profile,
                    direction_seed(seed, false),
                    &mut ctl,
                )
                .await
            }
            TcpLoss::Emulate => {
                relay_tcp_direction_emulate(
                    client_read,
                    upstream_write,
                    up_profile,
                    direction_seed(seed, false),
                    &mut ctl,
                )
                .await
            }
        }
    });
    let down = tokio::spawn(async move {
        let mut watch = plan.subscribe();
        let mut ctl = DirCtl {
            bytes: &down_bytes,
            toward_upstream: false,
            watch: &mut watch,
            accepted_at,
        };
        match tcp_loss {
            TcpLoss::Off => {
                relay_tcp_direction(
                    upstream_read,
                    client_write,
                    profile,
                    direction_seed(seed, true),
                    &mut ctl,
                )
                .await
            }
            TcpLoss::Emulate => {
                relay_tcp_direction_emulate(
                    upstream_read,
                    client_write,
                    profile,
                    direction_seed(seed, true),
                    &mut ctl,
                )
                .await
            }
        }
    });
    let _ = up.await;
    let _ = down.await;
    Ok(())
}

/// TCP is reliable, so only delay, jitter and the bandwidth cap apply here.
/// A loss draw skips the delay (the historical path) and still forwards the bytes.
///
/// With no fault armed, a read still takes the shaper delay and is written
/// immediately afterwards. A fault only changes what happens after that delay,
/// or wakes a read that is blocked when the fault fires.
async fn relay_tcp_direction<R, W>(
    mut reader: R,
    mut writer: W,
    profile: ImpairProfile,
    seed: u64,
    ctl: &mut DirCtl<'_>,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut shaper = Shaper::new(profile, seed);
    let mut buffer = vec![0u8; 16 * 1024];
    let mut held = Vec::<u8>::new();
    let mut eof = false;
    loop {
        if eof && held.is_empty() {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        let now = Instant::now();
        match ctl.watch.effect(now, ctl.accepted_at, false) {
            FaultEffect::Close => {
                let _ = writer.shutdown().await;
                return Ok(());
            }
            FaultEffect::Silent => {
                held.clear();
                if eof {
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
                if read_discard(&mut reader, &mut buffer, ctl).await? {
                    eof = true;
                }
            }
            FaultEffect::HoldUntil(end) => {
                if eof {
                    sleep_until(end).await;
                    continue;
                }
                match read_hold(&mut reader, &mut buffer, &mut held, ctl, end).await? {
                    ReadHold::Eof => eof = true,
                    ReadHold::Buffered | ReadHold::Woke => {}
                }
            }
            FaultEffect::Forward => {
                if !held.is_empty() {
                    let closed = flush_held(&mut writer, &mut shaper, &mut held, ctl).await?;
                    if closed {
                        return Ok(());
                    }
                    continue;
                }
                if eof {
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
                match read_forward(
                    &mut reader,
                    &mut writer,
                    &mut buffer,
                    &mut shaper,
                    &mut held,
                    ctl,
                )
                .await?
                {
                    ForwardRead::Eof => return Ok(()),
                    ForwardRead::Again => {}
                }
            }
        }
    }
}

enum ReadHold {
    Eof,
    Buffered,
    Woke,
}

enum ForwardRead {
    Eof,
    Again,
}

async fn read_discard<R>(
    reader: &mut R,
    buffer: &mut [u8],
    ctl: &mut DirCtl<'_>,
) -> Result<bool, BenchError>
where
    R: AsyncRead + Unpin,
{
    let wake = ctl.watch.next_wake(Instant::now(), ctl.accepted_at);
    tokio::select! {
        biased;
        result = reader.read(buffer) => {
            let len = read_len(result)?;
            Ok(len == 0)
        }
        _ = sleep_or_pending(wake) => Ok(false),
        _ = fault_changed(ctl.watch) => Ok(false),
    }
}

async fn read_hold<R>(
    reader: &mut R,
    buffer: &mut [u8],
    held: &mut Vec<u8>,
    ctl: &mut DirCtl<'_>,
    end: Instant,
) -> Result<ReadHold, BenchError>
where
    R: AsyncRead + Unpin,
{
    tokio::select! {
        biased;
        result = reader.read(buffer) => {
            let len = read_len(result)?;
            if len == 0 {
                return Ok(ReadHold::Eof);
            }
            held.extend_from_slice(&buffer[..len]);
            Ok(ReadHold::Buffered)
        }
        _ = sleep_until(end) => Ok(ReadHold::Woke),
        _ = fault_changed(ctl.watch) => Ok(ReadHold::Woke),
    }
}

/// `Ok(true)` means this direction was closed and the caller must stop.
async fn flush_held<W>(
    writer: &mut W,
    shaper: &mut Shaper,
    held: &mut Vec<u8>,
    ctl: &mut DirCtl<'_>,
) -> Result<bool, BenchError>
where
    W: AsyncWrite + Unpin,
{
    let n = held.len();
    if let Some(release) = shaper.schedule(Instant::now(), n) {
        sleep_until(release).await;
    }
    let now = Instant::now();
    match ctl.watch.effect(now, ctl.accepted_at, false) {
        FaultEffect::Forward => {
            write_chunk(writer, held, ctl).await?;
            held.clear();
            Ok(false)
        }
        FaultEffect::Close => {
            let _ = writer.shutdown().await;
            held.clear();
            Ok(true)
        }
        FaultEffect::Silent => {
            held.clear();
            Ok(false)
        }
        FaultEffect::HoldUntil(_) => Ok(false),
    }
}

/// One historical read: shaper delay, then write, unless a fault now says
/// otherwise. An idle fault plan takes the same delay-then-write path as before.
async fn read_forward<R, W>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut [u8],
    shaper: &mut Shaper,
    held: &mut Vec<u8>,
    ctl: &mut DirCtl<'_>,
) -> Result<ForwardRead, BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let wake = ctl.watch.next_wake(Instant::now(), ctl.accepted_at);
    let read = tokio::select! {
        biased;
        result = reader.read(buffer) => Some(read_len(result)?),
        _ = sleep_or_pending(wake) => None,
        _ = fault_changed(ctl.watch) => None,
    };
    let Some(len) = read else {
        return Ok(ForwardRead::Again);
    };
    if len == 0 {
        let _ = writer.shutdown().await;
        return Ok(ForwardRead::Eof);
    }
    let chunk_at = Instant::now();
    match ctl.watch.effect(chunk_at, ctl.accepted_at, false) {
        FaultEffect::Close => {
            let _ = writer.shutdown().await;
            return Ok(ForwardRead::Eof);
        }
        FaultEffect::Silent => return Ok(ForwardRead::Again),
        FaultEffect::HoldUntil(_) => {
            held.extend_from_slice(&buffer[..len]);
            return Ok(ForwardRead::Again);
        }
        FaultEffect::Forward => {}
    }
    if let Some(release) = shaper.schedule(chunk_at, len) {
        sleep_until(release).await;
    }
    let now = Instant::now();
    match ctl.watch.effect(now, ctl.accepted_at, false) {
        FaultEffect::Forward => {
            write_chunk(writer, &buffer[..len], ctl).await?;
        }
        FaultEffect::HoldUntil(_) => held.extend_from_slice(&buffer[..len]),
        FaultEffect::Silent => {}
        FaultEffect::Close => {
            let _ = writer.shutdown().await;
            return Ok(ForwardRead::Eof);
        }
    }
    Ok(ForwardRead::Again)
}

fn read_len(result: std::io::Result<usize>) -> Result<usize, BenchError> {
    result.map_err(|source| BenchError::Io {
        action: "reading from the impair TCP relay".to_owned(),
        source,
    })
}

async fn write_chunk<W>(
    writer: &mut W,
    bytes: &[u8],
    ctl: &mut DirCtl<'_>,
) -> Result<(), BenchError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(bytes)
        .await
        .map_err(|source| BenchError::Io {
            action: "writing to the impair TCP relay".to_owned(),
            source,
        })?;
    add_bytes(ctl.bytes, ctl.toward_upstream, bytes.len());
    Ok(())
}

fn add_bytes(bytes: &RelayBytes, toward_upstream: bool, len: usize) {
    let counter = if toward_upstream {
        &bytes.up
    } else {
        &bytes.down
    };
    counter.fetch_add(len as u64, Ordering::Relaxed);
}

async fn relay_tcp_direction_emulate<R, W>(
    reader: R,
    writer: W,
    profile: ImpairProfile,
    seed: u64,
    ctl: &mut DirCtl<'_>,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    relay_tcp_emulate_with(reader, writer, TcpDirection::new(profile, seed), ctl).await
}

async fn relay_tcp_emulate_with<R, W>(
    mut reader: R,
    mut writer: W,
    mut direction: TcpDirection,
    ctl: &mut DirCtl<'_>,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; TCP_SEGMENT_CAP];
    loop {
        let now = Instant::now();
        let effect = ctl.watch.effect(now, ctl.accepted_at, false);
        if matches!(effect, FaultEffect::Close) {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        // A past segment deadline must stay past so a ready segment still
        // flushes. A blackout or silent drop must not spin on that deadline:
        // the queue is held or discarded, and the fault's own wake is enough.
        let segment_due = match effect {
            FaultEffect::HoldUntil(_) | FaultEffect::Silent => None,
            FaultEffect::Forward | FaultEffect::Close => direction.next_deadline(now),
        };
        let deadline = earliest(segment_due, ctl.watch.next_wake(now, ctl.accepted_at));
        let sleep = async {
            match deadline {
                Some(instant) => sleep_until(instant).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            read = reader.read(&mut buffer), if !direction.eof => {
                let len = read_len(read)?;
                if len == 0 {
                    direction.mark_eof(Instant::now());
                } else {
                    direction.push(Instant::now(), &buffer[..len]);
                }
            }
            _ = sleep, if deadline.is_some() => {}
            _ = fault_changed(ctl.watch) => {}
        }
        let now = Instant::now();
        match ctl.watch.effect(now, ctl.accepted_at, false) {
            FaultEffect::Close => {
                let _ = writer.shutdown().await;
                return Ok(());
            }
            FaultEffect::Silent => direction.discard(),
            FaultEffect::HoldUntil(_) => {}
            FaultEffect::Forward => {
                while let Some(payload) = direction.pop_ready(now) {
                    write_chunk(&mut writer, &payload, ctl).await?;
                }
                if direction.finished() {
                    let _ = writer.shutdown().await;
                    return Ok(());
                }
            }
        }
    }
}

/// One direction of a TCP relay in loss-recovery emulation.
struct TcpDirection {
    profile: ImpairProfile,
    rng: Rng,
    loss: LossModel,
    rtt: Duration,
    next_free: Option<Instant>,
    queue: VecDeque<Seg>,
    /// Segments seen. The next push is the SYN flight when this is zero.
    seen: u64,
    eof: bool,
    /// Test-only loss script. `None` draws from [`LossModel`].
    script: Option<VecDeque<(bool, u32)>>,
}

struct Seg {
    data: Vec<u8>,
    sent: Instant,
    arrival: Instant,
    /// Lost data segment whose recovery delay is not known yet.
    pending_recovery: bool,
    retx_losses: u32,
}

impl TcpDirection {
    fn new(profile: ImpairProfile, seed: u64) -> Self {
        let loss = profile.loss_model();
        let rtt = profile_rtt(&profile);
        Self {
            profile,
            rng: Rng::new(seed),
            loss,
            rtt,
            next_free: None,
            queue: VecDeque::new(),
            seen: 0,
            eof: false,
            script: None,
        }
    }

    #[cfg(test)]
    fn scripted(profile: ImpairProfile, script: Vec<(bool, u32)>) -> Self {
        let mut direction = Self::new(profile, 0);
        direction.script = Some(script.into());
        direction
    }

    fn mark_eof(&mut self, now: Instant) {
        self.eof = true;
        self.decide(now);
    }

    fn finished(&self) -> bool {
        self.eof && self.queue.is_empty()
    }

    /// Drop every queued segment without writing it. Silent drop uses this so
    /// a dead mapping does not deliver bytes and does not close the socket.
    fn discard(&mut self) {
        self.queue.clear();
    }

    fn push(&mut self, now: Instant, data: &[u8]) {
        let (lost, retx_losses) = self.draw_loss();
        self.enqueue(now, data, lost, retx_losses);
    }

    /// `lost` / `retx_losses` bypass the RNG. Tests use this for exact timers.
    #[cfg(test)]
    fn push_controlled(&mut self, now: Instant, data: &[u8], lost: bool, retx_losses: u32) {
        self.enqueue(now, data, lost, retx_losses);
    }

    fn enqueue(&mut self, now: Instant, data: &[u8], lost: bool, retx_losses: u32) {
        let first = self.seen == 0;
        self.seen += 1;
        let (arrival, pending_recovery) = if !lost {
            (self.base_arrival(now, data.len()), false)
        } else if first {
            (add_instant(now, syn_recovery(self.rtt, retx_losses)), false)
        } else {
            (now, true)
        };
        self.queue.push_back(Seg {
            data: data.to_vec(),
            sent: now,
            arrival,
            pending_recovery,
            retx_losses,
        });
        self.decide(now);
    }

    fn draw_loss(&mut self) -> (bool, u32) {
        if let Some(script) = self.script.as_mut() {
            return script.pop_front().unwrap_or((false, 0));
        }
        let lost = self.loss.drop_packet(&mut self.rng);
        if !lost {
            return (false, 0);
        }
        let mut retx_losses = 0u32;
        while retx_losses < TCP_MAX_RETX && self.loss.drop_packet(&mut self.rng) {
            retx_losses += 1;
        }
        (true, retx_losses)
    }

    /// One-way delay, jitter, reorder extra and bandwidth, without a loss draw.
    fn base_arrival(&mut self, now: Instant, len: usize) -> Instant {
        let start = match self.next_free {
            Some(free) => now.max(free),
            None => now,
        };
        if let Some(rate) = self.profile.bandwidth {
            if rate > 0 {
                let seconds = len as f64 / rate as f64;
                self.next_free = Some(start + Duration::from_secs_f64(seconds));
            }
        }
        let jitter = self.profile.jitter.as_secs_f64();
        let offset = if jitter > 0.0 {
            self.rng.next_range(-jitter, jitter)
        } else {
            0.0
        };
        let mut delay = self.profile.delay.as_secs_f64() + offset;
        if self.profile.reorder > 0.0 && self.rng.next_f64() < self.profile.reorder {
            delay += self.profile.reorder_extra.as_secs_f64();
        }
        start + Duration::from_secs_f64(delay.max(0.0))
    }

    fn decide(&mut self, now: Instant) {
        let rtt = self.rtt;
        let eof = self.eof;
        let n = self.queue.len();
        for i in 0..n {
            if !self.queue[i].pending_recovery {
                continue;
            }
            let sent = self.queue[i].sent;
            let window_end = add_instant(sent, rtt);
            let inflight = self
                .queue
                .iter()
                .skip(i + 1)
                .filter(|seg| seg.sent <= window_end)
                .count();
            if inflight >= TCP_FAST_RETRANS_INFLIGHT || eof || now >= window_end {
                let retx_losses = self.queue[i].retx_losses;
                let delay = data_recovery(rtt, inflight, retx_losses);
                self.queue[i].arrival = add_instant(sent, delay);
                self.queue[i].pending_recovery = false;
            }
        }
    }

    fn next_deadline(&mut self, now: Instant) -> Option<Instant> {
        self.decide(now);
        let front = self.queue.front()?;
        if front.pending_recovery {
            return Some(add_instant(front.sent, self.rtt));
        }
        Some(front.arrival)
    }

    fn pop_ready(&mut self, now: Instant) -> Option<Vec<u8>> {
        self.decide(now);
        let front = self.queue.front()?;
        if front.pending_recovery || front.arrival > now {
            return None;
        }
        self.queue.pop_front().map(|seg| seg.data)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    fn empirical_loss(profile: &ImpairProfile, seed: u64, packets: usize) -> f64 {
        let mut model = profile.loss_model();
        let mut rng = Rng::new(seed);
        let dropped = (0..packets).filter(|_| model.drop_packet(&mut rng)).count();
        dropped as f64 / packets as f64
    }

    #[test]
    fn rng_is_deterministic_for_a_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        assert_ne!(Rng::new(42).next_u64(), c.next_u64());
    }

    #[test]
    fn rng_stays_in_the_unit_interval() {
        let mut rng = Rng::new(7);
        for _ in 0..10_000 {
            let value = rng.next_f64();
            assert!((0.0..1.0).contains(&value), "{value}");
        }
    }

    #[test]
    fn uniform_loss_matches_its_rate() {
        let profile = profile("rtt170-loss2").unwrap();
        let measured = empirical_loss(&profile, 1, 200_000);
        assert!(
            (measured - 0.02).abs() < 0.003,
            "measured {measured} for a 2% profile"
        );
    }

    #[test]
    fn gilbert_elliott_steady_state_matches_the_profile() {
        let profile = profile("cn163-peak").unwrap();
        let model = profile.loss_model();
        assert!((model.steady_state_loss() - 0.08).abs() < 0.001);
        let measured = empirical_loss(&profile, 2, 500_000);
        assert!(
            (measured - 0.08).abs() < 0.01,
            "measured {measured} for an 8% burst profile"
        );
    }

    #[test]
    fn gilbert_elliott_bursts_are_runs_not_isolated_drops() {
        let profile = profile("cn163-peak").unwrap();
        let mut model = profile.loss_model();
        let mut rng = Rng::new(3);
        let mut runs = Vec::new();
        let mut current = 0usize;
        for _ in 0..200_000 {
            if model.drop_packet(&mut rng) {
                current += 1;
            } else if current > 0 {
                runs.push(current);
                current = 0;
            }
        }
        assert!(!runs.is_empty());
        let mean = runs.iter().sum::<usize>() as f64 / runs.len() as f64;
        // The model is tuned for ~3-packet bursts; a uniform 8% model would
        // average ~1.09.
        assert!((2.0..4.5).contains(&mean), "mean burst {mean}");
    }

    #[test]
    fn offpeak_profile_is_less_lossy_than_peak() {
        let peak = profile("cn163-peak").unwrap().steady_state_loss();
        let offpeak = profile("cn163-offpeak").unwrap().steady_state_loss();
        assert!((offpeak - 0.02).abs() < 0.001);
        assert!(offpeak < peak);
    }

    #[test]
    fn clean_profile_never_drops() {
        let profile = profile("clean").unwrap();
        assert_eq!(empirical_loss(&profile, 9, 10_000), 0.0);
    }

    #[test]
    fn shaper_drops_nothing_without_loss() {
        let mut shaper = Shaper::new(profile("rtt170").unwrap(), 5);
        let now = Instant::now();
        for _ in 0..1000 {
            assert!(shaper.schedule(now, 100).is_some());
        }
    }

    #[test]
    fn bandwidth_cap_serialises_packets() {
        let mut profile = profile("clean").unwrap();
        profile.bandwidth = Some(100_000);
        let mut shaper = Shaper::new(profile, 6);
        let now = Instant::now();
        let first = shaper.schedule(now, 10_000).unwrap();
        let second = shaper.schedule(now, 10_000).unwrap();
        // 10 kB at 100 kB/s is 100 ms of serialisation.
        assert!(second - first >= Duration::from_millis(99));
    }

    #[test]
    fn pending_queue_releases_in_time_order() {
        let now = Instant::now();
        let mut pending = Pending::default();
        pending.push(now + Duration::from_millis(30), b"late".to_vec());
        pending.push(now + Duration::from_millis(10), b"early".to_vec());
        assert_eq!(
            pending.next_release(),
            Some(now + Duration::from_millis(10))
        );
        assert!(pending.pop_due(now).is_none());
        assert_eq!(
            pending.pop_due(now + Duration::from_millis(20)),
            Some(b"early".to_vec())
        );
        assert_eq!(
            pending.pop_due(now + Duration::from_millis(40)),
            Some(b"late".to_vec())
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn parse_impair_args_accepts_a_named_profile() {
        let args = [
            "--listen",
            "127.0.0.1:1080",
            "--upstream",
            "127.0.0.1:9000",
            "--profile",
            "cn163-peak",
            "--seed",
            "7",
        ]
        .map(str::to_owned);
        let options = parse_impair_args(&args).unwrap();
        assert_eq!(options.profile.name, "cn163-peak");
        assert_eq!(options.seed, 7);
        assert!(options.udp && options.tcp);
        assert_eq!(options.tcp_loss, TcpLoss::Off);
    }

    #[test]
    fn parse_impair_args_rejects_an_unknown_profile() {
        let args = [
            "--listen",
            "127.0.0.1:1080",
            "--upstream",
            "127.0.0.1:9000",
            "--profile",
            "nope",
        ]
        .map(str::to_owned);
        assert!(parse_impair_args(&args).is_err());
    }

    #[test]
    fn parse_impair_args_accepts_tcp_loss_emulate() {
        let args = [
            "--listen",
            "127.0.0.1:1080",
            "--upstream",
            "127.0.0.1:9000",
            "--tcp-loss",
            "emulate",
        ]
        .map(str::to_owned);
        let options = parse_impair_args(&args).unwrap();
        assert_eq!(options.tcp_loss, TcpLoss::Emulate);
    }

    #[test]
    fn parse_impair_args_rejects_an_unknown_tcp_loss_mode() {
        let args = [
            "--listen",
            "127.0.0.1:1080",
            "--upstream",
            "127.0.0.1:9000",
            "--tcp-loss",
            "drop",
        ]
        .map(str::to_owned);
        assert!(parse_impair_args(&args).is_err());
    }

    fn test_now() -> Instant {
        Instant::from_std(std::time::Instant::now())
    }

    /// One-way delay, no jitter, no loss. `rtt` is twice `delay_ms`.
    fn quiet(delay_ms: u64) -> ImpairProfile {
        let mut profile = profile("clean").unwrap();
        profile.delay = Duration::from_millis(delay_ms);
        profile
    }

    #[test]
    fn fast_retransmit_holds_the_hole_for_one_rtt() {
        let mut direction = TcpDirection::new(quiet(85), 1);
        let t0 = test_now();
        // Not the SYN flight: a clean first segment, then a lost one with 3 followers.
        direction.push_controlled(t0, b"syn", false, 0);
        direction.push_controlled(t0 + Duration::from_millis(1), b"lost", true, 0);
        direction.push_controlled(t0 + Duration::from_millis(2), b"a", false, 0);
        direction.push_controlled(t0 + Duration::from_millis(3), b"b", false, 0);
        direction.push_controlled(t0 + Duration::from_millis(4), b"c", false, 0);

        let syn_due = t0 + Duration::from_millis(85);
        assert_eq!(direction.pop_ready(syn_due), Some(b"syn".to_vec()));
        // Followers are only one way out, but the hole is in front of them.
        assert!(direction
            .pop_ready(t0 + Duration::from_millis(169))
            .is_none());
        let due = t0 + Duration::from_millis(1 + 170);
        assert_eq!(direction.pop_ready(due), Some(b"lost".to_vec()));
        assert_eq!(direction.pop_ready(due), Some(b"a".to_vec()));
        assert_eq!(direction.pop_ready(due), Some(b"b".to_vec()));
        assert_eq!(direction.pop_ready(due), Some(b"c".to_vec()));
        assert!(direction.queue.is_empty());
    }

    #[test]
    fn tail_loss_uses_two_rtts_when_fewer_than_three_follow() {
        let mut direction = TcpDirection::new(quiet(85), 1);
        let t0 = test_now();
        direction.push_controlled(t0, b"syn", false, 0);
        let sent = t0 + Duration::from_millis(10);
        direction.push_controlled(sent, b"tail", true, 0);
        direction.push_controlled(sent + Duration::from_millis(10), b"one", false, 0);

        assert_eq!(
            direction.pop_ready(t0 + Duration::from_millis(85)),
            Some(b"syn".to_vec())
        );
        // Window still open and inflight is 1: recovery is not decided yet.
        assert_eq!(
            direction.next_deadline(sent + Duration::from_millis(169)),
            Some(sent + Duration::from_millis(170))
        );
        // The window just closed, so the tail-loss probe is 2 * rtt, not yet due.
        assert!(direction
            .pop_ready(sent + Duration::from_millis(170))
            .is_none());
        let due = sent + Duration::from_millis(340);
        assert_eq!(direction.pop_ready(due), Some(b"tail".to_vec()));
        assert_eq!(direction.pop_ready(due), Some(b"one".to_vec()));
    }

    #[test]
    fn retransmission_loss_adds_a_doubling_rto() {
        let mut direction = TcpDirection::new(quiet(85), 1);
        let t0 = test_now();
        direction.push_controlled(t0, b"syn", false, 0);
        // inflight will be 3, two retransmission losses.
        // delay = rtt + RTO + 2*RTO, RTO = max(200ms, 3*170ms) = 510ms.
        direction.push_controlled(t0, b"lost", true, 2);
        direction.push_controlled(t0 + Duration::from_millis(1), b"a", false, 0);
        direction.push_controlled(t0 + Duration::from_millis(2), b"b", false, 0);
        direction.push_controlled(t0 + Duration::from_millis(3), b"c", false, 0);
        let delay = Duration::from_millis(170 + 510 + 1020);
        assert!(direction
            .pop_ready(t0 + delay - Duration::from_millis(1))
            .is_some()); // SYN only
        assert!(direction
            .pop_ready(t0 + delay - Duration::from_millis(1))
            .is_none());
        assert_eq!(direction.pop_ready(t0 + delay), Some(b"lost".to_vec()));
    }

    #[test]
    fn syn_loss_is_one_second_then_another() {
        let t0 = test_now();
        let mut once = TcpDirection::new(quiet(85), 1);
        once.push_controlled(t0, b"syn", true, 0);
        assert!(once.pop_ready(t0 + Duration::from_millis(999)).is_none());
        assert_eq!(
            once.pop_ready(t0 + Duration::from_secs(1)),
            Some(b"syn".to_vec())
        );

        let mut twice = TcpDirection::new(quiet(85), 1);
        twice.push_controlled(t0, b"syn", true, 1);
        assert!(twice.pop_ready(t0 + Duration::from_millis(1999)).is_none());
        assert_eq!(
            twice.pop_ready(t0 + Duration::from_secs(2)),
            Some(b"syn".to_vec())
        );

        // A third loss leaves the SYN special case and adds one RTO step.
        let mut more = TcpDirection::new(quiet(85), 1);
        more.push_controlled(t0, b"syn", true, 2);
        let due = t0 + Duration::from_secs(2) + Duration::from_millis(510);
        assert!(more.pop_ready(due - Duration::from_millis(1)).is_none());
        assert_eq!(more.pop_ready(due), Some(b"syn".to_vec()));
    }

    #[test]
    fn emulate_loss_draws_match_the_profile_model() {
        // Jitter and reorder also consume the seeded RNG. Zero them here so the
        // loss draws line up with a LossModel walked on its own; the cadence
        // test below uses the real profile, jitter included.
        let mut profile = profile("cn163-peak").unwrap();
        profile.jitter = Duration::ZERO;
        profile.reorder = 0.0;
        let now = test_now();
        for seed in [1u64, 2, 3, 99] {
            let mut model = profile.loss_model();
            let mut rng = Rng::new(seed);
            let mut direction = TcpDirection::new(profile.clone(), seed);
            for i in 0..200 {
                let lost = model.drop_packet(&mut rng);
                let mut retx = 0u32;
                if lost {
                    while retx < TCP_MAX_RETX && model.drop_packet(&mut rng) {
                        retx += 1;
                    }
                }
                direction.push(now, b"x");
                let seg = direction.queue.back().unwrap();
                assert_eq!(seg.retx_losses, retx, "seed {seed} seg {i}");
                if lost && i > 0 {
                    // Nothing later has been pushed yet, so the window is open
                    // and inflight is still 0.
                    assert!(seg.pending_recovery, "seed {seed} seg {i}");
                }
            }
        }
    }

    #[test]
    fn emulate_recovery_is_deterministic_for_a_seed() {
        let profile = profile("cn163-peak").unwrap();
        let now = test_now();
        for seed in [1u64, 2, 3] {
            let mut left = TcpDirection::new(profile.clone(), seed);
            let mut right = TcpDirection::new(profile.clone(), seed);
            for _ in 0..200 {
                left.push(now, b"x");
                right.push(now, b"x");
            }
            let left: Vec<_> = left
                .queue
                .iter()
                .map(|seg| (seg.retx_losses, seg.pending_recovery, seg.arrival))
                .collect();
            let right: Vec<_> = right
                .queue
                .iter()
                .map(|seg| (seg.retx_losses, seg.pending_recovery, seg.arrival))
                .collect();
            assert_eq!(left, right, "seed {seed}");
        }
    }

    #[test]
    fn eof_closes_the_inflight_window() {
        let mut direction = TcpDirection::new(quiet(85), 1);
        let t0 = test_now();
        direction.push_controlled(t0, b"syn", false, 0);
        direction.push_controlled(t0, b"tail", true, 0);
        direction.mark_eof(t0);
        // No followers and the window is forced shut: tail-loss probe, 2 * rtt.
        assert_eq!(
            direction.pop_ready(t0 + Duration::from_millis(85)),
            Some(b"syn".to_vec())
        );
        assert!(direction
            .pop_ready(t0 + Duration::from_millis(339))
            .is_none());
        assert_eq!(
            direction.pop_ready(t0 + Duration::from_millis(340)),
            Some(b"tail".to_vec())
        );
    }

    /// Download direction of the token harness: 30 B every 20 ms.
    /// cn163-peak must produce a gap over 300 ms for each benchmark seed,
    /// or the end-to-end sanity check cannot pass.
    #[test]
    fn cn163_peak_token_cadence_stalls_for_benchmark_seeds() {
        for seed in [1u64, 2, 3] {
            let gap = token_cadence_max_gap("cn163-peak", direction_seed(seed, true));
            assert!(
                gap > Duration::from_millis(300),
                "seed {seed} down-direction max gap {} ms",
                gap.as_millis()
            );
        }
    }

    fn token_cadence_max_gap(name: &str, seed: u64) -> Duration {
        let profile = profile(name).unwrap();
        let mut direction = TcpDirection::new(profile, seed);
        let base = test_now();
        let n = 500u64;
        let mut next_push = 0u64;
        let mut now = base;
        let mut last: Option<Instant> = None;
        let mut max_gap = Duration::ZERO;
        let mut steps = 0u32;
        while next_push < n || !direction.queue.is_empty() {
            steps += 1;
            assert!(steps < 100_000, "cadence simulation did not finish");
            while next_push < n {
                let sent = base + Duration::from_millis(20 * next_push);
                if sent > now {
                    break;
                }
                direction.push(sent, &[0u8; 30]);
                next_push += 1;
            }
            let mut progressed = false;
            while let Some(_payload) = direction.pop_ready(now) {
                if let Some(prev) = last {
                    let gap = now.checked_duration_since(prev).unwrap_or(Duration::ZERO);
                    if gap > max_gap {
                        max_gap = gap;
                    }
                }
                last = Some(now);
                progressed = true;
            }
            let next_send = if next_push < n {
                Some(base + Duration::from_millis(20 * next_push))
            } else {
                None
            };
            let next_due = direction.next_deadline(now);
            let next = match (next_send, next_due) {
                (Some(send), Some(due)) => send.min(due),
                (Some(send), None) => send,
                (None, Some(due)) => due,
                (None, None) => break,
            };
            if next > now {
                now = next;
            } else if !progressed {
                now += Duration::from_micros(1);
            }
        }
        max_gap
    }

    fn duplex_pair() -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (input_w, input_r) = tokio::io::duplex(4096);
        let (output_w, output_r) = tokio::io::duplex(4096);
        (input_w, input_r, output_w, output_r)
    }

    fn spawn_off(
        profile: ImpairProfile,
        plan: FaultPlan,
        accepted_at: Instant,
        reader: tokio::io::DuplexStream,
        writer: tokio::io::DuplexStream,
    ) -> Arc<RelayBytes> {
        let bytes = Arc::new(RelayBytes::default());
        let task_bytes = Arc::clone(&bytes);
        tokio::spawn(async move {
            let mut watch = plan.subscribe();
            let mut ctl = DirCtl {
                bytes: &task_bytes,
                toward_upstream: true,
                watch: &mut watch,
                accepted_at,
            };
            let _ = relay_tcp_direction(reader, writer, profile, 1, &mut ctl).await;
        });
        bytes
    }

    fn spawn_emulate(
        profile: ImpairProfile,
        plan: FaultPlan,
        accepted_at: Instant,
        reader: tokio::io::DuplexStream,
        writer: tokio::io::DuplexStream,
    ) -> Arc<RelayBytes> {
        let bytes = Arc::new(RelayBytes::default());
        let task_bytes = Arc::clone(&bytes);
        tokio::spawn(async move {
            let mut watch = plan.subscribe();
            let mut ctl = DirCtl {
                bytes: &task_bytes,
                toward_upstream: true,
                watch: &mut watch,
                accepted_at,
            };
            let _ = relay_tcp_direction_emulate(reader, writer, profile, 1, &mut ctl).await;
        });
        bytes
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_off_still_forwards_bytes_the_loss_model_would_drop() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        let mut profile = profile("clean").unwrap();
        profile.loss = 1.0;
        profile.delay = Duration::from_millis(85);
        spawn_off(profile, FaultPlan::new(), Instant::now(), input_r, output_w);
        input_w.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        // Historical path: a loss draw skips the delay and still writes.
        tokio::time::timeout(Duration::from_millis(5), output_r.read_exact(&mut buf))
            .await
            .expect("off mode held bytes the loss model dropped")
            .unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_off_applies_one_way_delay_when_nothing_is_lost() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        spawn_off(
            quiet(85),
            FaultPlan::new(),
            Instant::now(),
            input_r,
            output_w,
        );
        input_w.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let early =
            tokio::time::timeout(Duration::from_millis(84), output_r.read_exact(&mut buf)).await;
        assert!(early.is_err(), "off mode released a segment early");
        output_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_emulate_applies_one_way_delay_when_nothing_is_lost() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        spawn_emulate(
            quiet(85),
            FaultPlan::new(),
            Instant::now(),
            input_r,
            output_w,
        );
        input_w.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let early =
            tokio::time::timeout(Duration::from_millis(84), output_r.read_exact(&mut buf)).await;
        assert!(early.is_err(), "emulate released a clean segment early");
        output_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_emulate_fast_retransmit_releases_after_one_rtt() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        // SYN clean, then a lost segment with three clean followers. No jitter.
        let script = vec![(false, 0), (true, 0), (false, 0), (false, 0), (false, 0)];
        let direction = TcpDirection::scripted(quiet(85), script);
        let plan = FaultPlan::new();
        let accepted_at = Instant::now();
        tokio::spawn(async move {
            let bytes = Arc::new(RelayBytes::default());
            let mut watch = plan.subscribe();
            let mut ctl = DirCtl {
                bytes: &bytes,
                toward_upstream: true,
                watch: &mut watch,
                accepted_at,
            };
            let _ = relay_tcp_emulate_with(input_r, output_w, direction, &mut ctl).await;
        });
        // One write would be one segment. Yields do not advance the paused clock,
        // so each byte is its own segment at the same instant.
        for byte in [b's', b'A', b'B', b'C', b'D'] {
            input_w.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        let mut buf = [0u8; 5];
        let early = tokio::time::timeout(
            Duration::from_millis(84),
            output_r.read_exact(&mut buf[..1]),
        )
        .await;
        assert!(early.is_err(), "clean first segment arrived early");
        output_r.read_exact(&mut buf[..1]).await.unwrap();
        assert_eq!(buf[0], b's');
        // Now is one-way delay. The hole is due one rtt (85 ms later).
        let held = tokio::time::timeout(
            Duration::from_millis(84),
            output_r.read_exact(&mut buf[1..]),
        )
        .await;
        assert!(held.is_err(), "hole was filled before one rtt");
        output_r.read_exact(&mut buf[1..]).await.unwrap();
        assert_eq!(&buf, b"sABCD");
    }

    #[test]
    fn fault_off_always_forwards() {
        let now = test_now();
        assert_eq!(
            fault_effect(now, now, None, None, None, false),
            FaultEffect::Forward
        );
    }

    #[test]
    fn blackout_holds_until_the_window_ends() {
        let t0 = test_now();
        let start = t0 + Duration::from_secs(1);
        let end = start + Duration::from_secs(2);
        let window = Some((start, end));
        assert_eq!(
            fault_effect(
                start - Duration::from_millis(1),
                t0,
                window,
                None,
                None,
                false
            ),
            FaultEffect::Forward
        );
        assert_eq!(
            fault_effect(start, t0, window, None, None, false),
            FaultEffect::HoldUntil(end)
        );
        assert_eq!(
            fault_effect(
                end - Duration::from_millis(1),
                t0,
                window,
                None,
                None,
                false
            ),
            FaultEffect::HoldUntil(end)
        );
        assert_eq!(
            fault_effect(end, t0, window, None, None, false),
            FaultEffect::Forward
        );
    }

    #[test]
    fn reset_closes_an_existing_connection_once_and_spares_a_new_one() {
        let t0 = test_now();
        let reset_at = t0 + Duration::from_secs(5);
        let existing = t0;
        let fresh = reset_at + Duration::from_millis(1);
        assert_eq!(
            fault_effect(
                reset_at - Duration::from_millis(1),
                existing,
                None,
                Some(reset_at),
                None,
                false
            ),
            FaultEffect::Forward
        );
        assert_eq!(
            fault_effect(reset_at, existing, None, Some(reset_at), None, false),
            FaultEffect::Close
        );
        assert_eq!(
            fault_effect(reset_at, existing, None, Some(reset_at), None, true),
            FaultEffect::Forward,
            "a reset closes each existing connection once"
        );
        assert_eq!(
            fault_effect(
                reset_at + Duration::from_secs(1),
                fresh,
                None,
                Some(reset_at),
                None,
                false
            ),
            FaultEffect::Forward
        );
    }

    #[test]
    fn silent_drop_stops_an_existing_connection_and_spares_a_new_one() {
        let t0 = test_now();
        let silent_at = t0 + Duration::from_secs(5);
        let existing = t0;
        let fresh = silent_at + Duration::from_millis(1);
        assert_eq!(
            fault_effect(
                silent_at - Duration::from_millis(1),
                existing,
                None,
                None,
                Some(silent_at),
                false
            ),
            FaultEffect::Forward
        );
        assert_eq!(
            fault_effect(silent_at, existing, None, None, Some(silent_at), false),
            FaultEffect::Silent
        );
        assert_eq!(
            fault_effect(
                silent_at + Duration::from_secs(30),
                existing,
                None,
                None,
                Some(silent_at),
                false
            ),
            FaultEffect::Silent
        );
        assert_eq!(
            fault_effect(silent_at, fresh, None, None, Some(silent_at), false),
            FaultEffect::Forward
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_off_blackout_delays_bytes_then_delivers_them() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        let plan = FaultPlan::new();
        plan.arm_blackout(Duration::from_secs(2));
        let bytes = spawn_off(
            profile("clean").unwrap(),
            plan,
            Instant::now(),
            input_r,
            output_w,
        );
        input_w.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let early =
            tokio::time::timeout(Duration::from_millis(1999), output_r.read_exact(&mut buf)).await;
        assert!(early.is_err(), "blackout forwarded bytes early");
        output_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(bytes.up.load(Ordering::Relaxed), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_emulate_blackout_delays_bytes_then_delivers_them() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        let plan = FaultPlan::new();
        plan.arm_blackout(Duration::from_secs(2));
        let bytes = spawn_emulate(
            profile("clean").unwrap(),
            plan,
            Instant::now(),
            input_r,
            output_w,
        );
        input_w.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let early =
            tokio::time::timeout(Duration::from_millis(1999), output_r.read_exact(&mut buf)).await;
        assert!(early.is_err(), "emulate blackout forwarded bytes early");
        output_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(bytes.up.load(Ordering::Relaxed), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_off_reset_closes_existing_and_lets_a_later_connection_through() {
        let plan = FaultPlan::new();
        let existing = Instant::now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        plan.arm_reset();

        let (mut old_in, old_r, old_w, mut old_out) = duplex_pair();
        spawn_off(
            profile("clean").unwrap(),
            plan.clone(),
            existing,
            old_r,
            old_w,
        );
        old_in.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let n = old_out.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "reset did not close the existing connection");

        tokio::time::sleep(Duration::from_millis(1)).await;
        let fresh = Instant::now();
        let (mut new_in, new_r, new_w, mut new_out) = duplex_pair();
        spawn_off(profile("clean").unwrap(), plan, fresh, new_r, new_w);
        new_in.write_all(b"hello").await.unwrap();
        new_out.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_emulate_reset_closes_without_delivering() {
        let plan = FaultPlan::new();
        let existing = Instant::now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        plan.arm_reset();
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        spawn_emulate(profile("clean").unwrap(), plan, existing, input_r, output_w);
        input_w.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        let n = output_r.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "emulate reset did not close the connection");
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_off_silent_drop_discards_without_closing() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        let plan = FaultPlan::new();
        let bytes = spawn_off(
            profile("clean").unwrap(),
            plan.clone(),
            Instant::now(),
            input_r,
            output_w,
        );
        input_w.write_all(b"A").await.unwrap();
        let mut buf = [0u8; 1];
        output_r.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], b'A');
        plan.arm_silent_drop();
        input_w.write_all(b"B").await.unwrap();
        let hung =
            tokio::time::timeout(Duration::from_secs(5), output_r.read_exact(&mut buf)).await;
        assert!(
            hung.is_err(),
            "silent drop closed the socket or forwarded the byte"
        );
        assert_eq!(bytes.up.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_emulate_silent_drop_discards_without_closing() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        let plan = FaultPlan::new();
        spawn_emulate(
            profile("clean").unwrap(),
            plan.clone(),
            Instant::now(),
            input_r,
            output_w,
        );
        input_w.write_all(b"A").await.unwrap();
        let mut buf = [0u8; 1];
        output_r.read_exact(&mut buf).await.unwrap();
        plan.arm_silent_drop();
        input_w.write_all(b"B").await.unwrap();
        let hung =
            tokio::time::timeout(Duration::from_secs(5), output_r.read_exact(&mut buf)).await;
        assert!(
            hung.is_err(),
            "emulate silent drop closed the socket or forwarded the byte"
        );
    }

    #[test]
    fn parse_impair_args_accepts_tcp_faults() {
        let args = [
            "--listen",
            "127.0.0.1:1080",
            "--upstream",
            "127.0.0.1:9000",
            "--blackout",
            "1000:2000",
            "--reset-at",
            "1500",
            "--silent-drop-at",
            "2500",
        ]
        .map(str::to_owned);
        let options = parse_impair_args(&args).unwrap();
        assert_eq!(
            options.faults.blackout,
            Some(BlackoutSpec {
                after: Duration::from_millis(1000),
                duration: Duration::from_millis(2000),
            })
        );
        assert_eq!(
            options.faults.reset_after,
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            options.faults.silent_drop_after,
            Some(Duration::from_millis(2500))
        );
    }

    #[test]
    fn parse_impair_args_rejects_a_bad_blackout() {
        for raw in ["1000", "1000:0", "1000:2000:1", ":2000"] {
            let args = [
                "--listen",
                "127.0.0.1:1080",
                "--upstream",
                "127.0.0.1:9000",
                "--blackout",
                raw,
            ]
            .map(str::to_owned);
            assert!(
                parse_impair_args(&args).is_err(),
                "accepted --blackout {raw}"
            );
        }
    }

    #[test]
    fn parse_impair_args_leaves_faults_off_by_default() {
        let args =
            ["--listen", "127.0.0.1:1080", "--upstream", "127.0.0.1:9000"].map(str::to_owned);
        let options = parse_impair_args(&args).unwrap();
        assert_eq!(options.faults, FaultSchedule::default());
    }
}
