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
    })
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
    let bytes = Arc::new(RelayBytes::default());
    loop {
        let (client, _) = listener.accept().await.map_err(|source| BenchError::Io {
            action: "accepting on the impair TCP listener".to_owned(),
            source,
        })?;
        let upstream_addr = options.upstream;
        let profile = options.profile.clone();
        let seed = options.seed;
        let tcp_loss = options.tcp_loss;
        let bytes = Arc::clone(&bytes);
        tokio::spawn(async move {
            let _ = relay_tcp_client(client, upstream_addr, profile, seed, tcp_loss, bytes).await;
        });
    }
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
    let bytes_task = Arc::clone(&bytes);
    tokio::spawn(async move {
        let _ = accept_tcp(
            listener, upstream, profile, seed, tcp_loss, bytes_task, stop_rx,
        )
        .await;
    });
    Ok(TcpRelay {
        local,
        bytes,
        stop: stop_tx,
    })
}

async fn accept_tcp(
    listener: TcpListener,
    upstream: SocketAddr,
    profile: ImpairProfile,
    seed: u64,
    tcp_loss: TcpLoss,
    bytes: Arc<RelayBytes>,
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
                let profile = profile.clone();
                let bytes = Arc::clone(&bytes);
                tokio::spawn(async move {
                    let _ = relay_tcp_client(client, upstream, profile, seed, tcp_loss, bytes).await;
                });
            }
        }
    }
}

async fn relay_tcp_client(
    client: TcpStream,
    upstream_addr: SocketAddr,
    profile: ImpairProfile,
    seed: u64,
    tcp_loss: TcpLoss,
    bytes: Arc<RelayBytes>,
) -> Result<(), BenchError> {
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
    let up = tokio::spawn(async move {
        match tcp_loss {
            TcpLoss::Off => {
                relay_tcp_direction(
                    client_read,
                    upstream_write,
                    up_profile,
                    direction_seed(seed, false),
                    up_bytes,
                    true,
                )
                .await
            }
            TcpLoss::Emulate => {
                relay_tcp_direction_emulate(
                    client_read,
                    upstream_write,
                    up_profile,
                    direction_seed(seed, false),
                    up_bytes,
                    true,
                )
                .await
            }
        }
    });
    let down = tokio::spawn(async move {
        match tcp_loss {
            TcpLoss::Off => {
                relay_tcp_direction(
                    upstream_read,
                    client_write,
                    profile,
                    direction_seed(seed, true),
                    down_bytes,
                    false,
                )
                .await
            }
            TcpLoss::Emulate => {
                relay_tcp_direction_emulate(
                    upstream_read,
                    client_write,
                    profile,
                    direction_seed(seed, true),
                    down_bytes,
                    false,
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
async fn relay_tcp_direction<R, W>(
    mut reader: R,
    mut writer: W,
    profile: ImpairProfile,
    seed: u64,
    bytes: Arc<RelayBytes>,
    toward_upstream: bool,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut shaper = Shaper::new(profile, seed);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let len = reader
            .read(&mut buffer)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading from the impair TCP relay".to_owned(),
                source,
            })?;
        if len == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        let now = Instant::now();
        if let Some(release) = shaper.schedule(now, len) {
            sleep_until(release).await;
        }
        writer
            .write_all(&buffer[..len])
            .await
            .map_err(|source| BenchError::Io {
                action: "writing to the impair TCP relay".to_owned(),
                source,
            })?;
        add_bytes(&bytes, toward_upstream, len);
    }
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
    bytes: Arc<RelayBytes>,
    toward_upstream: bool,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    relay_tcp_emulate_with(
        reader,
        writer,
        TcpDirection::new(profile, seed),
        bytes,
        toward_upstream,
    )
    .await
}

async fn relay_tcp_emulate_with<R, W>(
    mut reader: R,
    mut writer: W,
    mut direction: TcpDirection,
    bytes: Arc<RelayBytes>,
    toward_upstream: bool,
) -> Result<(), BenchError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; TCP_SEGMENT_CAP];
    loop {
        let now = Instant::now();
        let deadline = direction.next_deadline(now);
        let sleep = async {
            match deadline {
                Some(instant) => sleep_until(instant).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            read = reader.read(&mut buffer), if !direction.eof => {
                let len = read.map_err(|source| BenchError::Io {
                    action: "reading from the impair TCP relay".to_owned(),
                    source,
                })?;
                if len == 0 {
                    direction.mark_eof(Instant::now());
                } else {
                    direction.push(Instant::now(), &buffer[..len]);
                }
            }
            _ = sleep, if deadline.is_some() => {}
        }
        let now = Instant::now();
        while let Some(payload) = direction.pop_ready(now) {
            let len = payload.len();
            writer
                .write_all(&payload)
                .await
                .map_err(|source| BenchError::Io {
                    action: "writing to the impair TCP relay".to_owned(),
                    source,
                })?;
            add_bytes(&bytes, toward_upstream, len);
        }
        if direction.finished() {
            let _ = writer.shutdown().await;
            return Ok(());
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

    #[tokio::test(start_paused = true)]
    async fn tcp_off_still_forwards_bytes_the_loss_model_would_drop() {
        let (mut input_w, input_r, output_w, mut output_r) = duplex_pair();
        let mut profile = profile("clean").unwrap();
        profile.loss = 1.0;
        profile.delay = Duration::from_millis(85);
        let bytes = Arc::new(RelayBytes::default());
        tokio::spawn(async move {
            let _ = relay_tcp_direction(input_r, output_w, profile, 1, bytes, true).await;
        });
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
        let bytes = Arc::new(RelayBytes::default());
        tokio::spawn(async move {
            let _ = relay_tcp_direction(input_r, output_w, quiet(85), 1, bytes, true).await;
        });
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
        let bytes = Arc::new(RelayBytes::default());
        tokio::spawn(async move {
            let _ = relay_tcp_direction_emulate(input_r, output_w, quiet(85), 1, bytes, true).await;
        });
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
        let bytes = Arc::new(RelayBytes::default());
        // SYN clean, then a lost segment with three clean followers. No jitter.
        let script = vec![(false, 0), (true, 0), (false, 0), (false, 0), (false, 0)];
        let direction = TcpDirection::scripted(quiet(85), script);
        tokio::spawn(async move {
            let _ = relay_tcp_emulate_with(input_r, output_w, direction, bytes, true).await;
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
}
