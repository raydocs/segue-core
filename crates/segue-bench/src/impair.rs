//! Userspace link impairment proxy for local WAN-like tests.
//!
//! A small async UDP/TCP relay that sits between a client and an upstream and
//! applies fixed delay, jitter, uniform loss, Gilbert-Elliott burst loss,
//! a bandwidth cap and reordering. Everything is driven by a seeded PRNG, so a
//! run is reproducible from `(profile, seed)`.
//!
//! No root, no `tc netem`, no host route changes: the relay only binds the
//! loopback addresses it is told to. TCP is a reliable byte stream, so loss and
//! reordering are applied to UDP only; TCP gets delay, jitter and the bandwidth
//! cap (dropping bytes there would corrupt the stream rather than emulate a
//! retransmission).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

use crate::{parse_u64, required_value, BenchError};

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
    /// Stop after this long; `None` runs until Ctrl-C.
    pub duration: Option<Duration>,
}

impl Eq for ImpairOptions {}

pub fn parse_impair_args(args: &[String]) -> Result<ImpairOptions, BenchError> {
    let mut listen = None;
    let mut upstream = None;
    let mut profile_name = "clean".to_owned();
    let mut seed = 0u64;
    let mut udp = true;
    let mut tcp = true;
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
    let mut up_shaper = Shaper::new(profile.clone(), seed);
    let mut down_shaper = Shaper::new(profile, seed ^ 0x5DEE_CE66_D1CE_4E5B);
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
    loop {
        let (client, _) = listener.accept().await.map_err(|source| BenchError::Io {
            action: "accepting on the impair TCP listener".to_owned(),
            source,
        })?;
        let upstream_addr = options.upstream;
        let profile = options.profile.clone();
        let seed = options.seed;
        tokio::spawn(async move {
            let _ = relay_tcp_client(client, upstream_addr, profile, seed).await;
        });
    }
}

async fn relay_tcp_client(
    client: TcpStream,
    upstream_addr: SocketAddr,
    profile: ImpairProfile,
    seed: u64,
) -> Result<(), BenchError> {
    let upstream = TcpStream::connect(upstream_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting TCP to {upstream_addr}"),
            source,
        })?;
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();
    let up = tokio::spawn(relay_tcp_direction(
        client_read,
        upstream_write,
        profile.clone(),
        seed,
    ));
    let down = tokio::spawn(relay_tcp_direction(
        upstream_read,
        client_write,
        profile,
        seed ^ 0x5DEE_CE66_D1CE_4E5B,
    ));
    let _ = up.await;
    let _ = down.await;
    Ok(())
}

/// TCP is reliable, so only delay, jitter and the bandwidth cap apply here.
async fn relay_tcp_direction<R, W>(
    mut reader: R,
    mut writer: W,
    profile: ImpairProfile,
    seed: u64,
) -> Result<(), BenchError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
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
}
