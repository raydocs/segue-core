//! Receive-window growth over a long path (§4 rule 8): a bulk transfer
//! whose receiver drains at once must reach close to the link rate, not
//! stay at `initial_credit / RTT`. Found on the LA node (2026-11-15): every
//! connection held 0.3–0.6 MB/s over a 50 ms path because the window never
//! grew past 16 KiB.
//!
//! The link is modelled per direction as a FIFO with a fixed serialization
//! rate and a one-way delay; time advances in 100 µs ticks.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use segue_session::codec::Frame;
use segue_session::flow::{RecvHalf, SendHalf, GROWTH_SHARE_DIV, RTT_WINDOW};
use segue_session::pool::{Pool, Tier, BLOCK};
use segue_session::{Limits, Timing};

const MB: f64 = 1_000_000.0;
const TICK: Duration = Duration::from_micros(100);

struct Link {
    /// One-way propagation delay.
    delay: Duration,
    /// Bytes per second; `None` = unlimited.
    rate: Option<f64>,
    /// When the wire is free again.
    free_at: Instant,
    q: VecDeque<(Instant, Frame)>,
}

impl Link {
    fn new(delay: Duration, rate: Option<f64>, now: Instant) -> Self {
        Self {
            delay,
            rate,
            free_at: now,
            q: VecDeque::new(),
        }
    }

    /// Whether the wire can take another frame now (sender pacing: it
    /// writes only when the socket buffer drains, like a TCP carrier).
    fn ready(&self, now: Instant) -> bool {
        self.free_at <= now
    }

    fn send(&mut self, now: Instant, f: Frame, len: usize) {
        let start = self.free_at.max(now);
        let ser = match self.rate {
            Some(r) => Duration::from_secs_f64(len as f64 / r),
            None => Duration::ZERO,
        };
        self.free_at = start + ser;
        // FIFO: a shorter delay set later does not overtake what is queued.
        let at = (start + ser + self.delay).max(self.q.back().map_or(now, |b| b.0));
        self.q.push_back((at, f));
    }

    fn recv(&mut self, now: Instant) -> Option<Frame> {
        if self.q.front().is_some_and(|(t, _)| *t <= now) {
            return self.q.pop_front().map(|(_, f)| f);
        }
        None
    }
}

/// One bulk flow: an unlimited source, a link each way, a receiving app
/// that reads everything at once unless `read_rate` limits it.
struct Flow {
    s: SendHalf,
    r: RecvHalf,
    fwd: Link,
    back: Link,
    read_rate: Option<f64>,
    read_budget: f64,
    /// The source has more to send.
    sending: bool,
    max_grant: usize,
    /// Deliver DATA to the receiver in pieces of at most this many bytes.
    piece: usize,
    /// Every ACK rides on reverse traffic (`poll_ack(now, true)`).
    piggyback: bool,
}

impl Flow {
    fn new(
        pool_s: &Arc<Pool>,
        pool_r: &Arc<Pool>,
        rtt: Duration,
        rate: Option<f64>,
        now: Instant,
    ) -> Option<Self> {
        let limits = Limits::default();
        Some(Self {
            s: SendHalf::new(pool_s, &limits)?,
            r: RecvHalf::new(pool_r, &limits, &Timing::default(), now)?,
            fwd: Link::new(rtt / 2, rate, now),
            back: Link::new(rtt / 2, None, now),
            read_rate: None,
            read_budget: 0.0,
            sending: true,
            max_grant: 0,
            piece: usize::MAX,
            piggyback: false,
        })
    }

    fn set_rtt(&mut self, rtt: Duration) {
        self.fwd.delay = rtt / 2;
        self.back.delay = rtt / 2;
    }

    fn step(&mut self, now: Instant) {
        let src = [0x5au8; 16 * 1024];
        while self.sending {
            let cap = self.s.write_capacity();
            if cap == 0 {
                break;
            }
            self.s.write(&src[..cap.min(src.len())]);
        }
        while self.fwd.ready(now) {
            let Some(f) = self.s.poll_frame() else { break };
            let len = match &f {
                Frame::Data { data, .. } => data.len() + 16,
                _ => 16,
            };
            self.fwd.send(now, f, len);
        }
        while let Some(f) = self.fwd.recv(now) {
            if let Frame::Data { offset, data, .. } = f {
                for (i, part) in data.chunks(self.piece).enumerate() {
                    let off = offset + (i * self.piece.min(data.len())) as u64;
                    self.r.on_data(off, part, now).unwrap();
                    if self.read_rate.is_none() {
                        let n = self.r.buffered();
                        self.r.consume(n, now);
                        if self.piggyback {
                            if let Some(a) = self.r.poll_ack(now, true) {
                                self.back.send(now, a, 16);
                            }
                        }
                    }
                }
            }
        }
        match self.read_rate {
            None => {
                let n = self.r.buffered();
                self.r.consume(n, now);
            }
            Some(rr) => {
                self.read_budget += rr * TICK.as_secs_f64();
                let n = (self.read_budget as usize).min(self.r.buffered());
                self.read_budget -= n as f64;
                if self.r.buffered() == 0 {
                    self.read_budget = self.read_budget.min(64.0 * 1024.0);
                }
                self.r.consume(n, now);
            }
        }
        if let Some(a) = self.r.poll_ack(now, self.piggyback) {
            self.back.send(now, a, 16);
        }
        self.max_grant = self.max_grant.max(self.r.grant_bytes());
        while let Some(f) = self.back.recv(now) {
            if let Frame::Ack {
                recv_offset,
                max_offset,
            } = f
            {
                self.s.on_ack(recv_offset, max_offset).unwrap();
            }
        }
    }
}

struct Run {
    bytes: u64,
    secs: f64,
    max_grant: usize,
    /// Bytes delivered in the last half of the run, per second.
    steady: f64,
}

fn bulk(rtt: Duration, rate: Option<f64>, read_rate: Option<f64>, dur: Duration) -> Run {
    let t0 = Instant::now();
    let mut f = Flow::new(&Pool::new(8 << 20), &Pool::new(8 << 20), rtt, rate, t0).unwrap();
    f.read_rate = read_rate;
    let mut now = t0;
    let mut half_mark = None;
    while now < t0 + dur {
        f.step(now);
        now += TICK;
        if half_mark.is_none() && now >= t0 + dur / 2 {
            half_mark = Some(f.r.consumed());
        }
    }
    let secs = (now - t0).as_secs_f64();
    let bytes = f.r.consumed();
    Run {
        bytes,
        secs,
        max_grant: f.max_grant,
        steady: (bytes - half_mark.unwrap()) as f64 / (secs / 2.0),
    }
}

#[test]
fn window_grows_to_the_link_rate_over_50ms() {
    let run = bulk(
        Duration::from_millis(50),
        Some(10.0 * MB),
        None,
        Duration::from_secs(4),
    );
    let avg = run.bytes as f64 / run.secs;
    eprintln!(
        "50 ms, 10 MB/s link: avg {:.2} MB/s, steady {:.2} MB/s, max grant {} KiB",
        avg / MB,
        run.steady / MB,
        run.max_grant / 1024
    );
    assert!(run.steady >= 8.0 * MB, "steady {:.2} MB/s", run.steady / MB);
    assert!(avg >= 5.0 * MB, "avg {:.2} MB/s", avg / MB);
}

#[test]
fn window_grows_over_a_150ms_path() {
    let run = bulk(
        Duration::from_millis(150),
        Some(5.0 * MB),
        None,
        Duration::from_secs(6),
    );
    eprintln!(
        "150 ms, 5 MB/s link: steady {:.2} MB/s, max grant {} KiB",
        run.steady / MB,
        run.max_grant / 1024
    );
    assert!(run.steady >= 4.0 * MB, "steady {:.2} MB/s", run.steady / MB);
}

#[test]
fn window_is_bounded_by_the_cap_on_an_unlimited_link() {
    let rtt = Duration::from_millis(50);
    let run = bulk(rtt, None, None, Duration::from_secs(3));
    let cap = Limits::default().window_cap;
    assert!(run.max_grant <= cap, "grant {} > cap {cap}", run.max_grant);
    // Window-limited at the cap: about cap per RTT.
    let expect = cap as f64 / rtt.as_secs_f64();
    eprintln!(
        "unlimited link: steady {:.2} MB/s (cap/RTT {:.2} MB/s)",
        run.steady / MB,
        expect / MB
    );
    assert!(
        run.steady >= 0.7 * expect,
        "steady {:.2} MB/s",
        run.steady / MB
    );
}

#[test]
fn a_slow_reader_does_not_get_a_large_window() {
    // The app reads 200 KB/s over a fast 50 ms link: the window should
    // stay near 2 × 200 KB/s × 50 ms = 20 KB, not grow to the cap.
    let run = bulk(
        Duration::from_millis(50),
        Some(10.0 * MB),
        Some(200_000.0),
        Duration::from_secs(4),
    );
    eprintln!(
        "slow reader: steady {:.0} KB/s, max grant {} KiB",
        run.steady / 1000.0,
        run.max_grant / 1024
    );
    assert!(
        run.max_grant <= 128 * 1024,
        "grant {} KiB",
        run.max_grant / 1024
    );
    assert!(
        run.steady >= 150_000.0,
        "steady {:.0} KB/s",
        run.steady / 1000.0
    );
}

/// Throughput over `[from, to)` of a run whose RTT goes from `before` to
/// `after` at 2 s, with or without the session being told of a new path.
fn path_change(before: Duration, after: Duration, tell: bool) -> (f64, usize) {
    let t0 = Instant::now();
    let mut f = Flow::new(
        &Pool::new(8 << 20),
        &Pool::new(8 << 20),
        before,
        Some(10.0 * MB),
        t0,
    )
    .unwrap();
    let switch = t0 + Duration::from_secs(2);
    let settle = switch + RTT_WINDOW + Duration::from_secs(1);
    let end = settle + Duration::from_secs(2);
    let mut now = t0;
    let mut mark = 0;
    let mut switched = false;
    while now < end {
        if !switched && now >= switch {
            f.set_rtt(after);
            if tell {
                f.r.new_path(now);
            }
            switched = true;
        }
        if mark == 0 && now >= settle {
            mark = f.r.consumed().max(1);
        }
        f.step(now);
        now += TICK;
    }
    let rate = (f.r.consumed() - mark) as f64 / (end - settle).as_secs_f64();
    (rate, f.r.target_window())
}

#[test]
fn a_higher_rtt_on_the_same_session_is_learned_again() {
    // astra review: a 1 ms path, then 50 ms without a carrier switch. The
    // old minimum must not keep the window at the 1 ms size.
    for tell in [false, true] {
        let (rate, win) = path_change(Duration::from_millis(1), Duration::from_millis(50), tell);
        eprintln!(
            "1 ms -> 50 ms (new_path {tell}): {:.2} MB/s, window {} KiB",
            rate / MB,
            win / 1024
        );
        assert!(rate >= 8.0 * MB, "new_path {tell}: {:.2} MB/s", rate / MB);
    }
}

#[test]
fn quiet_grown_sessions_leave_the_pool_to_admission() {
    // astra review: sessions that grew their window on a fast long path
    // and then went quiet without closing keep the credit they last
    // advertised (it cannot be revoked). Growth comes out of half the
    // elastic pool only, so fresh sessions are still admitted.
    let pool_s = Pool::new(64 << 20);
    let pool_r = Pool::new(8 << 20);
    let t0 = Instant::now();
    let mut flows: Vec<Flow> = (0..12)
        .map(|_| {
            Flow::new(
                &pool_s,
                &pool_r,
                Duration::from_millis(50),
                Some(10.0 * MB),
                t0,
            )
            .unwrap()
        })
        .collect();
    let mut now = t0;
    let stop = t0 + Duration::from_secs(3);
    while now < stop + Duration::from_millis(500) {
        if now >= stop {
            for f in &mut flows {
                f.sending = false;
            }
        }
        for f in &mut flows {
            f.step(now);
        }
        now += TICK;
    }
    let grown = flows.iter().filter(|f| f.max_grant > 256 * 1024).count();
    let elastic = pool_r.limit(Tier::Elastic) * BLOCK;
    let held = pool_r.used_bytes();
    let mut fresh = Vec::new();
    while let Some(r) = RecvHalf::new(&pool_r, &Limits::default(), &Timing::default(), now) {
        fresh.push(r);
    }
    eprintln!(
        "{} sessions ({grown} grew past 256 KiB) hold {} KiB after going quiet; {} fresh admitted",
        flows.len(),
        held / 1024,
        fresh.len()
    );
    assert!(grown >= 2, "only {grown} sessions grew");
    let init = Limits::default().initial_credit;
    assert!(
        held <= elastic / GROWTH_SHARE_DIV + flows.len() * (init + BLOCK),
        "quiet sessions hold {held} bytes"
    );
    // Every byte the quiet sessions left goes to fresh sessions.
    assert!(
        (fresh.len() + 1) * init > elastic - held,
        "{} fresh sessions in {} KiB",
        fresh.len(),
        (elastic - held) / 1024
    );
    assert!(fresh.len() >= 200, "{} fresh sessions", fresh.len());
}

#[test]
fn small_frames_with_piggybacked_acks_still_measure_rtt() {
    // astra review r2 P1-4: 1 KiB frames each handled on its own, every
    // ACK piggybacked on reverse traffic, so every 1 KiB read is a new
    // advertisement. The advertisement log must keep the boundary data
    // crosses next, or no RTT is ever sampled and the window stays 16 KiB.
    let t0 = Instant::now();
    let mut f = Flow::new(
        &Pool::new(8 << 20),
        &Pool::new(8 << 20),
        Duration::from_millis(50),
        Some(10.0 * MB),
        t0,
    )
    .unwrap();
    f.piece = 1024;
    f.piggyback = true;
    let mut now = t0;
    let end = t0 + Duration::from_secs(4);
    let mut mark = None;
    while now < end {
        f.step(now);
        now += TICK;
        if mark.is_none() && now >= t0 + Duration::from_secs(2) {
            mark = Some(f.r.consumed());
        }
    }
    let rate = (f.r.consumed() - mark.unwrap()) as f64 / 2.0;
    eprintln!(
        "1 KiB frames, piggybacked ACKs: {:.2} MB/s, srtt {:?}, window {} KiB",
        rate / MB,
        f.r.srtt(),
        f.r.target_window() / 1024
    );
    assert!(f.r.srtt().is_some(), "no RTT sample");
    assert!(rate >= 5.0 * MB, "{:.2} MB/s", rate / MB);
}

#[test]
fn a_transfer_grows_while_other_sessions_hold_their_initial_credit() {
    // astra review r2 P1-3: 145 open sessions that never grew already
    // hold half the elastic pool in initial credits, send floors and
    // pipes. Their credit is not growth: one of them starting a long
    // download must still grow its window.
    let pool = Pool::new(8 << 20);
    let limits = Limits::default();
    let t0 = Instant::now();
    let mut idle = Vec::new();
    while pool.used_bytes() < pool.limit(Tier::Elastic) * BLOCK / 2 + 64 * 1024 {
        idle.push((
            RecvHalf::new(&pool, &limits, &Timing::default(), t0).unwrap(),
            SendHalf::new(&pool, &limits).unwrap(),
            segue_session::pool::Grant::fixed(&pool, 2 * BLOCK).unwrap(),
        ));
    }
    let mut f = Flow::new(
        &Pool::new(64 << 20),
        &pool,
        Duration::from_millis(50),
        Some(10.0 * MB),
        t0,
    )
    .unwrap();
    let mut now = t0;
    let end = t0 + Duration::from_secs(4);
    let mut mark = None;
    while now < end {
        f.step(now);
        now += TICK;
        if mark.is_none() && now >= t0 + Duration::from_secs(2) {
            mark = Some(f.r.consumed());
        }
    }
    let rate = (f.r.consumed() - mark.unwrap()) as f64 / 2.0;
    eprintln!(
        "{} sessions at their initial credit ({} KiB of the pool): {:.2} MB/s, max grant {} KiB",
        idle.len(),
        (pool.used_bytes() - f.r.grant_bytes()) / 1024,
        rate / MB,
        f.max_grant / 1024
    );
    assert!(rate >= 8.0 * MB, "{:.2} MB/s", rate / MB);
    assert_eq!(
        pool.grown_bytes(),
        f.r.grant_bytes() - limits.initial_credit
    );
    drop(f);
    assert_eq!(pool.grown_bytes(), 0);
}
