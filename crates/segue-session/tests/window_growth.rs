//! Receive-window growth over a long path (§4 rule 8): a bulk transfer
//! whose receiver drains at once must reach close to the link rate, not
//! stay at `initial_credit / RTT`. Found on the LA node (2026-11-15): every
//! connection held 0.3–0.6 MB/s over a 50 ms path because the window never
//! grew past 16 KiB.
//!
//! The link is modelled per direction as a FIFO with a fixed serialization
//! rate and a one-way delay; time advances in 100 µs ticks.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use segue_session::codec::Frame;
use segue_session::flow::{RecvHalf, SendHalf};
use segue_session::pool::Pool;
use segue_session::{Limits, Timing};

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
        self.q.push_back((start + ser + self.delay, f));
    }

    fn recv(&mut self, now: Instant) -> Option<Frame> {
        if self.q.front().is_some_and(|(t, _)| *t <= now) {
            return self.q.pop_front().map(|(_, f)| f);
        }
        None
    }
}

struct Run {
    bytes: u64,
    secs: f64,
    max_grant: usize,
    /// Bytes delivered in the last half of the run, per second.
    steady: f64,
}

/// Unlimited-source bulk transfer for `dur`; the receiving app reads
/// everything as soon as it arrives unless `read_rate` limits it.
fn bulk(rtt: Duration, rate: Option<f64>, read_rate: Option<f64>, dur: Duration) -> Run {
    let pool_s = Pool::new(8 << 20);
    let pool_r = Pool::new(8 << 20);
    let limits = Limits::default();
    let timing = Timing::default();
    let t0 = Instant::now();
    let mut s = SendHalf::new(&pool_s, &limits).unwrap();
    let mut r = RecvHalf::new(&pool_r, &limits, &timing, t0).unwrap();
    let mut fwd = Link::new(rtt / 2, rate, t0);
    let mut back = Link::new(rtt / 2, None, t0);
    let src = vec![0x5au8; 64 * 1024];
    let tick = Duration::from_micros(100);
    let mut now = t0;
    let mut half_mark = None;
    let mut max_grant = 0;
    let mut read_budget = 0.0f64;
    let end = t0 + dur;
    while now < end {
        // Sender: keep the send buffer full, push frames while the wire is free.
        loop {
            let cap = s.write_capacity();
            if cap == 0 {
                break;
            }
            s.write(&src[..cap.min(src.len())]);
        }
        while fwd.ready(now) {
            let Some(f) = s.poll_frame() else { break };
            let len = match &f {
                Frame::Data { data, .. } => data.len() + 16,
                _ => 16,
            };
            fwd.send(now, f, len);
        }
        // Receiver.
        while let Some(f) = fwd.recv(now) {
            if let Frame::Data { offset, data, .. } = f {
                r.on_data(offset, &data, now).unwrap();
            }
        }
        match read_rate {
            None => {
                let n = r.buffered();
                r.consume(n, now);
            }
            Some(rr) => {
                read_budget += rr * tick.as_secs_f64();
                let n = (read_budget as usize).min(r.buffered());
                read_budget -= n as f64;
                if r.buffered() == 0 {
                    read_budget = read_budget.min(64.0 * 1024.0);
                }
                r.consume(n, now);
            }
        }
        if let Some(a) = r.poll_ack(now, false) {
            back.send(now, a, 16);
        }
        max_grant = max_grant.max(r.grant_bytes());
        // Sender gets ACKs.
        while let Some(f) = back.recv(now) {
            if let Frame::Ack {
                recv_offset,
                max_offset,
            } = f
            {
                s.on_ack(recv_offset, max_offset).unwrap();
            }
        }
        now += tick;
        if half_mark.is_none() && now >= t0 + dur / 2 {
            half_mark = Some(r.consumed());
        }
    }
    let secs = (now - t0).as_secs_f64();
    let bytes = r.consumed();
    Run {
        bytes,
        secs,
        max_grant,
        steady: (bytes - half_mark.unwrap()) as f64 / (secs / 2.0),
    }
}

const MB: f64 = 1_000_000.0;

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
