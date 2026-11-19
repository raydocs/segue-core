//! Seeded model of a token stream on a lossy path.
//!
//! No sockets. One 30–60 byte frame every 20 ms for 60 s, one-way delay 85 ms
//! (RTT 170 ms). Loss is drawn per packet per direction, either independent
//! Bernoulli at 7.5% or a Gilbert-Elliott chain with that same marginal and
//! the short bursts measured on the Beijing evening peak (see [`GE_BAD_TO_GOOD`]).
//!
//! The reliable baseline follows the TCP recovery rules in `impair`'s module
//! docs: fast retransmit when at least three later segments sit inside one
//! RTT, otherwise a tail-loss probe at `2 × RTT`, then an RTO ladder of
//! `max(200 ms, 3 × RTT)` doubling per lost retransmission and capped at 8 s.
//! Head-of-line applies. The first frame is not treated as a SYN: the carrier
//! is already up. Retransmission losses are drawn up front, as in
//! [`crate::impair`].
//!
//! Datagram schemes deliver by offset, so a later frame does not wait on the
//! wire. The app still releases tokens in order (a gap holds everything after
//! it), which is what "added delay" measures: release time minus birth minus
//! the 85 ms floor. A frame the redundancy copies never delivered counts as
//! residual even if a later retransmit saves it.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::impair::Rng;
use crate::{parse_u64, required_value, BenchError};

/// One-way delay. RTT is twice this. Not a new measurement: the brief's floor.
const ONE_WAY_US: u64 = 85_000;
const RTT_US: u64 = ONE_WAY_US * 2;
/// Retransmit a datagram frame still unacked after 1.5 × RTT.
const RETX_AFTER_US: u64 = RTT_US + RTT_US / 2;
const INTERVAL_US: u64 = 20_000;
const DURATION_US: u64 = 60_000_000;
const N_FRAMES: usize = (DURATION_US / INTERVAL_US) as usize;
const COALESCE_US: u64 = 40_000;

/// Bernoulli loss per direction. `1 - (1 - 0.075)^2 ≈ 14.4%` round trip,
/// inside the measured 13.4–16.6%.
const BERN_P: f64 = 0.075;

/// Mean bad run is `1 / 0.85 ≈ 1.176` packets: P(L=1) = 0.85, P(L=2) = 0.1275,
/// P(L=3) = 0.0191, P(L≥5) = 0.00051. Those ratios sit inside the measured
/// bins (singles 1820–2141, pairs 252–318, triples 26–56, runs of 5–8 packets
/// 0–1 times). Steady-state loss is 7.5% per direction, same as [`BERN_P`].
const GE_BAD_TO_GOOD: f64 = 0.85;
const GE_LOSS_GOOD: f64 = 0.0;
const GE_LOSS_BAD: f64 = 1.0;
const GE_GOOD_TO_BAD: f64 = BERN_P * GE_BAD_TO_GOOD / (1.0 - BERN_P);

const TCP_FAST_INFLIGHT: usize = 3;
const TCP_MAX_RETX: u32 = 16;
const TCP_RTO_FLOOR_US: u64 = 200_000;
const TCP_RTO_CAP_US: u64 = 8_000_000;
const DGRAM_MAX_RETX: u32 = 16;

/// Assumptions, not measurements. IP packets, so a 40-byte token pays a header.
const TCP_IP_HDR: u64 = 40;
const UDP_IP_HDR: u64 = 28;
/// type, flags, count, pad.
const DGRAM_HDR: u64 = 4;
/// offset u32 + length u16, per frame carried in the datagram.
const FRAME_HDR: u64 = 6;
/// ACK: type u8, count u8, then one u32 offset per frame.
const ACK_FIXED: u64 = 2;
const ACK_PER_FRAME: u64 = 4;

const DEFAULT_SEED: u64 = 1;

const PRIO_ACK: u8 = 0;
const PRIO_DATA: u8 = 1;
const PRIO_SEND: u8 = 2;
const PRIO_RETX: u8 = 3;

#[derive(Clone, Copy)]
enum LossKind {
    Bernoulli(f64),
    Gilbert,
}

struct PathLoss {
    rng: Rng,
    bad: bool,
    kind: LossKind,
}

impl PathLoss {
    fn new(seed: u64, kind: LossKind) -> Self {
        let mut rng = Rng::new(seed);
        let bad = match kind {
            LossKind::Bernoulli(_) => false,
            LossKind::Gilbert => {
                let pi = GE_GOOD_TO_BAD / (GE_GOOD_TO_BAD + GE_BAD_TO_GOOD);
                rng.next_f64() < pi
            }
        };
        Self { rng, bad, kind }
    }

    fn lost(&mut self) -> bool {
        match self.kind {
            LossKind::Bernoulli(p) => self.rng.next_f64() < p,
            LossKind::Gilbert => {
                if self.bad {
                    if self.rng.next_f64() < GE_BAD_TO_GOOD {
                        self.bad = false;
                    }
                } else if self.rng.next_f64() < GE_GOOD_TO_BAD {
                    self.bad = true;
                }
                let p = if self.bad { GE_LOSS_BAD } else { GE_LOSS_GOOD };
                self.rng.next_f64() < p
            }
        }
    }
}

fn mix(seed: u64, tag: u64) -> u64 {
    seed ^ tag.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Per-flow, per-direction seed. Reverse uses the same xor as `impair`.
fn path_seed(seed: u64, flow: usize, reverse: bool) -> u64 {
    let dir = if reverse { 0x5DEE_CE66_D1CE_4E5B } else { 0 };
    mix(seed, (flow as u64) + 1) ^ dir
}

struct Frame {
    born: u64,
    size: u64,
    started: bool,
    armed: bool,
    acked: bool,
    by_original: bool,
    arrival: Option<u64>,
    retx_sent: u32,
}

enum EvKind {
    Send,
    Data {
        frames: Vec<u16>,
        retx: bool,
        flow: u8,
    },
    Ack {
        frames: Vec<u16>,
    },
    Retx {
        frame: u16,
    },
}

struct Ev {
    time: u64,
    prio: u8,
    seq: u64,
    kind: EvKind,
}

impl PartialEq for Ev {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.prio == other.prio && self.seq == other.seq
    }
}

impl Eq for Ev {}

impl PartialOrd for Ev {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ev {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap pops the greatest. Smaller time, then smaller prio, runs first.
        other
            .time
            .cmp(&self.time)
            .then(other.prio.cmp(&self.prio))
            .then(other.seq.cmp(&self.seq))
    }
}

struct Sim {
    frames: Vec<Frame>,
    heap: BinaryHeap<Ev>,
    seq: u64,
    fwd: Vec<PathLoss>,
    back: Vec<PathLoss>,
    k: usize,
    /// `None` = no last-N (only the frames due now). `Some(n)` = up to n
    /// newest unacked, but never fewer than the frames due in this slot.
    carry: Option<usize>,
    coalesce: bool,
    wire: u64,
    packets: u64,
}

impl Sim {
    fn push(&mut self, time: u64, prio: u8, kind: EvKind) {
        let seq = self.seq;
        self.seq += 1;
        self.heap.push(Ev {
            time,
            prio,
            seq,
            kind,
        });
    }

    fn packet_bytes(&self, ids: &[u16]) -> u64 {
        let mut body = DGRAM_HDR;
        for &id in ids {
            body += FRAME_HDR + self.frames[id as usize].size;
        }
        UDP_IP_HDR + body
    }

    fn ack_bytes(n: usize) -> u64 {
        UDP_IP_HDR + ACK_FIXED + ACK_PER_FRAME * n as u64
    }

    fn send_copies(&mut self, ids: &[u16], retx: bool, now: u64) {
        if ids.is_empty() {
            return;
        }
        let bytes = self.packet_bytes(ids);
        for flow in 0..self.k {
            self.packets += 1;
            self.wire += bytes;
            if !self.fwd[flow].lost() {
                self.push(
                    now + ONE_WAY_US,
                    PRIO_DATA,
                    EvKind::Data {
                        frames: ids.to_vec(),
                        retx,
                        flow: flow as u8,
                    },
                );
            }
        }
    }

    fn due(&mut self, now: u64) -> Vec<u16> {
        let mut ids = Vec::new();
        if self.coalesce {
            for (i, frame) in self.frames.iter().enumerate() {
                if !frame.started && frame.born <= now && now - frame.born < COALESCE_US {
                    ids.push(i as u16);
                }
            }
        } else if let Some(i) = self.frames.iter().position(|frame| frame.born == now) {
            ids.push(i as u16);
        }
        for &id in &ids {
            self.frames[id as usize].started = true;
        }
        ids
    }

    fn select(&self, now: u64, new_ids: &[u16]) -> Vec<u16> {
        let Some(n) = self.carry else {
            return new_ids.to_vec();
        };
        // A coalesced slot can birth more frames than N. Dropping a fresh
        // token to honour the cap would stall it until the retransmit timer,
        // so the cap grows to fit every frame that is due now.
        let limit = n.max(new_ids.len());
        let mut picked = Vec::new();
        for id in (0..self.frames.len()).rev() {
            let frame = &self.frames[id];
            if frame.born > now || frame.acked {
                continue;
            }
            picked.push(id as u16);
            if picked.len() == limit {
                break;
            }
        }
        picked.reverse();
        picked
    }

    fn arm(&mut self, ids: &[u16], now: u64) {
        for &id in ids {
            if self.frames[id as usize].armed {
                continue;
            }
            self.frames[id as usize].armed = true;
            self.push(now + RETX_AFTER_US, PRIO_RETX, EvKind::Retx { frame: id });
        }
    }

    fn on_send(&mut self, now: u64) {
        let new_ids = self.due(now);
        if new_ids.is_empty() {
            return;
        }
        let carried = self.select(now, &new_ids);
        self.arm(&carried, now);
        self.send_copies(&carried, false, now);
    }

    fn on_data(&mut self, now: u64, ids: &[u16], retx: bool, flow: u8) {
        for &id in ids {
            let frame = &mut self.frames[id as usize];
            if frame.arrival.is_none() {
                frame.arrival = Some(now);
            }
            if !retx {
                frame.by_original = true;
            }
        }
        self.packets += 1;
        self.wire += Self::ack_bytes(ids.len());
        if !self.back[flow as usize].lost() {
            self.push(
                now + ONE_WAY_US,
                PRIO_ACK,
                EvKind::Ack {
                    frames: ids.to_vec(),
                },
            );
        }
    }

    fn on_ack(&mut self, ids: &[u16]) {
        for &id in ids {
            self.frames[id as usize].acked = true;
        }
    }

    fn on_retx(&mut self, now: u64, id: u16) {
        let frame = &mut self.frames[id as usize];
        if frame.acked || frame.retx_sent >= DGRAM_MAX_RETX {
            return;
        }
        frame.retx_sent += 1;
        self.push(now + RETX_AFTER_US, PRIO_RETX, EvKind::Retx { frame: id });
        self.send_copies(&[id], true, now);
    }
}

struct Outcome {
    added: Vec<u64>,
    releases: Vec<u64>,
    residual: f64,
    wire: u64,
    payload: u64,
    packets: u64,
}

fn finish_dgram(sim: Sim) -> Outcome {
    let mut payload = 0u64;
    let mut missed = 0usize;
    let mut added = Vec::with_capacity(sim.frames.len());
    let mut releases = Vec::with_capacity(sim.frames.len());
    let mut prev = 0u64;
    for frame in &sim.frames {
        payload += frame.size;
        if !frame.by_original {
            missed += 1;
        }
        // Give up after the last armed retransmit would have landed. Only
        // reachable if every copy and every retransmit was lost.
        let arrival = match frame.arrival {
            Some(at) => at,
            None => {
                let tries = u64::from(DGRAM_MAX_RETX + 1);
                frame.born + ONE_WAY_US + RETX_AFTER_US * tries
            }
        };
        let rel = arrival.max(prev);
        prev = rel;
        added.push(rel.saturating_sub(frame.born + ONE_WAY_US));
        releases.push(rel);
    }
    let n = sim.frames.len() as f64;
    Outcome {
        added,
        releases,
        residual: missed as f64 / n,
        wire: sim.wire,
        payload,
        packets: sim.packets,
    }
}

fn simulate_dgram(sizes: &[u64], seed: u64, kind: LossKind, scheme: &Scheme) -> Outcome {
    let Scheme::Dgram { carry, k, coalesce } = scheme else {
        unreachable!("tcp has its own simulator");
    };
    let frames = sizes
        .iter()
        .enumerate()
        .map(|(i, size)| Frame {
            born: i as u64 * INTERVAL_US,
            size: *size,
            started: false,
            armed: false,
            acked: false,
            by_original: false,
            arrival: None,
            retx_sent: 0,
        })
        .collect();
    let mut sim = Sim {
        frames,
        heap: BinaryHeap::new(),
        seq: 0,
        fwd: (0..*k)
            .map(|flow| PathLoss::new(path_seed(seed, flow, false), kind))
            .collect(),
        back: (0..*k)
            .map(|flow| PathLoss::new(path_seed(seed, flow, true), kind))
            .collect(),
        k: *k,
        carry: *carry,
        coalesce: *coalesce,
        wire: 0,
        packets: 0,
    };
    if *coalesce {
        let mut t = INTERVAL_US;
        while t < DURATION_US {
            sim.push(t, PRIO_SEND, EvKind::Send);
            t += COALESCE_US;
        }
    } else {
        for i in 0..sizes.len() {
            sim.push(i as u64 * INTERVAL_US, PRIO_SEND, EvKind::Send);
        }
    }
    while let Some(ev) = sim.heap.pop() {
        match ev.kind {
            EvKind::Send => sim.on_send(ev.time),
            EvKind::Data { frames, retx, flow } => sim.on_data(ev.time, &frames, retx, flow),
            EvKind::Ack { frames } => sim.on_ack(&frames),
            EvKind::Retx { frame } => sim.on_retx(ev.time, frame),
        }
    }
    finish_dgram(sim)
}

fn rto_ladder_us(losses: u32) -> u64 {
    let mut step = (RTT_US * 3).clamp(TCP_RTO_FLOOR_US, TCP_RTO_CAP_US);
    let mut extra = 0u64;
    for _ in 0..losses {
        extra = extra.saturating_add(step);
        step = step.saturating_mul(2).min(TCP_RTO_CAP_US);
    }
    extra
}

/// Delivery offset from send, matching `impair::data_recovery`: one RTT when
/// `inflight >= 3`, otherwise a tail-loss probe at two RTTs, then the RTO ladder.
fn tcp_recovery_us(inflight: usize, retx_losses: u32) -> u64 {
    let base = if inflight >= TCP_FAST_INFLIGHT {
        RTT_US
    } else {
        RTT_US * 2
    };
    base + rto_ladder_us(retx_losses)
}

fn inflight_within_rtt(index: usize) -> usize {
    let born = index as u64 * INTERVAL_US;
    let mut n = 0usize;
    let mut j = index + 1;
    while j < N_FRAMES {
        let sent = j as u64 * INTERVAL_US;
        if sent > born + RTT_US {
            break;
        }
        n += 1;
        j += 1;
    }
    n
}

fn simulate_tcp(sizes: &[u64], seed: u64, kind: LossKind) -> Outcome {
    let mut fwd = PathLoss::new(path_seed(seed, 0, false), kind);
    let mut payload = 0u64;
    let mut wire = 0u64;
    let mut packets = 0u64;
    let mut missed = 0usize;
    let mut own = Vec::with_capacity(sizes.len());
    for (i, size) in sizes.iter().enumerate() {
        payload += *size;
        let born = i as u64 * INTERVAL_US;
        let lost = fwd.lost();
        let mut retx_losses = 0u32;
        let mut sends = 1u64;
        if lost {
            missed += 1;
            while retx_losses < TCP_MAX_RETX && fwd.lost() {
                retx_losses += 1;
                sends += 1;
            }
            // The attempt after the lost ones is what `data_recovery` delivers.
            sends += 1;
        }
        packets += sends;
        wire += sends * (TCP_IP_HDR + *size);
        let arrival = if lost {
            born + tcp_recovery_us(inflight_within_rtt(i), retx_losses)
        } else {
            born + ONE_WAY_US
        };
        own.push(arrival);
    }
    // Assumption: a delayed ACK every two data segments, header only.
    // Duplicate ACKs that drive fast retransmit are not counted.
    let acks = packets.div_ceil(2);
    packets += acks;
    wire += acks * TCP_IP_HDR;

    let mut added = Vec::with_capacity(own.len());
    let mut releases = Vec::with_capacity(own.len());
    let mut prev = 0u64;
    for (i, arrival) in own.iter().enumerate() {
        let rel = (*arrival).max(prev);
        prev = rel;
        let born = i as u64 * INTERVAL_US;
        added.push(rel.saturating_sub(born + ONE_WAY_US));
        releases.push(rel);
    }
    let n = sizes.len() as f64;
    Outcome {
        added,
        releases,
        residual: missed as f64 / n,
        wire,
        payload,
        packets,
    }
}

struct Report {
    name: &'static str,
    loss: &'static str,
    p50: u64,
    p99: u64,
    p999: u64,
    max: u64,
    stalls_300: u64,
    stalls_1s: u64,
    residual: f64,
    wire_ratio: f64,
    pps: f64,
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (p * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

fn stalls(releases: &[u64], threshold_us: u64) -> u64 {
    releases
        .windows(2)
        .filter(|pair| pair[1].saturating_sub(pair[0]) > threshold_us)
        .count() as u64
}

fn report(name: &'static str, loss: &'static str, outcome: Outcome) -> Report {
    let mut added = outcome.added;
    added.sort_unstable();
    let max = added.last().copied().unwrap_or(0);
    let payload = outcome.payload.max(1);
    Report {
        name,
        loss,
        p50: percentile(&added, 0.50),
        p99: percentile(&added, 0.99),
        p999: percentile(&added, 0.999),
        max,
        stalls_300: stalls(&outcome.releases, 300_000),
        stalls_1s: stalls(&outcome.releases, 1_000_000),
        residual: outcome.residual,
        wire_ratio: outcome.wire as f64 / payload as f64,
        pps: outcome.packets as f64 / (DURATION_US as f64 / 1_000_000.0),
    }
}

enum Scheme {
    Tcp,
    Dgram {
        carry: Option<usize>,
        k: usize,
        coalesce: bool,
    },
}

struct Spec {
    name: &'static str,
    tag: u64,
    scheme: Scheme,
}

fn specs() -> Vec<Spec> {
    vec![
        Spec {
            name: "tcp",
            tag: 1,
            scheme: Scheme::Tcp,
        },
        Spec {
            name: "dgram/N=1",
            tag: 2,
            scheme: Scheme::Dgram {
                carry: Some(1),
                k: 1,
                coalesce: false,
            },
        },
        Spec {
            name: "dgram/N=2",
            tag: 3,
            scheme: Scheme::Dgram {
                carry: Some(2),
                k: 1,
                coalesce: false,
            },
        },
        Spec {
            name: "dgram/N=3",
            tag: 4,
            scheme: Scheme::Dgram {
                carry: Some(3),
                k: 1,
                coalesce: false,
            },
        },
        Spec {
            name: "dgram/N=4",
            tag: 5,
            scheme: Scheme::Dgram {
                carry: Some(4),
                k: 1,
                coalesce: false,
            },
        },
        Spec {
            name: "dup/K=2",
            tag: 6,
            scheme: Scheme::Dgram {
                carry: None,
                k: 2,
                coalesce: false,
            },
        },
        Spec {
            name: "dup/K=3",
            tag: 7,
            scheme: Scheme::Dgram {
                carry: None,
                k: 3,
                coalesce: false,
            },
        },
        Spec {
            name: "dup/K=2/N=2",
            tag: 8,
            scheme: Scheme::Dgram {
                carry: Some(2),
                k: 2,
                coalesce: false,
            },
        },
        Spec {
            name: "coal/N=1",
            tag: 9,
            scheme: Scheme::Dgram {
                carry: Some(1),
                k: 1,
                coalesce: true,
            },
        },
        Spec {
            name: "coal/N=2",
            tag: 10,
            scheme: Scheme::Dgram {
                carry: Some(2),
                k: 1,
                coalesce: true,
            },
        },
        Spec {
            name: "coal/N=3",
            tag: 11,
            scheme: Scheme::Dgram {
                carry: Some(3),
                k: 1,
                coalesce: true,
            },
        },
        Spec {
            name: "coal/N=4",
            tag: 12,
            scheme: Scheme::Dgram {
                carry: Some(4),
                k: 1,
                coalesce: true,
            },
        },
    ]
}

fn frame_sizes(seed: u64) -> Vec<u64> {
    let mut rng = Rng::new(mix(seed, 0x51CE));
    (0..N_FRAMES)
        .map(|_| 30 + (rng.next_f64() * 31.0) as u64)
        .collect()
}

fn run_spec(sizes: &[u64], seed: u64, kind: LossKind, spec: &Spec) -> Outcome {
    let seeded = mix(seed, spec.tag);
    match &spec.scheme {
        Scheme::Tcp => simulate_tcp(sizes, seeded, kind),
        Scheme::Dgram { .. } => simulate_dgram(sizes, seeded, kind, &spec.scheme),
    }
}

fn loss_label(kind: LossKind) -> &'static str {
    match kind {
        LossKind::Bernoulli(_) => "bern 7.5%",
        LossKind::Gilbert => "gilbert",
    }
}

fn reports(seed: u64) -> Vec<Report> {
    let sizes = frame_sizes(seed);
    let mut out = Vec::new();
    for kind in [LossKind::Bernoulli(BERN_P), LossKind::Gilbert] {
        let label = loss_label(kind);
        for spec in specs() {
            let outcome = run_spec(&sizes, seed, kind, &spec);
            out.push(report(spec.name, label, outcome));
        }
    }
    out
}

fn fmt_ms(us: u64) -> String {
    format!("{:.1}", us as f64 / 1000.0)
}

/// Markdown table for one seed. Delay columns are added delay over the 85 ms
/// floor, nearest-rank percentile (`ceil(p · n) - 1` on the sorted samples).
pub fn render(seed: u64) -> String {
    let rows = reports(seed);
    let mut text = String::new();
    text.push_str(&format!(
        "seed {seed}, {N_FRAMES} frames of 30–60 B every 20 ms, 60 s, one-way {ONE_WAY_US} µs\n\n"
    ));
    text.push_str("| scheme | loss | p50 ms | p99 ms | p99.9 ms | max ms | stalls>300ms | stalls>1s | residual | wire/payload | pkt/s |\n");
    text.push_str("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for row in &rows {
        text.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.3}% | {:.2} | {:.1} |\n",
            row.name,
            row.loss,
            fmt_ms(row.p50),
            fmt_ms(row.p99),
            fmt_ms(row.p999),
            fmt_ms(row.max),
            row.stalls_300,
            row.stalls_1s,
            row.residual * 100.0,
            row.wire_ratio,
            row.pps,
        ));
    }
    let pi = GE_GOOD_TO_BAD / (GE_GOOD_TO_BAD + GE_BAD_TO_GOOD);
    text.push_str(&format!(
        "\nGilbert-Elliott per direction: good→bad {GE_GOOD_TO_BAD:.5}, bad→good {GE_BAD_TO_GOOD}, \
         loss 0 in good / 1 in bad, steady-state loss {pi:.4}. \
         Transition then drop, same order as `impair::LossModel`, initial state drawn from the steady fraction. \
         TCP baseline is `impair`'s fast-retransmit / tail-loss / RTO ladder plus head-of-line; \
         retransmission losses are drawn up front; the SYN rule is not applied. \
         Datagram retransmit fires at 1.5 × RTT from first send and is redrawn when it is sent; \
         an ACK rides the flow that received the data. \
         Residual is the share of frames no original copy delivered (a later retransmit may still). \
         A stall is an in-order release gap. \
         Wire bytes assume IPv4+TCP 40 B or IPv4+UDP 28 B, a 4 B datagram header and 6 B per carried frame, \
         ACKs of 2+4n bytes, and one TCP ACK per two segments (dup-ACKs not counted). Those sizes are assumptions.\n"
    ));
    text
}

/// Both copies lost, K independent Bernoulli draws, no retransmit.
/// Scheme 3's residual when each flow drops with `loss`.
#[cfg(test)]
fn duplication_residual(loss: f64, k: usize, packets: u64, seed: u64) -> f64 {
    let mut paths: Vec<Rng> = (0..k)
        .map(|flow| Rng::new(path_seed(seed, flow, false)))
        .collect();
    let mut all_lost = 0u64;
    for _ in 0..packets {
        let mut survived = false;
        for path in &mut paths {
            if path.next_f64() >= loss {
                survived = true;
            }
        }
        if !survived {
            all_lost += 1;
        }
    }
    all_lost as f64 / packets as f64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DgramSimOptions {
    pub seed: u64,
}

pub fn parse_args(args: &[String]) -> Result<DgramSimOptions, BenchError> {
    let mut seed = DEFAULT_SEED;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--seed" => {
                seed = parse_u64(required_value(args, &mut index, flag)?, flag)?;
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\nusage: segue-bench dgramsim [--seed <n>]"
                )));
            }
        }
    }
    Ok(DgramSimOptions { seed })
}

pub fn run(options: DgramSimOptions) -> Result<(), BenchError> {
    println!("{}", render(options.seed));
    Ok(())
}

#[cfg(test)]
fn added_delays(spec: &Spec, kind: LossKind, seed: u64) -> Vec<u64> {
    let sizes = frame_sizes(seed);
    run_spec(&sizes, seed, kind, spec).added
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_loss_adds_no_delay_for_every_scheme() {
        let seed = 7u64;
        for spec in specs() {
            let added = added_delays(&spec, LossKind::Bernoulli(0.0), seed);
            assert_eq!(added.len(), N_FRAMES, "{}", spec.name);
            let coalesced = matches!(spec.scheme, Scheme::Dgram { coalesce: true, .. });
            if coalesced {
                // The packet waits for the later frame of the pair. That hold
                // is 0 or one 20 ms slot; loss adds nothing on top.
                let held = added.iter().filter(|d| **d == INTERVAL_US).count();
                assert!(
                    added.iter().all(|d| *d == 0 || *d == INTERVAL_US),
                    "{} had a delay other than 0 or 20 ms: {:?}",
                    spec.name,
                    added.iter().copied().max()
                );
                assert_eq!(held, N_FRAMES / 2, "{}", spec.name);
            } else {
                assert!(
                    added.iter().all(|d| *d == 0),
                    "{} added {} µs at zero loss",
                    spec.name,
                    added.iter().copied().max().unwrap_or(0)
                );
            }
        }
    }

    #[test]
    fn scheme3_k2_residual_at_14pct() {
        let rate = duplication_residual(0.14, 2, 100_000, 1);
        let pct = rate * 100.0;
        assert!(
            (pct - 1.96).abs() <= 0.4,
            "residual {pct:.4}% is outside 1.96% ± 0.4 over 100000 packets"
        );
    }

    #[test]
    fn same_seed_same_table() {
        let a = render(0xC0FFEE);
        let b = render(0xC0FFEE);
        assert_eq!(a, b);
        assert_ne!(a, render(0xC0FFEE ^ 0x9E37));
    }
}
