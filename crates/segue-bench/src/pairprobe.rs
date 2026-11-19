//! Pair probe: do two flows between the same hosts lose packets together?
//!
//! `pairprobe server` echoes UDP datagrams and 4-byte-length-prefixed TCP
//! records. `pairprobe client` sends the same light probe on every flow and
//! reports per-flow loss, loss-burst shape, and the conditional probability
//! that flow k is lost given that flow 0 was lost a few milliseconds earlier.
//!
//! Statistics are pure functions of `&[Option<Duration>]` (an echo's round
//! trip, or `None` when it did not arrive). UDP treats an echo later than
//! `LOSS_TIMEOUT` as lost. TCP has no loss; a stall is an echo later than
//! that flow's minimum RTT plus 200 ms. A loss burst's duration is the time
//! from its first lost probe to its last (`(length - 1) / pps`); a single
//! lost probe has duration 0.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep_until, timeout, Instant};

use crate::{parse_u64, required_value, BenchError};

const MAGIC: &[u8; 4] = b"SGPP";
const HEADER_LEN: usize = 4 + 1 + 8 + 8;
const MAX_PPS: u64 = 200;
const MAX_PROBE_SIZE: u64 = 1200;
const MIN_PROBE_SIZE: u64 = HEADER_LEN as u64;
const DEFAULT_PPS: u64 = 30;
const DEFAULT_SIZE: usize = 100;
const DEFAULT_SECONDS: u64 = 600;
const DEFAULT_FLOWS: u64 = 2;
const DEFAULT_STAGGER_MS: u64 = 0;
const DEFAULT_MAX_SECONDS: u64 = 900;
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FLOWS: u64 = 255;
const MAX_STAGGER_MS: u64 = 60_000;
const MAX_PROBES: u64 = 20_000_000;
const TCP_RECORD_CAP: usize = 65_536;
/// An echo that arrives after this is not a sample. UDP counts it as lost.
const LOSS_TIMEOUT: Duration = Duration::from_secs(3);
const STALL_MARGIN: Duration = Duration::from_millis(200);
const COND_LAGS_MS: [u64; 7] = [0, 10, 30, 50, 100, 200, 500];

const USAGE: &str = "\
usage: segue-bench pairprobe server --listen <addr> [--max-seconds <n>] [--max-bytes <n>]
       segue-bench pairprobe client --server <addr> [--pps <n>] [--size <n>] [--seconds <n>] [--flows <n>] [--stagger-ms <n>] [--out <file>]";

fn io_err(action: impl Into<String>, source: std::io::Error) -> BenchError {
    BenchError::Io {
        action: action.into(),
        source,
    }
}

fn encode_probe(buf: &mut [u8], flow: u8, seq: u64, send_us: u64) {
    buf[..4].copy_from_slice(MAGIC);
    buf[4] = flow;
    buf[5..13].copy_from_slice(&seq.to_be_bytes());
    buf[13..21].copy_from_slice(&send_us.to_be_bytes());
}

fn decode_probe(buf: &[u8]) -> Option<(u8, u64, u64)> {
    if buf.len() < HEADER_LEN || buf[..4] != MAGIC[..] {
        return None;
    }
    let seq = u64::from_be_bytes(buf[5..13].try_into().ok()?);
    let send_us = u64::from_be_bytes(buf[13..21].try_into().ok()?);
    Some((buf[4], seq, send_us))
}

/// Consecutive lost probes, bucketed the way the report prints them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BurstHistogram {
    pub len_1: u64,
    pub len_2: u64,
    pub len_3: u64,
    pub len_4: u64,
    pub len_5_to_8: u64,
    pub len_9_plus: u64,
}

/// Length, in probes, of each run of consecutive losses. A run at the end counts.
pub fn loss_bursts(samples: &[Option<Duration>]) -> Vec<usize> {
    let mut bursts = Vec::new();
    let mut run = 0usize;
    for sample in samples {
        if sample.is_none() {
            run += 1;
        } else if run > 0 {
            bursts.push(run);
            run = 0;
        }
    }
    if run > 0 {
        bursts.push(run);
    }
    bursts
}

pub fn burst_histogram(samples: &[Option<Duration>]) -> BurstHistogram {
    let mut hist = BurstHistogram::default();
    for len in loss_bursts(samples) {
        match len {
            1 => hist.len_1 += 1,
            2 => hist.len_2 += 1,
            3 => hist.len_3 += 1,
            4 => hist.len_4 += 1,
            5..=8 => hist.len_5_to_8 += 1,
            _ => hist.len_9_plus += 1,
        }
    }
    hist
}

/// Nearest-rank index. `p` is in `(0, 1]`. Empty input is `None`.
fn percentile_index(len: usize, p: f64) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let rank = (p * len as f64).ceil() as usize;
    Some(rank.saturating_sub(1).min(len - 1))
}

fn percentile_duration(sorted: &[Duration], p: f64) -> Option<Duration> {
    percentile_index(sorted.len(), p).map(|index| sorted[index])
}

fn percentile_f64(sorted: &[f64], p: f64) -> Option<f64> {
    percentile_index(sorted.len(), p).map(|index| sorted[index])
}

/// Time from the first lost probe of a burst to the last. One probe is 0.
fn burst_span_ms(len: usize, interval: Duration) -> f64 {
    let slots = len.saturating_sub(1) as u128;
    let nanos = interval.as_nanos().saturating_mul(slots);
    nanos as f64 / 1_000_000.0
}

/// Sequence offset nearest to `lag_ms`, and the lag that offset actually is.
pub fn nearest_lag(lag_ms: u64, interval: Duration) -> (i64, f64) {
    let interval_ns = interval.as_nanos();
    if interval_ns == 0 {
        return (0, 0.0);
    }
    let lag_ns = (lag_ms as u128).saturating_mul(1_000_000);
    let offset = ((lag_ns + interval_ns / 2) / interval_ns) as i64;
    let actual_ns = interval_ns.saturating_mul(offset as u128);
    (offset, actual_ns as f64 / 1_000_000.0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct CondLag {
    pub requested_lag_ms: u64,
    pub lag_ms: f64,
    pub probability: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PairLoss {
    pub a: u8,
    pub b: u8,
    pub p_loss_a: f64,
    pub p_loss_b: f64,
    pub p_both: f64,
    /// Unconditional loss rate of flow B, so a reader can compare `cond` to it.
    pub independent_expectation: f64,
    pub cond: Vec<CondLag>,
}

/// `P(B lost at the probe nearest to `lag` after A's probe | A lost)`.
fn conditional_loss(a: &[Option<Duration>], b: &[Option<Duration>], offset: i64) -> Option<f64> {
    let mut losses = 0u64;
    let mut both = 0u64;
    for (index, sample) in a.iter().enumerate() {
        if sample.is_some() {
            continue;
        }
        let shifted = index as i64 + offset;
        if shifted < 0 {
            continue;
        }
        let Some(other) = usize::try_from(shifted).ok().and_then(|at| b.get(at)) else {
            continue;
        };
        losses += 1;
        if other.is_none() {
            both += 1;
        }
    }
    if losses == 0 {
        None
    } else {
        Some(both as f64 / losses as f64)
    }
}

pub fn pair_loss(
    a_id: u8,
    b_id: u8,
    a: &[Option<Duration>],
    b: &[Option<Duration>],
    interval: Duration,
) -> PairLoss {
    let n = a.len().min(b.len());
    let a = &a[..n];
    let b = &b[..n];
    let loss_a = a.iter().filter(|sample| sample.is_none()).count();
    let loss_b = b.iter().filter(|sample| sample.is_none()).count();
    let both = a
        .iter()
        .zip(b.iter())
        .filter(|(left, right)| left.is_none() && right.is_none())
        .count();
    let denom = n as f64;
    let p_loss_a = if n == 0 { 0.0 } else { loss_a as f64 / denom };
    let p_loss_b = if n == 0 { 0.0 } else { loss_b as f64 / denom };
    let p_both = if n == 0 { 0.0 } else { both as f64 / denom };
    let cond = COND_LAGS_MS
        .iter()
        .copied()
        .map(|requested| {
            let (offset, lag_ms) = nearest_lag(requested, interval);
            CondLag {
                requested_lag_ms: requested,
                lag_ms,
                probability: conditional_loss(a, b, offset),
            }
        })
        .collect();
    PairLoss {
        a: a_id,
        b: b_id,
        p_loss_a,
        p_loss_b,
        p_both,
        independent_expectation: p_loss_b,
        cond,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UdpFlowStats {
    pub id: u8,
    pub sent: usize,
    pub lost: usize,
    pub loss_rate: f64,
    pub rtt_min: Option<Duration>,
    pub rtt_p50: Option<Duration>,
    pub rtt_p99: Option<Duration>,
    pub burst_histogram: BurstHistogram,
    pub burst_p50_ms: Option<f64>,
    pub burst_p99_ms: Option<f64>,
    pub burst_max_ms: Option<f64>,
}

pub fn udp_flow_stats(id: u8, samples: &[Option<Duration>], interval: Duration) -> UdpFlowStats {
    let sent = samples.len();
    let lost = samples.iter().filter(|sample| sample.is_none()).count();
    let mut rtts: Vec<Duration> = samples.iter().copied().flatten().collect();
    rtts.sort();
    let mut spans: Vec<f64> = loss_bursts(samples)
        .iter()
        .map(|len| burst_span_ms(*len, interval))
        .collect();
    spans.sort_by(f64::total_cmp);
    UdpFlowStats {
        id,
        sent,
        lost,
        loss_rate: if sent == 0 {
            0.0
        } else {
            lost as f64 / sent as f64
        },
        rtt_min: rtts.first().copied(),
        rtt_p50: percentile_duration(&rtts, 0.50),
        rtt_p99: percentile_duration(&rtts, 0.99),
        burst_histogram: burst_histogram(samples),
        burst_p50_ms: percentile_f64(&spans, 0.50),
        burst_p99_ms: percentile_f64(&spans, 0.99),
        burst_max_ms: spans.last().copied(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpFlowStats {
    pub id: u8,
    pub sent: usize,
    pub rtt_min: Option<Duration>,
    pub rtt_p50: Option<Duration>,
    pub rtt_p99: Option<Duration>,
    pub rtt_max: Option<Duration>,
    pub stalls: usize,
    pub stall_p50: Option<Duration>,
    pub stall_max: Option<Duration>,
}

fn stall_flags(samples: &[Option<Duration>]) -> Vec<bool> {
    let Some(min_rtt) = samples.iter().copied().flatten().min() else {
        return vec![false; samples.len()];
    };
    let threshold = min_rtt.saturating_add(STALL_MARGIN);
    samples
        .iter()
        .map(|sample| match sample {
            Some(rtt) => *rtt > threshold,
            None => false,
        })
        .collect()
}

pub fn tcp_flow_stats(id: u8, samples: &[Option<Duration>]) -> TcpFlowStats {
    let mut rtts: Vec<Duration> = samples.iter().copied().flatten().collect();
    rtts.sort();
    let min_rtt = rtts.first().copied();
    let mut stall_durs = Vec::new();
    if let Some(min_rtt) = min_rtt {
        let threshold = min_rtt.saturating_add(STALL_MARGIN);
        for rtt in &rtts {
            if *rtt > threshold {
                stall_durs.push(rtt.saturating_sub(min_rtt));
            }
        }
    }
    stall_durs.sort();
    TcpFlowStats {
        id,
        sent: samples.len(),
        rtt_min: min_rtt,
        rtt_p50: percentile_duration(&rtts, 0.50),
        rtt_p99: percentile_duration(&rtts, 0.99),
        rtt_max: rtts.last().copied(),
        stalls: stall_durs.len(),
        stall_p50: percentile_duration(&stall_durs, 0.50),
        stall_max: stall_durs.last().copied(),
    }
}

/// Fraction of flow-A stalls at which flow B, same sequence, was also stalled.
pub fn tcp_stall_overlap(a: &[Option<Duration>], b: &[Option<Duration>]) -> Option<f64> {
    let flags_a = stall_flags(a);
    let flags_b = stall_flags(b);
    let n = flags_a.len().min(flags_b.len());
    let mut stalls = 0u64;
    let mut both = 0u64;
    for index in 0..n {
        if flags_a[index] {
            stalls += 1;
            if flags_b[index] {
                both += 1;
            }
        }
    }
    if stalls == 0 {
        None
    } else {
        Some(both as f64 / stalls as f64)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TcpPair {
    pub a: u8,
    pub b: u8,
    pub stall_overlap: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub pps: u64,
    pub size: usize,
    pub seconds: u64,
    pub flows: u64,
    pub stagger_ms: u64,
    pub interval: Duration,
    pub udp_flows: Vec<UdpFlowStats>,
    pub udp_pairs: Vec<PairLoss>,
    pub tcp_flows: Vec<TcpFlowStats>,
    pub tcp_pairs: Vec<TcpPair>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

struct ReportParts<'a> {
    pps: u64,
    size: usize,
    seconds: u64,
    stagger_ms: u64,
    interval: Duration,
    udp: &'a [Vec<Option<Duration>>],
    tcp: &'a [Vec<Option<Duration>>],
    bytes_sent: u64,
    bytes_received: u64,
}

fn build_report(parts: ReportParts<'_>) -> Report {
    let ReportParts {
        pps,
        size,
        seconds,
        stagger_ms,
        interval,
        udp,
        tcp,
        bytes_sent,
        bytes_received,
    } = parts;
    let udp_flows = udp
        .iter()
        .enumerate()
        .map(|(index, samples)| udp_flow_stats(index as u8, samples, interval))
        .collect::<Vec<_>>();
    let tcp_flows = tcp
        .iter()
        .enumerate()
        .map(|(index, samples)| tcp_flow_stats(index as u8, samples))
        .collect::<Vec<_>>();
    let mut udp_pairs = Vec::new();
    let mut tcp_pairs = Vec::new();
    for (index, samples) in udp.iter().enumerate().skip(1) {
        let id = index as u8;
        udp_pairs.push(pair_loss(0, id, &udp[0], samples, interval));
    }
    for (index, samples) in tcp.iter().enumerate().skip(1) {
        let id = index as u8;
        tcp_pairs.push(TcpPair {
            a: 0,
            b: id,
            stall_overlap: tcp_stall_overlap(&tcp[0], samples),
        });
    }
    Report {
        pps,
        size,
        seconds,
        flows: udp.len().max(tcp.len()) as u64,
        stagger_ms,
        interval,
        udp_flows,
        udp_pairs,
        tcp_flows,
        tcp_pairs,
        bytes_sent,
        bytes_received,
    }
}

fn fmt_f64(value: f64) -> String {
    if value.is_finite() {
        format!("{value:.6}")
    } else {
        "null".to_owned()
    }
}

fn fmt_opt_f64(value: Option<f64>) -> String {
    match value {
        Some(value) => fmt_f64(value),
        None => "null".to_owned(),
    }
}

fn fmt_opt_us(value: Option<Duration>) -> String {
    match value {
        Some(value) => value.as_micros().to_string(),
        None => "null".to_owned(),
    }
}

fn fmt_opt_ms(value: Option<Duration>) -> String {
    match value {
        Some(value) => fmt_f64(value.as_micros() as f64 / 1000.0),
        None => "null".to_owned(),
    }
}

impl Report {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        let _ = writeln!(
            out,
            "  \"config\": {{\"pps\": {}, \"size\": {}, \"seconds\": {}, \"flows\": {}, \"stagger_ms\": {}, \"interval_us\": {}}},",
            self.pps,
            self.size,
            self.seconds,
            self.flows,
            self.stagger_ms,
            self.interval.as_micros()
        );
        out.push_str("  \"udp\": {\n    \"flows\": [\n");
        for (index, flow) in self.udp_flows.iter().enumerate() {
            push_udp_flow(&mut out, flow, index + 1 == self.udp_flows.len());
        }
        out.push_str("    ],\n    \"pairs\": [\n");
        for (index, pair) in self.udp_pairs.iter().enumerate() {
            push_udp_pair(&mut out, pair, index + 1 == self.udp_pairs.len());
        }
        out.push_str("    ]\n  },\n  \"tcp\": {\n    \"flows\": [\n");
        for (index, flow) in self.tcp_flows.iter().enumerate() {
            push_tcp_flow(&mut out, flow, index + 1 == self.tcp_flows.len());
        }
        out.push_str("    ],\n    \"pairs\": [\n");
        for (index, pair) in self.tcp_pairs.iter().enumerate() {
            let comma = if index + 1 == self.tcp_pairs.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                out,
                "      {{\"a\": {}, \"b\": {}, \"stall_overlap\": {}}}{comma}",
                pair.a,
                pair.b,
                fmt_opt_f64(pair.stall_overlap)
            );
        }
        let _ = writeln!(
            out,
            "    ]\n  }},\n  \"bytes_sent\": {},\n  \"bytes_received\": {}\n}}",
            self.bytes_sent, self.bytes_received
        );
        out
    }

    pub fn human(&self) -> String {
        let mut out = String::new();
        for flow in &self.udp_flows {
            let hist = &flow.burst_histogram;
            let _ = writeln!(
                out,
                "UDP flow {}: sent={} lost={} loss={:.2}% rtt_us min/p50/p99={}/{}/{} bursts 1/2/3/4/5-8/9+={}/{}/{}/{}/{}/{} burst_ms p50/p99/max={}/{}/{}",
                flow.id,
                flow.sent,
                flow.lost,
                flow.loss_rate * 100.0,
                fmt_opt_us(flow.rtt_min),
                fmt_opt_us(flow.rtt_p50),
                fmt_opt_us(flow.rtt_p99),
                hist.len_1,
                hist.len_2,
                hist.len_3,
                hist.len_4,
                hist.len_5_to_8,
                hist.len_9_plus,
                fmt_opt_f64(flow.burst_p50_ms),
                fmt_opt_f64(flow.burst_p99_ms),
                fmt_opt_f64(flow.burst_max_ms)
            );
        }
        for pair in &self.udp_pairs {
            let _ = writeln!(
                out,
                "UDP pair {},{}: p_loss_a={} p_loss_b={} p_both={} independent={}",
                pair.a,
                pair.b,
                fmt_f64(pair.p_loss_a),
                fmt_f64(pair.p_loss_b),
                fmt_f64(pair.p_both),
                fmt_f64(pair.independent_expectation)
            );
            for cond in &pair.cond {
                let _ = writeln!(
                    out,
                    "  cond requested {} ms used {} ms p={}",
                    cond.requested_lag_ms,
                    fmt_f64(cond.lag_ms),
                    fmt_opt_f64(cond.probability)
                );
            }
        }
        for flow in &self.tcp_flows {
            let _ = writeln!(
                out,
                "TCP flow {}: sent={} rtt_us min/p50/p99/max={}/{}/{}/{} stalls={} stall_ms p50/max={}/{}",
                flow.id,
                flow.sent,
                fmt_opt_us(flow.rtt_min),
                fmt_opt_us(flow.rtt_p50),
                fmt_opt_us(flow.rtt_p99),
                fmt_opt_us(flow.rtt_max),
                flow.stalls,
                fmt_opt_ms(flow.stall_p50),
                fmt_opt_ms(flow.stall_max)
            );
        }
        for pair in &self.tcp_pairs {
            let _ = writeln!(
                out,
                "TCP pair {},{}: stall_overlap={}",
                pair.a,
                pair.b,
                fmt_opt_f64(pair.stall_overlap)
            );
        }
        let _ = writeln!(
            out,
            "bytes_sent={} bytes_received={}",
            self.bytes_sent, self.bytes_received
        );
        out
    }
}

fn push_udp_flow(out: &mut String, flow: &UdpFlowStats, last: bool) {
    let comma = if last { "" } else { "," };
    let hist = &flow.burst_histogram;
    let _ = writeln!(
        out,
        "      {{\"id\": {}, \"sent\": {}, \"lost\": {}, \"loss_rate\": {}, \"rtt_min_us\": {}, \"rtt_p50_us\": {}, \"rtt_p99_us\": {}, \"loss_burst_histogram\": {{\"1\": {}, \"2\": {}, \"3\": {}, \"4\": {}, \"5-8\": {}, \"9+\": {}}}, \"burst_duration_ms\": {{\"p50\": {}, \"p99\": {}, \"max\": {}}}}}{comma}",
        flow.id,
        flow.sent,
        flow.lost,
        fmt_f64(flow.loss_rate),
        fmt_opt_us(flow.rtt_min),
        fmt_opt_us(flow.rtt_p50),
        fmt_opt_us(flow.rtt_p99),
        hist.len_1,
        hist.len_2,
        hist.len_3,
        hist.len_4,
        hist.len_5_to_8,
        hist.len_9_plus,
        fmt_opt_f64(flow.burst_p50_ms),
        fmt_opt_f64(flow.burst_p99_ms),
        fmt_opt_f64(flow.burst_max_ms)
    );
}

fn push_udp_pair(out: &mut String, pair: &PairLoss, last: bool) {
    let comma = if last { "" } else { "," };
    let _ = writeln!(
        out,
        "      {{\"a\": {}, \"b\": {}, \"p_loss_a\": {}, \"p_loss_b\": {}, \"p_both\": {}, \"independent_expectation\": {}, \"cond\": [",
        pair.a,
        pair.b,
        fmt_f64(pair.p_loss_a),
        fmt_f64(pair.p_loss_b),
        fmt_f64(pair.p_both),
        fmt_f64(pair.independent_expectation)
    );
    for (index, cond) in pair.cond.iter().enumerate() {
        let cond_comma = if index + 1 == pair.cond.len() {
            ""
        } else {
            ","
        };
        let _ = writeln!(
            out,
            "        {{\"requested_lag_ms\": {}, \"lag_ms\": {}, \"p\": {}}}{cond_comma}",
            cond.requested_lag_ms,
            fmt_f64(cond.lag_ms),
            fmt_opt_f64(cond.probability)
        );
    }
    let _ = writeln!(out, "      ]}}{comma}");
}

fn push_tcp_flow(out: &mut String, flow: &TcpFlowStats, last: bool) {
    let comma = if last { "" } else { "," };
    let _ = writeln!(
        out,
        "      {{\"id\": {}, \"sent\": {}, \"rtt_min_us\": {}, \"rtt_p50_us\": {}, \"rtt_p99_us\": {}, \"rtt_max_us\": {}, \"stalls\": {}, \"stall_duration_p50_ms\": {}, \"stall_duration_max_ms\": {}}}{comma}",
        flow.id,
        flow.sent,
        fmt_opt_us(flow.rtt_min),
        fmt_opt_us(flow.rtt_p50),
        fmt_opt_us(flow.rtt_p99),
        fmt_opt_us(flow.rtt_max),
        flow.stalls,
        fmt_opt_ms(flow.stall_p50),
        fmt_opt_ms(flow.stall_max)
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerOptions {
    pub listen: SocketAddr,
    pub max_seconds: u64,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOptions {
    pub server: SocketAddr,
    pub pps: u64,
    pub size: usize,
    pub seconds: u64,
    pub flows: u64,
    pub stagger_ms: u64,
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairProbeCommand {
    Server(ServerOptions),
    Client(ClientOptions),
}

pub fn parse_args(args: &[String]) -> Result<PairProbeCommand, BenchError> {
    let Some(mode) = args.first() else {
        return Err(BenchError::InvalidArguments(USAGE.to_owned()));
    };
    match mode.as_str() {
        "server" => parse_server_args(&args[1..]).map(PairProbeCommand::Server),
        "client" => parse_client_args(&args[1..]).map(PairProbeCommand::Client),
        other => Err(BenchError::InvalidArguments(format!(
            "unknown pairprobe mode `{other}`\n{USAGE}"
        ))),
    }
}

fn parse_socket(raw: &str, flag: &str) -> Result<SocketAddr, BenchError> {
    raw.parse::<SocketAddr>().map_err(|_| {
        BenchError::InvalidArguments(format!("invalid socket address `{raw}` for {flag}"))
    })
}

fn parse_bounded(raw: &str, flag: &str, min: u64, max: u64) -> Result<u64, BenchError> {
    let value = parse_u64(raw, flag)?;
    if value < min || value > max {
        return Err(BenchError::InvalidArguments(format!(
            "{flag} must be between {min} and {max}"
        )));
    }
    Ok(value)
}

fn parse_server_args(args: &[String]) -> Result<ServerOptions, BenchError> {
    let mut listen = None;
    let mut max_seconds = DEFAULT_MAX_SECONDS;
    let mut max_bytes = DEFAULT_MAX_BYTES;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--listen" => {
                listen = Some(parse_socket(required_value(args, &mut index, flag)?, flag)?);
            }
            "--max-seconds" => {
                max_seconds =
                    parse_bounded(required_value(args, &mut index, flag)?, flag, 1, 86_400)?;
            }
            "--max-bytes" => {
                max_bytes =
                    parse_bounded(required_value(args, &mut index, flag)?, flag, 1, u64::MAX)?;
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )))
            }
        }
    }
    let listen = listen.ok_or_else(|| {
        BenchError::InvalidArguments("pairprobe server requires --listen <addr>".to_owned())
    })?;
    Ok(ServerOptions {
        listen,
        max_seconds,
        max_bytes,
    })
}

fn parse_client_args(args: &[String]) -> Result<ClientOptions, BenchError> {
    let mut server = None;
    let mut pps = DEFAULT_PPS;
    let mut size = DEFAULT_SIZE as u64;
    let mut seconds = DEFAULT_SECONDS;
    let mut flows = DEFAULT_FLOWS;
    let mut stagger_ms = DEFAULT_STAGGER_MS;
    let mut out = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--server" => {
                server = Some(parse_socket(required_value(args, &mut index, flag)?, flag)?);
            }
            "--pps" => {
                pps = parse_bounded(required_value(args, &mut index, flag)?, flag, 1, MAX_PPS)?;
            }
            "--size" => {
                size = parse_bounded(
                    required_value(args, &mut index, flag)?,
                    flag,
                    MIN_PROBE_SIZE,
                    MAX_PROBE_SIZE,
                )?;
            }
            "--seconds" => {
                seconds = parse_bounded(required_value(args, &mut index, flag)?, flag, 1, 86_400)?;
            }
            "--flows" => {
                flows = parse_bounded(required_value(args, &mut index, flag)?, flag, 1, MAX_FLOWS)?;
            }
            "--stagger-ms" => {
                stagger_ms = parse_bounded(
                    required_value(args, &mut index, flag)?,
                    flag,
                    0,
                    MAX_STAGGER_MS,
                )?;
            }
            "--out" => {
                out = Some(PathBuf::from(required_value(args, &mut index, flag)?));
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )))
            }
        }
    }
    let server = server.ok_or_else(|| {
        BenchError::InvalidArguments("pairprobe client requires --server <addr>".to_owned())
    })?;
    Ok(ClientOptions {
        server,
        pps,
        size: usize::try_from(size).unwrap_or(usize::MAX),
        seconds,
        flows,
        stagger_ms,
        out,
    })
}

fn validate_client(options: &ClientOptions) -> Result<(), BenchError> {
    if options.pps == 0 || options.pps > MAX_PPS {
        return Err(BenchError::InvalidArguments(format!(
            "--pps must be between 1 and {MAX_PPS}"
        )));
    }
    if options.size < HEADER_LEN || options.size > MAX_PROBE_SIZE as usize {
        return Err(BenchError::InvalidArguments(format!(
            "--size must be between {HEADER_LEN} and {MAX_PROBE_SIZE}"
        )));
    }
    if options.seconds == 0 {
        return Err(BenchError::InvalidArguments(
            "--seconds must be greater than zero".to_owned(),
        ));
    }
    if options.flows == 0 || options.flows > MAX_FLOWS {
        return Err(BenchError::InvalidArguments(format!(
            "--flows must be between 1 and {MAX_FLOWS}"
        )));
    }
    if options.stagger_ms > MAX_STAGGER_MS {
        return Err(BenchError::InvalidArguments(format!(
            "--stagger-ms must be at most {MAX_STAGGER_MS}"
        )));
    }
    Ok(())
}

fn send_interval(pps: u64) -> Duration {
    let nanos = 1_000_000_000u64 / pps;
    let rem = 1_000_000_000u64 % pps;
    let nanos = if rem * 2 >= pps { nanos + 1 } else { nanos };
    Duration::from_nanos(nanos.max(1))
}

async fn bind_server(
    listen: SocketAddr,
) -> Result<(TcpListener, UdpSocket, SocketAddr), BenchError> {
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let tcp = TcpListener::bind(listen)
            .await
            .map_err(|source| io_err(format!("binding TCP {listen}"), source))?;
        let tcp_addr = tcp
            .local_addr()
            .map_err(|source| io_err("reading the TCP listen address", source))?;
        let udp_addr = SocketAddr::new(tcp_addr.ip(), tcp_addr.port());
        match UdpSocket::bind(udp_addr).await {
            Ok(udp) => return Ok((tcp, udp, udp_addr)),
            Err(_) if listen.port() == 0 && attempts < 32 => {}
            Err(source) => return Err(io_err(format!("binding UDP {udp_addr}"), source)),
        }
    }
}

fn note_bytes(echoed: &AtomicU64, nbytes: u64, max_bytes: u64) -> bool {
    echoed
        .fetch_add(nbytes, Ordering::Relaxed)
        .saturating_add(nbytes)
        >= max_bytes
}

async fn echo_udp(
    socket: UdpSocket,
    echoed: Arc<AtomicU64>,
    max_bytes: u64,
    stop_tx: tokio::sync::watch::Sender<bool>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), BenchError> {
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return Ok(());
                }
            }
            received = socket.recv_from(&mut buf) => {
                let (len, from) = received.map_err(|source| io_err("receiving a UDP probe", source))?;
                socket
                    .send_to(&buf[..len], from)
                    .await
                    .map_err(|source| io_err("echoing a UDP probe", source))?;
                if note_bytes(&echoed, len as u64, max_bytes) {
                    let _ = stop_tx.send(true);
                    return Ok(());
                }
            }
        }
    }
}

async fn echo_tcp_conn(
    mut stream: TcpStream,
    echoed: Arc<AtomicU64>,
    max_bytes: u64,
    stop_tx: tokio::sync::watch::Sender<bool>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), BenchError> {
    loop {
        let mut len_buf = [0u8; 4];
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    return Ok(());
                }
            }
            read = stream.read_exact(&mut len_buf) => {
                match read {
                    Ok(_) => {}
                    Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    Err(source) => return Err(io_err("reading a TCP probe length", source)),
                }
                let n = u32::from_be_bytes(len_buf) as usize;
                if n > TCP_RECORD_CAP {
                    return Err(BenchError::InvalidArguments(format!(
                        "TCP probe record of {n} bytes exceeds {TCP_RECORD_CAP}"
                    )));
                }
                let mut payload = vec![0u8; n];
                stream
                    .read_exact(&mut payload)
                    .await
                    .map_err(|source| io_err("reading a TCP probe", source))?;
                stream
                    .write_all(&len_buf)
                    .await
                    .map_err(|source| io_err("echoing a TCP probe length", source))?;
                stream
                    .write_all(&payload)
                    .await
                    .map_err(|source| io_err("echoing a TCP probe", source))?;
                if note_bytes(&echoed, 4u64.saturating_add(n as u64), max_bytes) {
                    let _ = stop_tx.send(true);
                    return Ok(());
                }
            }
        }
    }
}

async fn echo_tcp(
    listener: TcpListener,
    echoed: Arc<AtomicU64>,
    max_bytes: u64,
    stop_tx: tokio::sync::watch::Sender<bool>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), BenchError> {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|source| io_err("accepting a TCP probe", source))?;
                stream
                    .set_nodelay(true)
                    .map_err(|source| io_err("enabling TCP_NODELAY", source))?;
                let echoed = Arc::clone(&echoed);
                let stop_tx = stop_tx.clone();
                let stop_rx = stop_rx.clone();
                conns.spawn(async move {
                    let _ = echo_tcp_conn(stream, echoed, max_bytes, stop_tx, stop_rx).await;
                });
            }
        }
    }
    conns.abort_all();
    Ok(())
}

async fn serve(
    tcp: TcpListener,
    udp: UdpSocket,
    max_seconds: u64,
    max_bytes: u64,
) -> Result<(), BenchError> {
    let echoed = Arc::new(AtomicU64::new(0));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let mut udp_task = tokio::spawn(echo_udp(
        udp,
        Arc::clone(&echoed),
        max_bytes,
        stop_tx.clone(),
        stop_rx.clone(),
    ));
    let mut tcp_task = tokio::spawn(echo_tcp(
        tcp,
        echoed,
        max_bytes,
        stop_tx.clone(),
        stop_rx.clone(),
    ));
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(max_seconds)) => {}
        _ = stop_rx.changed() => {}
        result = &mut udp_task => {
            join_task(result)?;
        }
        result = &mut tcp_task => {
            join_task(result)?;
        }
    }
    let _ = stop_tx.send(true);
    udp_task.abort();
    tcp_task.abort();
    Ok(())
}

fn join_task(
    result: Result<Result<(), BenchError>, tokio::task::JoinError>,
) -> Result<(), BenchError> {
    match result {
        Ok(inner) => inner,
        Err(error) => Err(io_err(
            "joining a pairprobe task",
            std::io::Error::other(error.to_string()),
        )),
    }
}

fn local_unspecified(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

#[derive(Default)]
struct FlowAccum {
    sent_at: Vec<Instant>,
    rtt: Vec<Option<Duration>>,
}

fn lock_state(state: &Mutex<FlowAccum>) -> MutexGuard<'_, FlowAccum> {
    state.lock().unwrap_or_else(|poison| poison.into_inner())
}

fn note_echo(state: &Mutex<FlowAccum>, seq: u64, recv_at: Instant, max_rtt: Option<Duration>) {
    let mut guard = lock_state(state);
    let Some(index) = usize::try_from(seq).ok() else {
        return;
    };
    let Some(sent) = guard.sent_at.get(index).copied() else {
        return;
    };
    let Some(slot) = guard.rtt.get_mut(index) else {
        return;
    };
    if slot.is_some() {
        return;
    }
    let rtt = recv_at.saturating_duration_since(sent);
    if let Some(max_rtt) = max_rtt {
        if rtt > max_rtt {
            return;
        }
    }
    *slot = Some(rtt);
}

fn probe_instant(
    start: Instant,
    stagger: Duration,
    flow: u8,
    seq: u64,
    interval: Duration,
) -> Result<Instant, BenchError> {
    let seq_u32 = u32::try_from(seq).map_err(|_| {
        BenchError::InvalidArguments("probe run exceeded the safety cap".to_owned())
    })?;
    let offset = stagger
        .saturating_mul(u32::from(flow))
        .saturating_add(interval.saturating_mul(seq_u32));
    start
        .checked_add(offset)
        .ok_or_else(|| BenchError::InvalidArguments("probe schedule overflowed".to_owned()))
}

struct ProbePlan {
    start: Instant,
    end: Instant,
    interval: Duration,
    stagger: Duration,
    size: usize,
    bytes_sent: Arc<AtomicU64>,
    bytes_recv: Arc<AtomicU64>,
}

async fn join_tasks(tasks: Vec<JoinHandle<Result<(), BenchError>>>) -> Result<(), BenchError> {
    let mut first_error = None;
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if first_error.is_none() => first_error = Some(error),
            Ok(Err(_)) => {}
            Err(error) if first_error.is_none() => {
                first_error = Some(io_err(
                    "joining a probe task",
                    std::io::Error::other(error.to_string()),
                ));
            }
            Err(_) => {}
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn send_udp(
    socket: Arc<UdpSocket>,
    flow: u8,
    state: Arc<Mutex<FlowAccum>>,
    plan: &ProbePlan,
) -> Result<(), BenchError> {
    let mut payload = vec![0u8; plan.size];
    let mut seq = 0u64;
    loop {
        let when = probe_instant(plan.start, plan.stagger, flow, seq, plan.interval)?;
        if when >= plan.end {
            return Ok(());
        }
        sleep_until(when).await;
        let now = Instant::now();
        let send_us = u64::try_from(now.saturating_duration_since(plan.start).as_micros())
            .unwrap_or(u64::MAX);
        encode_probe(&mut payload, flow, seq, send_us);
        {
            let mut guard = lock_state(&state);
            guard.sent_at.push(now);
            guard.rtt.push(None);
        }
        socket
            .send(&payload)
            .await
            .map_err(|source| io_err("sending a UDP probe", source))?;
        plan.bytes_sent
            .fetch_add(plan.size as u64, Ordering::Relaxed);
        seq += 1;
        if seq > MAX_PROBES {
            return Err(BenchError::InvalidArguments(
                "probe run exceeded the safety cap".to_owned(),
            ));
        }
    }
}

async fn recv_udp(
    socket: Arc<UdpSocket>,
    flow: u8,
    state: Arc<Mutex<FlowAccum>>,
    stop: Instant,
    bytes_recv: Arc<AtomicU64>,
) -> Result<(), BenchError> {
    let mut buf = vec![0u8; 2048];
    loop {
        if Instant::now() >= stop {
            return Ok(());
        }
        let remaining = stop.saturating_duration_since(Instant::now());
        match timeout(remaining, socket.recv(&mut buf)).await {
            Err(_) => return Ok(()),
            Ok(Err(source)) => return Err(io_err("receiving a UDP echo", source)),
            Ok(Ok(n)) => {
                bytes_recv.fetch_add(n as u64, Ordering::Relaxed);
                if let Some((got_flow, seq, _)) = decode_probe(&buf[..n]) {
                    if got_flow == flow {
                        note_echo(&state, seq, Instant::now(), Some(LOSS_TIMEOUT));
                    }
                }
            }
        }
    }
}

async fn drive_udp(
    sockets: Vec<Arc<UdpSocket>>,
    states: Vec<Arc<Mutex<FlowAccum>>>,
    plan: Arc<ProbePlan>,
) -> Result<Vec<Vec<Option<Duration>>>, BenchError> {
    let stop = plan.end + LOSS_TIMEOUT;
    let mut sends = Vec::new();
    let mut recvs = Vec::new();
    for (index, socket) in sockets.into_iter().enumerate() {
        let flow = u8::try_from(index).expect("flow id fits in u8");
        let state = Arc::clone(&states[index]);
        let recv_state = Arc::clone(&state);
        let recv_socket = Arc::clone(&socket);
        let bytes_recv = Arc::clone(&plan.bytes_recv);
        recvs.push(tokio::spawn(async move {
            recv_udp(recv_socket, flow, recv_state, stop, bytes_recv).await
        }));
        let plan = Arc::clone(&plan);
        sends.push(tokio::spawn(async move {
            send_udp(socket, flow, state, &plan).await
        }));
    }
    if let Err(error) = join_tasks(sends).await {
        for task in &recvs {
            task.abort();
        }
        return Err(error);
    }
    join_tasks(recvs).await?;
    Ok(states
        .iter()
        .map(|state| lock_state(state).rtt.clone())
        .collect())
}

async fn connect_tcp(server: SocketAddr) -> Result<TcpStream, BenchError> {
    let stream = TcpStream::connect(server)
        .await
        .map_err(|source| io_err(format!("connecting TCP to {server}"), source))?;
    stream
        .set_nodelay(true)
        .map_err(|source| io_err("enabling TCP_NODELAY", source))?;
    Ok(stream)
}

async fn read_frame(reader: &mut OwnedReadHalf) -> Result<Option<Vec<u8>>, BenchError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(source) => return Err(io_err("reading a TCP echo length", source)),
    }
    let n = u32::from_be_bytes(len_buf) as usize;
    if n > TCP_RECORD_CAP {
        return Err(BenchError::InvalidArguments(format!(
            "TCP echo of {n} bytes exceeds {TCP_RECORD_CAP}"
        )));
    }
    let mut payload = vec![0u8; n];
    match reader.read_exact(&mut payload).await {
        Ok(_) => Ok(Some(payload)),
        Err(source) if source.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(source) => Err(io_err("reading a TCP echo", source)),
    }
}

async fn send_tcp(
    mut writer: OwnedWriteHalf,
    flow: u8,
    state: Arc<Mutex<FlowAccum>>,
    plan: &ProbePlan,
) -> Result<(), BenchError> {
    let mut frame = vec![0u8; 4 + plan.size];
    let len = u32::try_from(plan.size).map_err(|_| {
        BenchError::InvalidArguments("probe size does not fit a length prefix".to_owned())
    })?;
    frame[..4].copy_from_slice(&len.to_be_bytes());
    let mut seq = 0u64;
    loop {
        let when = probe_instant(plan.start, plan.stagger, flow, seq, plan.interval)?;
        if when >= plan.end {
            return Ok(());
        }
        sleep_until(when).await;
        let now = Instant::now();
        let send_us = u64::try_from(now.saturating_duration_since(plan.start).as_micros())
            .unwrap_or(u64::MAX);
        encode_probe(&mut frame[4..], flow, seq, send_us);
        {
            let mut guard = lock_state(&state);
            guard.sent_at.push(now);
            guard.rtt.push(None);
        }
        writer
            .write_all(&frame)
            .await
            .map_err(|source| io_err("sending a TCP probe", source))?;
        plan.bytes_sent
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
        seq += 1;
        if seq > MAX_PROBES {
            return Err(BenchError::InvalidArguments(
                "probe run exceeded the safety cap".to_owned(),
            ));
        }
    }
}

async fn recv_tcp(
    mut reader: OwnedReadHalf,
    flow: u8,
    state: Arc<Mutex<FlowAccum>>,
    stop: Instant,
    bytes_recv: Arc<AtomicU64>,
) -> Result<(), BenchError> {
    loop {
        if Instant::now() >= stop {
            return Ok(());
        }
        let remaining = stop.saturating_duration_since(Instant::now());
        match timeout(remaining, read_frame(&mut reader)).await {
            Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(payload))) => {
                bytes_recv.fetch_add(4 + payload.len() as u64, Ordering::Relaxed);
                if let Some((got_flow, seq, _)) = decode_probe(&payload) {
                    if got_flow == flow {
                        // No per-echo cap: a stall can outlast the UDP loss timeout,
                        // and the read loop already stops at `stop`.
                        note_echo(&state, seq, Instant::now(), None);
                    }
                }
            }
        }
    }
}

async fn drive_tcp(
    streams: Vec<TcpStream>,
    states: Vec<Arc<Mutex<FlowAccum>>>,
    plan: Arc<ProbePlan>,
) -> Result<Vec<Vec<Option<Duration>>>, BenchError> {
    let stop = plan.end + LOSS_TIMEOUT;
    let mut sends = Vec::new();
    let mut recvs = Vec::new();
    for (index, stream) in streams.into_iter().enumerate() {
        let flow = u8::try_from(index).expect("flow id fits in u8");
        let (reader, writer) = stream.into_split();
        let state = Arc::clone(&states[index]);
        let recv_state = Arc::clone(&state);
        let bytes_recv = Arc::clone(&plan.bytes_recv);
        recvs.push(tokio::spawn(async move {
            recv_tcp(reader, flow, recv_state, stop, bytes_recv).await
        }));
        let plan = Arc::clone(&plan);
        sends.push(tokio::spawn(async move {
            send_tcp(writer, flow, state, &plan).await
        }));
    }
    if let Err(error) = join_tasks(sends).await {
        for task in &recvs {
            task.abort();
        }
        return Err(error);
    }
    join_tasks(recvs).await?;
    Ok(states
        .iter()
        .map(|state| lock_state(state).rtt.clone())
        .collect())
}

async fn probe(options: &ClientOptions) -> Result<Report, BenchError> {
    validate_client(options)?;
    let flow_count = usize::try_from(options.flows).unwrap_or(usize::MAX);
    let mut udp_sockets = Vec::with_capacity(flow_count);
    let mut tcp_streams = Vec::with_capacity(flow_count);
    for _ in 0..flow_count {
        let socket = UdpSocket::bind(local_unspecified(options.server))
            .await
            .map_err(|source| io_err("binding a UDP probe socket", source))?;
        socket
            .connect(options.server)
            .await
            .map_err(|source| io_err(format!("connecting UDP to {}", options.server), source))?;
        udp_sockets.push(Arc::new(socket));
        tcp_streams.push(connect_tcp(options.server).await?);
    }
    let udp_states = (0..flow_count)
        .map(|_| Arc::new(Mutex::new(FlowAccum::default())))
        .collect::<Vec<_>>();
    let tcp_states = (0..flow_count)
        .map(|_| Arc::new(Mutex::new(FlowAccum::default())))
        .collect::<Vec<_>>();
    // One start instant so UDP and TCP share a grid. `end` is that instant
    // plus the run, not a second call to `Instant::now()`.
    let start = Instant::now() + Duration::from_millis(30);
    let plan = Arc::new(ProbePlan {
        start,
        end: start + Duration::from_secs(options.seconds),
        interval: send_interval(options.pps),
        stagger: Duration::from_millis(options.stagger_ms),
        size: options.size,
        bytes_sent: Arc::new(AtomicU64::new(0)),
        bytes_recv: Arc::new(AtomicU64::new(0)),
    });
    let udp_plan = Arc::clone(&plan);
    let tcp_plan = Arc::clone(&plan);
    let (udp, tcp) = tokio::try_join!(
        drive_udp(udp_sockets, udp_states, udp_plan),
        drive_tcp(tcp_streams, tcp_states, tcp_plan),
    )?;
    Ok(build_report(ReportParts {
        pps: options.pps,
        size: options.size,
        seconds: options.seconds,
        stagger_ms: options.stagger_ms,
        interval: plan.interval,
        udp: &udp,
        tcp: &tcp,
        bytes_sent: plan.bytes_sent.load(Ordering::Relaxed),
        bytes_received: plan.bytes_recv.load(Ordering::Relaxed),
    }))
}

fn emit(options: &ClientOptions, report: &Report) -> Result<(), BenchError> {
    let json = report.to_json();
    match &options.out {
        Some(path) => {
            std::fs::write(path, json.as_bytes())
                .map_err(|source| io_err(format!("writing {}", path.display()), source))?;
        }
        None => println!("{json}"),
    }
    eprint!("{}", report.human());
    Ok(())
}

pub async fn run(command: PairProbeCommand) -> Result<(), BenchError> {
    match command {
        PairProbeCommand::Server(options) => {
            let (tcp, udp, addr) = bind_server(options.listen).await?;
            eprintln!("pairprobe server listening on {addr} (udp and tcp)");
            serve(tcp, udp, options.max_seconds, options.max_bytes).await
        }
        PairProbeCommand::Client(options) => {
            let report = probe(&options).await?;
            emit(&options, &report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bernoulli(seed: u64, n: usize, p: f64) -> Vec<Option<Duration>> {
        let mut rng = crate::impair::Rng::new(seed);
        (0..n)
            .map(|_| {
                if rng.next_f64() < p {
                    None
                } else {
                    Some(Duration::from_millis(1))
                }
            })
            .collect()
    }

    #[test]
    fn burst_histogram_matches_hand_built_runs() {
        // Runs of 1, 2, 3, 4, 5, 9 and a trailing 6, separated by receipts.
        let runs = [1usize, 2, 3, 4, 5, 9, 6];
        let mut samples = Vec::new();
        for (index, run) in runs.iter().enumerate() {
            for _ in 0..*run {
                samples.push(None);
            }
            if index + 1 != runs.len() {
                samples.push(Some(Duration::from_millis(5)));
            }
        }
        let hist = burst_histogram(&samples);
        assert_eq!(
            hist,
            BurstHistogram {
                len_1: 1,
                len_2: 1,
                len_3: 1,
                len_4: 1,
                len_5_to_8: 2,
                len_9_plus: 1,
            }
        );
        let interval = Duration::from_millis(20);
        let stats = udp_flow_stats(0, &samples, interval);
        // Span is (length - 1) intervals: 0, 20, 40, 60, 80, 160, 100 ms.
        assert!((stats.burst_p50_ms.unwrap() - 60.0).abs() < 1e-9);
        assert!((stats.burst_p99_ms.unwrap() - 160.0).abs() < 1e-9);
        assert!((stats.burst_max_ms.unwrap() - 160.0).abs() < 1e-9);
    }

    #[test]
    fn fully_correlated_flows_have_conditional_loss_one() {
        let pattern: Vec<Option<Duration>> = (0..90)
            .map(|index| {
                if index % 3 == 0 {
                    None
                } else {
                    Some(Duration::from_millis(5))
                }
            })
            .collect();
        let pair = pair_loss(0, 1, &pattern, &pattern, Duration::from_millis(20));
        assert_eq!(pair.cond[0].probability, Some(1.0));
        assert!((pair.p_both - pair.p_loss_a).abs() < 1e-12);
        assert!((pair.independent_expectation - pair.p_loss_b).abs() < 1e-12);
        assert_eq!(pair.cond[1].requested_lag_ms, 10);
        assert!((pair.cond[1].lag_ms - 20.0).abs() < 1e-9);
        assert_eq!(pair.cond.len(), COND_LAGS_MS.len());
    }

    #[test]
    fn independent_flows_match_the_marginal_loss() {
        let a = bernoulli(1, 20_000, 0.15);
        let b = bernoulli(2, 20_000, 0.15);
        let pair = pair_loss(0, 1, &a, &b, Duration::from_millis(33));
        let cond = pair.cond[0].probability.expect("flow A has losses");
        assert!(
            (cond - 0.15).abs() < 0.05,
            "cond[0]={cond} independent={}",
            pair.independent_expectation
        );
    }

    #[test]
    fn tcp_stall_overlap_uses_each_flows_own_minimum() {
        let fast = Duration::from_millis(10);
        let slow = Duration::from_millis(300);
        let slower = Duration::from_millis(400);
        let a = vec![Some(fast), Some(slow), Some(fast), Some(slower)];
        let b = vec![Some(fast), Some(slow), Some(fast), Some(fast)];
        let stats = tcp_flow_stats(0, &a);
        assert_eq!(stats.stalls, 2);
        assert_eq!(stats.stall_p50, Some(Duration::from_millis(290)));
        assert_eq!(stats.stall_max, Some(Duration::from_millis(390)));
        assert_eq!(tcp_stall_overlap(&a, &b), Some(0.5));
    }

    #[test]
    fn probe_codec_roundtrip() {
        let mut buf = vec![0u8; 100];
        encode_probe(&mut buf, 3, 0x0102_0304_0506_0708, 42);
        assert_eq!(decode_probe(&buf), Some((3, 0x0102_0304_0506_0708, 42)));
        assert!(decode_probe(&buf[..20]).is_none());
        assert!(buf[21..].iter().all(|byte| *byte == 0));
        buf[0] = 0;
        assert!(decode_probe(&buf).is_none());
    }

    #[test]
    fn late_echo_and_duplicate_are_ignored() {
        let sent = Instant::now();
        let state = Mutex::new(FlowAccum {
            sent_at: vec![sent, sent],
            rtt: vec![None, Some(Duration::from_millis(10))],
        });
        note_echo(&state, 0, sent + Duration::from_secs(4), Some(LOSS_TIMEOUT));
        note_echo(
            &state,
            1,
            sent + Duration::from_millis(12),
            Some(LOSS_TIMEOUT),
        );
        let guard = lock_state(&state);
        assert!(guard.rtt[0].is_none());
        assert_eq!(guard.rtt[1], Some(Duration::from_millis(10)));
    }

    #[test]
    fn json_report_parses_and_carries_pair_fields() {
        let udp_a = vec![None, Some(Duration::from_micros(1000)), None];
        let udp_b = vec![
            None,
            Some(Duration::from_micros(1500)),
            Some(Duration::from_micros(1100)),
        ];
        let tcp_a = vec![
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(300)),
        ];
        let tcp_b = vec![
            Some(Duration::from_millis(10)),
            Some(Duration::from_millis(300)),
        ];
        let report = build_report(ReportParts {
            pps: 50,
            size: 100,
            seconds: 5,
            stagger_ms: 0,
            interval: Duration::from_millis(20),
            udp: &[udp_a, udp_b],
            tcp: &[tcp_a, tcp_b],
            bytes_sent: 1000,
            bytes_received: 800,
        });
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["udp"]["flows"][0]["lost"], 2);
        assert_eq!(
            value["udp"]["pairs"][0]["independent_expectation"],
            value["udp"]["pairs"][0]["p_loss_b"]
        );
        let cond0 = value["udp"]["pairs"][0]["cond"][0]["p"].as_f64().unwrap();
        assert!((cond0 - 0.5).abs() < 1e-6);
        assert_eq!(value["bytes_sent"], 1000);
        assert_eq!(value["bytes_received"], 800);
        assert!(value["tcp"]["pairs"][0]["stall_overlap"].as_f64().unwrap() > 0.0);
        assert!(report.human().contains("independent="));
    }

    #[test]
    fn parse_rejects_a_heavy_client_and_accepts_defaults() {
        let heavy = ["client", "--server", "127.0.0.1:9", "--pps", "201"].map(str::to_owned);
        assert!(parse_args(&heavy).is_err());
        let big = ["client", "--server", "127.0.0.1:9", "--size", "1201"].map(str::to_owned);
        assert!(parse_args(&big).is_err());
        let tiny = ["client", "--server", "127.0.0.1:9", "--size", "20"].map(str::to_owned);
        assert!(parse_args(&tiny).is_err());
        let ok = ["client", "--server", "127.0.0.1:9"].map(str::to_owned);
        let PairProbeCommand::Client(options) = parse_args(&ok).unwrap() else {
            panic!("client command");
        };
        assert_eq!(options.pps, DEFAULT_PPS);
        assert_eq!(options.size, DEFAULT_SIZE);
        assert_eq!(options.seconds, DEFAULT_SECONDS);
        assert_eq!(options.flows, DEFAULT_FLOWS);
        assert_eq!(options.stagger_ms, 0);
    }

    #[test]
    fn pairprobe_registers_as_a_command() {
        let args = [
            "segue-bench",
            "pairprobe",
            "server",
            "--listen",
            "127.0.0.1:9",
        ];
        match crate::parse_cli_args(args).unwrap() {
            crate::CliArgs::PairProbe(PairProbeCommand::Server(options)) => {
                assert_eq!(options.max_seconds, DEFAULT_MAX_SECONDS);
                assert_eq!(options.max_bytes, DEFAULT_MAX_BYTES);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Down-direction seed mix in `impair::relay_udp_client`.
    const IMPAIR_DOWN_SEED: u64 = 0x5DEE_CE66_D1CE_4E5B;
    const IMPAIR_SEED: u64 = 0xC163_5EED;

    fn simulated_echo_losses(seed: u64, packets: usize) -> usize {
        let profile = crate::impair::profile("cn163-peak").unwrap();
        let mut up = crate::impair::Shaper::new(profile.clone(), seed);
        let mut down = crate::impair::Shaper::new(profile, seed ^ IMPAIR_DOWN_SEED);
        let now = Instant::now();
        let mut lost = 0usize;
        for _ in 0..packets {
            if up.schedule(now, 100).is_none() {
                lost += 1;
                continue;
            }
            if down.schedule(now, 100).is_none() {
                lost += 1;
            }
        }
        lost
    }

    #[test]
    fn cn163_peak_echo_loss_tracks_steady_state() {
        let profile = crate::impair::profile("cn163-peak").unwrap();
        let p = profile.steady_state_loss();
        let packets = 20_000usize;
        let observed = simulated_echo_losses(IMPAIR_SEED, packets) as f64 / packets as f64;
        let round_trip = 1.0 - (1.0 - p) * (1.0 - p);
        assert!(
            (observed - round_trip).abs() <= 0.04,
            "simulated echo loss {observed} vs round-trip {round_trip} (one-way {p})"
        );
        let mut shaper = crate::impair::Shaper::new(profile, IMPAIR_SEED);
        let now = Instant::now();
        let one_way = (0..packets)
            .filter(|_| shaper.schedule(now, 100).is_none())
            .count() as f64
            / packets as f64;
        assert!(
            (one_way - p).abs() <= 0.04,
            "one-way {one_way} vs steady_state_loss {p}"
        );
    }

    struct Abort(JoinHandle<Result<(), BenchError>>);

    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn wait_impair(listen: SocketAddr, task: &JoinHandle<Result<(), BenchError>>) -> bool {
        for _ in 0..40 {
            if task.is_finished() {
                return false;
            }
            match timeout(Duration::from_millis(50), TcpStream::connect(listen)).await {
                Ok(Ok(_)) => return true,
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        !task.is_finished()
    }

    async fn start_impair(upstream: SocketAddr) -> Result<(SocketAddr, Abort), BenchError> {
        for _ in 0..40 {
            let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|source| io_err("reserving an impair port", source))?;
            let port = reserved
                .local_addr()
                .map_err(|source| io_err("reading the reserved impair port", source))?
                .port();
            let udp_ok = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok();
            drop(reserved);
            if !udp_ok {
                continue;
            }
            let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let options = crate::impair::ImpairOptions {
                listen,
                upstream,
                profile: crate::impair::profile("cn163-peak").expect("cn163-peak"),
                seed: IMPAIR_SEED,
                udp: true,
                tcp: true,
                duration: Some(Duration::from_secs(30)),
                tcp_loss: crate::impair::TcpLoss::Off,
            };
            let task = tokio::spawn(crate::impair::run(options));
            if wait_impair(listen, &task).await {
                return Ok((listen, Abort(task)));
            }
        }
        Err(BenchError::InvalidArguments(
            "could not bind an impair relay".to_owned(),
        ))
    }

    async fn wait_udp_echo(server: SocketAddr) -> Result<(), BenchError> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|source| io_err("binding the warmup socket", source))?;
        let payload = b"warmup";
        let mut buf = [0u8; 64];
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            socket
                .send_to(payload, server)
                .await
                .map_err(|source| io_err("sending a warmup probe", source))?;
            if let Ok(Ok(_)) = timeout(Duration::from_millis(200), socket.recv(&mut buf)).await {
                return Ok(());
            }
        }
        Err(BenchError::InvalidArguments(
            "impair UDP relay did not echo".to_owned(),
        ))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn max_bytes_stops_the_server() {
        let (tcp, udp, addr) = bind_server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let mut server = Abort(tokio::spawn(async move { serve(tcp, udp, 30, 250).await }));
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let payload = [7u8; 100];
        let mut buf = [0u8; 128];
        let mut echoed = 0u32;
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if server.0.is_finished() {
                break;
            }
            socket.send_to(&payload, addr).await.unwrap();
            if let Ok(Ok(_)) = timeout(Duration::from_millis(50), socket.recv(&mut buf)).await {
                echoed += 1;
            }
        }
        assert!(echoed >= 1, "server echoed nothing");
        let joined = timeout(Duration::from_secs(2), &mut server.0)
            .await
            .expect("server did not stop on --max-bytes");
        assert!(joined.unwrap().is_ok());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_cn163_peak_loss_matches_the_relay() {
        let (tcp, udp, server_addr) = bind_server(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let _server = Abort(tokio::spawn(async move {
            serve(tcp, udp, 30, DEFAULT_MAX_BYTES).await
        }));
        let (impair_addr, _impair) = start_impair(server_addr).await.unwrap();
        wait_udp_echo(impair_addr).await.unwrap();
        let report = probe(&ClientOptions {
            server: impair_addr,
            pps: 50,
            size: 100,
            seconds: 5,
            flows: 2,
            stagger_ms: 0,
            out: None,
        })
        .await
        .unwrap();

        let profile = crate::impair::profile("cn163-peak").unwrap();
        let p = profile.steady_state_loss();
        let round_trip = 1.0 - (1.0 - p) * (1.0 - p);
        assert_eq!(report.udp_flows.len(), 2);
        for flow in &report.udp_flows {
            assert!(
                (200..280).contains(&flow.sent),
                "flow {} sent {}",
                flow.id,
                flow.sent
            );
            let expected = simulated_echo_losses(IMPAIR_SEED, flow.sent) as f64 / flow.sent as f64;
            assert!(
                (flow.loss_rate - expected).abs() <= 0.04,
                "flow {} loss {} simulated {} sent {} lost {} profile {} round_trip {}",
                flow.id,
                flow.loss_rate,
                expected,
                flow.sent,
                flow.lost,
                p,
                round_trip
            );
            // Echoes cross the relay twice, so the long-run rate is the round
            // trip, not the one-way `steady_state_loss`. 250 bursty packets can
            // sit outside 4 points of either; the long sample is
            // `cn163_peak_echo_loss_tracks_steady_state`. Require the live run
            // to be in that neighbourhood so a relay that drops nothing fails.
            assert!(
                (flow.loss_rate - p).abs() <= 0.04 || (flow.loss_rate - round_trip).abs() <= 0.04,
                "flow {} loss {} not within 4 points of one-way {} or round-trip {}",
                flow.id,
                flow.loss_rate,
                p,
                round_trip
            );
        }
        assert!(!report.tcp_flows.is_empty());
        assert!(report.tcp_flows[0].sent >= 200);
        assert!(report.bytes_sent > 0);
        assert!(report.bytes_received > 0);
    }
}
