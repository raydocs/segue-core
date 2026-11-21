//! Additive per-session unreliable UDP datagram accelerator (`S1–S4`).
//!
//! Keeps the reliable stream carrier as the sole source of truth:
//! - Only activates for [`crate::EXIT_CLASS_AI`] (unless `ai_only == false`)
//!   when [`DgramConfig::enabled`] is true.
//! - Mirrors small frames (`<= max_frame_bytes`) across up to `K=2` UDP flows,
//!   piggybacking up to `N=2` unacked small frames per datagram (`N=4` when
//!   `K=1`), bounded by [`DGRAM_MAX_BYTES`] (`1200 B`).
//! - Never duplicates bulk frames (`> max_frame_bytes`); waits for bulk
//!   acknowledgement (`bulk_barrier`) so bulk tails never leap ahead.
//! - Enforces hard TX byte/packet rate caps with `N`-first then `K` shedding.
//! - Pauses UDP emission upon blackout (zero UDP progress across several
//!   retransmission intervals while the reliable carrier advances) and probes
//!   periodically until recovery.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::codec::{get_varint, put_varint, varint_len, DgramNonce, SessionId, VARINT_MAX};
use crate::flow::{RecvHalf, SendHalf};

/// Maximum encoded datagram size including the 36-byte session header.
pub const DGRAM_MAX_BYTES: usize = 1200;
/// Fixed header size: `session_id (16) + attach_gen (4 BE) + nonce (16)`.
pub const DGRAM_HEADER_BYTES: usize = 36;
/// Fixed body preamble: `pkt_type (1) + flags (1) + count (1)`.
pub const DGRAM_BODY_HEADER_BYTES: usize = 3;
const DGRAM_MAX_SACKS: usize = 16;
const DGRAM_MAX_TRACKED: usize = 64;
const DGRAM_MAX_RETX: u32 = 16;
const DGRAM_MAX_FIN_RETX: u8 = 4;

pub const PKT_DATA: u8 = 1;
pub const PKT_ACK: u8 = 2;
pub const PKT_FIN: u8 = 3;

pub const FLAG_PROBE: u8 = 0x01;
pub const FLAG_BIND: u8 = 0x02;

const RETX_MIN: Duration = Duration::from_millis(60);
const RETX_MAX: Duration = Duration::from_secs(1);
const SRTT_MIN: Duration = Duration::from_millis(10);
const SRTT_MAX: Duration = Duration::from_secs(2);

/// Configuration for the optional per-session UDP datagram accelerator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DgramConfig {
    /// Disabled by default until enabled by config/kernel/relay wiring.
    pub enabled: bool,
    /// When `true` (default), accelerate only [`crate::EXIT_CLASS_AI`] sessions.
    pub ai_only: bool,
    /// Largest small-frame `DATA` payload eligible for UDP transmission.
    pub max_frame_bytes: usize,
    /// Target number of independent UDP flows (`1` or `2`; clamped to `1..=2`).
    pub flows: u8,
    /// Piggyback depth `N` when `K >= 2` active UDP flows exist.
    pub piggyback_k2: usize,
    /// Fallback piggyback depth `N` when only `K == 1` active UDP flow exists.
    pub piggyback_k1: usize,
    /// Per-session accelerator TX byte rate ceiling (bytes/sec).
    pub max_bytes_per_sec: u32,
    /// Per-session accelerator TX packet rate ceiling (packets/sec).
    pub max_packets_per_sec: u32,
    /// Initial RTT seed before the first UDP ACK sample arrives.
    pub initial_rtt: Duration,
    /// Consecutive `retx_after` intervals with UDP silence while the reliable
    /// carrier advances before pausing UDP acceleration.
    pub blackout_retx_intervals: u32,
    /// Interval between probe packets while paused due to UDP blackout.
    pub blackout_probe_interval: Duration,
}

impl Default for DgramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ai_only: true,
            max_frame_bytes: 1024,
            flows: 2,
            piggyback_k2: 2,
            piggyback_k1: 4,
            max_bytes_per_sec: 32 * 1024,
            max_packets_per_sec: 200,
            initial_rtt: Duration::from_millis(170),
            blackout_retx_intervals: 4,
            blackout_probe_interval: Duration::from_secs(10),
        }
    }
}

impl DgramConfig {
    /// Default configuration enabled for AI sessions.
    pub fn for_ai_default() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }

    pub fn enabled_for(&self, exit_class: u8) -> bool {
        self.enabled && (!self.ai_only || exit_class == crate::EXIT_CLASS_AI)
    }

    pub fn max_flows(&self) -> usize {
        usize::from(self.flows.clamp(1, 2))
    }

    fn piggyback_for(&self, active_flows: usize) -> usize {
        if active_flows >= 2 {
            self.piggyback_k2.max(1)
        } else {
            self.piggyback_k1.max(1)
        }
    }
}

/// Per-session UDP datagram accelerator counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DgramStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped_bad: u64,
    pub rx_delivered_bytes: u64,
    pub retx_packets: u64,
    pub shed_n: u64,
    pub shed_k: u64,
    pub shed_suppressed: u64,
    pub blackout_pauses: u64,
    pub blackout_recoveries: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DgramHeader {
    pub session_id: SessionId,
    pub attach_gen: u32,
    pub nonce: DgramNonce,
}

impl std::fmt::Debug for DgramHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DgramHeader")
            .field("session_id", &self.session_id)
            .field("attach_gen", &self.attach_gen)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DgramBody {
    Data(Vec<(u64, Vec<u8>)>),
    Ack {
        recv_offset: u64,
        max_offset: u64,
        sacks: Vec<u64>,
        flags: u8,
    },
    Fin {
        offset: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DgramPacket {
    pub header: DgramHeader,
    pub body: DgramBody,
}

#[inline]
fn put_header(out: &mut Vec<u8>, h: DgramHeader) {
    out.extend_from_slice(&h.session_id);
    out.extend_from_slice(&h.attach_gen.to_be_bytes());
    out.extend_from_slice(&h.nonce);
}

#[inline]
fn entry_wire_len(offset: u64, len: usize) -> usize {
    varint_len(offset) + varint_len(len as u64) + len
}

/// Fast-path header parser for authentication and flow lookup before parsing body.
pub fn decode_dgram_header(buf: &[u8]) -> Option<DgramHeader> {
    if buf.len() < DGRAM_HEADER_BYTES || buf.len() > DGRAM_MAX_BYTES {
        return None;
    }
    let session_id: SessionId = buf[0..16].try_into().ok()?;
    let attach_gen = u32::from_be_bytes(buf[16..20].try_into().ok()?);
    let nonce: DgramNonce = buf[20..36].try_into().ok()?;
    Some(DgramHeader {
        session_id,
        attach_gen,
        nonce,
    })
}

/// Encode `pkt` into `out`, returning `false` if it exceeds [`DGRAM_MAX_BYTES`].
pub fn encode_dgram_packet(pkt: &DgramPacket, out: &mut Vec<u8>) -> bool {
    let start = out.len();
    out.reserve(128);
    put_header(out, pkt.header);
    match &pkt.body {
        DgramBody::Data(entries) => {
            if entries.is_empty() || entries.len() > usize::from(u8::MAX) {
                out.truncate(start);
                return false;
            }
            out.push(PKT_DATA);
            out.push(0);
            out.push(entries.len() as u8);
            for (offset, data) in entries {
                if data.is_empty()
                    || offset
                        .checked_add(data.len() as u64)
                        .is_none_or(|e| e > VARINT_MAX)
                {
                    out.truncate(start);
                    return false;
                }
                put_varint(out, *offset);
                put_varint(out, data.len() as u64);
                out.extend_from_slice(data);
            }
        }
        DgramBody::Ack {
            recv_offset,
            max_offset,
            sacks,
            flags,
        } => {
            if sacks.len() > DGRAM_MAX_SACKS
                || *recv_offset > VARINT_MAX
                || *max_offset > VARINT_MAX
                || sacks.iter().any(|&s| s > VARINT_MAX)
            {
                out.truncate(start);
                return false;
            }
            out.push(PKT_ACK);
            out.push(*flags);
            out.push(sacks.len() as u8);
            put_varint(out, *recv_offset);
            put_varint(out, *max_offset);
            for &s in sacks {
                put_varint(out, s);
            }
        }
        DgramBody::Fin { offset } => {
            if *offset > VARINT_MAX {
                out.truncate(start);
                return false;
            }
            out.push(PKT_FIN);
            out.push(0);
            out.push(0);
            put_varint(out, *offset);
        }
    }
    if out.len() - start > DGRAM_MAX_BYTES {
        out.truncate(start);
        return false;
    }
    true
}

/// Decode a datagram packet, returning `None` on any size or structural mismatch.
pub fn decode_dgram_packet(buf: &[u8]) -> Option<DgramPacket> {
    if buf.len() < DGRAM_HEADER_BYTES + DGRAM_BODY_HEADER_BYTES || buf.len() > DGRAM_MAX_BYTES {
        return None;
    }
    let header = decode_dgram_header(buf)?;
    let pkt_type = buf[36];
    let flags = buf[37];
    let count = usize::from(buf[38]);
    let mut rest = &buf[39..];
    let take_varint = |r: &mut &[u8]| -> Option<u64> {
        let (v, n) = get_varint(r)?;
        *r = &r[n..];
        Some(v)
    };
    let body = match pkt_type {
        PKT_DATA => {
            if count == 0 {
                return None;
            }
            let mut entries = Vec::with_capacity(count.min(8));
            for _ in 0..count {
                let offset = take_varint(&mut rest)?;
                let len = usize::try_from(take_varint(&mut rest)?).ok()?;
                if len == 0
                    || rest.len() < len
                    || offset
                        .checked_add(len as u64)
                        .is_none_or(|e| e > VARINT_MAX)
                {
                    return None;
                }
                let (bytes, tail) = rest.split_at(len);
                rest = tail;
                entries.push((offset, bytes.to_vec()));
            }
            DgramBody::Data(entries)
        }
        PKT_ACK => {
            if count > DGRAM_MAX_SACKS {
                return None;
            }
            let recv_offset = take_varint(&mut rest)?;
            let max_offset = take_varint(&mut rest)?;
            let mut sacks = Vec::with_capacity(count);
            for _ in 0..count {
                sacks.push(take_varint(&mut rest)?);
            }
            DgramBody::Ack {
                recv_offset,
                max_offset,
                sacks,
                flags,
            }
        }
        PKT_FIN => {
            if count != 0 {
                return None;
            }
            let offset = take_varint(&mut rest)?;
            DgramBody::Fin { offset }
        }
        _ => return None,
    };
    if !rest.is_empty() {
        return None;
    }
    Some(DgramPacket { header, body })
}

fn encode_data_from_send(
    hdr: DgramHeader,
    send: &SendHalf,
    frames: &[(u64, usize)],
    out: &mut Vec<u8>,
) -> bool {
    let start = out.len();
    let count_limit = frames.len().min(usize::from(u8::MAX));
    if count_limit == 0 {
        return false;
    }
    out.reserve(DGRAM_MAX_BYTES);
    put_header(out, hdr);
    out.push(PKT_DATA);
    out.push(0);
    let count_idx = out.len();
    out.push(0);
    let mut actual_count = 0u8;
    for &(off, len) in &frames[..count_limit] {
        let Some((real_off, real_len)) = send.range_unacked_len(off, len) else {
            continue;
        };
        if real_len == 0 {
            continue;
        }
        let add = entry_wire_len(real_off, real_len);
        if (out.len() - start) + add > DGRAM_MAX_BYTES {
            if actual_count == 0 {
                out.truncate(start);
                return false;
            }
            break;
        }
        put_varint(out, real_off);
        put_varint(out, real_len as u64);
        let copied = send.copy_range(real_off, real_len, out);
        debug_assert_eq!(copied, Some((real_off, real_len)));
        actual_count += 1;
    }
    if actual_count == 0 {
        out.truncate(start);
        return false;
    }
    out[count_idx] = actual_count;
    true
}

#[derive(Clone, Copy, Debug)]
struct TrackedFrame {
    offset: u64,
    len: usize,
    first_sent: Instant,
    next_retx: Instant,
    retx_count: u32,
    sacked: bool,
}

impl TrackedFrame {
    fn end(&self) -> u64 {
        self.offset.saturating_add(self.len as u64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaveKind {
    New,
    Retx(u64),
}

#[derive(Debug)]
pub(crate) struct DgramAccel {
    pub cfg: DgramConfig,
    pub session_id: SessionId,
    pub attach_gen: u32,
    pub nonce: DgramNonce,
    pub bound: bool,
    unacked: VecDeque<TrackedFrame>,
    bulk_barrier: u64,
    fin_offset: Option<u64>,
    fin_pending: [bool; 2],
    fin_retx_at: Option<Instant>,
    fin_retx_count: u8,
    pub parked_fin: Option<u64>,
    srtt: Duration,
    byte_tokens_us: u128,
    pkt_tokens_us: u128,
    last_refill: Instant,
    wave_due: Option<WaveKind>,
    planned_data: [Vec<(u64, usize)>; 2],
    planned_is_retx: [bool; 2],
    pending_ack: [Option<u8>; 2],
    rr_flow: usize,
    paused: bool,
    tx_without_rx_since: Option<Instant>,
    reliable_progressed_since_tx: bool,
    next_probe: Option<Instant>,
    pub reliable_rx_hw: u64,
    pub reliable_ack_hw: u64,
    pub stats: DgramStats,
}

impl DgramAccel {
    pub fn new(
        cfg: DgramConfig,
        session_id: SessionId,
        attach_gen: u32,
        nonce: DgramNonce,
        now: Instant,
    ) -> Self {
        let byte_burst = Self::byte_burst(&cfg) * 1_000_000;
        let pkt_burst = Self::pkt_burst(&cfg) * 1_000_000;
        Self {
            srtt: cfg.initial_rtt.clamp(SRTT_MIN, SRTT_MAX),
            cfg,
            session_id,
            attach_gen,
            nonce,
            bound: false,
            unacked: VecDeque::new(),
            bulk_barrier: 0,
            fin_offset: None,
            fin_pending: [false; 2],
            fin_retx_at: None,
            fin_retx_count: 0,
            parked_fin: None,
            byte_tokens_us: byte_burst,
            pkt_tokens_us: pkt_burst,
            last_refill: now,
            wave_due: None,
            planned_data: [Vec::new(), Vec::new()],
            planned_is_retx: [false; 2],
            pending_ack: [None; 2],
            rr_flow: 0,
            paused: false,
            tx_without_rx_since: None,
            reliable_progressed_since_tx: false,
            next_probe: None,
            reliable_rx_hw: 0,
            reliable_ack_hw: 0,
            stats: DgramStats::default(),
        }
    }

    pub fn rearm_gen(
        &mut self,
        attach_gen: u32,
        nonce: DgramNonce,
        reliable_rx_hw: u64,
        reliable_ack_hw: u64,
        now: Instant,
    ) {
        self.attach_gen = attach_gen;
        self.nonce = nonce;
        self.bound = false;
        self.unacked.clear();
        self.bulk_barrier = 0;
        self.fin_offset = None;
        self.fin_pending = [false; 2];
        self.fin_retx_at = None;
        self.fin_retx_count = 0;
        self.parked_fin = None;
        self.wave_due = None;
        self.planned_data[0].clear();
        self.planned_data[1].clear();
        self.planned_is_retx = [false; 2];
        self.pending_ack = [None; 2];
        self.paused = false;
        self.tx_without_rx_since = None;
        self.reliable_progressed_since_tx = false;
        self.next_probe = None;
        self.reliable_rx_hw = reliable_rx_hw;
        self.reliable_ack_hw = reliable_ack_hw;
        self.last_refill = now;
        self.byte_tokens_us = Self::byte_burst(&self.cfg) * 1_000_000;
        self.pkt_tokens_us = Self::pkt_burst(&self.cfg) * 1_000_000;
    }

    #[inline]
    fn byte_burst(cfg: &DgramConfig) -> u128 {
        u128::from((cfg.max_bytes_per_sec / 8).max(2400))
    }

    #[inline]
    fn pkt_burst(cfg: &DgramConfig) -> u128 {
        u128::from((cfg.max_packets_per_sec / 10).max(4))
    }

    pub fn header(&self) -> DgramHeader {
        DgramHeader {
            session_id: self.session_id,
            attach_gen: self.attach_gen,
            nonce: self.nonce,
        }
    }

    pub fn retx_after(&self) -> Duration {
        (self.srtt * 3 / 2).clamp(RETX_MIN, RETX_MAX)
    }

    fn refill(&mut self, now: Instant) {
        let dt_us = now.saturating_duration_since(self.last_refill).as_micros();
        self.last_refill = self.last_refill.max(now);
        if dt_us == 0 {
            return;
        }
        let max_b = Self::byte_burst(&self.cfg) * 1_000_000;
        let max_p = Self::pkt_burst(&self.cfg) * 1_000_000;
        self.byte_tokens_us = self
            .byte_tokens_us
            .saturating_add(dt_us.saturating_mul(u128::from(self.cfg.max_bytes_per_sec)))
            .min(max_b);
        self.pkt_tokens_us = self
            .pkt_tokens_us
            .saturating_add(dt_us.saturating_mul(u128::from(self.cfg.max_packets_per_sec)))
            .min(max_p);
    }

    pub fn prune_acked(&mut self, acked: u64) {
        while self.unacked.front().is_some_and(|it| it.end() <= acked) {
            self.unacked.pop_front();
        }
        if acked >= self.bulk_barrier {
            self.bulk_barrier = 0;
        }
        if self.fin_offset.is_some_and(|f| acked > f) {
            self.fin_offset = None;
            self.fin_pending = [false; 2];
            self.fin_retx_at = None;
        }
    }

    pub fn on_reliable_progress(&mut self, acked: u64) {
        self.prune_acked(acked);
        if self.tx_without_rx_since.is_some() {
            self.reliable_progressed_since_tx = true;
        }
    }

    fn note_dgram_tx(&mut self, now: Instant, expects_ack: bool) {
        if expects_ack {
            self.tx_without_rx_since.get_or_insert(now);
        }
    }

    fn note_dgram_rx(&mut self) {
        self.tx_without_rx_since = None;
        self.reliable_progressed_since_tx = false;
        if self.paused {
            self.paused = false;
            self.next_probe = None;
            self.stats.blackout_recoveries += 1;
        }
    }

    pub fn queue_ack_flag(&mut self, flow: usize, flags: u8) {
        if flow < 2 {
            let slot = &mut self.pending_ack[flow];
            *slot = Some(slot.map_or(flags, |prev| prev | flags));
        }
    }

    /// Record a primary-carrier `DATA` emission for optional UDP acceleration.
    pub fn on_primary_data(
        &mut self,
        acked: u64,
        offset: u64,
        len: usize,
        active_flows: usize,
        now: Instant,
    ) {
        self.prune_acked(acked);
        if len == 0 {
            return;
        }
        let Some(end) = offset.checked_add(len as u64) else {
            return;
        };
        if end <= acked {
            return;
        }
        if len > self.cfg.max_frame_bytes {
            self.bulk_barrier = self.bulk_barrier.max(end);
            self.wave_due = None;
            self.planned_data[0].clear();
            self.planned_data[1].clear();
            return;
        }
        if acked < self.bulk_barrier {
            return;
        }
        let start = offset.max(acked);
        let Ok(slice_len) = usize::try_from(end - start) else {
            return;
        };
        if self
            .unacked
            .back()
            .is_some_and(|last| last.offset == start && last.len >= slice_len)
        {
            return;
        }
        if self.unacked.len() == DGRAM_MAX_TRACKED {
            self.unacked.pop_front();
        }
        self.unacked.push_back(TrackedFrame {
            offset: start,
            len: slice_len,
            first_sent: now,
            next_retx: now + self.retx_after(),
            retx_count: 0,
            sacked: false,
        });
        if self.bound && !self.paused && active_flows > 0 {
            self.wave_due = Some(WaveKind::New);
        }
    }

    /// Record a primary-carrier `FIN` emission for optional UDP acceleration.
    pub fn on_primary_fin(&mut self, offset: u64, active_flows: usize, now: Instant) {
        self.fin_offset = Some(offset);
        self.fin_retx_count = 0;
        self.fin_retx_at = Some(now + self.retx_after());
        if self.bound && !self.paused && active_flows > 0 {
            let cap = active_flows.min(self.cfg.max_flows());
            for flag in &mut self.fin_pending[..cap] {
                *flag = true;
            }
        }
    }

    /// Select up to `base_n` unacked frames and apply byte/packet rate caps
    /// with `N`-first then `K` shedding.
    fn resolve_wave(&mut self, kind: WaveKind, send: &SendHalf, active_flows: usize, now: Instant) {
        self.planned_data[0].clear();
        self.planned_data[1].clear();
        self.planned_is_retx = [false; 2];

        let avail = active_flows.min(self.cfg.max_flows());
        if !self.bound || self.paused || avail == 0 {
            return;
        }
        let base_n = self.cfg.piggyback_for(avail);
        let mut selected: Vec<(u64, usize)> = Vec::with_capacity(base_n);
        let mut include_tail_after_overdue: Option<usize> = None;

        if let WaveKind::Retx(target_off) = kind {
            // Ensure the overdue unsacked anchor item is included first.
            if let Some((idx, it)) = self
                .unacked
                .iter()
                .enumerate()
                .find(|(_, it)| it.offset == target_off && !it.sacked)
            {
                if let Some(pair) = send.range_unacked_len(it.offset, it.len) {
                    selected.push(pair);
                    include_tail_after_overdue = Some(idx);
                }
            }
        }
        // Append newest unacked unsacked entries (avoiding duplicates with overdue).
        for (idx, it) in self.unacked.iter().enumerate().rev() {
            if selected.len() >= base_n {
                break;
            }
            if include_tail_after_overdue == Some(idx) || it.sacked {
                continue;
            }
            if let Some(pair) = send.range_unacked_len(it.offset, it.len) {
                selected.push(pair);
            }
        }
        // Fallback if all entries are SACKed (only for New waves; Retx only resends unsacked).
        if selected.is_empty() && kind == WaveKind::New {
            for it in self.unacked.iter().rev() {
                if selected.len() >= base_n {
                    break;
                }
                if let Some(pair) = send.range_unacked_len(it.offset, it.len) {
                    selected.push(pair);
                }
            }
        }
        if selected.is_empty() {
            return;
        }
        // Keep newest `count` (preserving overdue anchor if Retx).
        // Sort ascending by offset for receiver-friendly contiguous drain.
        selected.sort_unstable_by_key(|&(off, _)| off);
        selected.dedup_by_key(|x| x.0);

        self.refill(now);
        let byte_tokens = (self.byte_tokens_us / 1_000_000) as usize;
        let pkt_tokens = (self.pkt_tokens_us / 1_000_000) as usize;
        let want_n = selected.len();

        // Compute exact packet sizes for candidate subsets `n = 1..=selected.len()`
        // where subset `n` always prefers newest entries (and keeps overdue anchor if Retx).
        let is_retx = matches!(kind, WaveKind::Retx(_));
        let anchor_off = if is_retx {
            include_tail_after_overdue.and_then(|idx| self.unacked.get(idx).map(|x| x.offset))
        } else {
            None
        };
        let subset_for = |n: usize| -> Vec<(u64, usize)> {
            if n >= selected.len() {
                return selected.clone();
            }
            let mut sub = Vec::with_capacity(n);
            if let Some(anchor) = anchor_off {
                if let Some(pair) = selected.iter().copied().find(|&(o, _)| o == anchor) {
                    sub.push(pair);
                }
            }
            for &pair in selected.iter().rev() {
                if sub.len() >= n {
                    break;
                }
                if sub.first().is_some_and(|p| p.0 == pair.0) {
                    continue;
                }
                sub.push(pair);
            }
            sub.sort_unstable_by_key(|&(o, _)| o);
            sub
        };
        let pkt_size_for = |sub: &[(u64, usize)]| -> usize {
            let body: usize = sub.iter().map(|&(off, len)| entry_wire_len(off, len)).sum();
            DGRAM_HEADER_BYTES + DGRAM_BODY_HEADER_BYTES + body
        };

        // 1. Try K = avail, shrinking N from want_n down to 1.
        if pkt_tokens >= avail {
            for n in (1..=want_n).rev() {
                let sub = subset_for(n);
                let pkt_bytes = pkt_size_for(&sub);
                if pkt_bytes <= DGRAM_MAX_BYTES && pkt_bytes * avail <= byte_tokens {
                    if n < want_n {
                        self.stats.shed_n += 1;
                    }
                    self.pkt_tokens_us -= u128::from(avail as u64) * 1_000_000;
                    self.byte_tokens_us -= u128::from((pkt_bytes * avail) as u64) * 1_000_000;
                    for f in 0..avail {
                        self.planned_data[f] = sub.clone();
                        self.planned_is_retx[f] = is_retx;
                    }
                    return;
                }
            }
        }

        // 2. Drop K -> 1 (if avail >= 2 or pkt_tokens >= 1), shrinking N down to 1.
        if pkt_tokens >= 1 {
            for n in (1..=want_n).rev() {
                let sub = subset_for(n);
                let pkt_bytes = pkt_size_for(&sub);
                if pkt_bytes <= DGRAM_MAX_BYTES && pkt_bytes <= byte_tokens {
                    if avail >= 2 {
                        self.stats.shed_k += 1;
                    }
                    if n < want_n {
                        self.stats.shed_n += 1;
                    }
                    self.pkt_tokens_us -= 1_000_000;
                    self.byte_tokens_us -= u128::from(pkt_bytes as u64) * 1_000_000;
                    let flow = self.rr_flow % avail;
                    self.rr_flow = (flow + 1) % avail;
                    self.planned_data[flow] = sub;
                    self.planned_is_retx[flow] = is_retx;
                    return;
                }
            }
        }

        // 3. Budget exhausted: suppress UDP transmission (reliable carrier unaffected).
        self.stats.shed_suppressed += 1;
    }

    pub fn has_transmit(&self, flow: usize, active_flows: usize) -> bool {
        if !self.bound || flow >= 2 {
            return false;
        }
        if let Some(flags) = self.pending_ack[flow] {
            if flags & (FLAG_PROBE | FLAG_BIND) != 0 || (!self.paused && flow < active_flows) {
                return true;
            }
        }
        if flow >= active_flows || self.paused || active_flows == 0 {
            return false;
        }
        self.wave_due.is_some() || !self.planned_data[flow].is_empty() || self.fin_pending[flow]
    }

    /// Encode the next datagram for `flow` into `out`, returning `true` when written.
    pub fn poll_transmit(
        &mut self,
        flow: usize,
        send: &SendHalf,
        recv: &RecvHalf,
        active_flows: usize,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> bool {
        if !self.bound || flow >= 2 || active_flows == 0 || flow >= active_flows {
            return false;
        }

        if let Some(flags) = self.pending_ack[flow].take() {
            let force = flags & (FLAG_PROBE | FLAG_BIND) != 0;
            if force || !self.paused {
                let mut sacks = Vec::new();
                recv.ooo_offsets(DGRAM_MAX_SACKS, &mut sacks);
                let pkt = DgramPacket {
                    header: self.header(),
                    body: DgramBody::Ack {
                        recv_offset: recv.recv_offset(),
                        max_offset: recv.max_offset(),
                        sacks,
                        flags,
                    },
                };
                let before = out.len();
                if encode_dgram_packet(&pkt, out) {
                    let pkt_len = out.len() - before;
                    if !force {
                        self.refill(now);
                        self.byte_tokens_us = self
                            .byte_tokens_us
                            .saturating_sub(u128::from(pkt_len as u64) * 1_000_000);
                        self.pkt_tokens_us = self.pkt_tokens_us.saturating_sub(1_000_000);
                    }
                    self.stats.tx_packets += 1;
                    self.stats.tx_bytes += pkt_len as u64;
                    return true;
                }
            }
        }

        if self.paused {
            return false;
        }

        if let Some(kind) = self.wave_due.take() {
            self.resolve_wave(kind, send, active_flows, now);
        }

        if !self.planned_data[flow].is_empty() {
            let frames = std::mem::take(&mut self.planned_data[flow]);
            let is_retx = std::mem::take(&mut self.planned_is_retx[flow]);
            let before = out.len();
            if encode_data_from_send(self.header(), send, &frames, out) {
                let pkt_len = out.len() - before;
                self.stats.tx_packets += 1;
                self.stats.tx_bytes += pkt_len as u64;
                if is_retx {
                    self.stats.retx_packets += 1;
                }
                self.note_dgram_tx(now, true);
                return true;
            }
        }

        if self.fin_pending[flow] {
            self.fin_pending[flow] = false;
            if let Some(offset) = self.fin_offset {
                let pkt = DgramPacket {
                    header: self.header(),
                    body: DgramBody::Fin { offset },
                };
                let before = out.len();
                if encode_dgram_packet(&pkt, out) {
                    let pkt_len = out.len() - before;
                    self.stats.tx_packets += 1;
                    self.stats.tx_bytes += pkt_len as u64;
                    self.note_dgram_tx(now, true);
                    return true;
                }
            }
        }

        false
    }

    pub fn on_rx_data(
        &mut self,
        entries: &[(u64, Vec<u8>)],
        raw_bytes: usize,
        flow: usize,
        recv: &mut RecvHalf,
        held_fin: Option<u64>,
        now: Instant,
    ) -> usize {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += raw_bytes as u64;
        self.note_dgram_rx();
        let mut delivered = 0usize;
        for (offset, bytes) in entries {
            if let Some(f) = held_fin {
                if offset.saturating_add(bytes.len() as u64) > f {
                    continue;
                }
            }
            if let Ok(n) = recv.on_data_ooo(*offset, bytes, now) {
                delivered += n;
            }
        }
        self.stats.rx_delivered_bytes += delivered as u64;
        self.queue_ack_flag(flow, 0);
        delivered
    }

    #[allow(clippy::too_many_arguments)]
    pub fn on_rx_ack(
        &mut self,
        recv_offset: u64,
        max_offset: u64,
        sacks: &[u64],
        flags: u8,
        raw_bytes: usize,
        flow: usize,
        send: &mut SendHalf,
        now: Instant,
    ) -> bool {
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += raw_bytes as u64;
        self.note_dgram_rx();

        // Update RTT sample from cumulative ACK / SACKs on un-retransmitted frames.
        for it in &self.unacked {
            if it.retx_count == 0
                && !it.sacked
                && (it.end() <= recv_offset || sacks.contains(&it.offset))
            {
                let sample = now.saturating_duration_since(it.first_sent);
                if sample >= Duration::from_millis(1) && sample <= Duration::from_secs(10) {
                    let next = (self.srtt * 7 + sample) / 8;
                    self.srtt = next.clamp(SRTT_MIN, SRTT_MAX);
                }
                break;
            }
        }

        let prog = send.on_ack(recv_offset, max_offset).unwrap_or(false);
        self.prune_acked(send.acked());
        if !sacks.is_empty() {
            for it in &mut self.unacked {
                if sacks.contains(&it.offset) {
                    it.sacked = true;
                }
            }
        }
        if flags & (FLAG_PROBE | FLAG_BIND) != 0 {
            self.queue_ack_flag(flow, 0);
        }
        prog
    }

    pub fn on_rx_fin(
        &mut self,
        offset: u64,
        raw_bytes: usize,
        flow: usize,
        now: Instant,
    ) -> Option<u64> {
        let _ = now;
        self.stats.rx_packets += 1;
        self.stats.rx_bytes += raw_bytes as u64;
        self.note_dgram_rx();
        if self.parked_fin.is_none() {
            self.parked_fin = Some(offset);
        }
        self.queue_ack_flag(flow, 0);
        self.parked_fin
    }

    pub fn next_deadline(&self, acked: u64, active_flows: usize) -> Option<Instant> {
        if !self.bound || active_flows == 0 {
            return None;
        }
        if self.paused {
            return self.next_probe;
        }
        let mut earliest: Option<Instant> = None;
        let mut put = |x: Instant| earliest = Some(earliest.map_or(x, |cur| cur.min(x)));

        if let Some(it) = self
            .unacked
            .iter()
            .find(|it| !it.sacked && it.retx_count < DGRAM_MAX_RETX && it.end() > acked)
        {
            put(it.next_retx);
        }
        if let Some(f) = self.fin_offset {
            if acked <= f {
                if let Some(t) = self.fin_retx_at {
                    put(t);
                }
            }
        }
        if self.reliable_progressed_since_tx {
            if let Some(since) = self.tx_without_rx_since {
                put(since
                    + self
                        .retx_after()
                        .saturating_mul(self.cfg.blackout_retx_intervals));
            }
        }
        earliest
    }

    pub fn handle_timeout(&mut self, now: Instant, acked: u64, active_flows: usize) {
        self.prune_acked(acked);
        if !self.bound || active_flows == 0 {
            return;
        }
        if self.paused {
            if self.next_probe.is_some_and(|p| now >= p) {
                self.queue_ack_flag(0, FLAG_PROBE);
                self.next_probe = Some(now + self.cfg.blackout_probe_interval);
            }
            return;
        }
        if self.reliable_progressed_since_tx {
            let threshold = self
                .retx_after()
                .saturating_mul(self.cfg.blackout_retx_intervals);
            if self
                .tx_without_rx_since
                .is_some_and(|s| now >= s + threshold)
            {
                self.paused = true;
                self.next_probe = Some(now + self.cfg.blackout_probe_interval);
                self.wave_due = None;
                self.planned_data[0].clear();
                self.planned_data[1].clear();
                self.fin_pending = [false; 2];
                self.stats.blackout_pauses += 1;
                return;
            }
        }

        let retx_after = self.retx_after();
        let mut oldest_overdue: Option<u64> = None;
        for it in &mut self.unacked {
            if !it.sacked && it.retx_count < DGRAM_MAX_RETX && now >= it.next_retx {
                it.retx_count += 1;
                it.next_retx = now + retx_after;
                oldest_overdue.get_or_insert(it.offset);
            }
        }
        if let Some(off) = oldest_overdue {
            self.wave_due = Some(WaveKind::Retx(off));
        }

        if let Some(f) = self.fin_offset {
            if acked <= f && self.fin_retx_at.is_some_and(|t| now >= t) {
                if self.fin_retx_count < DGRAM_MAX_FIN_RETX {
                    self.fin_retx_count += 1;
                    self.fin_retx_at = Some(now + retx_after);
                    let cap = active_flows.min(self.cfg.max_flows());
                    for flag in &mut self.fin_pending[..cap] {
                        *flag = true;
                    }
                } else {
                    self.fin_retx_at = None;
                }
            }
        }
    }
}
