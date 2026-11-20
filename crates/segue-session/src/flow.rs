//! One direction of a session: offsets, flow control and replay (§4).
//!
//! [`SendHalf`] keeps the replay buffer `[acked_offset, written)` and two
//! separate send positions: `cursor` (next offset to put on the current
//! carrier, rewound on re-attach) and `sent_hw` (highest offset ever sent,
//! used for the fatal checks of rule 2 and rule 6).
//!
//! [`RecvHalf`] keeps `recv_offset`, `consumed_offset` and the receive
//! credit. The advertised `max_offset` never decreases and the pool grant
//! always covers `max_offset − consumed_offset`, so the bytes a peer can make
//! us buffer are bounded by the grant (rule 1, rule 8).
//!
//! FIN occupies one offset (rule 7) and is not counted against the window:
//! it carries no bytes, and requiring window for it could deadlock a peer
//! whose app has stopped reading.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::codec::{max_data_len, Frame};
use crate::pool::{Grant, Pool, Tier, BLOCK};
use crate::{Limits, ProtoError, Timing};

/// Maximum buffered out-of-order bytes parked per receive half for Stage 2
/// redundant frames arriving ahead of the primary cursor.
const OOO_MAX_BYTES: usize = 32 * 1024;

/// Make room for `add` more bytes without growing past `limit` (the grant):
/// capacity doubles as usual but stops at the grant, so the memory a buffer
/// holds stays covered by the blocks it was charged for.
fn reserve_within(buf: &mut VecDeque<u8>, add: usize, limit: usize) {
    let need = buf.len() + add;
    if need > buf.capacity() {
        let target = (buf.capacity() * 2).max(need).min(limit.max(need));
        buf.reserve_exact(target - buf.len());
    }
}

/// After the grant shrank: release the capacity it no longer covers.
/// `VecDeque::drain` never frees, so without this a buffer that was once
/// full keeps its memory after its blocks went back to the pool.
fn fit(buf: &mut VecDeque<u8>, limit: usize) {
    if buf.capacity() > limit {
        buf.shrink_to(limit);
    }
}

#[derive(Debug)]
pub struct SendHalf {
    acked: u64,
    buf: VecDeque<u8>,
    cursor: u64,
    sent_hw: u64,
    peer_max: u64,
    fin: Option<u64>,
    grant: Grant,
    replay_cap: usize,
    /// Capacity last reported by `write_capacity` and not yet used; an ACK
    /// must not shrink the grant below it (a caller may have issued a read of
    /// that size against a site socket before the ACK arrived).
    promised: usize,
}

/// Send buffer every session keeps for its whole life (r5 N12): however
/// the pool is spent, an admitted session can always take this much new
/// application data once its buffer is acknowledged, so it never sits
/// with `write_capacity() == 0` waiting on blocks other sessions hold.
pub const SEND_FLOOR: usize = crate::pool::BLOCK;

impl SendHalf {
    /// `None` when the pool cannot cover [`SEND_FLOOR`]: the session is
    /// refused at admission instead of being admitted without progress.
    pub fn new(pool: &Arc<Pool>, limits: &Limits) -> Option<Self> {
        let mut grant = Grant::new(pool, false);
        if !grant.try_resize(SEND_FLOOR.min(limits.replay_cap)) {
            return None;
        }
        Some(Self {
            acked: 0,
            buf: VecDeque::new(),
            cursor: 0,
            sent_hw: 0,
            peer_max: limits.initial_credit as u64,
            fin: None,
            grant,
            replay_cap: limits.replay_cap,
            promised: 0,
        })
    }

    /// End of application data (the FIN offset once closed).
    pub fn data_end(&self) -> u64 {
        self.fin.unwrap_or(self.acked + self.buf.len() as u64)
    }

    fn seq_end(&self) -> u64 {
        self.fin.map_or(self.data_end(), |f| f + 1)
    }

    pub fn acked(&self) -> u64 {
        self.acked
    }
    pub fn sent_hw(&self) -> u64 {
        self.sent_hw
    }
    pub fn cursor(&self) -> u64 {
        self.cursor
    }
    pub fn peer_max(&self) -> u64 {
        self.peer_max
    }
    pub fn fin_offset(&self) -> Option<u64> {
        self.fin
    }
    /// Bytes held in the replay buffer (sent-unacked plus not yet sent).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
    /// Memory the buffer holds (its capacity); never more than the grant.
    pub fn held_bytes(&self) -> usize {
        self.buf.capacity()
    }
    pub fn pool(&self) -> &Arc<Pool> {
        self.grant.pool()
    }

    pub fn grant_bytes(&self) -> usize {
        self.grant.bytes()
    }

    /// Bytes [`write`](Self::write) will accept right now. Grows the grant
    /// so that a following `write` of that many bytes is guaranteed to fit.
    pub fn write_capacity(&mut self) -> usize {
        if self.fin.is_some() {
            return 0;
        }
        let want = self.replay_cap.min(self.buf.len() + 16 * 1024);
        self.grant.grow_towards(want);
        let cap = self
            .grant
            .bytes()
            .min(self.replay_cap)
            .saturating_sub(self.buf.len());
        self.promised = cap;
        cap
    }

    /// Like [`write_capacity`](Self::write_capacity), but promises at most
    /// `max` bytes and holds no more than the data plus that promise: the
    /// grant grows to `buffered + max` (as far as the pool allows) and
    /// shrinks back when it holds more, never below the send floor. An idle
    /// session that asks for a small read keeps only the floor, not a
    /// 16 KiB prefetch (r7 #7).
    pub fn write_capacity_for(&mut self, max: usize) -> usize {
        if self.fin.is_some() {
            self.promised = 0;
            return 0;
        }
        let want = self.replay_cap.min(self.buf.len() + max);
        if self.grant.bytes() < want {
            self.grant.grow_towards(want);
        } else {
            let keep = want.max(SEND_FLOOR.min(self.replay_cap));
            if self.grant.bytes() > keep {
                self.grant.try_resize(keep);
                fit(&mut self.buf, self.grant.bytes());
            }
        }
        let cap = self
            .grant
            .bytes()
            .min(self.replay_cap)
            .saturating_sub(self.buf.len())
            .min(max);
        self.promised = cap;
        cap
    }

    /// Queue application bytes. Returns how many were accepted (backpressure:
    /// bounded by the replay cap and the pool). Grows the grant only for
    /// `data` (and what is still promised), no read-ahead.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data
            .len()
            .min(self.write_capacity_for(data.len().max(self.promised)));
        reserve_within(&mut self.buf, n, self.grant.bytes());
        self.buf.extend(&data[..n]);
        self.promised = self.promised.saturating_sub(n);
        n
    }

    /// The application closed its write side: FIN at the current end.
    pub fn close(&mut self) {
        if self.fin.is_none() {
            self.fin = Some(self.data_end());
            self.promised = 0;
        }
    }

    /// Copy of `[0, n)` for OPEN's `first_data`; the cursor moves past it.
    pub fn take_first_data(&mut self, limit: usize) -> Vec<u8> {
        let n = self.take_first_len(limit);
        let [a, b] = self.first_data(n);
        [a, b].concat()
    }

    /// Length of OPEN's `first_data` (`[0, n)`, at most `limit`); the
    /// cursor moves past it. The bytes stay in the replay buffer, see
    /// [`first_data`](Self::first_data).
    pub fn take_first_len(&mut self, limit: usize) -> usize {
        if self.acked != 0 {
            return 0;
        }
        let n = limit.min(self.buf.len()).min(self.peer_max as usize);
        self.cursor = self.cursor.max(n as u64);
        self.sent_hw = self.sent_hw.max(n as u64);
        n
    }

    /// `[0, n)` of the stream as the replay buffer's two halves; empty
    /// once anything was acknowledged (OPEN is answered by then).
    pub fn first_data(&self, n: usize) -> [&[u8]; 2] {
        if self.acked != 0 {
            return [&[], &[]];
        }
        deque_range(&self.buf, 0, n.min(self.buf.len()))
    }

    /// Process `ACK{recv_offset, max_offset}` (rule 2). Returns whether
    /// `acked_offset` moved forward.
    pub fn on_ack(&mut self, recv: u64, max: u64) -> Result<bool, ProtoError> {
        if recv > self.sent_hw {
            return Err(ProtoError::Violation("ack beyond sent"));
        }
        self.peer_max = self.peer_max.max(max);
        if recv <= self.acked {
            return Ok(false);
        }
        let drop = (recv.min(self.data_end()) - self.acked) as usize;
        self.buf.drain(..drop.min(self.buf.len()));
        self.acked = recv;
        self.cursor = self.cursor.max(recv);
        let keep = (self.buf.len() + self.promised).max(SEND_FLOOR.min(self.replay_cap));
        self.grant.try_resize(keep);
        fit(&mut self.buf, self.grant.bytes());
        Ok(true)
    }

    /// New carrier: replay from `max(peer.recv_offset, own.acked_offset)`
    /// (rule 6). An old snapshot is not an error; one beyond anything ever
    /// sent is.
    pub fn rewind(&mut self, peer_recv: u64, peer_max: u64) -> Result<(), ProtoError> {
        if peer_recv > self.sent_hw {
            return Err(ProtoError::Violation("resume offset beyond sent"));
        }
        self.on_ack(peer_recv, peer_max)?;
        self.cursor = self.acked;
        Ok(())
    }

    /// What goes out next for the current carrier, within the peer's
    /// window; the cursor moves past it.
    fn poll_next(&mut self, max_bytes: usize) -> Option<Next> {
        let end = self.data_end();
        if self.cursor < end {
            let lim = end.min(self.peer_max);
            if self.cursor < lim {
                let n = ((lim - self.cursor) as usize)
                    .min(max_data_len(self.cursor, 0))
                    .min(max_bytes);
                let start = (self.cursor - self.acked) as usize;
                let offset = self.cursor;
                self.cursor += n as u64;
                self.sent_hw = self.sent_hw.max(self.cursor);
                return Some(Next::Data { offset, start, n });
            }
            return None;
        }
        if let Some(f) = self.fin {
            if self.cursor == f {
                self.cursor = f + 1;
                self.sent_hw = self.sent_hw.max(f + 1);
                return Some(Next::Fin(f));
            }
        }
        None
    }

    /// Conservative upper-bound frame size for the next [`poll_frame_into`](Self::poll_frame_into)
    /// call so callers only reserve 1 block from [`Pool`] for small frames.
    pub fn pending_send_hint(&self) -> usize {
        let end = self.data_end();
        if self.cursor < end {
            let lim = end.min(self.peer_max);
            if self.cursor < lim {
                let n = ((lim - self.cursor) as usize).min(max_data_len(self.cursor, 0));
                return n.saturating_add(18).clamp(BLOCK, crate::pool::FRAME_MAX);
            }
        }
        BLOCK
    }

    /// Next DATA or FIN for the current carrier, within the peer's window.
    pub fn poll_frame(&mut self) -> Option<Frame> {
        self.poll_frame_meta().map(|(f, _)| f)
    }

    /// Next DATA or FIN plus metadata for Stage 2 standby duplication.
    pub fn poll_frame_meta(&mut self) -> Option<(Frame, SentFrame)> {
        Some(match self.poll_next(usize::MAX)? {
            Next::Data { offset, start, n } => (
                Frame::Data {
                    offset,
                    data: self.buf.range(start..start + n).copied().collect(),
                    pad: 0,
                },
                SentFrame::Data { offset, len: n },
            ),
            Next::Fin(offset) => (Frame::Fin { offset }, SentFrame::Fin(offset)),
        })
    }

    /// [`poll_frame`](Self::poll_frame) encoded straight into `out`, at
    /// most `room` bytes of it: DATA bytes go from the replay buffer to
    /// the wire buffer in one copy, and `out` grows exactly once (r6 N13).
    /// Returns whether a frame was written.
    pub fn poll_frame_into(&mut self, out: &mut Vec<u8>, room: usize) -> bool {
        self.poll_frame_into_meta(out, room).is_some()
    }

    /// Like [`poll_frame_into`](Self::poll_frame_into), returning the emitted
    /// frame metadata when a frame was written.
    pub fn poll_frame_into_meta(&mut self, out: &mut Vec<u8>, room: usize) -> Option<SentFrame> {
        // Type, flags, length and offset varints: at most 18 bytes.
        let max = room.saturating_sub(18).max(1);
        match self.poll_next(max) {
            None => None,
            Some(Next::Data { offset, start, n }) => {
                let f = Frame::Data {
                    offset,
                    data: Vec::new(),
                    pad: 0,
                };
                let payload_len = crate::codec::varint_len(offset) + n;
                out.reserve_exact(2 + crate::codec::varint_len(payload_len as u64) + payload_len);
                f.encode_with(out, deque_range(&self.buf, start, n));
                Some(SentFrame::Data { offset, len: n })
            }
            Some(Next::Fin(offset)) => {
                Frame::Fin { offset }.encode(out);
                Some(SentFrame::Fin(offset))
            }
        }
    }

    fn dup_slice_bounds(&self, offset: u64, len: usize) -> Option<(u64, usize, usize)> {
        let end = offset.checked_add(len as u64)?.min(self.data_end());
        let start_off = offset.max(self.acked);
        if start_off >= end {
            return None;
        }
        let start = (start_off - self.acked) as usize;
        let n = (end - start_off) as usize;
        Some((start_off, start, n))
    }

    /// Materialize an unacked duplicate `DATA` frame from the replay buffer.
    pub fn dup_frame(&self, offset: u64, len: usize) -> Option<Frame> {
        let (start_off, start, n) = self.dup_slice_bounds(offset, len)?;
        Some(Frame::Data {
            offset: start_off,
            data: self.buf.range(start..start + n).copied().collect(),
            pad: 0,
        })
    }

    /// Encode an unacked duplicate `DATA` frame straight from the replay
    /// buffer into `out`, respecting `room` (single-copy path).
    pub fn dup_frame_into(&self, out: &mut Vec<u8>, room: usize, offset: u64, len: usize) -> bool {
        let Some((start_off, start, n)) = self.dup_slice_bounds(offset, len) else {
            return false;
        };
        let max = room.saturating_sub(18);
        let n = n.min(max);
        if n == 0 {
            return false;
        }
        let f = Frame::Data {
            offset: start_off,
            data: Vec::new(),
            pad: 0,
        };
        let payload_len = crate::codec::varint_len(start_off) + n;
        out.reserve_exact(2 + crate::codec::varint_len(payload_len as u64) + payload_len);
        f.encode_with(out, deque_range(&self.buf, start, n));
        true
    }

    /// Something could be sent now (window permitting).
    pub fn has_sendable(&self) -> bool {
        let end = self.data_end();
        (self.cursor < end && self.cursor < self.peer_max) || self.fin == Some(self.cursor)
    }

    /// Bytes or FIN sent and not yet acknowledged.
    pub fn unacked(&self) -> bool {
        self.acked < self.sent_hw
    }

    /// Anything not yet acknowledged, sent or not.
    pub fn pending(&self) -> bool {
        self.acked < self.seq_end()
    }

    /// FIN sent and acknowledged (`acked == fin + 1`).
    pub fn done(&self) -> bool {
        self.fin.is_some_and(|f| self.acked > f)
    }
}

/// Frame metadata returned by [`SendHalf::poll_frame_meta`] and
/// [`SendHalf::poll_frame_into_meta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SentFrame {
    Data { offset: u64, len: usize },
    Fin(u64),
}

enum Next {
    Data { offset: u64, start: usize, n: usize },
    Fin(u64),
}

/// Hard cap on pending Stage 2 duplicates per redundant carrier.
const DUP_QUEUE_CAP: usize = 32;

#[derive(Clone, Copy, Debug)]
struct DupItem {
    offset: u64,
    len: u32,
    due: Instant,
}

/// Per-spare queue of delayed small-frame `DATA` duplicates referencing slices
/// in [`SendHalf`]'s replay buffer.
///
/// Tracks an active `bulk_barrier`: when a frame larger than `max_bytes` is
/// transmitted on the primary carrier, `bulk_barrier` advances to its end so
/// subsequent small frames wait until `acked >= bulk_barrier` instead of
/// leaping ahead of unacked bulk bytes. Once cleared (or on a streaming link
/// where small frames run ahead of `acked`), incoming small frames never wedge.
#[derive(Clone, Debug)]
pub struct DupQueue {
    items: VecDeque<DupItem>,
    bulk_barrier: u64,
}

impl DupQueue {
    /// Start an empty queue anchored after `acked`.
    pub fn new(_acked: u64) -> Self {
        Self {
            items: VecDeque::new(),
            bulk_barrier: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn next_due(&self) -> Option<Instant> {
        self.items.front().map(|it| it.due)
    }

    pub fn has_due(&self, now: Instant) -> bool {
        self.items.front().is_some_and(|it| now >= it.due)
    }

    pub fn has_due_unacked(&self, acked: u64, now: Instant) -> bool {
        self.items
            .iter()
            .any(|it| now >= it.due && it.offset.saturating_add(u64::from(it.len)) > acked)
    }

    pub fn next_due_unacked(&self, acked: u64) -> Option<Instant> {
        self.items
            .iter()
            .find(|it| it.offset.saturating_add(u64::from(it.len)) > acked)
            .map(|it| it.due)
    }

    pub fn peek_due(&self, now: Instant) -> Option<(u64, usize)> {
        let it = self.items.front()?;
        if now >= it.due {
            Some((it.offset, it.len as usize))
        } else {
            None
        }
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<(u64, usize)> {
        if !self.has_due(now) {
            return None;
        }
        let it = self.items.pop_front()?;
        Some((it.offset, it.len as usize))
    }

    /// Drop items already acknowledged by `acked` and clear `bulk_barrier` once
    /// peer acknowledgement reaches or passes it.
    pub fn prune_acked(&mut self, acked: u64) {
        while self
            .items
            .front()
            .is_some_and(|it| it.offset.saturating_add(u64::from(it.len)) <= acked)
        {
            self.items.pop_front();
        }
        if acked >= self.bulk_barrier {
            self.bulk_barrier = 0;
        }
    }

    /// Consider queuing a primary `DATA` frame `[offset, offset + len)` for
    /// delayed standby transmission if it fits `max_bytes` and does not jump
    /// past an unacked bulk frame (`bulk_barrier`).
    #[allow(clippy::too_many_arguments)]
    pub fn on_primary_data(
        &mut self,
        acked: u64,
        offset: u64,
        len: usize,
        max_bytes: usize,
        delay: Duration,
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
        if len > max_bytes {
            self.bulk_barrier = self.bulk_barrier.max(end);
            return;
        }
        if acked < self.bulk_barrier {
            return;
        }
        let start = offset.max(acked);
        let Ok(slice_len) = u32::try_from(end - start) else {
            return;
        };
        if self
            .items
            .back()
            .is_some_and(|last| last.offset.saturating_add(u64::from(last.len)) >= end)
        {
            return;
        }
        if self.items.len() >= DUP_QUEUE_CAP {
            self.items.pop_front();
        }
        self.items.push_back(DupItem {
            offset: start,
            len: slice_len,
            due: now + delay,
        });
    }

    /// Clear queued duplicates under writer/pool pressure without wedging
    /// future small frames once pressure lifts.
    pub fn drop_due(&mut self, acked: u64) {
        self.items.clear();
        if acked >= self.bulk_barrier {
            self.bulk_barrier = 0;
        }
    }

    /// Reset queue state cleanly on promotion or rebind.
    pub fn reset(&mut self, _acked: u64) {
        self.items.clear();
        self.bulk_barrier = 0;
    }

    /// Seed small in-flight `[acked, cursor)` segments when a spare carrier binds.
    /// Chunks up to `8 * max_bytes` into `max_bytes` slices so queued token bursts
    /// survive a stalled primary dial; larger backlogs set `bulk_barrier` instead.
    pub fn seed_inflight(
        &mut self,
        acked: u64,
        cursor: u64,
        max_bytes: usize,
        delay: Duration,
        now: Instant,
    ) {
        let in_flight = cursor.saturating_sub(acked);
        if in_flight == 0 || max_bytes == 0 {
            return;
        }
        let max_seed = (max_bytes as u64).saturating_mul(8);
        if in_flight > max_seed {
            self.bulk_barrier = self.bulk_barrier.max(cursor);
            return;
        }
        let mut offset = acked;
        while offset < cursor {
            let chunk = usize::try_from(cursor - offset)
                .unwrap_or(max_bytes)
                .min(max_bytes);
            self.on_primary_data(acked, offset, chunk, max_bytes, delay, now);
            offset += chunk as u64;
        }
    }
}

/// `[start, start + n)` of `buf` as at most two slices.
fn deque_range(buf: &VecDeque<u8>, start: usize, n: usize) -> [&[u8]; 2] {
    let (a, b) = buf.as_slices();
    if start >= a.len() {
        let s = start - a.len();
        [&b[s..s + n], &[]]
    } else {
        let end = (start + n).min(a.len());
        [&a[start..end], &b[..start + n - end]]
    }
}

/// Receiver-side SRTT and delivery-rate estimate for §4 rule 8.
///
/// RTT: the sender cannot send past an advertised `max_offset` M before it
/// has the next, larger advertisement. So when data first ends beyond M,
/// at least one round trip has passed since that next advertisement went
/// out: `now − t(next)` is an RTT sample, exact when the sender was
/// waiting on the window and larger otherwise, never smaller. The
/// estimate is therefore a windowed minimum of the samples (between one
/// and two halves of [`RTT_WINDOW`] old): a slow sender's large samples do not count while the
/// path still shows its real RTT, and a path whose RTT went up is learned
/// within the window. A new carrier ([`RecvHalf::new_path`]) starts over.
///
/// Delivery rate: bytes handed to the application per epoch of at least
/// one SRTT.
#[derive(Debug)]
struct RateRtt {
    /// Advertised `max_offset` values and when each went out, ascending.
    adv: VecDeque<(Instant, u64)>,
    /// Windowed minimum of the RTT samples: the minimum of the current
    /// half-window bucket (since `bucket_start`) and of the previous one,
    /// so samples count for between one and two halves of [`RTT_WINDOW`].
    /// Microseconds, 0 = no sample (samples are at least 100 µs).
    cur_min: u32,
    prev_min: u32,
    bucket_start: Instant,
    /// `min(cur_min, prev_min)` in microseconds, 0 = none yet.
    srtt_us: u32,
    epoch: (Instant, u64),
}

/// Advertisements remembered for RTT samples; past this, new ones are
/// folded into the newest entry (fewer samples, never wrong ones).
const ADV_LOG: usize = 8;

/// How long an RTT sample counts towards the minimum.
pub const RTT_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// RTT samples above this are clamped: a sender that paused for seconds
/// at a window edge says nothing about the path.
const MAX_RTT_SAMPLE: std::time::Duration = std::time::Duration::from_secs(2);

impl RateRtt {
    fn new(initial_max: u64, now: Instant) -> Self {
        let mut adv = VecDeque::with_capacity(2);
        adv.push_back((now, initial_max));
        Self {
            adv,
            cur_min: 0,
            prev_min: 0,
            bucket_start: now,
            srtt_us: 0,
            epoch: (now, 0),
        }
    }

    fn on_advertised(&mut self, max: u64, now: Instant) {
        if self.adv.back().is_some_and(|&(_, m)| m >= max) {
            return;
        }
        if self.adv.len() == ADV_LOG {
            // Full: fold this advertisement into the newest entry, keeping
            // that entry's time. The entries still pending (the oldest,
            // which data crosses next) stay, so sampling never stalls,
            // and every sample remains a lower bound on the time since
            // the first advertisement past the crossed value: the folded
            // entry's time is that of the first advertisement above the
            // entry before it, and the next entry recorded is the first
            // one above the folded value. Only samples for the folded
            // values are lost.
            self.adv.back_mut().unwrap().1 = max;
            return;
        }
        self.adv.push_back((now, max));
    }

    fn on_data(&mut self, end: u64, now: Instant) {
        let mut sample = None;
        while self.adv.len() >= 2 && end > self.adv[0].1 {
            let (t_next, _) = self.adv[1];
            sample = Some(now.saturating_duration_since(t_next));
            self.adv.pop_front();
        }
        if let Some(s) = sample {
            self.add_sample(s, now);
        }
    }

    fn add_sample(&mut self, s: std::time::Duration, now: Instant) {
        let s = s.clamp(std::time::Duration::from_micros(100), MAX_RTT_SAMPLE);
        let half = RTT_WINDOW / 2;
        let age = now.saturating_duration_since(self.bucket_start);
        if age >= half * 2 {
            self.prev_min = 0;
            self.cur_min = 0;
            self.bucket_start = now;
        } else if age >= half {
            self.prev_min = std::mem::take(&mut self.cur_min);
            self.bucket_start = now;
        }
        let us = s.as_micros() as u32;
        let min = |a: u32, b: u32| match (a, b) {
            (0, x) | (x, 0) => x,
            (a, b) => a.min(b),
        };
        self.cur_min = min(self.cur_min, us);
        self.srtt_us = min(self.cur_min, self.prev_min);
    }

    /// A new carrier: its path may have another RTT. The window keeps its
    /// size until the new path has been measured.
    fn new_path(&mut self, consumed: u64, now: Instant) {
        self.cur_min = 0;
        self.prev_min = 0;
        self.bucket_start = now;
        self.srtt_us = 0;
        self.epoch = (now, consumed);
    }

    /// A new epoch starts here (after idle: the old rate says nothing).
    /// The logs give their memory back, as the buffers do.
    fn restart(&mut self, consumed: u64, now: Instant) {
        self.epoch = (now, consumed);
        self.adv.shrink_to_fit();
    }

    fn srtt(&self) -> Option<std::time::Duration> {
        (self.srtt_us > 0).then(|| std::time::Duration::from_micros(self.srtt_us.into()))
    }

    /// The window target when an epoch of at least one SRTT has ended.
    fn on_consumed(&mut self, consumed: u64, now: Instant) -> Option<usize> {
        let srtt = self.srtt()?;
        let dt = now.saturating_duration_since(self.epoch.0);
        if dt < srtt {
            return None;
        }
        let bytes = consumed - self.epoch.1;
        self.epoch = (now, consumed);
        let target = 2.0 * bytes as f64 * srtt.as_secs_f64() / dt.as_secs_f64();
        Some(target.min(usize::MAX as f64 / 2.0) as usize)
    }
}

/// Receive credit above the initial credit (window growth) is taken only
/// while the pool's elastic part is less than this fraction (1/n) in use:
/// credit once advertised cannot be revoked (§4 rule 8), so sessions that
/// grew and then went quiet without closing must not pin what admission
/// needs. The other half always stays for floors, initial credits and
/// fresh sessions.
pub const GROWTH_SHARE_DIV: usize = 2;

#[derive(Debug)]
pub struct RecvHalf {
    consumed: u64,
    buf: VecDeque<u8>,
    ooo: BTreeMap<u64, Vec<u8>>,
    ooo_bytes: usize,
    recv: u64,
    adv_max: u64,
    fin: Option<u64>,
    grant: Grant,
    min_credit: usize,
    window_cap: usize,
    /// Receive window aimed for while active (§4 rule 8): the largest
    /// `clamp(2 × delivery_rate × SRTT, initial credit, window_cap)` seen
    /// since the session last went idle, measured here (see [`RateRtt`]).
    /// A window-limited sender delivers about `win` per RTT, so the
    /// target is about `2 × win` and the window doubles each round trip
    /// until the link, the reader or the cap limits it; a session that
    /// moves a few bytes keeps a small window it does not have to take
    /// back (`max_offset` never moves back). Back to the initial credit
    /// when idle.
    win: usize,
    win_init: usize,
    est: RateRtt,
    /// Latest time any call saw; stamps ACKs sent without one
    /// ([`force_ack`](Self::force_ack), [`mark_acked`](Self::mark_acked)).
    now_hint: Instant,
    /// Credit above the initial credit, as reported to the pool.
    grown: usize,
    /// What growth is counted above: the initial credit or the credit
    /// floor, whichever is larger, in whole blocks (as grants are taken).
    /// Any `Limits` keep the growth ledger consistent with it.
    grow_base: usize,
    idle_after: Duration,
    pressure_idle_after: Duration,
    ack_delay: Duration,
    last_ack: (u64, u64),
    pending_since: Option<Instant>,
    last_data: Instant,
}

impl RecvHalf {
    /// Takes the protocol's initial credit from the pool; `None` when the
    /// pool cannot cover it (→ `REJECT(capacity)` / local REFUSE).
    pub fn new(pool: &Arc<Pool>, limits: &Limits, timing: &Timing, now: Instant) -> Option<Self> {
        Self::new_with_idle(pool, limits, timing, timing.idle_after, now)
    }

    /// Variant of [`Self::new`] overriding the idle window-retention bound
    /// (for AI sessions using [`Timing::idle_after_ai`] while falling back to
    /// [`Timing::idle_after`] when the global pool is under pressure).
    pub fn new_with_idle(
        pool: &Arc<Pool>,
        limits: &Limits,
        timing: &Timing,
        idle_after: Duration,
        now: Instant,
    ) -> Option<Self> {
        let mut grant = Grant::new(pool, true);
        if !grant.try_resize(limits.initial_credit) {
            return None;
        }
        let initial = limits.initial_credit as u64;
        Some(Self {
            consumed: 0,
            buf: VecDeque::new(),
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            recv: 0,
            adv_max: initial,
            fin: None,
            grant,
            min_credit: limits.min_credit,
            window_cap: limits.window_cap.max(limits.initial_credit),
            win: limits.initial_credit,
            win_init: limits.initial_credit,
            est: RateRtt::new(initial, now),
            now_hint: now,
            grown: 0,
            grow_base: crate::pool::blocks_for(limits.initial_credit.max(limits.min_credit))
                * BLOCK,
            idle_after,
            pressure_idle_after: timing.idle_after,
            ack_delay: timing.ack_delay,
            last_ack: (0, initial),
            pending_since: None,
            last_data: now,
        })
    }

    pub fn recv_offset(&self) -> u64 {
        self.recv
    }
    pub fn max_offset(&self) -> u64 {
        self.adv_max
    }
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
    /// Memory the buffer holds (its capacity); never more than the grant.
    pub fn held_bytes(&self) -> usize {
        self.buf.capacity()
    }
    pub fn pool(&self) -> &Arc<Pool> {
        self.grant.pool()
    }

    pub fn grant_bytes(&self) -> usize {
        self.grant.bytes()
    }
    pub fn fin_received(&self) -> bool {
        self.fin.is_some()
    }
    /// The last ACK values put on the wire (or carried by RESUME/RESUMED).
    pub fn last_ack(&self) -> (u64, u64) {
        self.last_ack
    }
    /// All data up to FIN handed to the application.
    pub fn eof(&self) -> bool {
        self.fin == Some(self.consumed)
    }
    /// Our ACK covering the peer's FIN has been sent.
    pub fn fin_acked(&self) -> bool {
        self.fin.is_some_and(|f| self.last_ack.0 > f)
    }

    fn touch(&mut self, now: Instant) {
        if self.pending_since.is_none() && (self.recv, self.adv_max) != self.last_ack {
            self.pending_since = Some(now);
        }
    }

    /// Accept a DATA frame (rule 5). Returns the number of new bytes.
    pub fn on_data(&mut self, offset: u64, data: &[u8], now: Instant) -> Result<usize, ProtoError> {
        let end = offset + data.len() as u64;
        if let Some(f) = self.fin {
            if end > f {
                return Err(ProtoError::Violation("data after fin"));
            }
            return Ok(0);
        }
        if end > self.adv_max {
            return Err(ProtoError::Violation("data beyond max_offset"));
        }
        if offset > self.recv {
            return Err(ProtoError::Violation("gap in data"));
        }
        if end <= self.recv {
            return Ok(0);
        }
        let skip = (self.recv - offset) as usize;
        let fresh = &data[skip..];
        reserve_within(&mut self.buf, fresh.len(), self.grant.bytes());
        self.buf.extend(fresh);
        self.recv = end;
        self.now_hint = self.now_hint.max(now);
        self.est.on_data(end, now);
        self.last_data = now;
        let drained = self.drain_ooo(now);
        self.touch(now);
        Ok(fresh.len() + drained)
    }

    /// Variant for redundant / gap-tolerant carriers: delivers in-order bytes
    /// immediately (draining any parked suffix) and parks ahead-of-order
    /// chunks in a bounded side buffer up to `OOO_MAX_BYTES` without failing.
    pub fn on_data_ooo(
        &mut self,
        offset: u64,
        data: &[u8],
        now: Instant,
    ) -> Result<usize, ProtoError> {
        let Some(end) = offset.checked_add(data.len() as u64) else {
            return Err(ProtoError::Violation("data beyond max_offset"));
        };
        if let Some(f) = self.fin {
            if end > f {
                return Err(ProtoError::Violation("data after fin"));
            }
            return Ok(0);
        }
        if end > self.adv_max {
            return Err(ProtoError::Violation("data beyond max_offset"));
        }
        if offset <= self.recv {
            return self.on_data(offset, data, now);
        }
        self.park_ooo(offset, data);
        Ok(0)
    }

    fn park_ooo(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() || data.len() > OOO_MAX_BYTES || self.grant.pool().under_pressure() {
            return;
        }
        let end = offset + data.len() as u64;
        if self
            .ooo
            .range(..=offset)
            .next_back()
            .is_some_and(|(&k, v)| k + v.len() as u64 >= end)
        {
            return;
        }
        if let Some(existing) = self.ooo.get_mut(&offset) {
            let delta = data.len().saturating_sub(existing.len());
            if delta == 0 || self.ooo_bytes + delta > OOO_MAX_BYTES {
                return;
            }
            self.ooo_bytes += delta;
            *existing = data.to_vec();
            return;
        }
        if self.ooo_bytes + data.len() <= OOO_MAX_BYTES {
            self.ooo_bytes += data.len();
            self.ooo.insert(offset, data.to_vec());
        }
    }

    fn drain_ooo(&mut self, now: Instant) -> usize {
        let mut added = 0usize;
        while let Some(&off) = self.ooo.keys().next() {
            if off > self.recv {
                break;
            }
            let (_, seg) = self.ooo.pop_first().unwrap();
            self.ooo_bytes = self.ooo_bytes.saturating_sub(seg.len());
            let end = off + seg.len() as u64;
            if end <= self.recv {
                continue;
            }
            let skip = (self.recv - off) as usize;
            let fresh = &seg[skip..];
            reserve_within(&mut self.buf, fresh.len(), self.grant.bytes());
            self.buf.extend(fresh);
            self.recv = end;
            self.now_hint = self.now_hint.max(now);
            self.est.on_data(end, now);
            self.last_data = now;
            added += fresh.len();
        }
        added
    }

    pub fn on_fin(&mut self, offset: u64, now: Instant) -> Result<(), ProtoError> {
        match self.fin {
            Some(f) if f == offset => Ok(()),
            Some(_) => Err(ProtoError::Violation("fin moved")),
            None if offset != self.recv => Err(ProtoError::Violation("fin not at recv_offset")),
            None => {
                self.fin = Some(offset);
                self.recv = offset + 1;
                self.ooo.clear();
                self.ooo_bytes = 0;
                self.touch(now);
                // Nothing more arrives: give back credit (and growth) now,
                // even if the buffer is already drained and no read will
                // follow (a half-closed session keeps living).
                self.update_credit(now);
                Ok(())
            }
        }
    }

    /// Hand buffered bytes to the application.
    /// The first contiguous run of buffered bytes (see
    /// [`consume`](Self::consume)): lets a caller write received bytes to
    /// the application without copying them out first.
    pub fn front(&self) -> &[u8] {
        self.buf.as_slices().0
    }

    /// Drop `n` bytes from the front after they were delivered.
    pub fn consume(&mut self, n: usize, now: Instant) {
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
        self.consumed += n as u64;
        if n > 0 {
            self.update_credit(now);
        }
    }

    pub fn read(&mut self, out: &mut [u8], now: Instant) -> usize {
        let n = out.len().min(self.buf.len());
        if n > 0 {
            let (a, b) = self.buf.as_slices();
            let first = n.min(a.len());
            out[..first].copy_from_slice(&a[..first]);
            if first < n {
                out[first..n].copy_from_slice(&b[..n - first]);
            }
            self.buf.drain(..n);
            self.consumed += n as u64;
            self.update_credit(now);
        }
        n
    }

    /// Recompute the grant and possibly advance `max_offset` (rule 8).
    pub fn update_credit(&mut self, now: Instant) {
        if self.fin.is_some() {
            // Nothing more can arrive: hold only what is buffered.
            self.grant.try_resize(self.buf.len());
            fit(&mut self.buf, self.grant.bytes());
            self.sync_grown();
            return;
        }
        self.now_hint = self.now_hint.max(now);
        let outstanding = (self.adv_max - self.consumed) as usize;
        let idle_after = self.effective_idle_after();
        let active =
            !self.buf.is_empty() || now.saturating_duration_since(self.last_data) < idle_after;
        if !active {
            self.win = self.win_init;
            self.est.restart(self.consumed, now);
        } else if let Some(target) = self.est.on_consumed(self.consumed, now) {
            // Grows only while active, like TCP receive autotuning: an
            // epoch in which the app read little (it is busy, or a burst
            // ended) does not take back a window the path has shown it
            // needs. It falls back when the session goes idle, and the
            // pool limits it under pressure (fair share, growth budget).
            self.win = self.win.max(target.min(self.window_cap));
        }
        let mut desired = if active { self.win } else { self.min_credit };
        if !active {
            // Idle and drained: the buffer's memory goes back now; it is
            // re-reserved (within the grant) when data arrives. The grant
            // itself cannot fall below the window already advertised
            // (`max_offset` never moves back, rule 8), so the pool keeps
            // that promise charged.
            self.buf.shrink_to_fit();
        }
        let pool = self.grant.pool();
        if pool.under_pressure() {
            desired = desired.min(pool.fair_share_bytes());
        }
        let base = self.grow_base.max(outstanding);
        let mut need = desired.max(self.min_credit).max(outstanding);
        if need > base && need > self.grant.bytes() {
            // Growth past the initial credit comes out of the growth
            // budget only (GROWTH_SHARE_DIV): the sum over all sessions of
            // credit above their initial credit. Floors and initial
            // credits do not count against it.
            // Reserved atomically before the grant grows, so sessions on
            // other tasks cannot spend the same room twice; settled to the
            // grant actually taken by `sync_grown` below.
            // In whole blocks, as the grant is taken: the reservation is
            // never smaller than what `sync_grown` settles.
            let budget = pool.limit(Tier::Elastic) * BLOCK / GROWTH_SHARE_DIV;
            let want = need.div_ceil(BLOCK) * BLOCK - self.grow_base;
            self.grown = pool.reserve_grown(self.grown, want, budget, BLOCK);
            need = need.min(base.max(self.grow_base + self.grown));
        }
        if need <= self.grant.bytes() {
            self.grant.try_resize(need);
            fit(&mut self.buf, self.grant.bytes());
        } else {
            self.grant.grow_towards(need);
        }
        self.sync_grown();
        let new_max = self.consumed + self.grant.bytes() as u64;
        if new_max > self.adv_max {
            self.adv_max = new_max;
            self.touch(now);
        }
    }

    /// Report this session's credit above the initial credit to the pool.
    fn sync_grown(&mut self) {
        let g = self.grant.bytes().saturating_sub(self.grow_base);
        // The grant never grows past the reservation (whole blocks, and
        // `win_init` is a whole number of blocks), only up to it.
        debug_assert!(
            g <= self.grown,
            "growth {g} past reservation {}",
            self.grown
        );
        if g != self.grown {
            self.grant.pool().set_grown(self.grown, g);
            self.grown = g;
        }
    }

    fn credit(&self) -> u64 {
        (self.adv_max - self.consumed).max(1)
    }

    /// When an ACK should be sent: `None` = nothing to acknowledge.
    pub fn ack_deadline(&self) -> Option<Instant> {
        let since = self.pending_since?;
        if (self.recv, self.adv_max) == self.last_ack {
            return None;
        }
        let (lr, lm) = self.last_ack;
        let ack_bytes = (self.credit() / 4).max(1);
        let window_step = (self.credit() / 4).min(16 * 1024);
        let immediate = self.recv - lr >= ack_bytes
            || (lm <= self.recv && self.adv_max - lm >= window_step)
            || self.fin.is_some_and(|f| lr <= f);
        Some(if immediate {
            since
        } else {
            since + self.ack_delay
        })
    }

    pub fn ack_pending(&self) -> bool {
        (self.recv, self.adv_max) != self.last_ack
    }

    /// ACK frame if due by `now` (or any pending one when `piggyback`).
    pub fn poll_ack(&mut self, now: Instant, piggyback: bool) -> Option<Frame> {
        self.now_hint = self.now_hint.max(now);
        let due = self.ack_deadline()?;
        if due > now && !piggyback {
            return None;
        }
        Some(self.force_ack())
    }

    /// Emit the current ACK unconditionally.
    pub fn force_ack(&mut self) -> Frame {
        self.mark_acked();
        Frame::Ack {
            recv_offset: self.recv,
            max_offset: self.adv_max,
        }
    }

    /// The current values were sent in RESUME / RESUMED / OPENED.
    pub fn mark_acked(&mut self) {
        self.last_ack = (self.recv, self.adv_max);
        self.pending_since = None;
        self.est.on_advertised(self.adv_max, self.now_hint);
    }

    /// Smoothed RTT measured from window advertisements, if any yet.
    pub fn srtt(&self) -> Option<std::time::Duration> {
        self.est.srtt()
    }

    /// Receive window currently aimed for (before pool limits).
    pub fn target_window(&self) -> usize {
        self.win
    }

    /// The session moved to a new carrier (RESUME / attach): RTT is
    /// measured again on the new path.
    pub fn new_path(&mut self, now: Instant) {
        self.now_hint = self.now_hint.max(now);
        self.est.new_path(self.consumed, now);
    }

    fn effective_idle_after(&self) -> Duration {
        if self.grant.pool().under_pressure() {
            self.idle_after.min(self.pressure_idle_after)
        } else {
            self.idle_after
        }
    }

    /// Idle check for timeouts: lets credit fall back when no data arrives.
    pub fn idle_deadline(&self) -> Option<Instant> {
        // Buffered data keeps the flow active (`update_credit` would not
        // shrink), so there is nothing to time out until it is read.
        if self.fin.is_some()
            || !self.buf.is_empty()
            || (self.buf.capacity() == 0
                && self.grant.bytes()
                    <= self.min_credit.max((self.adv_max - self.consumed) as usize))
        {
            return None;
        }
        Some(self.last_data + self.effective_idle_after())
    }
}

impl Drop for RecvHalf {
    fn drop(&mut self) {
        self.grant.pool().set_grown(self.grown, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn halves(pool_bytes: usize) -> (SendHalf, RecvHalf, Instant) {
        let pool = Pool::new(pool_bytes);
        let l = Limits::default();
        let now = Instant::now();
        (
            SendHalf::new(&pool, &l).unwrap(),
            RecvHalf::new(&pool, &l, &Timing::default(), now).unwrap(),
            now,
        )
    }

    fn pump(s: &mut SendHalf, r: &mut RecvHalf, now: Instant) {
        while let Some(f) = s.poll_frame() {
            match f {
                Frame::Data { offset, data, .. } => {
                    r.on_data(offset, &data, now).unwrap();
                }
                Frame::Fin { offset } => r.on_fin(offset, now).unwrap(),
                _ => unreachable!(),
            }
        }
        if let Frame::Ack {
            recv_offset,
            max_offset,
        } = r.force_ack()
        {
            s.on_ack(recv_offset, max_offset).unwrap();
        }
    }

    #[test]
    fn window_bounds_buffering_when_app_does_not_read() {
        let (mut s, mut r, now) = halves(8 << 20);
        let mut written = 0;
        for _ in 0..100 {
            written += s.write(&[7u8; 4096]);
            pump(&mut s, &mut r, now);
        }
        // Nothing consumed: the receiver holds at most its initial credit.
        assert_eq!(r.buffered(), crate::INITIAL_CREDIT);
        assert_eq!(r.max_offset(), crate::INITIAL_CREDIT as u64);
        assert!(s.buffered() <= Limits::default().replay_cap);
        assert!(written <= Limits::default().replay_cap + crate::INITIAL_CREDIT);
        // App reads: window opens, more flows.
        let mut buf = vec![0; 1 << 20];
        let n = r.read(&mut buf, now);
        assert_eq!(n, crate::INITIAL_CREDIT);
        assert!(r.max_offset() > crate::INITIAL_CREDIT as u64);
        assert!(
            r.ack_deadline().unwrap() <= now,
            "zero-window update is immediate"
        );
        // The window update reaches the sender, then the new data flows.
        pump(&mut s, &mut r, now);
        pump(&mut s, &mut r, now);
        assert!(r.recv_offset() > crate::INITIAL_CREDIT as u64);
        assert!(r.buffered() <= r.grant_bytes());
    }

    #[test]
    fn overlap_is_trimmed_and_violations_are_fatal() {
        let (_, mut r, now) = halves(1 << 20);
        assert_eq!(r.on_data(0, b"hello", now).unwrap(), 5);
        assert_eq!(r.on_data(3, b"lo wo", now).unwrap(), 3);
        assert_eq!(r.on_data(0, b"he", now).unwrap(), 0);
        assert!(r.on_data(10, b"x", now).is_err());
        assert!(
            r.on_data(8, &vec![0; 20_000], now).is_err(),
            "beyond max_offset"
        );
        r.on_fin(8, now).unwrap();
        r.on_fin(8, now).unwrap();
        assert!(r.on_fin(9, now).is_err());
        assert!(r.on_data(7, b"zz", now).is_err());
        assert_eq!(r.on_data(5, b" wo", now).unwrap(), 0);
        let mut b = [0u8; 16];
        assert_eq!(r.read(&mut b, now), 8);
        assert_eq!(&b[..8], b"hello wo");
        assert!(r.eof());
    }

    #[test]
    fn rewind_uses_max_and_rejects_future_snapshot() {
        let (mut s, _r, _now) = halves(1 << 20);
        s.write(&[1u8; 1000]);
        while s.poll_frame().is_some() {}
        s.on_ack(600, 16384).unwrap();
        // Stale snapshot (400 < acked 600): replay from 600.
        s.rewind(400, 16384).unwrap();
        assert_eq!(s.cursor(), 600);
        match s.poll_frame() {
            Some(Frame::Data {
                offset: 600, data, ..
            }) => assert_eq!(data.len(), 400),
            f => panic!("{f:?}"),
        }
        assert!(s.rewind(1001, 16384).is_err());
        assert!(s.on_ack(1001, 0).is_err());
    }

    #[test]
    fn fin_is_replayed_until_acked() {
        let (mut s, _, _) = halves(1 << 20);
        s.write(b"abc");
        s.close();
        assert!(matches!(
            s.poll_frame(),
            Some(Frame::Data { offset: 0, .. })
        ));
        assert_eq!(s.poll_frame(), Some(Frame::Fin { offset: 3 }));
        assert_eq!(s.poll_frame(), None);
        s.on_ack(3, 100).unwrap();
        assert!(!s.done());
        s.rewind(3, 100).unwrap();
        assert_eq!(s.poll_frame(), Some(Frame::Fin { offset: 3 }));
        s.on_ack(4, 100).unwrap();
        assert!(s.done());
        assert_eq!(s.buffered(), 0);
    }

    #[test]
    fn credit_never_exceeds_pool() {
        // All elastic: four initial credits exactly.
        let pool = Pool::with_regions(64 * 1024, 0, 0);
        let l = Limits::default();
        let t = Timing::default();
        let now = Instant::now();
        let mut rs: Vec<RecvHalf> = (0..4)
            .map(|_| RecvHalf::new(&pool, &l, &t, now).unwrap())
            .collect();
        assert!(
            RecvHalf::new(&pool, &l, &t, now).is_none(),
            "pool exhausted → capacity"
        );
        for r in &mut rs {
            r.on_data(0, &[0; 1000], now).unwrap();
            let mut b = [0; 1000];
            r.read(&mut b, now);
        }
        assert!(pool.used_bytes() <= pool.capacity_bytes());
        for r in &rs {
            assert!((r.max_offset() - r.consumed()) as usize <= r.grant_bytes());
        }
    }

    #[test]
    fn returned_grant_also_returns_buffer_memory() {
        // Fill the replay and receive buffers, drain them, and check that
        // the memory they hold follows the grant back down (review R4 #15:
        // `drain` keeps capacity, so the old code re-used one logical
        // allowance for ever more resident memory).
        let (mut s, mut r, now) = halves(8 << 20);
        let mut sent = 0;
        let mut out = vec![0u8; 64 * 1024];
        while sent < 200 * 1024 {
            let n = s.write(&[1u8; 8192]);
            sent += n;
            assert!(s.held_bytes() <= s.grant_bytes(), "send over grant");
            while let Some(Frame::Data { offset, data, .. }) = s.poll_frame() {
                r.on_data(offset, &data, now).unwrap();
                assert!(r.held_bytes() <= r.grant_bytes(), "recv over grant");
            }
            if n == 0 {
                while r.read(&mut out, now) > 0 {}
                pump(&mut s, &mut r, now);
            }
        }
        let peak = r.held_bytes();
        assert!(peak >= 16 * 1024, "receive buffer never filled: {peak}");
        for _ in 0..100 {
            while r.read(&mut out, now) > 0 {}
            pump(&mut s, &mut r, now);
            if s.buffered() == 0 {
                break;
            }
        }
        while r.read(&mut out, now) > 0 {}
        assert_eq!(s.buffered(), 0);
        // Only the capacity promised to the last caller stays charged.
        assert!(s.grant_bytes() <= 16 * 1024, "{}", s.grant_bytes());
        assert!(
            s.held_bytes() <= s.grant_bytes(),
            "acked replay buffer keeps its memory: {} > {}",
            s.held_bytes(),
            s.grant_bytes()
        );
        // Idle: the receive grant drops to the floor and the buffer with it.
        let later = now + Timing::default().idle_after * 2;
        r.update_credit(later);
        // (The grant still covers credit already advertised, which cannot
        // be withdrawn; the memory behind it is released until used.)
        assert!(
            r.held_bytes() <= r.grant_bytes(),
            "{} > {}",
            r.held_bytes(),
            r.grant_bytes()
        );
        assert_eq!(
            r.held_bytes(),
            0,
            "idle drained receive buffer keeps {peak} bytes"
        );
    }

    #[test]
    fn burst_then_idle_keeps_only_the_send_floor_and_advertised_credit() {
        // r7 #7, at the half level: after a burst the send grant is back to
        // the floor (no 16 KiB read-ahead promise left behind), an idle
        // small-read promise fits in the floor, and the receive grant is
        // exactly the advertised credit still outstanding (never revoked).
        let (mut s, mut r, now) = halves(8 << 20);
        let pool = s.pool().clone();
        let floor = SEND_FLOOR;
        assert_eq!(s.grant_bytes(), floor);
        assert_eq!(s.write_capacity_for(512), 512);
        assert_eq!(s.grant_bytes(), floor, "idle small read grew the grant");
        let mut out = vec![0u8; 64 * 1024];
        let mut sent = 0;
        // Each exchange takes a millisecond, so the window has an RTT and a
        // delivery rate to grow from (§4 rule 8).
        let mut t = now;
        while sent < 512 * 1024 {
            let cap = s.write_capacity_for(16 * 1024);
            let n = s.write(&vec![3u8; cap.min(16 * 1024)]);
            sent += n;
            t += std::time::Duration::from_millis(1);
            pump(&mut s, &mut r, t);
            while r.read(&mut out, t) > 0 {}
            pump(&mut s, &mut r, t);
        }
        assert!(r.max_offset() - r.consumed() > crate::INITIAL_CREDIT as u64);
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.write_capacity_for(512), 512);
        assert_eq!(s.grant_bytes(), floor, "send grant after burst");
        let later = t + Timing::default().idle_after * 2;
        r.update_credit(later);
        let outstanding = (r.max_offset() - r.consumed()) as usize;
        assert_eq!(
            r.grant_bytes(),
            outstanding
                .max(Limits::default().min_credit)
                .div_ceil(crate::pool::BLOCK)
                * crate::pool::BLOCK
        );
        assert_eq!(r.held_bytes(), 0);
        assert_eq!(pool.used_bytes(), s.grant_bytes() + r.grant_bytes());
    }

    #[test]
    fn dup_queue_preserves_contiguous_prefix_and_resets_on_drop() {
        let now = Instant::now();
        let delay = Duration::from_millis(30);
        let mut q = DupQueue::new(100);

        // Small contiguous frames starting at acked=100 enqueue in order.
        q.on_primary_data(100, 100, 128, 1024, delay, now);
        q.on_primary_data(100, 228, 256, 1024, delay, now);
        assert_eq!(q.peek_due(now), None);
        assert_eq!(q.pop_due(now + delay), Some((100, 128)));

        // A bulk frame > 1024 sets `bulk_barrier`; trailing small frames wait
        // until peer ACK catches up past the bulk frame.
        q.on_primary_data(100, 484, 4096, 1024, delay, now);
        q.on_primary_data(100, 4580, 64, 1024, delay, now);
        assert_eq!(q.pop_due(now + delay), Some((228, 256)));
        assert!(q.is_empty());

        // Once peer ACK passes 4580, small frames resume cleanly even when
        // primary cursor is already ahead of `acked` (streaming RTT case).
        q.on_primary_data(4580, 4610, 64, 1024, delay, now);
        assert_eq!(q.peek_due(now + delay), Some((4610, 64)));

        // Shedding via `drop_due(4580)` clears pending items without wedging
        // future small frames sent ahead of `acked`.
        q.drop_due(4580);
        assert!(q.is_empty());
        q.on_primary_data(4580, 4674, 64, 1024, delay, now);
        assert_eq!(q.pop_due(now + delay), Some((4674, 64)));

        // Exceeding `DUP_QUEUE_CAP` (32) evicts oldest and retains newest 32.
        for i in 0..40u64 {
            q.on_primary_data(4738, 4738 + i * 16, 16, 1024, delay, now);
        }
        let mut items = Vec::new();
        while let Some(it) = q.pop_due(now + delay) {
            items.push(it);
        }
        assert_eq!(items.len(), DUP_QUEUE_CAP);
        assert_eq!(items.first().copied(), Some((4738 + 8 * 16, 16)));
        assert_eq!(items.last().copied(), Some((4738 + 39 * 16, 16)));
    }

    #[test]
    fn recv_ai_retains_window_until_idle_after_ai_or_pool_pressure() {
        let pool = Pool::new(8 << 20);
        let l = Limits::default();
        let timing = Timing::default();
        let mut t = Instant::now();
        let mut s = SendHalf::new(&pool, &l).unwrap();
        let mut r = RecvHalf::new_with_idle(&pool, &l, &timing, timing.idle_after_ai, t).unwrap();
        let mut out = vec![0u8; 64 * 1024];
        let mut sent = 0;
        while sent < 256 * 1024 {
            let cap = s.write_capacity_for(16 * 1024);
            let n = s.write(&vec![5u8; cap.min(16 * 1024)]);
            sent += n;
            t += Duration::from_millis(1);
            pump(&mut s, &mut r, t);
            while r.read(&mut out, t) > 0 {}
            pump(&mut s, &mut r, t);
        }
        let grown_win = r.target_window();
        assert!(grown_win > l.initial_credit);

        // After 10 s (< idle_after_ai = 60 s) with no pool pressure, the AI
        // receive window remains elevated.
        let idle_10s = t + Duration::from_secs(10);
        r.update_credit(idle_10s);
        assert_eq!(r.target_window(), grown_win);
        assert_eq!(r.idle_deadline(), Some(t + timing.idle_after_ai));

        // Putting the pool under pressure switches idle fallback back to 1 s
        // so idle memory is returned immediately.
        let _hog = Grant::between(&pool, 7 << 20, 7 << 20, Tier::Elastic);
        assert!(pool.under_pressure());
        assert_eq!(r.idle_deadline(), Some(t + timing.idle_after));
        r.update_credit(idle_10s);
        assert_eq!(r.target_window(), l.initial_credit);
    }

    #[test]
    fn dup_queue_seed_inflight_chunks_multiple_segments() {
        let now = Instant::now();
        let delay = Duration::from_millis(30);
        let mut q = DupQueue::new(100);
        // 2500 B in-flight (> max_bytes 1024) must split cleanly into 3 chunks
        // and not wipe earlier chunks via swapped `(acked, offset)` arguments.
        q.seed_inflight(100, 2600, 1024, delay, now);
        assert_eq!(q.pop_due(now + delay), Some((100, 1024)));
        assert_eq!(q.pop_due(now + delay), Some((1124, 1024)));
        assert_eq!(q.pop_due(now + delay), Some((2148, 452)));
        assert!(q.is_empty());
    }

    #[test]
    fn recv_ooo_parks_and_drains_on_gap_fill_and_slice_reads_wrapped() {
        let now = Instant::now();
        let pool = Pool::new(8 << 20);
        let limits = Limits {
            initial_credit: 64 * 1024,
            ..Limits::default()
        };
        let mut r = RecvHalf::new(&pool, &limits, &Timing::default(), now).unwrap();

        // Ahead-of-order chunk parks cleanly without error.
        assert_eq!(r.on_data_ooo(100, b"world!", now).unwrap(), 0);
        assert_eq!(r.recv_offset(), 0);
        // Exact duplicate/covered OOO chunk is ignored without inflating buffer.
        assert_eq!(r.on_data_ooo(101, b"orld", now).unwrap(), 0);
        // Missing prefix fills the gap and drains both segments contiguously.
        assert_eq!(r.on_data_ooo(0, &[b'a'; 100], now).unwrap(), 106);
        assert_eq!(r.recv_offset(), 106);

        let mut head = [0u8; 64];
        assert_eq!(r.read(&mut head, now), 64);
        assert_eq!(&head[..], &[b'a'; 64][..]);
        let mut rest = [0u8; 64];
        assert_eq!(r.read(&mut rest, now), 42);
        assert_eq!(&rest[..36], &[b'a'; 36][..]);
        assert_eq!(&rest[36..42], b"world!");

        // Segment > OOO_MAX_BYTES is skipped best-effort without error or parking.
        let base = r.recv_offset();
        let huge = vec![0x5a; OOO_MAX_BYTES + 1];
        assert_eq!(r.on_data_ooo(base + 100, &huge, now).unwrap(), 0);
        // Filling [base, base + 100) must NOT pull `huge` from OOO (it was dropped).
        assert_eq!(r.on_data_ooo(base, &[0x33u8; 100], now).unwrap(), 100);
        assert_eq!(r.recv_offset(), base + 100);

        // Force VecDeque wrap and verify slice-based `read()` copies exact bytes.
        let mut flush_buf = vec![0u8; 256];
        assert_eq!(r.read(&mut flush_buf, now), 100);
        let p1: Vec<u8> = (0..8 * 1024).map(|i| (i % 251) as u8).collect();
        let p2: Vec<u8> = (0..8 * 1024).map(|i| ((i + 7) % 251) as u8).collect();
        assert_eq!(r.on_data(r.recv_offset(), &p1, now).unwrap(), p1.len());
        let mut drain = vec![0u8; 4 * 1024];
        assert_eq!(r.read(&mut drain, now), 4 * 1024);
        assert_eq!(&drain[..], &p1[..4 * 1024]);
        assert_eq!(r.on_data(r.recv_offset(), &p2, now).unwrap(), p2.len());
        let mut merged = vec![0u8; 12 * 1024];
        assert_eq!(r.read(&mut merged, now), 12 * 1024);
        assert_eq!(&merged[..4 * 1024], &p1[4 * 1024..]);
        assert_eq!(&merged[4 * 1024..], &p2[..]);
    }
}
