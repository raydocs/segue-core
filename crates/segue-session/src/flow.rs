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

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use crate::codec::{max_data_len, Frame};
use crate::pool::{Grant, Pool};
use crate::{Limits, ProtoError, Timing};

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

impl SendHalf {
    pub fn new(pool: &Arc<Pool>, limits: &Limits) -> Self {
        Self {
            acked: 0,
            buf: VecDeque::new(),
            cursor: 0,
            sent_hw: 0,
            peer_max: limits.initial_credit as u64,
            fin: None,
            grant: Grant::new(pool, false),
            replay_cap: limits.replay_cap,
            promised: 0,
        }
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

    /// Queue application bytes. Returns how many were accepted (backpressure:
    /// bounded by the replay cap and the pool).
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.write_capacity());
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
        if self.acked != 0 {
            return Vec::new();
        }
        let n = limit.min(self.buf.len()).min(self.peer_max as usize);
        let v: Vec<u8> = self.buf.iter().take(n).copied().collect();
        self.cursor = self.cursor.max(n as u64);
        self.sent_hw = self.sent_hw.max(n as u64);
        v
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
        let keep = self.buf.len() + self.promised;
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

    /// Next DATA or FIN for the current carrier, within the peer's window.
    pub fn poll_frame(&mut self) -> Option<Frame> {
        let end = self.data_end();
        if self.cursor < end {
            let lim = end.min(self.peer_max);
            if self.cursor < lim {
                let n = ((lim - self.cursor) as usize).min(max_data_len(self.cursor, 0));
                let start = (self.cursor - self.acked) as usize;
                let data: Vec<u8> = self.buf.range(start..start + n).copied().collect();
                let offset = self.cursor;
                self.cursor += n as u64;
                self.sent_hw = self.sent_hw.max(self.cursor);
                return Some(Frame::Data {
                    offset,
                    data,
                    pad: 0,
                });
            }
            return None;
        }
        if let Some(f) = self.fin {
            if self.cursor == f {
                self.cursor = f + 1;
                self.sent_hw = self.sent_hw.max(f + 1);
                return Some(Frame::Fin { offset: f });
            }
        }
        None
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

#[derive(Debug)]
pub struct RecvHalf {
    consumed: u64,
    buf: VecDeque<u8>,
    recv: u64,
    adv_max: u64,
    fin: Option<u64>,
    grant: Grant,
    min_credit: usize,
    window_cap: usize,
    idle_after: std::time::Duration,
    ack_delay: std::time::Duration,
    last_ack: (u64, u64),
    pending_since: Option<Instant>,
    last_data: Instant,
}

impl RecvHalf {
    /// Takes the protocol's initial credit from the pool; `None` when the
    /// pool cannot cover it (→ `REJECT(capacity)` / local REFUSE).
    pub fn new(pool: &Arc<Pool>, limits: &Limits, timing: &Timing, now: Instant) -> Option<Self> {
        let mut grant = Grant::new(pool, true);
        if !grant.try_resize(limits.initial_credit) {
            return None;
        }
        let initial = limits.initial_credit as u64;
        Some(Self {
            consumed: 0,
            buf: VecDeque::new(),
            recv: 0,
            adv_max: initial,
            fin: None,
            grant,
            min_credit: limits.min_credit,
            window_cap: limits.window_cap.max(limits.initial_credit),
            idle_after: timing.idle_after,
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
        self.last_data = now;
        self.touch(now);
        Ok(fresh.len())
    }

    pub fn on_fin(&mut self, offset: u64, now: Instant) -> Result<(), ProtoError> {
        match self.fin {
            Some(f) if f == offset => Ok(()),
            Some(_) => Err(ProtoError::Violation("fin moved")),
            None if offset != self.recv => Err(ProtoError::Violation("fin not at recv_offset")),
            None => {
                self.fin = Some(offset);
                self.recv = offset + 1;
                self.touch(now);
                Ok(())
            }
        }
    }

    /// Hand buffered bytes to the application.
    pub fn read(&mut self, out: &mut [u8], now: Instant) -> usize {
        let n = out.len().min(self.buf.len());
        for (o, b) in out.iter_mut().zip(self.buf.drain(..n)) {
            *o = b;
        }
        self.consumed += n as u64;
        if n > 0 {
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
            return;
        }
        let outstanding = (self.adv_max - self.consumed) as usize;
        let active =
            !self.buf.is_empty() || now.saturating_duration_since(self.last_data) < self.idle_after;
        let mut desired = if active {
            self.window_cap
        } else {
            self.min_credit
        };
        if !active {
            // Idle and drained: the buffer's memory goes back now; it is
            // re-reserved (within the grant) when data arrives.
            self.buf.shrink_to_fit();
        }
        let pool = self.grant.pool();
        if pool.under_pressure() {
            desired = desired.min(pool.fair_share_bytes());
        }
        let need = desired.max(self.min_credit).max(outstanding);
        if need <= self.grant.bytes() {
            self.grant.try_resize(need);
            fit(&mut self.buf, self.grant.bytes());
        } else {
            self.grant.grow_towards(need);
        }
        let new_max = self.consumed + self.grant.bytes() as u64;
        if new_max > self.adv_max {
            self.adv_max = new_max;
            self.touch(now);
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
    }

    /// Idle check for timeouts: lets credit fall back when no data arrives.
    pub fn idle_deadline(&self) -> Option<Instant> {
        // Buffered data keeps the flow active (`update_credit` would not
        // shrink), so there is nothing to time out until it is read.
        if self.fin.is_some()
            || !self.buf.is_empty()
            || self.grant.bytes() <= self.min_credit.max((self.adv_max - self.consumed) as usize)
        {
            return None;
        }
        Some(self.last_data + self.idle_after)
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
            SendHalf::new(&pool, &l),
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
        let pool = Pool::new(64 * 1024);
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
        assert!(r.held_bytes() <= r.grant_bytes(), "{} > {}", r.held_bytes(), r.grant_bytes());
        assert_eq!(r.held_bytes(), 0, "idle drained receive buffer keeps {peak} bytes");
    }
}
