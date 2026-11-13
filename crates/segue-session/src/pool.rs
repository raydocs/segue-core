//! Global buffer pool (§4 rule 8, KERNEL_SPEC §6.3).
//!
//! The pool is counted in 4 KB blocks. A session never reserves memory up
//! front; it holds a [`Grant`] that grows and shrinks. The sum of all grants
//! never exceeds the pool (`try_resize` fails instead of overcommitting), and
//! every byte a session buffers is covered by its grant, so the pool size is
//! a hard bound on buffered session data.
//!
//! A grant is charged for the memory a buffer actually holds, not for the
//! bytes in it: buffers keep their capacity within their grant (see
//! `flow.rs`), so returning blocks to the pool also returns the memory.
//! The same pool can back other users of the process budget (the TUN
//! stack's rings and relay chunks, KERNEL_SPEC §6.3 "本地 TCP 收发缓冲、会话
//! 接收缓冲、回放缓冲都从池里取") through [`Pool::take_blocks`] /
//! [`Pool::give_blocks`].
//!
//! Progress without per-session reserves (r6 R5/R6). Buffers fall in two
//! kinds. *Elastic* ones (receive windows, replay buffers, pipe and TUN ring
//! growth, admission floors) may be held for as long as the peer or the
//! application likes. *Draining* ones (a frame queued to a carrier, a frame
//! just read from one, a chunk on its way to the application or the TUN)
//! are freed as soon as the next stage takes them, and that stage always
//! has a floor of its own. The top of the pool is kept for the draining
//! kinds in [`Tier`]s: elastic grants stop at [`Tier::Elastic`]'s limit, and
//! each draining kind may go up to its own, higher limit. A tier's holders
//! only ever wait for stages of a *higher* tier (or for the network and
//! the application), so the waits form no cycle and a pool full of elastic
//! grants still moves bytes: transport frames wait for nothing in the pool,
//! TUN relay chunks only for transport frames, and received bytes go from a
//! session's receive buffer to its application end with no buffer of their
//! own (the TUN takes them only into ring room it has). The regions are a few
//! frames in size and shared by every session, so admission costs only the
//! per-flow floors (§4 rule 8: 16 KB initial credit, one replay block, one
//! pipe block each way).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

pub const BLOCK: usize = 4096;

pub fn blocks_for(bytes: usize) -> usize {
    bytes.div_ceil(BLOCK)
}

/// Who may take blocks how far (see the module docs). Ordered: a higher
/// tier may use everything a lower one may, plus its own region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Grants that may be held indefinitely, and admission.
    Elastic,
    /// TUN relay chunks (stack ↔ relay task).
    Relay,
    /// Frames queued to, or just read from, a carrier.
    Transport,
}

/// Default regions on top of the elastic part, in blocks: two full
/// frames for carriers, four 16 KiB chunks for the TUN relay.
pub const TRANSPORT_REGION: usize = 2 * FRAME_MAX.div_ceil(BLOCK);
pub const RELAY_REGION: usize = 16;

#[derive(Debug)]
pub struct Pool {
    blocks: usize,
    /// Highest `used` each [`Tier`] may reach, ascending.
    limits: [usize; 3],
    used: AtomicUsize,
    sessions: AtomicUsize,
    waiters: AtomicUsize,
    freed: Notify,
}

impl Pool {
    /// `bytes` with the default regions, each at most an eighth of the
    /// pool (a tiny test pool is almost all elastic).
    pub fn new(bytes: usize) -> Arc<Self> {
        let blocks = bytes / BLOCK;
        let cap = |r: usize| r.min(blocks / 8);
        Self::with_regions(bytes, cap(RELAY_REGION), cap(TRANSPORT_REGION))
    }

    /// `bytes` with explicit draining regions (blocks) above the elastic
    /// part.
    pub fn with_regions(bytes: usize, relay: usize, transport: usize) -> Arc<Self> {
        let blocks = bytes / BLOCK;
        let relay_top = blocks.saturating_sub(transport);
        let elastic = relay_top.saturating_sub(relay);
        Arc::new(Self {
            blocks,
            limits: [elastic, relay_top, blocks],
            used: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
            waiters: AtomicUsize::new(0),
            freed: Notify::new(),
        })
    }

    /// Pool size in blocks.
    pub fn blocks(&self) -> usize {
        self.blocks
    }

    /// Highest number of blocks in use up to which `tier` may take.
    pub fn limit(&self, tier: Tier) -> usize {
        self.limits[tier as usize]
    }

    /// Take 1..=`want` blocks within `tier`; 0 if none is free there.
    pub fn take_tier(&self, want: usize, tier: Tier) -> usize {
        self.take_blocks(want, 1, self.limit(tier))
    }

    /// Blocks in use.
    pub fn used_blocks(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub fn capacity_bytes(&self) -> usize {
        self.blocks * BLOCK
    }

    pub fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Acquire) * BLOCK
    }

    /// Fewer than 25 % of the elastic blocks free.
    pub fn under_pressure(&self) -> bool {
        let elastic = self.limit(Tier::Elastic);
        let used = self.used.load(Ordering::Acquire);
        (elastic - used.min(elastic)) * 4 < elastic
    }

    /// Equal share of the elastic part per live session (floor one block).
    pub fn fair_share_bytes(&self) -> usize {
        let n = self.sessions.load(Ordering::Acquire).max(1);
        (self.limit(Tier::Elastic) / n).max(1) * BLOCK
    }

    fn try_take(&self, n: usize, tier: Tier) -> bool {
        n == 0 || self.take_blocks(n, n, self.limit(tier)) == n
    }

    fn give(&self, n: usize) {
        self.give_blocks(n);
    }

    /// Take up to `want` blocks (at least `min`, else none) while the pool
    /// stays at or under `limit` blocks in use. Returns the blocks taken;
    /// the caller returns them with [`give_blocks`](Self::give_blocks).
    pub fn take_blocks(&self, want: usize, min: usize, limit: usize) -> usize {
        let limit = limit.min(self.blocks);
        let mut cur = self.used.load(Ordering::Acquire);
        loop {
            let n = want.min(limit.saturating_sub(cur));
            if n == 0 || n < min {
                return 0;
            }
            match self
                .used
                .compare_exchange_weak(cur, cur + n, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return n,
                Err(v) => cur = v,
            }
        }
    }

    /// Return blocks taken with [`take_blocks`](Self::take_blocks) and wake
    /// whoever waits in [`freed`](Self::freed).
    pub fn give_blocks(&self, n: usize) {
        if n == 0 {
            return;
        }
        self.used.fetch_sub(n, Ordering::AcqRel);
        if self.waiters.load(Ordering::Acquire) > 0 {
            self.freed.notify_waiters();
        }
    }

    /// Resolves when blocks are returned (or spuriously).
    pub async fn freed(&self) {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        let _w = Waiting(&self.waiters);
        self.freed.notified().await;
    }

    /// Run `f` until it returns `Some`, waiting for blocks to be returned
    /// between attempts.
    pub async fn wait_for<T>(&self, mut f: impl FnMut() -> Option<T>) -> T {
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if let Some(v) = f() {
                return v;
            }
            self.waiters.fetch_add(1, Ordering::AcqRel);
            let _w = Waiting(&self.waiters);
            if let Some(v) = f() {
                return v;
            }
            freed.await;
        }
    }
}

struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Blocks held by one buffer. Released on drop.
#[derive(Debug)]
pub struct Grant {
    pool: Arc<Pool>,
    blocks: usize,
    counted: bool,
    tier: Tier,
}

impl Grant {
    /// An empty elastic grant. `counted` grants take part in the
    /// fair-share count.
    pub fn new(pool: &Arc<Pool>, counted: bool) -> Self {
        if counted {
            pool.sessions.fetch_add(1, Ordering::AcqRel);
        }
        Self {
            pool: pool.clone(),
            blocks: 0,
            counted,
            tier: Tier::Elastic,
        }
    }

    /// Exactly `bytes` (rounded up to blocks), elastic, for buffers whose
    /// size is fixed for their lifetime (floors). Not counted in the fair
    /// share. `None` when the pool cannot cover it.
    pub fn fixed(pool: &Arc<Pool>, bytes: usize) -> Option<Self> {
        Self::fixed_in(pool, bytes, Tier::Elastic)
    }

    /// Exactly `bytes` within `tier` (a draining buffer), all or nothing.
    pub fn fixed_in(pool: &Arc<Pool>, bytes: usize, tier: Tier) -> Option<Self> {
        let mut g = Self::new(pool, false);
        g.tier = tier;
        g.try_resize(bytes).then_some(g)
    }

    /// Between one block and `bytes` within `tier`, as much as is free;
    /// `None` when not even one block is (a draining buffer that can be
    /// made smaller).
    pub fn up_to(pool: &Arc<Pool>, bytes: usize, tier: Tier) -> Option<Self> {
        Self::between(pool, BLOCK, bytes, tier)
    }

    /// Between `min` and `want` bytes (rounded up to blocks, at least one)
    /// within `tier`, as much as is free; `None` below `min`.
    pub fn between(pool: &Arc<Pool>, min: usize, want: usize, tier: Tier) -> Option<Self> {
        let min = blocks_for(min).max(1);
        let n = pool.take_blocks(blocks_for(want).max(min), min, pool.limit(tier));
        (n > 0).then(|| Self {
            pool: pool.clone(),
            blocks: n,
            counted: false,
            tier,
        })
    }

    pub fn tier(&self) -> Tier {
        self.tier
    }

    pub fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }

    pub fn bytes(&self) -> usize {
        self.blocks * BLOCK
    }

    /// Resize to cover `bytes`. Shrinking always succeeds; growing is
    /// all-or-nothing and returns false when the pool cannot cover it.
    pub fn try_resize(&mut self, bytes: usize) -> bool {
        let want = blocks_for(bytes);
        if want <= self.blocks {
            self.pool.give(self.blocks - want);
            self.blocks = want;
            true
        } else if self.pool.try_take(want - self.blocks, self.tier) {
            self.blocks = want;
            true
        } else {
            false
        }
    }

    /// Grow as far as possible towards `bytes`, one block at a time when the
    /// pool is short. Returns the bytes now held.
    pub fn grow_towards(&mut self, bytes: usize) -> usize {
        if !self.try_resize(bytes.max(self.bytes())) {
            while self.blocks < blocks_for(bytes) && self.pool.try_take(1, self.tier) {
                self.blocks += 1;
            }
        }
        self.bytes()
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.pool.give(self.blocks);
        if self.counted {
            self.pool.sessions.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Largest encoded frame (payload plus type and length).
pub const FRAME_MAX: usize = crate::codec::MAX_PAYLOAD + 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_overcommits() {
        let pool = Pool::with_regions(10 * BLOCK, 0, 0);
        let mut a = Grant::new(&pool, true);
        let mut b = Grant::new(&pool, true);
        assert!(a.try_resize(6 * BLOCK));
        assert!(!b.try_resize(5 * BLOCK));
        assert_eq!(b.bytes(), 0);
        assert_eq!(b.grow_towards(5 * BLOCK), 4 * BLOCK);
        assert_eq!(pool.used_bytes(), 10 * BLOCK);
        assert!(pool.under_pressure());
        assert!(a.try_resize(BLOCK));
        assert_eq!(pool.used_bytes(), 5 * BLOCK);
        drop(a);
        drop(b);
        assert_eq!(pool.used_bytes(), 0);
        assert_eq!(pool.fair_share_bytes(), 10 * BLOCK);
    }

    #[test]
    fn thousand_idle_sessions_fit_8mb() {
        // §4 rule 8 arithmetic: 1000 × 4 KB floor = 4 MB of an 8 MB pool.
        let pool = Pool::new(8 << 20);
        let grants: Vec<_> = (0..1000)
            .map(|_| {
                let mut g = Grant::new(&pool, true);
                assert!(g.try_resize(BLOCK));
                g
            })
            .collect();
        assert_eq!(pool.used_bytes(), 1000 * BLOCK);
        assert!(!pool.under_pressure());
        drop(grants);
        assert_eq!(pool.used_bytes(), 0);
    }

    #[test]
    fn draining_tiers_keep_room_above_elastic_grants() {
        let pool = Pool::with_regions(20 * BLOCK, 4, 4);
        assert_eq!(pool.limit(Tier::Elastic), 12);
        // Elastic grants stop below every region, however hard they try.
        let mut hog = Grant::new(&pool, true);
        assert_eq!(hog.grow_towards(1 << 20), 12 * BLOCK);
        assert!(Grant::fixed(&pool, BLOCK).is_none());
        // Each draining tier reaches its own limit, and no further.
        let relay = Grant::up_to(&pool, 1 << 20, Tier::Relay).unwrap();
        assert_eq!(relay.bytes(), 4 * BLOCK);
        assert!(Grant::up_to(&pool, BLOCK, Tier::Relay).is_none());
        let frame = Grant::fixed_in(&pool, 4 * BLOCK, Tier::Transport).unwrap();
        assert!(Grant::fixed_in(&pool, BLOCK, Tier::Transport).is_none());
        assert_eq!(pool.used_bytes(), 20 * BLOCK);
        drop((relay, frame));
        // Under pressure the fair share is of the elastic part.
        assert!(pool.under_pressure());
        assert_eq!(pool.fair_share_bytes(), 12 * BLOCK);
        drop(hog);
        assert_eq!(pool.used_bytes(), 0);
    }

    #[test]
    fn default_regions_leave_most_of_8mb_elastic() {
        let pool = Pool::new(8 << 20);
        let reserved = pool.blocks() - pool.limit(Tier::Elastic);
        assert_eq!(reserved, RELAY_REGION + TRANSPORT_REGION);
        assert!(reserved * BLOCK <= 320 << 10, "{reserved} blocks");
        // A small pool keeps at most an eighth per region.
        let small = Pool::new(16 * BLOCK);
        assert_eq!(small.limit(Tier::Elastic), 16 - 4);
    }
}
