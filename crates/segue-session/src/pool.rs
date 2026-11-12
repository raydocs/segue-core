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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

pub const BLOCK: usize = 4096;

pub fn blocks_for(bytes: usize) -> usize {
    bytes.div_ceil(BLOCK)
}

#[derive(Debug)]
pub struct Pool {
    blocks: usize,
    used: AtomicUsize,
    sessions: AtomicUsize,
    waiters: AtomicUsize,
    freed: Notify,
}

impl Pool {
    pub fn new(bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            blocks: bytes / BLOCK,
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

    /// Fewer than 25 % of blocks free.
    pub fn under_pressure(&self) -> bool {
        let used = self.used.load(Ordering::Acquire);
        (self.blocks - used.min(self.blocks)) * 4 < self.blocks
    }

    /// Equal share per live session (floor one block).
    pub fn fair_share_bytes(&self) -> usize {
        let n = self.sessions.load(Ordering::Acquire).max(1);
        (self.blocks / n).max(1) * BLOCK
    }

    fn try_take(&self, n: usize) -> bool {
        n == 0 || self.take_blocks(n, n, self.blocks) == n
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
}

impl Grant {
    /// An empty grant. `counted` grants take part in the fair-share count.
    pub fn new(pool: &Arc<Pool>, counted: bool) -> Self {
        if counted {
            pool.sessions.fetch_add(1, Ordering::AcqRel);
        }
        Self {
            pool: pool.clone(),
            blocks: 0,
            counted,
        }
    }

    /// Exactly `bytes` (rounded up to blocks), for buffers whose size is
    /// fixed for their lifetime (driver I/O buffers and queues). Not counted
    /// in the fair share. `None` when the pool cannot cover it.
    pub fn fixed(pool: &Arc<Pool>, bytes: usize) -> Option<Self> {
        let mut g = Self::new(pool, false);
        g.try_resize(bytes).then_some(g)
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
        } else if self.pool.try_take(want - self.blocks) {
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
            while self.blocks < blocks_for(bytes) && self.pool.try_take(1) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_overcommits() {
        let pool = Pool::new(10 * BLOCK);
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
}
