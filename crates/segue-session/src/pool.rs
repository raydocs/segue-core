//! Global buffer pool (§4 rule 8, KERNEL_SPEC §6.3).
//!
//! The pool is counted in 4 KB blocks. A session never reserves memory up
//! front; it holds a [`Grant`] that grows and shrinks. The sum of all grants
//! never exceeds the pool (`try_resize` fails instead of overcommitting), and
//! every byte a session buffers is covered by its grant, so the pool size is
//! a hard bound on buffered session data.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub const BLOCK: usize = 4096;

pub fn blocks_for(bytes: usize) -> usize {
    bytes.div_ceil(BLOCK)
}

#[derive(Debug)]
pub struct Pool {
    blocks: usize,
    used: AtomicUsize,
    sessions: AtomicUsize,
}

impl Pool {
    pub fn new(bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            blocks: bytes / BLOCK,
            used: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
        })
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
        let mut cur = self.used.load(Ordering::Acquire);
        loop {
            if cur + n > self.blocks {
                return false;
            }
            match self
                .used
                .compare_exchange_weak(cur, cur + n, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    fn give(&self, n: usize) {
        self.used.fetch_sub(n, Ordering::AcqRel);
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
