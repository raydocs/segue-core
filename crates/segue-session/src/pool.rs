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
//!
//! The transport region is disjoint (r7 #1): it is counted on its own, so
//! frames of carriers that stopped moving can never take the relay region,
//! and nothing else can take it. Its blocks are handed out in arrival
//! order to [`Ticket`] holders, so a session whose carrier is healthy gets
//! the next freed frame instead of racing every waiter for it; the driver
//! bounds how long a frame may hold transport blocks (a carrier that does
//! not move it in time is dropped and its data replayed on a new one).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

pub const BLOCK: usize = 4096;

pub fn blocks_for(bytes: usize) -> usize {
    bytes.div_ceil(BLOCK)
}

/// Who may take blocks how far (see the module docs). Ordered: the relay
/// tier may use everything the elastic one may, plus its own region; the
/// transport tier has only its own, disjoint region (a frame first tries
/// elastic blocks, see the driver).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Grants that may be held indefinitely, and admission.
    Elastic,
    /// TUN relay chunks (stack ↔ relay task).
    Relay,
    /// Frames queued to, or just read from, a carrier.
    Transport,
}

/// Default [`Pool::transport_hold`]: how long a frame holding the
/// transport region may go with *no byte of it* moving. Well above the gap
/// between reads or writes on a working carrier, short enough that
/// carriers that stopped moving cannot keep the region from healthy ones
/// for long. Progress-based (r8 N5): a slow carrier that keeps moving the
/// frame is not cut by it.
pub const TRANSPORT_HOLD: Duration = Duration::from_secs(2);
/// Default [`Pool::transport_hold_max`]: overall bound on one frame's
/// hold, however it progresses. A [`FRAME_MAX`] frame within it needs
/// about 550 B/s.
pub const TRANSPORT_HOLD_MAX: Duration = Duration::from_secs(30);
/// Default regions on top of the elastic part, in blocks: two full
/// frames for carriers, four 16 KiB chunks for the TUN relay.
pub const TRANSPORT_REGION: usize = 2 * FRAME_MAX.div_ceil(BLOCK);
pub const RELAY_REGION: usize = 16;

#[derive(Debug)]
pub struct Pool {
    blocks: usize,
    /// Highest `used` each [`Tier`] may reach, ascending (the transport
    /// entry is the pool size, for [`limit`](Self::limit)).
    limits: [usize; 3],
    /// Blocks taken outside the transport region.
    used: AtomicUsize,
    /// Size of the transport region, and the blocks taken from it.
    transport: usize,
    transport_used: AtomicUsize,
    /// Tickets waiting for the transport region, oldest first.
    queue: Mutex<TicketQueue>,
    /// How long a frame may hold transport blocks without progress, and
    /// at most (milliseconds).
    hold_ms: AtomicU64,
    hold_max_ms: AtomicU64,
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
            transport: blocks - relay_top,
            transport_used: AtomicUsize::new(0),
            queue: Mutex::new(TicketQueue::default()),
            hold_ms: AtomicU64::new(TRANSPORT_HOLD.as_millis() as u64),
            hold_max_ms: AtomicU64::new(TRANSPORT_HOLD_MAX.as_millis() as u64),
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
        self.used.load(Ordering::Acquire) + self.transport_used.load(Ordering::Acquire)
    }

    /// Size of the transport region in blocks.
    pub fn transport_blocks(&self) -> usize {
        self.transport
    }

    /// Blocks taken from the transport region.
    pub fn transport_used_blocks(&self) -> usize {
        self.transport_used.load(Ordering::Acquire)
    }

    pub fn capacity_bytes(&self) -> usize {
        self.blocks * BLOCK
    }

    pub fn used_bytes(&self) -> usize {
        self.used_blocks() * BLOCK
    }

    /// Fewer than 25 % of the elastic blocks free.
    pub fn under_pressure(&self) -> bool {
        let elastic = self.limit(Tier::Elastic);
        let used = self.used_blocks();
        (elastic - used.min(elastic)) * 4 < elastic
    }

    /// Equal share of the elastic part per live session (floor one block).
    pub fn fair_share_bytes(&self) -> usize {
        let n = self.sessions.load(Ordering::Acquire).max(1);
        (self.limit(Tier::Elastic) / n).max(1) * BLOCK
    }

    fn try_take(&self, n: usize, tier: Tier) -> bool {
        n == 0
            || match tier {
                Tier::Transport => self.take_transport(n, n, None) == n,
                _ => self.take_blocks(n, n, self.limit(tier)) == n,
            }
    }

    fn give(&self, n: usize, tier: Tier) {
        match tier {
            Tier::Transport => self.give_counter(&self.transport_used, n),
            _ => self.give_blocks(n),
        }
    }

    /// Take up to `want` blocks (at least `min`, else none) while the pool
    /// stays at or under `limit` blocks in use. Returns the blocks taken;
    /// the caller returns them with [`give_blocks`](Self::give_blocks).
    /// Never reaches into the transport region.
    pub fn take_blocks(&self, want: usize, min: usize, limit: usize) -> usize {
        self.take_counter(
            &self.used,
            want,
            min,
            limit.min(self.blocks - self.transport),
        )
    }

    /// Take from the transport region. The oldest waiting [`Ticket`] has
    /// what it last asked for reserved: everyone else takes only what
    /// leaves that much free, so blocks given back go to the first in line
    /// as soon as they cover it, however many others retry (r7 #1).
    ///
    /// The reservation is read and the blocks are claimed under the queue
    /// lock (r8 N6): the first in line cannot raise what it needs between
    /// another taker's check and its claim, so a reservation, once made, is
    /// never taken from. Blocks given back only lower the count, so they
    /// need no lock.
    fn take_transport(&self, want: usize, min: usize, ticket: Option<&Ticket>) -> usize {
        let mut q = self.queue.lock().unwrap();
        let head_id = q.ids.front().map(|(id, _)| *id);
        let reserve = match head_id {
            None => 0,
            Some(h) if ticket.is_some_and(|t| t.id == h) => {
                q.need = min.min(self.transport);
                0
            }
            Some(_) => q.need,
        };
        #[cfg(test)]
        tests::between_check_and_claim();
        let n = self.take_counter(&self.transport_used, want, min, self.transport - reserve);
        drop(q);
        n
    }

    fn take_counter(&self, c: &AtomicUsize, want: usize, min: usize, limit: usize) -> usize {
        let mut cur = c.load(Ordering::Acquire);
        loop {
            let n = want.min(limit.saturating_sub(cur));
            if n == 0 || n < min {
                return 0;
            }
            match c.compare_exchange_weak(cur, cur + n, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return n,
                Err(v) => cur = v,
            }
        }
    }

    /// Return blocks taken with [`take_blocks`](Self::take_blocks) and wake
    /// whoever waits in [`freed`](Self::freed).
    pub fn give_blocks(&self, n: usize) {
        self.give_counter(&self.used, n);
    }

    fn give_counter(&self, c: &AtomicUsize, n: usize) {
        if n == 0 {
            return;
        }
        c.fetch_sub(n, Ordering::AcqRel);
        self.wake();
    }

    fn wake(&self) {
        self.wake_head();
        if self.waiters.load(Ordering::Acquire) > 0 {
            self.freed.notify_waiters();
        }
    }

    fn wake_head(&self) {
        if let Some((_, w)) = self.queue.lock().unwrap().ids.front() {
            w.notify_one();
        }
    }

    /// A place in line for the transport region (see [`Grant::transport`]).
    /// Dropping it leaves the line.
    pub fn ticket(self: &Arc<Self>) -> Ticket {
        let mut q = self.queue.lock().unwrap();
        q.next += 1;
        let id = q.next;
        let wake = Arc::new(Notify::new());
        if q.ids.is_empty() {
            q.need = 1;
        }
        q.ids.push_back((id, wake.clone()));
        Ticket {
            pool: self.clone(),
            id,
            wake,
        }
    }

    /// How long a frame holding transport-region blocks may go without
    /// any of its bytes moving before its carrier is given up (its data is
    /// replayed on the next one).
    pub fn transport_hold(&self) -> Duration {
        Duration::from_millis(self.hold_ms.load(Ordering::Relaxed))
    }

    pub fn set_transport_hold(&self, d: Duration) {
        self.hold_ms
            .store(d.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    /// Overall bound on one frame's hold of transport-region blocks,
    /// however steadily it moves.
    pub fn transport_hold_max(&self) -> Duration {
        Duration::from_millis(self.hold_max_ms.load(Ordering::Relaxed))
    }

    pub fn set_transport_hold_max(&self, d: Duration) {
        self.hold_max_ms
            .store(d.as_millis().max(1) as u64, Ordering::Relaxed);
    }

    /// Tickets waiting for the transport region.
    pub fn queued(&self) -> usize {
        self.queue.lock().unwrap().ids.len()
    }

    /// Resolves when blocks are returned (or spuriously).
    pub async fn freed(&self) {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        let _w = Waiting(&self.waiters);
        self.freed.notified().await;
    }

    /// Listen for blocks (or a turn for the transport region) given back
    /// from now on; await with [`Armed::wait`]. Take it before the last
    /// attempt, so nothing given in between is missed.
    pub fn armed(&self) -> Armed<'_> {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        let _w = Waiting(&self.waiters);
        let mut n = Box::pin(self.freed.notified());
        n.as_mut().enable();
        Armed { n, _w }
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

#[derive(Debug, Default)]
struct TicketQueue {
    next: u64,
    /// Blocks reserved for the first in line (what it last asked for).
    need: usize,
    ids: VecDeque<(u64, Arc<Notify>)>,
}

/// A waiter's place in line for the transport region; see [`Pool::ticket`].
#[derive(Debug)]
pub struct Ticket {
    pool: Arc<Pool>,
    id: u64,
    wake: Arc<Notify>,
}

impl Ticket {
    /// Resolves once this ticket may have a turn: it became first in line,
    /// or blocks were given back while it was. Only the first in line is
    /// woken (no herd of every waiter), and a wake that comes before this is
    /// awaited is kept, so none is missed.
    pub async fn ready(&self) {
        self.wake.notified().await
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let head = {
            let mut q = self.pool.queue.lock().unwrap();
            let head = q.ids.front().is_some_and(|(i, _)| *i == self.id);
            q.ids.retain(|(i, _)| *i != self.id);
            if head {
                // Unknown until the new first in line asks.
                q.need = 1;
            }
            head
        };
        if head {
            // The next in line may take now.
            self.pool.wake_head();
        }
    }
}

/// See [`Pool::armed`].
pub struct Armed<'a> {
    n: std::pin::Pin<Box<tokio::sync::futures::Notified<'a>>>,
    _w: Waiting<'a>,
}

impl Armed<'_> {
    pub async fn wait(self) {
        let Armed { n, _w } = self;
        n.await;
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
        let want = blocks_for(want).max(min);
        let n = match tier {
            Tier::Transport => pool.take_transport(want, min, None),
            _ => pool.take_blocks(want, min, pool.limit(tier)),
        };
        (n > 0).then(|| Self {
            pool: pool.clone(),
            blocks: n,
            counted: false,
            tier,
        })
    }

    /// Between `min` and `want` bytes from the transport region, for the
    /// holder of `ticket` when it is first in line (or nobody is queued).
    pub fn transport(pool: &Arc<Pool>, min: usize, want: usize, ticket: &Ticket) -> Option<Self> {
        debug_assert!(Arc::ptr_eq(pool, &ticket.pool));
        let min = blocks_for(min).max(1);
        let n = pool.take_transport(blocks_for(want).max(min), min, Some(ticket));
        (n > 0).then(|| Self {
            pool: pool.clone(),
            blocks: n,
            counted: false,
            tier: Tier::Transport,
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
            self.pool.give(self.blocks - want, self.tier);
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
        self.pool.give(self.blocks, self.tier);
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
    use std::cell::RefCell;

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static BETWEEN: RefCell<Option<Hook>> = RefCell::new(None);
    }

    /// Runs (once) the hook this thread set, between a transport taker's
    /// reservation check and its claim.
    pub(super) fn between_check_and_claim() {
        if let Some(f) = BETWEEN.with(|b| b.borrow_mut().take()) {
            f();
        }
    }

    #[test]
    fn a_reservation_cannot_be_raised_between_anothers_check_and_claim() {
        // r8 N6: another taker read the reservation (1 block, the first in
        // line had not asked yet), then the first in line asked for the
        // whole region and failed (one block held), then that block came
        // back, and only then did the other claim, against the stale
        // reservation: it took blocks reserved for the first in line. Now
        // the check and the claim happen under one lock, so the first in
        // line cannot register in between.
        let pool = Pool::with_regions(16 * BLOCK, 0, 8);
        let head = pool.ticket();
        let held = Grant::up_to(&pool, BLOCK, Tier::Transport).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let p = pool.clone();
        let head_thread = std::thread::spawn(move || {
            let g = Grant::transport(&p, 8 * BLOCK, 8 * BLOCK, &head);
            let _ = tx.send(g.is_some());
            (head, g.is_some())
        });
        let p2 = pool.clone();
        BETWEEN.with(|b| {
            *b.borrow_mut() = Some(Box::new(move || {
                // Give the first in line every chance to register now.
                let registered = rx.recv_timeout(Duration::from_millis(200)).ok();
                // Give the held block back without the wake-up (which takes
                // the queue lock this taker may hold).
                std::mem::forget(held);
                p2.transport_used.fetch_sub(1, Ordering::AcqRel);
                REGISTERED.with(|r| r.set(registered));
            }))
        });
        let other = Grant::up_to(&pool, 4 * BLOCK, Tier::Transport);
        let registered = REGISTERED.with(|r| r.get());
        let (_head, _) = head_thread.join().unwrap();
        assert!(
            !(registered == Some(false) && other.is_some()),
            "the first in line registered its need between another's check and \
             claim, and the other took {} reserved blocks",
            other.as_ref().map_or(0, |g| g.bytes() / BLOCK)
        );
    }

    thread_local! {
        static REGISTERED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

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
    fn transport_frames_cannot_take_the_relay_region() {
        // r7 #1: the transport region is disjoint. Frames stuck on carriers
        // fill it and no more; relay chunks keep their own region, and
        // giving transport blocks back frees transport room only.
        let pool = Pool::with_regions(20 * BLOCK, 4, 4);
        let mut hog = Grant::new(&pool, true);
        hog.grow_towards(1 << 20);
        let stuck = Grant::up_to(&pool, 1 << 20, Tier::Transport).unwrap();
        assert_eq!(stuck.bytes(), 4 * BLOCK);
        assert_eq!(pool.transport_used_blocks(), 4);
        assert!(Grant::up_to(&pool, BLOCK, Tier::Transport).is_none());
        let relay = Grant::up_to(&pool, 1 << 20, Tier::Relay).unwrap();
        assert_eq!(relay.bytes(), 4 * BLOCK, "relay region taken by frames");
        assert_eq!(pool.used_blocks(), 20);
        drop(relay);
        assert_eq!(pool.transport_used_blocks(), 4);
        assert!(Grant::up_to(&pool, BLOCK, Tier::Transport).is_none());
        drop(stuck);
        assert_eq!(pool.transport_used_blocks(), 0);
        drop(hog);
        assert_eq!(pool.used_bytes(), 0);
    }

    #[test]
    fn the_first_in_line_has_its_frame_reserved() {
        // r7 #1: once someone waits for the transport region, what it asked
        // for is kept for it: others (with a later ticket or none) take
        // only beyond that, so freed blocks cannot be raced away from it.
        let pool = Pool::with_regions(16 * BLOCK, 0, 8);
        let held = Grant::up_to(&pool, 8 * BLOCK, Tier::Transport).unwrap();
        let first = pool.ticket();
        let second = pool.ticket();
        assert_eq!(pool.queued(), 2);
        assert!(Grant::transport(&pool, 4 * BLOCK, 4 * BLOCK, &first).is_none());
        drop(held);
        // Four of eight blocks are the first's; the rest is anyone's.
        let other = Grant::transport(&pool, BLOCK, 8 * BLOCK, &second).unwrap();
        assert_eq!(other.bytes(), 4 * BLOCK);
        assert!(Grant::up_to(&pool, BLOCK, Tier::Transport).is_none());
        let a = Grant::transport(&pool, 4 * BLOCK, 4 * BLOCK, &first).unwrap();
        drop(first);
        assert_eq!(pool.transport_used_blocks(), 8);
        drop((a, other));
        // The next in line inherits the turn; a ticket leaving the line
        // passes it on.
        let third = pool.ticket();
        assert!(
            Grant::transport(&pool, 8 * BLOCK, 8 * BLOCK, &second).is_some_and(|g| {
                drop(g);
                true
            })
        );
        drop(second);
        let g = Grant::transport(&pool, 8 * BLOCK, 8 * BLOCK, &third).unwrap();
        drop((g, third));
        assert_eq!(pool.queued(), 0);
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
