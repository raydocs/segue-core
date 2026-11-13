//! Real allocations of the client side (KERNEL_SPEC §6.3), measured with a
//! counting allocator rather than computed from configuration: many
//! sessions download at once while the app does not read (peak), then the
//! app drains them and they stay open but idle (retained).
//!
//! Every allocation is tagged with the thread that made it, so the client
//! runtime (one thread: drivers, app pipes, app readers) is counted apart
//! from the relay and sites (another thread), wherever a block is freed.
//! Carriers are loopback TCP sockets: their buffers are the OS's, as on a
//! device.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use segue_session::client::{ClientSession, OpenParams};
use segue_session::codec::{Kind, Target};
use segue_session::driver::{run_client, run_relay, BoxCarrier, Connector, SiteConnector};
use segue_session::pipe::pipe;
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayTable};
use segue_session::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Counting allocator

struct Counting;

thread_local! {
    static CLIENT: Cell<bool> = const { Cell::new(false) };
}

static CLIENT_LIVE: AtomicIsize = AtomicIsize::new(0);
static CLIENT_PEAK: AtomicIsize = AtomicIsize::new(0);
static OTHER_LIVE: AtomicIsize = AtomicIsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

const HDR: usize = 16;

fn padded(l: Layout) -> (Layout, usize) {
    let pad = HDR.max(l.align());
    (
        Layout::from_size_align(l.size() + pad, l.align().max(HDR)).unwrap(),
        pad,
    )
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let (pl, pad) = padded(l);
        let base = System.alloc(pl);
        if base.is_null() {
            return base;
        }
        let client = CLIENT.try_with(|c| c.get()).unwrap_or(false);
        let p = base.add(pad);
        (p.sub(8) as *mut u64).write(client as u64);
        let n = l.size() as isize;
        if client {
            let now = CLIENT_LIVE.fetch_add(n, Ordering::Relaxed) + n;
            CLIENT_PEAK.fetch_max(now, Ordering::Relaxed);
        } else {
            OTHER_LIVE.fetch_add(n, Ordering::Relaxed);
        }
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        let (pl, pad) = padded(l);
        let client = (p.sub(8) as *const u64).read() == 1;
        let n = l.size() as isize;
        if client {
            CLIENT_LIVE.fetch_sub(n, Ordering::Relaxed);
        } else {
            OTHER_LIVE.fetch_sub(n, Ordering::Relaxed);
        }
        System.dealloc(p.sub(pad), pl);
    }
}

#[global_allocator]
static A: Counting = Counting;

fn client_live() -> isize {
    CLIENT_LIVE.load(Ordering::Relaxed)
}

fn reset_peak() {
    CLIENT_PEAK.store(client_live(), Ordering::Relaxed);
}

fn client_peak() -> isize {
    CLIENT_PEAK.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------

const SESSIONS: usize = 50;
const DOWN: usize = 512 * 1024;
const POOL: usize = 8 << 20;
const MIB: f64 = (1 << 20) as f64;

/// Relay and sites on their own thread: each site sends `DOWN` bytes and
/// then keeps the connection open (a long-lived idle session).
fn start_relay() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
            tokio::spawn(async move {
                while let Ok((c, _)) = listener.accept().await {
                    let _ = c.set_nodelay(true);
                    if accept_tx.send(Box::new(c)).await.is_err() {
                        return;
                    }
                }
            });
            let net = Pool::new(1 << 30);
            let site: SiteConnector = Arc::new(move |_t, _k| {
                let (ours, mut theirs) = pipe(&net, 64 << 10).unwrap();
                tokio::spawn(async move {
                    let chunk = vec![0x5a; 16 * 1024];
                    for _ in 0..DOWN / chunk.len() {
                        if theirs.write_all(&chunk).await.is_err() {
                            return;
                        }
                    }
                    let mut b = [0u8; 1024];
                    while matches!(theirs.read(&mut b).await, Ok(n) if n > 0) {}
                });
                Box::pin(async move { Ok(Box::new(ours) as BoxCarrier) })
            });
            let table = RelayTable::new(
                Config::default(),
                Pool::new(64 << 20),
                Box::new(AllowAll),
                1,
            );
            run_relay(table, accept_rx, site, None).await;
        });
    });
    (addr, h)
}

#[test]
fn client_memory_is_bounded_by_the_pool_and_released_when_idle() {
    let (addr, _relay) = start_relay();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    CLIENT.with(|c| c.set(true));
    let pool = Pool::new(POOL);
    let base = client_live();
    reset_peak();
    let report = rt.block_on(async {
        let connector: Connector = Arc::new(move || {
            Box::pin(async move {
                let c = tokio::net::TcpStream::connect(addr).await?;
                c.set_nodelay(true)?;
                Ok(Box::new(c) as BoxCarrier)
            })
        });
        let (go_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<usize>();
        let mut drivers = Vec::new();
        for i in 0..SESSIONS {
            let params = OpenParams {
                ticket: b"t".to_vec(),
                kind: Kind::Tcp,
                target: Target::Domain(format!("site{i}.example"), 443),
                exit_class: 0,
                anchor_node_id: 1,
                instance_hint: 1,
            };
            let s = ClientSession::new(Config::default(), &pool, params, Instant::now())
                .expect("session memory");
            let (mut app, far) = pipe(&pool, 64 << 10).expect("pipe memory");
            drivers.push(tokio::spawn(run_client(s, far, connector.clone())));
            let mut go = go_tx.subscribe();
            let done = done_tx.clone();
            tokio::spawn(async move {
                app.write_all(b"GET").await.unwrap();
                // The app does not read until told to: buffers fill.
                let _ = go.recv().await;
                let mut b = vec![0u8; 4096];
                let mut got = 0;
                while got < DOWN {
                    match app.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }
                drop(b);
                let _ = done.send(got);
                // Keep the session open, idle.
                std::future::pending::<()>().await;
            });
        }
        // Let every session fill what the pool allows.
        let mut last = 0;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let used = pool.used_bytes();
            if used == last && used > POOL / 2 {
                break;
            }
            last = used;
        }
        let filled = client_live() - base;
        let pool_used = pool.used_bytes();
        let _ = go_tx.send(());
        for _ in 0..SESSIONS {
            let got = tokio::time::timeout(Duration::from_secs(30), done_rx.recv())
                .await
                .expect("download stalled")
                .unwrap();
            assert_eq!(got, DOWN);
        }
        let peak = client_peak() - base;
        // Idle: past the receive idle shrink and the read-buffer release.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let retained = client_live() - base;
        let retained_pool = pool.used_bytes();
        (
            filled,
            pool_used,
            peak,
            retained,
            retained_pool,
            drivers.len(),
        )
    });
    let (filled, pool_used, peak, retained, retained_pool, n) = report;
    println!(
        "{n} sessions: filled {:.2} MiB (pool {:.2} MiB), peak {:.2} MiB, \
         retained idle {:.0} KiB = {:.1} KiB/session (pool {:.0} KiB)",
        filled as f64 / MIB,
        pool_used as f64 / MIB,
        peak as f64 / MIB,
        retained as f64 / 1024.0,
        retained as f64 / 1024.0 / n as f64,
        retained_pool as f64 / 1024.0,
    );
    // Downloads wanted far more than the pool: the pool held them back.
    assert!(pool_used > POOL / 2, "pool barely used: {pool_used}");
    // The heap follows the pool: what the pool charges plus a fixed cost
    // per session (state, tasks, channels, small read buffers, this test's
    // app task and its 4 KiB read buffer: ~28 KiB measured) — not a 64 KiB
    // pipe, a 256 KiB window and 16 KiB buffers per session outside it.
    const FIXED: isize = 32 * 1024;
    let bound = POOL as isize + SESSIONS as isize * FIXED;
    assert!(
        peak <= bound,
        "peak {:.2} MiB over pool + fixed {:.2} MiB",
        peak as f64 / MIB,
        bound as f64 / MIB
    );
    assert!(peak < 20 << 20, "client peak over the 20 MiB device budget");
    // Idle sessions give their buffers back. (The pool stays charged for
    // receive windows already advertised: `max_offset` never retracts.)
    assert!(retained_pool <= POOL);
    assert!(
        retained <= SESSIONS as isize * FIXED,
        "idle sessions keep {:.1} KiB each",
        retained as f64 / 1024.0 / SESSIONS as f64
    );
}
