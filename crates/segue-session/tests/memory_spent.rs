//! r5 N13 / r6 R6: with the pool spent, the client's real allocations stay
//! inside what the pool charges (plus the fixed per-session cost measured
//! in `memory.rs`), at the budget's scale: 256 sessions with their app
//! pipes admitted into the 8 MiB process pool, every elastic block then
//! held elsewhere. Sessions own no reserve: what they need to progress
//! comes from the pool's shared draining regions. Same counting allocator
//! and relay as `memory.rs` (own binary: the counters are process-wide).
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

const SESSIONS: usize = 256;
const DOWN: usize = 256 * 1024;
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
fn a_spent_pool_bounds_real_client_memory() {
    use segue_session::pool::{Grant, BLOCK};
    let (addr, _relay) = start_relay();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    CLIENT.with(|c| c.set(true));
    let pool = Pool::new(POOL);
    let base = client_live();
    reset_peak();
    let (peak, phantom) = rt.block_on(async {
        let connector: Connector = Arc::new(move || {
            Box::pin(async move {
                let c = tokio::net::TcpStream::connect(addr).await?;
                c.set_nodelay(true)?;
                Ok(Box::new(c) as BoxCarrier)
            })
        });
        let (go_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<usize>();
        let mut apps = Vec::new();
        for i in 0..SESSIONS {
            let params = OpenParams {
                ticket: b"t".to_vec(),
                kind: Kind::Tcp,
                target: Target::Domain(format!("s{i}.example"), 443),
                exit_class: 0,
                anchor_node_id: 1,
                instance_hint: 1,
            };
            let s = ClientSession::new(Config::default(), &pool, params, Instant::now())
                .expect("session memory");
            let (app, far) = pipe(&pool, 64 << 10).expect("pipe memory");
            apps.push((s, app, far));
        }
        // Spend the pool: what is left goes to grants that hold no memory.
        let mut hog = Vec::new();
        while let Some(g) = Grant::fixed(&pool, BLOCK) {
            hog.push(g);
        }
        let phantom = (hog.len() * BLOCK) as isize;
        let mut drivers = Vec::new();
        for (s, mut app, far) in apps {
            drivers.push(tokio::spawn(run_client(s, far, connector.clone())));
            let mut go = go_tx.subscribe();
            let done = done_tx.clone();
            tokio::spawn(async move {
                app.write_all(b"GET").await.unwrap();
                let _ = go.recv().await;
                let mut b = vec![0u8; 4096];
                let mut got = 0;
                while got < DOWN {
                    match app.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got += n,
                    }
                }
                let _ = done.send(got);
                std::future::pending::<()>().await;
            });
        }
        // The app is not reading: every buffer fills as far as it can.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let _ = go_tx.send(());
        for _ in 0..SESSIONS {
            let got = tokio::time::timeout(Duration::from_secs(60), done_rx.recv())
                .await
                .expect("download stalled with the pool spent")
                .unwrap();
            assert_eq!(got, DOWN);
        }
        drop(hog);
        (client_peak() - base, phantom)
    });
    // As in memory.rs: state, tasks, channels, small read buffers and this
    // test's app task, per session. Move counters on the session add a few
    // hundred bytes; 24 KiB failed one run when the peak sat 20 KiB under
    // the bound across 256 sessions.
    const FIXED: isize = 25 * 1024;
    let bound = POOL as isize - phantom + SESSIONS as isize * FIXED;
    println!(
        "{SESSIONS} sessions, pool spent: peak {:.2} MiB, bound {:.2} MiB",
        peak as f64 / MIB,
        bound as f64 / MIB
    );
    assert!(
        peak <= bound,
        "peak {:.2} MiB over what the pool covers {:.2} MiB",
        peak as f64 / MIB,
        bound as f64 / MIB
    );
}
