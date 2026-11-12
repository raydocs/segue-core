//! The async drivers end to end over `tokio::io::duplex` pipes: a client app
//! stream, carriers that are cut after a byte budget (mid-frame), a relay and
//! a site. Checks exact delivery in both directions and a single site connect.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use segue_session::client::{ClientSession, CloseReason, OpenParams};
use segue_session::codec::{Kind, Target};
use segue_session::driver::{run_client, run_relay, BoxCarrier, Connector, SiteConnector};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayTable};
use segue_session::Config;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot};

const INSTANCE: u64 = 3;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 131 + (i >> 9)) as u8) ^ seed)
        .collect()
}

/// Copy both ways until `budget` bytes have passed (or either side ends),
/// then drop both ends: whatever was in flight is lost.
async fn pump(mut a: DuplexStream, mut b: DuplexStream, budget: usize) {
    let mut ab = vec![0u8; 4096];
    let mut bb = vec![0u8; 4096];
    let mut passed = 0usize;
    while passed < budget {
        let chunk = (budget - passed).min(4096);
        tokio::select! {
            r = a.read(&mut ab[..chunk]) => match r {
                Ok(0) | Err(_) => return,
                Ok(n) => { if b.write_all(&ab[..n]).await.is_err() { return; } passed += n; }
            },
            r = b.read(&mut bb[..chunk]) => match r {
                Ok(0) | Err(_) => return,
                Ok(n) => { if a.write_all(&bb[..n]).await.is_err() { return; } passed += n; }
            },
        }
    }
}

/// The site: sends `down`, then FIN, while collecting the uplink until EOF.
async fn site<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    s: S,
    down: Vec<u8>,
    got: oneshot::Sender<Vec<u8>>,
) {
    let (mut r, mut w) = tokio::io::split(s);
    let writer = tokio::spawn(async move {
        w.write_all(&down).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut up = Vec::new();
    r.read_to_end(&mut up).await.unwrap();
    writer.await.unwrap();
    let _ = got.send(up);
}

struct Outcome {
    reason: CloseReason,
    carriers: usize,
    connects: usize,
}

async fn transfer(up: Vec<u8>, down: Vec<u8>, budgets: Vec<usize>) -> Outcome {
    let cfg = Config::default();
    let client_pool = Pool::new(8 << 20);
    let relay_pool = Pool::new(8 << 20);
    let params = OpenParams {
        ticket: b"t".to_vec(),
        kind: Kind::Tcp,
        target: Target::Domain("example.com".into(), 443),
        exit_class: 0,
        anchor_node_id: 1,
        instance_hint: INSTANCE,
    };
    let session = ClientSession::new(cfg.clone(), &client_pool, params, Instant::now()).unwrap();
    let table = RelayTable::new(cfg, relay_pool, Box::new(AllowAll), INSTANCE);

    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let carriers = Arc::new(AtomicUsize::new(0));
    let budgets = Arc::new(Mutex::new(budgets.into_iter()));
    let connector: Connector = {
        let carriers = carriers.clone();
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            carriers.fetch_add(1, Ordering::SeqCst);
            let budget = budgets.lock().unwrap().next().unwrap_or(usize::MAX);
            Box::pin(async move {
                let (client_end, p1) = tokio::io::duplex(64 << 10);
                let (p2, relay_end) = tokio::io::duplex(64 << 10);
                tokio::spawn(pump(p1, p2, budget));
                accept_tx
                    .send(Box::new(relay_end))
                    .await
                    .map_err(|_| std::io::Error::other("relay gone"))?;
                Ok(Box::new(client_end) as BoxCarrier)
            })
        })
    };

    let connects = Arc::new(AtomicUsize::new(0));
    let (site_tx, site_rx) = oneshot::channel();
    let site_tx = Arc::new(Mutex::new(Some(site_tx)));
    let site_conn: SiteConnector = {
        let connects = connects.clone();
        let down = down.clone();
        Arc::new(move |_t, _k| {
            connects.fetch_add(1, Ordering::SeqCst);
            let (ours, theirs) = tokio::io::duplex(64 << 10);
            if let Some(tx) = site_tx.lock().unwrap().take() {
                tokio::spawn(site(theirs, down.clone(), tx));
            }
            Box::pin(async move { Ok(Box::new(ours) as BoxCarrier) })
        })
    };
    let relay = tokio::spawn(run_relay(table, accept_rx, site_conn, None));

    let (app, app_far) = tokio::io::duplex(64 << 10);
    let client = tokio::spawn(run_client(session, app_far, connector));
    let (mut ar, mut aw) = tokio::io::split(app);
    let upc = up.clone();
    let app_writer = tokio::spawn(async move {
        aw.write_all(&upc).await.unwrap();
        aw.shutdown().await.unwrap();
    });
    let mut got_down = Vec::new();
    ar.read_to_end(&mut got_down).await.unwrap();
    app_writer.await.unwrap();
    let reason = client.await.unwrap();
    let got_up = site_rx.await.unwrap();
    relay.abort();

    assert_eq!(got_up.len(), up.len(), "uplink length");
    assert!(got_up == up, "uplink corrupted");
    assert_eq!(got_down.len(), down.len(), "downlink length");
    assert!(got_down == down, "downlink corrupted");
    Outcome {
        reason,
        carriers: carriers.load(Ordering::SeqCst),
        connects: connects.load(Ordering::SeqCst),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplex_transfer_without_faults() {
    let o = tokio::time::timeout(
        Duration::from_secs(30),
        transfer(pattern(1 << 20, 1), pattern(2 << 20, 2), vec![]),
    )
    .await
    .expect("transfer timed out");
    assert_eq!(o.reason, CloseReason::Clean);
    assert_eq!(o.carriers, 1);
    assert_eq!(o.connects, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplex_disconnect_mid_transfer_resumes_without_loss_or_duplication() {
    // Odd budgets so cuts land inside frames.
    let budgets = vec![300_001, 250_003, 411_007, 199_999, 333_331];
    let o = tokio::time::timeout(
        Duration::from_secs(60),
        transfer(pattern(2 << 20, 3), pattern(3 << 20, 4), budgets),
    )
    .await
    .expect("transfer timed out");
    assert_eq!(o.reason, CloseReason::Clean);
    assert!(
        o.carriers >= 6,
        "only {} carriers: cuts not exercised",
        o.carriers
    );
    assert_eq!(o.connects, 1, "site connected more than once");
}

/// CPU time of the calling thread (a current-thread runtime runs every task
/// on it).
fn thread_cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out pointer.
    let r = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    assert_eq!(r, 0);
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn params() -> OpenParams {
    OpenParams {
        ticket: b"t".to_vec(),
        kind: Kind::Tcp,
        target: Target::Domain("example.com".into(), 443),
        exit_class: 0,
        anchor_node_id: 1,
        instance_hint: INSTANCE,
    }
}

const SLOW: Duration = Duration::from_millis(1500);
const CPU_LIMIT: Duration = Duration::from_millis(300);

#[tokio::test]
async fn relay_does_not_spin_while_the_site_connect_is_slow() {
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), pool.clone(), Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let site_conn: SiteConnector = Arc::new(move |_t, _k| {
        Box::pin(async move {
            tokio::time::sleep(SLOW).await;
            Err(std::io::Error::other("refused"))
        })
    });
    let relay = tokio::spawn(run_relay(table, accept_rx, site_conn, None));
    let connector: Connector = Arc::new(move || {
        let accept_tx = accept_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(64 << 10);
            accept_tx
                .send(Box::new(b))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(64 << 10);
    // First bytes ride in OPEN, so the relay holds unacknowledged data
    // while it waits for the site.
    app.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let cpu = thread_cpu();
    let wall = Instant::now();
    let reason = tokio::time::timeout(Duration::from_secs(10), run_client(s, far, connector))
        .await
        .expect("client hung");
    let used = thread_cpu() - cpu;
    assert!(wall.elapsed() >= SLOW);
    assert_ne!(reason, CloseReason::Clean);
    assert!(used < CPU_LIMIT, "drivers burnt {used:?} CPU in {SLOW:?}");
    relay.abort();
}

#[tokio::test]
async fn client_does_not_spin_while_a_reconnect_is_slow() {
    use segue_session::codec::{code, Frame, FrameDecoder, Reject};
    let pool = Pool::new(8 << 20);
    let calls = Arc::new(AtomicUsize::new(0));
    let connector: Connector = {
        let calls = calls.clone();
        Arc::new(move || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n > 0 {
                    // The retry after the backoff: slow, then fails.
                    tokio::time::sleep(SLOW).await;
                    return Err(std::io::Error::other("slow network"));
                }
                // First carrier: the relay cannot reach the anchor (B2).
                let (a, mut b) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let mut dec = FrameDecoder::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = b.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        dec.push(&buf[..n]);
                        if let Ok(Some(Frame::Open(o))) = dec.next_frame() {
                            let rj = Frame::Reject(Reject {
                                code: code::ANCHOR_UNREACHABLE,
                                attach_gen: o.attach_gen,
                                closed: None,
                            });
                            let _ = b.write_all(&rj.to_bytes()).await;
                        }
                    }
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let s = ClientSession::new(Config::default(), &pool, params(), Instant::now()).unwrap();
    let (_app, far) = tokio::io::duplex(64 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    // Backoff (200 ms) passes, then the slow connect is in flight.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "retry not started");
    let cpu = thread_cpu();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let used = thread_cpu() - cpu;
    assert!(
        used < CPU_LIMIT,
        "client burnt {used:?} CPU waiting on a connect"
    );
    client.abort();
}

/// A relay + client pair whose site connector is `site_conn`; returns the
/// app end, the relay's control channel and the client task.
fn revocable_pair(
    site_conn: segue_session::driver::DeviceSiteConnector,
) -> (
    DuplexStream,
    mpsc::Sender<segue_session::driver::RelayCtrl>,
    tokio::task::JoinHandle<CloseReason>,
    tokio::task::JoinHandle<()>,
) {
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), pool.clone(), Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let (ctrl_tx, ctrl_rx) = mpsc::channel(4);
    let relay = tokio::spawn(segue_session::driver::run_relay_ctl(
        table,
        accept_rx,
        site_conn,
        None,
        Some(ctrl_rx),
    ));
    let connector: Connector = Arc::new(move || {
        let accept_tx = accept_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(256 << 10);
            accept_tx
                .send(Box::new(b))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    let (app, far) = tokio::io::duplex(256 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    (app, ctrl_tx, client, relay)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_cancels_a_site_writer_blocked_on_a_site_that_stopped_reading() {
    use segue_session::codec::code;
    use segue_session::driver::{DeviceSiteConnector, RelayCtrl, SiteRequest};
    const SITE_BUF: usize = 1024;
    let (site_tx, mut site_rx) = mpsc::unbounded_channel::<DuplexStream>();
    let site_conn: DeviceSiteConnector = Arc::new(move |_r: SiteRequest| {
        let site_tx = site_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(SITE_BUF);
            let _ = site_tx.send(b);
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let (mut app, ctrl, client, relay) = revocable_pair(site_conn);
    let up = pattern(400 << 10, 3);
    let writer = tokio::spawn(async move {
        let _ = app.write_all(&up).await;
        app
    });
    // The site never reads: its buffer fills, the relay's site writer
    // blocks in write_all with more queued behind it.
    let mut site = tokio::time::timeout(Duration::from_secs(5), site_rx.recv())
        .await
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    ctrl.send(RelayCtrl::ResetDevice {
        device: 0,
        close_code: code::REVOKED,
    })
    .await
    .unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("client did not end")
        .unwrap();
    assert_eq!(reason, CloseReason::Reset(code::REVOKED));
    // The site now reads: it gets what was already in its socket buffer,
    // then the connection is gone — nothing queued before the revoke.
    let mut got = 0usize;
    let mut buf = vec![0u8; 64 << 10];
    let end = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match site.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => got += n,
            }
        }
    })
    .await;
    assert!(end.is_ok(), "site connection outlived the revoke");
    assert!(
        got <= SITE_BUF,
        "{got} bytes reached the site after the revoke"
    );
    writer.abort();
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_cancels_a_site_connect_in_flight() {
    use segue_session::codec::code;
    use segue_session::driver::{DeviceSiteConnector, RelayCtrl, SiteRequest};
    struct Guard(Arc<AtomicUsize>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let site_conn: DeviceSiteConnector = {
        let (dropped, started) = (dropped.clone(), started.clone());
        Arc::new(move |_r: SiteRequest| {
            let g = Guard(dropped.clone());
            started.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let _g = g;
                tokio::time::sleep(Duration::from_secs(3600)).await;
                Err(std::io::Error::other("never"))
            })
        })
    };
    let (mut app, ctrl, client, relay) = revocable_pair(site_conn);
    app.write_all(b"hello").await.unwrap();
    for _ in 0..100 {
        if started.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(started.load(Ordering::SeqCst), 1);
    ctrl.send(RelayCtrl::ResetDevice {
        device: 0,
        close_code: code::REVOKED,
    })
    .await
    .unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("client did not end")
        .unwrap();
    assert_eq!(reason, CloseReason::Reset(code::REVOKED));
    for _ in 0..100 {
        if dropped.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "site connect kept running"
    );
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn app_write_failure_resets_the_session() {
    // The app's side goes away mid-download: the client must reset, not
    // keep pulling data nobody will read.
    let site_conn: SiteConnector = Arc::new(|_t, _k| {
        Box::pin(async {
            let (a, mut b) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let chunk = vec![7u8; 16 << 10];
                while b.write_all(&chunk).await.is_ok() {}
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let site_conn: segue_session::driver::DeviceSiteConnector =
        Arc::new(move |r: segue_session::driver::SiteRequest| site_conn(r.target, r.kind));
    let (mut app, _ctrl, client, relay) = revocable_pair(site_conn);
    app.write_all(b"GET /big").await.unwrap();
    let mut buf = vec![0u8; 4096];
    app.read_exact(&mut buf).await.unwrap();
    drop(app);
    let reason = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("client kept running after the app went away")
        .unwrap();
    assert_ne!(reason, CloseReason::Clean);
    relay.abort();
}

/// Sets its flag when dropped.
struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// A carrier that flags when the last owner lets go of it.
struct Tracked {
    io: DuplexStream,
    _flag: DropFlag,
}

impl AsyncRead for Tracked {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tracked {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn wait_flag(f: &std::sync::atomic::AtomicBool, what: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !f.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} outlived the aborted driver"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborting_the_client_driver_releases_its_carrier_and_dial() {
    // r5 N9: dropping the driver future (user disconnect) must take its
    // reader / writer / dial tasks with it.
    use std::sync::atomic::AtomicBool;
    let carrier_gone = Arc::new(AtomicBool::new(false));
    let dial_gone = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let peers = Arc::new(Mutex::new(Vec::new()));
    let connector: Connector = {
        let (carrier_gone, dial_gone, calls, peers) = (
            carrier_gone.clone(),
            dial_gone.clone(),
            calls.clone(),
            peers.clone(),
        );
        Arc::new(move || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let (carrier_gone, dial_gone, peers) =
                (carrier_gone.clone(), dial_gone.clone(), peers.clone());
            Box::pin(async move {
                if n > 0 {
                    // A reconnect that never completes.
                    let _f = DropFlag(dial_gone);
                    std::future::pending::<()>().await;
                }
                // A silent relay: never answers, never closes.
                let (a, b) = tokio::io::duplex(64 << 10);
                peers.lock().unwrap().push(b);
                Ok(Box::new(Tracked {
                    io: a,
                    _flag: DropFlag(carrier_gone),
                }) as BoxCarrier)
            })
        })
    };
    let pool = Pool::new(8 << 20);
    let s = ClientSession::new(Config::default(), &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(64 << 10);
    app.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let client = tokio::spawn(run_client(s, far, connector));
    // T_attach passes on the silent carrier and a second dial starts.
    tokio::time::timeout(Duration::from_secs(10), async {
        while calls.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .ok();
    client.abort();
    let _ = client.await;
    wait_flag(&carrier_gone, "the carrier").await;
    if calls.load(Ordering::SeqCst) >= 2 {
        wait_flag(&dial_gone, "the dial").await;
    }
    assert_eq!(pool.used_blocks(), 0, "pool not returned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drain_cut_short_is_never_reported_clean() {
    // r5 N8: both sides FIN while the app is not reading; the drain bound
    // passes with the tail still queued. The app must get either every byte
    // or a non-clean reason, never a prefix and a clean EOF.
    const BODY: usize = 256 << 10;
    let body = pattern(BODY, 5);
    let site_conn: SiteConnector = {
        let body = body.clone();
        Arc::new(move |_t, _k| {
            let body = body.clone();
            Box::pin(async move {
                let (a, b) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(b);
                    let mut req = Vec::new();
                    let _ = r.read_to_end(&mut req).await;
                    let _ = w.write_all(&body).await;
                    let _ = w.shutdown().await;
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), pool.clone(), Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let relay = tokio::spawn(run_relay(table, accept_rx, site_conn, None));
    let connector: Connector = Arc::new(move || {
        let accept_tx = accept_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(256 << 10);
            accept_tx
                .send(Box::new(b))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    // A small app pipe: the tail has to wait in the driver.
    let (mut app, far) = tokio::io::duplex(4 << 10);
    let (closed_tx, mut closed_rx) = oneshot::channel();
    let ctl = segue_session::driver::ClientCtl {
        closed: Some(closed_tx),
        ..Default::default()
    };
    let client = tokio::spawn(segue_session::driver::run_client_ctl(
        s, far, connector, ctl,
    ));
    app.write_all(b"GET /big HTTP/1.1\r\n\r\n").await.unwrap();
    app.shutdown().await.unwrap();
    // Paused well past the drain bound.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), app.read_to_end(&mut got))
        .await
        .expect("app stream never ended");
    let reason = tokio::time::timeout(Duration::from_secs(5), &mut closed_rx)
        .await
        .expect("no close reason")
        .ok();
    if got.len() < BODY {
        assert_ne!(
            reason,
            Some(CloseReason::Clean),
            "{} of {BODY} bytes delivered, yet reported clean",
            got.len()
        );
    } else {
        assert_eq!(got, body);
    }
    let _ = client.await;
    relay.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_admitted_before_the_pool_ran_out_still_finish() {
    // r5 N12/N13: the client pool is spent exactly once the sessions are
    // admitted. Each must still move its request and the echo (its send
    // floor and driver reserve were taken at admission); a new session is
    // refused instead of being admitted without progress; after release the
    // pool admits again.
    use segue_session::pipe::pipe;
    use segue_session::pool::{Grant, BLOCK};
    const N: usize = 4;
    const LEN: usize = 64 << 10;
    let cfg = Config::default();
    let pool = Pool::new(1 << 20);
    let relay_pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), relay_pool, Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(16);
    let echo: SiteConnector = Arc::new(|_t, _k| {
        Box::pin(async {
            let (a, mut b) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match b.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if b.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let relay = tokio::spawn(run_relay(table, accept_rx, echo, None));
    let connector: Connector = Arc::new(move || {
        let accept_tx = accept_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(64 << 10);
            accept_tx
                .send(Box::new(b))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let mut admitted = Vec::new();
    for _ in 0..N {
        let s = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()).unwrap();
        let (app, far) = pipe(&pool, 64 << 10).unwrap();
        admitted.push((s, app, far));
    }
    let mut hog = Vec::new();
    while let Some(g) = Grant::fixed(&pool, BLOCK) {
        hog.push(g);
    }
    assert_eq!(pool.used_bytes(), pool.capacity_bytes());
    assert!(
        ClientSession::new(cfg.clone(), &pool, params(), Instant::now()).is_none(),
        "admitted a session the spent pool cannot move"
    );
    assert!(pipe(&pool, 64 << 10).is_none());
    let mut apps = Vec::new();
    for (i, (s, app, far)) in admitted.into_iter().enumerate() {
        let client = tokio::spawn(run_client(s, far, connector.clone()));
        apps.push(tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(app);
            let up = pattern(LEN, i as u8);
            let want = up.clone();
            let writer = tokio::spawn(async move { w.write_all(&up).await.map(|_| w) });
            let mut got = vec![0u8; LEN];
            r.read_exact(&mut got).await.unwrap();
            assert_eq!(got, want);
            let mut w = writer.await.unwrap().unwrap();
            w.shutdown().await.unwrap();
            drop((r, w));
            client
        }));
    }
    for a in apps {
        let client = tokio::time::timeout(Duration::from_secs(20), a)
            .await
            .expect("a session admitted before the pool ran out stalled")
            .unwrap();
        client.abort();
    }
    drop(hog);
    assert!(ClientSession::new(cfg, &pool, params(), Instant::now()).is_some());
    relay.abort();
}
