//! The async drivers end to end over `tokio::io::duplex` pipes: a client app
//! stream, carriers that are cut after a byte budget (mid-frame), a relay and
//! a site. Checks exact delivery in both directions and a single site connect.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use segue_session::client::{ClientSession, CloseReason, OpenParams};
use segue_session::codec::{Kind, Target};
use segue_session::driver::{
    run_client, run_client_ctl_with_redundant, run_relay, BoxCarrier, ClientCtl, Connector,
    SiteConnector,
};
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
    let mut cfg = Config::default();
    // Re-attach only when a carrier is really cut: a loaded test machine
    // can delay ACKs past the 1 s stall bound, which would add a carrier
    // to a fault-free transfer (flaky `carriers == 1`). Cuts close the
    // carrier, so they are still noticed at once.
    cfg.timing.t_stall = Duration::from_secs(60);
    cfg.timing.t_live = Duration::from_secs(60);
    cfg.timing.t_attach = Duration::from_secs(60);
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

/// Open, add a redundant carrier, move 1 MiB each way, then drop either
/// carrier. Bytes match and no third carrier is dialed: the spare's death
/// is local, and the current carrier's death promotes the spare.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redundant_either_carrier_cut_mid_transfer() {
    for kill_current in [true, false] {
        let o = tokio::time::timeout(Duration::from_secs(30), redundant_cut(kill_current))
            .await
            .unwrap_or_else(|_| panic!("timed out kill_current={kill_current}"));
        assert_eq!(o.reason, CloseReason::Clean, "kill_current={kill_current}");
        assert_eq!(o.connects, 1, "kill_current={kill_current}");
        assert_eq!(
            o.carriers, 2,
            "kill_current={kill_current}: a third carrier means promotion or the spare failed"
        );
    }
}

async fn redundant_cut(kill_current: bool) -> Outcome {
    let mut cfg = Config::default();
    cfg.timing.t_stall = Duration::from_secs(60);
    cfg.timing.t_live = Duration::from_secs(60);
    cfg.timing.t_attach = Duration::from_secs(60);
    let up = pattern(1 << 20, 9);
    let down = pattern(1 << 20, 8);
    let client_pool = Pool::new(8 << 20);
    let relay_pool = Pool::new(8 << 20);
    let session = ClientSession::new(cfg.clone(), &client_pool, params(), Instant::now()).unwrap();
    let table = RelayTable::new(cfg, relay_pool, Box::new(AllowAll), INSTANCE);

    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let carriers = Arc::new(AtomicUsize::new(0));
    // Set once the spare carrier's ferry is running, so the current carrier
    // is not cut before REDUNDANT_OK can land.
    let spare_up = Arc::new(AtomicBool::new(false));
    let connector: Connector = {
        let carriers = carriers.clone();
        let spare_up = spare_up.clone();
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            let n = carriers.fetch_add(1, Ordering::SeqCst);
            let spare_up = spare_up.clone();
            Box::pin(async move {
                let (client_end, p1) = tokio::io::duplex(64 << 10);
                let (p2, relay_end) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let mut a = p1;
                    let mut b = p2;
                    let mut ab = vec![0u8; 8192];
                    let mut bb = vec![0u8; 8192];
                    let mut passed = 0usize;
                    let spare_deadline = (n == 1 && !kill_current)
                        .then(|| tokio::time::Instant::now() + Duration::from_millis(80));
                    loop {
                        // Slow the current carrier until the spare exists so
                        // the cut lands in the middle of the 1 MiB, not after.
                        if n == 0 && kill_current && !spare_up.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                        }
                        // The spare has carried the attach (and, shortly, the
                        // OK). The current carrier may die only after that.
                        if n == 1 && passed >= 64 {
                            spare_up.store(true, Ordering::SeqCst);
                        }
                        if spare_deadline.is_some_and(|t| tokio::time::Instant::now() >= t) {
                            return;
                        }
                        if n == 0 && kill_current && spare_up.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            return;
                        }
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(5)), if spare_deadline.is_some() => {}
                            r = a.read(&mut ab) => match r {
                                Ok(0) | Err(_) => return,
                                Ok(k) => {
                                    if b.write_all(&ab[..k]).await.is_err() { return; }
                                    passed += k;
                                }
                            },
                            r = b.read(&mut bb) => match r {
                                Ok(0) | Err(_) => return,
                                Ok(k) => {
                                    if a.write_all(&bb[..k]).await.is_err() { return; }
                                    passed += k;
                                }
                            },
                        }
                    }
                });
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
    let (add_tx, add_rx) = mpsc::unbounded_channel();
    let _ = add_tx.send(());
    let (app, app_far) = tokio::io::duplex(64 << 10);
    let client = tokio::spawn(run_client_ctl_with_redundant(
        session,
        app_far,
        connector,
        ClientCtl::default(),
        add_rx,
    ));
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
    tokio::time::timeout(Duration::from_secs(10), async {
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
            let (carrier_gone, peers) = (carrier_gone.clone(), peers.clone());
            // Owned by the dial future from its creation, so the flag is
            // raised when the future is dropped even if it never ran (the
            // driver may be aborted before its dial task is first polled).
            let dial_flag = (n > 0).then(|| DropFlag(dial_gone.clone()));
            Box::pin(async move {
                if let Some(_f) = dial_flag {
                    // A reconnect that never completes.
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
    // Aborted tasks drop their state when the runtime next gets to them.
    tokio::time::timeout(Duration::from_secs(10), async {
        while pool.used_blocks() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("pool not returned: {} blocks", pool.used_blocks()));
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
    use segue_session::pool::{Grant, Tier, BLOCK};
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
    // Every elastic block is spent; only the shared draining regions
    // (no session owns them) are left.
    assert_eq!(pool.used_blocks(), pool.limit(Tier::Elastic));
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
            client.abort();
        }));
    }
    for a in apps {
        tokio::time::timeout(Duration::from_secs(20), a)
            .await
            .expect("a session admitted before the pool ran out stalled")
            .unwrap();
    }
    drop(hog);
    assert!(ClientSession::new(cfg, &pool, params(), Instant::now()).is_some());
    relay.abort();
}

/// Review r6 (relay upload drain): the client FINs an upload the site is
/// slow to take (it reads only after a pause longer than the old 1 s drain
/// bound). The session may end CLEAN only once the site writer actually
/// handed it every byte; before, the relay acknowledged the FIN when the
/// bytes left the table, reported CLEAN, and then aborted the writer after
/// the drain bound, so the site got a prefix of a "clean" upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncated_upload_is_never_reported_clean() {
    use segue_session::driver::{DeviceSiteConnector, SiteRequest};
    const SITE_BUF: usize = 1024;
    const UP: usize = 24 << 10;
    let (got_tx, got_rx) = oneshot::channel::<Vec<u8>>();
    let got_tx = Arc::new(Mutex::new(Some(got_tx)));
    let site_conn: DeviceSiteConnector = Arc::new(move |_r: SiteRequest| {
        let got_tx = got_tx.lock().unwrap().take();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(SITE_BUF);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(b);
                // Nothing to send back: half-close at once.
                let _ = w.shutdown().await;
                tokio::time::sleep(Duration::from_millis(2500)).await;
                let mut up = Vec::new();
                let _ = r.read_to_end(&mut up).await;
                if let Some(tx) = got_tx {
                    let _ = tx.send(up);
                }
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let (mut app, _ctrl, client, relay) = revocable_pair(site_conn);
    let up = pattern(UP, 7);
    app.write_all(&up).await.unwrap();
    app.shutdown().await.unwrap();
    let mut down = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut down))
        .await
        .expect("app stream never ended");
    let reason = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client did not end")
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
        .await
        .expect("site never finished reading")
        .unwrap();
    assert_eq!(
        reason,
        CloseReason::Clean,
        "a slow but working site is a clean close"
    );
    assert_eq!(
        got.len(),
        UP,
        "reported clean, site got {} of {UP} bytes",
        got.len()
    );
    assert!(got == up, "upload corrupted");
    relay.abort();
}

#[test]
fn the_8mb_pool_admits_hundreds_of_flows() {
    // r6 R6 / KERNEL_SPEC §6.3: no per-session reserve. A fresh flow costs
    // its floors only: the 16 KiB initial credit (§4 rule 8), one replay
    // block, one pipe block each way, and through the TUN one ring block
    // each way.
    use segue_session::pipe::pipe;
    use segue_session::pool::{Grant, Tier, BLOCK};
    let cfg = Config::default();
    let admit = |tun: bool| {
        let pool = Pool::new(8 << 20);
        let mut flows = Vec::new();
        loop {
            let Some(s) = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()) else {
                break;
            };
            let Some(p) = pipe(&pool, 64 << 10) else {
                break;
            };
            let ring = if tun {
                match Grant::fixed(&pool, 2 * BLOCK) {
                    Some(g) => Some(g),
                    None => break,
                }
            } else {
                None
            };
            flows.push((s, p, ring));
        }
        // Refused only once the elastic part is spent; the draining
        // regions stay free for progress.
        assert!(pool.limit(Tier::Elastic) - pool.used_blocks() < 7);
        flows.len()
    };
    let (sessions, tun_flows) = (admit(false), admit(true));
    println!("8 MiB pool admits {sessions} session flows, {tun_flows} TUN session flows");
    assert!(sessions >= 280, "{sessions} session flows");
    assert!(tun_flows >= 220, "{tun_flows} TUN flows");
}

// ---- Review r7 #9 / #11: the upload drain after a client's FIN ----

/// A relay with `tune` applied to its timing, the device site connector
/// `site_conn`, and its notices; one client session bridging `app`.
fn flush_pair(
    tune: impl FnOnce(&mut segue_session::Timing),
    site_conn: segue_session::driver::DeviceSiteConnector,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<CloseReason>,
    tokio::task::JoinHandle<()>,
    mpsc::UnboundedReceiver<segue_session::driver::RelayNotice>,
) {
    let mut cfg = Config::default();
    // Only the drain bounds may end these sessions.
    cfg.timing.t_stall = Duration::from_secs(60);
    cfg.timing.t_live = Duration::from_secs(60);
    cfg.timing.t_attach = Duration::from_secs(60);
    tune(&mut cfg.timing);
    flush_pair_cfg(cfg, site_conn, Arc::new(AtomicUsize::new(0)))
}

/// [`flush_pair`] with `cfg` as given (no timing changed) and every
/// carrier dial counted in `dials`.
fn flush_pair_cfg(
    cfg: Config,
    site_conn: segue_session::driver::DeviceSiteConnector,
    dials: Arc<AtomicUsize>,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<CloseReason>,
    tokio::task::JoinHandle<()>,
    mpsc::UnboundedReceiver<segue_session::driver::RelayNotice>,
) {
    flush_pair_cfgs(cfg.clone(), cfg, site_conn, dials)
}

/// [`flush_pair_cfg`] with separate relay and client configurations.
fn flush_pair_cfgs(
    cfg: Config,
    client_cfg: Config,
    site_conn: segue_session::driver::DeviceSiteConnector,
    dials: Arc<AtomicUsize>,
) -> (
    DuplexStream,
    tokio::task::JoinHandle<CloseReason>,
    tokio::task::JoinHandle<()>,
    mpsc::UnboundedReceiver<segue_session::driver::RelayNotice>,
) {
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), pool.clone(), Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let (note_tx, note_rx) = mpsc::unbounded_channel();
    let relay = tokio::spawn(segue_session::driver::run_relay_ctl(
        table,
        accept_rx,
        site_conn,
        Some(note_tx),
        None,
    ));
    let connector: Connector = Arc::new(move || {
        let accept_tx = accept_tx.clone();
        dials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(256 << 10);
            accept_tx
                .send(Box::new(b))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let s = ClientSession::new(client_cfg, &pool, params(), Instant::now()).unwrap();
    let (app, far) = tokio::io::duplex(512 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    (app, client, relay, note_rx)
}

/// Write `up` and FIN it, wait for the client to end; returns how it
/// ended and how long after the FIN.
async fn upload_and_fin(
    mut app: DuplexStream,
    up: &[u8],
    client: tokio::task::JoinHandle<CloseReason>,
) -> (CloseReason, Duration) {
    app.write_all(up).await.unwrap();
    app.shutdown().await.unwrap();
    let fin = Instant::now();
    // Keep reading so the app side never blocks the session.
    tokio::spawn(async move {
        let mut sink = Vec::new();
        let _ = app.read_to_end(&mut sink).await;
    });
    let reason = tokio::time::timeout(Duration::from_secs(30), client)
        .await
        .expect("client did not end")
        .unwrap();
    (reason, fin.elapsed())
}

/// The relay's report of how the session ended: written by the same
/// `finish` that writes the tombstone, so this is the tombstone's code
/// (the tombstone itself: `review.rs`).
async fn closed_code(
    notes: &mut mpsc::UnboundedReceiver<segue_session::driver::RelayNotice>,
) -> u8 {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), notes.recv())
            .await
            .expect("no Closed notice")
            .expect("relay gone")
        {
            segue_session::driver::RelayNotice::Closed { close_code, .. } => return close_code,
            _ => continue,
        }
    }
}

/// A site that accepts the connection and then never reads; it keeps its
/// end open (the relay must not wait for it to go away).
fn deaf_site(keep: Arc<Mutex<Vec<DuplexStream>>>) -> segue_session::driver::DeviceSiteConnector {
    Arc::new(move |_r| {
        let keep = keep.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(1024);
            keep.lock().unwrap().push(b);
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// A site that reads `step` bytes every `every` until EOF, then reports
/// what it got.
fn slow_site(
    step: usize,
    every: Duration,
    got: Arc<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
) -> segue_session::driver::DeviceSiteConnector {
    Arc::new(move |_r| {
        let got = got.lock().unwrap().take();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(b);
                let _ = w.shutdown().await;
                let mut up = Vec::new();
                let mut buf = vec![0u8; step];
                loop {
                    tokio::time::sleep(every).await;
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => up.extend_from_slice(&buf[..n]),
                    }
                }
                if let Some(tx) = got {
                    let _ = tx.send(up);
                }
                // Hold the write half until the relay is done with it.
                std::future::pending::<()>().await;
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// A site whose write side fails: writes after `ok_bytes` and/or the
/// shutdown return an error. Reads never end.
struct FailingSite {
    inner: DuplexStream,
    ok_bytes: usize,
    fail_shutdown: bool,
}

impl AsyncRead for FailingSite {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

impl AsyncWrite for FailingSite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.ok_bytes == 0 {
            return std::task::Poll::Ready(Err(std::io::Error::other("forced write error")));
        }
        let n = buf.len().min(self.ok_bytes);
        let r = std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..n]));
        if let Ok(k) = r {
            self.ok_bytes -= k;
        }
        std::task::Poll::Ready(r)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.fail_shutdown {
            return std::task::Poll::Ready(Err(std::io::Error::other("forced shutdown error")));
        }
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn failing_site(
    ok_bytes: usize,
    fail_shutdown: bool,
) -> segue_session::driver::DeviceSiteConnector {
    Arc::new(move |_r| {
        Box::pin(async move {
            let (a, mut b) = tokio::io::duplex(1 << 20);
            // Take what the relay writes, so only the forced error stops it.
            tokio::spawn(async move {
                let mut sink = vec![0u8; 64 << 10];
                while b.read(&mut sink).await.is_ok_and(|n| n > 0) {}
            });
            Ok(Box::new(FailingSite {
                inner: a,
                ok_bytes,
                fail_shutdown,
            }) as BoxCarrier)
        })
    })
}

/// #9 (writer queue full): the site never reads and the upload (112 KiB)
/// is more than the blocked site write plus the full writer queue hold
/// (74-90 KiB measured), so when the client's FIN arrives 22-38 KiB still
/// sit in the relay's receive buffer and the shutdown cannot even be
/// queued (checked by instrumenting the driver: queue capacity 0,
/// shutdown not queued, at both drain start and reset). Both ends use a
/// 64 KiB initial credit here: the receive window follows delivery rate
/// × SRTT (§4 rule 8), so a relay whose site stopped reading keeps it
/// near the initial credit, and with the default 16 KiB the last part of
/// the upload (and the FIN) would not always reach the relay. With 64 KiB
/// the FIN arrives whatever the queue holds (hold + 64 KiB > 112 KiB) and
/// data is left over (hold < 112 KiB). Before, the 30 s timer started only
/// once the shutdown was queued, i.e. never: the session hung. Now it is
/// reset after `site_flush_idle` without progress, never CLEAN, and the
/// relay's record (tombstone code) says `site_reset`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_site_that_never_reads_resets_the_drain_even_with_a_full_writer_queue() {
    use segue_session::codec::code;
    let keep = Arc::new(Mutex::new(Vec::new()));
    let mut cfg = Config::default();
    cfg.timing.t_stall = Duration::from_secs(60);
    cfg.timing.t_live = Duration::from_secs(60);
    cfg.timing.t_attach = Duration::from_secs(60);
    cfg.timing.site_flush_idle = Duration::from_secs(1);
    cfg.timing.site_flush_max = Duration::from_secs(60);
    cfg.limits.initial_credit = 64 << 10;
    let (app, client, relay, mut notes) =
        flush_pair_cfg(cfg, deaf_site(keep.clone()), Arc::new(AtomicUsize::new(0)));
    let (reason, took) = upload_and_fin(app, &pattern(112 << 10, 1), client).await;
    assert_eq!(reason, CloseReason::Reset(code::SITE_RESET));
    assert_eq!(closed_code(&mut notes).await, code::SITE_RESET);
    assert!(
        took >= Duration::from_millis(900),
        "reset before the idle bound: {took:?}"
    );
    assert!(
        took < Duration::from_secs(20),
        "idle bound not applied: {took:?}"
    );
    assert_eq!(keep.lock().unwrap().len(), 1);
    relay.abort();
}

/// #9 (progress): a site that keeps taking the upload, slowly, for many
/// times `site_flush_idle` is never cut: the bound is on no progress, not
/// on total time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_but_progressing_drain_outlives_the_idle_bound() {
    const UP: usize = 24 << 10;
    let (got_tx, got_rx) = oneshot::channel();
    let site = slow_site(
        2048,
        Duration::from_millis(250),
        Arc::new(Mutex::new(Some(got_tx))),
    );
    let (app, client, relay, mut notes) = flush_pair(
        |t| {
            t.site_flush_idle = Duration::from_millis(800);
            t.site_flush_max = Duration::from_secs(60);
        },
        site,
    );
    let up = pattern(UP, 2);
    let (reason, took) = upload_and_fin(app, &up, client).await;
    assert_eq!(reason, CloseReason::Clean, "a progressing site was reset");
    assert_eq!(
        closed_code(&mut notes).await,
        segue_session::codec::code::CLEAN
    );
    assert!(
        took > Duration::from_millis(1600),
        "drain did not outlast twice the idle bound ({took:?}): the test proves nothing"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(got == up, "site got {} of {UP} bytes", got.len());
    relay.abort();
}

/// #9 (overall cap): progress does not extend the drain past
/// `site_flush_max`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_progressing_drain_is_still_capped() {
    use segue_session::codec::code;
    let (got_tx, _got_rx) = oneshot::channel();
    let site = slow_site(
        1024,
        Duration::from_millis(200),
        Arc::new(Mutex::new(Some(got_tx))),
    );
    let (app, client, relay, mut notes) = flush_pair(
        |t| {
            t.site_flush_idle = Duration::from_secs(1);
            t.site_flush_max = Duration::from_secs(2);
        },
        site,
    );
    // ~10 s of upload at 5 KiB/s.
    let (reason, took) = upload_and_fin(app, &pattern(48 << 10, 3), client).await;
    assert_eq!(reason, CloseReason::Reset(code::SITE_RESET));
    assert_eq!(closed_code(&mut notes).await, code::SITE_RESET);
    assert!(took >= Duration::from_millis(1900), "{took:?}");
    assert!(took < Duration::from_secs(8), "cap not applied: {took:?}");
    relay.abort();
}

/// #11: a site write that fails mid-upload resets the session (never
/// CLEAN), with `site_reset` on record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_site_write_resets_not_clean() {
    use segue_session::codec::code;
    let (app, client, relay, mut notes) = flush_pair(|_| {}, failing_site(8 << 10, false));
    let (reason, _) = upload_and_fin(app, &pattern(24 << 10, 4), client).await;
    assert_eq!(reason, CloseReason::Reset(code::SITE_RESET));
    assert_eq!(closed_code(&mut notes).await, code::SITE_RESET);
    relay.abort();
}

/// #11: every upload byte written but the site's shutdown fails: the FIN
/// never reached the site, so the session is reset, not CLEAN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_site_shutdown_resets_not_clean() {
    use segue_session::codec::code;
    let (app, client, relay, mut notes) = flush_pair(|_| {}, failing_site(usize::MAX, true));
    let (reason, took) = upload_and_fin(app, &pattern(24 << 10, 5), client).await;
    assert_eq!(reason, CloseReason::Reset(code::SITE_RESET));
    assert_eq!(closed_code(&mut notes).await, code::SITE_RESET);
    assert!(
        took < Duration::from_secs(10),
        "waited for a timer: {took:?}"
    );
    relay.abort();
}

/// Poll `f` until it returns true or `limit` passes.
async fn settle(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_sessions_hold_only_their_floors_before_and_after_a_burst() {
    // r7 #7: run N sessions to steady state and look at what the pool
    // holds, not at object counts. An idle session holds its receive
    // credit (the 16 KiB initial window it advertised, which cannot be
    // revoked) and one send-floor block, nothing else: before, every idle
    // driver asked `write_capacity()` for a 16 KiB read-ahead with no data
    // to send, so each idle connection kept 12 KiB more, and after an
    // upload burst the unused promise was never given back.
    use segue_session::pool::BLOCK;
    const N: usize = 6;
    const BURST: usize = 256 << 10;
    const IDLE: Duration = Duration::from_secs(10);
    let cfg = Config::default();
    let floor = cfg.limits.initial_credit + BLOCK;
    let pool = Pool::new(8 << 20);
    let relay_pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), relay_pool, Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(16);
    // The site takes the upload and sends nothing back, so the receive
    // side never earns a window beyond the initial credit.
    let got = Arc::new(AtomicUsize::new(0));
    let sink: SiteConnector = {
        let got = got.clone();
        Arc::new(move |_t, _k| {
            let got = got.clone();
            Box::pin(async move {
                let (a, mut b) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 << 10];
                    while let Ok(n) = b.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        got.fetch_add(n, Ordering::SeqCst);
                    }
                    drop(b);
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let relay = tokio::spawn(run_relay(table, accept_rx, sink, None));
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
    let mut apps = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..N {
        let s = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()).unwrap();
        let (app, far) = tokio::io::duplex(64 << 10);
        clients.push(tokio::spawn(run_client(s, far, connector.clone())));
        apps.push(app);
    }
    // A small request each, then idle: the steady state new sessions are
    // admitted against.
    for a in &mut apps {
        a.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    }
    let want = N * 18;
    assert!(
        settle(IDLE, || got.load(Ordering::SeqCst) == want).await,
        "requests not delivered"
    );
    let ok = settle(IDLE, || pool.used_bytes() == N * floor).await;
    assert!(
        ok,
        "idle: pool holds {} bytes, floors are {}",
        pool.used_bytes(),
        N * floor
    );
    // Burst, then idle again: everything above the floors goes back.
    for (i, a) in apps.iter_mut().enumerate() {
        a.write_all(&pattern(BURST, i as u8)).await.unwrap();
    }
    let want = want + N * BURST;
    assert!(
        settle(IDLE, || got.load(Ordering::SeqCst) == want).await,
        "burst not delivered: {} of {want}",
        got.load(Ordering::SeqCst)
    );
    let ok = settle(IDLE, || pool.used_bytes() == N * floor).await;
    assert!(
        ok,
        "after burst then idle: pool holds {} bytes, floors are {}",
        pool.used_bytes(),
        N * floor
    );
    // And the pool still admits as before.
    assert!(ClientSession::new(cfg, &pool, params(), Instant::now()).is_some());
    drop(apps);
    for c in clients {
        let _ = tokio::time::timeout(Duration::from_secs(10), c).await;
    }
    relay.abort();
}

/// A carrier between the client end `a` and the relay end `b`: both ways
/// until `freeze` is set; then the downlink delivers the header of a
/// `len`-byte DATA frame and `body` bytes of it, never the rest (a carrier
/// that stalls mid-frame), while the uplink keeps moving.
async fn freezable(
    a: DuplexStream,
    b: DuplexStream,
    freeze: Arc<std::sync::atomic::AtomicBool>,
    len: u16,
    body: usize,
) {
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok(n) = ar.read(&mut buf).await {
            if n == 0 || bw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        std::future::pending::<()>().await;
    });
    let mut buf = vec![0u8; 4096];
    loop {
        if freeze.load(Ordering::SeqCst) {
            // DATA, no flags, two-byte varint length.
            let len = len | 0x4000;
            let hdr = [0x10, 0, (len >> 8) as u8, len as u8];
            let _ = aw.write_all(&hdr).await;
            let _ = aw.write_all(&vec![0u8; body]).await;
            let _ = up.await;
            return;
        }
        tokio::select! {
            r = br.read(&mut buf) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => { if aw.write_all(&buf[..n]).await.is_err() { break; } }
            },
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }
    std::future::pending::<()>().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn carriers_that_stopped_moving_cannot_starve_a_healthy_session() {
    // r7 #1: with the elastic part spent, every frame is charged to the
    // transport region. Idle open sessions whose carriers then deliver a
    // frame header and stall each held a frame's charge there waiting for
    // the body (no data in flight, so no stall timer fires), for ever, and
    // the region being cumulative they ate the relay region too, so a
    // session with a working carrier could not read a single ACK. Now the
    // region is disjoint, a body is charged only once it starts arriving,
    // a frame may hold the region only for the pool's hold time (the
    // carrier is then given up; the session resumes on a new one), and the
    // first in line has its frame reserved.
    use segue_session::pool::{Grant, BLOCK};
    const STUCK: usize = 32;
    const PARTIAL: usize = 3;
    const PARTIAL_BODY: usize = 8000;
    const UP: usize = 64 << 10;
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    pool.set_transport_hold(Duration::from_millis(300));
    let table = RelayTable::new(
        cfg.clone(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    // Bytes the sites got: the healthy session's, and everyone's.
    let healthy_got = Arc::new(AtomicUsize::new(0));
    let all_got = Arc::new(AtomicUsize::new(0));
    let sink: SiteConnector = {
        let (healthy_got, all_got) = (healthy_got.clone(), all_got.clone());
        Arc::new(move |t, _k| {
            let mine = matches!(&t, Target::Domain(d, _) if d == "healthy.example");
            let (healthy_got, all_got) = (healthy_got.clone(), all_got.clone());
            Box::pin(async move {
                let (a, mut b) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 << 10];
                    while let Ok(n) = b.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        all_got.fetch_add(n, Ordering::SeqCst);
                        if mine {
                            healthy_got.fetch_add(n, Ordering::SeqCst);
                        }
                    }
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let relay = tokio::spawn(run_relay(table, accept_rx, sink, None));
    // Every carrier goes to the relay through a pump that stops moving
    // bytes once `freeze` is set (healthy ones never freeze); carriers
    // dialled after that are frozen from the start.
    let freeze = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dials = Arc::new(AtomicUsize::new(0));
    let conn = |freeze: Arc<std::sync::atomic::AtomicBool>, len: u16, body: usize| -> Connector {
        let accept_tx = accept_tx.clone();
        let dials = dials.clone();
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            let freeze = freeze.clone();
            dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let (a, mid) = tokio::io::duplex(1024);
                let (to_relay, b) = tokio::io::duplex(64 << 10);
                tokio::spawn(freezable(mid, to_relay, freeze, len, body));
                accept_tx
                    .send(Box::new(b))
                    .await
                    .map_err(|_| std::io::Error::other("gone"))?;
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let healthy_conn = conn(Arc::new(std::sync::atomic::AtomicBool::new(false)), 0, 0);
    // Most stall right after the header of a one-block frame (enough of
    // them to charge every draining block before); a few after part of a
    // large body.
    let stuck_conn = conn(freeze.clone(), 4000, 0);
    let partial_conn = conn(freeze.clone(), 16_000, PARTIAL_BODY);
    let mut hp = params();
    hp.target = Target::Domain("healthy.example".into(), 443);
    let hs = ClientSession::new(cfg.clone(), &pool, hp, Instant::now()).unwrap();
    let (mut happ, hfar) = tokio::io::duplex(64 << 10);
    let healthy = tokio::spawn(run_client(hs, hfar, healthy_conn));
    let mut stuck_apps = Vec::new();
    let mut stuck = Vec::new();
    for i in 0..STUCK + PARTIAL {
        let s = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()).unwrap();
        let (app, far) = tokio::io::duplex(64 << 10);
        let c = if i < STUCK {
            &stuck_conn
        } else {
            &partial_conn
        };
        stuck.push(tokio::spawn(run_client(s, far, c.clone())));
        stuck_apps.push(app);
    }
    // Everyone opens and delivers a first request.
    happ.write_all(b"hello").await.unwrap();
    for a in &mut stuck_apps {
        a.write_all(b"hello").await.unwrap();
    }
    assert!(
        settle(Duration::from_secs(10), || all_got.load(Ordering::SeqCst)
            == 5 * (STUCK + PARTIAL + 1))
        .await,
        "sessions never opened"
    );
    let dialled = dials.load(Ordering::SeqCst);
    // Let the ACKs settle, spend the elastic part, then stall the stuck
    // sessions' downlinks mid-frame.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut hog = Vec::new();
    while let Some(g) = Grant::fixed(&pool, BLOCK) {
        hog.push(g);
    }
    freeze.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A header alone holds nothing; a started body holds its frame, for
    // the hold at most.
    let held = pool.transport_used_blocks();
    assert!(
        held <= PARTIAL * 16_000usize.div_ceil(BLOCK),
        "stalled carriers hold {held} transport blocks"
    );
    // Written from a task: a starved session would never take it all.
    let up = pattern(UP, 5);
    let writer = tokio::spawn(async move {
        let _ = happ.write_all(&up).await;
        happ
    });
    let t0 = Instant::now();
    let ok = settle(Duration::from_secs(20), || {
        healthy_got.load(Ordering::SeqCst) == 5 + UP
    })
    .await;
    println!("healthy upload done in {:?}", t0.elapsed());
    assert!(
        ok,
        "healthy session starved: {} of {UP} bytes delivered (transport region {}/{} blocks, {} waiting)",
        healthy_got.load(Ordering::SeqCst) - 5,
        pool.transport_used_blocks(),
        pool.transport_blocks(),
        pool.queued()
    );
    // Carriers holding transport blocks past the hold were given up.
    assert!(
        settle(Duration::from_secs(5), || dials.load(Ordering::SeqCst)
            >= dialled + PARTIAL)
        .await,
        "stuck carriers were never given up"
    );
    drop(hog);
    drop(writer.await);
    for h in stuck {
        h.abort();
    }
    healthy.abort();
    relay.abort();
}

// ---- Review r8 ----

/// r8 N4: with the default timing (`t_stall` 1 s) the relay holds the
/// client's FIN unacknowledged until the site took the whole upload. A
/// site that drains slowly, with nothing coming back, left the carrier
/// quiet for longer than `t_stall`, so the client took it for stalled and
/// redialled once a second for the whole drain. Now the relay repeats its
/// current ACK while the FIN waits: one carrier, clean end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_site_drain_with_default_timing_does_not_redial() {
    const UP: usize = 24 << 10;
    let (got_tx, got_rx) = oneshot::channel();
    // 2 KiB every 250 ms: about 3 s of drain, three `t_stall`s.
    let site = slow_site(
        2048,
        Duration::from_millis(250),
        Arc::new(Mutex::new(Some(got_tx))),
    );
    let dials = Arc::new(AtomicUsize::new(0));
    let (app, client, relay, mut notes) = flush_pair_cfg(Config::default(), site, dials.clone());
    let up = pattern(UP, 4);
    let (reason, took) = upload_and_fin(app, &up, client).await;
    assert_eq!(reason, CloseReason::Clean, "slow drain was not clean");
    assert_eq!(
        closed_code(&mut notes).await,
        segue_session::codec::code::CLEAN
    );
    assert!(
        took > 2 * Config::default().timing.t_stall,
        "drain took only {took:?}: the test proves nothing"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(got == up, "site got {} of {UP} bytes", got.len());
    let n = dials.load(Ordering::SeqCst);
    println!("slow drain over {took:?}: {n} carrier dial(s)");
    assert_eq!(n, 1, "a healthy carrier was redialled during the drain");
    relay.abort();
}

/// r9 (keepalive assumption): the relay is configured with a 4 s
/// `t_stall`, the client with 1 s. Before, the relay's held-FIN keepalive
/// came every 2 s, and the client took its healthy carrier for stalled
/// once a second for the whole drain. Now the client announces its bound
/// in OPEN/RESUME and the relay keeps alive at half the shorter one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_with_a_shorter_stall_bound_than_the_relay_does_not_redial() {
    const UP: usize = 24 << 10;
    let (got_tx, got_rx) = oneshot::channel();
    // About 3 s of drain: three client `t_stall`s.
    let site = slow_site(
        2048,
        Duration::from_millis(250),
        Arc::new(Mutex::new(Some(got_tx))),
    );
    let mut relay_cfg = Config::default();
    relay_cfg.timing.t_stall = Duration::from_secs(4);
    let mut client_cfg = Config::default();
    client_cfg.timing.t_stall = Duration::from_secs(1);
    let dials = Arc::new(AtomicUsize::new(0));
    let (app, client, relay, mut notes) =
        flush_pair_cfgs(relay_cfg, client_cfg, site, dials.clone());
    let up = pattern(UP, 5);
    let (reason, took) = upload_and_fin(app, &up, client).await;
    assert_eq!(reason, CloseReason::Clean);
    assert_eq!(
        closed_code(&mut notes).await,
        segue_session::codec::code::CLEAN
    );
    assert!(
        took > Duration::from_secs(2),
        "drain took only {took:?}: the test proves nothing"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), got_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(got == up, "site got {} of {UP} bytes", got.len());
    let n = dials.load(Ordering::SeqCst);
    println!("relay 4 s / client 1 s over {took:?}: {n} dial(s)");
    assert_eq!(n, 1, "the client took a live carrier for stalled");
    relay.abort();
}

/// r8 N8: the drain's idle bound counts from the site's last actual write,
/// not from when the relay driver noticed it. The site takes 1 KiB once,
/// some time into the drain, while the site writer is in the middle of a
/// chunk (no wake-up of the driver), then nothing more. Before, the driver
/// noticed the write only when the first idle bound ran out and started
/// the bound again from then: about twice the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_drain_idle_bound_counts_from_the_last_site_write() {
    // Well past the site's buffer: the site writer is in the middle of a
    // chunk when the site takes its late bytes.
    const UP: usize = 48 << 10;
    const IDLE: Duration = Duration::from_millis(1500);
    const LATE: Duration = Duration::from_millis(600);
    let keep = Arc::new(Mutex::new(Vec::new()));
    let site: segue_session::driver::DeviceSiteConnector = {
        let keep = keep.clone();
        Arc::new(move |_r| {
            let keep = keep.clone();
            Box::pin(async move {
                let (a, mut b) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    // Wait for the upload (the buffer fills), then take one
                    // buffer's worth late, then never read again.
                    let mut buf = [0u8; 1];
                    let _ = b.read_exact(&mut buf).await;
                    tokio::time::sleep(LATE).await;
                    let mut buf = vec![0u8; 1023];
                    let _ = b.read_exact(&mut buf).await;
                    keep.lock().unwrap().push(b);
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let (app, client, relay, mut notes) = flush_pair(
        |t| {
            t.site_flush_idle = IDLE;
            t.site_flush_max = Duration::from_secs(60);
        },
        site,
    );
    let up = pattern(UP, 5);
    let (reason, took) = upload_and_fin(app, &up, client).await;
    assert_ne!(reason, CloseReason::Clean, "a stuck drain ended clean");
    assert_ne!(
        closed_code(&mut notes).await,
        segue_session::codec::code::CLEAN
    );
    println!("stuck drain reset {took:?} after the FIN");
    assert!(took >= IDLE, "reset before the idle bound: {took:?}");
    assert!(
        took < LATE + IDLE + Duration::from_millis(300),
        "reset {took:?} after the FIN: the idle bound did not count from the last write"
    );
    relay.abort();
}

/// A carrier that moves at most `chunk` bytes every `every` each way: a
/// slow path that keeps moving.
fn throttled_connector(
    accept_tx: mpsc::Sender<BoxCarrier>,
    dials: Arc<AtomicUsize>,
    chunk: usize,
    every: Duration,
) -> Connector {
    async fn pump(
        mut from: tokio::io::ReadHalf<DuplexStream>,
        mut to: tokio::io::WriteHalf<DuplexStream>,
        chunk: usize,
        every: Duration,
    ) {
        let mut buf = vec![0u8; chunk];
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown().await;
    }
    Arc::new(move || {
        let accept_tx = accept_tx.clone();
        dials.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let (client, ca) = tokio::io::duplex(chunk);
            let (rb, relay) = tokio::io::duplex(chunk);
            let (car, caw) = tokio::io::split(ca);
            let (rbr, rbw) = tokio::io::split(rb);
            tokio::spawn(pump(car, rbw, chunk, every));
            tokio::spawn(pump(rbr, caw, chunk, every));
            accept_tx
                .send(Box::new(relay))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(client) as BoxCarrier)
        })
    })
}

/// A site that sends `down` in large writes (so the relay sends full
/// frames) while it takes the upload, then ends.
fn bulk_site(down: Arc<Vec<u8>>) -> SiteConnector {
    Arc::new(move |_t, _k| {
        let down = down.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(256 << 10);
            let (mut r, mut w) = tokio::io::split(b);
            tokio::spawn(async move {
                let _ = w.write_all(&down).await;
                let _ = w.shutdown().await;
                std::future::pending::<()>().await;
                drop(w);
            });
            tokio::spawn(async move {
                let mut sink = Vec::new();
                let _ = r.read_to_end(&mut sink).await;
                std::future::pending::<()>().await;
                drop(r);
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// An echo site.
fn echo_site() -> SiteConnector {
    Arc::new(|_t, _k| {
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
                let _ = b.shutdown().await;
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// Upload `len` bytes and download `len` (sent by the site in large
/// writes, so in full frames) through a carrier moving `chunk` per `every`
/// each way, with the default timing and the client's elastic
/// blocks spent (every frame is charged to the transport region and so
/// under its hold). Returns the session's end, the time, and the dials.
async fn slow_echo(len: usize, chunk: usize, every: Duration) -> (CloseReason, Duration, usize) {
    use segue_session::pool::{Grant, Tier, BLOCK};
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(
        cfg.clone(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(16);
    let want = Arc::new(pattern(len, 7));
    let relay = tokio::spawn(run_relay(table, accept_rx, bulk_site(want.clone()), None));
    let dials = Arc::new(AtomicUsize::new(0));
    let connector = throttled_connector(accept_tx, dials.clone(), chunk, every);
    let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(512 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    // Spend the elastic part, and keep it spent: what other flows hold.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hog = tokio::spawn({
        let (pool, done) = (pool.clone(), done.clone());
        async move {
            let mut hog = Vec::new();
            while !done.load(Ordering::SeqCst) {
                while let Some(g) = Grant::fixed(&pool, BLOCK) {
                    hog.push(g);
                }
                assert!(pool.used_blocks() >= pool.limit(Tier::Elastic));
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            hog.len()
        }
    });
    let up = pattern(len, 6);
    let t0 = Instant::now();
    let (mut ar, mut aw) = tokio::io::split(&mut app);
    let (w, r) = tokio::join!(
        async {
            aw.write_all(&up).await.unwrap();
            aw.shutdown().await.unwrap();
        },
        async {
            let mut down = Vec::new();
            let _ = ar.read_to_end(&mut down).await;
            down
        }
    );
    let () = w;
    let took = t0.elapsed();
    let reason = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client did not end")
        .unwrap();
    done.store(true, Ordering::SeqCst);
    let hogged = hog.await.unwrap();
    assert!(hogged > 100, "the pool was never spent ({hogged} blocks)");
    assert!(
        r.len() == len,
        "download {} of {len} bytes; session ended {reason:?} after {took:?}, {} dial(s)",
        r.len(),
        dials.load(Ordering::SeqCst)
    );
    assert!(r == *want, "download differs");
    relay.abort();
    (reason, took, dials.load(Ordering::SeqCst))
}

/// r8 N5: a 20 KB/s path, default parameters, transport region only:
/// the transfer completes with a bounded number of carriers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_20kbps_carrier_completes_with_default_timing_and_bounded_redials() {
    let (reason, took, dials) = tokio::time::timeout(
        Duration::from_secs(60),
        slow_echo(96 << 10, 2000, Duration::from_millis(100)),
    )
    .await
    .expect("slow transfer did not finish");
    println!("96 KiB each way at 20 KB/s in {took:?}: {dials} dial(s)");
    assert_eq!(reason, CloseReason::Clean);
    assert!(dials <= 2, "{dials} carriers for a slow but working path");
}

/// r8 N5: slower still (5 KB/s): a full frame takes over 3 s to cross,
/// longer than the transport hold (2 s), `t_stall` (1 s) and `t_live`
/// (3 s). Each was an absolute bound on a frame or on the gap between
/// whole frames, so every frame was cut and replayed into the same bound,
/// for ever. Now they count bytes moving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_slower_than_every_hold_still_crosses() {
    let (reason, took, dials) = tokio::time::timeout(
        Duration::from_secs(60),
        slow_echo(40 << 10, 500, Duration::from_millis(100)),
    )
    .await
    .expect("slow transfer did not finish");
    println!("40 KiB each way at 5 KB/s in {took:?}: {dials} dial(s)");
    assert_eq!(reason, CloseReason::Clean);
    assert!(
        took > Duration::from_secs(8),
        "{took:?}: not slow enough to prove anything"
    );
    assert!(dials <= 2, "{dials} carriers for a slow but working path");
}

/// r8 N5: carriers that open and then move nothing are redialled with a
/// growing backoff, and the session gives up after a bounded number.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_carriers_are_redialled_with_backoff_and_a_bound() {
    use segue_session::client::{LOCAL_GIVE_UP, MAX_FRUITLESS};
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(
        cfg.clone(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let relay = tokio::spawn(run_relay(table, accept_rx, echo_site(), None));
    let dials = Arc::new(AtomicUsize::new(0));
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let keep = Arc::new(Mutex::new(Vec::new()));
    // The first carrier works; every later one accepts and black-holes.
    let connector: Connector = {
        let (dials, first, keep) = (dials.clone(), first.clone(), keep.clone());
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            let keep = keep.clone();
            dials.fetch_add(1, Ordering::SeqCst);
            let live = first.swap(false, Ordering::SeqCst);
            Box::pin(async move {
                let (a, b) = tokio::io::duplex(64 << 10);
                if live {
                    accept_tx
                        .send(Box::new(b))
                        .await
                        .map_err(|_| std::io::Error::other("gone"))?;
                } else {
                    keep.lock().unwrap().push(b);
                }
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let mut cfg2 = cfg.clone();
    // Only the bound on fruitless carriers may end it; an unanswered
    // attach is given up quickly.
    cfg2.timing.t_detached = Duration::from_secs(600);
    cfg2.timing.t_attach = Duration::from_millis(300);
    let s = ClientSession::new(cfg2, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(64 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    app.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    app.read_exact(&mut buf).await.unwrap();
    // Cut the working carrier: the relay is gone, data is outstanding.
    relay.abort();
    app.write_all(&pattern(4096, 1)).await.unwrap();
    let t0 = Instant::now();
    let reason = match tokio::time::timeout(Duration::from_secs(60), client).await {
        Ok(r) => r.unwrap(),
        Err(_) => panic!(
            "session kept going: {} dial(s) in 60 s",
            dials.load(Ordering::SeqCst)
        ),
    };
    let took = t0.elapsed();
    let n = dials.load(Ordering::SeqCst);
    println!("gave up after {took:?} and {n} dials");
    assert_eq!(reason, CloseReason::Reset(LOCAL_GIVE_UP));
    // The working carrier, then exactly MAX_FRUITLESS dead ones: the
    // MAX_FRUITLESS-th fruitless carrier ends the session (r9: before,
    // `fruitless > MAX_FRUITLESS` gave up only on the one after).
    assert_eq!(n, 1 + MAX_FRUITLESS as usize, "{n} dials for a dead path");
    // The backoff spaced them: without it the attempts take t_attach
    // each (2.7 s in all).
    assert!(
        took >= Duration::from_secs(6),
        "gave up after only {took:?}"
    );
}

/// Checklist r8 #3: what a burst each way leaves held once sessions go
/// idle, then how many more *fresh* sessions (and pipes) the pool takes
/// on top. Only 24 of them ran, so its 260+ is not a steady-state
/// capacity: that is ~181 (at least 170) sessions that all ran
/// (`each_session_reaches_steady_state_before_the_next_is_admitted`, r10).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_is_measured_after_sessions_reach_steady_state() {
    use segue_session::pipe::pipe;
    use segue_session::pool::BLOCK;
    const N: usize = 24;
    const BURST: usize = 192 << 10;
    let cfg = Config::default();
    let floor = cfg.limits.initial_credit + BLOCK;
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(
        cfg.clone(),
        Pool::new(16 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let relay = tokio::spawn(run_relay(table, accept_rx, echo_site(), None));
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
    let mut apps = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..N {
        let s = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()).unwrap();
        let (app, far) = tokio::io::duplex(64 << 10);
        clients.push(tokio::spawn(run_client(s, far, connector.clone())));
        apps.push(app);
    }
    // A burst each way on every session, all at once.
    let mut peak = 0;
    let mut jobs = Vec::new();
    for (i, mut a) in apps.drain(..).enumerate() {
        jobs.push(tokio::spawn(async move {
            let up = pattern(BURST, i as u8);
            let (mut r, mut w) = tokio::io::split(&mut a);
            let (_, down) = tokio::join!(w.write_all(&up), async {
                let mut down = vec![0u8; BURST];
                r.read_exact(&mut down).await.map(|_| down)
            });
            assert!(down.unwrap() == up, "echo differs");
            a
        }));
    }
    let mut done = Vec::new();
    for j in jobs {
        while !j.is_finished() {
            peak = peak.max(pool.used_blocks());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        done.push(j.await.unwrap());
    }
    // Idle: the steady state new flows are admitted against. A session
    // that received keeps the credit it advertised and the peer has not
    // used yet (it cannot be revoked, r7 #7): up to one more initial
    // window above its floors. Wait until nothing more goes back.
    let mut last = usize::MAX;
    let mut since = Instant::now();
    while since.elapsed() < Duration::from_secs(2) {
        let u = pool.used_bytes();
        if u != last {
            last = u;
            since = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Since the receive window grows with delivery rate × SRTT (§4 rule
    // 8), a session that ran keeps the window it last advertised, which
    // the peer has not used and which cannot be revoked: its floors plus
    // at most one grown window (in practice ~90 KiB here, never the cap
    // for all 24 since growth stops at the fair share under pressure).
    let held = pool.used_bytes();
    let bound = N * floor + pool.capacity_bytes() * 3 / 4;
    assert!(
        held <= bound,
        "idle after the burst: {N} sessions hold {held} bytes, more than {bound}"
    );
    let mut more = Vec::new();
    while let Some(s) = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()) {
        let Some(p) = pipe(&pool, 64 << 10) else {
            break;
        };
        more.push((s, p));
    }
    let total = N + more.len();
    println!(
        "{N} sessions after a {} KiB burst each way (peak {} KiB of the pool, idle {:.1} KiB each, floors {} KiB): {} more admitted, {total} in all",
        BURST >> 10,
        (peak * BLOCK) >> 10,
        held as f64 / N as f64 / 1024.0,
        floor >> 10,
        more.len()
    );
    // Fresh pools admit at least 280 (the_8mb_pool_admits_hundreds_of_
    // flows, ~29 KiB each); what the 24 that ran still hold is taken at
    // that same rate: every 32 KiB left in the pool is another flow. With
    // every session having run, the figure is ~181 (see above).
    let free = pool.capacity_bytes() - held;
    assert!(
        more.len() * (32 << 10) >= free,
        "{} fresh flows in {free} free bytes",
        more.len()
    );
    assert!(total >= 200, "{total} flows (24 that ran, the rest fresh)");
    drop(more);
    drop(done);
    for c in clients {
        let _ = tokio::time::timeout(Duration::from_secs(10), c).await;
    }
    relay.abort();
}

/// A relay-side carrier end whose writes stop completing once `block` is
/// set (the client stopped reading: the relay's writer is stuck and its
/// queue fills), while reads keep working.
struct Blockable {
    inner: DuplexStream,
    block: Arc<std::sync::atomic::AtomicBool>,
}

impl AsyncRead for Blockable {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Blockable {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.block.load(Ordering::SeqCst) {
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// r9 F3: the client's FIN is held (the site never takes the upload) and
/// the relay's carrier writer is blocked (the client stopped reading), so
/// the held-FIN keepalive and the ACK of the upload can not go out; after
/// `t_live` the session is also DETACHED. Before, their deadlines stayed
/// in the past and the relay driver woke in a loop for as long as that
/// lasted. Now it waits for the writer: a few seconds of it cost almost
/// no CPU.
#[tokio::test]
async fn relay_does_not_spin_with_a_held_fin_and_a_blocked_writer() {
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), pool.clone(), Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    // The site sends an endless download and never reads the upload.
    let site_conn: SiteConnector = Arc::new(|_t, _k| {
        Box::pin(async {
            let (a, mut b) = tokio::io::duplex(4 << 10);
            tokio::spawn(async move {
                let chunk = vec![7u8; 4096];
                while b.write_all(&chunk).await.is_ok() {}
                std::future::pending::<()>().await;
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let relay = tokio::spawn(run_relay(table, accept_rx, site_conn, None));
    let block = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let connector: Connector = {
        let (block, first) = (block.clone(), first.clone());
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            let block = block.clone();
            let live = first.swap(false, Ordering::SeqCst);
            Box::pin(async move {
                if !live {
                    // No second carrier: only the first one's relay side
                    // is measured.
                    std::future::pending::<()>().await;
                }
                let (a, b) = tokio::io::duplex(64 << 10);
                accept_tx
                    .send(Box::new(Blockable { inner: b, block }))
                    .await
                    .map_err(|_| std::io::Error::other("gone"))?;
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    // The client never takes its quiet carrier for a stalled one here.
    let mut ccfg = cfg.clone();
    ccfg.timing.t_stall = Duration::from_secs(60);
    ccfg.timing.t_detached = Duration::from_secs(600);
    let s = ClientSession::new(ccfg, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(1 << 20);
    let client = tokio::spawn(run_client(s, far, connector));
    app.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), app.read(&mut buf))
        .await
        .expect("no download")
        .unwrap();
    assert!(n > 0);
    // Block the relay's writer, then upload and FIN: the relay acknowledges
    // nothing from here on and holds the FIN.
    block.store(true, Ordering::SeqCst);
    app.write_all(&pattern(8 << 10, 3)).await.unwrap();
    app.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Past the keepalive (t_stall / 2) and, at 3 s, t_live (DETACHED).
    let cpu = thread_cpu();
    tokio::time::sleep(Duration::from_secs(4)).await;
    let used = thread_cpu() - cpu;
    println!("held FIN, blocked writer: {used:?} CPU in 4 s");
    assert!(
        used < CPU_LIMIT,
        "relay burnt {used:?} CPU with a held FIN and a blocked writer"
    );
    client.abort();
    relay.abort();
}

/// A site that takes the whole upload, sends nothing, and closes after
/// the upload's end.
fn sink_site() -> SiteConnector {
    Arc::new(|_t, _k| {
        Box::pin(async {
            let (a, mut b) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let mut sink = vec![0u8; 16 << 10];
                while b.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                let _ = b.shutdown().await;
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// r9 (write side cap): a frame charged to the transport region waits in
/// the carrier's writer queue behind frames queued before it (charged to
/// the elastic part while it lasted). The carrier moves bytes steadily,
/// only slowly: the frames ahead take longer than the hold cap, the frame
/// itself much less. Before, the cap counted from when the frame was
/// queued, so the healthy carrier was given up; now it counts from when
/// the writer starts on the frame. (Scaled: cap 2.5 s, hold 1 s, 10 KB/s,
/// so one 16 KiB frame takes 1.6 s and the ~16 KiB send window queued
/// ahead of it about as much again.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_write_hold_cap_counts_from_the_frame_start_not_its_enqueue() {
    use segue_session::pool::{Grant, BLOCK};
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    pool.set_transport_hold(Duration::from_secs(1));
    pool.set_transport_hold_max(Duration::from_millis(2500));
    let table = RelayTable::new(
        cfg.clone(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(16);
    let (note_tx, mut notes) = mpsc::unbounded_channel();
    let relay = tokio::spawn(run_relay(table, accept_rx, sink_site(), Some(note_tx)));
    let dials = Arc::new(AtomicUsize::new(0));
    let connector = throttled_connector(accept_tx, dials.clone(), 1000, Duration::from_millis(100));
    let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(512 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    const UP: usize = 64 << 10;
    app.write_all(&pattern(UP, 8)).await.unwrap();
    app.shutdown().await.unwrap();
    // The send window's worth of elastic frames is queued; then the
    // elastic part runs out and the next frame is charged to the
    // transport region, behind them.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hog = tokio::spawn({
        let (pool, done) = (pool.clone(), done.clone());
        async move {
            let mut hog = Vec::new();
            while !done.load(Ordering::SeqCst) {
                while let Some(g) = Grant::fixed(&pool, BLOCK) {
                    hog.push(g);
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            hog.len()
        }
    });
    let reason = tokio::time::timeout(Duration::from_secs(30), client)
        .await
        .expect("client did not end")
        .unwrap();
    done.store(true, Ordering::SeqCst);
    assert!(hog.await.unwrap() > 100, "the pool was never spent");
    let n = dials.load(Ordering::SeqCst);
    println!("write hold behind queued frames: {reason:?}, {n} dial(s)");
    assert_eq!(reason, CloseReason::Clean);
    let _ = notes.try_recv();
    assert_eq!(n, 1, "a carrier that kept moving was given up");
    relay.abort();
}

/// r9 F7: admission measured one session at a time, each driven to its
/// steady state by a real transfer (a burst each way through its app pipe
/// and carrier, then idle until the pool stops changing) before the next
/// is admitted; until the 8 MiB pool refuses. Every admitted session then
/// still moves data (the first and the last), with the pool full.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_session_reaches_steady_state_before_the_next_is_admitted() {
    use segue_session::pipe::pipe;
    use segue_session::pool::BLOCK;
    const BURST: usize = 32 << 10;
    const MAX: usize = 1000;
    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(
        cfg.clone(),
        Pool::new(256 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let relay = tokio::spawn(run_relay(table, accept_rx, echo_site(), None));
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
    async fn echo_burst<A: AsyncRead + AsyncWrite + Unpin>(app: &mut A, salt: u8) {
        let up = pattern(BURST, salt);
        let (mut r, mut w) = tokio::io::split(app);
        let (_, down) = tokio::join!(async { w.write_all(&up).await.unwrap() }, async {
            let mut d = vec![0u8; BURST];
            r.read_exact(&mut d).await.unwrap();
            d
        });
        assert!(down == up, "echo differs");
    }
    async fn steady(pool: &Pool) -> usize {
        let mut last = usize::MAX;
        let mut since = Instant::now();
        let t0 = Instant::now();
        while since.elapsed() < Duration::from_millis(80) && t0.elapsed() < Duration::from_secs(3) {
            let u = pool.used_bytes();
            if u != last {
                last = u;
                since = Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        pool.used_bytes()
    }
    let mut apps = Vec::new();
    let mut clients = Vec::new();
    let mut worst = 0usize;
    let mut refused = "";
    while apps.len() < MAX {
        let before = pool.used_bytes();
        let Some(s) = ClientSession::new(cfg.clone(), &pool, params(), Instant::now()) else {
            refused = "session";
            break;
        };
        let Some((mut app, far)) = pipe(&pool, 64 << 10) else {
            refused = "pipe";
            break;
        };
        clients.push(tokio::spawn(run_client(s, far, connector.clone())));
        tokio::time::timeout(
            Duration::from_secs(10),
            echo_burst(&mut app, apps.len() as u8),
        )
        .await
        .unwrap_or_else(|_| panic!("session {} stalled in its burst", apps.len()));
        let after = steady(&pool).await;
        worst = worst.max(after.saturating_sub(before));
        apps.push(app);
    }
    let n = apps.len();
    let held = pool.used_bytes();
    println!(
        "{n} sessions admitted one by one after a {} KiB echo each ({refused} refused): \
         {:.1} KiB each idle, worst {:.1} KiB",
        BURST >> 10,
        held as f64 / n as f64 / 1024.0,
        worst as f64 / 1024.0
    );
    assert!(n < MAX, "the pool never refused");
    // Steady state per session: its floors (initial credit, a replay
    // block, a pipe block each way) plus the credit it advertised and the
    // peer has not used (at most one more initial window, r7 #7), and a
    // read buffer block. Measured: about 45 KiB each, so the 8 MiB pool
    // holds ~180 sessions that ran (fresh ones: 280+). Raising that is
    // the protocol v0.5 item (initial credit), not this test's.
    let per = 2 * cfg.limits.initial_credit + 4 * BLOCK;
    assert!(
        held <= n * per,
        "{n} sessions hold {held} bytes at steady state, over {per} each"
    );
    assert!(n >= 170, "only {n} sessions at steady state");
    // The pool is full; earlier and later sessions still move data.
    let last = n - 1;
    for i in [0, last] {
        tokio::time::timeout(Duration::from_secs(20), echo_burst(&mut apps[i], 0x33))
            .await
            .unwrap_or_else(|_| panic!("session {i} stalled with the pool full"));
    }
    drop(apps);
    for c in clients {
        let _ = tokio::time::timeout(Duration::from_secs(10), c).await;
    }
    relay.abort();
}

/// A scripted relay end for one carrier: answers the client's OPEN with
/// OPENED (or a RESUME with RESUMED), waits `hold`, writes `tail` and
/// closes the carrier.
async fn answer_then_cut(mut b: DuplexStream, hold: Duration, tail: Vec<u8>) {
    use segue_session::codec::{Frame, FrameDecoder, Opened, Resumed};
    let mut dec = FrameDecoder::new();
    let mut buf = [0u8; 4096];
    let answer = loop {
        let n = match b.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        dec.push(&buf[..n]);
        match dec.next_frame() {
            Ok(Some(Frame::Open(o))) => {
                break Frame::Opened(Opened {
                    instance_id: INSTANCE,
                    attach_gen: o.attach_gen,
                    recv_offset: o.first_data.len() as u64,
                    max_offset: 1 << 20,
                    window_cap: 1 << 20,
                    ack_bytes: 0,
                })
            }
            Ok(Some(Frame::Resume(r))) => {
                break Frame::Resumed(Resumed {
                    instance_id: INSTANCE,
                    attach_gen: r.attach_gen,
                    recv_offset: 0,
                    max_offset: 1 << 20,
                })
            }
            Ok(_) => {}
            Err(_) => return,
        }
    };
    if b.write_all(&answer.to_bytes()).await.is_err() {
        return;
    }
    tokio::time::sleep(hold).await;
    let _ = b.write_all(&tail).await;
    // Drop: EOF on the client's reader.
}

/// r10 N5: a carrier that ends inside a frame header (after the type
/// byte, the flags, or part of the length varint) owed the rest of the
/// frame, as one that ends inside a body does: it counts against the
/// recovery budget. Download-only (nothing of ours outstanding, no STALL
/// hint) and cut well after `t_live`, so nothing else counts it: before,
/// such a path was redialled for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn carriers_cut_inside_a_frame_header_count_against_the_budget() {
    use segue_session::client::{LOCAL_GIVE_UP, MAX_FRUITLESS};
    use segue_session::codec::Frame;
    // 100 bytes: a 2-byte length varint. The encoder never needs a
    // 4-byte one (MAX_PAYLOAD fits in two), but a peer may send any
    // varint form: the same frame with its length as 4 bytes.
    let small = Frame::Data {
        offset: 0,
        data: vec![7; 100],
        pad: 0,
    }
    .to_bytes();
    assert_eq!(small[2] >> 6, 1, "2-byte varint");
    let len = (small.len() - 4) as u32;
    let mut big = small[..2].to_vec();
    big.extend_from_slice(&(len | 0x8000_0000).to_be_bytes());
    big.extend_from_slice(&small[4..]);
    let mut cuts: Vec<(&'static str, Vec<u8>)> = vec![
        ("type", small[..1].to_vec()),
        ("type+flags", small[..2].to_vec()),
        ("varint 1/2", small[..3].to_vec()),
    ];
    for k in 1..4 {
        cuts.push((
            ["", "varint 1/4", "varint 2/4", "varint 3/4"][k],
            big[..2 + k].to_vec(),
        ));
    }
    // Cut after `t_live` (not a brief carrier: only the truncation counts
    // it) and before (brief: counted either way).
    let cases = [
        (Duration::from_millis(300), Duration::from_millis(100)),
        (Duration::from_millis(50), Duration::from_secs(1)),
    ];
    let runs = cuts
        .into_iter()
        .flat_map(|(name, tail)| cases.map(|c| (name, tail.clone(), c)))
        .map(|(name, tail, (hold, t_live))| {
            tokio::spawn(async move {
                let dials = Arc::new(AtomicUsize::new(0));
                let connector: Connector = {
                    let (dials, tail) = (dials.clone(), tail.clone());
                    Arc::new(move || {
                        dials.fetch_add(1, Ordering::SeqCst);
                        let tail = tail.clone();
                        Box::pin(async move {
                            let (a, b) = tokio::io::duplex(64 << 10);
                            tokio::spawn(answer_then_cut(b, hold, tail));
                            Ok(Box::new(a) as BoxCarrier)
                        })
                    })
                };
                let mut cfg = Config::default();
                cfg.timing.t_live = t_live;
                cfg.timing.t_detached = Duration::from_secs(600);
                let pool = Pool::new(8 << 20);
                let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
                // The app keeps its end open and sends nothing.
                let (_app, far) = tokio::io::duplex(64 << 10);
                let r =
                    tokio::time::timeout(Duration::from_secs(40), run_client(s, far, connector))
                        .await;
                let n = dials.load(Ordering::SeqCst);
                (format!("{name} hold {hold:?} t_live {t_live:?}"), r, n)
            })
        });
    for run in runs.collect::<Vec<_>>() {
        let (name, r, n) = run.await.unwrap();
        let reason = r.unwrap_or_else(|_| panic!("{name}: redialled for ever ({n} dials in 40 s)"));
        assert_eq!(reason, CloseReason::Reset(LOCAL_GIVE_UP), "{name}");
        // OPENED resets the budget, so the first carrier counts as one.
        assert_eq!(n, MAX_FRUITLESS as usize, "{name}: {n} dials");
    }
}

/// r10 N4: the client's pool is full (no elastic block left) and the
/// session's one transport-region frame is stuck in a slow writer, whose
/// queue still has room; meanwhile the relay keeps sending DATA, so a
/// delayed ACK falls due. It cannot be sent without credit: before, its
/// deadline stayed in the past and the driver woke in a loop until the
/// writer moved. Now it waits for credit (or the writer), at almost no
/// CPU and a bounded number of wakeups.
#[tokio::test]
async fn client_does_not_spin_on_an_ack_it_has_no_credit_for() {
    use segue_session::codec::{Frame, FrameDecoder, Opened};
    use segue_session::pool::Tier;
    let pool = Pool::new(1 << 20);
    // Only the bound under test may end the stuck frame.
    pool.set_transport_hold(Duration::from_secs(60));
    pool.set_transport_hold_max(Duration::from_secs(60));
    let dials = Arc::new(AtomicUsize::new(0));
    let sent = Arc::new(AtomicUsize::new(0));
    // Set: the relay end reads again, and counts the ACKs it gets.
    let go = Arc::new(tokio::sync::Notify::new());
    let acks = Arc::new(AtomicUsize::new(0));
    let connector: Connector = {
        let (dials, sent, go, acks) = (dials.clone(), sent.clone(), go.clone(), acks.clone());
        Arc::new(move || {
            let (sent, go, acks) = (sent.clone(), go.clone(), acks.clone());
            dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                // A tiny pipe: the relay end reads the OPEN and then
                // nothing, so the client's writer blocks inside its next
                // frame.
                let (a, b) = tokio::io::duplex(256);
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(b);
                    let mut dec = FrameDecoder::new();
                    let mut buf = [0u8; 256];
                    let gen = loop {
                        let n = r.read(&mut buf).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        dec.push(&buf[..n]);
                        if let Ok(Some(Frame::Open(o))) = dec.next_frame() {
                            break o.attach_gen;
                        }
                    };
                    let opened = Frame::Opened(Opened {
                        instance_id: INSTANCE,
                        attach_gen: gen,
                        recv_offset: 0,
                        max_offset: 1 << 30,
                        window_cap: 1 << 30,
                        ack_bytes: 0,
                    });
                    if w.write_all(&opened.to_bytes()).await.is_err() {
                        return;
                    }
                    tokio::spawn(async move {
                        go.notified().await;
                        loop {
                            let n = r.read(&mut buf).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            dec.push(&buf[..n]);
                            while let Ok(Some(f)) = dec.next_frame() {
                                if matches!(f, Frame::Ack { .. }) {
                                    acks.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                    });
                    // A slow download, 200 bytes every 20 ms.
                    let mut off = 0u64;
                    loop {
                        let f = Frame::Data {
                            offset: off,
                            data: vec![9; 200],
                            pad: 0,
                        };
                        if w.write_all(&f.to_bytes()).await.is_err() {
                            return;
                        }
                        off += 200;
                        sent.store(off as usize, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let mut cfg = Config::default();
    cfg.timing.t_stall = Duration::from_secs(60);
    cfg.timing.t_live = Duration::from_secs(60);
    let s = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(64 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), app.read(&mut buf))
        .await
        .expect("no download")
        .unwrap();
    assert!(n > 0);
    // Spend every elastic block, then upload: the next frame takes the
    // transport slot and sticks in the writer.
    let mut held = 0;
    loop {
        let k = pool.take_blocks(1 << 20, 1, pool.limit(Tier::Elastic));
        if k == 0 {
            break;
        }
        held += k;
    }
    app.write_all(&pattern(4 << 10, 5)).await.unwrap();
    // The app keeps taking the download (so ACKs fall due).
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok(n) = app.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        app
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        pool.transport_used_blocks() > 0,
        "no frame in the transport region"
    );
    let cpu = thread_cpu();
    let at = sent.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let used = thread_cpu() - cpu;
    println!("full pool, stuck slot, ACK due: {used:?} CPU in 2 s");
    assert!(sent.load(Ordering::SeqCst) > at, "the download stopped");
    assert!(
        used < CPU_LIMIT,
        "client burnt {used:?} CPU on an ACK it had no credit for"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1, "carrier given up");
    // Credit comes back and the relay reads again: the stuck frame
    // completes, and ACKs go out promptly.
    pool.give_blocks(held);
    go.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while acks.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("no ACK after credit came back");
    assert!(!client.is_finished(), "session ended");
    client.abort();
    reader.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redundant_tx_sheds_under_pool_pressure_without_blocking_primary() {
    use segue_session::driver::{run_client_standby, StandbyCtl, StandbyEvent};
    use segue_session::pool::Tier;
    let pool = Pool::new(256 << 10);
    let relay_pool = Pool::new(8 << 20);
    let mut params = params();
    params.exit_class = segue_session::EXIT_CLASS_AI;
    let s = ClientSession::new(Config::default(), &pool, params, Instant::now()).unwrap();
    let table = RelayTable::new(Config::default(), relay_pool, Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(8);
    let relay = tokio::spawn(run_relay(
        table,
        accept_rx,
        Arc::new(|_t, _k| {
            Box::pin(async {
                let (s, mut r) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if r.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                Ok(Box::new(s) as BoxCarrier)
            })
        }),
        None,
    ));
    let connector: Connector = Arc::new(move || {
        let tx = accept_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(64 << 10);
            tx.send(Box::new(b) as BoxCarrier).await.unwrap();
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let bound = Arc::new(AtomicBool::new(false));
    let (mut app, far) = tokio::io::duplex(64 << 10);
    let ctl = ClientCtl {
        standby: Some(StandbyCtl {
            connect: connector.clone(),
            allowed: Arc::new(|| true),
            on_event: Arc::new({
                let bound = bound.clone();
                move |ev| {
                    if ev == StandbyEvent::Bound {
                        bound.store(true, Ordering::SeqCst);
                    }
                }
            }),
            swaps: None,
        }),
        ..Default::default()
    };
    let client = tokio::spawn(run_client_standby(s, far, connector, ctl));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !bound.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("standby never bound");

    // Exhaust the elastic region so `pool.under_pressure()` is true. Primary
    // still progresses via Tier::Transport while redundant TX sheds cleanly.
    let held = pool.take_blocks(1 << 20, 1, pool.limit(Tier::Elastic));
    assert!(pool.under_pressure());
    let msg = vec![0x55u8; 256];
    let mut got = vec![0u8; 256];
    for _ in 0..8 {
        app.write_all(&msg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut got))
            .await
            .expect("primary blocked under pool pressure with bound standby")
            .unwrap();
        assert_eq!(got, msg);
    }
    pool.give_blocks(held);
    drop(app);
    let reason = tokio::time::timeout(Duration::from_secs(5), client)
        .await
        .expect("client never finished")
        .unwrap();
    assert_eq!(reason, CloseReason::Clean);
    relay.abort();
}

#[tokio::test]
async fn reattach_aborts_in_flight_standby_dial_and_rearms() {
    use segue_session::driver::{run_client_standby, StandbyCtl, StandbyEvent};
    let pool = Pool::new(2 << 20);
    let relay_pool = Pool::new(2 << 20);
    let mut params = params();
    params.exit_class = segue_session::EXIT_CLASS_AI;
    let s = ClientSession::new(Config::default(), &pool, params, Instant::now()).unwrap();
    let table = RelayTable::new(Config::default(), relay_pool, Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(8);
    let relay = tokio::spawn(run_relay(
        table,
        accept_rx,
        Arc::new(|_t, _k| {
            Box::pin(async {
                let (s, _r) = tokio::io::duplex(64 << 10);
                Ok(Box::new(s) as BoxCarrier)
            })
        }),
        None,
    ));
    let main_conn: Connector = Arc::new({
        let accept_tx = accept_tx.clone();
        move || {
            let tx = accept_tx.clone();
            Box::pin(async move {
                let (a, b) = tokio::io::duplex(64 << 10);
                tx.send(Box::new(b) as BoxCarrier).await.unwrap();
                Ok(Box::new(a) as BoxCarrier)
            })
        }
    });
    struct AbortGuard(Arc<AtomicBool>);
    impl Drop for AbortGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let attempt = Arc::new(AtomicUsize::new(0));
    let aborted = Arc::new(AtomicBool::new(false));
    let first_started = Arc::new(AtomicBool::new(false));
    let bound = Arc::new(AtomicUsize::new(0));
    let standby_conn: Connector = Arc::new({
        let (accept_tx, attempt, aborted, first_started) = (
            accept_tx,
            attempt.clone(),
            aborted.clone(),
            first_started.clone(),
        );
        move || {
            let k = attempt.fetch_add(1, Ordering::SeqCst);
            let tx = accept_tx.clone();
            let aborted = aborted.clone();
            let first_started = first_started.clone();
            Box::pin(async move {
                if k == 0 {
                    let _guard = AbortGuard(aborted);
                    first_started.store(true, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                let (a, b) = tokio::io::duplex(64 << 10);
                tx.send(Box::new(b) as BoxCarrier).await.unwrap();
                Ok(Box::new(a) as BoxCarrier)
            })
        }
    });
    let (reattach_tx, reattach_rx) = tokio::sync::watch::channel(0u64);
    let (_app, far) = tokio::io::duplex(64 << 10);
    let ctl = ClientCtl {
        reattach: Some(reattach_rx),
        standby: Some(StandbyCtl {
            connect: standby_conn,
            allowed: Arc::new(|| true),
            on_event: Arc::new({
                let bound = bound.clone();
                move |ev| {
                    if ev == StandbyEvent::Bound {
                        bound.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }),
            swaps: None,
        }),
        ..Default::default()
    };
    let client = tokio::spawn(run_client_standby(s, far, main_conn, ctl));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !first_started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("first standby dial never started");
    // Trigger reattach while standby dial #1 is still in flight: dial #1 must
    // abort cleanly and dial #2 binds right after without waiting on backoff.
    reattach_tx.send(1).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !aborted.load(Ordering::SeqCst) || bound.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reattach did not abort hanging standby dial and rebind");
    assert_eq!(attempt.load(Ordering::SeqCst), 2);
    client.abort();
    relay.abort();
}
