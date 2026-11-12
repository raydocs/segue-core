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
