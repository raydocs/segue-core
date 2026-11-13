//! `run_control` against relays that refuse, close or answer badly
//! (review r11 R3): only a valid CTRL_HELLO reply makes a stream accepted,
//! terminal refusals stop the task with their reason, and nothing makes it
//! reconnect faster than `ControlTiming::retry`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use segue_session::codec::{code, CtrlHello, CtrlHelloReply, Frame, Kind, Reject, Target, VERSION};
use segue_session::driver::{
    run_control, run_relay, BoxCarrier, Connector, ControlHint, ControlTiming,
};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, Authorizer, Grant, RelayTable};
use segue_session::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

fn timing() -> ControlTiming {
    ControlTiming {
        ping_every: Duration::from_millis(100),
        dead_after: Duration::from_millis(300),
        retry: Duration::from_millis(200),
    }
}

fn hello(version: u8) -> CtrlHello {
    CtrlHello {
        version,
        ticket: b"ticket".to_vec(),
        held_anchors: vec![1],
    }
}

/// A connector into a real relay table; counts dials.
fn relay_connector(auth: Box<dyn Authorizer>, dials: Arc<AtomicUsize>) -> Connector {
    let table = RelayTable::new(Config::default(), Pool::new(1 << 20), auth, 7);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(4);
    let site: segue_session::driver::SiteConnector =
        Arc::new(|_, _| Box::pin(async { Err(std::io::Error::other("no sites")) }));
    tokio::spawn(run_relay(table, accept_rx, site, None));
    Arc::new(move || {
        dials.fetch_add(1, Ordering::SeqCst);
        let accept_tx = accept_tx.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(64 << 10);
            accept_tx
                .send(Box::new(b))
                .await
                .map_err(|_| std::io::Error::other("gone"))?;
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// A connector whose far end reads the hello and then runs `relay`.
fn scripted<F, Fut>(dials: Arc<AtomicUsize>, relay: F) -> Connector
where
    F: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let relay = Arc::new(relay);
    Arc::new(move || {
        dials.fetch_add(1, Ordering::SeqCst);
        let relay = relay.clone();
        Box::pin(async move {
            let (a, mut b) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                if matches!(b.read(&mut buf).await, Ok(n) if n > 0) {
                    relay(b).await;
                }
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

struct Run {
    hints: Vec<ControlHint>,
    /// run_control returned by itself (not cut off at the deadline).
    ended: bool,
}

async fn run_for(connect: Connector, hello: CtrlHello, limit: Duration) -> Run {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run_control(connect, hello, timing(), tx));
    let ended = tokio::time::timeout(limit, async {
        loop {
            if task.is_finished() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    task.abort();
    let mut hints = Vec::new();
    while let Ok(h) = rx.try_recv() {
        hints.push(h);
    }
    Run { hints, ended }
}

fn deads(r: &Run) -> usize {
    r.hints.iter().filter(|h| **h == ControlHint::Dead).count()
}

#[tokio::test]
async fn a_version_reject_from_a_real_relay_stops_the_task_without_dead_or_redial() {
    let dials = Arc::new(AtomicUsize::new(0));
    let c = relay_connector(Box::new(AllowAll), dials.clone());
    let r = run_for(c, hello(VERSION - 1), Duration::from_secs(2)).await;
    assert!(r.ended, "control task kept running after REJECT(version)");
    assert_eq!(r.hints, vec![ControlHint::Rejected(code::VERSION)]);
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "redialled after REJECT(version)"
    );
}

struct DenyResume(u8);

impl Authorizer for DenyResume {
    fn open(&self, _: &[u8], _: &Target, _: Kind) -> Result<Grant, u8> {
        Err(self.0)
    }
    fn resume(&self, _: &[u8]) -> Result<u64, u8> {
        Err(self.0)
    }
}

#[tokio::test]
async fn refused_credentials_stop_the_task_with_their_code() {
    for c in [code::AUTH, code::EXPIRED, code::REVOKED] {
        let dials = Arc::new(AtomicUsize::new(0));
        let conn = relay_connector(Box::new(DenyResume(c)), dials.clone());
        let r = run_for(conn, hello(VERSION), Duration::from_secs(2)).await;
        assert!(r.ended, "code {c}: kept running");
        assert_eq!(r.hints, vec![ControlHint::Rejected(c)], "code {c}");
        assert_eq!(dials.load(Ordering::SeqCst), 1, "code {c}: redialled");
    }
}

#[tokio::test]
async fn a_real_relay_accepts_and_the_stream_stays_up() {
    let dials = Arc::new(AtomicUsize::new(0));
    let c = relay_connector(Box::new(AllowAll), dials.clone());
    let r = run_for(c, hello(VERSION), Duration::from_millis(1500)).await;
    assert!(!r.ended);
    assert!(r.hints.is_empty(), "{:?}", r.hints);
    assert_eq!(dials.load(Ordering::SeqCst), 1);
}

/// Failures that are not terminal: each reconnect waits `retry`, none of
/// them reports a dead channel (it never was up).
#[tokio::test]
async fn unaccepted_streams_back_off_and_never_report_dead() {
    let limit = Duration::from_millis(1500);
    // At most one dial per `retry` (200 ms) plus the first.
    let max = 1 + (limit.as_millis() / timing().retry.as_millis()) as usize;
    type Script =
        fn(DuplexStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
    let cases: [(&str, Script); 5] = [
        ("closed at once", |b| Box::pin(async move { drop(b) })),
        ("REJECT(capacity)", |mut b| {
            Box::pin(async move {
                let f = Frame::Reject(Reject {
                    code: code::CAPACITY,
                    attach_gen: 0,
                    closed: None,
                });
                let _ = b.write_all(&f.to_bytes()).await;
            })
        }),
        ("PONG instead of a reply", |mut b| {
            Box::pin(async move {
                let f = Frame::Pong {
                    nonce: 1,
                    extra: vec![],
                };
                let _ = b.write_all(&f.to_bytes()).await;
                std::future::pending::<()>().await;
            })
        }),
        ("malformed reply", |mut b| {
            Box::pin(async move {
                let f = Frame::Control {
                    ty: segue_session::codec::ty::CTRL_HELLO,
                    payload: vec![1, 2, 3],
                };
                let _ = b.write_all(&f.to_bytes()).await;
                std::future::pending::<()>().await;
            })
        }),
        ("silent", |b| {
            Box::pin(async move {
                let _keep = b;
                std::future::pending::<()>().await;
            })
        }),
    ];
    for (name, script) in cases {
        let dials = Arc::new(AtomicUsize::new(0));
        let c = scripted(dials.clone(), script);
        let r = run_for(c, hello(VERSION), limit).await;
        let n = dials.load(Ordering::SeqCst);
        assert!(!r.ended, "{name}: task stopped");
        assert_eq!(
            deads(&r),
            0,
            "{name}: reported Dead for a stream never accepted"
        );
        assert!(n >= 2, "{name}: never retried ({n})");
        assert!(
            n <= max,
            "{name}: {n} dials in {limit:?}, more than one per retry"
        );
    }
}

/// An accepted stream that breaks is a dead channel, once per stream, and
/// the next connect still waits `retry`: a relay that accepts and closes
/// at once cannot make a Dead storm.
#[tokio::test]
async fn accepted_then_closed_reports_dead_once_per_stream_with_backoff() {
    let limit = Duration::from_millis(1500);
    let max = 1 + (limit.as_millis() / timing().retry.as_millis()) as usize;
    let dials = Arc::new(AtomicUsize::new(0));
    let c = scripted(dials.clone(), |mut b| async move {
        let reply = CtrlHelloReply {
            node_id: 0,
            instance_id: 1,
            ticket_expired: false,
        };
        let _ = b.write_all(&reply.to_frame().to_bytes()).await;
    });
    let r = run_for(c, hello(VERSION), limit).await;
    let n = dials.load(Ordering::SeqCst);
    assert!(!r.ended);
    assert!(n >= 2 && n <= max, "{n} dials");
    let d = deads(&r);
    assert!(d == n || d + 1 == n, "{d} Dead for {n} accepted streams");
}
