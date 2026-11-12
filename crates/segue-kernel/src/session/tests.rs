//! KernelDialer against in-process relays: the "engine" is a mock dialer
//! whose carriers are duplex pipes into a `segue_session` relay table, and
//! whose carriers can be switched off per exit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use segue_session::codec::{Kind, Target};
use segue_session::driver::{run_relay, SiteConnector};
use segue_session::relay::{AllowAll, Authorizer, RelayTable};
use segue_session::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::*;
use crate::dial::UdpSession;

/// A relay that refuses every OPEN with `code`.
struct Deny(u8);

impl Authorizer for Deny {
    fn open(&self, _: &[u8], _: &Target, _: Kind) -> Result<u64, u8> {
        Err(self.0)
    }
    fn resume(&self, _: &[u8]) -> Result<u64, u8> {
        Err(self.0)
    }
}

struct Node {
    accept: mpsc::Sender<BoxCarrier>,
    up: Arc<AtomicBool>,
    /// Carriers handed out.
    carriers: Arc<AtomicUsize>,
    /// Site connects at this relay.
    sites: Arc<AtomicUsize>,
}

/// Engine stand-in: `dial(Some(carrier), relay)` → a pipe into that
/// carrier's relay; anything else is recorded and refused.
#[derive(Default)]
struct Engine {
    nodes: HashMap<String, Node>,
    other_tcp: Mutex<Vec<Option<String>>>,
    udp: Mutex<Vec<Option<String>>>,
}

struct NoUdp;

#[async_trait]
impl UdpSession for NoUdp {
    fn max_payload(&self, _: &TargetAddr, _: u16) -> usize {
        0
    }
    async fn send(&self, _: &TargetAddr, _: u16, _: &[u8]) -> Result<(), DialError> {
        Ok(())
    }
    async fn recv(&self, _: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError> {
        std::future::pending().await
    }
}

#[async_trait]
impl Dialer for Engine {
    async fn dial(
        &self,
        tag: Option<&str>,
        _addr: &TargetAddr,
        _port: u16,
    ) -> Result<crate::dial::Stream, DialError> {
        let Some(node) = tag.and_then(|t| self.nodes.get(t)) else {
            self.other_tcp.lock().unwrap().push(tag.map(String::from));
            return Err(DialError("mock: no such outbound".into()));
        };
        if !node.up.load(Ordering::SeqCst) {
            return Err(DialError("mock: carrier down".into()));
        }
        node.carriers.fetch_add(1, Ordering::SeqCst);
        let (client, relay) = tokio::io::duplex(64 << 10);
        node.accept
            .send(Box::new(relay))
            .await
            .map_err(|_| DialError("mock: relay gone".into()))?;
        Ok(Box::new(client))
    }

    async fn dial_udp(
        &self,
        tag: Option<&str>,
        _addr: &TargetAddr,
        _port: u16,
    ) -> Result<Datagrams, DialError> {
        self.udp.lock().unwrap().push(tag.map(String::from));
        Ok(Box::new(NoUdp))
    }
}

/// Echo site: everything written comes back.
fn echo_site(count: Arc<AtomicUsize>) -> SiteConnector {
    Arc::new(move |_t, _k| {
        count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
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
    })
}

fn node(auth: Box<dyn Authorizer>, site: Option<SiteConnector>) -> Node {
    let (tx, rx) = mpsc::channel(16);
    let sites = Arc::new(AtomicUsize::new(0));
    let table = RelayTable::new(Config::default(), Pool::new(8 << 20), auth, 9);
    let site = match site {
        Some(f) => {
            let n = sites.clone();
            Arc::new(move |t, k| {
                n.fetch_add(1, Ordering::SeqCst);
                f(t, k)
            })
        }
        None => echo_site(sites.clone()),
    };
    tokio::spawn(run_relay(table, rx, site, None));
    Node {
        accept: tx,
        up: Arc::new(AtomicBool::new(true)),
        carriers: Arc::default(),
        sites,
    }
}

struct Lab {
    d: KernelDialer,
    la_up: Arc<AtomicBool>,
    ny_up: Arc<AtomicBool>,
    la_carriers: Arc<AtomicUsize>,
    ny_carriers: Arc<AtomicUsize>,
    la_sites: Arc<AtomicUsize>,
    engine: Arc<Engine>,
}

fn lab_with(la_auth: Box<dyn Authorizer>) -> Lab {
    lab_parts(la_auth, None)
}

fn lab_parts(la_auth: Box<dyn Authorizer>, la_site: Option<SiteConnector>) -> Lab {
    let la = node(la_auth, la_site);
    let ny = node(Box::new(AllowAll), None);
    let (la_up, ny_up) = (la.up.clone(), ny.up.clone());
    let (la_carriers, ny_carriers) = (la.carriers.clone(), ny.carriers.clone());
    let la_sites = la.sites.clone();
    let engine = Arc::new(Engine {
        nodes: [("reality-la".to_string(), la), ("hy2-ny".to_string(), ny)].into(),
        ..Default::default()
    });
    let exits = vec![
        Exit {
            name: "la".into(),
            carrier: "reality-la".into(),
            relay: "127.0.0.1:7443".parse().unwrap(),
            node_id: 1,
        },
        Exit {
            name: "ny".into(),
            carrier: "hy2-ny".into(),
            relay: "127.0.0.1:7444".parse().unwrap(),
            node_id: 2,
        },
    ];
    let route = |c| SegueRoute {
        ticket: b"ticket".to_vec(),
        exit_class: c,
    };
    let routes = [
        ("overseas".to_string(), route(EXIT_OVERSEAS)),
        ("ai".to_string(), route(EXIT_AI)),
    ]
    .into();
    let home = ["ai".to_string(), "home-out".to_string()].into();
    let d = KernelDialer::new(engine.clone(), exits, routes, home);
    Lab {
        d,
        la_up,
        ny_up,
        la_carriers,
        ny_carriers,
        la_sites,
        engine,
    }
}

fn lab() -> Lab {
    lab_with(Box::new(AllowAll))
}

fn site() -> TargetAddr {
    TargetAddr::Domain("example.com".into())
}

async fn roundtrip(mut s: crate::dial::Stream) {
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut buf))
        .await
        .expect("echo timed out")
        .unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn session_route_opens_through_carrier_and_relay() {
    let l = lab();
    assert_eq!(l.d.posture(), Posture::Connecting);
    let s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    roundtrip(s).await;
    assert_eq!(l.d.posture(), Posture::Connected);
    assert_eq!(l.la_carriers.load(Ordering::SeqCst), 1);
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 0, "auto = first exit");
    assert!(
        l.engine.other_tcp.lock().unwrap().is_empty(),
        "nothing direct"
    );
    let st = l.d.status();
    assert_eq!(st.choice, ExitChoice::Auto);
    assert_eq!(st.current_exit.as_deref(), Some("la"));
}

#[tokio::test]
async fn relay_refusal_is_a_dial_error_not_success() {
    // home_unavailable-style refusal from the relay: never OPENED.
    let l = lab_with(Box::new(Deny(7)));
    let e = match l.d.dial(Some("ai"), &site(), 443).await {
        Ok(_) => panic!("refused session reported success"),
        Err(e) => e,
    };
    assert!(e.0.contains("code 7"), "{e}");
    assert_eq!(l.la_sites.load(Ordering::SeqCst), 0);
    assert!(
        l.engine.other_tcp.lock().unwrap().is_empty(),
        "no fallback dial"
    );
}

#[tokio::test]
async fn ai_refused_at_once_while_carrier_down_then_recovers() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.la_up.store(false, Ordering::SeqCst);
    assert!(l.d.probe().await.is_err());
    assert_eq!(l.d.posture(), Posture::Error);
    let t = Instant::now();
    let e = match l.d.dial(Some("ai"), &site(), 443).await {
        Ok(_) => panic!("AI flow opened with the carrier down"),
        Err(e) => e,
    };
    assert!(e.0.contains("strict"), "{e}");
    assert!(
        t.elapsed() < Duration::from_millis(200),
        "not refused at once"
    );
    assert!(
        l.engine.other_tcp.lock().unwrap().is_empty(),
        "no direct fallback"
    );
    // Carrier back: the next probe flips the posture and AI works again.
    l.la_up.store(true, Ordering::SeqCst);
    l.d.probe().await.unwrap();
    assert_eq!(l.d.posture(), Posture::Connected);
    roundtrip(l.d.dial(Some("ai"), &site(), 443).await.unwrap()).await;
}

#[tokio::test]
async fn connected_then_lost_is_reconnecting_and_refuses_ai() {
    let l = lab();
    roundtrip(l.d.dial(Some("overseas"), &site(), 443).await.unwrap()).await;
    l.d.set_exit("la").unwrap();
    l.la_up.store(false, Ordering::SeqCst);
    assert!(l.d.probe().await.is_err());
    assert_eq!(l.d.posture(), Posture::Reconnecting);
    assert!(l.d.dial(Some("ai"), &site(), 443).await.is_err());
}

#[tokio::test]
async fn auto_moves_new_sessions_off_a_failed_exit() {
    let l = lab();
    l.la_up.store(false, Ordering::SeqCst);
    l.d.probe().await.unwrap(); // la fails, Auto moves on to ny
    assert_eq!(l.la_carriers.load(Ordering::SeqCst), 0);
    assert_eq!(l.d.status().current_exit.as_deref(), Some("ny"));
    roundtrip(l.d.dial(Some("ai"), &site(), 443).await.unwrap()).await;
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 2, "probe + session");
    assert_eq!(l.d.posture(), Posture::Connected);
    // Both down: AI refused fast, overseas never goes direct.
    l.ny_up.store(false, Ordering::SeqCst);
    let _ = l.d.probe().await;
    assert!(l.d.dial(Some("ai"), &site(), 443).await.is_err());
    assert!(l.engine.other_tcp.lock().unwrap().is_empty());
}

#[tokio::test]
async fn named_exit_pins_the_carrier() {
    let l = lab();
    l.d.set_exit("ny").unwrap();
    let st = l.d.status();
    assert_eq!(st.choice, ExitChoice::Named("ny".into()));
    assert_eq!(st.current_exit.as_deref(), Some("ny"));
    roundtrip(l.d.dial(Some("overseas"), &site(), 80).await.unwrap()).await;
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 1);
    assert_eq!(l.la_carriers.load(Ordering::SeqCst), 0);
    assert!(l.d.set_exit("tokyo").is_err());
    assert_eq!(
        l.d.status().choice,
        ExitChoice::Named("ny".into()),
        "unchanged"
    );
    l.d.set_exit("auto").unwrap();
    assert_eq!(l.d.status().choice, ExitChoice::Auto);
}

#[tokio::test]
async fn disconnect_refuses_and_ends_live_sessions() {
    let l = lab();
    let mut live = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    live.write_all(b"a").await.unwrap();
    let mut b = [0u8; 1];
    live.read_exact(&mut b).await.unwrap();

    l.d.disconnect();
    assert_eq!(l.d.posture(), Posture::Disconnected);
    assert!(l.d.dial(Some("overseas"), &site(), 443).await.is_err());
    assert!(l.d.dial(Some("ai"), &site(), 443).await.is_err());
    assert!(l.d.dial(Some("reality-la"), &site(), 443).await.is_err());
    // The live session's app stream ends.
    let mut rest = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), live.read_to_end(&mut rest)).await;
    assert!(r.is_ok(), "live session not ended on disconnect");

    l.d.connect();
    assert_eq!(l.d.posture(), Posture::Connecting);
    roundtrip(l.d.dial(Some("overseas"), &site(), 443).await.unwrap()).await;
}

#[tokio::test]
async fn udp_never_reaches_home_or_session_routes() {
    let l = lab();
    for tag in ["ai", "home-out", "overseas"] {
        assert!(
            l.d.dial_udp(Some(tag), &site(), 3478).await.is_err(),
            "{tag}"
        );
    }
    assert!(
        l.engine.udp.lock().unwrap().is_empty(),
        "engine never asked"
    );
    // Ordinary outbounds and direct are passed through.
    assert!(l.d.dial_udp(Some("reality-la"), &site(), 53).await.is_ok());
    assert!(l.d.dial_udp(None, &site(), 53).await.is_ok());
    assert_eq!(
        *l.engine.udp.lock().unwrap(),
        vec![Some("reality-la".to_string()), None]
    );
    l.d.disconnect();
    assert!(l.d.dial_udp(Some("reality-la"), &site(), 53).await.is_err());
}

#[tokio::test]
async fn no_exits_refuses_session_routes() {
    let engine = Arc::new(Engine::default());
    let routes = [(
        "overseas".to_string(),
        SegueRoute {
            ticket: vec![1],
            exit_class: EXIT_OVERSEAS,
        },
    )]
    .into();
    let d = KernelDialer::new(engine, Vec::new(), routes, BTreeSet::new());
    assert!(d.dial(Some("overseas"), &site(), 443).await.is_err());
    assert_eq!(d.status().current_exit, None);
}

#[tokio::test]
async fn unknown_session_reject_opens_a_fresh_session_bounded() {
    // UNKNOWN_SESSION (an OPEN retry the relay never saw): a fresh session
    // is tried, at most FRESH_OPENS times, then the dial fails.
    let l = lab_with(Box::new(Deny(segue_session::codec::code::UNKNOWN_SESSION)));
    assert!(l.d.dial(Some("overseas"), &site(), 443).await.is_err());
    assert_eq!(
        l.la_carriers.load(Ordering::SeqCst),
        1 + FRESH_OPENS as usize
    );
    // Any other refusal is final at once.
    let l = lab_with(Box::new(Deny(7)));
    assert!(l.d.dial(Some("overseas"), &site(), 443).await.is_err());
    assert_eq!(l.la_carriers.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_while_on_keeps_kill_switch_state() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.la_up.store(false, Ordering::SeqCst);
    let _ = l.d.probe().await;
    l.d.connect(); // already on: must not reset to Connecting / clear the failure
    assert_eq!(l.d.posture(), Posture::Error);
    assert!(l.d.dial(Some("ai"), &site(), 443).await.is_err());
}

/// A site that sends `body`, then ends with `end` (None: a clean FIN; Some:
/// a read error, which the relay turns into RST(site_reset)).
fn scripted_site(body: &'static [u8], fail: bool) -> SiteConnector {
    struct Scripted {
        body: &'static [u8],
        fail: bool,
    }
    impl tokio::io::AsyncRead for Scripted {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if !self.body.is_empty() {
                let n = self.body.len().min(buf.remaining());
                buf.put_slice(&self.body[..n]);
                self.body = &self.body[n..];
                return std::task::Poll::Ready(Ok(()));
            }
            if self.fail {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl tokio::io::AsyncWrite for Scripted {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            b: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(b.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    Arc::new(move |_t, _k| {
        Box::pin(async move { Ok(Box::new(Scripted { body, fail }) as BoxCarrier) })
    })
}

/// Read until EOF or error; returns what arrived and how it ended.
async fn read_to_end(s: &mut crate::dial::Stream) -> (Vec<u8>, std::io::Result<()>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("stream hung")
        {
            Ok(0) => return (got, Ok(())),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => return (got, Err(e)),
        }
    }
}

#[tokio::test]
async fn site_reset_mid_download_is_an_error_not_eof() {
    let l = lab_parts(
        Box::new(AllowAll),
        Some(scripted_site(b"HTTP/1.0 200 OK\r\n\r\npart", true)),
    );
    let mut s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    // The site fails at once, so the write may already see the reset.
    let _ = s.write_all(b"GET / HTTP/1.0\r\n\r\n").await;
    let (got, end) = read_to_end(&mut s).await;
    assert!(b"HTTP/1.0 200 OK\r\n\r\npart".starts_with(&got));
    let e = end.expect_err("a reset session ended like a complete download");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(e.to_string().contains("code 23"), "{e}");
}

#[tokio::test]
async fn clean_close_is_eof() {
    let l = lab_parts(
        Box::new(AllowAll),
        Some(scripted_site(b"complete body", false)),
    );
    let mut s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    s.write_all(b"GET").await.unwrap();
    s.shutdown().await.unwrap();
    let (got, end) = read_to_end(&mut s).await;
    assert_eq!(got, b"complete body");
    end.expect("clean close must be a plain EOF");
}

#[tokio::test]
async fn user_disconnect_ends_live_sessions_with_an_error() {
    let l = lab();
    let mut s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    l.d.disconnect();
    let (_, end) = read_to_end(&mut s).await;
    assert!(end.is_err(), "disconnect looked like a clean end");
}
