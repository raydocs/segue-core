//! KernelDialer against in-process relays: the "engine" is a mock dialer
//! whose carriers are duplex pipes into a `segue_session` relay table, and
//! whose carriers can be switched off per exit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use segue_session::codec::{Kind, Target};
use segue_session::driver::{run_relay_ctl, RelayCtrl, SiteConnector, SiteRequest};
use segue_session::relay::{AllowAll, Authorizer, RelayTable};
use segue_session::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::*;
use crate::dial::UdpSession;

/// A relay that refuses every OPEN with `code`.
struct Deny(u8);

impl Authorizer for Deny {
    fn open(&self, _: &[u8], _: &Target, _: Kind) -> Result<segue_session::relay::Grant, u8> {
        Err(self.0)
    }
    fn resume(&self, _: &[u8]) -> Result<u64, u8> {
        Err(self.0)
    }
}

struct Node {
    accept: mpsc::Sender<BoxCarrier>,
    up: Arc<AtomicBool>,
    /// Carriers handed out (control streams excluded).
    carriers: Arc<AtomicUsize>,
    /// Control streams (first frame CTRL_HELLO).
    controls: Arc<AtomicUsize>,
    /// Every carrier's blackhole switch, and whether it is a control stream.
    holes: Holes,
    /// Site connects at this relay.
    sites: Arc<AtomicUsize>,
    /// Relay commands (revocation).
    ctrl: mpsc::Sender<RelayCtrl>,
    /// When non-zero, each new session carrier's downlink delivers only
    /// this many bytes and then drops everything (control streams are
    /// spared): a path that answers RESUME and stalls mid-DATA.
    cut: Arc<AtomicUsize>,
}

/// Engine stand-in: `dial(Some(carrier), relay)` → a pipe into that
/// carrier's relay; anything else is recorded and refused.
#[derive(Default)]
struct Engine {
    nodes: HashMap<String, Node>,
    other_tcp: Mutex<Vec<Option<String>>>,
    udp: Mutex<Vec<Option<String>>>,
}

/// A carrier that moves itself from the carrier count to the control
/// count when its first frame is CTRL_HELLO.
struct Counted {
    inner: tokio::io::DuplexStream,
    carriers: Arc<AtomicUsize>,
    controls: Arc<AtomicUsize>,
    is_control: Arc<AtomicBool>,
    seen: bool,
}

type Holes = Arc<Mutex<Vec<(Arc<AtomicBool>, Arc<AtomicBool>)>>>;

/// One direction of a carrier's network path. With `cut`, it delivers
/// that many bytes and then turns into a blackhole, unless the carrier
/// is a control stream.
async fn path<R, W>(
    mut r: R,
    mut w: W,
    hole: Arc<AtomicBool>,
    cut: Option<(usize, Arc<AtomicBool>)>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 4096];
    let mut left = cut.as_ref().map(|c| c.0);
    loop {
        let mut n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let (Some(l), Some((_, control))) = (left.as_mut(), &cut) {
            if !control.load(Ordering::SeqCst) {
                if *l == 0 {
                    hole.store(true, Ordering::SeqCst);
                }
                n = n.min(*l);
                *l -= n;
                if n > 0 {
                    let _ = w.write_all(&buf[..n]).await;
                }
                continue;
            }
        }
        if hole.load(Ordering::SeqCst) {
            continue; // dropped
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    if !hole.load(Ordering::SeqCst) {
        let _ = w.shutdown().await;
    } else {
        // A blackhole never delivers a close either.
        std::future::pending::<()>().await;
    }
}

impl tokio::io::AsyncRead for Counted {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Counted {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if !self.seen && !b.is_empty() {
            self.seen = true;
            if b[0] == segue_session::codec::ty::CTRL_HELLO {
                self.carriers.fetch_sub(1, Ordering::SeqCst);
                self.is_control.store(true, Ordering::SeqCst);
                self.controls.fetch_add(1, Ordering::SeqCst);
            }
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

impl segue_transport::TransportStream for Counted {
    fn poll_read_direct(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(self, cx, output)
    }
    fn poll_write_direct(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        input: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self, cx, input)
    }
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
        // client <-> [path] <-> relay; the path can turn into a blackhole
        // that drops every byte both ways and closes nothing.
        let (client, a) = tokio::io::duplex(64 << 10);
        let (b, relay) = tokio::io::duplex(64 << 10);
        let hole = Arc::new(AtomicBool::new(false));
        let is_control = Arc::new(AtomicBool::new(false));
        node.holes
            .lock()
            .unwrap()
            .push((hole.clone(), is_control.clone()));
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let cut = match node.cut.load(Ordering::SeqCst) {
            0 => None,
            n => Some((n, is_control.clone())),
        };
        tokio::spawn(path(ar, bw, hole.clone(), None));
        tokio::spawn(path(br, aw, hole, cut));
        node.accept
            .send(Box::new(relay))
            .await
            .map_err(|_| DialError("mock: relay gone".into()))?;
        Ok(Box::new(Counted {
            inner: client,
            carriers: node.carriers.clone(),
            controls: node.controls.clone(),
            is_control,
            seen: false,
        }))
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

fn node(auth: Box<dyn Authorizer>, site: Option<SiteConnector>, cfg: Config) -> Node {
    let (tx, rx) = mpsc::channel(16);
    let sites = Arc::new(AtomicUsize::new(0));
    let table = RelayTable::new(cfg, Pool::new(8 << 20), auth, 9);
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
    let site: segue_session::driver::DeviceSiteConnector =
        Arc::new(move |r: SiteRequest| site(r.target, r.kind));
    let (ctrl, ctrl_rx) = mpsc::channel(4);
    tokio::spawn(run_relay_ctl(table, rx, site, None, Some(ctrl_rx)));
    Node {
        ctrl,
        accept: tx,
        up: Arc::new(AtomicBool::new(true)),
        carriers: Arc::default(),
        controls: Arc::default(),
        holes: Holes::default(),
        sites,
        cut: Arc::default(),
    }
}

struct Lab {
    d: KernelDialer,
    la_up: Arc<AtomicBool>,
    ny_up: Arc<AtomicBool>,
    la_carriers: Arc<AtomicUsize>,
    ny_carriers: Arc<AtomicUsize>,
    la_sites: Arc<AtomicUsize>,
    la_holes: Holes,
    la_ctrl: mpsc::Sender<RelayCtrl>,
    la_cut: Arc<AtomicUsize>,
    engine: Arc<Engine>,
}

impl Lab {
    /// Every la carrier open now (session carriers, and the control stream
    /// too when `control`) starts dropping all packets. New ones work.
    fn blackhole_la(&self, control: bool) {
        for (hole, is_control) in self.la_holes.lock().unwrap().iter() {
            if control || !is_control.load(Ordering::SeqCst) {
                hole.store(true, Ordering::SeqCst);
            }
        }
    }
}

fn lab_with(la_auth: Box<dyn Authorizer>) -> Lab {
    lab_parts(la_auth, None)
}

fn lab_parts(la_auth: Box<dyn Authorizer>, la_site: Option<SiteConnector>) -> Lab {
    lab_cfg(la_auth, la_site, Config::default())
}

/// [`lab_parts`] with the la relay's configuration `la_cfg`.
fn lab_cfg(la_auth: Box<dyn Authorizer>, la_site: Option<SiteConnector>, la_cfg: Config) -> Lab {
    let la = node(la_auth, la_site, la_cfg);
    let ny = node(Box::new(AllowAll), None, Config::default());
    let la_cut = la.cut.clone();
    let (la_up, ny_up) = (la.up.clone(), ny.up.clone());
    let (la_carriers, ny_carriers) = (la.carriers.clone(), ny.carriers.clone());
    let la_sites = la.sites.clone();
    let la_holes = la.holes.clone();
    let la_ctrl = la.ctrl.clone();
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
        la_holes,
        la_ctrl,
        la_cut,
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

/// A site that streams a numbered byte pattern for ever, 1 KiB every 5 ms.
fn endless_download() -> SiteConnector {
    Arc::new(move |_t, _k| {
        Box::pin(async move {
            let (a, mut b) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let mut i = 0u64;
                loop {
                    let chunk: Vec<u8> = (i..i + 1024).map(|x| (x % 251) as u8).collect();
                    if b.write_all(&chunk).await.is_err() {
                        return;
                    }
                    i += 1024;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// Read `n` more bytes of the pattern, checking every byte, within `limit`.
async fn read_pattern(s: &mut crate::dial::Stream, at: &mut u64, n: u64, limit: Duration) {
    let end = *at + n;
    let mut buf = [0u8; 4096];
    tokio::time::timeout(limit, async {
        while *at < end {
            let k = s.read(&mut buf).await.expect("download failed");
            assert!(k > 0, "download ended");
            for &b in &buf[..k] {
                assert_eq!(b, (*at % 251) as u8, "byte {at} wrong (lost or duplicated)");
                *at += 1;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("download stalled at byte {at}"));
}

fn quick_control() -> ControlTiming {
    ControlTiming {
        ping_every: Duration::from_millis(200),
        dead_after: Duration::from_millis(1000),
        retry: Duration::from_millis(200),
    }
}

async fn download_lab() -> (Lab, crate::dial::Stream, u64) {
    download_lab_cfg(Config::default()).await
}

/// [`download_lab`] with the la relay's configuration `la_cfg`.
async fn download_lab_cfg(la_cfg: Config) -> (Lab, crate::dial::Stream, u64) {
    let mut l = lab_cfg(Box::new(AllowAll), Some(endless_download()), la_cfg);
    l.d = std::mem::replace(
        &mut l.d,
        KernelDialer::new(
            Arc::new(Engine::default()),
            vec![],
            Default::default(),
            Default::default(),
        ),
    )
    .with_control_timing(quick_control());
    let mut s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    // The whole request is acknowledged; from here on the client only
    // receives, so it has nothing unacknowledged of its own to notice a
    // stall with.
    s.write_all(b"GET /big HTTP/1.1\r\n\r\n").await.unwrap();
    let mut at = 0;
    read_pattern(&mut s, &mut at, 32 << 10, Duration::from_secs(5)).await;
    // The control stream is up by now.
    tokio::time::timeout(Duration::from_secs(2), async {
        while l
            .la_holes
            .lock()
            .unwrap()
            .iter()
            .all(|(_, c)| !c.load(Ordering::SeqCst))
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("no control stream");
    (l, s, at)
}

#[tokio::test]
async fn download_survives_a_blackhole_on_the_whole_channel() {
    // Packets on every la carrier (data and control) are dropped, nothing
    // is closed: the control stream goes silent, the channel is judged
    // dead, and the session RESUMEs on a new carrier.
    let (l, mut s, mut at) = download_lab().await;
    let before = l.la_carriers.load(Ordering::SeqCst);
    l.blackhole_la(true);
    read_pattern(&mut s, &mut at, 64 << 10, Duration::from_secs(6)).await;
    assert!(
        l.la_carriers.load(Ordering::SeqCst) > before,
        "no new carrier"
    );
    assert!(l.engine.other_tcp.lock().unwrap().is_empty());
}

#[tokio::test]
async fn download_survives_a_blackhole_on_the_session_carrier_via_stall() {
    // Only the session's carrier drops packets; the control stream is
    // healthy. The relay sees its downstream unacknowledged for T_live,
    // goes DETACHED and sends STALL on the control stream (B1); the client
    // RESUMEs. Without STALL the client would wait for ever.
    let (l, mut s, mut at) = download_lab().await;
    let before = l.la_carriers.load(Ordering::SeqCst);
    let controls = l.la_holes.lock().unwrap().len() - before;
    l.blackhole_la(false);
    read_pattern(&mut s, &mut at, 64 << 10, Duration::from_secs(8)).await;
    assert!(
        l.la_carriers.load(Ordering::SeqCst) > before,
        "no new carrier"
    );
    assert_eq!(
        l.la_holes.lock().unwrap().len() - l.la_carriers.load(Ordering::SeqCst),
        controls,
        "the control stream was not replaced: recovery came from STALL"
    );
}

#[tokio::test]
async fn revoked_on_the_control_stream_resets_sessions_whose_carriers_are_dead() {
    // r5 N10: the data carrier is blackholed, the control stream works.
    // The relay's RST cannot arrive, its REVOKED can: the kernel must reset
    // the session locally, report it and refuse new sessions.
    let (l, mut s, _at) = download_lab().await;
    l.blackhole_la(false);
    l.la_ctrl
        .send(RelayCtrl::ResetDevice {
            device: 0,
            close_code: code::REVOKED,
        })
        .await
        .unwrap();
    let mut buf = vec![0u8; 16 << 10];
    let end = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .expect("session not reset after REVOKED");
    let e = end.expect_err("revoked session ended with a clean EOF");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    let st = l.d.status();
    assert_eq!(st.revoked, Some(code::REVOKED));
    assert_eq!(st.posture, Posture::Error);
    let refused = l.d.dial(Some("overseas"), &site(), 443).await;
    assert!(
        refused.is_err_and(|e| e.0.contains("revoked")),
        "new session not refused after REVOKED"
    );
}

/// Relay timing for the r9 F2/F5 tests: the relay notices a stalled
/// download (and sends STALL) after 500 ms instead of 3 s.
fn quick_stall_relay() -> Config {
    let mut c = Config::default();
    c.timing.t_live = Duration::from_millis(500);
    c
}

/// Read until the stream ends; how it ended, within `limit`.
async fn read_to_end_within(
    s: &mut crate::dial::Stream,
    limit: Duration,
) -> Result<std::io::Result<()>, tokio::time::error::Elapsed> {
    let mut buf = vec![0u8; 16 << 10];
    tokio::time::timeout(limit, async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    })
    .await
}

#[tokio::test]
async fn a_download_whose_carriers_resume_then_stall_mid_data_is_reset_after_the_bound() {
    // r9 F2: the client only downloads (nothing of its own outstanding).
    // Its carrier dies; every carrier after that answers RESUME and then
    // stalls in the middle of a DATA frame. Each is given up on the
    // relay's STALL. Before, a lost carrier counted against the bound only
    // with upload data pending and RESUMED reset the count: the session
    // redialled for ever. Now each counts, and the MAX_FRUITLESS-th ends
    // the session with a reset the app sees.
    use segue_session::client::MAX_FRUITLESS;
    let (l, mut s, _at) = download_lab_cfg(quick_stall_relay()).await;
    let before = l.la_carriers.load(Ordering::SeqCst);
    // RESUMED, a DATA header and part of its body.
    l.la_cut.store(120, Ordering::SeqCst);
    l.blackhole_la(false);
    let t0 = Instant::now();
    let end = read_to_end_within(&mut s, Duration::from_secs(60))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "session never gave up: {} carrier(s) in 60 s",
                l.la_carriers.load(Ordering::SeqCst) - before
            )
        });
    let e = end.expect_err("the session ended with a clean EOF");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    let dials = l.la_carriers.load(Ordering::SeqCst) - before;
    println!("gave up after {:?} and {dials} carriers", t0.elapsed());
    assert_eq!(
        dials, MAX_FRUITLESS as usize,
        "carriers dialled after the last progress"
    );
}

#[tokio::test]
async fn ai_is_refused_fast_while_sessions_back_off_and_after_give_up_then_recovers() {
    // r9 F5: the outer carrier connects fine but the session layer is
    // broken (every carrier stalls after RESUME). Carrier dials alone said
    // `Connected`, so a new AI flow went out and waited. Now session
    // failures make the exit unavailable: AI is refused at once, during
    // the backoff and after the give-up, and only a valid protocol answer
    // makes the exit healthy again.
    let (l, mut s, _at) = download_lab_cfg(quick_stall_relay()).await;
    // Pinned: with Auto, new flows would rightly move to the other exit.
    l.d.set_exit("la").unwrap();
    l.la_cut.store(120, Ordering::SeqCst);
    l.blackhole_la(false);
    // Wait for the first failure report (STALL after t_live).
    tokio::time::timeout(Duration::from_secs(5), async {
        while l.d.posture() == Posture::Connected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session failures never reached the exit health");
    let refused_fast = |what: &'static str| {
        let d = &l.d;
        async move {
            let t = Instant::now();
            let r = d.dial(Some("ai"), &site(), 443).await;
            let e = match r {
                Ok(_) => panic!("AI flow opened {what}"),
                Err(e) => e,
            };
            assert!(e.0.contains("strict"), "{what}: {e}");
            assert!(
                t.elapsed() < Duration::from_millis(200),
                "{what}: refused only after {:?}",
                t.elapsed()
            );
        }
    };
    // Repeatedly during the backoff, over several redials: the carrier
    // dials succeed meanwhile, which must not count as recovery.
    for _ in 0..5 {
        refused_fast("during the backoff").await;
        assert_ne!(l.d.posture(), Posture::Connected);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    // A carrier connect is not proof either.
    l.d.probe().await.unwrap();
    assert_ne!(
        l.d.posture(),
        Posture::Connected,
        "carrier connect restored health"
    );
    refused_fast("after a successful carrier probe").await;
    // Give-up: the session ends in a reset.
    let e = read_to_end_within(&mut s, Duration::from_secs(60))
        .await
        .expect("session never gave up")
        .expect_err("clean EOF after the give-up");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    refused_fast("right after the give-up").await;
    assert!(
        l.engine.other_tcp.lock().unwrap().is_empty(),
        "an AI flow went direct"
    );
    // The path heals: a non-strict flow gets OPENED (a valid answer), the
    // exit is healthy again and AI flows work.
    l.la_cut.store(0, Ordering::SeqCst);
    let mut ok = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    let mut ok_at = 0;
    ok.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    read_pattern(&mut ok, &mut ok_at, 4096, Duration::from_secs(5)).await;
    assert_eq!(l.d.posture(), Posture::Connected);
    let mut ai = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    ai.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut b = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), ai.read(&mut b))
        .await
        .expect("AI flow after recovery got nothing")
        .unwrap();
    assert!(n > 0);
}

/// r10 N3: a session timing the relay would floor (client `t_stall`
/// below `MIN_CLIENT_STALL`) is refused when configured; a valid one is
/// used for new sessions.
#[tokio::test]
async fn session_config_with_a_too_short_stall_is_refused() {
    let mut cfg = Config::default();
    cfg.timing.t_stall = Duration::from_millis(50);
    assert!(lab().d.with_session_config(cfg).is_err());
    let lab = lab();
    let mut cfg = Config::default();
    cfg.timing.t_stall = segue_session::MIN_CLIENT_STALL;
    let d = lab.d.with_session_config(cfg).unwrap();
    roundtrip(d.dial(Some("overseas"), &site(), 443).await.unwrap()).await;
}
