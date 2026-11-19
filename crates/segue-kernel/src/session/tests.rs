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
use tokio::sync::{mpsc, watch};

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
    /// The next this many carriers drop everything from the start.
    drop_next: Arc<AtomicUsize>,
    /// Checked before `drop_next`: each new carrier takes the next entry
    /// (true: it drops everything from the start).
    drop_plan: Arc<Mutex<std::collections::VecDeque<bool>>>,
    /// When non-zero, the next carrier's downlink is throttled to this
    /// many bytes per second (control streams are spared); then reset.
    slow_next: Arc<AtomicUsize>,
    /// Dials started against this node, counted before any hang.
    dials: Arc<AtomicUsize>,
    /// The next dial sleeps this long before connecting, then clears it.
    hang_next: Arc<Mutex<Option<Duration>>>,
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

/// Blackhole flag, control-stream flag, and a watch that closes the carrier
/// (EOF both ways) when it becomes true.
type Holes = Arc<Mutex<Vec<(Arc<AtomicBool>, Arc<AtomicBool>, watch::Sender<bool>)>>>;

/// One direction of a carrier's network path. With `cut`, it delivers
/// that many bytes and then turns into a blackhole, unless the carrier
/// is a control stream.
async fn path<R, W>(
    mut r: R,
    mut w: W,
    hole: Arc<AtomicBool>,
    mut end: watch::Receiver<bool>,
    cut: Option<(usize, Arc<AtomicBool>)>,
    slow: Option<(usize, Arc<AtomicBool>)>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 4096];
    let mut left = cut.as_ref().map(|c| c.0);
    loop {
        if *end.borrow() {
            break;
        }
        // Throttled: at most rate/10 bytes per 100 ms.
        let lim = match &slow {
            Some((rate, control)) if !control.load(Ordering::SeqCst) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                (rate / 10).clamp(1, buf.len())
            }
            _ => buf.len(),
        };
        let mut n = tokio::select! {
            biased;
            res = end.changed() => {
                if res.is_err() || *end.borrow() {
                    break;
                }
                continue;
            }
            res = r.read(&mut buf[..lim]) => match res {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
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
        node.dials.fetch_add(1, Ordering::SeqCst);
        let hang = node.hang_next.lock().unwrap().take();
        if let Some(delay) = hang {
            tokio::time::sleep(delay).await;
        }
        if !node.up.load(Ordering::SeqCst) {
            return Err(DialError("mock: carrier down".into()));
        }
        node.carriers.fetch_add(1, Ordering::SeqCst);
        // client <-> [path] <-> relay; the path can turn into a blackhole
        // that drops every byte both ways and closes nothing.
        let (client, a) = tokio::io::duplex(64 << 10);
        let (b, relay) = tokio::io::duplex(64 << 10);
        let planned = node.drop_plan.lock().unwrap().pop_front();
        let dropped = planned.unwrap_or_else(|| {
            node.drop_next
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        });
        let hole = Arc::new(AtomicBool::new(dropped));
        let is_control = Arc::new(AtomicBool::new(false));
        let (end_tx, end_rx) = watch::channel(false);
        node.holes
            .lock()
            .unwrap()
            .push((hole.clone(), is_control.clone(), end_tx));
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let cut = match node.cut.load(Ordering::SeqCst) {
            0 => None,
            n => Some((n, is_control.clone())),
        };
        let slow = match node.slow_next.swap(0, Ordering::SeqCst) {
            0 => None,
            n => Some((n, is_control.clone())),
        };
        tokio::spawn(path(ar, bw, hole.clone(), end_rx.clone(), None, None));
        tokio::spawn(path(br, aw, hole, end_rx, cut, slow));
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
        drop_next: Arc::default(),
        drop_plan: Arc::default(),
        slow_next: Arc::default(),
        dials: Arc::default(),
        hang_next: Arc::default(),
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
    la_drop_next: Arc<AtomicUsize>,
    la_controls: Arc<AtomicUsize>,
    la_drop_plan: Arc<Mutex<std::collections::VecDeque<bool>>>,
    la_slow_next: Arc<AtomicUsize>,
    la_dials: Arc<AtomicUsize>,
    la_hang_next: Arc<Mutex<Option<Duration>>>,
    engine: Arc<Engine>,
}

impl Lab {
    /// Every la carrier open now (session carriers, and the control stream
    /// too when `control`) starts dropping all packets. New ones work.
    fn blackhole_la(&self, control: bool) {
        for (hole, is_control, _) in self.la_holes.lock().unwrap().iter() {
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
    lab_full(la_auth, la_site, la_cfg, None, None)
}

/// [`lab_cfg`] whose dialer charges its sessions to `pool` (default: the
/// process pool) and opens them with `client` (default: the default
/// session configuration).
fn lab_full(
    la_auth: Box<dyn Authorizer>,
    la_site: Option<SiteConnector>,
    la_cfg: Config,
    pool: Option<Arc<Pool>>,
    client: Option<Config>,
) -> Lab {
    let la = node(la_auth, la_site, la_cfg);
    let ny = node(Box::new(AllowAll), None, Config::default());
    let la_cut = la.cut.clone();
    let la_drop_next = la.drop_next.clone();
    let la_controls = la.controls.clone();
    let la_drop_plan = la.drop_plan.clone();
    let la_slow_next = la.slow_next.clone();
    let la_dials = la.dials.clone();
    let la_hang_next = la.hang_next.clone();
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
            redundant_carrier: None,
            relay: "127.0.0.1:7443".parse().unwrap(),
            node_id: 1,
            egress_group: String::new(),
        },
        Exit {
            name: "ny".into(),
            carrier: "hy2-ny".into(),
            redundant_carrier: None,
            relay: "127.0.0.1:7444".parse().unwrap(),
            node_id: 2,
            egress_group: String::new(),
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
    let mut d = KernelDialer::new(engine.clone(), exits, routes, home);
    if let Some(p) = pool {
        d = d.with_pool(p);
    }
    if let Some(c) = client {
        d = d.with_session_config(c).unwrap();
    }
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
        la_drop_next,
        la_controls,
        la_drop_plan,
        la_slow_next,
        la_dials,
        la_hang_next,
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

/// AI under Auto pins the exit it first uses. When that exit is down it
/// is refused, not moved to an exit in another egress group. Overseas
/// still fails over. Two exits in one group may take the AI flow.
#[tokio::test]
async fn ai_auto_does_not_leave_its_egress_group() {
    let l = lab();
    l.d.probe().await.unwrap();
    roundtrip(l.d.dial(Some("ai"), &site(), 443).await.unwrap()).await;
    assert_eq!(
        l.ny_carriers.load(Ordering::SeqCst),
        0,
        "first pin was not la"
    );
    l.la_up.store(false, Ordering::SeqCst);
    // Probe moves Auto's overseas pick to ny. The AI pin stays on la.
    let _ = l.d.probe().await;
    assert!(
        l.ny_carriers.load(Ordering::SeqCst) >= 1,
        "ny was not probed"
    );
    let ny_before = l.ny_carriers.load(Ordering::SeqCst);
    let t = Instant::now();
    let Err(e) = l.d.dial(Some("ai"), &site(), 443).await else {
        panic!("the AI dial was not refused");
    };
    assert!(e.0.contains("strict"), "{e}");
    assert!(
        t.elapsed() < Duration::from_millis(200),
        "not refused at once"
    );
    assert_eq!(
        l.ny_carriers.load(Ordering::SeqCst),
        ny_before,
        "AI moved to ny"
    );
    // Overseas is not pinned: it uses the exit Auto is on now.
    roundtrip(l.d.dial(Some("overseas"), &site(), 443).await.unwrap()).await;
    assert!(l.ny_carriers.load(Ordering::SeqCst) > ny_before);

    // Same egress group: the AI flow may move from la to ny.
    let mut l = lab();
    l.d.set_egress_group("la", "iad").unwrap();
    l.d.set_egress_group("ny", "iad").unwrap();
    l.d.probe().await.unwrap();
    roundtrip(l.d.dial(Some("ai"), &site(), 443).await.unwrap()).await;
    l.la_up.store(false, Ordering::SeqCst);
    let _ = l.d.probe().await;
    roundtrip(l.d.dial(Some("ai"), &site(), 443).await.unwrap()).await;
    assert!(
        l.ny_carriers.load(Ordering::SeqCst) >= 1,
        "AI did not move inside the egress group"
    );
}

/// The user naming an exit, or returning to Auto, replaces the AI pin.
/// A fresh session after that follows the new choice.
#[test]
fn user_exit_change_resets_the_ai_pin() {
    let mut st = State {
        user_off: false,
        revoked: None,
        choice: None,
        choice_gen: 0,
        ai_pin: None,
        health: vec![Health::new(), Health::new()],
        auto: AutoChoice::default(),
    };
    st.health[0].ks.on_event(Event::ChannelUp);
    let groups = vec!["la".to_string(), "ny".to_string()];
    assert_eq!(st.pick_ai(&groups), 0, "first Auto pin");
    assert_eq!(st.pick_ai(&groups), 0);
    st.health[0].ks.on_event(Event::ChannelLost);
    assert_eq!(st.pick_ai(&groups), 0, "down pin does not leave its group");
    // User names ny.
    st.choice = Some(1);
    st.choice_gen += 1;
    st.ai_pin = Some(1);
    assert_eq!(st.pick_ai(&groups), 1);
    // Back to Auto: the dialer clears the pin. Re-pin from scratch.
    st.choice = None;
    st.ai_pin = None;
    st.health[1].ks.on_event(Event::ChannelUp);
    assert_eq!(st.pick_ai(&groups), 1, "Auto re-pins the exit that is up");
    // Same group, la down, ny up: the pin may move.
    let mut st = State {
        user_off: false,
        revoked: None,
        choice: None,
        choice_gen: 0,
        ai_pin: Some(0),
        health: vec![Health::new(), Health::new()],
        auto: AutoChoice::default(),
    };
    st.health[0].ks.on_event(Event::ChannelLost);
    st.health[1].ks.on_event(Event::ChannelUp);
    let same = vec!["iad".to_string(), "iad".to_string()];
    assert_eq!(st.pick_ai(&same), 1);
    assert_eq!(st.ai_pin, Some(1));
}

#[tokio::test]
async fn auto_moves_new_sessions_off_a_failed_exit() {
    let l = lab();
    l.la_up.store(false, Ordering::SeqCst);
    l.d.probe().await.unwrap(); // la fails, Auto moves on to ny
    assert_eq!(l.la_carriers.load(Ordering::SeqCst), 0);
    assert_eq!(l.d.status().current_exit.as_deref(), Some("ny"));
    roundtrip(l.d.dial(Some("ai"), &site(), 443).await.unwrap()).await;
    for _ in 0..100 {
        if l.d.standby_bound.load(Ordering::Relaxed) >= 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        l.ny_carriers.load(Ordering::SeqCst),
        3,
        "probe + session + standby"
    );
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

/// Give `l`'s dialer the quick control timing.
fn quicken(l: &mut Lab) {
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
            .all(|(_, c, _)| !c.load(Ordering::SeqCst))
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

/// r10 N6: exit health aggregates its sessions. Reports are fed in
/// directly, with explicit times.
mod exit_health {
    use super::*;
    use segue_session::client::Health as S;

    fn exit() -> Health {
        let mut h = Health::new();
        h.ks.on_event(Event::UserConnect);
        h
    }

    fn feed(h: &mut Health, id: u64, r: S, at: Instant) -> Posture {
        session_health(h, id, r, at);
        h.ks.posture()
    }

    #[test]
    fn one_bad_session_among_good_ones_does_not_take_the_exit_down() {
        let t = Instant::now();
        let mut h = exit();
        assert_eq!(feed(&mut h, 1, S::Up, t), Posture::Connected);
        assert_eq!(feed(&mut h, 2, S::Up, t), Posture::Connected);
        // Session 2 stalls and redials while 1 keeps moving data.
        let t = t + Duration::from_secs(1);
        assert_eq!(feed(&mut h, 2, S::Failed, t), Posture::Connected);
        assert_eq!(h.failing(), 1);
        assert!(!h.unproven);
        assert!(h.last_fail.is_none(), "strict flows would be refused");
    }

    #[test]
    fn interleaved_reports_do_not_flap() {
        let t = Instant::now();
        let mut h = exit();
        // A alone: its failure takes the exit down.
        feed(&mut h, 1, S::Up, t);
        assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Reconnecting);
        // B's OPENED proves the path.
        let t = t + Duration::from_millis(500);
        assert_eq!(feed(&mut h, 2, S::Up, t), Posture::Connected);
        // A, still backing off, fails again, and again: B's proof is
        // fresh, the exit stays up.
        for k in 1..4 {
            let t = t + Duration::from_millis(400 * k);
            assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Connected, "flapped");
        }
        // B keeps proving (refreshed while data moves).
        let t = t + Duration::from_secs(3);
        feed(&mut h, 2, S::Up, t);
        let t = t + PROOF_FRESH - Duration::from_millis(1);
        assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Connected);
        // B's proof went stale (it stopped moving data): A's next failure
        // is no longer outweighed.
        let t = t + Duration::from_millis(2);
        assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Reconnecting);
    }

    #[test]
    fn a_session_that_failed_after_success_takes_its_proof_with_it() {
        let t = Instant::now();
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 2, S::Up, t);
        let t = t + Duration::from_millis(100);
        assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Connected);
        // The other one fails too: nothing proves the exit any more.
        assert_eq!(feed(&mut h, 2, S::Failed, t), Posture::Reconnecting);
        assert_eq!(h.failing(), 2);
        assert!(h.unproven);
    }

    #[test]
    fn failing_sessions_that_end_stop_counting() {
        let t = Instant::now();
        let mut h = exit();
        h.sessions.insert(1, SessionMark::default());
        h.sessions.insert(2, SessionMark::default());
        // Worked once (else a failure is `Error`: never connected).
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 1, S::Failed, t);
        feed(&mut h, 2, S::Failed, t);
        assert_eq!(h.failing(), 2);
        // 1 gives up; 2 ends otherwise (its reporter is dropped).
        assert_eq!(feed(&mut h, 1, S::GaveUp, t), Posture::Reconnecting);
        assert_eq!(h.failing(), 1);
        h.sessions.remove(&2);
        assert_eq!(h.failing(), 0);
        // Down still, until a valid answer.
        assert_eq!(h.ks.posture(), Posture::Reconnecting);
        assert!(h.unproven);
        assert_eq!(feed(&mut h, 3, S::Up, t), Posture::Connected);
        assert!(!h.unproven);
    }

    #[test]
    fn reporters_leave_the_exit_when_dropped() {
        let st = Arc::new(Mutex::new(State {
            user_off: false,
            revoked: None,
            choice: None,
            choice_gen: 0,
            ai_pin: None,
            health: vec![exit()],
            auto: AutoChoice::default(),
        }));
        let a = HealthReporter::new(st.clone(), 0);
        let b = HealthReporter::new(st.clone(), 0);
        a.report(S::Up);
        b.report(S::Failed);
        assert_eq!(st.lock().unwrap().health[0].sessions.len(), 2);
        assert_eq!(st.lock().unwrap().health[0].failing(), 1);
        drop(b);
        assert_eq!(st.lock().unwrap().health[0].failing(), 0);
        drop(a);
        assert!(st.lock().unwrap().health[0].sessions.is_empty());
    }

    /// r11 R4: path liveness (bytes arriving, no data moving end to end)
    /// keeps a session's path counted for its exit, with the same window
    /// as proof, on both sides of it.
    #[test]
    fn liveness_counts_within_the_window_and_not_after() {
        let t = Instant::now();
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 2, S::Up, t);
        // B's proof is old; B shows liveness at t + 4 s (a large frame
        // still crossing).
        let alive = t + Duration::from_secs(4);
        assert_eq!(feed(&mut h, 2, S::Alive(alive), alive), Posture::Connected);
        let edge = alive + PROOF_FRESH;
        assert_eq!(
            feed(&mut h, 1, S::Failed, edge - Duration::from_millis(1)),
            Posture::Connected,
            "fresh liveness did not count"
        );
        assert_eq!(
            feed(&mut h, 1, S::Failed, edge),
            Posture::Reconnecting,
            "stale liveness counted"
        );
    }

    /// r12 #1: liveness counts from when its bytes arrived, not from when
    /// it was reported: a report of old bytes renews nothing.
    #[test]
    fn liveness_counts_from_its_receive_time() {
        let t = Instant::now();
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 2, S::Up, t);
        let rx = t + Duration::from_secs(1);
        let late = rx + PROOF_FRESH;
        assert_eq!(feed(&mut h, 2, S::Alive(rx), late), Posture::Connected);
        assert_eq!(
            feed(&mut h, 1, S::Failed, late),
            Posture::Reconnecting,
            "a late report of old bytes counted as fresh"
        );
        // An older report never moves liveness back.
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 2, S::Alive(rx), rx);
        feed(&mut h, 2, S::Alive(t), rx);
        assert_eq!(
            feed(&mut h, 1, S::Failed, t + PROOF_FRESH),
            Posture::Connected,
            "liveness moved back"
        );
    }

    /// r11 R4: liveness restores nothing and does not count for a session
    /// that is failing; that session's own failure drops it.
    #[test]
    fn liveness_restores_nothing_and_a_failing_session_has_none() {
        let t = Instant::now();
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        let t = t + PROOF_FRESH;
        assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Reconnecting);
        // Down: bytes arriving on another session do not bring it back.
        assert_eq!(feed(&mut h, 2, S::Alive(t), t), Posture::Reconnecting);
        assert!(h.unproven);
        // A failing session's liveness does not outweigh a failure.
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 2, S::Up, t);
        feed(
            &mut h,
            2,
            S::Alive(t + Duration::from_secs(1)),
            t + Duration::from_secs(1),
        );
        assert_eq!(
            feed(&mut h, 2, S::Failed, t + Duration::from_secs(2)),
            Posture::Connected,
            "1's proof still fresh"
        );
        feed(
            &mut h,
            2,
            S::Alive(t + Duration::from_secs(3)),
            t + Duration::from_secs(3),
        );
        assert_eq!(
            feed(&mut h, 1, S::Failed, t + PROOF_FRESH),
            Posture::Reconnecting,
            "a failing session's liveness counted"
        );
    }

    /// r11 R4 boundary: a session idle for the whole window gives no
    /// evidence; a failure then takes the exit down, until a valid
    /// answer (the next OPENED or data moving).
    #[test]
    fn an_idle_session_gives_no_evidence() {
        let t = Instant::now();
        let mut h = exit();
        feed(&mut h, 1, S::Up, t);
        feed(&mut h, 2, S::Up, t);
        let t = t + PROOF_FRESH;
        assert_eq!(feed(&mut h, 1, S::Failed, t), Posture::Reconnecting);
        assert_eq!(feed(&mut h, 2, S::Up, t), Posture::Connected);
    }
}

/// The quality-based `Auto` choice, end to end: both exits are up, but
/// one has measured worse quality. `Auto` prefers the better one, and
/// `status()` reports the per-exit quality the choice was made from.
mod auto_quality {
    use super::*;
    use segue_session::quality::Quality;

    /// Mark exit `i` up (its carrier connected), as a probe or a session
    /// would.
    fn bring_up(d: &KernelDialer, i: usize) {
        d.state.lock().unwrap().health[i]
            .ks
            .on_event(Event::ChannelUp);
    }

    /// Feed `quality` into exit `i`'s tracker as if its sessions and
    /// control stream had measured it.
    fn measure(d: &KernelDialer, i: usize, quality: Quality) {
        let mut st = d.state.lock().unwrap();
        let q = &mut st.health[i].quality;
        if let Some(srtt) = quality.srtt {
            q.on_rtt(srtt);
        }
        if quality.loss > 0.0 {
            // A replay of `loss` of the sent bytes.
            q.on_replay(1000, (quality.loss * 1000.0) as u64);
        }
        for _ in 0..quality.stalls {
            q.on_carrier_lost();
        }
    }

    #[tokio::test]
    async fn auto_prefers_lower_loss_then_rtt() {
        let l = lab();
        // Both carriers up (a probe only dials the first).
        l.d.probe().await.unwrap();
        bring_up(&l.d, 1);
        assert_eq!(l.d.status().current_exit.as_deref(), Some("la"));
        // la is lossy, ny is clean: after the hysteresis, Auto moves.
        measure(
            &l.d,
            0,
            Quality {
                srtt: Some(Duration::from_millis(200)),
                loss: 0.10,
                stalls: 0,
            },
        );
        measure(
            &l.d,
            1,
            Quality {
                srtt: Some(Duration::from_millis(100)),
                loss: 0.0,
                stalls: 0,
            },
        );
        // The streak needs three fresh observations; `status()` polls
        // with the same evidence and must not count.
        for _ in 0..5 {
            assert_eq!(l.d.status().current_exit.as_deref(), Some("la"));
        }
        // New evidence each round (a fresh RTT sample) advances it. The
        // loss is already measured; only the RTT moves.
        for k in 1..=3u64 {
            measure(
                &l.d,
                0,
                Quality {
                    srtt: Some(Duration::from_millis(200 + k)),
                    loss: 0.0,
                    stalls: 0,
                },
            );
            let _ = l.d.status();
        }
        assert_eq!(
            l.d.status().current_exit.as_deref(),
            Some("ny"),
            "Auto did not move to the cleaner exit"
        );
        // The status carries the quality the choice was made from. la's
        // loss has aged a little on the PING clock (each RTT sample
        // decays it), but it is still clearly the lossier exit.
        let st = l.d.status();
        assert_eq!(st.quality[0].name, "la");
        assert!(
            st.quality[0].quality.loss > 0.05,
            "la loss {}",
            st.quality[0].quality.loss
        );
        assert_eq!(st.quality[1].name, "ny");
        assert_eq!(st.quality[1].quality.loss, 0.0);
    }

    #[tokio::test]
    async fn a_down_incumbent_fails_over_at_once() {
        let l = lab();
        l.d.probe().await.unwrap();
        assert_eq!(l.d.status().current_exit.as_deref(), Some("la"));
        // la's carrier goes down: no hysteresis, Auto moves to ny.
        l.la_up.store(false, Ordering::SeqCst);
        let _ = l.d.probe().await;
        assert_eq!(l.d.status().current_exit.as_deref(), Some("ny"));
    }

    #[tokio::test]
    async fn a_named_exit_ignores_quality() {
        let l = lab();
        l.d.set_exit("la").unwrap();
        measure(
            &l.d,
            0,
            Quality {
                srtt: Some(Duration::from_millis(300)),
                loss: 0.20,
                stalls: 3,
            },
        );
        measure(
            &l.d,
            1,
            Quality {
                srtt: Some(Duration::from_millis(50)),
                loss: 0.0,
                stalls: 0,
            },
        );
        for _ in 0..5 {
            assert_eq!(l.d.status().current_exit.as_deref(), Some("la"));
        }
    }
}

/// r10 N6, end to end: on one exit, a good session keeps downloading
/// while another one's carriers stall. The exit stays `Connected` (AI
/// flows open) through the bad one's failures and its give-up; when the
/// good one fails too the exit goes down; with no session left, the
/// healed exit recovers through an AI request alone.
#[tokio::test]
async fn one_good_and_one_bad_session_on_an_exit() {
    let (l, good, _at) = download_lab_cfg(quick_stall_relay()).await;
    l.d.set_exit("la").unwrap();
    let moved = Arc::new(AtomicUsize::new(0));
    let good = {
        let moved = moved.clone();
        let mut s = good;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 << 10];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        moved.fetch_add(n, Ordering::SeqCst);
                    }
                    Err(e) => return Err(e),
                }
            }
        })
    };
    // The bad session: works at first, then its carrier is black-holed
    // and every carrier after it stalls after RESUME.
    let mut bad = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    bad.write_all(b"GET /big HTTP/1.1\r\n\r\n").await.unwrap();
    let mut bad_at = 0;
    read_pattern(&mut bad, &mut bad_at, 8 << 10, Duration::from_secs(5)).await;
    l.la_cut.store(120, Ordering::SeqCst);
    {
        let holes = l.la_holes.lock().unwrap();
        let (hole, _, _) = holes
            .iter()
            .rev()
            .find(|(_, c, _)| !c.load(Ordering::SeqCst))
            .expect("no session carrier");
        hole.store(true, Ordering::SeqCst);
    }
    // Through the bad session's failures and give-up: the exit stays up.
    let bad_end =
        tokio::spawn(async move { read_to_end_within(&mut bad, Duration::from_secs(60)).await });
    let mut checked_ai = false;
    let t0 = Instant::now();
    while !bad_end.is_finished() {
        assert_eq!(
            l.d.posture(),
            Posture::Connected,
            "one bad session took the exit down after {:?}",
            t0.elapsed()
        );
        if !checked_ai && t0.elapsed() > Duration::from_secs(2) {
            let ai = l.d.dial(Some("ai"), &site(), 443).await;
            assert!(
                ai.is_ok(),
                "AI refused while a session on the exit is healthy"
            );
            checked_ai = true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let e = bad_end
        .await
        .unwrap()
        .expect("bad session never gave up")
        .expect_err("bad session ended clean");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(checked_ai);
    let before = moved.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        moved.load(Ordering::SeqCst) > before,
        "good session stopped"
    );
    assert_eq!(l.d.posture(), Posture::Connected);
    // The good session's path breaks too: nothing proves the exit.
    l.blackhole_la(false);
    tokio::time::timeout(Duration::from_secs(10), async {
        while l.d.posture() == Posture::Connected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("exit stayed up with every session failing");
    let r = l.d.dial(Some("ai"), &site(), 443).await;
    assert!(r.is_err_and(|e| e.0.contains("strict")), "AI not refused");
    let e = tokio::time::timeout(Duration::from_secs(60), good)
        .await
        .expect("good session never gave up")
        .unwrap()
        .expect_err("good session ended clean");
    assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    assert_ne!(l.d.posture(), Posture::Connected);
    // The path heals. Wait until any backing-off AI probe session clears so
    // the strict route admits a new request (t_stall_ai = 5 s can still hold
    // an exit past the 3 s STRICT_RETRY_AFTER pause).
    l.la_cut.store(0, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let clear = {
                let st = l.d.state.lock().unwrap();
                st.health
                    .iter()
                    .all(|h| !h.recently_failed() && h.failing() == 0)
            };
            if clear {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("exit kept a failing session after the path healed");
    let mut ai =
        l.d.dial(Some("ai"), &site(), 443)
            .await
            .expect("AI never let through to recover");
    assert_eq!(l.d.posture(), Posture::Connected);
    ai.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut b = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), ai.read(&mut b))
        .await
        .expect("AI flow after recovery got nothing")
        .unwrap();
    assert!(n > 0);
}

/// r10 failover (e2e "Auto failover"): under Auto, la works (probed) and
/// ny is down but has not failed lately (nothing tried it). An AI flow's
/// first OPEN on la is lost, so it is retried after T_attach and the
/// relay answers the retry UNKNOWN_SESSION (it never saw the first). That
/// slow OPEN reported failures that took la down; the fresh session then
/// re-picked an exit and went to ny, whose carrier is down, and the AI
/// flow failed although la had just answered. The answer lets the fresh
/// session try la once more (r11 R5: it is not proof by itself, la is
/// still down until then); its OPENED makes la `Connected` again.
#[tokio::test]
async fn a_fresh_session_after_unknown_session_stays_on_the_exit_that_answered() {
    let l = lab();
    l.d.probe().await.unwrap();
    assert_eq!(l.d.posture(), Posture::Connected);
    l.ny_up.store(false, Ordering::SeqCst);
    l.la_drop_next.store(1, Ordering::SeqCst);
    let sites = l.la_sites.load(Ordering::SeqCst);
    let s = tokio::time::timeout(Duration::from_secs(15), l.d.dial(Some("ai"), &site(), 443))
        .await
        .expect("AI dial hung")
        .expect("AI flow failed although la answered");
    assert_eq!(
        la_posture(&l),
        Posture::Connected,
        "OPENED did not restore la"
    );
    roundtrip(s).await;
    assert_eq!(
        l.la_sites.load(Ordering::SeqCst),
        sites + 1,
        "site connected more than once"
    );
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 0, "moved to ny");
    assert_eq!(l.d.posture(), Posture::Connected);
    assert_eq!(l.d.status().current_exit.as_deref(), Some("la"));
}

/// Opens sessions, refuses every control stream (RESUME / CTRL_HELLO)
/// with `code`.
struct NoControl(u8);

impl Authorizer for NoControl {
    fn open(&self, _: &[u8], _: &Target, _: Kind) -> Result<segue_session::relay::Grant, u8> {
        Ok(segue_session::relay::Grant::all(0))
    }
    fn resume(&self, _: &[u8]) -> Result<u64, u8> {
        Err(self.0)
    }
}

/// r11 R3, through the kernel: a relay that refuses the control stream
/// for good (here: the ticket) gets one CTRL_HELLO, no redial loop and no
/// dead-channel resume storm; the refusal shows in the status; later
/// sessions do not restart it; a new connect does.
#[tokio::test]
async fn a_control_stream_refused_for_good_is_not_redialled() {
    let mut l = lab_with(Box::new(NoControl(code::AUTH)));
    quicken(&mut l);
    l.d.set_exit("la").unwrap();
    let s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while l.d.status().control_refused.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("refusal never reported");
    assert_eq!(
        l.d.status().control_refused,
        vec![("la".to_string(), code::AUTH)]
    );
    let carriers = l.la_carriers.load(Ordering::SeqCst);
    roundtrip(s).await;
    for _ in 0..3 {
        roundtrip(l.d.dial(Some("overseas"), &site(), 443).await.unwrap()).await;
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        l.la_controls.load(Ordering::SeqCst),
        1,
        "control stream redialled"
    );
    assert_eq!(
        l.la_carriers.load(Ordering::SeqCst),
        carriers + 3,
        "sessions reattached (a Dead resume storm)"
    );
    assert_eq!(l.d.posture(), Posture::Connected);
    assert_eq!(l.d.status().revoked, None);
}

/// r12 #2: the refusal reaches the UI. `GET /v1/status` (through
/// `Control::handle`) names the exit and the `REJECT` code while the data
/// sessions keep the posture `connected`; it stays while disconnected and
/// a new connect clears it.
#[tokio::test]
async fn a_control_refusal_shows_in_the_http_status() {
    use crate::control::Control;
    use crate::policy::{Policy, PolicyStore};
    use crate::rules::{Action, CidrTable, RuleSet};
    let mut l = lab_with(Box::new(NoControl(code::VERSION)));
    quicken(&mut l);
    l.d.set_exit("la").unwrap();
    let s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    let d = Arc::new(std::mem::replace(
        &mut l.d,
        KernelDialer::new(
            Arc::new(Engine::default()),
            vec![],
            Default::default(),
            Default::default(),
        ),
    ));
    let policy = PolicyStore::inline(Policy::inline(
        RuleSet::new(Vec::new(), Action::Reject),
        CidrTable::default(),
    ));
    let c = Control::new(d.clone(), policy, "t".into());
    let (code, before) = c.handle("GET", "/v1/status", b"").await;
    assert_eq!(code, 200);
    assert!(before["control_refused"].is_array(), "{before}");
    let refused = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (_, st) = c.handle("GET", "/v1/status", b"").await;
            if st["control_refused"] != serde_json::json!([]) {
                return st;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("refusal never reached the HTTP status");
    assert_eq!(
        refused["control_refused"],
        serde_json::json!([{"exit": "la", "code": code::VERSION}]),
        "{refused}"
    );
    assert_eq!(refused["state"], "connected", "{refused}");
    assert_eq!(refused["revoked"], false);
    roundtrip(s).await;
    let (_, off) = c.handle("POST", "/v1/disconnect", b"").await;
    assert_eq!(off["state"], "disconnected");
    assert_eq!(
        off["control_refused"],
        serde_json::json!([{"exit": "la", "code": code::VERSION}]),
        "the reason went away with the disconnect: {off}"
    );
    let (_, on) = c.handle("POST", "/v1/connect", b"").await;
    assert_eq!(
        on["control_refused"],
        serde_json::json!([]),
        "a new connect kept the old refusal: {on}"
    );
}

fn la_posture(l: &Lab) -> Posture {
    l.d.state.lock().unwrap().health[0].ks.posture()
}

/// A strict (AI) flow on la is refused at once by la's health. The exit
/// is named so the pin is la even if Auto would otherwise be on ny; an
/// AI pin does not leave its egress group either
/// ([`ai_auto_does_not_leave_its_egress_group`]).
async fn ai_refused_fast(l: &Lab, what: &str) {
    l.d.set_exit("la").unwrap();
    let t = Instant::now();
    match l.d.dial(Some("ai"), &site(), 443).await {
        Ok(_) => panic!("{what}: AI flow opened"),
        Err(e) => assert!(e.0.contains("strict"), "{what}: {e}"),
    }
    assert!(
        t.elapsed() < Duration::from_millis(200),
        "{what}: refused after {:?}",
        t.elapsed()
    );
}

/// The lab with la probed `Connected`, ny down, and la's next carriers
/// following `plan` (true: dropped from the start).
async fn unknown_session_lab(l: Lab, plan: &[bool]) -> Lab {
    l.d.probe().await.unwrap();
    assert_eq!(l.d.posture(), Posture::Connected);
    l.ny_up.store(false, Ordering::SeqCst);
    l.la_drop_plan.lock().unwrap().extend(plan.iter().copied());
    l
}

/// r11 R5: the relay restarted (so the OPEN retry is UNKNOWN_SESSION,
/// answered before the ticket is read) and the ticket was revoked
/// meanwhile. The fresh OPEN is refused; la must not be left `Connected`
/// by the UNKNOWN_SESSION, and the refusal is a health failure.
#[tokio::test]
async fn unknown_session_then_a_revoked_ticket_leaves_the_exit_down() {
    for c in [code::REVOKED, code::AUTH, code::EXIT_DENIED] {
        let l = unknown_session_lab(lab_with(Box::new(Deny(c))), &[true]).await;
        let e = tokio::time::timeout(Duration::from_secs(15), l.d.dial(Some("ai"), &site(), 443))
            .await
            .expect("AI dial hung")
            .err()
            .expect("AI flow opened with a refused ticket");
        assert!(e.0.contains(&format!("code {c}")), "{c}: {e}");
        assert_ne!(la_posture(&l), Posture::Connected, "{c}: la Connected");
        assert_eq!(l.la_sites.load(Ordering::SeqCst), 0);
        assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 0, "{c}: moved to ny");
        ai_refused_fast(&l, "after the refusal").await;
    }
}

/// r11 R5: relay restart, and the Home exit is down: the fresh OPEN is
/// reset with HOME_UNAVAILABLE before OPENED. la stays down.
#[tokio::test]
async fn unknown_session_then_home_unavailable_leaves_the_exit_down() {
    let home_down: SiteConnector = Arc::new(|_, _| {
        Box::pin(async { Err(segue_session::driver::SiteError::io(code::HOME_UNAVAILABLE)) })
    });
    let l = unknown_session_lab(lab_parts(Box::new(AllowAll), Some(home_down)), &[true]).await;
    let e = tokio::time::timeout(Duration::from_secs(15), l.d.dial(Some("ai"), &site(), 443))
        .await
        .expect("AI dial hung")
        .err()
        .expect("AI flow opened with Home down");
    assert!(
        e.0.contains(&format!("code {}", code::HOME_UNAVAILABLE)),
        "{e}"
    );
    assert_eq!(
        l.la_sites.load(Ordering::SeqCst),
        1,
        "fresh OPEN never reached the relay"
    );
    assert_ne!(la_posture(&l), Posture::Connected);
    ai_refused_fast(&l, "Home down").await;
}

/// Refuses OPENs to `denied.example`, allows the rest.
struct DenyTarget;

impl Authorizer for DenyTarget {
    fn open(&self, _: &[u8], t: &Target, _: Kind) -> Result<segue_session::relay::Grant, u8> {
        match t {
            Target::Domain(d, _) if d == "denied.example" => Err(code::TARGET_DENIED),
            _ => Ok(segue_session::relay::Grant::all(0)),
        }
    }
    fn resume(&self, _: &[u8]) -> Result<u64, u8> {
        Ok(0)
    }
}

/// r11 R5: another session on la is failing (it took la down). An
/// UNKNOWN_SESSION answer to some flow does not bring la back nor clear
/// that failure; a fresh OPEN refused for its target (TARGET_DENIED: the
/// one flow, not the exit) leaves la as it was; a fresh OPEN that is
/// answered OPENED restores it.
#[tokio::test]
async fn unknown_session_beside_a_failing_session_restores_nothing_until_opened() {
    let l = unknown_session_lab(lab_with(Box::new(DenyTarget)), &[]).await;
    l.d.set_exit("la").unwrap();
    // The coexisting bad session: its carriers fail, nothing proves la.
    let bad = HealthReporter::new(l.d.state.clone(), 0);
    bad.report(SessionHealth::Failed);
    assert_eq!(la_posture(&l), Posture::Reconnecting);
    let denied = TargetAddr::Domain("denied.example".into());
    l.la_drop_plan.lock().unwrap().extend([true, false]);
    // An overseas flow (not refused while la is down) gets UNKNOWN_SESSION.
    let e = tokio::time::timeout(
        Duration::from_secs(15),
        l.d.dial(Some("overseas"), &denied, 443),
    )
    .await
    .expect("dial hung")
    .err()
    .expect("denied target opened");
    assert!(
        e.0.contains(&format!("code {}", code::TARGET_DENIED)),
        "{e}"
    );
    {
        let st = l.d.state.lock().unwrap();
        let h = &st.health[0];
        assert_eq!(
            h.ks.posture(),
            Posture::Reconnecting,
            "la restored without OPENED"
        );
        assert!(h.unproven, "failure state cleared");
        assert_eq!(h.failing(), 1, "the bad session's failure was cleared");
    }
    ai_refused_fast(&l, "beside the failing session").await;
    // OPENED (after an UNKNOWN_SESSION too) is proof.
    l.la_drop_plan.lock().unwrap().extend([true, false]);
    let s = tokio::time::timeout(
        Duration::from_secs(15),
        l.d.dial(Some("overseas"), &site(), 443),
    )
    .await
    .expect("dial hung")
    .expect("fresh session failed");
    assert_eq!(la_posture(&l), Posture::Connected);
    roundtrip(s).await;
    drop(bad);
}

/// r11 R5: every attempt's OPEN is lost and its retry answered
/// UNKNOWN_SESSION. Each answer grants one more try on la, bounded; none
/// of them restores la or clears its failures.
#[tokio::test]
async fn repeated_unknown_session_never_restores_the_exit() {
    let plan = [true, false].repeat(1 + FRESH_OPENS as usize);
    let l = unknown_session_lab(lab(), &plan).await;
    let seen_connected = Arc::new(AtomicBool::new(false));
    let watch = {
        let st = l.d.state.clone();
        let seen = seen_connected.clone();
        let failed_once = Arc::new(AtomicBool::new(false));
        tokio::spawn(async move {
            loop {
                let p = st.lock().unwrap().health[0].ks.posture();
                if p != Posture::Connected {
                    failed_once.store(true, Ordering::SeqCst);
                } else if failed_once.load(Ordering::SeqCst) {
                    seen.store(true, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    let e = tokio::time::timeout(Duration::from_secs(25), l.d.dial(Some("ai"), &site(), 443))
        .await
        .expect("AI dial hung")
        .err()
        .expect("AI flow opened although every OPEN was lost");
    watch.abort();
    assert!(
        e.0.contains(&format!("code {}", code::UNKNOWN_SESSION)),
        "{e}"
    );
    assert!(
        !seen_connected.load(Ordering::SeqCst),
        "UNKNOWN_SESSION made la Connected"
    );
    assert_ne!(la_posture(&l), Posture::Connected);
    assert!(l.d.state.lock().unwrap().health[0].unproven);
    assert!(
        l.la_drop_plan.lock().unwrap().is_empty(),
        "fewer attempts than allowed"
    );
    assert_eq!(l.la_sites.load(Ordering::SeqCst), 0);
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 0, "moved to ny");
    ai_refused_fast(&l, "after the attempts").await;
}

/// r11 R5: the user changes the manual exit while the first attempt is
/// outstanding. The fresh session after UNKNOWN_SESSION follows the new
/// choice, not the old attempt's exit.
#[tokio::test]
async fn a_manual_exit_change_during_the_attempt_voids_the_pin() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.d.probe().await.unwrap();
    l.la_drop_plan.lock().unwrap().extend([true, false]);
    let d = Arc::new(l.d);
    let dial = {
        let d = d.clone();
        tokio::spawn(async move { d.dial(Some("ai"), &site(), 443).await })
    };
    // Before T_attach (2 s): the first OPEN is still outstanding on la.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 0);
    d.set_exit("ny").unwrap();
    let s = tokio::time::timeout(Duration::from_secs(15), dial)
        .await
        .expect("AI dial hung")
        .unwrap()
        .expect("AI flow failed on the new exit");
    roundtrip(s).await;
    assert!(
        l.ny_carriers.load(Ordering::SeqCst) >= 1,
        "fresh session stayed on la"
    );
    assert_eq!(l.la_sites.load(Ordering::SeqCst), 0, "opened on la");
    assert_eq!(d.status().current_exit.as_deref(), Some("ny"));
}

/// A site that sends `n` bytes in one write as soon as it is connected
/// (the relay then sends full frames), then holds the stream open.
fn burst_site(n: usize) -> SiteConnector {
    Arc::new(move |_t, _k| {
        Box::pin(async move {
            let (a, mut b) = tokio::io::duplex(256 << 10);
            tokio::spawn(async move {
                let _ = b.write_all(&vec![7u8; n]).await;
                std::future::pending::<()>().await;
                drop(b);
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// A site that never reads (its buffer takes 1 KiB): an upload's FIN
/// stays held at the relay, which repeats its ACK to show it is alive.
fn deaf_site() -> SiteConnector {
    let keep = Arc::new(Mutex::new(Vec::new()));
    Arc::new(move |_t, _k| {
        let keep = keep.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(1024);
            keep.lock().unwrap().push(b);
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// Open a session on la, then lose its carrier and every carrier after
/// it (a bad session beside the others on the same exit); it keeps
/// failing in the background.
async fn start_bad_session(l: &Lab) -> tokio::task::JoinHandle<()> {
    let mut bad = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    l.la_drop_next.store(1000, Ordering::SeqCst);
    {
        let holes = l.la_holes.lock().unwrap();
        let (hole, _, _) = holes
            .iter()
            .rev()
            .find(|(_, c, _)| !c.load(Ordering::SeqCst))
            .expect("no session carrier");
        hole.store(true, Ordering::SeqCst);
    }
    tokio::spawn(async move {
        let _ = bad.write_all(b"ping").await;
        let _ = read_to_end_within(&mut bad, Duration::from_secs(120)).await;
    })
}

/// Watch la for `dur`: it must stay `Connected`; returns whether some
/// session on it was failing meanwhile (the bad one did fail).
async fn la_stays_connected(l: &Lab, dur: Duration, what: &str) -> bool {
    let end = Instant::now() + dur;
    let mut saw_failing = false;
    while Instant::now() < end {
        {
            let st = l.d.state.lock().unwrap();
            let h = &st.health[0];
            assert_eq!(h.ks.posture(), Posture::Connected, "{what}: la taken down");
            saw_failing |= h.failing() > 0;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    saw_failing
}

/// Open la's control stream first, so the next carrier is a session's.
async fn warm(l: &Lab) {
    l.d.set_exit("la").unwrap();
    let mut s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    let mut one = [0u8; 1];
    s.read_exact(&mut one).await.unwrap();
    drop(s);
    tokio::time::timeout(Duration::from_secs(2), async {
        while l.la_controls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("no control stream");
}

/// r11 R4: session B receives a 16 KiB frame at 1 KB/s (about 16 s, no
/// whole frame for far longer than PROOF_FRESH) while session A on the
/// same exit keeps failing. B's bytes arriving are path liveness: the
/// exit stays `Connected`, and B gets its frame.
#[tokio::test]
async fn a_slow_frame_keeps_the_exit_up_beside_a_failing_session() {
    let l = lab_parts(Box::new(AllowAll), Some(burst_site(64 << 10)));
    warm(&l).await;
    l.la_slow_next.store(1024, Ordering::SeqCst);
    let mut b = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    let bad = start_bad_session(&l).await;
    let t0 = Instant::now();
    let failed =
        la_stays_connected(&l, PROOF_FRESH * 2 + Duration::from_secs(1), "slow frame").await;
    assert!(failed, "the bad session never failed");
    // No whole frame reached B meanwhile (the test's premise) ...
    let mut buf = vec![0u8; 64 << 10];
    let n = tokio::time::timeout(Duration::from_secs(15), b.read(&mut buf))
        .await
        .expect("B's frame never arrived")
        .unwrap();
    assert!(n > 0);
    assert!(
        t0.elapsed() > PROOF_FRESH * 2,
        "frame arrived early: {:?}",
        t0.elapsed()
    );
    bad.abort();
}

/// A site that sends one byte at once, then holds its stream until `go`
/// is set, then sends `n` bytes in one write and holds it open.
fn site_on_cue(go: Arc<AtomicBool>, n: usize) -> SiteConnector {
    Arc::new(move |_t, _k| {
        let go = go.clone();
        Box::pin(async move {
            let (a, mut b) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let _ = b.write_all(&[7]).await;
                while !go.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let _ = b.write_all(&vec![7u8; n]).await;
                std::future::pending::<()>().await;
                drop(b);
            });
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// r12 #1: session B's next frame (a full 16 KiB DATA) is here, header
/// and body read off the carrier, but the shared pool cannot hold it: the
/// transport region is taken (another exit's slow frame) and fewer
/// elastic blocks are free than the frame needs, so B's reader waits in
/// `wait_charge`, reporting progress every 250 ms, while nothing more
/// arrives. That wait keeps B's carrier from stalling, but it is no new
/// path liveness: once B's last real bytes are older than PROOF_FRESH,
/// session A failing on the same exit (its small frames still fit) takes
/// the exit down.
#[tokio::test]
async fn a_local_pool_wait_is_no_liveness_beside_a_failing_session() {
    use segue_session::pool::{Grant, Tier, BLOCK};
    const FRAME: usize = segue_session::codec::MAX_PAYLOAD;
    let pool = Pool::new(8 << 20);
    let go = Arc::new(AtomicBool::new(false));
    let l = lab_full(
        Box::new(AllowAll),
        Some(site_on_cue(go.clone(), FRAME)),
        Config::default(),
        Some(pool.clone()),
        None,
    );
    warm(&l).await;
    // B's real evidence (OPENED, its first byte) is no older than this.
    let b_start = Instant::now();
    let mut b = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    let mut one = [0u8; 1];
    b.read_exact(&mut one).await.unwrap();
    let bad = start_bad_session(&l).await;
    // Leave fewer elastic blocks than B's frame needs (A's frames, of a
    // block or so, still fit), and take the whole transport region.
    let room = FRAME / BLOCK - 1;
    let free = pool.limit(Tier::Elastic) - pool.used_blocks();
    let elastic = Grant::fixed_in(&pool, (free - room) * BLOCK, Tier::Elastic).expect("elastic");
    let transport =
        Grant::between(&pool, BLOCK, usize::MAX / 2, Tier::Transport).expect("transport region");
    assert!(Grant::between(&pool, FRAME, FRAME, Tier::Elastic).is_none());
    assert!(Grant::between(&pool, 1, 1, Tier::Transport).is_none());
    let t0 = Instant::now();
    go.store(true, Ordering::SeqCst);
    let down = tokio::time::timeout(PROOF_FRESH * 3, async {
        loop {
            if l.d.state.lock().unwrap().health[0].ks.posture() != Posture::Connected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        down.is_ok(),
        "a local pool wait kept la Connected for {:?}: {:?}",
        t0.elapsed(),
        l.d.state.lock().unwrap().health[0].sessions
    );
    assert!(
        b_start.elapsed() >= PROOF_FRESH,
        "la went down before B's evidence aged: {:?}",
        b_start.elapsed()
    );
    // B itself never failed (its carrier was not taken for stalled): the
    // exit went down on A alone. With memory back, B's frame arrives.
    {
        let st = l.d.state.lock().unwrap();
        let failing = st.health[0].sessions.values().filter(|m| m.failing).count();
        assert_eq!(failing, 1, "{:?}", st.health[0].sessions);
    }
    drop((elastic, transport));
    let mut buf = vec![0u8; FRAME];
    tokio::time::timeout(Duration::from_secs(5), b.read_exact(&mut buf))
        .await
        .expect("B's frame never arrived")
        .unwrap();
    bad.abort();
}

/// A site that sends one byte at once and then never reads: an upload's
/// FIN stays held at the relay, which repeats its ACK as a keepalive.
fn one_byte_deaf_site() -> SiteConnector {
    let keep = Arc::new(Mutex::new(Vec::new()));
    Arc::new(move |_t, _k| {
        let keep = keep.clone();
        Box::pin(async move {
            let (a, mut b) = tokio::io::duplex(1024);
            let _ = b.write_all(&[7]).await;
            keep.lock().unwrap().push(b);
            Ok(Box::new(a) as BoxCarrier)
        })
    })
}

/// r13: session B's next frame is a whole duplicate keepalive ACK, read
/// off the carrier into the reader's buffer, but the shared pool is full
/// (every elastic block and the transport region taken), so it waits in
/// `wait_charge` while nothing more arrives (B's carrier black-holed
/// right after). Past PROOF_FRESH the memory comes back and the ACK is
/// handled: it was read long ago and moves nothing, so it is no fresh
/// liveness, and session A failing on the same exit right after takes the
/// exit down. (A long client `t_stall` keeps B's own carrier from
/// stalling once the wait ends, so B never fails itself.)
#[tokio::test]
async fn a_buffered_ack_after_a_pool_wait_is_no_liveness_beside_a_failing_session() {
    use segue_session::pool::{Grant, Tier, BLOCK};
    let pool = Pool::new(8 << 20);
    let mut client = Config::default();
    client.timing.t_stall = Duration::from_secs(30);
    let l = lab_full(
        Box::new(AllowAll),
        Some(one_byte_deaf_site()),
        Config::default(),
        Some(pool.clone()),
        Some(client),
    );
    warm(&l).await;
    let mut b = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    let mut one = [0u8; 1];
    b.read_exact(&mut one).await.unwrap();
    // Upload and FIN: the site never reads, the relay holds the FIN and
    // repeats its ACK twice a second.
    b.write_all(&vec![1u8; 8 << 10]).await.unwrap();
    b.shutdown().await.unwrap();
    // Let idle buffers go back first (READ_IDLE, idle credit).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let free = pool.limit(Tier::Elastic) - pool.used_blocks();
    let elastic = Grant::fixed_in(&pool, free * BLOCK, Tier::Elastic).expect("elastic");
    let transport =
        Grant::between(&pool, BLOCK, usize::MAX / 2, Tier::Transport).expect("transport region");
    assert!(Grant::between(&pool, 1, 1, Tier::Elastic).is_none());
    assert!(Grant::between(&pool, 1, 1, Tier::Transport).is_none());
    // The next keepalive ACK arrives whole and waits for memory; before
    // another can follow, B's carrier delivers nothing more.
    tokio::time::timeout(Duration::from_secs(2), async {
        while pool.queued() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("B's ACK never waited for memory");
    let t0 = Instant::now();
    {
        let holes = l.la_holes.lock().unwrap();
        let (hole, _, _) = holes
            .iter()
            .rev()
            .find(|(_, c, _)| !c.load(Ordering::SeqCst))
            .expect("no session carrier");
        hole.store(true, Ordering::SeqCst);
    }
    tokio::time::sleep(PROOF_FRESH + Duration::from_secs(1)).await;
    assert_eq!(pool.queued(), 1, "B's ACK no longer waits");
    assert_eq!(
        l.d.state.lock().unwrap().health[0].ks.posture(),
        Posture::Connected
    );
    // Memory back: B's ACK is handled now; then A fails on la.
    drop((elastic, transport));
    let release = Instant::now();
    let bad = start_bad_session(&l).await;
    let down = tokio::time::timeout(PROOF_FRESH - Duration::from_secs(1), async {
        loop {
            if l.d.state.lock().unwrap().health[0].ks.posture() != Posture::Connected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        down.is_ok(),
        "a buffered ACK kept la Connected {:?} after the wait ({:?} after its arrival): {:?}",
        release.elapsed(),
        t0.elapsed(),
        l.d.state.lock().unwrap().health[0].sessions
    );
    {
        let st = l.d.state.lock().unwrap();
        let failing = st.health[0].sessions.values().filter(|m| m.failing).count();
        assert_eq!(failing, 1, "B failed too: {:?}", st.health[0].sessions);
    }
    bad.abort();
    drop(b);
}

/// r11 R4: an upload-only session B (its FIN held at the relay, which only
/// repeats its ACK) beside a failing session A: the keepalive ACKs are
/// path liveness, the exit stays `Connected`.
#[tokio::test]
async fn an_upload_only_session_keeps_the_exit_up_beside_a_failing_session() {
    let l = lab_parts(Box::new(AllowAll), Some(deaf_site()));
    l.d.set_exit("la").unwrap();
    l.d.probe().await.unwrap();
    let mut b = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    b.write_all(&vec![1u8; 8 << 10]).await.unwrap();
    b.shutdown().await.unwrap();
    // B's last data moved now (its upload acknowledged).
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bad = start_bad_session(&l).await;
    let failed = la_stays_connected(&l, PROOF_FRESH * 2, "upload only").await;
    assert!(failed, "the bad session never failed");
    bad.abort();
    drop(b);
}

/// r11 R4: an exit whose only session sat idle well past PROOF_FRESH is
/// still `Connected` (idle is no evidence against it), and the first AI
/// request after the idle period opens.
#[tokio::test]
async fn the_first_request_after_idle_opens() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    let s = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    tokio::time::sleep(PROOF_FRESH + Duration::from_secs(1)).await;
    assert_eq!(l.d.posture(), Posture::Connected);
    let ai =
        l.d.dial(Some("ai"), &site(), 443)
            .await
            .expect("AI refused after idle");
    roundtrip(ai).await;
    roundtrip(s).await;
}

/// A lost first carrier (here, a dial that does not answer for a second)
/// must not stall the session: the second attempt to the same exit wins,
/// and the exit is not marked failed.
#[tokio::test(start_paused = true)]
async fn a_slow_first_carrier_loses_to_the_raced_second() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    *l.la_hang_next.lock().unwrap() = Some(Duration::from_secs(1));
    let start = tokio::time::Instant::now();
    let s =
        l.d.dial(Some("overseas"), &site(), 443)
            .await
            .expect("session did not open");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(900),
        "opened in {elapsed:?}; the slow dial was not raced"
    );
    assert_eq!(l.d.posture(), Posture::Connected);
    assert_eq!(l.d.fail_marks(0), 0, "a losing attempt is not a failure");
    assert_eq!(
        l.d.race_second_started.load(Ordering::Relaxed),
        1,
        "the second attempt was not started"
    );
    assert_eq!(
        l.d.race_second_won.load(Ordering::Relaxed),
        1,
        "the second attempt did not win"
    );
    assert_eq!(l.ny_carriers.load(Ordering::SeqCst), 0, "race stayed on la");
    roundtrip(s).await;
}

/// Both attempts of one race fail: the exit is marked failed once, not
/// once per attempt.
#[tokio::test(start_paused = true)]
async fn both_carrier_attempts_failing_marks_the_exit_once() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.la_up.store(false, Ordering::SeqCst);
    assert!(l.d.probe().await.is_err());
    assert_eq!(
        l.la_dials.load(Ordering::SeqCst),
        2,
        "the race dialed twice"
    );
    assert_eq!(l.d.race_second_started.load(Ordering::Relaxed), 1);
    assert_eq!(l.d.race_second_won.load(Ordering::Relaxed), 0);
    assert_eq!(
        l.d.fail_marks(0),
        1,
        "marked failed once for the whole race"
    );
    assert_eq!(l.d.posture(), Posture::Error);
    assert_eq!(
        l.ny_carriers.load(Ordering::SeqCst),
        0,
        "named exit was not left"
    );
}

async fn spin_until(mut ready: impl FnMut() -> bool) {
    for _ in 0..100 {
        if ready() {
            return;
        }
        tokio::task::yield_now().await;
    }
    for _ in 0..40 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not met");
}

/// AI sessions dial a second carrier after OPENED and bind it. A non-AI
/// session never does, and turning the switch off is the old one-dial path.
#[tokio::test(start_paused = true)]
async fn an_ai_session_binds_a_standby_and_other_sessions_do_not() {
    let l = lab();
    let overseas = l.d.dial(Some("overseas"), &site(), 443).await.unwrap();
    roundtrip(overseas).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 0);
    assert_eq!(l.d.standby_bound.load(Ordering::Relaxed), 0);

    let l = lab();
    let ai = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| l.d.standby_bound.load(Ordering::Relaxed) >= 1).await;
    assert!(
        l.d.standby_dials.load(Ordering::Relaxed) >= 1,
        "no standby dial"
    );
    let dials = l.d.standby_dials.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        dials,
        "a bound standby was dialled again"
    );
    roundtrip(ai).await;

    let mut l = lab();
    l.d.set_standby_ai(false);
    let ai = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| l.la_controls.load(Ordering::SeqCst) >= 1).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 0);
    assert_eq!(l.d.standby_bound.load(Ordering::Relaxed), 0);
    assert_eq!(
        l.la_carriers.load(Ordering::SeqCst),
        1,
        "standby off dialled more than the session carrier"
    );
    roundtrip(ai).await;
}

/// Three failed standby dials leave the exit's posture and loss counters
/// alone, and the waits double from 1 s.
#[tokio::test(start_paused = true)]
async fn a_failing_standby_does_not_mark_the_exit_and_backs_off() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.d.fail_standby_dials(true);
    let s = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) >= 1).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 1);
    assert_eq!(l.d.fail_marks(0), 0, "standby dial marked the exit failed");
    assert_eq!(l.d.posture(), Posture::Connected);
    assert_eq!(l.d.status().quality[0].quality.stalls, 0);

    let t0 = tokio::time::Instant::now();
    tokio::time::sleep_until(t0 + Duration::from_millis(900)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        1,
        "retried before the 1 s backoff"
    );
    tokio::time::sleep_until(t0 + Duration::from_millis(1100)).await;
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) >= 2).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 2);

    let t1 = tokio::time::Instant::now();
    tokio::time::sleep_until(t1 + Duration::from_millis(1900)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        2,
        "retried before the doubled 2 s backoff"
    );
    tokio::time::sleep_until(t1 + Duration::from_millis(2200)).await;
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) >= 3).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 3);
    assert_eq!(l.d.fail_marks(0), 0);
    assert_eq!(l.d.posture(), Posture::Connected);
    assert_eq!(l.d.status().quality[0].quality.stalls, 0);
    assert_eq!(l.d.standby_promotions.load(Ordering::Relaxed), 0);
    roundtrip(s).await;
}

/// Two failed dials leave the next wait at 4 s. A spare that then stays
/// bound for 10 s resets that wait to 1 s when it is closed.
#[tokio::test(start_paused = true)]
async fn standby_backoff_resets_to_one_second_after_ten_seconds_bound() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.d.fail_standby_dials(true);
    let s = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) >= 1).await;
    let t0 = tokio::time::Instant::now();
    tokio::time::sleep_until(t0 + Duration::from_millis(900)).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 1);
    tokio::time::sleep_until(t0 + Duration::from_millis(1100)).await;
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) >= 2).await;
    assert_eq!(l.d.standby_dials.load(Ordering::Relaxed), 2);

    l.d.fail_standby_dials(false);
    let t1 = tokio::time::Instant::now();
    tokio::time::sleep_until(t1 + Duration::from_millis(1900)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        2,
        "retried before the 2 s backoff"
    );
    tokio::time::sleep_until(t1 + Duration::from_millis(2200)).await;
    spin_until(|| l.d.standby_bound.load(Ordering::Relaxed) >= 1).await;
    let dials = l.d.standby_dials.load(Ordering::Relaxed);
    assert_eq!(dials, 3, "the spare that reset the backoff was not dialled");
    let lost = l.d.standby_lost.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        dials,
        "a bound standby was redialled"
    );

    let end = {
        let holes = l.la_holes.lock().unwrap();
        let mut session = Vec::new();
        for (_, is_control, end) in holes.iter() {
            if is_control.load(Ordering::SeqCst) {
                continue;
            }
            session.push(end.clone());
        }
        assert!(
            session.len() >= 2,
            "expected the session carrier and the standby, saw {}",
            session.len()
        );
        session.swap_remove(1)
    };
    end.send(true).expect("standby path is gone");
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) > lost).await;
    assert_eq!(
        l.d.standby_promotions.load(Ordering::Relaxed),
        0,
        "closing the spare promoted it"
    );
    let t2 = tokio::time::Instant::now();
    tokio::time::sleep_until(t2 + Duration::from_millis(900)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        dials,
        "retried before the reset 1 s backoff"
    );
    tokio::time::sleep_until(t2 + Duration::from_millis(1200)).await;
    spin_until(|| l.d.standby_dials.load(Ordering::Relaxed) > dials).await;
    roundtrip(s).await;
}

/// Killing the current carrier promotes the standby. Bytes keep matching,
/// and the replacement standby is dialled only after data has resumed.
#[tokio::test(start_paused = true)]
async fn ai_standby_promotes_without_waiting_for_a_dial() {
    let mut off_cfg = Config::default();
    off_cfg.redundancy.mode = segue_session::RedundancyMode::Off;
    let l = lab_full(
        Box::new(AllowAll),
        Some(endless_download()),
        off_cfg.clone(),
        None,
        Some(off_cfg),
    );
    l.d.set_exit("la").unwrap();
    let mut s = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    let mut at = 0u64;
    read_pattern(&mut s, &mut at, 8192, Duration::from_secs(5)).await;
    spin_until(|| {
        l.d.standby_bound.load(Ordering::Relaxed) >= 1 && l.la_controls.load(Ordering::SeqCst) >= 1
    })
    .await;
    let dials = l.d.standby_dials.load(Ordering::Relaxed);
    {
        let holes = l.la_holes.lock().unwrap();
        let mut session_holes = 0usize;
        for (hole, is_control, _) in holes.iter() {
            if is_control.load(Ordering::SeqCst) {
                continue;
            }
            if session_holes == 0 {
                hole.store(true, Ordering::SeqCst);
            }
            session_holes += 1;
        }
        assert!(
            session_holes >= 2,
            "expected the session carrier and the standby, saw {session_holes}"
        );
    }
    read_pattern(&mut s, &mut at, 128 * 1024, Duration::from_secs(8)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        dials,
        "promotion waited for a new dial"
    );
    assert!(
        l.d.standby_promotions.load(Ordering::Relaxed) >= 1,
        "standby was not promoted"
    );
    assert!(
        l.d.standby_swaps.load(Ordering::Relaxed) >= 1,
        "the stall did not swap"
    );
    assert_eq!(
        l.d.standby_bound.load(Ordering::Relaxed),
        1,
        "a swap was counted as another bind"
    );
    // The old carrier is the spare now. It is dropped after 10 s with no
    // frame, and the replacement dial waits out the backoff that schedule
    // armed (1 s, then 2 s because the swap itself scheduled once).
    let swapped = tokio::time::Instant::now();
    tokio::time::sleep_until(swapped + Duration::from_secs(10)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        dials,
        "a swapped carrier was replaced before it had been silent for 10 s"
    );
    tokio::time::sleep_until(swapped + Duration::from_secs(13)).await;
    spin_until(|| l.d.standby_dials.load(Ordering::Relaxed) > dials).await;
}

/// A disconnect or a revocation stops standby dials, including ones the
/// backoff would otherwise start.
#[tokio::test(start_paused = true)]
async fn no_standby_dials_while_disconnected_or_revoked() {
    let l = lab();
    l.d.set_exit("la").unwrap();
    l.d.fail_standby_dials(true);
    let live = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| l.d.standby_lost.load(Ordering::Relaxed) >= 1).await;
    let n = l.d.standby_dials.load(Ordering::Relaxed);
    l.d.disconnect();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        n,
        "disconnected session dialled a standby"
    );
    let _ = live;

    let l = lab();
    l.d.set_exit("la").unwrap();
    l.d.fail_standby_dials(true);
    let mut live = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| {
        l.d.standby_lost.load(Ordering::Relaxed) >= 1 && l.la_controls.load(Ordering::SeqCst) >= 1
    })
    .await;
    let n = l.d.standby_dials.load(Ordering::Relaxed);
    l.la_ctrl
        .send(RelayCtrl::ResetDevice {
            device: 0,
            close_code: code::REVOKED,
        })
        .await
        .unwrap();
    let mut buf = [0u8; 8];
    let end = tokio::time::timeout(Duration::from_secs(2), live.read(&mut buf)).await;
    assert!(end.is_ok(), "revoked session did not end");
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(
        l.d.standby_dials.load(Ordering::Relaxed),
        n,
        "revoked session dialled a standby"
    );
    assert_eq!(l.d.status().revoked, Some(code::REVOKED));
}

/// Under default Stage 2 duplication, a blackholed primary carrier still
/// delivers 1024-byte SSE tokens through the bound standby immediately (< 2 s)
/// before the 5 s `t_live_ai` swap fires, then swaps once `5 s` elapses.
#[tokio::test(start_paused = true)]
async fn ai_stage2_dup_delivers_through_blackhole_immediately_then_swaps() {
    let l = lab_parts(Box::new(AllowAll), Some(endless_download()));
    l.d.set_exit("la").unwrap();
    let mut s = l.d.dial(Some("ai"), &site(), 443).await.unwrap();
    let mut at = 0u64;
    read_pattern(&mut s, &mut at, 8192, Duration::from_secs(5)).await;
    spin_until(|| {
        l.d.standby_bound.load(Ordering::Relaxed) >= 1 && l.la_controls.load(Ordering::SeqCst) >= 1
    })
    .await;
    {
        let holes = l.la_holes.lock().unwrap();
        for (hole, is_control, _) in holes.iter() {
            if !is_control.load(Ordering::SeqCst) {
                hole.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
    // Delivered rapidly via Stage 2 dup before `t_live_ai` = 5 s swaps.
    read_pattern(&mut s, &mut at, 128 * 1024, Duration::from_secs(2)).await;
    assert_eq!(
        l.d.standby_promotions.load(Ordering::Relaxed),
        0,
        "swapped before t_live_ai while Stage 2 dup was still flowing"
    );
    // Keep reading across the 5 s threshold so swap still triggers and cleans up.
    read_pattern(&mut s, &mut at, 1024 * 1024, Duration::from_secs(8)).await;
    assert!(l.d.standby_promotions.load(Ordering::Relaxed) >= 1);
    assert!(l.d.standby_swaps.load(Ordering::Relaxed) >= 1);
}

/// Standby dials route through `Exit::redundant_carrier` when configured and
/// never run parallel carrier racing even across a slow handshake.
#[tokio::test(start_paused = true)]
async fn standby_uses_redundant_carrier_without_racing() {
    let main = node(Box::new(AllowAll), None, Config::default());
    // Second outbound reaching the same exit relay (`main.accept`).
    let alt = Node {
        accept: main.accept.clone(),
        up: Arc::new(AtomicBool::new(true)),
        carriers: Arc::default(),
        controls: Arc::default(),
        holes: Holes::default(),
        sites: main.sites.clone(),
        ctrl: main.ctrl.clone(),
        cut: Arc::default(),
        drop_next: Arc::default(),
        drop_plan: Arc::default(),
        slow_next: Arc::default(),
        dials: Arc::default(),
        hang_next: Arc::default(),
    };
    let main_carriers = main.carriers.clone();
    let alt_dials = alt.dials.clone();
    let alt_carriers = alt.carriers.clone();
    let alt_hang = alt.hang_next.clone();
    let engine = Arc::new(Engine {
        nodes: [("la-main".to_string(), main), ("la-alt".to_string(), alt)].into(),
        ..Default::default()
    });
    let exits = vec![Exit {
        name: "la".into(),
        carrier: "la-main".into(),
        redundant_carrier: Some("la-alt".into()),
        relay: "127.0.0.1:7443".parse().unwrap(),
        node_id: 1,
        egress_group: String::new(),
    }];
    let routes = [(
        "ai".to_string(),
        SegueRoute {
            ticket: b"ticket".to_vec(),
            exit_class: EXIT_AI,
        },
    )]
    .into();
    let dialer = KernelDialer::new(engine, exits, routes, ["ai".to_string()].into());
    // Establish an SRTT sample via control PING first so `race_delay(srtt)` is finite (~200 ms),
    // then force a 400 ms handshake delay on `la-alt` before the standby dial runs.
    *alt_hang.lock().unwrap() = Some(Duration::from_millis(400));
    let s = dialer.dial(Some("ai"), &site(), 443).await.unwrap();
    spin_until(|| dialer.standby_bound() >= 1).await;
    assert_eq!(
        alt_dials.load(Ordering::SeqCst),
        1,
        "standby did not use redundant_carrier"
    );
    assert_eq!(alt_carriers.load(Ordering::SeqCst), 1);
    assert_eq!(
        main_carriers.load(Ordering::SeqCst),
        1,
        "main outbound received extra standby carrier"
    );
    assert_eq!(
        dialer.race_second_started.load(Ordering::Relaxed),
        0,
        "standby dial started parallel carrier race"
    );
    roundtrip(s).await;
}
