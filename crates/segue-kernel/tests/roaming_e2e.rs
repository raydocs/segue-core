//! An AI-style SSE stream survives a carrier cut (SESSION_PROTOCOL v0.5
//! §4.4, §5.1, §5.3).
//!
//! ```text
//! app TCP ──SOCKS── segue-kernel session ──cut proxy── segue-relay ── origin
//! ```
//!
//! The proxy is the carrier. At 40% of the stream it RSTs every spliced
//! socket and drops its listener for 1.5 s (reconnects are refused), then
//! listens again. The app's one SOCKS connection must stay up and receive
//! every event once, in order. A direct path through the same proxy, with
//! no session, breaks — resumption is what saves the stream.
//!
//! Plain TCP is the carrier. A second case dials that same proxy through
//! the kernel's freedom outbound (no external binary).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use segue_kernel::dial::{DialError, Dialer, EngineDialer, Stream};
use segue_kernel::rules::{Action, RuleSet};
use segue_kernel::session::{Exit, KernelDialer, SegueRoute};
use segue_kernel::socks::{serve, Kernel, REP_OK};
use segue_relay::cidr::Cidr;
use segue_relay::config::Config;
use segue_relay::dial::Resolver;
use segue_relay::guard::Guard;
use segue_relay::server::{serve as serve_relay, Relay};
use segue_relay::system_clock;
use segue_relay::ticket::{generate_pkcs8, Claims, ExitClass, Signer};
use segue_session::pool::Pool;
use segue_transport::TransportDialer;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

const EVENTS: u32 = 4_000;
const EVENT_LEN: usize = 512;
/// 40% of [`EVENTS`].
const CUT_AT: u32 = 1_600;
const BLACKOUT: Duration = Duration::from_millis(1_500);
const STALL_LIMIT: Duration = Duration::from_secs(5);

fn checksum(n: u32) -> u32 {
    n.wrapping_mul(0x0100_0193) ^ 0xA5A5_5A5A
}

/// One SSE event, exactly 512 bytes, ending in `\n\n`. `id` is the sequence
/// number; `sum` covers it. Padding is `x`, so the only `\n\n` is the tail.
fn event(n: u32) -> [u8; EVENT_LEN] {
    let head = format!("id:{n:06}\ndata: sum={:08x} ", checksum(n));
    let head = head.as_bytes();
    assert!(head.len() + 2 < EVENT_LEN, "event head does not fit");
    let mut out = [b'x'; EVENT_LEN];
    out[..head.len()].copy_from_slice(head);
    out[EVENT_LEN - 2] = b'\n';
    out[EVENT_LEN - 1] = b'\n';
    out
}

/// `frame` is one event without its trailing `\n\n`.
fn parse_event(frame: &[u8]) -> Result<u32, String> {
    if frame.len() + 2 != EVENT_LEN {
        return Err(format!("len {}", frame.len()));
    }
    let s = std::str::from_utf8(frame).map_err(|e| e.to_string())?;
    let rest = s
        .strip_prefix("id:")
        .ok_or_else(|| "missing id".to_string())?;
    let (num, rest) = rest
        .split_once('\n')
        .ok_or_else(|| "missing newline".to_string())?;
    let n: u32 = num
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())?;
    let rest = rest
        .strip_prefix("data: sum=")
        .ok_or_else(|| "missing sum".to_string())?;
    if rest.len() < 8 {
        return Err("short sum".into());
    }
    let sum = u32::from_str_radix(&rest[..8], 16).map_err(|e| e.to_string())?;
    if sum != checksum(n) {
        return Err(format!("checksum {sum:08x} != {:08x}", checksum(n)));
    }
    Ok(n)
}

fn find_sub(buf: &[u8], needle: &[u8]) -> Option<usize> {
    buf.windows(needle.len()).position(|w| w == needle)
}

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir(tag: &str) -> TempDir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let p = std::env::temp_dir().join(format!(
        "segue-roaming-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

fn now_unix() -> u64 {
    system_clock()()
}

struct RelayEnv {
    relay: Arc<Relay>,
    signer: Signer,
    _dir: TempDir,
}

fn relay_env() -> RelayEnv {
    let dir = tempdir("relay");
    let signer = Signer::from_pkcs8(3, &generate_pkcs8()).unwrap();
    let pk = base64::engine::general_purpose::STANDARD.encode(signer.public_key());
    let (policy_key, policy_pub) = segue_policy::generate_key();
    let body = json!({
        "version": 1,
        "expires_at": now_unix() + 3600,
        "ai_domains": ["ai.test"],
        "ai_cidrs": [],
        "default": {"type": "proxy", "outbound": "overseas"}
    });
    let bundle = segue_policy::sign(&policy_key, 1, body.to_string().as_bytes()).unwrap();
    std::fs::write(dir.0.join("policy.bundle"), bundle).unwrap();
    let json = format!(
        r#"{{
            "listen": "127.0.0.1:1",
            "node_id": 1,
            "ticket_keys": [{{"key_id": 3, "public_key": "{pk}"}}],
            "policy": {{
                "public_keys": [{{"key_id": 1, "public_key": "{policy_pub}"}}],
                "bundle": "policy.bundle"
            }}
        }}"#
    );
    let cfg = Config::parse_in(&json, &dir.0).unwrap();
    // The origin is on loopback. A real node would not set this.
    let guard = Guard {
        extra_blocked: vec![],
        exceptions: vec![Cidr::parse("127.0.0.1/32").unwrap()],
    };
    let resolver: Resolver = Arc::new(|host: String| {
        Box::pin(async move {
            if host == "echo.test" {
                Ok(vec![IpAddr::from([127, 0, 0, 1])])
            } else {
                Err(io::Error::other("nxdomain"))
            }
        })
    });
    let relay = Arc::new(Relay::new(cfg, system_clock(), Some(resolver), Some(guard)).unwrap());
    RelayEnv {
        relay,
        signer,
        _dir: dir,
    }
}

fn ticket(env: &RelayEnv) -> Vec<u8> {
    let t = now_unix();
    env.signer.sign(&Claims {
        v: 1,
        key_id: 0,
        device_id: 7,
        account_id: 1,
        plan: "pro".into(),
        exit_classes: vec![ExitClass::Overseas],
        ai_anchor_node_id: 0,
        not_before: t.saturating_sub(60),
        not_after: t + 3600,
    })
}

/// Byte pipe that can be cut. `carriers` counts splices to `backend`
/// (refused handshakes are not counted).
#[derive(Clone)]
struct Proxy {
    addr: SocketAddr,
    carriers: Arc<AtomicUsize>,
    pause: watch::Sender<bool>,
    kill: watch::Sender<u64>,
    /// `true` once the accept loop has dropped the listener for a pause.
    dropped: watch::Sender<bool>,
}

impl Proxy {
    async fn start(backend: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (pause_tx, pause_rx) = watch::channel(false);
        let (kill_tx, _) = watch::channel(0u64);
        let (dropped_tx, _) = watch::channel(false);
        let carriers = Arc::new(AtomicUsize::new(0));
        let proxy = Self {
            addr,
            carriers: carriers.clone(),
            pause: pause_tx,
            kill: kill_tx.clone(),
            dropped: dropped_tx.clone(),
        };
        tokio::spawn(accept_loop(
            listener, addr, backend, pause_rx, kill_tx, carriers, dropped_tx,
        ));
        proxy
    }

    /// RST every live splice and refuse new connects for `d`.
    async fn cut_for(&self, d: Duration) {
        let mut dropped = self.dropped.subscribe();
        dropped.mark_unchanged();
        self.pause.send_replace(true);
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if *dropped.borrow() {
                    return;
                }
                if dropped.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
        if closed.is_err() {
            panic!("cut proxy did not drop its listener");
        }
        self.kill.send_modify(|g| *g += 1);
        tokio::time::sleep(d).await;
        self.pause.send_replace(false);
    }
}

fn rst(stream: TcpStream) {
    // Abortive close: RST, and it does not block the runtime on drop.
    let _ = stream.set_zero_linger();
    drop(stream);
}

async fn accept_loop(
    listener: TcpListener,
    addr: SocketAddr,
    backend: SocketAddr,
    mut pause_rx: watch::Receiver<bool>,
    kill: watch::Sender<u64>,
    carriers: Arc<AtomicUsize>,
    dropped: watch::Sender<bool>,
) {
    // The initial `false` is not a pause.
    pause_rx.mark_unchanged();
    let mut slot = Some(listener);
    loop {
        if *pause_rx.borrow() {
            slot = None;
            dropped.send_replace(true);
            if pause_rx.changed().await.is_err() {
                return;
            }
            continue;
        }
        dropped.send_replace(false);
        if slot.is_none() {
            slot = Some(TcpListener::bind(addr).await.expect("rebind cut proxy"));
        }
        let acc = {
            let lis = slot.as_mut().unwrap();
            tokio::select! {
                biased;
                changed = pause_rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    None
                }
                acc = lis.accept() => Some(acc),
            }
        };
        let Some(acc) = acc else {
            continue;
        };
        let down = match acc {
            Ok((stream, _)) => stream,
            Err(_) => {
                slot = None;
                continue;
            }
        };
        if *pause_rx.borrow() {
            rst(down);
            continue;
        }
        let kill_rx = kill.subscribe();
        let gen = *kill_rx.borrow();
        let carriers = carriers.clone();
        tokio::spawn(async move {
            splice_one(down, backend, kill_rx, gen, carriers).await;
        });
    }
}

async fn splice_one(
    down: TcpStream,
    backend: SocketAddr,
    mut kill_rx: watch::Receiver<u64>,
    gen: u64,
    carriers: Arc<AtomicUsize>,
) {
    let up = match TcpStream::connect(backend).await {
        Ok(s) => s,
        Err(_) => {
            rst(down);
            return;
        }
    };
    // A cut that landed while we were connecting: do not become a carrier.
    if *kill_rx.borrow() != gen {
        rst(down);
        rst(up);
        return;
    }
    let _ = down.set_nodelay(true);
    let _ = up.set_nodelay(true);
    carriers.fetch_add(1, Ordering::SeqCst);
    let mut down = down;
    let mut up = up;
    tokio::select! {
        _ = tokio::io::copy_bidirectional(&mut down, &mut up) => {
            // A finished stream is not a fault. RST here would look like
            // another carrier cut to a session that has already drained.
            drop(down);
            drop(up);
        }
        _ = async {
            loop {
                if *kill_rx.borrow() != gen {
                    return;
                }
                if kill_rx.changed().await.is_err() {
                    return;
                }
            }
        } => {
            rst(down);
            rst(up);
        }
    }
}

/// Local HTTP/1.1 origin. One response: a chat-style SSE body, 4,000
/// events of 512 bytes, 2 ms apart.
async fn serve_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(write_sse(sock));
        }
    });
    addr
}

async fn write_sse(mut sock: TcpStream) {
    let _ = sock.set_nodelay(true);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if find_sub(&buf, b"\r\n\r\n").is_some() {
            break;
        }
    }
    let header =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n";
    if sock.write_all(header).await.is_err() {
        return;
    }
    for n in 0..EVENTS {
        if sock.write_all(&event(n)).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let _ = sock.shutdown().await;
}

struct PlainCarrier;

#[async_trait]
impl Dialer for PlainCarrier {
    async fn dial(
        &self,
        _tag: Option<&str>,
        addr: &segue_routing::TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        let ip = match addr {
            segue_routing::TargetAddr::Ip(ip) => *ip,
            segue_routing::TargetAddr::Domain(d) => {
                return Err(DialError(format!("carrier dial wants an ip, got {d}")));
            }
        };
        let stream = TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(|e| DialError(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }
}

fn freedom_carrier() -> Arc<dyn Dialer> {
    let mut specs = BTreeMap::new();
    specs.insert("tcp".to_owned(), json!({"protocol": "freedom"}));
    let transport = Arc::new(TransportDialer::system().expect("system transport"));
    let engine = EngineDialer::with_transport_dialer(&specs, transport).expect("freedom outbound");
    Arc::new(engine)
}

/// Dials the cut proxy and ignores the requested target. The proxy's
/// backend is the origin, so this is a direct path with no session.
struct DirectViaProxy {
    proxy: SocketAddr,
}

#[async_trait]
impl Dialer for DirectViaProxy {
    async fn dial(
        &self,
        _tag: Option<&str>,
        _addr: &segue_routing::TargetAddr,
        _port: u16,
    ) -> Result<Stream, DialError> {
        let stream = TcpStream::connect(self.proxy)
            .await
            .map_err(|e| DialError(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(stream))
    }
}

async fn spawn_socks(dialer: Arc<dyn Dialer>, tag: &str) -> SocketAddr {
    let rules = RuleSet::new(Vec::new(), Action::Proxy(tag.into()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kernel = Arc::new(Kernel::new(rules, dialer));
    tokio::spawn(async move {
        let _ = serve(listener, kernel).await;
    });
    addr
}

fn session_dialer(engine: Arc<dyn Dialer>, proxy: SocketAddr, ticket: Vec<u8>) -> Arc<dyn Dialer> {
    let mut routes = BTreeMap::new();
    routes.insert(
        "ov".into(),
        SegueRoute {
            ticket,
            exit_class: segue_kernel::session::EXIT_OVERSEAS,
        },
    );
    let dialer = KernelDialer::new(
        engine,
        vec![Exit {
            name: "ov".into(),
            carrier: "tcp".into(),
            relay: proxy,
            node_id: 1,
            egress_group: String::new(),
        }],
        routes,
        BTreeSet::new(),
    )
    .with_pool(Pool::new(8 << 20));
    Arc::new(dialer)
}

async fn socks_connect(kernel: SocketAddr, host: &str, port: u16) -> TcpStream {
    let mut conn = TcpStream::connect(kernel).await.unwrap();
    let _ = conn.set_nodelay(true);
    conn.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    conn.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0], "SOCKS method");
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    conn.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    conn.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], REP_OK, "SOCKS connect refused ({})", rep[1]);
    conn
}

struct ReadOut {
    events: u32,
    stall: Duration,
    /// `Ok(())` is a clean EOF. `Err` is a reset or a deadline.
    end: io::Result<()>,
    carriers_at_cut: usize,
    cut: Option<JoinHandle<()>>,
}

async fn read_sse(mut sock: TcpStream, proxy: Proxy, deadline: Duration) -> ReadOut {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut header = false;
    let mut next = 0u32;
    let mut last: Option<Instant> = None;
    let mut stall = Duration::ZERO;
    let mut carriers_at_cut = 0usize;
    let mut cut: Option<JoinHandle<()>> = None;
    let deadline_at = Instant::now() + deadline;
    let end = loop {
        let left = deadline_at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("still short of the stream after {deadline:?} ({next} events)"),
            ));
        }
        let n = match tokio::time::timeout(left, sock.read(&mut tmp)).await {
            Err(_) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("read idle ({next} events)"),
                ));
            }
            Ok(Err(e)) => break Err(e),
            Ok(Ok(0)) => break Ok(()),
            Ok(Ok(n)) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if !header {
            if let Some(i) = find_sub(&buf, b"\r\n\r\n") {
                buf.drain(..i + 4);
                header = true;
            } else {
                continue;
            }
        }
        while let Some(i) = find_sub(&buf, b"\n\n") {
            let frame: Vec<u8> = buf.drain(..i).collect();
            buf.drain(..2);
            let seq = parse_event(&frame).unwrap_or_else(|e| {
                panic!("event {next} invalid ({e}): {frame:?}");
            });
            assert_eq!(seq, next, "event out of order or duplicated");
            next += 1;
            let now = Instant::now();
            if let Some(prev) = last {
                let gap = now.saturating_duration_since(prev);
                if gap > stall {
                    stall = gap;
                }
            }
            last = Some(now);
            if next == CUT_AT && cut.is_none() {
                carriers_at_cut = proxy.carriers.load(Ordering::SeqCst);
                let proxy = proxy.clone();
                cut = Some(tokio::spawn(async move {
                    proxy.cut_for(BLACKOUT).await;
                }));
            }
        }
    };
    // A reset can arrive with a complete event still in `buf`.
    if header {
        while let Some(i) = find_sub(&buf, b"\n\n") {
            let frame: Vec<u8> = buf.drain(..i).collect();
            buf.drain(..2);
            let seq = parse_event(&frame).unwrap_or_else(|e| {
                panic!("event {next} invalid ({e})");
            });
            assert_eq!(seq, next, "event out of order or duplicated");
            next += 1;
        }
    }
    ReadOut {
        events: next,
        stall,
        end,
        carriers_at_cut,
        cut,
    }
}

async fn drive(sock: TcpStream, proxy: Proxy, deadline: Duration) -> ReadOut {
    let mut sock = sock;
    sock.write_all(b"GET /v1/chat HTTP/1.1\r\nHost: echo.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    // Half-close the upload. The download, and a resumed one, keep going.
    sock.shutdown().await.unwrap();
    read_sse(sock, proxy, deadline).await
}

async fn session_case(engine: Arc<dyn Dialer>, label: &str) {
    let sample = event(0);
    assert_eq!(parse_event(&sample[..EVENT_LEN - 2]).unwrap(), 0);

    let origin = serve_origin().await;
    let env = relay_env();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let (stop, stop_rx) = watch::channel(false);
    let relay = env.relay.clone();
    tokio::spawn(async move {
        serve_relay(relay, relay_listener, stop_rx).await;
    });
    let proxy = Proxy::start(relay_addr).await;
    let dialer = session_dialer(engine, proxy.addr, ticket(&env));
    let socks = spawn_socks(dialer, "ov").await;
    let app = socks_connect(socks, "echo.test", origin.port()).await;
    let out = drive(app, proxy.clone(), Duration::from_secs(40)).await;
    let cut_fired = out.cut.is_some();
    if let Some(task) = out.cut {
        task.await.expect("cut task");
    }
    let carriers = proxy.carriers.load(Ordering::SeqCst);
    let stall_ms = out.stall.as_millis();
    println!(
        "roaming_e2e {label} events={} stall_ms={stall_ms} carriers={carriers}",
        out.events
    );
    let end = out.end.as_ref().map(|_| ()).map_err(|e| e.to_string());
    assert_eq!(end, Ok(()), "app connection did not end cleanly");
    assert_eq!(out.events, EVENTS, "missing or extra events");
    assert!(cut_fired, "stream ended before 40%");
    assert!(
        carriers > out.carriers_at_cut,
        "no new carrier after the cut (before {}, after {carriers})",
        out.carriers_at_cut
    );
    assert!(
        out.stall < STALL_LIMIT,
        "stall {:?} is not under 5s",
        out.stall
    );
    assert!(
        out.stall >= Duration::from_millis(1_000),
        "stall {:?} never showed the 1.5s refuse window",
        out.stall
    );
    let _ = stop.send(true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_stream_survives_carrier_cut() {
    session_case(Arc::new(PlainCarrier), "tcp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_stream_survives_carrier_cut_via_freedom() {
    session_case(freedom_carrier(), "freedom").await;
}

/// Same origin, same cut, no session: the app's TCP is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_path_breaks_on_the_same_cut() {
    let origin = serve_origin().await;
    let proxy = Proxy::start(origin).await;
    let dialer = Arc::new(DirectViaProxy { proxy: proxy.addr });
    let socks = spawn_socks(dialer, "cut").await;
    let app = socks_connect(socks, "echo.test", origin.port()).await;
    let out = drive(app, proxy.clone(), Duration::from_secs(20)).await;
    if let Some(task) = out.cut {
        task.await.expect("cut task");
    }
    let carriers = proxy.carriers.load(Ordering::SeqCst);
    let stall_ms = out.stall.as_millis();
    let broken = out.end.is_err() || out.events < EVENTS;
    println!(
        "roaming_e2e direct events={} stall_ms={stall_ms} carriers={carriers} broken={broken}",
        out.events
    );
    assert!(
        out.events >= CUT_AT,
        "cut fired before 40% of the stream ({})",
        out.events
    );
    assert!(
        out.events < EVENTS,
        "direct path delivered the whole stream across the cut"
    );
    assert!(
        out.end.is_err(),
        "direct app connection ended cleanly ({:?}) instead of breaking",
        out.end
    );
}
