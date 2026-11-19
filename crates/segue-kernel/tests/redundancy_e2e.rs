//! Stage 0 token-stream baseline (session redundancy plan §6–§7).
//!
//! ```text
//! app TCP ──SOCKS── kernel session ──impair (tcp-loss emulate)── relay ── origin
//! ```
//!
//! The origin writes one 30-byte event every 20 ms. The impair relay is the
//! carrier: TCP loss is recovery emulation, not a dropped byte. Ignored by
//! default; `scripts/bench/session-redundancy.sh` runs it.
//!
//! `conversation_baseline` is the second scenario: one app connection, several
//! upload / silence / token turns, plus optional impair faults. Runs that do
//! not survive are reported. Only `rtt170` with no fault is asserted.
//!
//! Move reasons (`stall`, `hold`, `relay_stall`, `closed`, `io`, `reject`,
//! `attach`) are the kernel dialer's sums for that run, plus `resumes`,
//! `replay_bytes` and `recover_max_ms`.
//!
//! `SEGUE_EXIT_CLASS=ai|overseas` (default `ai`) picks the route, the ticket
//! class and, for `ai`, a pinned exit plus a loopback home SOCKS line.
//! `SEGUE_STANDBY=0|1` (default 1, the product default) is the standby
//! switch. Both are columns. An overseas route never dials a standby.
//! `SEGUE_CONVO_FAULTS=none|blackout|all` (default `all`) limits the
//! conversation faults. `none` is the no-fault rows only. `blackout` adds
//! the 2 s / 8 s / 40 s / 120 s blackouts on `rtt170`.
//! `SEGUE_PROFILES` and `SEGUE_SEEDS` (comma-separated, or `all`) restrict
//! which rows run. Unset runs every profile and seed.
//!
//! Relay, ticket and SOCKS wiring matches `roaming_e2e.rs`. An AI route also
//! needs a home line: the relay sends a confirmed AI target there, not direct.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use segue_bench::impair::{self, TcpLoss};
use segue_kernel::dial::{DialError, Dialer, Stream};
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
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};

const EVENT_LEN: usize = 30;
const EVENT_EVERY: Duration = Duration::from_millis(20);
const PROFILES: &[&str] = &["clean", "rtt170", "cn163-offpeak", "cn163-peak"];
const SEEDS: [u64; 3] = [1, 2, 3];
const NEW_FLOWS: usize = 20;
const REQUEST: &[u8] = b"GET /events\n";
const PING: &[u8] = b"PING\n";
const PONG: &[u8] = b"pongpong";

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Product default is on. `SEGUE_STANDBY=0` turns the AI standby off.
fn standby_enabled() -> bool {
    match std::env::var("SEGUE_STANDBY") {
        Err(_) => true,
        Ok(v) if v == "1" => true,
        Ok(v) if v == "0" => false,
        Ok(v) => panic!("SEGUE_STANDBY={v} is not 0 or 1"),
    }
}

/// `SEGUE_EXIT_CLASS=ai|overseas`. Default is `ai`.
fn exit_is_ai() -> bool {
    match std::env::var("SEGUE_EXIT_CLASS") {
        Err(_) => true,
        Ok(v) if v == "ai" => true,
        Ok(v) if v == "overseas" => false,
        Ok(v) => panic!("SEGUE_EXIT_CLASS={v} is not ai or overseas"),
    }
}

fn class_name() -> &'static str {
    if exit_is_ai() {
        "ai"
    } else {
        "overseas"
    }
}

fn route_tag() -> &'static str {
    if exit_is_ai() {
        "ai"
    } else {
        "ov"
    }
}

fn token_seconds() -> u64 {
    match std::env::var("SEGUE_TOKEN_SECONDS") {
        Ok(raw) => {
            let n: u64 = raw
                .parse()
                .unwrap_or_else(|_| panic!("SEGUE_TOKEN_SECONDS={raw} is not an integer"));
            assert!(n > 0, "SEGUE_TOKEN_SECONDS must be > 0");
            n
        }
        Err(_) => 30,
    }
}

fn event_count(seconds: u64) -> u64 {
    seconds.saturating_mul(1_000) / EVENT_EVERY.as_millis() as u64
}

fn encode_event(index: u64, send_us: u64) -> [u8; EVENT_LEN] {
    let mut out = [0u8; EVENT_LEN];
    out[..8].copy_from_slice(&index.to_le_bytes());
    out[8..16].copy_from_slice(&send_us.to_le_bytes());
    out
}

fn decode_event(buf: &[u8]) -> (u64, u64) {
    let mut index = [0u8; 8];
    let mut send = [0u8; 8];
    index.copy_from_slice(&buf[..8]);
    send.copy_from_slice(&buf[8..16]);
    (u64::from_le_bytes(index), u64::from_le_bytes(send))
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
        "segue-token-{}-{tag}-{}",
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

fn relay_env(home: Option<SocketAddr>) -> RelayEnv {
    let dir = tempdir("relay");
    let signer = Signer::from_pkcs8(3, &generate_pkcs8()).unwrap();
    let pk = base64::engine::general_purpose::STANDARD.encode(signer.public_key());
    let (policy_key, policy_pub) = segue_policy::generate_key();
    // An AI-classified name is sent Home even when the client hint is
    // overseas, so the overseas runs keep echo.test off the list.
    let ai_domain = if exit_is_ai() { "echo.test" } else { "ai.test" };
    let body = json!({
        "version": 1,
        "expires_at": now_unix() + 3600,
        "ai_domains": [ai_domain],
        "ai_cidrs": [],
        "default": {"type": "proxy", "outbound": "overseas"}
    });
    let bundle = segue_policy::sign(&policy_key, 1, body.to_string().as_bytes()).unwrap();
    std::fs::write(dir.0.join("policy.bundle"), bundle).unwrap();
    let home_lines = match home {
        Some(addr) => {
            format!(r#""home_lines": [{{"id": "L1", "server": "{addr}", "isp": "lab"}}],"#,)
        }
        None => String::new(),
    };
    let json = format!(
        r#"{{
            "listen": "127.0.0.1:1",
            "node_id": 1,
            "ticket_keys": [{{"key_id": 3, "public_key": "{pk}"}}],
            {home_lines}
            "policy": {{
                "public_keys": [{{"key_id": 1, "public_key": "{policy_pub}"}}],
                "bundle": "policy.bundle"
            }}
        }}"#
    );
    let cfg = Config::parse_in(&json, &dir.0).unwrap();
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
        exit_classes: vec![if exit_is_ai() {
            ExitClass::Ai
        } else {
            ExitClass::Overseas
        }],
        ai_anchor_node_id: 0,
        not_before: t.saturating_sub(60),
        not_after: t + 7_200,
    })
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

/// No-auth SOCKS5. The relay's home dial CONNECTs an IPv4 target through it.
async fn spawn_home_socks() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = home_socks_one(&mut sock).await;
            });
        }
    });
    addr
}

async fn home_socks_one(sock: &mut TcpStream) -> io::Result<()> {
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet[0] != 5 {
        return Err(io::Error::other("not socks5"));
    }
    let mut methods = vec![0u8; greet[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[5, 0xff]).await?;
        return Err(io::Error::other("no no-auth method"));
    }
    sock.write_all(&[5, 0]).await?;
    let mut req = [0u8; 4];
    if sock.read_exact(&mut req).await.is_err() {
        return Ok(());
    }
    if req[0] != 5 || req[1] != 1 || req[3] != 1 {
        let _ = sock.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Err(io::Error::other("unsupported connect"));
    }
    let mut raw = [0u8; 6];
    sock.read_exact(&mut raw).await?;
    let target = SocketAddr::from((
        [raw[0], raw[1], raw[2], raw[3]],
        u16::from_be_bytes([raw[4], raw[5]]),
    ));
    match TcpStream::connect(target).await {
        Ok(mut upstream) => {
            let _ = upstream.set_nodelay(true);
            sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            let _ = tokio::io::copy_bidirectional(sock, &mut upstream).await;
            Ok(())
        }
        Err(_) => {
            let _ = sock.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            Err(io::Error::other("connect failed"))
        }
    }
}

fn session_dialer(
    engine: Arc<dyn Dialer>,
    proxy: SocketAddr,
    ticket: Vec<u8>,
) -> Arc<KernelDialer> {
    let class = if exit_is_ai() {
        segue_kernel::session::EXIT_AI
    } else {
        segue_kernel::session::EXIT_OVERSEAS
    };
    let tag = route_tag();
    let mut routes = BTreeMap::new();
    routes.insert(
        tag.into(),
        SegueRoute {
            ticket,
            exit_class: class,
        },
    );
    let mut home = BTreeSet::new();
    if exit_is_ai() {
        home.insert(tag.to_string());
    }
    let dialer = KernelDialer::new(
        engine,
        vec![Exit {
            name: "exit".into(),
            carrier: "tcp".into(),
            relay: proxy,
            node_id: 1,
            egress_group: String::new(),
        }],
        routes,
        home,
    )
    .with_pool(Pool::new(8 << 20))
    .with_standby_ai(standby_enabled());
    if exit_is_ai() {
        // Named choice: the AI session stays on this exit.
        dialer.set_exit("exit").expect("pin the only exit");
    }
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

/// Local origin. `PING` gets 8 bytes back; a `turn` line is one conversation
/// upload; anything else is a token stream.
async fn serve_origin(seconds: u64) -> SocketAddr {
    serve_origin_with(seconds, None).await
}

async fn serve_origin_with(seconds: u64, waiters: Option<Arc<BodyWaiters>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let waiters = waiters.clone();
            tokio::spawn(async move {
                handle_origin(sock, seconds, waiters).await;
            });
        }
    });
    addr
}

async fn handle_origin(mut sock: TcpStream, seconds: u64, waiters: Option<Arc<BodyWaiters>>) {
    let _ = sock.set_nodelay(true);
    let mut buf = Vec::new();
    if !read_request_prefix(&mut sock, &mut buf).await {
        return;
    }
    if turn_spec(&buf).is_some() {
        convo_session(&mut sock, &mut buf, waiters.as_deref()).await;
        return;
    }
    if buf.starts_with(b"PING") {
        if sock.write_all(PONG).await.is_err() {
            return;
        }
        let _ = sock.shutdown().await;
        return;
    }
    let n_events = event_count(seconds);
    let start = tokio::time::Instant::now();
    for i in 0..n_events {
        let target = start + EVENT_EVERY * u32::try_from(i).unwrap_or(u32::MAX);
        tokio::time::sleep_until(target).await;
        let send_us = u64::try_from(epoch().elapsed().as_micros()).unwrap_or(u64::MAX);
        if sock.write_all(&encode_event(i, send_us)).await.is_err() {
            return;
        }
    }
    let _ = sock.shutdown().await;
}

/// FNV-1a 64 of an upload. Event 0 carries it in bytes 16..24 so the app can
/// check the origin got those exact bytes.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    fnv_feed(&mut hash, bytes);
    hash
}

fn fnv_feed(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x100000001b3);
    }
}

struct OriginBody {
    checksum: u64,
    at: Instant,
}

/// One in-process queue of "the origin has the upload" notices. Each
/// conversation run has its own queue, so a late body cannot complete the
/// next run.
struct BodyWaiters {
    queue: Mutex<VecDeque<oneshot::Sender<OriginBody>>>,
}

impl BodyWaiters {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    fn register(&self) -> oneshot::Receiver<OriginBody> {
        let (tx, rx) = oneshot::channel();
        self.queue.lock().unwrap().push_back(tx);
        rx
    }

    /// Drop waiters whose receiver is already gone (the app gave up).
    fn abandon(&self) {
        self.queue.lock().unwrap().retain(|tx| !tx.is_closed());
    }

    fn complete(&self, body: OriginBody) {
        if let Some(tx) = self.queue.lock().unwrap().pop_front() {
            let _ = tx.send(body);
        }
    }
}

/// Same read the token origin used to do: stop at the first newline, or give
/// up past 1024 bytes with no newline. A buffer that already holds a newline
/// (leftover from the previous turn) is ready.
async fn read_request_prefix(sock: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    if buf.contains(&b'\n') {
        return true;
    }
    let mut tmp = [0u8; 256];
    loop {
        let n = match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.contains(&b'\n') {
            return true;
        }
        if buf.len() > 1024 {
            return false;
        }
    }
}

/// `turn <upload> <silence_ms> <tokens>` and the index where the body starts.
fn turn_spec(buf: &[u8]) -> Option<(u64, u64, u64, usize)> {
    let nl = buf.iter().position(|b| *b == b'\n')?;
    let mut line = &buf[..nl];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    if parts.next() != Some("turn") {
        return None;
    }
    let upload = parts.next()?.parse().ok()?;
    let silence_ms = parts.next()?.parse().ok()?;
    let tokens = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((upload, silence_ms, tokens, nl + 1))
}

async fn read_body(
    sock: &mut TcpStream,
    buf: &mut Vec<u8>,
    body_at: usize,
    need: usize,
) -> io::Result<Vec<u8>> {
    let mut body = buf.split_off(body_at);
    buf.clear();
    if body.len() > need {
        let extra = body.split_off(need);
        buf.extend_from_slice(&extra);
    }
    while body.len() < need {
        let mut tmp = [0u8; 16 * 1024];
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "eof during upload",
            ));
        }
        let take = n.min(need - body.len());
        body.extend_from_slice(&tmp[..take]);
        if take < n {
            buf.extend_from_slice(&tmp[take..n]);
        }
    }
    Ok(body)
}

/// Several `turn` requests on one connection. After each body the origin waits
/// `silence_ms`, then writes `tokens` events. Event 0 carries the body checksum.
async fn convo_session(sock: &mut TcpStream, buf: &mut Vec<u8>, waiters: Option<&BodyWaiters>) {
    const MAX_UPLOAD: u64 = 64 * 1024 * 1024;
    loop {
        let Some((upload, silence_ms, tokens, body_at)) = turn_spec(buf) else {
            return;
        };
        if upload > MAX_UPLOAD {
            return;
        }
        let body = match read_body(sock, buf, body_at, upload as usize).await {
            Ok(body) => body,
            Err(_) => return,
        };
        let checksum = fnv1a(&body);
        if let Some(waiters) = waiters {
            waiters.complete(OriginBody {
                checksum,
                at: Instant::now(),
            });
        }
        tokio::time::sleep(Duration::from_millis(silence_ms)).await;
        let start = tokio::time::Instant::now();
        for i in 0..tokens {
            let target = start + EVENT_EVERY * u32::try_from(i).unwrap_or(u32::MAX);
            tokio::time::sleep_until(target).await;
            let send_us = u64::try_from(epoch().elapsed().as_micros()).unwrap_or(u64::MAX);
            let mut event = encode_event(i, send_us);
            if i == 0 {
                event[16..24].copy_from_slice(&checksum.to_le_bytes());
            }
            if sock.write_all(&event).await.is_err() {
                return;
            }
        }
        if !read_request_prefix(sock, buf).await {
            return;
        }
    }
}

struct Stack {
    origin: SocketAddr,
    relay_addr: SocketAddr,
    ticket: Vec<u8>,
    _stop: watch::Sender<bool>,
    _env: RelayEnv,
}

async fn stack() -> Stack {
    let seconds = token_seconds();
    let origin = serve_origin(seconds).await;
    let home = if exit_is_ai() {
        Some(spawn_home_socks().await)
    } else {
        None
    };
    let env = relay_env(home);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let (stop, stop_rx) = watch::channel(false);
    let relay = env.relay.clone();
    tokio::spawn(async move {
        serve_relay(relay, listener, stop_rx).await;
    });
    let ticket = ticket(&env);
    Stack {
        origin,
        relay_addr,
        ticket,
        _stop: stop,
        _env: env,
    }
}

/// Nearest rank: index `ceil(p * n) - 1` on the sorted sample.
fn percentile(samples: &mut [f64], p: f64) -> f64 {
    assert!(!samples.is_empty());
    samples.sort_by(|a, b| a.total_cmp(b));
    let n = samples.len();
    let rank = (p * n as f64).ceil() as usize;
    samples[rank.saturating_sub(1).min(n - 1)]
}

fn round3(ms: f64) -> f64 {
    (ms * 1000.0).round() / 1000.0
}

fn us_to_ms(us: u128) -> f64 {
    round3(us as f64 / 1000.0)
}

struct TokenRow {
    profile: &'static str,
    seed: u64,
    ttft_ms: f64,
    delay_p50_ms: f64,
    delay_p99_ms: f64,
    delay_p999_ms: f64,
    delay_max_ms: f64,
    ia_p50_ms: f64,
    ia_p99_ms: f64,
    ia_p999_ms: f64,
    stalls_300: u64,
    stalls_1s: u64,
    up_bytes: u64,
    down_bytes: u64,
    payload_bytes: u64,
}

struct FlowRow {
    profile: &'static str,
    seed: u64,
    ttfb_p50_ms: f64,
    ttfb_p99_ms: f64,
    ttfb_max_ms: f64,
}

async fn open_path(stack: &Stack, profile_name: &str, seed: u64) -> (SocketAddr, impair::TcpRelay) {
    let profile = impair::profile(profile_name).expect("profile");
    let impair = impair::serve_tcp(
        "127.0.0.1:0".parse().unwrap(),
        stack.relay_addr,
        profile,
        seed,
        TcpLoss::Emulate,
    )
    .await
    .expect("impair relay");
    let dialer = session_dialer(Arc::new(PlainCarrier), impair.local, stack.ticket.clone());
    let socks = spawn_socks(dialer, route_tag()).await;
    (socks, impair)
}

async fn run_token(stack: &Stack, profile: &'static str, seed: u64, seconds: u64) -> TokenRow {
    println!("run token {profile} seed {seed}");
    let (socks, impair) = open_path(stack, profile, seed).await;
    let n = event_count(seconds);
    let connect_start = Instant::now();
    let mut sock = socks_connect(socks, "echo.test", stack.origin.port()).await;
    sock.write_all(REQUEST).await.expect("token request");
    let mut delays = Vec::with_capacity(n as usize);
    let mut arrivals = Vec::with_capacity(n as usize);
    let deadline = connect_start + Duration::from_secs(seconds.saturating_add(120));
    let mut buf = [0u8; EVENT_LEN];
    for i in 0..n {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            panic!("{profile} seed {seed}: deadline after {i} of {n} events");
        }
        let read = tokio::time::timeout(left, sock.read_exact(&mut buf)).await;
        match read {
            Err(_) => panic!("{profile} seed {seed}: timeout after {i} of {n} events"),
            Ok(Err(e)) => panic!("{profile} seed {seed}: read after {i} of {n} events: {e}"),
            Ok(Ok(_)) => {}
        }
        let arrival = Instant::now();
        let (index, send_us) = decode_event(&buf);
        assert_eq!(index, i, "{profile} seed {seed}: event out of order");
        let delay = epoch()
            .elapsed()
            .saturating_sub(Duration::from_micros(send_us));
        delays.push(us_to_ms(delay.as_micros()));
        arrivals.push(arrival);
    }
    drop(sock);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let up_bytes = impair.up_bytes();
    let down_bytes = impair.down_bytes();
    drop(impair);

    let ttft_ms = round3(
        arrivals[0]
            .saturating_duration_since(connect_start)
            .as_secs_f64()
            * 1000.0,
    );
    let mut gaps = Vec::with_capacity(arrivals.len().saturating_sub(1));
    let mut stalls_300 = 0u64;
    let mut stalls_1s = 0u64;
    for pair in arrivals.windows(2) {
        let gap_ms = round3(pair[1].saturating_duration_since(pair[0]).as_secs_f64() * 1000.0);
        if gap_ms > 300.0 {
            stalls_300 += 1;
        }
        if gap_ms > 1000.0 {
            stalls_1s += 1;
        }
        gaps.push(gap_ms);
    }
    let delay_max_ms = delays.iter().copied().fold(0.0_f64, f64::max);
    TokenRow {
        profile,
        seed,
        ttft_ms,
        delay_p50_ms: percentile(&mut delays.clone(), 0.50),
        delay_p99_ms: percentile(&mut delays.clone(), 0.99),
        delay_p999_ms: percentile(&mut delays.clone(), 0.999),
        delay_max_ms: round3(delay_max_ms),
        ia_p50_ms: percentile(&mut gaps.clone(), 0.50),
        ia_p99_ms: percentile(&mut gaps.clone(), 0.99),
        ia_p999_ms: percentile(&mut gaps, 0.999),
        stalls_300,
        stalls_1s,
        up_bytes,
        down_bytes,
        payload_bytes: REQUEST.len() as u64 + n * EVENT_LEN as u64,
    }
}

async fn run_flows(stack: &Stack, profile: &'static str, seed: u64) -> FlowRow {
    println!("run flows {profile} seed {seed}");
    let (socks, impair) = open_path(stack, profile, seed).await;
    let mut samples = Vec::with_capacity(NEW_FLOWS);
    for i in 0..NEW_FLOWS {
        let t0 = Instant::now();
        let mut sock = socks_connect(socks, "echo.test", stack.origin.port()).await;
        sock.write_all(PING).await.expect("ping request");
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(45), sock.read_exact(&mut buf)).await;
        match read {
            Err(_) => panic!("{profile} seed {seed}: new flow {i} timed out"),
            Ok(Err(e)) => panic!("{profile} seed {seed}: new flow {i}: {e}"),
            Ok(Ok(_)) => {}
        }
        assert_eq!(&buf, PONG, "{profile} seed {seed}: bad pong");
        samples.push(round3(t0.elapsed().as_secs_f64() * 1000.0));
        drop(sock);
    }
    drop(impair);
    let ttfb_max_ms = samples.iter().copied().fold(0.0_f64, f64::max);
    FlowRow {
        profile,
        seed,
        ttfb_p50_ms: percentile(&mut samples.clone(), 0.50),
        ttfb_p99_ms: percentile(&mut samples.clone(), 0.99),
        ttfb_max_ms: round3(ttfb_max_ms),
    }
}

fn print_token_table(rows: &[TokenRow]) {
    let mode = u8::from(standby_enabled());
    let class = class_name();
    println!("## token stream");
    println!(
        "| class | standby | profile | seed | ttft_ms | delay_p50_ms | delay_p99_ms | delay_p99.9_ms | delay_max_ms | ia_p50_ms | ia_p99_ms | ia_p99.9_ms | stalls_300 | stalls_1s | up_bytes | down_bytes | payload_bytes |"
    );
    println!(
        "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    );
    for r in rows {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            class,
            mode,
            r.profile,
            r.seed,
            r.ttft_ms,
            r.delay_p50_ms,
            r.delay_p99_ms,
            r.delay_p999_ms,
            r.delay_max_ms,
            r.ia_p50_ms,
            r.ia_p99_ms,
            r.ia_p999_ms,
            r.stalls_300,
            r.stalls_1s,
            r.up_bytes,
            r.down_bytes,
            r.payload_bytes
        );
    }
}

fn print_flow_table(rows: &[FlowRow]) {
    let mode = u8::from(standby_enabled());
    let class = class_name();
    println!("## new flows");
    println!("| class | standby | profile | seed | ttfb_p50_ms | ttfb_p99_ms | ttfb_max_ms |");
    println!("|---|---:|---|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            class, mode, r.profile, r.seed, r.ttfb_p50_ms, r.ttfb_p99_ms, r.ttfb_max_ms
        );
    }
}

fn token_json(row: &TokenRow) -> Value {
    json!({
        "class": class_name(),
        "standby": u8::from(standby_enabled()),
        "profile": row.profile,
        "seed": row.seed,
        "ttft_ms": row.ttft_ms,
        "delay_p50_ms": row.delay_p50_ms,
        "delay_p99_ms": row.delay_p99_ms,
        "delay_p99_9_ms": row.delay_p999_ms,
        "delay_max_ms": row.delay_max_ms,
        "ia_p50_ms": row.ia_p50_ms,
        "ia_p99_ms": row.ia_p99_ms,
        "ia_p99_9_ms": row.ia_p999_ms,
        "stalls_300": row.stalls_300,
        "stalls_1s": row.stalls_1s,
        "up_bytes": row.up_bytes,
        "down_bytes": row.down_bytes,
        "payload_bytes": row.payload_bytes,
    })
}

fn flow_json(row: &FlowRow) -> Value {
    json!({
        "class": class_name(),
        "standby": u8::from(standby_enabled()),
        "profile": row.profile,
        "seed": row.seed,
        "ttfb_p50_ms": row.ttfb_p50_ms,
        "ttfb_p99_ms": row.ttfb_p99_ms,
        "ttfb_max_ms": row.ttfb_max_ms,
    })
}

fn write_json(seconds: u64, tokens: &[TokenRow], flows: &[FlowRow]) {
    let Some(path) = std::env::var_os("SEGUE_BENCH_OUT") else {
        return;
    };
    let body = json!({
        "token_seconds": seconds,
        "percentile": "ceil(p * n) - 1",
        "note": "no carrier re-attach column; SessionHealth is not observable without changing the kernel",
        "token_stream": tokens.iter().map(token_json).collect::<Vec<_>>(),
        "new_flows": flows.iter().map(flow_json).collect::<Vec<_>>(),
    });
    let text = serde_json::to_string_pretty(&body).unwrap();
    std::fs::write(&path, text)
        .unwrap_or_else(|e| panic!("writing {}: {e}", path.to_string_lossy()));
}

fn assert_sane(tokens: &[TokenRow]) {
    for row in tokens {
        if row.profile == "clean" {
            assert_eq!(
                row.stalls_300, 0,
                "clean seed {} stalled {} times over 300 ms",
                row.seed, row.stalls_300
            );
            assert!(
                row.delay_p99_ms < 20.0,
                "clean seed {} token delay p99 {} ms is not under 20 ms",
                row.seed,
                row.delay_p99_ms
            );
        }
        if row.profile == "rtt170" {
            let off = (row.delay_p50_ms - 85.0).abs();
            assert!(
                off <= 15.0,
                "rtt170 seed {} token delay p50 {} ms is outside 85 ± 15",
                row.seed,
                row.delay_p50_ms
            );
        }
        if row.profile == "cn163-peak" {
            assert!(
                row.stalls_300 >= 1,
                "cn163-peak seed {} had no stall over 300 ms",
                row.seed
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stage 0 token baseline; run via scripts/bench/session-redundancy.sh"]
async fn token_stream_baseline() {
    let seconds = token_seconds();
    let stack = stack().await;
    let mut tokens = Vec::new();
    let mut flows = Vec::new();
    for profile in selected_profiles(PROFILES) {
        for seed in selected_seeds() {
            tokens.push(run_token(&stack, profile, seed, seconds).await);
            flows.push(run_flows(&stack, profile, seed).await);
        }
    }
    print_token_table(&tokens);
    println!();
    println!(
        "stalls_300 counts inter-arrival gaps over 300 ms; stalls_1s counts gaps over 1 s (a gap over 1 s is in both)."
    );
    println!(
        "No carrier re-attach column: SessionHealth is not observable without changing the kernel."
    );
    println!();
    print_flow_table(&flows);
    write_json(seconds, &tokens, &flows);
    assert_sane(&tokens);
}

const CONVO_PROFILES: &[&str] = &["rtt170", "cn163-offpeak", "cn163-peak"];
const UPLOAD_BUDGET: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConvoFault {
    None,
    BlackoutUpload2s,
    BlackoutTokens8s,
    BlackoutTokens40s,
    BlackoutTokens120s,
    ResetUpload,
    ResetTokens,
    SilentSilence,
}

fn fault_name(fault: ConvoFault) -> &'static str {
    match fault {
        ConvoFault::None => "none",
        ConvoFault::BlackoutUpload2s => "blackout-upload-2s",
        ConvoFault::BlackoutTokens8s => "blackout-tokens-8s",
        ConvoFault::BlackoutTokens40s => "blackout-tokens-40s",
        ConvoFault::BlackoutTokens120s => "blackout-tokens-120s",
        ConvoFault::ResetUpload => "reset-upload",
        ConvoFault::ResetTokens => "reset-tokens",
        ConvoFault::SilentSilence => "silent-silence",
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|_| panic!("{name}={raw} is not an integer")),
        Err(_) => default,
    }
}

fn selected_profiles<'a>(all: &'a [&'a str]) -> Vec<&'a str> {
    let Ok(raw) = std::env::var("SEGUE_PROFILES") else {
        return all.to_vec();
    };
    if raw.is_empty() || raw == "all" {
        return all.to_vec();
    }
    let mut out = Vec::new();
    for name in raw.split(',') {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        match all.iter().copied().find(|profile| *profile == name) {
            Some(profile) => out.push(profile),
            None => panic!("SEGUE_PROFILES={name} is not one of {all:?}"),
        }
    }
    assert!(!out.is_empty(), "SEGUE_PROFILES is empty");
    out
}

fn selected_seeds() -> Vec<u64> {
    let Ok(raw) = std::env::var("SEGUE_SEEDS") else {
        return SEEDS.to_vec();
    };
    if raw.is_empty() || raw == "all" {
        return SEEDS.to_vec();
    }
    let mut seeds = Vec::new();
    for raw in raw.split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let seed = raw
            .parse()
            .unwrap_or_else(|_| panic!("SEGUE_SEEDS={raw} is not an integer"));
        assert!(
            SEEDS.contains(&seed),
            "SEGUE_SEEDS={seed} is not one of {SEEDS:?}"
        );
        seeds.push(seed);
    }
    assert!(!seeds.is_empty(), "SEGUE_SEEDS is empty");
    seeds
}

fn convo_turns() -> u64 {
    let n = env_u64("SEGUE_CONVO_TURNS", 3);
    assert!(n > 0, "SEGUE_CONVO_TURNS must be > 0");
    n
}

fn convo_upload() -> u64 {
    env_u64("SEGUE_CONVO_UPLOAD", 1024 * 1024)
}

fn convo_silence_ms() -> u64 {
    env_u64("SEGUE_CONVO_SILENCE_MS", 5_000)
}

fn convo_tokens() -> u64 {
    let n = env_u64("SEGUE_CONVO_TOKENS", 500);
    assert!(n > 0, "SEGUE_CONVO_TOKENS must be > 0");
    n
}

/// `SEGUE_CONVO_FAULTS`: `all` (default) keeps every fault, `none` is the
/// no-fault rows, `blackout` adds only the timed blackouts on `rtt170`.
fn convo_fault_set() -> &'static str {
    match std::env::var("SEGUE_CONVO_FAULTS") {
        Ok(raw) => match raw.as_str() {
            "none" | "0" => "none",
            "blackout" => "blackout",
            "all" | "" => "all",
            other => panic!("SEGUE_CONVO_FAULTS={other} is not none, blackout or all"),
        },
        Err(_) => "all",
    }
}

fn convo_cases() -> Vec<(&'static str, u64, ConvoFault)> {
    let mut cases = Vec::new();
    let seeds = selected_seeds();
    for profile in selected_profiles(CONVO_PROFILES) {
        for seed in &seeds {
            cases.push((profile, *seed, ConvoFault::None));
        }
    }
    let faults: &[ConvoFault] = match convo_fault_set() {
        "none" => &[],
        "blackout" => &[
            ConvoFault::BlackoutUpload2s,
            ConvoFault::BlackoutTokens8s,
            ConvoFault::BlackoutTokens40s,
            ConvoFault::BlackoutTokens120s,
        ],
        _ => &[
            ConvoFault::BlackoutUpload2s,
            ConvoFault::BlackoutTokens8s,
            ConvoFault::BlackoutTokens40s,
            ConvoFault::BlackoutTokens120s,
            ConvoFault::ResetUpload,
            ConvoFault::ResetTokens,
            ConvoFault::SilentSilence,
        ],
    };
    if selected_profiles(CONVO_PROFILES).contains(&"rtt170") {
        for fault in faults {
            for seed in &seeds {
                cases.push(("rtt170", *seed, *fault));
            }
        }
    }
    cases
}

struct DialCounts {
    dials: AtomicUsize,
    control: AtomicUsize,
    session: AtomicUsize,
}

struct CountingDialer {
    counts: Arc<DialCounts>,
}

struct Classified {
    inner: TcpStream,
    counts: Arc<DialCounts>,
    seen: bool,
}

impl Classified {
    fn note(&mut self, bytes: &[u8]) {
        if self.seen || bytes.is_empty() {
            return;
        }
        self.seen = true;
        if bytes[0] == segue_session::codec::ty::CTRL_HELLO {
            self.counts.control.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counts.session.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AsyncRead for Classified {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Classified {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.note(bytes);
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl segue_transport::TransportStream for Classified {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

#[async_trait]
impl Dialer for CountingDialer {
    async fn dial(
        &self,
        _tag: Option<&str>,
        addr: &segue_routing::TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        self.counts.dials.fetch_add(1, Ordering::Relaxed);
        let ip = match addr {
            segue_routing::TargetAddr::Ip(ip) => *ip,
            segue_routing::TargetAddr::Domain(domain) => {
                return Err(DialError(format!("carrier dial wants an ip, got {domain}")));
            }
        };
        let stream = TcpStream::connect(SocketAddr::new(ip, port))
            .await
            .map_err(|err| DialError(err.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(Box::new(Classified {
            inner: stream,
            counts: Arc::clone(&self.counts),
            seen: false,
        }))
    }
}

struct TurnEnd {
    turn: u64,
    phase: &'static str,
    saw: String,
}

struct TurnMetrics {
    turn: u64,
    upload_ms: f64,
    ttft_after_silence_ms: f64,
    delay_p50_ms: f64,
    delay_p99_ms: f64,
    delay_max_ms: f64,
    stalls_300: u64,
    stalls_1s: u64,
    stalls_20s: u64,
    longest_gap_ms: f64,
}

struct ConvoRow {
    class: &'static str,
    standby: u8,
    profile: &'static str,
    seed: u64,
    fault: &'static str,
    survived: bool,
    end: Option<TurnEnd>,
    engine_dials: u64,
    control_streams: u64,
    session_carriers: u64,
    standby_dials: u64,
    standby_bound: u64,
    standby_promotions: u64,
    swaps: u64,
    stall: u64,
    hold: u64,
    relay_stall: u64,
    closed: u64,
    io: u64,
    reject: u64,
    attach: u64,
    resumes: u64,
    replay_bytes: u64,
    recover_max_ms: u64,
    impair_accepts: u64,
    up_bytes: u64,
    down_bytes: u64,
    payload_up: u64,
    payload_down: u64,
    turns: Vec<TurnMetrics>,
}

fn saw_io(err: &io::Error) -> String {
    match err.kind() {
        ErrorKind::UnexpectedEof => "eof".to_owned(),
        ErrorKind::ConnectionReset => format!("reset: {err}"),
        ErrorKind::BrokenPipe => format!("broken pipe: {err}"),
        ErrorKind::TimedOut => "timeout".to_owned(),
        _ => err.to_string(),
    }
}

fn cell(text: &str) -> String {
    text.replace('|', "/").replace('\n', " ")
}

fn pct_or_zero(samples: &mut [f64], p: f64) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        percentile(samples, p)
    }
}

fn token_gaps(arrivals: &[Instant]) -> (u64, u64, u64, f64) {
    let mut stalls_300 = 0u64;
    let mut stalls_1s = 0u64;
    let mut stalls_20s = 0u64;
    let mut longest = 0.0f64;
    for pair in arrivals.windows(2) {
        let gap_ms = round3(pair[1].saturating_duration_since(pair[0]).as_secs_f64() * 1000.0);
        if gap_ms > 300.0 {
            stalls_300 += 1;
        }
        if gap_ms > 1000.0 {
            stalls_1s += 1;
        }
        if gap_ms > 20_000.0 {
            stalls_20s += 1;
        }
        if gap_ms > longest {
            longest = gap_ms;
        }
    }
    (stalls_300, stalls_1s, stalls_20s, longest)
}

fn fill_body(turn: u64, offset: usize, out: &mut [u8]) {
    for (index, byte) in out.iter_mut().enumerate() {
        let n = (offset + index) as u64;
        *byte = n.wrapping_mul(131).wrapping_add(turn) as u8;
    }
}

fn arm_upload(fault: ConvoFault, turn: u64, impair: &impair::TcpRelay) {
    if turn != 2 {
        return;
    }
    match fault {
        ConvoFault::BlackoutUpload2s => impair.arm_blackout(Duration::from_secs(2)),
        ConvoFault::ResetUpload => impair.arm_reset(),
        _ => {}
    }
}

fn arm_silence(fault: ConvoFault, turn: u64, impair: &impair::TcpRelay) {
    if turn == 2 && fault == ConvoFault::SilentSilence {
        impair.arm_silent_drop();
    }
}

fn arm_tokens(fault: ConvoFault, turn: u64, impair: &impair::TcpRelay) {
    if turn != 2 {
        return;
    }
    match fault {
        ConvoFault::BlackoutTokens8s => impair.arm_blackout(Duration::from_secs(8)),
        ConvoFault::BlackoutTokens40s => impair.arm_blackout(Duration::from_secs(40)),
        ConvoFault::BlackoutTokens120s => impair.arm_blackout(Duration::from_secs(120)),
        ConvoFault::ResetTokens => impair.arm_reset(),
        _ => {}
    }
}

fn token_pad(fault: ConvoFault, turn: u64) -> Duration {
    if turn != 2 {
        return Duration::ZERO;
    }
    match fault {
        ConvoFault::BlackoutTokens8s => Duration::from_secs(8),
        ConvoFault::BlackoutTokens40s => Duration::from_secs(40),
        ConvoFault::BlackoutTokens120s => Duration::from_secs(120),
        ConvoFault::BlackoutUpload2s => Duration::from_secs(2),
        _ => Duration::ZERO,
    }
}

async fn try_socks_connect(kernel: SocketAddr, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut conn = TcpStream::connect(kernel).await?;
    let _ = conn.set_nodelay(true);
    conn.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    conn.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(io::Error::other(format!(
            "SOCKS method {:02x}{:02x}",
            method[0], method[1]
        )));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    conn.write_all(&req).await?;
    let mut rep = [0u8; 10];
    conn.read_exact(&mut rep).await?;
    if rep[1] != REP_OK {
        return Err(io::Error::other(format!(
            "SOCKS connect refused ({})",
            rep[1]
        )));
    }
    Ok(conn)
}

async fn write_upload(
    sock: &mut TcpStream,
    turn: u64,
    upload: u64,
    silence_ms: u64,
    tokens: u64,
) -> io::Result<u64> {
    let line = format!("turn {upload} {silence_ms} {tokens}\n");
    sock.write_all(line.as_bytes()).await?;
    let mut hash = 0xcbf29ce484222325u64;
    let total = upload as usize;
    let mut offset = 0usize;
    let mut chunk = vec![0u8; 16 * 1024];
    while offset < total {
        let n = (total - offset).min(chunk.len());
        fill_body(turn, offset, &mut chunk[..n]);
        fnv_feed(&mut hash, &chunk[..n]);
        sock.write_all(&chunk[..n]).await?;
        offset += n;
    }
    Ok(hash)
}

struct TurnPlan {
    turn: u64,
    upload: u64,
    silence_ms: u64,
    tokens: u64,
    fault: ConvoFault,
}

async fn read_tokens(
    sock: &mut TcpStream,
    plan: &TurnPlan,
    body: &OriginBody,
    checksum: u64,
    impair: &impair::TcpRelay,
) -> Result<TurnMetrics, TurnEnd> {
    let silence = Duration::from_millis(plan.silence_ms);
    let deadline = Instant::now()
        + silence
        + Duration::from_millis(plan.tokens.saturating_mul(20))
        + token_pad(plan.fault, plan.turn)
        + Duration::from_secs(90);
    let mut delays = Vec::with_capacity(plan.tokens as usize);
    let mut arrivals = Vec::with_capacity(plan.tokens as usize);
    let mut armed = false;
    for index in 0..plan.tokens {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(token_end(plan.turn, "timeout"));
        }
        let mut buf = [0u8; EVENT_LEN];
        match tokio::time::timeout(left, sock.read_exact(&mut buf)).await {
            Err(_) => return Err(token_end(plan.turn, "timeout")),
            Ok(Err(err)) => return Err(token_end(plan.turn, &saw_io(&err))),
            Ok(Ok(_)) => {}
        }
        let arrival = Instant::now();
        let (got, send_us) = decode_event(&buf);
        if got != index {
            return Err(token_end(plan.turn, &format!("index {got} wanted {index}")));
        }
        if index == 0 {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[16..24]);
            let got_sum = u64::from_le_bytes(raw);
            if got_sum != checksum {
                return Err(TurnEnd {
                    turn: plan.turn,
                    phase: "checksum",
                    saw: format!("checksum {got_sum:#x} != {checksum:#x}"),
                });
            }
        }
        let delay = epoch()
            .elapsed()
            .saturating_sub(Duration::from_micros(send_us));
        delays.push(us_to_ms(delay.as_micros()));
        arrivals.push(arrival);
        if !armed {
            arm_tokens(plan.fault, plan.turn, impair);
            armed = true;
        }
    }
    Ok(metrics_from(
        plan.turn,
        0.0,
        body,
        silence,
        &mut delays,
        &arrivals,
    ))
}

fn token_end(turn: u64, saw: &str) -> TurnEnd {
    TurnEnd {
        turn,
        phase: "tokens",
        saw: saw.to_owned(),
    }
}

fn metrics_from(
    turn: u64,
    upload_ms: f64,
    body: &OriginBody,
    silence: Duration,
    delays: &mut [f64],
    arrivals: &[Instant],
) -> TurnMetrics {
    let (stalls_300, stalls_1s, stalls_20s, longest) = token_gaps(arrivals);
    let ttft = match arrivals.first() {
        Some(first) => {
            let expected = body.at + silence;
            round3(first.saturating_duration_since(expected).as_secs_f64() * 1000.0)
        }
        None => 0.0,
    };
    let delay_max = delays.iter().copied().fold(0.0_f64, f64::max);
    let p50 = pct_or_zero(delays, 0.50);
    let p99 = pct_or_zero(delays, 0.99);
    TurnMetrics {
        turn,
        upload_ms,
        ttft_after_silence_ms: ttft,
        delay_p50_ms: p50,
        delay_p99_ms: p99,
        delay_max_ms: round3(delay_max),
        stalls_300,
        stalls_1s,
        stalls_20s,
        longest_gap_ms: longest,
    }
}

fn end_upload(turn: u64, saw: String) -> TurnEnd {
    TurnEnd {
        turn,
        phase: "upload",
        saw,
    }
}

async fn one_turn(
    sock: &mut TcpStream,
    plan: &TurnPlan,
    waiters: &BodyWaiters,
    impair: &impair::TcpRelay,
) -> Result<TurnMetrics, TurnEnd> {
    let rx = waiters.register();
    arm_upload(plan.fault, plan.turn, impair);
    let sent = Instant::now();
    let wrote = tokio::time::timeout(
        UPLOAD_BUDGET,
        write_upload(sock, plan.turn, plan.upload, plan.silence_ms, plan.tokens),
    )
    .await;
    let checksum = match wrote {
        Err(_) => {
            drop(rx);
            waiters.abandon();
            return Err(end_upload(plan.turn, "timeout".to_owned()));
        }
        Ok(Err(err)) => {
            drop(rx);
            waiters.abandon();
            return Err(end_upload(plan.turn, saw_io(&err)));
        }
        Ok(Ok(checksum)) => checksum,
    };
    let body = match tokio::time::timeout(UPLOAD_BUDGET, rx).await {
        Err(_) => {
            waiters.abandon();
            return Err(end_upload(plan.turn, "timeout".to_owned()));
        }
        Ok(Err(_)) => {
            return Err(end_upload(
                plan.turn,
                "origin closed before the body arrived".to_owned(),
            ));
        }
        Ok(Ok(body)) => body,
    };
    if body.checksum != checksum {
        return Err(TurnEnd {
            turn: plan.turn,
            phase: "checksum",
            saw: format!("origin {:#x} != sent {checksum:#x}", body.checksum),
        });
    }
    let upload_ms = round3(body.at.saturating_duration_since(sent).as_secs_f64() * 1000.0);
    arm_silence(plan.fault, plan.turn, impair);
    let mut metrics = read_tokens(sock, plan, &body, checksum, impair).await?;
    metrics.upload_ms = upload_ms;
    Ok(metrics)
}

async fn open_convo(
    stack: &Stack,
    origin: SocketAddr,
    profile_name: &str,
    seed: u64,
    counts: Arc<DialCounts>,
) -> io::Result<(TcpStream, impair::TcpRelay, Arc<KernelDialer>)> {
    let profile = impair::profile(profile_name).expect("profile");
    let impair = impair::serve_tcp(
        "127.0.0.1:0".parse().unwrap(),
        stack.relay_addr,
        profile,
        seed,
        TcpLoss::Emulate,
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()))?;
    let engine = Arc::new(CountingDialer { counts });
    let dialer = session_dialer(engine, impair.local, stack.ticket.clone());
    let socks_dialer: Arc<dyn Dialer> = dialer.clone();
    let socks = spawn_socks(socks_dialer, route_tag()).await;
    let sock = tokio::time::timeout(
        Duration::from_secs(60),
        try_socks_connect(socks, "echo.test", origin.port()),
    )
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "timeout"))??;
    Ok((sock, impair, dialer))
}

fn payload_of(turns: u64, upload: u64, silence_ms: u64, tokens: u64) -> (u64, u64) {
    let line = format!("turn {upload} {silence_ms} {tokens}\n").len() as u64;
    let up = turns.saturating_mul(line.saturating_add(upload));
    let down = turns
        .saturating_mul(tokens)
        .saturating_mul(EVENT_LEN as u64);
    (up, down)
}

async fn run_convo(
    stack: &Stack,
    profile: &'static str,
    seed: u64,
    fault: ConvoFault,
    spec: (u64, u64, u64, u64),
) -> ConvoRow {
    let (n_turns, upload, silence_ms, tokens) = spec;
    let name = fault_name(fault);
    println!("run convo {profile} seed {seed} fault {name}");
    let (payload_up, payload_down) = payload_of(n_turns, upload, silence_ms, tokens);
    let counts = Arc::new(DialCounts {
        dials: AtomicUsize::new(0),
        control: AtomicUsize::new(0),
        session: AtomicUsize::new(0),
    });
    let waiters = Arc::new(BodyWaiters::new());
    let origin = serve_origin_with(1, Some(Arc::clone(&waiters))).await;
    let mut row = ConvoRow {
        class: class_name(),
        standby: u8::from(standby_enabled()),
        profile,
        seed,
        fault: name,
        survived: false,
        end: None,
        engine_dials: 0,
        control_streams: 0,
        session_carriers: 0,
        standby_dials: 0,
        standby_bound: 0,
        standby_promotions: 0,
        swaps: 0,
        stall: 0,
        hold: 0,
        relay_stall: 0,
        closed: 0,
        io: 0,
        reject: 0,
        attach: 0,
        resumes: 0,
        replay_bytes: 0,
        recover_max_ms: 0,
        impair_accepts: 0,
        up_bytes: 0,
        down_bytes: 0,
        payload_up,
        payload_down,
        turns: Vec::new(),
    };
    let opened = open_convo(stack, origin, profile, seed, Arc::clone(&counts)).await;
    let (mut sock, impair, dialer) = match opened {
        Ok(opened) => opened,
        Err(err) => {
            row.end = Some(TurnEnd {
                turn: 0,
                phase: "connect",
                saw: saw_io(&err),
            });
            return row;
        }
    };
    for turn in 1..=n_turns {
        let plan = TurnPlan {
            turn,
            upload,
            silence_ms,
            tokens,
            fault,
        };
        match one_turn(&mut sock, &plan, &waiters, &impair).await {
            Ok(metrics) => row.turns.push(metrics),
            Err(end) => {
                row.end = Some(end);
                break;
            }
        }
    }
    if row.end.is_none() && row.turns.len() as u64 == n_turns {
        row.survived = true;
    }
    drop(sock);
    tokio::time::sleep(Duration::from_millis(50)).await;
    row.engine_dials = counts.dials.load(Ordering::Relaxed) as u64;
    row.control_streams = counts.control.load(Ordering::Relaxed) as u64;
    row.session_carriers = counts.session.load(Ordering::Relaxed) as u64;
    row.standby_dials = dialer.standby_dials();
    row.standby_bound = dialer.standby_bound();
    row.standby_promotions = dialer.standby_promotions();
    row.swaps = dialer.standby_swaps();
    let moves = dialer.move_stats();
    row.stall = moves.stall;
    row.hold = moves.hold;
    row.relay_stall = moves.relay_stall;
    row.closed = moves.closed;
    row.io = moves.io;
    row.reject = moves.reject;
    row.attach = moves.attach;
    row.resumes = moves.resumes;
    row.replay_bytes = moves.bytes_replayed;
    row.recover_max_ms = moves.recovery_us_max / 1000;
    row.impair_accepts = impair.accepted();
    row.up_bytes = impair.up_bytes();
    row.down_bytes = impair.down_bytes();
    drop(impair);
    row
}

fn print_convo(rows: &[ConvoRow]) {
    println!("## conversation");
    println!(
        "| class | standby | profile | seed | fault | survived | end_turn | end_phase | app_saw | engine_dials | control_streams | session_carriers | standby_dials | standby_bound | promotions | swaps | stall | hold | relay_stall | closed | io | reject | attach | resumes | replay_bytes | recover_max_ms | impair_accepts | up_bytes | down_bytes | payload_up | payload_down |"
    );
    println!(
        "|---|---:|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    );
    for row in rows {
        let (end_turn, end_phase, saw) = match &row.end {
            Some(end) => (end.turn.to_string(), end.phase, cell(&end.saw)),
            None => ("-".to_owned(), "-", String::new()),
        };
        let survived = if row.survived { "yes" } else { "no" };
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            row.class,
            row.standby,
            row.profile,
            row.seed,
            row.fault,
            survived,
            end_turn,
            end_phase,
            saw,
            row.engine_dials,
            row.control_streams,
            row.session_carriers,
            row.standby_dials,
            row.standby_bound,
            row.standby_promotions,
            row.swaps,
            row.stall,
            row.hold,
            row.relay_stall,
            row.closed,
            row.io,
            row.reject,
            row.attach,
            row.resumes,
            row.replay_bytes,
            row.recover_max_ms,
            row.impair_accepts,
            row.up_bytes,
            row.down_bytes,
            row.payload_up,
            row.payload_down
        );
    }
    println!();
    println!(
        "session_carriers counts engine dials whose first byte was not CTRL_HELLO (a standby dial is one of these). control_streams counts CTRL_HELLO. engine_dials counts every dial, including a raced dial dropped before it wrote. standby_dials, standby_bound, promotions and swaps are the kernel dialer's counters for this run. stall, hold, relay_stall, closed, io, reject and attach count why the session gave a carrier up. resumes is a RESUME re-attach. replay_bytes is uplink sent again after a promotion or a RESUME. recover_max_ms is the longest wait from that loss until the next byte of progress. impair_accepts is TCP connections the relay accepted. Relay byte totals include session framing and the control stream. Stalls in the turn table are token inter-arrival gaps, not the planned silence. ttft_after_silence_ms is first-token arrival minus (origin has the body + silence)."
    );
    println!();
    println!(
        "| class | standby | profile | seed | fault | turn | upload_ms | ttft_after_silence_ms | delay_p50_ms | delay_p99_ms | delay_max_ms | stalls_300 | stalls_1s | stalls_20s | longest_gap_ms |"
    );
    println!("|---|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for row in rows {
        for turn in &row.turns {
            println!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                row.class,
                row.standby,
                row.profile,
                row.seed,
                row.fault,
                turn.turn,
                turn.upload_ms,
                turn.ttft_after_silence_ms,
                turn.delay_p50_ms,
                turn.delay_p99_ms,
                turn.delay_max_ms,
                turn.stalls_300,
                turn.stalls_1s,
                turn.stalls_20s,
                turn.longest_gap_ms
            );
        }
    }
}

fn convo_json(rows: &[ConvoRow], spec: (u64, u64, u64, u64)) -> Value {
    let (n_turns, upload, silence_ms, tokens) = spec;
    json!({
        "scenario": "conversation",
        "class": class_name(),
        "standby": u8::from(standby_enabled()),
        "turns": n_turns,
        "upload_bytes": upload,
        "silence_ms": silence_ms,
        "tokens": tokens,
        "event_len": EVENT_LEN,
        "percentile": "ceil(p * n) - 1",
        "note": "session_carriers are engine dials whose first byte was not CTRL_HELLO; control_streams are CTRL_HELLO; engine_dials includes a raced dial dropped before it wrote. Relay bytes include framing and the control stream.",
        "runs": rows.iter().map(convo_run_json).collect::<Vec<_>>(),
    })
}

fn turn_json(turn: &TurnMetrics) -> Value {
    json!({
        "turn": turn.turn,
        "upload_ms": turn.upload_ms,
        "ttft_after_silence_ms": turn.ttft_after_silence_ms,
        "delay_p50_ms": turn.delay_p50_ms,
        "delay_p99_ms": turn.delay_p99_ms,
        "delay_max_ms": turn.delay_max_ms,
        "stalls_300": turn.stalls_300,
        "stalls_1s": turn.stalls_1s,
        "stalls_20s": turn.stalls_20s,
        "longest_gap_ms": turn.longest_gap_ms,
    })
}

fn convo_run_json(row: &ConvoRow) -> Value {
    json!({
        "class": row.class,
        "standby": row.standby,
        "profile": row.profile,
        "seed": row.seed,
        "fault": row.fault,
        "survived": row.survived,
        "end_turn": row.end.as_ref().map(|end| end.turn),
        "end_phase": row.end.as_ref().map(|end| end.phase),
        "app_saw": row.end.as_ref().map(|end| end.saw.as_str()),
        "engine_dials": row.engine_dials,
        "control_streams": row.control_streams,
        "session_carriers": row.session_carriers,
        "standby_dials": row.standby_dials,
        "standby_bound": row.standby_bound,
        "promotions": row.standby_promotions,
        "swaps": row.swaps,
        "stall": row.stall,
        "hold": row.hold,
        "relay_stall": row.relay_stall,
        "closed": row.closed,
        "io": row.io,
        "reject": row.reject,
        "attach": row.attach,
        "resumes": row.resumes,
        "replay_bytes": row.replay_bytes,
        "recover_max_ms": row.recover_max_ms,
        "impair_accepts": row.impair_accepts,
        "up_bytes": row.up_bytes,
        "down_bytes": row.down_bytes,
        "payload_up": row.payload_up,
        "payload_down": row.payload_down,
        "turn_metrics": row.turns.iter().map(turn_json).collect::<Vec<_>>(),
    })
}

fn write_convo_json(rows: &[ConvoRow], spec: (u64, u64, u64, u64)) {
    let Some(path) = std::env::var_os("SEGUE_BENCH_OUT") else {
        return;
    };
    let text = serde_json::to_string_pretty(&convo_json(rows, spec)).unwrap();
    std::fs::write(&path, text)
        .unwrap_or_else(|err| panic!("writing {}: {err}", path.to_string_lossy()));
}

fn assert_convo(rows: &[ConvoRow]) {
    for row in rows {
        if row.profile == "rtt170" && row.fault == "none" {
            let end = row
                .end
                .as_ref()
                .map(|end| format!("turn {} phase {} saw {}", end.turn, end.phase, end.saw));
            assert!(
                row.survived,
                "rtt170 seed {} fault none did not survive ({})",
                row.seed,
                end.unwrap_or_else(|| "no end recorded".to_owned())
            );
            assert_eq!(
                row.control_streams, 1,
                "rtt170 seed {} control streams {} (session carriers {}). The control stream is the dial whose first byte is CTRL_HELLO.",
                row.seed, row.control_streams, row.session_carriers
            );
            // Overseas, and AI with the standby switch off, dial one session
            // carrier. AI with standby on also dials the spare: two session
            // carriers, one of them the standby.
            let expect_standby = exit_is_ai() && standby_enabled();
            let expect_carriers = if expect_standby { 2 } else { 1 };
            assert_eq!(
                row.session_carriers, expect_carriers,
                "rtt170 seed {} session carriers {} (standby dials {}, bound {}, control {}, engine dials {}). A session carrier is an engine dial whose first byte was not CTRL_HELLO; the control stream is counted separately.",
                row.seed, row.session_carriers, row.standby_dials, row.standby_bound, row.control_streams, row.engine_dials
            );
            if expect_standby {
                assert!(
                    row.standby_dials >= 1 && row.standby_bound >= 1,
                    "rtt170 seed {} did not bind a standby (dials {}, bound {})",
                    row.seed,
                    row.standby_dials,
                    row.standby_bound
                );
            } else {
                assert_eq!(
                    row.standby_dials, 0,
                    "rtt170 seed {} dialled a standby with class {} standby {}",
                    row.seed, row.class, row.standby
                );
            }
            for turn in &row.turns {
                assert_eq!(
                    turn.stalls_300, 0,
                    "rtt170 seed {} turn {} had {} stalls over 300 ms (longest gap {} ms)",
                    row.seed, turn.turn, turn.stalls_300, turn.longest_gap_ms
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "conversation soak; run via scripts/bench/session-redundancy.sh"]
async fn conversation_baseline() {
    let spec = (
        convo_turns(),
        convo_upload(),
        convo_silence_ms(),
        convo_tokens(),
    );
    let stack = stack().await;
    let mut rows = Vec::new();
    for (profile, seed, fault) in convo_cases() {
        rows.push(run_convo(&stack, profile, seed, fault, spec).await);
    }
    print_convo(&rows);
    write_convo_json(&rows, spec);
    assert_convo(&rows);
}
