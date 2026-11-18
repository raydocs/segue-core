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
//! Carrier re-attach is not a column. `SessionHealth` is not observable from
//! this test without changing the kernel.
//!
//! Relay, ticket and SOCKS wiring matches `roaming_e2e.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

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

/// Local origin. `PING` gets 8 bytes back; anything else is a token stream.
async fn serve_origin(seconds: u64) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                handle_origin(sock, seconds).await;
            });
        }
    });
    addr
}

async fn handle_origin(mut sock: TcpStream, seconds: u64) {
    let _ = sock.set_nodelay(true);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.contains(&b'\n') {
            break;
        }
        if buf.len() > 1024 {
            return;
        }
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
    let env = relay_env();
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
    let socks = spawn_socks(dialer, "ov").await;
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
    println!("## token stream");
    println!(
        "| profile | seed | ttft_ms | delay_p50_ms | delay_p99_ms | delay_p99.9_ms | delay_max_ms | ia_p50_ms | ia_p99_ms | ia_p99.9_ms | stalls_300 | stalls_1s | up_bytes | down_bytes | payload_bytes |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
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
    println!("## new flows");
    println!("| profile | seed | ttfb_p50_ms | ttfb_p99_ms | ttfb_max_ms |");
    println!("|---|---:|---:|---:|---:|");
    for r in rows {
        println!(
            "| {} | {} | {} | {} | {} |",
            r.profile, r.seed, r.ttfb_p50_ms, r.ttfb_p99_ms, r.ttfb_max_ms
        );
    }
}

fn token_json(row: &TokenRow) -> Value {
    json!({
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
    for profile in PROFILES {
        for seed in SEEDS {
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
