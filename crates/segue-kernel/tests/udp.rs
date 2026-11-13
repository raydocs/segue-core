//! SOCKS5 UDP ASSOCIATE routing, with a fake dialer and a local UDP echo.
//! No external network.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use segue_kernel::dial::{Datagrams, DialError, Dialer, Stream, UdpSession};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::policy::{Policy, PolicyStore};
use segue_kernel::quic::{hex, RFC9001_CLIENT_INITIAL, RFC9369_CLIENT_INITIAL};
use segue_kernel::rules::{Action, Cidr, CidrTable, Matcher, Rule, RuleSet};
use segue_kernel::socks::{serve, Kernel, REP_CMD_UNSUPPORTED, REP_OK};
use segue_kernel::udp::{Udp, UdpSettings};
use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type Calls = Vec<(Option<String>, String)>;

struct Fake {
    calls: Mutex<Calls>,
    echo: SocketAddr,
    /// Session payload cap.
    max: usize,
    /// Every datagram a session was asked to send.
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// Sends every datagram to the echo server; replies claim to come from the
/// flow's target, as a real proxy's would.
struct FakeSession {
    sock: UdpSocket,
    from: (TargetAddr, u16),
    max: usize,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl UdpSession for FakeSession {
    fn max_payload(&self, _: &TargetAddr, _: u16) -> usize {
        self.max
    }
    async fn send(&self, _: &TargetAddr, _: u16, p: &[u8]) -> Result<(), DialError> {
        self.sent.lock().unwrap().push(p.to_vec());
        self.sock
            .send(p)
            .await
            .map(drop)
            .map_err(|e| DialError(e.to_string()))
    }
    async fn recv(&self, buf: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError> {
        buf.clear();
        buf.reserve(2048);
        self.sock
            .recv_buf(buf)
            .await
            .map_err(|e| DialError(e.to_string()))?;
        Ok(self.from.clone())
    }
}

#[async_trait]
impl Dialer for Fake {
    async fn dial(&self, _: Option<&str>, _: &TargetAddr, _: u16) -> Result<Stream, DialError> {
        Err(DialError("tcp not used here".into()))
    }
    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        let shown = match addr {
            TargetAddr::Ip(ip) => SocketAddr::new(*ip, port).to_string(),
            TargetAddr::Domain(d) => format!("{d}:{port}"),
        };
        self.calls
            .lock()
            .unwrap()
            .push((tag.map(str::to_owned), shown));
        if tag == Some("slow") {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        if tag == Some("broken") {
            return Err(DialError("outer link down".into()));
        }
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(self.echo).await.unwrap();
        Ok(Box::new(FakeSession {
            sock,
            from: (addr.clone(), port),
            max: self.max,
            sent: self.sent.clone(),
        }))
    }
}

impl Fake {
    fn calls(&self) -> Calls {
        self.calls.lock().unwrap().clone()
    }
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 4096];
        while let Ok((n, from)) = s.recv_from(&mut b).await {
            let _ = s.send_to(&b[..n], from).await;
        }
    });
    a
}

fn rule(m: Matcher, a: Action) -> Rule {
    Rule {
        matcher: m,
        action: a,
    }
}
fn proxy(t: &str) -> Action {
    Action::Proxy(t.into())
}

fn rules() -> RuleSet {
    RuleSet::new(
        vec![
            rule(Matcher::DomainSuffix("openai.com".into()), proxy("home")),
            rule(Matcher::DomainSuffix("chatgpt.com".into()), proxy("home")),
            rule(
                Matcher::Cidr(Cidr::parse("1.2.3.0/24").unwrap()),
                proxy("home"),
            ),
            rule(Matcher::DomainSuffix("broken.test".into()), proxy("broken")),
            rule(Matcher::DomainSuffix("ads.test".into()), Action::Reject),
            rule(Matcher::DomainSuffix("slow.test".into()), proxy("slow")),
            rule(Matcher::DomainSuffix("p2.test".into()), proxy("p2")),
            rule(
                Matcher::Cidr(Cidr::parse("10.0.0.0/8").unwrap()),
                Action::Direct,
            ),
            rule(
                Matcher::Cidr(Cidr::parse("5.5.0.0/16").unwrap()),
                proxy("reality"),
            ),
        ],
        proxy("proxy"),
    )
}

fn settings() -> UdpSettings {
    UdpSettings {
        refuse: BTreeSet::from(["home".to_owned()]),
        refuse_quic: BTreeSet::from(["reality".to_owned()]),
        idle_timeout: Duration::from_millis(300),
        max_flows: 4,
        queue: 8,
        max_associations: 2,
        queue_bytes: 1 << 20,
    }
}

struct Env {
    fake: Arc<Fake>,
    udp: Option<Arc<Udp>>,
    socks: SocketAddr,
}

async fn start(udp: Option<UdpSettings>, pool: Option<Arc<FakeIpPool>>) -> Env {
    start_max(udp, pool, 1000).await
}

async fn start_max(udp: Option<UdpSettings>, pool: Option<Arc<FakeIpPool>>, max: usize) -> Env {
    let fake = Arc::new(Fake {
        calls: Mutex::default(),
        echo: udp_echo().await,
        max,
        sent: Arc::default(),
    });
    let udp = udp.map(|s| Arc::new(Udp::new(s)));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = l.local_addr().unwrap();
    let kernel = Kernel {
        policy: PolicyStore::inline(Policy::inline(rules(), CidrTable::default())),
        dialer: fake.clone(),
        fake_ip: pool,
        sniff: None,
        udp: udp.clone(),
    };
    tokio::spawn(serve(l, Arc::new(kernel)));
    Env { fake, udp, socks }
}

/// UDP ASSOCIATE: (reply code, control conn, relay address).
async fn associate(socks: SocketAddr) -> (u8, TcpStream, SocketAddr) {
    let mut c = TcpStream::connect(socks).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    c.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    let ip = Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
    let port = u16::from_be_bytes([rep[8], rep[9]]);
    (rep[1], c, SocketAddr::new(IpAddr::V4(ip), port))
}

fn packet(addr: &TargetAddr, port: u16, data: &[u8]) -> Vec<u8> {
    let mut p = vec![0, 0, 0];
    match addr {
        TargetAddr::Ip(IpAddr::V4(v4)) => {
            p.push(1);
            p.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(IpAddr::V6(v6)) => {
            p.push(4);
            p.extend_from_slice(&v6.octets());
        }
        TargetAddr::Domain(d) => {
            p.push(3);
            p.push(d.len() as u8);
            p.extend_from_slice(d.as_bytes());
        }
    }
    p.extend_from_slice(&port.to_be_bytes());
    p.extend_from_slice(data);
    p
}

fn ip(s: &str) -> TargetAddr {
    TargetAddr::Ip(s.parse().unwrap())
}
fn dom(s: &str) -> TargetAddr {
    TargetAddr::Domain(s.into())
}

async fn client(relay: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(relay).await.unwrap();
    s
}

async fn recv(s: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
    let mut b = vec![0u8; 4096];
    let n = tokio::time::timeout(wait, s.recv(&mut b))
        .await
        .ok()?
        .ok()?;
    b.truncate(n);
    Some(b)
}

const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(250);

#[tokio::test]
async fn direct_and_proxied_destinations_are_routed_per_datagram() {
    let env = start(Some(settings()), None).await;
    let (rep, _ctl, relay) = associate(env.socks).await;
    assert_eq!(rep, REP_OK);
    assert!(relay.ip().is_loopback());
    let c = client(relay).await;

    c.send(&packet(&ip("10.1.1.1"), 53, b"direct"))
        .await
        .unwrap();
    assert_eq!(
        recv(&c, WAIT).await.unwrap(),
        packet(&ip("10.1.1.1"), 53, b"direct")
    );
    c.send(&packet(&dom("example.org"), 443, b"proxied"))
        .await
        .unwrap();
    assert_eq!(
        recv(&c, WAIT).await.unwrap(),
        packet(&dom("example.org"), 443, b"proxied")
    );
    // Second datagram to the same destination reuses the flow.
    c.send(&packet(&ip("10.1.1.1"), 53, b"again"))
        .await
        .unwrap();
    assert_eq!(
        recv(&c, WAIT).await.unwrap(),
        packet(&ip("10.1.1.1"), 53, b"again")
    );
    assert_eq!(
        env.fake.calls(),
        vec![
            (None, "10.1.1.1:53".into()),
            (Some("proxy".into()), "example.org:443".into())
        ]
    );
}

#[tokio::test]
async fn home_ai_reject_and_quic_on_reality_are_refused_without_dialling() {
    let env = start(Some(settings()), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    for (a, p) in [
        (dom("api.openai.com"), 443),
        (ip("1.2.3.4"), 3478),
        (dom("ads.test"), 53),
        (ip("5.5.1.1"), 443),
    ] {
        c.send(&packet(&a, p, b"x")).await.unwrap();
    }
    assert_eq!(recv(&c, QUIET).await, None);
    assert!(env.fake.calls().is_empty(), "{:?}", env.fake.calls());
    assert_eq!(env.udp.as_ref().unwrap().dropped(), 4);
    // Reality UDP to another port is carried.
    c.send(&packet(&ip("5.5.1.1"), 3478, b"ok")).await.unwrap();
    assert!(recv(&c, WAIT).await.is_some());
    assert_eq!(
        env.fake.calls(),
        vec![(Some("reality".into()), "5.5.1.1:3478".into())]
    );
}

#[tokio::test]
async fn failed_proxy_is_refused_and_never_goes_direct() {
    let env = start(Some(settings()), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    for _ in 0..5 {
        c.send(&packet(&dom("x.broken.test"), 443, b"x"))
            .await
            .unwrap();
    }
    assert_eq!(recv(&c, QUIET).await, None);
    // One dial for the flow, through its own outbound; nothing direct.
    let calls = env.fake.calls();
    assert_eq!(
        calls,
        vec![(Some("broken".into()), "x.broken.test:443".into())]
    );
    assert!(calls.iter().all(|(t, _)| t.is_some()));
}

#[tokio::test]
async fn fake_ip_destinations_are_dialled_by_name_and_stale_ones_dropped() {
    let pool = Arc::new(
        FakeIpPool::new(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::from_secs(60),
            Duration::from_secs(600),
            [7; 32],
        )
        .unwrap(),
    );
    let fake = pool.assign("video.example", 0).unwrap();
    let ai = pool.assign("chat.openai.com", 0).unwrap();
    let env = start(Some(settings()), Some(pool)).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let fake = TargetAddr::Ip(IpAddr::V4(fake));
    c.send(&packet(&fake, 443, b"q")).await.unwrap();
    // The reply names the fake address the app sent to.
    assert_eq!(recv(&c, WAIT).await.unwrap(), packet(&fake, 443, b"q"));
    c.send(&packet(&TargetAddr::Ip(IpAddr::V4(ai)), 443, b"q"))
        .await
        .unwrap();
    c.send(&packet(&ip("198.19.255.1"), 443, b"q"))
        .await
        .unwrap();
    assert_eq!(recv(&c, QUIET).await, None);
    assert_eq!(
        env.fake.calls(),
        vec![(Some("proxy".into()), "video.example:443".into())]
    );
}

#[tokio::test]
async fn oversize_fragments_and_flow_limit_are_dropped_and_counted() {
    let env = start(Some(settings()), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let udp = env.udp.as_ref().unwrap();
    c.send(&packet(&ip("10.0.0.1"), 1, &[0u8; 1001]))
        .await
        .unwrap();
    let mut frag = packet(&ip("10.0.0.1"), 1, b"f");
    frag[2] = 1;
    c.send(&frag).await.unwrap();
    assert_eq!(recv(&c, QUIET).await, None);
    assert_eq!(udp.dropped(), 2);
    // max_flows = 4 (the oversize one opened flow 1).
    for port in 2..=5 {
        c.send(&packet(&ip("10.0.0.1"), port, b"y")).await.unwrap();
    }
    let mut got = 0;
    while recv(&c, QUIET).await.is_some() {
        got += 1;
    }
    assert_eq!(got, 3);
    assert_eq!(udp.dropped(), 3);
}

#[tokio::test]
async fn idle_association_ends_and_closing_control_ends_it() {
    let env = start(Some(settings()), None).await;
    let (_, mut ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    c.send(&packet(&ip("10.0.0.1"), 7, b"z")).await.unwrap();
    assert!(recv(&c, WAIT).await.is_some());
    // Flow and association idle out (300 ms each): the control conn closes.
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(WAIT, ctl.read(&mut b)).await.unwrap();
    assert!(matches!(n, Ok(0) | Err(_)));

    // Association limit is 2; slots come back when control conns close.
    let (a, c1, _) = associate(env.socks).await;
    let (b2, _c2, _) = associate(env.socks).await;
    let (third, _c3, _) = associate(env.socks).await;
    assert_eq!((a, b2), (REP_OK, REP_OK));
    assert_ne!(third, REP_OK);
    drop(c1);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (again, _c4, _) = associate(env.socks).await;
    assert_eq!(again, REP_OK);
}

#[tokio::test]
async fn udp_off_answers_command_unsupported() {
    let env = start(None, None).await;
    let (rep, _, _) = associate(env.socks).await;
    assert_eq!(rep, REP_CMD_UNSUPPORTED);
}

#[tokio::test]
async fn queued_bytes_are_bounded_per_association() {
    let mut s = settings();
    s.queue_bytes = 4 * 900;
    s.idle_timeout = Duration::from_secs(5);
    let env = start(Some(s), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let udp = env.udp.as_ref().unwrap();
    // Two flows, both still dialling: 4 datagrams of 900 bytes fit in the
    // budget (each flow's queue of 8 would hold more), the other 6 drop.
    for i in 0..10u8 {
        let to = if i % 2 == 0 {
            "a.slow.test"
        } else {
            "b.slow.test"
        };
        c.send(&packet(&dom(to), 53, &[i; 900])).await.unwrap();
    }
    let mut got = 0;
    while recv(&c, Duration::from_secs(1)).await.is_some() {
        got += 1;
    }
    assert_eq!((got, udp.dropped()), (4, 6));
    // The budget came back once the queues drained.
    for i in 0..4u8 {
        c.send(&packet(&dom("a.slow.test"), 53, &[i; 900]))
            .await
            .unwrap();
    }
    let mut got = 0;
    while recv(&c, Duration::from_secs(1)).await.is_some() {
        got += 1;
    }
    assert_eq!((got, udp.dropped()), (4, 6));
}

fn fake_pool() -> Arc<FakeIpPool> {
    Arc::new(
        FakeIpPool::new(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::from_secs(60),
            Duration::from_secs(600),
            [7; 32],
        )
        .unwrap(),
    )
}

/// QUIC-shaped datagrams: v1, v2, an unknown version, and an Initial with
/// a short header of another connection hidden behind it.
fn quic_variants() -> Vec<Vec<u8>> {
    let rfc = hex(RFC9001_CLIENT_INITIAL);
    let mut unknown = rfc.clone();
    unknown[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
    let mut coalesced = rfc[..600].to_vec();
    coalesced.extend_from_slice(b"\x40\x99\x99\x99\x99\x99\x99\x99\x99 hidden");
    vec![rfc, hex(RFC9369_CLIENT_INITIAL), unknown, coalesced]
}

/// r8 N1–N3 (§5.2a.2): QUIC to a bare IP is dropped on any port (SOCKS
/// has no per-datagram refusal; the client's handshake times out and it
/// falls back to TCP), and so is anything on UDP/443 to a bare IP. Nothing
/// is dialled.
#[tokio::test]
async fn quic_to_bare_ip_is_dropped_on_any_port() {
    let env = start_max(Some(settings()), None, 1500).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let mut n = 0;
    for port in [443, 8443] {
        for d in quic_variants() {
            c.send(&packet(&ip("8.8.8.8"), port, &d)).await.unwrap();
            n += 1;
        }
    }
    c.send(&packet(&ip("8.8.8.8"), 443, b"\x40short"))
        .await
        .unwrap();
    n += 1;
    assert_eq!(recv(&c, QUIET).await, None);
    assert!(env.fake.calls().is_empty(), "{:?}", env.fake.calls());
    assert_eq!(env.udp.as_ref().unwrap().dropped(), n);
}

/// QUIC with a name known for certain (a domain in the request, or a
/// fake IP) is routed by that name and the flow pinned: every datagram,
/// whatever it looks like, rides it.
#[tokio::test]
async fn quic_to_a_name_is_routed_by_it_and_pinned() {
    let pool = fake_pool();
    let fake = TargetAddr::Ip(IpAddr::V4(pool.assign("www.p2.test", 0).unwrap()));
    let env = start_max(Some(settings()), Some(pool), 1500).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    for dst in [dom("example.com"), fake.clone()] {
        for d in quic_variants() {
            c.send(&packet(&dst, 443, &d)).await.unwrap();
            assert_eq!(recv(&c, WAIT).await.unwrap(), packet(&dst, 443, &d));
        }
        let short = b"\x40\x31\x31\x31\x31\x31\x31\x31\x31 rotated".to_vec();
        c.send(&packet(&dst, 443, &short)).await.unwrap();
        assert_eq!(recv(&c, WAIT).await.unwrap(), packet(&dst, 443, &short));
    }
    assert_eq!(
        env.fake.calls(),
        vec![
            (Some("proxy".into()), "example.com:443".into()),
            (Some("p2".into()), "www.p2.test:443".into()),
        ]
    );
    // An AI name is refused as for any UDP to it.
    c.send(&packet(&dom("chatgpt.com"), 443, &quic_variants()[0]))
        .await
        .unwrap();
    assert_eq!(recv(&c, QUIET).await, None);
    assert_eq!(env.fake.calls().len(), 2);
}

/// r8 N1: every datagram of a bare-IP flow is checked, not only the first.
/// A plain flow is routed by IP; a QUIC datagram on it is dropped while
/// plain datagrams keep flowing.
#[tokio::test]
async fn plain_flow_drops_each_quic_datagram() {
    let env = start_max(Some(settings()), None, 1500).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let dst = ip("8.8.8.8");
    c.send(&packet(&dst, 8443, b"\x12\x34plain")).await.unwrap();
    assert!(recv(&c, WAIT).await.is_some());
    for d in quic_variants() {
        c.send(&packet(&dst, 8443, &d)).await.unwrap();
    }
    assert_eq!(recv(&c, QUIET).await, None);
    c.send(&packet(&dst, 8443, b"\x12\x34again")).await.unwrap();
    assert!(recv(&c, WAIT).await.is_some());
    assert_eq!(
        env.fake.calls(),
        vec![(Some("proxy".into()), "8.8.8.8:8443".into())]
    );
    assert_eq!(env.udp.as_ref().unwrap().dropped(), 4);
    assert_eq!(env.fake.sent.lock().unwrap().len(), 2);
}

/// QUIC short header of `n` bytes (first byte 0x40..=0x7F).
fn short_header(first: u8, n: usize) -> Vec<u8> {
    let mut p = vec![first];
    p.resize(n, 0x31);
    p
}

/// Ordinary UDP protocols' first datagrams (none QUIC-shaped).
fn plain_firsts() -> Vec<(&'static str, Vec<u8>)> {
    let sized = |head: &[u8], n: usize| {
        let mut p = head.to_vec();
        p.resize(n, 0x5a);
        p
    };
    vec![
        ("wireguard", sized(&[0x01, 0, 0, 0], 148)),
        (
            "stun",
            sized(&[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42], 28),
        ),
        (
            "dtls",
            sized(&[0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0], 200),
        ),
        ("rtp", sized(&[0x80, 0x60, 0x12, 0x34], 1000)),
        ("dns-like", sized(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01], 40)),
    ]
}

/// r9 F1: a new bare-IP flow whose first datagram is a QUIC short header
/// (a connection set up before the kernel, or migrated from elsewhere) is
/// dropped like an Initial, v4 and v6; nothing is dialled. Ordinary UDP
/// protocols' first datagrams still go by the IP rules.
#[tokio::test]
async fn short_header_first_to_bare_ip_is_dropped_plain_udp_passes() {
    // Each protocol on its own flow: room for all of them.
    let s = UdpSettings {
        max_flows: 8,
        ..settings()
    };
    let env = start_max(Some(s), None, 1500).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let mut n = 0;
    for dst in [ip("8.8.8.8"), ip("2001:4860:4860::8888")] {
        for first in [0x40, 0x5c, 0x7f] {
            c.send(&packet(&dst, 8443, &short_header(first, 40)))
                .await
                .unwrap();
            n += 1;
        }
    }
    assert_eq!(recv(&c, QUIET).await, None);
    assert!(env.fake.calls().is_empty(), "{:?}", env.fake.calls());
    assert_eq!(env.udp.as_ref().unwrap().dropped(), n);
    for (i, (name, d)) in plain_firsts().into_iter().enumerate() {
        let port = 9000 + i as u16;
        c.send(&packet(&ip("8.8.8.8"), port, &d)).await.unwrap();
        assert_eq!(
            recv(&c, WAIT).await.as_deref(),
            Some(&packet(&ip("8.8.8.8"), port, &d)[..]),
            "{name}"
        );
    }
    assert_eq!(env.fake.calls().len(), plain_firsts().len());
    assert_eq!(env.udp.as_ref().unwrap().dropped(), n);
}
