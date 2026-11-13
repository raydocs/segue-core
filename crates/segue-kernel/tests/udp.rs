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
use segue_kernel::quic::{
    hex, initial_for_test, QUIC_GO_CHATGPT_INITIAL, QUIC_GO_CHATGPT_INITIAL_2,
    RFC9001_CLIENT_INITIAL,
};
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

/// §5.2a.2: a bare-IP QUIC flow is routed by its Initial's SNI.
#[tokio::test]
async fn quic_initial_sni_routes_bare_ip_udp_by_name() {
    let env = start(Some(settings()), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let initial = hex(RFC9001_CLIENT_INITIAL);
    c.send(&packet(&ip("8.8.8.8"), 443, &initial))
        .await
        .unwrap();
    // (The fake session's 1000-byte payload limit drops the 1200-byte
    // Initial itself; the dial is what is checked.)
    for _ in 0..100 {
        if !env.fake.calls().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        env.fake.calls(),
        vec![(Some("proxy".into()), "example.com:443".into())]
    );
}

/// An AI name in a ClientHello split over two datagrams (real quic-go
/// capture) is refused: nothing dialled, both datagrams dropped.
#[tokio::test]
async fn quic_ai_sni_split_over_two_datagrams_is_refused() {
    let env = start(Some(settings()), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    for d in [QUIC_GO_CHATGPT_INITIAL, QUIC_GO_CHATGPT_INITIAL_2] {
        c.send(&packet(&ip("8.8.8.8"), 443, &hex(d))).await.unwrap();
    }
    assert_eq!(recv(&c, QUIET).await, None);
    assert!(env.fake.calls().is_empty(), "{:?}", env.fake.calls());
    assert_eq!(env.udp.as_ref().unwrap().dropped(), 2);
}

/// Until classified, QUIC that cannot be confirmed non-AI is refused (the
/// app falls back to TCP): an incomplete ClientHello, anything on UDP/443
/// that is not a readable Initial. Other UDP still goes by IP rules.
#[tokio::test]
async fn unconfirmed_quic_is_refused() {
    let env = start(Some(settings()), None).await;
    let (_, _ctl, relay) = associate(env.socks).await;
    let c = client(relay).await;
    let first = hex(QUIC_GO_CHATGPT_INITIAL);
    for _ in 0..segue_kernel::quic::MAX_DATAGRAMS {
        c.send(&packet(&ip("8.8.4.4"), 443, &first)).await.unwrap();
    }
    c.send(&packet(&ip("8.8.8.8"), 443, b"\x40short-header"))
        .await
        .unwrap();
    assert_eq!(recv(&c, QUIET).await, None);
    assert!(env.fake.calls().is_empty(), "{:?}", env.fake.calls());
    c.send(&packet(&ip("8.8.8.8"), 3478, b"stun"))
        .await
        .unwrap();
    assert!(recv(&c, WAIT).await.is_some());
    assert_eq!(
        env.fake.calls(),
        vec![(Some("proxy".into()), "8.8.8.8:3478".into())]
    );
}

/// N7: on one SOCKS UDP flow (same client socket, same destination), an
/// allowed QUIC connection, then a new Initial (new DCID) naming an AI host.
/// The AI connection is classified on its own: none of its datagrams reach
/// the flow's outbound, while the first connection keeps flowing. Same for
/// a non-443 flow that started as plain UDP.
#[tokio::test]
async fn second_quic_connection_on_same_flow_is_classified() {
    for (port, first) in [
        (443, hex(RFC9001_CLIENT_INITIAL)),
        (8443, b"\x12\x34plain".to_vec()),
    ] {
        let env = start_max(Some(settings()), None, 1500).await;
        let (_, _ctl, relay) = associate(env.socks).await;
        let c = client(relay).await;
        let dst = ip("8.8.8.8");
        c.send(&packet(&dst, port, &first)).await.unwrap();
        assert!(recv(&c, WAIT).await.is_some(), "{port}: first connection");
        c.send(&packet(
            &dst,
            port,
            &initial_for_test(&[9; 8], "chatgpt.com"),
        ))
        .await
        .unwrap();
        for d in [QUIC_GO_CHATGPT_INITIAL, QUIC_GO_CHATGPT_INITIAL_2] {
            c.send(&packet(&dst, port, &hex(d))).await.unwrap();
        }
        // R7: QUIC the guard cannot attribute to the allowed connection (an
        // unknown version, a Handshake to an ID nobody chose) never rides
        // the flow, on any port.
        let mut other_version = hex(RFC9001_CLIENT_INITIAL);
        other_version[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        let mut handshake = vec![0xe0, 0, 0, 0, 1, 8];
        handshake.extend_from_slice(&[8; 8]);
        handshake.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
        for d in [other_version, handshake] {
            c.send(&packet(&dst, port, &d)).await.unwrap();
        }
        // (Within the 300 ms idle timeout of the first connection.)
        assert_eq!(
            recv(&c, QUIET).await,
            None,
            "{port}: AI or unattributed QUIC echoed"
        );
        let short = b"\x40short header".to_vec();
        c.send(&packet(&dst, port, &short)).await.unwrap();
        assert!(recv(&c, WAIT).await.is_some(), "{port}: first still flows");
        assert_eq!(*env.fake.sent.lock().unwrap(), vec![first.clone(), short]);
        assert_eq!(env.fake.calls().len(), 1);
        assert_eq!(env.udp.as_ref().unwrap().dropped(), 5);
    }
}

/// R7 #2/#3 over SOCKS. The echo server reflects the client Initial, so
/// the reply path learns a zero-length "server ID": that must not make
/// every short header the allowed connection's. A short header to an
/// unknown ID rides the flow only while no other outbound carries QUIC to
/// the same server (the client switched to a CID issued inside the
/// encryption); once another association reaches that server through
/// another outbound, it is dropped (SOCKS cannot signal a refusal).
#[tokio::test]
async fn unknown_short_header_needs_an_uncontested_route() {
    let env = start_max(Some(settings()), None, 1500).await;
    let dst = ip("8.8.8.8");
    let (_, _ctl_a, relay_a) = associate(env.socks).await;
    let a = client(relay_a).await;
    a.send(&packet(
        &dst,
        443,
        &initial_for_test(&[1; 8], "example.com"),
    ))
    .await
    .unwrap();
    assert!(recv(&a, WAIT).await.is_some(), "first connection");
    let rotated = b"\x40\x31\x31\x31\x31\x31\x31\x31\x31 rotated".to_vec();
    a.send(&packet(&dst, 443, &rotated)).await.unwrap();
    assert!(recv(&a, WAIT).await.is_some(), "rotated CID keeps flowing");
    let (_, _ctl_b, relay_b) = associate(env.socks).await;
    let b = client(relay_b).await;
    b.send(&packet(
        &dst,
        443,
        &initial_for_test(&[2; 8], "www.p2.test"),
    ))
    .await
    .unwrap();
    assert!(recv(&b, WAIT).await.is_some(), "other route's connection");
    assert_eq!(
        env.fake.calls(),
        vec![
            (Some("proxy".into()), "example.com:443".into()),
            (Some("p2".into()), "www.p2.test:443".into()),
        ]
    );
    let moved = b"\x40\x32\x32\x32\x32\x32\x32\x32\x32 moved".to_vec();
    a.send(&packet(&dst, 443, &moved)).await.unwrap();
    assert_eq!(recv(&a, QUIET).await, None, "contested unknown ID dropped");
    assert_eq!(env.udp.as_ref().unwrap().dropped(), 1);
}
