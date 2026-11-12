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
}

/// Sends every datagram to the echo server; replies claim to come from the
/// flow's target, as a real proxy's would.
struct FakeSession {
    sock: UdpSocket,
    from: (TargetAddr, u16),
}

#[async_trait]
impl UdpSession for FakeSession {
    fn max_payload(&self, _: &TargetAddr, _: u16) -> usize {
        1000
    }
    async fn send(&self, _: &TargetAddr, _: u16, p: &[u8]) -> Result<(), DialError> {
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
            rule(
                Matcher::Cidr(Cidr::parse("1.2.3.0/24").unwrap()),
                proxy("home"),
            ),
            rule(Matcher::DomainSuffix("broken.test".into()), proxy("broken")),
            rule(Matcher::DomainSuffix("ads.test".into()), Action::Reject),
            rule(Matcher::DomainSuffix("slow.test".into()), proxy("slow")),
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
    let fake = Arc::new(Fake {
        calls: Mutex::default(),
        echo: udp_echo().await,
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
    let fake = pool.assign("video.example", proxy("proxy")).unwrap();
    let ai = pool.assign("chat.openai.com", proxy("home")).unwrap();
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
