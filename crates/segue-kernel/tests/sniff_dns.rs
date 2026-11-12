//! SNI/Host sniffing on bare-IP CONNECTs and the smart-DNS → fake-IP path,
//! with a fake dialer and a fake domestic resolver on loopback. No external
//! network.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use segue_kernel::dial::{DialError, Dialer, Stream};
use segue_kernel::dns::{
    answers_for_test, query_for_test, serve_tcp, serve_udp, DnsSettings, SmartDns, RCODE_NXDOMAIN,
    RCODE_OK, TYPE_A, TYPE_AAAA,
};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::rules::{Action, Cidr, CidrTable, Matcher, Rule, RuleSet};
use segue_kernel::sniff::client_hello_for_test;
use segue_kernel::socks::{serve, Kernel, SniffSettings, REP_NOT_ALLOWED, REP_OK};
use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type Calls = Vec<(Option<String>, String)>;

#[derive(Default)]
struct Fake {
    calls: Mutex<Calls>,
    echo: Mutex<Option<SocketAddr>>,
}

#[async_trait]
impl Dialer for Fake {
    async fn dial(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        let shown = match addr {
            TargetAddr::Ip(ip) => format!("{ip}:{port}"),
            TargetAddr::Domain(d) => format!("{d}:{port}"),
        };
        self.calls
            .lock()
            .unwrap()
            .push((tag.map(str::to_owned), shown));
        if tag == Some("broken") {
            return Err(DialError("outer link down".into()));
        }
        let echo = self.echo.lock().unwrap().expect("echo server");
        Ok(Box::new(TcpStream::connect(echo).await.unwrap()))
    }
}

impl Fake {
    fn calls(&self) -> Calls {
        self.calls.lock().unwrap().clone()
    }
}

async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = c.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

fn rule(m: Matcher, a: Action) -> Rule {
    Rule {
        matcher: m,
        action: a,
    }
}
fn proxy(tag: &str) -> Action {
    Action::Proxy(tag.into())
}
fn suffix(s: &str) -> Matcher {
    Matcher::DomainSuffix(s.into())
}
fn cidr(s: &str) -> Matcher {
    Matcher::Cidr(Cidr::parse(s).unwrap())
}

/// AI rules first (§5.2a.4: equal-rank conflicts go to the earlier rule).
fn rules() -> RuleSet {
    RuleSet::new(
        vec![
            rule(suffix("openai.com"), proxy("ai")),
            rule(cidr("1.2.3.0/24"), proxy("ai")),
            rule(suffix("broken.test"), proxy("broken")),
            rule(suffix("ads.test"), Action::Reject),
            rule(cidr("10.66.0.0/16"), Action::Reject),
            rule(suffix("baidu.com"), Action::Direct),
            rule(cidr("10.0.0.0/8"), Action::Direct),
        ],
        proxy("proxy"),
    )
}

const SNIFF_TIMEOUT: Duration = Duration::from_millis(150);

async fn start_kernel(fake: Arc<Fake>, pool: Option<Arc<FakeIpPool>>) -> SocketAddr {
    *fake.echo.lock().unwrap() = Some(echo_server().await);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let kernel = Kernel {
        rules: rules(),
        dialer: fake,
        fake_ip: pool,
        sniff: Some(SniffSettings {
            timeout: SNIFF_TIMEOUT,
            max_bytes: 16 * 1024,
        }),
    };
    tokio::spawn(serve(l, Arc::new(kernel)));
    addr
}

/// SOCKS5 CONNECT to an IPv4 address.
async fn connect_ip(kernel: SocketAddr, ip: Ipv4Addr, port: u16) -> (u8, TcpStream) {
    let mut c = TcpStream::connect(kernel).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.to_be_bytes());
    c.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    (rep[1], c)
}

/// Send `data` (split at `split` with a pause), read the echo back.
async fn roundtrip(c: &mut TcpStream, data: &[u8], split: usize) -> Vec<u8> {
    c.write_all(&data[..split]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    c.write_all(&data[split..]).await.unwrap();
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    back
}

/// After an early SOCKS success the flow is refused with an RST.
async fn expect_reset(mut c: TcpStream) {
    let mut b = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(5), c.read(&mut b))
        .await
        .unwrap()
    {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
        Ok(n) => panic!("expected RST, got clean read of {n} bytes"),
    }
}

#[tokio::test]
async fn split_client_hello_is_sniffed_and_replayed_byte_for_byte() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    // IP rule says direct, SNI says AI proxy: proxy wins (stricter).
    let (rep, mut c) = connect_ip(k, "10.1.2.3".parse().unwrap(), 443).await;
    assert_eq!(rep, REP_OK);
    // ~3 KiB hello spanning two writes, cut inside the SNI extension area.
    let hello = client_hello_for_test(Some("chat.openai.com"), 3000);
    assert_eq!(roundtrip(&mut c, &hello, 60).await, hello);
    // Traffic after the hello still flows.
    assert_eq!(
        roundtrip(&mut c, b"application data", 4).await,
        b"application data"
    );
    assert_eq!(
        fake.calls(),
        vec![(Some("ai".into()), "chat.openai.com:443".into())]
    );
}

#[tokio::test]
async fn ai_cidr_beats_direct_sni() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, mut c) = connect_ip(k, "1.2.3.4".parse().unwrap(), 443).await;
    assert_eq!(rep, REP_OK);
    let hello = client_hello_for_test(Some("www.baidu.com"), 0);
    assert_eq!(roundtrip(&mut c, &hello, hello.len()).await, hello);
    assert_eq!(
        fake.calls(),
        vec![(Some("ai".into()), "www.baidu.com:443".into())]
    );
}

#[tokio::test]
async fn direct_sni_on_unmatched_ip_dials_the_ip_not_the_name() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, mut c) = connect_ip(k, "8.8.4.4".parse().unwrap(), 8443).await;
    assert_eq!(rep, REP_OK);
    let hello = client_hello_for_test(Some("pan.baidu.com"), 0);
    assert_eq!(roundtrip(&mut c, &hello, 10).await, hello);
    assert_eq!(fake.calls(), vec![(None, "8.8.4.4:8443".into())]);
}

#[tokio::test]
async fn http_host_is_sniffed() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, mut c) = connect_ip(k, "10.9.9.9".parse().unwrap(), 80).await;
    assert_eq!(rep, REP_OK);
    let req = b"GET / HTTP/1.1\r\nUser-Agent: t\r\nHost: API.OpenAI.com:80\r\n\r\n";
    assert_eq!(roundtrip(&mut c, req, 20).await, req);
    assert_eq!(
        fake.calls(),
        vec![(Some("ai".into()), "api.openai.com:80".into())]
    );
}

#[tokio::test]
async fn silent_client_falls_back_to_ip_rules_after_timeout() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, mut c) = connect_ip(k, "10.4.4.4".parse().unwrap(), 22).await;
    assert_eq!(rep, REP_OK);
    tokio::time::sleep(SNIFF_TIMEOUT / 3).await;
    assert!(
        fake.calls().is_empty(),
        "dialled before the sniff window closed"
    );
    tokio::time::sleep(SNIFF_TIMEOUT * 2).await;
    assert_eq!(fake.calls(), vec![(None, "10.4.4.4:22".into())]);
    assert_eq!(
        roundtrip(&mut c, b"SSH-2.0-x\r\n", 3).await,
        b"SSH-2.0-x\r\n"
    );
}

#[tokio::test]
async fn non_tls_bytes_use_ip_rules_and_are_replayed() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, mut c) = connect_ip(k, "9.9.9.9".parse().unwrap(), 443).await;
    assert_eq!(rep, REP_OK);
    let junk = b"\x00\x01binary-protocol";
    assert_eq!(roundtrip(&mut c, junk, junk.len()).await, junk);
    // No IP rule, no name → default route, dialled by IP.
    assert_eq!(
        fake.calls(),
        vec![(Some("proxy".into()), "9.9.9.9:443".into())]
    );
}

#[tokio::test]
async fn failed_proxy_after_sniff_is_reset_never_direct() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    // IP rule is direct, SNI routes to the broken outbound.
    let (rep, mut c) = connect_ip(k, "10.1.1.1".parse().unwrap(), 443).await;
    assert_eq!(rep, REP_OK);
    c.write_all(&client_hello_for_test(Some("api.broken.test"), 0))
        .await
        .unwrap();
    expect_reset(c).await;
    assert_eq!(
        fake.calls(),
        vec![(Some("broken".into()), "api.broken.test:443".into())]
    );
}

#[tokio::test]
async fn sniffed_reject_is_reset_without_dial() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, mut c) = connect_ip(k, "10.1.1.1".parse().unwrap(), 443).await;
    assert_eq!(rep, REP_OK);
    c.write_all(&client_hello_for_test(Some("x.ads.test"), 0))
        .await
        .unwrap();
    expect_reset(c).await;
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn ip_reject_refused_before_sniff() {
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), None).await;
    let (rep, _c) = connect_ip(k, "10.66.1.1".parse().unwrap(), 443).await;
    assert_eq!(rep, REP_NOT_ALLOWED);
    assert!(fake.calls().is_empty());
}

// ---- smart DNS -------------------------------------------------------------

/// Fake domestic resolver: answers A from `table`, NXDOMAIN otherwise, and
/// echoes any non-A query back as an empty NOERROR response. Counts queries.
struct Upstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

async fn fake_resolver(table: &[(&str, Ipv4Addr)]) -> Upstream {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let table: HashMap<String, Ipv4Addr> =
        table.iter().map(|(n, ip)| (n.to_string(), *ip)).collect();
    let h = hits.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            h.fetch_add(1, Ordering::SeqCst);
            let q = &buf[..n];
            // Decode the name (no compression in queries).
            let mut p = 12;
            let mut labels = Vec::new();
            while q[p] != 0 {
                let l = q[p] as usize;
                labels.push(String::from_utf8_lossy(&q[p + 1..p + 1 + l]).to_lowercase());
                p += 1 + l;
            }
            let qend = p + 5;
            let qtype = u16::from_be_bytes([q[p + 1], q[p + 2]]);
            let name = labels.join(".");
            let ip = table.get(&name).filter(|_| qtype == TYPE_A);
            let mut r = q[..2].to_vec();
            r.push(0x81);
            r.push(if ip.is_some() || qtype != TYPE_A {
                0x80
            } else {
                0x80 | RCODE_NXDOMAIN
            });
            r.extend_from_slice(&[0, 1, 0, u8::from(ip.is_some()), 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..qend]);
            if let Some(ip) = ip {
                r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
                r.extend_from_slice(&ip.octets());
            }
            sock.send_to(&r, peer).await.unwrap();
        }
    });
    Upstream { addr, hits }
}

/// A resolver that never answers (the race must not wait on it).
async fn silent_resolver() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let _ = sock.recv_from(&mut buf).await;
        }
    });
    addr
}

fn pool() -> Arc<FakeIpPool> {
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

async fn smart_dns(domestic: Vec<SocketAddr>, pool: Arc<FakeIpPool>) -> Arc<SmartDns> {
    let settings = DnsSettings {
        domestic,
        chnroute: CidrTable::new(&[
            Cidr::parse("1.0.0.0/8").unwrap(),
            Cidr::parse("36.0.0.0/8").unwrap(),
        ]),
        foreign: proxy("proxy"),
        query_timeout: Duration::from_millis(500),
        cache_size: 128,
    };
    Arc::new(SmartDns::new(rules(), pool, settings))
}

async fn ask(dns: &Arc<SmartDns>, id: u16, name: &str, qtype: u16) -> (u8, Vec<IpAddr>) {
    let reply = dns
        .handle(&query_for_test(id, name, qtype))
        .await
        .expect("reply");
    let (rid, rcode, ips) = answers_for_test(&reply).expect("parse");
    assert_eq!(rid, id);
    (rcode, ips)
}

fn v4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn smart_dns_classifies_and_caches() {
    let up = fake_resolver(&[
        ("www.baidu.com", "36.152.44.95".parse().unwrap()),
        ("cdn.example", "1.2.3.9".parse().unwrap()),
        ("polluted.example", "31.13.70.1".parse().unwrap()),
    ])
    .await;
    let silent = silent_resolver().await;
    let pool = pool();
    let dns = smart_dns(vec![silent, up.addr], pool.clone()).await;

    // Firefox canary.
    assert_eq!(
        ask(&dns, 1, "use-application-dns.net", TYPE_A).await,
        (RCODE_NXDOMAIN, vec![])
    );

    // Proxied name → fake-IP, no upstream query; AAAA → NODATA.
    let (rcode, ips) = ask(&dns, 2, "chat.openai.com", TYPE_A).await;
    assert_eq!(rcode, RCODE_OK);
    assert_eq!(ips.len(), 1);
    assert!(pool.contains(ips[0]), "{ips:?}");
    assert_eq!(
        ask(&dns, 3, "Chat.OpenAI.com.", TYPE_A).await.1,
        ips,
        "stable per name, case-insensitive"
    );
    assert_eq!(
        ask(&dns, 4, "chat.openai.com", TYPE_AAAA).await,
        (RCODE_OK, vec![])
    );
    assert_eq!(up.hits.load(Ordering::SeqCst), 0);
    assert_eq!(dns.upstream_queries.load(Ordering::SeqCst), 0);

    // Domestic list → real answer from the domestic resolver (despite the
    // silent one racing alongside), then cached.
    assert_eq!(
        ask(&dns, 5, "www.baidu.com", TYPE_A).await,
        (RCODE_OK, vec![v4("36.152.44.95")])
    );
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        ask(&dns, 6, "WWW.baidu.com", TYPE_A).await,
        (RCODE_OK, vec![v4("36.152.44.95")])
    );
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        1,
        "second query served from cache"
    );

    // Unmatched, answer inside chnroute → real IP.
    assert_eq!(
        ask(&dns, 7, "cdn.example", TYPE_A).await,
        (RCODE_OK, vec![v4("1.2.3.9")])
    );
    // Unmatched, answer outside chnroute → fake-IP routed by dns.foreign.
    let (_, ips) = ask(&dns, 8, "polluted.example", TYPE_A).await;
    assert!(pool.contains(ips[0]), "{ips:?}");
    let entry = pool.lookup(ips[0]).unwrap();
    assert_eq!(
        (entry.domain.as_str(), entry.action),
        ("polluted.example", proxy("proxy"))
    );
    let hits = up.hits.load(Ordering::SeqCst);
    assert_eq!(ask(&dns, 9, "polluted.example", TYPE_A).await.1, ips);
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        hits,
        "foreign verdict cached too"
    );

    // Unknown name → NXDOMAIN passed through (and negatively cached).
    assert_eq!(
        ask(&dns, 10, "nope.example", TYPE_A).await,
        (RCODE_NXDOMAIN, vec![])
    );

    // Non-A/AAAA for an unmatched name goes straight to the resolver with
    // the client's id restored.
    let hits = up.hits.load(Ordering::SeqCst);
    let reply = dns
        .handle(&query_for_test(0xbeef, "cdn.example", 16))
        .await
        .unwrap();
    assert_eq!(&reply[..2], &[0xbe, 0xef]);
    assert_eq!(up.hits.load(Ordering::SeqCst), hits + 1);
    // ...and for a fake-IP name is answered empty locally.
    let reply = dns
        .handle(&query_for_test(0xcafe, "chat.openai.com", 16))
        .await
        .unwrap();
    assert_eq!(answers_for_test(&reply), Some((0xcafe, RCODE_OK, vec![])));
    assert_eq!(up.hits.load(Ordering::SeqCst), hits + 1);

    // Garbage is dropped or FORMERR'd, never a panic.
    assert!(dns.handle(&[1, 2, 3]).await.is_none());
}

#[tokio::test]
async fn upstream_failure_is_servfail() {
    let dns = smart_dns(vec![silent_resolver().await], pool()).await;
    assert_eq!(ask(&dns, 1, "www.baidu.com", TYPE_A).await.0, 2);
}

#[tokio::test]
async fn dns_listeners_then_connect_to_fake_ip_dials_by_domain() {
    let up = fake_resolver(&[("polluted.example", "31.13.70.1".parse().unwrap())]).await;
    let pool = pool();
    let dns = smart_dns(vec![up.addr], pool.clone()).await;

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_addr = udp.local_addr().unwrap();
    tokio::spawn(serve_udp(udp, dns.clone()));
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    tokio::spawn(serve_tcp(tcp, dns.clone()));

    // UDP query for an AI name.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&query_for_test(42, "chat.openai.com", TYPE_A), udp_addr)
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (id, rcode, ips) = answers_for_test(&buf[..n]).unwrap();
    assert_eq!((id, rcode), (42, RCODE_OK));
    let IpAddr::V4(ai_ip) = ips[0] else {
        panic!("v4")
    };

    // TCP query (two on one connection) for the polluted name.
    let mut t = TcpStream::connect(tcp_addr).await.unwrap();
    let mut foreign_ip = None;
    for id in [7u16, 8] {
        let q = query_for_test(id, "polluted.example", TYPE_A);
        t.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        t.write_all(&q).await.unwrap();
        let len = t.read_u16().await.unwrap() as usize;
        let mut r = vec![0u8; len];
        t.read_exact(&mut r).await.unwrap();
        let (rid, rcode, ips) = answers_for_test(&r).unwrap();
        assert_eq!((rid, rcode), (id, RCODE_OK));
        foreign_ip = Some(ips[0]);
    }
    let Some(IpAddr::V4(foreign_ip)) = foreign_ip else {
        panic!("v4")
    };

    // CONNECTs to the fake addresses go out by name on the recorded route.
    let fake = Arc::new(Fake::default());
    let k = start_kernel(fake.clone(), Some(pool.clone())).await;
    let (rep, mut c) = connect_ip(k, ai_ip, 443).await;
    assert_eq!(rep, REP_OK);
    assert_eq!(roundtrip(&mut c, b"hi", 1).await, b"hi");
    let (rep, _c2) = connect_ip(k, foreign_ip, 443).await;
    assert_eq!(rep, REP_OK);
    // A fake address nobody was given is refused, never dialled.
    let unknown = (18u8..=19)
        .flat_map(|a| (0u8..=255).map(move |b| Ipv4Addr::new(198, a, b, 1)))
        .find(|ip| pool.lookup(IpAddr::V4(*ip)).is_none())
        .unwrap();
    let (rep, _c3) = connect_ip(k, unknown, 443).await;
    assert_eq!(rep, REP_NOT_ALLOWED);

    assert_eq!(
        fake.calls(),
        vec![
            (Some("ai".into()), "chat.openai.com:443".into()),
            (Some("proxy".into()), "polluted.example:443".into()),
        ]
    );
}
