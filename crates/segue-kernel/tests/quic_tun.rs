//! r8 N1–N3, §5.2a.2: real QUIC (quinn) through the TUN front end.
//!
//! The client endpoint is an ordinary UDP socket; a bridge wraps each of
//! its datagrams in an IPv4/UDP packet from an app address to the chosen
//! destination, feeds it to a [`TunStack`] built by
//! [`TunStack::for_kernel`], and hands UDP replies back (ICMP is recorded).
//! The kernel's UDP sessions reach a quinn echo server on loopback whose
//! connection IDs expire every [`ROTATE`] (NEW_CONNECTION_ID with Retire
//! Prior To, inside the encryption).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ConnectionIdGenerator, Endpoint, EndpointConfig, TokioRuntime};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use segue_kernel::dial::{Datagrams, DialError, Dialer, Stream, UdpSession};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::policy::{Policy, PolicyStore};
use segue_kernel::rules::{Action, CidrTable, RuleSet};
use segue_kernel::socks::Kernel;
use segue_kernel::tun::{PacketIo, TunStack};
use segue_kernel::udp::{Udp, UdpSettings};
use segue_routing::TargetAddr;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Packet, IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How often the server replaces its connection IDs.
const ROTATE: Duration = Duration::from_millis(200);
/// The app's address on the TUN; its port is the client socket's own, so
/// a client that rebinds starts a new 5-tuple.
const APP: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2));

fn configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"t".to_vec()];
    let server =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let mut ctls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ctls.alpn_protocols = vec![b"t".to_vec()];
    let mut client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(2).try_into().unwrap()));
    client.transport_config(Arc::new(transport));
    (server, client)
}

/// Echo server whose connection IDs expire every [`ROTATE`].
fn server(cfg: quinn::ServerConfig) -> SocketAddr {
    let mut ep = EndpointConfig::default();
    ep.cid_generator(|| {
        let mut g = quinn_proto::RandomConnectionIdGenerator::new(8);
        g.set_lifetime(ROTATE);
        Box::new(g) as Box<dyn ConnectionIdGenerator>
    });
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let ep = Endpoint::new(ep, Some(cfg), sock, Arc::new(TokioRuntime)).unwrap();
    tokio::spawn(async move {
        while let Some(inc) = ep.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = inc.await else { return };
                while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                    tokio::spawn(async move {
                        let data = rx.read_to_end(1 << 16).await.unwrap_or_default();
                        let _ = tx.write_all(&data).await;
                        let _ = tx.finish();
                    });
                }
            });
        }
    });
    addr
}

/// Dials every UDP flow to the quinn server, recording the destination.
struct ToServer {
    server: SocketAddr,
    udp_dials: Mutex<Vec<(Option<String>, TargetAddr, u16)>>,
}

struct Session {
    sock: UdpSocket,
    from: (TargetAddr, u16),
}

#[async_trait]
impl UdpSession for Session {
    fn max_payload(&self, _: &TargetAddr, _: u16) -> usize {
        1472
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
impl Dialer for ToServer {
    async fn dial(&self, _: Option<&str>, _: &TargetAddr, _: u16) -> Result<Stream, DialError> {
        Err(DialError("no TCP here".into()))
    }
    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        self.udp_dials
            .lock()
            .unwrap()
            .push((tag.map(str::to_owned), addr.clone(), port));
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(self.server).await.unwrap();
        Ok(Box::new(Session {
            sock,
            from: (addr.clone(), port),
        }))
    }
}

struct ChanIo {
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

#[async_trait]
impl PacketIo for ChanIo {
    async fn recv(&self) -> std::io::Result<Bytes> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("closed"))
    }
    async fn send(&self, pkt: Bytes) -> std::io::Result<()> {
        self.tx
            .send(pkt)
            .await
            .map_err(|_| std::io::Error::other("closed"))
    }
}

fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        unreachable!()
    };
    let caps = ChecksumCapabilities::default();
    let ip = Ipv4Repr {
        src_addr: s,
        dst_addr: d,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    };
    let mut buf = vec![0u8; 20 + 8 + payload.len()];
    let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip.emit(&mut p, &caps);
    UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    }
    .emit(
        &mut UdpPacket::new_unchecked(p.payload_mut()),
        &IpAddress::from(s),
        &IpAddress::from(d),
        payload.len(),
        |b| b.copy_from_slice(payload),
        &caps,
    );
    buf
}

/// What the TUN sent back to the app.
#[derive(Default)]
struct Seen {
    /// The client's first datagram left the bridge at this time.
    first_sent: Option<Instant>,
    /// (type, code, time) of every ICMP error.
    icmp: Vec<(u8, u8, Instant)>,
    replies: usize,
    /// Every client source port seen (one per 5-tuple).
    app_ports: std::collections::BTreeSet<u16>,
}

struct World {
    dialer: Arc<ToServer>,
    pool: Arc<FakeIpPool>,
    /// The client endpoint's peer address: the bridge.
    bridge: SocketAddr,
    /// Where the bridge sends the client's datagrams on the TUN.
    dst: Arc<Mutex<Option<SocketAddr>>>,
    seen: Arc<Mutex<Seen>>,
    client: quinn::ClientConfig,
}

async fn world() -> World {
    world_with(|_| {}).await
}

async fn world_with(server_cfg: impl FnOnce(&mut quinn::ServerConfig)) -> World {
    let (mut scfg, client) = configs();
    server_cfg(&mut scfg);
    let dialer = Arc::new(ToServer {
        server: server(scfg),
        udp_dials: Mutex::new(Vec::new()),
    });
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
    let kernel = Arc::new(Kernel {
        policy: PolicyStore::inline(Policy::inline(
            RuleSet::new(Vec::new(), Action::Proxy("p1".into())),
            CidrTable::default(),
        )),
        dialer: dialer.clone(),
        fake_ip: Some(pool.clone()),
        sniff: None,
        udp: Some(Arc::new(Udp::new(UdpSettings::default()))),
        hidden: Default::default(),
        flows: None,
    });
    let (to_stack, rx) = mpsc::channel(256);
    let (tx, mut from_stack) = mpsc::channel::<Bytes>(256);
    let io = Arc::new(ChanIo {
        rx: tokio::sync::Mutex::new(rx),
        tx,
    });
    tokio::spawn(TunStack::for_kernel(kernel, None).run(io));

    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let bridge = sock.local_addr().unwrap();
    let dst: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let peer: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
    // Client → TUN.
    {
        let (sock, dst, seen, peer) = (sock.clone(), dst.clone(), seen.clone(), peer.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                *peer.lock().unwrap() = Some(from);
                let Some(to) = *dst.lock().unwrap() else {
                    continue;
                };
                seen.lock()
                    .unwrap()
                    .first_sent
                    .get_or_insert_with(Instant::now);
                seen.lock().unwrap().app_ports.insert(from.port());
                let pkt = udp_packet(SocketAddr::new(APP, from.port()), to, &buf[..n]);
                if to_stack.send(Bytes::from(pkt)).await.is_err() {
                    return;
                }
            }
        });
    }
    // TUN → client.
    {
        let seen = seen.clone();
        tokio::spawn(async move {
            while let Some(pkt) = from_stack.recv().await {
                let Ok(ip) = Ipv4Packet::new_checked(&pkt[..]) else {
                    continue;
                };
                match ip.next_header() {
                    IpProtocol::Udp => {
                        let Ok(u) = UdpPacket::new_checked(ip.payload()) else {
                            continue;
                        };
                        seen.lock().unwrap().replies += 1;
                        // Back to the client socket the flow came from.
                        let to = peer
                            .lock()
                            .unwrap()
                            .map(|p| SocketAddr::new(p.ip(), u.dst_port()));
                        if let Some(to) = to {
                            let _ = sock.send_to(u.payload(), to).await;
                        }
                    }
                    IpProtocol::Icmp => {
                        let Ok(i) = Icmpv4Packet::new_checked(ip.payload()) else {
                            continue;
                        };
                        let mut s = seen.lock().unwrap();
                        s.icmp
                            .push((u8::from(i.msg_type()), i.msg_code(), Instant::now()));
                    }
                    _ => {}
                }
            }
        });
    }
    World {
        dialer,
        pool,
        bridge,
        dst,
        seen,
        client,
    }
}

impl World {
    fn client(&self) -> Endpoint {
        let mut ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(self.client.clone());
        ep
    }
}

async fn echo(conn: &quinn::Connection, msg: &[u8]) -> Result<Vec<u8>, String> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
    tx.write_all(msg).await.map_err(|e| e.to_string())?;
    tx.finish().map_err(|e| e.to_string())?;
    rx.read_to_end(1 << 16).await.map_err(|e| e.to_string())
}

/// (a) To a fake-IP name the flow is routed by that name and pinned: the
/// connection keeps working across 15 server CID rotations (3 s at one
/// rotation per 200 ms), with no CID tracking anywhere.
#[tokio::test]
async fn quic_to_fake_ip_name_survives_server_cid_rotation() {
    let w = world().await;
    let ip = w.pool.assign("localhost", 0).unwrap();
    *w.dst.lock().unwrap() = Some(SocketAddr::new(IpAddr::V4(ip), 443));
    let ep = w.client();
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        ep.connect(w.bridge, "localhost").unwrap(),
    )
    .await
    .expect("handshake timed out")
    .expect("handshake");
    for i in 0..15u8 {
        let got = tokio::time::timeout(Duration::from_secs(3), echo(&conn, &[i; 100]))
            .await
            .unwrap_or_else(|_| panic!("request {i} timed out"))
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(got, vec![i; 100]);
        tokio::time::sleep(ROTATE).await;
    }
    assert_eq!(
        w.dialer.udp_dials.lock().unwrap().clone(),
        vec![(
            Some("p1".to_string()),
            TargetAddr::Domain("localhost".into()),
            443
        )],
        "one flow, dialled by name, for the whole connection"
    );
    assert!(w.seen.lock().unwrap().icmp.is_empty());
}

/// (b) To a real IP the very first datagram is refused with ICMP port
/// unreachable (on 443 and elsewhere), nothing is dialled and no QUIC
/// reply ever reaches the client, so its connect fails.
#[tokio::test]
async fn quic_to_real_ip_is_refused_at_the_first_datagram() {
    for port in [443, 4433] {
        let w = world().await;
        *w.dst.lock().unwrap() = Some(SocketAddr::new("8.8.8.8".parse().unwrap(), port));
        let ep = w.client();
        let connect = ep.connect(w.bridge, "localhost").unwrap();
        let r = tokio::time::timeout(Duration::from_secs(5), connect).await;
        assert!(
            !matches!(r, Ok(Ok(_))),
            "{port}: connected through a real IP"
        );
        let s = w.seen.lock().unwrap();
        let first = s.first_sent.expect("client sent");
        let (t, code, at) = *s.icmp.first().expect("ICMP refusal");
        assert_eq!((t, code), (3, 3), "{port}: port unreachable");
        assert!(
            at - first < Duration::from_millis(200),
            "{port}: not immediate"
        );
        assert_eq!(s.replies, 0, "{port}");
        assert!(w.dialer.udp_dials.lock().unwrap().is_empty(), "{port}");
    }
}

/// (c) A first batch that coalesces quinn's real Initial with a short
/// header of another connection hidden behind it is refused whole on a
/// real IP: the first packet decides for the datagram (RFC 9000 §12.2).
#[tokio::test]
async fn coalesced_first_batch_with_hidden_packet_is_refused() {
    let w = world().await;
    // Capture quinn's real first datagram.
    let cap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ep = w.client();
    let _connecting = ep.connect(cap.local_addr().unwrap(), "localhost").unwrap();
    let mut initial = vec![0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), cap.recv_from(&mut initial))
        .await
        .unwrap()
        .unwrap();
    initial.truncate(n);
    assert_eq!(initial[0] & 0x80, 0x80, "quinn sends a long header first");
    let mut batch = initial.clone();
    batch.extend_from_slice(b"\x40\x99\x99\x99\x99\x99\x99\x99\x99 hidden short header");
    // Fixed bit greased away too (quinn's default as a server; clients may).
    let mut greased = batch.clone();
    greased[0] &= !0x40;
    for (name, d) in [("coalesced", batch), ("greased", greased)] {
        let w = world().await;
        *w.dst.lock().unwrap() = Some("8.8.8.8:8443".parse().unwrap());
        let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        raw.send_to(&d, w.bridge).await.unwrap();
        let mut waited = 0;
        while w.seen.lock().unwrap().icmp.is_empty() && waited < 50 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        let s = w.seen.lock().unwrap();
        assert_eq!(
            s.icmp.iter().map(|(t, c, _)| (*t, *c)).collect::<Vec<_>>(),
            vec![(3, 3)],
            "{name}"
        );
        assert!(w.dialer.udp_dials.lock().unwrap().is_empty(), "{name}");
    }
}

/// r10 N1: a QUIC connection opened after the kernel started goes through
/// a fake-IP flow and stays on fake-IP flows: the client only ever learns
/// the fake address. When it migrates (rebinds to a new local port, a new
/// 5-tuple) the new flow is again a fake-IP flow, routed and dialled by
/// name, and the connection carries on. A server preferred address (a
/// real IP inside the encrypted transport parameters, RFC 9000 §9.6) is
/// not followed by quinn: nothing is ever sent there. No flow is dialled
/// by IP and no ICMP is sent.
#[tokio::test]
async fn quic_via_fake_ip_never_lands_on_a_real_ip_flow_after_migration() {
    let watch = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    watch.set_nonblocking(true).unwrap();
    let preferred = match watch.local_addr().unwrap() {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(_) => unreachable!(),
    };
    let w = world_with(|c| {
        c.preferred_address_v4(Some(preferred));
    })
    .await;
    let ip = w.pool.assign("localhost", 0).unwrap();
    *w.dst.lock().unwrap() = Some(SocketAddr::new(IpAddr::V4(ip), 443));
    let ep = w.client();
    let conn = tokio::time::timeout(
        Duration::from_secs(5),
        ep.connect(w.bridge, "localhost").unwrap(),
    )
    .await
    .expect("handshake timed out")
    .expect("handshake");
    // Traffic on the first path and after each of three migrations (r11
    // checklist 4: the round after the third rebind must carry data too).
    let mut ports = vec![ep.local_addr().unwrap().port()];
    for round in 0..4u8 {
        for i in 0..4u8 {
            let msg = [round * 16 + i; 64];
            let got = tokio::time::timeout(Duration::from_secs(3), echo(&conn, &msg))
                .await
                .unwrap_or_else(|_| panic!("round {round} request {i} timed out"))
                .unwrap_or_else(|e| panic!("round {round} request {i}: {e}"));
            assert_eq!(got, msg);
        }
        if round < 3 {
            // Migrate: a new local socket, so a new 5-tuple on the TUN.
            ep.rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap();
            ports.push(ep.local_addr().unwrap().port());
        }
    }
    // A large transfer on the last path as well, both ways.
    let big: Vec<u8> = (0..60_000u32).map(|i| i as u8).collect();
    let got = tokio::time::timeout(Duration::from_secs(10), echo(&conn, &big))
        .await
        .expect("bulk echo after the third rebind timed out")
        .expect("bulk echo after the third rebind");
    assert_eq!(got, big);
    let mut b = [0u8; 2048];
    assert!(
        watch.recv_from(&mut b).is_err(),
        "nothing sent to the preferred address"
    );
    let dials = w.dialer.udp_dials.lock().unwrap().clone();
    assert!(dials.len() >= 4, "one flow per 5-tuple: {dials:?}");
    assert!(
        dials.iter().all(|d| *d
            == (
                Some("p1".to_string()),
                TargetAddr::Domain("localhost".into()),
                443
            )),
        "every flow dialled by name: {dials:?}"
    );
    let s = w.seen.lock().unwrap();
    assert_eq!(ports.len(), 4);
    for p in &ports {
        assert!(
            s.app_ports.contains(p),
            "path {p} not seen: {:?}",
            s.app_ports
        );
    }
    assert!(s.icmp.is_empty());
}
