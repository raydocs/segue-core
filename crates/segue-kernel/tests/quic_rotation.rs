//! R7 #3: a real QUIC connection (quinn) through a relay that applies the
//! kernel's per-flow [`ConnGuard`], with the server rotating its
//! connection IDs (issued inside the encryption, NEW_CONNECTION_ID with
//! Retire Prior To). The established connection must keep working; when
//! another route carries QUIC to the same server, the unknown ID must be
//! refused explicitly (the front end then fails the flow fast), never
//! silently black-holed.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ConnectionIdGenerator, Endpoint, EndpointConfig, TokioRuntime};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use segue_kernel::quic::{ConnGuard, InitialSniffer, Quic, QuicRoutes, ReplyWatch, Step};
use tokio::net::UdpSocket;

/// How often the server replaces its connection IDs.
const ROTATE: Duration = Duration::from_millis(200);

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
    let client = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(ctls).unwrap()));
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

struct Relay {
    addr: SocketAddr,
    refused: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
    /// Short-header DCID prefixes (8 bytes) the client used.
    short_ids: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// One kernel UDP flow: the first datagrams classify the connection, then
/// a [`ConnGuard`] with a route claim in `routes` decides every datagram;
/// every reply is shown to the guard's [`ReplyWatch`] first.
async fn relay(server: SocketAddr, routes: QuicRoutes, tag: &str) -> Relay {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    back.connect(server).await.unwrap();
    let r = Relay {
        addr: front.local_addr().unwrap(),
        refused: Arc::default(),
        dropped: Arc::default(),
        short_ids: Arc::default(),
    };
    let (refused, dropped, ids) = (r.refused.clone(), r.dropped.clone(), r.short_ids.clone());
    let watch: Arc<Mutex<Option<ReplyWatch>>> = Arc::default();
    let tag = tag.to_owned();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        let mut sniffer = InitialSniffer::default();
        let mut held = Vec::new();
        let mut guard: Option<ConnGuard<Vec<u8>>> = None;
        let mut client: Option<SocketAddr> = None;
        loop {
            let (n, from) = front.recv_from(&mut b).await.unwrap();
            let d = b[..n].to_vec();
            if client.is_none() {
                client = Some(from);
                let (front, back, w) = (front.clone(), back.clone(), watch.clone());
                tokio::spawn(async move {
                    let mut b = vec![0u8; 65536];
                    while let Ok(n) = back.recv(&mut b).await {
                        if let Some(w) = w.lock().unwrap().as_ref() {
                            w.observe(&b[..n]);
                        }
                        let _ = front.send_to(&b[..n], from).await;
                    }
                });
            }
            let Some(g) = guard.as_mut() else {
                held.push(d.clone());
                match sniffer.push(&d) {
                    Quic::NeedMore => continue,
                    Quic::Domain(name) => assert_eq!(name, "localhost"),
                    other => panic!("not classified: {other:?}"),
                }
                let g = ConnGuard::new(Some(&sniffer), true).with_route(
                    routes.clone(),
                    server,
                    Some(tag.clone()),
                );
                *watch.lock().unwrap() = Some(g.watch());
                guard = Some(g);
                for h in held.drain(..) {
                    back.send(&h).await.unwrap();
                }
                continue;
            };
            if d[0] & 0x80 == 0 && d.len() > 9 {
                let mut ids = ids.lock().unwrap();
                if !ids.iter().any(|c| c[..] == d[1..9]) {
                    ids.push(d[1..9].to_vec());
                }
            }
            match g.push(d.clone(), &d, |q| q == &Quic::Domain("localhost".into())) {
                Step::Forward(ds) => {
                    for x in ds {
                        back.send(&x).await.unwrap();
                    }
                }
                Step::Hold => {}
                Step::Drop(_) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
                Step::Refuse(_) => {
                    refused.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });
    r
}

async fn echo(conn: &quinn::Connection, msg: &[u8]) -> Result<Vec<u8>, String> {
    let (mut tx, mut rx) = conn.open_bi().await.map_err(|e| e.to_string())?;
    tx.write_all(msg).await.map_err(|e| e.to_string())?;
    tx.finish().map_err(|e| e.to_string())?;
    rx.read_to_end(1 << 16).await.map_err(|e| e.to_string())
}

fn client(cfg: quinn::ClientConfig) -> Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(2).try_into().unwrap()));
    let mut cfg = cfg;
    cfg.transport_config(Arc::new(transport));
    let mut ep = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(cfg);
    ep
}

#[tokio::test(flavor = "current_thread")]
async fn established_quic_survives_server_cid_rotation() {
    let (scfg, ccfg) = configs();
    let server = server(scfg);
    let routes = QuicRoutes::default();
    let r = relay(server, routes, "p1").await;
    let ep = client(ccfg);
    let conn = ep.connect(r.addr, "localhost").unwrap().await.unwrap();
    for i in 0..15u8 {
        let got = tokio::time::timeout(Duration::from_secs(3), echo(&conn, &[i; 100]))
            .await
            .unwrap_or_else(|_| panic!("request {i} timed out"))
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(got, vec![i; 100]);
        tokio::time::sleep(ROTATE / 2).await;
    }
    assert!(
        r.short_ids.lock().unwrap().len() >= 3,
        "the client switched IDs: {:?}",
        r.short_ids.lock().unwrap()
    );
    assert_eq!(r.refused.load(Ordering::Relaxed), 0);
    assert_eq!(r.dropped.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn rotation_on_a_contested_server_is_refused_not_black_holed() {
    let (scfg, ccfg) = configs();
    let server = server(scfg);
    let routes = QuicRoutes::default();
    let r = relay(server, routes.clone(), "p1").await;
    let ep = client(ccfg.clone());
    let conn = ep.connect(r.addr, "localhost").unwrap().await.unwrap();
    assert_eq!(echo(&conn, b"hi").await.unwrap(), b"hi");
    // Another flow carries QUIC to the same server by another outbound.
    let other = relay(server, routes, "p2").await;
    let ep2 = client(ccfg);
    // (Its own later rotations are contested by p1 the same way.)
    let _conn2 = ep2.connect(other.addr, "localhost").unwrap().await.unwrap();
    // The first connection's next ID is refused as soon as it is used.
    for _ in 0..30 {
        if r.refused.load(Ordering::Relaxed) > 0 {
            break;
        }
        let _ = tokio::time::timeout(Duration::from_millis(200), echo(&conn, b"x")).await;
        tokio::time::sleep(ROTATE / 2).await;
    }
    assert!(r.refused.load(Ordering::Relaxed) > 0, "rotated ID refused");
    assert_eq!(r.dropped.load(Ordering::Relaxed), 0, "never a silent drop");
}
