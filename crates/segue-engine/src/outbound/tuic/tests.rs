use super::*;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const PASSWORD: &str = "synthetic-local-tuic-loopback-password";

fn configured(port: u16, mode: TuicUdpRelayMode) -> OutboundConfig {
    let text = format!(
        r#"{{"outbounds":[{{"protocol":"tuic","settings":{{
            "server":"127.0.0.1","port":{port},"uuid":"{UUID}","password":"{PASSWORD}",
            "congestion_control":"new_reno","udp_relay_mode":"{}","heartbeat":"10s"
        }},"streamSettings":{{"network":"udp","security":"tls",
            "tlsSettings":{{"serverName":"localhost","alpn":["h3"]}}}}}}]}}"#,
        match mode {
            TuicUdpRelayMode::Native => "native",
            TuicUdpRelayMode::Quic => "quic",
        },
    );
    segue_config::parse_xray_json(&text)
        .unwrap()
        .config
        .outbounds
        .remove(0)
}

struct TestTls {
    connector: segue_transport::TlsConnector,
    server: quinn::ServerConfig,
}

fn tls(alpn: &[&[u8]]) -> TestTls {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = cert.cert.der().clone();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
    )
    .unwrap();
    server.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
    let server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server).unwrap(),
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    TestTls {
        connector: segue_transport::TlsConnector::with_pinned_client_config(Arc::new(client)),
        server,
    }
}

struct MockEndpoint {
    address: SocketAddr,
    tls: TestTls,
    // The accept task owns the endpoint, which keeps the server socket open.
    task: JoinHandle<()>,
}

async fn server(mode: TuicUdpRelayMode) -> MockEndpoint {
    let tls = tls(&[b"h3"]);
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(256 * 1024));
    transport.datagram_send_buffer_size(256 * 1024);
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(128));
    let mut config = tls.server.clone();
    config.transport_config(Arc::new(transport));
    let endpoint =
        quinn::Endpoint::server(config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = endpoint.local_addr().unwrap();
    let native = mode == TuicUdpRelayMode::Native;
    let task = tokio::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let connection = incoming.await.unwrap();
        // QUIC does not order streams against each other: the client's CONNECT
        // bi stream can be accepted before its Authenticate uni stream is read.
        // Like the reference servers, hold every other stream until the
        // connection has authenticated (the client sends Authenticate first).
        let mut authenticated = {
            let mut stream = connection.accept_uni().await.unwrap();
            let bytes = stream.read_to_end(MAX_STREAM_IN).await.unwrap();
            let Ok(Command::Authenticate { uuid, token }) = wire::decode_datagram(&bytes) else {
                panic!("the first uni stream is not Authenticate");
            };
            assert_eq!(uuid, *uuid::Uuid::parse_str(UUID).unwrap().as_bytes());
            let mut exported = [0_u8; 32];
            connection
                .export_keying_material(&mut exported, &uuid, PASSWORD.as_bytes())
                .unwrap();
            assert_eq!(token, exported);
            true
        };
        let mut associated = false;
        loop {
            tokio::select! {
                stream = connection.accept_uni() => {
                    let Ok(mut stream) = stream else { break };
                    let Ok(bytes) = stream.read_to_end(MAX_STREAM_IN).await else { break };
                    match wire::decode_datagram(&bytes) {
                        Ok(Command::Authenticate { uuid, token }) => {
                            assert_eq!(uuid, *uuid::Uuid::parse_str(UUID).unwrap().as_bytes());
                            let mut exported = [0_u8; 32];
                            connection
                                .export_keying_material(&mut exported, &uuid, PASSWORD.as_bytes())
                                .unwrap();
                            assert_eq!(token, exported);
                            authenticated = true;
                        }
                        Ok(Command::Packet(packet)) => {
                            assert!(authenticated);
                            associated = true;
                            // Each QUIC-mode command occupies its own complete stream.
                            let mut reply = packet;
                            reply.fragment_total = 1;
                            reply.fragment_id = 0;
                            let bytes = wire::encode(&Command::Packet(reply)).unwrap();
                            let mut stream = connection.open_uni().await.unwrap();
                            stream.write_all(&bytes).await.unwrap();
                            stream.finish().unwrap();
                        }
                        Ok(Command::Dissociate { association_id: _ }) => {
                            assert!(associated);
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                stream = connection.accept_bi() => {
                    let Ok((mut write, mut read)) = stream else { break };
                    assert!(authenticated);
                    // Read IPv4 CONNECT exactly: every subsequent byte is the
                    // relayed TCP payload. No server response header is expected.
                    let mut command = [0_u8; 9];
                    read.read_exact(&mut command).await.unwrap();
                    assert_eq!(command[..3], [5, 1, 1]);
                    assert_eq!(&command[3..7], &[127, 0, 0, 1]);
                    assert_eq!(&command[7..], &[1, 187]);
                    let mut payload = [0; 8];
                    read.read_exact(&mut payload).await.unwrap();
                    assert_eq!(&payload, b"loopback");
                    write.write_all(&payload).await.unwrap();
                }
                datagram = connection.read_datagram() => {
                    let Ok(bytes) = datagram else { break };
                    match wire::decode_datagram(&bytes) {
                        Ok(Command::Packet(packet)) if native => {
                            assert!(authenticated);
                            associated = true;
                            let bytes = wire::encode(&Command::Packet(packet)).unwrap();
                            connection.send_datagram(bytes::Bytes::from(bytes)).unwrap();
                        }
                        Ok(Command::Heartbeat) => {}
                        _ => {}
                    }
                }
            }
        }
    });
    MockEndpoint { address, tls, task }
}

async fn loopback(mode: TuicUdpRelayMode) {
    let server = server(mode).await;
    let outbound = TuicOutbound::new(&configured(server.address.port(), mode)).unwrap();
    let dns = segue_transport::SystemDnsResolver;
    let dialer = TransportDialer::with_tls_connector(server.tls.connector.clone());
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        443,
        RoutingNetwork::Tcp,
    );
    let mut stream = outbound.open_tcp(&target, &dns, &dialer).await.unwrap();
    stream.write_all(b"loopback").await.unwrap();
    stream.flush().await.unwrap();
    let mut reply = [0; 8];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"loopback");
    drop(stream);
    let udp = outbound.open_udp(&dns, &dialer).await.unwrap();
    let target = Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        53,
        RoutingNetwork::Udp,
    );
    udp.send(&target, b"one UDP datagram").await.unwrap();
    let (source, payload) = udp.recv().await.unwrap();
    assert_eq!(source, target);
    assert_eq!(payload, b"one UDP datagram");
    drop(udp);
    // Dissociate is a valid uni stream, not a datagram in either relay mode.
    tokio::time::sleep(Duration::from_millis(40)).await;
    outbound.close();
    server.task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_udp_and_tcp_use_one_authenticated_quic_connection() {
    tokio::time::timeout(Duration::from_secs(15), loopback(TuicUdpRelayMode::Native))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_udp_streams_use_an_authenticated_uni_stream() {
    tokio::time::timeout(Duration::from_secs(15), loopback(TuicUdpRelayMode::Quic))
        .await
        .unwrap();
}
#[test]
fn config_defaults_and_never_treats_quic_as_a_tcp_stream() {
    for control in ["cubic", "new_reno", "bbr"] {
        let mut config = configured(443, TuicUdpRelayMode::Native);
        let OutboundSettings::Tuic(settings) = &mut config.settings else {
            panic!("TUIC")
        };
        settings.congestion_control = match control {
            "cubic" => TuicCongestionControl::Cubic,
            "new_reno" => TuicCongestionControl::NewReno,
            _ => TuicCongestionControl::Bbr,
        };
        assert!(TuicOutbound::new(&config).is_ok());
    }
    let config = configured(443, TuicUdpRelayMode::Native);
    assert!(TuicOutbound::new(&config).is_ok());
    let mut insecure = config.clone();
    let StreamSecurity::Tls(tls) = &mut insecure.stream.security else {
        panic!("TLS")
    };
    tls.allow_insecure = true;
    assert!(TuicOutbound::new(&insecure).is_ok());
    let mut custom_alpn = config.clone();
    let StreamSecurity::Tls(tls) = &mut custom_alpn.stream.security else {
        panic!("TLS")
    };
    tls.alpn = vec!["tuic".into()];
    assert!(TuicOutbound::new(&custom_alpn).is_ok());
    let mut config = config;
    config.stream.network = Network::Tcp;
    assert!(TuicOutbound::new(&config).is_err());
}

/// A carrier that records every `poll_write` and never yields read data.
#[derive(Default)]
struct Recorder {
    writes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl AsyncRead for Recorder {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.lock().unwrap().push(input.to_vec());
        Poll::Ready(Ok(input.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for Recorder {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, output)
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write(cx, input)
    }
}

/// The CONNECT header must share the first payload's write, as sing-box's
/// TUIC client does, instead of costing its own round trip.
#[tokio::test]
async fn connect_header_leaves_with_the_first_payload() {
    let recorder = Recorder::default();
    let writes = recorder.writes.clone();
    let header = wire::encode(&Command::Connect(Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        443,
        RoutingNetwork::Tcp,
    )))
    .unwrap();
    let mut stream = coalesced(Box::new(recorder), &header);
    stream.write_all(b"payload").await.unwrap();
    stream.flush().await.unwrap();
    let writes = writes.lock().unwrap();
    assert_eq!(writes.len(), 1, "header and payload share one write");
    assert_eq!(writes[0], [header.as_slice(), b"payload"].concat());
}

/// With no payload, the header still leaves once the wait expires.
#[tokio::test]
async fn connect_header_leaves_alone_when_no_payload_follows() {
    let recorder = Recorder::default();
    let writes = recorder.writes.clone();
    let header = wire::encode(&Command::Connect(Target::new(
        RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        443,
        RoutingNetwork::Tcp,
    )))
    .unwrap();
    let mut stream = coalesced(Box::new(recorder), &header);
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(TUIC_FIRST_PAYLOAD_WAIT * 4, stream.read(&mut byte)).await;
    assert!(read.is_err(), "the recorder never yields read data");
    let writes = writes.lock().unwrap();
    assert_eq!(writes.len(), 1, "the header left on its own");
    assert_eq!(writes[0], header);
}
