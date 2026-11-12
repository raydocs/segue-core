//! Connection flow control over streams the receiver stops and the sender
//! then resets, as a Hysteria2 client does to every download it cancels.
//!
//! The vendored quinn-proto once credited a stopped stream's unread bytes to
//! the connection window twice, once on STOP_SENDING and again on the
//! peer's RESET_STREAM, so each cancelled download let the peer keep that
//! much more data in flight and buffered memory grew without bound.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::{sleep, timeout};

/// The client's connection receive window. Each stream's window is far
/// larger, so only the connection window limits what the server can send.
const CONNECTION_WINDOW: u32 = 64 * 1024;
const STREAM_WINDOW: u32 = 16 * 1024 * 1024;
const ROUNDS: usize = 6;

async fn connected_pair() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("generate test certificate");
    let certificate = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .expect("server certificate");
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).expect("QUIC server TLS"),
    ));
    let server = quinn::Endpoint::server(
        server_config,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .expect("bind QUIC server");
    let server_addr = server.local_addr().expect("QUIC server address");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate).expect("add test root");
    let client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut transport = quinn::TransportConfig::default();
    transport
        .receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW))
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW));
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).expect("QUIC client TLS"),
    ));
    client_config.transport_config(Arc::new(transport));
    let mut client = quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("bind QUIC client");
    client.set_default_client_config(client_config);

    let (client_connection, server_connection) = tokio::join!(
        async {
            client
                .connect(server_addr, "localhost")
                .expect("start handshake")
                .await
                .expect("client handshake")
        },
        async {
            server
                .accept()
                .await
                .expect("incoming connection")
                .await
                .expect("server handshake")
        },
    );
    (server, client, server_connection, client_connection)
}

/// Writes to `send` until the connection's flow control stops accepting
/// data, and returns how many bytes it accepted.
async fn write_until_blocked(send: &mut quinn::SendStream) -> usize {
    let chunk = [0u8; 4096];
    let mut written = 0;
    while let Ok(result) = timeout(Duration::from_millis(300), send.write(&chunk)).await {
        written += result.expect("write before the stream is stopped");
    }
    written
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_and_reset_streams_do_not_inflate_the_connection_window() {
    let (_server, _client, server_connection, client_connection) = connected_pair().await;

    let mut accepted = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let mut send = server_connection.open_uni().await.expect("open stream");
        let writer = tokio::spawn(async move {
            let written = write_until_blocked(&mut send).await;
            (send, written)
        });
        let mut recv = client_connection.accept_uni().await.expect("accept stream");
        let (send, written) = writer.await.expect("writer task");
        accepted.push(written);

        // Let everything written arrive unread, then cancel the download.
        sleep(Duration::from_millis(100)).await;
        recv.stop(0u32.into()).expect("stop the stream");
        drop(recv);
        // The server learns of STOP_SENDING; dropping the stopped stream
        // sends RESET_STREAM at the offset it reached.
        let stopped = timeout(Duration::from_secs(5), send.stopped())
            .await
            .expect("STOP_SENDING arrives");
        assert!(matches!(stopped, Ok(Some(_))), "{stopped:?}");
        drop(send);
        // Let the client process the reset and return its credit.
        sleep(Duration::from_millis(100)).await;
    }

    let window = CONNECTION_WINDOW as usize;
    for (round, &written) in accepted.iter().enumerate() {
        assert!(
            written >= window / 2,
            "round {round}: only {written} bytes accepted: {accepted:?}"
        );
        assert!(
            written <= window,
            "round {round}: {written} bytes in flight exceed the {window}-byte \
             connection window: {accepted:?}"
        );
    }
}
