//! Fixed reference vectors and a v3 relay over a real local rustls server.

use std::{io, net::SocketAddr, time::Duration};

use hmac::KeyInit;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{self as tokio_io, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::TlsAcceptor;

use super::*;

const PASSWORD: &[u8] = b"shadowtls-v3-vector";
const RANDOM: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const DUMMY: &[u8] = b"shadowtls-v3-dummy";
const REQUEST: &[u8] = b"inner-proxy-request";
const RESPONSE: &[u8] = b"inner-proxy-response";

fn password() -> Zeroizing<String> {
    Zeroizing::new(std::str::from_utf8(PASSWORD).unwrap().to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn client_hello_and_xor_vectors_match_sing_shadowtls() {
    let mut hello: Vec<u8> = (0..=255).collect();
    let random: [u8; 28] = (16..=43).collect::<Vec<_>>().try_into().unwrap();
    seal_session_id(PASSWORD, &mut hello, random).unwrap();
    let mut record = vec![HANDSHAKE, 3, 3, 0, 0];
    record[3..5].copy_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    assert_eq!(hex(&hello[67..71]), "b77a61e4");
    assert!(client_hello_tag_valid(PASSWORD, &record));
    assert!(!client_hello_tag_valid(b"wrong", &record));
    let mut wrong = record;
    wrong[67] ^= 1;
    assert!(!client_hello_tag_valid(PASSWORD, &wrong));
    assert_eq!(
        hex(&xor_wrap_key(PASSWORD, &RANDOM)),
        "c0515f15ba5d006afedc2d68f5766874aef13ed72300f04a1dc00745597b0955"
    );
    let mut wrapped = *b"first";
    xor_wrap(&mut wrapped, &xor_wrap_key(PASSWORD, &RANDOM));
    assert_eq!(hex(&wrapped), "a6382d66ce")
}

#[test]
fn framing_vectors_have_directional_chaining_and_transactional_open() {
    let mut write = FrameMac::new(PASSWORD, &RANDOM, b'C');
    let mut read = FrameMac::new(PASSWORD, &RANDOM, b'C');
    for (payload, expected) in [(&b"first"[..], "6883c0d8"), (&b"second"[..], "0a1ca088")] {
        let tag = write.seal(payload);
        assert!(read.open(payload, &tag));
        assert_eq!(hex(&tag), expected);
        let mut other = FrameMac::new(PASSWORD, &RANDOM, b'C');
        assert!(other.open(payload, &tag));
        assert_eq!(
            other.seal(payload),
            tag,
            "next seal includes the previous tag"
        );
    }
    let mut server = FrameMac::new(PASSWORD, &RANDOM, b'S');
    assert_eq!(hex(&server.seal(b"first")), "212eaef7");
    assert_eq!(hex(&server.seal(b"second")), "8b3cff74");

    let mut check = FrameMac::new(PASSWORD, &RANDOM, b'C');
    assert!(!check.open(b"wrong", &[0x68, 0x83, 0xc0, 0xd8]));
    let mut correct = FrameMac::new(PASSWORD, &RANDOM, b'C');
    assert_eq!(check.seal(b"first"), correct.seal(b"first"));
}

fn tls13_server_hello() -> Vec<u8> {
    let mut body = vec![SERVER_HELLO, 0, 0, 0, 3, 3];
    body.extend_from_slice(&RANDOM);
    body.push(32);
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&[0x13, 1, 0, 0, 0, 6, 0, 43, 0, 2, 3, 4]);
    let handshake_len = ((body.len() - 4) as u16).to_be_bytes();
    body[2..4].copy_from_slice(&handshake_len);
    let mut record = vec![HANDSHAKE, 3, 3, 0, 0];
    record[3..5].copy_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(&body);
    record
}

#[test]
fn server_hello_extraction_inspects_the_extensions() {
    let record = tls13_server_hello();
    assert_eq!(server_random(&record), Some(RANDOM));
    assert!(hello_supports_tls13(&record));
    let mut malformed = record;
    let index = malformed.len() - 2;
    malformed[index..].copy_from_slice(&[3, 3]);
    assert!(!hello_supports_tls13(&malformed));
}

#[tokio::test]
async fn framed_stream_enforces_tags_and_round_trips() {
    let (left, right) = tokio_io::duplex(128 * 1024);
    let (mut client, mut server) = (
        ShadowTlsStream::new(left, password(), RANDOM),
        ShadowTlsStream::new(right, password(), RANDOM),
    );
    client.write_all(b"first").await.unwrap();
    server.write_all(b"reply").await.unwrap();
    client.write_all(b"second").await.unwrap();
    let mut read = [0; 5];
    server.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"first");
    client.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"reply");
    let mut read = [0; 6];
    server.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"second");

    let tag = client.read_mac.seal(b"untrusted");
    let mut bad = vec![APPLICATION_DATA, 3, 3, 0, 18];
    bad.extend_from_slice(&tag);
    bad.extend_from_slice(b"untrusted");
    bad[5] ^= 1;
    assert!(client.open_record(&bad).is_err());
}

fn test_tls_configs() -> (Arc<rustls::ClientConfig>, Arc<rustls::ServerConfig>) {
    let generated = rcgen::generate_simple_self_signed(vec!["relay.test".to_owned()]).unwrap();
    let cert = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    (Arc::new(client), Arc::new(server))
}

fn client_config() -> ShadowTlsConfig {
    ShadowTlsConfig {
        password: password(),
        tls: TlsClientConfig {
            server_name: "relay.test".to_owned(),
            allow_insecure: false,
            pinned_peer_cert_sha256: Vec::new(),
            verify_peer_cert_by_name: Vec::new(),
            alpn: Vec::new(),
            fingerprint: Some("chrome".to_owned()),
            ech_config_list: None,
        },
    }
}

async fn record<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0; TLS_HEADER_LEN];
    stream.read_exact(&mut header).await?;
    let mut payload = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    stream.read_exact(&mut payload).await?;
    let mut record = header.to_vec();
    record.extend_from_slice(&payload);
    Ok(record)
}

/// Standalone v3 frontend logic, intentionally test-only. Its two directions
/// mirror copyByFrameUntilHMACMatches/copyByFrameWithModification.
async fn relay(
    frontend: TcpStream,
    upstream: TcpStream,
    cutover: oneshot::Receiver<()>,
) -> io::Result<()> {
    let (mut client_read, mut client_write) = frontend.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let hello = record(&mut client_read).await?;
    assert!(client_hello_tag_valid(PASSWORD, &hello));
    upstream_write.write_all(&hello).await?;
    let hello = record(&mut upstream_read).await?;
    let random = server_random(&hello).expect("ServerHello random");
    client_write.write_all(&hello).await?;

    let toward_tls = tokio::spawn(async move {
        let mut verify = FrameMac::new(PASSWORD, &random, b'C');
        loop {
            let frame = record(&mut client_read).await?;
            if frame.len() > TLS_HMAC_HEADER_LEN && frame[0] == APPLICATION_DATA {
                if verify.open(
                    &frame[TLS_HMAC_HEADER_LEN..],
                    &frame[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN],
                ) {
                    assert_eq!(&frame[TLS_HMAC_HEADER_LEN..], REQUEST);
                    break;
                }
                let mut handshake = <Sha1Hmac as KeyInit>::new_from_slice(PASSWORD).unwrap();
                handshake.update(&random);
                handshake.update(&frame[TLS_HMAC_HEADER_LEN..]);
                let expected = handshake.finalize().into_bytes()[..HMAC_LEN].to_vec();
                assert_eq!(&frame[TLS_HEADER_LEN..TLS_HMAC_HEADER_LEN], &expected);
            }
            upstream_write.write_all(&frame).await?;
            upstream_write.flush().await?;
        }
        upstream_write.shutdown().await?;
        io::Result::Ok(())
    });

    let mut handshake = <Sha1Hmac as KeyInit>::new_from_slice(PASSWORD).unwrap();
    handshake.update(&random);
    let xor_key = xor_wrap_key(PASSWORD, &random);
    let mut next = record(&mut upstream_read).await?;
    while next[0] != APPLICATION_DATA {
        client_write.write_all(&next).await?;
        next = record(&mut upstream_read).await?;
    }
    xor_wrap(&mut next[TLS_HEADER_LEN..], &xor_key);
    handshake.update(&next[TLS_HEADER_LEN..]);
    let tag = handshake.finalize().into_bytes()[..HMAC_LEN].to_vec();
    let mut transformed = negotiated_tag_frame(&next[..], &tag);
    client_write.write_all(&transformed).await?;
    client_write.flush().await?;

    toward_tls.await??;
    cutover.await.expect("dummy consumed by genuine TLS");
    let mut write = FrameMac::new(PASSWORD, &random, b'S');
    let tag = write.seal(RESPONSE);
    transformed = vec![APPLICATION_DATA, 3, 3];
    put_len(&mut transformed, RESPONSE.len() + HMAC_LEN);
    transformed.extend_from_slice(&tag);
    transformed.extend_from_slice(RESPONSE);
    client_write.write_all(&transformed).await?;
    client_write.flush().await?;
    Ok(())
}

fn put_len(record: &mut [u8], size: usize) {
    record[3..5].copy_from_slice(&(size as u16).to_be_bytes());
}

fn negotiated_tag_frame(record: &[u8], tag: &[u8]) -> Vec<u8> {
    let mut frame = record[..TLS_HEADER_LEN].to_vec();
    put_len(&mut frame, record.len() - TLS_HEADER_LEN + HMAC_LEN);
    frame.extend_from_slice(tag);
    frame.extend_from_slice(&record[TLS_HEADER_LEN..]);
    frame
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_handshakes_with_real_tls_then_carries_inner_protocol() {
    let (client_tls, server_tls) = test_tls_configs();
    let real_listener = TcpListener::bind(server_addr()).await.unwrap();
    let listener = TcpListener::bind(server_addr()).await.unwrap();
    let real_addr = real_listener.local_addr().unwrap();
    let frontend_addr = listener.local_addr().unwrap();
    let prepared = TlsConnector::with_pinned_client_config(client_tls)
        .prepare_shadow_tls_stream(&client_config())
        .unwrap();
    let (dummy_done_tx, dummy_done_rx) = oneshot::channel();
    let tls_server = tokio::spawn(async move {
        let (socket, _) = real_listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(server_tls).accept(socket).await.unwrap();
        tls.write_all(DUMMY).await.unwrap();
        tls.flush().await.unwrap();
        let mut dummy = [0; 17];
        tls.read_exact(&mut dummy).await.unwrap();
        assert_eq!(&dummy, DUMMY);
        dummy_done_tx.send(()).unwrap();
    });
    let client = tokio::spawn(async move {
        let socket = TcpStream::connect(frontend_addr).await.unwrap();
        let mut stream = tokio::time::timeout(
            Duration::from_secs(2),
            connect_shadow_tls_stream(Box::new(socket), prepared),
        )
        .await
        .unwrap()
        .unwrap();
        stream.write_all(REQUEST).await.unwrap();
        let mut response = [0; 20];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response, RESPONSE);
    });
    let (socket, _) = listener.accept().await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        relay(
            socket,
            TcpStream::connect(real_addr).await.unwrap(),
            dummy_done_rx,
        ),
    )
    .await
    .expect("ShadowTLS relay must not stall")
    .unwrap();
    client.await.unwrap();
    tls_server.await.unwrap();
}

fn server_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}
