//! Xray-core Vision bug classes #7438, #7164 and #7369, exercised through the
//! public padding and stream API the engine relays on.

use std::io;

use bytes::BytesMut;
use segue_proxy::vless::{unpad_vision_block, VisionCommand, VisionPadding, VisionStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const USER_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[test]
fn oversized_padding_round_trips_and_short_headers_do_not_panic() {
    let user = [3_u8; 16];
    for len in [8_171_usize, 8_192, 8_213, 12_288, 20_000, 65_535] {
        let mut padding = VisionPadding::new(user, [900, 500, 900, 256]);
        let payload = BytesMut::from(vec![0xAB; len].as_slice());
        let padded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            padding
                .pad(payload.clone(), VisionCommand::Continue, 0)
                .unwrap_or_else(|error| panic!("len {len}: {error}"))
        }))
        .unwrap_or_else(|_| panic!("pad panicked at {len}"));
        let unpadded = std::panic::catch_unwind(|| unpad_vision_block(&padded, &user))
            .unwrap_or_else(|_| panic!("unpad panicked at {len}"))
            .unwrap_or_else(|error| panic!("len {len}: {error}"));
        assert_eq!(unpadded.payload, payload, "len {len}");
    }

    let mut padding = VisionPadding::new(user, [0, 0, 0, 0]);
    let too_big = BytesMut::from(vec![0_u8; u16::MAX as usize + 1].as_slice());
    assert!(padding.pad(too_big, VisionCommand::Continue, 0).is_err());

    for len in 0..64 {
        let buffer = vec![0x3C_u8; len];
        assert!(
            std::panic::catch_unwind(|| unpad_vision_block(&buffer, &user)).is_ok(),
            "panicked on a {len}-byte header"
        );
    }
    for header in [
        &[][..],
        &[0x02][..],
        &[VisionCommand::Continue as u8, 0xFF, 0xFF, 0xFF, 0xFF][..],
        &[VisionCommand::Direct as u8, 0x00, 0x01, 0xFF, 0xFF, 0x00][..],
    ] {
        let result = std::panic::catch_unwind(|| unpad_vision_block(header, &user));
        assert!(result.is_ok() && result.unwrap().is_err(), "{header:?}");
    }
}

#[tokio::test]
async fn oversized_vision_writes_round_trip() {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    let mut writer = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    let mut reader = VisionStream::new(server, USER_ID, [0, 0, 0, 0]);
    for size in [8_213_usize, 12_288, 20_000, 65_535, 70_000] {
        let payload = vec![0x5A; size];
        writer.write_all(&payload).await.unwrap();
        let mut got = vec![0; size];
        reader.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "size {size}");
    }
}

#[tokio::test]
async fn two_tls_app_records_after_handshake_switch_to_direct_copy() {
    let (mut stream, mut server) = tls13_ready().await;
    let record_a = tls_app_record(b"alpha-record");
    let record_b = tls_app_record(b"beta-record");
    let mut both = record_a.clone();
    both.extend_from_slice(&record_b);
    stream.write_all(&both).await.unwrap();
    stream.flush().await.unwrap();

    let unpadded = read_frame(&mut server, record_a.len()).await;
    assert_eq!(unpadded.0, VisionCommand::Direct);
    assert_eq!(unpadded.1, record_a);
    let mut raw = vec![0; record_b.len()];
    server.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw, record_b);
}

#[tokio::test]
async fn split_tls_records_still_switch_to_direct_copy() {
    let (mut stream, mut server) = tls13_ready().await;
    let record_a = tls_app_record(b"alpha-record");
    let record_b = tls_app_record(b"beta-record-payload");
    let split = 4;
    let mut first = record_a.clone();
    first.extend_from_slice(&record_b[..split]);
    stream.write_all(&first).await.unwrap();
    stream.flush().await.unwrap();

    let unpadded = read_frame(&mut server, record_a.len()).await;
    assert_eq!(unpadded.0, VisionCommand::Direct);
    assert_eq!(unpadded.1, record_a);
    let mut raw_head = vec![0; split];
    server.read_exact(&mut raw_head).await.unwrap();
    assert_eq!(raw_head, record_b[..split]);

    stream.write_all(&record_b[split..]).await.unwrap();
    stream.flush().await.unwrap();
    let mut raw_tail = vec![0; record_b.len() - split];
    server.read_exact(&mut raw_tail).await.unwrap();
    assert_eq!(raw_tail, record_b[split..]);
}

#[tokio::test]
async fn short_padding_header_at_eof_is_an_error() {
    let (client, mut server) = tokio::io::duplex(64);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    server.write_all(&[0, 1, 2]).await.unwrap();
    drop(server);
    let mut output = [0_u8; 8];
    let error = stream.read(&mut output).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

fn tls_app_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&[0x17, 0x03, 0x03]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn read_frame(
    server: &mut tokio::io::DuplexStream,
    payload_len: usize,
) -> (VisionCommand, Vec<u8>) {
    let mut frame = vec![0; 5 + payload_len];
    server.read_exact(&mut frame).await.unwrap();
    let unpadded = unpad_vision_block(&frame, &USER_ID).unwrap();
    (unpadded.command, unpadded.payload.to_vec())
}

async fn tls13_ready() -> (
    VisionStream<tokio::io::DuplexStream>,
    tokio::io::DuplexStream,
) {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    let client_hello = b"\x16\x03\x01\x00\x01\x01";
    stream.write_all(client_hello).await.unwrap();
    stream.flush().await.unwrap();
    let mut handshake_frame = vec![0; 16 + 5 + client_hello.len()];
    server.read_exact(&mut handshake_frame).await.unwrap();

    let server_hello = tls13_server_hello();
    let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
    let frame = padding
        .pad(
            BytesMut::from(server_hello.as_slice()),
            VisionCommand::Continue,
            0,
        )
        .unwrap();
    server.write_all(&frame).await.unwrap();
    let mut received = vec![0; server_hello.len()];
    stream.read_exact(&mut received).await.unwrap();
    (stream, server)
}

fn tls13_server_hello() -> Vec<u8> {
    let mut hello = vec![0; 90];
    let record_len = hello.len() - 5;
    hello[0] = 0x16;
    hello[1] = 0x03;
    hello[2] = 0x03;
    hello[3] = (record_len >> 8) as u8;
    hello[4] = record_len as u8;
    hello[5] = 0x02;
    hello[43] = 0;
    hello[44] = 0x13;
    hello[45] = 0x01;
    hello[70..76].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    hello
}
