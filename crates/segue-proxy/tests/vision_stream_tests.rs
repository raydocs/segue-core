use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use segue_proxy::vless::{
    unpad_vision_block, VisionCommand, VisionPadding, VisionStream, VisionStreamIo,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const USER_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[tokio::test]
async fn vision_stream_write_emits_padded_blocks() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);

    stream.write_all(b"hello vision").await.unwrap();
    stream.flush().await.unwrap();

    let mut padded = vec![0; 16 + 5 + "hello vision".len()];
    server.read_exact(&mut padded).await.unwrap();
    let unpadded = unpad_vision_block(&padded, &USER_ID).unwrap();

    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], b"hello vision");
}

#[tokio::test]
async fn vision_stream_write_ends_padding_without_tls13_confirmation() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    let client_hello = b"\x16\x03\x01\x00\x01\x01";
    let application_data = b"\x17\x03\x03\x00\x01a";

    stream.write_all(client_hello).await.unwrap();
    stream.flush().await.unwrap();

    let mut handshake_frame = vec![0; 16 + 5 + client_hello.len()];
    server.read_exact(&mut handshake_frame).await.unwrap();
    let unpadded = unpad_vision_block(&handshake_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], client_hello);

    stream.write_all(application_data).await.unwrap();
    stream.flush().await.unwrap();

    let mut end_frame = vec![0; 5 + application_data.len()];
    server.read_exact(&mut end_frame).await.unwrap();
    let unpadded = unpad_vision_block(&end_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::End);
    assert_eq!(&unpadded.payload[..], application_data);

    stream.write_all(b"normal next").await.unwrap();
    stream.flush().await.unwrap();

    let mut normal = vec![0; "normal next".len()];
    server.read_exact(&mut normal).await.unwrap();
    assert_eq!(&normal[..], b"normal next");
}

#[tokio::test]
async fn vision_stream_write_uses_direct_after_tls13_server_hello() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    let client_hello = b"\x16\x03\x01\x00\x01\x01";
    let server_hello = tls13_server_hello_fixture();
    let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
    let server_hello_frame = padding
        .pad(
            BytesMut::from(server_hello.as_slice()),
            VisionCommand::Continue,
            0,
        )
        .unwrap();
    let application_data = b"\x17\x03\x03\x00\x01a";

    stream.write_all(client_hello).await.unwrap();
    stream.flush().await.unwrap();
    let mut handshake_frame = vec![0; 16 + 5 + client_hello.len()];
    server.read_exact(&mut handshake_frame).await.unwrap();
    let unpadded = unpad_vision_block(&handshake_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], client_hello);

    server.write_all(&server_hello_frame).await.unwrap();
    let mut received_server_hello = vec![0; server_hello.len()];
    stream.read_exact(&mut received_server_hello).await.unwrap();
    assert_eq!(received_server_hello, server_hello);

    stream.write_all(application_data).await.unwrap();
    stream.flush().await.unwrap();

    let mut direct_frame = vec![0; 5 + application_data.len()];
    server.read_exact(&mut direct_frame).await.unwrap();
    let unpadded = unpad_vision_block(&direct_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Direct);
    assert_eq!(&unpadded.payload[..], application_data);

    stream.write_all(b"direct raw").await.unwrap();
    stream.flush().await.unwrap();

    let mut raw = vec![0; "direct raw".len()];
    server.read_exact(&mut raw).await.unwrap();
    assert_eq!(&raw[..], b"direct raw");
}

#[tokio::test]
async fn vision_stream_write_keeps_mixed_tls_prefix_padded() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    let change_cipher_spec = b"\x14\x03\x03\x00\x01\x01";
    let application_data = b"\x17\x03\x03\x00\x01a";
    let mixed = [change_cipher_spec.as_slice(), application_data.as_slice()].concat();

    stream.write_all(&mixed).await.unwrap();
    stream.flush().await.unwrap();

    let mut continue_frame = vec![0; 16 + 5 + mixed.len()];
    server.read_exact(&mut continue_frame).await.unwrap();
    let unpadded = unpad_vision_block(&continue_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], mixed);
}

/// Xray-core #7164: two complete TLS application records in one read after the
/// handshake must switch to direct copy. The second record is already past
/// the boundary, so it is raw, not another padded frame.
#[tokio::test]
async fn two_tls_app_records_in_one_write_switch_to_direct_copy() {
    let (mut stream, mut server) = tls13_vision_ready().await;
    let record_a = tls_app_record(b"alpha-record");
    let record_b = tls_app_record(b"beta-record");
    let mut both = record_a.clone();
    both.extend_from_slice(&record_b);

    stream.write_all(&both).await.unwrap();
    stream.flush().await.unwrap();

    let mut direct_frame = vec![0; 5 + record_a.len()];
    server.read_exact(&mut direct_frame).await.unwrap();
    let unpadded = unpad_vision_block(&direct_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Direct);
    assert_eq!(&unpadded.payload[..], record_a.as_slice());

    let mut raw = vec![0; record_b.len()];
    server.read_exact(&mut raw).await.unwrap();
    assert_eq!(raw, record_b);

    stream.write_all(b"after switch").await.unwrap();
    stream.flush().await.unwrap();
    let mut after = vec![0; "after switch".len()];
    server.read_exact(&mut after).await.unwrap();
    assert_eq!(&after[..], b"after switch");
}

/// The same bug with the record cut between writes: the first buffer ends
/// inside the second record, so a per-buffer completeness check never passes.
#[tokio::test]
async fn tls_records_split_across_writes_still_switch_to_direct_copy() {
    let (mut stream, mut server) = tls13_vision_ready().await;
    let record_a = tls_app_record(b"alpha-record");
    let record_b = tls_app_record(b"beta-record-payload");
    let split = 4;
    let mut first = record_a.clone();
    first.extend_from_slice(&record_b[..split]);

    stream.write_all(&first).await.unwrap();
    stream.flush().await.unwrap();

    let mut direct_frame = vec![0; 5 + record_a.len()];
    server.read_exact(&mut direct_frame).await.unwrap();
    let unpadded = unpad_vision_block(&direct_frame, &USER_ID).unwrap();
    assert_eq!(unpadded.command, VisionCommand::Direct);
    assert_eq!(&unpadded.payload[..], record_a.as_slice());

    let mut raw_head = vec![0; split];
    server.read_exact(&mut raw_head).await.unwrap();
    assert_eq!(raw_head, record_b[..split]);

    stream.write_all(&record_b[split..]).await.unwrap();
    stream.flush().await.unwrap();
    let mut raw_tail = vec![0; record_b.len() - split];
    server.read_exact(&mut raw_tail).await.unwrap();
    assert_eq!(raw_tail, record_b[split..]);
}

/// Xray-core #7438: a buffer bigger than the legacy 8192-byte frame, and one
/// bigger than a single u16 vision frame, must round-trip. No panic, no loss.
#[tokio::test]
async fn oversized_vision_buffers_round_trip_without_loss() {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    let mut writer = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    let mut reader = VisionStream::new(server, USER_ID, [0, 0, 0, 0]);

    for size in [8_171_usize, 8_192, 8_213, 12_288, 20_000, 65_535, 70_000] {
        let payload = vec![0x5A; size];
        writer.write_all(&payload).await.unwrap();
        let mut got = vec![0; size];
        reader.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "size {size}");
    }
}

/// Xray-core #7369: a short or truncated padding header is an error, not a
/// slice panic, including when the peer then closes.
#[tokio::test]
async fn short_padding_header_at_eof_errors_without_panic() {
    let (client, mut server) = tokio::io::duplex(64);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);
    server.write_all(&[0, 1, 2]).await.unwrap();
    drop(server);
    let mut output = [0_u8; 8];
    let error = stream.read(&mut output).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn vision_stream_read_returns_unpadded_payload() {
    let (client, server) = tokio::io::duplex(4096);
    let mut sender = VisionStream::new(server, USER_ID, [0, 0, 0, 0]);
    let mut receiver = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);

    sender.write_all(b"reply bytes").await.unwrap();
    sender.shutdown().await.unwrap();

    let mut received = Vec::new();
    receiver.read_to_end(&mut received).await.unwrap();

    assert_eq!(received, b"reply bytes");
}

#[tokio::test]
async fn vision_stream_reads_direct_bytes_after_direct_block_via_direct_io() {
    let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
    let direct = padding
        .pad(BytesMut::from(&b"padded"[..]), VisionCommand::Direct, 0)
        .unwrap();
    let inner = DirectIoFixture::new(direct.to_vec(), b"direct raw".to_vec());
    let mut stream = VisionStream::new(inner, USER_ID, [0, 0, 0, 0]);

    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();

    assert_eq!(received, b"paddeddirect raw");
    assert!(stream.get_ref().direct_read_used);
}

#[tokio::test]
async fn vision_stream_reads_normal_bytes_after_end_block_via_normal_io() {
    let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
    let end = padding
        .pad(BytesMut::from(&b"padded"[..]), VisionCommand::End, 0)
        .unwrap();
    let inner = DirectIoFixture::new([end.to_vec(), b"normal next".to_vec()].concat(), Vec::new());
    let mut stream = VisionStream::new(inner, USER_ID, [0, 0, 0, 0]);

    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();

    assert_eq!(received, b"paddednormal next");
    assert!(!stream.get_ref().direct_read_used);
}

#[tokio::test]
async fn vision_stream_writes_direct_bytes_after_direct_block_via_direct_io() {
    let server_hello = tls13_server_hello_fixture();
    let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
    let server_hello_frame = padding
        .pad(
            BytesMut::from(server_hello.as_slice()),
            VisionCommand::Continue,
            0,
        )
        .unwrap();
    let inner = DirectIoFixture::new(server_hello_frame.to_vec(), Vec::new());
    let mut stream = VisionStream::new(inner, USER_ID, [0, 0, 0, 0]);
    let application_data = b"\x17\x03\x03\x00\x01a";

    let mut received_server_hello = vec![0; server_hello.len()];
    stream.read_exact(&mut received_server_hello).await.unwrap();
    assert_eq!(received_server_hello, server_hello);

    stream.write_all(application_data).await.unwrap();
    stream.write_all(b"direct raw").await.unwrap();
    stream.flush().await.unwrap();

    let inner = stream.into_inner();
    assert_eq!(&inner.direct_written[..], b"direct raw");
    assert!(inner.direct_write_used);
}

fn tls_app_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.extend_from_slice(&[0x17, 0x03, 0x03]);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn tls13_vision_ready() -> (
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

    let server_hello = tls13_server_hello_fixture();
    let mut padding = VisionPadding::new(USER_ID, [0, 0, 0, 0]);
    let server_hello_frame = padding
        .pad(
            BytesMut::from(server_hello.as_slice()),
            VisionCommand::Continue,
            0,
        )
        .unwrap();
    server.write_all(&server_hello_frame).await.unwrap();
    let mut received = vec![0; server_hello.len()];
    stream.read_exact(&mut received).await.unwrap();
    assert_eq!(received, server_hello);
    (stream, server)
}

fn tls13_server_hello_fixture() -> Vec<u8> {
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

#[derive(Default)]
struct DirectIoFixture {
    normal_read: Vec<u8>,
    direct_read: Vec<u8>,
    direct_written: Vec<u8>,
    direct_read_used: bool,
    direct_write_used: bool,
}

impl DirectIoFixture {
    fn new(normal_read: Vec<u8>, direct_read: Vec<u8>) -> Self {
        Self {
            normal_read,
            direct_read,
            ..Self::default()
        }
    }
}

impl AsyncRead for DirectIoFixture {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let len = output.remaining().min(this.normal_read.len());
        output.put_slice(&this.normal_read[..len]);
        this.normal_read.drain(..len);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DirectIoFixture {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(input.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl VisionStreamIo for DirectIoFixture {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.direct_read_used = true;
        let len = output.remaining().min(this.direct_read.len());
        output.put_slice(&this.direct_read[..len]);
        this.direct_read.drain(..len);
        Poll::Ready(Ok(()))
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.direct_write_used = true;
        this.direct_written.extend_from_slice(input);
        Poll::Ready(Ok(input.len()))
    }
}
