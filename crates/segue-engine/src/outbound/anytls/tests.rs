//! Session-pool tests over an in-memory carrier, checked against the frames
//! `sing-anytls`'s server would read.

use super::session::MAX_SESSIONS;
use super::*;
use segue_proxy::anytls::{Command, FrameHeader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A carrier pair whose client half the pool owns and whose server half the
/// test reads and writes.
fn carrier_pair() -> (BoxedTransportStream, tokio::io::DuplexStream) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    (Box::new(client), server)
}

fn options() -> PoolOptions {
    PoolOptions {
        idle_check_interval: Duration::from_secs(60),
        idle_session_timeout: Duration::from_secs(60),
        min_idle_session: 0,
        client_metadata: None,
    }
}

fn target(network: RoutingNetwork) -> Target {
    Target::new(
        RoutingTargetAddr::Domain("example.test".into()),
        443,
        network,
    )
}

/// Read one frame from the server side.
async fn read_frame(server: &mut tokio::io::DuplexStream) -> (FrameHeader, Vec<u8>) {
    let mut header = [0u8; wire::HEADER_LENGTH];
    server.read_exact(&mut header).await.unwrap();
    let header = FrameHeader::decode(&header).unwrap().unwrap();
    let mut payload = vec![0u8; usize::from(header.length)];
    server.read_exact(&mut payload).await.unwrap();
    (header, payload)
}

/// Skip `Waste` frames, as the server's reader does.
async fn read_until_not_waste(server: &mut tokio::io::DuplexStream) -> (FrameHeader, Vec<u8>) {
    loop {
        let frame = read_frame(server).await;
        if frame.0.command != Command::Waste {
            return frame;
        }
    }
}

/// A carrier source that hands out one carrier and counts its calls. `open`
/// takes one future, so a retired-open test asserts the count after a fresh
/// `connect()` from this source.
struct CarrierSource {
    slot: Mutex<Option<BoxedTransportStream>>,
    calls: AtomicUsize,
}
impl CarrierSource {
    fn new(carrier: BoxedTransportStream) -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(Some(carrier)),
            calls: AtomicUsize::new(0),
        })
    }
    /// Counts when polled, not when built: a pool that serves the open from
    /// an idle session drops the future unstarted.
    async fn connect(&self) -> Result<BoxedTransportStream, CoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let taken = self.slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        taken.ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "no carrier left").into())
    }
}

#[tokio::test]
async fn settings_syn_and_data_go_out_in_one_padded_record() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"hi").await.unwrap();
    // The first record is padded to the scheme's counter-1 size, so the
    // frames arrive back to back: Settings, Syn, Push, then Waste.
    let (settings, payload) = read_frame(&mut server).await;
    assert_eq!(settings.command, Command::Settings);
    assert_eq!(settings.stream_id, 0);
    let map = wire::parse_settings(&payload).unwrap();
    assert_eq!(map["v"], "2");
    assert_eq!(map["client"], wire::CLIENT_VERSION);
    let (syn, _) = read_frame(&mut server).await;
    assert_eq!((syn.command, syn.stream_id), (Command::Syn, 1));
    let (push, payload) = read_frame(&mut server).await;
    assert_eq!((push.command, push.stream_id), (Command::Push, 1));
    assert_eq!(payload, b"hi");
    let (waste, _) = read_frame(&mut server).await;
    assert_eq!(waste.command, Command::Waste);
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn the_stream_target_is_the_first_bytes_of_the_stream() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    let header = wire::encode_stream_target(&target(RoutingNetwork::Tcp)).unwrap();
    stream.write_all(&header).await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    let (push, payload) = read_until_not_waste(&mut server).await;
    assert_eq!(push.command, Command::Push);
    assert_eq!(payload, header);
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_finished_stream_returns_its_session_to_the_idle_pool() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    {
        let mut stream = pool.open(source.connect()).await.unwrap();
        stream.write_all(b"one").await.unwrap();
        read_until_not_waste(&mut server).await; // Settings
        read_until_not_waste(&mut server).await; // Syn
        read_until_not_waste(&mut server).await; // Push
    }
    // The second open reuses the session: no second dial, and its Syn is
    // stream 2 on the same carrier.
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"two").await.unwrap();
    let (fin, _) = read_until_not_waste(&mut server).await;
    assert_eq!((fin.command, fin.stream_id), (Command::Fin, 1));
    let (syn, _) = read_until_not_waste(&mut server).await;
    assert_eq!((syn.command, syn.stream_id), (Command::Syn, 2));
    let (push, payload) = read_until_not_waste(&mut server).await;
    assert_eq!((push.command, push.stream_id), (Command::Push, 2));
    assert_eq!(payload, b"two");
    assert_eq!(source.calls.load(Ordering::Relaxed), 1);
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_server_fin_ends_the_stream_at_eof() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"x").await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    read_until_not_waste(&mut server).await; // Push
    // The server answers with data and then Fin.
    let mut reply = wire::push_frames(1, b"pong");
    reply.extend_from_slice(&wire::control_frame(Command::Fin, 1, &[]));
    server.write_all(&reply).await.unwrap();
    let mut received = Vec::new();
    stream.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"pong");
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_synack_error_fails_the_stream_with_the_server_message() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"x").await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    read_until_not_waste(&mut server).await; // Push
    server
        .write_all(&wire::control_frame(Command::SynAck, 1, b"no route"))
        .await
        .unwrap();
    let mut received = Vec::new();
    let error = stream.read_to_end(&mut received).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert!(error.to_string().contains("no route"));
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_server_alert_fails_every_stream_and_closes_the_session() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"x").await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    read_until_not_waste(&mut server).await; // Push
    server
        .write_all(&wire::control_frame(Command::Alert, 0, b"bad password"))
        .await
        .unwrap();
    let mut received = Vec::new();
    let error = stream.read_to_end(&mut received).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(error.to_string().contains("bad password"));
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_heartbeat_request_is_answered_on_the_same_stream_id() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"x").await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    read_until_not_waste(&mut server).await; // Push
    server
        .write_all(&wire::control_frame(Command::HeartRequest, 9, &[]))
        .await
        .unwrap();
    let (reply, _) = read_until_not_waste(&mut server).await;
    assert_eq!((reply.command, reply.stream_id), (Command::HeartResponse, 9));
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_server_padding_scheme_replaces_the_client_one() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    stream.write_all(b"x").await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    read_until_not_waste(&mut server).await; // Push
    // A scheme with `stop=1` turns padding off after the first packet.
    server
        .write_all(&wire::control_frame(
            Command::UpdatePaddingScheme,
            0,
            b"stop=1\n0=30-30",
        ))
        .await
        .unwrap();
    // Let the reader apply it before the next write.
    tokio::time::sleep(Duration::from_millis(20)).await;
    stream.write_all(b"y").await.unwrap();
    let (push, payload) = read_until_not_waste(&mut server).await;
    assert_eq!(push.command, Command::Push);
    assert_eq!(payload, b"y");
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn a_closed_pool_refuses_new_streams() {
    let (client, _server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    pool.close();
    assert!(pool.open(source.connect()).await.is_err());
}

#[tokio::test]
async fn udp_datagrams_are_length_prefixed_and_bounded() {
    let (client, mut server) = carrier_pair();
    let pool = Pool::new(options());
    let source = CarrierSource::new(client);
    let mut stream = pool.open(source.connect()).await.unwrap();
    let destination = target(RoutingNetwork::Udp);
    let mut header = wire::encode_stream_target(&wire::uot_request_target()).unwrap();
    header.extend_from_slice(&wire::encode_uot_request(&destination, true).unwrap());
    stream.write_all(&header).await.unwrap();
    read_until_not_waste(&mut server).await; // Settings
    read_until_not_waste(&mut server).await; // Syn
    let (push, payload) = read_until_not_waste(&mut server).await;
    assert_eq!(push.command, Command::Push);
    assert_eq!(payload, header);
    // The session's own framing is the UoT length prefix.
    let frame = wire::encode_uot_datagram(b"dns query").unwrap();
    assert_eq!(&frame[..2], &[0, 9]);
    assert_eq!(&frame[2..], b"dns query");
    drop(stream);
    pool.close();
}

#[tokio::test]
async fn the_pool_bounds_its_sessions() {
    let pool = Pool::new(options());
    let mut carriers = Vec::new();
    let mut streams = Vec::new();
    for _ in 0..MAX_SESSIONS {
        let (client, server) = carrier_pair();
        carriers.push(server);
        let source = CarrierSource::new(client);
        // Keep each session busy so it is not reused.
        streams.push(pool.open(source.connect()).await.unwrap());
    }
    let (client, _server) = carrier_pair();
    let source = CarrierSource::new(client);
    let error = pool.open(source.connect()).await.unwrap_err();
    assert!(error.to_string().contains("capacity"), "{error}");
    drop(streams);
    pool.close();
}
