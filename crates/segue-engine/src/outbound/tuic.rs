//! TUIC v5 outbound over the shared protected QUIC carrier.
//!
//! TCP uses CONNECT followed by payload on a bidirectional stream. A UDP
//! association has a bounded receive queue; native datagrams go through
//! bounded reassembly, while the QUIC mode sends each Packet on its own
//! unidirectional stream. Authentication uses TLS keying material export.
use super::*;
use segue_config::{TuicCongestionControl, TuicSettings, TuicUdpRelayMode};
use segue_proxy::tuic::{self as wire, Command, Packet};
use segue_transport::stream::quic::H3ConnectConfig;
use std::collections::HashMap;
use std::fmt;
use std::task;

use std::time::Instant;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PAYLOAD: usize = 65_535;
const MAX_STREAM_IN: usize = MAX_PAYLOAD + 384;
const TCP_STREAMS: usize = 100;
const UDP_ASSOCIATIONS: usize = 256;
const UDP_QUEUE: usize = 32;
const FRAME_SIZE: u16 = 1200;
const DATAGRAM_BUFFER: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TuicError {
    #[error("invalid TUIC configuration")]
    Configuration,
    #[error("TUIC socket protection failed")]
    Protection,
    #[error("TUIC QUIC connection failed")]
    Connect,
    #[error("TUIC operation timed out")]
    Timeout,
    #[error("TUIC connection is closed")]
    Closed,
    #[error("TUIC stream operation failed")]
    Stream,
    #[error("TUIC UDP is unsupported or too large")]
    Datagram,
    #[error("TUIC flow budget reached")]
    Limit,
}

#[derive(Clone, Debug)]
pub struct TuicOutbound(Arc<Owner>);

struct Owner {
    settings: TuicSettings,
    server: Target,
    tls: TlsClientConfig,
    quic: H3QuicConfig,
    socket_options: Option<Arc<segue_transport::SocketOptions>>,
    address_port: segue_config::AddressPortStrategy,
    derived_dialer: Mutex<Option<(TransportDialer, TransportDialer)>>,
    cached: Mutex<Option<Cached>>,
    connecting: AsyncMutex<()>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TuicOwner")
            .field("server", &self.server)
            .field("quic", &self.quic)
            .finish_non_exhaustive()
    }
}

struct Cached {
    client: Client,
    tls: segue_transport::TlsConnector,
}

impl Drop for Cached {
    fn drop(&mut self) {
        self.client.close();
    }
}

#[derive(Clone)]
struct Client {
    inner: Arc<Shared>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TuicClient")
            .field("live", &self.live())
            .field("udp_native", &self.inner.native)
            .finish_non_exhaustive()
    }
}

struct Shared {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    sessions: Mutex<Associations>,
    packet_id: std::sync::atomic::AtomicU32,
    tcp_slots: Arc<tokio::sync::Semaphore>,
    rebind: Mutex<Option<JoinHandle<()>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    closed: std::sync::atomic::AtomicBool,
    native: bool,
}

struct Associations {
    next_id: u16,
    sinks: HashMap<u16, mpsc::Sender<Packet>>,
    fragments: wire::Reassembler,
}

impl Shared {
    fn live(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.connection.close_reason().is_none()
    }

    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shutdown.send_replace(true);
        self.connection.close(quinn::VarInt::from_u32(0), b"");
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
        if let Some(task) = self
            .rebind
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            task.abort();
        }
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .drain(..)
        {
            task.abort();
        }
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .sinks
            .clear();
    }

    async fn uni(&self, bytes: Vec<u8>) -> Result<(), TuicError> {
        if !self.live() {
            return Err(TuicError::Closed);
        }
        let mut stream = self
            .connection
            .open_uni()
            .await
            .map_err(|_| TuicError::Stream)?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| TuicError::Stream)?;
        stream.finish().map_err(|_| TuicError::Stream)
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close();
    }
}

impl Client {
    fn live(&self) -> bool {
        self.inner.live()
    }

    fn close(&self) {
        self.inner.close();
    }

    async fn open_tcp(&self, target: &Target) -> Result<BoxedTransportStream, TuicError> {
        if !self.inner.live() {
            return Err(TuicError::Closed);
        }
        let permit = Arc::clone(&self.inner.tcp_slots)
            .acquire_owned()
            .await
            .map_err(|_| TuicError::Limit)?;
        let header =
            wire::encode(&Command::Connect(target.clone())).map_err(|_| TuicError::Stream)?;
        let (mut write, read) = self
            .inner
            .connection
            .open_bi()
            .await
            .map_err(|_| TuicError::Stream)?;
        write
            .write_all(&header)
            .await
            .map_err(|_| TuicError::Stream)?;
        Ok(Box::new(TuicStream {
            read,
            write,
            _permit: permit,
            client: self.clone(),
        }))
    }

    fn deliver(&self, packet: Packet) {
        let mut sessions = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        sessions.fragments.expire(Instant::now());
        let packet = if self.inner.native {
            match sessions.fragments.feed(&packet, Instant::now()) {
                Ok(Some(packet)) => packet,
                _ => return,
            }
        } else if packet.fragment_total == 1 {
            packet
        } else {
            return;
        };
        if let Some(sink) = sessions.sinks.get(&packet.association_id) {
            let _ = sink.try_send(packet);
        }
    }

    async fn open_udp(&self) -> Result<UdpAssociation, TuicError> {
        if !self.inner.live() {
            return Err(TuicError::Closed);
        }
        if self.inner.native && self.inner.connection.max_datagram_size().is_none() {
            return Err(TuicError::Datagram);
        }
        let mut sessions = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if sessions.sinks.len() >= UDP_ASSOCIATIONS {
            return Err(TuicError::Limit);
        }
        let id = sessions.next_id;
        if sessions.sinks.contains_key(&id) {
            return Err(TuicError::Limit);
        }
        sessions.next_id = id.wrapping_add(1);
        let (sender, receiver) = mpsc::channel(UDP_QUEUE);
        sessions.sinks.insert(id, sender);
        drop(sessions);
        Ok(UdpAssociation {
            client: self.clone(),
            id,
            receiver: AsyncMutex::new(receiver),
        })
    }
}

struct TuicStream {
    read: quinn::RecvStream,
    write: quinn::SendStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
    client: Client,
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut task::Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.read), context, output)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut task::Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // `SendStream::poll_write` returns `WriteError`; the trait method returns `io::Error`.
        AsyncWrite::poll_write(Pin::new(&mut self.write), context, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.write), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.write), context)
    }
}

impl TransportStream for TuicStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        context: &mut task::Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, context, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        context: &mut task::Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, context, data)
    }
}

pub(crate) struct UdpAssociation {
    client: Client,
    id: u16,
    receiver: AsyncMutex<mpsc::Receiver<Packet>>,
}

impl Drop for UdpAssociation {
    fn drop(&mut self) {
        self.client
            .inner
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .sinks
            .remove(&self.id);
        if let Ok(bytes) = wire::encode(&Command::Dissociate {
            association_id: self.id,
        }) {
            let client = self.client.clone();
            tokio::spawn(async move {
                let _ = client.inner.uni(bytes).await;
            });
        }
    }
}

impl UdpAssociation {
    pub(crate) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), TuicError> {
        if !self.client.live() {
            return Err(TuicError::Closed);
        }
        let id = self.client.inner.packet_id.fetch_add(1, Ordering::AcqRel) as u16;
        if self.client.inner.native {
            let limit = self
                .client
                .inner
                .connection
                .max_datagram_size()
                .ok_or(TuicError::Datagram)?;
            let packets = wire::fragment_datagrams(self.id, id, target, payload, limit)
                .map_err(|_| TuicError::Datagram)?;
            for packet in packets {
                self.client
                    .inner
                    .connection
                    .send_datagram_wait(bytes::Bytes::from(packet))
                    .await
                    .map_err(|_| TuicError::Datagram)?;
            }
        } else {
            let packet = Packet {
                association_id: self.id,
                packet_id: id,
                fragment_total: 1,
                fragment_id: 0,
                address: Some(wire::Address::from_target(target).map_err(|_| TuicError::Datagram)?),
                payload: payload.to_vec(),
            };
            let encoded =
                wire::encode(&Command::Packet(packet)).map_err(|_| TuicError::Datagram)?;
            self.client.inner.uni(encoded).await?;
        }
        Ok(())
    }

    pub(crate) async fn recv(&self) -> Result<(Target, Vec<u8>), TuicError> {
        if !self.client.live() {
            return Err(TuicError::Closed);
        }
        let packet = self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or(TuicError::Closed)?;
        let address = packet.address.ok_or(TuicError::Stream)?;
        Ok((address.routing(RoutingNetwork::Udp), packet.payload))
    }
}

impl TuicOutbound {
    pub(crate) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::Tuic(settings) = &config.settings else {
            return Err(CoreError::NoSupportedOutbound);
        };
        let StreamSecurity::Tls(tls) = &config.stream.security else {
            return Err(CoreError::UnsupportedOutboundSecurity);
        };
        let stream = &config.stream;
        let unsupported_mask = stream.tcp_fragment.is_some()
            || stream.tcp_header_custom.is_some()
            || stream.tcp_sudoku.is_some()
            || stream.tcp_xmc.is_some()
            || stream.udp_header_custom.is_some()
            || stream.udp_sudoku.is_some()
            || stream.udp_xdns.is_some()
            || stream.udp_realm.is_some()
            || stream.udp_xicmp.is_some()
            || stream.udp_noise.is_some()
            || stream.udp_salamander.is_some();
        if settings.port == 0
            || settings.password.is_empty()
            || settings.password.len() > 4096
            || stream.network != Network::Udp
            || config.proxy_settings.is_some()
            || !matches!(stream.transport, StreamTransport::Raw)
            || unsupported_mask
            || tls.ech_config_list.is_some()
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let server_name = match tls.server_name.clone().filter(|name| !name.is_empty()) {
            Some(name) => name,
            None => match &settings.server {
                TargetAddr::Domain(domain) => domain.clone(),
                TargetAddr::Ip(ip) => ip.to_string(),
            },
        };
        segue_transport::validate_tls_server_name(&server_name)
            .map_err(|_| CoreError::UnsupportedOutboundSecurity)?;
        let quic = H3QuicConfig {
            max_idle_timeout: Duration::from_secs(30),
            max_incoming_unidirectional_streams: Some(128),
            enable_early_data: settings.zero_rtt_handshake,
            congestion: match settings.congestion_control {
                TuicCongestionControl::Cubic => H3Congestion::Cubic,
                TuicCongestionControl::NewReno => H3Congestion::Reno,
                TuicCongestionControl::Bbr => H3Congestion::BbrStandard,
            },
            ..H3QuicConfig::default()
        };
        quic.diagnostics()
            .map_err(|_| CoreError::UnsupportedOutboundNetwork)?;
        let server = Target::new(
            match &settings.server {
                TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
                TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
            },
            settings.port,
            RoutingNetwork::Udp,
        );
        Ok(Self(Arc::new(Owner {
            server,
            quic,
            settings: settings.clone(),
            tls: TlsClientConfig {
                server_name,
                allow_insecure: tls.allow_insecure,
                pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                alpn: if tls.alpn.is_empty() {
                    vec!["h3".to_owned()]
                } else {
                    tls.alpn.clone()
                },
                fingerprint: None,
                ech_config_list: None,
            },
            socket_options: socket_options::compile(&config.stream),
            address_port: super::carrier::address_port_strategy(&config.stream),
            derived_dialer: Mutex::new(None),
            cached: Mutex::new(None),
            connecting: AsyncMutex::new(()),
            shutdown: tokio::sync::watch::channel(false).0,
        })))
    }

    pub(super) fn close(&self) {
        self.0.shutdown.send_replace(true);
        if let Some(cached) = self
            .0
            .cached
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            cached.client.close();
        }
    }

    fn socket_dialer<'a>(
        &self,
        dialer: &'a TransportDialer,
    ) -> std::borrow::Cow<'a, TransportDialer> {
        let Some(options) = &self.0.socket_options else {
            return std::borrow::Cow::Borrowed(dialer);
        };
        let mut cached = self
            .0
            .derived_dialer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((base, derived)) = cached.as_ref() {
            if base
                .tls_connector()
                .shares_session_context(dialer.tls_connector())
            {
                return std::borrow::Cow::Owned(derived.clone());
            }
        }
        let derived = dialer.clone().with_socket_options(Arc::clone(options));
        *cached = Some((dialer.clone(), derived.clone()));
        std::borrow::Cow::Owned(derived)
    }

    async fn client(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<Client, TuicError> {
        let mut shutdown = self.0.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(TuicError::Closed);
        }
        let dialer = self.socket_dialer(dialer);
        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(TuicError::Closed),
            result = tokio::time::timeout(DIAL_TIMEOUT, self.client_inner(resolver, &dialer)) => {
                result.map_err(|_| TuicError::Timeout)?
            }
        }
    }

    async fn client_inner(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<Client, TuicError> {
        let _admission = self.0.connecting.lock().await;
        {
            let cached = self
                .0
                .cached
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(cached) = cached.as_ref().filter(|cached| cached.client.live()) {
                if !cached.tls.shares_session_context(dialer.tls_connector()) {
                    return Err(TuicError::Configuration);
                }
                return Ok(cached.client.clone());
            }
        }
        let candidates = super::address_port::resolve_server(
            &self.0.server,
            self.0.address_port,
            resolver,
            dialer,
        )
        .await
        .map_err(|_| TuicError::Connect)?;
        let mut error = TuicError::Connect;
        for address in candidates.into_iter().take(3) {
            match Box::pin(self.connect(address, dialer)).await {
                Ok(client) => {
                    let mut cached = self
                        .0
                        .cached
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    if *self.0.shutdown.borrow() {
                        client.close();
                        return Err(TuicError::Closed);
                    }
                    *cached = Some(Cached {
                        client: client.clone(),
                        tls: dialer.tls_connector().clone(),
                    });
                    return Ok(client);
                }
                Err(error @ (TuicError::Configuration | TuicError::Protection)) => {
                    return Err(error)
                }
                Err(current) => error = current,
            }
        }
        Err(error)
    }

    async fn connect(
        &self,
        address: SocketAddr,
        dialer: &TransportDialer,
    ) -> Result<Client, TuicError> {
        let alpns: Vec<&[u8]> = self.0.tls.alpn.iter().map(String::as_bytes).collect();
        let tls = dialer
            .tls_connector()
            .quic_client_config_for_alpns(&self.0.tls, &alpns, self.0.quic.enable_early_data)
            .map_err(|_| TuicError::Configuration)?;
        let config = H3ConnectConfig {
            remote_addr: address,
            server_name: self.0.tls.server_name.clone(),
            tls_config: tls,
            socket_protector: dialer.socket_protector_arc(),
            quic: self.0.quic.clone(),
            realm: None,
            network_changes: Some(dialer.network_changes().clone()),
        };
        let connected = segue_transport::stream::quic::connect(
            config,
            None,
            Some((DATAGRAM_BUFFER, DATAGRAM_BUFFER, FRAME_SIZE)),
        )
        .await
        .map_err(|error| match error {
            segue_transport::stream::quic::H3Error::Transport(
                TransportError::SocketProtection(_),
            ) => TuicError::Protection,
            _ => TuicError::Connect,
        })?;
        // Own both handles until the authenticated client takes over.
        let cleaned = PendingConnection {
            endpoint: connected.endpoint.clone(),
            connection: connected.connection.clone(),
            owned: true,
        };
        let client = self
            .start_client(
                connected.endpoint,
                connected.connection,
                connected.rebind,
                connected.zero_rtt_accepted,
            )
            .await?;
        cleaned.disarm();
        Ok(client)
    }

    async fn start_client(
        &self,
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        rebind: Option<JoinHandle<()>>,
        zero_rtt_accepted: Option<quinn::ZeroRttAccepted>,
    ) -> Result<Client, TuicError> {
        let mut token = zeroize::Zeroizing::new([0_u8; 32]);
        connection
            .export_keying_material(
                &mut token[..],
                self.0.settings.uuid.as_bytes(),
                self.0.settings.password.as_bytes(),
            )
            .map_err(|_| TuicError::Stream)?;
        let auth = wire::encode(&Command::Authenticate {
            uuid: *self.0.settings.uuid.as_bytes(),
            token: *token,
        })
        .map_err(|_| TuicError::Stream)?;
        let mut stream = connection.open_uni().await.map_err(|_| TuicError::Stream)?;
        stream
            .write_all(&auth)
            .await
            .map_err(|_| TuicError::Stream)?;
        stream.finish().map_err(|_| TuicError::Stream)?;
        if let Some(accepted) = zero_rtt_accepted {
            // Resolves to whether the peer accepted 0-RTT; a dropped sender is false.
            if !accepted.await {
                connection.close(quinn::VarInt::from_u32(0xfffffff1), b"");
                return Err(TuicError::Connect);
            }
        }
        let fragments = wire::Reassembler::new(FRAGMENT_TIMEOUT, MAX_PAYLOAD)
            .map_err(|_| TuicError::Configuration)?;
        let client = Client {
            inner: Arc::new(Shared {
                endpoint,
                connection,
                sessions: Mutex::new(Associations {
                    next_id: 0,
                    sinks: HashMap::new(),
                    fragments,
                }),
                packet_id: std::sync::atomic::AtomicU32::new(1),
                tcp_slots: Arc::new(tokio::sync::Semaphore::new(TCP_STREAMS)),
                rebind: Mutex::new(rebind),
                tasks: Mutex::new(Vec::new()),
                shutdown: tokio::sync::watch::channel(false).0,
                closed: std::sync::atomic::AtomicBool::new(false),
                native: self.0.settings.udp_relay_mode == TuicUdpRelayMode::Native,
            }),
        };
        // All waited-on I/O belongs to tasks held by Shared. close() aborts
        // them deterministically, including any stream awaiting FIN.
        let receive = tokio::spawn(receive_packets(client.clone()));
        let heartbeat = tokio::spawn(heartbeats(client.clone(), self.0.settings.heartbeat));
        *client
            .inner
            .tasks
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = vec![receive, heartbeat];
        Ok(client)
    }

    pub(crate) async fn open_tcp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        // `Client::open_tcp` already returns `BoxedTransportStream`. Boxing it
        // again would ask `Box<dyn TransportStream>` to implement the trait.
        Ok(self
            .client(resolver, dialer)
            .await?
            .open_tcp(target)
            .await?)
    }

    pub(crate) async fn open_udp(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<UdpAssociation, CoreError> {
        Ok(self.client(resolver, dialer).await?.open_udp().await?)
    }
}

struct PendingConnection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    owned: bool,
}

impl PendingConnection {
    fn disarm(mut self) {
        self.owned = false;
    }
}

impl Drop for PendingConnection {
    fn drop(&mut self) {
        if self.owned {
            self.connection
                .close(quinn::VarInt::from_u32(0xfffffff1), b"");
            self.endpoint
                .close(quinn::VarInt::from_u32(0xfffffff1), b"");
        }
    }
}

async fn receive_packets(client: Client) {
    let mut shutdown = client.inner.shutdown.subscribe();
    loop {
        let packet = if client.inner.native {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                bytes = client.inner.connection.read_datagram() => match bytes {
                    Ok(bytes) => wire::decode_datagram(&bytes),
                    Err(_) => break,
                },
            }
        } else {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                command = read_uni_command(&client.inner.connection) => match command {
                    Ok(command) => Ok(command),
                    Err(()) => break,
                },
            }
        };
        match packet {
            Ok(Command::Packet(packet)) => client.deliver(packet),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
}

async fn read_uni_command(connection: &quinn::Connection) -> Result<Command, ()> {
    let mut stream = connection.accept_uni().await.map_err(|_| ())?;
    let bytes = stream.read_to_end(MAX_STREAM_IN).await.map_err(|_| ())?;
    wire::decode_datagram(&bytes).map_err(|_| ())
}

async fn heartbeats(client: Client, period: Duration) {
    let mut shutdown = client.inner.shutdown.subscribe();
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let encoded = bytes::Bytes::from(wire::encode(&Command::Heartbeat).expect("valid heartbeat"));
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = interval.tick() => {
                let _ = client.inner.connection.send_datagram(encoded.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests;
