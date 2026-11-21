//! The only place the kernel touches the outer engine.
//!
//! Everything above this module sees `Dialer`; swapping the engine for
//! another implementation means rewriting this file only.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use segue_config::parse_xray_json;
use segue_engine::{
    open_tcp_stream_with_resolver_and_dialer, OutboundRouter, OutboundUdpSession, TcpOutbound,
};
use segue_routing::{Network, Target, TargetAddr};
use segue_transport::{
    BoxedTransportStream, ConnectorConfig, HappyEyeballsConfig, SystemDnsResolver, TransportDialer,
};
use serde_json::{json, Value};
use tokio::net::UdpSocket;

#[derive(Debug)]
pub struct DialError(pub String);

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DialError {}

/// A connected byte stream to the requested target.
pub type Stream = BoxedTransportStream;

#[async_trait]
pub trait Dialer: Send + Sync {
    /// Dial `addr:port` through outbound `tag`, or directly when `tag` is None.
    async fn dial(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError>;

    /// Open a UDP flow to `addr:port` through outbound `tag`, or directly
    /// when `tag` is None. None means direct, so callers pass None only for
    /// a Direct rule, never as a fallback for a failed or refused proxy.
    /// The default refuses: a dialer without UDP never carries it some
    /// other way.
    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        let _ = (tag, addr, port);
        Err(DialError("udp not supported by this dialer".into()))
    }
}

/// One UDP flow opened by `Dialer::dial_udp`. `send` and `recv` may run
/// concurrently from different tasks.
#[async_trait]
pub trait UdpSession: Send + Sync {
    /// Largest payload `send` accepts towards `addr:port`. Callers drop
    /// bigger datagrams themselves (counted, not silently).
    fn max_payload(&self, addr: &TargetAddr, port: u16) -> usize;
    /// Whether datagrams on this flow travel unreliably (UDP/QUIC datagrams)
    /// rather than encapsulated over a reliable stream.
    fn loses_datagrams(&self) -> bool {
        true
    }
    /// Errors for a payload above `max_payload`; any other error means the
    /// flow is broken.
    async fn send(&self, addr: &TargetAddr, port: u16, payload: &[u8]) -> Result<(), DialError>;
    /// The next datagram, written into `buf` (cleared first; its capacity is
    /// reused across calls), and its source.
    async fn recv(&self, buf: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError>;
}

pub type Datagrams = Box<dyn UdpSession>;

/// Dialer backed by segue-engine.
pub struct EngineDialer {
    outbounds: BTreeMap<String, TcpOutbound>,
    /// Kept for UDP: the UDP outbound is selected on first use, so a
    /// TCP-only outbound does not fail startup.
    routers: BTreeMap<String, OutboundRouter>,
    transport: Arc<TransportDialer>,
}

impl EngineDialer {
    /// Build outbounds using an unprotected system transport, as the prototype
    /// does. Embedded callers use [`Self::with_transport_dialer`] so the host's
    /// socket protector covers every carrier and direct-flow socket.
    pub fn new(specs: &BTreeMap<String, Value>) -> Result<Self, DialError> {
        let transport =
            TransportDialer::system().map_err(|e| DialError(format!("transport: {e}")))?;
        Self::with_transport_dialer(specs, Arc::new(transport))
    }

    /// Build one engine outbound per tag from its Xray-style JSON object.
    ///
    /// The same `TransportDialer` serves all outbounds and direct flows, so
    /// they inherit its socket protection.
    pub fn with_transport_dialer(
        specs: &BTreeMap<String, Value>,
        transport: Arc<TransportDialer>,
    ) -> Result<Self, DialError> {
        let mut outbounds = BTreeMap::new();
        let mut routers = BTreeMap::new();
        for (tag, spec) in specs {
            let mut spec = spec.clone();
            if let Value::Object(map) = &mut spec {
                map.insert("tag".into(), Value::String(tag.clone()));
            }
            let doc = json!({ "outbounds": [spec] }).to_string();
            let parsed =
                parse_xray_json(&doc).map_err(|e| DialError(format!("outbound {tag:?}: {e}")))?;
            let router = OutboundRouter::new(Arc::new(parsed.config));
            let outbound = router
                .select_tcp_outbound()
                .map_err(|e| DialError(format!("outbound {tag:?}: {e}")))?;
            outbounds.insert(tag.clone(), outbound);
            routers.insert(tag.clone(), router);
        }
        Ok(Self {
            outbounds,
            routers,
            transport,
        })
    }
}

#[async_trait]
impl Dialer for EngineDialer {
    async fn dial(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        let Some(tag) = tag else {
            let target = Target::new(addr.clone(), port, Network::Tcp);
            let dests = match addr {
                TargetAddr::Ip(ip) => vec![SocketAddr::new(*ip, port)],
                TargetAddr::Domain(name) => tokio::net::lookup_host((name.as_str(), port))
                    .await
                    .map_err(|e| DialError(format!("direct: {e}")))?
                    .collect::<Vec<_>>(),
            };
            let (stream, _) = self
                .transport
                .connect_raw_stream_with_peer(
                    &ConnectorConfig::Tcp,
                    &target,
                    &dests,
                    Some(&HappyEyeballsConfig::default()),
                )
                .await
                .map_err(|e| DialError(format!("direct: {e}")))?;
            return Ok(stream);
        };
        let outbound = self
            .outbounds
            .get(tag)
            .ok_or_else(|| DialError(format!("unknown outbound {tag:?}")))?;
        let target = Target::new(addr.clone(), port, Network::Tcp);
        open_tcp_stream_with_resolver_and_dialer(
            outbound,
            &target,
            &SystemDnsResolver,
            &self.transport,
        )
        .await
        .map_err(|e| DialError(format!("{tag}: {e}")))
    }

    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        let Some(tag) = tag else {
            return Ok(Box::new(
                DirectUdp::connect(&self.transport, addr, port).await?,
            ));
        };
        let router = self
            .routers
            .get(tag)
            .ok_or_else(|| DialError(format!("unknown outbound {tag:?}")))?;
        let target = Target::new(addr.clone(), port, Network::Udp);
        let outbound = router
            .select_udp_outbound_for_session(None, &target)
            .map_err(|e| DialError(format!("{tag}: udp: {e}")))?;
        let session = OutboundUdpSession::open(
            &outbound,
            &target,
            &SystemDnsResolver,
            &self.transport,
            rand::random(),
        )
        .await
        .map_err(|e| DialError(format!("{tag}: udp: {e}")))?;
        Ok(Box::new(EngineUdp(session)))
    }
}

struct EngineUdp(OutboundUdpSession);

#[async_trait]
impl UdpSession for EngineUdp {
    fn max_payload(&self, addr: &TargetAddr, port: u16) -> usize {
        self.0
            .max_payload(&Target::new(addr.clone(), port, Network::Udp))
    }

    fn loses_datagrams(&self) -> bool {
        self.0.loses_datagrams()
    }

    async fn send(&self, addr: &TargetAddr, port: u16, payload: &[u8]) -> Result<(), DialError> {
        let target = Target::new(addr.clone(), port, Network::Udp);
        let max = self.0.max_payload(&target);
        if payload.len() > max {
            return Err(DialError(format!(
                "udp send: payload {} > {max} bytes",
                payload.len()
            )));
        }
        self.0
            .send(&target, payload)
            .await
            .map_err(|e| DialError(format!("udp send: {e}")))
    }

    async fn recv(&self, buf: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError> {
        let (source, payload) = self
            .0
            .recv()
            .await
            .map_err(|e| DialError(format!("udp recv: {e}")))?;
        *buf = payload;
        Ok((source.addr, source.port))
    }
}

/// Largest UDP payload over IPv4/IPv6 without jumbograms.
const MAX_UDP_PAYLOAD: usize = 65_507;

/// A connected socket from this device to one destination.
struct DirectUdp {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl DirectUdp {
    async fn connect(
        transport: &TransportDialer,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Self, DialError> {
        let dests: Vec<SocketAddr> = match addr {
            TargetAddr::Ip(ip) => vec![SocketAddr::new(*ip, port)],
            TargetAddr::Domain(name) => tokio::net::lookup_host((name.as_str(), port))
                .await
                .map_err(|e| DialError(format!("direct udp: {e}")))?
                .collect(),
        };
        // UDP connect only checks that a route exists, so try each address
        // until one works (e.g. an AAAA first on a host without IPv6).
        let mut last = DialError(format!("direct udp: {addr:?}: no address"));
        for dest in dests {
            let local: SocketAddr = if dest.is_ipv4() {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let attempt = async {
                let socket = UdpSocket::bind(local).await?;
                segue_transport::protect_udp_socket(&socket, transport.socket_protector())
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                socket.connect(dest).await?;
                Ok::<_, std::io::Error>(socket)
            };
            match attempt.await {
                Ok(socket) => return Ok(Self { socket, peer: dest }),
                Err(e) => last = DialError(format!("direct udp: {dest}: {e}")),
            }
        }
        Err(last)
    }
}

#[async_trait]
impl UdpSession for DirectUdp {
    fn max_payload(&self, _addr: &TargetAddr, _port: u16) -> usize {
        MAX_UDP_PAYLOAD
    }

    async fn send(&self, _addr: &TargetAddr, _port: u16, payload: &[u8]) -> Result<(), DialError> {
        // One socket per destination: the flow's address is fixed.
        self.socket
            .send(payload)
            .await
            .map(drop)
            .map_err(|e| DialError(format!("direct udp: {e}")))
    }

    async fn recv(&self, buf: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError> {
        // recv_buf fills spare capacity without zeroing it, so the 64 KiB
        // reserve is allocated once per flow and only touched pages count.
        // A caller that sized the buffer itself (the TUN, to its MTU) keeps
        // that size; a longer datagram is truncated to it.
        buf.clear();
        if buf.capacity() == 0 {
            buf.reserve(MAX_UDP_PAYLOAD);
        }
        self.socket
            .recv_buf(buf)
            .await
            .map_err(|e| DialError(format!("direct udp: {e}")))?;
        Ok((TargetAddr::Ip(self.peer.ip()), self.peer.port()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Exit, KernelDialer};
    use segue_transport::{SocketHandle, SocketProtector};
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct RecordingProtector(Mutex<Vec<i64>>);

    impl RecordingProtector {
        fn sockets(&self) -> Vec<i64> {
            self.0.lock().unwrap().clone()
        }
    }

    impl SocketProtector for RecordingProtector {
        fn protect(&self, socket: SocketHandle) -> std::io::Result<()> {
            self.0.lock().unwrap().push(socket.raw());
            Ok(())
        }
    }

    fn protected_dialer(protector: Arc<RecordingProtector>) -> Arc<TransportDialer> {
        Arc::new(
            TransportDialer::system_with_socket_protector(Some(protector))
                .expect("protected transport"),
        )
    }

    #[test]
    fn kernel_dialer_accepts_protected_engine_dialer() {
        let mut specs = BTreeMap::new();
        specs.insert("carrier".to_owned(), json!({"protocol": "freedom"}));
        let engine = EngineDialer::with_transport_dialer(
            &specs,
            protected_dialer(Arc::new(RecordingProtector::default())),
        )
        .unwrap();
        let dialer: Arc<dyn crate::dial::Dialer> = Arc::new(KernelDialer::new(
            Arc::new(engine),
            vec![Exit {
                name: "test".into(),
                carrier: "carrier".into(),
                redundant_carrier: None,
                dgram_carriers: Vec::new(),
                dgram_relay: None,
                relay: "127.0.0.1:9000".parse().unwrap(),
                node_id: 1,
                egress_group: String::new(),
            }],
            BTreeMap::new(),
            Default::default(),
        ));
        drop(dialer);
    }

    #[tokio::test]
    async fn shared_transport_protects_the_session_carrier_socket() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let protector = Arc::new(RecordingProtector::default());
        let mut specs = BTreeMap::new();
        specs.insert("carrier".to_owned(), json!({"protocol": "freedom"}));
        let dialer =
            EngineDialer::with_transport_dialer(&specs, protected_dialer(protector.clone()))
                .unwrap();
        let mut stream = dialer
            .dial(Some("carrier"), &TargetAddr::Ip(addr.ip()), addr.port())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        stream.write_all(b"carrier").await.unwrap();
        let mut got = [0u8; 7];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"carrier");
        let sockets = protector.sockets();
        assert_eq!(sockets.len(), 1);
        assert!(sockets.iter().all(|fd| *fd >= 0));
    }

    #[tokio::test]
    async fn shared_transport_protects_direct_tcp_and_udp_sockets() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let protector = Arc::new(RecordingProtector::default());
        let dialer = EngineDialer::with_transport_dialer(
            &BTreeMap::new(),
            protected_dialer(protector.clone()),
        )
        .unwrap();
        let target = TargetAddr::Ip(Ipv4Addr::LOCALHOST.into());
        let stream = dialer
            .dial(None, &target, listener.local_addr().unwrap().port())
            .await
            .unwrap();
        let _ = listener.accept().await.unwrap();
        drop(stream);
        let port = udp.local_addr().unwrap().port();
        let datagrams = dialer.dial_udp(None, &target, port).await.unwrap();
        datagrams.send(&target, port, b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        udp.recv(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert_eq!(protector.sockets().len(), 2);
    }
}
