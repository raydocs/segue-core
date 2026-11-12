//! The only place the kernel touches the outer engine.
//!
//! Everything above this module sees `Dialer`; swapping the engine for
//! another implementation means rewriting this file only.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use segue_config::parse_xray_json;
use segue_engine::{
    open_tcp_stream_with_resolver_and_dialer, OutboundRouter, OutboundUdpSession, TcpOutbound,
};
use segue_routing::{Network, Target, TargetAddr};
use segue_transport::{BoxedTransportStream, SystemDnsResolver, TransportDialer};
use serde_json::{json, Value};
use tokio::net::{TcpStream, UdpSocket};

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
    async fn dial(&self, tag: Option<&str>, addr: &TargetAddr, port: u16) -> Result<Stream, DialError>;

    /// Open a UDP flow to `addr:port` through outbound `tag`, or directly
    /// when `tag` is None. The default refuses: a dialer without UDP never
    /// carries it some other way.
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

/// One UDP flow opened by `Dialer::dial_udp`.
#[async_trait]
pub trait UdpSession: Send + Sync {
    async fn send(&self, addr: &TargetAddr, port: u16, payload: &[u8]) -> Result<(), DialError>;
    /// The next datagram and its source. Must be cancel-safe.
    async fn recv(&self) -> Result<(TargetAddr, u16, Vec<u8>), DialError>;
}

pub type Datagrams = Box<dyn UdpSession>;

/// Dialer backed by segue-engine.
pub struct EngineDialer {
    outbounds: BTreeMap<String, TcpOutbound>,
    /// Kept for UDP: the UDP outbound is selected on first use, so a
    /// TCP-only outbound does not fail startup.
    routers: BTreeMap<String, OutboundRouter>,
    transport: TransportDialer,
}

impl EngineDialer {
    /// Build one engine outbound per tag from its Xray-style JSON object.
    pub fn new(specs: &BTreeMap<String, Value>) -> Result<Self, DialError> {
        let mut outbounds = BTreeMap::new();
        let mut routers = BTreeMap::new();
        for (tag, spec) in specs {
            let mut spec = spec.clone();
            if let Value::Object(map) = &mut spec {
                map.insert("tag".into(), Value::String(tag.clone()));
            }
            let doc = json!({ "outbounds": [spec] }).to_string();
            let parsed = parse_xray_json(&doc).map_err(|e| DialError(format!("outbound {tag:?}: {e}")))?;
            let router = OutboundRouter::new(Arc::new(parsed.config));
            let outbound = router
                .select_tcp_outbound()
                .map_err(|e| DialError(format!("outbound {tag:?}: {e}")))?;
            outbounds.insert(tag.clone(), outbound);
            routers.insert(tag.clone(), router);
        }
        let transport = TransportDialer::system().map_err(|e| DialError(format!("transport: {e}")))?;
        Ok(Self { outbounds, routers, transport })
    }
}

#[async_trait]
impl Dialer for EngineDialer {
    async fn dial(&self, tag: Option<&str>, addr: &TargetAddr, port: u16) -> Result<Stream, DialError> {
        let Some(tag) = tag else {
            let stream = match addr {
                TargetAddr::Ip(ip) => TcpStream::connect((*ip, port)).await,
                TargetAddr::Domain(name) => TcpStream::connect((name.as_str(), port)).await,
            }
            .map_err(|e| DialError(format!("direct: {e}")))?;
            let _ = stream.set_nodelay(true);
            return Ok(Box::new(stream));
        };
        let outbound = self
            .outbounds
            .get(tag)
            .ok_or_else(|| DialError(format!("unknown outbound {tag:?}")))?;
        let target = Target::new(addr.clone(), port, Network::Tcp);
        open_tcp_stream_with_resolver_and_dialer(outbound, &target, &SystemDnsResolver, &self.transport)
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
            return Ok(Box::new(DirectUdp::connect(addr, port).await?));
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
    async fn send(&self, addr: &TargetAddr, port: u16, payload: &[u8]) -> Result<(), DialError> {
        let target = Target::new(addr.clone(), port, Network::Udp);
        if payload.len() > self.0.max_payload(&target) {
            // Too big for this path: dropped on its own, as a router would.
            return Ok(());
        }
        self.0.send(&target, payload).await.map_err(|e| DialError(format!("udp send: {e}")))
    }

    async fn recv(&self) -> Result<(TargetAddr, u16, Vec<u8>), DialError> {
        let (source, payload) = self.0.recv().await.map_err(|e| DialError(format!("udp recv: {e}")))?;
        Ok((source.addr, source.port, payload))
    }
}

/// A connected socket from this device to one destination.
struct DirectUdp(UdpSocket);

impl DirectUdp {
    async fn connect(addr: &TargetAddr, port: u16) -> Result<Self, DialError> {
        let dest = match addr {
            TargetAddr::Ip(ip) => std::net::SocketAddr::new(*ip, port),
            TargetAddr::Domain(name) => tokio::net::lookup_host((name.as_str(), port))
                .await
                .map_err(|e| DialError(format!("direct udp: {e}")))?
                .next()
                .ok_or_else(|| DialError(format!("direct udp: {name}: no address")))?,
        };
        let local: std::net::SocketAddr = if dest.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local).await.map_err(|e| DialError(format!("direct udp: {e}")))?;
        socket.connect(dest).await.map_err(|e| DialError(format!("direct udp: {e}")))?;
        Ok(Self(socket))
    }
}

#[async_trait]
impl UdpSession for DirectUdp {
    async fn send(&self, _addr: &TargetAddr, _port: u16, payload: &[u8]) -> Result<(), DialError> {
        // One socket per destination: the flow's address is fixed.
        self.0.send(payload).await.map(drop).map_err(|e| DialError(format!("direct udp: {e}")))
    }

    async fn recv(&self) -> Result<(TargetAddr, u16, Vec<u8>), DialError> {
        let mut buf = vec![0u8; 65535];
        let n = self.0.recv(&mut buf).await.map_err(|e| DialError(format!("direct udp: {e}")))?;
        buf.truncate(n);
        let peer = self.0.peer_addr().map_err(|e| DialError(format!("direct udp: {e}")))?;
        Ok((TargetAddr::Ip(peer.ip()), peer.port(), buf))
    }
}
