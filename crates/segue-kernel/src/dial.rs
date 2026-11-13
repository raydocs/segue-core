//! The only place the kernel touches the outer engine.
//!
//! Everything above this module sees `Dialer`; swapping the engine for
//! another implementation means rewriting this file only.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use segue_config::parse_xray_json;
use segue_engine::{open_tcp_stream_with_resolver_and_dialer, OutboundRouter, TcpOutbound};
use segue_routing::{Network, Target, TargetAddr};
use segue_transport::{BoxedTransportStream, SystemDnsResolver, TransportDialer};
use serde_json::{json, Value};
use tokio::net::TcpStream;

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
}

/// Dialer backed by segue-engine.
pub struct EngineDialer {
    outbounds: BTreeMap<String, TcpOutbound>,
    transport: TransportDialer,
}

impl EngineDialer {
    /// Build one engine outbound per tag from its Xray-style JSON object.
    pub fn new(specs: &BTreeMap<String, Value>) -> Result<Self, DialError> {
        let mut outbounds = BTreeMap::new();
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
        }
        let transport =
            TransportDialer::system().map_err(|e| DialError(format!("transport: {e}")))?;
        Ok(Self {
            outbounds,
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
        open_tcp_stream_with_resolver_and_dialer(
            outbound,
            &target,
            &SystemDnsResolver,
            &self.transport,
        )
        .await
        .map_err(|e| DialError(format!("{tag}: {e}")))
    }
}
