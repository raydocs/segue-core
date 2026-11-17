//! AnyTLS client over the shared protected stream carrier.
//!
//! AnyTLS is TLS-only: the carrier must be TLS or REALITY, and the session
//! hello (the password digest and its padding) is the first thing written on
//! it. TCP flows ride multiplexed streams of a small session pool; UDP rides
//! sing's UDP-over-TCP framing on a stream of its own, as sing-box's AnyTLS
//! outbound does.
use super::*;
use segue_proxy::anytls::{self as wire, AnyTlsAuth, WireError};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex as AsyncMutex;

mod session;
use session::{Pool, PoolOptions};

#[derive(Debug, Clone)]
pub struct AnyTlsOutbound(Arc<Payload>);

#[derive(Debug)]
struct Payload {
    carrier: StreamCarrier,
    auth: AnyTlsAuth,
    pool: Pool,
    level: u32,
}

impl AnyTlsOutbound {
    pub(super) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        let OutboundSettings::AnyTls(settings) = &config.settings else {
            return Err(CoreError::NoSupportedOutbound);
        };
        if settings.port == 0
            || matches!(&settings.server, TargetAddr::Domain(d) if d.is_empty() || d.len() > 255 || d.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(CoreError::UnsupportedOutboundServerAddress);
        }
        if settings.level > 255 {
            return Err(CoreError::NoSupportedOutbound);
        }
        // AnyTLS has no plaintext mode: the password digest and every frame
        // would travel in the clear. The parser refuses this too; keep it for
        // programmatically built configs.
        if config.stream.security == StreamSecurity::None
            || matches!(&config.stream.security, StreamSecurity::Tls(tls) if tls.allow_insecure)
        {
            return Err(CoreError::UnsupportedOutboundSecurity);
        }
        let auth = AnyTlsAuth::new(&settings.password)?;
        Ok(Self(Arc::new(Payload {
            carrier: StreamCarrier::new(
                &config.stream,
                &settings.server,
                settings.port,
                false,
                carrier::TROJAN_PATHS,
            )?,
            auth,
            pool: Pool::new(PoolOptions {
                idle_check_interval: settings.idle_session_check_interval,
                idle_session_timeout: settings.idle_session_timeout,
                min_idle_session: settings.min_idle_session,
                client_metadata: settings.client_metadata.clone(),
            }),
            level: settings.level,
        })))
    }

    pub(super) fn close(&self) {
        self.0.pool.close();
    }
    pub(super) async fn join(&self) {
        self.0.pool.join().await;
    }

    pub fn server(&self) -> &Target {
        &self.0.carrier.server
    }
    pub(super) fn carrier(&self) -> &super::carrier::StreamCarrier {
        &self.0.carrier
    }
    pub fn level(&self) -> u32 {
        self.0.level
    }

    pub(super) async fn open(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        // Validate before DNS or dialing, including programmatically built
        // targets.
        wire::encode_stream_target(target)?;
        let candidates = self.0.carrier.resolve_server(resolver, dialer).await?;
        let download = self.0.carrier.resolve_download(resolver, dialer).await?;
        self.open_resolved(target, &candidates, &download, dialer)
            .await
    }

    pub(super) async fn open_resolved(
        &self,
        target: &Target,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let header = wire::encode_stream_target(target)?;
        let mut stream = self
            .0
            .pool
            .open(self.open_session(candidates, download, dialer))
            .await?;
        // The stream's destination is its first bytes, as the AnyTLS service
        // reads them before it routes the stream.
        stream.write_all(&header).await?;
        Ok(Box::new(stream))
    }

    /// One carrier session: the TLS carrier, then the password hello.
    async fn open_session(
        &self,
        candidates: &[SocketAddr],
        download: &[SocketAddr],
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        let mut stream = self.0.carrier.open(candidates, download, dialer).await?;
        stream.release_record_alignment();
        let padding = self.0.pool.hello_padding();
        let hello = wire::hello_frames(&self.0.auth, padding);
        stream.write_all(&hello).await?;
        stream.flush().await?;
        Ok(stream)
    }

    pub(super) async fn open_udp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<UdpSession, CoreError> {
        if target.network != RoutingNetwork::Udp {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        // A UDP association is a stream to the magic destination whose first
        // bytes are the UoT request.
        let magic = wire::uot_request_target();
        let request = wire::encode_uot_request(target, true)?;
        let candidates = self.0.carrier.resolve_server(resolver, dialer).await?;
        let download = self.0.carrier.resolve_download(resolver, dialer).await?;
        let mut stream = self
            .0
            .pool
            .open(self.open_session(&candidates, &download, dialer))
            .await?;
        let mut header = wire::encode_stream_target(&magic)?;
        header.extend_from_slice(&request);
        stream.write_all(&header).await?;
        Ok(UdpSession::new(Box::new(stream), target.clone()))
    }
}

/// UDP over one AnyTLS stream: a length-prefixed datagram each way, with the
/// destination fixed by the UoT connect request.
pub(super) struct UdpSession {
    writer: AsyncMutex<Option<tokio::io::WriteHalf<BoxedTransportStream>>>,
    reader: AsyncMutex<Reader>,
    target: Target,
}
struct Reader {
    stream: tokio::io::ReadHalf<BoxedTransportStream>,
    pending: Vec<u8>,
    closed: bool,
}
impl UdpSession {
    fn new(stream: BoxedTransportStream, target: Target) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer: AsyncMutex::new(Some(writer)),
            reader: AsyncMutex::new(Reader {
                stream: reader,
                pending: Vec::with_capacity(wire::MAX_UOT_FRAME_LENGTH),
                closed: false,
            }),
            target,
        }
    }
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        if target != &self.target {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "AnyTLS UDP session carries one destination",
            )
            .into());
        }
        let frame = wire::encode_uot_datagram(payload)?;
        let mut owner = self.writer.lock().await;
        // Cancellation after any partial write permanently closes this writer.
        let mut writer = owner
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS UDP writer closed"))?;
        writer.write_all(&frame).await?;
        writer.flush().await?;
        *owner = Some(writer);
        Ok(())
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut reader = self.reader.lock().await;
        if reader.closed {
            return Err(
                io::Error::new(io::ErrorKind::BrokenPipe, "AnyTLS UDP reader closed").into(),
            );
        }
        loop {
            match wire::decode_uot_datagram(&reader.pending) {
                Ok(Some((payload, consumed))) => {
                    let payload = payload.to_vec();
                    reader.pending.drain(..consumed);
                    return Ok(datagram::Datagram {
                        source: self.target.clone(),
                        payload,
                    });
                }
                Ok(None) => {}
                Err(error) => {
                    reader.closed = true;
                    return Err(error.into());
                }
            }
            let remaining = wire::MAX_UOT_FRAME_LENGTH - reader.pending.len();
            if remaining == 0 {
                reader.closed = true;
                return Err(WireError::PayloadLength.into());
            }
            let mut scratch = [0u8; 1024];
            let limit = remaining.min(scratch.len());
            // read is cancellation-safe; committed bytes move into persistent
            // state without another await, so select cancellation cannot lose
            // a prefix.
            let read = match reader.stream.read(&mut scratch[..limit]).await {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    reader.closed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "AnyTLS UDP stream closed",
                    )
                    .into());
                }
                Err(error) => {
                    reader.closed = true;
                    return Err(error.into());
                }
            };
            reader.pending.extend_from_slice(&scratch[..read]);
        }
    }
}

#[cfg(test)]
mod tests;
