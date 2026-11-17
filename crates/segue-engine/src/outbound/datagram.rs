//! Shared bounded datagram relay for connection-oriented UDP outbounds.
use super::*;
use segue_transport::hysteria::{HysteriaError, HysteriaUdpSession};

pub(crate) enum Session {
    /// Only a pooled XUDP child: VLESS native UDP keeps its own relay.
    VlessMux(super::mux::UdpSession),
    Trojan(trojan::UdpSession),
    Socks(socks::UdpSession),
    Vmess(vmess::UdpSession),
    Shadowsocks2022(Box<shadowsocks::UdpSession>),
    Hysteria(HysteriaUdpSession),
    Wireguard {
        session: segue_wireguard::UdpSession,
        requested: Target,
    },
    Masque {
        session: super::masque::MasqueUdpSession,
        requested: Target,
    },
    AnyTls(anytls::UdpSession),
}
pub(crate) struct Datagram {
    pub(crate) source: Target,
    pub(crate) payload: Vec<u8>,
}
pub(crate) async fn open(
    outbound: &UdpOutbound,
    target: &Target,
    destination: &dyn DnsResolver,
    bootstrap: &dyn DnsResolver,
    dialer: &TransportDialer,
    global_id: [u8; 8],
) -> Result<Session, CoreError> {
    match outbound {
        UdpOutbound::Vless(outbound) => Ok(Session::VlessMux(
            outbound
                .open_mux_udp(target, bootstrap, dialer, global_id)
                .await?,
        )),
        UdpOutbound::Trojan(outbound) => Ok(Session::Trojan(
            outbound
                .open_udp(target, bootstrap, dialer, global_id)
                .await?,
        )),
        UdpOutbound::Socks(outbound) => Ok(Session::Socks(
            outbound.open_udp(target, bootstrap, dialer).await?,
        )),
        UdpOutbound::Vmess(outbound) => Ok(Session::Vmess(
            outbound
                .open_udp(target, bootstrap, dialer, global_id)
                .await?,
        )),
        UdpOutbound::Shadowsocks2022(outbound) => Ok(Session::Shadowsocks2022(Box::new(
            outbound
                .open_udp(target, bootstrap, dialer, global_id)
                .await?,
        ))),
        UdpOutbound::Hysteria(outbound) => Ok(Session::Hysteria(
            outbound.open_udp(bootstrap, dialer).await?,
        )),
        UdpOutbound::Wireguard(outbound) => Ok(Session::Wireguard {
            session: outbound
                .open_udp(target, destination, bootstrap, dialer)
                .await?,
            requested: target.clone(),
        }),
        UdpOutbound::Masque(outbound) => Ok(Session::Masque {
            session: outbound.open_udp(target, bootstrap, dialer).await?,
            requested: target.clone(),
        }),
        UdpOutbound::AnyTls(outbound) => Ok(Session::AnyTls(
            outbound.open_udp(target, bootstrap, dialer).await?,
        )),
        _ => Err(CoreError::UnsupportedOutboundNetwork),
    }
}
/// [`open`] under the handshake policy of the outbound's level, the deadline
/// the TCP opens get. Xray-core sets it on its SOCKS client handshake, UDP
/// ASSOCIATE included (`proxy/socks/client.go`). DNS exchanges call [`open`]
/// under their own attempt deadlines instead.
pub(crate) async fn open_within_handshake(
    config: &CoreConfig,
    outbound: &UdpOutbound,
    target: &Target,
    destination: &dyn DnsResolver,
    bootstrap: &dyn DnsResolver,
    dialer: &TransportDialer,
    global_id: [u8; 8],
) -> Result<Session, CoreError> {
    let level = match outbound {
        UdpOutbound::Vless(outbound) => outbound.user().level,
        UdpOutbound::Trojan(outbound) => outbound.level(),
        UdpOutbound::AnyTls(outbound) => outbound.level(),
        UdpOutbound::Socks(outbound) => outbound.level(),
        UdpOutbound::Vmess(outbound) => outbound.level(),
        UdpOutbound::Shadowsocks2022(outbound) => outbound.level(),
        UdpOutbound::Hysteria(_) | UdpOutbound::Wireguard(_) | UdpOutbound::Masque(_) => 0,
        UdpOutbound::Freedom(_) => return Err(CoreError::UnsupportedOutboundNetwork),
    };
    let mut handshake = effective_policy_for_level(config, Some(level)).handshake;
    if matches!(outbound, UdpOutbound::Masque(_)) {
        handshake = super::masque::open_timeout(handshake);
    }
    within_handshake(
        handshake,
        open(outbound, target, destination, bootstrap, dialer, global_id),
    )
    .await
}
/// Runs a UDP open under `handshake`. Zero means no bound, as for Xray-core's
/// WireGuard client (`proxy/wireguard/client.go`); a zero deadline would fail
/// every open on its first poll.
pub(crate) async fn within_handshake<T>(
    handshake: std::time::Duration,
    open: impl std::future::Future<Output = Result<T, CoreError>>,
) -> Result<T, CoreError> {
    if handshake.is_zero() {
        return open.await;
    }
    tokio::time::timeout(handshake, open)
        .await
        .map_err(|_| open_timed_out())?
}
pub(crate) fn open_timed_out() -> CoreError {
    io::Error::new(io::ErrorKind::TimedOut, "outbound udp open timed out").into()
}
impl Session {
    /// The largest datagram this session's path carries to `target`. A TUN
    /// with a jumbo MTU admits datagrams beyond it, and they must not end
    /// the flow.
    pub(crate) fn max_payload(&self, target: &Target) -> usize {
        match self {
            Self::VlessMux(_) => segue_proxy::mux::MAX_PAYLOAD,
            Self::Trojan(_) => segue_proxy::trojan::MAX_UDP_PAYLOAD_LENGTH,
            Self::AnyTls(_) => segue_proxy::anytls::MAX_UDP_PAYLOAD_LENGTH,
            Self::Vmess(session) => session.max_payload(),
            Self::Wireguard { session, .. } => session.max_payload(),
            Self::Masque { session, .. } => session.max_payload(),
            // Shadowsocks of either family: what fits Xray's 8192-byte UDP
            // buffer after this method's framing for `target`, or one Mux frame.
            Self::Shadowsocks2022(session) => session.max_payload(target),
            // SOCKS carries what fits one IP datagram, and Hysteria fragments
            // a datagram across QUIC datagrams.
            Self::Socks(_) | Self::Hysteria(_) => usize::MAX,
        }
    }
    /// Whether a datagram of this session can be lost on its way with
    /// nothing under it to send it again: the carrier is UDP itself or QUIC
    /// datagrams. The others ride a stream.
    pub(crate) fn loses_datagrams(&self) -> bool {
        match self {
            Self::VlessMux(_) | Self::Trojan(_) | Self::Vmess(_) | Self::AnyTls(_) => false,
            Self::Shadowsocks2022(session) => session.loses_datagrams(),
            Self::Socks(_) | Self::Hysteria(_) | Self::Wireguard { .. } | Self::Masque { .. } => {
                true
            }
        }
    }
    pub(crate) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        match self {
            Self::VlessMux(session) => session.send(target, payload).await,
            Self::Trojan(session) => session.send(target, payload).await,
            Self::AnyTls(session) => session.send(target, payload).await,
            Self::Socks(session) => session.send(target, payload).await,
            Self::Vmess(session) => session.send(target, payload).await,
            Self::Shadowsocks2022(session) => session.send(target, payload).await,
            Self::Hysteria(session) => Ok(session.send(target, payload).await?),
            Self::Wireguard { session, requested } => {
                if target != requested {
                    return Err(segue_wireguard::Error::NoRoute.into());
                }
                Ok(session.send(payload).await?)
            }
            // A connected socket in the stack, as Xray's `tnet.Dial("udp")`.
            Self::Masque { session, requested } => {
                if target != requested {
                    return Err(segue_wireguard::Error::NoRoute.into());
                }
                session.send(payload).await
            }
        }
    }
    pub(crate) async fn recv(&self) -> Result<Datagram, CoreError> {
        match self {
            Self::VlessMux(session) => session.recv().await,
            Self::Trojan(session) => session.recv().await,
            Self::AnyTls(session) => session.recv().await,
            Self::Socks(session) => session.recv().await,
            Self::Vmess(session) => session.recv().await,
            Self::Shadowsocks2022(session) => session.recv().await,
            Self::Hysteria(session) => {
                let packet = session.recv().await?;
                Ok(Datagram {
                    source: packet.source,
                    payload: packet.payload,
                })
            }
            Self::Wireguard { session, .. } => {
                let peer = session.peer_addr();
                Ok(Datagram {
                    source: Target::new(
                        RoutingTargetAddr::Ip(peer.ip()),
                        peer.port(),
                        RoutingNetwork::Udp,
                    ),
                    payload: session.recv().await?.to_vec(),
                })
            }
            Self::Masque { session, .. } => {
                let peer = session.peer_addr();
                Ok(Datagram {
                    source: Target::new(
                        RoutingTargetAddr::Ip(peer.ip()),
                        peer.port(),
                        RoutingNetwork::Udp,
                    ),
                    payload: session.recv().await?.to_vec(),
                })
            }
        }
    }
}

/// Logs a datagram dropped because its outbound path cannot carry it.
pub(crate) fn log_oversize_udp_datagram(
    logger: &crate::RuntimeLogger,
    inbound: &str,
    len: usize,
    max_payload: usize,
) {
    logger.debug(|| {
        format!("Debug udpOversizeDatagram inbound={inbound} len={len} pathMax={max_payload}")
    });
}

/// Shared flow loop; the inbound adapter owns shutdown/host-close cancellation.
/// A datagram larger than the session's path is dropped on its own, as a
/// router would, and handed to the adapter's `oversize` handler.
#[expect(
    clippy::too_many_arguments,
    reason = "shared relay carries optional TUN telemetry and inbound delivery"
)]
pub(crate) async fn relay_udp<O, OFut, F, Fut>(
    session: Session,
    target: &Target,
    mut input: crate::udp_ingress::UdpIngress,
    first: bytes::Bytes,
    traffic: &crate::connection::ConnectionTraffic,
    idle: Duration,
    tun: Option<&segue_tun::TunEndpoint>,
    mut oversize: O,
    mut deliver: F,
) -> Result<(), CoreError>
where
    O: FnMut(bytes::Bytes, usize) -> OFut,
    OFut: Future<Output = ()>,
    F: FnMut(Target, bytes::Bytes) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    let max_payload = session.max_payload(target);
    let send = async |payload: &bytes::Bytes, oversize: &mut O| -> Result<(), CoreError> {
        if payload.len() > max_payload {
            oversize(payload.clone(), max_payload).await;
            return Ok(());
        }
        session.send(target, payload).await.inspect_err(|_| {
            if let Some(tun) = tun {
                tun.record_udp_remote_write_error();
            }
        })?;
        if let Some(tun) = tun {
            tun.record_udp_remote_written(payload.len());
        }
        traffic.record_uplink(payload.len() as u64);
        Ok(())
    };
    send(&first, &mut oversize).await?;
    let idle_deadline = tokio::time::sleep(idle);
    tokio::pin!(idle_deadline);
    loop {
        tokio::select! {
            _ = &mut idle_deadline => break,
            payload = input.recv() => {
                let Some(payload) = payload else { break; };
                send(&payload, &mut oversize).await?;
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + idle);
            }
            packet = session.recv() => {
                let packet = packet.inspect_err(|error| { if let Some(tun) = tun {
                    if matches!(error, CoreError::Hysteria(HysteriaError::Closed) | CoreError::Wireguard(segue_wireguard::Error::Closed)) { tun.record_udp_remote_closed(); } else { tun.record_udp_remote_read_error(); }
                } })?;
                if let Some(tun) = tun { tun.record_udp_remote_read(packet.payload.len()); }
                traffic.record_downlink(packet.payload.len() as u64);
                deliver(packet.source, bytes::Bytes::from(packet.payload)).await?;
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + idle);
            }
        }
    }
    Ok(())
}

/// One outbound UDP session, for embedders outside this crate (the Segue
/// kernel). A thin wrapper over the same session the engine's own SOCKS and
/// TUN inbounds relay through; framing stays here.
pub struct OutboundUdpSession(Session);

impl OutboundUdpSession {
    /// Opens a session through `outbound` for datagrams to `target`. Names
    /// are resolved with `resolver` (destination and server bootstrap
    /// alike). `global_id` keys XUDP/connection reuse where the protocol has
    /// one; distinct flows should pass distinct ids. A Freedom (direct)
    /// outbound is refused: direct UDP is the embedder's own socket. Plain
    /// VLESS UDP without Mux is not offered here (it needs inbound-side
    /// framing).
    pub async fn open(
        outbound: &UdpOutbound,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
        global_id: [u8; 8],
    ) -> Result<Self, CoreError> {
        if let UdpOutbound::Vless(vless) = outbound {
            if !vless.udp_uses_mux(target) {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
        }
        open(outbound, target, resolver, resolver, dialer, global_id)
            .await
            .map(Self)
    }

    /// The largest payload this session carries to `target`.
    pub fn max_payload(&self, target: &Target) -> usize {
        self.0.max_payload(target)
    }

    pub async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        self.0.send(target, payload).await
    }

    /// The next datagram and the source it came from.
    pub async fn recv(&self) -> Result<(Target, Vec<u8>), CoreError> {
        self.0.recv().await.map(|d| (d.source, d.payload))
    }
}
