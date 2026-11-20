//! Runtime ownership of one authenticated connection per configured Hysteria outbound.
use super::*;
use segue_transport::hysteria::{
    GeckoPacketSize, HysteriaClient, HysteriaConfig, HysteriaError, HysteriaUdpSession,
};
use std::sync::atomic::AtomicBool;
use tokio::sync::Mutex as AsyncMutex;

/// One dial's whole deadline: admission, the server's lookup and every
/// connect attempt. It is the default policy `handshake`, which also bounds
/// each open that waits on a dial.
const DIAL_DEADLINE: Duration = Duration::from_secs(10);
/// Stagger delay between Happy Eyeballs candidate connect attempts.
const HAPPY_EYEBALLS_STAGGER: Duration = Duration::from_millis(250);
/// Maximum concurrent candidate connect attempts during Happy Eyeballs.
const MAX_CONCURRENT_DIALS: usize = 3;

type RaceAttemptOutcome = (Result<HysteriaClient, HysteriaError>, u64);
/// A connect attempt's share while other server addresses are still to be
/// tried, so a dead address leaves time for the next.
const CANDIDATE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
/// The last address's attempt, which is the only one for a server with one
/// address. The first probe, before an RTT sample, is 200 ms (twice the 100 ms
/// initial RTT, as in quic-go). Eight seconds still covers several lost
/// Initials on a lossy path.
const LAST_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);

/// How long the connect attempt with `remaining` addresses left, itself
/// included, may take when `left` remains of the dial's deadline: three
/// seconds while others wait, up to eight for the last, and never past the
/// deadline.
fn attempt_timeout(remaining: usize, left: Duration) -> Duration {
    let share = if remaining > 1 {
        CANDIDATE_ATTEMPT_TIMEOUT
    } else {
        LAST_ATTEMPT_TIMEOUT
    };
    share.min(left)
}

#[derive(Clone, Debug)]
pub struct HysteriaOutbound {
    inner: Arc<SessionOwner>,
}

#[derive(Debug)]
struct SessionOwner {
    limits: segue_transport::hysteria::HysteriaLimits,
    carrier: segue_transport::hysteria::HysteriaCarrierConfig,
    quic: H3QuicConfig,
    receive_bytes_per_second: u64,
    server: Target,
    tls: TlsClientConfig,
    auth: segue_config::HysteriaSettings,
    /// `sockopt`, for the QUIC socket.
    socket_options: Option<Arc<segue_transport::SocketOptions>>,
    /// `sockopt.addressPortStrategy`, for the server's address and port.
    address_port: segue_config::AddressPortStrategy,
    /// The dialer given and the one made from it with `socket_options`,
    /// kept so its protector, which a cached session is matched by, stays
    /// the same.
    socket_dialer: Mutex<Option<(TransportDialer, TransportDialer)>>,
    // Synchronous ownership permits deterministic close even while a dial is pending.
    session: Mutex<Option<CachedSession>>,
    connecting: AsyncMutex<()>,
    closed: AtomicBool,
    network_generation: std::sync::atomic::AtomicU64,
    shutdown: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug)]
struct CachedSession {
    client: HysteriaClient,
    connector: segue_transport::TlsConnector,
}

impl Drop for CachedSession {
    fn drop(&mut self) {
        self.client.close();
    }
}

impl HysteriaOutbound {
    pub(crate) fn new(config: &OutboundConfig) -> Result<Self, CoreError> {
        Self::with_stream_limits(config, crate::HysteriaStreamLimits::default())
    }

    pub(crate) fn with_stream_limits(
        config: &OutboundConfig,
        limits: crate::HysteriaStreamLimits,
    ) -> Result<Self, CoreError> {
        let (
            OutboundSettings::Hysteria(server),
            StreamTransport::Hysteria(auth),
            StreamSecurity::Tls(tls),
        ) = (
            &config.settings,
            &config.stream.transport,
            &config.stream.security,
        )
        else {
            return Err(CoreError::UnsupportedOutboundSecurity);
        };
        if config.stream.tcp_fragment.is_some()
            || config.stream.network != Network::Udp
            || config.proxy_settings.is_some()
            || tls.allow_insecure
            || tls.fingerprint.is_some()
            || (!tls.alpn.is_empty() && tls.alpn != ["h3"])
            || server.port == 0
            || auth.auth.is_empty()
            || auth.auth.len() > 4096
            || auth.auth.bytes().any(|b| b < 0x20 || b == 0x7f)
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        let gecko = auth
            .gecko_packet_size
            .map(|size| {
                let bound = |value: u32| u16::try_from(value).ok();
                bound(size.from)
                    .zip(bound(size.to))
                    .and_then(|(min, max)| GeckoPacketSize::new(min, max))
                    .filter(|_| auth.salamander_password.is_some())
                    .ok_or(CoreError::UnsupportedOutboundNetwork)
            })
            .transpose()?;
        let mut carrier = segue_transport::hysteria::HysteriaCarrierConfig {
            salamander_password: auth.salamander_password.clone().map(Arc::new),
            gecko,
            noise: config
                .stream
                .udp_noise
                .as_ref()
                .map(super::xhttp::udp_noise_config)
                .transpose()?,
            header_custom: config
                .stream
                .udp_header_custom
                .as_ref()
                .map(super::carrier::quic_header_custom),
            sudoku: config
                .stream
                .udp_sudoku
                .as_ref()
                .map(super::carrier::quic_sudoku),
            xdns: config
                .stream
                .udp_xdns
                .as_ref()
                .map(super::carrier::xdns_config),
            realm: config
                .stream
                .udp_realm
                .as_ref()
                .map(super::carrier::realm_config),
            xicmp: config
                .stream
                .udp_xicmp
                .as_ref()
                .map(super::carrier::xicmp_config),
            ..Default::default()
        };
        let (quic, receive_bytes_per_second) =
            hysteria_quic_config(config.stream.quic_params.as_ref())?;
        if let Some(quic) = &config.stream.quic_params {
            let hop = &quic.udp_hop;
            let interval = |value: i32| -> Result<Duration, CoreError> {
                if value == 0 {
                    Ok(Duration::from_secs(30))
                } else if value >= 5 {
                    Ok(Duration::from_secs(value as u64))
                } else {
                    Err(CoreError::UnsupportedOutboundNetwork)
                }
            };
            carrier.udp_hop = super::xhttp::udp_hop_config(
                hop,
                interval(hop.interval.from)?,
                interval(hop.interval.to)?,
            );
            if carrier.udp_hop.ports.len() > 65_535
                || carrier.udp_hop.ports.contains(&0)
                || carrier.udp_hop.interval_max < carrier.udp_hop.interval_min
            {
                return Err(CoreError::UnsupportedOutboundNetwork);
            }
        }
        if carrier
            .salamander_password
            .as_ref()
            .is_some_and(|p| !(4..=4096).contains(&p.len()))
        {
            return Err(CoreError::UnsupportedOutboundNetwork);
        }
        super::carrier::check_xicmp_server(&config.stream, &server.server)?;
        let server_name = tls
            .server_name
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| match &server.server {
                TargetAddr::Domain(domain) => domain.clone(),
                TargetAddr::Ip(ip) => ip.to_string(),
            });
        segue_transport::validate_tls_server_name(&server_name)
            .map_err(|_| CoreError::UnsupportedOutboundSecurity)?;
        Ok(Self {
            inner: Arc::new(SessionOwner {
                socket_options: socket_options::compile(&config.stream),
                address_port: super::carrier::address_port_strategy(&config.stream),
                socket_dialer: Mutex::new(None),
                limits: limits.transport_limits(),
                carrier,
                quic,
                receive_bytes_per_second,
                server: Target::new(
                    match &server.server {
                        TargetAddr::Domain(domain) => RoutingTargetAddr::Domain(domain.clone()),
                        TargetAddr::Ip(ip) => RoutingTargetAddr::Ip(*ip),
                    },
                    server.port,
                    RoutingNetwork::Udp,
                ),
                tls: TlsClientConfig {
                    server_name,
                    allow_insecure: false,
                    pinned_peer_cert_sha256: tls.pinned_peer_cert_sha256.clone(),
                    verify_peer_cert_by_name: tls.verify_peer_cert_by_name.clone(),
                    alpn: vec!["h3".into()],
                    fingerprint: None,
                    ech_config_list: None,
                },
                auth: auth.clone(),
                session: Mutex::new(None),
                connecting: AsyncMutex::new(()),
                closed: AtomicBool::new(false),
                network_generation: std::sync::atomic::AtomicU64::new(0),
                shutdown: tokio::sync::watch::channel(false).0,
            }),
        })
    }

    pub(super) fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.shutdown.send_replace(true);
        if let Some(client) = self
            .inner
            .session
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            client.client.close();
        }
    }

    pub(super) fn rebind(&self) -> bool {
        let cached = self.inner.session.lock().unwrap_or_else(|e| e.into_inner());
        self.inner.network_generation.fetch_add(1, Ordering::AcqRel);
        cached
            .as_ref()
            .is_some_and(|session| session.client.rebind())
    }

    async fn client(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<HysteriaClient, CoreError> {
        let mut shutdown = self.inner.shutdown.subscribe();
        if *shutdown.borrow() {
            return Err(HysteriaError::Closed.into());
        }
        let dialer = self.socket_dialer(dialer);
        // One total deadline includes contention, endpoint DNS and candidate
        // attempts, and a realm introduction before them.
        let deadline = tokio::time::Instant::now() + DIAL_DEADLINE + self.realm_budget();
        tokio::select! {
            biased;
            _ = shutdown.changed() => Err(HysteriaError::Closed.into()),
            result = tokio::time::timeout_at(deadline, self.client_inner(resolver, &dialer, deadline)) => result.map_err(|_| HysteriaError::Timeout)?,
        }
    }

    /// How long a realm introduction may add to a dial.
    fn realm_budget(&self) -> Duration {
        if self.inner.carrier.realm.is_some() {
            segue_transport::realm::ESTABLISH_BUDGET
        } else {
            Duration::ZERO
        }
    }

    /// `dialer` with this outbound's socket options: the same dialer each
    /// time `dialer` is the same, so a cached session still matches it.
    pub(super) fn socket_dialer<'a>(
        &self,
        dialer: &'a TransportDialer,
    ) -> std::borrow::Cow<'a, TransportDialer> {
        let Some(options) = &self.inner.socket_options else {
            return std::borrow::Cow::Borrowed(dialer);
        };
        let mut cached = self
            .inner
            .socket_dialer
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((given, derived)) = cached.as_ref() {
            if given
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

    async fn client_inner(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
        deadline: tokio::time::Instant,
    ) -> Result<HysteriaClient, CoreError> {
        let _admission = self.inner.connecting.lock().await;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(HysteriaError::Closed.into());
        }
        {
            let mut cached = self.inner.session.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(session) = cached.as_ref().filter(|s| s.client.is_live()) {
                if !session
                    .connector
                    .shares_session_context(dialer.tls_connector())
                {
                    return Err(HysteriaError::Configuration.into());
                }
                return Ok(session.client.clone());
            }
            if let Some(stale) = cached.take() {
                drop(stale);
            }
        }
        let candidates = super::address_port::resolve_server(
            &self.inner.server,
            self.inner.address_port,
            resolver,
            dialer,
        )
        .await?;
        let mut last = HysteriaError::Connect;
        // A realm socket goes to the punched peer whatever the address, so one
        // introduction is all a dial makes.
        let realm = self
            .inner
            .carrier
            .realm
            .as_ref()
            .map(|_| dialer.realm_env());
        // Nor does an xicmp client, which sends to its own addresses or to
        // the one literal address it needs.
        let attempts = if realm.is_some() || self.inner.carrier.xicmp.is_some() {
            1
        } else {
            8
        };
        let attempts = candidates.len().min(attempts);
        let realm_budget = self.realm_budget();
        let build_config = |candidate: SocketAddr| {
            let mut config = HysteriaConfig::new(candidate, self.inner.tls.clone(), String::new());
            config.auth = self.inner.auth.auth.clone();
            config.limits = self.inner.limits;
            config.carrier = self.inner.carrier.clone();
            config.quic = self.inner.quic.clone();
            config.receive_bytes_per_second = self.inner.receive_bytes_per_second;
            config.realm = realm.clone();
            config
        };

        if realm.is_none() && self.inner.carrier.xicmp.is_none() && attempts >= 2 {
            return self
                .race_candidates(
                    candidates.into_iter().take(attempts).collect(),
                    build_config,
                    dialer,
                    deadline,
                )
                .await;
        }

        for (index, candidate) in candidates.into_iter().take(attempts).enumerate() {
            let config = build_config(candidate);
            // Give later DNS candidates a chance within the total operation
            // deadline, and the last one what is left of it.
            let generation = self.inner.network_generation.load(Ordering::Acquire);
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let attempt = tokio::time::timeout(
                attempt_timeout(attempts - index, left.saturating_sub(realm_budget)) + realm_budget,
                HysteriaClient::connect(config, dialer.tls_connector()),
            )
            .await;
            match attempt.unwrap_or(Err(HysteriaError::Timeout)) {
                Ok(client) => {
                    return self.finish_connected(client, dialer, generation);
                }
                Err(
                    error @ (HysteriaError::SocketProtection
                    | HysteriaError::Authentication
                    | HysteriaError::AuthenticationHeaders
                    | HysteriaError::Configuration
                    | HysteriaError::TlsConfiguration),
                ) => return Err(error.into()),
                Err(error) => last = error,
            }
        }
        Err(last.into())
    }

    async fn race_candidates<F>(
        &self,
        candidates: Vec<SocketAddr>,
        build_config: F,
        dialer: &TransportDialer,
        deadline: tokio::time::Instant,
    ) -> Result<HysteriaClient, CoreError>
    where
        F: Fn(SocketAddr) -> HysteriaConfig,
    {
        let total = candidates.len();
        let connector = dialer.tls_connector().clone();
        let mut iter = candidates.into_iter().enumerate();
        let mut in_flight = tokio::task::JoinSet::new();
        let mut last = HysteriaError::Connect;

        let spawn_next =
            |iter: &mut std::iter::Enumerate<std::vec::IntoIter<SocketAddr>>,
             in_flight: &mut tokio::task::JoinSet<RaceAttemptOutcome>| {
                let Some((index, candidate)) = iter.next() else {
                    return false;
                };
                let config = build_config(candidate);
                let connector = connector.clone();
                let generation = self.inner.network_generation.load(Ordering::Acquire);
                let per_attempt_timeout =
                    (index + MAX_CONCURRENT_DIALS < total).then_some(CANDIDATE_ATTEMPT_TIMEOUT);
                in_flight.spawn(async move {
                    let outcome = match per_attempt_timeout {
                        Some(limit) => {
                            tokio::time::timeout(limit, HysteriaClient::connect(config, &connector))
                                .await
                                .unwrap_or(Err(HysteriaError::Timeout))
                        }
                        None => HysteriaClient::connect(config, &connector).await,
                    };
                    (outcome, generation)
                });
                true
            };

        spawn_next(&mut iter, &mut in_flight);

        let race_loop = async {
            loop {
                if in_flight.is_empty() && !spawn_next(&mut iter, &mut in_flight) {
                    return Err(last.into());
                }

                let has_more = iter.len() > 0 && in_flight.len() < MAX_CONCURRENT_DIALS;
                if has_more {
                    let stagger = tokio::time::sleep(HAPPY_EYEBALLS_STAGGER);
                    tokio::pin!(stagger);
                    tokio::select! {
                        biased;
                        res = in_flight.join_next() => {
                            if let Some(result) = self.handle_race_outcome(
                                res,
                                &mut in_flight,
                                dialer,
                                &mut last,
                            )? {
                                return Ok(result);
                            }
                        }
                        () = &mut stagger => {
                            spawn_next(&mut iter, &mut in_flight);
                        }
                    }
                } else {
                    let res = in_flight.join_next().await;
                    if in_flight.is_empty() && res.is_none() {
                        return Err(last.into());
                    }
                    if let Some(result) =
                        self.handle_race_outcome(res, &mut in_flight, dialer, &mut last)?
                    {
                        return Ok(result);
                    }
                }
            }
        };

        match tokio::time::timeout_at(deadline, race_loop).await {
            Ok(result) => result,
            Err(_) => {
                in_flight.abort_all();
                Err(HysteriaError::Timeout.into())
            }
        }
    }

    fn handle_race_outcome(
        &self,
        joined: Option<Result<RaceAttemptOutcome, tokio::task::JoinError>>,
        in_flight: &mut tokio::task::JoinSet<RaceAttemptOutcome>,
        dialer: &TransportDialer,
        last: &mut HysteriaError,
    ) -> Result<Option<HysteriaClient>, CoreError> {
        match joined {
            Some(Ok((Ok(client), generation))) => {
                in_flight.abort_all();
                self.finish_connected(client, dialer, generation).map(Some)
            }
            Some(Ok((
                Err(
                    error @ (HysteriaError::SocketProtection
                    | HysteriaError::Authentication
                    | HysteriaError::AuthenticationHeaders
                    | HysteriaError::Configuration
                    | HysteriaError::TlsConfiguration),
                ),
                _,
            ))) => {
                in_flight.abort_all();
                Err(error.into())
            }
            Some(Ok((Err(error), _))) => {
                *last = error;
                Ok(None)
            }
            Some(Err(_)) | None => Ok(None),
        }
    }

    fn finish_connected(
        &self,
        client: HysteriaClient,
        dialer: &TransportDialer,
        generation: u64,
    ) -> Result<HysteriaClient, CoreError> {
        let mut cached = self.inner.session.lock().unwrap_or_else(|e| e.into_inner());
        if self.inner.closed.load(Ordering::Acquire) {
            client.close();
            return Err(HysteriaError::Closed.into());
        }
        // A usable-path update during auth/socket creation must
        // also reach a client that was not cached at that instant.
        if self.inner.network_generation.load(Ordering::Acquire) != generation {
            client.rebind();
        }
        *cached = Some(CachedSession {
            client: client.clone(),
            connector: dialer.tls_connector().clone(),
        });
        Ok(client)
    }

    pub(crate) async fn open_tcp(
        &self,
        target: &Target,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<BoxedTransportStream, CoreError> {
        Ok(Box::new(
            self.client(resolver, dialer)
                .await?
                .open_tcp(target)
                .await?,
        ))
    }

    pub(crate) async fn open_udp(
        &self,
        resolver: &dyn DnsResolver,
        dialer: &TransportDialer,
    ) -> Result<HysteriaUdpSession, CoreError> {
        Ok(self.client(resolver, dialer).await?.open_udp()?)
    }
}

/// Xray's Hysteria dialer settings from `finalmask.quicParams`, and the
/// receive rate (`brutalDown`) announced in `Hysteria-CC-RX`.
///
/// They differ from XHTTP's: a 30-second idle timeout, no incoming-stream
/// limit of its own, and Brutal at the lower of `brutalUp` and the server's
/// announced rate once both are nonzero, otherwise BBR. quic-go grows a
/// connection's receive windows from the initial value to the maximum, while
/// quinn keeps a Hysteria connection's windows fixed, so the larger of the two
/// is the window. UDP hop travels in the Hysteria carrier instead.
pub(super) fn hysteria_quic_config(
    settings: Option<&QuicParamsSettings>,
) -> Result<(H3QuicConfig, u64), CoreError> {
    let mut quic = super::xhttp::xhttp_h3_quic_config(settings)
        .map_err(|_| CoreError::UnsupportedOutboundNetwork)?;
    let defaults = H3QuicConfig::default();
    let receive_bytes_per_second = settings.map_or(0, |s| s.brutal_down_bytes_per_sec);
    if settings.is_none_or(|s| s.max_idle_timeout_secs == 0) {
        quic.max_idle_timeout = Duration::from_secs(30);
    }
    quic.max_incoming_bidirectional_streams = defaults.max_incoming_bidirectional_streams;
    quic.initial_stream_receive_window = quic
        .initial_stream_receive_window
        .max(quic.max_stream_receive_window.take().unwrap_or(0));
    quic.initial_connection_receive_window = quic
        .initial_connection_receive_window
        .max(quic.max_connection_receive_window.take().unwrap_or(0));
    quic.udp_hop = H3UdpHopConfig::default();
    if let Some(settings) = settings {
        let negotiates = matches!(
            settings.congestion,
            segue_config::QuicCongestion::Default | segue_config::QuicCongestion::Brutal
        );
        if negotiates {
            quic.congestion = if settings.brutal_up_bytes_per_sec > 0 {
                H3Congestion::Brutal {
                    up_bytes_per_second: settings.brutal_up_bytes_per_sec,
                    bbr_profile: super::xhttp::h3_bbr_profile(settings.bbr_profile),
                }
            } else {
                // Without its own rate the client never uses Brutal: BBR.
                super::xhttp::bbr_congestion(settings.bbr_profile)
            };
        }
    }
    quic.diagnostics()
        .map_err(|_| CoreError::UnsupportedOutboundNetwork)?;
    Ok((quic, receive_bytes_per_second))
}

#[cfg(test)]
mod tests;
