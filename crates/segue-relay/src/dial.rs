//! Site connector: independent classification (R2-1), exit checks (§5.5),
//! SSRF guard, overseas direct dial and Home SOCKS5 dial. A refused route is
//! answered with its code; nothing ever falls back to a direct connection.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use segue_session::codec::{code, Kind, Target};
use segue_session::driver::{BoxCarrier, BoxFuture, DeviceSiteConnector, SiteError, SiteRequest};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::guard::Guard;
use crate::home::{HomeError, HomePool, Lease};
use crate::metrics::Metrics;
use crate::policy::{normalize_domain, AiPolicy};
use crate::ticket::{grant_allows, ExitClass};
use crate::Clock;
use segue_session::relay::Grant;

/// Resolves a host name to addresses (injectable for tests).
pub type Resolver = Arc<dyn Fn(String) -> BoxFuture<io::Result<Vec<IpAddr>>> + Send + Sync>;

pub fn system_resolver() -> Resolver {
    Arc::new(|host: String| {
        Box::pin(async move {
            let it = tokio::net::lookup_host((host.as_str(), 0)).await?;
            Ok(it.map(|a| a.ip()).collect())
        })
    })
}

/// Per-device live site connections.
#[derive(Default)]
pub struct DeviceCounts {
    map: Mutex<HashMap<u64, usize>>,
}

impl DeviceCounts {
    fn try_acquire(self: &Arc<Self>, device: u64, max: usize) -> Option<DeviceSlot> {
        let mut m = self.map.lock().unwrap();
        let n = m.entry(device).or_default();
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(DeviceSlot {
            counts: self.clone(),
            device,
        })
    }

    pub fn get(&self, device: u64) -> usize {
        self.map.lock().unwrap().get(&device).copied().unwrap_or(0)
    }
}

struct DeviceSlot {
    counts: Arc<DeviceCounts>,
    device: u64,
}

impl Drop for DeviceSlot {
    fn drop(&mut self) {
        let mut m = self.counts.map.lock().unwrap();
        if let Some(n) = m.get_mut(&self.device) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.device);
            }
        }
    }
}

/// Site stream that holds the device slot and counts Home bytes.
struct Site<S> {
    inner: S,
    _slot: DeviceSlot,
    home: Option<(Arc<Metrics>, String)>,
    /// Home seat held for as long as this connection lives.
    _lease: Option<Lease>,
    bytes: AtomicU64,
}

impl<S> Drop for Site<S> {
    fn drop(&mut self) {
        if let Some((m, line)) = &self.home {
            m.add_home_bytes(line, self.bytes.load(Ordering::Relaxed));
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Site<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        self.bytes.fetch_add(n, Ordering::Relaxed);
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Site<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            self.bytes.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Addresses tried per overseas connect.
const MAX_CONNECT_ADDRS: usize = 4;

pub struct Dialer {
    pub node_id: u64,
    pub guard: Guard,
    pub ai: Arc<AiPolicy>,
    pub home: Arc<HomePool>,
    pub clock: Clock,
    pub metrics: Arc<Metrics>,
    pub resolver: Resolver,
    pub devices: Arc<DeviceCounts>,
    pub max_sessions_per_device: usize,
    pub connect_timeout: Duration,
    pub dns_timeout: Duration,
}

/// Where a target goes after classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Overseas(Vec<SocketAddr>),
    Home(SocketAddr),
}

impl Dialer {
    pub fn connector(self: &Arc<Self>) -> DeviceSiteConnector {
        let d = self.clone();
        Arc::new(move |r: SiteRequest| {
            let d = d.clone();
            Box::pin(async move { d.connect(r).await })
        })
    }

    fn deny(&self, c: u8) -> io::Error {
        SiteError::io(c)
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, u8> {
        match tokio::time::timeout(self.dns_timeout, (self.resolver)(host.to_string())).await {
            Ok(Ok(v)) if !v.is_empty() => Ok(v),
            _ => {
                Metrics::inc(&self.metrics.dns_failures);
                Err(code::DNS_FAILURE)
            }
        }
    }

    /// Classify and check a target for the session whose OPEN produced
    /// `grant`. Pure policy; no connect.
    ///
    /// The relay classifies on its own (R2-1) with the AI set of the signed
    /// bundle. The client's hint can only make the decision stricter: an
    /// `overseas` hint on an AI target is upgraded to AI, but an `ai` hint
    /// the relay cannot confirm is refused (`target_denied`), never sent
    /// out of the data centre as overseas.
    pub async fn route(&self, grant: &Grant, target: &Target, hint: u8) -> Result<Route, u8> {
        let device = grant.device;
        let Some(ai) = self.ai.check((self.clock)()) else {
            // No unexpired signed bundle: nothing can be classified.
            Metrics::inc(&self.metrics.policy_unavailable);
            return Err(code::TARGET_DENIED);
        };
        let (ai_name, ips, port) = match target {
            Target::Ip(a) => (false, vec![a.ip()], a.port()),
            Target::Domain(name, port) => {
                let n = normalize_domain(name).ok_or(code::TARGET_DENIED)?;
                let ai = ai.is_ai_domain(&n);
                (ai, self.resolve(&n).await?, *port)
            }
        };
        if port == 0 {
            return Err(code::TARGET_DENIED);
        }
        let is_ai = ai_name || ips.iter().any(|&ip| ai.is_ai_ip(ip));
        let hint_ai = hint == crate::hint::AI;
        if is_ai != hint_ai {
            let n = self.metrics.reclass(device);
            if n == 1 || n.is_power_of_two() {
                crate::log!(
                    "warn",
                    "target reclassified",
                    "device" = device,
                    "hint" = hint,
                    "ai" = is_ai,
                    "policy_version" = ai.version(),
                    "count" = n
                );
            }
            if hint_ai {
                // Never downgrade AI to the data-centre exit.
                Metrics::inc(&self.metrics.target_denied);
                return Err(code::TARGET_DENIED);
            }
        }
        let allowed: Vec<IpAddr> = ips
            .iter()
            .copied()
            .filter(|&ip| self.guard.allows(ip))
            .collect();
        if allowed.len() != ips.len() {
            // Any forbidden answer makes the whole name suspect (rebinding),
            // for both overseas and Home targets.
            Metrics::inc(&self.metrics.ssrf_blocked);
            return Err(code::TARGET_DENIED);
        }
        if is_ai {
            if !grant_allows(grant, ExitClass::Ai) {
                Metrics::inc(&self.metrics.exit_denied);
                return Err(code::EXIT_DENIED);
            }
            if grant.ai_anchor_node_id != 0 && grant.ai_anchor_node_id != self.node_id {
                // Cross-node AI anchoring is M9+.
                Metrics::inc(&self.metrics.exit_denied);
                return Err(code::EXIT_DENIED);
            }
            // Home lines have no IPv6 (§5.6 item 5); every address must be
            // either a whitelisted IP or a result of a whitelisted name.
            let pick = allowed
                .iter()
                .copied()
                .find(|ip| crate::cidr::canon(*ip).is_ipv4() && (ai_name || ai.is_ai_ip(*ip)));
            return match pick {
                Some(ip) => Ok(Route::Home(SocketAddr::new(crate::cidr::canon(ip), port))),
                None => {
                    Metrics::inc(&self.metrics.target_denied);
                    Err(code::TARGET_DENIED)
                }
            };
        }
        if !grant_allows(grant, ExitClass::Overseas) {
            Metrics::inc(&self.metrics.exit_denied);
            return Err(code::EXIT_DENIED);
        }
        if allowed.is_empty() {
            Metrics::inc(&self.metrics.ssrf_blocked);
            return Err(code::TARGET_DENIED);
        }
        Ok(Route::Overseas(
            allowed
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        ))
    }

    pub async fn connect(&self, r: SiteRequest) -> io::Result<BoxCarrier> {
        if r.kind != Kind::Tcp {
            Metrics::inc(&self.metrics.exit_denied);
            return Err(self.deny(code::EXIT_DENIED));
        }
        let Some(slot) = self
            .devices
            .try_acquire(r.grant.device, self.max_sessions_per_device)
        else {
            Metrics::inc(&self.metrics.session_limit);
            return Err(self.deny(code::CAPACITY));
        };
        let route = self
            .route(&r.grant, &r.target, r.exit_class)
            .await
            .map_err(|c| self.deny(c))?;
        match route {
            Route::Overseas(addrs) => {
                let mut last = code::CONNECT_REFUSED;
                // Bound the total connect time: a name with many dead
                // addresses must not hold the slot for `n × timeout`.
                for a in addrs.into_iter().take(MAX_CONNECT_ADDRS) {
                    match tokio::time::timeout(self.connect_timeout, TcpStream::connect(a)).await {
                        Ok(Ok(s)) => {
                            let _ = s.set_nodelay(true);
                            Metrics::inc(&self.metrics.connects_overseas);
                            return Ok(Box::new(Site {
                                inner: s,
                                _slot: slot,
                                home: None,
                                _lease: None,
                                bytes: AtomicU64::new(0),
                            }));
                        }
                        Ok(Err(_)) => last = code::CONNECT_REFUSED,
                        Err(_) => last = code::CONNECT_TIMEOUT,
                    }
                }
                Metrics::inc(&self.metrics.connect_failures);
                Err(self.deny(last))
            }
            Route::Home(a) => match self
                .home
                .dial(r.grant.device, a, self.connect_timeout)
                .await
            {
                Ok((s, line, lease)) => {
                    Metrics::inc(&self.metrics.connects_home);
                    Ok(Box::new(Site {
                        inner: s,
                        _slot: slot,
                        home: Some((self.metrics.clone(), line)),
                        _lease: Some(lease),
                        bytes: AtomicU64::new(0),
                    }))
                }
                Err(HomeError::TargetRefused) => {
                    Metrics::inc(&self.metrics.connect_failures);
                    Err(self.deny(code::CONNECT_REFUSED))
                }
                Err(e) => {
                    Metrics::inc(&self.metrics.home_unavailable);
                    crate::log!(
                        "warn",
                        "home unavailable",
                        "device" = r.grant.device,
                        "reason" = format!("{e:?}")
                    );
                    Err(self.deny(code::HOME_UNAVAILABLE))
                }
            },
        }
    }
}
