//! Session-layer routes (SESSION_PROTOCOL v0.4) behind the [`Dialer`] seam.
//!
//! A rule whose outbound tag names a `segue` route does not dial the target
//! through the engine. Instead it opens a resumable session to the node's
//! relay: every carrier is an engine stream (Reality / Hy2) to the relay's
//! loopback address on the node. A dropped carrier is replaced with RESUME,
//! so the app connection survives the outer tunnel dying.
//!
//! The app gets success only after the relay answered OPENED, which it does
//! only once the site connect worked: a refused session (exit_denied,
//! home_unavailable, target_denied, ...) is a dial error, so SOCKS answers
//! with an error and nothing is ever retried direct.
//!
//! Kill switch (KILLSWITCH.md L1): carrier outcomes drive a [`KillSwitch`].
//! While a carrier cannot be established (`Reconnecting` / `Error`), new
//! flows on strict (AI) routes are refused at once; overseas flows are tried
//! (the session retries OPEN for a bounded time) and refused if that fails.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use segue_routing::TargetAddr;
use segue_session::client::{ClientSession, CloseReason, OpenParams};
use segue_session::codec::{Kind, Target};
use segue_session::driver::{run_client_ctl, BoxCarrier, ClientCtl, Connector};
use segue_session::pool::Pool;

use crate::dial::{Datagrams, DialError, Dialer, EngineDialer, Stream};
use crate::killswitch::{Event, KillSwitch, Posture};

/// `exit_class` hints in OPEN (the relay classifies by itself).
pub const EXIT_OVERSEAS: u8 = 0;
pub const EXIT_AI: u8 = 1;

/// Session memory for all client sessions of this process.
pub const POOL_BYTES: usize = 32 << 20;
/// Longest wait for OPENED (covers the session's own OPEN retries).
const OPEN_WAIT: Duration = Duration::from_secs(20);
/// After this long since the last failed carrier connect, a strict route
/// may try again (the next carrier attempt decides the posture).
const STRICT_RETRY_AFTER: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct SegueRoute {
    /// Engine outbound that carries the session.
    pub carrier: String,
    /// Relay address as the carrier's server sees it.
    pub relay: SocketAddr,
    pub ticket: Vec<u8>,
    pub exit_class: u8,
    pub anchor_node_id: u64,
}

impl std::fmt::Debug for SegueRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegueRoute")
            .field("carrier", &self.carrier)
            .field("relay", &self.relay)
            .field("ticket", &"<redacted>")
            .field("exit_class", &self.exit_class)
            .field("anchor_node_id", &self.anchor_node_id)
            .finish()
    }
}

struct Health {
    ks: KillSwitch,
    last_fail: Option<Instant>,
}

/// Engine outbounds plus session routes.
pub struct KernelDialer {
    engine: Arc<EngineDialer>,
    routes: BTreeMap<String, SegueRoute>,
    pool: Arc<Pool>,
    health: Arc<Mutex<Health>>,
}

impl KernelDialer {
    pub fn new(engine: EngineDialer, routes: BTreeMap<String, SegueRoute>) -> Self {
        Self {
            engine: Arc::new(engine),
            routes,
            pool: Pool::new(POOL_BYTES),
            health: Arc::new(Mutex::new(Health {
                ks: KillSwitch::new(),
                last_fail: None,
            })),
        }
    }

    pub fn posture(&self) -> Posture {
        self.health.lock().unwrap().ks.posture()
    }

    fn connector(&self, r: &SegueRoute) -> Connector {
        let engine = self.engine.clone();
        let health = self.health.clone();
        let carrier = r.carrier.clone();
        let relay = r.relay;
        Arc::new(move || {
            let engine = engine.clone();
            let health = health.clone();
            let carrier = carrier.clone();
            Box::pin(async move {
                let res = tokio::time::timeout(
                    Duration::from_secs(10),
                    engine.dial(Some(&carrier), &TargetAddr::Ip(relay.ip()), relay.port()),
                )
                .await;
                let mut h = health.lock().unwrap();
                match res {
                    Ok(Ok(s)) => {
                        h.ks.on_event(Event::ChannelUp);
                        h.last_fail = None;
                        Ok(Box::new(s) as BoxCarrier)
                    }
                    Ok(Err(e)) => {
                        mark_failed(&mut h);
                        Err(std::io::Error::other(e.0))
                    }
                    Err(_) => {
                        mark_failed(&mut h);
                        Err(std::io::ErrorKind::TimedOut.into())
                    }
                }
            })
        })
    }

    async fn open(
        &self,
        r: &SegueRoute,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        if r.exit_class == EXIT_AI {
            let h = self.health.lock().unwrap();
            let down = matches!(h.ks.posture(), Posture::Reconnecting | Posture::Error)
                && h.last_fail
                    .is_some_and(|t| t.elapsed() < STRICT_RETRY_AFTER);
            if down {
                return Err(DialError(
                    "refused: tunnel reconnecting (strict route)".into(),
                ));
            }
        }
        let target = match addr {
            TargetAddr::Ip(ip) => Target::Ip(SocketAddr::new(*ip, port)),
            TargetAddr::Domain(d) => Target::Domain(d.clone(), port),
        };
        let params = OpenParams {
            ticket: r.ticket.clone(),
            kind: Kind::Tcp,
            target,
            exit_class: r.exit_class,
            anchor_node_id: r.anchor_node_id,
            instance_hint: 0,
        };
        let s = ClientSession::new(Default::default(), &self.pool, params, Instant::now())
            .ok_or_else(|| DialError("refused: session memory exhausted".into()))?;
        let (app, far) = tokio::io::duplex(64 << 10);
        let (open_tx, open_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, mut closed_rx) = tokio::sync::oneshot::channel();
        let ctl = ClientCtl {
            reattach: None,
            closed: Some(closed_tx),
            opened: Some(open_tx),
        };
        tokio::spawn(run_client_ctl(s, far, self.connector(r), ctl));
        tokio::select! {
            o = open_rx => match o {
                Ok(()) => Ok(Box::new(app)),
                Err(_) => Err(DialError(closed_text((&mut closed_rx).await.ok()))),
            },
            c = &mut closed_rx => Err(DialError(closed_text(c.ok()))),
            _ = tokio::time::sleep(OPEN_WAIT) => Err(DialError("session open timed out".into())),
        }
    }
}

fn mark_failed(h: &mut Health) {
    match h.ks.posture() {
        Posture::Connected => {
            h.ks.on_event(Event::ChannelLost);
        }
        Posture::Error => {
            h.ks.on_event(Event::Retry);
        }
        _ => {}
    }
    h.last_fail = Some(Instant::now());
}

fn closed_text(r: Option<CloseReason>) -> String {
    match r {
        Some(CloseReason::Refused(c)) => format!("session refused (code {c})"),
        Some(CloseReason::Reset(c)) => format!("session reset (code {c})"),
        Some(CloseReason::Clean) => "session closed before open".into(),
        None => "session ended".into(),
    }
}

#[async_trait]
impl Dialer for KernelDialer {
    async fn dial(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        match tag.and_then(|t| self.routes.get(t)) {
            Some(r) => self.open(r, addr, port).await,
            None => self.engine.dial(tag, addr, port).await,
        }
    }

    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        if tag.is_some_and(|t| self.routes.contains_key(t)) {
            // UDP sessions are not implemented; Home UDP is refused anyway.
            return Err(DialError("udp refused on session routes".into()));
        }
        self.engine.dial_udp(tag, addr, port).await
    }
}
