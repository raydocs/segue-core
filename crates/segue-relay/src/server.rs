//! Wiring: loopback listener → session carriers → `run_relay_ctl`, the
//! revocation watcher, line probes, metrics endpoint, graceful shutdown.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use segue_session::codec::code;
use segue_session::driver::{run_relay_ctl, BoxCarrier, RelayCtrl, RelayNotice};
use segue_session::pool::Pool;
use segue_session::relay::RelayTable;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};

use crate::config::Config;
use crate::dial::{system_resolver, DeviceCounts, Dialer, Resolver};
use crate::guard::Guard;
use crate::home::HomePool;
use crate::metrics::Metrics;
use crate::revoke::Revocations;
use crate::ticket::{ClaimsCache, TicketAuth, Verifier};
use crate::Clock;

/// How often the revocation file is polled (spec pull interval: 30 s).
pub const REVOCATION_POLL: Duration = Duration::from_secs(5);

/// Carrier that holds a slot of the global carrier limit.
struct Counted {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Everything the relay shares between tasks.
pub struct Relay {
    pub cfg: Config,
    pub metrics: Arc<Metrics>,
    pub revoked: Arc<Revocations>,
    pub claims: Arc<ClaimsCache>,
    pub home: Arc<HomePool>,
    pub dialer: Arc<Dialer>,
    pub verifier: Arc<Verifier>,
    pub clock: Clock,
}

impl Relay {
    pub fn new(
        cfg: Config,
        clock: Clock,
        resolver: Option<Resolver>,
        guard: Option<Guard>,
    ) -> Result<Self, String> {
        let metrics = Arc::new(Metrics::default());
        let revoked = Arc::new(Revocations::new(cfg.revocation_file.clone()));
        if cfg.revocation_file.is_some() {
            revoked.reload()?;
        }
        let claims = Arc::new(ClaimsCache::default());
        let home = Arc::new(HomePool::new(
            cfg.home_lines.clone(),
            &cfg.home_assignments,
            cfg.limits.clone(),
            cfg.home_auto_failover,
            metrics.clone(),
        )?);
        let dialer = Arc::new(Dialer {
            node_id: cfg.node_id,
            guard: guard.unwrap_or_else(|| Guard::new(cfg.blocked_cidrs.clone())),
            ai: cfg.ai.clone(),
            home: home.clone(),
            claims: claims.clone(),
            metrics: metrics.clone(),
            resolver: resolver.unwrap_or_else(system_resolver),
            devices: Arc::new(DeviceCounts::default()),
            max_sessions_per_device: cfg.limits.max_sessions_per_device,
            connect_timeout: cfg.limits.connect_timeout,
            dns_timeout: cfg.limits.dns_timeout,
        });
        let verifier = Arc::new(Verifier::new(cfg.ticket_keys.clone()));
        Ok(Self {
            cfg,
            metrics,
            revoked,
            claims,
            home,
            dialer,
            verifier,
            clock,
        })
    }

    pub fn table(&self) -> RelayTable {
        let mut scfg = segue_session::Config::default();
        scfg.limits.window_cap = self.cfg.limits.window_cap;
        scfg.limits.replay_cap = self.cfg.limits.replay_cap;
        let auth = TicketAuth {
            verifier: self.verifier.clone(),
            revoked: self.revoked.clone(),
            claims: self.claims.clone(),
            metrics: self.metrics.clone(),
            clock: self.clock.clone(),
        };
        RelayTable::new(
            scfg,
            Pool::new(self.cfg.limits.pool_bytes),
            Box::new(auth),
            (rand::random::<u64>() >> 2) | 1,
        )
    }

    /// Re-read the revocation list; RST sessions of newly revoked devices.
    pub async fn reload_revocations(&self, ctrl: &mpsc::Sender<RelayCtrl>) {
        match self.revoked.reload() {
            Ok(added) => {
                if !added.is_empty() {
                    Metrics::inc(&self.metrics.revocation_reloads);
                    crate::log!(
                        "info",
                        "revocation list reloaded",
                        "entries" = self.revoked.len(),
                        "new" = added.len()
                    );
                }
                for d in added {
                    self.claims.remove(d);
                    Metrics::inc(&self.metrics.devices_reset);
                    let _ = ctrl
                        .send(RelayCtrl::ResetDevice {
                            device: d,
                            close_code: code::REVOKED,
                        })
                        .await;
                }
            }
            Err(e) => crate::log!(
                "error",
                "revocation reload failed; keeping last list",
                "error" = e
            ),
        }
    }
}

/// Serve until `shutdown` turns true, then drain up to `limits.drain`.
pub async fn serve(relay: Arc<Relay>, listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<RelayCtrl>(256);
    let (note_tx, mut note_rx) = mpsc::unbounded_channel::<RelayNotice>();
    let table = relay.table();
    let driver = tokio::spawn(run_relay_ctl(
        table,
        accept_rx,
        relay.dialer.connector(),
        Some(note_tx),
        Some(ctrl_rx),
    ));

    let m = relay.metrics.clone();
    let notes = tokio::spawn(async move {
        while let Some(n) = note_rx.recv().await {
            if let RelayNotice::Closed { close_code, .. } = n {
                Metrics::inc(&m.sessions_closed);
                let _ = close_code;
            }
        }
    });

    let bg = {
        let relay = relay.clone();
        let ctrl = ctrl_tx.clone();
        tokio::spawn(async move {
            let mut rev = tokio::time::interval(REVOCATION_POLL);
            let mut probe = tokio::time::interval(relay.cfg.limits.probe_interval);
            loop {
                tokio::select! {
                    _ = rev.tick() => relay.reload_revocations(&ctrl).await,
                    _ = probe.tick() => {
                        if relay.home.line_count() > 0 {
                            relay.home.probe_all(relay.cfg.limits.connect_timeout).await;
                        }
                    }
                }
            }
        })
    };

    let metrics_srv = relay.cfg.metrics_listen.map(|addr| {
        let m = relay.metrics.clone();
        tokio::spawn(async move {
            let Ok(l) = TcpListener::bind(addr).await else {
                crate::log!("error", "metrics listen failed", "addr" = addr.to_string());
                return;
            };
            while let Ok((mut s, _)) = l.accept().await {
                let body = m.render();
                let resp = format!("HTTP/1.0 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\n\r\n{body}", body.len());
                let _ = s.write_all(resp.as_bytes()).await;
            }
        })
    });

    let limit = Arc::new(Semaphore::new(relay.cfg.limits.max_carriers));
    let first = relay.cfg.limits.first_frame_timeout;
    loop {
        tokio::select! {
            r = listener.accept() => {
                let Ok((s, _peer)) = r else { continue };
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    Metrics::inc(&relay.metrics.carriers_rejected_limit);
                    let _ = s.set_zero_linger();
                    drop(s);
                    continue;
                };
                let _ = s.set_nodelay(true);
                let tx = accept_tx.clone();
                let m = relay.metrics.clone();
                tokio::spawn(async move {
                    // A carrier must start talking quickly; idle sockets
                    // would otherwise pin a slot.
                    let mut b = [0u8; 1];
                    match tokio::time::timeout(first, s.peek(&mut b)).await {
                        Ok(Ok(n)) if n > 0 => {
                            Metrics::inc(&m.carriers_accepted);
                            let _ = tx.send(Box::new(Counted { inner: s, _permit: permit })).await;
                        }
                        Ok(_) => {}
                        Err(_) => Metrics::inc(&m.carriers_first_frame_timeout),
                    }
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
    crate::log!(
        "info",
        "shutting down; draining sessions",
        "drain_secs" = relay.cfg.limits.drain.as_secs()
    );
    drop(listener);
    drop(accept_tx);
    bg.abort();
    if let Some(h) = metrics_srv {
        h.abort();
    }
    let mut driver = driver;
    if tokio::time::timeout(relay.cfg.limits.drain, &mut driver)
        .await
        .is_err()
    {
        crate::log!("warn", "drain limit reached; closing remaining sessions");
        driver.abort();
    }
    drop(ctrl_tx);
    notes.abort();
    crate::log!("info", "relay stopped", "metrics" = relay.metrics.render());
}
