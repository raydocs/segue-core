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
use crate::policy::AiPolicy;
use crate::revoke::Revocations;
use crate::ticket::{TicketAuth, Verifier};
use crate::Clock;

/// How often the revocation file is polled (spec pull interval: 30 s).
pub const REVOCATION_POLL: Duration = Duration::from_secs(5);

/// Carrier that holds a slot of the global carrier limit. `pre` holds the
/// bytes read while waiting for the first frame; they are read again first.
struct Counted {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    pre: Vec<u8>,
    pos: usize,
}

impl AsyncRead for Counted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = buf.remaining().min(self.pre.len() - self.pos);
            let p = self.pos;
            buf.put_slice(&self.pre[p..p + n]);
            self.pos += n;
            if self.pos == self.pre.len() {
                self.pre = Vec::new();
                self.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Read until one complete frame has been decoded (or the bytes cannot be
/// a frame: the table answers that, e.g. `REJECT(version)`). Returns the
/// bytes read; `None` on EOF / error before a full frame.
async fn read_first_frame(s: &mut TcpStream) -> Option<Vec<u8>> {
    use segue_session::codec::FrameDecoder;
    use tokio::io::AsyncReadExt as _;
    let mut dec = FrameDecoder::new();
    let mut pre = Vec::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = s.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        pre.extend_from_slice(&buf[..n]);
        dec.push(&buf[..n]);
        match dec.next_frame() {
            Ok(None) => {}
            Ok(Some(_)) | Err(_) => return Some(pre),
        }
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
    pub ai: Arc<AiPolicy>,
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
        let revoked = Arc::new(Revocations::with_state(
            cfg.revocation_file.clone(),
            cfg.revocation_state.clone(),
        ));
        // An accepted state that exists but cannot be read is fatal (review
        // r6 R3): its floor is unknown, and starting from nothing would
        // take back an older snapshot that un-revokes devices.
        revoked
            .restore()
            .map_err(|e| format!("{e}; refusing to start (repair or remove it)"))?;
        if cfg.revocation_file.is_some() {
            // Without an earlier snapshot a bad file is fatal; with one,
            // the file (e.g. an older list replayed) is refused and the
            // restored snapshot stays.
            match (revoked.reload(), revoked.seq()) {
                (Ok(_), _) => {}
                (Err(e), Some(seq)) => crate::log!(
                    "error",
                    "revocation file refused; keeping restored list",
                    "seq" = seq,
                    "error" = e.message
                ),
                (Err(e), None) => return Err(e.into()),
            }
        }
        let ai = Arc::new(AiPolicy::with_state(
            cfg.policy_keys.clone(),
            Some(cfg.policy_bundle.clone()),
            Some(cfg.policy_state.clone()),
        ));
        // The rollback floor of earlier runs first (review r5 N2): a bundle
        // file replaced by an older one while the relay was down is refused.
        if let Err(e) = ai.restore() {
            crate::log!(
                "error",
                "policy state unreadable; refusing all bundles until repaired",
                "error" = e
            );
        }
        // A missing or bad bundle is not fatal: the relay refuses every
        // target until a good one arrives (fail closed).
        match (ai.reload(clock()), ai.version()) {
            (Ok(_), v) => crate::log!("info", "policy bundle loaded", "version" = v),
            (Err(e), Some(v)) => crate::log!(
                "error",
                "policy bundle file rejected; keeping the accepted bundle",
                "version" = v,
                "error" = e
            ),
            (Err(e), None) => crate::log!(
                "error",
                "policy bundle not loaded; refusing all targets",
                "error" = e
            ),
        }
        let home = Arc::new(HomePool::new(
            cfg.home_lines.clone(),
            &cfg.home_assignments,
            cfg.limits.clone(),
            cfg.home_auto_failover,
            metrics.clone(),
        )?);
        let dialer = Arc::new(Dialer {
            node_id: cfg.node_id,
            guard: guard.unwrap_or_else(|| Guard {
                extra_blocked: cfg.blocked_cidrs.clone(),
                exceptions: cfg.dev_allow_cidrs.clone(),
            }),
            ai: ai.clone(),
            home: home.clone(),
            clock: clock.clone(),
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
            ai,
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
        scfg.timing.site_flush_idle = self.cfg.limits.site_flush_idle;
        scfg.timing.site_flush_max = self.cfg.limits.site_flush_max;
        let auth = TicketAuth {
            verifier: self.verifier.clone(),
            revoked: self.revoked.clone(),
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
        let added = match self.revoked.reload() {
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
                added
            }
            Err(e) => {
                if !e.newly_revoked.is_empty() || self.revoked.storage_fault() {
                    // Not committed (state not durable), but the newly
                    // revoked devices are enforced now (review r6 R2).
                    Metrics::inc(&self.metrics.state_persist_failures);
                }
                crate::log!(
                    "error",
                    "revocation snapshot not committed; keeping last list",
                    "enforced_now" = e.newly_revoked.len(),
                    "error" = e.message
                );
                e.newly_revoked
            }
        };
        for d in added {
            Metrics::inc(&self.metrics.devices_reset);
            let _ = ctrl
                .send(RelayCtrl::ResetDevice {
                    device: d,
                    close_code: code::REVOKED,
                })
                .await;
        }
    }
}

impl Relay {
    /// Re-read the policy bundle if it changed; the last good one stays on
    /// error.
    pub fn reload_policy(&self) {
        match self.ai.reload((self.clock)()) {
            Ok(Some(v)) => {
                Metrics::inc(&self.metrics.policy_reloads);
                crate::log!("info", "policy bundle installed", "version" = v);
            }
            Ok(None) => {}
            Err(e) => crate::log!(
                "error",
                "policy bundle rejected; keeping last good",
                "error" = e
            ),
        }
    }
}

/// A spawned task owned by `serve`: aborted when dropped, so a cancelled
/// or aborted `serve` future (hot restart, embedding, tests) takes its
/// driver, notice, revocation/policy, prober and metrics tasks with it
/// instead of leaving them running detached (review r6, server.rs task
/// ownership).
struct Owned(tokio::task::JoinHandle<()>);

impl Drop for Owned {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn own<F: std::future::Future<Output = ()> + Send + 'static>(f: F) -> Owned {
    Owned(tokio::spawn(f))
}

/// Serve until `shutdown` turns true, then drain up to `limits.drain`.
///
/// Every task this spawns is owned by the future: dropping it before it
/// returns aborts them all, including first-frame reads in flight.
pub async fn serve(relay: Arc<Relay>, listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<RelayCtrl>(256);
    let (note_tx, mut note_rx) = mpsc::unbounded_channel::<RelayNotice>();
    let table = relay.table();
    let mut driver = own(run_relay_ctl(
        table,
        accept_rx,
        relay.dialer.connector(),
        Some(note_tx),
        Some(ctrl_rx),
    ));

    let m = relay.metrics.clone();
    let notes = own(async move {
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
        own(async move {
            // Probes run in their own task: a slow or hung gateway must
            // never delay revocation (≤ 60 s to RST, §6.4).
            let _prober = {
                let relay = relay.clone();
                own(async move {
                    let mut probe = tokio::time::interval(relay.cfg.limits.probe_interval);
                    probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        probe.tick().await;
                        if relay.home.line_count() > 0 {
                            relay.home.probe_all(relay.cfg.limits.connect_timeout).await;
                        }
                    }
                })
            };
            let mut rev = tokio::time::interval(REVOCATION_POLL);
            loop {
                rev.tick().await;
                relay.reload_revocations(&ctrl).await;
                relay.reload_policy();
            }
        })
    };

    let metrics_srv = relay.cfg.metrics_listen.map(|addr| {
        let m = relay.metrics.clone();
        own(async move {
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
    // Carriers still waiting for their first frame (aborted on drop).
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
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
                handshakes.spawn(async move {
                    // The whole first frame must arrive and parse within
                    // the deadline; a byte at a time does not extend it.
                    // The table then authenticates that frame at once, and
                    // a failed check closes the carrier with REJECT.
                    let mut s = s;
                    match tokio::time::timeout(first, read_first_frame(&mut s)).await {
                        Ok(Some(pre)) => {
                            Metrics::inc(&m.carriers_accepted);
                            let c = Counted { inner: s, _permit: permit, pre, pos: 0 };
                            let _ = tx.send(Box::new(c)).await;
                        }
                        Ok(None) => {}
                        Err(_) => {
                            Metrics::inc(&m.carriers_first_frame_timeout);
                            let _ = s.set_zero_linger();
                        }
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
    handshakes.abort_all();
    drop(accept_tx);
    drop(bg);
    drop(metrics_srv);
    if tokio::time::timeout(relay.cfg.limits.drain, &mut driver.0)
        .await
        .is_err()
    {
        crate::log!("warn", "drain limit reached; closing remaining sessions");
    }
    drop(driver);
    drop(ctrl_tx);
    drop(notes);
    crate::log!("info", "relay stopped", "metrics" = relay.metrics.render());
}
