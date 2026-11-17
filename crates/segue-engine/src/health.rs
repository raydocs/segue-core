use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use segue_config::{ObservatoryConfig, OBSERVATORY_PROBE_TIMEOUT};
use segue_transport::{DnsResolver, TransportDialer};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::outbound::{OutboundNodeId, OutboundRouter, OutboundSelectionOverlay};
use crate::startup_probe::{
    run_outbound_url_probe, ProbeStatusPolicy, StartupProbeError, StartupProbeOptions,
};

const MAX_CONCURRENT_HEALTH_PROBES: usize = 4;

/// sing-box urltest `idle_timeout` (`constant.DefaultURLTestIdleTimeout`).
pub(crate) const DEFAULT_OBSERVATORY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

pub(crate) struct ObservatoryRuntime {
    config: ObservatoryConfig,
    nodes: Vec<OutboundNodeId>,
    outbound_router: Arc<OutboundRouter>,
    selection: Arc<OutboundSelectionOverlay>,
    destination_resolver: Arc<dyn DnsResolver>,
    bootstrap_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    lazy_idle_timeout: Option<Duration>,
    activity: Option<Arc<ObservatoryActivity>>,
}

impl ObservatoryRuntime {
    pub(crate) fn new(
        config: ObservatoryConfig,
        nodes: Vec<OutboundNodeId>,
        outbound_router: Arc<OutboundRouter>,
        selection: Arc<OutboundSelectionOverlay>,
        destination_resolver: Arc<dyn DnsResolver>,
        bootstrap_resolver: Arc<dyn DnsResolver>,
        transport_dialer: Arc<TransportDialer>,
        lazy_idle_timeout: Option<Duration>,
    ) -> Self {
        let activity = lazy_idle_timeout.map(|_| ObservatoryActivity::new());
        if let Some(activity) = &activity {
            selection.configure_observatory_activity(Arc::clone(activity));
        }
        Self {
            config,
            nodes,
            outbound_router,
            selection,
            destination_resolver,
            bootstrap_resolver,
            transport_dialer,
            lazy_idle_timeout,
            activity,
        }
    }
}

/// A channel-notified generation, so a connection during a probe or at an idle
/// boundary cannot be lost. Selection only bumps this watch; it does not take
/// the health update lock or spawn work.
#[derive(Debug)]
pub(crate) struct ObservatoryActivity {
    changed: watch::Sender<ObservatoryActivityState>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ObservatoryActivityState {
    generation: u64,
    active: bool,
}

impl ObservatoryActivity {
    pub(crate) fn new() -> Arc<Self> {
        let (changed, _receiver) = watch::channel(ObservatoryActivityState::default());
        Arc::new(Self { changed })
    }

    pub(crate) fn touch(&self) {
        self.changed.send_modify(|state| {
            state.generation = state.generation.wrapping_add(1);
            state.active = true;
        });
    }

    pub(crate) fn generation(&self) -> u64 {
        self.changed.borrow().generation
    }

    /// Reads the latest touch. A new generation moves `last_active` to the
    /// scheduler's Tokio clock, not the wall clock.
    fn observe(
        &self,
        receiver: &mut watch::Receiver<ObservatoryActivityState>,
        seen_generation: &mut u64,
        last_active: &mut tokio::time::Instant,
    ) -> bool {
        let state = *receiver.borrow_and_update();
        if state.generation != *seen_generation {
            *seen_generation = state.generation;
            *last_active = tokio::time::Instant::now();
        }
        state.active
    }

    /// Clears `active` only when no touch newer than `seen_generation` has
    /// landed. Returns true when probing should continue.
    fn retain_if_newer_than(&self, seen_generation: u64) -> bool {
        let mut continue_probing = false;
        self.changed.send_if_modified(|state| {
            if state.generation != seen_generation {
                continue_probing = state.active;
                return false;
            }
            if !state.active {
                continue_probing = false;
                return false;
            }
            state.active = false;
            continue_probing = false;
            true
        });
        continue_probing
    }
}

pub(crate) async fn run_observatory(
    runtime: ObservatoryRuntime,
    mut shutdown: watch::Receiver<bool>,
) {
    if runtime.nodes.is_empty() {
        return;
    }
    if let Some(idle_timeout) = runtime.lazy_idle_timeout {
        if let Some(activity) = runtime.activity.clone() {
            let mut rounds = RuntimeRounds {
                runtime: &runtime,
                next_node: 0,
                one_node_sequential: true,
            };
            run_lazy_schedule(
                &mut rounds,
                &activity,
                runtime.config.probe_interval,
                runtime.config.enable_concurrency,
                idle_timeout,
                &mut shutdown,
            )
            .await;
            return;
        }
    }
    run_eager_observatory(runtime, &mut shutdown).await;
}

/// Today's loop. Concurrent rounds sleep `probe_interval` after the round.
/// Sequential rounds sleep after every node inside the round, and this loop
/// does not add another wait. Lazy mode does not call this.
async fn run_eager_observatory(runtime: ObservatoryRuntime, shutdown: &mut watch::Receiver<bool>) {
    let probe_interval = runtime.config.probe_interval;
    let concurrent = runtime.config.enable_concurrency;
    let mut rounds = RuntimeRounds {
        runtime: &runtime,
        next_node: 0,
        one_node_sequential: false,
    };
    run_eager_schedule(&mut rounds, probe_interval, concurrent, shutdown).await;
}

trait ObservatoryRounds {
    fn probe_round(
        &mut self,
        shutdown: &mut watch::Receiver<bool>,
    ) -> impl std::future::Future<Output = bool> + Send + '_;
}

struct RuntimeRounds<'a> {
    runtime: &'a ObservatoryRuntime,
    next_node: usize,
    /// Eager sequential mode probes the whole list per call, as before. Lazy
    /// sequential mode probes one node so the idle timeout can land between nodes.
    one_node_sequential: bool,
}

impl ObservatoryRounds for RuntimeRounds<'_> {
    async fn probe_round(&mut self, shutdown: &mut watch::Receiver<bool>) -> bool {
        if self.runtime.config.enable_concurrency {
            return run_concurrent_round(
                &self.runtime.config,
                &self.runtime.nodes,
                &self.runtime.outbound_router,
                &self.runtime.selection,
                &self.runtime.destination_resolver,
                &self.runtime.bootstrap_resolver,
                &self.runtime.transport_dialer,
                shutdown,
            )
            .await;
        }
        if !self.one_node_sequential {
            return run_sequential_round(
                &self.runtime.config,
                &self.runtime.nodes,
                &self.runtime.outbound_router,
                &self.runtime.selection,
                &self.runtime.destination_resolver,
                &self.runtime.bootstrap_resolver,
                &self.runtime.transport_dialer,
                shutdown,
            )
            .await;
        }
        self.probe_one_sequential_node(shutdown).await
    }
}

impl RuntimeRounds<'_> {
    /// One iteration of [`run_sequential_round`]: probe, then sleep the interval.
    async fn probe_one_sequential_node(&mut self, shutdown: &mut watch::Receiver<bool>) -> bool {
        let node_count = self.runtime.nodes.len();
        if node_count == 0 {
            return false;
        }
        if self.next_node >= node_count {
            self.next_node = 0;
        }
        let node = self.runtime.nodes[self.next_node];
        self.next_node += 1;
        if self.next_node == node_count {
            self.next_node = 0;
        }
        let result = tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => return false,
            result = probe_node(
                &self.runtime.config,
                node,
                &self.runtime.outbound_router,
                &self.runtime.destination_resolver,
                &self.runtime.bootstrap_resolver,
                &self.runtime.transport_dialer,
            ) => result,
        };
        record_result(&self.runtime.selection, node, result);
        !wait_interval_or_shutdown(self.runtime.config.probe_interval, shutdown).await
    }
}

enum AfterRound {
    Again,
    Paused,
    Stopped,
}

async fn run_eager_schedule<R: ObservatoryRounds>(
    rounds: &mut R,
    probe_interval: Duration,
    concurrent: bool,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        let completed = rounds.probe_round(shutdown).await;
        if !completed || !concurrent {
            if !completed {
                return;
            }
            continue;
        }
        if wait_interval_or_shutdown(probe_interval, shutdown).await {
            return;
        }
    }
}

/// Starts on the first health-aware balancer connection, pauses after
/// `idle_timeout` without one, and resumes on the next. Pausing does not clear
/// observations already recorded on the selection overlay.
async fn run_lazy_schedule<R: ObservatoryRounds>(
    rounds: &mut R,
    activity: &ObservatoryActivity,
    probe_interval: Duration,
    concurrent: bool,
    idle_timeout: Duration,
    shutdown: &mut watch::Receiver<bool>,
) {
    let mut notifications = activity.changed.subscribe();
    let mut seen_generation = 0u64;
    let mut last_active = tokio::time::Instant::now();
    loop {
        while !activity.observe(&mut notifications, &mut seen_generation, &mut last_active) {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                biased;
                () = wait_for_shutdown(shutdown) => return,
                changed = notifications.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
        }
        loop {
            if !rounds.probe_round(shutdown).await {
                return;
            }
            let step = if concurrent {
                wait_out_concurrent_gap(
                    activity,
                    &mut notifications,
                    &mut seen_generation,
                    &mut last_active,
                    probe_interval,
                    idle_timeout,
                    shutdown,
                )
                .await
            } else {
                finish_sequential_step(
                    activity,
                    &mut notifications,
                    &mut seen_generation,
                    &mut last_active,
                    idle_timeout,
                    shutdown,
                )
            };
            match step {
                AfterRound::Again => {}
                AfterRound::Paused => break,
                AfterRound::Stopped => return,
            }
        }
    }
}

fn finish_sequential_step(
    activity: &ObservatoryActivity,
    notifications: &mut watch::Receiver<ObservatoryActivityState>,
    seen_generation: &mut u64,
    last_active: &mut tokio::time::Instant,
    idle_timeout: Duration,
    shutdown: &watch::Receiver<bool>,
) -> AfterRound {
    if *shutdown.borrow() {
        return AfterRound::Stopped;
    }
    if !activity.observe(notifications, seen_generation, last_active) {
        return AfterRound::Paused;
    }
    // The node step already slept `probe_interval`, matching eager sequential
    // mode. Do not sleep again; only decide whether the next node may start.
    if idle_elapsed(*last_active, idle_timeout) {
        if activity.retain_if_newer_than(*seen_generation) {
            activity.observe(notifications, seen_generation, last_active);
        } else {
            return AfterRound::Paused;
        }
    }
    AfterRound::Again
}

async fn wait_out_concurrent_gap(
    activity: &ObservatoryActivity,
    notifications: &mut watch::Receiver<ObservatoryActivityState>,
    seen_generation: &mut u64,
    last_active: &mut tokio::time::Instant,
    probe_interval: Duration,
    idle_timeout: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> AfterRound {
    // Eager concurrent mode also counts the interval from the end of the round,
    // including when the probes themselves outlasted it.
    let next_round = tokio::time::Instant::now() + probe_interval;
    loop {
        if *shutdown.borrow() {
            return AfterRound::Stopped;
        }
        if !activity.observe(notifications, seen_generation, last_active) {
            return AfterRound::Paused;
        }
        let now = tokio::time::Instant::now();
        if idle_elapsed(*last_active, idle_timeout) {
            if activity.retain_if_newer_than(*seen_generation) {
                activity.observe(notifications, seen_generation, last_active);
                continue;
            }
            return AfterRound::Paused;
        }
        if now >= next_round {
            return AfterRound::Again;
        }
        let wake_at = next_round.min(*last_active + idle_timeout);
        tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => return AfterRound::Stopped,
            changed = notifications.changed() => {
                if changed.is_err() {
                    return AfterRound::Stopped;
                }
            }
            () = tokio::time::sleep_until(wake_at) => {}
        }
    }
}

fn idle_elapsed(last_active: tokio::time::Instant, idle_timeout: Duration) -> bool {
    tokio::time::Instant::now() >= last_active + idle_timeout
}

#[allow(clippy::too_many_arguments)]
async fn run_sequential_round(
    config: &ObservatoryConfig,
    nodes: &[OutboundNodeId],
    outbound_router: &Arc<OutboundRouter>,
    selection: &Arc<OutboundSelectionOverlay>,
    destination_resolver: &Arc<dyn DnsResolver>,
    bootstrap_resolver: &Arc<dyn DnsResolver>,
    transport_dialer: &Arc<TransportDialer>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    for node in nodes {
        let result = tokio::select! {
            biased;
            () = wait_for_shutdown(shutdown) => return false,
            result = probe_node(
                config,
                *node,
                outbound_router,
                destination_resolver,
                bootstrap_resolver,
                transport_dialer,
            ) => result,
        };
        record_result(selection, *node, result);
        if wait_interval_or_shutdown(config.probe_interval, shutdown).await {
            return false;
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
async fn run_concurrent_round(
    config: &ObservatoryConfig,
    nodes: &[OutboundNodeId],
    outbound_router: &Arc<OutboundRouter>,
    selection: &Arc<OutboundSelectionOverlay>,
    destination_resolver: &Arc<dyn DnsResolver>,
    bootstrap_resolver: &Arc<dyn DnsResolver>,
    transport_dialer: &Arc<TransportDialer>,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    for chunk in nodes.chunks(MAX_CONCURRENT_HEALTH_PROBES) {
        let mut tasks = JoinSet::new();
        for node in chunk.iter().copied() {
            let config = config.clone();
            let outbound_router = Arc::clone(outbound_router);
            let destination_resolver = Arc::clone(destination_resolver);
            let bootstrap_resolver = Arc::clone(bootstrap_resolver);
            let transport_dialer = Arc::clone(transport_dialer);
            tasks.spawn(async move {
                let result = probe_node(
                    &config,
                    node,
                    &outbound_router,
                    &destination_resolver,
                    &bootstrap_resolver,
                    &transport_dialer,
                )
                .await;
                (node, result)
            });
        }

        while !tasks.is_empty() {
            tokio::select! {
                biased;
                () = wait_for_shutdown(shutdown) => {
                    tasks.abort_all();
                    return false;
                }
                joined = tasks.join_next() => {
                    if let Some(Ok((node, result))) = joined {
                        record_result(selection, node, result);
                    }
                }
            }
        }
    }
    true
}

async fn probe_node(
    config: &ObservatoryConfig,
    node: OutboundNodeId,
    outbound_router: &OutboundRouter,
    destination_resolver: &Arc<dyn DnsResolver>,
    bootstrap_resolver: &Arc<dyn DnsResolver>,
    transport_dialer: &TransportDialer,
) -> Result<Duration, StartupProbeError> {
    let outbound_tag = outbound_router
        .graph()
        .node(node)
        .and_then(|node| node.tag())
        .map(ToOwned::to_owned);
    run_outbound_url_probe(
        outbound_router,
        StartupProbeOptions {
            url: config.probe_url.clone(),
            timeout: OBSERVATORY_PROBE_TIMEOUT,
            outbound_tag,
        },
        destination_resolver.as_ref(),
        bootstrap_resolver.as_ref(),
        transport_dialer,
        ProbeStatusPolicy::AnyResponse,
    )
    .await
}

fn record_result(
    selection: &OutboundSelectionOverlay,
    node: OutboundNodeId,
    result: Result<Duration, StartupProbeError>,
) {
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    match result {
        Ok(delay) => selection.record_health_success(node, delay, now_unix_ms),
        Err(error) => {
            selection.record_health_failure(node, error.health_failure(), now_unix_ms);
        }
    }
}

async fn wait_interval_or_shutdown(
    interval: Duration,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        () = wait_for_shutdown(shutdown) => true,
        () = tokio::time::sleep(interval) => false,
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::OutboundHealthFailure;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    #[test]
    fn failure_classification_is_structured() {
        let error = StartupProbeError::HttpStatus {
            url: "http://<redacted-host>:80".to_owned(),
            status: 503,
        };

        assert_eq!(
            error.health_failure(),
            OutboundHealthFailure::HttpStatus(503)
        );
    }

    struct ScriptedRounds {
        stamps: Arc<Mutex<Vec<tokio::time::Instant>>>,
        kept: Arc<AtomicU64>,
        limit: usize,
        /// Sleep after a probe, the way one sequential node waits out the interval.
        gap: Option<Duration>,
    }

    impl ObservatoryRounds for ScriptedRounds {
        async fn probe_round(&mut self, shutdown: &mut watch::Receiver<bool>) -> bool {
            let stop = {
                let mut stamps = self.stamps.lock().expect("probe stamps");
                stamps.push(tokio::time::Instant::now());
                self.kept.store(stamps.len() as u64, Ordering::SeqCst);
                stamps.len() >= self.limit
            };
            if stop {
                return false;
            }
            if let Some(gap) = self.gap {
                if wait_interval_or_shutdown(gap, shutdown).await {
                    return false;
                }
            }
            true
        }
    }

    async fn drain() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    fn stamps_of(stamps: &Arc<Mutex<Vec<tokio::time::Instant>>>) -> Vec<tokio::time::Instant> {
        stamps.lock().expect("probe stamps").clone()
    }

    #[tokio::test(start_paused = true)]
    async fn eager_concurrent_schedule_probes_immediately_then_on_the_interval() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let mut rounds = ScriptedRounds {
            stamps: Arc::clone(&stamps),
            kept: Arc::new(AtomicU64::new(0)),
            limit: 3,
            gap: None,
        };

        // Awaiting the schedule parks on each interval. With the clock paused
        // the runtime advances time to the next sleep, which is the same cadence
        // as the historical eager loop: a round, then `probe_interval`, with no
        // touch required.
        run_eager_schedule(&mut rounds, Duration::from_secs(10), true, &mut shutdown).await;

        let recorded = stamps_of(&stamps);
        assert_eq!(recorded.len(), 3, "got {recorded:?}");
        assert_eq!(recorded[1] - recorded[0], Duration::from_secs(10));
        assert_eq!(recorded[2] - recorded[1], Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn eager_sequential_schedule_does_not_insert_a_gap_between_rounds() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let mut rounds = ScriptedRounds {
            stamps: Arc::clone(&stamps),
            kept: Arc::new(AtomicU64::new(0)),
            limit: 3,
            gap: None,
        };

        run_eager_schedule(&mut rounds, Duration::from_secs(10), false, &mut shutdown).await;

        let recorded = stamps_of(&stamps);
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[1] - recorded[0], Duration::ZERO);
        assert_eq!(recorded[2] - recorded[1], Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn eager_schedule_stops_on_shutdown_during_the_interval() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let mut rounds = ScriptedRounds {
            stamps: Arc::clone(&stamps),
            kept: Arc::new(AtomicU64::new(0)),
            limit: 10,
            gap: None,
        };
        let schedule = tokio::spawn(async move {
            run_eager_schedule(&mut rounds, Duration::from_secs(10), true, &mut shutdown).await;
        });

        drain().await;
        assert_eq!(stamps_of(&stamps).len(), 1);
        shutdown_tx.send(true).expect("shutdown");
        tokio::time::advance(Duration::from_secs(10)).await;
        schedule.await.expect("eager schedule");
        assert_eq!(stamps_of(&stamps).len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_schedule_waits_for_the_first_use_then_pauses_and_resumes() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let activity = ObservatoryActivity::new();
        let activity_for_task = Arc::clone(&activity);
        let mut_stamps = Arc::clone(&stamps);
        let mut_kept = Arc::clone(&kept);
        let schedule = tokio::spawn(async move {
            let mut rounds = ScriptedRounds {
                stamps: mut_stamps,
                kept: mut_kept,
                limit: 100,
                gap: None,
            };
            run_lazy_schedule(
                &mut rounds,
                &activity_for_task,
                Duration::from_secs(10),
                true,
                Duration::from_secs(30),
                &mut shutdown,
            )
            .await;
        });

        drain().await;
        tokio::time::advance(Duration::from_secs(60 * 60)).await;
        assert!(
            stamps_of(&stamps).is_empty(),
            "lazy mode does not probe before the first health-aware connection"
        );

        activity.touch();
        drain().await;
        assert_eq!(stamps_of(&stamps).len(), 1);

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(stamps_of(&stamps).len(), 2);
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(stamps_of(&stamps).len(), 3);
        // Idle deadline is 30s from the touch at t=0, so the gap after the
        // probe at t=20 pauses instead of probing at t=30.
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(stamps_of(&stamps).len(), 3);
        let kept_across_pause = kept.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(60 * 60)).await;
        assert_eq!(stamps_of(&stamps).len(), 3);
        assert_eq!(
            kept.load(Ordering::SeqCst),
            kept_across_pause,
            "pausing must not drop observations already gathered"
        );

        activity.touch();
        drain().await;
        assert_eq!(
            stamps_of(&stamps).len(),
            4,
            "the next connection resumes probing immediately"
        );

        shutdown_tx.send(true).expect("shutdown");
        schedule.await.expect("lazy schedule");
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_schedule_extends_the_idle_deadline_when_used_again() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let activity = ObservatoryActivity::new();
        let activity_for_task = Arc::clone(&activity);
        let mut_stamps = Arc::clone(&stamps);
        let schedule = tokio::spawn(async move {
            let mut rounds = ScriptedRounds {
                stamps: mut_stamps,
                kept: Arc::new(AtomicU64::new(0)),
                limit: 100,
                gap: None,
            };
            run_lazy_schedule(
                &mut rounds,
                &activity_for_task,
                Duration::from_secs(10),
                true,
                Duration::from_secs(30),
                &mut shutdown,
            )
            .await;
        });

        activity.touch();
        drain().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(stamps_of(&stamps).len(), 2);
        // A connection at t=10 moves the idle deadline from 30s to 40s.
        activity.touch();
        drain().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(stamps_of(&stamps).len(), 4);
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            stamps_of(&stamps).len(),
            4,
            "probing pauses at the extended deadline instead of the original one"
        );

        shutdown_tx.send(true).expect("shutdown");
        schedule.await.expect("lazy schedule");
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_sequential_schedule_pauses_after_the_idle_timeout() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let activity = ObservatoryActivity::new();
        let activity_for_task = Arc::clone(&activity);
        let mut_stamps = Arc::clone(&stamps);
        let schedule = tokio::spawn(async move {
            let mut rounds = ScriptedRounds {
                stamps: mut_stamps,
                kept: Arc::new(AtomicU64::new(0)),
                limit: 100,
                gap: Some(Duration::from_secs(10)),
            };
            run_lazy_schedule(
                &mut rounds,
                &activity_for_task,
                Duration::from_secs(10),
                false,
                Duration::from_secs(25),
                &mut shutdown,
            )
            .await;
        });

        activity.touch();
        drain().await;
        assert_eq!(stamps_of(&stamps).len(), 1);
        // Each step probes then sleeps 10s. Idle is 25s, so probes start at
        // 0s, 10s and 20s, and the step that returns at 30s pauses.
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        let recorded = stamps_of(&stamps);
        assert_eq!(recorded.len(), 3, "got {recorded:?}");
        assert_eq!(recorded[1] - recorded[0], Duration::from_secs(10));
        assert_eq!(recorded[2] - recorded[1], Duration::from_secs(10));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(stamps_of(&stamps).len(), 3);

        activity.touch();
        drain().await;
        assert_eq!(stamps_of(&stamps).len(), 4);

        shutdown_tx.send(true).expect("shutdown");
        schedule.await.expect("lazy sequential schedule");
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_schedule_stops_on_shutdown_before_the_first_use() {
        let stamps = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, mut shutdown) = watch::channel(false);
        let activity = ObservatoryActivity::new();
        let mut_stamps = Arc::clone(&stamps);
        let schedule = tokio::spawn(async move {
            let mut rounds = ScriptedRounds {
                stamps: mut_stamps,
                kept: Arc::new(AtomicU64::new(0)),
                limit: 10,
                gap: None,
            };
            run_lazy_schedule(
                &mut rounds,
                &activity,
                Duration::from_secs(10),
                true,
                Duration::from_secs(30),
                &mut shutdown,
            )
            .await;
        });

        drain().await;
        shutdown_tx.send(true).expect("shutdown");
        schedule.await.expect("lazy schedule");
        assert!(stamps_of(&stamps).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn pause_loses_to_a_touch_newer_than_the_observed_generation() {
        let activity = ObservatoryActivity::new();
        let mut notifications = activity.changed.subscribe();
        let mut seen = 0u64;
        let mut last_active = tokio::time::Instant::now();
        assert!(!activity.observe(&mut notifications, &mut seen, &mut last_active));

        activity.touch();
        assert!(activity.observe(&mut notifications, &mut seen, &mut last_active));
        assert_eq!(seen, 1);

        activity.touch();
        assert!(activity.retain_if_newer_than(seen));
        assert!(activity.observe(&mut notifications, &mut seen, &mut last_active));
        assert_eq!(seen, 2);
        assert_eq!(activity.generation(), 2);

        assert!(!activity.retain_if_newer_than(seen));
        assert!(!activity.observe(&mut notifications, &mut seen, &mut last_active));
    }
}
