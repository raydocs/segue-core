//! Process memory watchdog for hosts with a hard memory budget.
//!
//! iOS kills a Network Extension that exceeds its jetsam limit, and that limit
//! counts the physical footprint, not the resident set. A static per-profile
//! budget cannot know how close the process is to the line, so this module
//! samples the footprint about once a second and, when it crosses
//! `limit - margin` or the growth rate projects it will within the next
//! interval, asks the connection registry to shed idle connections and frees
//! the relay buffers the process keeps for reuse.
//!
//! The watchdog is off unless the host sets a limit in
//! `TunRuntimeOptions::memory_limit`. The sampler allocates nothing:
//! Darwin reads `task_info(TASK_VM_INFO)` into a stack buffer, Linux keeps
//! `/proc/self/statm` open and reads it into a stack buffer, and every other
//! target disables the watchdog.
//!
//! The thresholds and the growth-rate projection follow sing-box's OOM killer
//! (`service/oomkiller/timer.go`): trigger at `limit - margin`, resume at
//! `limit - 2 * margin`, and trigger early when the current rate would reach
//! the limit within `min(2 * interval, 1 s)`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use crate::connection::{unix_millis, ConnectionRegistry, ShedRequest};
use crate::RuntimeLogger;

/// The safety margin below the limit at which shedding starts.
pub(crate) const DEFAULT_MARGIN_BYTES: u64 = 5 * 1024 * 1024;
/// How often the footprint is sampled.
pub(crate) const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
/// How long a connection must have relayed nothing to count as idle.
pub(crate) const DEFAULT_IDLE_AFTER: Duration = Duration::from_secs(30);
/// The most connections one pass closes, so a single tick cannot tear down
/// every flow at once.
pub(crate) const DEFAULT_MAX_SHED_PER_TICK: usize = 16;
/// The longest lookahead of the growth-rate projection.
const MAX_RATE_LOOKAHEAD: Duration = Duration::from_secs(1);
/// How long a growth baseline is kept before it is taken again.
const BASELINE_MAX_AGE: Duration = Duration::from_secs(10);
/// A limit below this is raised to it: the default margin would leave no
/// room between the trigger and the resume point.
const MIN_LIMIT_BYTES: u64 = 16 * 1024 * 1024;

/// How the watchdog decides when to shed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryWatchOptions {
    /// The budget the platform kills the process for exceeding.
    pub(crate) limit_bytes: u64,
    /// How often the footprint is sampled.
    pub(crate) interval: Duration,
    /// How far below the limit shedding starts.
    pub(crate) margin_bytes: u64,
    /// How long a connection must have relayed nothing to count as idle.
    pub(crate) idle_after: Duration,
    /// The most connections one pass closes.
    pub(crate) max_shed_per_tick: usize,
}

impl MemoryWatchOptions {
    /// The defaults for a host-supplied limit.
    pub(crate) fn from_limit(limit_bytes: u64) -> Self {
        Self {
            limit_bytes: limit_bytes.max(MIN_LIMIT_BYTES),
            interval: DEFAULT_INTERVAL,
            margin_bytes: DEFAULT_MARGIN_BYTES,
            idle_after: DEFAULT_IDLE_AFTER,
            max_shed_per_tick: DEFAULT_MAX_SHED_PER_TICK,
        }
    }

    /// The footprint at which shedding starts.
    fn trigger_bytes(self) -> u64 {
        self.limit_bytes.saturating_sub(self.margin_bytes)
    }

    /// The footprint below which a triggered watchdog returns to normal.
    fn resume_bytes(self) -> u64 {
        self.limit_bytes
            .saturating_sub(self.margin_bytes.saturating_mul(2))
    }

    /// How far ahead the growth rate is projected.
    fn rate_lookahead(self) -> Duration {
        self.interval.saturating_mul(2).min(MAX_RATE_LOOKAHEAD)
    }
}

/// Whether the growth since `baseline_bytes` would reach `limit_bytes` within
/// `lookahead`.
///
/// This is sing-box's `headroom / rate < lookahead` in integer form, so it
/// cannot round a near miss into a trigger: the sample must be above the
/// baseline and below the limit, and the caller decides how old the baseline
/// must be before a burst reads as a trend.
pub(crate) fn growth_projects_limit(
    usage_bytes: u64,
    baseline_bytes: u64,
    elapsed: Duration,
    limit_bytes: u64,
    lookahead: Duration,
) -> bool {
    if usage_bytes <= baseline_bytes || usage_bytes >= limit_bytes {
        return false;
    }
    let elapsed_nanos = elapsed.as_nanos();
    let lookahead_nanos = lookahead.as_nanos();
    if elapsed_nanos == 0 || lookahead_nanos == 0 {
        return false;
    }
    let growth = u128::from(usage_bytes - baseline_bytes);
    let headroom = u128::from(limit_bytes - usage_bytes);
    // growth / elapsed > headroom / lookahead
    growth.saturating_mul(lookahead_nanos) > headroom.saturating_mul(elapsed_nanos)
}

/// Reads the process footprint in bytes without allocating.
pub(crate) struct FootprintSampler {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    statm: std::fs::File,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    page_size: u64,
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
impl FootprintSampler {
    pub(crate) fn open() -> Option<Self> {
        Some(Self {})
    }

    /// The physical footprint, which is what jetsam counts.
    pub(crate) fn sample(&mut self) -> Option<u64> {
        darwin::phys_footprint_bytes()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl FootprintSampler {
    pub(crate) fn open() -> Option<Self> {
        let statm = std::fs::File::open("/proc/self/statm").ok()?;
        // SAFETY: `sysconf` has no preconditions and only reads the system
        // configuration.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = u64::try_from(page_size).ok().filter(|size| *size > 0)?;
        Some(Self { statm, page_size })
    }

    /// The resident set size, the closest equivalent of the footprint on
    /// Linux and Android.
    pub(crate) fn sample(&mut self) -> Option<u64> {
        use std::os::unix::fs::FileExt;

        let mut buffer = [0u8; 64];
        let read = self.statm.read_at(&mut buffer, 0).ok()?;
        let text = std::str::from_utf8(&buffer[..read]).ok()?;
        // `size resident shared text lib data dt`, all in pages.
        let resident_pages = text.split_ascii_whitespace().nth(1)?.parse::<u64>().ok()?;
        Some(resident_pages.saturating_mul(self.page_size))
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "linux",
    target_os = "android"
)))]
impl FootprintSampler {
    /// No sampler exists, so the watchdog never starts on this target.
    pub(crate) fn open() -> Option<Self> {
        None
    }

    pub(crate) fn sample(&mut self) -> Option<u64> {
        None
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
mod darwin {
    use std::mem::MaybeUninit;

    /// `mach_port_t`.
    type MachPort = u32;
    /// `kern_return_t`.
    type KernReturn = i32;

    /// `TASK_VM_INFO` from `mach/task_info.h`.
    const TASK_VM_INFO: u32 = 22;

    /// The prefix of `struct task_vm_info` through `phys_footprint`, which is
    /// `TASK_VM_INFO_REV1_COUNT` words. The kernel fills only the fields the
    /// caller's count covers, so the later ledger fields are not needed.
    #[repr(C)]
    // Only `phys_footprint` is read; the other fields are the SDK layout that
    // puts it at its offset.
    #[allow(dead_code)]
    struct TaskVmInfo {
        virtual_size: u64,
        region_count: i32,
        page_size: i32,
        resident_size: u64,
        resident_size_peak: u64,
        device: u64,
        device_peak: u64,
        internal: u64,
        internal_peak: u64,
        external: u64,
        external_peak: u64,
        reusable: u64,
        reusable_peak: u64,
        purgeable_volatile_pmap: u64,
        purgeable_volatile_resident: u64,
        purgeable_volatile_virtual: u64,
        compressed: u64,
        compressed_peak: u64,
        compressed_lifetime: u64,
        phys_footprint: u64,
    }

    // The layout is the SDK's; a mismatch would read the wrong field.
    const _: () = assert!(std::mem::size_of::<TaskVmInfo>() == 152);

    extern "C" {
        static mach_task_self_: MachPort;
        fn task_info(
            target_task: MachPort,
            flavor: u32,
            task_info_out: *mut i32,
            task_info_out_cnt: *mut u32,
        ) -> KernReturn;
    }

    /// The words of `struct task_vm_info` through `phys_footprint`.
    const TASK_VM_INFO_REV1_COUNT: u32 =
        (std::mem::size_of::<TaskVmInfo>() / std::mem::size_of::<u32>()) as u32;

    pub(super) fn phys_footprint_bytes() -> Option<u64> {
        let mut info = MaybeUninit::<TaskVmInfo>::uninit();
        let mut count = TASK_VM_INFO_REV1_COUNT;
        // SAFETY: the buffer is a writable `task_vm_info` prefix and `count`
        // is its length in `natural_t` words, the layout `TASK_VM_INFO`
        // fills; the result is read only after the call reports success.
        let result = unsafe {
            task_info(
                mach_task_self_,
                TASK_VM_INFO,
                info.as_mut_ptr().cast::<i32>(),
                &mut count,
            )
        };
        // An older kernel that fills fewer words than asked leaves
        // `phys_footprint` unwritten: treat that as no sample.
        if result != 0 || count < TASK_VM_INFO_REV1_COUNT {
            return None;
        }
        // SAFETY: the call succeeded, so the kernel wrote the fields the
        // count covers, `phys_footprint` among them.
        let info = unsafe { info.assume_init() };
        Some(info.phys_footprint)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PressureState {
    Normal,
    Triggered,
}

/// What the watchdog remembers between samples.
#[derive(Debug)]
struct WatchState {
    state: PressureState,
    /// The footprint and time the growth rate is measured from.
    baseline: Option<(u64, Instant)>,
}

impl WatchState {
    fn new() -> Self {
        Self {
            state: PressureState::Normal,
            baseline: None,
        }
    }

    /// One sample: decide the pressure state, shed if it is triggered, and
    /// log what changed.
    fn tick(
        &mut self,
        options: MemoryWatchOptions,
        usage_bytes: u64,
        registry: &ConnectionRegistry,
        logger: &RuntimeLogger,
    ) {
        let now = Instant::now();
        let was_triggered = self.state == PressureState::Triggered;
        let mut reason = None;
        if usage_bytes >= options.trigger_bytes() {
            reason = Some("threshold");
        } else if let Some((baseline, at)) = self.baseline {
            let elapsed = now.saturating_duration_since(at);
            // A baseline younger than half an interval would read one burst
            // as a trend.
            if elapsed >= options.interval / 2
                && growth_projects_limit(
                    usage_bytes,
                    baseline,
                    elapsed,
                    options.limit_bytes,
                    options.rate_lookahead(),
                )
            {
                reason = Some("rate");
            }
        }

        if reason.is_some() {
            self.state = PressureState::Triggered;
        } else if was_triggered && usage_bytes < options.resume_bytes() {
            self.state = PressureState::Normal;
        }

        if self.state == PressureState::Triggered {
            // A fresh baseline once the pressure clears, so the next trend is
            // measured from where the process settled.
            self.baseline = None;
        } else if self
            .baseline
            .is_none_or(|(_, at)| now.saturating_duration_since(at) > BASELINE_MAX_AGE)
        {
            self.baseline = Some((usage_bytes, now));
        }

        if self.state != PressureState::Triggered {
            if was_triggered {
                logger.debug(|| {
                    format!(
                        "Debug memoryWatch recovered usage={} limit={}",
                        usage_bytes, options.limit_bytes
                    )
                });
            }
            return;
        }

        // Above the hard limit even a connection that is moving data is
        // closed; below it only the idle ones are.
        let include_active = usage_bytes >= options.limit_bytes;
        let outcome = registry.shed_idle(ShedRequest {
            now_unix_ms: unix_millis(),
            idle_after_ms: u64::try_from(options.idle_after.as_millis()).unwrap_or(u64::MAX),
            max_connections: options.max_shed_per_tick,
            include_active,
        });
        let released_buffers = crate::policy::release_idle_relay_buffers();

        if !was_triggered {
            let reason = reason.unwrap_or("threshold");
            logger.error(|| {
                format!(
                    "memoryWatch trigger reason={} usage={} limit={} margin={} shed={} remaining={} releasedBuffers={}",
                    reason,
                    usage_bytes,
                    options.limit_bytes,
                    options.margin_bytes,
                    outcome.closed,
                    outcome.remaining,
                    released_buffers
                )
            });
        } else if outcome.closed > 0 || released_buffers > 0 {
            logger.debug(|| {
                format!(
                    "Debug memoryWatch shed usage={} limit={} shed={} remaining={} releasedBuffers={}",
                    usage_bytes,
                    options.limit_bytes,
                    outcome.closed,
                    outcome.remaining,
                    released_buffers
                )
            });
        }
    }
}

/// Starts the watchdog when the host set a limit and the platform can be
/// sampled; returns `None` otherwise, so no task exists without a limit.
pub(crate) fn spawn_memory_watchdog(
    registry: Arc<ConnectionRegistry>,
    limit_bytes: Option<u64>,
    logger: RuntimeLogger,
    mut shutdown: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    let limit_bytes = limit_bytes.filter(|limit| *limit > 0)?;
    let options = MemoryWatchOptions::from_limit(limit_bytes);
    let mut sampler = FootprintSampler::open()?;

    Some(tokio::spawn(async move {
        let mut state = WatchState::new();
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                () = sleep(options.interval) => {
                    let Some(usage_bytes) = sampler.sample() else {
                        continue;
                    };
                    state.tick(options, usage_bytes, registry.as_ref(), &logger);
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use segue_routing::{Network, Target, TargetAddr};
    use tokio::sync::watch;

    use super::{
        growth_projects_limit, spawn_memory_watchdog, MemoryWatchOptions, PressureState,
        WatchState, DEFAULT_IDLE_AFTER, DEFAULT_INTERVAL, DEFAULT_MARGIN_BYTES,
        DEFAULT_MAX_SHED_PER_TICK, MIN_LIMIT_BYTES,
    };
    use crate::connection::ConnectionRegistry;
    use crate::RuntimeLogger;

    const MIB: u64 = 1024 * 1024;
    const LIMIT: u64 = 50 * MIB;

    fn target() -> Target {
        Target::new(
            TargetAddr::Domain("example.test".to_owned()),
            443,
            Network::Tcp,
        )
    }

    /// Options whose idle window is zero, so a connection that has not moved
    /// a byte since the previous pass counts as idle at once.
    fn immediate_options() -> MemoryWatchOptions {
        MemoryWatchOptions {
            idle_after: Duration::ZERO,
            ..MemoryWatchOptions::from_limit(LIMIT)
        }
    }

    fn tick(state: &mut WatchState, options: MemoryWatchOptions, usage: u64) {
        let registry = ConnectionRegistry::new();
        state.tick(options, usage, &registry, &RuntimeLogger::disabled());
    }

    #[test]
    fn a_sample_below_the_trigger_sheds_nothing() {
        let registry = Arc::new(ConnectionRegistry::new());
        let lease = registry.register(None, None, target());
        let close = lease.close_receiver();
        let mut state = WatchState::new();

        state.tick(
            immediate_options(),
            10 * MIB,
            registry.as_ref(),
            &RuntimeLogger::disabled(),
        );

        assert_eq!(state.state, PressureState::Normal);
        assert!(!close.has_changed().unwrap());
    }

    #[test]
    fn a_sample_at_the_trigger_sheds_idle_connections_oldest_first() {
        let registry = Arc::new(ConnectionRegistry::new());
        let oldest = registry.register(None, None, target());
        let newest = registry.register(None, None, target());
        let oldest_close = oldest.close_receiver();
        let newest_close = newest.close_receiver();
        let mut state = WatchState::new();
        let options = MemoryWatchOptions {
            max_shed_per_tick: 1,
            ..immediate_options()
        };

        // The first pass is below the trigger and sheds nothing; the second
        // closes the oldest connection only, because the pass is capped.
        state.tick(
            options,
            10 * MIB,
            registry.as_ref(),
            &RuntimeLogger::disabled(),
        );
        state.tick(
            options,
            options.trigger_bytes(),
            registry.as_ref(),
            &RuntimeLogger::disabled(),
        );

        assert_eq!(state.state, PressureState::Triggered);
        assert!(oldest_close.has_changed().unwrap());
        assert!(!newest_close.has_changed().unwrap());
    }

    #[test]
    fn a_triggered_watchdog_returns_to_normal_only_below_the_resume_point() {
        let options = immediate_options();
        let mut state = WatchState::new();

        tick(&mut state, options, options.trigger_bytes());
        assert_eq!(state.state, PressureState::Triggered);

        // Between resume and trigger it stays triggered, so a process that
        // hovers at the line keeps shedding.
        tick(&mut state, options, options.resume_bytes() + 1);
        assert_eq!(state.state, PressureState::Triggered);

        tick(&mut state, options, options.resume_bytes() - 1);
        assert_eq!(state.state, PressureState::Normal);
    }

    #[test]
    fn growth_projects_a_limit_reached_within_the_lookahead() {
        let lookahead = Duration::from_secs(1);
        let elapsed = Duration::from_secs(1);
        // 1 MiB in 1 s with 2 MiB of headroom reaches the limit in 2 s.
        assert!(!growth_projects_limit(
            48 * MIB,
            47 * MIB,
            elapsed,
            LIMIT,
            lookahead
        ));
        // 4 MiB in 1 s with 2 MiB of headroom reaches it in 0.5 s.
        assert!(growth_projects_limit(
            48 * MIB,
            44 * MIB,
            elapsed,
            LIMIT,
            lookahead
        ));
    }

    #[test]
    fn growth_projection_ignores_flat_shrinking_and_over_limit_samples() {
        let lookahead = Duration::from_secs(1);
        let elapsed = Duration::from_secs(1);
        assert!(!growth_projects_limit(
            40 * MIB,
            40 * MIB,
            elapsed,
            LIMIT,
            lookahead
        ));
        assert!(!growth_projects_limit(
            40 * MIB,
            45 * MIB,
            elapsed,
            LIMIT,
            lookahead
        ));
        assert!(!growth_projects_limit(
            51 * MIB,
            40 * MIB,
            elapsed,
            LIMIT,
            lookahead
        ));
        assert!(!growth_projects_limit(
            40 * MIB,
            30 * MIB,
            Duration::ZERO,
            LIMIT,
            lookahead
        ));
        assert!(!growth_projects_limit(
            40 * MIB,
            30 * MIB,
            elapsed,
            LIMIT,
            Duration::ZERO
        ));
    }

    #[test]
    fn growth_projection_is_exact_at_the_lookahead_boundary() {
        let lookahead = Duration::from_secs(1);
        // 1 MiB of headroom at 1 MiB/s is exactly the 1 s lookahead: not yet.
        assert!(!growth_projects_limit(
            49 * MIB,
            48 * MIB,
            lookahead,
            LIMIT,
            lookahead
        ));
        // A nanosecond faster is.
        let faster = lookahead - Duration::from_nanos(1);
        assert!(growth_projects_limit(
            49 * MIB,
            48 * MIB,
            faster,
            LIMIT,
            lookahead
        ));
    }

    #[test]
    fn options_derive_thresholds_from_the_limit() {
        let options = MemoryWatchOptions::from_limit(LIMIT);
        assert_eq!(options.limit_bytes, LIMIT);
        assert_eq!(options.margin_bytes, DEFAULT_MARGIN_BYTES);
        assert_eq!(options.trigger_bytes(), 45 * MIB);
        assert_eq!(options.resume_bytes(), 40 * MIB);
        assert_eq!(options.interval, DEFAULT_INTERVAL);
        assert_eq!(options.idle_after, DEFAULT_IDLE_AFTER);
        assert_eq!(options.max_shed_per_tick, DEFAULT_MAX_SHED_PER_TICK);
        assert_eq!(options.rate_lookahead(), Duration::from_secs(1));
    }

    #[test]
    fn a_tiny_limit_is_raised_to_the_floor_and_its_margin_fits() {
        let options = MemoryWatchOptions::from_limit(1);
        assert_eq!(options.limit_bytes, MIN_LIMIT_BYTES);
        assert_eq!(options.margin_bytes, DEFAULT_MARGIN_BYTES);
        let trigger = MIN_LIMIT_BYTES - DEFAULT_MARGIN_BYTES;
        assert_eq!(options.trigger_bytes(), trigger);
        let resume = MIN_LIMIT_BYTES - 2 * DEFAULT_MARGIN_BYTES;
        assert_eq!(options.resume_bytes(), resume);
    }

    #[test]
    fn no_task_is_spawned_without_a_limit() {
        let registry = Arc::new(ConnectionRegistry::new());
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let without = spawn_memory_watchdog(
            Arc::clone(&registry),
            None,
            RuntimeLogger::disabled(),
            shutdown_rx.clone(),
        );
        assert!(without.is_none());

        let zero = spawn_memory_watchdog(registry, Some(0), RuntimeLogger::disabled(), shutdown_rx);
        assert!(zero.is_none());
    }
}
