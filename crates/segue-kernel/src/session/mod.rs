//! Session-layer routes (SESSION_PROTOCOL v0.4) behind the [`Dialer`] seam.
//!
//! A rule whose outbound tag names a `segue` route does not dial the target
//! through the engine. Instead it opens a resumable session to a node's
//! relay: every carrier is an engine stream (Reality / Hy2) to the relay's
//! loopback address on the node. A dropped carrier is replaced with RESUME,
//! so the app connection survives the outer tunnel dying.
//!
//! Which node: the configured exits (e.g. `la`, `ny`) each name a carrier
//! outbound and a relay. The exit choice is `Auto` (first exit in config
//! order whose carrier is up or not recently failed) or one named exit; a
//! session stays on the exit it was opened on (its state lives in that
//! relay), so a change applies to new sessions. An AI-class session
//! (`exit_class` [`EXIT_AI`]) does not follow that failover: under Auto it
//! pins one exit and may move only to another exit in the same
//! [`Exit::group`]. A named choice is the pin. If that exit (and its group)
//! is down the dial is refused, not sent to a different egress.
//!
//! The app gets success only after the relay answered OPENED, which it does
//! only once the site connect worked: a refused session (exit_denied,
//! home_unavailable, target_denied, ...) is a dial error, so SOCKS answers
//! with an error and nothing is ever retried direct.
//!
//! Kill switch (KILLSWITCH.md L1): carrier outcomes drive one [`KillSwitch`]
//! per exit, and a new flow asks [`KillSwitch::verdict`]. While that exit is
//! reconnecting or in error, a strict (AI) route is refused at once, except
//! the pinned fresh OPEN after UNKNOWN_SESSION and a route whose retry window
//! has elapsed with nothing backing off (that attempt is what brings the exit
//! back). Overseas is [`crate::killswitch::Protection::Wait`]: the SOCKS/TUN
//! front end holds TCP; a dial that is asked anyway still tries the OPEN.
//! A user disconnect (L5) refuses every proxied flow and ends the live sessions.
//!
//! Channel health (SESSION_PROTOCOL §3, §5.1): each exit that has sessions
//! keeps a control stream to its relay. A `STALL` from the relay (it sees
//! a session's downstream unacknowledged, B1) moves that session to a new
//! carrier with RESUME; a control stream that answers nothing for
//! `dead_after` (a blackhole that drops packets without closing anything)
//! moves every session of that exit. Without this a download-only session
//! has nothing unacknowledged upstream and would never notice the stall.
//!
//! UDP is never carried to a `home` role route or outbound, whatever the
//! UDP settings say (KERNEL_SPEC §5.4): [`KernelDialer::dial_udp`] is the
//! one place every UDP flow passes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use segue_routing::TargetAddr;
use segue_session::client::{ClientSession, CloseReason, Health as SessionHealth, OpenParams};
use segue_session::codec::{code, CtrlHello, Kind, SessionId, Target, VERSION};
use segue_session::driver::{
    run_client_ctl, run_control, BoxCarrier, ClientCtl, Connector, ControlHint, ControlTiming,
};
use segue_session::pool::Pool;
use segue_session::quality::{Quality, QualityEvent, QualityTracker};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

mod choice;
pub use choice::AutoChoice;

use crate::dial::{Datagrams, DialError, Dialer};

mod stream;
use crate::killswitch::{
    protection_for_exit_class, Event, FlowPosture, HoldGuard, KillSwitch, Posture, Protection,
    Verdict, WAIT_CAP,
};
use crate::rules::Action;
pub use stream::SessionStream;

/// `exit_class` hints in OPEN (the relay classifies by itself).
pub const EXIT_OVERSEAS: u8 = 0;
pub const EXIT_AI: u8 = 1;

/// The process buffer budget (KERNEL_SPEC §6.3: one 8 MB pool of 4 KB
/// blocks for session receive/replay buffers, driver queues and the TUN
/// stack's TCP buffers).
pub const POOL_BYTES: usize = 8 << 20;

/// The pool every [`KernelDialer`] and the TUN stack
/// ([`crate::tun::TunStack::for_kernel`]) charge, so their buffers share
/// one bound instead of each having its own.
pub fn process_pool() -> Arc<Pool> {
    static POOL: std::sync::OnceLock<Arc<Pool>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| Pool::new(POOL_BYTES)).clone()
}
/// Longest wait for OPENED (covers the session's own OPEN retries).
const OPEN_WAIT: Duration = Duration::from_secs(20);
/// Fresh sessions after an UNKNOWN_SESSION answer to an OPEN retry.
const FRESH_OPENS: u32 = 2;
/// After this long since the last failed carrier connect, a strict route
/// may try again (the next carrier attempt decides the posture), and Auto
/// may pick that exit again.
pub const STRICT_RETRY_AFTER: Duration = Duration::from_secs(3);
const CARRIER_TIMEOUT: Duration = Duration::from_secs(10);

/// One node the sessions can anchor at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    /// `la`, `ny`, ... (what the UI shows and `set_exit` takes).
    pub name: String,
    /// Engine outbound that carries the session.
    pub carrier: String,
    /// Relay address as the carrier's server sees it.
    pub relay: SocketAddr,
    /// Node id sent as `anchor_node_id`.
    pub node_id: u64,
    /// Exits that share an egress identity. Empty means this exit is its
    /// own group ([`Exit::group`]): an AI flow pinned here never moves to
    /// another exit.
    pub egress_group: String,
}

impl Exit {
    /// The egress identity AI flows may move inside. Absent in config
    /// (empty here) means the exit's own name.
    pub fn group(&self) -> &str {
        if self.egress_group.is_empty() {
            &self.name
        } else {
            &self.egress_group
        }
    }
}

#[derive(Clone)]
pub struct SegueRoute {
    pub ticket: Vec<u8>,
    pub exit_class: u8,
}

impl std::fmt::Debug for SegueRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegueRoute")
            .field("ticket", &"<redacted>")
            .field("exit_class", &self.exit_class)
            .finish()
    }
}

/// The user's exit selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitChoice {
    Auto,
    Named(String),
}

impl ExitChoice {
    pub fn name(&self) -> &str {
        match self {
            Self::Auto => "auto",
            Self::Named(n) => n,
        }
    }
}

#[derive(Clone, Debug)]
struct Health {
    ks: KillSwitch,
    last_fail: Option<Instant>,
    /// The exit was judged down on session evidence (r9 F5) and no
    /// session has had a valid answer since. A carrier connect alone does
    /// not clear it: the outer tunnel can come up while session frames
    /// are black-holed. Cleared by [`SessionHealth::Up`] (OPENED, or data
    /// moving end to end).
    unproven: bool,
    /// Every live session on this exit, by reporter id: its own health,
    /// apart from its recovery budget (r10 N6).
    sessions: HashMap<u64, SessionMark>,
    /// Measured path quality (RTT, replay loss, stalls) for the exit
    /// choice (see [`crate::session::ExitChoice`] and [`Quality`]).
    quality: QualityTracker,
}

/// One session's latest health on its exit.
#[derive(Clone, Copy, Debug, Default)]
struct SessionMark {
    /// Its last report was a failure: it is redialling.
    failing: bool,
    /// When it last proved the path (OPENED, or data moving end to end).
    ok_at: Option<Instant>,
    /// When bytes from the relay last arrived on its carrier without
    /// moving data end to end ([`SessionHealth::Alive`], r11 R4): part of
    /// a large frame on a slow path, a keepalive ACK during an upload.
    alive_at: Option<Instant>,
}

/// A session's proof of the path counts this long for its exit (it is
/// refreshed every [`segue_session::client::HEALTH_REFRESH`] while data
/// moves): another session's failure within it does not take the exit
/// down (r10 N6).
pub const PROOF_FRESH: Duration = Duration::from_secs(5);

impl Health {
    fn new() -> Self {
        Self {
            ks: KillSwitch::new(),
            last_fail: None,
            unproven: false,
            sessions: HashMap::new(),
            quality: QualityTracker::new(),
        }
    }

    fn recently_failed(&self) -> bool {
        self.last_fail
            .is_some_and(|t| t.elapsed() < STRICT_RETRY_AFTER)
    }

    /// Live sessions whose last report was a failure.
    fn failing(&self) -> usize {
        self.sessions.values().filter(|m| m.failing).count()
    }

    /// A live session, not failing, proved the path or showed it alive
    /// (bytes arriving, r11 R4) within [`PROOF_FRESH`].
    fn proven(&self, now: Instant) -> bool {
        let fresh = |t: Option<Instant>| t.is_some_and(|t| now.duration_since(t) < PROOF_FRESH);
        self.sessions
            .values()
            .any(|m| !m.failing && (fresh(m.ok_at) || fresh(m.alive_at)))
    }
}

struct State {
    user_off: bool,
    /// The relay revoked this device (REVOKED on a control stream, r5
    /// N10): the code. Every session was reset locally and new ones are
    /// refused until the user connects again.
    revoked: Option<u8>,
    /// None: Auto; Some(i): exits[i].
    choice: Option<usize>,
    /// Bumped whenever the user changes `choice` (r11 R5): a fresh
    /// session pinned to the exit of an earlier attempt keeps the pin
    /// only while this is unchanged. The AI pin is updated in the same
    /// assignment: a named exit becomes the pin, Auto clears it so the
    /// next AI flow pins whatever Auto selects then.
    choice_gen: u64,
    /// Exit index the AI class is stuck to under Auto. `None` until the
    /// first AI flow, and after the user switches back to Auto.
    ai_pin: Option<usize>,
    health: Vec<Health>,
    /// The quality-based `Auto` choice and its hysteresis (see
    /// [`crate::session::choice`]).
    auto: AutoChoice,
}

impl State {
    /// Exit for a new session. A named choice is that exit. Under Auto,
    /// the quality-based choice ([`AutoChoice`]) decides among the exits
    /// that are up, preferring lower loss then lower RTT with hysteresis;
    /// when none is up, the old fallback order applies (first not
    /// recently failed, else the one that failed longest ago).
    fn pick(&mut self) -> usize {
        if let Some(i) = self.choice {
            return i;
        }
        let up: Vec<bool> = self
            .health
            .iter()
            .map(|h| h.ks.posture() == Posture::Connected)
            .collect();
        if up.iter().any(|&u| u) {
            let quality: Vec<Quality> = self.health.iter().map(|h| h.quality.snapshot()).collect();
            if let Some(i) = self.auto.observe(&up, &quality) {
                return i;
            }
        }
        if let Some(i) = self.health.iter().position(|h| !h.recently_failed()) {
            return i;
        }
        // All failed recently: the one that failed longest ago.
        (0..self.health.len())
            .min_by_key(|&i| self.health[i].last_fail)
            .unwrap_or(0)
    }

    /// Exit for an AI-class session.
    ///
    /// A named choice is that exit, even when it is down (the caller then
    /// refuses; this does not shop for another). Under Auto the first call
    /// pins [`Self::pick`]'s exit and later calls stay there. A down pin may
    /// move only to an exit whose [`Exit::group`] is the same and that is
    /// up. If none is, the pin is returned unchanged so the strict verdict
    /// refuses on it instead of opening on a different egress.
    fn pick_ai(&mut self, groups: &[String]) -> usize {
        if let Some(i) = self.choice {
            self.ai_pin = Some(i);
            return i;
        }
        if let Some(i) = self.ai_pin {
            if self.ai_up(i) {
                return i;
            }
            let group = groups.get(i).map(String::as_str).unwrap_or("");
            let moved = (0..self.health.len()).find(|&j| {
                j != i && groups.get(j).map(String::as_str) == Some(group) && self.ai_up(j)
            });
            if let Some(j) = moved {
                self.ai_pin = Some(j);
                return j;
            }
            return i;
        }
        let i = self.pick();
        self.ai_pin = Some(i);
        i
    }

    /// Connected, and not waiting on a session answer that never came.
    fn ai_up(&self, i: usize) -> bool {
        let h = &self.health[i];
        h.ks.posture() == Posture::Connected && !h.unproven
    }

    fn posture(&mut self) -> Posture {
        if self.user_off {
            return Posture::Disconnected;
        }
        if self.revoked.is_some() {
            return Posture::Error;
        }
        let i = self.pick();
        match self.health.get(i) {
            Some(h) => h.ks.posture(),
            None => Posture::Connecting,
        }
    }
}

/// One exit's control stream and the sessions it can hint.
#[derive(Default)]
struct Channel {
    /// Bumped when the channel is judged dead: every session reattaches.
    epoch: Arc<watch::Sender<u64>>,
    /// Live sessions on this exit, for `STALL` hints.
    sessions: Arc<Mutex<HashMap<SessionId, mpsc::UnboundedSender<u32>>>>,
    task: Mutex<Option<JoinHandle<()>>>,
    /// The relay refused this exit's CTRL_HELLO for good (r11 R3): the
    /// code. The control stream is not restarted until the user connects
    /// again (new credentials); sessions on the exit run without hints.
    rejected: Arc<Mutex<Option<u8>>>,
}

impl Channel {
    fn stop(&self) {
        if let Some(h) = self.task.lock().unwrap().take() {
            h.abort();
        }
    }
}

/// One exit's measured path quality, for the control API.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitQuality {
    pub name: String,
    pub quality: Quality,
}

/// Snapshot for the control API.
#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub posture: Posture,
    pub choice: ExitChoice,
    /// The exit new sessions use now (None: no exits configured).
    pub current_exit: Option<String>,
    pub exits: Vec<String>,
    /// Per exit, same order as `exits`: measured RTT, loss and stalls.
    pub quality: Vec<ExitQuality>,
    /// Set when the relay revoked this device: its code.
    pub revoked: Option<u8>,
    /// Exits whose relay refused the control stream for good, with the
    /// `REJECT` code (r11 R3: `version` after a mixed-version deploy,
    /// or refused credentials).
    pub control_refused: Vec<(String, u8)>,
}

/// Engine outbounds plus session routes.
pub struct KernelDialer {
    engine: Arc<dyn Dialer>,
    exits: Vec<Exit>,
    routes: BTreeMap<String, SegueRoute>,
    /// Tags with the `home` role: never carry UDP.
    home: BTreeSet<String>,
    pool: Arc<Pool>,
    state: Arc<Mutex<State>>,
    /// true while the user has Segue off; live sessions watch it.
    off: watch::Sender<bool>,
    /// Some(code) once the relay revoked this device; live sessions reset
    /// with that code.
    revoked: Arc<watch::Sender<Option<u8>>>,
    /// Per exit, same order as `exits`.
    channels: Vec<Channel>,
    control: ControlTiming,
    /// Session timing and limits (validated: [`Self::with_session_config`]).
    session_cfg: segue_session::Config,
    /// TCP flows currently held in [`crate::killswitch::Verdict::Wait`].
    holds: Arc<AtomicUsize>,
}

impl Drop for KernelDialer {
    fn drop(&mut self) {
        for c in &self.channels {
            c.stop();
        }
    }
}

impl KernelDialer {
    pub fn new(
        engine: Arc<dyn Dialer>,
        exits: Vec<Exit>,
        routes: BTreeMap<String, SegueRoute>,
        home: BTreeSet<String>,
    ) -> Self {
        let exits_len = exits.len();
        let health = (0..exits.len()).map(|_| Health::new()).collect();
        Self {
            engine,
            exits,
            routes,
            home,
            pool: process_pool(),
            state: Arc::new(Mutex::new(State {
                user_off: false,
                revoked: None,
                choice: None,
                choice_gen: 0,
                ai_pin: None,
                health,
                auto: AutoChoice::default(),
            })),
            off: watch::channel(false).0,
            revoked: Arc::new(watch::channel(None).0),
            channels: (0..exits_len).map(|_| Channel::default()).collect(),
            control: ControlTiming::default(),
            session_cfg: segue_session::Config::default(),
            holds: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Use `cfg` for new sessions. Refused when the client timing is one
    /// the protocol cannot honour (r10 N3: a `t_stall` below
    /// [`segue_session::MIN_CLIENT_STALL`] would be floored by the relay
    /// and the client would take live carriers for stalled ones).
    pub fn with_session_config(mut self, cfg: segue_session::Config) -> Result<Self, DialError> {
        cfg.timing
            .validate_client()
            .map_err(|e| DialError(format!("session config: {e}")))?;
        self.session_cfg = cfg;
        Ok(self)
    }

    /// Charge sessions to `pool` instead of [`process_pool`].
    pub fn with_pool(mut self, pool: Arc<Pool>) -> Self {
        self.pool = pool;
        self
    }

    pub fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }

    /// Control stream PING period and dead-channel threshold.
    pub fn with_control_timing(mut self, t: ControlTiming) -> Self {
        self.control = t;
        self
    }

    /// Start exit `i`'s control stream unless it is running.
    fn ensure_channel(&self, i: usize, ticket: &[u8]) {
        let ch = &self.channels[i];
        let mut task = ch.task.lock().unwrap();
        if task.as_ref().is_some_and(|h| !h.is_finished()) || ch.rejected.lock().unwrap().is_some()
        {
            return;
        }
        let hello = CtrlHello {
            version: VERSION,
            ticket: ticket.to_vec(),
            held_anchors: vec![self.exits[i].node_id],
        };
        let connect = self.connector(i);
        let timing = self.control.clone();
        let epoch = ch.epoch.clone();
        let sessions = ch.sessions.clone();
        let sessions_idle = ch.sessions.clone();
        let name = self.exits[i].name.clone();
        let state = self.state.clone();
        let revoked = self.revoked.clone();
        let rejected = ch.rejected.clone();
        *task = Some(tokio::spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let hints = async move {
                while let Some(h) = rx.recv().await {
                    match h {
                        ControlHint::Stall {
                            session_id,
                            attach_gen,
                        } => {
                            if let Some(s) = sessions.lock().unwrap().get(&session_id) {
                                let _ = s.send(attach_gen);
                            }
                        }
                        ControlHint::Dead => {
                            eprintln!("segue-kernel: exit {name}: channel dead, resuming sessions");
                            epoch.send_modify(|e| *e += 1);
                        }
                        // A control PING/PONG round trip: the exit's RTT
                        // sample for the quality-based exit choice.
                        ControlHint::Rtt(rtt) => {
                            state.lock().unwrap().health[i].quality.on_rtt(rtt);
                        }
                        // The relay resets the sessions too, but its RSTs
                        // ride the data carriers, which may be dead while
                        // this stream works: reset every session locally and
                        // refuse new ones (r5 N10).
                        ControlHint::Revoked(c) => {
                            eprintln!("segue-kernel: exit {name}: device revoked (code {c})");
                            state.lock().unwrap().revoked = Some(c);
                            revoked.send_replace(Some(c));
                        }
                        // The relay refused the control stream for good
                        // (r11 R3): no Dead, no reconnect loop. A refused
                        // device is a revocation like the one above.
                        ControlHint::Rejected(c) => {
                            eprintln!(
                                "segue-kernel: exit {name}: control stream refused (code {c}), not retried"
                            );
                            *rejected.lock().unwrap() = Some(c);
                            if c == code::REVOKED {
                                state.lock().unwrap().revoked = Some(c);
                                revoked.send_replace(Some(c));
                            }
                        }
                    }
                }
            };
            let idle_check = timing.ping_every;
            let idle = {
                let sessions = sessions_idle;
                async move {
                    loop {
                        tokio::time::sleep(idle_check).await;
                        if sessions.lock().unwrap().is_empty() {
                            return;
                        }
                    }
                }
            };
            tokio::select! {
                _ = async { tokio::join!(run_control(connect, hello, timing, tx), hints) } => {}
                // No sessions on this exit: no control stream (no idle wake-ups).
                _ = idle => {}
            }
        }));
    }

    pub fn posture(&self) -> Posture {
        self.state.lock().unwrap().posture()
    }

    pub fn status(&self) -> Status {
        let mut st = self.state.lock().unwrap();
        let choice = match st.choice {
            None => ExitChoice::Auto,
            Some(i) => ExitChoice::Named(self.exits[i].name.clone()),
        };
        let posture = st.posture();
        let current = (!self.exits.is_empty()).then(|| st.pick());
        let quality: Vec<ExitQuality> = self
            .exits
            .iter()
            .zip(&st.health)
            .map(|(e, h)| ExitQuality {
                name: e.name.clone(),
                quality: h.quality.snapshot(),
            })
            .collect();
        Status {
            posture,
            choice,
            current_exit: current.map(|i| self.exits[i].name.clone()),
            exits: self.exits.iter().map(|e| e.name.clone()).collect(),
            quality,
            revoked: st.revoked,
            control_refused: self
                .exits
                .iter()
                .zip(&self.channels)
                .filter_map(|(e, c)| Some((e.name.clone(), (*c.rejected.lock().unwrap())?)))
                .collect(),
        }
    }

    /// Select the exit for new sessions (`auto` or a configured name).
    pub fn set_exit(&self, name: &str) -> Result<(), DialError> {
        let choice = if name == "auto" {
            None
        } else {
            Some(
                self.exits
                    .iter()
                    .position(|e| e.name == name)
                    .ok_or_else(|| DialError(format!("unknown exit {name:?}")))?,
            )
        };
        let mut st = self.state.lock().unwrap();
        if st.choice != choice {
            st.choice = choice;
            st.choice_gen += 1;
            // The user changed exit. Named: AI follows that exit now.
            // Auto: drop the pin; the next AI flow pins the exit Auto
            // is on at that moment, and sticks to its egress group.
            st.ai_pin = choice;
        }
        Ok(())
    }

    /// Lab / tests: put `name` in `group` (AI may move to other exits in it).
    #[cfg(test)]
    pub(crate) fn set_egress_group(&mut self, name: &str, group: &str) -> Result<(), DialError> {
        let exit = self
            .exits
            .iter_mut()
            .find(|e| e.name == name)
            .ok_or_else(|| DialError(format!("unknown exit {name:?}")))?;
        exit.egress_group = group.to_string();
        Ok(())
    }

    /// User turned Segue on (L5).
    pub fn connect(&self) {
        let mut st = self.state.lock().unwrap();
        if !st.user_off {
            // Already on: keep what the kill switch knows.
            return;
        }
        st.user_off = false;
        // A new start (fresh credentials): the relay judges them again.
        st.revoked = None;
        self.revoked.send_replace(None);
        for c in &self.channels {
            *c.rejected.lock().unwrap() = None;
        }
        for h in &mut st.health {
            h.ks.on_event(Event::UserConnect);
            h.last_fail = None;
            h.unproven = false;
        }
        self.off.send_replace(false);
    }

    /// User turned Segue off (L5): new proxied flows are refused and live
    /// sessions end.
    pub fn disconnect(&self) {
        let mut st = self.state.lock().unwrap();
        st.user_off = true;
        for h in &mut st.health {
            h.ks.on_event(Event::UserDisconnect);
        }
        self.off.send_replace(true);
        for c in &self.channels {
            c.stop();
        }
    }

    /// Try a carrier to the current exit now, so the posture reflects
    /// reality before any flow arrives (after connect / set_exit). Under
    /// Auto, a failed exit moves the pick on, so each exit is tried once.
    pub async fn probe(&self) -> Result<(), DialError> {
        let mut last = DialError("no exits configured".into());
        for _ in 0..self.exits.len() {
            let (i, auto) = {
                let mut st = self.state.lock().unwrap();
                if st.user_off {
                    return Err(DialError("disconnected".into()));
                }
                (st.pick(), st.choice.is_none())
            };
            match (self.connector(i))().await {
                Ok(_) => return Ok(()),
                Err(e) => last = DialError(format!("probe {}: {e}", self.exits[i].name)),
            }
            if !auto {
                break;
            }
        }
        if self.exits.is_empty() {
            return Ok(());
        }
        Err(last)
    }

    fn connector(&self, i: usize) -> Connector {
        let engine = self.engine.clone();
        let state = self.state.clone();
        let carrier = self.exits[i].carrier.clone();
        let relay = self.exits[i].relay;
        Arc::new(move || {
            let engine = engine.clone();
            let state = state.clone();
            let carrier = carrier.clone();
            Box::pin(async move {
                let res = tokio::time::timeout(
                    CARRIER_TIMEOUT,
                    engine.dial(Some(&carrier), &TargetAddr::Ip(relay.ip()), relay.port()),
                )
                .await;
                let mut st = state.lock().unwrap();
                let h = &mut st.health[i];
                match res {
                    Ok(Ok(s)) => {
                        // While sessions are failing, the carrier being up
                        // proves nothing (r9 F5): wait for a valid answer.
                        if !h.unproven {
                            h.ks.on_event(Event::ChannelUp);
                            h.last_fail = None;
                        }
                        Ok(Box::new(s) as BoxCarrier)
                    }
                    Ok(Err(e)) => {
                        mark_failed(h);
                        eprintln!("segue-kernel: carrier {carrier} failed: {e}");
                        Err(std::io::Error::other(e.0))
                    }
                    Err(_) => {
                        mark_failed(h);
                        eprintln!("segue-kernel: carrier {carrier} timed out");
                        Err(std::io::ErrorKind::TimedOut.into())
                    }
                }
            })
        })
    }

    /// Open a session. An OPEN retry the relay does not know (the first
    /// carrier stalled past T_attach, so its OPEN never arrived) is answered
    /// UNKNOWN_SESSION by design (A2): nothing was confirmed and no app byte
    /// was sent (SOCKS success waits for OPENED), so a fresh session is safe.
    async fn open(
        &self,
        r: &SegueRoute,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<crate::dial::Stream, DialError> {
        let start = Instant::now();
        let mut tries = 0;
        let mut pin = None;
        loop {
            let mut exit = None;
            match self.open_once(r, addr, port, pin, &mut exit).await {
                Err((e, Some(c)))
                    if c == code::UNKNOWN_SESSION
                        && tries < FRESH_OPENS
                        && start.elapsed() < OPEN_WAIT =>
                {
                    tries += 1;
                    eprintln!("segue-kernel: {e}; opening a fresh session");
                    // UNKNOWN_SESSION is sent before the ticket is checked
                    // (A2), so it proves only that this exit's relay is
                    // reachable (r11 R5): not that the ticket is valid,
                    // the target reachable or the exit's failing sessions
                    // recovered. It changes nothing in the exit's health;
                    // it only lets the fresh session try the same exit
                    // once, even if the slow OPEN's failures took the exit
                    // down (r10 failover: re-picking would move it, under
                    // Auto, to an exit that has not failed lately only
                    // because nothing tried it). Its OPENED, or data
                    // moving, is what restores the exit. The pin holds only
                    // while the user's exit choice is unchanged.
                    pin = exit;
                }
                res => return res.map_err(|(e, _)| e),
            }
        }
    }

    async fn open_once(
        &self,
        r: &SegueRoute,
        addr: &TargetAddr,
        port: u16,
        pin: Option<(usize, u64)>,
        exit: &mut Option<(usize, u64)>,
    ) -> Result<crate::dial::Stream, (DialError, Option<u8>)> {
        let groups: Vec<String> = self.exits.iter().map(|e| e.group().to_string()).collect();
        let i = {
            let mut st = self.state.lock().unwrap();
            if st.user_off {
                return Err((DialError("refused: disconnected".into()), None));
            }
            if let Some(c) = st.revoked {
                return Err((
                    DialError(format!("refused: device revoked (code {c})")),
                    Some(c),
                ));
            }
            if groups.is_empty() {
                return Err((DialError("refused: no exits configured".into()), None));
            }
            // A pin from an UNKNOWN_SESSION answer (see `open`) is void
            // once the user picked another exit.
            let pinned = pin.filter(|&(_, g)| g == st.choice_gen).map(|(i, _)| i);
            let i = if r.exit_class == EXIT_AI {
                if let Some(i) = pinned {
                    // The fresh OPEN stays on the exit that answered.
                    // Re-picking would move an AI flow to another egress.
                    st.ai_pin = Some(i);
                    i
                } else {
                    st.pick_ai(&groups)
                }
            } else {
                pinned.unwrap_or_else(|| st.pick())
            };
            *exit = Some((i, st.choice_gen));
            let h = &st.health[i];
            // Posture decides. Protection comes from the route's exit class,
            // not from a second AI check. A strict Refuse is immediate while
            // the exit's carrier connects are failing or its sessions are
            // backing off (r9 F5). Two attempts are still made, because they
            // are what restores the exit: the pinned fresh OPEN after
            // UNKNOWN_SESSION, and a route whose retry window has elapsed
            // with nothing backing off. Wait is not an error here — the
            // front end holds TCP; if a dial is asked anyway, the OPEN is tried.
            let protection = protection_for_exit_class(r.exit_class);
            let verdict = h.ks.verdict(&Action::Proxy(String::new()), protection);
            match verdict {
                Verdict::Release => {
                    return Err((DialError("refused: disconnected".into()), None));
                }
                Verdict::Refuse
                    if protection == Protection::Strict
                        && pinned.is_none()
                        && (h.recently_failed() || h.failing() > 0) =>
                {
                    return Err((
                        DialError("refused: tunnel reconnecting (strict route)".into()),
                        None,
                    ));
                }
                _ => {}
            }
            i
        };
        let target = match addr {
            TargetAddr::Ip(ip) => Target::Ip(SocketAddr::new(*ip, port)),
            TargetAddr::Domain(d) => Target::Domain(d.clone(), port),
        };
        let params = OpenParams {
            ticket: r.ticket.clone(),
            kind: Kind::Tcp,
            target,
            exit_class: r.exit_class,
            anchor_node_id: self.exits[i].node_id,
            instance_hint: 0,
        };
        let s = ClientSession::new(self.session_cfg.clone(), &self.pool, params, Instant::now())
            .ok_or_else(|| (DialError("refused: session memory exhausted".into()), None))?;
        // Pool-charged and released when drained (tokio's duplex keeps a
        // burst's capacity for the life of the stream); its reserved blocks
        // are taken here, so a spent pool refuses instead of overcommitting.
        let (app, far) = segue_session::pipe::pipe(&self.pool, 64 << 10)
            .ok_or_else(|| (DialError("refused: session memory exhausted".into()), None))?;
        let ch = &self.channels[i];
        let sid = s.session_id();
        let (stall_tx, stall_rx) = mpsc::unbounded_channel();
        ch.sessions.lock().unwrap().insert(sid, stall_tx);
        let sessions = ch.sessions.clone();
        let (open_tx, open_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, mut closed_rx) = tokio::sync::oneshot::channel();
        let ctl = ClientCtl {
            reattach: Some(ch.epoch.subscribe()),
            stall: Some(stall_rx),
            closed: Some(closed_tx),
            opened: Some(open_tx),
            cancel: Some(self.revoked.subscribe()),
            health: Some({
                let rep = HealthReporter::new(self.state.clone(), i);
                Arc::new(move |r| rep.report(r))
            }),
            quality: Some({
                let state = self.state.clone();
                Arc::new(move |e: QualityEvent| {
                    state.lock().unwrap().health[i].quality.on_event(e);
                })
            }),
        };
        let run = run_client_ctl(s, far, self.connector(i), ctl);
        let mut off = self.off.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                _ = run => {}
                // Dropping the session drops its carriers and the app pipe.
                _ = off.wait_for(|off| *off) => {}
            }
            sessions.lock().unwrap().remove(&sid);
        });
        tokio::select! {
            // OPENED first: a session reset right after it still counts as
            // opened (its stream then ends with that reset).
            biased;
            o = open_rx => match o {
                Ok(()) => {
                    // Only a working route gets (and keeps) a control stream.
                    self.ensure_channel(i, &r.ticket);
                    Ok(Box::new(SessionStream::new(app, closed_rx)))
                }
                Err(_) => Err(self.refused(i, (&mut closed_rx).await.ok())),
            },
            c = &mut closed_rx => Err(self.refused(i, c.ok())),
            _ = tokio::time::sleep(OPEN_WAIT) => Err((DialError("session open timed out".into()), None)),
        }
    }
}

impl KernelDialer {
    /// A session on exit `i` ended before OPENED with `reason`. A refusal
    /// that says the exit cannot serve this device's new sessions is a
    /// health failure (r11 R5), aggregated like a session's `Failed`;
    /// others (the target, the site, capacity) are not, and none of them
    /// proves the exit.
    fn refused(&self, i: usize, reason: Option<CloseReason>) -> (DialError, Option<u8>) {
        let (e, c) = closed_err(reason);
        if c.is_some_and(refusal_fails_exit) {
            let mut st = self.state.lock().unwrap();
            let h = &mut st.health[i];
            if !h.proven(Instant::now()) {
                h.unproven = true;
                mark_failed(h);
            }
        }
        (e, c)
    }
}

/// A REJECT / RST of an OPEN that says the exit cannot open sessions for
/// this device now: refused credentials, an exit class the ticket does
/// not grant, another wire version, or the Home exit being unavailable.
/// `TARGET_DENIED`, site errors and capacity are about the one flow.
fn refusal_fails_exit(c: u8) -> bool {
    matches!(
        c,
        code::VERSION
            | code::AUTH
            | code::EXPIRED
            | code::REVOKED
            | code::EXIT_DENIED
            | code::HOME_UNAVAILABLE
    )
}

/// A session's health report (r9 F5) into its exit's health (r10 N6).
/// The exit health aggregates its sessions, apart from their recovery
/// budgets:
///
/// - `Up` (a valid protocol answer) proves the exit: `Connected`.
/// - `Alive` (bytes arriving without data moving end to end: a large
///   frame on a slow path, keepalive ACKs during an upload; r11 R4) is
///   path liveness: it counts like proof below, restores nothing. It
///   counts from when those bytes arrived: a frame that is here and waits
///   for local memory (a full shared pool) renews nothing (r12 #1).
/// - `Failed` / `GaveUp` takes it down (`Reconnecting`, or `Error` if it
///   never worked) only when no other live, non-failing session proved
///   the path or showed it alive within [`PROOF_FRESH`]: one bad session
///   beside a working one blocks nothing. Sessions that were idle for
///   the whole window give no evidence either way, so a failure then
///   does take the exit down (until a valid answer).
/// - A failed carrier connect (the exit's probe) takes it down at once.
///
/// While down, new strict (AI) flows are refused at once while sessions
/// back off; only a valid protocol answer brings the exit back.
fn session_health(h: &mut Health, id: u64, r: SessionHealth, now: Instant) {
    match r {
        SessionHealth::Up => {
            let m = h.sessions.entry(id).or_default();
            m.failing = false;
            m.ok_at = Some(now);
            h.unproven = false;
            h.last_fail = None;
            h.ks.on_event(Event::ChannelUp);
        }
        // Liveness keeps the session's path counted for the exit (another
        // session's failure does not take it down), but restores nothing:
        // bytes arriving are not a valid protocol answer. It does not clear
        // the session's own failing mark either (a failing session's next
        // carrier has to bring proof).
        // Stamped with when the bytes arrived, not with the report (r12
        // #1): a frame waiting for local memory adds nothing.
        SessionHealth::Alive(at) => {
            let m = h.sessions.entry(id).or_default();
            m.alive_at = m.alive_at.max(Some(at.min(now)));
        }
        SessionHealth::Failed | SessionHealth::GaveUp => {
            if r == SessionHealth::GaveUp {
                // It is ending: nothing of it counts any more.
                h.sessions.remove(&id);
            } else {
                let m = h.sessions.entry(id).or_default();
                m.failing = true;
                m.ok_at = None;
                m.alive_at = None;
            }
            if !h.proven(now) {
                h.unproven = true;
                mark_failed(h);
            }
        }
    }
}

/// One session's [`ClientCtl::health`] hook: reports into exit `i`, and
/// when the session ends (the driver drops the hook) it leaves the exit's
/// health.
struct HealthReporter {
    state: Arc<Mutex<State>>,
    i: usize,
    id: u64,
}

static NEXT_REPORTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl HealthReporter {
    fn new(state: Arc<Mutex<State>>, i: usize) -> Self {
        let id = NEXT_REPORTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state.lock().unwrap().health[i]
            .sessions
            .insert(id, SessionMark::default());
        Self { state, i, id }
    }

    fn report(&self, r: SessionHealth) {
        let mut st = self.state.lock().unwrap();
        session_health(&mut st.health[self.i], self.id, r, Instant::now());
    }
}

impl Drop for HealthReporter {
    fn drop(&mut self) {
        if let Ok(mut st) = self.state.lock() {
            st.health[self.i].sessions.remove(&self.id);
        }
    }
}

fn mark_failed(h: &mut Health) {
    match h.ks.posture() {
        Posture::Connected => {
            h.ks.on_event(Event::ChannelLost);
        }
        // Never had a carrier on this exit: no channel can be established.
        Posture::Connecting => {
            h.ks.on_event(Event::Failed);
        }
        _ => {}
    }
    h.last_fail = Some(Instant::now());
}

fn closed_err(r: Option<CloseReason>) -> (DialError, Option<u8>) {
    let c = match r {
        Some(CloseReason::Refused(c) | CloseReason::Reset(c)) => Some(c),
        _ => None,
    };
    (DialError(closed_text(r)), c)
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
    ) -> Result<crate::dial::Stream, DialError> {
        if let Some(r) = tag.and_then(|t| self.routes.get(t)) {
            return self.open(r, addr, port).await;
        }
        if tag.is_some() && *self.off.borrow() {
            return Err(DialError("refused: disconnected".into()));
        }
        self.engine.dial(tag, addr, port).await
    }

    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        if let Some(t) = tag {
            if self.home.contains(t) {
                // Fixed property of the Home exit (§5.4), not a setting.
                return Err(DialError("udp refused: home exit never carries UDP".into()));
            }
            if self.routes.contains_key(t) {
                return Err(DialError("udp refused on session routes".into()));
            }
            if *self.off.borrow() {
                return Err(DialError("refused: disconnected".into()));
            }
        }
        self.engine.dial_udp(tag, addr, port).await
    }
}

impl FlowPosture for KernelDialer {
    fn posture(&self) -> Posture {
        // The trait method would recurse; this is the aggregate posture.
        KernelDialer::posture(self)
    }

    fn protection(&self, tag: &str) -> Option<Protection> {
        self.routes
            .get(tag)
            .map(|r| protection_for_exit_class(r.exit_class))
    }

    fn try_hold(&self) -> Option<HoldGuard> {
        HoldGuard::try_acquire(&self.holds, WAIT_CAP)
    }
}

#[cfg(test)]
mod tests;
