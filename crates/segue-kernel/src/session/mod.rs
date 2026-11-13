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
//! relay), so a change applies to new sessions.
//!
//! The app gets success only after the relay answered OPENED, which it does
//! only once the site connect worked: a refused session (exit_denied,
//! home_unavailable, target_denied, ...) is a dial error, so SOCKS answers
//! with an error and nothing is ever retried direct.
//!
//! Kill switch (KILLSWITCH.md L1): carrier outcomes drive one [`KillSwitch`]
//! per exit. While a carrier cannot be established (`Reconnecting` /
//! `Error`), new flows on strict (AI) routes are refused at once; overseas
//! flows are tried (the session retries OPEN for a bounded time) and refused
//! if that fails. A user disconnect (L5) refuses every proxied flow and ends
//! the live sessions.
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
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::dial::{Datagrams, DialError, Dialer};

mod stream;
use crate::killswitch::{Event, KillSwitch, Posture};
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
}

/// One session's latest health on its exit.
#[derive(Clone, Copy, Debug, Default)]
struct SessionMark {
    /// Its last report was a failure: it is redialling.
    failing: bool,
    /// When it last proved the path (OPENED, or data moving end to end).
    ok_at: Option<Instant>,
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

    /// A live session, not failing, proved the path within
    /// [`PROOF_FRESH`].
    fn proven(&self, now: Instant) -> bool {
        self.sessions
            .values()
            .any(|m| !m.failing && m.ok_at.is_some_and(|t| now.duration_since(t) < PROOF_FRESH))
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
    health: Vec<Health>,
}

impl State {
    fn pick(&self) -> usize {
        if let Some(i) = self.choice {
            return i;
        }
        if let Some(i) = self
            .health
            .iter()
            .position(|h| h.ks.posture() == Posture::Connected)
        {
            return i;
        }
        if let Some(i) = self.health.iter().position(|h| !h.recently_failed()) {
            return i;
        }
        // All failed recently: the one that failed longest ago.
        (0..self.health.len())
            .min_by_key(|&i| self.health[i].last_fail)
            .unwrap_or(0)
    }

    fn posture(&self) -> Posture {
        if self.user_off {
            return Posture::Disconnected;
        }
        if self.revoked.is_some() {
            return Posture::Error;
        }
        match self.health.get(self.pick()) {
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

/// Snapshot for the control API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub posture: Posture,
    pub choice: ExitChoice,
    /// The exit new sessions use now (None: no exits configured).
    pub current_exit: Option<String>,
    pub exits: Vec<String>,
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
                health,
            })),
            off: watch::channel(false).0,
            revoked: Arc::new(watch::channel(None).0),
            channels: (0..exits_len).map(|_| Channel::default()).collect(),
            control: ControlTiming::default(),
            session_cfg: segue_session::Config::default(),
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
        let st = self.state.lock().unwrap();
        let choice = match st.choice {
            None => ExitChoice::Auto,
            Some(i) => ExitChoice::Named(self.exits[i].name.clone()),
        };
        Status {
            posture: st.posture(),
            choice,
            current_exit: (!self.exits.is_empty()).then(|| self.exits[st.pick()].name.clone()),
            exits: self.exits.iter().map(|e| e.name.clone()).collect(),
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
        self.state.lock().unwrap().choice = choice;
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
                let st = self.state.lock().unwrap();
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
                    // The relay answered on that exit (r10 failover): the
                    // path works, the first OPEN was only slow (T_attach)
                    // or lost. That answer is proof for the exit, and the
                    // fresh session goes to the same exit: re-picking
                    // would move it (under Auto) to an exit that has not
                    // failed lately only because nothing tried it, and
                    // the failures the slow OPEN reported would refuse a
                    // strict flow on the exit that just answered.
                    if let Some(i) = exit {
                        relay_answered(&mut self.state.lock().unwrap().health[i]);
                        pin = Some(i);
                    }
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
        pin: Option<usize>,
        exit: &mut Option<usize>,
    ) -> Result<crate::dial::Stream, (DialError, Option<u8>)> {
        let i = {
            let st = self.state.lock().unwrap();
            if st.user_off {
                return Err((DialError("refused: disconnected".into()), None));
            }
            if let Some(c) = st.revoked {
                return Err((
                    DialError(format!("refused: device revoked (code {c})")),
                    Some(c),
                ));
            }
            if self.exits.is_empty() {
                return Err((DialError("refused: no exits configured".into()), None));
            }
            let i = pin.unwrap_or_else(|| st.pick());
            *exit = Some(i);
            let h = &st.health[i];
            // Refused at once while the exit's carrier connects fail, or
            // its sessions are backing off after failures (r9 F5).
            let down = matches!(h.ks.posture(), Posture::Reconnecting | Posture::Error)
                && (h.recently_failed() || h.failing() > 0);
            if r.exit_class == EXIT_AI && down {
                return Err((
                    DialError("refused: tunnel reconnecting (strict route)".into()),
                    None,
                ));
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
                Err(_) => Err(closed_err((&mut closed_rx).await.ok())),
            },
            c = &mut closed_rx => Err(closed_err(c.ok())),
            _ = tokio::time::sleep(OPEN_WAIT) => Err((DialError("session open timed out".into()), None)),
        }
    }
}

/// A session's health report (r9 F5) into its exit's health (r10 N6).
/// The exit health aggregates its sessions, apart from their recovery
/// budgets:
///
/// - `Up` (a valid protocol answer) proves the exit: `Connected`.
/// - `Failed` / `GaveUp` takes it down (`Reconnecting`, or `Error` if it
///   never worked) only when no other live session proved the path
///   within [`PROOF_FRESH`]: one bad session among good ones blocks
///   nothing, and does not flip the exit back and forth.
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
        SessionHealth::Failed | SessionHealth::GaveUp => {
            if r == SessionHealth::GaveUp {
                // It is ending: nothing of it counts any more.
                h.sessions.remove(&id);
            } else {
                let m = h.sessions.entry(id).or_default();
                m.failing = true;
                m.ok_at = None;
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

/// The relay answered a session on this exit with a protocol frame (a
/// REJECT it sends only when it read our OPEN): the path works.
fn relay_answered(h: &mut Health) {
    h.unproven = false;
    h.last_fail = None;
    h.ks.on_event(Event::ChannelUp);
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

#[cfg(test)]
mod tests;
