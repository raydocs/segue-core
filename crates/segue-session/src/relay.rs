//! Relay-side session table (§5.2, §5.3, §5.5).
//!
//! Sans-IO like the client. Carriers are named by a caller-chosen
//! [`CarrierId`]; the first frame on a carrier must be OPEN, RESUME,
//! REDUNDANT_ATTACH (v0.6 draft) or CTRL_HELLO. The
//! table asks the caller to connect to a site with
//! [`RelayEvent::Connect`] exactly once per session (A2): the session entry
//! exists before the connect starts, so an OPEN retry or a duplicate OPEN
//! that arrives while connecting finds it.
//!
//! A carrier whose first frame is `CTRL_HELLO` is the device's control
//! stream (§3): the table answers PING with PONG and sends `STALL` there
//! when one of the device's sessions goes DETACHED (B1), and `REVOKED` on
//! a device reset. Control streams are bounded (review r5 N11): at most
//! [`MAX_CTRL_PER_DEVICE`] per device (a new one replaces the oldest), and
//! each is closed after `t_ctrl_idle` without a frame or `max_lifetime`
//! after its CTRL_HELLO.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::codec::{
    code, ty, ClosedInfo, CtrlHello, CtrlHelloReply, Frame, Kind, Opened, RedundantAttach,
    RedundantOk, Reject, Resumed, Secret, SessionId, Target,
};
use crate::flow::{DupQueue, RecvHalf, SendHalf, SentFrame};
use crate::pool::Pool;
use crate::{ct_eq, Config, MoveStats, ProtoError};

pub type CarrierId = u64;

/// What one OPEN's ticket authorized. It travels with that session's
/// connect request ([`RelayEvent::Connect`]), so a site connect is decided
/// by the ticket of its own OPEN, never by per-device state another OPEN or
/// RESUME may have changed in the meantime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Grant {
    pub device: u64,
    /// Exit classes, as bits defined by the [`Authorizer`].
    pub exit_classes: u32,
    /// Node the device's AI traffic must anchor on (0: any).
    pub ai_anchor_node_id: u64,
}

impl Grant {
    /// Every class allowed (tests, [`AllowAll`]).
    pub fn all(device: u64) -> Self {
        Self {
            device,
            exit_classes: u32::MAX,
            ai_anchor_node_id: 0,
        }
    }
}

/// Ticket / revocation check, or a REJECT code. Both calls must be free of
/// side effects: a RESUME that is rejected later (secret, device,
/// generation) must not have changed anything.
pub trait Authorizer: Send + Sync {
    fn open(&self, ticket: &[u8], target: &Target, kind: Kind) -> Result<Grant, u8>;
    /// Returns the device id.
    fn resume(&self, ticket: &[u8]) -> Result<u64, u8>;
}

/// Accepts every ticket as device 0 (tests, and until tickets exist).
pub struct AllowAll;

impl Authorizer for AllowAll {
    fn open(&self, _: &[u8], _: &Target, _: Kind) -> Result<Grant, u8> {
        Ok(Grant::all(0))
    }
    fn resume(&self, _: &[u8]) -> Result<u64, u8> {
        Ok(0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayEvent {
    /// Connect to the site; answer with [`RelayTable::connect_done`].
    Connect {
        session_id: SessionId,
        /// What this OPEN's ticket authorized (device, exit classes).
        grant: Grant,
        target: Target,
        kind: Kind,
        /// The client's hint (R2-1: the relay classifies on its own; the
        /// hint is only used to count reclassifications).
        exit_class: u8,
    },
    /// Send `STALL` on the device's control stream (B1).
    Stall {
        device: u64,
        session_id: SessionId,
        attach_gen: u32,
    },
    /// The session is gone: drop the site connection.
    Closed {
        session_id: SessionId,
        close_code: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Active,
    Detached,
}

#[derive(Debug)]
struct Tomb {
    info: ClosedInfo,
    until: Instant,
}

struct RelayRedundant {
    cid: CarrierId,
    /// When this carrier was demoted from current by a stall. `None` for a
    /// freshly attached spare or after any valid frame arrives on it.
    demoted_at: Option<Instant>,
    /// Next periodic probe time while `demoted_at.is_some()`.
    next_probe: Option<Instant>,
    /// Last TX or RX timestamp on this carrier (for AI idle keepalive).
    last_activity: Instant,
    /// Last RX timestamp when this bound spare delivered end-to-end progress.
    progressed_at: Option<Instant>,
    /// Last `(recv_offset, max_offset)` transmitted as `ACK` on this spare.
    last_acked: (u64, u64),
    /// Mirrored `ACK` owed on this bound spare.
    ack_due: bool,
    /// Mirrored `FIN` offset owed on this bound spare.
    fin_due: Option<u64>,
    /// Contiguous-prefix delayed duplicate queue for Stage 2 small `DATA`.
    dup: DupQueue,
}

struct Session {
    device: u64,
    secret: Secret,
    cur_gen: u32,
    carrier: Option<CarrierId>,
    /// Second live carrier (v0.6 draft), boxed so single-carrier sessions do
    /// not pay for Stage 2 spare state inline.
    redundant: Option<Box<RelayRedundant>>,
    /// Reply owed on the current carrier once connected.
    reply: Option<ReplyKind>,
    connected: bool,
    state: SessionState,
    last_progress: Instant,
    detached_since: Option<Instant>,
    /// Downlink (relay → client).
    send: SendHalf,
    /// Uplink (client → relay).
    recv: RecvHalf,
    rst: Option<u8>,
    /// When OPEN created the session; fixed for its whole life.
    created: Instant,
    /// The client's FIN offset, received but not yet acknowledged because
    /// the site has not taken the upload yet (see
    /// [`RelayTable::confirm_site_flush`]).
    held_fin: Option<u64>,
    /// When a frame of this session last went out (see
    /// [`RelayTable::keepalive`]).
    last_sent: Instant,
    /// Bytes of a frame from the client are arriving: repeat the current
    /// ACK so the client sees its carrier alive (see
    /// [`RelayTable::on_carrier_progress`]).
    ka_due: bool,
    /// The keepalive period: half the shorter of this relay's `t_stall`
    /// and the one the client announced in its latest OPEN or RESUME
    /// (r9: with only the relay's, a client with a shorter bound took
    /// a live carrier for a stalled one).
    keepalive: std::time::Duration,
    /// OPEN's `exit_class` hint. [`crate::EXIT_CLASS_AI`] uses
    /// [`crate::Timing::t_detached_ai`] and keeps reading the site while
    /// detached, into the replay buffer the send half already has.
    exit_class: u8,
    /// Last frame received on the current carrier. A stall swap follows the
    /// client when it starts sending on a spare after primary silence.
    carrier_rx: Instant,
    /// Current carrier was promoted in-place in this generation (no RESUME),
    /// so in-flight Stage 2 duplicates/FIN may arrive out of order relative to
    /// `recv_offset`.
    promoted_in_gen: bool,
}

// Manual so the resume secret never reaches a log.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("device", &self.device)
            .field("cur_gen", &self.cur_gen)
            .field("carrier", &self.carrier)
            .field("redundant", &self.redundant.as_ref().map(|r| r.cid))
            .field("connected", &self.connected)
            .field("state", &self.state)
            .field("rst", &self.rst)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplyKind {
    Opened,
    Resumed,
}

#[derive(Debug, Default)]
struct CarrierSlot {
    session: Option<SessionId>,
    /// Frame queued before the carrier is bound or closed (REJECT).
    out: Option<Frame>,
    close_after: bool,
    /// Control stream of this device (first frame was CTRL_HELLO).
    control: Option<u64>,
    /// Control frames to send (PONG, STALL, REVOKED), bounded.
    ctrl_out: VecDeque<Frame>,
    /// Control stream: when CTRL_HELLO was accepted, last frame received.
    ctrl_since: Option<Instant>,
    ctrl_seen: Option<Instant>,
}

pub use crate::MIN_CLIENT_STALL;

/// Control frames queued per control stream; PINGs beyond this are not
/// answered (a peer that never reads cannot grow the queue).
const CTRL_QUEUE: usize = 64;
/// Live control streams one device may hold on this relay.
///
/// The kernel keeps one control stream per configured exit, and nothing
/// limits how many exits of one device point at the same relay; during a
/// network change the replacement streams arrive while the old ones are
/// still open. So the cap is not "a few" (review r6 R8: with 4, a fifth
/// exit kicked the first, whose reconnect kicked another, forever) but
/// 2 × 16 exits: comfortably above any real configuration, still a small
/// fraction of the relay's carrier slots (`max_carriers`, 4096 by default).
///
/// At the cap a newcomer replaces only a stream that has gone quiet
/// ([`ctrl_quiet`]); a stream that is still pinging is never kicked, the
/// newcomer is closed instead (without a reply, so the client just
/// retries and does not treat a channel as dead).
pub const MAX_CTRL_PER_DEVICE: usize = 32;

/// A control stream that sent nothing for this long may be replaced by a
/// new one of the same device: a third of `t_ctrl_idle` (10 s by default,
/// two missed kernel PINGs at 5 s).
pub fn ctrl_quiet(t: &crate::Timing) -> std::time::Duration {
    t.t_ctrl_idle / 3
}
/// STALL entries per frame (20 bytes each, under MAX_PAYLOAD).
const STALL_BATCH: usize = 512;

enum TxSink<'a> {
    Owned(Option<Frame>),
    Encoded { out: &'a mut Vec<u8> },
}

impl TxSink<'_> {
    fn emit(&mut self, f: Frame) {
        match self {
            Self::Owned(slot) => *slot = Some(f),
            Self::Encoded { out } => f.encode(out),
        }
    }
}

pub struct RelayTable {
    cfg: Config,
    pool: Arc<Pool>,
    auth: Box<dyn Authorizer>,
    instance_id: u64,
    sessions: HashMap<SessionId, Session>,
    sessions_by_device: HashMap<u64, HashSet<SessionId>>,
    tombs: HashMap<SessionId, Tomb>,
    tombs_exp: BinaryHeap<Reverse<(Instant, SessionId)>>,
    carriers: HashMap<CarrierId, CarrierSlot>,
    ctrl_by_device: HashMap<u64, Vec<CarrierId>>,
    ctrl_carriers: HashSet<CarrierId>,
    events: VecDeque<RelayEvent>,
    to_close: Vec<CarrierId>,
    /// Latest `now` seen; used for tombstone expiry.
    clock: Instant,
    /// See [`RelayTable::confirm_site_flush`].
    hold_fin: bool,
    /// `t_live` expiries and `STALL` hints queued on a control stream.
    moves: MoveStats,
}

impl RelayTable {
    pub fn new(cfg: Config, pool: Arc<Pool>, auth: Box<dyn Authorizer>, instance_id: u64) -> Self {
        Self {
            cfg,
            pool,
            auth,
            instance_id,
            sessions: HashMap::new(),
            sessions_by_device: HashMap::new(),
            tombs: HashMap::new(),
            tombs_exp: BinaryHeap::new(),
            carriers: HashMap::new(),
            ctrl_by_device: HashMap::new(),
            ctrl_carriers: HashSet::new(),
            events: VecDeque::new(),
            to_close: Vec::new(),
            clock: Instant::now(),
            hold_fin: false,
            moves: MoveStats::default(),
        }
    }

    fn remove_ctrl_index(&mut self, device: u64, cid: CarrierId) {
        self.ctrl_carriers.remove(&cid);
        if let Some(cids) = self.ctrl_by_device.get_mut(&device) {
            cids.retain(|&c| c != cid);
            if cids.is_empty() {
                self.ctrl_by_device.remove(&device);
            }
        }
    }

    /// `t_live` expiries and `STALL` hints this table has sent.
    /// Client fields of the snapshot stay zero.
    pub fn move_stats(&self) -> MoveStats {
        self.moves
    }

    /// With `on`, the client's FIN is acknowledged (and a session can end
    /// CLEAN) only after [`site_flushed`]: the driver reports that the site
    /// took every uploaded byte and its write side was shut down. Until
    /// then [`read_eof`] already reports the end, so the driver can shut
    /// the site down. A site that fails or never finishes is reset
    /// ([`site_reset`]), so a truncated upload is never reported clean
    /// (review r6, relay upload drain). Off: FIN is acknowledged on
    /// arrival (state-machine tests that have no site writer).
    ///
    /// [`site_flushed`]: Self::site_flushed
    /// [`read_eof`]: Self::read_eof
    /// [`site_reset`]: Self::site_reset
    pub fn confirm_site_flush(&mut self, on: bool) {
        self.hold_fin = on;
    }

    pub fn timing(&self) -> &crate::Timing {
        &self.cfg.timing
    }

    /// The client's FIN and every upload byte before it have arrived: what
    /// is left of the upload is only waiting for the site (the driver's
    /// flush bounds start here, review r7 #9).
    pub fn upload_complete(&self, sid: &SessionId) -> bool {
        self.sessions
            .get(sid)
            .is_some_and(|s| s.recv.fin_received() || s.held_fin == Some(s.recv.recv_offset()))
    }

    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions.keys().copied().collect()
    }
    pub fn state(&self, sid: &SessionId) -> Option<SessionState> {
        self.sessions.get(sid).map(|s| s.state)
    }
    pub fn cur_gen(&self, sid: &SessionId) -> Option<u32> {
        self.sessions.get(sid).map(|s| s.cur_gen)
    }
    pub fn current_carrier(&self, sid: &SessionId) -> Option<CarrierId> {
        self.sessions.get(sid).and_then(|s| s.carrier)
    }

    /// The session's redundant carrier, if one is bound (v0.6 draft).
    pub fn redundant_carrier(&self, sid: &SessionId) -> Option<CarrierId> {
        self.sessions
            .get(sid)
            .and_then(|s| s.redundant.as_ref().map(|r| r.cid))
    }
    pub fn has_tomb(&self, sid: &SessionId) -> Option<ClosedInfo> {
        self.tombs.get(sid).map(|t| t.info)
    }
    pub fn send_half(&self, sid: &SessionId) -> Option<&SendHalf> {
        self.sessions.get(sid).map(|s| &s.send)
    }
    pub fn recv_half(&self, sid: &SessionId) -> Option<&RecvHalf> {
        self.sessions.get(sid).map(|s| &s.recv)
    }

    pub fn take_event(&mut self) -> Option<RelayEvent> {
        self.events.pop_front()
    }

    /// Carriers to close once their queued frames are flushed.
    pub fn take_closed_carriers(&mut self) -> Vec<CarrierId> {
        std::mem::take(&mut self.to_close)
    }

    /// A new carrier was accepted.
    pub fn add_carrier(&mut self, cid: CarrierId) {
        self.carriers.entry(cid).or_default();
    }

    pub fn on_carrier_closed(&mut self, cid: CarrierId, now: Instant) {
        self.clock = self.clock.max(now);
        let Some(slot) = self.carriers.remove(&cid) else {
            return;
        };
        if let Some(device) = slot.control {
            self.remove_ctrl_index(device, cid);
        }
        let Some(sid) = slot.session else {
            return;
        };
        // A spare carrier dying changes nothing else: the current carrier
        // stays current and the session is not detached.
        if self.sessions.get(&sid).is_some_and(|s| {
            s.redundant.as_ref().is_some_and(|r| r.cid == cid) && s.carrier != Some(cid)
        }) {
            if let Some(s) = self.sessions.get_mut(&sid) {
                s.redundant = None;
            }
            return;
        }
        // The current carrier died. A bound spare is promoted in place:
        // same generation, no RESUME, unacked downlink replayed from the
        // last acknowledged offset. Rule 6: a later switch still drops it.
        let was_current = self
            .sessions
            .get(&sid)
            .is_some_and(|s| s.carrier == Some(cid));
        // A hard close. The carrier is gone, so it cannot be demoted.
        if was_current && self.promote_bound_spare(&sid, now, false) {
            return;
        }
        let Some(s) = self.sessions.get_mut(&sid) else {
            return;
        };
        if s.carrier != Some(cid) {
            return;
        }
        s.carrier = None;
        s.detached_since.get_or_insert(now);
        if s.state == SessionState::Active {
            s.state = SessionState::Detached;
        }
    }

    fn reject(&mut self, cid: CarrierId, code: u8, gen: u32, closed: Option<ClosedInfo>) {
        let slot = self.carriers.entry(cid).or_default();
        slot.session = None;
        slot.out = Some(Frame::Reject(Reject {
            code,
            attach_gen: gen,
            closed,
        }));
        slot.close_after = true;
        self.to_close.push(cid);
    }

    fn close_carrier_now(&mut self, cid: CarrierId) {
        let mut ctrl_device = None;
        if let Some(slot) = self.carriers.get_mut(&cid) {
            slot.session = None;
            slot.close_after = true;
            ctrl_device = slot.control;
        }
        if let Some(device) = ctrl_device {
            self.remove_ctrl_index(device, cid);
        }
        self.to_close.push(cid);
    }

    /// A frame decoded from carrier `cid`.
    pub fn on_frame(&mut self, cid: CarrierId, frame: Frame, now: Instant) {
        self.clock = self.clock.max(now);
        let slot = self.carriers.entry(cid).or_default();
        if slot.close_after {
            return;
        }
        if slot.control.is_some() {
            slot.ctrl_seen = Some(now);
            if let Frame::Ping { nonce } = frame {
                if slot.ctrl_out.len() < CTRL_QUEUE {
                    slot.ctrl_out.push_back(Frame::Pong {
                        nonce,
                        extra: Vec::new(),
                    });
                }
            }
            // Other control frames (RESOLVE, REFRESH, PARK) are not
            // implemented; session frames do not belong here.
            return;
        }
        match slot.session {
            None => self.on_first(cid, frame, now),
            Some(sid) => {
                let (mut is_current, is_redundant) = self
                    .sessions
                    .get(&sid)
                    .map(|s| {
                        (
                            s.carrier == Some(cid),
                            s.redundant.as_ref().is_some_and(|r| r.cid == cid),
                        )
                    })
                    .unwrap_or((false, false));
                // Frames from any other carrier are still dropped. The
                // redundant carrier is the one exception (v0.6 draft): its
                // DATA/ACK/FIN/RST are applied and deduplicated by offset.
                if !is_current && !is_redundant {
                    return;
                }
                if is_redundant {
                    let is_rst = matches!(frame, Frame::Rst { .. });
                    let mut promote_detached = false;
                    if let Some(s) = self.sessions.get_mut(&sid) {
                        if let Some(r) = s.redundant.as_mut().filter(|r| r.cid == cid) {
                            r.demoted_at = None;
                            r.next_probe = None;
                            r.last_activity = now;
                        }
                        if !is_rst && s.state == SessionState::Detached {
                            promote_detached = true;
                        }
                    }
                    if promote_detached && self.promote_bound_spare(&sid, now, false) {
                        is_current = true;
                    }
                }
                if is_current {
                    if let Some(s) = self.sessions.get_mut(&sid) {
                        s.carrier_rx = now;
                    }
                }
                match self.on_session_frame(&sid, frame, now, is_current) {
                    Ok(progressed) => {
                        if !is_current && progressed {
                            let live = self
                                .cfg
                                .timing
                                .live_for(self.sessions.get(&sid).map_or(0, |s| s.exit_class));
                            let mut promote_stale = false;
                            if let Some(s) = self.sessions.get_mut(&sid) {
                                if let Some(r) = s.redundant.as_mut().filter(|r| r.cid == cid) {
                                    r.progressed_at = Some(now);
                                }
                                if s.state == SessionState::Active && now >= s.carrier_rx + live {
                                    promote_stale = true;
                                }
                            }
                            if promote_stale {
                                let _ = self.promote_bound_spare(&sid, now, true);
                            }
                        }
                    }
                    Err(e) => {
                        if is_current {
                            self.fail(&sid, e);
                        } else {
                            // A bad frame on the spare path drops only that carrier.
                            self.drop_spare(sid, cid);
                        }
                    }
                }
                self.check_done(&sid, now);
            }
        }
    }

    /// Make the bound spare the current carrier. Same generation, no RESUME.
    /// Replays unacked downlink from the last acknowledged offset.
    ///
    /// `demote` keeps the previous current carrier bound as the spare. A hard
    /// close (or detached recovery) passes `false`. A spare that was itself
    /// demoted and has received nothing since is not promoted.
    fn promote_bound_spare(&mut self, sid: &SessionId, now: Instant, demote: bool) -> bool {
        let Some(red) = self
            .sessions
            .get(sid)
            .and_then(|s| s.redundant.as_ref().map(|r| r.cid))
        else {
            return false;
        };
        if self
            .sessions
            .get(sid)
            .is_some_and(|s| s.carrier == Some(red))
        {
            return false;
        }
        if self.carriers.get(&red).is_none_or(|c| c.close_after) {
            return false;
        }
        if demote
            && self
                .sessions
                .get(sid)
                .and_then(|s| s.redundant.as_ref())
                .is_some_and(|r| r.demoted_at.is_some())
        {
            return false;
        }
        let old = self.sessions.get(sid).and_then(|s| s.carrier);
        let old_open = old.is_some_and(|cid| {
            cid != red && self.carriers.get(&cid).is_some_and(|c| !c.close_after)
        });
        let s = self.sessions.get_mut(sid).unwrap();
        s.redundant = None;
        s.carrier = Some(red);
        let acked = s.send.acked();
        let max = s.send.peer_max();
        // Fails only if `acked` is past `sent_hw`, which `on_ack` never allows.
        let _ = s.send.rewind(acked, max);
        s.detached_since = None;
        s.last_progress = now;
        s.carrier_rx = now;
        s.promoted_in_gen = true;
        if s.connected && s.state != SessionState::Connecting {
            s.state = SessionState::Active;
        }
        if demote && old_open {
            if let Some(old_cid) = old {
                s.redundant = Some(Box::new(RelayRedundant {
                    cid: old_cid,
                    demoted_at: Some(now),
                    next_probe: self.cfg.timing.demoted_probe_interval().map(|d| now + d),
                    last_activity: now,
                    progressed_at: None,
                    last_acked: (u64::MAX, u64::MAX),
                    ack_due: false,
                    fin_due: None,
                    dup: DupQueue::new(acked),
                }));
            }
        }
        true
    }

    /// Close a redundant carrier and forget it. The session is untouched.
    fn drop_spare(&mut self, sid: SessionId, cid: CarrierId) {
        if let Some(s) = self.sessions.get_mut(&sid) {
            if s.redundant.as_ref().is_some_and(|r| r.cid == cid) {
                s.redundant = None;
            }
        }
        self.close_carrier_now(cid);
    }

    pub fn on_decode_error(&mut self, cid: CarrierId, e: ProtoError) {
        let sid = self.carriers.get(&cid).and_then(|s| s.session);
        match sid {
            Some(sid)
                if self
                    .sessions
                    .get(&sid)
                    .is_some_and(|s| s.carrier == Some(cid)) =>
            {
                self.fail(&sid, e)
            }
            // A decode error on the spare carrier drops only that carrier.
            Some(sid)
                if self
                    .sessions
                    .get(&sid)
                    .is_some_and(|s| s.redundant.as_ref().is_some_and(|r| r.cid == cid)) =>
            {
                self.drop_spare(sid, cid);
            }
            // OPEN / RESUME with another version (§10): REJECT(version).
            None if matches!(e, ProtoError::Version(_)) => self.reject(cid, code::VERSION, 0, None),
            _ => self.close_carrier_now(cid),
        }
    }

    fn fail(&mut self, sid: &SessionId, _e: ProtoError) {
        if let Some(s) = self.sessions.get_mut(sid) {
            s.rst = Some(code::PROTOCOL);
        }
        self.finish(sid, code::PROTOCOL, true);
    }

    fn on_control_hello(&mut self, cid: CarrierId, payload: &[u8], now: Instant) {
        let hello = match CtrlHello::parse(payload) {
            Ok(h) => h,
            Err(ProtoError::Version(_)) => return self.reject(cid, code::VERSION, 0, None),
            Err(_) => return self.close_carrier_now(cid),
        };
        // An expired ticket would still get a control stream for REFRESH
        // (§6); REFRESH is not implemented, so it is refused like OPEN.
        let device = match self.auth.resume(&hello.ticket) {
            Ok(d) => d,
            Err(c) => return self.reject(cid, c, 0, None),
        };
        // At the cap, replace the device's quietest streams, but only ones
        // that stopped sending; never kick a live one (review r6 R8).
        let mut mine: Vec<(Instant, Instant, CarrierId)> = self
            .ctrl_by_device
            .get(&device)
            .into_iter()
            .flat_map(|cids| cids.iter().copied())
            .filter(|&c| c != cid)
            .filter_map(|c| {
                let x = self.carriers.get(&c)?;
                (!x.close_after).then(|| {
                    let since = x.ctrl_since.unwrap_or(now);
                    (x.ctrl_seen.unwrap_or(since), since, c)
                })
            })
            .collect();
        if mine.len() >= MAX_CTRL_PER_DEVICE {
            mine.sort_unstable();
            let quiet = ctrl_quiet(&self.cfg.timing);
            let over = mine.len() + 1 - MAX_CTRL_PER_DEVICE;
            let stale: Vec<CarrierId> = mine
                .iter()
                .take(over)
                .take_while(|(seen, _, _)| now.saturating_duration_since(*seen) >= quiet)
                .map(|&(_, _, c)| c)
                .collect();
            if stale.len() < over {
                return self.close_carrier_now(cid);
            }
            for old in stale {
                self.close_carrier_now(old);
            }
        }
        let slot = self.carriers.entry(cid).or_default();
        slot.control = Some(device);
        slot.ctrl_since = Some(now);
        slot.ctrl_seen = Some(now);
        slot.ctrl_out.push_back(
            CtrlHelloReply {
                node_id: 0,
                instance_id: self.instance_id,
                ticket_expired: false,
            }
            .to_frame(),
        );
        let entry = self.ctrl_by_device.entry(device).or_default();
        if !entry.contains(&cid) {
            entry.push(cid);
        }
        self.ctrl_carriers.insert(cid);
    }

    /// Queue `STALL` entries on every control stream of `device`.
    fn send_stall(&mut self, device: u64, entries: &[(SessionId, u32)]) {
        let mut queued = 0u64;
        if let Some(cids) = self.ctrl_by_device.get(&device) {
            for &cid in cids {
                let Some(slot) = self.carriers.get_mut(&cid) else {
                    continue;
                };
                if slot.control != Some(device) || slot.close_after {
                    continue;
                }
                for batch in entries.chunks(STALL_BATCH) {
                    if slot.ctrl_out.len() < CTRL_QUEUE {
                        slot.ctrl_out.push_back(Frame::Stall(batch.to_vec()));
                        queued = queued.saturating_add(batch.len() as u64);
                    }
                }
            }
        }
        self.moves.stall_hints = self.moves.stall_hints.saturating_add(queued);
    }

    fn on_first(&mut self, cid: CarrierId, frame: Frame, now: Instant) {
        match frame {
            Frame::Control {
                ty: ty::CTRL_HELLO,
                payload,
            } => self.on_control_hello(cid, &payload, now),
            Frame::Open(o) => {
                let sid = o.session_id;
                if let Some(t) = self.tombs.get(&sid) {
                    let info = t.info;
                    return self.reject(cid, code::CLOSED, o.attach_gen, Some(info));
                }
                if let Some(s) = self.sessions.get(&sid) {
                    if !ct_eq(&s.secret, &o.resume_secret) {
                        return self.reject(cid, code::AUTH, o.attach_gen, None);
                    }
                    if o.attach_gen <= s.cur_gen || !o.retry {
                        // Late duplicate OPEN: never evicts the current carrier.
                        return self.reject(cid, code::STALE_GEN, o.attach_gen, None);
                    }
                    if o.anchor_instance_id != 0 && o.anchor_instance_id != self.instance_id {
                        return self.reject(cid, code::UNKNOWN_SESSION, o.attach_gen, None);
                    }
                    match self.auth.resume(&o.ticket) {
                        Ok(d) if d == s.device => {}
                        Ok(_) => return self.reject(cid, code::AUTH, o.attach_gen, None),
                        Err(c) => return self.reject(cid, c, o.attach_gen, None),
                    }
                    // Retry of a known session: treated as a resume (no new
                    // connect). OPEN carries no offsets; the client has
                    // confirmed nothing, so its snapshot is (0, initial).
                    let init = self.cfg.limits.initial_credit as u64;
                    if let Err(e) =
                        self.switch(&sid, cid, o.attach_gen, 0, init, ReplyKind::Resumed, now)
                    {
                        return self.fail(&sid, e);
                    }
                    if !o.first_data.is_empty() {
                        let r = self.sessions.get_mut(&sid).unwrap().recv.on_data(
                            0,
                            &o.first_data,
                            now,
                        );
                        if let Err(e) = r {
                            self.fail(&sid, e);
                        }
                    }
                    return;
                }
                if o.retry {
                    // A2: never open on a retry; the first attempt may have
                    // connected in a process that has since restarted.
                    return self.reject(cid, code::UNKNOWN_SESSION, o.attach_gen, None);
                }
                let grant = match self.auth.open(&o.ticket, &o.target, o.kind) {
                    Ok(g) => g,
                    Err(c) => return self.reject(cid, c, o.attach_gen, None),
                };
                let idle = self.cfg.timing.idle_after_for(o.exit_class);
                let Some(mut recv) = RecvHalf::new_with_idle(
                    &self.pool,
                    &self.cfg.limits,
                    &self.cfg.timing,
                    idle,
                    now,
                ) else {
                    return self.reject(cid, code::CAPACITY, o.attach_gen, None);
                };
                let Some(send) = SendHalf::new(&self.pool, &self.cfg.limits) else {
                    return self.reject(cid, code::CAPACITY, o.attach_gen, None);
                };
                if !o.first_data.is_empty() && recv.on_data(0, &o.first_data, now).is_err() {
                    return self.reject(cid, code::PROTOCOL, o.attach_gen, None);
                }
                let s = Session {
                    device: grant.device,
                    secret: o.resume_secret,
                    cur_gen: o.attach_gen,
                    carrier: Some(cid),
                    redundant: None,
                    reply: Some(ReplyKind::Opened),
                    connected: false,
                    state: SessionState::Connecting,
                    last_progress: now,
                    detached_since: None,
                    send,
                    recv,
                    rst: None,
                    created: now,
                    held_fin: None,
                    last_sent: now,
                    ka_due: false,
                    keepalive: self.keepalive_for(o.t_stall_ms),
                    exit_class: o.exit_class,
                    carrier_rx: now,
                    promoted_in_gen: false,
                };
                let device = s.device;
                self.sessions.insert(sid, s);
                self.sessions_by_device
                    .entry(device)
                    .or_default()
                    .insert(sid);
                self.carriers.get_mut(&cid).unwrap().session = Some(sid);
                self.events.push_back(RelayEvent::Connect {
                    session_id: sid,
                    grant,
                    target: o.target,
                    kind: o.kind,
                    exit_class: o.exit_class,
                });
            }
            Frame::Resume(r) => {
                let sid = r.session_id;
                if let Some(t) = self.tombs.get(&sid) {
                    let info = t.info;
                    return self.reject(cid, code::CLOSED, r.attach_gen, Some(info));
                }
                if r.anchor_instance_id != 0 && r.anchor_instance_id != self.instance_id {
                    // §9.2 hand-off between instances is not implemented.
                    return self.reject(cid, code::UNKNOWN_SESSION, r.attach_gen, None);
                }
                let Some(s) = self.sessions.get(&sid) else {
                    return self.reject(cid, code::UNKNOWN_SESSION, r.attach_gen, None);
                };
                if !ct_eq(&s.secret, &r.resume_secret) {
                    return self.reject(cid, code::AUTH, r.attach_gen, None);
                }
                match self.auth.resume(&r.ticket) {
                    Ok(d) if d == s.device => {}
                    Ok(_) => return self.reject(cid, code::AUTH, r.attach_gen, None),
                    Err(c) => return self.reject(cid, c, r.attach_gen, None),
                }
                if r.attach_gen <= s.cur_gen {
                    return self.reject(cid, code::STALE_GEN, r.attach_gen, None);
                }
                let ka = self.keepalive_for(r.t_stall_ms);
                if let Some(s) = self.sessions.get_mut(&sid) {
                    s.keepalive = ka;
                }
                if let Err(e) = self.switch(
                    &sid,
                    cid,
                    r.attach_gen,
                    r.recv_offset,
                    r.max_offset,
                    ReplyKind::Resumed,
                    now,
                ) {
                    self.fail(&sid, e);
                }
            }
            Frame::RedundantAttach(a) => self.on_redundant_attach(cid, a, now),
            _ => self.close_carrier_now(cid),
        }
    }

    /// Bind `cid` as the session's redundant carrier. Does not call
    /// [`switch`](Self::switch): the current carrier stays current and is
    /// not closed. A second attach replaces the first. An unknown session
    /// or a bad proof closes only this carrier.
    ///
    /// Binding reserves no session memory (no new grant, no admission
    /// floor). The carrier-slot limit lives in the relay process, which
    /// refuses a new connection before this table sees it; a full table
    /// never drops a session to make room for a spare.
    fn on_redundant_attach(&mut self, cid: CarrierId, a: RedundantAttach, now: Instant) {
        let sid = a.session_id;
        if self.tombs.contains_key(&sid) || !self.sessions.contains_key(&sid) {
            self.close_carrier_now(cid);
            return;
        }
        let ok = self.sessions.get(&sid).is_some_and(|s| {
            s.connected
                && s.state == SessionState::Active
                && s.carrier.is_some()
                && ct_eq(&s.secret, &a.resume_secret)
                && a.attach_gen == s.cur_gen
                && s.carrier != Some(cid)
        });
        if !ok {
            self.close_carrier_now(cid);
            return;
        }
        // The client's snapshot is an ACK of what it has, applied without
        // rewinding the current carrier's send cursor.
        if self
            .sessions
            .get_mut(&sid)
            .unwrap()
            .send
            .on_ack(a.recv_offset, a.max_offset)
            .is_err()
        {
            self.close_carrier_now(cid);
            return;
        }
        let old = self
            .sessions
            .get(&sid)
            .unwrap()
            .redundant
            .as_ref()
            .map(|r| r.cid);
        if let Some(old) = old {
            if old != cid {
                self.close_carrier_now(old);
                if let Some(s) = self.sessions.get_mut(&sid) {
                    if s.redundant.as_ref().is_some_and(|r| r.cid == old) {
                        s.redundant = None;
                    }
                }
            }
        }
        let (recv_offset, max_offset, gen, acked, cursor, exit_class, fin_in_flight) = {
            let s = self.sessions.get(&sid).unwrap();
            (
                s.recv.recv_offset(),
                s.recv.max_offset(),
                s.cur_gen,
                s.send.acked(),
                s.send.cursor(),
                s.exit_class,
                s.send
                    .fin_offset()
                    .filter(|&f| s.send.sent_hw() > f && !s.send.done()),
            )
        };
        let mut dup = DupQueue::new(acked);
        if cursor > acked {
            if let Some(delay) = self.cfg.redundancy.dup_delay_for(exit_class) {
                dup.seed_inflight(
                    acked,
                    cursor,
                    self.cfg.redundancy.max_frame_bytes,
                    delay,
                    now,
                );
            }
        }
        if let Some(s) = self.sessions.get_mut(&sid) {
            s.redundant = Some(Box::new(RelayRedundant {
                cid,
                demoted_at: None,
                next_probe: None,
                last_activity: now,
                progressed_at: None,
                last_acked: (u64::MAX, u64::MAX),
                ack_due: false,
                fin_due: fin_in_flight,
                dup,
            }));
        }
        let slot = self.carriers.get_mut(&cid).unwrap();
        slot.session = Some(sid);
        slot.out = Some(Frame::RedundantOk(RedundantOk {
            attach_gen: gen,
            recv_offset,
            max_offset,
        }));
    }

    /// Atomic attach (§5.2): snapshot, close the current carrier, switch.
    #[allow(clippy::too_many_arguments)]
    fn switch(
        &mut self,
        sid: &SessionId,
        cid: CarrierId,
        gen: u32,
        peer_recv: u64,
        peer_max: u64,
        reply: ReplyKind,
        now: Instant,
    ) -> Result<(), ProtoError> {
        let s = self.sessions.get_mut(sid).unwrap();
        // A move bumps the generation. The spare was authenticated at the
        // old one, so it is dropped rather than left bound (rule 6).
        let spare = s.redundant.take().map(|r| r.cid);
        if let Err(e) = s.send.rewind(peer_recv, peer_max) {
            // The new carrier is not bound yet: answer it here, the caller
            // fails the session (and its current carrier).
            self.reject(cid, code::PROTOCOL, gen, None);
            if let Some(spare) = spare {
                if spare != cid {
                    self.close_carrier_now(spare);
                }
            }
            return Err(e);
        }
        let old = s.carrier.replace(cid);
        // A carrier other than the current one, including after the old
        // one already closed (`carrier` is None then): another path.
        if old != Some(cid) {
            s.recv.new_path(now);
        }
        s.cur_gen = gen;
        s.reply = Some(reply);
        s.detached_since = None;
        s.last_progress = now;
        s.carrier_rx = now;
        s.promoted_in_gen = false;
        if s.state == SessionState::Detached {
            s.state = SessionState::Active;
        }
        self.carriers.get_mut(&cid).unwrap().session = Some(*sid);
        if let Some(old) = old {
            if old != cid {
                self.close_carrier_now(old);
            }
        }
        if let Some(spare) = spare {
            if spare != cid {
                self.close_carrier_now(spare);
            }
        }
        Ok(())
    }

    fn on_session_frame(
        &mut self,
        sid: &SessionId,
        frame: Frame,
        now: Instant,
        from_current: bool,
    ) -> Result<bool, ProtoError> {
        let hold = self.hold_fin;
        let s = self.sessions.get_mut(sid).unwrap();
        let allow_gap = !from_current || s.promoted_in_gen;
        let mut progressed = false;
        match frame {
            Frame::Data { offset, data, .. } => {
                if s.held_fin.is_some_and(|f| offset + data.len() as u64 > f) {
                    if !from_current {
                        return Ok(false);
                    }
                    return Err(ProtoError::Violation("data after fin"));
                }
                let n = if allow_gap {
                    s.recv.on_data_ooo(offset, &data, now)?
                } else {
                    s.recv.on_data(offset, &data, now)?
                };
                if n > 0 {
                    progressed = true;
                    if !from_current {
                        if let Some(r) = s.redundant.as_mut() {
                            r.ack_due = true;
                        }
                    }
                }
            }
            Frame::Fin { offset } if hold && !s.recv.fin_received() => {
                if allow_gap && offset > s.recv.recv_offset() {
                    return Ok(false);
                }
                match s.held_fin {
                    Some(f) if f == offset => {}
                    Some(_) => return Err(ProtoError::Violation("fin moved")),
                    None if offset != s.recv.recv_offset() => {
                        return Err(ProtoError::Violation("fin not at recv_offset"))
                    }
                    None => {
                        s.held_fin = Some(offset);
                        progressed = true;
                        if !from_current {
                            if let Some(r) = s.redundant.as_mut() {
                                r.ack_due = true;
                            }
                        }
                    }
                }
            }
            Frame::Fin { offset } => {
                if allow_gap && offset > s.recv.recv_offset() {
                    return Ok(false);
                }
                let was_fin = s.recv.fin_received();
                s.recv.on_fin(offset, now)?;
                if !was_fin {
                    progressed = true;
                    if !from_current {
                        if let Some(r) = s.redundant.as_mut() {
                            r.ack_due = true;
                        }
                    }
                }
            }
            Frame::Ack {
                recv_offset,
                max_offset,
            } => {
                let ack_progressed = s.send.on_ack(recv_offset, max_offset)?;
                if ack_progressed {
                    progressed = true;
                    let acked = s.send.acked();
                    if let Some(r) = s.redundant.as_mut() {
                        r.dup.prune_acked(acked);
                    }
                }
                // An ACK on the spare updates the window and is deduplicated,
                // but it must not keep `t_live` from firing on the current
                // carrier.
                if from_current && s.state == SessionState::Active {
                    s.last_progress = now;
                }
                if from_current && ack_progressed {
                    s.last_progress = now;
                    if s.state == SessionState::Detached && s.carrier.is_some() {
                        // B1: ACK progress on the current carrier.
                        s.state = SessionState::Active;
                        s.detached_since = None;
                    }
                }
            }
            Frame::Rst { code } => {
                self.finish(sid, code, false);
            }
            Frame::Pad(_) | Frame::Dgram { .. } => {}
            _ => return Err(ProtoError::Violation("unexpected frame on session carrier")),
        }
        Ok(progressed)
    }

    /// The site connect finished.
    pub fn connect_done(&mut self, sid: &SessionId, result: Result<(), u8>, now: Instant) {
        self.clock = self.clock.max(now);
        let Some(s) = self.sessions.get_mut(sid) else {
            return;
        };
        match result {
            Ok(()) => {
                s.connected = true;
                if s.state == SessionState::Connecting {
                    s.state = if s.carrier.is_some() {
                        SessionState::Active
                    } else {
                        SessionState::Detached
                    };
                }
                s.last_progress = now;
            }
            Err(c) => {
                s.rst = Some(c);
                self.finish(sid, c, true);
            }
        }
    }

    /// End the session and write a tombstone. `send_rst` queues RST on the
    /// current carrier first.
    fn finish(&mut self, sid: &SessionId, close_code: u8, send_rst: bool) {
        let Some(s) = self.sessions.remove(sid) else {
            return;
        };
        if let Some(sids) = self.sessions_by_device.get_mut(&s.device) {
            sids.remove(sid);
            if sids.is_empty() {
                self.sessions_by_device.remove(&s.device);
            }
        }
        let info = ClosedInfo {
            close_code,
            final_recv_offset: s.recv.recv_offset(),
            final_sent_offset: s.send.sent_hw(),
        };
        let until = self.clock + self.cfg.timing.t_tomb;
        self.tombs.insert(*sid, Tomb { info, until });
        self.tombs_exp.push(Reverse((until, *sid)));
        if let Some(cid) = s.carrier {
            if let Some(slot) = self.carriers.get_mut(&cid) {
                slot.session = None;
                slot.close_after = true;
                if send_rst {
                    slot.out = Some(Frame::Rst {
                        code: s.rst.unwrap_or(close_code),
                    });
                }
            }
            self.to_close.push(cid);
        }
        if let Some(r) = s.redundant {
            if send_rst {
                if let Some(slot) = self.carriers.get_mut(&r.cid) {
                    slot.session = None;
                    slot.close_after = true;
                    slot.out = Some(Frame::Rst {
                        code: s.rst.unwrap_or(close_code),
                    });
                }
                self.to_close.push(r.cid);
            } else {
                self.close_carrier_now(r.cid);
            }
        }
        self.events.push_back(RelayEvent::Closed {
            session_id: *sid,
            close_code,
        });
    }

    fn check_done(&mut self, sid: &SessionId, _now: Instant) {
        let done = self
            .sessions
            .get(sid)
            .is_some_and(|s| s.send.done() && s.recv.fin_acked() && s.recv.eof());
        if done {
            self.finish(sid, code::CLEAN, false);
        }
    }

    /// Next frame for carrier `cid`.
    pub fn poll_transmit(&mut self, cid: CarrierId, now: Instant) -> Option<Frame> {
        let mut sink = TxSink::Owned(None);
        self.poll_transmit_inner(cid, now, &mut sink);
        match sink {
            TxSink::Owned(f) => f,
            TxSink::Encoded { .. } => unreachable!(),
        }
    }

    /// Encode the next frame for carrier `cid` directly into `out`, returning
    /// the number of wire bytes written (`None` when nothing is queued).
    pub fn poll_transmit_into(
        &mut self,
        cid: CarrierId,
        now: Instant,
        out: &mut Vec<u8>,
    ) -> Option<usize> {
        let before = out.len();
        let wrote = {
            let mut sink = TxSink::Encoded { out };
            self.poll_transmit_inner(cid, now, &mut sink)
        };
        wrote.then(|| out.len() - before)
    }

    fn poll_transmit_inner(&mut self, cid: CarrierId, now: Instant, sink: &mut TxSink<'_>) -> bool {
        self.clock = self.clock.max(now);
        let redundancy = self.cfg.redundancy;
        let Some(slot) = self.carriers.get_mut(&cid) else {
            return false;
        };
        if let Some(f) = slot.out.take() {
            sink.emit(f);
            return true;
        }
        if slot.control.is_some() {
            let Some(f) = slot.ctrl_out.pop_front() else {
                return false;
            };
            sink.emit(f);
            return true;
        }
        let Some(sid) = slot.session else {
            return false;
        };
        let Some(s) = self.sessions.get_mut(&sid) else {
            return false;
        };
        if s.redundant.as_ref().is_some_and(|r| r.cid == cid) {
            if !s.connected || s.state == SessionState::Detached {
                return false;
            }
            let acked = s.send.acked();
            let recv_offset = s.recv.recv_offset();
            let max_offset = s.recv.max_offset();
            let Some(r) = s.redundant.as_mut() else {
                return false;
            };
            if r.ack_due {
                r.ack_due = false;
                r.last_acked = (recv_offset, max_offset);
                r.last_activity = now;
                sink.emit(Frame::Ack {
                    recv_offset,
                    max_offset,
                });
                return true;
            }
            r.dup.prune_acked(acked);
            if let Some(offset) = r.fin_due {
                if acked > offset {
                    r.fin_due = None;
                } else if acked == offset {
                    r.fin_due = None;
                    r.last_activity = now;
                    sink.emit(Frame::Fin { offset });
                    return true;
                }
            }
            while let Some((offset, len)) = r.dup.pop_due(now) {
                let sent = match sink {
                    TxSink::Owned(out_frame) => {
                        if let Some(f) = s.send.dup_frame(offset, len) {
                            *out_frame = Some(f);
                            true
                        } else {
                            false
                        }
                    }
                    TxSink::Encoded { out } => s.send.dup_frame_into(out, usize::MAX, offset, len),
                };
                if sent {
                    r.last_activity = now;
                    return true;
                }
            }
            return false;
        }
        if s.carrier != Some(cid) {
            return false;
        }
        if let Some(kind) = s.reply {
            if !s.connected {
                return false;
            }
            s.reply = None;
            s.recv.mark_acked();
            let (recv_offset, max_offset) = s.recv.last_ack();
            sink.emit(match kind {
                ReplyKind::Opened => Frame::Opened(Opened {
                    instance_id: self.instance_id,
                    attach_gen: s.cur_gen,
                    recv_offset,
                    max_offset,
                    window_cap: self.cfg.limits.window_cap as u64,
                    ack_bytes: 0,
                }),
                ReplyKind::Resumed => Frame::Resumed(Resumed {
                    instance_id: self.instance_id,
                    attach_gen: s.cur_gen,
                    recv_offset,
                    max_offset,
                }),
            });
            return true;
        }
        if !s.connected {
            return false;
        }
        let piggyback = s.send.has_sendable();
        if let Some(a) = s.recv.poll_ack(now, piggyback) {
            s.last_sent = now;
            let cur = (s.recv.recv_offset(), s.recv.max_offset());
            if let Some(r) = s.redundant.as_mut().filter(|r| r.demoted_at.is_none()) {
                if cur != r.last_acked {
                    r.ack_due = true;
                }
            }
            sink.emit(a);
            self.check_done(&sid, now);
            return true;
        }
        if s.state == SessionState::Detached {
            return false;
        }
        if s.send.has_sendable() && !s.send.unacked() {
            s.last_progress = now;
        }
        let meta = match sink {
            TxSink::Owned(out_frame) => s.send.poll_frame_meta().map(|(f, meta)| {
                *out_frame = Some(f);
                meta
            }),
            TxSink::Encoded { out } => s.send.poll_frame_into_meta(out, usize::MAX),
        };
        if let Some(meta) = meta {
            s.last_sent = now;
            let acked = s.send.acked();
            let exit_class = s.exit_class;
            if let Some(r) = s.redundant.as_mut().filter(|r| r.demoted_at.is_none()) {
                match meta {
                    SentFrame::Fin(offset) => r.fin_due = Some(offset),
                    SentFrame::Data { offset, len } => {
                        if let Some(delay) = redundancy.dup_delay_for(exit_class) {
                            r.dup.on_primary_data(
                                acked,
                                offset,
                                len,
                                redundancy.max_frame_bytes,
                                delay,
                                now,
                            );
                        }
                    }
                }
            }
            return true;
        }
        // r8 N4: while the client's FIN waits for the site to take the
        // upload, or on an idle AI keepalive, repeat the current ACK.
        if s.ka_due || (s.held_fin.is_some() && now >= s.last_sent + s.keepalive) {
            s.ka_due = false;
            s.last_sent = now;
            sink.emit(s.recv.force_ack());
            return true;
        }
        false
    }

    /// Shed queued Stage 2 duplicates and mirrored control frames when the
    /// redundant carrier's writer queue is busy.
    pub fn drop_redundant_dups_if_busy(&mut self, cid: CarrierId, now: Instant) {
        let Some(sid) = self.carriers.get(&cid).and_then(|c| c.session) else {
            return;
        };
        let Some(s) = self.sessions.get_mut(&sid) else {
            return;
        };
        let acked = s.send.acked();
        let Some(r) = s.redundant.as_mut().filter(|r| r.cid == cid) else {
            return;
        };
        r.dup.drop_due(acked);
        r.ack_due = false;
        r.fin_due = None;
        r.last_activity = now;
    }

    /// How often a session whose upload FIN waits for the site repeats its
    /// ACK: twice per stall bound, the shorter of this relay's `t_stall`
    /// and the client's announced one (`t_stall_ms`), so a client with a
    /// shorter bound than the relay's configuration still sees its carrier
    /// alive. An announced bound below [`MIN_CLIENT_STALL`] is taken as
    /// that floor (a client cannot make the relay send ACKs in a loop).
    fn keepalive_for(&self, client_ms: Option<u64>) -> std::time::Duration {
        let own = self.cfg.timing.t_stall;
        let stall = match client_ms {
            Some(ms) => own.min(std::time::Duration::from_millis(ms).max(MIN_CLIENT_STALL)),
            None => own,
        };
        (stall / 2).max(std::time::Duration::from_millis(10))
    }

    /// The keepalive period of session `sid` (see `keepalive_for`).
    pub fn keepalive(&self, sid: &SessionId) -> Option<std::time::Duration> {
        self.sessions.get(sid).map(|s| s.keepalive)
    }

    /// Bytes of a frame not yet complete arrived on carrier `cid` (the
    /// driver's reader reports it, rate-limited): the client and the path
    /// are alive, only slow. The session repeats its current ACK (no
    /// offset moves; at most once per keepalive period) so the client does
    /// not take a carrier busy with a large frame for a stalled one
    /// (r8 N5). Only bytes that arrived count, never bytes this side wrote:
    /// a black-holed carrier's socket buffer absorbs writes.
    pub fn on_carrier_progress(&mut self, cid: CarrierId, now: Instant) {
        self.clock = self.clock.max(now);
        let Some(sid) = self.carriers.get(&cid).and_then(|c| c.session) else {
            return;
        };
        if let Some(s) = self.sessions.get_mut(&sid) {
            if s.carrier == Some(cid) {
                s.carrier_rx = now;
                if s.state == SessionState::Active && now >= s.last_sent + s.keepalive {
                    s.ka_due = true;
                }
            }
        }
    }

    // ---- site side ----

    /// Bytes of site data the relay may read now.
    ///
    /// A non-AI session returns 0 while DETACHED: stop reading the site
    /// (§5.2). An AI session ([`crate::EXIT_CLASS_AI`]) keeps reading while
    /// detached, into the replay buffer, up to the credit and pool limits
    /// [`crate::flow::SendHalf::write_capacity`] already enforces. No extra
    /// memory and no new floor: a token stream of a few KB/s is consumed
    /// during the outage and sent when a carrier returns; reading stops
    /// when that bound is reached.
    pub fn site_read_capacity(&mut self, sid: &SessionId) -> usize {
        let Some(s) = self.sessions.get_mut(sid) else {
            return 0;
        };
        if !s.connected {
            return 0;
        }
        let ai_detached = s.exit_class == crate::EXIT_CLASS_AI && s.state == SessionState::Detached;
        if s.state == SessionState::Active || ai_detached {
            s.send.write_capacity()
        } else {
            0
        }
    }

    pub fn site_data(&mut self, sid: &SessionId, data: &[u8]) -> usize {
        match self.sessions.get_mut(sid) {
            Some(s) => s.send.write(data),
            None => 0,
        }
    }

    /// Site closed its side: FIN goes into the replay buffer.
    pub fn site_fin(&mut self, sid: &SessionId) {
        if let Some(s) = self.sessions.get_mut(sid) {
            s.send.close();
        }
    }

    /// Site reset: CLOSED immediately, tombstone `site_reset` (§5.2).
    pub fn site_reset(&mut self, sid: &SessionId) {
        if let Some(s) = self.sessions.get_mut(sid) {
            s.rst = Some(code::SITE_RESET);
            self.finish(sid, code::SITE_RESET, true);
        }
    }

    /// Uplink bytes for the site.
    pub fn read(&mut self, sid: &SessionId, out: &mut [u8], now: Instant) -> usize {
        let n = match self.sessions.get_mut(sid) {
            Some(s) => s.recv.read(out, now),
            None => return 0,
        };
        self.check_done(sid, now);
        n
    }

    /// The client's FIN has been reached by `read`.
    pub fn read_eof(&self, sid: &SessionId) -> bool {
        self.sessions.get(sid).is_some_and(|s| {
            s.recv.eof() || (s.held_fin == Some(s.recv.consumed()) && s.recv.buffered() == 0)
        })
    }

    /// The site writer flushed the whole upload and shut the site's write
    /// side down (see [`confirm_site_flush`]): acknowledge the client's FIN.
    ///
    /// [`confirm_site_flush`]: Self::confirm_site_flush
    pub fn site_flushed(&mut self, sid: &SessionId, now: Instant) {
        self.clock = self.clock.max(now);
        let Some(s) = self.sessions.get_mut(sid) else {
            return;
        };
        let Some(f) = s.held_fin.take() else {
            return;
        };
        if let Err(e) = s.recv.on_fin(f, now) {
            self.fail(sid, e);
        }
    }

    /// Revocation / admin: RST every session of `device`.
    pub fn reset_device(&mut self, device: u64, close_code: u8) {
        if let Some(ids) = self.sessions_by_device.remove(&device) {
            for sid in ids {
                if let Some(s) = self.sessions.get_mut(&sid) {
                    s.rst = Some(close_code);
                }
                self.finish(&sid, close_code, true);
            }
        }
        // REVOKED on the device's control streams, then close them (§6).
        if let Some(cids) = self.ctrl_by_device.remove(&device) {
            for cid in cids {
                self.ctrl_carriers.remove(&cid);
                if let Some(slot) = self.carriers.get_mut(&cid) {
                    if slot.control == Some(device) && !slot.close_after {
                        slot.ctrl_out.clear();
                        slot.ctrl_out.push_back(Frame::Control {
                            ty: ty::REVOKED,
                            payload: vec![close_code],
                        });
                        slot.close_after = true;
                        self.to_close.push(cid);
                    }
                }
            }
        }
    }

    // ---- time ----

    pub fn poll_timeout(&self) -> Option<Instant> {
        self.poll_timeout_writable(|_| true)
    }

    /// [`poll_timeout`](Self::poll_timeout) for a driver that can tell
    /// which carriers' writers have room (r9 F3). A deadline that is only
    /// served by sending (a delayed ACK, the held-FIN keepalive) is left
    /// out for a carrier that cannot take a frame now: once due it would
    /// stay in the past and wake the driver in a loop until the writer
    /// drains. The driver waits for the writer instead (it wakes on every
    /// message the writer finishes) and calls this again.
    pub fn poll_timeout_writable(&self, writable: impl Fn(CarrierId) -> bool) -> Option<Instant> {
        let t = &self.cfg.timing;
        let mut d: Option<Instant> = self.tombs_exp.peek().map(|&Reverse((until, _))| until);
        let mut put = |x: Instant| d = Some(d.map_or(x, |d| d.min(x)));
        for s in self.sessions.values() {
            put(s.created + t.max_lifetime);
            if let Some(ds) = s.detached_since {
                put(ds + t.detach_for(s.exit_class));
            }
            let live = t.live_for(s.exit_class);
            let ka_ai = t.keepalive_ai_for(s.exit_class);
            if let Some(r) = &s.redundant {
                if let Some(at) = r.demoted_at {
                    put(at + t.t_detached_standby);
                    if s.connected
                        && s.state == SessionState::Active
                        && writable(r.cid)
                        && !r.ack_due
                    {
                        if let Some(p) = r.next_probe {
                            put(p);
                        }
                    }
                }
                if s.state == SessionState::Active {
                    if r.demoted_at.is_none() && r.progressed_at.is_some_and(|rx| rx > s.carrier_rx)
                    {
                        put(s.carrier_rx + live);
                    }
                    if s.connected && writable(r.cid) {
                        if let Some(due) = r.dup.next_due_unacked(s.send.acked()) {
                            put(due);
                        }
                        if r.demoted_at.is_none() && !r.ack_due {
                            if let Some(ka) = ka_ai {
                                put(r.last_activity + ka);
                            }
                        }
                    }
                }
            }
            if s.state == SessionState::Active && s.send.unacked() {
                put(s.last_progress + live);
            }
            let sendable = s.connected && s.carrier.is_some_and(&writable);
            // The keepalive goes out only where `poll_transmit` sends it:
            // never while DETACHED (r9 F3: the deadline stayed in the past
            // and the driver spun until T_detached).
            if s.held_fin.is_some() && sendable && s.state == SessionState::Active {
                put(s.last_sent + s.keepalive);
            }
            if sendable && s.state == SessionState::Active && !s.ka_due {
                if let Some(ka) = ka_ai {
                    put(s.last_sent.max(s.carrier_rx) + ka);
                }
            }
            // ACKs go out only once connected (`poll_transmit` holds them
            // back before), so an earlier deadline could never be served.
            if sendable {
                if let Some(a) = s.recv.ack_deadline() {
                    put(a);
                }
            }
            if let Some(i) = s.recv.idle_deadline() {
                put(i);
            }
        }
        for cid in &self.ctrl_carriers {
            if let Some(c) = self.carriers.get(cid).filter(|c| !c.close_after) {
                if let (Some(since), Some(seen)) = (c.ctrl_since, c.ctrl_seen) {
                    put((seen + t.t_ctrl_idle).min(since + t.max_lifetime));
                }
            }
        }
        d
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.clock = self.clock.max(now);
        let t = self.cfg.timing.clone();
        while let Some(&Reverse((until, sid))) = self.tombs_exp.peek() {
            if until > now {
                break;
            }
            self.tombs_exp.pop();
            if self.tombs.get(&sid).is_some_and(|x| x.until <= now) {
                self.tombs.remove(&sid);
            }
        }
        let ctrl_done: Vec<CarrierId> = self
            .ctrl_carriers
            .iter()
            .copied()
            .filter(|cid| {
                self.carriers.get(cid).is_some_and(|c| {
                    !c.close_after
                        && match (c.ctrl_since, c.ctrl_seen) {
                            (Some(since), Some(seen)) => {
                                now >= seen + t.t_ctrl_idle || now >= since + t.max_lifetime
                            }
                            _ => false,
                        }
                })
            })
            .collect();
        for cid in ctrl_done {
            self.close_carrier_now(cid);
        }
        let mut expired = Vec::new();
        let mut too_old = Vec::new();
        let mut stalled: Vec<(u64, SessionId, u32)> = Vec::new();
        let mut live = 0u64;
        // `t_live` with a spare bound promotes that spare instead of going
        // DETACHED. Collected here: promoting needs `&mut self`.
        let mut promote_on_live: Vec<SessionId> = Vec::new();
        let mut promote_on_rx: Vec<SessionId> = Vec::new();
        let mut standby: Vec<(SessionId, CarrierId)> = Vec::new();
        for (sid, s) in self.sessions.iter_mut() {
            if now >= s.created + t.max_lifetime {
                s.rst = Some(code::MAX_LIFETIME);
                too_old.push(*sid);
                continue;
            }
            if s.detached_since
                .is_some_and(|ds| now >= ds + t.detach_for(s.exit_class))
            {
                expired.push(*sid);
                continue;
            }
            let live_bound = t.live_for(s.exit_class);
            if s.state == SessionState::Active
                && s.send.unacked()
                && now >= s.last_progress + live_bound
            {
                live += 1;
                if s.redundant.is_some() {
                    promote_on_live.push(*sid);
                    continue;
                }
                s.state = SessionState::Detached;
                s.detached_since = Some(now);
                self.events.push_back(RelayEvent::Stall {
                    device: s.device,
                    session_id: *sid,
                    attach_gen: s.cur_gen,
                });
                stalled.push((s.device, *sid, s.cur_gen));
            } else if s.state == SessionState::Active
                && now >= s.carrier_rx + live_bound
                && s.redundant.as_ref().is_some_and(|r| {
                    r.demoted_at.is_none() && r.progressed_at.is_some_and(|rx| rx > s.carrier_rx)
                })
            {
                promote_on_rx.push(*sid);
            }
            if s.connected && s.state == SessionState::Active {
                let ka = t.keepalive_ai_for(s.exit_class);
                if let Some(ka) = ka {
                    if now >= s.last_sent.max(s.carrier_rx) + ka {
                        s.ka_due = true;
                    }
                }
                if let Some(r) = s.redundant.as_mut() {
                    if r.demoted_at.is_some() {
                        if r.next_probe.is_some_and(|p| now >= p) {
                            r.ack_due = true;
                            r.next_probe = t.demoted_probe_interval().map(|d| now + d);
                        }
                    } else if let Some(ka) = ka {
                        if now >= r.last_activity + ka {
                            r.ack_due = true;
                        }
                    }
                }
            }
            if s.recv.idle_deadline().is_some_and(|d| now >= d) {
                s.recv.update_credit(now);
            }
            if let Some(r) = s.redundant.as_ref() {
                if let Some(at) = r.demoted_at {
                    if now >= at + t.t_detached_standby {
                        standby.push((*sid, r.cid));
                    }
                }
            }
        }
        for sid in promote_on_live {
            if self.promote_bound_spare(&sid, now, true) {
                // The client promotes on this hint if it has not already.
                // The spare is current here either way; no RESUME follows.
                if let Some(s) = self.sessions.get(&sid) {
                    self.events.push_back(RelayEvent::Stall {
                        device: s.device,
                        session_id: sid,
                        attach_gen: s.cur_gen,
                    });
                    stalled.push((s.device, sid, s.cur_gen));
                }
            } else if let Some(s) = self.sessions.get_mut(&sid) {
                if s.state == SessionState::Active
                    && s.send.unacked()
                    && now >= s.last_progress + t.live_for(s.exit_class)
                {
                    s.state = SessionState::Detached;
                    s.detached_since = Some(now);
                    self.events.push_back(RelayEvent::Stall {
                        device: s.device,
                        session_id: sid,
                        attach_gen: s.cur_gen,
                    });
                    stalled.push((s.device, sid, s.cur_gen));
                }
                if let Some(r) = s.redundant.as_ref() {
                    if r.demoted_at
                        .is_some_and(|at| now >= at + t.t_detached_standby)
                    {
                        standby.push((sid, r.cid));
                    }
                }
            }
        }
        for sid in promote_on_rx {
            let _ = self.promote_bound_spare(&sid, now, true);
        }
        // A demoted carrier with no frame in `t_detached_standby` is dropped.
        for (sid, cid) in standby {
            self.drop_spare(sid, cid);
        }
        self.moves.t_live = self.moves.t_live.saturating_add(live);
        stalled.sort_unstable_by_key(|x| x.0);
        for group in stalled.chunk_by(|a, b| a.0 == b.0) {
            let entries: Vec<_> = group.iter().map(|&(_, sid, g)| (sid, g)).collect();
            self.send_stall(group[0].0, &entries);
        }
        for sid in expired {
            self.finish(&sid, code::IDLE, false);
        }
        for sid in too_old {
            self.finish(&sid, code::MAX_LIFETIME, true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Kind, Open, RedundantAttach, VERSION};
    use crate::{RedundancyMode, Timing};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    struct DeviceAuth(u64);
    impl Authorizer for DeviceAuth {
        fn open(&self, _ticket: &[u8], _target: &Target, _kind: Kind) -> Result<Grant, u8> {
            Ok(Grant {
                device: self.0,
                exit_classes: 1,
                ai_anchor_node_id: 0,
            })
        }
        fn resume(&self, _ticket: &[u8]) -> Result<u64, u8> {
            Ok(self.0)
        }
    }

    fn make_open(sid: SessionId, gen: u32) -> Frame {
        Frame::Open(Open {
            version: VERSION,
            ticket: b"t".to_vec(),
            session_id: sid,
            resume_secret: [0x22; 32],
            attach_gen: gen,
            retry: false,
            anchor_instance_id: 0,
            kind: Kind::Tcp,
            target: Target::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                443,
            )),
            exit_class: 0,
            t_stall_ms: None,
            first_data: Vec::new(),
        })
    }

    #[test]
    fn poll_transmit_into_matches_poll_transmit_bytes() {
        let mut cfg = Config::default();
        cfg.redundancy.mode = RedundancyMode::Dup {
            delay: Duration::from_millis(1),
        };
        cfg.redundancy.ai_only = false;
        let t0 = Instant::now();

        let make = || {
            let mut t =
                RelayTable::new(cfg.clone(), Pool::new(1 << 20), Box::new(DeviceAuth(7)), 99);
            let sid = [0x11; 16];
            t.add_carrier(1);
            t.on_frame(1, make_open(sid, 1), t0);
            t.connect_done(&sid, Ok(()), t0);
            t.add_carrier(2);
            t.on_frame(
                2,
                Frame::RedundantAttach(RedundantAttach {
                    session_id: sid,
                    resume_secret: [0x22; 32],
                    attach_gen: 1,
                    recv_offset: 0,
                    max_offset: 16_384,
                }),
                t0,
            );
            t.site_data(&sid, b"hello downlink payload");
            t.add_carrier(3);
            t.on_frame(
                3,
                CtrlHello {
                    version: VERSION,
                    ticket: b"t".to_vec(),
                    held_anchors: Vec::new(),
                }
                .to_frame(),
                t0,
            );
            t
        };

        let mut a = make();
        let mut b = make();
        let t1 = t0 + Duration::from_millis(5);
        for cid in [3, 1, 1, 2, 2] {
            let expected = a.poll_transmit(cid, t1).map(|f| f.to_bytes());
            let mut got = Vec::new();
            let wrote = b.poll_transmit_into(cid, t1, &mut got);
            assert_eq!(wrote.is_some(), expected.is_some(), "cid {cid}");
            if let Some(exp) = expected {
                assert_eq!(got, exp, "cid {cid}");
                assert_eq!(wrote, Some(exp.len()));
            }
        }
    }

    #[test]
    fn device_ctrl_and_tomb_indices_stay_consistent() {
        let mut cfg = Config {
            timing: Timing {
                t_tomb: Duration::from_secs(5),
                t_ctrl_idle: Duration::from_secs(2),
                ..Timing::default()
            },
            ..Config::default()
        };
        cfg.timing.max_lifetime = Duration::from_secs(60);
        let mut table = RelayTable::new(cfg, Pool::new(1 << 20), Box::new(DeviceAuth(42)), 1);
        let t0 = Instant::now();

        let sid1 = [1u8; 16];
        let sid2 = [2u8; 16];
        table.add_carrier(10);
        table.on_frame(10, make_open(sid1, 1), t0);
        table.add_carrier(11);
        table.on_frame(11, make_open(sid2, 1), t0);
        table.add_carrier(20);
        table.on_frame(
            20,
            CtrlHello {
                version: VERSION,
                ticket: b"t".to_vec(),
                held_anchors: Vec::new(),
            }
            .to_frame(),
            t0,
        );
        assert_eq!(table.sessions_by_device.get(&42).map(HashSet::len), Some(2));
        assert_eq!(table.ctrl_by_device.get(&42).map(Vec::len), Some(1));
        assert!(table.ctrl_carriers.contains(&20));

        table.send_stall(42, &[(sid1, 1)]);
        assert_eq!(table.move_stats().stall_hints, 1);

        // Revoking device closes sessions and control streams and records tombs.
        table.reset_device(42, code::REVOKED);
        assert!(table.sessions.is_empty());
        assert!(table.sessions_by_device.is_empty());
        assert!(table.ctrl_by_device.is_empty());
        assert!(table.ctrl_carriers.is_empty());
        assert_eq!(table.tombs.len(), 2);
        assert_eq!(table.tombs_exp.len(), 2);

        // Poll timeout sees earliest tombstone deadline; handle_timeout evicts expired tombs.
        let due = table.poll_timeout().unwrap();
        assert_eq!(due, t0 + Duration::from_secs(5));
        table.handle_timeout(t0 + Duration::from_secs(4));
        assert_eq!(table.tombs.len(), 2);
        table.handle_timeout(t0 + Duration::from_secs(5));
        assert!(table.tombs.is_empty());
        assert!(table.tombs_exp.is_empty());
    }
}
