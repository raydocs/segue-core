//! Relay-side session table (§5.2, §5.3, §5.5).
//!
//! Sans-IO like the client. Carriers are named by a caller-chosen
//! [`CarrierId`]; the first frame on a carrier must be OPEN or RESUME. The
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

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::codec::{
    code, ty, ClosedInfo, CtrlHello, CtrlHelloReply, Frame, Kind, Opened, Reject, Resumed, Secret,
    SessionId, Target,
};
use crate::flow::{RecvHalf, SendHalf};
use crate::pool::Pool;
use crate::{ct_eq, Config, ProtoError};

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

struct Session {
    device: u64,
    secret: Secret,
    cur_gen: u32,
    carrier: Option<CarrierId>,
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
}

// Manual so the resume secret never reaches a log.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("device", &self.device)
            .field("cur_gen", &self.cur_gen)
            .field("carrier", &self.carrier)
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

/// The shortest client stall bound the relay serves keepalives for.
pub const MIN_CLIENT_STALL: std::time::Duration = std::time::Duration::from_millis(100);

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

pub struct RelayTable {
    cfg: Config,
    pool: Arc<Pool>,
    auth: Box<dyn Authorizer>,
    instance_id: u64,
    sessions: HashMap<SessionId, Session>,
    tombs: HashMap<SessionId, Tomb>,
    carriers: HashMap<CarrierId, CarrierSlot>,
    events: VecDeque<RelayEvent>,
    to_close: Vec<CarrierId>,
    /// Latest `now` seen; used for tombstone expiry.
    clock: Instant,
    /// See [`RelayTable::confirm_site_flush`].
    hold_fin: bool,
}

impl RelayTable {
    pub fn new(cfg: Config, pool: Arc<Pool>, auth: Box<dyn Authorizer>, instance_id: u64) -> Self {
        Self {
            cfg,
            pool,
            auth,
            instance_id,
            sessions: HashMap::new(),
            tombs: HashMap::new(),
            carriers: HashMap::new(),
            events: VecDeque::new(),
            to_close: Vec::new(),
            clock: Instant::now(),
            hold_fin: false,
        }
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
        if let Some(slot) = self.carriers.remove(&cid) {
            if let Some(sid) = slot.session {
                if let Some(s) = self.sessions.get_mut(&sid) {
                    if s.carrier == Some(cid) {
                        s.carrier = None;
                        s.detached_since.get_or_insert(now);
                        if s.state == SessionState::Active {
                            s.state = SessionState::Detached;
                        }
                    }
                }
            }
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
        if let Some(slot) = self.carriers.get_mut(&cid) {
            slot.session = None;
            slot.close_after = true;
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
                let is_current = self
                    .sessions
                    .get(&sid)
                    .is_some_and(|s| s.carrier == Some(cid));
                if !is_current {
                    return;
                }
                if let Err(e) = self.on_session_frame(&sid, frame, now) {
                    self.fail(&sid, e);
                }
                self.check_done(&sid, now);
            }
        }
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
            .carriers
            .iter()
            .filter(|(c, x)| **c != cid && x.control == Some(device) && !x.close_after)
            .map(|(c, x)| {
                let since = x.ctrl_since.unwrap_or(now);
                (x.ctrl_seen.unwrap_or(since), since, *c)
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
    }

    /// Queue `STALL` entries on every control stream of `device`.
    fn send_stall(&mut self, device: u64, entries: &[(SessionId, u32)]) {
        for slot in self.carriers.values_mut() {
            if slot.control != Some(device) || slot.close_after {
                continue;
            }
            for batch in entries.chunks(STALL_BATCH) {
                if slot.ctrl_out.len() < CTRL_QUEUE {
                    slot.ctrl_out.push_back(Frame::Stall(batch.to_vec()));
                }
            }
        }
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
                let Some(mut recv) =
                    RecvHalf::new(&self.pool, &self.cfg.limits, &self.cfg.timing, now)
                else {
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
                };
                self.sessions.insert(sid, s);
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
            _ => self.close_carrier_now(cid),
        }
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
        if let Err(e) = s.send.rewind(peer_recv, peer_max) {
            // The new carrier is not bound yet: answer it here, the caller
            // fails the session (and its current carrier).
            self.reject(cid, code::PROTOCOL, gen, None);
            return Err(e);
        }
        let old = s.carrier.replace(cid);
        s.cur_gen = gen;
        s.reply = Some(reply);
        s.detached_since = None;
        s.last_progress = now;
        if s.state == SessionState::Detached {
            s.state = SessionState::Active;
        }
        self.carriers.get_mut(&cid).unwrap().session = Some(*sid);
        if let Some(old) = old {
            if old != cid {
                self.close_carrier_now(old);
            }
        }
        Ok(())
    }

    fn on_session_frame(
        &mut self,
        sid: &SessionId,
        frame: Frame,
        now: Instant,
    ) -> Result<(), ProtoError> {
        let hold = self.hold_fin;
        let s = self.sessions.get_mut(sid).unwrap();
        match frame {
            Frame::Data { offset, data, .. } => {
                if s.held_fin.is_some_and(|f| offset + data.len() as u64 > f) {
                    return Err(ProtoError::Violation("data after fin"));
                }
                s.recv.on_data(offset, &data, now)?;
            }
            Frame::Fin { offset } if hold && !s.recv.fin_received() => match s.held_fin {
                Some(f) if f == offset => {}
                Some(_) => return Err(ProtoError::Violation("fin moved")),
                None if offset != s.recv.recv_offset() => {
                    return Err(ProtoError::Violation("fin not at recv_offset"))
                }
                None => s.held_fin = Some(offset),
            },
            Frame::Fin { offset } => s.recv.on_fin(offset, now)?,
            Frame::Ack {
                recv_offset,
                max_offset,
            } => {
                let progressed = s.send.on_ack(recv_offset, max_offset)?;
                if s.state == SessionState::Active {
                    // Any ACK on the current carrier shows the client is
                    // taking what this side sends, if slowly: a client
                    // receiving a large frame piecemeal repeats its ACK
                    // (r8 N5), which keeps `t_live` from firing.
                    s.last_progress = now;
                }
                if progressed {
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
        Ok(())
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
        let info = ClosedInfo {
            close_code,
            final_recv_offset: s.recv.recv_offset(),
            final_sent_offset: s.send.sent_hw(),
        };
        self.tombs.insert(
            *sid,
            Tomb {
                info,
                until: self.clock + self.cfg.timing.t_tomb,
            },
        );
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
        self.clock = self.clock.max(now);
        let slot = self.carriers.get_mut(&cid)?;
        if let Some(f) = slot.out.take() {
            return Some(f);
        }
        if slot.control.is_some() {
            return slot.ctrl_out.pop_front();
        }
        let sid = slot.session?;
        let s = self.sessions.get_mut(&sid)?;
        if s.carrier != Some(cid) {
            return None;
        }
        if let Some(kind) = s.reply {
            if !s.connected {
                return None;
            }
            s.reply = None;
            s.recv.mark_acked();
            let (recv_offset, max_offset) = s.recv.last_ack();
            return Some(match kind {
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
        }
        if !s.connected {
            return None;
        }
        let piggyback = s.send.has_sendable();
        if let Some(a) = s.recv.poll_ack(now, piggyback) {
            s.last_sent = now;
            self.check_done(&sid, now);
            return Some(a);
        }
        if s.state == SessionState::Detached {
            return None;
        }
        if s.send.has_sendable() && !s.send.unacked() {
            s.last_progress = now;
        }
        if let Some(f) = s.send.poll_frame() {
            s.last_sent = now;
            return Some(f);
        }
        // r8 N4: while the client's FIN waits for the site to take the
        // upload, nothing else may go out for a long time, and the client
        // would take the quiet carrier (its FIN unacknowledged) for a
        // stalled one. Repeat the current ACK (it moves no offset, so the
        // FIN stays unacknowledged) to show the carrier is alive.
        if s.ka_due || (s.held_fin.is_some() && now >= s.last_sent + s.keepalive) {
            s.ka_due = false;
            s.last_sent = now;
            return Some(s.recv.force_ack());
        }
        None
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

    /// The keepalive period of session `sid` (see [`Self::keepalive_for`]).
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
            if s.carrier == Some(cid)
                && s.state == SessionState::Active
                && now >= s.last_sent + s.keepalive
            {
                s.ka_due = true;
            }
        }
    }

    // ---- site side ----

    /// Bytes of site data the relay may read now (0 while DETACHED: stop
    /// reading the site, §5.2).
    pub fn site_read_capacity(&mut self, sid: &SessionId) -> usize {
        match self.sessions.get_mut(sid) {
            Some(s) if s.connected && s.state == SessionState::Active => s.send.write_capacity(),
            _ => 0,
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
        let ids: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.device == device)
            .map(|(k, _)| *k)
            .collect();
        for sid in ids {
            if let Some(s) = self.sessions.get_mut(&sid) {
                s.rst = Some(close_code);
            }
            self.finish(&sid, close_code, true);
        }
        // REVOKED on the device's control streams, then close them (§6).
        for (&cid, slot) in self.carriers.iter_mut() {
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
        let mut d: Option<Instant> = self.tombs.values().map(|x| x.until).min();
        let mut put = |x: Instant| d = Some(d.map_or(x, |d| d.min(x)));
        for s in self.sessions.values() {
            put(s.created + t.max_lifetime);
            if let Some(ds) = s.detached_since {
                put(ds + t.t_detached);
            }
            if s.state == SessionState::Active && s.send.unacked() {
                put(s.last_progress + t.t_live);
            }
            let sendable = s.connected && s.carrier.is_some_and(&writable);
            // The keepalive goes out only where `poll_transmit` sends it:
            // never while DETACHED (r9 F3: the deadline stayed in the past
            // and the driver spun until T_detached).
            if s.held_fin.is_some() && sendable && s.state == SessionState::Active {
                put(s.last_sent + s.keepalive);
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
        for c in self.carriers.values().filter(|c| !c.close_after) {
            if let (Some(since), Some(seen)) = (c.ctrl_since, c.ctrl_seen) {
                put((seen + t.t_ctrl_idle).min(since + t.max_lifetime));
            }
        }
        d
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.clock = self.clock.max(now);
        let t = self.cfg.timing.clone();
        self.tombs.retain(|_, x| x.until > now);
        let ctrl_done: Vec<CarrierId> = self
            .carriers
            .iter()
            .filter(|(_, c)| !c.close_after)
            .filter(|(_, c)| match (c.ctrl_since, c.ctrl_seen) {
                (Some(since), Some(seen)) => {
                    now >= seen + t.t_ctrl_idle || now >= since + t.max_lifetime
                }
                _ => false,
            })
            .map(|(id, _)| *id)
            .collect();
        for cid in ctrl_done {
            self.close_carrier_now(cid);
        }
        let mut expired = Vec::new();
        let mut too_old = Vec::new();
        let mut stalled: Vec<(u64, SessionId, u32)> = Vec::new();
        for (sid, s) in self.sessions.iter_mut() {
            if now >= s.created + t.max_lifetime {
                s.rst = Some(code::MAX_LIFETIME);
                too_old.push(*sid);
                continue;
            }
            if s.detached_since.is_some_and(|ds| now >= ds + t.t_detached) {
                expired.push(*sid);
                continue;
            }
            if s.state == SessionState::Active
                && s.send.unacked()
                && now >= s.last_progress + t.t_live
            {
                s.state = SessionState::Detached;
                s.detached_since = Some(now);
                self.events.push_back(RelayEvent::Stall {
                    device: s.device,
                    session_id: *sid,
                    attach_gen: s.cur_gen,
                });
                stalled.push((s.device, *sid, s.cur_gen));
            }
            if s.recv.idle_deadline().is_some_and(|d| now >= d) {
                s.recv.update_credit(now);
            }
        }
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
