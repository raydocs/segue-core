//! Relay-side session table (§5.2, §5.3, §5.5).
//!
//! Sans-IO like the client. Carriers are named by a caller-chosen
//! [`CarrierId`]; the first frame on a carrier must be OPEN or RESUME. The
//! table asks the caller to connect to a site with
//! [`RelayEvent::Connect`] exactly once per session (A2): the session entry
//! exists before the connect starts, so an OPEN retry or a duplicate OPEN
//! that arrives while connecting finds it.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use crate::codec::{
    code, ClosedInfo, Frame, Kind, Opened, Reject, Resumed, Secret, SessionId, Target,
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
}

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
        }
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

    fn on_first(&mut self, cid: CarrierId, frame: Frame, now: Instant) {
        match frame {
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
                    send: SendHalf::new(&self.pool, &self.cfg.limits),
                    recv,
                    rst: None,
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
        let s = self.sessions.get_mut(sid).unwrap();
        match frame {
            Frame::Data { offset, data, .. } => {
                s.recv.on_data(offset, &data, now)?;
            }
            Frame::Fin { offset } => s.recv.on_fin(offset, now)?,
            Frame::Ack {
                recv_offset,
                max_offset,
            } => {
                if s.send.on_ack(recv_offset, max_offset)? {
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
            self.check_done(&sid, now);
            return Some(a);
        }
        if s.state == SessionState::Detached {
            return None;
        }
        if s.send.has_sendable() && !s.send.unacked() {
            s.last_progress = now;
        }
        s.send.poll_frame()
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
        self.sessions.get(sid).is_some_and(|s| s.recv.eof())
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
    }

    // ---- time ----

    pub fn poll_timeout(&self) -> Option<Instant> {
        let t = &self.cfg.timing;
        let mut d: Option<Instant> = self.tombs.values().map(|x| x.until).min();
        let mut put = |x: Instant| d = Some(d.map_or(x, |d| d.min(x)));
        for s in self.sessions.values() {
            if let Some(ds) = s.detached_since {
                put(ds + t.t_detached);
            }
            if s.state == SessionState::Active && s.send.unacked() {
                put(s.last_progress + t.t_live);
            }
            if s.carrier.is_some() {
                if let Some(a) = s.recv.ack_deadline() {
                    put(a);
                }
            }
            if let Some(i) = s.recv.idle_deadline() {
                put(i);
            }
        }
        d
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.clock = self.clock.max(now);
        let t = self.cfg.timing.clone();
        self.tombs.retain(|_, x| x.until > now);
        let mut expired = Vec::new();
        for (sid, s) in self.sessions.iter_mut() {
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
            }
            if s.recv.idle_deadline().is_some_and(|d| now >= d) {
                s.recv.update_credit(now);
            }
        }
        for sid in expired {
            self.finish(&sid, code::IDLE, false);
        }
    }
}
