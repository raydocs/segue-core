//! Client session state machine (§5.1, §5.3).
//!
//! Sans-IO: the caller owns the carriers (byte streams) and hands frames in
//! with [`ClientSession::on_frame`], pulls frames out with
//! [`ClientSession::poll_transmit`], and drives time with
//! [`ClientSession::handle_timeout`]. Each carrier is named by a
//! caller-chosen [`CarrierId`].
//!
//! Generations (A1): at most one attach is in flight. Calling
//! [`ClientSession::attach`] with a new carrier supersedes the previous one;
//! the previous carrier is frozen (no DATA, no ACK) and every non-DATA event
//! from it is ignored. DATA from it is still deduplicated by offset.

use std::sync::Arc;
use std::time::Instant;

use rand::RngCore;

use crate::codec::{
    code, Frame, Kind, Open, Reject, Resume, Secret, SessionId, Target, MAX_PAYLOAD, VERSION,
};
use crate::flow::{RecvHalf, SendHalf};
use crate::park::{ParkDecision, ParkTracker};
use crate::pool::Pool;
use crate::{Config, ProtoError};

pub type CarrierId = u64;

/// What the client asks the relay to open.
#[derive(Clone)]
pub struct OpenParams {
    pub ticket: Vec<u8>,
    pub kind: Kind,
    pub target: Target,
    pub exit_class: u8,
    /// Node the session is anchored on (catalog id; 0 = unknown).
    pub anchor_node_id: u64,
    /// Relay instance from the carrier's CTRL_HELLO; used for OPEN retries
    /// before OPENED tells us the real one (§5.3). 0 = unknown.
    pub instance_hint: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// OPEN sent (or about to be), OPENED not yet received.
    Opening,
    Active,
    /// RESUME sent (or a new carrier is awaited).
    Attaching,
    Closed(CloseReason),
}

/// How the local connection must end (§8 local mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// Both directions finished: local FIN.
    Clean,
    /// Local RST with the protocol code that caused it.
    Reset(u8),
    /// The flow is refused (e.g. `capacity`): never sent anywhere else.
    Refused(u8),
}

impl CloseReason {
    fn from_reject(r: &Reject, fin_sent: Option<u64>, peer_fin: bool) -> Self {
        match r.code {
            code::CAPACITY | code::HOME_UNAVAILABLE => CloseReason::Refused(r.code),
            code::CLOSED => match r.closed {
                // B6: the relay finished cleanly, our FIN reached it and we
                // already hold its FIN: the only thing lost was an ACK.
                Some(c)
                    if c.close_code == code::CLEAN
                        && fin_sent.is_some_and(|f| c.final_recv_offset == f + 1)
                        && peer_fin =>
                {
                    CloseReason::Clean
                }
                Some(c) if c.close_code != code::CLEAN => CloseReason::Reset(c.close_code),
                _ => CloseReason::Reset(code::CLOSED),
            },
            other => CloseReason::Reset(other),
        }
    }
}

impl std::fmt::Debug for OpenParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenParams")
            .field("ticket", &"<redacted>")
            .field("kind", &self.kind)
            .field("target", &self.target)
            .field("exit_class", &self.exit_class)
            .field("anchor_node_id", &self.anchor_node_id)
            .field("instance_hint", &self.instance_hint)
            .finish()
    }
}

/// Local code used when the client gives up re-attaching / retrying OPEN.
pub const LOCAL_GIVE_UP: u8 = code::CONNECT_TIMEOUT;

/// Result of [`ClientSession::poll_transmit_into`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tx {
    /// Nothing to send now.
    Idle,
    /// One frame was appended.
    Wrote,
    /// The next frame (OPEN/RESUME) needs this many bytes of room.
    NeedRoom(usize),
}

enum TxNext {
    Hello,
    Frame(Frame),
    Send,
}

pub struct ClientSession {
    cfg: Config,
    session_id: SessionId,
    secret: Secret,
    params: OpenParams,
    state: State,
    gen: u32,
    attached_once: bool,
    ever_opened: bool,
    instance_id: u64,
    carrier: Option<CarrierId>,
    /// The current carrier's OPEN/RESUME has been answered.
    confirmed: bool,
    hello: Option<Frame>,
    rst: Option<u8>,
    need_attach: bool,
    abandoned: Vec<CarrierId>,
    first_len: usize,
    /// `first_data` of the pending OPEN: `[0, hello_first)` of the replay
    /// buffer, attached when the OPEN is encoded (no copy held meanwhile).
    hello_first: usize,
    open_started: Option<Instant>,
    attach_started: Option<Instant>,
    detached_since: Option<Instant>,
    backoff_until: Option<Instant>,
    backoff: std::time::Duration,
    last_rx: Instant,
    send: SendHalf,
    recv: RecvHalf,
    park: ParkTracker,
}

// Manual so the resume secret and ticket never reach a log.
impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession")
            .field("session_id", &self.session_id)
            .field("params", &self.params)
            .field("state", &self.state)
            .field("gen", &self.gen)
            .field("instance_id", &self.instance_id)
            .field("carrier", &self.carrier)
            .field("confirmed", &self.confirmed)
            .field("rst", &self.rst)
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// `None` when the pool cannot give the initial credit: the local flow
    /// is refused (§4 rule 8).
    pub fn new(cfg: Config, pool: &Arc<Pool>, params: OpenParams, now: Instant) -> Option<Self> {
        let mut rng = rand::thread_rng();
        let mut session_id = [0u8; 16];
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut session_id);
        rng.fill_bytes(&mut secret);
        Self::with_ids(cfg, pool, params, session_id, secret, now)
    }

    pub fn with_ids(
        cfg: Config,
        pool: &Arc<Pool>,
        params: OpenParams,
        session_id: SessionId,
        secret: Secret,
        now: Instant,
    ) -> Option<Self> {
        let recv = RecvHalf::new(pool, &cfg.limits, &cfg.timing, now)?;
        let send = SendHalf::new(pool, &cfg.limits)?;
        Some(Self {
            backoff: std::time::Duration::from_millis(200),
            cfg,
            session_id,
            secret,
            params,
            state: State::Opening,
            gen: 0,
            attached_once: false,
            ever_opened: false,
            instance_id: 0,
            carrier: None,
            confirmed: false,
            hello: None,
            rst: None,
            need_attach: true,
            abandoned: Vec::new(),
            first_len: 0,
            hello_first: 0,
            open_started: None,
            attach_started: None,
            detached_since: None,
            backoff_until: None,
            last_rx: now,
            send,
            recv,
            park: ParkTracker::default(),
        })
    }

    /// The pool this session's buffers are charged to.
    pub fn pool(&self) -> &Arc<Pool> {
        self.recv.pool()
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn gen(&self) -> u32 {
        self.gen
    }
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }
    pub fn carrier(&self) -> Option<CarrierId> {
        self.carrier
    }
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed(_))
    }
    pub fn close_reason(&self) -> Option<CloseReason> {
        match self.state {
            State::Closed(r) => Some(r),
            _ => None,
        }
    }
    pub fn send_half(&self) -> &SendHalf {
        &self.send
    }
    pub fn recv_half(&self) -> &RecvHalf {
        &self.recv
    }

    /// The caller should open a new carrier and call [`attach`](Self::attach).
    pub fn wants_attach(&self, now: Instant) -> bool {
        self.need_attach && !self.is_closed() && self.backoff_until.is_none_or(|t| now >= t)
    }

    /// Carriers the caller should close (superseded or timed out).
    pub fn take_abandoned(&mut self) -> Vec<CarrierId> {
        std::mem::take(&mut self.abandoned)
    }

    /// Whether `cid` is still the session's live carrier. Once false the
    /// caller flushes what [`poll_transmit`](Self::poll_transmit) returned
    /// and closes it.
    pub fn carrier_live(&self, cid: CarrierId) -> bool {
        self.carrier == Some(cid) && !self.is_closed()
    }

    /// Bind a new carrier and queue OPEN / OPEN retry / RESUME on it.
    pub fn attach(&mut self, cid: CarrierId, now: Instant) {
        if self.is_closed() {
            self.abandoned.push(cid);
            return;
        }
        if let Some(old) = self.carrier.replace(cid) {
            if old != cid {
                self.abandoned.push(old);
            }
        }
        if self.attached_once {
            self.gen += 1;
        }
        self.need_attach = false;
        self.backoff_until = None;
        self.confirmed = false;
        self.rst = None;
        self.attach_started = Some(now);
        self.park.cancel();
        self.last_rx = now;
        let hello = if !self.ever_opened {
            let retry = self.attached_once;
            if !retry {
                self.open_started = Some(now);
                let limit = MAX_PAYLOAD - self.open_header_len();
                self.first_len = self.send.take_first_len(limit);
                self.hello_first = self.first_len;
                self.state = State::Opening;
                Frame::Open(self.open_frame(false, Vec::new()))
            } else {
                self.hello_first = self.send.take_first_len(self.first_len);
                Frame::Open(self.open_frame(true, Vec::new()))
            }
        } else {
            self.state = State::Attaching;
            self.recv.mark_acked();
            Frame::Resume(Resume {
                version: VERSION,
                ticket: self.params.ticket.clone(),
                anchor_node_id: self.params.anchor_node_id,
                anchor_instance_id: self.instance_id,
                session_id: self.session_id,
                resume_secret: self.secret,
                attach_gen: self.gen,
                recv_offset: self.recv.recv_offset(),
                max_offset: self.recv.max_offset(),
            })
        };
        self.attached_once = true;
        self.hello = Some(hello);
    }

    fn open_frame(&self, retry: bool, first_data: Vec<u8>) -> Open {
        Open {
            version: VERSION,
            ticket: self.params.ticket.clone(),
            session_id: self.session_id,
            resume_secret: self.secret,
            attach_gen: self.gen,
            retry,
            anchor_instance_id: if retry { self.params.instance_hint } else { 0 },
            kind: self.params.kind,
            target: self.params.target.clone(),
            exit_class: self.params.exit_class,
            first_data,
        }
    }

    fn open_header_len(&self) -> usize {
        // Worst case: retry with an 8-byte instance varint.
        let mut f = self.open_frame(true, Vec::new());
        f.anchor_instance_id = u64::MAX >> 2;
        let mut v = Vec::new();
        Frame::Open(f).encode(&mut v);
        v.len() - 2
    }

    /// Network change, stall, or a STALL hint: move to a new carrier.
    pub fn reattach(&mut self, now: Instant) {
        if self.is_closed() || self.need_attach {
            return;
        }
        if let Some(old) = self.carrier.take() {
            self.abandoned.push(old);
        }
        self.confirmed = false;
        self.need_attach = true;
        if self.state == State::Active {
            self.state = State::Attaching;
        }
        self.detached_since.get_or_insert(now);
    }

    /// `STALL{session_id, attach_gen}` from the control stream (B1).
    pub fn on_stall(&mut self, gen: u32, now: Instant) {
        if gen == self.gen && self.state == State::Active {
            self.reattach(now);
        }
    }

    pub fn on_carrier_closed(&mut self, cid: CarrierId, now: Instant) {
        if self.carrier != Some(cid) {
            return;
        }
        self.carrier = None;
        if self.is_closed() {
            return;
        }
        self.confirmed = false;
        self.need_attach = true;
        if self.state == State::Active {
            self.state = State::Attaching;
        }
        self.detached_since.get_or_insert(now);
    }

    fn close(&mut self, reason: CloseReason) {
        if !self.is_closed() {
            self.state = State::Closed(reason);
            self.need_attach = false;
            self.hello = None;
        }
    }

    fn fatal(&mut self, e: ProtoError) -> Result<(), ProtoError> {
        self.rst = Some(code::PROTOCOL);
        self.close(CloseReason::Reset(code::PROTOCOL));
        Err(e)
    }

    /// A frame decoded from carrier `cid`. An error means the carrier is
    /// broken; for the current carrier the session is closed as well.
    pub fn on_frame(
        &mut self,
        cid: CarrierId,
        frame: Frame,
        now: Instant,
    ) -> Result<(), ProtoError> {
        if self.carrier != Some(cid) {
            // Superseded carrier: only DATA, deduplicated by offset.
            if let Frame::Data { offset, data, .. } = frame {
                if !self.is_closed() {
                    let _ = self.recv.on_data(offset, &data, now);
                }
            }
            return Ok(());
        }
        if self.is_closed() {
            return Ok(());
        }
        self.last_rx = now;
        let r = self.on_current(frame, now);
        if let Err(e) = r {
            return self.fatal(e);
        }
        self.check_done();
        Ok(())
    }

    /// Bytes on carrier `cid` could not be decoded.
    pub fn on_decode_error(&mut self, cid: CarrierId, e: ProtoError) {
        if self.carrier == Some(cid) && !self.is_closed() {
            let _ = self.fatal(e);
        }
    }

    fn on_current(&mut self, frame: Frame, now: Instant) -> Result<(), ProtoError> {
        match frame {
            Frame::Opened(o) => {
                if o.attach_gen != self.gen {
                    return Ok(());
                }
                if self.state != State::Opening || self.confirmed || self.ever_opened {
                    return Err(ProtoError::Violation("unexpected OPENED"));
                }
                self.send.on_ack(o.recv_offset, o.max_offset)?;
                self.instance_id = o.instance_id;
                self.established();
            }
            Frame::Resumed(r) => {
                if r.attach_gen != self.gen {
                    return Ok(());
                }
                if self.confirmed || !matches!(self.state, State::Opening | State::Attaching) {
                    return Err(ProtoError::Violation("unexpected RESUMED"));
                }
                // R2-2b: an OPEN retry the relay treated as a resume is the
                // same as OPENED; replay from the relay's snapshot.
                self.send.rewind(r.recv_offset, r.max_offset)?;
                self.instance_id = r.instance_id;
                self.established();
            }
            Frame::Reject(rj) => {
                if rj.attach_gen != self.gen {
                    return Ok(());
                }
                match rj.code {
                    code::STALE_GEN => {}
                    code::ANCHOR_UNREACHABLE => {
                        // B2: retry with backoff until T_detached.
                        if let Some(old) = self.carrier.take() {
                            self.abandoned.push(old);
                        }
                        self.confirmed = false;
                        self.need_attach = true;
                        self.backoff_until = Some(now + self.backoff);
                        self.backoff = (self.backoff * 2).min(std::time::Duration::from_secs(5));
                        self.detached_since.get_or_insert(now);
                    }
                    _ => {
                        let reason = CloseReason::from_reject(
                            &rj,
                            self.send.fin_offset(),
                            self.recv.fin_received(),
                        );
                        self.close(reason);
                    }
                }
            }
            Frame::Rst { code } => self.close(CloseReason::Reset(code)),
            Frame::Pad(_) | Frame::Dgram { .. } => {}
            Frame::Data { offset, data, .. } if self.confirmed => {
                self.recv.on_data(offset, &data, now)?;
            }
            Frame::Ack {
                recv_offset,
                max_offset,
            } if self.confirmed => {
                self.send.on_ack(recv_offset, max_offset)?;
            }
            Frame::Fin { offset } if self.confirmed => self.recv.on_fin(offset, now)?,
            _ => return Err(ProtoError::Violation("unexpected frame on session carrier")),
        }
        Ok(())
    }

    fn established(&mut self) {
        self.confirmed = true;
        self.ever_opened = true;
        self.state = State::Active;
        self.attach_started = None;
        self.detached_since = None;
        self.backoff = std::time::Duration::from_millis(200);
    }

    fn check_done(&mut self) {
        if !self.is_closed() && self.send.done() && self.recv.fin_acked() && self.recv.eof() {
            self.close(CloseReason::Clean);
        }
    }

    /// What goes out next on carrier `cid`.
    fn next_tx(&mut self, cid: CarrierId, now: Instant) -> Option<TxNext> {
        if self.carrier != Some(cid) {
            return None;
        }
        if self.hello.is_some() {
            return Some(TxNext::Hello);
        }
        if let Some(code) = self.rst.take() {
            return Some(TxNext::Frame(Frame::Rst { code }));
        }
        if self.is_closed() {
            return None;
        }
        // Before the answer only the first OPEN may carry optimistic DATA.
        let optimistic = self.state == State::Opening && self.gen == 0 && !self.confirmed;
        if !self.confirmed && !optimistic {
            return None;
        }
        if self.confirmed {
            let piggyback = self.send.has_sendable();
            if let Some(ack) = self.recv.poll_ack(now, piggyback) {
                self.check_done();
                return Some(TxNext::Frame(ack));
            }
        }
        Some(TxNext::Send)
    }

    /// Whether [`poll_transmit`](Self::poll_transmit) would return a
    /// frame now (so a driver only takes memory for one when it would).
    pub fn has_transmit(&self, cid: CarrierId, now: Instant) -> bool {
        if self.carrier != Some(cid) {
            return false;
        }
        if self.hello.is_some() || self.rst.is_some() {
            return true;
        }
        if self.is_closed() {
            return false;
        }
        let optimistic = self.state == State::Opening && self.gen == 0 && !self.confirmed;
        if !self.confirmed && !optimistic {
            return false;
        }
        self.send.has_sendable()
            || (self.confirmed && self.recv.ack_deadline().is_some_and(|d| d <= now))
    }

    /// Next frame for carrier `cid`, if any.
    pub fn poll_transmit(&mut self, cid: CarrierId, now: Instant) -> Option<Frame> {
        match self.next_tx(cid, now)? {
            TxNext::Hello => {
                let mut h = self.hello.take().expect("checked");
                if let Frame::Open(o) = &mut h {
                    o.first_data = self.send.first_data(self.hello_first).concat();
                }
                Some(h)
            }
            TxNext::Frame(f) => Some(f),
            TxNext::Send => self.send.poll_frame(),
        }
    }

    /// [`poll_transmit`](Self::poll_transmit) encoded straight into `out`
    /// (reserved exactly, application bytes copied once from the replay
    /// buffer, r6 N13), using at most `room` bytes. DATA is cut to fit;
    /// an OPEN or RESUME that does not fit is kept and its size returned.
    pub fn poll_transmit_into(
        &mut self,
        cid: CarrierId,
        now: Instant,
        out: &mut Vec<u8>,
        room: usize,
    ) -> Tx {
        match self.next_tx(cid, now) {
            None => Tx::Idle,
            Some(TxNext::Hello) => {
                let h = self.hello.as_ref().expect("checked");
                let tail = match h {
                    Frame::Open(_) => self.send.first_data(self.hello_first),
                    _ => [&[][..], &[][..]],
                };
                // The header alone is small; its exact size bounds the
                // frame (the length varint grows by at most two bytes).
                let mut hdr = Vec::new();
                h.encode(&mut hdr);
                let need = hdr.len() + 2 + tail[0].len() + tail[1].len();
                if need > room {
                    return Tx::NeedRoom(need);
                }
                out.reserve_exact(need);
                h.encode_with(out, tail);
                self.hello = None;
                Tx::Wrote
            }
            Some(TxNext::Frame(f)) => {
                out.reserve_exact(f.size_hint());
                f.encode(out);
                Tx::Wrote
            }
            Some(TxNext::Send) => {
                if self.send.poll_frame_into(out, room) {
                    Tx::Wrote
                } else {
                    Tx::Idle
                }
            }
        }
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.is_closed() {
            return None;
        }
        let t = &self.cfg.timing;
        let mut d: Option<Instant> = None;
        let mut put = |x: Option<Instant>| {
            if let Some(x) = x {
                d = Some(d.map_or(x, |d| d.min(x)));
            }
        };
        if !self.ever_opened {
            put(self.open_started.map(|s| s + t.t_open_retry));
        }
        put(self.detached_since.map(|s| s + t.t_detached));
        if self.carrier.is_some() && !self.confirmed {
            put(self.attach_started.map(|s| s + t.t_attach));
        }
        if self.need_attach {
            put(self.backoff_until);
        }
        if self.confirmed {
            if self.send.unacked() {
                put(Some(self.last_rx + t.t_stall));
            }
            put(self.recv.ack_deadline());
        }
        put(self.recv.idle_deadline());
        d
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        if self.is_closed() {
            return;
        }
        let t = self.cfg.timing.clone();
        if !self.ever_opened && self.open_started.is_some_and(|s| now >= s + t.t_open_retry) {
            self.rst = None;
            self.close(CloseReason::Reset(LOCAL_GIVE_UP));
            return;
        }
        if self.detached_since.is_some_and(|s| now >= s + t.t_detached) {
            self.close(CloseReason::Reset(LOCAL_GIVE_UP));
            return;
        }
        if self.carrier.is_some()
            && !self.confirmed
            && self.attach_started.is_some_and(|s| now >= s + t.t_attach)
        {
            // T_attach: abandon this attempt, retry on a new carrier.
            let old = self.carrier.take().unwrap();
            self.abandoned.push(old);
            self.need_attach = true;
            self.detached_since.get_or_insert(now);
        }
        if self.confirmed && self.send.unacked() && now >= self.last_rx + t.t_stall {
            self.reattach(now);
        }
        if self.recv.idle_deadline().is_some_and(|d| now >= d) {
            self.recv.update_credit(now);
        }
        // A passed backoff is no longer a deadline: `wants_attach` already
        // allows the attempt, and keeping it would make `poll_timeout`
        // return the past while the connect is in flight (busy loop).
        if self.backoff_until.is_some_and(|b| now >= b) {
            self.backoff_until = None;
        }
    }

    // ---- application side ----

    /// Bytes the app may write now.
    pub fn write_capacity(&mut self) -> usize {
        if self.is_closed() {
            0
        } else {
            self.send.write_capacity()
        }
    }

    /// Bytes the app may write now, at most `max`; holds no read-ahead
    /// beyond that (see [`SendHalf::write_capacity_for`]).
    pub fn write_capacity_for(&mut self, max: usize) -> usize {
        if self.is_closed() {
            0
        } else {
            self.send.write_capacity_for(max)
        }
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.is_closed() {
            return 0;
        }
        let n = self.send.write(data);
        if n > 0 {
            self.park.cancel();
        }
        n
    }

    /// App closed its write side.
    pub fn close_write(&mut self) {
        if !self.is_closed() {
            self.send.close();
        }
    }

    /// App reset the connection.
    pub fn abort(&mut self) {
        self.reset(code::SITE_RESET);
    }

    /// Reset the session locally with `code` (RST to the relay), e.g. when
    /// the control stream reports the device revoked.
    pub fn reset(&mut self, code: u8) {
        if !self.is_closed() {
            self.rst = Some(code);
            self.close(CloseReason::Reset(code));
        }
    }

    pub fn read(&mut self, out: &mut [u8], now: Instant) -> usize {
        let n = self.recv.read(out, now);
        self.check_done();
        n
    }

    /// Received bytes ready for the application, without copying them
    /// out (see [`consume`](Self::consume)).
    pub fn readable(&self) -> &[u8] {
        self.recv.front()
    }

    /// `n` bytes of [`readable`](Self::readable) reached the application.
    pub fn consume(&mut self, n: usize, now: Instant) {
        self.recv.consume(n, now);
        self.check_done();
    }

    /// All data up to the relay's FIN has been read.
    pub fn read_eof(&self) -> bool {
        self.recv.eof()
    }

    // ---- PARK (M9+: matching rule only) ----

    /// Begin a PARK request; the caller sends it on the control stream.
    pub fn request_park(&mut self) -> Option<crate::codec::ParkEntry> {
        if self.state != State::Active || self.send.pending() || self.recv.buffered() > 0 {
            return None;
        }
        let req_id = self.park.request(self.gen);
        Some(crate::codec::ParkEntry {
            session_id: self.session_id,
            req_id,
            attach_gen: self.gen,
            c_recv_offset: self.recv.recv_offset(),
            c_sent_offset: self.send.sent_hw(),
        })
    }

    pub fn on_park_ack(&mut self, ack: &crate::codec::ParkAckEntry) -> ParkDecision {
        self.park.on_ack(ack, self.gen)
    }
}
