//! Deterministic end-to-end simulation of one client session against a relay
//! table, over in-memory byte pipes that go through the real frame codec.
//! Carriers can be cut at any point (including mid-frame); the test checks
//! that every byte arrives exactly once, in order, in both directions.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use segue_session::client::{ClientSession, CloseReason, Health, OpenParams, State};
use segue_session::codec::{code, Frame, FrameDecoder, Kind, RedundantOk, SessionId, Target};
use segue_session::pool::Pool;
use segue_session::quality::QualityEvent;
use segue_session::relay::{AllowAll, RelayEvent, RelayTable};
use segue_session::{Config, ProtoError};

const INSTANCE: u64 = 77;

struct Pipe {
    c2r: VecDeque<u8>,
    r2c: VecDeque<u8>,
    rdec: FrameDecoder,
    cdec: FrameDecoder,
    /// The relay closed this carrier; the client sees EOF once `r2c` drains.
    relay_closed: bool,
}

impl Pipe {
    fn new() -> Self {
        Self {
            c2r: VecDeque::new(),
            r2c: VecDeque::new(),
            rdec: FrameDecoder::new(),
            cdec: FrameDecoder::new(),
            relay_closed: false,
        }
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i * 31 + (i >> 8) * 7) as u8) ^ seed)
        .collect()
}

struct Sim {
    rng: StdRng,
    now: Instant,
    client: ClientSession,
    relay: RelayTable,
    client_pool: Arc<Pool>,
    relay_pool: Arc<Pool>,
    pipes: HashMap<u64, Pipe>,
    next_cid: u64,
    up: Vec<u8>,
    up_written: usize,
    up_got: Vec<u8>,
    up_eof: bool,
    down: Vec<u8>,
    down_written: usize,
    down_got: Vec<u8>,
    down_eof: bool,
    site: Option<SessionId>,
    site_fin: bool,
    connects: usize,
    relay_closed: Vec<u8>,
    carriers_opened: usize,
    /// Per-step probability of cutting the current carrier.
    p_cut: f64,
    /// Per-step probability that a pipe delivers what it holds (latency).
    p_deliver: f64,
    /// The app reads downlink data.
    app_reads: bool,
    /// The site reads uplink data.
    site_reads: bool,
    /// Drop whatever the relay queued on the next this-many carriers it
    /// closes (e.g. the final ACK, §5.5 B6).
    drop_on_relay_close: usize,
    /// An abandoned carrier is not closed towards the relay (the client's
    /// network changed and the old path just went silent... or keeps
    /// delivering late frames).
    silent_abandon: bool,
    /// Keep a redundant carrier bound whenever the session is established.
    keep_redundant: bool,
    /// The spare's REDUNDANT_OK is never delivered (an old relay, or a
    /// black hole). The client must drop that carrier after `t_attach`.
    drop_redundant_ok: bool,
    /// Drop relay→client bytes on this carrier.
    mute_rx: Option<u64>,
    /// Leave this carrier's bytes in the pipe: neither side sees them, and
    /// the carrier stays open. Used to fire `t_stall` without a close.
    hold_carrier: Option<u64>,
    max_client_recv_buffered: usize,
    max_relay_send_buffered: usize,
}

impl Sim {
    fn new(seed: u64, up_len: usize, down_len: usize) -> Self {
        let cfg = Config::default();
        let now = Instant::now();
        let client_pool = Pool::new(8 << 20);
        let relay_pool = Pool::new(8 << 20);
        let params = OpenParams {
            ticket: b"ticket".to_vec(),
            kind: Kind::Tcp,
            target: Target::Domain("example.com".into(), 443),
            exit_class: 1,
            anchor_node_id: 5,
            instance_hint: INSTANCE,
        };
        let client =
            ClientSession::with_ids(cfg.clone(), &client_pool, params, [7; 16], [9; 32], now)
                .unwrap();
        let relay = RelayTable::new(cfg, relay_pool.clone(), Box::new(AllowAll), INSTANCE);
        Self {
            rng: StdRng::seed_from_u64(seed),
            now,
            client,
            relay,
            client_pool,
            relay_pool,
            pipes: HashMap::new(),
            next_cid: 0,
            up: pattern(up_len, 0x5a),
            up_written: 0,
            up_got: Vec::new(),
            up_eof: false,
            down: pattern(down_len, 0xa5),
            down_written: 0,
            down_got: Vec::new(),
            down_eof: false,
            site: None,
            site_fin: false,
            connects: 0,
            relay_closed: Vec::new(),
            carriers_opened: 0,
            p_cut: 0.0,
            p_deliver: 1.0,
            app_reads: true,
            site_reads: true,
            drop_on_relay_close: 0,
            silent_abandon: false,
            keep_redundant: false,
            drop_redundant_ok: false,
            mute_rx: None,
            hold_carrier: None,
            max_client_recv_buffered: 0,
            max_relay_send_buffered: 0,
        }
    }

    /// The network drops carrier `cid`: both ends see it closed, after a
    /// random prefix of what was in flight (possibly a partial frame).
    fn cut(&mut self, cid: u64) {
        let Some(mut p) = self.pipes.remove(&cid) else {
            return;
        };
        let keep_c = self.rng.gen_range(0..=p.c2r.len());
        let keep_r = self.rng.gen_range(0..=p.r2c.len());
        p.c2r.truncate(keep_c);
        p.r2c.truncate(keep_r);
        self.deliver(cid, &mut p);
        let now = self.now;
        self.client.on_carrier_closed(cid, now);
        if !p.relay_closed {
            self.relay.on_carrier_closed(cid, now);
        }
    }

    fn cut_current(&mut self) -> bool {
        match self.client.carrier() {
            Some(cid) if self.pipes.contains_key(&cid) => {
                self.cut(cid);
                true
            }
            _ => false,
        }
    }

    fn deliver(&mut self, cid: u64, p: &mut Pipe) {
        let now = self.now;
        if !p.relay_closed && !p.c2r.is_empty() {
            let bytes: Vec<u8> = p.c2r.drain(..).collect();
            p.rdec.push(&bytes);
            loop {
                match p.rdec.next_frame() {
                    Ok(Some(f)) => self.relay.on_frame(cid, f, now),
                    Ok(None) => break,
                    Err(e) => {
                        self.relay.on_decode_error(cid, e);
                        break;
                    }
                }
            }
        }
        p.c2r.clear();
        if self.mute_rx == Some(cid) {
            // The client never sees this carrier's downlink (no REDUNDANT_OK).
            p.r2c.clear();
        } else if !p.r2c.is_empty() {
            let bytes: Vec<u8> = p.r2c.drain(..).collect();
            p.cdec.push(&bytes);
            loop {
                match p.cdec.next_frame() {
                    Ok(Some(f)) => {
                        if self.client.on_frame(cid, f, now).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        self.client.on_decode_error(cid, e);
                        break;
                    }
                }
            }
        }
    }

    fn step(&mut self) {
        self.now += Duration::from_millis(1);
        let now = self.now;
        self.client.handle_timeout(now);
        self.relay.handle_timeout(now);

        if self.p_cut > 0.0 && self.rng.gen_bool(self.p_cut) {
            self.cut_current();
        }
        for cid in self.client.take_abandoned() {
            if self.silent_abandon {
                continue;
            }
            // The client closes the socket; the relay sees EOF.
            if let Some(p) = self.pipes.remove(&cid) {
                if !p.relay_closed {
                    self.relay.on_carrier_closed(cid, now);
                }
            }
        }
        if self.client.wants_attach(now) {
            self.next_cid += 1;
            let cid = self.next_cid;
            self.carriers_opened += 1;
            self.pipes.insert(cid, Pipe::new());
            self.relay.add_carrier(cid);
            self.client.attach(cid, now);
        }
        if self.keep_redundant {
            self.client.request_redundant();
        }
        if self.client.wants_redundant() {
            self.next_cid += 1;
            let cid = self.next_cid;
            self.carriers_opened += 1;
            self.pipes.insert(cid, Pipe::new());
            self.relay.add_carrier(cid);
            if self.drop_redundant_ok && self.mute_rx.is_none() {
                self.mute_rx = Some(cid);
            }
            self.client.attach_redundant(cid, now);
        }

        self.drain_events();

        // App writes uplink.
        self.app_write();
        self.step_rest();
    }

    fn drain_events(&mut self) {
        let now = self.now;
        while let Some(ev) = self.relay.take_event() {
            match ev {
                RelayEvent::Connect { session_id, .. } => {
                    self.connects += 1;
                    self.site = Some(session_id);
                    self.relay.connect_done(&session_id, Ok(()), now);
                }
                RelayEvent::Stall { attach_gen, .. } => self.client.on_stall(attach_gen, now),
                RelayEvent::Closed { close_code, .. } => self.relay_closed.push(close_code),
            }
        }
    }

    fn app_write(&mut self) {
        if self.up_written < self.up.len() {
            let cap = self.client.write_capacity();
            let chunk = self.rng.gen_range(1..=40_000);
            let n = cap.min(chunk).min(self.up.len() - self.up_written);
            if n > 0 {
                let w = self
                    .client
                    .write(&self.up[self.up_written..self.up_written + n]);
                assert_eq!(w, n, "write_capacity promised more than write accepted");
                self.up_written += n;
            }
        } else {
            self.client.close_write();
        }
    }

    fn step_rest(&mut self) {
        let now = self.now;
        // Site writes downlink, reads uplink.
        if let Some(sid) = self.site {
            if self.down_written < self.down.len() {
                let cap = self.relay.site_read_capacity(&sid);
                let chunk = self.rng.gen_range(1..=40_000);
                let n = cap.min(chunk).min(self.down.len() - self.down_written);
                if n > 0 {
                    let w = self
                        .relay
                        .site_data(&sid, &self.down[self.down_written..self.down_written + n]);
                    assert_eq!(
                        w, n,
                        "site_read_capacity promised more than site_data accepted"
                    );
                    self.down_written += n;
                }
            } else if !self.site_fin {
                self.site_fin = true;
                self.relay.site_fin(&sid);
            }
            if let Some(sh) = self.relay.send_half(&sid) {
                self.max_relay_send_buffered = self.max_relay_send_buffered.max(sh.buffered());
            }
            if self.site_reads {
                let mut buf = [0u8; 8192];
                loop {
                    let n = self.relay.read(&sid, &mut buf, now);
                    if n == 0 {
                        break;
                    }
                    self.up_got.extend_from_slice(&buf[..n]);
                }
                if self.relay.read_eof(&sid) {
                    self.up_eof = true;
                }
            }
        }

        // Transmit on the current carrier and, if any, the spare (only
        // REDUNDANT_ATTACH until it is bound).
        let mut send_on = Vec::new();
        if let Some(cid) = self.client.carrier() {
            send_on.push(cid);
        }
        if let Some(cid) = self.client.redundant_carrier() {
            if !send_on.contains(&cid) {
                send_on.push(cid);
            }
        }
        for cid in send_on {
            if let Some(p) = self.pipes.get_mut(&cid) {
                while let Some(f) = self.client.poll_transmit(cid, now) {
                    p.c2r.extend(f.to_bytes());
                }
            }
        }
        let cids: Vec<u64> = self.pipes.keys().copied().collect();
        for cid in &cids {
            let p = self.pipes.get_mut(cid).unwrap();
            if p.relay_closed {
                continue;
            }
            while let Some(f) = self.relay.poll_transmit(*cid, now) {
                p.r2c.extend(f.to_bytes());
            }
        }
        for cid in self.relay.take_closed_carriers() {
            if let Some(p) = self.pipes.get_mut(&cid) {
                while let Some(f) = self.relay.poll_transmit(cid, now) {
                    p.r2c.extend(f.to_bytes());
                }
                if self.drop_on_relay_close > 0 {
                    self.drop_on_relay_close -= 1;
                    p.r2c.clear();
                }
                p.relay_closed = true;
            }
            self.relay.on_carrier_closed(cid, now);
        }

        // Deliver.
        let mut cids: Vec<u64> = self.pipes.keys().copied().collect();
        cids.sort();
        for cid in cids {
            if self.p_deliver < 1.0 && !self.rng.gen_bool(self.p_deliver) {
                continue;
            }
            let Some(mut p) = self.pipes.remove(&cid) else {
                continue;
            };
            if self.hold_carrier == Some(cid) {
                self.pipes.insert(cid, p);
                continue;
            }
            self.deliver(cid, &mut p);
            if p.relay_closed && p.r2c.is_empty() {
                self.client.on_carrier_closed(cid, now);
            } else {
                self.pipes.insert(cid, p);
            }
        }

        self.drain_events();

        // App reads downlink.
        self.max_client_recv_buffered = self
            .max_client_recv_buffered
            .max(self.client.recv_half().buffered());
        if self.app_reads {
            let mut buf = [0u8; 8192];
            loop {
                let n = self.client.read(&mut buf, now);
                if n == 0 {
                    break;
                }
                self.down_got.extend_from_slice(&buf[..n]);
            }
            if self.client.read_eof() {
                self.down_eof = true;
            }
        }
        assert!(self.client_pool.used_bytes() <= self.client_pool.capacity_bytes());
        assert!(self.relay_pool.used_bytes() <= self.relay_pool.capacity_bytes());
    }

    fn finished(&mut self) -> bool {
        if !(self.client.is_closed() && self.relay.session_count() == 0) {
            return false;
        }
        // Like the driver: what was received before a clean close still
        // goes to the app, which drains it on its own schedule.
        {
            let mut buf = [0u8; 8192];
            loop {
                let n = self.client.read(&mut buf, self.now);
                if n == 0 {
                    break;
                }
                self.down_got.extend_from_slice(&buf[..n]);
            }
            self.down_eof |= self.client.read_eof();
        }
        true
    }

    fn run(&mut self, max_steps: usize) {
        for _ in 0..max_steps {
            if self.finished() {
                return;
            }
            self.step();
        }
        panic!(
            "did not finish: client {:?}, relay sessions {}, up {}/{} down {}/{}",
            self.client.state(),
            self.relay.session_count(),
            self.up_got.len(),
            self.up.len(),
            self.down_got.len(),
            self.down.len()
        );
    }

    fn assert_exact(&self) {
        assert_eq!(self.up_got.len(), self.up.len(), "uplink length");
        assert!(
            self.up_got == self.up,
            "uplink corrupted (loss / duplication / reorder)"
        );
        assert_eq!(self.down_got.len(), self.down.len(), "downlink length");
        assert!(
            self.down_got == self.down,
            "downlink corrupted (loss / duplication / reorder)"
        );
        assert!(self.up_eof && self.down_eof);
        assert_eq!(self.client.close_reason(), Some(CloseReason::Clean));
        assert_eq!(self.connects, 1, "site connected more than once");
    }
}

#[test]
fn clean_transfer_without_faults() {
    let mut s = Sim::new(1, 300_000, 1_000_000);
    s.run(100_000);
    s.assert_exact();
    assert_eq!(s.relay_closed, vec![code::CLEAN]);
    assert_eq!(s.carriers_opened, 1);
    assert_eq!(s.client.gen(), 0);
}

#[test]
fn empty_session_closes_cleanly() {
    let mut s = Sim::new(2, 0, 0);
    s.run(10_000);
    s.assert_exact();
}

#[test]
fn disconnect_mid_transfer_then_resume_loses_and_duplicates_nothing() {
    let mut s = Sim::new(3, 2_000_000, 3_000_000);
    let mut cuts = 0;
    for step in 0..400_000 {
        if s.finished() {
            break;
        }
        // Cut the carrier whenever another ~400 KB has moved.
        let moved = s.up_got.len() + s.down_got.len();
        if moved > (cuts + 1) * 400_000 && s.client.state() == State::Active && s.cut_current() {
            cuts += 1;
        }
        s.step();
        assert!(step < 399_999, "did not finish");
    }
    assert!(cuts >= 5, "only {cuts} cuts");
    s.assert_exact();
    assert!(
        s.client.gen() as usize >= cuts,
        "every cut is a new attach_gen"
    );
    assert_eq!(s.relay_closed, vec![code::CLEAN]);
}

#[test]
fn relay_that_misses_the_disconnect_is_taken_over_by_resume() {
    // The client's network changes; the relay never sees the old carrier
    // close. RESUME on the new carrier must switch atomically.
    let mut s = Sim::new(4, 500_000, 500_000);
    for _ in 0..3 {
        s.step();
    }
    s.silent_abandon = true;
    let old = s.client.carrier().unwrap();
    s.client.reattach(s.now);
    for _ in 0..100_000 {
        if s.finished() {
            break;
        }
        s.step();
    }
    // The relay closed the old carrier when RESUME switched (§5.2).
    assert!(!s.pipes.contains_key(&old));
    s.assert_exact();
    assert_eq!(s.client.gen(), 1);
}

#[test]
fn cut_during_open_retries_without_second_connect() {
    // Cut right after the OPEN reached the relay but before OPENED came
    // back: the retry is answered as a resume; the site is connected once.
    let mut s = Sim::new(5, 50_000, 50_000);
    s.p_deliver = 0.0;
    s.step(); // attach + OPEN queued
    let cid = s.client.carrier().unwrap();
    let mut p = s.pipes.remove(&cid).unwrap();
    s.deliver(cid, &mut p); // OPEN reaches the relay
    s.pipes.insert(cid, p);
    s.step(); // site connected, OPENED queued
    let mut p = s.pipes.remove(&cid).unwrap();
    assert!(!p.r2c.is_empty());
    p.r2c.clear(); // OPENED lost
    s.pipes.insert(cid, p);
    assert_eq!(s.connects, 1);
    assert_eq!(s.client.state(), State::Opening);
    s.cut(cid);
    s.p_deliver = 1.0;
    s.run(100_000);
    s.assert_exact();
    assert!(s.carriers_opened >= 2);
}

#[test]
fn cut_before_open_arrives_is_refused_never_reopened() {
    // The OPEN never reached the relay: the retry must get
    // REJECT(unknown_session), not a fresh connect (A2).
    let mut s = Sim::new(6, 1000, 1000);
    s.p_deliver = 0.0;
    s.step();
    let cid = s.client.carrier().unwrap();
    let mut p = s.pipes.remove(&cid).unwrap();
    p.c2r.clear();
    s.pipes.insert(cid, p);
    s.cut(cid);
    s.p_deliver = 1.0;
    s.run(10_000);
    assert_eq!(s.connects, 0);
    assert_eq!(
        s.client.close_reason(),
        Some(CloseReason::Reset(code::UNKNOWN_SESSION))
    );
}

#[test]
fn lost_final_ack_is_resolved_by_tombstone_as_clean() {
    // B6: the relay finished cleanly, but the ACK of the client's FIN was
    // lost with the carrier. RESUME meets the tombstone: REJECT(closed,
    // clean, final_recv_offset = fin + 1) and the client closes cleanly.
    let mut s = Sim::new(7, 200_000, 1_000);
    s.drop_on_relay_close = 1;
    s.run(100_000);
    assert_eq!(s.relay_closed, vec![code::CLEAN]);
    s.assert_exact();
    assert!(
        s.carriers_opened >= 2,
        "the tombstone path was not exercised"
    );
}

#[test]
fn flow_control_bounds_memory_when_the_app_stops_reading() {
    let mut s = Sim::new(8, 0, 8_000_000);
    s.app_reads = false;
    for _ in 0..20_000 {
        s.step();
    }
    let cfg = Config::default();
    // Receive side never buffers more than the window cap.
    assert!(
        s.max_client_recv_buffered <= cfg.limits.window_cap,
        "{}",
        s.max_client_recv_buffered
    );
    // The relay stops reading the site once its replay buffer is full.
    assert!(
        s.max_relay_send_buffered <= cfg.limits.replay_cap,
        "{}",
        s.max_relay_send_buffered
    );
    assert!(
        s.down_written < cfg.limits.window_cap + cfg.limits.replay_cap + (256 << 10),
        "site was drained regardless of the app: {}",
        s.down_written
    );
    assert!(!s.client.is_closed());
    // Resume reading: everything arrives.
    s.app_reads = true;
    s.run(400_000);
    s.assert_exact();
}

#[test]
fn site_that_stops_reading_bounds_relay_memory() {
    let mut s = Sim::new(9, 8_000_000, 0);
    s.site_reads = false;
    for _ in 0..20_000 {
        s.step();
    }
    let cfg = Config::default();
    assert!(s.relay.recv_half(&s.site.unwrap()).unwrap().buffered() <= cfg.limits.window_cap);
    assert!(s.client.send_half().buffered() <= cfg.limits.replay_cap);
    assert!(s.up_written < cfg.limits.window_cap + cfg.limits.replay_cap + (256 << 10));
    s.site_reads = true;
    s.run(400_000);
    s.assert_exact();
}

#[test]
fn randomized_faults_never_lose_or_duplicate() {
    let seeds: u64 = std::env::var("SEGUE_SIM_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    let mut refused = 0;
    let mut gens = 0u64;
    for seed in 0..seeds {
        let mut r = StdRng::seed_from_u64(seed ^ 0xfeed);
        let up = r.gen_range(0..400_000);
        let down = r.gen_range(0..600_000);
        let mut s = Sim::new(seed, up, down);
        s.p_cut = [0.0, 0.0005, 0.002, 0.01][r.gen_range(0..4)];
        s.p_deliver = [1.0, 0.7, 0.3][r.gen_range(0..3)];
        s.drop_on_relay_close = r.gen_range(0..3);
        s.silent_abandon = r.gen_bool(0.3);
        let pause_app = r.gen_bool(0.3);
        let mut steps = 0;
        while !s.finished() {
            if pause_app {
                s.app_reads = (steps / 500) % 3 != 0;
            }
            s.step();
            steps += 1;
            // Stop cutting after a while so every run terminates.
            if steps == 150_000 {
                s.p_cut = 0.0;
            }
            assert!(
                steps < 400_000,
                "seed {seed}: no progress, client {:?}",
                s.client.state()
            );
        }
        if s.connects == 0 {
            // The very first OPEN was lost: refused, never reopened (A2).
            assert_eq!(
                s.client.close_reason(),
                Some(CloseReason::Reset(code::UNKNOWN_SESSION)),
                "seed {seed}"
            );
            refused += 1;
            continue;
        }
        // Prefix property even before the final check.
        assert!(s.up.starts_with(&s.up_got), "seed {seed}: uplink corrupted");
        assert!(
            s.down.starts_with(&s.down_got),
            "seed {seed}: downlink corrupted"
        );
        s.assert_exact();
        gens += u64::from(s.client.gen());
    }
    eprintln!("randomized: {seeds} seeds, {refused} refused at OPEN, {gens} re-attaches");
    assert!(gens * 2 > seeds, "faults were not exercised");
    assert!(refused < seeds as usize, "every seed was refused");
}

#[test]
fn stale_frames_from_a_superseded_carrier_are_harmless() {
    // DATA arriving late on an old carrier is deduplicated by offset.
    let mut s = Sim::new(10, 100_000, 400_000);
    s.p_deliver = 0.5;
    s.silent_abandon = true;
    for i in 0..200_000 {
        if s.finished() {
            break;
        }
        if i % 997 == 0 && s.client.state() == State::Active {
            // Re-attach without closing: the old pipe keeps delivering.
            s.client.reattach(s.now);
        }
        s.step();
    }
    s.assert_exact();
}

fn wait_until_redundant(s: &mut Sim) -> u64 {
    for _ in 0..20_000 {
        if s.client.redundant_bound() {
            return s.client.redundant_carrier().unwrap();
        }
        s.step();
    }
    panic!(
        "redundant carrier never bound, state {:?}",
        s.client.state()
    );
}

#[test]
fn redundant_carrier_dies_session_continues_exact() {
    let mut s = Sim::new(11, 200_000, 300_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let gen = s.client.gen();
    let fruitless = s.client.fruitless_carriers();
    s.keep_redundant = false;
    s.client.take_health();
    s.client.take_quality();
    s.cut(spare);
    assert!(s.client.redundant_carrier().is_none());
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));
    assert!(s.client.carrier().is_some());
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen, "losing the spare is not a re-attach");
}

#[test]
fn current_dies_with_redundant_bound_session_continues_exact() {
    let mut s = Sim::new(12, 200_000, 300_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let gen = s.client.gen();
    s.keep_redundant = false;
    assert!(s.cut_current());
    // The spare is promoted: same generation, no new dial.
    assert_eq!(s.client.carrier(), Some(spare));
    assert_eq!(s.client.gen(), gen);
    assert!(!s.client.is_closed());
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen, "promotion is not a RESUME");
    assert_eq!(s.connects, 1);
}

#[test]
fn no_redundant_ok_drops_the_spare_and_leaves_the_session() {
    let mut s = Sim::new(13, 400_000, 400_000);
    s.keep_redundant = true;
    s.drop_redundant_ok = true;
    let mut spare = None;
    for _ in 0..5_000 {
        s.step();
        if let Some(cid) = s.client.redundant_carrier() {
            spare = Some(cid);
            s.keep_redundant = false;
            break;
        }
        assert!(!s.client.is_closed());
    }
    let spare = spare.expect("spare was not dialed");
    assert!(!s.client.redundant_bound());
    let fruitless = s.client.fruitless_carriers();
    // Hold the download so the session cannot finish before t_attach (2s,
    // and each step is 1ms). The spare must go; the session stays.
    s.app_reads = false;
    s.client.take_health();
    s.client.take_quality();
    for _ in 0..2_500 {
        s.step();
        assert!(
            !s.client.is_closed(),
            "session ended while the spare timed out"
        );
        assert_ne!(s.client.take_health(), Some(Health::Failed));
        assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));
    }
    assert_ne!(s.client.redundant_carrier(), Some(spare));
    assert!(!s.client.redundant_bound());
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    s.app_reads = true;
    s.drop_redundant_ok = false;
    s.mute_rx = None;
    s.run(200_000);
    s.assert_exact();
}

#[test]
fn randomized_faults_with_redundant_never_lose_or_duplicate() {
    let seeds: u64 = std::env::var("SEGUE_SIM_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let mut refused = 0;
    for seed in 0..seeds {
        let mut r = StdRng::seed_from_u64(seed ^ 0x5eed);
        let up = r.gen_range(0..300_000);
        let down = r.gen_range(0..400_000);
        let mut s = Sim::new(seed, up, down);
        s.keep_redundant = true;
        s.p_cut = [0.0, 0.0005, 0.002, 0.01][r.gen_range(0..4)];
        s.p_deliver = [1.0, 0.7, 0.3][r.gen_range(0..3)];
        s.drop_on_relay_close = r.gen_range(0..3);
        s.silent_abandon = r.gen_bool(0.3);
        // Cut the spare as often as the current carrier.
        let cut_spare = r.gen_bool(0.5);
        let mut steps = 0;
        while !s.finished() {
            if s.keep_redundant && cut_spare && s.p_cut > 0.0 && s.rng.gen_bool(s.p_cut) {
                if let Some(cid) = s.client.redundant_carrier() {
                    s.cut(cid);
                }
            }
            s.step();
            steps += 1;
            if steps == 150_000 {
                s.p_cut = 0.0;
            }
            assert!(
                steps < 400_000,
                "seed {seed}: no progress, client {:?}",
                s.client.state()
            );
        }
        if s.connects == 0 {
            assert_eq!(
                s.client.close_reason(),
                Some(CloseReason::Reset(code::UNKNOWN_SESSION)),
                "seed {seed}"
            );
            refused += 1;
            continue;
        }
        assert!(s.up.starts_with(&s.up_got), "seed {seed}: uplink corrupted");
        assert!(
            s.down.starts_with(&s.down_got),
            "seed {seed}: downlink corrupted"
        );
        s.assert_exact();
    }
    assert!(refused < seeds as usize, "every seed was refused");
}

#[test]
fn redundant_is_off_unless_requested() {
    let mut s = Sim::new(3, 80_000, 80_000);
    assert!(!s.client.wants_redundant());
    assert!(s.client.redundant_carrier().is_none());
    s.run(200_000);
    s.assert_exact();
    // One carrier, no spare dial, no second generation: the session that
    // never calls `request_redundant` is the single-carrier session.
    assert_eq!(s.carriers_opened, 1);
    assert_eq!(s.client.gen(), 0);
    assert!(s.client.redundant_carrier().is_none());
    assert!(!s.client.wants_redundant());
}

#[test]
fn redundant_ok_with_the_wrong_generation_does_not_bind() {
    let mut s = Sim::new(21, 50_000, 50_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    s.keep_redundant = false;
    assert!(s.client.redundant_bound());
    let fruitless = s.client.fruitless_carriers();
    let gen = s.client.gen();
    s.client.take_health();
    s.client.take_quality();
    s.client
        .on_frame(
            spare,
            Frame::RedundantOk(RedundantOk {
                attach_gen: gen.wrapping_add(9),
                recv_offset: 0,
                max_offset: 0,
            }),
            s.now,
        )
        .unwrap();
    assert!(s.client.redundant_carrier().is_none());
    assert!(!s.client.redundant_bound());
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert_eq!(s.client.gen(), gen);
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));
    s.run(200_000);
    s.assert_exact();
}

#[test]
fn redundant_stuck_or_undecodable_drops_only_itself() {
    let mut s = Sim::new(22, 80_000, 80_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let current = s.client.carrier();
    let gen = s.client.gen();
    let fruitless = s.client.fruitless_carriers();
    s.client.take_health();
    s.client.take_quality();
    s.client.on_carrier_stuck(spare, s.now);
    assert!(s.client.redundant_carrier().is_none());
    assert_eq!(s.client.carrier(), current);
    assert_eq!(s.client.gen(), gen);
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));

    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    s.client.take_health();
    s.client.take_quality();
    s.client.on_decode_error(spare, ProtoError::Malformed);
    assert!(s.client.redundant_carrier().is_none());
    assert_eq!(s.client.carrier(), current);
    assert_eq!(s.client.gen(), gen);
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));

    s.keep_redundant = false;
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen);
}

#[test]
fn t_stall_promotes_the_spare_without_a_new_dial() {
    let mut s = Sim::new(31, 200_000, 200_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let current = s.client.carrier().unwrap();
    assert_ne!(current, spare);
    s.keep_redundant = false;
    let opened = s.carriers_opened;
    let gen = s.client.gen();
    let fruitless = s.client.fruitless_carriers();
    s.client.take_health();
    s.client.take_quality();
    // Quiet the current carrier. Uplink is still in flight, so `t_stall`
    // (1s) fires before the relay's `t_live` (3s).
    s.hold_carrier = Some(current);
    let mut promoted = false;
    for _ in 0..3_000 {
        s.step();
        if s.client.carrier() == Some(spare) {
            promoted = true;
            break;
        }
    }
    assert!(promoted, "t_stall did not promote the spare");
    assert_eq!(s.client.gen(), gen);
    assert_eq!(s.carriers_opened, opened);
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert!(!s.client.wants_attach(s.now));
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));
    let sid = s.client.session_id();
    assert_eq!(s.relay.current_carrier(&sid), Some(spare));
    s.hold_carrier = None;
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen, "promotion is not a RESUME");
}

#[test]
fn stall_hint_promotes_the_spare_without_a_new_dial() {
    let mut s = Sim::new(32, 4_000, 500_000);
    s.keep_redundant = true;
    let mut ready = false;
    for _ in 0..50_000 {
        s.step();
        if s.client.redundant_bound()
            && s.up_written == s.up.len()
            && !s.client.send_half().unacked()
            && s.down_got.len() < s.down.len()
        {
            ready = true;
            break;
        }
        assert!(!s.finished(), "session ended before the stall window");
    }
    assert!(ready, "uplink never went idle with a spare bound");
    let spare = s.client.redundant_carrier().unwrap();
    let current = s.client.carrier().unwrap();
    let gen = s.client.gen();
    let opened = s.carriers_opened;
    let fruitless = s.client.fruitless_carriers();
    s.keep_redundant = false;
    s.client.take_health();
    s.client.take_quality();
    // No downlink reaches the client, so it sends no further ACKs. The
    // relay's `t_live` promotes the spare and emits STALL. Uplink is fully
    // acknowledged, so the client's own `t_stall` stays quiet.
    s.mute_rx = Some(current);
    let mut promoted = false;
    for _ in 0..5_000 {
        s.step();
        if s.client.carrier() == Some(spare) {
            promoted = true;
            break;
        }
        assert_eq!(s.client.gen(), gen, "stall dialed a new carrier");
    }
    assert!(promoted, "STALL did not promote the spare");
    assert_eq!(s.carriers_opened, opened);
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));
    let sid = s.client.session_id();
    assert_eq!(s.relay.current_carrier(&sid), Some(spare));
    assert!(s.relay.redundant_carrier(&sid).is_none());
    s.mute_rx = None;
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen, "promotion is not a RESUME");
}

#[test]
fn transport_hold_promotes_the_spare_without_a_new_dial() {
    let mut s = Sim::new(33, 80_000, 80_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let current = s.client.carrier().unwrap();
    let gen = s.client.gen();
    let opened = s.carriers_opened;
    let fruitless = s.client.fruitless_carriers();
    s.keep_redundant = false;
    s.client.take_health();
    s.client.take_quality();
    s.client.on_carrier_stuck(current, s.now);
    assert_eq!(s.client.carrier(), Some(spare));
    assert_eq!(s.client.gen(), gen);
    assert!(s.client.redundant_carrier().is_none());
    assert_eq!(s.client.fruitless_carriers(), fruitless);
    assert!(!s.client.wants_attach(s.now));
    assert_ne!(s.client.take_health(), Some(Health::Failed));
    assert_ne!(s.client.take_quality(), Some(QualityEvent::CarrierLost));
    // The abandon closes the old carrier; the relay promotes on that close.
    s.step();
    let sid = s.client.session_id();
    assert_eq!(s.relay.current_carrier(&sid), Some(spare));
    assert_eq!(s.carriers_opened, opened);
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen, "promotion is not a RESUME");
}

#[test]
fn promotion_allows_another_redundant_carrier() {
    let mut s = Sim::new(34, 80_000, 80_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let gen = s.client.gen();
    s.keep_redundant = false;
    assert!(s.cut_current());
    assert_eq!(s.client.carrier(), Some(spare));
    assert!(!s.client.wants_redundant());
    // What the driver does when the caller asks again.
    s.client.request_redundant();
    assert!(s.client.wants_redundant());
    s.keep_redundant = true;
    let spare2 = wait_until_redundant(&mut s);
    assert_ne!(spare2, spare);
    assert_eq!(s.client.gen(), gen);
    s.keep_redundant = false;
    s.run(200_000);
    s.assert_exact();
    assert_eq!(s.client.gen(), gen);
}

#[test]
fn move_onto_a_third_carrier_drops_the_spare() {
    let mut s = Sim::new(35, 80_000, 80_000);
    s.keep_redundant = true;
    let spare = wait_until_redundant(&mut s);
    let gen = s.client.gen();
    let sid = s.client.session_id();
    assert_eq!(s.relay.redundant_carrier(&sid), Some(spare));
    s.keep_redundant = false;
    s.client.reattach(s.now);
    assert!(s.client.redundant_carrier().is_none());
    let mut moved = false;
    for _ in 0..50 {
        s.step();
        if s.client.gen() == gen + 1
            && s.client.redundant_carrier().is_none()
            && s.relay.redundant_carrier(&sid).is_none()
            && s.client.carrier().is_some()
        {
            moved = true;
            break;
        }
    }
    assert!(moved, "move did not drop the spare on both sides");
    assert_ne!(s.client.carrier(), Some(spare));
    s.run(200_000);
    s.assert_exact();
    assert!(s.client.gen() > gen);
}

#[allow(dead_code)]
fn frame_of(bytes: &[u8]) -> Frame {
    let mut d = FrameDecoder::new();
    d.push(bytes);
    d.next_frame().unwrap().unwrap()
}
