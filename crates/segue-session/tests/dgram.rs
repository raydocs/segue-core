//! S1–S3 acceptance & deterministic discrete-event tests for the UDP
//! datagram accelerator (`docs/design/session-datagram-redundancy.md` §8).

use std::collections::{BTreeMap, BinaryHeap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use segue_session::client::{ClientSession, CloseReason, OpenParams, State};
use segue_session::codec::{
    put_varint, ty, DgramBind, DgramBindOk, Frame, FrameDecoder, Kind, Target, FLAG_IGNORABLE,
    VERSION,
};
use segue_session::dgram::{
    decode_dgram_header, decode_dgram_packet, encode_dgram_packet, DgramBody, DgramConfig,
    DgramHeader, DgramPacket, DGRAM_MAX_BYTES, FLAG_BIND, FLAG_PROBE,
};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayEvent, RelayTable, SessionState};
use segue_session::Config;

const INSTANCE: u64 = 77;
const ONE_WAY: Duration = Duration::from_millis(85);
const RTT: Duration = Duration::from_millis(170);
const BERN_P: f64 = 0.075;
const GE_BAD_TO_GOOD: f64 = 0.85;
const GE_GOOD_TO_BAD: f64 = BERN_P * GE_BAD_TO_GOOD / (1.0 - BERN_P);

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

fn mix(seed: u64, tag: u64) -> u64 {
    seed ^ tag.wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

#[derive(Clone, Copy)]
enum LossKind {
    Clean,
    #[allow(dead_code)]
    DropAll,
    Gilbert,
}

struct PathLoss {
    rng: Rng,
    bad: bool,
    kind: LossKind,
}

impl PathLoss {
    fn new(seed: u64, kind: LossKind) -> Self {
        let mut rng = Rng::new(seed);
        let bad = match kind {
            LossKind::Clean | LossKind::DropAll => false,
            LossKind::Gilbert => {
                let pi = GE_GOOD_TO_BAD / (GE_GOOD_TO_BAD + GE_BAD_TO_GOOD);
                rng.next_f64() < pi
            }
        };
        Self { rng, bad, kind }
    }

    fn lost(&mut self) -> bool {
        match self.kind {
            LossKind::Clean => false,
            LossKind::DropAll => true,
            LossKind::Gilbert => {
                if self.bad {
                    if self.rng.next_f64() < GE_BAD_TO_GOOD {
                        self.bad = false;
                    }
                } else if self.rng.next_f64() < GE_GOOD_TO_BAD {
                    self.bad = true;
                }
                self.bad
            }
        }
    }
}

#[derive(Clone)]
struct TcpSeg {
    seq: u64,
    data: Vec<u8>,
    sent_at: Instant,
    tlp_at: Instant,
    rto_at: Instant,
    retx: u32,
    delivered: bool,
}

struct TcpDir {
    next_seq: u64,
    recv_next: u64,
    sent: VecDeque<TcpSeg>,
    ooo: BTreeMap<u64, Vec<u8>>,
    in_flight_wire: VecDeque<(Instant, u64, Vec<u8>, bool)>,
    ack_wire: VecDeque<(Instant, u64, u64)>,
    dup_acks_for_head: u32,
    last_ack_seen: u64,
    loss: PathLoss,
    dec: FrameDecoder,
}

impl TcpDir {
    fn new(seed: u64, kind: LossKind) -> Self {
        Self {
            next_seq: 0,
            recv_next: 0,
            sent: VecDeque::new(),
            ooo: BTreeMap::new(),
            in_flight_wire: VecDeque::new(),
            ack_wire: VecDeque::new(),
            dup_acks_for_head: 0,
            last_ack_seen: 0,
            loss: PathLoss::new(seed, kind),
            dec: FrameDecoder::new(),
        }
    }

    fn send(&mut self, bytes: Vec<u8>, now: Instant) {
        if bytes.is_empty() {
            return;
        }
        let seq = self.next_seq;
        self.next_seq += bytes.len() as u64;
        let lost = self.loss.lost();
        if !lost {
            self.in_flight_wire
                .push_back((now + ONE_WAY, seq, bytes.clone(), false));
        }
        self.sent.push_back(TcpSeg {
            seq,
            data: bytes,
            sent_at: now,
            tlp_at: now + RTT * 2,
            rto_at: now + (RTT * 3).max(Duration::from_millis(200)),
            retx: 0,
            delivered: false,
        });
    }

    fn next_deadline(&self) -> Option<Instant> {
        let mut d: Option<Instant> = None;
        let mut put = |t: Instant| d = Some(d.map_or(t, |cur| cur.min(t)));
        if let Some((t, ..)) = self.in_flight_wire.front() {
            put(*t);
        }
        if let Some((t, ..)) = self.ack_wire.front() {
            put(*t);
        }
        if let Some(head) = self.sent.front() {
            put(head.rto_at);
            if let Some(tail) = self.sent.back() {
                if !tail.delivered {
                    put(tail.tlp_at);
                }
            }
        }
        d
    }

    fn step(&mut self, now: Instant) -> Vec<Frame> {
        let mut out = Vec::new();
        while self
            .in_flight_wire
            .front()
            .is_some_and(|(at, ..)| *at <= now)
        {
            let (_, seq, bytes, _is_retx) = self.in_flight_wire.pop_front().unwrap();
            let end = seq + bytes.len() as u64;
            if seq == self.recv_next {
                self.dec.push(&bytes);
                self.recv_next = end;
                while let Some(k) = self.ooo.keys().next().copied() {
                    if k > self.recv_next {
                        break;
                    }
                    let seg = self.ooo.remove(&k).unwrap();
                    let ke = k + seg.len() as u64;
                    if ke > self.recv_next {
                        let skip = (self.recv_next - k) as usize;
                        self.dec.push(&seg[skip..]);
                        self.recv_next = ke;
                    }
                }
            } else if end > self.recv_next {
                self.ooo.entry(seq).or_insert(bytes);
            }
            self.ack_wire
                .push_back((now + ONE_WAY, self.recv_next, end));
        }

        loop {
            match self.dec.next_frame() {
                Ok(Some(f)) => out.push(f),
                Ok(None) => break,
                Err(e) => panic!("unexpected TCP carrier decode error: {e:?}"),
            }
        }

        while self.ack_wire.front().is_some_and(|(at, ..)| *at <= now) {
            let (_, ack, sack_end) = self.ack_wire.pop_front().unwrap();
            while self
                .sent
                .front()
                .is_some_and(|s| s.seq + s.data.len() as u64 <= ack)
            {
                self.sent.pop_front();
                self.dup_acks_for_head = 0;
            }
            for seg in &mut self.sent {
                if seg.seq + seg.data.len() as u64 <= sack_end && seg.seq >= ack {
                    seg.delivered = true;
                }
            }
            if ack == self.last_ack_seen && !self.sent.is_empty() && sack_end > ack {
                self.dup_acks_for_head += 1;
                if self.dup_acks_for_head == 3 {
                    if let Some(head) = self.sent.front_mut() {
                        head.retx += 1;
                        let rto = ((RTT * 3).max(Duration::from_millis(200)))
                            .saturating_mul(1 << head.retx.min(4))
                            .min(Duration::from_secs(8));
                        head.rto_at = now + rto;
                        head.tlp_at = now + RTT * 2;
                        head.sent_at = now;
                        if !self.loss.lost() {
                            self.in_flight_wire.push_back((
                                now + ONE_WAY,
                                head.seq,
                                head.data.clone(),
                                true,
                            ));
                        }
                    }
                }
            } else if ack > self.last_ack_seen {
                self.last_ack_seen = ack;
                self.dup_acks_for_head = 0;
            }
        }

        // TLP on tail or RTO on head.
        if let Some(tail) = self.sent.back_mut() {
            if now >= tail.tlp_at && !tail.delivered {
                tail.retx += 1;
                tail.tlp_at = now + RTT * 2;
                let rto = ((RTT * 3).max(Duration::from_millis(200)))
                    .saturating_mul(1 << tail.retx.min(4))
                    .min(Duration::from_secs(8));
                tail.rto_at = tail.rto_at.max(now + rto);
                if !self.loss.lost() {
                    self.in_flight_wire.push_back((
                        now + ONE_WAY,
                        tail.seq,
                        tail.data.clone(),
                        true,
                    ));
                }
            }
        }
        if let Some(head) = self.sent.front_mut() {
            if now >= head.rto_at {
                head.retx += 1;
                let rto = ((RTT * 3).max(Duration::from_millis(200)))
                    .saturating_mul(1 << head.retx.min(4))
                    .min(Duration::from_secs(8));
                head.rto_at = now + rto;
                head.tlp_at = now + RTT * 2;
                if !self.loss.lost() {
                    self.in_flight_wire.push_back((
                        now + ONE_WAY,
                        head.seq,
                        head.data.clone(),
                        true,
                    ));
                }
            }
        }

        out
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TokenSpec {
    born: Instant,
    start: usize,
    end: usize,
    delivered_at: Option<Instant>,
}

fn peer_addr(flow: usize) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000 + flow as u16)
}

fn peer_to_flow(addr: SocketAddr) -> usize {
    usize::from(addr.port() - 40_000)
}

struct SimPair {
    now: Instant,
    client: ClientSession,
    relay: RelayTable,
    tcp_c2r: TcpDir,
    tcp_r2c: TcpDir,
    udp_c2r: Vec<(PathLoss, BinaryHeap<UdpInFlight>)>,
    udp_r2c: Vec<(PathLoss, BinaryHeap<UdpInFlight>)>,
    udp_blackhole: bool,
    k_flows: u8,
    seq: u64,
}

#[derive(Clone, Eq, PartialEq)]
struct UdpInFlight {
    at: Instant,
    seq: u64,
    flow: usize,
    pkt: Vec<u8>,
}

impl Ord for UdpInFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.at.cmp(&self.at).then(other.seq.cmp(&self.seq))
    }
}
impl PartialOrd for UdpInFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl SimPair {
    fn new(
        seed: u64,
        exit_class: u8,
        cfg: Config,
        tcp_kind: LossKind,
        udp_kind: LossKind,
        k_flows: u8,
    ) -> Self {
        let now = Instant::now();
        let cpool = Pool::new(8 << 20);
        let rpool = Pool::new(8 << 20);
        let params = OpenParams {
            ticket: b"t".to_vec(),
            kind: Kind::Tcp,
            target: Target::Domain("api.openai.com".into(), 443),
            exit_class,
            anchor_node_id: 1,
            instance_hint: INSTANCE,
        };
        let mut client =
            ClientSession::with_ids(cfg.clone(), &cpool, params, [0x44; 16], [0x55; 32], now)
                .unwrap();
        client.set_dgram_flows(k_flows, now);
        client.attach(1, now);
        let mut relay = RelayTable::new(cfg, rpool, Box::new(AllowAll), INSTANCE);
        relay.add_carrier(1);

        let mut udp_c2r = Vec::new();
        let mut udp_r2c = Vec::new();
        for f in 0..usize::from(k_flows.max(1)) {
            udp_c2r.push((
                PathLoss::new(mix(seed, 100 + f as u64), udp_kind),
                BinaryHeap::new(),
            ));
            udp_r2c.push((
                PathLoss::new(mix(seed, 200 + f as u64), udp_kind),
                BinaryHeap::new(),
            ));
        }

        Self {
            now,
            client,
            relay,
            tcp_c2r: TcpDir::new(mix(seed, 1), tcp_kind),
            tcp_r2c: TcpDir::new(mix(seed, 2), tcp_kind),
            udp_c2r,
            udp_r2c,
            udp_blackhole: false,
            k_flows,
            seq: 0,
        }
    }

    fn flush_once(&mut self) {
        for f in &mut self.tcp_c2r.step(self.now).drain(..) {
            self.relay.on_frame(1, f, self.now);
        }
        for f in &mut self.tcp_r2c.step(self.now).drain(..) {
            let _ = self.client.on_frame(1, f, self.now);
        }
        for flow in 0..self.udp_c2r.len() {
            while self.udp_c2r[flow]
                .1
                .peek()
                .is_some_and(|u| u.at <= self.now)
            {
                let u = self.udp_c2r[flow].1.pop().unwrap();
                self.relay.on_dgram(peer_addr(u.flow), &u.pkt, self.now);
            }
        }
        for flow in 0..self.udp_r2c.len() {
            while self.udp_r2c[flow]
                .1
                .peek()
                .is_some_and(|u| u.at <= self.now)
            {
                let u = self.udp_r2c[flow].1.pop().unwrap();
                let _ = self.client.on_dgram(u.flow, &u.pkt, self.now);
            }
        }

        while let Some(ev) = self.relay.take_event() {
            if let RelayEvent::Connect { session_id, .. } = ev {
                self.relay.connect_done(&session_id, Ok(()), self.now);
            }
        }

        self.client.handle_timeout(self.now);
        self.relay.handle_timeout(self.now);

        let mut buf = Vec::new();
        while self
            .client
            .poll_transmit_into(1, self.now, &mut buf, 1 << 20)
            == segue_session::client::Tx::Wrote
        {
            self.tcp_c2r.send(std::mem::take(&mut buf), self.now);
        }
        while self
            .relay
            .poll_transmit_into(1, self.now, &mut buf)
            .is_some()
        {
            self.tcp_r2c.send(std::mem::take(&mut buf), self.now);
        }

        for flow in 0..usize::from(self.k_flows) {
            while self.client.has_dgram_transmit(flow, self.now) {
                buf.clear();
                if self.client.poll_dgram_transmit(flow, self.now, &mut buf) {
                    if !self.udp_blackhole && !self.udp_c2r[flow].0.lost() {
                        self.seq += 1;
                        self.udp_c2r[flow].1.push(UdpInFlight {
                            at: self.now + ONE_WAY,
                            seq: self.seq,
                            flow,
                            pkt: std::mem::take(&mut buf),
                        });
                    }
                } else {
                    break;
                }
            }
        }
        loop {
            buf.clear();
            let Some(peer) = self.relay.poll_dgram_transmit(self.now, &mut buf) else {
                break;
            };
            let flow = peer_to_flow(peer);
            if flow < self.udp_r2c.len() && !self.udp_blackhole && !self.udp_r2c[flow].0.lost() {
                self.seq += 1;
                self.udp_r2c[flow].1.push(UdpInFlight {
                    at: self.now + ONE_WAY,
                    seq: self.seq,
                    flow,
                    pkt: std::mem::take(&mut buf),
                });
            }
        }
    }

    fn next_net_deadline(&self) -> Option<Instant> {
        let mut d: Option<Instant> = None;
        let mut put = |x: Option<Instant>| {
            if let Some(x) = x {
                d = Some(d.map_or(x, |cur| cur.min(x)));
            }
        };
        put(self.tcp_c2r.next_deadline());
        put(self.tcp_r2c.next_deadline());
        for (_, h) in &self.udp_c2r {
            put(h.peek().map(|u| u.at));
        }
        for (_, h) in &self.udp_r2c {
            put(h.peek().map(|u| u.at));
        }
        put(self.client.poll_timeout());
        put(self.relay.poll_timeout());
        d
    }

    fn wait_bound(&mut self, sid: &[u8; 16], need_peers: usize) {
        let deadline = self.now + Duration::from_secs(5);
        while self.now < deadline {
            self.flush_once();
            if self.client.dgram_bound() && self.relay.dgram_peers(sid) == Some(need_peers) {
                return;
            }
            let next = self
                .next_net_deadline()
                .unwrap_or(self.now + Duration::from_millis(5));
            self.now = next.max(self.now);
        }
        panic!(
            "timed out waiting for dgram bind (client_bound={}, relay_peers={:?})",
            self.client.dgram_bound(),
            self.relay.dgram_peers(sid)
        );
    }
}

#[derive(Debug)]
struct StreamMetrics {
    p50_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    stalls_gt_300ms: usize,
    residual_gt_rtt: usize,
    total_frames: usize,
    residual_pct: f64,
}

fn run_gilbert_stream(seed: u64, downlink: bool, k_flows: u8) -> StreamMetrics {
    const N_FRAMES: usize = 3000;
    const INTERVAL: Duration = Duration::from_millis(20);
    let mut cfg = Config {
        dgram: DgramConfig {
            flows: k_flows,
            ..DgramConfig::for_ai_default()
        },
        ..Config::default()
    };
    // Allow generous time for completion so TCP recovery never false-stalls at 5s.
    cfg.timing.t_stall_ai = Duration::from_secs(20);
    cfg.timing.t_live_ai = Duration::from_secs(20);

    let mut sim = SimPair::new(
        seed,
        segue_session::EXIT_CLASS_AI,
        cfg,
        LossKind::Gilbert,
        LossKind::Gilbert,
        k_flows,
    );
    let sid = sim.client.session_id();
    sim.wait_bound(&sid, usize::from(k_flows));

    let t_start = sim.now;
    let mut rng = Rng::new(mix(seed, 999));
    let mut tokens = Vec::with_capacity(N_FRAMES);
    let mut expected = Vec::new();
    let mut offset = 0usize;
    for i in 0..N_FRAMES {
        let len = 30 + (rng.next_u64() % 31) as usize;
        let payload: Vec<u8> = (0..len).map(|j| ((i * 17 + j * 13) & 0xff) as u8).collect();
        expected.extend_from_slice(&payload);
        tokens.push(TokenSpec {
            born: t_start + INTERVAL * (i as u32),
            start: offset,
            end: offset + len,
            delivered_at: None,
        });
        offset += len;
    }

    let mut pushed = 0usize;
    let mut received = Vec::with_capacity(expected.len());
    let mut delivered_idx = 0usize;
    let mut scratch = vec![0u8; 64 * 1024];
    let mut fin_sent = false;
    let hard_end = t_start + Duration::from_secs(120);

    while delivered_idx < N_FRAMES
        || !fin_sent
        || (downlink && !sim.client.recv_half().fin_received())
        || (!downlink && !sim.relay.read_eof(&sid))
    {
        assert!(
            sim.now < hard_end,
            "simulation hung at {delivered_idx}/{N_FRAMES}"
        );
        while pushed < N_FRAMES && tokens[pushed].born <= sim.now {
            let spec = tokens[pushed];
            let chunk = &expected[spec.start..spec.end];
            let n = if downlink {
                sim.relay.site_data(&sid, chunk)
            } else {
                sim.client.write(chunk)
            };
            if n < chunk.len() {
                break;
            }
            pushed += 1;
        }
        if pushed == N_FRAMES && !fin_sent {
            if downlink {
                sim.relay.site_fin(&sid);
            } else {
                sim.client.close_write();
            }
            fin_sent = true;
        }

        sim.flush_once();

        loop {
            let n = if downlink {
                sim.client.read(&mut scratch, sim.now)
            } else {
                sim.relay.read(&sid, &mut scratch, sim.now)
            };
            if n == 0 {
                break;
            }
            received.extend_from_slice(&scratch[..n]);
            while delivered_idx < N_FRAMES && received.len() >= tokens[delivered_idx].end {
                tokens[delivered_idx].delivered_at = Some(sim.now);
                delivered_idx += 1;
            }
        }

        assert!(
            !matches!(sim.client.state(), State::Closed(CloseReason::Reset(_))),
            "client reset unexpectedly"
        );

        let next_birth = (pushed < N_FRAMES).then(|| tokens[pushed].born);
        let next_ev = [sim.next_net_deadline(), next_birth]
            .into_iter()
            .flatten()
            .min();
        if let Some(t) = next_ev {
            if t > sim.now {
                sim.now = t;
            } else {
                sim.now += Duration::from_micros(100);
            }
        } else {
            break;
        }
    }

    assert_eq!(received, expected, "stream bytes mismatch");
    assert_eq!(sim.client.move_stats().stall, 0);
    assert_eq!(sim.client.move_stats().resumes, 0);

    let mut delays: Vec<Duration> = tokens
        .iter()
        .map(|t| {
            let arr = t.delivered_at.expect("delivered");
            arr.saturating_duration_since(t.born + ONE_WAY)
        })
        .collect();
    let stalls_gt_300ms = delays
        .iter()
        .filter(|&&d| d > Duration::from_millis(300))
        .count();
    let residual_gt_rtt = delays.iter().filter(|&&d| d >= RTT).count();
    delays.sort_unstable();
    let p50_ms = delays[N_FRAMES / 2].as_secs_f64() * 1000.0;
    let p99_ms = delays[(N_FRAMES * 99) / 100].as_secs_f64() * 1000.0;
    let max_ms = delays[N_FRAMES - 1].as_secs_f64() * 1000.0;
    StreamMetrics {
        p50_ms,
        p99_ms,
        max_ms,
        stalls_gt_300ms,
        residual_gt_rtt,
        total_frames: N_FRAMES,
        residual_pct: (residual_gt_rtt as f64) * 100.0 / (N_FRAMES as f64),
    }
}

#[test]
fn s1_codec_roundtrip_ignorable_skip_and_malformed_rejection() {
    let hdr = DgramHeader {
        session_id: [0x12; 16],
        attach_gen: 7,
        nonce: [0x34; 16],
    };
    let pkts = [
        DgramPacket {
            header: hdr,
            body: DgramBody::Data(vec![(0, b"hello".to_vec()), (5, b"world".to_vec())]),
        },
        DgramPacket {
            header: hdr,
            body: DgramBody::Ack {
                recv_offset: 100,
                max_offset: 16_384,
                sacks: vec![120, 160],
                flags: FLAG_BIND | FLAG_PROBE,
            },
        },
        DgramPacket {
            header: hdr,
            body: DgramBody::Fin { offset: 42 },
        },
    ];
    for pkt in pkts {
        let mut wire = Vec::new();
        assert!(encode_dgram_packet(&pkt, &mut wire));
        assert!(wire.len() <= DGRAM_MAX_BYTES);
        assert_eq!(decode_dgram_header(&wire), Some(hdr));
        assert_eq!(decode_dgram_packet(&wire), Some(pkt));
    }

    // Malformed / oversized / truncated / trailing garbage inputs return None cleanly.
    assert!(decode_dgram_packet(&[]).is_none());
    assert!(decode_dgram_packet(&vec![0u8; DGRAM_MAX_BYTES + 1]).is_none());
    assert!(decode_dgram_packet(&[0u8; 38]).is_none());
    let mut bad_fin = Vec::new();
    encode_dgram_packet(
        &DgramPacket {
            header: hdr,
            body: DgramBody::Fin { offset: 1 },
        },
        &mut bad_fin,
    );
    bad_fin.push(0x99); // trailing garbage
    assert!(decode_dgram_packet(&bad_fin).is_none());

    // Zero-count DATA must fail.
    let mut zero_data = Vec::new();
    zero_data.extend_from_slice(&hdr.session_id);
    zero_data.extend_from_slice(&hdr.attach_gen.to_be_bytes());
    zero_data.extend_from_slice(&hdr.nonce);
    zero_data.extend_from_slice(&[1, 0, 0]);
    assert!(decode_dgram_packet(&zero_data).is_none());

    // Reliable control frames encode with FLAG_IGNORABLE so an old peer's
    // FrameDecoder skips unknown 0x3E/0x3F opcodes cleanly without error.
    let bind = Frame::DgramBind(DgramBind {
        session_id: [0xaa; 16],
        attach_gen: 3,
        nonce: [0xbb; 16],
    });
    let bind_ok = Frame::DgramBindOk(DgramBindOk {
        attach_gen: 3,
        nonce: [0xbb; 16],
    });
    assert_ne!(bind.to_bytes()[1] & FLAG_IGNORABLE, 0);
    assert_ne!(bind_ok.to_bytes()[1] & FLAG_IGNORABLE, 0);

    let mut dec = FrameDecoder::new();
    dec.push(&bind.to_bytes());
    assert_eq!(dec.next_frame().unwrap(), Some(bind.clone()));
    dec.push(&bind_ok.to_bytes());
    assert_eq!(dec.next_frame().unwrap(), Some(bind_ok.clone()));

    // Simulate unknown ignorable opcodes (`0x5E`, `0x5F`) followed by ACK: skipped cleanly.
    let mut wire = Vec::new();
    for raw_ty in [ty::DGRAM_BIND + 0x20, ty::DGRAM_BIND_OK + 0x20] {
        wire.push(raw_ty);
        wire.push(FLAG_IGNORABLE);
        put_varint(&mut wire, 4);
        wire.extend_from_slice(b"test");
    }
    let expected_ack = Frame::Ack {
        recv_offset: 12,
        max_offset: 34,
    };
    expected_ack.encode(&mut wire);
    dec.push(&wire);
    assert_eq!(dec.next_frame().unwrap(), Some(expected_ack));
}

#[test]
fn s1_100pct_dgram_drop_and_forged_packets_preserve_reliable_baseline() {
    let cfg = Config {
        dgram: DgramConfig::for_ai_default(),
        ..Config::default()
    };
    let mut sim = SimPair::new(
        9,
        segue_session::EXIT_CLASS_AI,
        cfg,
        LossKind::Clean,
        LossKind::DropAll,
        2,
    );
    let sid = sim.client.session_id();
    for _ in 0..40 {
        sim.flush_once();
        if sim.client.dgram_bound() {
            break;
        }
        sim.now += Duration::from_millis(20);
    }
    assert!(sim.client.dgram_bound());

    // Inject random garbage, wrong nonce, and stale attach_gen on both ends:
    // none may reset or corrupt the session.
    let bad_hdr = DgramHeader {
        session_id: sid,
        attach_gen: sim.client.gen() + 1,
        nonce: [0xff; 16],
    };
    let mut forged = Vec::new();
    encode_dgram_packet(
        &DgramPacket {
            header: bad_hdr,
            body: DgramBody::Data(vec![(0, b"forged".to_vec())]),
        },
        &mut forged,
    );
    assert!(!sim.client.on_dgram(0, &forged, sim.now));
    assert!(!sim.relay.on_dgram(peer_addr(0), &forged, sim.now));
    assert!(!sim.client.on_dgram(1, b"short", sim.now));
    assert!(!sim.relay.on_dgram(peer_addr(1), b"short", sim.now));
    assert_eq!(sim.client.state(), State::Active);
    assert_eq!(sim.relay.state(&sid), Some(SessionState::Active));

    let msg = b"hello reliable baseline with 100% UDP dropped";
    assert_eq!(sim.client.write(msg), msg.len());
    sim.client.close_write();
    for _ in 0..50 {
        sim.flush_once();
        sim.now += Duration::from_millis(20);
    }
    let mut got = vec![0u8; 256];
    let n = sim.relay.read(&sid, &mut got, sim.now);
    assert_eq!(&got[..n], msg);
    assert!(sim.relay.read_eof(&sid));
    assert!(!matches!(
        sim.client.state(),
        State::Closed(CloseReason::Reset(_))
    ));
    assert!(sim.client.dgram_stats().rx_dropped_bad >= 2);

    // Relay with dgram.enabled == false safely ignores DgramBind without error.
    let now = Instant::now();
    let pool = Pool::new(1 << 20);
    let mut off_relay = RelayTable::new(Config::default(), pool, Box::new(AllowAll), 1);
    off_relay.add_carrier(1);
    off_relay.on_frame(
        1,
        Frame::Open(segue_session::codec::Open {
            version: VERSION,
            ticket: b"t".to_vec(),
            session_id: [1; 16],
            resume_secret: [2; 32],
            attach_gen: 0,
            retry: false,
            anchor_instance_id: 0,
            kind: Kind::Tcp,
            target: Target::Domain("example.com".into(), 443),
            exit_class: segue_session::EXIT_CLASS_AI,
            t_stall_ms: None,
            first_data: Vec::new(),
        }),
        now,
    );
    let _ = off_relay.take_event();
    off_relay.connect_done(&[1; 16], Ok(()), now);
    off_relay.on_frame(
        1,
        Frame::DgramBind(DgramBind {
            session_id: [1; 16],
            attach_gen: 0,
            nonce: [3; 16],
        }),
        now,
    );
    assert_eq!(off_relay.state(&[1; 16]), Some(SessionState::Active));
    assert_eq!(off_relay.dgram_peers(&[1; 16]), None);
}

#[test]
fn s1_non_ai_and_bulk_excluded_from_udp() {
    // Non-AI session (exit_class = 0): zero UDP binds or transmits.
    let cfg = Config {
        dgram: DgramConfig::for_ai_default(),
        ..Config::default()
    };
    let mut non_ai = SimPair::new(1, 0, cfg.clone(), LossKind::Clean, LossKind::Clean, 2);
    for _ in 0..10 {
        non_ai.flush_once();
        non_ai.now += Duration::from_millis(20);
    }
    assert!(!non_ai.client.dgram_enabled());
    assert!(!non_ai.client.dgram_bound());
    assert_eq!(non_ai.client.write(b"non-ai payload"), 14);
    for _ in 0..10 {
        non_ai.flush_once();
        non_ai.now += Duration::from_millis(20);
    }
    assert_eq!(non_ai.client.dgram_stats().tx_packets, 0);

    // AI session sending 64 KiB bulk (> max_frame_bytes 1024): bulk is NOT duplicated
    // onto UDP; subsequent small frame only goes onto UDP once bulk is ACKed.
    let mut ai = SimPair::new(
        2,
        segue_session::EXIT_CLASS_AI,
        cfg,
        LossKind::Clean,
        LossKind::Clean,
        2,
    );
    let sid = ai.client.session_id();
    ai.wait_bound(&sid, 2);
    let tx_before_bulk = ai.client.dgram_stats().tx_packets;
    let bulk = vec![0x7au8; 64 * 1024];
    let wrote = ai.client.write(&bulk);
    assert_eq!(wrote, bulk.len());
    ai.flush_once();
    // Large frame(s) + tail chunk must be held back by bulk_barrier -> 0 UDP DATA packets.
    assert_eq!(
        ai.client.dgram_stats().tx_packets,
        tx_before_bulk,
        "bulk bytes must not leak onto UDP"
    );
    // Let TCP carry & ACK the entire 64 KiB bulk transfer.
    let mut sink = vec![0u8; 32 * 1024];
    let mut total_read = 0usize;
    for _ in 0..100 {
        ai.flush_once();
        total_read += ai.relay.read(&sid, &mut sink, ai.now);
        if total_read == bulk.len() && ai.client.send_half().acked() == bulk.len() as u64 {
            break;
        }
        ai.now += Duration::from_millis(20);
    }
    assert_eq!(total_read, bulk.len());
    assert_eq!(ai.client.send_half().acked(), bulk.len() as u64);

    // Now a 48 B small token IS sent over UDP again.
    let small = vec![0x33u8; 48];
    assert_eq!(ai.client.write(&small), small.len());
    ai.flush_once();
    assert!(
        ai.client.dgram_stats().tx_packets > tx_before_bulk,
        "small frame after bulk ACK should accelerate on UDP"
    );
}

#[test]
fn s2_downlink_gilbert_k2_n2_meets_acceptance() {
    let m = run_gilbert_stream(1, true, 2);
    eprintln!("S2 downlink K=2, N=2: {m:?}");
    assert!(
        m.p50_ms <= 1.0,
        "S2 p50 added delay {:.2} ms exceeded 1 ms",
        m.p50_ms
    );
    assert!(
        m.p99_ms <= 15.0,
        "S2 p99 added delay {:.2} ms exceeded 15 ms",
        m.p99_ms
    );
    assert_eq!(
        m.stalls_gt_300ms, 0,
        "S2 had {} stalls > 300 ms (max {:.2} ms)",
        m.stalls_gt_300ms, m.max_ms
    );
    assert!(
        m.residual_pct <= 0.034,
        "S2 residual {:.4}% ({}/{}) exceeded 0.033%",
        m.residual_pct,
        m.residual_gt_rtt,
        m.total_frames
    );
}

#[test]
fn s2_downlink_gilbert_k1_n4_fallback() {
    let m = run_gilbert_stream(1, true, 1);
    eprintln!("S2 downlink K=1, N=4 fallback: {m:?}");
    assert!(
        m.p99_ms <= 40.0,
        "K=1 fallback p99 added delay {:.2} ms exceeded 40 ms",
        m.p99_ms
    );
    assert_eq!(
        m.stalls_gt_300ms, 0,
        "K=1 fallback had {} stalls > 300 ms (max {:.2} ms)",
        m.stalls_gt_300ms, m.max_ms
    );
}

#[test]
fn s3_uplink_gilbert_k2_n2_meets_acceptance() {
    let m = run_gilbert_stream(2, false, 2);
    eprintln!("S3 uplink K=2, N=2: {m:?}");
    assert!(
        m.p50_ms <= 1.0,
        "S2 p50 added delay {:.2} ms exceeded 1 ms",
        m.p50_ms
    );
    assert!(
        m.p99_ms <= 15.0,
        "S3 p99 added delay {:.2} ms exceeded 15 ms",
        m.p99_ms
    );
    assert_eq!(
        m.stalls_gt_300ms, 0,
        "S3 had {} stalls > 300 ms (max {:.2} ms)",
        m.stalls_gt_300ms, m.max_ms
    );
    assert!(
        m.residual_pct <= 0.034,
        "S3 residual {:.4}% ({}/{}) exceeded 0.033%",
        m.residual_pct,
        m.residual_gt_rtt,
        m.total_frames
    );
}

#[test]
fn s2_rate_and_packet_cap_shedding() {
    let cfg = Config {
        dgram: DgramConfig::for_ai_default(),
        ..Config::default()
    };
    // 250 small frames/s * 400 B -> > 32 KB/s byte cap & > 200 pkt/s under K=2.
    let mut sim = SimPair::new(
        5,
        segue_session::EXIT_CLASS_AI,
        cfg.clone(),
        LossKind::Clean,
        LossKind::Clean,
        2,
    );
    let sid = sim.client.session_id();
    sim.wait_bound(&sid, 2);

    let baseline = sim.client.dgram_stats();
    let t0 = sim.now;
    let payload = vec![0x42u8; 400];
    let mut sink = vec![0u8; 64 * 1024];
    let mut received = 0usize;
    let total_frames = 1250usize; // 5 s @ 250 frames/s

    for i in 0..total_frames {
        sim.now = t0 + Duration::from_millis((i as u64) * 4);
        assert_eq!(sim.client.write(&payload), payload.len());
        sim.flush_once();
        loop {
            let n = sim.relay.read(&sid, &mut sink, sim.now);
            if n == 0 {
                break;
            }
            received += n;
        }
    }
    for _ in 0..50 {
        sim.flush_once();
        loop {
            let n = sim.relay.read(&sid, &mut sink, sim.now);
            if n == 0 {
                break;
            }
            received += n;
        }
        if received == total_frames * payload.len() {
            break;
        }
        sim.now += Duration::from_millis(20);
    }

    assert_eq!(received, total_frames * payload.len());
    let st = sim.client.dgram_stats();
    let delta_bytes = st.tx_bytes - baseline.tx_bytes;
    let delta_pkts = st.tx_packets - baseline.tx_packets;
    // Allow at most the 1/8 s burst above steady-state 32 KB/s * 5 s + ACK overhead.
    let max_bytes_allowed = (u64::from(cfg.dgram.max_bytes_per_sec) * 5) + 8192;
    let max_pkts_allowed = (u64::from(cfg.dgram.max_packets_per_sec) * 5) + 40;
    assert!(
        delta_bytes <= max_bytes_allowed,
        "tx_bytes {delta_bytes} exceeded {max_bytes_allowed}"
    );
    assert!(
        delta_pkts <= max_pkts_allowed,
        "tx_packets {delta_pkts} exceeded {max_pkts_allowed}"
    );
    assert!(st.shed_n > 0, "expected N shedding, stats={st:?}");
    assert!(st.shed_k > 0, "expected K shedding, stats={st:?}");
}

#[test]
fn s2_udp_blackout_pauses_and_probe_recovers() {
    let cfg = Config {
        dgram: DgramConfig::for_ai_default(),
        ..Config::default()
    };
    let mut sim = SimPair::new(
        8,
        segue_session::EXIT_CLASS_AI,
        cfg,
        LossKind::Clean,
        LossKind::Clean,
        2,
    );
    let sid = sim.client.session_id();
    sim.wait_bound(&sid, 2);

    // Blackhole all UDP while continuing small frames over reliable TCP.
    sim.udp_blackhole = true;
    let mut sent = 0usize;
    let mut received = 0usize;
    let mut sink = vec![0u8; 4096];
    let mut blackout_pkts_after_pause = 0u64;
    let mut paused_at_pkts: Option<u64> = None;

    for step in 0..800 {
        let chunk = vec![(step & 0xff) as u8; 40];
        sent += sim.client.write(&chunk);
        sim.flush_once();
        received += sim.relay.read(&sid, &mut sink, sim.now);

        let st = sim.client.dgram_stats();
        if st.blackout_pauses >= 1 {
            if let Some(base) = paused_at_pkts {
                blackout_pkts_after_pause = st.tx_packets - base;
            } else {
                paused_at_pkts = Some(st.tx_packets);
            }
        }
        sim.now += Duration::from_millis(20);
    }

    let st_mid = sim.client.dgram_stats();
    assert!(
        st_mid.blackout_pauses >= 1,
        "expected UDP blackout pause, stats={st_mid:?}"
    );
    assert!(
        blackout_pkts_after_pause <= 3,
        "expected probe-only traffic during 14s blackout, got {blackout_pkts_after_pause}"
    );

    // Restore UDP and advance to the next probe interval: acceleration recovers.
    sim.udp_blackhole = false;
    for _ in 0..600 {
        sim.flush_once();
        if sim.client.dgram_stats().blackout_recoveries >= 1 {
            break;
        }
        sim.now += Duration::from_millis(25);
    }
    let st_end = sim.client.dgram_stats();
    assert!(
        st_end.blackout_recoveries >= 1,
        "expected probe recovery after UDP restored, stats={st_end:?}"
    );
    assert!(
        sim.client.write(b"post-recovery") == 13,
        "session must continue smoothly after recovery"
    );
    for _ in 0..20 {
        sim.flush_once();
        received += sim.relay.read(&sid, &mut sink, sim.now);
        sim.now += Duration::from_millis(20);
    }
    assert_eq!(received, sent + 13);
}

#[test]
fn s2_resume_rebinds_and_rejects_old_nonce() {
    let cfg = Config {
        dgram: DgramConfig::for_ai_default(),
        ..Config::default()
    };
    let mut sim = SimPair::new(
        11,
        segue_session::EXIT_CLASS_AI,
        cfg,
        LossKind::Clean,
        LossKind::Clean,
        2,
    );
    let sid = sim.client.session_id();
    sim.wait_bound(&sid, 2);

    // Capture a valid gen-0 packet before reattach.
    assert_eq!(sim.client.write(b"before"), 6);
    sim.flush_once();
    let mut old_pkt = Vec::new();
    let _ = encode_dgram_packet(
        &DgramPacket {
            header: DgramHeader {
                session_id: sid,
                attach_gen: 0,
                nonce: [0x99; 16],
            },
            body: DgramBody::Ack {
                recv_offset: 0,
                max_offset: 16_384,
                sacks: vec![],
                flags: 0,
            },
        },
        &mut old_pkt,
    );

    // Force a reliable carrier move (gen 0 -> 1).
    sim.client.reattach(sim.now);
    sim.client.attach(2, sim.now);
    sim.relay.add_carrier(2);
    for _ in 0..25 {
        let mut buf = Vec::new();
        while sim.client.poll_transmit_into(2, sim.now, &mut buf, 1 << 20)
            == segue_session::client::Tx::Wrote
        {
            let mut dec = FrameDecoder::new();
            dec.push(&buf);
            while let Some(f) = dec.next_frame().unwrap() {
                sim.relay.on_frame(2, f, sim.now);
            }
            buf.clear();
        }
        while let Some(f) = sim.relay.poll_transmit(2, sim.now) {
            let _ = sim.client.on_frame(2, f, sim.now);
        }
        if sim.client.gen() == 1 && sim.client.dgram_bound() {
            break;
        }
        sim.now += Duration::from_millis(20);
    }
    assert_eq!(sim.client.gen(), 1);
    assert!(sim.client.dgram_bound());

    // Old-generation / stale-nonce packets must be silently ignored.
    assert!(!sim.relay.on_dgram(peer_addr(0), &old_pkt, sim.now));
    assert!(!sim.client.on_dgram(0, &old_pkt, sim.now));
}

#[tokio::test]
async fn s4_loopback_impaired_tcp_and_dual_udp_eliminates_stalls() {
    s4_e2e::run().await;
}

mod s4_e2e {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::{mpsc, oneshot};

    use segue_session::client::{ClientSession, OpenParams};
    use segue_session::codec::{Kind, Target};
    use segue_session::driver::{
        run_client_standby, run_relay_ctl_dgram, BoxCarrier, ClientCtl, Connector,
        DeviceSiteConnector, DgramCtl, DgramFlow, SiteRequest,
    };
    use segue_session::pool::Pool;
    use segue_session::relay::{AllowAll, RelayTable};
    use segue_session::{Config, DgramConfig, EXIT_CLASS_AI};

    #[derive(Clone, Copy)]
    struct SplitMix64(u64);
    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn next_f64(&mut self) -> f64 {
            (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
        }
    }

    /// Two-state Gilbert-Elliott loss model tuned for 7.5% stationary loss:
    /// P(G->B) = 0.03, P(B->G) = 0.27 -> pi(B) = 0.10, loss(B) = 0.75 => 7.5% loss.
    struct GilbertElliott {
        rng: SplitMix64,
        bad: bool,
    }
    impl GilbertElliott {
        fn new(seed: u64) -> Self {
            Self {
                rng: SplitMix64(seed),
                bad: false,
            }
        }
        fn should_drop(&mut self) -> bool {
            let p_switch = self.rng.next_f64();
            if self.bad {
                if p_switch < 0.27 {
                    self.bad = false;
                }
            } else if p_switch < 0.03 {
                self.bad = true;
            }
            if self.bad {
                self.rng.next_f64() < 0.75
            } else {
                false
            }
        }
    }

    /// Loopback TCP proxy enforcing `one_way` delay both ways and one `stall_dur`
    /// hole on the relay->client stream after `stall_after_bytes` payload bytes.
    async fn spawn_tcp_stall_forwarder(
        target: SocketAddr,
        one_way: Duration,
        stall_after_bytes: usize,
        stall_dur: Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((cli, _)) = listener.accept().await else {
                    break;
                };
                let _ = cli.set_nodelay(true);
                let Ok(srv) = TcpStream::connect(target).await else {
                    continue;
                };
                let _ = srv.set_nodelay(true);
                let (cr, cw) = cli.into_split();
                let (sr, sw) = srv.into_split();
                tokio::spawn(pipe_delayed(cr, sw, one_way, None));
                tokio::spawn(pipe_delayed(
                    sr,
                    cw,
                    one_way,
                    Some((stall_after_bytes, stall_dur)),
                ));
            }
        });
        (addr, task)
    }

    async fn pipe_delayed<R, W>(
        mut r: R,
        mut w: W,
        one_way: Duration,
        stall: Option<(usize, Duration)>,
    ) where
        R: AsyncReadExt + Unpin + Send + 'static,
        W: AsyncWriteExt + Unpin + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
        tokio::spawn(async move {
            let mut stalled = false;
            let mut sent = 0usize;
            while let Some((due, data)) = rx.recv().await {
                let mut wait_until = due;
                if let Some((after_bytes, stall_len)) = stall {
                    if !stalled && sent >= after_bytes {
                        stalled = true;
                        wait_until = wait_until.max(tokio::time::Instant::now() + stall_len);
                    }
                }
                tokio::time::sleep_until(wait_until).await;
                if w.write_all(&data).await.is_err() {
                    break;
                }
                sent += data.len();
            }
        });
        let mut buf = vec![0u8; 8192];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let due = tokio::time::Instant::now() + one_way;
                    if tx.send((due, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    }

    /// Independent loopback UDP path between `client_peer` and `relay_addr` with
    /// per-direction `one_way` latency and independent Gilbert-Elliott 7.5% loss.
    async fn spawn_udp_ge_forwarder(
        client_peer: SocketAddr,
        relay_addr: SocketAddr,
        one_way: Duration,
        seed_up: u64,
        seed_down: u64,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let fwd_cli = Arc::new(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap(),
        );
        let fwd_rel = Arc::new(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap(),
        );
        let fwd_cli_addr = fwd_cli.local_addr().unwrap();

        let (up_tx, mut up_rx) = mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(512);
        let (dn_tx, mut dn_rx) = mpsc::channel::<(tokio::time::Instant, Vec<u8>)>(512);

        let task = tokio::spawn(async move {
            let fwd_rel_w = fwd_rel.clone();
            let up_writer = tokio::spawn(async move {
                while let Some((due, pkt)) = up_rx.recv().await {
                    tokio::time::sleep_until(due).await;
                    let _ = fwd_rel_w.send_to(&pkt, relay_addr).await;
                }
            });
            let fwd_cli_w = fwd_cli.clone();
            let dn_writer = tokio::spawn(async move {
                while let Some((due, pkt)) = dn_rx.recv().await {
                    tokio::time::sleep_until(due).await;
                    let _ = fwd_cli_w.send_to(&pkt, client_peer).await;
                }
            });
            let up_reader = tokio::spawn(async move {
                let mut ge = GilbertElliott::new(seed_up);
                let mut buf = vec![0u8; 2048];
                while let Ok((n, _)) = fwd_cli.recv_from(&mut buf).await {
                    if n > 0 && !ge.should_drop() {
                        let _ = up_tx
                            .try_send((tokio::time::Instant::now() + one_way, buf[..n].to_vec()));
                    }
                }
            });
            let mut ge = GilbertElliott::new(seed_down);
            let mut buf = vec![0u8; 2048];
            while let Ok((n, _)) = fwd_rel.recv_from(&mut buf).await {
                if n > 0 && !ge.should_drop() {
                    let _ =
                        dn_tx.try_send((tokio::time::Instant::now() + one_way, buf[..n].to_vec()));
                }
            }
            up_writer.abort();
            dn_writer.abort();
            up_reader.abort();
        });
        (fwd_cli_addr, task)
    }

    struct RunStats {
        p50_total_ms: f64,
        p99_total_ms: f64,
        p99_added_ms: f64,
        max_added_ms: f64,
        max_gap_ms: f64,
        stalls_gt_1000ms: usize,
    }

    async fn run_case(use_dgram: bool) -> RunStats {
        const CHUNK_BYTES: usize = 100;
        const CHUNKS: usize = 160;
        let one_way = Duration::from_millis(85);
        let chunk_period = Duration::from_millis(20);

        let relay_listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let relay_tcp_addr = relay_listener.local_addr().unwrap();
        let relay_udp = Arc::new(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap(),
        );
        let relay_udp_addr = relay_udp.local_addr().unwrap();

        let (fwd_tcp_addr, fwd_tcp_task) = spawn_tcp_stall_forwarder(
            relay_tcp_addr,
            one_way,
            40 * CHUNK_BYTES,
            Duration::from_millis(1500),
        )
        .await;

        let mut cfg = Config::default();
        if use_dgram {
            cfg.dgram = DgramConfig::for_ai_default();
        }
        let relay_cfg = cfg.clone();

        let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(16);
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((s, _)) = relay_listener.accept().await else {
                    break;
                };
                let _ = s.set_nodelay(true);
                if accept_tx.send(Box::new(s)).await.is_err() {
                    break;
                }
            }
        });

        let expected: Vec<Vec<u8>> = (0..CHUNKS)
            .map(|idx| {
                let mut v = vec![((idx as u8).wrapping_mul(31)).wrapping_add(7); CHUNK_BYTES];
                v[..4].copy_from_slice(&(idx as u32).to_le_bytes());
                v
            })
            .collect();
        let send_times: Arc<Mutex<Vec<Option<tokio::time::Instant>>>> =
            Arc::new(Mutex::new(vec![None; CHUNKS]));

        let site_expected = expected.clone();
        let site_times = send_times.clone();
        let site: DeviceSiteConnector = Arc::new(move |_req: SiteRequest| {
            let chunks = site_expected.clone();
            let times = site_times.clone();
            Box::pin(async move {
                let (app, far) = tokio::io::duplex(64 << 10);
                tokio::spawn(async move {
                    let (mut r, mut w) = tokio::io::split(far);
                    let mut start = [0u8; 5];
                    if r.read_exact(&mut start).await.is_err() {
                        return;
                    }
                    for (idx, chunk) in chunks.iter().enumerate() {
                        times.lock().unwrap()[idx] = Some(tokio::time::Instant::now());
                        if w.write_all(chunk).await.is_err() {
                            return;
                        }
                        if idx + 1 < chunks.len() {
                            tokio::time::sleep(chunk_period).await;
                        }
                    }
                    let _ = w.shutdown().await;
                });
                Ok(Box::new(app) as BoxCarrier)
            })
        });

        let table = RelayTable::new(relay_cfg, Pool::new(8 << 20), Box::new(AllowAll), 9);
        let relay_task = tokio::spawn(run_relay_ctl_dgram(
            table,
            accept_rx,
            site,
            None,
            None,
            use_dgram.then_some(relay_udp),
        ));

        let mut fwd_udp_tasks = Vec::new();
        let dgram_ctl = if use_dgram {
            let mut endpoints = Vec::with_capacity(2);
            for f in 0usize..2 {
                let csock = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                    .await
                    .unwrap();
                let caddr = csock.local_addr().unwrap();
                let (fwd_addr, fwd_task) = spawn_udp_ge_forwarder(
                    caddr,
                    relay_udp_addr,
                    one_way,
                    0x1000_0000_u64 + (f as u64) * 100 + 1,
                    0x2000_0000_u64 + (f as u64) * 100 + 2,
                )
                .await;
                fwd_udp_tasks.push(fwd_task);
                endpoints.push((Arc::new(Mutex::new(Some(csock))), fwd_addr));
            }
            let ep = Arc::new(endpoints);
            Some(DgramCtl {
                open: Arc::new(move |idx| {
                    let ep = ep.clone();
                    Box::pin(async move {
                        let slot = ep.get(idx).ok_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad flow")
                        })?;
                        let sock = slot
                            .0
                            .lock()
                            .unwrap()
                            .take()
                            .ok_or_else(|| std::io::Error::other("socket already taken"))?;
                        sock.connect(slot.1).await?;
                        Ok(DgramFlow::from_udp_socket(sock))
                    })
                }),
                flows: 2,
            })
        } else {
            None
        };

        let pool = Pool::new(8 << 20);
        let params = OpenParams {
            ticket: b"loopback-s4".to_vec(),
            kind: Kind::Tcp,
            target: Target::Domain("api.anthropic.com".into(), 443),
            exit_class: EXIT_CLASS_AI,
            anchor_node_id: 9,
            instance_hint: 0,
        };
        let sess = ClientSession::new(cfg, &pool, params, Instant::now()).unwrap();
        let (mut app, far) = tokio::io::duplex(64 << 10);
        let (open_tx, open_rx) = oneshot::channel();
        let connector: Connector = Arc::new(move || {
            Box::pin(async move {
                let s = TcpStream::connect(fwd_tcp_addr).await?;
                let _ = s.set_nodelay(true);
                Ok(Box::new(s) as BoxCarrier)
            })
        });
        let ctl = ClientCtl {
            opened: Some(open_tx),
            dgram: dgram_ctl,
            ..Default::default()
        };
        let client_task = tokio::spawn(run_client_standby(sess, far, connector, ctl));

        tokio::time::timeout(Duration::from_secs(5), open_rx)
            .await
            .expect("open timeout")
            .expect("opened dropped");
        // Allow UDP flows on loopback through the 85 ms forwarders to dial and bind.
        if use_dgram {
            tokio::time::sleep(Duration::from_millis(320)).await;
        }
        app.write_all(b"START").await.unwrap();

        let mut received = Vec::with_capacity(CHUNKS * CHUNK_BYTES);
        let mut recv_times = Vec::with_capacity(CHUNKS);
        let mut tmp = [0u8; 4096];
        let mut next_chunk_end = CHUNK_BYTES;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        while received.len() < CHUNKS * CHUNK_BYTES {
            let n = tokio::time::timeout_at(deadline, app.read(&mut tmp))
                .await
                .expect("stream read timed out")
                .expect("stream read error");
            assert!(n > 0, "unexpected EOF at {} bytes", received.len());
            let now_rx = tokio::time::Instant::now();
            received.extend_from_slice(&tmp[..n]);
            while received.len() >= next_chunk_end {
                recv_times.push(now_rx);
                next_chunk_end += CHUNK_BYTES;
            }
        }
        let expected_flat: Vec<u8> = expected.iter().flatten().copied().collect();
        assert_eq!(received, expected_flat, "stream bytes must match 100%");
        let _ = app.shutdown().await;

        let mut totals_ms = Vec::with_capacity(CHUNKS);
        let mut added_ms = Vec::with_capacity(CHUNKS);
        {
            let times = send_times.lock().unwrap();
            for i in 0..CHUNKS {
                let sent_at = times[i].expect("missing send timestamp");
                let tot = recv_times[i].saturating_duration_since(sent_at);
                let tot_f = tot.as_secs_f64() * 1000.0;
                let add_f = (tot.saturating_sub(one_way)).as_secs_f64() * 1000.0;
                totals_ms.push(tot_f);
                added_ms.push(add_f);
            }
        }
        let mut max_gap_ms = 0.0f64;
        let mut stalls_gt_1000ms = 0usize;
        for w in recv_times.windows(2) {
            let gap_ms = w[1].saturating_duration_since(w[0]).as_secs_f64() * 1000.0;
            if gap_ms > max_gap_ms {
                max_gap_ms = gap_ms;
            }
            if gap_ms > 1000.0 {
                stalls_gt_1000ms += 1;
            }
        }
        totals_ms.sort_by(|a, b| a.total_cmp(b));
        added_ms.sort_by(|a, b| a.total_cmp(b));
        let p50_total_ms = totals_ms[totals_ms.len() / 2];
        let p99_idx = ((totals_ms.len() * 99) / 100).min(totals_ms.len() - 1);
        let p99_total_ms = totals_ms[p99_idx];
        let p99_added_ms = added_ms[p99_idx];
        let max_added_ms = *added_ms.last().unwrap();

        client_task.abort();
        relay_task.abort();
        accept_task.abort();
        fwd_tcp_task.abort();
        for t in fwd_udp_tasks {
            t.abort();
        }

        RunStats {
            p50_total_ms,
            p99_total_ms,
            p99_added_ms,
            max_added_ms,
            max_gap_ms,
            stalls_gt_1000ms,
        }
    }

    pub async fn run() {
        let tcp_only = run_case(false).await;
        eprintln!(
            "S4 loopback TCP-only: p50_total={:.1}ms p99_total={:.1}ms p99_added={:.1}ms max_added={:.1}ms max_gap={:.1}ms stalls>1s={}",
            tcp_only.p50_total_ms,
            tcp_only.p99_total_ms,
            tcp_only.p99_added_ms,
            tcp_only.max_added_ms,
            tcp_only.max_gap_ms,
            tcp_only.stalls_gt_1000ms
        );
        assert!(
            tcp_only.stalls_gt_1000ms >= 1,
            "TCP-only run should exhibit >= 1 stall > 1000 ms, got max_gap={:.1}ms",
            tcp_only.max_gap_ms
        );

        let accelerated = run_case(true).await;
        eprintln!(
            "S4 loopback TCP+2xUDP(GE 7.5%): p50_total={:.1}ms p99_total={:.1}ms p99_added={:.1}ms max_added={:.1}ms max_gap={:.1}ms stalls>1s={}",
            accelerated.p50_total_ms,
            accelerated.p99_total_ms,
            accelerated.p99_added_ms,
            accelerated.max_added_ms,
            accelerated.max_gap_ms,
            accelerated.stalls_gt_1000ms
        );
        assert_eq!(
            accelerated.stalls_gt_1000ms, 0,
            "TCP+dual UDP must eliminate >1000 ms stalls (max_gap={:.1}ms)",
            accelerated.max_gap_ms
        );
        assert!(
            accelerated.p99_added_ms <= 255.0,
            "TCP+dual UDP p99 added delay {:.1}ms exceeded 255 ms",
            accelerated.p99_added_ms
        );
    }
}
