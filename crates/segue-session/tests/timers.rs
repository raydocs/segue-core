//! Timer behaviour: no deadline that is already due survives
//! `handle_timeout` (a driver would spin on it), and the absolute session
//! lifetime (§5.2 `max_lifetime`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use segue_session::client::{ClientSession, CloseReason, OpenParams, State};
use segue_session::codec::{code, Frame, Kind, Reject, Resume, SessionId, Target};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayEvent, RelayTable};
use segue_session::Config;

const INSTANCE: u64 = 11;
const SID: SessionId = [7; 16];
const SECRET: [u8; 32] = [9; 32];

fn params() -> OpenParams {
    OpenParams {
        ticket: b"ticket".to_vec(),
        kind: Kind::Tcp,
        target: Target::Domain("example.com".into(), 443),
        exit_class: 1,
        anchor_node_id: 5,
        instance_hint: INSTANCE,
    }
}

fn client(now: Instant) -> ClientSession {
    ClientSession::with_ids(
        Config::default(),
        &Pool::new(1 << 20),
        params(),
        SID,
        SECRET,
        now,
    )
    .unwrap()
}

/// After `handle_timeout(t)` the next deadline is strictly later than `t`.
fn assert_client_settled(c: &mut ClientSession, t: Instant) {
    c.handle_timeout(t);
    if let Some(d) = c.poll_timeout() {
        assert!(d > t, "client deadline {:?} not after {:?}", d - t, t);
    }
}

fn assert_relay_settled(r: &mut RelayTable, t: Instant) {
    r.handle_timeout(t);
    if let Some(d) = r.poll_timeout() {
        assert!(d > t, "relay deadline already due");
    }
}

#[test]
fn client_passed_backoff_is_not_a_deadline_while_connecting() {
    let t0 = Instant::now();
    let mut c = client(t0);
    c.write(b"hello");
    c.attach(1, t0);
    let open = c.poll_transmit(1, t0).expect("OPEN");
    assert!(matches!(open, Frame::Open(_)));
    // B2: anchor unreachable → retry after a backoff.
    c.on_frame(
        1,
        Frame::Reject(Reject {
            code: code::ANCHOR_UNREACHABLE,
            attach_gen: 0,
            closed: None,
        }),
        t0,
    )
    .unwrap();
    assert!(!c.wants_attach(t0));
    // Backoff over: the caller starts a connect, which is slow. Until it
    // completes, no deadline may be in the past.
    let t1 = t0 + Duration::from_millis(500);
    assert_client_settled(&mut c, t1);
    assert!(c.wants_attach(t1));
    for ms in [501, 510, 900, 1500] {
        assert_client_settled(&mut c, t0 + Duration::from_millis(ms));
    }
}

#[test]
fn relay_does_not_arm_ack_before_the_site_connects() {
    let t0 = Instant::now();
    let mut c = client(t0);
    c.write(b"first bytes travel in OPEN");
    c.attach(1, t0);
    let open = c.poll_transmit(1, t0).unwrap();
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    r.add_carrier(1);
    r.on_frame(1, open, t0);
    assert!(matches!(r.take_event(), Some(RelayEvent::Connect { .. })));
    // The site connect is slow: the relay holds the ACK until connected.
    for ms in [0, 1, 25, 100, 1000] {
        let t = t0 + Duration::from_millis(ms);
        assert_relay_settled(&mut r, t);
        assert!(r.poll_transmit(1, t).is_none());
    }
    r.connect_done(&SID, Ok(()), t0 + Duration::from_secs(1));
    assert!(matches!(
        r.poll_transmit(1, t0 + Duration::from_secs(1)),
        Some(Frame::Opened(_))
    ));
}

#[test]
fn unread_buffered_data_does_not_keep_an_idle_deadline_due() {
    // The site never reads: the relay's receive buffer holds data, so the
    // idle shrink does nothing and its deadline must not stay armed.
    let t0 = Instant::now();
    let mut c = client(t0);
    c.write(&[1u8; 8000]);
    c.attach(1, t0);
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    r.add_carrier(1);
    let open = c.poll_transmit(1, t0).unwrap();
    r.on_frame(1, open, t0);
    let _ = r.take_event();
    r.connect_done(&SID, Ok(()), t0);
    while let Some(f) = r.poll_transmit(1, t0) {
        c.on_frame(1, f, t0).unwrap();
    }
    while let Some(f) = c.poll_transmit(1, t0) {
        r.on_frame(1, f, t0);
    }
    for s in [1, 2, 5, 10] {
        assert_relay_settled(&mut r, t0 + Duration::from_secs(s));
    }
}

fn relay_with_session(t0: Instant) -> (RelayTable, ClientSession) {
    let mut c = client(t0);
    c.attach(1, t0);
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    r.add_carrier(1);
    r.on_frame(1, c.poll_transmit(1, t0).unwrap(), t0);
    let _ = r.take_event();
    r.connect_done(&SID, Ok(()), t0);
    while let Some(f) = r.poll_transmit(1, t0) {
        c.on_frame(1, f, t0).unwrap();
    }
    assert_eq!(c.state(), State::Active);
    (r, c)
}

#[test]
fn session_is_reset_at_max_lifetime_even_when_resumed() {
    let t0 = Instant::now();
    let life = Config::default().timing.max_lifetime;
    assert_eq!(life, Duration::from_secs(24 * 3600));
    let (mut r, mut c) = relay_with_session(t0);
    // Resume every few hours on a fresh carrier: none of them extends the
    // lifetime.
    let mut cid = 1;
    let mut t = t0;
    for _ in 0..7 {
        t += Duration::from_secs(3 * 3600);
        r.handle_timeout(t);
        assert!(r.state(&SID).is_some(), "closed before max_lifetime");
        c.reattach(t);
        cid += 1;
        c.attach(cid, t);
        r.add_carrier(cid);
        while let Some(f) = c.poll_transmit(cid, t) {
            assert!(matches!(f, Frame::Resume(Resume { .. })));
            r.on_frame(cid, f, t);
        }
        while let Some(f) = r.poll_transmit(cid, t) {
            c.on_frame(cid, f, t).unwrap();
        }
        assert_eq!(c.state(), State::Active);
    }
    // 21 h: still open; the next deadline is the absolute lifetime.
    assert_eq!(r.state(&SID).map(|_| ()), Some(()));
    assert!(r.poll_timeout().unwrap() <= t0 + life);
    let just_before = t0 + life - Duration::from_millis(1);
    r.handle_timeout(just_before);
    assert!(r.state(&SID).is_some());
    r.handle_timeout(t0 + life);
    assert!(r.state(&SID).is_none(), "session outlived max_lifetime");
    let rst = r.poll_transmit(cid, t0 + life).expect("RST on the carrier");
    assert_eq!(
        rst,
        Frame::Rst {
            code: code::MAX_LIFETIME
        }
    );
    assert!(r.take_closed_carriers().contains(&cid));
    let mut closed = None;
    while let Some(ev) = r.take_event() {
        if let RelayEvent::Closed { close_code, .. } = ev {
            closed = Some(close_code);
        }
    }
    assert_eq!(closed, Some(code::MAX_LIFETIME));
    c.on_frame(cid, rst, t0 + life).unwrap();
    assert_eq!(
        c.close_reason(),
        Some(CloseReason::Reset(code::MAX_LIFETIME))
    );
}

#[test]
fn detached_session_past_max_lifetime_rejects_resume_with_max_lifetime() {
    let t0 = Instant::now();
    let mut cfg = Config::default();
    cfg.timing.max_lifetime = Duration::from_secs(60);
    let mut c =
        ClientSession::with_ids(cfg.clone(), &Pool::new(1 << 20), params(), SID, SECRET, t0)
            .unwrap();
    c.attach(1, t0);
    let mut r = RelayTable::new(
        cfg,
        Arc::clone(&Pool::new(1 << 20)),
        Box::new(AllowAll),
        INSTANCE,
    );
    r.add_carrier(1);
    r.on_frame(1, c.poll_transmit(1, t0).unwrap(), t0);
    let _ = r.take_event();
    r.connect_done(&SID, Ok(()), t0);
    while let Some(f) = r.poll_transmit(1, t0) {
        c.on_frame(1, f, t0).unwrap();
    }
    // Carrier lost; the client resumes just after the lifetime ran out.
    let t = t0 + Duration::from_secs(20);
    r.on_carrier_closed(1, t);
    c.on_carrier_closed(1, t);
    let t = t0 + Duration::from_secs(60);
    r.handle_timeout(t);
    c.attach(2, t);
    r.add_carrier(2);
    while let Some(f) = c.poll_transmit(2, t) {
        r.on_frame(2, f, t);
    }
    while let Some(f) = r.poll_transmit(2, t) {
        let _ = c.on_frame(2, f, t);
    }
    assert_eq!(
        c.close_reason(),
        Some(CloseReason::Reset(code::MAX_LIFETIME))
    );
}

#[test]
fn control_stream_answers_ping_and_carries_stall_and_revoked() {
    use segue_session::codec::{ty, CtrlHello, CtrlHelloReply, VERSION};
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    r.add_carrier(1);
    r.on_frame(1, c.poll_transmit(1, t0).unwrap(), t0);
    let _ = r.take_event();
    r.connect_done(&SID, Ok(()), t0);
    while let Some(f) = r.poll_transmit(1, t0) {
        c.on_frame(1, f, t0).unwrap();
    }
    // Control stream.
    r.add_carrier(9);
    let hello = CtrlHello {
        version: VERSION,
        ticket: b"ticket".to_vec(),
        held_anchors: vec![5],
    };
    r.on_frame(9, hello.to_frame(), t0);
    match r.poll_transmit(9, t0) {
        Some(Frame::Control { ty: t, payload }) if t == ty::CTRL_HELLO => {
            assert_eq!(
                CtrlHelloReply::parse(&payload).unwrap().instance_id,
                INSTANCE
            );
        }
        f => panic!("expected CTRL_HELLO reply, got {f:?}"),
    }
    r.on_frame(9, Frame::Ping { nonce: 42 }, t0);
    assert_eq!(
        r.poll_transmit(9, t0),
        Some(Frame::Pong {
            nonce: 42,
            extra: vec![]
        })
    );
    // Downstream data that is never acknowledged: after T_live, STALL on
    // the control stream (B1), and the client acts on it.
    r.site_data(&SID, &[7u8; 1000]);
    while r.poll_transmit(1, t0).is_some() {}
    let t = t0 + Config::default().timing.t_live_ai;
    r.handle_timeout(t);
    let stall = r.poll_transmit(9, t).expect("STALL");
    let Frame::Stall(entries) = stall else {
        panic!("expected STALL, got {stall:?}")
    };
    assert_eq!(entries, vec![(SID, c.gen())]);
    c.on_stall(entries[0].1, t);
    // AI does not abandon the carrier on the hint until it has been quiet
    // for `t_stall_ai`, spare or not. The hint above arrived at that bound,
    // so it already counted. A stalled carrier counts against the redial
    // bound (r9 F2) even with nothing to upload.
    let t = t0 + Config::default().timing.t_stall_ai;
    c.handle_timeout(t);
    assert_eq!(c.fruitless_carriers(), 1);
    assert!(c.wants_attach(t + segue_session::client::RECONNECT_BACKOFF));
    // Device reset: REVOKED on the control stream, which then closes.
    r.reset_device(0, code::REVOKED);
    let mut got_revoked = false;
    while let Some(f) = r.poll_transmit(9, t) {
        got_revoked |= matches!(f, Frame::Control { ty: t, .. } if t == ty::REVOKED);
    }
    assert!(got_revoked);
    assert!(r.take_closed_carriers().contains(&9));
}

/// Review r5 N11: one valid ticket repeating CTRL_HELLO cannot pile up
/// control streams. The device keeps at most `MAX_CTRL_PER_DEVICE` (a
/// newcomer beyond it replaces only a quiet stream, else it is closed), a
/// stream that stops sending is closed after `t_ctrl_idle`, and none
/// outlives `max_lifetime`.
#[test]
fn control_streams_are_bounded_per_device_and_expire() {
    use segue_session::codec::{CtrlHello, VERSION};
    use segue_session::relay::{ctrl_quiet, MAX_CTRL_PER_DEVICE};
    let t0 = Instant::now();
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let hello = CtrlHello {
        version: VERSION,
        ticket: b"ticket".to_vec(),
        held_anchors: vec![],
    };
    let n = 2 * MAX_CTRL_PER_DEVICE as u64;
    let mut closed = std::collections::HashSet::new();
    let hello_at = |r: &mut RelayTable, cid: u64, t: Instant| {
        r.add_carrier(cid);
        r.on_frame(cid, hello.to_frame(), t);
        let gone = r.take_closed_carriers();
        // A closed carrier leaves the table once the driver drops it.
        for &c in &gone {
            r.on_carrier_closed(c, t);
        }
        gone
    };
    for cid in 1..=n {
        closed.extend(hello_at(&mut r, cid, t0));
    }
    let live: Vec<u64> = (1..=n).filter(|c| !closed.contains(c)).collect();
    assert_eq!(live.len(), MAX_CTRL_PER_DEVICE, "live control streams");
    // Once the first ones went quiet, newcomers replace exactly those.
    let quiet = ctrl_quiet(&Config::default().timing);
    let tq = t0 + quiet;
    for &c in &live[2..] {
        r.on_frame(c, Frame::Ping { nonce: 0 }, tq);
        while r.poll_transmit(c, tq).is_some() {}
    }
    let mut closed = std::collections::HashSet::new();
    for cid in n + 1..=n + 3 {
        closed.extend(hello_at(&mut r, cid, tq));
    }
    let want: std::collections::HashSet<u64> = [live[0], live[1], n + 3].into();
    assert_eq!(closed, want, "quiet streams replaced, live ones kept");
    let live: Vec<u64> = live[2..].iter().copied().chain([n + 1, n + 2]).collect();
    // Idle: one stream keeps pinging, the others go silent.
    let timing = Config::default().timing;
    let keep = *live.last().unwrap();
    let mut t = tq;
    let step = Duration::from_secs(5);
    while t < tq + timing.t_ctrl_idle + step {
        t += step;
        r.on_frame(keep, Frame::Ping { nonce: 1 }, t);
        while r.poll_transmit(keep, t).is_some() {}
        assert_relay_settled(&mut r, t);
    }
    let gone = r.take_closed_carriers();
    for c in &live[..live.len() - 1] {
        assert!(gone.contains(c), "idle control stream {c} not closed");
    }
    assert!(!gone.contains(&keep), "live control stream closed");
    // Even a pinging stream ends at max_lifetime.
    let end = tq + timing.max_lifetime;
    r.on_frame(keep, Frame::Ping { nonce: 2 }, end - Duration::from_secs(1));
    assert!(r.poll_timeout().is_some_and(|d| d <= end));
    assert_relay_settled(&mut r, end);
    assert!(r.take_closed_carriers().contains(&keep));
}

/// Review r6 R8: a device with more exits on one relay than the old cap
/// (one control stream each, all pinging, each reconnecting as soon as it
/// is closed) must not kick its own channels. With 5 such exits and the
/// old cap of 4, every reconnect closed another live stream, forever.
#[test]
fn live_control_streams_of_many_exits_are_not_kicked() {
    use segue_session::codec::{CtrlHello, VERSION};
    let t0 = Instant::now();
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    let hello = CtrlHello {
        version: VERSION,
        ticket: b"ticket".to_vec(),
        held_anchors: vec![],
    };
    let exits = 5usize;
    // exit i -> its current carrier
    let mut cur: Vec<u64> = Vec::new();
    let mut next_cid = 1u64;
    let mut kicked = 0;
    let mut t = t0;
    for round in 0..40 {
        t += Duration::from_secs(1);
        // Every exit without a stream (re)connects, like run_control.
        while cur.len() < exits {
            r.add_carrier(next_cid);
            r.on_frame(next_cid, hello.to_frame(), t);
            cur.push(next_cid);
            next_cid += 1;
        }
        // Every stream pings each round.
        for &c in &cur {
            r.on_frame(c, Frame::Ping { nonce: round }, t);
            while r.poll_transmit(c, t).is_some() {}
        }
        let gone = r.take_closed_carriers();
        for &c in &gone {
            r.on_carrier_closed(c, t);
        }
        kicked += gone.len();
        cur.retain(|c| !gone.contains(c));
    }
    assert_eq!(kicked, 0, "live control streams closed");
    assert_eq!(next_cid as usize - 1, exits, "streams reconnected");
}

/// A relay with the FIN held for the site writer and site data out that
/// the client never acknowledges, plus the client whose OPEN made it.
fn held_fin_relay(t0: Instant, relay_cfg: Config, client_cfg: Config) -> RelayTable {
    let mut c = ClientSession::with_ids(client_cfg, &Pool::new(1 << 20), params(), SID, SECRET, t0)
        .unwrap();
    c.attach(1, t0);
    let mut r = RelayTable::new(relay_cfg, Pool::new(1 << 20), Box::new(AllowAll), INSTANCE);
    r.confirm_site_flush(true);
    r.add_carrier(1);
    r.on_frame(1, c.poll_transmit(1, t0).unwrap(), t0);
    let _ = r.take_event();
    r.connect_done(&SID, Ok(()), t0);
    r.on_frame(1, Frame::Fin { offset: 0 }, t0);
    r.site_data(&SID, &[7u8; 1000]);
    while r.poll_transmit(1, t0).is_some() {}
    r
}

/// Drive `r` like its driver for `span` from `t`: wake at each deadline,
/// handle it, send what carrier 1 has. Returns the wake-ups at which the
/// deadline was already due (each one a lap of a spinning driver).
fn spins(r: &mut RelayTable, mut t: Instant, span: Duration) -> usize {
    let end = t + span;
    let mut due = 0;
    while t < end && due < 1000 {
        r.handle_timeout(t);
        while r.poll_transmit(1, t).is_some() {}
        match r.poll_timeout() {
            Some(d) if d <= t => due += 1,
            Some(d) => t = d,
            None => break,
        }
    }
    due
}

/// r9 F3: with the client's FIN held and the session DETACHED (nothing is
/// acknowledged for `t_live`), the held-FIN keepalive cannot go out
/// (`poll_transmit` sends nothing while detached). Before, its deadline
/// stayed in the past and the driver woke in a loop until `t_detached`.
#[test]
fn a_held_fin_keepalive_is_no_deadline_while_detached() {
    let t0 = Instant::now();
    let mut r = held_fin_relay(t0, Config::default(), Config::default());
    let t = t0 + Config::default().timing.t_live_ai;
    r.handle_timeout(t);
    assert_eq!(
        r.state(&SID),
        Some(segue_session::relay::SessionState::Detached)
    );
    assert_eq!(spins(&mut r, t, Duration::from_secs(5)), 0);
}

/// r9 F3: while the carrier's writer is full the driver asks with
/// `poll_timeout_writable`: deadlines only sending can serve (the
/// keepalive, a delayed ACK) are left out, nothing else is.
#[test]
fn deadlines_served_by_sending_wait_for_a_writable_carrier() {
    let t0 = Instant::now();
    let r = held_fin_relay(t0, Config::default(), Config::default());
    let ka = r.keepalive(&SID).unwrap();
    let t = t0 + ka;
    let free = r.poll_timeout_writable(|_| true).unwrap();
    assert!(free <= t, "keepalive not due with room");
    let blocked = r.poll_timeout_writable(|_| false).unwrap();
    assert!(
        blocked > t,
        "a blocked carrier's keepalive kept a due deadline"
    );
    // Still bounded by the session's own timers (t_live_ai: this session is AI).
    assert!(blocked <= t0 + Config::default().timing.t_live_ai);
}

/// r9 (keepalive assumption): the relay keeps alive at half the shorter
/// of its own and the client's announced `t_stall`, with a floor.
#[test]
fn relay_keepalive_follows_the_shorter_stall_bound() {
    let t0 = Instant::now();
    let with = |relay_ms: u64, client_ms: u64| {
        let mut rc = Config::default();
        rc.timing.t_stall = Duration::from_millis(relay_ms);
        let mut cc = Config::default();
        cc.timing.t_stall = Duration::from_millis(client_ms);
        // The client is AI, so the wire field is `t_stall_ai`, not `t_stall`.
        cc.timing.t_stall_ai = Duration::from_millis(client_ms);
        held_fin_relay(t0, rc, cc).keepalive(&SID).unwrap()
    };
    assert_eq!(with(4000, 1000), Duration::from_millis(500));
    assert_eq!(with(1000, 4000), Duration::from_millis(500));
    assert_eq!(
        with(4000, 1),
        segue_session::relay::MIN_CLIENT_STALL / 2,
        "a client cannot make the relay send ACKs in a loop"
    );
}

/// r10 N3: a client `t_stall` below what a relay serves keepalives for
/// is a configuration error, not something the relay floors silently.
#[test]
fn client_stall_below_the_relay_floor_is_refused() {
    use segue_session::{TimingError, MIN_CLIENT_STALL};
    let mut t = Config::default().timing;
    assert_eq!(t.validate_client(), Ok(()));
    t.t_stall = MIN_CLIENT_STALL;
    assert_eq!(t.validate_client(), Ok(()));
    t.t_stall = MIN_CLIENT_STALL - Duration::from_millis(1);
    assert_eq!(
        t.validate_client(),
        Err(TimingError::StallTooShort(t.t_stall))
    );
    t.t_stall = Duration::ZERO;
    assert!(t.validate_client().is_err());
    t.t_stall = Duration::MAX;
    assert_eq!(
        t.validate_client(),
        Err(TimingError::StallTooLong(t.t_stall))
    );
}

/// r10 N5: OPENED proves the path, so OPEN attempts lost before it no
/// longer count; RESUMED does not reset the count.
#[test]
fn opened_resets_the_recovery_budget_and_resumed_does_not() {
    use segue_session::codec::{Opened, Resumed};
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    let _ = c.poll_transmit(1, t0);
    c.on_carrier_closed(1, t0);
    assert_eq!(c.fruitless_carriers(), 1, "an unanswered OPEN counts");
    let t = t0 + Duration::from_secs(5);
    assert!(c.wants_attach(t));
    c.attach(2, t);
    while c.poll_transmit(2, t).is_some() {}
    c.on_frame(
        2,
        Frame::Opened(Opened {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 16,
            window_cap: 1 << 16,
            ack_bytes: 0,
        }),
        t,
    )
    .unwrap();
    assert_eq!(c.fruitless_carriers(), 0, "OPENED resets the budget");
    // Lost with a frame expected: counts again; RESUMED keeps it.
    c.on_carrier_stuck(2, t);
    assert_eq!(c.fruitless_carriers(), 1);
    let t = t + Duration::from_secs(5);
    c.attach(3, t);
    while c.poll_transmit(3, t).is_some() {}
    c.on_frame(
        3,
        Frame::Resumed(Resumed {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 16,
        }),
        t,
    )
    .unwrap();
    assert_eq!(c.fruitless_carriers(), 1, "RESUMED is not progress");
}

/// Path quality (see `segue_session::quality`): a carrier lost with
/// something expected on it is a stall, and the bytes replayed onto the
/// next carrier are reported as deltas, so the exit's tracker can sum
/// them across sessions.
#[test]
fn carrier_loss_and_replay_are_reported_as_quality_events() {
    use segue_session::codec::{Opened, Resumed};
    use segue_session::quality::QualityEvent;
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    while c.poll_transmit(1, t0).is_some() {}
    c.on_frame(
        1,
        Frame::Opened(Opened {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
            window_cap: 1 << 20,
            ack_bytes: 0,
        }),
        t0,
    )
    .unwrap();
    assert_eq!(c.take_quality(), None, "OPENED is not a quality event");
    // Send 100 bytes, none acknowledged, then lose the carrier.
    assert_eq!(c.write(&[7u8; 100]), 100);
    while c.poll_transmit(1, t0).is_some() {}
    c.on_carrier_stuck(1, t0);
    assert_eq!(c.take_quality(), Some(QualityEvent::CarrierLost));
    // The next carrier replays all 100 bytes: a delta of 100 sent, 100
    // replayed.
    let t = t0 + Duration::from_secs(5);
    c.attach(2, t);
    assert_eq!(
        c.take_quality(),
        Some(QualityEvent::Replay {
            sent: 100,
            replayed: 100
        })
    );
    while c.poll_transmit(2, t).is_some() {}
    c.on_frame(
        2,
        Frame::Resumed(Resumed {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            // The relay got all 100 bytes: nothing left to replay.
            recv_offset: 100,
            max_offset: 1 << 20,
        }),
        t,
    )
    .unwrap();
    // Nothing new sent and nothing unacked: the next attach reports no
    // replay.
    c.on_carrier_stuck(2, t);
    let _ = c.take_quality();
    let t = t + Duration::from_secs(5);
    c.attach(3, t);
    assert_eq!(c.take_quality(), None, "nothing to replay");
}

/// r10 N6: health and the recovery budget are separate. A carrier that
/// moved data and then stalls is a failure for health (before, it
/// reported nothing), though it does not count against the budget; and
/// while data keeps moving, `Up` is reported again every
/// `HEALTH_REFRESH`, so the exit sees recent proof.
#[test]
fn a_stall_after_success_reports_failed_and_progress_refreshes_up() {
    use segue_session::client::{Health, HEALTH_REFRESH};
    use segue_session::codec::Opened;
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    while c.poll_transmit(1, t0).is_some() {}
    c.on_frame(
        1,
        Frame::Opened(Opened {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
            window_cap: 1 << 20,
            ack_bytes: 0,
        }),
        t0,
    )
    .unwrap();
    assert_eq!(c.take_health(), Some(Health::Up));
    let data = |off: u64| Frame::Data {
        offset: off,
        data: vec![1; 100],
        pad: 0,
    };
    // Data within the refresh interval: no new report.
    let t = t0 + Duration::from_millis(100);
    c.on_frame(1, data(0), t).unwrap();
    assert_eq!(c.take_health(), None);
    // After it: Up again.
    let t = t0 + HEALTH_REFRESH;
    c.on_frame(1, data(100), t).unwrap();
    assert_eq!(c.take_health(), Some(Health::Up), "no refreshed proof");
    // Upload, never acknowledged, nothing received: a stall. This client is
    // AI, so the only carrier waits `t_stall_ai`.
    assert_eq!(c.write(b"hello"), 5);
    while c.poll_transmit(1, t).is_some() {}
    let t = t + Config::default().timing.t_stall_ai + Duration::from_millis(1);
    c.handle_timeout(t);
    assert_eq!(
        c.take_health(),
        Some(Health::Failed),
        "a stall after earlier success went unreported"
    );
    assert_eq!(
        c.fruitless_carriers(),
        0,
        "budget counted a carrier that moved data"
    );
}

/// r11 R4: bytes arriving without data moving end to end (part of a large
/// frame, a keepalive ACK) report `Alive`, at most every
/// `HEALTH_REFRESH`, never `Up`, never before the session is confirmed,
/// and they leave the recovery budget alone.
#[test]
fn partial_frames_and_keepalive_acks_report_alive_not_up() {
    use segue_session::client::{Health, HEALTH_REFRESH};
    use segue_session::codec::Opened;
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    while c.poll_transmit(1, t0).is_some() {}
    // Before OPENED: bytes arriving prove nothing.
    c.on_carrier_progress(1, t0, t0);
    assert_eq!(c.take_health(), None);
    c.on_frame(
        1,
        Frame::Opened(Opened {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
            window_cap: 1 << 20,
            ack_bytes: 0,
        }),
        t0,
    )
    .unwrap();
    assert_eq!(c.take_health(), Some(Health::Up));
    // A large frame crossing slowly: no report within the interval, then
    // Alive (not Up), again once per interval.
    {
        let at = t0 + Duration::from_millis(300);
        c.on_carrier_progress(1, at, at);
    }
    assert_eq!(c.take_health(), None);
    let t = t0 + HEALTH_REFRESH;
    c.on_carrier_progress(1, t, t);
    assert!(matches!(c.take_health(), Some(Health::Alive(_))));
    {
        let at = t + Duration::from_millis(500);
        c.on_carrier_progress(1, at, at);
    }
    assert_eq!(c.take_health(), None);
    let t = t + HEALTH_REFRESH;
    c.on_carrier_progress(1, t, t);
    assert!(matches!(c.take_health(), Some(Health::Alive(_))));
    // Upload: the relay repeats its ACK (no offset moves).
    assert_eq!(c.write(b"hello"), 5);
    while c.poll_transmit(1, t).is_some() {}
    let ka = Frame::Ack {
        recv_offset: 0,
        max_offset: 1 << 20,
    };
    let t = t + HEALTH_REFRESH;
    c.on_frame(1, ka.clone(), t).unwrap();
    assert!(matches!(c.take_health(), Some(Health::Alive(_))));
    let t = t + HEALTH_REFRESH;
    c.on_frame(1, ka, t).unwrap();
    assert!(matches!(c.take_health(), Some(Health::Alive(_))));
    // The ACK of the upload is progress: Up.
    let t = t + HEALTH_REFRESH;
    c.on_frame(
        1,
        Frame::Ack {
            recv_offset: 5,
            max_offset: 1 << 20,
        },
        t,
    )
    .unwrap();
    assert_eq!(c.take_health(), Some(Health::Up));
}

/// r12 #1: a frame that is here and waits for local memory repeats its
/// progress report with the time its bytes arrived. That keeps the
/// carrier from stalling but is no new evidence: `Alive` carries the
/// receive time and is not repeated until newer bytes arrive.
#[test]
fn a_local_wait_reports_no_new_liveness() {
    use segue_session::client::{Health, HEALTH_REFRESH};
    use segue_session::codec::Opened;
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    while c.poll_transmit(1, t0).is_some() {}
    c.on_frame(
        1,
        Frame::Opened(Opened {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
            window_cap: 1 << 20,
            ack_bytes: 0,
        }),
        t0,
    )
    .unwrap();
    assert_eq!(c.take_health(), Some(Health::Up));
    // Part of a frame arrives, then it waits for memory: the reader keeps
    // reporting with the same receive time.
    let rx = t0 + Duration::from_millis(200);
    let t = t0 + HEALTH_REFRESH;
    c.on_carrier_progress(1, rx, t);
    assert_eq!(c.take_health(), Some(Health::Alive(rx)));
    let stall = Config::default().timing.t_stall;
    let mut t = t;
    for _ in 0..40 {
        t += Duration::from_millis(250);
        c.on_carrier_progress(1, rx, t);
        c.handle_timeout(t);
        assert_eq!(c.take_health(), None, "a local wait renewed liveness");
    }
    assert!(t > rx + stall, "the wait outlasted t_stall");
    assert_eq!(c.state(), State::Active, "a local wait stalled the carrier");
    // r13: the waiting frame, all of it read at `rx`, is a duplicate ACK
    // handled now: it moves nothing and is no newer evidence.
    t += Duration::from_millis(250);
    c.on_frame_at(
        1,
        Frame::Ack {
            recv_offset: 0,
            max_offset: 1 << 20,
        },
        rx,
        t,
    )
    .unwrap();
    assert_eq!(c.take_health(), None, "a buffered ACK renewed liveness");
    // A new byte is new evidence.
    t += Duration::from_millis(250);
    c.on_carrier_progress(1, t, t);
    assert_eq!(c.take_health(), Some(Health::Alive(t)));
}

/// r11 R4: liveness does not reset the recovery budget.
#[test]
fn liveness_neither_resets_the_budget_nor_hides_a_failure() {
    use segue_session::client::{Health, HEALTH_REFRESH};
    use segue_session::codec::{Opened, Resumed};
    let t0 = Instant::now();
    let mut c = client(t0);
    c.attach(1, t0);
    while c.poll_transmit(1, t0).is_some() {}
    c.on_frame(
        1,
        Frame::Opened(Opened {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
            window_cap: 1 << 20,
            ack_bytes: 0,
        }),
        t0,
    )
    .unwrap();
    assert_eq!(c.take_health(), Some(Health::Up));
    // An upload nobody acknowledges: the carrier stalls, moved nothing.
    // AI waits `t_stall_ai`, not `t_stall`.
    assert_eq!(c.write(b"hello"), 5);
    while c.poll_transmit(1, t0).is_some() {}
    let mut t = t0 + Config::default().timing.t_stall_ai + Duration::from_millis(1);
    c.handle_timeout(t);
    assert_eq!(c.take_health(), Some(Health::Failed));
    assert_eq!(c.fruitless_carriers(), 1);
    // The next carrier is answered RESUMED (not progress); bytes then
    // keep arriving without completing a frame.
    for _ in 0..100 {
        if c.wants_attach(t) {
            break;
        }
        t += Duration::from_millis(50);
        c.handle_timeout(t);
    }
    assert!(c.wants_attach(t));
    c.attach(2, t);
    while c.poll_transmit(2, t).is_some() {}
    c.on_frame(
        2,
        Frame::Resumed(Resumed {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
        }),
        t,
    )
    .unwrap();
    assert_eq!(c.state(), State::Active);
    let _ = c.take_health();
    let mut alive = 0;
    for _ in 0..5 {
        t += HEALTH_REFRESH;
        c.on_carrier_progress(2, t, t);
        match c.take_health() {
            Some(Health::Alive(_)) => alive += 1,
            h => assert_eq!(h, None),
        }
    }
    assert!(alive >= 4, "{alive} Alive reports");
    assert_eq!(c.fruitless_carriers(), 1, "liveness reset the budget");
}

fn params_class(exit_class: u8) -> OpenParams {
    let mut p = params();
    p.exit_class = exit_class;
    p
}

/// Move every frame both ways and drain what the app and the site can read.
fn exchange(
    c: &mut ClientSession,
    r: &mut RelayTable,
    cid: u64,
    now: Instant,
    down: &mut Vec<u8>,
    up: &mut Vec<u8>,
) {
    let mut buf = [0u8; 8192];
    for _ in 0..64 {
        let mut moved = false;
        while let Some(f) = c.poll_transmit(cid, now) {
            r.on_frame(cid, f, now);
            moved = true;
        }
        while let Some(f) = r.poll_transmit(cid, now) {
            c.on_frame(cid, f, now).expect("session frame");
            moved = true;
        }
        loop {
            let n = c.read(&mut buf, now);
            if n == 0 {
                break;
            }
            down.extend_from_slice(&buf[..n]);
            moved = true;
        }
        loop {
            let n = r.read(&SID, &mut buf, now);
            if n == 0 {
                break;
            }
            up.extend_from_slice(&buf[..n]);
            moved = true;
        }
        if !moved {
            break;
        }
    }
}

fn open_class(exit_class: u8, t0: Instant) -> (RelayTable, ClientSession) {
    let mut c = ClientSession::with_ids(
        Config::default(),
        &Pool::new(1 << 20),
        params_class(exit_class),
        SID,
        SECRET,
        t0,
    )
    .unwrap();
    c.attach(1, t0);
    let mut r = RelayTable::new(
        Config::default(),
        Pool::new(1 << 20),
        Box::new(AllowAll),
        INSTANCE,
    );
    r.add_carrier(1);
    let open = c.poll_transmit(1, t0).expect("OPEN");
    r.on_frame(1, open, t0);
    assert!(
        matches!(r.take_event(), Some(RelayEvent::Connect { .. })),
        "OPEN did not ask for a site connect"
    );
    r.connect_done(&SID, Ok(()), t0);
    let mut down = Vec::new();
    let mut up = Vec::new();
    exchange(&mut c, &mut r, 1, t0, &mut down, &mut up);
    assert_eq!(c.state(), State::Active, "OPEN did not complete");
    (r, c)
}

fn close_code(r: &mut RelayTable) -> Option<u8> {
    let mut code = None;
    while let Some(ev) = r.take_event() {
        if let RelayEvent::Closed { close_code, .. } = ev {
            code = Some(close_code);
        }
    }
    code
}

/// AI detach is 150 s, not 30 s: 40 s of blackout still resumes, and every
/// byte the site wrote meanwhile arrives once. A non-AI session still ends
/// at 30 s. 160 s of silence is the give-up on both sides.
#[test]
fn ai_session_waits_out_a_blackout_and_delivers_site_bytes_once() {
    use segue_session::client::LOCAL_GIVE_UP;
    use segue_session::EXIT_CLASS_AI;

    let t0 = Instant::now();
    let (mut r, mut c) = open_class(EXIT_CLASS_AI, t0);
    let up_body = vec![0x11u8; 4000];
    let down_body = vec![0x22u8; 4000];
    assert_eq!(c.write(&up_body), up_body.len());
    let sid = c.session_id();
    let cap = r.site_read_capacity(&sid);
    assert!(cap >= down_body.len());
    assert_eq!(r.site_data(&sid, &down_body), down_body.len());
    let mut down = Vec::new();
    let mut up = Vec::new();
    exchange(&mut c, &mut r, 1, t0, &mut down, &mut up);
    assert_eq!(down, down_body);
    assert_eq!(up, up_body);

    let t_cut = t0 + Duration::from_secs(1);
    c.on_carrier_closed(1, t_cut);
    r.on_carrier_closed(1, t_cut);
    assert_eq!(
        r.state(&sid),
        Some(segue_session::relay::SessionState::Detached)
    );

    // 2 KB/s for 20 s while detached. The site is never blocked: each
    // second's write fits in the replay buffer the send half already has.
    let mut extra = Vec::new();
    for i in 0..20 {
        let t = t_cut + Duration::from_secs(i);
        c.handle_timeout(t);
        r.handle_timeout(t);
        assert!(!c.is_closed(), "AI session ended {i}s into the outage");
        assert!(
            r.state(&sid).is_some(),
            "relay dropped the AI session at {i}s"
        );
        let chunk = vec![0x30 + (i as u8); 2048];
        let cap = r.site_read_capacity(&sid);
        assert!(cap >= chunk.len(), "site blocked at {i}s: capacity {cap}");
        assert_eq!(r.site_data(&sid, &chunk), chunk.len());
        extra.extend_from_slice(&chunk);
    }
    let later = c.write(&[0x44; 1000]);
    assert_eq!(later, 1000);

    let t_back = t_cut + Duration::from_secs(40);
    c.handle_timeout(t_back);
    r.handle_timeout(t_back);
    assert!(!c.is_closed(), "40s blackout ended an AI session");
    assert!(r.state(&sid).is_some());
    assert!(c.wants_attach(t_back));
    c.attach(2, t_back);
    r.add_carrier(2);
    exchange(&mut c, &mut r, 2, t_back, &mut down, &mut up);
    assert_eq!(c.state(), State::Active);
    assert_eq!(down, {
        let mut all = down_body.clone();
        all.extend_from_slice(&extra);
        all
    });
    assert_eq!(up, {
        let mut all = up_body.clone();
        all.extend_from_slice(&[0x44; 1000]);
        all
    });

    // 160 s with no carrier: client give-up, relay IDLE.
    let (mut r, mut c) = open_class(EXIT_CLASS_AI, t0);
    let sid = c.session_id();
    let t_cut = t0 + Duration::from_secs(1);
    c.on_carrier_closed(1, t_cut);
    r.on_carrier_closed(1, t_cut);
    let t_still = t_cut + Duration::from_secs(149);
    c.handle_timeout(t_still);
    r.handle_timeout(t_still);
    assert!(!c.is_closed());
    assert!(r.state(&sid).is_some());
    let t_gone = t_cut + Duration::from_secs(160);
    c.handle_timeout(t_gone);
    r.handle_timeout(t_gone);
    assert_eq!(c.close_reason(), Some(CloseReason::Reset(LOCAL_GIVE_UP)));
    assert!(r.state(&sid).is_none());
    assert_eq!(close_code(&mut r), Some(code::IDLE));

    // Non-AI still ends at 30 s, and the relay does not read the site
    // while that session is detached.
    let (mut r, mut c) = open_class(0, t0);
    let sid = c.session_id();
    let t_cut = t0 + Duration::from_secs(1);
    c.on_carrier_closed(1, t_cut);
    r.on_carrier_closed(1, t_cut);
    assert_eq!(r.site_read_capacity(&sid), 0);
    let t_still = t_cut + Duration::from_secs(29);
    c.handle_timeout(t_still);
    r.handle_timeout(t_still);
    assert!(!c.is_closed());
    assert!(r.state(&sid).is_some());
    let t_gone = t_cut + Duration::from_secs(30);
    c.handle_timeout(t_gone);
    r.handle_timeout(t_gone);
    assert_eq!(c.close_reason(), Some(CloseReason::Reset(LOCAL_GIVE_UP)));
    assert!(r.state(&sid).is_none());
    assert_eq!(close_code(&mut r), Some(code::IDLE));
}

/// Eight fruitless carriers inside a minute do not end an AI session.
/// It ends when `t_detached_ai` has elapsed since the carrier was lost,
/// not when the count hits [`MAX_FRUITLESS`].
#[test]
fn ai_session_does_not_end_on_fruitless_count_alone() {
    use segue_session::client::{LOCAL_GIVE_UP, MAX_FRUITLESS};

    let t0 = Instant::now();
    let (mut r, mut c) = open_class(segue_session::EXIT_CLASS_AI, t0);
    let sid = c.session_id();
    assert_eq!(c.write(b"pending"), 7);
    let t_cut = t0 + Duration::from_secs(1);
    c.on_carrier_closed(1, t_cut);
    r.on_carrier_closed(1, t_cut);
    assert!(
        c.fruitless_carriers() <= 1,
        "the opened carrier must not by itself exhaust the budget"
    );

    let mut t = t_cut;
    let mut cid = 1u64;
    let mut losses = 0u32;
    let mut spins = 0u32;
    while losses < MAX_FRUITLESS + 2 {
        spins += 1;
        assert!(spins < 10_000, "stopped attaching");
        t += Duration::from_millis(50);
        c.handle_timeout(t);
        assert!(!c.is_closed(), "ended while backing off");
        if !c.wants_attach(t) {
            continue;
        }
        cid += 1;
        c.attach(cid, t);
        t += Duration::from_millis(10);
        c.on_carrier_closed(cid, t);
        losses += 1;
        assert!(
            !c.is_closed(),
            "AI session ended on fruitless loss {losses}"
        );
    }
    assert!(c.fruitless_carriers() >= MAX_FRUITLESS);
    assert!(t < t_cut + Duration::from_secs(60), "losses took {t:?}");
    c.handle_timeout(t_cut + Duration::from_secs(60));
    r.handle_timeout(t_cut + Duration::from_secs(60));
    assert!(!c.is_closed(), "ended inside 60s");
    assert!(
        r.state(&sid).is_some(),
        "relay ended an AI session inside 60s"
    );
    let t_gone = t_cut + Config::default().timing.t_detached_ai;
    c.handle_timeout(t_gone);
    r.handle_timeout(t_gone);
    assert_eq!(c.close_reason(), Some(CloseReason::Reset(LOCAL_GIVE_UP)));
    assert!(r.state(&sid).is_none());
    assert_eq!(close_code(&mut r), Some(code::IDLE));
}
