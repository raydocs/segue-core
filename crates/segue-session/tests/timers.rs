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
    let t = t0 + Config::default().timing.t_live;
    r.handle_timeout(t);
    let stall = r.poll_transmit(9, t).expect("STALL");
    let Frame::Stall(entries) = stall else {
        panic!("expected STALL, got {stall:?}")
    };
    assert_eq!(entries, vec![(SID, c.gen())]);
    c.on_stall(entries[0].1, t);
    // A stalled carrier counts against the redial bound (r9 F2) even
    // with nothing to upload: the first redial waits the first backoff.
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
    let t = t0 + Config::default().timing.t_live;
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
    // Still bounded by the session's own timers (t_live here).
    assert!(blocked <= t0 + Config::default().timing.t_live);
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
