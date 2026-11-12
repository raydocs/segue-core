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
