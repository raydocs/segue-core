//! Each way a session gives up its carrier increments that counter, and
//! nothing else.

use std::time::{Duration, Instant};

use segue_session::client::{ClientSession, OpenParams, State};
use segue_session::codec::{
    code, ty, CtrlHello, Frame, Kind, Opened, RedundantOk, Reject, Resumed, SessionId, Target,
    VERSION,
};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayTable};
use segue_session::{Config, MoveStats, ProtoError};

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
    client_class(now, 1)
}

fn client_class(now: Instant, exit_class: u8) -> ClientSession {
    let mut p = params();
    p.exit_class = exit_class;
    ClientSession::with_ids(Config::default(), &Pool::new(1 << 20), p, SID, SECRET, now).unwrap()
}

fn opened(gen: u32) -> Frame {
    Frame::Opened(Opened {
        instance_id: INSTANCE,
        attach_gen: gen,
        recv_offset: 0,
        max_offset: 1 << 20,
        window_cap: 1 << 20,
        ack_bytes: 0,
    })
}

fn active(now: Instant) -> ClientSession {
    let mut c = client(now);
    c.attach(1, now);
    while c.poll_transmit(1, now).is_some() {}
    c.on_frame(1, opened(c.gen()), now).unwrap();
    assert_eq!(c.state(), State::Active);
    assert_eq!(c.move_stats(), MoveStats::default());
    c
}

/// 36 bytes sent and not acknowledged, so `t_stall` is armed.
fn with_unacked(now: Instant) -> ClientSession {
    let mut c = active(now);
    assert_eq!(c.write(b"abcdefghijklmnopqrstuvwxyz0123456789"), 36);
    assert!(c.poll_transmit(1, now).is_some());
    while c.poll_transmit(1, now).is_some() {}
    assert!(c.send_half().unacked());
    c
}

fn bind_spare(c: &mut ClientSession, now: Instant) {
    c.request_redundant();
    c.attach_redundant(2, now);
    c.on_frame(
        2,
        Frame::RedundantOk(RedundantOk {
            attach_gen: c.gen(),
            recv_offset: 0,
            max_offset: 1 << 20,
        }),
        now,
    )
    .unwrap();
    assert!(c.redundant_bound());
}

#[test]
fn stall_then_resume_counts_the_stall_the_resume_and_the_replay() {
    let t0 = Instant::now();
    let mut c = with_unacked(t0);
    // AI, no spare: the 1 s timer must not abandon the only carrier.
    c.handle_timeout(t0 + Duration::from_secs(1));
    assert_eq!(c.move_stats().stall, 0);
    assert_eq!(c.carrier(), Some(1));
    let stalled = t0 + Duration::from_secs(5);
    c.handle_timeout(stalled);
    let mid = c.move_stats();
    assert_eq!(mid.stall, 1);
    assert_eq!(
        mid.resumes, 0,
        "the resume is the next attach, not the stall"
    );
    assert!(c.wants_attach(stalled + segue_session::client::RECONNECT_BACKOFF));
    let resumed_at = stalled + segue_session::client::RECONNECT_BACKOFF + Duration::from_millis(50);
    c.attach(2, resumed_at);
    assert!(matches!(
        c.poll_transmit(2, resumed_at),
        Some(Frame::Resume(_))
    ));
    c.on_frame(
        2,
        Frame::Resumed(Resumed {
            instance_id: INSTANCE,
            attach_gen: c.gen(),
            recv_offset: 36,
            max_offset: 1 << 20,
        }),
        resumed_at,
    )
    .unwrap();
    let s = c.move_stats();
    assert_eq!(s.stall, 1);
    assert_eq!(s.resumes, 1);
    assert!(s.bytes_replayed >= 36, "replayed {}", s.bytes_replayed);
    assert_eq!(s.recoveries, 1);
    assert_eq!(s.recovery_us_sum, s.recovery_us_max);
    assert!(
        s.recovery_us_sum >= 250_000,
        "recovery {}",
        s.recovery_us_sum
    );
    assert_eq!(s.hold, 0);
    assert_eq!(s.closed, 0);
    assert_eq!(s.promotions, 0);
}

#[test]
fn hold_closed_io_reject_and_attach_each_increment_only_themselves() {
    let t0 = Instant::now();

    let mut held = active(t0);
    held.on_carrier_stuck(1, t0);
    assert_eq!(held.move_stats().hold, 1);
    assert_eq!(held.move_stats().closed, 0);

    let mut closed = active(t0);
    closed.on_carrier_closed(1, t0);
    assert_eq!(closed.move_stats().closed, 1);
    assert_eq!(closed.move_stats().hold, 0);
    assert_eq!(closed.move_stats().io, 0);

    let mut io = active(t0);
    io.on_carrier_io(1, t0);
    assert_eq!(io.move_stats().io, 1);
    assert_eq!(io.move_stats().closed, 0);

    let mut decoded = active(t0);
    decoded.on_decode_error(1, ProtoError::Malformed);
    assert!(decoded.is_closed());
    // The reader reports the close after the decode error. That is not a
    // second move.
    decoded.on_carrier_closed(1, t0);
    assert_eq!(decoded.move_stats().io, 1);
    assert_eq!(decoded.move_stats().closed, 0);

    let mut rejected = active(t0);
    rejected
        .on_frame(
            1,
            Frame::Reject(Reject {
                code: code::TARGET_DENIED,
                attach_gen: rejected.gen(),
                closed: None,
            }),
            t0,
        )
        .unwrap();
    assert_eq!(rejected.move_stats().reject, 1);

    let mut stale = active(t0);
    stale
        .on_frame(
            1,
            Frame::Reject(Reject {
                code: code::STALE_GEN,
                attach_gen: stale.gen(),
                closed: None,
            }),
            t0,
        )
        .unwrap();
    assert_eq!(
        stale.move_stats().reject,
        0,
        "an ignored stale generation is not a move"
    );

    let mut unanswered = client(t0);
    unanswered.attach(1, t0);
    while unanswered.poll_transmit(1, t0).is_some() {}
    unanswered.handle_timeout(t0 + Duration::from_secs(2));
    assert_eq!(unanswered.move_stats().attach, 1);
    assert_eq!(unanswered.move_stats().stall, 0);
    assert_eq!(unanswered.move_stats().resumes, 0, "OPEN never completed");
}

#[test]
fn a_stall_with_a_spare_swaps_and_does_not_resume() {
    let t0 = Instant::now();
    let mut c = with_unacked(t0);
    bind_spare(&mut c, t0);
    // AI waits `t_stall_ai` even with a spare bound. 1 s is inside TCP recovery.
    c.handle_timeout(t0 + Duration::from_secs(1));
    assert_eq!(c.carrier(), Some(1), "a spare must not swap at t_stall");
    assert_eq!(c.move_stats().stall, 0);
    c.handle_timeout(t0 + Duration::from_secs(5));
    assert_eq!(c.carrier(), Some(2));
    assert_eq!(c.redundant_carrier(), Some(1));
    let s = c.move_stats();
    assert_eq!(s.stall, 1);
    assert_eq!(s.swaps, 1);
    assert_eq!(s.promotions, 1);
    assert_eq!(s.resumes, 0);
    assert!(s.bytes_replayed >= 36, "replayed {}", s.bytes_replayed);
}

#[test]
fn a_hold_swaps_and_a_close_promotes_without_a_swap() {
    let t0 = Instant::now();
    let mut held = with_unacked(t0);
    bind_spare(&mut held, t0);
    // A transport hold hard-drops the stuck carrier rather than demoting it
    // so a hung writer/hold carrier cannot stay in `redundant` holding `tx_slot`.
    held.on_carrier_stuck(1, t0);
    assert_eq!(held.carrier(), Some(2));
    assert!(
        held.redundant_carrier().is_none(),
        "a transport hold drops the stuck carrier"
    );
    assert_eq!(held.move_stats().hold, 1);
    assert_eq!(held.move_stats().swaps, 0);
    assert_eq!(held.move_stats().promotions, 1);
    assert_eq!(held.move_stats().stall, 0);

    let mut closed = with_unacked(t0);
    bind_spare(&mut closed, t0);
    closed.on_carrier_closed(1, t0);
    assert_eq!(closed.carrier(), Some(2));
    assert!(
        closed.redundant_carrier().is_none(),
        "a hard close drops the old carrier"
    );
    assert_eq!(closed.move_stats().closed, 1);
    assert_eq!(closed.move_stats().promotions, 1);
    assert_eq!(closed.move_stats().swaps, 0);
}

#[test]
fn a_spare_dying_is_not_a_session_move() {
    let t0 = Instant::now();
    let mut c = active(t0);
    bind_spare(&mut c, t0);
    c.on_carrier_closed(2, t0);
    assert_eq!(c.carrier(), Some(1));
    assert_eq!(c.move_stats(), MoveStats::default());
    c.on_carrier_stuck(2, t0);
    assert_eq!(c.move_stats(), MoveStats::default());
    c.on_decode_error(2, ProtoError::Malformed);
    assert_eq!(c.move_stats(), MoveStats::default());
}

#[test]
fn a_relay_stall_hint_counts_even_when_it_promotes() {
    let t0 = Instant::now();
    let mut bare = active(t0);
    bare.on_stall(bare.gen().wrapping_add(1), t0);
    assert_eq!(bare.move_stats().relay_stall, 0, "wrong generation");
    bare.on_stall(bare.gen(), t0);
    assert_eq!(
        bare.move_stats().relay_stall,
        0,
        "no spare: wait t_stall_ai"
    );
    assert_eq!(bare.carrier(), Some(1));
    let due = t0 + Duration::from_secs(5);
    bare.handle_timeout(due);
    assert_eq!(bare.move_stats().relay_stall, 1);
    assert_eq!(
        bare.move_stats().resumes,
        0,
        "resume waits for the next attach"
    );
    assert!(bare.wants_attach(due + segue_session::client::RECONNECT_BACKOFF));

    let mut spared = with_unacked(t0);
    bind_spare(&mut spared, t0);
    spared.on_stall(spared.gen(), t0);
    assert_eq!(
        spared.carrier(),
        Some(1),
        "STALL waits t_stall_ai with a spare"
    );
    assert_eq!(spared.move_stats().relay_stall, 0);
    spared.handle_timeout(t0 + Duration::from_secs(5));
    assert_eq!(spared.carrier(), Some(2));
    assert_eq!(spared.move_stats().relay_stall, 1);
    assert_eq!(spared.move_stats().swaps, 1);
    assert_eq!(spared.move_stats().promotions, 1);
    assert_eq!(spared.move_stats().resumes, 0);
}

#[test]
fn relay_counts_t_live_and_the_stall_hint_it_queues() {
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
    while r.poll_transmit(1, t0).is_some() {}
    r.add_carrier(9);
    r.on_frame(
        9,
        CtrlHello {
            version: VERSION,
            ticket: b"ticket".to_vec(),
            held_anchors: vec![5],
        }
        .to_frame(),
        t0,
    );
    assert!(matches!(
        r.poll_transmit(9, t0),
        Some(Frame::Control { ty: t, .. }) if t == ty::CTRL_HELLO
    ));
    assert_eq!(r.move_stats().t_live, 0);
    assert_eq!(r.move_stats().stall_hints, 0);
    r.site_data(&SID, &[7u8; 1000]);
    while r.poll_transmit(1, t0).is_some() {}
    r.handle_timeout(t0 + Config::default().timing.t_live_ai);
    let s = r.move_stats();
    assert_eq!(s.t_live, 1);
    assert_eq!(s.stall_hints, 1);
    assert!(matches!(r.poll_transmit(9, t0), Some(Frame::Stall(_))));
    assert_eq!(s.stall, 0, "client counters stay zero on the relay");
}

#[test]
fn a_non_ai_session_still_stalls_at_one_second() {
    let t0 = Instant::now();
    let mut c = client_class(t0, 0);
    c.attach(1, t0);
    while c.poll_transmit(1, t0).is_some() {}
    c.on_frame(1, opened(c.gen()), t0).unwrap();
    assert_eq!(c.write(b"abcdefghijklmnopqrstuvwxyz0123456789"), 36);
    while c.poll_transmit(1, t0).is_some() {}
    c.handle_timeout(t0 + Duration::from_secs(1));
    assert_eq!(c.move_stats().stall, 1);
    assert!(c.carrier().is_none());
}

#[test]
fn a_received_byte_cancels_a_deferred_stall_hint() {
    let t0 = Instant::now();
    let mut c = active(t0);
    c.on_stall(c.gen(), t0);
    c.on_frame(
        1,
        Frame::Ack {
            recv_offset: 0,
            max_offset: 1 << 20,
        },
        t0 + Duration::from_secs(1),
    )
    .unwrap();
    c.handle_timeout(t0 + Duration::from_secs(5));
    assert_eq!(c.move_stats().relay_stall, 0);
    assert_eq!(c.carrier(), Some(1));
}

#[test]
fn a_move_marks_a_live_spare_dropped_for_the_move_and_a_failure_does_not() {
    let t0 = Instant::now();
    let mut c = active(t0);
    bind_spare(&mut c, t0);
    c.reattach(t0);
    assert!(c.take_spare_dropped_for_move());
    assert!(!c.take_spare_dropped_for_move());

    let mut c = active(t0);
    bind_spare(&mut c, t0);
    c.on_carrier_closed(2, t0);
    assert!(
        !c.take_spare_dropped_for_move(),
        "a spare that died is not a move"
    );
}

#[tokio::test(start_paused = true)]
async fn a_resume_redials_the_spare_without_waiting_out_the_backoff() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use segue_session::driver::{
        run_client_standby, run_relay, BoxCarrier, ClientCtl, Connector, StandbyCtl, StandbyEvent,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, watch};

    let cfg = Config::default();
    let pool = Pool::new(8 << 20);
    let table = RelayTable::new(cfg.clone(), pool.clone(), Box::new(AllowAll), INSTANCE);
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(8);
    let site: segue_session::driver::SiteConnector = Arc::new(|_target, _kind| {
        Box::pin(async {
            let (site_end, relay_end) = tokio::io::duplex(64 << 10);
            tokio::spawn(async move {
                let mut site_end = site_end;
                let mut buf = [0u8; 1024];
                loop {
                    match site_end.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
            Ok(Box::new(relay_end) as BoxCarrier)
        })
    });
    tokio::spawn(run_relay(table, accept_rx, site, None));

    let standby_dials = Arc::new(AtomicU64::new(0));
    let connect_session: Connector = {
        let accept_tx = accept_tx.clone();
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            Box::pin(async move {
                let (client_end, relay_end) = tokio::io::duplex(64 << 10);
                accept_tx
                    .send(Box::new(relay_end))
                    .await
                    .map_err(|_| std::io::Error::other("relay gone"))?;
                Ok(Box::new(client_end) as BoxCarrier)
            })
        })
    };
    let connect_standby: Connector = {
        let accept_tx = accept_tx.clone();
        let dials = Arc::clone(&standby_dials);
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            let dials = Arc::clone(&dials);
            Box::pin(async move {
                dials.fetch_add(1, Ordering::Relaxed);
                let (client_end, relay_end) = tokio::io::duplex(64 << 10);
                accept_tx
                    .send(Box::new(relay_end))
                    .await
                    .map_err(|_| std::io::Error::other("relay gone"))?;
                Ok(Box::new(client_end) as BoxCarrier)
            })
        })
    };
    let (bound_tx, mut bound_rx) = mpsc::unbounded_channel();
    let bound_tx = Arc::new(Mutex::new(Some(bound_tx)));
    let (epoch_tx, epoch_rx) = watch::channel(0u64);
    let session = ClientSession::new(cfg, &pool, params(), Instant::now()).unwrap();
    let (mut app, far) = tokio::io::duplex(64 << 10);
    let ctl = ClientCtl {
        reattach: Some(epoch_rx),
        standby: Some(StandbyCtl {
            connect: connect_standby,
            allowed: Arc::new(|| true),
            on_event: Arc::new(move |ev| {
                if ev == StandbyEvent::Bound {
                    if let Some(tx) = bound_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                }
            }),
            swaps: None,
        }),
        ..ClientCtl::default()
    };
    tokio::spawn(run_client_standby(session, far, connect_session, ctl));
    app.write_all(b"hello").await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), bound_rx.recv())
        .await
        .expect("standby never bound")
        .expect("bound channel closed");
    let dials = standby_dials.load(Ordering::Relaxed);
    assert!(dials >= 1, "no standby dial");
    epoch_tx.send(1).unwrap();
    // The move itself backs off the RESUME by 200 ms. The spare used to wait
    // another 1 s after that. 800 ms covers the RESUME and not that wait.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        standby_dials.load(Ordering::Relaxed) > dials,
        "spare was not redialled within 800 ms of the RESUME (backoff is 1 s), dials {dials} now {}",
        standby_dials.load(Ordering::Relaxed)
    );
}
