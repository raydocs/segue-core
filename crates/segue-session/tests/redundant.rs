//! Relay rules for a redundant carrier (v0.6 draft, stage 1).
//!
//! Binding one does not switch or close the current carrier, does not
//! reserve session memory, and a bad proof closes only the spare.

use std::sync::Arc;
use std::time::Instant;

use segue_session::codec::{
    Frame, Kind, Open, RedundantAttach, RedundantOk, Resume, Target, VERSION,
};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayEvent, RelayTable, SessionState};
use segue_session::Config;

const INSTANCE: u64 = 7;

struct Opened {
    relay: RelayTable,
    pool: Arc<Pool>,
    sid: [u8; 16],
    secret: [u8; 32],
    now: Instant,
}

fn opened() -> Opened {
    let now = Instant::now();
    let pool = Pool::new(1 << 20);
    let mut relay = RelayTable::new(
        Config::default(),
        pool.clone(),
        Box::new(AllowAll),
        INSTANCE,
    );
    let sid = [3u8; 16];
    let secret = [9u8; 32];
    relay.add_carrier(1);
    relay.on_frame(
        1,
        Frame::Open(Open {
            version: VERSION,
            ticket: b"t".to_vec(),
            session_id: sid,
            resume_secret: secret,
            attach_gen: 0,
            retry: false,
            anchor_instance_id: 0,
            kind: Kind::Tcp,
            target: Target::Domain("example.com".into(), 443),
            exit_class: 0,
            t_stall_ms: None,
            first_data: Vec::new(),
        }),
        now,
    );
    match relay.take_event() {
        Some(RelayEvent::Connect { session_id, .. }) => assert_eq!(session_id, sid),
        other => panic!("expected connect, got {other:?}"),
    }
    relay.connect_done(&sid, Ok(()), now);
    assert!(matches!(
        relay.poll_transmit(1, now),
        Some(Frame::Opened(_))
    ));
    assert_eq!(relay.state(&sid), Some(SessionState::Active));
    Opened {
        relay,
        pool,
        sid,
        secret,
        now,
    }
}

fn attach(sid: [u8; 16], secret: [u8; 32]) -> Frame {
    Frame::RedundantAttach(RedundantAttach {
        session_id: sid,
        resume_secret: secret,
        attach_gen: 0,
        recv_offset: 0,
        max_offset: 16 * 1024,
    })
}

#[test]
fn redundant_attach_keeps_the_current_carrier() {
    let Opened {
        mut relay,
        pool,
        sid,
        secret,
        now,
    } = opened();
    let before = pool.used_bytes();
    let sessions = relay.session_count();
    relay.add_carrier(2);
    relay.on_frame(2, attach(sid, secret), now);
    assert_eq!(relay.current_carrier(&sid), Some(1));
    assert_eq!(relay.redundant_carrier(&sid), Some(2));
    assert!(
        relay.take_closed_carriers().is_empty(),
        "the current carrier must stay up"
    );
    assert!(matches!(
        relay.poll_transmit(2, now),
        Some(Frame::RedundantOk(RedundantOk { attach_gen: 0, .. }))
    ));
    // Rule 8: no new grant. The session count is unchanged.
    assert_eq!(
        pool.used_bytes(),
        before,
        "a spare carrier reserves no session memory"
    );
    assert_eq!(relay.session_count(), sessions);

    // Frames on the spare are accepted and deduplicated by offset.
    relay.on_frame(
        2,
        Frame::Data {
            offset: 0,
            data: b"hello".to_vec(),
            pad: 0,
        },
        now,
    );
    relay.on_frame(
        2,
        Frame::Data {
            offset: 0,
            data: b"hello".to_vec(),
            pad: 0,
        },
        now,
    );
    let mut buf = [0u8; 8];
    assert_eq!(relay.read(&sid, &mut buf, now), 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(relay.read(&sid, &mut buf, now), 0);
    assert_eq!(relay.current_carrier(&sid), Some(1));
}

#[test]
fn second_redundant_attach_replaces_the_first() {
    let Opened {
        mut relay,
        sid,
        secret,
        now,
        ..
    } = opened();
    relay.add_carrier(2);
    relay.on_frame(2, attach(sid, secret), now);
    assert!(relay.poll_transmit(2, now).is_some());
    relay.add_carrier(3);
    relay.on_frame(3, attach(sid, secret), now);
    let closed = relay.take_closed_carriers();
    assert!(closed.contains(&2), "the first spare is closed: {closed:?}");
    assert!(
        !closed.contains(&1),
        "the current carrier stays: {closed:?}"
    );
    assert_eq!(relay.current_carrier(&sid), Some(1));
    assert_eq!(relay.redundant_carrier(&sid), Some(3));
    assert!(matches!(
        relay.poll_transmit(3, now),
        Some(Frame::RedundantOk(_))
    ));
}

#[test]
fn invalid_proof_or_unknown_session_closes_only_that_carrier() {
    let Opened {
        mut relay,
        sid,
        secret,
        now,
        ..
    } = opened();
    relay.add_carrier(2);
    relay.on_frame(2, attach(sid, secret), now);
    let _ = relay.poll_transmit(2, now);

    let mut bad = secret;
    bad[0] ^= 0xff;
    relay.add_carrier(3);
    relay.on_frame(3, attach(sid, bad), now);
    assert_eq!(relay.take_closed_carriers(), vec![3]);
    assert_eq!(relay.current_carrier(&sid), Some(1));
    assert_eq!(relay.redundant_carrier(&sid), Some(2));
    assert_eq!(relay.session_count(), 1);

    relay.add_carrier(4);
    relay.on_frame(
        4,
        Frame::RedundantAttach(RedundantAttach {
            session_id: [8; 16],
            resume_secret: secret,
            attach_gen: 0,
            recv_offset: 0,
            max_offset: 1024,
        }),
        now,
    );
    assert_eq!(relay.take_closed_carriers(), vec![4]);
    assert_eq!(relay.current_carrier(&sid), Some(1));
    assert_eq!(relay.redundant_carrier(&sid), Some(2));
    assert!(relay.state(&sid).is_some());

    // A stale generation is not a proof for this generation.
    relay.add_carrier(5);
    relay.on_frame(
        5,
        Frame::RedundantAttach(RedundantAttach {
            session_id: sid,
            resume_secret: secret,
            attach_gen: 9,
            recv_offset: 0,
            max_offset: 1024,
        }),
        now,
    );
    assert_eq!(relay.take_closed_carriers(), vec![5]);
    assert_eq!(relay.redundant_carrier(&sid), Some(2));
}

#[test]
fn resume_switch_drops_the_redundant_carrier() {
    let Opened {
        mut relay,
        sid,
        secret,
        now,
        ..
    } = opened();
    relay.add_carrier(2);
    relay.on_frame(2, attach(sid, secret), now);
    let _ = relay.poll_transmit(2, now);
    relay.add_carrier(6);
    relay.on_frame(
        6,
        Frame::Resume(Resume {
            version: VERSION,
            ticket: b"t".to_vec(),
            anchor_node_id: 0,
            anchor_instance_id: INSTANCE,
            session_id: sid,
            resume_secret: secret,
            attach_gen: 1,
            recv_offset: 0,
            max_offset: 16 * 1024,
            t_stall_ms: None,
        }),
        now,
    );
    let closed = relay.take_closed_carriers();
    assert!(closed.contains(&1), "old current closed: {closed:?}");
    assert!(closed.contains(&2), "spare closed on move: {closed:?}");
    assert_eq!(relay.current_carrier(&sid), Some(6));
    assert_eq!(relay.redundant_carrier(&sid), None);
    assert_eq!(relay.cur_gen(&sid), Some(1));
}
