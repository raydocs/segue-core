//! Regression tests from review: REJECT(version) and secret redaction.

use std::time::Instant;

use segue_session::client::{ClientSession, OpenParams};
use segue_session::codec::{code, Frame, FrameDecoder, Kind, Open, Target};
use segue_session::pool::Pool;
use segue_session::relay::{AllowAll, RelayTable};
use segue_session::Config;

fn open(version: u8) -> Open {
    Open {
        version,
        ticket: b"TICKET-SECRET".to_vec(),
        session_id: [1; 16],
        resume_secret: [0xab; 32],
        attach_gen: 0,
        retry: false,
        anchor_instance_id: 0,
        kind: Kind::Tcp,
        target: Target::Domain("example.com".into(), 443),
        exit_class: 0,
        first_data: Vec::new(),
    }
}

#[test]
fn open_with_other_version_is_rejected_with_version() {
    let pool = Pool::new(1 << 20);
    let mut relay = RelayTable::new(Config::default(), pool, Box::new(AllowAll), 1);
    relay.add_carrier(1);
    let mut d = FrameDecoder::new();
    d.push(&Frame::Open(open(3)).to_bytes());
    let e = d.next_frame().unwrap_err();
    relay.on_decode_error(1, e);
    match relay.poll_transmit(1, Instant::now()) {
        Some(Frame::Reject(r)) => assert_eq!(r.code, code::VERSION),
        other => panic!("expected REJECT(version), got {other:?}"),
    }
    assert_eq!(relay.take_closed_carriers(), vec![1]);
    assert_eq!(relay.session_count(), 0);
}

#[test]
fn debug_output_never_contains_secrets() {
    let o = format!("{:?}", Frame::Open(open(4)));
    assert!(!o.contains("171"), "resume secret leaked: {o}"); // 0xab
    assert!(!o.contains("84, 73, 67"), "ticket leaked: {o}");
    let pool = Pool::new(1 << 20);
    let params = OpenParams {
        ticket: b"TICKET-SECRET".to_vec(),
        kind: Kind::Tcp,
        target: Target::Domain("example.com".into(), 443),
        exit_class: 0,
        anchor_node_id: 0,
        instance_hint: 0,
    };
    let c = ClientSession::with_ids(
        Config::default(),
        &pool,
        params,
        [2; 16],
        [0xab; 32],
        Instant::now(),
    )
    .unwrap();
    let s = format!("{c:?}");
    assert!(!s.contains("171") && !s.contains("84, 73, 67"), "{s}");
}
