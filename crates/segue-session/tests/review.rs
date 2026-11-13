//! Regression tests from review: REJECT(version) and secret redaction.

use std::time::Instant;

use segue_session::client::{ClientSession, OpenParams};
use segue_session::codec::{code, Frame, FrameDecoder, Kind, Open, Opened, Target};
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

/// Review r7 #11 / #9: with the FIN held for the site writer, a site that
/// never finishes is reset. The tombstone records `site_reset`, and its
/// final receive offset stops at the FIN offset (the FIN was never
/// acknowledged), so a RESUME can never read the end as clean. Only a
/// reported flush acknowledges the FIN.
#[test]
fn a_held_fin_reset_by_the_site_writer_leaves_a_reset_tombstone() {
    let sid = [1; 16];
    let up = b"upload".to_vec();
    let start = |hold: bool| {
        let pool = Pool::new(1 << 20);
        let mut relay = RelayTable::new(Config::default(), pool, Box::new(AllowAll), 1);
        relay.confirm_site_flush(hold);
        relay.add_carrier(1);
        let t = Instant::now();
        relay.on_frame(1, Frame::Open(open(4)), t);
        relay.connect_done(&sid, Ok(()), t);
        relay.on_frame(
            1,
            Frame::Data {
                offset: 0,
                data: up.clone(),
                pad: 0,
            },
            t,
        );
        assert!(!relay.upload_complete(&sid), "no FIN yet");
        relay.on_frame(1, Frame::Fin { offset: 6 }, t);
        assert!(relay.upload_complete(&sid));
        let mut b = [0u8; 64];
        assert_eq!(relay.read(&sid, &mut b, t), 6);
        assert!(relay.read_eof(&sid), "the site writer may shut down");
        relay
    };

    let mut relay = start(true);
    // Past the delayed-ACK timer: whatever ACK is owed goes out.
    let t = Instant::now() + std::time::Duration::from_secs(1);
    relay.handle_timeout(t);
    // Drain the carrier: the data is acknowledged, the held FIN is not.
    let mut acked = 0;
    while let Some(f) = relay.poll_transmit(1, t) {
        match f {
            Frame::Ack { recv_offset, .. } | Frame::Opened(Opened { recv_offset, .. }) => {
                acked = acked.max(recv_offset)
            }
            _ => {}
        }
    }
    assert_eq!(acked, 6, "FIN acknowledged before the site flush");
    assert!(relay.state(&sid).is_some());
    relay.site_reset(&sid);
    let tomb = relay.has_tomb(&sid).expect("tombstone");
    assert_eq!(tomb.close_code, code::SITE_RESET);
    assert_ne!(tomb.close_code, code::CLEAN);
    assert_eq!(tomb.final_recv_offset, 6, "the FIN must not be counted");
    let mut rst = None;
    while let Some(f) = relay.poll_transmit(1, t) {
        if let Frame::Rst { code } = f {
            rst = Some(code);
        }
    }
    assert_eq!(rst, Some(code::SITE_RESET));

    // Control: the same upload reported flushed acknowledges the FIN.
    let mut relay = start(true);
    relay.site_flushed(&sid, t);
    let t = t + std::time::Duration::from_secs(1);
    relay.handle_timeout(t);
    let mut acked = 0;
    while let Some(f) = relay.poll_transmit(1, t) {
        match f {
            Frame::Ack { recv_offset, .. } | Frame::Opened(Opened { recv_offset, .. }) => {
                acked = acked.max(recv_offset)
            }
            _ => {}
        }
    }
    assert_eq!(acked, 7, "flushed: the FIN is acknowledged");
}
