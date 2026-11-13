//! Regression tests from review: REJECT(version) and secret redaction.

use std::time::Instant;

use segue_session::client::{ClientSession, OpenParams};
use segue_session::codec::{
    code, Frame, FrameDecoder, Kind, Open, Opened, Resume, Target, VERSION,
};
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
        t_stall_ms: None,
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
    let o = format!("{:?}", Frame::Open(open(VERSION)));
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
        relay.on_frame(1, Frame::Open(open(VERSION)), t);
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

/// What a wire-version-4 decoder (7faf3d0b, before `t_stall_ms`) does
/// with an OPEN / RESUME / CTRL_HELLO payload before reading anything
/// else: the version byte first, `ProtoError::Version` on mismatch, which
/// its relay answers with `REJECT(version)` (relay.rs, same path as
/// today's). Only this gate matters for the matrix: past it a v4 decoder
/// would read the new field as `first_data`.
fn v4_gate(ty: u8, payload: &[u8]) -> Result<(), segue_session::ProtoError> {
    use segue_session::codec::ty as t;
    assert!(matches!(ty, t::OPEN | t::RESUME | t::CTRL_HELLO), "{ty:#x}");
    match payload.first() {
        Some(4) => Ok(()),
        Some(&v) => Err(segue_session::ProtoError::Version(v)),
        None => Err(segue_session::ProtoError::Malformed),
    }
}

fn split(bytes: &[u8]) -> (u8, Vec<u8>) {
    let (_, n) = segue_session::codec::get_varint(&bytes[2..]).unwrap();
    (bytes[0], bytes[2 + n..].to_vec())
}

fn resume_v(version: u8) -> Resume {
    Resume {
        version,
        ticket: b"t".to_vec(),
        anchor_node_id: 0,
        anchor_instance_id: 1,
        session_id: [1; 16],
        resume_secret: [0xab; 32],
        attach_gen: 1,
        recv_offset: 0,
        max_offset: 0,
        t_stall_ms: Some(1000),
    }
}

/// r10 N3, v4 client → v5 relay: OPEN (with or without the field, with
/// first data), RESUME and CTRL_HELLO of version 4 are answered
/// `REJECT(version)` before any session state exists.
#[test]
fn v4_frames_to_a_v5_relay_are_rejected_with_version() {
    let mut o = open(4);
    o.first_data = b"GET / HTTP/1.1\r\n".to_vec();
    let mut o_field = o.clone();
    o_field.t_stall_ms = Some(1000);
    let hello = segue_session::codec::CtrlHello {
        version: 4,
        ticket: b"t".to_vec(),
        held_anchors: vec![1],
    };
    let hello_bytes = hello.to_frame().to_bytes();
    for (name, bytes) in [
        ("open", Frame::Open(o).to_bytes()),
        ("open+field", Frame::Open(o_field).to_bytes()),
        ("resume", Frame::Resume(resume_v(4)).to_bytes()),
        ("hello", hello_bytes),
    ] {
        let pool = Pool::new(1 << 20);
        let mut relay = RelayTable::new(Config::default(), pool, Box::new(AllowAll), 1);
        relay.add_carrier(1);
        let t = Instant::now();
        let mut d = FrameDecoder::new();
        d.push(&bytes);
        match d.next_frame() {
            Err(e) => {
                assert_eq!(e, segue_session::ProtoError::Version(4), "{name}");
                relay.on_decode_error(1, e);
            }
            Ok(Some(f)) => relay.on_frame(1, f, t),
            Ok(None) => panic!("{name}: skipped"),
        }
        match relay.poll_transmit(1, t) {
            Some(Frame::Reject(r)) => assert_eq!(r.code, code::VERSION, "{name}"),
            other => panic!("{name}: expected REJECT(version), got {other:?}"),
        }
        assert_eq!(relay.take_closed_carriers(), vec![1], "{name}");
        assert_eq!(relay.session_count(), 0, "{name}");
    }
}

/// r10 N3, v5 client → v4 relay: every frame the client sends that a v4
/// decoder reads differently fails its version gate (so the old relay
/// answers `REJECT(version)` instead of taking the field for upload
/// bytes), and the client ends the session on that REJECT, on the first
/// OPEN and on a RESUME (whose generation the REJECT cannot echo), with
/// no byte delivered to the app.
#[test]
fn v5_client_to_a_v4_relay_fails_the_version_gate_and_resets() {
    let params = OpenParams {
        ticket: b"t".to_vec(),
        kind: Kind::Tcp,
        target: Target::Domain("example.com".into(), 443),
        exit_class: 0,
        anchor_node_id: 0,
        instance_hint: 0,
    };
    let t = Instant::now();
    let pool = Pool::new(1 << 20);
    let mut c = ClientSession::new(Config::default(), &pool, params.clone(), t).unwrap();
    c.attach(1, t);
    let f = c.poll_transmit(1, t).expect("OPEN");
    let (ty, p) = split(&f.to_bytes());
    assert_eq!(
        v4_gate(ty, &p),
        Err(segue_session::ProtoError::Version(VERSION))
    );
    c.on_frame(
        1,
        Frame::Reject(segue_session::codec::Reject {
            code: code::VERSION,
            attach_gen: 0,
            closed: None,
        }),
        t,
    )
    .unwrap();
    assert_eq!(
        c.close_reason(),
        Some(segue_session::client::CloseReason::Reset(code::VERSION))
    );
    assert!(!c.wants_attach(t + std::time::Duration::from_secs(10)));

    // A RESUME (generation 1) answered REJECT(version), generation 0.
    let mut c = ClientSession::new(Config::default(), &pool, params, t).unwrap();
    c.attach(1, t);
    let _ = c.poll_transmit(1, t);
    c.on_frame(
        1,
        Frame::Opened(Opened {
            instance_id: 9,
            attach_gen: 0,
            recv_offset: 0,
            max_offset: 1 << 16,
            window_cap: 1 << 16,
            ack_bytes: 0,
        }),
        t,
    )
    .unwrap();
    c.attach(2, t);
    let f = c.poll_transmit(2, t).expect("RESUME");
    assert!(matches!(f, Frame::Resume(_)), "{f:?}");
    let (ty, p) = split(&f.to_bytes());
    assert!(v4_gate(ty, &p).is_err());
    c.on_frame(
        2,
        Frame::Reject(segue_session::codec::Reject {
            code: code::VERSION,
            attach_gen: 0,
            closed: None,
        }),
        t,
    )
    .unwrap();
    assert_eq!(
        c.close_reason(),
        Some(segue_session::client::CloseReason::Reset(code::VERSION)),
        "a RESUME answered REJECT(version) ends the session"
    );
    assert_eq!(c.recv_half().recv_offset(), 0, "no byte reached the app");

    // CTRL_HELLO.
    let hello = segue_session::codec::CtrlHello {
        version: VERSION,
        ticket: b"t".to_vec(),
        held_anchors: vec![],
    };
    let (ty, p) = split(&hello.to_frame().to_bytes());
    assert!(v4_gate(ty, &p).is_err());
}
