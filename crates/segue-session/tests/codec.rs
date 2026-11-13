//! Wire codec round trips for frames the driver rarely sends (r7 #6).

use segue_session::codec::{Frame, FrameDecoder, MAX_PAYLOAD};

fn pad_len(f: Option<Frame>) -> usize {
    match f {
        Some(Frame::Pad(n)) => n,
        other => panic!("expected PAD, got {other:?}"),
    }
}

#[test]
fn pad_frames_round_trip_at_every_length_class() {
    for n in [0, 1, 5, 6, 63, 64, 16_383, MAX_PAYLOAD] {
        let bytes = Frame::Pad(n).to_bytes();
        let mut d = FrameDecoder::new();
        d.push(&bytes);
        assert_eq!(pad_len(d.next_frame().unwrap()), n, "PAD({n})");
        assert_eq!(d.buffered(), 0, "PAD({n}) left bytes behind");
    }
}

#[test]
fn pad_appended_after_other_frames_keeps_them_intact() {
    let mut out = Vec::new();
    Frame::Ping { nonce: 7 }.encode(&mut out);
    Frame::Pad(10).encode(&mut out);
    Frame::Pad(0).encode(&mut out);
    Frame::Fin { offset: 99 }.encode(&mut out);
    let mut d = FrameDecoder::new();
    d.push(&out);
    assert!(matches!(
        d.next_frame().unwrap(),
        Some(Frame::Ping { nonce: 7 })
    ));
    assert_eq!(pad_len(d.next_frame().unwrap()), 10);
    assert_eq!(pad_len(d.next_frame().unwrap()), 0);
    assert!(matches!(
        d.next_frame().unwrap(),
        Some(Frame::Fin { offset: 99 })
    ));
    assert!(d.next_frame().unwrap().is_none());
    assert_eq!(d.buffered(), 0);
}

/// r9: OPEN and RESUME carry the client's stall bound (optional, so a
/// frame without it decodes as before).
#[test]
fn open_and_resume_carry_the_client_stall_bound() {
    use segue_session::codec::{Kind, Open, Resume, Target, VERSION};
    for ms in [None, Some(1000), Some(1 << 40)] {
        let open = Frame::Open(Open {
            version: VERSION,
            ticket: b"t".to_vec(),
            session_id: [1; 16],
            resume_secret: [2; 32],
            attach_gen: 3,
            retry: true,
            anchor_instance_id: 4,
            kind: Kind::Tcp,
            target: Target::Domain("example.com".into(), 443),
            exit_class: 1,
            t_stall_ms: ms,
            first_data: b"hello".to_vec(),
        });
        let resume = Frame::Resume(Resume {
            version: VERSION,
            ticket: b"t".to_vec(),
            anchor_node_id: 5,
            anchor_instance_id: 6,
            session_id: [1; 16],
            resume_secret: [2; 32],
            attach_gen: 7,
            recv_offset: 8,
            max_offset: 9,
            t_stall_ms: ms,
        });
        for f in [open, resume] {
            let mut d = FrameDecoder::new();
            d.push(&f.to_bytes());
            assert_eq!(d.next_frame().unwrap(), Some(f));
        }
    }
}
