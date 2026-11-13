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
    assert!(matches!(d.next_frame().unwrap(), Some(Frame::Ping { nonce: 7 })));
    assert_eq!(pad_len(d.next_frame().unwrap()), 10);
    assert_eq!(pad_len(d.next_frame().unwrap()), 0);
    assert!(matches!(d.next_frame().unwrap(), Some(Frame::Fin { offset: 99 })));
    assert!(d.next_frame().unwrap().is_none());
    assert_eq!(d.buffered(), 0);
}
