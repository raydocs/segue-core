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

mod stall_field {
    //! r10 N3: the `t_stall_ms` field changed the OPEN / RESUME layout, so
    //! the wire version is 5; its range is `1..=STALL_MS_MAX` on both
    //! sides (0 malformed, the encoder clamps instead of asserting).

    use segue_session::codec::{
        ty, Frame, FrameDecoder, Kind, Open, Resume, Target, STALL_MS_MAX, VARINT_MAX, VERSION,
    };
    use segue_session::ProtoError;

    pub fn open(version: u8, ms: Option<u64>, first: &[u8]) -> Open {
        Open {
            version,
            ticket: b"t".to_vec(),
            session_id: [1; 16],
            resume_secret: [2; 32],
            attach_gen: 3,
            retry: false,
            anchor_instance_id: 0,
            kind: Kind::Tcp,
            target: Target::Domain("example.com".into(), 443),
            exit_class: 1,
            t_stall_ms: ms,
            first_data: first.to_vec(),
        }
    }

    pub fn resume(version: u8, ms: Option<u64>) -> Resume {
        Resume {
            version,
            ticket: b"t".to_vec(),
            anchor_node_id: 5,
            anchor_instance_id: 6,
            session_id: [1; 16],
            resume_secret: [2; 32],
            attach_gen: 7,
            recv_offset: 8,
            max_offset: 9,
            t_stall_ms: ms,
        }
    }

    /// `(type, flags, payload)` of one encoded frame.
    pub fn split(bytes: &[u8]) -> (u8, u8, Vec<u8>) {
        let (len, n) = segue_session::codec::get_varint(&bytes[2..]).unwrap();
        let p = bytes[2 + n..].to_vec();
        assert_eq!(p.len() as u64, len);
        (bytes[0], bytes[1], p)
    }

    #[test]
    fn version_is_five() {
        assert_eq!(VERSION, 5, "the t_stall_ms layout is wire version 5");
        assert_eq!(STALL_MS_MAX, VARINT_MAX);
    }

    #[test]
    fn zero_is_malformed_in_open_and_resume() {
        // Encode with 1, then patch the field to 0 on the wire.
        let (t, f, mut p) = split(&Frame::Open(open(VERSION, Some(1), b"")).to_bytes());
        assert_eq!(*p.last().unwrap(), 1);
        *p.last_mut().unwrap() = 0;
        assert_eq!(Frame::decode(t, f, &p), Err(ProtoError::Malformed));
        let (t, f, mut p) = split(&Frame::Resume(resume(VERSION, Some(1))).to_bytes());
        *p.last_mut().unwrap() = 0;
        assert_eq!(Frame::decode(t, f, &p), Err(ProtoError::Malformed));
    }

    #[test]
    fn boundaries_round_trip_and_out_of_range_clamps() {
        for (sent, read) in [
            (1, 1),
            (63, 63),
            (64, 64),
            (16_383, 16_383),
            (16_384, 16_384),
            ((1 << 30) - 1, (1 << 30) - 1),
            (1 << 30, 1 << 30),
            (STALL_MS_MAX, STALL_MS_MAX),
            // Beyond the varint range: clamped, never an encoder panic.
            (STALL_MS_MAX + 1, STALL_MS_MAX),
            (u64::MAX, STALL_MS_MAX),
            // 0 is never sent: the smallest bound instead.
            (0, 1),
        ] {
            for f in [
                Frame::Open(open(VERSION, Some(sent), b"x")),
                Frame::Resume(resume(VERSION, Some(sent))),
            ] {
                let mut d = FrameDecoder::new();
                d.push(&f.to_bytes());
                let got = match d.next_frame().unwrap().unwrap() {
                    Frame::Open(o) => {
                        assert_eq!(o.first_data, b"x", "first_data intact for {sent}");
                        o.t_stall_ms
                    }
                    Frame::Resume(r) => r.t_stall_ms,
                    other => panic!("{other:?}"),
                };
                assert_eq!(got, Some(read), "sent {sent}");
            }
        }
    }

    #[test]
    fn truncated_field_is_malformed() {
        // 16_384 takes a 4-byte varint (0x80 prefix).
        for f in [
            Frame::Open(open(VERSION, Some(16_384), b"")),
            Frame::Resume(resume(VERSION, Some(16_384))),
        ] {
            let (t, fl, p) = split(&f.to_bytes());
            for cut in 1..4 {
                let q = &p[..p.len() - cut];
                assert_eq!(
                    Frame::decode(t, fl, q),
                    Err(ProtoError::Malformed),
                    "type {t:#x} cut {cut}"
                );
            }
        }
        // OPEN flagged as carrying the field but ending right after
        // exit_class.
        let (t, fl, p) = split(&Frame::Open(open(VERSION, Some(5), b"")).to_bytes());
        assert_eq!(Frame::decode(t, fl, &p[..p.len() - 1]), Err(ProtoError::Malformed));
        // RESUME with a byte after the field.
        let (t, fl, mut p) = split(&Frame::Resume(resume(VERSION, Some(5))).to_bytes());
        p.push(0);
        assert_eq!(Frame::decode(t, fl, &p), Err(ProtoError::Malformed));
        assert_eq!(t, ty::RESUME);
    }
}
