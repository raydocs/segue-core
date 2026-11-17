//! Vectors derived from `anytls/sing-anytls` (`session/session.go`,
//! `session/frame.go`, `padding/padding.go`, `client.go`) and sing's
//! `common/uot/protocol.go`. Randomness is replaced by a fixed jitter so that
//! the record splits are exactly reproducible.

use super::*;

fn fixed_jitter(min: u32, _max: u32) -> u32 {
    min
}

fn target_addr(addr: segue_routing::TargetAddr) -> Target {
    Target::new(addr, 443, segue_routing::Network::Tcp)
}

#[test]
fn frame_header_is_command_stream_id_and_length_big_endian() {
    let header = FrameHeader {
        command: Command::Push,
        stream_id: 0x0102_0304,
        length: 0x0506,
    };
    let mut wire = Vec::new();
    header.encode(&mut wire);
    assert_eq!(wire, [0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    assert_eq!(FrameHeader::decode(&wire).unwrap(), Some(header));
}

#[test]
fn short_or_unknown_headers_are_incomplete_or_invalid() {
    assert_eq!(FrameHeader::decode(&[0x02, 0, 0, 0]), Ok(None));
    assert_eq!(
        FrameHeader::decode(&[0x0b, 0, 0, 0, 1, 0, 0]),
        Err(WireError::UnknownCommand(11))
    );
    // A `Waste` header with no payload is well formed.
    assert_eq!(
        FrameHeader::decode(&[0x00, 0, 0, 0, 0, 0, 0]).unwrap(),
        Some(FrameHeader {
            command: Command::Waste,
            stream_id: 0,
            length: 0
        })
    );
}

#[test]
fn commands_match_the_pinned_numbering() {
    for (byte, command) in [
        (0, Command::Waste),
        (1, Command::Syn),
        (2, Command::Push),
        (3, Command::Fin),
        (4, Command::Settings),
        (5, Command::Alert),
        (6, Command::UpdatePaddingScheme),
        (7, Command::SynAck),
        (8, Command::HeartRequest),
        (9, Command::HeartResponse),
        (10, Command::ServerSettings),
    ] {
        assert_eq!(Command::from_byte(byte), Some(command), "{byte}");
        assert_eq!(command as u8, byte);
    }
    assert_eq!(Command::from_byte(11), None);
}

#[test]
fn push_frames_split_at_the_uint16_limit() {
    // One frame.
    assert_eq!(
        push_frames(7, b"ab"),
        [0x02, 0, 0, 0, 7, 0, 2, b'a', b'b']
    );
    // Empty data writes nothing at all, as the reference `writeDataFrame`.
    assert!(push_frames(7, b"").is_empty());
    // 0xFFFF + 1 bytes become two frames, 0xFFFF and 1.
    let data = vec![0xaa; MAX_FRAME_PAYLOAD + 1];
    let wire = push_frames(1, &data);
    assert_eq!(&wire[..7], &[0x02, 0, 0, 0, 1, 0xff, 0xff]);
    let second = 7 + MAX_FRAME_PAYLOAD;
    assert_eq!(&wire[second..second + 7], &[0x02, 0, 0, 0, 1, 0x00, 0x01]);
    assert_eq!(wire.len(), data.len() + 2 * HEADER_LENGTH);
    assert_eq!(wire[second + 7], 0xaa);
}

#[test]
fn settings_payload_round_trips() {
    let payload = settings_payload("75cff2ad89aadf5e257059ee571ebe11", None);
    assert_eq!(
        payload,
        b"client=segue-anytls/0.1\npadding-md5=75cff2ad89aadf5e257059ee571ebe11\nv=2"
    );
    let map = parse_settings(&payload).unwrap();
    assert_eq!(map["v"], "2");
    assert_eq!(map["padding-md5"], "75cff2ad89aadf5e257059ee571ebe11");
    assert_eq!(map["client"], CLIENT_VERSION);
    // `client_metadata` replaces the client string verbatim.
    let map = parse_settings(&settings_payload("00", Some("sing-anytls/0.0.13"))).unwrap();
    assert_eq!(map["client"], "sing-anytls/0.0.13");
    assert_eq!(map["padding-md5"], "00");
    // A line without `=` is skipped; a later duplicate wins.
    let map = parse_settings(b"v=1\nnonsense\nv=2").unwrap();
    assert_eq!(map["v"], "2");
    assert_eq!(parse_settings(b"\xff").unwrap_err(), WireError::Settings);
}

#[test]
fn auth_is_the_sha256_of_the_password() {
    let auth = AnyTlsAuth::new("synthetic-anytls-password").unwrap();
    let hex: String = auth
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        hex,
        "9eba6ae55bcaf115192f5729114a0e96031eff4e71dc3fe27f21e08f699078f1"
    );
    // The digest is a credential: Debug never prints it.
    assert_eq!(format!("{auth:?}"), "AnyTlsAuth(<redacted>)");
    assert_eq!(
        AnyTlsAuth::new("").unwrap_err(),
        WireError::PasswordLength
    );
}

#[test]
fn default_padding_scheme_digest_matches_the_reference() {
    // `fmt.Sprintf("%x", md5.Sum(DefaultPaddingScheme))` over the 137-byte
    // scheme in `sing-anytls/padding/padding.go`.
    assert_eq!(DEFAULT_PADDING_SCHEME.len(), 137);
    let factory = PaddingFactory::default();
    assert_eq!(factory.md5_hex(), "75cff2ad89aadf5e257059ee571ebe11");
    assert_eq!(factory.stop(), 8);
    assert_eq!(factory.raw(), DEFAULT_PADDING_SCHEME);
}

#[test]
fn padding_scheme_splits_every_default_counter_as_the_go_code_does() {
    let factory = PaddingFactory::default();
    // Counter 0 is a single 30-byte hello record.
    assert_eq!(factory.record_sizes(0, fixed_jitter), [30]);
    assert_eq!(factory.hello_padding(fixed_jitter), 30);
    // 1=100-400 draws from [100, 400).
    assert_eq!(factory.record_sizes(1, fixed_jitter), [100]);
    assert_eq!(factory.record_sizes(1, |_, max| max - 1), [399]);
    // 2 alternates ranges with check marks: five ranges, four marks.
    assert_eq!(
        factory.record_sizes(2, fixed_jitter),
        [400, 0, 500, 0, 500, 0, 500, 0, 500]
    );
    // 3=9-9,500-1000 is an exact 9 then a range.
    assert_eq!(factory.record_sizes(3, |_, max| max - 1), [9, 999]);
    // Counters 4..=7 are one 500-1000 range; 8 and up are absent.
    assert_eq!(factory.record_sizes(7, fixed_jitter), [500]);
    assert!(factory.record_sizes(8, fixed_jitter).is_empty());
    assert!(factory.record_sizes(9, fixed_jitter).is_empty());
}

#[test]
fn malformed_schemes_are_rejected_or_skipped_like_the_reference() {
    // No `stop`, or a non-numeric one: `NewPaddingFactory` returns nil.
    assert!(PaddingFactory::new(b"0=30-30").is_none());
    assert!(PaddingFactory::new(b"stop=x\n0=30-30").is_none());
    // Reversed ranges are swapped; non-positive, unparsable and shapeless
    // entries are dropped.
    let factory = PaddingFactory::new(b"stop=2\n0=50-40\n1=2-2,0-10,nope,7,1-2-3").unwrap();
    assert_eq!(factory.record_sizes(0, fixed_jitter), [40]);
    assert_eq!(factory.record_sizes(1, fixed_jitter), [2]);
    // An empty scheme has no keys at all, so it is nil.
    assert!(PaddingFactory::new(b"").is_none());
}

#[test]
fn hello_is_the_digest_the_padding_length_and_zeros() {
    let auth = AnyTlsAuth::new("synthetic-anytls-password").unwrap();
    let frame = hello_frames(&auth, 4);
    assert_eq!(frame.len(), PASSWORD_HASH_LENGTH + 2 + 4);
    assert_eq!(&frame[..PASSWORD_HASH_LENGTH], auth.as_bytes());
    assert_eq!(&frame[PASSWORD_HASH_LENGTH..], &[0, 4, 0, 0, 0, 0]);
}

#[test]
fn records_are_split_and_filled_with_waste_frames() {
    let factory = PaddingFactory::new(b"stop=2\n0=30-30\n1=40-40,c").unwrap();
    // A 12-byte payload at counter 0 leaves 30 - 12 = 18 bytes, which become
    // one `Waste` frame of 18 - 7 = 11 payload bytes.
    let payload = vec![0xee; 12];
    let writes = pad_record(&factory, 0, payload.clone(), fixed_jitter);
    assert_eq!(writes.len(), 1);
    assert_eq!(&writes[0][..12], &payload[..]);
    assert_eq!(&writes[0][12..19], &[0x00, 0, 0, 0, 0, 0, 11]);
    assert_eq!(writes[0].len(), 30);
    // A payload longer than the record is cut at 30 bytes with the rest sent
    // after the scheme's entries.
    let writes = pad_record(&factory, 0, vec![0xee; 50], fixed_jitter);
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0].len(), 30);
    assert_eq!(writes[1].len(), 20);
    // Nothing left over: the record is one bare `Waste` frame of `size`
    // payload bytes plus its header, as the reference writes it.
    let writes = pad_record(&factory, 0, Vec::new(), fixed_jitter);
    assert_eq!(writes.len(), 1);
    assert_eq!(&writes[0][..7], &[0x00, 0, 0, 0, 0, 0, 0x1e]);
    assert_eq!(writes[0].len(), HEADER_LENGTH + 30);
    // Counter 1 is 40 bytes then a check mark: 10 bytes fit, and no filler.
    let writes = pad_record(&factory, 1, vec![0x01; 10], fixed_jitter);
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].len(), 40);
    assert_eq!(&writes[0][10..17], &[0x00, 0, 0, 0, 0, 0, 23]);
    // At or past `stop`, the bytes go out untouched.
    let writes = pad_record(&factory, 2, vec![0x02; 3], fixed_jitter);
    assert_eq!(writes, [vec![0x02; 3]]);
    assert!(pad_record(&factory, 2, Vec::new(), fixed_jitter).is_empty());
}

#[test]
fn waste_frame_filling_never_underflows_a_short_record() {
    // Record 5 with 4 bytes left: 5 - 4 - 7 underflows, so nothing is added
    // and the tail goes out as it is.
    let factory = PaddingFactory::new(b"stop=1\n0=5-5\n1=5-5").unwrap();
    let writes = pad_record(&factory, 0, vec![9, 9, 9, 9], fixed_jitter);
    assert_eq!(writes, [vec![9, 9, 9, 9]]);
}

#[test]
fn socksaddr_encodes_each_family_like_sing() {
    let mut wire = Vec::new();
    encode_socksaddr(
        &target_addr(segue_routing::TargetAddr::Ip("192.0.2.1".parse().unwrap())),
        &mut wire,
    )
    .unwrap();
    assert_eq!(wire, [0x00, 192, 0, 2, 1, 0x01, 0xbb]);

    let mut wire = Vec::new();
    encode_socksaddr(
        &target_addr(segue_routing::TargetAddr::Ip("2001:db8::1".parse().unwrap())),
        &mut wire,
    )
    .unwrap();
    assert_eq!(wire[0], 0x01);
    assert_eq!(wire.len(), 19);
    assert_eq!(&wire[17..], &[0x01, 0xbb]);

    let wire = encode_stream_target(&target_addr(segue_routing::TargetAddr::Domain(
        "example.test".into(),
    )))
    .unwrap();
    assert_eq!(&wire[..2], &[0x02, 12]);
    assert_eq!(&wire[2..14], b"example.test");
    assert_eq!(&wire[14..], &[0x01, 0xbb]);

    // Every encoding decodes back to the same destination.
    for target in [
        target_addr(segue_routing::TargetAddr::Ip("192.0.2.1".parse().unwrap())),
        target_addr(segue_routing::TargetAddr::Ip("2001:db8::1".parse().unwrap())),
        target_addr(segue_routing::TargetAddr::Domain("example.test".into())),
    ] {
        let wire = encode_stream_target(&target).unwrap();
        let (addr, port, consumed) = decode_socksaddr(&wire).unwrap().unwrap();
        assert_eq!(addr, target.addr);
        assert_eq!(port, 443);
        assert_eq!(consumed, wire.len());
    }
}

#[test]
fn empty_or_oversized_domains_and_zero_ports_are_rejected() {
    let long = "a".repeat(256);
    for target in [
        target_addr(segue_routing::TargetAddr::Domain(String::new())),
        target_addr(segue_routing::TargetAddr::Domain(long)),
    ] {
        assert_eq!(
            encode_stream_target(&target).unwrap_err(),
            WireError::Domain
        );
    }
    // `Target` of port 0 is refused, except for the UoT magic destination,
    // which sing writes with port 0.
    let zero = Target::new(
        segue_routing::TargetAddr::Domain("example.test".into()),
        0,
        segue_routing::Network::Tcp,
    );
    assert_eq!(encode_stream_target(&zero).unwrap_err(), WireError::Port);

    // A truncated buffer is incomplete, not malformed.
    assert_eq!(decode_socksaddr(&[]).unwrap(), None);
    assert_eq!(decode_socksaddr(&[0x00, 1, 2]).unwrap(), None);
    assert_eq!(decode_socksaddr(&[0x02, 5, b'a']).unwrap(), None);
    // An unknown family is refused.
    assert!(decode_socksaddr(&[0x07, 0, 0]).is_err());
}

#[test]
fn uot_magic_matches_sing_and_carries_port_zero() {
    assert_eq!(UOT_MAGIC_ADDRESS, "sp.v2.udp-over-tcp.arpa");
    let target = uot_request_target();
    assert_eq!(target.port, 0);
    // `CreateProxy` writes the magic address as the stream's destination.
    let wire = encode_stream_target(&target).unwrap();
    assert_eq!(wire[0], 0x02);
    assert_eq!(&wire[2..2 + UOT_MAGIC_ADDRESS.len()], UOT_MAGIC_ADDRESS.as_bytes());
    assert_eq!(&wire[2 + UOT_MAGIC_ADDRESS.len()..], &[0, 0]);
}

#[test]
fn uot_requests_and_datagrams_round_trip() {
    let destination = Target::new(
        segue_routing::TargetAddr::Domain("dns.example".into()),
        53,
        segue_routing::Network::Udp,
    );
    // isConnect = true, then the destination.
    let request = encode_uot_request(&destination, true).unwrap();
    assert_eq!(request[0], 1);
    assert_eq!(&request[1..], &encode_stream_target(&destination).unwrap()[..]);
    assert_eq!(encode_uot_request(&destination, false).unwrap()[0], 0);
    let zero = Target::new(destination.addr.clone(), 0, segue_routing::Network::Udp);
    assert_eq!(
        encode_uot_request(&zero, true).unwrap_err(),
        WireError::Port
    );

    let frame = encode_uot_datagram(b"hello").unwrap();
    assert_eq!(frame, [0, 5, b'h', b'e', b'l', b'l', b'o']);
    assert_eq!(decode_uot_datagram(&frame).unwrap(), Some((&b"hello"[..], 7)));
    // Prefixes are incomplete until the whole frame arrives.
    assert_eq!(decode_uot_datagram(&frame[..1]).unwrap(), None);
    assert_eq!(decode_uot_datagram(&frame[..6]).unwrap(), None);
    // A length past the 8192-byte bound poisons the stream at once.
    assert_eq!(
        decode_uot_datagram(&[0x20, 0x01]).unwrap_err(),
        WireError::PayloadLength
    );
    assert_eq!(
        encode_uot_datagram(&vec![0u8; MAX_UDP_PAYLOAD_LENGTH + 1]).unwrap_err(),
        WireError::PayloadLength
    );
}

#[test]
fn random_jitter_stays_inside_the_exclusive_range() {
    for _ in 0..256 {
        let value = random_jitter(100, 400);
        assert!((100..400).contains(&value), "{value}");
    }
}
