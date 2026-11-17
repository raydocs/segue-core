use super::*;
use std::net::IpAddr;

fn target() -> Target {
    Target::new(TargetAddr::Domain("dns.example".into()), 53, Network::Udp)
}

fn packet(id: u16, total: u8, index: u8, payload: &[u8]) -> Packet {
    Packet {
        association_id: 0x1234,
        packet_id: id,
        fragment_total: total,
        fragment_id: index,
        address: if index == 0 {
            Some(Address::from_target(&target()).unwrap())
        } else {
            None
        },
        payload: payload.to_vec(),
    }
}

#[test]
fn address_encodings_cover_domains_ips_and_the_fragment_sentinel() {
    for (address, expected) in [
        (
            Target::new(TargetAddr::Domain("a.example".into()), 443, Network::Udp),
            &[
                0, 9, b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 1, 187,
            ][..],
        ),
        (
            Target::new(
                TargetAddr::Ip(IpAddr::from([192, 0, 2, 1])),
                53,
                Network::Udp,
            ),
            &[1, 192, 0, 2, 1, 0, 53][..],
        ),
        (
            Target::new(
                TargetAddr::Ip("2001:db8::1".parse().unwrap()),
                443,
                Network::Udp,
            ),
            &[
                2, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187,
            ][..],
        ),
    ] {
        let (decoded, consumed) =
            decode(&encode(&Command::Connect(address.clone())).unwrap()).unwrap();
        assert_eq!(decoded, Command::Connect(address));
        assert_eq!(consumed, encode(&decoded).unwrap().len());
    }
    assert_eq!(decode(&[5, 1, 0xff, 0]).unwrap_err(), WireError::Address);
    let target = Target::new(
        TargetAddr::Ip("2001:db8::1".parse().unwrap()),
        443,
        Network::Udp,
    );
    let (decoded, _) = decode(&encode(&Command::Connect(target.clone())).unwrap()).unwrap();
    assert_eq!(decoded, Command::Connect(target));
}

#[test]
fn all_five_command_kinds_have_an_exact_wire_codec() {
    let uuid = [0x11; 16];
    let token = [0x22; 32];
    let cases = vec![
        Command::Authenticate { uuid, token },
        Command::Connect(target()),
        Command::Packet(packet(1, 1, 0, b"request")),
        Command::Dissociate {
            association_id: 0x1234,
        },
        Command::Heartbeat,
    ];
    for command in cases {
        let encoded = encode(&command).unwrap();
        assert_eq!(encoded[0], 5);
        assert_eq!(decode_datagram(&encoded).unwrap(), command);
        assert_eq!(decode(&encoded).unwrap().1, encoded.len());
        for length in 0..encoded.len() {
            assert_eq!(
                decode(&encoded[..length]).unwrap_err(),
                WireError::Truncated,
                "prefix of {command:?} at {length}"
            );
        }
    }
    assert_eq!(
        encode(&Command::Dissociate { association_id: 7 }).unwrap(),
        [5, 3, 0, 7]
    );
    assert_eq!(encode(&Command::Heartbeat).unwrap(), [5, 4]);
    assert_eq!(decode(&[4, 4]).unwrap_err(), WireError::Command);
    assert_eq!(decode(&[5, 255]).unwrap_err(), WireError::Command);
    assert_eq!(decode(&[5, 1, 3]).unwrap_err(), WireError::Address);
    assert_eq!(
        decode_datagram(&[5, 4, 0]).unwrap_err(),
        WireError::Trailing
    );
}

#[test]
fn authentication_encoding_does_not_expose_the_token_in_debug() {
    let command = Command::Authenticate {
        uuid: [1; 16],
        token: [2; 32],
    };
    assert_eq!(encode(&command).unwrap().len(), 50);
    assert!(format!("{command:?}").contains("redacted"));
}

#[test]
fn native_fragmentation_respects_datagram_limits_and_timeout_eviction() {
    let ipv6 = Target::new(
        TargetAddr::Ip("2001:db8::2".parse().unwrap()),
        53,
        Network::Udp,
    );
    let original = (0_u8..=255).cycle().take(5000).collect::<Vec<_>>();
    for destination in [target(), ipv6] {
        let fragments = fragment_datagrams(3, 4, &destination, &original, 1200).unwrap();
        assert!(fragments.len() >= 2);
        assert!(fragments.iter().all(|fragment| fragment.len() <= 1200));
        let decoded = fragments
            .iter()
            .map(|bytes| match decode_datagram(bytes).unwrap() {
                Command::Packet(packet) => packet,
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();
        for fragment in &decoded[1..] {
            assert!(fragment.address.is_none());
        }
        let mut reassembly = Reassembler::new(Duration::from_secs(10), 65_535).unwrap();
        let now = Instant::now();
        let last = decoded.len() - 1;
        for fragment in decoded[..last].iter().rev() {
            assert!(reassembly.feed(fragment, now).unwrap().is_none());
        }
        // Duplicate delivery is ignored and does not complete the packet early.
        assert!(reassembly.feed(&decoded[last], now).unwrap().is_none());
        let completed = reassembly.feed(&decoded[last], now).unwrap().unwrap();
        assert_eq!(completed.payload, original);
        assert_eq!(
            completed.address.unwrap().routing(Network::Udp),
            destination
        );
        // An ID already completed starts an independent subsequent packet,
        // not a ghost delivery of the earlier buffer.
        assert!(reassembly.feed(&decoded[0], now).unwrap().is_none());
    }
    let mut expired = Reassembler::new(Duration::from_secs(10), 3).unwrap();
    let mut half = packet(199, 2, 1, b"later");
    let now = Instant::now();
    assert!(expired.feed(&half, now).unwrap().is_none());
    // The original deadline evicts 'later' instead of refreshing the bag.
    assert!(expired
        .feed(&half, now + Duration::from_secs(11))
        .unwrap()
        .is_none());
    half.fragment_id = 0;
    half.address = Some(Address::from_target(&target()).unwrap());
    assert_eq!(
        expired.feed(&half, now).unwrap_err(),
        WireError::ReassemblyLimit
    );
    let commands = fragment_datagrams(4, 0, &target(), b"", 300).unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!(
        decode_datagram(&commands[0]).unwrap(),
        Command::Packet(packet(0, 1, 0, b""))
    );
    assert!(fragment_datagrams(1, 1, &target(), b"a", 5).is_err());
    assert!(fragment_datagrams(1, 1, &target(), &original, 25).is_err());
}

#[test]
fn reassembly_orders_fragments_deduplicates_and_rejects_conflicts() {
    let mut reassembly = Reassembler::new(Duration::from_secs(10), 65535).unwrap();
    let start = Instant::now();
    let second = packet(9, 3, 1, b" second");
    let third = packet(9, 3, 2, b" third");
    assert!(reassembly.feed(&second, start).unwrap().is_none());
    assert!(reassembly.feed(&second, start).unwrap().is_none());
    assert!(reassembly
        .feed(&packet(9, 3, 0, b"first"), start)
        .unwrap()
        .is_none());
    assert_eq!(
        reassembly.feed(&third, start).unwrap().unwrap().payload,
        b"first second third"
    );
    // Once complete the packet ID can be reused by the peer.
    assert!(reassembly.feed(&second, start).unwrap().is_none());
    let mut reassembly = Reassembler::new(Duration::from_secs(10), 65535).unwrap();
    assert!(reassembly
        .feed(&packet(10, 2, 0, b"one"), start)
        .unwrap()
        .is_none());
    assert_eq!(
        reassembly.feed(
            &packet(10, 2, 1, b"different"),
            start + Duration::from_secs(1)
        ),
        Err(WireError::Fragmentation)
    );
    // A duplicate mismatch is not accepted as an idempotent retransmission.
    let mut reassembly = Reassembler::new(Duration::from_secs(10), 65535).unwrap();
    reassembly.feed(&second, start).unwrap();
    assert_eq!(
        reassembly.feed(&packet(9, 3, 1, b"changed"), start),
        Err(WireError::Fragmentation)
    );
    assert_eq!(
        reassembly.feed(&packet(9, 4, 2, b"changed"), start),
        Err(WireError::Fragmentation)
    );
}

#[test]
fn reassembly_bounds_payload_size_count_and_total_memory() {
    let mut reassembly = Reassembler::new(Duration::from_secs(30), 100).unwrap();
    let start = Instant::now();
    for id in 0..16 {
        assert!(reassembly
            .feed(&packet(id, 2, 0, b"x"), start)
            .unwrap()
            .is_none());
    }
    assert_eq!(
        reassembly.feed(&packet(100, 2, 0, b"last"), start),
        Err(WireError::ReassemblyLimit)
    );
    let mut reassembly = Reassembler::new(Duration::from_secs(30), 100).unwrap();
    reassembly
        .feed(&packet(1, 2, 0, &vec![1; 80]), start)
        .unwrap();
    assert_eq!(
        reassembly.feed(&packet(1, 2, 1, &vec![2; 21]), start),
        Err(WireError::ReassemblyLimit)
    );
    assert!(Reassembler::new(Duration::ZERO, 100).is_err());
    assert!(Reassembler::new(Duration::from_secs(1), 65_536).is_err());
}
