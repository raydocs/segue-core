//! QUIC detection for the UDP front ends (KERNEL_SPEC §5.2a.2).
//!
//! The kernel carries QUIC only when it knows the destination's name for
//! certain: a fake-IP destination (TUN) or a domain in the SOCKS request.
//! Such a flow is routed by that name when it is created and stays pinned
//! to that one outbound for its life (its 5-tuple). Nothing inside the
//! flow is inspected: every connection on it goes to the same name.
//!
//! QUIC to a real IP is refused: on TUN with an ICMP port unreachable for
//! the very datagram, so the app falls back to TCP (where the TLS SNI is
//! always sniffable and routes the flow by name); on SOCKS by dropping it.
//! The kernel does not try to follow connection IDs: a short header names
//! a connection by an ID the server may have issued inside the encryption
//! (NEW_CONNECTION_ID), so no observer can prove which connection, and so
//! which server name, it belongs to (astra r8 N1–N3). Connection migration
//! across flows is therefore not supported.
//!
//! [`looks_quic`] is the one test, stateless and applied to every datagram
//! of a real-IP flow, not only the first.

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;

/// Smallest datagram a client may carry an Initial in (RFC 9000 §14.1).
/// A long header of a version we do not know counts as QUIC only from this
/// size, so ordinary UDP with a high first byte (a DNS query whose ID
/// starts with 0xC0.., say) is not taken for it.
pub const MIN_INITIAL_DATAGRAM: usize = 1200;

/// Whether `dgram` is (or starts like) a QUIC client datagram.
///
/// - A long header of QUIC v1 (RFC 9000/9001) or v2 (RFC 9369), whatever
///   its packet type and with or without the fixed bit: a client may grease
///   that bit away (RFC 9287; quinn does by default and its servers accept
///   such packets).
/// - A long header with the fixed bit set and any other version (drafts,
///   gQUIC, versions we cannot read) in a datagram of Initial size.
///
/// Packets are coalesced only behind a long header (RFC 9000 §12.2), so the
/// first packet already decides for every packet of the datagram: a
/// datagram that hides a second packet behind a QUIC first one is QUIC. A
/// short header alone cannot be told from ordinary UDP; without a long
/// header on the same flow first it is no connection any server knows.
pub fn looks_quic(dgram: &[u8]) -> bool {
    if dgram.len() < 7 || dgram[0] & 0x80 == 0 {
        return false;
    }
    let version = u32::from_be_bytes([dgram[1], dgram[2], dgram[3], dgram[4]]);
    matches!(version, V1 | V2) || (dgram[0] & 0x40 != 0 && dgram.len() >= MIN_INITIAL_DATAGRAM)
}

/// RFC 9001 Appendix A.2: the client Initial (QUIC v1, SNI example.com).
#[doc(hidden)]
pub const RFC9001_CLIENT_INITIAL: &str =
    include_str!("../testdata/quic/rfc9001-client-initial.hex");
/// RFC 9369 Appendix A.2: the same Initial for QUIC v2.
#[doc(hidden)]
pub const RFC9369_CLIENT_INITIAL: &str =
    include_str!("../testdata/quic/rfc9369-client-initial.hex");
/// The first datagram captured from quic-go (sing-box hysteria2 client,
/// SNI chatgpt.com).
#[doc(hidden)]
pub const QUIC_GO_CHATGPT_INITIAL: &str =
    include_str!("../testdata/quic/quic-go-chatgpt-initial.hex");
/// The second datagram of the same capture.
#[doc(hidden)]
pub const QUIC_GO_CHATGPT_INITIAL_2: &str =
    include_str!("../testdata/quic/quic-go-chatgpt-initial-2.hex");

#[doc(hidden)]
pub fn hex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap_or("00"), 16).unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_and_captured_initials_are_quic() {
        for v in [
            RFC9001_CLIENT_INITIAL,
            RFC9369_CLIENT_INITIAL,
            QUIC_GO_CHATGPT_INITIAL,
            QUIC_GO_CHATGPT_INITIAL_2,
        ] {
            assert!(looks_quic(&hex(v)));
        }
    }

    #[test]
    fn greased_fixed_bit_is_still_quic() {
        for v in [RFC9001_CLIENT_INITIAL, RFC9369_CLIENT_INITIAL] {
            let mut p = hex(v);
            p[0] &= !0x40;
            assert!(looks_quic(&p));
            // Any packet type, any size: a Handshake / 0-RTT long header.
            p.truncate(40);
            p[0] = 0xa0;
            assert!(looks_quic(&p));
        }
    }

    #[test]
    fn unknown_versions_count_at_initial_size() {
        let mut p = hex(RFC9001_CLIENT_INITIAL);
        p[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        assert!(looks_quic(&p));
        // gQUIC Q050.
        p[1..5].copy_from_slice(b"Q050");
        assert!(looks_quic(&p));
        // Fixed bit cleared and an unknown version: no QUIC server reads it.
        p[0] &= !0x40;
        assert!(!looks_quic(&p));
        // A DNS query whose ID starts 0xC3: ordinary UDP.
        let dns = b"\xc3\x51\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01";
        assert!(!looks_quic(dns));
    }

    #[test]
    fn short_headers_and_plain_udp_are_not() {
        assert!(!looks_quic(b"\x40\x01\x02\x03\x04\x05\x06\x07\x08 short"));
        assert!(!looks_quic(b"\x12\x34plain"));
        assert!(!looks_quic(&[]));
        assert!(!looks_quic(&[0xc0, 0, 0, 0, 1, 0]));
        // RTP (version 2: 0b10 in the top bits, fixed bit clear).
        let mut rtp = vec![0x80, 0x60, 0x12, 0x34];
        rtp.resize(1300, 0x55);
        assert!(!looks_quic(&rtp));
    }

    #[test]
    fn coalesced_datagram_is_decided_by_its_first_packet() {
        // An Initial with a short header of another connection behind it.
        let mut p = hex(RFC9001_CLIENT_INITIAL);
        p.truncate(600);
        p.extend_from_slice(b"\x40\x99\x99\x99\x99 hidden");
        assert!(looks_quic(&p));
    }
}
