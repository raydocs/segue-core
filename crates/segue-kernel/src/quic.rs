//! QUIC detection for the UDP front ends (KERNEL_SPEC §5.2a.2).
//!
//! The kernel carries QUIC only when it knows the destination's name for
//! certain: a fake-IP destination (TUN) or a domain in the SOCKS request.
//! Such a flow is routed by that name when it is created and stays pinned
//! to that one outbound for its life (its 5-tuple). Nothing inside the
//! flow is inspected: every connection on it goes to the same name.
//!
//! QUIC to a real IP is refused: on TUN with an ICMP port unreachable for
//! the very datagram (an app that honours it, on a connected socket, gives
//! up on QUIC at once and may fall back to TCP, where the flow is sniffed
//! like any TCP flow, §5.2a.1); on SOCKS by dropping it (the app times out).
//! The kernel does not try to follow connection IDs: a short header names
//! a connection by an ID the server may have issued inside the encryption
//! (NEW_CONNECTION_ID), so no observer can prove which connection, and so
//! which server name, it belongs to (astra r8 N1–N3). Connection migration
//! across flows is therefore not supported.
//!
//! Two stateless tests, applied to datagrams of a real-IP flow:
//! [`looks_quic_first`] to its first datagram, [`looks_quic`] to every
//! later one.

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
/// datagram that hides a second packet behind a QUIC first one is QUIC.
/// A short header is not recognised here; see [`looks_quic_first`].
pub fn looks_quic(dgram: &[u8]) -> bool {
    if dgram.len() < 7 || dgram[0] & 0x80 == 0 {
        return false;
    }
    let version = u32::from_be_bytes([dgram[1], dgram[2], dgram[3], dgram[4]]);
    matches!(version, V1 | V2) || (dgram[0] & 0x40 != 0 && dgram.len() >= MIN_INITIAL_DATAGRAM)
}

/// Smallest datagram counted as a QUIC short header. Header protection
/// samples 16 bytes starting 4 bytes after the packet number offset
/// (RFC 9001 §5.4.2), so even with an empty connection ID a protected
/// packet has 1 + 4 + 16 bytes; anything shorter is not one.
pub const MIN_SHORT_HEADER_DATAGRAM: usize = 21;

/// Whether the first datagram of a real-IP flow is to be taken for QUIC:
/// [`looks_quic`], or a short header (1-RTT packet; first byte `0x40..=0x7F`:
/// form bit 0, fixed bit 1) of at least [`MIN_SHORT_HEADER_DATAGRAM`] bytes.
///
/// A short header first on a new 5-tuple is a connection set up elsewhere:
/// before the kernel started, from another address, or moved by the
/// server's preferred address (RFC 9000 §9). Its server name cannot be
/// proven, so it is refused like an Initial (astra r9 F1). Later datagrams
/// of a flow admitted as ordinary UDP are held to [`looks_quic`] only: a
/// flow whose first datagram was not QUIC carries no QUIC connection, and
/// one byte in four of ordinary UDP payload falls in that range.
///
/// The price: ordinary UDP whose first datagram starts `0x40..=0x7F` and
/// is 21 bytes or longer is refused too (a DNS-shaped query with such an
/// ID to a port other than 53, say).
pub fn looks_quic_first(dgram: &[u8]) -> bool {
    looks_quic(dgram) || (dgram.len() >= MIN_SHORT_HEADER_DATAGRAM && dgram[0] & 0xc0 == 0x40)
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
    fn short_header_first_is_quic_from_21_bytes() {
        for b in [0x40u8, 0x41, 0x5f, 0x7f] {
            let mut p = vec![b];
            p.resize(MIN_SHORT_HEADER_DATAGRAM, 0x33);
            assert!(looks_quic_first(&p), "{b:#x}");
            assert!(
                !looks_quic(&p),
                "{b:#x}: later datagrams are not held to it"
            );
            p.pop();
            assert!(!looks_quic_first(&p), "{b:#x}: too short to be protected");
        }
        // Long headers are QUIC first or later.
        assert!(looks_quic_first(&hex(RFC9001_CLIENT_INITIAL)));
    }

    /// Representative ordinary UDP first datagrams that must pass.
    #[test]
    fn plain_udp_first_datagrams_pass() {
        let sized = |head: &[u8], n: usize| {
            let mut p = head.to_vec();
            p.resize(n, 0x5a);
            p
        };
        let cases = [
            // WireGuard handshake initiation: type 1, three reserved zeros, 148 bytes.
            ("wireguard", sized(&[0x01, 0, 0, 0], 148)),
            // STUN binding request: type 0x0001, magic cookie.
            (
                "stun",
                sized(&[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42], 20 + 8),
            ),
            // DTLS 1.2 ClientHello record.
            (
                "dtls",
                sized(&[0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0], 200),
            ),
            // RTP version 2, at a large size too.
            ("rtp", sized(&[0x80, 0x60, 0x12, 0x34, 0, 0, 0, 0], 1300)),
            // DNS-shaped: ID 0x1234, RD.
            ("dns", sized(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01], 40)),
        ];
        for (name, p) in cases {
            assert!(!looks_quic_first(&p), "{name}");
            assert!(!looks_quic(&p), "{name}");
        }
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
