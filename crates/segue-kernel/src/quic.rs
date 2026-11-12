//! QUIC Initial SNI (KERNEL_SPEC §5.2a.2).
//!
//! A client's first QUIC datagram carries Initial packets protected with
//! keys derived from public salts (RFC 9001 §5.2, RFC 9369 §3.3.1). We
//! remove header protection, decrypt, collect the CRYPTO frames and read
//! the ClientHello's server_name with the TCP sniffer's parser.
//!
//! Pure and allocation-bounded; arbitrary bytes never panic. Modern
//! clients (Chrome, quic-go) split a post-quantum ClientHello over two or
//! more Initial datagrams and shuffle the CRYPTO frames, so the name is
//! often not in the first datagram: [`InitialSniffer`] reassembles the
//! CRYPTO stream over up to [`MAX_DATAGRAMS`] datagrams. A flow whose name
//! cannot be confirmed is refused by the caller, so the app falls back to
//! TCP, where the name is always sniffable.

use ring::aead::{self, quic, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;

use crate::sniff::{self, Sniff};

/// What the first datagram of a UDP flow says about QUIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Quic {
    /// A QUIC client Initial naming this server (lowercase, no trailing dot).
    Domain(String),
    /// A client Initial whose ClientHello is not complete enough yet: feed
    /// the flow's next datagram.
    NeedMore,
    /// Looks like QUIC (long header with the fixed bit, or an unknown QUIC
    /// version) but no server name could be confirmed. Final.
    Unclassified,
    /// Not a QUIC long-header packet.
    NotQuic,
}

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Ignore CRYPTO data beyond this offset (a ClientHello is a few KB).
const MAX_CRYPTO: usize = 16 * 1024;
/// Datagrams looked at before giving up on a flow.
pub const MAX_DATAGRAMS: usize = 4;

/// One datagram on its own (see [`InitialSniffer`]).
pub fn initial_sni(dgram: &[u8]) -> Quic {
    InitialSniffer::default().push(dgram)
}

/// CRYPTO-stream reassembly over a flow's first datagrams.
#[derive(Default)]
pub struct InitialSniffer {
    crypto: Crypto,
    seen: usize,
    initials: usize,
}

impl InitialSniffer {
    /// Feed the flow's next client datagram. After a final answer (anything
    /// but [`Quic::NeedMore`]) the sniffer should be dropped.
    pub fn push(&mut self, dgram: &[u8]) -> Quic {
        self.seen += 1;
        let first = self.seen == 1;
        let quic_shaped = dgram.first().is_some_and(|b| b & 0xc0 == 0xc0) && dgram.len() >= 7;
        if !quic_shaped {
            return if first { Quic::NotQuic } else { self.verdict() };
        }
        let mut rest = dgram;
        // Coalesced packets (RFC 9000 §12.2): walk every long-header packet.
        while let Some(&b) = rest.first() {
            if b & 0xc0 != 0xc0 {
                break;
            }
            match packet(rest, &mut self.crypto) {
                Some((used, initial)) => {
                    self.initials += usize::from(initial);
                    rest = &rest[used..];
                }
                None => break,
            }
        }
        self.verdict()
    }

    fn verdict(&self) -> Quic {
        if self.initials == 0 {
            return Quic::Unclassified;
        }
        match sniff::client_hello_sni(&self.crypto.contiguous()) {
            Sniff::Domain(d) => Quic::Domain(d),
            Sniff::NeedMore if self.seen < MAX_DATAGRAMS => Quic::NeedMore,
            _ => Quic::Unclassified,
        }
    }
}

/// Parse one long-header packet at the start of `p`. Returns the bytes it
/// takes and whether it was a client Initial that decrypted.
fn packet(p: &[u8], crypto: &mut Crypto) -> Option<(usize, bool)> {
    let mut c = Cur { b: p, p: 0 };
    let b0 = c.u8()?;
    let version = u32::from_be_bytes(c.take(4)?.try_into().ok()?);
    let dcid_len = c.u8()? as usize;
    if dcid_len > 20 {
        return None;
    }
    let dcid = c.take(dcid_len)?;
    let scid_len = c.u8()? as usize;
    if scid_len > 20 {
        return None;
    }
    c.take(scid_len)?;
    let ptype = (b0 >> 4) & 0x03;
    let (salt, label_v2, initial_type) = match version {
        V1 => (&SALT_V1, false, 0),
        V2 => (&SALT_V2, true, 1),
        // Version negotiation or unknown version: no length to skip by.
        _ => return None,
    };
    // Retry (v1 type 3, v2 type 0) has no Length field.
    let retry_type = if label_v2 { 0 } else { 3 };
    if ptype == retry_type {
        return None;
    }
    if ptype == initial_type {
        let tlen = c.varint()?;
        c.take(usize::try_from(tlen).ok()?)?;
    }
    let len = usize::try_from(c.varint()?).ok()?;
    let pn_off = c.p;
    let end = pn_off.checked_add(len)?;
    if end > p.len() {
        return None;
    }
    if ptype != initial_type {
        return Some((end, false));
    }
    let ok = decrypt_initial(&p[..end], pn_off, dcid, salt, label_v2, crypto).is_some();
    Some((end, ok))
}

fn decrypt_initial(
    pkt: &[u8],
    pn_off: usize,
    dcid: &[u8],
    salt: &[u8],
    v2: bool,
    crypto: &mut Crypto,
) -> Option<()> {
    let (key, iv, hp) = client_keys(salt, dcid, v2)?;
    let sample = pkt.get(pn_off + 4..pn_off + 20)?;
    let hp = quic::HeaderProtectionKey::new(&quic::AES_128, &hp).ok()?;
    let mask = hp.new_mask(sample).ok()?;
    let mut hdr = pkt[..pn_off].to_vec();
    hdr[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(hdr[0] & 0x03) + 1;
    let pn_bytes = pkt.get(pn_off..pn_off + pn_len)?;
    let mut pn: u64 = 0;
    for (i, b) in pn_bytes.iter().enumerate() {
        let b = b ^ mask[1 + i];
        hdr.push(b);
        pn = (pn << 8) | u64::from(b);
    }
    let mut nonce = iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let mut body = pkt.get(pn_off + pn_len..)?.to_vec();
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).ok()?);
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&hdr),
            &mut body,
        )
        .ok()?;
    frames(plain, crypto)
}

/// Client Initial key, IV and header-protection key.
fn client_keys(salt: &[u8], dcid: &[u8], v2: bool) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let mut client = [0u8; 32];
    expand(&initial, b"client in", &mut client)?;
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
    let (lk, li, lh): (&[u8], &[u8], &[u8]) = if v2 {
        (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")
    } else {
        (b"quic key", b"quic iv", b"quic hp")
    };
    let (mut k, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand(&client, lk, &mut k)?;
    expand(&client, li, &mut iv)?;
    expand(&client, lh, &mut hp)?;
    Some((k, iv, hp))
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// TLS 1.3 HKDF-Expand-Label with an empty context.
fn expand(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Option<()> {
    let full = [b"tls13 ".as_slice(), label].concat();
    let len = u16::try_from(out.len()).ok()?.to_be_bytes();
    let llen = [u8::try_from(full.len()).ok()?];
    let info: [&[u8]; 4] = [&len, &llen, &full, &[0]];
    prk.expand(&info, Len(out.len())).ok()?.fill(out).ok()
}

/// Walk Initial frames, collecting CRYPTO data. Stops (keeping what it has)
/// at a frame type an Initial may not carry.
fn frames(b: &[u8], crypto: &mut Crypto) -> Option<()> {
    let mut c = Cur { b, p: 0 };
    while c.p < b.len() {
        match c.varint()? {
            0x00 | 0x01 => {} // PADDING, PING
            t @ (0x02 | 0x03) => {
                // ACK
                c.varint()?;
                c.varint()?;
                let ranges = c.varint()?;
                c.varint()?;
                for _ in 0..ranges.min(256) {
                    c.varint()?;
                    c.varint()?;
                }
                if t == 0x03 {
                    for _ in 0..3 {
                        c.varint()?;
                    }
                }
            }
            0x06 => {
                let off = usize::try_from(c.varint()?).ok()?;
                let len = usize::try_from(c.varint()?).ok()?;
                let data = c.take(len)?;
                crypto.add(off, data);
            }
            0x1c => return Some(()), // CONNECTION_CLOSE
            _ => return Some(()),
        }
    }
    Some(())
}

/// CRYPTO stream pieces, possibly out of order.
#[derive(Default)]
struct Crypto {
    parts: Vec<(usize, Vec<u8>)>,
}

impl Crypto {
    fn add(&mut self, off: usize, data: &[u8]) {
        if off >= MAX_CRYPTO || self.parts.len() >= 256 {
            return;
        }
        let n = data.len().min(MAX_CRYPTO - off);
        self.parts.push((off, data[..n].to_vec()));
    }

    /// The bytes from offset 0 up to the first gap.
    fn contiguous(&self) -> Vec<u8> {
        let mut parts: Vec<_> = self.parts.iter().collect();
        parts.sort_by_key(|(o, _)| *o);
        let mut out = Vec::new();
        for (off, data) in parts {
            if *off > out.len() {
                break;
            }
            let skip = out.len() - off;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let n = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        for &b in self.take(n - 1)? {
            v = (v << 8) | u64::from(b);
        }
        Some(v)
    }
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
/// SNI chatgpt.com): a 1975-byte ClientHello with shuffled CRYPTO frames,
/// the name not in this datagram.
#[doc(hidden)]
pub const QUIC_GO_CHATGPT_INITIAL: &str =
    include_str!("../testdata/quic/quic-go-chatgpt-initial.hex");
/// The second datagram of the same capture: the rest of the ClientHello.
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
    fn rfc9001_client_initial() {
        let pkt = hex(RFC9001_CLIENT_INITIAL);
        assert_eq!(pkt.len(), 1200);
        assert_eq!(initial_sni(&pkt), Quic::Domain("example.com".into()));
    }

    #[test]
    fn rfc9369_client_initial_v2() {
        let pkt = hex(RFC9369_CLIENT_INITIAL);
        assert_eq!(pkt.len(), 1200);
        assert_eq!(initial_sni(&pkt), Quic::Domain("example.com".into()));
    }

    #[test]
    fn quic_go_capture() {
        let pkt = hex(QUIC_GO_CHATGPT_INITIAL);
        assert_eq!(pkt.len(), 1250);
        let mut s = InitialSniffer::default();
        assert_eq!(s.push(&pkt), Quic::NeedMore);
        // Retransmissions of the same datagram never complete it.
        for _ in 1..MAX_DATAGRAMS - 1 {
            assert_eq!(s.push(&pkt), Quic::NeedMore);
        }
        assert_eq!(s.push(&pkt), Quic::Unclassified);
        // Both datagrams, either order.
        let second = hex(QUIC_GO_CHATGPT_INITIAL_2);
        let mut s = InitialSniffer::default();
        assert_eq!(s.push(&pkt), Quic::NeedMore);
        assert_eq!(s.push(&second), Quic::Domain("chatgpt.com".into()));
        let mut s = InitialSniffer::default();
        let r = s.push(&second);
        assert!(
            r == Quic::NeedMore || r == Quic::Domain("chatgpt.com".into()),
            "{r:?}"
        );
        if r == Quic::NeedMore {
            assert_eq!(s.push(&pkt), Quic::Domain("chatgpt.com".into()));
        }
    }

    #[test]
    fn rfc9001_key_schedule() {
        // RFC 9001 A.1.
        let dcid = hex("8394c8f03e515708");
        let (k, iv, hp) = client_keys(&SALT_V1, &dcid, false).unwrap();
        assert_eq!(k.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn tampered_or_truncated_is_unclassified_never_panics() {
        let pkt = hex(RFC9001_CLIENT_INITIAL);
        let mut bad = pkt.clone();
        bad[100] ^= 1;
        assert_eq!(initial_sni(&bad), Quic::Unclassified);
        for n in [0, 1, 6, 7, 20, 40, 600, 1199] {
            let r = initial_sni(&pkt[..n]);
            assert_ne!(r, Quic::Domain("example.com".into()), "len {n}");
        }
        // Unknown version: QUIC-shaped, not classifiable.
        let mut v = pkt.clone();
        v[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        assert_eq!(initial_sni(&v), Quic::Unclassified);
        // Short header / not QUIC.
        assert_eq!(initial_sni(&[0x40, 1, 2, 3]), Quic::NotQuic);
        assert_eq!(initial_sni(b"\x12\x34 dns query"), Quic::NotQuic);
        for seed in 0u8..=255 {
            let mut junk = vec![seed | 0xc0; 1200];
            junk[1..5].copy_from_slice(&V1.to_be_bytes());
            let _ = initial_sni(&junk);
        }
    }

    #[test]
    fn crypto_reassembly_out_of_order() {
        let mut c = Crypto::default();
        c.add(5, b"fghij");
        c.add(0, b"abcdef");
        c.add(20, b"zz");
        assert_eq!(c.contiguous(), b"abcdefghij");
    }
}
