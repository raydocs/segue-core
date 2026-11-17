//! Client-side AnyTLS framing, pinned to `anytls/sing-anytls` and the
//! `sagernet/sing-anytls` fork sing-box 1.15 pins.
//!
//! AnyTLS multiplexes streams over one TLS session. The session starts with a
//! 32-byte SHA-256 of the password and a padded hello, then carries 7-byte
//! framed commands. This module is the wire layer only: it does not dial, keep
//! sessions, or enable an outbound. Every length is bounded so that a peer can
//! never make the caller allocate more than one frame's payload.
//!
//! Sources: `sing-anytls/client.go`, `session/frame.go`, `session/session.go`,
//! `padding/padding.go`, `util/string_map.go`, and sing's
//! `common/uot/protocol.go` for the UDP-over-TCP companion.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::RngCore;
use segue_routing::{Target, TargetAddr};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// SHA-256 of the password is the session credential, sent verbatim.
pub const PASSWORD_HASH_LENGTH: usize = 32;
/// `headerOverHeadSize`: command, stream id, payload length.
pub const HEADER_LENGTH: usize = 1 + 4 + 2;
/// The payload length is a `uint16`, so one data frame carries this much.
pub const MAX_FRAME_PAYLOAD: usize = u16::MAX as usize;
/// Largest UDP payload one UoT frame carries. The UoT length is a `uint16`,
/// but every other stream outbound here bounds a datagram at 8192 bytes, and
/// the TUN flow loop drops what a path cannot carry.
pub const MAX_UDP_PAYLOAD_LENGTH: usize = 8192;
/// One UoT frame: a length and the payload.
pub const MAX_UOT_FRAME_LENGTH: usize = 2 + MAX_UDP_PAYLOAD_LENGTH;
/// Magic destination a session's stream carries when it is a UDP-over-TCP
/// association, from sing's `uot.MagicAddress`.
pub const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
/// The client version string sing-box sends in its settings frame.
pub const CLIENT_VERSION: &str = "segue-anytls/0.1";
/// Session protocol version this client speaks (v2 adds SYNACK, heartbeats and
/// server settings).
pub const PROTOCOL_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WireError {
    #[error("AnyTLS password must not be empty")]
    PasswordLength,
    #[error("AnyTLS domain must contain 1..255 UTF-8 bytes without whitespace or controls")]
    Domain,
    #[error("AnyTLS target port must be nonzero")]
    Port,
    #[error("incomplete AnyTLS frame")]
    Incomplete,
    #[error("unknown AnyTLS command {0}")]
    UnknownCommand(u8),
    #[error("unknown AnyTLS address family {0}")]
    AddressFamily(u8),
    #[error("AnyTLS UDP payload exceeds the 8192-byte limit")]
    PayloadLength,
    #[error("invalid AnyTLS padding scheme")]
    PaddingScheme,
    #[error("AnyTLS settings frame is not a valid key=value list")]
    Settings,
    #[error("AnyTLS UDP target requires the UDP network")]
    Network,
}

/// One command byte, as `session/frame.go` numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Padding; the payload is discarded.
    Waste = 0,
    /// Open a stream.
    Syn = 1,
    /// Data for a stream.
    Push = 2,
    /// The stream's writer is done.
    Fin = 3,
    /// Client settings.
    Settings = 4,
    /// The server refuses the session; the payload says why.
    Alert = 5,
    /// The server replaces the padding scheme.
    UpdatePaddingScheme = 6,
    /// The server reports that a stream opened, or carries its error.
    SynAck = 7,
    /// Keepalive.
    HeartRequest = 8,
    /// Keepalive reply.
    HeartResponse = 9,
    /// Server settings.
    ServerSettings = 10,
}

impl Command {
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Waste,
            1 => Self::Syn,
            2 => Self::Push,
            3 => Self::Fin,
            4 => Self::Settings,
            5 => Self::Alert,
            6 => Self::UpdatePaddingScheme,
            7 => Self::SynAck,
            8 => Self::HeartRequest,
            9 => Self::HeartResponse,
            10 => Self::ServerSettings,
            _ => return None,
        })
    }
}

/// A decoded frame header. The payload follows, `length` bytes of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub command: Command,
    pub stream_id: u32,
    pub length: u16,
}

impl FrameHeader {
    /// Decode one header; `None` means the input holds fewer than
    /// [`HEADER_LENGTH`] bytes and the caller should read more.
    pub fn decode(input: &[u8]) -> Result<Option<Self>, WireError> {
        if input.len() < HEADER_LENGTH {
            return Ok(None);
        }
        let command = Command::from_byte(input[0]).ok_or(WireError::UnknownCommand(input[0]))?;
        let stream_id = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        let length = u16::from_be_bytes([input[5], input[6]]);
        Ok(Some(Self {
            command,
            stream_id,
            length,
        }))
    }

    /// Append this header to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.command as u8);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
    }

    /// The whole frame, header and payload.
    pub fn into_frame(self, payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(HEADER_LENGTH + payload.len());
        self.encode(&mut wire);
        wire.extend_from_slice(payload);
        wire
    }
}

/// A control frame: no payload, or one bounded by the caller.
pub fn control_frame(command: Command, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    FrameHeader {
        command,
        stream_id,
        // Only a payload that fits the wire field survives; the server sends
        // at most its own error text.
        length: payload.len().min(MAX_FRAME_PAYLOAD) as u16,
    }
    .into_frame(&payload[..payload.len().min(MAX_FRAME_PAYLOAD)])
}

/// Encode `data` as one or more `Push` frames for `stream_id`. More than
/// [`MAX_FRAME_PAYLOAD`] bytes become consecutive frames in one buffer, so a
/// single `write_all` keeps them contiguous against control frames.
pub fn push_frames(stream_id: u32, data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let chunks = data.len().div_ceil(MAX_FRAME_PAYLOAD);
    let mut wire = Vec::with_capacity(data.len() + chunks * HEADER_LENGTH);
    for chunk in data.chunks(MAX_FRAME_PAYLOAD) {
        FrameHeader {
            command: Command::Push,
            stream_id,
            length: chunk.len() as u16,
        }
        .encode(&mut wire);
        wire.extend_from_slice(chunk);
    }
    wire
}

/// The session's client settings, a `key=value` list separated by newlines.
/// sing-box writes `v`, `client` and `padding-md5` in map order; this order is
/// fixed, which the server's parser does not care about. `client` is
/// sing-box's `client_metadata` when the config sets it, otherwise this
/// client's own version string.
pub fn settings_payload(padding_md5: &str, client_metadata: Option<&str>) -> Vec<u8> {
    let client = client_metadata.unwrap_or(CLIENT_VERSION);
    format!("client={client}\npadding-md5={padding_md5}\nv={PROTOCOL_VERSION}").into_bytes()
}

/// Parse a settings payload. Duplicate keys keep the last value, as Go's map
/// assignment does.
pub fn parse_settings(payload: &[u8]) -> Result<BTreeMap<String, String>, WireError> {
    let text = std::str::from_utf8(payload).map_err(|_| WireError::Settings)?;
    let mut map = BTreeMap::new();
    for line in text.split('\n') {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_owned(), value.to_owned());
        }
    }
    Ok(map)
}

/// The session credential. The digest is a credential itself: never printed,
/// and cleared on drop.
pub struct AnyTlsAuth(Zeroizing<[u8; PASSWORD_HASH_LENGTH]>);

impl AnyTlsAuth {
    pub fn new(password: &str) -> Result<Self, WireError> {
        if password.is_empty() {
            return Err(WireError::PasswordLength);
        }
        let mut digest = Sha256::digest(password.as_bytes());
        let mut hash = Zeroizing::new([0u8; PASSWORD_HASH_LENGTH]);
        hash.copy_from_slice(&digest);
        digest[..].zeroize();
        Ok(Self(hash))
    }

    pub fn as_bytes(&self) -> &[u8; PASSWORD_HASH_LENGTH] {
        &*self.0
    }
}

impl fmt::Debug for AnyTlsAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AnyTlsAuth(<redacted>)")
    }
}

/// One entry of a padding scheme: a payload length to pad a record up to, a
/// range drawn from `[min, max)`, or `c` ("check mark"), which stops the
/// scheme when nothing is left to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingSize {
    Exact(u32),
    Range(u32, u32),
    CheckMark,
}

/// The padding scheme `sing-anytls/padding.go` ships and both reference
/// clients use.
pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000";

/// A parsed padding scheme: `stop` and, per packet counter, the record sizes
/// to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingFactory {
    raw: Vec<u8>,
    md5_hex: String,
    stop: u32,
    entries: BTreeMap<u32, Vec<PaddingSize>>,
}

impl PaddingFactory {
    /// Parse a scheme. Returns `None` when `stop` is missing or not a number,
    /// as the reference parser does; malformed entries are skipped.
    pub fn new(raw: &[u8]) -> Option<Self> {
        let mut stop = None;
        let mut entries = BTreeMap::new();
        for (key, value) in split_settings(raw) {
            if key == "stop" {
                stop = value.parse::<u32>().ok();
                continue;
            }
            let Ok(counter) = key.parse::<u32>() else {
                continue;
            };
            let mut sizes = Vec::new();
            for part in value.split(',') {
                if part == "c" {
                    sizes.push(PaddingSize::CheckMark);
                    continue;
                }
                let Some((min, max)) = part.split_once('-') else {
                    continue;
                };
                let (Ok(mut min), Ok(mut max)) = (min.parse::<i64>(), max.parse::<i64>()) else {
                    continue;
                };
                if min > max {
                    std::mem::swap(&mut min, &mut max);
                }
                if min <= 0 || max <= 0 {
                    continue;
                }
                // A single value is exact; a range is drawn from
                // `[min, max)` as `rand.Int(max-min) + min`.
                if min == max {
                    sizes.push(PaddingSize::Exact(min as u32));
                } else {
                    sizes.push(PaddingSize::Range(min as u32, max as u32));
                }
            }
            entries.insert(counter, sizes);
        }
        Some(Self {
            raw: raw.to_vec(),
            md5_hex: md5_hex(raw),
            stop: stop?,
            entries,
        })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn md5_hex(&self) -> &str {
        &self.md5_hex
    }

    pub fn stop(&self) -> u32 {
        self.stop
    }

    /// The record sizes for packet counter `packet`, as the reference
    /// `GenerateRecordPayloadSizes` returns them. A range is drawn from
    /// `jitter(min, max)` with an exclusive `max`; a check mark is zero here,
    /// which [`pad_record`] reads as "stop when nothing is left".
    pub fn record_sizes(&self, packet: u32, mut jitter: impl FnMut(u32, u32) -> u32) -> Vec<u32> {
        let Some(sizes) = self.entries.get(&packet) else {
            return Vec::new();
        };
        sizes
            .iter()
            .map(|size| match *size {
                PaddingSize::Exact(size) => size,
                PaddingSize::Range(min, max) => jitter(min, max),
                PaddingSize::CheckMark => 0,
            })
            .collect()
    }

    /// The hello's padding length: the first record size for counter 0.
    pub fn hello_padding(&self, jitter: impl FnMut(u32, u32) -> u32) -> u32 {
        self.record_sizes(0, jitter).first().copied().unwrap_or(0)
    }
}

impl Default for PaddingFactory {
    fn default() -> Self {
        Self::new(DEFAULT_PADDING_SCHEME).expect("the built-in padding scheme parses")
    }
}

fn split_settings(raw: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(text) = std::str::from_utf8(raw) else {
        return out;
    };
    for line in text.split('\n') {
        if let Some((key, value)) = line.split_once('=') {
            out.push((key.to_owned(), value.to_owned()));
        }
    }
    out
}

/// Lowercase hex MD5, as `fmt.Sprintf("%x", md5.Sum(raw))` prints it.
pub fn md5_hex(raw: &[u8]) -> String {
    use md5::Digest;
    use std::fmt::Write;
    let digest = md5::Md5::digest(raw);
    let mut hex = String::with_capacity(32);
    for byte in digest.iter() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The session hello: the password digest, the padding length and that many
/// zero bytes. A server that does not know the digest hands the connection to
/// its fallback, so this must be the first bytes a session writes.
pub fn hello_frames(auth: &AnyTlsAuth, padding: u32) -> Vec<u8> {
    let mut wire = Vec::with_capacity(PASSWORD_HASH_LENGTH + 2 + padding as usize);
    wire.extend_from_slice(auth.as_bytes());
    wire.extend_from_slice(&(padding.min(u16::MAX as u32) as u16).to_be_bytes());
    wire.resize(wire.len() + padding.min(u16::MAX as u32) as usize, 0);
    wire
}

/// Split one write through a padding scheme, as the reference `writeConn`
/// does. Each scheme entry is a record size: a record smaller than what is
/// left is all payload, a record that holds the payload's tail is filled with
/// one `Waste` frame, and a record with no payload left is a `Waste` frame
/// alone. Returns the chunks to write in order; an empty list means nothing
/// goes out.
///
/// The reference's quirks are kept: a `Waste`-only record is `size` payload
/// bytes plus its 7-byte header, and a check mark stops the scheme only once
/// the payload is spent.
pub fn pad_record(
    factory: &PaddingFactory,
    packet: u32,
    mut bytes: Vec<u8>,
    mut jitter: impl FnMut(u32, u32) -> u32,
) -> Vec<Vec<u8>> {
    let mut writes = Vec::new();
    if packet >= factory.stop() {
        if !bytes.is_empty() {
            writes.push(bytes);
        }
        return writes;
    }
    for size in factory.record_sizes(packet, &mut jitter) {
        let size = size as usize;
        let remaining = bytes.len();
        if size == 0 {
            // A check mark: stop padding once the payload is spent.
            if remaining == 0 {
                break;
            }
            continue;
        }
        if remaining > size {
            writes.push(bytes[..size].to_vec());
            bytes.drain(..size);
        } else if remaining > 0 {
            // The record holds the payload's tail and `Waste` filling it.
            let waste = size.saturating_sub(remaining + HEADER_LENGTH);
            if waste > 0 {
                let zeros = vec![0u8; waste];
                let frame = control_frame(Command::Waste, 0, &zeros);
                bytes.extend_from_slice(&frame);
            }
            writes.push(std::mem::take(&mut bytes));
        } else {
            let zeros = vec![0u8; size];
            writes.push(control_frame(Command::Waste, 0, &zeros));
            bytes.clear();
        }
    }
    if !bytes.is_empty() {
        writes.push(bytes);
    }
    writes
}

/// Encode a target as sing's `Socksaddr`: family byte, address, port. The
/// AnyTLS stream opens with this, and UoT's non-connect form repeats it per
/// datagram.
pub fn encode_socksaddr(target: &Target, out: &mut Vec<u8>) -> Result<(), WireError> {
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            out.push(0x00);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(WireError::Domain);
            }
            out.push(0x02);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

/// The stream's opening bytes: the destination's `Socksaddr`. The AnyTLS
/// service reads exactly this before it routes the stream.
pub fn encode_stream_target(target: &Target) -> Result<Vec<u8>, WireError> {
    if target.port == 0 && !is_uot_magic(target) {
        return Err(WireError::Port);
    }
    let mut out = Vec::with_capacity(1 + 1 + 255 + 2);
    encode_socksaddr(target, &mut out)?;
    Ok(out)
}

/// The magic destination a UDP association rides.
pub fn uot_request_target() -> Target {
    Target::new(
        segue_routing::TargetAddr::Domain(UOT_MAGIC_ADDRESS.to_owned()),
        0,
        segue_routing::Network::Tcp,
    )
}

fn is_uot_magic(target: &Target) -> bool {
    target.addr == TargetAddr::Domain(UOT_MAGIC_ADDRESS.to_owned())
}

/// A UoT connect request: `isConnect` then the destination. A `true` first
/// byte means every datagram goes to this one destination and carries no
/// address of its own.
pub fn encode_uot_request(target: &Target, is_connect: bool) -> Result<Vec<u8>, WireError> {
    if target.port == 0 {
        return Err(WireError::Port);
    }
    let mut out = Vec::with_capacity(1 + 1 + 255 + 2);
    out.push(u8::from(is_connect));
    encode_socksaddr(target, &mut out)?;
    Ok(out)
}

/// One UoT datagram: a big-endian length and the payload.
pub fn encode_uot_datagram(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.len() > MAX_UDP_PAYLOAD_LENGTH {
        return Err(WireError::PayloadLength);
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode one UoT datagram; `None` means more bytes are needed.
pub fn decode_uot_datagram(input: &[u8]) -> Result<Option<(&[u8], usize)>, WireError> {
    if input.len() < 2 {
        return Ok(None);
    }
    let length = u16::from_be_bytes([input[0], input[1]]) as usize;
    if length > MAX_UDP_PAYLOAD_LENGTH {
        return Err(WireError::PayloadLength);
    }
    if input.len() < 2 + length {
        return Ok(None);
    }
    Ok(Some((&input[2..2 + length], 2 + length)))
}

/// Fill `out` from an OS random source. The padding scheme's ranges draw from
/// it, as `crypto/rand` does in Go.
pub fn random_jitter(min: u32, max: u32) -> u32 {
    debug_assert!(min < max);
    let span = u64::from(max - min);
    let mut word = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut word);
    min + (u64::from_be_bytes(word) % span) as u32
}

/// IPv4, IPv6 or a domain: the address types a `Socksaddr` carries.
pub fn decode_socksaddr(input: &[u8]) -> Result<Option<(TargetAddr, u16, usize)>, WireError> {
    let Some(&family) = input.first() else {
        return Ok(None);
    };
    match family {
        0x00 => {
            if input.len() < 1 + 4 + 2 {
                return Ok(None);
            }
            let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&input[1..5]).expect("fixed-size slice"));
            let port = u16::from_be_bytes([input[5], input[6]]);
            Ok(Some((TargetAddr::Ip(IpAddr::V4(ip)), port, 7)))
        }
        0x01 => {
            if input.len() < 1 + 16 + 2 {
                return Ok(None);
            }
            let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&input[1..17]).expect("fixed-size slice"));
            let port = u16::from_be_bytes([input[17], input[18]]);
            Ok(Some((TargetAddr::Ip(IpAddr::V6(ip)), port, 19)))
        }
        0x02 => {
            let Some(&length) = input.get(1) else {
                return Ok(None);
            };
            let length = usize::from(length);
            if input.len() < 2 + length + 2 {
                return Ok(None);
            }
            let domain = std::str::from_utf8(&input[2..2 + length]).map_err(|_| WireError::Domain)?;
            if domain.is_empty() || domain.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(WireError::Domain);
            }
            let port = u16::from_be_bytes([input[2 + length], input[3 + length]]);
            Ok(Some((
                TargetAddr::Domain(domain.to_owned()),
                port,
                2 + length + 2,
            )))
        }
        other => Err(WireError::AddressFamily(other)),
    }
}

#[cfg(test)]
mod tests;
