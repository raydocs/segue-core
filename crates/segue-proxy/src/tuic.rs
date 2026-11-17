//! TUIC protocol version 5 commands, addresses, and UDP fragmentation.
//!
//! This follows the v5 SPEC on `tuic-protocol/tuic` and the mihomo v5 wire
//! implementation. The authentication token is exported by the QUIC transport:
//! the exporter label is the raw 16-byte UUID, its context the raw password.
use segue_routing::{Network, Target, TargetAddr};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

const VERSION: u8 = 5;
const AUTHENTICATE: u8 = 0;
const CONNECT: u8 = 1;
const PACKET: u8 = 2;
const DISSOCIATE: u8 = 3;
const HEARTBEAT: u8 = 4;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_IPV6: u8 = 2;
const ADDRESS_NONE: u8 = 0xff;
/// Header, metadata, TYPE=IPv6, 16 address bytes, and a port.
const MAX_PACKET_OVERHEAD: usize = 10 + 19;
const MAX_PENDING_PACKETS: usize = 16;
const MAX_PENDING_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct TargetAddress(pub Target);

impl fmt::Debug for TargetAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TargetAddress")
            .field(&self.0)
            .finish()
    }
}

/// The target address of a command, or `None` in a non-first fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Target(TargetAddress),
    None,
}

impl Address {
    pub fn new(target: &Target) -> Self {
        Self::Target(TargetAddress(target.clone()))
    }

    pub fn target(&self) -> Option<&Target> {
        match self {
            Self::Target(address) => Some(&address.0),
            Self::None => None,
        }
    }

    fn wire_len(&self) -> usize {
        match self {
            Self::None => 1,
            Self::Target(target) => match &target.0.addr {
                TargetAddr::Ip(ip) => 1 + if ip.is_ipv4() { 4 } else { 16 } + 2,
                TargetAddr::Domain(domain) => 1 + 1 + domain.len() + 2,
            },
        }
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), WireError> {
        match self {
            Self::None => output.push(ADDRESS_NONE),
            Self::Target(target) => {
                if target.0.network != Network::Udp {
                    return Err(WireError::Network);
                }
                match &target.0.addr {
                    TargetAddr::Ip(ip) => match ip {
                        std::net::IpAddr::V4(ip) => {
                            output.push(ADDRESS_IPV4);
                            output.extend_from_slice(&ip.octets());
                        }
                        std::net::IpAddr::V6(ip) => {
                            output.push(ADDRESS_IPV6);
                            output.extend_from_slice(&ip.octets());
                        }
                    },
                    TargetAddr::Domain(domain) => {
                        let length = u8::try_from(domain.len())
                            .ok()
                            .filter(|length| *length > 0)
                            .ok_or(WireError::Address)?;
                        output.push(0);
                        output.push(length);
                        output.extend_from_slice(domain.as_bytes());
                    }
                }
                output.extend_from_slice(&target.0.port.to_be_bytes());
            }
        }
        Ok(())
    }
}

/// One v5 command. `Authenticate` carries only derived authentication material.
#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    Authenticate {
        uuid: [u8; 16],
        token: [u8; 32],
    },
    Connect(Target),
    Packet(Packet),
    Dissociate {
        association_id: u16,
    },
    Heartbeat,
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticate { uuid, .. } => formatter
                .debug_struct("Authenticate")
                .field("uuid", uuid)
                .field("token", &"<redacted>")
                .finish(),
            Self::Connect(target) => formatter.debug_tuple("Connect").field(target).finish(),
            Self::Packet(packet) => formatter.debug_tuple("Packet").field(packet).finish(),
            Self::Dissociate { association_id } => formatter
                .debug_struct("Dissociate")
                .field("association_id", association_id)
                .finish(),
            Self::Heartbeat => formatter.write_str("Heartbeat"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub association_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub address: Address,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("truncated TUIC command")]
    Truncated,
    #[error("unsupported TUIC protocol version")]
    Version,
    #[error("unknown TUIC command")]
    Command,
    #[error("invalid TUIC network address")]
    Address,
    #[error("TUIC datagram has trailing bytes")]
    Trailing,
    #[error("TUIC address needs UDP network")]
    Network,
    #[error("invalid TUIC fragmentation")]
    Fragmentation,
    #[error("TUIC payload exceeds the retry/QUIC datagram size")]
    DatagramSize,
    #[error("TUIC reassembler limit reached")]
    ReassemblyLimit,
}

/// Encode a command for a stream or one complete QUIC datagram.
pub fn encode(command: &Command) -> Result<Vec<u8>, WireError> {
    let mut output = vec![VERSION, command_type(command)];
    match command {
        Command::Authenticate { uuid, token } => {
            output.extend_from_slice(uuid);
            output.extend_from_slice(token);
        }
        Command::Connect(target) => Address::new(target).encode(&mut output)?,
        Command::Packet(packet) => encode_packet(packet, &mut output)?,
        Command::Dissociate { association_id } => {
            output.extend_from_slice(&association_id.to_be_bytes());
        }
        Command::Heartbeat => {}
    }
    Ok(output)
}

fn command_type(command: &Command) -> u8 {
    match command {
        Command::Authenticate { .. } => AUTHENTICATE,
        Command::Connect(_) => CONNECT,
        Command::Packet(_) => PACKET,
        Command::Dissociate { .. } => DISSOCIATE,
        Command::Heartbeat => HEARTBEAT,
    }
}

fn encode_packet(packet: &Packet, output: &mut Vec<u8>) -> Result<(), WireError> {
    let size = u16::try_from(packet.payload.len()).map_err(|_| WireError::DatagramSize)?;
    if packet.fragment_total == 0
        || packet.fragment_id >= packet.fragment_total
        || (packet.fragment_total > 1
            && packet.fragment_id == 0
            && matches!(packet.address, Address::None))
        || (packet.fragment_total == 1 && matches!(packet.address, Address::None))
    {
        return Err(WireError::Fragmentation);
    }
    output.extend_from_slice(&packet.association_id.to_be_bytes());
    output.extend_from_slice(&packet.packet_id.to_be_bytes());
    output.push(packet.fragment_total);
    output.push(packet.fragment_id);
    output.extend_from_slice(&size.to_be_bytes());
    packet.address.encode(output)?;
    output.extend_from_slice(&packet.payload);
    Ok(())
}

/// Decode a command prefix, returning the command and bytes consumed.
/// Stream callers retain the remainder as application data.
pub fn decode(input: &[u8]) -> Result<(Command, usize), WireError> {
    if input.len() < 2 {
        return Err(WireError::Truncated);
    }
    if input[0] != VERSION {
        return Err(WireError::Version);
    }
    let mut reader = Reader(input);
    reader.position = 2;
    let command = match input[1] {
        AUTHENTICATE => Command::Authenticate {
            uuid: reader.array::<16>()?,
            token: reader.array::<32>()?,
        },
        CONNECT => Command::Connect(decode_target(&mut reader)?),
        PACKET => Command::Packet(decode_packet(&mut reader)?),
        DISSOCIATE => Command::Dissociate {
            association_id: reader.u16()?,
        },
        HEARTBEAT => Command::Heartbeat,
        _ => return Err(WireError::Command),
    };
    Ok((command, reader.position))
}

/// Decode exactly one datagram; commands do not carry extra frame payloads.
pub fn decode_datagram(input: &[u8]) -> Result<Command, WireError> {
    let (command, consumed) = decode(input)?;
    if consumed != input.len() {
        return Err(WireError::Trailing);
    }
    Ok(command)
}

fn decode_packet(reader: &mut Reader<'_>) -> Result<Packet, WireError> {
    let association_id = reader.u16()?;
    let packet_id = reader.u16()?;
    let fragment_total = reader.byte()?;
    let fragment_id = reader.byte()?;
    let size = usize::from(reader.u16()?);
    let address = decode_address(reader)?;
    let payload = reader.take(size)?.to_vec();
    let packet = Packet {
        association_id,
        packet_id,
        fragment_total,
        fragment_id,
        address,
        payload,
    };
    // Apply the same structural rules to received and generated packets.
    let mut check = vec![VERSION, PACKET];
    encode_packet(&packet, &mut check)?;
    Ok(packet)
}

fn decode_target(reader: &mut Reader<'_>) -> Result<Target, WireError> {
    match decode_address(reader)? {
        Address::Target(target) => Ok(target.0),
        Address::None => Err(WireError::Address),
    }
}

fn decode_address(reader: &mut Reader<'_>) -> Result<Address, WireError> {
    let kind = reader.byte()?;
    if kind == ADDRESS_NONE {
        return Ok(Address::None);
    }
    let addr = match kind {
        0 => {
            let length = usize::from(reader.byte()?);
            if length == 0 {
                return Err(WireError::Address);
            }
            let domain = std::str::from_utf8(reader.take(length)?)
                .map_err(|_| WireError::Address)?
                .to_owned();
            TargetAddr::Domain(domain)
        }
        ADDRESS_IPV4 => TargetAddr::Ip(std::net::Ipv4Addr::from(reader.array::<4>()?).into()),
        ADDRESS_IPV6 => TargetAddr::Ip(std::net::Ipv6Addr::from(reader.array::<16>()?).into()),
        _ => return Err(WireError::Address),
    };
    let port = reader.u16()?;
    Ok(Address::new(&Target::new(addr, port, Network::Udp)))
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, WireError> {
        let byte = *self.input.get(self.position).ok_or(WireError::Truncated)?;
        self.position += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let bytes: [u8; N] = self
            .take(N)?
            .try_into()
            .map_err(|_| WireError::Truncated)?;
        Ok(bytes)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let end = self.position.checked_add(count).ok_or(WireError::Truncated)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(WireError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
}

/// Fragment one UDP packet for native QUIC datagrams no larger than `max_size`.
/// Subsequent fragments carry the one-byte `None` address. In QUIC relay mode
/// use [`encode`] without this function: each complete command is one uni stream.
pub fn fragment_datagrams(
    association_id: u16,
    packet_id: u16,
    target: &Target,
    payload: &[u8],
    max_size: usize,
) -> Result<Vec<Vec<u8>>, WireError> {
    let first_address = Address::new(target);
    let room = max_size
        .checked_sub(MAX_PACKET_OVERHEAD - 19 + first_address.wire_len())
        .ok_or(WireError::DatagramSize)?;
    let fragment_size = room
        .min(max_size.saturating_sub(MAX_PACKET_OVERHEAD))
        .min(65_535);
    if fragment_size == 0 || payload.len() > u16::MAX as usize {
        return Err(WireError::DatagramSize);
    }
    let count = payload.len().max(1).div_ceil(fragment_size);
    let total = u8::try_from(count).map_err(|_| WireError::Fragmentation)?;
    let mut encoded = Vec::with_capacity(count);
    for (id, chunk) in payload.chunks(fragment_size).enumerate() {
        let address = if id == 0 {
            first_address.clone()
        } else {
            Address::None
        };
        let command = Command::Packet(Packet {
            association_id,
            packet_id,
            fragment_total: total,
            fragment_id: u8::try_from(id).map_err(|_| WireError::Fragmentation)?,
            address,
            payload: chunk.to_vec(),
        });
        let packet = encode(&command)?;
        if packet.len() > max_size {
            return Err(WireError::DatagramSize);
        }
        encoded.push(packet);
    }
    // An empty UDP packet still has one fragment, as the v5 framing permits.
    if payload.is_empty() {
        encoded.push(encode(&Command::Packet(Packet {
            association_id,
            packet_id,
            fragment_total: 1,
            fragment_id: 0,
            address: first_address,
            payload: Vec::new(),
        }))?);
    }
    Ok(encoded)
}

struct PartialPacket {
    target: Target,
    first_seen: Instant,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
}

/// Bounded, connection-wide TUIC fragment reassembly. Packet IDs are scoped by
/// association ID; duplicates are ignored and never extend fragment deadlines.
pub struct Reassembler {
    timeout: Duration,
    max_payload: usize,
    pending: HashMap<(u16, u16), PartialPacket>,
    bytes: usize,
}

impl Reassembler {
    pub fn new(timeout: Duration, max_payload: usize) -> Result<Self, WireError> {
        if timeout.is_zero() || max_payload == 0 || max_payload > u16::MAX as usize {
            return Err(WireError::ReassemblyLimit);
        }
        Ok(Self {
            timeout,
            max_payload,
            pending: HashMap::new(),
            bytes: 0,
        })
    }

    pub fn expire(&mut self, now: Instant) {
        self.pending.retain(|_, partial| {
            now.saturating_duration_since(partial.first_seen) < self.timeout
        });
        self.bytes = self.pending.values().map(|partial| partial.bytes).sum();
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.bytes = 0;
    }

    pub fn feed(&mut self, packet: &Packet, now: Instant) -> Result<Option<Packet>, WireError> {
        self.expire(now);
        // Structural validation, including `None` only on non-first fragments.
        encode(&Command::Packet(packet.clone()))?;
        if packet.payload.len() > self.max_payload {
            return Err(WireError::ReassemblyLimit);
        }
        if packet.fragment_total == 1 {
            return Ok(Some(packet.clone()));
        }
        let key = (packet.association_id, packet.packet_id);
        if let Some(partial) = self.pending.get(&key) {
            if partial.fragments.len() != usize::from(packet.fragment_total) {
                return Err(WireError::Fragmentation);
            }
            if let Some(previous) = partial.fragments[usize::from(packet.fragment_id)].as_ref() {
                // A duplicate is an idempotent retransmission only when its
                // bytes agree. It also never changes the original deadline.
                return if previous == &packet.payload {
                    Ok(None)
                } else {
                    Err(WireError::Fragmentation)
                };
            }
        } else {
            if self.pending.len() >= MAX_PENDING_PACKETS {
                return Err(WireError::ReassemblyLimit);
            }
            let Some(target) = packet.address.target().cloned() else {
                return Err(WireError::Fragmentation);
            };
            self.pending.insert(
                key,
                PartialPacket {
                    target,
                    first_seen: now,
                    fragments: vec![None; usize::from(packet.fragment_total)],
                    received: 0,
                    bytes: 0,
                },
            );
        }
        let partial = self.pending.get_mut(&key).expect("partial packet inserted");
        if partial.bytes + packet.payload.len() > self.max_payload
            || self.bytes + packet.payload.len() > MAX_PENDING_BYTES
        {
            return Err(WireError::ReassemblyLimit);
        }
        if packet.fragment_id != 0 && !matches!(packet.address, Address::None) {
            return Err(WireError::Fragmentation);
        }
        if packet.fragment_id == 0 && partial.target != *packet.address.target().expect("first") {
            return Err(WireError::Fragmentation);
        }
        partial.fragments[usize::from(packet.fragment_id)] = Some(packet.payload.clone());
        partial.bytes += packet.payload.len();
        partial.received += 1;
        self.bytes += packet.payload.len();
        if partial.received != partial.fragments.len() {
            return Ok(None);
        }
        let partial = self.pending.remove(&key).expect("all fragments received");
        self.bytes -= partial.bytes;
        let mut payload = Vec::with_capacity(partial.bytes);
        for fragment in partial.fragments {
            payload.extend_from_slice(&fragment.expect("all fragments received"));
        }
        Ok(Some(Packet {
            association_id: packet.association_id,
            packet_id: packet.packet_id,
            fragment_total: 1,
            fragment_id: 0,
            address: Address::new(&partial.target),
            payload,
        }))
    }
}

#[cfg(test)]
mod tests;
