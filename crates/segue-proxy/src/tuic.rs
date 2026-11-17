//! TUIC protocol version 5 commands, addresses and UDP fragmentation.
//! Wire grammar follows tuic-protocol/tuic's dev SPEC and mihomo's v5 client.
use segue_routing::{Network, Target, TargetAddr};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

const VERSION: u8 = 5;
const AUTHENTICATE: u8 = 0;
const CONNECT: u8 = 1;
const PACKET: u8 = 2;
const DISSOCIATE: u8 = 3;
const HEARTBEAT: u8 = 4;
const ADDRESS_NONE: u8 = 0xff;
const MAX_PACKET_OVERHEAD: usize = 29;
const MAX_PENDING_PACKETS: usize = 16;
const MAX_PENDING_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireAddress {
    Domain(String),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl WireAddress {
    pub fn from_routing(target: &TargetAddr) -> Self {
        match target {
            TargetAddr::Domain(domain) => Self::Domain(domain.clone()),
            TargetAddr::Ip(IpAddr::V4(ip)) => Self::V4(*ip),
            TargetAddr::Ip(IpAddr::V6(ip)) => Self::V6(*ip),
        }
    }

    fn routing(&self) -> TargetAddr {
        match self {
            Self::Domain(domain) => TargetAddr::Domain(domain.clone()),
            Self::V4(ip) => TargetAddr::Ip((*ip).into()),
            Self::V6(ip) => TargetAddr::Ip((*ip).into()),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Domain(domain) => 1 + domain.len(),
            Self::V4(_) => 4,
            Self::V6(_) => 16,
        }
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), WireError> {
        match self {
            Self::Domain(domain) => {
                if domain.is_empty() || domain.len() > 255 {
                    return Err(WireError::Address);
                }
                output.push(domain.len() as u8);
                output.extend_from_slice(domain.as_bytes());
            }
            Self::V4(ip) => output.extend_from_slice(&ip.octets()),
            Self::V6(ip) => output.extend_from_slice(&ip.octets()),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub host: WireAddress,
    pub port: u16,
}

impl Address {
    pub fn new(host: WireAddress, port: u16) -> Result<Self, WireError> {
        if port == 0 {
            return Err(WireError::Address);
        }
        Ok(Self { host, port })
    }

    pub fn from_target(target: &Target) -> Result<Self, WireError> {
        Self::new(WireAddress::from_routing(&target.addr), target.port)
    }

    pub fn routing(&self, network: Network) -> Target {
        Target::new(self.host.routing(), self.port, network)
    }

    fn len(&self) -> usize {
        1 + self.host.len() + 2
    }

    fn encode(&self, output: &mut Vec<u8>) -> Result<(), WireError> {
        let kind = match self.host {
            WireAddress::Domain(_) => 0,
            WireAddress::V4(_) => 1,
            WireAddress::V6(_) => 2,
        };
        output.push(kind);
        self.host.encode(output)?;
        output.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    Authenticate { uuid: [u8; 16], token: [u8; 32] },
    Connect(Target),
    Packet(Packet),
    Dissociate { association_id: u16 },
    Heartbeat,
}

impl fmt::Debug for Command {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticate { .. } => formatter.write_str("Authenticate(<redacted>)"),
            Self::Connect(target) => formatter.debug_tuple("Connect").field(target).finish(),
            Self::Packet(packet) => formatter.debug_tuple("Packet").field(packet).finish(),
            Self::Dissociate { association_id } => formatter
                .debug_tuple("Dissociate")
                .field(association_id)
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
    pub address: Option<Address>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("truncated TUIC command")]
    Truncated,
    #[error("unsupported TUIC version or command")]
    Command,
    #[error("invalid TUIC address")]
    Address,
    #[error("trailing TUIC datagram bytes")]
    Trailing,
    #[error("invalid TUIC fragmentation")]
    Fragmentation,
    #[error("TUIC payload exceeds its negotiated size")]
    DatagramSize,
    #[error("TUIC bounded reassembly limit reached")]
    ReassemblyLimit,
    #[error("TUIC target must be TCP or UDP with a nonzero port")]
    Network,
}

pub fn encode(command: &Command) -> Result<Vec<u8>, WireError> {
    let mut output = vec![VERSION, match command {
        Command::Authenticate { .. } => AUTHENTICATE,
        Command::Connect(_) => CONNECT,
        Command::Packet(_) => PACKET,
        Command::Dissociate { .. } => DISSOCIATE,
        Command::Heartbeat => HEARTBEAT,
    }];
    match command {
        Command::Authenticate { uuid, token } => {
            output.extend_from_slice(uuid);
            output.extend_from_slice(token);
        }
        Command::Connect(target) => Address::from_target(target)?.encode(&mut output)?,
        Command::Packet(packet) => encode_packet(packet, &mut output)?,
        Command::Dissociate { association_id } => output.extend_from_slice(&association_id.to_be_bytes()),
        Command::Heartbeat => {}
    }
    Ok(output)
}

fn encode_packet(packet: &Packet, output: &mut Vec<u8>) -> Result<(), WireError> {
    if packet.fragment_total == 0
        || packet.fragment_id >= packet.fragment_total
        || (packet.fragment_id == 0 && packet.address.is_none())
    {
        return Err(WireError::Fragmentation);
    }
    output.extend_from_slice(&packet.association_id.to_be_bytes());
    output.extend_from_slice(&packet.packet_id.to_be_bytes());
    output.push(packet.fragment_total);
    output.push(packet.fragment_id);
    let length = u16::try_from(packet.payload.len()).map_err(|_| WireError::DatagramSize)?;
    output.extend_from_slice(&length.to_be_bytes());
    match &packet.address {
        Some(address) => address.encode(output)?,
        None => output.push(ADDRESS_NONE),
    }
    output.extend_from_slice(&packet.payload);
    Ok(())
}

/// Decode one complete datagram or unidirectional stream command.
pub fn decode_datagram(input: &[u8]) -> Result<Command, WireError> {
    let (command, consumed) = decode(input)?;
    if consumed != input.len() {
        return Err(WireError::Trailing);
    }
    Ok(command)
}

/// Decode a stream command and return its prefix length, preserving TCP data.
pub fn decode(input: &[u8]) -> Result<(Command, usize), WireError> {
    if input.len() < 2 {
        return Err(WireError::Truncated);
    }
    if input[0] != VERSION {
        return Err(WireError::Command);
    }
    let mut reader = Reader { bytes: input, position: 2 };
    let command = match input[1] {
        AUTHENTICATE => Command::Authenticate {
            uuid: reader.array::<16>()?,
            token: reader.array::<32>()?,
        },
        CONNECT => Command::Connect(reader.address()?.ok_or(WireError::Address)?.routing(Network::Tcp)),
        PACKET => Command::Packet(reader.packet()?),
        DISSOCIATE => Command::Dissociate { association_id: reader.u16()? },
        HEARTBEAT => Command::Heartbeat,
        _ => return Err(WireError::Command),
    };
    Ok((command, reader.position))
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, WireError> {
        let byte = *self.bytes.get(self.position).ok_or(WireError::Truncated)?;
        self.position += 1;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let end = self.position.checked_add(N).ok_or(WireError::Truncated)?;
        let slice = self.bytes.get(self.position..end).ok_or(WireError::Truncated)?;
        self.position = end;
        Ok(slice.try_into().map_err(|_| WireError::Truncated)?)
    }

    fn take(&mut self, count: usize) -> Result<Vec<u8>, WireError> {
        let end = self.position.checked_add(count).ok_or(WireError::Truncated)?;
        let slice = self.bytes.get(self.position..end).ok_or(WireError::Truncated)?;
        self.position = end;
        Ok(slice.to_vec())
    }

    fn address(&mut self) -> Result<Option<Address>, WireError> {
        let kind = self.byte()?;
        if kind == ADDRESS_NONE {
            return Ok(None);
        }
        let host = match kind {
            0 => {
                let length = usize::from(self.byte()?);
                let name = self.take(length)?;
                WireAddress::Domain(
                    std::str::from_utf8(&name)
                        .map_err(|_| WireError::Address)?
                        .to_owned(),
                )
            }
            1 => WireAddress::V4(Ipv4Addr::from(self.array::<4>()?)),
            2 => WireAddress::V6(Ipv6Addr::from(self.array::<16>()?)),
            _ => return Err(WireError::Address),
        };
        Ok(Some(Address::new(host, self.u16()?)?))
    }

    fn packet(&mut self) -> Result<Packet, WireError> {
        let packet = Packet {
            association_id: self.u16()?,
            packet_id: self.u16()?,
            fragment_total: self.byte()?,
            fragment_id: self.byte()?,
            // The metadata comes before the address; read size separately.
            address: None,
            payload: Vec::new(),
        };
        let length = usize::from(self.u16()?);
        let address = self.address()?;
        let payload = self.take(length)?;
        let packet = Packet { address, payload, ..packet };
        if packet.fragment_total == 0
            || packet.fragment_id >= packet.fragment_total
            || (packet.fragment_id == 0 && packet.address.is_none())
        {
            return Err(WireError::Fragmentation);
        }
        Ok(packet)
    }
}

/// Native relay mode fragments each payload to fit one datagram.
/// In QUIC mode the caller sends each unfragmented command in its own uni stream.
pub fn fragment_datagrams(
    association_id: u16,
    packet_id: u16,
    target: &Target,
    payload: &[u8],
    max_datagram: usize,
) -> Result<Vec<Vec<u8>>, WireError> {
    if payload.len() > u16::MAX as usize {
        return Err(WireError::DatagramSize);
    }
    let address = Address::from_target(target)?;
    let first_room = max_datagram.saturating_sub(10 + address.len());
    let next_room = max_datagram.saturating_sub(MAX_PACKET_OVERHEAD);
    let stride = first_room.min(next_room).min(u16::MAX as usize);
    if stride == 0 {
        return Err(WireError::DatagramSize);
    }
    // The first target can instead be encoded as IPv6/None on later pieces;
    // choose the minimum room to ensure every encoded fragment fits.
    let total = u8::try_from(payload.len().max(1).div_ceil(stride))
        .map_err(|_| WireError::Fragmentation)?;
    let mut result = Vec::new();
    for (index, chunk) in payload.chunks(stride).enumerate() {
        let command = Command::Packet(Packet {
            association_id,
            packet_id,
            fragment_total: total,
            fragment_id: index as u8,
            address: if index == 0 { Some(address.clone()) } else { None },
            payload: chunk.to_vec(),
        });
        result.push(encode(&command)?);
    }
    if payload.is_empty() {
        result.push(encode(&Command::Packet(Packet {
            association_id,
            packet_id,
            fragment_total: 1,
            fragment_id: 0,
            address: Some(address),
            payload: Vec::new(),
        }))?);
    }
    if result.iter().any(|fragment| fragment.len() > max_datagram) {
        return Err(WireError::DatagramSize);
    }
    Ok(result)
}

struct PartialPacket {
    target: Address,
    created: Instant,
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
}

/// Fragment identity includes the association; the reference's packet-ID-only
/// map can combine two different UDP associations otherwise.
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
        Ok(Self { timeout, max_payload, pending: HashMap::new(), bytes: 0 })
    }

    pub fn expire(&mut self, now: Instant) {
        self.pending.retain(|_, partial| now.duration_since(partial.created) < self.timeout);
        self.bytes = self.pending.values().map(|partial| partial.bytes).sum();
    }

    pub fn feed(&mut self, packet: &Packet, now: Instant) -> Result<Option<Packet>, WireError> {
        self.expire(now);
        let check = Command::Packet(packet.clone());
        encode(&check)?;
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
            if let Some(existing) = &partial.fragments[usize::from(packet.fragment_id)] {
                return if existing == &packet.payload {
                    Ok(None)
                } else {
                    Err(WireError::Fragmentation)
                };
            }
        } else {
            if self.pending.len() >= MAX_PENDING_PACKETS {
                return Err(WireError::ReassemblyLimit);
            }
            self.pending.insert(key, PartialPacket {
                target: packet.address.clone().ok_or(WireError::Fragmentation)?,
                created: now,
                fragments: vec![None; usize::from(packet.fragment_total)],
                received: 0,
                bytes: 0,
            });
        }
        let partial = self.pending.get_mut(&key).expect("partial inserted");
        if partial.bytes.saturating_add(packet.payload.len()) > self.max_payload
            || self.bytes.saturating_add(packet.payload.len()) > MAX_PENDING_BYTES
        {
            return Err(WireError::ReassemblyLimit);
        }
        if packet.fragment_id == 0 {
            if packet.address.clone() != Some(partial.target.clone()) {
                return Err(WireError::Fragmentation);
            }
        } else if packet.address.is_some() {
            // None is optional on later fragments in mihomo, but if present it
            // must not silently switch the destination halfway through a packet.
            if packet.address.clone() != Some(partial.target.clone()) {
                return Err(WireError::Fragmentation);
            }
        }
        partial.fragments[usize::from(packet.fragment_id)] = Some(packet.payload.clone());
        partial.bytes += packet.payload.len();
        partial.received += 1;
        self.bytes += packet.payload.len();
        if partial.received != partial.fragments.len() {
            return Ok(None);
        }
        let complete = self.pending.remove(&key).expect("complete fragment bag");
        self.bytes -= complete.bytes;
        let mut payload = Vec::with_capacity(complete.bytes);
        for fragment in complete.fragments {
            payload.extend_from_slice(&fragment.expect("every fragment received"));
        }
        Ok(Some(Packet {
            association_id: packet.association_id,
            packet_id: packet.packet_id,
            fragment_total: 1,
            fragment_id: 0,
            address: Some(complete.target),
            payload,
        }))
    }
}

#[cfg(test)]
mod tests;
