//! Wire format (SESSION_PROTOCOL v0.4 §2).
//!
//! `frame = type:u8 flags:u8 length:varint payload[length]`, varints are QUIC
//! variable-length integers (RFC 9000 §16).
//!
//! The spec lists the fields of each frame but not their encodings. This
//! crate fixes them as follows (all integers are varints unless noted):
//! - `session_id`: 16 raw bytes; `resume_secret`: 32 raw bytes;
//!   `attach_gen`: u32 big-endian; `version`, `kind`, `exit_class`,
//!   `open_flags`, error codes: one byte each.
//! - `ticket`: varint length + bytes. `target`: `atyp:u8` (1 = IPv4,
//!   3 = domain with a one-byte length, 4 = IPv6), address, `port:u16` BE.
//! - `anchor_instance_id` / `instance_id` / `anchor_node_id`: varint; 0 means
//!   "none" (the first OPEN carries 0).
//! - OPEN's `first_data` is the rest of the payload.
//!
//! CTRL_HELLO, RESOLVE, RESOLVED, REFRESH, REFRESHED and REVOKED are
//! recognised (so they are not fatal) but carried as [`Frame::Control`] with
//! an unparsed payload: their handlers live outside this crate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::ProtoError;

/// Protocol version carried by OPEN / RESUME / CTRL_HELLO (§10).
pub const VERSION: u8 = 4;
/// Largest allowed payload (§2).
pub const MAX_PAYLOAD: usize = 16_384;
/// Unknown frame types carrying this flag are skipped instead of fatal.
pub const FLAG_IGNORABLE: u8 = 0x80;
/// DATA only: payload starts with `pad_len`.
pub const FLAG_PADDED: u8 = 0x40;
/// Largest varint value.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

pub mod ty {
    pub const OPEN: u8 = 0x01;
    pub const OPENED: u8 = 0x02;
    pub const RESUME: u8 = 0x03;
    pub const RESUMED: u8 = 0x04;
    pub const REJECT: u8 = 0x05;
    pub const DATA: u8 = 0x10;
    pub const ACK: u8 = 0x11;
    pub const FIN: u8 = 0x12;
    pub const RST: u8 = 0x13;
    pub const PAD: u8 = 0x14;
    pub const DGRAM: u8 = 0x20;
    pub const CTRL_HELLO: u8 = 0x30;
    pub const PING: u8 = 0x31;
    pub const PONG: u8 = 0x32;
    pub const WAKE: u8 = 0x33;
    pub const PARK: u8 = 0x34;
    pub const PARK_ACK: u8 = 0x35;
    pub const STALL: u8 = 0x36;
    pub const RESOLVE: u8 = 0x37;
    pub const RESOLVED: u8 = 0x38;
    pub const REFRESH: u8 = 0x39;
    pub const REFRESHED: u8 = 0x3A;
    pub const REVOKED: u8 = 0x3B;
}

/// Error codes (§8).
pub mod code {
    pub const VERSION: u8 = 1;
    pub const AUTH: u8 = 2;
    pub const EXPIRED: u8 = 3;
    pub const UNKNOWN_SESSION: u8 = 4;
    pub const STALE_GEN: u8 = 5;
    pub const CAPACITY: u8 = 6;
    pub const EXIT_DENIED: u8 = 7;
    pub const TARGET_DENIED: u8 = 8;
    pub const CLOSED: u8 = 9;
    pub const ANCHOR_UNREACHABLE: u8 = 10;
    pub const REVOKED: u8 = 11;
    pub const RATE_LIMITED: u8 = 12;
    pub const CONNECT_REFUSED: u8 = 20;
    pub const CONNECT_TIMEOUT: u8 = 21;
    pub const DNS_FAILURE: u8 = 22;
    pub const SITE_RESET: u8 = 23;
    pub const IDLE: u8 = 24;
    pub const ADMIN: u8 = 25;
    pub const MAX_LIFETIME: u8 = 26;
    pub const PROTOCOL: u8 = 27;
    pub const INTERNAL: u8 = 28;
    pub const HOME_UNAVAILABLE: u8 = 29;
    /// `close_code` in a tombstone for a clean close (§5.5). Not a §8 code;
    /// it only appears inside `REJECT(closed)`.
    pub const CLEAN: u8 = 0;
}

pub type SessionId = [u8; 16];
pub type Secret = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tcp = 0,
    Udp = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Open {
    pub version: u8,
    pub ticket: Vec<u8>,
    pub session_id: SessionId,
    pub resume_secret: Secret,
    pub attach_gen: u32,
    /// `open_flags` bit 0.
    pub retry: bool,
    pub anchor_instance_id: u64,
    pub kind: Kind,
    pub target: Target,
    /// Hint only: the relay classifies the target itself (R2-1).
    pub exit_class: u8,
    pub first_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub instance_id: u64,
    pub attach_gen: u32,
    pub recv_offset: u64,
    pub max_offset: u64,
    pub window_cap: u64,
    pub ack_bytes: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Resume {
    pub version: u8,
    pub ticket: Vec<u8>,
    pub anchor_node_id: u64,
    pub anchor_instance_id: u64,
    pub session_id: SessionId,
    pub resume_secret: Secret,
    pub attach_gen: u32,
    pub recv_offset: u64,
    pub max_offset: u64,
}

// Debug never prints the ticket or the resume secret (no secrets in logs).
impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Open")
            .field("version", &self.version)
            .field("ticket", &"<redacted>")
            .field("session_id", &self.session_id)
            .field("resume_secret", &"<redacted>")
            .field("attach_gen", &self.attach_gen)
            .field("retry", &self.retry)
            .field("anchor_instance_id", &self.anchor_instance_id)
            .field("kind", &self.kind)
            .field("target", &self.target)
            .field("exit_class", &self.exit_class)
            .field("first_data_len", &self.first_data.len())
            .finish()
    }
}

impl std::fmt::Debug for Resume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resume")
            .field("version", &self.version)
            .field("ticket", &"<redacted>")
            .field("anchor_node_id", &self.anchor_node_id)
            .field("anchor_instance_id", &self.anchor_instance_id)
            .field("session_id", &self.session_id)
            .field("resume_secret", &"<redacted>")
            .field("attach_gen", &self.attach_gen)
            .field("recv_offset", &self.recv_offset)
            .field("max_offset", &self.max_offset)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resumed {
    pub instance_id: u64,
    pub attach_gen: u32,
    pub recv_offset: u64,
    pub max_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosedInfo {
    pub close_code: u8,
    pub final_recv_offset: u64,
    pub final_sent_offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub code: u8,
    pub attach_gen: u32,
    /// Present exactly when `code == code::CLOSED`.
    pub closed: Option<ClosedInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeEntry {
    pub anchor_node_id: u64,
    pub session_id: SessionId,
    pub park_gen: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParkEntry {
    pub session_id: SessionId,
    pub req_id: u64,
    pub attach_gen: u32,
    pub c_recv_offset: u64,
    pub c_sent_offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParkAckEntry {
    pub session_id: SessionId,
    pub req_id: u64,
    pub attach_gen: u32,
    pub accepted: bool,
    pub park_gen: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Open(Open),
    Opened(Opened),
    Resume(Resume),
    Resumed(Resumed),
    Reject(Reject),
    /// `pad` bytes of padding follow the data when non-zero (A8).
    Data {
        offset: u64,
        data: Vec<u8>,
        pad: usize,
    },
    Ack {
        recv_offset: u64,
        max_offset: u64,
    },
    Fin {
        offset: u64,
    },
    Rst {
        code: u8,
    },
    Pad(usize),
    Dgram {
        addr: SocketAddr,
        data: Vec<u8>,
    },
    Ping {
        nonce: u64,
    },
    /// Optional measurements are kept opaque.
    Pong {
        nonce: u64,
        extra: Vec<u8>,
    },
    Wake {
        full: bool,
        entries: Vec<WakeEntry>,
    },
    Park(Vec<ParkEntry>),
    ParkAck(Vec<ParkAckEntry>),
    Stall(Vec<(SessionId, u32)>),
    /// A recognised control frame whose payload this crate does not parse
    /// (CTRL_HELLO, RESOLVE, RESOLVED, REFRESH, REFRESHED, REVOKED).
    Control {
        ty: u8,
        payload: Vec<u8>,
    },
}

pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    assert!(v <= VARINT_MAX, "varint out of range");
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

pub fn varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Parse a varint from the start of `buf`: `Ok(None)` if incomplete.
pub fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for b in &buf[1..len] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, len))
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn bad() -> ProtoError {
        ProtoError::Malformed
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.buf.len() < n {
            return Err(Self::bad());
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtoError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn varint(&mut self) -> Result<u64, ProtoError> {
        let (v, n) = get_varint(self.buf).ok_or_else(Self::bad)?;
        self.buf = &self.buf[n..];
        Ok(v)
    }
    fn usize(&mut self) -> Result<usize, ProtoError> {
        usize::try_from(self.varint()?).map_err(|_| Self::bad())
    }
    fn lp(&mut self) -> Result<Vec<u8>, ProtoError> {
        let n = self.usize()?;
        Ok(self.take(n)?.to_vec())
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    fn rest(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf).to_vec()
    }
    fn end(&self) -> Result<(), ProtoError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Self::bad())
        }
    }
    fn count(&mut self) -> Result<usize, ProtoError> {
        let n = self.usize()?;
        // Every entry is at least 16 bytes: refuse absurd counts up front.
        if n > self.buf.len() {
            return Err(Self::bad());
        }
        Ok(n)
    }
    fn target(&mut self) -> Result<Target, ProtoError> {
        Ok(match self.u8()? {
            1 => {
                let ip = Ipv4Addr::from(self.arr::<4>()?);
                Target::Ip(SocketAddr::new(IpAddr::V4(ip), self.u16()?))
            }
            4 => {
                let ip = Ipv6Addr::from(self.arr::<16>()?);
                Target::Ip(SocketAddr::new(IpAddr::V6(ip), self.u16()?))
            }
            3 => {
                let n = self.u8()? as usize;
                let name = String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Self::bad())?;
                if name.is_empty() {
                    return Err(Self::bad());
                }
                Target::Domain(name, self.u16()?)
            }
            _ => return Err(Self::bad()),
        })
    }
    fn addr(&mut self) -> Result<SocketAddr, ProtoError> {
        match self.target()? {
            Target::Ip(a) => Ok(a),
            Target::Domain(..) => Err(Self::bad()),
        }
    }
}

fn put_lp(out: &mut Vec<u8>, b: &[u8]) {
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_target(out: &mut Vec<u8>, t: &Target) {
    match t {
        Target::Ip(SocketAddr::V4(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(name, port) => {
            assert!(!name.is_empty() && name.len() <= 255, "domain length");
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

impl Frame {
    pub fn type_byte(&self) -> u8 {
        match self {
            Frame::Open(_) => ty::OPEN,
            Frame::Opened(_) => ty::OPENED,
            Frame::Resume(_) => ty::RESUME,
            Frame::Resumed(_) => ty::RESUMED,
            Frame::Reject(_) => ty::REJECT,
            Frame::Data { .. } => ty::DATA,
            Frame::Ack { .. } => ty::ACK,
            Frame::Fin { .. } => ty::FIN,
            Frame::Rst { .. } => ty::RST,
            Frame::Pad(_) => ty::PAD,
            Frame::Dgram { .. } => ty::DGRAM,
            Frame::Ping { .. } => ty::PING,
            Frame::Pong { .. } => ty::PONG,
            Frame::Wake { .. } => ty::WAKE,
            Frame::Park(_) => ty::PARK,
            Frame::ParkAck(_) => ty::PARK_ACK,
            Frame::Stall(_) => ty::STALL,
            Frame::Control { ty, .. } => *ty,
        }
    }

    /// Append the encoded frame to `out`. Panics if the payload would exceed
    /// [`MAX_PAYLOAD`]; callers size DATA with [`max_data_len`].
    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut p = Vec::new();
        let mut flags = 0u8;
        match self {
            Frame::Open(o) => {
                p.push(o.version);
                put_lp(&mut p, &o.ticket);
                p.extend_from_slice(&o.session_id);
                p.extend_from_slice(&o.resume_secret);
                p.extend_from_slice(&o.attach_gen.to_be_bytes());
                p.push(u8::from(o.retry));
                put_varint(&mut p, o.anchor_instance_id);
                p.push(o.kind as u8);
                put_target(&mut p, &o.target);
                p.push(o.exit_class);
                p.extend_from_slice(&o.first_data);
            }
            Frame::Opened(o) => {
                put_varint(&mut p, o.instance_id);
                p.extend_from_slice(&o.attach_gen.to_be_bytes());
                put_varint(&mut p, o.recv_offset);
                put_varint(&mut p, o.max_offset);
                put_varint(&mut p, o.window_cap);
                put_varint(&mut p, o.ack_bytes);
            }
            Frame::Resume(r) => {
                p.push(r.version);
                put_lp(&mut p, &r.ticket);
                put_varint(&mut p, r.anchor_node_id);
                put_varint(&mut p, r.anchor_instance_id);
                p.extend_from_slice(&r.session_id);
                p.extend_from_slice(&r.resume_secret);
                p.extend_from_slice(&r.attach_gen.to_be_bytes());
                put_varint(&mut p, r.recv_offset);
                put_varint(&mut p, r.max_offset);
            }
            Frame::Resumed(r) => {
                put_varint(&mut p, r.instance_id);
                p.extend_from_slice(&r.attach_gen.to_be_bytes());
                put_varint(&mut p, r.recv_offset);
                put_varint(&mut p, r.max_offset);
            }
            Frame::Reject(r) => {
                p.push(r.code);
                p.extend_from_slice(&r.attach_gen.to_be_bytes());
                if let Some(c) = &r.closed {
                    p.push(c.close_code);
                    put_varint(&mut p, c.final_recv_offset);
                    put_varint(&mut p, c.final_sent_offset);
                }
            }
            Frame::Data { offset, data, pad } => {
                if *pad > 0 {
                    flags |= FLAG_PADDED;
                    put_varint(&mut p, *pad as u64);
                }
                put_varint(&mut p, *offset);
                p.extend_from_slice(data);
                p.resize(p.len() + pad, 0);
            }
            Frame::Ack {
                recv_offset,
                max_offset,
            } => {
                put_varint(&mut p, *recv_offset);
                put_varint(&mut p, *max_offset);
            }
            Frame::Fin { offset } => put_varint(&mut p, *offset),
            Frame::Rst { code } => p.push(*code),
            Frame::Pad(n) => p.resize(*n, 0),
            Frame::Dgram { addr, data } => {
                put_target(&mut p, &Target::Ip(*addr));
                p.extend_from_slice(data);
            }
            Frame::Ping { nonce } => p.extend_from_slice(&nonce.to_be_bytes()),
            Frame::Pong { nonce, extra } => {
                p.extend_from_slice(&nonce.to_be_bytes());
                p.extend_from_slice(extra);
            }
            Frame::Wake { full, entries } => {
                flags |= u8::from(*full);
                put_varint(&mut p, entries.len() as u64);
                for e in entries {
                    put_varint(&mut p, e.anchor_node_id);
                    p.extend_from_slice(&e.session_id);
                    p.extend_from_slice(&e.park_gen.to_be_bytes());
                }
            }
            Frame::Park(entries) => {
                put_varint(&mut p, entries.len() as u64);
                for e in entries {
                    p.extend_from_slice(&e.session_id);
                    put_varint(&mut p, e.req_id);
                    p.extend_from_slice(&e.attach_gen.to_be_bytes());
                    put_varint(&mut p, e.c_recv_offset);
                    put_varint(&mut p, e.c_sent_offset);
                }
            }
            Frame::ParkAck(entries) => {
                put_varint(&mut p, entries.len() as u64);
                for e in entries {
                    p.extend_from_slice(&e.session_id);
                    put_varint(&mut p, e.req_id);
                    p.extend_from_slice(&e.attach_gen.to_be_bytes());
                    p.push(u8::from(e.accepted));
                    p.extend_from_slice(&e.park_gen.to_be_bytes());
                }
            }
            Frame::Stall(entries) => {
                put_varint(&mut p, entries.len() as u64);
                for (sid, gen) in entries {
                    p.extend_from_slice(sid);
                    p.extend_from_slice(&gen.to_be_bytes());
                }
            }
            Frame::Control { payload, .. } => p.extend_from_slice(payload),
        }
        assert!(p.len() <= MAX_PAYLOAD, "frame payload too large");
        out.push(self.type_byte());
        out.push(flags);
        put_varint(out, p.len() as u64);
        out.extend_from_slice(&p);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }

    /// Decode one payload. `Ok(None)` = unknown ignorable type, skipped.
    pub fn decode(ty: u8, flags: u8, payload: &[u8]) -> Result<Option<Frame>, ProtoError> {
        let mut r = Reader { buf: payload };
        let f = match ty {
            ty::OPEN => {
                let version = r.u8()?;
                if version != VERSION {
                    // Remaining fields may have another layout.
                    return Err(ProtoError::Version(version));
                }
                let ticket = r.lp()?;
                let session_id = r.arr()?;
                let resume_secret = r.arr()?;
                let attach_gen = r.u32()?;
                let open_flags = r.u8()?;
                let anchor_instance_id = r.varint()?;
                let kind = match r.u8()? {
                    0 => Kind::Tcp,
                    1 => Kind::Udp,
                    _ => return Err(ProtoError::Malformed),
                };
                let target = r.target()?;
                let exit_class = r.u8()?;
                Frame::Open(Open {
                    version,
                    ticket,
                    session_id,
                    resume_secret,
                    attach_gen,
                    retry: open_flags & 1 != 0,
                    anchor_instance_id,
                    kind,
                    target,
                    exit_class,
                    first_data: r.rest(),
                })
            }
            ty::OPENED => Frame::Opened(Opened {
                instance_id: r.varint()?,
                attach_gen: r.u32()?,
                recv_offset: r.varint()?,
                max_offset: r.varint()?,
                window_cap: r.varint()?,
                ack_bytes: r.varint()?,
            }),
            ty::RESUME => {
                let version = r.u8()?;
                if version != VERSION {
                    return Err(ProtoError::Version(version));
                }
                Frame::Resume(Resume {
                    version,
                    ticket: r.lp()?,
                    anchor_node_id: r.varint()?,
                    anchor_instance_id: r.varint()?,
                    session_id: r.arr()?,
                    resume_secret: r.arr()?,
                    attach_gen: r.u32()?,
                    recv_offset: r.varint()?,
                    max_offset: r.varint()?,
                })
            }
            ty::RESUMED => Frame::Resumed(Resumed {
                instance_id: r.varint()?,
                attach_gen: r.u32()?,
                recv_offset: r.varint()?,
                max_offset: r.varint()?,
            }),
            ty::REJECT => {
                let code = r.u8()?;
                let attach_gen = r.u32()?;
                let closed = if code == code::CLOSED {
                    Some(ClosedInfo {
                        close_code: r.u8()?,
                        final_recv_offset: r.varint()?,
                        final_sent_offset: r.varint()?,
                    })
                } else {
                    None
                };
                Frame::Reject(Reject {
                    code,
                    attach_gen,
                    closed,
                })
            }
            ty::DATA => {
                let pad = if flags & FLAG_PADDED != 0 {
                    r.usize()?
                } else {
                    0
                };
                let offset = r.varint()?;
                let rest = r.rest();
                if pad > rest.len() {
                    return Err(ProtoError::Malformed);
                }
                let data = rest[..rest.len() - pad].to_vec();
                if offset
                    .checked_add(data.len() as u64)
                    .is_none_or(|e| e > VARINT_MAX)
                {
                    return Err(ProtoError::Malformed);
                }
                Frame::Data { offset, data, pad }
            }
            ty::ACK => Frame::Ack {
                recv_offset: r.varint()?,
                max_offset: r.varint()?,
            },
            ty::FIN => Frame::Fin {
                offset: r.varint()?,
            },
            ty::RST => Frame::Rst { code: r.u8()? },
            ty::PAD => return Ok(Some(Frame::Pad(payload.len()))),
            ty::DGRAM => Frame::Dgram {
                addr: r.addr()?,
                data: r.rest(),
            },
            ty::PING => Frame::Ping { nonce: r.u64()? },
            ty::PONG => Frame::Pong {
                nonce: r.u64()?,
                extra: r.rest(),
            },
            ty::WAKE => {
                let n = r.count()?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push(WakeEntry {
                        anchor_node_id: r.varint()?,
                        session_id: r.arr()?,
                        park_gen: r.u32()?,
                    });
                }
                Frame::Wake {
                    full: flags & 1 != 0,
                    entries,
                }
            }
            ty::PARK => {
                let n = r.count()?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push(ParkEntry {
                        session_id: r.arr()?,
                        req_id: r.varint()?,
                        attach_gen: r.u32()?,
                        c_recv_offset: r.varint()?,
                        c_sent_offset: r.varint()?,
                    });
                }
                Frame::Park(entries)
            }
            ty::PARK_ACK => {
                let n = r.count()?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    let session_id = r.arr()?;
                    let req_id = r.varint()?;
                    let attach_gen = r.u32()?;
                    let accepted = match r.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(ProtoError::Malformed),
                    };
                    entries.push(ParkAckEntry {
                        session_id,
                        req_id,
                        attach_gen,
                        accepted,
                        park_gen: r.u32()?,
                    });
                }
                Frame::ParkAck(entries)
            }
            ty::STALL => {
                let n = r.count()?;
                let mut entries = Vec::with_capacity(n);
                for _ in 0..n {
                    entries.push((r.arr()?, r.u32()?));
                }
                Frame::Stall(entries)
            }
            ty::CTRL_HELLO
            | ty::RESOLVE
            | ty::RESOLVED
            | ty::REFRESH
            | ty::REFRESHED
            | ty::REVOKED => Frame::Control {
                ty,
                payload: r.rest(),
            },
            _ if flags & FLAG_IGNORABLE != 0 => return Ok(None),
            _ => return Err(ProtoError::UnknownFrame(ty)),
        };
        r.end()?;
        Ok(Some(f))
    }
}

/// Largest DATA chunk that fits one frame with `pad` bytes of padding.
pub fn max_data_len(offset: u64, pad: usize) -> usize {
    let pad_hdr = if pad > 0 { varint_len(pad as u64) } else { 0 };
    MAX_PAYLOAD - pad_hdr - varint_len(offset) - pad
}

/// Incremental decoder. Holds at most one partial frame plus whatever the
/// caller pushed since the last drain.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    pos: usize,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if self.pos > 0 && self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > MAX_PAYLOAD {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes held but not yet returned as frames.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Next complete frame. Errors are fatal for the carrier.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, ProtoError> {
        loop {
            let b = &self.buf[self.pos..];
            if b.len() < 3 {
                return Ok(None);
            }
            let (len, n) = match get_varint(&b[2..]) {
                Some(v) => v,
                None => return Ok(None),
            };
            if len > MAX_PAYLOAD as u64 {
                return Err(ProtoError::FrameTooLong);
            }
            let total = 2 + n + len as usize;
            if b.len() < total {
                return Ok(None);
            }
            let (ty, flags) = (b[0], b[1]);
            let res = Frame::decode(ty, flags, &b[2 + n..total]);
            self.pos += total;
            match res? {
                Some(f) => return Ok(Some(f)),
                None => continue,
            }
        }
    }
}
