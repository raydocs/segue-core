//! TUN entry point: IP packets in, IP packets out, flows into the kernel's
//! routing and [`Dialer`].
//!
//! Layering (KERNEL_SPEC §4.2, §4.3, §5):
//!
//! * [`Netstack`] is synchronous and owns no I/O and no clock: the caller
//!   feeds packets and timestamps in and drains packets out. It parses
//!   IPv4/IPv6, keeps a flow table keyed by 5-tuple, terminates TCP in a
//!   userspace stack (the vendored smoltcp), hands UDP datagrams to the caller
//!   and synthesizes refusals (TCP RST, ICMP/ICMPv6 administratively
//!   prohibited, rate limited). Everything here is testable without root.
//! * [`TunStack`] is the async driver: it pumps a [`PacketIo`] through a
//!   `Netstack`, asks a [`TunRouter`] what to do with each new flow, dials
//!   accepted TCP flows through the kernel [`Dialer`] and relays bytes, and
//!   passes UDP to an optional [`UdpHandler`].
//! * Device I/O is the thin [`PacketIo`] trait. The engine's
//!   `segue_tun::TunEndpoint` implements it, and the engine's
//!   `segue_engine::TunFdRuntime` already moves packets between an OS TUN file
//!   descriptor (raw IP or Darwin utun framing) and a `TunEndpoint`, so no
//!   extra device crate is needed.
//!
//! Refusal semantics (§5.4): a refused flow never falls back to anything.
//! A refused SYN gets a RST, an accepted flow whose dial fails is reset after
//! the local handshake, a refused UDP flow gets ICMP unreachable. Private,
//! loopback and link-local destinations that reach the TUN are refused before
//! the router is asked; multicast/broadcast/unspecified are dropped silently.
//!
//! Memory is bounded: TCP flows ≤ `max_tcp_flows` (each with fixed smoltcp
//! buffers plus a few relay chunks), UDP flows ≤ `max_udp_flows`, the UDP
//! datagram queue drops oldest, and the outbound packet queue drops newest
//! when full. A new flow that does not fit is refused, never queued.
//!
//! Not handled: IPv4 fragments and IPv6 extension headers are dropped
//! (counted); oversize outbound UDP is dropped rather than fragmented.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use segue_routing::TargetAddr;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp::{self, State};
use smoltcp::wire::{
    HardwareAddress, Icmpv4DstUnreachable, Icmpv4Packet, Icmpv4Repr, Icmpv6DstUnreachable,
    Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Packet,
    Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket,
    UdpRepr, IPV4_HEADER_LEN, IPV6_HEADER_LEN, UDP_HEADER_LEN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

use crate::dial::Dialer;
use crate::rules::{Action, RuleSet};

const TCP_HEADER_LEN: usize = 20;
/// Bytes moved per relay chunk between the stack and a flow task.
const CHUNK: usize = 16 * 1024;
/// Relay chunks buffered per direction per flow.
const RELAY_CHUNKS: usize = 4;
/// IPv6 minimum MTU; ICMPv6 errors must fit in it (RFC 4443 §2.4).
const IPV6_MIN_MTU: usize = 1280;

// ---------------------------------------------------------------------------
// Flow identity

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A flow as seen from the TUN: `src` is the local application, `dst` the
/// destination it tried to reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowId(pub u64);

/// What the policy decided for a new flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Accept; the value is an opaque outbound tag carried with the flow
    /// (`None` = direct).
    Accept(Option<String>),
    Refuse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A SYN was accepted and answered locally; the caller should dial.
    TcpAccepted {
        id: FlowId,
        key: FlowKey,
        tag: Option<String>,
    },
    /// The flow is gone (closed, reset or aborted); its id is dead.
    TcpClosed { id: FlowId, key: FlowKey },
    /// A UDP flow expired.
    UdpClosed { key: FlowKey },
}

/// One received UDP datagram for an accepted flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram {
    pub key: FlowKey,
    pub tag: Option<String>,
    pub payload: Bytes,
}

#[derive(Clone, Debug)]
pub struct NetstackConfig {
    /// TUN MTU. Bounds inbound packets, outbound packets and the MSS the
    /// stack advertises (MTU minus IP and TCP headers).
    pub mtu: usize,
    /// Address of the TUN interface itself; used as the source of ICMP
    /// errors and as the stack's own address for any-IP routing.
    pub v4_addr: Ipv4Addr,
    pub v6_addr: Ipv6Addr,
    pub max_tcp_flows: usize,
    pub tcp_rx_buffer: usize,
    pub tcp_tx_buffer: usize,
    /// Abort a TCP flow when sent data stays unacknowledged this long.
    pub tcp_timeout: Duration,
    pub max_udp_flows: usize,
    pub udp_idle_timeout: Duration,
    /// Received UDP datagrams awaiting the handler; oldest dropped first.
    pub udp_queue: usize,
    /// Outbound packets awaiting the device; newest dropped when full.
    pub out_queue: usize,
    /// Synthesized ICMP: sustained rate and burst (token bucket).
    pub icmp_per_sec: u32,
    pub icmp_burst: u32,
}

impl Default for NetstackConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            v4_addr: Ipv4Addr::new(198, 18, 0, 1),
            v6_addr: Ipv6Addr::new(0xfd00, 0x5e9e, 0, 0, 0, 0, 0, 1),
            max_tcp_flows: 512,
            tcp_rx_buffer: 64 * 1024,
            tcp_tx_buffer: 64 * 1024,
            tcp_timeout: Duration::from_secs(120),
            max_udp_flows: 1024,
            udp_idle_timeout: Duration::from_secs(60),
            udp_queue: 512,
            out_queue: 4096,
            icmp_per_sec: 50,
            icmp_burst: 50,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetstackStats {
    pub packets_in: u64,
    pub packets_out: u64,
    pub dropped_malformed: u64,
    pub dropped_oversize: u64,
    pub dropped_fragment: u64,
    pub dropped_unsupported: u64,
    pub dropped_silent_dst: u64,
    pub dropped_out_queue_full: u64,
    pub dropped_udp_queue_full: u64,
    pub tcp_accepted: u64,
    pub tcp_refused_policy: u64,
    pub tcp_refused_reserved: u64,
    pub tcp_refused_full: u64,
    pub tcp_rst_stale: u64,
    pub tcp_aborted: u64,
    pub udp_refused_policy: u64,
    pub udp_refused_reserved: u64,
    pub udp_refused_full: u64,
    pub icmp_sent: u64,
    pub icmp_suppressed: u64,
}

/// Why a destination is not admitted before the router is consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedDst {
    /// Never answered (multicast, broadcast, unspecified).
    Silent,
    /// Refused (private, loopback, link-local, CGNAT, ULA): §5.4.
    Refuse,
}

/// Classify destinations that must not be routed out of the TUN.
pub fn reserved_dst(ip: IpAddr) -> Option<ReservedDst> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
                Some(ReservedDst::Silent)
            } else if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                || v4.octets()[0] == 0
            {
                Some(ReservedDst::Refuse)
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return reserved_dst(IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            if v6.is_unspecified() || v6.is_multicast() {
                Some(ReservedDst::Silent)
            } else if v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80 {
                Some(ReservedDst::Refuse)
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Packet parsing

#[derive(Clone, Copy, Debug)]
struct TcpMeta {
    syn: bool,
    ack: bool,
    rst: bool,
    fin: bool,
    seq: u32,
    ack_no: u32,
    payload_len: usize,
}

enum L4<'a> {
    Tcp(TcpMeta),
    Udp(&'a [u8]),
}

struct Parsed<'a> {
    key: FlowKey,
    l4: L4<'a>,
    /// The whole L4 segment (for ICMP quoting).
    ip_payload: &'a [u8],
    /// The IP header length (for ICMP quoting).
    ip_header_len: usize,
}

enum Reject {
    Malformed,
    Fragment,
    Unsupported,
}

fn parse(pkt: &[u8]) -> Result<Parsed<'_>, Reject> {
    let version = pkt.first().ok_or(Reject::Malformed)? >> 4;
    let (src, dst, proto, ip_payload, ip_header_len) = match version {
        4 => {
            let ip = Ipv4Packet::new_checked(pkt).map_err(|_| Reject::Malformed)?;
            if !ip.verify_checksum() {
                return Err(Reject::Malformed);
            }
            if ip.more_frags() || ip.frag_offset() != 0 {
                return Err(Reject::Fragment);
            }
            let hl = ip.header_len() as usize;
            let total = ip.total_len() as usize;
            (
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.next_header(),
                &pkt[hl..total],
                hl,
            )
        }
        6 => {
            let ip = Ipv6Packet::new_checked(pkt).map_err(|_| Reject::Malformed)?;
            let total = IPV6_HEADER_LEN + ip.payload_len() as usize;
            (
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ip.next_header(),
                &pkt[IPV6_HEADER_LEN..total],
                IPV6_HEADER_LEN,
            )
        }
        _ => return Err(Reject::Malformed),
    };
    let (s, d) = (IpAddress::from(src), IpAddress::from(dst));
    match proto {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(ip_payload).map_err(|_| Reject::Malformed)?;
            if !tcp.verify_checksum(&s, &d) {
                return Err(Reject::Malformed);
            }
            let meta = TcpMeta {
                syn: tcp.syn(),
                ack: tcp.ack(),
                rst: tcp.rst(),
                fin: tcp.fin(),
                seq: tcp.seq_number().0 as u32,
                ack_no: tcp.ack_number().0 as u32,
                payload_len: tcp.payload().len(),
            };
            Ok(Parsed {
                key: FlowKey {
                    proto: Proto::Tcp,
                    src: SocketAddr::new(src, tcp.src_port()),
                    dst: SocketAddr::new(dst, tcp.dst_port()),
                },
                l4: L4::Tcp(meta),
                ip_payload,
                ip_header_len,
            })
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(ip_payload).map_err(|_| Reject::Malformed)?;
            // IPv4 UDP may omit the checksum; IPv6 may not.
            if (udp.checksum() != 0 || src.is_ipv6()) && !udp.verify_checksum(&s, &d) {
                return Err(Reject::Malformed);
            }
            let payload = &ip_payload[UDP_HEADER_LEN..udp.len() as usize];
            Ok(Parsed {
                key: FlowKey {
                    proto: Proto::Udp,
                    src: SocketAddr::new(src, udp.src_port()),
                    dst: SocketAddr::new(dst, udp.dst_port()),
                },
                l4: L4::Udp(payload),
                ip_payload,
                ip_header_len,
            })
        }
        _ => Err(Reject::Unsupported),
    }
}

// ---------------------------------------------------------------------------
// Packet building

fn checksums() -> ChecksumCapabilities {
    ChecksumCapabilities::default()
}

/// Build an IP packet `src → dst` whose L4 body (`len` bytes) `fill` writes.
fn build_ip(
    src: IpAddr,
    dst: IpAddr,
    proto: IpProtocol,
    len: usize,
    fill: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let repr = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: proto,
                payload_len: len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; IPV4_HEADER_LEN + len];
            let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
            repr.emit(&mut ip, &checksums());
            fill(ip.payload_mut());
            buf
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let repr = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: proto,
                payload_len: len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; IPV6_HEADER_LEN + len];
            let mut ip = Ipv6Packet::new_unchecked(&mut buf[..]);
            repr.emit(&mut ip);
            fill(ip.payload_mut());
            buf
        }
        _ => unreachable!("address families of a flow always match"),
    }
}

/// RST answering a segment for which no connection will exist (RFC 9293
/// §3.10.7.1): if the segment carried an ACK the RST takes its sequence from
/// it, otherwise it acknowledges the segment.
fn build_rst(key: &FlowKey, meta: &TcpMeta) -> Vec<u8> {
    let seg_len = meta.payload_len as u32 + meta.syn as u32 + meta.fin as u32;
    let (seq, ack) = if meta.ack {
        (meta.ack_no, None)
    } else {
        (0, Some(TcpSeqNumber(meta.seq.wrapping_add(seg_len) as i32)))
    };
    let repr = TcpRepr {
        src_port: key.dst.port(),
        dst_port: key.src.port(),
        control: TcpControl::Rst,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: ack,
        window_len: 0,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let (src, dst) = (IpAddress::from(key.dst.ip()), IpAddress::from(key.src.ip()));
    build_ip(
        key.dst.ip(),
        key.src.ip(),
        IpProtocol::Tcp,
        repr.buffer_len(),
        |b| {
            repr.emit(&mut TcpPacket::new_unchecked(b), &src, &dst, &checksums());
        },
    )
}

fn build_udp(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let repr = UdpRepr {
        src_port: from.port(),
        dst_port: to.port(),
    };
    let (src, dst) = (IpAddress::from(from.ip()), IpAddress::from(to.ip()));
    build_ip(
        from.ip(),
        to.ip(),
        IpProtocol::Udp,
        UDP_HEADER_LEN + payload.len(),
        |b| {
            repr.emit(
                &mut UdpPacket::new_unchecked(b),
                &src,
                &dst,
                payload.len(),
                |p| p.copy_from_slice(payload),
                &checksums(),
            );
        },
    )
}

/// ICMP destination unreachable, administratively prohibited, quoting the
/// offending packet. `pkt` is the original packet, already parsed.
fn build_icmp_prohibited(own: IpAddr, pkt: &[u8], parsed: &Parsed<'_>) -> Option<Vec<u8>> {
    let client = parsed.key.src.ip();
    match (own, client) {
        (IpAddr::V4(own), IpAddr::V4(_)) => {
            let orig = Ipv4Repr::parse(&Ipv4Packet::new_unchecked(pkt), &checksums()).ok()?;
            let data = &parsed.ip_payload[..parsed.ip_payload.len().min(8)];
            let repr = Icmpv4Repr::DstUnreachable {
                reason: Icmpv4DstUnreachable::CommProhibited,
                header: orig,
                data,
            };
            Some(build_ip(
                IpAddr::V4(own),
                client,
                IpProtocol::Icmp,
                repr.buffer_len(),
                |b| {
                    repr.emit(&mut Icmpv4Packet::new_unchecked(b), &checksums());
                },
            ))
        }
        (IpAddr::V6(own), IpAddr::V6(dst)) => {
            let orig = Ipv6Repr::parse(&Ipv6Packet::new_unchecked(pkt)).ok()?;
            // ICMPv6 header (8) + quoted IPv6 header (40) + data, in 1280.
            let room = IPV6_MIN_MTU - IPV6_HEADER_LEN - 8 - IPV6_HEADER_LEN;
            let data = &parsed.ip_payload[..parsed.ip_payload.len().min(room)];
            let repr = Icmpv6Repr::DstUnreachable {
                reason: Icmpv6DstUnreachable::AdminProhibit,
                header: orig,
                data,
            };
            debug_assert_eq!(parsed.ip_header_len, IPV6_HEADER_LEN);
            Some(build_ip(
                IpAddr::V6(own),
                client,
                IpProtocol::Icmpv6,
                repr.buffer_len(),
                |b| {
                    repr.emit(
                        &own,
                        &dst,
                        &mut Icmpv6Packet::new_unchecked(b),
                        &checksums(),
                    );
                },
            ))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// smoltcp device: one packet in, any number of packets out.

struct QueueDevice {
    mtu: usize,
    rx: Option<Vec<u8>>,
    tx: VecDeque<Bytes>,
}

struct RxTok(Vec<u8>);
struct TxTok<'a>(&'a mut VecDeque<Bytes>);

impl phy::RxToken for RxTok {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl phy::TxToken for TxTok<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(Bytes::from(buf));
        r
    }
}

impl Device for QueueDevice {
    type RxToken<'a>
        = RxTok
    where
        Self: 'a;
    type TxToken<'a>
        = TxTok<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _ts: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.take()?;
        Some((RxTok(pkt), TxTok(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTok(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

fn tcp_timestamp() -> u32 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u32
}

// ---------------------------------------------------------------------------
// Netstack

struct TcpEntry {
    id: FlowId,
    handle: SocketHandle,
}

struct UdpEntry {
    tag: Option<String>,
    last_seen: Instant,
}

struct TokenBucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl TokenBucket {
    fn take(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Error from a per-flow socket call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowGone {
    Gone,
}

/// Synchronous userspace TCP/IP endpoint for TUN packets. See module docs.
pub struct Netstack {
    cfg: NetstackConfig,
    epoch: Instant,
    iface: Interface,
    dev: QueueDevice,
    sockets: SocketSet<'static>,
    tcp: HashMap<FlowKey, TcpEntry>,
    ids: HashMap<FlowId, FlowKey>,
    next_id: u64,
    udp: HashMap<FlowKey, UdpEntry>,
    udp_rx: VecDeque<UdpDatagram>,
    events: VecDeque<Event>,
    out: VecDeque<Bytes>,
    icmp: TokenBucket,
    last_udp_sweep: Instant,
    stats: NetstackStats,
}

impl Netstack {
    pub fn new(cfg: NetstackConfig, now: Instant) -> Self {
        let mut dev = QueueDevice {
            mtu: cfg.mtu,
            rx: None,
            tx: VecDeque::new(),
        };
        let ts = smoltcp::time::Instant::from_micros(0);
        let mut iface = Interface::new(IfaceConfig::new(HardwareAddress::Ip), &mut dev, ts);
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addrs| {
            // Capacity is IFACE_MAX_ADDR_COUNT (2): exactly one per family.
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(cfg.v4_addr), 32));
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(cfg.v6_addr), 128));
        });
        // any-IP delivery needs a route whose gateway is one of our own
        // addresses.
        let _ = iface.routes_mut().add_default_ipv4_route(cfg.v4_addr);
        let _ = iface.routes_mut().add_default_ipv6_route(cfg.v6_addr);
        let icmp = TokenBucket {
            tokens: cfg.icmp_burst as f64,
            rate: cfg.icmp_per_sec as f64,
            burst: cfg.icmp_burst as f64,
            last: now,
        };
        Self {
            cfg,
            epoch: now,
            iface,
            dev,
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            ids: HashMap::new(),
            next_id: 1,
            udp: HashMap::new(),
            udp_rx: VecDeque::new(),
            events: VecDeque::new(),
            out: VecDeque::new(),
            icmp,
            last_udp_sweep: now,
            stats: NetstackStats::default(),
        }
    }

    pub fn config(&self) -> &NetstackConfig {
        &self.cfg
    }

    pub fn stats(&self) -> &NetstackStats {
        &self.stats
    }

    pub fn tcp_flows(&self) -> usize {
        self.tcp.len()
    }

    pub fn udp_flows(&self) -> usize {
        self.udp.len()
    }

    fn ts(&self, now: Instant) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_micros(
            now.saturating_duration_since(self.epoch).as_micros() as i64
        )
    }

    fn emit(&mut self, pkt: Vec<u8>) {
        if self.out.len() >= self.cfg.out_queue {
            self.stats.dropped_out_queue_full += 1;
            return;
        }
        self.stats.packets_out += 1;
        self.out.push_back(Bytes::from(pkt));
    }

    fn emit_icmp(&mut self, pkt: &[u8], parsed: &Parsed<'_>, now: Instant) {
        if !self.icmp.take(now) {
            self.stats.icmp_suppressed += 1;
            return;
        }
        let own = match parsed.key.src {
            SocketAddr::V4(_) => IpAddr::V4(self.cfg.v4_addr),
            SocketAddr::V6(_) => IpAddr::V6(self.cfg.v6_addr),
        };
        if let Some(reply) = build_icmp_prohibited(own, pkt, parsed) {
            self.stats.icmp_sent += 1;
            self.emit(reply);
        }
    }

    /// Feed one packet read from the TUN. `policy` is asked once per new flow
    /// (TCP SYN or first UDP datagram) after the built-in checks.
    pub fn input(&mut self, pkt: &[u8], now: Instant, policy: &mut dyn FnMut(&FlowKey) -> Verdict) {
        self.stats.packets_in += 1;
        if pkt.len() > self.cfg.mtu {
            self.stats.dropped_oversize += 1;
            return;
        }
        let parsed = match parse(pkt) {
            Ok(p) => p,
            Err(Reject::Malformed) => {
                self.stats.dropped_malformed += 1;
                return;
            }
            Err(Reject::Fragment) => {
                self.stats.dropped_fragment += 1;
                return;
            }
            Err(Reject::Unsupported) => {
                self.stats.dropped_unsupported += 1;
                return;
            }
        };
        match parsed.l4 {
            L4::Tcp(meta) => self.input_tcp(pkt, &parsed.key, meta, now, policy),
            L4::Udp(payload) => {
                let payload = Bytes::copy_from_slice(payload);
                self.input_udp(pkt, &parsed, payload, now, policy)
            }
        }
    }

    fn input_tcp(
        &mut self,
        pkt: &[u8],
        key: &FlowKey,
        meta: TcpMeta,
        now: Instant,
        policy: &mut dyn FnMut(&FlowKey) -> Verdict,
    ) {
        if self.tcp.contains_key(key) {
            self.feed(pkt, now);
            return;
        }
        if meta.rst {
            return;
        }
        if !meta.syn || meta.ack {
            // Segment for a connection we do not have (e.g. after a short
            // TIME_WAIT, or a flow that predates us).
            self.stats.tcp_rst_stale += 1;
            self.emit(build_rst(key, &meta));
            return;
        }
        match reserved_dst(key.dst.ip()) {
            Some(ReservedDst::Silent) => {
                self.stats.dropped_silent_dst += 1;
                return;
            }
            Some(ReservedDst::Refuse) => {
                self.stats.tcp_refused_reserved += 1;
                self.emit(build_rst(key, &meta));
                return;
            }
            None => {}
        }
        if self.tcp.len() >= self.cfg.max_tcp_flows {
            self.stats.tcp_refused_full += 1;
            self.emit(build_rst(key, &meta));
            return;
        }
        let tag = match policy(key) {
            Verdict::Accept(tag) => tag,
            Verdict::Refuse => {
                self.stats.tcp_refused_policy += 1;
                self.emit(build_rst(key, &meta));
                return;
            }
        };
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; self.cfg.tcp_rx_buffer]),
            tcp::SocketBuffer::new(vec![0u8; self.cfg.tcp_tx_buffer]),
        );
        sock.set_nagle_enabled(false);
        sock.set_timeout(Some(self.cfg.tcp_timeout.into()));
        sock.set_tsval_generator(Some(tcp_timestamp));
        sock.set_congestion_control(tcp::CongestionControl::Reno);
        let listen = IpListenEndpoint {
            addr: Some(IpAddress::from(key.dst.ip())),
            port: key.dst.port(),
        };
        if sock.listen(listen).is_err() {
            self.stats.dropped_malformed += 1;
            return;
        }
        let handle = self.sockets.add(sock);
        let id = FlowId(self.next_id);
        self.next_id += 1;
        self.tcp.insert(*key, TcpEntry { id, handle });
        self.ids.insert(id, *key);
        self.feed(pkt, now);
        if self.sockets.get::<tcp::Socket>(handle).state() == State::Listen {
            // smoltcp did not take the SYN; drop the listener again.
            self.remove_tcp(key);
            self.stats.dropped_malformed += 1;
            return;
        }
        self.stats.tcp_accepted += 1;
        self.events
            .push_back(Event::TcpAccepted { id, key: *key, tag });
    }

    fn input_udp(
        &mut self,
        pkt: &[u8],
        parsed: &Parsed<'_>,
        payload: Bytes,
        now: Instant,
        policy: &mut dyn FnMut(&FlowKey) -> Verdict,
    ) {
        let key = parsed.key;
        let tag = if let Some(entry) = self.udp.get_mut(&key) {
            entry.last_seen = now;
            entry.tag.clone()
        } else {
            match reserved_dst(key.dst.ip()) {
                Some(ReservedDst::Silent) => {
                    self.stats.dropped_silent_dst += 1;
                    return;
                }
                Some(ReservedDst::Refuse) => {
                    self.stats.udp_refused_reserved += 1;
                    self.emit_icmp(pkt, parsed, now);
                    return;
                }
                None => {}
            }
            if self.udp.len() >= self.cfg.max_udp_flows {
                self.sweep_udp(now);
            }
            if self.udp.len() >= self.cfg.max_udp_flows {
                self.stats.udp_refused_full += 1;
                self.emit_icmp(pkt, parsed, now);
                return;
            }
            match policy(&key) {
                Verdict::Accept(tag) => {
                    self.udp.insert(
                        key,
                        UdpEntry {
                            tag: tag.clone(),
                            last_seen: now,
                        },
                    );
                    tag
                }
                Verdict::Refuse => {
                    self.stats.udp_refused_policy += 1;
                    self.emit_icmp(pkt, parsed, now);
                    return;
                }
            }
        };
        if self.cfg.udp_queue == 0 {
            self.stats.dropped_udp_queue_full += 1;
            return;
        }
        if self.udp_rx.len() >= self.cfg.udp_queue {
            self.udp_rx.pop_front();
            self.stats.dropped_udp_queue_full += 1;
        }
        self.udp_rx.push_back(UdpDatagram { key, tag, payload });
    }

    fn feed(&mut self, pkt: &[u8], now: Instant) {
        self.dev.rx = Some(pkt.to_vec());
        self.poll(now);
    }

    /// Run the TCP stack's timers and transmit whatever is due; reap dead
    /// flows. Call after socket reads/writes and when [`Self::poll_delay`]
    /// expires.
    pub fn poll(&mut self, now: Instant) {
        let ts = self.ts(now);
        self.iface.poll(ts, &mut self.dev, &mut self.sockets);
        self.dev.rx = None;
        while let Some(pkt) = self.dev.tx.pop_front() {
            if pkt.len() > self.cfg.mtu {
                self.stats.dropped_oversize += 1;
                continue;
            }
            if self.out.len() >= self.cfg.out_queue {
                self.stats.dropped_out_queue_full += 1;
                continue;
            }
            self.stats.packets_out += 1;
            self.out.push_back(pkt);
        }
        // Short TIME_WAIT (§4.2): a flow is gone once both sides finished.
        let dead: Vec<FlowKey> = self
            .tcp
            .iter()
            .filter(|(_, e)| {
                matches!(
                    self.sockets.get::<tcp::Socket>(e.handle).state(),
                    State::Closed | State::TimeWait
                )
            })
            .map(|(k, _)| *k)
            .collect();
        for key in dead {
            self.remove_tcp(&key);
        }
        if now.saturating_duration_since(self.last_udp_sweep) >= Duration::from_secs(1) {
            self.sweep_udp(now);
        }
    }

    fn remove_tcp(&mut self, key: &FlowKey) {
        if let Some(entry) = self.tcp.remove(key) {
            self.sockets.remove(entry.handle);
            self.ids.remove(&entry.id);
            self.events.push_back(Event::TcpClosed {
                id: entry.id,
                key: *key,
            });
        }
    }

    fn sweep_udp(&mut self, now: Instant) {
        self.last_udp_sweep = now;
        let idle = self.cfg.udp_idle_timeout;
        let expired: Vec<FlowKey> = self
            .udp
            .iter()
            .filter(|(_, e)| now.saturating_duration_since(e.last_seen) >= idle)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            self.udp.remove(&key);
            self.events.push_back(Event::UdpClosed { key });
        }
    }

    /// How long until [`Self::poll`] must run again (`None`: only on input).
    pub fn poll_delay(&mut self, now: Instant) -> Option<Duration> {
        let ts = self.ts(now);
        self.iface.poll_delay(ts, &self.sockets).map(Duration::from)
    }

    pub fn pop_output(&mut self) -> Option<Bytes> {
        self.out.pop_front()
    }

    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn pop_udp(&mut self) -> Option<UdpDatagram> {
        self.udp_rx.pop_front()
    }

    fn socket(&mut self, id: FlowId) -> Result<&mut tcp::Socket<'static>, FlowGone> {
        let key = self.ids.get(&id).ok_or(FlowGone::Gone)?;
        let handle = self.tcp.get(key).ok_or(FlowGone::Gone)?.handle;
        Ok(self.sockets.get_mut::<tcp::Socket>(handle))
    }

    /// Bytes the application sent that are ready to be read.
    pub fn tcp_recv_queue(&mut self, id: FlowId) -> Result<usize, FlowGone> {
        Ok(self.socket(id)?.recv_queue())
    }

    /// Read application bytes. Returns 0 when nothing is buffered.
    pub fn tcp_read(&mut self, id: FlowId, buf: &mut [u8]) -> Result<usize, FlowGone> {
        let sock = self.socket(id)?;
        if !sock.can_recv() {
            return Ok(0);
        }
        sock.recv_slice(buf).map_err(|_| FlowGone::Gone)
    }

    /// The application half-closed (FIN received) and everything it sent has
    /// been read.
    pub fn tcp_peer_finished(&mut self, id: FlowId) -> Result<bool, FlowGone> {
        let sock = self.socket(id)?;
        Ok(!sock.can_recv()
            && matches!(
                sock.state(),
                State::CloseWait | State::LastAck | State::Closing
            ))
    }

    /// Room for bytes towards the application.
    pub fn tcp_send_capacity(&mut self, id: FlowId) -> Result<usize, FlowGone> {
        let sock = self.socket(id)?;
        if !sock.may_send() {
            return Ok(0);
        }
        Ok(sock.send_capacity() - sock.send_queue())
    }

    /// Queue bytes towards the application; returns how many were taken.
    pub fn tcp_write(&mut self, id: FlowId, data: &[u8]) -> Result<usize, FlowGone> {
        let sock = self.socket(id)?;
        if !sock.may_send() {
            return Ok(0);
        }
        sock.send_slice(data).map_err(|_| FlowGone::Gone)
    }

    /// The handshake with the application completed.
    pub fn tcp_established(&mut self, id: FlowId) -> Result<bool, FlowGone> {
        let sock = self.socket(id)?;
        Ok(!matches!(
            sock.state(),
            State::Listen | State::SynReceived | State::SynSent
        ))
    }

    /// Half-close towards the application (FIN after queued data).
    pub fn tcp_close(&mut self, id: FlowId) -> Result<(), FlowGone> {
        self.socket(id)?.close();
        Ok(())
    }

    /// Reset the flow (refusal after accept, dial failure, upstream error).
    /// The RST goes out on the next [`Self::poll`].
    pub fn tcp_abort(&mut self, id: FlowId) -> Result<(), FlowGone> {
        self.socket(id)?.abort();
        self.stats.tcp_aborted += 1;
        Ok(())
    }

    /// Send a UDP datagram back to the application of flow `key` (as it was
    /// received: `key.src` is the application). Oversize replies are dropped.
    pub fn send_udp(&mut self, key: &FlowKey, payload: &[u8]) {
        let ip_hdr = if key.src.is_ipv4() {
            IPV4_HEADER_LEN
        } else {
            IPV6_HEADER_LEN
        };
        if ip_hdr + UDP_HEADER_LEN + payload.len() > self.cfg.mtu {
            self.stats.dropped_oversize += 1;
            return;
        }
        let pkt = build_udp(key.dst, key.src, payload);
        self.emit(pkt);
    }
}

/// Largest TCP payload the stack advertises for an IPv4/IPv6 flow at `mtu`.
pub fn mss_for(mtu: usize, v6: bool) -> usize {
    mtu - if v6 { IPV6_HEADER_LEN } else { IPV4_HEADER_LEN } - TCP_HEADER_LEN
}

// ---------------------------------------------------------------------------
// Device I/O

/// Packet device. `recv` must be cancel safe (it is raced against timers).
#[async_trait]
pub trait PacketIo: Send + Sync {
    async fn recv(&self) -> io::Result<Bytes>;
    async fn send(&self, pkt: Bytes) -> io::Result<()>;
}

#[async_trait]
impl PacketIo for segue_tun::TunEndpoint {
    async fn recv(&self) -> io::Result<Bytes> {
        self.poll_inbound()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))
    }

    async fn send(&self, pkt: Bytes) -> io::Result<()> {
        match self.push_outbound(pkt).await {
            Ok(())
            | Err(segue_tun::TunError::QueueFull)
            | Err(segue_tun::TunError::PacketTooLarge { .. }) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Routing

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// Dial through outbound `tag`, or directly (protected socket) for `None`.
    Dial(Option<String>),
    Refuse,
}

/// Decides new TUN flows. Called synchronously on the packet path.
pub trait TunRouter: Send + Sync {
    fn route_tcp(&self, key: &FlowKey) -> Route;
    /// Default: refuse (UDP relaying is a separate handler, §4.3).
    fn route_udp(&self, _key: &FlowKey) -> Route {
        Route::Refuse
    }
}

fn action_route(action: &Action) -> Route {
    match action {
        Action::Proxy(tag) => Route::Dial(Some(tag.clone())),
        Action::Direct => Route::Dial(None),
        Action::Reject => Route::Refuse,
    }
}

impl TunRouter for RuleSet {
    fn route_tcp(&self, key: &FlowKey) -> Route {
        action_route(self.decide(&TargetAddr::Ip(key.dst.ip())))
    }
}

/// Router for "policy not loaded": every flow is refused (§5.4).
pub struct RefuseAll;

impl TunRouter for RefuseAll {
    fn route_tcp(&self, _key: &FlowKey) -> Route {
        Route::Refuse
    }
}

/// Handle to answer a UDP flow.
#[derive(Clone)]
pub struct UdpReply {
    key: FlowKey,
    tx: mpsc::Sender<(FlowKey, Bytes)>,
}

impl UdpReply {
    /// Queue a datagram back to the application; false when the queue is
    /// full (dropped) or the stack is gone.
    pub fn send(&self, payload: Bytes) -> bool {
        self.tx.try_send((self.key, payload)).is_ok()
    }
}

/// Consumer of accepted UDP flows. Must not block (runs on the packet path).
pub trait UdpHandler: Send + Sync {
    fn datagram(&self, datagram: UdpDatagram, reply: UdpReply);
}

// ---------------------------------------------------------------------------
// Async driver

enum Up {
    Data(Bytes),
    Fin,
    Abort,
}

struct Pipe {
    down: Option<mpsc::Sender<Bytes>>,
    up: mpsc::Receiver<Up>,
    pending: Option<Bytes>,
    fin: bool,
    closed: bool,
}

/// TUN driver: device ↔ [`Netstack`] ↔ router/dialer.
pub struct TunStack {
    pub config: NetstackConfig,
    pub router: Arc<dyn TunRouter>,
    pub dialer: Arc<dyn Dialer>,
    pub udp: Option<Arc<dyn UdpHandler>>,
    pub dial_timeout: Duration,
}

impl TunStack {
    pub fn new(router: Arc<dyn TunRouter>, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            config: NetstackConfig::default(),
            router,
            dialer,
            udp: None,
            dial_timeout: Duration::from_secs(15),
        }
    }

    /// Run until the device fails or closes.
    pub async fn run(self, io: Arc<dyn PacketIo>) -> io::Result<()> {
        let mut stack = Netstack::new(self.config.clone(), Instant::now());
        let notify = Arc::new(Notify::new());
        let mut pipes: HashMap<FlowId, Pipe> = HashMap::new();
        let (udp_tx, mut udp_rx) = mpsc::channel::<(FlowKey, Bytes)>(self.config.udp_queue.max(1));
        let router = self.router.clone();
        let udp_enabled = self.udp.is_some();
        let mut policy = move |key: &FlowKey| {
            let route = match key.proto {
                Proto::Tcp => router.route_tcp(key),
                Proto::Udp if udp_enabled => router.route_udp(key),
                Proto::Udp => Route::Refuse,
            };
            match route {
                Route::Dial(tag) => Verdict::Accept(tag),
                Route::Refuse => Verdict::Refuse,
            }
        };
        let mut buf = vec![0u8; CHUNK];
        loop {
            let now = Instant::now();
            stack.poll(now);
            loop {
                while let Some(event) = stack.pop_event() {
                    match event {
                        Event::TcpAccepted { id, key, tag } => {
                            let (down_tx, down_rx) = mpsc::channel(RELAY_CHUNKS);
                            let (up_tx, up_rx) = mpsc::channel(RELAY_CHUNKS);
                            pipes.insert(
                                id,
                                Pipe {
                                    down: Some(down_tx),
                                    up: up_rx,
                                    pending: None,
                                    fin: false,
                                    closed: false,
                                },
                            );
                            tokio::spawn(relay(
                                self.dialer.clone(),
                                tag,
                                key,
                                self.dial_timeout,
                                down_rx,
                                up_tx,
                                notify.clone(),
                            ));
                        }
                        Event::TcpClosed { id, .. } => {
                            pipes.remove(&id);
                        }
                        Event::UdpClosed { .. } => {}
                    }
                }
                let mut progressed = false;
                for (id, pipe) in pipes.iter_mut() {
                    progressed |= pump(&mut stack, *id, pipe, &mut buf);
                }
                if !progressed {
                    break;
                }
                stack.poll(now);
            }
            while let Some(d) = stack.pop_udp() {
                if let Some(handler) = &self.udp {
                    let reply = UdpReply {
                        key: d.key,
                        tx: udp_tx.clone(),
                    };
                    handler.datagram(d, reply);
                }
            }
            while let Some(pkt) = stack.pop_output() {
                io.send(pkt).await?;
            }
            let delay = stack
                .poll_delay(now)
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1));
            tokio::select! {
                pkt = io.recv() => {
                    let pkt = pkt?;
                    stack.input(&pkt, Instant::now(), &mut policy);
                }
                Some((key, payload)) = udp_rx.recv() => {
                    stack.send_udp(&key, &payload);
                }
                _ = notify.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }
}

/// Move bytes between one flow's socket and its relay task. Returns whether
/// anything changed.
fn pump(stack: &mut Netstack, id: FlowId, pipe: &mut Pipe, buf: &mut [u8]) -> bool {
    let mut progressed = false;
    // Application → upstream.
    while let Some(tx) = &pipe.down {
        if tx.is_closed() {
            // The relay stopped taking upload bytes before the application
            // finished sending (dial failed or the site write failed): the
            // upload is truncated, so reset rather than let it look clean,
            // even if the site's FIN was already passed on.
            pipe.down = None;
            let _ = stack.tcp_abort(id);
            pipe.closed = true;
            return true;
        }
        match stack.tcp_recv_queue(id) {
            Ok(0) => {
                if stack.tcp_peer_finished(id).unwrap_or(true) {
                    pipe.down = None;
                    progressed = true;
                }
                break;
            }
            Ok(_) => {}
            Err(_) => return progressed,
        }
        let Ok(permit) = tx.try_reserve() else { break };
        let n = match stack.tcp_read(id, buf) {
            Ok(n) => n,
            Err(_) => return progressed,
        };
        if n == 0 {
            break;
        }
        permit.send(Bytes::copy_from_slice(&buf[..n]));
        progressed = true;
    }
    // Upstream → application.
    loop {
        if pipe.closed {
            break;
        }
        if let Some(mut data) = pipe.pending.take() {
            let n = stack.tcp_write(id, &data).unwrap_or(0);
            if n > 0 {
                progressed = true;
            }
            if n < data.len() {
                let _ = data.split_to(n);
                pipe.pending = Some(data);
                break;
            }
            continue;
        }
        if pipe.fin {
            let _ = stack.tcp_close(id);
            pipe.closed = true;
            progressed = true;
            break;
        }
        match pipe.up.try_recv() {
            Ok(Up::Data(data)) => pipe.pending = Some(data),
            Ok(Up::Fin) => pipe.fin = true,
            Ok(Up::Abort) | Err(mpsc::error::TryRecvError::Disconnected) => {
                let _ = stack.tcp_abort(id);
                pipe.closed = true;
                progressed = true;
                break;
            }
            Err(mpsc::error::TryRecvError::Empty) => break,
        }
    }
    progressed
}

/// Per-flow task: dial, then relay both directions with half-close.
async fn relay(
    dialer: Arc<dyn Dialer>,
    tag: Option<String>,
    key: FlowKey,
    dial_timeout: Duration,
    mut down: mpsc::Receiver<Bytes>,
    up: mpsc::Sender<Up>,
    notify: Arc<Notify>,
) {
    let target = TargetAddr::Ip(key.dst.ip());
    let dialed = tokio::time::timeout(
        dial_timeout,
        dialer.dial(tag.as_deref(), &target, key.dst.port()),
    )
    .await;
    let Ok(Ok(stream)) = dialed else {
        // Refused, never retried direct (§5.4).
        let _ = up.send(Up::Abort).await;
        notify.notify_one();
        return;
    };
    let (mut r, mut w) = tokio::io::split(stream);
    let abort = up.clone();
    let to_app = async {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let res = tokio::select! {
                res = r.read(&mut buf) => res,
                _ = up.closed() => return,
            };
            let msg = match res {
                Ok(0) => Up::Fin,
                Ok(n) => Up::Data(Bytes::copy_from_slice(&buf[..n])),
                Err(_) => Up::Abort,
            };
            let last = !matches!(msg, Up::Data(_));
            if up.send(msg).await.is_err() {
                return;
            }
            notify.notify_one();
            if last {
                return;
            }
        }
    };
    let to_site = async {
        while let Some(data) = down.recv().await {
            notify.notify_one();
            if w.write_all(&data).await.is_err() {
                let _ = abort.send(Up::Abort).await;
                notify.notify_one();
                return;
            }
        }
        let _ = w.shutdown().await;
    };
    tokio::join!(to_app, to_site);
}
