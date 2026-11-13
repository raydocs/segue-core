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
//!   prohibited or packet-too-big, rate limited). Everything here is testable
//!   without root.
//! * [`TunStack`] is the async driver: it pumps a [`PacketIo`] through a
//!   `Netstack`, asks a [`TunRouter`] what to do with each new flow, dials
//!   accepted TCP flows through the kernel [`Dialer`] (after sniffing the
//!   TLS SNI / HTTP Host when the router asks for it, D8), answers hijacked
//!   DNS (UDP and TCP port 53) with the kernel's [`SmartDns`] and relays UDP
//!   through [`Dialer::dial_udp`]. [`TunKernel`] is the router that applies
//!   exactly the SOCKS front end's decisions (fake-IP lookup, sniffing, UDP
//!   refusals for the home exit and QUIC), and [`TunStack::for_kernel`]
//!   wires all of it to one [`Kernel`]. Kill-switch posture lives in the
//!   kernel dialer, so TUN flows inherit it: a refused dial is a RST or an
//!   ICMP error, never a direct retry.
//! * Device I/O is the thin [`PacketIo`] trait. The engine's
//!   `segue_tun::TunEndpoint` implements it.
//!
//! Refusal semantics (§5.4): a refused flow never falls back to anything.
//! A refused SYN gets a RST, an accepted flow whose dial fails (or whose
//! sniffed name is rejected) is reset after the local handshake, a refused
//! UDP flow gets ICMP unreachable (port unreachable for QUIC to a bare IP,
//! §5.2a.2; administratively prohibited otherwise), and a UDP flow whose
//! relay fails is
//! answered with ICMP unreachable until it expires. Private, loopback and
//! link-local destinations that reach the TUN are refused before the router
//! is asked (DNS on port 53 excepted, which is answered locally when the
//! router hijacks it); multicast/broadcast/unspecified are dropped silently.
//!
//! Memory (§4.2). Per-flow TCP buffers are not reserved up front. All TCP
//! byte storage — smoltcp receive/transmit rings, relay chunks in flight,
//! sniff and DNS-over-TCP buffers — is charged to one [`BufferPool`] of 4 KiB
//! blocks (`NetstackConfig::buffer_pool`, 6 MiB by default):
//!
//! * a new flow is admitted only if the pool is under its 80 % high-water
//!   mark after charging the flow's 2-block minimum (1 receive, 1 transmit);
//!   otherwise the SYN is refused with a RST;
//! * a receive ring starts at 4 KiB, a transmit ring at zero; each doubles
//!   (up to `tcp_rx_buffer` / `tcp_tx_buffer`, 64 KiB max) when it is found
//!   full and the pool is under high water;
//! * relay chunks may use the pool up to 100 %, so the 20 % above high water
//!   is always left for moving bytes, and a flow that cannot get a chunk
//!   waits instead of failing. With a shared session pool (the kernel's)
//!   ring growth and admission stay in its elastic part and chunks use its
//!   relay region ([`segue_session::pool::Tier`]). A chunk is only made for
//!   a transfer that completes without waiting (r6 R5): uplink bytes are a
//!   copy of the receive ring's head, dequeued once the site took them (a
//!   site that would block keeps one byte, not a chunk); downlink chunks
//!   are cut to transmit ring room the stack published. No chunk is held
//!   across a wait on the network or the application, so a full pool still
//!   moves every flow;
//! * a flow idle for `buffer_idle` with empty rings drops both rings to zero
//!   bytes and its charge to the 2-block minimum.
//!
//! [`TunStack::memory_budget`] states the worst case for a configuration;
//! with the defaults it is 13 740 252 bytes ≈ 13.1 MiB: TCP pool 6 MiB,
//! 512 TCP flows × 4 KiB bookkeeping = 2 MiB, packet queues 1.5 MiB
//! ((512 out + 2 × 256 UDP + 1) × 1500), 256 UDP flows × 14 524 B
//! = 3.5 MiB (9 × 1500 queue and reply buffer, 1 KiB bookkeeping), 32 DNS
//! queries in flight 94 KiB (test
//! `default_memory_budget_is_well_under_20_mib`). QUIC keeps no
//! state of its own (§5.2a.2). The PR #14 layout reserved
//! 128 KiB per TCP flow up front: 64 MiB at 512 flows.
//! Outbound transport state (TLS/QUIC buffers inside the dialer) is not part
//! of the TUN budget.
//!
//! Timers: an established flow with no traffic for `tcp_idle_timeout` and a
//! flow stuck in a handshake or half-closed state (SYN-RECEIVED, FIN-WAIT-1/2,
//! CLOSING, LAST-ACK, CLOSE-WAIT) with no traffic for
//! `tcp_half_close_timeout` are reset, so dead peers cannot pin the flow
//! table. TIME-WAIT is not kept.
//!
//! Size limits. An inbound packet larger than the TUN MTU is answered with
//! ICMP "fragmentation needed" (IPv4 with DF) or ICMPv6 "packet too big",
//! carrying the MTU; IPv4 without DF is dropped (counted). A UDP datagram
//! larger than its relay can carry gets the same error with the relay's
//! limit (IPv6 only when that limit is at least 1280). Fragments are not
//! reassembled: IPv4 fragments and IPv6 packets with extension headers
//! (including the fragment header) are dropped and counted. TCP never
//! fragments because the advertised MSS is clamped to the MTU; applications
//! that send oversize UDP learn the MTU from the ICMP error. Replies larger
//! than the MTU are dropped, except DNS answers, which are truncated with TC
//! set so the client retries over TCP.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use segue_routing::TargetAddr;
use segue_session::pool::{Pool as SessionPool, Tier};
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
use tokio::sync::{mpsc, Notify, Semaphore};

use crate::dial::{Dialer, UdpSession};
use crate::dns::SmartDns;
use crate::policy::Policy;
use crate::quic::{looks_quic, looks_quic_first};
use crate::rules::{Action, RuleSet};
use crate::sniff::{sniff, Sniff};
use crate::socks::{Kernel, SniffSettings};

const TCP_HEADER_LEN: usize = 20;
/// Pool block size (§4.2).
pub const BLOCK: usize = 4096;
/// Most bytes moved per relay chunk between the stack and a flow task.
const CHUNK: usize = 16 * 1024;
/// Relay chunks buffered per direction per flow.
const RELAY_CHUNKS: usize = 4;
/// IPv6 minimum MTU; ICMPv6 errors must fit in it (RFC 4443 §2.4).
const IPV6_MIN_MTU: usize = 1280;
/// smoltcp's window scale is fixed when the socket is created (at 4 KiB, so
/// no scaling): a ring may not grow past what an unscaled window can offer.
const MAX_RING: usize = 64 * 1024;
const DNS_PORT: u16 = 53;
/// Budget for one TCP flow's bookkeeping outside the pool: socket struct,
/// flow-table entries, relay task, two channels (~3.1 KiB measured by the
/// unit test `per_flow_overhead_estimate_holds`, plus task header and
/// allocator slack).
const TCP_FLOW_OVERHEAD: usize = 4096;

fn blocks_for(bytes: usize) -> usize {
    bytes.div_ceil(BLOCK)
}

// ---------------------------------------------------------------------------
// Buffer pool (§4.2)

/// Bounded pool of 4 KiB blocks shared by every TCP flow of one stack. It is
/// an accounting pool: memory is allocated by the user of a [`Charge`] and
/// freed with it, and the pool bounds the total. With a shared session pool
/// (`NetstackConfig::shared_pool`) every block is also taken from that pool,
/// so TUN buffers and session buffers count against one process budget
/// (KERNEL_SPEC §6.3) and a flow waiting for blocks wakes when a session
/// returns some.
pub struct BufferPool {
    blocks: usize,
    high_water: usize,
    used: AtomicUsize,
    waiters: AtomicUsize,
    freed: Notify,
    shared: Option<Arc<SessionPool>>,
}

impl BufferPool {
    pub fn new(bytes: usize) -> Arc<Self> {
        Self::with_shared(bytes, None)
    }

    /// At most `bytes` for this stack, each block also charged to `shared`.
    pub fn with_shared(bytes: usize, shared: Option<Arc<SessionPool>>) -> Arc<Self> {
        let blocks = bytes / BLOCK;
        Arc::new(Self {
            blocks,
            high_water: blocks * 4 / 5,
            used: AtomicUsize::new(0),
            waiters: AtomicUsize::new(0),
            freed: Notify::new(),
            shared,
        })
    }

    pub fn capacity_bytes(&self) -> usize {
        self.blocks * BLOCK
    }

    pub fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed) * BLOCK
    }

    /// Take between `min` and `want` blocks while staying at or under `limit`
    /// (and within `tier` of the shared pool, if any).
    fn take(&self, want: usize, min: usize, limit: usize, tier: Tier) -> usize {
        let mut used = self.used.load(Ordering::Relaxed);
        let n = loop {
            let n = want.min(limit.saturating_sub(used));
            if n < min || n == 0 {
                return 0;
            }
            match self.used.compare_exchange_weak(
                used,
                used + n,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break n,
                Err(now) => used = now,
            }
        };
        let Some(shared) = &self.shared else {
            return n;
        };
        let got = shared.take_blocks(n, min.max(1), shared.limit(tier));
        if got < n {
            self.used.fetch_sub(n - got, Ordering::AcqRel);
        }
        got
    }

    fn give(&self, blocks: usize) {
        self.used.fetch_sub(blocks, Ordering::AcqRel);
        if let Some(shared) = &self.shared {
            // Wakes our waiters too: they wait on the shared pool.
            shared.give_blocks(blocks);
        } else if self.waiters.load(Ordering::Acquire) > 0 {
            self.freed.notify_waiters();
        }
    }

    /// Exactly `blocks` blocks, only while the pool stays under high water
    /// (admission and ring growth).
    pub fn charge(self: &Arc<Self>, blocks: usize) -> Option<Charge> {
        let n = self.take(blocks, blocks, self.high_water, Tier::Elastic);
        (n > 0).then(|| Charge {
            pool: self.clone(),
            blocks: n,
        })
    }

    /// 1..=`want` blocks for bytes in flight, using the whole pool.
    pub fn chunk(self: &Arc<Self>, want: usize) -> Option<Charge> {
        let n = self.take(want.max(1), 1, self.blocks, Tier::Relay);
        (n > 0).then(|| Charge {
            pool: self.clone(),
            blocks: n,
        })
    }

    /// Resolves when blocks are returned (or spuriously).
    async fn freed(&self) {
        if let Some(shared) = &self.shared {
            return shared.freed().await;
        }
        self.waiters.fetch_add(1, Ordering::AcqRel);
        let _waiting = Waiting(&self.waiters);
        self.freed.notified().await;
    }

    /// Like [`Self::chunk`], waiting for blocks to be freed.
    pub async fn chunk_wait(self: &Arc<Self>, want: usize) -> Charge {
        if let Some(shared) = &self.shared {
            return shared.wait_for(|| self.chunk(want)).await;
        }
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if let Some(c) = self.chunk(want) {
                return c;
            }
            self.waiters.fetch_add(1, Ordering::AcqRel);
            let _waiting = Waiting(&self.waiters);
            if let Some(c) = self.chunk(want) {
                return c;
            }
            freed.await;
        }
    }
}

struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Blocks charged to a [`BufferPool`]; returned on drop.
pub struct Charge {
    pool: Arc<BufferPool>,
    blocks: usize,
}

impl Charge {
    pub fn bytes(&self) -> usize {
        self.blocks * BLOCK
    }

    /// Grow to `blocks` under the pool's high-water mark.
    fn grow_to(&mut self, blocks: usize) -> bool {
        if blocks <= self.blocks {
            return true;
        }
        let extra = blocks - self.blocks;
        if self
            .pool
            .take(extra, extra, self.pool.high_water, Tier::Elastic)
            == 0
        {
            return false;
        }
        self.blocks = blocks;
        true
    }

    fn shrink_to(&mut self, blocks: usize) {
        if blocks < self.blocks {
            self.pool.give(self.blocks - blocks);
            self.blocks = blocks;
        }
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        if self.blocks > 0 {
            self.pool.give(self.blocks);
        }
    }
}

impl std::fmt::Debug for Charge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Charge({} blocks)", self.blocks)
    }
}

/// Bytes in flight between the stack and a relay task, with their charge.
struct Chunk {
    data: Bytes,
    /// Returned when the chunk is dropped.
    _charge: Charge,
}

impl Chunk {
    fn new(data: Bytes, charge: Charge) -> Self {
        debug_assert!(data.len() <= charge.bytes());
        Self {
            data,
            _charge: charge,
        }
    }

    fn advance(&mut self, n: usize) {
        let _ = self.data.split_to(n);
    }
}

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
    /// (`None` = direct or decided later).
    Accept(Option<String>),
    /// [`Verdict::Accept`] for ordinary UDP only: the first later datagram
    /// that looks like QUIC ([`looks_quic`]) refuses the flow with ICMP
    /// port unreachable, it and every datagram after it (§5.2a.2). For TCP
    /// the same as `Accept`.
    AcceptPlain(Option<String>),
    /// Answered inside the process (hijacked DNS). Exempt from the
    /// reserved-destination refusal; UDP gets no flow-table entry.
    Local,
    Refuse,
    /// Refuse a UDP flow with ICMP port unreachable rather than
    /// "administratively prohibited": QUIC to a destination whose name is
    /// not known for certain (§5.2a.2). An app that honours ICMP on its
    /// (connected) socket gets ECONNREFUSED at once and may try TCP; one
    /// that ignores it times out. For TCP the same as `Refuse`.
    Unreachable,
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

/// One received UDP datagram for an accepted (or local) flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram {
    pub key: FlowKey,
    pub tag: Option<String>,
    /// Answered locally ([`Verdict::Local`]): no flow-table entry exists.
    pub local: bool,
    pub payload: Bytes,
}

#[derive(Clone, Debug)]
pub struct NetstackConfig {
    /// TUN MTU. Bounds inbound packets, outbound packets and the MSS the
    /// stack advertises (MTU minus IP and TCP headers).
    pub mtu: usize,
    /// Address of the TUN interface itself; used as the source of ICMP
    /// errors and as the stack's own address for any-IP routing. Must lie
    /// outside the fake-IP range (default 198.18.0.0/15), or the pool could
    /// hand the interface's own address to a name.
    pub v4_addr: Ipv4Addr,
    pub v6_addr: Ipv6Addr,
    pub max_tcp_flows: usize,
    /// Largest receive / transmit ring per flow (grown lazily, ≤ 64 KiB).
    pub tcp_rx_buffer: usize,
    pub tcp_tx_buffer: usize,
    /// Pool shared by every flow's TCP buffers and relay chunks (§4.2).
    pub buffer_pool: usize,
    /// Process-wide pool the TUN blocks are also charged to, shared with the
    /// session layer (KERNEL_SPEC §6.3: one budget). `None`: standalone.
    pub shared_pool: Option<Arc<SessionPool>>,
    /// Abort a TCP flow when sent data stays unacknowledged this long.
    pub tcp_timeout: Duration,
    /// Reset an established flow with no traffic for this long.
    pub tcp_idle_timeout: Duration,
    /// Reset a flow in a handshake or half-closed state with no traffic for
    /// this long (FIN-WAIT-2 and friends).
    pub tcp_half_close_timeout: Duration,
    /// Release the buffers of a flow with no traffic for this long.
    pub buffer_idle: Duration,
    pub max_udp_flows: usize,
    pub udp_idle_timeout: Duration,
    /// Received UDP datagrams awaiting the driver; oldest dropped first.
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
            v4_addr: Ipv4Addr::new(172, 19, 0, 1),
            v6_addr: Ipv6Addr::new(0xfd00, 0x5e9e, 0, 0, 0, 0, 0, 1),
            max_tcp_flows: 512,
            tcp_rx_buffer: 64 * 1024,
            tcp_tx_buffer: 64 * 1024,
            buffer_pool: 6 * 1024 * 1024,
            shared_pool: None,
            tcp_timeout: Duration::from_secs(120),
            tcp_idle_timeout: Duration::from_secs(30 * 60),
            tcp_half_close_timeout: Duration::from_secs(60),
            buffer_idle: Duration::from_secs(10),
            max_udp_flows: 256,
            udp_idle_timeout: Duration::from_secs(60),
            udp_queue: 256,
            out_queue: 512,
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
    pub tcp_refused_memory: u64,
    pub tcp_rst_stale: u64,
    pub tcp_aborted: u64,
    pub tcp_idle_timeouts: u64,
    pub tcp_half_close_timeouts: u64,
    pub buffers_released: u64,
    pub udp_refused_policy: u64,
    pub udp_refused_reserved: u64,
    pub udp_refused_full: u64,
    pub udp_refused_upstream: u64,
    /// UDP flows refused as QUIC to a destination whose name is not known
    /// for certain (§5.2a.2): at the first datagram, or later on a flow
    /// admitted as ordinary UDP.
    pub udp_refused_quic: u64,
    pub icmp_sent: u64,
    pub icmp_too_big: u64,
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

/// Which ICMP error to synthesize.
#[derive(Clone, Copy, Debug)]
enum IcmpError {
    /// Destination unreachable, administratively prohibited (§5.4).
    Prohibited,
    /// Destination (port) unreachable: QUIC refused (§5.2a.2).
    PortUnreachable,
    /// IPv4 "fragmentation needed and DF set" / ICMPv6 "packet too big",
    /// carrying the largest packet that fits (RFC 1191, RFC 8201).
    TooBig(usize),
}

/// ICMP error quoting the offending packet. `pkt` is the original packet,
/// already parsed.
fn build_icmp_error(
    own: IpAddr,
    pkt: &[u8],
    parsed: &Parsed<'_>,
    kind: IcmpError,
) -> Option<Vec<u8>> {
    let client = parsed.key.src.ip();
    match (own, client) {
        (IpAddr::V4(own), IpAddr::V4(_)) => {
            let orig = Ipv4Repr::parse(&Ipv4Packet::new_unchecked(pkt), &checksums()).ok()?;
            let data = &parsed.ip_payload[..parsed.ip_payload.len().min(8)];
            let reason = match kind {
                IcmpError::Prohibited => Icmpv4DstUnreachable::CommProhibited,
                IcmpError::PortUnreachable => Icmpv4DstUnreachable::PortUnreachable,
                IcmpError::TooBig(_) => Icmpv4DstUnreachable::FragRequired,
            };
            let repr = Icmpv4Repr::DstUnreachable {
                reason,
                header: orig,
                data,
            };
            Some(build_ip(
                IpAddr::V4(own),
                client,
                IpProtocol::Icmp,
                repr.buffer_len(),
                |b| {
                    let mut icmp = Icmpv4Packet::new_unchecked(b);
                    repr.emit(&mut icmp, &checksums());
                    if let IcmpError::TooBig(mtu) = kind {
                        // Next-hop MTU lives in the second half of the
                        // otherwise unused word (RFC 1191 §4).
                        let mtu = u16::try_from(mtu).unwrap_or(u16::MAX);
                        let raw = icmp.into_inner();
                        raw[6..8].copy_from_slice(&mtu.to_be_bytes());
                        Icmpv4Packet::new_unchecked(raw).fill_checksum();
                    }
                },
            ))
        }
        (IpAddr::V6(own), IpAddr::V6(dst)) => {
            let orig = Ipv6Repr::parse(&Ipv6Packet::new_unchecked(pkt)).ok()?;
            // ICMPv6 header (8) + quoted IPv6 header (40) + data, in 1280.
            let room = IPV6_MIN_MTU - IPV6_HEADER_LEN - 8 - IPV6_HEADER_LEN;
            let data = &parsed.ip_payload[..parsed.ip_payload.len().min(room)];
            let repr = match kind {
                IcmpError::Prohibited => Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::AdminProhibit,
                    header: orig,
                    data,
                },
                IcmpError::PortUnreachable => Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: orig,
                    data,
                },
                IcmpError::TooBig(mtu) => Icmpv6Repr::PktTooBig {
                    mtu: mtu as u32,
                    header: orig,
                    data,
                },
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

/// Fit a DNS response into `max` bytes: keep the header and question, drop
/// every record and set TC so the client retries over TCP (RFC 1035 §4.2.1).
fn truncate_dns(msg: &[u8], max: usize) -> Option<Vec<u8>> {
    if msg.len() <= max {
        return Some(msg.to_vec());
    }
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let mut at = 12;
    for _ in 0..qd {
        loop {
            let len = *msg.get(at)? as usize;
            if len & 0xc0 == 0xc0 {
                at += 2;
                break;
            }
            at += 1 + len;
            if len == 0 {
                break;
            }
        }
        at += 4;
    }
    let keep = if at <= max.min(msg.len()) { at } else { 12 };
    let mut out = msg[..keep].to_vec();
    out[2] |= 0x02;
    if keep == 12 {
        out[4..6].fill(0);
    }
    out[6..12].fill(0);
    Some(out)
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
    /// Covers both rings; never below the 2-block admission minimum.
    charge: Charge,
    rx_cap: usize,
    tx_cap: usize,
    /// Bytes read since the receive ring last grew: a ring that turned over
    /// completely is the flow's bottleneck and doubles.
    rx_moved: usize,
    last_activity: Instant,
}

struct UdpEntry {
    tag: Option<String>,
    last_seen: Instant,
    /// Refused (the relay failed, or QUIC on a plain flow): answer with
    /// this ICMP until the flow expires.
    refused: Option<IcmpError>,
    /// Ordinary UDP only ([`Verdict::AcceptPlain`]).
    plain: bool,
    /// Largest payload the relay can carry, once known.
    limit: Option<usize>,
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

/// Blocks a flow holds for its rings. An empty ring still keeps one block
/// reserved, so a ring released while idle always comes back without
/// asking the pool (and the receive window never stays closed).
fn ring_blocks(rx: usize, tx: usize) -> usize {
    blocks_for(rx).max(1) + blocks_for(tx).max(1)
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
    /// Latest time passed to `input` / `poll`.
    now: Instant,
    pool: Arc<BufferPool>,
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
        let pool = BufferPool::with_shared(cfg.buffer_pool, cfg.shared_pool.clone());
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
            now,
            pool,
            stats: NetstackStats::default(),
        }
    }

    pub fn config(&self) -> &NetstackConfig {
        &self.cfg
    }

    pub fn stats(&self) -> &NetstackStats {
        &self.stats
    }

    /// The pool every TCP buffer of this stack is charged to.
    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    pub fn tcp_flows(&self) -> usize {
        self.tcp.len()
    }

    pub fn udp_flows(&self) -> usize {
        self.udp.len()
    }

    /// The flow is in the table (TCP or UDP).
    pub fn has_flow(&self, key: &FlowKey) -> bool {
        match key.proto {
            Proto::Tcp => self.tcp.contains_key(key),
            Proto::Udp => self.udp.contains_key(key),
        }
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

    fn emit_icmp(&mut self, pkt: &[u8], parsed: &Parsed<'_>, now: Instant, kind: IcmpError) {
        if reserved_dst(parsed.key.dst.ip()) == Some(ReservedDst::Silent) {
            return;
        }
        if !self.icmp.take(now) {
            self.stats.icmp_suppressed += 1;
            return;
        }
        let own = match parsed.key.src {
            SocketAddr::V4(_) => IpAddr::V4(self.cfg.v4_addr),
            SocketAddr::V6(_) => IpAddr::V6(self.cfg.v6_addr),
        };
        if let Some(reply) = build_icmp_error(own, pkt, parsed, kind) {
            self.stats.icmp_sent += 1;
            if matches!(kind, IcmpError::TooBig(_)) {
                self.stats.icmp_too_big += 1;
            }
            self.emit(reply);
        }
    }

    /// Feed one packet read from the TUN. `policy` is asked once per new flow
    /// (TCP SYN or first UDP datagram) after the built-in checks.
    pub fn input(&mut self, pkt: &[u8], now: Instant, policy: &mut dyn FnMut(&FlowKey) -> Verdict) {
        self.input_with(pkt, now, &mut |k: &FlowKey, _: &[u8]| policy(k))
    }

    /// [`Self::input`], with the policy also seeing the first UDP datagram's
    /// payload (empty for TCP).
    pub fn input_with(
        &mut self,
        pkt: &[u8],
        now: Instant,
        policy: &mut dyn FnMut(&FlowKey, &[u8]) -> Verdict,
    ) {
        self.stats.packets_in += 1;
        self.now = now;
        let oversize = pkt.len() > self.cfg.mtu;
        let parsed = match parse(pkt) {
            Ok(p) => p,
            Err(e) => {
                match e {
                    _ if oversize => self.stats.dropped_oversize += 1,
                    Reject::Malformed => self.stats.dropped_malformed += 1,
                    Reject::Fragment => self.stats.dropped_fragment += 1,
                    Reject::Unsupported => self.stats.dropped_unsupported += 1,
                }
                return;
            }
        };
        if oversize {
            // Tell the sender the MTU instead of silently black-holing it
            // (RFC 1191 / RFC 8201). IPv4 without DF may be fragmented by
            // the sender's stack; we do not reassemble, so it is dropped.
            self.stats.dropped_oversize += 1;
            let df = parsed.key.src.is_ipv6() || Ipv4Packet::new_unchecked(pkt).dont_frag();
            if df {
                self.emit_icmp(pkt, &parsed, now, IcmpError::TooBig(self.cfg.mtu));
            }
            return;
        }
        match parsed.l4 {
            L4::Tcp(meta) => self.input_tcp(pkt, &parsed.key, meta, now, &mut |k: &FlowKey| {
                policy(k, &[])
            }),
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
        if let Some(entry) = self.tcp.get_mut(key) {
            entry.last_activity = now;
            let id = entry.id;
            // A ring released while idle comes back before its data.
            self.ensure_rx(id);
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
        let mut verdict = None;
        match reserved_dst(key.dst.ip()) {
            Some(ReservedDst::Silent) => {
                self.stats.dropped_silent_dst += 1;
                return;
            }
            Some(ReservedDst::Refuse) => {
                // DNS to a LAN resolver is answered locally when hijacked.
                let v = (key.dst.port() == DNS_PORT).then(|| policy(key));
                if v != Some(Verdict::Local) {
                    self.stats.tcp_refused_reserved += 1;
                    self.emit(build_rst(key, &meta));
                    return;
                }
                verdict = v;
            }
            None => {}
        }
        if self.tcp.len() >= self.cfg.max_tcp_flows {
            self.stats.tcp_refused_full += 1;
            self.emit(build_rst(key, &meta));
            return;
        }
        let tag = match verdict.unwrap_or_else(|| policy(key)) {
            Verdict::Accept(tag) | Verdict::AcceptPlain(tag) => tag,
            Verdict::Local => None,
            Verdict::Refuse | Verdict::Unreachable => {
                self.stats.tcp_refused_policy += 1;
                self.emit(build_rst(key, &meta));
                return;
            }
        };
        // §4.2: admission needs the 2-block minimum under high water.
        let Some(charge) = self.pool.charge(2) else {
            self.stats.tcp_refused_memory += 1;
            self.emit(build_rst(key, &meta));
            return;
        };
        let rx_cap = BLOCK.min(self.max_rx());
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; rx_cap]),
            tcp::SocketBuffer::new(Vec::new()),
        );
        sock.set_nagle_enabled(false);
        // Armed by `expire_tcp` only while data is unacknowledged.
        sock.set_timeout(None);
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
        self.tcp.insert(
            *key,
            TcpEntry {
                id,
                handle,
                charge,
                rx_cap,
                tx_cap: 0,
                rx_moved: 0,
                last_activity: now,
            },
        );
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
        policy: &mut dyn FnMut(&FlowKey, &[u8]) -> Verdict,
    ) {
        let key = parsed.key;
        let tag = if let Some(entry) = self.udp.get_mut(&key) {
            if let Some(kind) = entry.refused {
                self.emit_icmp(pkt, parsed, now, kind);
                return;
            }
            entry.last_seen = now;
            if entry.plain && looks_quic(&payload) {
                // QUIC on a flow admitted as ordinary UDP: refuse it, now
                // and for the rest of its life, and end its relay.
                entry.refused = Some(IcmpError::PortUnreachable);
                self.stats.udp_refused_quic += 1;
                self.events.push_back(Event::UdpClosed { key });
                self.emit_icmp(pkt, parsed, now, IcmpError::PortUnreachable);
                return;
            }
            if let Some(limit) = entry.limit.filter(|l| payload.len() > *l) {
                self.stats.dropped_oversize += 1;
                let hdr = parsed.ip_header_len + UDP_HEADER_LEN;
                if key.src.is_ipv4() || limit + hdr >= IPV6_MIN_MTU {
                    self.emit_icmp(pkt, parsed, now, IcmpError::TooBig(limit + hdr));
                }
                return;
            }
            entry.tag.clone()
        } else {
            let mut verdict = None;
            match reserved_dst(key.dst.ip()) {
                Some(ReservedDst::Silent) => {
                    self.stats.dropped_silent_dst += 1;
                    return;
                }
                Some(ReservedDst::Refuse) => {
                    let v = (key.dst.port() == DNS_PORT).then(|| policy(&key, &payload));
                    if v != Some(Verdict::Local) {
                        self.stats.udp_refused_reserved += 1;
                        self.emit_icmp(pkt, parsed, now, IcmpError::Prohibited);
                        return;
                    }
                    verdict = v;
                }
                None => {}
            }
            let verdict = match verdict {
                Some(v) => v,
                None => {
                    if self.udp.len() >= self.cfg.max_udp_flows {
                        self.sweep_udp(now);
                    }
                    if self.udp.len() >= self.cfg.max_udp_flows && key.dst.port() != DNS_PORT {
                        self.stats.udp_refused_full += 1;
                        self.emit_icmp(pkt, parsed, now, IcmpError::Prohibited);
                        return;
                    }
                    policy(&key, &payload)
                }
            };
            let plain = matches!(verdict, Verdict::AcceptPlain(_));
            match verdict {
                Verdict::Local => {
                    self.push_udp(UdpDatagram {
                        key,
                        tag: None,
                        local: true,
                        payload,
                    });
                    return;
                }
                Verdict::Accept(_) | Verdict::AcceptPlain(_)
                    if self.udp.len() >= self.cfg.max_udp_flows =>
                {
                    self.stats.udp_refused_full += 1;
                    self.emit_icmp(pkt, parsed, now, IcmpError::Prohibited);
                    return;
                }
                Verdict::Accept(tag) | Verdict::AcceptPlain(tag) => {
                    self.udp.insert(
                        key,
                        UdpEntry {
                            tag: tag.clone(),
                            last_seen: now,
                            refused: None,
                            plain,
                            limit: None,
                        },
                    );
                    tag
                }
                Verdict::Unreachable => {
                    self.stats.udp_refused_quic += 1;
                    self.emit_icmp(pkt, parsed, now, IcmpError::PortUnreachable);
                    return;
                }
                Verdict::Refuse => {
                    self.stats.udp_refused_policy += 1;
                    self.emit_icmp(pkt, parsed, now, IcmpError::Prohibited);
                    return;
                }
            }
        };
        self.push_udp(UdpDatagram {
            key,
            tag,
            local: false,
            payload,
        });
    }

    fn push_udp(&mut self, d: UdpDatagram) {
        if self.cfg.udp_queue == 0 {
            self.stats.dropped_udp_queue_full += 1;
            return;
        }
        if self.udp_rx.len() >= self.cfg.udp_queue {
            self.udp_rx.pop_front();
            self.stats.dropped_udp_queue_full += 1;
        }
        self.udp_rx.push_back(d);
    }

    fn feed(&mut self, pkt: &[u8], now: Instant) {
        self.dev.rx = Some(pkt.to_vec());
        self.poll(now);
    }

    /// Run the TCP stack's timers and transmit whatever is due; reap dead
    /// flows. Call after socket reads/writes and when [`Self::poll_delay`]
    /// expires.
    pub fn poll(&mut self, now: Instant) {
        self.now = now;
        // Before the interface runs, so the RSTs of flows reset here go out
        // now and the flows are reaped below.
        self.expire_tcp(now);
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

    /// Idle and half-close timeouts, and releasing idle buffers.
    fn expire_tcp(&mut self, now: Instant) {
        let (idle, half, release) = (
            self.cfg.tcp_idle_timeout,
            self.cfg.tcp_half_close_timeout,
            self.cfg.buffer_idle,
        );
        let unacked: smoltcp::time::Duration = self.cfg.tcp_timeout.into();
        for entry in self.tcp.values_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(entry.handle);
            // smoltcp's timeout counts from the last segment received, also
            // on a quiet flow with nothing in flight: arm it only while data
            // waits for an ACK (smoltcp restarts the count when data is
            // queued on an empty ring). Unacked SYN/FIN are covered by the
            // half-close timeout below.
            let armed = sock.send_queue() > 0;
            if armed != sock.timeout().is_some() {
                sock.set_timeout(armed.then_some(unacked));
            }
            let quiet = now.saturating_duration_since(entry.last_activity);
            if quiet < release.min(half).min(idle) {
                continue;
            }
            match sock.state() {
                State::SynReceived
                | State::FinWait1
                | State::FinWait2
                | State::Closing
                | State::LastAck
                | State::CloseWait
                    if quiet >= half =>
                {
                    sock.abort();
                    self.stats.tcp_half_close_timeouts += 1;
                    continue;
                }
                State::Established if quiet >= idle => {
                    sock.abort();
                    self.stats.tcp_idle_timeouts += 1;
                    continue;
                }
                _ => {}
            }
            if quiet >= release
                && (entry.rx_cap > 0 || entry.tx_cap > 0)
                && sock.recv_queue() == 0
                && sock.send_queue() == 0
                && sock.resize_recv_buffer(0)
                && sock.resize_send_buffer(0)
            {
                entry.rx_cap = 0;
                entry.tx_cap = 0;
                entry.charge.shrink_to(2);
                self.stats.buffers_released += 1;
            }
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

    fn max_rx(&self) -> usize {
        self.cfg.tcp_rx_buffer.clamp(BLOCK, MAX_RING)
    }

    fn max_tx(&self) -> usize {
        self.cfg.tcp_tx_buffer.clamp(BLOCK, MAX_RING)
    }

    fn entry(&mut self, id: FlowId) -> Result<&mut TcpEntry, FlowGone> {
        let key = self.ids.get(&id).ok_or(FlowGone::Gone)?;
        self.tcp.get_mut(key).ok_or(FlowGone::Gone)
    }

    fn socket(&mut self, id: FlowId) -> Result<&mut tcp::Socket<'static>, FlowGone> {
        let handle = self.entry(id)?.handle;
        Ok(self.sockets.get_mut::<tcp::Socket>(handle))
    }

    /// Resize one flow's rings, charging the pool. Growth beyond the
    /// admission minimum only happens under the high-water mark.
    fn resize(&mut self, id: FlowId, rx: usize, tx: usize) -> bool {
        let Some(key) = self.ids.get(&id) else {
            return false;
        };
        let Some(entry) = self.tcp.get_mut(key) else {
            return false;
        };
        let need = ring_blocks(rx, tx);
        if !entry.charge.grow_to(need) {
            return false;
        }
        let sock = self.sockets.get_mut::<tcp::Socket>(entry.handle);
        let ok = (rx == entry.rx_cap || sock.resize_recv_buffer(rx))
            && (tx == entry.tx_cap || sock.resize_send_buffer(tx));
        entry.rx_cap = sock.recv_capacity();
        entry.tx_cap = sock.send_capacity();
        entry
            .charge
            .shrink_to(ring_blocks(entry.rx_cap, entry.tx_cap));
        ok
    }

    /// Give a ring released while idle its first block back (always within
    /// the flow's reservation).
    fn ensure_rx(&mut self, id: FlowId) {
        if let Ok(e) = self.entry(id) {
            if e.rx_cap == 0 {
                let tx = e.tx_cap;
                self.resize(id, BLOCK, tx);
            }
        }
    }

    /// (receive ring, transmit ring) capacity of a flow.
    pub fn tcp_buffers(&mut self, id: FlowId) -> Result<(usize, usize), FlowGone> {
        let e = self.entry(id)?;
        Ok((e.rx_cap, e.tx_cap))
    }

    /// Bytes the application sent that are ready to be read.
    pub fn tcp_recv_queue(&mut self, id: FlowId) -> Result<usize, FlowGone> {
        Ok(self.socket(id)?.recv_queue())
    }

    /// Read application bytes. Returns 0 when nothing is buffered.
    pub fn tcp_read(&mut self, id: FlowId, buf: &mut [u8]) -> Result<usize, FlowGone> {
        let (rx, tx) = self.tcp_buffers(id)?;
        let queued = self.socket(id)?.recv_queue();
        let moved = self.entry(id)?.rx_moved;
        if rx > 0 && rx < self.max_rx() && (queued * 2 >= rx || moved >= rx) {
            // The window was mostly used, or turned over: offer more before
            // reading frees it.
            if self.resize(id, (rx * 2).min(self.max_rx()), tx) {
                self.entry(id)?.rx_moved = 0;
            }
        }
        let sock = self.socket(id)?;
        if !sock.can_recv() {
            return Ok(0);
        }
        let n = sock.recv_slice(buf).map_err(|_| FlowGone::Gone)?;
        if n > 0 {
            let now = self.now;
            let e = self.entry(id)?;
            e.last_activity = now;
            e.rx_moved += n;
        }
        Ok(n)
    }

    /// Copy the first `buf.len()` bytes the application sent without
    /// taking them off the receive ring (they leave it with
    /// [`tcp_consume`](Self::tcp_consume) once delivered upstream, r6 R5).
    pub fn tcp_peek(&mut self, id: FlowId, buf: &mut [u8]) -> Result<usize, FlowGone> {
        let (rx, tx) = self.tcp_buffers(id)?;
        let queued = self.socket(id)?.recv_queue();
        let moved = self.entry(id)?.rx_moved;
        if rx > 0 && rx < self.max_rx() && (queued * 2 >= rx || moved >= rx) {
            // The window was mostly used, or turned over: offer more.
            if self.resize(id, (rx * 2).min(self.max_rx()), tx) {
                self.entry(id)?.rx_moved = 0;
            }
        }
        self.socket(id)?.peek_slice(buf).map_err(|_| FlowGone::Gone)
    }

    /// Drop `n` delivered bytes from the front of the receive ring.
    pub fn tcp_consume(&mut self, id: FlowId, n: usize) -> Result<usize, FlowGone> {
        let sock = self.socket(id)?;
        let mut done = 0;
        while done < n && sock.recv_queue() > 0 {
            let want = n - done;
            match sock.recv(|b| {
                let k = b.len().min(want);
                (k, k)
            }) {
                Ok(0) | Err(_) => break,
                Ok(k) => done += k,
            }
        }
        if done > 0 {
            let now = self.now;
            let e = self.entry(id)?;
            e.last_activity = now;
            e.rx_moved += done;
        }
        Ok(done)
    }

    /// Free transmit ring space for bytes towards the application, growing
    /// the ring (doubling, under high water) when it is half full; a
    /// released ring gets its reserved block back.
    pub fn tcp_tx_room(&mut self, id: FlowId) -> Result<usize, FlowGone> {
        self.ensure_rx(id);
        let (rx, tx) = self.tcp_buffers(id)?;
        let sock = self.socket(id)?;
        if !sock.may_send() {
            return Ok(0);
        }
        let queue = sock.send_queue();
        if (tx == 0 || queue * 2 >= tx) && tx < self.max_tx() {
            let want = (tx * 2).clamp(BLOCK, self.max_tx());
            if !self.resize(id, rx, want) && tx == 0 {
                // The reservation always covers one block each way.
                self.resize(id, rx, BLOCK);
            }
        }
        let tx = self.tcp_buffers(id)?.1;
        Ok(tx.saturating_sub(self.socket(id)?.send_queue()))
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

    /// Room for bytes towards the application, counting what the transmit
    /// ring may still grow to.
    pub fn tcp_send_capacity(&mut self, id: FlowId) -> Result<usize, FlowGone> {
        let max = self.max_tx();
        let sock = self.socket(id)?;
        if !sock.may_send() {
            return Ok(0);
        }
        Ok(max.saturating_sub(sock.send_queue()))
    }

    /// Queue bytes towards the application; returns how many were taken.
    pub fn tcp_write(&mut self, id: FlowId, data: &[u8]) -> Result<usize, FlowGone> {
        self.ensure_rx(id);
        let (rx, tx) = self.tcp_buffers(id)?;
        let sock = self.socket(id)?;
        if !sock.may_send() {
            return Ok(0);
        }
        let queue = sock.send_queue();
        if data.len() > tx - queue && tx < self.max_tx() {
            // Double, or straight to what this write needs.
            let need = blocks_for(queue + data.len()) * BLOCK;
            let want = (tx * 2).max(need).clamp(BLOCK, self.max_tx());
            if !self.resize(id, rx, want) && tx == 0 {
                // The reservation always covers one block each way.
                self.resize(id, rx, BLOCK);
            }
        }
        let n = self
            .socket(id)?
            .send_slice(data)
            .map_err(|_| FlowGone::Gone)?;
        if n > 0 {
            self.entry(id)?.last_activity = self.now;
        }
        Ok(n)
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
        self.ensure_rx(id);
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

    /// Largest UDP payload a reply to `key` can carry inside the MTU.
    pub fn max_udp_reply(&self, key: &FlowKey) -> usize {
        let ip_hdr = if key.src.is_ipv4() {
            IPV4_HEADER_LEN
        } else {
            IPV6_HEADER_LEN
        };
        self.cfg.mtu.saturating_sub(ip_hdr + UDP_HEADER_LEN)
    }

    /// Send a UDP datagram back to the application of flow `key` (as it was
    /// received: `key.src` is the application). Oversize replies are dropped.
    pub fn send_udp(&mut self, key: &FlowKey, payload: &[u8]) {
        if payload.len() > self.max_udp_reply(key) {
            self.stats.dropped_oversize += 1;
            return;
        }
        if let Some(e) = self.udp.get_mut(key) {
            e.last_seen = self.now;
        }
        let pkt = build_udp(key.dst, key.src, payload);
        self.emit(pkt);
    }

    /// The relay of a UDP flow failed (refused, never retried direct): its
    /// datagrams are answered with ICMP until the flow expires.
    pub fn udp_refuse(&mut self, key: &FlowKey) {
        if let Some(e) = self.udp.get_mut(key) {
            if e.refused.is_none() {
                e.refused = Some(IcmpError::Prohibited);
                self.stats.udp_refused_upstream += 1;
            }
        }
    }

    /// Largest payload the relay of a UDP flow carries; bigger datagrams get
    /// a packet-too-big error.
    pub fn udp_set_limit(&mut self, key: &FlowKey, max_payload: usize) {
        if let Some(e) = self.udp.get_mut(key) {
            e.limit = Some(max_payload);
        }
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

/// Where an accepted flow goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dial {
    /// Outbound tag, or `None` for direct (protected socket).
    pub tag: Option<String>,
    /// What to dial: the destination IP, or a name (fake-IP, sniffed SNI).
    pub target: TargetAddr,
}

impl Dial {
    fn from_action(action: &Action, target: TargetAddr) -> Option<Self> {
        match action {
            Action::Reject => None,
            Action::Direct => Some(Self { tag: None, target }),
            Action::Proxy(tag) => Some(Self {
                tag: Some(tag.clone()),
                target,
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub enum TcpRoute {
    Dial(Dial),
    /// Complete the handshake, peek at the first bytes for a TLS SNI / HTTP
    /// Host, then ask [`TunRouter::sniffed`] (§5.2a).
    Sniff(SniffSettings),
    /// DNS over TCP, answered by the stack's [`SmartDns`].
    Dns,
    Refuse,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpRoute {
    /// Anything, QUIC included: the destination's name is known for certain
    /// (fake IP), and the flow stays on this outbound for its life.
    Dial(Dial),
    /// Ordinary UDP only (a bare IP, §5.2a.2): UDP/443 or a first datagram
    /// that looks like QUIC is refused with ICMP port unreachable at once,
    /// and so is the flow at the first later datagram that does.
    Plain(Dial),
    /// Answered by the stack's [`SmartDns`].
    Dns,
    Refuse,
}

/// Decides new TUN flows. Called synchronously on the packet path.
pub trait TunRouter: Send + Sync {
    fn route_tcp(&self, key: &FlowKey) -> TcpRoute;
    /// After [`TcpRoute::Sniff`]: what sniffing found (final:
    /// [`Sniff::NeedMore`] means the deadline or `max_bytes` came first).
    /// `None` refuses (the flow is reset after its handshake).
    fn sniffed(&self, _key: &FlowKey, _found: &Sniff) -> Option<Dial> {
        None
    }
    /// Default: refuse.
    fn route_udp(&self, _key: &FlowKey) -> UdpRoute {
        UdpRoute::Refuse
    }
}

fn ip_route(rules: &RuleSet, key: &FlowKey) -> Option<Dial> {
    let target = TargetAddr::Ip(key.dst.ip());
    Dial::from_action(rules.decide(&target), target)
}

/// IP rules only; UDP refused.
impl TunRouter for RuleSet {
    fn route_tcp(&self, key: &FlowKey) -> TcpRoute {
        ip_route(self, key).map_or(TcpRoute::Refuse, TcpRoute::Dial)
    }
}

/// Router for "policy not loaded": every flow is refused (§5.4).
pub struct RefuseAll;

impl TunRouter for RefuseAll {
    fn route_tcp(&self, _key: &FlowKey) -> TcpRoute {
        TcpRoute::Refuse
    }
}

/// The kernel's routing for TUN flows: the same decisions the SOCKS front
/// end makes, read from the kernel's current policy bundle
/// ([`crate::policy::PolicyStore`]; no valid bundle refuses everything). Fake-IP destinations are dialled by their name (a stale fake
/// address is refused, never dialled as an IP); with sniffing on, bare IPs
/// are routed by the sniffed name per D8 (`socks::stricter`); UDP uses the
/// SOCKS UDP refusals (home exit, QUIC on refused tags); DNS on port 53 is
/// hijacked when `hijack_dns`.
pub struct TunKernel {
    pub kernel: Arc<Kernel>,
    pub hijack_dns: bool,
}

impl TunKernel {
    /// Fake-IP destination: the recorded name, authorized against the
    /// policy in force now (the pool stores no decision).
    fn fake(&self, policy: &Policy, key: &FlowKey) -> Option<Option<Dial>> {
        let ip = key.dst.ip();
        let pool = self.kernel.fake_ip.as_ref().filter(|p| p.contains(ip))?;
        Some(pool.lookup(ip).and_then(|e| {
            let action = policy.decide_fake(&e.domain).clone();
            Dial::from_action(&action, TargetAddr::Domain(e.domain))
        }))
    }
}

impl TunRouter for TunKernel {
    fn route_tcp(&self, key: &FlowKey) -> TcpRoute {
        if self.hijack_dns && key.dst.port() == DNS_PORT {
            return TcpRoute::Dns;
        }
        let policy = self.kernel.policy.current();
        if policy.refuse_all {
            // No valid policy bundle: fail closed, fake-IP included (§5.4).
            return TcpRoute::Refuse;
        }
        if let Some(fake) = self.fake(&policy, key) {
            return fake.map_or(TcpRoute::Refuse, TcpRoute::Dial);
        }
        let rules = &policy.rules;
        if let Some(s) = self.kernel.sniff {
            // An IP reject cannot be overridden by a name: refuse the SYN.
            if let Some((_, Action::Reject)) = rules.lookup(&TargetAddr::Ip(key.dst.ip())) {
                return TcpRoute::Refuse;
            }
            return TcpRoute::Sniff(s);
        }
        ip_route(rules, key).map_or(TcpRoute::Refuse, TcpRoute::Dial)
    }

    fn sniffed(&self, key: &FlowKey, found: &Sniff) -> Option<Dial> {
        // The policy current now: a bundle installed during the sniff applies.
        let policy = self.kernel.policy.current();
        if policy.refuse_all {
            return None;
        }
        crate::socks::sniffed_route(&policy, key.dst.ip(), found)
            .map(|(tag, target)| Dial { tag, target })
    }

    fn route_udp(&self, key: &FlowKey) -> UdpRoute {
        if self.hijack_dns && key.dst.port() == DNS_PORT {
            return UdpRoute::Dns;
        }
        let Some(udp) = self.kernel.udp.as_ref() else {
            return UdpRoute::Refuse;
        };
        let ip = key.dst.ip();
        let addr = TargetAddr::Ip(ip);
        let dial = crate::udp::route(&self.kernel, &udp.settings, &addr, key.dst.port())
            .map(|(tag, target)| Dial { tag, target });
        match dial {
            None => UdpRoute::Refuse,
            Some(d) if crate::udp::plain(&self.kernel, ip) => UdpRoute::Plain(d),
            Some(d) => UdpRoute::Dial(d),
        }
    }
}

// ---------------------------------------------------------------------------
// Async driver

enum Up {
    Data(Chunk),
    Fin,
    Abort,
}

/// What a flow's relay task and the stack loop share besides the chunk
/// channels (r6 R5). Upload bytes stay in the flow's receive ring until the
/// relay wrote them upstream: the relay asks for a chunk (`want`), gets a
/// copy of the ring's head, reports what it wrote (`written`, dequeued by
/// the stack), and drops a chunk the site would block on (keeping one byte
/// for a waiting write). Download chunks are only made into transmit ring
/// room the stack published (`room`), so the stack takes them at once.
/// Relay chunks are therefore never held while waiting for the network or
/// the application, and the pool's relay region always comes back: a full
/// pool still moves every flow.
#[derive(Default)]
struct Link {
    state: std::sync::Mutex<LinkState>,
    /// Ring room was published.
    room_ready: Notify,
}

#[derive(Default)]
struct LinkState {
    written: usize,
    /// (at least, at most) bytes wanted from the ring head.
    want: Option<(usize, usize)>,
    room: usize,
    room_wanted: bool,
}

impl Link {
    fn state(&self) -> std::sync::MutexGuard<'_, LinkState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

struct Pipe {
    link: Arc<Link>,
    down: Option<mpsc::Sender<Chunk>>,
    up: mpsc::Receiver<Up>,
    pending: Option<Chunk>,
    fin: bool,
    closed: bool,
}

enum TcpPlan {
    Dial(Dial),
    Sniff(SniffSettings),
    Dns,
}

/// A UDP flow with its relay task.
struct UdpLive {
    tx: mpsc::Sender<Bytes>,
}

enum UdpMsg {
    Reply { key: FlowKey, payload: Bytes },
    Dns { key: FlowKey, payload: Vec<u8> },
    Refused(FlowKey),
    Limit(FlowKey, usize),
}

/// Shared by the relay tasks of one stack.
struct Ctx {
    dialer: Arc<dyn Dialer>,
    router: Arc<dyn TunRouter>,
    dns: Option<Arc<SmartDns>>,
    pool: Arc<BufferPool>,
    notify: Arc<Notify>,
    dial_timeout: Duration,
}

/// Worst-case memory of one [`TunStack`], in bytes. Outbound transport
/// state (inside the dialer) is not included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBudget {
    /// Every TCP ring, relay chunk, sniff and DNS-over-TCP buffer.
    pub tcp_pool: usize,
    /// Socket structs, flow-table entries, relay tasks.
    pub tcp_flows: usize,
    /// Outbound packet queue, received-datagram queue, reply channel.
    pub packet_queues: usize,
    /// Per-flow UDP queues and receive buffers, flow entries.
    pub udp_flows: usize,
    /// Hijacked DNS queries and answers in flight.
    pub dns: usize,
    pub total: usize,
}

/// TUN driver: device ↔ [`Netstack`] ↔ router/dialer/DNS.
pub struct TunStack {
    pub config: NetstackConfig,
    pub router: Arc<dyn TunRouter>,
    pub dialer: Arc<dyn Dialer>,
    /// Answers [`TcpRoute::Dns`] / [`UdpRoute::Dns`]; without it those
    /// flows are refused.
    pub dns: Option<Arc<SmartDns>>,
    pub dial_timeout: Duration,
    /// Datagrams queued per UDP flow towards its relay; newest dropped.
    pub udp_flow_queue: usize,
    /// Hijacked DNS queries answered concurrently; more are dropped.
    pub max_dns_in_flight: usize,
}

impl TunStack {
    pub fn new(router: Arc<dyn TunRouter>, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            config: NetstackConfig::default(),
            router,
            dialer,
            dns: None,
            dial_timeout: Duration::from_secs(15),
            udp_flow_queue: 8,
            max_dns_in_flight: 32,
        }
    }

    /// A stack routed exactly like the kernel's SOCKS front end, dialling
    /// through its dialer (kill switch included), with DNS on port 53
    /// hijacked to `dns` when given.
    pub fn for_kernel(kernel: Arc<Kernel>, dns: Option<Arc<SmartDns>>) -> Self {
        let dialer = kernel.dialer.clone();
        let mut config = NetstackConfig {
            shared_pool: Some(crate::session::process_pool()),
            ..NetstackConfig::default()
        };
        if let Some(udp) = kernel.udp.as_ref() {
            config.udp_idle_timeout = udp.settings.idle_timeout;
        }
        let router = Arc::new(TunKernel {
            kernel,
            hijack_dns: dns.is_some(),
        });
        let mut stack = Self::new(router, dialer);
        stack.config = config;
        stack.dns = dns;
        stack
    }

    /// Worst case with this configuration (see module docs).
    pub fn memory_budget(&self) -> MemoryBudget {
        let c = &self.config;
        let mtu = c.mtu;
        let tcp_pool = c.buffer_pool / BLOCK * BLOCK;
        let tcp_flows = c.max_tcp_flows * TCP_FLOW_OVERHEAD;
        // Outbound queue, received datagrams, reply channel (same bound),
        // the device's one-packet receive slot.
        let packet_queues = (c.out_queue + 2 * c.udp_queue + 1) * mtu;
        // Per flow: queued datagrams, one receive buffer of a reply's size,
        // bookkeeping. QUIC needs no per-flow state (§5.2a.2: a flow is
        // pinned by its 5-tuple, nothing held or tracked inside it).
        let udp_flows = c.max_udp_flows * ((self.udp_flow_queue + 1) * mtu + 1024);
        // A query and its answer (TCP answers live in the pool).
        let dns = self.max_dns_in_flight * 2 * mtu;
        MemoryBudget {
            tcp_pool,
            tcp_flows,
            packet_queues,
            udp_flows,
            dns,
            total: tcp_pool + tcp_flows + packet_queues + udp_flows + dns,
        }
    }

    /// Run until the device fails or closes.
    pub async fn run(self, io: Arc<dyn PacketIo>) -> io::Result<()> {
        let mut stack = Netstack::new(self.config.clone(), Instant::now());
        let ctx = Arc::new(Ctx {
            dialer: self.dialer.clone(),
            router: self.router.clone(),
            dns: self.dns.clone(),
            pool: stack.pool().clone(),
            notify: Arc::new(Notify::new()),
            dial_timeout: self.dial_timeout,
        });
        let mut pipes: HashMap<FlowId, Pipe> = HashMap::new();
        let mut tcp_plans: HashMap<FlowKey, TcpPlan> = HashMap::new();
        let mut udp_plans: HashMap<FlowKey, Dial> = HashMap::new();
        let mut udp_flows: HashMap<FlowKey, UdpLive> = HashMap::new();
        let (msg_tx, mut msg_rx) = mpsc::channel::<UdpMsg>(self.config.udp_queue.max(1));
        let dns_slots = Arc::new(Semaphore::new(self.max_dns_in_flight));
        let has_dns = self.dns.is_some();
        let router = self.router.clone();
        loop {
            let now = Instant::now();
            stack.poll(now);
            let mut starved = false;
            loop {
                while let Some(event) = stack.pop_event() {
                    match event {
                        Event::TcpAccepted { id, key, .. } => {
                            let Some(plan) = tcp_plans.remove(&key) else {
                                let _ = stack.tcp_abort(id);
                                continue;
                            };
                            let (down_tx, down_rx) = mpsc::channel(1);
                            let (up_tx, up_rx) = mpsc::channel(RELAY_CHUNKS);
                            let link = Arc::new(Link::default());
                            pipes.insert(
                                id,
                                Pipe {
                                    link: link.clone(),
                                    down: Some(down_tx),
                                    up: up_rx,
                                    pending: None,
                                    fin: false,
                                    closed: false,
                                },
                            );
                            tokio::spawn(relay(ctx.clone(), plan, key, link, down_rx, up_tx));
                        }
                        Event::TcpClosed { id, .. } => {
                            pipes.remove(&id);
                        }
                        Event::UdpClosed { key } => {
                            udp_flows.remove(&key);
                            udp_plans.remove(&key);
                        }
                    }
                }
                let mut progressed = false;
                for (id, pipe) in pipes.iter_mut() {
                    let (p, s) = pump(&mut stack, &ctx.pool, *id, pipe);
                    progressed |= p;
                    starved |= s;
                }
                if !progressed {
                    break;
                }
                stack.poll(now);
            }
            while let Some(d) = stack.pop_udp() {
                if d.local {
                    let (Some(dns), Ok(slot)) =
                        (self.dns.clone(), dns_slots.clone().try_acquire_owned())
                    else {
                        continue;
                    };
                    let out = msg_tx.clone();
                    tokio::spawn(async move {
                        if let Some(payload) = dns.handle(&d.payload).await {
                            let _ = out
                                .send(UdpMsg::Dns {
                                    key: d.key,
                                    payload,
                                })
                                .await;
                        }
                        drop(slot);
                    });
                    continue;
                }
                let live = match udp_flows.entry(d.key) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        let Some(dial) = udp_plans.remove(&d.key) else {
                            continue;
                        };
                        let (tx, rx) = mpsc::channel(self.udp_flow_queue.max(1));
                        tokio::spawn(udp_flow(
                            ctx.clone(),
                            d.key,
                            dial,
                            rx,
                            msg_tx.clone(),
                            stack.max_udp_reply(&d.key),
                        ));
                        e.insert(UdpLive { tx })
                    }
                };
                if live.tx.try_send(d.payload).is_err() {
                    stack.stats.dropped_udp_queue_full += 1;
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
                    let mut asked = None;
                    stack.input_with(&pkt, Instant::now(), &mut |key: &FlowKey, first: &[u8]| {
                        asked = Some(*key);
                        policy(&*router, has_dns, &mut tcp_plans, &mut udp_plans, key, first)
                    });
                    // Admission can still fail after the router said yes.
                    if let Some(key) = asked.filter(|k| !stack.has_flow(k)) {
                        tcp_plans.remove(&key);
                        udp_plans.remove(&key);
                    }
                }
                Some(msg) = msg_rx.recv() => {
                    let mut msg = Some(msg);
                    while let Some(m) = msg.take() {
                        match m {
                            UdpMsg::Reply { key, payload } => {
                                stack.send_udp(&key, &payload);
                            }
                            UdpMsg::Dns { key, payload } => {
                                if let Some(p) = truncate_dns(&payload, stack.max_udp_reply(&key)) {
                                    stack.send_udp(&key, &p);
                                }
                            }
                            UdpMsg::Refused(key) => {
                                udp_flows.remove(&key);
                                stack.udp_refuse(&key);
                            }
                            UdpMsg::Limit(key, limit) => stack.udp_set_limit(&key, limit),
                        }
                        msg = msg_rx.try_recv().ok();
                    }
                }
                _ = ctx.notify.notified() => {}
                _ = ctx.pool.freed(), if starved => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }
}

/// Map the router's answer for a new flow to a [`Verdict`], remembering
/// what to do once the flow exists.
fn policy(
    router: &dyn TunRouter,
    has_dns: bool,
    tcp_plans: &mut HashMap<FlowKey, TcpPlan>,
    udp_plans: &mut HashMap<FlowKey, Dial>,
    key: &FlowKey,
    first: &[u8],
) -> Verdict {
    match key.proto {
        Proto::Tcp => {
            let (plan, tag) = match router.route_tcp(key) {
                TcpRoute::Refuse => return Verdict::Refuse,
                TcpRoute::Dns if !has_dns => return Verdict::Refuse,
                TcpRoute::Dns => {
                    tcp_plans.insert(*key, TcpPlan::Dns);
                    return Verdict::Local;
                }
                TcpRoute::Sniff(s) => (TcpPlan::Sniff(s), None),
                TcpRoute::Dial(d) => {
                    let tag = d.tag.clone();
                    (TcpPlan::Dial(d), tag)
                }
            };
            tcp_plans.insert(*key, plan);
            Verdict::Accept(tag)
        }
        Proto::Udp => match router.route_udp(key) {
            UdpRoute::Refuse => Verdict::Refuse,
            UdpRoute::Dns if !has_dns => Verdict::Refuse,
            UdpRoute::Dns => Verdict::Local,
            UdpRoute::Dial(d) => {
                let tag = d.tag.clone();
                udp_plans.insert(*key, d);
                Verdict::Accept(tag)
            }
            UdpRoute::Plain(_)
                if key.dst.port() == crate::udp::QUIC_PORT || looks_quic_first(first) =>
            {
                Verdict::Unreachable
            }
            UdpRoute::Plain(d) => {
                let tag = d.tag.clone();
                udp_plans.insert(*key, d);
                Verdict::AcceptPlain(tag)
            }
        },
    }
}

/// Move bytes between the stack and one flow's relay task without blocking.
/// Returns (progressed, starved for pool blocks).
fn pump(stack: &mut Netstack, pool: &Arc<BufferPool>, id: FlowId, pipe: &mut Pipe) -> (bool, bool) {
    let mut progressed = false;
    let mut starved = false;
    // Taken before the up channel is drained: chunks the relay sent before
    // asking for room are counted below.
    let room_wanted = std::mem::take(&mut pipe.link.state().room_wanted);
    // Application → upstream: bytes leave the receive ring once written.
    // Under the link lock throughout, so a request is never answered from
    // a ring head that still holds bytes reported written.
    let link = pipe.link.clone();
    let mut l = link.state();
    let written = std::mem::take(&mut l.written);
    if written > 0 {
        if stack.tcp_consume(id, written).is_err() {
            return (progressed, starved);
        }
        progressed = true;
    }
    if let Some(tx) = &pipe.down {
        let queued = match stack.tcp_recv_queue(id) {
            Ok(q) => q,
            Err(_) => return (progressed, starved),
        };
        if tx.is_closed() && queued > 0 {
            // The upstream is gone: bytes the application still sends can
            // no longer be delivered, so reset rather than look closed,
            // even if the site's FIN was already passed on.
            pipe.down = None;
            let _ = stack.tcp_abort(id);
            pipe.closed = true;
            return (true, starved);
        }
        let finished = stack.tcp_peer_finished(id).unwrap_or(true);
        if queued == 0 {
            if finished {
                pipe.down = None;
                progressed = true;
            }
        } else if let Some((min, max)) = l.want {
            // Sent under the lock, so a relay that withdraws its request
            // never finds a late chunk.
            if queued >= min || finished {
                let n = queued.min(max);
                match pool.chunk(blocks_for(n)) {
                    None => starved = true,
                    Some(charge) => {
                        let mut buf = vec![0u8; n.min(charge.bytes())];
                        let k = match stack.tcp_peek(id, &mut buf) {
                            Ok(k) => k,
                            Err(_) => return (progressed, starved),
                        };
                        buf.truncate(k);
                        if k < min && !finished {
                            // The pool is short of what the relay needs
                            // at once: retry when blocks return.
                            starved = true;
                        } else if k > 0 && tx.try_send(Chunk::new(Bytes::from(buf), charge)).is_ok()
                        {
                            l.want = None;
                            progressed = true;
                        }
                    }
                }
            }
        }
    }
    drop(l);

    // Upstream → application.
    loop {
        if pipe.closed {
            // After our FIN the relay may still report that upload to the
            // site failed: the application must see a reset, not a clean
            // close.
            if pipe.fin && matches!(pipe.up.try_recv(), Ok(Up::Abort)) {
                let _ = stack.tcp_abort(id);
                pipe.fin = false;
                progressed = true;
            }
            break;
        }
        if let Some(mut chunk) = pipe.pending.take() {
            let n = stack.tcp_write(id, &chunk.data).unwrap_or(0);
            if n > 0 {
                progressed = true;
            }
            if n < chunk.data.len() {
                chunk.advance(n);
                pipe.pending = Some(chunk);
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
            Ok(Up::Data(chunk)) => pipe.pending = Some(chunk),
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
    if room_wanted {
        let room = if pipe.closed || pipe.pending.is_some() {
            0
        } else {
            stack.tcp_tx_room(id).unwrap_or(0)
        };
        let mut l = pipe.link.state();
        if room > 0 {
            l.room += room;
            drop(l);
            pipe.link.room_ready.notify_one();
        } else {
            // Asked again on the next round (the application acks, the
            // pending chunk drains).
            l.room_wanted = true;
        }
    }
    (progressed, starved)
}

async fn send_up(ctx: &Ctx, up: &mpsc::Sender<Up>, msg: Up) -> bool {
    let ok = up.send(msg).await.is_ok();
    ctx.notify.notify_one();
    ok
}

/// Ask the stack for the head of the flow's receive ring: at least `min`
/// bytes (fewer only once the application finished), at most `max`.
/// `None`: the application finished and everything was delivered.
async fn request(
    ctx: &Ctx,
    link: &Link,
    down: &mut mpsc::Receiver<Chunk>,
    min: usize,
    max: usize,
) -> Option<Chunk> {
    link.state().want = Some((min.max(1), max));
    ctx.notify.notify_one();
    down.recv().await
}

/// Withdraw a request, dropping a chunk that answered it meanwhile (the
/// stack sends under the same lock).
fn withdraw(link: &Link, down: &mut mpsc::Receiver<Chunk>) {
    let mut l = link.state();
    l.want = None;
    while down.try_recv().is_ok() {}
}

/// `n` bytes of the ring head reached the site.
fn wrote(ctx: &Ctx, link: &Link, n: usize) {
    if n > 0 {
        link.state().written += n;
        ctx.notify.notify_one();
    }
}

/// Wait for up to `want` bytes of transmit ring room (`None`: the stack
/// dropped the flow).
async fn wait_room(ctx: &Ctx, link: &Link, up: &mpsc::Sender<Up>, want: usize) -> Option<usize> {
    loop {
        let ready = link.room_ready.notified();
        tokio::pin!(ready);
        ready.as_mut().enable();
        {
            let mut l = link.state();
            if l.room > 0 {
                let k = l.room.min(want);
                l.room -= k;
                return Some(k);
            }
            l.room_wanted = true;
        }
        ctx.notify.notify_one();
        tokio::select! {
            _ = &mut ready => {}
            _ = up.closed() => return None,
        }
    }
}

/// Return room a chunk did not use.
fn give_room(link: &Link, n: usize) {
    if n > 0 {
        link.state().room += n;
    }
}

/// `data` towards the application, in chunks that fit published ring room.
async fn send_to_app(ctx: &Ctx, link: &Link, up: &mpsc::Sender<Up>, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let Some(room) = wait_room(ctx, link, up, data.len().min(CHUNK)).await else {
            return false;
        };
        let charge = tokio::select! {
            c = ctx.pool.chunk_wait(blocks_for(room)) => c,
            _ = up.closed() => return false,
        };
        let n = room.min(charge.bytes());
        give_room(link, room - n);
        let chunk = Chunk::new(Bytes::copy_from_slice(&data[..n]), charge);
        data = &data[n..];
        if !send_up(ctx, up, Up::Data(chunk)).await {
            return false;
        }
    }
    true
}

/// Write what `w` takes right now (`None`: it would block).
fn try_write<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> Option<io::Result<usize>> {
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    let mut cx = Context::from_waker(Waker::noop());
    match Pin::new(w).poll_write(&mut cx, buf) {
        Poll::Ready(r) => Some(r),
        Poll::Pending => None,
    }
}

/// Per-flow task: decide (sniff), dial, then relay both directions with
/// half-close. A refusal or failed dial resets the flow; nothing is retried
/// direct (§5.4).
async fn relay(
    ctx: Arc<Ctx>,
    plan: TcpPlan,
    key: FlowKey,
    link: Arc<Link>,
    mut down: mpsc::Receiver<Chunk>,
    up: mpsc::Sender<Up>,
) {
    let dial = match plan {
        TcpPlan::Dns => return dns_tcp(&ctx, &link, down, up).await,
        TcpPlan::Dial(d) => d,
        TcpPlan::Sniff(s) => {
            let mut found = Sniff::NeedMore;
            let deadline = tokio::time::sleep(s.timeout);
            tokio::pin!(deadline);
            let mut min = 1;
            loop {
                // Each chunk is the ring head so far: nothing to keep
                // between rounds.
                let c = tokio::select! {
                    c = request(&ctx, &link, &mut down, min, s.max_bytes) => c,
                    _ = &mut deadline => break,
                };
                let Some(c) = c else { break };
                found = sniff(&c.data);
                match found {
                    // Shorter than asked: the application finished (or
                    // the pool is short); sniff no further.
                    Sniff::NeedMore if c.data.len() < s.max_bytes && c.data.len() >= min => {
                        min = c.data.len() + 1;
                    }
                    _ => break,
                }
            }
            withdraw(&link, &mut down);
            match ctx.router.sniffed(&key, &found) {
                Some(d) => d,
                None => {
                    send_up(&ctx, &up, Up::Abort).await;
                    return;
                }
            }
        }
    };
    let dialed = tokio::time::timeout(
        ctx.dial_timeout,
        ctx.dialer
            .dial(dial.tag.as_deref(), &dial.target, key.dst.port()),
    )
    .await;
    let Ok(Ok(stream)) = dialed else {
        send_up(&ctx, &up, Up::Abort).await;
        return;
    };
    let (mut r, mut w) = tokio::io::split(stream);
    let abort = up.clone();
    let to_app = async {
        let mut one = [0u8; 1];
        loop {
            // Wait with a 1-byte buffer so an idle flow holds no chunk.
            let res = tokio::select! {
                res = r.read(&mut one) => res,
                _ = up.closed() => return,
            };
            let msg = match res {
                Ok(0) => Up::Fin,
                Ok(_) => {
                    // Only into ring room the stack published, so the
                    // chunk is taken at once (r6 R5).
                    let Some(room) = wait_room(&ctx, &link, &up, CHUNK).await else {
                        return;
                    };
                    let charge = tokio::select! {
                        c = ctx.pool.chunk_wait(blocks_for(room)) => c,
                        _ = up.closed() => return,
                    };
                    let size = room.min(charge.bytes());
                    give_room(&link, room - size);
                    let mut buf = vec![0u8; size];
                    buf[0] = one[0];
                    match read_ready(&mut r, &mut buf[1..]).await {
                        Ok(n) => {
                            give_room(&link, size - 1 - n);
                            buf.truncate(1 + n);
                            Up::Data(Chunk::new(Bytes::from(buf), charge))
                        }
                        Err(_) => Up::Abort,
                    }
                }
                Err(_) => Up::Abort,
            };
            let last = !matches!(msg, Up::Data(_));
            if !send_up(&ctx, &up, msg).await || last {
                return;
            }
        }
    };
    let to_site = async {
        // Bytes leave the ring only once written; a chunk the site would
        // block on is dropped but for one byte, whose write is awaited.
        while let Some(c) = request(&ctx, &link, &mut down, 1, CHUNK).await {
            let mut off = 0;
            let mut blocked = false;
            while off < c.data.len() {
                match try_write(&mut w, &c.data[off..]) {
                    Some(Ok(n)) if n > 0 => off += n,
                    Some(_) => {
                        send_up(&ctx, &abort, Up::Abort).await;
                        return;
                    }
                    None => {
                        blocked = true;
                        break;
                    }
                }
            }
            let next = blocked.then(|| c.data[off]);
            drop(c);
            wrote(&ctx, &link, off);
            if let Some(b) = next {
                if w.write_all(&[b]).await.is_err() {
                    send_up(&ctx, &abort, Up::Abort).await;
                    return;
                }
                wrote(&ctx, &link, 1);
            }
        }
        let _ = w.shutdown().await;
    };
    tokio::join!(to_app, to_site);
}

/// Read whatever is ready without waiting (0 if nothing is).
async fn read_ready<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    use std::pin::Pin;
    use std::task::Poll;
    std::future::poll_fn(|cx| {
        let mut rb = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut *r).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(0)),
        }
    })
    .await
}

/// DNS over TCP to the hijacked resolver: length-prefixed messages answered
/// by the [`SmartDns`] one at a time. Queries are read from the ring head
/// and copied out (charged like a ring) before they are answered, so no
/// relay chunk waits for the resolver.
async fn dns_tcp(ctx: &Ctx, link: &Link, mut down: mpsc::Receiver<Chunk>, up: mpsc::Sender<Up>) {
    const IDLE: Duration = Duration::from_secs(10);
    let Some(dns) = ctx.dns.clone() else {
        send_up(ctx, &up, Up::Abort).await;
        return;
    };
    let mut min = 2;
    loop {
        let c = match tokio::time::timeout(IDLE, request(ctx, link, &mut down, min, 2 + 65_535))
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(_) => {
                withdraw(link, &mut down);
                break;
            }
        };
        let data = &c.data;
        if data.len() < 2 {
            if data.len() < min {
                // The application finished mid-message.
                break;
            }
            min = 2;
            continue;
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            if data.len() < min {
                break;
            }
            min = 2 + len;
            continue;
        }
        min = 2;
        let Some(_held) = ctx.pool.charge(blocks_for(len).max(1)) else {
            // No room to hold the query: refuse the flow.
            send_up(ctx, &up, Up::Abort).await;
            return;
        };
        let query = data[2..2 + len].to_vec();
        drop(c);
        wrote(ctx, link, 2 + len);
        let Some(answer) = dns.handle(&query).await else {
            continue;
        };
        drop(query);
        let Ok(n) = u16::try_from(answer.len()) else {
            continue;
        };
        if !send_to_app(ctx, link, &up, &n.to_be_bytes()).await
            || !send_to_app(ctx, link, &up, &answer).await
        {
            return;
        }
    }
    send_up(ctx, &up, Up::Fin).await;
    // Keep the receiver until the stack drops us, so a late query is not
    // mistaken for undeliverable upload.
    while down.recv().await.is_some() {}
}

/// Per-flow UDP relay through [`Dialer::dial_udp`]. A failed dial or send
/// marks the flow refused (ICMP from then on); never retried direct.
async fn udp_flow(
    ctx: Arc<Ctx>,
    key: FlowKey,
    dial: Dial,
    mut rx: mpsc::Receiver<Bytes>,
    out: mpsc::Sender<UdpMsg>,
    reply_max: usize,
) {
    let port = key.dst.port();
    let dialed = tokio::time::timeout(
        ctx.dial_timeout,
        ctx.dialer.dial_udp(dial.tag.as_deref(), &dial.target, port),
    )
    .await;
    let Ok(Ok(session)) = dialed else {
        let _ = out.send(UdpMsg::Refused(key)).await;
        return;
    };
    let session: Arc<dyn UdpSession> = Arc::from(session);
    let limit = session.max_payload(&dial.target, port);
    let _ = out.send(UdpMsg::Limit(key, limit)).await;
    let down = tokio::spawn({
        let (session, out) = (session.clone(), out.clone());
        async move {
            // Sized to the largest reply the TUN can carry (+1 to detect
            // truncation): bigger replies are dropped anyway.
            let mut buf = Vec::with_capacity(reply_max + 1);
            while session.recv(&mut buf).await.is_ok() {
                if buf.len() > reply_max {
                    continue;
                }
                let payload = Bytes::copy_from_slice(&buf);
                // Replies are dropped when the driver is behind.
                let _ = out.try_send(UdpMsg::Reply { key, payload });
            }
        }
    });
    while let Some(p) = rx.recv().await {
        if p.len() > limit {
            continue;
        }
        if session.send(&dial.target, port, &p).await.is_err() {
            let _ = out.send(UdpMsg::Refused(key)).await;
            break;
        }
        if down.is_finished() {
            break;
        }
    }
    down.abort();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoDial;
    #[async_trait]
    impl Dialer for NoDial {
        async fn dial(
            &self,
            _: Option<&str>,
            _: &TargetAddr,
            _: u16,
        ) -> Result<crate::dial::Stream, crate::dial::DialError> {
            Err(crate::dial::DialError("test".into()))
        }
    }

    /// `TCP_FLOW_OVERHEAD` must cover what one flow holds outside the pool.
    #[test]
    fn per_flow_overhead_estimate_holds() {
        let (down_tx, down_rx) = mpsc::channel::<Chunk>(RELAY_CHUNKS);
        let (up_tx, up_rx) = mpsc::channel::<Up>(RELAY_CHUNKS);
        let ctx = Arc::new(Ctx {
            dialer: Arc::new(NoDial),
            router: Arc::new(RefuseAll),
            dns: None,
            pool: BufferPool::new(BLOCK * 4),
            notify: Arc::new(Notify::new()),
            dial_timeout: Duration::from_secs(1),
        });
        let key = FlowKey {
            proto: Proto::Tcp,
            src: "10.0.0.1:1".parse().unwrap(),
            dst: "10.0.0.2:2".parse().unwrap(),
        };
        let plan = TcpPlan::Dial(Dial {
            tag: None,
            target: TargetAddr::Ip(key.dst.ip()),
        });
        let task = relay(ctx, plan, key, Arc::new(Link::default()), down_rx, up_tx);
        // Socket (storage is pooled), table entries (key → entry, id → key,
        // pipes), the relay task and its two channel headers.
        // Channel headers and the tokio task header.
        let channels = 2 * 256 + 256;
        let tables = 2 * (size_of::<FlowKey>() + size_of::<TcpEntry>())
            + size_of::<FlowKey>()
            + size_of::<FlowId>()
            + size_of::<Pipe>()
            + size_of::<Link>()
            + 16;
        let total =
            size_of::<tcp::Socket<'static>>() + tables + std::mem::size_of_val(&task) + channels;
        println!(
            "per-flow overhead: {total} bytes (socket {}, relay {})",
            size_of::<tcp::Socket<'static>>(),
            std::mem::size_of_val(&task)
        );
        assert!(total <= TCP_FLOW_OVERHEAD, "{total} > {TCP_FLOW_OVERHEAD}");
        drop((down_tx, up_rx));
    }
}
