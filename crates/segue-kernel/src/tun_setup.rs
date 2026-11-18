//! macOS utun address, split default routes and exit exclusions.
//!
//! Routes are written to a `PF_ROUTE` socket (`RTM_ADD` / `RTM_DELETE`), not
//! `/sbin/route`. The message is the same one sing-tun's `execRoute` writes
//! (`golang.org/x/net/route` on Darwin): a version-5 `rt_msghdr` plus
//! destination, netmask and gateway sockaddrs, each padded to 4 bytes. Doing
//! it in-process keeps removal on the same path as install, including `Drop`,
//! and the bytes are testable without root. Shelling out would only hide that
//! layout behind `route(8)`'s parser.
//!
//! Split defaults are `0.0.0.0/1`, `128.0.0.0/1`, `::/1` and `8000::/1` via
//! the utun peer, which is more specific than the system's default and leaves
//! that default in place. Exit addresses are host routes via the physical
//! gateway, scoped to that interface (`RTF_IFSCOPE`), installed *before* the
//! split defaults so the carrier is never captured. Direct and domestic
//! sockets are also bound with `IP_BOUND_IF` / `IPV6_BOUND_IF`, except a dial
//! whose next hop is loopback: the physical NIC cannot reach `127.0.0.0/8`
//! or `::1`.
//!
//! Nothing in the pure half opens a socket. The syscalls are
//! `cfg(target_os = "macos")`.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use segue_transport::{SocketHandle, SocketProtector};
use serde_json::Value;

#[cfg(unix)]
use std::os::fd::RawFd;

/// Default utun MTU. The 4-byte Darwin address-family header is not part of it.
pub const DEFAULT_MTU: u32 = 1500;
pub const DEFAULT_IPV4: &str = "172.19.0.1/30";
pub const DEFAULT_IPV4_PEER: &str = "172.19.0.2";
pub const DEFAULT_IPV6: &str = "fd00:5e9e::1/64";
pub const DEFAULT_IPV6_PEER: &str = "fd00:5e9e::2";

const MIN_MTU: u32 = 1280;
const MAX_MTU: u32 = 16_384;

/// Darwin `rt_msghdr` (92 bytes: 36 of header, 56 of `rt_metrics`).
const HEADER_LEN: usize = 92;
const RTM_VERSION: u8 = 5;
const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_GET: u8 = 0x4;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_HOST: i32 = 0x4;
const RTF_STATIC: i32 = 0x800;
const RTF_IFSCOPE: i32 = 0x0100_0000;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
/// Darwin `AF_INET`. Not Linux's.
const AF_INET: u8 = 2;
/// Darwin `AF_INET6` is 30, not 10.
const AF_INET6: u8 = 30;
const AF_LINK: u8 = 18;

/// Address and peer programmed on the utun. The peer is the gateway of the
/// split default routes; it must sit on the utun or those routes cannot resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunAddress {
    pub mtu: u32,
    pub v4: Ipv4Addr,
    pub v4_prefix: u8,
    pub v4_peer: Ipv4Addr,
    pub v6: Option<V6Address>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V6Address {
    pub addr: Ipv6Addr,
    pub prefix: u8,
    pub peer: Ipv6Addr,
}

impl Default for TunAddress {
    fn default() -> Self {
        Self::from_parts(
            DEFAULT_MTU,
            DEFAULT_IPV4,
            DEFAULT_IPV4_PEER,
            true,
            None,
            None,
        )
        .expect("built-in utun address")
    }
}

impl TunAddress {
    pub fn from_parts(
        mtu: u32,
        ipv4: &str,
        ipv4_peer: &str,
        ipv6: bool,
        ipv6_address: Option<&str>,
        ipv6_peer: Option<&str>,
    ) -> Result<Self, String> {
        if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
            return Err(format!("tun.mtu must be {MIN_MTU}..={MAX_MTU}, got {mtu}"));
        }
        let (v4, v4_prefix) = parse_v4_cidr(ipv4)?;
        let v4_peer: Ipv4Addr = ipv4_peer
            .parse()
            .map_err(|_| format!("tun.ipv4_peer {ipv4_peer:?} is not an IPv4 address"))?;
        check_v4(v4, v4_prefix, v4_peer)?;
        let v6 = if !ipv6 {
            None
        } else {
            let addr_s = ipv6_address.unwrap_or(DEFAULT_IPV6);
            let peer_s = ipv6_peer.unwrap_or(DEFAULT_IPV6_PEER);
            if ipv6_address.is_some() && ipv6_peer.is_none() {
                return Err("tun.ipv6_peer is required when tun.ipv6_address is set".into());
            }
            let (addr, prefix) = parse_v6_cidr(addr_s)?;
            let peer: Ipv6Addr = peer_s
                .parse()
                .map_err(|_| format!("tun.ipv6_peer {peer_s:?} is not an IPv6 address"))?;
            check_v6(addr, prefix, peer)?;
            Some(V6Address { addr, prefix, peer })
        };
        Ok(Self {
            mtu,
            v4,
            v4_prefix,
            v4_peer,
            v6,
        })
    }

    /// The interface address must not be one the fake-IP pool can hand out.
    pub fn overlaps_fake(&self, base: Ipv4Addr, prefix: u8) -> bool {
        in_v4(self.v4, base, prefix) || in_v4(self.v4_peer, base, prefix)
    }
}

fn check_v4(addr: Ipv4Addr, prefix: u8, peer: Ipv4Addr) -> Result<(), String> {
    if !(1..=32).contains(&prefix) {
        return Err(format!("tun.ipv4 prefix must be 1..=32, got {prefix}"));
    }
    if !usable_v4(addr) {
        return Err(format!("tun.ipv4 {addr} must be a unicast address"));
    }
    if !usable_v4(peer) || peer == addr {
        return Err(format!(
            "tun.ipv4_peer {peer} must be a different unicast address"
        ));
    }
    if prefix < 32 && !in_v4(peer, addr, prefix) {
        return Err(format!("tun.ipv4_peer {peer} is outside {addr}/{prefix}"));
    }
    Ok(())
}

fn check_v6(addr: Ipv6Addr, prefix: u8, peer: Ipv6Addr) -> Result<(), String> {
    if !(1..=128).contains(&prefix) {
        return Err(format!("tun.ipv6 prefix must be 1..=128, got {prefix}"));
    }
    if !usable_v6(addr) {
        return Err(format!("tun.ipv6 {addr} must be a unicast address"));
    }
    if !usable_v6(peer) || peer == addr {
        return Err(format!(
            "tun.ipv6_peer {peer} must be a different unicast address"
        ));
    }
    if prefix < 128 && !in_v6(peer, addr, prefix) {
        return Err(format!("tun.ipv6_peer {peer} is outside {addr}/{prefix}"));
    }
    Ok(())
}

fn usable_v4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn usable_v6(ip: Ipv6Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

fn in_v4(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = 32 - u32::from(prefix);
    let mask = u32::MAX << shift;
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let bits = prefix as usize;
    let ip = ip.octets();
    let net = net.octets();
    let full = bits / 8;
    if ip[..full] != net[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (ip[full] & mask) == (net[full] & mask)
}

fn parse_v4_cidr(s: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("tun.ipv4 {s:?} must be an address/prefix"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| format!("tun.ipv4 {s:?} must be an address/prefix"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("tun.ipv4 {s:?} must be an address/prefix"))?;
    Ok((addr, prefix))
}

fn parse_v6_cidr(s: &str) -> Result<(Ipv6Addr, u8), String> {
    let (addr, prefix) = s
        .rsplit_once('/')
        .ok_or_else(|| format!("tun.ipv6 {s:?} must be an address/prefix"))?;
    let addr: Ipv6Addr = addr
        .parse()
        .map_err(|_| format!("tun.ipv6 {s:?} must be an address/prefix"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("tun.ipv6 {s:?} must be an address/prefix"))?;
    Ok((addr, prefix))
}

/// Where a route sends packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextHop {
    /// An IP next hop. `scope` sets `RTF_IFSCOPE` so the route cannot be
    /// recursive through the utun (exit exclusions).
    Gateway {
        addr: IpAddr,
        index: u32,
        scope: bool,
    },
    /// On-link: the gateway sockaddr is `AF_LINK` for `index`.
    Interface { index: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub destination: IpAddr,
    pub prefix: u8,
    pub hop: NextHop,
}

impl std::fmt::Display for RouteSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{} ", self.destination, self.prefix)?;
        match &self.hop {
            NextHop::Gateway { addr, index, scope } => {
                write!(f, "via {addr} dev {index}")?;
                if *scope {
                    write!(f, " scope")?;
                }
                Ok(())
            }
            NextHop::Interface { index } => write!(f, "dev {index}"),
        }
    }
}

/// The physical next hop a probe found, before any utun route exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhysicalPath {
    pub gateway: IpAddr,
    pub index: u32,
    pub on_link: bool,
}

/// `0/1 + 128/1` and, when v6 is configured, `::/1 + 8000::/1`.
pub fn split_defaults(tun: &TunAddress, utun_index: u32) -> Vec<RouteSpec> {
    let v4 = |destination: Ipv4Addr, prefix: u8| RouteSpec {
        destination: IpAddr::V4(destination),
        prefix,
        hop: NextHop::Gateway {
            addr: IpAddr::V4(tun.v4_peer),
            index: utun_index,
            scope: false,
        },
    };
    let mut routes = vec![
        v4(Ipv4Addr::UNSPECIFIED, 1),
        v4(Ipv4Addr::new(128, 0, 0, 0), 1),
    ];
    if let Some(v6) = &tun.v6 {
        let hop = NextHop::Gateway {
            addr: IpAddr::V6(v6.peer),
            index: utun_index,
            scope: false,
        };
        routes.push(RouteSpec {
            destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix: 1,
            hop: hop.clone(),
        });
        routes.push(RouteSpec {
            destination: IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 1,
            hop,
        });
    }
    routes
}

/// Host routes for `targets` via the physical path of their family.
/// Addresses inside the utun prefix, and non-unicast addresses, are skipped:
/// a host route for the utun peer would steal the split-default gateway.
/// A target whose family has no physical path is an error (the tunnel would
/// capture the carrier).
pub fn exclusion_routes(
    targets: &[IpAddr],
    v4: Option<&PhysicalPath>,
    v6: Option<&PhysicalPath>,
    tun: &TunAddress,
) -> Result<Vec<RouteSpec>, String> {
    let mut seen = BTreeSet::new();
    let mut routes = Vec::new();
    for ip in targets {
        if !seen.insert(*ip) || on_tun(*ip, tun) || !usable(*ip) {
            continue;
        }
        let path = match ip {
            IpAddr::V4(_) => v4,
            IpAddr::V6(_) => v6,
        };
        let Some(path) = path else {
            return Err(format!("no physical route for exit {ip}"));
        };
        if path.index == 0 {
            return Err(format!("physical route for {ip} has no interface"));
        }
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        let hop = if path.on_link {
            NextHop::Interface { index: path.index }
        } else {
            if path.gateway.is_ipv4() != ip.is_ipv4() {
                return Err(format!(
                    "physical gateway {} does not match {ip}",
                    path.gateway
                ));
            }
            NextHop::Gateway {
                addr: path.gateway,
                index: path.index,
                scope: true,
            }
        };
        routes.push(RouteSpec {
            destination: *ip,
            prefix,
            hop,
        });
    }
    Ok(routes)
}

fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => usable_v4(v4),
        IpAddr::V6(v6) => usable_v6(v6),
    }
}

fn on_tun(ip: IpAddr, tun: &TunAddress) -> bool {
    match ip {
        IpAddr::V4(v4) => in_v4(v4, tun.v4, tun.v4_prefix) || v4 == tun.v4_peer,
        IpAddr::V6(v6) => tun
            .v6
            .as_ref()
            .is_some_and(|n| in_v6(v6, n.addr, n.prefix) || v6 == n.peer),
    }
}

/// Carrier addresses named by outbound JSON, plus relay IPs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitTargets {
    pub ips: Vec<IpAddr>,
    pub names: Vec<String>,
}

pub fn exit_targets(
    outbounds: &std::collections::BTreeMap<String, Value>,
    relays: &[IpAddr],
) -> ExitTargets {
    let mut ips = BTreeSet::new();
    let mut names = BTreeSet::new();
    for spec in outbounds.values() {
        walk(spec, 0, &mut ips, &mut names);
    }
    for ip in relays {
        if usable(*ip) {
            ips.insert(*ip);
        }
    }
    ExitTargets {
        ips: ips.into_iter().collect(),
        names: names.into_iter().collect(),
    }
}

fn walk(v: &Value, depth: u8, ips: &mut BTreeSet<IpAddr>, names: &mut BTreeSet<String>) {
    if depth > 16 {
        return;
    }
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if k == "address" {
                    if let Some(s) = child.as_str() {
                        take_host(s, ips, names);
                    }
                } else if k == "endpoint" {
                    if let Some(s) = child.as_str() {
                        take_host(host_of_endpoint(s), ips, names);
                    }
                }
                walk(child, depth + 1, ips, names);
            }
        }
        Value::Array(items) => {
            for child in items {
                walk(child, depth + 1, ips, names);
            }
        }
        _ => {}
    }
}

fn take_host(host: &str, ips: &mut BTreeSet<IpAddr>, names: &mut BTreeSet<String>) {
    let host = host.trim();
    if host.is_empty() {
        return;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if usable(ip) {
            ips.insert(ip);
        }
        return;
    }
    if host.bytes().any(|b| b.is_ascii_alphanumeric()) {
        names.insert(host.to_string());
    }
}

fn host_of_endpoint(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match s.matches(':').count() {
        1 => s.split(':').next().unwrap_or(s),
        _ => s,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOp {
    Add,
    Delete,
}

/// Darwin route-socket message for `spec`. Fails if the interface index does
/// not fit the 16-bit `rtm_index`.
pub fn encode_route(spec: &RouteSpec, op: RouteOp, seq: i32) -> Result<Vec<u8>, String> {
    let index = u16::try_from(hop_index(&spec.hop))
        .map_err(|_| format!("interface index does not fit a route message ({spec})"))?;
    let mut body = Vec::new();
    push_ip(&mut body, spec.destination);
    match &spec.hop {
        NextHop::Gateway { addr, .. } => push_ip(&mut body, *addr),
        NextHop::Interface { .. } => push_link(&mut body, index),
    }
    push_mask(&mut body, spec.destination, spec.prefix);
    let mut flags = RTF_UP | RTF_STATIC;
    if matches!(spec.hop, NextHop::Gateway { .. }) {
        flags |= RTF_GATEWAY;
    }
    if matches!(
        spec.hop,
        NextHop::Gateway { scope: true, .. } | NextHop::Interface { .. }
    ) {
        flags |= RTF_IFSCOPE;
    }
    let host = matches!(
        (spec.destination, spec.prefix),
        (IpAddr::V4(_), 32) | (IpAddr::V6(_), 128)
    );
    if host {
        flags |= RTF_HOST;
    }
    let typ = match op {
        RouteOp::Add => RTM_ADD,
        RouteOp::Delete => RTM_DELETE,
    };
    Ok(finish(
        typ,
        index,
        flags,
        RTA_DST | RTA_GATEWAY | RTA_NETMASK,
        seq,
        body,
    ))
}

/// `RTM_GET` for `dest`, used to learn the physical gateway before our routes exist.
pub fn encode_get(dest: IpAddr, seq: i32) -> Vec<u8> {
    let mut body = Vec::new();
    push_ip(&mut body, dest);
    finish(RTM_GET, 0, RTF_UP, RTA_DST, seq, body)
}

fn hop_index(hop: &NextHop) -> u32 {
    match hop {
        NextHop::Gateway { index, .. } | NextHop::Interface { index } => *index,
    }
}

fn finish(typ: u8, index: u16, flags: i32, addrs: i32, seq: i32, body: Vec<u8>) -> Vec<u8> {
    let len = HEADER_LEN + body.len();
    let mut msg = vec![0u8; len];
    let len16 = u16::try_from(len).unwrap_or(u16::MAX);
    msg[0..2].copy_from_slice(&len16.to_le_bytes());
    msg[2] = RTM_VERSION;
    msg[3] = typ;
    msg[4..6].copy_from_slice(&index.to_le_bytes());
    msg[8..12].copy_from_slice(&flags.to_le_bytes());
    msg[12..16].copy_from_slice(&addrs.to_le_bytes());
    msg[20..24].copy_from_slice(&seq.to_le_bytes());
    msg[HEADER_LEN..].copy_from_slice(&body);
    msg
}

fn push_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            buf.push(16);
            buf.push(AF_INET);
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&v4.octets());
            buf.extend_from_slice(&[0u8; 8]);
        }
        IpAddr::V6(v6) => push_in6(buf, &v6.octets()),
    }
}

fn push_in6(buf: &mut Vec<u8>, addr: &[u8; 16]) {
    buf.push(28);
    buf.push(AF_INET6);
    buf.extend_from_slice(&[0u8; 6]);
    buf.extend_from_slice(addr);
    buf.extend_from_slice(&[0u8; 4]);
}

fn push_link(buf: &mut Vec<u8>, index: u16) {
    buf.push(20);
    buf.push(AF_LINK);
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
}

fn push_mask(buf: &mut Vec<u8>, dest: IpAddr, prefix: u8) {
    match dest {
        IpAddr::V4(_) => {
            let mask = mask_octets(prefix, 4);
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&mask);
            push_ip(buf, IpAddr::V4(Ipv4Addr::from(addr)));
        }
        IpAddr::V6(_) => {
            let mask = mask_octets(prefix, 16);
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&mask);
            push_in6(buf, &addr);
        }
    }
}

fn mask_octets(bits: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, byte) in out.iter_mut().enumerate() {
        let have = bits.saturating_sub((i as u8).saturating_mul(8));
        *byte = if have >= 8 {
            0xff
        } else if have == 0 {
            0
        } else {
            0xff << (8 - have)
        };
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedRoute {
    pub typ: u8,
    pub index: u16,
    pub flags: i32,
    pub seq: i32,
    pub pid: i32,
    pub errno: i32,
    pub destination: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
    pub link_index: Option<u16>,
    pub prefix: Option<u8>,
}

pub fn parse_route(buf: &[u8]) -> Option<ParsedRoute> {
    if buf.len() < HEADER_LEN || buf[2] != RTM_VERSION {
        return None;
    }
    let msglen = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if msglen < HEADER_LEN || msglen > buf.len() {
        return None;
    }
    let addrs = i32::from_le_bytes(buf[12..16].try_into().ok()?);
    let mut rest = &buf[HEADER_LEN..msglen];
    let mut parsed = ParsedRoute {
        typ: buf[3],
        index: u16::from_le_bytes([buf[4], buf[5]]),
        flags: i32::from_le_bytes(buf[8..12].try_into().ok()?),
        seq: i32::from_le_bytes(buf[20..24].try_into().ok()?),
        pid: i32::from_le_bytes(buf[16..20].try_into().ok()?),
        errno: i32::from_le_bytes(buf[24..28].try_into().ok()?),
        destination: None,
        gateway: None,
        link_index: None,
        prefix: None,
    };
    for bit in 0..8 {
        if addrs & (1 << bit) == 0 {
            continue;
        }
        let (sa, next) = take_sockaddr(rest)?;
        rest = next;
        match bit {
            0 => parsed.destination = ip_of(sa),
            1 => match ip_of(sa) {
                Some(ip) => parsed.gateway = Some(ip),
                None if sa.len() >= 4 && sa[1] == AF_LINK => {
                    parsed.link_index = Some(u16::from_le_bytes([sa[2], sa[3]]));
                }
                None => {}
            },
            2 => parsed.prefix = mask_prefix(sa),
            _ => {}
        }
    }
    Some(parsed)
}

fn take_sockaddr(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let len = buf[0] as usize;
    let n = if len == 0 { 4 } else { (len + 3) & !3 };
    if buf.len() < n || (len > 0 && len > buf.len()) {
        return None;
    }
    let sa_len = if len == 0 { n } else { len };
    Some((&buf[..sa_len], &buf[n..]))
}

fn ip_of(sa: &[u8]) -> Option<IpAddr> {
    if sa.len() >= 8 && sa[1] == AF_INET {
        let mut o = [0u8; 4];
        o.copy_from_slice(&sa[4..8]);
        return Some(IpAddr::V4(Ipv4Addr::from(o)));
    }
    if sa.len() >= 24 && sa[1] == AF_INET6 {
        let mut o = [0u8; 16];
        o.copy_from_slice(&sa[8..24]);
        return Some(IpAddr::V6(Ipv6Addr::from(o)));
    }
    None
}

fn mask_prefix(sa: &[u8]) -> Option<u8> {
    let octets: &[u8] = if sa.len() >= 8 && sa[1] == AF_INET {
        &sa[4..8]
    } else if sa.len() >= 24 && sa[1] == AF_INET6 {
        &sa[8..24]
    } else {
        return None;
    };
    let mut bits = 0u8;
    for byte in octets {
        if *byte == 0xff {
            bits = bits.saturating_add(8);
            continue;
        }
        bits = bits.saturating_add(byte.leading_ones() as u8);
        break;
    }
    Some(bits)
}

/// `_IOW('i', num, len)` from Darwin `sys/ioccom.h`.
pub fn ioc_in(group: u8, num: u8, len: usize) -> u64 {
    let len = (len as u64) & 0x1fff;
    0x8000_0000 | (len << 16) | (u64::from(group) << 8) | u64::from(num)
}

/// Binds `fd` to interface `index` (`IP_BOUND_IF` / `IPV6_BOUND_IF`).
/// Index 0 leaves the socket alone. Off macOS this is an error for a non-zero
/// index: a silent no-op would route the carrier back into the utun.
#[cfg(unix)]
pub fn bind_fd_to_interface(fd: RawFd, index: u32) -> io::Result<()> {
    if index == 0 {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        sys::bind_fd(fd, index)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fd;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IP_BOUND_IF is macOS-only",
        ))
    }
}

/// Socket protector that pins every dial the transport opens to one interface.
///
/// Loopback next hops are left unbound. `IP_BOUND_IF` on the physical NIC
/// has no route to `127.0.0.0/8` or `::1`, so a local exit (a SOCKS server
/// on `127.0.0.1`) would never complete its handshake. Every other
/// destination stays pinned, which is what keeps the tunnel's own traffic
/// out of the utun.
pub struct InterfaceBind {
    index: u32,
}

/// `127.0.0.0/8`, `::1`, and an IPv4-mapped loopback.
pub(crate) fn destination_is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

impl InterfaceBind {
    pub fn new(index: u32) -> Self {
        Self { index }
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

impl SocketProtector for InterfaceBind {
    fn protect(&self, socket: SocketHandle) -> io::Result<()> {
        #[cfg(unix)]
        {
            bind_fd_to_interface(socket.raw() as RawFd, self.index)
        }
        #[cfg(not(unix))]
        {
            let _ = socket;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IP_BOUND_IF is macOS-only",
            ))
        }
    }

    fn protects_destination(&self, dest: IpAddr) -> bool {
        !destination_is_loopback(dest)
    }
}

/// A brought-up utun. Drop removes routes and closes the descriptor, in that
/// order, so a setup error or a panic does not leave the split defaults behind.
pub struct TunSession {
    name: Option<String>,
    index: u32,
    protector: Option<Arc<InterfaceBind>>,
    notes: Vec<String>,
    #[cfg(target_os = "macos")]
    live: Option<sys::LiveTun>,
}

impl TunSession {
    /// No tun section: socks only, on every OS.
    pub fn inactive() -> Self {
        Self {
            name: None,
            index: 0,
            protector: None,
            notes: Vec::new(),
            #[cfg(target_os = "macos")]
            live: None,
        }
    }

    pub fn prepare(
        addr: Option<&TunAddress>,
        outbounds: &std::collections::BTreeMap<String, Value>,
        relays: &[IpAddr],
    ) -> Result<Self, String> {
        let Some(addr) = addr else {
            return Ok(Self::inactive());
        };
        #[cfg(target_os = "macos")]
        {
            sys::bring_up(addr, outbounds, relays)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (addr, outbounds, relays);
            Err("tun mode is macOS only".into())
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Interface index for `IP_BOUND_IF`: the physical NIC, never the utun.
    /// Zero when tun mode is off.
    pub fn interface_index(&self) -> u32 {
        self.index
    }

    pub fn protector(&self) -> Option<Arc<dyn SocketProtector>> {
        self.protector
            .clone()
            .map(|p| p as Arc<dyn SocketProtector>)
    }

    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Borrowed utun descriptor, still owned here. `None` when tun is off.
    pub fn raw_fd(&self) -> Option<std::os::raw::c_int> {
        #[cfg(target_os = "macos")]
        {
            self.live.as_ref().and_then(|l| l.raw_fd())
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Delete routes, then close the utun. Safe to call more than once.
    pub fn shutdown(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(live) = self.live.as_mut() {
            live.shutdown();
        }
    }
}

impl Drop for TunSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use std::ffi::CString;
    use std::io::{self, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        encode_get, encode_route, exclusion_routes, exit_targets, ioc_in, parse_route,
        split_defaults, ExitTargets, InterfaceBind, PhysicalPath, RouteOp, TunAddress, TunSession,
    };

    const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    /// Darwin `SO_DOMAIN` (`sys/socket.h`). Not in the libc crate we build with.
    const SO_DOMAIN: libc::c_int = 0x1010;
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;
    const IN6_IFF_NODAD: u32 = 0x0020;
    const IN6_IFF_SECURED: u32 = 0x0400;

    pub struct LiveTun {
        fd: Option<OwnedFd>,
        /// utun name for `SIOCIFDESTROY`. Empty for a test fd that is not a utun.
        name: String,
        routes: Vec<super::RouteSpec>,
    }

    impl LiveTun {
        pub fn raw_fd(&self) -> Option<RawFd> {
            self.fd.as_ref().map(|fd| fd.as_raw_fd())
        }

        pub fn shutdown(&mut self) {
            // Routes first. They point at this utun; a split default left
            // behind blackholes the host until something else deletes it.
            let routes = std::mem::take(&mut self.routes);
            for spec in routes.into_iter().rev() {
                if let Err(e) = write_route(&spec, RouteOp::Delete) {
                    if e.raw_os_error() != Some(libc::ESRCH) {
                        eprintln!("segue-kernel: remove route {spec}: {e}");
                    }
                }
            }
            // The packet runtime (`TunFdClosePolicy::Borrowed`) holds a
            // duplicate of this control socket and does not close the
            // caller's descriptor. The caller stops that runtime first, so
            // this close is the last reference, and the utun disappears with
            // it. SIGKILL never reaches this function: the kernel closes
            // whatever fds the process still holds, which is the only
            // teardown a killed process gets.
            if let Some(fd) = self.fd.take() {
                close_control(fd);
            }
            // Closing the control fd is what destroys a utun. `SIOCIFDESTROY`
            // covers a graceful stop whose last close did not tear the
            // interface down. It cannot run after SIGKILL.
            if !self.name.is_empty() {
                if let Err(e) = destroy_interface(&self.name) {
                    if e.raw_os_error() != Some(libc::ENXIO)
                        && e.raw_os_error() != Some(libc::EINVAL)
                    {
                        eprintln!("segue-kernel: destroy {}: {e}", self.name);
                    }
                }
                self.name.clear();
            }
        }
    }

    /// One `close`. Not retried: after `EINTR` the descriptor's state is
    /// unspecified, and a second close can hit a number the kernel has reused.
    fn close_control(fd: OwnedFd) {
        use std::os::fd::IntoRawFd;
        let raw = fd.into_raw_fd();
        // SAFETY: `raw` is the control descriptor this `OwnedFd` owned.
        let rc = unsafe { libc::close(raw) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EBADF) {
                eprintln!("segue-kernel: close utun: {err}");
            }
        }
    }

    fn destroy_interface(name: &str) -> io::Result<()> {
        let sock = inet_socket(libc::AF_INET)?;
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        set_ifr_name(&mut ifr.ifr_name, name)?;
        ioctl(sock.as_raw_fd(), libc::SIOCIFDESTROY, &mut ifr)
    }

    pub fn bring_up(
        addr: &TunAddress,
        outbounds: &std::collections::BTreeMap<String, serde_json::Value>,
        relays: &[IpAddr],
    ) -> Result<TunSession, String> {
        let (fd, name, index) = open_utun().map_err(|e| format!("utun: {e}"))?;
        let result = configure(&fd, &name, index, addr, outbounds, relays);
        match result {
            Ok((routes, notes, physical)) => Ok(TunSession {
                name: Some(name.clone()),
                // The index callers bind to is the physical NIC, not the utun.
                index: physical,
                protector: Some(Arc::new(InterfaceBind::new(physical))),
                notes,
                live: Some(LiveTun {
                    fd: Some(fd),
                    name,
                    routes,
                }),
            }),
            Err(e) => {
                drop(fd);
                Err(e)
            }
        }
    }

    fn configure(
        _fd: &OwnedFd,
        name: &str,
        index: u32,
        addr: &TunAddress,
        outbounds: &std::collections::BTreeMap<String, serde_json::Value>,
        relays: &[IpAddr],
    ) -> Result<(Vec<super::RouteSpec>, Vec<String>, u32), String> {
        set_mtu(name, addr.mtu).map_err(|e| format!("tun mtu: {e}"))?;
        set_v4(name, addr).map_err(|e| format!("tun address: {e}"))?;
        if let Some(v6) = &addr.v6 {
            set_v6(name, v6).map_err(|e| format!("tun ipv6: {e}"))?;
        }
        let targets = resolve_targets(exit_targets(outbounds, relays));
        let v4_probe =
            first_family(&targets.ips, true).unwrap_or(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let v4 = probe(v4_probe).map_err(|e| format!("physical route for {v4_probe}: {e}"))?;
        if tunnel_name(&v4.name) {
            return Err(format!(
                "default route is already on {} ({}); disconnect it before starting the utun",
                v4.name, v4_probe
            ));
        }
        let v6_probe = first_family(&targets.ips, false)
            .unwrap_or(IpAddr::V6("2606:4700:4700::1111".parse().unwrap()));
        let v6 = match probe(v6_probe) {
            Ok(path) if !tunnel_name(&path.name) => Some(path),
            Ok(path) => {
                return Err(format!(
                    "IPv6 default route is already on {} ({})",
                    path.name, v6_probe
                ));
            }
            Err(e) => {
                if targets.ips.iter().any(|ip| ip.is_ipv6()) {
                    return Err(format!("physical route for {v6_probe}: {e}"));
                }
                None
            }
        };
        let mut notes = vec![format!(
            "utun {name} index {index} mtu {}, physical {} via {} (if {})",
            addr.mtu, v4.name, v4.path.gateway, v4.path.index
        )];
        if let Some(v6) = &v6 {
            notes.push(format!(
                "physical v6 {} via {} (if {})",
                v6.name, v6.path.gateway, v6.path.index
            ));
        } else if addr.v6.is_some() {
            notes.push(
                "no IPv6 physical gateway; v6 split routes still capture ::/1 and 8000::/1".into(),
            );
        }
        let exclusions = exclusion_routes(
            &targets.ips,
            Some(&v4.path),
            v6.as_ref().map(|p| &p.path),
            addr,
        )?;
        let mut specs = exclusions;
        specs.extend(split_defaults(addr, index));
        install(&specs).map_err(|e| format!("route: {e}"))?;
        notes.push(format!("installed {} routes", specs.len()));
        Ok((specs, notes, v4.path.index))
    }

    fn first_family(ips: &[IpAddr], v4: bool) -> Option<IpAddr> {
        ips.iter().copied().find(|ip| ip.is_ipv4() == v4)
    }

    fn tunnel_name(name: &str) -> bool {
        let n = name.as_bytes();
        let starts = |p: &[u8]| n.len() >= p.len() && n[..p.len()].eq_ignore_ascii_case(p);
        starts(b"utun") || starts(b"ipsec") || starts(b"ppp") || name == "lo0"
    }

    fn resolve_targets(mut targets: ExitTargets) -> ExitTargets {
        for name in &targets.names {
            match (name.as_str(), 0u16).to_socket_addrs_note() {
                Ok(ips) => targets.ips.extend(ips),
                Err(e) => eprintln!("segue-kernel: resolve {name}: {e}"),
            }
        }
        targets.names.clear();
        targets.ips.sort();
        targets.ips.dedup();
        targets
    }

    trait ResolveNote {
        fn to_socket_addrs_note(&self) -> io::Result<Vec<IpAddr>>;
    }

    impl ResolveNote for (&str, u16) {
        fn to_socket_addrs_note(&self) -> io::Result<Vec<IpAddr>> {
            use std::net::ToSocketAddrs;
            Ok(self
                .to_socket_addrs()?
                .map(|sa| sa.ip())
                .filter(|ip| super::usable(*ip))
                .collect())
        }
    }

    struct FoundPath {
        path: PhysicalPath,
        name: String,
    }

    fn probe(dest: IpAddr) -> io::Result<FoundPath> {
        let sock = route_socket()?;
        let msg = encode_get(dest, 1);
        write_all(sock.as_raw_fd(), &msg)?;
        set_recv_timeout(sock.as_raw_fd(), Duration::from_secs(2))?;
        let mut buf = vec![0u8; 2048];
        // SAFETY: getpid is a pure read of the process id.
        let pid = unsafe { libc::getpid() };
        let started = std::time::Instant::now();
        loop {
            if started.elapsed() > Duration::from_secs(2) {
                return Err(io::Error::new(ErrorKind::TimedOut, "RTM_GET timed out"));
            }
            let n = read_fd(sock.as_raw_fd(), &mut buf)?;
            let Some(parsed) = parse_route(&buf[..n]) else {
                continue;
            };
            if parsed.seq != 1 || parsed.pid != pid {
                continue;
            }
            if parsed.errno != 0 {
                return Err(io::Error::from_raw_os_error(parsed.errno));
            }
            let index = parsed.index as u32;
            if index == 0 {
                return Err(io::Error::other("RTM_GET returned no interface"));
            }
            let name = if_name(index)?;
            let (gateway, on_link) = if let Some(gw) = parsed.gateway {
                if gw.is_unspecified() {
                    (dest, true)
                } else {
                    (gw, false)
                }
            } else if parsed.link_index.is_some() {
                (dest, true)
            } else {
                return Err(io::Error::other("RTM_GET returned no gateway"));
            };
            return Ok(FoundPath {
                path: PhysicalPath {
                    gateway,
                    index,
                    on_link,
                },
                name,
            });
        }
    }

    fn install(specs: &[super::RouteSpec]) -> io::Result<()> {
        for (done, spec) in specs.iter().enumerate() {
            if let Err(e) = add_one(spec) {
                for added in specs[..done].iter().rev() {
                    let _ = write_route(added, RouteOp::Delete);
                }
                return Err(io::Error::new(e.kind(), format!("add {spec}: {e}")));
            }
        }
        Ok(())
    }

    fn add_one(spec: &super::RouteSpec) -> io::Result<()> {
        match write_route(spec, RouteOp::Add) {
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                let _ = write_route(spec, RouteOp::Delete);
                write_route(spec, RouteOp::Add)
            }
            other => other,
        }
    }

    fn write_route(spec: &super::RouteSpec, op: RouteOp) -> io::Result<()> {
        let msg =
            encode_route(spec, op, 1).map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let sock = route_socket()?;
        write_all(sock.as_raw_fd(), &msg)
    }

    fn route_socket() -> io::Result<OwnedFd> {
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket() just returned this descriptor, and nothing else owns it.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        set_cloexec(fd.as_raw_fd())?;
        Ok(fd)
    }

    fn open_utun() -> io::Result<(OwnedFd, String, u32)> {
        // SAFETY: a fresh PF_SYSTEM socket. ctl_info and sockaddr_ctl are
        // zeroed and then filled to the sizes Darwin's utun control expects,
        // the same sequence as sing-tun's create() and the tun_lab example.
        unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);
            set_cloexec(fd.as_raw_fd())?;
            let mut info: libc::ctl_info = std::mem::zeroed();
            for (dst, src) in info.ctl_name.iter_mut().zip(UTUN_CONTROL) {
                *dst = *src as libc::c_char;
            }
            if libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut info) < 0 {
                return Err(io::Error::last_os_error());
            }
            let addr = libc::sockaddr_ctl {
                sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };
            if libc::connect(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_ctl).cast(),
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut name = [0u8; libc::IFNAMSIZ];
            let mut len = name.len() as libc::socklen_t;
            if libc::getsockopt(
                fd.as_raw_fd(),
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
            let name = String::from_utf8_lossy(&name[..end]).into_owned();
            let index = if_index(&name)?;
            Ok((fd, name, index))
        }
    }

    fn set_mtu(name: &str, mtu: u32) -> io::Result<()> {
        let sock = inet_socket(libc::AF_INET)?;
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        set_ifr_name(&mut ifr.ifr_name, name)?;
        ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        let cmd = ioc_in(b'i', 52, std::mem::size_of::<libc::ifreq>()) as libc::c_ulong;
        ioctl(sock.as_raw_fd(), cmd, &mut ifr)
    }

    fn set_v4(name: &str, addr: &TunAddress) -> io::Result<()> {
        let sock = inet_socket(libc::AF_INET)?;
        let mut req: libc::ifaliasreq = unsafe { std::mem::zeroed() };
        set_ifr_name(&mut req.ifra_name, name)?;
        req.ifra_addr = v4_sockaddr(addr.v4);
        req.ifra_broadaddr = v4_sockaddr(addr.v4_peer);
        req.ifra_mask = v4_sockaddr(prefix_mask_v4(addr.v4_prefix));
        let cmd = ioc_in(b'i', 26, std::mem::size_of::<libc::ifaliasreq>()) as libc::c_ulong;
        ioctl(sock.as_raw_fd(), cmd, &mut req)
    }

    fn set_v6(name: &str, addr: &super::V6Address) -> io::Result<()> {
        let sock = inet_socket(libc::AF_INET6)?;
        let req = v6_alias(name, addr)?;
        // SIOCAIFADDR_IN6 is `_IOW('i', 26, struct in6_aliasreq)` and that
        // struct is 128 bytes (sing-tun's constant 0x8080691a).
        let cmd = ioc_in(b'i', 26, req.len()) as libc::c_ulong;
        ioctl(sock.as_raw_fd(), cmd, req.as_ptr() as *mut u8)
    }

    fn v6_alias(name: &str, addr: &super::V6Address) -> io::Result<[u8; 128]> {
        let bytes = name.as_bytes();
        if bytes.len() >= 16 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        let mut buf = [0u8; 128];
        buf[..bytes.len()].copy_from_slice(bytes);
        write_in6(&mut buf[16..44], &addr.addr.octets());
        write_in6(&mut buf[44..72], &addr.peer.octets());
        let mut mask = [0u8; 16];
        mask.copy_from_slice(&super::mask_octets(addr.prefix, 16));
        write_in6(&mut buf[72..100], &mask);
        let flags = IN6_IFF_NODAD | IN6_IFF_SECURED;
        buf[100..104].copy_from_slice(&flags.to_ne_bytes());
        buf[120..124].copy_from_slice(&u32::MAX.to_ne_bytes());
        buf[124..128].copy_from_slice(&u32::MAX.to_ne_bytes());
        Ok(buf)
    }

    fn write_in6(dst: &mut [u8], addr: &[u8; 16]) {
        dst[0] = 28;
        dst[1] = super::AF_INET6;
        dst[8..24].copy_from_slice(addr);
    }

    fn v4_sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        sin.sin_addr = libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        };
        let mut sa: libc::sockaddr = unsafe { std::mem::zeroed() };
        // SAFETY: on Darwin sockaddr and sockaddr_in are both 16 bytes. The
        // macos test asserts that, and the copy is that many bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&sin as *const libc::sockaddr_in).cast::<u8>(),
                (&mut sa as *mut libc::sockaddr).cast::<u8>(),
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }
        sa
    }

    fn prefix_mask_v4(prefix: u8) -> Ipv4Addr {
        let mut o = [0u8; 4];
        o.copy_from_slice(&super::mask_octets(prefix, 4));
        Ipv4Addr::from(o)
    }

    pub fn bind_fd(fd: RawFd, index: u32) -> io::Result<()> {
        let v = index as libc::c_int;
        let domain = socket_domain(fd);
        let attempts: &[(libc::c_int, libc::c_int)] = match domain {
            Some(d) if d == libc::AF_INET6 => &[(libc::IPPROTO_IPV6, IPV6_BOUND_IF)],
            Some(_) => &[(libc::IPPROTO_IP, IP_BOUND_IF)],
            None => &[
                (libc::IPPROTO_IP, IP_BOUND_IF),
                (libc::IPPROTO_IPV6, IPV6_BOUND_IF),
            ],
        };
        let mut last = io::Error::other("IP_BOUND_IF");
        for &(level, name) in attempts {
            // SAFETY: `v` is a live c_int and `fd` is a caller-owned socket.
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    name,
                    (&v as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc == 0 {
                return Ok(());
            }
            last = io::Error::last_os_error();
        }
        Err(last)
    }

    fn socket_domain(fd: RawFd) -> Option<libc::c_int> {
        let mut domain: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: domain and len are live and match the getsockopt contract.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_DOMAIN,
                (&mut domain as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        (rc == 0).then_some(domain)
    }

    fn inet_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socket() just returned this descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        set_cloexec(fd.as_raw_fd())?;
        Ok(fd)
    }

    fn if_index(name: &str) -> io::Result<u32> {
        let c = CString::new(name)
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "interface name"))?;
        // SAFETY: `c` is a NUL-terminated name that outlives the call.
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(idx)
    }

    fn if_name(index: u32) -> io::Result<String> {
        let mut buf = [0u8; libc::IFNAMSIZ];
        // SAFETY: buf is IFNAMSIZ bytes, which is what if_indextoname writes.
        let rc = unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast()) };
        if rc.is_null() {
            return Err(io::Error::last_os_error());
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
    }

    fn set_ifr_name(dst: &mut [libc::c_char], name: &str) -> io::Result<()> {
        let bytes = name.as_bytes();
        if bytes.len() >= dst.len() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        for (slot, byte) in dst.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        Ok(())
    }

    fn set_cloexec(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn set_recv_timeout(fd: RawFd, dur: Duration) -> io::Result<()> {
        let tv = libc::timeval {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_usec: dur.subsec_micros() as libc::suseconds_t,
        };
        // SAFETY: tv is a live timeval of the length passed.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn ioctl<T>(fd: RawFd, cmd: libc::c_ulong, arg: *mut T) -> io::Result<()> {
        // SAFETY: caller passes a live object of the type the ioctl number encodes.
        if unsafe { libc::ioctl(fd, cmd, arg) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn write_all(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            // SAFETY: buf is the caller's message and stays borrowed for the write.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            buf = &buf[n as usize..];
        }
        Ok(())
    }

    fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: buf is writable for buf.len() and owned by the caller.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(n as usize);
        }
    }

    #[cfg(test)]
    mod tests {
        use std::os::fd::{FromRawFd, OwnedFd, RawFd};

        use super::super::TunSession;
        use super::LiveTun;

        fn pipe_ends() -> (OwnedFd, RawFd, RawFd) {
            let mut ends = [0; 2];
            assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
            // SAFETY: pipe() just returned this read end.
            let owned = unsafe { OwnedFd::from_raw_fd(ends[0]) };
            (owned, ends[0], ends[1])
        }

        fn session_holding(fd: OwnedFd) -> TunSession {
            TunSession {
                name: None,
                index: 0,
                protector: None,
                notes: Vec::new(),
                // Empty name: this fd is a pipe, not a utun. `SIOCIFDESTROY`
                // must not run against a real interface.
                live: Some(LiveTun {
                    fd: Some(fd),
                    name: String::new(),
                    routes: Vec::new(),
                }),
            }
        }

        fn assert_closed(raw: RawFd) {
            let rc = unsafe { libc::fcntl(raw, libc::F_GETFD) };
            let err = std::io::Error::last_os_error();
            assert_eq!(rc, -1);
            assert_eq!(err.raw_os_error(), Some(libc::EBADF), "{err}");
        }

        #[test]
        fn shutdown_closes_an_injected_control_fd() {
            let (fd, raw, write) = pipe_ends();
            let mut session = session_holding(fd);
            session.shutdown();
            assert_closed(raw);
            // Idempotent: the descriptor is already gone, routes too.
            session.shutdown();
            unsafe { libc::close(write) };
        }

        #[test]
        fn drop_closes_an_injected_control_fd() {
            let (fd, raw, write) = pipe_ends();
            {
                let _session = session_holding(fd);
            }
            assert_closed(raw);
            unsafe { libc::close(write) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(target_os = "macos")]
    use std::net::SocketAddr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn tun() -> TunAddress {
        TunAddress::default()
    }

    #[test]
    fn default_address_and_mtu() {
        let t = tun();
        assert_eq!(t.mtu, 1500);
        assert_eq!(t.v4, Ipv4Addr::new(172, 19, 0, 1));
        assert_eq!(t.v4_prefix, 30);
        assert_eq!(t.v4_peer, Ipv4Addr::new(172, 19, 0, 2));
        let v6 = t.v6.unwrap();
        assert_eq!(v6.addr, "fd00:5e9e::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6.prefix, 64);
        assert_eq!(v6.peer, "fd00:5e9e::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn rejects_bad_address_and_mtu() {
        let err = TunAddress::from_parts(1279, DEFAULT_IPV4, DEFAULT_IPV4_PEER, false, None, None)
            .unwrap_err();
        assert!(err.contains("mtu"), "{err}");
        let err = TunAddress::from_parts(1500, "172.19.0.1/30", "10.0.0.1", false, None, None)
            .unwrap_err();
        assert!(err.contains("outside"), "{err}");
        let err = TunAddress::from_parts(1500, "127.0.0.1/8", "127.0.0.2", false, None, None)
            .unwrap_err();
        assert!(err.contains("unicast"), "{err}");
        let err = TunAddress::from_parts(
            1500,
            DEFAULT_IPV4,
            DEFAULT_IPV4_PEER,
            true,
            Some("fd00::1/64"),
            None,
        )
        .unwrap_err();
        assert!(err.contains("ipv6_peer"), "{err}");
        let ok = TunAddress::from_parts(1500, "10.7.0.1/32", "10.7.0.2", false, None, None);
        assert!(ok.is_ok(), "{ok:?}");
    }

    #[test]
    fn fake_ip_range_must_not_contain_the_utun_address() {
        let t = tun();
        assert!(!t.overlaps_fake(Ipv4Addr::new(198, 18, 0, 0), 15));
        assert!(t.overlaps_fake(Ipv4Addr::new(172, 19, 0, 0), 16));
    }

    #[test]
    fn split_defaults_are_the_two_halves() {
        let routes = split_defaults(&tun(), 12);
        let got: Vec<_> = routes.iter().map(|r| (r.destination, r.prefix)).collect();
        assert_eq!(
            got,
            vec![
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
                (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
                (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
                (IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
            ]
        );
        assert!(routes.iter().all(|r| matches!(
            r.hop,
            NextHop::Gateway {
                index: 12,
                scope: false,
                ..
            }
        )));
        let v4_only =
            TunAddress::from_parts(1500, DEFAULT_IPV4, DEFAULT_IPV4_PEER, false, None, None)
                .unwrap();
        assert_eq!(split_defaults(&v4_only, 1).len(), 2);
    }

    #[test]
    fn exclusions_are_scoped_host_routes_and_skip_the_utun() {
        let v4 = PhysicalPath {
            gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            index: 5,
            on_link: false,
        };
        let targets = [
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6("2001:db8::9".parse().unwrap()),
        ];
        let err = exclusion_routes(&targets, Some(&v4), None, &tun()).unwrap_err();
        assert!(err.contains("2001:db8::9"), "{err}");
        let v6 = PhysicalPath {
            gateway: "fe80::1".parse().unwrap(),
            index: 5,
            on_link: false,
        };
        let routes = exclusion_routes(&targets, Some(&v4), Some(&v6), &tun()).unwrap();
        assert_eq!(routes.len(), 2, "{routes:?}");
        assert_eq!(routes[0].destination, targets[0]);
        assert_eq!(routes[0].prefix, 32);
        assert!(matches!(
            routes[0].hop,
            NextHop::Gateway {
                index: 5,
                scope: true,
                ..
            }
        ));
        assert_eq!(routes[1].prefix, 128);
        let on_link = PhysicalPath {
            gateway: targets[0],
            index: 5,
            on_link: true,
        };
        let routes = exclusion_routes(&targets[..1], Some(&on_link), None, &tun()).unwrap();
        assert!(matches!(routes[0].hop, NextHop::Interface { index: 5 }));
    }

    #[test]
    fn exit_targets_read_address_and_endpoint() {
        let specs = [
            (
                "proxy".into(),
                json!({"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.5","port":443}]}}),
            ),
            (
                "ss".into(),
                json!({"settings":{"servers":[{"address":"198.51.100.8","port":1}]}}),
            ),
            (
                "wg".into(),
                json!({"settings":{"peers":[{"endpoint":"192.0.2.9:51820"}]}}),
            ),
            (
                "v6".into(),
                json!({"settings":{"endpoint":"[2001:db8::5]:443"}}),
            ),
            ("name".into(), json!({"settings":{"address":"exit.example"}})),
            ("loop".into(), json!({"settings":{"address":"127.0.0.1"}})),
        ]
        .into_iter()
        .collect();
        let targets = exit_targets(
            &specs,
            &[
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ],
        );
        assert_eq!(
            targets.ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                "2001:db8::5".parse().unwrap(),
            ]
        );
        assert_eq!(targets.names, vec!["exit.example".to_string()]);
    }

    #[test]
    fn route_messages_round_trip() {
        let tun = tun();
        let split = &split_defaults(&tun, 12)[0];
        let add = encode_route(split, RouteOp::Add, 7).unwrap();
        let parsed = parse_route(&add).unwrap();
        assert_eq!(parsed.typ, RTM_ADD);
        assert_eq!(parsed.index, 12);
        assert_eq!(parsed.seq, 7);
        assert_eq!(parsed.destination, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(parsed.prefix, Some(1));
        assert_eq!(
            parsed.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)))
        );
        assert_eq!(parsed.flags & RTF_UP, RTF_UP);
        assert_eq!(parsed.flags & RTF_GATEWAY, RTF_GATEWAY);
        assert_eq!(parsed.flags & RTF_IFSCOPE, 0);
        assert_eq!(add.len(), u16::from_le_bytes([add[0], add[1]]) as usize);

        let del = encode_route(split, RouteOp::Delete, 8).unwrap();
        assert_eq!(parse_route(&del).unwrap().typ, RTM_DELETE);

        let high = &split_defaults(&tun, 3)[3];
        let parsed = parse_route(&encode_route(high, RouteOp::Add, 1).unwrap()).unwrap();
        assert_eq!(
            parsed.destination,
            Some(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)))
        );
        assert_eq!(parsed.prefix, Some(1));
        assert_eq!(parsed.gateway, Some(IpAddr::V6(tun.v6.unwrap().peer)));

        let host = RouteSpec {
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            prefix: 32,
            hop: NextHop::Gateway {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                index: 5,
                scope: true,
            },
        };
        let parsed = parse_route(&encode_route(&host, RouteOp::Add, 1).unwrap()).unwrap();
        assert_eq!(parsed.prefix, Some(32));
        assert_eq!(parsed.flags & RTF_HOST, RTF_HOST);
        assert_eq!(parsed.flags & RTF_IFSCOPE, RTF_IFSCOPE);
        assert_eq!(parsed.index, 5);
        assert_eq!(
            parsed.gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );

        let link = RouteSpec {
            destination: host.destination,
            prefix: 32,
            hop: NextHop::Interface { index: 5 },
        };
        let parsed = parse_route(&encode_route(&link, RouteOp::Add, 1).unwrap()).unwrap();
        assert_eq!(parsed.link_index, Some(5));
        assert!(parsed.gateway.is_none());
        assert_eq!(parsed.flags & RTF_GATEWAY, 0);

        let get = encode_get(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 4);
        let parsed = parse_route(&get).unwrap();
        assert_eq!(parsed.typ, RTM_GET);
        assert_eq!(
            parsed.destination,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        assert!(encode_route(
            &RouteSpec {
                destination: host.destination,
                prefix: 32,
                hop: NextHop::Interface { index: 70_000 },
            },
            RouteOp::Add,
            1
        )
        .is_err());
    }

    #[test]
    fn ioctl_numbers_match_darwin() {
        // `_IOW('i', 52, 32)` is SIOCSIFMTU when ifreq is 32 bytes, and
        // `_IOW('i', 26, 128)` is the SIOCAIFADDR_IN6 constant sing-tun uses.
        assert_eq!(ioc_in(b'i', 52, 32), 0x8020_6934);
        assert_eq!(ioc_in(b'i', 26, 128), 0x8080_691a);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn header_matches_the_darwin_rt_msghdr() {
        assert_eq!(HEADER_LEN, std::mem::size_of::<libc::rt_msghdr>());
        assert_eq!(std::mem::offset_of!(libc::rt_msghdr, rtm_flags), 8);
        assert_eq!(std::mem::offset_of!(libc::rt_msghdr, rtm_pid), 16);
        assert_eq!(std::mem::offset_of!(libc::rt_msghdr, rtm_seq), 20);
        assert_eq!(std::mem::offset_of!(libc::rt_msghdr, rtm_errno), 24);
        assert_eq!(std::mem::offset_of!(libc::rt_msghdr, rtm_rmx), 36);
        assert_eq!(std::mem::size_of::<libc::rt_metrics>(), 56);
        assert_eq!(AF_INET as i32, libc::AF_INET);
        assert_eq!(AF_INET6 as i32, libc::AF_INET6);
        assert_eq!(AF_LINK as i32, libc::AF_LINK);
        assert_eq!(RTM_ADD as i32, libc::RTM_ADD);
        assert_eq!(RTM_DELETE as i32, libc::RTM_DELETE);
        assert_eq!(RTM_GET as i32, libc::RTM_GET);
        assert_eq!(RTF_UP, libc::RTF_UP);
        assert_eq!(RTF_GATEWAY, libc::RTF_GATEWAY);
        assert_eq!(RTF_HOST, libc::RTF_HOST);
        assert_eq!(RTF_STATIC, libc::RTF_STATIC);
        assert_eq!(RTF_IFSCOPE, libc::RTF_IFSCOPE);
        assert_eq!(
            std::mem::size_of::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>()
        );
        assert_eq!(std::mem::size_of::<libc::ifreq>(), 32);
        assert_eq!(
            ioc_in(b'i', 121, std::mem::size_of::<libc::ifreq>()) as libc::c_ulong,
            libc::SIOCIFDESTROY
        );
    }

    #[test]
    fn prepare_without_tun_is_inert() {
        let session = TunSession::prepare(None, &std::collections::BTreeMap::new(), &[]).unwrap();
        assert!(session.name().is_none());
        assert!(session.protector().is_none());
        assert_eq!(session.interface_index(), 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn prepare_rejects_tun_off_macos() {
        let Err(err) = TunSession::prepare(
            Some(&TunAddress::default()),
            &std::collections::BTreeMap::new(),
            &[],
        ) else {
            panic!("a TUN session was prepared off macOS");
        };
        assert!(err.contains("macOS"), "{err}");
    }

    #[test]
    fn loopback_next_hop_is_not_pinned_to_the_nic() {
        let bind = InterfaceBind::new(1);
        let loopback = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "::ffff:127.0.0.1".parse().unwrap(),
            "::ffff:127.1.2.3".parse().unwrap(),
        ];
        for ip in loopback {
            assert!(destination_is_loopback(ip), "{ip}");
            assert!(!bind.protects_destination(ip), "{ip}");
        }
        let pinned = [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            "2001:db8::1".parse().unwrap(),
            "::ffff:8.8.8.8".parse().unwrap(),
            "fe80::1".parse().unwrap(),
        ];
        for ip in pinned {
            assert!(!destination_is_loopback(ip), "{ip}");
            assert!(bind.protects_destination(ip), "{ip}");
        }
    }

    #[cfg(target_os = "macos")]
    fn non_loopback_interface() -> u32 {
        let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
        for index in 1..128u32 {
            buf.fill(0);
            // SAFETY: buf is IFNAMSIZ bytes, which is what if_indextoname writes.
            let rc = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
            if rc.is_null() {
                continue;
            }
            let bytes: Vec<u8> = buf
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| *c as u8)
                .collect();
            let name = String::from_utf8_lossy(&bytes);
            if !name.starts_with("lo") {
                return index;
            }
        }
        panic!("no non-loopback interface; cannot prove IP_BOUND_IF is skipped");
    }

    #[cfg(target_os = "macos")]
    fn bound_if(fd: std::os::fd::RawFd, ipv6: bool) -> i32 {
        let mut value: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let (level, name) = if ipv6 {
            (libc::IPPROTO_IPV6, 125) // IPV6_BOUND_IF
        } else {
            (libc::IPPROTO_IP, 25) // IP_BOUND_IF
        };
        let rc = unsafe {
            libc::getsockopt(
                fd,
                level,
                name,
                (&mut value as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
        value
    }

    /// A protector pinned to a real NIC must still reach a loopback listener.
    /// Binding that socket to the NIC would make `127.0.0.1` / `::1` fail.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn protected_dial_reaches_a_loopback_listener() {
        use std::os::fd::AsRawFd;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let index = non_loopback_interface();
        let bind = InterfaceBind::new(index);

        let v4 = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let v4_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, v4.local_addr().unwrap().port()));
        let mut client = segue_transport::connect_tcp_stream(v4_addr, Some(&bind))
            .await
            .unwrap_or_else(|err| panic!("dial {v4_addr} via if {index}: {err}"));
        assert_eq!(
            bound_if(client.as_raw_fd(), false),
            0,
            "loopback dial was pinned to interface {index}"
        );
        client.write_all(b"v4").await.unwrap();
        let (mut accepted, _) = v4.accept().await.unwrap();
        let mut got = [0u8; 2];
        accepted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"v4");

        let v6 = tokio::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let v6_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, v6.local_addr().unwrap().port()));
        let mut client = segue_transport::connect_tcp_stream(v6_addr, Some(&bind))
            .await
            .unwrap_or_else(|err| panic!("dial {v6_addr} via if {index}: {err}"));
        assert_eq!(bound_if(client.as_raw_fd(), true), 0);
        client.write_all(b"v6").await.unwrap();
        let (mut accepted, _) = v6.accept().await.unwrap();
        accepted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"v6");
    }
}
