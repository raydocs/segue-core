//! IP prefixes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is treated as the IPv4 address.
pub fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn mask4(a: Ipv4Addr, p: u8) -> Ipv4Addr {
    let m = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    Ipv4Addr::from(u32::from(a) & m)
}

fn mask6(a: Ipv6Addr, p: u8) -> Ipv6Addr {
    let m = if p == 0 { 0 } else { u128::MAX << (128 - p) };
    Ipv6Addr::from(u128::from(a) & m)
}

impl Cidr {
    /// `a.b.c.d/n`, `x::y/n`, or a bare address (a host prefix).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip: IpAddr = a.parse().map_err(|_| format!("bad address in prefix {s:?}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|&p| p <= max)
                .ok_or_else(|| format!("bad prefix length in {s:?}"))?,
            None => max,
        };
        Ok(Self::new(ip, prefix))
    }

    pub fn new(ip: IpAddr, prefix: u8) -> Self {
        let net = match ip {
            IpAddr::V4(a) => IpAddr::V4(mask4(a, prefix.min(32))),
            IpAddr::V6(a) => IpAddr::V6(mask6(a, prefix.min(128))),
        };
        Self {
            net,
            prefix: if ip.is_ipv4() { prefix.min(32) } else { prefix.min(128) },
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canon(ip)) {
            (IpAddr::V4(n), IpAddr::V4(i)) => mask4(i, self.prefix) == n,
            (IpAddr::V6(n), IpAddr::V6(i)) => mask6(i, self.prefix) == n,
            _ => false,
        }
    }
}

pub fn any_contains(set: &[Cidr], ip: IpAddr) -> bool {
    set.iter().any(|c| c.contains(ip))
}
