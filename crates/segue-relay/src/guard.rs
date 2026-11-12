//! SSRF guard for overseas and Home targets (KERNEL_SPEC §5.5 item 2).
//!
//! Applied to every address the relay would connect to (or hand to a SOCKS
//! line), after DNS resolution and also for IP literals. IPv4-mapped IPv6 is
//! checked as IPv4.

use std::net::IpAddr;
use std::sync::OnceLock;

use crate::cidr::{any_contains, canon, Cidr};

const BUILTIN: &[&str] = &[
    // IPv4
    "0.0.0.0/8",       // "this network"
    "10.0.0.0/8",      // RFC 1918
    "100.64.0.0/10",   // CGNAT
    "127.0.0.0/8",     // loopback
    "169.254.0.0/16",  // link-local, cloud metadata 169.254.169.254
    "172.16.0.0/12",   // RFC 1918
    "192.0.0.0/24",    // IETF protocol assignments
    "192.0.2.0/24",    // TEST-NET-1
    "192.88.99.0/24",  // 6to4 relay anycast
    "192.168.0.0/16",  // RFC 1918
    "198.18.0.0/15",   // benchmarking
    "198.51.100.0/24", // TEST-NET-2
    "203.0.113.0/24",  // TEST-NET-3
    "224.0.0.0/4",     // multicast
    "240.0.0.0/4",     // reserved, broadcast
    // IPv6
    "::/96",           // unspecified, loopback, IPv4-compatible
    "64:ff9b::/96",    // NAT64 (could reach internal IPv4)
    "64:ff9b:1::/48",  // local-use NAT64
    "100::/64",        // discard
    "2001::/23",       // IETF protocol assignments incl. Teredo
    "2001:db8::/32",   // documentation
    "2002::/16",       // 6to4 (embeds arbitrary IPv4)
    "3fff::/20",       // documentation
    "fc00::/7",        // ULA (incl. fd00:ec2::254 metadata)
    "fe80::/10",       // link-local
    "fec0::/10",       // site-local (deprecated)
    "ff00::/8",        // multicast
];

fn builtin() -> &'static [Cidr] {
    static SET: OnceLock<Vec<Cidr>> = OnceLock::new();
    SET.get_or_init(|| BUILTIN.iter().map(|s| Cidr::parse(s).unwrap()).collect())
}

/// Built-in forbidden ranges only.
pub fn is_forbidden(ip: IpAddr) -> bool {
    any_contains(builtin(), canon(ip))
}

#[derive(Clone, Debug, Default)]
pub struct Guard {
    /// Operator ranges: the node's own addresses, inter-node subnets.
    pub extra_blocked: Vec<Cidr>,
    /// Exceptions to the built-in ranges. Tests only: the config file has
    /// no field for it.
    pub exceptions: Vec<Cidr>,
}

impl Guard {
    pub fn new(extra_blocked: Vec<Cidr>) -> Self {
        Self {
            extra_blocked,
            exceptions: Vec::new(),
        }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = canon(ip);
        if any_contains(&self.extra_blocked, ip) {
            return false;
        }
        if any_contains(&self.exceptions, ip) {
            return true;
        }
        !is_forbidden(ip)
    }
}
