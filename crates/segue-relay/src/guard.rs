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
    "::/96",          // unspecified, loopback, IPv4-compatible
    "64:ff9b::/96",   // NAT64 (could reach internal IPv4)
    "64:ff9b:1::/48", // local-use NAT64
    "100::/64",       // discard
    "2001::/23",      // IETF protocol assignments incl. Teredo
    "2001:db8::/32",  // documentation
    "2002::/16",      // 6to4 (embeds arbitrary IPv4)
    "3fff::/20",      // documentation
    "fc00::/7",       // ULA (incl. fd00:ec2::254 metadata)
    "fe80::/10",      // link-local
    "fec0::/10",      // site-local (deprecated)
    "ff00::/8",       // multicast
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
        !is_forbidden(ip) && !is_local_addr(ip)
    }
}

/// The address belongs to this host (§5.5 item 2: the node's own
/// addresses). A public address bound on an interface would otherwise let a
/// target loop back into the node's own inbounds or local services. Cached
/// interface enumeration on Unix avoids a UDP bind syscall per connect; non-Unix
/// targets (and any enumeration failure) fall back to binding port 0.
pub fn is_local_addr(ip: IpAddr) -> bool {
    let ip = canon(ip);
    #[cfg(unix)]
    if let Some(hit) = check_local_unix(ip) {
        return hit;
    }
    std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)).is_ok()
}

#[cfg(unix)]
fn check_local_unix(ip: IpAddr) -> Option<bool> {
    use std::collections::HashSet;
    use std::sync::RwLock;
    use std::time::{Duration, Instant};

    const TTL: Duration = Duration::from_secs(30);
    static CACHE: OnceLock<RwLock<(Instant, HashSet<IpAddr>)>> = OnceLock::new();

    let lock = CACHE.get_or_init(|| {
        let ips = collect_unix_local_ips().unwrap_or_default();
        RwLock::new((Instant::now(), ips))
    });
    let now = Instant::now();
    {
        let guard = lock.read().unwrap_or_else(|e| e.into_inner());
        if now.saturating_duration_since(guard.0) < TTL && !guard.1.is_empty() {
            return Some(guard.1.contains(&ip));
        }
    }
    let fresh = collect_unix_local_ips()?;
    let hit = fresh.contains(&ip);
    let mut guard = lock.write().unwrap_or_else(|e| e.into_inner());
    *guard = (Instant::now(), fresh);
    Some(hit)
}

#[cfg(unix)]
fn collect_unix_local_ips() -> Option<std::collections::HashSet<IpAddr>> {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct IfAddrs(*mut libc::ifaddrs);
    impl Drop for IfAddrs {
        fn drop(&mut self) {
            // SAFETY: pointer obtained from `libc::getifaddrs` and owned solely here.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer for `getifaddrs`.
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return None;
    }
    let _guard = IfAddrs(head);
    let mut ips = HashSet::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null in the linked list owned by `_guard`.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is a valid socket address header.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            match family {
                libc::AF_INET => {
                    // SAFETY: `sa_family == AF_INET` implies `sockaddr_in`.
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    ips.insert(canon(IpAddr::V4(Ipv4Addr::from(
                        sin.sin_addr.s_addr.to_ne_bytes(),
                    ))));
                }
                libc::AF_INET6 => {
                    // SAFETY: `sa_family == AF_INET6` implies `sockaddr_in6`.
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    ips.insert(canon(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))));
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    Some(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_interface_addresses_are_detected() {
        assert!(is_local_addr("127.0.0.1".parse().unwrap()));
        assert!(is_local_addr("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_local_addr("1.1.1.1".parse().unwrap()));
        // The address of the default route's interface (no packet is sent).
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        if s.connect("1.1.1.1:53").is_ok() {
            let me = s.local_addr().unwrap().ip();
            assert!(is_local_addr(me));
            assert!(!Guard::default().allows(me));
        }
    }
}
