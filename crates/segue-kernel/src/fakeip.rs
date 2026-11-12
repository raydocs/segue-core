//! Fake-IP pool (KERNEL_SPEC §5.2.2).
//!
//! Domains that will be proxied get a local address from a reserved IPv4
//! range instead of a real DNS answer. A later CONNECT to that address is
//! routed by the recorded domain, so the name, not a possibly polluted IP,
//! reaches the outer engine.
//!
//! Placement is deterministic: `sha256(key || domain) mod size`, then linear
//! probing on collision. With the same key a domain gets the same address
//! after a restart as long as nothing collided differently.
//!
//! Not done here: persisting the key and the collision table to disk every
//! 30 s (spec §5.2.2). The shell owns storage; until it passes a key in,
//! a random per-process key is used.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::rules::Action;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeEntry {
    pub domain: String,
    pub action: Action,
}

struct Slot {
    entry: FakeEntry,
    last_used: Instant,
}

struct Inner {
    by_offset: HashMap<u32, Slot>,
    by_domain: HashMap<String, u32>,
}

pub struct FakeIpPool {
    base: u32,
    prefix: u8,
    /// Usable offsets are 1..size-1 (network and broadcast addresses skipped).
    size: u32,
    key: [u8; 32],
    /// DNS TTL handed to clients.
    pub ttl: Duration,
    /// How long after its last use an entry can still be looked up. After
    /// that a CONNECT to the address is refused and the slot may be reused.
    lifetime: Duration,
    inner: Mutex<Inner>,
}

impl FakeIpPool {
    /// `base/prefix` must be an IPv4 range with prefix 8..=30.
    pub fn new(
        base: Ipv4Addr,
        prefix: u8,
        ttl: Duration,
        grace: Duration,
        key: [u8; 32],
    ) -> Result<Self, String> {
        if !(8..=30).contains(&prefix) {
            return Err(format!(
                "fake_ip_range prefix must be 8..=30, got /{prefix}"
            ));
        }
        let size = 1u32 << (32 - prefix);
        let base = u32::from(base) & !(size - 1);
        Ok(Self {
            base,
            prefix,
            size,
            key,
            ttl,
            lifetime: ttl + grace,
            inner: Mutex::new(Inner {
                by_offset: HashMap::new(),
                by_domain: HashMap::new(),
            }),
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => v4,
                None => return false,
            },
        };
        (u32::from(ip) >> (32 - self.prefix)) == (self.base >> (32 - self.prefix))
    }

    fn home(&self, domain: &str) -> u32 {
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(domain.as_bytes());
        let d = h.finalize();
        let v = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
        1 + v % (self.size - 2)
    }

    /// Address for `domain`, allocating one if needed. Refreshes its age.
    /// None when every slot is held by a live entry.
    pub fn assign(&self, domain: &str, action: Action) -> Option<Ipv4Addr> {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("fake-ip lock");
        if let Some(&off) = inner.by_domain.get(domain) {
            let slot = inner.by_offset.get_mut(&off).expect("index consistent");
            slot.last_used = now;
            slot.entry.action = action;
            return Some(self.addr(off));
        }
        let usable = self.size - 2;
        let start = self.home(domain);
        for i in 0..usable {
            let off = 1 + (start - 1 + i) % usable;
            let free = match inner.by_offset.get(&off) {
                None => true,
                Some(s) => now.duration_since(s.last_used) > self.lifetime,
            };
            if free {
                if let Some(old) = inner.by_offset.remove(&off) {
                    inner.by_domain.remove(&old.entry.domain);
                }
                inner.by_domain.insert(domain.to_owned(), off);
                inner.by_offset.insert(
                    off,
                    Slot {
                        entry: FakeEntry {
                            domain: domain.to_owned(),
                            action,
                        },
                        last_used: now,
                    },
                );
                return Some(self.addr(off));
            }
        }
        None
    }

    /// Reverse lookup for a CONNECT. Stale (past TTL + grace) or unknown
    /// addresses give None; the caller refuses the flow.
    pub fn lookup(&self, ip: IpAddr) -> Option<FakeEntry> {
        if !self.contains(ip) {
            return None;
        }
        let v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => v6.to_ipv4_mapped()?,
        };
        let off = u32::from(v4) - self.base;
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("fake-ip lock");
        let slot = inner.by_offset.get_mut(&off)?;
        if now.duration_since(slot.last_used) > self.lifetime {
            return None;
        }
        slot.last_used = now;
        Some(slot.entry.clone())
    }

    fn addr(&self, off: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base + off)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(prefix: u8, grace_ms: u64) -> FakeIpPool {
        FakeIpPool::new(
            "198.18.0.0".parse().unwrap(),
            prefix,
            Duration::from_millis(0),
            Duration::from_millis(grace_ms),
            [7; 32],
        )
        .unwrap()
    }

    #[test]
    fn deterministic_and_reversible() {
        let a = pool(15, 60_000);
        let b = pool(15, 60_000);
        let px = Action::Proxy("p".into());
        let ip = a.assign("api.openai.com", px.clone()).unwrap();
        assert_eq!(
            b.assign("api.openai.com", px.clone()),
            Some(ip),
            "same key, same address"
        );
        assert_eq!(
            a.assign("api.openai.com", px.clone()),
            Some(ip),
            "stable on re-ask"
        );
        assert!(a.contains(ip.into()));
        assert_eq!(a.lookup(ip.into()).unwrap().domain, "api.openai.com");
        assert_eq!(a.lookup("198.18.255.254".parse().unwrap()), None);
        assert_eq!(a.lookup("8.8.8.8".parse().unwrap()), None);
        let mapped: IpAddr = format!("::ffff:{ip}").parse().unwrap();
        assert!(a.lookup(mapped).is_some());
    }

    #[test]
    fn collisions_probe_and_full_pool() {
        // /30 has two usable addresses.
        let p = pool(30, 60_000);
        let px = Action::Proxy("p".into());
        let x = p.assign("a.com", px.clone()).unwrap();
        let y = p.assign("b.com", px.clone()).unwrap();
        assert_ne!(x, y);
        assert_eq!(p.assign("c.com", px), None, "full of live entries");
    }

    #[test]
    fn stale_entries_refused_and_reused() {
        let p = pool(30, 20);
        let px = Action::Proxy("p".into());
        let x = p.assign("a.com", px.clone()).unwrap();
        let _ = p.assign("b.com", px.clone()).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(p.lookup(x.into()), None, "past grace: refused");
        assert!(p.assign("c.com", px).is_some(), "stale slot reused");
    }

    #[test]
    fn bad_prefix() {
        let k = [0; 32];
        let d = Duration::from_secs(1);
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 31, d, d, k).is_err());
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 4, d, d, k).is_err());
    }
}
