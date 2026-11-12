//! Fake-IP pool (KERNEL_SPEC §5.2.2).
//!
//! Domains that will be proxied get a local address from a reserved IPv4
//! range instead of a real DNS answer. A later flow to that address is
//! routed by the recorded domain, so the name, not a possibly polluted IP,
//! reaches the outer engine.
//!
//! The pool stores only the domain (and the policy version it was handed out
//! under), never a routing decision: every new flow re-authorizes the domain
//! against the policy in force at that moment.
//!
//! Placement is deterministic: `sha256(key || domain) mod size`, then linear
//! probing on collision. With the same key (persisted with the mapping, see
//! [`FakeIpPool::save`]) a domain gets the same address after a restart.
//!
//! Address lifecycle. An address is never reinterpreted as another domain
//! while a client may still hold it:
//!
//! - **live** (`age ≤ ttl + grace`): lookups return the domain and refresh
//!   its age;
//! - **quarantined** (`ttl + grace < age ≤ ttl + grace + quarantine`):
//!   lookups are refused; only the same domain may take the address back;
//! - **free** after that.
//!
//! When no free address is left, or the pool already tracks `max_entries`
//! addresses, allocation fails (the DNS answers SERVFAIL) rather than reuse
//! a quarantined one.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default time an expired address stays out of circulation.
pub const DEFAULT_QUARANTINE: Duration = Duration::from_secs(6 * 3600);
/// Default cap on tracked (live + quarantined) addresses.
pub const DEFAULT_MAX_ENTRIES: usize = 16_384;
/// Refresh-only changes (last-use times) are saved this often (spec: 30 s).
pub const SAVE_INTERVAL: Duration = Duration::from_secs(30);
/// A new allocation is saved within this long, so a crash can lose at most
/// this much of the mapping.
pub const NEW_SAVE_INTERVAL: Duration = Duration::from_secs(1);

const STATE_FORMAT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeEntry {
    pub domain: String,
    /// Policy version in force when the address was handed out. Informational:
    /// flows re-authorize the domain against the current policy.
    pub version: u64,
}

struct Slot {
    domain: String,
    version: u64,
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
    /// How long after its last use an entry can still be looked up.
    lifetime: Duration,
    /// After `lifetime`, how long the address stays reserved for its domain.
    quarantine: Duration,
    max_entries: usize,
    inner: Mutex<Inner>,
    /// Something changed since the last save.
    dirty: AtomicBool,
    /// A new address was allocated since the last save.
    allocated: AtomicBool,
}

#[derive(Serialize, Deserialize)]
struct State {
    format: u32,
    /// Base64 placement key.
    key: String,
    /// `base/prefix` the offsets refer to.
    range: String,
    /// Unix seconds at save time.
    saved_at: u64,
    /// (offset, domain, policy version, seconds since last use at save).
    entries: Vec<(u32, String, u64, u64)>,
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
            quarantine: DEFAULT_QUARANTINE,
            max_entries: DEFAULT_MAX_ENTRIES,
            inner: Mutex::new(Inner {
                by_offset: HashMap::new(),
                by_domain: HashMap::new(),
            }),
            dirty: AtomicBool::new(false),
            allocated: AtomicBool::new(false),
        })
    }

    /// Override the quarantine and the tracked-address cap.
    pub fn with_limits(mut self, quarantine: Duration, max_entries: usize) -> Self {
        self.quarantine = quarantine;
        self.max_entries = max_entries.max(1);
        self
    }

    /// Build a pool from the state file at `path` (key + mapping), or with a
    /// fresh random key when there is none. Returns log lines.
    pub fn open(
        base: Ipv4Addr,
        prefix: u8,
        ttl: Duration,
        grace: Duration,
        quarantine: Duration,
        max_entries: usize,
        path: Option<&Path>,
    ) -> Result<(Self, Vec<String>), String> {
        let mut log = Vec::new();
        let fresh = || {
            Self::new(base, prefix, ttl, grace, rand::random())
                .map(|p| p.with_limits(quarantine, max_entries))
        };
        let Some(path) = path else {
            log.push("fake-ip: no state file; addresses are stable for this process only".into());
            return Ok((fresh()?, log));
        };
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                log.push(format!("fake-ip: new state {}", path.display()));
                return Ok((fresh()?, log));
            }
            Err(e) => return Err(format!("fake-ip state {}: {e}", path.display())),
        };
        match Self::restore(base, prefix, ttl, grace, &bytes, crate::policy::unix_now()) {
            Ok((pool, n)) => {
                log.push(format!(
                    "fake-ip: restored key and {n} entries from {}",
                    path.display()
                ));
                Ok((pool.with_limits(quarantine, max_entries), log))
            }
            Err(e) => {
                log.push(format!(
                    "fake-ip: state {} unusable ({e}); starting with a new key",
                    path.display()
                ));
                Ok((fresh()?, log))
            }
        }
    }

    fn restore(
        base: Ipv4Addr,
        prefix: u8,
        ttl: Duration,
        grace: Duration,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<(Self, usize), String> {
        let st: State = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if st.format != STATE_FORMAT {
            return Err(format!("format {}", st.format));
        }
        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&st.key)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "key must be 32 bytes".to_string())?;
        let pool = Self::new(base, prefix, ttl, grace, key)?;
        if st.range != pool.range() {
            // Offsets refer to another range: keep the key only.
            return Ok((pool, 0));
        }
        // Time the kernel was down counts as idle time (a clock that went
        // backwards counts as none).
        let down = now_unix.saturating_sub(st.saved_at);
        let now = Instant::now();
        let keep = pool.lifetime + pool.quarantine;
        let mut n = 0;
        {
            let mut inner = pool.inner.lock().expect("fake-ip lock");
            for (off, domain, version, idle) in st.entries {
                if off == 0 || off >= pool.size - 1 || domain.is_empty() {
                    continue;
                }
                let idle = Duration::from_secs(idle.saturating_add(down));
                if idle > keep
                    || inner.by_offset.contains_key(&off)
                    || inner.by_domain.contains_key(&domain)
                {
                    continue;
                }
                // Early after boot `now - idle` may not exist: treat as just
                // used (the mapping stays reserved longer, never shorter).
                let last_used = now.checked_sub(idle).unwrap_or(now);
                inner.by_domain.insert(domain.clone(), off);
                inner.by_offset.insert(
                    off,
                    Slot {
                        domain,
                        version,
                        last_used,
                    },
                );
                n += 1;
            }
        }
        Ok((pool, n))
    }

    fn range(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }

    /// Serialized key + mapping (live and quarantined addresses).
    pub fn snapshot(&self) -> Vec<u8> {
        let now = Instant::now();
        let keep = self.lifetime + self.quarantine;
        let inner = self.inner.lock().expect("fake-ip lock");
        let entries = inner
            .by_offset
            .iter()
            .filter_map(|(&off, s)| {
                let idle = now.duration_since(s.last_used);
                (idle <= keep).then(|| (off, s.domain.clone(), s.version, idle.as_secs()))
            })
            .collect();
        drop(inner);
        let st = State {
            format: STATE_FORMAT,
            key: base64::engine::general_purpose::STANDARD.encode(self.key),
            range: self.range(),
            saved_at: crate::policy::unix_now(),
            entries,
        };
        serde_json::to_vec(&st).expect("state serializes")
    }

    /// True when a new allocation has not been saved yet.
    pub fn has_unsaved_allocation(&self) -> bool {
        self.allocated.load(Ordering::Acquire)
    }

    /// Write the state to `path` (atomically, owner-only) if anything
    /// changed since the last save. Returns whether it wrote.
    pub fn save(&self, path: &Path) -> std::io::Result<bool> {
        self.allocated.store(false, Ordering::Release);
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        let bytes = self.snapshot();
        let tmp = path.with_extension("tmp");
        let r = (|| {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if r.is_err() {
            self.dirty.store(true, Ordering::Release);
            self.allocated.store(true, Ordering::Release);
        }
        r.map(|()| true)
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

    /// Drop every address past its quarantine.
    fn prune(&self, inner: &mut Inner, now: Instant) {
        let keep = self.lifetime + self.quarantine;
        let Inner {
            by_offset,
            by_domain,
        } = inner;
        by_offset.retain(|_, s| {
            let alive = now.duration_since(s.last_used) <= keep;
            if !alive {
                by_domain.remove(&s.domain);
            }
            alive
        });
    }

    /// Address for `domain`, allocating one if needed; `version` is the
    /// policy version in force. Refreshes its age. None when no address can
    /// be handed out without reusing one that is live or quarantined.
    pub fn assign(&self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        let now = Instant::now();
        let keep = self.lifetime + self.quarantine;
        let mut inner = self.inner.lock().expect("fake-ip lock");
        if let Some(&off) = inner.by_domain.get(domain) {
            let slot = inner.by_offset.get_mut(&off).expect("index consistent");
            if now.duration_since(slot.last_used) <= keep {
                // Live, or quarantined for this very domain: same address.
                slot.last_used = now;
                slot.version = version;
                self.dirty.store(true, Ordering::Release);
                return Some(self.addr(off));
            }
            inner.by_offset.remove(&off);
            inner.by_domain.remove(domain);
        }
        if inner.by_offset.len() >= self.max_entries {
            self.prune(&mut inner, now);
            if inner.by_offset.len() >= self.max_entries {
                return None;
            }
        }
        let usable = self.size - 2;
        let start = self.home(domain);
        for i in 0..usable {
            let off = 1 + (start - 1 + i) % usable;
            let free = match inner.by_offset.get(&off) {
                None => true,
                Some(s) => now.duration_since(s.last_used) > keep,
            };
            if !free {
                continue;
            }
            if let Some(old) = inner.by_offset.remove(&off) {
                inner.by_domain.remove(&old.domain);
            }
            inner.by_domain.insert(domain.to_owned(), off);
            inner.by_offset.insert(
                off,
                Slot {
                    domain: domain.to_owned(),
                    version,
                    last_used: now,
                },
            );
            self.dirty.store(true, Ordering::Release);
            self.allocated.store(true, Ordering::Release);
            return Some(self.addr(off));
        }
        None
    }

    /// Reverse lookup for a new flow. Unknown, quarantined or free addresses
    /// give None; the caller refuses the flow. Never returns a domain other
    /// than the one the address was handed out for.
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
        self.dirty.store(true, Ordering::Release);
        Some(FakeEntry {
            domain: slot.domain.clone(),
            version: slot.version,
        })
    }

    /// Tracked (live + quarantined) addresses.
    pub fn tracked(&self) -> usize {
        self.inner.lock().expect("fake-ip lock").by_offset.len()
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
        let ip = a.assign("api.openai.com", 1).unwrap();
        assert_eq!(
            b.assign("api.openai.com", 1),
            Some(ip),
            "same key, same address"
        );
        assert_eq!(a.assign("api.openai.com", 2), Some(ip), "stable on re-ask");
        assert!(a.contains(ip.into()));
        let e = a.lookup(ip.into()).unwrap();
        assert_eq!(e.domain, "api.openai.com");
        assert_eq!(e.version, 2);
        assert_eq!(a.lookup("198.18.255.254".parse().unwrap()), None);
        assert_eq!(a.lookup("8.8.8.8".parse().unwrap()), None);
        let mapped: IpAddr = format!("::ffff:{ip}").parse().unwrap();
        assert!(a.lookup(mapped).is_some());
    }

    #[test]
    fn collisions_probe_and_full_pool() {
        // /30 has two usable addresses.
        let p = pool(30, 60_000);
        let x = p.assign("a.com", 0).unwrap();
        let y = p.assign("b.com", 0).unwrap();
        assert_ne!(x, y);
        assert_eq!(p.assign("c.com", 0), None, "full of live entries");
    }

    /// Expire → another domain wants the address → the old address is
    /// neither handed to it nor reinterpreted; only after the quarantine is
    /// the address reused.
    #[test]
    fn expired_address_is_quarantined_not_reinterpreted() {
        let p = pool(30, 20).with_limits(Duration::from_millis(300), 16);
        let x = p.assign("a.com", 1).unwrap();
        let y = p.assign("b.com", 1).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(p.lookup(x.into()), None, "past grace: refused");
        assert_eq!(p.assign("c.com", 1), None, "no safe address: refused");
        assert_eq!(p.lookup(x.into()), None, "still refused, not c.com");
        assert_eq!(p.lookup(y.into()), None);
        // The same domain may take its quarantined address back.
        assert_eq!(p.assign("a.com", 2), Some(x));
        assert_eq!(p.lookup(x.into()).unwrap().domain, "a.com");
        std::thread::sleep(Duration::from_millis(400));
        // Past quarantine: free for anyone.
        let z = p.assign("c.com", 3).unwrap();
        assert_eq!(p.lookup(z.into()).unwrap().domain, "c.com");
    }

    #[test]
    fn max_entries_cap_refuses_instead_of_reusing() {
        let p = pool(15, 60_000).with_limits(Duration::from_secs(60), 2);
        assert!(p.assign("a.com", 0).is_some());
        assert!(p.assign("b.com", 0).is_some());
        assert_eq!(p.assign("c.com", 0), None);
        assert!(p.assign("a.com", 0).is_some(), "known names still answered");
    }

    #[test]
    fn state_roundtrip_keeps_key_and_mapping() {
        let a = pool(15, 60_000);
        let x = a.assign("a.com", 4).unwrap();
        let y = a.assign("b.com", 4).unwrap();
        let bytes = a.snapshot();
        let (b, n) = FakeIpPool::restore(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::ZERO,
            Duration::from_secs(60),
            &bytes,
            crate::policy::unix_now(),
        )
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(b.lookup(x.into()).unwrap().domain, "a.com");
        assert_eq!(b.lookup(y.into()).unwrap().version, 4);
        // Same key: a new name lands where the old process would put it.
        assert_eq!(b.assign("c.com", 4), a.assign("c.com", 4));
        // Downtime counts: a restart long after leaves nothing live.
        let (c, n) = FakeIpPool::restore(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::ZERO,
            Duration::from_secs(60),
            &bytes,
            crate::policy::unix_now() + 120,
        )
        .unwrap();
        assert_eq!(n, 2, "still quarantined (default quarantine)");
        assert_eq!(c.lookup(x.into()), None);
        assert_ne!(c.assign("z.com", 0), Some(x));
    }

    #[test]
    fn save_writes_only_when_dirty() {
        let dir = std::env::temp_dir().join(format!("fakeip-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fakeip.state");
        let p = pool(15, 60_000);
        assert!(!p.save(&path).unwrap());
        let x = p.assign("a.com", 1).unwrap();
        assert!(p.save(&path).unwrap());
        assert!(!p.save(&path).unwrap());
        let (q, log) = FakeIpPool::open(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::ZERO,
            Duration::from_secs(60),
            DEFAULT_QUARANTINE,
            DEFAULT_MAX_ENTRIES,
            Some(&path),
        )
        .unwrap();
        assert!(log[0].contains("restored"), "{log:?}");
        assert_eq!(q.lookup(x.into()).unwrap().domain, "a.com");
        std::fs::write(&path, b"junk").unwrap();
        let (_, log) = FakeIpPool::open(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::ZERO,
            Duration::from_secs(60),
            DEFAULT_QUARANTINE,
            DEFAULT_MAX_ENTRIES,
            Some(&path),
        )
        .unwrap();
        assert!(log[0].contains("unusable"), "{log:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_prefix() {
        let k = [0; 32];
        let d = Duration::from_secs(1);
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 31, d, d, k).is_err());
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 4, d, d, k).is_err());
    }
}
