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
//! probing on collision.
//!
//! Address identity. An address, once handed out for a domain, is **never**
//! handed to another domain: a client may cache an address (or keep using
//! it) for longer than any timeout we could pick, and the address itself
//! carries no name or generation. So:
//!
//! - **live** (`age ≤ ttl + grace`): lookups return the domain and refresh
//!   its age;
//! - **idle** after that: lookups are refused until the same domain is asked
//!   for again, which gets the very same address back;
//! - when the pool already tracks `max_entries` addresses (or the range is
//!   full), a new name is refused (the DNS answers SERVFAIL) instead of
//!   reusing anything.
//!
//! Persistence ([`FakeIpPool::open`]). The key and every binding live in a
//! private state file plus an append-only journal next to it. A new binding
//! is appended to the journal and fsynced **before** its address is
//! returned, so no crash can lose an address a client was given. The state
//! is written once at first start (before any address exists), so a
//! missing state file later means someone removed it. Missing-but-journaled,
//! corrupt, oversized, foreign (other range) or unsafely stored state
//! (symlink, not a regular file, group/other permissions, another owner,
//! a directory others can write) is an error: the kernel refuses to start
//! rather than reinterpret addresses with a new key.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Default cap on tracked addresses.
pub const DEFAULT_MAX_ENTRIES: usize = 16_384;
/// Last-use times (and journal compaction) are saved this often.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(30);
/// Longest domain kept (DNS presentation form).
pub const MAX_DOMAIN: usize = 253;
/// State or journal bytes allowed per tracked entry when reading (plus
/// [`STATE_SLACK`]): an offset, a 253-byte name, a version and a time in
/// JSON.
const BYTES_PER_ENTRY: u64 = 320;
const STATE_SLACK: u64 = 4096;

/// Format 1 (quarantine-era) state has the same fields and is still read.
const STATE_FORMAT: u32 = 2;

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

struct Journal {
    file: File,
    /// Bindings appended since the journal was last emptied.
    lines: u64,
}

struct Inner {
    by_offset: HashMap<u32, Slot>,
    by_domain: HashMap<String, u32>,
    /// Present when persistence is on and the journal is writable. A failed
    /// append leaves `None` with `broken` set: new names are refused until a
    /// save rewrites the state and empties the journal.
    journal: Option<Journal>,
    broken: bool,
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
    max_entries: usize,
    inner: Mutex<Inner>,
    /// Something changed since the last save.
    dirty: AtomicBool,
    /// Where the state is kept (None: this process only).
    state: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// One journal line: (offset, domain, policy version, unix seconds).
type JournalLine = (u32, String, u64, u64);

impl FakeIpPool {
    /// A pool kept in memory only. `base/prefix` must be an IPv4 range with
    /// prefix 8..=30.
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
            max_entries: DEFAULT_MAX_ENTRIES,
            inner: Mutex::new(Inner {
                by_offset: HashMap::new(),
                by_domain: HashMap::new(),
                journal: None,
                broken: false,
            }),
            dirty: AtomicBool::new(false),
            state: None,
        })
    }

    /// Override the tracked-address cap.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries.max(1);
        self
    }

    /// Build a pool from the state at `path` (key + bindings, see the module
    /// docs), creating it on first start. `None`: in memory only. Errors when
    /// the state exists but cannot be trusted. Returns log lines.
    pub fn open(
        base: Ipv4Addr,
        prefix: u8,
        ttl: Duration,
        grace: Duration,
        max_entries: usize,
        path: Option<&Path>,
    ) -> Result<(Self, Vec<String>), String> {
        let mut log = Vec::new();
        let Some(path) = path else {
            log.push("fake-ip: no state file; addresses are stable for this process only".into());
            let pool = Self::new(base, prefix, ttl, grace, rand::random())?;
            return Ok((pool.with_max_entries(max_entries), log));
        };
        let refuse = |e: String| {
            format!(
                "fake-ip state {}: {e}. Refusing to start: addresses handed out \
                 earlier could be reinterpreted. Repair it, or remove it and its \
                 .journal deliberately (clients must then forget cached fake \
                 addresses, e.g. by reconnecting the network)",
                path.display()
            )
        };
        let jpath = journal_path(path);
        let limit = STATE_SLACK + max_entries as u64 * BYTES_PER_ENTRY;
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        check_dir(dir.unwrap_or(Path::new("."))).map_err(|e| refuse(e.to_string()))?;
        let state = read_private(path, limit).map_err(|e| refuse(e.to_string()))?;
        let journal = read_private(&jpath, limit).map_err(|e| refuse(e.to_string()))?;
        let now = crate::policy::unix_now();
        let mut pool = match state {
            None if journal.is_some() => {
                return Err(refuse(format!(
                    "missing, but its journal {} exists",
                    jpath.display()
                )))
            }
            None => {
                log.push(format!("fake-ip: new state {}", path.display()));
                Self::new(base, prefix, ttl, grace, rand::random())?.with_max_entries(max_entries)
            }
            Some(bytes) => {
                let (pool, n) = Self::restore(base, prefix, ttl, grace, max_entries, &bytes, now)
                    .map_err(refuse)?;
                log.push(format!(
                    "fake-ip: restored key and {n} entries from {}",
                    path.display()
                ));
                pool
            }
        };
        if let Some(j) = &journal {
            let n = pool
                .replay(j, now)
                .map_err(|e| refuse(format!("journal: {e}")))?;
            if n > 0 {
                log.push(format!("fake-ip: {n} entries from the journal"));
            }
        }
        pool.state = Some(path.to_owned());
        // Write the state now (first start: the key exists on disk before
        // any address does; restart: the journal is folded in), then open an
        // empty journal for this run's new bindings.
        pool.dirty.store(true, Ordering::Release);
        pool.save().map_err(|e| refuse(e.to_string()))?;
        Ok((pool, log))
    }

    fn restore(
        base: Ipv4Addr,
        prefix: u8,
        ttl: Duration,
        grace: Duration,
        max_entries: usize,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<(Self, usize), String> {
        let st: State = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if st.format != STATE_FORMAT && st.format != 1 {
            return Err(format!("unknown format {}", st.format));
        }
        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&st.key)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "key must be 32 bytes".to_string())?;
        let pool = Self::new(base, prefix, ttl, grace, key)?.with_max_entries(max_entries);
        if st.range != pool.range() {
            return Err(format!(
                "kept for range {}, configured {}",
                st.range,
                pool.range()
            ));
        }
        if st.entries.len() > pool.max_entries {
            return Err(format!(
                "{} entries, more than fake_ip_max_entries {}",
                st.entries.len(),
                pool.max_entries
            ));
        }
        let down = now_unix.saturating_sub(st.saved_at);
        let n = st.entries.len();
        {
            let mut inner = pool.inner.lock().expect("fake-ip lock");
            for (off, domain, version, idle) in st.entries {
                let idle = idle.saturating_add(down);
                pool.bind(&mut inner, off, domain, version, idle, false)?;
            }
        }
        Ok((pool, n))
    }

    /// Fold journal lines into the pool. A last line without its newline is
    /// an append cut short by a crash; its address was never returned.
    fn replay(&self, bytes: &[u8], now_unix: u64) -> Result<usize, String> {
        let mut inner = self.inner.lock().expect("fake-ip lock");
        let mut n = 0;
        let complete = match bytes.iter().rposition(|&b| b == b'\n') {
            Some(i) => &bytes[..=i],
            None => &[][..],
        };
        for (i, line) in complete.split(|&b| b == b'\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let (off, domain, version, t): JournalLine =
                serde_json::from_slice(line).map_err(|e| format!("line {}: {e}", i + 1))?;
            let idle = now_unix.saturating_sub(t);
            if self.bind(&mut inner, off, domain, version, idle, true)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Record a restored binding after validating it. `dup_ok`: the same
    /// binding again is fine (journal lines already in the state). Returns
    /// whether it was new.
    fn bind(
        &self,
        inner: &mut Inner,
        off: u32,
        domain: String,
        version: u64,
        idle: u64,
        dup_ok: bool,
    ) -> Result<bool, String> {
        if off == 0 || off >= self.size - 1 {
            return Err(format!("offset {off} outside the range"));
        }
        if !valid_domain(&domain) {
            return Err(format!("invalid domain at offset {off}"));
        }
        match (inner.by_offset.get(&off), inner.by_domain.get(&domain)) {
            (Some(s), Some(&o)) if dup_ok && s.domain == domain && o == off => return Ok(false),
            (None, None) => {}
            _ => return Err(format!("conflicting bindings for offset {off} / {domain}")),
        }
        if inner.by_offset.len() >= self.max_entries {
            return Err(format!(
                "more than fake_ip_max_entries {} entries",
                self.max_entries
            ));
        }
        // Early after boot `now - idle` may not exist: treat as just used
        // (the address stays live a little longer, never another domain's).
        let now = Instant::now();
        let last_used = now
            .checked_sub(Duration::from_secs(idle))
            .unwrap_or(now);
        inner.by_domain.insert(domain.clone(), off);
        inner.by_offset.insert(
            off,
            Slot {
                domain,
                version,
                last_used,
            },
        );
        Ok(true)
    }

    fn range(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }

    /// Serialized key + every binding.
    pub fn snapshot(&self) -> Vec<u8> {
        let inner = self.inner.lock().expect("fake-ip lock");
        self.snapshot_of(&inner)
    }

    fn snapshot_of(&self, inner: &Inner) -> Vec<u8> {
        let now = Instant::now();
        let entries = inner
            .by_offset
            .iter()
            .map(|(&off, s)| {
                let idle = now.duration_since(s.last_used);
                (off, s.domain.clone(), s.version, idle.as_secs())
            })
            .collect();
        let st = State {
            format: STATE_FORMAT,
            key: base64::engine::general_purpose::STANDARD.encode(self.key),
            range: self.range(),
            saved_at: crate::policy::unix_now(),
            entries,
        };
        serde_json::to_vec(&st).expect("state serializes")
    }

    /// Rewrite the state file (atomically, owner-only, via a fresh
    /// exclusively created temporary) if anything changed since the last
    /// save, then empty the journal when nothing was appended meanwhile.
    /// Returns whether it wrote. No-op for an in-memory pool.
    pub fn save(&self) -> std::io::Result<bool> {
        let Some(path) = &self.state else {
            return Ok(false);
        };
        if !self.dirty.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        let (bytes, lines) = {
            let inner = self.inner.lock().expect("fake-ip lock");
            let lines = inner.journal.as_ref().map(|j| j.lines);
            (self.snapshot_of(&inner), lines)
        };
        let r = write_atomic(path, &bytes).and_then(|()| {
            let mut inner = self.inner.lock().expect("fake-ip lock");
            match (&mut inner.journal, lines) {
                // Bindings appended after the snapshot stay journaled.
                (Some(j), Some(l)) if j.lines != l => Ok(()),
                (Some(j), _) => {
                    j.file.set_len(0)?;
                    j.file.sync_all()?;
                    j.lines = 0;
                    Ok(())
                }
                (None, _) => {
                    // First save, or after a failed append (no binding was
                    // added since: they are refused while broken).
                    let file = open_journal(&journal_path(path))?;
                    file.set_len(0)?;
                    file.sync_all()?;
                    inner.journal = Some(Journal { file, lines: 0 });
                    inner.broken = false;
                    Ok(())
                }
            }
        });
        if r.is_err() {
            self.dirty.store(true, Ordering::Release);
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

    /// Address for `domain`, allocating one if needed; `version` is the
    /// policy version in force. Refreshes its age. None when the name gets
    /// no address: the pool is full (no address is ever reused for another
    /// name), the name cannot be stored, or the binding could not be made
    /// durable.
    pub fn assign(&self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        let now = Instant::now();
        let mut inner = self.inner.lock().expect("fake-ip lock");
        if let Some(&off) = inner.by_domain.get(domain) {
            let slot = inner.by_offset.get_mut(&off).expect("index consistent");
            slot.last_used = now;
            slot.version = version;
            self.dirty.store(true, Ordering::Release);
            return Some(self.addr(off));
        }
        if !valid_domain(domain) || inner.by_offset.len() >= self.max_entries {
            return None;
        }
        let usable = self.size - 2;
        let start = self.home(domain);
        let off = (0..usable)
            .map(|i| 1 + (start - 1 + i) % usable)
            .find(|off| !inner.by_offset.contains_key(off))?;
        if self.state.is_some() {
            // Durable before the address is handed out.
            let j = inner.journal.as_mut()?;
            let mut line =
                serde_json::to_vec(&(off, domain, version, crate::policy::unix_now()))
                    .expect("line serializes");
            line.push(b'\n');
            if j.file.write_all(&line).and_then(|()| j.file.sync_data()).is_err() {
                inner.journal = None;
                inner.broken = true;
                self.dirty.store(true, Ordering::Release);
                return None;
            }
            j.lines += 1;
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
        Some(self.addr(off))
    }

    /// Reverse lookup for a new flow. Unknown or idle addresses give None;
    /// the caller refuses the flow. Never returns a domain other than the
    /// one the address was handed out for.
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

    /// Tracked addresses.
    pub fn tracked(&self) -> usize {
        self.inner.lock().expect("fake-ip lock").by_offset.len()
    }

    fn addr(&self, off: u32) -> Ipv4Addr {
        Ipv4Addr::from(self.base + off)
    }
}

/// Names the pool stores: printable ASCII without spaces, 1..=253 bytes
/// (never a newline or control byte in the journal).
fn valid_domain(d: &str) -> bool {
    !d.is_empty() && d.len() <= MAX_DOMAIN && d.bytes().all(|b| b.is_ascii_graphic())
}

fn journal_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".journal");
    path.with_file_name(name)
}

fn invalid(msg: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The state directory must not let anyone else replace our files.
fn check_dir(dir: &Path) -> std::io::Result<()> {
    let m = std::fs::metadata(dir)?;
    if !m.is_dir() {
        return Err(invalid(format!("{} is not a directory", dir.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if m.uid() != euid() && m.uid() != 0 {
            return Err(invalid(format!(
                "directory {} is owned by uid {}",
                dir.display(),
                m.uid()
            )));
        }
        if m.mode() & 0o022 != 0 {
            return Err(invalid(format!(
                "directory {} is writable by group or others (mode {:o})",
                dir.display(),
                m.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

/// An opened state or journal file must be a regular file of ours, 0600.
fn check_file(f: &File, path: &Path) -> std::io::Result<()> {
    let m = f.metadata()?;
    if !m.file_type().is_file() {
        return Err(invalid(format!("{} is not a regular file", path.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if m.uid() != euid() {
            return Err(invalid(format!(
                "{} is owned by uid {}",
                path.display(),
                m.uid()
            )));
        }
        if m.mode() & 0o077 != 0 {
            return Err(invalid(format!(
                "{} has mode {:o}, must be 0600",
                path.display(),
                m.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

fn private_opts() -> std::fs::OpenOptions {
    #[allow(unused_mut)]
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Never follow a link at the final component; never block on a FIFO.
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    opts
}

fn open_err(path: &Path, e: std::io::Error) -> std::io::Error {
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return invalid(format!("{} is a symbolic link", path.display()));
    }
    std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

/// Read a private file of at most `limit` bytes; None when it does not
/// exist.
fn read_private(path: &Path, limit: u64) -> std::io::Result<Option<Vec<u8>>> {
    let f = match private_opts().read(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(open_err(path, e)),
    };
    check_file(&f, path)?;
    let mut buf = Vec::new();
    f.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(invalid(format!(
            "{} is larger than {limit} bytes",
            path.display()
        )));
    }
    Ok(Some(buf))
}

fn open_journal(path: &Path) -> std::io::Result<File> {
    let f = private_opts()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| open_err(path, e))?;
    check_file(&f, path)?;
    Ok(f)
}

/// Replace `path` with `bytes`: write a new, exclusively created 0600
/// temporary next to it, fsync, rename over, fsync the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.{:016x}.tmp", rand::random::<u64>()));
    let r = (|| {
        let mut f = private_opts()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| open_err(&tmp, e))?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
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

    /// Expire, then another name wants the address: the old address is
    /// neither handed to it nor reinterpreted, ever.
    #[test]
    fn expired_address_is_never_rebound() {
        let p = pool(30, 20);
        let x = p.assign("a.com", 1).unwrap();
        let y = p.assign("b.com", 1).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(p.lookup(x.into()), None, "past grace: refused");
        assert_eq!(p.assign("c.com", 1), None, "no unbound address: refused");
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(p.assign("c.com", 1), None, "still refused much later");
        assert_eq!(p.lookup(x.into()), None, "never c.com");
        assert_eq!(p.lookup(y.into()), None);
        // The same name takes its address back.
        assert_eq!(p.assign("a.com", 2), Some(x));
        assert_eq!(p.lookup(x.into()).unwrap().domain, "a.com");
    }

    #[test]
    fn max_entries_cap_refuses_instead_of_reusing() {
        let p = pool(15, 60_000).with_max_entries(2);
        assert!(p.assign("a.com", 0).is_some());
        assert!(p.assign("b.com", 0).is_some());
        assert_eq!(p.assign("c.com", 0), None);
        assert!(p.assign("a.com", 0).is_some(), "known names still answered");
    }

    #[test]
    fn invalid_names_get_no_address() {
        let p = pool(15, 60_000);
        assert_eq!(p.assign("", 0), None);
        assert_eq!(p.assign("a\nb.com", 0), None);
        assert_eq!(p.assign("a b.com", 0), None);
        assert_eq!(p.assign(&"a".repeat(MAX_DOMAIN + 1), 0), None);
        assert!(p.assign(&"a".repeat(MAX_DOMAIN), 0).is_some());
    }

    fn restore_at(bytes: &[u8], max: usize, now: u64) -> Result<(FakeIpPool, usize), String> {
        FakeIpPool::restore(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::ZERO,
            Duration::from_secs(60),
            max,
            bytes,
            now,
        )
    }

    #[test]
    fn state_roundtrip_keeps_key_and_mapping() {
        let a = pool(15, 60_000);
        let x = a.assign("a.com", 4).unwrap();
        let y = a.assign("b.com", 4).unwrap();
        let bytes = a.snapshot();
        let (b, n) = restore_at(&bytes, DEFAULT_MAX_ENTRIES, crate::policy::unix_now()).unwrap();
        assert_eq!(n, 2);
        assert_eq!(b.lookup(x.into()).unwrap().domain, "a.com");
        assert_eq!(b.lookup(y.into()).unwrap().version, 4);
        // Same key: a new name lands where the old process would put it.
        assert_eq!(b.assign("c.com", 4), a.assign("c.com", 4));
        // A restart long after: nothing live, but nothing rebound either.
        let (c, n) = restore_at(&bytes, DEFAULT_MAX_ENTRIES, crate::policy::unix_now() + 1_000_000)
            .unwrap();
        assert_eq!(n, 2, "bindings survive any downtime");
        assert_eq!(c.lookup(x.into()), None);
        assert_ne!(c.assign("z.com", 0), Some(x));
        assert_ne!(c.assign("z.com", 0), Some(y));
        assert_eq!(c.assign("a.com", 0), Some(x));
    }

    fn tamper(bytes: &[u8], f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        f(&mut v);
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn untrusted_state_content_is_rejected() {
        let a = pool(15, 60_000);
        a.assign("a.com", 1).unwrap();
        a.assign("b.com", 1).unwrap();
        let ok = a.snapshot();
        let now = crate::policy::unix_now();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("junk", b"junk".to_vec()),
            ("format", tamper(&ok, |v| v["format"] = 9.into())),
            ("short key", tamper(&ok, |v| v["key"] = "AAAA".into())),
            ("range", tamper(&ok, |v| v["range"] = "10.0.0.0/8".into())),
            ("unknown field", tamper(&ok, |v| v["x"] = 1.into())),
            ("offset 0", tamper(&ok, |v| v["entries"][0][0] = 0.into())),
            ("offset past end", tamper(&ok, |v| v["entries"][0][0] = (1u32 << 17).into())),
            ("bad name", tamper(&ok, |v| v["entries"][0][1] = "a\nb".into())),
            ("empty name", tamper(&ok, |v| v["entries"][0][1] = "".into())),
            ("same offset twice", tamper(&ok, |v| {
                let o = v["entries"][0][0].clone();
                v["entries"][1][0] = o;
            })),
            ("same name twice", tamper(&ok, |v| {
                let d = v["entries"][0][1].clone();
                v["entries"][1][1] = d;
            })),
        ];
        for (what, bytes) in cases {
            assert!(
                restore_at(&bytes, DEFAULT_MAX_ENTRIES, now).is_err(),
                "{what} accepted"
            );
        }
        assert!(restore_at(&ok, 1, now).is_err(), "more entries than the cap");
        assert!(restore_at(&ok, 2, now).is_ok());
    }

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn private_dir() -> Dir {
        let dir = std::env::temp_dir().join(format!("fakeip-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Dir(dir)
    }
    /// Write a test file owner-only (as the kernel would).
    fn put(path: &Path, bytes: &[u8]) {
        let _ = std::fs::remove_file(path);
        private_opts()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn open_at(path: &Path, max: usize) -> Result<(FakeIpPool, Vec<String>), String> {
        FakeIpPool::open(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::ZERO,
            Duration::from_secs(60),
            max,
            Some(path),
        )
    }

    #[test]
    fn save_writes_only_when_dirty() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, log) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        assert!(log[0].contains("new state"), "{log:?}");
        assert!(path.exists(), "key on disk before any address");
        assert!(!p.save().unwrap());
        let x = p.assign("a.com", 1).unwrap();
        assert!(p.save().unwrap());
        assert!(!p.save().unwrap());
        drop(p);
        let (q, log) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        assert!(log[0].contains("restored"), "{log:?}");
        assert_eq!(q.lookup(x.into()).unwrap().domain, "a.com");
    }

    /// A crash right after an address was handed out (no save ran) keeps
    /// the binding: it is in the journal before the address is returned.
    #[test]
    fn binding_survives_crash_before_save() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        let x = p.assign("a.com", 1).unwrap();
        std::mem::forget(p); // no save, no drop: like a crash
        let (q, log) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        assert!(log.iter().any(|l| l.contains("1 entries from the journal")), "{log:?}");
        assert_eq!(q.lookup(x.into()).unwrap().domain, "a.com");
        assert_ne!(q.assign("b.com", 1), Some(x));
        // A torn last line (crash mid-append) is ignored.
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(journal_path(&path))
            .unwrap();
        j.write_all(b"[5,\"c.co").unwrap();
        drop(j);
        drop(q);
        let (r, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        assert_eq!(r.lookup(x.into()).unwrap().domain, "a.com");
    }

    /// Custom limits apply to the restored pool, not only to a fresh one.
    #[test]
    fn restored_pool_keeps_configured_cap() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, _) = open_at(&path, 2).unwrap();
        p.assign("a.com", 0).unwrap();
        p.save().unwrap();
        drop(p);
        let (q, _) = open_at(&path, 2).unwrap();
        assert!(q.assign("b.com", 0).is_some());
        assert_eq!(q.assign("c.com", 0), None);
        drop(q);
        // Lowering the cap below what is bound refuses to start.
        assert!(open_at(&path, 1).is_err());
    }

    #[test]
    fn missing_or_corrupt_state_refuses_to_start() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        p.assign("a.com", 1).unwrap();
        std::mem::forget(p);
        // Corrupt.
        let good = std::fs::read(&path).unwrap();
        put(&path, b"junk");
        let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
        assert!(e.contains("Refusing to start"), "{e}");
        assert_eq!(std::fs::read(&path).unwrap(), b"junk", "left for repair");
        // Removed while its journal remains.
        std::fs::remove_file(&path).unwrap();
        let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
        assert!(e.contains("journal"), "{e}");
        // Corrupt journal line.
        put(&path, &good);
        put(&journal_path(&path), b"nope\n");
        assert!(open_at(&path, DEFAULT_MAX_ENTRIES).is_err());
        // Oversized.
        put(&journal_path(&path), b"");
        let mut big = good.clone();
        big.resize(STATE_SLACK as usize + 2 * BYTES_PER_ENTRY as usize + 1, b' ');
        put(&path, &big);
        let e = open_at(&path, 2).err().unwrap();
        assert!(e.contains("larger than"), "{e}");
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_storage_refuses_to_start() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        drop(p);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state is owner-only");
        let jmode = std::fs::metadata(journal_path(&path)).unwrap().permissions().mode() & 0o777;
        assert_eq!(jmode, 0o600, "journal is owner-only");
        // Readable by others.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
        assert!(e.contains("must be 0600"), "{e}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A symlink in place of the state.
        let real = d.0.join("real");
        std::fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
        assert!(e.contains("symbolic link"), "{e}");
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&real, &path).unwrap();
        // Not a regular file.
        let j = journal_path(&path);
        std::fs::remove_file(&j).unwrap();
        std::fs::create_dir(&j).unwrap();
        assert!(open_at(&path, DEFAULT_MAX_ENTRIES).is_err());
        std::fs::remove_dir(&j).unwrap();
        // A directory others can write to.
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
        assert!(e.contains("writable by group or others"), "{e}");
        std::fs::set_permissions(&d.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_at(&path, DEFAULT_MAX_ENTRIES).is_ok());
    }

    /// The temporary is created fresh (never through a planted link) and
    /// owner-only, regardless of umask.
    #[cfg(unix)]
    #[test]
    fn atomic_write_never_follows_planted_files() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let victim = d.0.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        // The old fixed temporary name, planted as a link.
        std::os::unix::fs::symlink(&victim, d.0.join("fakeip.state.tmp")).unwrap();
        write_atomic(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // A state path that is a link is replaced, not written through.
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        write_atomic(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
    }

    #[test]
    fn bad_prefix() {
        let k = [0; 32];
        let d = Duration::from_secs(1);
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 31, d, d, k).is_err());
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 4, d, d, k).is_err());
    }
}
