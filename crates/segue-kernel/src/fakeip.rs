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
//! returned, so no crash can lose an address a client was given. That disk
//! work runs on a dedicated persistence thread
//! ([`FakeIpPool::assign_durable`]), never on the network runtime. At first
//! start the journal is created and its directory entry synced, then the
//! state is written (before any address exists), so a missing state file
//! later means someone removed it, and a missing journal next to a current
//! state means bindings were lost. Missing-but-journaled, journal-less,
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
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

/// Default cap on tracked addresses.
pub const DEFAULT_MAX_ENTRIES: usize = 16_384;
/// Last-use times (and journal compaction) are saved this often.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(30);
/// Longest domain kept (DNS presentation form).
pub const MAX_DOMAIN: usize = 253;
/// Worst-case serialized size of one entry, in the state or as a journal
/// line: offset, version and time at their widest, plus a 253-byte name
/// whose every byte JSON escapes to two (`"` or `\`). Reads and writes use
/// the same bound, so the pool never writes state it would refuse to read.
const BYTES_PER_ENTRY: u64 = 2 * MAX_DOMAIN as u64 + 64;
const STATE_SLACK: u64 = 4096;

/// Format 3: the journal was created (and its directory entry synced)
/// before this state was first written, so a missing journal next to it
/// means bindings were lost. Formats 1 and 2 have the same fields and are
/// still read, but only together with their journal: they could not
/// promise one, so without it the pool cannot tell "never had bindings
/// since the snapshot" from "lost them" (r7 #4), and refuses to start.
const STATE_FORMAT: u32 = 3;

/// Persistence jobs queued at most; a new name over this is refused (the
/// DNS answers SERVFAIL) instead of queuing behind a slow disk (r7 #5).
pub const MAX_PENDING_JOBS: usize = 64;
/// Longest a DNS answer waits for its binding to become durable. Past it the
/// name gets no address now (SERVFAIL); the job, if it still runs, only
/// makes a binding the next query for the name is answered from.
pub const DURABLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Largest state or journal (bytes) a pool of `max_entries` writes or reads.
fn size_limit(max_entries: usize) -> u64 {
    STATE_SLACK + max_entries as u64 * BYTES_PER_ENTRY
}

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

/// Bindings and placement, shared by the pool and its persistence thread.
struct Core {
    base: u32,
    prefix: u8,
    /// Usable offsets are 1..size-1 (network and broadcast addresses skipped).
    size: u32,
    key: [u8; 32],
    /// How long after its last use an entry can still be looked up.
    lifetime: Duration,
    max_entries: usize,
    inner: Mutex<Inner>,
    /// Something changed since the last save.
    dirty: AtomicBool,
    /// Test hook: extra time each journal append takes (slow storage).
    #[cfg(test)]
    slow_append: Mutex<Duration>,
}

pub struct FakeIpPool {
    /// DNS TTL handed to clients.
    pub ttl: Duration,
    core: Arc<Core>,
    /// Persistence thread (None: in memory only). It alone appends to the
    /// journal, adds new bindings and writes the state, so the network
    /// runtime never waits on the disk and a binding is never both missing
    /// from a snapshot and dropped from the journal.
    jobs: Option<Mutex<mpsc::SyncSender<Job>>>,
    /// See [`DURABLE_TIMEOUT`].
    durable_timeout: Duration,
}

enum Job {
    Assign {
        domain: String,
        version: u64,
        reply: oneshot::Sender<Option<Ipv4Addr>>,
    },
    Save {
        reply: oneshot::Sender<std::io::Result<bool>>,
    },
}

/// The open journal. None in [`Writer`] means a failed append: new names
/// are refused until a save recreates it and rewrites the state.
struct Journal {
    file: File,
    /// Current length; appends stop at the read limit.
    bytes: u64,
}

/// Owns the files. Runs on the persistence thread (and, before the pool
/// is shared, inside [`FakeIpPool::open`]).
struct Writer {
    core: Arc<Core>,
    path: PathBuf,
    journal: Option<Journal>,
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
        Ok(Self {
            ttl,
            core: Arc::new(Core::new(
                base,
                prefix,
                ttl + grace,
                key,
                DEFAULT_MAX_ENTRIES,
            )?),
            jobs: None,
            durable_timeout: DURABLE_TIMEOUT,
        })
    }

    /// Override the tracked-address cap (in-memory pools; [`Self::open`]
    /// takes it as an argument).
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        Arc::get_mut(&mut self.core)
            .expect("set before the pool is shared")
            .max_entries = max_entries.max(1);
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
        let max_entries = max_entries.max(1);
        let limit = size_limit(max_entries);
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        check_dir(dir.unwrap_or(Path::new("."))).map_err(|e| refuse(e.to_string()))?;
        let state = read_private(path, limit).map_err(|e| refuse(e.to_string()))?;
        let journal = read_private(&jpath, limit).map_err(|e| refuse(e.to_string()))?;
        let now = crate::policy::unix_now();
        let lifetime = ttl + grace;
        let core = match state {
            None if journal.is_some() => {
                return Err(refuse(format!(
                    "missing, but its journal {} exists",
                    jpath.display()
                )))
            }
            None => {
                log.push(format!("fake-ip: new state {}", path.display()));
                Core::new(base, prefix, lifetime, rand::random(), max_entries)?
            }
            Some(bytes) => {
                let (core, n, format) =
                    Core::restore(base, prefix, lifetime, max_entries, &bytes, now)
                        .map_err(refuse)?;
                if journal.is_none() {
                    // Format 3: the journal is made durable before such a
                    // state is ever written, so its loss may have taken
                    // bindings with it. Formats 1 and 2: there is no way to
                    // tell a journal that never existed from one that was
                    // lost, so they are never migrated without it.
                    let why = if format >= 3 {
                        String::new()
                    } else {
                        format!(" (format {format} state; cannot be migrated without it)")
                    };
                    return Err(refuse(format!(
                        "its journal {} is missing{why}",
                        jpath.display()
                    )));
                }
                log.push(format!(
                    "fake-ip: restored key and {n} entries from {}",
                    path.display()
                ));
                core
            }
        };
        if let Some(j) = &journal {
            let n = core
                .replay(j, now)
                .map_err(|e| refuse(format!("journal: {e}")))?;
            if n > 0 {
                log.push(format!("fake-ip: {n} entries from the journal"));
            }
        }
        let core = Arc::new(core);
        // Write the state now (first start: the journal, then the key, exist
        // on disk before any address does; restart: the journal is folded
        // in), leaving an empty journal for this run's new bindings.
        let mut writer = Writer {
            core: core.clone(),
            path: path.to_owned(),
            journal: None,
        };
        core.dirty.store(true, Ordering::Release);
        writer.save().map_err(|e| refuse(e.to_string()))?;
        let (tx, rx) = mpsc::sync_channel(MAX_PENDING_JOBS);
        std::thread::Builder::new()
            .name("fake-ip-persist".into())
            .spawn(move || writer.run(rx))
            .map_err(|e| refuse(format!("persistence thread: {e}")))?;
        Ok((
            Self {
                ttl,
                core,
                jobs: Some(Mutex::new(tx)),
                durable_timeout: DURABLE_TIMEOUT,
            },
            log,
        ))
    }

    #[cfg(test)]
    fn restore(
        base: Ipv4Addr,
        prefix: u8,
        ttl: Duration,
        grace: Duration,
        max_entries: usize,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<(Self, usize), String> {
        let (core, n, _) = Core::restore(base, prefix, ttl + grace, max_entries, bytes, now_unix)?;
        Ok((
            Self {
                ttl,
                core: Arc::new(core),
                jobs: None,
                durable_timeout: DURABLE_TIMEOUT,
            },
            n,
        ))
    }

    /// Queue a job; false when the queue is full (the disk is behind) or
    /// the thread is gone. Never waits.
    fn send(&self, job: Job) -> bool {
        let jobs = self.jobs.as_ref().expect("persistent pool");
        jobs.lock().expect("fake-ip jobs").try_send(job).is_ok()
    }

    /// Serialized key + every binding.
    pub fn snapshot(&self) -> Vec<u8> {
        self.core.snapshot()
    }

    /// Address for `domain`, allocating one if needed; `version` is the
    /// policy version in force. Refreshes its age. None when the name gets
    /// no address: the pool is full (no address is ever reused for another
    /// name), the name cannot be stored, or the binding could not be made
    /// durable. A new binding of a persistent pool is journaled and synced
    /// on the persistence thread before this returns; the caller's task
    /// yields meanwhile, so the network runtime keeps running. The wait is
    /// bounded: with [`MAX_PENDING_JOBS`] already queued, or no durable
    /// answer within [`DURABLE_TIMEOUT`], this is None at once / then.
    pub async fn assign_durable(&self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        if self.jobs.is_none() {
            return self.core.assign_mem(domain, version);
        }
        if let Some(ip) = self.core.existing(domain, version) {
            return Some(ip);
        }
        let (reply, rx) = oneshot::channel();
        if !self.send(Job::Assign {
            domain: domain.to_owned(),
            version,
            reply,
        }) {
            return None;
        }
        tokio::time::timeout(self.durable_timeout, rx)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten()
    }

    /// [`Self::assign_durable`] for callers outside an async runtime
    /// (tests, tools). On a persistent pool it blocks on the disk; never
    /// call it from a runtime thread.
    pub fn assign(&self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        if self.jobs.is_none() {
            return self.core.assign_mem(domain, version);
        }
        if let Some(ip) = self.core.existing(domain, version) {
            return Some(ip);
        }
        let (reply, rx) = oneshot::channel();
        if !self.send(Job::Assign {
            domain: domain.to_owned(),
            version,
            reply,
        }) {
            return None;
        }
        rx.blocking_recv().ok().flatten()
    }

    /// Rewrite the state file (atomically, owner-only, via a fresh
    /// exclusively created temporary) if anything changed since the last
    /// save, then empty the journal. Runs on the persistence thread.
    /// Returns whether it wrote. No-op for an in-memory pool.
    pub async fn save_durable(&self) -> std::io::Result<bool> {
        if self.jobs.is_none() {
            return Ok(false);
        }
        let (reply, rx) = oneshot::channel();
        if !self.send(Job::Save { reply }) {
            return Err(std::io::Error::other(
                "fake-ip persistence busy or gone; saved next time",
            ));
        }
        rx.await
            .unwrap_or_else(|_| Err(std::io::Error::other("fake-ip persistence thread gone")))
    }

    /// [`Self::save_durable`], blocking (never from a runtime thread).
    pub fn save(&self) -> std::io::Result<bool> {
        if self.jobs.is_none() {
            return Ok(false);
        }
        let (reply, rx) = oneshot::channel();
        let jobs = self.jobs.as_ref().expect("persistent pool");
        // Blocking: may wait for room behind queued bindings.
        let sent = jobs
            .lock()
            .expect("fake-ip jobs")
            .clone()
            .send(Job::Save { reply });
        if sent.is_err() {
            return Err(std::io::Error::other("fake-ip persistence thread gone"));
        }
        rx.blocking_recv()
            .unwrap_or_else(|_| Err(std::io::Error::other("fake-ip persistence thread gone")))
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.core.contains(ip)
    }

    /// Reverse lookup for a new flow. Unknown or idle addresses give None;
    /// the caller refuses the flow. Never returns a domain other than the
    /// one the address was handed out for.
    pub fn lookup(&self, ip: IpAddr) -> Option<FakeEntry> {
        self.core.lookup(ip)
    }

    /// Tracked addresses.
    pub fn tracked(&self) -> usize {
        self.core
            .inner
            .lock()
            .expect("fake-ip lock")
            .by_offset
            .len()
    }

    #[cfg(test)]
    pub(crate) fn set_slow_append(&self, d: Duration) {
        *self.core.slow_append.lock().unwrap() = d;
    }

    #[cfg(test)]
    pub(crate) fn set_durable_timeout(&mut self, d: Duration) {
        self.durable_timeout = d;
    }
}

impl Writer {
    fn run(mut self, rx: mpsc::Receiver<Job>) {
        while let Ok(job) = rx.recv() {
            match job {
                Job::Assign {
                    domain,
                    version,
                    reply,
                } => {
                    // Its asker gave up (timed out or cancelled): nobody
                    // would get the address, so no binding is made.
                    if reply.is_closed() {
                        continue;
                    }
                    let _ = reply.send(self.assign(&domain, version));
                }
                Job::Save { reply } => {
                    let _ = reply.send(self.save());
                }
            }
        }
    }

    /// Journal (and sync) a new binding, then add it. Only this thread adds
    /// bindings, so the offset picked stays free while the disk works, and
    /// a save (same thread) sees every binding whose line it truncates.
    fn assign(&mut self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        if let Some(ip) = self.core.existing(domain, version) {
            return Some(ip);
        }
        let off = self.core.pick(domain)?;
        let j = self.journal.as_mut()?;
        let mut line = serde_json::to_vec(&(off, domain, version, crate::policy::unix_now()))
            .expect("line serializes");
        line.push(b'\n');
        if j.bytes + line.len() as u64 > size_limit(self.core.max_entries) {
            // Cannot happen within the bounds (one line per binding, each
            // at most BYTES_PER_ENTRY); never write what a restart refuses.
            return None;
        }
        #[cfg(test)]
        std::thread::sleep(*self.core.slow_append.lock().unwrap());
        if j.file
            .write_all(&line)
            .and_then(|()| j.file.sync_data())
            .is_err()
        {
            self.journal = None;
            self.core.dirty.store(true, Ordering::Release);
            return None;
        }
        j.bytes += line.len() as u64;
        self.core.insert(off, domain, version);
        Some(self.core.addr(off))
    }

    fn save(&mut self) -> std::io::Result<bool> {
        if !self.core.dirty.swap(false, Ordering::AcqRel) {
            return Ok(false);
        }
        let r = self.compact();
        if r.is_err() {
            self.core.dirty.store(true, Ordering::Release);
        }
        r.map(|()| true)
    }

    /// Make sure a durable journal exists, write the state, empty the
    /// journal.
    fn compact(&mut self) -> std::io::Result<()> {
        if self.journal.is_none() {
            // First save, or after a failed append (no binding was added
            // since: they are refused meanwhile). Created and its directory
            // entry synced before any state that requires it is written; its
            // old lines (if any) stay until that state is in place.
            let jpath = journal_path(&self.path);
            let file = open_journal(&jpath)?;
            file.sync_all()?;
            sync_dir(&self.path)?;
            let bytes = file.metadata()?.len();
            self.journal = Some(Journal { file, bytes });
        }
        let bytes = self.core.snapshot();
        if bytes.len() as u64 > size_limit(self.core.max_entries) {
            return Err(invalid(format!(
                "state of {} bytes exceeds the {}-byte read limit",
                bytes.len(),
                size_limit(self.core.max_entries)
            )));
        }
        write_atomic(&self.path, &bytes)?;
        let j = self.journal.as_mut().expect("opened above");
        j.file.set_len(0)?;
        j.file.sync_all()?;
        j.bytes = 0;
        Ok(())
    }
}

impl Core {
    fn new(
        base: Ipv4Addr,
        prefix: u8,
        lifetime: Duration,
        key: [u8; 32],
        max_entries: usize,
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
            lifetime,
            max_entries: max_entries.max(1),
            inner: Mutex::new(Inner {
                by_offset: HashMap::new(),
                by_domain: HashMap::new(),
            }),
            dirty: AtomicBool::new(false),
            #[cfg(test)]
            slow_append: Mutex::new(Duration::ZERO),
        })
    }

    /// Returns the core, the number of entries and the state format.
    fn restore(
        base: Ipv4Addr,
        prefix: u8,
        lifetime: Duration,
        max_entries: usize,
        bytes: &[u8],
        now_unix: u64,
    ) -> Result<(Self, usize, u32), String> {
        let st: State = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if !(1..=STATE_FORMAT).contains(&st.format) {
            return Err(format!("unknown format {}", st.format));
        }
        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&st.key)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "key must be 32 bytes".to_string())?;
        let core = Self::new(base, prefix, lifetime, key, max_entries)?;
        if st.range != core.range() {
            return Err(format!(
                "kept for range {}, configured {}",
                st.range,
                core.range()
            ));
        }
        if st.entries.len() > core.max_entries {
            return Err(format!(
                "{} entries, more than fake_ip_max_entries {}",
                st.entries.len(),
                core.max_entries
            ));
        }
        let down = now_unix.saturating_sub(st.saved_at);
        let n = st.entries.len();
        {
            let mut inner = core.inner.lock().expect("fake-ip lock");
            for (off, domain, version, idle) in st.entries {
                let idle = idle.saturating_add(down);
                core.bind(&mut inner, off, domain, version, idle, false)?;
            }
        }
        Ok((core, n, st.format))
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
        let last_used = now.checked_sub(Duration::from_secs(idle)).unwrap_or(now);
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
    fn snapshot(&self) -> Vec<u8> {
        let inner = self.inner.lock().expect("fake-ip lock");
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

    fn contains(&self, ip: IpAddr) -> bool {
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

    /// The address already bound to `domain`, refreshed.
    fn existing(&self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        let mut inner = self.inner.lock().expect("fake-ip lock");
        let off = *inner.by_domain.get(domain)?;
        let slot = inner.by_offset.get_mut(&off).expect("index consistent");
        slot.last_used = Instant::now();
        slot.version = version;
        self.dirty.store(true, Ordering::Release);
        Some(self.addr(off))
    }

    /// A free offset for a new `domain`; None when the name cannot be
    /// stored or nothing may be handed out (cap reached, range full).
    fn pick(&self, domain: &str) -> Option<u32> {
        let inner = self.inner.lock().expect("fake-ip lock");
        self.pick_in(&inner, domain)
    }

    fn pick_in(&self, inner: &Inner, domain: &str) -> Option<u32> {
        if !valid_domain(domain) || inner.by_offset.len() >= self.max_entries {
            return None;
        }
        let usable = self.size - 2;
        let start = self.home(domain);
        (0..usable)
            .map(|i| 1 + (start - 1 + i) % usable)
            .find(|off| !inner.by_offset.contains_key(off))
    }

    fn insert(&self, off: u32, domain: &str, version: u64) {
        let mut inner = self.inner.lock().expect("fake-ip lock");
        Self::insert_in(&mut inner, off, domain, version);
        self.dirty.store(true, Ordering::Release);
    }

    fn insert_in(inner: &mut Inner, off: u32, domain: &str, version: u64) {
        inner.by_domain.insert(domain.to_owned(), off);
        inner.by_offset.insert(
            off,
            Slot {
                domain: domain.to_owned(),
                version,
                last_used: Instant::now(),
            },
        );
    }

    /// Assign without persistence (in-memory pool).
    fn assign_mem(&self, domain: &str, version: u64) -> Option<Ipv4Addr> {
        if let Some(ip) = self.existing(domain, version) {
            return Some(ip);
        }
        let mut inner = self.inner.lock().expect("fake-ip lock");
        let off = self.pick_in(&inner, domain)?;
        Self::insert_in(&mut inner, off, domain, version);
        self.dirty.store(true, Ordering::Release);
        Some(self.addr(off))
    }

    /// Reverse lookup for a new flow. Unknown or idle addresses give None;
    /// the caller refuses the flow. Never returns a domain other than the
    /// one the address was handed out for.
    fn lookup(&self, ip: IpAddr) -> Option<FakeEntry> {
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

/// Sync the directory holding `path`, so a file created or renamed there
/// survives a power loss.
fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
        sync_dir(path)?;
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
        let (c, n) = restore_at(
            &bytes,
            DEFAULT_MAX_ENTRIES,
            crate::policy::unix_now() + 1_000_000,
        )
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
            (
                "offset past end",
                tamper(&ok, |v| v["entries"][0][0] = (1u32 << 17).into()),
            ),
            (
                "bad name",
                tamper(&ok, |v| v["entries"][0][1] = "a\nb".into()),
            ),
            (
                "empty name",
                tamper(&ok, |v| v["entries"][0][1] = "".into()),
            ),
            (
                "same offset twice",
                tamper(&ok, |v| {
                    let o = v["entries"][0][0].clone();
                    v["entries"][1][0] = o;
                }),
            ),
            (
                "same name twice",
                tamper(&ok, |v| {
                    let d = v["entries"][0][1].clone();
                    v["entries"][1][1] = d;
                }),
            ),
        ];
        for (what, bytes) in cases {
            assert!(
                restore_at(&bytes, DEFAULT_MAX_ENTRIES, now).is_err(),
                "{what} accepted"
            );
        }
        assert!(
            restore_at(&ok, 1, now).is_err(),
            "more entries than the cap"
        );
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
        assert!(
            log.iter().any(|l| l.contains("1 entries from the journal")),
            "{log:?}"
        );
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
        big.resize(
            STATE_SLACK as usize + 2 * BYTES_PER_ENTRY as usize + 1,
            b' ',
        );
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
        let jmode = std::fs::metadata(journal_path(&path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
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
        put(&j, b"");
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
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // A state path that is a link is replaced, not written through.
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        write_atomic(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// R4: the journal is durable before the first state names it, so a
    /// current state without its journal is a lost binding log, not a
    /// fresh one.
    #[test]
    fn missing_journal_next_to_state_refuses_to_start() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        assert!(
            journal_path(&path).exists(),
            "journal exists before any address"
        );
        let x = p.assign("a.com", 1).unwrap();
        assert!(p.save().unwrap(), "folded into the state");
        drop(p);
        // The journal's directory entry was lost (power cut before it
        // reached the disk): refuse instead of starting with an empty log.
        std::fs::remove_file(journal_path(&path)).unwrap();
        let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
        assert!(e.contains("journal") && e.contains("missing"), "{e}");
        assert!(!journal_path(&path).exists(), "nothing recreated");
        let _ = x;
    }

    /// r7 #4: a legacy (format 1 or 2) state whose journal is gone is never
    /// migrated: a binding that only that journal held would be lost and
    /// its address handed to another name. With its journal it migrates.
    #[test]
    fn legacy_state_without_journal_refuses_to_start() {
        for format in [1u32, 2] {
            let d = private_dir();
            let path = d.0.join("fakeip.state");
            let (p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
            let a = p.assign("a.com", 1).unwrap();
            assert!(p.save().unwrap());
            // Handed out after the last snapshot: only the journal has it.
            let b = p.assign("b.com", 1).unwrap();
            drop(p);
            let legacy = tamper(&std::fs::read(&path).unwrap(), |v| {
                v["format"] = format.into();
            });
            put(&path, &legacy);
            assert!(!String::from_utf8_lossy(&legacy).contains("b.com"));
            let journal = std::fs::read(journal_path(&path)).unwrap();
            assert!(String::from_utf8_lossy(&journal).contains("b.com"));
            // The journal's directory entry was lost: refuse, recreate nothing.
            std::fs::remove_file(journal_path(&path)).unwrap();
            let e = open_at(&path, DEFAULT_MAX_ENTRIES).err().unwrap();
            assert!(
                e.contains("journal") && e.contains("missing") && e.contains("format"),
                "{e}"
            );
            assert!(!journal_path(&path).exists(), "nothing recreated");
            assert_eq!(std::fs::read(&path).unwrap(), legacy, "state untouched");
            // With its journal, the legacy state migrates and keeps both.
            put(&journal_path(&path), &journal);
            let (q, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
            assert_eq!(q.lookup(a.into()).unwrap().domain, "a.com");
            assert_eq!(q.lookup(b.into()).unwrap().domain, "b.com");
            drop(q);
            let st: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(st["format"], STATE_FORMAT);
        }
    }

    /// R9: every name the pool accepts can be saved and read back, even
    /// when JSON doubles each byte (quotes, backslashes).
    #[test]
    fn worst_case_names_save_and_restore() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let max = 64;
        let names: Vec<String> = (0..max)
            .map(|i| {
                format!(
                    "{i:02}{}",
                    if i % 2 == 0 { "\"" } else { "\\" }.repeat(MAX_DOMAIN - 2)
                )
            })
            .collect();
        assert!(names
            .iter()
            .all(|n| valid_domain(n) && n.len() == MAX_DOMAIN));
        let (p, _) = open_at(&path, max).unwrap();
        let ips: Vec<_> = names
            .iter()
            .map(|n| p.assign(n, u64::MAX).unwrap())
            .collect();
        // Crash before any save: everything is in the journal.
        std::mem::forget(p);
        let (q, _) = open_at(&path, max).expect("journal within the read limit");
        for (n, ip) in names.iter().zip(&ips) {
            assert_eq!(&q.lookup((*ip).into()).unwrap().domain, n);
        }
        // Folded into the state (open saves): still readable.
        assert!(std::fs::metadata(&path).unwrap().len() > 24_576);
        drop(q);
        let (r, _) = open_at(&path, max).expect("state within the read limit");
        assert_eq!(r.tracked(), max);
    }

    /// R10: a slow disk delays only the DNS answer waiting for its binding,
    /// not the runtime; the line is synced before the address is returned.
    #[tokio::test(flavor = "current_thread")]
    async fn slow_journal_does_not_stall_the_runtime() {
        use std::sync::atomic::AtomicU32;
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        p.set_slow_append(Duration::from_millis(300));
        let ticks = Arc::new(AtomicU32::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t.fetch_add(1, Ordering::Relaxed);
            }
        });
        let start = Instant::now();
        let ip = p.assign_durable("a.com", 1).await.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(300));
        let n = ticks.load(Ordering::Relaxed);
        assert!(n >= 10, "runtime ran only {n} ticks during a 300 ms append");
        let journal = std::fs::read(journal_path(&path)).unwrap();
        assert!(
            String::from_utf8_lossy(&journal).contains("a.com"),
            "journaled before the answer"
        );
        // Known names answer at once; saving also runs off the runtime.
        assert_eq!(p.assign_durable("a.com", 1).await, Some(ip));
        assert!(p.save_durable().await.unwrap());
        ticker.abort();
        drop(p);
        let (q, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        assert_eq!(q.lookup(ip.into()).unwrap().domain, "a.com");
    }

    /// r7 #5: a disk that stops answering neither grows the job queue
    /// without bound nor holds a DNS answer forever: over
    /// [`MAX_PENDING_JOBS`] a new name is refused at once, and a queued one
    /// gives up after the durable timeout. A job whose asker gave up makes
    /// no binding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stuck_disk_bounds_queue_and_wait() {
        let d = private_dir();
        let path = d.0.join("fakeip.state");
        let (mut p, _) = open_at(&path, DEFAULT_MAX_ENTRIES).unwrap();
        p.set_slow_append(Duration::from_millis(400));
        p.set_durable_timeout(Duration::from_millis(150));
        let p = Arc::new(p);
        let start = Instant::now();
        let mut set = tokio::task::JoinSet::new();
        for i in 0..MAX_PENDING_JOBS + 8 {
            let p = p.clone();
            set.spawn(async move {
                let r = p.assign_durable(&format!("n{i}.com"), 1).await;
                (r, Instant::now())
            });
        }
        let mut early = 0;
        while let Some(r) = set.join_next().await {
            let (r, at) = r.unwrap();
            assert_eq!(r, None, "no answer from a stuck disk");
            let waited = at - start;
            assert!(waited < Duration::from_millis(1000), "{waited:?}");
            if waited < Duration::from_millis(100) {
                early += 1;
            }
        }
        assert!(early >= 7, "over the queue refused at once: {early}");
        // Only the job already on the disk completes; the abandoned ones
        // are skipped, not journaled one by one.
        p.set_slow_append(Duration::ZERO);
        tokio::time::sleep_until((start + Duration::from_millis(600)).into()).await;
        let t = Instant::now();
        assert!(p.assign_durable("late.com", 1).await.is_some());
        assert!(
            t.elapsed() < Duration::from_millis(1000),
            "{:?}",
            t.elapsed()
        );
        assert!(
            p.tracked() <= 2,
            "abandoned jobs bound nothing: {}",
            p.tracked()
        );
    }

    #[test]
    fn bad_prefix() {
        let k = [0; 32];
        let d = Duration::from_secs(1);
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 31, d, d, k).is_err());
        assert!(FakeIpPool::new("10.0.0.0".parse().unwrap(), 4, d, d, k).is_err());
    }
}
