//! Owning process of a local socket, used as a third AI-tier matcher.
//!
//! Destination suffixes and CIDRs cannot name the shared telemetry and CDN
//! hosts an AI tool also talks to. When the AI tier lists process names or
//! paths and the destination did not match, the kernel asks who owns the
//! flow's local endpoint and, on a hit, applies the AI action.
//!
//! macOS reads `net.inet.tcp.pcblist_n` / `net.inet.udp.pcblist_n` (no root)
//! and `proc_pidpath`. The record layout is the kernel's `xinpcb_n` /
//! `xsocket_n` export: a 24-byte `xinpgen` header, then fixed-stride
//! records whose first field is `xi_len`. Other operating systems answer
//! [`None`] until they grow their own resolver. A miss, or any failure,
//! leaves the flow on the destination decision; it is never a block.
//!
//! Results are cached by `(proto, local address, local port)` for 30 s, up
//! to 4096 entries. A port reused inside that window can still be charged
//! to the previous process.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Transport the local socket speaks. Not [`crate::tun::Proto`]: this
/// module does not depend on the packet path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Process that owns a socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    /// Executable file name (`claude`), not a path.
    pub name: String,
    /// Absolute path from the kernel, when it could be read.
    pub path: String,
}

/// Resolves the process that owns `local`. `None` is "unknown", not a
/// refusal: callers fall through.
pub trait OwnerResolver: Send + Sync {
    fn owner(&self, proto: Proto, local: SocketAddr) -> Option<ProcessInfo>;
}

/// Resolver that never knows. Used where no platform lookup exists, and
/// in tests that must prove the resolver was not asked.
pub struct UnknownOwner;

impl OwnerResolver for UnknownOwner {
    fn owner(&self, _proto: Proto, _local: SocketAddr) -> Option<ProcessInfo> {
        None
    }
}

/// The process resolver for this operating system.
pub fn system_owner() -> &'static dyn OwnerResolver {
    #[cfg(target_os = "macos")]
    {
        darwin::shared()
    }
    #[cfg(not(target_os = "macos"))]
    {
        static UNKNOWN: UnknownOwner = UnknownOwner;
        &UNKNOWN
    }
}

/// One `name` / `path` / `bundle` / `cmd` line from `data/ai-processes.txt`
/// or the bundle's `ai_processes` field.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProcField {
    Name,
    Path,
    Bundle,
    Cmd,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcEntry {
    field: ProcField,
    value: String,
}

/// Process patterns that pull a flow onto the AI exit. `bundle` and `cmd`
/// are parsed and kept; only `name` and `path` match.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AiProcessSet {
    entries: Vec<ProcEntry>,
}

impl AiProcessSet {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut set = Self::default();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            set.push_line(line)
                .map_err(|e| format!("ai processes line {}: {e}", n + 1))?;
        }
        Ok(set)
    }

    /// One already-stripped line (`name claude`). Duplicate lines are kept
    /// once.
    pub fn push_line(&mut self, line: &str) -> Result<(), String> {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return Err("missing kind".into());
        }
        let mut parts = line.split_whitespace();
        let kind = parts.next().unwrap_or("");
        let field = match kind {
            "name" => ProcField::Name,
            "path" => ProcField::Path,
            "bundle" => ProcField::Bundle,
            "cmd" => ProcField::Cmd,
            other => return Err(format!("unknown kind {other:?}")),
        };
        let value = match field {
            ProcField::Name | ProcField::Bundle => {
                let value = parts.next().ok_or("missing value")?;
                if parts.next().is_some() {
                    return Err("extra token".into());
                }
                value.to_owned()
            }
            ProcField::Path | ProcField::Cmd => {
                let rest = line[kind.len()..].trim();
                if rest.is_empty() {
                    return Err("missing value".into());
                }
                rest.to_owned()
            }
        };
        let entry = ProcEntry { field, value };
        if !self.entries.iter().any(|e| e == &entry) {
            self.entries.push(entry);
        }
        Ok(())
    }

    /// True when a lookup could possibly hit. Bundle/cmd-only sets do not:
    /// the resolver must not be called for them.
    pub fn matchable(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.field, ProcField::Name | ProcField::Path))
    }

    /// Label to put after `process:` when `info` hits, otherwise None.
    pub fn matched_label(&self, info: &ProcessInfo) -> Option<String> {
        let base = file_name(&info.path);
        let name = if info.name.is_empty() {
            base
        } else {
            info.name.as_str()
        };
        for entry in &self.entries {
            match entry.field {
                ProcField::Name => {
                    if (!name.is_empty() && name == entry.value)
                        || (!base.is_empty() && base == entry.value)
                    {
                        return Some(entry.value.clone());
                    }
                }
                ProcField::Path => {
                    if !info.path.is_empty() && info.path == entry.value {
                        if !name.is_empty() {
                            return Some(name.to_owned());
                        }
                        let from_rule = file_name(&entry.value);
                        if !from_rule.is_empty() {
                            return Some(from_rule.to_owned());
                        }
                    }
                }
                ProcField::Bundle | ProcField::Cmd => {}
            }
        }
        None
    }
}

/// Built-in process list (`data/ai-processes.txt`). A bad line is a bug.
pub fn builtin_ai_processes() -> AiProcessSet {
    AiProcessSet::parse(include_str!("../data/ai-processes.txt")).expect("builtin AI processes")
}

fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Cache key. The address is unmapped, so a v4-mapped v6 socket shares
/// the v4 entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OwnerKey {
    pub proto: Proto,
    pub addr: IpAddr,
    pub port: u16,
}

impl OwnerKey {
    pub fn new(proto: Proto, local: SocketAddr) -> Self {
        Self {
            proto,
            addr: normalize_ip(local.ip()),
            port: local.port(),
        }
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Slot {
    at: Instant,
    info: Option<ProcessInfo>,
}

/// What [`OwnerCache::get`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheGet {
    Miss,
    Hit(Option<ProcessInfo>),
}

/// `(proto, local address, local port)` → owner, with a TTL and a cap.
/// Expired entries do not count as hits. At the cap, the oldest entry is
/// dropped to make room.
pub struct OwnerCache {
    ttl: Duration,
    cap: usize,
    map: HashMap<OwnerKey, Slot>,
}

impl OwnerCache {
    pub fn new(ttl: Duration, cap: usize) -> Self {
        Self {
            ttl,
            cap,
            map: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&mut self, key: OwnerKey, now: Instant) -> CacheGet {
        let fresh = match self.map.get(&key) {
            Some(slot) => now.saturating_duration_since(slot.at) < self.ttl,
            None => return CacheGet::Miss,
        };
        if !fresh {
            self.map.remove(&key);
            return CacheGet::Miss;
        }
        CacheGet::Hit(self.map.get(&key).map(|s| s.info.clone()).unwrap_or(None))
    }

    pub fn insert(&mut self, key: OwnerKey, info: Option<ProcessInfo>, now: Instant) {
        if self.cap == 0 {
            return;
        }
        if let Some(slot) = self.map.get_mut(&key) {
            slot.at = now;
            slot.info = info;
            return;
        }
        self.map
            .retain(|_, slot| now.saturating_duration_since(slot.at) < self.ttl);
        while self.map.len() >= self.cap {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, slot)| slot.at)
                .map(|(k, _)| *k);
            let Some(oldest) = oldest else {
                break;
            };
            self.map.remove(&oldest);
        }
        self.map.insert(key, Slot { at: now, info });
    }
}

#[cfg(target_os = "macos")]
const CACHE_TTL: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
const CACHE_CAP: usize = 4096;

/// PCB list parser. Compiled into the macOS resolver and into tests (the
/// layout checks run on every OS). A non-macOS library build has no caller.
#[cfg(any(test, target_os = "macos"))]
mod pcb {
    use super::*;

    /// `xinpgen` is 24 bytes on the current export. The header's own `xig_len`
    /// is trusted when it looks like a size.
    const XINPGEN_FALLBACK: usize = 24;
    /// `so_last_pid` inside `xsocket_n` (pack-4 layout).
    pub(super) const PID_IN_XSOCKET: usize = 68;
    pub(super) const VFLAG_OFF: usize = 44;
    pub(super) const LPORT_OFF: usize = 18;
    pub(super) const LADDR_OFF: usize = 64;
    /// IPv4 sits 12 bytes into `in_addr_4in6` (three pad words, then the address).
    pub(super) const IPV4_IN_4IN6: usize = 12;
    pub(super) const INP_IPV4: u8 = 0x1;
    pub(super) const INP_IPV6: u8 = 0x2;
    /// `xtcpcb_n` rounded up to 8, added to the socket record for TCP.
    pub(super) const TCP_CB_BYTES: usize = 208;

    fn roundup8(n: usize) -> usize {
        n.saturating_add(7) & !7
    }

    fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
        let b = buf.get(off..off + 4)?;
        Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_port(buf: &[u8]) -> Option<u16> {
        let b = buf.get(LPORT_OFF..LPORT_OFF + 2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    fn read_v6(buf: &[u8], off: usize) -> Option<Ipv6Addr> {
        let b = buf.get(off..off + 16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Some(Ipv6Addr::from(octets))
    }

    /// Socket-table bytes before the TCP control block: 408 since Darwin 22
    /// (`xinpcb_n` + `xsocket_n` + two `xsockbuf_n` + `xsockstat_n`, each
    /// rounded to 8), 384 before that.
    fn socket_table_len() -> usize {
        #[cfg(target_os = "macos")]
        {
            if super::darwin::osrelease_major().unwrap_or(22) >= 22 {
                408
            } else {
                384
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            408
        }
    }

    fn fallback_stride(tcp: bool) -> usize {
        let base = socket_table_len();
        if tcp {
            base + TCP_CB_BYTES
        } else {
            base
        }
    }

    /// Pid of the socket bound to `local`, from a `pcblist_n` buffer. `None`
    /// when the buffer is not that table or nothing matches. UDP may fall
    /// back to an unspecified local address on the same port (a wildcard
    /// bind); TCP does not, so a listener is not blamed for a connection.
    pub(super) fn find_owner_pid(buf: &[u8], local: SocketAddr, tcp: bool) -> Option<u32> {
        let header = match read_u32(buf, 0) {
            Some(n) if (16..=128).contains(&n) && n as usize <= buf.len() => n as usize,
            _ => XINPGEN_FALLBACK,
        };
        if buf.len() < header + 4 {
            return None;
        }
        let count = read_u32(buf, 4)? as usize;
        if count == 0 {
            return None;
        }
        let stride = detect_stride(buf, header, count, tcp)?;
        let want = normalize_ip(local.ip());
        let mut wildcard: Option<u32> = None;
        let mut off = header;
        let mut seen = 0usize;
        while seen < count && off + stride <= buf.len() {
            let rec = &buf[off..off + stride];
            off += stride;
            seen += 1;
            let Some(pid) = record_pid(rec) else {
                continue;
            };
            if read_port(rec) != Some(local.port()) {
                continue;
            }
            let Some(addr) = record_local(rec, want) else {
                continue;
            };
            if addr == want {
                return Some(pid);
            }
            if !tcp && wildcard.is_none() && addr.is_unspecified() {
                wildcard = Some(pid);
            }
        }
        wildcard
    }

    fn detect_stride(buf: &[u8], header: usize, count: usize, tcp: bool) -> Option<usize> {
        let body = buf.len().saturating_sub(header);
        if count > 0 && body.is_multiple_of(count) {
            let stride = body / count;
            if stride >= PID_IN_XSOCKET + 8 && plausible_xi(buf, header) {
                return Some(stride);
            }
        }
        let stride = fallback_stride(tcp);
        if stride >= PID_IN_XSOCKET + 8 && header + stride <= buf.len() && plausible_xi(buf, header)
        {
            return Some(stride);
        }
        None
    }

    fn plausible_xi(buf: &[u8], off: usize) -> bool {
        matches!(read_u32(buf, off), Some(n) if (80..=512).contains(&n))
    }

    fn record_pid(rec: &[u8]) -> Option<u32> {
        let xi_len = read_u32(rec, 0)? as usize;
        if !(80..=512).contains(&xi_len) {
            return None;
        }
        let so = roundup8(xi_len);
        let xso_len = read_u32(rec, so)?;
        if !(64..=256).contains(&xso_len) {
            return None;
        }
        let pid = read_u32(rec, so + PID_IN_XSOCKET)?;
        if pid == 0 {
            None
        } else {
            Some(pid)
        }
    }

    fn record_local(rec: &[u8], want: IpAddr) -> Option<IpAddr> {
        let flag = *rec.get(VFLAG_OFF)?;
        match want {
            IpAddr::V4(_) => {
                if flag & INP_IPV4 != 0 {
                    let off = LADDR_OFF + IPV4_IN_4IN6;
                    let b = rec.get(off..off + 4)?;
                    return Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
                }
                if flag & INP_IPV6 != 0 {
                    let mapped = read_v6(rec, LADDR_OFF)?.to_ipv4_mapped()?;
                    return Some(IpAddr::V4(mapped));
                }
                None
            }
            IpAddr::V6(_) => {
                if flag & INP_IPV6 == 0 {
                    return None;
                }
                Some(IpAddr::V6(read_v6(rec, LADDR_OFF)?))
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::CStr;
    use std::sync::{Mutex, OnceLock};

    use super::pcb::find_owner_pid;
    use super::{
        file_name, OwnerCache, OwnerKey, OwnerResolver, ProcessInfo, Proto, CACHE_CAP, CACHE_TTL,
    };

    extern "C" {
        fn proc_pidpath(
            pid: libc::c_int,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }

    pub struct DarwinOwner {
        cache: Mutex<OwnerCache>,
    }

    pub fn shared() -> &'static DarwinOwner {
        static OWNER: OnceLock<DarwinOwner> = OnceLock::new();
        OWNER.get_or_init(|| DarwinOwner {
            cache: Mutex::new(OwnerCache::new(CACHE_TTL, CACHE_CAP)),
        })
    }

    impl OwnerResolver for DarwinOwner {
        fn owner(&self, proto: Proto, local: std::net::SocketAddr) -> Option<ProcessInfo> {
            let key = OwnerKey::new(proto, local);
            let now = std::time::Instant::now();
            let cached = self
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(key, now);
            if let super::CacheGet::Hit(info) = cached {
                return info;
            }
            let found = lookup(proto, local);
            self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(
                key,
                found.clone(),
                std::time::Instant::now(),
            );
            found
        }
    }

    fn lookup(proto: Proto, local: std::net::SocketAddr) -> Option<ProcessInfo> {
        let tcp = matches!(proto, Proto::Tcp);
        let name = if tcp {
            c"net.inet.tcp.pcblist_n"
        } else {
            c"net.inet.udp.pcblist_n"
        };
        let buf = sysctl_raw(name)?;
        let pid = find_owner_pid(&buf, local, tcp)?;
        let path = path_for_pid(pid)?;
        let name = file_name(&path).to_owned();
        if name.is_empty() {
            return None;
        }
        Some(ProcessInfo { pid, name, path })
    }

    fn sysctl_raw(name: &CStr) -> Option<Vec<u8>> {
        let mut len: libc::size_t = 0;
        // Size probe. A null oldp writes the estimate into `len`.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len == 0 {
            return None;
        }
        let mut cap = len.saturating_add(len / 2).max(len.saturating_add(65_536));
        for _ in 0..4 {
            let mut buf = vec![0u8; cap];
            let mut out = buf.len();
            let rc = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    &mut out,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc == 0 {
                if out > buf.len() {
                    return None;
                }
                buf.truncate(out);
                return Some(buf);
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOMEM) {
                return None;
            }
            cap = cap.saturating_mul(2);
        }
        None
    }

    fn path_for_pid(pid: u32) -> Option<String> {
        let mut buf = vec![0u8; 4096];
        // proc_pidpath writes a NUL-terminated path and returns its length.
        let n = unsafe {
            proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return None;
        }
        let end = (n as usize).min(buf.len());
        let bytes = buf[..end].split(|b| *b == 0).next().unwrap_or(b"");
        let path = std::str::from_utf8(bytes).ok()?;
        if path.is_empty() {
            None
        } else {
            Some(path.to_owned())
        }
    }

    pub(super) fn osrelease_major() -> Option<u32> {
        let mut buf = [0u8; 32];
        let mut len = buf.len();
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.osrelease".as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let text = CStr::from_bytes_until_nul(&buf).ok()?.to_str().ok()?;
        text.split('.').next()?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::pcb::{
        find_owner_pid, INP_IPV4, INP_IPV6, IPV4_IN_4IN6, LADDR_OFF, LPORT_OFF, PID_IN_XSOCKET,
        TCP_CB_BYTES, VFLAG_OFF,
    };
    use super::{
        builtin_ai_processes, AiProcessSet, CacheGet, OwnerCache, OwnerKey, OwnerResolver,
        ProcessInfo, Proto, UnknownOwner,
    };

    fn addr(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    #[test]
    fn parser_accepts_the_four_kinds_and_rejects_a_bad_line() {
        let set = AiProcessSet::parse(
            "# comment\n\nname claude\nname codex\npath /usr/local/bin/claude\nbundle com.anthropic.claude\ncmd claude --model opus\nname claude # twice\n",
        )
        .unwrap();
        assert!(set.matchable());
        let claude = ProcessInfo {
            pid: 1,
            name: "claude".into(),
            path: "/usr/local/bin/claude".into(),
        };
        assert_eq!(set.matched_label(&claude).as_deref(), Some("claude"));
        let by_path_only = AiProcessSet::parse("path /opt/codex\n").unwrap();
        assert_eq!(
            by_path_only
                .matched_label(&ProcessInfo {
                    pid: 2,
                    name: "codex".into(),
                    path: "/opt/codex".into(),
                })
                .as_deref(),
            Some("codex")
        );
        assert!(by_path_only
            .matched_label(&ProcessInfo {
                pid: 2,
                name: "codex".into(),
                path: "/opt/other".into(),
            })
            .is_none());
        // bundle and cmd are stored but do not match, and do not make the
        // set worth a lookup.
        let stored = AiProcessSet::parse("bundle com.anthropic.claude\ncmd claude\n").unwrap();
        assert!(!stored.matchable());
        assert!(stored.matched_label(&claude).is_none());
        assert!(AiProcessSet::parse("name\n").is_err());
        assert!(AiProcessSet::parse("name claude extra\n").is_err());
        assert!(AiProcessSet::parse("nope claude\n").is_err());
        assert!(AiProcessSet::parse("bundle\n").is_err());
        assert!(AiProcessSet::parse("bundle a b\n").is_err());
        assert!(AiProcessSet::parse("path\n").is_err());
        assert!(AiProcessSet::parse("cmd\n").is_err());
        let builtin = builtin_ai_processes();
        assert!(builtin.matchable());
        assert_eq!(builtin.matched_label(&claude).as_deref(), Some("claude"));
    }

    #[test]
    fn cache_expires_and_respects_the_cap() {
        let mut cache = OwnerCache::new(Duration::from_secs(30), 2);
        let now = Instant::now();
        let key = |port| OwnerKey::new(Proto::Tcp, addr(Ipv4Addr::LOCALHOST.into(), port));
        let info = |name: &str| {
            Some(ProcessInfo {
                pid: 1,
                name: name.into(),
                path: format!("/bin/{name}"),
            })
        };
        assert!(matches!(cache.get(key(1), now), CacheGet::Miss));
        cache.insert(key(1), info("a"), now);
        cache.insert(key(2), info("b"), now + Duration::from_secs(1));
        assert_eq!(cache.len(), 2);
        match cache.get(key(1), now + Duration::from_secs(29)) {
            CacheGet::Hit(Some(hit)) => assert_eq!(hit.name, "a"),
            other => panic!("expected a fresh hit, got {other:?}"),
        }
        assert!(matches!(
            cache.get(key(1), now + Duration::from_secs(30)),
            CacheGet::Miss
        ));
        // The expired entry was dropped by get. Fill the cap again and
        // force an eviction of the oldest remaining slot.
        cache.insert(key(1), info("a"), now + Duration::from_secs(30));
        cache.insert(key(3), info("c"), now + Duration::from_secs(31));
        assert_eq!(cache.len(), 2);
        assert!(matches!(
            cache.get(key(2), now + Duration::from_secs(31)),
            CacheGet::Miss
        ));
        assert!(matches!(
            cache.get(key(3), now + Duration::from_secs(31)),
            CacheGet::Hit(_)
        ));
        // A miss is cached too, so a failed lookup is not repeated.
        cache.insert(key(9), None, now);
        assert_eq!(cache.get(key(9), now), CacheGet::Hit(None));
    }

    struct CountOwner {
        calls: AtomicUsize,
    }

    impl OwnerResolver for CountOwner {
        fn owner(&self, _proto: Proto, _local: SocketAddr) -> Option<ProcessInfo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            None
        }
    }

    #[test]
    fn fake_resolver_is_what_the_trait_returns() {
        let owner = CountOwner {
            calls: AtomicUsize::new(0),
        };
        assert!(owner
            .owner(Proto::Udp, addr(Ipv4Addr::LOCALHOST.into(), 9))
            .is_none());
        assert_eq!(owner.calls.load(Ordering::SeqCst), 1);
        assert!(UnknownOwner
            .owner(Proto::Tcp, addr(Ipv4Addr::LOCALHOST.into(), 9))
            .is_none());
    }

    fn pcb_record(
        port: u16,
        flag: u8,
        addr_at: usize,
        octets: &[u8],
        pid: u32,
        stride: usize,
    ) -> Vec<u8> {
        let mut rec = vec![0u8; stride];
        rec[0..4].copy_from_slice(&104u32.to_ne_bytes());
        rec[LPORT_OFF..LPORT_OFF + 2].copy_from_slice(&port.to_be_bytes());
        rec[VFLAG_OFF] = flag;
        rec[addr_at..addr_at + octets.len()].copy_from_slice(octets);
        // xsocket_n begins at roundup8(xi_len) == 104; its length field
        // has to look like a real xsocket or the record is skipped.
        rec[104..108].copy_from_slice(&104u32.to_ne_bytes());
        let pid_at = 104 + PID_IN_XSOCKET;
        rec[pid_at..pid_at + 4].copy_from_slice(&pid.to_ne_bytes());
        rec
    }

    fn table(records: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&24u32.to_ne_bytes());
        buf[4..8].copy_from_slice(&(records.len() as u32).to_ne_bytes());
        for rec in records {
            buf.extend_from_slice(rec);
        }
        buf
    }

    #[test]
    fn pcb_scan_matches_the_local_endpoint_and_not_a_wildcard_tcp_listener() {
        let stride = 408 + TCP_CB_BYTES;
        let v4 = pcb_record(
            54321,
            INP_IPV4,
            LADDR_OFF + IPV4_IN_4IN6,
            &[127, 0, 0, 1],
            4242,
            stride,
        );
        let buf = table(&[v4]);
        let local = addr(Ipv4Addr::LOCALHOST.into(), 54321);
        assert_eq!(find_owner_pid(&buf, local, true), Some(4242));
        // A v4-mapped query is the same socket.
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert_eq!(
            find_owner_pid(&buf, addr(IpAddr::V6(mapped), 54321), true),
            Some(4242)
        );
        assert_eq!(
            find_owner_pid(&buf, addr(Ipv4Addr::LOCALHOST.into(), 1), true),
            None
        );

        let wild = pcb_record(
            54321,
            INP_IPV4,
            LADDR_OFF + IPV4_IN_4IN6,
            &[0, 0, 0, 0],
            7,
            stride,
        );
        let wild_buf = table(&[wild]);
        assert_eq!(find_owner_pid(&wild_buf, local, true), None);
        assert_eq!(find_owner_pid(&wild_buf, local, false), Some(7));

        let exact = pcb_record(
            54321,
            INP_IPV4,
            LADDR_OFF + IPV4_IN_4IN6,
            &[127, 0, 0, 1],
            99,
            stride,
        );
        let earlier_wild = pcb_record(
            54321,
            INP_IPV4,
            LADDR_OFF + IPV4_IN_4IN6,
            &[0, 0, 0, 0],
            7,
            stride,
        );
        let both = table(&[earlier_wild, exact]);
        assert_eq!(find_owner_pid(&both, local, false), Some(99));

        let mut v6_octets = [0u8; 16];
        v6_octets[15] = 1;
        let v6 = pcb_record(80, INP_IPV6, LADDR_OFF, &v6_octets, 55, stride);
        let v6_buf = table(&[v6]);
        assert_eq!(
            find_owner_pid(&v6_buf, addr(IpAddr::V6(Ipv6Addr::LOCALHOST), 80), true),
            Some(55)
        );
        assert_eq!(find_owner_pid(&[], local, true), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resolver_names_this_test_binary_for_its_local_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _accepted = listener.accept().unwrap();
        let local = client.local_addr().unwrap();
        let info = super::darwin::shared()
            .owner(Proto::Tcp, local)
            .unwrap_or_else(|| panic!("no owner for {local}"));
        assert_eq!(info.pid, std::process::id(), "path {}", info.path);
        let exe = std::env::current_exe().unwrap();
        let expect = exe.file_name().unwrap().to_string_lossy();
        assert_eq!(info.name, expect.as_ref(), "path {}", info.path);
        assert!(
            info.path.ends_with(expect.as_ref()),
            "path {} does not end with {expect}",
            info.path
        );
    }
}
