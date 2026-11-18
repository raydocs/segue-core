# Finding the process that owns a connection

How sing-box and mihomo map a flow back to the process that opened its socket,
per OS, and what Segue should build. Read-only research: the reference trees
(`/Volumes/dev/ref/sing-box`, `/Volumes/dev/ref/mihomo`, `/Volumes/dev/ref/sing-tun`,
`/Volumes/dev/ref/apps/sing-box-for-android`) are GPL. Nothing below is copied
into Segue; only the approach is.

Status: research, no code. Owner: kernel. Related:
[`ai-lock.md`](./ai-lock.md), [`ffi-kernel-embedding.md`](./ffi-kernel-embedding.md).

## 0. Summary

| OS | API | Root? | Key | Cached |
|---|---|---|---|---|
| macOS | `sysctl net.inet.{tcp,udp}.pcblist_n` + `proc_pidpath` | no (verified) | proto + local addr/port (+ dest) | 200 ms snapshot, 200 ms router cache |
| Windows | `GetExtendedTcpTable` / `GetExtendedUdpTable` + `QueryFullProcessImageName` | no for own user | proto + local addr/port | none |
| Linux | netlink `INET_DIAG` + `/proc/<pid>/fd` inode scan | own uid only; root for others | proto + local addr/port (+ dest) | 1 s per-uid path map |
| Android | `ConnectivityManager.getConnectionOwnerUid` (API 29+) or `/proc/net/*` | no (app API) | proto + local addr/port (+ dest) | none |
| iOS | — | — | — | — |

iOS: impossible outside a jailbreak. The app sandbox denies `sysctl
net.inet.*.pcblist_n` and `proc_pidpath` for other processes, and a
NetworkExtension runs in its own container, so there is no way to name the
process behind a flow. sing-box's own matrix says process rules are "only
supported in the macOS standalone and iOS jailbreak versions"
(`sing-box/docs/clients/apple/features.md:42-44`).

## 1. macOS

### 1.1 The API

Both projects read the kernel's per-socket control blocks with
`sysctlbyname("net.inet.tcp.pcblist_n")` and `"net.inet.udp.pcblist_n"`
(`sing-box/common/process/searcher_darwin_shared.go:169-179`;
`mihomo/component/process/process_darwin.go:36-52`). The `_n` suffix is the
variant that carries the `xsocket_n` block with pid and uid; the plain
`pcblist` does not.

The buffer is a 24-byte `xinpgen` header followed by fixed-size records
(`searcher_darwin_shared.go:181-192`). Record size depends on the kernel
version, keyed off `kern.osrelease` major: 408 bytes for Darwin ≥ 22 (macOS 13),
384 before (`searcher_darwin.go:35-49`). TCP records add 208 bytes for
`xtcpcb_n` (`searcher_darwin_shared.go:34,173`). There is no ABI-stable way to
read the size; both projects hard-code the two values.

Offsets inside a record, identical in both trees
(`searcher_darwin_shared.go:23-34`; `process_darwin.go:63-101`):

| field | offset | notes |
|---|---|---|
| `xinpcb_n` start | 0 | |
| foreign (remote) port | 16 | big-endian u16 |
| local port | 18 | big-endian u16 |
| `inp_vflag` | 44 | bit 0 = IPv4, bit 1 = IPv6 |
| foreign addr | 48 | 16 bytes; IPv4 at +12 |
| local addr | 64 | 16 bytes; IPv4 at +12 |
| `xsocket_n` start | 104 | |
| `so_uid` | 104+64 = 168 | native-endian i32 |
| `so_last_pid` | 104+68 = 172 | native-endian u32 |
| `so_effective_pid` | 104+72 = 176 | native-endian u32 |

I verified these offsets against a live snapshot on this machine (Darwin 27.0.0,
macOS 26): parsing `net.inet.tcp.pcblist_n` with record size 616 (408+208) and
`net.inet.udp.pcblist_n` with 408 yields sane ports, addresses, pids and uids,
and the TCP entry count matches `netstat -an -p tcp` exactly.

**Root is not required.** As uid 501 I read both sysctls and saw sockets owned
by uid 0 and uid 65, and `proc_pidpath` returned paths for root-owned pids
(`/sbin/launchd`, `apsd`, a WebKit XPC service). Neither project asks for
privilege on macOS.

The path comes from `proc_pidpath` (`SYS_PROC_INFO` / `PROC_PIDPATHINFO`,
`searcher_darwin_shared.go:267-286`; `process_darwin.go:112-127`).

### 1.2 Lookup key and matching

sing-box takes `(network, source AddrPort, destination AddrPort)`
(`searcher_darwin_shared.go:77-79`). It normalises v4-mapped addresses with
`Unmap` (`:260-265`), then scans for a record whose local port and address
family match the source (`:220-258`):

1. exact: local addr == source **and** remote addr/port == destination;
2. if no destination was given (UDP), local addr == source;
3. UDP only: local addr == source (unconnected socket), then local addr
   unspecified (`0.0.0.0` / `::`).

A cached snapshot that only produced a fallback match is discarded and the
snapshot rebuilt once (`:86-125`), so a stale cache cannot pin a wrong pid.

mihomo takes only `(network, source IP, source port)` — no destination
(`process.go:21-23`, `process_darwin.go:36`). It matches local port, then local
address, and for UDP keeps a fallback for a socket bound to the unspecified
address (`process_darwin.go:63-107`). It always returns uid 0 on macOS
(`:96,106`); sing-box reports the real uid.

### 1.3 Cost and caching

One sysctl read is a full copy of every socket on the machine — ~60 KB and
~100 records for TCP on an idle laptop, more under load. sing-box caches the
parsed snapshot per network for 200 ms (`searcher_darwin_shared.go:21,67,138-152`)
and adds a router-level cache of 256 entries, 200 ms lifetime, keyed by
`(network, source, destination)` (`route/router.go:203-204`;
`route/process_cache.go:13-36`). mihomo caches nothing: every lookup re-reads
the sysctl.

### 1.4 What they match on

sing-box reports `ProcessPaths` (a list) and `UserId`; rules match
`process_name` on `filepath.Base(path)`, `process_path` on the full path, and
`process_path_regex` on the path (`route/rule/rule_item_process_name.go:29-34`,
`rule_item_process_path.go:29-35`, `rule_item_process_path_regex.go:41-48`).
mihomo reports `Process` (basename) and `ProcessPath`, with exact, regex and
wildcard variants (`rules/common/process.go:32-52`).

**Responsible process.** sing-box prefers `so_effective_pid` over `so_last_pid`
and, when they differ, reports *both* paths, effective first
(`searcher_darwin_shared.go:112-118`). That is how a helper or XPC service that
opens the socket on behalf of an app is attributed to the app. mihomo uses only
`so_last_pid` (`process_darwin.go:94,101`).

**`node`-run CLIs.** Neither project reads argv or `KERN_PROCARGS` on macOS or
Windows (grep finds no `procargs`/`argv` in either `common/process` or
`component/process`). A script run by `node` is therefore reported as the
`node` binary, and every such script is indistinguishable. Only mihomo on
Android reads `/proc/<pid>/cmdline` (`process_linux.go:213-221,274-285`), and
only to get a process name, not to separate scripts. A rule that wants to
distinguish `node` CLIs must match on the working directory or an env marker,
which neither does.

## 2. Windows

### 2.1 The API

`GetExtendedTcpTable` with class `TCP_TABLE_OWNER_PID_CONNECTIONS` (4) and
`GetExtendedUdpTable` with `UDP_TABLE_OWNER_PID` (1), both from `iphlpapi.dll`
(`mihomo/component/process/process_windows.go:15-21,78-89`). sing-box wraps the
same calls in `common/winiphlpapi` (`searcher_windows.go:28-30,39-42`). The
table is a 4-byte row count followed by fixed-size rows; the row layout differs
per family and protocol (`process_windows.go:152-178`):

| table | row size | local port | local addr | pid | state |
|---|---|---|---|---|---|
| `MIB_TCPROW_OWNER_PID` | 24 | 8 | 4 | 20 | 0 |
| `MIB_UDPROW_OWNER_PID` | 12 | 4 | 0 | 8 | — |
| `MIB_TCP6ROW_OWNER_PID` | 56 | 20 | 0 | 52 | 48 |
| `MIB_UDP6ROW_OWNER_PID` | 28 | 20 | 0 | 24 | — |

The port is stored network-endian in the low 16 bits of a native u32, so it
needs `Ntohs` (`process_windows.go:129-134`). The path comes from
`QueryFullProcessImageNameW` after `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`
(`process_windows.go:200-229`; `searcher_windows.go:81-100`). Pids 0 and 4 are
special-cased to `:System Idle Process` and `:System`
(`process_windows.go:201-209`).

No admin is needed for processes of the same user; `OpenProcess` on another
user's process needs elevation. (Not verified here — no Windows host.)

### 2.2 Lookup key and matching

Both take `(network, source IP, source port)` and match local port then local
address (`process_windows.go:115-150`; `searcher_windows.go:39-42`). TCP rows
are filtered to state 5 (`MIB_TCP_STATE_ESTAB`) so a listener or a
`TIME_WAIT` row cannot win (`process_windows.go:121-127`). UDP accepts a row
bound to the unspecified address, because Windows binds an unbound UDP socket
to `0.0.0.0`/`::` on first `sendto` (`:141-144`).

sing-box additionally resolves a service's DLL path from the registry when the
owner is a service (`searcher_windows.go:49-79`), so a rule can match the
service binary rather than `svchost.exe`.

### 2.3 Cost and caching

One `GetExtended*Table` call returns every connection of that family and
protocol — the same order of cost as the macOS sysctl. Neither project caches
on Windows (`searcher_windows.go:32-33`; mihomo has no cache at all).

## 3. Linux

### 3.1 The API

netlink `NETLINK_INET_DIAG` with `SOCK_DIAG_BY_FAMILY` (20)
(`sing-box/common/process/socket_diag_linux.go:107-130`;
`mihomo/component/process/process_linux.go:93-131`). The request is a 56-byte
`inet_diag_req_v2`-shaped struct: family, protocol, states, source/dest ports
and addresses (`socket_diag_linux.go:141-183`). The response carries uid at
offset 64 and inode at 68 (`:303-325`).

sing-box first tries an exact-match query, then falls back to a dump filtered
by local port (`searcher_linux.go:113-134`, `socket_diag_linux.go:219-301`).
The dump only filters by port, so every socket in the namespace with that local
port comes back and the code re-checks the address (`socket_diag_linux.go:216-218,281-297`).
A dual-stack socket carrying a v4-mapped address is only listed under
`AF_INET6`, so an `AF_INET` dump is retried as `AF_INET6` (`:219-231`).

UDP has a quirk: `udp_dump_one` expects the endpoints reversed, so the request
swaps source and destination for UDP (`socket_diag_linux.go:163-166`).

The inode is then mapped to a process by scanning `/proc/<pid>/fd` for a
`socket:[<inode>]` link (`searcher_linux.go:164-214`). sing-box scans the
socket's uid first, then all users, because a socket keeps the uid it was
created with while `/proc` shows the process's current uid — a socket created
before a privilege drop only appears under a full scan (`searcher_linux.go:136-162`).

**Privilege.** The kernel allows an unprivileged `INET_DIAG` dump only for the
caller's own sockets; other users' sockets need `CAP_NET_ADMIN` (root). Reading
another user's `/proc/<pid>/fd` likewise needs root. The code does not check
this; the kernel enforces it.

### 3.2 Lookup key and matching

sing-box takes `(network, source, destination)` and matches local port, then
local address, then (UDP) the unspecified address
(`socket_diag_linux.go:281-297`). mihomo takes `(network, source IP, source
port)` only (`process_linux.go:65-91`).

### 3.3 Cost and caching

The netlink query is cheap; the `/proc` scan is the expensive part — it walks
every pid and every fd. sing-box caches the inode→paths map per uid for 1 s, 64
entries (`searcher_linux.go:47-48,140-162`). mihomo caches nothing.

### 3.4 Android

Android is Linux with two differences. On API 29+ the app asks the platform
directly: `ConnectivityManager.getConnectionOwnerUid(protocol, source, dest)`
(`apps/sing-box-for-android/.../bg/PlatformInterfaceWrapper.kt:60-90`), which
returns the uid without any netlink or `/proc` work. Below 29 it falls back to
the `/proc/net/{tcp,tcp6,udp,udp6}` scan
(`sing-box/experimental/libbox/internal/procfs/procfs.go:35-120`), which parses
the hex `local_address` column and ranks exact IP+port above port-only
(`:95-119`). mihomo does the same `/proc/net` scan as a fallback when netlink
fails or returns uid 0 (`process_linux.go:65-91,297-420`).

The uid is then turned into a package name. sing-box reads
`/data/system/packages.xml` through the `tun.PackageManager`
(`sing-tun/packages_android.go:97-105`; `searcher_linux.go:99-109`), taking
`uid % 100000` as the app id. The Android app itself uses
`PackageManager.getPackagesForUid` (`PlatformInterfaceWrapper.kt:81-83`).
mihomo exposes a `PackageNameResolver` hook for the same job
(`component/process/process.go:25-38`).

Android also filters `/system/bin/app_process` out of the path list, because
every app process is a fork of it (`searcher_linux.go:92-95`).

## 4. TUN specifics on macOS

A flow read from a utun has `src` = the application's socket local address,
because the app's socket is bound to the utun interface address and the packet
the kernel hands the utun carries that same source. So the lookup key is
exactly the flow's `(proto, src, src_port)` — no translation is needed.

sing-box guards this with `isLocalSource`: it only looks up a source that is
loopback or one of the machine's interface addresses
(`route/process_cache.go:78-95`), which includes the utun address. The
destination it passes is `OriginDestination` when the inbound recorded one
(the pre-NAT destination), else `Destination` (`route/process_cache.go:42-48`).
For a plain TUN flow the destination is the real one; for UDP the destination
may be absent, which is why the UDP fallbacks exist.

Segue's utun defaults are `172.19.0.1/30` with peer `172.19.0.2`
(`crates/segue-kernel/src/tun_setup.rs:34-35`), so an app's source is one of
those two addresses. Segue's smoltcp stack terminates TCP in userspace but the
app's socket is still a real kernel socket bound to the utun address, so the
pcblist entry exists and the lookup works the same way.

## 5. When they look up at all

sing-box computes `needFindProcess` once at router init from the rule table
(`route/router.go:65`), from rule-set metadata (`:171-181`), and forces it on
Android (`:178-180`). Only then is a searcher constructed (`:182-198`). The
lookup itself runs once per flow, before matching
(`route/process_cache.go:38-76`; called from `route/route.go:565` and the DNS
hijack paths `route/dns.go:21,41,63`).

mihomo has an explicit `find-process-mode` (`component/process/find_process_mode.go:8-12`):
`strict` (default) looks up lazily, only when a process rule is evaluated
(`rules/common/process.go:33-35`); `always` looks up eagerly for every
connection (`tunnel/tunnel.go:400-403`); `off` never does. Inner connections
skip the lookup (`tunnel/tunnel.go:335`).

## 6. Recommendation for Segue

### 6.1 Shape

Add a resolver behind a trait in `segue-kernel`, in a new module (the existing
`crates/segue-kernel/src/process.rs` is about the kernel's own process
lifecycle — exit codes, log file — and should not be overloaded):

```rust
// crates/segue-kernel/src/process_owner.rs
pub struct ProcessOwner {
    pub pid: u32,
    pub uid: u32,
    /// Effective (responsible) process first, then the socket's own.
    pub paths: Vec<PathBuf>,
}

pub trait ProcessResolver: Send + Sync {
    /// `local` is the flow's source; `remote` may be unspecified for UDP.
    fn owner(&self, proto: Proto, local: SocketAddr, remote: SocketAddr)
        -> Option<ProcessOwner>;
}
```

`Kernel` gains `pub process: Option<Arc<dyn ProcessResolver>>`
(`crates/segue-kernel/src/socks.rs:49`), defaulting to `None`. `TunKernel`
consults it in `route_tcp` / `route_udp`
(`crates/segue-kernel/src/tun.rs:2084-2135`) only when the AI tier has process
entries, and passes the result into the rule decision.

### 6.2 macOS implementation

1. `libc::sysctlbyname("net.inet.tcp.pcblist_n")` / `"net.inet.udp.pcblist_n"`,
   record size 408 (+208 for TCP) on Darwin ≥ 22, 384 otherwise, keyed off
   `kern.osrelease` — the same two values sing-box and mihomo use
   (`searcher_darwin.go:35-49`).
2. Parse with the offsets in §1.1. Match local port, then local address, then
   (UDP) the unspecified address. Prefer `so_effective_pid` and report both
   paths, effective first (`searcher_darwin_shared.go:112-118`).
3. `proc_pidpath` for each pid (`searcher_darwin_shared.go:267-286`).
4. No root, no entitlement. Verified on this machine.

### 6.3 Cache

Key `(proto, local addr, local port)`, TTL 200 ms–1 s, small fixed capacity
(256 entries is what sing-box uses, `route/router.go:203-204`). Excluding the
remote address is deliberate: UDP sockets are often unconnected, and the same
local port can be reused, so a short TTL bounds staleness. Cache the *snapshot*
per protocol for the same TTL so a burst of new flows costs one sysctl read,
not one per flow. Do the lookup on the flow's first packet only (SYN or first
datagram), never per packet.

### 6.4 Enablement

Only construct the resolver when the AI tier carries process entries. Today
`AiTier` holds only `suffixes` and `cidrs`
(`crates/segue-kernel/src/rules.rs:54-58`); add an optional
`processes: Vec<String>` (or a separate process rule list) and build the
resolver only when it is non-empty. With no process entries the default path
stays free of sysctl cost, matching sing-box's `needFindProcess` gate and
mihomo's `strict` mode.

### 6.5 Failure behaviour

`owner()` returns `Option`. `None` — sysctl failed, no matching record, or
`proc_pidpath` failed — means the AI tier's process matcher does not match, and
the flow falls through to the domain and IP tiers exactly as it does today.
Never block, never refuse, never delay the SYN beyond the single lookup. A
resolver that panics or returns a stale pid must not change a routing decision
that the domain/IP tiers would otherwise make.

### 6.6 What not to do

- Do not read argv to separate `node` scripts; neither reference does, and it
  is not reliable.
- Do not cache by pid alone: pids are reused.
- Do not look up on every packet, and do not look up when no rule needs it.
- Do not require root on macOS; it is not needed and would break the app.
