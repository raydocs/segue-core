# Segue Windows app

Status: design, 2026-11-17. Second platform, after macOS. Windows ships after the
macOS beta, and it is not a port of the macOS app: the process split is the same,
the enforcement primitive is different.

Read with `docs/design/app/macos.md` (the process model this mirrors and the
reasoning for the root helper), `docs/design/app/segue-client.md` §8 stage 11 and
§4.2, `docs/design/ai-lock.md` (the kernel matrix; this document is the OS half),
and `docs/research/apps/kill-switch-survey.md` §1/§5/§8 (the Windows WFP
comparison). Reference code is read-only:
`/Volumes/dev/ref/apps/tono` at `006984ae` (Windows service in Rust, WFP rule
model, DNS/NRPT engine), `/Volumes/dev/ref/apps/mullvadvpn-app` at `7e0e4413`
(`talpid-winfw`), `/Volumes/dev/ref/apps/wireguard-windows` at `6ece77bc`
(`tunnel/firewall/blocker.go`), `/Volumes/dev/ref/apps/desktop-app` at
`98b99f55` (IVPN, boot-time filters, Go), and `/Volumes/dev/ref/sing-tun`
(`tun_windows.go`, `internal/wintun/`). Paths below are relative to the clone
named in the same paragraph unless they start with `crates/`, `docs/` or `apps/`
(this repository).

The headline is the same as macOS: AI traffic leaves only through the connected
IDC exit, other traffic keeps working, and that holds when Segue is dead. On
Windows the OS has a facility macOS does not — persistent and boot-time WFP
filters — so the AI layer can hold from before the service starts (`§2.5`),
which macOS cannot do at all (`macos.md` §2, "Reboot").

## What is copied

| | |
| --- | --- |
| **Lift, rename only** | `service/src/core/wfp_model.rs` (3313 lines, no `windows-sys`: the provider/sublayer GUIDs, weight ladder, `Condition`/`FilterSpec`, `expected_filters`, the tag-keyed diff) — `segue-client.md` §7.1 already names this as `crates/segue-helper/src/wfp_model.rs`. `service/src/core/wfp/mod.rs` engine shape (transaction, install-before-remove, verify-by-key, `FwpmGetAppIdFromFileName`) minus Tono's session/`Locked` modes. `service/src/core/dns/{snapshot,restore,restore_proof,status_cache,native_apply}.rs` (registry capture/restore discipline, lost-original markers). `service/src/release_wire.rs` (the second service's wire). `service/src/bin/install_service.rs` SCM install shape: staged copy verified by SHA-256 then renamed (`:44-100`, `:171-190`), BFE as a hard SCM dependency (`:2537`), recovery actions 5/10/30 s (`:2780-2805`). |
| **Lift, then change behaviour** | `ai_home_filters` (`wfp_model.rs:1100-1246`) becomes the whole steady state: today it is a mode under a block-all family; for Segue it is the only rule set. Its CIDR loop reads `three_tier::ai_home_held_ipv4_cidrs` (`crates/tono-core/src/three_tier.rs:163-190`); Segue reads `crates/segue-kernel/data/ai-lock.txt`. `selective_fail_open.rs` (suffix list, NRPT GUIDs) becomes the AI suffix table with no hard-coded Anthropic prefixes beyond what the kernel list carries. `TonoService`'s supervision/watchdog becomes "exit the kernel on a deadline, never release the layer" (`§2.6`). |
| **New** | WinTun backend and Windows tun mode in `segue-kernel` (`crates/segue-engine/src/tun_fd.rs:3466-3484` is `Unsupported` off Unix today). Windows outbound interface binding (`crates/segue-transport/src/socket_options.rs:597-616` is a no-op stub). Named-pipe IPC with an image-path + session check. A Tauri shell written fresh (Tono's is GPL-3.0-only, `apps/windows/app/package.json:4`, per `segue-client.md` §7.3). An MSI/NSIS installer, Authenticode signing. |
| **Not in the first beta** | Tono's `Locked`/`Blocked`/`Bootstrap` full-block modes, its LAN/RDP/DIRECT permit families (`wfp_model.rs:699-788`, `:935-1035`), its three-tier router, mihomo/sing-box, its account/catalog client, config import from other VPN products. Per-app filters. IPv6 dual-stack exit traffic beyond the AI CIDR drop. Linux. |

Two things are deliberately **not** copied as behaviour even though the code is
lifted: Tono's non-strict watchdog releases protection after three ticks
(`service/src/core/windows_kill_switch/policy.rs:40-56`), and its persistent
floor is a block-all with permits on top. Segue's shape is the opposite —
`ai_home_filters`' "block only AI prefixes, permit everything else by omission"
— because `docs/design/ai-lock.md` defines the product as narrower than a kill
switch.

## 1. Data plane

### 1.1 Where it lives

```
crates/segue-wintun/        wintun.dll bindings + safe Session (ring I/O)
crates/segue-kernel/src/tun_windows.rs
                            adapter lifecycle, addresses, routes, exit exclusion,
                            impl PacketIo for the wintun session
crates/segue-helper/        WFP rule model, engine, NRPT/DNS guard, intent,
                            release/update wire (the portable half)
apps/windows/service/       SegueService.exe: SCM entry, pipe, supervision,
                            arm/disarm latch, update executor
apps/windows/ui/            Tauri shell, unprivileged
```

`crates/segue-wintun` is a new workspace member: FFI (`WintunCreateAdapter`,
`WintunStartSession`, `WintunReceivePacket`/`ReleaseReceivePacket`,
`WintunAllocateSendPacket`/`SendPacket`, `WintunGetReadWaitEvent`, LUID and
driver-version queries) plus the ring bookkeeping. It has no policy and no
config. The reference for the call set is `internal/wintun/{wintun,session}_windows.go`
in `sing-tun`, which is WireGuard's own binding (both files carry
`SPDX-License-Identifier: MIT` and a WireGuard LLC copyright line); the ring
contract it encodes is: a packet is at most 65535 bytes
(`session_windows.go:20`), the driver buffer is valid only until
`ReleaseReceivePacket`, and send packets must be allocated at the exact length
(the binding's API shape, `WintunAllocateSendPacket(packetSize)`). wintun.dll
is shipped next to the binary and loaded by explicit path (0.14.1 is what
`internal/wintun/README.md` records), not from `PATH`;
`vendor/gotatun/src/tun/tun_async_device.rs:68-101` shows the same concern from
the Rust side.

Why a separate crate rather than another `tun_fd` backend: `TunFdRuntime` exists
to attach a descriptor *someone else* opened (`crates/segue-cli/src/lib.rs:356-369`,
`crates/segue-ffi/src/lib.rs:2611-2620`). On Windows the kernel process opens the
adapter itself, so there is no fd, and the receive side is a shared-memory ring
with a wait event rather than a socket. Keeping the ring code in its own crate
also keeps the arithmetic (packet size bounds, wrap handling, session shutdown)
testable on the Linux runner with a fake ring.

### 1.2 Adapter lifecycle

`segue-kernel run <config.json>` grows a mode: `tun` in the config, present only
on Windows. Sequence, in `tun_windows.rs`:

1. `WintunCreateAdapter("Segue", "Segue", <fixed GUID>)`; if it exists, open it
   (`sing-tun` `tun_windows.go:55-70` does create-then-open on `ERROR_ALREADY_EXISTS`).
   The fixed GUID gives the interface a stable NLA identity; a random GUID
   creates a new "network" on every launch and re-prompts the user about network
   discovery.
2. `WintunStartSession(0x800000)` (8 MiB ring, `sing-tun` `tun_windows.go:70`;
   the allowed range is 128 KiB–64 MiB, `internal/wintun/session_windows.go:18-21`).
3. Assign addresses: `172.19.0.1/32` and `fd00:5e9e::1/128` on the adapter —
   the same values `NetstackConfig::default` uses (`crates/segue-kernel/src/tun.rs:472-476`),
   and outside the fake-IP range `198.18.0.0/15` as `v4_addr` requires
   (`tun.rs:432-438`).
4. Set the interface options `sing-tun` sets and Windows needs for a route to
   win: `NLMTU = 1500`, `DadTransmits = 0`, `RouterDiscoveryDisabled`,
   `DisableDefaultRoutes = false`, `UseAutomaticMetric = false`, `Metric = 0`
   (`tun_windows.go:133-178`), and `DisableDNSRegistration()`.
5. Install routes (§1.4).
6. Publish the adapter's LUID and interface alias on the control API, so the
   helper can render the tunnel permit without guessing (`§2.3`).

Teardown on `SIGTERM`/service stop: delete the routes, `EndSession`,
`CloseAdapter`. A crashed kernel leaves no adapter behind — the adapter
disappears when its last handle closes, and the driver stays installed — so
"kernel dead" is observable as "LUID gone" rather than as a stale permit, which
is the property `§2.3` depends on.

The kernel is a normal child process of LocalSystem, not a driver, exactly as on
macOS (`macos.md` §1). It owns the adapter, routes and DNS ordering; the helper
owns WFP and the arm latch.

### 1.3 Ring I/O and the kernel stack

The receive path: one task awaits `WaitForSingleObjectEx` on
`WintunGetReadWaitEvent` (registered with the tokio runtime via
`windows-sys`'s handle API, or a dedicated blocking thread), and for each
`WintunReceivePacket` copies into a `Bytes` and feeds `Netstack::input` through
the same `PacketIo`-shaped adapter `TunKernel::run` takes. The copy is
mandatory: the driver's buffer is released at
`ReleaseReceivePacket` (`internal/wintun/session_windows.go:73-75`), so a zero-copy
handoff into the netstack would need a reference-counted release callback. The
copy costs the same one `read(2)` copy the Unix paths make.

The send path mirrors `tun_fd`'s writer (`crates/segue-engine/src/tun_fd.rs:961-1035`):
`poll_outbound_batch_into(max_packets, &mut batch)` (`segue-tun` `lib.rs:440-444`),
then per packet `AllocateSendPacket(len)` → copy → `SendPacket`. An allocation
failure (`ERROR_NO_MORE_ITEMS`/`ERROR_BUFFER_OVERFLOW`, i.e. the ring is full)
is `Retry` with the same backoff classification the fd writer uses
(`tun_fd.rs:777-808`); it is never fatal unless the session was closed.
`AllocateSendPacket` must not be retried in a busy loop: the driver signals the
next slot only after the consumer drains, so the writer waits on the batch queue.

Nothing above `PacketIo` changes. `TunKernel::run(io)` (`crates/segue-kernel/src/tun.rs:2333-2334`)
is the consumer, so the rule table, fake-IP DNS hijack (`tun.rs:2086`, `:2122`),
QUIC refusal, sniffing and the kill-switch verdicts are the same code on both
desktop platforms. `TunEndpoint` is *not* used on Windows: it is the same-process
queue that `TunFdRuntime` and the FFI hosts hand packets through, and there is no
host here.

### 1.4 Routing

**Full default into the tunnel, exit endpoints excluded.** This is the macOS
decision (`macos.md` §1) and it matters more on Windows: a split default would
leave hard-coded DoH and QUIC-to-a-real-IP outside the kernel for the whole time
the user is connected.

- IPv4: `0.0.0.0/1` and `128.0.0.0/1` via the adapter, next hop `172.19.0.1`,
  metric 0. Two half-routes, not `0.0.0.0/0`: the half-routes are the shape
  WireGuard's Windows UI writes when the user asks for a full tunnel
  (`ui/editdialog.go:188-196` builds exactly `0.0.0.0/1` + `128.0.0.0/1` and
  `::/1` + `8000::/1`), and they win against a coexisting `/0` on another
  interface by longest-prefix match. `sing-tun` instead writes a single `/0` on
  non-Darwin (`tun_rules.go:124-136`); we do not, because a `/0` competes with
  the physical adapter's own `/0` on metric rather than on prefix length.
- IPv6: `::/1` and `8000::/1` via the adapter when the config enables IPv6 (a
  new kernel-config field, `tun.routes_v6`, default on). The netstack already
  has a v6 interface address and default route (`tun.rs:1088-1096`), and AI
  IPv6 literals (`2607:6bc0::/48`) must reach the kernel's AI tier rather than
  leave direct. A v6-less exit just refuses what it cannot carry.
- Exclusion: for every outbound server address and every `exits[].relay`
  (`crates/segue-kernel/src/session/mod.rs:100-113`) whose IP is not in the fake
  range, add a `/32` (or `/128`) on the **physical** interface with the physical
  gateway, before the half-routes. Longest-prefix match then keeps the carrier
  out of its own tunnel. This is `sing-tun`'s `Inet4RouteExcludeAddress`
  (`tun_rules.go:144-153`) reduced to the set we have.
- Fake-IP: `198.18.0.0/15` is inside the tunnel by construction (it is inside
  both half-routes), and the netstack answers it without a route of its own
  because it is the destination of a flow the client initiated.
- The adapter's own DNS: NRPT target `172.19.0.1` (§2.4). For that to bind,
  `crates/segue-kernel/src/config.rs:614-620` ("`dns.listen` must be a loopback
  address") must accept the TUN address on Windows. The listener is mostly a
  formality — `hijack_dns` answers port 53 arriving on the TUN before any socket
  sees it — but the config check is what makes the address real.

**Interface binding of direct dials.** With the default route inside the tunnel,
every direct socket loops. On Linux the answer is `SO_BINDTODEVICE`
(`crates/segue-transport/src/socket_options.rs:411-445`). On Windows the
primitive is `IP_UNICAST_IF`/`IPV6_UNICAST_IF` with the physical interface
index, and it is unreliable when that interface has weak-host-send or forwarding
enabled — `sing-tun` documents this and disables weak host send on candidate
interfaces while its TUN is up (`tun_interface_windows.go:71-107`). The plan:

1. Implement `apply_outbound` for `cfg(windows)` in
   `crates/segue-transport/src/socket_options.rs` (replace the stub at
   `:597-616`): `setsockopt(IPPROTO_IP, IP_UNICAST_IF, ifindex)` for v4 and
   `IPV6_UNICAST_IF` for v6, from `options.interface` resolved to an index.
2. While the tunnel is up, the kernel clears weak host send on the physical
   interface (lift the `setWeakHostSend` call at `tun_interface_windows.go:94-107`)
   and restores it on teardown.
3. Direct outbounds are generated with `bind_interface` set to the physical
   alias, the way Tono does it (`crates/tono-core/src/config.rs:602-615`,
   `direct_outbound` sets `interface-name`) — but the *value* comes from
   `segue-client`'s plan, not from server config.
4. Belt and braces: the AI lock's WFP tunnel permit is matched on the adapter
   LUID (§2.3), so even a direct dial that escaped binding could not carry AI
   traffic off-tunnel.

`SocketProtector` stays `None` on Windows. Its `protect()` call is the
`VpnService.protect` analog (`crates/segue-transport/src/lib.rs:452-460`) and
Windows has no equivalent; the loop is broken by host routes and interface
binding instead. `SocketHandle::from_*` already compiles for Windows
(`lib.rs:430-449`), so nothing else in the transport changes.

## 2. The AI lock on Windows

Everything in this chapter is one WFP provider and **one** sublayer, plus NRPT
and one registry-value guard. It is not a block-all: ordinary traffic is never
matched, so it passes by omission.

### 2.1 Why one sublayer

WFP arbitrates sublayer-by-sublayer, highest weight first, and within a sublayer
by descending filter weight, first terminating match wins
(`wfp_model.rs:9-24`). Two sublayers would therefore mean "one of them decides
everything", which is how a higher block-all silently voids every permit.
Tono's single-sublayer decision (weight 1000, `wfp_model.rs:47-54`) is lifted
unchanged. So are the GUIDs' *shape* — fixed, generated once, never reused —
but the values are new (§6 question 6). Everything carries `SEGUE_WFP_PROVIDER_KEY`, so
enumeration, verification and emergency deletion are provider-scoped and cannot
touch Windows Defender Firewall policy or another VPN's rules
(`apps/windows/SECURITY.md` invariant 6, Tono clone).

### 2.2 The rule set

| Rule | Layer | Weight | Lifetime | Matches |
| --- | --- | --- | --- | --- |
| loopback v4/v6, inbound and outbound | `ALE_AUTH_CONNECT_V4/V6`, `ALE_AUTH_RECV_ACCEPT_V4/V6` | 8 (hard permit) | persistent + boot-time copy | `127.0.0.0/8`, `::1/128`, and ALE loopback (`wfp_model.rs:1100-1189`) |
| tunnel permit | `ALE_AUTH_CONNECT_V4/V6`, `ALE_AUTH_RECV_ACCEPT_V4/V6` | 8 | session only | `IP_LOCAL_INTERFACE == <adapter LUID>` |
| AI CIDR block, one per prefix | `ALE_AUTH_CONNECT_V4/V6` | 1 | persistent + boot-time copy | `RemoteAddress` = the prefix |
| DHCP / NDP permits | as in `wfp_model.rs:280-300` | 7 | persistent + boot-time copy | ports 67/68, 546/547, ICMPv6 133–137 |

Notes on each:

- **Loopback** is the floor. It is a *hard* permit
  (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, `wfp_model.rs:254-258`) so that a later
  filtering provider cannot veto the pipe between kernel and helper. Address and
  ALE form are both kept: `127.0.0.0/8` alone is not equivalent on the real ALE
  layers, which is the comment `wfp_model.rs:164-169` records.
- **The tunnel permit is what makes the lock usable**, and it is the least
  obvious part. The client's `connect()` to an AI address is authorized at
  `ALE_AUTH_CONNECT` *after* route selection, so `IP_LOCAL_INTERFACE` is the
  WinTun adapter for exactly the flows the route put inside Segue. Weight 8 beats
  the weight-1 CIDR block. The kernel reaches the IDC exit by dialling the exit
  IP on the physical NIC, never by dialling an AI address, so it never needs the
  permit (`wfp_model.rs:1094-1099`).
- **The permit must not outlive the adapter.** A `NET_LUID` is
  `{index, iftype}` and the index is reused; an unconditional permit bound to a
  recycled LUID would permit everything on whatever device got it. Tono keeps
  the permit tied to a `(pid, generation)` core instance and lets it disappear
  whenever that instance is not the current one
  (`windows_kill_switch/state.rs:199-225`). Segue keeps the same rule with the
  kernel's own identity: the permit is rendered only while the helper's
  supervised kernel process is alive **and** the LUID it published matches the
  live adapter. The permit is never persistent.
- **The CIDR blocks** come from `crates/segue-kernel/data/ai-lock.txt` plus the
  signed bundle's `ai_cidrs`, parsed by the same list the kernel uses (one
  parser, one list — the macOS rule in `macos.md` §2). Today that is
  `160.79.104.0/23`, `153.61.224.0/22`, `2607:6bc0::/48`. IPv6 is included;
  unlike macOS PF, there is no reason not to.
- **Inbound AI blocks are omitted.** Tono's full-block floor needs
  `ALE_AUTH_RECV_ACCEPT` because a listener on the physical adapter could accept
  a whole flow off-tunnel. With no block-all there is no flow to divert: an
  inbound connection to an AI address is the *server* dialling the machine, not
  AI traffic leaving it. The tunnel and loopback permits are still rendered on
  inbound layers so the two directions agree.

### 2.3 Install, verify, and the arm protocol

Installation is lifted with its bug fixes:

- One `FwpmTransactionBegin0` … `Commit` for provider, sublayer and all filters;
  abort on any error (`wfp/mod.rs:176-200`).
- **Install before remove.** A rule whose conditions changed keeps its tag but
  also has a new key when the namespace version is bumped, so the plan is
  `install` then `remove` inside the one transaction, never a window with
  neither (`wfp/mod.rs:836-858`, `:909-931`).
- **Verify by key, then by exact set.** Presence of every expected key is not
  enough: one stale permit beside the new set keeps an escape path live, so the
  engine enumerates every filter under the provider key and requires set equality
  (`wfp/mod.rs:860-907`, `:706-720`). Only after that does the helper publish `held: true`.
- The same discipline covers the boot-time/persistent split (§2.5): the same
  filter, two objects, two GUIDs, one key each.

Arm and disarm are the two-signal contract in `segue-client.md` §3.3, unchanged:
the app proposes, the helper decides, a generation fences late requests, and only
`user_disconnect` / `sign_out` / `quit` release. A lost arm reply keeps intent; a
lost disarm reply is not a release — the app shows the helper's read-back.

Order on arm: persist intent → install WFP → install NRPT → start the kernel →
wait for `GET /v1/status` to report a carrier → publish `held`. Order on disarm
(the macOS order, `macos.md` §2 and `kill-switch-survey.md` §8): DNS restored and
read back → then WFP withdrawn. A restore that cannot be read back is a failure,
not a success.

### 2.4 DNS guard

Two mechanisms, one visible to the Windows resolver and one not.

**(a) NRPT, per suffix.** Windows resolves through the DNS Client, which honours
Policy Table rules in the registry. A rule names suffixes and, with
`ConfigOptions = DA_NRPT_CONFIG_DNS` (`0x8`), a list of servers
(`dns/engine.rs:1556-1570`). Segue writes one rule per armed suffix, with two
names each — `openai.com` and `.openai.com` — because the bare apex and the
dotted form match different query shapes (`selective_fail_open.rs:97-106`).
Names off the list never see the rule, so ordinary DNS is untouched.

| State | NRPT rule | Server | Effect |
| --- | --- | --- | --- |
| tunnel up | **catch-all** (`"."`, one rule) | `172.19.0.1` (TUN) | every lookup enters the netstack; `hijack_dns` answers (`tun.rs:2086`, `:2122`); AI names get fake-IP or empty NOERROR, the rest go to the kernel's resolver |
| armed, tunnel down, helper up | per-suffix rules | `127.0.0.1` (helper) | helper answers empty NOERROR for A and AAAA, and does not recurse. Everything else uses the restored resolver |
| armed, tunnel down, helper dead | per-suffix rules | `127.0.0.1`, nothing listening | the query fails (RST) instead of leaking. It does not fall through to the physical DNS servers |
| boot, before the service | per-suffix rules (persisted) | `192.0.2.1` sinkhole | fails by timeout. AI names hang rather than resolve; the service rewrites to `127.0.0.1` when it starts |
| intent clear | none | — | normal |

The helper listener binds `127.0.0.1:53` only while the tunnel is down. That is
the one difference from Tono's always-on catch-all to `198.18.0.2` and its
`strict-route`/`dns-hijack` reasoning (`dns/mod.rs:1-18`): while a TUN is up,
loopback DNS is reclassified and unreliable, which is why the tunnel-up row uses
the TUN address. While the tunnel is down there is no reclassification, and the
listener must fail fast — Tono's `192.0.2.1` sinkhole with no process is a
slow timeout and `macos.md` §2 rejects it for the same reason. If port 53 is
already taken on the machine, the helper refuses to install the NRPT hold, still
installs the WFP CIDR blocks, and reports `dns_guard: unavailable` in the status
snapshot — it must not point NRPT at a listener it does not own, because the
other listener would answer with real addresses. Product copy says so (§2.7).

**(b) DoH suppression, snapshot and restore.** The Windows resolver can
silently upgrade a configured server to DoH, which would bypass (a) inside the
OS itself. Tono captures `EnableAutoDoh` and every adapter's `DohFlags`,
zeroes them, and restores from the durable capture, with a "lost originals"
marker for captures that cannot be rewritten (`dns/engine.rs:1556-1562`,
`:1759-1770`). Segue lifts that whole mechanism, because it is exactly the class
of bug that leaves a machine's DNS settings mutated after an uninstall. The
capture is written before the first write, atomic and fsynced
(`dns/engine.rs:319-336`), and restore flushes the resolver cache
(`dns/engine.rs:1308-1340`) so fake-IP answers and negative entries do not
survive the disconnect.

**What is not covered:** a browser or CLI doing DoH to its own resolver never
asks the DNS Client, so neither NRPT nor the DoH keys see it. That is a stated
limit, not a bug (§2.7).

### 2.5 Boot, crash, and why Windows can do better than macOS

WFP has two lifetimes beyond "as long as the handle": `FWPM_FILTER_FLAG_PERSISTENT`
(filters survive process death and reboot, restored when BFE starts) and
`FWPM_FILTER_FLAG_BOOTTIME` (filters exist *before* BFE initialises). They
cannot be combined on one object, so the pair is written together. Mullvad does
exactly this for its lockdown block-alls (`talpid-winfw/src/persistent.rs:37-92`:
"Both are needed to keep traffic blocked across a reboot"); IVPN does it for its
optional persistent mode (`firewall_windows.go:330-340`).

Segue uses the same facility for a **narrow** layer, which is new: the AI CIDR
blocks, the loopback floor and the DHCP/NDP permits are written persistent *and*
boot-time while intent is armed. The provider and the sublayer must be
persistent too (`FWPM_PROVIDER_FLAG_PERSISTENT`,
`FWPM_SUBLAYER_FLAG_PERSISTENT`, `wfp/mod.rs:210-252`), or a boot-time filter
would reference an object that does not exist yet and BFE would not load it.
Consequences:

- From the moment the driver stack initialises, an AI prefix cannot be reached
  outside the tunnel, even if `SegueService` never starts.
- The tunnel permit is not persistent (it cannot be — the LUID does not exist
  yet), so before the service starts there is no permit, and traffic to an AI
  prefix is simply dropped, which is the intended direction.
- Boot-time filters are visible in the WFP store as their own objects with their
  own keys, so the verify-by-set step covers both copies.

This is also why the macOS "do not re-arm a leftover block across reboot" rule
(Tono's `docs/decisions/035-2026-09-30-boot-does-not-rearm-kill-switch.md`,
cited in `macos.md` §2) reads differently here: a persisted *AI-prefix* block is
not an unrequested lockdown. It is the persisted intent, and it blocks only the
prefixes on `ai-lock.txt` plus the bundle — today three. Segue still never
persists a block-all.

Crash behaviour: WFP objects live in BFE, not in the service, so the layer
survives a service crash, a hung service and a service kill. What does not
survive is the tunnel permit (session-only) and the kernel (a child). So a
service crash degrades to "armed, tunnel down", which is the state the matrix
calls acceptable: AI CIDRs dropped, AI names answered by NRPT→`127.0.0.1` (the
helper is gone but the rule points at a closed port), ordinary traffic direct.
SCM recovery actions (5 s/10 s/30 s, `install_service.rs:2780-2805`) bring the
service back; the helper's own startup step re-renders the tunnel permit.

### 2.6 The watchdog

The kernel can be alive and not forwarding (carrier exhausted, posture
`Reconnecting`). While that is true the default route is still inside the
tunnel, so ordinary traffic stalls. The helper's watchdog **exits the kernel**
once `KernelDialer::WAIT_DEADLINE` (`crates/segue-kernel/src/killswitch.rs:71`,
12 s) has passed without `Connected`, rather than releasing the AI layer. The
tunnel dies with the process, routes go, ordinary traffic is direct, and the AI
layer is still installed — which is the macOS rule (`macos.md` §2, "The awkward
row") and the opposite of Tono's non-strict release
(`windows_kill_switch/policy.rs:40-56`). One deadline, owned by the kernel,
not a second policy in the helper.

### 2.7 State × traffic-class matrix

Rows are the OS, not the kernel. The kernel's own matrix is
`docs/design/ai-lock.md` and applies only while the kernel runs and the flow is
inside the tunnel. "AI name" is a name on the armed suffix list asked of the
Windows resolver; "AI CIDR" is a prefix on the armed list.

| | AI name | AI CIDR | AI literal IP not in a CIDR; QUIC to it; app DoH | Other traffic |
| --- | --- | --- | --- | --- |
| Intent clear | normal | normal | normal | normal |
| Armed, service up, kernel not started | empty NOERROR from the helper | WFP drop (persistent) | **not held** — the leak | direct |
| Armed, service not yet started (boot) | sinkhole timeout | WFP drop (boot-time) | not held | direct |
| Connecting | helper empty until the catch-all NRPT is in place, then fake-IP | drop except on the TUN interface | inside the tunnel once the half-routes are in; before that not held | direct until the half-routes move, then the kernel |
| Connected | kernel fake-IP / empty NOERROR, IDC exit | through the tunnel, IDC exit | inside the tunnel: QUIC refused, SNI sniffed (`ai-lock.md`) | kernel policy |
| Reconnecting, kernel alive | kernel refuses (Strict) | drop off-tunnel | kernel refuses | held by the tunnel until the watchdog exits it |
| Reconnecting, kernel dead | helper empty NOERROR | drop | not held | direct |
| Service crashed / killed, intent armed | NRPT→closed port, fails fast | drop (persistent) | not held | direct |
| Reboot with intent armed | sinkhole until the service rewrites | drop (boot-time) | not held | direct |
| Restore network / user disconnect | normal | normal | normal | normal |

The two rows worth stating in product copy are "kernel dead" (AI names fail
rather than resolve; ordinary traffic works) and "service dead" (same, without
the fast failure). Neither takes the machine offline.

**Honest limits, in the copy:**

- **CDN-fronted vendors.** Setting aside Anthropic's published inbound ranges,
  the names on the list are served by Cloudflare, AWS, Vercel, Google and Azure.
  Blocking those ranges blocks other people's sites; no surveyed product does it,
  and Tono explicitly rejected it (Tono's `docs/decisions/036-2026-09-30-crash-hang-releases-then-ai-layer.md`). For those vendors the
  name guard plus the in-tunnel kernel is the whole lock.
- **App-level DoH/DoT** bypasses NRPT. The Windows DoH keys only stop the
  resolver's own upgrade.
- **A literal IP with no CIDR match** is not blocked. With three prefixes, that
  is most of the list.
- **QUIC to an unlisted IP** is just UDP/443 and is not dropped outside the
  tunnel. Inside, the kernel refuses AI-route UDP (`ai-lock.md`).
- **Cached answers and live connections** keep going until they expire.
  Installing the layer does not flush every state; it does flush the resolver
  cache on arm and on restore (`dns/engine.rs:1308`). WFP does re-authorize
  existing flows when an ALE filter is added or removed — that is why
  enforcement sits at ALE rather than the packet layers
  (`wfp_model.rs:9-24`) — but a flow already inside a permit is not re-decided.
- **WFP does not match a code signature** in the way a user expects; an
  `ALE_APP_ID` is a file path, and a copied binary carries it. Per-app scoping
  is not a security boundary here, and Segue does not offer it.
- **A local administrator** can delete the provider. The threat model is the same
  as Tono's (`apps/windows/SECURITY.md` §"Threat model", Tono clone).

## 3. Process model

```
Segue.exe            Tauri UI, the logged-in user, medium IL
   |   named pipe \\.\pipe\segue-service  (HTTP/1.1 + JSON, versioned)
   v
SegueService.exe     LocalSystem, SCM auto-start, depends on BFE
   |   spawns, supervises, restarts, renders WFP and NRPT
   v
segue-kernel.exe     LocalSystem child; WinTun adapter, routes, netstack, loopback control API
   ^
   |   \\.\pipe\segue-release
SegueRelease.exe     second LocalSystem service; only "restore internet"
```

- **UI: Tauri.** Not WinUI. Reasons, in order: `segue-client.md` §4.2 already
  binds Windows to "Rust → `use segue_client` directly", and a Tauri command
  layer is Rust; the Linux shell later is the same shell; and the team already
  has Tono's Tauri *shape* to copy. The React pages are **not** copied — Tono's
  app is GPL-3.0-only (`apps/windows/app/package.json:4`) — so the shell is
  written fresh against Tono's six-command webview capability model
  (`docs/architecture.md:56-66` and `app/src-tauri/tests/webview_capabilities.rs:16-18`, both in the Tono clone),
  which is a good pattern independent of the licence.
- **`segue-client` lives in the service, not the app.** This corrects
  `segue-client.md` §4.2's Windows row: the app cannot be the protection
  authority (Tono's `apps/windows/SECURITY.md` invariant 2, and `segue-client.md` §3.3
  "the protector decides, the app proposes"). The service links
  `segue-client`, builds the `KernelPlan`, writes it, spawns the kernel; the UI
  renders `GET /v1/status` and sends arm/disarm. The UI still links the
  `segue-client` *types* (status, failure codes, `user_copy`) so the copy is
  shared, not re-typed.
- **IPC: one pipe, HTTP/1.1 + JSON.** Tono's transport is HTTP over a named pipe
  with a per-capability `ProtocolVersion { epoch, revision }`
  (`service/src/lib.rs:131-143`, `core/structure.rs:13-110`); Segue starts at
  `1` like the macOS socket (`macos.md` §3) and degrades rather than refuses.
  Versioned envelopes, one in-flight owner, and the version constant is checked
  by the build (Tono's `HelperProtocolVersion` lesson, `macos.md` §3).
- **Caller verification, three layers, none of them "the pipe is local":**
  1. *Pipe ACL.* The pipe is created with an SDDL DACL granting only LocalSystem,
     Builtin\Administrators and the installing user's SID, plus
     `PIPE_REJECT_REMOTE_CLIENTS`. Tono parses the SID through
     `ConvertStringSecurityDescriptorToSecurityDescriptorW`
     (`core/auth.rs:1180-1200`; private-object SDDL constants at
     `core/windows_security.rs:37-44`).
  2. *Peer identity.* `GetNamedPipeClientProcessId` → open the process → open its
     token → compare `TokenUser`/`TokenOwner` SID with the allowed-uid file
     written at install. Read the peer's **session id** at the same moment and
     keep it, because a reused PID can name another process later
     (`core/auth.rs:20-33` is Tono's version of this reasoning).
  3. *Image identity.* `QueryFullProcessImageNameW` must equal the installed
     `Segue.exe` path **and** its Authenticode chain must verify against the same
     publisher as the service. Tono binds arm-widening commands to the installed
     app image for the same reason (`core/server/mod.rs:1241-1300`, `prove_installed_app_peer`).
  A fourth, per-session credential (Tono's token hash) is optional: the
  publisher check subsumes it, and one mechanism fewer is one thing fewer to get
  wrong.
- **State files**, under `%ProgramData%\Segue\` with an ACL that only SYSTEM and
  Administrators can write (`windows_security.rs:37-44`), one state file per
  concern: `ai-lock.intent`, `protected-dns.json`, `doh-capture.json`,
  `pf`→`wfp` equivalent is the WFP store itself, `release.sock` equivalent is
  the release pipe. `lost-capture` markers as in §2.4.
- **Release service.** A second service on its own pipe, with the main service and
  the update executor killed inside a job object first, an answer deadline and a
  hard cap (Tono `release_wire.rs:1-10`, `:37-41`). Lifted as-is. "Restore
  network" must work when the main service is wedged in a WFP call; a
  `Fwpm*` RPC to a sick BFE blocks for a long time and a single-service design
  makes the user wait for it.
- **Updater, not in the first beta (§5 stage 9).** The first beta is a signed MSI
  the owner hands out. After that, Tono's protected-update v1 shape is the
  candidate: a signed manifest, a compiled-in minisign key, a `releaseSequence`
  floor, a private staging copy, and adoption only by the service
  (`docs/UPDATE_PROTOCOL_V1.md:1-80` in the Tono clone,
  `service/src/core/update.rs:274-360`). The properties that must hold then are
  the same as macOS's (`macos.md` §4): a failed update keeps the AI layer, the
  release service stays outside the transaction, and a moved binary rekeys its
  `ALE_APP_ID` permits — Tono's `app_path` folded into the key
  (`wfp_model.rs:215-220`).
- **Code signing.** Authenticode on every executable and on the MSI, with an EV
  certificate if one is available (SmartScreen reputation accrues instantly for
  EV). The service verifies its own child's signature before spawning it and
  re-verifies the kernel before every respawn; the pipe verifies the app as in
  §3. Nothing ships unsigned, including the beta.
- **Wintun driver.** `wintun.dll` (0.14.1) and its signed driver are shipped in
  the installer and loaded by explicit path; the driver is installed on first
  adapter creation. Uninstall deletes the adapter and the driver only if no other
  wintun user is present (`WintunDeleteDriver` semantics, `internal/wintun/wintun_windows.go:94-100`).

## 4. Tests

### 4.1 On the existing Linux CI

- **`crates/segue-helper` unit and golden tests.** The WFP rule model compiles
  off-Windows by construction (`wfp_model.rs:1-10`: "free of `windows-sys` ...
  makes the rule tables unit-testable on any host"), which is the reason
  `segue-client.md` §7.1 proposes that placement. Golden tests: the exact
  expected filter set for each arm state; no block-all ever appears; every
  filter carries the provider key; the tunnel permit is absent when the kernel
  identity is stale; the weight ladder; the key-namespace bump rule
  (`wfp_model.rs:72-94`: a changed condition without a namespace bump silently
  adopts a stale filter).
- **The §2.7 matrix as data**, the same way `macos.md` §5 encodes its table.
- **NRPT renderer and guards**: one rule per suffix, apex and dotted names, the
  catch-all only in the tunnel-up state, `nrpt_name_is_safe` refusals
  (`selective_fail_open.rs:80-106`), and the port-53-occupied path producing
  `dns_guard: unavailable` rather than a rule pointing at a foreign listener.
- **Snapshot/restore**: capture-before-write, atomic write, lost-original
  marker, restore read-back, and "restore is attempted before WFP is withdrawn"
  as an ordering assertion.
- **Arm/disarm contract**: generation fence, refuse-without-explicit-intent,
  lost-reply semantics — the same vector set as macOS's.
- **Drift test**: the suffix list the helper embeds equals
  `crates/segue-kernel/data/ai-lock.txt` before the signed bundle is applied.
  A drift fails the build.
- **Type-check the Windows code on Linux**: `cargo check -p segue-wintun
  -p segue-helper -p segue-kernel --target x86_64-pc-windows-msvc` after
  `rustup target add`. `check` does not link, so no MSVC toolchain is needed and
  the `cfg(windows)` halves get compiled for the first time. This is the single
  highest-value addition to the `rust` job in `.github/workflows/ci.yml`
  (`.github/workflows/ci.yml:269-300`) and costs a few minutes.
- **The wintun ring arithmetic** against a fake ring (bounds, wrap, short
  packet, full-ring allocation failure).

### 4.2 A Windows runner

Nothing above needs Windows. Everything below does, and it needs
**Administrator** and a real WFP: filters, NRPT, adapters and `segue-kernel`'s
WinTun mode cannot be faked honestly.

Proposal: one self-hosted runner `segue-windows` (Windows 11, the owner's
machine or a small VM host), plus a **VM inside it** (Hyper-V, snapshot-restored
per run) that a nightly job drives:

1. The runner only builds and signs (`cargo check --target`, MSI, Authenticode).
2. The nightly job restores the snapshot, installs the MSI in the VM, and runs
   packet fixtures — no live vendor networks — exactly the macOS VM matrix shape
   (`macos.md` §5):

| Case | Pass |
| --- | --- |
| Armed, kernel not started | `Resolve-DnsName` of an armed name is empty; `example.com` resolves; TCP to a fixture CIDR is dropped; TCP elsewhere works |
| Connected | armed name is fake-IP; a connection's egress is the fixture exit; an unlisted connection is direct |
| Kill the kernel only | adapter gone; ordinary traffic resolves and connects; armed name still empty; fixture CIDR still dropped; tunnel permit gone from the WFP store |
| Kill the helper/service | same, without the fast failure; SCM restarts it within 30 s |
| Reboot with intent armed | before the service starts, fixture CIDR is already dropped (boot-time filter); after it starts, sinkhole replaced by the listener; no block-all |
| Reboot with intent clear | no provider filters, no NRPT rules |
| Restore network with the service paused in a WFP call | the release service clears filters, NRPT and DNS capture |
| App DoH and QUIC to an unlisted IP | **expected leak**, asserted so nobody "fixes" the test by claiming the lock |

3. Manual, once, before a beta is handed out: UAC approval, Authenticode
   reputation, sleep/resume, Wi-Fi to Ethernet change, and a machine with a
   third-party VPN installed (provider coexistence).

Linux servers cannot host this: WFP and NRPT are Windows-only. GitHub-hosted
`windows-*` runners do run as Administrator, so a one-shot filter test would
work there, but three of the rows need a **reboot** and a snapshot rollback
("reboot with intent armed", "reboot with intent clear", and the leftover-state
check after an uninstall), which a hosted runner cannot give. The self-hosted
runner plus a snapshot-restored VM is the honest answer; a cloud Windows VM is
the fallback if that machine becomes a bottleneck.

## 5. Stages

Sizes are one person. Each stage is one PR-sized branch and testable without
the next.

| # | What | Done when | Size |
| --- | --- | --- | --- |
| 0 | `crates/segue-wintun`: FFI, session, rings, fake-ring tests. | `cargo test -p segue-wintun` green on Linux; `cargo check --target x86_64-pc-windows-msvc` green. | 1 week |
| 1 | Windows tun mode in `segue-kernel`: adapter, addresses, half-routes + exclusions, `PacketIo`, LUID on the control API, `dns.listen` allowed on the TUN address, exit teardown. | On the VM, a dev machine's traffic goes through the fixture exit while the process lives, and is direct when it dies. Route arithmetic unit-tested. | 2–3 weeks |
| 2 | Windows outbound interface binding: `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, weak-host-send clear/restore, `bind_interface` from the plan. | A direct dial does not loop into the tunnel; a socket bound to a missing interface fails the dial, as the Linux path does. | 1 week |
| 3 | `apps/windows/service` skeleton + pipe + caller verification + kernel supervision + SCM install + release service. No WFP. | The UI connects, arm is refused, status is served, killing the kernel respawns it; a non-Segue client is refused at the pipe. | 1–2 weeks |
| 4 | `crates/segue-helper` WFP: model lift, engine lift, transactional install, verify-by-key-and-set, arm/disarm with generations, the §2.2 rule set. | §4.1 golden tests green; VM rows "armed", "kill kernel", "restore" pass. | 2 weeks |
| 5 | AI prefix persistence: boot-time + persistent copies, key namespace, the reboot rows, the watchdog that exits a stuck kernel. | The two reboot rows of `§4.2` pass on the VM. | 1 week |
| 6 | DNS guard: NRPT per-suffix and catch-all, helper listener, DoH capture/restore, resolver flush, port-53-occupied path. | The DNS column of §2.7 is green on the VM; restore is read back before WFP is withdrawn. | 1–2 weeks |
| 7 | Tauri shell: connect, status from the service's read-back, restore, config folder, diagnostics zip (redacted, no upload). | The owner can connect, kill the UI, and watch ordinary traffic work while an armed name does not resolve. | 1–2 weeks |
| 8 | Installer, Authenticode, MSI, first-run service install with UAC, uninstall that removes only Segue objects. | A clean VM installs from the MSI, prompts once, passes stage 7's check, and uninstall leaves no provider, no NRPT rule, no captured DNS. | 1 week |
| 9 | Nightly VM matrix (§4.2), then the protected update transaction. Update only after a beta is in someone's hands. | Nightly red on a real leak, green on the expected app-DoH leak. | 1 week, then 2+ |

Out of scope on purpose: per-app filters, Tono's full-block modes, Linux, mihomo
or sing-box, account sign-in in the shell, Windows Store packaging, ARM64.

## 6. Open questions

Defaults are what §5 assumes.

1. **Where does the app live?** Default: `apps/windows` in this repo, matching
   `macos.md`'s `apps/macos` and `segue-client.md` open question 1's default. A
   separate `segue-windows` repo costs a second CI and an artifact hop before
   there is anything to build.
2. **Re-arm across reboot?** Default: yes, and only the narrow AI layer —
   persisted intent is the user asking. `macos.md` §2's reading, applied to a
   primitive that can actually do it. Never a persisted block-all.
3. **Full tunnel while healthy?** Default: yes, with endpoint exclusions (§1.4),
   for the same reason as macOS: a split default makes the in-kernel lock blind
   to DoH and QUIC toward real addresses.
4. **UI toolkit?** Default: Tauri, fresh shell, no GPL code. WinUI only if a
   native-look requirement appears; the Rust side would not change.
5. **Which `wintun.dll`?** Default: 0.14.1 from the official signed release,
   shipped in the installer, loaded by explicit path. Not embedded in the exe
   (defeats signature checking and the driver's own install path).
6. **New WFP GUIDs.** Default: new provider, sublayer and namespace values,
   generated once, recorded in `docs/decisions/`, and never reused from Tono's
   (`wfp_model.rs:47-54`) — two products' filters must not be able to collide or
   delete each other.
7. **Do we need `segue-client` in the app at all?** Default: types only, never
   authority. See §3.
8. **Bundle/identity.** Default: `com.raydocs.segue` and one Authenticode
   publisher identity used by the service-check and installer. This is a
   purchasing decision, not an engineering one.
9. **IPv6 exit traffic.** Default: routes in, kernel decides; no NAT66, no
   v6 fake-IP. If the exit has no v6 carrier, AI v6 literals are refused rather
   than leaked, which is the product's stated direction.
