# Embedding the Segue kernel/session layer in the mobile FFI

Status: design, not implemented. Owner: FFI/platform.
Related: [`docs/ffi.md`](../ffi.md), [`docs/architecture.md`](../architecture.md),
[`docs/design/`](./), `crates/segue-ffi/include/segue_ffi.h`.

## 1. Problem

`crates/segue-ffi` today depends only on `segue-engine`, `segue-config`,
`segue-routing`, `segue-tun` and `segue-transport`. Everything the product calls
"Segue" — the L5 session protocol (`segue-session`), the rule table + smart DNS +
fake-IP + kill-switch kernel (`segue-kernel`) and the signed policy envelope
(`segue-policy`) — is reachable only through the `segue-kernel` prototype binary
(`crates/segue-kernel/src/main.rs`). The iOS XCFramework and the Android AAR are
built from `segue-ffi` (`scripts/build-apple-xcframework.sh`,
`scripts/build-android-libs.sh`), so both ship without them.

The mobile apps therefore run the engine directly: one Xray JSON config, one TUN
inbound, outbound routing inside `segue-engine`. They cannot express the kernel's
contract:

* a rule table in front of the outer engine, with `proxy` / `direct` / `reject`
  decisions and fake-IP destinations dialled by name;
* a loopback smart DNS that hands fake-IP addresses to proxied names and keeps
  domestic answers real;
* a kill switch whose invariant is that a proxied flow can never become direct;
* a signed policy bundle as the only source of rules (`policy.rs`), with
  fail-closed behaviour when no bundle is valid.

This document is the implementation plan for exposing that layer over the C ABI
and through the Swift and Kotlin wrappers, without changing what the engine does
today when the kernel is not in use.

## 2. Shape of the change

### 2.1 One handle, two modes

The kernel is a **mode of the existing `XrayCoreHandle`**, not a second handle
type.

* `xray_core_new` still allocates the handle and its Tokio runtime
  (`xray_core_new_inner`, `crates/segue-ffi/src/lib.rs:628`).
* A handle accepts exactly one successful configuration load. Today that is
  `xray_core_load_config_json` (engine mode). This design adds
  `xray_kernel_load_config_json` (kernel mode). Calling either after a
  successful load of the other returns `XRAY_STATUS_RUNTIME_ERROR`, exactly as
  reloading the engine config does now.
* `xray_core_start`, `xray_core_stop`, `xray_core_free`,
  `xray_core_set_tun_fd`, `xray_core_set_tun_mtu`,
  `xray_core_set_socket_protect_callback`, `xray_core_set_file_logging` and the
  packet entry points keep their signatures and meaning.
* Engine-only calls (`xray_core_replace_routing_policy_json`,
  `xray_core_set_startup_probe`, `xray_core_probe_outbound_url`,
  `xray_core_rebind_*`, snapshot calls, `xray_core_set_hyster*_stream_limits`,
  …) return `XRAY_STATUS_CORE_NOT_LOADED` on a kernel-mode handle: there is no
  engine `Core` in that mode (see 2.2), and "not loaded" is already the
  contract for "this surface does not apply".

Rationale for a second config entry point rather than a boolean:

* the kernel config (`KernelConfig`, `crates/segue-kernel/src/config.rs:278`) is
  a different document with different invariants (`listen` loopback-only, rules
  only from a signed bundle in product mode). Parsing it through
  `segue-config::parse_xray_json` would silently accept things the kernel
  refuses;
* a distinct name keeps the ABI self-describing and makes the capability gate
  obvious to the wrappers;
* it makes the "off" build provably untouched (section 6).

### 2.2 In kernel mode there is no engine `Core`

This is the most important structural decision.

`KernelConfig::outbounds` is a map of *Xray-style outbound objects*, and
`EngineDialer::new` (`crates/segue-kernel/src/dial.rs:88`) already parses each
one with `segue_config::parse_xray_json` and builds its own
`OutboundRouter`/`OutboundFactory`. The kernel never needs an engine `Core`: it
needs the outbound graph, not the inbound/lifecycle machinery. That matters
because `Core::start` refuses to start with no inbound
(`CoreError::NoSupportedInbound`, `crates/segue-engine/src/lib.rs:1393`), and a
kernel-only handle would otherwise need a dummy inbound or a new engine mode.

So, in kernel mode the FFI constructs, from the kernel JSON:

```
Arc<EngineDialer>  ──►  KernelDialer (segue-kernel/src/session/mod.rs:284)
                            │  posture, exits, session routes, buffer pool
                            ▼
                       Kernel { policy, dialer, fake_ip, sniff, udp, hidden }
                            │
                            ▼
        TunStack::for_kernel(kernel, dns)  ──►  TunStack::run(Arc<dyn PacketIo>)
```

and `handle.core` stays `None`. `xray_core_start` on a kernel handle starts the
kernel runtime instead of a `Core`.

`EngineDialer` must stop creating its own transport:

* **today** `EngineDialer::new` calls `TransportDialer::system()`
  (`crates/segue-kernel/src/dial.rs:106`). That dialer has **no socket
  protector**. On Android, every outbound the kernel opened would be captured by
  `VpnService` and loop back into the tunnel; on Apple the NE would route it the
  same way. This is a hard bug for the embedded case, not a nicety.
* **required** add `EngineDialer::with_transport_dialer(specs, Arc<TransportDialer>)`
  (and keep `new` delegating to it with `TransportDialer::system()`), then build
  the FFI's kernel dialer from
  `TransportDialer::system_with_socket_protector(handle.socket_protector.clone())`
  — the same call `xray_core_load_config_json_inner`
  (`crates/segue-ffi/src/lib.rs:984`) makes for engine mode. The kernel's carrier
  sockets and its direct/domestic dials then share one protected transport.
* `EngineDialer::new` is `segue-kernel`'s only engine coupling
  ("Everything above this module sees `Dialer`"), so this is a contained change.

The kernel's own smart-DNS upstream sockets are a second, separate gap:
`exchange` / `exchange_tcp` (`crates/segue-kernel/src/dns.rs:438`, `:458`) bind
plain `UdpSocket`/`TcpStream` and the module doc says binding upstream sockets to
a protected interface "is the shell's job under TUN". A shell that is a C ABI
cannot do that. Either the kernel takes an `Option<Arc<dyn SocketProtector>>` and
protects those sockets, or domestic DNS must be reached through the same
protected `TransportDialer`. Pick one in stage 3 (open question Q3).

### 2.3 The kernel owns its own `TunEndpoint`

`TunStack::run` consumes a `PacketIo`
(`crates/segue-kernel/src/tun.rs:1907`), and `segue_tun::TunEndpoint`
implements it (`crates/segue-kernel/src/tun.rs:1912`). In kernel mode the FFI
allocates a `TunEndpoint` with
`TunEndpoint::new_with_queue_depths(TunConfig { mtu, queue_depth }, in, out)` —
the same constructor the engine uses (`crates/segue-engine/src/lib.rs:902`) —
and hands it to `TunStack::run`. The engine's `TunEndpoint` is never created in
this mode.

That gives, with no new packet plumbing at all:

* `xray_tun_push_packet` → kernel endpoint's `push_inbound`;
* `xray_tun_poll_packet` / `xray_tun_poll_packets` → kernel endpoint's
  `try_poll_outbound` / `poll_outbound_batch_into`;
* `xray_core_set_tun_fd` → the existing `TunFdRuntime::start(config, tun)`
  (`crates/segue-engine/src/tun_fd.rs:88`) with the kernel's endpoint — the same
  fd bridge, the same duplicate-fd ownership rules, the same Darwin utun
  framing;
* `xray_tun_stats` and the diagnostic event polls → the kernel endpoint's
  counters.

The dispatch is one `match` on `handle.kernel`. When `handle.kernel` is `None`
every one of those functions runs its current body unchanged.

## 3. The C surface

### 3.1 Naming, version, capability bits

New symbols use the prefix **`xray_kernel_`**, and packet/fd functions keep
their existing `xray_tun_*` / `xray_core_*` names.

Justification for the new prefix: `xray_core_*` is documented (`docs/ffi.md`) as
the lifecycle of an engine config, and `xray_tun_*` as the packet path. The new
calls configure a different subsystem — session exits, kill-switch events and
signed-policy state have no engine analogue and would read as lifecycle calls if
named `xray_core_set_*`. Keeping the packet functions unnamed is deliberate:
the packet path genuinely is the same function.

ABI: `XRAY_FFI_ABI_MAJOR` stays `1`; `XRAY_FFI_ABI_MINOR` goes `17 → 18`
(`crates/segue-ffi/src/lib.rs:33`). All new symbols are additive, all new
capability bits are additive, no existing struct grows except by the append-only
`struct_size` rule already used by `XrayTunStats`.

Capability bits (first free is `1 << 31`):

| Bit | Name | Claims |
| --- | --- | --- |
| 31 | `XRAY_FFI_CAPABILITY_KERNEL` | kernel mode exists: `xray_kernel_load_config_json`, start/stop, packet dispatch, status |
| 32 | `XRAY_FFI_CAPABILITY_KERNEL_KILLSWITCH` | user enable/disable, exit selection, posture events |
| 33 | `XRAY_FFI_CAPABILITY_KERNEL_POLICY` | signed bundle install, policy status |
| 34 | `XRAY_FFI_CAPABILITY_KERNEL_DNS` | smart DNS / fake-IP controls |
| 35 | `XRAY_FFI_CAPABILITY_KERNEL_STATS` | `xray_kernel_stats` |
| 36 | `XRAY_FFI_CAPABILITY_KERNEL_TUN_FD` | fd backend valid in kernel mode (see 3.4) |

`xray_ffi_capabilities()` returns them only when the crate was built with the
`proprietary-kernel` feature (section 5.1). A build without the feature must not
advertise bits whose symbols are absent.

### 3.2 New declarations (shape, not final text)

```c
/* ABI 1.18, KERNEL. Alternative to xray_core_load_config_json within one
 * handle: the document is the kernel config (crates/segue-kernel/src/config.rs),
 * not Xray JSON. Exactly one of the two may succeed per handle. Relative paths
 * in the document resolve against the directory given to
 * xray_kernel_set_state_dir. Lifecycle call: serialize with all other
 * configuration/lifecycle calls. */
XrayStatus xray_kernel_load_config_json(
    XrayCoreHandle *handle, const char *json, XrayError **error);

/* ABI 1.18. The app-group / no-backup directory the kernel may use for the
 * fake-IP state file, the installed policy bundle and ticket files. Set before
 * the kernel config load. Rejected (INVALID_ARGUMENT) if the path is not
 * absolute, not a directory, or group/other-writable (fakeip::open refuses such
 * states anyway; this reports it before the load). */
XrayStatus xray_kernel_set_state_dir(
    XrayCoreHandle *handle, const char *dir, XrayError **error);

/* ABI 1.18. Startup log lines from the policy store (what was restored,
 * rejected, expired) — same size-query protocol as xray_core_config_warnings. */
XrayStatus xray_kernel_config_warnings(
    XrayCoreHandle *handle, char *buffer, size_t buffer_len,
    size_t *written, XrayError **error);

/* ABI 1.18, KERNEL_KILLSWITCH. Maps to KernelDialer::connect / disconnect
 * (segue-kernel/src/session/mod.rs:500, :523). Shared call: concurrent with
 * packet/stat/event calls, not with lifecycle. */
XrayStatus xray_kernel_set_user_enabled(
    XrayCoreHandle *handle, int32_t enabled, XrayError **error);

/* ABI 1.18, KERNEL_KILLSWITCH. "auto" or a configured exit name
 * (KernelDialer::set_exit). INVALID_ARGUMENT for an unknown name. Shared call. */
XrayStatus xray_kernel_set_exit(
    XrayCoreHandle *handle, const char *name, XrayError **error);

/* ABI 1.18, KERNEL_KILLSWITCH. Establish a carrier now so the posture reflects
 * reality before the UI polls (KernelDialer::probe). Blocks for bounded time,
 * like the carrier timeout (10 s), and returns RUNTIME_ERROR when no exit
 * answered. Shared call; never from the socket-protect callback. */
XrayStatus xray_kernel_probe(XrayCoreHandle *handle, XrayError **error);

/* ABI 1.18, KERNEL_KILLSWITCH. One event, NO_PACKET when the queue is empty —
 * the convention of every existing TUN diagnostic poll. detail_buffer receives
 * a NUL-terminated label (exit name, policy reason), truncated if needed. */
XrayStatus xray_kernel_poll_event(
    XrayCoreHandle *handle, XrayKernelEvent *event,
    char *detail_buffer, size_t detail_buffer_len, size_t *detail_written,
    XrayError **error);

/* ABI 1.18, KERNEL_POLICY. Verify against the configured public keys, install,
 * persist to the state dir, and report the new version. Mirrors
 * PolicyStore::install (segue-kernel/src/policy.rs:469). Shared call: safe with
 * packet/stat/event calls; a bundle installed mid-flow applies to flows that
 * start after it. Rejects with CONFIG_ERROR for bad signature, rollback
 * (version <= high_water), expiry or an oversized envelope (> 8 MiB,
 * MAX_BUNDLE_BYTES). Input contains no credentials but is borrowed only for the
 * call. */
XrayStatus xray_kernel_install_policy_bundle(
    XrayCoreHandle *handle, const uint8_t *bytes, size_t len,
    uint64_t *installed_version, XrayError **error);

/* ABI 1.18. schemaVersion 1 JSON: posture, user enabled, exit choice, current
 * exit, exits, revoked code, control-refused list, policy status. Same
 * size-query protocol as the other snapshot calls. */
XrayStatus xray_kernel_status_snapshot_json(
    XrayCoreHandle *handle, char *buffer, size_t buffer_len,
    size_t *written, XrayError **error);

/* ABI 1.18, KERNEL_STATS. struct_size prefix rule exactly as XrayTunStats. */
XrayStatus xray_kernel_stats(
    XrayCoreHandle *handle, XrayKernelStats *stats, XrayError **error);
```

`XrayKernelEvent`:

```c
typedef enum XrayKernelEventKind {
  XRAY_KERNEL_EVENT_POSTURE_CHANGED = 0, /* detail: posture name */
  XRAY_KERNEL_EVENT_EXIT_CHANGED    = 1, /* detail: exit name, or "auto" */
  XRAY_KERNEL_EVENT_POLICY_CHANGED  = 2, /* detail: version, or reason */
  XRAY_KERNEL_EVENT_REVOKED         = 3, /* detail: exit; value = code */
  XRAY_KERNEL_EVENT_CONTROL_REFUSED = 4  /* detail: exit; value = code */
} XrayKernelEventKind;

typedef struct XrayKernelEvent {
  size_t struct_size;   /* in: allocation size; out: preserved */
  XrayKernelEventKind kind;
  uint64_t value;       /* posture enum value, policy version, or code */
  uint64_t timestamp_ms;/* host-independent monotonic ms, for ordering only */
} XrayKernelEvent;
```

Posture values in `value` are a fixed small set (`connecting = 0`,
`connected = 1`, `reconnecting = 2`, `error = 3`, `disconnected = 4`) that mirrors
`killswitch::Posture`; the numeric mapping is part of the ABI and must be
asserted in a Rust test next to the enum.

`XrayKernelStats` is append-only with `struct_size`; its first version carries
the kernel's own counters (`tcp_accepted`, `tcp_refused_policy`,
`udp_refused_policy`, `udp_refused_quic`, `fakeip_entries`, `fakeip_refusals`,
`dns_cache_entries`, `dns_upstream_queries`, `session_opens`, `session_resumes`,
`session_carrier_failures`, `policy_installs`, `policy_refusals`) —
`NetstackStats` (`crates/segue-kernel/src/tun.rs:495`) plus the session/dns
counters that have no engine equivalent. The engine's rich TCP timing counters
do not exist in the kernel stack; `xray_tun_stats` in kernel mode therefore
reports the kernel endpoint's packet counters in the fields that map
(`inbound_packets`, `outbound_packets`, dropped, queue depths) and zeros
elsewhere, which is what the observability code already tolerates.

### 3.3 Error codes

**No new `XrayStatus` values.** Every outcome maps onto the existing set, which
keeps the Swift `XrayCoreError` and Kotlin mapping tables source-compatible:

| Situation | Status |
| --- | --- |
| kernel config parse/validate failure | `CONFIG_ERROR` |
| kernel config loaded, no start yet / wrong mode | `CORE_NOT_LOADED` |
| start/stop/probe runtime failure | `RUNTIME_ERROR` |
| packet push failure in kernel mode | `TUN_ERROR` |
| empty event queue | `NO_PACKET` |
| bad bundle signature/expiry/rollback | `CONFIG_ERROR` |
| unknown exit name, non-absolute state dir | `INVALID_ARGUMENT` |
| panic across the boundary | `PANIC` |

Rationale: adding `XRAY_STATUS_KERNEL_ERROR = 10` would be legal (the header
documents enum values as additive) but forces a wrapper release in lockstep and
buys nothing the message string does not already say.

### 3.4 Ownership, threading, lifecycle

Threading follows the existing contract (`docs/ffi.md` §Threading):

* **Serialized lifecycle** (external mutex on the handle): `xray_core_new`,
  `xray_kernel_load_config_json`, `xray_kernel_set_state_dir`,
  `xray_core_set_tun_fd`, `xray_core_set_tun_mtu`, `xray_core_start`,
  `xray_core_stop`, `xray_core_free`.
* **Shared calls** (the runtime gate; may overlap data-path calls):
  `xray_kernel_set_user_enabled`, `xray_kernel_set_exit`,
  `xray_kernel_install_policy_bundle`, `xray_kernel_status_snapshot_json`,
  `xray_kernel_stats`, `xray_kernel_config_warnings`.
* **Data path** (`&XrayCoreHandle`, concurrent with each other):
  `xray_tun_push_packet`, `xray_tun_poll_packet(s)`, `xray_tun_stats`, and
  `xray_kernel_poll_event`.
* **Borrowed-until-return**: every input pointer, as everywhere else in the ABI.
* **Retained until stop/free**: the `user_data` of the socket-protect callback
  and of the TUN admission callback — both already documented; the kernel dialer
  holds the same protector `Arc`, so a kernel-mode handle must keep the same
  lifetime rule.
* **Tickets**: `KernelConfig` reads tickets from `ticket_file` at parse time and
  stores them in `SegueRoute { ticket: Vec<u8> }` with a `Debug` impl that
  redacts them. The FFI must keep that: never put a ticket in an error string,
  never log the kernel JSON, and zeroise the buffer it copies the JSON into
  (`zeroize` is already a `segue-ffi` dependency).
* Event queue: bounded (proposal: 64 events, newest dropped when full — the same
  policy as the engine's diagnostic queues), owned by the handle, drained by the
  host. Posture is also readable synchronously from the status snapshot, so a
  dropped event never hides state.

Restart semantics: `xray_kernel_load_config_json` may run again **after**
`xray_core_stop` on the same handle only if the fake-IP state and policy store
close cleanly; the simplest contract is one load per handle (as engine mode), and
that is what the wrappers should implement. A new config means `xray_core_free`
plus `xray_core_new`.

## 4. Data flow, kill switch and policy

### 4.1 TUN path

Identical to the engine's, chosen per mode:

| Host does | Engine mode (today) | Kernel mode (new) |
| --- | --- | --- |
| packet pump | `xray_tun_push_packet` → `core.tun()` | `xray_tun_push_packet` → kernel `TunEndpoint` |
| fd backend | `xray_core_set_tun_fd` → `TunFdRuntime::start(config, core.tun_handle())` | same call → `TunFdRuntime::start(config, kernel_tun.clone())` |
| outbound poll | `xray_tun_poll_packet(s)` | same functions, kernel endpoint |
| MTU | `xray_core_set_tun_mtu` → engine `TunRuntimeOptions` | same value → kernel `NetstackConfig::mtu` |
| stats | `xray_tun_stats` | same function, kernel counters |

The kernel's `TunStack` is spawned on the handle's existing runtime with
`tokio::spawn(stack.run(tun_endpoint))`; its `JoinHandle` lives in the handle so
`xray_core_stop` can signal shutdown (close the endpoint and abort after a
bounded drain, mirroring `Core::stop`'s "observe the signal, then join").

The fd bridge is unchanged, which preserves the property the header documents:
"Reconfiguring the same numeric fd transfers packet format and close policy
without closing it", and the `Owned`/`Borrowed` rules. In kernel mode the FFI
still owns the `TunFdConfig` and closes an `Owned` fd on `xray_core_free`.

### 4.2 Kill switch in and out

**In — posture is driven from the host, not guessed.** The kernel's posture is
already fully derived from carrier outcomes (`KernelDialer::connector` emits
`Event::ChannelUp` / `mark_failed`) and from the user:

* `xray_kernel_set_user_enabled(handle, 0|1)` → `KernelDialer::disconnect` /
  `connect`. `UserDisconnect` is the *only* transition that releases the tunnel
  (`KillSwitch::hold_tunnel`), so the host must call it when the user turns the
  switch off and never as part of an error path.
* `xray_kernel_set_exit` → `set_exit`, applied to new sessions only.
* `xray_kernel_probe` → establish a carrier so the posture is real before the UI
  reads it.

The kernel's refusal of proxied flows while the path is unhealthy needs no host
input: `KillSwitch::verdict` is structural (`killswitch.rs:109`) and the TUN
router/dialer already honour it (a refused dial becomes a RST or ICMP error,
never a direct retry — `tun.rs` module doc, §5.4).

**Out — events reuse the capability-gated queue pattern.** `xray_kernel_poll_event`
is a diagnostic queue in the same sense as
`xray_tun_poll_tcp_slow_flow_event`: `NO_PACKET` when empty, caller-owned output
struct, NUL-terminated detail string that may be truncated. The Swift/Kotlin
wrappers add typed bounded-drain methods exactly like
`pollTcpSlowFlowEvents(maxEvents:)`, gated on bits 31/32/33; the JNI projection
does not change the C ABI shape.

Where the events come from: `KernelDialer::status()` is the single source of
truth. A small supervisor task on the handle's runtime samples it after every
posture-relevant action (connect/disconnect/set_exit/probe, and on a slow tick
while `Reconnecting`) and enqueues a `POSTURE_CHANGED` when the posture differs
from the last enqueued one, plus `EXIT_CHANGED` on a choice change,
`POLICY_CHANGED` on an install, and `REVOKED` / `CONTROL_REFUSED` from
`Status::revoked` / `Status::control_refused`. Sampling a single mutex-guarded
snapshot is cheap and avoids threading callbacks into `segue-session`.

### 4.3 Signed policy

* Keys and the persisted-bundle path come from the kernel config's `policy`
  section (`public_keys`, `installed`, `bundle`, `ai_route`), resolved against
  `xray_kernel_set_state_dir`.
* A freshly delivered bundle is installed with
  `xray_kernel_install_policy_bundle`; the store enforces the rollback floor
  (`high_water`), expiry and signature, and persists atomically
  (`write_atomic`).
* Fail-closed is preserved: with no valid bundle `Policy::fail_closed` refuses
  every flow, including fake-IP destinations (`refuse_all`, `tun.rs:2047`). The
  host cannot install a "permissive" state by accident.
* `xray_kernel_config_warnings` reports the startup log
  (`PolicyStore::load_startup`) so the host can surface "policy expired" before
  the user sees a dead tunnel.
* In kernel mode `xray_core_replace_routing_policy_json` is refused (3.1): rules
  change only through a signed bundle.

## 5. Build, licensing and memory

### 5.1 Cargo feature, not an unconditional dependency

`segue-kernel`, `segue-session` and `segue-policy` are
`LicenseRef-Segue-Proprietary` (`crates/*/Cargo.toml:7`); `segue-ffi` is
MPL-2.0 (`license.workspace = true`). Linking them unconditionally into the
published static library would change the licence story of every artifact built
from this crate — including macOS/tvOS builds that do not need the kernel.

Proposal: an **off-by-default feature** `proprietary-kernel`:

```toml
[features]
default = []
proprietary-kernel = ["dep:segue-kernel", "dep:segue-session", "dep:segue-policy"]
```

* `segue-ffi`'s default build is byte-for-byte the current crate (same deps, same
  symbols, same size);
* the mobile build scripts pass `--features proprietary-kernel`
  (`scripts/build-apple-xcframework.sh`, `scripts/build-android-libs.sh`), so the
  shipping XCFramework and `.so` include it;
* CI's `cargo clippy --workspace --all-targets --all-features` and
  `cargo test --workspace` build it, so it cannot rot;
* `deny.toml`'s `private = { ignore = true }` already covers the proprietary
  workspace crates, and `publish = false` on all three means nothing is pushed to
  a registry.

The feature also gives the "off" test for free (section 6): a build without it
must export exactly the ABI 1.17 symbol set.

### 5.2 Memory on iOS (Network Extension 50 MB limit)

The kernel's own budget is documented as ~13.1 MiB for
`NetstackConfig::default` (`crates/segue-kernel/src/tun.rs:63`,
`default_memory_budget_is_well_under_20_mib`). In the embedded case the picture
changes, because `TunStack::for_kernel` sets `shared_pool` to the process session
pool (`crates/segue-kernel/src/tun.rs:2217`): the TUN rings and relay chunks are
charged to the same 8 MiB `POOL_BYTES`
(`crates/segue-kernel/src/session/mod.rs:68`), so the pooled part is 8 MiB, not
6 MiB + 8 MiB. Non-pooled terms at defaults: 512 × 4 KiB flow bookkeeping
(2 MiB), packet queues 1.5 MiB, 256 UDP flows × 14.5 KiB (3.5 MiB), 32 DNS
queries in flight (94 KiB) ≈ 7.1 MiB.

| Component | Worst case | Lazy? |
| --- | --- | --- |
| session + TUN shared pool | 8 MiB (`POOL_BYTES`) | allocated on start; **content** grows on demand only |
| TUN non-pooled bookkeeping | ~7.1 MiB at defaults | flow tables grow per flow; queues are preallocated at start |
| fake-IP pool | 16 384 × (2×253+64) ≈ 9.3 MiB of state/journal **on disk**; in-memory slots scale with assigned names only | **must be lazy**: default `fake_ip_max_entries` should drop to 2 048 (≈1.2 MiB worst-case in memory) in the mobile profile |
| smart DNS cache | 4 096 entries × (domain + RR set) — a few hundred KiB | lazy; entries appear on use |
| outbound transport state (TLS/QUIC per carrier) | outside the kernel budget; 1 TLS + 1 QUIC per exit | lazy (`OutboundFactory` compiles per tag on first use) |
| engine `Core` | **zero in kernel mode** | not constructed |

Budget for the NE: pool 8 + bookkeeping 7.1 + fake-IP ~1.2 + DNS cache ~0.4 ≈
**16.7 MiB worst case**, before outbound transport state and Rust/tokio baseline.
That leaves ~30 MB inside the 50 MB limit for TLS/QUIC, Swift, and fragmentation —
the same envelope the engine path occupies today, so the kernel can *replace* the
engine's TUN stack rather than sit beside it.

What must be lazy, concretely:

1. no engine `Core` in kernel mode (2.2) — the single largest saving;
2. `NetstackConfig::buffer_pool` and `max_tcp_flows`/`max_udp_flows` selected
   from the existing TUN runtime profiles (`TunRuntimeOptions::with_profile`),
   with the LOW_MEMORY profile mapping to 256 TCP / 128 UDP flows for the NE;
3. fake-IP pool only when the config has a `dns` section, and its entry cap from
   the mobile profile rather than the 16 384 prototype default;
4. the smart DNS cache only when DNS is configured (already the case);
5. the fd bridge allocates one ~64 KiB read arena per endpoint
   (`TUN_FD_READ_ARENA_MIN`), already bounded by the existing design;
6. the kernel's event queue and status snapshots are small fixed allocations.

`xray_kernel_stats` should expose `fakeip_entries`, `tcp_flows`, `udp_flows` and
the pool's used bytes so the host can log headroom; the pool already reports
`used_bytes` (`crates/segue-kernel/src/tun.rs:188`).

### 5.3 Binary size

The kernel adds `segue-session`, `segue-policy` (ring), and smoltcp's TCP stack
(already compiled for the engine's TUN inbound in every mobile artifact today).
The proprietary feature should be measured in the existing artifact-size check
before it becomes the default path for both platforms.

## 6. Staged PR plan

Each stage is independently testable, lands behind the feature flag, and keeps
the "off" test green: **with `proprietary-kernel` disabled, the built library's
exported symbol set, header, and packet-path behaviour are byte-identical to
`main`.** The mechanism: a test (`mobile_artifacts_tests.rs` pattern) builds both
feature configurations with `--config profile.release.lto="off"`, runs `nm`, and
asserts the off build exports exactly the ABI 1.17 symbol list while the on build
is that list plus the new symbols; a second test diffs the header symbol list the
off build advertises through `xray_ffi_capabilities()` (must equal the pre-change
constant).

**Stage 0 — prerequisites in the kernel crate (no FFI).**
`EngineDialer::with_transport_dialer`; a `Dialer`-friendly constructor for the
kernel dialer that takes an `Arc<TransportDialer>`; kernel DNS upstream
protection decision (Q3) implemented or explicitly deferred. Tests: kernel crate
unit tests with a recording `SocketProtector` asserting carrier and upstream
sockets are protected. Off test: `segue-ffi` untouched.

**Stage 1 — feature and module skeleton.**
`Cargo.toml` feature, `crates/segue-ffi/src/kernel.rs` behind
`#[cfg(feature = "proprietary-kernel")]`, handle fields (`kernel: Option<…>`,
`kernel_config: Option<…>`), ABI minor 18, capability constant. Tests: symbol
scan for both configurations; `xray_ffi_capabilities()` differs between them by
exactly the six bits; C harness compile with the new declarations.

**Stage 2 — config load and lifecycle, no packets.**
`xray_kernel_set_state_dir`, `xray_kernel_load_config_json`,
`xray_kernel_config_warnings`, start/stop wiring of the `TunStack` task (with a
null `PacketIo` that parks), `xray_core_free` teardown. Tests: config validation
errors map to `CONFIG_ERROR`; loading engine then kernel config fails; kernel
then engine fails; start/stop twice; free without stop; ticket never appears in
an error message.

**Stage 3 — packet path and TUN fd.**
Dispatch the five packet/fd functions; `xray_tun_stats` from the kernel endpoint;
MTU plumbing. Tests: synthetic IPv4/IPv6 TCP handshake through
`xray_tun_push_packet`/`poll_packets` against a fake `Dialer`, reusing the
`ChanIo` harness shape from `crates/segue-kernel/tests/tun.rs`; fd path over a
`socketpair` (the existing fd-bridge test pattern) proving an ICMP echo flows
through the kernel stack; `Owned` vs `Borrowed` close semantics; MTU from
`xray_core_set_tun_mtu`.

**Stage 4 — kill switch and events.**
`xray_kernel_set_user_enabled`, `set_exit`, `probe`, `poll_event`,
`status_snapshot_json`. Tests: posture transitions produce exactly one event per
change; `UserDisconnect` is the only release; proxied flow is RST, never direct,
in every posture (an FFI-level version of
`proxied_flow_never_goes_direct_in_any_state`); unknown exit → `INVALID_ARGUMENT`
and no state change.

**Stage 5 — signed policy.**
`xray_kernel_install_policy_bundle`. Tests: a synthetic key pair signs a bundle
in-process (the `ring` dev-dependency pattern from `segue-kernel`) and installs;
rollback, expiry, tampered signature, oversized envelope rejected with the right
status; fail-closed before the first install (a SYN is RST); install while a flow
is live applies to the next flow only.

**Stage 6 — wrappers.**
Swift `XrayCore`: `loadKernelConfig`, `setUserEnabled`, `setExit`,
`pollKernelEvents(maxEvents:)`, `installPolicyBundle`,
`kernelStatusSnapshot()`, capability gates, and the `XrayKernelEventSnapshot`
value types. Kotlin/JNI: the same through `XrayCore.kt` plus
`xray_mobile_jni.cpp` entry points; no C ABI change. Tests: header/`nm` symbol
tests already cover the C side; Swift/Kotlin unit tests cover mapping and
version gates on CI (no device).

**Stage 7 — host integration (separate repos).**
`XrayPacketTunnelProvider` / `XrayVpnService` choose kernel mode from the
profile, pass the fd (or keep the packet pump), and forward `NWPathMonitor` /
`ConnectivityManager` changes as `probe`. Not part of this repository's PR chain.

Ordering note: stages 1–3 are the risky ones (ownership, threading, memory);
4–5 are additive on top; 6–7 are mechanical. Each stage ships with the off test
and keeps `cargo test --workspace` green.

## 7. Test plan (CI, no devices)

Everything below runs on the existing `ci.yml` job on an ordinary runner:

1. **Dual-build symbol test.** `cargo build -p segue-ffi --release` with and
   without `--features proprietary-kernel`, `nm` both staticlibs, assert the off
   build's exported set equals a checked-in ABI 1.17 list and the on build's set
   is that list plus the new symbols. This is the executable form of the "off"
   requirement.
2. **Capability test.** `xray_ffi_capabilities()` on both builds; off equals the
   pre-change constant; on differs by exactly bits 31–36.
3. **Header tests.** New symbols, enum discriminants (`XrayKernelEventKind`),
   struct fields and `struct_size` comments present; C harness compiles with
   `-Wall -Wextra -Werror -std=c11` (existing `ffi_header_compiles_as_c_harness`).
4. **Status mapping test.** A Rust table test asserting every documented
   kernel failure path returns the status in 3.3, so wrappers do not need a
   device to discover it.
5. **Packet-path tests** (stage 3): in-process, fake `Dialer`, synthetic
   packets; IPv4 and IPv6; TCP handshake + one round trip; UDP relay; DNS-hijack
   path answered by a fake resolver; refusals (private dst, QUIC to a bare IP,
   home-role UDP).
6. **fd tests** (stage 3): `socketpair`-backed fd, raw-IP and Darwin-utun
   framing, `Borrowed`/`Owned` close semantics, re-registering the same fd.
7. **Kill-switch matrix** (stage 4): posture × protection × action table as the
   existing unit test, but driven through the FFI and asserting the emitted
   event sequence and the packet outcome (RST/ICMP) rather than the enum.
8. **Policy tests** (stage 5): generated key pair, in-process signing,
   accept/reject matrix, fail-closed packet probe.
9. **Memory budget test.** A test asserting the mobile profile's
   `TunStack::memory_budget().total` plus the fake-IP/DNS terms is under a
   checked-in ceiling, the same way
   `default_memory_budget_is_well_under_20_mib` guards the prototype. If the
   mobile profile changes, the ceiling moves in the same commit.
10. **Wrapper mapping tests.** Swift `swift test --package-path platform/apple`
    (existing job) and the Android JVM tests; no device needed. Real-device
    energy/memory evidence stays in the release-evidence flow
    (`docs/check-mobile-device-evidence.py`).

Explicitly out of CI: anything requiring a real TUN interface, a live exit, a
real VPN entitlement, or a physical network change. Those are stage 7 and the
release evidence.

## 8. Open questions

1. **Where does the kernel's outbound graph come from?** Option A (proposed):
   `EngineDialer` builds it from the kernel JSON's `outbounds`, exactly as the
   prototype does, sharing only the `TransportDialer`. Option B: build it from
   the engine `Core`'s `OutboundFactory` so engine-mode snapshots/observatory see
   the same graph. B removes the duplicate parse but couples kernel mode to a
   started `Core`, reintroducing the `NoSupportedInbound` problem. Decide before
   stage 2.
2. **Second runtime or the handle's runtime?** The prototype uses a
   single-threaded runtime ("the target is a phone VPN extension"), while
   `xray_core_new` builds a multi-thread runtime with 2–6 workers. Running
   `KernelDialer` + `TunStack` on 6 workers costs stack memory per worker inside
   the 50 MB NE limit. Proposal: the handle's runtime, but the memory profile
   should be measured; if it does not fit, kernel mode gets its own
   1–2-worker runtime and `xray_core_free` drains both.
3. **Kernel DNS upstream protection.** `dns::exchange` / `exchange_tcp` cannot
   protect their sockets today and the module says that is the shell's job. The
   C ABI has no way to do it. Options: pass the `SocketProtector` into
   `SmartDns`; route domestic DNS through the protected `TransportDialer`; or
   exclude the DNS upstream addresses from the TUN routes in the host (host
   responsibility, fragile). This is a real leak/loop risk on Android and must be
   settled in stage 0.
4. **Should `xray_kernel_load_config_json` accept the prototype's `listen`
   (SOCKS) section at all?** In an embedded product the SOCKS front end is not
   used; leaving `listen` in the kernel JSON means the FFI would open a loopback
   listener. Proposal: require `listen` to be present (it is non-optional in
   `RawConfig`), bind it only when the host asks with a new
   `xray_kernel_set_socks_listener(handle, enable)`; otherwise parse and ignore.
   Alternative: make `listen` optional in `KernelConfig` behind a constructor the
   FFI uses. The latter is a kernel-crate change, so it belongs in stage 0.
5. **Does the handle need both modes at once?** Some hosts might want the engine
   TUN inbound *and* the kernel (e.g. a private direct path). This design says no
   (one handle, one mode). If the need appears, a second handle is the answer,
   not two stacks on one `TunEndpoint`.
6. **`XrayKernelStats` field set.** The list in 3.1 is a first cut; the host
   logging that was useful on device will decide the final set. It is append-only,
   so starting small is safe.
7. **Where does the event supervisor live?** Sampling `KernelDialer::status()` on
   a timer is simple but costs a wake-up per tick. Emitting from inside
   `segue-session`'s state changes is cheaper and more precise but threads a
   callback (and its lifetime rules) through the session layer. Proposal: start
   with sampling at a slow tick plus immediate sampling after each host call.
8. **iOS fd vs packet pump in kernel mode.** Both work through the same
   `TunEndpoint`; which one the NE uses is stage 7 policy. The `DarwinUtun`
   header handling is already shared, so no ABI difference is expected — but the
   per-packet copy cost of the pump should be measured against the engine path
   before committing.
9. **Policy and clock.** `PolicyStore` reads the wall clock (`unix_now`). A
   device with a wrong clock can mark a valid bundle expired. The engine path has
   the same exposure; it should be documented for the host ("keep the clock
   sane, or pin policy validity to server time") rather than fixed here.
10. **Feature naming and the release gate.** `proprietary-kernel` is explicit,
    but the queen may prefer a neutral name (`kernel-mode`) so the feature does
    not read as a licensing statement in build logs. The licence boundary itself
    still needs a decision from whoever owns the artifact licensing: shipping a
    proprietary crate inside an MPL-2.0 crate's static library is a distribution
    question, not a code question.
11. **`xray_core_set_tun_admission` in kernel mode.** The kernel has its own
    refusal semantics (reserved destinations, home-role UDP, QUIC). The engine's
    host admission callback has no equivalent hook in `TunKernel`. Proposal:
    refuse the call in kernel mode rather than silently ignore it.
