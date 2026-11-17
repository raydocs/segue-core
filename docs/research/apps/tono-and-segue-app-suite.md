# Tono as the template for a Segue app suite

Engineering study, 2026-11-17. Scope: read Tono's macOS, Windows, iOS and Android
clients, its control plane, node provisioning and release machinery; then propose
how a Segue app suite (iOS, Android, macOS, Windows, maybe Linux) should be split
across repositories on top of Segue Core.

Sources (read-only clones; nothing in them was built or run):

| Clone | Revision | Notes |
| --- | --- | --- |
| `/Volumes/dev/ref/apps/tono` | `006984ae211056ea2f921c93d0b6e74f6c7f3a5e` (2026-11-09) | the product repo; ~112 k lines Swift, ~191 k Rust, ~144 k TypeScript |
| `/Volumes/dev/ref/apps/tono-node-provisioning` | `74c6f91e878c3bddfed1197b85ece4a18ca44dfc` | Ruby/Python VPS provisioner, 5 docs, 20 scripts |
| `/Volumes/dev/ref/apps/tono-build` | `44b344b851cad71c52e0288ec47071f73d40e2e9` | one README; the self-hosted runner plan, later retired |

Segue paths are relative to this repository at `59d39b3a` (the branch this study
was written on). Where a Tono claim comes from a sub-agent's reading rather than
my own, the file path is still given; line numbers were spot-checked, not
exhaustively re-verified. Anything labelled **guess** is not established by a file.

Two things up front, because they change the plan:

1. **Tono and Segue are the same product shape.** Both are "sign in, receive a
   per-device exit catalog and a signed routing policy, then connect directly to
   exits you operate"; both put a rule table and a kill switch in front of an
   outer transport. Tono's data plane is sing-box/mihomo; Segue's is
   `segue-engine`, `segue-session`, `segue-kernel` and `segue-relay`. The app
   *shells* — the privileged helpers, the update protocol, the state files, the
   release gates — are Tono's most reusable asset, and they are the part Segue
   Core does not have.
2. **Segue Core has no control plane and no desktop story at all.** The
   `segue-relay` crate states plainly that ticket-key sync, revocation sync,
   line credentials, control-stream proxying and cross-node forwarding are
   "control plane deferred" (`crates/segue-relay/src/lib.rs:22-25`), and the
   ticket/policy tools are `keygen`/`issue-ticket`/`sign-bundle` dev binaries
   standing in for one (`crates/segue-relay/src/main.rs:9`,
   `crates/segue-kernel/src/main.rs:6`). There is no Windows TUN: the fd bridge
   is a stub that returns `Unsupported` off Unix
   (`crates/segue-engine/src/tun_fd.rs:2225-2245`) and no wintun dependency
   exists anywhere in the workspace. Any app suite plan that does not say
   "build a control plane and a Windows data path" is fiction.

---

## 1. What Tono actually is

```
macOS SwiftUI        Windows Tauri + React      iOS app + NE      Android app + VpnService
      \                     |                        |                    /
       \                    |                        |                   /
        root helper      LocalSystem service      app process        :vpn process
        (PF, DNS,        (WFP, DNS, core,         (libbox,           (libbox, AIDL
         core, arm)       update executor)         App Group files)   engine client)
              \                 |                        |                   /
               \                |                        |                  /
                `-------- outer core: sing-box (libbox) / mihomo ----------'
                                        |
                               Cloudflare Worker + D1  (auth, catalog, policy)
```

Deployables are enumerated in `docs/architecture.md:12-30` of the Tono clone. The
Worker is never on the data plane (`README.md:3-5`).

### 1.1 Repository layout

| Path | Role | Size signal |
| --- | --- | --- |
| `apps/macos/` | SwiftUI app + separately compiled root helper | 178 Swift files in `Tono/`, 141 XCTest files in `TonoTests/` |
| `apps/windows/` | Tauri/React app, `TonoService.exe`, four portable Rust crates | 371 Rust files under `apps/windows/` |
| `apps/ios/` | XcodeGen project: app, PacketTunnel, Widgets, `TonoKit` SwiftPM package | 154 `func test…` in `TonoKit/Tests` |
| `apps/android/` | Gradle: `:routing` (pure Kotlin) and `:mobile` (app) | 53 JVM tests discovered |
| `services/control-plane/` | Cloudflare Worker, D1 (94 migrations), admin API | 45 TS modules in `src/` |
| `services/ops-console/` | Vite/React operator UI served from the Worker | shared types import `../control-plane/src/ops/contract.ts` |
| `services/{exit-agent,node-agent,home-agent}/` | per-node Python reporters (roster, heartbeat, residential metering) | one script + tests each |
| `tooling/scripts/` | 91 build/release/provision/ops scripts, including `core-helper/` — the helper's Swift source lives here, not in `apps/macos` | — |
| `docs/decisions/` | 138 dated decision records, each with status `owner`/`provisional`/`reversed` | — |

The single most instructive structural fact: **the privileged helper's source is
not in the app.** macOS's PF/DNS/core/update-executor code lives in
`tooling/scripts/core-helper/` (`KillSwitchManager.swift`, `KillSwitchPF.swift`,
`CoreManager.swift`, `UpdateExecutor.swift`, `SocketServer.swift`, …) and is
built by `tooling/scripts/build-core-helper.sh`. That is what makes "bump the
helper independently of the app" possible, and it is why the helper has its own
CI and its own contract hash (`tooling/scripts/core-helper/CONTRACT.sha256`).

### 1.2 macOS

| Concern | Implementation | Cite |
| --- | --- | --- |
| Privileged install | root LaunchDaemon at `/Library/PrivilegedHelperTools/tono-core-helper`, plist `/Library/LaunchDaemons/com.raydocs.tono.core-helper.plist`, installed by the app's own script, not `SMJobBless` | `apps/macos/Tono/Core/HelperManager.swift:16-19` |
| IPC | Unix socket `/var/run/tono-core/service.sock`, JSON envelopes, per-UID allowlist file, peer checked by audit token + code-signing identity | `HelperManager.swift:13`, `:5-9` |
| Versioning | one hand-maintained `HelperProtocolVersion.current`; **the build fails if helper sources change without the bump** | `Core/HelperProtocolVersion.swift:1-40` |
| Kill switch | PF anchor rendered by the helper; `/etc/pf.conf` hook is migrated, not trusted; labelled rules so pfctl cannot collapse exact permits into the bundle permit | `tooling/scripts/core-helper/KillSwitchManager.swift:12-14`, `:233`; decision `130-2026-10-19` |
| DNS | helper owns the resolver; packets to protected DNS go through the tunnel | `Core/ProtectedDNSServiceIdentity.swift` |
| Core supervision | helper starts the core binary, the app talks to the core's Clash-API over a websocket | `Core/CoreRuntimeManager.swift`, `Core/CoreWebSocket.swift`, `Core/CoreControllerClient.swift` |
| Routing contract | three-tier graph is a generated JSON template compiled into **both** app and helper, with LAN prefixes fixed in Swift | `Core/ThreeTierRoutingContract.swift:4-9`, `:32-` |
| Signed policy | client verifies an Ed25519 signature over a canonical document before using it | `Core/ManagedTrafficPolicySignature.swift` |
| State | `AppState.swift` plus domain extensions (`AppState+Connect`, `+Catalog`, `+Proxy`, …) | `docs/architecture.md:44-52` |
| Update | **no longer Sparkle**: a root-owned transaction (`/update/stage→prepare→execute→reconcile→commit`) run by a private copy of the old helper; the appcast only advertises, signed with the pinned `sign_update` tool | `apps/macos/NATIVE_UPDATE_V1.md:14`, `tooling/scripts/core-helper/UpdateTransaction.swift:67-277`; Sparkle remnants in `Tono/Info.plist` and `Package.resolved` |
| Restore-internet path | a **separate** root daemon `com.raydocs.tono.release` on `/var/run/tono-release.sock`, so a helper stuck in a long update cannot delay the release | `tooling/scripts/core-helper/ReleaseWorker.swift:11-24`, `Core/HelperManager.swift:1754` |

The comments in `HelperProtocolVersion.swift:6-40` are the best single document in
the repo on what goes wrong when a privileged component and its app version
separately: two shipped builds broke in both directions, and the fix was a build
gate rather than discipline.

### 1.3 Windows

| Concern | Implementation | Cite |
| --- | --- | --- |
| UI | React pages under `app/src/pages/tono/`, Tauri commands under `app/src-tauri/src/tono/`; the webview may call only six controller commands | `docs/architecture.md:56-66`, `app/src-tauri/tests/webview_capabilities.rs:10-18` |
| Privileged service | `TonoService.exe` (LocalSystem), hard SCM dependency on BFE, SCM recovery actions 5 s/10 s/30 s | `apps/windows/README.md:20-24`, `service/src/bin/install_service.rs:2537`, `:2780-2805` |
| Installation | a separate elevated `tono-service-install.exe` stages the binary, verifies SHA-256 of the staged copy, then renames; `MoveFileExW` reboot-queue when in use | `app/src-tauri/src/core/service/install.rs:512-576`, `service/src/bin/install_service.rs:75-250` |
| IPC | HTTP/1.1 over a named pipe `\\.\pipe\tono-service`; **three** trust layers: pipe SDDL, peer-PID→token→SID + owner-token file compare, per-session token hash | `service/src/lib.rs:131-143`, `service/src/core/server/mod.rs:105-107`, `service/src/core/auth.rs:362-575` |
| Protocol versioning | `ProtocolVersion { epoch, revision }`, epoch 2 / revision 23, with per-capability minimums so the app degrades instead of refusing | `service/src/core/structure.rs:327-401`, `service/src/lib.rs:144-235` |
| Kill switch | WFP: one provider, **one** sublayer (arbitration is sublayer-first), weighted permits over a persistent block floor; transactional install-before-remove; exact key-set verification | `service/src/core/wfp_model.rs:47-66`, `:1847-1990`, `service/src/core/wfp/mod.rs:838-905` |
| Product logic | `crates/tono-core` — portable catalog, policy, credentials, connect FSM, update contract; `#![forbid(unsafe_code)]`; ships no HTTP stack | `crates/tono-core/src/lib.rs:1-40`, `src/auth.rs:1-9` |
| Core | sing-box (default since 0.0.74) or pinned mihomo; the service owns supervision, a 10 restarts/600 s watchdog, and orphan sweep with PID-identity guard | `docs/decisions/040-…-windows-default-core-sing-box.md`, `service/src/core/manager.rs:243-253`, `service/src/core/reconcile.rs:24-90` |
| Invariants | 7 numbered security invariants, checked on every review | `apps/windows/SECURITY.md:3-28` |
| Restore internet | a **second** LocalSystem service `TonoRelease` on its own pipe, kill-on-close job object, so a wedged main service cannot block the escape hatch | `service/src/release_wire.rs:1-38`, `service/src/core/release/worker.rs` |
| Update | Tauri signed updater for the ordinary path; **protected update v1** (signed manifest, compiled-in minisign key, `releaseSequence` floor, private staging, Service-only adoption) for anything that must install over a protected session | `docs/UPDATE_PROTOCOL_V1.md:1-80`, `service/src/core/update.rs:274-360`, `crates/tono-core/src/update_contract.rs:58` |

The Windows service deliberately reimplements macOS's contract rather than
sharing code, and says so (`apps/windows/README.md:26-28`); what is shared is
`tono-core` — and even that only partially: the Service workspace does not
depend on it, and `#[path]`-includes four individual files
(`service/src/lib.rs:4-27`) so the wire models stay byte-identical without
dragging catalog/async deps into the installer binaries.

Two honest inconsistencies in the tree, worth knowing before treating it as a
template: `tono-client` and `tono-service-client` are declared dependencies with
no call sites (the real IPC client is `service/src/client/mod.rs`, with a
parallel copy in `app/src-tauri/src/core/service/mod.rs`), and
`register_selective_ai_block` — the failure-time selective fail-open hook — has
no production caller, so `plan_failure` currently always resolves to a full
release (`crates/tono-core/src/network_disposition.rs:36`, decision 031). The
release-time AI hold is a different mechanism and *does* run (`disarm.rs:129-156`).
**Copy the design; do not assume the shipped behaviour matches the design doc.**

### 1.4 iOS and Android

| Concern | iOS | Android |
| --- | --- | --- |
| Tunnel | `NEPacketTunnelProvider` in `PacketTunnel/`, libbox pinned `1.15.0-alpha.12` (`apps/ios/supply-chain/sing-box.pin:5-10`) | `TonoVpnService : VpnService()` in its own `:vpn` process (`apps/android/mobile/src/main/kotlin/…/engine/TonoVpnService.kt:57`, manifest `android:process=":vpn"`), same libbox pin |
| Uplink to core | utun **fd only** via `packetFlow.value(forKeyPath: "socket.fileDescriptor")`; no packet pump (`PacketTunnel/TunnelPlatform.swift:31-44`) | `Builder.establish()` fd handed to libbox; `protect(fd)` on every outbound (`engine/BoxPlatform.kt:75-115`) |
| MTU | 4064 — above that the utun path collapses (`TonoKit/Sources/TonoKit/SingBoxConfig.swift:56-58`) | 9000 (`routing/src/main/kotlin/…/SingBoxConfig.kt:221`) |
| Memory guard | `oomKillerEnabled = true` against the ~50 MB jetsam limit (`PacketTunnel/PacketTunnelProvider.swift:204-205`) | none needed; process budget is not the constraint |
| Kill switch | none of its own; relies on `includeAllNetworks` / on-demand (`App/Services/TunnelController.swift:163-190`) | none of its own; reads Android always-on/lockdown and never calls `allowBypass()` (`TonoVpnService.kt:488`) |
| Cross-process state | App Group JSON: `tunnel-inputs.json`, `tunnel-failure.json`, `status.json` with `flock` and atomic writes (`Shared/SharedFiles.swift:10-61`, `Status/StatusStore.swift:7-36`) | `PublicStatus` file with boot count, monotonic clock and per-engine-instance version (`surface/PublicStatus.kt:19-45`) |
| Confirmation rule | only the tunnel's own stamped reply counts as "connected" (`TonoKit/.../TunnelConfirmation.swift:1-9`) | only a TUN established **during this call** counts (`TonoVpnService.kt:467`, `:484`) |
| Widgets / surfaces | widgets and Control Center read `status.json`; commands only go through a `LiveActivityIntent` that iOS runs **in the app process** (`Status/TunnelIntents.swift:5-30`, `Widgets/TunnelCommand.swift:7-11`) | tile/widget/notification read `PublicStatus`; a `:watch` process + alarm catch a dead engine (`surface/EngineWatch.kt:1-24`) |
| Routing module | `TonoKit` builds the graph, admits the catalog, explains routes | `:routing` does the same in Kotlin, plus `package_name` rules iOS cannot have |

Both platforms consume a **generated** routing contract derived from desktop
sources (`apps/ios/tools/sync-desktop-routing.py:1-13`,
`apps/android/scripts/routing/sync-desktop-routing.py`), with a `--check` mode
that fails CI on drift. This is the pattern that keeps four clients on one
routing policy.

### 1.5 Control plane, provisioning and release

| Concern | Implementation | Cite |
| --- | --- | --- |
| API | `/api/v1/auth/{email/start,email/verify,oidc/*,refresh,logout}`, `/api/v1/me`, `/api/v1/exit-catalog`, `/api/v1/traffic-policy`, `/api/v1/devices`, `/api/v1/device-actions[/:id/result]`, plus `/api/v1/ops/*` and `/api/v1/admin/*` | `services/control-plane/src/index.ts:158-470`, `:874-894` |
| Data | D1, 94 migrations, append-only numbering with a checked-in `migrations/README.md` | `services/control-plane/migrations/` |
| Catalog delivery | encrypted column + `content_sha256` verified on every read; server YAML contributes only whitelisted node fields | `src/catalog.ts:370-404`, `src/catalog-yaml.ts:30-40` |
| Policy delivery | `managed_traffic_policy` row: ciphertext, digest, **optional Ed25519 signature** the client verifies against a compiled-in key | `src/traffic-policy.ts:416-460` |
| Auth | JWT with session row joined to user + device on **every** request; entitlement checked inline | `src/auth.ts:1-50` |
| Cron | 5-minute `scheduled`: user enforcement, pending expiry, revocation outbox, retention, ops cron, API-relay probe | `src/scheduled.ts:1-13` |
| Node provisioning | `tono-node-provisioning`: staged transaction (inspect→plan→apply→verify→measure→tune), pinned SHA-256 Xray, secrets generated on the VPS, rollback to deployment ID | `README.md:1-40` |
| Node roster | control plane pushes a client roster to each node; `exit-agent` reconciles Xray and reports monotonic usage | `services/exit-agent/README.md:1-20` |
| Node heartbeat | `node-agent` self-registers every 5 min (`ops_node_agents`, migration 0097) | `services/node-agent/README.md:1-20` |
| CI | one required check `ci-gate` that fans out to path-filtered workflows; merge queue | `.github/workflows/ci-gate.yml:1-60` |
| Release lines | `release/macos` and `release/windows` own their platforms; `main` integrates and deploys the Worker | `docs/RELEASE_LINES.md:1-16` |
| Gates | G1 "connected means usable", G2 "has a next move", G3 "can ship again", G4 "customer version = yours" | `docs/SHIP_PLAN.md` (header + §0) |
| Updates | one shared manifest/receipt wire protocol for both desktops, with `releaseSequence` as the anti-downgrade floor | `docs/UPDATE_PROTOCOL_V1.md:1-80` |

`tono-build` is a single README describing a private self-hosted-runner plan that
was never registered and is now archived; the product repo's README says it is
retired (`README.md:37-40`). It is a **negative** example: the build farm idea was
abandoned in favour of GitHub-hosted runners.

---

## 2. What Segue Core already provides, and what it does not

| Layer | Segue Core today | Cite |
| --- | --- | --- |
| Transport engine | VLESS/REALITY/Vision, Hysteria 2, WireGuard, Trojan, SS2022, VMess, XHTTP, mKCP, MASQUE over a typed client core | `README.md:1-30`, `docs/status.md:20-60` |
| C ABI | 49 exported `xray_*` functions, ABI 1.17, capability bitmap bits 0–30, size-negotiated structs | `crates/segue-ffi/include/segue_ffi.h:220-267`, `crates/segue-ffi/src/lib.rs:32-33` |
| Swift wrapper | `XrayMobileAdapter` (`XrayCore.swift`, 2227 lines) + shared/client/tunnel products; reference app for iOS/tvOS/macOS | `platform/apple/Package.swift:12-16`, `platform/apple/Sources/` |
| Kotlin wrapper | `XrayCore.kt` + JNI + `XrayVpnService` + `XrayTunInterface` + network-change coordinator; **reference, explicitly not a production VPN app** | `platform/android/README.md:1-10`, `platform/android/xraymobile/src/main/` |
| Session layer | resumable L5 sessions with RESUME, control streams, exit health, shared pool | `crates/segue-kernel/src/session/mod.rs:1-40` |
| Routing kernel | rule table, smart DNS with fake-IP, SNI/Host sniffing, kill-switch verdicts | `crates/segue-kernel/src/{rules,dns,sniff,killswitch}.rs` |
| Signed policy | Ed25519 envelope over `"segue-policy-v1\0" ‖ body`, rollback floor, fail-closed | `crates/segue-policy/src/lib.rs:24-31`, `crates/segue-kernel/src/policy.rs:1-35` |
| Node relay | tickets, revocation list, home (AI) line pool, SSRF guard, metrics | `crates/segue-relay/src/lib.rs:1-30` |
| CLI | `segue run -config`, `segue config check/contract/example` | `crates/segue-cli/src/lib.rs:20-25` |
| CI | Rust/Android/Go-oracle/interop/fuzz/supply-chain jobs on `instabox-medium` | `.github/workflows/ci.yml` |

| Missing | Evidence | Consequence for an app suite |
| --- | --- | --- |
| Kernel/session/policy reachable from the C ABI | `crates/segue-ffi/Cargo.toml` lists only `segue-{config,engine,routing,tun,transport}`; plan is `docs/design/ffi-kernel-embedding.md` | apps today run the bare engine, with no rule table, fake-IP DNS or kill switch of their own |
| Control plane | `crates/segue-relay/src/lib.rs:22` "control plane deferred" | accounts, device enrolment, catalog issuance, ticket signing, revocation sync all have to be built |
| Windows | `crates/segue-engine/src/tun_fd.rs:2225-2245` stub; `cfg(windows)` appears 4× in `segue-transport` (raw socket handle only) | a Windows client needs a new TUN backend and a socket-protector implementation for WinTun |
| Desktop shell | `platform/apple/XrayClientMac` is a debug sample (`MenuBarExtra` + settings); no privileged helper, no PF/WFP, no updater | macOS/Windows apps are greenfield, not ports |
| Release/evidence machinery for apps | `docs/release-process.md` covers core + SDK only | app versioning, signing, notarization, update channels are greenfield |
| Apple CI | `.github/workflows/ci.yml:799-807` — `apple:` job is `if: false`, "no macOS runner, owner 2026-11-13" | Swift changes are not compiled in CI today |

---

## 3. Proposed Segue app-suite architecture

### 3.1 Repositories

Tono's single-repo choice worked because one team owned client, control plane and
release at once, and it cost a 912 MB checkout and a 24-workflow CI where every
PR touches five path filters. Segue should split along **change cadence**, which
is also Tono's own stated reason for splitting node provisioning out
(`tono-node-provisioning/README.md:6-10`).

| Repo | Owns | Cadence | Reuses |
| --- | --- | --- | --- |
| `segue-core` (this repo) | Rust engine, C ABI, kernel/session/policy/relay, Swift + Kotlin wrappers, core CI | weekly | — |
| `segue-cloud` | control plane (API + DB + admin), policy compiler and signer, catalog publisher, revocation/ticket issuance, ops console | daily | Tono `services/control-plane` structure, auth model, catalog/policy shapes; **not** its code (see §5 licensing) |
| `segue-apple` | SwiftUI app + `NEPacketTunnelProvider` + menu-bar agent + privileged helper (PF/DNS/core) + root-owned updater | per release | Tono's helper protocol, `HelperProtocolVersion` gate, PF label rules, App-Group state files |
| `segue-windows` | Tauri/React app + LocalSystem service + portable `segue-client-core` crate + WFP + updater | per release | Tono's `tono-core` *shape*, WFP module layout, update manifest v1 |
| `segue-linux` (later) | Tauri UI reuse + nftables service + CLI | as needed | Windows crate's non-Windows service halves (`service/src/lib.rs:109-121` already has a `/run/…` path) |
| `segue-ops` (optional; can start inside `segue-cloud`) | node provisioning, node agents, fleet inventory | per fleet turnover | `tono-node-provisioning` transaction model, `node-agent` heartbeat |
| `segue-release` (optional) | shared release manifest schema and conformance tests both desktops compile against | rarely | `docs/UPDATE_PROTOCOL_V1.md` |

**One shared crate, not shared UI.** Tono proved that one portable Rust crate
(`tono-core`, `#![forbid(unsafe_code)]`) carrying catalog admission, policy
verification, routing generation, connect FSM and the update contract can serve
all desktop targets (`apps/windows/crates/tono-core/src/lib.rs:1-40`). Segue
already has most of that logic *in Rust* (`segue-kernel/src/rules.rs`,
`policy.rs`, `config.rs`) — but it is inside `segue-kernel`, which is proprietary
and mobile-shaped. The suite needs a **`segue-client` crate** that sits above the
FFI-or-kernel choice and is the one thing every app links:

```
segue-cloud ──(catalog, policy bundle, ticket)──┐
                                                ▼
                        segue-client (portable Rust, no OS calls)
                        catalog admission · policy verify · routing graph
                        connect FSM · state-intent rule · update contract
                                 │                         │
                    ┌────────────┴───────────┐   ┌─────────┴──────────┐
                    ▼                        ▼   ▼                    ▼
             segue-apple (Swift)      segue-windows (Rust)   segue-linux (Rust)
             helper: PF, DNS          service: WFP, DNS      service: nftables
                    │                        │                      │
                    └──── segue-ffi ─────────┴──────────────────────┘
                          (kernel mode, ABI 1.18)
```

This crate is the missing piece in Segue Core today, and building it is cheaper
than letting four clients re-derive routing from a signed bundle in three
languages (which is what Tono ended up doing: Swift `Catalog.swift`, Kotlin
`Catalog.kt`, Rust `tono-core/src/catalog.rs` — three hand-kept twins with
generated-contract `--check` scripts to stop drift,
`apps/ios/tools/sync-desktop-routing.py`).

### 3.2 Component map: reuse vs. build

| Component | iOS | Android | macOS | Windows | Linux |
| --- | --- | --- | --- | --- | --- |
| Data plane | Segue Core kernel mode (ABI 1.18, stage 3 of the embedding plan) | same | Segue Core kernel mode, packet pump or fd | Segue Core + **new WinTun backend** | Segue Core + nftables |
| Tunnel host | NE `NEPacketTunnelProvider` — Tono's fd-only pattern and 4064 MTU cap | `VpnService` — Tono's `:vpn` process + AIDL + `PublicStatus` fencing | None (packet tunnel not available outside NE) → helper + `utun` route injection (Tono's model) | `TonoService`-shaped service + WinTun adapter | systemd service + TUN |
| Kill switch | `includeAllNetworks` + on-demand; kernel refuses proxied flows | always-on/lockdown + kernel refusals | **PF anchor in a root helper** (reuse Tono's label/`quick` design) | **WFP** sublayer + filters (reuse Tono's module split) | nftables (new) |
| Privileged boundary | none (NE) | none (`VpnService`) | helper + Unix socket + audit-token peer check | LocalSystem service + named pipe + caller SID check | root service + Unix socket |
| Config source | signed policy bundle from `segue-cloud` | same | same | same | same |
| UI stack | SwiftUI | Compose | SwiftUI (`MenuBarExtra` + window, as the Segue sample already does) | Tauri + React | Tauri + React (shared with Windows) |
| Update | App Store, or Sparkle-equivalent not needed | Play, or self-update | root-owned update transaction (Tono's `NATIVE_UPDATE_V1` shape) | Tauri signed updater | distro packages first |
| State / confirmation | App-Group JSON + stamped tunnel reply | `PublicStatus` with boot/monotonic/instance fencing | helper-owned state file + app readback | service-owned state + app readback | service-owned |

Everything in the "kill switch" and "privileged boundary" rows is **copied from
Tono's design, not its code**, for licence reasons (§5) — but the design is worth
copying verbatim in shape, because it encodes years of failure.

### 3.3 Where the policy and kill switch actually live

This is the decision the suite must make before any UI work, because it decides
whether the apps are thin.

Tono's answer: **the privileged component is the only protection authority**
(`apps/windows/SECURITY.md:3-12`), and the client is not trusted to say "I am
connected". On Windows the service goes further and *derives* the strict
contract from the runtime graph rather than from client-supplied endpoint lists
(`service/src/core/windows_kill_switch/strict.rs:9-60`); only routes that arm or
widen protection additionally require the peer image to be the installed
`Tono.exe` (`service/src/core/server/mod.rs:1241-1300`). Segue's kernel already agrees in structure —
`KillSwitch::verdict` can only return `Proxy`/`Refuse`/`Wait` for a proxied
action, never `Direct` (`crates/segue-kernel/src/killswitch.rs:3-11`, `:109`) —
but that verdict only guards flows *inside* the tunnel. Packets that the OS never
routes into the TUN (a crashed helper, a dead core, an excluded route) are the
case Tono spends 138 decisions on.

Proposal:

1. **In-tunnel enforcement = kernel.** `segue-kernel`'s rule table, smart DNS and
   verdicts decide every flow. Apps do not re-implement routing.
2. **Out-of-tunnel enforcement = the privileged component.** One PF anchor
   (macOS) / one WFP sublayer (Windows) / one nftables table (Linux), owned by the
   helper, armed only after the kernel reports a healthy carrier, released only on
   an explicit user action — exactly Tono's `UserDisconnect` rule
   (`crates/segue-kernel/src/session/mod.rs:20-24` makes the same statement inside
   the kernel).
3. **Posture comes from the kernel, not the UI.** `xray_kernel_status_snapshot_json`
   and `xray_kernel_poll_event` (both in the embedding plan,
   `docs/design/ffi-kernel-embedding.md:3.2`) feed the app; the app feeds the
   **privileged** component only two things: arm-intent and disarm-intent, plus
   the "healthy" evidence the helper itself verifies (a TCP proof, as Tono's
   `TcpEndpointProof.swift`/`UnarmedReconnect.swift` do).
4. **Fail-open vs. fail-closed is a product setting, chosen per route class.**
   Tono's *design* is two-tier: strict mode blocks everything; the default
   releases ordinary traffic and keeps a narrow AI hold
   (`docs/selective-fail-open.md:1-20`, decision
   `036-2026-09-30-crash-hang-releases-then-ai-layer.md`). Its *shipped*
   behaviour is weaker than that on Windows: the failure-time hook is
   unregistered, so an exhausted connect releases everything (see §1.3), and the
   hold only runs on the explicit Quit / account-replacement path. Segue's kernel
   has the primitives (`Protection::Strict` / `Protection::Wait`,
   `crates/segue-kernel/src/killswitch.rs:27-35`) but no product policy, and the
   mapping from "all exits failed" to a verdict is missing entirely. Whatever is
   chosen, the lesson is to implement it in one place (Tono's
   `NetworkEffect` / `plan_failure`), test the table, and make the product copy
   describe what actually ships.
   **This is an owner question, not an engineering one.**

### 3.4 Phasing

| Milestone | Content | Exit criterion |
| --- | --- | --- |
| **M0 — Core completeness (in `segue-core`)** | finish `docs/design/ffi-kernel-embedding.md` stages 0–5: `EngineDialer::with_transport_dialer`, socket protection for kernel DNS upstreams, feature flag, `xray_kernel_*` surface, packets, kill switch, policy. Then stage 6 wrappers. | `xray_ffi_capabilities()` advertises bits 31–36; `cargo test --workspace` and the "off build is byte-identical" symbol test green |
| **M1 — Portable client crate** | new `segue-client` crate: catalog admission, policy verify, graph generation, connect FSM, state-intent rule, update contract; one conformance vector set | all four app shells link it; no OS calls in it (`#![forbid(unsafe_code)]` like `tono-core`) |
| **M2 — Control plane MVP (`segue-cloud`)** | email/OTP auth, device enrolment, catalog issuance + signing, policy compilation + Ed25519 signing, ticket issuance, revocation list, 5-min cron, one ops page | a device can sign in, receive a catalog + policy + ticket, and the kernel's fail-closed path reaches `Connected` |
| **M3 — iOS shipping app** | Segue app on `segue-client` + kernel mode; NE with fd; App-Group state; widgets deferred | TestFlight build connects, survives sleep/wake and Wi-Fi↔cellular, memory under NE limit on a real device |
| **M4 — Android shipping app** | `:vpn` process, AIDL, `PublicStatus`, tile; per-app routing | Play internal-track build, same acceptance |
| **M5 — macOS app + helper** | SwiftUI menu-bar app, root helper with PF, root-owned updater | notarized build; kill switch survives crash/reboot per the documented matrix |
| **M6 — Windows app + service** | WinTun backend in `segue-core`, Tauri UI, WFP service, updater | signed installer; same matrix |
| **M7 — Linux (optional)** | Tauri UI reuse, nftables service, CLI | Debian package |

Ordering note: M3/M4 before M5/M6 is deliberate. Mobile is where Segue Core is
already strong and where the reference apps exist; desktop is where the
privileged component, updater and installer work is entirely new, and that is 3–4×
the effort of a mobile shell (**guess**, based on Tono's file counts: 191 k lines
of Windows Rust versus ~35 k of iOS-side Swift including TonoKit).

---

## 4. Open questions for the owner

1. **Is Segue a consumer product with its own accounts, or a core + SDK that
   others' apps embed?** Tono is unambiguously the former; Segue Core today is the
   latter. The whole `segue-cloud` line of work only exists in the first answer.
2. **Fail-open or fail-closed by default?** Tono spent ~40 decision records on
   this and settled on "network first, narrow AI hold" for mainland-China
   customers. Segue's `KillSwitch` currently refuses everything when unhealthy.
   This changes the product's failure feel more than any other decision.
3. **Which product identity do the apps carry?** `platform/` intentionally keeps
   `Xray*` Swift/Kotlin names because the ABI is `xray_*`. A shipping app suite
   named Segue with `XrayCore` types inside is a branding and support-call
   problem; decide whether to rename the wrappers (an ABI-adjacent, breaking
   change) or keep the names private.
4. **Does the kernel ship inside the MPL-2.0 FFI?** The embedding plan flags this
   itself (`docs/design/ffi-kernel-embedding.md` §5.1, open question 10):
   `segue-ffi` is MPL-2.0, the kernel is `LicenseRef-Segue-Proprietary`. Shipping
   a proprietary static library inside an MPL-2.0 crate's artifact is a
   distribution question, not a code question.
5. **One helper binary per platform, or one privileged component reused?** Tono
   wrote macOS's helper in Swift and Windows's service in Rust, with no shared
   code. Segue could write **one Rust privileged component** for macOS + Windows
   + Linux, because `segue-core` and the client crate are already Rust — at the
   cost of PF/WFP bindings in Rust and a second FFI-ish surface. (**Guess:** this
   is probably worth it; it removes the entire class of "macOS fixed it, Windows
   did not" drift that Tono's decision log is full of.)
6. **How much of the update protocol is needed at v1?** Tono's v1 manifest binds
   both desktop targets to one `releaseSequence` with per-component digests
   (`docs/UPDATE_PROTOCOL_V1.md:20-60`). For Segue, `releaseSequence` and
   anti-downgrade are load-bearing; the paired-target part may not be.
7. **Node side: reuse `segue-relay` as-is behind Xray/sing-box inbounds, or fold
   the relay into the node's own process?** `segue-relay` expects loopback
   forwarding from an outer server (`crates/segue-relay/src/lib.rs:3-8`), which
   matches Tono's "Xray forwards to the relay on loopback" deployment — but who
   provisions that outer server? `tono-node-provisioning`'s staged transaction is
   the model; the tooling does not exist for Segue.
8. **Apple CI.** The `apple:` job is disabled for lack of a macOS runner
   (`.github/workflows/ci.yml:799-807`). An iOS app cannot ship without it. Is
   the answer Instabox macOS capacity, GitHub-hosted `macos-*`, or local builds
   only?
9. **Windows scope.** No WinTun backend exists. Is Windows in scope for v1, or is
   the suite iOS + Android + macOS first (which is what Tono's own history
   suggests is realistic: Windows shipped later and diverged)?
10. **Where do decisions live?** Tono's 138 decision records are its most valuable
    artifact after the code. Adopt the same `docs/decisions/NNN-YYYY-MM-DD-slug.md`
    convention with `owner`/`provisional` status in `segue-core`, or in a shared
    docs repo?

---

## 5. Licensing and copying

| Tono component | Licence signal | Reuse guidance |
| --- | --- | --- |
| `apps/windows` workspace | `license = "LicenseRef-Proprietary"` (`apps/windows/Cargo.toml:24`); the Tauri app's `package.json` says `GPL-3.0-only` (`apps/windows/app/package.json:4`) | **do not copy code**; copy structure and tests |
| iOS/Android apps | no root LICENSE file; the bundled sing-box is GPL-3.0 with notices in `apps/android/mobile/src/main/assets/licenses/` | **do not copy code**; copy the patterns |
| `services/control-plane` | no licence file; private product code | **do not copy code**; copy the API shape and the security invariants |
| Documentation (`docs/*.md`, `docs/decisions/*`) | no licence file, but it is prose that describes *what was learned* | read freely, restate in Segue's own words; do not paste |
| Vendor pins (sing-box, mihomo) | GPL-3.0 / MIT respectively | irrelevant to Segue, which ships its own core |

Note also that Segue Core itself is MPL-2.0 with four proprietary workspace crates
(`crates/segue-{kernel,session,policy,relay}/Cargo.toml:7`). Any "copy Tono's Rust"
plan would import a **GPL-3.0-adjacent product licence into an MPL/proprietary
tree** — another reason the answer is "copy the design, write the code".

---

## 6. What Segue should copy / avoid

### Copy (ranked)

1. **The privileged component as the only protection authority, with the app
   never able to weaken it.** `apps/windows/SECURITY.md:3-12` and Tono's
   helper/app split are the strongest thing in the repo. Segue's kernel already
   holds the in-tunnel half of this; the helper must hold the other half.
2. **A build-enforced contract version between app and privileged component.**
   `HelperProtocolVersion.swift:1-40` — one hand-bumped constant, a build gate
   that fails if helper sources changed without it, and a decision-log entry for
   why. Two shipped builds broke without it. Copy this on day one for the Segue
   helper and for the Windows service (`PROTOCOL_EPOCH`).
3. **One generated routing contract consumed by every client, checked for drift
   in CI.** `apps/ios/tools/sync-desktop-routing.py --check`,
   `ThreeTierRoutingContract.swift:4-9`. Segue gets this almost free if the
   contract lives in the Rust `segue-client` crate and the Swift/Kotlin sides
   *call* it rather than regenerate it.
4. **Truthful connected-state rules.** A tunnel is "connected" only when the
   core's own stamped reply or an OS-level TUN establishment says so —
   `TonoKit/.../TunnelConfirmation.swift:1-9`, `TonoVpnService.kt:467,484`. This
   is exactly the kind of bug a proxy app ships for months without noticing.
5. **Two-store cross-process state with fencing.** App-Group files with `flock` +
   atomic writes on iOS (`Shared/SharedFiles.swift:10-61`); boot count + monotonic
   clock + per-instance version on Android (`surface/PublicStatus.kt:19-45`).
   Segue's `segue-kernel` control API is HTTP-with-token
   (`crates/segue-kernel/src/control.rs:1-33`) — fine for a desktop helper,
   overkill and awkward inside an NE; the file pattern is the right one on mobile.
6. **fd over packet pump on Apple, and why.** `TunnelPlatform.swift:31-44` and the
   4064 MTU comment in `SingBoxConfig.swift:56-58`. Segue already has the fd path
   (`docs/architecture.md` TUN section) — copy the numbers and the reason, not the
   plumbing.
7. **A one-status-check CI gate with path filters**, and a merge queue
   (`.github/workflows/ci-gate.yml:1-60`). Segue's `ci.yml` is already close; the
   gate name is what makes "green on the exact head SHA" enforceable.
8. **Release gates expressed as customer-observable sentences** (G1–G4,
   `docs/SHIP_PLAN.md` §0) rather than "tag exists". Tono's most useful sentence:
   *a tag, a candidate installer or a green build is not a proof of a customer
   release* (`README.md:79-84`).
9. **A single update wire contract with a monotonic floor** for the two desktops
   (`docs/UPDATE_PROTOCOL_V1.md:20-60`) — worth adopting if Windows is ever in
   scope; overkill for an iOS/Android-only v1.
10. **A decision log with owner/provisional status.** 138 records, each answering
    one question with "Chosen / Why stricter / Rejected / Applied in". This is how
    the kill-switch behaviour stayed coherent across two independent clients.
11. **The PF/WFP details that only come from being burned.** Worth copying
    outright: on macOS, `/etc/pf.conf` gets only `anchor "tono.killswitch"`, never
    `load anchor … from`, because the latter is what `com.apple.pfctl` reinstalls
    at boot including Safe Mode (`KillSwitchPF.swift:711-768`, decision 034);
    every rule carries a class `label` or pfctl collapses exact permits into the
    bundle permit (`KillSwitchPF.swift:345-375`); and a withdrawal kills only the
    named hosts' states instead of `pfctl -F states`
    (`KillSwitchPF.swift:863-904`). On Windows: **one** WFP sublayer, because
    arbitration is sublayer-first and a second sublayer would cut loopback/DHCP/NDP
    the instant it armed (`wfp_model.rs:1-22`); a versioned filter-key namespace,
    or a key-only diff adopts the old build's stale filters (`:74-94`); and
    install-strictly-before-remove inside one transaction, so an endpoint swap
    never passes through a direct-traffic window (`wfp/mod.rs:838-858`).
12. **A lost arm reply keeps the fail-closed intent; a lost disarm reply is not a
    release.** `KillSwitchService.arm`'s catch block and
    `HelperManager.cleanUpAbandonedUpgrade` (`HelperManager.swift:604-625`). This
    is the single most leak-prone edge in any kill-switch client.
13. **A separate root daemon for "restore internet".** Tono has this on both
    platforms: `com.raydocs.tono.release` on its own socket on macOS
    (`ReleaseWorker.swift:11-24`) and the `TonoRelease` service on its own pipe on
    Windows (`service/src/release_wire.rs:1-30`). It exists so a helper blocked in
    a long update, or a wedged WFP call, cannot delay the user's escape hatch.
    Cheap to design in, expensive to retrofit.
14. **Order the release so DNS is restored before the firewall opens, and treat
    an unproven restore as a failure.** Windows refuses to disarm unless the DNS
    restore read-back succeeds, with a timeout counted as unproven
    (`disarm.rs:209-219`), and has exactly one deliberate escape (registry-only
    after a streak) so a machine without CIM can still Disconnect
    (`dns/mod.rs:74-82`). macOS carries the same idea as "a missing snapshot is
    not evidence" (`RuntimeCleanup.swift:394-403`).
15. **A pending privileged operation must fence every other one.** Tono's update
    attempt fences Connect, repair and startup core restore, and Disconnect is
    explicitly *not* update cancellation (`service/src/core/update.rs:100-270`);
    session generations make a late arm unable to touch a newer session
    (`HelperSessionGeneration.swift`, `SocketServer.swift:1042-1090`). Segue will
    need the same generation discipline the moment a helper exists.

### Avoid (ranked)

1. **Do not build a control plane and four clients at once.** Tono's repo is
   912 MB, 24 workflows, five platform path filters and a 138-entry decision log,
   and its Windows client still lags macOS. Sequence M0–M4.
2. **Do not let three languages each own catalog admission and graph generation.**
   Tono has `Catalog.swift`, `Catalog.kt` and `catalog.rs` with digests, YAML
   restrictions and reserved names duplicated, kept in sync by generated-contract
   scripts. Put it in `segue-client` once.
3. **Do not trust the core's "started" or the OS's "connected".** Tono needed
   explicit confirmation rules on both platforms; Segue's FFI has the same gap and
   its `xray_core_start` currently means "runtime spawned", not "flows work".
4. **Do not build a self-hosted runner farm.** `tono-build` was created
   2026-09-14, never registered a runner, and was retired; Tono now uses
   GitHub-hosted `macos-26`/`windows-2025`/`ubuntu-24.04`
   (`README.md:26-40`). Segue's Instabox runners do not include macOS — fix that
   with hosted runners, not a farm.
5. **Do not write the helper in a different language from the core unless you
   have a reason.** Tono wrote the macOS helper in Swift and the Windows service
   in Rust, so every protection fix lands twice and the decision log fills with
   "macOS fixed it, Windows pending". Segue's core is Rust; a Rust helper for all
   three desktops removes a whole drift class.
6. **Do not ship a design document as if it were the behaviour.** On Windows,
   `plan_failure` maps every exhausted non-strict connect to a full release
   because the selective-AI hook has no production caller
   (`crates/tono-core/src/network_disposition.rs:36`, decision 031), while
   `docs/selective-fail-open.md` reads as though the hold runs. Whatever Segue
   promises about post-failure protection must be the shipped table, tested, with
   the doc and the copy pointing at the same code.
7. **Do not copy Tono's per-platform MTU and routing divergence blindly.** Android
   9000, iOS 4064, different rule sets because Android has `package_name`. Fine —
   but Segue should state the numbers in one shared table and let the graph differ
   only where the OS genuinely can.
8. **Do not put `listen`/SOCKS front ends into the embedded kernel config
   accidentally.** The embedding plan flags this (open question 4): the prototype
   config requires `listen` (`crates/segue-kernel/src/config.rs:278`), and an
   embedded app must not open a loopback listener it never uses.
9. **Do not promise leak protection the OS cannot deliver.** Tono's
   `docs/selective-fail-open.md` is essentially a long proof that PF/WFP cannot
   keep a real IP from reaching a CDN-hosted AI service after a crash. Segue will
   face the same wall; say so in the product copy, as Tono eventually did
   (`apps/ios/README.md:60-64` states iOS's ECH/DoH boundary explicitly).
10. **Do not ship a GPL-3.0-licensed app shell on top of an MPL/proprietary core**
    without checking the combination deliberately; Tono's own licensing is
    inconsistent between the Rust workspace (`LicenseRef-Proprietary`) and the
    Tauri app (`GPL-3.0-only`), which is a cautionary signal, not a template.
11. **Do not let the update path be the last thing built.** Tono's gates G3/G4
    ("can ship again", "customer version = yours") are consistently the ones that
    slip, because an update mechanism that was never exercised cannot be
    qualified (decisions `025`, `032`, `118`, `119`, `120`; `RELEASE_LINES.md`
    records feeds stuck at 0.0.67/0.0.34 while source was 0.0.80).
