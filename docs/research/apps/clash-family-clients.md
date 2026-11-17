# Clash-family client apps: how FlClash, Clash Verge Rev, Mihomo Party and Clash Nyanpasu are built

Engineering study, 2026-11-17. Scope: architecture, core embedding, IPC, per-OS
TUN, privilege model, subscriptions, UX, and the operational layer (system
proxy, DNS, kill switch, logging, updates) of the four most-used GUI clients
around the mihomo core. Purpose: decide what Segue's own app should copy and
what to avoid. Recommendations are in the last section.

Sources (read-only shallow clones, `git clone --depth 30`):

| Clone | Revision | App version |
| --- | --- | --- |
| `/Volumes/dev/ref/apps/FlClash` (chen08209/FlClash) | `be84736` (2026-11-04) | v0.9.3 (`pubspec.yaml:5`) |
| `/Volumes/dev/ref/apps/clash-verge-rev` (clash-verge-rev/clash-verge-rev) | `e0b6fb9` (2026-11-17) | 2.6.0 (`package.json:3`) |
| `/Volumes/dev/ref/apps/mihomo-party` (mihomo-party-org/mihomo-party) | `e837463` (2026-11-16) | Clash Party, electron-builder |
| `/Volumes/dev/ref/apps/clash-nyanpasu` (libnyanpasu/clash-nyanpasu) | `d28a8b3` (2026-11-17) | Tauri v2 |

All citations are `path:line` relative to the clone root unless prefixed with a
clone name. Because the clones are shallow, a file path plus line is often the
only durable citation; commit hashes above pin the snapshot. Claims marked
**(guess)** are inferred rather than read.

---

## 0. Summary table

| | FlClash | Clash Verge Rev | Mihomo Party | Clash Nyanpasu |
| --- | --- | --- | --- | --- |
| UI | Flutter/Dart, Riverpod | React 19 + MUI, Tauri v2 (Rust) | React 19 + HeroUI, Electron 43 | React 19, Tauri v2 (Rust) |
| Core | mihomo **as a Go library**, linked in (`core/lib.go`) | mihomo **sidecar** (`sidecar/verge-mihomo`) | mihomo **sidecar** (downloaded) | mihomo **sidecar** (+ clash-rs, meow) |
| App↔core IPC | custom framed JSON-RPC over **unix socket / named pipe / gomobile FFI** | mihomo REST only (unix socket or named pipe per owner key) | mihomo REST over unix socket / named pipe | own framed JSON-RPC, then mihomo REST |
| App↔privileged helper | **per-OS helper** (Windows service, Linux systemd socket, macOS none) | `clash-verge-service` (separate repo, IPC crate) | macOS LaunchDaemon; setuid-elsewhere | `nyanpasu-service` sidecar |
| Platforms | Win, macOS, Linux, Android | Win, macOS, Linux | Win, macOS, Linux | Win, macOS, Linux |
| TUN owner | core itself (mihomo `sing-tun`) | mihomo in service/sidecar process | mihomo, setuid or elevated app | mihomo via service |
| Kill switch | **none** | **none** | **none** | **none** |
| Telemetry | none (privacy text) | none | none | none |
| Notable idea | helper protocol with core **SHA-256 pinning**; response spill to disk | lightweight mode; runtime-bundle staging; authoritative-field enforcement | controller with **no TCP port at all**; per-app page cards | app-wide RPC registry shared by desktop/server/CLI |

---

## 1. FlClash

### 1.1 Shell

Flutter + Dart, `flutter_riverpod ^3.4.3` (`pubspec.yaml:59`), Freezed models.
The app is one Dart tree for all platforms (`lib/`), with native code in
Kotlin (`android/`), Swift (`macos/Runner`), CMake (`plugins/proxy/windows`,
`windows/`) and a Rust plugin (`plugins/rust_api`).

**No iOS target exists**: there is no `ios/` directory, and the Go core is
behind `//go:build android` for mobile (`core/lib.go:1`, `core/mobile/mobile.go:1`).
Android is the only mobile platform.

Navigation is an 8-tab layout: dashboard, proxies, profiles, requests, DNS,
resources, logs, tools (`lib/views/navigation.dart:18-63`).

### 1.2 Driving the core

FlClash is the only one of the four that **links mihomo as a Go library**
(`core/go.mod:5` requires `github.com/metacubex/mihomo` with a `replace` to a
vendored `core/Clash.Meta` fork, `.gitmodules`). There is no sidecar on any
platform.

Two IPC transports and two TUN paths reach that in-process core:

| Platform | Transport | Evidence |
| --- | --- | --- |
| Desktop | length-prefixed JSON-RPC over unix socket or Windows named pipe, server in Rust (`plugins/rust_api`, `IpcServer::bind`) | `core/server.go:29` (64 MiB frame cap), `lib/core/desktop/rpc_client.dart:35`, `lib/plugins/service.dart:42-56` |
| Android | gomobile binding, `InvokeMethod` / `StartTun` callbacks | `core/mobile/mobile.go:48-54`, `android/core/src/main/java/com/follow/clash/core/Core.kt:31` |
| Android TUN | fd handed to Go, with `Protect`/`ResolveUid`/`ResolvePackage` callbacks | `core/lib.go:24-40`, `android/service/.../VpnService.kt:159-170` |
| Desktop TUN | core opens the TUN itself while privileged (setuid core) | §1.5 |

Desktop IPC is a JSON-RPC with **method namespacing** (`core.init`,
`config.setup`, `proxy.testDelay`, …) enumerated as constants
(`core/protocol.go:19-40`), a single `ResultHandler` callback
(`core/mobile/mobile.go:48`), and a **response spill**: any reply over 1 MiB is
written to a file under the core home dir and the host deletes it after reading,
because "Android copies a reply into the Java heap three times and the desktop
IPC frame stops at maxIPCFrameSize" (`core/spill.go:8-13`). This is a real
mobile-memory trick, not a conventional design (copy item 5 in §7).

Large-response handling also has a client-side rule: the Dart client decodes
off the UI isolate when the payload exceeds 50 KiB (`lib/plugins/service.dart:27-30`).

### 1.3 Desktop helper (privilege)

Desktop needs root for TUN. FlClash ships a **Rust helper binary**
(`services/helper`, `warp` HTTP server, `services/helper/Cargo.toml:10-20`)
that the app installs per OS. It is not a proxy: it only spawns and reaps the
core.

| OS | Mechanism | Evidence |
| --- | --- | --- |
| Windows | real Windows service `FlClashHelperService`, `windows-service` crate; app does `ShellExecute("runas")` with `install --owner-pid N` | `services/helper/src/service/windows.rs:26,147`, `lib/common/system.dart:345-352`, `:280-300` |
| Linux | systemd unit `/etc/systemd/system/flclash-helper.service`, unix socket `/run/flclash/helper.sock` mode 0660, owner uid/gid passed as env | `services/helper/src/service/linux.rs:22-28`, install via `pkexec` then `sudo` fallback (`lib/common/linux_elevation.dart:31-60`) |
| macOS | **no helper.** The app makes the core binary **setuid** with `chown root:admin && chmod 4750` through `osascript ... with administrator privileges` | `lib/common/system.dart:105-108`, `:245-255`; `hasHelperService` excludes macOS (`:138-139`) |

The helper's security model is worth copying (§7):

- The helper serves **only** `GET /ping`, `POST /start`, `POST /stop`, `GET /logs`
  on `127.0.0.1:47890` (Linux: the unix socket) — `hub.rs:787-812`, `:853`.
- Every request must have no `Origin` header and a `Host` of
  `127.0.0.1`/`localhost`/`FlClashHelperService`, which defeats browser-based
  CSRF against the loopback port (`hub.rs:767-785`).
- The request body is capped at **4096 bytes** and `Content-Length` is
  required (`hub.rs:58`, `:795-802`).
- `start` carries an `address` (the core socket path) and a `sessionId`; the
  helper rejects an address it did not issue (`is_allowed_core_address`,
  `hub.rs:319`, `:435`), and on Linux re-verifies the socket is owned by the
  helper owner (`services/helper/src/service/linux.rs:71-80`) and that every
  accepted connection's peer uid is the owner's (`is_authorized_peer`,
  `linux.rs:315-317`).
- **The helper pins the core binary by SHA-256**: `EXPECTED_CORE_SHA256` is
  baked in at build time (`hub.rs:56`), checked on every spawn
  (`hub.rs:230`), and `ping?coreSha256=…` fails when the on-disk core does not
  match the bundled manifest (`hub.rs:632-641`,
  `lib/core/desktop/helper_client.dart:158-210`). A user-writable directory
  next to a root helper is the classic local privilege-escalation hole; this
  shuts it.
- The helper holds the core in a **Windows Job Object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`** so a helper crash does not orphan a
  root core (`hub.rs:189`).
- The core is started **elevated and then drops back**: the Go core detects
  "euid 0 but real uid not 0" and reclaims file ownership in the app home
  (`core/ownership_unix.go:27`, `canReclaim` `:31`, `reclaimOwnership` `:132`), so the root core
  does not leave root-owned config files that the GUI cannot rewrite.

Fallback: if the helper is absent or its manifest is missing, the app launches
the core directly as the user (`DirectCoreLauncher`, `lib/core/desktop/launcher.dart:24-47`);
`HelperLauncherResolver` picks helper-then-direct and wraps the pair in a
`FallbackCoreLauncher` (`lib/core/desktop/helper_client.dart:485-535`), and TUN
authorization fails cleanly rather than silently hanging.

The Dart side treats helper *lifecycle* as a state machine with revisions and
timeout-window extension: a method is failed only when the core stops answering
*anything*, not when one call is slow (`lib/core/desktop/rpc_client.dart:44-55`).

### 1.4 IPC details

The helper protocol version is header-carried (`x-flclash-helper-protocol`,
`hub.rs:51-55`) and versioned differently per OS (8 on Windows, 6 elsewhere) —
a shortcut, but it lets the app refuse an old helper rather than misparse it.
Dart's helper client forces **DIRECT** for the helper connection
(`client.findProxy = (uri) => 'DIRECT'`, `helper_client.dart:98`) so a
system proxy cannot loop the control channel through the core it controls.

### 1.5 TUN per OS

- **Android**: a `VpnService` in its own module
  (`android/service/src/main/AndroidManifest.xml:8-19`,
  `foregroundServiceType="specialUse"`, `BIND_VPN_SERVICE`), plus a second
  `ProxyService` for the "proxy only, no TUN" mode (`:21-31`). The builder sets
  addresses, routes, DNS, MTU, **`setBlocking(false)`** (non-blocking fd; the Go
  side owns the loop) and, on Android 10+, **`setHttpProxy`** to the core's
  mixed port when the user wants system-proxy semantics
  (`VpnService.kt:125-150`). Access control is per-app allow/disallow
  (`configureAccessControl`, `:231`). `allowBypass()` when the user opts in.
  `onStartCommand` catches the **always-on VPN** start path Android uses
  instead of the app's bound path (`VpnService.kt:113-117`) — a detail most
  clients miss. If the core rejects the fd, the service tears the VPN down
  rather than leaving routes pointing at a dead interface
  (`VpnService.kt:155-175`).
- **Desktop macOS/Linux/Windows**: the privileged core opens the utun/wintun
  itself; the app does not manage a tun fd. The app only patches
  `tun.enable`, `auto-route`, `device` and `stack` into the config
  (`core/config.go:252-263`); the interface code is in the vendored mihomo fork
  (`core/Clash.Meta`), not in this repo.

DNS: the Android tun gets either the configured servers or `NET_ANY` when DNS
hijacking is on (`VpnService.kt:77-86`).

### 1.6 Profiles

`Profile` is Freezed with `url`, `ageSecretKey` (age-encrypted subscriptions),
`autoUpdate`, `autoUpdateDuration`, `selectedMap`, per-profile `overrides`
(`lib/models/profile.dart:65-86`). Update fetches bytes through a Dio client
whose `HttpClient` sets **`userAgent = globalState.ua`** (a browser UA,
`lib/common/constant.dart:15-16`, `lib/common/request.dart:36-40`) and honours
`content-disposition` and `subscription-userinfo` (`profile.dart:186-200`).
The update path validates the downloaded YAML by calling the core before
committing the file, and writes a temp file then copies it (`profile.dart:202-216`).
An in-flight download never clobbers a concurrently edited profile
(`lib/providers/actions/profiles.dart:138-160`).

### 1.7 System proxy / DNS / autostart

- System proxy is a **separate Flutter plugin** (`plugins/proxy`): macOS via
  `networksetup -setwebproxy` per network service (`plugins/proxy/lib/src/macos_proxy.dart:5-38`),
  Linux via GNOME/MATE/KDE backends writing gsettings/kwrite config
  (`plugins/proxy/lib/src/linux_proxy.dart:7-40`), Windows via a C++ plugin
  writing WinINet (`plugins/proxy/windows/proxy_plugin.cpp:146-186`), with a
  carefully sanitised bypass list (`plugins/proxy/lib/src/windows_proxy.dart:7-24`).
- System DNS: optional "auto set system DNS" that records the old servers and
  restores them, and only while TUN is actually authorized
  (`lib/common/system_dns.dart:10-51`, `:77-97`, `lib/providers/state/system.dart:177-192`).
- Autostart: `launch_at_startup` fork (`pubspec.yaml:29-32`,
  `lib/common/launch.dart:10-40`).
- Crash recovery: desktop detects an unexpected transport disconnect and moves
  to a failed state; it does **not** auto-restart the core (it stops the
  lease and surfaces the failure, `lib/core/desktop/lifecycle.dart:732-773`).
  Android has a **BootGuard** that records boot stages and uses
  `getLastExitInfo` to detect a crash loop (`lib/common/boot_guard.dart:9-40`).
- Mobile battery: requests the battery-unrestricted allowlist and follows
  Xiaomi's battery-saver variant (`lib/plugins/battery.dart:4-28`,
  `android/app/src/main/kotlin/com/follow/clash/plugins/BatteryPlugin.kt:87,130,188`).
  A Quick Settings tile toggles the service (`TileService.kt:15-30`).
  Wi-Fi-SSID-based "on demand" suspend (`lib/providers/on_demand.dart:44`,
  `lib/providers/state/system.dart:297`).
- Update: GitHub `releases/latest` (`lib/common/request.dart:108-113`); the
  release downloader refuses bad certs even when the user disabled cert checks
  because it installs as administrator (`request.dart:19-21`, `:45-49`).

### 1.8 Kill switch

**Absent.** Grepped `kill.?switch|block when|block-outbound` across `lib/`,
`core/`, `android/`: no hits. (Android always-on VPN "block connections without
VPN" is a system setting, not the app's.)

### 1.9 Telemetry

**Absent**, and stated so in the app's own privacy text: "The Software includes
no analytics or crash reporting service on any platform"
(`lib/l10n/intl/messages_en.dart:709`).

---

## 2. Clash Verge Rev

### 2.1 Shell

React 19.3.1 + MUI 9 + Tailwind (`package.json:51-74`), Vite, TanStack Router;
backend is **Tauri v2** in Rust (`src-tauri/`), with six workspace crates for
logging, i18n, sysinfo, media unlock, a rate limiter and a "draft" store
(`crates/`). IPC is Tauri commands plus a generated, typed contract
(`src-tauri/src/ipc.rs:3-98`, `tauri-specta`).

### 2.2 Driving the core

Sidecar only: `externalBin: ["sidecar/verge-mihomo", "sidecar/verge-mihomo-alpha"]`
(`src-tauri/tauri.conf.json:17`), downloaded at build time from MetaCubeX
releases (`scripts/prebuild.mjs:163-173`). `RunningMode` is
`Service | Sidecar | NotRunning` (`src-tauri/src/core/manager/mod.rs:61-65`) —
the app prefers the privileged service and **falls back to a user-owned
sidecar** with an explicit notice (`lifecycle.rs:55`, `:378-407`).

Config layout: `verge.yaml` (GUI), `profiles.yaml` (index), `profiles/`
(`src-tauri/src/utils/dirs.rs:20-22`, `:105-111`). The app owns the control
plane: `CONTROL_PLANE_KEYS` (`external-controller`, `secret`, ports, `mode`,
`log-level`, `ipv6`, …) are captured after the app derives them and **re-enforced
after every user merge/script** so a profile cannot hijack them
(`src-tauri/src/enhance/mod.rs:296-318`, `AuthoritativeFields::enforce` `:366`).
TUN and DNS get the same treatment (`enhance/tun.rs:10-44`).
That is the strongest config-integrity idea in this group.

### 2.3 IPC

The GUI never talks HTTP to mihomo over TCP. The controller address is a
**unix socket** or **named pipe**: `verge-mihomo.sock` in the macOS per-user
temp dir (with a hard `<104 byte` sun_path check, `dirs.rs:201-240`), in the
app data dir on Linux (`:196-200`), or
`\\.\pipe\verge-mihomo-sidecar-{release|dev}-{owner_key}` on Windows
(`:245-253`). The owner key is derived from the owner identity, so two users'
sidecars cannot collide. mihomo itself supports `external-controller-unix` and
`external-controller-pipe` (upstream `/Volumes/dev/ref/mihomo/config/config.go:426-427`),
so there is no secret to leak: the filesystem permission is the credential.

### 2.4 Privilege model

Platforms: Windows, macOS, Linux (bundle targets in `tauri.conf.json`).
The privileged part is a **separate project**, `clash-verge-service`, consumed
as a git dependency `clash_verge_service_ipc` v2.8.1 with a typed IPC crate
(`src-tauri/Cargo.toml:96-98`). Install paths are OS-specific and the app
detects registration, not just presence:

| OS | Registration | Evidence |
| --- | --- | --- |
| Windows | SCM service `WINDOWS_SERVICE_NAME`, queried via the `windows-service` crate; notes when it is installed but not AutoStart | `service.rs:279-330` |
| macOS | `/Library/LaunchDaemons/<MACOS_SERVICE_ID>.plist` + `/Library/PrivilegedHelperTools/<MACOS_SERVICE_ID>.bundle`, with legacy-marker migration | `service.rs:251-277` |
| Linux | systemd unit, or an `/etc/init.d` OpenRC script when `/run/systemd/system` is absent | `service.rs:336-352` |

The app models **service health** finely — `NotInstalled`, `NeedsReinstall`,
`ReinstallRequired`, `ForceReinstallRequired`, `SidecarAllowed`,
`Unavailable(reason)` — and can reinstall/repair from the UI (`service.rs:204-215`,
`cmd/service.rs:86-120`).
On Windows it elevates only for the install step, with `runas` and
`CREATE_NO_WINDOW` (`service.rs:614-630`).

### 2.5 TUN / DNS per OS

The app does not create a tun fd on desktop; mihomo does. `use_tun` injects
`tun.enable` and, when the DNS mode is fake-ip, fills `enable`, `ipv6`,
`fake-ip-range` and `fake-ip-range6` defaults (`enhance/tun.rs:10-44`). DNS is
editable as a separate YAML that is applied over the profile
(`cmd/clash.rs:129-170`: `save_dns_config`, `apply_dns_config`,
`set_dns_override`). There is no mobile target and therefore no `VpnService`
or NetworkExtension code.

### 2.6 Profiles

`PrfItem` carries `user_agent` and `update_interval` (minutes) per profile
(`src-tauri/src/config/prfitem.rs:86-95`); when absent, `profile-update-interval`
(hours) is read from a response header and multiplied by 60 (`prfitem.rs:340-350`).
The default UA is `clash-verge/v<version>` (`src-tauri/src/utils/network.rs:275-280`).
A **timer registry** refreshes only overdue/allow_auto_update items and runs
overdue tasks immediately at startup (`src-tauri/src/core/timer.rs:115-170`).
Per-profile transform chain types: `Merge`, `Script`, `Rules`, `Proxies`,
`Groups` (`enhance/chain.rs:22-27`), with caching keyed on file mtime
(`CachedChain`). Scripts run in **Boa** with hard limits: 5 s, 10 MiB input,
1 MiB output, 10^7 loop iterations (`enhance/script.rs:12-16`), and a failure
returns the config unchanged (`:22-30`).

### 2.7 UX

Pages: home, proxies, profiles, connections, rules, logs, settings, unlock
(`src/pages/`). Proxies are group cards with a navigator strip, per-group
filter/sort, and a delay tester with a configurable timeout
(`src/components/proxy/proxy-groups.tsx:115-141`,
`use-filter-sort.ts`).

### 2.8 Operations

- **System proxy**: `sysproxy` with a **GuardMonitor** that re-asserts the OS
  proxy every 30 s and distinguishes sysproxy vs PAC ordering per OS
  (`sysopt.rs:18`, `:39-53`, `:257`). State is modelled as authoritative vs
  externally-changed (`proxy_control`, `AuthoritativeState`).
- **Lightweight mode**: close-to-tray destroys the main Tauri window after a
  timer and keeps only the core + tray; a menu action recreates the window
  (`core/lightweight.rs:150-200`). This is a memory trick: the WebView process
  goes away.
- **Runtime bundle**: before starting the service, the app collects profile,
  providers and SSH keys into a staged runtime directory so the service can
  read them without broad filesystem access (`core/runtime_bundle.rs:32`, `:210-654`).
- Variants: `verge-mihomo` / `verge-mihomo-alpha`; core upgrade is a UI command
  (`cmd::upgrade_clash_core`).
- **Logging**: `clash-verge-logging` on `flexi_logger`, 128 KiB files × N with
  `Criterion::Size` rotation and `Cleanup::KeepLogFiles`
  (`crates/clash-verge-logging/src/lib.rs:156-241`), plus structured event
  types per subsystem (`Type` enum, `:23-40`).
- **Updates**: `tauri-plugin-updater` with a minisign pubkey and three mirror
  endpoints (`tauri.conf.json:33-40`), including GitHub-proxy mirrors — a
  China-accessibility decision.
- **Kill switch / telemetry**: **absent** (grepped `src-tauri/src`, `src`:
  no hits).

---

## 3. Mihomo Party

### 3.1 Shell

Electron 43 + React 19 + HeroUI + Tailwind 4 (`package.json:76-77,94`), built by
electron-vite. Three processes: `src/main` (core lifecycle, config, sysproxy,
tray, updater), `src/preload` (whitelist bridge), `src/renderer` (React SPA).
The window is `show: false` then shown, so there is no white flash
(`src/main/window.ts:199`).

### 3.2 Driving the core

mihomo / mihomo-alpha / mihomo-smart sidecars bundled into
`resources/sidecar` (`scripts/prepare.mjs:190-199`, `electron-builder.yml:20-22`),
and a user-installable specific version (`src/main/utils/github.ts:172-278`).
Spawn: `spawn(corePath, ['-d', workDir, ctlParam, ipcPath])` with
`-ext-ctl-pipe` on Windows and `-ext-ctl-unix` elsewhere
(`src/main/core/manager.ts:89,626,635`). **`external-controller` is forced
empty** in the generated config (`src/main/utils/template.ts:95`,
`src/main/core/factory.ts:229-233`).

The controller therefore has **no TCP port and no secret at all**:
`/tmp/mihomo-party-<uid>-<pid>.sock` or
`\\.\pipe\MihomoParty\mihomo-{admin|user}-<session>-<pid>`
(`manager.ts:484-498`). Main talks HTTP-over-socket with
`axios.create({ baseURL: 'http://localhost', socketPath })` and WS with a custom
`createConnection({ path })` (`src/main/core/mihomoApi.ts:161-167`, `:180-184`). The socket
path *is* the credential.

### 3.3 IPC

Preload exposes a **hard-coded channel whitelist** of ~200 invoke channels,
plus `listen`/`send` lists; anything else throws
(`src/preload/index.ts:4-199`, `:199-227`, `:240-300`), via `contextBridge`
(`:306-307`). The renderer never sees the core socket;
main pushes `mihomoTraffic`, `mihomoConnections`, `mihomoLogs`, `mihomoMemory`
events (`mihomoApi.ts:529,578,619,661`). This is the cleanest
secret-containment model of the four: even a compromised renderer can only call
the enumerated commands, not the core API.

### 3.4 Platforms and TUN

| OS | Privilege approach | Evidence |
| --- | --- | --- |
| Windows | **the whole app runs elevated** for TUN; self-relaunch through PowerShell `Start-Process -Verb RunAs` | `src/main/core/permissions.ts:278-300` |
| macOS | sidecar is **setuid root** (`chmod +s`, root:admin) in the pkg postinstall; separate root LaunchDaemon `party.mihomo.helper` for sysproxy/DNS | `build/pkg-scripts/postinstall:40-41`, `:25-27` |
| Linux | setuid root on the sidecars in `postinst` and AUR PKGBUILD, runtime `pkexec chown root && chmod +sx` fallback | `build/linux/postinst:17-19`, `aur/mihomo-party-bin/PKGBUILD:23`, `permissions.ts:245-290` |

TUN defaults `stack: mixed`, `auto-route: true`, `dns-hijack: ['any:53']`, MTU
1500; device `Mihomo` (Win/Linux) or `utun1500` (macOS)
(`src/shared/appConfig.ts:56`, `:72-79`).

macOS DNS: only macOS changes the **system** DNS — sets `223.5.5.5` via the
helper/`networksetup` while TUN is up and restores the saved value
(`src/main/core/dns.ts:9`, `:55-106`). Windows/Linux rely on `dns-hijack` alone.

### 3.5 Profiles

`profiles/<id>.yaml` + `profile.yaml` index (`src/main/utils/dirs.ts:148-156`).
Item: `type remote|local`, `url`, `interval` (minutes *or* 5-field cron),
`autoUpdate`, `useProxy`, `substore`, `userAgent`, `ageSecretKey`, `override[]`,
`pluginId` (`src/shared/types.d.ts:602-623`). Default UA
`mihomo.party/v<ver> (clash.meta)`, per-profile override
(`src/main/config/profile.ts:640-651`). Scheduling with `croner` for cron and a
plain interval for minutes, minimum 1 min, six-field cron rejected
(`core/profileUpdater.ts:15-16`, `:71-92`); on-start refresh gated by a setting
(`:110-160`). Overrides are YAML merge **or JavaScript run in `node:vm`** with
`main(profile)` (`src/main/core/factory.ts:425-430`).

### 3.6 UX

No single dashboard: the **sider is the dashboard**, with 15 draggable status
cards (`src/shared/appConfig.ts:23-39`, `src/renderer/src/components/sider/sider-cards.tsx:57`).
Proxies page has a configurable-column group grid (`pages/proxies.tsx:282`),
dnd-kit reordering (`:237`) and per-node delay testing with concurrency
(`:283`, `:293`). Rules filter persisted in localStorage (`pages/rules.tsx:35-39`).

### 3.7 Operations

- System proxy with a **local PAC server** on `127.0.0.1:10000+`
  (`src/main/sys/sysproxy.ts:77-160`, `resolve/server.ts:51-87`), macOS via the
  privileged helper, Win/Linux via the `sysproxy-rs` N-API addon
  (`src/native/sysproxy/index.js`).
- Autostart: Windows **scheduled task** (to avoid a UAC prompt at login), macOS
  `setLoginItemSettings`, Linux XDG autostart desktop file
  (`src/main/sys/autoRun.ts:82-167`, `:217`, `:239-243`).
- Crash recovery: Linux-only core watchdog `sh -c 'cat >/dev/null; kill -9 $1'`
  tied to the parent's stdin (so an app crash kills the core)
  (`manager.ts:200-220`, `:208`), auto-restart twice 750 ms apart on unexpected exit
  (`:91`, `:1080-1098`), and resume-from-suspend recovery (`sys/resume.ts:50-71`).
- Logging: daily files per component, 10 MB cap compacted to 50%, 7-day
  retention (`utils/logFile.ts:5-11`, `:115-130`, `utils/init.ts:310-311`).
- Update: **custom** updater (not electron-updater): reads `latest.yml`, SHA-256
  verifies, falls back across GitHub mirrors, elevates as needed
  (`resolve/autoUpdater.ts:92-112`, `:190-194`).
- Plugin system: `.cpx` association, Ed25519 device keys, encrypted vault, and a
  provider-integration spec that keeps the real subscription URL out of the
  client (`docs/plugin/PROVIDER_INTEGRATION_v2.md:19-21`). Significant but out
  of scope for a core client.
- **Kill switch / telemetry: absent** (grepped `src/`, `docs/`).

---

## 4. Clash Nyanpasu

### 4.1 Shell

React 19 + TanStack Router + Tailwind 4 frontend (`frontend/nyanpasu`), a
component library (`frontend/ui`), and a very large Rust workspace under
`backend/` behind Tauri v2. Distinctive crates: `nyanpasu-core` (application
facade), `nyanpasu-server` (headless daemon that **refuses elevation by
design**, `backend/nyanpasu-server/src/lib.rs:1`), `nyanpasu-rpc`,
`nyanpasu-rpc-protocol`, `nyanpasu-rpc-wire`, `nyanpasu-os`, `nyanpasu-config`,
`nyanpasu-tsdb`, `nyanpasu-local-channel`, `nyanpasu-cli`, a Slint
statistics widget running as its own process, and a crash-reporter child
process.

### 4.2 Driving the core

Sidecars `sidecar/mihomo`, `mihomo-alpha`, `clash-rs`, `clash-rs-alpha`,
`meow`, `meow-alpha`, `nyanpasu-service`, `nyanpasu-cli`
(`backend/tauri/tauri.conf.json:48-59`); six selectable cores in `ClashCore`
(`backend/nyanpasu-config/src/application/clash_core.rs:26-40`). The process
supervisor itself lives in an external submodule `nyanpasu-runtime`
(`backend/Cargo.toml:48`, `.gitmodules:1-3`), so the spawn code is not in this clone **(guess:
spawn arguments mirror mihomo's `-d <dir> -ext-ctl-* <path>`)**. The controller
port is chosen and probed, then forced into the generated config
(`backend/nyanpasu-config/src/runtime/executor/plan.rs:62`,
`backend/nyanpasu-core/src/client/ports.rs:194-218`); `secret` is modelled and
stripped from read-only views (`clash/api.rs:10-45`). Generated config:
`runtime/clash-config.yaml` (`client/runtime.rs:27-28`).

### 4.3 IPC — the notable part

One **length-prefixed JSON-RPC** for every surface: 4-byte big-endian length +
JSON, `PROTOCOL_VERSION = 1`, 4 MiB cap (`backend/nyanpasu-rpc-wire/src/frame.rs:10-14`),
`Hello/Accept` handshake declaring required/optional features
(`.../client/transport.rs:27-40`). Transports:

| Transport | Use | Evidence |
| --- | --- | --- |
| Tauri `invoke('call_rpc', {method, params})` | desktop UI | `backend/tauri/src/unified_rpc/native.rs:104-118`, `frontend/rpc/src/tauri-bindings.ts:9-13` |
| Unix socket / Windows named pipe | server + CLI, first-binder ownership | `nyanpasu-single-instance/src/endpoint/unix.rs:30-45` (peer euid check, 107/103-byte path limit), `.../windows.rs:30-46` (pipe ACL + peer SID check) |
| Opt-in HTTP on `127.0.0.1:0` | browser UI | `nyanpasu-rpc/src/http/listener.rs:61-64`, auth in `.../http/auth.rs` |

The **command catalogue is data**: each method declares `RpcTarget`
(Desktop/Http/Local) and `Scope` (`command_catalog.rs:170-171`), the frontend
generates typed bindings, and `rpc_describe` lets a client discover the surface.
That is a genuinely better-controlled IPC boundary than either Verge's
command sprawl or Party's 200-channel list.

### 4.4 Privilege model

`nyanpasu-service` sidecar installed elevated — `pkexec --disable-internal-agent`
(Linux), `runas` (Windows), `sudo` via osascript (macOS) — with an
`ElevationConsent` port so the headless server yields `RefuseElevation`
(`backend/nyanpasu-os/src/service.rs:86-150`,
`backend/nyanpasu-os/src/elevation/mod.rs:1-24`). No setcap anywhere. The
desktop can run in service mode or user mode (`enable_service_mode`,
`nyanpasu-config/src/application/mod.rs:130`).

TUN specifics: Windows `wintun.dll` fetched and hash-verified at build
(`scripts/src/prepare/resources.ts:394-403`); UWP loopback exemption via a
bundled `enableLoopback.exe` (`backend/tauri/src/core/win_uwp.rs:22-38`);
transparent proxy (redir/tproxy) **Linux only**, applied by the privileged host
(`backend/nyanpasu-core/src/client/transparent_proxy.rs:8`, `:50-99`); macOS DNS via a
scoped `State:/Network/Service/nyanpasu-dns/DNS` setting
(`actor_v2/local_host.rs:50-54`).

### 4.5 Profiles

`profiles.yaml` with `current`, `global_transforms`, `valid`, folders, layouts,
`items` (`backend/nyanpasu-config/src/profile/profiles.rs:12-52`). Remote
options: `user_agent`, `with_proxy`, `self_proxy`, `update_interval_minutes`
(0 = off, default 120) (`profile/source.rs:111-145`). Fetch via rustls reqwest
with 30 s timeout and a proxy chain self → system → direct, default UA
`clash-nyanpasu/v<version>`, plus `x-hwid`, `x-device-os`, `x-ver-os`,
`x-device-model` headers, parsing `subscription-userinfo` and the suggested
interval, and exponential retry that does not retry 401/403/404
(`backend/nyanpasu-net/src/subscription_http.rs:94-140`, `:255-260`) — the most
provider-friendly subscription client of the four. Scheduling is per-profile
interval jobs with `StartupCatchUp` when overdue
(`nyanpasu-core/src/state/profiles/jobs.rs:145`, `:206`). Transforms:
`Overlay` or `Script{JavaScript|Lua}` through a pure pipeline with builtin
transforms (`nyanpasu-config/src/profile/definition.rs:56-61`,
`nyanpasu-profile-transform/src/builtin/*`).

### 4.6 UX and operations

Pages: proxies, rules, connections, logs, profiles, providers, topology,
dashboard, settings (`frontend/nyanpasu/src/route-tree.gen.ts:96-141`), plus a
tray-menu mini app. System proxy via a `sysproxy` fork with an optional
**proxy guard** re-assert loop (`nyanpasu-os/src/system_proxy.rs:18-63`,
`nyanpasu-core/src/client/effects/plan.rs:43`, `:164`). Logging goes to redb with
sharded tables and a capped cache (`nyanpasu-core/src/logs/redb.rs:23-25`) plus
a time-series store (`nyanpasu-tsdb/src/lib.rs:1-6`). Crash recovery uses crash-safe stamped
documents and versioned snapshots (`nyanpasu-persistence/src/lib.rs:1-4`) and a
separate crash-report window. Updates: `tauri-plugin-updater` with four mirrors
and minisign (`tauri.conf.json:114-125`), plus a core updater manifest
(`nyanpasu-updater/src/updater/mod.rs:42-54`). Memory: the Slint widget is
software-rendered to avoid the GL driver (~45–54 MB saved)
(`nyanpasu-widget/Cargo.toml:33-37`). **Kill switch and telemetry: absent**
(greps found zero hits).

---

## 5. Cross-cutting findings

### 5.1 Privilege and the elevated core

Three different answers to "who owns root":

1. **FlClash**: a tiny, narrow helper that only spawns a **SHA-256-pinned**
   core, plus a macOS setuid-in-place core. Narrow API, peer-uid checks on the
   Linux socket, browser-origin rejection, job objects.
2. **Verge**: a separate, versioned service project with typed IPC and rich
   health states; falls back to an unprivileged sidecar with a notice.
3. **Party**: setuid binaries and a fully elevated app on Windows — the widest
   root surface, and the one most exposed to replacing a setuid binary.

All three run the **core** as root, not just a tun helper. Since mihomo parses
untrusted subscription YAML and runs user JS, that is a large root attack
surface in every one of them (a note for Segue, which keeps TUN fd delivery
across a typed ABI instead — `crates/segue-ffi/include/segue_ffi.h:472`).

### 5.2 No control plane over TCP

Verge, Party and Nyanpasu (local transport) all moved the Clash controller to a
**unix socket or named pipe** with per-owner naming, and Party removed the
secret entirely. Verge and Nyanpasu additionally verify peer identity
(`SO_PEERCRED`/SID). FlClash instead replaces the Clash REST API with its own
framed JSON-RPC and never exposes one. The shared conclusion: a loopback TCP
port with a shared secret is the weakest of the options available today.

### 5.3 Subscription defaults

| | Default UA | Interval | Extras |
| --- | --- | --- | --- |
| FlClash | browser UA | per profile | `content-disposition`, `subscription-userinfo`, age |
| Verge | `clash-verge/v…` | minutes, or header hours ×60 | script/merge/rules/proxies/groups chain |
| Party | `mihomo.party/v… (clash.meta)` | minutes or cron, min 1 | Sub-Store rewrite, age |
| Nyanpasu | `clash-nyanpasu/v…` | 120 min default | HWID/OS headers, suggested interval, retry policy |

Verge's and Nyanpasu's handling of a server-suggested interval, and
Nyanpasu's retry policy, are the two things worth taking.

### 5.4 Config integrity

Only Verge enforces **app-owned keys** after every user transform
(`enhance/mod.rs:296-318`). Without that, a malicious or careless profile can
redirect the controller or the mixed port. Party and FlClash instead generate
their config from parts they control; Nyanpasu forces ports from
`ResolvedPortBindings`.

### 5.5 Kill switch and battery/background

None of the four has a kill switch; on desktop the OS proxy revert guard and
on mobile Android's always-on setting are the only backstops. Battery/sleep
techniques actually present: destroy the WebView when idle (Verge lightweight
mode), stop the renderer when hidden + software renderer for the widget
(Nyanpasu), software rendering avoidance of the GL driver, periodic
lightweight timers, and on Android only FlClash does battery-allowlist prompts,
boot-crash detection, suspend-by-SSID and a QS tile.

---

## 6. Where Segue already differs (context for the recommendations)

- Segue's mobile boundary is a **typed C ABI** with a capability mask, not a
  REST control plane: `xray_ffi_capabilities()`, additive minor versions, and a
  deliberate "no embedded dashboard" rule (`docs/ffi.md:8-50`,
  `docs/roadmap.md:49-51`).
- TUN ownership is split: the host app creates the fd (iOS
  `NEPacketTunnelProvider`, Android `VpnService`) and hands it to the core via
  `xray_core_set_tun_fd` (`crates/segue-ffi/include/segue_ffi.h:472`); the core
  never opens the interface itself, so there is no setuid binary anywhere.
  Socket protection is a callback (`:445`), not a uid trick.
- Controls the Clash apps build in the GUI already exist as core APIs for
  Segue: outbound selector override, routing-policy replacement, health and
  connection snapshots, per-outbound probes, accounting
  (`segue_ffi.h:334-382`), file logging (`:450`).
- The kill switch, fake-IP DNS and rule table exist only in the
  `segue-kernel` prototype, not in the shipped FFI
  (`docs/design/ffi-kernel-embedding.md:1-30`, `crates/segue-kernel/src/lib.rs:13-14`).
- Segue has no subscription/profile-store, no system-proxy code, no autostart,
  and no per-app UX: a grep for `system_proxy|autostart` across `crates/` and
  `platform/` returns nothing. Those live in the app.

---

## 7. What Segue should copy / avoid

Ranked by expected value for a mobile-first client that owns its app.

**Copy**

1. **FlClash's helper discipline, if Segue ever needs a desktop privileged
   part**: bind to loopback/unix socket only, reject browser `Origin`s, cap the
   request body, accept only an address you issued, and **pin the spawned core
   binary by SHA-256** at build time
   (`FlClash/services/helper/src/service/hub.rs:56,230,632-641,767-785`;
   `lib/core/desktop/helper_client.dart:158-210`). The setuid core it also
   ships is the thing to *avoid*, not copy.
2. **Verge's app-owned control-plane fields.** Whatever config the app
   generates (ports, DNS, listener addresses), re-enforce it after any
   user-supplied merge or script (`clash-verge-rev/src-tauri/src/enhance/mod.rs:296-318,366`).
   Cheap and closes a whole class of profile-level hijack.
3. **Nyanpasu's subscription fetch policy**: honour
   `profile-update-interval`/suggested interval, apply an explicit retry policy
   that does not retry 401/403/404, and send the standard device headers
   (`nyanpasu-net/src/subscription_http.rs:94-140`, `:255-260`). Providers implement
   anti-abuse around exactly these signals.
4. **Verge's lightweight mode** for a desktop build: destroy the WebView after
   an idle timer, keep core + tray, recreate on demand
   (`core/lightweight.rs:150-200`). This is the single biggest desktop memory
   win available to a Tauri/Electron shell.
5. **FlClash's method-liveness semantics** for any RPC the app adds: fail a
   call only when the peer stops answering *every* call, not when one call is
   slow (`lib/core/desktop/rpc_client.dart:44-55`), plus a large-payload spill
   rather than allocating multi-MB replies on the mobile heap
   (`core/spill.go:8-13`).
6. **Nyanpasu's first-binder local endpoint with peer-identity verification**
   (`nyanpasu-single-instance/src/endpoint/unix.rs:30-45`,
   `.../windows.rs:30-46`) if Segue ever exposes a local control socket to a
   companion process. It is the correct pattern; a port+secret is not.
7. **Verge's service health model** (`NotInstalled` / `NeedsReinstall` /
   `ReinstallRequired` / `Unavailable(reason)`, `core/service.rs:204-215`) and
   FlClash's Android always-on/`onStartCommand` and BootGuard crash-loop
   handling (`VpnService.kt:113-117`, `lib/common/boot_guard.dart:9-40`).

**Avoid**

1. **Running the core as root** (Party's setuid sidecars, FlClash's
   `chmod 4750` macOS core, Verge's service). mihomo parses subscription YAML
   and runs user JS as root in all of them. Segue's fd-handoff over a typed ABI
   is strictly better; do not regress it for a desktop convenience.
2. **Elevating the whole GUI on Windows** (Party, `permissions.ts:278-300`).
   Any renderer/XSS bug becomes SYSTEM.
3. **A loopback TCP controller with a shared secret** as the only auth. Use a
   socket/pipe plus a secret, or a typed ABI.
4. **Root-level script engines without hard resource caps.** Verge's Boa has
   explicit 5 s / 10 MiB input / 1 MiB output / 10^7-iteration caps
   (`enhance/script.rs:12-16`). Party's `node:vm` override (`factory.ts:425-430`)
   has none — no timeout, no memory bound, in a process that may be root.
   Nyanpasu's JS runner has a ~2 s settle timeout (`nyanpasu-scripts/src/js.rs:176-186`)
   but no loop or memory cap. Design against the unlimited case, not around it.
5. **Clash YAML pass-through as the app's own config format.** All four
   inherit mihomo's huge, loosely validated schema and its mixed
   provider/rule-set config. Segue's fail-closed typed parser
   (`docs/architecture.md` "Configuration path") is the asset to keep.
6. **Any analytics/SDK in the client.** None of the four ships telemetry;
   matching that costs nothing.

**Not worth copying**

- Party's plugin/vault/OAuth provider-integration system
  (`docs/plugin/PROVIDER_INTEGRATION_v2.md`) — it is a distribution business
  feature, not a core-client technique.
- The `link-channel`-per-platform duplication (FlClash keeps four transports
  for one core call). One typed boundary plus one local transport is enough.
- Cron expressions for subscription refresh; plain minute intervals cover the
  real provider behaviour (Verge, Nyanpasu).
